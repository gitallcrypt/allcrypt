/*
SSH's ciphers by name: RFC 4253 section 6.3, RFC 4344's counter modes,
RFC 5647 as OpenSSH profiles it (`aes*-gcm@openssh.com`), and OpenSSH's
`chacha20-poly1305@openssh.com` (PROTOCOL.chacha20poly1305).

`Cipher::crypt` has the shape of OpenSSH's `cipher_crypt`, because both
places that encrypt in SSH use it: the binary packet protocol, and the
private section of an `openssh-key-v1` file. The first `aad_len` bytes
are the part the cipher must not hide - the packet length, for the AEAD
modes and for encrypt-then-MAC - and the rest is encrypted. What
happens to those first bytes is the cipher's business: sent as they are
and authenticated (GCM), encrypted under a key of their own
(ChaCha20-Poly1305), or sent as they are (everything else).

# Pitfalls

**`chacha20-poly1305@openssh.com` is not RFC 8439.** It is the original
ChaCha20 with a 64 bit nonce - the packet sequence number - and a 64 bit
block counter; the 64 byte key is two keys, and the *second* half
encrypts the length while the first encrypts the payload and makes the
Poly1305 key; and the MAC covers the encrypted length and payload with
no padding and no length block. An RFC 8439 AEAD with the sequence
number as its nonce is wrong in four places at once.

**GCM's nonce is the IV the key exchange produced, incremented after
every packet** - the low 64 bits, as one big-endian counter (RFC 5647
section 7.1). A fresh random nonce per packet would be safer in the
abstract and would interoperate with nothing.

**CBC and CTR state runs across packets.** The IV of a packet is the
last ciphertext block (CBC) or the next counter (CTR) of the one before;
the cipher is created once per direction per key exchange and never
reset. Restarting per packet decrypts the first packet and nothing else.
*/

use crate::api::AnyBlockCipher;
use crate::block_ciphers::gcm::GcmState;
use crate::block_ciphers::modes::{CbcState, CtrState};
use crate::mac::poly1305::Poly1305;
use crate::stream_ciphers::{chacha::Chacha, rc4::RC4, StreamCipher};
use crate::Mac;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    None,
    /// CBC over the named block cipher.
    Cbc(&'static str),
    /// CTR over it: the IV is the initial counter, incremented as one
    /// big-endian integer the width of the block (RFC 4344 section 4).
    Ctr(&'static str),
    Gcm,
    ChaChaPoly,
    /// RC4, with this many bytes of keystream thrown away first
    /// (RFC 4345: 1536, because RC4's first bytes are biased).
    Rc4 { discard: usize },
}

/// What an SSH cipher name means.
#[derive(Debug, PartialEq, Eq)]
pub struct Spec {
    pub name: &'static str,
    pub key_len: usize,
    pub iv_len: usize,
    /// The unit packets are padded to: the cipher's block, or 8 for the
    /// stream-like ones (RFC 4253 section 6).
    pub block_size: usize,
    /// Bytes of authentication tag after the ciphertext; zero for every
    /// cipher that leaves integrity to a separate MAC.
    pub tag_len: usize,
    kind: Kind,
}

const fn spec(name: &'static str, key_len: usize, iv_len: usize, block_size: usize,
              tag_len: usize, kind: Kind) -> Spec {
    Spec { name, key_len, iv_len, block_size, tag_len, kind }
}

/// Every cipher this module speaks.
pub const CIPHERS: &[Spec] = &[
    spec("chacha20-poly1305@openssh.com", 64, 0, 8, 16, Kind::ChaChaPoly),
    spec("aes128-ctr", 16, 16, 16, 0, Kind::Ctr("aes")),
    spec("aes192-ctr", 24, 16, 16, 0, Kind::Ctr("aes")),
    spec("aes256-ctr", 32, 16, 16, 0, Kind::Ctr("aes")),
    spec("aes128-gcm@openssh.com", 16, 12, 16, 16, Kind::Gcm),
    spec("aes256-gcm@openssh.com", 32, 12, 16, 16, Kind::Gcm),
    spec("aes128-cbc", 16, 16, 16, 0, Kind::Cbc("aes")),
    spec("aes192-cbc", 24, 16, 16, 0, Kind::Cbc("aes")),
    spec("aes256-cbc", 32, 16, 16, 0, Kind::Cbc("aes")),
    spec("3des-cbc", 24, 8, 8, 0, Kind::Cbc("3des")),
    // The ones OpenSSH removed in 7.6 (2017) and old devices kept.
    // `rijndael-cbc@lysator.liu.se` is AES-256-CBC under its name from
    // before AES was AES.
    spec("rijndael-cbc@lysator.liu.se", 32, 16, 16, 0, Kind::Cbc("aes")),
    spec("blowfish-cbc", 16, 8, 8, 0, Kind::Cbc("blowfish")),
    spec("cast128-cbc", 16, 8, 8, 0, Kind::Cbc("cast5")),
    spec("arcfour256", 32, 0, 8, 0, Kind::Rc4 { discard: 1536 }),
    spec("arcfour128", 16, 0, 8, 0, Kind::Rc4 { discard: 1536 }),
    spec("arcfour", 16, 0, 8, 0, Kind::Rc4 { discard: 0 }),
    spec("none", 0, 0, 8, 0, Kind::None),
];

impl Spec {
    /// How many IV bytes OpenSSH derives for this cipher: its IV length,
    /// or for a cipher without one (RC4) the block size - OpenSSH's
    /// `cipher_ivlen`. ChaCha20-Poly1305 takes none. Only the private key
    /// format sees the difference, because bcrypt_pbkdf's output depends
    /// on its total length; see `ssh::private_key`.
    pub fn kdf_iv_len(&self) -> usize {
        if self.iv_len != 0 || matches!(self.kind, Kind::ChaChaPoly | Kind::None) {
            self.iv_len
        } else {
            self.block_size
        }
    }
}

/// The spec for a name.
pub fn lookup(name: &str) -> Result<&'static Spec, String> {
    CIPHERS.iter().find(|spec| spec.name == name).ok_or_else(|| {
        let known: Vec<&str> = CIPHERS.iter().map(|spec| spec.name).collect();
        format!("SSH: unknown cipher {name:?}. Known: {}.", known.join(", "))
    })
}

enum State {
    None,
    Cbc { cipher: AnyBlockCipher, chain: CbcState },
    Ctr { cipher: AnyBlockCipher, counter: CtrState },
    Gcm { cipher: AnyBlockCipher, nonce: [u8; 12] },
    ChaChaPoly { main: [u8; 32], header: [u8; 32] },
    Rc4(RC4),
}

/// One direction's cipher, created once per key exchange.
pub struct Cipher {
    spec: &'static Spec,
    state: State,
    encrypting: bool,
}

impl Cipher {
    pub fn new(name: &str, key: &[u8], iv: &[u8], encrypting: bool)
               -> Result<Cipher, String> {
        let spec = lookup(name)?;
        if key.len() != spec.key_len || iv.len() != spec.iv_len {
            return Err(format!(
                "SSH: {name} takes a {} byte key and a {} byte IV, and was \
                 given {} and {}.", spec.key_len, spec.iv_len, key.len(), iv.len()));
        }
        let state = match spec.kind {
            Kind::None => State::None,
            Kind::Cbc(block) => {
                let mut cipher = AnyBlockCipher::new(block, key, None)?;
                let chain = CbcState::new(&mut cipher, iv, !encrypting)?;
                State::Cbc { cipher, chain }
            }
            Kind::Ctr(block) => {
                let mut cipher = AnyBlockCipher::new(block, key, None)?;
                let counter = CtrState::new(&mut cipher, iv)?;
                State::Ctr { cipher, counter }
            }
            Kind::Gcm => State::Gcm {
                cipher: AnyBlockCipher::new("aes", key, None)?,
                nonce: iv.try_into().map_err(|_| "SSH: GCM IV length".to_string())?,
            },
            Kind::Rc4 { discard } => {
                let mut rc4 = RC4::new(key)?;
                let mut thrown = Vec::with_capacity(discard);
                rc4.crypt(&vec![0u8; discard], &mut thrown);
                State::Rc4(rc4)
            }
            Kind::ChaChaPoly => {
                let (main, header) = key.split_at(32);
                State::ChaChaPoly {
                    main: main.try_into().map_err(|_| "SSH: key length".to_string())?,
                    header: header.try_into().map_err(|_| "SSH: key length".to_string())?,
                }
            }
        };
        Ok(Cipher { spec, state, encrypting })
    }

    pub fn spec(&self) -> &'static Spec {
        self.spec
    }

    /// ChaCha20-Poly1305's packet length, decrypted with the header key
    /// alone. This is what the second key is for: a receiver needs the
    /// length before it has the whole packet to authenticate. The value
    /// is unauthenticated until `crypt` has checked the tag, and is only
    /// fit for deciding how much more to read.
    pub fn peek_length(&self, sequence: u32, encrypted: &[u8]) -> Result<u32, String> {
        match &self.state {
            State::ChaChaPoly { header, .. } => {
                let mut length = Chacha::new(&header[..],
                                             &u64::from(sequence).to_be_bytes(), 20)?;
                let mut out = Vec::with_capacity(4);
                length.crypt(encrypted.get(..4).ok_or("SSH: a length is four bytes.")?,
                             &mut out);
                Ok(u32::from_be_bytes([out[0], out[1], out[2], out[3]]))
            }
            _ => Err(format!("SSH: {} does not encrypt the length on its own.",
                             self.spec.name)),
        }
    }

    /// OpenSSH's `cipher_crypt`.
    ///
    /// Encrypting, `data` is `aad_len` bytes of length field and then the
    /// bytes to encrypt, which must be a whole number of blocks; the
    /// result is the same layout transformed, with the tag appended for
    /// an AEAD cipher. Decrypting, `data` is what encrypting produced, tag
    /// included, and the result has the tag removed - or is an error, with
    /// nothing decrypted, if the tag does not match.
    pub fn crypt(&mut self, sequence: u32, data: &[u8], aad_len: usize)
                 -> Result<Vec<u8>, String> {
        let tag_len = if self.encrypting { 0 } else { self.spec.tag_len };
        if data.len() < aad_len + tag_len {
            return Err(format!("SSH: {} needs at least {} bytes here and was \
                                given {}.", self.spec.name, aad_len + tag_len,
                               data.len()));
        }
        let (aad, rest) = data.split_at(aad_len);
        let (body, tag) = rest.split_at(rest.len() - tag_len);
        if !body.len().is_multiple_of(self.spec.block_size) {
            return Err(format!("SSH: {} encrypts whole {} byte blocks, and {} \
                                bytes is not a whole number of them.",
                               self.spec.name, self.spec.block_size, body.len()));
        }
        let mut out = Vec::with_capacity(data.len() + self.spec.tag_len);
        match &mut self.state {
            State::None => out.extend_from_slice(data),
            State::Cbc { cipher, chain } => {
                out.extend_from_slice(aad);
                chain.update(cipher, body, &mut out)?;
            }
            State::Ctr { cipher, counter } => {
                out.extend_from_slice(aad);
                counter.update(cipher, body, &mut out)?;
            }
            State::Rc4(rc4) => {
                out.extend_from_slice(aad);
                rc4.crypt(body, &mut out);
            }
            State::Gcm { cipher, nonce } => {
                out.extend_from_slice(aad);
                if self.encrypting {
                    let mut gcm = GcmState::encryptor(cipher, nonce, aad)?;
                    gcm.update(cipher, body, &mut out)?;
                    out.extend_from_slice(&gcm.tag(cipher)?);
                } else {
                    // Checked before anything decrypted is released.
                    let mut gcm = GcmState::decryptor(cipher, nonce, aad)?;
                    let mut plain = Vec::with_capacity(body.len());
                    gcm.update(cipher, body, &mut plain)?;
                    gcm.verify(cipher, tag)?;
                    out.extend_from_slice(&plain);
                }
                // The invocation counter: the low 64 bits, big endian.
                let mut counter = [0u8; 8];
                counter.copy_from_slice(&nonce[4..]);
                let next = u64::from_be_bytes(counter).wrapping_add(1);
                nonce[4..].copy_from_slice(&next.to_be_bytes());
            }
            State::ChaChaPoly { main, header } => {
                let nonce = u64::from(sequence).to_be_bytes();
                // Block zero of the main key is the Poly1305 key, and the
                // same stream then carries on into block one, where the
                // payload starts.
                let mut payload = Chacha::new(&main[..], &nonce, 20)?;
                let mut poly_key = Vec::with_capacity(64);
                payload.crypt(&[0u8; 64], &mut poly_key);
                let mut mac = Poly1305::new(&poly_key[..32])?;
                let mut length = Chacha::new(&header[..], &nonce, 20)?;
                if self.encrypting {
                    length.crypt(aad, &mut out);
                    payload.crypt(body, &mut out);
                    mac.update(&out);
                    out.extend_from_slice(&mac.tag());
                } else {
                    mac.update(aad);
                    mac.update(body);
                    if !mac.verify(tag) {
                        return Err("SSH: the chacha20-poly1305 tag does not \
                                    match.".to_string());
                    }
                    length.crypt(aad, &mut out);
                    payload.crypt(body, &mut out);
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_cipher_round_trips_across_packets() {
        for spec in CIPHERS {
            let key: Vec<u8> = (0..spec.key_len as u8).collect();
            let iv: Vec<u8> = (0..spec.iv_len as u8).map(|b| b ^ 0x5a).collect();
            let mut sender = Cipher::new(spec.name, &key, &iv, true).unwrap();
            let mut receiver = Cipher::new(spec.name, &key, &iv, false).unwrap();
            for sequence in 0..3u32 {
                // The AEAD modes leave the four byte length outside the
                // blocks; the rest encrypt the whole packet.
                let aad = if spec.tag_len > 0 { 4 } else { 0 };
                let packet: Vec<u8> = (0..aad + 2 * spec.block_size)
                    .map(|i| (i as u32 * 7 + sequence) as u8).collect();
                let sealed = sender.crypt(sequence, &packet, aad).unwrap();
                assert_eq!(sealed.len(), packet.len() + spec.tag_len, "{}", spec.name);
                if spec.kind != Kind::None {
                    assert_ne!(&sealed[aad..packet.len()], &packet[aad..], "{}", spec.name);
                }
                assert_eq!(receiver.crypt(sequence, &sealed, aad).unwrap(), packet,
                           "{} packet {sequence}", spec.name);
            }
        }
    }

    #[test]
    fn test_a_changed_byte_fails_the_aead_ciphers() {
        for name in ["aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"] {
            let spec = lookup(name).unwrap();
            let key = vec![1; spec.key_len];
            let iv = vec![2; spec.iv_len];
            let packet = [9u8; 4 + 32];
            let sealed = Cipher::new(name, &key, &iv, true).unwrap()
                .crypt(5, &packet, 4).unwrap();
            for at in [0, 4, sealed.len() - 1] {
                let mut broken = sealed.clone();
                broken[at] ^= 1;
                assert!(Cipher::new(name, &key, &iv, false).unwrap()
                        .crypt(5, &broken, 4).is_err(), "{name} byte {at}");
            }
        }
        // ChaCha20-Poly1305 takes its nonce from the sequence number, so
        // a packet replayed at another position fails.
        let name = "chacha20-poly1305@openssh.com";
        let sealed = Cipher::new(name, &[1; 64], &[], true).unwrap()
            .crypt(5, &[9u8; 4 + 32], 4).unwrap();
        assert!(Cipher::new(name, &[1; 64], &[], false).unwrap()
                .crypt(6, &sealed, 4).is_err());
    }
}
