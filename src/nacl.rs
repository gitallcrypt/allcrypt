/*
NaCl's boxes and the libsodium functions built round them.

NaCl (Bernstein, Lange and Schwabe; "Cryptography in NaCl", 2009) put a
small number of fixed constructions behind names that say what they are
for. libsodium kept the names and the bytes and added a few more. Both
are what this module reproduces, byte for byte:

  * **secretbox** - authenticated encryption under a shared key, with a
    24 byte nonce. `xsalsa20poly1305` is NaCl's; `xchacha20poly1305` is
    libsodium's `crypto_secretbox_xchacha20poly1305`.
  * **box** - the same, under a key two X25519 key pairs agree on:
    `HSalsa20(X25519(sk, pk), 0)` (or HChaCha20 for the XChaCha form).
    `box_beforenm` is that key, and a secretbox under it is a box.
  * **box_seal** - libsodium's anonymous box: a fresh key pair per
    message, its public half sent in front, and the nonce
    `BLAKE2b-192(ephemeral_pk || recipient_pk)`.
  * **kx** - libsodium's session keys: `BLAKE2b-512(q || client_pk ||
    server_pk)`, split into two 32 byte keys, one per direction.
  * **auth** - NaCl's `crypto_auth`, HMAC-SHA-512 truncated to 32
    bytes; **sign** - Ed25519 in NaCl's combined form, the signature
    followed by the message.

## The secretbox

    keystream = XSalsa20(key, nonce)   (or libsodium's XChaCha20)
    poly_key  = keystream[0..32]
    c         = message XOR keystream[32..]
    tag       = Poly1305(poly_key, c)

Three ways it differs from the IETF AEADs, each of which produces a
working, self-consistent box that opens nothing anybody else sealed:

  * **The payload starts at byte 32 of the keystream, not at block one.**
    The rest of block zero encrypts the first 32 bytes of the message;
    ChaCha20-Poly1305 discards it and starts at byte 64.
  * **Poly1305 sees the ciphertext alone** - no padding to 16 bytes, no
    lengths, no additional data. So `xchacha20poly1305` here is a
    different construction from `xchacha20-poly1305`, the AEAD, under
    almost the same name; `test_the_secretbox_is_not_the_aead` shows them
    disagreeing on the same key and nonce.
  * **The XChaCha form runs the 8 byte nonce, 64 bit counter ChaCha20**
    on the nonce's last eight bytes - libsodium's `crypto_stream_chacha20`,
    not RFC 8439's 12 byte one.

The combined form is the tag followed by the ciphertext (libsodium's
`_easy` functions). NaCl's original API instead had the caller put 32
zero bytes in front of the message and returned 16 zero bytes in front of
the box; those zeros carry nothing, and the bytes between them are the
same.

## What it refuses that NaCl did not

`box_beforenm` refuses a peer key whose shared secret is all zeros - a
low-order point, which makes every exchange's key the same known value.
libsodium refuses it too; NaCl did not.
*/

use crate::ec::x25519;
use crate::hash_functions::blake2::Blake2b;
use crate::hash_functions::sha2::SHA512;
use crate::hash_functions::HashFunction;
use crate::mac::{Hmac, Poly1305};
use crate::stream_ciphers::chacha::{hchacha20, xchacha20, Chacha};
use crate::stream_ciphers::salsa20::{hsalsa20, xsalsa20, Salsa20};
use crate::Mac;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const MAC_BYTES: usize = 16;
/// What `box_seal` adds: the ephemeral public key and the tag.
pub const SEAL_BYTES: usize = 32 + MAC_BYTES;

/// Which stream cipher a box runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Construction {
    /// NaCl's: XSalsa20 and Poly1305, keyed through HSalsa20.
    XSalsa20Poly1305,
    /// libsodium's: XChaCha20 and Poly1305, keyed through HChaCha20.
    XChaCha20Poly1305,
}

/// The names `from_name` takes, secretbox first and box second.
pub const CONSTRUCTIONS: &[&str] = &["xsalsa20poly1305", "xchacha20poly1305",
                                     "curve25519xsalsa20poly1305",
                                     "curve25519xchacha20poly1305"];

impl Construction {
    /// libsodium's primitive name, with or without the box's
    /// `curve25519` prefix.
    pub fn from_name(name: &str) -> Result<Construction, String> {
        let lower = name.to_ascii_lowercase();
        match lower.strip_prefix("curve25519").unwrap_or(&lower) {
            "xsalsa20poly1305" => Ok(Construction::XSalsa20Poly1305),
            "xchacha20poly1305" => Ok(Construction::XChaCha20Poly1305),
            _ => Err(format!("Unknown box construction {name:?}. Known: {}. \
                              The IETF AEAD xchacha20-poly1305 is a different \
                              construction; it is reached through the AEAD \
                              interface.", CONSTRUCTIONS.join(", "))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Construction::XSalsa20Poly1305 => "xsalsa20poly1305",
            Construction::XChaCha20Poly1305 => "xchacha20poly1305",
        }
    }

    fn keystream(self, key: &[u8; 32], nonce: &[u8; 24]) -> Result<Keystream, String> {
        Ok(match self {
            Construction::XSalsa20Poly1305 => Keystream::Salsa(xsalsa20(key, nonce)?),
            Construction::XChaCha20Poly1305 => Keystream::Chacha(xchacha20(key, nonce)?),
        })
    }

    /// The box key from an X25519 shared secret: the construction's
    /// H-function over sixteen zero bytes.
    fn box_key(self, shared: &[u8; 32]) -> [u8; 32] {
        match self {
            Construction::XSalsa20Poly1305 => hsalsa20(shared, &[0u8; 16]),
            Construction::XChaCha20Poly1305 => hchacha20(shared, &[0u8; 16]),
        }
    }
}

enum Keystream {
    Salsa(Salsa20),
    Chacha(Chacha),
}

impl Keystream {
    fn apply(&mut self, buf: &mut [u8]) -> Result<(), String> {
        match self {
            Keystream::Salsa(cipher) => cipher.apply(buf).map_err(|(_, e)| e),
            Keystream::Chacha(cipher) => {
                cipher.apply(buf);
                Ok(())
            }
        }
    }
}

fn array<const N: usize>(what: &str, bytes: &[u8]) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| format!("A {what} is {N} bytes, not {}.", bytes.len()))
}

/// The stream positioned at byte 32, and the Poly1305 key it gave.
fn start(construction: Construction, key: &[u8], nonce: &[u8])
         -> Result<(Keystream, Poly1305), String> {
    let key = array::<32>("secretbox key", key)?;
    let nonce = array::<24>("secretbox nonce", nonce)?;
    let mut stream = construction.keystream(&key, &nonce)?;
    let mut poly_key = [0u8; 32];
    stream.apply(&mut poly_key)?;
    Ok((stream, Poly1305::new(&poly_key)?))
}

/// Encrypt, returning the ciphertext and the tag apart.
pub fn secretbox_encrypt_detached(construction: Construction, key: &[u8], nonce: &[u8],
                                  message: &[u8]) -> Result<(Vec<u8>, [u8; 16]), String> {
    let (mut stream, mut mac) = start(construction, key, nonce)?;
    let mut ciphertext = message.to_vec();
    stream.apply(&mut ciphertext)?;
    mac.update(&ciphertext);
    Ok((ciphertext, mac.tag()))
}

/// Decrypt a detached ciphertext and tag. The tag is checked, in
/// constant time, before anything is decrypted, and a failure returns
/// nothing but the error.
pub fn secretbox_decrypt_detached(construction: Construction, key: &[u8], nonce: &[u8],
                                  ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>, String> {
    let (mut stream, mut mac) = start(construction, key, nonce)?;
    mac.update(ciphertext);
    if !mac.verify(tag) {
        return Err(format!("The {} box did not authenticate: the key, the nonce \
                            or the box is not the one that was sealed.",
                           construction.name()));
    }
    let mut message = ciphertext.to_vec();
    stream.apply(&mut message)?;
    Ok(message)
}

/// Encrypt: the tag followed by the ciphertext, `MAC_BYTES` longer than
/// the message.
pub fn secretbox_encrypt(construction: Construction, key: &[u8], nonce: &[u8],
                         message: &[u8]) -> Result<Vec<u8>, String> {
    let (ciphertext, tag) = secretbox_encrypt_detached(construction, key, nonce, message)?;
    let mut out = Vec::with_capacity(MAC_BYTES + ciphertext.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn secretbox_decrypt(construction: Construction, key: &[u8], nonce: &[u8],
                         boxed: &[u8]) -> Result<Vec<u8>, String> {
    if boxed.len() < MAC_BYTES {
        return Err(format!("A box is at least its {MAC_BYTES} byte tag; this one is {} \
                            bytes.", boxed.len()));
    }
    secretbox_decrypt_detached(construction, key, nonce, &boxed[MAC_BYTES..],
                               &boxed[..MAC_BYTES])
}

/// The key a box between `private` and `peer_public` is sealed under,
/// the same from either side: NaCl's `crypto_box_beforenm`. A secretbox
/// under it is a box, which is how a session of many boxes avoids an
/// X25519 per message.
pub fn box_beforenm(construction: Construction, peer_public: &[u8], private: &[u8])
                    -> Result<[u8; 32], String> {
    let shared = x25519::exchange(&array::<32>("private key", private)?,
                                  &array::<32>("public key", peer_public)?)?;
    Ok(construction.box_key(&shared))
}

pub fn box_encrypt(construction: Construction, peer_public: &[u8], private: &[u8],
                   nonce: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let key = box_beforenm(construction, peer_public, private)?;
    secretbox_encrypt(construction, &key, nonce, message)
}

pub fn box_decrypt(construction: Construction, peer_public: &[u8], private: &[u8],
                   nonce: &[u8], boxed: &[u8]) -> Result<Vec<u8>, String> {
    let key = box_beforenm(construction, peer_public, private)?;
    secretbox_decrypt(construction, &key, nonce, boxed)
}

/// A box key pair from a 32 byte seed, as `(private, public)`:
/// libsodium's `crypto_box_seed_keypair`, whose private key is the first
/// half of SHA-512 of the seed, stored unclamped.
pub fn box_seed_keypair(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let seed = array::<32>("box seed", seed)?;
    let digest = SHA512::new(&seed, 512).digest();
    let private = array::<32>("digest half", &digest[..32])?;
    Ok((private, x25519::public_key(&private)?))
}

/// The nonce of a sealed box: BLAKE2b with a 24 byte output over the
/// ephemeral public key and then the recipient's.
fn seal_nonce(ephemeral_public: &[u8; 32], recipient_public: &[u8; 32])
              -> Result<Vec<u8>, String> {
    let mut hash = Blake2b::with_length(NONCE_BYTES)?;
    hash.update(ephemeral_public);
    hash.update(recipient_public);
    Ok(hash.digest())
}

/// An anonymous box to `recipient_public`: libsodium's `crypto_box_seal`.
/// The ephemeral public key, then a box from the ephemeral private key.
///
/// Nothing in it says who sealed it - anybody can make one - so it is
/// confidentiality with integrity, not authentication of the sender.
pub fn box_seal(construction: Construction, recipient_public: &[u8], message: &[u8])
                -> Result<Vec<u8>, String> {
    let (ephemeral_private, _) = x25519::generate_key_pair()?;
    box_seal_with_ephemeral(construction, recipient_public, message, &ephemeral_private)
}

/// `box_seal` with the ephemeral private key supplied rather than drawn.
/// **For known-answer tests only**: a sealed box's nonce is a function of
/// the two public keys, so two messages sealed with one ephemeral key to
/// one recipient share a nonce under one key.
pub fn box_seal_with_ephemeral(construction: Construction, recipient_public: &[u8],
                               message: &[u8], ephemeral_private: &[u8])
                               -> Result<Vec<u8>, String> {
    let recipient = array::<32>("public key", recipient_public)?;
    let ephemeral_private = array::<32>("private key", ephemeral_private)?;
    let ephemeral_public = x25519::public_key(&ephemeral_private)?;
    let nonce = seal_nonce(&ephemeral_public, &recipient)?;
    let mut out = ephemeral_public.to_vec();
    out.extend(box_encrypt(construction, &recipient, &ephemeral_private, &nonce, message)?);
    Ok(out)
}

/// Open a sealed box. The recipient's public key is needed as well as
/// the private one, because it is half of the nonce.
pub fn box_seal_open(construction: Construction, recipient_public: &[u8],
                     recipient_private: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < SEAL_BYTES {
        return Err(format!("A sealed box is at least {SEAL_BYTES} bytes; this one is {}.",
                           sealed.len()));
    }
    let recipient = array::<32>("public key", recipient_public)?;
    let ephemeral_public = array::<32>("public key", &sealed[..32])?;
    let nonce = seal_nonce(&ephemeral_public, &recipient)?;
    box_decrypt(construction, &ephemeral_public, recipient_private, &nonce, &sealed[32..])
}

/// A key-exchange key pair from a 32 byte seed: libsodium's
/// `crypto_kx_seed_keypair`, whose private key is **BLAKE2b-256** of the
/// seed - not the SHA-512 half `box_seed_keypair` takes, so one seed
/// gives two different key pairs through the two functions.
pub fn kx_seed_keypair(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let seed = array::<32>("kx seed", seed)?;
    let mut hash = Blake2b::with_length(32)?;
    hash.update(&seed);
    let private = array::<32>("digest", &hash.digest())?;
    Ok((private, x25519::public_key(&private)?))
}

/// `BLAKE2b-512(q || client_pk || server_pk)`: both sides hash the keys
/// in the same order, client first, and take the halves the other way
/// round.
fn kx_hash(shared: &[u8; 32], client_public: &[u8; 32], server_public: &[u8; 32])
           -> Result<Vec<u8>, String> {
    let mut hash = Blake2b::with_length(64)?;
    hash.update(shared);
    hash.update(client_public);
    hash.update(server_public);
    Ok(hash.digest())
}

/// The client's session keys, `(receive, transmit)`: libsodium's
/// `crypto_kx_client_session_keys`. The client's receive key is the
/// server's transmit key, and the other way round.
pub fn kx_client_session_keys(client_public: &[u8], client_private: &[u8],
                              server_public: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let client_public = array::<32>("public key", client_public)?;
    let server_public = array::<32>("public key", server_public)?;
    let shared = x25519::exchange(&array::<32>("private key", client_private)?,
                                  &server_public)?;
    let h = kx_hash(&shared, &client_public, &server_public)?;
    Ok((array("key", &h[..32])?, array("key", &h[32..])?))
}

/// The server's session keys, `(receive, transmit)`.
pub fn kx_server_session_keys(server_public: &[u8], server_private: &[u8],
                              client_public: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let client_public = array::<32>("public key", client_public)?;
    let server_public = array::<32>("public key", server_public)?;
    let shared = x25519::exchange(&array::<32>("private key", server_private)?,
                                  &client_public)?;
    let h = kx_hash(&shared, &client_public, &server_public)?;
    Ok((array("key", &h[32..])?, array("key", &h[..32])?))
}

/// NaCl's `crypto_auth`: HMAC-SHA-512 truncated to 32 bytes, under a 32
/// byte key.
pub fn auth(key: &[u8], message: &[u8]) -> Result<[u8; 32], String> {
    let key = array::<32>("crypto_auth key", key)?;
    let mut mac = Hmac::new(SHA512::new(&[], 512), &key);
    mac.update(message);
    array("tag", &mac.digest()[..32])
}

/// Check a `crypto_auth` tag, in constant time.
pub fn auth_verify(key: &[u8], message: &[u8], tag: &[u8]) -> Result<(), String> {
    let expected = auth(key, message)?;
    let mut difference = u8::from(tag.len() != expected.len());
    for (a, b) in expected.iter().zip(tag) {
        difference |= a ^ b;
    }
    if difference != 0 {
        return Err("The crypto_auth tag does not match.".to_string());
    }
    Ok(())
}

/// The 32 byte Ed25519 seed from either form libsodium uses: the seed
/// itself, or the 64 byte secret key that is the seed followed by the
/// public key. The second is **checked**: libsodium signs with the stored
/// public half as it stands, and a signature under a key whose two
/// halves disagree gives away the private scalar to anybody holding a
/// second signature of the same message.
fn ed25519_seed(private: &[u8]) -> Result<[u8; 32], String> {
    use crate::ec::eddsa;
    match private.len() {
        32 => array("seed", private),
        64 => {
            let seed = array::<32>("seed", &private[..32])?;
            if eddsa::public_key(eddsa::Variant::Ed25519, &seed)? != private[32..] {
                return Err("This 64 byte Ed25519 secret key's second half is not the \
                            public key of its first; signing with it would leak the \
                            key.".to_string());
            }
            Ok(seed)
        }
        other => Err(format!("An Ed25519 secret key is a 32 byte seed or 64 bytes of \
                              seed and public key; this one is {other} bytes.")),
    }
}

/// NaCl's `crypto_sign`: the 64 byte Ed25519 signature followed by the
/// message.
pub fn sign(private: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    use crate::ec::eddsa;
    let seed = ed25519_seed(private)?;
    let mut out = eddsa::sign(eddsa::Variant::Ed25519, &seed, message, &[])?;
    out.extend_from_slice(message);
    Ok(out)
}

/// NaCl's `crypto_sign_open`: the message, if the signature in front of
/// it verifies.
pub fn sign_open(public: &[u8], signed: &[u8]) -> Result<Vec<u8>, String> {
    use crate::ec::eddsa;
    if signed.len() < 64 {
        return Err(format!("A signed message is at least its 64 byte signature; this \
                            one is {} bytes.", signed.len()));
    }
    eddsa::verify(eddsa::Variant::Ed25519, public, &signed[64..], &signed[..64], &[])?;
    Ok(signed[64..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_ciphers::chacha20poly1305;

    const ALL: [Construction; 2] = [Construction::XSalsa20Poly1305,
                                    Construction::XChaCha20Poly1305];

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 131 + 7) as u8).collect()
    }

    /// The payload starts at keystream byte 32: the ciphertext is the
    /// message XORed with the stream from there, for every length across
    /// the end of block zero.
    #[test]
    fn test_the_payload_starts_at_byte_32() {
        let (key, nonce) = ([3u8; 32], [5u8; 24]);
        for construction in ALL {
            let mut stream = construction.keystream(&key, &nonce).unwrap();
            let mut keystream = vec![0u8; 32 + 200];
            stream.apply(&mut keystream).unwrap();
            for length in [0usize, 1, 31, 32, 33, 63, 64, 65, 200] {
                let message = data(length);
                let (ciphertext, _) = secretbox_encrypt_detached(construction, &key, &nonce,
                                                                 &message).unwrap();
                let want: Vec<u8> = message.iter().zip(&keystream[32..])
                    .map(|(m, k)| m ^ k).collect();
                assert_eq!(ciphertext, want, "{construction:?} {length}");
            }
        }
    }

    /// libsodium's `crypto_secretbox_xchacha20poly1305` and the AEAD
    /// `xchacha20-poly1305` share a key, a nonce length and a name, and
    /// are not the same construction.
    #[test]
    fn test_the_secretbox_is_not_the_aead() {
        let (key, nonce, message) = ([1u8; 32], [2u8; 24], data(100));
        let boxed = secretbox_encrypt(Construction::XChaCha20Poly1305, &key, &nonce,
                                      &message).unwrap();
        let mut aead = chacha20poly1305::ChaCha20Poly1305::x_encryptor(&key, &nonce, &[])
            .unwrap();
        let mut ciphertext = Vec::new();
        aead.update(&message, &mut ciphertext).unwrap();
        assert_ne!(&boxed[16..], &ciphertext[..]);
        assert_ne!(&boxed[..16], &aead.tag().unwrap()[..]);
    }

    /// Every bit of the box matters, and a failure gives no plaintext.
    #[test]
    fn test_any_change_is_refused() {
        let (key, nonce) = ([7u8; 32], [9u8; 24]);
        for construction in ALL {
            let boxed = secretbox_encrypt(construction, &key, &nonce, &data(40)).unwrap();
            assert_eq!(secretbox_decrypt(construction, &key, &nonce, &boxed).unwrap(), data(40));
            for bit in 0..boxed.len() * 8 {
                let mut bad = boxed.clone();
                bad[bit / 8] ^= 1 << (bit % 8);
                assert!(secretbox_decrypt(construction, &key, &nonce, &bad).is_err(),
                        "{construction:?} bit {bit}");
            }
            let mut other_nonce = nonce;
            other_nonce[23] ^= 1;
            assert!(secretbox_decrypt(construction, &key, &other_nonce, &boxed).is_err());
            assert!(secretbox_decrypt(construction, &key, &nonce, &boxed[..15]).is_err());
        }
    }

    /// The two constructions are different boxes.
    #[test]
    fn test_the_constructions_differ() {
        let a = secretbox_encrypt(ALL[0], &[1; 32], &[1; 24], b"m").unwrap();
        let b = secretbox_encrypt(ALL[1], &[1; 32], &[1; 24], b"m").unwrap();
        assert_ne!(a, b);
    }

    /// Both ends of a box compute one key, and a box from either opens at
    /// the other.
    #[test]
    fn test_a_box_opens_at_the_other_end() {
        let (alice, alice_public) = box_seed_keypair(&[1; 32]).unwrap();
        let (bob, bob_public) = box_seed_keypair(&[2; 32]).unwrap();
        for construction in ALL {
            assert_eq!(box_beforenm(construction, &bob_public, &alice).unwrap(),
                       box_beforenm(construction, &alice_public, &bob).unwrap());
            let boxed = box_encrypt(construction, &bob_public, &alice, &[4; 24], b"hello")
                .unwrap();
            assert_eq!(box_decrypt(construction, &alice_public, &bob, &[4; 24], &boxed)
                       .unwrap(), b"hello");
        }
    }

    /// A low-order peer key is refused rather than boxed under a known key.
    #[test]
    fn test_a_low_order_peer_is_refused() {
        let (alice, _) = box_seed_keypair(&[1; 32]).unwrap();
        // u = 0 and u = 1, two of the low-order points libsodium lists.
        let mut one = [0u8; 32];
        one[0] = 1;
        for peer in [[0u8; 32], one] {
            assert!(box_beforenm(Construction::XSalsa20Poly1305, &peer, &alice).is_err());
        }
    }

    #[test]
    fn test_a_sealed_box_opens_and_only_for_its_recipient() {
        let (bob, bob_public) = box_seed_keypair(&[2; 32]).unwrap();
        let (carol, carol_public) = box_seed_keypair(&[3; 32]).unwrap();
        for construction in ALL {
            let sealed = box_seal(construction, &bob_public, b"for bob").unwrap();
            assert_eq!(sealed.len(), SEAL_BYTES + 7);
            assert_eq!(box_seal_open(construction, &bob_public, &bob, &sealed).unwrap(),
                       b"for bob");
            assert!(box_seal_open(construction, &carol_public, &carol, &sealed).is_err());
            // The right private key with the wrong public key gives the
            // wrong nonce.
            assert!(box_seal_open(construction, &carol_public, &bob, &sealed).is_err());
        }
    }

    #[test]
    fn test_kx_keys_cross_over() {
        let (client, client_public) = kx_seed_keypair(&[5; 32]).unwrap();
        let (server, server_public) = kx_seed_keypair(&[6; 32]).unwrap();
        let (client_rx, client_tx) =
            kx_client_session_keys(&client_public, &client, &server_public).unwrap();
        let (server_rx, server_tx) =
            kx_server_session_keys(&server_public, &server, &client_public).unwrap();
        assert_eq!(client_rx, server_tx);
        assert_eq!(client_tx, server_rx);
        assert_ne!(client_rx, client_tx);
        // One seed, two key pairs.
        assert_ne!(kx_seed_keypair(&[5; 32]).unwrap().0, box_seed_keypair(&[5; 32]).unwrap().0);
    }

    #[test]
    fn test_auth_is_truncated_hmac_sha512() {
        let tag = auth(&[8; 32], b"message").unwrap();
        let mut mac = Hmac::new(SHA512::new(&[], 512), &[8; 32]);
        mac.update(b"message");
        assert_eq!(&tag[..], &mac.digest()[..32]);
        assert!(auth_verify(&[8; 32], b"message", &tag).is_ok());
        assert!(auth_verify(&[8; 32], b"messagE", &tag).is_err());
        assert!(auth_verify(&[8; 32], b"message", &tag[..31]).is_err());
        assert!(auth(&[8; 31], b"").is_err());
    }

    #[test]
    fn test_signed_messages_and_both_key_forms() {
        use crate::ec::eddsa;
        let seed = [11u8; 32];
        let public = eddsa::public_key(eddsa::Variant::Ed25519, &seed).unwrap();
        let mut long = seed.to_vec();
        long.extend_from_slice(&public);
        let signed = sign(&seed, b"msg").unwrap();
        assert_eq!(signed, sign(&long, b"msg").unwrap());
        assert_eq!(&signed[64..], b"msg");
        assert_eq!(sign_open(&public, &signed).unwrap(), b"msg");
        let mut bad = signed.clone();
        bad[66] ^= 1;
        assert!(sign_open(&public, &bad).is_err());
        // A 64 byte key whose halves disagree is refused.
        long[40] ^= 1;
        assert!(sign(&long, b"msg").is_err());
    }
}
