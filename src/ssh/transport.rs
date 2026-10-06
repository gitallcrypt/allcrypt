/*
SSH's binary packet protocol, RFC 4253 section 6, both directions.

    uint32  packet_length     (not counting itself or the MAC)
    byte    padding_length
    byte[]  payload
    byte[]  random padding    (at least 4 bytes)
    byte[]  MAC, or the AEAD tag

`packet_length + 4` must be a multiple of the cipher's block size (8 at
least) - or, where the length is not encrypted (encrypt-then-MAC, the
AEAD modes), `packet_length` alone must be.

`Sealer` and `Opener` hold one direction's cipher, MAC and sequence
number. Both are sans-I/O: bytes in, packets out.

# Pitfalls

**The receiver has to decrypt before it knows how much to read**, for
every cipher that encrypts the length: the first block is decrypted to
find the length, and the rest of the packet is decrypted after - with
the cipher state carried on, not restarted. ChaCha20-Poly1305 encrypts
the length with a key of its own precisely so it can be read alone; it
is authenticated with the rest only once the whole packet is in.

**Nothing from a packet is trusted before its MAC is checked**, except
the length, which has to be read to find the MAC at all - so it is
bounded (35000 bytes, RFC 4253 6.1's minimum, raised to 256 KiB as
OpenSSH does) before anything is buffered on its word.

**The sequence number counts every packet**, including the ones sent
before encryption starts, and wraps at 2^32. Strict key exchange
(`kex-strict-*-v00@openssh.com`) resets it at each NEWKEYS; without
that, an attacker who can delete or insert packets during the initial
exchange shifts it and the authentication of later packets with it
(Terrapin, CVE-2023-48795).
*/

use super::cipher::Cipher;
use super::kex::Fill;
use super::mac::Mac;

/// The largest packet accepted, as OpenSSH's PACKET_MAX_SIZE.
pub const MAX_PACKET: usize = 256 * 1024;

/// One direction's protection: a cipher, perhaps a MAC.
pub struct Keys {
    pub cipher: Cipher,
    pub mac: Option<Mac>,
}

impl Keys {
    /// No protection: what both directions use until the first NEWKEYS.
    pub fn none() -> Result<Keys, String> {
        Ok(Keys { cipher: Cipher::new("none", &[], &[], true)?, mac: None })
    }

    fn none_receiving() -> Result<Keys, String> {
        Ok(Keys { cipher: Cipher::new("none", &[], &[], false)?, mac: None })
    }

    /// Whether the length field travels unencrypted.
    fn length_in_clear(&self) -> bool {
        let spec = self.cipher.spec();
        spec.tag_len > 0 || self.mac.as_ref().is_some_and(|mac| mac.spec().etm)
    }

    fn tag_len(&self) -> usize {
        self.cipher.spec().tag_len + self.mac.as_ref().map_or(0, |mac| mac.spec().mac_len)
    }
}

/// The sending half.
pub struct Sealer {
    keys: Keys,
    pub sequence: u32,
}

impl Sealer {
    pub fn new() -> Result<Sealer, String> {
        Ok(Sealer { keys: Keys::none()?, sequence: 0 })
    }

    /// New keys, after sending NEWKEYS. `reset` is strict key exchange.
    pub fn rekey(&mut self, keys: Keys, reset: bool) {
        self.keys = keys;
        if reset {
            self.sequence = 0;
        }
    }

    /// One packet carrying `payload`, ready to send.
    pub fn seal(&mut self, payload: &[u8], fill: Fill<'_>) -> Result<Vec<u8>, String> {
        let block = self.keys.cipher.spec().block_size.max(8);
        let clear_length = self.keys.length_in_clear();
        // What must be a multiple of the block: the whole packet, or the
        // part after the length when the length is not encrypted.
        let covered = if clear_length { 1 + payload.len() } else { 5 + payload.len() };
        let mut padding = block - covered % block;
        if padding < 4 {
            padding += block;
        }
        let mut packet = Vec::with_capacity(5 + payload.len() + padding + self.keys.tag_len());
        packet.extend_from_slice(&((1 + payload.len() + padding) as u32).to_be_bytes());
        packet.push(padding as u8);
        packet.extend_from_slice(payload);
        let start = packet.len();
        packet.resize(start + padding, 0);
        fill(&mut packet[start..])?;

        let aad = if clear_length { 4 } else { 0 };
        let mut out = match &mut self.keys.mac {
            Some(mac) if !mac.spec().etm => {
                let tag = mac.compute(self.sequence, &packet)?;
                let mut sealed = self.keys.cipher.crypt(self.sequence, &packet, aad)?;
                sealed.extend_from_slice(&tag);
                sealed
            }
            _ => self.keys.cipher.crypt(self.sequence, &packet, aad)?,
        };
        if let Some(mac) = self.keys.mac.as_mut().filter(|mac| mac.spec().etm) {
            let tag = mac.compute(self.sequence, &out)?;
            out.extend_from_slice(&tag);
        }
        self.sequence = self.sequence.wrapping_add(1);
        Ok(out)
    }
}

/// The receiving half: feed it bytes, take payloads out.
pub struct Opener {
    keys: Keys,
    pub sequence: u32,
    buffer: Vec<u8>,
    /// For a cipher that encrypts the length: the first block, already
    /// decrypted, and the length it gave.
    first_block: Option<(Vec<u8>, usize)>,
}

impl Opener {
    pub fn new() -> Result<Opener, String> {
        Ok(Opener { keys: Keys::none_receiving()?, sequence: 0, buffer: Vec::new(),
                    first_block: None })
    }

    /// New keys, after receiving NEWKEYS.
    pub fn rekey(&mut self, keys: Keys, reset: bool) {
        self.keys = keys;
        if reset {
            self.sequence = 0;
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Bytes received and not yet part of a packet.
    pub fn buffered(&self) -> &[u8] {
        &self.buffer
    }

    /// Take bytes off the front without decrypting them - the version
    /// line, which precedes every packet.
    pub fn take_line(&mut self) -> Option<Vec<u8>> {
        let end = self.buffer.windows(2).position(|pair| pair == b"\r\n")
            .map(|at| at + 2)
            .or_else(|| self.buffer.iter().position(|b| *b == b'\n').map(|at| at + 1))?;
        Some(self.buffer.drain(..end).collect())
    }

    fn check_length(length: usize, block: usize, clear: bool) -> Result<(), String> {
        let covered = if clear { length } else { length + 4 };
        if !(5..=MAX_PACKET).contains(&length) || !covered.is_multiple_of(block) {
            return Err(format!("SSH: a packet length of {length} is not one this \
                                connection can carry."));
        }
        Ok(())
    }

    /// The next whole packet's payload, or `None` until more bytes arrive.
    pub fn open(&mut self) -> Result<Option<Vec<u8>>, String> {
        let block = self.keys.cipher.spec().block_size.max(8);
        let tag_len = self.keys.tag_len();
        let clear = self.keys.length_in_clear();
        let spec_name = self.keys.cipher.spec().name;

        let length = if spec_name == "chacha20-poly1305@openssh.com" {
            if self.buffer.len() < 4 {
                return Ok(None);
            }
            self.keys.cipher.peek_length(self.sequence, &self.buffer[..4])? as usize
        } else if clear {
            if self.buffer.len() < 4 {
                return Ok(None);
            }
            u32::from_be_bytes(self.buffer[..4].try_into().map_err(|_| "length")?) as usize
        } else {
            match &self.first_block {
                Some((_, length)) => *length,
                None => {
                    if self.buffer.len() < block {
                        return Ok(None);
                    }
                    let first: Vec<u8> = self.buffer.drain(..block).collect();
                    let plain = self.keys.cipher.crypt(self.sequence, &first, 0)?;
                    let length = u32::from_be_bytes(plain[..4].try_into()
                        .map_err(|_| "length")?) as usize;
                    Self::check_length(length, block, false)?;
                    self.first_block = Some((plain, length));
                    length
                }
            }
        };
        let in_clear_length = clear || spec_name == "chacha20-poly1305@openssh.com";
        Self::check_length(length, block, in_clear_length)?;

        let packet = if in_clear_length {
            let total = 4 + length + tag_len;
            if self.buffer.len() < total {
                return Ok(None);
            }
            let sealed: Vec<u8> = self.buffer.drain(..total).collect();
            let (body, mac_tag) = sealed.split_at(4 + length + self.keys.cipher.spec().tag_len);
            if let Some(mac) = &mut self.keys.mac {
                if !mac.verify(self.sequence, body, mac_tag)? {
                    return Err("SSH: a packet failed its MAC.".to_string());
                }
            }
            self.keys.cipher.crypt(self.sequence, body, 4)?
        } else {
            let (first_plain, _) = self.first_block.as_ref().ok_or("state")?;
            let rest = 4 + length - first_plain.len();
            if self.buffer.len() < rest + tag_len {
                return Ok(None);
            }
            let sealed: Vec<u8> = self.buffer.drain(..rest + tag_len).collect();
            let (body, mac_tag) = sealed.split_at(rest);
            let mut plain = self.first_block.take().ok_or("state")?.0;
            plain.extend_from_slice(&self.keys.cipher.crypt(self.sequence, body, 0)?);
            if let Some(mac) = &mut self.keys.mac {
                if !mac.verify(self.sequence, &plain, mac_tag)? {
                    return Err("SSH: a packet failed its MAC.".to_string());
                }
            }
            plain
        };
        let padding = packet[4] as usize;
        if padding < 4 || 5 + padding > packet.len() {
            return Err(format!("SSH: a packet's padding length of {padding} does not fit."));
        }
        self.sequence = self.sequence.wrapping_add(1);
        Ok(Some(packet[5..packet.len() - padding].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::cipher::CIPHERS;
    use crate::ssh::mac::MACS;

    fn keys(cipher: &str, mac: Option<&str>, sending: bool) -> Keys {
        let spec = crate::ssh::cipher::lookup(cipher).unwrap();
        let key: Vec<u8> = (0..spec.key_len as u8).collect();
        let iv = vec![9; spec.iv_len];
        Keys {
            cipher: Cipher::new(cipher, &key, &iv, sending).unwrap(),
            mac: mac.map(|name| {
                let spec = crate::ssh::mac::lookup(name).unwrap();
                Mac::new(name, &vec![3; spec.key_len]).unwrap()
            }),
        }
    }

    /// Every cipher with every MAC (or none, for the AEAD ciphers), in
    /// pieces of every awkward size, several packets in a row.
    #[test]
    fn test_packets_survive_every_cipher_and_mac_fed_a_byte_at_a_time() {
        let mut fill = |buf: &mut [u8]| crate::random::fill(buf);
        for cipher in CIPHERS {
            let macs: Vec<Option<&str>> = if cipher.tag_len > 0 {
                vec![None]
            } else {
                MACS.iter().map(|mac| Some(mac.name)).collect()
            };
            for mac in macs {
                let mut sealer = Sealer::new().unwrap();
                let mut opener = Opener::new().unwrap();
                sealer.rekey(keys(cipher.name, mac, true), false);
                opener.rekey(keys(cipher.name, mac, false), false);
                let mut wire = Vec::new();
                let payloads: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 1 + 37 * i]).collect();
                for payload in &payloads {
                    wire.extend_from_slice(&sealer.seal(payload, &mut fill).unwrap());
                }
                let mut out = Vec::new();
                for byte in &wire {
                    opener.push(&[*byte]);
                    while let Some(payload) = opener.open().unwrap() {
                        out.push(payload);
                    }
                }
                assert_eq!(out, payloads, "{} {:?}", cipher.name, mac);
                assert_eq!(opener.sequence, 4);
            }
        }
    }

    #[test]
    fn test_a_flipped_bit_is_refused() {
        let mut fill = |buf: &mut [u8]| crate::random::fill(buf);
        for (cipher, mac) in [("aes128-ctr", Some("hmac-sha2-256")),
                              ("aes128-ctr", Some("hmac-sha2-256-etm@openssh.com")),
                              ("aes256-gcm@openssh.com", None),
                              ("chacha20-poly1305@openssh.com", None)] {
            let mut sealer = Sealer::new().unwrap();
            sealer.rekey(keys(cipher, mac, true), false);
            let wire = sealer.seal(b"a payload", &mut fill).unwrap();
            let mut broken = wire.clone();
            let last = broken.len() - 1;
            broken[last] ^= 1;
            let mut opener = Opener::new().unwrap();
            opener.rekey(keys(cipher, mac, false), false);
            opener.push(&broken);
            assert!(opener.open().is_err(), "{cipher} {mac:?}");
        }
    }
}
