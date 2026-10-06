//! Traditional PKWARE encryption, "ZipCrypto" (PKWARE APPNOTE.TXT
//! section 6.1).
//!
//! PKWARE's own stream cipher, from 1989. Three 32-bit keys start at
//! fixed values and are updated by every byte of the password and then
//! by every byte of *plaintext*: the first is a CRC-32 register, the
//! second a linear congruential step on the first's low byte, the third
//! a CRC-32 register fed the second's top byte. Each keystream byte comes
//! from the low 16 bits of the third key.
//!
//! Because the keys absorb the plaintext, this is not a keystream XORed
//! onto the data: encrypting and decrypting are different operations
//! (each must feed the plaintext back, which decryption knows only after
//! the XOR), and encrypting a ciphertext does not give the plaintext.
//! That is why `ZipCrypto` does not implement `StreamCipher`, whose
//! single `crypt` has no direction.
//!
//! It is broken. Biham and Kocher (1994) recover the three keys from 12
//! bytes of known plaintext, with no need for the password; bkcrack is
//! the current implementation of that attack. The keys after the password
//! are the whole secret, so `from_keys` and `keys` exist for working with
//! such results.
//!
//! The 12-byte encryption header a ZIP entry carries in front of its data
//! is the format's, not the cipher's: it is ten random bytes and one or
//! two bytes of the entry's CRC or time, encrypted with everything else.

use crate::checksum::crc32_byte;

const INITIAL: [u32; 3] = [0x1234_5678, 0x2345_6789, 0x3456_7890];
const LCG_MULTIPLIER: u32 = 134_775_813;

#[derive(Clone)]
pub struct ZipCrypto {
    keys: [u32; 3],
}

impl ZipCrypto {
    /// The cipher keyed by a password. Any length is a password, the
    /// empty one included: it leaves the keys at their initial values.
    pub fn new(password: &[u8]) -> ZipCrypto {
        let mut cipher = ZipCrypto { keys: INITIAL };
        for &byte in password {
            cipher.absorb(byte);
        }
        cipher
    }

    /// The cipher in a given internal state: what a known-plaintext
    /// attack recovers in place of the password.
    pub fn from_keys(keys: [u32; 3]) -> ZipCrypto {
        ZipCrypto { keys }
    }

    /// The internal state.
    pub fn keys(&self) -> [u32; 3] {
        self.keys
    }

    fn absorb(&mut self, plain: u8) {
        self.keys[0] = crc32_byte(self.keys[0], plain);
        self.keys[1] = self.keys[1].wrapping_add(self.keys[0] & 0xff)
            .wrapping_mul(LCG_MULTIPLIER).wrapping_add(1);
        self.keys[2] = crc32_byte(self.keys[2], (self.keys[1] >> 24) as u8);
    }

    fn keystream_byte(&self) -> u8 {
        let temp = (self.keys[2] | 2) & 0xffff;
        (temp.wrapping_mul(temp ^ 1) >> 8) as u8
    }

    pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            let plain = *byte;
            *byte = plain ^ self.keystream_byte();
            self.absorb(plain);
        }
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            let plain = *byte ^ self.keystream_byte();
            self.absorb(plain);
            *byte = plain;
        }
    }

    /// Encrypt `input`, appending to `result`. The state carries on, so
    /// a message may be encrypted in pieces.
    pub fn encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.encrypt_in_place(&mut result[start..]);
    }

    /// Decrypt `input`, appending to `result`.
    pub fn decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.decrypt_in_place(&mut result[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 167 + 13) & 0xff) as u8).collect()
    }

    /// From a Python transcription of APPNOTE 6.1 written apart from this
    /// file, and decrypted back to the plaintext by CPython's `zipfile`.
    /// `scripts/diff_check.py hash` checks hundreds more against
    /// `zipfile` in both directions.
    #[test]
    fn test_a_vector_cpython_zipfile_decrypts() {
        let mut out = Vec::new();
        ZipCrypto::new(b"secret").encrypt(b"hello, world", &mut out);
        assert_eq!(crate::to_hex(&out), "A0254D7B73BEE67C15583A7E");
        let mut back = Vec::new();
        ZipCrypto::new(b"secret").decrypt(&out, &mut back);
        assert_eq!(back, b"hello, world");
    }

    #[test]
    fn test_the_empty_password_leaves_the_initial_keys() {
        assert_eq!(ZipCrypto::new(b"").keys(), INITIAL);
        assert_ne!(ZipCrypto::new(b"a").keys(), INITIAL);
    }

    /// The keys after a password are the cipher: a copy made with
    /// `from_keys` encrypts exactly as the original does.
    #[test]
    fn test_from_keys_is_the_password_s_state() {
        let keyed = ZipCrypto::new(b"secret");
        let mut a = keyed.clone();
        let mut b = ZipCrypto::from_keys(keyed.keys());
        let (mut x, mut y) = (Vec::new(), Vec::new());
        a.encrypt(&data(100), &mut x);
        b.encrypt(&data(100), &mut y);
        assert_eq!(x, y);
    }

    #[test]
    fn test_round_trip_in_pieces() {
        let plain = data(1000);
        let mut whole = Vec::new();
        ZipCrypto::new(b"pw").encrypt(&plain, &mut whole);
        for step in [1usize, 2, 7, 64, 333] {
            let mut cipher = ZipCrypto::new(b"pw");
            let mut pieces = Vec::new();
            for chunk in plain.chunks(step) {
                cipher.encrypt(chunk, &mut pieces);
            }
            assert_eq!(pieces, whole, "encrypting in pieces of {step}");
            let mut cipher = ZipCrypto::new(b"pw");
            let mut back = Vec::new();
            for chunk in whole.chunks(step) {
                cipher.decrypt(chunk, &mut back);
            }
            assert_eq!(back, plain, "decrypting in pieces of {step}");
        }
    }

    /// The keys absorb the plaintext, not the ciphertext: so encrypting
    /// twice does not undo itself, as it would for a keystream XOR, and
    /// a decryptor that fed back the ciphertext would go wrong from the
    /// second byte.
    #[test]
    fn test_the_plaintext_is_fed_back() {
        let plain = data(64);
        let mut once = Vec::new();
        ZipCrypto::new(b"pw").encrypt(&plain, &mut once);
        let mut twice = Vec::new();
        ZipCrypto::new(b"pw").encrypt(&once, &mut twice);
        assert_ne!(twice, plain);
        // The first byte is keyed by the password alone, so it agrees.
        assert_eq!(twice[0], plain[0]);
    }
}
