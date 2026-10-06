//! WEP's encapsulation (IEEE 802.11-2020 12.3.2): RC4 under the 24-bit
//! IV followed by the key, over the plaintext and its CRC-32 integrity
//! check value, the ICV, little endian.
//!
//! **WEP is broken**, in every way it could be. The 24-bit IV repeats
//! within hours on a busy network, and RC4's keystream bytes after an IV
//! with a known prefix leak the key: Fluhrer, Mantin and Shamir (2001),
//! then Klein and PTW (2007) recover a 104-bit key from some tens of
//! thousands of frames. The CRC-32 is linear, so a frame can be altered
//! and its ICV fixed without the key. It is here because the frames
//! exist, and because TKIP reuses `seal` and `open` with its own RC4
//! key.

use crate::stream_ciphers::rc4::RC4;
use crate::stream_ciphers::StreamCipher;

fn rc4(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    RC4::new(key.to_vec())?.crypt(data, &mut out);
    Ok(out)
}

/// RC4 under `rc4_key` over `plaintext || CRC-32(plaintext)`.
pub fn seal(rc4_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut data = plaintext.to_vec();
    data.extend_from_slice(&crate::checksum::crc32(plaintext).to_le_bytes());
    rc4(rc4_key, &data).expect("an RC4 key of one byte or more")
}

/// The inverse of `seal`; a wrong key or an altered frame fails the ICV.
pub fn open(rc4_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 4 {
        return Err("A WEP body is at least its 4-byte ICV.".to_string());
    }
    let mut plain = rc4(rc4_key, ciphertext)?;
    let icv = plain.split_off(plain.len() - 4);
    if crate::checksum::crc32(&plain).to_le_bytes() != icv[..] {
        return Err("The ICV does not match: a wrong key, or the frame was damaged."
            .to_string());
    }
    Ok(plain)
}

/// WEP proper: the RC4 key is the frame's 3-byte IV followed by the
/// 5- or 13-byte shared key (WEP-40 and WEP-104), or any other length a
/// vendor allowed.
pub fn encrypt(key: &[u8], iv: &[u8; 3], plaintext: &[u8]) -> Vec<u8> {
    seal(&[&iv[..], key].concat(), plaintext)
}

pub fn decrypt(key: &[u8], iv: &[u8; 3], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    open(&[&iv[..], key].concat(), ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_and_icv() {
        let key = [0x1f; 5];
        let sealed = encrypt(&key, &[1, 2, 3], b"hello");
        assert_eq!(sealed.len(), 9);
        assert_eq!(decrypt(&key, &[1, 2, 3], &sealed).unwrap(), b"hello");
        assert!(decrypt(&key, &[1, 2, 4], &sealed).is_err());
        assert!(decrypt(&key, &[1, 2, 3], &sealed[..3]).is_err());
    }

    /// The RC4 key is IV first, then the shared key; the ICV is the
    /// CRC-32 little endian.
    #[test]
    fn test_layout() {
        let sealed = encrypt(b"ABCDE", &[9, 8, 7], b"x");
        let mut plain = Vec::new();
        RC4::new(b"\x09\x08\x07ABCDE".to_vec()).unwrap().crypt(&sealed, &mut plain);
        assert_eq!(plain[0], b'x');
        assert_eq!(plain[1..], crate::checksum::crc32(b"x").to_le_bytes());
    }

    /// The CRC is linear: XORing a difference into the ciphertext and the
    /// difference's CRC (without its constants) into the ICV gives a
    /// frame that still opens - the forgery that needs no key.
    #[test]
    fn test_the_icv_does_not_authenticate() {
        let key = [3u8; 13];
        let plain = b"pay 100 to alice";
        let mut sealed = encrypt(&key, &[0, 0, 1], plain);
        let mut delta = vec![0u8; plain.len()];
        delta[4] = b'1' ^ b'9';
        let crc = |d: &[u8]| crate::checksum::crc32(d) ^ crate::checksum::crc32(&vec![0; d.len()]);
        for (s, d) in sealed.iter_mut().zip(&delta) {
            *s ^= d;
        }
        for (s, d) in sealed[plain.len()..].iter_mut().zip(crc(&delta).to_le_bytes()) {
            *s ^= d;
        }
        assert_eq!(decrypt(&key, &[0, 0, 1], &sealed).unwrap(), b"pay 900 to alice");
    }
}
