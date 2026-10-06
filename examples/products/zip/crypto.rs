//! The two ways a ZIP entry is encrypted with a password.
//!
//! ## Traditional PKWARE encryption ("ZipCrypto")
//!
//! The cipher is the library's (`allcrypt::stream_ciphers::zipcrypto`).
//! What is ZIP's is the 12-byte header in front of the data: random
//! bytes whose last one (or two, in PKWARE's own writer) is a check
//! value, so a wrong password is caught 255 times in 256 before any data
//! is decrypted.
//!
//! ## WinZip AES (AE-1 and AE-2)
//!
//! The entry's method is 99 and an extra field (0x9901) holds the real
//! method and the key size. PBKDF2-HMAC-SHA1 with 1000 iterations turns
//! the password and an 8, 12 or 16 byte salt into an AES key, an HMAC
//! key and a two-byte password verifier. The data is AES in counter
//! mode with a **little-endian** counter starting at **1** - Brian
//! Gladman's `fileenc`, which WinZip adopted - and is authenticated by
//! the first 10 bytes of HMAC-SHA1 over the ciphertext. AE-2 differs
//! from AE-1 only in leaving the CRC-32 field zero, because a CRC of the
//! plaintext tells an attacker something about it.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::CtrState;
use allcrypt::hash_functions::sha1::SHA1;
use allcrypt::mac::hmac::Hmac;
use allcrypt::stream_ciphers::zipcrypto::ZipCrypto;

// ---------------------------------------------------------- ZipCrypto --

/// Decrypt a ZipCrypto entry's data. `check` is the byte the header's
/// last byte must decrypt to: the CRC's high byte, or the modification
/// time's high byte when the CRC follows the data in a descriptor and
/// was not known when the header was written.
pub fn zipcrypto_open(password: &[u8], data: &[u8], check: u8) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("A ZipCrypto entry shorter than its 12-byte header.".to_string());
    }
    let mut cipher = ZipCrypto::new(password);
    let mut header = [0u8; 12];
    header.copy_from_slice(&data[..12]);
    cipher.decrypt_in_place(&mut header);
    if header[11] != check {
        return Err("Wrong password.".to_string());
    }
    let mut out = data[12..].to_vec();
    cipher.decrypt_in_place(&mut out);
    Ok(out)
}

/// Encrypt, with a header of 10 random bytes and the CRC's top two
/// bytes, as PKWARE writes it; Info-ZIP's readers check only the last.
pub fn zipcrypto_seal(password: &[u8], data: &[u8], crc: u32) -> Result<Vec<u8>, String> {
    let mut header = allcrypt::api::random_bytes(12)?;
    header[10] = (crc >> 16) as u8;
    header[11] = (crc >> 24) as u8;
    let mut cipher = ZipCrypto::new(password);
    cipher.encrypt_in_place(&mut header);
    let mut body = data.to_vec();
    cipher.encrypt_in_place(&mut body);
    header.extend_from_slice(&body);
    Ok(header)
}

// --------------------------------------------------------- WinZip AES --

const AUTH_LEN: usize = 10;

/// Bytes of salt, and of key, for strength 1, 2 or 3.
pub fn aes_sizes(strength: u8) -> Result<(usize, usize), String> {
    match strength {
        1 => Ok((8, 16)),
        2 => Ok((12, 24)),
        3 => Ok((16, 32)),
        other => Err(format!("WinZip AES strength {other} is not 1, 2 or 3.")),
    }
}

struct AesKeys {
    cipher: Vec<u8>,
    mac: Vec<u8>,
    verifier: [u8; 2],
}

fn derive(password: &[u8], salt: &[u8], key_len: usize) -> Result<AesKeys, String> {
    let material = allcrypt::api::pbkdf2("sha1", password, salt, 1000, 2 * key_len + 2)?;
    Ok(AesKeys {
        cipher: material[..key_len].to_vec(),
        mac: material[key_len..2 * key_len].to_vec(),
        verifier: [material[2 * key_len], material[2 * key_len + 1]],
    })
}

/// AES-CTR as `fileenc` does it: the library's little-endian counter
/// mode, from a counter of 1.
fn ctr(key: &[u8], data: &mut [u8]) -> Result<(), String> {
    let mut cipher = AesCrypto::new(key.to_vec())?;
    CtrState::new_little_endian(&mut cipher, &1u128.to_le_bytes())?.apply(&mut cipher, data)
}

pub fn aes_open(password: &[u8], strength: u8, data: &[u8]) -> Result<Vec<u8>, String> {
    let (salt_len, key_len) = aes_sizes(strength)?;
    if data.len() < salt_len + 2 + AUTH_LEN {
        return Err("A WinZip AES entry too short for its salt and code.".to_string());
    }
    let salt = &data[..salt_len];
    let keys = derive(password, salt, key_len)?;
    if data[salt_len..salt_len + 2] != keys.verifier {
        return Err("Wrong password.".to_string());
    }
    let body = &data[salt_len + 2..data.len() - AUTH_LEN];
    let code = Hmac::mac(SHA1::new(&[]), &keys.mac, body);
    if code[..AUTH_LEN] != data[data.len() - AUTH_LEN..] {
        return Err("The authentication code does not match: the entry was changed \
                    (or the password collides on its verifier)."
            .to_string());
    }
    let mut out = body.to_vec();
    ctr(&keys.cipher, &mut out)?;
    Ok(out)
}

pub fn aes_seal(password: &[u8], strength: u8, data: &[u8]) -> Result<Vec<u8>, String> {
    let (salt_len, key_len) = aes_sizes(strength)?;
    let salt = allcrypt::api::random_bytes(salt_len)?;
    let keys = derive(password, &salt, key_len)?;
    let mut body = data.to_vec();
    ctr(&keys.cipher, &mut body)?;
    let code = Hmac::mac(SHA1::new(&[]), &keys.mac, &body);
    let mut out = salt;
    out.extend_from_slice(&keys.verifier);
    out.extend_from_slice(&body);
    out.extend_from_slice(&code[..AUTH_LEN]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zipcrypto_round_trips_and_catches_a_wrong_password_by_its_check_byte() {
        let data = b"some plaintext that is longer than a header".to_vec();
        let crc = allcrypt::checksum::crc32(&data);
        let sealed = zipcrypto_seal(b"secret", &data, crc).unwrap();
        assert_eq!(zipcrypto_open(b"secret", &sealed, (crc >> 24) as u8).unwrap(), data);
        // Over 64 wrong passwords, nearly all fail the one-byte check;
        // the ones that pass it decrypt to something else.
        let passed: Vec<Vec<u8>> = (0..64u8)
            .filter_map(|i| zipcrypto_open(&[b'x', i], &sealed, (crc >> 24) as u8).ok())
            .collect();
        assert!(passed.len() < 4);
        assert!(passed.iter().all(|plain| *plain != data));
    }

    #[test]
    fn test_aes_round_trips_at_every_strength_and_refuses_a_changed_byte() {
        for strength in 1..=3 {
            let data: Vec<u8> = (0..40u8).collect();
            let sealed = aes_seal(b"pw", strength, &data).unwrap();
            assert_eq!(aes_open(b"pw", strength, &sealed).unwrap(), data);
            let mut bent = sealed.clone();
            let at = bent.len() - 15;
            bent[at] ^= 1;
            assert!(aes_open(b"pw", strength, &bent).unwrap_err().contains("authentication"));
        }
        assert!(aes_sizes(4).is_err());
    }
}
