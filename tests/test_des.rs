//! DES and Triple DES against the published vectors.
//!
//! The unit tests in `src/block_ciphers/des.rs` cover the tables and the
//! structure; this is the outside view, through the same trait every other
//! cipher uses, plus the modes - because a cipher with an 8 byte block
//! exercises the mode code differently from one with 16, and every mode in
//! this library was written and tested against AES first.

use allcrypt::block_ciphers::des::{Des, TripleDes};
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_des_block() {
    // The vector the old, commented-out version of this file carried,
    // which never ran because the cipher was a stub with empty block
    // functions and was commented out of mod.rs.
    let key = unhex("1234567812345678");
    let plain = vec![0xffu8; 8];

    let mut cipher = Des::new(&key).unwrap();
    let mut encrypted = Vec::new();
    cipher.block_encrypt(&plain, &mut encrypted);

    let mut decrypted = Vec::new();
    cipher.block_decrypt(&encrypted, &mut decrypted);
    assert_eq!(decrypted, plain);

    // And the standard's own worked example, which is the one to trust.
    let mut cipher = Des::new(&unhex("133457799bbcdff1")).unwrap();
    let mut out = Vec::new();
    cipher.block_encrypt(&unhex("0123456789abcdef"), &mut out);
    assert_eq!(hex(&out), "85e813540f0ab405");
}

/// Every mode, over an 8 byte block. The modes were all written against
/// AES, where the block is 16 - a mode that hardcoded that anywhere works
/// perfectly for AES and fails only here.
#[test]
fn test_des_through_every_mode() {
    let key = unhex("133457799bbcdff1");
    let iv = unhex("0011223344556677");

    for length in [8usize, 16, 24, 64, 800] {
        let plaintext: Vec<u8> = (0..length).map(|i| (i * 7) as u8).collect();

        for mode in ["ecb", "cbc"] {
            let mut cipher = Des::new(&key).unwrap();
            let mut encrypted = Vec::new();
            match mode {
                "ecb" => cipher.ecb_encrypt(&plaintext, &mut encrypted).unwrap(),
                _ => cipher.cbc_encrypt(&plaintext, &mut encrypted, &iv).unwrap(),
            }
            assert_eq!(encrypted.len(), length, "{} grew the input", mode);

            let mut cipher = Des::new(&key).unwrap();
            let mut decrypted = Vec::new();
            match mode {
                "ecb" => cipher.ecb_decrypt(&encrypted, &mut decrypted).unwrap(),
                _ => cipher.cbc_decrypt(&encrypted, &mut decrypted, &iv).unwrap(),
            }
            assert_eq!(decrypted, plaintext, "{} at {} bytes", mode, length);
        }
    }

    // The byte-at-a-time modes take any length, including ones that are
    // not a multiple of 8.
    for length in [1usize, 7, 9, 100, 333] {
        let plaintext: Vec<u8> = (0..length).map(|i| (i * 11) as u8).collect();
        for mode in ["cfb", "ofb", "ctr"] {
            let mut cipher = Des::new(&key).unwrap();
            let mut encrypted = Vec::new();
            match mode {
                "cfb" => cipher.cfb_encrypt(&plaintext, &mut encrypted, &iv).unwrap(),
                "ofb" => cipher.ofb_encrypt(&plaintext, &mut encrypted, &iv).unwrap(),
                _ => cipher.ctr_encrypt(&plaintext, &mut encrypted, &iv).unwrap(),
            }
            assert_eq!(encrypted.len(), length);

            let mut cipher = Des::new(&key).unwrap();
            let mut decrypted = Vec::new();
            match mode {
                "cfb" => cipher.cfb_decrypt(&encrypted, &mut decrypted, &iv).unwrap(),
                "ofb" => cipher.ofb_decrypt(&encrypted, &mut decrypted, &iv).unwrap(),
                _ => cipher.ctr_decrypt(&encrypted, &mut decrypted, &iv).unwrap(),
            }
            assert_eq!(decrypted, plaintext, "{} at {} bytes", mode, length);
        }
    }
}

/// GCM needs a 128 bit block and must refuse an 8 byte one rather than
/// improvising something smaller.
#[test]
fn test_des_cannot_do_gcm() {
    let key = unhex("0123456789abcdef23456789abcdef01456789abcdef0123");
    let mut cipher = TripleDes::new(&key).unwrap();
    let mut out = Vec::new();
    let mut tag = Vec::new();
    let error = cipher.gcm_encrypt(b"data", &mut out, &[0; 12], &mut tag, &[])
        .unwrap_err();
    assert!(error.contains("128 bit"), "{}", error);
    assert!(out.is_empty());
}

#[test]
fn test_triple_des_block() {
    // NIST's Triple DES example, three distinct keys.
    let key = unhex("0123456789abcdef23456789abcdef01456789abcdef0123");
    let mut cipher = TripleDes::new(&key).unwrap();
    let mut encrypted = Vec::new();
    cipher.block_encrypt(&unhex("0123456789abcdef"), &mut encrypted);

    let mut cipher = TripleDes::new(&key).unwrap();
    let mut decrypted = Vec::new();
    cipher.block_decrypt(&encrypted, &mut decrypted);
    assert_eq!(hex(&decrypted), "0123456789abcdef");
}
