/*!
`vectors/xchacha.vec` against `allcrypt`'s HChaCha20, XChaCha20 and
XChaCha20-Poly1305: golang.org/x/crypto v0.37.0's answers, written by
`scripts/make_xchacha_vectors.py`. The draft's own vectors are read out of
`rfcs/draft-irtf-cfrg-xchacha-03.txt` by the unit tests in
`src/stream_ciphers`; these are another implementation's, at lengths
around the ChaCha and Poly1305 block sizes and at a block counter of
2^32 - 1.
*/

use allcrypt::api::{aead_decrypt, aead_encrypt, AnyStreamCipher};
use allcrypt::stream_ciphers::chacha::{hchacha20, xchacha20};
use allcrypt::stream_ciphers::StreamCipher;

const VECTORS: &str = include_str!("../vectors/xchacha.vec");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Each section's records, as field lists.
fn section(name: &str) -> Vec<Vec<(String, String)>> {
    let mut out: Vec<Vec<(String, String)>> = Vec::new();
    let mut inside = false;
    for line in VECTORS.lines() {
        let line = line.trim();
        if let Some(heading) = line.strip_prefix('[') {
            inside = heading.trim_end_matches(']') == name;
            continue;
        }
        if !inside || line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(" = ").unwrap_or((line.trim_end_matches(" ="), ""));
        if key == "Key" {
            out.push(Vec::new());
        }
        out.last_mut().unwrap().push((key.to_string(), value.to_string()));
    }
    out
}

fn get<'a>(record: &'a [(String, String)], key: &str) -> &'a str {
    &record.iter().find(|(k, _)| k == key).unwrap_or_else(|| panic!("no {key}")).1
}

#[test]
fn test_hchacha20_against_x_crypto() {
    let records = section("HChaCha20");
    assert_eq!(records.len(), 12);
    for r in records {
        let key: [u8; 32] = hex(get(&r, "Key")).try_into().unwrap();
        let nonce: [u8; 16] = hex(get(&r, "Nonce")).try_into().unwrap();
        assert_eq!(hchacha20(&key, &nonce).to_vec(), hex(get(&r, "Out")));
    }
}

#[test]
fn test_xchacha20_against_x_crypto() {
    let records = section("XChaCha20");
    assert_eq!(records.len(), 8);
    for r in records {
        let (key, nonce, input) = (hex(get(&r, "Key")), hex(get(&r, "Nonce")), hex(get(&r, "In")));
        let mut cipher = xchacha20(&key, &nonce).unwrap();
        cipher.set_counter(get(&r, "Counter").parse().unwrap()).unwrap();
        let mut out = Vec::new();
        cipher.crypt(&input, &mut out);
        assert_eq!(out, hex(get(&r, "Out")), "counter {}", get(&r, "Counter"));
        if get(&r, "Counter") == "0" {
            // The same through the facade's name.
            let mut facade = AnyStreamCipher::new("xchacha20", &key, &nonce).unwrap();
            assert_eq!(facade.update(&input).unwrap(), hex(get(&r, "Out")));
        }
    }
}

#[test]
fn test_xchacha20_poly1305_against_x_crypto() {
    let records = section("XChaCha20-Poly1305");
    assert_eq!(records.len(), 18);
    for r in records {
        let (key, nonce) = (hex(get(&r, "Key")), hex(get(&r, "Nonce")));
        let (aad, input) = (hex(get(&r, "AD")), hex(get(&r, "In")));
        let expected = hex(get(&r, "Out"));
        let (ciphertext, tag) = aead_encrypt("xchacha20-poly1305", &key, &nonce, &aad, &input)
            .unwrap();
        assert_eq!([ciphertext.clone(), tag.clone()].concat(), expected);
        assert_eq!(aead_decrypt("xchacha20-poly1305", &key, &nonce, &aad, &ciphertext, &tag)
                       .unwrap(), input);
        let mut bad = tag.clone();
        bad[0] ^= 1;
        assert!(aead_decrypt("xchacha20-poly1305", &key, &nonce, &aad, &ciphertext, &bad)
            .is_err());
    }
}
