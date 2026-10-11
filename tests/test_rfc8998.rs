//! SM4-GCM and SM4-CCM against RFC 8998 appendix A, read out of the
//! vendored document at test time. GCM and CCM here are SP 800-38D's and
//! RFC 3610's over any 128 bit cipher; these two worked examples are the
//! published answers for one cipher other than AES.

use allcrypt::api::{aead_decrypt, aead_encrypt};

struct Vector {
    iv: Vec<u8>,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The section under `heading`, up to the next blank line after a tag.
/// Each label is followed by hex that may continue on lines holding hex
/// alone. The heading is matched at the start of a line, because the
/// table of contents holds it too, indented.
fn read(document: &str, heading: &str) -> Vector {
    let start = document.find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("no {heading}")) + 1;
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in document[start + heading.len()..].lines() {
        let trimmed = line.trim();
        if let Some((label, value)) = trimmed.split_once(':') {
            fields.push((label.trim().to_string(), value.trim().to_string()));
        } else if !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            fields.last_mut().expect("hex before any label").1.push_str(trimmed);
        } else if !trimmed.is_empty() {
            break;
        }
        if fields.len() == 6 && trimmed.is_empty() {
            break;
        }
    }
    let get = |label: &str| -> Vec<u8> {
        let found: Vec<_> = fields.iter().filter(|(l, _)| l == label).collect();
        assert_eq!(found.len(), 1, "{heading}: {label} {fields:?}");
        unhex(&found[0].1)
    };
    Vector {
        iv: get("Initialization Vector"),
        key: get("Key"),
        plaintext: get("Plaintext"),
        aad: get("Associated Data"),
        ciphertext: get("CipherText"),
        tag: get("Authentication Tag"),
    }
}

#[test]
fn test_rfc8998_appendix_a() {
    let document = include_str!("../rfcs/rfc8998.txt");
    let mut checked = 0;
    for (heading, aead) in [("A.1.  SM4-GCM Test Vectors", "sm4-gcm"),
                            ("A.2.  SM4-CCM Test Vectors", "sm4-ccm")] {
        let v = read(document, heading);
        // A parser that stops at the first line of a multi-line value
        // still finds every label; the lengths say whether it read on.
        assert_eq!((v.iv.len(), v.key.len(), v.plaintext.len(), v.aad.len(),
                    v.ciphertext.len(), v.tag.len()),
                   (12, 16, 64, 20, 64, 16), "{heading}");

        let (ciphertext, tag) = aead_encrypt(aead, &v.key, &v.iv, &v.aad, &v.plaintext)
            .unwrap();
        assert_eq!(ciphertext, v.ciphertext, "{aead}");
        assert_eq!(tag, v.tag, "{aead}");
        assert_eq!(aead_decrypt(aead, &v.key, &v.iv, &v.aad, &v.ciphertext, &v.tag).unwrap(),
                   v.plaintext);
        let mut altered = v.tag.clone();
        altered[15] ^= 1;
        assert!(aead_decrypt(aead, &v.key, &v.iv, &v.aad, &v.ciphertext, &altered).is_err());

        // Naming the default length is the same AEAD.
        let named = format!("{aead}-16");
        assert_eq!(aead_encrypt(&named, &v.key, &v.iv, &v.aad, &v.plaintext).unwrap().1, v.tag);

        // A shorter tag: GCM's is the full tag's prefix (SP 800-38D
        // MSB_t). CCM's is not, because its length is written into B0
        // and so is part of what the MAC covers.
        let (short_ciphertext, short) =
            aead_encrypt(&format!("{aead}-8"), &v.key, &v.iv, &v.aad, &v.plaintext).unwrap();
        assert_eq!(short_ciphertext, v.ciphertext);
        assert_eq!(short.len(), 8);
        if aead.ends_with("gcm") {
            assert_eq!(short, v.tag[..8]);
        } else {
            assert_ne!(short, v.tag[..8]);
        }
        checked += 1;
    }
    assert_eq!(checked, 2);
}
