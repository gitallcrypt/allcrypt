//! VMAC against `vectors/vmac.vec`, written by `scripts/make_vmac_vectors.py`:
//! Crypto++'s published tests, the draft's among them, and rows over seven
//! 128 bit ciphers, both tags and nonces of 1 to 16 bytes, on which
//! Crypto++ 8.9.0 and - for AES-128 with the 64 bit tag - the Linux
//! kernel's vmac64 agree. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api;
use allcrypt::mac::vmac::Vmac;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A message field: hex, or `r<count>:<unit hex>` for a long repetition.
fn message(field: &str) -> Vec<u8> {
    match field.strip_prefix('r').and_then(|rest| rest.split_once(':')) {
        Some((count, unit)) => unhex(unit).repeat(count.parse().unwrap()),
        None => unhex(field),
    }
}

#[test]
fn test_vmac_vectors() {
    let mut seen: BTreeMap<(String, usize, String), usize> = BTreeMap::new();
    let mut both = 0;
    for line in include_str!("../vectors/vmac.vec").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let (cipher, key, nonce, msg, tag) = (f["cipher"], unhex(f["key"]), unhex(f["nonce"]),
                                              message(f["msg"]), unhex(f["tag"]));
        assert_eq!(api::vmac(cipher, &key, &nonce, &msg, tag.len()).unwrap(), tag, "{line}");
        // One key, two messages: the key's state carries nothing over.
        let mut vmac = Vmac::new(cipher, &key, tag.len()).unwrap();
        let _ = vmac.tag(b"something else", &nonce).unwrap();
        assert_eq!(vmac.tag(&msg, &nonce).unwrap(), tag, "{line}");
        if f["witnesses"] == "cryptopp,kernel" {
            both += 1;
        }
        *seen.entry((cipher.to_string(), tag.len(), f["source"].to_string())).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(seen[&("aes".to_string(), 8, "cryptopp-tests".to_string())], 10, "{seen:?}");
    assert_eq!(seen[&("aes".to_string(), 16, "cryptopp-tests".to_string())], 10, "{seen:?}");
    for cipher in ["aes", "twofish", "serpent", "camellia", "aria", "seed", "sm4"] {
        for tag_len in [8usize, 16] {
            assert!(seen.get(&(cipher.to_string(), tag_len, "generated".to_string()))
                        .copied().unwrap_or(0) >= 13, "{cipher} {tag_len}: {seen:?}");
        }
    }
    assert!(both >= 40, "{both} rows with both witnesses");
}
