//! PMAC against `vectors/pmac.vec`, written by `scripts/make_pmac_vectors.py`:
//! Rogaway's fourteen published PMAC-AES tests, and rows over AES, DES,
//! 3DES and Blowfish on which libtomcrypt 1.18.2, RustCrypto's `pmac`
//! 0.7.1 and miscreant.go agree, each where it has the cipher. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api;
use allcrypt::mac::Pmac;
use allcrypt::Mac;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_pmac_vectors() {
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut longest = 0;
    for line in include_str!("../vectors/pmac.vec").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let (cipher, key, msg, tag) = (f["cipher"], unhex(f["key"]), unhex(f["msg"]),
                                       unhex(f["tag"]));
        assert_eq!(api::pmac(cipher, &key, &msg).unwrap(), tag, "{line}");
        // In pieces that straddle the block and the batch boundaries.
        let mut mac = Pmac::with_key(cipher, &key).unwrap();
        for chunk in msg.chunks(11) {
            mac.update(chunk);
        }
        assert_eq!(mac.digest(), tag, "{line}");
        longest = longest.max(msg.len() / mac.tag_len());
        *seen.entry((cipher.to_string(), f["source"].to_string())).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(seen[&("aes".to_string(), "rogaway".to_string())], 14, "{seen:?}");
    for cipher in ["aes", "des", "3des", "blowfish"] {
        assert!(seen.get(&(cipher.to_string(), "generated".to_string())).copied().unwrap_or(0) >= 12,
                "{cipher}: {seen:?}");
    }
    // Long enough to reach L(6), and more than one batch.
    assert!(longest >= 128, "{longest}");
}
