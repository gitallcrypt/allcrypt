//! DSTU 7564's MAC over Kupyna against `vectors/kupyna_mac.vec`, written
//! by `scripts/make_kupyna_mac_vectors.py`: the standard's three
//! examples and Bouncy Castle's other three, rows on which Bouncy Castle
//! 1.77, cryptonite and the reference implementation all agree, rows the
//! first two agree on, and long keys from Bouncy Castle alone. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api;
use allcrypt::hash_functions::kupyna::KupynaMac;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_kupyna_mac_vectors() {
    let mut seen: BTreeMap<(usize, String), usize> = BTreeMap::new();
    for line in include_str!("../vectors/kupyna_mac.vec").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let bits: usize = f["bits"].parse().unwrap();
        let (key, msg, mac) = (unhex(f["key"]), unhex(f["msg"]), unhex(f["mac"]));
        assert_eq!(api::kupyna_mac(bits, &key, &msg).unwrap(), mac, "{line}");
        // In pieces, and through verify.
        let mut m = KupynaMac::new(bits, &key).unwrap();
        for chunk in msg.chunks(29) {
            m.update(chunk);
        }
        assert!(m.verify(&mac), "{line}");
        let mut wrong = mac.clone();
        wrong[mac.len() - 1] ^= 1;
        assert!(!m.verify(&wrong));
        *seen.entry((bits, f["source"].to_string())).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    let count = |source: &str| seen.iter().filter(|((_, s), _)| s == source)
        .map(|(_, n)| n).sum::<usize>();
    assert_eq!(count("standard"), 3, "{seen:?}");
    assert_eq!(count("bouncycastle-tests"), 3, "{seen:?}");
    for bits in [256usize, 384, 512] {
        for (source, at_least) in [("all", 9), ("both", 30), ("bouncycastle", 8)] {
            assert!(seen.get(&(bits, source.to_string())).copied().unwrap_or(0) >= at_least,
                    "{bits} {source}: {seen:?}");
        }
    }
}
