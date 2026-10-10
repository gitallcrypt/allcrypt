//! Kupyna (DSTU 7564:2014) against `vectors/kupyna.vec`: the standard's
//! byte-aligned examples, rows on which the authors' reference
//! implementation and Bouncy Castle 1.77 agree for 256, 384 and 512 bits,
//! and the reference alone for other sizes, written by
//! `scripts/make_kupyna_vectors.py`. Offline.

use std::collections::BTreeMap;

use allcrypt::api::AnyHash;
use allcrypt::hash_functions::kupyna::Kupyna;
use allcrypt::hash_functions::HashFunction;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_kupyna_vectors() {
    let mut per_source: BTreeMap<(usize, &str), usize> = BTreeMap::new();
    for line in include_str!("../vectors/kupyna.vec").lines() {
        if !line.starts_with("kupyna ") {
            continue;
        }
        let f: BTreeMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let bits: usize = f["bits"].parse().unwrap();
        let (msg, digest) = (unhex(f["msg"]), unhex(f["digest"]));

        let mut one = Kupyna::new(bits).unwrap();
        one.update(&msg);
        assert_eq!(one.digest(), digest, "kupyna-{bits} of {} bytes", msg.len());
        // In uneven pieces too.
        let mut pieces = Kupyna::new(bits).unwrap();
        for chunk in msg.chunks(37) {
            pieces.update(chunk);
        }
        assert_eq!(pieces.digest(), digest);
        if [256, 384, 512].contains(&bits) {
            let mut any = AnyHash::new(&format!("kupyna{bits}")).unwrap();
            any.update(&msg);
            assert_eq!(any.digest(), digest);
        }
        *per_source.entry((bits, f["source"])).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    for bits in [256, 384, 512] {
        assert!(per_source[&(bits, "both")] >= 19, "{bits}");
        assert!(per_source[&(bits, "standard")] >= 1, "{bits}");
    }
    assert_eq!(per_source.values().sum::<usize>(), 112);
}

#[test]
fn test_the_catalogue_names() {
    for bits in [256, 384, 512] {
        let h = AnyHash::new(&format!("kupyna{bits}")).unwrap();
        assert_eq!(h.name(), format!("kupyna{bits}"));
        assert_eq!(h.digest_len(), bits / 8);
        assert_eq!(h.block_size(), if bits == 256 { 64 } else { 128 });
    }
}
