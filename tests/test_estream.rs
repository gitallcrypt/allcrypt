//! Rabbit, HC-128, HC-256 and SOSEMANUK against `vectors/estream.vec`,
//! written by `scripts/make_estream_vectors.py`: Crypto++'s published
//! rows and generated ones, every row given by every witness that takes
//! the cipher - the eSTREAM submissions as SUPERCOP carries them,
//! Crypto++, libtomcrypt, Bouncy Castle and RustCrypto. Each keystream is
//! taken through the stream cipher facade, in one call and in pieces.
//! Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api::AnyStreamCipher;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_estream_vectors() {
    let mut seen: BTreeMap<(String, bool), usize> = BTreeMap::new();
    for line in include_str!("../vectors/estream.vec").lines() {
        if !line.starts_with("stream ") {
            continue;
        }
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let (cipher, key, iv, want) = (f["cipher"], unhex(f["key"]), unhex(f["iv"]),
                                       unhex(f["keystream"]));
        let zeros = vec![0u8; want.len()];
        let mut c = AnyStreamCipher::new(cipher, &key, &iv).unwrap();
        assert_eq!(c.encrypt(&zeros).unwrap(), want, "{}", &line[..line.len().min(120)]);
        // In pieces of 1, 2, 3 .. bytes.
        let mut c = AnyStreamCipher::new(cipher, &key, &iv).unwrap();
        let (mut got, mut at, mut piece) = (Vec::new(), 0, 1);
        while at < zeros.len() {
            let end = (at + piece).min(zeros.len());
            got.extend(c.update(&zeros[at..end]).unwrap());
            at = end;
            piece += 1;
        }
        assert_eq!(got, want, "{} in pieces", &line[..line.len().min(120)]);
        *seen.entry((cipher.to_string(), f["source"] == "generated")).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    for (cipher, published, generated) in [("rabbit", 260, 18), ("hc128", 80, 9),
                                            ("hc256", 3, 9), ("sosemanuk", 1, 35)] {
        assert_eq!(seen.get(&(cipher.to_string(), false)), Some(&published), "{seen:?}");
        assert!(seen[&(cipher.to_string(), true)] >= generated, "{cipher}: {seen:?}");
    }
}
