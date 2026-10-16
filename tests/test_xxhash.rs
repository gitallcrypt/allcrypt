//! xxHash against `vectors/xxhash.vec`: XXH32, XXH64, XXH3-64 and
//! XXH3-128, seeded and with secrets, as PHP, the reference C, twox-hash,
//! OneOfOne/xxhash, cespare/xxhash, pierrec/xxHash and zeebo/xxh3 agree
//! on them (`scripts/make_xxhash_vectors.py`). Offline.

use std::collections::HashMap;

use allcrypt::api::{self, AnyHash, Xxh3, Xxh32, Xxh64};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/xxhash.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn fields(line: &str) -> HashMap<&str, &str> {
    line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect()
}

fn lines(kind: &str) -> impl Iterator<Item = HashMap<&'static str, &'static str>> + '_ {
    VECTORS.lines().filter(move |l| l.split(' ').next() == Some(kind)).map(fields)
}

fn messages() -> Vec<Vec<u8>> {
    let messages: Vec<Vec<u8>> = lines("msg").enumerate().map(|(i, f)| {
        assert_eq!(f["n"], i.to_string());
        match f.get("fill") {
            Some(byte) => vec![unhex(byte)[0]; f["len"].parse().unwrap()],
            None => unhex(f["data"]),
        }
    }).collect();
    assert_eq!(messages.len(), 59);
    messages
}

fn secrets() -> HashMap<&'static str, Vec<u8>> {
    let secrets: HashMap<_, _> = lines("secret").map(|f| (f["n"], unhex(f["data"]))).collect();
    assert_eq!(secrets.len(), 7);
    assert_eq!(secrets["short"].len(), api::XXH3_SECRET_MIN - 1);
    secrets
}

/// Streams `message` in pieces of 1, 4, 13 ... bytes, then a byte at a
/// time, and checks both against `value`.
fn streamed<H: Clone>(start: &H, message: &[u8], update: impl Fn(&mut H, &[u8]),
                      value: impl Fn(&H) -> Vec<u8>, expected: &[u8], label: &str) {
    let mut pieces = start.clone();
    let mut rest = message;
    let mut step = 1;
    while !rest.is_empty() {
        let take = step.min(rest.len());
        update(&mut pieces, &rest[..take]);
        rest = &rest[take..];
        step = step * 3 + 1;
        assert!(!value(&pieces).is_empty());
    }
    assert_eq!(value(&pieces), expected, "{label} in pieces");
    if message.len() <= 5000 {
        let mut bytes = start.clone();
        for byte in message.chunks(1) {
            update(&mut bytes, byte);
        }
        assert_eq!(value(&bytes), expected, "{label} a byte at a time");
    }
}

#[test]
fn test_every_seeded_row() {
    let messages = messages();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in lines("seeded") {
        let (name, message, expected) = (f["name"], &messages[f["msg"].parse::<usize>().unwrap()],
                                         unhex(f["value"]));
        let seed = u64::from_str_radix(f["seed"], 16).unwrap();
        let label = format!("{name} seed {seed:x} of {} bytes", message.len());
        *counts.entry(name).or_default() += 1;
        match name {
            "xxh32" => {
                let seed = u32::try_from(seed).unwrap();
                assert_eq!(api::xxh32(message, seed).to_be_bytes(), &expected[..], "{label}");
                streamed(&Xxh32::new(seed), message, |h, d| h.update(d),
                         |h| h.value().to_be_bytes().to_vec(), &expected, &label);
            }
            "xxh64" => {
                assert_eq!(api::xxh64(message, seed).to_be_bytes(), &expected[..], "{label}");
                streamed(&Xxh64::new(seed), message, |h, d| h.update(d),
                         |h| h.value().to_be_bytes().to_vec(), &expected, &label);
            }
            "xxh3" => {
                assert_eq!(api::xxh3_64(message, seed).to_be_bytes(), &expected[..], "{label}");
                streamed(&Xxh3::new(64, seed).unwrap(), message, |h, d| h.update(d),
                         |h| h.value(), &expected, &label);
            }
            "xxh128" => {
                assert_eq!(api::xxh3_128(message, seed).to_be_bytes(), &expected[..],
                           "{label}");
                let hash = Xxh3::new(128, seed).unwrap();
                streamed(&hash, message, |h, d| h.update(d), |h| h.value(), &expected, &label);
                // XXH3-64 is XXH3-128's low half at 1 to 3 bytes and above
                // 240, and nowhere else.
                if (1..=3).contains(&message.len()) || message.len() > 240 {
                    assert_eq!(api::xxh3_64(message, seed).to_be_bytes(), &expected[8..],
                               "{label}: the low half");
                }
            }
            other => panic!("{other}"),
        }
        if seed == 0 {
            let mut by_name = AnyHash::new(name).unwrap();
            assert_eq!(by_name.name(), name);
            assert_eq!(by_name.digest_len(), expected.len());
            by_name.update(message);
            assert_eq!(by_name.digest(), expected, "{label} by name");
            assert_eq!(by_name.digest(), expected, "{label} digested twice");
        }
    }
    assert_eq!(counts, HashMap::from([("xxh32", 4 * 59), ("xxh64", 7 * 59), ("xxh3", 7 * 59),
                                      ("xxh128", 7 * 59)]));
}

#[test]
fn test_every_row_with_a_secret() {
    let messages = messages();
    let secrets = secrets();
    let mut count = 0;
    for f in lines("keyed") {
        let (name, message, expected) = (f["name"], &messages[f["msg"].parse::<usize>().unwrap()],
                                         unhex(f["value"]));
        let secret = &secrets[f["secret"]];
        let label = format!("{name} with a secret of {} bytes, of {} bytes", secret.len(),
                            message.len());
        let bits = if name == "xxh3" { 64 } else { 128 };
        let one = if bits == 64 {
            api::xxh3_64_with_secret(message, secret).unwrap().to_be_bytes().to_vec()
        } else {
            api::xxh3_128_with_secret(message, secret).unwrap().to_be_bytes().to_vec()
        };
        assert_eq!(one, expected, "{label}");
        streamed(&Xxh3::with_secret(bits, secret).unwrap(), message, |h, d| h.update(d),
                 |h| h.value(), &expected, &label);
        count += 1;
    }
    assert_eq!(count, 2 * 6 * 59);
}

#[test]
fn test_the_short_secret_is_refused() {
    let secrets = secrets();
    let refused: Vec<_> = lines("refused").collect();
    assert_eq!(refused.len(), 2);
    for f in refused {
        let bits = if f["name"] == "xxh3" { 64 } else { 128 };
        let error = Xxh3::with_secret(bits, &secrets[f["secret"]]).err().unwrap();
        assert!(error.contains("136"), "{error}");
    }
    assert!(api::xxh3_64_with_secret(b"", &secrets["short"]).is_err());
    assert!(api::xxh3_128_with_secret(b"", &secrets["short"]).is_err());
}

/// The names XXH3 is also written by.
#[test]
fn test_xxh3s_other_names() {
    let messages = messages();
    for (spelling, name) in [("xxh3_64", "xxh3"), ("XXH3-64", "xxh3"), ("XXH3_128", "xxh128"),
                             ("XXH128", "xxh128")] {
        let mut h = AnyHash::new(spelling).unwrap();
        assert_eq!(h.name(), name, "{spelling}");
        h.update(&messages[20]);
        let expected = if name == "xxh3" {
            api::xxh3_64(&messages[20], 0).to_be_bytes().to_vec()
        } else {
            api::xxh3_128(&messages[20], 0).to_be_bytes().to_vec()
        };
        assert_eq!(h.digest(), expected, "{spelling}");
    }
    for name in ["xxh", "xxh16", "xxh3_32", "xxh256", "xxh3_256"] {
        assert!(AnyHash::new(name).is_err(), "{name}");
    }
}
