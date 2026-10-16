//! MurmurHash3 against `vectors/murmur3.vec`: x86_32, x86_128 and
//! x64_128, seeded, as PHP, SMHasher's reference, the murmur3 crate,
//! murmurhash3js, spaolacci/murmur3 and twmb/murmur3 agree on them
//! (`scripts/make_murmur3_vectors.py`). Offline.

use std::collections::HashMap;

use allcrypt::api::{self, AnyHash, Murmur3, Murmur3Variant};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/murmur3.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn fields(line: &str) -> HashMap<&str, &str> {
    line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect()
}

fn messages() -> Vec<Vec<u8>> {
    let messages: Vec<Vec<u8>> = VECTORS.lines().filter(|l| l.starts_with("msg ")).enumerate()
        .map(|(i, line)| {
            let f = fields(line);
            assert_eq!(f["n"], i.to_string());
            match f.get("fill") {
                Some(byte) => vec![unhex(byte)[0]; f["len"].parse().unwrap()],
                None => unhex(f["data"]),
            }
        }).collect();
    assert_eq!(messages.len(), 50);
    messages
}

fn variant(name: &str) -> Murmur3Variant {
    match name {
        "murmur3_32" => Murmur3Variant::X86_32,
        "murmur3_x86_128" => Murmur3Variant::X86_128,
        "murmur3_x64_128" => Murmur3Variant::X64_128,
        other => panic!("{other}"),
    }
}

#[test]
fn test_every_row() {
    let messages = messages();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for line in VECTORS.lines().filter(|l| l.starts_with("hash ")) {
        let f = fields(line);
        let (name, message) = (f["name"], &messages[f["msg"].parse::<usize>().unwrap()]);
        let seed = u32::from_str_radix(f["seed"], 16).unwrap();
        let expected = unhex(f["value"]);
        let label = format!("{name} seed {seed:08x} of {} bytes", message.len());
        *counts.entry(name).or_default() += 1;

        let number = expected.iter().fold(0u128, |acc, &b| (acc << 8) | u128::from(b));
        match name {
            "murmur3_32" => assert_eq!(u128::from(api::murmur3_32(message, seed)), number),
            "murmur3_x86_128" => assert_eq!(api::murmur3_x86_128(message, seed), number),
            _ => assert_eq!(api::murmur3_x64_128(message, seed), number),
        }

        let start = Murmur3::new(variant(name), seed);
        let mut pieces = start.clone();
        let mut rest = &message[..];
        let mut step = 1;
        while !rest.is_empty() {
            let take = step.min(rest.len());
            pieces.update(&rest[..take]);
            rest = &rest[take..];
            step = step * 3 + 1;
            let _ = pieces.value();
        }
        assert_eq!(pieces.value(), expected, "{label} in pieces");
        assert_eq!(pieces.value_number(), number, "{label} as a number");
        if message.len() <= 5000 {
            let mut bytes = start.clone();
            for byte in message.chunks(1) {
                bytes.update(byte);
            }
            assert_eq!(bytes.value(), expected, "{label} a byte at a time");
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
    assert_eq!(counts, HashMap::from([("murmur3_32", 300), ("murmur3_x86_128", 300),
                                      ("murmur3_x64_128", 300)]));
}

/// PHP's names, and none that is not there.
#[test]
fn test_phps_names() {
    let messages = messages();
    for (spelling, name) in [("murmur3a", "murmur3_32"), ("MURMUR3C", "murmur3_x86_128"),
                             ("murmur3f", "murmur3_x64_128"), ("murmur3_x86_32", "murmur3_32"), ("Murmur3-x64-128",
                                                               "murmur3_x64_128")] {
        let mut h = AnyHash::new(spelling).unwrap();
        assert_eq!(h.name(), name, "{spelling}");
        h.update(&messages[40]);
        let mut by_type = Murmur3::new(variant(name), 0);
        by_type.update(&messages[40]);
        assert_eq!(h.digest(), by_type.value(), "{spelling}");
    }
    for name in ["murmur3", "murmur3b", "murmur3_64", "murmur3_x64_64", "murmur2", "murmur3_128"] {
        assert!(AnyHash::new(name).is_err(), "{name}");
    }
}
