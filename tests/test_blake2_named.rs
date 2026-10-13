//! The BLAKE2 output lengths the catalogue names, BLAKE2b-128, -160, -256
//! and -384 and BLAKE2s-128 and -160, against `vectors/blake2_named.vec`
//! (hashlib, OpenSSL 3.5 and, for BLAKE2b, b2sum agree on every row;
//! written by `scripts/make_blake2_vectors.py`). Offline.

use allcrypt::api::{AnyHash, HASHES};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/blake2_named.vec");
const NAMES: [&str; 6] = ["blake2b_128", "blake2b_160", "blake2b_256", "blake2b_384",
                          "blake2s_128", "blake2s_160"];

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    VECTORS.lines().filter(|l| l.starts_with("hash ")).map(|line| {
        let f: std::collections::HashMap<_, _> =
            line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect();
        (f["name"].to_string(), unhex(f["msg"]), unhex(f["digest"]))
    }).collect()
}

#[test]
fn test_every_named_length_against_three_implementations() {
    let rows = rows();
    assert_eq!(rows.len(), 102);
    for name in NAMES {
        assert!(HASHES.contains(&name), "{name} is not in the catalogue");
        assert_eq!(rows.iter().filter(|r| r.0 == name).count(), 17, "{name}");
    }
    for (name, message, digest) in rows {
        let mut h = AnyHash::new(&name).unwrap();
        assert_eq!(h.name(), name);
        assert_eq!(h.digest_len(), digest.len());
        h.update(&message);
        assert_eq!(h.digest(), digest, "{name} of {} bytes", message.len());

        // In irregular pieces, and under the spellings other software
        // uses for the same function.
        let mut pieces = AnyHash::new(&name.to_uppercase().replace('_', "-")).unwrap();
        let mut rest = &message[..];
        let mut step = 1;
        while !rest.is_empty() {
            let take = step.min(rest.len());
            pieces.update(&rest[..take]);
            rest = &rest[take..];
            step = step * 3 + 1;
        }
        assert_eq!(pieces.digest(), digest, "{name} in pieces");
    }
}

#[test]
fn test_a_named_length_is_not_the_full_digest_cut_short() {
    for name in NAMES {
        let full = if name.starts_with("blake2b") { "blake2b" } else { "blake2s" };
        let mut short = AnyHash::new(name).unwrap();
        let mut long = AnyHash::new(full).unwrap();
        short.update(b"abc");
        long.update(b"abc");
        let short = short.digest();
        assert_ne!(short, long.digest()[..short.len()], "{name}");
    }
}
