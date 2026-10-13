//! The SHA-3 finalists as their teams finally submitted them, against
//! `vectors/sha3_finalists.vec` (two or three implementations agreeing on
//! every row; written by `scripts/make_finalist_vectors.py`). Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyHash, HASHES};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/sha3_finalists.vec");
const NAMES: [&str; 25] = ["blake224", "blake256", "blake384", "blake512",
                           "groestl224", "groestl256", "groestl384", "groestl512",
                           "jh224", "jh256", "jh384", "jh512",
                           "skein256_128", "skein256_160", "skein256_224", "skein256_256",
                           "skein512_128", "skein512_160", "skein512_224", "skein512_256",
                           "skein512_384", "skein512_512",
                           "skein1024_384", "skein1024_512", "skein1024_1024"];
/// Reachable by name, not catalogued: one byte out, and outputs longer
/// than the state, which take several output blocks.
const MORE: [&str; 3] = ["skein256_8", "skein512_1032", "skein1024_2056"];

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
            unhex(f["data"])
        }).collect();
    assert_eq!(messages.len(), 34);
    messages
}

fn rows() -> Vec<(String, usize, Vec<u8>)> {
    let rows: Vec<_> = VECTORS.lines().filter(|l| l.starts_with("hash ")).map(|line| {
        let f = fields(line);
        (f["name"].to_string(), f["msg"].parse().unwrap(), unhex(f["digest"]))
    }).collect();
    assert_eq!(rows.len(), 952);
    rows
}

#[test]
fn test_every_name_against_its_witnesses() {
    let messages = messages();
    let rows = rows();
    for name in NAMES {
        assert!(HASHES.contains(&name), "{name} is not in the catalogue");
        assert_eq!(rows.iter().filter(|r| r.0 == name).count(), 34, "{name}");
    }
    for name in MORE {
        assert!(!HASHES.contains(&name), "{name}");
        assert_eq!(rows.iter().filter(|r| r.0 == name).count(), 34, "{name}");
    }
    for (name, msg, digest) in rows {
        let message = &messages[msg];
        let mut h = AnyHash::new(&name).unwrap();
        assert_eq!(h.name(), name);
        assert_eq!(h.digest_len(), digest.len());
        h.update(message);
        assert_eq!(h.digest(), digest, "{name} of {} bytes", message.len());
        assert_eq!(h.digest(), digest, "{name} digested twice");

        // In irregular pieces, with a digest taken midway, and under the
        // capitalised spelling.
        let mut pieces = AnyHash::new(&name.to_uppercase()).unwrap();
        let mut rest = &message[..];
        let mut step = 1;
        while !rest.is_empty() {
            let take = step.min(rest.len());
            pieces.update(&rest[..take]);
            rest = &rest[take..];
            step = step * 3 + 1;
            let _ = pieces.digest();
        }
        assert_eq!(pieces.digest(), digest, "{name} in pieces");
    }
}

#[test]
fn test_blake_is_not_blake2() {
    // Same permutations, same initial values, different hash: BLAKE2
    // changed the rounds, the padding and the parameter block.
    for (blake, blake2) in [("blake256", "blake2s"), ("blake512", "blake2b")] {
        let mut a = AnyHash::new(blake).unwrap();
        let mut b = AnyHash::new(blake2).unwrap();
        a.update(b"abc");
        b.update(b"abc");
        assert_ne!(a.digest(), b.digest(), "{blake}");
    }
}

#[test]
fn test_the_shorter_blakes_are_not_cut_short() {
    // BLAKE-224 and -384 start from SHA-224's and SHA-384's values and
    // pad with a different final bit, so neither is a prefix.
    for (short, long) in [("blake224", "blake256"), ("blake384", "blake512")] {
        let mut a = AnyHash::new(short).unwrap();
        let mut b = AnyHash::new(long).unwrap();
        a.update(b"abc");
        b.update(b"abc");
        let a = a.digest();
        assert_ne!(a, b.digest()[..a.len()], "{short}");
    }
}

#[test]
fn test_the_shorter_groestls_are_not_cut_short() {
    // The output length is in Grøstl's starting value.
    for (short, long) in [("groestl224", "groestl256"), ("groestl384", "groestl512")] {
        let mut a = AnyHash::new(short).unwrap();
        let mut b = AnyHash::new(long).unwrap();
        a.update(b"abc");
        b.update(b"abc");
        let a = a.digest();
        let b = b.digest();
        assert_ne!(a, b[..a.len()], "{short}");
        assert_ne!(a, b[b.len() - a.len()..], "{short}");
    }
}

#[test]
fn test_the_shorter_jhs_are_not_cut_short() {
    // JH's output is the end of its state, and the length is in its
    // starting value, so neither end of a longer digest is a shorter one.
    for (short, long) in [("jh224", "jh256"), ("jh384", "jh512"), ("jh256", "jh512")] {
        let mut a = AnyHash::new(short).unwrap();
        let mut b = AnyHash::new(long).unwrap();
        a.update(b"abc");
        b.update(b"abc");
        let a = a.digest();
        let b = b.digest();
        assert_ne!(a, b[..a.len()], "{short}");
        assert_ne!(a, b[b.len() - a.len()..], "{short}");
    }
    assert!(AnyHash::new("jh160").is_err());
}

#[test]
fn test_skein_names() {
    // A bare skein256 means Skein-256-256 to some software and
    // Skein-512-256 to others, so it is refused rather than guessed.
    for name in ["skein256", "skein512", "skein1024", "skein128_256", "skein512_0",
                 "skein512_100", "skein512_", "skein_256"] {
        assert!(AnyHash::new(name).is_err(), "{name}");
    }
    let mut a = AnyHash::new("SKEIN512-256").unwrap();
    assert_eq!(a.name(), "skein512_256");
    // The output length is in the configuration block, so a longer
    // output does not begin with a shorter one.
    let mut b = AnyHash::new("skein512_512").unwrap();
    a.update(b"abc");
    b.update(b"abc");
    let a = a.digest();
    assert_ne!(a, b.digest()[..a.len()]);
}
