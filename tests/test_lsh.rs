//! LSH (KS X 3262) against `vectors/lsh.vec` (KISA's reference and
//! Crypto++ agreeing on every row, go-krypto on the six named sizes;
//! written by `scripts/make_lsh_vectors.py`). Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyHash, HASHES};
use allcrypt::hash_functions::lsh::{Lsh256, Lsh512};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/lsh.vec");

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
    assert_eq!(messages.len(), 23);
    messages
}

fn rows() -> Vec<(String, usize, Vec<u8>)> {
    let rows: Vec<_> = VECTORS.lines().filter(|l| l.starts_with("hash ")).map(|line| {
        let f = fields(line);
        (f["name"].to_string(), f["msg"].parse().unwrap(), unhex(f["digest"]))
    }).collect();
    assert_eq!(rows.len(), 253);
    rows
}

#[test]
fn test_every_size_against_its_witnesses() {
    let messages = messages();
    let rows = rows();
    let named: Vec<&str> = HASHES.iter().copied().filter(|n| n.starts_with("lsh")).collect();
    assert_eq!(named.len(), 6);
    // The six the standard names, and five it allows and does not.
    for name in named.into_iter()
        .chain(["lsh256_8", "lsh256_120", "lsh512_8", "lsh512_200", "lsh512_504"]) {
        assert_eq!(rows.iter().filter(|r| r.0 == name).count(), 23, "{name}");
    }
    for (name, msg, digest) in rows {
        let message = &messages[msg];
        let mut h = AnyHash::new(&name).unwrap();
        assert_eq!(h.name(), name);
        assert_eq!(h.digest_len(), digest.len());
        assert_eq!(h.block_size(), if name.starts_with("lsh256") { 128 } else { 256 });
        h.update(message);
        assert_eq!(h.digest(), digest, "{name} of {} bytes", message.len());
        // Twice, and then carrying on, as hashlib allows.
        assert_eq!(h.digest(), digest, "{name} digested twice");

        // In irregular pieces, with a digest taken midway.
        let mut pieces = AnyHash::new(&name).unwrap();
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
fn test_the_standards_spelling() {
    let messages = messages();
    let rows = rows();
    let message = &messages[22];
    for (spelling, name) in [("LSH-256-224", "lsh256_224"), ("LSH-512-512", "lsh512_512"),
                             ("lsh512-256", "lsh512_256"), ("LSH256_256", "lsh256_256")] {
        let want = &rows.iter().find(|r| r.0 == name && r.1 == 22).unwrap().2;
        let mut h = AnyHash::new(spelling).unwrap();
        assert_eq!(h.name(), name);
        h.update(message);
        assert_eq!(&h.digest(), want, "{spelling}");
    }
}

#[test]
fn test_what_is_not_an_lsh_is_refused() {
    for name in ["lsh256_264", "lsh512_520", "lsh256_0", "lsh512_0", "lsh384_256",
                 "lsh256_12", "lsh256", "lsh512", "lsh", "lsh_", "lsh256_", "lsh_256",
                 "lsh256_256_1", "lsh256__256"] {
        assert!(AnyHash::new(name).is_err(), "{name}");
    }
    assert!(Lsh256::new(0).is_err());
    assert!(Lsh256::new(33).is_err());
    assert!(Lsh256::new(32).is_ok());
    assert!(Lsh512::new(0).is_err());
    assert!(Lsh512::new(65).is_err());
    assert!(Lsh512::new(64).is_ok());
}

#[test]
fn test_the_shorter_outputs_are_not_the_longer_cut_short() {
    // The output length is in the starting value, so every length is
    // its own function from the first block.
    let rows = rows();
    let find = |name: &str| rows.iter().find(|r| r.0 == name && r.1 == 22).unwrap().2.clone();
    assert_ne!(find("lsh256_224")[..], find("lsh256_256")[..28]);
    assert_ne!(find("lsh512_384")[..], find("lsh512_512")[..48]);
    assert_ne!(find("lsh512_256")[..], find("lsh256_256")[..]);
}
