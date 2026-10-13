//! Tiger, Tiger2, HAVAL and Snefru against `vectors/tiger_haval_snefru.vec`
//! (PHP, sphlib, RHash, mhash and Botan 1.10.17, two to four of them
//! agreeing on every catalogued name, Botan alone on Tiger past four
//! passes; written by
//! `scripts/make_tiger_haval_snefru_vectors.py`). Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyHash, HASHES};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/tiger_haval_snefru.vec");

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
    assert_eq!(messages.len(), 30);
    messages
}

fn rows() -> Vec<(String, usize, Vec<u8>)> {
    let rows: Vec<_> = VECTORS.lines().filter(|l| l.starts_with("hash ")).map(|line| {
        let f = fields(line);
        (f["name"].to_string(), f["msg"].parse().unwrap(), unhex(f["digest"]))
    }).collect();
    assert_eq!(rows.len(), 780);
    rows
}

fn names() -> Vec<&'static str> {
    HASHES.iter().copied()
        .filter(|n| n.starts_with("tiger") || n.starts_with("haval") || n.starts_with("snefru"))
        .collect()
}

#[test]
fn test_every_name_against_its_witnesses() {
    let messages = messages();
    let rows = rows();
    assert_eq!(names().len(), 24);
    // Every catalogued name, and Tiger at five and six passes, where
    // the loop after the third pass runs more than once (Botan's rows).
    for name in names().into_iter().chain(["tiger192_5", "tiger160_6"]) {
        assert_eq!(rows.iter().filter(|r| r.0 == name).count(), 30, "{name}");
    }
    for (name, msg, digest) in rows {
        let message = &messages[msg];
        let mut h = AnyHash::new(&name).unwrap();
        assert_eq!(h.name(), name);
        assert_eq!(h.digest_len(), digest.len());
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
fn test_the_spellings_other_software_uses() {
    let messages = messages();
    let rows = rows();
    let find = |name: &str| rows.iter().find(|r| r.0 == name && r.1 == 29).unwrap().2.clone();
    let message = &messages[29];
    for (spelling, name) in [("tiger192_3", "tiger"), ("TIGER192,3", "tiger"),
                             ("tiger128,4", "tiger128_4"), ("HAVAL256,5", "haval256_5"),
                             ("HAVAL160-4", "haval160_4"), ("snefru", "snefru256"),
                             ("SNEFRU128", "snefru128")] {
        let mut h = AnyHash::new(spelling).unwrap();
        h.update(message);
        assert_eq!(h.digest(), find(name), "{spelling}");
    }
}

#[test]
fn test_what_is_not_a_tiger_or_a_haval_is_refused() {
    for name in ["tiger256_3", "tiger192_2", "tiger64_3", "haval256_6", "haval256_2",
                 "haval100_3", "tiger_3", "haval256_"] {
        assert!(AnyHash::new(name).is_err(), "{name}");
    }
}

#[test]
fn test_the_shorter_forms_are_the_longer_cut_short_for_tiger_alone() {
    // Tiger's 128 and 160 bit forms are truncations; HAVAL's fold the
    // whole state into the shorter output, so theirs must not be.
    let message = &messages()[29];
    let digest = |name: &str| {
        let mut h = AnyHash::new(name).unwrap();
        h.update(message);
        h.digest()
    };
    for passes in [3, 4] {
        let full = digest(&format!("tiger192_{passes}"));
        assert_eq!(digest(&format!("tiger128_{passes}")), full[..16]);
        assert_eq!(digest(&format!("tiger160_{passes}")), full[..20]);
    }
    for passes in [3, 4, 5] {
        let full = digest(&format!("haval256_{passes}"));
        for bits in [128, 160, 192, 224] {
            let short = digest(&format!("haval{bits}_{passes}"));
            assert_ne!(short, full[..bits / 8], "haval{bits}_{passes}");
        }
    }
}
