//! BLAKE3 against the BLAKE3 team's own test vectors
//! (`rfcs/blake3-test-vectors.json`, read here) and against
//! `vectors/blake3.vec` (their C and reference implementations and Bouncy
//! Castle agreeing; written by `scripts/make_blake3_vectors.py`).
//! Offline.

use std::collections::HashMap;

use allcrypt::api::{self, AnyHash, HASHES};
use allcrypt::hash_functions::HashFunction;

const TEAM: &str = include_str!("../rfcs/blake3-test-vectors.json");
const VECTORS: &str = include_str!("../vectors/blake3.vec");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The string value of `"name": "..."` at or after `at`.
fn field<'a>(text: &'a str, name: &str, at: usize) -> (&'a str, usize) {
    let key = format!("\"{name}\": ");
    let start = at + text[at..].find(&key).unwrap() + key.len();
    if let Some(rest) = text[start..].strip_prefix('"') {
        let end = rest.find('"').unwrap();
        (&rest[..end], start + 1 + end + 1)
    } else {
        let end = text[start..].find([',', '\n', '}']).unwrap();
        (text[start..start + end].trim(), start + end)
    }
}

#[test]
fn test_the_teams_vectors() {
    let (key, _) = field(TEAM, "key", 0);
    let (context, _) = field(TEAM, "context_string", 0);
    let key: [u8; 32] = key.as_bytes().try_into().unwrap();
    let mut at = TEAM.find("\"cases\"").unwrap();
    let mut cases = 0;
    while TEAM[at..].contains("\"input_len\"") {
        let (len, next) = field(TEAM, "input_len", at);
        let (hash, next) = field(TEAM, "hash", next);
        let (keyed, next) = field(TEAM, "keyed_hash", next);
        let (derive, next) = field(TEAM, "derive_key", next);
        at = next;
        cases += 1;
        let input: Vec<u8> = (0..len.parse::<usize>().unwrap()).map(|i| (i % 251) as u8).collect();
        for (expected, key, context) in [(hash, None, None), (keyed, Some(&key[..]), None),
                                         (derive, None, Some(context))] {
            let expected = unhex(expected);
            assert_eq!(expected.len(), 131);
            assert_eq!(api::blake3_xof(&input, 131, key, context, 0).unwrap(), expected,
                       "{len} bytes, key {key:?}, context {context:?}");
            // The digest is the first 32 bytes, whatever the pieces.
            let mut h = AnyHash::blake3(key, context).unwrap();
            for piece in input.chunks(1 + input.len() / 7) {
                h.update(piece);
            }
            assert_eq!(h.digest(), expected[..32]);
            assert_eq!(api::blake3_xof(&input, 40, key, context, 91).unwrap(), expected[91..]);
        }
    }
    assert_eq!(cases, 35);
}

fn fields(line: &str) -> HashMap<&str, &str> {
    line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect()
}

/// Message `n`: SHA-256 of "SEED:j" for j = 0, 1, 2 ..., cut.
fn message(seed: &str, length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut j = 0;
    while out.len() < length {
        let mut sha = AnyHash::new("sha256").unwrap();
        sha.update(format!("{seed}:{j}").as_bytes());
        out.extend(sha.digest());
        j += 1;
    }
    out.truncate(length);
    out
}

#[test]
fn test_against_three_implementations() {
    let key = unhex(VECTORS.lines().find_map(|l| l.strip_prefix("# KEY=")).unwrap());
    let context = VECTORS.lines().find_map(|l| l.strip_prefix("# CONTEXT=")).unwrap();
    let messages: Vec<Vec<u8>> = VECTORS.lines().filter(|l| l.starts_with("msg ")).map(|l| {
        let f = fields(l);
        message(f["seed"], f["len"].parse().unwrap())
    }).collect();
    assert_eq!(messages.len(), 28);
    let (mut out, mut seek) = (0, 0);
    for line in VECTORS.lines().filter(|l| l.starts_with("out ") || l.starts_with("seek ")) {
        if line.starts_with("out ") { out += 1 } else { seek += 1 }
        let f = fields(line);
        let (k, c) = match f["mode"] {
            "hash" => (None, None),
            "keyed" => (Some(&key[..]), None),
            _ => (None, Some(context)),
        };
        let message = &messages[f["msg"].parse::<usize>().unwrap()];
        let length: usize = f["length"].parse().unwrap();
        let offset: u64 = f["seek"].parse().unwrap();
        assert_eq!(api::blake3_xof(message, length, k, c, offset).unwrap(), unhex(f["digest"]),
                   "{line}");
    }
    assert_eq!((out, seek), (504, 27));
}

#[test]
fn test_streaming_in_irregular_pieces() {
    // Every split of a three-chunk message at a few awkward places,
    // with a digest taken midway: the chunk and block boundaries are
    // where held-back blocks are decided.
    let message = message("stream", 3 * 1024 + 1);
    let whole = api::blake3_xof(&message, 32, None, None, 0).unwrap();
    for first in [0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3072, 3073] {
        let mut h = AnyHash::new("BLAKE3").unwrap();
        h.update(&message[..first]);
        let _ = h.digest();
        for piece in message[first..].chunks(64) {
            h.update(piece);
        }
        assert_eq!(h.digest(), whole, "split at {first}");
    }
    assert!(HASHES.contains(&"blake3"));
}

#[test]
fn test_what_the_modes_refuse() {
    assert!(AnyHash::blake3(Some(&[0; 31]), None).is_err());
    assert!(AnyHash::blake3(Some(&[0; 33]), None).is_err());
    assert!(AnyHash::blake3(Some(&[0; 32]), Some("context")).is_err());
    // A key is not a context, and neither is the hash mode.
    let keyed = api::blake3_xof(b"abc", 32, Some(&[7; 32]), None, 0).unwrap();
    let plain = api::blake3_xof(b"abc", 32, None, None, 0).unwrap();
    let derived = api::blake3_xof(b"abc", 32, None, Some("context"), 0).unwrap();
    assert!(keyed != plain && plain != derived && keyed != derived);
}
