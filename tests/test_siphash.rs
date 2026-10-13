//! SipHash and HalfSipHash against the designers' own vectors
//! (`rfcs/siphash-vectors.h`, read here) and against `vectors/siphash.vec`
//! (the designers' reference, OpenSSL 3.5 and Bouncy Castle 1.77; written
//! by `scripts/make_siphash_vectors.py`). Offline.

use std::collections::HashMap;

use allcrypt::api;

const DESIGNERS: &str = include_str!("../rfcs/siphash-vectors.h");
const VECTORS: &str = include_str!("../vectors/siphash.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The rows of `const uint8_t NAME[64][N] = { { 0x.., ... }, ... };`.
fn table(name: &str) -> Vec<Vec<u8>> {
    let start = DESIGNERS.find(&format!("{name}[")).unwrap();
    let body = &DESIGNERS[start..];
    let body = &body[body.find('{').unwrap() + 1..body.find("};").unwrap()];
    body.split('}').filter(|row| row.contains("0x")).map(|row| {
        row.split("0x").skip(1).map(|b| u8::from_str_radix(&b[..2], 16).unwrap()).collect()
    }).collect()
}

#[test]
fn test_the_designers_vectors() {
    // The key is 00 01 02 ..., and message i is 00 01 ... i-1.
    let key: Vec<u8> = (0..16).collect();
    for (name, size, half) in [("vectors_sip64", 8, false), ("vectors_sip128", 16, false),
                               ("vectors_hsip32", 4, true), ("vectors_hsip64", 8, true)] {
        let rows = table(name);
        assert_eq!(rows.len(), 64, "{name}");
        for (i, expected) in rows.iter().enumerate() {
            assert_eq!(expected.len(), size, "{name} {i}");
            let message: Vec<u8> = (0..i as u8).collect();
            let got = if half {
                api::halfsiphash(&key[..8], &message, 2, 4, size)
            } else {
                api::siphash(&key, &message, 2, 4, size)
            };
            assert_eq!(&got.unwrap(), expected, "{name} {i}");
        }
    }
}

fn fields(line: &str) -> HashMap<&str, &str> {
    line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect()
}

#[test]
fn test_against_three_implementations() {
    let messages: Vec<Vec<u8>> = VECTORS.lines().filter(|l| l.starts_with("msg "))
        .map(|l| unhex(fields(l)["data"])).collect();
    let keys: Vec<Vec<u8>> = VECTORS.lines().filter(|l| l.starts_with("key "))
        .map(|l| unhex(fields(l)["data"])).collect();
    assert_eq!((messages.len(), keys.len()), (46, 2));
    let mut counts = HashMap::new();
    for line in VECTORS.lines().filter(|l| l.starts_with("mac ")) {
        let f = fields(line);
        let (c, d, size): (usize, usize, usize) =
            (f["c"].parse().unwrap(), f["d"].parse().unwrap(), f["size"].parse().unwrap());
        let key = &keys[f["key"].parse::<usize>().unwrap()];
        let message = &messages[f["msg"].parse::<usize>().unwrap()];
        let got = match f["kind"] {
            "siphash" => api::siphash(key, message, c, d, size),
            _ => api::halfsiphash(&key[..8], message, c, d, size),
        };
        assert_eq!(got.unwrap(), unhex(f["tag"]), "{line}");
        *counts.entry(f["kind"]).or_insert(0) += 1;
    }
    assert_eq!(counts["siphash"], 736);
    assert_eq!(counts["halfsiphash"], 736);
}

#[test]
fn test_what_is_refused() {
    assert!(api::siphash(&[0; 15], b"", 2, 4, 8).is_err());
    assert!(api::siphash(&[0; 16], b"", 2, 4, 12).is_err());
    assert!(api::siphash(&[0; 16], b"", 0, 4, 8).is_err());
    assert!(api::siphash(&[0; 16], b"", 2, 0, 8).is_err());
    assert!(api::halfsiphash(&[0; 16], b"", 2, 4, 4).is_err());
    assert!(api::halfsiphash(&[0; 8], b"", 2, 4, 16).is_err());
    // The 128 bit output is not the 64 bit one and another half.
    let short = api::siphash(&[1; 16], b"abc", 2, 4, 8).unwrap();
    let long = api::siphash(&[1; 16], b"abc", 2, 4, 16).unwrap();
    assert_ne!(short, long[..8]);
    let short = api::halfsiphash(&[1; 8], b"abc", 2, 4, 4).unwrap();
    let long = api::halfsiphash(&[1; 8], b"abc", 2, 4, 8).unwrap();
    assert_ne!(short, long[..4]);
}
