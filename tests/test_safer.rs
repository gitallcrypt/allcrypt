//! SAFER K-64, K-128, SK-64 and SK-128 against `vectors/safer.vec`,
//! written by `scripts/make_safer_vectors.py`: libtomcrypt 1.18.2 and
//! Crypto++ 8.9.0 agree on every row from 6 to 13 rounds, and Botan
//! 1.10.17 on SK-128 as well, from 1 round. The published tests the
//! three carry at the round counts their projects run them, NESSIE's test
//! sets in shape at each variant's usual count - every single-bit key and
//! block, every byte repeated, so every entry of `exp` and `log` - random
//! blocks at every other count, and iterated runs. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::safer::{Safer, SaferVariant};
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

const VARIANTS: [(&str, SaferVariant); 4] = [("safer-k64", SaferVariant::K64),
                                              ("safer-k128", SaferVariant::K128),
                                              ("safer-sk64", SaferVariant::Sk64),
                                              ("safer-sk128", SaferVariant::Sk128)];

struct Row {
    kind: String,
    rounds: usize,
    key: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    n: usize,
    published: bool,
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/safer.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows: Vec<Row> = text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let kind = line.split(' ').next().unwrap().to_string();
            let f: HashMap<&str, &str> = line.split(' ').skip(1)
                .map(|w| w.split_once('=').unwrap()).collect();
            Row { kind, rounds: f["rounds"].parse().unwrap(), key: unhex(f["key"]),
                  pt: unhex(f["pt"]), ct: unhex(f["ct"]),
                  n: f.get("n").map_or(1, |n| n.parse().unwrap()),
                  published: f.get("src") == Some(&"published") }
        })
        .collect();
    assert_eq!(rows.len(), declared);
    rows
}

fn variant(kind: &str) -> SaferVariant {
    let name = kind.strip_suffix("-iter").unwrap_or(kind);
    VARIANTS.iter().find(|(n, _)| *n == name).unwrap().1
}

#[test]
fn test_safer_vectors() {
    let rows = rows();
    for (name, want_published, want_rounds) in [("safer-k64", 5, 6..=13), ("safer-k128", 4, 6..=13),
                                                ("safer-sk64", 5, 6..=13),
                                                ("safer-sk128", 17, 1..=13)] {
        let (mut single, mut published) = (0, 0);
        let mut counts = std::collections::BTreeSet::new();
        for r in rows.iter().filter(|r| r.kind == name) {
            let mut c = Safer::with_rounds(variant(name), &r.key, r.rounds).unwrap();
            let mut out = Vec::new();
            c.block_encrypt(&r.pt, &mut out);
            assert_eq!(out, r.ct, "{name} {} encrypt {:02x?} {:02x?}", r.rounds, r.key, r.pt);
            let mut back = Vec::new();
            c.block_decrypt(&r.ct, &mut back);
            assert_eq!(back, r.pt, "{name} {} decrypt {:02x?}", r.rounds, r.key);
            single += 1;
            published += usize::from(r.published);
            counts.insert(r.rounds);
        }
        // A parser that found nothing would pass every assertion above.
        assert_eq!(published, want_published, "{name}");
        assert!(single >= 580, "{name}: {single}");
        assert!(counts.into_iter().eq(want_rounds), "{name}");
    }
}

/// A block encrypted `n` times over and decrypted as many times back:
/// each step's input is the cipher's own output, so these reach blocks
/// nobody chose.
#[test]
fn test_safer_iterated() {
    let mut checked = 0;
    for r in rows().iter().filter(|r| r.kind.ends_with("-iter")) {
        let mut c = Safer::with_rounds(variant(&r.kind), &r.key, r.rounds).unwrap();
        let mut block = r.pt.clone();
        for _ in 0..r.n {
            let mut out = Vec::new();
            c.block_encrypt(&block, &mut out);
            block = out;
        }
        assert_eq!(block, r.ct, "{} {} {:02x?} {}", r.kind, r.rounds, r.key, r.n);
        for _ in 0..r.n {
            let mut out = Vec::new();
            c.block_decrypt(&block, &mut out);
            block = out;
        }
        assert_eq!(block, r.pt, "{} {} {:02x?} {}", r.kind, r.rounds, r.key, r.n);
        checked += 1;
    }
    assert_eq!(checked, 44);
}

/// No round count means the variant's usual one, which the vectors name
/// independently: it is the count NESSIE's test sets were written at, so
/// the one with the most rows.
#[test]
fn test_no_round_count_is_the_usual_one() {
    let rows = rows();
    for (name, v) in VARIANTS {
        let mut counts: HashMap<usize, usize> = HashMap::new();
        for r in rows.iter().filter(|r| r.kind == name) {
            *counts.entry(r.rounds).or_default() += 1;
        }
        let usual = counts.iter().max_by_key(|(_, n)| **n).map(|(r, _)| *r).unwrap();
        let r = rows.iter().find(|r| r.kind == name && r.rounds == usual && !r.published).unwrap();
        let mut out = Vec::new();
        Safer::new(v, &r.key).unwrap().block_encrypt(&r.pt, &mut out);
        assert_eq!(out, r.ct, "{name}: the usual count is {usual}");
        let mut s = CipherStream::new(AnyBlockCipher::new(name, &r.key, None).unwrap(), Mode::Ecb,
                                      &[], false).unwrap();
        assert_eq!(s.update(&r.pt).unwrap(), r.ct, "{name}");
    }
}

/// Through the catalogue: the round count is the parameter, absent means
/// the variant's usual count, and anything else is refused; every mode
/// round-trips in irregular pieces.
#[test]
fn test_safer_through_the_catalogue() {
    let rows = rows();
    for (name, v) in VARIANTS {
        for r in rows.iter().filter(|r| r.kind == name && !r.published).take(40) {
            let rounds = r.rounds.to_string();
            let param = if r.rounds == v.default_rounds() { None } else { Some(rounds.as_str()) };
            let cipher = AnyBlockCipher::new(name, &r.key, param).unwrap();
            assert_eq!(cipher.name(), name);
            let mut ecb = CipherStream::new(cipher, Mode::Ecb, &[], false).unwrap();
            let mut out = ecb.update(&r.pt).unwrap();
            out.extend(ecb.finish().unwrap());
            assert_eq!(out[..8], r.ct[..], "{name} {}", r.rounds);
        }
        let key = vec![7u8; v.key_len()];
        for bad in ["0", "14", "six", ""] {
            assert!(AnyBlockCipher::new(name, &key, Some(bad)).is_err(), "{name} {bad:?}");
        }
    }

    let key: Vec<u8> = (0..16).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 8] };
            let new = || AnyBlockCipher::new("safer-sk128", &key, None).unwrap();
            let one = {
                let mut s = match CipherStream::new(new(), mode, &iv, false) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut out = s.update(&message).unwrap();
                match s.finish() {
                    Ok(tail) => out.extend(tail),
                    // A mode that cannot take this length says so; that
                    // is checked for every cipher elsewhere.
                    Err(_) => continue,
                }
                out
            };
            let mut s = CipherStream::new(new(), mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(5) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(new(), mode, &iv, true).unwrap();
            let mut back = d.update(&one).unwrap();
            back.extend(d.finish().unwrap());
            assert_eq!(back, message, "{mode_name} {len}");
            checked += 1;
        }
    }
    // The `continue`s skip lengths a mode cannot take; most must remain.
    assert!(checked >= 50, "only {checked} mode and length pairs ran");
}
