//! MARS against `vectors/mars.vec`, which Crypto++ 8.9.0 and Botan
//! 1.10.17 agree on, written by `scripts/make_mars_vectors.py`: Crypto++'s
//! published MARS tests, then every key length from 16 to 56 bytes with
//! single blocks and Monte Carlo tests each way, full and short. The S-box is derived
//! from its construction in `src/block_ciphers/mars.rs`. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::mars::Mars;
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Row {
    kind: String,
    key: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    /// The Monte Carlo test's two counts, `(outer, inner)`.
    counts: Option<(usize, usize)>,
    published: bool,
}

fn rows() -> Vec<Row> {
    include_str!("../vectors/mars.vec").lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let kind = line.split(' ').next().unwrap().to_string();
            let f: HashMap<&str, &str> = line.split(' ').skip(1)
                .map(|w| w.split_once('=').unwrap()).collect();
            let counts = f.get("outer").map(|o| (o.parse().unwrap(), f["inner"].parse().unwrap()));
            Row { kind, key: unhex(f["key"]), pt: unhex(f["pt"]), ct: unhex(f["ct"]), counts,
                  published: f.get("src") == Some(&"published") }
        })
        .collect()
}

/// Crypto++'s Monte Carlo test (`datatest.cpp`, EncryptionMCT and
/// DecryptionMCT), there with 400 and 10,000 for the counts: `outer`
/// times, process the block `inner` times in place under one key, then
/// XOR the key with the last key-length bytes of those outputs.
fn monte_carlo(key: &[u8], block: &[u8], decrypt: bool, (outer, inner): (usize, usize))
               -> Vec<u8> {
    let mut key = key.to_vec();
    // The last four outputs, oldest first: enough for a 56 byte key.
    let mut last: Vec<u8> = Vec::with_capacity(80);
    last.extend_from_slice(block);
    for _ in 0..outer {
        let mut c = Mars::new(&key).unwrap();
        for _ in 0..inner {
            let start = last.len() - 16;
            let input: [u8; 16] = last[start..].try_into().unwrap();
            if last.len() >= 64 {
                last.drain(..16);
            }
            if decrypt { c.block_decrypt(&input, &mut last) } else { c.block_encrypt(&input, &mut last) }
        }
        let tail = &last[last.len() - key.len()..];
        for (k, t) in key.iter_mut().zip(tail) {
            *k ^= t;
        }
    }
    last[last.len() - 16..].to_vec()
}

fn check_monte_carlo(r: &Row) {
    let counts = r.counts.unwrap();
    match r.kind.as_str() {
        "mars-mct" => assert_eq!(monte_carlo(&r.key, &r.pt, false, counts), r.ct,
                                 "{:02x?} {counts:?}", r.key),
        "mars-mct-dec" => assert_eq!(monte_carlo(&r.key, &r.ct, true, counts), r.pt,
                                     "{:02x?} {counts:?}", r.key),
        other => panic!("{other}"),
    }
}

#[test]
fn test_mars_vectors() {
    let mut per_length: BTreeMap<usize, usize> = BTreeMap::new();
    let mut published = 0;
    for r in rows().iter().filter(|r| r.kind == "mars") {
        let mut c = Mars::new(&r.key).unwrap();
        let mut out = Vec::new();
        c.block_encrypt(&r.pt, &mut out);
        assert_eq!(out, r.ct, "encrypt {:02x?}", r.key);
        let mut back = Vec::new();
        c.block_decrypt(&r.ct, &mut back);
        assert_eq!(back, r.pt, "decrypt {:02x?}", r.key);
        *per_length.entry(r.key.len()).or_default() += 1;
        published += usize::from(r.published);
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(published, 10);
    assert_eq!(per_length.keys().copied().collect::<Vec<_>>(),
               (16..=56).step_by(4).collect::<Vec<_>>());
    assert!(per_length.values().all(|&n| n >= 62), "{per_length:?}");
}

/// The short Monte Carlo tests, eight keys of 5,000 blocks, at every key
/// length and in each direction: each key after the first is derived
/// from the cipher's own output, so these reach keys nobody chose.
#[test]
fn test_mars_short_monte_carlo_at_every_length() {
    let mut per_length: BTreeMap<usize, usize> = BTreeMap::new();
    for r in rows().iter().filter(|r| r.counts == Some((8, 5000))) {
        check_monte_carlo(r);
        *per_length.entry(r.key.len()).or_default() += 1;
    }
    assert_eq!(per_length.keys().copied().collect::<Vec<_>>(),
               (16..=56).step_by(4).collect::<Vec<_>>());
    assert!(per_length.values().all(|&n| n == 2), "{per_length:?}");
}

/// Crypto++'s six published Monte Carlo tests and the recorded full ones
/// at every key length, each way: 28 tests of four million blocks.
///
/// Ignored for cost alone. Measured on the development container: 45
/// seconds in release, 638 in debug - against under five for the rest of
/// this file in debug. Run with
///
///     cargo test --release --test test_mars -- --ignored
///
/// `test_mars_short_monte_carlo_at_every_length` runs the same procedure
/// at every length and direction with smaller counts, and the single
/// blocks cover every key length, so what this adds is breadth: 400 keys
/// per test where that one has eight. The build script for the witnesses
/// requires both to reproduce the six published tests before any row is
/// recorded.
#[test]
#[ignore]
fn test_mars_full_monte_carlo() {
    let (mut published, mut recorded) = (0, BTreeMap::new());
    for r in rows().iter().filter(|r| r.counts == Some((400, 10_000))) {
        check_monte_carlo(r);
        if r.published {
            published += 1;
        } else {
            *recorded.entry(r.key.len()).or_insert(0) += 1;
        }
    }
    assert_eq!(published, 6);
    assert_eq!(recorded.keys().copied().collect::<Vec<_>>(),
               (16..=56).step_by(4).collect::<Vec<_>>());
    assert!(recorded.values().all(|&n| n == 2), "{recorded:?}");
}

/// Through the catalogue, in every mode and at lengths around the block,
/// encrypting in irregular pieces must equal one call, and decrypting
/// must give the message back.
#[test]
fn test_mars_through_the_catalogue_in_every_mode() {
    let key: Vec<u8> = (0..44).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 16] };
            let one = {
                let mut s = match CipherStream::new(
                    AnyBlockCipher::new("mars", &key, None).unwrap(), mode, &iv, false) {
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
            let mut s = CipherStream::new(AnyBlockCipher::new("mars", &key, None).unwrap(),
                                          mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(7) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(AnyBlockCipher::new("mars", &key, None).unwrap(),
                                          mode, &iv, true).unwrap();
            let mut back = d.update(&one).unwrap();
            back.extend(d.finish().unwrap());
            assert_eq!(back, message, "{mode_name} {len}");
            checked += 1;
        }
    }
    // The `continue`s skip lengths a mode cannot take; most must remain.
    assert!(checked >= 60, "only {checked} mode and length pairs ran");
}
