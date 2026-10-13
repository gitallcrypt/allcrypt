//! Noekeon against `vectors/noekeon.vec`, written by
//! `scripts/make_noekeon_vectors.py`: the direct-key mode as libtomcrypt
//! 1.18.2 and Bouncy Castle 1.77 agree on it, with libtomcrypt's
//! published tests, and the indirect-key mode as Botan 1.10.17 and Bouncy
//! Castle under the mode's definition agree on it, with Botan's tests
//! from the NESSIE reference code. Each mode: every single-bit key, every
//! single-bit block, every byte repeated, random blocks, and blocks
//! iterated 100 and 1,000 times. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::noekeon::Noekeon;
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Row {
    kind: String,
    key: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    n: usize,
    published: bool,
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/noekeon.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows: Vec<Row> = text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let kind = line.split(' ').next().unwrap().to_string();
            let f: HashMap<&str, &str> = line.split(' ').skip(1)
                .map(|w| w.split_once('=').unwrap()).collect();
            Row { kind, key: unhex(f["key"]), pt: unhex(f["pt"]), ct: unhex(f["ct"]),
                  n: f.get("n").map_or(1, |n| n.parse().unwrap()),
                  published: f.get("src") == Some(&"published") }
        })
        .collect();
    assert_eq!(rows.len(), declared);
    rows
}

fn cipher(mode: &str, key: &[u8]) -> Noekeon {
    match mode {
        "noekeon" => Noekeon::new(key).unwrap(),
        "noekeon-indirect" => Noekeon::new_indirect(key).unwrap(),
        other => panic!("{other}"),
    }
}

fn check_single(mode: &str) -> (usize, usize) {
    let (mut single, mut published) = (0, 0);
    for r in rows().iter().filter(|r| r.kind == mode) {
        let mut c = cipher(mode, &r.key);
        let mut out = Vec::new();
        c.block_encrypt(&r.pt, &mut out);
        assert_eq!(out, r.ct, "{mode} encrypt {:02x?} {:02x?}", r.key, r.pt);
        let mut back = Vec::new();
        c.block_decrypt(&r.ct, &mut back);
        assert_eq!(back, r.pt, "{mode} decrypt {:02x?}", r.key);
        single += 1;
        published += usize::from(r.published);
    }
    (single, published)
}

#[test]
fn test_noekeon_direct_vectors() {
    let (single, published) = check_single("noekeon");
    // A parser that found nothing would pass every assertion above.
    assert_eq!(published, 8);
    assert!(single >= 580, "{single}");
}

#[test]
fn test_noekeon_indirect_vectors() {
    let (single, published) = check_single("noekeon-indirect");
    assert_eq!(published, 11);
    assert!(single >= 580, "{single}");
}

/// The two modes share no rows: the same key and block give different
/// blocks, so a mode taken for the other cannot pass the vectors.
#[test]
fn test_the_modes_differ() {
    let rows = rows();
    let direct: HashMap<(&[u8], &[u8]), &[u8]> = rows.iter().filter(|r| r.kind == "noekeon")
        .map(|r| ((&r.key[..], &r.pt[..]), &r.ct[..])).collect();
    let mut shared = 0;
    for r in rows.iter().filter(|r| r.kind == "noekeon-indirect") {
        if let Some(ct) = direct.get(&(&r.key[..], &r.pt[..])) {
            assert_ne!(*ct, &r.ct[..]);
            shared += 1;
        }
    }
    assert!(shared >= 500, "{shared}");
}

/// Blocks encrypted `n` times over and decrypted as many times back, in
/// each mode.
#[test]
fn test_noekeon_iterated() {
    let mut checked = 0;
    for r in rows().iter().filter(|r| r.kind.ends_with("-iter")) {
        let mut c = cipher(r.kind.strip_suffix("-iter").unwrap(), &r.key);
        let mut block = r.pt.clone();
        for _ in 0..r.n {
            let mut out = Vec::new();
            c.block_encrypt(&block, &mut out);
            block = out;
        }
        assert_eq!(block, r.ct, "{} {:02x?} {}", r.kind, r.key, r.n);
        for _ in 0..r.n {
            let mut out = Vec::new();
            c.block_decrypt(&block, &mut out);
            block = out;
        }
        assert_eq!(block, r.pt, "{} {:02x?} {}", r.kind, r.key, r.n);
        checked += 1;
    }
    assert_eq!(checked, 32);
}

/// Through the catalogue, by both names, in every mode and at lengths
/// around the block: pieces equal one call, decryption gives the
/// message back, and ECB is the recorded rows.
#[test]
fn test_noekeon_through_the_catalogue_in_every_mode() {
    let rows = rows();
    for name in ["noekeon", "noekeon-indirect"] {
        let r = rows.iter().find(|r| r.kind == name && !r.published).unwrap();
        let built = AnyBlockCipher::new(name, &r.key, None).unwrap();
        assert_eq!(built.name(), name);
        let mut ecb = CipherStream::new(built, Mode::from_name("ecb").unwrap(), &[], false)
            .unwrap();
        let mut out = ecb.update(&r.pt).unwrap();
        out.extend(ecb.finish().unwrap());
        assert_eq!(out[..16], r.ct[..], "{name}");

        let key: Vec<u8> = (0..16).collect();
        let mut checked = 0;
        for mode_name in allcrypt::api::MODES {
            let mode = Mode::from_name(mode_name).unwrap();
            for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
                let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
                let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 16] };
                let one = {
                    let mut s = match CipherStream::new(
                        AnyBlockCipher::new(name, &key, None).unwrap(), mode, &iv, false) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let mut out = s.update(&message).unwrap();
                    match s.finish() {
                        Ok(tail) => out.extend(tail),
                        // A mode that cannot take this length says so;
                        // that is checked for every cipher elsewhere.
                        Err(_) => continue,
                    }
                    out
                };
                let mut s = CipherStream::new(AnyBlockCipher::new(name, &key, None).unwrap(),
                                              mode, &iv, false).unwrap();
                let mut pieces = Vec::new();
                for chunk in message.chunks(7) {
                    pieces.extend(s.update(chunk).unwrap());
                }
                pieces.extend(s.finish().unwrap());
                assert_eq!(pieces, one, "{name} {mode_name} {len}");
                let mut d = CipherStream::new(AnyBlockCipher::new(name, &key, None).unwrap(),
                                              mode, &iv, true).unwrap();
                let mut back = d.update(&one).unwrap();
                back.extend(d.finish().unwrap());
                assert_eq!(back, message, "{name} {mode_name} {len}");
                checked += 1;
            }
        }
        assert!(checked >= 60, "{name}: only {checked} mode and length pairs ran");
    }
}
