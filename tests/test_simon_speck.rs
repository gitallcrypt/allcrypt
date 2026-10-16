//! Speck and Simon at every block size against
//! `vectors/simon_speck.vec`, written by
//! `scripts/make_simon_speck_vectors.py`: rows on which every witness
//! that takes the key agrees - Crypto++ 8.9.0, the Linux kernel's Speck,
//! jedisct1/rust-lwbc and inmcm's Python reference - Crypto++'s and the
//! paper's published tests, NESSIE's test sets in shape at every key
//! length, random blocks, and blocks iterated 100 and 1,000 times. The
//! rows at Speck48/72, Speck96/96, Simon48/72 and Simon96/96 are inmcm's
//! alone and say so. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::simon::{Simon128, Simon32, Simon48, Simon64, Simon96};
use allcrypt::block_ciphers::speck::{Speck128, Speck32, Speck48, Speck64, Speck96};
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
    alone: bool,
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/simon_speck.vec");
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
                  published: f.get("src") == Some(&"published"),
                  alone: f.get("witnesses") == Some(&"1") }
        })
        .collect();
    assert_eq!(rows.len(), declared);
    rows
}

fn cipher(kind: &str, key: &[u8]) -> Box<dyn BlockCipher> {
    match kind.trim_end_matches("-iter") {
        "speck32" => Box::new(Speck32::new(key).unwrap()),
        "speck48" => Box::new(Speck48::new(key).unwrap()),
        "speck96" => Box::new(Speck96::new(key).unwrap()),
        "simon32" => Box::new(Simon32::new(key).unwrap()),
        "simon48" => Box::new(Simon48::new(key).unwrap()),
        "simon96" => Box::new(Simon96::new(key).unwrap()),
        "speck64" => Box::new(Speck64::new(key).unwrap()),
        "speck128" => Box::new(Speck128::new(key).unwrap()),
        "simon64" => Box::new(Simon64::new(key).unwrap()),
        "simon128" => Box::new(Simon128::new(key).unwrap()),
        other => panic!("{other}"),
    }
}

/// Each name, its published rows, its key lengths, and those only inmcm
/// computes.
const KINDS: [(&str, usize, &[usize], &[usize]); 10] = [
    ("speck32", 1, &[8], &[]), ("speck48", 2, &[9, 12], &[9]),
    ("speck64", 16, &[12, 16], &[]), ("speck96", 2, &[12, 18], &[12]),
    ("speck128", 24, &[16, 24, 32], &[]),
    ("simon32", 1, &[8], &[]), ("simon48", 2, &[9, 12], &[9]),
    ("simon64", 16, &[12, 16], &[]), ("simon96", 2, &[12, 18], &[12]),
    ("simon128", 24, &[16, 24, 32], &[]),
];

#[test]
fn test_simon_speck_vectors() {
    let rows = rows();
    for (kind, want_published, lengths, alone) in KINDS {
        let (mut single, mut published) = (0, 0);
        let mut by_length = HashMap::new();
        for r in rows.iter().filter(|r| r.kind == kind) {
            let mut c = cipher(kind, &r.key);
            let mut out = Vec::new();
            c.block_encrypt(&r.pt, &mut out);
            assert_eq!(out, r.ct, "{kind} encrypt {:02x?} {:02x?}", r.key, r.pt);
            let mut back = Vec::new();
            c.block_decrypt(&r.ct, &mut back);
            assert_eq!(back, r.pt, "{kind} decrypt {:02x?}", r.key);
            single += 1;
            published += usize::from(r.published);
            *by_length.entry(r.key.len()).or_insert(0) += 1;
            assert_eq!(r.alone, alone.contains(&r.key.len()), "{kind} {:02x?}", r.key);
        }
        // A parser that found nothing would pass every assertion above.
        assert_eq!(published, want_published, "{kind}");
        assert!(single >= 350, "{kind}: {single}");
        for len in lengths {
            assert!(by_length.get(len).copied().unwrap_or(0) >= 100, "{kind} {len}: {by_length:?}");
        }
    }
}

/// A block encrypted `n` times over, as NESSIE's "Iterated" lines, and
/// decrypted as many times back.
#[test]
fn test_simon_speck_iterated() {
    let mut checked = 0;
    for r in rows().iter().filter(|r| r.kind.ends_with("-iter")) {
        let mut c = cipher(&r.kind, &r.key);
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
    assert_eq!(checked, 2 * (9 + 18 + 18 + 18 + 27));
}

/// The byte order is the little-endian encoding of the paper's numbers,
/// so a published test read the way the paper prints it - every byte
/// string reversed - is a different block under a different key.
#[test]
fn test_the_paper_order_is_the_reverse() {
    for r in rows().iter().filter(|r| r.published) {
        let mut key = r.key.clone();
        let mut pt = r.pt.clone();
        key.reverse();
        pt.reverse();
        let mut out = Vec::new();
        cipher(&r.kind, &key).block_encrypt(&pt, &mut out);
        out.reverse();
        assert_ne!(out, r.ct, "{} {:02x?}", r.kind, r.key);
    }
}

/// Through the catalogue, in every mode and at lengths around the
/// block, encrypting in irregular pieces must equal one call and
/// decrypting must give the message back; ECB through the catalogue is
/// the recorded rows.
#[test]
fn test_simon_speck_through_the_catalogue_in_every_mode() {
    let rows = rows();
    let mut checked = 0;
    for (kind, _, lengths, _) in KINDS {
        let r = rows.iter().find(|r| r.kind == kind && !r.published).unwrap();
        let block = r.pt.len();
        let mut ecb = CipherStream::new(AnyBlockCipher::new(kind, &r.key, None).unwrap(),
                                        Mode::from_name("ecb").unwrap(), &[], false).unwrap();
        let mut out = ecb.update(&r.pt).unwrap();
        out.extend(ecb.finish().unwrap());
        assert_eq!(out[..block], r.ct[..], "{kind}");
        assert_eq!(AnyBlockCipher::new(kind, &r.key, None).unwrap().name(), kind);

        let key: Vec<u8> = (0..lengths[lengths.len() - 1] as u8).collect();
        for mode_name in allcrypt::api::MODES {
            let mode = Mode::from_name(mode_name).unwrap();
            for len in [0usize, 1, block - 1, block, block + 1, 2 * block + 1, 100] {
                let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
                let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; block] };
                let one = {
                    let mut s = match CipherStream::new(
                        AnyBlockCipher::new(kind, &key, None).unwrap(), mode, &iv, false) {
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
                let mut s = CipherStream::new(AnyBlockCipher::new(kind, &key, None).unwrap(),
                                              mode, &iv, false).unwrap();
                let mut pieces = Vec::new();
                for chunk in message.chunks(5) {
                    pieces.extend(s.update(chunk).unwrap());
                }
                pieces.extend(s.finish().unwrap());
                assert_eq!(pieces, one, "{kind} {mode_name} {len}");
                let mut d = CipherStream::new(AnyBlockCipher::new(kind, &key, None).unwrap(),
                                              mode, &iv, true).unwrap();
                let mut back = d.update(&one).unwrap();
                back.extend(d.finish().unwrap());
                assert_eq!(back, message, "{kind} {mode_name} {len}");
                checked += 1;
            }
        }
    }
    // The `continue`s skip lengths a mode cannot take; most must remain.
    assert!(checked >= 150, "only {checked} cipher, mode and length triples ran");
}
