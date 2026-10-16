//! SAFER+ against `vectors/saferplus.vec`, written by
//! `scripts/make_saferplus_vectors.py`: libtomcrypt 1.18.2's byte order
//! and libmcrypt 2.5.8's, with the 32-bit words of key, block and result
//! reversed - the two witnesses agreeing on every row once the order is
//! accounted for. libtomcrypt's published tests at all three key
//! lengths, NESSIE's test sets in shape - every single-bit key at each
//! length, every single-bit block, every byte repeated - random blocks,
//! and blocks iterated 100 and 1,000 times. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::saferplus::SaferPlus;
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
    let text = include_str!("../vectors/saferplus.vec");
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

fn cipher(kind: &str, key: &[u8]) -> SaferPlus {
    if kind.starts_with("saferplus-reversed-words") {
        SaferPlus::new_reversed_words(key).unwrap()
    } else {
        SaferPlus::new(key).unwrap()
    }
}

#[test]
fn test_saferplus_vectors() {
    for (kind, want_published, want_single) in [("saferplus", 3, 1000), ("saferplus-reversed-words", 3, 90)] {
        let (mut single, mut published) = (0, 0);
        for r in rows().iter().filter(|r| r.kind == kind) {
            let mut c = cipher(kind, &r.key);
            let mut out = Vec::new();
            c.block_encrypt(&r.pt, &mut out);
            assert_eq!(out, r.ct, "{kind} encrypt {:02x?} {:02x?}", r.key, r.pt);
            let mut back = Vec::new();
            c.block_decrypt(&r.ct, &mut back);
            assert_eq!(back, r.pt, "{kind} decrypt {:02x?}", r.key);
            single += 1;
            published += usize::from(r.published);
        }
        // A parser that found nothing would pass every assertion above.
        assert_eq!(published, want_published, "{kind}");
        assert!(single >= want_single, "{kind}: {single}");
    }
}

/// A block encrypted `n` times over, as NESSIE's "Iterated" lines, and
/// decrypted as many times back: each step's input is the cipher's own
/// output, so these reach blocks nobody chose.
#[test]
fn test_saferplus_iterated() {
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
    assert_eq!(checked, 54);
}

/// The two orders are different ciphers under one key: the published
/// test of each order is not an answer of the other.
#[test]
fn test_the_two_orders_differ_on_the_published_tests() {
    let rows = rows();
    for r in rows.iter().filter(|r| r.published) {
        let other = if r.kind == "saferplus" { "saferplus-reversed-words" } else { "saferplus" };
        let mut out = Vec::new();
        cipher(other, &r.key).block_encrypt(&r.pt, &mut out);
        assert_ne!(out, r.ct, "{} {:02x?}", r.kind, r.key);
    }
}

/// Through the catalogue, in every mode and at lengths around the block,
/// encrypting in irregular pieces must equal one call, and decrypting
/// must give the message back; ECB through the catalogue is the
/// recorded rows, under both names.
#[test]
fn test_saferplus_through_the_catalogue_in_every_mode() {
    let rows = rows();
    for name in ["saferplus", "saferplus-reversed-words"] {
        let r = rows.iter().find(|r| r.kind == name && !r.published).unwrap();
        let mut ecb = CipherStream::new(AnyBlockCipher::new(name, &r.key, None).unwrap(),
                                        Mode::from_name("ecb").unwrap(), &[], false).unwrap();
        let mut out = ecb.update(&r.pt).unwrap();
        out.extend(ecb.finish().unwrap());
        assert_eq!(out[..16], r.ct[..], "{name}");
        assert_eq!(AnyBlockCipher::new(name, &r.key, None).unwrap().name(), name);
    }

    let key: Vec<u8> = (0..24).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 16] };
            let one = {
                let mut s = match CipherStream::new(
                    AnyBlockCipher::new("saferplus", &key, None).unwrap(), mode, &iv, false) {
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
            let mut s = CipherStream::new(AnyBlockCipher::new("saferplus", &key, None).unwrap(),
                                          mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(5) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(AnyBlockCipher::new("saferplus", &key, None).unwrap(),
                                          mode, &iv, true).unwrap();
            let mut back = d.update(&one).unwrap();
            back.extend(d.finish().unwrap());
            assert_eq!(back, message, "{mode_name} {len}");
            checked += 1;
        }
    }
    // The `continue`s skip lengths a mode cannot take; most must remain.
    assert!(checked >= 50, "only {checked} mode and length pairs ran");
}
