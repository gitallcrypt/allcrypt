//! SHACAL-1 against `vectors/shacal1.vec`, written by
//! `scripts/make_shacal1_vectors.py`: blocks on which Crypto++ 8.9.0's
//! and OpenSSL's SHA-1 compression functions, less their feed-forward,
//! agree - Project Nayuki's two published tests, every single-bit key at
//! 64 and 16 bytes and every single-bit block, every byte repeated,
//! random blocks at every key length from 16 to 64 bytes, and blocks
//! iterated 100 and 1,000 times. The witnesses encrypt only; decryption
//! is required to give every row's block back. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::shacal1::Shacal1;
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
    let text = include_str!("../vectors/shacal1.vec");
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

#[test]
fn test_shacal1_vectors() {
    let (mut single, mut published) = (0, 0);
    let mut lengths = std::collections::BTreeSet::new();
    for r in rows().iter().filter(|r| r.kind == "shacal1") {
        let mut c = Shacal1::new(&r.key).unwrap();
        let mut out = Vec::new();
        c.block_encrypt(&r.pt, &mut out);
        assert_eq!(out, r.ct, "encrypt {:02x?} {:02x?}", r.key, r.pt);
        let mut back = Vec::new();
        c.block_decrypt(&r.ct, &mut back);
        assert_eq!(back, r.pt, "decrypt {:02x?}", r.key);
        single += 1;
        published += usize::from(r.published);
        lengths.insert(r.key.len());
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(published, 2);
    assert!(single >= 1200, "{single}");
    assert_eq!(lengths.into_iter().collect::<Vec<_>>(), (16..=64).collect::<Vec<_>>());
}

/// A block encrypted `n` times over, as NESSIE's "Iterated" lines, and
/// decrypted as many times back: each step's input is the cipher's own
/// output, so these reach blocks nobody chose.
#[test]
fn test_shacal1_iterated() {
    let mut checked = 0;
    for r in rows().iter().filter(|r| r.kind == "shacal1-iter") {
        let mut c = Shacal1::new(&r.key).unwrap();
        let mut block = r.pt.clone();
        for _ in 0..r.n {
            let mut out = Vec::new();
            c.block_encrypt(&block, &mut out);
            block = out;
        }
        assert_eq!(block, r.ct, "{:02x?} {}", r.key, r.n);
        for _ in 0..r.n {
            let mut out = Vec::new();
            c.block_decrypt(&block, &mut out);
            block = out;
        }
        assert_eq!(block, r.pt, "{:02x?} {}", r.key, r.n);
        checked += 1;
    }
    assert_eq!(checked, 13);
}

/// Through the catalogue, in every mode and at lengths around the block,
/// encrypting in irregular pieces must equal one call, and decrypting
/// must give the message back; ECB through the catalogue is the
/// recorded rows.
#[test]
fn test_shacal1_through_the_catalogue_in_every_mode() {
    let rows = rows();
    let r = rows.iter().find(|r| r.kind == "shacal1" && !r.published).unwrap();
    let mut ecb = CipherStream::new(AnyBlockCipher::new("shacal1", &r.key, None).unwrap(),
                                    Mode::from_name("ecb").unwrap(), &[], false).unwrap();
    let mut out = ecb.update(&r.pt).unwrap();
    out.extend(ecb.finish().unwrap());
    assert_eq!(out[..20], r.ct[..]);
    assert_eq!(AnyBlockCipher::new("shacal1", &r.key, None).unwrap().name(), "shacal1");

    let key: Vec<u8> = (0..64).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 19, 20, 21, 39, 40, 41, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 20] };
            let one = {
                let mut s = match CipherStream::new(
                    AnyBlockCipher::new("shacal1", &key, None).unwrap(), mode, &iv, false) {
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
            let mut s = CipherStream::new(AnyBlockCipher::new("shacal1", &key, None).unwrap(),
                                          mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(5) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(AnyBlockCipher::new("shacal1", &key, None).unwrap(),
                                          mode, &iv, true).unwrap();
            let mut back = d.update(&one).unwrap();
            back.extend(d.finish().unwrap());
            assert_eq!(back, message, "{mode_name} {len}");
            checked += 1;
        }
    }
    // The `continue`s skip lengths a mode cannot take; most must remain.
    assert!(checked >= 40, "only {checked} mode and length pairs ran");
}
