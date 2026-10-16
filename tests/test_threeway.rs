//! 3-Way against `vectors/threeway.vec`, which Crypto++ 8.9.0 and
//! libmcrypt 2.5.8 agree on, written by `scripts/make_threeway_vectors.py`:
//! Crypto++'s published tests and libmcrypt's self-test, NESSIE's test
//! sets in shape - every single-bit key, every single-bit block, every
//! byte repeated - random blocks, and blocks iterated 100 and 1,000
//! times. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::threeway::ThreeWay;
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
    let text = include_str!("../vectors/threeway.vec");
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
fn test_threeway_vectors() {
    let (mut single, mut published) = (0, 0);
    for r in rows().iter().filter(|r| r.kind == "threeway") {
        let mut c = ThreeWay::new(&r.key).unwrap();
        let mut out = Vec::new();
        c.block_encrypt(&r.pt, &mut out);
        assert_eq!(out, r.ct, "encrypt {:02x?} {:02x?}", r.key, r.pt);
        let mut back = Vec::new();
        c.block_decrypt(&r.ct, &mut back);
        assert_eq!(back, r.pt, "decrypt {:02x?}", r.key);
        single += 1;
        published += usize::from(r.published);
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(published, 5);
    assert!(single >= 500, "{single}");
}

/// A block encrypted `n` times over, as NESSIE's "Iterated" lines, and
/// decrypted as many times back: each step's input is the cipher's own
/// output, so these reach blocks nobody chose.
#[test]
fn test_threeway_iterated() {
    let mut checked = 0;
    for r in rows().iter().filter(|r| r.kind == "threeway-iter") {
        let mut c = ThreeWay::new(&r.key).unwrap();
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
    assert_eq!(checked, 17);
}

/// Through the catalogue, in every mode and at lengths around the block,
/// encrypting in irregular pieces must equal one call, and decrypting
/// must give the message back; ECB through the catalogue is the
/// recorded rows.
#[test]
fn test_threeway_through_the_catalogue_in_every_mode() {
    let rows = rows();
    let r = rows.iter().find(|r| r.kind == "threeway" && !r.published).unwrap();
    let mut ecb = CipherStream::new(AnyBlockCipher::new("threeway", &r.key, None).unwrap(),
                                    Mode::from_name("ecb").unwrap(), &[], false).unwrap();
    let mut out = ecb.update(&r.pt).unwrap();
    out.extend(ecb.finish().unwrap());
    assert_eq!(out[..12], r.ct[..]);

    let key: Vec<u8> = (0..12).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 11, 12, 13, 23, 24, 25, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 12] };
            let one = {
                let mut s = match CipherStream::new(
                    AnyBlockCipher::new("threeway", &key, None).unwrap(), mode, &iv, false) {
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
            let mut s = CipherStream::new(AnyBlockCipher::new("threeway", &key, None).unwrap(),
                                          mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(5) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(AnyBlockCipher::new("threeway", &key, None).unwrap(),
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
