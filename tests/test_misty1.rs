//! MISTY1 against RFC 2994's own examples, read out of the vendored
//! `rfcs/rfc2994.txt`, and against `vectors/misty1.vec`, which Botan
//! 1.10.17 and Crypt::Misty1 1.1.3 agree on, written by
//! `scripts/make_misty1_vectors.py`: Botan's published tests, NESSIE's
//! test sets in shape - every single-bit key, every
//! single-bit block, every byte repeated - random blocks, and blocks
//! iterated 100 and 1,000 times. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::misty1::Misty1;
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
    let text = include_str!("../vectors/misty1.vec");
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
fn test_misty1_vectors() {
    let (mut single, mut published) = (0, 0);
    for r in rows().iter().filter(|r| r.kind == "misty1") {
        let mut c = Misty1::new(&r.key).unwrap();
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
    assert_eq!(published, 31);
    assert!(single >= 500, "{single}");
}

/// A block encrypted `n` times over, as NESSIE's "Iterated" lines, and
/// decrypted as many times back: each step's input is the cipher's own
/// output, so these reach blocks nobody chose.
#[test]
fn test_misty1_iterated() {
    let mut checked = 0;
    for r in rows().iter().filter(|r| r.kind == "misty1-iter") {
        let mut c = Misty1::new(&r.key).unwrap();
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
fn test_misty1_through_the_catalogue_in_every_mode() {
    let rows = rows();
    let r = rows.iter().find(|r| r.kind == "misty1" && !r.published).unwrap();
    let mut ecb = CipherStream::new(AnyBlockCipher::new("misty1", &r.key, None).unwrap(),
                                    Mode::from_name("ecb").unwrap(), &[], false).unwrap();
    let mut out = ecb.update(&r.pt).unwrap();
    out.extend(ecb.finish().unwrap());
    assert_eq!(out[..8], r.ct[..]);

    let key: Vec<u8> = (0..16).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 8] };
            let one = {
                let mut s = match CipherStream::new(
                    AnyBlockCipher::new("misty1", &key, None).unwrap(), mode, &iv, false) {
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
            let mut s = CipherStream::new(AnyBlockCipher::new("misty1", &key, None).unwrap(),
                                          mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(5) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(AnyBlockCipher::new("misty1", &key, None).unwrap(),
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

/// RFC 2994's Appendix A, read out of the document: the key, the
/// 128-bit plaintext and its ciphertext in ECB, and the same plaintext in
/// CBC under an IV. A missing field is a panic, and both examples must
/// be found.
#[test]
fn test_the_rfcs_examples() {
    let rfc = include_str!("../rfcs/rfc2994.txt");
    let appendix = &rfc[rfc.find("Appendix A. Example Data of MISTY1").unwrap()..];
    let field = |text: &str, name: &str| -> Vec<u8> {
        let line = text.lines().find(|l| l.trim_start().starts_with(name)).unwrap();
        line.trim_start()[name.len()..].split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    };
    let (ecb, cbc) = appendix.split_at(appendix.find("CBC mode").unwrap());
    let key = field(ecb, "Key:");
    let (pt, ct) = (field(ecb, "Plaintext:"), field(ecb, "Ciphertext:"));
    assert_eq!((key.len(), pt.len(), ct.len()), (16, 16, 16));
    let mut out = Vec::new();
    let mut c = Misty1::new(&key).unwrap();
    for block in pt.chunks(8) {
        c.block_encrypt(block, &mut out);
    }
    assert_eq!(out, ct);

    let (iv, pt, ct) = (field(cbc, "IV:"), field(cbc, "Plaintext:"), field(cbc, "Ciphertext:"));
    assert_eq!(field(cbc, "Key:"), key);
    assert_eq!((iv.len(), pt.len(), ct.len()), (8, 16, 16));
    let mut s = CipherStream::new(AnyBlockCipher::new("misty1", &key, None).unwrap(), Mode::Cbc,
                                  &iv, false).unwrap();
    let mut out = s.update(&pt).unwrap();
    out.extend(s.finish().unwrap());
    // The RFC shows the two blocks without the padding block that
    // section 3 adds; CBC's first blocks do not depend on it.
    assert_eq!(out[..16], ct[..]);
}
