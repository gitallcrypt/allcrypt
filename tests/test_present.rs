//! PRESENT with 80 and 128 bit keys against `vectors/present.vec`,
//! written by `scripts/make_present_vectors.py`: rows on which
//! Nirusu/PRESENT.go, kurtfu/present and OpenTitan's Python PRESENT all
//! agree - the paper's tests and PRESENT.go's, NESSIE's test sets in
//! shape at both key lengths, random blocks, and blocks iterated 100 and
//! 1,000 times. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::present::Present;
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
    let text = include_str!("../vectors/present.vec");
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

fn cipher(kind: &str, key: &[u8]) -> Box<dyn BlockCipher> {
    assert_eq!(kind.trim_end_matches("-iter"), "present");
    Box::new(Present::new(key).unwrap())
}

/// The paper's four tests at 80 bits and PRESENT.go's five at 128.
const KINDS: [(&str, usize, &[usize]); 1] = [("present", 9, &[10, 16])];

#[test]
fn test_present_vectors() {
    let rows = rows();
    for (kind, want_published, lengths) in KINDS {
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
        }
        // A parser that found nothing would pass every assertion above.
        assert_eq!(published, want_published, "{kind}");
        assert!(single >= 600, "{kind}: {single}");
        for len in lengths {
            assert!(by_length.get(len).copied().unwrap_or(0) >= 100, "{kind} {len}: {by_length:?}");
        }
    }
}

/// A block encrypted `n` times over, as NESSIE's "Iterated" lines, and
/// decrypted as many times back.
#[test]
fn test_present_iterated() {
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
    assert_eq!(checked, 18);
}

/// The byte order is the specification's, most significant byte first;
/// read the other way, as kurtfu/present takes it, a published test is a
/// different block under a different key.
#[test]
fn test_the_reversed_order_is_another_cipher() {
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
fn test_present_through_the_catalogue_in_every_mode() {
    let rows = rows();
    let mut checked = 0;
    for (kind, _, lengths) in KINDS {
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
    assert!(checked >= 40, "only {checked} cipher, mode and length triples ran");
}
