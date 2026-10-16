//! LOKI97 against `vectors/loki97.vec`, written by
//! `scripts/make_loki97_vectors.py`: the designers' reference C, as
//! Crypt::Loki97 1.0.1 carries it, and libmcrypt 2.5.8, whose LOKI97
//! byte-swaps every 32-bit word and zero-pads the key to 32 bytes. The
//! two agree on every row once libmcrypt's form is accounted for, except
//! the rows with a 16 or 24 byte key, which libmcrypt cannot compute and
//! which are the reference's alone. The published tests, NESSIE's test
//! sets in shape - every single-bit key at each length, every single-bit
//! block, every byte repeated - random blocks, and blocks iterated 100
//! and 1,000 times. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::loki97::Loki97;
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
    let text = include_str!("../vectors/loki97.vec");
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

fn cipher(kind: &str, key: &[u8]) -> Loki97 {
    if kind.starts_with("loki97-mcrypt") {
        Loki97::new_mcrypt(key).unwrap()
    } else {
        Loki97::new(key).unwrap()
    }
}

#[test]
fn test_loki97_vectors() {
    for (kind, want_published, want_single) in [("loki97", 6, 1000), ("loki97-mcrypt", 2, 90)] {
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
fn test_loki97_iterated() {
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

/// The two forms are different ciphers under one key: the published
/// test of each is not an answer of the other.
#[test]
fn test_the_two_forms_differ_on_the_published_tests() {
    let rows = rows();
    for r in rows.iter().filter(|r| r.published) {
        let other = if r.kind == "loki97" { "loki97-mcrypt" } else { "loki97" };
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
fn test_loki97_through_the_catalogue_in_every_mode() {
    let rows = rows();
    for name in ["loki97", "loki97-mcrypt"] {
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
                    AnyBlockCipher::new("loki97", &key, None).unwrap(), mode, &iv, false) {
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
            let mut s = CipherStream::new(AnyBlockCipher::new("loki97", &key, None).unwrap(),
                                          mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(5) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(AnyBlockCipher::new("loki97", &key, None).unwrap(),
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

/// The file's own account of its witnesses: a row is the reference's
/// alone exactly when it is a `loki97` row with a 16 or 24 byte key, and
/// there are two-witness rows at 32 bytes in both forms and one-witness
/// rows at both shorter lengths.
#[test]
fn test_the_rows_with_one_witness_are_the_short_keys() {
    let text = include_str!("../vectors/loki97.vec");
    let mut seen = HashMap::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let kind = line.split(' ').next().unwrap();
        let key = line.split(' ').find_map(|w| w.strip_prefix("key=")).unwrap();
        let alone = line.ends_with(" witnesses=1");
        let short = key.len() != 64;
        assert_eq!(alone, short && !kind.starts_with("loki97-mcrypt"), "{line}");
        *seen.entry((kind.starts_with("loki97-mcrypt"), key.len() / 2, alone)).or_insert(0) += 1;
    }
    for wanted in [(false, 16, true), (false, 24, true), (false, 32, false), (true, 16, false),
                   (true, 24, false), (true, 32, false)] {
        assert!(seen.contains_key(&wanted), "{wanted:?}");
    }
}
