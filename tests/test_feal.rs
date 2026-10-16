//! FEAL-N and FEAL-NX against NTT's own FEAL-NX test data,
//! `vectors/feal_nx_ntt.txt` - ten keys with 4,096 blocks each, at 32
//! rounds, as NTT published it - and against `vectors/feal.vec`, written
//! by `scripts/make_feal_vectors.py`: rows on which zilijonas/FEAL-NX's
//! Java and Donaldduck8's Python agree, FEAL-N at 4, 8, 16 and 32 rounds
//! and FEAL-NX at 2, 8, 32 and 64. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::feal::Feal;
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// NTT's data: `KEY = <hex>`, then `PT: <hex>,  CT: <hex>` lines. The
/// file is Shift JIS; the lines read here are ASCII, and the rest - the
/// Japanese commentary, and the legend's own `KEY = (...)` - is skipped.
fn ntt() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let text = include_bytes!("../vectors/feal_nx_ntt.txt");
    let mut key = None;
    let mut rows = Vec::new();
    for line in text.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else { continue };
        let line = line.trim();
        if let Some(hex) = line.strip_prefix("KEY = ").filter(|h| is_hex(h, 32)) {
            key = Some(unhex(hex));
        } else if let Some(rest) = line.strip_prefix("PT: ") {
            let (pt, ct) = rest.split_once(",").unwrap();
            let ct = ct.trim().strip_prefix("CT: ").unwrap();
            assert!(is_hex(pt, 16) && is_hex(ct, 16), "{line}");
            rows.push((key.clone().expect("a key before its blocks"), unhex(pt), unhex(ct)));
        }
    }
    rows
}

#[test]
fn test_ntt_feal_nx_data() {
    let rows = ntt();
    // A parser that found nothing would pass every assertion below.
    assert_eq!(rows.len(), 40960);
    let mut keys: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    let mut ciphers = HashMap::new();
    for (key, pt, ct) in &rows {
        *keys.entry(key.clone()).or_insert(0) += 1;
        let c = ciphers.entry(key.clone()).or_insert_with(|| Feal::new_nx(key, 32).unwrap());
        let mut out = Vec::new();
        c.block_encrypt(pt, &mut out);
        assert_eq!(&out, ct, "{key:02x?} {pt:02x?}");
        let mut back = Vec::new();
        c.block_decrypt(ct, &mut back);
        assert_eq!(&back, pt, "{key:02x?}");
    }
    assert_eq!(keys.len(), 10);
    assert!(keys.values().all(|&n| n == 4096), "{keys:?}");
}

/// The catalogue's feal-nx is 32 rounds unless asked otherwise.
#[test]
fn test_ntt_data_through_the_catalogue() {
    let rows = ntt();
    for (key, pt, ct) in rows.iter().step_by(97) {
        let mut ecb = CipherStream::new(AnyBlockCipher::new("feal-nx", key, None).unwrap(),
                                        Mode::from_name("ecb").unwrap(), &[], false).unwrap();
        let mut out = ecb.update(pt).unwrap();
        out.extend(ecb.finish().unwrap());
        assert_eq!(&out[..8], &ct[..]);
    }
}

struct Row {
    kind: String,
    key: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    rounds: usize,
    n: usize,
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/feal.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows: Vec<Row> = text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let kind = line.split(' ').next().unwrap().to_string();
            let f: HashMap<&str, &str> = line.split(' ').skip(1)
                .map(|w| w.split_once('=').unwrap()).collect();
            Row { kind, key: unhex(f["key"]), pt: unhex(f["pt"]), ct: unhex(f["ct"]),
                  rounds: f["rounds"].parse().unwrap(),
                  n: f.get("n").map_or(1, |n| n.parse().unwrap()) }
        })
        .collect();
    assert_eq!(rows.len(), declared);
    rows
}

fn cipher(kind: &str, key: &[u8], rounds: usize) -> Feal {
    match kind.trim_end_matches("-iter") {
        "feal" => Feal::new_n(key, rounds).unwrap(),
        "feal-nx" => Feal::new_nx(key, rounds).unwrap(),
        other => panic!("{other}"),
    }
}

#[test]
fn test_feal_vectors() {
    let mut counts: BTreeMap<(String, usize), usize> = BTreeMap::new();
    for r in rows().iter().filter(|r| !r.kind.ends_with("-iter")) {
        let mut c = cipher(&r.kind, &r.key, r.rounds);
        let mut out = Vec::new();
        c.block_encrypt(&r.pt, &mut out);
        assert_eq!(out, r.ct, "{} {} {:02x?} {:02x?}", r.kind, r.rounds, r.key, r.pt);
        let mut back = Vec::new();
        c.block_decrypt(&r.ct, &mut back);
        assert_eq!(back, r.pt, "{} {} {:02x?}", r.kind, r.rounds, r.key);
        *counts.entry((r.kind.clone(), r.rounds)).or_insert(0) += 1;
    }
    let want: Vec<(String, usize)> = [("feal", 4), ("feal", 8), ("feal", 16), ("feal", 32),
                                      ("feal-nx", 2), ("feal-nx", 8), ("feal-nx", 32),
                                      ("feal-nx", 64)]
        .iter().map(|&(k, n)| (k.to_string(), n)).collect();
    assert_eq!(counts.keys().cloned().collect::<Vec<_>>(), {
        let mut w = want.clone();
        w.sort();
        w
    });
    for ((kind, rounds), n) in &counts {
        assert!(*n >= 170, "{kind} {rounds}: {n}");
    }
}

/// A block encrypted `n` times over, and decrypted as many times back.
#[test]
fn test_feal_iterated() {
    let mut checked = 0;
    for r in rows().iter().filter(|r| r.kind.ends_with("-iter")) {
        let mut c = cipher(&r.kind, &r.key, r.rounds);
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
        assert_eq!(block, r.pt, "{} {:02x?} {}", r.kind, r.key, r.n);
        checked += 1;
    }
    assert_eq!(checked, 32);
}

/// The catalogue's feal is FEAL-8 unless asked otherwise, and its
/// parameter is the round count; feal-nx's default is 32.
#[test]
fn test_the_catalogue_round_counts() {
    let rows = rows();
    for r in rows.iter().filter(|r| !r.kind.ends_with("-iter")).step_by(23) {
        let default = if r.kind == "feal" { 8 } else { 32 };
        let param = r.rounds.to_string();
        let param = (r.rounds != default).then_some(param.as_str());
        let c = AnyBlockCipher::new(&r.kind, &r.key, param).unwrap();
        assert_eq!(c.name(), r.kind);
        let mut s = CipherStream::new(c, Mode::from_name("ecb").unwrap(), &[], false).unwrap();
        let mut out = s.update(&r.pt).unwrap();
        out.extend(s.finish().unwrap());
        assert_eq!(out[..8], r.ct[..], "{} {}", r.kind, r.rounds);
    }
    assert!(AnyBlockCipher::new("feal", &[0; 8], Some("7")).is_err());
    assert!(AnyBlockCipher::new("feal", &[0; 8], Some("eight")).is_err());
    assert!(AnyBlockCipher::new("feal", &[0; 16], None).is_err());
    assert!(AnyBlockCipher::new("feal-nx", &[0; 8], None).is_err());
}

/// Through the catalogue, in every mode and at lengths around the
/// block: encrypting in irregular pieces must equal one call, and
/// decrypting must give the message back.
#[test]
fn test_feal_through_the_catalogue_in_every_mode() {
    let mut checked = 0;
    for (kind, len) in [("feal", 8), ("feal-nx", 16)] {
        let key: Vec<u8> = (1..=len as u8).collect();
        for mode_name in allcrypt::api::MODES {
            let mode = Mode::from_name(mode_name).unwrap();
            for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 100] {
                let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
                let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 8] };
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
    assert!(checked >= 80, "only {checked} cipher, mode and length triples ran");
}
