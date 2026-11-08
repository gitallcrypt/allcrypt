//! The Chaskey-LTS block cipher against `vectors/chaskey_lts.vec`, written
//! by `scripts/make_chaskey_lts_vectors.py`: the FELIX block in sacundim's
//! tests, every single-bit key and block, every byte repeated, random
//! blocks and blocks iterated 100 and 1,000 times, each agreed by
//! sacundim's Rust crate and volexity's Python package and decrypted back
//! by both. The 16 round `chaskey-cipher` rows of `vectors/chaskey.vec`
//! are checked here too. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::chaskey_lts::ChaskeyLts;
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Row {
    key: Vec<u8>,
    block: Vec<u8>,
    out: Vec<u8>,
    source: String,
    times: usize,
}

fn parse(text: &str, kind: &str) -> Vec<Row> {
    text.lines()
        .filter(|l| l.starts_with(&format!("{kind} ")))
        .map(|line| {
            let f: HashMap<&str, &str> = line.split(' ').skip(1)
                .map(|w| w.split_once('=').unwrap()).collect();
            Row { key: unhex(f["key"]), block: unhex(f["block"]), out: unhex(f["out"]),
                  source: f["source"].to_string(),
                  times: f.get("times").map_or(1, |n| n.parse().unwrap()) }
        })
        .collect()
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/chaskey_lts.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows = parse(text, "chaskey-lts");
    assert_eq!(rows.len(), declared);
    rows
}

fn encrypt(c: &mut ChaskeyLts, block: &[u8], times: usize) -> Vec<u8> {
    let mut block = block.to_vec();
    for _ in 0..times {
        let mut out = Vec::new();
        c.block_encrypt(&block, &mut out);
        block = out;
    }
    block
}

fn decrypt(c: &mut ChaskeyLts, block: &[u8], times: usize) -> Vec<u8> {
    let mut block = block.to_vec();
    for _ in 0..times {
        let mut out = Vec::new();
        c.block_decrypt(&block, &mut out);
        block = out;
    }
    block
}

#[test]
fn test_chaskey_lts_vectors() {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in rows() {
        let mut c = ChaskeyLts::new(&r.key).unwrap();
        assert_eq!(encrypt(&mut c, &r.block, r.times), r.out, "{:02x?} {:02x?}", r.key, r.block);
        assert_eq!(decrypt(&mut c, &r.out, r.times), r.block, "{:02x?} {:02x?}", r.key, r.out);
        *counts.entry(r.source).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(counts["felix"], 1);
    assert_eq!(counts["single-bit"], 256);
    assert_eq!(counts["repeated"], 256);
    assert_eq!(counts["random"], 64);
    assert_eq!(counts["iterated"], 17);
}

/// The 16 round block cipher rows of the Chaskey MAC vectors, which come
/// from the same two witnesses by a different script.
#[test]
fn test_chaskey_lts_against_the_mac_vectors() {
    let text = include_str!("../vectors/chaskey.vec");
    // Every one of them is at 16 rounds; a row at another count would
    // fail the comparison.
    let rows = parse(text, "chaskey-cipher");
    for r in &rows {
        let mut c = ChaskeyLts::new(&r.key).unwrap();
        assert_eq!(encrypt(&mut c, &r.block, 1), r.out, "{:02x?}", r.block);
        assert_eq!(decrypt(&mut c, &r.out, 1), r.block, "{:02x?}", r.out);
    }
    assert_eq!(rows.len(), 40);
}

/// Through the catalogue in every mode and at lengths around the block:
/// pieces equal one call, decryption gives the message back, and ECB is
/// the recorded rows.
#[test]
fn test_chaskey_lts_through_the_catalogue_in_every_mode() {
    let r = rows().into_iter().find(|r| r.source == "random").unwrap();
    let built = AnyBlockCipher::new("chaskey-lts", &r.key, None).unwrap();
    assert_eq!(built.name(), "chaskey-lts");
    let mut ecb = CipherStream::new(built, Mode::from_name("ecb").unwrap(), &[], false).unwrap();
    let mut out = ecb.update(&r.block).unwrap();
    out.extend(ecb.finish().unwrap());
    assert_eq!(out[..16], r.out[..]);

    let key: Vec<u8> = (0..16).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 16] };
            let fresh = || AnyBlockCipher::new("chaskey-lts", &key, None).unwrap();
            let one = {
                let Ok(mut s) = CipherStream::new(fresh(), mode, &iv, false) else { continue };
                let mut out = s.update(&message).unwrap();
                match s.finish() {
                    Ok(tail) => out.extend(tail),
                    // A mode that cannot take this length says so; that is
                    // checked for every cipher elsewhere.
                    Err(_) => continue,
                }
                out
            };
            let mut s = CipherStream::new(fresh(), mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(7) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(fresh(), mode, &iv, true).unwrap();
            let mut back = d.update(&one).unwrap();
            back.extend(d.finish().unwrap());
            assert_eq!(back, message, "{mode_name} {len}");
            checked += 1;
        }
    }
    assert!(checked >= 60, "only {checked} mode and length pairs ran");
}

#[test]
fn test_chaskey_lts_refuses_other_key_lengths() {
    for n in [0usize, 8, 15, 17, 24, 32] {
        let err = AnyBlockCipher::new("chaskey-lts", &vec![0; n], None).err().unwrap();
        assert!(err.to_string().contains(&format!("not {n}")), "{err}");
    }
}
