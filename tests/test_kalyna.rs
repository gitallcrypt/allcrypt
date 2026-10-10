//! Kalyna (DSTU 7624:2014) against `vectors/kalyna.vec`: the standard's
//! ten examples and 75 rows on which the authors' reference
//! implementation and Bouncy Castle 1.77 agree, over all five variants,
//! written by `scripts/make_kalyna_vectors.py`. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::kalyna::{Kalyna, SBOX};
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    include_str!("../vectors/kalyna.vec").lines()
        .filter(|line| line.split(' ').next() == Some(kind))
        .map(|line| line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

/// The S-boxes here are the ones both witnesses carry.
#[test]
fn test_the_sboxes_are_the_witnesses() {
    let tables = rows("sbox");
    assert_eq!(tables.len(), 4);
    for row in tables {
        let index: usize = row["index"].parse().unwrap();
        assert_eq!(SBOX[index].to_vec(), unhex(row["table"]), "π{index}");
    }
}

#[test]
fn test_kalyna_vectors() {
    let mut per_variant: BTreeMap<(usize, usize, &str), usize> = BTreeMap::new();
    for row in rows("kalyna") {
        let block: usize = row["block"].parse().unwrap();
        let (key, pt, ct) = (unhex(row["key"]), unhex(row["pt"]), unhex(row["ct"]));
        let mut c = Kalyna::new(block, &key).unwrap();
        let mut out = Vec::new();
        c.block_encrypt(&pt, &mut out);
        assert_eq!(out, ct, "encrypt {row:?}");
        let mut back = Vec::new();
        c.block_decrypt(&ct, &mut back);
        assert_eq!(back, pt, "decrypt {row:?}");

        // The same row through the catalogue name.
        let name = format!("kalyna-{}", 8 * block);
        let mut any = AnyBlockCipher::new(&name, &key, None).unwrap();
        assert_eq!((any.name(), any.blocksize()), (name.as_str(), block));
        let mut via = Vec::new();
        any.block_encrypt(&pt, &mut via);
        assert_eq!(via, ct, "catalogue {row:?}");

        *per_variant.entry((block, key.len(), row["source"])).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    for (block, key) in [(16, 16), (16, 32), (32, 32), (32, 64), (64, 64)] {
        assert_eq!(per_variant[&(block, key, "standard")], 2, "{block}/{key}");
        assert!(per_variant[&(block, key, "both")] >= 15, "{block}/{key}");
    }
}

/// Every variant through the catalogue in every mode: irregular pieces
/// equal one call, and decryption gives the message back, with an IV of
/// one block.
#[test]
fn test_kalyna_through_the_catalogue_in_every_mode() {
    let mut checked = 0;
    for (block, key_len) in [(16, 16), (16, 32), (32, 32), (32, 64), (64, 64)] {
        let name = format!("kalyna-{}", 8 * block);
        let key: Vec<u8> = (0..key_len as u8).collect();
        for mode_name in allcrypt::api::MODES {
            let mode = Mode::from_name(mode_name).unwrap();
            for len in [0usize, 1, block - 1, block, block + 1, 2 * block + 3] {
                let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
                let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; block] };
                let new = || AnyBlockCipher::new(&name, &key, None).unwrap();
                let one = {
                    let mut s = CipherStream::new(new(), mode, &iv, false).unwrap();
                    let mut out = s.update(&message).unwrap();
                    match s.finish() {
                        Ok(tail) => out.extend(tail),
                        // ECB and CBC take whole blocks only.
                        Err(_) => continue,
                    }
                    out
                };
                let mut s = CipherStream::new(new(), mode, &iv, false).unwrap();
                let mut pieces = Vec::new();
                for chunk in message.chunks(7) {
                    pieces.extend(s.update(chunk).unwrap());
                }
                pieces.extend(s.finish().unwrap());
                assert_eq!(pieces, one, "{name} {mode_name} {len}");
                let mut d = CipherStream::new(new(), mode, &iv, true).unwrap();
                let mut back = d.update(&one).unwrap();
                back.extend(d.finish().unwrap());
                assert_eq!(back, message, "{name} {mode_name} {len}");
                checked += 1;
            }
        }
    }
    assert!(checked >= 150, "only {checked} cases ran");
}

#[test]
fn test_wrong_key_lengths_are_refused() {
    for (name, bad) in [("kalyna-128", 24), ("kalyna-128", 64), ("kalyna-256", 16),
                        ("kalyna-256", 48), ("kalyna-512", 32), ("kalyna-512", 128)] {
        assert!(AnyBlockCipher::new(name, &vec![0u8; bad], None).is_err(), "{name} {bad}");
    }
}
