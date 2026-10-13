//! Strumok (DSTU 8845:2019) against `vectors/strumok.vec`, written by
//! `scripts/make_strumok_vectors.py`: the standard's Annex D examples,
//! UAPKI's self-test, the conformance letter's two examples, and rows on
//! which UAPKI's `dstu8845.c` and uacrypt's `hazmat/strumok.rs` agree -
//! every single-bit key and IV at both key lengths, random keys at
//! lengths around a word and a 128 byte block, and a 1 MiB keystream
//! for each key length by its SHA-256. Offline.

use std::collections::{BTreeMap, HashSet};

use allcrypt::api::{AnyHash, AnyStreamCipher};
use allcrypt::hash_functions::HashFunction;
use allcrypt::stream_ciphers::strumok::Strumok;
use allcrypt::stream_ciphers::StreamCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows() -> Vec<BTreeMap<&'static str, &'static str>> {
    include_str!("../vectors/strumok.vec").lines()
        .filter(|l| l.starts_with("strumok "))
        .map(|l| l.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

fn keystream(key: &[u8], iv: &[u8], n: usize) -> Vec<u8> {
    let mut z = vec![0u8; n];
    Strumok::new(key, iv).unwrap().apply_keystream(&mut z);
    z
}

#[test]
fn test_strumok_vectors() {
    let mut per_source: BTreeMap<(&str, usize), usize> = BTreeMap::new();
    for f in rows().iter().filter(|f| f.contains_key("keystream")) {
        let (key, iv, want) = (unhex(f["key"]), unhex(f["iv"]), unhex(f["keystream"]));
        assert_eq!(keystream(&key, &iv, want.len()), want, "key={}", f["key"]);

        // In uneven pieces, through the trait.
        let mut cipher = Strumok::new(&key, &iv).unwrap();
        let mut pieces = Vec::new();
        for chunk in vec![0u8; want.len()].chunks(13) {
            cipher.crypt(chunk, &mut pieces);
        }
        assert_eq!(pieces, want);

        // Through the catalogue, the IV as the nonce.
        let mut any = AnyStreamCipher::new("strumok", &key, &iv).unwrap();
        assert_eq!(any.update(&vec![0u8; want.len()]).unwrap(), want);

        *per_source.entry((f["source"], key.len())).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(per_source[&("standard", 32)], 4);
    assert_eq!(per_source[&("standard", 64)], 4);
    assert_eq!(per_source[&("uapki", 32)], 5);
    assert_eq!(per_source[&("uapki", 64)], 4);
    assert_eq!(per_source[&("letter", 32)], 1);
    assert_eq!(per_source[&("letter", 64)], 1);
    assert_eq!(per_source[&("both", 32)], 2 + 256 + 256 + 15);
    assert_eq!(per_source[&("both", 64)], 2 + 512 + 256 + 15);
}

#[test]
fn test_a_long_keystream() {
    let long: Vec<_> = rows().into_iter().filter(|f| f.contains_key("sha256")).collect();
    assert_eq!(long.len(), 2);
    for f in long {
        let n: usize = f["length"].parse().unwrap();
        let mut h = AnyHash::new("sha256").unwrap();
        h.update(&keystream(&unhex(f["key"]), &unhex(f["iv"]), n));
        assert_eq!(h.digest(), unhex(f["sha256"]), "key={}", f["key"]);
    }
}

/// Annex D as the standard prints it and as UAPKI carries it are the
/// same eight examples once each is read in its own byte order, which
/// checks the two transcriptions and the conversion of each.
#[test]
fn test_the_standard_and_uapki_agree() {
    let examples = |source: &str| -> HashSet<(String, String, String)> {
        rows().into_iter().filter(|f| f["source"] == source)
            .filter(|f| f["keystream"].len() == 128)
            .map(|f| (f["key"].to_string(), f["iv"].to_string(), f["keystream"].to_string()))
            .collect()
    };
    let standard = examples("standard");
    assert_eq!(standard.len(), 8);
    assert_eq!(standard, examples("uapki"));
}

#[test]
fn test_encryption_round_trips() {
    let key = [0x3cu8; 32];
    let iv = [0xc3u8; 32];
    let pt: Vec<u8> = (0..=255u8).cycle().take(777).collect();
    let mut ct = Vec::new();
    Strumok::new(&key, &iv).unwrap().encrypt(&pt, &mut ct);
    assert_ne!(ct, pt);
    let mut back = Vec::new();
    Strumok::new(&key, &iv).unwrap().decrypt(&ct, &mut back);
    assert_eq!(back, pt);
}

#[test]
fn test_wrong_lengths_are_errors() {
    for (k, v) in [(31, 32), (33, 32), (48, 32), (16, 32), (0, 32), (32, 0), (32, 31), (64, 64)] {
        assert!(AnyStreamCipher::new("strumok", &vec![0; k], &vec![0; v]).is_err(), "{k}/{v}");
    }
}
