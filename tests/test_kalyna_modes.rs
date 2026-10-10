//! DSTU 7624:2014's modes over Kalyna against `vectors/kalyna_modes.vec`:
//! the standard's examples, rows on which Bouncy Castle 1.77 and
//! cryptonite agree, and rows from whichever does what the other does
//! not, written by `scripts/make_kalyna_mode_vectors.py`. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api::{self, AnyBlockCipher, CipherStream, Mode};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    let found: Vec<_> = include_str!("../vectors/kalyna_modes.vec").lines()
        .filter(|line| line.split(' ').next() == Some(kind))
        .map(|line| line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect();
    assert!(!found.is_empty(), "no {kind} rows");
    found
}

fn name(row: &HashMap<&str, &str>) -> String {
    format!("kalyna-{}", 8 * row["block"].parse::<usize>().unwrap())
}

fn run(cipher: &str, mode: Mode, key: &[u8], iv: &[u8], data: &[u8], decrypting: bool) -> Vec<u8> {
    let c = AnyBlockCipher::new(cipher, key, None).unwrap();
    let mut s = CipherStream::new(c, mode, iv, decrypting).unwrap();
    let mut out = Vec::new();
    // In uneven pieces, so the counter carries across calls.
    for chunk in data.chunks(7) {
        out.extend(s.update(chunk).unwrap());
    }
    out.extend(s.finish().unwrap());
    out
}

/// CBC, CFB and OFB are the generic modes, and `ctr` on a Kalyna name is
/// DSTU 7624's counter mode.
#[test]
fn test_streaming_modes() {
    let mut per: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for row in rows("stream") {
        let mode = Mode::from_name(row["mode"]).unwrap();
        let (key, iv, pt, ct) = (unhex(row["key"]), unhex(row["iv"]), unhex(row["pt"]),
                                 unhex(row["ct"]));
        assert_eq!(run(&name(&row), mode, &key, &iv, &pt, false), ct, "{row:?}");
        assert_eq!(run(&name(&row), mode, &key, &iv, &ct, true), pt, "{row:?}");
        *per.entry((row["mode"], row["source"])).or_default() += 1;
    }
    for mode in ["cbc", "cfb", "ofb", "ctr"] {
        assert!(per[&(mode, "both")] >= 15, "{mode}");
        assert!(per[&(mode, "standard")] >= 1, "{mode}");
    }
}

#[test]
fn test_mac() {
    for row in rows("mac") {
        let (key, msg) = (unhex(row["key"]), unhex(row["msg"]));
        let q: usize = row["q"].parse().unwrap();
        assert_eq!(api::kalyna_mac(&name(&row), &key, &msg, q).unwrap(), unhex(row["tag"]),
                   "{row:?}");
    }
    assert_eq!(rows("mac").iter().filter(|r| r["source"] == "cryptonite").count(), 20);
}

/// Whole-block data unwraps as it is; other data through its padding.
#[test]
fn test_key_wrap() {
    for row in rows("kw") {
        let (cipher, key, data) = (name(&row), unhex(row["key"]), unhex(row["data"]));
        let wrapped = unhex(row["wrapped"]);
        let block = row["block"].parse::<usize>().unwrap();
        assert_eq!(api::kalyna_key_wrap(&cipher, &key, &data).unwrap(), wrapped, "{row:?}");
        if data.len().is_multiple_of(block) {
            assert_eq!(api::kalyna_key_unwrap(&cipher, &key, &wrapped).unwrap(), data);
        } else {
            assert_eq!(api::kalyna_key_unwrap_padded(&cipher, &key, &wrapped).unwrap(), data);
        }
    }
    assert!(rows("kw").iter().any(|r| r["source"] == "bouncycastle"));
}

/// The modes refuse a cipher that is not Kalyna, and an unwrap under
/// the wrong key.
#[test]
fn test_refusals() {
    assert!(api::kalyna_mac("aes", &[0; 16], b"x", 16).is_err());
    assert!(api::kalyna_key_wrap("rijndael-256", &[0; 32], &[0; 32]).is_err());
    let wrapped = api::kalyna_key_wrap("kalyna-128", &[1; 16], &[2; 32]).unwrap();
    assert!(api::kalyna_key_unwrap("kalyna-128", &[3; 16], &wrapped).is_err());
    assert!(api::kalyna_mac("kalyna-128", &[0; 16], b"x", 17).is_err());
}
