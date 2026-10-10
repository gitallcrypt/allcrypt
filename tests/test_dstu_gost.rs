//! GOST 28147-89 and GOST 34.311-95 under the DSTU 4145 default DKE, and
//! the DSTU GOST key wrap, against `vectors/dstu_gost.vec`: Bouncy
//! Castle 1.77 and gost89 in agreement on every row but the counter-mode
//! rows (Bouncy Castle's) and the wrap rows (gost89's), written by
//! `scripts/make_dstu_gost_vectors.py`. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, AnyHash, CipherStream, Mode};
use allcrypt::block_ciphers::cms_wrap::{unwrap_gost_dstu, wrap_gost_dstu};
use allcrypt::block_ciphers::gost::{GostCrypto, DSTU4145_DEFAULT_DKE, DSTU_PARAM_SET};
use allcrypt::hash_functions::HashFunction;
use allcrypt::Mac;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Every row of one kind, as field maps.
fn rows(kind: &str) -> Vec<HashMap<&'static str, Vec<u8>>> {
    let found: Vec<_> = include_str!("../vectors/dstu_gost.vec").lines()
        .filter(|line| line.split(' ').next() == Some(kind))
        .map(|line| line.split(' ').skip(1)
            .map(|w| { let (k, v) = w.split_once('=').unwrap(); (k, unhex(v)) })
            .collect())
        .collect();
    // A parser that found nothing would pass every loop below.
    assert!(!found.is_empty(), "no {kind} rows");
    found
}

fn run(mode: Mode, key: &[u8], iv: &[u8], data: &[u8], decrypting: bool) -> Vec<u8> {
    let cipher = AnyBlockCipher::new("gost", key, Some(DSTU_PARAM_SET)).unwrap();
    let mut s = CipherStream::new(cipher, mode, iv, decrypting).unwrap();
    let mut out = s.update(data).unwrap();
    out.extend(s.finish().unwrap());
    out
}

/// The table: both witnesses' default DKE is the constant, and the named
/// parameter set is that DKE unpacked.
#[test]
fn test_the_default_dke_is_the_witnesses() {
    let dke = &rows("dke")[0]["value"];
    assert_eq!(dke.as_slice(), DSTU4145_DEFAULT_DKE.as_slice());
    let named = GostCrypto::sbox_named(DSTU_PARAM_SET).unwrap();
    assert_eq!(named, GostCrypto::sbox_from_dke(dke).unwrap());
    for row in &named {
        let mut sorted = row.clone();
        sorted.sort();
        assert_eq!(sorted, (0..16u8).collect::<Vec<_>>(), "not a permutation");
    }
    assert!(GostCrypto::sbox_from_dke(&dke[..63]).is_err());
}

#[test]
fn test_ecb_cfb_and_counter_mode() {
    for (kind, mode) in [("gost-ecb", Mode::Ecb), ("gost-cfb", Mode::Cfb), ("gost-cnt", Mode::Ctr)] {
        for r in rows(kind) {
            let iv = r.get("iv").cloned().unwrap_or_default();
            assert_eq!(run(mode, &r["key"], &iv, &r["pt"], false), r["ct"], "{kind}");
            assert_eq!(run(mode, &r["key"], &iv, &r["ct"], true), r["pt"], "{kind}");
        }
    }
}

#[test]
fn test_mac() {
    for r in rows("gost-mac") {
        let mut mac = GostCrypto::new(&r["key"], DSTU_PARAM_SET).unwrap();
        mac.update(&r["msg"]);
        assert_eq!(mac.digest()[..4], r["tag"][..], "{} bytes", r["msg"].len());
    }
}

/// Through the catalogue name, in one call and fed in irregular pieces.
#[test]
fn test_gost34311() {
    for r in rows("gost34311") {
        let mut one = AnyHash::new("gost34311").unwrap();
        one.update(&r["msg"]);
        assert_eq!(one.digest(), r["digest"], "{} bytes", r["msg"].len());
        let mut pieces = AnyHash::new("gost34311").unwrap();
        for chunk in r["msg"].chunks(13) {
            pieces.update(chunk);
        }
        assert_eq!(pieces.digest(), r["digest"]);
    }
    assert_eq!(AnyHash::new("gost34311").unwrap().name(), "gost34311");
}

/// The same message under the three tables is three different hashes,
/// so a lookup that fell back to one table cannot pass the rows above
/// by accident.
#[test]
fn test_the_three_tables_are_three_hashes() {
    let digest = |name: &str| {
        let mut h = AnyHash::new(name).unwrap();
        h.update(b"abc");
        h.digest()
    };
    let (a, b, c) = (digest("gost94"), digest("gost94_test"), digest("gost34311"));
    assert!(a != b && b != c && a != c);
}

#[test]
fn test_wrap_and_unwrap() {
    for r in rows("wrap") {
        let wrapped = wrap_gost_dstu(&r["kek"], &r["cek"], &r["iv"]).unwrap();
        assert_eq!(wrapped, r["wrapped"]);
        assert_eq!(unwrap_gost_dstu(&r["kek"], &wrapped).unwrap(), r["cek"]);
        // Any one byte changed is refused, with the one message.
        for at in [0, 7, 8, 20, 35, 36, 43] {
            let mut bad = wrapped.clone();
            bad[at] ^= 1;
            let error = unwrap_gost_dstu(&r["kek"], &bad).unwrap_err();
            assert!(error.contains("Wrong key-encryption key"), "{error}");
        }
    }
    let r = &rows("wrap")[1];
    let mut other = r["kek"].clone();
    other[0] ^= 1;
    assert!(unwrap_gost_dstu(&other, &r["wrapped"]).is_err());
    assert!(unwrap_gost_dstu(&r["kek"], &r["wrapped"][..43]).is_err());
    assert!(wrap_gost_dstu(&r["kek"], &r["cek"][..16], &r["iv"]).is_err());
    assert!(wrap_gost_dstu(&r["kek"], &r["cek"], &r["iv"][..4]).is_err());
}

/// A wrap whose check value is wrong in its last byte only, built by
/// hand from the two passes. Corrupting a wrapped byte scrambles the
/// whole check value through CFB, so the test above could not tell an
/// unwrap that compares all four bytes from one that compares three.
#[test]
fn test_unwrap_checks_every_byte_of_the_check_value() {
    use allcrypt::block_ciphers::BlockCipher;
    // RFC 3217 3.1's fixed IV, which the DSTU wrap's second pass uses.
    let outer_iv = vec![0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];
    let r = &rows("wrap")[2];
    let (kek, cek, iv) = (&r["kek"], &r["cek"], &r["iv"]);
    let mut gost = GostCrypto::new(kek, DSTU_PARAM_SET).unwrap();
    let mut mac = gost.clone();
    mac.update(cek);
    let mut cekicv = cek.clone();
    cekicv.extend_from_slice(&mac.digest()[..4]);

    let wrap = |cekicv: &[u8], gost: &mut GostCrypto| {
        let mut temp2 = iv.clone();
        gost.cfb_encrypt(cekicv, &mut temp2, iv).unwrap();
        temp2.reverse();
        let mut out = Vec::new();
        gost.cfb_encrypt(&temp2, &mut out, &outer_iv).unwrap();
        out
    };
    // Built by hand with the right check value, it is the row.
    assert_eq!(wrap(&cekicv, &mut gost), r["wrapped"]);
    for at in 32..36 {
        let mut bad = cekicv.clone();
        bad[at] ^= 0x80;
        assert!(unwrap_gost_dstu(kek, &wrap(&bad, &mut gost)).is_err(), "check byte {}", at - 32);
    }
}
