//! DSTU 4145-2002 against `vectors/dstu4145.vec`, written by
//! `scripts/make_dstu4145_vectors.py`: the standard's worked example,
//! the other examples in Bouncy Castle's and cryptonite's tests, rows on
//! which Bouncy Castle 1.77 and cryptonite agree, and signatures over
//! hashes of other lengths from Bouncy Castle alone. Offline.
//!
//! The whole file is about seventeen seconds in a debug build, most of it
//! the 431-bit curves; each kind of row is its own test so that they run
//! side by side.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api;
use allcrypt::bignum::BigUint;
use allcrypt::ec::dstu4145::{Curve, Point, NAMES};

const VECTORS: &str = include_str!("../vectors/dstu4145.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn int(s: &str) -> BigUint {
    BigUint::from_bytes_be(&unhex(s))
}

/// A curve as the file names it: a named one, or `M:K3,K2,K1:A:B:N:GX:GY`.
fn curve(spec: &str, cache: &mut HashMap<String, Curve>) -> Curve {
    cache.entry(spec.to_string()).or_insert_with(|| {
        if spec.starts_with("dstu4145-") {
            return Curve::by_name(spec).unwrap();
        }
        let p: Vec<&str> = spec.split(':').collect();
        let mut terms: Vec<usize> = p[1].split(',').map(|t| t.parse().unwrap()).collect();
        terms.push(0);
        Curve::custom(p[0].parse().unwrap(), &terms, p[2].parse().unwrap(), &unhex(p[3]),
                      &int(p[4]), &unhex(p[5]), &unhex(p[6])).unwrap()
    }).clone()
}

fn point(c: &Curve, x: &str, y: &str) -> Point {
    Point::Affine(c.field().from_bytes(&unhex(x)).unwrap(),
                  c.field().from_bytes(&unhex(y)).unwrap())
}

/// The rows of one kind, as maps of their fields, and a count by source
/// that the caller checks: a parser that found nothing would pass every
/// assertion.
fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    VECTORS.lines()
        .filter(|line| line.split(' ').next() == Some(kind))
        .map(|line| line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

fn count(rows: &[HashMap<&str, &str>]) -> BTreeMap<String, usize> {
    let mut seen = BTreeMap::new();
    for r in rows {
        *seen.entry(r["source"].to_string()).or_insert(0) += 1;
    }
    seen
}

#[test]
fn test_public_keys() {
    let rows = rows("pub");
    let mut cache = HashMap::new();
    for r in &rows {
        let c = curve(r["curve"], &mut cache);
        let q = c.public_key(&int(r["d"])).unwrap();
        assert_eq!(q, point(&c, r["qx"], r["qy"]), "{r:?}");
        if let Some(name) = c.name() {
            let key = api::Dstu4145Key::from_private(name, &unhex(r["d"])).unwrap();
            let public = key.public_key().to_bytes(false).unwrap();
            assert_eq!(public, [unhex(r["qx"]), unhex(r["qy"])].concat(), "{r:?}");
        }
    }
    let seen = count(&rows);
    assert_eq!(seen["standard"], 1, "{seen:?}");
    assert_eq!(seen["bouncycastle-tests"], 3, "{seen:?}");
    assert_eq!(seen["cryptonite-tests"], 1, "{seen:?}");
    assert_eq!(seen["both"], 70, "{seen:?}");
}

#[test]
fn test_compression() {
    let rows = rows("compress");
    let mut cache = HashMap::new();
    for r in &rows {
        let c = curve(r["curve"], &mut cache);
        let q = point(&c, r["qx"], r["qy"]);
        let packed = unhex(r["packed"]);
        assert_eq!(c.compress(&q).unwrap(), packed, "{r:?}");
        assert_eq!(c.decompress(&packed).unwrap(), q, "{r:?}");
        if let Some(name) = c.name() {
            let key = api::Dstu4145PublicKey::from_bytes(name, &packed).unwrap();
            assert_eq!(key.to_bytes(false).unwrap(), [unhex(r["qx"]), unhex(r["qy"])].concat());
            assert_eq!(key.to_bytes(true).unwrap(), packed);
        }
    }
    let seen = count(&rows);
    assert_eq!(seen["cryptonite-tests"], 1, "{seen:?}");
    assert_eq!(seen["both"], 70, "{seen:?}");
}

/// Signing with the example's `e` gives the example's `(r, s)`; through
/// the facade it is `s || r` at `n`'s width.
#[test]
fn test_signatures() {
    let rows = rows("sign");
    let mut cache = HashMap::new();
    let mut lengths = BTreeMap::new();
    for r in &rows {
        let c = curve(r["curve"], &mut cache);
        let (d, e, hash) = (int(r["d"]), unhex(r["e"]), unhex(r["hash"]));
        // Each of these signatures has a verify row of its own.
        let (rr, ss) = c.sign_with_nonce(&d, &hash, &e).unwrap();
        assert_eq!((&rr, &ss), (&int(r["r"]), &int(r["s"])), "{r:?}");
        if let Some(name) = c.name() {
            let key = api::Dstu4145Key::from_private(name, &unhex(r["d"])).unwrap();
            let signature = key.sign_with_nonce(&hash, &unhex(r["e"])).unwrap();
            let width = c.order().bit_len().div_ceil(8);
            assert_eq!(signature, [ss.to_bytes_be_padded(width).unwrap(),
                                   rr.to_bytes_be_padded(width).unwrap()].concat());
        }
        *lengths.entry(hash.len()).or_insert(0) += 1;
    }
    let seen = count(&rows);
    assert_eq!(seen["standard"], 1, "{seen:?}");
    assert_eq!(seen["bouncycastle-tests"], 4, "{seen:?}");
    assert_eq!(seen["both"], 28, "{seen:?}");
    assert_eq!(seen["bouncycastle"], 14, "{seen:?}");
    // Hashes shorter and longer than every field, and empty.
    for length in [0, 1, 20, 22, 26, 32, 64, 77] {
        assert!(lengths.contains_key(&length), "{lengths:?}");
    }
}

#[test]
fn test_verification() {
    let rows = rows("verify");
    let mut cache = HashMap::new();
    let mut verdicts = BTreeMap::new();
    let mut facade = std::collections::HashSet::new();
    for r in &rows {
        let c = curve(r["curve"], &mut cache);
        let q = point(&c, r["qx"], r["qy"]);
        let ok = r["ok"] == "1";
        let got = c.verify(&q, &unhex(r["hash"]), &int(r["r"]), &int(r["s"])).unwrap();
        assert_eq!(got, ok, "{r:?}");
        // The facade's `s || r`, once per named curve and verdict.
        if let Some(name) = c.name() {
            if facade.insert((name, ok)) {
                let key = api::Dstu4145PublicKey::from_bytes(
                    name, &[unhex(r["qx"]), unhex(r["qy"])].concat()).unwrap();
                let width = c.order().bit_len().div_ceil(8);
                let signature = [int(r["s"]).to_bytes_be_padded(width).unwrap(),
                                 int(r["r"]).to_bytes_be_padded(width).unwrap()].concat();
                assert_eq!(key.verify(&unhex(r["hash"]), &signature).unwrap(), ok, "{r:?}");
            }
        }
        *verdicts.entry(ok).or_insert(0) += 1;
    }
    let seen = count(&rows);
    assert_eq!(seen["standard"], 1, "{seen:?}");
    assert_eq!(seen["cryptonite-tests"], 2, "{seen:?}");
    assert_eq!(seen["both"], 84, "{seen:?}");
    assert_eq!(seen["bouncycastle"], 42, "{seen:?}");
    assert!(verdicts[&false] >= 80 && verdicts[&true] >= 40, "{verdicts:?}");
    assert_eq!(facade.len(), 20);
}

#[test]
fn test_shared_points() {
    let rows = rows("dh");
    let mut cache = HashMap::new();
    for r in &rows {
        let c = curve(r["curve"], &mut cache);
        let peer = point(&c, r["qx"], r["qy"]);
        let cofactor = r["cofactor"] == "1";
        let z = c.shared_point(&int(r["d"]), &peer, cofactor).unwrap();
        assert_eq!(z, point(&c, r["zx"], r["zy"]), "{r:?}");
        if let Some(name) = c.name() {
            let key = api::Dstu4145Key::from_private(name, &unhex(r["d"])).unwrap();
            let peer = api::Dstu4145PublicKey::from_bytes(
                name, &[unhex(r["qx"]), unhex(r["qy"])].concat()).unwrap();
            assert_eq!(key.shared_point(&peer, cofactor).unwrap(),
                       [unhex(r["zx"]), unhex(r["zy"])].concat());
        }
    }
    let seen = count(&rows);
    assert_eq!(seen["cryptonite-tests"], 1, "{seen:?}");
    assert_eq!(seen["both"], 28, "{seen:?}");
}

/// Every named curve has rows of every kind.
#[test]
fn test_every_named_curve_is_covered() {
    for name in NAMES {
        for kind in ["pub", "compress", "sign", "verify", "dh"] {
            assert!(VECTORS.lines().any(|l| l.starts_with(&format!("{kind} curve={name} "))),
                    "{kind} {name}");
        }
    }
}
