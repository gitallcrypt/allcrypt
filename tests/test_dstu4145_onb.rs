//! DSTU 4145-2002 on its five curves in an optimal normal basis,
//! `dstu4145-m173-onb` to `dstu4145-m431-onb`, against
//! `vectors/dstu4145_onb.vec`, written by
//! `scripts/make_dstu4145_onb_vectors.py`: public keys, compressions,
//! signatures by li0ard with a given `e` that cryptonite verifies too,
//! changed signatures both refuse, and shared points, every field
//! element in the normal basis. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api;
use allcrypt::bignum::BigUint;
use allcrypt::ec::dstu4145::{Curve, Point, NAMES};

const VECTORS: &str = include_str!("../vectors/dstu4145_onb.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn int(s: &str) -> BigUint {
    BigUint::from_bytes_be(&unhex(s))
}

fn curve(name: &str, cache: &mut HashMap<String, Curve>) -> Curve {
    cache.entry(name.to_string()).or_insert_with(|| Curve::by_name(name).unwrap()).clone()
}

/// A point from its normal-basis coordinates.
fn point(c: &Curve, x: &str, y: &str) -> Point {
    Point::Affine(c.element_from_bytes(&unhex(x)).unwrap(),
                  c.element_from_bytes(&unhex(y)).unwrap())
}

fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    let found: Vec<_> = VECTORS.lines()
        .filter(|line| line.split(' ').next() == Some(kind))
        .map(|line| line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect();
    assert!(!found.is_empty(), "no {kind} rows");
    found
}

fn count(rows: &[HashMap<&str, &str>]) -> BTreeMap<String, usize> {
    let mut seen = BTreeMap::new();
    for r in rows {
        *seen.entry(r["source"].to_string()).or_insert(0) += 1;
    }
    seen
}

#[test]
fn test_public_keys_and_compression() {
    let mut cache = HashMap::new();
    for r in rows("pub") {
        let c = curve(r["curve"], &mut cache);
        assert!(c.is_normal_basis());
        assert_eq!(c.public_key(&int(r["d"])).unwrap(), point(&c, r["qx"], r["qy"]), "{r:?}");
        let key = api::Dstu4145Key::from_private(r["curve"], &unhex(r["d"])).unwrap();
        assert_eq!(key.public_key().to_bytes(false).unwrap(),
                   [unhex(r["qx"]), unhex(r["qy"])].concat());
    }
    let compress = rows("compress");
    for r in &compress {
        let c = curve(r["curve"], &mut cache);
        let q = point(&c, r["qx"], r["qy"]);
        let packed = unhex(r["packed"]);
        assert_eq!(c.compress(&q).unwrap(), packed, "{r:?}");
        assert_eq!(c.decompress(&packed).unwrap(), q, "{r:?}");
        let key = api::Dstu4145PublicKey::from_bytes(r["curve"], &packed).unwrap();
        assert_eq!(key.to_bytes(false).unwrap(), [unhex(r["qx"]), unhex(r["qy"])].concat());
    }
    assert_eq!(count(&rows("pub"))["both"], 30);
    assert_eq!(count(&compress)["both"], 30);
}

#[test]
fn test_signatures_and_verification() {
    let mut cache = HashMap::new();
    let signs = rows("sign");
    for r in &signs {
        let c = curve(r["curve"], &mut cache);
        let (d, hash) = (int(r["d"]), unhex(r["hash"]));
        let (rr, ss) = c.sign_with_nonce(&d, &hash, &unhex(r["e"])).unwrap();
        assert_eq!((&rr, &ss), (&int(r["r"]), &int(r["s"])), "{r:?}");
        let key = api::Dstu4145Key::from_private(r["curve"], &unhex(r["d"])).unwrap();
        let width = c.order().bit_len().div_ceil(8);
        assert_eq!(key.sign_with_nonce(&hash, &unhex(r["e"])).unwrap(),
                   [ss.to_bytes_be_padded(width).unwrap(),
                    rr.to_bytes_be_padded(width).unwrap()].concat());
    }
    let verifies = rows("verify");
    let mut verdicts = BTreeMap::new();
    for r in &verifies {
        let c = curve(r["curve"], &mut cache);
        let q = point(&c, r["qx"], r["qy"]);
        let ok = r["ok"] == "1";
        assert_eq!(c.verify(&q, &unhex(r["hash"]), &int(r["r"]), &int(r["s"])).unwrap(), ok,
                   "{r:?}");
        *verdicts.entry(ok).or_insert(0) += 1;
    }
    assert_eq!(count(&signs), BTreeMap::from([("both".to_string(), 15),
                                              ("li0ard".to_string(), 5)]));
    assert_eq!(verdicts[&true], 20);
    assert!(verdicts[&false] >= 15, "{verdicts:?}");
}

#[test]
fn test_shared_points() {
    let mut cache = HashMap::new();
    let dh = rows("dh");
    for r in &dh {
        let c = curve(r["curve"], &mut cache);
        let cofactor = r["cofactor"] == "1";
        let z = c.shared_point(&int(r["d"]), &point(&c, r["qx"], r["qy"]), cofactor).unwrap();
        assert_eq!(z, point(&c, r["zx"], r["zy"]), "{r:?}");
        let key = api::Dstu4145Key::from_private(r["curve"], &unhex(r["d"])).unwrap();
        let peer = api::Dstu4145PublicKey::from_bytes(
            r["curve"], &[unhex(r["qx"]), unhex(r["qy"])].concat()).unwrap();
        assert_eq!(key.shared_point(&peer, cofactor).unwrap(),
                   [unhex(r["zx"]), unhex(r["zy"])].concat());
    }
    assert_eq!(count(&dh)["both"], 10);
}

/// Every curve in a normal basis has rows of every kind, and a key on
/// one is refused a container, whose parameters cannot describe it.
#[test]
fn test_every_normal_basis_curve_is_covered() {
    for name in &NAMES[10..] {
        for kind in ["pub", "compress", "sign", "verify", "dh"] {
            assert!(VECTORS.lines().any(|l| l.starts_with(&format!("{kind} curve={name} "))),
                    "{kind} {name}");
        }
        let key = api::Dstu4145Key::from_private(name, &[7]).unwrap();
        assert!(key.private_key_info(None).is_err());
    }
}
