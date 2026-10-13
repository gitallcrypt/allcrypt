//! Ukraine's ten S-boxes, "DKE No. 1 from supplements 1 to 10 to
//! instruction 114", against `vectors/dstu_dke.vec`, written by
//! `scripts/make_dstu_dke_vectors.py`: the tables as cryptonite and
//! li0ard both carry them, and GOST 28147-89 in ECB, CFB and counter
//! mode, its MAC and GOST 34.311-95 under tables 2 to 10, on which
//! Bouncy Castle 1.77, gost89 and cryptonite agree (Bouncy Castle and
//! cryptonite for the counter mode). Offline.

use std::collections::{BTreeMap, HashSet};

use allcrypt::api::{AnyBlockCipher, AnyHash, CipherStream, Mode, HASHES};
use allcrypt::block_ciphers::gost::{GostCrypto, DSTU4145_DEFAULT_DKE, DSTU_DKE_NAMES,
                                    DSTU_PARAM_SET};
use allcrypt::hash_functions::gost94::Gost94;
use allcrypt::hash_functions::HashFunction;
use allcrypt::Mac;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows(kind: &str) -> Vec<BTreeMap<&'static str, &'static str>> {
    let found: Vec<_> = include_str!("../vectors/dstu_dke.vec").lines()
        .filter(|line| line.split(' ').next() == Some(kind))
        .map(|line| line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect();
    assert!(!found.is_empty(), "no {kind} rows");
    found
}

/// The table's name, spelt out rather than read from `DSTU_DKE_NAMES`,
/// so a list in the wrong order cannot agree with itself.
fn name(row: &BTreeMap<&str, &str>) -> String {
    format!("dstu-dke-{}", row["dke"])
}

#[test]
fn test_the_tables_are_the_witnesses() {
    let tables = rows("dke");
    assert_eq!(tables.len(), 10);
    let mut seen = HashSet::new();
    for (i, row) in tables.iter().enumerate() {
        assert_eq!(row["number"], (i + 1).to_string());
        let dke = unhex(row["value"]);
        assert_eq!(DSTU_DKE_NAMES[i], format!("dstu-dke-{}", i + 1));
        let named = GostCrypto::sbox_named(&format!("dstu-dke-{}", i + 1)).unwrap();
        assert_eq!(named, GostCrypto::sbox_from_dke(&dke).unwrap());
        for line in &named {
            let mut sorted = line.clone();
            sorted.sort();
            assert_eq!(sorted, (0..16u8).collect::<Vec<_>>(), "not a permutation");
        }
        assert!(seen.insert(dke));
    }
    // The first is the default DKE.
    assert_eq!(unhex(tables[0]["value"]), DSTU4145_DEFAULT_DKE);
    assert_eq!(GostCrypto::sbox_named("dstu-dke-1").unwrap(),
               GostCrypto::sbox_named(DSTU_PARAM_SET).unwrap());
}

fn run(sbox: &str, mode: Mode, key: &[u8], iv: &[u8], data: &[u8], decrypting: bool) -> Vec<u8> {
    let cipher = AnyBlockCipher::new("gost", key, Some(sbox)).unwrap();
    let mut s = CipherStream::new(cipher, mode, iv, decrypting).unwrap();
    let mut out = s.update(data).unwrap();
    out.extend(s.finish().unwrap());
    out
}

#[test]
fn test_ecb_cfb_and_counter_mode() {
    let mut count = 0;
    for (kind, mode) in [("gost-ecb", Mode::Ecb), ("gost-cfb", Mode::Cfb), ("gost-cnt", Mode::Ctr)] {
        for r in rows(kind) {
            let (key, pt, ct) = (unhex(r["key"]), unhex(r["pt"]), unhex(r["ct"]));
            let iv = r.get("iv").map(|v| unhex(v)).unwrap_or_default();
            assert_eq!(run(&name(&r), mode, &key, &iv, &pt, false), ct, "{kind} {}", r["dke"]);
            assert_eq!(run(&name(&r), mode, &key, &iv, &ct, true), pt, "{kind} {}", r["dke"]);
            count += 1;
        }
    }
    assert_eq!(count, 9 * (3 + 5 + 5));
}

#[test]
fn test_mac() {
    for r in rows("gost-mac") {
        let mut mac = GostCrypto::new(&unhex(r["key"]), &name(&r)).unwrap();
        mac.update(&unhex(r["msg"]));
        assert_eq!(mac.digest()[..4], unhex(r["tag"])[..], "dke {}", r["dke"]);
    }
}

#[test]
fn test_gost34311() {
    for r in rows("gost34311") {
        let (msg, digest) = (unhex(r["msg"]), unhex(r["digest"]));
        let n = r["dke"];
        assert_eq!(Gost94::with_param_set(&msg, &name(&r)).unwrap().digest(), digest, "dke {n}");
        let catalogue = format!("gost34311_dke{n}");
        assert!(HASHES.contains(&catalogue.as_str()));
        let mut h = AnyHash::new(&catalogue).unwrap();
        for chunk in msg.chunks(13) {
            h.update(chunk);
        }
        assert_eq!(h.digest(), digest);
        assert_eq!(h.name(), catalogue);
    }
    // dstu-dke-1 is the default table, under the default name.
    assert_eq!(Gost94::with_param_set(b"abc", "dstu-dke-1").unwrap().name(), "gost34311");
    assert!(AnyHash::new("gost34311_dke1").is_err());
    assert!(AnyHash::new("gost34311_dke11").is_err());
    assert!(AnyHash::new("gost34311_dke02").is_err());
}
