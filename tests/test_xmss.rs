//! XMSS and XMSS^MT against the XMSS reference implementation's answers
//! that Botan's tests carry (`vectors/botan_xmss/`, unchanged) and against
//! `vectors/xmss.vec`, written by `scripts/make_xmss_vectors.py`: the
//! reference implementation and Botan 3.6.1 signing alike, Bouncy Castle
//! 1.77 verifying, and signatures with one part changed, which they all
//! refuse. Offline.
//!
//! Every signature here is verified, and every changed one refused. Making
//! a signature again means building its trees, a few million hash calls
//! at height 10, which a debug build takes minutes over: the XMSS^MT rows
//! of trees of height 5 are made again here, and every row is made again
//! by `pytests/test_xmss.py`, which runs the release build - four of them
//! only under `--run-slow`.

use std::collections::HashMap;

use allcrypt::pq::xmss::{verify, XmssParams, XmssPrivateKey};

const OURS: &str = include_str!("../vectors/xmss.vec");
const BOTAN_KEYGEN: &str = include_str!("../vectors/botan_xmss/xmss_keygen_reference.vec");
const BOTAN_SIG: &str = include_str!("../vectors/botan_xmss/xmss_sig.vec");
const BOTAN_VERIFY: &str = include_str!("../vectors/botan_xmss/xmss_verify.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" || s.is_empty() {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Botan's `.vec` records: each starts at a `Params` line.
fn botan(text: &str) -> Vec<HashMap<String, String>> {
    let mut out: Vec<HashMap<String, String>> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (key, value) = line.split_once('=').unwrap();
        let (key, value) = (key.trim().to_string(), value.trim().to_string());
        if key == "Params" {
            out.push(HashMap::new());
        }
        out.last_mut().unwrap().insert(key, value);
    }
    out
}

fn xmss_params(name: &str) -> &'static XmssParams {
    let full = if name.starts_with("XMSS-") { name.to_string() } else { format!("XMSS-{name}") };
    XmssParams::named(&full).unwrap()
}

fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    OURS.lines().filter(|l| l.starts_with(&format!("{kind} ")))
        .map(|l| l.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

#[test]
fn test_the_files() {
    assert_eq!(botan(BOTAN_KEYGEN).len(), 7);
    assert_eq!(botan(BOTAN_SIG).len(), 27);
    assert_eq!(botan(BOTAN_VERIFY).len(), 63);
    assert_eq!(rows("sign").len(), 38);
    assert_eq!(rows("rfc8391").len(), 5);
    assert_eq!(rows("bad").len(), 54);
    for row in rows("sign").iter().chain(&rows("rfc8391")) {
        assert!(row["witnesses"].split(',').count() >= 2, "{}", row["set"]);
    }
}

#[test]
fn test_botan_s_signatures_verify() {
    // xmss_verify.vec, and xmss_sig.vec's signatures under the public key
    // at the front of each private key - Botan 2's derivation among them,
    // which this library does not sign with but verifies.
    let mut count = 0;
    for r in botan(BOTAN_VERIFY) {
        let p = xmss_params(&r["Params"]);
        let (public, msg, sig) = (unhex(&r["PublicKey"]), unhex(&r["Msg"]), unhex(&r["Signature"]));
        assert!(verify(&public, &msg, &sig, false), "{}", p.name);
        let mut bad = sig.clone();
        bad[sig.len() / 2] ^= 0x40;
        assert!(!verify(&public, &msg, &bad, false));
        count += 1;
    }
    for r in botan(BOTAN_SIG) {
        let p = xmss_params(&r["Params"]);
        let key = unhex(&r["PrivateKey"]);
        let public = &key[..4 + 2 * p.n];
        assert!(verify(public, &unhex(&r["Msg"]), &unhex(&r["Signature"]), false), "{}", p.name);
        count += 1;
    }
    assert_eq!(count, 63 + 27);
}

#[test]
fn test_every_signature_verifies() {
    for row in rows("sign").iter().chain(&rows("rfc8391")) {
        let mt = row["kind"] == "xmssmt";
        let (public, msg, sig) = (unhex(row["public"]), unhex(row["msg"]), unhex(row["sig"]));
        assert!(verify(&public, &msg, &sig, mt), "{}", row["set"]);
        assert!(!verify(&public, &msg, &sig, !mt), "{} as the other kind", row["set"]);
        assert_eq!(XmssParams::named(row["set"]).unwrap().oid,
                   u32::from_be_bytes(public[..4].try_into().unwrap()));
    }
}

#[test]
fn test_every_changed_signature_is_refused() {
    let mut seen: Vec<&str> = Vec::new();
    for row in rows("bad") {
        let mt = row["kind"] == "xmssmt";
        let (public, msg, sig) = (unhex(row["public"]), unhex(row["msg"]), unhex(row["sig"]));
        assert!(!verify(&public, &msg, &sig, mt), "{} {}", row["kind"], row["what"]);
        if !seen.contains(&row["what"]) {
            seen.push(row["what"]);
        }
    }
    seen.sort();
    assert_eq!(seen, ["auth-first", "auth-last", "empty", "index", "index-past-the-end", "long",
                      "message", "r", "root", "seed", "short", "upper-layer", "wots-first",
                      "wots-last"]);
}

#[test]
fn test_trees_of_height_five_are_signed_again() {
    // XMSSMT-SHA2_20/4_256 across the end of its lowest tree: one key,
    // signing on from index 31 to 32, as the file's two rows say.
    let all = rows("sign");
    let pick = |idx: &str| all.iter().find(|r| r["set"] == "XMSSMT-SHA2_20/4_256"
                                            && r["idx"] == idx).unwrap();
    let (first, second) = (pick("31"), pick("32"));
    let p = XmssParams::named(first["set"]).unwrap();
    let mut key = XmssPrivateKey::from_seeds(p, &unhex(first["sk_seed"]), &unhex(first["sk_prf"]),
                                             &unhex(first["seed"]), 31).unwrap();
    assert_eq!(key.public_key(), unhex(first["public"]));
    assert_eq!(key.sign(&unhex(first["msg"])).unwrap(), unhex(first["sig"]));
    assert_eq!(key.sign(&unhex(second["msg"])).unwrap(), unhex(second["sig"]));
    assert_eq!(key.index(), 33);
}

/// The cells of every table row in RFC 8391 that names a parameter set.
fn rfc_rows() -> Vec<Vec<String>> {
    include_str!("../rfcs/rfc8391.txt").lines().map(str::trim)
        .filter(|l| l.starts_with('|') && (l.contains("| XMSS-") || l.contains("| XMSSMT-")))
        .map(|l| l.trim_matches('|').split('|').map(|c| c.trim().to_string()).collect())
        .collect()
}

#[test]
fn test_the_parameter_sets_are_rfc_8391_s() {
    // Sections 5.3 and 5.4: name, hash, n, w, len, h and, for XMSS^MT, d;
    // the IANA registries: OID and name; section 5.3's table of sizes:
    // name and signature bytes. SP 800-208's added sets are not in it.
    let (mut shapes, mut oids, mut sizes) = (0, 0, 0);
    for row in rfc_rows() {
        let p = XmssParams::named(&row[1].replace(' ', "")).ok()
            .or_else(|| XmssParams::named(&row[0]).ok()).unwrap_or_else(|| panic!("{row:?}"));
        match row.len() {
            3 => {
                assert_eq!(u32::from_str_radix(&row[0][2..], 16).unwrap(), p.oid, "{}", p.name);
                assert_eq!(p.multi_tree, row[1].starts_with("XMSSMT-"));
                oids += 1;
            }
            6 if row[1].contains(',') => {
                assert_eq!(row[1].replace(',', "").parse::<usize>().unwrap(), p.signature_len(),
                           "{}", p.name);
                sizes += 1;
            }
            6 | 7 => {
                assert_eq!(row[2].parse::<usize>().unwrap(), p.n, "{}", p.name);
                assert_eq!(row[3], "16");
                assert_eq!(row[4].parse::<usize>().unwrap(), p.wots_len(), "{}", p.name);
                assert_eq!(row[5].parse::<u32>().unwrap(), p.h, "{}", p.name);
                assert_eq!(row.get(6).map_or(1, |d| d.parse::<u32>().unwrap()), p.d);
                use allcrypt::pq::xmss::XmssHash;
                let hash = match &row[1][..8] {
                    "SHAKE128" => XmssHash::Shake128,
                    "SHAKE256" => XmssHash::Shake256,
                    _ => XmssHash::Sha2,
                };
                assert_eq!(hash, p.hash, "{}", p.name);
                shapes += 1;
            }
            _ => panic!("{row:?}"),
        }
    }
    assert_eq!((shapes, oids, sizes), (12 + 32, 12 + 32, 6));
}
