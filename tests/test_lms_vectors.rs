//! LMS and HSS against `vectors/lms.vec`, written by
//! `scripts/make_lms_vectors.py`: trees of every parameter set and
//! hierarchies of one, two and three levels, signed by hash-sigs, Bouncy
//! Castle 1.77 and pyhsslms, agreeing, and verified by those and hbs-lms;
//! and signatures with one part changed, which they refuse. Offline.
//!
//! Every signature is verified here, and every changed one refused. The
//! signatures are made again from their seeds where building the trees
//! costs little in a debug build - the hash calls a tree costs, SHAKE
//! weighted for its slower debug build, under a budget; the rest are made
//! again by `pytests/test_lms.py`, which runs the release build.

use std::collections::HashMap;

use allcrypt::pq::lms::{hss_verify, lms_verify, HssPrivateKey, LmotsParams, LmsHash,
                        LmsParams, LmsPrivateKey};

const VECTORS: &str = include_str!("../vectors/lms.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    VECTORS.lines().filter(|l| l.starts_with(&format!("{kind} ")))
        .map(|l| l.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

/// What building a tree costs in hash calls, SHAKE counted five times.
fn cost(lms: &LmsParams, ots: &LmotsParams) -> u64 {
    let calls = (1u64 << lms.h) * ots.p as u64 * ((1u64 << ots.w) - 1);
    if lms.hash == LmsHash::Shake256 { 5 * calls } else { calls }
}

const BUDGET: u64 = 40_000;
const REBUILT_TREES: usize = 28;
const REBUILT_HIERARCHIES: usize = 12;

#[test]
fn test_the_file() {
    assert_eq!(rows("lms").len(), 88);
    assert_eq!(rows("hss").len(), 37);
    assert_eq!(rows("bad").len(), 162);
    // Every LM-OTS parameter set signs.
    let mut seen: Vec<&str> = rows("lms").iter().map(|r| r["ots"]).collect();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 16);
    for row in rows("lms").iter().chain(&rows("hss")) {
        let w = row["witnesses"];
        assert!(w.contains("hashsigs") && w.contains("bc-lms"), "{w}");
    }
    for row in rows("bad") {
        assert!(row["witnesses"].contains("hashsigs"));
        if row["what"] != "long" {
            assert!(row["witnesses"].contains("bc-lms") && row["witnesses"].contains("pyhsslms"));
        }
    }
}

#[test]
fn test_every_tree() {
    let mut rebuilt = 0;
    for row in rows("lms") {
        let lms = LmsParams::named(row["lms"]).unwrap();
        let ots = LmotsParams::named(row["ots"]).unwrap();
        let (public, msg, sig) = (unhex(row["public"]), unhex(row["msg"]), unhex(row["sig"]));
        assert!(lms_verify(&public, &msg, &sig), "{} {}", lms.name, ots.name);
        let mut wrapped_public = 1u32.to_be_bytes().to_vec();
        wrapped_public.extend_from_slice(&public);
        let mut wrapped_sig = vec![0u8; 4];
        wrapped_sig.extend_from_slice(&sig);
        assert!(hss_verify(&wrapped_public, &msg, &wrapped_sig));
        if cost(lms, ots) <= BUDGET {
            let id: [u8; 16] = unhex(row["i"]).try_into().unwrap();
            let q: u32 = row["q"].parse().unwrap();
            let mut key = LmsPrivateKey::from_seed(lms, ots, &unhex(row["seed"]), &id, q)
                .unwrap();
            assert_eq!(key.public_key(), public, "{} {}", lms.name, ots.name);
            assert_eq!(key.sign(&msg).unwrap(), sig, "{} {} q={q}", lms.name, ots.name);
            rebuilt += 1;
        }
    }
    assert!(rebuilt >= REBUILT_TREES, "{rebuilt}");
}

#[test]
fn test_every_hierarchy() {
    let mut rebuilt = 0;
    for row in rows("hss") {
        let levels: Vec<_> = row["levels"].split(',').map(|pair| {
            let (lms, ots) = pair.split_once('/').unwrap();
            (LmsParams::named(lms).unwrap(), LmotsParams::named(ots).unwrap())
        }).collect();
        let (public, msg, sig) = (unhex(row["public"]), unhex(row["msg"]), unhex(row["sig"]));
        assert!(hss_verify(&public, &msg, &sig), "{}", row["levels"]);
        if levels.iter().map(|(l, o)| cost(l, o)).sum::<u64>() <= BUDGET {
            let id: [u8; 16] = unhex(row["i"]).try_into().unwrap();
            let count: u64 = row["count"].parse().unwrap();
            let mut key = HssPrivateKey::from_seed(&levels, &unhex(row["seed"]), &id, count)
                .unwrap();
            assert_eq!(key.public_key(), public, "{}", row["levels"]);
            assert_eq!(key.sign(&msg).unwrap(), sig, "{} count={count}", row["levels"]);
            // Read back from its bytes, the key has moved past the leaf.
            let copy = HssPrivateKey::from_bytes(&key.to_bytes()).unwrap();
            assert_eq!(copy.count(), count + 1);
            assert_eq!(copy.to_bytes(), key.to_bytes());
            rebuilt += 1;
        }
    }
    assert!(rebuilt >= REBUILT_HIERARCHIES, "{rebuilt}");
}

#[test]
fn test_every_changed_signature_is_refused() {
    let mut seen: Vec<&str> = Vec::new();
    for row in rows("bad") {
        let (public, msg, sig) = (unhex(row["public"]), unhex(row["msg"]), unhex(row["sig"]));
        assert!(!hss_verify(&public, &msg, &sig), "{}", row["what"]);
        if !seen.contains(&row["what"]) {
            seen.push(row["what"]);
        }
    }
    seen.sort();
    assert_eq!(seen, ["C", "chain-public", "empty", "last-signature", "levels", "lms-type",
                      "long", "message", "nspk", "ots-type", "path-first", "path-last", "q",
                      "q-past-the-tree", "root", "short", "y-first", "y-last"]);
}

#[test]
fn test_a_hierarchy_signs_across_its_lower_trees_in_order() {
    // Signing on from a key equals reading the key at each count: the
    // lower tree is replaced when it runs out, from the next leaf above.
    let row = rows("hss").into_iter()
        .find(|r| r["levels"] == "LMS_SHA256_M24_H5/LMOTS_SHA256_N24_W2,\
                                  LMS_SHA256_M24_H5/LMOTS_SHA256_N24_W2,\
                                  LMS_SHA256_M24_H5/LMOTS_SHA256_N24_W2"
                    .replace(' ', "")).unwrap();
    let levels = [(LmsParams::named("LMS_SHA256_M24_H5").unwrap(),
                   LmotsParams::named("LMOTS_SHA256_N24_W2").unwrap()); 3];
    let id: [u8; 16] = unhex(row["i"]).try_into().unwrap();
    let seed = unhex(row["seed"]);
    let mut walking = HssPrivateKey::from_seed(&levels, &seed, &id, 1020).unwrap();
    for count in 1020..1030u64 {
        let mut fresh = HssPrivateKey::from_seed(&levels, &seed, &id, count).unwrap();
        let message = count.to_be_bytes();
        let sig = walking.sign(&message).unwrap();
        assert_eq!(sig, fresh.sign(&message).unwrap(), "count {count}");
        assert!(hss_verify(&walking.public_key(), &message, &sig));
    }
    assert_eq!(walking.count(), 1030);
    let mut last = HssPrivateKey::from_seed(&levels, &seed, &id, (1 << 15) - 1).unwrap();
    assert_eq!(last.remaining(), 1);
    assert!(last.sign(b"the last").is_ok());
    assert!(last.sign(b"one more").is_err());
    assert!(HssPrivateKey::from_seed(&levels, &seed, &id, 1 << 15).unwrap().sign(b"x").is_err());
    assert!(HssPrivateKey::from_seed(&levels, &seed, &id, (1 << 15) + 1).is_err());
}
