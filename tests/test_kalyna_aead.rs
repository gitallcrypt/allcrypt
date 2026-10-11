//! DSTU 7624's GCM, GMAC, CCM and XTS over Kalyna against
//! `vectors/kalyna_aead.vec`, written by
//! `scripts/make_kalyna_aead_vectors.py`: the published examples, rows on
//! which Bouncy Castle 1.77 and cryptonite agree, and rows from each
//! alone where the other stops - each row tagged with its source. Every
//! row is checked in both directions, directly and through `api`.
//! Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api;
use allcrypt::block_ciphers::kalyna::Kalyna;
use allcrypt::block_ciphers::kalyna_aead as aead;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn cipher_name(block: usize) -> String {
    format!("kalyna-{}", 8 * block)
}

/// Every row's fields, with the kind first.
fn rows() -> Vec<(String, HashMap<String, String>)> {
    include_str!("../vectors/kalyna_aead.vec").lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let kind = line.split(' ').next().unwrap().to_string();
            let fields = line.split(' ').skip(1)
                .map(|w| { let (k, v) = w.split_once('=').unwrap(); (k.to_string(), v.to_string()) })
                .collect();
            (kind, fields)
        })
        .collect()
}

#[test]
fn test_kalyna_aead_vectors() {
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (kind, f) in rows() {
        let block: usize = f["block"].parse().unwrap();
        let key = unhex(&f["key"]);
        let name = cipher_name(block);
        let mut cipher = Kalyna::new(block, &key).unwrap();
        let line = format!("{kind} {f:?}");
        match kind.as_str() {
            "gcm" => {
                let (iv, aad, pt) = (unhex(&f["iv"]), unhex(&f["aad"]), unhex(&f["pt"]));
                let (ct, tag) = (unhex(&f["ct"]), unhex(&f["tag"]));
                let q: usize = f["q"].parse().unwrap();
                assert_eq!(aead::gcm_encrypt(&mut cipher, &iv, &aad, &pt, q).unwrap(),
                           (ct.clone(), tag.clone()), "{line}");
                assert_eq!(aead::gcm_decrypt(&mut cipher, &iv, &aad, &ct, &tag, q).unwrap(), pt,
                           "{line}");
                let mut bad = tag.clone();
                bad[0] ^= 1;
                assert!(aead::gcm_decrypt(&mut cipher, &iv, &aad, &ct, &bad, q).is_err());
                let aead_name = format!("{name}-gcm-{q}");
                assert_eq!(api::aead_encrypt(&aead_name, &key, &iv, &aad, &pt).unwrap(),
                           (ct.clone(), tag.clone()), "{line}");
                assert_eq!(api::aead_decrypt(&aead_name, &key, &iv, &aad, &ct, &tag).unwrap(), pt);
            }
            "gmac" => {
                let q: usize = f["q"].parse().unwrap();
                let tag = unhex(&f["tag"]);
                assert_eq!(aead::gmac(&mut cipher, &unhex(&f["msg"]), q).unwrap(), tag, "{line}");
                assert_eq!(api::kalyna_gmac(&name, &key, &unhex(&f["msg"]), q).unwrap(), tag);
            }
            "ccm" => {
                let (iv, aad, pt) = (unhex(&f["iv"]), unhex(&f["aad"]), unhex(&f["pt"]));
                let sealed = unhex(&f["sealed"]);
                let q: usize = f["q"].parse().unwrap();
                let nb: usize = f["nb"].parse().unwrap();
                assert_eq!(aead::ccm_encrypt(&mut cipher, &iv, &aad, &pt, q, nb).unwrap(), sealed,
                           "{line}");
                assert_eq!(aead::ccm_decrypt(&mut cipher, &iv, &aad, &sealed, q, nb).unwrap(), pt,
                           "{line}");
                assert_eq!(api::kalyna_ccm_decrypt(&name, &key, &iv, &aad, &sealed, q, nb).unwrap(),
                           pt);
                for i in [0, sealed.len() - 1] {
                    let mut bad = sealed.clone();
                    bad[i] ^= 0x80;
                    assert!(aead::ccm_decrypt(&mut cipher, &iv, &aad, &bad, q, nb).is_err(), "{i}");
                }
                if nb == 4 {
                    let (ct, tag) = sealed.split_at(pt.len());
                    let aead_name = format!("{name}-ccm-{q}");
                    assert_eq!(api::aead_encrypt(&aead_name, &key, &iv, &aad, &pt).unwrap(),
                               (ct.to_vec(), tag.to_vec()), "{line}");
                    assert_eq!(api::aead_decrypt(&aead_name, &key, &iv, &aad, ct, tag).unwrap(), pt);
                }
            }
            "xts" => {
                let (iv, pt, ct) = (unhex(&f["iv"]), unhex(&f["pt"]), unhex(&f["ct"]));
                assert_eq!(aead::xts_encrypt(&mut cipher, &iv, &pt).unwrap(), ct, "{line}");
                assert_eq!(aead::xts_decrypt(&mut cipher, &iv, &ct).unwrap(), pt, "{line}");
                assert_eq!(api::kalyna_xts_encrypt(&name, &key, &iv, &pt).unwrap(), ct);
                assert_eq!(api::kalyna_xts_decrypt(&name, &key, &iv, &ct).unwrap(), pt);
            }
            other => panic!("{other}"),
        }
        *seen.entry((kind, f["source"].clone())).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    let count = |kind: &str, source: &str| seen.get(&(kind.into(), source.into())).copied()
        .unwrap_or(0);
    assert_eq!(count("gcm", "standard"), 6, "{seen:?}");
    assert_eq!(count("gmac", "standard"), 5, "{seen:?}");
    assert_eq!(count("ccm", "standard") + count("ccm", "cryptonite-tests"), 5, "{seen:?}");
    assert_eq!(count("xts", "standard") + count("xts", "cryptonite-tests"), 10, "{seen:?}");
    for (kind, source, at_least) in [("gcm", "both", 100), ("gcm", "bouncycastle", 20),
                                     ("gmac", "both", 40), ("gmac", "bouncycastle", 10),
                                     ("ccm", "both", 150), ("ccm", "cryptonite", 40),
                                     ("ccm", "bouncycastle", 10), ("xts", "both", 20),
                                     ("xts", "cryptonite", 15)] {
        assert!(count(kind, source) >= at_least, "{kind} {source}: {seen:?}");
    }
}

/// Every AEAD through the stream interface: what `finish` produces
/// `open` takes back, and the tag length the name asks for is the one it
/// gets.
#[test]
fn test_the_kalyna_aeads_through_the_catalogue() {
    for block in [16usize, 32, 64] {
        for mode in ["gcm", "ccm"] {
            let name = format!("kalyna-{}-{mode}", 8 * block);
            assert!(api::AEADS.contains(&name.as_str()), "{name}");
            let key = vec![7u8; block];
            let nonce = vec![9u8; block];
            for len in [0usize, 1, block - 1, block, block + 1, 3 * block] {
                let msg: Vec<u8> = (0..len as u32).map(|i| i as u8).collect();
                let (ct, tag) = api::aead_encrypt(&name, &key, &nonce, b"header", &msg).unwrap();
                assert_eq!(tag.len(), block, "{name}");
                assert_eq!(ct.len(), len);
                assert_eq!(api::aead_decrypt(&name, &key, &nonce, b"header", &ct, &tag).unwrap(),
                           msg);
                assert!(api::aead_decrypt(&name, &key, &nonce, b"other", &ct, &tag).is_err());
            }
            // The nonce is one block, exactly.
            assert!(api::aead_encrypt(&name, &key, &nonce[1..], b"", b"m").is_err());
            assert!(api::aead_encrypt(&name, &key, &[0u8; 12], b"", b"m").is_err());
        }
        // GCM's tag is 8 bytes to the block.
        let gcm = format!("kalyna-{}-gcm", 8 * block);
        let (_, tag) = api::aead_encrypt(&format!("{gcm}-8"), &vec![1; block], &vec![0; block],
                                         b"", b"m").unwrap();
        assert_eq!(tag.len(), 8);
        assert!(api::AeadStream::new(&format!("{gcm}-7"), &vec![1; block], &vec![0; block], b"",
                                     false).is_err());
        assert!(api::AeadStream::new(&format!("{gcm}-{}", block + 1), &vec![1; block],
                                     &vec![0; block], b"", false).is_err());
        // CCM's tag length must have a code in the flag byte.
        let ccm = format!("kalyna-{}-ccm", 8 * block);
        assert!(api::AeadStream::new(&format!("{ccm}-12"), &vec![1; block], &vec![0; block],
                                     b"", false).is_err());
        assert!(api::AeadStream::new(&format!("{ccm}-8"), &vec![1; block], &vec![0; block],
                                     b"", false).is_ok());
    }
}
