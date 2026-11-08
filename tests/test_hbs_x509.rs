//! HSS, XMSS and XMSS^MT certificates (RFC 9802) against
//! `vectors/hbs_x509.vec`, written by `scripts/make_hbs_x509_vectors.py`:
//! Bouncy Castle 1.85's self-signed certificates, which this library reads
//! and verifies, and this library's, which Bouncy Castle verified and which
//! are made again here byte for byte. RFC 9802's own three appendix
//! certificates are read in `src/x509/rfc9802_tests.rs`. Offline.

use std::cell::RefCell;
use std::collections::HashMap;

use allcrypt::pq::lms::{HssPrivateKey, LmotsParams, LmsParams};
use allcrypt::pq::xmss::{XmssParams, XmssPrivateKey};
use allcrypt::x509::builder::{key_usage, CertificateBuilder, SigningKey, SubjectKey};
use allcrypt::x509::{verify, Certificate, HashSig, PublicKey, SignatureAlgorithm};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    let text = include_str!("../vectors/hbs_x509.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: ")).unwrap()
        .parse().unwrap();
    assert_eq!(text.lines().filter(|l| !l.starts_with('#')).count(), declared);
    text.lines().filter(|l| l.starts_with(&format!("{kind} ")))
        .map(|l| l.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

fn verifies_itself(der: &[u8]) -> (HashSig, String) {
    let certificate = Certificate::parse(der).unwrap();
    let scheme = match certificate.public_key {
        PublicKey::HashSig { scheme, key } => {
            assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::HashSig(scheme));
            (scheme, allcrypt::x509::hash_sig_key_name(scheme, key).unwrap())
        }
        ref other => panic!("{other:?}"),
    };
    let policy = verify::Policy::default();
    verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                          certificate.signature, &certificate.public_key, &policy).unwrap();
    let mut signature = certificate.signature.to_vec();
    let last = signature.len() - 1;
    signature[last] ^= 0x01;
    assert!(verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                                  &signature, &certificate.public_key, &policy).is_err());
    scheme
}

#[test]
fn test_bouncy_castle_s_certificates() {
    let all = rows("bc");
    assert_eq!(all.len(), 12);
    for r in all {
        let (scheme, name) = verifies_itself(&unhex(r["cert"]));
        let expected = match r["scheme"] {
            "hss" => HashSig::Hss,
            "xmss" => HashSig::Xmss,
            _ => HashSig::XmssMt,
        };
        assert_eq!(scheme, expected, "{}", r["params"]);
        if scheme == HashSig::Hss {
            // The top level's parameter sets, as the row names them.
            let top = r["params"].split(',').next().unwrap();
            assert!(name.ends_with(&format!("{top} on top")), "{name}");
        }
    }
}

/// What `tools/src/bin/hbs_certs.rs` makes, made again.
fn certificate(name: &str, scheme: HashSig, public: &[u8], key: &SigningKey<'_>) -> Vec<u8> {
    let common_name = format!("allcrypt {name}");
    let mut builder = CertificateBuilder::new(&common_name, SubjectKey::HashSig { scheme,
                                                                              key: public });
    builder.is_ca = Some((true, None));
    builder.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
    builder.key_identifiers = true;
    builder.sign(key).unwrap()
}

/// Whether a row's key is cheap to build in a debug build: SHA-256, and
/// no tree above height 5. Measured in debug, a tree of height 10 takes
/// most of a minute, and the SHAKE rows of height 5 take 7 to 28 seconds
/// each, Keccak being slow unoptimised; the SHA-256 ones under a second,
/// XMSS^MT 20/4 and 40/8 two and four.
fn cheap(r: &HashMap<&str, &str>) -> bool {
    let (tallest, name) = if r["scheme"] == "hss" {
        (r["levels"].split(',')
            .map(|l| LmsParams::named(l.split_once('/').unwrap().0).unwrap().h).max().unwrap(),
         r["levels"])
    } else {
        (XmssParams::named(r["set"]).unwrap().tree_height(), r["set"])
    };
    tallest <= 5 && !name.contains("SHAKE")
}

fn make_again(r: &HashMap<&str, &str>) -> Vec<u8> {
    if r["scheme"] == "hss" {
            let levels: Vec<(&'static LmsParams, &'static LmotsParams)> = r["levels"].split(',')
                .map(|l| {
                    let (lms, ots) = l.split_once('/').unwrap();
                    (LmsParams::named(lms).unwrap(), LmotsParams::named(ots).unwrap())
                }).collect();
            let id: [u8; 16] = unhex(r["id"]).try_into().unwrap();
            let count: u64 = r["count"].parse().unwrap();
            let key = HssPrivateKey::from_seed(&levels, &unhex(r["seed"]), &id, count).unwrap();
            let public = key.public_key();
            let key = RefCell::new(key);
            let der = certificate(r["levels"].split(',').next().unwrap(), HashSig::Hss, &public,
                                  &SigningKey::Hss(&key));
            assert_eq!(key.borrow().count(), count + 1);
            der
    } else {
            let p = XmssParams::named(r["set"]).unwrap();
            let idx: u64 = r["idx"].parse().unwrap();
            let key = XmssPrivateKey::from_seeds(p, &unhex(r["sk_seed"]), &unhex(r["sk_prf"]),
                                                 &unhex(r["seed"]), idx).unwrap();
            let public = key.public_key();
            let scheme = if p.multi_tree { HashSig::XmssMt } else { HashSig::Xmss };
            let key = RefCell::new(key);
            let der = certificate(p.name, scheme, &public, &SigningKey::Xmss(&key));
            assert_eq!(key.borrow().index(), idx + 1);
            der
    }
}

/// Every certificate this library made verifies here, as it did under
/// Bouncy Castle; the five whose keys are cheap to build - HSS under
/// three LM-OTS parameter sets and two hash lengths, and XMSS^MT at two
/// and eight layers - are made again byte for byte. The rest are
/// `test_the_expensive_keys_are_made_again`.
#[test]
fn test_this_library_s_certificates_are_made_again() {
    let all = rows("ours");
    assert_eq!(all.len(), 15);
    let (mut schemes, mut made) = (Vec::new(), 0);
    for r in &all {
        let der = unhex(r["cert"]);
        let (scheme, _) = verifies_itself(&der);
        if !schemes.contains(&scheme) {
            schemes.push(scheme);
        }
        if cheap(r) {
            assert_eq!(make_again(r), der, "{}", r.get("set").or(r.get("levels")).unwrap());
            made += 1;
        }
    }
    assert_eq!(schemes.len(), 3);
    assert_eq!(made, 5);
}

/// The ten other rows, made again: 17 seconds in release, and about seven
/// minutes in debug (measured as the whole file's 418 seconds before
/// these rows moved here, against 9 after). Run with
/// `cargo test --release --test test_hbs_x509 -- --ignored`. The
/// builder's code paths are the cheap test's - HSS at one and more
/// levels and XMSS^MT go through the same `SigningKey` arms as these, and
/// XMSS's own arm differs from XMSS^MT's only in the OID it names, which
/// every row here verifies; what this adds is the SHAKE families and
/// trees of height 10, whose hashing `tests/test_lms*.rs` and
/// `tests/test_xmss.rs` test on every run.
#[test]
#[ignore]
fn test_the_expensive_keys_are_made_again() {
    let mut made = 0;
    for r in rows("ours").iter().filter(|r| !cheap(r)) {
        assert_eq!(make_again(r), unhex(r["cert"]),
                   "{}", r.get("set").or(r.get("levels")).unwrap());
        made += 1;
    }
    assert_eq!(made, 10);
}

