/*!
RFC 9802's appendices, read out of the vendored document: one
self-signed certificate each for HSS (A), XMSS (B) and XMSS^MT (C).
Nothing is transcribed: the PEM blocks are cut out of the text, and each
test asserts how many it found before it uses them.

And the builder's side: certificates signed with this library's
stateful keys, which the reader then verifies, and the key moved on by
each one.
*/

use std::cell::RefCell;

use super::builder::{CertificateBuilder, SigningKey, SubjectKey};
use super::{read_public_key, verify, Certificate, HashSig, PublicKey, SignatureAlgorithm};
use crate::asn1::{Reader, Writer};

const RFC: &str = include_str!("../../rfcs/rfc9802.txt");

/// The certificate under each appendix heading, in order A, B, C.
fn examples() -> Vec<(String, Vec<u8>)> {
    let start = RFC.lines().position(|l| l.starts_with("Appendix A.  HSS X.509"))
        .expect("Appendix A heading");
    let mut found = Vec::new();
    let mut heading = String::new();
    let mut body: Option<String> = None;
    for line in RFC.lines().skip(start) {
        if line == "Acknowledgments" {
            break;
        }
        if line.starts_with("Appendix ") {
            heading = line.to_string();
            continue;
        }
        let text = line.trim();
        if text == "-----BEGIN CERTIFICATE-----" {
            body = Some(String::new());
        } else if text == "-----END CERTIFICATE-----" {
            let der = crate::pem::decode(&body.take().expect("END without BEGIN")).unwrap();
            found.push((heading.clone(), der));
        } else if let Some(b) = body.as_mut() {
            // Only base64 lines: page furniture inside a block is dropped.
            if !text.is_empty() && text.len() <= 64
                && text.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c)) {
                b.push_str(text);
            }
        }
    }
    found
}

fn the_three() -> Vec<(HashSig, Vec<u8>)> {
    let found = examples();
    assert_eq!(found.len(), 3);
    let schemes = [HashSig::Hss, HashSig::Xmss, HashSig::XmssMt];
    for ((heading, _), scheme) in found.iter().zip(schemes) {
        let wanted = format!("{} X.509 v3 Certificate Example", scheme.name());
        assert!(heading.ends_with(&wanted), "{heading}");
    }
    schemes.into_iter().zip(found.into_iter().map(|(_, der)| der)).collect()
}

/// Each appendix's certificate: its key under its scheme's OID, naming a
/// parameter set this library has; its signature verifying under that
/// key, and failing once a byte of what was signed changes; and the
/// builder writing the same SubjectPublicKeyInfo for the key.
#[test]
fn test_the_appendix_certificates_verify() {
    // RFC 8554's type codes 5 and 4, which the key carries.
    let names = ["HSS with 1 level, LMS_SHA256_M32_H5/LMOTS_SHA256_N32_W8 on top",
                 "XMSS-SHA2_10_256", "XMSSMT-SHA2_20/2_256"];
    for ((scheme, der), name) in the_three().into_iter().zip(names) {
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::HashSig(scheme));
        let key = match certificate.public_key {
            PublicKey::HashSig { scheme: s, key } if s == scheme => key,
            ref other => panic!("{other:?}"),
        };
        assert_eq!(super::hash_sig_key_name(scheme, key).unwrap(), name);

        let policy = verify::Policy::default();
        verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                              certificate.signature, &certificate.public_key, &policy).unwrap();
        let mut tbs = certificate.tbs.to_vec();
        let last = tbs.len() - 1;
        tbs[last] ^= 1;
        assert!(verify::verify_signed(&tbs, certificate.signature_algorithm,
                                      certificate.signature, &certificate.public_key,
                                      &policy).is_err(), "{}", scheme.name());

        let mut writer = Writer::new();
        super::builder::write_spki(&mut writer, &SubjectKey::HashSig { scheme, key }).unwrap();
        let spki = writer.finish();
        assert!(der.windows(spki.len()).any(|w| w == spki), "{}", scheme.name());

        // And the certificate as the API describes it.
        let info = crate::api::Certificate::parse(&der).unwrap().info().unwrap();
        assert_eq!(info.public_key_type, name);
    }
}

/// A key verifies only its own scheme's signatures: the HSS appendix's
/// signature checked under its key labelled XMSS is refused by name, not
/// handed to the XMSS verifier.
#[test]
fn test_a_key_verifies_only_its_own_scheme() {
    let three = the_three();
    let certificate = Certificate::parse(&three[0].1).unwrap();
    let policy = verify::Policy::default();
    let error = verify::verify_signed(certificate.tbs,
                                      SignatureAlgorithm::HashSig(HashSig::Xmss),
                                      certificate.signature, &certificate.public_key,
                                      &policy).unwrap_err();
    assert!(error.contains("cannot verify an XMSS signature"), "{error}");
}

fn spki_of(oid: &[u8], parameters: bool, key: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_sequence(|w| {
        w.write_sequence(|w| {
            w.write_oid(oid);
            if parameters {
                w.write_null();
            }
        });
        w.write_bit_string(key);
    });
    writer.finish()
}

/// Section 9: the parameters are absent, and a NULL is refused. A key
/// whose type codes or OID this library does not have, or whose length
/// is not its parameter set's, is refused where it is read.
#[test]
fn test_what_the_reader_refuses() {
    let three = the_three();
    let keys: Vec<Vec<u8>> = three.iter().map(|(_, der)| match Certificate::parse(der)
                                                   .unwrap().public_key {
        PublicKey::HashSig { key, .. } => key.to_vec(),
        other => panic!("{other:?}"),
    }).collect();
    for ((scheme, _), key) in three.iter().zip(&keys) {
        let good = spki_of(scheme.oid(), false, key);
        assert!(read_public_key(&mut Reader::new(&good)).is_ok());
        let error = read_public_key(&mut Reader::new(&spki_of(scheme.oid(), true, key)))
            .unwrap_err();
        assert!(error.contains("absent"), "{error}");
        let short = spki_of(scheme.oid(), false, &key[..key.len() - 1]);
        assert!(read_public_key(&mut Reader::new(&short)).is_err());
        let mut long = key.clone();
        long.push(0);
        assert!(read_public_key(&mut Reader::new(&spki_of(scheme.oid(), false, &long)))
                    .is_err());
        // The builder refuses what the reader refuses.
        let shorter = &key[..key.len() - 1];
        assert!(super::builder::write_spki(&mut Writer::new(),
                                           &SubjectKey::HashSig { scheme: *scheme,
                                                                  key: shorter }).is_err());
    }
    let hss = &keys[0];
    for (at, value) in [(0, 0u32), (0, 9), (4, 0x7f), (8, 0x7f)] {
        let mut bad = hss.clone();
        bad[at..at + 4].copy_from_slice(&value.to_be_bytes());
        let error = read_public_key(&mut Reader::new(&spki_of(HashSig::Hss.oid(), false, &bad)))
            .unwrap_err();
        assert!(error.contains("level") || error.contains("Unknown"), "{error}");
    }
    let mut unknown = keys[1].clone();
    unknown[..4].copy_from_slice(&0x7fu32.to_be_bytes());
    assert!(read_public_key(&mut Reader::new(&spki_of(HashSig::Xmss.oid(), false, &unknown)))
                .is_err());
}

/// XMSS's and XMSS^MT's OID registries overlap, and a key is its OID
/// and `n` bytes twice: the XMSS^MT appendix key, XMSSMT-SHA2_20/2_256
/// (OID 1), under the XMSS OID is a perfectly good XMSS-SHA2_10_256 key
/// (OID 1 there too). Only the certificate's OID tells them apart, which
/// is why the scheme travels with the key everywhere here; the
/// certificate's signature does not verify under the key read the wrong
/// way.
/// Which scheme an XMSS key signs under is decided by `HashSig::of_xmss`
/// alone, for the builder and the CMS example: every single-tree set is
/// XMSS and every multi-tree one XMSS^MT, with different OIDs. A key of
/// height 10, the smallest single tree, takes seconds to make in a debug
/// build, so this is the cheap check of the single-tree branch that a
/// signing test would reach only through such a key.
#[test]
fn test_each_xmss_set_signs_under_its_own_scheme() {
    let (mut single, mut multi) = (0, 0);
    for p in crate::pq::xmss::parameter_sets() {
        let scheme = HashSig::of_xmss(p);
        if p.name.starts_with("XMSSMT-") {
            assert_eq!(scheme, HashSig::XmssMt, "{}", p.name);
            multi += 1;
        } else {
            assert!(p.name.starts_with("XMSS-"), "{}", p.name);
            assert_eq!(scheme, HashSig::Xmss, "{}", p.name);
            single += 1;
        }
    }
    assert!(single >= 12 && multi >= 32, "{single} {multi}");
    assert_ne!(HashSig::Xmss.oid(), HashSig::XmssMt.oid());
}

#[test]
fn test_the_overlapping_registries() {
    let three = the_three();
    let certificate = Certificate::parse(&three[2].1).unwrap();
    let key = match certificate.public_key {
        PublicKey::HashSig { key, .. } => key,
        other => panic!("{other:?}"),
    };
    let misread = spki_of(HashSig::Xmss.oid(), false, key);
    let misread = read_public_key(&mut Reader::new(&misread)).unwrap();
    assert!(matches!(misread, PublicKey::HashSig { scheme: HashSig::Xmss, .. }));
    assert_eq!(super::hash_sig_key_name(HashSig::Xmss, key).unwrap(), "XMSS-SHA2_10_256");
    assert!(!HashSig::Xmss.verify(key, certificate.tbs, certificate.signature));
    assert!(HashSig::XmssMt.verify(key, certificate.tbs, certificate.signature));
}

/// A certificate signed with each kind of stateful key here: it verifies
/// under its own key, it names the scheme the key is, and the key has
/// moved on by one signature.
#[test]
fn test_the_builder_signs_with_stateful_keys() {
    use crate::pq::lms::{HssPrivateKey, LmotsParams, LmsParams};
    use crate::pq::xmss::{XmssParams, XmssPrivateKey};
    let lms = LmsParams::named("LMS_SHA256_M32_H5").unwrap();
    let ots = LmotsParams::named("LMOTS_SHA256_N32_W8").unwrap();
    let hss = RefCell::new(HssPrivateKey::from_seed(&[(lms, ots), (lms, ots)], &[7; 32],
                                                    &[9; 16], 0).unwrap());
    let mt = XmssParams::named("XMSSMT-SHA2_20/4_256").unwrap();
    let xmss = RefCell::new(XmssPrivateKey::from_seeds(mt, &[1; 32], &[2; 32], &[3; 32], 0)
        .unwrap());

    let hss_public = hss.borrow().public_key();
    let builder = CertificateBuilder::new("hss", SubjectKey::HashSig { scheme: HashSig::Hss,
                                                                      key: &hss_public });
    let der = builder.sign(&SigningKey::Hss(&hss)).unwrap();
    assert_eq!(hss.borrow().count(), 1);
    let certificate = Certificate::parse(&der).unwrap();
    assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::HashSig(HashSig::Hss));
    let policy = verify::Policy::default();
    verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                          certificate.signature, &certificate.public_key, &policy).unwrap();
    // Two levels: the signature carries the lower tree's key.
    assert_eq!(certificate.signature.len(),
               4 + 2 * lms.signature_len(ots) + lms.public_key_len());

    let xmss_public = xmss.borrow().public_key();
    let mut builder = CertificateBuilder::new("xmssmt", SubjectKey::HashSig {
        scheme: HashSig::XmssMt, key: &xmss_public });
    builder.key_identifiers = true;
    let der = builder.sign(&SigningKey::Xmss(&xmss)).unwrap();
    assert_eq!(xmss.borrow().index(), 1);
    let certificate = Certificate::parse(&der).unwrap();
    assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::HashSig(HashSig::XmssMt));
    verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                          certificate.signature, &certificate.public_key, &policy).unwrap();
    assert_eq!(certificate.signature.len(), mt.signature_len());
    // A second certificate is made with the next one-time key, and so is
    // a different signature over the same TBS.
    let again = builder.sign(&SigningKey::Xmss(&xmss)).unwrap();
    assert_eq!(xmss.borrow().index(), 2);
    assert_ne!(Certificate::parse(&again).unwrap().signature, certificate.signature);
}

/// The API's key: each scheme by its names, the key checked, and the
/// SubjectPublicKeyInfo it writes read back as the same key.
#[test]
fn test_the_api_key() {
    use crate::api::HashSigPublicKey;
    for (scheme, der) in the_three() {
        let certificate = Certificate::parse(&der).unwrap();
        let key = HashSigPublicKey::from_certificate(&der).unwrap();
        assert_eq!(key.scheme(), scheme.name());
        let names: &[&str] = match scheme {
            HashSig::Hss => &["HSS", "hss"],
            HashSig::Xmss => &["XMSS", "xmss"],
            HashSig::XmssMt => &["XMSS^MT", "XMSSMT", "xmssmt"],
        };
        for name in names {
            let again = HashSigPublicKey::from_public(name, key.public_bytes()).unwrap();
            assert_eq!(again, key, "{name}");
        }
        assert_eq!(HashSigPublicKey::from_spki(&key.to_spki().unwrap()).unwrap(), key);
        assert!(key.verify(certificate.tbs, certificate.signature));
        assert!(!key.verify(&certificate.tbs[1..], certificate.signature));
        let short = &key.public_bytes()[..key.public_bytes().len() - 1];
        assert!(HashSigPublicKey::from_public(scheme.name(), short).is_err());
    }
    assert!(HashSigPublicKey::from_public("LMS", &[0; 60]).is_err());
}
