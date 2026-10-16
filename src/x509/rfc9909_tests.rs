/*!
RFC 9909's Appendix C, read out of the vendored document.

One SLH-DSA-SHA2-128s key, three ways: the public key (C.1), the
private key it is the tail of (C.2), and a certificate it signed for
itself (C.3). Nothing below is transcribed: the PEM blocks are cut out
of the text, and each test asserts how many it found before it uses
them.
*/

use super::builder::SubjectKey;
use super::rfc9881_tests::{examples_in, Example};
use super::{read_public_key, verify, Certificate, PublicKey, SignatureAlgorithm};
use crate::asn1::{Reader, Writer};
use crate::pq::slh_dsa;
use crate::x509::private_key::{self, PrivateKey};

const RFC: &str = include_str!("../../rfcs/rfc9909.txt");
const SET: &str = "SLH-DSA-SHA2-128s";

fn one(label: &str) -> Example {
    let mut found: Vec<Example> = examples_in(RFC).into_iter()
        .filter(|e| e.label == label).collect();
    assert_eq!(found.len(), 1, "{label}");
    found.remove(0)
}

fn public_bytes() -> Vec<u8> {
    let example = one("PUBLIC KEY");
    match read_public_key(&mut Reader::new(&example.der)).unwrap() {
        PublicKey::SlhDsa { key, .. } => key.to_vec(),
        other => panic!("{other:?}"),
    }
}

/// C.1: a pure key, `PK.seed ‖ PK.root` with nothing around it, and what
/// the builder writes for it is the same DER, byte for byte.
#[test]
fn test_the_example_public_key() {
    let example = one("PUBLIC KEY");
    assert_eq!(example.section, "C.1");
    let key = match read_public_key(&mut Reader::new(&example.der)).unwrap() {
        PublicKey::SlhDsa { parameter_set, pre_hash, key } => {
            assert_eq!(parameter_set, SET);
            assert_eq!(pre_hash, None);
            key.to_vec()
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(key.len(), slh_dsa::parameters(SET).unwrap().public_key_len());

    let ours = SubjectKey::SlhDsa { parameter_set: SET, pre_hash: None, key: &key };
    let mut writer = Writer::new();
    super::builder::write_spki(&mut writer, &ours).unwrap();
    assert_eq!(writer.finish(), example.der);

    let api = crate::api::SlhDsaPublicKey::from_spki(&example.der).unwrap();
    assert_eq!(api.public_bytes(), &key[..]);
    assert_eq!(api.parameter_set(), SET);
    assert_eq!(api.pre_hash(), None);
}

/// C.2: the private key is FIPS 205's `4n` bytes straight in the
/// OCTET STRING, its tail is C.1's public key, and its seeds regenerate
/// that public key - the key is consistent, not merely the right length.
#[test]
fn test_the_example_private_key() {
    let example = one("PRIVATE KEY");
    assert_eq!(example.section, "C.2");
    let private = match private_key::parse(&example.der).unwrap() {
        PrivateKey::SlhDsa { parameter_set, pre_hash, private } => {
            assert_eq!(parameter_set, SET);
            assert_eq!(pre_hash, None);
            private
        }
        other => panic!("{}", other.algorithm()),
    };
    let parameters = slh_dsa::parameters(SET).unwrap();
    let n = parameters.n;
    assert_eq!(private.len(), 4 * n);
    assert_eq!(&private[2 * n..], &public_bytes()[..]);
    let (regenerated, public) = slh_dsa::key_gen_internal(
        parameters, &private[..n], &private[n..2 * n], &private[2 * n..3 * n]).unwrap();
    assert_eq!(regenerated, private);
    assert_eq!(public, public_bytes());

    let key = crate::api::SlhDsaKey::from_private(SET, &private).unwrap();
    assert!(key.recompute_public().unwrap());
}

/// C.3: self-signed with the C.1 key, which verifies it, and stops
/// verifying it when one byte of what was signed changes.
#[test]
fn test_the_example_certificate_verifies() {
    let example = one("CERTIFICATE");
    assert_eq!(example.section, "C.3");
    let certificate = Certificate::parse(&example.der).unwrap();
    assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::SlhDsa(SET, None));
    assert_eq!(certificate.signature.len(),
               slh_dsa::parameters(SET).unwrap().signature_len());
    assert!(matches!(certificate.public_key,
                     PublicKey::SlhDsa { parameter_set: SET, pre_hash: None, key }
                         if key == &public_bytes()[..]));

    let policy = verify::Policy::default();
    verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                          certificate.signature, &certificate.public_key, &policy).unwrap();
    let mut tbs = certificate.tbs.to_vec();
    let last = tbs.len() - 1;
    tbs[last] ^= 1;
    assert!(verify::verify_signed(&tbs, certificate.signature_algorithm,
                                  certificate.signature, &certificate.public_key,
                                  &policy).is_err());

    let api = crate::api::SlhDsaPublicKey::from_certificate(&example.der).unwrap();
    assert_eq!(api.public_bytes(), &public_bytes()[..]);
}

/// Section 8: a pure key does not verify a HashSLH-DSA signature, nor a
/// HashSLH-DSA key a pure one, though FIPS 205's arithmetic would allow
/// either. Both are refused by name, before any hashing.
#[test]
fn test_a_key_verifies_only_its_own_form() {
    let example = one("CERTIFICATE");
    let certificate = Certificate::parse(&example.der).unwrap();
    let policy = verify::Policy::default();
    let error = verify::verify_signed(
        certificate.tbs, SignatureAlgorithm::SlhDsa(SET, Some("SHA2-256")),
        certificate.signature, &certificate.public_key, &policy).unwrap_err();
    assert!(error.contains("section 8"), "{error}");

    let key = public_bytes();
    let hashed = PublicKey::SlhDsa { parameter_set: SET, pre_hash: Some("SHA2-256"), key: &key };
    let error = verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                                      certificate.signature, &hashed, &policy).unwrap_err();
    assert!(error.contains("section 8"), "{error}");

    // And another parameter set with the same n is refused too.
    let other = PublicKey::SlhDsa { parameter_set: "SLH-DSA-SHA2-128f", pre_hash: None,
                                    key: &key };
    assert!(verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                                  certificate.signature, &other, &policy).is_err());
}

/// A HashSLH-DSA key written by the builder carries its own OID and reads
/// back bound to its pre-hash; a pre-hash RFC 9909 does not pair with the
/// set has no OID and is refused.
#[test]
fn test_a_hash_slh_dsa_key_round_trips() {
    let key = public_bytes();
    let ours = SubjectKey::SlhDsa { parameter_set: SET, pre_hash: Some("SHA2-256"), key: &key };
    let mut writer = Writer::new();
    super::builder::write_spki(&mut writer, &ours).unwrap();
    let der = writer.finish();
    let mut reader = Reader::new(&der);
    let mut spki = reader.read_sequence().unwrap();
    let mut algorithm = spki.read_sequence().unwrap();
    assert_eq!(algorithm.read_oid().unwrap().as_bytes(),
               crate::x509::oids::ID_HASH_SLH_DSA_SHA2_128S_WITH_SHA256);
    match read_public_key(&mut Reader::new(&der)).unwrap() {
        PublicKey::SlhDsa { parameter_set, pre_hash, key: read } => {
            assert_eq!((parameter_set, pre_hash), (SET, Some("SHA2-256")));
            assert_eq!(read, &key[..]);
        }
        other => panic!("{other:?}"),
    }
    let api = crate::api::SlhDsaPublicKey::from_spki(&der).unwrap();
    assert_eq!(api.pre_hash(), Some("SHA2-256"));

    let wrong = SubjectKey::SlhDsa { parameter_set: SET, pre_hash: Some("SHA2-512"), key: &key };
    let error = super::builder::write_spki(&mut Writer::new(), &wrong).unwrap_err();
    assert!(error.contains("no OID"), "{error}");
}

/// Rebuild both AlgorithmIdentifiers with a NULL after the OID; section 3
/// says the parameters are absent, and both readers refuse them.
#[test]
fn test_present_parameters_are_refused() {
    let public = one("PUBLIC KEY").der;
    let mut outer = Reader::new(&public);
    let mut spki = outer.read_sequence().unwrap();
    let mut algorithm = spki.read_sequence().unwrap();
    let oid = algorithm.read_oid().unwrap();
    let bits = spki.read_bit_string().unwrap();
    let mut writer = Writer::new();
    writer.write_sequence(|w| {
        w.write_sequence(|w| {
            w.write_oid(oid.as_bytes());
            w.write_null();
        });
        w.write_bit_string(bits);
    });
    let error = read_public_key(&mut Reader::new(&writer.finish())).unwrap_err();
    assert!(error.contains("absent"), "{error}");

    let private = one("PRIVATE KEY").der;
    let mut outer = Reader::new(&private);
    let mut info = outer.read_sequence().unwrap();
    let version = info.read_u32().unwrap();
    let mut algorithm = info.read_sequence().unwrap();
    let oid = algorithm.read_oid().unwrap();
    let key = info.read_octet_string().unwrap();
    let mut writer = Writer::new();
    writer.write_sequence(|w| {
        w.write_u32(version);
        w.write_sequence(|w| {
            w.write_oid(oid.as_bytes());
            w.write_null();
        });
        w.write_octet_string(key);
    });
    let error = private_key::parse(&writer.finish()).map(|k| k.algorithm()).unwrap_err();
    assert!(error.contains("absent"), "{error}");
}

/// Keys of the wrong length are refused where they are read: a public key
/// one byte short, and a private key wrapped the way ML-DSA's and RFC
/// 8410's are, in a second OCTET STRING, which section 7 does not do.
#[test]
fn test_wrong_lengths_are_refused() {
    let key = public_bytes();
    let mut writer = Writer::new();
    writer.write_sequence(|w| {
        w.write_sequence(|w| w.write_oid(crate::x509::oids::ID_SLH_DSA_SHA2_128S));
        w.write_bit_string(&key[1..]);
    });
    assert!(read_public_key(&mut Reader::new(&writer.finish())).is_err());

    let private = one("PRIVATE KEY").der;
    let mut outer = Reader::new(&private);
    let mut info = outer.read_sequence().unwrap();
    info.read_any().unwrap();
    info.read_any().unwrap();
    let key = info.read_octet_string().unwrap();
    let mut wrapped = Writer::new();
    wrapped.write_octet_string(key);
    let mut writer = Writer::new();
    writer.write_sequence(|w| {
        w.write_u32(0);
        w.write_sequence(|w| w.write_oid(crate::x509::oids::ID_SLH_DSA_SHA2_128S));
        w.write_octet_string(&wrapped.finish());
    });
    let error = private_key::parse(&writer.finish()).map(|k| k.algorithm()).unwrap_err();
    assert!(error.contains("64 bytes"), "{error}");
}

/// Writing: C.2's private key and C.1's public key are what
/// `SlhDsaKey::to_pkcs8` and `to_spki` write, byte for byte; bound to a
/// pre-hash, both carry the HashSLH-DSA OID and read back bound to it.
#[test]
fn test_the_examples_are_what_is_written() {
    let private = match private_key::parse(&one("PRIVATE KEY").der).unwrap() {
        PrivateKey::SlhDsa { private, .. } => private,
        other => panic!("{}", other.algorithm()),
    };
    let key = crate::api::SlhDsaKey::from_private(SET, &private).unwrap();
    assert_eq!(key.to_pkcs8().unwrap(), one("PRIVATE KEY").der);
    assert_eq!(key.public_key().to_spki().unwrap(), one("PUBLIC KEY").der);

    let hashed = key.with_pre_hash(Some("SHA2-256")).unwrap();
    match private_key::parse(&hashed.to_pkcs8().unwrap()).unwrap() {
        PrivateKey::SlhDsa { parameter_set, pre_hash, private: read } => {
            assert_eq!((parameter_set, pre_hash), (SET, Some("SHA2-256")));
            assert_eq!(read, private);
        }
        other => panic!("{}", other.algorithm()),
    }
    let public = crate::api::SlhDsaPublicKey::from_spki(&hashed.public_key().to_spki().unwrap())
        .unwrap();
    assert_eq!(public.pre_hash(), Some("SHA2-256"));
}
