/*!
RFC 9935's Appendix C, read out of the vendored document.

Every example there is derived from the one seed `00 01 02 .. 3f`, `d`
then `z`: nine private keys (three formats at three parameter sets), the
three public keys, a certificate for each - signed by RFC 9881's ML-DSA
example key at the matching level, so they are checked against that
document's public keys - and four private keys that are inconsistent on
purpose. Nothing below is transcribed: the PEM blocks are cut out of the
text, and each test asserts how many it found before it uses them.
*/

use super::builder::SubjectKey;
use super::rfc9881_tests::{examples_in, Example};
use super::{read_public_key, verify, Certificate, PublicKey, SignatureAlgorithm};
use crate::asn1::{Reader, Writer};
use crate::pq::ml_kem;
use crate::x509::private_key::{self, PrivateKey};

const RFC: &str = include_str!("../../rfcs/rfc9935.txt");
const RFC_9881: &str = include_str!("../../rfcs/rfc9881.txt");

const SETS: [&str; 3] = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
const SIGNERS: [&str; 3] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

fn of(label: &str) -> Vec<Example> {
    examples_in(RFC).into_iter().filter(|e| e.label == label).collect()
}

fn seed() -> Vec<u8> {
    (0..64).collect()
}

/// `(ek, dk)`: FIPS 203's KeyGen_internal on `d = 00 .. 1f`, `z = 20 .. 3f`.
fn reference_keys(parameter_set: &str) -> (Vec<u8>, Vec<u8>) {
    let seed = seed();
    ml_kem::key_gen_internal(ml_kem::parameters(parameter_set).unwrap(), &seed[..32],
                             &seed[32..]).unwrap()
}

/// C.1: three formats at three parameter sets, all one key per set.
#[test]
fn test_the_nine_example_private_keys() {
    let keys: Vec<Example> = of("PRIVATE KEY").into_iter()
        .filter(|e| e.section.starts_with("C.1")).collect();
    assert_eq!(keys.len(), 9);
    for (i, example) in keys.iter().enumerate() {
        let parameter_set = SETS[i / 3];
        let (_, expected) = reference_keys(parameter_set);
        let parsed = private_key::parse(&example.der)
            .unwrap_or_else(|e| panic!("{}: {e}", example.section));
        match parsed {
            PrivateKey::MlKem { parameter_set: set, seed: found, expanded } => {
                assert_eq!(set, parameter_set, "{}", example.section);
                assert_eq!(expanded, expected, "{}", example.section);
                // Seed, Expanded, Both - in that order in every C.1.n.
                assert_eq!(found.is_some(), i % 3 != 1, "{}", example.section);
                if let Some(found) = found {
                    assert_eq!(found, seed());
                }
            }
            other => panic!("{}: {}", example.section, other.algorithm()),
        }
    }
}

/// C.2: the public keys are FIPS 203's encoding of the reference key with
/// nothing around it, and what the builder writes for that key is the
/// same DER, byte for byte.
#[test]
fn test_the_example_public_keys() {
    let keys = of("PUBLIC KEY");
    assert_eq!(keys.len(), 3);
    for (example, parameter_set) in keys.iter().zip(SETS) {
        let (expected, _) = reference_keys(parameter_set);
        let mut reader = Reader::new(&example.der);
        match read_public_key(&mut reader).unwrap() {
            PublicKey::MlKem { parameter_set: set, key } => {
                assert_eq!(set, parameter_set);
                assert_eq!(key, &expected[..]);
            }
            other => panic!("{}: {:?}", example.section, other),
        }
        let ours = SubjectKey::MlKem { parameter_set, key: &expected };
        let mut writer = Writer::new();
        super::builder::write_spki(&mut writer, &ours).unwrap();
        assert_eq!(writer.finish(), example.der, "{parameter_set}");

        let api = crate::api::MlKemPublicKey::from_spki(&example.der).unwrap();
        assert_eq!(api.public_bytes(), &expected[..]);
        assert_eq!(api.parameter_set(), parameter_set);
    }
}

/// C.3: each certificate carries the reference key, says keyEncipherment
/// and nothing else, and verifies under RFC 9881's ML-DSA example key of the matching level -
/// and stops verifying when one byte of what was signed changes.
#[test]
fn test_the_example_certificates_verify_under_rfc_9881s_keys() {
    let certificates = of("CERTIFICATE");
    assert_eq!(certificates.len(), 3);
    let signers: Vec<Example> = examples_in(RFC_9881).into_iter()
        .filter(|e| e.label == "PUBLIC KEY").collect();
    assert_eq!(signers.len(), 3);
    let policy = verify::Policy::default();
    for ((example, parameter_set), (signer, signer_set)) in
            certificates.iter().zip(SETS).zip(signers.iter().zip(SIGNERS)) {
        let certificate = Certificate::parse(&example.der).unwrap();
        assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::MlDsa(signer_set));
        let (expected, _) = reference_keys(parameter_set);
        assert!(matches!(certificate.public_key,
                         PublicKey::MlKem { parameter_set: set, key }
                             if set == parameter_set && key == &expected[..]));
        let usage = certificate.extensions.key_usage.expect("keyUsage");
        assert!(usage.key_encipherment && !usage.digital_signature && !usage.key_agreement
                && !usage.key_cert_sign, "{parameter_set}");

        let mut reader = Reader::new(&signer.der);
        let signer_key = read_public_key(&mut reader).unwrap();
        verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                              certificate.signature, &signer_key, &policy)
            .unwrap_or_else(|e| panic!("{parameter_set}: {e}"));
        let mut tbs = certificate.tbs.to_vec();
        let last = tbs.len() - 1;
        tbs[last] ^= 1;
        assert!(verify::verify_signed(&tbs, certificate.signature_algorithm,
                                      certificate.signature, &signer_key, &policy).is_err());

        let from_certificate = crate::api::MlKemPublicKey::from_certificate(&example.der)
            .unwrap();
        assert_eq!(from_certificate.public_bytes(), &expected[..]);
    }
}

/// An ML-KEM key verifies nothing: a certificate claiming to be signed by
/// one is refused by name, not as a bad signature.
#[test]
fn test_an_ml_kem_key_verifies_nothing() {
    let certificates = of("CERTIFICATE");
    let certificate = Certificate::parse(&certificates[0].der).unwrap();
    let error = verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                                      certificate.signature, &certificate.public_key,
                                      &verify::Policy::default()).unwrap_err();
    assert!(error.contains("ML-KEM-512"), "{error}");
}

/// C.4: four ML-KEM-512 keys that are wrong on purpose. The first and the
/// fourth carry a seed and an expanded key that do not match - the fourth
/// only in `z`, which nothing but the seed can show. The second's secret
/// vector was altered and its hash left alone, which only the pairwise
/// test sees; the third's `H(ek)` was altered.
#[test]
fn test_the_inconsistent_examples_are_refused() {
    let keys: Vec<Example> = of("PRIVATE KEY").into_iter()
        .filter(|e| e.section.starts_with("C.4")).collect();
    assert_eq!(keys.len(), 4);
    let errors: Vec<String> = keys.iter()
        .map(|example| private_key::parse(&example.der).map(|k| k.algorithm()).unwrap_err())
        .collect();
    for error in &errors {
        assert!(error.contains("ML-KEM-512"), "{error}");
    }
    assert!(errors[0].contains("do not belong together"), "{}", errors[0]);
    assert!(errors[1].contains("pairwise"), "{}", errors[1]);
    assert!(errors[2].contains("hash check"), "{}", errors[2]);
    assert!(errors[3].contains("do not belong together"), "{}", errors[3]);
}

/// The second bad key passes the hash and modulus checks and fails only
/// the pairwise test: removing that test would let it through.
#[test]
fn test_only_the_pairwise_test_sees_an_altered_secret_vector() {
    let keys: Vec<Example> = of("PRIVATE KEY").into_iter()
        .filter(|e| e.section.starts_with("C.4")).collect();
    let mut outer = Reader::new(&keys[1].der);
    let mut info = outer.read_sequence().unwrap();
    info.read_any().unwrap();
    info.read_any().unwrap();
    let mut inner = Reader::new(info.read_octet_string().unwrap());
    let dk = inner.read_octet_string().unwrap();
    let parameters = ml_kem::parameters("ML-KEM-512").unwrap();
    assert!(ml_kem::hash_check(parameters, dk).unwrap());
    let k = parameters.k;
    assert!(ml_kem::modulus_check(parameters, &dk[384 * k..768 * k + 32]).unwrap());
    assert!(ml_kem::check_expanded(parameters, dk).unwrap_err().contains("pairwise"));
    // And importing it directly, without a file around it, runs the same test.
    let error = crate::api::MlKemKey::from_private("ML-KEM-512", dk).err().unwrap();
    assert!(error.contains("pairwise"), "{error}");
}

/// Rebuild an AlgorithmIdentifier with a NULL after the OID, which is what
/// an encoder written from the RSA case emits; RFC 9935 section 3 says the
/// parameters are absent, and both readers refuse them.
#[test]
fn test_present_parameters_are_refused() {
    let public = &of("PUBLIC KEY")[0].der;
    let mut outer = Reader::new(public);
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

    let private = &of("PRIVATE KEY")[0].der;
    let mut outer = Reader::new(private);
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

/// A seed of 32 bytes - ML-DSA's length - is refused by name rather than
/// expanded: `d` alone with an empty `z` is no key.
#[test]
fn test_a_short_seed_is_refused() {
    let mut writer = Writer::new();
    writer.write_sequence(|w| {
        w.write_u32(0);
        w.write_sequence(|w| w.write_oid(crate::x509::oids::ID_ML_KEM_768));
        let mut inner = Writer::new();
        inner.write_tlv(crate::asn1::Tag::context(0, false), &[7u8; 32]);
        w.write_octet_string(&inner.finish());
    });
    let error = private_key::parse(&writer.finish()).map(|k| k.algorithm()).unwrap_err();
    assert!(error.contains("64 bytes"), "{error}");
}

/// A public key with a coefficient encoded at q is refused where it is
/// read, by FIPS 203's modulus check.
#[test]
fn test_a_non_canonical_public_key_is_refused() {
    let (mut ek, _) = reference_keys("ML-KEM-768");
    // The first twelve bit coefficient is the low byte and the low half of
    // the next: set it to q = 3329 = 0xd01.
    ek[0] = 0x01;
    ek[1] = (ek[1] & 0xf0) | 0x0d;
    let mut writer = Writer::new();
    writer.write_sequence(|w| {
        w.write_sequence(|w| w.write_oid(crate::x509::oids::ID_ML_KEM_768));
        w.write_bit_string(&ek);
    });
    let error = read_public_key(&mut Reader::new(&writer.finish())).unwrap_err();
    assert!(error.contains("modulus"), "{error}");
}

/// An expanded key whose `ek` encodes a coefficient at q, with its `H(ek)`
/// recomputed so the hash check passes, is refused: the pairwise test
/// encapsulates to that `ek`, and encapsulation runs the modulus check.
#[test]
fn test_an_expanded_key_with_a_non_canonical_ek_is_refused() {
    use crate::hash_functions::HashFunction;
    let parameters = ml_kem::parameters("ML-KEM-768").unwrap();
    let (_, mut dk) = reference_keys("ML-KEM-768");
    let k = parameters.k;
    let start = 384 * k;
    dk[start] = 0x01;
    dk[start + 1] = (dk[start + 1] & 0xf0) | 0x0d;
    let mut hash = crate::hash_functions::keccak::Keccak::sha3(32).unwrap();
    hash.update(&dk[start..768 * k + 32]);
    let digest = hash.digest();
    dk[768 * k + 32..768 * k + 64].copy_from_slice(&digest);
    assert!(ml_kem::hash_check(parameters, &dk).unwrap());
    let error = ml_kem::check_expanded(parameters, &dk).unwrap_err();
    assert!(error.contains("non-canonically"), "{error}");
}

/// Writing: each of C.1's nine private keys is what `MlKemKey::to_pkcs8`
/// writes for the reference key in that form, byte for byte, and each of
/// C.2's public keys what `to_spki` writes. A key keeps its seed from
/// `from_seed` and has none from `from_private`, which then refuses the
/// two forms that need one.
#[test]
fn test_the_examples_are_what_is_written() {
    use crate::api::{MlKemKey, PrivateKeyForm};
    let keys: Vec<Example> = of("PRIVATE KEY").into_iter()
        .filter(|e| e.section.starts_with("C.1")).collect();
    assert_eq!(keys.len(), 9);
    let forms = [PrivateKeyForm::Seed, PrivateKeyForm::Expanded, PrivateKeyForm::Both];
    for (i, example) in keys.iter().enumerate() {
        let key = MlKemKey::from_seed(SETS[i / 3], &seed()).unwrap();
        assert_eq!(key.seed(), Some(&seed()[..]));
        assert_eq!(key.to_pkcs8(forms[i % 3]).unwrap(), example.der, "{}", example.section);
    }
    let publics = of("PUBLIC KEY");
    assert_eq!(publics.len(), 3);
    for (example, parameter_set) in publics.iter().zip(SETS) {
        let key = MlKemKey::from_seed(parameter_set, &seed()).unwrap();
        assert_eq!(key.public_key().to_spki().unwrap(), example.der, "{parameter_set}");
    }
    let (_, dk) = reference_keys("ML-KEM-512");
    let expanded = MlKemKey::from_private("ML-KEM-512", &dk).unwrap();
    assert_eq!(expanded.seed(), None);
    assert_eq!(expanded.to_pkcs8(PrivateKeyForm::Expanded).unwrap(), keys[1].der);
    for form in [PrivateKeyForm::Seed, PrivateKeyForm::Both] {
        assert!(expanded.to_pkcs8(form).unwrap_err().contains("no seed"));
    }
}
