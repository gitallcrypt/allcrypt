/*!
RFC 9881's Appendix C, read out of the vendored document.

Every example there is derived from the one seed `00 01 02 .. 1f`: nine
private keys (three formats at three parameter sets), the three public
keys, a self-signed certificate for each, and three private keys that are
inconsistent on purpose. Nothing below is transcribed: the PEM blocks are
cut out of the text, page breaks and all, and each test asserts how many
it found before it uses them.
*/

use super::{read_public_key, verify, Certificate, PublicKey, SignatureAlgorithm};
use crate::asn1::Reader;
use crate::pq::ml_dsa;
use crate::x509::private_key::{self, PrivateKey};

const RFC: &str = include_str!("../../rfcs/rfc9881.txt");

const SETS: [&str; 3] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

/// One PEM block from the appendix: the subsection it is under (`C.1.2.3`)
/// and its DER.
struct Example {
    section: String,
    label: String,
    der: Vec<u8>,
}

/// Every PEM block after the appendix heading, with the heading it sits
/// under. Page furniture inside a block - a footer, a form feed, the next
/// page's header - is dropped by keeping only lines that are base64.
fn examples() -> Vec<Example> {
    // The heading as a whole line: the table of contents carries the same
    // words followed by dots and a page number.
    let start = RFC.lines().position(|line| line == "Appendix C.  Examples")
        .expect("Appendix C heading");
    let mut found = Vec::new();
    let mut section = String::new();
    let mut block: Option<(String, String)> = None;
    for line in RFC.lines().skip(start) {
        if line.starts_with("Appendix D.") {
            break;
        }
        if line.starts_with("C.") {
            section = line.split_whitespace().next().unwrap().trim_end_matches('.').to_string();
            continue;
        }
        let text = line.trim();
        if let Some(label) = text.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) {
            block = Some((label.to_string(), String::new()));
        } else if text.starts_with("-----END ") {
            let (label, body) = block.take().expect("END without BEGIN");
            let der = crate::pem::decode(&body).unwrap_or_else(|e| panic!("{section}: {e}"));
            found.push(Example { section: section.clone(), label, der });
        } else if let Some((_, body)) = block.as_mut() {
            let base64 = !text.is_empty() && text.len() <= 64 && text.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b));
            if base64 {
                body.push_str(text);
            }
        }
    }
    found
}

fn of(label: &str) -> Vec<Example> {
    examples().into_iter().filter(|e| e.label == label).collect()
}

/// The keys every example is derived from: FIPS 204's KeyGen_internal on
/// the seed `00 01 .. 1f`, at each parameter set.
fn reference_keys(parameter_set: &str) -> (Vec<u8>, Vec<u8>) {
    let seed: Vec<u8> = (0..32).collect();
    ml_dsa::key_gen_internal(ml_dsa::parameters(parameter_set).unwrap(), &seed).unwrap()
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
            PrivateKey::MlDsa { parameter_set: set, seed, expanded } => {
                assert_eq!(set, parameter_set, "{}", example.section);
                assert_eq!(expanded, expected, "{}", example.section);
                // Seed, Expanded, Both - in that order in every C.1.n.
                let seed_expected = i % 3 != 1;
                assert_eq!(seed.is_some(), seed_expected, "{}", example.section);
                if let Some(seed) = seed {
                    assert_eq!(seed, (0..32).collect::<Vec<u8>>());
                }
            }
            other => panic!("{}: {}", example.section, other.algorithm()),
        }
    }
}

/// C.2: the public keys, which must be FIPS 204's encoding of the
/// reference key with nothing around it.
#[test]
fn test_the_example_public_keys() {
    let keys = of("PUBLIC KEY");
    assert_eq!(keys.len(), 3);
    for (example, parameter_set) in keys.iter().zip(SETS) {
        let (expected, _) = reference_keys(parameter_set);
        let mut reader = Reader::new(&example.der);
        match read_public_key(&mut reader).unwrap() {
            PublicKey::MlDsa { parameter_set: set, key } => {
                assert_eq!(set, parameter_set);
                assert_eq!(key, &expected[..]);
            }
            other => panic!("{}: {:?}", example.section, other),
        }
    }
}

/// C.3: a self-signed certificate per parameter set. Each verifies under
/// its own key, carries the reference public key, and stops verifying
/// when any one byte of the signature or the signed part changes.
#[test]
fn test_the_example_certificates_verify() {
    let certificates = of("CERTIFICATE");
    assert_eq!(certificates.len(), 3);
    let policy = verify::Policy::default();
    for (example, parameter_set) in certificates.iter().zip(SETS) {
        let certificate = Certificate::parse(&example.der).unwrap();
        assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::MlDsa(parameter_set));
        let (expected, _) = reference_keys(parameter_set);
        assert!(matches!(certificate.public_key,
                         PublicKey::MlDsa { key, .. } if key == &expected[..]));
        verify::verify_signature(&certificate, &certificate, &policy)
            .unwrap_or_else(|e| panic!("{parameter_set}: {e}"));

        let mut signature = certificate.signature.to_vec();
        signature[100] ^= 1;
        assert!(verify::verify_signed(certificate.tbs, certificate.signature_algorithm,
                                      &signature, &certificate.public_key, &policy).is_err());
        let mut tbs = certificate.tbs.to_vec();
        let last = tbs.len() - 1;
        tbs[last] ^= 1;
        assert!(verify::verify_signed(&tbs, certificate.signature_algorithm,
                                      certificate.signature, &certificate.public_key,
                                      &policy).is_err());
    }
}

/// A certificate signed by one parameter set and checked against a key
/// of another is refused by name, not as a bad signature.
#[test]
fn test_a_parameter_set_mismatch_is_named() {
    let certificates = of("CERTIFICATE");
    let a = Certificate::parse(&certificates[0].der).unwrap();
    let b = Certificate::parse(&certificates[1].der).unwrap();
    let error = verify::verify_signed(a.tbs, a.signature_algorithm, a.signature,
                                      &b.public_key, &verify::Policy::default()).unwrap_err();
    assert!(error.contains("ML-DSA-44") && error.contains("ML-DSA-65"), "{error}");
}

/// C.4: three keys that are wrong on purpose - a seed and an expanded key
/// that do not match, an expanded key whose `tr` is not the hash of its
/// public key, and one whose `t0` is not what `s1` and `s2` give. Each is
/// a different check, and each is refused.
#[test]
fn test_the_inconsistent_examples_are_refused() {
    let keys: Vec<Example> = of("PRIVATE KEY").into_iter()
        .filter(|e| e.section.starts_with("C.4")).collect();
    assert_eq!(keys.len(), 3);
    for example in &keys {
        let error = private_key::parse(&example.der).map(|k| k.algorithm()).unwrap_err();
        assert!(error.contains("ML-DSA-44"), "{error}");
    }
    let first = private_key::parse(&keys[0].der).map(|k| k.algorithm()).unwrap_err();
    assert!(first.contains("do not belong together"), "{first}");
}

/// Parameters must be absent from both AlgorithmIdentifiers, as RFC 9881
/// section 2 says. A NULL, which is what an encoder written from the RSA
/// case emits, is refused.
#[test]
fn test_present_parameters_are_refused() {
    let keys = of("PUBLIC KEY");
    let der = &keys[0].der;
    // SEQUENCE { SEQUENCE { OID }, BIT STRING }: rebuild with a NULL after
    // the OID.
    let mut outer = Reader::new(der);
    let mut spki = outer.read_sequence().unwrap();
    let mut algorithm = spki.read_sequence().unwrap();
    let oid = algorithm.read_oid().unwrap();
    let bits = spki.read_bit_string().unwrap();
    let mut writer = crate::asn1::Writer::new();
    writer.write_sequence(|w| {
        w.write_sequence(|w| {
            w.write_oid(oid.as_bytes());
            w.write_null();
        });
        w.write_bit_string(bits);
    });
    let rebuilt = writer.finish();
    let error = read_public_key(&mut Reader::new(&rebuilt)).unwrap_err();
    assert!(error.contains("absent"), "{error}");
}
