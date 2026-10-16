/*!
ML-KEM keys and certificates (RFC 9935), checked against what OpenSSL 3.5
wrote.

`src/x509/rfc9935_tests.rs` reads RFC 9935's own examples, which all come
from one seed. This reads files OpenSSL 3.5 produced, recorded by
`scripts/capture_mlkem.py` into `vectors/ml_kem_openssl.vec`, and needs no
OpenSSL: one key per parameter set in all three private key forms OpenSSL
writes, its public key, OpenSSL's encapsulations to that key - which the
key read here must decapsulate to the secret OpenSSL kept - and an ML-KEM
certificate OpenSSL issued under an ML-DSA CA.

The other direction - OpenSSL decapsulating what this library
encapsulated, and accepting the certificates it issues - is checked live
by the same script, which fails if OpenSSL disagrees.
*/

use allcrypt::api::{MlKemKey, MlKemPublicKey};
use allcrypt::x509::private_key::{self, PrivateKey};
use allcrypt::x509::{verify, Certificate, PublicKey, SignatureAlgorithm};

const VECTORS: &str = include_str!("../vectors/ml_kem_openssl.vec");

type Record = Vec<(String, String)>;

fn section(name: &str) -> Vec<Record> {
    let header = format!("[{name}]");
    let start = VECTORS.lines().position(|line| line == header)
        .unwrap_or_else(|| panic!("no {header}"));
    let mut records = Vec::new();
    let mut current: Record = Vec::new();
    for line in VECTORS.lines().skip(start + 1) {
        if line.starts_with('[') {
            break;
        }
        if line.trim().is_empty() {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            continue;
        }
        let (key, value) = line.split_once(" = ").unwrap_or_else(|| panic!("{line}"));
        current.push((key.to_string(), value.to_string()));
    }
    if !current.is_empty() {
        records.push(current);
    }
    let declared: usize = VECTORS.lines()
        .filter_map(|line| line.strip_prefix("#   "))
        .find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(name)).then(|| words.next().unwrap().parse().unwrap())
        })
        .unwrap_or_else(|| panic!("no count for {name}"));
    assert_eq!(records.len(), declared, "[{name}]");
    records
}

fn field<'a>(record: &'a Record, name: &str) -> &'a str {
    &record.iter().find(|(key, _)| key == name).unwrap_or_else(|| panic!("{name}")).1
}

fn base64(record: &Record, name: &str) -> Vec<u8> {
    allcrypt::pem::decode(field(record, name)).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// The raw key inside a SubjectPublicKeyInfo, read with nothing of ours
/// above the DER layer: SEQUENCE { SEQUENCE { OID }, BIT STRING }.
fn spki_key(der: &[u8]) -> Vec<u8> {
    let mut outer = allcrypt::asn1::Reader::new(der);
    let mut spki = outer.read_sequence().unwrap();
    spki.read_sequence().unwrap();
    spki.read_bit_string().unwrap().to_vec()
}

/// A private key form as read: the seed if it had one, and the
/// decapsulation key.
type Form = (Option<Vec<u8>>, Vec<u8>);

/// One key per set, in each of the three forms, and its public key.
fn keys() -> Vec<(String, Vec<Form>, Vec<u8>)> {
    section("key").iter().map(|record| {
        let name = field(record, "name").to_string();
        let forms = ["seed-only", "priv-only", "seed-priv"].iter()
            .map(|form| match private_key::parse(&base64(record, form))
                .unwrap_or_else(|e| panic!("{name} {form}: {e}")) {
                PrivateKey::MlKem { parameter_set, seed, expanded } => {
                    assert_eq!(parameter_set, name);
                    (seed, expanded)
                }
                other => panic!("{name} {form}: {}", other.algorithm()),
            }).collect();
        (name, forms, base64(record, "public"))
    }).collect()
}

/// The three private key forms of one OpenSSL key are one key: the same
/// decapsulation key, the 64 byte seed where the form has one, and the
/// encapsulation key inside it equal to the one OpenSSL wrote.
#[test]
fn test_openssls_three_private_key_forms_are_one_key() {
    let keys = keys();
    assert_eq!(keys.len(), 3);
    for (name, forms, public) in &keys {
        assert!(forms[0].0.is_some() && forms[1].0.is_none() && forms[2].0.is_some());
        assert_eq!(forms[0].0, forms[2].0, "{name}: two seeds");
        assert_eq!(forms[0].0.as_ref().unwrap().len(), 64);
        assert!(forms.iter().all(|(_, expanded)| *expanded == forms[0].1), "{name}");

        let key = MlKemKey::from_private(name, &forms[1].1).unwrap();
        assert_eq!(key.public_bytes(), &spki_key(public)[..], "{name}");
        let from_spki = MlKemPublicKey::from_spki(public).unwrap();
        assert_eq!(from_spki.public_bytes(), key.public_bytes(), "{name}");
        assert_eq!(from_spki.parameter_set(), name.as_str());
    }
}

/// OpenSSL's ciphertexts decapsulate, under the key read in any of its
/// forms, to the secret OpenSSL kept - and a ciphertext with one bit
/// changed decapsulates to something else, the implicit rejection secret.
#[test]
fn test_openssls_encapsulations_decapsulate_here() {
    let keys = keys();
    let encapsulations = section("encapsulation");
    assert_eq!(encapsulations.len(), 9);
    for record in &encapsulations {
        let name = field(record, "name");
        let (_, forms, _) = keys.iter().find(|(n, _, _)| n == name).unwrap();
        let ciphertext = hex(field(record, "ciphertext"));
        let secret = hex(field(record, "secret"));
        for (seed, expanded) in forms {
            let key = match seed {
                Some(seed) => MlKemKey::from_seed(name, seed).unwrap(),
                None => MlKemKey::from_private(name, expanded).unwrap(),
            };
            assert_eq!(key.decapsulate(&ciphertext).unwrap(), secret, "{name}");
        }
        let key = MlKemKey::from_private(name, &forms[1].1).unwrap();
        let mut changed = ciphertext.clone();
        changed[5] ^= 0x10;
        assert_ne!(key.decapsulate(&changed).unwrap(), secret, "{name}");
    }
}

/// OpenSSL's ML-KEM certificates carry the key, say keyEncipherment and
/// nothing else, and verify under the ML-DSA CA that issued them.
#[test]
fn test_openssls_ml_kem_certificates() {
    let keys = keys();
    let certificates = section("certificate");
    assert_eq!(certificates.len(), 3);
    let policy = verify::Policy::default();
    for (record, signer) in certificates.iter().zip(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) {
        let name = field(record, "name");
        let der = base64(record, "certificate");
        let ca_der = base64(record, "ca");
        let certificate = Certificate::parse(&der).unwrap();
        let ca = Certificate::parse(&ca_der).unwrap();
        assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::MlDsa(signer));
        let (_, _, public) = keys.iter().find(|(n, _, _)| n == name).unwrap();
        let expected = spki_key(public);
        assert!(matches!(certificate.public_key,
                         PublicKey::MlKem { parameter_set, key }
                             if parameter_set == name && key == &expected[..]), "{name}");
        let usage = certificate.extensions.key_usage.expect("keyUsage");
        assert!(usage.key_encipherment && !usage.digital_signature, "{name}");
        verify::verify_signature(&certificate, &ca, &policy)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        // A time inside the window OpenSSL gave it, so the test does not
        // depend on today's date.
        let options = allcrypt::api::VerifyOptions { now: certificate.not_before + 60,
                                                     ..Default::default() };
        allcrypt::api::verify_chain(&[&der[..]], &[&ca_der[..]], &options)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(MlKemPublicKey::from_certificate(&der).unwrap().public_bytes(),
                   &expected[..]);
        // The CA's own certificate carries a signing key, which is not one.
        let error = MlKemPublicKey::from_certificate(&ca_der).err().unwrap();
        assert!(error.contains(signer) && error.contains("not an ML-KEM"), "{error}");
    }
}

/// A certificate this library issues for an OpenSSL key carries that key
/// unchanged and verifies here; OpenSSL's verdict on the same certificate
/// is taken live by `scripts/capture_mlkem.py`.
#[test]
fn test_a_certificate_issued_here_for_openssls_key() {
    let keys = keys();
    let ca = allcrypt::api::CertificateAuthority::generate_with(
        "ML-DSA-65", "ML-DSA CA", "20260101000000Z", "20360101000000Z").unwrap();
    for (name, _, public) in &keys {
        let key = MlKemPublicKey::from_spki(public).unwrap();
        let der = ca.issue_ml_kem(&format!("{name} key"), &key, "20260101000000Z",
                                  "20360101000000Z").unwrap();
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(certificate.spki, &public[..], "{name}: the SubjectPublicKeyInfo");
        let usage = certificate.extensions.key_usage.expect("keyUsage");
        assert!(usage.key_encipherment && !usage.digital_signature && !usage.key_cert_sign);
        assert!(certificate.extensions.extended_key_usage.is_none());
        let options = allcrypt::api::VerifyOptions { now: certificate.not_before + 60,
                                                     ..Default::default() };
        allcrypt::api::verify_chain(&[&der[..]], &[ca.certificate()], &options)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}
