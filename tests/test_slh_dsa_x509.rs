/*!
SLH-DSA certificates and private keys (RFC 9909) written by four other
implementations.

`src/x509/rfc9909_tests.rs` reads RFC 9909's own example, one key at one
parameter set. This reads the IETF hackathon's interoperability
artifacts, recorded by `scripts/make_slh_dsa_x509_vectors.py` into
`vectors/slh_dsa_x509.vec`: self-signed certificates and the private keys
that signed them, from OpenSSL 3.5 and Bouncy Castle at all twelve pure
parameter sets, from Bouncy Castle and Redhound at all twelve HashSLH-DSA
ones, and from Botan and Redhound at the 128-bit pure sets.

The other direction - OpenSSL verifying the certificates this library
issues - is checked live by the same script, which fails if OpenSSL
disagrees.
*/

use allcrypt::api::{CertificateAuthority, SlhDsaKey, SlhDsaPublicKey};
use allcrypt::x509::private_key::{self, PrivateKey};
use allcrypt::x509::{verify, Certificate, PublicKey, SignatureAlgorithm};

const VECTORS: &str = include_str!("../vectors/slh_dsa_x509.vec");

type Record = Vec<(String, String)>;

fn records() -> Vec<Record> {
    let start = VECTORS.lines().position(|line| line == "[certificate]").expect("section");
    let mut records = Vec::new();
    let mut current: Record = Vec::new();
    for line in VECTORS.lines().skip(start + 1) {
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
        .find_map(|line| line.strip_prefix("#   certificate"))
        .expect("count").trim().parse().unwrap();
    assert_eq!(records.len(), declared);
    records
}

fn field<'a>(record: &'a Record, name: &str) -> &'a str {
    &record.iter().find(|(key, _)| key == name).unwrap_or_else(|| panic!("{name}")).1
}

fn base64(record: &Record, name: &str) -> Vec<u8> {
    allcrypt::pem::decode(field(record, name)).unwrap()
}

fn label(record: &Record) -> String {
    format!("{} {}", field(record, "provider"), field(record, "name"))
}

/// What the participant's file name says: the parameter set, lowercased
/// as everyone writes it, and whether it is pre-hashed - Bouncy Castle
/// writes `slh-dsa-sha2-128s-with-sha256`, Redhound `hash-slh-dsa-sha2-128s`.
fn named(record: &Record) -> (String, Option<Option<String>>) {
    let name = field(record, "name");
    let (hashed, rest) = match name.strip_prefix("hash-") {
        Some(rest) => (true, rest),
        None => (false, name),
    };
    match rest.split_once("-with-") {
        Some((set, hash)) => (set.to_string(), Some(Some(hash.to_string()))),
        None if hashed => (rest.to_string(), Some(None)),
        None => (rest.to_string(), None),
    }
}

/// The pre-hash as the file names write it: `SHA2-256` is `sha256`.
fn short(pre_hash: &str) -> String {
    pre_hash.to_ascii_lowercase().replace("sha2-", "sha").replace('-', "")
}

#[test]
fn test_every_provider_is_here() {
    let records = records();
    for (provider, count) in [("ossl35", 12), ("bc", 24), ("carl-redhound", 16), ("botan", 4)] {
        assert_eq!(records.iter().filter(|r| field(r, "provider") == provider).count(), count,
                   "{provider}");
    }
    // Every set in both forms, from two implementations each.
    for set in allcrypt::api::slh_dsa_parameter_sets() {
        for hashed in [false, true] {
            let signers: Vec<&str> = records.iter().filter(|r| {
                let (name, form) = named(r);
                name.eq_ignore_ascii_case(set) && form.is_some() == hashed
            }).map(|r| field(r, "provider")).collect();
            assert!(signers.len() >= 2, "{set} hashed={hashed}: {signers:?}");
        }
    }
}

/// The OID in each file name maps, through this library's table, to the
/// set and form the name states; and the certificate carries that OID.
#[test]
fn test_the_oid_table_agrees_with_every_file_name() {
    for record in records() {
        let label = label(&record);
        let oid = allcrypt::asn1::encode_oid(field(&record, "oid")).unwrap();
        let (set, pre_hash) = allcrypt::x509::slh_dsa_parameter_set(&oid)
            .unwrap_or_else(|| panic!("{label}: no SLH-DSA OID"));
        let (name, form) = named(&record);
        assert!(name.eq_ignore_ascii_case(set), "{label}: {set}");
        match form {
            None => assert_eq!(pre_hash, None, "{label}"),
            Some(hash) => {
                let ours = pre_hash.unwrap_or_else(|| panic!("{label}: pure here"));
                if let Some(hash) = hash {
                    assert_eq!(short(ours), hash, "{label}");
                }
            }
        }
        let der = base64(&record, "certificate");
        let certificate = Certificate::parse(&der).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::SlhDsa(set, pre_hash),
                   "{label}");
    }
}

/// Redhound's HashSLH-DSA certificates are signed with the HashSLH-DSA
/// OID by a key whose SubjectPublicKeyInfo carries the pure one - and the
/// PKCS#8 file beside each carries the HashSLH-DSA one again. Those twelve,
/// and nothing else here, mix the forms.
fn mixes_forms(certificate: &Certificate<'_>) -> bool {
    let SignatureAlgorithm::SlhDsa(_, signed) = certificate.signature_algorithm else {
        panic!("not SLH-DSA");
    };
    let PublicKey::SlhDsa { pre_hash: carried, .. } = certificate.public_key else {
        panic!("not an SLH-DSA key");
    };
    signed != carried
}

#[test]
fn test_only_redhounds_hash_slh_dsa_certificates_mix_forms() {
    for record in records() {
        let der = base64(&record, "certificate");
        let certificate = Certificate::parse(&der).unwrap();
        let expected = field(&record, "provider") == "carl-redhound"
            && field(&record, "name").starts_with("hash-");
        assert_eq!(mixes_forms(&certificate), expected, "{}", label(&record));
    }
}

/// Every self-signed certificate verifies under the key it carries, and
/// with one byte of what was signed changed, does not.
///
/// Except the twelve that mix forms, which RFC 9909 section 8 forbids -
/// a key named pure "is not permitted to be used to ... verify a
/// signature identified by a HashSLH-DSA OID" - and which are refused by
/// name. Their signatures are still checked, with the key taken as the
/// HashSLH-DSA key it was used as: that is a second implementation's
/// HashSLH-DSA beside Bouncy Castle's.
#[test]
fn test_every_certificate_verifies() {
    let policy = verify::Policy::default();
    let mut mixed = 0;
    for (i, record) in records().iter().enumerate() {
        let label = label(record);
        let der = base64(record, "certificate");
        let certificate = Certificate::parse(&der).unwrap();
        let SignatureAlgorithm::SlhDsa(set, pre_hash) = certificate.signature_algorithm else {
            panic!("{label}");
        };
        let PublicKey::SlhDsa { parameter_set, key, .. } = certificate.public_key else {
            panic!("{label}");
        };
        assert_eq!(parameter_set, set, "{label}");
        if mixes_forms(&certificate) {
            mixed += 1;
            let error = verify::verify_signature(&certificate, &certificate, &policy)
                .unwrap_err();
            assert!(error.contains("section 8"), "{label}: {error}");
            let as_used = SlhDsaPublicKey::from_public(set, key).unwrap();
            assert!(as_used.verify(certificate.tbs, b"", pre_hash, certificate.signature)
                        .unwrap(), "{label}");
            continue;
        }
        verify::verify_signature(&certificate, &certificate, &policy)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        let public = SlhDsaPublicKey::from_certificate(&der).unwrap();
        assert_eq!(public.pre_hash(), pre_hash, "{label}");
        // One in four, tampered: verifying is the slow part.
        if i % 4 == 0 {
            let mut tbs = certificate.tbs.to_vec();
            let middle = tbs.len() / 2;
            tbs[middle] ^= 0x10;
            assert!(verify::verify_signed(&tbs, certificate.signature_algorithm,
                                          certificate.signature, &certificate.public_key,
                                          &policy).is_err(), "{label}");
        }
    }
    assert_eq!(mixed, 12);
}

/// Each private key reads as the set and form its file name states -
/// which is its certificate's signature algorithm - and its tail is the
/// certificate's public key.
#[test]
fn test_every_private_key_is_its_certificates() {
    for record in records() {
        let label = label(&record);
        let der = base64(&record, "certificate");
        let certificate = Certificate::parse(&der).unwrap();
        let SignatureAlgorithm::SlhDsa(parameter_set, pre_hash) = certificate.signature_algorithm
            else { panic!("{label}") };
        let PublicKey::SlhDsa { key, .. } = certificate.public_key else {
            panic!("{label}");
        };
        match private_key::parse(&base64(&record, "private"))
                .unwrap_or_else(|e| panic!("{label}: {e}")) {
            PrivateKey::SlhDsa { parameter_set: set, pre_hash: form, private } => {
                assert_eq!((set, form), (parameter_set, pre_hash), "{label}");
                let n = private.len() / 4;
                assert_eq!(&private[2 * n..], key, "{label}");
            }
            other => panic!("{label}: {}", other.algorithm()),
        }
    }
}

/// At the 128-bit `f` sets, where generation and signing are quick: a
/// signature made here with the key bound to
/// its pre-hash verifies under the participant's certificate, and the key
/// with its certificate makes a CA whose leaves verify under that
/// certificate - pre-hashed when the certificate's key is. Redhound's
/// mixed ones count as the pure keys their certificates say they are.
#[test]
fn test_their_keys_sign_here() {
    let policy = verify::Policy::default();
    let mut tried = 0;
    for record in records() {
        let label = label(&record);
        let der = base64(&record, "certificate");
        let certificate = Certificate::parse(&der).unwrap();
        let PublicKey::SlhDsa { parameter_set, pre_hash, .. } = certificate.public_key else {
            panic!("{label}");
        };
        if !parameter_set.ends_with("128f") {
            continue;
        }
        tried += 1;
        let private = match private_key::parse(&base64(&record, "private")).unwrap() {
            PrivateKey::SlhDsa { private, .. } => private,
            other => panic!("{label}: {}", other.algorithm()),
        };
        let key = SlhDsaKey::from_private(parameter_set, &private).unwrap()
            .with_pre_hash(pre_hash).unwrap();
        let message = b"signed with someone else's key";
        let signature = key.sign(message, b"", key.pre_hash()).unwrap();
        let public = SlhDsaPublicKey::from_certificate(&der).unwrap();
        assert!(public.verify(message, b"", public.pre_hash(), &signature).unwrap(), "{label}");
        if pre_hash.is_some() {
            assert!(!public.verify(message, b"", None, &signature).unwrap(), "{label}");
        }

        // Which also regenerates the root from the seeds, and refuses a key
        // whose root is not the one they give.
        let ca = CertificateAuthority::from_parts_with(parameter_set, &private, der.clone())
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        let (leaf, _) = ca.issue("slh-dsa.example", "20260101000000Z", "20360101000000Z")
            .unwrap();
        let leaf = Certificate::parse(&leaf).unwrap();
        assert_eq!(leaf.signature_algorithm, SignatureAlgorithm::SlhDsa(parameter_set, pre_hash),
                   "{label}");
        verify::verify_signature(&leaf, &certificate, &policy)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        // Section 6: a signature key, so digitalSignature and never
        // keyEncipherment.
        let usage = leaf.extensions.key_usage.expect("keyUsage");
        assert!(usage.digital_signature && !usage.key_encipherment, "{label}");
    }
    // OpenSSL, Bouncy Castle, Botan and Redhound pure, Bouncy Castle and
    // Redhound pre-hashed, at both families.
    assert_eq!(tried, 12);
}

/// A private key whose `PK.root` is not the one its seeds give, with a
/// certificate that holds that wrong public key, is refused as a CA: the
/// one place a stored key signs for others regenerates the root.
#[test]
fn test_a_ca_refuses_a_key_whose_root_is_wrong() {
    use allcrypt::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
    let record = records().into_iter()
        .find(|r| field(r, "provider") == "ossl35" && field(r, "name") == "slh-dsa-sha2-128f")
        .expect("record");
    let set = "SLH-DSA-SHA2-128f";
    let mut private = match private_key::parse(&base64(&record, "private")).unwrap() {
        PrivateKey::SlhDsa { private, .. } => private,
        other => panic!("{}", other.algorithm()),
    };
    let signer = SlhDsaKey::from_private(set, &private).unwrap();
    let last = private.len() - 1;
    private[last] ^= 1;
    let wrong = SlhDsaKey::from_private(set, &private).unwrap();
    // Any signer will do: from_parts does not verify the certificate.
    let mut builder = CertificateBuilder::new("wrong root", SubjectKey::SlhDsa {
        parameter_set: set, pre_hash: None, key: wrong.public_bytes() });
    builder.is_ca = Some((true, Some(0)));
    let certificate = builder.sign(&SigningKey::SlhDsa(&signer)).unwrap();
    let error = CertificateAuthority::from_parts_with(set, &private, certificate)
        .err().expect("refused");
    assert!(error.contains("PK.root"), "{error}");
}
