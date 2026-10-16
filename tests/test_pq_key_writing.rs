/*!
Post-quantum keys written here, against files other implementations
wrote for the same keys.

Every private key OpenSSL 3.5 wrote in `vectors/ml_dsa_openssl.vec` and
`vectors/ml_kem_openssl.vec`, in each of its three forms, and every
SLH-DSA private key in the IETF hackathon's artifacts
(`vectors/slh_dsa_x509.vec`, from four implementations), is read and
written again, and must come out byte for byte the file it came from;
so must each public key, from OpenSSL's `PUBLIC KEY` file or the
certificate's SubjectPublicKeyInfo. The other direction - OpenSSL reading
what is written here - is checked live by
`scripts/check_pq_key_writing.py`.
*/

use allcrypt::api::{self, MlDsaKey, MlKemKey, PrivateKeyForm, SlhDsaKey};
use allcrypt::x509::private_key::{self, PrivateKey};
use allcrypt::x509::Certificate;

type Record = Vec<(String, String)>;

fn section(text: &str, name: &str) -> Vec<Record> {
    let header = format!("[{name}]");
    let start = text.lines().position(|line| line == header)
        .unwrap_or_else(|| panic!("no {header}"));
    let mut records = Vec::new();
    let mut current: Record = Vec::new();
    for line in text.lines().skip(start + 1) {
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
    records
}

fn base64(record: &Record, name: &str) -> Vec<u8> {
    let value = &record.iter().find(|(key, _)| key == name)
        .unwrap_or_else(|| panic!("{name}")).1;
    allcrypt::pem::decode(value).unwrap()
}

fn field<'a>(record: &'a Record, name: &str) -> &'a str {
    &record.iter().find(|(key, _)| key == name).unwrap_or_else(|| panic!("{name}")).1
}

const FORMS: [(&str, PrivateKeyForm); 3] = [("seed-only", PrivateKeyForm::Seed),
                                            ("priv-only", PrivateKeyForm::Expanded),
                                            ("seed-priv", PrivateKeyForm::Both)];

/// OpenSSL's three files for each ML-DSA key: read any one, write each
/// form, get OpenSSL's file for that form.
#[test]
fn test_ml_dsa_keys_written_as_openssl_writes_them() {
    let keys = section(include_str!("../vectors/ml_dsa_openssl.vec"), "key");
    assert_eq!(keys.len(), 3);
    for record in &keys {
        let name = field(record, "name");
        for (read_form, _) in FORMS {
            let key = match private_key::parse(&base64(record, read_form)).unwrap() {
                PrivateKey::MlDsa { parameter_set, seed: Some(seed), .. } =>
                    MlDsaKey::from_seed(parameter_set, &seed).unwrap(),
                PrivateKey::MlDsa { parameter_set, seed: None, expanded } =>
                    MlDsaKey::from_private(parameter_set, &expanded).unwrap(),
                other => panic!("{name}: {}", other.algorithm()),
            };
            for (write_form, form) in FORMS {
                match key.to_pkcs8(form) {
                    Ok(der) => assert_eq!(der, base64(record, write_form),
                                          "{name}: {read_form} written {write_form}"),
                    // Only a key read without its seed refuses, and only
                    // the forms that need one.
                    Err(e) => assert!(read_form == "priv-only" && write_form != "priv-only",
                                      "{name}: {read_form} as {write_form}: {e}"),
                }
            }
            assert_eq!(key.public_key().to_spki().unwrap(), base64(record, "public"), "{name}");
        }
    }
}

/// The same for ML-KEM: every key, every form.
#[test]
fn test_ml_kem_keys_written_as_openssl_writes_them() {
    let keys = section(include_str!("../vectors/ml_kem_openssl.vec"), "key");
    assert_eq!(keys.len(), 3);
    for record in &keys {
        let name = field(record, "name");
        for (read_form, _) in FORMS {
            let key = match private_key::parse(&base64(record, read_form)).unwrap() {
                PrivateKey::MlKem { parameter_set, seed: Some(seed), .. } =>
                    MlKemKey::from_seed(parameter_set, &seed).unwrap(),
                PrivateKey::MlKem { parameter_set, seed: None, expanded } =>
                    MlKemKey::from_private(parameter_set, &expanded).unwrap(),
                other => panic!("{name}: {}", other.algorithm()),
            };
            for (write_form, form) in FORMS {
                match key.to_pkcs8(form) {
                    Ok(der) => assert_eq!(der, base64(record, write_form),
                                          "{name}: {read_form} written {write_form}"),
                    Err(e) => assert!(read_form == "priv-only" && write_form != "priv-only",
                                      "{name}: {read_form} as {write_form}: {e}"),
                }
            }
            assert_eq!(key.public_key().to_spki().unwrap(), base64(record, "public"), "{name}");
        }
    }
}

/// Every SLH-DSA private key in the hackathon's artifacts, written again,
/// is its file; every public key, its certificate's SubjectPublicKeyInfo.
#[test]
fn test_slh_dsa_keys_written_as_four_implementations_write_them() {
    let records = section(include_str!("../vectors/slh_dsa_x509.vec"), "certificate");
    assert_eq!(records.len(), 56);
    for record in &records {
        let label = format!("{} {}", field(record, "provider"), field(record, "name"));
        let file = base64(record, "private");
        let key = match private_key::parse(&file).unwrap() {
            PrivateKey::SlhDsa { parameter_set, pre_hash, private } =>
                SlhDsaKey::from_private(parameter_set, &private).unwrap()
                    .with_pre_hash(pre_hash).unwrap(),
            other => panic!("{label}: {}", other.algorithm()),
        };
        assert_eq!(key.to_pkcs8().unwrap(), file, "{label}");

        let der = base64(record, "certificate");
        let certificate = Certificate::parse(&der).unwrap();
        let public = api::SlhDsaPublicKey::from_certificate(&der).unwrap();
        assert_eq!(public.to_spki().unwrap(), certificate.spki, "{label}");
    }
}

/// A written key, encrypted with `encrypt_private_key`, reads back as the
/// same key with the password and not without it.
#[test]
fn test_a_written_key_encrypts() {
    let key = MlDsaKey::generate("ML-DSA-65").unwrap();
    let der = key.to_pkcs8(PrivateKeyForm::Seed).unwrap();
    let pem = allcrypt::pem::wrap("PRIVATE KEY", &der);
    let encrypted = api::encrypt_private_key(pem.as_bytes(), b"correct horse", "aes-256-cbc",
                                             None, Some(1000), None, None).unwrap();
    assert!(private_key::parse(&encrypted).is_err());
    match private_key::parse_with_password(&encrypted, Some(b"correct horse")).unwrap() {
        PrivateKey::MlDsa { seed, .. } => assert_eq!(seed.as_deref(), key.seed()),
        other => panic!("{}", other.algorithm()),
    }
}

#[test]
fn test_the_form_names() {
    for (name, form) in [("seed", PrivateKeyForm::Seed), ("Seed-Only", PrivateKeyForm::Seed),
                         ("expanded", PrivateKeyForm::Expanded),
                         ("priv-only", PrivateKeyForm::Expanded),
                         ("both", PrivateKeyForm::Both), ("seed-priv", PrivateKeyForm::Both)] {
        assert_eq!(PrivateKeyForm::from_name(name).unwrap(), form, "{name}");
    }
    for name in ["", "private", "seed+priv", "full"] {
        assert!(PrivateKeyForm::from_name(name).is_err(), "{name}");
    }
}
