/*!
ML-DSA in X.509 and TLS 1.3, checked against what OpenSSL 3.5 wrote.

`src/x509/rfc9881_tests.rs` reads RFC 9881's own examples, which all come
from one seed. This reads files and handshakes **OpenSSL 3.5** produced,
recorded by `scripts/capture_mldsa.py`, and needs no OpenSSL:

  * `vectors/ml_dsa_openssl.vec` - one key per parameter set in all three
    private key forms OpenSSL writes, its public key, self-signed
    certificates, a chain across all three sets (an ML-DSA-87 root signs
    an ML-DSA-65 intermediate, which signs an ML-DSA-44 leaf), and
    `pkeyutl` signatures with and without a context string;
  * `tests/transcripts/mldsa_handshakes.txt` - a TLS 1.3 handshake per
    parameter set between `s_client` and `s_server`, with the key log.
    The server's flight is decrypted here and its CertificateVerify -
    OpenSSL's ML-DSA signature over the transcript - is checked by the
    function this library's client and server use.

The other direction - OpenSSL accepting what this library signs - is
`scripts/check_mldsa_witness.py`, run by hand.
*/

use allcrypt::hash_functions::{sha2, HashFunction};
use allcrypt::tls::handshake::{HandshakeReader, HandshakeType};
use allcrypt::tls::handshake13::{certificate_verify_content, scheme, Certificate13,
                                 CertificateVerify, Side13};
use allcrypt::tls::keys13::{TrafficKeys, NONCE_LEN};
use allcrypt::tls::record::RecordReader;
use allcrypt::tls::record13::Aead13;
use allcrypt::tls::ContentType;
use allcrypt::x509::private_key::{self, PrivateKey};
use allcrypt::x509::{verify, Certificate, PublicKey, SignatureAlgorithm};

mod fixture {
    include!("transcripts/loader.rs");
}

const VECTORS: &str = include_str!("../vectors/ml_dsa_openssl.vec");

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

/// The three private key forms of one OpenSSL key are one key: the same
/// expanded key, the seed where the form has one, and a public key
/// derived from it equal to the one OpenSSL wrote.
#[test]
fn test_openssls_three_private_key_forms_are_one_key() {
    let keys = section("key");
    assert_eq!(keys.len(), 3);
    for record in &keys {
        let name = field(record, "name");
        let parsed: Vec<(Option<Vec<u8>>, Vec<u8>)> = ["seed-only", "priv-only", "seed-priv"]
            .iter().map(|form| match private_key::parse(&base64(record, form))
                .unwrap_or_else(|e| panic!("{name} {form}: {e}")) {
                PrivateKey::MlDsa { parameter_set, seed, expanded } => {
                    assert_eq!(parameter_set, name);
                    (seed, expanded)
                }
                other => panic!("{name} {form}: {}", other.algorithm()),
            }).collect();
        assert!(parsed[0].0.is_some() && parsed[1].0.is_none() && parsed[2].0.is_some());
        assert_eq!(parsed[0].0, parsed[2].0, "{name}: two seeds");
        assert!(parsed.iter().all(|(_, expanded)| *expanded == parsed[0].1), "{name}");

        let key = allcrypt::api::MlDsaKey::from_private(name, &parsed[1].1).unwrap();
        assert_eq!(key.public_bytes(), &spki_key(&base64(record, "public"))[..], "{name}");
    }
}

/// A private key with one byte changed is refused, in each form that can
/// be checked: the seed and expanded key disagree in `seed-priv`, and the
/// expanded key's own parts disagree in `priv-only`.
#[test]
fn test_a_changed_byte_in_an_openssl_key_is_refused() {
    for record in &section("key") {
        for form in ["priv-only", "seed-priv"] {
            let mut der = base64(record, form);
            // A byte well inside the expanded key: past the headers,
            // the seed and `rho`, into `s1`.
            let at = der.len() - 1500;
            der[at] ^= 0x01;
            assert!(private_key::parse(&der).is_err(), "{} {form}", field(record, "name"));
        }
    }
}

/// OpenSSL's self-signed certificates verify, and say what they are.
#[test]
fn test_openssls_self_signed_certificates_verify() {
    let certificates = section("certificate");
    let keys = section("key");
    for (record, key) in certificates.iter().take(3).zip(&keys) {
        let name = field(key, "name");
        assert_eq!(field(record, "name"), format!("{name}-self-signed"));
        let der = base64(record, "certificate");
        let certificate = Certificate::parse(&der).unwrap();
        assert!(matches!(certificate.signature_algorithm,
                         SignatureAlgorithm::MlDsa(set) if set == name));
        let public = spki_key(&base64(key, "public"));
        assert!(matches!(certificate.public_key,
                         PublicKey::MlDsa { key, .. } if key == &public[..]));
        verify::verify_signature(&certificate, &certificate, &verify::Policy::default())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// A chain whose every link crosses parameter sets: an ML-DSA-87 root
/// signs an ML-DSA-65 intermediate, which signs an ML-DSA-44 leaf for
/// `localhost`. Each signature is checked under the issuer's key, of a
/// different set from the certificate's own.
#[test]
fn test_an_openssl_chain_across_the_three_sets() {
    let record = section("certificate").into_iter()
        .find(|r| field(r, "name") == "chain").expect("the chain");
    let (leaf, intermediate, root) =
        (base64(&record, "leaf"), base64(&record, "intermediate"), base64(&record, "root"));
    let chain = [Certificate::parse(&leaf).unwrap(), Certificate::parse(&intermediate).unwrap()];
    let roots = [Certificate::parse(&root).unwrap()];
    assert_eq!(chain[0].signature_algorithm, SignatureAlgorithm::MlDsa("ML-DSA-65"));
    assert_eq!(chain[1].signature_algorithm, SignatureAlgorithm::MlDsa("ML-DSA-87"));
    // Inside the certificates' validity, which OpenSSL set from the run.
    let policy = verify::Policy::at(chain[0].not_before + 60);
    verify::verify_chain(&chain, &roots, &policy, verify::Purpose::ServerAuth).unwrap();
    assert!(verify::matches_hostname(&chain[0], "localhost"));

    // The leaf checked under the root, skipping the intermediate, is a
    // signature under the wrong key - and the wrong parameter set, which
    // is refused by name.
    let error = verify::verify_signature(&chain[0], &roots[0], &policy).unwrap_err();
    assert!(error.contains("ML-DSA-65") && error.contains("ML-DSA-87"), "{error}");
}

/// `pkeyutl -sign` over several lengths, with and without a FIPS 204
/// context string. A signature made with a context must not verify
/// without it - which is also what shows the context really reached
/// OpenSSL's signer.
#[test]
fn test_openssls_signatures_verify_with_their_context_only() {
    let keys = section("key");
    let signatures = section("signature");
    assert_eq!(signatures.len(), 24);
    let mut with_context = 0;
    for record in &signatures {
        let name = field(record, "name");
        let key = keys.iter().find(|k| field(k, "name") == name).unwrap();
        let public = allcrypt::api::MlDsaPublicKey::from_public(
            name, &spki_key(&base64(key, "public"))).unwrap();
        let length: usize = field(record, "length").parse().unwrap();
        let message: Vec<u8> = (0..length).map(|i| ((7 * i + 3) & 0xff) as u8).collect();
        let context = hex(field(record, "context"));
        let signature = hex(field(record, "signature"));
        assert!(public.verify(&message, &context, None, &signature).unwrap(),
                "{name}, {length} bytes, context {:?}", field(record, "context"));
        let other: &[u8] = if context.is_empty() { b"allcrypt" } else { b"" };
        assert!(!public.verify(&message, other, None, &signature).unwrap());
        with_context += usize::from(!context.is_empty());
    }
    assert_eq!(with_context, 12);
}

// ------------------------------------------------------------ handshakes ---

/// Every record in one direction, framed but not decrypted.
fn frame(bytes: &[u8]) -> Vec<(ContentType, Vec<u8>)> {
    let mut reader = RecordReader::new();
    reader.push_incoming(bytes);
    let mut records = Vec::new();
    while let Some(record) = reader.read().expect("framing a real transcript") {
        records.push((record.content_type, record.payload));
    }
    records
}

fn messages(bytes: &[u8]) -> Vec<allcrypt::tls::handshake::HandshakeMessage> {
    let mut reader = HandshakeReader::new();
    reader.push(bytes);
    let mut found = Vec::new();
    while let Some(message) = reader.next_message().unwrap() {
        found.push(message);
    }
    found
}

/// For each of the three handshakes: decrypt the server's flight with
/// OpenSSL's own handshake secret, then check its CertificateVerify the
/// way this library's client does - over SHA-256 of ClientHello through
/// Certificate, with the server's context string, under the key in the
/// certificate. Then the same signature over a transcript one byte
/// different, which must fail.
#[test]
fn test_openssls_certificate_verify_in_three_real_handshakes() {
    let captures = fixture::load_mldsa();
    assert_eq!(captures.len(), 3);
    let mut schemes = Vec::new();
    for capture in &captures {
        assert_eq!(capture.cipher, "TLS_AES_128_GCM_SHA256");
        let secret = capture.secrets.iter()
            .find(|(label, _, _)| label == "SERVER_HANDSHAKE_TRAFFIC_SECRET")
            .map(|(_, _, value)| hex(value)).expect("a handshake secret");
        let keys = TrafficKeys::derive("sha256", &secret, 16, NONCE_LEN).unwrap();
        let mut state = Aead13::new("aes-gcm", "sha256", keys, 16).unwrap();

        let client_hello = frame(&capture.to_server).into_iter()
            .find(|(t, _)| *t == ContentType::Handshake).unwrap().1;
        let mut plain = Vec::new();
        let mut server_hello = Vec::new();
        for (content_type, fragment) in frame(&capture.to_client) {
            match content_type {
                ContentType::Handshake => server_hello.extend_from_slice(&fragment),
                ContentType::ChangeCipherSpec => {}
                ContentType::ApplicationData => match state.decrypt(&fragment) {
                    Ok((ContentType::Handshake, bytes)) => plain.extend_from_slice(&bytes),
                    _ => break,
                },
                other => panic!("{:?}", other),
            }
        }
        let flight = messages(&plain);
        let kinds: Vec<HandshakeType> = flight.iter().map(|m| m.message_type).collect();
        assert_eq!(kinds, [HandshakeType::EncryptedExtensions, HandshakeType::Certificate,
                           HandshakeType::CertificateVerify, HandshakeType::Finished],
                   "{}", capture.name);

        let chain = Certificate13::parse(&flight[1].body).unwrap().chain();
        let verify = CertificateVerify::parse(&flight[2].body).unwrap();
        schemes.push(verify.scheme);

        let mut transcript = Vec::new();
        for raw in [&messages(&client_hello)[0].raw, &messages(&server_hello)[0].raw,
                    &flight[0].raw, &flight[1].raw] {
            transcript.extend_from_slice(raw);
        }
        let hash = sha2::SHA256::new(&transcript).digest();
        let content = certificate_verify_content(Side13::Server, &hash);
        allcrypt::tls::server13::verify_signature(&chain[0], verify.scheme, &content,
                                                  &verify.signature)
            .unwrap_or_else(|e| panic!("{}: {e:?}", capture.name));

        let mut wrong = transcript.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 1;
        let content = certificate_verify_content(Side13::Server,
                                                 &sha2::SHA256::new(&wrong).digest());
        assert!(allcrypt::tls::server13::verify_signature(&chain[0], verify.scheme, &content,
                                                          &verify.signature).is_err());
    }
    assert_eq!(schemes, [scheme::MLDSA44, scheme::MLDSA65, scheme::MLDSA87]);
}
