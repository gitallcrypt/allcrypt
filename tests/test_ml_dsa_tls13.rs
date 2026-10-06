/*
TLS 1.3 handshakes authenticated with ML-DSA, both ends this library.

What this settles is the wiring: that the server picks the one scheme its
key's parameter set names, that the client checks that binding rather
than accepting any ML-DSA scheme with any ML-DSA certificate, that the
CertificateVerify covers the transcript through the Certificate in both
directions, and that client certificates work as well as server ones.
Both ends are ours, so a shared misreading would round trip; what settles
the bytes is `tests/test_ml_dsa_openssl.rs` (OpenSSL 3.5's handshakes,
checked offline) and `scripts/check_mldsa_witness.py` (OpenSSL 3.5 live,
both directions).
*/

use std::sync::Arc;

use allcrypt::api::MlDsaKey;
use allcrypt::tls::client::{ClientConfig, ClientConnection, ClientIdentity, ClientKey};
use allcrypt::tls::handshake13::scheme;
use allcrypt::tls::server::{ServerConfig, ServerConnection, ServerKey};
use allcrypt::trust::TrustStore;
use allcrypt::x509::builder::{CertificateBuilder, SanEntry, SigningKey, SubjectKey};
use allcrypt::x509::oids;

const NOW: i64 = 1_700_000_000;
const SETS: [&str; 3] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

/// A root under `root_set` and a leaf under `leaf_set` for `hostname`, so
/// the leaf's signature is checked under a key of a different set from
/// its own.
struct Pki {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_key: Arc<MlDsaKey>,
}

fn pki(root_set: &str, leaf_set: &str, hostname: &str) -> Pki {
    let root_key = MlDsaKey::generate(root_set).unwrap();
    let leaf_key = MlDsaKey::generate(leaf_set).unwrap();

    let mut root = CertificateBuilder::new("ML-DSA Root", SubjectKey::MlDsa {
        parameter_set: root_key.parameter_set(), key: root_key.public_bytes() });
    root.serial = vec![1];
    root.issuer = vec![(oids::COMMON_NAME, "ML-DSA Root".to_string())];
    root.not_before = "20200101000000Z";
    root.not_after = "20400101000000Z";
    root.is_ca = Some((true, None));
    let root_der = root.sign(&SigningKey::MlDsa(&root_key)).unwrap();

    let mut leaf = CertificateBuilder::new(hostname, SubjectKey::MlDsa {
        parameter_set: leaf_key.parameter_set(), key: leaf_key.public_bytes() });
    leaf.serial = vec![2];
    leaf.issuer = vec![(oids::COMMON_NAME, "ML-DSA Root".to_string())];
    leaf.not_before = "20200101000000Z";
    leaf.not_after = "20400101000000Z";
    leaf.sans = vec![SanEntry::Dns(hostname.to_string())];
    let leaf_der = leaf.sign(&SigningKey::MlDsa(&root_key)).unwrap();

    Pki { root_der, leaf_der, leaf_key: Arc::new(leaf_key) }
}

struct Ends {
    client: ClientConnection,
    server: ServerConnection,
}

fn handshake(server: &Pki, client_identity: Option<&Pki>) -> Result<Ends, String> {
    let mut server_config = ServerConfig::new(vec![server.leaf_der.clone()],
                                              ServerKey::MlDsa(server.leaf_key.clone()));
    server_config.now = NOW;
    if let Some(identity) = client_identity {
        server_config.request_client_certificate = true;
        server_config.require_client_certificate = true;
        let mut roots = TrustStore::new();
        roots.add_der(&identity.root_der).unwrap();
        server_config.client_roots = Some(roots);
        server_config.client_policy = allcrypt::x509::verify::Policy::at(NOW);
    }

    let mut roots = TrustStore::new();
    roots.add_der(&server.root_der).unwrap();
    let mut client_config = ClientConfig::new(roots, NOW);
    client_config.min_version = allcrypt::tls::Version::TLS13;
    client_config.max_version = allcrypt::tls::Version::TLS13;
    if let Some(identity) = client_identity {
        client_config.client_certificate = Some(ClientIdentity {
            chain: vec![identity.leaf_der.clone()],
            key: ClientKey::MlDsa(identity.leaf_key.clone()),
        });
    }

    let mut client = ClientConnection::new(client_config, "pq.test")
        .map_err(|e| e.detail.clone())?;
    let mut server = ServerConnection::new(server_config).map_err(|e| e.detail.clone())?;
    for _ in 0..12 {
        let from_client = client.take_outgoing();
        if !from_client.is_empty() {
            server.push_incoming(&from_client);
            server.process().map_err(|e| format!("server: {}", e.detail))?;
        }
        let from_server = server.take_outgoing();
        if !from_server.is_empty() {
            client.push_incoming(&from_server);
            client.process().map_err(|e| format!("client: {}", e.detail))?;
        }
        if from_client.is_empty() && from_server.is_empty() {
            break;
        }
    }
    Ok(Ends { client, server })
}

/// Every parameter set as the server's key, each under a root of the
/// next set along, and the scheme the client saw is the one the leaf's
/// set names.
#[test]
fn test_each_parameter_set_authenticates_a_server() {
    for (i, leaf_set) in SETS.iter().enumerate() {
        let root_set = SETS[(i + 1) % 3];
        let pki = pki(root_set, leaf_set, "pq.test");
        let ends = handshake(&pki, None).unwrap_or_else(|e| panic!("{leaf_set}: {e}"));
        assert!(ends.client.is_established() && ends.server.is_established(), "{leaf_set}");
        assert!(ends.client.certificate_verified(), "{leaf_set}");
        assert_eq!(ends.client.peer_signature_scheme(),
                   scheme::ml_dsa_for_parameter_set(leaf_set), "{leaf_set}");
    }
}

/// An ML-DSA client certificate, required and verified by the server.
#[test]
fn test_an_ml_dsa_client_certificate() {
    let server = pki("ML-DSA-87", "ML-DSA-65", "pq.test");
    let client = pki("ML-DSA-65", "ML-DSA-44", "client.test");
    let ends = handshake(&server, Some(&client)).expect("the handshake");
    assert!(ends.server.is_established());
    assert_eq!(ends.server.peer_certificates().len(), 1);
    assert!(ends.server.client_certificate_verified());
}

/// The scheme names a parameter set and so does the certificate; a
/// signature under the wrong pairing is refused by name, even though
/// the signature itself is valid for the key.
#[test]
fn test_a_scheme_naming_another_parameter_set_is_refused() {
    use allcrypt::tls::server13;
    let pki = pki("ML-DSA-44", "ML-DSA-65", "bind.test");
    let content = b"the CertificateVerify content";
    let signature = pki.leaf_key.sign(content, &[], None).unwrap();

    server13::verify_signature(&pki.leaf_der, scheme::MLDSA65, content, &signature)
        .expect("the right scheme verifies");
    let error = server13::verify_signature(&pki.leaf_der, scheme::MLDSA44, content, &signature)
        .expect_err("ML-DSA-44's scheme with an ML-DSA-65 key");
    assert!(error.detail.contains("mldsa44") && error.detail.contains("ML-DSA-65"),
            "{}", error.detail);

    // The FIPS 204 context is empty; a signature made with any other is
    // a different signature and does not verify.
    let with_context = pki.leaf_key.sign(content, b"TLS 1.3, server CertificateVerify", None)
        .unwrap();
    assert!(server13::verify_signature(&pki.leaf_der, scheme::MLDSA65, content,
                                       &with_context).is_err());
}

/// Below TLS 1.3 an ML-DSA key signs nothing: draft-ietf-tls-mldsa
/// section 3.2. The client's key declines both older constructions.
#[test]
fn test_an_ml_dsa_client_key_declines_before_tls13() {
    let pki = pki("ML-DSA-44", "ML-DSA-44", "legacy.test");
    let identity = ClientIdentity { chain: vec![pki.leaf_der.clone()],
                                    key: ClientKey::MlDsa(pki.leaf_key.clone()) };
    assert_eq!(identity.schemes(), vec![scheme::MLDSA44]);
    assert!(identity.sign_digest_12(0x0904, "sha256", &[0; 32]).unwrap_err()
            .contains("1.3 only"));
    assert!(identity.sign_certificate_verify_10(&[0; 36]).unwrap_err().contains("1.3 only"));
}

/// The scheme the server used is recorded on the EdDSA path too.
///
/// EdDSA and ML-DSA both leave `handle_certificate_verify` early, before
/// the digest every other scheme computes, and the EdDSA return set the
/// next state but not `peer_signature_scheme` - so an Ed25519 handshake
/// reported no scheme at all. Nothing asked until the ML-DSA test above
/// did, because no handshake test of an Ed25519 server ran this client
/// against our own server and looked.
#[test]
fn test_the_peer_scheme_is_recorded_on_the_eddsa_path_too() {
    let (seed, public) = allcrypt::api::eddsa_generate("ed25519").unwrap();
    let mut root = CertificateBuilder::new("pq.test", SubjectKey::Eddsa {
        name: "ed25519", key: &public });
    root.serial = vec![1];
    root.issuer = vec![(oids::COMMON_NAME, "pq.test".to_string())];
    root.not_before = "20200101000000Z";
    root.not_after = "20400101000000Z";
    root.sans = vec![SanEntry::Dns("pq.test".to_string())];
    let der = root.sign(&SigningKey::Eddsa { name: "ed25519", seed: &seed }).unwrap();

    let mut server_config = ServerConfig::new(vec![der.clone()],
                                              ServerKey::Eddsa { name: "ed25519", seed });
    server_config.now = NOW;
    let mut roots = TrustStore::new();
    roots.add_der(&der).unwrap();
    let mut client_config = ClientConfig::new(roots, NOW);
    client_config.min_version = allcrypt::tls::Version::TLS13;
    let mut client = ClientConnection::new(client_config, "pq.test").unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    for _ in 0..12 {
        let up = client.take_outgoing();
        server.push_incoming(&up);
        server.process().unwrap();
        let down = server.take_outgoing();
        client.push_incoming(&down);
        client.process().unwrap();
        if up.is_empty() && down.is_empty() {
            break;
        }
    }
    assert!(client.is_established());
    assert_eq!(client.peer_signature_scheme(), Some(scheme::ED25519));
}
