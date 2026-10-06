/*
A TLS 1.3 handshake whose CertificateVerify is signed with GOST R 34.10.

**This reaches code that nothing could reach before.** `client.rs`'s
GOST arm of `handle_certificate_verify_13` - the RFC 9367 scheme-to-curve
binding, the offered-scheme check, the `str_l(r) | str_l(s)` decode - has
existed and been unreachable, because producing a GOST 1.3
CertificateVerify needed a server that could sign one and there was none.
Neither could anything else supply it: OpenSSL has GOST only through an
engine, that engine has no TLS 1.3 GOST suite at all, and
`python-cryptography` has never had Streebog.

What this settles, and what it does not:

  * **Settled here.** The wiring. That the server picks the one scheme RFC
    9367 binds to its key's curve, that the digest follows the key size
    rather than the curve's name, that the transcript hash is taken before
    the CertificateVerify is added to it, that the context string is the
    server's, and that the client checks the binding rather than accepting
    any GOST scheme with any GOST certificate.
  * **Not settled here, and not by anything that can be written here.**
    The cryptography. Both ends are ours, so a shared misreading round
    trips perfectly. What settles that is `tests/test_rfc9367_flight.rs`,
    which verifies RFC 9367 appendix A's own `sgn` against the document's
    own certificate and asserts that our *encoder* reproduces the
    document's bytes. Those are different questions and both need
    answering - and the order matters, because building this on an
    unpinned encoder would have proved nothing at all.
*/

use allcrypt::api::AnyHash;
use allcrypt::ec::{curves, Curve};
use allcrypt::hash_functions::HashFunction;
use allcrypt::tls::client::{ClientConfig, ClientConnection, ClientIdentity,
                            ClientKey};
use allcrypt::tls::handshake13::scheme;
use allcrypt::tls::server::{ServerConfig, ServerConnection, ServerKey};
use allcrypt::tls::suites::Selection;
use allcrypt::trust::TrustStore;
use allcrypt::x509::builder::{CertificateBuilder, SanEntry, SigningKey, SubjectKey};
use allcrypt::x509::oids;

const NOW: i64 = 1_700_000_000;

/// A GOST root and a leaf under it, on one curve.
struct Pki {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_private: allcrypt::bignum::BigUint,
}

fn pki(curve: &Curve, hostname: &str) -> Pki {
    let (root_private, root_public) = curve.generate_key_pair().unwrap();
    let (leaf_private, leaf_public) = curve.generate_key_pair().unwrap();

    let mut root = CertificateBuilder::new(
        "GOST 1.3 Root", SubjectKey::Gost { curve, point: &root_public });
    root.serial = vec![1];
    root.issuer = vec![(oids::COMMON_NAME, "GOST 1.3 Root".to_string())];
    root.subject = vec![(oids::COMMON_NAME, "GOST 1.3 Root".to_string())];
    root.not_before = "20200101000000Z";
    root.not_after = "20400101000000Z";
    root.is_ca = Some((true, None));
    let root_der = root.sign(&SigningKey::Gost { curve, private: &root_private })
        .unwrap();

    let mut leaf = CertificateBuilder::new(
        hostname, SubjectKey::Gost { curve, point: &leaf_public });
    leaf.serial = vec![2];
    leaf.issuer = vec![(oids::COMMON_NAME, "GOST 1.3 Root".to_string())];
    leaf.subject = vec![(oids::COMMON_NAME, hostname.to_string())];
    leaf.not_before = "20200101000000Z";
    leaf.not_after = "20400101000000Z";
    leaf.sans = vec![SanEntry::Dns(hostname.to_string())];
    let leaf_der = leaf.sign(&SigningKey::Gost { curve, private: &root_private })
        .unwrap();

    Pki { root_der, leaf_der, leaf_private }
}

/// The four RFC 9367 suites, which are the only 1.3 suites whose PRF is
/// Streebog and therefore the only ones a GOST key is negotiated under.
const SUITES: &[&str] = &["TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
                          "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
                          "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
                          "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"];

struct Ends {
    client: ClientConnection,
    server: ServerConnection,
}

/// Both ends, over no socket: each one's output is fed straight to the
/// other until neither produces anything.
fn handshake(curve_name: &str, hostname: &str, suite: &str,
             client_identity: Option<(&Curve, Vec<Vec<u8>>,
                                      allcrypt::bignum::BigUint)>,
             ask_for_a_client_certificate: bool)
             -> Result<Ends, String> {
    let curve = curves::by_name(curve_name).unwrap();
    let pki = pki(&curve, hostname);

    let mut server_config = ServerConfig::new(
        vec![pki.leaf_der.clone(), pki.root_der.clone()],
        ServerKey::Gost { curve: curve.name, private: pki.leaf_private.clone() });
    server_config.suites = Selection::named(&[suite]).unwrap();
    server_config.now = NOW;
    if ask_for_a_client_certificate {
        server_config.request_client_certificate = true;
        let mut roots = TrustStore::new();
        if let Some((_, chain, _)) = &client_identity {
            roots.add_der(chain.last().unwrap()).unwrap();
        }
        server_config.client_roots = Some(roots);
        // **The policy carries its own clock**, and `config.now` does not
        // set it - `Policy::default()` judges as at the epoch, so leaving
        // this out refuses the client's certificate with "not valid until
        // ...". See the note on `ServerConfig::client_policy`.
        server_config.client_policy = allcrypt::x509::verify::Policy::at(NOW);
    }

    let mut roots = TrustStore::new();
    roots.add_der(&pki.root_der).unwrap();
    let mut client_config = ClientConfig::new(roots, NOW);
    client_config.suites = Selection::named(&[suite]).unwrap();
    client_config.min_version = allcrypt::tls::Version::TLS13;
    client_config.max_version = allcrypt::tls::Version::TLS13;
    if let Some((client_curve, chain, private)) = client_identity {
        client_config.client_certificate = Some(ClientIdentity {
            chain,
            key: ClientKey::Gost { curve: client_curve.name, private },
        });
    }

    let mut client = ClientConnection::new(client_config, hostname)
        .map_err(|e| e.detail.clone())?;
    let mut server = ServerConnection::new(server_config)
        .map_err(|e| e.detail.clone())?;

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

/// Every GOST curve RFC 9367 names, on every one of its four suites.
///
/// All seven curves rather than one, because the scheme-to-curve mapping
/// is where this goes wrong: three of the seven are named by a letter that
/// does not match their parameter set's, so a table written from the
/// letters is wrong in three places and a single-curve test would very
/// likely pick one of the four that happen to agree.
#[test]
fn test_a_gost_certificate_verify_at_tls13() {
    let mut checked = 0;
    for curve_name in curves::gost_names() {
        for suite in SUITES {
            let ends = handshake(curve_name, "gost13.test", suite, None, false)
                .unwrap_or_else(|e| panic!("{} on {}: {}", curve_name, suite, e));
            assert!(ends.client.is_established(),
                    "{} on {}: not established", curve_name, suite);
            assert!(ends.server.is_established(), "{} on {}", curve_name, suite);
            assert!(ends.client.certificate_verified(),
                    "{} on {}: the chain was not verified", curve_name, suite);

            // The scheme the server chose is the one RFC 9367 binds to
            // this curve, and the client accepted it for that reason
            // rather than because it accepts any GOST scheme.
            let expected = scheme::gost_13_for_curve(curve_name)
                .unwrap_or_else(|| panic!("no RFC 9367 scheme for {}", curve_name));
            assert_eq!(ends.client.peer_signature_scheme(), Some(expected),
                       "{} on {}", curve_name, suite);
            checked += 1;
        }
    }
    // Seven curves times four suites. Asserted so that a curve dropped
    // from `gost_names` shrinks the loop visibly rather than silently.
    assert_eq!(checked, 7 * 4, "{} combinations ran", checked);
}

/// The digest follows the **key size**, not the curve's name.
///
/// RFC 9367 section 5.2: a 256 bit key signs under Streebog-256 and a 512
/// bit one under Streebog-512, while the handshake hash is Streebog-256
/// for all four suites either way. Two different questions that share an
/// answer four times out of seven, which is exactly the shape that gets
/// one of them written in terms of the other.
#[test]
fn test_the_signature_digest_follows_the_key_size() {
    for (curve_name, expected) in [("gost256-a", "streebog256"),
                                   ("gost256-tc26-a", "streebog256"),
                                   ("gost512-a", "streebog512"),
                                   ("gost512-b", "streebog512")] {
        let chosen = scheme::gost_13_for_curve(curve_name).unwrap();
        assert_eq!(scheme::hash_name(chosen), Some(expected), "{}", curve_name);

        // And the handshake really completes with that pairing, which the
        // mapping alone does not show.
        let ends = handshake(curve_name, "digest.test", SUITES[0], None, false)
            .unwrap_or_else(|e| panic!("{}: {}", curve_name, e));
        assert!(ends.client.is_established(), "{}", curve_name);
    }
}

/// A GOST client certificate, verified by the server.
///
/// The other direction through the same code: `server13::verify_signature`
/// has a GOST arm for this, and it too was unreachable until a client
/// could produce the signature.
#[test]
fn test_a_gost_client_certificate_at_tls13() {
    let curve = curves::by_name("gost256-a").unwrap();
    let client_pki = pki(&curve, "client.test");
    let chain = vec![client_pki.leaf_der.clone(), client_pki.root_der.clone()];

    let ends = handshake("gost256-a", "gost13.test", SUITES[0],
                         Some((&curve, chain, client_pki.leaf_private.clone())),
                         true)
        .expect("the handshake with a GOST client certificate");
    assert!(ends.client.is_established());
    assert!(ends.server.is_established());
    // The server saw a certificate and verified the signature over it -
    // `established` alone would also be true of a server that asked and
    // accepted nothing.
    assert_eq!(ends.server.peer_certificates().len(), 2,
               "the server did not receive the client's chain");
}

/// The binding, refused.
///
/// A GOST signature that is perfectly valid under the *wrong* scheme for
/// the certificate's curve must be refused, or the binding in RFC 9367
/// section 5.2 is decoration. Checked by calling the verifier directly
/// with a mismatched scheme, because a handshake cannot produce this - our
/// own server picks the right one.
#[test]
fn test_a_scheme_bound_to_another_curve_is_refused() {
    use allcrypt::tls::server13;

    let curve = curves::by_name("gost256-a").unwrap();
    let pki = pki(&curve, "bind.test");
    let content = b"whatever the context string was";

    let mut hasher = AnyHash::new("streebog256").unwrap();
    hasher.update(content);
    let digest = hasher.digest();
    let signature = curve.gost_sign(&pki.leaf_private, &digest,
                                    AnyHash::new("streebog256").unwrap()).unwrap();
    let bytes = curve.gost_signature_bytes_13(&signature).unwrap();

    // The right scheme verifies, so the refusal below is about the
    // binding and not about the signature being broken.
    let right = scheme::gost_13_for_curve("gost256-a").unwrap();
    server13::verify_signature(&pki.leaf_der, right, content, &bytes)
        .expect("the correct scheme should verify");

    // `256c` is bound to gost256-b. The signature is valid, the key is a
    // GOST key, and the pairing is wrong.
    let wrong = scheme::GOSTR34102012_256C;
    assert_ne!(right, wrong);
    let error = server13::verify_signature(&pki.leaf_der, wrong, content, &bytes)
        .expect_err("a scheme bound to another curve must be refused");
    assert!(error.detail.contains("gost256-b"), "{}", error.detail);
}

/// A 1.2 GOST client certificate is refused rather than signed wrongly.
///
/// The codepoints exist - RFC 9189 assigns the schemes and section 7 the
/// certificate types - but the 1.2 CertificateVerify construction for them
/// is not built, and the pair carries no hash byte for `hash_name` to
/// answer. Refusing at the decision is what keeps the failure away from
/// the signature.
#[test]
fn test_a_gost_client_key_declines_before_tls13() {
    let curve = curves::by_name("gost256-a").unwrap();
    let pki = pki(&curve, "legacy.test");
    let identity = ClientIdentity {
        chain: vec![pki.leaf_der.clone()],
        key: ClientKey::Gost { curve: curve.name, private: pki.leaf_private },
    };

    // One scheme at 1.3, and nothing usable at 1.2 or below.
    assert_eq!(identity.schemes(),
               vec![scheme::gost_13_for_curve("gost256-a").unwrap()]);
    let error = identity.sign_digest_12(0x0804, "streebog256", &[0u8; 32])
        .expect_err("1.2 must refuse");
    assert!(error.contains("1.3 only"), "{}", error);
    let error = identity.sign_certificate_verify_10(&[0u8; 36])
        .expect_err("1.0 and 1.1 must refuse");
    assert!(error.contains("MD5"), "{}", error);
}
