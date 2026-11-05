//! The public enums that grow - a variant per algorithm, key type,
//! message or mode - are `#[non_exhaustive]`, so that adding a variant
//! is a compatible change: code outside the crate that matches on one
//! has to have a catch-all arm, and does not stop compiling when a cipher
//! is added. Enums that describe a closed set (`Side`, a CRL reason, an
//! OCSP status) are left exhaustive on purpose, so a caller can match on
//! them completely.
//!
//! Losing the attribute compiles and passes everything else - the crate's
//! own matches are unaffected by it - so this reads the sources.

/// (source file, its text, the growing enums it declares)
const GROWING: &[(&str, &str, &[&str])] = &[
    ("src/api.rs", include_str!("../src/api.rs"), &["AnyBlockCipher", "AnyHash", "AnyStreamCipher", "Mode", "CaKey", "ClientKeyMaterial", "PrivateKeyParts"]),
    ("src/block_ciphers/cbc_hmac.rs", include_str!("../src/block_ciphers/cbc_hmac.rs"), &["Variant"]),
    ("src/kdf/nist.rs", include_str!("../src/kdf/nist.rs"), &["Prf"]),
    ("src/nacl.rs", include_str!("../src/nacl.rs"), &["Construction"]),
    ("src/pq/prehash.rs", include_str!("../src/pq/prehash.rs"), &["PreHash"]),
    ("src/prng/lcg.rs", include_str!("../src/prng/lcg.rs"), &["Seeding"]),
    ("src/registry.rs", include_str!("../src/registry.rs"), &["Meaning"]),
    ("src/ssh/client.rs", include_str!("../src/ssh/client.rs"), &["Auth"]),
    ("src/ssh/kex.rs", include_str!("../src/ssh/kex.rs"), &["Method"]),
    ("src/ssh/keys.rs", include_str!("../src/ssh/keys.rs"), &["PublicKey"]),
    ("src/ssh/private_key.rs", include_str!("../src/ssh/private_key.rs"), &["PrivateKey"]),
    ("src/ssh/server.rs", include_str!("../src/ssh/server.rs"), &["Credential", "SessionRequest"]),
    ("src/tls/client.rs", include_str!("../src/tls/client.rs"), &["ClientKey", "State"]),
    ("src/tls/handshake.rs", include_str!("../src/tls/handshake.rs"), &["HandshakeType", "Incoming"]),
    ("src/tls/kex.rs", include_str!("../src/tls/kex.rs"), &["EphemeralKey"]),
    ("src/tls/record.rs", include_str!("../src/tls/record.rs"), &["Protection"]),
    ("src/tls/server.rs", include_str!("../src/tls/server.rs"), &["ServerKey"]),
    ("src/tls/suites.rs", include_str!("../src/tls/suites.rs"), &["BulkCipher", "KeyExchange", "MacAlgorithm"]),
    ("src/x509/builder.rs", include_str!("../src/x509/builder.rs"), &["SanEntry", "SigningKey", "SubjectKey"]),
    ("src/x509/mod.rs", include_str!("../src/x509/mod.rs"), &["PublicKey", "SignatureAlgorithm"]),
    ("src/x509/private_key.rs", include_str!("../src/x509/private_key.rs"), &["PrivateKey"]),
    ("src/x509/verify.rs", include_str!("../src/x509/verify.rs"), &["Purpose"]),
];

#[test]
fn test_the_growing_enums_are_non_exhaustive() {
    let mut checked = 0;
    for (path, text, names) in GROWING {
        let lines: Vec<&str> = text.lines().collect();
        for name in *names {
            let at = lines.iter().position(|l| {
                let l = l.trim_start();
                l.strip_prefix("pub enum ").is_some_and(|rest| {
                    rest.strip_prefix(name)
                        .is_some_and(|after| after.starts_with([' ', '<', '{']))
                })
            }).unwrap_or_else(|| panic!("{path} declares no pub enum {name}"));
            let attributes = lines[..at].iter().rev()
                .take_while(|l| l.trim_start().starts_with("#["));
            assert!(attributes.clone().any(|l| l.trim() == "#[non_exhaustive]"),
                    "{path}: pub enum {name} grows and is not #[non_exhaustive]");
            checked += 1;
        }
    }
    assert_eq!(checked, 36);
}
