/*
Real, signed certificates for the tests.

Hand-assembled DER is fine for testing the parser and useless for testing
the verifier: a chain whose signatures do not actually verify cannot
distinguish a verifier that checks them from one that does not. So these
build genuine certificates with `builder`, signed with real keys.

Everything here uses EC P-256 rather than RSA, for one reason: an RSA key
generation is a prime search and these run on every `cargo test`. The RSA
path is covered by its own tests and by the differential example.
*/

use crate::bignum::BigUint;
use crate::ec::{curves, Curve};
use crate::x509::builder::{key_usage, CertificateBuilder, SanEntry, SigningKey, SubjectKey};
use crate::x509::oids;

/// A key pair on a GOST curve, for the certificate path that shares no
/// code with the ECDSA one.
pub struct GostTestKey {
    pub curve: Curve,
    pub private: BigUint,
    pub point: crate::ec::Point,
}

impl GostTestKey {
    pub fn new(curve_name: &str) -> GostTestKey {
        let curve = curves::by_name(curve_name).unwrap();
        let (private, point) = curve.generate_key_pair().unwrap();
        GostTestKey { curve, private, point }
    }

    pub fn signing(&self) -> SigningKey<'_> {
        SigningKey::Gost { curve: &self.curve, private: &self.private }
    }

    pub fn subject(&self) -> SubjectKey<'_> {
        SubjectKey::Gost { curve: &self.curve, point: &self.point }
    }

    /// A self-signed certificate, and one signed by this key for another.
    pub fn issue(&self, subject: &GostTestKey, common_name: &str,
                 issuer_common_name: &str, serial: u8) -> Vec<u8> {
        let mut certificate = CertificateBuilder::new(common_name,
                                                      subject.subject());
        certificate.serial = vec![serial];
        certificate.issuer = vec![(oids::COMMON_NAME,
                                   issuer_common_name.to_string())];
        certificate.subject = vec![(oids::COMMON_NAME, common_name.to_string())];
        certificate.not_before = "20200101000000Z";
        certificate.not_after = "20400101000000Z";
        certificate.sans = vec![SanEntry::Dns(common_name.to_string())];
        certificate.sign(&self.signing()).expect("building a GOST certificate")
    }
}

/// A key pair on P-256, kept together for convenience.
pub struct TestKey {
    pub curve: Curve,
    pub private: BigUint,
    pub point: Vec<u8>,
}

impl Default for TestKey {
    fn default() -> Self {
        Self::new()
    }
}

impl TestKey {
    pub fn new() -> TestKey {
        let curve = curves::p256();
        let (private, public) = curve.generate_key_pair().unwrap();
        let point = curve.encode_point(&public, false).unwrap();
        TestKey { curve, private, point }
    }

    pub fn signing(&self) -> SigningKey<'_> {
        SigningKey::Ec { curve: &self.curve, private: &self.private }
    }

    pub fn subject(&self) -> SubjectKey<'_> {
        SubjectKey::Ec { curve: &self.curve, point: &self.point }
    }
}

/// The knobs the verifier's tests turn.
pub struct Builder {
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<Vec<u8>>,
    pub not_before: String,
    pub not_after: String,
    pub is_ca: Option<(bool, Option<u32>)>,
    pub key_usage: Option<u16>,
    pub extended_key_usage: Vec<&'static [u8]>,
    pub extra_extensions: Vec<(Vec<u8>, bool, Vec<u8>)>,
    /// SANs beyond the DNS and IP ones, for the name forms name
    /// constraints cover.
    pub extra_sans: Vec<SanEntry>,
    /// The whole subject DN, when a single CN will not do - a
    /// directoryName constraint is a prefix of the RDN sequence, so a
    /// test of one needs more than one RDN.
    pub subject: Option<Vec<(&'static [u8], String)>>,
    pub hash: String,
}

impl Default for Builder {
    fn default() -> Builder {
        Builder {
            common_name: "leaf.test".to_string(),
            dns_names: vec!["leaf.test".to_string()],
            ip_addresses: vec![],
            not_before: "20200101000000Z".to_string(),
            not_after: "20400101000000Z".to_string(),
            is_ca: None,
            key_usage: None,
            extended_key_usage: vec![],
            extra_extensions: vec![],
            extra_sans: vec![],
            subject: None,
            hash: "sha256".to_string(),
        }
    }
}

impl Builder {
    /// Build and sign with `signer`, taking the issuer name from
    /// `issuer_common_name`.
    pub fn issue(&self, subject_key: &TestKey, signer: &TestKey,
                 issuer_common_name: &str, serial: u8) -> Vec<u8> {
        let mut certificate = CertificateBuilder::new(&self.common_name,
                                                      subject_key.subject());
        certificate.serial = vec![serial];
        certificate.issuer = vec![(oids::COMMON_NAME, issuer_common_name.to_string())];
        certificate.subject = self.subject.clone().unwrap_or_else(
            || vec![(oids::COMMON_NAME, self.common_name.clone())]);
        certificate.not_before = &self.not_before;
        certificate.not_after = &self.not_after;
        certificate.is_ca = self.is_ca;
        certificate.key_usage = self.key_usage;
        certificate.extended_key_usage = self.extended_key_usage.clone();
        certificate.extra_extensions = self.extra_extensions.clone();
        certificate.hash = &self.hash;
        certificate.sans = self.dns_names.iter()
            .map(|name| SanEntry::Dns(name.clone()))
            .chain(self.ip_addresses.iter().map(|ip| SanEntry::Ip(ip.clone())))
            .chain(self.extra_sans.iter().cloned())
            .collect();
        certificate.sign(&signer.signing()).expect("building a test certificate")
    }
}

/// A self-signed leaf with whatever the closure sets. Signed by its own key,
/// which is enough for anything that does not check the signature.
pub fn leaf(mutate: impl FnOnce(&mut Builder)) -> Vec<u8> {
    let mut builder = Builder::default();
    mutate(&mut builder);
    let key = TestKey::new();
    let name = builder.common_name.clone();
    builder.issue(&key, &key, &name, 1)
}

pub fn leaf_with_sans(names: &[&str]) -> Vec<u8> {
    leaf(|b| b.dns_names = names.iter().map(|n| n.to_string()).collect())
}

/// A root, an intermediate and a leaf, with real signatures all the way up.
pub struct Chain {
    pub root: Vec<u8>,
    pub intermediate: Vec<u8>,
    pub leaf: Vec<u8>,
    pub root_key: TestKey,
    pub intermediate_key: TestKey,
    pub leaf_key: TestKey,
}

/// Build a three-certificate chain, with each level's builder available to
/// be mutated - which is how the verifier's tests break exactly one thing
/// at a time.
pub fn chain(configure_root: impl FnOnce(&mut Builder),
             configure_intermediate: impl FnOnce(&mut Builder),
             configure_leaf: impl FnOnce(&mut Builder)) -> Chain {
    let root_key = TestKey::new();
    let intermediate_key = TestKey::new();
    let leaf_key = TestKey::new();

    let mut root_builder = Builder {
        common_name: "Test Root".to_string(),
        dns_names: vec![],
        is_ca: Some((true, None)),
        key_usage: Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN),
        ..Builder::default()
    };
    configure_root(&mut root_builder);

    let mut intermediate_builder = Builder {
        common_name: "Test Intermediate".to_string(),
        dns_names: vec![],
        is_ca: Some((true, Some(0))),
        key_usage: Some(key_usage::KEY_CERT_SIGN),
        ..Builder::default()
    };
    configure_intermediate(&mut intermediate_builder);

    let mut leaf_builder = Builder {
        key_usage: Some(key_usage::DIGITAL_SIGNATURE),
        extended_key_usage: vec![oids::EKU_SERVER_AUTH],
        ..Builder::default()
    };
    configure_leaf(&mut leaf_builder);

    let root_name = root_builder.common_name.clone();
    let intermediate_name = intermediate_builder.common_name.clone();

    let root = root_builder.issue(&root_key, &root_key, &root_name, 1);
    let intermediate = intermediate_builder.issue(&intermediate_key, &root_key,
                                                  &root_name, 2);
    let leaf = leaf_builder.issue(&leaf_key, &intermediate_key,
                                  &intermediate_name, 3);

    Chain { root, intermediate, leaf, root_key, intermediate_key, leaf_key }
}
