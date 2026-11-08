//! Certificates and private keys from files, and the private key as the
//! library's types for signing and decrypting.

use std::cell::RefCell;

use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, Curve};
use allcrypt::publickey_ciphers::dsa::{DsaParameters, DsaPrivateKey};
use allcrypt::pq::lms::HssPrivateKey;
use allcrypt::pq::xmss::XmssPrivateKey;
use allcrypt::publickey_ciphers::rsa::RsaPrivateKey;
use allcrypt::x509::builder::SigningKey;
use allcrypt::x509::private_key::{self, PrivateKey};
use allcrypt::x509::HashSig;

/// A private key in the form the operations want it.
pub enum Key {
    Rsa(Box<RsaPrivateKey>),
    Ec { name: &'static str, curve: Curve, private: BigUint },
    Eddsa { name: &'static str, seed: Vec<u8> },
    Dsa(DsaPrivateKey),
    /// A stateful hash-based key (RFC 8554, RFC 8391): every signature
    /// spends a one-time key, so the signer moves it on through the cell
    /// and its state has to be written back before the signature leaves.
    Hss(RefCell<HssPrivateKey>),
    Xmss(RefCell<XmssPrivateKey>),
}

impl Key {
    pub fn from_private(key: PrivateKey) -> Result<Key, String> {
        Ok(match key {
            PrivateKey::Rsa { p, q, e } =>
                Key::Rsa(Box::new(RsaPrivateKey::from_primes(p, q, e)?)),
            PrivateKey::Ec { curve, private } => Key::Ec {
                name: curve, curve: curves::by_name(curve)?,
                private: BigUint::from_bytes_be(&private),
            },
            PrivateKey::Eddsa { curve, private } => Key::Eddsa { name: curve, seed: private },
            PrivateKey::Dsa { p, q, g, x } =>
                Key::Dsa(DsaPrivateKey::from_x(DsaParameters::new(p, q, g)?, x)?),
            other => return Err(format!("A {} key cannot be used here.", other.algorithm())),
        })
    }

    /// PEM or DER, PKCS#8 (encrypted or not) or the traditional forms.
    pub fn load(path: &str, password: Option<&[u8]>) -> Result<Key, String> {
        let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        Key::from_private(private_key::parse_with_password(&data, password)
            .map_err(|e| format!("{path}: {e}"))?)
    }

    /// A stateful key's file, in the library's own form for HSS (RFC 8554
    /// defines none) and the XMSS reference implementation's for XMSS and
    /// XMSS^MT - which share OIDs, so the certificate's scheme says which.
    pub fn load_hash_sig(path: &str, scheme: HashSig) -> Result<Key, String> {
        let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        Key::hash_sig_from_bytes(&data, scheme).map_err(|e| format!("{path}: {e}"))
    }

    pub fn hash_sig_from_bytes(data: &[u8], scheme: HashSig) -> Result<Key, String> {
        Ok(match scheme {
            HashSig::Hss => Key::Hss(RefCell::new(HssPrivateKey::from_bytes(data)?)),
            HashSig::Xmss | HashSig::XmssMt => Key::Xmss(RefCell::new(
                XmssPrivateKey::from_bytes(data, scheme == HashSig::XmssMt)?)),
        })
    }

    /// The public key of a stateful key, to hold against its certificate.
    pub fn hash_sig_public(&self) -> Option<Vec<u8>> {
        match self {
            Key::Hss(key) => Some(key.borrow().public_key()),
            Key::Xmss(key) => Some(key.borrow().public_key()),
            _ => None,
        }
    }

    /// A stateful key's state as it now stands, for its file; `None` for
    /// every other key.
    pub fn state(&self) -> Option<Vec<u8>> {
        match self {
            Key::Hss(key) => Some(key.borrow().to_bytes()),
            Key::Xmss(key) => Some(key.borrow().to_bytes()),
            _ => None,
        }
    }

    pub fn signing(&self) -> SigningKey<'_> {
        match self {
            Key::Rsa(key) => SigningKey::Rsa(key),
            Key::Ec { curve, private, .. } => SigningKey::Ec { curve, private },
            Key::Eddsa { name, seed } => SigningKey::Eddsa { name, seed },
            Key::Dsa(key) => SigningKey::Dsa(key),
            Key::Hss(key) => SigningKey::Hss(key),
            Key::Xmss(key) => SigningKey::Xmss(key),
        }
    }
}

/// Every certificate in a file: PEM blocks, or one DER certificate.
pub fn load_certificates(path: &str) -> Result<Vec<Vec<u8>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    certificates(&data).map_err(|e| format!("{path}: {e}"))
}

pub fn certificates(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if data.starts_with(&[0x30]) {
        allcrypt::x509::Certificate::parse(data)?;
        return Ok(vec![data.to_vec()]);
    }
    let text = std::str::from_utf8(data).map_err(|_| "neither DER nor PEM.".to_string())?;
    let found = allcrypt::api::pem_certificates(text)?;
    if found.is_empty() {
        return Err("no certificate in it.".to_string());
    }
    Ok(found)
}
