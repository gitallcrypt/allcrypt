//! DNSSEC's algorithms: each one's public key in a DNSKEY, its signature
//! in an RRSIG, and its private key in BIND's `Private-key-format` file;
//! with the key tag (RFC 4034 appendix B), DS digests (RFC 4034 section
//! 5.1.4, RFC 4509, 5933, 6605, 9558, 9563) and NSEC3's hash (RFC 5155
//! section 5).
//!
//! | Number | Mnemonic | Defined in |
//! |---|---|---|
//! | 1 | RSAMD5 | RFC 4034 appendix A.1 |
//! | 3 | DSA | RFC 2536 |
//! | 5 | RSASHA1 | RFC 3110 |
//! | 6 | DSA-NSEC3-SHA1 | RFC 5155 |
//! | 7 | RSASHA1-NSEC3-SHA1 | RFC 5155 |
//! | 8 | RSASHA256 | RFC 5702 |
//! | 10 | RSASHA512 | RFC 5702 |
//! | 12 | ECC-GOST | RFC 5933 |
//! | 13 | ECDSAP256SHA256 | RFC 6605 |
//! | 14 | ECDSAP384SHA384 | RFC 6605 |
//! | 15 | ED25519 | RFC 8080 |
//! | 16 | ED448 | RFC 8080 |
//! | 17 | SM2SM3 | RFC 9563 |
//! | 23 | ECC-GOST12 | RFC 9558 |

use allcrypt::api::{self, AnyHash, DsaKey, EcKey, EcPublicKey, RsaKey, RsaPublicKey};
use allcrypt::bignum::BigUint;
use allcrypt::hash_functions::HashFunction;
use allcrypt::publickey_ciphers::dsa::{DsaParameters, DsaPrivateKey, DsaPublicKey};

use crate::base64;
use crate::name::Name;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Rsa,
    Dsa,
    Ecdsa,
    Gost,
    Eddsa,
    Sm2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithm {
    pub number: u8,
    pub mnemonic: &'static str,
    pub family: Family,
    /// The hash the signature is over; for EdDSA, `None`.
    pub hash: Option<&'static str>,
    /// The curve, for the elliptic families.
    pub curve: Option<&'static str>,
}

pub const ALGORITHMS: [Algorithm; 14] = [
    Algorithm { number: 1, mnemonic: "RSAMD5", family: Family::Rsa, hash: Some("md5"),
                curve: None },
    Algorithm { number: 3, mnemonic: "DSA", family: Family::Dsa, hash: Some("sha1"),
                curve: None },
    Algorithm { number: 5, mnemonic: "RSASHA1", family: Family::Rsa, hash: Some("sha1"),
                curve: None },
    Algorithm { number: 6, mnemonic: "DSA-NSEC3-SHA1", family: Family::Dsa,
                hash: Some("sha1"), curve: None },
    Algorithm { number: 7, mnemonic: "RSASHA1-NSEC3-SHA1", family: Family::Rsa,
                hash: Some("sha1"), curve: None },
    Algorithm { number: 8, mnemonic: "RSASHA256", family: Family::Rsa, hash: Some("sha256"),
                curve: None },
    Algorithm { number: 10, mnemonic: "RSASHA512", family: Family::Rsa, hash: Some("sha512"),
                curve: None },
    // CryptoPro-A is the curve; the hash is GOST R 34.11-94 under the
    // CryptoPro parameter set (RFC 5933 section 2).
    Algorithm { number: 12, mnemonic: "ECC-GOST", family: Family::Gost, hash: Some("gost94"),
                curve: Some("gost256-a") },
    Algorithm { number: 13, mnemonic: "ECDSAP256SHA256", family: Family::Ecdsa,
                hash: Some("sha256"), curve: Some("P-256") },
    Algorithm { number: 14, mnemonic: "ECDSAP384SHA384", family: Family::Ecdsa,
                hash: Some("sha384"), curve: Some("P-384") },
    Algorithm { number: 15, mnemonic: "ED25519", family: Family::Eddsa, hash: None,
                curve: Some("ed25519") },
    Algorithm { number: 16, mnemonic: "ED448", family: Family::Eddsa, hash: None,
                curve: Some("ed448") },
    Algorithm { number: 17, mnemonic: "SM2SM3", family: Family::Sm2, hash: Some("sm3"),
                curve: Some("sm2p256v1") },
    // id-tc26-gost-3410-2012-256-paramSetA, the twisted Edwards curve
    // with cofactor 4 (RFC 9558 section 2).
    Algorithm { number: 23, mnemonic: "ECC-GOST12", family: Family::Gost,
                hash: Some("streebog256"), curve: Some("gost256-tc26-a") },
];

pub fn algorithm(number: u8) -> Result<Algorithm, String> {
    ALGORITHMS.iter().find(|a| a.number == number).copied()
        .ok_or_else(|| format!("DNSSEC algorithm {number} is not implemented here."))
}

pub fn algorithm_named(text: &str) -> Result<Algorithm, String> {
    if let Ok(n) = text.parse::<u8>() {
        return algorithm(n);
    }
    ALGORITHMS.iter().find(|a| a.mnemonic.eq_ignore_ascii_case(text)).copied()
        .ok_or_else(|| format!("No DNSSEC algorithm {text}."))
}

// ------------------------------------------------------------------ key tag --

/// RFC 4034 appendix B. Algorithm 1 is the exception: its tag is the
/// modulus's third- and second-to-last bytes (appendix B.1).
pub fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    if dnskey_rdata.get(3) == Some(&1) && dnskey_rdata.len() >= 4 + 3 {
        let n = dnskey_rdata.len();
        return u16::from_be_bytes([dnskey_rdata[n - 3], dnskey_rdata[n - 2]]);
    }
    let mut acc: u32 = 0;
    for (i, &b) in dnskey_rdata.iter().enumerate() {
        acc += if i & 1 == 1 { b as u32 } else { (b as u32) << 8 };
    }
    acc += (acc >> 16) & 0xffff;
    (acc & 0xffff) as u16
}

// ----------------------------------------------------------------------- DS --

pub const DIGEST_TYPES: [(u8, &str, &str); 6] = [
    (1, "SHA-1", "sha1"),
    (2, "SHA-256", "sha256"),
    (3, "GOST R 34.11-94", "gost94"),
    (4, "SHA-384", "sha384"),
    (5, "GOST R 34.11-2012", "streebog256"),
    (6, "SM3", "sm3"),
];

/// `digest(owner | DNSKEY RDATA)`, the owner in canonical form.
pub fn ds_digest(owner: &Name, dnskey_rdata: &[u8], digest_type: u8)
                 -> Result<Vec<u8>, String> {
    let (_, _, hash) = DIGEST_TYPES.iter().find(|(n, _, _)| *n == digest_type)
        .ok_or_else(|| format!("DS digest type {digest_type} is not implemented here."))?;
    let mut h = AnyHash::new(hash)?;
    h.update(&owner.canonical().to_wire());
    h.update(dnskey_rdata);
    Ok(h.digest())
}

// -------------------------------------------------------------------- NSEC3 --

/// RFC 5155 section 5: `IH(salt, x, 0) = H(x || salt)`, then
/// `IH(salt, x, k) = H(IH(salt, x, k - 1) || salt)`, over the owner name
/// in canonical wire form. Hash algorithm 1, SHA-1, is the only one
/// defined.
pub fn nsec3_hash(name: &Name, hash_algorithm: u8, salt: &[u8], iterations: u16)
                  -> Result<Vec<u8>, String> {
    if hash_algorithm != 1 {
        return Err(format!("NSEC3 hash algorithm {hash_algorithm} is not defined."));
    }
    let round = |data: &[u8]| -> Result<Vec<u8>, String> {
        let mut h = AnyHash::new("sha1")?;
        h.update(data);
        h.update(salt);
        Ok(h.digest())
    };
    let mut value = round(&name.canonical().to_wire())?;
    for _ in 0..iterations {
        value = round(&value)?;
    }
    Ok(value)
}

// ------------------------------------------------------------- private keys --

/// A private key and what is needed to sign with it.
pub enum PrivateKey {
    Rsa(Box<RsaKey>),
    Dsa(DsaKey),
    /// ECDSA, GOST and SM2: the curve and the big endian scalar.
    Ec { algorithm: Algorithm, key: EcKey },
    Eddsa { algorithm: Algorithm, seed: Vec<u8> },
}

pub struct Key {
    pub algorithm: Algorithm,
    pub private: PrivateKey,
}

fn trim(bytes: &[u8]) -> &[u8] {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    &bytes[zeros.min(bytes.len().saturating_sub(1))..]
}

fn number(numbers: &[(&'static str, Vec<u8>)], name: &str) -> Vec<u8> {
    numbers.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone()).unwrap_or_default()
}

/// The DER prefixes of RFC 5933 section 2.2's and RFC 9558 section 2.2's
/// PKCS#8 private keys. The scalar follows, 32 bytes little endian.
const GOST2001_PKCS8: [u8; 39] = [
    0x30, 0x45, 0x02, 0x01, 0x00, 0x30, 0x1c, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x13,
    0x30, 0x12, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, 0x06, 0x07, 0x2a, 0x85,
    0x03, 0x02, 0x02, 0x1e, 0x01, 0x04, 0x22, 0x04, 0x20,
];
const GOST2012_PKCS8: [u8; 32] = [
    0x30, 0x3e, 0x02, 0x01, 0x00, 0x30, 0x17, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01,
    0x01, 0x01, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01,
    0x04, 0x20,
];

fn gost_prefix(algorithm: Algorithm) -> &'static [u8] {
    if algorithm.number == 12 { &GOST2001_PKCS8 } else { &GOST2012_PKCS8 }
}

impl Key {
    /// A new key. RSA takes `bits`; DSA is 1024 bits, the most RFC 2536's
    /// `T` can express.
    pub fn generate(algorithm: Algorithm, bits: usize) -> Result<Key, String> {
        let private = match algorithm.family {
            Family::Rsa => {
                if !(512..=4096).contains(&bits) {
                    return Err(format!("RSA keys here are 512 to 4096 bits, not {bits}."));
                }
                PrivateKey::Rsa(Box::new(RsaKey::generate(bits)?))
            }
            Family::Dsa => PrivateKey::Dsa(DsaKey::generate(1024, 160)?),
            Family::Ecdsa | Family::Gost | Family::Sm2 => PrivateKey::Ec {
                algorithm, key: EcKey::generate(algorithm.curve.expect("a curve"))? },
            Family::Eddsa => {
                let (seed, _) = api::eddsa_generate(algorithm.curve.expect("a curve"))?;
                PrivateKey::Eddsa { algorithm, seed }
            }
        };
        Ok(Key { algorithm, private })
    }

    /// The DNSKEY public key field.
    pub fn public_key(&self) -> Result<Vec<u8>, String> {
        match &self.private {
            // RFC 3110 section 2: exponent length, one byte or zero and
            // two, then the exponent and the modulus.
            PrivateKey::Rsa(key) => {
                let numbers = key.numbers();
                let e = number(&numbers, "e");
                let n = number(&numbers, "n");
                let (e, n) = (trim(&e), trim(&n));
                let mut out = if e.len() < 256 { vec![e.len() as u8] }
                              else { vec![0, (e.len() >> 8) as u8, e.len() as u8] };
                out.extend_from_slice(e);
                out.extend_from_slice(n);
                Ok(out)
            }
            // RFC 2536 section 2: T, Q, P, G, Y with T = (|P| - 64) / 8.
            PrivateKey::Dsa(key) => {
                let (p, q, g) = key.parameters();
                let y = key.public_key().public_bytes();
                let width = 64 + 8 * ((trim(&p).len().max(64) - 64) / 8);
                let t = (width - 64) / 8;
                let mut out = vec![t as u8];
                out.extend(pad(&q, 20)?);
                for v in [&p, &g, &y] {
                    out.extend(pad(v, width)?);
                }
                Ok(out)
            }
            PrivateKey::Ec { algorithm, key } => {
                let sec1 = key.public_bytes(false)?;
                let (x, y) = sec1[1..].split_at((sec1.len() - 1) / 2);
                Ok(match algorithm.family {
                    // Little endian x, then little endian y.
                    Family::Gost => x.iter().rev().chain(y.iter().rev()).copied().collect(),
                    // x | y, big endian (RFC 6605 section 4, RFC 9563 4.1).
                    _ => sec1[1..].to_vec(),
                })
            }
            PrivateKey::Eddsa { algorithm, seed } =>
                api::eddsa_public_key(algorithm.curve.expect("a curve"), seed),
        }
    }

    /// The RRSIG signature field over `data`.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let digest = |hash: &str| -> Result<Vec<u8>, String> {
            let mut h = AnyHash::new(hash)?;
            h.update(data);
            Ok(h.digest())
        };
        match &self.private {
            PrivateKey::Rsa(key) => {
                let hash = self.algorithm.hash.expect("a hash");
                key.sign(hash, &digest(hash)?)
            }
            // RFC 2536 section 3: T, R, S, R and S 20 bytes each.
            PrivateKey::Dsa(key) => {
                let (p, q, g) = key.parameters();
                let parameters = DsaParameters::new(BigUint::from_bytes_be(&p),
                                                    BigUint::from_bytes_be(&q),
                                                    BigUint::from_bytes_be(&g))?;
                let private = DsaPrivateKey::from_x(parameters,
                                                    BigUint::from_bytes_be(&key.private_bytes()))?;
                let (r, s) = private.sign(&digest("sha1")?, AnyHash::new("sha1")?)?;
                let t = (trim(&p).len().max(64) - 64) / 8;
                let mut out = vec![t as u8];
                out.extend(r.to_bytes_be_padded(20)?);
                out.extend(s.to_bytes_be_padded(20)?);
                Ok(out)
            }
            PrivateKey::Ec { algorithm, key } => match algorithm.family {
                Family::Ecdsa => {
                    let hash = algorithm.hash.expect("a hash");
                    key.sign(&digest(hash)?, hash)
                }
                // s | r, each big endian (RFC 4490 section 3.2, as RFC 5933
                // and 9558 adopt it). The digest is read little endian.
                Family::Gost => {
                    let hash = algorithm.hash.expect("a hash");
                    key.sign_gost(&digest(hash)?, hash)
                }
                // r | s over the data itself, with GB/T 32918's default
                // identity: SM2 hashes Z_A || M internally.
                Family::Sm2 => key.sm2_sign(data),
                _ => unreachable!("an EC key of a non-EC family"),
            },
            PrivateKey::Eddsa { algorithm, seed } =>
                api::eddsa_sign(algorithm.curve.expect("a curve"), seed, data, &[]),
        }
    }

    /// BIND's private key file, format v1.3.
    pub fn to_private_file(&self) -> Result<String, String> {
        let mut out = format!("Private-key-format: v1.3\nAlgorithm: {} ({})\n",
                              self.algorithm.number, self.algorithm.mnemonic);
        let mut field = |name: &str, value: &[u8]| {
            out.push_str(&format!("{name}: {}\n", base64::encode(value)));
        };
        match &self.private {
            PrivateKey::Rsa(key) => {
                let numbers = key.numbers();
                for (label, name) in [("Modulus", "n"), ("PublicExponent", "e"),
                                      ("PrivateExponent", "d"), ("Prime1", "p"),
                                      ("Prime2", "q"), ("Exponent1", "dp"),
                                      ("Exponent2", "dq"), ("Coefficient", "qinv")] {
                    field(label, trim(&number(&numbers, name)));
                }
            }
            PrivateKey::Dsa(key) => {
                let (p, q, g) = key.parameters();
                field("Prime(p)", trim(&p));
                field("Subprime(q)", trim(&q));
                field("Base(g)", trim(&g));
                field("Private_value(x)", trim(&key.private_bytes()));
                field("Public_value(y)", trim(&key.public_key().public_bytes()));
            }
            PrivateKey::Ec { algorithm, key } => {
                let scalar = key.private_bytes()?;
                if algorithm.family == Family::Gost {
                    let mut der = gost_prefix(*algorithm).to_vec();
                    der.extend(scalar.iter().rev());
                    field(if algorithm.number == 12 { "GostAsn1" } else { "Gost12Asn1" },
                          &der);
                } else {
                    field("PrivateKey", &scalar);
                }
            }
            PrivateKey::Eddsa { seed, .. } => field("PrivateKey", seed),
        }
        Ok(out)
    }

    pub fn from_private_file(text: &str) -> Result<Key, String> {
        let mut fields: Vec<(String, String)> = Vec::new();
        for line in text.lines() {
            let line = line.trim_end();
            if let Some((k, v)) = line.split_once(':') {
                if !line.starts_with(' ') && !line.starts_with('\t') {
                    fields.push((k.trim().to_string(), v.trim().to_string()));
                    continue;
                }
            }
            // A value continued on the next line, as the RFCs print them.
            if let Some(last) = fields.last_mut() {
                last.1.push_str(line.trim());
            }
        }
        let get = |name: &str| -> Result<&str, String> {
            fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
                .ok_or_else(|| format!("The private key file has no {name}."))
        };
        let bytes = |name: &str| -> Result<Vec<u8>, String> {
            base64::decode(get(name)?).ok_or_else(|| format!("{name} is not base64."))
        };
        let number_text = get("Algorithm")?.split_whitespace().next().unwrap_or("");
        let algorithm = algorithm_named(number_text)?;
        let private = match algorithm.family {
            Family::Rsa => PrivateKey::Rsa(Box::new(RsaKey::from_primes(
                &bytes("Prime1")?, &bytes("Prime2")?, &bytes("PublicExponent")?)?)),
            Family::Dsa => PrivateKey::Dsa(DsaKey::from_numbers(
                &bytes("Prime(p)")?, &bytes("Subprime(q)")?, &bytes("Base(g)")?,
                &bytes("Private_value(x)")?)?),
            Family::Ecdsa | Family::Sm2 => PrivateKey::Ec {
                algorithm,
                key: EcKey::from_private(algorithm.curve.expect("a curve"),
                                         &bytes("PrivateKey")?)?,
            },
            Family::Gost => {
                let name = if algorithm.number == 12 { "GostAsn1" } else { "Gost12Asn1" };
                let der = bytes(name)?;
                let prefix = gost_prefix(algorithm);
                let scalar = der.strip_prefix(prefix).filter(|s| s.len() == 32)
                    .ok_or_else(|| format!("{name} is not the PKCS#8 structure the RFC \
                                            gives."))?;
                let big_endian: Vec<u8> = scalar.iter().rev().copied().collect();
                PrivateKey::Ec { algorithm,
                                 key: EcKey::from_private(algorithm.curve.expect("a curve"),
                                                          &big_endian)? }
            }
            Family::Eddsa => {
                let seed = bytes("PrivateKey")?;
                api::eddsa_public_key(algorithm.curve.expect("a curve"), &seed)?;
                PrivateKey::Eddsa { algorithm, seed }
            }
        };
        Ok(Key { algorithm, private })
    }
}

fn pad(bytes: &[u8], width: usize) -> Result<Vec<u8>, String> {
    let bytes = trim(bytes);
    if bytes.len() > width {
        return Err(format!("A {}-byte number in a {width}-byte field.", bytes.len()));
    }
    let mut out = vec![0; width - bytes.len()];
    out.extend_from_slice(bytes);
    Ok(out)
}

// ------------------------------------------------------------- verification --

/// Check an RRSIG signature field against a DNSKEY public key field.
/// `Ok(false)` for a signature that does not verify; an error for a key or
/// signature that is not well formed.
pub fn verify(algorithm: Algorithm, public_key: &[u8], data: &[u8], signature: &[u8])
              -> Result<bool, String> {
    let digest = |hash: &str| -> Result<Vec<u8>, String> {
        let mut h = AnyHash::new(hash)?;
        h.update(data);
        Ok(h.digest())
    };
    match algorithm.family {
        Family::Rsa => {
            let (e, n) = match public_key.first() {
                Some(0) if public_key.len() >= 3 => {
                    let len = u16::from_be_bytes([public_key[1], public_key[2]]) as usize;
                    let rest = &public_key[3..];
                    (rest.get(..len).ok_or("Short RSA key.")?, &rest[len.min(rest.len())..])
                }
                Some(&len) => {
                    let rest = &public_key[1..];
                    (rest.get(..len as usize).ok_or("Short RSA key.")?,
                     &rest[(len as usize).min(rest.len())..])
                }
                None => return Err("An empty RSA key.".to_string()),
            };
            let key = RsaPublicKey::new(n, e)?;
            if signature.len() != n.len() - n.iter().take_while(|&&b| b == 0).count() {
                return Ok(false);
            }
            let hash = algorithm.hash.expect("a hash");
            key.verify(hash, &digest(hash)?, signature)
        }
        Family::Dsa => {
            let t = *public_key.first().ok_or("An empty DSA key.")? as usize;
            let width = 64 + 8 * t;
            if t > 8 || public_key.len() != 1 + 20 + 3 * width {
                return Err(format!("A DSA key of {} bytes for T = {t}.", public_key.len()));
            }
            let q = &public_key[1..21];
            let p = &public_key[21..21 + width];
            let g = &public_key[21 + width..21 + 2 * width];
            let y = &public_key[21 + 2 * width..];
            if signature.len() != 41 {
                return Ok(false);
            }
            let parameters = DsaParameters::new(BigUint::from_bytes_be(p),
                                                BigUint::from_bytes_be(q),
                                                BigUint::from_bytes_be(g))?;
            let public = DsaPublicKey::new(parameters, BigUint::from_bytes_be(y))?;
            public.verify(&digest("sha1")?, &BigUint::from_bytes_be(&signature[1..21]),
                          &BigUint::from_bytes_be(&signature[21..]))
        }
        Family::Ecdsa | Family::Gost | Family::Sm2 => {
            let curve = algorithm.curve.expect("a curve");
            if !public_key.len().is_multiple_of(2) {
                return Err("An EC public key of odd length.".to_string());
            }
            let mut sec1 = vec![4u8];
            if algorithm.family == Family::Gost {
                let (x, y) = public_key.split_at(public_key.len() / 2);
                sec1.extend(x.iter().rev());
                sec1.extend(y.iter().rev());
            } else {
                sec1.extend_from_slice(public_key);
            }
            let key = EcPublicKey::from_bytes(curve, &sec1)?;
            if signature.len() != public_key.len() {
                return Ok(false);
            }
            match algorithm.family {
                Family::Ecdsa => key.verify(&digest(algorithm.hash.expect("a hash"))?,
                                            signature),
                Family::Gost => key.verify_gost(&digest(algorithm.hash.expect("a hash"))?,
                                                signature),
                _ => key.sm2_verify(data, signature),
            }
        }
        Family::Eddsa => api::eddsa_verify(algorithm.curve.expect("a curve"), public_key, data,
                                           signature, &[]),
    }
}
