//! EnvelopedData (RFC 5652 section 6), AuthEnvelopedData (RFC 5083 with
//! AES-GCM, RFC 5084) and EncryptedData (section 8), with all four kinds
//! of recipient this example knows:
//!
//! - key transport (`ktri`): RSA PKCS#1 v1.5, or RSA-OAEP (RFC 8017,
//!   parameters as RFC 4055 writes them);
//! - key agreement (`kari`): ephemeral-static ECDH, the shared x
//!   coordinate through the ANSI X9.63 KDF with ECC-CMS-SharedInfo, and
//!   the content key wrapped with AES key wrap (RFC 5753);
//! - a previously shared key (`kekri`): AES key wrap (RFC 3394);
//! - a password (`pwri`): PBKDF2, and RFC 3211's double CBC wrap.
//!
//! Content: AES-128/192/256, Triple DES, DES and RC2 in CBC with PKCS#7
//! padding, and AES-GCM for AuthEnvelopedData.

use allcrypt::api::{self, AnyBlockCipher};
use allcrypt::asn1::{Reader, Tag, Writer};
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::ec::curves;
use allcrypt::publickey_ciphers::rsa::{self, RsaPublicKey};
use allcrypt::x509::{Certificate, PublicKey};

use crate::asn::{self, AlgId, CertId, IssuerSerial};
use crate::keys::Key;
use crate::signed::{content_info, read_cert_id, write_cert_id};

/// The most PBKDF2 iterations read from a message unless the caller
/// raises it: the sender chooses the count.
pub const DEFAULT_MAX_ITERATIONS: u32 = 10_000_000;

// ---------------------------------------------------------- content ciphers --

/// A content-encryption algorithm, with its parameters read.
#[derive(Clone, Debug)]
pub enum ContentCipher {
    /// The library's cipher name, the key length (`None` for RC2, whose
    /// key is as long as the content key that arrives), the IV, and RC2's
    /// effective key bits.
    Cbc { cipher: &'static str, key_len: Option<usize>, iv: Vec<u8>, rc2_bits: Option<usize> },
    Gcm { key_len: usize, nonce: Vec<u8>, tag_len: usize },
}

/// RC2's effective key bits as RFC 3370 encodes them: 160, 120 and 58
/// for 40, 64 and 128 bits, and the number itself from 256 up.
fn rc2_bits(version: u32) -> Result<usize, String> {
    Ok(match version {
        160 => 40,
        120 => 64,
        58 => 128,
        v if v >= 256 => v as usize,
        other => return Err(format!("RC2 parameter version {other} is not one RFC 3370 \
                                     defines.")),
    })
}

fn rc2_version(bits: usize) -> Result<u32, String> {
    Ok(match bits {
        40 => 160,
        64 => 120,
        128 => 58,
        b if b >= 256 => b as u32,
        other => return Err(format!("RC2 with {other} effective bits has no parameter \
                                     version here.")),
    })
}

impl ContentCipher {
    pub fn read(alg: &AlgId) -> Result<ContentCipher, String> {
        let iv = |len: usize| -> Result<Vec<u8>, String> {
            let mut r = alg.params_reader()?;
            let iv = r.read_octet_string()?;
            r.finish()?;
            if iv.len() != len {
                return Err(format!("An IV of {} bytes where {len} belong.", iv.len()));
            }
            Ok(iv.to_vec())
        };
        let aes = [(asn::AES128_CBC, 16), (asn::AES192_CBC, 24), (asn::AES256_CBC, 32)];
        let gcm = [(asn::AES128_GCM, 16), (asn::AES192_GCM, 24), (asn::AES256_GCM, 32)];
        if let Some((_, len)) = aes.iter().find(|(o, _)| alg.is(o)) {
            return Ok(ContentCipher::Cbc { cipher: "aes", key_len: Some(*len), iv: iv(16)?,
                                           rc2_bits: None });
        }
        if let Some((_, len)) = gcm.iter().find(|(o, _)| alg.is(o)) {
            let mut r = alg.params_reader()?;
            let mut seq = r.read_sequence()?;
            let nonce = seq.read_octet_string()?.to_vec();
            let tag_len = if seq.is_empty() { 12 } else { seq.read_u32()? as usize };
            seq.finish()?;
            if !(12..=16).contains(&tag_len) || nonce.is_empty() {
                return Err(format!("AES-GCM with a {tag_len} byte tag and a {} byte nonce.",
                                   nonce.len()));
            }
            return Ok(ContentCipher::Gcm { key_len: *len, nonce, tag_len });
        }
        if alg.is(asn::DES_EDE3_CBC) {
            return Ok(ContentCipher::Cbc { cipher: "3des", key_len: Some(24), iv: iv(8)?,
                                           rc2_bits: None });
        }
        if alg.is(asn::DES_CBC) {
            return Ok(ContentCipher::Cbc { cipher: "des", key_len: Some(8), iv: iv(8)?,
                                           rc2_bits: None });
        }
        if alg.is(asn::RC2_CBC) {
            let mut r = alg.params_reader()?;
            // RC2-CBC-Parameter: the SEQUENCE, or a bare IV meaning 32
            // effective bits (RFC 8018 B.2.3).
            let (bits, iv) = if r.peek_tag() == Some(Tag::sequence()) {
                let mut seq = r.read_sequence()?;
                let bits = rc2_bits(seq.read_u32()?)?;
                let iv = seq.read_octet_string()?.to_vec();
                seq.finish()?;
                (bits, iv)
            } else {
                (32, r.read_octet_string()?.to_vec())
            };
            if iv.len() != 8 {
                return Err("RC2's IV is 8 bytes.".to_string());
            }
            return Ok(ContentCipher::Cbc { cipher: "rc2", key_len: None, iv,
                                           rc2_bits: Some(bits) });
        }
        Err(format!("Content encryption {} is not one this reads.", asn::dotted(&alg.oid)))
    }

    /// A fresh algorithm by name, with a random IV or nonce.
    pub fn named(name: &str) -> Result<(ContentCipher, AlgId), String> {
        let (cipher, oid, key_len, block, rc2) = match name {
            "aes-128-cbc" => ("aes", asn::AES128_CBC, 16, 16, None),
            "aes-192-cbc" => ("aes", asn::AES192_CBC, 24, 16, None),
            "aes-256-cbc" => ("aes", asn::AES256_CBC, 32, 16, None),
            "des-ede3-cbc" => ("3des", asn::DES_EDE3_CBC, 24, 8, None),
            "des-cbc" => ("des", asn::DES_CBC, 8, 8, None),
            "rc2-40-cbc" => ("rc2", asn::RC2_CBC, 5, 8, Some(40)),
            "rc2-64-cbc" => ("rc2", asn::RC2_CBC, 8, 8, Some(64)),
            "rc2-128-cbc" => ("rc2", asn::RC2_CBC, 16, 8, Some(128)),
            "aes-128-gcm" | "aes-192-gcm" | "aes-256-gcm" => {
                let (oid, key_len) = match name {
                    "aes-128-gcm" => (asn::AES128_GCM, 16),
                    "aes-192-gcm" => (asn::AES192_GCM, 24),
                    _ => (asn::AES256_GCM, 32),
                };
                let nonce = api::random_bytes(12)?;
                let mut w = Writer::new();
                w.write_sequence(|w| {
                    w.write_octet_string(&nonce);
                    w.write_u32(16);
                });
                return Ok((ContentCipher::Gcm { key_len, nonce, tag_len: 16 },
                           AlgId::with_params(oid, w.finish())));
            }
            other => return Err(format!("No content cipher named {other}.")),
        };
        let iv = api::random_bytes(block)?;
        let mut w = Writer::new();
        match rc2 {
            Some(bits) => w.write_sequence(|w| {
                w.write_u32(rc2_version(bits).unwrap_or(58));
                w.write_octet_string(&iv);
            }),
            None => w.write_octet_string(&iv),
        }
        Ok((ContentCipher::Cbc { cipher, key_len: Some(key_len), iv, rc2_bits: rc2 },
            AlgId::with_params(oid, w.finish())))
    }

    pub fn key_len(&self) -> Option<usize> {
        match self {
            ContentCipher::Cbc { key_len, .. } => *key_len,
            ContentCipher::Gcm { key_len, .. } => Some(*key_len),
        }
    }

    fn block(&self, key: &[u8]) -> Result<AnyBlockCipher, String> {
        let ContentCipher::Cbc { cipher, key_len, rc2_bits, .. } = self else {
            return Err("Not a CBC cipher.".to_string());
        };
        if key_len.is_some_and(|l| l != key.len()) {
            return Err("decryption failed".to_string());
        }
        let bits = rc2_bits.map(|b| b.to_string());
        AnyBlockCipher::new(cipher, key, bits.as_deref())
    }

    pub fn encrypt(&self, key: &[u8], data: &[u8], aad: &[u8])
                   -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
        match self {
            ContentCipher::Gcm { nonce, .. } => {
                let (sealed, tag) = api::aead_encrypt("aes-gcm", key, nonce, aad, data)?;
                Ok((sealed, Some(tag)))
            }
            ContentCipher::Cbc { iv, .. } => {
                let mut cipher = self.block(key)?;
                let padded = api::pad_pkcs7(data, cipher.blocksize())?;
                let mut out = Vec::with_capacity(padded.len());
                cipher.cbc_encrypt(&padded, &mut out, iv)?;
                Ok((out, None))
            }
        }
    }

    /// The plaintext, or one error that says nothing about why: a padding
    /// error told apart from a wrong key is an oracle.
    pub fn decrypt(&self, key: &[u8], data: &[u8], aad: &[u8], tag: Option<&[u8]>)
                   -> Result<Vec<u8>, String> {
        let failed = || "Decryption failed: wrong key, or the message is damaged.".to_string();
        match self {
            ContentCipher::Gcm { nonce, tag_len, .. } => {
                let tag = tag.ok_or("AES-GCM content without its MAC.")?;
                if tag.len() != *tag_len {
                    return Err(format!("A {} byte MAC where the parameters say {tag_len}.",
                                       tag.len()));
                }
                api::aead_decrypt("aes-gcm", key, nonce, aad, data, tag).map_err(|_| failed())
            }
            ContentCipher::Cbc { iv, .. } => {
                let mut cipher = self.block(key).map_err(|_| failed())?;
                let block = cipher.blocksize();
                if data.is_empty() || !data.len().is_multiple_of(block) {
                    return Err(failed());
                }
                let mut out = Vec::with_capacity(data.len());
                cipher.cbc_decrypt(data, &mut out, iv)?;
                api::unpad_pkcs7(&out, block).map_err(|_| failed())
            }
        }
    }
}

// -------------------------------------------------------------- recipients --

/// One RecipientInfo, read.
#[derive(Clone, Debug)]
pub enum Recipient {
    KeyTrans { rid: CertId, alg: AlgId, encrypted_key: Vec<u8> },
    KeyAgree { originator: Vec<u8>, originator_alg: AlgId, ukm: Option<Vec<u8>>, alg: AlgId,
               keys: Vec<(CertId, Vec<u8>)> },
    Kek { id: Vec<u8>, alg: AlgId, encrypted_key: Vec<u8> },
    Password { kdf: Option<AlgId>, alg: AlgId, encrypted_key: Vec<u8> },
    Other(u8),
}

impl Recipient {
    pub fn describe(&self) -> String {
        match self {
            Recipient::KeyTrans { rid, alg, .. } => format!(
                "key transport ({}) to {}",
                if alg.is(asn::RSAES_OAEP) { "RSA-OAEP" } else { "RSA PKCS#1 v1.5" },
                rid.describe()),
            Recipient::KeyAgree { keys, alg, .. } => format!(
                "key agreement ({}) to {}", describe_kdf(alg),
                keys.iter().map(|(id, _)| id.describe()).collect::<Vec<_>>().join(", ")),
            Recipient::Kek { id, .. } => format!("shared key {}", asn::hex(id)),
            Recipient::Password { .. } => "password".to_string(),
            Recipient::Other(t) => format!("recipient of kind [{t}], not read here"),
        }
    }
}

fn describe_kdf(alg: &AlgId) -> String {
    kdf_scheme(alg).map(|(h, cofactor)| format!("ECDH {}, X9.63 KDF {h}",
                                               if cofactor { "cofactor" } else { "standard" }))
        .unwrap_or_else(|_| asn::dotted(&alg.oid))
}

fn read_recipient(r: &mut Reader) -> Result<Recipient, String> {
    let tag = r.peek_tag().ok_or("A RecipientInfo ends early.")?;
    if tag == Tag::sequence() {
        let mut seq = r.read_sequence()?;
        let _version = seq.read_u32()?;
        let rid = read_cert_id(&mut seq)?;
        let alg = AlgId::read(&mut seq)?;
        let encrypted_key = seq.read_octet_string()?.to_vec();
        seq.finish()?;
        return Ok(Recipient::KeyTrans { rid, alg, encrypted_key });
    }
    match tag.number {
        1 if tag.constructed => {
            let mut seq = r.read_constructed(Tag::context(1, true))?;
            if seq.read_u32()? != 3 {
                return Err("A KeyAgreeRecipientInfo of a version other than 3.".to_string());
            }
            let originator = seq.read_tagged(Tag::context(0, true))?;
            let mut o = Reader::new(originator);
            let key = o.read_constructed(Tag::context(1, true))
                .map_err(|_| "Key agreement whose originator is a certificate rather than an \
                              ephemeral key: static-static ECDH is not supported.".to_string())?;
            o.finish()?;
            let mut key = key;
            let originator_alg = AlgId::read(&mut key)?;
            let point = key.read_bit_string()?.to_vec();
            key.finish()?;
            let ukm = match seq.read_optional_context(1, true)? {
                Some(explicit) => Some(Reader::new(explicit).read_octet_string()?.to_vec()),
                None => None,
            };
            let alg = AlgId::read(&mut seq)?;
            let mut list = seq.read_sequence()?;
            seq.finish()?;
            let mut keys = Vec::new();
            while !list.is_empty() {
                let mut rek = list.read_sequence()?;
                let id = if rek.peek_tag() == Some(Tag::context(0, true)) {
                    let mut rkey = rek.read_constructed(Tag::context(0, true))?;
                    let ski = rkey.read_octet_string()?.to_vec();
                    CertId::KeyId(ski)
                } else {
                    CertId::IssuerSerial(IssuerSerial::read(&mut rek)?)
                };
                let encrypted = rek.read_octet_string()?.to_vec();
                rek.finish()?;
                keys.push((id, encrypted));
            }
            Ok(Recipient::KeyAgree { originator: point, originator_alg, ukm, alg, keys })
        }
        2 if tag.constructed => {
            let mut seq = r.read_constructed(Tag::context(2, true))?;
            if seq.read_u32()? != 4 {
                return Err("A KEKRecipientInfo of a version other than 4.".to_string());
            }
            let mut kekid = seq.read_sequence()?;
            let id = kekid.read_octet_string()?.to_vec();
            let alg = AlgId::read(&mut seq)?;
            let encrypted_key = seq.read_octet_string()?.to_vec();
            seq.finish()?;
            Ok(Recipient::Kek { id, alg, encrypted_key })
        }
        3 if tag.constructed => {
            let mut seq = r.read_constructed(Tag::context(3, true))?;
            if seq.read_u32()? != 0 {
                return Err("A PasswordRecipientInfo of a version other than 0.".to_string());
            }
            // keyDerivationAlgorithm [0] IMPLICIT AlgorithmIdentifier.
            let kdf = match seq.read_optional_context(0, true)? {
                Some(content) => {
                    let mut k = Reader::new(content);
                    let oid = k.read_oid()?.as_bytes().to_vec();
                    let params = if k.is_empty() { None } else { Some(k.read_raw()?.to_vec()) };
                    k.finish()?;
                    Some(AlgId { oid, params })
                }
                None => None,
            };
            let alg = AlgId::read(&mut seq)?;
            let encrypted_key = seq.read_octet_string()?.to_vec();
            seq.finish()?;
            Ok(Recipient::Password { kdf, alg, encrypted_key })
        }
        other => {
            r.read_raw()?;
            Ok(Recipient::Other(other as u8))
        }
    }
}

/// What to unlock a message with.
pub struct Credentials<'a> {
    pub key: Option<&'a Key>,
    pub cert: Option<&'a [u8]>,
    pub password: Option<&'a [u8]>,
    pub kek: Option<(&'a [u8], &'a [u8])>,
    pub max_iterations: u32,
}

/// The X9.63 KDF (SEC 1 3.6.1): the library's.
pub use allcrypt::kdf::nist::x963_kdf;

/// The KDF hash a key agreement scheme names, and whether it is the
/// cofactor variant - the same computation on every curve here, which
/// all have cofactor 1.
fn kdf_scheme(alg: &AlgId) -> Result<(&'static str, bool), String> {
    let table = [(asn::STD_DH_SHA1KDF, "sha1", false), (asn::STD_DH_SHA224KDF, "sha224", false),
                 (asn::STD_DH_SHA256KDF, "sha256", false), (asn::STD_DH_SHA384KDF, "sha384", false),
                 (asn::STD_DH_SHA512KDF, "sha512", false),
                 (asn::COFACTOR_DH_SHA1KDF, "sha1", true), (asn::COFACTOR_DH_SHA224KDF, "sha224", true),
                 (asn::COFACTOR_DH_SHA256KDF, "sha256", true),
                 (asn::COFACTOR_DH_SHA384KDF, "sha384", true),
                 (asn::COFACTOR_DH_SHA512KDF, "sha512", true)];
    table.iter().find(|(o, _, _)| alg.is(o)).map(|(_, h, c)| (*h, *c))
        .ok_or_else(|| format!("Key agreement scheme {} is not one this reads.",
                               asn::dotted(&alg.oid)))
}

/// The key-encryption key's length for a wrap algorithm: AES key wrap
/// (RFC 3565, parameters absent) or the CMS Triple-DES wrap (RFC 3217,
/// parameters NULL), which OpenSSL uses for an EC recipient of 3DES
/// content.
fn wrap_len(alg: &AlgId) -> Result<usize, String> {
    if alg.is(asn::DES3_WRAP) {
        return Ok(24);
    }
    let table = [(asn::AES128_WRAP, 16), (asn::AES192_WRAP, 24), (asn::AES256_WRAP, 32)];
    let len = table.iter().find(|(o, _)| alg.is(o)).map(|(_, l)| *l)
        .ok_or_else(|| format!("Key wrap {} is not one this reads.", asn::dotted(&alg.oid)))?;
    if alg.params.is_some() {
        return Err("AES key wrap with parameters (RFC 3565 says absent).".to_string());
    }
    Ok(len)
}

fn unwrap(alg: &AlgId, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    if alg.is(asn::DES3_WRAP) { des3_unwrap(kek, wrapped) }
    else { api::key_unwrap("aes", kek, wrapped) }
}

pub use allcrypt::block_ciphers::des::set_odd_parity;

/// RFC 3217's Triple-DES key wrap: the library's.
pub fn des3_wrap(kek: &[u8], cek: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    allcrypt::block_ciphers::cms_wrap::wrap_3des(kek, cek, iv)
}

pub fn des3_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    allcrypt::block_ciphers::cms_wrap::unwrap_3des(kek, wrapped)
}

fn aes_wrap_alg(len: usize) -> Result<AlgId, String> {
    Ok(AlgId::new(match len {
        16 => asn::AES128_WRAP,
        24 => asn::AES192_WRAP,
        32 => asn::AES256_WRAP,
        other => return Err(format!("No AES key wrap for a {other} byte key.")),
    }))
}

/// ECC-CMS-SharedInfo (RFC 5753 7.2): the wrap algorithm, the ukm if
/// there is one, and the key-encryption key's length in bits.
fn shared_info(wrap: &AlgId, ukm: Option<&[u8]>, kek_len: usize) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_sequence(|w| {
        wrap.write(w);
        if let Some(ukm) = ukm {
            w.write_constructed(Tag::context(0, true), |w| w.write_octet_string(ukm));
        }
        w.write_constructed(Tag::context(2, true),
                            |w| w.write_octet_string(&((kek_len * 8) as u32).to_be_bytes()));
    });
    w.finish()
}

fn curve_oid(name: &str) -> Result<&'static str, String> {
    Ok(match name {
        "P-256" => asn::PRIME256V1,
        "P-384" => asn::SECP384R1,
        "P-521" => asn::SECP521R1,
        "secp256k1" => asn::SECP256K1,
        other => return Err(format!("No curve identifier for {other}.")),
    })
}

/// RSAES-OAEP-params (RFC 4055 4.1): hash, MGF1's hash and the label.
fn oaep_params(alg: &AlgId) -> Result<(&'static str, &'static str, Vec<u8>), String> {
    let (mut hash, mut mgf, mut label) = ("sha1", "sha1", Vec::new());
    if let Some(params) = &alg.params {
        let mut r = Reader::new(params);
        let mut seq = r.read_sequence()?;
        if let Some(h) = seq.read_optional_context(0, true)? {
            hash = asn::digest_name(&AlgId::read(&mut Reader::new(h))?)?;
        }
        if let Some(m) = seq.read_optional_context(1, true)? {
            let mgf_alg = AlgId::read(&mut Reader::new(m))?;
            if !mgf_alg.is(asn::MGF1) {
                return Err("RSA-OAEP with a mask generation function other than MGF1."
                           .to_string());
            }
            mgf = asn::digest_name(&AlgId::read(&mut mgf_alg.params_reader()?)?)?;
        }
        if let Some(p) = seq.read_optional_context(2, true)? {
            let source = AlgId::read(&mut Reader::new(p))?;
            if !source.is(asn::P_SPECIFIED) {
                return Err("RSA-OAEP with a label source other than pSpecified.".to_string());
            }
            label = source.params_reader()?.read_octet_string()?.to_vec();
        }
        seq.finish()?;
    }
    Ok((hash, mgf, label))
}

fn oaep_alg(hash: &str) -> Result<AlgId, String> {
    let mut w = Writer::new();
    if hash == "sha1" {
        w.write_sequence(|_| {});
    } else {
        let hash_alg = asn::digest_alg(hash)?;
        w.write_sequence(|w| {
            w.write_constructed(Tag::context(0, true), |w| hash_alg.write(w));
            w.write_constructed(Tag::context(1, true), |w| {
                AlgId::with_params(asn::MGF1, hash_alg.to_der()).write(w);
            });
        });
    }
    Ok(AlgId::with_params(asn::RSAES_OAEP, w.finish()))
}

/// RFC 3211's password recipient wrap: the library's.
pub fn pwri_wrap(cipher: &mut AnyBlockCipher, iv: &[u8], cek: &[u8], padding: &[u8])
                 -> Result<Vec<u8>, String> {
    allcrypt::block_ciphers::cms_wrap::pwri_wrap(cipher, iv, cek, padding)
}

pub fn pwri_unwrap(cipher: &mut AnyBlockCipher, iv: &[u8], wrapped: &[u8])
                   -> Result<Vec<u8>, String> {
    allcrypt::block_ciphers::cms_wrap::pwri_unwrap(cipher, iv, wrapped)
}

/// The PBKDF2 parameters of a PasswordRecipientInfo.
struct Pbkdf2 {
    salt: Vec<u8>,
    iterations: u32,
    key_len: Option<usize>,
    prf: &'static str,
}

fn pbkdf2_params(alg: &AlgId) -> Result<Pbkdf2, String> {
    if !alg.is(asn::PBKDF2) {
        return Err(format!("Key derivation {} is not PBKDF2.", asn::dotted(&alg.oid)));
    }
    let mut r = alg.params_reader()?;
    let mut seq = r.read_sequence()?;
    let salt = seq.read_octet_string().map_err(|_| "PBKDF2 with a salt that is not an OCTET \
                                                    STRING.".to_string())?.to_vec();
    let iterations = seq.read_u32()?;
    let key_len = if seq.peek_tag() == Some(Tag::universal(allcrypt::asn1::tag::INTEGER)) {
        Some(seq.read_u32()? as usize)
    } else {
        None
    };
    let prf = if seq.is_empty() {
        "sha1"
    } else {
        let prf = AlgId::read(&mut seq)?;
        let table = [(asn::HMAC_SHA1, "sha1"), (asn::HMAC_SHA224, "sha224"),
                     (asn::HMAC_SHA256, "sha256"), (asn::HMAC_SHA384, "sha384"),
                     (asn::HMAC_SHA512, "sha512")];
        table.iter().find(|(o, _)| prf.is(o)).map(|(_, h)| *h)
            .ok_or_else(|| format!("PBKDF2 with PRF {}.", asn::dotted(&prf.oid)))?
    };
    seq.finish()?;
    Ok(Pbkdf2 { salt, iterations, key_len, prf })
}

/// Try to recover the content key from one recipient. `Ok(None)` means
/// the recipient is not for these credentials.
/// `strict` makes a PKCS#1 v1.5 failure mean "not this recipient"
/// rather than a random key: for trying recipients one by one when no
/// certificate says which is ours.
fn unlock(recipient: &Recipient, creds: &Credentials, cek_len: Option<usize>, strict: bool)
          -> Result<Option<Vec<u8>>, String> {
    let cert = creds.cert.map(Certificate::parse).transpose()?;
    let ours = |id: &CertId| cert.as_ref().is_none_or(|c| id.matches(c));
    match recipient {
        Recipient::KeyTrans { rid, alg, encrypted_key } => {
            let (Some(Key::Rsa(key)), true) = (creds.key, ours(rid)) else { return Ok(None) };
            if alg.is(asn::RSAES_OAEP) {
                let (hash, mgf, label) = oaep_params(alg)?;
                return rsa::decrypt_oaep(key, hash, mgf, &label, encrypted_key).map(Some)
                    .map_err(|_| "Decryption failed: wrong key, or the message is damaged."
                             .to_string());
            }
            if !alg.is(asn::RSA_ENCRYPTION) {
                return Err(format!("Key transport {} is not one this reads.",
                                   asn::dotted(&alg.oid)));
            }
            // RFC 3218 2.3: a padding failure carries on with a random key,
            // so it fails where a wrong key fails - at the content.
            let random = api::random_bytes(cek_len.unwrap_or(16))?;
            match rsa::decrypt_pkcs1v15(key, encrypted_key) {
                Ok(cek) => Ok(Some(cek)),
                Err(_) if strict => Ok(None),
                Err(_) => Ok(Some(random)),
            }
        }
        Recipient::KeyAgree { originator, originator_alg, ukm, alg, keys } => {
            let Some(Key::Ec { name, curve, private }) = creds.key else { return Ok(None) };
            let Some((_, encrypted)) = keys.iter().find(|(id, _)| ours(id)) else {
                return Ok(None);
            };
            // RFC 5753 3.1.1: id-ecPublicKey, its parameters absent, NULL
            // or the named curve - which must then be the recipient's.
            if !originator_alg.is(asn::EC_PUBLIC_KEY) {
                return Err("Key agreement whose ephemeral key is not an EC key.".to_string());
            }
            if !originator_alg.params_empty() {
                let named = originator_alg.params_reader()?.read_oid()?.as_bytes().to_vec();
                if named != asn::oid(curve_oid(name)?) {
                    return Err("The ephemeral key is on another curve than ours.".to_string());
                }
            }
            let (hash, _cofactor) = kdf_scheme(alg)?;
            let wrap = AlgId::read(&mut alg.params_reader()?)?;
            let kek_len = wrap_len(&wrap)?;
            let peer = curve.decode_point(originator)?;
            let z = curve.ecdh(private, &peer)?;
            let kek = x963_kdf(hash, &z, &shared_info(&wrap, ukm.as_deref(), kek_len), kek_len)?;
            unwrap(&wrap, &kek, encrypted).map(Some)
                .map_err(|_| "Decryption failed: wrong key, or the message is damaged."
                         .to_string())
        }
        Recipient::Kek { id, alg, encrypted_key } => {
            let Some((kek_id, kek)) = creds.kek else { return Ok(None) };
            if kek_id != id.as_slice() {
                return Ok(None);
            }
            if wrap_len(alg)? != kek.len() {
                return Err(format!("The key is {} bytes and the wrap algorithm wants {}.",
                                   kek.len(), wrap_len(alg)?));
            }
            unwrap(alg, kek, encrypted_key).map(Some)
                .map_err(|_| "Wrong key-encryption key, or the message is damaged.".to_string())
        }
        Recipient::Password { kdf, alg, encrypted_key } => {
            let Some(password) = creds.password else { return Ok(None) };
            let kdf = kdf.as_ref().ok_or("A password recipient without its key derivation.")?;
            let Pbkdf2 { salt, iterations, key_len, prf } = pbkdf2_params(kdf)?;
            if iterations > creds.max_iterations {
                return Err(format!("The message asks for {iterations} PBKDF2 iterations, \
                                    more than the {} allowed (--max-iterations).",
                                   creds.max_iterations));
            }
            if !alg.is(asn::PWRI_KEK) {
                return Err(format!("Password key encryption {} is not id-alg-PWRI-KEK.",
                                   asn::dotted(&alg.oid)));
            }
            let kek_alg = AlgId::read(&mut alg.params_reader()?)?;
            let kek_cipher = ContentCipher::read(&kek_alg)?;
            let ContentCipher::Cbc { iv, .. } = &kek_cipher else {
                return Err("PWRI-KEK with a cipher that is not CBC.".to_string());
            };
            // An RC2 KEK's length comes from PBKDF2's keyLength, or - as
            // OpenSSL reads its own - from the effective key bits.
            let rc2_len = match &kek_cipher {
                ContentCipher::Cbc { rc2_bits: Some(bits), .. } => Some(bits / 8),
                _ => None,
            };
            let len = kek_cipher.key_len().or(key_len).or(rc2_len).unwrap_or(16);
            if key_len.is_some_and(|k| k != len) {
                return Err("PBKDF2's key length is not the KEK cipher's.".to_string());
            }
            let kek = api::pbkdf2(prf, password, &salt, iterations, len)?;
            let mut block = kek_cipher.block(&kek)?;
            pwri_unwrap(&mut block, iv, encrypted_key).map(Some)
        }
        Recipient::Other(_) => Ok(None),
    }
}

// ---------------------------------------------------------------- messages --

pub struct Enveloped {
    pub auth: bool,
    pub recipients: Vec<Recipient>,
    pub content_type: Vec<u8>,
    pub cipher_alg: AlgId,
    pub encrypted: Vec<u8>,
    /// The `authAttrs [1]` content and the MAC, for AuthEnvelopedData.
    pub auth_attrs: Option<Vec<u8>>,
    pub mac: Option<Vec<u8>>,
}

fn read_encrypted_content_info(r: &mut Reader)
                               -> Result<(Vec<u8>, AlgId, Vec<u8>), String> {
    let mut eci = r.read_sequence()?;
    let content_type = eci.read_oid()?.as_bytes().to_vec();
    let alg = AlgId::read(&mut eci)?;
    let encrypted = match eci.peek_tag() {
        None => return Err("The encrypted content is not in the message.".to_string()),
        Some(t) if t.class == allcrypt::asn1::CLASS_CONTEXT && t.number == 0 => {
            let (t, content) = eci.read_any()?;
            asn::string_pieces(if t.constructed { 0x20 } else { 0 }, content)?
        }
        Some(_) => return Err("encryptedContent with the wrong tag.".to_string()),
    };
    eci.finish()?;
    Ok((content_type, alg, encrypted))
}

pub fn parse(der: &[u8], auth: bool) -> Result<Enveloped, String> {
    let mut r = Reader::new(der);
    let mut seq = r.read_sequence()?;
    r.finish()?;
    seq.read_u32()?;
    seq.read_optional_context(0, true)?; // originatorInfo
    let mut set = seq.read_set()?;
    let mut recipients = Vec::new();
    while !set.is_empty() {
        recipients.push(read_recipient(&mut set)?);
    }
    let (content_type, cipher_alg, encrypted) = read_encrypted_content_info(&mut seq)?;
    let (auth_attrs, mac) = if auth {
        let attrs = seq.read_optional_context(1, true)?.map(<[u8]>::to_vec);
        let mac = seq.read_octet_string()?.to_vec();
        seq.read_optional_context(2, true)?;
        (attrs, Some(mac))
    } else {
        seq.read_optional_context(1, true)?;
        (None, None)
    };
    seq.finish()?;
    Ok(Enveloped { auth, recipients, content_type, cipher_alg, encrypted, auth_attrs, mac })
}

impl Enveloped {
    /// The content: the content key from the first recipient these
    /// credentials open, then the content under it.
    pub fn decrypt(&self, creds: &Credentials) -> Result<Vec<u8>, String> {
        let cipher = ContentCipher::read(&self.cipher_alg)?;
        if self.auth != matches!(cipher, ContentCipher::Gcm { .. }) {
            return Err(if self.auth { "AuthEnvelopedData with a cipher that does not \
                                       authenticate." } else { "AES-GCM in EnvelopedData, \
                                       which has nowhere for its MAC." }.to_string());
        }
        // With an RSA key and no certificate to say which recipient is
        // ours, every key transport recipient is tried strictly first: a
        // wrong key's random content key decrypts to valid padding about
        // once in 256, which would be taken for the content. Only when
        // none decrypts does the RFC 3218 random key take over, so that
        // the failure still looks like any other.
        let strict_first = creds.cert.is_none() && matches!(creds.key, Some(Key::Rsa(_)));
        let mut order: Vec<(&Recipient, bool)> = Vec::new();
        if strict_first {
            order.extend(self.recipients.iter().filter(|r| matches!(r, Recipient::KeyTrans { .. }))
                         .map(|r| (r, true)));
        }
        order.extend(self.recipients.iter().map(|r| (r, false)));
        let mut tried_random = false;
        let mut last_error = None;
        for (recipient, strict) in order {
            let random_fallback = !strict && strict_first
                && matches!(recipient, Recipient::KeyTrans { .. });
            if random_fallback {
                // One random-key attempt is enough to fail like a wrong key.
                if tried_random {
                    continue;
                }
                tried_random = true;
            }
            match unlock(recipient, creds, cipher.key_len(), strict) {
                Ok(Some(cek)) => {
                    let aad = match &self.auth_attrs {
                        Some(attrs) => {
                            let mut w = Writer::new();
                            w.write_tlv(Tag::set(), attrs);
                            w.finish()
                        }
                        None => Vec::new(),
                    };
                    match cipher.decrypt(&cek, &self.encrypted, &aad, self.mac.as_deref()) {
                        Ok(plain) => return Ok(plain),
                        Err(e) => last_error = Some(e),
                    }
                }
                Ok(None) => {}
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| "None of the recipients is for the key, password or \
                                           key-encryption key given.".to_string()))
    }
}

/// Who to encrypt to.
pub enum RecipientSpec {
    Certificate { der: Vec<u8>, oaep: Option<String>, key_id: bool, kdf_hash: String },
    Password { password: Vec<u8>, iterations: u32, prf: String },
    Kek { id: Vec<u8>, key: Vec<u8> },
}

fn write_recipient(spec: &RecipientSpec, cek: &[u8], content: &ContentCipher)
                   -> Result<(Vec<u8>, u32), String> {
    let mut w = Writer::new();
    let version;
    match spec {
        RecipientSpec::Certificate { der, oaep, key_id, kdf_hash } => {
            let cert = Certificate::parse(der)?;
            let rid = if *key_id {
                CertId::KeyId(cert.extensions.subject_key_id
                    .ok_or("--keyid needs certificates with a subject key identifier.")?
                    .to_vec())
            } else {
                CertId::IssuerSerial(IssuerSerial::of(&cert))
            };
            match &cert.public_key {
                PublicKey::Rsa { n, e } => {
                    let key = RsaPublicKey::new(n.clone(), e.clone())?;
                    let (alg, encrypted) = match oaep {
                        Some(hash) => (oaep_alg(hash)?,
                                       rsa::encrypt_oaep(&key, hash, hash, &[], cek)?),
                        None => (AlgId::with_null(asn::RSA_ENCRYPTION),
                                 rsa::encrypt_pkcs1v15(&key, cek)?),
                    };
                    version = if *key_id { 2 } else { 0 };
                    w.write_sequence(|w| {
                        w.write_u32(version);
                        write_cert_id(w, &rid);
                        alg.write(w);
                        w.write_octet_string(&encrypted);
                    });
                }
                PublicKey::Ec { curve: name, point } => {
                    let curve = curves::by_name(name)?;
                    let peer = curve.decode_point(point)?;
                    let (ephemeral, ephemeral_point) = curve.generate_key_pair()?;
                    let z = curve.ecdh(&ephemeral, &peer)?;
                    // The wrap follows the content cipher, as OpenSSL
                    // chooses it: AES of the same size, the CMS
                    // Triple-DES wrap for 3DES, AES-256 otherwise.
                    let triple_des = matches!(content, ContentCipher::Cbc { cipher: "3des", .. });
                    let kek_len = match content.key_len() {
                        Some(len @ (16 | 24)) if matches!(content,
                            ContentCipher::Cbc { cipher: "aes", .. } | ContentCipher::Gcm { .. })
                            => len,
                        _ if triple_des => 24,
                        _ => 32,
                    };
                    let wrap = if triple_des { AlgId::with_null(asn::DES3_WRAP) }
                               else { aes_wrap_alg(kek_len)? };
                    let kek = x963_kdf(kdf_hash, &z, &shared_info(&wrap, None, kek_len),
                                       kek_len)?;
                    if !triple_des && (cek.len() < 16 || !cek.len().is_multiple_of(8)) {
                        return Err(format!("A {} byte content key cannot be AES-key-wrapped \
                                            for an EC recipient; choose another cipher.",
                                           cek.len()));
                    }
                    let encrypted = if triple_des {
                        des3_wrap(&kek, cek, &api::random_bytes(8)?)?
                    } else {
                        api::key_wrap("aes", &kek, cek)?
                    };
                    let scheme = match kdf_hash.as_str() {
                        "sha1" => asn::STD_DH_SHA1KDF, "sha224" => asn::STD_DH_SHA224KDF,
                        "sha256" => asn::STD_DH_SHA256KDF, "sha384" => asn::STD_DH_SHA384KDF,
                        "sha512" => asn::STD_DH_SHA512KDF,
                        other => return Err(format!("No ECDH scheme with an X9.63 KDF over \
                                                     {other}.")),
                    };
                    let curve_id = asn::oid(curve_oid(name)?);
                    let encoded = curve.encode_point(&ephemeral_point, false)?;
                    version = 3;
                    w.write_constructed(Tag::context(1, true), |w| {
                        w.write_u32(3);
                        w.write_constructed(Tag::context(0, true), |w| {
                            w.write_constructed(Tag::context(1, true), |w| {
                                let mut params = Writer::new();
                                params.write_oid(&curve_id);
                                AlgId::with_params(asn::EC_PUBLIC_KEY, params.finish()).write(w);
                                w.write_bit_string(&encoded);
                            });
                        });
                        AlgId::with_params(scheme, wrap.to_der()).write(w);
                        w.write_sequence(|w| {
                            w.write_sequence(|w| {
                                match &rid {
                                    CertId::IssuerSerial(is) => is.write(w),
                                    CertId::KeyId(id) => w.write_constructed(
                                        Tag::context(0, true), |w| w.write_octet_string(id)),
                                }
                                w.write_octet_string(&encrypted);
                            });
                        });
                    });
                }
                _ => return Err(format!("{}: only RSA and EC certificates can be encrypted \
                                         to.", cert.subject)),
            }
        }
        RecipientSpec::Kek { id, key } => {
            let alg = aes_wrap_alg(key.len())?;
            if cek.len() < 16 || !cek.len().is_multiple_of(8) {
                return Err(format!("A {} byte content key cannot be AES-key-wrapped; choose \
                                    another cipher.", cek.len()));
            }
            let encrypted = api::key_wrap("aes", key, cek)?;
            version = 4;
            w.write_constructed(Tag::context(2, true), |w| {
                w.write_u32(4);
                w.write_sequence(|w| w.write_octet_string(id));
                alg.write(w);
                w.write_octet_string(&encrypted);
            });
        }
        RecipientSpec::Password { password, iterations, prf } => {
            // The KEK cipher is the content cipher when that is CBC,
            // AES-256-CBC otherwise.
            let (kek_cipher, kek_alg) = match content {
                ContentCipher::Cbc { cipher, key_len, rc2_bits, .. } => {
                    let name = match (*cipher, key_len, rc2_bits) {
                        ("aes", Some(16), _) => "aes-128-cbc",
                        ("aes", Some(24), _) => "aes-192-cbc",
                        ("3des", _, _) => "des-ede3-cbc",
                        ("des", _, _) => "des-cbc",
                        ("rc2", _, Some(40)) => "rc2-40-cbc",
                        ("rc2", _, Some(64)) => "rc2-64-cbc",
                        ("rc2", _, _) => "rc2-128-cbc",
                        _ => "aes-256-cbc",
                    };
                    ContentCipher::named(name)?
                }
                ContentCipher::Gcm { .. } => ContentCipher::named("aes-256-cbc")?,
            };
            let salt = api::random_bytes(16)?;
            let len = kek_cipher.key_len().unwrap_or(16);
            let kek = api::pbkdf2(prf, password, &salt, *iterations, len)?;
            let ContentCipher::Cbc { iv, .. } = &kek_cipher else { unreachable!() };
            let mut block = kek_cipher.block(&kek)?;
            let encrypted = pwri_wrap(&mut block, iv, cek, &api::random_bytes(64)?)?;
            let prf_oid = match prf.as_str() {
                "sha1" => asn::HMAC_SHA1, "sha224" => asn::HMAC_SHA224,
                "sha256" => asn::HMAC_SHA256, "sha384" => asn::HMAC_SHA384,
                "sha512" => asn::HMAC_SHA512,
                other => return Err(format!("No HMAC identifier for {other}.")),
            };
            // An RC2 key's length is not in its AlgorithmIdentifier, so
            // PBKDF2 says it; a reader without it would take 16 bytes.
            let rc2 = matches!(kek_cipher, ContentCipher::Cbc { cipher: "rc2", .. });
            let mut params = Writer::new();
            params.write_sequence(|w| {
                w.write_octet_string(&salt);
                w.write_u32(*iterations);
                if rc2 {
                    w.write_u32(len as u32);
                }
                if prf != "sha1" {
                    AlgId::new(prf_oid).write(w);
                }
            });
            let params = params.finish();
            version = 3;
            w.write_constructed(Tag::context(3, true), |w| {
                w.write_u32(0);
                w.write_constructed(Tag::context(0, true), |w| {
                    w.write_oid(&asn::oid(asn::PBKDF2));
                    w.write_raw(&params);
                });
                AlgId::with_params(asn::PWRI_KEK, kek_alg.to_der()).write(w);
                w.write_octet_string(&encrypted);
            });
        }
    }
    Ok((w.finish(), version))
}

/// An EnvelopedData - or, for AES-GCM, an AuthEnvelopedData -
/// ContentInfo of `content` for `recipients`.
pub fn encrypt(content: &[u8], recipients: &[RecipientSpec], cipher_name: &str)
               -> Result<Vec<u8>, String> {
    if recipients.is_empty() {
        return Err("Encrypting needs at least one recipient.".to_string());
    }
    let (cipher, cipher_alg) = ContentCipher::named(cipher_name)?;
    let mut cek = api::random_bytes(cipher.key_len().unwrap_or(16))?;
    if matches!(cipher, ContentCipher::Cbc { cipher: "3des" | "des", .. }) {
        set_odd_parity(&mut cek);
    }
    let mut infos = Vec::new();
    let mut versions = Vec::new();
    for spec in recipients {
        let (info, version) = write_recipient(spec, &cek, &cipher)?;
        infos.push(info);
        versions.push(version);
    }
    let (encrypted, tag) = cipher.encrypt(&cek, content, &[])?;
    let auth = tag.is_some();
    // RFC 5652 6.1: 3 with a password recipient, 0 when every recipient
    // is version 0, 2 otherwise. AuthEnvelopedData is always 0.
    let has_pwri = recipients.iter().any(|r| matches!(r, RecipientSpec::Password { .. }));
    let version = if auth { 0 } else if has_pwri { 3 }
                  else if versions.iter().all(|&v| v == 0) { 0 } else { 2 };
    let mut body = Writer::new();
    body.write_sequence(|w| {
        w.write_u32(version);
        w.write_raw(&asn::der_set_of(infos, 0x31));
        w.write_sequence(|w| {
            w.write_oid(&asn::oid(asn::DATA));
            cipher_alg.write(w);
            w.write_tlv(Tag::context(0, false), &encrypted);
        });
        if let Some(tag) = &tag {
            w.write_octet_string(tag);
        }
    });
    Ok(content_info(if auth { asn::AUTH_ENVELOPED_DATA } else { asn::ENVELOPED_DATA },
                    &body.finish()))
}

/// EncryptedData: content under a key the parties already share.
pub fn encrypt_with_key(content: &[u8], key: &[u8], cipher_name: &str) -> Result<Vec<u8>, String> {
    let (cipher, alg) = ContentCipher::named(cipher_name)?;
    if matches!(cipher, ContentCipher::Gcm { .. }) {
        return Err("EncryptedData has nowhere for a MAC: use a CBC cipher.".to_string());
    }
    if cipher.key_len().is_some_and(|l| l != key.len()) {
        return Err(format!("{cipher_name} takes a {} byte key.", cipher.key_len().unwrap_or(0)));
    }
    let (encrypted, _) = cipher.encrypt(key, content, &[])?;
    let mut body = Writer::new();
    body.write_sequence(|w| {
        w.write_u32(0);
        w.write_sequence(|w| {
            w.write_oid(&asn::oid(asn::DATA));
            alg.write(w);
            w.write_tlv(Tag::context(0, false), &encrypted);
        });
    });
    Ok(content_info(asn::ENCRYPTED_DATA, &body.finish()))
}

pub fn decrypt_with_key(der: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut r = Reader::new(der);
    let mut seq = r.read_sequence()?;
    r.finish()?;
    seq.read_u32()?;
    let (content_type, alg, encrypted) = read_encrypted_content_info(&mut seq)?;
    seq.read_optional_context(1, true)?;
    seq.finish()?;
    let cipher = ContentCipher::read(&alg)?;
    if matches!(cipher, ContentCipher::Gcm { .. }) {
        return Err("AES-GCM in EncryptedData, which has nowhere for its MAC.".to_string());
    }
    Ok((content_type, cipher.decrypt(key, &encrypted, &[], None)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `len` bytes of hex after `label` in an RFC: groups of hex digits
    /// on its line and the lines after, each of which may start with a
    /// label of its own ("pass output:") that is skipped.
    fn hex_bytes(text: &str, label: &str, len: usize) -> Vec<u8> {
        let start = text.find(label).unwrap_or_else(|| panic!("{label} not found"));
        let mut digits = String::new();
        for line in text[start + label.len()..].lines() {
            let line = line.rsplit_once(':').map_or(line, |(_, rest)| rest);
            for group in line.split_whitespace() {
                if group.len() % 2 == 1 || !group.chars().all(|c| c.is_ascii_hexdigit()) {
                    break;
                }
                digits.push_str(group);
            }
            if digits.len() >= 2 * len {
                break;
            }
        }
        assert_eq!(digits.len(), 2 * len, "{label}");
        (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap())
            .collect()
    }

    fn rfc(name: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rfcs").join(name)).unwrap()
    }

    /// RFC 3217 3.4's example, read out of the document.
    #[test]
    fn test_rfc_3217_triple_des_key_wrap() {
        let text = rfc("rfc3217.txt");
        let example = &text[text.find("3.4  Triple-DES Key Wrap Example").unwrap()..];
        let cek = hex_bytes(example, "CEK:", 24);
        let kek = hex_bytes(example, "KEK:", 24);
        let iv = hex_bytes(example, "IV:", 8);
        let result = hex_bytes(example, "RESULT:", 40);
        assert_eq!(des3_wrap(&kek, &cek, &iv).unwrap(), result);
        assert_eq!(des3_unwrap(&kek, &result).unwrap(), cek);
        let mut damaged = result.clone();
        damaged[20] ^= 1;
        assert!(des3_unwrap(&kek, &damaged).is_err());
    }

    /// RFC 3211 section 3's two vectors, read out of the document:
    /// PBKDF2, then the double CBC wrap with the padding the document
    /// used, and the unwrap back.
    #[test]
    fn test_rfc_3211_password_recipient_vectors() {
        let text = rfc("rfc3211.txt");
        let vectors = &text[text.find("3. Test Vectors").unwrap()..];
        let second = vectors.find("using a triple DES-CBC key derived").unwrap();
        let cases = [(&vectors[..second], "des", &b"password"[..], 5, 8, 8),
                     (&vectors[second..], "3des",
                      &b"All n-entities must communicate with other n-entities via n-1 \
                         entiteeheehees"[..], 500, 24, 32)];
        for (section, cipher, password, iterations, key_len, cek_len) in cases {
            let salt = hex_bytes(section, "salt:", 8);
            let key = api::pbkdf2("sha1", password, &salt, iterations, key_len).unwrap();
            let label = if cipher == "des" { "output key:" } else { "output" };
            assert_eq!(key, hex_bytes(section, label, key_len), "{cipher}");
            let formatting = &section[section.find("CEK formatting phase").unwrap()..];
            let cek = hex_bytes(formatting, "CEK:", cek_len);
            let padding = hex_bytes(formatting, "padding:", 4);
            let iv = hex_bytes(section, "IV:", 8);
            let wrapped_len = (4 + cek_len + 4).max(16);
            let wrapped = hex_bytes(section, "second encr.", wrapped_len);
            let mut block = AnyBlockCipher::new(cipher, &key, None).unwrap();
            assert_eq!(pwri_wrap(&mut block, &iv, &cek, &padding).unwrap(), wrapped, "{cipher}");
            assert_eq!(pwri_unwrap(&mut block, &iv, &wrapped).unwrap(), cek, "{cipher}");
            // A wrong key fails the length and check bytes. They cover
            // the length and three bytes of the key and nothing else, so
            // a damaged wrap can come back as a different key; then the
            // content's padding is what refuses it.
            let mut other = AnyBlockCipher::new(cipher, &vec![0x5a; key_len], None).unwrap();
            assert!(pwri_unwrap(&mut other, &iv, &wrapped).is_err(), "{cipher}");
        }
        // The known answer: DES under the derived key, of a zero block.
        let key = api::pbkdf2("sha1", b"password", &hex_bytes(vectors, "salt:", 8), 5, 8).unwrap();
        let mut des = AnyBlockCipher::new("des", &key, None).unwrap();
        let mut out = Vec::new();
        des.block_encrypt(&[0; 8], &mut out);
        assert_eq!(out, hex_bytes(vectors, "known answer:", 8));
    }

    /// The MAC must be as long as the parameters say: GCM checks any
    /// tag from 12 bytes up, so a shortened one would otherwise pass.
    #[test]
    fn test_a_shortened_gcm_tag_is_refused() {
        let cipher = ContentCipher::Gcm { key_len: 16, nonce: vec![1; 12], tag_len: 16 };
        let (sealed, tag) = cipher.encrypt(&[2; 16], b"content", b"").unwrap();
        let tag = tag.unwrap();
        assert!(cipher.decrypt(&[2; 16], &sealed, b"", Some(&tag)).is_ok());
        let error = cipher.decrypt(&[2; 16], &sealed, b"", Some(&tag[..12])).unwrap_err();
        assert!(error.contains("where the parameters say 16"), "{error}");
    }

    /// RFC 5084: an AES-GCM ICV length left out means 12.
    #[test]
    fn test_gcm_icv_length_defaults_to_12() {
        let mut w = Writer::new();
        w.write_sequence(|w| w.write_octet_string(&[1; 12]));
        let cipher = ContentCipher::read(&AlgId::with_params(asn::AES128_GCM, w.finish()))
            .unwrap();
        assert!(matches!(cipher, ContentCipher::Gcm { tag_len: 12, .. }));
    }

    /// CBC under `cipher` twice, the second pass chained on from the
    /// first, as RFC 3211 wraps - for formatted blocks pwri_wrap would
    /// not make.
    fn double_cbc(cipher: &mut AnyBlockCipher, iv: &[u8], formatted: &[u8]) -> Vec<u8> {
        let block = cipher.blocksize();
        let mut first = Vec::new();
        cipher.cbc_encrypt(formatted, &mut first, iv).unwrap();
        let mut second = Vec::new();
        cipher.cbc_encrypt(&first, &mut second, &first[first.len() - block..]).unwrap();
        second
    }

    /// The length byte and the check bytes are each enough to refuse: a
    /// right check with an impossible length, and a possible length with
    /// a wrong check.
    #[test]
    fn test_pwri_length_and_check_are_each_checked() {
        let mut cipher = AnyBlockCipher::new("aes", &[3; 16], None).unwrap();
        let iv = [4u8; 16];
        let cek = [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let good = [&[8, !0x10, !0x20, !0x30][..], &cek, &[0; 20]].concat();
        let wrapped = double_cbc(&mut cipher, &iv, &good);
        assert_eq!(pwri_unwrap(&mut cipher, &iv, &wrapped).unwrap(), cek);
        for (len, check0) in [(2u8, !0x10u8), (29, !0x10), (200, !0x10), (8, 0x10)] {
            let mut formatted = good.clone();
            formatted[0] = len;
            formatted[1] = check0;
            let wrapped = double_cbc(&mut cipher, &iv, &formatted);
            assert!(pwri_unwrap(&mut cipher, &iv, &wrapped).is_err(), "{len} {check0:#x}");
        }
    }

    /// An RC2 key-encryption key's length is written into PBKDF2's
    /// parameters: nothing else in the message says it.
    #[test]
    fn test_an_rc2_kek_length_is_written() {
        let spec = RecipientSpec::Password { password: b"pw".to_vec(), iterations: 1,
                                             prf: "sha256".into() };
        let (cipher, _) = ContentCipher::named("rc2-40-cbc").unwrap();
        let (info, _) = write_recipient(&spec, &[1, 2, 3, 4, 5], &cipher).unwrap();
        let Recipient::Password { kdf: Some(kdf), .. } = read_recipient(&mut Reader::new(&info))
            .unwrap() else { panic!("not a password recipient") };
        assert_eq!(pbkdf2_params(&kdf).unwrap().key_len, Some(5));
    }

    /// An ephemeral key must be an EC key on the recipient's curve, and
    /// say so in its algorithm identifier.
    #[test]
    fn test_the_ephemeral_key_is_checked() {
        let fixture = |name: &str| std::fs::read(crate::fixtures::dir().join("cms").join(name))
            .unwrap();
        let cert = crate::keys::certificates(&fixture("ec.crt")).unwrap().remove(0);
        let key = Key::from_private(allcrypt::x509::private_key::parse(&fixture("ec.key"))
            .unwrap()).unwrap();
        let spec = RecipientSpec::Certificate { der: cert, oaep: None, key_id: false,
                                                kdf_hash: "sha256".into() };
        let der = encrypt(b"x", &[spec], "aes-128-cbc").unwrap();
        let mut r = Reader::new(&der);
        let mut ci = r.read_sequence().unwrap();
        ci.read_oid().unwrap();
        let body = Reader::new(ci.read_tagged(Tag::context(0, true)).unwrap()).read_raw()
            .unwrap().to_vec();
        let creds = Credentials { key: Some(&key), cert: None, password: None, kek: None,
                                  max_iterations: 0 };
        let env = parse(&body, false).unwrap();
        assert_eq!(env.decrypt(&creds).unwrap(), b"x");
        for (alg, why) in [(AlgId::with_null(asn::RSA_ENCRYPTION), "not an EC key"),
                           (AlgId::with_params(asn::EC_PUBLIC_KEY,
                                               vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
                            "another curve")] {
            let mut changed = parse(&body, false).unwrap();
            let Recipient::KeyAgree { originator_alg, .. } = &mut changed.recipients[0] else {
                panic!("not key agreement");
            };
            *originator_alg = alg;
            let error = changed.decrypt(&creds).unwrap_err();
            assert!(error.contains(why), "{error}");
        }
    }

    #[test]
    fn test_odd_parity() {
        let mut key = [0x00, 0x01, 0x28, 0x29, 0xfe, 0xff];
        set_odd_parity(&mut key);
        assert_eq!(key, [0x01, 0x01, 0x29, 0x29, 0xfe, 0xfe]);
    }
}
