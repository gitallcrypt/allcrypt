//! Encrypted Office Open XML documents ([MS-OFFCRYPTO] 2.3.4): a
//! `.docx`, `.xlsx` or `.pptx` - a ZIP package - encrypted whole and
//! stored as the `EncryptedPackage` stream of a compound file, with an
//! `EncryptionInfo` stream that says how.
//!
//! Two of the three ways are here:
//!
//! - **Standard** (Office 2007; LibreOffice still writes it): AES-128,
//!   192 or 256 in ECB over the whole package, under a key from
//!   SHA-1 iterated 50,000 times over a salt and the password, then
//!   stretched with CryptoAPI's `CryptDeriveKey` construction. A
//!   16-byte verifier and its SHA-1 hash, both encrypted, check the
//!   password. Nothing authenticates the package.
//! - **Agile** (Office 2010 on): the package in 4096-byte segments,
//!   each in CBC under its own IV - the hash of the key-data salt and
//!   the segment number. The key is random, and is stored encrypted
//!   under a key from the password (100,000 hashes by default, SHA-512
//!   from Office 2013); the verifier works the same way, and an HMAC
//!   over the encrypted stream, its key and value encrypted too, guards
//!   the package against change.
//!
//! The third, extensible encryption (a third-party cryptographic
//! provider), names code that is not here and is refused.
//!
//! The 8-byte block keys that separate the agile derivations are taken
//! from msoffcrypto-tool's `ecma376_agile.py`, which quotes the
//! specification; every Office-written fixture depends on each one.

use allcrypt::api::{AnyBlockCipher, AnyHash};
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::hash_functions::HashFunction;

use crate::base64;
use crate::cfb::{self, Storage};
use crate::xml::{self, Element};

const VERIFIER_HASH_INPUT: [u8; 8] = [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
const VERIFIER_HASH_VALUE: [u8; 8] = [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];
const KEY_VALUE: [u8; 8] = [0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6];
const INTEGRITY_KEY: [u8; 8] = [0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6];
const INTEGRITY_VALUE: [u8; 8] = [0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33];
const SEGMENT: usize = 4096;
const STANDARD_SPIN: u32 = 50_000;

/// The password as Office hashes it: UTF-16, little endian.
pub fn utf16(password: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(password).map_err(|_| "The password is not UTF-8.")?;
    Ok(text.encode_utf16().flat_map(u16::to_le_bytes).collect())
}

fn hash_name(name: &str) -> Result<&'static str, String> {
    match name {
        "SHA1" => Ok("sha1"),
        "SHA256" => Ok("sha256"),
        "SHA384" => Ok("sha384"),
        "SHA512" => Ok("sha512"),
        "MD5" => Ok("md5"),
        "MD4" => Ok("md4"),
        "MD2" => Ok("md2"),
        "RIPEMD-160" => Ok("ripemd160"),
        "WHIRLPOOL" => Ok("whirlpool"),
        other => Err(format!("Hash algorithm {other} is not supported.")),
    }
}

fn digest(hash: &str, parts: &[&[u8]]) -> Result<Vec<u8>, String> {
    let mut h = AnyHash::new(hash)?;
    for part in parts {
        h.update(part);
    }
    Ok(h.digest())
}

/// Cut to `length`, or pad with 0x36 to it ([MS-OFFCRYPTO] 2.3.4.11
/// and 2.3.4.12).
fn fit(mut bytes: Vec<u8>, length: usize) -> Vec<u8> {
    bytes.resize(length, 0x36);
    bytes
}

fn cbc(key: &[u8], iv: &[u8], data: &[u8], decrypt: bool) -> Result<Vec<u8>, String> {
    let mut cipher = AnyBlockCipher::new("aes", key, None)?;
    let mut out = Vec::with_capacity(data.len());
    if decrypt {
        cipher.cbc_decrypt(data, &mut out, iv.to_vec())?;
    } else {
        cipher.cbc_encrypt(data, &mut out, iv.to_vec())?;
    }
    Ok(out)
}

fn ecb(key: &[u8], data: &[u8], decrypt: bool) -> Result<Vec<u8>, String> {
    let mut cipher = AnyBlockCipher::new("aes", key, None)?;
    let mut out = Vec::with_capacity(data.len());
    if decrypt {
        cipher.ecb_decrypt(data, &mut out)?;
    } else {
        cipher.ecb_encrypt(data, &mut out)?;
    }
    Ok(out)
}

fn zero_pad(data: &[u8], block: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out.resize(data.len().div_ceil(block) * block, 0);
    out
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))
        .ok_or("EncryptionInfo is truncated.".to_string())
}

/// The iterated password hash both methods start from: H(salt ||
/// password), then H(i || previous) for each i below the spin count.
fn spun(hash: &str, salt: &[u8], password: &[u8], spin: u32) -> Result<Vec<u8>, String> {
    let mut h = digest(hash, &[salt, password])?;
    for i in 0..spin {
        h = digest(hash, &[&i.to_le_bytes(), &h])?;
    }
    Ok(h)
}

// ------------------------------------------------------------- standard --

#[derive(Clone, Debug)]
pub struct Standard {
    pub version: (u16, u16),
    pub flags: u32,
    pub header_flags: u32,
    pub alg_id: u32,
    pub alg_id_hash: u32,
    pub key_bits: u32,
    pub provider_type: u32,
    pub csp_name: String,
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
    pub verifier_hash_size: u32,
    pub verifier_hash: Vec<u8>,
}

impl Standard {
    fn parse(version: (u16, u16), data: &[u8]) -> Result<Standard, String> {
        let flags = u32_at(data, 4)?;
        let header_size = u32_at(data, 8)? as usize;
        let header = data.get(12..12 + header_size).ok_or("EncryptionInfo is truncated.")?;
        let alg_id = u32_at(header, 8)?;
        let alg_id_hash = u32_at(header, 12)?;
        let key_bits = u32_at(header, 16)?;
        let units: Vec<u16> = header.get(32..).unwrap_or(&[]).chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
        let verifier = &data[12 + header_size..];
        let salt_size = u32_at(verifier, 0)? as usize;
        if salt_size != 16 {
            return Err(format!("A verifier salt of {salt_size} bytes; the format has 16."));
        }
        let take = |at: usize, n: usize| verifier.get(at..at + n).map(<[u8]>::to_vec)
            .ok_or("The encryption verifier is truncated.".to_string());
        let verifier_hash_size = u32_at(verifier, 36)?;
        Ok(Standard {
            version,
            flags,
            header_flags: u32_at(header, 0)?,
            alg_id,
            alg_id_hash,
            key_bits,
            provider_type: u32_at(header, 20)?,
            csp_name: String::from_utf16_lossy(&units),
            salt: take(4, 16)?,
            verifier: take(20, 16)?,
            verifier_hash_size,
            // SHA-1's 20 bytes, encrypted in whole AES blocks.
            verifier_hash: take(40, verifier.len().saturating_sub(40).min(32))?,
        })
    }

    fn key_bytes(&self) -> Result<usize, String> {
        match (self.alg_id, self.key_bits) {
            (0x660e, 128) | (0x660f, 192) | (0x6610, 256) => Ok(self.key_bits as usize / 8),
            // A zero AlgID means AES-128 when the flags say AES.
            (0, 128) if self.flags & 0x20 != 0 => Ok(16),
            (alg, bits) => Err(format!("Standard encryption with AlgID {alg:#x} and {bits} \
                                        bits; only AES is defined for it.")),
        }
    }

    /// [MS-OFFCRYPTO] 2.3.4.7: the iterated SHA-1, then CryptDeriveKey's
    /// two hashes of the result XORed into 0x36 and 0x5c buffers.
    pub fn key(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        if self.alg_id_hash != 0x8004 && self.alg_id_hash != 0 {
            return Err(format!("Standard encryption with hash AlgID {:#x}; it is SHA-1.",
                               self.alg_id_hash));
        }
        let h = spun("sha1", &self.salt, password, STANDARD_SPIN)?;
        let h_final = digest("sha1", &[&h, &0u32.to_le_bytes()])?;
        let mut x1 = [0x36u8; 64];
        let mut x2 = [0x5cu8; 64];
        for (i, b) in h_final.iter().enumerate() {
            x1[i] ^= b;
            x2[i] ^= b;
        }
        let mut derived = digest("sha1", &[&x1])?;
        derived.extend(digest("sha1", &[&x2])?);
        derived.truncate(self.key_bytes()?);
        Ok(derived)
    }

    pub fn verify(&self, key: &[u8]) -> Result<bool, String> {
        let verifier = ecb(key, &self.verifier, true)?;
        let hash = ecb(key, &self.verifier_hash, true)?;
        Ok(hash.get(..20) == Some(&digest("sha1", &[&verifier])?[..]))
    }

    fn write(&self) -> Vec<u8> {
        let mut header = Vec::new();
        for value in [self.header_flags, 0, self.alg_id, self.alg_id_hash, self.key_bits,
                      self.provider_type, 0, 0] {
            header.extend_from_slice(&value.to_le_bytes());
        }
        header.extend(self.csp_name.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.0.to_le_bytes());
        out.extend_from_slice(&self.version.1.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend(header);
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.verifier);
        out.extend_from_slice(&self.verifier_hash_size.to_le_bytes());
        out.extend_from_slice(&self.verifier_hash);
        out
    }

    /// New parameters for AES with `key_bits`, and the key.
    pub fn create(password: &[u8], key_bits: u32) -> Result<(Standard, Vec<u8>), String> {
        let alg_id = match key_bits {
            128 => 0x660e,
            192 => 0x660f,
            256 => 0x6610,
            other => return Err(format!("AES-{other}? Standard encryption takes 128, 192 or \
                                         256.")),
        };
        // What Office 2007 and LibreOffice write: flags fCryptoAPI and
        // fAES, and the provider's name.
        let mut info = Standard {
            version: (4, 2),
            flags: 0x24,
            header_flags: 0x24,
            alg_id,
            alg_id_hash: 0x8004,
            key_bits,
            provider_type: 0x18,
            csp_name: "Microsoft Enhanced RSA and AES Cryptographic Provider".to_string(),
            salt: allcrypt::api::random_bytes(16)?,
            verifier: Vec::new(),
            verifier_hash_size: 20,
            verifier_hash: Vec::new(),
        };
        let key = info.key(password)?;
        let verifier = allcrypt::api::random_bytes(16)?;
        info.verifier = ecb(&key, &verifier, false)?;
        info.verifier_hash = ecb(&key, &zero_pad(&digest("sha1", &[&verifier])?, 16), false)?;
        Ok((info, key))
    }
}

// ---------------------------------------------------------------- agile --

#[derive(Clone, Debug)]
pub struct Params {
    pub salt: Vec<u8>,
    pub block_size: usize,
    pub key_bits: usize,
    pub hash_size: usize,
    pub cipher: String,
    pub chaining: String,
    pub hash: String,
}

impl Params {
    fn read(element: &Element) -> Result<Params, String> {
        let text = |name: &str| element.attribute(name).map(str::to_string)
            .ok_or(format!("<{}> has no {name}.", element.name));
        let number = |name: &str| -> Result<usize, String> {
            text(name)?.parse().map_err(|_| format!("{name} is not a number."))
        };
        let params = Params {
            salt: base64::decode(&text("saltValue")?).ok_or("saltValue is not base64.")?,
            block_size: number("blockSize")?,
            key_bits: number("keyBits")?,
            hash_size: number("hashSize")?,
            cipher: text("cipherAlgorithm")?,
            chaining: text("cipherChaining")?,
            hash: text("hashAlgorithm")?,
        };
        if params.cipher != "AES" || params.chaining != "ChainingModeCBC" {
            return Err(format!("{} in {}; only AES in CBC is supported.", params.cipher,
                               params.chaining));
        }
        if params.block_size != 16 || ![128, 192, 256].contains(&params.key_bits) {
            return Err(format!("AES with {}-byte blocks and {}-bit keys.", params.block_size,
                               params.key_bits));
        }
        hash_name(&params.hash)?;
        Ok(params)
    }

    fn hash(&self) -> &'static str {
        hash_name(&self.hash).unwrap_or("sha1")
    }

    fn attributes(&self) -> Vec<(String, String)> {
        [("saltSize", self.salt.len().to_string()), ("blockSize", self.block_size.to_string()),
         ("keyBits", self.key_bits.to_string()), ("hashSize", self.hash_size.to_string()),
         ("cipherAlgorithm", self.cipher.clone()), ("cipherChaining", self.chaining.clone()),
         ("hashAlgorithm", self.hash.clone()), ("saltValue", base64::encode(&self.salt))]
            .into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    /// IV for a block key ([MS-OFFCRYPTO] 2.3.4.12): H(salt || block
    /// key), fitted to the block size.
    fn iv(&self, block_key: &[u8]) -> Result<Vec<u8>, String> {
        Ok(fit(digest(self.hash(), &[&self.salt, block_key])?, self.block_size))
    }
}

#[derive(Clone, Debug)]
pub struct PasswordKey {
    pub params: Params,
    pub spin_count: u32,
    pub verifier_hash_input: Vec<u8>,
    pub verifier_hash_value: Vec<u8>,
    pub key_value: Vec<u8>,
}

impl PasswordKey {
    /// The key for one block key ([MS-OFFCRYPTO] 2.3.4.11).
    fn key(&self, spun: &[u8], block_key: &[u8]) -> Result<Vec<u8>, String> {
        Ok(fit(digest(self.params.hash(), &[spun, block_key])?, self.params.key_bits / 8))
    }

    fn salt_iv(&self) -> Vec<u8> {
        fit(self.params.salt.clone(), self.params.block_size)
    }
}

#[derive(Clone, Debug)]
pub struct Agile {
    pub key_data: Params,
    pub hmac_key: Vec<u8>,
    pub hmac_value: Vec<u8>,
    pub password: PasswordKey,
    /// Other key encryptors (certificates), which are kept on reading
    /// and not used.
    pub other_encryptors: usize,
}

impl Agile {
    fn parse(data: &[u8]) -> Result<Agile, String> {
        let root = xml::parse(data.get(8..).ok_or("EncryptionInfo is truncated.")?)?;
        let child = |e: &Element, name: &str| -> Option<Element> {
            e.elements().find(|c| c.local_name() == name).cloned()
        };
        let key_data = Params::read(&child(&root, "keyData").ok_or("No <keyData>.")?)?;
        let integrity = child(&root, "dataIntegrity").ok_or("No <dataIntegrity>.")?;
        let decode = |e: &Element, name: &str| -> Result<Vec<u8>, String> {
            base64::decode(e.attribute(name).ok_or(format!("No {name}."))?)
                .ok_or(format!("{name} is not base64."))
        };
        let encryptors = child(&root, "keyEncryptors").ok_or("No <keyEncryptors>.")?;
        let mut password = None;
        let mut other_encryptors = 0;
        for encryptor in encryptors.elements() {
            let is_password = encryptor.attribute("uri")
                == Some("http://schemas.microsoft.com/office/2006/keyEncryptor/password");
            match (is_password, child(encryptor, "encryptedKey")) {
                (true, Some(key)) => {
                    password = Some(PasswordKey {
                        params: Params::read(&key)?,
                        spin_count: key.attribute("spinCount").and_then(|s| s.parse().ok())
                            .ok_or("No spinCount.")?,
                        verifier_hash_input: decode(&key, "encryptedVerifierHashInput")?,
                        verifier_hash_value: decode(&key, "encryptedVerifierHashValue")?,
                        key_value: decode(&key, "encryptedKeyValue")?,
                    })
                }
                _ => other_encryptors += 1,
            }
        }
        Ok(Agile {
            key_data,
            hmac_key: decode(&integrity, "encryptedHmacKey")?,
            hmac_value: decode(&integrity, "encryptedHmacValue")?,
            password: password.ok_or("No password key encryptor: the document is \
                                      encrypted to a certificate only.")?,
            other_encryptors,
        })
    }

    /// The document's key, if `password` is right ([MS-OFFCRYPTO]
    /// 2.3.4.13: the verifier first, then the key).
    pub fn key(&self, password: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let p = &self.password;
        let spun = spun(p.params.hash(), &p.params.salt, password, p.spin_count)?;
        let iv = p.salt_iv();
        let input = cbc(&p.key(&spun, &VERIFIER_HASH_INPUT)?, &iv, &p.verifier_hash_input, true)?;
        let input = &input[..p.params.salt.len().min(input.len())];
        let value = cbc(&p.key(&spun, &VERIFIER_HASH_VALUE)?, &iv, &p.verifier_hash_value, true)?;
        let expected = digest(p.params.hash(), &[input])?;
        if value.get(..p.params.hash_size) != expected.get(..p.params.hash_size) {
            return Ok(None);
        }
        let key = cbc(&p.key(&spun, &KEY_VALUE)?, &iv, &p.key_value, true)?;
        Ok(Some(key[..(self.key_data.key_bits / 8).min(key.len())].to_vec()))
    }

    /// Whether the HMAC over the encrypted package matches.
    pub fn integrity(&self, key: &[u8], package: &[u8]) -> Result<bool, String> {
        let d = &self.key_data;
        let hmac_key = cbc(key, &d.iv(&INTEGRITY_KEY)?, &self.hmac_key, true)?;
        let hmac_value = cbc(key, &d.iv(&INTEGRITY_VALUE)?, &self.hmac_value, true)?;
        let n = d.hash_size;
        let computed = allcrypt::api::hmac(d.hash(), hmac_key.get(..n).unwrap_or(&hmac_key),
                                           package)?;
        Ok(hmac_value.get(..n) == Some(&computed[..]))
    }

    fn write(&self) -> Vec<u8> {
        let mut key = Element::new("p:encryptedKey");
        key.attributes.push(("spinCount".to_string(), self.password.spin_count.to_string()));
        key.attributes.extend(self.password.params.attributes());
        for (name, value) in [("encryptedVerifierHashInput", &self.password.verifier_hash_input),
                              ("encryptedVerifierHashValue", &self.password.verifier_hash_value),
                              ("encryptedKeyValue", &self.password.key_value)] {
            key.attributes.push((name.to_string(), base64::encode(value)));
        }
        let mut key_data = Element::new("keyData");
        key_data.attributes = self.key_data.attributes();
        let root = Element::new("encryption")
            .with_attribute("xmlns", "http://schemas.microsoft.com/office/2006/encryption")
            .with_attribute("xmlns:p", "http://schemas.microsoft.com/office/2006/keyEncryptor/password")
            .with_attribute("xmlns:c",
                            "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate")
            .with_child(key_data)
            .with_child(Element::new("dataIntegrity")
                .with_attribute("encryptedHmacKey", &base64::encode(&self.hmac_key))
                .with_attribute("encryptedHmacValue", &base64::encode(&self.hmac_value)))
            .with_child(Element::new("keyEncryptors").with_child(Element::new("keyEncryptor")
                .with_attribute("uri", "http://schemas.microsoft.com/office/2006/keyEncryptor/password")
                .with_child(key)));
        let mut out = vec![4, 0, 4, 0, 0x40, 0, 0, 0];
        out.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n");
        let body = xml::write(&root);
        // `xml::write` puts its own declaration first; keep only the
        // element.
        let start = body.windows(11).position(|w| w == b"<encryption").unwrap_or(0);
        out.extend_from_slice(&body[start..]);
        out
    }
}

// ------------------------------------------------------------- the file --

#[derive(Clone, Debug)]
pub enum Info {
    Standard(Standard),
    Agile(Box<Agile>),
}

pub fn parse_info(data: &[u8]) -> Result<Info, String> {
    let major = u16::from_le_bytes([*data.first().ok_or("EncryptionInfo is empty.")?,
                                    *data.get(1).ok_or("EncryptionInfo is empty.")?]);
    let minor = u16::from_le_bytes([*data.get(2).ok_or("EncryptionInfo is truncated.")?,
                                    *data.get(3).ok_or("EncryptionInfo is truncated.")?]);
    match (major, minor) {
        (4, 4) => Ok(Info::Agile(Box::new(Agile::parse(data)?))),
        (2..=4, 2) => Ok(Info::Standard(Standard::parse((major, minor), data)?)),
        (3 | 4, 3) => Err("Extensible encryption: the document names a third-party \
                           cryptographic provider, which is not here.".to_string()),
        _ => Err(format!("EncryptionInfo version {major}.{minor}.")),
    }
}

pub fn info(root: &Storage) -> Result<Info, String> {
    parse_info(root.stream("EncryptionInfo").ok_or("No EncryptionInfo stream: not an \
                                                    encrypted OOXML document.")?)
}

/// What `decrypt` found besides the package.
pub struct Opened {
    pub package: Vec<u8>,
    /// Agile only: whether the HMAC over the encrypted stream matched.
    pub integrity: Option<bool>,
}

pub fn decrypt(root: &Storage, password: &[u8]) -> Result<Opened, String> {
    let info = info(root)?;
    let encrypted = root.stream("EncryptedPackage").ok_or("No EncryptedPackage stream.")?;
    let size = encrypted.get(..8).map(|b| u64::from_le_bytes(b.try_into().expect("eight")))
        .ok_or("EncryptedPackage is shorter than its size field.")? as usize;
    let body = &encrypted[8..];
    let password = utf16(password)?;
    match info {
        Info::Standard(standard) => {
            let key = standard.key(&password)?;
            if !standard.verify(&key)? {
                return Err("Wrong password.".to_string());
            }
            let whole = body.len() / 16 * 16;
            let mut package = ecb(&key, &body[..whole], true)?;
            if package.len() < size {
                return Err(format!("EncryptedPackage holds {} bytes of a {size}-byte package.",
                                   package.len()));
            }
            package.truncate(size);
            Ok(Opened { package, integrity: None })
        }
        Info::Agile(agile) => {
            let key = agile.key(&password)?.ok_or("Wrong password.")?;
            let integrity = agile.integrity(&key, encrypted)?;
            let mut package = Vec::with_capacity(body.len());
            for (i, segment) in body.chunks(SEGMENT).enumerate() {
                let iv = agile.key_data.iv(&(i as u32).to_le_bytes())?;
                let whole = segment.len() / 16 * 16;
                package.extend(cbc(&key, &iv, &segment[..whole], true)?);
                if package.len() >= size {
                    break;
                }
            }
            if package.len() < size {
                return Err(format!("EncryptedPackage holds {} bytes of a {size}-byte package.",
                                   package.len()));
            }
            package.truncate(size);
            Ok(Opened { package, integrity: Some(integrity) })
        }
    }
}

/// The `\x06DataSpaces` storage ([MS-OFFCRYPTO] 2.1, 2.2): one data
/// space, `StrongEncryptionDataSpace`, over the `EncryptedPackage`
/// stream, through one transform. The specification requires it and
/// Office writes it, the same bytes in every document; nothing that
/// checked this example reads it.
pub fn data_spaces() -> Storage {
    fn text(s: &str) -> Vec<u8> {
        // UNICODE-LP-P4: a byte length, UTF-16, padded to four bytes.
        let units: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut out = (units.len() as u32).to_le_bytes().to_vec();
        out.extend(&units);
        out.resize(out.len().div_ceil(4) * 4, 0);
        out
    }
    fn u32s(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }
    let version = [text("Microsoft.Container.DataSpaces"), u32s(&[1, 1, 1])].concat();
    let entry = [u32s(&[1, 0]), text("EncryptedPackage"), text("StrongEncryptionDataSpace")]
        .concat();
    let map = [u32s(&[8, 1, entry.len() as u32 + 4]), entry].concat();
    let space = [u32s(&[8, 1]), text("StrongEncryptionTransform")].concat();
    // TransformInfoHeader: its length field counts itself, the type and
    // the ID, and not the name that follows.
    let id = text("{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}");
    let primary = [u32s(&[8 + id.len() as u32, 1]), id,
                   text("Microsoft.Container.EncryptionTransform"), u32s(&[1, 1, 1]),
                   // EncryptionTransformInfo: no name, block size and
                   // cipher mode zero, and 4 in the reserved field.
                   u32s(&[0, 0, 0, 4])].concat();
    Storage::new("\u{6}DataSpaces")
        .with_stream("Version", version)
        .with_stream("DataSpaceMap", map)
        .with_storage(Storage::new("DataSpaceInfo")
            .with_stream("StrongEncryptionDataSpace", space))
        .with_storage(Storage::new("TransformInfo")
            .with_storage(Storage::new("StrongEncryptionTransform")
                .with_stream("\u{6}Primary", primary)))
}

pub struct AgileOptions {
    pub key_bits: usize,
    pub hash: String,
    pub spin_count: u32,
}

/// Encrypt a package, agile or standard, into a compound file.
pub fn encrypt(package: &[u8], password: &[u8], method: &str, agile: &AgileOptions)
               -> Result<Vec<u8>, String> {
    let password = utf16(password)?;
    let mut stream = (package.len() as u64).to_le_bytes().to_vec();
    let info = match method {
        "standard" => {
            let (info, key) = Standard::create(&password, agile.key_bits as u32)?;
            stream.extend(ecb(&key, &zero_pad(package, 16), false)?);
            info.write()
        }
        "agile" => {
            let hash = hash_name(&agile.hash)?;
            let hash_size = digest(hash, &[])?.len();
            let params = |salt: Vec<u8>| Params {
                salt, block_size: 16, key_bits: agile.key_bits, hash_size,
                cipher: "AES".to_string(), chaining: "ChainingModeCBC".to_string(),
                hash: agile.hash.clone(),
            };
            let key_data = params(allcrypt::api::random_bytes(16)?);
            let key = allcrypt::api::random_bytes(agile.key_bits / 8)?;
            for (i, segment) in package.chunks(SEGMENT).enumerate() {
                let iv = key_data.iv(&(i as u32).to_le_bytes())?;
                stream.extend(cbc(&key, &iv, &zero_pad(segment, 16), false)?);
            }
            let hmac_key = allcrypt::api::random_bytes(hash_size)?;
            let hmac_value = allcrypt::api::hmac(hash, &hmac_key, &stream)?;
            let mut p = PasswordKey {
                params: params(allcrypt::api::random_bytes(16)?), spin_count: agile.spin_count,
                verifier_hash_input: Vec::new(), verifier_hash_value: Vec::new(),
                key_value: Vec::new(),
            };
            let spun = spun(hash, &p.params.salt, &password, p.spin_count)?;
            let iv = p.salt_iv();
            let verifier = allcrypt::api::random_bytes(16)?;
            p.verifier_hash_input = cbc(&p.key(&spun, &VERIFIER_HASH_INPUT)?, &iv, &verifier,
                                        false)?;
            p.verifier_hash_value = cbc(&p.key(&spun, &VERIFIER_HASH_VALUE)?, &iv,
                                        &zero_pad(&digest(hash, &[&verifier])?, 16), false)?;
            p.key_value = cbc(&p.key(&spun, &KEY_VALUE)?, &iv, &zero_pad(&key, 16), false)?;
            let agile = Agile {
                // Padded with 0x36 to whole blocks, as LibreOffice pads
                // them; a reader takes the first hashSize bytes.
                hmac_key: cbc(&key, &key_data.iv(&INTEGRITY_KEY)?,
                              &fit(hmac_key.clone(), hmac_key.len().div_ceil(16) * 16), false)?,
                hmac_value: cbc(&key, &key_data.iv(&INTEGRITY_VALUE)?,
                                &fit(hmac_value.clone(), hmac_value.len().div_ceil(16) * 16),
                                false)?,
                key_data, password: p, other_encryptors: 0,
            };
            agile.write()
        }
        other => return Err(format!("Unknown method {other}: agile or standard.")),
    };
    let root = Storage::new("Root Entry")
        .with_stream("EncryptionInfo", info)
        .with_stream("EncryptedPackage", stream)
        .with_storage(data_spaces());
    cfb::write(&root)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A derived key longer than the hash - AES-192 or AES-256 under
    /// SHA-1 - is padded with 0x36, and so is an IV ([MS-OFFCRYPTO]
    /// 2.3.4.11 and 2.3.4.12; LibreOffice's `calculateIV` pads the same
    /// way). No witness here writes or reads such a key, so this is the
    /// only check of it.
    #[test]
    fn test_short_keys_and_ivs_are_padded_with_0x36() {
        assert_eq!(fit(vec![1, 2], 5), [1, 2, 0x36, 0x36, 0x36]);
        assert_eq!(fit(vec![1, 2, 3], 2), [1, 2]);
        let p = PasswordKey {
            params: Params { salt: vec![9; 16], block_size: 16, key_bits: 256, hash_size: 20,
                             cipher: "AES".into(), chaining: "ChainingModeCBC".into(),
                             hash: "SHA1".into() },
            spin_count: 1, verifier_hash_input: Vec::new(), verifier_hash_value: Vec::new(),
            key_value: Vec::new(),
        };
        let key = p.key(b"spun", &KEY_VALUE).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(&key[..20], &digest("sha1", &[b"spun", &KEY_VALUE]).unwrap()[..]);
        assert_eq!(&key[20..], &[0x36; 12]);
    }
}
