//! OpenDocument package encryption (ODF 1.2 part 3, section 3.8, and
//! LibreOffice's ODF 1.4 "wholesome" extension).
//!
//! An encrypted package keeps its `mimetype` and `META-INF/manifest.xml`
//! in the clear; the manifest says, for each file, how it was
//! encrypted. Three ways are in use:
//!
//! | scheme   | cipher                 | start key | key derivation        | password check   |
//! |----------|------------------------|-----------|-----------------------|------------------|
//! | blowfish | Blowfish, 64-bit CFB   | SHA-1     | PBKDF2-HMAC-SHA1, 16 bytes | SHA-1 of 1 KB  |
//! | aes      | AES-256-CBC, W3C padding | SHA-256 | PBKDF2-HMAC-SHA1, 32 bytes | SHA-256 of 1 KB |
//! | gcm      | AES-256-GCM, whole package | SHA-256 | Argon2id          | the GCM tag      |
//!
//! In the first two every file is deflated, then encrypted on its own
//! with its own salt and IV, and the checksum - of the first 1024 bytes
//! of the deflated, not yet encrypted, data - is all that tells a right
//! password from a wrong one. The checksum is of plaintext, so it leaks
//! a little of every file, and nothing authenticates anything after
//! its first kilobyte. The third, which LibreOffice writes in its
//! experimental mode, encrypts the whole package - itself a complete
//! plain package - as one file, `encrypted-package`, under AES-GCM, so
//! the tag covers everything and no file name or size is in the clear.
//!
//! The "start key" is the hash of the password's UTF-8; the key
//! derivation's password is that hash, not the password.

use allcrypt::api::{AnyBlockCipher, AnyHash};
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::hash_functions::HashFunction;

use crate::base64;
use crate::xml::{self, Element, Node};
use crate::ziparchive::{self, Entry};

const AES_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const AES_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const BLOWFISH: &str = "Blowfish CFB";
const SHA256_START: &str = "http://www.w3.org/2000/09/xmldsig#sha256";
const SHA256_START_GCM: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA256_1K: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k";
const SHA1_1K: &str = "SHA1/1K";
const ARGON2ID: &str = "urn:org:documentfoundation:names:experimental:office:manifest:argon2id";
const LOEXT: &str = "urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0";
const WHOLE: &str = "encrypted-package";

fn digest(hash: &str, data: &[u8]) -> Vec<u8> {
    let mut h = AnyHash::new(hash).expect("a built-in hash");
    h.update(data);
    h.digest()
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Cipher {
    Blowfish,
    AesCbc,
    AesGcm,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { passes: u32, memory_kib: u32, lanes: u32 },
}

/// One `<manifest:encryption-data>`.
#[derive(Clone, Debug)]
pub struct Encryption {
    pub cipher: Cipher,
    pub iv: Vec<u8>,
    pub start_hash: &'static str,
    pub kdf: Kdf,
    pub salt: Vec<u8>,
    pub key_size: usize,
    /// The hash and value of the 1 KB checksum, where there is one.
    pub checksum: Option<(&'static str, Vec<u8>)>,
}

/// The value of an attribute whatever its namespace prefix.
fn attribute<'a>(element: &'a Element, local: &str) -> Option<&'a str> {
    element.attributes.iter()
        .find(|(name, _)| name.rsplit(':').next() == Some(local))
        .map(|(_, value)| value.as_str())
}

fn child<'a>(element: &'a Element, local: &str) -> Option<&'a Element> {
    element.elements().find(|e| e.local_name() == local)
}

impl Encryption {
    pub fn parse(data: &Element) -> Result<Encryption, String> {
        let decode = |text: Option<&str>, what: &str| -> Result<Vec<u8>, String> {
            base64::decode(text.ok_or(format!("No {what}."))?).ok_or(format!("{what} is not base64."))
        };
        let number = |e: &Element, name: &str| -> Result<u32, String> {
            attribute(e, name).ok_or(format!("No {name}."))?.parse()
                .map_err(|_| format!("{name} is not a number."))
        };
        let algorithm = child(data, "algorithm").ok_or("No <manifest:algorithm>.")?;
        let cipher = match attribute(algorithm, "algorithm-name") {
            Some(BLOWFISH) => Cipher::Blowfish,
            Some(AES_CBC) => Cipher::AesCbc,
            Some(AES_GCM) => Cipher::AesGcm,
            other => return Err(format!("Encryption algorithm {other:?} is not supported.")),
        };
        let start_hash = match child(data, "start-key-generation")
            .and_then(|e| attribute(e, "start-key-generation-name")) {
            None | Some("SHA1") | Some("http://www.w3.org/2000/09/xmldsig#sha1") => "sha1",
            Some(SHA256_START) | Some(SHA256_START_GCM) | Some("SHA256") => "sha256",
            Some(other) => return Err(format!("Start key generation {other} is not supported.")),
        };
        let derivation = child(data, "key-derivation").ok_or("No <manifest:key-derivation>.")?;
        let kdf = match attribute(derivation, "key-derivation-name") {
            Some("PBKDF2") => Kdf::Pbkdf2 { iterations: number(derivation, "iteration-count")? },
            Some(ARGON2ID) => Kdf::Argon2id {
                passes: number(derivation, "argon2-iterations")?,
                memory_kib: number(derivation, "argon2-memory")?,
                lanes: number(derivation, "argon2-lanes")?,
            },
            other => return Err(format!("Key derivation {other:?} is not supported.")),
        };
        let key_size = match attribute(derivation, "key-size") {
            Some(size) => size.parse().map_err(|_| "key-size is not a number.")?,
            // ODF 1.2: 16 bytes when the attribute is absent.
            None => 16,
        };
        let checksum = match attribute(data, "checksum-type") {
            None => None,
            Some(kind) => {
                let hash = if kind == SHA1_1K || kind.ends_with("#sha1-1k") {
                    "sha1"
                } else if kind == SHA256_1K || kind == "SHA256/1K" {
                    "sha256"
                } else {
                    return Err(format!("Checksum {kind} is not supported."));
                };
                Some((hash, decode(attribute(data, "checksum"), "checksum")?))
            }
        };
        let encryption = Encryption {
            cipher, start_hash, kdf, key_size, checksum,
            iv: decode(attribute(algorithm, "initialisation-vector"), "initialisation-vector")?,
            salt: decode(attribute(derivation, "salt"), "salt")?,
        };
        let iv_size = match cipher {
            Cipher::Blowfish => 8,
            Cipher::AesCbc => 16,
            Cipher::AesGcm => 12,
        };
        if encryption.iv.len() != iv_size {
            return Err(format!("An IV of {} bytes for {cipher:?}.", encryption.iv.len()));
        }
        Ok(encryption)
    }

    pub fn key(&self, password: &[u8]) -> Result<Vec<u8>, String> {
        let start = digest(self.start_hash, password);
        match self.kdf {
            Kdf::Pbkdf2 { iterations } => {
                allcrypt::api::pbkdf2("sha1", &start, &self.salt, iterations, self.key_size)
            }
            Kdf::Argon2id { passes, memory_kib, lanes } => {
                allcrypt::api::argon2("argon2id", &start, &self.salt, memory_kib, passes, lanes,
                                      &[], &[], self.key_size)
            }
        }
    }

    /// Decrypt one file's stored bytes to its deflated data, checking
    /// the password as the format allows.
    pub fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let plain = match self.cipher {
            Cipher::Blowfish => {
                let mut cipher = AnyBlockCipher::new("blowfish", key, None)?;
                let mut out = Vec::with_capacity(data.len());
                cipher.cfb_decrypt(data, &mut out, &self.iv)?;
                out
            }
            Cipher::AesCbc => {
                if data.is_empty() || !data.len().is_multiple_of(16) {
                    return Err(format!("{} bytes of AES-CBC data.", data.len()));
                }
                let mut cipher = AnyBlockCipher::new("aes", key, None)?;
                let mut out = Vec::with_capacity(data.len());
                cipher.cbc_decrypt(data, &mut out, &self.iv)?;
                // W3C padding: the last byte counts the padding, and the
                // rest of it is arbitrary.
                let pad = usize::from(*out.last().expect("not empty"));
                if pad == 0 || pad > 16 {
                    return Err("The AES padding is wrong: a wrong password, or a changed \
                                file.".to_string());
                }
                out.truncate(out.len() - pad);
                out
            }
            Cipher::AesGcm => {
                // The IV is repeated before the ciphertext, the tag after.
                if data.len() < 28 || data[..12] != self.iv[..] {
                    return Err("The GCM data does not start with the IV the manifest gives."
                        .to_string());
                }
                let (body, tag) = data[12..].split_at(data.len() - 28);
                return allcrypt::api::aead_decrypt("aes-gcm", key, &self.iv, &[], body, tag)
                    .map_err(|_| "Wrong password, or the package was changed.".to_string());
            }
        };
        if let Some((hash, expected)) = &self.checksum {
            if digest(hash, &plain[..plain.len().min(1024)]) != *expected {
                return Err("Wrong password.".to_string());
            }
        }
        Ok(plain)
    }

    fn encrypt(&self, key: &[u8], deflated: &[u8]) -> Result<Vec<u8>, String> {
        match self.cipher {
            Cipher::Blowfish => {
                let mut cipher = AnyBlockCipher::new("blowfish", key, None)?;
                let mut out = Vec::with_capacity(deflated.len());
                cipher.cfb_encrypt(deflated, &mut out, &self.iv)?;
                Ok(out)
            }
            Cipher::AesCbc => {
                let mut cipher = AnyBlockCipher::new("aes", key, None)?;
                let mut out = Vec::with_capacity(deflated.len() + 16);
                cipher.cbc_encrypt(&allcrypt::api::pad_pkcs7(deflated, 16)?, &mut out,
                                   &self.iv)?;
                Ok(out)
            }
            Cipher::AesGcm => {
                let (body, tag) = allcrypt::api::aead_encrypt("aes-gcm", key, &self.iv, &[],
                                                              deflated)?;
                Ok([self.iv.as_slice(), &body, &tag].concat())
            }
        }
    }

    fn element(&self) -> Element {
        let (algorithm, start) = match self.cipher {
            Cipher::Blowfish => (BLOWFISH, None),
            Cipher::AesCbc => (AES_CBC, Some(SHA256_START)),
            Cipher::AesGcm => (AES_GCM, Some(SHA256_START_GCM)),
        };
        let mut data = Element::new("manifest:encryption-data");
        if let Some((hash, value)) = &self.checksum {
            data = data
                .with_attribute("manifest:checksum-type",
                                if *hash == "sha1" { SHA1_1K } else { SHA256_1K })
                .with_attribute("manifest:checksum", &base64::encode(value));
        }
        data = data.with_child(Element::new("manifest:algorithm")
            .with_attribute("manifest:algorithm-name", algorithm)
            .with_attribute("manifest:initialisation-vector", &base64::encode(&self.iv)));
        if let Some(start) = start {
            data = data.with_child(Element::new("manifest:start-key-generation")
                .with_attribute("manifest:start-key-generation-name", start)
                .with_attribute("manifest:key-size", "32"));
        }
        let mut derivation = Element::new("manifest:key-derivation");
        match self.kdf {
            Kdf::Pbkdf2 { iterations } => {
                derivation = derivation.with_attribute("manifest:key-derivation-name", "PBKDF2")
                    .with_attribute("manifest:iteration-count", &iterations.to_string());
            }
            Kdf::Argon2id { passes, memory_kib, lanes } => {
                derivation = derivation.with_attribute("manifest:key-derivation-name", ARGON2ID)
                    .with_attribute("loext:argon2-iterations", &passes.to_string())
                    .with_attribute("loext:argon2-memory", &memory_kib.to_string())
                    .with_attribute("loext:argon2-lanes", &lanes.to_string());
            }
        }
        derivation = derivation.with_attribute("manifest:salt", &base64::encode(&self.salt));
        if self.cipher != Cipher::Blowfish {
            derivation = derivation.with_attribute("manifest:key-size",
                                                   &self.key_size.to_string());
        }
        data.with_child(derivation)
    }
}

// --------------------------------------------------------------- reading --

pub struct Package {
    pub entries: Vec<Entry>,
    pub manifest: Element,
}

pub fn open(data: &[u8]) -> Result<Package, String> {
    let entries = ziparchive::read(data)?;
    let manifest = entries.iter().find(|e| e.name == "META-INF/manifest.xml")
        .ok_or("No META-INF/manifest.xml: not an OpenDocument package.")?;
    let manifest = xml::parse(&ziparchive::content(manifest)?)?;
    Ok(Package { entries, manifest })
}

/// Each file entry in the manifest: its path, and its encryption if it
/// has one.
pub fn encrypted_files(manifest: &Element) -> Result<Vec<(String, Encryption, u64)>, String> {
    let mut out = Vec::new();
    for entry in manifest.elements().filter(|e| e.local_name() == "file-entry") {
        if let Some(data) = child(entry, "encryption-data") {
            let path = attribute(entry, "full-path").ok_or("A file-entry with no full-path.")?;
            let size = attribute(entry, "size").and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("{path}: an encrypted file with no size."))?;
            out.push((path.to_string(), Encryption::parse(data)?, size));
        }
    }
    Ok(out)
}

/// What `info` prints.
pub fn describe(package: &Package) -> Result<Vec<String>, String> {
    let files = encrypted_files(&package.manifest)?;
    let Some((_, first, _)) = files.first() else {
        return Ok(vec!["not encrypted".to_string()]);
    };
    let kdf = match first.kdf {
        Kdf::Pbkdf2 { iterations } => format!("PBKDF2-HMAC-SHA1 x {iterations}"),
        Kdf::Argon2id { passes, memory_kib, lanes } => {
            format!("Argon2id, {passes} passes, {memory_kib} KiB, {lanes} lanes")
        }
    };
    Ok(vec![
        format!("{} encrypted file(s){}", files.len(),
                if files.iter().any(|f| f.0 == WHOLE) { ", the whole package" } else { "" }),
        format!("{:?}, a {}-byte key, start key {}", first.cipher, first.key_size,
                first.start_hash),
        kdf,
    ])
}

/// The plain package: every encrypted file decrypted and stored
/// deflated, as it was before encryption; the manifest without its
/// encryption data. A whole-package encryption gives back the package
/// inside it.
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let package = open(data)?;
    let files = encrypted_files(&package.manifest)?;
    if files.is_empty() {
        return Err("The package is not encrypted.".to_string());
    }
    let mut out = Vec::new();
    for entry in &package.entries {
        if entry.name == "META-INF/manifest.xml" {
            continue;
        }
        let Some((path, encryption, size)) = files.iter().find(|f| f.0 == entry.name) else {
            out.push(entry.clone());
            continue;
        };
        if entry.method != 0 {
            return Err(format!("{path}: an encrypted file that is compressed in the ZIP."));
        }
        let key = encryption.key(password)?;
        let deflated = encryption.decrypt(&key, &entry.data)?;
        let (plain, _) = crate::inflate::inflate(&deflated, *size as usize)
            .map_err(|e| format!("{path}: {e}"))?;
        if plain.len() as u64 != *size {
            return Err(format!("{path}: {} bytes where the manifest says {size}.", plain.len()));
        }
        if path == WHOLE {
            // The inner package is the document.
            ziparchive::read(&plain).map_err(|e| format!("The decrypted package: {e}"))?;
            return Ok(plain);
        }
        out.push(Entry { name: entry.name.clone(), method: 8, crc: allcrypt::checksum::crc32(&plain),
                         size: *size, data: deflated });
    }
    let mut manifest = package.manifest.clone();
    for entry in manifest.elements_mut().filter(|e| e.local_name() == "file-entry") {
        entry.children.retain(|n| !matches!(n, Node::Element(e)
                                            if e.local_name() == "encryption-data"));
        entry.attributes.retain(|(name, _)| name != "manifest:size");
    }
    out.push(ziparchive::deflated("META-INF/manifest.xml", &xml::write(&manifest)));
    Ok(ziparchive::write(&out))
}

// --------------------------------------------------------------- writing --

pub struct Options {
    pub scheme: String,
    pub iterations: u32,
    pub argon2: (u32, u32, u32),
}

fn new_encryption(options: &Options) -> Result<Encryption, String> {
    let random = allcrypt::api::random_bytes;
    Ok(match options.scheme.as_str() {
        "aes" => Encryption {
            cipher: Cipher::AesCbc, iv: random(16)?, start_hash: "sha256",
            kdf: Kdf::Pbkdf2 { iterations: options.iterations }, salt: random(16)?,
            key_size: 32, checksum: Some(("sha256", Vec::new())),
        },
        "blowfish" => Encryption {
            cipher: Cipher::Blowfish, iv: random(8)?, start_hash: "sha1",
            kdf: Kdf::Pbkdf2 { iterations: options.iterations }, salt: random(16)?,
            key_size: 16, checksum: Some(("sha1", Vec::new())),
        },
        "gcm" => Encryption {
            cipher: Cipher::AesGcm, iv: random(12)?, start_hash: "sha256",
            kdf: Kdf::Argon2id { passes: options.argon2.0, memory_kib: options.argon2.1,
                                 lanes: options.argon2.2 },
            salt: random(16)?, key_size: 32, checksum: None,
        },
        other => return Err(format!("Unknown scheme {other}: aes, blowfish or gcm.")),
    })
}

/// The deflated form of an entry: its own bytes if the ZIP already
/// deflated it, else stored deflate blocks.
fn deflated_form(entry: &Entry) -> Result<(Vec<u8>, Vec<u8>), String> {
    let plain = ziparchive::content(entry)?;
    let deflated = if entry.method == 8 { entry.data.clone() } else {
        ziparchive::deflate_stored(&plain)
    };
    Ok((plain, deflated))
}

pub fn encrypt(data: &[u8], password: &[u8], options: &Options) -> Result<Vec<u8>, String> {
    let package = open(data)?;
    if !encrypted_files(&package.manifest)?.is_empty() {
        return Err("The package is already encrypted.".to_string());
    }
    let mimetype = package.entries.iter().find(|e| e.name == "mimetype")
        .ok_or("No mimetype entry.")?;
    let media_type = String::from_utf8_lossy(&ziparchive::content(mimetype)?).into_owned();
    if options.scheme == "gcm" {
        let mut encryption = new_encryption(options)?;
        let key = encryption.key(password)?;
        let sealed = encryption.encrypt(&key, &ziparchive::deflate_stored(data))?;
        encryption.checksum = None;
        let manifest = Element::new("manifest:manifest")
            .with_attribute("xmlns:manifest", "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0")
            .with_attribute("manifest:version", "1.3")
            .with_attribute("xmlns:loext", LOEXT)
            .with_child(Element::new("manifest:file-entry")
                .with_attribute("manifest:full-path", WHOLE)
                .with_attribute("manifest:media-type", &media_type)
                .with_attribute("manifest:size", &data.len().to_string())
                .with_child(encryption.element()));
        return Ok(ziparchive::write(&[
            ziparchive::stored("mimetype", media_type.into_bytes()),
            ziparchive::stored(WHOLE, sealed),
            ziparchive::deflated("META-INF/manifest.xml", &xml::write(&manifest)),
        ]));
    }
    let mut manifest = package.manifest.clone();
    if options.scheme == "aes" && attribute(&manifest, "version").is_none() {
        // AES-256 and SHA-256 are ODF 1.2.
        manifest.attributes.push(("manifest:version".to_string(), "1.2".to_string()));
    }
    let mut out = vec![ziparchive::stored("mimetype", media_type.into_bytes())];
    for entry in &package.entries {
        if entry.name == "mimetype" || entry.name == "META-INF/manifest.xml"
            || entry.name.ends_with('/') {
            if entry.name.ends_with('/') {
                out.push(entry.clone());
            }
            continue;
        }
        let (plain, deflated) = deflated_form(entry)?;
        let mut encryption = new_encryption(options)?;
        let hash = encryption.checksum.as_ref().map(|c| c.0).expect("a checksum");
        encryption.checksum = Some((hash, digest(hash, &deflated[..deflated.len().min(1024)])));
        let key = encryption.key(password)?;
        out.push(ziparchive::stored(&entry.name, encryption.encrypt(&key, &deflated)?));
        let existing = manifest.elements_mut().find(|e| e.local_name() == "file-entry"
                                                    && attribute(e, "full-path")
                                                        == Some(entry.name.as_str()));
        let file = match existing {
            Some(file) => file,
            None => {
                manifest.push(Element::new("manifest:file-entry")
                    .with_attribute("manifest:full-path", &entry.name)
                    .with_attribute("manifest:media-type", ""));
                manifest.elements_mut().last().expect("just pushed")
            }
        };
        file.attributes.push(("manifest:size".to_string(), plain.len().to_string()));
        file.push(encryption.element());
    }
    out.push(ziparchive::deflated("META-INF/manifest.xml", &xml::write(&manifest)));
    Ok(ziparchive::write(&out))
}
