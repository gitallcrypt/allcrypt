//! The KDBX container: header, key derivation, outer encryption, the
//! block stream that authenticates it, compression, and for version 4
//! the inner header. What comes out is the XML document and the
//! attachments; `database.rs` reads the XML.
//!
//! ## Two formats under one signature
//!
//! **KDBX 3.1** (KeePass 2.x before 2.35): header fields with 16-bit
//! lengths; the key transformed by AES-KDF; the payload encrypted, then
//! *inside* the encryption a hashed block stream (index, SHA-256, size,
//! data) and 32 "stream start bytes" from the header to recognise a
//! wrong key. Nothing authenticates the header except that its SHA-256
//! may be repeated in the XML.
//!
//! **KDBX 4.0 / 4.1**: header fields with 32-bit lengths, a KDF chosen
//! by UUID with its parameters in a typed dictionary (AES-KDF, Argon2d,
//! Argon2id), the header followed by its SHA-256 and an HMAC-SHA256, and
//! the *ciphertext* cut into HMAC-SHA256 blocks - encrypt-then-MAC,
//! where 3.1 was hash-then-encrypt. Each block's HMAC key is
//! `SHA-512(index || K)` with `K = SHA-512(seed || transformed || 01)`,
//! the header's own key using index `2^64 - 1`, so blocks cannot be
//! reordered and the header cannot pass for a block. The inner random
//! stream's key and the attachments move into an inner header after
//! decryption.
//!
//! In both, the composite key is `SHA-256(SHA-256(password) || key
//! file's 32 bytes)` with either part left out when absent, the
//! transformed key comes from the KDF, and the cipher key is
//! `SHA-256(master seed || transformed key)`.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::twofish::Twofish;
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::hash_functions::sha2::{SHA256, SHA512};
use allcrypt::hash_functions::HashFunction;
use allcrypt::mac::hmac::Hmac;
use allcrypt::stream_ciphers::chacha::Chacha;
use allcrypt::stream_ciphers::salsa20::Salsa20;
use allcrypt::stream_ciphers::StreamCipher;

use crate::inflate;

pub const SIGNATURE_1: u32 = 0x9AA2_D903;
pub const SIGNATURE_2: u32 = 0xB54B_FB67;

pub const CIPHER_AES: [u8; 16] = hex16("31c1f2e6bf714350be5805216afc5aff");
pub const CIPHER_TWOFISH: [u8; 16] = hex16("ad68f29f576f4bb9a36ad47af965346c");
pub const CIPHER_CHACHA20: [u8; 16] = hex16("d6038a2b8b6f4cb5a524339a31dbb59a");
pub const KDF_AES_KDBX3: [u8; 16] = hex16("c9d9f39a628a4460bf740d08c18a4fea");
pub const KDF_AES: [u8; 16] = hex16("7c02bb8279a74ac0927d114a00648238");
pub const KDF_ARGON2D: [u8; 16] = hex16("ef636ddf8c29444b91f7a9a403e30a0c");
pub const KDF_ARGON2ID: [u8; 16] = hex16("9e298b1956db4773b23dfc3ec6f0a1e6");

const fn hex16(text: &str) -> [u8; 16] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (digit(bytes[2 * i]) << 4) | digit(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not a hex digit"),
    }
}

/// Salsa20's fixed nonce for the KDBX 3.1 inner stream.
const SALSA20_NONCE: [u8; 8] = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = SHA256::new(&[]);
    for part in parts {
        hash.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash.digest());
    out
}

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = SHA512::new(&[], 512);
    for part in parts {
        hash.update(part);
    }
    hash.digest()
}

// ------------------------------------------------------------------ keys --

/// The 32 bytes a key file contributes, by KeePass's rules in order:
/// an XML key file (version 1.0, base64; version 2.0, hex checked
/// against the first four bytes of its SHA-256), exactly 32 bytes taken
/// as they are, exactly 64 hex digits decoded, and anything else hashed
/// with SHA-256 whole.
pub fn key_file(data: &[u8]) -> Result<[u8; 32], String> {
    if let Ok(root) = crate::xml::parse(data) {
        if root.name == "KeyFile" {
            let version = root.child("Meta").map(|m| m.child_text("Version")).unwrap_or_default();
            let key = root.child("Key").ok_or("A KeyFile with no Key.")?;
            let data = key.child("Data").ok_or("A KeyFile with no Data.")?;
            let text: String = data.text().chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = if version.starts_with("2.") {
                let bytes = unhex(&text).ok_or("A version 2 key file's Data is not hex.")?;
                let expected = unhex(data.attribute("Hash").unwrap_or(""))
                    .ok_or("A version 2 key file without a hex Hash.")?;
                if sha256(&[&bytes])[..4] != expected[..] {
                    return Err("The key file's hash does not match its key.".to_string());
                }
                bytes
            } else {
                crate::base64::decode(&text).ok_or("A version 1 key file's Data is not base64.")?
            };
            return bytes.try_into().map_err(|_| "A key file key is not 32 bytes.".to_string());
        }
    }
    if data.len() == 32 {
        return Ok(data.try_into().unwrap_or([0; 32]));
    }
    if data.len() == 64 {
        if let Some(bytes) = std::str::from_utf8(data).ok().and_then(unhex) {
            return Ok(bytes.try_into().unwrap_or([0; 32]));
        }
    }
    Ok(sha256(&[data]))
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

pub struct Credentials {
    pub password: Option<String>,
    pub key_file: Option<[u8; 32]>,
}

impl Credentials {
    pub fn composite(&self) -> [u8; 32] {
        let mut parts: Vec<[u8; 32]> = Vec::new();
        if let Some(password) = &self.password {
            parts.push(sha256(&[password.as_bytes()]));
        }
        if let Some(key) = &self.key_file {
            parts.push(*key);
        }
        let slices: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
        sha256(&slices)
    }
}

// ---------------------------------------------------------- the header --

#[derive(Clone, Debug, PartialEq)]
pub enum Kdf {
    Aes { seed: Vec<u8>, rounds: u64 },
    Argon2 { id: bool, salt: Vec<u8>, iterations: u64, memory: u64, parallelism: u32,
             version: u32, secret: Vec<u8>, associated: Vec<u8> },
}

impl Kdf {
    pub fn name(&self) -> &'static str {
        match self {
            Kdf::Aes { .. } => "aes",
            Kdf::Argon2 { id: false, .. } => "argon2d",
            Kdf::Argon2 { id: true, .. } => "argon2id",
        }
    }

    fn transform(&self, key: &[u8; 32]) -> Result<[u8; 32], String> {
        match self {
            Kdf::Aes { seed, rounds } =>
                allcrypt::kdf::password::keepass_aes_kdf(key, seed, *rounds),
            Kdf::Argon2 { id, salt, iterations, memory, parallelism, version, secret,
                          associated } => {
                if *version != 0x13 {
                    return Err(format!("Argon2 version {version:#x} is not supported; \
                                        only 1.3 (0x13) is."));
                }
                let variant = if *id { "argon2id" } else { "argon2d" };
                let memory_kib = u32::try_from(memory / 1024).map_err(|_| "Too much memory.")?;
                let passes = u32::try_from(*iterations).map_err(|_| "Too many iterations.")?;
                let derived = allcrypt::api::argon2(variant, key, salt, memory_kib, passes,
                                                    *parallelism, secret, associated, 32)?;
                Ok(derived.try_into().unwrap_or([0; 32]))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Cipher {
    Aes,
    Twofish,
    ChaCha20,
}

impl Cipher {
    pub fn name(self) -> &'static str {
        match self {
            Cipher::Aes => "aes",
            Cipher::Twofish => "twofish",
            Cipher::ChaCha20 => "chacha20",
        }
    }

    fn uuid(self) -> [u8; 16] {
        match self {
            Cipher::Aes => CIPHER_AES,
            Cipher::Twofish => CIPHER_TWOFISH,
            Cipher::ChaCha20 => CIPHER_CHACHA20,
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            Cipher::ChaCha20 => 12,
            _ => 16,
        }
    }

    fn block(self, key: &[u8; 32]) -> Result<Box<dyn BlockCipher>, String> {
        Ok(match self {
            Cipher::Aes => Box::new(AesCrypto::new(key.to_vec())?),
            Cipher::Twofish => Box::new(Twofish::new(key.to_vec())?),
            Cipher::ChaCha20 => return Err("ChaCha20 is not a block cipher.".to_string()),
        })
    }

    fn encrypt(self, key: &[u8; 32], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        if self == Cipher::ChaCha20 {
            let mut stream = Chacha::new(key.to_vec(), iv.to_vec(), 20)?;
            let mut out = Vec::with_capacity(data.len());
            stream.crypt(data, &mut out);
            return Ok(out);
        }
        let padded = allcrypt::api::pad_pkcs7(data, 16)?;
        let mut out = Vec::with_capacity(padded.len());
        self.block(key)?.cbc_encrypt(&padded, &mut out, iv.to_vec())?;
        Ok(out)
    }

    fn decrypt(self, key: &[u8; 32], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        if self == Cipher::ChaCha20 {
            return self.encrypt(key, iv, data);
        }
        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err("The payload is not a whole number of blocks.".to_string());
        }
        let mut out = Vec::with_capacity(data.len());
        self.block(key)?.cbc_decrypt(data, &mut out, iv.to_vec())?;
        allcrypt::api::unpad_pkcs7(&out, 16)
            .map_err(|_| "The payload's padding is wrong: the key is wrong.".to_string())
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub major: u16,
    pub minor: u16,
    pub cipher: Cipher,
    pub compressed: bool,
    pub master_seed: Vec<u8>,
    pub iv: Vec<u8>,
    pub kdf: Kdf,
    /// KDBX 3.1 only; in 4.x they are in the inner header.
    pub protected_stream_key: Vec<u8>,
    pub stream_start: Vec<u8>,
    pub inner_stream: u32,
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|end| *end <= self.data.len())
            .ok_or("The file ends early.")?;
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap_or([0; 2])))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap_or([0; 4])))
    }
}

fn le_u64(bytes: &[u8]) -> Result<u64, String> {
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| "An 8-byte field is not 8 bytes.")?))
}

fn le_u32(bytes: &[u8]) -> Result<u32, String> {
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| "A 4-byte field is not 4 bytes.")?))
}

/// KDBX 4's VariantDictionary: version 1.0, then (type, name, value)
/// items until a zero type byte.
fn read_dictionary(data: &[u8]) -> Result<Vec<(String, u8, Vec<u8>)>, String> {
    let mut cursor = Cursor { data, at: 0 };
    let version = cursor.u16()?;
    if version >> 8 != 1 {
        return Err(format!("A VariantDictionary of version {version:#06x}."));
    }
    let mut items = Vec::new();
    loop {
        let kind = cursor.u8()?;
        if kind == 0 {
            return Ok(items);
        }
        let name_len = cursor.u32()? as usize;
        let name = String::from_utf8(cursor.take(name_len)?.to_vec())
            .map_err(|_| "A dictionary name is not UTF-8.")?;
        let value_len = cursor.u32()? as usize;
        items.push((name, kind, cursor.take(value_len)?.to_vec()));
    }
}

fn write_dictionary(items: &[(&str, u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0x00, 0x01];
    for (name, kind, value) in items {
        out.push(*kind);
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    out.push(0);
    out
}

fn kdf_from_dictionary(data: &[u8]) -> Result<Kdf, String> {
    let items = read_dictionary(data)?;
    let get = |name: &str| items.iter().find(|(n, _, _)| n == name).map(|(_, _, v)| v.clone());
    let uuid = get("$UUID").ok_or("KDF parameters without a $UUID.")?;
    if uuid == KDF_AES || uuid == KDF_AES_KDBX3 {
        return Ok(Kdf::Aes {
            seed: get("S").ok_or("AES-KDF without a seed.")?,
            rounds: le_u64(&get("R").ok_or("AES-KDF without rounds.")?)?,
        });
    }
    if uuid == KDF_ARGON2D || uuid == KDF_ARGON2ID {
        return Ok(Kdf::Argon2 {
            id: uuid == KDF_ARGON2ID,
            salt: get("S").ok_or("Argon2 without a salt.")?,
            iterations: le_u64(&get("I").ok_or("Argon2 without iterations.")?)?,
            memory: le_u64(&get("M").ok_or("Argon2 without memory.")?)?,
            parallelism: le_u32(&get("P").ok_or("Argon2 without parallelism.")?)?,
            version: le_u32(&get("V").ok_or("Argon2 without a version.")?)?,
            secret: get("K").unwrap_or_default(),
            associated: get("A").unwrap_or_default(),
        });
    }
    Err(format!("Unknown key derivation function {}.", crate::hex(&uuid)))
}

fn kdf_to_dictionary(kdf: &Kdf) -> Vec<u8> {
    match kdf {
        Kdf::Aes { seed, rounds } => write_dictionary(&[
            ("$UUID", 0x42, KDF_AES.to_vec()),
            ("R", 0x05, rounds.to_le_bytes().to_vec()),
            ("S", 0x42, seed.clone()),
        ]),
        Kdf::Argon2 { id, salt, iterations, memory, parallelism, version, secret, associated } => {
            let uuid = if *id { KDF_ARGON2ID } else { KDF_ARGON2D };
            let mut items = vec![
                ("$UUID", 0x42, uuid.to_vec()),
                ("S", 0x42, salt.clone()),
                ("P", 0x04, parallelism.to_le_bytes().to_vec()),
                ("M", 0x05, memory.to_le_bytes().to_vec()),
                ("I", 0x05, iterations.to_le_bytes().to_vec()),
                ("V", 0x04, version.to_le_bytes().to_vec()),
            ];
            if !secret.is_empty() {
                items.push(("K", 0x42, secret.clone()));
            }
            if !associated.is_empty() {
                items.push(("A", 0x42, associated.clone()));
            }
            write_dictionary(&items)
        }
    }
}

/// The header and the bytes it occupied.
fn read_header(file: &[u8]) -> Result<(Header, usize), String> {
    let mut cursor = Cursor { data: file, at: 0 };
    if cursor.u32()? != SIGNATURE_1 {
        return Err("Not a KeePass database.".to_string());
    }
    let second = cursor.u32()?;
    if second == 0xB54B_FB65 {
        return Err("A KeePass 1.x (.kdb) database, which this does not read.".to_string());
    }
    if second != SIGNATURE_2 {
        return Err("Not a KeePass 2 database.".to_string());
    }
    let minor = cursor.u16()?;
    let major = cursor.u16()?;
    if !(3..=4).contains(&major) {
        return Err(format!("KDBX version {major}.{minor} is not supported."));
    }
    let mut header = Header {
        major, minor, cipher: Cipher::Aes, compressed: false, master_seed: Vec::new(),
        iv: Vec::new(), kdf: Kdf::Aes { seed: Vec::new(), rounds: 0 },
        protected_stream_key: Vec::new(), stream_start: Vec::new(), inner_stream: 0,
    };
    let mut kdbx3_rounds = None;
    loop {
        let id = cursor.u8()?;
        let length = if major >= 4 { cursor.u32()? as usize } else { cursor.u16()? as usize };
        let value = cursor.take(length)?;
        match id {
            0 => break,
            2 => {
                header.cipher = match value {
                    v if v == CIPHER_AES => Cipher::Aes,
                    v if v == CIPHER_TWOFISH => Cipher::Twofish,
                    v if v == CIPHER_CHACHA20 => Cipher::ChaCha20,
                    v => return Err(format!("Unknown cipher {}.", crate::hex(v))),
                }
            }
            3 => header.compressed = le_u32(value)? == 1,
            4 => header.master_seed = value.to_vec(),
            5 if major < 4 => {
                header.kdf = Kdf::Aes { seed: value.to_vec(), rounds: kdbx3_rounds.unwrap_or(0) }
            }
            6 if major < 4 => {
                let rounds = le_u64(value)?;
                kdbx3_rounds = Some(rounds);
                if let Kdf::Aes { rounds: r, .. } = &mut header.kdf {
                    *r = rounds;
                }
            }
            7 => header.iv = value.to_vec(),
            8 if major < 4 => header.protected_stream_key = value.to_vec(),
            9 if major < 4 => header.stream_start = value.to_vec(),
            10 if major < 4 => header.inner_stream = le_u32(value)?,
            11 if major >= 4 => header.kdf = kdf_from_dictionary(value)?,
            // A comment (1) and public custom data (12) carry nothing
            // the reader needs.
            1 | 12 => {}
            other => return Err(format!("Unknown header field {other}.")),
        }
    }
    if header.master_seed.len() != 32 {
        return Err("The master seed is not 32 bytes.".to_string());
    }
    if header.iv.len() != header.cipher.iv_len() {
        return Err(format!("A {}-byte IV for {}.", header.iv.len(), header.cipher.name()));
    }
    Ok((header, cursor.at))
}

fn write_header(header: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE_1.to_le_bytes());
    out.extend_from_slice(&SIGNATURE_2.to_le_bytes());
    out.extend_from_slice(&header.minor.to_le_bytes());
    out.extend_from_slice(&header.major.to_le_bytes());
    let four = header.major >= 4;
    let mut field = |id: u8, value: &[u8]| {
        out.push(id);
        if four {
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        } else {
            out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        }
        out.extend_from_slice(value);
    };
    field(2, &header.cipher.uuid());
    field(3, &u32::from(header.compressed).to_le_bytes());
    field(4, &header.master_seed);
    if four {
        field(7, &header.iv);
        field(11, &kdf_to_dictionary(&header.kdf));
    } else {
        let (seed, rounds) = match &header.kdf {
            Kdf::Aes { seed, rounds } => (seed.clone(), *rounds),
            Kdf::Argon2 { .. } => (Vec::new(), 0),
        };
        field(5, &seed);
        field(6, &rounds.to_le_bytes());
        field(7, &header.iv);
        field(8, &header.protected_stream_key);
        field(9, &header.stream_start);
        field(10, &header.inner_stream.to_le_bytes());
    }
    field(0, b"\r\n\r\n");
    out
}

// ----------------------------------------------------- the inner stream --

/// The keystream that hides protected values inside the XML (and, in
/// version 3.1, protected attachments in `Meta/Binaries`, which are
/// XML too; a version 4 attachment in the inner header is not under
/// it): one stream for the whole document, consumed in document order. 2 is Salsa20 with a fixed
/// nonce, 3 is ChaCha20 keyed from SHA-512 of the key.
pub enum InnerStream {
    None,
    Salsa20(Salsa20),
    ChaCha20(Chacha),
}

impl InnerStream {
    pub fn new(id: u32, key: &[u8]) -> Result<InnerStream, String> {
        match id {
            0 => Ok(InnerStream::None),
            2 => Ok(InnerStream::Salsa20(Salsa20::new(sha256(&[key]).to_vec(),
                                                      SALSA20_NONCE.to_vec())?)),
            3 => {
                let hash = sha512(&[key]);
                Ok(InnerStream::ChaCha20(Chacha::new(hash[..32].to_vec(), hash[32..44].to_vec(),
                                                     20)?))
            }
            1 => Err("The ArcFourVariant inner stream (KeePass 2.0's) is not supported.".into()),
            other => Err(format!("Unknown inner random stream {other}.")),
        }
    }

    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        match self {
            InnerStream::None => out.extend_from_slice(data),
            InnerStream::Salsa20(stream) => stream.crypt(data, &mut out),
            InnerStream::ChaCha20(stream) => stream.crypt(data, &mut out),
        }
        out
    }
}

// --------------------------------------------------------------- gzip --

pub fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return Err("The payload is not gzip.".to_string());
    }
    let flags = data[3];
    let mut at = 10;
    let skip_to = |at: &mut usize, n: usize| -> Result<(), String> {
        *at = at.checked_add(n).filter(|e| *e <= data.len()).ok_or("A truncated gzip header.")?;
        Ok(())
    };
    if flags & 4 != 0 {
        let length = data.get(at..at + 2).ok_or("A truncated gzip header.")?;
        let extra = usize::from(u16::from_le_bytes([length[0], length[1]]));
        skip_to(&mut at, 2 + extra)?;
    }
    for flag in [8u8, 16] {
        if flags & flag != 0 {
            let end = data[at..].iter().position(|b| *b == 0).ok_or("A truncated gzip name.")?;
            skip_to(&mut at, end + 1)?;
        }
    }
    if flags & 2 != 0 {
        skip_to(&mut at, 2)?;
    }
    let (out, used) = inflate::inflate(&data[at..], 1 << 30)?;
    match data.get(at + used..at + used + 8) {
        Some(trailer) => {
            if allcrypt::checksum::crc32(&out) != le_u32(&trailer[..4])? {
                return Err("The gzip CRC does not match.".to_string());
            }
        }
        // gokeepasslib writes a KDBX 3.1 attachment through gzip into a
        // base64 encoder it never closes, so the last one or two bytes
        // of the trailer are lost, and reads its own back by ignoring
        // the error. The deflate stream has ended properly - it carries
        // its own end marker - so what is lost is a check, not data;
        // a trailer that is there is still checked.
        None if data.len() - (at + used) < 8 => {}
        None => return Err("A gzip stream with no trailer.".to_string()),
    }
    Ok(out)
}

/// A gzip member of stored deflate blocks: a valid gzip stream that
/// every reader accepts, without the compressor a smaller one needs.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    let mut chunks = data.chunks(0xffff).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(chunk) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        let length = chunk.len() as u16;
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&(!length).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&allcrypt::checksum::crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

// --------------------------------------------------------- the payload --

/// An attachment as the version 4 inner header holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct InnerBinary {
    pub protected: bool,
    pub data: Vec<u8>,
}

pub struct Opened {
    pub header: Header,
    pub xml: Vec<u8>,
    /// The inner stream, at its start.
    pub stream: InnerStream,
    pub binaries: Vec<InnerBinary>,
    /// SHA-256 of the header, which a KDBX 3.1 document repeats in
    /// `Meta/HeaderHash` so that the header is authenticated after all.
    pub header_hash: [u8; 32],
}

fn block_key(base: &[u8], index: u64) -> Vec<u8> {
    sha512(&[&index.to_le_bytes(), base])
}

pub fn open(file: &[u8], credentials: &Credentials) -> Result<Opened, String> {
    let (header, header_len) = read_header(file)?;
    let header_bytes = &file[..header_len];
    let header_hash = sha256(&[header_bytes]);
    let transformed = header.kdf.transform(&credentials.composite())?;
    let key = sha256(&[&header.master_seed, &transformed]);
    let mut rest = Cursor { data: file, at: header_len };

    let (payload, stream_id, stream_key, binaries) = if header.major >= 4 {
        if rest.take(32)? != header_hash {
            return Err("The header's SHA-256 does not match: the file is damaged.".to_string());
        }
        let base = sha512(&[&header.master_seed, &transformed, &[1]]);
        let mac = Hmac::mac(SHA256::new(&[]), &block_key(&base, u64::MAX), header_bytes);
        if rest.take(32)? != mac {
            return Err("The header's HMAC does not match: the key is wrong \
                        (or the header was changed).".to_string());
        }
        let mut ciphertext = Vec::new();
        for index in 0u64.. {
            let tag = rest.take(32)?;
            let size = rest.u32()?;
            let data = rest.take(size as usize)?;
            let mut input = index.to_le_bytes().to_vec();
            input.extend_from_slice(&size.to_le_bytes());
            input.extend_from_slice(data);
            if Hmac::mac(SHA256::new(&[]), &block_key(&base, index), &input) != tag {
                return Err(format!("Block {index}'s HMAC does not match: the file is damaged."));
            }
            if size == 0 {
                break;
            }
            ciphertext.extend_from_slice(data);
        }
        let plain = header.cipher.decrypt(&key, &header.iv, &ciphertext)?;
        let plain = if header.compressed { gunzip(&plain)? } else { plain };
        let mut inner = Cursor { data: &plain, at: 0 };
        let mut stream_id = 0;
        let mut stream_key = Vec::new();
        let mut binaries = Vec::new();
        loop {
            let kind = inner.u8()?;
            let size = inner.u32()? as usize;
            let value = inner.take(size)?;
            match kind {
                0 => break,
                1 => stream_id = le_u32(value)?,
                2 => stream_key = value.to_vec(),
                3 => {
                    let (flags, data) = value.split_first().ok_or("An empty inner binary.")?;
                    binaries.push(InnerBinary { protected: flags & 1 != 0, data: data.to_vec() });
                }
                other => return Err(format!("Unknown inner header field {other}.")),
            }
        }
        (plain[inner.at..].to_vec(), stream_id, stream_key, binaries)
    } else {
        let plain = header.cipher.decrypt(&key, &header.iv, rest.take(file.len() - header_len)?)?;
        if plain.len() < 32 || plain[..32] != header.stream_start[..] {
            return Err("The stream start bytes do not match: the key is wrong.".to_string());
        }
        let mut blocks = Cursor { data: &plain, at: 32 };
        let mut joined = Vec::new();
        loop {
            let index = blocks.u32()?;
            let hash = blocks.take(32)?.to_vec();
            let size = blocks.u32()? as usize;
            if size == 0 {
                if hash.iter().any(|b| *b != 0) {
                    return Err("The final block's hash is not zero.".to_string());
                }
                break;
            }
            let data = blocks.take(size)?;
            if sha256(&[data])[..] != hash[..] {
                return Err(format!("Block {index}'s hash does not match: the file is damaged."));
            }
            joined.extend_from_slice(data);
        }
        let joined = if header.compressed { gunzip(&joined)? } else { joined };
        (joined, header.inner_stream, header.protected_stream_key.clone(), Vec::new())
    };

    // The inner stream covers the XML's protected elements only - in
    // 3.1 that includes protected attachments in `Meta/Binaries`. A
    // version 4 attachment's "protected" flag in the inner header asks
    // the reader to guard it in memory; it is stored as it is.
    let stream = InnerStream::new(stream_id, &stream_key)?;
    Ok(Opened { header, xml: payload, stream, binaries, header_hash })
}

/// What to write: everything but the per-file randomness, which comes
/// from the system unless given.
pub struct Plan {
    pub major: u16,
    pub minor: u16,
    pub cipher: Cipher,
    pub kdf: Kdf,
    pub compressed: bool,
    pub inner_stream: u32,
}

/// The header for a new file, with fresh seeds, IV and stream key.
pub fn new_header(plan: &Plan) -> Result<Header, String> {
    let random = |n: usize| allcrypt::api::random_bytes(n);
    Ok(Header {
        major: plan.major,
        minor: plan.minor,
        cipher: plan.cipher,
        compressed: plan.compressed,
        master_seed: random(32)?,
        iv: random(plan.cipher.iv_len())?,
        kdf: plan.kdf.clone(),
        protected_stream_key: if plan.major < 4 { random(32)? } else { Vec::new() },
        stream_start: if plan.major < 4 { random(32)? } else { Vec::new() },
        inner_stream: plan.inner_stream,
    })
}

/// The header's SHA-256, for a KDBX 3.1 document's `HeaderHash`, before
/// the document is written.
pub fn header_hash(header: &Header) -> [u8; 32] {
    sha256(&[&write_header(header)])
}

/// Seal a document. `stream_key` is the inner stream's key for version
/// 4 (the header carries 3.1's), and `binaries` its attachments.
pub fn seal(header: &Header, credentials: &Credentials, xml: &[u8], stream_key: &[u8],
            binaries: &[InnerBinary]) -> Result<Vec<u8>, String> {
    let header_bytes = write_header(header);
    let transformed = header.kdf.transform(&credentials.composite())?;
    let key = sha256(&[&header.master_seed, &transformed]);
    let mut out = header_bytes.clone();
    if header.major >= 4 {
        let mut plain = Vec::new();
        let mut inner = |kind: u8, value: &[u8]| {
            plain.push(kind);
            plain.extend_from_slice(&(value.len() as u32).to_le_bytes());
            plain.extend_from_slice(value);
        };
        inner(1, &header.inner_stream.to_le_bytes());
        inner(2, stream_key);
        for binary in binaries {
            let mut value = vec![u8::from(binary.protected)];
            value.extend_from_slice(&binary.data);
            inner(3, &value);
        }
        inner(0, &[]);
        plain.extend_from_slice(xml);
        let plain = if header.compressed { gzip_stored(&plain) } else { plain };
        let ciphertext = header.cipher.encrypt(&key, &header.iv, &plain)?;

        let base = sha512(&[&header.master_seed, &transformed, &[1]]);
        out.extend_from_slice(&sha256(&[&header_bytes]));
        out.extend_from_slice(&Hmac::mac(SHA256::new(&[]), &block_key(&base, u64::MAX),
                                         &header_bytes));
        let mut blocks: Vec<&[u8]> = ciphertext.chunks(1 << 20).collect();
        blocks.push(&[]);
        for (index, data) in blocks.iter().enumerate() {
            let index = index as u64;
            let size = data.len() as u32;
            let mut input = index.to_le_bytes().to_vec();
            input.extend_from_slice(&size.to_le_bytes());
            input.extend_from_slice(data);
            out.extend_from_slice(&Hmac::mac(SHA256::new(&[]), &block_key(&base, index), &input));
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(data);
        }
    } else {
        let body = if header.compressed { gzip_stored(xml) } else { xml.to_vec() };
        let mut plain = header.stream_start.clone();
        let mut index = 0u32;
        for chunk in body.chunks(1 << 20) {
            plain.extend_from_slice(&index.to_le_bytes());
            plain.extend_from_slice(&sha256(&[chunk]));
            plain.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            plain.extend_from_slice(chunk);
            index += 1;
        }
        plain.extend_from_slice(&index.to_le_bytes());
        plain.extend_from_slice(&[0u8; 32]);
        plain.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&header.cipher.encrypt(&key, &header.iv, &plain)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_gzip_reads_back_at_every_boundary() {
        for length in [0, 1, 0xffff, 0x10000, 0x20001] {
            let data: Vec<u8> = (0..length).map(|i| (i * 7 % 251) as u8).collect();
            assert_eq!(gunzip(&gzip_stored(&data)).unwrap(), data, "{length}");
        }
    }

    #[test]
    fn test_key_files_of_each_kind() {
        let raw: Vec<u8> = (0..32).collect();
        assert_eq!(key_file(&raw).unwrap().to_vec(), raw);
        let hex = crate::hex(&raw);
        assert_eq!(key_file(hex.as_bytes()).unwrap().to_vec(), raw);
        let other = b"any other content at all";
        assert_eq!(key_file(other).unwrap(), sha256(&[other]));
        // 64 bytes that are not hex are hashed, not decoded.
        let not_hex = [b'z'; 64];
        assert_eq!(key_file(&not_hex).unwrap(), sha256(&[&not_hex]));
    }

    #[test]
    fn test_a_dictionary_round_trips() {
        let kdf = Kdf::Argon2 { id: true, salt: vec![1; 32], iterations: 2, memory: 1 << 20,
                                parallelism: 2, version: 0x13, secret: vec![9],
                                associated: vec![] };
        assert_eq!(kdf_from_dictionary(&kdf_to_dictionary(&kdf)).unwrap(), kdf);
    }
}
