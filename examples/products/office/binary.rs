//! The encryption of the binary Office formats, `.doc` ([MS-DOC]
//! 2.2.6) and `.xls` ([MS-XLS] 2.2.10), decrypted.
//!
//! Three schemes, from [MS-OFFCRYPTO] 2.3.6 and 2.3.7:
//!
//! - **RC4** (Office 97 and 2000; LibreOffice still writes it): MD5 of
//!   the UTF-16 password cut to 5 bytes, hashed sixteen times over with
//!   the salt, cut to 5 bytes again - so the key has 40 bits of
//!   entropy whatever its length - and then one RC4 key per block, the
//!   MD5 of those 5 bytes and the block number.
//! - **RC4 CryptoAPI** (Office 2002 on): SHA-1 of the salt and the
//!   password, and per block the SHA-1 of that and the block number,
//!   cut to the key length; a 40-bit key is padded with eleven zero
//!   bytes to the 128 bits RC4 is given.
//! - **XOR obfuscation** (`.xls` only here): the library's
//!   `stream_ciphers::office_xor` - a 16-bit verifier of the password
//!   and a 16-byte array derived from it, XORed into every byte and
//!   rotated, which is to say no encryption at all.
//!
//! In both RC4 schemes the keystream belongs to the stream position: a
//! new key every 512 bytes of a Word stream and every 1024 of a
//! workbook, and bytes that are not encrypted - the first 68 of a Word
//! document, every record header in a workbook - still use up their
//! keystream.

use allcrypt::api::AnyHash;
use allcrypt::hash_functions::HashFunction;
use allcrypt::stream_ciphers::office_xor::OfficeXor;
use allcrypt::stream_ciphers::rc4::RC4;
use allcrypt::stream_ciphers::StreamCipher;

use crate::cfb::Storage;
use crate::ooxml::utf16;

fn digest(hash: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut h = AnyHash::new(hash).expect("a built-in hash");
    for part in parts {
        h.update(part);
    }
    h.digest()
}

/// RC4 of `data` under `key`. A key the cipher refuses - empty, or past
/// 256 bytes - is an error, not an empty result that the verifier would
/// then read as a wrong password.
fn rc4(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    RC4::new(key)?.crypt(data, &mut out);
    Ok(out)
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "The encryption header is truncated.".to_string())
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))
        .ok_or_else(|| "The encryption header is truncated.".to_string())
}

/// How a binary document is encrypted.
#[derive(Clone, Debug)]
pub enum Scheme {
    Rc4 { salt: Vec<u8>, verifier: Vec<u8>, verifier_hash: Vec<u8> },
    CryptoApi { version: (u16, u16), key_bits: u32, provider: String,
                salt: Vec<u8>, verifier: Vec<u8>, verifier_hash: Vec<u8> },
    Xor { key: u16, verifier: u16 },
}

impl Scheme {
    pub fn describe(&self) -> String {
        match self {
            Scheme::Rc4 { .. } => "RC4 (Office 97/2000), MD5, a 40-bit key".to_string(),
            Scheme::CryptoApi { version, key_bits, provider, .. } => {
                format!("RC4 CryptoAPI, version {}.{}, SHA-1, a {key_bits}-bit key, provider {:?}",
                        version.0, version.1, provider)
            }
            Scheme::Xor { .. } => "XOR obfuscation (method 1)".to_string(),
        }
    }

    /// The RC4 encryption header: what follows a Word table stream's
    /// first bytes, or a FilePass record's encryption type.
    fn parse_rc4(header: &[u8]) -> Result<Scheme, String> {
        let version = (u16_at(header, 0)?, u16_at(header, 2)?);
        let take = |at: usize, n: usize| header.get(at..at + n).map(<[u8]>::to_vec)
            .ok_or_else(|| "The encryption header is truncated.".to_string());
        match version {
            (1, 1) => Ok(Scheme::Rc4 { salt: take(4, 16)?, verifier: take(20, 16)?,
                                       verifier_hash: take(36, 16)? }),
            (2..=4, 2) => {
                let header_size = u32_at(header, 8)? as usize;
                let h = header.get(12..12 + header_size).ok_or("The encryption header is \
                                                                truncated.")?;
                let alg_id = u32_at(h, 8)?;
                if alg_id != 0x6801 && alg_id != 0 {
                    return Err(format!("CryptoAPI encryption with AlgID {alg_id:#x}; only RC4 \
                                        is defined for the binary formats."));
                }
                let key_bits = match u32_at(h, 16)? {
                    0 => 40,
                    bits @ 40..=128 if bits % 8 == 0 => bits,
                    bits => return Err(format!("An RC4 key of {bits} bits.")),
                };
                let units: Vec<u16> = h.get(32..).unwrap_or(&[]).chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
                let v = 12 + header_size;
                if u32_at(header, v)? != 16 {
                    return Err("A verifier salt that is not 16 bytes.".to_string());
                }
                Ok(Scheme::CryptoApi {
                    version, key_bits, provider: String::from_utf16_lossy(&units),
                    salt: take(v + 4, 16)?, verifier: take(v + 20, 16)?,
                    // An RC4 verifier hash is SHA-1's 20 bytes, unpadded.
                    verifier_hash: take(v + 40, 20)?,
                })
            }
            (major, minor) => Err(format!("Encryption header version {major}.{minor} is not \
                                           RC4 or RC4 CryptoAPI.")),
        }
    }
}

// ---------------------------------------------------------------- RC4 --

/// The per-block RC4 keys of either scheme, for one password.
pub struct Keys {
    /// RC4: the five bytes every block key starts from. CryptoAPI: H0.
    base: Vec<u8>,
    cryptoapi_bits: Option<u32>,
}

impl Keys {
    pub fn new(scheme: &Scheme, password: &[u8]) -> Result<Keys, String> {
        let password = utf16(password)?;
        match scheme {
            Scheme::Rc4 { salt, .. } => {
                // [MS-OFFCRYPTO] 2.3.6.2.
                let h0 = digest("md5", &[&password]);
                let mut buffer = Vec::with_capacity(16 * 21);
                for _ in 0..16 {
                    buffer.extend_from_slice(&h0[..5]);
                    buffer.extend_from_slice(salt);
                }
                Ok(Keys { base: digest("md5", &[&buffer])[..5].to_vec(), cryptoapi_bits: None })
            }
            Scheme::CryptoApi { salt, key_bits, .. } => Ok(Keys {
                // [MS-OFFCRYPTO] 2.3.5.2.
                base: digest("sha1", &[salt, &password]),
                cryptoapi_bits: Some(*key_bits),
            }),
            Scheme::Xor { .. } => Err("XOR obfuscation has no RC4 keys.".to_string()),
        }
    }

    pub fn block(&self, block: u32) -> Vec<u8> {
        let b = block.to_le_bytes();
        match self.cryptoapi_bits {
            None => digest("md5", &[&self.base, &b]),
            Some(bits) => {
                let h = digest("sha1", &[&self.base, &b]);
                if bits == 40 {
                    // CryptoAPI's 40-bit RC4 is a 128-bit key whose last
                    // eleven bytes are zero.
                    let mut key = h[..5].to_vec();
                    key.resize(16, 0);
                    key
                } else {
                    h[..bits as usize / 8].to_vec()
                }
            }
        }
    }

    /// The keystream for stream positions `0..length`, in blocks of
    /// `block_size`.
    pub fn keystream(&self, length: usize, block_size: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(length);
        let zeros = vec![0u8; block_size];
        let mut block = 0u32;
        while out.len() < length {
            let n = block_size.min(length - out.len());
            out.extend(rc4(&self.block(block), &zeros[..n])?);
            block += 1;
        }
        Ok(out)
    }

    /// Whether the password is right: the verifier and its hash are one
    /// RC4 stream under block 0's key.
    pub fn verify(&self, scheme: &Scheme) -> Result<bool, String> {
        let (verifier, hash, name) = match scheme {
            Scheme::Rc4 { verifier, verifier_hash, .. } => (verifier, verifier_hash, "md5"),
            Scheme::CryptoApi { verifier, verifier_hash, .. } => (verifier, verifier_hash, "sha1"),
            Scheme::Xor { .. } => return Ok(false),
        };
        let plain = rc4(&self.block(0), &[verifier.as_slice(), hash.as_slice()].concat())?;
        let (v, h) = plain.split_at(16);
        Ok(digest(name, &[v]) == h)
    }
}

fn xor_into(data: &mut [u8], keystream: &[u8], range: std::ops::Range<usize>) {
    for i in range {
        data[i] ^= keystream[i];
    }
}

// ----------------------------------------------------------------- Word --

/// The first 68 bytes of a Word document - the FIB's fixed part - are
/// never encrypted ([MS-DOC] 2.2.6.2).
const FIB_CLEAR: usize = 0x44;
const WORD_BLOCK: usize = 512;

pub struct Word {
    pub scheme: Scheme,
    table: String,
    header_length: usize,
}

pub fn word_info(root: &Storage) -> Result<Word, String> {
    let document = root.stream("WordDocument").ok_or("No WordDocument stream.")?;
    if u16_at(document, 0)? != 0xa5ec {
        return Err("WordDocument does not start with the FIB's 0xA5EC.".to_string());
    }
    let flags = u16_at(document, 10)?;
    if flags & 0x0100 == 0 {
        return Err("The document is not encrypted.".to_string());
    }
    if flags & 0x8000 != 0 {
        return Err("The document is XOR-obfuscated, which is not supported for Word.".into());
    }
    let table = if flags & 0x0200 != 0 { "1Table" } else { "0Table" };
    let header_length = u32_at(document, 14)? as usize;
    let header = root.stream(table).ok_or_else(|| format!("No {table} stream."))?;
    let scheme = Scheme::parse_rc4(header.get(..header_length).ok_or("The encryption header \
                                                                       is longer than the \
                                                                       table stream.")?)?;
    Ok(Word { scheme, table: table.to_string(), header_length })
}

/// The document with its streams decrypted and the FIB saying so.
pub fn decrypt_word(root: &Storage, password: &[u8]) -> Result<Storage, String> {
    let info = word_info(root)?;
    let keys = Keys::new(&info.scheme, password)?;
    if !keys.verify(&info.scheme)? {
        return Err("Wrong password.".to_string());
    }
    let mut out = root.clone();
    for name in ["WordDocument", info.table.as_str(), "Data"] {
        let Some(stream) = out.stream_mut(name) else { continue };
        let keystream = keys.keystream(stream.len(), WORD_BLOCK)?;
        let length = stream.len();
        let start = match name {
            "WordDocument" => FIB_CLEAR.min(length),
            // The encryption header is the table stream's first bytes;
            // nothing refers to them once the document is plain.
            _ if name == info.table => {
                stream[..info.header_length].fill(0);
                info.header_length
            }
            _ => 0,
        };
        xor_into(stream, &keystream, start..length);
    }
    let document = out.stream_mut("WordDocument").expect("checked above");
    let flags = u16::from_le_bytes([document[10], document[11]]) & !0x8100;
    document[10..12].copy_from_slice(&flags.to_le_bytes());
    document[14..18].fill(0);
    Ok(out)
}

// ---------------------------------------------------------------- Excel --

const BOF: u16 = 0x0809;
const FILE_PASS: u16 = 0x002f;
const BOUND_SHEET: u16 = 0x0085;
/// Records that are never encrypted ([MS-XLS] 2.2.10): BOF, FilePass,
/// UsrExcl, FileLock, InterfaceHdr, RRDInfo, RRDHead.
const CLEAR_RECORDS: [u16; 7] = [BOF, FILE_PASS, 0x0194, 0x0195, 0x00e1, 0x0196, 0x0138];
const EXCEL_BLOCK: usize = 1024;

/// A workbook's records: type, the body's position, its length.
fn records(stream: &[u8]) -> Result<Vec<(u16, usize, usize)>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= stream.len() {
        let kind = u16_at(stream, at)?;
        let size = u16_at(stream, at + 2)? as usize;
        if at + 4 + size > stream.len() {
            return Err(format!("A record at {at} runs past the end of the workbook."));
        }
        out.push((kind, at + 4, size));
        at += 4 + size;
    }
    Ok(out)
}

pub fn excel_info(root: &Storage) -> Result<Scheme, String> {
    let book = root.stream("Workbook").ok_or("No Workbook stream (BIFF8).")?;
    let records = records(book)?;
    if records.first().map(|r| r.0) != Some(BOF) {
        return Err("The workbook does not start with BOF.".to_string());
    }
    let &(_, at, size) = records.iter().take_while(|r| r.0 != 0x000a)
        .find(|r| r.0 == FILE_PASS).ok_or("The workbook is not encrypted: no FilePass.")?;
    let body = &book[at..at + size];
    match u16_at(body, 0)? {
        0 => Ok(Scheme::Xor { key: u16_at(body, 2)?, verifier: u16_at(body, 4)? }),
        1 => Scheme::parse_rc4(&body[2..]),
        other => Err(format!("FilePass encryption type {other}.")),
    }
}

pub fn decrypt_excel(root: &Storage, password: &[u8]) -> Result<Storage, String> {
    let scheme = excel_info(root)?;
    let mut out = root.clone();
    let book = out.stream_mut("Workbook").expect("checked above");
    let records = records(book)?;
    // What is encrypted: every record body but the clear ones, and a
    // BoundSheet8 after its stream position (lbPlyPos), which is read
    // before anything is decrypted.
    let mut ranges = Vec::new();
    for &(kind, at, size) in &records {
        match kind {
            k if CLEAR_RECORDS.contains(&k) => {}
            BOUND_SHEET => ranges.push((at + 4.min(size), at + size, true)),
            _ => ranges.push((at, at + size, false)),
        }
    }
    match &scheme {
        Scheme::Xor { key, verifier } => {
            let xor = OfficeXor::new(&xor_password(password)?)?;
            if xor.verifier() != *verifier || xor.key() != *key {
                return Err("Wrong password.".to_string());
            }
            for &(start, end, bound_sheet) in &ranges {
                // The array index is the position just past the record,
                // and past a BoundSheet8's four clear bytes as well -
                // as msoffcrypto-tool and Excel's files have it.
                xor.decrypt(&mut book[start..end], end + if bound_sheet { 4 } else { 0 });
            }
        }
        _ => {
            let keys = Keys::new(&scheme, password)?;
            if !keys.verify(&scheme)? {
                return Err("Wrong password.".to_string());
            }
            let keystream = keys.keystream(book.len(), EXCEL_BLOCK)?;
            for &(start, end, _) in &ranges {
                xor_into(book, &keystream, start..end);
            }
        }
    }
    // FilePass goes, its bytes kept so that every stream position in the
    // workbook stays where it was: a record of type 0, all zeros, which
    // is what msoffcrypto-tool writes too.
    for &(kind, at, size) in &records {
        if kind == FILE_PASS {
            book[at - 4..at - 2].fill(0);
            book[at..at + size].fill(0);
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------ XOR --

/// The password as XOR obfuscation takes it: single bytes, so text whose
/// characters are all below U+0100.
fn xor_password(password: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(password).map_err(|_| "The password is not UTF-8.")?;
    let bytes: Option<Vec<u8>> = text.chars().map(|c| u8::try_from(u32::from(c)).ok()).collect();
    bytes.ok_or_else(|| "An XOR-obfuscated workbook's password is single bytes.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rc4` swallowed the cipher's refusal of its key and returned
    /// nothing, so an empty key would have decrypted to nothing and
    /// the verifier would have said "wrong password". Every key here is
    /// five bytes or more, so no test reached the empty result.
    #[test]
    fn test_rc4_refuses_a_key_the_cipher_refuses() {
        assert!(rc4(&[], b"data").is_err());
        assert_eq!(rc4(b"key", b"data").unwrap().len(), 4);
    }

    /// A 40-bit CryptoAPI key is five bytes of the hash and eleven
    /// zeros, and a key size of 0 in the header means 40 bits
    /// ([MS-OFFCRYPTO] 2.3.5.2 and 2.3.2). Every CryptoAPI document a
    /// witness here wrote has a 128-bit key, so this is the only check
    /// of either.
    #[test]
    fn test_a_40_bit_cryptoapi_key() {
        let mut header = vec![4, 0, 2, 0, 0x0c, 0, 0, 0];
        let mut h = vec![0u8; 32];
        h[8..12].copy_from_slice(&0x6801u32.to_le_bytes());
        h[12..16].copy_from_slice(&0x8004u32.to_le_bytes());
        h.extend_from_slice(&[0, 0]);
        header.extend_from_slice(&(h.len() as u32).to_le_bytes());
        header.extend_from_slice(&h);
        header.extend_from_slice(&16u32.to_le_bytes());
        header.extend_from_slice(&[0x5a; 16 + 16]);
        header.extend_from_slice(&20u32.to_le_bytes());
        header.extend_from_slice(&[0xa5; 20]);
        let scheme = Scheme::parse_rc4(&header).unwrap();
        assert!(matches!(scheme, Scheme::CryptoApi { key_bits: 40, .. }), "{scheme:?}");
        let keys = Keys::new(&scheme, b"pw").unwrap();
        let key = keys.block(3);
        let h = digest("sha1", &[&keys.base, &3u32.to_le_bytes()]);
        assert_eq!(&key[..5], &h[..5]);
        assert_eq!(&key[5..], &[0; 11]);
    }
}
