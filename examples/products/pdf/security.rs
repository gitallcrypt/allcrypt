//! The PDF standard security handler, revisions 2 to 6 (ISO 32000-2
//! section 7.6.4, and Adobe's extension level 3 for revision 5).
//!
//! | R | V | cipher              | file key from the password              |
//! |---|---|---------------------|-----------------------------------------|
//! | 2 | 1 | RC4, 40 bits        | MD5 of password, O, P, ID               |
//! | 3 | 2 | RC4, 40-128 bits    | the same, then MD5 fifty more times     |
//! | 4 | 4 | RC4 or AES-128      | as 3, through crypt filters             |
//! | 5 | 5 | AES-256             | SHA-256 of password and salt (withdrawn)|
//! | 6 | 5 | AES-256             | the 2.B loop of SHA-256/384/512 and AES |
//!
//! Up to revision 4 every object is encrypted under its own key,
//! `MD5(file key || object number || generation [|| "sAlT"])` cut to
//! `n + 5` bytes, and both passwords lead to the same file key: the
//! owner password decrypts `O` into the user password. From revision 5
//! the file key is random, wrapped twice - in `UE` under the user
//! password and in `OE` under the owner's - and every object uses it
//! directly.
//!
//! Revisions 2 to 4 are broken in several ways: 40-bit RC4 is
//! exhaustible, RC4's keystream is biased, the user password check
//! (`U`) is known plaintext for the file key, and revision 5's single
//! SHA-256 made password guessing fast enough that Adobe replaced it
//! within two years. All of it is here because those files exist.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::hash_functions::md5::MD5;
use allcrypt::hash_functions::sha2::{SHA256, SHA384, SHA512};
use allcrypt::hash_functions::HashFunction;
use allcrypt::stream_ciphers::rc4::RC4;
use allcrypt::stream_ciphers::StreamCipher;

use crate::object::{get, Dict, Object};

/// The 32 bytes a short password is padded with. Taken from qpdf's
/// `QPDF_encryption.cc` (`padding_string`), which quotes the standard;
/// every revision 2-4 file in the fixtures depends on it being right.
const PADDING: [u8; 32] = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
];

fn md5(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = MD5::new(&[]);
    for part in parts {
        hash.update(part);
    }
    hash.digest()
}

/// RC4 of `data` under `key`. A key the cipher refuses - empty, or past
/// 256 bytes - is an error, not an empty result that a verifier would
/// then read as a wrong password.
fn rc4(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    RC4::new(key.to_vec())?.crypt(data, &mut out);
    Ok(out)
}

fn pad(password: &[u8]) -> [u8; 32] {
    let mut out = PADDING;
    let n = password.len().min(32);
    out[..n].copy_from_slice(&password[..n]);
    out[n..].copy_from_slice(&PADDING[..32 - n]);
    out
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Method {
    Identity,
    Rc4,
    AesV2,
    AesV3,
}

impl Method {
    pub fn name(self) -> &'static str {
        match self {
            Method::Identity => "none",
            Method::Rc4 => "RC4",
            Method::AesV2 => "AES-128",
            Method::AesV3 => "AES-256",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Which {
    User,
    Owner,
}

#[derive(Clone, Debug)]
pub struct Security {
    pub v: i64,
    pub r: i64,
    pub key: Vec<u8>,
    pub streams: Method,
    pub strings: Method,
    /// `/EFF`: embedded file streams that name no crypt filter of their
    /// own. The streams' method when absent.
    pub files: Method,
    /// `/CF`, for a stream whose `/Crypt` filter names one.
    pub filters: Vec<(Vec<u8>, Method)>,
    pub encrypt_metadata: bool,
    pub permissions: i32,
    /// Revisions 5 and 6: whether `/Perms` decrypted to `/P`. A
    /// mismatch means the permissions were edited; qpdf warns and
    /// carries on, and so does this, saying so in `info`.
    pub perms_match: Option<bool>,
}

fn bytes<'a>(dict: &'a Dict, key: &str) -> Result<&'a [u8], String> {
    get(dict, key).and_then(Object::as_bytes).ok_or(format!("The /Encrypt dictionary has no /{key}."))
}

fn int(dict: &Dict, key: &str) -> Option<i64> {
    get(dict, key).and_then(Object::as_int)
}

/// A crypt filter's method, by name, from `/CF`.
fn filter_method(dict: &Dict, name: Option<&[u8]>) -> Result<Method, String> {
    let name = match name {
        None | Some(b"Identity") => return Ok(Method::Identity),
        Some(name) => name,
    };
    let filter = get(dict, "CF").and_then(Object::as_dict)
        .and_then(|cf| cf.iter().find(|(k, _)| k == name).map(|(_, v)| v))
        .and_then(Object::as_dict)
        .ok_or(format!("Crypt filter /{} is not in /CF.", String::from_utf8_lossy(name)))?;
    match get(filter, "CFM").and_then(Object::as_name) {
        Some(b"V2") => Ok(Method::Rc4),
        Some(b"AESV2") => Ok(Method::AesV2),
        Some(b"AESV3") => Ok(Method::AesV3),
        Some(b"None") | None => Ok(Method::Identity),
        Some(other) => Err(format!("Crypt filter method /{} is not supported.",
                                   String::from_utf8_lossy(other))),
    }
}

// ------------------------------------------------------ revisions 2-4 --

/// The file key's length in bytes up to revision 4, read as qpdf reads
/// it: 40 bits at V 1, 128 at V 4 whatever `/Length` says (the crypt
/// filter's own `/Length` is in bytes, and writers disagree on it), and
/// at V 2 and 3 `/Length` when it is a whole number of bytes from 40 to
/// 128 bits. Anything else is taken as 128 bits rather than refused.
fn key_length(v: i64, bits: Option<i64>) -> usize {
    match (v, bits) {
        (1, _) => 5,
        (4, _) => 16,
        (_, Some(bits)) if (40..=128).contains(&bits) && bits % 8 == 0 => bits as usize / 8,
        _ => 16,
    }
}

struct Legacy<'a> {
    r: i64,
    length: usize,
    o: &'a [u8],
    p: i32,
    id: &'a [u8],
    encrypt_metadata: bool,
}

impl Legacy<'_> {
    /// Algorithm 2: the file key from a user password.
    fn file_key(&self, password: &[u8]) -> Vec<u8> {
        let mut parts: Vec<&[u8]> = Vec::new();
        let padded = pad(password);
        let p = self.p.to_le_bytes();
        parts.push(&padded);
        parts.push(&self.o[..32.min(self.o.len())]);
        parts.push(&p);
        parts.push(self.id);
        let all_ones = [0xffu8; 4];
        if self.r >= 4 && !self.encrypt_metadata {
            parts.push(&all_ones);
        }
        let mut key = md5(&parts);
        if self.r >= 3 {
            for _ in 0..50 {
                key = md5(&[&key[..self.length]]);
            }
        }
        key.truncate(self.length);
        key
    }

    /// Algorithms 4 and 5: what `U` must be for this file key.
    fn u_for(&self, key: &[u8]) -> Result<Vec<u8>, String> {
        if self.r == 2 {
            return rc4(key, &PADDING);
        }
        let mut value = rc4(key, &md5(&[&PADDING, self.id]))?;
        for i in 1..=19u8 {
            let round: Vec<u8> = key.iter().map(|k| k ^ i).collect();
            value = rc4(&round, &value)?;
        }
        // Sixteen arbitrary bytes complete the 32; these are what qpdf
        // and Acrobat write.
        value.extend_from_slice(&PADDING[..16]);
        Ok(value)
    }

    fn user_matches(&self, key: &[u8], u: &[u8]) -> Result<bool, String> {
        let expected = self.u_for(key)?;
        let compared = if self.r == 2 { 32 } else { 16 };
        Ok(u.len() >= compared && expected[..compared] == u[..compared])
    }

    /// Algorithm 3's first steps: the RC4 key the owner password gives.
    fn owner_key(&self, owner: &[u8]) -> Vec<u8> {
        let mut key = md5(&[&pad(owner)]);
        if self.r >= 3 {
            for _ in 0..50 {
                key = md5(&[&key]);
            }
        }
        key.truncate(self.length);
        key
    }

    /// Algorithm 7: the padded user password `O` hides under the owner's.
    fn user_from_owner(&self, owner: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.owner_key(owner);
        if self.r == 2 {
            return rc4(&key, self.o);
        }
        let mut value = self.o.to_vec();
        for i in (0..=19u8).rev() {
            let round: Vec<u8> = key.iter().map(|k| k ^ i).collect();
            value = rc4(&round, &value)?;
        }
        Ok(value)
    }

    /// Algorithm 3: `O` for an owner and a user password.
    fn o_for(&self, owner: &[u8], user: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.owner_key(owner);
        let mut value = rc4(&key, &pad(user))?;
        if self.r >= 3 {
            for i in 1..=19u8 {
                let round: Vec<u8> = key.iter().map(|k| k ^ i).collect();
                value = rc4(&round, &value)?;
            }
        }
        Ok(value)
    }
}

// ------------------------------------------------------ revisions 5-6 --

fn aes_cbc_no_padding(key: &[u8], iv: &[u8], data: &[u8], decrypt: bool)
                      -> Result<Vec<u8>, String> {
    let mut cipher = AesCrypto::new(key.to_vec())?;
    let mut out = Vec::with_capacity(data.len());
    if decrypt {
        cipher.cbc_decrypt(data, &mut out, iv.to_vec())?;
    } else {
        cipher.cbc_encrypt(data, &mut out, iv.to_vec())?;
    }
    Ok(out)
}

/// The password hash: SHA-256 for revision 5, Algorithm 2.B for 6.
fn hash(r: i64, password: &[u8], salt: &[u8], udata: &[u8]) -> Result<Vec<u8>, String> {
    let mut first = SHA256::new(&[]);
    first.update(password);
    first.update(salt);
    first.update(udata);
    let mut k = first.digest();
    if r == 5 {
        return Ok(k);
    }
    let mut round = 0u32;
    loop {
        let mut k1 = Vec::with_capacity(64 * (password.len() + k.len() + udata.len()));
        for _ in 0..64 {
            k1.extend_from_slice(password);
            k1.extend_from_slice(&k);
            k1.extend_from_slice(udata);
        }
        let e = aes_cbc_no_padding(&k[..16], &k[16..32], &k1, false)?;
        // The first 16 bytes of E as a big number, mod 3: a byte's
        // weight 256 is 1 mod 3, so the sum of the bytes will do.
        let selector = e[..16].iter().map(|&b| u32::from(b)).sum::<u32>() % 3;
        k = match selector {
            0 => {
                let mut h = SHA256::new(&[]);
                h.update(&e);
                h.digest()
            }
            1 => {
                let mut h = SHA384::new(&[]);
                h.update(&e);
                h.digest()
            }
            _ => {
                let mut h = SHA512::new(&[], 512);
                h.update(&e);
                h.digest()
            }
        };
        round += 1;
        // At least 64 rounds, then until the last byte of E is no more
        // than the round number less 32.
        if round >= 64 && u32::from(*e.last().unwrap_or(&0)) <= round - 32 {
            break;
        }
    }
    k.truncate(32);
    Ok(k)
}

/// A password as revisions 5 and 6 take it: UTF-8, at most 127 bytes.
/// (SASLprep is not applied, so a password with characters it would
/// change does not open a file whose writer applied it.)
fn modern_password(password: &[u8]) -> &[u8] {
    &password[..password.len().min(127)]
}

// ---------------------------------------------------------- open, seal --

impl Security {
    /// The method of a crypt filter a stream names. `None` for a name
    /// that is neither `/Identity` nor in `/CF`.
    pub fn named(&self, name: &[u8]) -> Option<Method> {
        if name == b"Identity" {
            return Some(Method::Identity);
        }
        self.filters.iter().find(|(n, _)| n == name).map(|(_, m)| *m)
    }

    /// Authenticate `password` - as the owner password first, then the
    /// user's - against an `/Encrypt` dictionary.
    pub fn open(encrypt: &Dict, id: &[u8], password: &[u8]) -> Result<(Security, Which), String> {
        match get(encrypt, "Filter").and_then(Object::as_name) {
            Some(b"Standard") => {}
            other => return Err(format!("Security handler {:?} is not supported; only \
                                         /Standard is.",
                                        other.map(String::from_utf8_lossy))),
        }
        let v = int(encrypt, "V").unwrap_or(0);
        let r = int(encrypt, "R").ok_or("The /Encrypt dictionary has no /R.")?;
        let p = int(encrypt, "P").ok_or("The /Encrypt dictionary has no /P.")? as i32;
        let encrypt_metadata = !matches!(get(encrypt, "EncryptMetadata"), Some(Object::Bool(false)));
        let o = bytes(encrypt, "O")?;
        let u = bytes(encrypt, "U")?;

        let (streams, strings) = match v {
            1 | 2 => (Method::Rc4, Method::Rc4),
            4 | 5 => (filter_method(encrypt, get(encrypt, "StmF").and_then(Object::as_name))?,
                      filter_method(encrypt, get(encrypt, "StrF").and_then(Object::as_name))?),
            other => return Err(format!("Encryption /V {other} is not supported.")),
        };
        let mut filters = Vec::new();
        let mut files = streams;
        if v >= 4 {
            if let Some(cf) = get(encrypt, "CF").and_then(Object::as_dict) {
                for (name, _) in cf {
                    filters.push((name.clone(), filter_method(encrypt, Some(name))?));
                }
            }
            if let Some(name) = get(encrypt, "EFF").and_then(Object::as_name) {
                files = filter_method(encrypt, Some(name))?;
            }
        }

        if r >= 5 {
            if o.len() < 48 || u.len() < 48 {
                return Err("/O and /U are shorter than revision 5's 48 bytes.".to_string());
            }
            let password = modern_password(password);
            // ISO 32000-2 Algorithm 2.A tests the owner password first, and
            // so does qpdf: a password that is both is reported as the
            // owner's.
            let (which, intermediate, wrapped) =
                if hash(r, password, &o[32..40], &u[..48])? == o[..32] {
                    (Which::Owner, hash(r, password, &o[40..48], &u[..48])?, bytes(encrypt, "OE")?)
                } else if hash(r, password, &u[32..40], &[])? == u[..32] {
                    (Which::User, hash(r, password, &u[40..48], &[])?, bytes(encrypt, "UE")?)
                } else {
                    return Err("Wrong password.".to_string());
                };
            let key = aes_cbc_no_padding(&intermediate, &[0; 16], wrapped, true)?;
            let mut security = Security { v, r, key, streams, strings, files, filters,
                                          encrypt_metadata, permissions: p, perms_match: None };
            security.perms_match = Some(security.check_perms(encrypt).is_ok());
            return Ok((security, which));
        }

        let legacy = Legacy { r, length: key_length(v, int(encrypt, "Length")), o, p, id,
                              encrypt_metadata };
        // Owner first, as above: the empty password is commonly both.
        let recovered = legacy.user_from_owner(password)?;
        let owner_key = legacy.file_key(&recovered);
        let (key, which) = if legacy.user_matches(&owner_key, u)? {
            (owner_key, Which::Owner)
        } else {
            let user_key = legacy.file_key(password);
            if !legacy.user_matches(&user_key, u)? {
                return Err("Wrong password.".to_string());
            }
            (user_key, Which::User)
        };
        Ok((Security { v, r, key, streams, strings, files, filters, encrypt_metadata,
                       permissions: p, perms_match: None }, which))
    }

    /// `/Perms` repeats the permissions under the file key.
    fn check_perms(&self, encrypt: &Dict) -> Result<(), String> {
        let perms = bytes(encrypt, "Perms")?;
        if perms.len() < 16 {
            return Err("/Perms is shorter than 16 bytes.".to_string());
        }
        let mut cipher = AesCrypto::new(self.key.clone())?;
        let mut plain = Vec::new();
        cipher.ecb_decrypt(&perms[..16], &mut plain)?;
        if &plain[9..12] != b"adb" {
            return Err("/Perms does not decrypt to its marker: the file key is wrong.".into());
        }
        if plain[..4] != self.permissions.to_le_bytes() {
            return Err("/Perms disagrees with /P: the permissions were changed.".to_string());
        }
        Ok(())
    }

    fn object_key(&self, number: u32, generation: u16, method: Method) -> Vec<u8> {
        if method == Method::AesV3 {
            return self.key.clone();
        }
        let n = number.to_le_bytes();
        let g = generation.to_le_bytes();
        let mut parts: Vec<&[u8]> = vec![&self.key, &n[..3], &g];
        if method == Method::AesV2 {
            parts.push(b"sAlT");
        }
        let mut key = md5(&parts);
        key.truncate((self.key.len() + 5).min(16));
        key
    }

    pub fn decrypt(&self, number: u32, generation: u16, method: Method, data: &[u8])
                   -> Result<Vec<u8>, String> {
        match method {
            Method::Identity => Ok(data.to_vec()),
            Method::Rc4 => rc4(&self.object_key(number, generation, method), data),
            Method::AesV2 | Method::AesV3 => {
                if data.is_empty() {
                    // Seen in files written by several producers for an
                    // empty string, which has no room for an IV.
                    return Ok(Vec::new());
                }
                if data.len() < 32 || !data.len().is_multiple_of(16) {
                    return Err(format!("Object {number}: {} bytes of AES data, not an IV and \
                                        whole blocks.", data.len()));
                }
                let plain = aes_cbc_no_padding(&self.object_key(number, generation, method),
                                               &data[..16], &data[16..], true)?;
                allcrypt::api::unpad_pkcs7(&plain, 16)
                    .map_err(|_| format!("Object {number}: the AES padding is wrong."))
            }
        }
    }

    pub fn encrypt(&self, number: u32, generation: u16, method: Method, data: &[u8])
                   -> Result<Vec<u8>, String> {
        match method {
            Method::Identity => Ok(data.to_vec()),
            Method::Rc4 => rc4(&self.object_key(number, generation, method), data),
            Method::AesV2 | Method::AesV3 => {
                let mut out = allcrypt::api::random_bytes(16)?;
                let padded = allcrypt::api::pad_pkcs7(data, 16)?;
                let iv = out.clone();
                out.extend_from_slice(&aes_cbc_no_padding(
                    &self.object_key(number, generation, method), &iv, &padded, false)?);
                Ok(out)
            }
        }
    }

    /// A new security handler and its `/Encrypt` dictionary.
    pub fn create(scheme: &str, user: &[u8], owner: &[u8], permissions: i32, id: &[u8])
                  -> Result<(Security, Dict), String> {
        let name = |s: &str| Object::Name(s.as_bytes().to_vec());
        let crypt_filter = |cfm: &str, bytes: i64| {
            Object::Dictionary(vec![(b"StdCF".to_vec(), Object::Dictionary(vec![
                (b"CFM".to_vec(), name(cfm)),
                (b"AuthEvent".to_vec(), name("DocOpen")),
                (b"Length".to_vec(), Object::Integer(bytes)),
            ]))])
        };
        let (v, r, bits, method) = match scheme {
            "rc4-40" => (1, 2, 40, Method::Rc4),
            "rc4-128" => (2, 3, 128, Method::Rc4),
            "rc4-128-r4" => (4, 4, 128, Method::Rc4),
            "aes-128" => (4, 4, 128, Method::AesV2),
            "aes-256-r5" => (5, 5, 256, Method::AesV3),
            "aes-256" => (5, 6, 256, Method::AesV3),
            other => return Err(format!("Unknown scheme {other}; rc4-40, rc4-128, rc4-128-r4, \
                                         aes-128, aes-256-r5 or aes-256.")),
        };
        let mut dict: Dict = vec![
            (b"Filter".to_vec(), name("Standard")),
            (b"V".to_vec(), Object::Integer(v)),
            (b"R".to_vec(), Object::Integer(r)),
            (b"Length".to_vec(), Object::Integer(bits)),
            (b"P".to_vec(), Object::Integer(i64::from(permissions))),
        ];
        if v == 4 {
            dict.push((b"CF".to_vec(), crypt_filter(if method == Method::Rc4 { "V2" } else { "AESV2" }, 16)));
            dict.push((b"StmF".to_vec(), name("StdCF")));
            dict.push((b"StrF".to_vec(), name("StdCF")));
        }

        let security;
        if r >= 5 {
            let key = allcrypt::api::random_bytes(32)?;
            let salts = allcrypt::api::random_bytes(32)?;
            let (user, owner) = (modern_password(user), modern_password(owner));
            let mut u = hash(r, user, &salts[..8], &[])?;
            u.extend_from_slice(&salts[..16]);
            let ue = aes_cbc_no_padding(&hash(r, user, &salts[8..16], &[])?, &[0; 16], &key, false)?;
            let mut o = hash(r, owner, &salts[16..24], &u)?;
            o.extend_from_slice(&salts[16..32]);
            let oe = aes_cbc_no_padding(&hash(r, owner, &salts[24..32], &u)?, &[0; 16], &key,
                                        false)?;
            let mut perms = permissions.to_le_bytes().to_vec();
            perms.extend_from_slice(&[0xff; 4]);
            perms.push(b'T');
            perms.extend_from_slice(b"adb");
            perms.extend_from_slice(&allcrypt::api::random_bytes(4)?);
            let mut cipher = AesCrypto::new(key.clone())?;
            let mut sealed = Vec::new();
            cipher.ecb_encrypt(&perms, &mut sealed)?;
            dict.push((b"CF".to_vec(), crypt_filter("AESV3", 32)));
            dict.push((b"StmF".to_vec(), name("StdCF")));
            dict.push((b"StrF".to_vec(), name("StdCF")));
            for (k, value) in [("O", o), ("U", u), ("OE", oe), ("UE", ue), ("Perms", sealed)] {
                dict.push((k.as_bytes().to_vec(), Object::String(value)));
            }
            security = Security { v, r, key, streams: method, strings: method, files: method,
                                  filters: vec![(b"StdCF".to_vec(), method)],
                                  encrypt_metadata: true, permissions, perms_match: Some(true) };
        } else {
            let length = bits as usize / 8;
            let mut legacy = Legacy { r, length, o: &[], p: permissions, id,
                                      encrypt_metadata: true };
            let o = legacy.o_for(owner, user)?;
            legacy.o = &o;
            let key = legacy.file_key(user);
            let u = legacy.u_for(&key)?;
            dict.push((b"O".to_vec(), Object::String(o.clone())));
            dict.push((b"U".to_vec(), Object::String(u)));
            let filters = if v == 4 { vec![(b"StdCF".to_vec(), method)] } else { Vec::new() };
            security = Security { v, r, key, streams: method, strings: method, files: method,
                                  filters, encrypt_metadata: true, permissions,
                                  perms_match: None };
        }
        if r == 2 {
            crate::object::remove(&mut dict, "Length");
        }
        Ok((security, dict))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rc4` swallowed the cipher's refusal of its key and returned
    /// nothing, so an empty key would have decrypted to nothing and
    /// been reported as a wrong password. Every key here is five bytes
    /// or more, so no test reached the empty result.
    #[test]
    fn test_rc4_refuses_a_key_the_cipher_refuses() {
        assert!(rc4(&[], b"data").is_err());
        assert!(rc4(&[0; 257], b"data").is_err());
        assert_eq!(rc4(b"key", b"data").unwrap().len(), 4);
    }

    #[test]
    fn test_every_scheme_opens_with_either_password_and_refuses_others() {
        let id = [7u8; 16];
        for scheme in ["rc4-40", "rc4-128", "rc4-128-r4", "aes-128", "aes-256-r5", "aes-256"] {
            let (made, dict) = Security::create(scheme, b"user", b"owner", -44, &id).unwrap();
            let (as_user, which) = Security::open(&dict, &id, b"user").unwrap();
            assert_eq!((as_user.key.clone(), which), (made.key.clone(), Which::User), "{scheme}");
            let (as_owner, which) = Security::open(&dict, &id, b"owner").unwrap();
            assert_eq!((as_owner.key, which), (made.key.clone(), Which::Owner), "{scheme}");
            assert!(Security::open(&dict, &id, b"other").is_err(), "{scheme}");
            let sealed = made.encrypt(12, 0, made.strings, b"a string").unwrap();
            assert_eq!(made.decrypt(12, 0, made.strings, &sealed).unwrap(), b"a string");
        }
    }

    #[test]
    fn test_an_empty_user_password_opens_without_one() {
        let id = [1u8; 16];
        for scheme in ["rc4-128", "aes-256"] {
            let (_, dict) = Security::create(scheme, b"", b"owner", -4, &id).unwrap();
            assert_eq!(Security::open(&dict, &id, b"").unwrap().1, Which::User);
        }
    }

    /// The owner password is tested first, as ISO 32000-2 Algorithm 2.A
    /// and qpdf do, so a password that is both is the owner's - which
    /// grants every permission rather than /P's.
    #[test]
    fn test_a_password_that_is_both_is_the_owners() {
        let id = [3u8; 16];
        for scheme in ["rc4-40", "rc4-128", "rc4-128-r4", "aes-128", "aes-256-r5", "aes-256"] {
            let (made, dict) = Security::create(scheme, b"same", b"same", -4, &id).unwrap();
            let (opened, which) = Security::open(&dict, &id, b"same").unwrap();
            assert_eq!((opened.key, which), (made.key, Which::Owner), "{scheme}");
        }
    }

    #[test]
    fn test_the_key_length_is_read_as_qpdf_reads_it() {
        assert_eq!(key_length(1, Some(128)), 5);
        assert_eq!(key_length(2, Some(40)), 5);
        assert_eq!(key_length(3, Some(96)), 12);
        assert_eq!(key_length(4, Some(40)), 16);
        for impossible in [None, Some(41), Some(32), Some(136), Some(129)] {
            assert_eq!(key_length(2, impossible), 16, "{impossible:?}");
        }
    }

    /// `/EFF` names the method for embedded files that name none of
    /// their own; here it differs from `/StmF`, which is the only way
    /// to see it read at all.
    #[test]
    fn test_eff_is_read_apart_from_stmf() {
        let id = [5u8; 16];
        let (_, mut dict) = Security::create("aes-128", b"u", b"o", -4, &id).unwrap();
        crate::object::set(&mut dict, "StmF", Object::Name(b"Identity".to_vec()));
        crate::object::set(&mut dict, "EFF", Object::Name(b"StdCF".to_vec()));
        let (opened, _) = Security::open(&dict, &id, b"u").unwrap();
        assert_eq!((opened.streams, opened.files), (Method::Identity, Method::AesV2));
        assert_eq!(opened.named(b"StdCF"), Some(Method::AesV2));
        assert_eq!(opened.named(b"Identity"), Some(Method::Identity));
        assert_eq!(opened.named(b"Other"), None);
    }

    #[test]
    fn test_changed_permissions_are_noticed_at_revision_6() {
        let id = [1u8; 16];
        let (_, mut dict) = Security::create("aes-256", b"u", b"o", -4, &id).unwrap();
        assert_eq!(Security::open(&dict, &id, b"u").unwrap().0.perms_match, Some(true));
        crate::object::set(&mut dict, "P", Object::Integer(-1));
        assert_eq!(Security::open(&dict, &id, b"u").unwrap().0.perms_match, Some(false));
    }
}
