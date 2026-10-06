//! Kerberos 5 encryption and checksum types (RFC 3961's framework):
//!
//! - single DES with CRC-32, MD4 or MD5 (RFC 3961 6.2), with the MIT
//!   string-to-key and its weak-key correction;
//! - Triple DES with key derivation and HMAC-SHA1 (RFC 3961 6.3);
//! - AES with ciphertext stealing and HMAC-SHA1-96 (RFC 3962);
//! - AES with HMAC-SHA-256/384 and the SP 800-108 KDF (RFC 8009);
//! - RC4 with HMAC-MD5, and its 40-bit export variant (RFC 4757);
//! - Camellia with ciphertext stealing and CMAC (RFC 6803).
//!
//! Every type but RC4 encrypts a random confounder ahead of the
//! plaintext and keys its encryption and its integrity check from the
//! base key and the key usage, so the same key under two usages is two
//! unrelated sets of keys.

use allcrypt::api::{self, AnyBlockCipher};
use allcrypt::kdf::nist::{kbkdf_counter, kbkdf_feedback, Prf};
use allcrypt::block_ciphers::{BlockCipher, CtsVariant};
use allcrypt::hash_functions::HashFunction;
use allcrypt::stream_ciphers::rc4::RC4;
use allcrypt::stream_ciphers::StreamCipher;


#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    /// Single DES and the checksum inside the encryption.
    Des(DesCheck),
    Des3,
    /// AES with HMAC-SHA1-96, the key length.
    AesSha1(usize),
    /// AES with HMAC-SHA2, the key length (16 with SHA-256, 32 with
    /// SHA-384).
    AesSha2(usize),
    /// RC4-HMAC; `true` for the export variant.
    Rc4(bool),
    Camellia(usize),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum DesCheck {
    Crc,
    Md4,
    Md5,
}

/// A usage's checksum, encryption and integrity keys.
struct UsageKeys {
    kc: Vec<u8>,
    ke: Vec<u8>,
    ki: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Enctype {
    pub id: i32,
    pub name: &'static str,
    kind: Kind,
}

pub const ENCTYPES: &[Enctype] = &[
    Enctype { id: 1, name: "des-cbc-crc", kind: Kind::Des(DesCheck::Crc) },
    Enctype { id: 2, name: "des-cbc-md4", kind: Kind::Des(DesCheck::Md4) },
    Enctype { id: 3, name: "des-cbc-md5", kind: Kind::Des(DesCheck::Md5) },
    Enctype { id: 16, name: "des3-cbc-sha1", kind: Kind::Des3 },
    Enctype { id: 17, name: "aes128-cts-hmac-sha1-96", kind: Kind::AesSha1(16) },
    Enctype { id: 18, name: "aes256-cts-hmac-sha1-96", kind: Kind::AesSha1(32) },
    Enctype { id: 19, name: "aes128-cts-hmac-sha256-128", kind: Kind::AesSha2(16) },
    Enctype { id: 20, name: "aes256-cts-hmac-sha384-192", kind: Kind::AesSha2(32) },
    Enctype { id: 23, name: "arcfour-hmac", kind: Kind::Rc4(false) },
    Enctype { id: 24, name: "arcfour-hmac-exp", kind: Kind::Rc4(true) },
    Enctype { id: 25, name: "camellia128-cts-cmac", kind: Kind::Camellia(16) },
    Enctype { id: 26, name: "camellia256-cts-cmac", kind: Kind::Camellia(32) },
];

pub fn by_id(id: i32) -> Result<&'static Enctype, String> {
    ENCTYPES.iter().find(|e| e.id == id)
        .ok_or_else(|| format!("Encryption type {id} is not one this knows."))
}

pub fn by_name(name: &str) -> Result<&'static Enctype, String> {
    let name = match name {
        "rc4-hmac" => "arcfour-hmac",
        "rc4-hmac-exp" => "arcfour-hmac-exp",
        "des3-cbc-sha1-kd" | "des3-hmac-sha1" => "des3-cbc-sha1",
        "aes128" | "aes128-sha1" => "aes128-cts-hmac-sha1-96",
        "aes256" | "aes256-sha1" => "aes256-cts-hmac-sha1-96",
        "aes128-sha2" => "aes128-cts-hmac-sha256-128",
        "aes256-sha2" => "aes256-cts-hmac-sha384-192",
        "camellia128-cts" => "camellia128-cts-cmac",
        "camellia256-cts" => "camellia256-cts-cmac",
        other => other,
    };
    ENCTYPES.iter().find(|e| e.name == name).or_else(|| {
        name.parse::<i32>().ok().and_then(|id| ENCTYPES.iter().find(|e| e.id == id))
    }).ok_or_else(|| format!("No encryption type named {name}."))
}

// ------------------------------------------------------------ building blocks --

pub use allcrypt::kdf::kerberos::nfold;

/// The modified CRC-32 of RFC 3961 6.2.3: the reflected CRC with neither
/// the initial nor the final inversion, little endian.
pub fn mod_crc32(data: &[u8]) -> [u8; 4] {
    allcrypt::checksum::crc32_update(0, data).to_le_bytes()
}

fn hash(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h = api::AnyHash::new(name).expect("a known hash");
    h.update(data);
    h.digest()
}

fn hmac(hash_name: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    api::hmac(hash_name, key, data).expect("a known hash")
}

fn cipher(name: &str, key: &[u8]) -> Result<AnyBlockCipher, String> {
    AnyBlockCipher::new(name, key, None)
}

fn cbc_encrypt(c: &mut AnyBlockCipher, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    c.cbc_encrypt(data, &mut out, iv.to_vec())?;
    Ok(out)
}

fn cbc_decrypt(c: &mut AnyBlockCipher, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    c.cbc_decrypt(data, &mut out, iv.to_vec())?;
    Ok(out)
}

/// CBC with ciphertext stealing as RFC 3962 uses it: the library's
/// CS3, which swaps the last two blocks even when the last one is whole.
pub fn cts_encrypt(c: &mut AnyBlockCipher, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    c.cbc_cs_encrypt(data, &mut out, iv, CtsVariant::Cs3)?;
    Ok(out)
}

pub fn cts_decrypt(c: &mut AnyBlockCipher, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    c.cbc_cs_decrypt(data, &mut out, iv, CtsVariant::Cs3)?;
    Ok(out)
}

// RFC 3961's random-to-key, DR and DES string-to-key, and the SP 800-108
// KDFs RFC 8009 and RFC 6803 use, are the library's (`kdf::kerberos`,
// `kdf::nist`).

fn des3_random_to_key(bytes: &[u8]) -> Vec<u8> {
    allcrypt::kdf::kerberos::des3_random_to_key(bytes).expect("21 bytes")
}

/// DR (RFC 3961 5.1) under the named cipher.
fn derive_random(cipher_name: &str, key: &[u8], constant: &[u8], len: usize)
                 -> Result<Vec<u8>, String> {
    allcrypt::kdf::kerberos::derive_random(&mut cipher(cipher_name, key)?, constant, len)
}

/// KDF-HMAC-SHA2 (RFC 8009 3): SP 800-108 counter mode, one block.
fn kdf_hmac_sha2(hash_name: &str, key: &[u8], label: &[u8], bits: usize) -> Vec<u8> {
    kdf_hmac_sha2_context(hash_name, key, label, &[], bits)
}

/// The same with a context after the zero byte, which only the PRF uses.
fn kdf_hmac_sha2_context(hash_name: &str, key: &[u8], label: &[u8], context: &[u8], bits: usize)
                         -> Vec<u8> {
    kbkdf_counter(Prf::Hmac(hash_name), key, label, context, bits / 8).expect("a known hash")
}

/// KDF-FEEDBACK-CMAC (RFC 6803 3): SP 800-108 feedback mode over
/// Camellia's CMAC, from a zero block.
fn kdf_feedback_cmac(key: &[u8], constant: &[u8], len: usize) -> Result<Vec<u8>, String> {
    kbkdf_feedback(Prf::Cmac("camellia"), key, &[0; 16], constant, &[], len)
}

/// The usage constant for checksum (0x99), encryption (0xAA) and
/// integrity (0x55) keys.
fn usage_constant(usage: u32, which: u8) -> Vec<u8> {
    let mut c = usage.to_be_bytes().to_vec();
    c.push(which);
    c
}

/// RFC 3961 6.2's DES string-to-key: the library's.
fn des_string_to_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    allcrypt::kdf::kerberos::des_string_to_key(password, salt)
}

/// The key usage as RC4-HMAC numbers it (RFC 4757 3): the AS-REP's
/// encrypted part is 8, like the TGS-REP's, and the GSS wrap token's
/// signature usage, 23, is 13.
///
/// RFC 4757 also gives the TGS-REP encrypted under a subkey (usage 9)
/// T = 8. MIT Kerberos and Heimdal both keep it 9, so a TGS-REP the RFC's
/// way decrypts under neither, and 9 stays 9 here; a test pins it.
fn rc4_usage(usage: u32) -> u32 {
    match usage {
        3 => 8,
        23 => 13,
        other => other,
    }
}

// ------------------------------------------------------------------- the types --

impl Enctype {
    pub fn key_len(&self) -> usize {
        match self.kind {
            Kind::Des(_) => 8,
            Kind::Des3 => 24,
            Kind::AesSha1(n) | Kind::AesSha2(n) | Kind::Camellia(n) => n,
            Kind::Rc4(_) => 16,
        }
    }

    /// The default string-to-key parameters: the PBKDF2 count, big
    /// endian, for the types that take one.
    pub fn default_params(&self) -> Option<Vec<u8>> {
        match self.kind {
            Kind::AesSha1(_) => Some(4096u32.to_be_bytes().to_vec()),
            Kind::AesSha2(_) | Kind::Camellia(_) => Some(32768u32.to_be_bytes().to_vec()),
            _ => None,
        }
    }

    pub fn string_to_key(&self, password: &[u8], salt: &[u8], params: Option<&[u8]>)
                         -> Result<Vec<u8>, String> {
        let iterations = || -> Result<u32, String> {
            let params = params.map(<[u8]>::to_vec).or_else(|| self.default_params())
                .unwrap_or_default();
            let bytes: [u8; 4] = params.as_slice().try_into()
                .map_err(|_| "String-to-key parameters are a four-byte count.".to_string())?;
            let count = u32::from_be_bytes(bytes);
            // RFC 3962 4 reads zero as 2^32 iterations. MIT Kerberos
            // refuses it, and so does this.
            if count == 0 {
                return Err("An iteration count of zero, which means 2^32; refused.".to_string());
            }
            Ok(count)
        };
        match self.kind {
            Kind::Des(_) => {
                if params.is_some_and(|p| !p.is_empty()) {
                    return Err("DES string-to-key with parameters (the AFS variant) is not \
                                supported.".to_string());
                }
                des_string_to_key(password, salt)
            }
            Kind::Des3 => {
                let mut input = password.to_vec();
                input.extend_from_slice(salt);
                let temp = des3_random_to_key(&nfold(&input, 21));
                self.derive(&temp, b"kerberos")
            }
            Kind::AesSha1(n) => {
                let temp = api::pbkdf2("sha1", password, salt, iterations()?, n)?;
                self.derive(&temp, b"kerberos")
            }
            Kind::AesSha2(n) | Kind::Camellia(n) => {
                // RFC 8009 4 matches the PRF to the type's hash; RFC 6803 4
                // keeps RFC 3962's HMAC-SHA1.
                let prf = match self.kind {
                    Kind::AesSha2(32) => "sha384",
                    Kind::AesSha2(_) => "sha256",
                    _ => "sha1",
                };
                let mut saltp = self.name.as_bytes().to_vec();
                saltp.push(0);
                saltp.extend_from_slice(salt);
                let temp = api::pbkdf2(prf, password, &saltp, iterations()?, n)?;
                self.derive(&temp, b"kerberos")
            }
            Kind::Rc4(_) => {
                // MD4 of the password as UTF-16LE: the NT hash. No salt.
                let text = std::str::from_utf8(password)
                    .map_err(|_| "An RC4-HMAC password must be UTF-8.".to_string())?;
                let utf16: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
                Ok(hash("md4", &utf16))
            }
        }
    }

    /// DK for the derived-key types: a key from the base key and a
    /// constant.
    pub fn derive(&self, key: &[u8], constant: &[u8]) -> Result<Vec<u8>, String> {
        match self.kind {
            Kind::Des3 => Ok(des3_random_to_key(&derive_random("3des", key, constant, 21)?)),
            Kind::AesSha1(n) => derive_random("aes", key, constant, n),
            Kind::AesSha2(n) => {
                let (hash_name, bits) = if n == 16 { ("sha256", 128) } else { ("sha384", 256) };
                Ok(kdf_hmac_sha2(hash_name, key, constant, bits))
            }
            Kind::Camellia(n) => kdf_feedback_cmac(key, constant, n),
            _ => Err(format!("{} derives no keys.", self.name)),
        }
    }

    /// The three keys of a usage.
    fn usage_keys(&self, key: &[u8], usage: u32) -> Result<UsageKeys, String> {
        let kc = |which| usage_constant(usage, which);
        Ok(match self.kind {
            Kind::AesSha2(n) => {
                let (hash_name, short) = if n == 16 { ("sha256", 128) } else { ("sha384", 192) };
                UsageKeys { kc: kdf_hmac_sha2(hash_name, key, &kc(0x99), short),
                            ke: kdf_hmac_sha2(hash_name, key, &kc(0xaa), n * 8),
                            ki: kdf_hmac_sha2(hash_name, key, &kc(0x55), short) }
            }
            _ => UsageKeys { kc: self.derive(key, &kc(0x99))?, ke: self.derive(key, &kc(0xaa))?,
                             ki: self.derive(key, &kc(0x55))? },
        })
    }

    fn check_key(&self, key: &[u8]) -> Result<(), String> {
        if key.len() != self.key_len() {
            return Err(format!("A {} key is {} bytes, not {}.", self.name, self.key_len(),
                               key.len()));
        }
        Ok(())
    }

    /// Encrypt under a key usage. `confounder` is for known-answer
    /// tests; otherwise it is random.
    pub fn encrypt(&self, key: &[u8], usage: u32, plain: &[u8], confounder: Option<&[u8]>)
                   -> Result<Vec<u8>, String> {
        self.check_key(key)?;
        let conf_len = match self.kind { Kind::Des(_) | Kind::Des3 | Kind::Rc4(_) => 8, _ => 16 };
        let confounder = match confounder {
            Some(c) if c.len() == conf_len => c.to_vec(),
            Some(_) => return Err(format!("A {} confounder is {conf_len} bytes.", self.name)),
            None => api::random_bytes(conf_len)?,
        };
        let mut data = confounder.clone();
        match self.kind {
            Kind::Des(check) => {
                let check_len = if check == DesCheck::Crc { 4 } else { 16 };
                data.extend(std::iter::repeat_n(0, check_len));
                data.extend_from_slice(plain);
                data.resize(data.len().next_multiple_of(8), 0);
                let sum = match check {
                    DesCheck::Crc => mod_crc32(&data).to_vec(),
                    DesCheck::Md4 => hash("md4", &data),
                    DesCheck::Md5 => hash("md5", &data),
                };
                data[8..8 + check_len].copy_from_slice(&sum);
                // des-cbc-crc uses the key as its IV; the others zero.
                let iv = if check == DesCheck::Crc { key.to_vec() } else { vec![0; 8] };
                cbc_encrypt(&mut cipher("des", key)?, &iv, &data)
            }
            Kind::Des3 => {
                data.extend_from_slice(plain);
                data.resize(data.len().next_multiple_of(8), 0);
                let UsageKeys { ke, ki, .. } = self.usage_keys(key, usage)?;
                let mut out = cbc_encrypt(&mut cipher("3des", &ke)?, &[0; 8], &data)?;
                out.extend(hmac("sha1", &ki, &data));
                Ok(out)
            }
            Kind::AesSha1(_) | Kind::Camellia(_) => {
                data.extend_from_slice(plain);
                let UsageKeys { ke, ki, .. } = self.usage_keys(key, usage)?;
                let name = if matches!(self.kind, Kind::Camellia(_)) { "camellia" } else { "aes" };
                let mut out = cts_encrypt(&mut cipher(name, &ke)?, &[0; 16], &data)?;
                if name == "aes" {
                    out.extend_from_slice(&hmac("sha1", &ki, &data)[..12]);
                } else {
                    out.extend(allcrypt::mac::cmac::cmac("camellia", &ki, &data)?);
                }
                Ok(out)
            }
            Kind::AesSha2(n) => {
                data.extend_from_slice(plain);
                let UsageKeys { ke, ki, .. } = self.usage_keys(key, usage)?;
                let (hash_name, mac_len) = if n == 16 { ("sha256", 16) } else { ("sha384", 24) };
                let mut out = cts_encrypt(&mut cipher("aes", &ke)?, &[0; 16], &data)?;
                // The MAC covers the cipher state - sixteen zeros by
                // default - and the ciphertext (RFC 8009 5).
                let mut mac_input = vec![0u8; 16];
                mac_input.extend_from_slice(&out);
                out.extend_from_slice(&hmac(hash_name, &ki, &mac_input)[..mac_len]);
                Ok(out)
            }
            Kind::Rc4(export) => {
                data.extend_from_slice(plain);
                let (k1, k2) = rc4_keys(key, usage, export);
                let checksum = hmac("md5", &k2, &data);
                let k3 = hmac("md5", &k1, &checksum);
                let mut out = checksum.clone();
                RC4::new(k3)?.crypt(&data, &mut out);
                Ok(out)
            }
        }
    }

    /// Decrypt and check. Every failure of the check is the same error.
    pub fn decrypt(&self, key: &[u8], usage: u32, cipher_text: &[u8]) -> Result<Vec<u8>, String> {
        self.check_key(key)?;
        let failed = || "Integrity check failed: wrong key or usage, or the data is damaged."
            .to_string();
        match self.kind {
            Kind::Des(check) => {
                let check_len = if check == DesCheck::Crc { 4 } else { 16 };
                if cipher_text.len() < 8 + check_len || !cipher_text.len().is_multiple_of(8) {
                    return Err(failed());
                }
                let iv = if check == DesCheck::Crc { key.to_vec() } else { vec![0; 8] };
                let mut data = cbc_decrypt(&mut cipher("des", key)?, &iv, cipher_text)?;
                let sum = data[8..8 + check_len].to_vec();
                data[8..8 + check_len].fill(0);
                let expected = match check {
                    DesCheck::Crc => mod_crc32(&data).to_vec(),
                    DesCheck::Md4 => hash("md4", &data),
                    DesCheck::Md5 => hash("md5", &data),
                };
                if sum != expected {
                    return Err(failed());
                }
                Ok(data[8 + check_len..].to_vec())
            }
            Kind::Des3 => {
                if cipher_text.len() < 8 + 20 || !(cipher_text.len() - 20).is_multiple_of(8) {
                    return Err(failed());
                }
                let (body, mac) = cipher_text.split_at(cipher_text.len() - 20);
                let UsageKeys { ke, ki, .. } = self.usage_keys(key, usage)?;
                let data = cbc_decrypt(&mut cipher("3des", &ke)?, &[0; 8], body)?;
                if !constant_eq(&hmac("sha1", &ki, &data), mac) {
                    return Err(failed());
                }
                Ok(data[8..].to_vec())
            }
            Kind::AesSha1(_) | Kind::Camellia(_) => {
                let mac_len = if matches!(self.kind, Kind::Camellia(_)) { 16 } else { 12 };
                if cipher_text.len() < 16 + mac_len {
                    return Err(failed());
                }
                let (body, mac) = cipher_text.split_at(cipher_text.len() - mac_len);
                let UsageKeys { ke, ki, .. } = self.usage_keys(key, usage)?;
                let name = if mac_len == 16 { "camellia" } else { "aes" };
                let data = cts_decrypt(&mut cipher(name, &ke)?, &[0; 16], body)?;
                let expected = if name == "aes" { hmac("sha1", &ki, &data)[..12].to_vec() }
                               else { allcrypt::mac::cmac::cmac("camellia", &ki, &data)? };
                if !constant_eq(&expected, mac) {
                    return Err(failed());
                }
                Ok(data[16..].to_vec())
            }
            Kind::AesSha2(n) => {
                let (hash_name, mac_len) = if n == 16 { ("sha256", 16) } else { ("sha384", 24) };
                if cipher_text.len() < 16 + mac_len {
                    return Err(failed());
                }
                let (body, mac) = cipher_text.split_at(cipher_text.len() - mac_len);
                let UsageKeys { ke, ki, .. } = self.usage_keys(key, usage)?;
                let mut mac_input = vec![0u8; 16];
                mac_input.extend_from_slice(body);
                // Encrypt-then-MAC: the MAC is checked before decrypting.
                if !constant_eq(&hmac(hash_name, &ki, &mac_input)[..mac_len], mac) {
                    return Err(failed());
                }
                let data = cts_decrypt(&mut cipher("aes", &ke)?, &[0; 16], body)?;
                Ok(data[16..].to_vec())
            }
            Kind::Rc4(export) => {
                if cipher_text.len() < 16 + 8 {
                    return Err(failed());
                }
                let (checksum, body) = cipher_text.split_at(16);
                let (k1, k2) = rc4_keys(key, usage, export);
                let k3 = hmac("md5", &k1, checksum);
                let mut data = Vec::with_capacity(body.len());
                RC4::new(k3)?.crypt(body, &mut data);
                if !constant_eq(&hmac("md5", &k2, &data), checksum) {
                    return Err(failed());
                }
                Ok(data[8..].to_vec())
            }
        }
    }

    /// The checksum type RFC 3961 6 makes mandatory for the type.
    pub fn mandatory_cksumtype(&self) -> &'static Cksumtype {
        let id = match self.kind {
            Kind::Des(DesCheck::Md4) => 3,
            Kind::Des(_) => 8,
            Kind::Des3 => 12,
            Kind::AesSha1(16) => 15,
            Kind::AesSha1(_) => 16,
            Kind::Camellia(16) => 17,
            Kind::Camellia(_) => 18,
            Kind::AesSha2(16) => 19,
            Kind::AesSha2(_) => 20,
            Kind::Rc4(_) => -138,
        };
        cksumtype_by_id(id).expect("every mandatory type is in the table")
    }

    /// The derived-key types' checksums: an HMAC or CMAC under the
    /// usage's checksum key, and RC4-HMAC's.
    fn keyed_checksum(&self, key: &[u8], usage: u32, data: &[u8]) -> Result<Vec<u8>, String> {
        self.check_key(key)?;
        Ok(match self.kind {
            Kind::Des(_) => return Err("Single DES keys checksum through a DES checksum type."
                                       .to_string()),
            Kind::Des3 => hmac("sha1", &self.usage_keys(key, usage)?.kc, data),
            Kind::AesSha1(_) => hmac("sha1", &self.derive(key, &usage_constant(usage, 0x99))?,
                                     data)[..12].to_vec(),
            Kind::AesSha2(n) => {
                let kc = self.usage_keys(key, usage)?.kc;
                let (hash_name, len) = if n == 16 { ("sha256", 16) } else { ("sha384", 24) };
                hmac(hash_name, &kc, data)[..len].to_vec()
            }
            Kind::Camellia(_) => allcrypt::mac::cmac::cmac(
                "camellia", &self.derive(key, &usage_constant(usage, 0x99))?, data)?,
            Kind::Rc4(_) => {
                // RFC 4757 4: HMAC-MD5 under a key derived from
                // "signaturekey", over MD5 of the usage and the data.
                let ksign = hmac("md5", key, b"signaturekey\0");
                let mut input = rc4_usage(usage).to_le_bytes().to_vec();
                input.extend_from_slice(data);
                hmac("md5", &ksign, &hash("md5", &input))
            }
        })
    }
}

// ---------------------------------------------------------------- checksums --

#[derive(Clone, Copy, Debug, PartialEq)]
enum CkKind {
    /// No key: CRC-32 or a hash.
    Unkeyed,
    /// RFC 3961 6.2.4 and 6.2.5: a confounder and the hash of it and the
    /// message, DES-CBC encrypted under the key XOR F0F0...
    DesConfounded(&'static str),
    /// RFC 3961 6.2.7: a confounder and a DES CBC-MAC, encrypted the same
    /// way.
    DesMac,
    /// RFC 3961 6.2.8: a DES CBC-MAC with the key as its IV.
    DesMacK,
    /// RFC 3961 6.2.6: MD4 DES-CBC encrypted with the key as its IV.
    Md4DesK,
    /// The checksum of a derived-key or RC4 type, by its enctype number.
    Keyed(i32),
}

#[derive(Debug, PartialEq)]
pub struct Cksumtype {
    pub id: i32,
    pub name: &'static str,
    kind: CkKind,
}

pub const CKSUMTYPES: &[Cksumtype] = &[
    Cksumtype { id: 1, name: "crc32", kind: CkKind::Unkeyed },
    Cksumtype { id: 2, name: "rsa-md4", kind: CkKind::Unkeyed },
    Cksumtype { id: 3, name: "rsa-md4-des", kind: CkKind::DesConfounded("md4") },
    Cksumtype { id: 4, name: "des-mac", kind: CkKind::DesMac },
    Cksumtype { id: 5, name: "des-mac-k", kind: CkKind::DesMacK },
    Cksumtype { id: 6, name: "rsa-md4-des-k", kind: CkKind::Md4DesK },
    Cksumtype { id: 7, name: "rsa-md5", kind: CkKind::Unkeyed },
    Cksumtype { id: 8, name: "rsa-md5-des", kind: CkKind::DesConfounded("md5") },
    Cksumtype { id: 10, name: "sha1", kind: CkKind::Unkeyed },
    Cksumtype { id: 12, name: "hmac-sha1-des3-kd", kind: CkKind::Keyed(16) },
    // RFC 3961 8 lists SHA-1 under both 10 and 14.
    Cksumtype { id: 14, name: "sha1-14", kind: CkKind::Unkeyed },
    Cksumtype { id: 15, name: "hmac-sha1-96-aes128", kind: CkKind::Keyed(17) },
    Cksumtype { id: 16, name: "hmac-sha1-96-aes256", kind: CkKind::Keyed(18) },
    Cksumtype { id: 17, name: "cmac-camellia128", kind: CkKind::Keyed(25) },
    Cksumtype { id: 18, name: "cmac-camellia256", kind: CkKind::Keyed(26) },
    Cksumtype { id: 19, name: "hmac-sha256-128-aes128", kind: CkKind::Keyed(19) },
    Cksumtype { id: 20, name: "hmac-sha384-192-aes256", kind: CkKind::Keyed(20) },
    Cksumtype { id: -138, name: "hmac-md5-arcfour", kind: CkKind::Keyed(23) },
];

pub fn cksumtype_by_id(id: i32) -> Result<&'static Cksumtype, String> {
    CKSUMTYPES.iter().find(|c| c.id == id)
        .ok_or_else(|| format!("Checksum type {id} is not one this knows."))
}

pub fn cksumtype_by_name(name: &str) -> Result<&'static Cksumtype, String> {
    CKSUMTYPES.iter().find(|c| c.name == name)
        .or_else(|| name.parse::<i32>().ok().and_then(|id| cksumtype_by_id(id).ok()))
        .ok_or_else(|| format!("No checksum type named {name}."))
}

/// The key XOR F0F0F0F0F0F0F0F0 that the confounded DES checksums
/// encrypt under (RFC 3961 6.2.4).
fn des_variant(key: &[u8]) -> Vec<u8> {
    key.iter().map(|b| b ^ 0xf0).collect()
}

/// A DES CBC-MAC over the zero-padded data: the library's, with ISO
/// 9797-1 padding method 1.
fn des_cbc_mac(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    allcrypt::mac::cbc_mac::cbc_mac_zero_padded(&mut cipher("des", key)?, iv, data)
}

impl Cksumtype {
    /// Whether the checksum takes a key.
    pub fn keyed(&self) -> bool {
        self.kind != CkKind::Unkeyed
    }

    /// The confounder's part of a confounded DES checksum; the rest is
    /// computed from it and the message.
    fn des_inner(&self, key: &[u8], confounder: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let mut input = confounder.to_vec();
        input.extend_from_slice(data);
        Ok(match self.kind {
            CkKind::DesConfounded(h) => hash(h, &input),
            CkKind::DesMac => des_cbc_mac(key, &[0; 8], &input)?,
            _ => unreachable!("only the confounded types"),
        })
    }

    /// Make a checksum. `confounder` is for known-answer tests of the
    /// confounded DES types; otherwise it is random.
    pub fn make(&self, key: &[u8], usage: u32, data: &[u8], confounder: Option<&[u8]>)
                -> Result<Vec<u8>, String> {
        let des_key = || -> Result<(), String> {
            if key.len() != 8 {
                return Err(format!("{} takes an eight-byte DES key.", self.name));
            }
            Ok(())
        };
        match self.kind {
            CkKind::Unkeyed => unkeyed_checksum(self.id, data),
            CkKind::DesConfounded(_) | CkKind::DesMac => {
                des_key()?;
                let confounder = match confounder {
                    Some(c) if c.len() == 8 => c.to_vec(),
                    Some(_) => return Err("A DES checksum's confounder is 8 bytes.".to_string()),
                    None => api::random_bytes(8)?,
                };
                let mut input = confounder.clone();
                input.extend(self.des_inner(key, &confounder, data)?);
                cbc_encrypt(&mut cipher("des", &des_variant(key))?, &[0; 8], &input)
            }
            CkKind::DesMacK => {
                des_key()?;
                des_cbc_mac(key, key, data)
            }
            CkKind::Md4DesK => {
                des_key()?;
                cbc_encrypt(&mut cipher("des", key)?, key, &hash("md4", data))
            }
            CkKind::Keyed(enctype) => by_id(enctype)?.keyed_checksum(key, usage, data),
        }
    }

    /// Check a checksum: the confounded types by decrypting it and
    /// recomputing from the confounder inside, the rest by recomputing.
    pub fn verify(&self, key: &[u8], usage: u32, data: &[u8], sum: &[u8])
                  -> Result<bool, String> {
        match self.kind {
            CkKind::DesConfounded(_) | CkKind::DesMac => {
                let expected_len = if self.kind == CkKind::DesMac { 16 } else { 24 };
                if key.len() != 8 || sum.len() != expected_len {
                    return Ok(false);
                }
                let plain = cbc_decrypt(&mut cipher("des", &des_variant(key))?, &[0; 8], sum)?;
                let (confounder, inner) = plain.split_at(8);
                Ok(constant_eq(&self.des_inner(key, confounder, data)?, inner))
            }
            _ => Ok(constant_eq(&self.make(key, usage, data, None)?, sum)),
        }
    }
}

impl Enctype {
    /// The pseudo-random function (RFC 3961 3): output of a fixed length
    /// per type, from the base key and any octet string.
    pub fn prf(&self, key: &[u8], input: &[u8]) -> Result<Vec<u8>, String> {
        self.check_key(key)?;
        Ok(match self.kind {
            // RFC 3961 6.2: DES-CBC of MD5 under the key, for all three
            // single-DES types (des-cbc-md4 included).
            Kind::Des(_) => cbc_encrypt(&mut cipher("des", key)?, &[0; 8], &hash("md5", input))?,
            // The simplified profile (RFC 3961 5.3): the hash truncated to
            // whole blocks and encrypted under DK(key, "prf").
            Kind::Des3 => {
                let kp = self.derive(key, b"prf")?;
                cbc_encrypt(&mut cipher("3des", &kp)?, &[0; 8], &hash("sha1", input)[..16])?
            }
            Kind::AesSha1(_) => {
                let kp = self.derive(key, b"prf")?;
                cbc_encrypt(&mut cipher("aes", &kp)?, &[0; 16], &hash("sha1", input)[..16])?
            }
            // RFC 8009 5: KDF-HMAC-SHA2 with "prf" as the label and the
            // input as the context.
            Kind::AesSha2(n) => {
                let (hash_name, bits) = if n == 16 { ("sha256", 256) } else { ("sha384", 384) };
                kdf_hmac_sha2_context(hash_name, key, b"prf", input, bits)
            }
            // RFC 6803 3.
            Kind::Camellia(n) => allcrypt::mac::cmac::cmac(
                "camellia", &kdf_feedback_cmac(key, b"prf", n)?, input)?,
            // RFC 4757 5.
            Kind::Rc4(_) => hmac("sha1", key, input),
        })
    }
}

/// RC4-HMAC's two keys for a usage: the one that keys RC4 (masked to 40
/// bits for the export variant) and the one that keys the checksum.
fn rc4_keys(key: &[u8], usage: u32, export: bool) -> (Vec<u8>, Vec<u8>) {
    let mut salt = Vec::new();
    if export {
        salt.extend_from_slice(b"fortybits\0");
    }
    salt.extend_from_slice(&rc4_usage(usage).to_le_bytes());
    let k1 = hmac("md5", key, &salt);
    let k2 = k1.clone();
    let mut k1 = k1;
    if export {
        k1[7..].fill(0xab);
    }
    (k1, k2)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The unkeyed checksums: CRC-32 (1), RSA-MD4 (2), RSA-MD5 (7) and
/// SHA-1 (10 and 14).
pub fn unkeyed_checksum(kind: i32, data: &[u8]) -> Result<Vec<u8>, String> {
    Ok(match kind {
        1 => mod_crc32(data).to_vec(),
        2 => hash("md4", data),
        7 => hash("md5", data),
        10 | 14 => hash("sha1", data),
        other => return Err(format!("Checksum type {other} is not an unkeyed one this knows.")),
    })
}

/// The published vectors, read out of the vendored RFCs at test time:
/// RFC 3961 appendix A, RFC 3962 appendix B, RFC 8009 appendix A and
/// RFC 6803 section 10. Every parser asserts how many it found.
#[cfg(test)]
mod document_tests {
    use super::*;

    const RFC3961: &str = include_str!("../../../rfcs/rfc3961.txt");
    const RFC3962: &str = include_str!("../../../rfcs/rfc3962.txt");
    const RFC8009: &str = include_str!("../../../rfcs/rfc8009.txt");
    const RFC6803: &str = include_str!("../../../rfcs/rfc6803.txt");

    /// The text from the line starting `start` to the line starting `end`,
    /// without page headers and footers, form feeds or blank lines.
    fn section<'a>(doc: &'a str, start: &str, end: &str) -> Vec<&'a str> {
        let mut lines = doc.lines().skip_while(|l| !l.starts_with(start));
        let first = lines.next().unwrap_or_else(|| panic!("no section {start}"));
        std::iter::once(first).chain(lines.take_while(|l| !l.starts_with(end)))
            .filter(|l| !l.trim().is_empty() && !l.contains("[Page ") && !l.starts_with("RFC ")
                    && !l.starts_with('\x0c'))
            .collect()
    }

    fn is_hex(token: &str) -> bool {
        token.len() >= 2 && token.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// A line of nothing but hex, optionally after an offset like `0010:`.
    fn hex_line(line: &str) -> Option<Vec<u8>> {
        let tokens: Vec<&str> = line.split_whitespace()
            .filter(|t| !(t.len() == 5 && t.ends_with(':') && is_hex(&t[..4]))).collect();
        if tokens.is_empty() || !tokens.iter().all(|t| is_hex(t)) {
            return None;
        }
        Some(unhex(&tokens.concat()))
    }

    fn unhex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "odd hex {text}");
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The hex value of a labelled line: hex tokens at the end of the line
    /// after its first `:` or `=` (or failing that at the start), then any
    /// lines of nothing but hex that follow.
    fn value(lines: &[&str], i: usize) -> Vec<u8> {
        let line = lines[i];
        let at = line.find([':', '=']).unwrap_or_else(|| panic!("no label: {line}"));
        let tokens: Vec<&str> = line[at + 1..].split_whitespace().collect();
        let tail: Vec<&str> = tokens.iter().rev().take_while(|t| is_hex(t)).copied().collect();
        let text: String = if tail.is_empty() {
            tokens.iter().take_while(|t| is_hex(t)).copied().collect()
        } else {
            tail.into_iter().rev().collect()
        };
        let mut out = unhex(&text);
        for line in &lines[i + 1..] {
            match hex_line(line) {
                Some(more) => out.extend(more),
                None => break,
            }
        }
        out
    }

    /// A string as RFC 3961 writes one: quoted pieces and named code
    /// points joined by `+`, e.g. `"Juri" + s-caron(U+0161) + "i"`.
    fn expression(text: &str) -> Vec<u8> {
        let mut out = String::new();
        // " + " rather than '+', which also appears inside "(U+0161)".
        for piece in text.split(" + ").map(|p| p.trim().trim_start_matches("+ "))
            .filter(|p| !p.is_empty()) {
            if let Some(quoted) = piece.strip_prefix('"').and_then(|p| p.strip_suffix('"')) {
                out.push_str(quoted);
            } else {
                let code = piece.split("(U+").nth(1).and_then(|c| c.strip_suffix(')'))
                    .unwrap_or_else(|| panic!("not a string piece: {piece}"));
                out.push(char::from_u32(u32::from_str_radix(code, 16).unwrap()).unwrap());
            }
        }
        out.into_bytes()
    }

    fn label(line: &str) -> &str {
        line.trim_start()
    }

    // ---------------------------------------------------------- RFC 3961 --

    #[test]
    fn rfc_3961_nfold() {
        let lines = section(RFC3961, "A.1.", "A.2.");
        let text = lines.join(" ");
        let mut found = 0;
        let mut rest = text.as_str();
        while let Some(at) = rest.find("-fold(") {
            let bits: usize = rest[..at].rsplit(|c: char| !c.is_ascii_digit()).next().unwrap()
                .parse().unwrap();
            let close = rest[at..].find(')').unwrap() + at;
            let inner = rest[at + 6..close].trim();
            rest = &rest[close + 1..];
            let after = rest.trim_start();
            let Some(after) = after.strip_prefix('=') else { continue };
            let output: String = after.split_whitespace().take_while(|t| is_hex(t)).collect();
            if output.is_empty() {
                continue;
            }
            let input = match inner.strip_prefix('"').and_then(|i| i.strip_suffix('"')) {
                Some(s) => s.as_bytes().to_vec(),
                None => unhex(&inner.split_whitespace().collect::<String>()),
            };
            assert_eq!(nfold(&input, bits / 8), unhex(&output), "{bits}-fold({inner})");
            found += 1;
        }
        assert_eq!(found, 11);
    }

    #[test]
    fn rfc_3961_des_string_to_key() {
        let lines = section(RFC3961, "A.2.", "A.3.");
        let lines: Vec<&str> = lines.into_iter().take_while(|l| !l.contains("This trace"))
            .collect();
        let (mut salt, mut password, mut found) = (Vec::new(), Vec::new(), 0);
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if l.starts_with("salt:") {
                salt = value(&lines, i);
            } else if l.starts_with("password:") {
                password = value(&lines, i);
            } else if l.starts_with("DES key:") {
                let key = by_name("des-cbc-md5").unwrap().string_to_key(&password, &salt, None)
                    .unwrap();
                assert_eq!(key, value(&lines, i), "{}", String::from_utf8_lossy(&salt));
                found += 1;
            }
        }
        assert_eq!(found, 6);
    }

    #[test]
    fn rfc_3961_des3_dr_and_dk() {
        let lines = section(RFC3961, "A.3.", "A.4.");
        let des3 = by_name("des3-cbc-sha1").unwrap();
        let (mut key, mut usage, mut found) = (Vec::new(), Vec::new(), 0);
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if l.starts_with("key:") {
                key = value(&lines, i);
            } else if l.starts_with("usage:") {
                usage = value(&lines, i);
            } else if l.starts_with("DR:") {
                assert_eq!(derive_random("3des", &key, &usage, 21).unwrap(), value(&lines, i));
            } else if l.starts_with("DK:") {
                assert_eq!(des3.derive(&key, &usage).unwrap(), value(&lines, i));
                found += 1;
            }
        }
        assert_eq!(found, 9);
    }

    #[test]
    fn rfc_3961_des3_string_to_key() {
        let lines = section(RFC3961, "A.4.", "A.5.");
        let des3 = by_name("des3-cbc-sha1").unwrap();
        let (mut salt, mut password, mut found) = (String::new(), String::new(), 0);
        let mut current: Option<&mut String> = None;
        for line in &lines {
            let l = label(line);
            if let Some(rest) = l.strip_prefix("salt:") {
                salt = rest.to_string();
                current = Some(&mut salt);
            } else if let Some(rest) = l.strip_prefix("passwd:") {
                // The document names the G clef U+1011E, here and in A.2,
                // where its UTF-8 is printed too: F0 9D 84 9E, which is
                // U+1D11E (MUSICAL SYMBOL G CLEF). The key printed is the
                // one for U+1D11E; MIT Kerberos computes the same.
                password = rest.replace("g-clef(U+1011E)", "g-clef(U+1D11E)");
                current = Some(&mut password);
            } else if let Some(rest) = l.strip_prefix("key:") {
                current = None;
                let key = des3.string_to_key(&expression(&password), &expression(&salt), None)
                    .unwrap();
                assert_eq!(key, unhex(rest.trim()), "{salt}");
                found += 1;
            } else if l.starts_with('+') {
                let current = current.as_mut().expect("a continuation");
                current.push(' ');
                current.push_str(l);
            }
        }
        assert_eq!(found, 5);
        assert!(RFC3961.contains("passwd: g-clef(U+1011E)"), "the misprint has gone");
        assert_eq!("\u{1D11E}".as_bytes(), [0xf0, 0x9d, 0x84, 0x9e]);
    }

    #[test]
    fn rfc_3961_modified_crc32() {
        let lines = section(RFC3961, "A.5.", "B.");
        let mut found = 0;
        for line in lines.iter().filter(|l| l.contains("mod-crc-32(")) {
            let inner = line.split("mod-crc-32(").nth(1).unwrap().split(')').next().unwrap();
            let input = match inner.strip_prefix('"').and_then(|i| i.strip_suffix('"')) {
                Some(s) => s.as_bytes().to_vec(),
                None => unhex(inner),
            };
            let expected: String = line.split('=').nth(1).unwrap().split_whitespace().collect();
            assert_eq!(mod_crc32(&input).to_vec(), unhex(&expected), "{inner}");
            found += 1;
        }
        assert_eq!(found, 9);
    }

    // ------------------------------------------------- RFC 3962 and 6803 --

    /// `Pass phrase = ...` and `Salt = ...` in the forms these two
    /// documents use: a quoted string, possibly on the next line, a
    /// `0x` hex string, or a named code point with its UTF-8 in hex.
    fn phrase(lines: &[&str], i: usize) -> Vec<u8> {
        let text = lines[i].split_once('=').unwrap().1.trim();
        let text = if text.starts_with('(') && !text.contains("0x") { lines[i + 1].trim() }
                   else { text };
        if let Some(q) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            q.as_bytes().to_vec()
        } else if let Some(hex) = text.split("0x").nth(1) {
            unhex(hex.trim_end_matches(')'))
        } else {
            panic!("not a phrase: {text}")
        }
    }

    /// The string-to-key vectors common to RFC 3962 and RFC 6803:
    /// (iterations, pass phrase, salt, key length, key).
    type Pbkdf2Vector = (u32, Vec<u8>, Vec<u8>, usize, Vec<u8>);

    fn pbkdf2_vectors(lines: &[&str], key_label: &str) -> Vec<Pbkdf2Vector> {
        let (mut count, mut password, mut salt) = (0u32, Vec::new(), Vec::new());
        let mut out = Vec::new();
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if let Some(n) = l.strip_prefix("Iteration count = ") {
                count = n.trim().parse().unwrap();
            } else if l.starts_with("Pass phrase") {
                password = phrase(lines, i);
            } else if l.starts_with("Salt") {
                salt = phrase(lines, i);
            } else if l.ends_with(key_label) {
                let bits: usize = l.split('-').next().unwrap().parse().unwrap();
                out.push((count, password.clone(), salt.clone(), bits / 8, value(lines, i)));
            }
        }
        out
    }

    #[test]
    fn rfc_3962_string_to_key() {
        let lines = section(RFC3962, "B.  Sample", "Normative");
        let vectors = pbkdf2_vectors(&lines, "-bit AES key:");
        assert_eq!(vectors.len(), 14);
        for (count, password, salt, len, key) in vectors {
            let e = by_name(if len == 16 { "aes128-cts-hmac-sha1-96" }
                            else { "aes256-cts-hmac-sha1-96" }).unwrap();
            assert_eq!(e.string_to_key(&password, &salt, Some(&count.to_be_bytes())).unwrap(),
                       key, "{count} {}", String::from_utf8_lossy(&salt));
        }
    }

    #[test]
    fn rfc_3962_ciphertext_stealing() {
        let lines = section(RFC3962, "B.  Sample", "Normative");
        let (mut key, mut iv, mut input, mut found) = (Vec::new(), Vec::new(), Vec::new(), 0);
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if l.starts_with("AES 128-bit key:") {
                key = value(&lines, i);
            } else if l == "IV:" {
                iv = value(&lines, i);
            } else if l == "Input:" {
                input = value(&lines, i);
            } else if l == "Output:" {
                let expected = value(&lines, i);
                let mut c = cipher("aes", &key).unwrap();
                assert_eq!(cts_encrypt(&mut c, &iv, &input).unwrap(), expected,
                           "{} bytes", input.len());
                assert_eq!(cts_decrypt(&mut c, &iv, &expected).unwrap(), input);
                found += 1;
            }
        }
        assert_eq!(found, 6);
    }

    #[test]
    fn rfc_6803_string_to_key() {
        let lines = section(RFC6803, "10.  Test Vectors", "   Sample results for key");
        let vectors = pbkdf2_vectors(&lines, "-bit Camellia key:");
        assert_eq!(vectors.len(), 14);
        for (count, password, salt, len, key) in vectors {
            let e = by_name(if len == 16 { "camellia128-cts-cmac" }
                            else { "camellia256-cts-cmac" }).unwrap();
            assert_eq!(e.string_to_key(&password, &salt, Some(&count.to_be_bytes())).unwrap(),
                       key, "{count} {}", String::from_utf8_lossy(&salt));
        }
    }

    /// Kc, Ke and Ki for usage 2 under each base key, in RFC 8009's and
    /// RFC 6803's shared layout. The base key line ends `key:`.
    fn usage_key_vectors(lines: &[&str], base_label: &str,
                         enctype_for: impl Fn(&[u8]) -> &'static Enctype) -> usize {
        let mut base = Vec::new();
        let mut found = 0;
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if l.ends_with(base_label) {
                base = value(lines, i);
            } else if let Some(which) = ["Kc", "Ke", "Ki"].iter().position(|k| l.starts_with(k)) {
                let e = enctype_for(&base);
                let keys = e.usage_keys(&base, 2).unwrap();
                let derived = [keys.kc, keys.ke, keys.ki];
                assert_eq!(derived[which], value(lines, i), "{} {l}", e.name);
                found += 1;
            }
        }
        found
    }

    #[test]
    fn rfc_6803_key_derivation() {
        let lines = section(RFC6803, "   Sample results for key", "   Sample encryptions");
        let found = usage_key_vectors(&lines, "-bit Camellia key:", |base| {
            by_name(if base.len() == 16 { "camellia128-cts-cmac" } else { "camellia256-cts-cmac" })
                .unwrap()
        });
        assert_eq!(found, 6);
    }

    /// RFC 6803's plaintexts are literal text after the label, or
    /// `(empty)`.
    fn literal(line: &str) -> Vec<u8> {
        let text = line.split_once(": ").unwrap().1;
        if text == "(empty)" { Vec::new() } else { text.as_bytes().to_vec() }
    }

    #[test]
    fn rfc_6803_encryption() {
        // The document gives no key usage for these. They are 0 to 4 in
        // the order printed, restarting for the 256-bit keys - which is
        // what MIT Kerberos's t_decrypt.c uses for them.
        let lines = section(RFC6803, "   Sample encryptions", "   Sample checksums");
        let (mut plain, mut confounder, mut key) = (Vec::new(), Vec::new(), Vec::new());
        let mut found = 0;
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if l.starts_with("Plaintext:") {
                plain = literal(l);
            } else if l.starts_with("Random confounder:") {
                confounder = value(&lines, i);
            } else if l.ends_with("-bit Camellia key:") {
                key = value(&lines, i);
            } else if l.starts_with("Ciphertext:") {
                let e = by_name(if key.len() == 16 { "camellia128-cts-cmac" }
                                else { "camellia256-cts-cmac" }).unwrap();
                let usage = found % 5;
                let expected = value(&lines, i);
                assert_eq!(e.encrypt(&key, usage, &plain, Some(&confounder)).unwrap(), expected,
                           "{} {:?}", e.name, String::from_utf8_lossy(&plain));
                assert_eq!(e.decrypt(&key, usage, &expected).unwrap(), plain);
                found += 1;
            }
        }
        assert_eq!(found, 10);
    }

    #[test]
    fn rfc_6803_checksums() {
        let lines = section(RFC6803, "   Sample checksums", "11.");
        let (mut plain, mut key, mut usage, mut found) = (Vec::new(), Vec::new(), 0, 0);
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if l.starts_with("Plaintext:") {
                plain = literal(l);
            } else if l.ends_with("-bit Camellia key:") {
                key = value(&lines, i);
            } else if let Some(u) = l.strip_prefix("Key usage: ") {
                usage = u.parse().unwrap();
            } else if l.starts_with("Checksum:") {
                let e = by_name(if key.len() == 16 { "camellia128-cts-cmac" }
                                else { "camellia256-cts-cmac" }).unwrap();
                let kind = e.mandatory_cksumtype();
                let sum = kind.make(&key, usage, &plain, None).unwrap();
                assert_eq!(kind.id, if key.len() == 16 { 17 } else { 18 });
                assert_eq!(sum, value(&lines, i), "usage {usage}");
                found += 1;
            }
        }
        assert_eq!(found, 4);
    }

    // ---------------------------------------------------------- RFC 8009 --

    fn sha2_enctype(len: usize) -> &'static Enctype {
        by_name(if len == 16 { "aes128-cts-hmac-sha256-128" } else { "aes256-cts-hmac-sha384-192" })
            .unwrap()
    }

    #[test]
    fn rfc_8009_string_to_key() {
        let lines = section(RFC8009, "Appendix A", "   Sample results for key");
        let (mut count, mut password, mut saltp, mut found) = (0u32, Vec::new(), Vec::new(), 0);
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if let Some(n) = l.strip_prefix("Iteration count = ") {
                count = n.parse().unwrap();
            } else if l.starts_with("Pass phrase") {
                password = phrase(&lines, i);
            } else if l.starts_with("Saltp for") {
                saltp = value(&lines, i);
            } else if l.ends_with("base-key:") {
                let key = value(&lines, i);
                let e = sha2_enctype(key.len());
                // saltp is the type's name, a zero byte and the salt.
                let prefix = format!("{}\0", e.name);
                let salt = saltp.strip_prefix(prefix.as_bytes()).expect("the enctype's name");
                assert_eq!(e.string_to_key(&password, salt, Some(&count.to_be_bytes())).unwrap(),
                           key);
                found += 1;
            }
        }
        assert_eq!(found, 2);
    }

    #[test]
    fn rfc_8009_key_derivation() {
        let lines = section(RFC8009, "   Sample results for key", "   Sample encryptions");
        assert_eq!(usage_key_vectors(&lines, "base-key:", |base| sha2_enctype(base.len())), 6);
    }

    /// The usage 2 base keys of the key derivation section, by length.
    fn sha2_base_keys() -> Vec<Vec<u8>> {
        let lines = section(RFC8009, "   Sample results for key", "   Sample encryptions");
        (0..lines.len()).filter(|&i| label(lines[i]).ends_with("base-key:"))
            .map(|i| value(&lines, i)).collect()
    }

    #[test]
    fn rfc_8009_encryption() {
        let bases = sha2_base_keys();
        assert_eq!(bases.len(), 2);
        let lines = section(RFC8009, "   Sample encryptions", "   Sample checksums");
        let (mut e, mut plain, mut confounder) = (None, Vec::new(), Vec::new());
        let mut found = 0;
        for i in 0..lines.len() {
            let l = label(lines[i]);
            let named = l.trim_start_matches("enctype ").trim_end_matches(':');
            if let Ok(t) = by_name(named) {
                e = Some(t);
            } else if l.starts_with("Plaintext:") {
                plain = value(&lines, i);
            } else if l.starts_with("Confounder:") {
                confounder = value(&lines, i);
            } else if l.starts_with("Ciphertext") {
                let e = e.expect("an enctype before the first vector");
                let base = bases.iter().find(|b| b.len() == e.key_len()).unwrap();
                let expected = value(&lines, i);
                assert_eq!(e.encrypt(base, 2, &plain, Some(&confounder)).unwrap(), expected,
                           "{} {} bytes", e.name, plain.len());
                assert_eq!(e.decrypt(base, 2, &expected).unwrap(), plain);
                found += 1;
            }
        }
        assert_eq!(found, 8);
    }

    #[test]
    fn rfc_8009_checksums() {
        let bases = sha2_base_keys();
        let lines = section(RFC8009, "   Sample checksums", "   Sample pseudorandom");
        let (mut plain, mut found) = (Vec::new(), 0);
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if l.starts_with("Plaintext:") {
                plain = value(&lines, i);
            } else if l.starts_with("Checksum:") {
                let expected = value(&lines, i);
                let e = sha2_enctype(if expected.len() == 16 { 16 } else { 32 });
                let base = bases.iter().find(|b| b.len() == e.key_len()).unwrap();
                let kind = e.mandatory_cksumtype();
                assert_eq!(kind.make(base, 2, &plain, None).unwrap(), expected);
                assert!(kind.verify(base, 2, &plain, &expected).unwrap());
                assert!(!kind.verify(base, 3, &plain, &expected).unwrap());
                found += 1;
            }
        }
        assert_eq!(found, 2);
    }

    #[test]
    fn rfc_8009_prf() {
        let lines = section(RFC8009, "   Sample pseudorandom", "Acknowledgements");
        let input = b"test";
        assert!(lines.iter().any(|l| l.contains("\"test\" (0x74657374)")));
        let (mut key, mut found) = (Vec::new(), 0);
        for i in 0..lines.len() {
            let l = label(lines[i]);
            if l.starts_with("input-key value") {
                key = value(&lines, i);
            } else if l.starts_with("PRF output:") {
                let e = sha2_enctype(key.len());
                assert_eq!(e.prf(&key, input).unwrap(), value(&lines, i), "{}", e.name);
                found += 1;
            }
        }
        assert_eq!(found, 2);
    }

    /// RFC 3961 6.3.1 corrects each third of a Triple DES key as 6.2
    /// corrects a DES key. No published vector reaches it; seven zero
    /// bytes do, becoming the weak key 0101010101010101.
    #[test]
    fn des3_random_to_key_corrects_weak_keys() {
        let key = des3_random_to_key(&[0; 21]);
        assert_eq!(key, [[1, 1, 1, 1, 1, 1, 1, 0xf1]; 3].concat());
        assert!(!allcrypt::block_ciphers::des::Des::is_weak(&key[..8]));
        // A key that is not weak is left alone.
        // 0x02 has odd parity already; the eighth byte, 0, becomes 0x01.
        assert_eq!(allcrypt::kdf::kerberos::des_random_to_key(&[2; 7]).unwrap(),
                   [2, 2, 2, 2, 2, 2, 2, 1]);
    }

    /// A parser that skips a line is caught by the counts above; one that
    /// reads the wrong bytes is caught here, against values in the
    /// document checked by eye.
    #[test]
    fn the_value_parser_reads_what_is_printed() {
        let lines = ["   DK:  925179d04591a79b", r#"   usage:   6b65726265726f73 ("kerberos")"#,
                     "   Input:", "     0000:  49 20 77", "     0010:  20", "   Next IV:"];
        assert_eq!(value(&lines, 0), unhex("925179d04591a79b"));
        assert_eq!(value(&lines, 1), b"kerberos");
        assert_eq!(value(&lines, 2), unhex("49207720"));
        assert_eq!(expression("\"Juri\" + s-caron(U+0161) + \"i\""), "Juri\u{161}i".as_bytes());
    }
}
