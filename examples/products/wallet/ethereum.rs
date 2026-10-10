//! Ethereum's account formats: the address (with EIP-55's mixed-case
//! checksum), the keystore files clients write (Web3 Secret Storage
//! version 3 under scrypt or PBKDF2, the version 1 files of early geth,
//! and the 2014 presale wallet), and EIP-191 signed messages.

use allcrypt::api::{self, AnyBlockCipher};
use allcrypt::bignum::BigUint;
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::ec::Point;

use crate::cli::hex;
use crate::hash::keccak256;
use crate::json::{self, Json};
use crate::keys::{private_bytes, private_from_bytes, public_key, recover, sign_recoverable,
                  uncompressed};

/// The last 20 bytes of Keccak-256 of the uncompressed key without its
/// 04 prefix.
pub fn address(point: &Point) -> [u8; 20] {
    keccak256(&uncompressed(point)[1..])[12..].try_into().expect("20 bytes")
}

/// EIP-55: each letter upper case where the same nibble of the Keccak-256
/// of the lower-case hex address is 8 or more.
pub fn checksummed(address: &[u8; 20]) -> String {
    let lower: String = address.iter().map(|b| format!("{b:02x}")).collect();
    let hash = keccak256(lower.as_bytes());
    let mixed: String = lower.chars().enumerate().map(|(i, c)| {
        let nibble = (hash[i / 2] >> if i % 2 == 0 { 4 } else { 0 }) & 0xf;
        if c.is_ascii_alphabetic() && nibble >= 8 { c.to_ascii_uppercase() } else { c }
    }).collect();
    format!("0x{mixed}")
}

/// Parse an address. Mixed case must be EIP-55's; all lower or all upper
/// carries no checksum and is taken as it is.
pub fn parse_address(text: &str) -> Result<[u8; 20], String> {
    let hex = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{text}: an address is 40 hex digits."));
    }
    let bytes: [u8; 20] = unhex(hex)?.try_into().map_err(|_| "20 bytes".to_string())?;
    let mixed = hex.chars().any(|c| c.is_ascii_lowercase())
        && hex.chars().any(|c| c.is_ascii_uppercase());
    if mixed && checksummed(&bytes)[2..] != *hex {
        return Err(format!("{text}: the EIP-55 checksum (the letters' case) does not match."));
    }
    Ok(bytes)
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    crate::cli::unhex(text, &[])
}

// ---------------------------------------------------------------- keystores --

/// The most scrypt memory (128 * N * r bytes) a keystore may ask for: 2
/// GiB, eight times geth's standard. A file sets its own cost.
pub const MAX_SCRYPT_MEMORY: u64 = 2 << 30;

fn number(params: &Json, name: &str) -> Result<u64, String> {
    params.get(name).and_then(Json::as_u64)
        .ok_or_else(|| format!("The key derivation parameter {name} is missing."))
}

fn field<'a>(json: &'a Json, name: &str) -> Result<&'a str, String> {
    json.str(name).ok_or_else(|| format!("The keystore has no {name}."))
}

fn derive(crypto: &Json, password: &[u8]) -> Result<Vec<u8>, String> {
    let params = crypto.get("kdfparams").ok_or("The keystore has no kdfparams.")?;
    let salt = unhex(field(params, "salt")?)?;
    let len = number(params, "dklen")? as usize;
    if len < 32 {
        return Err(format!("A derived key of {len} bytes; the MAC needs 32."));
    }
    match field(crypto, "kdf")? {
        "scrypt" => {
            let (n, r, p) = (number(params, "n")?, number(params, "r")?, number(params, "p")?);
            if 128 * n.saturating_mul(r) > MAX_SCRYPT_MEMORY {
                return Err(format!("scrypt with N = {n} and r = {r} needs more than 2 GiB."));
            }
            api::scrypt(password, &salt, n, u32::try_from(r).map_err(|_| "r too large")?,
                        u32::try_from(p).map_err(|_| "p too large")?, len)
        }
        "pbkdf2" => {
            let prf = field(params, "prf")?;
            if prf != "hmac-sha256" {
                return Err(format!("PBKDF2 with {prf}; Web3 Secret Storage uses hmac-sha256."));
            }
            api::pbkdf2("sha256", password, &salt,
                        u32::try_from(number(params, "c")?).map_err(|_| "c too large")?, len)
        }
        other => Err(format!("Key derivation {other} is not one Web3 Secret Storage defines.")),
    }
}

pub struct Account {
    pub key: BigUint,
    pub address: [u8; 20],
    pub format: &'static str,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account").field("key", &crate::hidden::Hidden)
            .field("address", &self.address).field("format", &self.format).finish()
    }
}

/// A keystore file of any of the three kinds, opened. The MAC (or, for a
/// presale wallet, the address) is what says the password was right.
pub fn decrypt_keystore(text: &str, password: &[u8]) -> Result<Account, String> {
    let json = json::parse(text)?;
    if let Some(seed) = json.str("encseed") {
        return decrypt_presale(&json, seed, password);
    }
    // Version 1 files write the number as a string.
    let version = match json.get("version") {
        Some(Json::String(s)) => s.parse().ok(),
        Some(v) => v.as_u64(),
        None => None,
    }.ok_or("The keystore has no version.")?;
    let crypto = match version {
        3 => json.get("crypto").or_else(|| json.get("Crypto")),
        1 => json.get("Crypto"),
        other => return Err(format!("Keystore version {other} is not one this reads.")),
    }.ok_or("The keystore has no crypto section.")?;
    let cipher_text = unhex(field(crypto, "ciphertext")?)?;
    let iv = unhex(field(crypto.get("cipherparams").ok_or("No cipherparams.")?, "iv")?)?;
    let derived = derive(crypto, password)?;
    let mut mac_input = derived[16..32].to_vec();
    mac_input.extend_from_slice(&cipher_text);
    let mac = unhex(field(crypto, "mac")?)?;
    if keccak256(&mac_input) != mac {
        return Err("Wrong password: the keystore's MAC does not match.".to_string());
    }
    let plain = if version == 3 {
        let name = field(crypto, "cipher")?;
        if name != "aes-128-ctr" {
            return Err(format!("Cipher {name}; Web3 Secret Storage uses aes-128-ctr."));
        }
        if iv.len() != 16 {
            return Err("The CTR IV is 16 bytes.".to_string());
        }
        let mut out = Vec::new();
        AnyBlockCipher::new("aes", &derived[..16], None)?.ctr_encrypt(&cipher_text, &mut out,
                                                                        &iv)?;
        out
    } else {
        // Version 1: CBC under the first half of Keccak-256 of the first
        // half of the derived key, PKCS#7 padded.
        let key = keccak256(&derived[..16]);
        let mut out = Vec::new();
        AnyBlockCipher::new("aes", &key[..16], None)?.cbc_decrypt(&cipher_text, &mut out,
                                                                    &iv)?;
        unpad(out)?
    };
    // geth accepts keys shorter than 32 bytes, left-padded (its 30- and
    // 31-byte test vectors).
    if plain.len() > 32 {
        return Err(format!("A {}-byte private key.", plain.len()));
    }
    let mut padded = vec![0u8; 32 - plain.len()];
    padded.extend(plain);
    let key = private_from_bytes(&padded)?;
    let address = address(&public_key(&key));
    if let Some(stated) = json.str("address") {
        if parse_address(stated)? != address {
            return Err("The key opens, but is not the key of the address the file states."
                .to_string());
        }
    }
    Ok(Account { key, address, format: if version == 3 { "version 3" } else { "version 1" } })
}

fn unpad(mut data: Vec<u8>) -> Result<Vec<u8>, String> {
    let n = *data.last().ok_or("Nothing decrypted.")? as usize;
    if n == 0 || n > 16 || n > data.len() || data[data.len() - n..].iter().any(|&b| b as usize != n) {
        return Err("Bad padding: the password is wrong or the file damaged.".to_string());
    }
    data.truncate(data.len() - n);
    Ok(data)
}

/// The 2014 presale wallet: PBKDF2-HMAC-SHA256 of the password salted
/// with itself, 2000 rounds, keys AES-128-CBC over a seed whose
/// Keccak-256 is the private key. There is no MAC; the stated address is
/// the check.
fn decrypt_presale(json: &Json, seed: &str, password: &[u8]) -> Result<Account, String> {
    let data = unhex(seed)?;
    if data.len() < 32 || !data.len().is_multiple_of(16) {
        return Err("A presale encseed is an IV and whole blocks.".to_string());
    }
    let key = api::pbkdf2("sha256", password, password, 2000, 16)?;
    let mut out = Vec::new();
    AnyBlockCipher::new("aes", &key, None)?.cbc_decrypt(&data[16..], &mut out,
                                                          &data[..16])?;
    let wrong = || "Wrong password: the key it gives is not the address's.".to_string();
    let plain = unpad(out).map_err(|_| wrong())?;
    let key = private_from_bytes(&keccak256(&plain))?;
    let address = address(&public_key(&key));
    let stated = parse_address(json.str("ethaddr").ok_or("The presale file has no ethaddr.")?)?;
    if stated != address {
        return Err(wrong());
    }
    Ok(Account { key, address, format: "presale" })
}

/// Parameters for a new keystore.
pub enum Kdf {
    Scrypt { n: u64, r: u32, p: u32 },
    Pbkdf2 { iterations: u32 },
}

/// A version 3 keystore. `fixed` gives the salt, IV and id for
/// known-answer tests; otherwise they are random.
pub fn encrypt_keystore(key: &BigUint, password: &[u8], kdf: &Kdf,
                        fixed: Option<(&[u8], &[u8], &[u8])>) -> Result<String, String> {
    let (salt, iv, id) = match fixed {
        Some((s, i, d)) => (s.to_vec(), i.to_vec(), d.to_vec()),
        None => (api::random_bytes(32)?, api::random_bytes(16)?, api::random_bytes(16)?),
    };
    let (derived, kdf_name, mut params) = match kdf {
        Kdf::Scrypt { n, r, p } => {
            let mut params = Json::object();
            params.set("dklen", Json::Number("32".to_string()));
            params.set("n", Json::Number(n.to_string()));
            params.set("p", Json::Number(p.to_string()));
            params.set("r", Json::Number(r.to_string()));
            (api::scrypt(password, &salt, *n, *r, *p, 32)?, "scrypt", params)
        }
        Kdf::Pbkdf2 { iterations } => {
            let mut params = Json::object();
            params.set("c", Json::Number(iterations.to_string()));
            params.set("dklen", Json::Number("32".to_string()));
            params.set("prf", Json::string("hmac-sha256"));
            (api::pbkdf2("sha256", password, &salt, *iterations, 32)?, "pbkdf2", params)
        }
    };
    params.set("salt", Json::string(&hex(&salt)));
    let mut cipher_text = Vec::new();
    AnyBlockCipher::new("aes", &derived[..16], None)?.ctr_encrypt(&private_bytes(key),
                                                                    &mut cipher_text, &iv)?;
    let mut mac_input = derived[16..32].to_vec();
    mac_input.extend_from_slice(&cipher_text);
    let mut cipherparams = Json::object();
    cipherparams.set("iv", Json::string(&hex(&iv)));
    let mut crypto = Json::object();
    crypto.set("cipher", Json::string("aes-128-ctr"));
    crypto.set("ciphertext", Json::string(&hex(&cipher_text)));
    crypto.set("cipherparams", cipherparams);
    crypto.set("kdf", Json::string(kdf_name));
    crypto.set("kdfparams", params);
    crypto.set("mac", Json::string(&hex(&keccak256(&mac_input))));
    let mut out = Json::object();
    out.set("address", Json::string(&hex(&address(&public_key(key)))));
    out.set("crypto", crypto);
    out.set("id", Json::string(&uuid_v4(&id)));
    out.set("version", Json::Number("3".to_string()));
    Ok(out.to_text())
}

/// A version 4 (random) UUID from 16 bytes, its version and variant bits
/// set.
fn uuid_v4(bytes: &[u8]) -> String {
    let mut b = bytes.to_vec();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

// ----------------------------------------------------------------- messages --

/// EIP-191 version 0x45, as `personal_sign` and `eth_sign` use it: the
/// prefix, the message's length in decimal, the message.
pub fn message_hash(message: &[u8]) -> Vec<u8> {
    let mut data = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    data.extend_from_slice(message);
    keccak256(&data)
}

/// r, s and v = 27 + the recovery id.
pub fn sign_message(key: &BigUint, message: &[u8]) -> Result<Vec<u8>, String> {
    let sig = sign_recoverable(key, &message_hash(message))?;
    let mut out = sig.r.to_bytes_be_padded(32)?;
    out.extend(sig.s.to_bytes_be_padded(32)?);
    out.push(27 + sig.recid);
    Ok(out)
}

/// The signer's address. v may be 27 or 28, or 0 or 1 as some signers
/// write it; s above n/2 is refused, as EIP-2 requires.
pub fn recover_signer(signature: &[u8], message: &[u8]) -> Result<[u8; 20], String> {
    if signature.len() != 65 {
        return Err(format!("A signature is 65 bytes, not {}.", signature.len()));
    }
    let recid = match signature[64] {
        v @ (27 | 28) => v - 27,
        v @ (0 | 1) => v,
        v => return Err(format!("v = {v}; a message signature's is 27 or 28.")),
    };
    let r = BigUint::from_bytes_be(&signature[..32]);
    let s = BigUint::from_bytes_be(&signature[32..64]);
    if s > crate::keys::curve().n.shr(1) {
        return Err("s is in the upper half of the group (EIP-2 forbids it).".to_string());
    }
    Ok(address(&recover(&r, &s, recid, &message_hash(message))?))
}
