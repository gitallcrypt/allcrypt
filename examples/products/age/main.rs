//! age, the file encryption format (C2SP age.md, age-encryption.org/v1),
//! built from this library's primitives.
//!
//!     cargo run --release --example age -- keygen [--pq] [--seed N]
//!     cargo run --release --example age -- encrypt IN OUT (-r RECIPIENT)... [--armor]
//!     cargo run --release --example age -- encrypt IN OUT --passphrase PW [--work-factor N] [--armor]
//!     cargo run --release --example age -- decrypt IN OUT (-i IDENTITY | --identity-file FILE)...
//!     cargo run --release --example age -- decrypt IN OUT --passphrase PW
//!
//! `--passphrase-stdin` in place of `--passphrase PW` reads it from
//! standard input instead of the command line.
//!
//! Three recipient types: X25519 (`age1...`), the post-quantum hybrid
//! MLKEM768-X25519 (`age1pq1...`, X-Wing through HPKE), and a
//! passphrase through scrypt. An age file is a textual header that
//! wraps a 16 byte file key once per recipient and ends with an
//! HMAC-SHA-256 under a key derived from the file key, then the payload:
//! a nonce and 64 KiB chunks of ChaCha20-Poly1305 whose nonces count the
//! chunks and mark the last.
//!
//! What has checked it is in `examples/products/README.md`.

use allcrypt::api::{AnyHash, MlKemKey};
use allcrypt::ec::x25519;
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::hash_functions::keccak::Keccak;
use allcrypt::hash_functions::HashFunction;
use allcrypt::kdf::{hkdf, hkdf_expand, hkdf_extract};
use allcrypt::mac::hmac::Hmac;
use allcrypt::pq::ml_kem;
use allcrypt::stream_ciphers::chacha20poly1305;

#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/inflate.rs"]
#[cfg(test)]
mod inflate;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

const VERSION_LINE: &str = "age-encryption.org/v1";
const CHUNK: usize = 64 * 1024;
const ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_END: &str = "-----END AGE ENCRYPTED FILE-----";
/// The largest scrypt work factor accepted: 2^22 is a gigabyte of
/// memory, age's own ceiling.
const MAX_WORK_FACTOR: u32 = 22;

type Random<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

/// How decryption failed, in the age test suite's categories.
#[derive(Debug, PartialEq)]
enum Failure {
    Armor(String),
    Header(String),
    NoMatch,
    Hmac,
    Payload(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Armor(why) => write!(f, "the ASCII armor is not valid: {why}"),
            Failure::Header(why) => write!(f, "the header is not valid: {why}"),
            Failure::NoMatch => write!(f, "no identity matches any of the recipients"),
            Failure::Hmac => write!(f, "the header's MAC does not match"),
            Failure::Payload(why) => write!(f, "the payload does not decrypt: {why}"),
        }
    }
}

fn header_error<T>(why: &str) -> Result<T, Failure> {
    Err(Failure::Header(why.to_string()))
}

// ------------------------------------------------------- encodings ---

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 without padding, as the header writes it.
fn b64_encode(data: &[u8]) -> String {
    allcrypt::pem::encode(data).trim_end_matches('=').to_string()
}

/// Base64 without padding, refusing anything that would not encode back
/// to the same text: padding, a stray character, or unused bits set in
/// the last character.
fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 6 || acc != 0 {
        return None;
    }
    Some(out)
}

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|b| b & 31));
    out
}

fn regroup(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    let max = (1 << to) - 1;
    for &v in data {
        acc = (acc << from) | u32::from(v);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || (acc << (to - bits)) & max != 0 {
        return None;
    }
    Some(out)
}

/// BIP 173 Bech32, without its 90 character limit: an `age1pq`
/// recipient is nearly two thousand.
fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let values = regroup(data, 8, 5, true).unwrap_or_default();
    let mut check_input = hrp_expand(hrp);
    check_input.extend(&values);
    check_input.extend([0u8; 6]);
    let polymod = bech32_polymod(&check_input) ^ 1;
    let mut out = format!("{hrp}1");
    for v in values.iter().copied().chain((0..6).map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8)) {
        out.push(BECH32[v as usize] as char);
    }
    out
}

/// Bech32 back to its human readable part (lower case) and data. One
/// case throughout, as BIP 173 requires.
fn bech32_decode(text: &str) -> Result<(String, Vec<u8>), String> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) && text.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err("Bech32 in mixed case.".to_string());
    }
    let lower = text.to_ascii_lowercase();
    let split = lower.rfind('1').ok_or("Bech32 without a separator.")?;
    let (hrp, rest) = (&lower[..split], &lower[split + 1..]);
    if hrp.is_empty() || rest.len() < 6 {
        return Err("Bech32 too short.".to_string());
    }
    let values: Vec<u8> = rest.bytes().map(|b| BECH32.iter().position(|&c| c == b).map(|v| v as u8))
        .collect::<Option<_>>().ok_or("Bech32 with a character outside its alphabet.")?;
    let mut check_input = hrp_expand(hrp);
    check_input.extend(&values);
    if bech32_polymod(&check_input) != 1 {
        return Err("Bech32 checksum does not match.".to_string());
    }
    let data = regroup(&values[..values.len() - 6], 5, 8, false)
        .ok_or("Bech32 with leftover bits.")?;
    Ok((hrp.to_string(), data))
}

// ------------------------------------------------------- primitives ---

fn sha256_hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    hkdf(SHA256::new(&[]), salt, ikm, info, length).unwrap_or_default()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    Hmac::mac(SHA256::new(&[]), key, data)
}

fn aead_seal(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let (mut ciphertext, tag) = chacha20poly1305::seal(key, nonce, &[], plaintext)
        .expect("a 32 byte key and a 12 byte nonce");
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

fn aead_open(key: &[u8], nonce: &[u8; 12], sealed: &[u8]) -> Option<Vec<u8>> {
    let (ciphertext, tag) = sealed.split_at(sealed.len().checked_sub(16)?);
    chacha20poly1305::open(key, nonce, &[], ciphertext, tag).ok()
}

fn x25519_checked(scalar: &[u8; 32], point: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = x25519::exchange(scalar, point).ok()?;
    if shared == [0u8; 32] { None } else { Some(shared) }
}

// ------------------------------------------------------ X-Wing HPKE ---

/// MLKEM768-X25519 (X-Wing) as draft-ietf-hpke-pq specifies it: a 32
/// byte seed, through SHAKE256, gives ML-KEM-768's 64 byte seed and
/// then the X25519 secret; the shared secret is SHA3-256 of both shared
/// secrets, the X25519 ciphertext and public key, and a six byte label.
mod xwing {
    use super::*;

    pub const KEM_ID: u16 = 0x647a;
    const LABEL: &[u8] = b"\\.//^\\";
    pub const PUBLIC_LEN: usize = 1184 + 32;
    pub const ENC_LEN: usize = 1088 + 32;

    pub struct PrivateKey {
        kem: MlKemKey,
        x25519: [u8; 32],
        x25519_public: [u8; 32],
    }

    impl PrivateKey {
        pub fn from_seed(seed: &[u8; 32]) -> Result<PrivateKey, String> {
            let mut shake = Keccak::shake(256, 96)?;
            shake.update(seed);
            let expanded = shake.digest();
            let kem = MlKemKey::from_seed("ML-KEM-768", &expanded[..64])?;
            let x25519: [u8; 32] = expanded[64..96].try_into().map_err(|_| "length")?;
            let x25519_public = x25519::public_key(&x25519)?;
            Ok(PrivateKey { kem, x25519, x25519_public })
        }

        pub fn public(&self) -> Vec<u8> {
            let mut out = self.kem.public_bytes().to_vec();
            out.extend_from_slice(&self.x25519_public);
            out
        }

        pub fn decapsulate(&self, enc: &[u8]) -> Option<Vec<u8>> {
            if enc.len() != ENC_LEN {
                return None;
            }
            let (ct_m, ct_x) = enc.split_at(1088);
            let ss_m = self.kem.decapsulate(ct_m).ok()?;
            let ct_x: [u8; 32] = ct_x.try_into().ok()?;
            let ss_x = x25519_checked(&self.x25519, &ct_x)?;
            Some(combine(&ss_m, &ss_x, &ct_x, &self.x25519_public))
        }
    }

    fn combine(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Vec<u8> {
        let mut h = Keccak::sha3(32).expect("SHA3-256");
        for part in [ss_m, ss_x, ct_x, pk_x, LABEL] {
            h.update(part);
        }
        h.digest()
    }

    /// `(shared secret, enc)`.
    pub fn encapsulate(public: &[u8], random: Random<'_>) -> Result<(Vec<u8>, Vec<u8>), String> {
        if public.len() != PUBLIC_LEN {
            return Err("an MLKEM768-X25519 recipient is 1216 bytes".to_string());
        }
        let (ek, pk_x) = public.split_at(1184);
        let mut m = [0u8; 32];
        random(&mut m)?;
        let (ss_m, mut enc) = ml_kem::encapsulate_internal(ml_kem::parameters("ML-KEM-768")?,
                                                         ek, &m)?;
        let mut e = [0u8; 32];
        random(&mut e)?;
        let ct_x = x25519::public_key(&e)?;
        let pk_x: [u8; 32] = pk_x.try_into().map_err(|_| "length")?;
        let ss_x = x25519_checked(&e, &pk_x).ok_or("a low-order X25519 recipient")?;
        enc.extend_from_slice(&ct_x);
        Ok((combine(&ss_m, &ss_x, &ct_x, &pk_x), enc))
    }

    /// RFC 9180's base mode key schedule for one message: the AEAD key
    /// and nonce, for KEM `KEM_ID`, HKDF-SHA256 and ChaCha20Poly1305.
    pub fn key_schedule(shared_secret: &[u8], info: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let mut suite = b"HPKE".to_vec();
        suite.extend_from_slice(&KEM_ID.to_be_bytes());
        suite.extend_from_slice(&1u16.to_be_bytes());
        suite.extend_from_slice(&3u16.to_be_bytes());
        let labeled = |label: &str, rest: &[u8]| -> Vec<u8> {
            let mut out = b"HPKE-v1".to_vec();
            out.extend_from_slice(&suite);
            out.extend_from_slice(label.as_bytes());
            out.extend_from_slice(rest);
            out
        };
        let extract = |salt: &[u8], label: &str, ikm: &[u8]|
            hkdf_extract(SHA256::new(&[]), salt, &labeled(label, ikm));
        let expand = |prk: &[u8], label: &str, info: &[u8], length: u16| {
            let mut full = length.to_be_bytes().to_vec();
            full.extend_from_slice(&labeled(label, info));
            hkdf_expand(SHA256::new(&[]), prk, &full, length as usize).unwrap_or_default()
        };
        let psk_id_hash = extract(b"", "psk_id_hash", b"");
        let info_hash = extract(b"", "info_hash", info);
        let mut context = vec![0u8];
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);
        let secret = extract(shared_secret, "secret", b"");
        let key = expand(&secret, "key", &context, 32);
        let nonce = expand(&secret, "base_nonce", &context, 12);
        (key, nonce.try_into().unwrap_or([0; 12]))
    }
}

const HYBRID_INFO: &[u8] = b"age-encryption.org/mlkem768x25519";

// ---------------------------------------------------- identities ---

enum Identity {
    X25519([u8; 32]),
    Hybrid(Box<xwing::PrivateKey>),
    Passphrase(Vec<u8>),
}

enum Recipient {
    X25519([u8; 32]),
    Hybrid(Vec<u8>),
    Passphrase { passphrase: Vec<u8>, work_factor: u32 },
}

fn parse_identity(text: &str) -> Result<Identity, String> {
    let (hrp, data) = bech32_decode(text.trim())?;
    match hrp.as_str() {
        "age-secret-key-" => Ok(Identity::X25519(data.try_into()
            .map_err(|_| "an X25519 identity is 32 bytes")?)),
        "age-secret-key-pq-" => Ok(Identity::Hybrid(Box::new(xwing::PrivateKey::from_seed(
            &data.try_into().map_err(|_| "a hybrid identity is 32 bytes")?)?))),
        other => Err(format!("{other:?} is not an age identity.")),
    }
}

fn parse_recipient(text: &str) -> Result<Recipient, String> {
    let (hrp, data) = bech32_decode(text.trim())?;
    match hrp.as_str() {
        "age" => Ok(Recipient::X25519(data.try_into()
            .map_err(|_| "an X25519 recipient is 32 bytes")?)),
        "age1pq" if data.len() == xwing::PUBLIC_LEN => Ok(Recipient::Hybrid(data)),
        other => Err(format!("{other:?} is not an age recipient.")),
    }
}

// ----------------------------------------------------------- header ---

struct Stanza {
    args: Vec<String>,
    body: Vec<u8>,
}

struct Header {
    stanzas: Vec<Stanza>,
    mac: Vec<u8>,
    /// Everything the MAC covers: up to and including `---`.
    covered_len: usize,
    /// Where the payload starts.
    len: usize,
}

fn line(data: &[u8], at: usize) -> Result<&str, Failure> {
    let end = data[at..].iter().position(|&b| b == b'\n')
        .ok_or(Failure::Header("a line without its line feed".into()))?;
    std::str::from_utf8(&data[at..at + end]).map_err(|_| Failure::Header("not ASCII".into()))
}

fn parse_header(data: &[u8]) -> Result<Header, Failure> {
    let mut at = 0;
    let version = line(data, at)?;
    if version != VERSION_LINE {
        return header_error("not an age v1 file");
    }
    at += version.len() + 1;
    let mut stanzas = Vec::new();
    loop {
        let text = line(data, at)?;
        if let Some(rest) = text.strip_prefix("---") {
            let covered_len = at + 3;
            let encoded = rest.strip_prefix(' ').ok_or(Failure::Header("--- without its MAC".into()))?;
            let mac = b64_decode(encoded).filter(|m| m.len() == 32)
                .ok_or(Failure::Header("the MAC is not 32 bytes of canonical base64".into()))?;
            if stanzas.is_empty() {
                return header_error("no recipient stanzas");
            }
            return Ok(Header { stanzas, mac, covered_len, len: at + text.len() + 1 });
        }
        let args_text = text.strip_prefix("-> ").ok_or(Failure::Header("a line that is not a stanza".into()))?;
        let args: Vec<String> = args_text.split(' ').map(str::to_string).collect();
        if args.iter().any(|a| a.is_empty() || !a.bytes().all(|b| (0x21..=0x7e).contains(&b))) {
            return header_error("an empty or non-printable stanza argument");
        }
        at += text.len() + 1;
        let mut body_text = String::new();
        loop {
            let body_line = line(data, at)?;
            if body_line.len() > 64 {
                return header_error("a stanza body line longer than 64 columns");
            }
            body_text.push_str(body_line);
            at += body_line.len() + 1;
            if body_line.len() < 64 {
                break;
            }
        }
        let body = b64_decode(&body_text).ok_or(Failure::Header("a stanza body that is not canonical base64".into()))?;
        stanzas.push(Stanza { args, body });
    }
}

fn write_header(stanzas: &[Stanza], hmac_key: &[u8]) -> Vec<u8> {
    let mut out = format!("{VERSION_LINE}\n");
    for stanza in stanzas {
        out.push_str(&format!("-> {}\n", stanza.args.join(" ")));
        let body = b64_encode(&stanza.body);
        let mut rest = body.as_str();
        while rest.len() >= 64 {
            out.push_str(&rest[..64]);
            out.push('\n');
            rest = &rest[64..];
        }
        out.push_str(rest);
        out.push('\n');
    }
    out.push_str("---");
    let mac = hmac_sha256(hmac_key, out.as_bytes());
    out.push_str(&format!(" {}\n", b64_encode(&mac)));
    out.into_bytes()
}

// ---------------------------------------------------- wrapping keys ---

const ZERO_NONCE: [u8; 12] = [0; 12];

/// `Ok(Some(file key))`, `Ok(None)` for a stanza that is not this
/// identity's, `Err` for one that is malformed.
fn unwrap(identity: &Identity, stanza: &Stanza) -> Result<Option<Vec<u8>>, Failure> {
    let kind = stanza.args[0].as_str();
    match (identity, kind) {
        (Identity::X25519(secret), "X25519") => {
            if stanza.args.len() != 2 {
                return header_error("an X25519 stanza has one argument");
            }
            let share: [u8; 32] = b64_decode(&stanza.args[1]).and_then(|s| s.try_into().ok())
                .ok_or(Failure::Header("an X25519 share is 32 bytes".into()))?;
            if stanza.body.len() != 32 {
                return header_error("an X25519 stanza body is 32 bytes");
            }
            let Some(shared) = x25519_checked(secret, &share) else {
                return header_error("a low-order X25519 share");
            };
            let recipient = x25519::public_key(secret).map_err(Failure::Header)?;
            let mut salt = share.to_vec();
            salt.extend_from_slice(&recipient);
            let key = sha256_hkdf(&salt, &shared, b"age-encryption.org/v1/X25519", 32);
            Ok(aead_open(&key, &ZERO_NONCE, &stanza.body))
        }
        (Identity::Hybrid(secret), "mlkem768x25519") => {
            if stanza.args.len() != 2 {
                return header_error("an mlkem768x25519 stanza has one argument");
            }
            let enc = b64_decode(&stanza.args[1]).filter(|e| e.len() == xwing::ENC_LEN)
                .ok_or(Failure::Header("an mlkem768x25519 enc is 1120 bytes".into()))?;
            if stanza.body.len() != 32 {
                return header_error("an mlkem768x25519 stanza body is 32 bytes");
            }
            let Some(shared) = secret.decapsulate(&enc) else {
                return header_error("the encapsulated key does not decapsulate");
            };
            let (key, nonce) = xwing::key_schedule(&shared, HYBRID_INFO);
            Ok(aead_open(&key, &nonce, &stanza.body))
        }
        (Identity::Passphrase(passphrase), "scrypt") => {
            if stanza.args.len() != 3 {
                return header_error("an scrypt stanza has two arguments");
            }
            let salt = b64_decode(&stanza.args[1]).filter(|s| s.len() == 16)
                .ok_or(Failure::Header("an scrypt salt is 16 bytes".into()))?;
            let factor = &stanza.args[2];
            if !factor.starts_with(|c: char| ('1'..='9').contains(&c))
                || !factor.bytes().all(|b| b.is_ascii_digit()) {
                return header_error("an scrypt work factor is a decimal without leading zeros");
            }
            let factor: u32 = factor.parse().map_err(|_| Failure::Header("work factor".into()))?;
            if factor > MAX_WORK_FACTOR {
                return header_error("an scrypt work factor over the limit");
            }
            if stanza.body.len() != 32 {
                return header_error("an scrypt stanza body is 32 bytes");
            }
            let mut full_salt = b"age-encryption.org/v1/scrypt".to_vec();
            full_salt.extend_from_slice(&salt);
            let key = allcrypt::kdf::scrypt::scrypt(passphrase, &full_salt, 1 << factor, 8, 1, 32)
                .map_err(Failure::Header)?;
            Ok(aead_open(&key, &ZERO_NONCE, &stanza.body))
        }
        _ => Ok(None),
    }
}

fn wrap(recipient: &Recipient, file_key: &[u8], random: Random<'_>) -> Result<Stanza, String> {
    match recipient {
        Recipient::X25519(public) => {
            let mut ephemeral = [0u8; 32];
            random(&mut ephemeral)?;
            let share = x25519::public_key(&ephemeral)?;
            let shared = x25519_checked(&ephemeral, public).ok_or("a low-order recipient")?;
            let mut salt = share.to_vec();
            salt.extend_from_slice(public);
            let key = sha256_hkdf(&salt, &shared, b"age-encryption.org/v1/X25519", 32);
            Ok(Stanza { args: vec!["X25519".into(), b64_encode(&share)],
                        body: aead_seal(&key, &ZERO_NONCE, file_key) })
        }
        Recipient::Hybrid(public) => {
            let (shared, enc) = xwing::encapsulate(public, random)?;
            let (key, nonce) = xwing::key_schedule(&shared, HYBRID_INFO);
            Ok(Stanza { args: vec!["mlkem768x25519".into(), b64_encode(&enc)],
                        body: aead_seal(&key, &nonce, file_key) })
        }
        Recipient::Passphrase { passphrase, work_factor } => {
            let mut salt = [0u8; 16];
            random(&mut salt)?;
            let mut full_salt = b"age-encryption.org/v1/scrypt".to_vec();
            full_salt.extend_from_slice(&salt);
            let key = allcrypt::kdf::scrypt::scrypt(passphrase, &full_salt, 1 << work_factor, 8, 1,
                                                    32)?;
            Ok(Stanza { args: vec!["scrypt".into(), b64_encode(&salt), work_factor.to_string()],
                        body: aead_seal(&key, &ZERO_NONCE, file_key) })
        }
    }
}

// ---------------------------------------------------------- payload ---

fn chunk_nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

/// The payload decrypted chunk by chunk, as age's reference reader
/// does. On failure, what was released before it - each chunk only once
/// its tag has verified.
///
/// A short chunk is the last, and must authenticate as the final chunk.
/// A full one is tried as an ordinary chunk and then as the final one;
/// if final, nothing may follow it. An empty final chunk is allowed only
/// as the whole payload.
fn decrypt_payload(file_key: &[u8], nonce: &[u8], mut rest: &[u8]) -> (Vec<u8>, Option<Failure>) {
    let key = sha256_hkdf(nonce, file_key, b"payload", 32);
    let mut out = Vec::new();
    let mut counter = 0u64;
    loop {
        if rest.is_empty() && counter > 0 {
            return (out, Some(Failure::Payload("the file ends without a final chunk".into())));
        }
        let take = rest.len().min(CHUNK + 16);
        let sealed = &rest[..take];
        rest = &rest[take..];
        let (plain, last) = if take < CHUNK + 16 {
            (aead_open(&key, &chunk_nonce(counter, true), sealed), true)
        } else {
            match aead_open(&key, &chunk_nonce(counter, false), sealed) {
                Some(plain) => (Some(plain), false),
                None => (aead_open(&key, &chunk_nonce(counter, true), sealed), true),
            }
        };
        let Some(plain) = plain else {
            return (out, Some(Failure::Payload(format!("chunk {counter} does not authenticate"))));
        };
        if last && plain.is_empty() && counter > 0 {
            return (out, Some(Failure::Payload("an empty final chunk after others".into())));
        }
        out.extend_from_slice(&plain);
        if last {
            if !rest.is_empty() {
                return (out, Some(Failure::Payload("data after the final chunk".into())));
            }
            return (out, None);
        }
        counter += 1;
    }
}

fn encrypt_payload(file_key: &[u8], plaintext: &[u8], random: Random<'_>)
                   -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; 16];
    random(&mut nonce)?;
    let key = sha256_hkdf(&nonce, file_key, b"payload", 32);
    let mut out = nonce.to_vec();
    let chunks: Vec<&[u8]> = if plaintext.is_empty() { vec![&[]] }
                             else { plaintext.chunks(CHUNK).collect() };
    for (i, chunk) in chunks.iter().enumerate() {
        out.extend(aead_seal(&key, &chunk_nonce(i as u64, i + 1 == chunks.len()), chunk));
    }
    Ok(out)
}

// ------------------------------------------------------------ armor ---

/// RFC 7468's strict encoding, with whitespace around the block and
/// CRLF line ends tolerated.
fn dearmor(data: &[u8]) -> Result<Vec<u8>, Failure> {
    let text = std::str::from_utf8(data).map_err(|_| Failure::Armor("not text".into()))?;
    let text = text.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n');
    let normalized = text.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    if lines.first() != Some(&ARMOR_BEGIN) || lines.last() != Some(&ARMOR_END) {
        return Err(Failure::Armor("not between the BEGIN and END lines".into()));
    }
    lines.remove(0);
    lines.pop();
    if lines.is_empty() {
        // Nothing inside: an empty file, for the header to refuse.
        return Ok(Vec::new());
    }
    let last = lines.len() - 1;
    let mut encoded = String::new();
    for (i, l) in lines.iter().enumerate() {
        if (i < last && l.len() != 64) || (i == last && (l.is_empty() || l.len() > 64)) {
            return Err(Failure::Armor("a line of the wrong length".into()));
        }
        encoded.push_str(l);
    }
    if !encoded.len().is_multiple_of(4) {
        return Err(Failure::Armor("base64 without its padding".into()));
    }
    let unpadded = encoded.trim_end_matches('=');
    if encoded.len() - unpadded.len() > 2 {
        return Err(Failure::Armor("too much padding".into()));
    }
    b64_decode(unpadded).ok_or(Failure::Armor("base64 that is not canonical".into()))
}

fn armor(data: &[u8]) -> Vec<u8> {
    let encoded = allcrypt::pem::encode(data);
    let mut out = format!("{ARMOR_BEGIN}\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out.push('\n');
    out.into_bytes()
}

// ------------------------------------------------- whole files ---

/// Decrypt an age file. `armored` says whether it is ASCII armored;
/// `None` decides by whether it starts, after any whitespace, with the
/// armor's first line.
fn decrypt(file: &[u8], identities: &[Identity], armored: Option<bool>)
           -> (Vec<u8>, Option<Failure>) {
    let armored = armored.unwrap_or_else(|| file.trim_ascii_start()
        .starts_with(ARMOR_BEGIN.as_bytes()));
    let dearmored;
    let data = if armored {
        match dearmor(file) {
            Ok(d) => {
                dearmored = d;
                &dearmored[..]
            }
            Err(failure) => return (Vec::new(), Some(failure)),
        }
    } else {
        file
    };
    let header = match parse_header(data) {
        Ok(h) => h,
        Err(failure) => return (Vec::new(), Some(failure)),
    };
    let scrypt = header.stanzas.iter().any(|s| s.args[0] == "scrypt");
    if scrypt && header.stanzas.len() > 1 {
        return (Vec::new(), Some(Failure::Header("an scrypt stanza with others".into())));
    }
    let mut file_key = None;
    'search: for identity in identities {
        for stanza in &header.stanzas {
            match unwrap(identity, stanza) {
                Ok(Some(key)) => {
                    file_key = Some(key);
                    break 'search;
                }
                Ok(None) => {}
                Err(failure) => return (Vec::new(), Some(failure)),
            }
        }
    }
    let Some(file_key) = file_key else {
        return (Vec::new(), Some(Failure::NoMatch));
    };
    if file_key.len() != 16 {
        return (Vec::new(), Some(Failure::Header("a file key that is not 16 bytes".into())));
    }
    let hmac_key = sha256_hkdf(b"", &file_key, b"header", 32);
    if hmac_sha256(&hmac_key, &data[..header.covered_len]) != header.mac {
        return (Vec::new(), Some(Failure::Hmac));
    }
    // The nonce is read with the header: a file too short for it is a
    // malformed header, not a payload that fails.
    let Some(nonce) = data.get(header.len..header.len + 16) else {
        return (Vec::new(), Some(Failure::Header("no payload nonce".into())));
    };
    decrypt_payload(&file_key, nonce, &data[header.len + 16..])
}

fn encrypt(plaintext: &[u8], recipients: &[Recipient], random: Random<'_>)
           -> Result<Vec<u8>, String> {
    if recipients.is_empty() {
        return Err("at least one recipient".to_string());
    }
    let mut file_key = [0u8; 16];
    random(&mut file_key)?;
    let stanzas = recipients.iter().map(|r| wrap(r, &file_key, random))
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = write_header(&stanzas, &sha256_hkdf(b"", &file_key, b"header", 32));
    out.extend(encrypt_payload(&file_key, plaintext, random)?);
    Ok(out)
}

// -------------------------------------------------------------- CLI ---

fn counter_stream(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), String> {
    let mut counter = 0u64;
    let mut pool: Vec<u8> = Vec::new();
    move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            if pool.is_empty() {
                let mut h = AnyHash::new("sha256")?;
                h.update(&seed.to_be_bytes());
                h.update(&counter.to_be_bytes());
                pool = h.digest();
                counter += 1;
                pool.reverse();
            }
            *byte = pool.pop().unwrap_or(0);
        }
        Ok(())
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: age keygen [--pq] | encrypt IN OUT (-r R)... | --passphrase P | \
                 decrypt IN OUT (-i IDENTITY | --identity-file F)... | --passphrase P; \
                 --passphrase-stdin in place of --passphrase P";
    let command = args.first().ok_or(usage)?;
    let mut values: Vec<(String, String)> = Vec::new();
    let mut flags = Vec::new();
    let mut positional = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--pq" || a == "--armor" || a == "--passphrase-stdin" {
            flags.push(a.clone());
            i += 1;
        } else if a.starts_with('-') {
            values.push((a.trim_start_matches('-').to_string(),
                         args.get(i + 1).ok_or(format!("{a} needs a value"))?.clone()));
            i += 2;
        } else {
            positional.push(a.clone());
            i += 1;
        }
    }
    let get = |name: &str| values.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str())
        .collect::<Vec<_>>();
    let mut passphrases: Vec<Vec<u8>> = get("passphrase").iter()
        .map(|p| p.as_bytes().to_vec()).collect();
    if flags.iter().any(|f| f == "--passphrase-stdin") {
        passphrases.push(passphrase::read_line("Passphrase: ")?);
    }
    let seed = get("seed").first().map(|s| s.parse::<u64>().map_err(|e| e.to_string())).transpose()?;
    let mut os_random = |b: &mut [u8]| allcrypt::random::fill(b);
    let mut seeded = seed.map(counter_stream);
    let random: Random<'_> = match seeded.as_mut() {
        Some(s) => s,
        None => &mut os_random,
    };
    match command.as_str() {
        "keygen" => {
            let mut secret = [0u8; 32];
            random(&mut secret)?;
            if flags.iter().any(|f| f == "--pq") {
                let key = xwing::PrivateKey::from_seed(&secret)?;
                println!("# public key: {}", bech32_encode("age1pq", &key.public()));
                println!("{}", bech32_encode("age-secret-key-pq-", &secret).to_ascii_uppercase());
            } else {
                println!("# public key: {}", bech32_encode("age", &x25519::public_key(&secret)?));
                println!("{}", bech32_encode("age-secret-key-", &secret).to_ascii_uppercase());
            }
            Ok(())
        }
        "encrypt" => {
            let [input, output] = &positional[..] else { return Err(usage.to_string()) };
            let plaintext = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
            let mut recipients = get("r").iter().map(|r| parse_recipient(r))
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(p) = passphrases.first() {
                let work_factor = get("work-factor").first().map(|w| w.parse::<u32>())
                    .transpose().map_err(|e| e.to_string())?.unwrap_or(18);
                recipients.push(Recipient::Passphrase { passphrase: p.clone(), work_factor });
            }
            let mut out = encrypt(&plaintext, &recipients, random)?;
            if flags.iter().any(|f| f == "--armor") {
                out = armor(&out);
            }
            std::fs::write(output, out).map_err(|e| format!("{output}: {e}"))
        }
        "decrypt" => {
            let [input, output] = &positional[..] else { return Err(usage.to_string()) };
            let file = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
            let mut identities = get("i").iter().map(|i| parse_identity(i))
                .collect::<Result<Vec<_>, _>>()?;
            for path in get("identity-file") {
                let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                for l in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                    identities.push(parse_identity(l)?);
                }
            }
            for p in passphrases {
                identities.push(Identity::Passphrase(p));
            }
            let (plaintext, failure) = decrypt(&file, &identities, None);
            if let Some(failure) = failure {
                return Err(failure.to_string());
            }
            std::fs::write(output, plaintext).map_err(|e| format!("{output}: {e}"))
        }
        _ => Err(usage.to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("age: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = AnyHash::new("sha256").unwrap();
        h.update(data);
        fixtures::hex(&h.digest())
    }

    /// The age test suite (C2SP CCTV, `fixtures/age/testkit/`, 0BSD):
    /// every vector's file decrypted with its identities or passphrases,
    /// the outcome its `expect` line names, and the plaintext released -
    /// all of it, failure or not - hashing to its `payload` line.
    #[test]
    fn test_age_testkit() {
        let dir = fixtures::dir().join("age").join("testkit");
        let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        let mut checked = 0;
        let mut failed = Vec::new();
        for name in &names {
            let raw = std::fs::read(dir.join(name)).unwrap();
            let split = raw.windows(2).position(|w| w == b"\n\n").unwrap();
            let fields: Vec<(String, String)> = std::str::from_utf8(&raw[..split]).unwrap().lines()
                .filter_map(|l| l.split_once(": ").map(|(k, v)| (k.to_string(), v.to_string())))
                .collect();
            let field = |k: &str| fields.iter().filter(|(key, _)| key == k).map(|(_, v)| v.as_str())
                .collect::<Vec<_>>();
            let mut body = raw[split + 2..].to_vec();
            if field("compressed").first() == Some(&"zlib") {
                body = inflate::zlib_decompress(&body, 64 << 20).unwrap();
            }
            let mut identities: Vec<Identity> = field("identity").iter()
                .map(|i| parse_identity(i).unwrap()).collect();
            identities.extend(field("passphrase").iter()
                .map(|p| Identity::Passphrase(p.as_bytes().to_vec())));
            let armored = field("armored").first() == Some(&"yes");
            let (released, failure) = decrypt(&body, &identities, Some(armored));
            let got = match &failure {
                None => "success",
                Some(Failure::Armor(_)) => "armor failure",
                Some(Failure::Header(_)) => "header failure",
                Some(Failure::NoMatch) => "no match",
                Some(Failure::Hmac) => "HMAC failure",
                Some(Failure::Payload(_)) => "payload failure",
            };
            let expected = field("expect")[0];
            let mut ok = got == expected;
            if let Some(hash) = field("payload").first() {
                ok &= sha256_hex(&released) == *hash;
            } else if expected != "success" && expected != "payload failure" {
                ok &= released.is_empty();
            }
            if !ok {
                failed.push(format!("{name}: expected {expected}, got {got} \
                                     ({:?})", failure.map(|f| f.to_string())));
            }
            checked += 1;
        }
        assert!(failed.is_empty(), "{} of {checked} failed:\n{}", failed.len(), failed.join("\n"));
        assert!(checked >= 140, "{checked}");
    }

    /// The spec's own examples of each encoding.
    #[test]
    fn test_spec_keys() {
        let identity = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX";
        let Identity::X25519(secret) = parse_identity(identity).unwrap() else { panic!() };
        assert_eq!(bech32_encode("age", &x25519::public_key(&secret).unwrap()),
                   "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj");
        assert_eq!(bech32_encode("age-secret-key-", &secret).to_ascii_uppercase(), identity);
        assert!(parse_identity(&identity.replace('G', "g")).is_err());
    }

    #[test]
    fn test_round_trips() {
        let mut random = counter_stream(5);
        let plaintext: Vec<u8> = (0..(2 * CHUNK + 100) as u32).map(|i| i as u8).collect();
        let mut x_secret = [0u8; 32];
        random(&mut x_secret).unwrap();
        let mut pq_seed = [0u8; 32];
        random(&mut pq_seed).unwrap();
        let pq = xwing::PrivateKey::from_seed(&pq_seed).unwrap();
        let recipients = [Recipient::X25519(x25519::public_key(&x_secret).unwrap()),
                          Recipient::Hybrid(pq.public())];
        for (len, armored) in [(0, false), (CHUNK, false), (plaintext.len(), true)] {
            let mut file = encrypt(&plaintext[..len], &recipients, &mut random).unwrap();
            if armored {
                file = armor(&file);
            }
            for identity in [Identity::X25519(x_secret), Identity::Hybrid(Box::new(
                    xwing::PrivateKey::from_seed(&pq_seed).unwrap()))] {
                let (out, failure) = decrypt(&file, &[identity], None);
                assert!(failure.is_none(), "{len}: {failure:?}");
                assert_eq!(out, &plaintext[..len]);
            }
        }
        let file = encrypt(b"pw", &[Recipient::Passphrase { passphrase: b"hunter2".to_vec(),
                                                             work_factor: 4 }], &mut random).unwrap();
        assert_eq!(decrypt(&file, &[Identity::Passphrase(b"hunter2".to_vec())], None).0, b"pw");
        assert_eq!(decrypt(&file, &[Identity::Passphrase(b"hunter3".to_vec())], None).1,
                   Some(Failure::NoMatch));
    }
}
