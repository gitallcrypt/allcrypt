//! Messages: session keys under passphrases, the four encryption
//! containers, compression and literal data.
//!
//! Containers, oldest first:
//!
//!   * Symmetrically Encrypted Data (tag 9): CFB with a random prefix and
//!     a resynchronisation after it, and no integrity check at all.
//!   * SEIPD version 1 (tag 18): CFB without the resynchronisation, and a
//!     SHA-1 of everything appended inside the encryption (the MDC).
//!   * OCB Encrypted Data (tag 20, LibrePGP, written by GnuPG 2.3 and
//!     later): AEAD chunks under the session key itself.
//!   * SEIPD version 2 (tag 18, RFC 9580): AEAD chunks under a key derived
//!     by HKDF from the session key and a salt.
//!
//! And the session key packets that go with them: SKESK version 4 (CFB,
//! or the S2K output as the session key), version 5 (LibrePGP, AEAD
//! under the S2K output) and version 6 (RFC 9580, AEAD under an HKDF of
//! it).

use crate::algo::{self, Aead, Cipher, TAG_LEN};
use crate::packet::{self, Packet, Reader};
use crate::s2k::S2k;
use allcrypt::hash_functions::HashFunction;

use crate::{bunzip2, inflate};

/// The most a compressed packet may expand to.
const DECOMPRESSED_LIMIT: usize = 1 << 31;
/// How deeply packets may nest (compressed in encrypted in compressed...).
const MAX_DEPTH: usize = 8;

pub type Random<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

/// A session key: the cipher it is for when the session key packet says
/// (SKESK and PKESK version 3 and 4 do; version 5 and 6 and SEIPD version
/// 2 take it from the container), and the key.
#[derive(Clone, Debug)]
pub struct SessionKey {
    pub cipher: Option<Cipher>,
    pub key: Vec<u8>,
}

/// A source of session keys for the session key packets of a message;
/// passphrases here, and secret keys (`keys.rs`).
pub trait Unlocker {
    /// The session keys this packet yields - none if it is not for us.
    fn session_keys(&self, esk: &Packet, log: &mut Vec<String>) -> Vec<SessionKey>;

    /// Session keys to try whatever the packets say.
    fn direct(&self) -> Vec<SessionKey> {
        Vec::new()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Literal {
    pub format: u8,
    pub filename: Vec<u8>,
    pub date: u32,
    pub data: Vec<u8>,
}

/// What reading a message found.
#[derive(Default)]
pub struct Message {
    pub literal: Option<Literal>,
    /// One-pass signature and signature packets, in order, and the
    /// literal data they cover.
    pub signatures: Vec<Packet>,
    pub one_pass: Vec<Packet>,
    /// What was decrypted with what, for a reader to see.
    pub log: Vec<String>,
    /// Whether the message was encrypted without integrity protection.
    pub unprotected: bool,
}

// ------------------------------------------------------------ SKESK ---

/// A parsed SKESK packet, of any version.
pub struct Skesk<'a> {
    pub version: u8,
    pub cipher: Cipher,
    /// Versions 5 and 6.
    pub aead: Option<Aead>,
    pub s2k: S2k,
    pub iv: &'a [u8],
    /// The encrypted session key (with its tag for versions 5 and 6);
    /// empty in a version 4 packet whose S2K output is the session key.
    pub esk: &'a [u8],
}

impl<'a> Skesk<'a> {
    pub fn parse(body: &'a [u8]) -> Result<Skesk<'a>, String> {
        let mut r = Reader::new(body);
        let version = r.u8()?;
        match version {
            4 => {
                let cipher = algo::cipher(r.u8()?)?;
                let s2k = S2k::read(&mut r)?;
                Ok(Skesk { version, cipher, aead: None, s2k, iv: &[], esk: r.rest() })
            }
            5 => {
                let cipher = algo::cipher(r.u8()?)?;
                let aead = algo::aead(r.u8()?)?;
                let s2k = S2k::read(&mut r)?;
                let iv = r.bytes(aead.nonce_len)?;
                Ok(Skesk { version, cipher, aead: Some(aead), s2k, iv, esk: r.rest() })
            }
            6 => {
                let count = r.u8()? as usize;
                let start = r.at;
                let cipher = algo::cipher(r.u8()?)?;
                let aead = algo::aead(r.u8()?)?;
                let s2k_len = r.u8()? as usize;
                let s2k_start = r.at;
                let s2k = S2k::read(&mut r)?;
                if r.at - s2k_start != s2k_len {
                    return Err("a v6 SKESK's S2K length does not match its S2K".to_string());
                }
                let iv = r.bytes(aead.nonce_len)?;
                if r.at - start != count {
                    return Err("a v6 SKESK's field count does not match its fields".to_string());
                }
                Ok(Skesk { version, cipher, aead: Some(aead), s2k, iv, esk: r.rest() })
            }
            v => Err(format!("SKESK version {v} is not one this program reads")),
        }
    }

    pub fn describe(&self) -> String {
        format!("SKESK v{}: {}{}, {}{}", self.version, self.cipher.display,
                self.aead.map(|a| format!(" {}", a.display)).unwrap_or_default(),
                self.s2k.describe(),
                if self.version == 4 && !self.esk.is_empty() { ", encrypted session key" }
                else { "" })
    }

    /// The session key, given the S2K's output.
    pub fn unlock(&self, derived: &[u8]) -> Result<SessionKey, String> {
        let wrong = || "the passphrase does not decrypt the session key".to_string();
        match (self.version, self.aead) {
            (4, _) => {
                if self.esk.is_empty() {
                    return Ok(SessionKey { cipher: Some(self.cipher), key: derived.to_vec() });
                }
                let zero = vec![0u8; self.cipher.block_len];
                let plain = algo::cfb(self.cipher, derived, &zero, self.esk, true)?;
                let inner = algo::cipher(plain[0]).map_err(|_| wrong())?;
                if plain.len() != 1 + inner.key_len {
                    return Err(wrong());
                }
                Ok(SessionKey { cipher: Some(inner), key: plain[1..].to_vec() })
            }
            (5, Some(aead)) => {
                let aad = [0xC0 | packet::SKESK, 5, self.cipher.id, aead.id];
                let key = algo::open(self.cipher, aead, derived, self.iv, &aad, self.esk)
                    .map_err(|_| wrong())?;
                Ok(SessionKey { cipher: None, key })
            }
            (_, Some(aead)) => {
                let info = [0xC0 | packet::SKESK, 6, self.cipher.id, aead.id];
                let kek = algo::hkdf_sha256(&[], derived, &info, self.cipher.key_len);
                let key = algo::open(self.cipher, aead, &kek, self.iv, &info, self.esk)
                    .map_err(|_| wrong())?;
                Ok(SessionKey { cipher: None, key })
            }
            _ => Err("an SKESK without its AEAD".to_string()),
        }
    }
}

/// The session key a passphrase gives for one SKESK packet.
pub fn skesk_session_key(body: &[u8], passphrase: &[u8], log: &mut Vec<String>)
                         -> Result<SessionKey, String> {
    let skesk = Skesk::parse(body)?;
    log.push(skesk.describe());
    skesk.unlock(&skesk.s2k.derive(passphrase, skesk.cipher.key_len)?)
}

/// Session keys given outright, as `gpg --override-session-key` takes
/// them: they open the container whatever its session key packets say.
pub struct SessionKeys(pub Vec<SessionKey>);

impl Unlocker for SessionKeys {
    fn session_keys(&self, _esk: &Packet, _log: &mut Vec<String>) -> Vec<SessionKey> {
        Vec::new()
    }

    fn direct(&self) -> Vec<SessionKey> {
        self.0.clone()
    }
}

/// `CIPHER:HEX` or `CIPHER.AEAD:HEX`, GnuPG's `--show-session-key`
/// forms: the cipher's number (and for an AEAD container the AEAD's,
/// which the container states anyway), then the key.
pub fn parse_session_key(text: &str) -> Result<SessionKey, String> {
    let bad = || "a session key is CIPHER:HEX or CIPHER.AEAD:HEX".to_string();
    let (algorithm, hex) = text.split_once(':').ok_or_else(bad)?;
    let (cipher, aead) = algorithm.split_once('.').unwrap_or((algorithm, ""));
    if !aead.is_empty() {
        algo::aead(aead.parse().map_err(|_| bad())?)?;
    }
    let cipher = algo::cipher(cipher.parse().map_err(|_| bad())?)?;
    if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let key: Vec<u8> = (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    if key.len() != cipher.key_len {
        return Err(format!("{} takes a {} byte key", cipher.display, cipher.key_len));
    }
    Ok(SessionKey { cipher: Some(cipher), key })
}

/// Passphrases as an `Unlocker`.
pub struct Passphrases(pub Vec<Vec<u8>>);

impl Unlocker for Passphrases {
    fn session_keys(&self, esk: &Packet, log: &mut Vec<String>) -> Vec<SessionKey> {
        if esk.tag != packet::SKESK {
            return Vec::new();
        }
        let mut keys = Vec::new();
        for passphrase in &self.0 {
            match skesk_session_key(&esk.body, passphrase, log) {
                Ok(key) => keys.push(key),
                Err(why) => log.push(why),
            }
        }
        keys
    }
}

/// Secret keys and the passphrases that may unlock them (and any SKESK
/// packets) as an `Unlocker`. A key is unlocked only when a PKESK packet
/// names it, and at most once.
pub struct Keys {
    pub certs: Vec<crate::keys::Cert>,
    pub passphrases: Vec<Vec<u8>>,
    unlocked: std::cell::RefCell<Vec<(Vec<u8>, crate::keys::Secret)>>,
}

impl Keys {
    pub fn new(certs: Vec<crate::keys::Cert>, passphrases: Vec<Vec<u8>>) -> Keys {
        Keys { certs, passphrases, unlocked: std::cell::RefCell::new(Vec::new()) }
    }

    fn secret_for(&self, key: &crate::keys::SecretKey, log: &mut Vec<String>)
                  -> Option<crate::keys::Secret> {
        let fingerprint = key.public.fingerprint();
        if let Some((_, secret)) = self.unlocked.borrow().iter().find(|(f, _)| *f == fingerprint) {
            return Some(secret.clone());
        }
        if key.is_stub() {
            log.push("the key's secret part is not in this file (a GnuPG stub)".to_string());
            return None;
        }
        let attempts: Vec<&[u8]> = if key.is_protected() {
            self.passphrases.iter().map(Vec::as_slice).collect()
        } else {
            vec![&[]]
        };
        for passphrase in attempts {
            match key.unlock(passphrase) {
                Ok(secret) => {
                    self.unlocked.borrow_mut().push((fingerprint, secret.clone()));
                    return Some(secret);
                }
                Err(why) => log.push(why),
            }
        }
        if key.is_protected() && self.passphrases.is_empty() {
            log.push("the secret key is protected and no passphrase was given".to_string());
        }
        None
    }
}

impl Unlocker for Keys {
    fn session_keys(&self, esk: &Packet, log: &mut Vec<String>) -> Vec<SessionKey> {
        if esk.tag == packet::SKESK {
            return Passphrases(self.passphrases.clone()).session_keys(esk, log);
        }
        let pkesk = match crate::pubkey::Pkesk::parse(&esk.body) {
            Ok(p) => p,
            Err(why) => {
                log.push(why);
                return Vec::new();
            }
        };
        let mut found = Vec::new();
        for cert in &self.certs {
            for key in cert.keys() {
                let Some(secret_key) = &key.secret else { continue };
                if !pkesk.is_for(&key.public) || key.public.algorithm != pkesk.algorithm {
                    continue;
                }
                let Some(secret) = self.secret_for(secret_key, log) else { continue };
                match pkesk.decrypt(&key.public, &secret) {
                    Ok(session) => {
                        log.push(format!("PKESK v{}: {} key {}", pkesk.version,
                                         key.public.describe(),
                                         crate::keys::hex_upper(&key.public.fingerprint())));
                        found.push(session);
                    }
                    Err(why) => log.push(why),
                }
            }
        }
        found
    }
}

// ------------------------------------------------------- containers ---

fn quick_check(prefix: &[u8], block: usize) -> bool {
    prefix[block - 2..block] == prefix[block..block + 2]
}

/// Tag 9: CFB, prefix, resynchronise, no integrity.
fn decrypt_sed(cipher: Cipher, key: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    let bs = cipher.block_len;
    if body.len() < bs + 2 {
        return Err("encrypted data shorter than its prefix".to_string());
    }
    let zero = vec![0u8; bs];
    let prefix = algo::cfb(cipher, key, &zero, &body[..bs + 2], true)?;
    if !quick_check(&prefix, bs) {
        return Err("wrong session key (the prefix's check bytes differ)".to_string());
    }
    // The resynchronisation: the IV for the rest is the ciphertext's
    // bytes 2 to block+2, so the next block's keystream comes from the
    // last full block of ciphertext as if the two check bytes had not
    // been there.
    algo::cfb(cipher, key, &body[2..bs + 2], &body[bs + 2..], true)
}

fn encrypt_sed(cipher: Cipher, key: &[u8], plaintext: &[u8], random: Random<'_>)
               -> Result<Vec<u8>, String> {
    let bs = cipher.block_len;
    let mut prefix = vec![0u8; bs];
    random(&mut prefix)?;
    prefix.extend_from_within(bs - 2..);
    let zero = vec![0u8; bs];
    let mut out = algo::cfb(cipher, key, &zero, &prefix, false)?;
    let iv = out[2..bs + 2].to_vec();
    out.extend(algo::cfb(cipher, key, &iv, plaintext, false)?);
    Ok(out)
}

/// SEIPD v1: CFB over prefix, data and the MDC packet.
fn decrypt_seipd1(cipher: Cipher, key: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    let bs = cipher.block_len;
    if body.len() < bs + 2 + 22 {
        return Err("SEIPD data too short for its prefix and MDC".to_string());
    }
    let zero = vec![0u8; bs];
    let plain = algo::cfb(cipher, key, &zero, body, true)?;
    if !quick_check(&plain, bs) {
        return Err("wrong session key (the prefix's check bytes differ)".to_string());
    }
    let (covered, mdc) = plain.split_at(plain.len() - 20);
    if covered[covered.len() - 2..] != [0xD3, 0x14] {
        return Err("the modification detection code packet is missing: the data was \
                    altered".to_string());
    }
    let sha1 = algo::digest(algo::hash(2)?, &[covered]);
    if allcrypt::bignum::ct::bytes_differ(&sha1, mdc) {
        return Err("the modification detection code does not match: the data was \
                    altered".to_string());
    }
    Ok(covered[bs + 2..covered.len() - 2].to_vec())
}

fn encrypt_seipd1(cipher: Cipher, key: &[u8], plaintext: &[u8], random: Random<'_>)
                  -> Result<Vec<u8>, String> {
    let bs = cipher.block_len;
    let mut plain = vec![0u8; bs];
    random(&mut plain)?;
    plain.extend_from_within(bs - 2..);
    plain.extend_from_slice(plaintext);
    plain.extend_from_slice(&[0xD3, 0x14]);
    let sha1 = algo::digest(algo::hash(2)?, &[&plain]);
    plain.extend_from_slice(&sha1);
    let zero = vec![0u8; bs];
    let mut body = vec![1u8];
    body.extend(algo::cfb(cipher, key, &zero, &plain, false)?);
    Ok(body)
}

/// The chunked AEAD shared by the OCB packet and SEIPD v2. `nonce(i)`
/// gives chunk `i`'s nonce and `aad(i, total)` its associated data, with
/// `total` set only for the final tag.
fn aead_chunks_open(cipher: Cipher, aead: Aead, key: &[u8], chunk_byte: u8, data: &[u8],
                    nonce: &dyn Fn(u64) -> Vec<u8>, aad: &dyn Fn(u64, Option<u64>) -> Vec<u8>)
                    -> Result<Vec<u8>, String> {
    if chunk_byte > 16 {
        return Err(format!("a chunk size octet of {chunk_byte}; at most 16 is allowed"));
    }
    let chunk = 1usize << (chunk_byte + 6);
    if data.len() < TAG_LEN {
        return Err("AEAD data shorter than its final tag".to_string());
    }
    let (chunks, final_tag) = data.split_at(data.len() - TAG_LEN);
    let mut out = Vec::with_capacity(chunks.len());
    let mut index = 0u64;
    for piece in chunks.chunks(chunk + TAG_LEN) {
        let plain = algo::open(cipher, aead, key, &nonce(index), &aad(index, None), piece)
            .map_err(|_| format!("chunk {index} does not authenticate: wrong key, or the \
                                  data was altered"))?;
        out.extend_from_slice(&plain);
        index += 1;
    }
    algo::open(cipher, aead, key, &nonce(index), &aad(index, Some(out.len() as u64)),
               final_tag)
        .map_err(|_| "the final tag does not authenticate: the data was truncated or \
                      altered".to_string())?;
    Ok(out)
}

fn aead_chunks_seal(cipher: Cipher, aead: Aead, key: &[u8], chunk_byte: u8, plaintext: &[u8],
                    nonce: &dyn Fn(u64) -> Vec<u8>, aad: &dyn Fn(u64, Option<u64>) -> Vec<u8>)
                    -> Result<Vec<u8>, String> {
    let chunk = 1usize << (chunk_byte + 6);
    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN * 2);
    let mut index = 0u64;
    for piece in plaintext.chunks(chunk) {
        out.extend(algo::seal(cipher, aead, key, &nonce(index), &aad(index, None), piece)?);
        index += 1;
    }
    out.extend(algo::seal(cipher, aead, key, &nonce(index),
                          &aad(index, Some(plaintext.len() as u64)), &[])?);
    Ok(out)
}

/// LibrePGP's OCB Encrypted Data packet (tag 20).
fn decrypt_ocb_packet(session: &SessionKey, body: &[u8], log: &mut Vec<String>)
                      -> Result<Vec<u8>, String> {
    let mut r = Reader::new(body);
    if r.u8()? != 1 {
        return Err("an OCB Encrypted Data packet of a version other than 1".to_string());
    }
    let cipher = algo::cipher(r.u8()?)?;
    let aead = algo::aead(r.u8()?)?;
    let chunk_byte = r.u8()?;
    let iv = r.bytes(aead.nonce_len)?.to_vec();
    if session.key.len() != cipher.key_len {
        return Err("the session key's length is not the cipher's".to_string());
    }
    log.push(format!("OCB Encrypted Data: {} {}, {} byte chunks", cipher.display,
                     aead.display, 1u64 << (chunk_byte + 6)));
    let header = [0xC0 | packet::OCB, 1, cipher.id, aead.id, chunk_byte];
    aead_chunks_open(cipher, aead, &session.key, chunk_byte, r.rest(),
                     &|i| librepgp_nonce(&iv, i), &|i, total| index_aad(&header, i, total))
}

/// The starting IV with the chunk index XORed into its last eight bytes.
fn librepgp_nonce(iv: &[u8], index: u64) -> Vec<u8> {
    let mut nonce = iv.to_vec();
    let n = nonce.len();
    for (byte, i) in nonce[n - 8..].iter_mut().zip(index.to_be_bytes()) {
        *byte ^= i;
    }
    nonce
}

/// LibrePGP's associated data: the header, the index, and for the final
/// tag the total.
fn index_aad(header: &[u8], index: u64, total: Option<u64>) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(&index.to_be_bytes());
    if let Some(total) = total {
        aad.extend_from_slice(&total.to_be_bytes());
    }
    aad
}

/// RFC 9580's associated data: the header, and for the final tag the
/// total. The index is in the nonce only.
fn header_aad(header: &[u8], total: Option<u64>) -> Vec<u8> {
    let mut aad = header.to_vec();
    if let Some(total) = total {
        aad.extend_from_slice(&total.to_be_bytes());
    }
    aad
}

/// SEIPD version 2's message key and IV, from the session key and salt.
fn seipd2_keys(session_key: &[u8], salt: &[u8], header: &[u8], cipher: Cipher, aead: Aead)
               -> (Vec<u8>, Vec<u8>) {
    let derived = algo::hkdf_sha256(salt, session_key, header,
                                    cipher.key_len + aead.nonce_len - 8);
    let (key, iv) = derived.split_at(cipher.key_len);
    (key.to_vec(), iv.to_vec())
}

fn seipd2_nonce(iv: &[u8], index: u64) -> Vec<u8> {
    let mut nonce = iv.to_vec();
    nonce.extend_from_slice(&index.to_be_bytes());
    nonce
}

fn decrypt_seipd2(session: &SessionKey, body: &[u8], log: &mut Vec<String>)
                  -> Result<Vec<u8>, String> {
    let mut r = Reader::new(body);
    r.u8()?;
    let cipher = algo::cipher(r.u8()?)?;
    let aead = algo::aead(r.u8()?)?;
    let chunk_byte = r.u8()?;
    let salt = r.bytes(32)?;
    if session.key.len() != cipher.key_len {
        return Err("the session key's length is not the cipher's".to_string());
    }
    log.push(format!("SEIPD v2: {} {}, {} byte chunks", cipher.display, aead.display,
                     1u64 << (chunk_byte + 6)));
    let header = [0xC0 | packet::SEIPD, 2, cipher.id, aead.id, chunk_byte];
    let (key, iv) = seipd2_keys(&session.key, salt, &header, cipher, aead);
    aead_chunks_open(cipher, aead, &key, chunk_byte, r.rest(),
                     &|i| seipd2_nonce(&iv, i), &|_, total| header_aad(&header, total))
}

/// Decrypt one container with one session key.
fn decrypt_container(container: &Packet, session: &SessionKey, log: &mut Vec<String>)
                     -> Result<(Vec<u8>, bool), String> {
    let need_cipher = || session.cipher
        .ok_or_else(|| "a version 5 or 6 session key cannot open this container".to_string());
    match (container.tag, container.body.first()) {
        (packet::SED, _) => {
            let cipher = need_cipher()?;
            log.push(format!("Symmetrically Encrypted Data: {} CFB, no integrity \
                              protection", cipher.display));
            Ok((decrypt_sed(cipher, &session.key, &container.body)?, true))
        }
        (packet::SEIPD, Some(1)) => {
            let cipher = need_cipher()?;
            log.push(format!("SEIPD v1: {} CFB with MDC", cipher.display));
            Ok((decrypt_seipd1(cipher, &session.key, &container.body[1..])?, false))
        }
        (packet::SEIPD, Some(2)) => Ok((decrypt_seipd2(session, &container.body, log)?, false)),
        (packet::OCB, _) => Ok((decrypt_ocb_packet(session, &container.body, log)?, false)),
        (packet::SEIPD, version) =>
            Err(format!("SEIPD version {version:?} is not one this program reads")),
        _ => Err("not an encrypted container".to_string()),
    }
}

// --------------------------------------------------------- reading ---

fn decompress(body: &[u8]) -> Result<(Vec<u8>, &'static str), String> {
    let (algorithm, data) = body.split_first().ok_or("an empty compressed packet")?;
    Ok(match algorithm {
        0 => (data.to_vec(), "uncompressed"),
        1 => (inflate::inflate(data, DECOMPRESSED_LIMIT)?.0, "ZIP"),
        2 => (inflate::zlib_decompress(data, DECOMPRESSED_LIMIT)?, "ZLIB"),
        3 => (bunzip2::decompress(data, DECOMPRESSED_LIMIT)?, "BZip2"),
        other => return Err(format!("compression algorithm {other} is not one this program \
                                     has")),
    })
}

fn literal(body: &[u8]) -> Result<Literal, String> {
    let mut r = Reader::new(body);
    let format = r.u8()?;
    let name_len = r.u8()? as usize;
    let filename = r.bytes(name_len)?.to_vec();
    let date = r.u32()?;
    Ok(Literal { format, filename, date, data: r.rest().to_vec() })
}

/// Read a message: decrypt it if it is encrypted, decompress it, and
/// collect its literal data and signatures.
pub fn read(packets: &[Packet], unlocker: &dyn Unlocker) -> Result<Message, String> {
    let mut message = Message::default();
    read_into(packets, unlocker, &mut message, 0)?;
    if message.literal.is_none() {
        return Err("the message holds no literal data".to_string());
    }
    Ok(message)
}

fn read_into(packets: &[Packet], unlocker: &dyn Unlocker, message: &mut Message, depth: usize)
             -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("packets nested too deeply".to_string());
    }
    let mut esks: Vec<&Packet> = Vec::new();
    for p in packets {
        match p.tag {
            packet::PKESK | packet::SKESK => esks.push(p),
            packet::SED | packet::SEIPD | packet::OCB => {
                let mut sessions = unlocker.direct();
                for esk in esks.drain(..) {
                    sessions.extend(unlocker.session_keys(esk, &mut message.log));
                }
                if sessions.is_empty() {
                    return Err("no passphrase or key opens any of the message's session key \
                                packets".to_string());
                }
                let mut last_error = String::new();
                let mut opened = None;
                for session in &sessions {
                    let mut log = Vec::new();
                    match decrypt_container(p, session, &mut log) {
                        Ok(plain) => {
                            message.log.extend(log);
                            opened = Some(plain);
                            break;
                        }
                        Err(why) => last_error = why,
                    }
                }
                let (plain, unprotected) = opened.ok_or(last_error)?;
                message.unprotected |= unprotected;
                read_into(&packet::parse(&plain)?, unlocker, message, depth + 1)?;
            }
            packet::COMPRESSED => {
                let (data, name) = decompress(&p.body)?;
                message.log.push(format!("compressed: {name}"));
                read_into(&packet::parse(&data)?, unlocker, message, depth + 1)?;
            }
            packet::LITERAL => {
                if message.literal.is_some() {
                    return Err("a message with two literal data packets".to_string());
                }
                message.literal = Some(literal(&p.body)?);
            }
            packet::ONE_PASS => message.one_pass.push(p.clone()),
            packet::SIGNATURE => message.signatures.push(p.clone()),
            packet::MARKER | packet::PADDING => {}
            other => return Err(format!("a {} packet where a message is expected",
                                        packet::tag_name(other))),
        }
    }
    if !esks.is_empty() {
        return Err("session key packets with no encrypted data after them".to_string());
    }
    Ok(())
}

// --------------------------------------------------------- writing ---

/// Which family of packets to write.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Format {
    /// SKESK v4 and SEIPD v1 (RFC 4880): what every OpenPGP reader takes.
    V4,
    /// SKESK v4 and Symmetrically Encrypted Data, with no integrity
    /// protection (RFC 1991 and 2440 era).
    NoMdc,
    /// SKESK v5 and the OCB Encrypted Data packet (LibrePGP, GnuPG 2.3+).
    LibrePgp,
    /// SKESK v6 and SEIPD v2 (RFC 9580).
    Rfc9580,
}

pub struct Options {
    pub cipher: Cipher,
    pub aead: Aead,
    pub format: Format,
    /// 0 none, 1 ZIP, 2 ZLIB - written as stored (uncompressed) blocks.
    pub compression: u8,
    pub s2k: S2kChoice,
    pub chunk_byte: u8,
    /// Whether a single passphrase's SKESK v4 carries an encrypted
    /// session key rather than being the session key.
    pub esk: bool,
    pub filename: Vec<u8>,
    pub date: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum S2kChoice {
    Iterated { hash: algo::Hash, octets: usize },
    Argon2 { passes: u8, parallelism: u8, encoded_memory: u8 },
}

impl Options {
    pub fn new(cipher: Cipher) -> Options {
        Options {
            cipher,
            aead: algo::aead(2).unwrap(),
            format: Format::V4,
            compression: 0,
            s2k: S2kChoice::Iterated { hash: algo::hash(8).unwrap(), octets: 65011712 },
            chunk_byte: 16,
            esk: false,
            filename: Vec::new(),
            date: 0,
        }
    }
}

pub fn new_s2k(choice: S2kChoice, random: Random<'_>) -> Result<S2k, String> {
    Ok(match choice {
        S2kChoice::Iterated { hash, octets } => {
            let mut salt = [0u8; 8];
            random(&mut salt)?;
            S2k::Iterated { hash, salt, coded_count: crate::s2k::encode_count(octets) }
        }
        S2kChoice::Argon2 { passes, parallelism, encoded_memory } => {
            let mut salt = [0u8; 16];
            random(&mut salt)?;
            S2k::Argon2 { salt, passes, parallelism, encoded_memory }
        }
    })
}

/// A ZIP (raw DEFLATE) or ZLIB stream in stored blocks: valid for every
/// reader, and no smaller than the input.
pub fn stored_deflate(data: &[u8], zlib: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 65535 * 5 + 11);
    if zlib {
        out.extend_from_slice(&[0x78, 0x01]);
    }
    let mut blocks = data.chunks(65535).peekable();
    if blocks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(block) = blocks.next() {
        out.push(u8::from(blocks.peek().is_none()));
        out.extend_from_slice(&(block.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        out.extend_from_slice(block);
    }
    if zlib {
        let (mut a, mut b) = (1u32, 0u32);
        for &byte in data {
            a = (a + u32::from(byte)) % 65521;
            b = (b + a) % 65521;
        }
        out.extend_from_slice(&(b << 16 | a).to_be_bytes());
    }
    out
}

/// The literal data packet, compressed if asked, as a packet sequence.
pub fn literal_packets(data: &[u8], options: &Options) -> Vec<u8> {
    let mut body = vec![b'b', options.filename.len() as u8];
    body.extend_from_slice(&options.filename);
    body.extend_from_slice(&options.date.to_be_bytes());
    body.extend_from_slice(data);
    let inner = packet::write(packet::LITERAL, &body);
    if options.compression == 0 {
        return inner;
    }
    let mut compressed = vec![options.compression];
    compressed.extend(stored_deflate(&inner, options.compression == 2));
    packet::write(packet::COMPRESSED, &compressed)
}

/// A signer: a key and its unlocked secret half.
pub struct Signer<'a> {
    pub key: &'a crate::keys::PublicKey,
    pub secret: crate::keys::Secret,
}

/// One-pass signature, literal data and signature packets: an inline
/// signed message, before any compression or encryption. A text
/// signature (`text`) marks the literal data `t`, and both stores and
/// signs it in its CR LF form.
pub fn signed_packets(data: &[u8], options: &Options, signer: &Signer<'_>, hash: algo::Hash,
                      text: bool, created: u32, random: Random<'_>) -> Result<Vec<u8>, String> {
    let sig_type = if text { crate::sig::TEXT } else { crate::sig::BINARY };
    let mut literal_body = vec![if text { b't' } else { b'b' }, options.filename.len() as u8];
    literal_body.extend_from_slice(&options.filename);
    literal_body.extend_from_slice(&options.date.to_be_bytes());
    let metadata = literal_body.clone();
    // Text literal data is stored with CR LF line endings, as GnuPG
    // writes it and reads it back for the signature.
    let signed = if text { crate::sig::canonical_text(data) } else { data.to_vec() };
    literal_body.extend_from_slice(&signed);
    let (hashed, unhashed) = crate::sig::standard_subpackets(signer.key, created);
    let signature = crate::sig::make(signer.key, &signer.secret, sig_type, hash, hashed, unhashed,
                                     Some(&metadata), &|h| h.update(&signed), random)?;
    let salt = crate::sig::Signature::parse(&signature)?.salt;
    let mut out = packet::write(packet::ONE_PASS,
                                &crate::sig::one_pass(sig_type, hash, signer.key, &salt, true));
    out.extend(packet::write(packet::LITERAL, &literal_body));
    out.extend(packet::write(packet::SIGNATURE, &signature));
    if options.compression == 0 {
        return Ok(out);
    }
    let mut compressed = vec![options.compression];
    compressed.extend(stored_deflate(&out, options.compression == 2));
    Ok(packet::write(packet::COMPRESSED, &compressed))
}

/// A recipient of an encrypted message.
pub enum Recipient {
    Passphrase(Vec<u8>),
    /// A key that can encrypt (the encryption subkey of a certificate).
    Key(crate::keys::PublicKey),
}

/// Encrypt `inner` (a packet sequence) to the recipients.
pub fn encrypt(inner: &[u8], recipients: &[Recipient], options: &Options,
               random: Random<'_>) -> Result<Vec<u8>, String> {
    if recipients.is_empty() {
        return Err("no recipients: give a passphrase or a key".to_string());
    }
    let cipher = options.cipher;
    let aead = options.aead;
    if options.format == Format::LibrePgp || options.format == Format::Rfc9580 {
        if cipher.block_len != 16 {
            return Err(format!("{} needs a 128 bit block cipher; {} is not", aead.display,
                               cipher.display));
        }
        if options.chunk_byte > 16 {
            return Err("a chunk size octet above 16 must not be written".to_string());
        }
    }
    if options.format == Format::LibrePgp && aead.id == 3 {
        return Err("LibrePGP's OCB Encrypted Data packet is defined for EAX and OCB, not \
                    GCM; GCM is RFC 9580's (--format rfc9580)".to_string());
    }
    // One passphrase and nothing else: in v4, the S2K output is the
    // session key unless asked otherwise. Otherwise a random one.
    let single = recipients.len() == 1 && matches!(recipients[0], Recipient::Passphrase(_))
        && matches!(options.format, Format::V4 | Format::NoMdc) && !options.esk;
    let mut session = vec![0u8; cipher.key_len];
    if !single {
        random(&mut session)?;
    }
    let mut out = Vec::new();
    for recipient in recipients {
        match recipient {
            Recipient::Passphrase(passphrase) => {
                let s2k = new_s2k(options.s2k, random)?;
                let mut body = Vec::new();
                match options.format {
                    Format::V4 | Format::NoMdc => {
                        body.extend_from_slice(&[4, cipher.id]);
                        s2k.write(&mut body);
                        let key = s2k.derive(passphrase, cipher.key_len)?;
                        if single {
                            session = key;
                        } else {
                            let mut plain = vec![cipher.id];
                            plain.extend_from_slice(&session);
                            let zero = vec![0u8; cipher.block_len];
                            body.extend(algo::cfb(cipher, &key, &zero, &plain, false)?);
                        }
                    }
                    Format::LibrePgp => {
                        body.extend_from_slice(&[5, cipher.id, aead.id]);
                        s2k.write(&mut body);
                        let mut iv = vec![0u8; aead.nonce_len];
                        random(&mut iv)?;
                        body.extend_from_slice(&iv);
                        let key = s2k.derive(passphrase, cipher.key_len)?;
                        let aad = [0xC0 | packet::SKESK, 5, cipher.id, aead.id];
                        body.extend(algo::seal(cipher, aead, &key, &iv, &aad, &session)?);
                    }
                    Format::Rfc9580 => {
                        let mut s2k_bytes = Vec::new();
                        s2k.write(&mut s2k_bytes);
                        let mut iv = vec![0u8; aead.nonce_len];
                        random(&mut iv)?;
                        body.extend_from_slice(&[6, (3 + s2k_bytes.len() + iv.len()) as u8,
                                                 cipher.id, aead.id, s2k_bytes.len() as u8]);
                        body.extend_from_slice(&s2k_bytes);
                        body.extend_from_slice(&iv);
                        let info = [0xC0 | packet::SKESK, 6, cipher.id, aead.id];
                        let derived = s2k.derive(passphrase, cipher.key_len)?;
                        let kek = algo::hkdf_sha256(&[], &derived, &info, cipher.key_len);
                        body.extend(algo::seal(cipher, aead, &kek, &iv, &info, &session)?);
                    }
                }
                out.extend(packet::write(packet::SKESK, &body));
            }
            Recipient::Key(public) => {
                let session = SessionKey { cipher: Some(cipher), key: session.clone() };
                let body = crate::pubkey::encrypt_session_key(
                    &session, public, options.format == Format::Rfc9580, random)?;
                out.extend(packet::write(packet::PKESK, &body));
            }
        }
    }
    let key = session;
    let container = match options.format {
        Format::NoMdc => packet::write(packet::SED, &encrypt_sed(cipher, &key, inner, random)?),
        Format::V4 => packet::write(packet::SEIPD, &encrypt_seipd1(cipher, &key, inner, random)?),
        Format::LibrePgp => {
            let mut iv = vec![0u8; aead.nonce_len];
            random(&mut iv)?;
            let header = [0xC0 | packet::OCB, 1, cipher.id, aead.id, options.chunk_byte];
            let mut body = header[1..].to_vec();
            body.extend_from_slice(&iv);
            body.extend(aead_chunks_seal(cipher, aead, &key, options.chunk_byte, inner,
                                         &|i| librepgp_nonce(&iv, i),
                                         &|i, total| index_aad(&header, i, total))?);
            packet::write(packet::OCB, &body)
        }
        Format::Rfc9580 => {
            let mut salt = [0u8; 32];
            random(&mut salt)?;
            let header = [0xC0 | packet::SEIPD, 2, cipher.id, aead.id, options.chunk_byte];
            let (message_key, iv) = seipd2_keys(&key, &salt, &header, cipher, aead);
            let mut body = header[1..].to_vec();
            body.extend_from_slice(&salt);
            body.extend(aead_chunks_seal(cipher, aead, &message_key, options.chunk_byte, inner,
                                         &|i| seipd2_nonce(&iv, i),
                                         &|_, total| header_aad(&header, total))?);
            packet::write(packet::SEIPD, &body)
        }
    };
    out.extend(container);
    Ok(out)
}
