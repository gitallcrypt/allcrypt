//! Whether a key may be used, and whether signatures are good.
//!
//! A certificate's subkeys and user IDs mean nothing until the primary
//! key's signatures bind them: a subkey with no valid binding signature
//! is somebody else's key appended to the file. So the key to encrypt
//! to and the key a signature must come from are both chosen by
//! checking those signatures first, and their flags and expiry with
//! them.

use crate::keys::{self, Cert, KeyPacket, PublicKey};
use crate::message::Message;
use crate::packet::{self, Packet};
use crate::sig::{self, Signature};
use allcrypt::hash_functions::HashFunction;

/// What the certificate says about one of its keys.
#[derive(Clone, Debug)]
pub struct KeyCheck {
    pub usable: bool,
    /// The key flags of the binding (or self-) signature, if it has any.
    pub flags: Option<u8>,
    /// Why the key is not usable, or notes about it.
    pub problems: Vec<String>,
}

impl KeyCheck {
    fn may(&self, flag: u8, algorithm_can: bool) -> bool {
        self.usable && self.flags.map_or(algorithm_can, |f| f & flag != 0)
    }
}

pub struct CertCheck {
    pub primary: KeyCheck,
    pub subkeys: Vec<KeyCheck>,
    pub user_ids: Vec<bool>,
}

fn parsed(packets: &[Packet]) -> Vec<Signature> {
    packets.iter().filter_map(|p| Signature::parse(&p.body).ok()).collect()
}

/// Verify `s` as a signature by `signer` over the data `feed` hashes.
fn signature_ok(s: &Signature, signer: &PublicKey, feed: &dyn Fn(&mut allcrypt::api::AnyHash))
                -> bool {
    if !s.may_be_by(signer) {
        return false;
    }
    let mut h = s.hasher();
    feed(&mut h);
    s.verify_digest(signer, &s.finish(h, None)).is_ok()
}

fn current(s: &Signature, now: u32) -> bool {
    let created = s.created().unwrap_or(0);
    created <= now && s.signature_expiration().is_none_or(|e| created as u64 + e as u64 > now as u64)
}

/// The newest of the signatures that verify and are current.
fn newest(signatures: Vec<Signature>) -> Option<Signature> {
    signatures.into_iter().max_by_key(|s| s.created().unwrap_or(0))
}

fn expired(key: &PublicKey, binding: Option<&Signature>, now: u32) -> bool {
    if key.version <= 3 && key.expiry_days != 0 {
        return key.created as u64 + key.expiry_days as u64 * 86400 <= now as u64;
    }
    binding.and_then(Signature::key_expiration)
        .is_some_and(|e| key.created as u64 + e as u64 <= now as u64)
}

pub fn check(cert: &Cert, now: u32) -> CertCheck {
    let primary = &cert.primary.public;
    let hash_primary = |h: &mut allcrypt::api::AnyHash| sig::hash_key(h, primary);

    let revoked = parsed(&cert.direct).iter().any(|s| s.sig_type == sig::KEY_REVOCATION
        && signature_ok(s, primary, &hash_primary));
    let direct = newest(parsed(&cert.direct).into_iter().filter(|s| s.sig_type == sig::DIRECT_KEY
        && current(s, now) && signature_ok(s, primary, &hash_primary)).collect());

    // Each user ID's newest valid self-certification, unless revoked
    // after it.
    let mut user_ids = Vec::new();
    let mut self_certs: Vec<(bool, Signature)> = Vec::new();
    for uid in &cert.user_ids {
        let feed = |h: &mut allcrypt::api::AnyHash| {
            sig::hash_key(h, primary);
            sig::hash_user_id(h, &uid.packet, if primary.version >= 6 { 6 } else { 4 });
        };
        let signatures = parsed(&uid.signatures);
        let certification = newest(signatures.iter().filter(|s| (0x10..=0x13).contains(&s.sig_type)
            && current(s, now) && signature_ok(s, primary, &feed)).cloned().collect());
        let revocation = signatures.iter().filter(|s| s.sig_type == sig::CERTIFICATION_REVOCATION
            && signature_ok(s, primary, &feed)).map(|s| s.created().unwrap_or(0)).max();
        let valid = match (&certification, revocation) {
            (Some(c), Some(r)) => r < c.created().unwrap_or(0),
            (Some(_), None) => true,
            _ => false,
        };
        user_ids.push(valid);
        if let (true, Some(c)) = (valid, certification) {
            self_certs.push((c.subpacket(sig::PRIMARY_USER_ID).is_some_and(|d| d == [1]), c));
        }
    }
    // The primary key's flags and expiry: a version 6 key's direct key
    // signature, or the primary user ID's certification, or the newest.
    self_certs.sort_by_key(|(primary_uid, s)| (*primary_uid, s.created().unwrap_or(0)));
    let governing = if primary.version >= 6 { direct.clone() }
                    else { self_certs.last().map(|(_, s)| s.clone()).or(direct.clone()) };
    let mut primary_check = KeyCheck {
        usable: governing.is_some() && !revoked,
        flags: governing.as_ref().and_then(Signature::key_flags),
        problems: Vec::new(),
    };
    if governing.is_none() {
        primary_check.problems.push("no valid self-signature".to_string());
    }
    if revoked {
        primary_check.problems.push("revoked".to_string());
    }
    if expired(primary, governing.as_ref(), now) {
        primary_check.usable = false;
        primary_check.problems.push("expired".to_string());
    }

    let mut subkeys = Vec::new();
    for sub in &cert.subkeys {
        let key = &sub.key.public;
        let feed = |h: &mut allcrypt::api::AnyHash| {
            sig::hash_key(h, primary);
            sig::hash_key(h, key);
        };
        let signatures = parsed(&sub.signatures);
        let binding = newest(signatures.iter().filter(|s| s.sig_type == sig::SUBKEY_BINDING
            && current(s, now) && signature_ok(s, primary, &feed)).cloned().collect());
        let revoked = signatures.iter().any(|s| s.sig_type == sig::SUBKEY_REVOCATION
            && signature_ok(s, primary, &feed));
        let flags = binding.as_ref().and_then(Signature::key_flags);
        let mut c = KeyCheck { usable: binding.is_some() && primary_check.usable && !revoked,
                               flags, problems: Vec::new() };
        if binding.is_none() {
            c.problems.push("no valid binding signature".to_string());
        }
        if revoked {
            c.problems.push("revoked".to_string());
        }
        if expired(key, binding.as_ref(), now) {
            c.usable = false;
            c.problems.push("expired".to_string());
        }
        // A signing subkey must sign the primary key back, or anybody's
        // signing key could be claimed as this certificate's.
        if flags.is_some_and(|f| f & sig::FLAG_SIGN != 0) {
            let backed = binding.as_ref().is_some_and(|b| b.embedded().iter().any(|e|
                e.sig_type == sig::PRIMARY_KEY_BINDING && signature_ok(e, key, &feed)));
            if !backed {
                c.flags = flags.map(|f| f & !sig::FLAG_SIGN);
                c.problems.push("signs, but has no primary key binding signature".to_string());
            }
        }
        subkeys.push(c);
    }
    CertCheck { primary: primary_check, subkeys, user_ids }
}

/// The key a certificate's mail goes to: its newest usable subkey that
/// may encrypt, or the primary key.
pub fn encryption_key(cert: &Cert, now: u32) -> Result<PublicKey, String> {
    let c = check(cert, now);
    for (sub, k) in cert.subkeys.iter().zip(&c.subkeys).rev() {
        if k.may(sig::FLAG_ENCRYPT, keys::can_encrypt(sub.key.public.algorithm)) {
            return Ok(sub.key.public.clone());
        }
    }
    if c.primary.may(sig::FLAG_ENCRYPT, keys::can_encrypt(cert.primary.public.algorithm)) {
        return Ok(cert.primary.public.clone());
    }
    let mut why = c.primary.problems.clone();
    for (i, k) in c.subkeys.iter().enumerate() {
        why.extend(k.problems.iter().map(|p| format!("subkey {}: {p}", i + 1)));
    }
    Err(format!("the key has no usable part that may encrypt{}",
                if why.is_empty() { String::new() } else { format!(" ({})", why.join("; ")) }))
}

/// The key that signs for a certificate: its newest usable subkey that
/// may sign, or the primary key. Must have its secret part.
pub fn signing_key(cert: &Cert, now: u32) -> Result<&KeyPacket, String> {
    let c = check(cert, now);
    for (sub, k) in cert.subkeys.iter().zip(&c.subkeys).rev() {
        if sub.key.secret.as_ref().is_some_and(|s| !s.is_stub())
            && k.may(sig::FLAG_SIGN, keys::can_sign(sub.key.public.algorithm)) {
            return Ok(&sub.key);
        }
    }
    if cert.primary.secret.as_ref().is_some_and(|s| !s.is_stub())
        && c.primary.may(sig::FLAG_SIGN, keys::can_sign(cert.primary.public.algorithm)) {
        return Ok(&cert.primary);
    }
    Err("the key has no usable secret part that may sign".to_string())
}

/// What became of one signature.
#[derive(Debug)]
pub struct Verdict {
    pub good: bool,
    pub text: String,
}

/// Check signatures over a document against the certificates given.
/// `data` is the signed document; `literal` its literal data packet's
/// format, name and date (LibrePGP's version 5 signatures hash them).
pub fn verify_document(signatures: &[Packet], data: &[u8], literal: Option<&[u8]>,
                       certs: &[Cert], now: u32) -> Vec<Verdict> {
    let mut verdicts = Vec::new();
    let text = std::cell::OnceCell::new();
    for p in signatures {
        let s = match Signature::parse(&p.body) {
            Ok(s) => s,
            Err(why) => {
                verdicts.push(Verdict { good: false, text: format!("unreadable signature: {why}") });
                continue;
            }
        };
        if !matches!(s.sig_type, sig::BINARY | sig::TEXT) {
            verdicts.push(Verdict { good: false, text: format!(
                "a {} signature where a document signature belongs", sig::type_name(s.sig_type)) });
            continue;
        }
        let signed: &[u8] = if s.sig_type == sig::TEXT {
            text.get_or_init(|| sig::canonical_text(data))
        } else {
            data
        };
        let mut h = s.hasher();
        h.update(signed);
        let digest = s.finish(h, literal);
        let mut verdict = None;
        for cert in certs {
            let checked = check(cert, now);
            let keys_and_checks = std::iter::once((&cert.primary, &checked.primary))
                .chain(cert.subkeys.iter().map(|s| &s.key).zip(&checked.subkeys));
            for (key, key_check) in keys_and_checks {
                if !s.may_be_by(&key.public) || s.algorithm != key.public.algorithm {
                    continue;
                }
                let who = format!("{} {} ({})", key.public.describe(),
                                  keys::hex_upper(&key.public.fingerprint()),
                                  cert.user_ids.first().map(|u| String::from_utf8_lossy(
                                      &u.packet.body).to_string()).unwrap_or_default());
                let made = format!("v{} {} signature, {}, made {}", s.version,
                                   sig::type_name(s.sig_type), s.hash.display,
                                   s.created().unwrap_or(0));
                verdict = Some(match s.verify_digest(&key.public, &digest) {
                    Ok(()) if !key_check.may(sig::FLAG_SIGN, keys::can_sign(key.public.algorithm)) =>
                        Verdict { good: false, text: format!(
                            "the signature verifies, but by {who}, which may not sign: {}",
                            key_check.problems.join("; ")) },
                    Ok(()) if s.created().unwrap_or(0) > now =>
                        Verdict { good: false, text: format!("{made} by {who} is from the future") },
                    Ok(()) => Verdict { good: true, text: format!("good {made} by {who}") },
                    Err(why) => Verdict { good: false, text: format!("BAD {made} by {who}: {why}") },
                });
                break;
            }
            if verdict.is_some() {
                break;
            }
        }
        verdicts.push(verdict.unwrap_or_else(|| Verdict { good: false, text: format!(
            "a signature by {} with no key given to check it",
            s.issuer_fingerprints().first().map(|f| keys::hex_upper(f))
                .or_else(|| s.issuer_key_ids().first().map(|i| keys::hex_upper(i)))
                .unwrap_or_else(|| "an unnamed key".to_string())) }));
    }
    verdicts
}

/// A literal data packet's format, file name and date, as LibrePGP's
/// version 5 document signatures hash them.
pub fn literal_metadata(m: &crate::message::Literal) -> Vec<u8> {
    let mut out = vec![m.format, m.filename.len() as u8];
    out.extend_from_slice(&m.filename);
    out.extend_from_slice(&m.date.to_be_bytes());
    out
}

/// The signatures inside a message, over its literal data.
pub fn verify_message(message: &Message, certs: &[Cert], now: u32) -> Vec<Verdict> {
    let Some(literal) = &message.literal else { return Vec::new() };
    verify_document(&message.signatures, &literal.data, Some(&literal_metadata(literal)),
                    certs, now)
}

// ------------------------------------------------- cleartext framework ---

/// A cleartext signed message (RFC 9580 section 7): the text as it is
/// signed - dash-escaping removed, trailing spaces and tabs removed from
/// each line, CR LF between lines and none after the last - and the
/// signature packets.
pub fn read_cleartext(text: &str) -> Result<(Vec<u8>, Vec<Packet>), String> {
    let begin = text.find("-----BEGIN PGP SIGNED MESSAGE-----")
        .ok_or("not a cleartext signed message")?;
    let mut lines = text[begin..].split('\n').skip(1);
    // Armor headers ("Hash: ...") up to the blank line.
    for line in lines.by_ref() {
        if line.trim_end_matches('\r').trim().is_empty() {
            break;
        }
    }
    let mut body: Vec<String> = Vec::new();
    let mut rest = String::new();
    let mut in_signature = false;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if in_signature {
            rest.push_str(line);
            rest.push('\n');
        } else if line == "-----BEGIN PGP SIGNATURE-----" {
            in_signature = true;
            rest.push_str(line);
            rest.push('\n');
        } else {
            let unescaped = line.strip_prefix("- ").unwrap_or(line);
            body.push(unescaped.trim_end_matches([' ', '\t']).to_string());
        }
    }
    if !in_signature {
        return Err("a cleartext signed message without its signature".to_string());
    }
    let signed = body.join("\r\n").into_bytes();
    let mut packets = Vec::new();
    for block in crate::armor::decode_all(&rest)? {
        packets.extend(packet::parse(&block.data)?);
    }
    Ok((signed, packets))
}

/// What LibrePGP's version 5 signatures hash in place of a literal
/// packet's metadata for a cleartext signature: `t` and five zeros.
pub const CLEARTEXT_METADATA: [u8; 6] = [b't', 0, 0, 0, 0, 0];

/// The text a cleartext signature covers, from the text as given.
pub fn cleartext_signed_form(text: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(text);
    let lines: Vec<&str> = text.strip_suffix('\n').unwrap_or(&text).split('\n')
        .map(|l| l.trim_end_matches('\r').trim_end_matches([' ', '\t'])).collect();
    lines.join("\r\n").into_bytes()
}

/// A cleartext signed message around `text` with the armored
/// `signatures`.
pub fn write_cleartext(text: &[u8], signatures: &[u8], hash_header: Option<&str>) -> String {
    let mut out = String::from("-----BEGIN PGP SIGNED MESSAGE-----\n");
    if let Some(hash) = hash_header {
        out.push_str(&format!("Hash: {hash}\n"));
    }
    out.push('\n');
    let text = String::from_utf8_lossy(text);
    for line in text.strip_suffix('\n').unwrap_or(&text).split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with('-') {
            out.push_str("- ");
        }
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&crate::armor::encode("SIGNATURE", signatures));
    out
}
