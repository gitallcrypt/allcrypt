//! Git's OpenPGP signatures: armoured detached signatures over the
//! payload, made and checked with the OpenPGP example's packets, keys and
//! signatures, and the parts of `gpg` git calls - `-bsau KEY` to sign and
//! `--verify SIG -` to check - with the status lines git reads
//! (`gpg-interface.c`, `parse_gpg_output`).

use allcrypt::hash_functions::HashFunction;

use crate::{armor, keys, packet, sig, verify};

/// Every transferable key in the files named.
pub fn read_certs(paths: &[String]) -> Result<Vec<keys::Cert>, String> {
    let mut certs = Vec::new();
    for path in paths {
        let raw = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        let packets = if armor::is_armored(&raw) {
            let text = std::str::from_utf8(&raw).map_err(|_| format!("{path}: not text"))?;
            let mut all = Vec::new();
            for block in armor::decode_all(text)? {
                all.extend(packet::parse(&block.data)?);
            }
            all
        } else {
            packet::parse(&raw)?
        };
        certs.extend(keys::Cert::read_all(&packets)?);
    }
    Ok(certs)
}

/// The certificate a `-u` argument names: a fingerprint or key ID in hex
/// (the tail of a fingerprint matches, as gpg's does), or text in a user
/// ID.
pub fn find<'a>(certs: &'a [keys::Cert], name: &str) -> Option<&'a keys::Cert> {
    let hex = name.trim_start_matches("0x").to_ascii_uppercase();
    let hexlike = hex.len() >= 8 && hex.bytes().all(|c| c.is_ascii_hexdigit());
    certs.iter().find(|cert| {
        let mut ids = vec![keys::hex_upper(&cert.primary.public.fingerprint())];
        ids.extend(cert.subkeys.iter().map(|s| keys::hex_upper(&s.key.public.fingerprint())));
        (hexlike && ids.iter().any(|f| f.ends_with(&hex) || f.starts_with(&hex)))
            || cert.user_ids.iter().any(|u| String::from_utf8_lossy(&u.packet.body)
                                        .contains(name))
    })
}

pub struct Signed {
    pub armoured: String,
    pub fingerprint: String,
    pub algorithm: u8,
    pub hash: u8,
    pub created: u32,
}

/// A binary-document signature over `payload` by the certificate's
/// signing key, as `gpg -bsa` writes it.
pub fn sign(cert: &keys::Cert, passphrase: &[u8], payload: &[u8], now: u32)
            -> Result<Signed, String> {
    let key = verify::signing_key(cert, now)?;
    let secret = key.secret.as_ref().ok_or("The key has no secret part.")?;
    let secret = secret.unlock(if secret.is_protected() { passphrase } else { &[] })?;
    let public = key.public.clone();
    let hash = match public.curve().map(|c| c.name) {
        Some("NIST P-384" | "brainpoolP384r1") => crate::algo::hash(9)?,
        Some("NIST P-521" | "brainpoolP512r1" | "Ed448") => crate::algo::hash(10)?,
        _ if public.algorithm == keys::ED448 => crate::algo::hash(10)?,
        _ => crate::algo::hash(8)?,
    };
    let (hashed, unhashed) = sig::standard_subpackets(&public, now);
    let mut random = |b: &mut [u8]| allcrypt::random::fill(b);
    let body = sig::make(&public, &secret, sig::BINARY, hash, hashed, unhashed, None,
                         &|h| h.update(payload), &mut random)?;
    let packet = packet::write(packet::SIGNATURE, &body);
    Ok(Signed { armoured: armor::encode("SIGNATURE", &packet),
                fingerprint: keys::hex_upper(&public.fingerprint()),
                algorithm: public.algorithm, hash: hash.id, created: now })
}

pub struct Checked {
    pub good: bool,
    pub text: String,
    /// The signing key's fingerprint and the certificate it is in, when
    /// one of the keys given made the signature.
    pub signer: Option<(String, String, String)>,
}

/// Check a detached signature over `payload` against the certificates.
pub fn check(armoured: &[u8], payload: &[u8], certs: &[keys::Cert], now: u32)
             -> Result<Checked, String> {
    let packets = packet::parse(&armor::dearmor(armoured)?)?;
    let verdicts = verify::verify_document(&packets, payload, None, certs, now);
    let verdict = verdicts.first().ok_or("No signature.")?;
    // The verdict names the key by fingerprint; find it to report the
    // key ID, the primary key and the user ID as gpg would.
    let signer = certs.iter().find_map(|cert| {
        let keys = std::iter::once(&cert.primary).chain(cert.subkeys.iter().map(|s| &s.key));
        keys.map(|k| keys::hex_upper(&k.public.fingerprint()))
            .find(|f| verdict.text.contains(f.as_str()))
            .map(|f| (f, keys::hex_upper(&cert.primary.public.fingerprint()),
                      cert.user_ids.first().map(|u| String::from_utf8_lossy(&u.packet.body)
                                                .to_string()).unwrap_or_default()))
    });
    Ok(Checked { good: verdicts.iter().all(|v| v.good), text: verdict.text.clone(), signer })
}

/// The long key ID of a fingerprint: its last 16 hex digits for version 4
/// (40 digits), its first 16 for versions 5 and 6 (64 digits).
pub fn long_key_id(fingerprint: &str) -> &str {
    if fingerprint.len() == 40 { &fingerprint[24..] } else { &fingerprint[..16] }
}
