//! Kerberos's RC4-HMAC (RFC 4757, and Microsoft's MS-KILE): encryption
//! types 23, `arcfour-hmac`, and 24, `arcfour-hmac-exp`, the checksum
//! type -138, `hmac-md5-arcfour`, and the pseudo-random function.
//!
//! The key is the NT hash of the password: MD4 of its UTF-16 little
//! endian form, with no salt, so it is the same key NTLM uses and the
//! same key for every realm. Encryption, for a usage `T`:
//!
//! ```text
//! K2 = HMAC-MD5(key, T as 4 bytes little endian)      export: "fortybits\0" || T
//! K1 = K2                                             export: bytes 7 to 15 set to 0xAB
//! checksum = HMAC-MD5(K2, confounder || plaintext)
//! K3 = HMAC-MD5(K1, checksum)
//! ciphertext = checksum || RC4(K3, confounder || plaintext)
//! ```
//!
//! with an 8 byte random confounder. The checksum is over the plaintext
//! and keys the RC4 key, so a decryption has to decrypt before it can
//! check, and nothing is released until the check passes. The names are
//! the RFC's. The export variant cuts the RC4 key's source to 40 bits
//! and keeps the full HMAC for the checksum.
//!
//! `T` is the RFC 3961 key usage except where RFC 4757 section 3 renumbers
//! it: the AS-REP's encrypted part, usage 3, is 8 like the TGS-REP's,
//! and the GSS wrap token's 23 is 13. The RFC also maps 9, the TGS-REP
//! under a subkey, to 8; MIT Kerberos, Heimdal and impacket keep it 9,
//! following the erratum, and so does [`message_type`].
//!
//! The checksum is `HMAC-MD5(HMAC-MD5(key, "signaturekey\0"), MD5(T ||
//! data))`, and the PRF is HMAC-SHA1 under the key (section 5).
//!
//! RC4's key schedule and output index its state by key-dependent
//! values, so this is not constant time; the tag comparison is.

use crate::hash_functions::md5::MD5;
use crate::hash_functions::HashFunction;
use crate::mac::hmac::{hmac_md5, hmac_sha1};
use crate::Mac;
use crate::stream_ciphers::rc4::RC4;
use crate::stream_ciphers::StreamCipher;

/// The key, the NT hash.
pub const KEY_LEN: usize = 16;
/// The random bytes ahead of the plaintext.
pub const CONFOUNDER_LEN: usize = 8;
/// The HMAC-MD5 checksum at the front of a ciphertext, and the length
/// of a `hmac-md5-arcfour` checksum.
pub const CHECKSUM_LEN: usize = 16;

/// String-to-key: the NT hash of the password. There is no salt; the
/// realm and principal a Kerberos string-to-key would take do not enter.
pub fn string_to_key(password: &str) -> [u8; KEY_LEN] {
    crate::kdf::windows::nt_hash(password)
}

/// The message type `T` RFC 4757 section 3 gives a key usage: 3 becomes 8,
/// 23 becomes 13, and every other usage is itself - 9 included, as MIT
/// Kerberos and Heimdal have it, where the RFC's text maps 9 to 8.
pub fn message_type(usage: u32) -> u32 {
    match usage {
        3 => 8,
        23 => 13,
        other => other,
    }
}

fn hmac_md5_of(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = hmac_md5(key);
    for part in parts {
        mac.update(part);
    }
    mac.digest().try_into().expect("HMAC-MD5 is 16 bytes")
}

fn key16(key: &[u8]) -> Result<&[u8], String> {
    if key.len() != KEY_LEN {
        return Err(format!("An RC4-HMAC key is 16 bytes, not {}.", key.len()));
    }
    Ok(key)
}

/// RFC 4757's K1, from which the RC4 key is made, and K2, which keys the
/// checksum.
fn usage_keys(key: &[u8], usage: u32, export: bool) -> ([u8; 16], [u8; 16]) {
    let t = message_type(usage).to_le_bytes();
    let k2 = if export {
        hmac_md5_of(key, &[b"fortybits\0", &t])
    } else {
        hmac_md5_of(key, &[&t])
    };
    let mut k1 = k2;
    if export {
        k1[7..].fill(0xab);
    }
    (k1, k2)
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    RC4::new(key).expect("a 16 byte RC4 key").crypt(data, &mut out);
    out
}

/// Encrypt under a key usage with the given 8 byte confounder, which
/// should be random; `export` selects `arcfour-hmac-exp`. The result is
/// the 16 byte checksum and the encrypted confounder and plaintext.
///
/// # Errors
/// A key that is not 16 bytes or a confounder that is not 8.
pub fn encrypt(key: &[u8], usage: u32, plaintext: &[u8], confounder: &[u8], export: bool)
               -> Result<Vec<u8>, String> {
    let key = key16(key)?;
    if confounder.len() != CONFOUNDER_LEN {
        return Err(format!("An RC4-HMAC confounder is 8 bytes, not {}.", confounder.len()));
    }
    let (k1, k2) = usage_keys(key, usage, export);
    let checksum = hmac_md5_of(&k2, &[confounder, plaintext]);
    let k3 = hmac_md5_of(&k1, &[&checksum]);
    let mut data = Vec::with_capacity(CONFOUNDER_LEN + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);
    let mut out = checksum.to_vec();
    out.extend(rc4(&k3, &data));
    Ok(out)
}

/// Decrypt and check. The plaintext without its confounder, or an error
/// and nothing else.
///
/// # Errors
/// A key that is not 16 bytes, a ciphertext shorter than the checksum
/// and confounder, or a checksum that does not match.
pub fn decrypt(key: &[u8], usage: u32, ciphertext: &[u8], export: bool)
               -> Result<Vec<u8>, String> {
    let key = key16(key)?;
    if ciphertext.len() < CHECKSUM_LEN + CONFOUNDER_LEN {
        return Err(format!("An RC4-HMAC ciphertext is at least 24 bytes, its checksum and \
                            confounder; this one is {}.", ciphertext.len()));
    }
    let (checksum, body) = ciphertext.split_at(CHECKSUM_LEN);
    let (k1, k2) = usage_keys(key, usage, export);
    let k3 = hmac_md5_of(&k1, &[checksum]);
    let mut data = rc4(&k3, body);
    if crate::bignum::ct::bytes_differ(&hmac_md5_of(&k2, &[&data]), checksum) {
        return Err("RC4-HMAC integrity check failed: a wrong key or key usage, or the data is \
                    damaged.".to_string());
    }
    Ok(data.split_off(CONFOUNDER_LEN))
}

/// The keyed checksum `hmac-md5-arcfour` (-138) over `data` under a key
/// usage: RFC 4757 section 4.
///
/// # Errors
/// A key that is not 16 bytes.
pub fn checksum(key: &[u8], usage: u32, data: &[u8]) -> Result<[u8; CHECKSUM_LEN], String> {
    let key = key16(key)?;
    let ksign = hmac_md5_of(key, &[b"signaturekey\0"]);
    let mut md5 = MD5::new(&message_type(usage).to_le_bytes());
    md5.update(data);
    Ok(hmac_md5_of(&ksign, &[&md5.digest()]))
}

/// The pseudo-random function: HMAC-SHA1 under the key, 20 bytes
/// (RFC 4757 section 5's `PRF`, which RFC 3961 section 3 asks of every
/// encryption type).
///
/// # Errors
/// A key that is not 16 bytes.
pub fn prf(key: &[u8], input: &[u8]) -> Result<[u8; 20], String> {
    let mut mac = hmac_sha1(key16(key)?);
    mac.update(input);
    Ok(mac.digest().try_into().expect("HMAC-SHA1 is 20 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_and_refusals() {
        let key = string_to_key("password");
        for export in [false, true] {
            for len in [0, 1, 7, 8, 9, 100] {
                let pt: Vec<u8> = (0..len as u8).collect();
                let ct = encrypt(&key, 7, &pt, b"confound", export).unwrap();
                assert_eq!(ct.len(), 24 + len);
                assert_eq!(decrypt(&key, 7, &ct, export).unwrap(), pt);
                assert!(decrypt(&key, 8, &ct, export).is_err());
                assert!(decrypt(&key, 7, &ct, !export).is_err());
                for i in 0..ct.len() {
                    let mut bad = ct.clone();
                    bad[i] ^= 0x01;
                    assert!(decrypt(&key, 7, &bad, export).is_err(), "byte {i}");
                }
            }
        }
        assert!(encrypt(&key[..15], 1, b"", b"confound", false).is_err());
        assert!(encrypt(&key, 1, b"", b"short", false).is_err());
        assert!(decrypt(&key, 1, &[0; 23], false).is_err());
        assert!(checksum(&[0; 17], 1, b"").is_err());
        assert!(prf(&[0; 8], b"").is_err());
    }

    /// A body shorter than the confounder is refused by its length, even
    /// when its checksum is right: built here with the key, as only the
    /// key's holder could, it would otherwise reach the confounder's
    /// removal with fewer than 8 bytes.
    #[test]
    fn test_a_short_body_with_a_good_checksum_is_refused() {
        let key = string_to_key("password");
        for len in 0..CONFOUNDER_LEN {
            let body: Vec<u8> = (0..len as u8).collect();
            let (k1, k2) = usage_keys(&key, 1, false);
            let sum = hmac_md5_of(&k2, &[&body]);
            let mut ct = sum.to_vec();
            ct.extend(rc4(&hmac_md5_of(&k1, &[&sum]), &body));
            assert!(decrypt(&key, 1, &ct, false).is_err(), "{len}");
        }
    }

    /// Usages 3 and 8 are one key, 23 and 13 are one key, and 9 is its
    /// own: a confounder fixed, the ciphertexts say which usages share.
    #[test]
    fn test_the_renumbered_usages() {
        let key = string_to_key("x");
        let ct = |u| encrypt(&key, u, b"m", b"12345678", false).unwrap();
        assert_eq!(ct(3), ct(8));
        assert_eq!(ct(23), ct(13));
        assert_ne!(ct(9), ct(8));
        assert_ne!(ct(3), ct(2));
        assert_eq!(checksum(&key, 23, b"d").unwrap(), checksum(&key, 13, b"d").unwrap());
        assert_ne!(checksum(&key, 9, b"d").unwrap(), checksum(&key, 8, b"d").unwrap());
    }

    /// The export variant's checksum is made under the whole K2 - only
    /// K1, the RC4 key's source, is cut to 40 bits.
    #[test]
    fn test_the_export_variant_cuts_only_the_rc4_key() {
        let key = string_to_key("password");
        let (k1, k2) = usage_keys(&key, 1, true);
        assert_eq!(k1[..7], k2[..7]);
        assert_eq!(k1[7..], [0xab; 9]);
        assert_ne!(k1[7..], k2[7..]);
        let (plain_k1, plain_k2) = usage_keys(&key, 1, false);
        assert_eq!(plain_k1, plain_k2);
        assert_ne!(plain_k2, k2);
    }
}
