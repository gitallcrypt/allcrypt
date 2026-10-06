//! The NIST and ANSI key derivations built from a hash or a MAC:
//!
//! - **SP 800-108** (KBKDF), counter and feedback modes, over HMAC with
//!   any hash here or CMAC with any block cipher. The fixed input data is
//!   the form the standard and RFC 8009 use: `Label || 0x00 || Context
//!   || [L]_32`, with a 32-bit big-endian counter. Kerberos's AES-SHA2
//!   types (RFC 8009) are counter mode over HMAC; its Camellia types (RFC
//!   6803) are feedback mode over CMAC with a counter.
//! - **SP 800-56C's one-step KDF** with a hash, the "Concat KDF": for
//!   counters from 1, `Hash([counter]_32 || Z || OtherInfo)`. JWE's
//!   ECDH-ES (RFC 7518 4.6) and OpenPGP's ECDH (RFC 6637) are this.
//! - **ANSI X9.63** (SEC 1 3.6.1): `Hash(Z || [counter]_32 ||
//!   SharedInfo)`, the counter after the secret rather than before. CMS's
//!   ECDH recipients (RFC 5753) use it.
//!
//! The last two differ only in where the counter goes, and each is
//! self-consistent with the other's mistake.

use crate::api::{hmac, AnyHash};
use crate::hash_functions::HashFunction;

/// SP 800-108's PRF: HMAC over a named hash, or CMAC over a named block
/// cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prf<'a> {
    Hmac(&'a str),
    Cmac(&'a str),
}

impl Prf<'_> {
    /// `"hmac-sha256"`, `"cmac-aes"` and so on.
    pub fn named(name: &str) -> Result<Prf<'_>, String> {
        if let Some(hash) = name.strip_prefix("hmac-") {
            AnyHash::new(hash)?;
            Ok(Prf::Hmac(hash))
        } else if let Some(cipher) = name.strip_prefix("cmac-") {
            Ok(Prf::Cmac(cipher))
        } else {
            Err(format!("Unknown PRF {name:?}: hmac-<hash> or cmac-<block cipher>."))
        }
    }

    fn apply(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Prf::Hmac(hash) => hmac(hash, key, data),
            Prf::Cmac(cipher) => crate::mac::cmac::cmac(cipher, key, data),
        }
    }
}

/// `Label || 0x00 || Context || [L]_32`, L the output length in bits.
fn fixed_data(label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let bits = u32::try_from(length.checked_mul(8).ok_or("Too long.")?)
        .map_err(|_| "SP 800-108's length field is 32 bits.".to_string())?;
    let mut out = label.to_vec();
    out.push(0);
    out.extend_from_slice(context);
    out.extend_from_slice(&bits.to_be_bytes());
    Ok(out)
}

/// SP 800-108 counter mode: `PRF(key, [i]_32 || fixed data)` for i from
/// 1, concatenated and cut to `length` bytes.
pub fn kbkdf_counter(prf: Prf<'_>, key: &[u8], label: &[u8], context: &[u8], length: usize)
                     -> Result<Vec<u8>, String> {
    let fixed = fixed_data(label, context, length)?;
    let mut out = Vec::with_capacity(length + 64);
    let mut counter = 1u32;
    while out.len() < length {
        let mut input = counter.to_be_bytes().to_vec();
        input.extend_from_slice(&fixed);
        out.extend(prf.apply(key, &input)?);
        counter = counter.checked_add(1).ok_or("SP 800-108's counter ran out.")?;
    }
    out.truncate(length);
    Ok(out)
}

/// SP 800-108 feedback mode, with the counter: `K(i) = PRF(key, K(i-1)
/// || [i]_32 || fixed data)`, `K(0)` being `iv` (empty, or a block of
/// zeros as RFC 6803 has it).
pub fn kbkdf_feedback(prf: Prf<'_>, key: &[u8], iv: &[u8], label: &[u8], context: &[u8],
                      length: usize) -> Result<Vec<u8>, String> {
    let fixed = fixed_data(label, context, length)?;
    let mut out = Vec::with_capacity(length + 64);
    let mut previous = iv.to_vec();
    let mut counter = 1u32;
    while out.len() < length {
        let mut input = previous;
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(&fixed);
        previous = prf.apply(key, &input)?;
        out.extend_from_slice(&previous);
        counter = counter.checked_add(1).ok_or("SP 800-108's counter ran out.")?;
    }
    out.truncate(length);
    Ok(out)
}

fn hash_parts(hash: &str, parts: &[&[u8]]) -> Result<Vec<u8>, String> {
    let mut h = AnyHash::new(hash)?;
    for part in parts {
        h.update(part);
    }
    Ok(h.digest())
}

/// SP 800-56C's one-step KDF over a hash (the "Concat KDF"):
/// `Hash([i]_32 || Z || OtherInfo)` for i from 1.
pub fn concat_kdf(hash: &str, z: &[u8], other_info: &[u8], length: usize)
                  -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(length + 64);
    let mut counter = 1u32;
    while out.len() < length {
        out.extend(hash_parts(hash, &[&counter.to_be_bytes(), z, other_info])?);
        counter = counter.checked_add(1).ok_or("The KDF's counter ran out.")?;
    }
    out.truncate(length);
    Ok(out)
}

/// ANSI X9.63's KDF: `Hash(Z || [i]_32 || SharedInfo)` for i from 1.
pub fn x963_kdf(hash: &str, z: &[u8], shared_info: &[u8], length: usize)
                -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(length + 64);
    let mut counter = 1u32;
    while out.len() < length {
        out.extend(hash_parts(hash, &[z, &counter.to_be_bytes(), shared_info])?);
        counter = counter.checked_add(1).ok_or("The KDF's counter ran out.")?;
    }
    out.truncate(length);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two hash KDFs put the counter in different places, and nothing
    /// else differs: swap the order of Z and the counter and one becomes
    /// the other.
    #[test]
    fn test_concat_and_x963_differ_only_in_the_counter_s_place() {
        let (z, info) = (b"shared secret", b"other info");
        let concat = concat_kdf("sha256", z, info, 40).unwrap();
        let x963 = x963_kdf("sha256", z, info, 40).unwrap();
        assert_ne!(concat, x963);
        let first = hash_parts("sha256", &[&1u32.to_be_bytes(), z, info]).unwrap();
        assert_eq!(concat[..32], first[..]);
        let first = hash_parts("sha256", &[z, &1u32.to_be_bytes(), info]).unwrap();
        assert_eq!(x963[..32], first[..]);
    }

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The `Sample results for key derivation` of RFC 8009 (counter mode
    /// over HMAC-SHA-256 and -384) and RFC 6803 (feedback mode over
    /// CMAC-Camellia, from a block of zeros): a base key, then Kc, Ke and
    /// Ki for usage 2, each with its label in the line above, read out of
    /// the vendored documents.
    fn key_derivations(doc: &str, base: &str) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let start = doc.find("Sample results for key derivation:").unwrap();
        let end = start + doc[start..].find("Sample encryptions").unwrap();
        let lines: Vec<&str> = doc[start..end].lines().collect();
        let is_hex = |l: &str| !l.trim().is_empty()
            && l.split_whitespace().all(|t| t.len() == 2 && t.chars().all(|c| c.is_ascii_hexdigit()));
        let value = |i: usize| -> Vec<u8> {
            lines[i + 1..].iter().take_while(|l| is_hex(l)).flat_map(|l| unhex(l)).collect()
        };
        let mut out = Vec::new();
        let mut key = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if line.contains(base) {
                key = value(i);
            } else if let Some(at) = line.find("= 0x") {
                let label = unhex(&line[at + 4..at + 14]);
                out.push((key.clone(), label, value(i)));
            }
        }
        out
    }

    #[test]
    fn test_rfc_8009_key_derivation() {
        let doc = include_str!("../../rfcs/rfc8009.txt");
        let cases = key_derivations(doc, "base-key:");
        assert_eq!(cases.len(), 6);
        for (key, label, want) in cases {
            let prf = if key.len() == 16 { Prf::Hmac("sha256") } else { Prf::Hmac("sha384") };
            assert_eq!(kbkdf_counter(prf, &key, &label, &[], want.len()).unwrap(), want);
        }
    }

    #[test]
    fn test_rfc_6803_key_derivation() {
        let doc = include_str!("../../rfcs/rfc6803.txt");
        let cases = key_derivations(doc, "Camellia key:");
        assert_eq!(cases.len(), 6);
        for (key, label, want) in cases {
            let got = kbkdf_feedback(Prf::Cmac("camellia"), &key, &[0; 16], &label, &[],
                                     want.len()).unwrap();
            assert_eq!(got, want);
        }
    }

    /// RFC 7518 appendix C: ECDH-ES's Concat KDF, its Z, OtherInfo and
    /// derived key given as JSON arrays of decimal octets.
    #[test]
    fn test_rfc_7518_appendix_c() {
        let doc = include_str!("../../rfcs/rfc7518.txt");
        let text = &doc[doc.find("Appendix C.  Example ECDH-ES").unwrap()..];
        let array = |after: &str| -> Vec<u8> {
            let at = text.find(after).unwrap() + after.len();
            let open = at + text[at..].find('[').unwrap();
            let close = open + text[open..].find(']').unwrap();
            text[open + 1..close].split(',').map(|t| t.trim().parse().unwrap()).collect()
        };
        let z = array("Z is following the octet sequence");
        let other_info = array("in an OtherInfo value of:");
        let want = array("hash output is:");
        assert_eq!((z.len(), want.len()), (32, 16));
        assert_eq!(concat_kdf("sha256", &z, &other_info, 16).unwrap(), want);
    }

    /// A counter-mode KDF with a different length gives a different
    /// prefix: L is in every block's input.
    #[test]
    fn test_the_length_is_part_of_the_input() {
        let prf = Prf::named("hmac-sha256").unwrap();
        let a = kbkdf_counter(prf, b"key", b"label", b"context", 16).unwrap();
        let b = kbkdf_counter(prf, b"key", b"label", b"context", 32).unwrap();
        assert_ne!(a, b[..16]);
        assert!(Prf::named("sha256").is_err());
        assert!(Prf::named("hmac-nosuch").is_err());
    }
}
