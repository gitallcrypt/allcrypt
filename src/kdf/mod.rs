/*
Key derivation functions.

All built on HMAC, all needed by some version of TLS:

  * HKDF (RFC 5869), the extract-then-expand construction used by TLS 1.3.
  * The TLS 1.2 PRF (RFC 5246 section 5), which is P_hash over a label and
    a seed. TLS 1.0 and 1.1 use the same P_hash but split the secret across
    MD5 and SHA-1 and XOR the results; `tls10_prf` does that.
  * `gost`, holding RFC 7836's `KDF_GOSTR3411_2012_256` and RFC 9189's
    TLSTREE, which is how the GOST cipher suites re-key per record.
  * `bcrypt_pbkdf`, which is not HMAC at all: OpenSSH's derivation for
    encrypted private keys, built on Blowfish's key schedule.

The first two take the hash as a value so the caller picks the algorithm:
`hkdf(sha2::SHA256::new(&[]), ...)`. The GOST ones do not - the standard
names Streebog-256 and nothing else.
*/

pub mod app_passwords;
pub mod argon2;
pub mod bcrypt_pbkdf;
pub mod gost;
pub mod ieee80211;
pub mod kerberos;
pub mod luks_af;
pub mod nist;
pub mod password;
pub mod scrypt;
pub mod unix_crypt;
pub mod windows;

use crate::hash_functions::{md5::MD5, sha1::SHA1, HashFunction};
use crate::mac::hmac::Hmac;
use crate::Mac;

/// The most bytes any derivation here produces in one call: 1 GiB.
///
/// Several constructions have a far larger ceiling of their own (PBKDF2
/// with SHA-256 can address 137 GB) or none at all (P_hash), and every
/// one reserves its output before the first MAC. A length from a caller
/// (the Python and C surfaces take one) therefore reached the
/// allocator unchecked, where failure is an abort rather than an error.
/// No key is a gigabyte; the cap is a bound on damage, not on use.
pub const MAX_OUTPUT_BYTES: usize = 1 << 30;

/// An empty output buffer with room for `length` bytes, or an error:
/// above `MAX_OUTPUT_BYTES`, or if the allocator refuses.
///
/// `try_reserve_exact` rather than `with_capacity` because the latter
/// calls `handle_alloc_error` on failure, which aborts the process and
/// cannot be caught from Python or C.
pub(crate) fn output_buffer(length: usize, what: &str) -> Result<Vec<u8>, String> {
    if length > MAX_OUTPUT_BYTES {
        return Err(format!("{} produces at most {} bytes in one call; asked for {}.",
                           what, MAX_OUTPUT_BYTES, length));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(length).map_err(|_| format!(
        "Could not allocate {} bytes for the {} output.", length, what))?;
    Ok(out)
}

// ------------------------------------------------------------------ HKDF ---

/// HKDF-Extract (RFC 5869 section 2.2): condense the input keying material
/// into a fixed length pseudorandom key.
///
/// An empty `salt` means "a string of zeros the length of the hash output",
/// which is what the RFC specifies.
pub fn hkdf_extract<H: HashFunction + Clone>(hash: H, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let zeros;
    let salt = if salt.is_empty() {
        zeros = vec![0u8; hash.digest_len()];
        &zeros[..]
    } else {
        salt
    };
    Hmac::mac(hash, salt, ikm)
}

/// HKDF-Expand (RFC 5869 section 2.3): stretch a pseudorandom key to
/// `length` bytes of output keying material.
pub fn hkdf_expand<H: HashFunction + Clone>(hash: H, prk: &[u8], info: &[u8],
                                            length: usize) -> Result<Vec<u8>, String> {
    let hash_len = hash.digest_len();
    if length > 255 * hash_len {
        return Err(format!("HKDF can produce at most {} bytes with this hash, asked for {}.",
                           255 * hash_len, length));
    }
    let mut out = Vec::with_capacity(length);
    let mut previous: Vec<u8> = Vec::new();
    // Bounded by construction: the counter is a single byte, so 255 blocks is
    // the most the construction can ever emit. Incrementing past that would
    // overflow, which is exactly the length limit checked above.
    for counter in 1..=255u8 {
        if out.len() >= length {
            break;
        }
        let mut mac = Hmac::new(hash.clone(), prk);
        mac.update(&previous);          // T(0) is empty
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.digest();
        let take = core::cmp::min(previous.len(), length - out.len());
        out.extend_from_slice(&previous[..take]);
    }
    Ok(out)
}

/// Extract then expand, the whole of RFC 5869 in one call.
pub fn hkdf<H: HashFunction + Clone>(hash: H, salt: &[u8], ikm: &[u8], info: &[u8],
                                     length: usize) -> Result<Vec<u8>, String> {
    let prk = hkdf_extract(hash.clone(), salt, ikm);
    hkdf_expand(hash, &prk, info, length)
}

// -------------------------------------------------------------- TLS 1.2 ----

/// P_hash from RFC 5246 section 5:
///
/// ```text
/// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
///                        HMAC_hash(secret, A(2) + seed) + ...
/// A(0) = seed,  A(i) = HMAC_hash(secret, A(i-1))
/// ```
///
/// # Panics
/// `length` above `MAX_OUTPUT_BYTES`, or an output buffer the allocator
/// refuses. TLS asks for key blocks of a few hundred bytes; a length
/// from outside goes through `try_p_hash`.
pub fn p_hash<H: HashFunction + Clone>(hash: H, secret: &[u8], seed: &[u8],
                                       length: usize) -> Vec<u8> {
    match try_p_hash(hash, secret, seed, length) {
        Ok(out) => out,
        Err(reason) => panic!("{reason}"),
    }
}

/// `p_hash`, with the cap and the allocation reported as an error.
pub fn try_p_hash<H: HashFunction + Clone>(hash: H, secret: &[u8], seed: &[u8],
                                           length: usize) -> Result<Vec<u8>, String> {
    let mut out = output_buffer(length, "P_hash")?;
    let mut a = seed.to_vec();          // A(0)
    while out.len() < length {
        // A(i) = HMAC(secret, A(i-1))
        a = Hmac::mac(hash.clone(), secret, &a);

        let mut mac = Hmac::new(hash.clone(), secret);
        mac.update(&a);
        mac.update(seed);
        let block = mac.digest();

        let take = core::cmp::min(block.len(), length - out.len());
        out.extend_from_slice(&block[..take]);
    }
    Ok(out)
}

/// The TLS 1.2 PRF: `P_hash(secret, label + seed)`. The hash is whatever the
/// negotiated cipher suite specifies, usually SHA-256.
///
/// # Panics
/// As `p_hash`; `try_tls12_prf` reports the cap as an error.
pub fn tls12_prf<H: HashFunction + Clone>(hash: H, secret: &[u8], label: &[u8],
                                          seed: &[u8], length: usize) -> Vec<u8> {
    match try_tls12_prf(hash, secret, label, seed, length) {
        Ok(out) => out,
        Err(reason) => panic!("{reason}"),
    }
}

/// `tls12_prf`, with the cap and the allocation reported as an error.
pub fn try_tls12_prf<H: HashFunction + Clone>(hash: H, secret: &[u8], label: &[u8],
                                              seed: &[u8], length: usize)
                                              -> Result<Vec<u8>, String> {
    let mut label_and_seed = Vec::with_capacity(label.len() + seed.len());
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);
    try_p_hash(hash, secret, &label_and_seed, length)
}

/// The TLS 1.0/1.1 PRF (RFC 2246 section 5): split the secret in half, run
/// P_MD5 over the first half and P_SHA-1 over the second, and XOR them.
///
/// An odd length secret shares its middle byte between the halves, which the
/// RFC specifies explicitly.
///
/// # Panics
/// As `p_hash`; `try_tls10_prf` reports the cap as an error.
pub fn tls10_prf(secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    match try_tls10_prf(secret, label, seed, length) {
        Ok(out) => out,
        Err(reason) => panic!("{reason}"),
    }
}

/// `tls10_prf`, with the cap and the allocation reported as an error.
pub fn try_tls10_prf(secret: &[u8], label: &[u8], seed: &[u8], length: usize)
                     -> Result<Vec<u8>, String> {
    let half = secret.len().div_ceil(2);
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];

    let mut label_and_seed = Vec::with_capacity(label.len() + seed.len());
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);

    let md5 = try_p_hash(MD5::new(&[]), s1, &label_and_seed, length)?;
    let sha1 = try_p_hash(SHA1::new(&[]), s2, &label_and_seed, length)?;
    Ok(md5.iter().zip(sha1.iter()).map(|(a, b)| a ^ b).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_functions::sha2;

    /// `p_hash` reserved its whole output with `Vec::with_capacity`
    /// and had no ceiling at all, so a length from Python's `tls12_prf`
    /// or `tls10_prf` in the gigabytes aborted the process at the
    /// allocator. The existing tests derived TLS-sized key blocks. The
    /// requests here are refused by the cap before any allocation, and
    /// the `try_` forms agree with the plain ones inside it.
    #[test]
    fn test_an_oversized_prf_output_is_an_error_not_an_abort() {
        let too_long = MAX_OUTPUT_BYTES + 1;
        let reason = try_p_hash(sha2::SHA256::new(&[]), b"s", b"seed", too_long)
            .unwrap_err();
        assert!(reason.contains("at most"), "{reason}");
        assert!(try_tls12_prf(sha2::SHA256::new(&[]), b"s", b"l", b"seed", too_long)
                    .is_err());
        assert!(try_tls10_prf(b"s", b"l", b"seed", usize::MAX).is_err());
        assert_eq!(try_tls12_prf(sha2::SHA256::new(&[]), b"s", b"l", b"seed", 100).unwrap(),
                   tls12_prf(sha2::SHA256::new(&[]), b"s", b"l", b"seed", 100));
        assert_eq!(try_tls10_prf(b"s", b"l", b"seed", 100).unwrap(),
                   tls10_prf(b"s", b"l", b"seed", 100));
    }

    /// RFC 5869 test case 1: SHA-256, 22 byte IKM, with salt and info.
    #[test]
    fn test_hkdf_rfc5869_case1() {
        let ikm = vec![0x0b; 22];
        let salt: Vec<u8> = (0..13).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();

        let prk = hkdf_extract(sha2::SHA256::new(&[]), &salt, &ikm);
        assert_eq!(crate::to_hex(&prk).to_lowercase(),
                   "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

        let okm = hkdf_expand(sha2::SHA256::new(&[]), &prk, &info, 42).unwrap();
        assert_eq!(crate::to_hex(&okm).to_lowercase(),
                   "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                    34007208d5b887185865");
    }

    /// RFC 5869 test case 3: empty salt and info, which exercises the
    /// "salt defaults to zeros" path.
    #[test]
    fn test_hkdf_rfc5869_case3() {
        let ikm = vec![0x0b; 22];
        let okm = hkdf(sha2::SHA256::new(&[]), &[], &ikm, &[], 42).unwrap();
        assert_eq!(crate::to_hex(&okm).to_lowercase(),
                   "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                    9d201395faa4b61a96c8");
    }

    /// RFC 5869 test case 4: SHA-1.
    #[test]
    fn test_hkdf_rfc5869_case4_sha1() {
        let ikm = vec![0x0b; 11];
        let salt: Vec<u8> = (0..13).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf(SHA1::new(&[]), &salt, &ikm, &info, 42).unwrap();
        assert_eq!(crate::to_hex(&okm).to_lowercase(),
                   "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2\
                    c22e422478d305f3f896");
    }

    #[test]
    fn test_hkdf_rejects_over_long_output() {
        let prk = vec![0u8; 32];
        assert!(hkdf_expand(sha2::SHA256::new(&[]), &prk, &[], 255 * 32).is_ok());
        assert!(hkdf_expand(sha2::SHA256::new(&[]), &prk, &[], 255 * 32 + 1).is_err());
    }

    /// Output length must not change the prefix: asking for fewer bytes gives
    /// a prefix of asking for more.
    #[test]
    fn test_output_is_a_prefix() {
        let secret = b"secret";
        let seed = b"seed material";
        let long = tls12_prf(sha2::SHA256::new(&[]), secret, b"label", seed, 200);
        for n in [0usize, 1, 31, 32, 33, 100, 199] {
            let short = tls12_prf(sha2::SHA256::new(&[]), secret, b"label", seed, n);
            assert_eq!(short[..], long[..n], "tls12_prf length {}", n);
        }

        let ikm = vec![0x0b; 22];
        let long = hkdf(sha2::SHA256::new(&[]), b"salt", &ikm, b"info", 200).unwrap();
        for n in [0usize, 1, 31, 32, 33, 100, 199] {
            let short = hkdf(sha2::SHA256::new(&[]), b"salt", &ikm, b"info", n).unwrap();
            assert_eq!(short[..], long[..n], "hkdf length {}", n);
        }
    }

    /// The 1.0/1.1 PRF splits an odd length secret with a shared middle byte.
    #[test]
    fn test_tls10_prf_odd_secret_splits() {
        let out = tls10_prf(b"12345", b"label", b"seed", 48);
        assert_eq!(out.len(), 48);
        // Same secret via the two halves it should decompose into.
        let md5 = p_hash(MD5::new(&[]), b"123", b"labelseed", 48);
        let sha1 = p_hash(SHA1::new(&[]), b"345", b"labelseed", 48);
        let expected: Vec<u8> = md5.iter().zip(sha1.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(out, expected);
    }
}
