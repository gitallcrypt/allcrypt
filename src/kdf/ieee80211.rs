//! IEEE 802.11's key derivations (802.11-2020 12.7.1): how a passphrase
//! becomes the pairwise master key, and how the 4-way handshake turns
//! that into the keys each frame is protected with.
//!
//! - **PSK** (Annex J.4): PBKDF2-HMAC-SHA1 of the passphrase, salted
//!   with the SSID, 4096 iterations, 32 bytes. The passphrase is 8 to
//!   63 printable ASCII characters; a 64-hex-digit PSK skips this.
//! - **PRF-n** (12.7.1.2), the WPA and WPA2 PRF: HMAC-SHA1 under the key
//!   over `label || 0x00 || data || i` for `i` from 0, concatenated and
//!   cut to `n` bits.
//! - **KDF-Hash-n** (12.7.1.7.2), for the SHA-256 AKMs (802.11w, WPA3):
//!   HMAC-SHA-256 under the key over `i || label || context || n`, with
//!   `i` from 1 and `i` and `n` as 16-bit little-endian numbers.
//! - The **PTK** comes from either over the label "Pairwise key
//!   expansion" and the two addresses and the two nonces, each pair in
//!   ascending order; the **PMKID** is the first 16 bytes of HMAC-SHA1
//!   over "PMK Name", the authenticator's address and the supplicant's.

use crate::hash_functions::{sha1::SHA1, sha2::SHA256};
use crate::mac::Hmac;

/// The PSK from a passphrase and the SSID.
pub fn psk(passphrase: &[u8], ssid: &[u8]) -> Result<[u8; 32], String> {
    let out = crate::kdf::password::pbkdf2(SHA1::new(&[]), passphrase, ssid, 4096, 32)?;
    Ok(out.try_into().unwrap())
}

/// The most bits PRF-n can produce: its counter is one byte, so 256
/// blocks of HMAC-SHA1. Past that the counter wrapped and the output
/// repeated its first block, with nothing to say so.
pub const PRF_SHA1_MAX_BITS: usize = 256 * 160;

/// The most bits KDF-SHA256-n can produce: `n` is a 16-bit field of
/// every block's input, so it must be below 2^16. Past that the field
/// was written truncated and the 16-bit counter overflowed.
pub const KDF_SHA256_MAX_BITS: usize = u16::MAX as usize;

/// PRF-n with HMAC-SHA1.
///
/// # Errors
/// `bits` not a multiple of 8, or above `PRF_SHA1_MAX_BITS`.
pub fn prf_sha1(key: &[u8], label: &[u8], data: &[u8], bits: usize) -> Result<Vec<u8>, String> {
    if !bits.is_multiple_of(8) || bits > PRF_SHA1_MAX_BITS {
        return Err(format!("PRF-n produces a whole number of bytes up to {} bits; {} bits \
                            is not one.", PRF_SHA1_MAX_BITS, bits));
    }
    let length = bits / 8;
    let mut out = Vec::with_capacity(length + 20);
    let mut i = 0u8;
    while out.len() < length {
        let mut input = label.to_vec();
        input.push(0);
        input.extend_from_slice(data);
        input.push(i);
        out.extend(Hmac::mac(SHA1::new(&[]), key, &input));
        // The length check above is what keeps this from wrapping.
        i = i.wrapping_add(1);
    }
    out.truncate(length);
    Ok(out)
}

/// KDF-SHA256-n.
///
/// # Errors
/// `bits` not a multiple of 8, or above `KDF_SHA256_MAX_BITS`.
pub fn kdf_sha256(key: &[u8], label: &[u8], context: &[u8], bits: usize)
                  -> Result<Vec<u8>, String> {
    if !bits.is_multiple_of(8) || bits > KDF_SHA256_MAX_BITS {
        return Err(format!("KDF-SHA256-n produces a whole number of bytes up to {} bits; \
                            {} bits is not one.", KDF_SHA256_MAX_BITS, bits));
    }
    let length = bits / 8;
    let n = bits as u16;
    let mut out = Vec::with_capacity(length + 32);
    let mut i = 1u16;
    while out.len() < length {
        let mut input = i.to_le_bytes().to_vec();
        input.extend_from_slice(label);
        input.extend_from_slice(context);
        input.extend_from_slice(&n.to_le_bytes());
        out.extend(Hmac::mac(SHA256::new(&[]), key, &input));
        // At most 256 blocks for 2^16 - 1 bits, so this cannot overflow.
        i += 1;
    }
    out.truncate(length);
    Ok(out)
}

/// The 4-way handshake's PTK input: `min(AA, SPA) || max(AA, SPA) ||
/// min(ANonce, SNonce) || max(ANonce, SNonce)`.
pub fn ptk_data(aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32]) -> Vec<u8> {
    let (a1, a2) = if aa < spa { (aa, spa) } else { (spa, aa) };
    let (n1, n2) = if anonce < snonce { (anonce, snonce) } else { (snonce, anonce) };
    [&a1[..], a2, n1, n2].concat()
}

/// The PTK of a SHA-1 AKM (WPA, WPA2-PSK): `bits` is 512 for TKIP (KCK,
/// KEK, TK and the two Michael keys) and 384 for CCMP.
///
/// # Panics
/// A `bits` `prf_sha1` refuses; `try_ptk_sha1` reports it instead.
pub fn ptk_sha1(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32],
                bits: usize) -> Vec<u8> {
    match try_ptk_sha1(pmk, aa, spa, anonce, snonce, bits) {
        Ok(ptk) => ptk,
        Err(reason) => panic!("{reason}"),
    }
}

/// `ptk_sha1`, with a bad `bits` reported as an error.
pub fn try_ptk_sha1(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32],
                    snonce: &[u8; 32], bits: usize) -> Result<Vec<u8>, String> {
    prf_sha1(pmk, b"Pairwise key expansion", &ptk_data(aa, spa, anonce, snonce), bits)
}

/// The PTK of a SHA-256 AKM (802.11w PSK, WPA3-SAE).
///
/// # Panics
/// A `bits` `kdf_sha256` refuses; `try_ptk_sha256` reports it instead.
pub fn ptk_sha256(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32],
                  snonce: &[u8; 32], bits: usize) -> Vec<u8> {
    match try_ptk_sha256(pmk, aa, spa, anonce, snonce, bits) {
        Ok(ptk) => ptk,
        Err(reason) => panic!("{reason}"),
    }
}

/// `ptk_sha256`, with a bad `bits` reported as an error.
pub fn try_ptk_sha256(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32],
                      snonce: &[u8; 32], bits: usize) -> Result<Vec<u8>, String> {
    kdf_sha256(pmk, b"Pairwise key expansion", &ptk_data(aa, spa, anonce, snonce), bits)
}

/// The PMKID of a SHA-1 AKM.
pub fn pmkid(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6]) -> [u8; 16] {
    let input = [&b"PMK Name"[..], aa, spa].concat();
    Hmac::mac(SHA1::new(&[]), pmk, &input)[..16].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PRF-n written out once: the counter is the last byte, after a NUL
    /// that separates the label.
    #[test]
    fn test_prf_layout() {
        let out = prf_sha1(b"key", b"label", b"data", 384).unwrap();
        assert_eq!(out.len(), 48);
        for i in 0..3u8 {
            let block = Hmac::mac(SHA1::new(&[]), b"key", &[&b"label\0data"[..], &[i]].concat());
            let take = 20.min(48 - 20 * i as usize);
            assert_eq!(out[20 * i as usize..20 * i as usize + take], block[..take]);
        }
        // A shorter request is a prefix: n is not an input.
        assert_eq!(prf_sha1(b"key", b"label", b"data", 128).unwrap()[..], out[..16]);
    }

    /// KDF-SHA256-n: i from 1, and n is an input, so a shorter request
    /// is not a prefix.
    #[test]
    fn test_kdf_sha256_layout() {
        let out = kdf_sha256(b"key", b"label", b"ctx", 384).unwrap();
        let first = Hmac::mac(SHA256::new(&[]), b"key",
                              &[&1u16.to_le_bytes()[..], b"label", b"ctx", &384u16.to_le_bytes()]
                                  .concat());
        assert_eq!(out[..32], first[..]);
        assert_ne!(kdf_sha256(b"key", b"label", b"ctx", 256).unwrap()[..], out[..32]);
    }

    /// `prf_sha1` wrapped its one byte counter, so past 5,120 bytes
    /// the output repeated its first block; `kdf_sha256` wrote `bits`
    /// truncated to 16 bits into every block and incremented a `u16`
    /// counter with `+=`, a panic in debug past 2 MiB. The doc comment
    /// said "below 2^16" and nothing enforced it, and `api::wpa_ptk`
    /// takes `bits` from the caller. The layout tests asked for 384
    /// bits. The first refused value here is one block past each
    /// construction's ceiling, where the old code repeated or
    /// truncated silently.
    #[test]
    fn test_a_request_past_the_counter_is_refused() {
        assert_eq!(prf_sha1(b"k", b"l", b"d", PRF_SHA1_MAX_BITS).unwrap().len(), 256 * 20);
        let reason = prf_sha1(b"k", b"l", b"d", PRF_SHA1_MAX_BITS + 160).unwrap_err();
        assert!(reason.contains("up to"), "{reason}");
        assert!(prf_sha1(b"k", b"l", b"d", 12).is_err(), "not whole bytes");

        assert!(kdf_sha256(b"k", b"l", b"c", KDF_SHA256_MAX_BITS - 7).is_ok());
        assert!(kdf_sha256(b"k", b"l", b"c", 1 << 16).is_err());
        assert!(kdf_sha256(b"k", b"l", b"c", 12).is_err(), "not whole bytes");
        assert!(try_ptk_sha256(&[0; 32], &[1; 6], &[2; 6], &[3; 32], &[4; 32], 1 << 16)
                    .is_err());
        assert!(try_ptk_sha1(&[0; 32], &[1; 6], &[2; 6], &[3; 32], &[4; 32], 1 << 20)
                    .is_err());
    }

    /// The PMKID is HMAC-SHA1("PMK Name" || AA || SPA) cut to 16 bytes:
    /// swapping the two addresses changes it, so a known value pins the
    /// order.
    #[test]
    fn test_pmkid_is_hmac_over_the_label_and_addresses() {
        let pmk = [0x22u8; 32];
        let (aa, spa) = ([1u8; 6], [2u8; 6]);
        let want = Hmac::mac(SHA1::new(&[]), &pmk,
                             &[&b"PMK Name"[..], &aa, &spa].concat())[..16].to_vec();
        assert_eq!(pmkid(&pmk, &aa, &spa).to_vec(), want);
        assert_ne!(pmkid(&pmk, &aa, &spa), pmkid(&pmk, &spa, &aa));
    }

    #[test]
    fn test_ptk_data_sorts_each_pair() {
        let (a, b) = ([2u8; 6], [1u8; 6]);
        let (n1, n2) = ([9u8; 32], [3u8; 32]);
        assert_eq!(ptk_data(&a, &b, &n1, &n2), ptk_data(&b, &a, &n2, &n1));
        assert_eq!(ptk_data(&a, &b, &n1, &n2)[..6], b);
        assert_eq!(ptk_data(&a, &b, &n1, &n2)[12..44], n2);
    }
}
