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

/// PRF-n with HMAC-SHA1: `bits` must be a multiple of 8.
pub fn prf_sha1(key: &[u8], label: &[u8], data: &[u8], bits: usize) -> Vec<u8> {
    let length = bits / 8;
    let mut out = Vec::with_capacity(length + 20);
    let mut i = 0u8;
    while out.len() < length {
        let mut input = label.to_vec();
        input.push(0);
        input.extend_from_slice(data);
        input.push(i);
        out.extend(Hmac::mac(SHA1::new(&[]), key, &input));
        i = i.wrapping_add(1);
    }
    out.truncate(length);
    out
}

/// KDF-SHA256-n: `bits` must be a multiple of 8 and below 2^16.
pub fn kdf_sha256(key: &[u8], label: &[u8], context: &[u8], bits: usize) -> Vec<u8> {
    let length = bits / 8;
    let mut out = Vec::with_capacity(length + 32);
    let mut i = 1u16;
    while out.len() < length {
        let mut input = i.to_le_bytes().to_vec();
        input.extend_from_slice(label);
        input.extend_from_slice(context);
        input.extend_from_slice(&(bits as u16).to_le_bytes());
        out.extend(Hmac::mac(SHA256::new(&[]), key, &input));
        i += 1;
    }
    out.truncate(length);
    out
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
pub fn ptk_sha1(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32],
                bits: usize) -> Vec<u8> {
    prf_sha1(pmk, b"Pairwise key expansion", &ptk_data(aa, spa, anonce, snonce), bits)
}

/// The PTK of a SHA-256 AKM (802.11w PSK, WPA3-SAE).
pub fn ptk_sha256(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32],
                  snonce: &[u8; 32], bits: usize) -> Vec<u8> {
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
        let out = prf_sha1(b"key", b"label", b"data", 384);
        assert_eq!(out.len(), 48);
        for i in 0..3u8 {
            let block = Hmac::mac(SHA1::new(&[]), b"key", &[&b"label\0data"[..], &[i]].concat());
            let take = 20.min(48 - 20 * i as usize);
            assert_eq!(out[20 * i as usize..20 * i as usize + take], block[..take]);
        }
        // A shorter request is a prefix: n is not an input.
        assert_eq!(prf_sha1(b"key", b"label", b"data", 128)[..], out[..16]);
    }

    /// KDF-SHA256-n: i from 1, and n is an input, so a shorter request
    /// is not a prefix.
    #[test]
    fn test_kdf_sha256_layout() {
        let out = kdf_sha256(b"key", b"label", b"ctx", 384);
        let first = Hmac::mac(SHA256::new(&[]), b"key",
                              &[&1u16.to_le_bytes()[..], b"label", b"ctx", &384u16.to_le_bytes()]
                                  .concat());
        assert_eq!(out[..32], first[..]);
        assert_ne!(kdf_sha256(b"key", b"label", b"ctx", 256)[..], out[..32]);
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
