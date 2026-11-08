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
//!   The SHA-384 AKMs (Suite B 192-bit, 802.1X-SHA384) take the same
//!   PTK over KDF-SHA384 with a 48 byte PMK.
//! - **Fast BSS transition** (802.11r, 12.7.1.7): the PMK - the PSK, the
//!   second 256 bits of the MSK, or SAE's PMK, called XXKey here - names
//!   a PMK-R0 for the mobility domain, which names a PMK-R1 for one
//!   access point, which gives the PTK:
//!
//!   ```text
//!   R0-Key-Data = KDF-Hash-(Q+128)(XXKey, "FT-R0", len(SSID) || SSID || MDID
//!                                  || len(R0KH-ID) || R0KH-ID || S0KH-ID)
//!   PMK-R0      = the first Q bits;   salt = the last 128
//!   PMKR0Name   = Truncate-128(Hash("FT-R0N" || salt))
//!   PMK-R1      = KDF-Hash-Q(PMK-R0, "FT-R1", R1KH-ID || S1KH-ID)
//!   PMKR1Name   = Truncate-128(Hash("FT-R1N" || PMKR0Name || R1KH-ID || S1KH-ID))
//!   PTK         = KDF-Hash-Length(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID
//!                                 || STA-ADDR)
//!   ```
//!
//!   `Hash` and `Q` follow the key's length: SHA-256 for 32 bytes,
//!   SHA-384 for 48 (FT-802.1X-SHA384), SHA-512 for 64 (FT-SAE-EXT-KEY
//!   over a 521 bit group). Unlike the 4-way handshake's, the FT PTK's
//!   input is in a fixed order, not sorted.

use crate::hash_functions::sha1::SHA1;
use crate::hash_functions::sha2::{SHA256, SHA384, SHA512};
use crate::hash_functions::HashFunction;
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

/// KDF-Hash-n over any hash: HMAC under the key over `i || label ||
/// context || n`, `i` from 1.
fn kdf_hash<H: HashFunction + Clone>(hash: H, name: &str, key: &[u8], label: &[u8],
                                     context: &[u8], bits: usize) -> Result<Vec<u8>, String> {
    if !bits.is_multiple_of(8) || bits > KDF_SHA256_MAX_BITS {
        return Err(format!("KDF-{name}-n produces a whole number of bytes up to {} bits; \
                            {} bits is not one.", KDF_SHA256_MAX_BITS, bits));
    }
    let length = bits / 8;
    let n = bits as u16;
    let mut out = Vec::with_capacity(length + 64);
    let mut i = 1u16;
    while out.len() < length {
        let mut input = i.to_le_bytes().to_vec();
        input.extend_from_slice(label);
        input.extend_from_slice(context);
        input.extend_from_slice(&n.to_le_bytes());
        out.extend(Hmac::mac(hash.clone(), key, &input));
        // At most 256 blocks for 2^16 - 1 bits, so this cannot overflow.
        i += 1;
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
    kdf_hash(SHA256::new(&[]), "SHA256", key, label, context, bits)
}

/// KDF-SHA384-n, for the SHA-384 AKMs. The same ceiling as
/// `kdf_sha256`'s: `n` is a 16-bit field.
///
/// # Errors
/// `bits` not a multiple of 8, or above `KDF_SHA256_MAX_BITS`.
pub fn kdf_sha384(key: &[u8], label: &[u8], context: &[u8], bits: usize)
                  -> Result<Vec<u8>, String> {
    kdf_hash(SHA384::new(&[]), "SHA384", key, label, context, bits)
}

/// KDF-SHA512-n, for FT-SAE-EXT-KEY over a 521 bit group.
///
/// # Errors
/// `bits` not a multiple of 8, or above `KDF_SHA256_MAX_BITS`.
pub fn kdf_sha512(key: &[u8], label: &[u8], context: &[u8], bits: usize)
                  -> Result<Vec<u8>, String> {
    kdf_hash(SHA512::new(&[], 512), "SHA512", key, label, context, bits)
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

/// The PTK of a SHA-384 AKM (Suite B 192-bit, 802.1X-SHA384): the PMK
/// is 48 bytes, and the PTK holds a 24 byte KCK and a 32 byte KEK
/// before the TK.
///
/// # Errors
/// A `bits` `kdf_sha384` refuses.
pub fn try_ptk_sha384(pmk: &[u8], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32],
                      snonce: &[u8; 32], bits: usize) -> Result<Vec<u8>, String> {
    kdf_sha384(pmk, b"Pairwise key expansion", &ptk_data(aa, spa, anonce, snonce), bits)
}

/// The hash a fast BSS transition key takes, by its length.
#[derive(Clone, Copy)]
enum FtHash {
    Sha256,
    Sha384,
    Sha512,
}

impl FtHash {
    fn for_key(key: &[u8], what: &str) -> Result<FtHash, String> {
        match key.len() {
            32 => Ok(FtHash::Sha256),
            48 => Ok(FtHash::Sha384),
            64 => Ok(FtHash::Sha512),
            n => Err(format!("A fast BSS transition {what} is 32, 48 or 64 bytes, for \
                              SHA-256, SHA-384 or SHA-512; {n} bytes is none of them.")),
        }
    }

    fn kdf(self, key: &[u8], label: &[u8], context: &[u8], bits: usize)
           -> Result<Vec<u8>, String> {
        match self {
            FtHash::Sha256 => kdf_sha256(key, label, context, bits),
            FtHash::Sha384 => kdf_sha384(key, label, context, bits),
            FtHash::Sha512 => kdf_sha512(key, label, context, bits),
        }
    }

    /// The first 128 bits of the hash of `parts`, concatenated.
    fn name(self, parts: &[&[u8]]) -> [u8; 16] {
        fn over<H: HashFunction>(mut hash: H, parts: &[&[u8]]) -> Vec<u8> {
            parts.iter().for_each(|part| hash.update(part));
            hash.digest()
        }
        let digest = match self {
            FtHash::Sha256 => over(SHA256::new(&[]), parts),
            FtHash::Sha384 => over(SHA384::new(&[]), parts),
            FtHash::Sha512 => over(SHA512::new(&[], 512), parts),
        };
        digest[..16].try_into().unwrap()
    }
}

/// PMK-R0 and PMKR0Name from XXKey: the PSK, the second 256 bits of the
/// MSK (FT-802.1X), the first 384 bits of it (FT-802.1X-SHA384), or
/// SAE's PMK. `mdid` is the mobility domain identifier as it is sent,
/// `r0kh_id` the R0 key holder's identifier (1 to 48 bytes, often a
/// name), `s0kh_id` the station's address.
///
/// # Errors
/// An XXKey that is not 32, 48 or 64 bytes, an SSID over 32 bytes, or
/// an R0KH-ID that is empty or over 48.
pub fn ft_pmk_r0(xxkey: &[u8], ssid: &[u8], mdid: &[u8; 2], r0kh_id: &[u8], s0kh_id: &[u8; 6])
                 -> Result<(Vec<u8>, [u8; 16]), String> {
    let hash = FtHash::for_key(xxkey, "XXKey")?;
    if ssid.len() > 32 {
        return Err(format!("An SSID is at most 32 bytes, not {}.", ssid.len()));
    }
    if r0kh_id.is_empty() || r0kh_id.len() > 48 {
        return Err(format!("An R0KH-ID is 1 to 48 bytes, not {}.", r0kh_id.len()));
    }
    let context = [&[ssid.len() as u8][..], ssid, mdid, &[r0kh_id.len() as u8], r0kh_id,
                   s0kh_id].concat();
    let q = xxkey.len();
    let data = hash.kdf(xxkey, b"FT-R0", &context, (q + 16) * 8)?;
    let name = hash.name(&[b"FT-R0N", &data[q..]]);
    Ok((data[..q].to_vec(), name))
}

/// PMK-R1 and PMKR1Name for one access point: `r1kh_id` is its R1 key
/// holder's identifier, six bytes and usually its BSSID, and `s1kh_id`
/// the station's address.
///
/// # Errors
/// A PMK-R0 that is not 32, 48 or 64 bytes.
pub fn ft_pmk_r1(pmk_r0: &[u8], pmk_r0_name: &[u8; 16], r1kh_id: &[u8; 6], s1kh_id: &[u8; 6])
                 -> Result<(Vec<u8>, [u8; 16]), String> {
    let hash = FtHash::for_key(pmk_r0, "PMK-R0")?;
    let pmk_r1 = hash.kdf(pmk_r0, b"FT-R1", &[&r1kh_id[..], s1kh_id].concat(),
                          pmk_r0.len() * 8)?;
    let name = hash.name(&[b"FT-R1N", pmk_r0_name, r1kh_id, s1kh_id]);
    Ok((pmk_r1, name))
}

/// The PTK from PMK-R1, `bits` long: KCK, KEK and TK, the first two 16
/// bytes each under SHA-256, 24 and 32 under SHA-384, 32 and 32 under
/// SHA-512.
///
/// # Errors
/// A PMK-R1 that is not 32, 48 or 64 bytes, or a `bits` the KDF refuses.
pub fn ft_ptk(pmk_r1: &[u8], snonce: &[u8; 32], anonce: &[u8; 32], bssid: &[u8; 6],
              sta: &[u8; 6], bits: usize) -> Result<Vec<u8>, String> {
    let hash = FtHash::for_key(pmk_r1, "PMK-R1")?;
    hash.kdf(pmk_r1, b"FT-PTK", &[&snonce[..], anonce, bssid, sta].concat(), bits)
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

    /// KDF-SHA384-n is KDF-SHA256-n's layout over HMAC-SHA-384.
    #[test]
    fn test_kdf_sha384_layout() {
        let out = kdf_sha384(b"key", b"label", b"ctx", 704).unwrap();
        let block = |i: u16| Hmac::mac(SHA384::new(&[]), b"key",
                                       &[&i.to_le_bytes()[..], b"label", b"ctx",
                                         &704u16.to_le_bytes()].concat());
        assert_eq!(out, [block(1), block(2)].concat()[..88]);
    }

    /// The FT PTK's input is SNonce first and is not sorted, so swapping
    /// the nonces, or the two addresses, gives another key.
    #[test]
    fn test_the_ft_ptk_input_is_in_order() {
        let (pmk_r1, n1, n2, a1, a2) = ([5u8; 32], [1u8; 32], [2u8; 32], [3u8; 6], [4u8; 6]);
        let ptk = ft_ptk(&pmk_r1, &n1, &n2, &a1, &a2, 384).unwrap();
        assert_ne!(ptk, ft_ptk(&pmk_r1, &n2, &n1, &a1, &a2, 384).unwrap());
        assert_ne!(ptk, ft_ptk(&pmk_r1, &n1, &n2, &a2, &a1, 384).unwrap());
        assert_eq!(ptk, kdf_sha256(&pmk_r1, b"FT-PTK", &[&n1[..], &n2, &a1, &a2].concat(), 384)
            .unwrap());
    }

    /// The names hash with the key's own hash: SHA-384 for a 48 byte key,
    /// where Wireshark 4.6 uses SHA-256 for every length.
    #[test]
    fn test_the_names_take_the_keys_hash() {
        let (pmk_r0, name, r1kh, s1kh) = ([7u8; 48], [8u8; 16], [1u8; 6], [2u8; 6]);
        let (_, r1_name) = ft_pmk_r1(&pmk_r0, &name, &r1kh, &s1kh).unwrap();
        let parts = [&b"FT-R1N"[..], &name, &r1kh, &s1kh].concat();
        assert_eq!(r1_name[..], SHA384::new(&parts).digest()[..16]);
        assert_ne!(r1_name[..], SHA256::new(&parts).digest()[..16]);
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
