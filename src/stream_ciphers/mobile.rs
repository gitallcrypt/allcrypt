//! The 3GPP confidentiality and integrity algorithms over KASUMI, SNOW 3G
//! and ZUC: UEA1 and UIA1 (UMTS, KASUMI's f8 and f9, 3GPP TS 35.201),
//! UEA2 (UMTS) and 128-EEA1 (LTE; 128-NEA1 in 5G), which are one
//! function, UIA2 and 128-EIA1 (UIA2 with FRESH = BEARER || 0^27),
//! 128-EEA3 and 128-EIA3 over ZUC, and 5G's 256 bit 256-NEA6, 256-NIA6
//! and 256-NCA6 over 3GPP's ZUC-256 (below).
//!
//! Each takes a 16 byte key, a 32 bit COUNT, a 5 bit BEARER (UIA2 a 32
//! bit FRESH instead), a DIRECTION bit, and a message of `bits` bits in
//! `ceil(bits / 8)` bytes, the first bit the top bit of the first byte.
//! A ciphertext comes back in as many bytes, with the bits past `bits`
//! in the last one cleared; a MAC ignores them.
//!
//! The IVs, from the implementors' test data, which prints them for each
//! set (`rfcs/Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.txt`):
//!
//! ```text
//! UEA2   k_i = CK word 3 - i    IV0 = IV2 = BEARER << 27 | DIRECTION << 26
//!                               IV1 = IV3 = COUNT
//! UIA2   k_i = IK word 3 - i    IV0 = FRESH ^ DIRECTION << 15, IV2 = FRESH
//!                               IV1 = COUNT ^ DIRECTION << 31, IV3 = COUNT
//! EEA3   IV  = COUNT || BEARER << 3 | DIRECTION << 2 || 0 0 0, twice
//! EIA3   IV  = COUNT || BEARER << 3 || 0 0 0 || COUNT ^ DIRECTION << 31
//!              || BEARER << 3 || 0 || DIRECTION << 7 || 0
//! ```
//!
//! UIA2 takes five keystream words `z1..z5`, `P = z1 || z2` and
//! `Q = z3 || z4`, and evaluates the message's 64 bit blocks `M_i` - the
//! last padded with zeros - as a polynomial in `P` over GF(2^64) mod
//! `x^64 + x^4 + x^3 + x + 1`:
//!
//! ```text
//! EVAL = 0;  EVAL = (EVAL ^ M_i) * P for each block
//! EVAL = (EVAL ^ LENGTH) * Q;  MAC = (EVAL >> 32) ^ z5
//! ```
//!
//! An empty message has no blocks and is defined by the same lines; the
//! reference f9 runs its block loop to `D - 2` in an unsigned type and
//! cannot take one, and Intel's library refuses one (`docs/pitfalls.md`).
//!
//! UEA1 and UIA1 are modes of KASUMI, each block a 64 bit big-endian
//! value:
//!
//! ```text
//! UEA1   A = KASUMI[CK ^ 0x55..](COUNT || BEARER << 3 | DIRECTION << 2 || 0 0 0)
//!        KS_0 = 0;  KS_n = KASUMI[CK](A ^ (n - 1) ^ KS_(n-1)), n from 1
//! UIA1   PS = COUNT || FRESH || MESSAGE || DIRECTION || 1 || 0..  to 64 bit blocks
//!        A = 0, B = 0;  A = KASUMI[IK](A ^ PS_i), B ^= A for each block
//!        MAC = the first 32 bits of KASUMI[IK ^ 0xAA..](B)
//! ```
//!
//! The block counter is added into the low 16 bits.
//!
//! ## 256-NEA6, 256-NIA6 and 256-NCA6
//!
//! TS 35.246 V20.0.0 (`rfcs/35246-k00.txt`) defines one construction,
//! 256-AEAD1, over a keystream generator - ZUC-256 for the three here
//! (`Zuc::zuc256_3gpp`) - and the three algorithms as uses of it. The
//! 16 byte IV, `Make_5GIV` (section 4.3):
//!
//! ```text
//! IV[0]      = MAC_BYTES << 3 | CF << 2 | LK << 1 | AI
//! IV[1]      = BEARER << 1 | DIRECTION
//! IV[2..8]   = EXTRA_IV (six bytes, zero when not given)
//! IV[8..12]  = COUNT, big endian;  IV[12..16] = 0
//! ```
//!
//! with CF 1 for NCA6 and 0 otherwise, LK 1 for a 16 byte key - which is
//! zero-extended to 32 (section 4.5) - and AI 0. When a MAC is wanted
//! the first twelve keystream words are `H`, `Q` and `P`, four each, and
//! the data's keystream follows them; NEA6 takes none. The MAC is
//! Mac5G, POLYVAL's polynomial with a length block and a mask:
//!
//! ```text
//! dot(A, B) = A * B * x^-128  mod x^128 + x^127 + x^126 + x^121 + 1
//! A = 0;  A = dot(A ^ block, H) for each 16 byte block of the AAD,
//!         then of the ciphertext, each zero-padded
//! A = dot(A ^ (LE32(S_LENGTH) || 0^4 || LE32(AAD_LENGTH) || 0^4), Q) ^ P
//! MAC = the first MAC_BYTES bytes of A
//! ```
//!
//! NIA6 is a MAC of the message as AAD and no data; NEA6 is the
//! keystream alone; NCA6 is both. Bits past a length in a last byte are
//! cleared in what is encrypted and ignored in what is authenticated.
//!
//! The multiplication in UIA2 masks each step on a bit of `P` or `Q`, and
//! the EIA3 sum masks each window on its message bit; POLYVAL's `dot`
//! masks each step on a bit of `A`, and the tag is compared with an OR of
//! XORs. UEA1 and UIA1 are
//! as constant time as KASUMI, whose S7 and S9 are tables indexed by the
//! data.

use crate::block_ciphers::kasumi::Kasumi;
use crate::block_ciphers::BlockCipher;
use crate::stream_ciphers::snow3g::Snow3g;
use crate::stream_ciphers::zuc::{check_bits, eia3_core, Zuc};

fn key16<'a>(key: &'a [u8], what: &str) -> Result<&'a [u8; 16], String> {
    key.try_into().map_err(|_| format!("A {what} key is 16 bytes, not {}.", key.len()))
}

fn check_bearer(bearer: u8, direction: u8) -> Result<(), String> {
    if bearer > 31 {
        return Err(format!("BEARER is five bits: 0 to 31, not {bearer}."));
    }
    if direction > 1 {
        return Err(format!("DIRECTION is one bit: 0 or 1, not {direction}."));
    }
    Ok(())
}

/// `data` with the bits past `bits` in its last byte cleared.
fn clear_tail(data: &mut [u8], bits: usize) {
    if !bits.is_multiple_of(8) {
        data[bits / 8] &= 0xffu8 << (8 - bits % 8);
    }
}

/// A key's four words, the first 32 bits `k3`: how UEA2 and UIA2 load CK
/// and IK into SNOW 3G.
fn reversed_words(key: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| {
        let at = 4 * (3 - i);
        u32::from_be_bytes(key[at..at + 4].try_into().unwrap())
    })
}

/// One KASUMI block.
fn kasumi(cipher: &mut Kasumi, block: [u8; 8]) -> [u8; 8] {
    let mut out = Vec::with_capacity(8);
    cipher.block_encrypt(&block, &mut out);
    out.try_into().expect("KASUMI appends one block")
}

/// KASUMI under `key` with every byte XORed with `modifier`.
fn modified(key: &[u8; 16], modifier: u8) -> Kasumi {
    let changed: Vec<u8> = key.iter().map(|b| b ^ modifier).collect();
    Kasumi::new(&changed).expect("a 16 byte key")
}

/// UEA1, KASUMI's f8: the first `bits` bits of `data` encrypted or
/// decrypted.
///
/// # Errors
/// A key not of 16 bytes, a BEARER above 31 or a DIRECTION above 1, or
/// `data` not `ceil(bits / 8)` bytes.
pub fn uea1(key: &[u8], count: u32, bearer: u8, direction: u8, data: &[u8], bits: u64)
            -> Result<Vec<u8>, String> {
    let key = key16(key, "UEA1")?;
    check_bearer(bearer, direction)?;
    let bits = check_bits(data, bits)?;
    let mut iv = [0u8; 8];
    iv[..4].copy_from_slice(&count.to_be_bytes());
    iv[4] = bearer << 3 | direction << 2;
    let a = u64::from_be_bytes(kasumi(&mut modified(key, 0x55), iv));
    let mut cipher = Kasumi::new(key)?;
    let mut out = data.to_vec();
    let mut ks = 0u64;
    for (n, chunk) in out.chunks_mut(8).enumerate() {
        ks = u64::from_be_bytes(kasumi(&mut cipher, (a ^ n as u64 ^ ks).to_be_bytes()));
        for (byte, k) in chunk.iter_mut().zip(ks.to_be_bytes()) {
            *byte ^= k;
        }
    }
    clear_tail(&mut out, bits);
    Ok(out)
}

/// UIA1, KASUMI's f9: the 4 byte MAC of the first `bits` bits of `data`.
///
/// # Errors
/// A key not of 16 bytes, a DIRECTION above 1, or `data` not
/// `ceil(bits / 8)` bytes.
pub fn uia1(key: &[u8], count: u32, fresh: u32, direction: u8, data: &[u8], bits: u64)
            -> Result<[u8; 4], String> {
    let key = key16(key, "UIA1")?;
    check_bearer(0, direction)?;
    let bits = check_bits(data, bits)?;
    // PS: COUNT, FRESH, the message, DIRECTION, a one bit, then zeros to a
    // whole number of blocks. The bits past `bits` in the last byte are
    // not the message's.
    let mut ps = Vec::with_capacity(8 + data.len() + 9);
    ps.extend_from_slice(&count.to_be_bytes());
    ps.extend_from_slice(&fresh.to_be_bytes());
    ps.extend_from_slice(data);
    clear_tail(&mut ps, 64 + bits);
    for (at, bit) in (64 + bits..).zip([direction, 1]) {
        if at.is_multiple_of(8) {
            ps.push(0);
        }
        *ps.last_mut().expect("eight bytes at least") |= bit << (7 - at % 8);
    }
    ps.resize(ps.len().div_ceil(8) * 8, 0);
    let mut cipher = Kasumi::new(key)?;
    let (mut a, mut b) = (0u64, 0u64);
    for block in ps.chunks(8) {
        let input = a ^ u64::from_be_bytes(block.try_into().expect("whole blocks"));
        a = u64::from_be_bytes(kasumi(&mut cipher, input.to_be_bytes()));
        b ^= a;
    }
    let mac = kasumi(&mut modified(key, 0xaa), b.to_be_bytes());
    Ok(mac[..4].try_into().expect("four bytes"))
}

/// UEA2, which is 128-EEA1 and 128-NEA1: the first `bits` bits of `data`
/// encrypted or decrypted.
///
/// # Errors
/// A key not of 16 bytes, a BEARER above 31 or a DIRECTION above 1, or
/// `data` not `ceil(bits / 8)` bytes.
pub fn uea2(key: &[u8], count: u32, bearer: u8, direction: u8, data: &[u8], bits: u64)
            -> Result<Vec<u8>, String> {
    let key = key16(key, "UEA2")?;
    check_bearer(bearer, direction)?;
    let bits = check_bits(data, bits)?;
    let iv0 = u32::from(bearer) << 27 | u32::from(direction) << 26;
    let mut out = data.to_vec();
    Snow3g::from_words(reversed_words(key), [iv0, count, iv0, count]).apply_keystream(&mut out);
    clear_tail(&mut out, bits);
    Ok(out)
}

/// Multiplication in GF(2^64) mod x^64 + x^4 + x^3 + x + 1, a step per
/// bit of `p` under a mask.
fn mul64(mut v: u64, p: u64) -> u64 {
    let mut out = 0u64;
    for i in 0..64 {
        out ^= v & 0u64.wrapping_sub((p >> i) & 1);
        v = (v << 1) ^ (0x1b & 0u64.wrapping_sub(v >> 63));
    }
    out
}

/// UIA2: the 4 byte MAC of the first `bits` bits of `data`.
///
/// # Errors
/// A key not of 16 bytes, a DIRECTION above 1, or `data` not
/// `ceil(bits / 8)` bytes.
pub fn uia2(key: &[u8], count: u32, fresh: u32, direction: u8, data: &[u8], bits: u64)
            -> Result<[u8; 4], String> {
    let key = key16(key, "UIA2")?;
    check_bearer(0, direction)?;
    let length = bits;
    let bits = check_bits(data, bits)?;
    let dir = u32::from(direction);
    let iv = [fresh ^ dir << 15, count ^ dir << 31, fresh, count];
    let mut g = Snow3g::from_words(reversed_words(key), iv);
    let z: [u32; 5] = core::array::from_fn(|_| g.next_word());
    let p = u64::from(z[0]) << 32 | u64::from(z[1]);
    let q = u64::from(z[2]) << 32 | u64::from(z[3]);
    // The last block is padded with zeros, whatever the last byte holds
    // past `bits`.
    let mut message = data.to_vec();
    clear_tail(&mut message, bits);
    let mut eval = 0u64;
    for chunk in message.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        eval = mul64(eval ^ u64::from_be_bytes(block), p);
    }
    eval = mul64(eval ^ length, q);
    Ok(((eval >> 32) as u32 ^ z[4]).to_be_bytes())
}

/// 128-EIA1 and 128-NIA1: UIA2 with FRESH = BEARER || 0^27.
///
/// # Errors
/// As `uia2`, and a BEARER above 31.
pub fn eia1(key: &[u8], count: u32, bearer: u8, direction: u8, data: &[u8], bits: u64)
            -> Result<[u8; 4], String> {
    check_bearer(bearer, direction)?;
    uia2(key, count, u32::from(bearer) << 27, direction, data, bits)
        .map_err(|e| e.replace("UIA2", "128-EIA1"))
}

/// 128-EEA3 and 128-NEA3: the first `bits` bits of `data` encrypted or
/// decrypted.
///
/// # Errors
/// A key not of 16 bytes, a BEARER above 31 or a DIRECTION above 1, or
/// `data` not `ceil(bits / 8)` bytes.
pub fn eea3(key: &[u8], count: u32, bearer: u8, direction: u8, data: &[u8], bits: u64)
            -> Result<Vec<u8>, String> {
    let key = key16(key, "128-EEA3")?;
    check_bearer(bearer, direction)?;
    let bits = check_bits(data, bits)?;
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&count.to_be_bytes());
    iv[4] = bearer << 3 | direction << 2;
    iv.copy_within(..8, 8);
    let mut out = data.to_vec();
    Zuc::zuc128(key, &iv)?.apply_keystream(&mut out);
    clear_tail(&mut out, bits);
    Ok(out)
}

/// 128-EIA3 and 128-NIA3: the 4 byte MAC of the first `bits` bits of
/// `data`.
///
/// # Errors
/// A key not of 16 bytes, a BEARER above 31 or a DIRECTION above 1, or
/// `data` not `ceil(bits / 8)` bytes.
pub fn eia3(key: &[u8], count: u32, bearer: u8, direction: u8, data: &[u8], bits: u64)
            -> Result<[u8; 4], String> {
    let key = key16(key, "128-EIA3")?;
    check_bearer(bearer, direction)?;
    let bits = check_bits(data, bits)?;
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&count.to_be_bytes());
    iv[4] = bearer << 3;
    iv.copy_within(..8, 8);
    iv[8] ^= direction << 7;
    iv[14] ^= direction << 7;
    Ok(eia3_core(Zuc::zuc128(key, &iv)?, data, bits))
}

// ------------------------------------------- 5G's 256 bit algorithms ---

/// TS 35.246 section 4.3's `Make_5GIV`, AI 0.
fn make_5g_iv(count: u32, bearer: u8, direction: u8, extra_iv: &[u8; 6], mac_bytes: u8,
              combined: bool, short_key: bool) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0] = mac_bytes << 3 | u8::from(combined) << 2 | u8::from(short_key) << 1;
    iv[1] = bearer << 1 | direction;
    iv[2..8].copy_from_slice(extra_iv);
    iv[8..12].copy_from_slice(&count.to_be_bytes());
    iv
}

/// POLYVAL's `dot`: `A * B * x^-128` modulo `x^128 + x^127 + x^126 +
/// x^121 + 1`, each operand a 128 bit number stored little endian (TS
/// 35.246 section 5.2.3.3).
fn pdot(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let b0 = u64::from_le_bytes(b[..8].try_into().unwrap());
    let b1 = u64::from_le_bytes(b[8..].try_into().unwrap());
    let (mut r0, mut r1) = (0u64, 0u64);
    for byte in a {
        for bit in 0..8 {
            let take = 0u64.wrapping_sub(u64::from(byte >> bit & 1));
            r0 ^= b0 & take;
            r1 ^= b1 & take;
            let reduce = 0xe100_0000_0000_0000 & 0u64.wrapping_sub(r0 & 1);
            r0 = (r0 >> 1) ^ (r1 << 63);
            r1 = (r1 >> 1) ^ reduce;
        }
    }
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&r0.to_le_bytes());
    out[8..].copy_from_slice(&r1.to_le_bytes());
    out
}

/// Mac5G.Update: the first `bits` bits of `data`, in 16 byte blocks, the
/// last zero-padded, the bits past `bits` ignored.
fn mac5g_update(h: &[u8; 16], a: &mut [u8; 16], data: &[u8], bits: usize) {
    let mut data = data[..bits.div_ceil(8)].to_vec();
    clear_tail(&mut data, bits);
    for chunk in data.chunks(16) {
        for (x, y) in a.iter_mut().zip(chunk) {
            *x ^= y;
        }
        *a = pdot(a, h);
    }
}

/// 256-AEAD1 over 3GPP's ZUC-256 (TS 35.246 section 5.2): the first
/// `bits` bits of `data` encrypted or decrypted, and, when `mac_bytes`
/// is not 0, the MAC over the first `aad_bits` bits of `aad` and the
/// ciphertext - the output when encrypting, the input when decrypting.
#[allow(clippy::too_many_arguments)]
fn aead1(key: &[u8; 32], iv: &[u8; 16], decrypt: bool, mac_bytes: u8, aad: &[u8],
         aad_bits: usize, data: &[u8], bits: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut zuc = Zuc::zuc256_3gpp(key, iv)?;
    let block = |zuc: &mut Zuc| -> [u8; 16] {
        let mut out = [0u8; 16];
        zuc.apply_keystream(&mut out);
        out
    };
    let hqp = (mac_bytes > 0).then(|| (block(&mut zuc), block(&mut zuc), block(&mut zuc)));
    let mut out = data.to_vec();
    zuc.apply_keystream(&mut out);
    clear_tail(&mut out, bits);
    let mut mac = Vec::new();
    if let Some((h, q, p)) = hqp {
        let mut a = [0u8; 16];
        mac5g_update(&h, &mut a, aad, aad_bits);
        mac5g_update(&h, &mut a, if decrypt { data } else { &out }, bits);
        let mut lengths = [0u8; 16];
        lengths[..4].copy_from_slice(&(bits as u32).to_le_bytes());
        lengths[8..12].copy_from_slice(&(aad_bits as u32).to_le_bytes());
        for (x, y) in a.iter_mut().zip(lengths) {
            *x ^= y;
        }
        a = pdot(&a, &q);
        mac = a.iter().zip(p).take(usize::from(mac_bytes)).map(|(x, y)| x ^ y).collect();
    }
    Ok((out, mac))
}

/// The 32 byte key a 256-NxA6 algorithm runs under - a 16 byte one
/// zero-extended (TS 35.246 section 4.5) - and whether it was 16.
fn key_5g(key: &[u8], what: &str) -> Result<([u8; 32], bool), String> {
    let mut full = [0u8; 32];
    match key.len() {
        32 | 16 => {
            full[..key.len()].copy_from_slice(key);
            Ok((full, key.len() == 16))
        }
        n => Err(format!("A {what} key is 32 bytes, or 16 to be zero-extended, not {n}.")),
    }
}

/// EXTRA_IV: six bytes, or none for six zeros.
fn extra_iv_5g(extra_iv: &[u8]) -> Result<[u8; 6], String> {
    match extra_iv.len() {
        0 => Ok([0; 6]),
        6 => Ok(extra_iv.try_into().unwrap()),
        n => Err(format!("EXTRA_IV is six bytes, or none for zeros, not {n}.")),
    }
}

/// A length the algorithms carry in 32 bits, of `data`'s bytes.
fn bits_5g(data: &[u8], bits: u64, what: &str) -> Result<usize, String> {
    if bits > u64::from(u32::MAX) {
        return Err(format!("A {what} length is at most 2^32 - 1 bits, not {bits}."));
    }
    check_bits(data, bits)
}

fn mac_bytes_5g(mac_bytes: u8) -> Result<(), String> {
    if !(4..=16).contains(&mac_bytes) {
        return Err(format!("MAC_BYTES is 4 to 16, not {mac_bytes}."));
    }
    Ok(())
}

/// 256-NEA6: the first `bits` bits of `data` encrypted or decrypted under
/// a 32 byte key (or 16, zero-extended), COUNT, BEARER, DIRECTION and an
/// EXTRA_IV of six bytes or none.
///
/// # Errors
/// A key of another length, a BEARER above 31 or a DIRECTION above 1, an
/// EXTRA_IV of another length, more than 2^32 - 1 bits, or `data` not
/// `ceil(bits / 8)` bytes.
pub fn nea6(key: &[u8], count: u32, bearer: u8, direction: u8, extra_iv: &[u8], data: &[u8],
            bits: u64) -> Result<Vec<u8>, String> {
    let (key, short) = key_5g(key, "256-NEA6")?;
    check_bearer(bearer, direction)?;
    let extra = extra_iv_5g(extra_iv)?;
    let bits = bits_5g(data, bits, "256-NEA6")?;
    let iv = make_5g_iv(count, bearer, direction, &extra, 0, false, short);
    Ok(aead1(&key, &iv, false, 0, &[], 0, data, bits)?.0)
}

/// 256-NIA6: the MAC of `mac_bytes` bytes, 4 to 16, of the first `bits`
/// bits of `data`, under the inputs `nea6` takes.
///
/// # Errors
/// As `nea6`, and a MAC length outside 4 to 16.
#[allow(clippy::too_many_arguments)]
pub fn nia6(key: &[u8], count: u32, bearer: u8, direction: u8, extra_iv: &[u8], data: &[u8],
            bits: u64, mac_bytes: u8) -> Result<Vec<u8>, String> {
    let (key, short) = key_5g(key, "256-NIA6")?;
    check_bearer(bearer, direction)?;
    let extra = extra_iv_5g(extra_iv)?;
    let bits = bits_5g(data, bits, "256-NIA6")?;
    mac_bytes_5g(mac_bytes)?;
    let iv = make_5g_iv(count, bearer, direction, &extra, mac_bytes, false, short);
    Ok(aead1(&key, &iv, false, mac_bytes, data, bits, &[], 0)?.1)
}

/// 256-NCA6 encryption: the first `bits` bits of `data` encrypted, and the
/// MAC of `mac_bytes` bytes, 4 to 16, over the first `aad_bits` bits of
/// `aad` and the ciphertext.
///
/// # Errors
/// As `nia6`, for either length.
#[allow(clippy::too_many_arguments)]
pub fn nca6_encrypt(key: &[u8], count: u32, bearer: u8, direction: u8, extra_iv: &[u8],
                    aad: &[u8], aad_bits: u64, data: &[u8], bits: u64, mac_bytes: u8)
                    -> Result<(Vec<u8>, Vec<u8>), String> {
    let (key, short) = key_5g(key, "256-NCA6")?;
    check_bearer(bearer, direction)?;
    let extra = extra_iv_5g(extra_iv)?;
    let aad_bits = bits_5g(aad, aad_bits, "256-NCA6 AAD")?;
    let bits = bits_5g(data, bits, "256-NCA6")?;
    mac_bytes_5g(mac_bytes)?;
    let iv = make_5g_iv(count, bearer, direction, &extra, mac_bytes, true, short);
    aead1(&key, &iv, false, mac_bytes, aad, aad_bits, data, bits)
}

/// 256-NCA6 decryption: the first `bits` bits of `data` decrypted, if
/// `mac` - its length the MAC_BYTES the sender used - is the MAC over the
/// first `aad_bits` bits of `aad` and the ciphertext.
///
/// # Errors
/// As `nca6_encrypt`, and a MAC that does not match; nothing is returned
/// then.
#[allow(clippy::too_many_arguments)]
pub fn nca6_decrypt(key: &[u8], count: u32, bearer: u8, direction: u8, extra_iv: &[u8],
                    aad: &[u8], aad_bits: u64, data: &[u8], bits: u64, mac: &[u8])
                    -> Result<Vec<u8>, String> {
    let (key, short) = key_5g(key, "256-NCA6")?;
    check_bearer(bearer, direction)?;
    let extra = extra_iv_5g(extra_iv)?;
    let aad_bits = bits_5g(aad, aad_bits, "256-NCA6 AAD")?;
    let bits = bits_5g(data, bits, "256-NCA6")?;
    let mac_bytes = u8::try_from(mac.len()).unwrap_or(0);
    mac_bytes_5g(mac_bytes)?;
    let iv = make_5g_iv(count, bearer, direction, &extra, mac_bytes, true, short);
    let (plaintext, expected) = aead1(&key, &iv, true, mac_bytes, aad, aad_bits, data, bits)?;
    if expected.iter().zip(mac).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
        return Err("The 256-NCA6 MAC does not match.".to_string());
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The sets under `heading` (`=== heading TEST #n ===`) in a TS 35.247
    /// or 35.248 text: each `NAME = value`, a braced value's tokens
    /// joined, whatever lines it spans.
    fn sets(text: &str, heading: &str) -> Vec<HashMap<String, String>> {
        let marker = format!("=== {heading} TEST #");
        text.split(marker.as_str()).skip(1).map(|set| {
            let set = &set[set.find('\n').unwrap()..];
            let set = &set[..set.find("===").unwrap_or(set.len())];
            let mut fields = HashMap::new();
            let mut rest = set;
            while let Some(eq) = rest.find(" = ") {
                let name = rest[..eq].rsplit('\n').next().unwrap().trim().to_string();
                let after = &rest[eq + 3..];
                let (value, used) = if let Some(braced) = after.strip_prefix('{') {
                    let close = braced.find('}').unwrap();
                    (braced[..close].split_whitespace().collect::<String>(), close + 2)
                } else {
                    let end = after.find('\n').unwrap_or(after.len());
                    (after[..end].trim().to_string(), end)
                };
                fields.insert(name, value);
                rest = &after[used..];
            }
            fields
        }).collect()
    }

    fn bytes(fields: &HashMap<String, String>, name: &str) -> Vec<u8> {
        let hex = &fields[name];
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn number(fields: &HashMap<String, String>, name: &str) -> u64 {
        let value = &fields[name];
        match value.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).unwrap(),
            None => value.parse().unwrap(),
        }
    }

    /// TS 35.247 section 5.2's six POLYVAL dot products.
    #[test]
    fn test_polyval_dot() {
        let text = include_str!("../../rfcs/35247-k00.txt");
        let tests = sets(text, "POLYVAL");
        assert_eq!(tests.len(), 6);
        for t in &tests {
            let a: [u8; 16] = bytes(t, "A").try_into().unwrap();
            let b: [u8; 16] = bytes(t, "B").try_into().unwrap();
            assert_eq!(pdot(&a, &b).to_vec(), bytes(t, "A*B"));
            assert_eq!(pdot(&b, &a).to_vec(), bytes(t, "A*B"));
        }
    }

    /// The inputs every 35.248 set has.
    struct Inputs {
        key: Vec<u8>,
        count: u32,
        bearer: u8,
        direction: u8,
        extra: Vec<u8>,
    }

    fn inputs(t: &HashMap<String, String>, key: &str, count: &str) -> Inputs {
        Inputs { key: bytes(t, key), count: number(t, count) as u32,
                 bearer: number(t, "BEARER") as u8, direction: number(t, "DIRECTION") as u8,
                 extra: bytes(t, "EXTRA_IV") }
    }

    /// The IV `make_5g_iv` builds for a set, against its IV12, and the
    /// key it runs under; and H, Q and P against the set's when it has
    /// them.
    fn check_intermediates(t: &HashMap<String, String>, i: &Inputs, mac_bytes: u8,
                           combined: bool) {
        let (full, short) = key_5g(&i.key, "test").unwrap();
        let iv = make_5g_iv(i.count, i.bearer, i.direction, &extra_iv_5g(&i.extra).unwrap(),
                            mac_bytes, combined, short);
        assert_eq!(iv[..12].to_vec(), bytes(t, "IV12"));
        assert_eq!(iv[12..], [0; 4]);
        if t.contains_key("H") {
            let mut zuc = Zuc::zuc256_3gpp(&full, &iv).unwrap();
            for name in ["H", "Q", "P"] {
                let mut block = [0u8; 16];
                zuc.apply_keystream(&mut block);
                assert_eq!(block.to_vec(), bytes(t, name), "{name}");
            }
        }
    }

    /// TS 35.248's twelve conformance sets of each algorithm, with their
    /// intermediates: the IV, H, Q and P. NCA6's ciphertexts decrypt back
    /// under their MACs, and with a MAC bit changed do not.
    #[test]
    fn test_conformance_sets() {
        let text = include_str!("../../rfcs/35248-k00.txt");
        let nea = sets(text, "NEA6_256");
        assert_eq!(nea.len(), 12);
        for t in &nea {
            let i = inputs(t, "CK", "COUNT_C");
            check_intermediates(t, &i, 0, false);
            let Inputs { key, count, bearer, direction, extra } = i;
            let got = nea6(&key, count, bearer, direction, &extra, &bytes(t, "IBS"),
                           number(t, "LENGTH")).unwrap();
            assert_eq!(got, bytes(t, "OBS"));
        }
        let nia = sets(text, "NIA6_256");
        assert_eq!(nia.len(), 12);
        for t in &nia {
            let i = inputs(t, "IK", "COUNT_I");
            let mac_bytes = number(t, "MAC_BYTES") as u8;
            check_intermediates(t, &i, mac_bytes, false);
            let Inputs { key, count, bearer, direction, extra } = i;
            let got = nia6(&key, count, bearer, direction, &extra, &bytes(t, "MESSAGE"),
                           number(t, "LENGTH"), mac_bytes).unwrap();
            assert_eq!(got, bytes(t, "MAC_I"));
        }
        let nca = sets(text, "NCA6_256");
        assert_eq!(nca.len(), 12);
        for t in &nca {
            let i = inputs(t, "KEY", "COUNT");
            let mac_bytes = number(t, "MAC_BYTES") as u8;
            check_intermediates(t, &i, mac_bytes, true);
            let Inputs { key, count, bearer, direction, extra } = i;
            let (aad, aad_bits) = (bytes(t, "AAD"), number(t, "AAD_LENGTH"));
            let bits = number(t, "S_LENGTH");
            let (obs, mac) = nca6_encrypt(&key, count, bearer, direction, &extra, &aad, aad_bits,
                                          &bytes(t, "IBS"), bits, mac_bytes).unwrap();
            assert_eq!(obs, bytes(t, "OBS"));
            assert_eq!(mac, bytes(t, "MAC"));
            let back = nca6_decrypt(&key, count, bearer, direction, &extra, &aad, aad_bits, &obs,
                                    bits, &mac).unwrap();
            let mut ibs = bytes(t, "IBS");
            clear_tail(&mut ibs, bits as usize);
            assert_eq!(back, ibs);
            let mut bent = mac.clone();
            bent[mac.len() - 1] ^= 1;
            assert!(nca6_decrypt(&key, count, bearer, direction, &extra, &aad, aad_bits, &obs,
                                 bits, &bent).is_err());
        }
    }
}
