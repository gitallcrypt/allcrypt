//! AES and GHASH on the x86-64 instructions made for them: AES-NI
//! (`aesenc`, `aesdec`, `aesimc`) and PCLMULQDQ. Compiled only with the
//! `aes-ni` feature, and used only when the processor has them.
//!
//! ## Why this is behind a feature
//!
//! Everything else in the library is portable Rust with no `unsafe` in
//! its cryptography. Reaching these instructions takes `unsafe`: Rust
//! makes a call into a `#[target_feature]` function unsafe from any
//! caller that does not itself carry the feature, even after a run-time
//! check and even with the feature enabled for the whole build. So the
//! choice is the caller's. Without the feature, AES is the bitsliced
//! and table code in `aes.rs`; with it, on a processor that has the
//! instructions, it is this module.
//!
//! ## What the `unsafe` is
//!
//! The call sites in `aes.rs` and `ghash.rs`, each reached only after
//! `available()` has returned true, which `is_x86_feature_detected!`
//! decides once per process; at each, the only thing the `unsafe`
//! asserts is "this CPU has AES-NI, PCLMULQDQ, SSE2 and SSSE3". Inside,
//! one more pair: `load` and `store_into` move a block between a
//! `[u8; 16]` and a register with the unaligned `_mm_loadu_si128` and
//! `_mm_storeu_si128`, whose pointer comes from a reference to exactly
//! those sixteen bytes. Nothing else here touches a pointer.
//!
//! ## Why one would want it
//!
//! Speed: twenty to thirty times the portable code in ECB, CTR, XTS,
//! GCM and CBC decryption, the modes with blocks to run side by side,
//! and four times in CBC encryption, which has one at a time.
//!
//! And timing. The instructions take the same time whatever the key and
//! the data, so the modes that only ever have one block to encrypt - CBC
//! encryption, CFB, OFB, CMAC, CCM's MAC - become constant time too. In
//! the portable build those go through lookup tables, which leak through
//! the cache (`docs/pitfalls.md`, section 1).
//!
//! The round keys come from `aes.rs`'s own key schedule, so AES-NI's
//! `aeskeygenassist` is not used: one key schedule, one place to be
//! wrong. Decryption keys are `aesimc` of the encryption keys, which is
//! the equivalent inverse cipher `aes.rs`'s table path also uses.

use core::arch::x86_64::*;
use std::sync::OnceLock;

/// Whether this processor has AES-NI, PCLMULQDQ, SSE2 and SSSE3 (for
/// GHASH's byte shuffle). Checked once; every processor with the first
/// two has the others.
pub(crate) fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("sse2")
            && std::is_x86_feature_detected!("ssse3")
    })
}

/// Sixteen bytes into a register, one unaligned load.
#[inline]
#[target_feature(enable = "sse2")]
fn load(bytes: &[u8; 16]) -> __m128i {
    // SAFETY: the reference covers exactly the sixteen bytes read, and
    // `loadu` has no alignment requirement.
    unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
}

/// A register to sixteen bytes, one unaligned store.
#[inline]
#[target_feature(enable = "sse2")]
fn store_into(value: __m128i, bytes: &mut [u8; 16]) {
    // SAFETY: as in `load`, for the sixteen bytes written.
    unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), value) }
}

#[inline]
#[target_feature(enable = "sse2")]
fn store(value: __m128i) -> [u8; 16] {
    let mut out = [0u8; 16];
    store_into(value, &mut out);
    out
}

/// Round keys for both directions, as bytes.
pub(crate) struct Keys {
    rounds: usize,
    encrypt: [[u8; 16]; 15],
    /// The equivalent inverse cipher's keys, in the order they are used.
    decrypt: [[u8; 16]; 15],
}

/// From the FIPS 197 schedule as little-endian words.
///
/// # Safety
/// The processor must have AES-NI and SSE2 (`available()`).
#[target_feature(enable = "aes,sse2")]
pub(crate) unsafe fn keys(words: &[u32; 60], rounds: usize) -> Keys {
    let mut encrypt = [[0u8; 16]; 15];
    for (r, key) in encrypt.iter_mut().enumerate().take(rounds + 1) {
        for w in 0..4 {
            key[4 * w..4 * w + 4].copy_from_slice(&words[4 * r + w].to_le_bytes());
        }
    }
    let mut decrypt = [[0u8; 16]; 15];
    decrypt[0] = encrypt[rounds];
    for r in 1..rounds {
        decrypt[r] = store(_mm_aesimc_si128(load(&encrypt[rounds - r])));
    }
    decrypt[rounds] = encrypt[0];
    Keys { rounds, encrypt, decrypt }
}

/// Eight blocks at a time, which keeps the AES unit's pipeline full, then
/// one at a time. `blocks.len()` is a multiple of 16.
macro_rules! blocks {
    ($name:ident, $round:ident, $last:ident, $which:ident) => {
        /// # Safety
        /// The processor must have AES-NI and SSE2 (`available()`).
        #[target_feature(enable = "aes,sse2")]
        pub(crate) unsafe fn $name(keys: &Keys, blocks: &mut [u8]) {
            let n = keys.rounds;
            let mut rk = [_mm_setzero_si128(); 15];
            for (slot, key) in rk.iter_mut().zip(keys.$which.iter()).take(n + 1) {
                *slot = load(key);
            }
            let mut eights = blocks.chunks_exact_mut(128);
            for chunk in &mut eights {
                let mut s = [_mm_setzero_si128(); 8];
                for (i, state) in s.iter_mut().enumerate() {
                    let block: &[u8; 16] = chunk[16 * i..16 * i + 16].try_into().unwrap();
                    *state = _mm_xor_si128(load(block), rk[0]);
                }
                for key in &rk[1..n] {
                    for state in s.iter_mut() {
                        *state = $round(*state, *key);
                    }
                }
                for (i, state) in s.iter().enumerate() {
                    let block: &mut [u8; 16] =
                        (&mut chunk[16 * i..16 * i + 16]).try_into().unwrap();
                    store_into($last(*state, rk[n]), block);
                }
            }
            for block in eights.into_remainder().chunks_exact_mut(16) {
                let block: &mut [u8; 16] = block.try_into().unwrap();
                let mut state = _mm_xor_si128(load(block), rk[0]);
                for key in &rk[1..n] {
                    state = $round(state, *key);
                }
                store_into($last(state, rk[n]), block);
            }
        }
    };
}

blocks!(encrypt, _mm_aesenc_si128, _mm_aesenclast_si128, encrypt);
blocks!(decrypt, _mm_aesdec_si128, _mm_aesdeclast_si128, decrypt);

/// One block, for the chained modes, which call this once per block and
/// so pay for any setup each time: no table of loaded keys, each round
/// key read where it is used.
macro_rules! one_block {
    ($name:ident, $round:ident, $last:ident, $which:ident) => {
        /// # Safety
        /// The processor must have AES-NI and SSE2 (`available()`).
        #[target_feature(enable = "aes,sse2")]
        pub(crate) unsafe fn $name(keys: &Keys, block: &mut [u8; 16]) {
            let n = keys.rounds;
            let mut state = _mm_xor_si128(load(block), load(&keys.$which[0]));
            for key in &keys.$which[1..n] {
                state = $round(state, load(key));
            }
            store_into($last(state, load(&keys.$which[n])), block);
        }
    };
}

/// Counter mode in one pass: counter blocks made in registers, eight
/// encrypted side by side, the keystream XORed straight into `data` (a
/// whole number of blocks). `counter32` increments only the last four
/// bytes (GCM), otherwise the whole block, both big endian; `counter`
/// is left at the next block unused.
///
/// # Safety
/// The processor must have AES-NI, SSE2 and SSSE3 (`available()`).
#[target_feature(enable = "aes,sse2,ssse3")]
pub(crate) unsafe fn ctr_xor(keys: &Keys, counter: &mut [u8; 16], data: &mut [u8],
                             counter32: bool) {
    let n = keys.rounds;
    let mut rk = [_mm_setzero_si128(); 15];
    for (slot, key) in rk.iter_mut().zip(keys.encrypt.iter()).take(n + 1) {
        *slot = load(key);
    }
    let reverse = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    let mut value = u128::from_be_bytes(*counter);
    let mut next = || {
        let block = _mm_shuffle_epi8(
            _mm_set_epi64x((value >> 64) as i64, value as i64), reverse);
        value = if counter32 {
            (value & !0xFFFF_FFFF) | u128::from((value as u32).wrapping_add(1))
        } else {
            value.wrapping_add(1)
        };
        block
    };
    let mut eights = data.chunks_exact_mut(128);
    for chunk in &mut eights {
        let mut s = [_mm_setzero_si128(); 8];
        for state in s.iter_mut() {
            *state = _mm_xor_si128(next(), rk[0]);
        }
        for key in &rk[1..n] {
            for state in s.iter_mut() {
                *state = _mm_aesenc_si128(*state, *key);
            }
        }
        for (i, state) in s.iter().enumerate() {
            let block: &mut [u8; 16] = (&mut chunk[16 * i..16 * i + 16]).try_into().unwrap();
            store_into(_mm_xor_si128(load(block), _mm_aesenclast_si128(*state, rk[n])), block);
        }
    }
    for block in eights.into_remainder().chunks_exact_mut(16) {
        let block: &mut [u8; 16] = block.try_into().unwrap();
        let mut state = _mm_xor_si128(next(), rk[0]);
        for key in &rk[1..n] {
            state = _mm_aesenc_si128(state, *key);
        }
        store_into(_mm_xor_si128(load(block), _mm_aesenclast_si128(state, rk[n])), block);
    }
    *counter = value.to_be_bytes();
}

/// XTS over whole blocks, eight at a time: the tweak doubled in a
/// general register (a little-endian integer, `0x87` folded in by mask
/// when the top bit falls off) and XORed in registers on the way in and
/// out, so no block is written between the passes. `tweak` is left at
/// the next block's.
macro_rules! xts {
    ($name:ident, $round:ident, $last:ident, $which:ident) => {
        /// # Safety
        /// The processor must have AES-NI and SSE2 (`available()`).
        #[target_feature(enable = "aes,sse2")]
        pub(crate) unsafe fn $name(keys: &Keys, tweak: &mut [u8; 16], data: &mut [u8]) {
            let n = keys.rounds;
            let mut rk = [_mm_setzero_si128(); 15];
            for (slot, key) in rk.iter_mut().zip(keys.$which.iter()).take(n + 1) {
                *slot = load(key);
            }
            let mut value = u128::from_le_bytes(*tweak);
            let mut next = || {
                let mask = _mm_set_epi64x((value >> 64) as i64, value as i64);
                value = (value << 1) ^ (0x87 & 0u128.wrapping_sub(value >> 127));
                mask
            };
            let mut eights = data.chunks_exact_mut(128);
            for chunk in &mut eights {
                let mut masks = [_mm_setzero_si128(); 8];
                let mut s = [_mm_setzero_si128(); 8];
                for i in 0..8 {
                    masks[i] = next();
                    let block: &[u8; 16] = chunk[16 * i..16 * i + 16].try_into().unwrap();
                    s[i] = _mm_xor_si128(_mm_xor_si128(load(block), masks[i]), rk[0]);
                }
                for key in &rk[1..n] {
                    for state in s.iter_mut() {
                        *state = $round(*state, *key);
                    }
                }
                for i in 0..8 {
                    let block: &mut [u8; 16] =
                        (&mut chunk[16 * i..16 * i + 16]).try_into().unwrap();
                    store_into(_mm_xor_si128($last(s[i], rk[n]), masks[i]), block);
                }
            }
            for block in eights.into_remainder().chunks_exact_mut(16) {
                let block: &mut [u8; 16] = block.try_into().unwrap();
                let mask = next();
                let mut state = _mm_xor_si128(_mm_xor_si128(load(block), mask), rk[0]);
                for key in &rk[1..n] {
                    state = $round(state, *key);
                }
                store_into(_mm_xor_si128($last(state, rk[n]), mask), block);
            }
            *tweak = value.to_le_bytes();
        }
    };
}

xts!(xts_encrypt, _mm_aesenc_si128, _mm_aesenclast_si128, encrypt);
xts!(xts_decrypt, _mm_aesdec_si128, _mm_aesdeclast_si128, decrypt);

one_block!(encrypt_one, _mm_aesenc_si128, _mm_aesenclast_si128, encrypt);
one_block!(decrypt_one, _mm_aesdec_si128, _mm_aesdeclast_si128, decrypt);

/// GHASH's field product with `pclmulqdq`. Operands and result are a
/// block's two big-endian halves, `(bytes 0..8, bytes 8..16)`, which as a
/// 128 bit integer is the block byte-reversed - the form the instruction
/// wants for GCM's reflected bit order.
///
/// Four carry-less products (no Karatsuba), the 256 bit result shifted
/// left by one for the reflection, then reduced modulo
/// `x^128 + x^7 + x^2 + x + 1` in two folding steps: Gueron and
/// Kounavis, "Intel Carry-Less Multiplication Instruction and its Usage
/// for Computing the GCM Mode", algorithms 4 and 5.
///
/// # Safety
/// The processor must have PCLMULQDQ and SSE2 (`available()`).
#[target_feature(enable = "pclmulqdq,sse2")]
pub(crate) unsafe fn gf_mul(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    let a = _mm_set_epi64x(a.0 as i64, a.1 as i64);
    let b = _mm_set_epi64x(b.0 as i64, b.1 as i64);

    let low = _mm_clmulepi64_si128(a, b, 0x00);
    let middle = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x10),
                               _mm_clmulepi64_si128(a, b, 0x01));
    let high = _mm_clmulepi64_si128(a, b, 0x11);
    let result = reduce(low, middle, high);
    let lo = _mm_cvtsi128_si64(result) as u64;
    let hi = _mm_cvtsi128_si64(_mm_unpackhi_epi64(result, result)) as u64;
    (hi, lo)
}

/// The 256 bit carry-less product `high * 2^128 + middle * 2^64 + low`,
/// in GCM's reflected order, reduced to a field element.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
fn reduce(low: __m128i, middle: __m128i, high: __m128i) -> __m128i {
    let mut low = _mm_xor_si128(low, _mm_slli_si128(middle, 8));
    let mut high = _mm_xor_si128(high, _mm_srli_si128(middle, 8));

    // The product one bit to the left, across the two halves.
    let low_carry = _mm_srli_epi32(low, 31);
    let high_carry = _mm_srli_epi32(high, 31);
    low = _mm_slli_epi32(low, 1);
    high = _mm_slli_epi32(high, 1);
    let across = _mm_srli_si128(low_carry, 12);
    high = _mm_or_si128(_mm_or_si128(high, _mm_slli_si128(high_carry, 4)), across);
    low = _mm_or_si128(low, _mm_slli_si128(low_carry, 4));

    // Reduction: fold the low half into the high one.
    let fold = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi32(low, 31), _mm_slli_epi32(low, 30)),
                             _mm_slli_epi32(low, 25));
    let fold_out = _mm_srli_si128(fold, 4);
    low = _mm_xor_si128(low, _mm_slli_si128(fold, 12));
    let mut second = _mm_xor_si128(_mm_xor_si128(_mm_srli_epi32(low, 1), _mm_srli_epi32(low, 2)),
                                   _mm_srli_epi32(low, 7));
    second = _mm_xor_si128(second, fold_out);
    low = _mm_xor_si128(low, second);
    _mm_xor_si128(high, low)
}

/// GHASH over whole groups of eight blocks: `y` and `powers` (`H^1` ..
/// `H^8`) as `(hi, lo)` halves, `data` a multiple of 128 bytes. Each
/// group is `(y ^ X1) H^8 ^ X2 H^7 ^ .. ^ X8 H`: eight Karatsuba
/// products, three multiplications each, summed **unreduced** - the
/// reflection shift and the reduction are linear, so one of each per
/// group gives the sum of the eight reduced products.
///
/// # Safety
/// The processor must have PCLMULQDQ, SSE2 and SSSE3 (`available()`).
#[target_feature(enable = "pclmulqdq,sse2,ssse3")]
pub(crate) unsafe fn ghash_eights(powers: &[(u64, u64); 8], y: (u64, u64), data: &[u8])
                                  -> (u64, u64) {
    // Byte reversal: the block as a 128 bit integer is `gf_mul`'s form.
    let reverse = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    let mut h = [_mm_setzero_si128(); 8];
    let mut h_folded = [_mm_setzero_si128(); 8];
    for i in 0..8 {
        // h[i] multiplies the i-th block of a group: H^(8 - i).
        let (hi, lo) = powers[7 - i];
        h[i] = _mm_set_epi64x(hi as i64, lo as i64);
        h_folded[i] = _mm_set_epi64x(0, (hi ^ lo) as i64);
    }
    let mut acc = _mm_set_epi64x(y.0 as i64, y.1 as i64);
    for group in data.chunks_exact(128) {
        let mut low = _mm_setzero_si128();
        let mut middle = _mm_setzero_si128();
        let mut high = _mm_setzero_si128();
        for i in 0..8 {
            let bytes: &[u8; 16] = group[16 * i..16 * i + 16].try_into().unwrap();
            let mut x = _mm_shuffle_epi8(load(bytes), reverse);
            if i == 0 {
                x = _mm_xor_si128(x, acc);
            }
            low = _mm_xor_si128(low, _mm_clmulepi64_si128(x, h[i], 0x00));
            high = _mm_xor_si128(high, _mm_clmulepi64_si128(x, h[i], 0x11));
            let x_folded = _mm_xor_si128(x, _mm_srli_si128(x, 8));
            middle = _mm_xor_si128(middle, _mm_clmulepi64_si128(x_folded, h_folded[i], 0x00));
        }
        // Karatsuba's middle term: (x0 ^ x1)(h0 ^ h1) ^ x0 h0 ^ x1 h1.
        middle = _mm_xor_si128(middle, _mm_xor_si128(low, high));
        acc = reduce(low, middle, high);
    }
    let lo = _mm_cvtsi128_si64(acc) as u64;
    let hi = _mm_cvtsi128_si64(_mm_unpackhi_epi64(acc, acc)) as u64;
    (hi, lo)
}
