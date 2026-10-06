//! SHA-1 and SHA-256 (and SHA-224, which shares its compression
//! function) on the x86-64 SHA extensions (`sha1rnds4`,
//! `sha1nexte`, `sha1msg1`, `sha1msg2`, `sha256rnds2`, `sha256msg1`,
//! `sha256msg2`). Compiled only with the `sha-ni` feature, and used only
//! when the processor has them.
//!
//! ## Why this is behind a feature
//!
//! For the same reason as `aes-ni` (`block_ciphers/aes_ni.rs`): reaching
//! the instructions takes `unsafe`, and everything else in the library's
//! cryptography is portable Rust without it. Without the feature, SHA-1
//! and SHA-256 are the portable compression functions in `sha1.rs` and
//! `sha2.rs`; with it, on a processor that has the extensions, they are
//! this module. SHA-0 always takes the portable path: `sha1msg2` applies
//! SHA-1's one-bit rotation, which is the only thing SHA-0 lacks.
//!
//! ## What the `unsafe` is
//!
//! `sha1` and `sha256` below are safe functions that check `available()`,
//! which `is_x86_feature_detected!` decides once per process, and return
//! `false` without touching anything when the processor lacks the
//! extensions. Past that check the only assertion an `unsafe` makes is
//! "this CPU has SHA, SSE2, SSSE3 and SSE4.1", plus the unaligned
//! loads in `load`, whose pointer comes from a reference to exactly the
//! sixteen bytes read. The state goes in and out through `_mm_set_epi32`
//! and `_mm_extract_epi32`, which take no pointer.
//!
//! ## Why one would want it
//!
//! Speed: the extensions run SHA-256 several times faster than the best
//! scalar code, which is why OpenSSL on a processor that has them is out
//! of reach of any portable implementation. The instructions are also
//! data-independent in timing, as the portable code already is.

use core::arch::x86_64::*;
use std::sync::OnceLock;

/// Whether this processor has the SHA extensions, and SSE2, SSSE3 (the
/// byte shuffle) and SSE4.1 (`blend` and `extract`). Checked once; every
/// processor with the first has the others.
pub(crate) fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        std::is_x86_feature_detected!("sha")
            && std::is_x86_feature_detected!("sse2")
            && std::is_x86_feature_detected!("ssse3")
            && std::is_x86_feature_detected!("sse4.1")
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

/// The four sixteen-byte pieces of a block.
fn quarters(block: &[u8; 64]) -> [&[u8; 16]; 4] {
    let (q0, rest) = block.split_first_chunk::<16>().expect("64 bytes");
    let (q1, rest) = rest.split_first_chunk::<16>().expect("48 bytes");
    let (q2, q3) = rest.split_first_chunk::<16>().expect("32 bytes");
    [q0, q1, q2, q3.try_into().expect("16 bytes")]
}

/// Four words into a register, the first in the bottom lane.
#[inline]
#[target_feature(enable = "sse2")]
fn lanes(w0: u32, w1: u32, w2: u32, w3: u32) -> __m128i {
    _mm_set_epi32(w3 as i32, w2 as i32, w1 as i32, w0 as i32)
}

/// SHA-1 over `blocks`, a whole number of 64-byte blocks, on the
/// extensions - or `false`, with `state` untouched, on a processor
/// without them. The state stays in registers from the first block to
/// the last.
pub(crate) fn sha1(state: &mut [u32; 5], blocks: &[u8]) -> bool {
    assert!(blocks.len().is_multiple_of(64), "a run of {} bytes is not whole blocks", blocks.len());
    if !available() {
        return false;
    }
    // SAFETY: `available()` has confirmed SHA, SSE2, SSSE3 and SSE4.1.
    unsafe { sha1_blocks(state, blocks) };
    true
}

/// SHA-224/256 over `blocks`, as `sha1`.
pub(crate) fn sha256(state: &mut [u32; 8], blocks: &[u8]) -> bool {
    assert!(blocks.len().is_multiple_of(64), "a run of {} bytes is not whole blocks", blocks.len());
    if !available() {
        return false;
    }
    // SAFETY: as in `sha1`.
    unsafe { sha256_blocks(state, blocks) };
    true
}

/// SHA-1. `sha1rnds4` runs four rounds on `abcd` with `a` in the top
/// lane, taking `e` plus the four message words in its second operand;
/// `sha1nexte` derives the next `e` from the `a` four rounds back and
/// adds the next message words; `sha1msg1` and `sha1msg2` are the
/// schedule. The constant (0 to 3) picks the round function and `K` for
/// rounds 0-19, 20-39, 40-59 and 60-79.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn sha1_blocks(state: &mut [u32; 5], blocks: &[u8]) {
    // Every byte reversed: a big-endian word lands in a lane with the
    // block's first word in the top one, which is where `sha1rnds4`
    // expects W[0].
    let mask = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0A0B_0C0D_0E0F);
    let mut abcd = _mm_set_epi32(state[0] as i32, state[1] as i32, state[2] as i32,
                                 state[3] as i32);
    let mut e = _mm_set_epi32(state[4] as i32, 0, 0, 0);
    for block in blocks.chunks_exact(64) {
        (abcd, e) = sha1_block(abcd, e, block.try_into().expect("64 bytes"), mask);
    }
    state[0] = _mm_extract_epi32::<3>(abcd) as u32;
    state[1] = _mm_extract_epi32::<2>(abcd) as u32;
    state[2] = _mm_extract_epi32::<1>(abcd) as u32;
    state[3] = _mm_extract_epi32::<0>(abcd) as u32;
    state[4] = _mm_extract_epi32::<3>(e) as u32;
}

/// One block: the state in, the state out, both in register form.
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn sha1_block(abcd: __m128i, e: __m128i, block: &[u8; 64], mask: __m128i)
              -> (__m128i, __m128i) {
    let [q0, q1, q2, q3] = quarters(block);
    let mut w0 = _mm_shuffle_epi8(load(q0), mask);
    let mut w1 = _mm_shuffle_epi8(load(q1), mask);
    let mut w2 = _mm_shuffle_epi8(load(q2), mask);
    let mut w3 = _mm_shuffle_epi8(load(q3), mask);
    let mut w4;

    macro_rules! rounds4 {
        ($h0:ident, $h1:ident, $w:expr, $f:literal) => {
            _mm_sha1rnds4_epu32::<$f>($h0, _mm_sha1nexte_epu32($h1, $w))
        };
    }
    macro_rules! schedule {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
            _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32($v0, $v1), $v2), $v3)
        };
    }
    macro_rules! schedule_rounds4 {
        ($h0:ident, $h1:ident, $w0:ident, $w1:ident, $w2:ident, $w3:ident, $w4:ident,
         $f:literal) => {
            $w4 = schedule!($w0, $w1, $w2, $w3);
            $h1 = rounds4!($h0, $h1, $w4, $f);
        };
    }

    // Rounds 0-19. The first four take `e + W[0..4]` directly; after
    // that `sha1nexte` produces each next `e`.
    let mut h0 = abcd;
    let mut h1 = _mm_add_epi32(e, w0);
    h1 = _mm_sha1rnds4_epu32::<0>(h0, h1);
    h0 = rounds4!(h1, h0, w1, 0);
    h1 = rounds4!(h0, h1, w2, 0);
    h0 = rounds4!(h1, h0, w3, 0);
    schedule_rounds4!(h0, h1, w0, w1, w2, w3, w4, 0);
    // Rounds 20-39.
    schedule_rounds4!(h1, h0, w1, w2, w3, w4, w0, 1);
    schedule_rounds4!(h0, h1, w2, w3, w4, w0, w1, 1);
    schedule_rounds4!(h1, h0, w3, w4, w0, w1, w2, 1);
    schedule_rounds4!(h0, h1, w4, w0, w1, w2, w3, 1);
    schedule_rounds4!(h1, h0, w0, w1, w2, w3, w4, 1);
    // Rounds 40-59.
    schedule_rounds4!(h0, h1, w1, w2, w3, w4, w0, 2);
    schedule_rounds4!(h1, h0, w2, w3, w4, w0, w1, 2);
    schedule_rounds4!(h0, h1, w3, w4, w0, w1, w2, 2);
    schedule_rounds4!(h1, h0, w4, w0, w1, w2, w3, 2);
    schedule_rounds4!(h0, h1, w0, w1, w2, w3, w4, 2);
    // Rounds 60-79.
    schedule_rounds4!(h1, h0, w1, w2, w3, w4, w0, 3);
    schedule_rounds4!(h0, h1, w2, w3, w4, w0, w1, 3);
    schedule_rounds4!(h1, h0, w3, w4, w0, w1, w2, 3);
    schedule_rounds4!(h0, h1, w4, w0, w1, w2, w3, 3);
    schedule_rounds4!(h1, h0, w0, w1, w2, w3, w4, 3);

    // `h0` is the new abcd; `h1` the abcd before it, whose `a` rotated
    // is the last round's `e`.
    (_mm_add_epi32(abcd, h0), _mm_sha1nexte_epu32(h1, e))
}

/// SHA-256. `sha256rnds2` runs two rounds and wants the state split as
/// `abef` and `cdgh`, so the state is rearranged on the way in and back
/// on the way out; the message words plus `K` go in four at a time, the
/// upper two moved down for the second pair of rounds. `sha256msg1`
/// and `sha256msg2` are the schedule, with `W[i-7]` added in between.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn sha256_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    // Each word's bytes reversed in place: big-endian words, first word
    // in the bottom lane.
    let mask = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203);
    // The round constants four to a register, built once per run.
    let k = &super::sha2::K_32;
    let mut constants = [_mm_setzero_si128(); 16];
    for (i, lane) in constants.iter_mut().enumerate() {
        *lane = lanes(k[4 * i], k[4 * i + 1], k[4 * i + 2], k[4 * i + 3]);
    }

    let dcba = lanes(state[0], state[1], state[2], state[3]);
    let hgfe = lanes(state[4], state[5], state[6], state[7]);
    let cdab = _mm_shuffle_epi32::<0xB1>(dcba);
    let efgh = _mm_shuffle_epi32::<0x1B>(hgfe);
    let mut abef = _mm_alignr_epi8::<8>(cdab, efgh);
    let mut cdgh = _mm_blend_epi16::<0xF0>(efgh, cdab);
    for block in blocks.chunks_exact(64) {
        (abef, cdgh) = sha256_block(abef, cdgh, block.try_into().expect("64 bytes"), mask,
                                    &constants);
    }

    let feba = _mm_shuffle_epi32::<0x1B>(abef);
    let dchg = _mm_shuffle_epi32::<0xB1>(cdgh);
    let dcba = _mm_blend_epi16::<0xF0>(feba, dchg);
    let hgef = _mm_alignr_epi8::<8>(dchg, feba);
    state[0] = _mm_extract_epi32::<0>(dcba) as u32;
    state[1] = _mm_extract_epi32::<1>(dcba) as u32;
    state[2] = _mm_extract_epi32::<2>(dcba) as u32;
    state[3] = _mm_extract_epi32::<3>(dcba) as u32;
    state[4] = _mm_extract_epi32::<0>(hgef) as u32;
    state[5] = _mm_extract_epi32::<1>(hgef) as u32;
    state[6] = _mm_extract_epi32::<2>(hgef) as u32;
    state[7] = _mm_extract_epi32::<3>(hgef) as u32;
}

/// One block, the state in `sha256rnds2`'s `abef`/`cdgh` form.
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn sha256_block(mut abef: __m128i, mut cdgh: __m128i, block: &[u8; 64], mask: __m128i,
                constants: &[__m128i; 16]) -> (__m128i, __m128i) {
    let (abef_start, cdgh_start) = (abef, cdgh);
    let [q0, q1, q2, q3] = quarters(block);
    let mut w = [_mm_shuffle_epi8(load(q0), mask), _mm_shuffle_epi8(load(q1), mask),
                 _mm_shuffle_epi8(load(q2), mask), _mm_shuffle_epi8(load(q3), mask)];

    for (i, constant) in constants.iter().enumerate() {
        if i >= 4 {
            // w[i % 4] holds W[4i-16..4i-12]; the others follow in turn.
            let v0 = w[i % 4];
            let v1 = w[(i + 1) % 4];
            let v2 = w[(i + 2) % 4];
            let v3 = w[(i + 3) % 4];
            let t = _mm_add_epi32(_mm_sha256msg1_epu32(v0, v1), _mm_alignr_epi8::<4>(v3, v2));
            w[i % 4] = _mm_sha256msg2_epu32(t, v3);
        }
        let wk = _mm_add_epi32(w[i % 4], *constant);
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32::<0x0E>(wk));
    }

    (_mm_add_epi32(abef, abef_start), _mm_add_epi32(cdgh, cdgh_start))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes that are not a pattern a wrong lane order could agree with.
    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        (0..len).map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        }).collect()
    }

    /// The extensions against the portable compression functions, block
    /// by block from many starting states, so a lane or byte order
    /// mistake cannot hide behind one state. On a processor without the
    /// extensions there is nothing to compare, and the test says so.
    #[test]
    fn test_the_extensions_agree_with_the_portable_code() {
        if !available() {
            eprintln!("skipped: this processor has no SHA extensions");
            return;
        }
        let data = noise(64 * 200, 7);
        let mut hw1 = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
        let mut sw1 = hw1;
        let mut hw256 = [0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
                         0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19];
        let mut sw256 = hw256;
        for block in data.chunks_exact(64) {
            assert!(sha1(&mut hw1, block));
            super::super::sha1::compress::<false>(&mut sw1, block.try_into().unwrap());
            assert_eq!(hw1, sw1);
            assert!(sha256(&mut hw256, block));
            super::super::sha2::compress_256(&mut sw256, block.try_into().unwrap());
            assert_eq!(hw256, sw256);
        }
        // And as runs of every length up to nine blocks, which is where
        // keeping the state in registers between blocks could go wrong.
        for blocks in 0..=9 {
            let run = &data[..64 * blocks];
            let (mut hw1, mut sw1) = ([1, 2, 3, 4, 5], [1, 2, 3, 4, 5]);
            let (mut hw256, mut sw256) = ([1, 2, 3, 4, 5, 6, 7, 8], [1, 2, 3, 4, 5, 6, 7, 8]);
            assert!(sha1(&mut hw1, run));
            assert!(sha256(&mut hw256, run));
            for block in run.chunks_exact(64) {
                super::super::sha1::compress::<false>(&mut sw1, block.try_into().unwrap());
                super::super::sha2::compress_256(&mut sw256, block.try_into().unwrap());
            }
            assert_eq!((hw1, hw256), (sw1, sw256), "{} blocks", blocks);
        }
    }

    /// Without the extensions both entry points refuse and leave the
    /// state alone, which is what lets the callers fall back.
    #[test]
    fn test_no_extensions_means_no_change() {
        if available() {
            return;
        }
        let mut state1 = [1, 2, 3, 4, 5];
        let mut state256 = [1, 2, 3, 4, 5, 6, 7, 8];
        assert!(!sha1(&mut state1, &[0; 64]));
        assert!(!sha256(&mut state256, &[0; 64]));
        assert_eq!(state1, [1, 2, 3, 4, 5]);
        assert_eq!(state256, [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
