//! ChaCha's rounds on x86-64 vector registers: four blocks side by side
//! in SSE2, or eight in AVX2 when the processor has it. Compiled only
//! with the `simd` feature.
//!
//! ## Why this is behind a feature
//!
//! For the same reason as `aes-ni` and `sha-ni`: it takes `unsafe`, and
//! everything else in the library's cryptography is portable Rust
//! without it. The portable four-block code in `chacha.rs` is what the
//! compiler makes of it, and it does not vectorise: LLVM leaves the
//! quarter rounds as scalar code whatever shape the lanes are written
//! in, `x86-64-v3` included - the disassembly has no vector arithmetic.
//!
//! ## What the `unsafe` is
//!
//! Two calls, one into each function compiled for a CPU feature, and
//! the unaligned loads and stores in `xor16` and `xor32`, whose pointer
//! comes from a reference to exactly the bytes moved. The rest takes
//! values, not pointers: the state goes in through `_mm_set_epi32` and
//! `_mm256_set_epi32`.
//!
//! - `sse2_four`: SSE2 is part of the x86-64 baseline - every x86-64
//!   processor has it and every `x86_64` target enables it - so the call
//!   asserts something true by construction. Rust still requires the
//!   `unsafe`, because it does not count the build's baseline features.
//! - `avx2_eight`: reached only after `avx2()`, which
//!   `is_x86_feature_detected!` decides once per process.

use core::arch::x86_64::*;
use std::sync::OnceLock;

/// Whether this processor has AVX2. Checked once.
pub(crate) fn avx2() -> bool {
    static AVX2: OnceLock<bool> = OnceLock::new();
    *AVX2.get_or_init(|| is_x86_feature_detected!("avx2"))
}

/// Four blocks XORed into `buf`, 256 bytes. `input[w][l]` is word `w`
/// of block `l`'s starting state.
pub(crate) fn four(input: &[[u32; 4]; 16], rounds: usize, buf: &mut [u8]) {
    assert_eq!(buf.len(), 256);
    // SSE2 is in the x86-64 baseline: this processor has it.
    unsafe { sse2_four(input, rounds, buf) }
}

/// Eight blocks XORed into `buf`, 512 bytes, if this processor has AVX2;
/// `false`, with nothing touched, if it does not.
pub(crate) fn eight(input: &[[u32; 8]; 16], rounds: usize, buf: &mut [u8]) -> bool {
    assert_eq!(buf.len(), 512);
    if !avx2() {
        return false;
    }
    // Checked just above.
    unsafe { avx2_eight(input, rounds, buf) }
    true
}

/// Sixteen bytes of keystream XORed into `bytes`.
#[inline]
#[target_feature(enable = "sse2")]
fn xor16(bytes: &mut [u8; 16], keystream: __m128i) {
    // SAFETY: the reference covers exactly the sixteen bytes read and
    // written, and `loadu`/`storeu` have no alignment requirement.
    unsafe {
        let data = _mm_loadu_si128(bytes.as_ptr().cast());
        _mm_storeu_si128(bytes.as_mut_ptr().cast(), _mm_xor_si128(data, keystream));
    }
}

/// Thirty-two bytes of keystream XORed into `bytes`.
#[inline]
#[target_feature(enable = "avx2")]
fn xor32(bytes: &mut [u8; 32], keystream: __m256i) {
    // SAFETY: as in `xor16`, for thirty-two bytes.
    unsafe {
        let data = _mm256_loadu_si256(bytes.as_ptr().cast());
        _mm256_storeu_si256(bytes.as_mut_ptr().cast(), _mm256_xor_si256(data, keystream));
    }
}

/// The `N` bytes of `buf` at `at`, as an array reference.
#[inline(always)]
fn at<const N: usize>(buf: &mut [u8], at: usize) -> &mut [u8; N] {
    (&mut buf[at..at + N]).try_into().expect("N bytes")
}

#[inline]
#[target_feature(enable = "sse2")]
fn rotate<const LEFT: i32, const RIGHT: i32>(v: __m128i) -> __m128i {
    _mm_or_si128(_mm_slli_epi32::<LEFT>(v), _mm_srli_epi32::<RIGHT>(v))
}

#[inline]
#[target_feature(enable = "sse2")]
fn quarter_round(x: &mut [__m128i; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = _mm_add_epi32(x[a], x[b]);
    // A rotation by 16 swaps each word's halves: two 16-bit shuffles.
    let t = _mm_xor_si128(x[d], x[a]);
    x[d] = _mm_shufflehi_epi16::<0xB1>(_mm_shufflelo_epi16::<0xB1>(t));
    x[c] = _mm_add_epi32(x[c], x[d]);
    x[b] = rotate::<12, 20>(_mm_xor_si128(x[b], x[c]));
    x[a] = _mm_add_epi32(x[a], x[b]);
    x[d] = rotate::<8, 24>(_mm_xor_si128(x[d], x[a]));
    x[c] = _mm_add_epi32(x[c], x[d]);
    x[b] = rotate::<7, 25>(_mm_xor_si128(x[b], x[c]));
}

/// Words `4g..4g + 4` of four blocks, one block to a register, out of
/// four registers that each hold one word of all four blocks: the 4 x 4
/// transpose.
#[inline]
#[target_feature(enable = "sse2")]
fn transpose(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> [__m128i; 4] {
    let ab_low = _mm_unpacklo_epi32(a, b);
    let cd_low = _mm_unpacklo_epi32(c, d);
    let ab_high = _mm_unpackhi_epi32(a, b);
    let cd_high = _mm_unpackhi_epi32(c, d);
    [_mm_unpacklo_epi64(ab_low, cd_low), _mm_unpackhi_epi64(ab_low, cd_low),
     _mm_unpacklo_epi64(ab_high, cd_high), _mm_unpackhi_epi64(ab_high, cd_high)]
}

#[target_feature(enable = "sse2")]
fn sse2_four(input: &[[u32; 4]; 16], rounds: usize, buf: &mut [u8]) {
    let mut start = [_mm_setzero_si128(); 16];
    for (register, word) in start.iter_mut().zip(input) {
        *register = _mm_set_epi32(word[3] as i32, word[2] as i32, word[1] as i32,
                                  word[0] as i32);
    }
    let mut x = start;
    for _ in (0..rounds).step_by(2) {
        quarter_round(&mut x, 0, 4,  8, 12);
        quarter_round(&mut x, 1, 5,  9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7,  8, 13);
        quarter_round(&mut x, 3, 4,  9, 14);
    }
    for (register, start) in x.iter_mut().zip(&start) {
        *register = _mm_add_epi32(*register, *start);
    }
    for group in 0..4 {
        let blocks = transpose(x[4 * group], x[4 * group + 1], x[4 * group + 2],
                               x[4 * group + 3]);
        for (block, v) in blocks.into_iter().enumerate() {
            xor16(at(buf, 64 * block + 16 * group), v);
        }
    }
}

#[inline]
#[target_feature(enable = "avx2")]
fn rotate8<const LEFT: i32, const RIGHT: i32>(v: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_slli_epi32::<LEFT>(v), _mm256_srli_epi32::<RIGHT>(v))
}

#[inline]
#[target_feature(enable = "avx2")]
fn quarter_round8(x: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize,
                  by16: __m256i, by8: __m256i) {
    x[a] = _mm256_add_epi32(x[a], x[b]);
    x[d] = _mm256_shuffle_epi8(_mm256_xor_si256(x[d], x[a]), by16);
    x[c] = _mm256_add_epi32(x[c], x[d]);
    x[b] = rotate8::<12, 20>(_mm256_xor_si256(x[b], x[c]));
    x[a] = _mm256_add_epi32(x[a], x[b]);
    x[d] = _mm256_shuffle_epi8(_mm256_xor_si256(x[d], x[a]), by8);
    x[c] = _mm256_add_epi32(x[c], x[d]);
    x[b] = rotate8::<7, 25>(_mm256_xor_si256(x[b], x[c]));
}

#[target_feature(enable = "avx2")]
fn avx2_eight(input: &[[u32; 8]; 16], rounds: usize, buf: &mut [u8]) {
    // Rotations by 16 and 8 move whole bytes, so they are one byte
    // shuffle each. Byte `i` of a result takes byte `index[i]` of the
    // word, within each 128-bit half.
    let by16 = _mm256_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
                                2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
    let by8 = _mm256_setr_epi8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
                               3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
    let mut start = [_mm256_setzero_si256(); 16];
    for (register, w) in start.iter_mut().zip(input) {
        *register = _mm256_set_epi32(w[7] as i32, w[6] as i32, w[5] as i32, w[4] as i32,
                                     w[3] as i32, w[2] as i32, w[1] as i32, w[0] as i32);
    }
    let mut x = start;
    for _ in (0..rounds).step_by(2) {
        quarter_round8(&mut x, 0, 4,  8, 12, by16, by8);
        quarter_round8(&mut x, 1, 5,  9, 13, by16, by8);
        quarter_round8(&mut x, 2, 6, 10, 14, by16, by8);
        quarter_round8(&mut x, 3, 7, 11, 15, by16, by8);
        quarter_round8(&mut x, 0, 5, 10, 15, by16, by8);
        quarter_round8(&mut x, 1, 6, 11, 12, by16, by8);
        quarter_round8(&mut x, 2, 7,  8, 13, by16, by8);
        quarter_round8(&mut x, 3, 4,  9, 14, by16, by8);
    }
    for (register, start) in x.iter_mut().zip(&start) {
        *register = _mm256_add_epi32(*register, *start);
    }
    // The 256-bit unpacks work within each 128-bit half, so the same
    // transpose as SSE2's leaves blocks 0-3 in the low halves and 4-7 in
    // the high ones: `quarters[group][k]` holds sixteen bytes of block
    // `k` and sixteen of block `k + 4`. Two groups' halves side by side
    // are thirty-two consecutive bytes of one block.
    let mut quarters = [[_mm256_setzero_si256(); 4]; 4];
    for (group, quarter) in quarters.iter_mut().enumerate() {
        let (a, b, c, d) = (x[4 * group], x[4 * group + 1], x[4 * group + 2],
                            x[4 * group + 3]);
        let ab_low = _mm256_unpacklo_epi32(a, b);
        let cd_low = _mm256_unpacklo_epi32(c, d);
        let ab_high = _mm256_unpackhi_epi32(a, b);
        let cd_high = _mm256_unpackhi_epi32(c, d);
        *quarter = [_mm256_unpacklo_epi64(ab_low, cd_low),
                    _mm256_unpackhi_epi64(ab_low, cd_low),
                    _mm256_unpacklo_epi64(ab_high, cd_high),
                    _mm256_unpackhi_epi64(ab_high, cd_high)];
    }
    for half in [0, 2] {
        for (k, (&first, &second)) in quarters[half].iter().zip(&quarters[half + 1]).enumerate() {
            xor32(at(buf, 64 * k + 16 * half),
                  _mm256_permute2x128_si256::<0x20>(first, second));
            xor32(at(buf, 64 * (k + 4) + 16 * half),
                  _mm256_permute2x128_si256::<0x31>(first, second));
        }
    }
}
