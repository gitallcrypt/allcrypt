/*
RIPEMD-128, RIPEMD-256 and RIPEMD-320 (Dobbertin, Bosselaers and Preneel,
1996), the companions of RIPEMD-160 in `ripemd160.rs`. ISO/IEC 10118-3
carries RIPEMD-128 alongside RIPEMD-160.

All three share RIPEMD-160's two lines, message word orders and rotation
tables:

  * **RIPEMD-128** is four rounds instead of five, on four words per line
    instead of five, with no extra addition and no rotation by ten in the
    step. The right line's last constant is zero rather than RIPEMD-160's
    fourth, and its boolean functions run f4..f1. The two lines combine
    into four words the way RIPEMD-160's combine into five.
  * **RIPEMD-256** is RIPEMD-128 with the two lines kept apart: each
    line has its own four words of state and its own initial value, one
    word is exchanged between the lines after every round, and each line
    is added to its own half of the output. Twice the output, the same
    security level as RIPEMD-128 - the designers say so.
  * **RIPEMD-320** is the same widening of RIPEMD-160.

## Which word is exchanged

The specification names the words by role - A to E after each step's
rotation, which is what this code's array holds - and exchanges B, D, A,
C, E after RIPEMD-320's five rounds and A, B, C, D after RIPEMD-256's
four. Reference code that keeps named variables and rotates the roles by
argument order instead exchanges a, b, c, d, e in turn: the same words,
because after `k` steps the role at position `p` is held by variable
`(p - k) mod 5`. With four words and sixteen steps a round the two
namings coincide; with five they do not, and reading one sequence in the
other naming gives a hash that is deterministic, avalanches, and matches
nothing.
*/

use super::buffer::BlockBuffer;
use super::ripemd160::{boolean, K_LEFT, K_RIGHT, ORDER_LEFT, ORDER_RIGHT, ROTATE_LEFT,
                       ROTATE_RIGHT};
use super::HashFunction;

/// RIPEMD-128's right-line constants: RIPEMD-160's first three, then
/// zero where RIPEMD-160 has its fourth.
const K_RIGHT_128: [u32; 4] = [K_RIGHT[0], K_RIGHT[1], K_RIGHT[2], 0];

/// The first four initial words, shared by every MD4-family hash.
const IV: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
/// The right line's initial words in the wide variants.
const IV_RIGHT: [u32; 5] = [0x7654_3210, 0xfedc_ba98, 0x89ab_cdef, 0x0123_4567, 0x3c2d_1e0f];

/// Which word, by role, is exchanged between the lines after each round.
const EXCHANGE_256: [usize; 4] = [0, 1, 2, 3];
const EXCHANGE_320: [usize; 5] = [1, 3, 0, 2, 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Ripemd128,
    Ripemd256,
    Ripemd320,
}

impl Variant {
    /// Words per line: four for the RIPEMD-128 kind, five for RIPEMD-160.
    fn width(self) -> usize {
        if self == Variant::Ripemd320 { 5 } else { 4 }
    }

    fn digest_len(self) -> usize {
        match self {
            Variant::Ripemd128 => 16,
            Variant::Ripemd256 => 32,
            Variant::Ripemd320 => 40,
        }
    }
}

#[derive(Clone)]
pub struct Ripemd {
    variant: Variant,
    /// Four words for RIPEMD-128; two lines of four or five for the wide
    /// ones, left then right.
    h: [u32; 10],
    buffer: BlockBuffer<64>,
    length: u64,
}

impl Ripemd {
    pub fn new(variant: Variant, input: &[u8]) -> Ripemd {
        let width = variant.width();
        let mut h = [0u32; 10];
        h[..width].copy_from_slice(&IV[..width]);
        if variant != Variant::Ripemd128 {
            h[width..2 * width].copy_from_slice(&IV_RIGHT[..width]);
        }
        let mut hash = Ripemd { variant, h, buffer: BlockBuffer::default(), length: 0 };
        hash.update(input);
        hash
    }

    pub fn ripemd128(input: &[u8]) -> Ripemd { Ripemd::new(Variant::Ripemd128, input) }
    pub fn ripemd256(input: &[u8]) -> Ripemd { Ripemd::new(Variant::Ripemd256, input) }
    pub fn ripemd320(input: &[u8]) -> Ripemd { Ripemd::new(Variant::Ripemd320, input) }

    fn compress(variant: Variant, h: &mut [u32; 10], block: &[u8; 64]) {
        let m: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().expect("4 bytes"))
        });
        match variant {
            Variant::Ripemd320 => {
                let mut left: [u32; 5] = h[..5].try_into().expect("5 words");
                let mut right: [u32; 5] = h[5..].try_into().expect("5 words");
                for round in 0..5 {
                    for step in 0..16 {
                        left = step160(left, boolean(round, left[1], left[2], left[3]),
                                       m[ORDER_LEFT[round][step]], K_LEFT[round],
                                       ROTATE_LEFT[round][step]);
                        right = step160(right, boolean(4 - round, right[1], right[2], right[3]),
                                        m[ORDER_RIGHT[round][step]], K_RIGHT[round],
                                        ROTATE_RIGHT[round][step]);
                    }
                    core::mem::swap(&mut left[EXCHANGE_320[round]],
                                    &mut right[EXCHANGE_320[round]]);
                }
                for (word, value) in h.iter_mut().zip(left.iter().chain(&right)) {
                    *word = word.wrapping_add(*value);
                }
            }
            Variant::Ripemd128 | Variant::Ripemd256 => {
                let wide = variant == Variant::Ripemd256;
                let mut left: [u32; 4] = h[..4].try_into().expect("4 words");
                let mut right: [u32; 4] = if wide {
                    h[4..8].try_into().expect("4 words")
                } else {
                    left
                };
                for round in 0..4 {
                    for step in 0..16 {
                        left = step128(left, boolean(round, left[1], left[2], left[3]),
                                       m[ORDER_LEFT[round][step]], K_LEFT[round],
                                       ROTATE_LEFT[round][step]);
                        right = step128(right, boolean(3 - round, right[1], right[2], right[3]),
                                        m[ORDER_RIGHT[round][step]], K_RIGHT_128[round],
                                        ROTATE_RIGHT[round][step]);
                    }
                    if wide {
                        core::mem::swap(&mut left[EXCHANGE_256[round]],
                                        &mut right[EXCHANGE_256[round]]);
                    }
                }
                if wide {
                    for (word, value) in h[..8].iter_mut().zip(left.iter().chain(&right)) {
                        *word = word.wrapping_add(*value);
                    }
                } else {
                    // Rotated by one as they combine, as RIPEMD-160's do.
                    let t = h[1].wrapping_add(left[2]).wrapping_add(right[3]);
                    h[1] = h[2].wrapping_add(left[3]).wrapping_add(right[0]);
                    h[2] = h[3].wrapping_add(left[0]).wrapping_add(right[1]);
                    h[3] = h[0].wrapping_add(left[1]).wrapping_add(right[2]);
                    h[0] = t;
                }
            }
        }
    }
}

/// One RIPEMD-128 step: the first word replaced and the roles rotated.
#[inline(always)]
fn step128(s: [u32; 4], f: u32, word: u32, k: u32, rotation: u32) -> [u32; 4] {
    let t = s[0].wrapping_add(f).wrapping_add(word).wrapping_add(k).rotate_left(rotation);
    [s[3], t, s[1], s[2]]
}

/// One RIPEMD-160 step, as in `ripemd160.rs`.
#[inline(always)]
fn step160(s: [u32; 5], f: u32, word: u32, k: u32, rotation: u32) -> [u32; 5] {
    let t = s[0].wrapping_add(f).wrapping_add(word).wrapping_add(k).rotate_left(rotation)
        .wrapping_add(s[4]);
    [s[4], t, s[1], s[2].rotate_left(10), s[3]]
}

impl HashFunction for Ripemd {
    fn name(&self) -> String {
        match self.variant {
            Variant::Ripemd128 => "ripemd128",
            Variant::Ripemd256 => "ripemd256",
            Variant::Ripemd320 => "ripemd320",
        }.to_string()
    }

    fn digest_len(&self) -> usize { self.variant.digest_len() }

    fn block_size(&self) -> usize { 64 }

    fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        let (variant, h) = (self.variant, &mut self.h);
        self.buffer.feed(input, |block| Ripemd::compress(variant, h, block));
    }

    fn digest(&mut self) -> Vec<u8> {
        // On a copy, so this is repeatable and `update` may continue.
        let mut last = self.clone();
        // The same little-endian Merkle-Damgard padding as RIPEMD-160.
        let bits = last.length.wrapping_mul(8);
        let pad = 1 + (119 - last.buffer.len()) % 64;
        let mut tail = vec![0u8; pad];
        tail[0] = 0x80;
        tail.extend_from_slice(&bits.to_le_bytes());
        let (variant, h) = (last.variant, &mut last.h);
        last.buffer.feed(&tail, |block| Ripemd::compress(variant, h, block));
        debug_assert!(last.buffer.is_empty());
        last.h[..self.variant.digest_len() / 4].iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The two namings of the exchanges agree: the role at position `p`
    /// after `k` steps is held by variable `(p - k) mod 5`, so B, D, A, C,
    /// E by role after rounds one to five are a, b, c, d, e by variable -
    /// the order reference code with named variables uses.
    #[test]
    fn test_the_exchange_roles_are_variables_a_to_e() {
        let mut roles: [usize; 5] = [0, 1, 2, 3, 4];
        for (round, role) in EXCHANGE_320.iter().enumerate() {
            for _ in 0..16 {
                roles = [roles[4], roles[0], roles[1], roles[2], roles[3]];
            }
            assert_eq!(roles[*role], round, "round {}", round + 1);
        }
    }

    #[test]
    fn test_digest_is_repeatable_and_streaming_agrees() {
        for variant in [Variant::Ripemd128, Variant::Ripemd256, Variant::Ripemd320] {
            let data: Vec<u8> = (0..300u32).map(|i| (i * 167 + 29) as u8).collect();
            for length in [0usize, 55, 56, 63, 64, 65, 119, 120, 128, 300] {
                let whole = Ripemd::new(variant, &data[..length]).digest();
                assert_eq!(whole.len(), variant.digest_len());
                for size in [1usize, 7, 64] {
                    let mut pieces = Ripemd::new(variant, &[]);
                    for chunk in data[..length].chunks(size) {
                        pieces.update(chunk);
                    }
                    assert_eq!(hex(&pieces.digest()), hex(&whole), "{variant:?} {length} {size}");
                    assert_eq!(hex(&pieces.digest()), hex(&whole), "repeated");
                }
            }
        }
    }
}
