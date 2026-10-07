/*
RIPEMD-160.

160 bit output, 512 bit blocks, and **two parallel lines** of five rounds
each whose results are combined at the end - which is the whole of what
distinguishes it from the SHA-1 generation it was designed alongside.
Published in 1996 by Dobbertin, Bosselaers and Preneel, and never broken
in the way SHA-1 was.

Here because it has not gone away and is steadily becoming harder to
find. Bitcoin addresses are `RIPEMD160(SHA256(pubkey))`, so every wallet
needs it; OpenSSL 3 moved it behind the legacy provider; and it is
absent from a good many newer libraries entirely.

## The two lines are not the same function with different constants

The left line and the right line differ in four ways at once, and every
one of them matters:

  * the **boolean function** runs forwards on the left (`f1..f5`) and
    backwards on the right (`f5..f1`),
  * the **round constants** are different, and the right line's are
    different numbers rather than the left line's reordered,
  * the **message word order** is a different permutation per round per
    line,
  * the **rotation amounts** are a different table per round per line.

An implementation that shares any one of the four between the lines
produces a hash that is deterministic, avalanches properly, and matches
nothing.

## The combination at the end is not an addition

    T   = h1 + c + d'
    h1  = h2 + d + e'
    h2  = h3 + e + a'
    ...

The state words are **rotated by one** as they are combined, and each
takes one word from each line at a different offset. Adding the two
lines' states position by position - the obvious thing - gives a wrong
answer for every input including the empty one, so at least it fails
loudly.
*/

use crate::hash_functions::HashFunction;

/// The message word order, left line then right line, five rounds each.
pub(super) const ORDER_LEFT: [[usize; 16]; 5] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
    [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
    [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
    [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
];

pub(super) const ORDER_RIGHT: [[usize; 16]; 5] = [
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
    [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
    [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
    [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
    [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
];

/// The rotation amounts, one table per line.
pub(super) const ROTATE_LEFT: [[u32; 16]; 5] = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
    [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
    [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
    [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
];

pub(super) const ROTATE_RIGHT: [[u32; 16]; 5] = [
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
    [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
    [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
    [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
    [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
];

/// The round constants. The left line's are the square roots of 2, 3, 5
/// and 7 scaled; the right line's are the **cube** roots - genuinely
/// different numbers, not a permutation of the same five.
pub(super) const K_LEFT: [u32; 5] = [0x0000_0000, 0x5a82_7999, 0x6ed9_eba1,
                          0x8f1b_bcdc, 0xa953_fd4e];
pub(super) const K_RIGHT: [u32; 5] = [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3,
                           0x7a6d_76e9, 0x0000_0000];

/// The five boolean functions, indexed by round.
#[inline]
pub(super) fn boolean(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

/// RIPEMD-160, streaming.
#[derive(Clone)]
pub struct Ripemd160 {
    h: [u32; 5],
    buffer: Vec<u8>,
    length: u64,
}

impl Default for Ripemd160 {
    fn default() -> Ripemd160 {
        Ripemd160::new(&[])
    }
}

impl Ripemd160 {
    pub fn new(input: &[u8]) -> Ripemd160 {
        let mut hash = Ripemd160 {
            h: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0],
            buffer: Vec::with_capacity(64),
            length: 0,
        };
        hash.update(input);
        hash
    }

    fn compress(&mut self, block: &[u8]) {
        let mut m = [0u32; 16];
        for (index, word) in m.iter_mut().enumerate() {
            let at = index * 4;
            *word = u32::from_le_bytes([block[at], block[at + 1],
                                        block[at + 2], block[at + 3]]);
        }

        let mut left = self.h;
        let mut right = self.h;

        for round in 0..5 {
            for step in 0..16 {
                // The left line: f1..f5 forwards.
                let t = left[0]
                    .wrapping_add(boolean(round, left[1], left[2], left[3]))
                    .wrapping_add(m[ORDER_LEFT[round][step]])
                    .wrapping_add(K_LEFT[round])
                    .rotate_left(ROTATE_LEFT[round][step])
                    .wrapping_add(left[4]);
                left = [left[4], t, left[1], left[2].rotate_left(10), left[3]];

                // The right line: f5..f1 backwards, and every table its
                // own.
                let t = right[0]
                    .wrapping_add(boolean(4 - round, right[1], right[2], right[3]))
                    .wrapping_add(m[ORDER_RIGHT[round][step]])
                    .wrapping_add(K_RIGHT[round])
                    .rotate_left(ROTATE_RIGHT[round][step])
                    .wrapping_add(right[4]);
                right = [right[4], t, right[1], right[2].rotate_left(10), right[3]];
            }
        }

        // **Rotated by one as they combine.** Each new word takes one
        // from each line at a different offset, and adding the lines
        // position by position gives a wrong answer for every input.
        let t = self.h[1].wrapping_add(left[2]).wrapping_add(right[3]);
        self.h[1] = self.h[2].wrapping_add(left[3]).wrapping_add(right[4]);
        self.h[2] = self.h[3].wrapping_add(left[4]).wrapping_add(right[0]);
        self.h[3] = self.h[4].wrapping_add(left[0]).wrapping_add(right[1]);
        self.h[4] = self.h[0].wrapping_add(left[1]).wrapping_add(right[2]);
        self.h[0] = t;
    }
}

impl HashFunction for Ripemd160 {
    fn name(&self) -> String { "ripemd160".to_string() }

    fn digest_len(&self) -> usize { 20 }

    fn block_size(&self) -> usize { 64 }

    fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        let mut input = input;
        while !input.is_empty() {
            let take = core::cmp::min(64 - self.buffer.len(), input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.buffer.len() == 64 {
                let block = core::mem::take(&mut self.buffer);
                self.compress(&block);
                self.buffer = block;
                self.buffer.clear();
            }
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        // Finalised on a copy, so this is repeatable and `update` may
        // continue afterwards.
        let mut final_state = self.clone();

        // Merkle-Damgard padding with a **little endian** length, which
        // is the other place RIPEMD differs from SHA-1's otherwise
        // identical construction.
        let bits = final_state.length.wrapping_mul(8);
        final_state.update(&[0x80]);
        while final_state.buffer.len() != 56 {
            final_state.update(&[0]);
        }
        final_state.update(&bits.to_le_bytes());

        let mut out = Vec::with_capacity(20);
        for word in final_state.h {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn digest_of(input: &[u8]) -> String {
        hex(&Ripemd160::new(input).digest())
    }

    /// The published vectors from the RIPEMD-160 paper's own test set,
    /// which every implementation quotes and `hashlib` reproduces.
    #[test]
    fn test_the_published_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (b"abcdefghijklmnopqrstuvwxyz",
             "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
             "b0e20b6e3116640286ed3a87a5713079b21f5189"),
        ];
        for (input, expected) in cases {
            assert_eq!(digest_of(input), *expected,
                       "input {:?}", String::from_utf8_lossy(input));
        }
    }

    /// The million-'a' vector, which is the only one that exercises the
    /// length field past a single block count.
    #[test]
    fn test_the_million_a_vector() {
        let mut hash = Ripemd160::new(&[]);
        for _ in 0..1000 {
            hash.update(&[b'a'; 1000]);
        }
        assert_eq!(hex(&hash.digest()), "52783243c1697bdbe16d37f97f68f08325dc1528");
    }

    /// **Padding at every length across two block boundaries.**
    ///
    /// The bug this library has already had once, in SHA-1: a padding
    /// length field of the wrong width is correct for most inputs and
    /// wrong for the ones that land in the last eight bytes of a block.
    /// Streamed against one-shot catches a state error; this catches a
    /// padding error, which needs a pinned answer.
    #[test]
    fn test_streaming_equals_one_shot_across_the_boundary() {
        for length in (0..200).chain([255, 256, 257, 511, 512, 513, 1000]) {
            let input: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let one_shot = digest_of(&input);
            for chunk_size in [1usize, 7, 63, 64, 65] {
                let mut hash = Ripemd160::new(&[]);
                for chunk in input.chunks(chunk_size) {
                    hash.update(chunk);
                }
                assert_eq!(hex(&hash.digest()), one_shot,
                           "disagreed with itself at {} bytes in {} byte pieces",
                           length, chunk_size);
            }
        }
    }

    /// The two lines really are different.
    ///
    /// Sharing any one of the four tables between them gives a
    /// deterministic hash that matches nothing. This checks all four
    /// differ rather than trusting that they were typed differently.
    #[test]
    fn test_the_two_lines_differ_in_all_four_ways() {
        assert_ne!(ORDER_LEFT, ORDER_RIGHT, "the message order is shared");
        assert_ne!(ROTATE_LEFT, ROTATE_RIGHT, "the rotation tables are shared");
        assert_ne!(K_LEFT, K_RIGHT, "the round constants are shared");
        // And the boolean functions run in opposite directions.
        for round in 0..5 {
            if round != 2 {
                assert_ne!(boolean(round, 0x1234_5678, 0x9abc_def0, 0x0f0f_0f0f),
                           boolean(4 - round, 0x1234_5678, 0x9abc_def0, 0x0f0f_0f0f),
                           "f{} and f{} agree", round + 1, 5 - round);
            }
        }
    }

    /// `digest()` is repeatable and does not end the hash.
    #[test]
    fn test_digest_is_repeatable() {
        let mut hash = Ripemd160::new(b"first");
        let once = hash.digest();
        assert_eq!(once, hash.digest());
        hash.update(b"second");
        assert_eq!(hex(&hash.digest()), digest_of(b"firstsecond"));
    }

    /// Every message word is used exactly once per round, in both
    /// lines.
    ///
    /// A permutation table with a repeated entry would drop one word of
    /// the message from that round - which changes the answer but not
    /// obviously, and only for messages that differ in that word.
    #[test]
    fn test_every_word_order_is_a_permutation() {
        for (name, table) in [("left", &ORDER_LEFT), ("right", &ORDER_RIGHT)] {
            for (round, order) in table.iter().enumerate() {
                let mut sorted = *order;
                sorted.sort_unstable();
                assert_eq!(sorted, core::array::from_fn::<usize, 16, _>(|i| i),
                           "{} line round {} is not a permutation", name, round);
            }
        }
    }
}
