/*
HAS-160, the Korean hash standard (TTA.KO-12.0011/R2, 2000), made for
KCDSA signatures. A 160-bit digest built like SHA-1 - five words, four
rounds of twenty steps, SHA-1's initial value and constants - with three
differences that each matter:

  * **The message expansion** is not SHA-1's recurrence. Each round reads
    the sixteen block words in its own order, plus four extra words, each
    the XOR of four of them: with the round's order `L`, the extras are
    `L0^L1^L2^L3`, `L4^..^L7`, `L8^..^L11` and `L12^..^L15`, and the
    round reads `X18, L0..L3, X19, L4..L7, X16, L8..L11, X17, L12..L15`
    where `X16..X19` are those four in that order.
  * **The rotations vary.** A is rotated by a different amount at each of
    the twenty steps of a round (the same twenty in every round), and B
    by an amount that changes per round rather than SHA-1's fixed 30.
  * **Byte order is little endian**, in the message words, the length and
    the output - MD5's convention, not SHA-1's.

The third round's function is `y ^ (x | !z)`, not SHA-1's majority.
*/

use super::buffer::BlockBuffer;
use super::HashFunction;

/// Each round's order of the sixteen block words. Round one is in order,
/// and the others step through the block by 3, 9 and 11.
const ORDER: [[usize; 16]; 4] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [3, 6, 9, 12, 15, 2, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0],
    [12, 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3],
    [7, 2, 13, 8, 3, 14, 9, 4, 15, 10, 5, 0, 11, 6, 1, 12],
];

/// A's rotation at each step of a round.
const ROTATE_A: [u32; 20] = [5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13];
/// B's rotation in each round.
const ROTATE_B: [u32; 4] = [10, 17, 25, 30];
const K: [u32; 4] = [0, 0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc];

#[inline(always)]
fn boolean(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0 => (x & y) | (!x & z),
        2 => y ^ (x | !z),
        _ => x ^ y ^ z,
    }
}

#[derive(Clone)]
pub struct Has160 {
    h: [u32; 5],
    buffer: BlockBuffer<64>,
    length: u64,
}

impl Default for Has160 {
    fn default() -> Has160 {
        Has160::new(&[])
    }
}

impl Has160 {
    pub fn new(input: &[u8]) -> Has160 {
        let mut hash = Has160 {
            h: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0],
            buffer: BlockBuffer::default(),
            length: 0,
        };
        hash.update(input);
        hash
    }

    fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
        let x: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().expect("4 bytes"))
        });
        let [mut a, mut b, mut c, mut d, mut e] = *h;
        for (round, order) in ORDER.iter().enumerate() {
            let word = |i: usize| x[order[i]];
            let extra = |g: usize| word(4 * g) ^ word(4 * g + 1) ^ word(4 * g + 2) ^ word(4 * g + 3);
            // X18, L0..L3, X19, L4..L7, X16, L8..L11, X17, L12..L15.
            let words: [u32; 20] = core::array::from_fn(|step| {
                let (group, within) = (step / 5, step % 5);
                if within == 0 {
                    extra((group + 2) % 4)
                } else {
                    word(4 * group + within - 1)
                }
            });
            for (step, w) in words.iter().enumerate() {
                let t = a.rotate_left(ROTATE_A[step])
                    .wrapping_add(boolean(round, b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(*w)
                    .wrapping_add(K[round]);
                e = d;
                d = c;
                c = b.rotate_left(ROTATE_B[round]);
                b = a;
                a = t;
            }
        }
        for (word, value) in h.iter_mut().zip([a, b, c, d, e]) {
            *word = word.wrapping_add(value);
        }
    }
}

impl HashFunction for Has160 {
    fn name(&self) -> String { "has160".to_string() }

    fn digest_len(&self) -> usize { 20 }

    fn block_size(&self) -> usize { 64 }

    fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        let h = &mut self.h;
        self.buffer.feed(input, |block| Has160::compress(h, block));
    }

    fn digest(&mut self) -> Vec<u8> {
        // On a copy, so this is repeatable and `update` may continue.
        let mut last = self.clone();
        let bits = last.length.wrapping_mul(8);
        let pad = 1 + (119 - last.buffer.len()) % 64;
        let mut tail = vec![0u8; pad];
        tail[0] = 0x80;
        tail.extend_from_slice(&bits.to_le_bytes());
        let h = &mut last.h;
        last.buffer.feed(&tail, |block| Has160::compress(h, block));
        debug_assert!(last.buffer.is_empty());
        last.h.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each round's order is a permutation of the sixteen words, and the
    /// later rounds step through the block by 3, 9 and 11 from their
    /// first entry.
    #[test]
    fn test_the_orders() {
        for (round, step) in [(1usize, 3usize), (2, 9), (3, 11)] {
            let mut sorted = ORDER[round];
            sorted.sort_unstable();
            assert_eq!(sorted, core::array::from_fn::<usize, 16, _>(|i| i));
            for i in 1..16 {
                assert_eq!(ORDER[round][i], (ORDER[round][i - 1] + step) % 16, "round {round}");
            }
        }
    }

    #[test]
    fn test_digest_is_repeatable_and_streaming_agrees() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 167 + 29) as u8).collect();
        for length in [0usize, 55, 56, 63, 64, 65, 119, 120, 128, 300] {
            let whole = Has160::new(&data[..length]).digest();
            for size in [1usize, 7, 64] {
                let mut pieces = Has160::new(&[]);
                for chunk in data[..length].chunks(size) {
                    pieces.update(chunk);
                }
                assert_eq!(pieces.digest(), whole, "{length} {size}");
                assert_eq!(pieces.digest(), whole, "repeated");
            }
        }
    }
}
