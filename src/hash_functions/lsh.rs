/*!
LSH (KS X 3262, Korea's hash standard, 2014): LSH-256 on 32 bit words
and LSH-512 on 64 bit words, each with any whole number of bytes of
output up to its width; the standard names LSH-256-224 and -256 and
LSH-512-224, -256, -384 and -512.

A wide-pipe hash: a chaining value of sixteen words, in two halves,
and message blocks of 32 words, little endian. A block becomes 26
(LSH-256) or 28 (LSH-512) sixteen-word sub-messages, the first two its
halves and each after that the one two back permuted and added to the
one before. Each step XORs a sub-message into the chaining value, then
mixes each left word with its right partner - add, rotate, XOR a step
constant, add, rotate, add, rotate the right word again by a distance
that depends on its position - and permutes the sixteen words; a last
sub-message is XORed in after the last step.

The step constants are generated: the first eight words of each width
come from `lsh_tables.rs`, which `scripts/make_lsh_tables.py` reads out
of KISA's reference and Crypto++, and each step's are the step before's
plus themselves rotated by eight. The starting value of each output
length is the steps run with no message from a chaining value holding
the width in bytes and the output length in bits. The padding is a 1
bit and zeros to the end of a block, with no length; the output is the
two halves XORed, the leading bytes of it.

Names: `lsh256_224`, `lsh256_256`, `lsh512_224`, `lsh512_256`,
`lsh512_384`, `lsh512_512`.
*/

use super::buffer::BlockBuffer;
use super::lsh_tables::{SC0_256, SC0_512};
use super::HashFunction;

/// Where each word of the permuted chaining value comes from.
const SIGMA: [usize; 16] = [6, 4, 5, 7, 12, 15, 14, 13, 2, 0, 1, 3, 8, 11, 10, 9];
/// Where each word of a sub-message's predecessor-but-one comes from
/// before it is added.
const TAU: [usize; 16] = [3, 2, 0, 1, 7, 4, 5, 6, 11, 10, 8, 9, 15, 12, 13, 14];

macro_rules! lsh {
    ($name:ident, $word:ty, $block:literal, $steps:literal, $sc0:ident,
     even: ($ea:literal, $eb:literal), odd: ($oa:literal, $ob:literal),
     gamma: $gamma:expr) => {
        /// LSH in progress, at one width.
        #[derive(Clone)]
        pub struct $name {
            cv: [$word; 16],
            buffer: BlockBuffer<$block>,
            digest_len: usize,
        }

        impl $name {
            /// The widest output in bytes: eight words.
            const MAX: usize = 8 * core::mem::size_of::<$word>();
            const GAMMA: [u32; 8] = $gamma;

            /// The step constants: the first step's from the table, each
            /// after it the one before plus itself rotated by eight.
            const SC: [[$word; 8]; $steps] = {
                let mut sc = [$sc0; $steps];
                let mut step = 1;
                while step < $steps {
                    let mut i = 0;
                    while i < 8 {
                        let before = sc[step - 1][i];
                        sc[step][i] = before.rotate_left(8).wrapping_add(before);
                        i += 1;
                    }
                    step += 1;
                }
                sc
            };

            /// One step's mixing and permutation, after its sub-message.
            fn step(cv: &mut [$word; 16], sc: &[$word; 8], step: usize) {
                let (alpha, beta) = if step % 2 == 0 { ($ea, $eb) } else { ($oa, $ob) };
                for i in 0..8 {
                    let (mut l, mut r) = (cv[i], cv[i + 8]);
                    l = l.wrapping_add(r).rotate_left(alpha) ^ sc[i];
                    r = r.wrapping_add(l).rotate_left(beta);
                    l = l.wrapping_add(r);
                    cv[i] = l;
                    cv[i + 8] = r.rotate_left(Self::GAMMA[i]);
                }
                let before = *cv;
                for i in 0..16 {
                    cv[i] = before[SIGMA[i]];
                }
            }

            fn compress(cv: &mut [$word; 16], block: &[u8; $block]) {
                const W: usize = core::mem::size_of::<$word>();
                let m: [$word; 32] = core::array::from_fn(|i| {
                    <$word>::from_le_bytes(block[W * i..W * (i + 1)].try_into().expect("a word"))
                });
                let sc = &Self::SC;
                // The two sub-messages before this one: even, then odd.
                let mut even: [$word; 16] = m[..16].try_into().expect("16 words");
                let mut odd: [$word; 16] = m[16..].try_into().expect("16 words");
                for step in 0..$steps {
                    if step >= 2 {
                        let (newer, older) =
                            if step % 2 == 0 { (&odd, &even) } else { (&even, &odd) };
                        let next: [$word; 16] =
                            core::array::from_fn(|i| newer[i].wrapping_add(older[TAU[i]]));
                        if step % 2 == 0 { even = next } else { odd = next }
                    }
                    let sub = if step % 2 == 0 { &even } else { &odd };
                    for i in 0..16 {
                        cv[i] ^= sub[i];
                    }
                    Self::step(cv, &sc[step], step);
                }
                let last: [$word; 16] = core::array::from_fn(|i| odd[i].wrapping_add(even[TAU[i]]));
                for i in 0..16 {
                    cv[i] ^= last[i];
                }
            }

            /// LSH at this width with `digest_len` bytes of output.
            ///
            /// # Errors
            /// No bytes, or more than the width.
            pub fn new(digest_len: usize) -> Result<$name, String> {
                if digest_len == 0 || digest_len > Self::MAX {
                    return Err(format!("LSH-{} gives 1 to {} bytes, not {digest_len}.",
                                       8 * Self::MAX, Self::MAX));
                }
                let mut cv = [0 as $word; 16];
                cv[0] = Self::MAX as $word;
                cv[1] = 8 * digest_len as $word;
                let sc = &Self::SC;
                for step in 0..$steps {
                    Self::step(&mut cv, &sc[step], step);
                }
                Ok($name { cv, buffer: BlockBuffer::default(), digest_len })
            }
        }

        impl HashFunction for $name {
            fn name(&self) -> String {
                format!("lsh{}_{}", 8 * Self::MAX, 8 * self.digest_len)
            }

            fn digest_len(&self) -> usize {
                self.digest_len
            }

            fn block_size(&self) -> usize {
                $block
            }

            fn update(&mut self, input: &[u8]) {
                let cv = &mut self.cv;
                self.buffer.feed(input, |block| Self::compress(cv, block));
            }

            fn digest(&mut self) -> Vec<u8> {
                let mut last = self.clone();
                let mut tail = vec![0u8; $block - last.buffer.len()];
                tail[0] = 0x80;
                let cv = &mut last.cv;
                last.buffer.feed(&tail, |block| Self::compress(cv, block));
                debug_assert!(last.buffer.is_empty());
                (0..8).flat_map(|i| (last.cv[i] ^ last.cv[i + 8]).to_le_bytes())
                    .take(self.digest_len).collect()
            }
        }
    };
}

lsh!(Lsh256, u32, 128, 26, SC0_256, even: (29, 1), odd: (5, 17),
     gamma: [0, 8, 16, 24, 24, 16, 8, 0]);
lsh!(Lsh512, u64, 256, 28, SC0_512, even: (23, 59), odd: (7, 3),
     gamma: [0, 16, 32, 48, 8, 24, 40, 56]);
