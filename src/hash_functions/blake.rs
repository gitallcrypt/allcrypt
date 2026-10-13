/*!
BLAKE (Aumasson, Henzen, Meier and Phan, 2008), the SHA-3 finalist, as
its designers' final submission defines it: BLAKE-224 and BLAKE-256 on
32 bit words with 14 rounds, BLAKE-384 and BLAKE-512 on 64 bit words
with 16. Not BLAKE2, which came after and changed the rounds, the
padding and the initial state; and not the earlier submissions' BLAKE-32
and BLAKE-64, which ran 10 and 14 rounds.

A HAIFA construction: each block is compressed with the number of
message bits hashed so far, counting the block's own, and a salt, which
is zero here. The compression function keeps a 16 word state, the
chaining value above four words of salt XOR constant and four of counter
XOR constant, and runs ChaCha's quarter-round over columns and diagonals,
each step taking a message word XORed with a constant, the pairs chosen
by the same ten permutations BLAKE2 later kept (`SIGMA`, cycled). The
constants are the first sixteen words of the fraction of pi (the same
words as HAVAL's, whose test computes them); the initial values are
SHA-2's at the same size.

The padding is a 1 bit, zeros, a bit that is 1 for BLAKE-256 and -512
and 0 for -224 and -384, and the message length in bits, big endian, in
64 or 128 bits. A block that holds padding alone is compressed with a
counter of zero, not the length - the one rule here a careless reading
gets wrong only for messages that end near a block boundary.

Names: `blake224`, `blake256`, `blake384`, `blake512`.
*/

use super::blake2::SIGMA;
use super::buffer::BlockBuffer;
use super::haval::{IV as PI_0_8, K as PI_8_136};
use super::sha2::{H224, H256, H384, H512};
use super::HashFunction;

/// The fraction of pi in 32 bit words, the first `N`.
const fn pi32<const N: usize>() -> [u32; N] {
    let mut out = [0u32; N];
    let mut i = 0;
    while i < N {
        out[i] = if i < 8 { PI_0_8[i] } else { PI_8_136[(i - 8) / 32][(i - 8) % 32] };
        i += 1;
    }
    out
}

/// BLAKE-256's sixteen constants.
const C32: [u32; 16] = pi32::<16>();

/// BLAKE-512's sixteen constants: the same digits, 64 bits at a time.
const C64: [u64; 16] = {
    let words = pi32::<32>();
    let mut out = [0u64; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (words[2 * i] as u64) << 32 | words[2 * i + 1] as u64;
        i += 1;
    }
    out
};

macro_rules! blake {
    ($name:ident, $word:ty, $counter:ty, $block:literal, $rounds:literal, $c:ident,
     [$r1:literal, $r2:literal, $r3:literal, $r4:literal]) => {
        /// BLAKE in progress.
        #[derive(Clone)]
        pub struct $name {
            state: [$word; 8],
            buffer: BlockBuffer<$block>,
            /// Message bits compressed so far; with the bytes waiting,
            /// the message's length.
            counter: $counter,
            digest_len: usize,
        }

        impl $name {
            const W: usize = core::mem::size_of::<$word>();

            fn compress(h: &mut [$word; 8], block: &[u8; $block], counter: $counter) {
                let m: [$word; 16] = core::array::from_fn(|i| {
                    <$word>::from_be_bytes(block[Self::W * i..Self::W * (i + 1)]
                                           .try_into().expect("a word"))
                });
                let (t0, t1) = (counter as $word, (counter >> (8 * Self::W)) as $word);
                let mut v = [0 as $word; 16];
                v[..8].copy_from_slice(h);
                v[8..12].copy_from_slice(&$c[..4]);
                v[12] = t0 ^ $c[4];
                v[13] = t0 ^ $c[5];
                v[14] = t1 ^ $c[6];
                v[15] = t1 ^ $c[7];
                // The four columns, then the four diagonals.
                const STEPS: [[usize; 4]; 8] = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14],
                                                [3, 7, 11, 15], [0, 5, 10, 15], [1, 6, 11, 12],
                                                [2, 7, 8, 13], [3, 4, 9, 14]];
                for round in 0..$rounds {
                    let s = &SIGMA[round % 10];
                    for (i, [a, b, c, d]) in STEPS.into_iter().enumerate() {
                        let (x, y) = (s[2 * i], s[2 * i + 1]);
                        v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[x] ^ $c[y]);
                        v[d] = (v[d] ^ v[a]).rotate_right($r1);
                        v[c] = v[c].wrapping_add(v[d]);
                        v[b] = (v[b] ^ v[c]).rotate_right($r2);
                        v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[y] ^ $c[x]);
                        v[d] = (v[d] ^ v[a]).rotate_right($r3);
                        v[c] = v[c].wrapping_add(v[d]);
                        v[b] = (v[b] ^ v[c]).rotate_right($r4);
                    }
                }
                for i in 0..8 {
                    h[i] ^= v[i] ^ v[i + 8];
                }
            }

            fn make(iv: [$word; 8], digest_len: usize) -> $name {
                $name { state: iv, buffer: BlockBuffer::default(), counter: 0, digest_len }
            }
        }

        impl HashFunction for $name {
            fn name(&self) -> String {
                format!("blake{}", 8 * self.digest_len)
            }

            fn digest_len(&self) -> usize {
                self.digest_len
            }

            fn block_size(&self) -> usize {
                $block
            }

            fn update(&mut self, input: &[u8]) {
                let (state, counter) = (&mut self.state, &mut self.counter);
                self.buffer.feed(input, |block| {
                    *counter = counter.wrapping_add(8 * $block);
                    Self::compress(state, block, *counter);
                });
            }

            fn digest(&mut self) -> Vec<u8> {
                let mut last = self.clone();
                let waiting = last.buffer.len();
                let bits = last.counter.wrapping_add(8 * waiting as $counter);
                // The 1 bit and zeros, ending in the size's final bit -
                // one byte, 0x81, when only one is free - then the length
                // in the counter's width.
                let field = core::mem::size_of::<$counter>();
                let marked = 1 + ($block + $block - field - waiting - 1) % $block;
                let mut tail = vec![0u8; marked];
                tail[0] = 0x80;
                if self.digest_len == 8 * Self::W {
                    tail[marked - 1] |= 0x01;
                }
                tail.extend_from_slice(&bits.to_be_bytes());
                // Every block of the tail that holds message bits is
                // compressed with the whole length; one of padding alone
                // with zero.
                let mut message = waiting;
                let state = &mut last.state;
                last.buffer.feed(&tail, |block| {
                    let counter = if message > 0 { bits } else { 0 };
                    message = 0;
                    Self::compress(state, block, counter);
                });
                debug_assert!(last.buffer.is_empty());
                last.state.iter().flat_map(|w| w.to_be_bytes()).take(self.digest_len).collect()
            }
        }
    };
}

blake!(BlakeSmall, u32, u64, 64, 14, C32, [16, 12, 8, 7]);
blake!(BlakeBig, u64, u128, 128, 16, C64, [32, 25, 16, 11]);

impl BlakeSmall {
    /// BLAKE-224.
    pub fn blake224() -> BlakeSmall {
        BlakeSmall::make(H224, 28)
    }

    /// BLAKE-256.
    pub fn blake256() -> BlakeSmall {
        BlakeSmall::make(H256, 32)
    }
}

impl BlakeBig {
    /// BLAKE-384.
    pub fn blake384() -> BlakeBig {
        BlakeBig::make(H384, 48)
    }

    /// BLAKE-512.
    pub fn blake512() -> BlakeBig {
        BlakeBig::make(H512, 64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The counter past 32 bits, which no message the tests can hash
    /// reaches: a hash told it has already taken `taken` bytes, against
    /// sphlib and the BLAKE team's reference told the same
    /// (`vectors/sha3_finalists.vec`'s `after` rows). BLAKE-256's counter
    /// carries into its high word in the middle of a message, and wraps
    /// past 2^64 bits; BLAKE-512's high word is set from the start.
    #[test]
    fn test_the_counter_past_32_bits() {
        let text = include_str!("../../vectors/sha3_finalists.vec");
        let field = |line: &'static str| -> std::collections::HashMap<&'static str, &'static str> {
            line.split(' ').skip(1).map(|w| w.split_once('=').expect("field")).collect()
        };
        let messages: Vec<Vec<u8>> = text.lines().filter(|l| l.starts_with("msg ")).map(|l| {
            let data = field(l)["data"];
            if data == "-" {
                return Vec::new();
            }
            (0..data.len()).step_by(2)
                .map(|i| u8::from_str_radix(&data[i..i + 2], 16).expect("hex")).collect()
        }).collect();
        let rows: Vec<_> = text.lines().filter(|l| l.starts_with("after ")).map(field).collect();
        assert_eq!(rows.len(), 24);
        for row in rows {
            let taken: u64 = row["taken"].parse().expect("taken");
            let message = &messages[row["msg"].parse::<usize>().expect("msg")];
            let got = match row["name"] {
                "blake256" => {
                    let mut h = BlakeSmall::blake256();
                    h.counter = taken.wrapping_mul(8);
                    h.update(message);
                    h.digest()
                }
                _ => {
                    let mut h = BlakeBig::blake512();
                    h.counter = u128::from(taken) * 8;
                    h.update(message);
                    h.digest()
                }
            };
            let got: String = got.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, row["digest"], "{} after {taken} bytes, then {}", row["name"],
                       message.len());
        }
    }
}
