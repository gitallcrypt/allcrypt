/*
MD6 (Rivest et al., 2008), the SHA-3 submission withdrawn from the
second round. Unkeyed, with the default mode parameter L = 64 and the
default number of rounds, for digest sizes that are whole bytes from 8
to 512 bits.

## The compression function

It takes 89 64-bit words - the constant `Q` (15), the key `K` (8, zero
here), a node identifier `U`, a control word `V` and a 64-word data block
`B` - and runs a nonlinear feedback register over them: each new word is

    x = S ^ A[i-89] ^ A[i-17] ^ (A[i-18] & A[i-21]) ^ (A[i-31] & A[i-67])
    x ^= x >> r;  A[i] = x ^ (x << l)

with `r` and `l` cycling through sixteen values and `S` changing every
sixteen steps. After `16 * rounds` steps the last sixteen words are the
result. `rounds = 40 + d / 4` for a `d`-bit digest.

`Q` is the first 960 bits of the fractional part of the square root of
6. It is computed, not typed: `test_q_is_the_square_root_of_six`
recomputes it with integer arithmetic.

## The mode

A 4-ary tree. Level one compresses the message in 512-byte blocks, the
last one zero-padded; each compression gives 128 bytes, and level two
compresses those four to a block, and so on until a level has a single
block. That compression is the root, marked by `z = 1` in its control
word, and the digest is the last `d` bits of its output. A block is
compressed only once it is known whether it is the root, which is why
`update` keeps the last full block of each level back until more arrives.

`U` holds the level and the block's index within it; `V` holds the round
count, `L`, `z`, the number of padding bits, the key length and `d`.
Words are big endian throughout. With `L = 64` the sequential mode MD6
switches to above level 64 is never reached by any message that fits in
memory, so it is not implemented.
*/

use super::HashFunction;

/// The fractional part of sqrt(6), 960 bits, most significant word first.
const Q: [u64; 15] = [
    0x7311c2812425cfa0, 0x6432286434aac8e7, 0xb60450e9ef68b7c1, 0xe8fb23908d9f06f1,
    0xdd2e76cba691e5bf, 0x0cd0d63b2c30bc41, 0x1f8ccf6823058f8a, 0x54e5ed5b88e3775d,
    0x4ad12aae0a6d6031, 0x3e7f16bb88222e0d, 0x8af8671d3fb50c2c, 0x995ad1178bd25c31,
    0xc878c1dd04c4b633, 0x3b72066c7a1552ac, 0x0d6f3522631effcb,
];

/// The feedback taps, counting back from the word being made.
const TAPS: [usize; 5] = [17, 18, 21, 31, 67];
const RIGHT: [u32; 16] = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12];
const LEFT: [u32; 16] = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9];
/// The round constant's first value and its update mask:
/// `S' = (S <<< 1) ^ (S & S_STAR)`.
const S0: u64 = 0x0123_4567_89ab_cdef;
const S_STAR: u64 = 0x7311_c281_2425_cfa0;

const N: usize = 89;
const BLOCK: usize = 512;
const CHAINING: usize = 128;
/// The mode parameter: the tree is used up to this level.
const L: u64 = 64;

/// One compression: the 89 input words in, 16 words out.
fn compress(input: &[u64; N], rounds: usize) -> [u64; 16] {
    let t = 16 * rounds;
    let mut a = vec![0u64; N + t];
    a[..N].copy_from_slice(input);
    let mut s = S0;
    for i in N..N + t {
        let step = (i - N) % 16;
        let mut x = s ^ a[i - N] ^ a[i - TAPS[0]]
            ^ (a[i - TAPS[1]] & a[i - TAPS[2]])
            ^ (a[i - TAPS[3]] & a[i - TAPS[4]]);
        x ^= x >> RIGHT[step];
        a[i] = x ^ (x << LEFT[step]);
        if step == 15 {
            s = s.rotate_left(1) ^ (s & S_STAR);
        }
    }
    a[N + t - 16..].try_into().expect("16 words")
}

#[derive(Clone)]
struct Level {
    /// Bytes of this level's input not yet compressed: at most one block,
    /// held back until it is known whether more follows.
    pending: Vec<u8>,
    /// How many blocks this level has compressed.
    done: u64,
}

#[derive(Clone)]
pub struct Md6 {
    /// Digest size in bits.
    d: usize,
    rounds: usize,
    /// Levels one upwards.
    levels: Vec<Level>,
}

impl Md6 {
    /// MD6 with a `bits`-bit digest: a multiple of 8 from 8 to 512.
    pub fn new(bits: usize) -> Result<Md6, String> {
        if bits == 0 || bits > 512 || !bits.is_multiple_of(8) {
            return Err(format!("An MD6 digest here is a whole number of bytes from 8 to 512 \
                                bits; {bits} is not."));
        }
        Ok(Md6 {
            d: bits,
            rounds: 40 + bits / 4,
            levels: vec![Level { pending: Vec::with_capacity(BLOCK), done: 0 }],
        })
    }

    /// Compress one block of `level` (counted from zero here, so the
    /// identifier's level is `level + 1`) with `padding` bits of zeros at
    /// its end.
    fn compress_block(&self, level: usize, index: u64, block: &[u8], padding: usize, last: bool)
                      -> [u64; 16] {
        let mut words = [0u64; N];
        words[..15].copy_from_slice(&Q);
        // words[15..23]: the key, zero.
        words[23] = ((level as u64 + 1) << 56) | index;
        words[24] = ((self.rounds as u64) << 48) | (L << 40) | ((last as u64) << 36)
            | ((padding as u64) << 20) | (self.d as u64);
        let mut padded = [0u8; BLOCK];
        padded[..block.len()].copy_from_slice(block);
        for (word, bytes) in words[25..].iter_mut().zip(padded.chunks_exact(8)) {
            *word = u64::from_be_bytes(bytes.try_into().expect("8 bytes"));
        }
        compress(&words, self.rounds)
    }

    /// Add `input` to `level`, compressing every block that is followed
    /// by more input and passing its output up.
    fn feed(&mut self, level: usize, mut input: &[u8]) {
        while !input.is_empty() {
            if self.levels[level].pending.len() == BLOCK {
                // More follows, so the held-back block is not the last.
                let block = core::mem::take(&mut self.levels[level].pending);
                let index = self.levels[level].done;
                let output = self.compress_block(level, index, &block, 0, false);
                self.levels[level].done += 1;
                self.levels[level].pending = block;
                self.levels[level].pending.clear();
                if self.levels.len() == level + 1 {
                    self.levels.push(Level { pending: Vec::with_capacity(BLOCK), done: 0 });
                }
                let bytes: Vec<u8> = output.iter().flat_map(|w| w.to_be_bytes()).collect();
                self.feed(level + 1, &bytes);
            }
            let take = (BLOCK - self.levels[level].pending.len()).min(input.len());
            self.levels[level].pending.extend_from_slice(&input[..take]);
            input = &input[take..];
        }
    }

    fn finish(&self) -> Vec<u8> {
        let mut state = self.clone();
        let mut level = 0;
        loop {
            let above = state.levels.len() > level + 1;
            let pending = core::mem::take(&mut state.levels[level].pending);
            let padding = (BLOCK - pending.len()) * 8;
            let index = state.levels[level].done;
            // The root: the only block this level will ever compress, and
            // nothing above it.
            let root = index == 0 && !above;
            let output = state.compress_block(level, index, &pending, padding, root);
            if root {
                let bytes: Vec<u8> = output.iter().flat_map(|w| w.to_be_bytes()).collect();
                return bytes[CHAINING - self.d / 8..].to_vec();
            }
            if !above {
                state.levels.push(Level { pending: Vec::with_capacity(BLOCK), done: 0 });
            }
            let bytes: Vec<u8> = output.iter().flat_map(|w| w.to_be_bytes()).collect();
            state.feed(level + 1, &bytes);
            level += 1;
        }
    }
}

impl HashFunction for Md6 {
    fn name(&self) -> String { format!("md6_{}", self.d) }

    fn digest_len(&self) -> usize { self.d / 8 }

    fn block_size(&self) -> usize { BLOCK }

    fn update(&mut self, input: &[u8]) {
        self.feed(0, input);
    }

    fn digest(&mut self) -> Vec<u8> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::BigUint;

    /// `Q` against the integer square root of `6 * 2^1920`, by Newton's
    /// method on `BigUint`: the integer part is 2, and what follows it is
    /// `Q`.
    #[test]
    fn test_q_is_the_square_root_of_six() {
        let target = BigUint::from_u64(6).shl(1920);
        let mut x = BigUint::from_u64(3).shl(960);
        loop {
            // x' = (x + target / x) / 2
            let (quotient, _) = target.divrem(&x).unwrap();
            let next = x.add(&quotient).shr(1);
            if next >= x {
                break;
            }
            x = next;
        }
        let fraction = x.sub(&BigUint::from_u64(2).shl(960)).unwrap();
        let mut bytes = fraction.to_bytes_be();
        while bytes.len() < 120 {
            bytes.insert(0, 0);
        }
        let words: Vec<u64> = bytes.chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap())).collect();
        assert_eq!(words, Q.to_vec());
    }

    #[test]
    fn test_only_whole_byte_sizes() {
        for bits in [0usize, 7, 9, 513, 1024] {
            assert!(Md6::new(bits).is_err(), "{bits}");
        }
        for bits in [8usize, 128, 224, 256, 384, 512] {
            assert_eq!(Md6::new(bits).unwrap().digest_len(), bits / 8);
        }
    }

    /// Streaming in pieces against one call, across block boundaries and
    /// into the second and third tree levels (2,048 bytes fill one
    /// level-two block; 8,192 reach level three).
    #[test]
    fn test_streaming_agrees_and_digest_repeats() {
        let data: Vec<u8> = (0..9000u32).map(|i| (i * 167 + 29) as u8).collect();
        for length in [0usize, 1, 511, 512, 513, 1024, 2047, 2048, 2049, 4096, 8192, 8193, 9000] {
            let mut whole = Md6::new(256).unwrap();
            whole.update(&data[..length]);
            let want = whole.digest();
            assert_eq!(whole.digest(), want, "repeated, {length}");
            for size in [1usize, 100, 512, 700] {
                let mut pieces = Md6::new(256).unwrap();
                for chunk in data[..length].chunks(size) {
                    pieces.update(chunk);
                }
                assert_eq!(pieces.digest(), want, "{length} in {size}");
            }
        }
    }
}
