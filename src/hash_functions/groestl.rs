/*!
Grøstl (Gauravaram, Knudsen, Matusiewicz, Mendel, Rechberger, Schläffer
and Thomsen, 2008), the SHA-3 finalist, as its team finally submitted
it: the round-3 version, whose round constants and Q's shifts were
tweaked from the first. Grøstl-224 and -256 on a 512 bit state with 10
rounds, Grøstl-384 and -512 on a 1024 bit state with 14.

The state is a matrix of 8 rows of bytes, filled column by column, with
8 or 16 columns. Two permutations, P and Q, each round adding a constant,
taking every byte through AES's S-box, shifting each row left by its own
distance and multiplying each column by the circulant matrix
circ(2, 2, 3, 4, 5, 3, 5, 7) in AES's field. A block is compressed as
`P(h ^ m) ^ Q(m) ^ h`, and the output is the last bytes of `P(h) ^ h`.

The starting value is the output length in bits, big endian, at the end
of an empty state. The padding is a 1 bit, zeros, and the number of
blocks - padding included - in a 64 bit big endian field, so a hash in
progress counts blocks rather than bytes.

Names: `groestl224`, `groestl256`, `groestl384`, `groestl512`.
*/

use super::buffer::BlockBuffer;
use super::HashFunction;
use crate::block_ciphers::aes::SBOX;

/// Doubling in AES's field.
const fn double(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

/// `x * k` in AES's field for the small `k` of the mixing matrix.
const fn times(x: u8, k: u8) -> u8 {
    let (x2, x4) = (double(x), double(double(x)));
    let mut out = 0;
    if k & 1 != 0 {
        out ^= x;
    }
    if k & 2 != 0 {
        out ^= x2;
    }
    if k & 4 != 0 {
        out ^= x4;
    }
    out
}

/// The mixing matrix's first row; row `i` is it turned right by `i`.
const B: [u8; 8] = [2, 2, 3, 4, 5, 3, 5, 7];

/// How far each row moves left: P's and Q's, at 8 and 16 columns.
const SHIFT_P8: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
const SHIFT_Q8: [usize; 8] = [1, 3, 5, 7, 0, 2, 4, 6];
const SHIFT_P16: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 11];
const SHIFT_Q16: [usize; 8] = [1, 3, 5, 11, 0, 2, 4, 6];

/// One of the two permutations on a state of `C` columns (byte `8j + i`
/// is row `i` of column `j`), for `rounds` rounds.
fn permute<const N: usize>(state: &mut [u8; N], q: bool, rounds: usize) {
    let columns = N / 8;
    let shift = match (q, columns) {
        (false, 8) => &SHIFT_P8,
        (true, 8) => &SHIFT_Q8,
        (false, _) => &SHIFT_P16,
        (true, _) => &SHIFT_Q16,
    };
    for round in 0..rounds {
        let r = round as u8;
        // The round constant: P's in row 0, Q's everywhere, its round
        // and column part in row 7.
        for j in 0..columns {
            let c = (j as u8) << 4;
            if q {
                for i in 0..7 {
                    state[8 * j + i] ^= 0xff;
                }
                state[8 * j + 7] ^= 0xff ^ c ^ r;
            } else {
                state[8 * j] ^= c ^ r;
            }
        }
        for byte in state.iter_mut() {
            *byte = SBOX[usize::from(*byte)];
        }
        let before = *state;
        for i in 0..8 {
            for j in 0..columns {
                state[8 * j + i] = before[8 * ((j + shift[i]) % columns) + i];
            }
        }
        for j in 0..columns {
            let column: [u8; 8] = state[8 * j..8 * j + 8].try_into().expect("a column");
            for i in 0..8 {
                state[8 * j + i] = (0..8)
                    .fold(0, |acc, k| acc ^ times(column[k], B[(k + 8 - i) % 8]));
            }
        }
    }
}

macro_rules! groestl {
    ($name:ident, $bytes:literal, $rounds:literal) => {
        /// Grøstl in progress.
        #[derive(Clone)]
        pub struct $name {
            state: [u8; $bytes],
            buffer: BlockBuffer<$bytes>,
            /// Blocks compressed so far.
            blocks: u64,
            digest_len: usize,
        }

        impl $name {
            fn compress(h: &mut [u8; $bytes], m: &[u8; $bytes]) {
                let mut p: [u8; $bytes] = core::array::from_fn(|i| h[i] ^ m[i]);
                let mut q = *m;
                permute(&mut p, false, $rounds);
                permute(&mut q, true, $rounds);
                for i in 0..$bytes {
                    h[i] ^= p[i] ^ q[i];
                }
            }

            fn make(digest_len: usize) -> $name {
                let mut state = [0u8; $bytes];
                state[$bytes - 2..].copy_from_slice(&(8 * digest_len as u16).to_be_bytes());
                $name { state, buffer: BlockBuffer::default(), blocks: 0, digest_len }
            }
        }

        impl HashFunction for $name {
            fn name(&self) -> String {
                format!("groestl{}", 8 * self.digest_len)
            }

            fn digest_len(&self) -> usize {
                self.digest_len
            }

            fn block_size(&self) -> usize {
                $bytes
            }

            fn update(&mut self, input: &[u8]) {
                let (state, blocks) = (&mut self.state, &mut self.blocks);
                self.buffer.feed(input, |block| {
                    *blocks = blocks.wrapping_add(1);
                    Self::compress(state, block);
                });
            }

            fn digest(&mut self) -> Vec<u8> {
                let mut last = self.clone();
                // The 1 bit, then zeros, so the count ends a block.
                let zeros = ($bytes + $bytes - 9 - last.buffer.len()) % $bytes;
                let tail_blocks = (last.buffer.len() + 9 + zeros) / $bytes;
                let total = last.blocks.wrapping_add(tail_blocks as u64);
                let mut tail = vec![0u8; 1 + zeros];
                tail[0] = 0x80;
                tail.extend_from_slice(&total.to_be_bytes());
                let state = &mut last.state;
                last.buffer.feed(&tail, |block| Self::compress(state, block));
                debug_assert!(last.buffer.is_empty());
                let mut out = last.state;
                permute(&mut out, false, $rounds);
                (0..$bytes).map(|i| out[i] ^ last.state[i]).skip($bytes - self.digest_len).collect()
            }
        }
    };
}

groestl!(GroestlSmall, 64, 10);
groestl!(GroestlBig, 128, 14);

impl GroestlSmall {
    /// Grøstl-224.
    pub fn groestl224() -> GroestlSmall {
        GroestlSmall::make(28)
    }

    /// Grøstl-256.
    pub fn groestl256() -> GroestlSmall {
        GroestlSmall::make(32)
    }
}

impl GroestlBig {
    /// Grøstl-384.
    pub fn groestl384() -> GroestlBig {
        GroestlBig::make(48)
    }

    /// Grøstl-512.
    pub fn groestl512() -> GroestlBig {
        GroestlBig::make(64)
    }
}
