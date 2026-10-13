/*!
Skein (Ferguson, Lucks, Schneier, Whiting, Bellare, Kohno, Callas and
Walker, 2008), the SHA-3 finalist, as finally submitted: version 1.3,
on Threefish-256, -512 and -1024, with any whole number of bytes out.

Threefish is a tweakable block cipher on 4, 8 or 16 64 bit words: 72
rounds (80 at 1024 bits) of adding pairs of words, rotating one of them
by a distance that depends on the round and the pair (`skein_tables.rs`,
read by `scripts/make_skein_tables.py` out of the Skein team's own
header), XORing it into the sum, and permuting the words; and every four
rounds a subkey, taken from the key words, a parity word, the tweak and
the subkey's number. Skein chains it in UBI mode: each block is
encrypted under the chaining value with a tweak carrying the bytes
processed so far, the block's type and whether it is the first or the
last, and XORed back in.

A hash is three UBI passes: a configuration block (the schema "SHA3",
version 1, the output length in bits and no tree) from zero, which gives
the starting value, the message, and the output pass, which encrypts an
eight byte counter for every block of output wanted. An empty message is
one block of zeros counted as no bytes.

Names: `skein256_256` and the others of the form `skeinSTATE_BITS`,
STATE 256, 512 or 1024 and BITS a multiple of 8 from 8 up, so
`skein512_256` is Skein-512-256; the catalogue lists the sizes the Skein
submission and sphlib name. The concrete type takes any output length
in bytes.
*/

use super::buffer::BlockBuffer;
use super::skein_tables::{R1024, R256, R512};
use super::HashFunction;

/// The key schedule's parity constant.
const C240: u64 = 0x1BD1_1BDA_A9FC_1A22;

/// The word permutation after each round, at 4, 8 and 16 words.
const PI4: [usize; 4] = [0, 3, 2, 1];
const PI8: [usize; 8] = [2, 1, 4, 7, 6, 5, 0, 3];
const PI16: [usize; 16] = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1];

/// The tweak's block types.
const CFG: u64 = 4;
const MSG: u64 = 48;
const OUT: u64 = 63;

/// Threefish-`64 N`: `block` encrypted under `key` and `tweak`.
fn threefish<const N: usize>(key: &[u64; N], tweak: [u64; 2], block: &[u64; N]) -> [u64; N] {
    let (rounds, pi): (usize, &[usize]) = match N {
        4 => (72, &PI4),
        8 => (72, &PI8),
        _ => (80, &PI16),
    };
    let rotation = |d: usize, j: usize| match N {
        4 => R256[d % 8][j],
        8 => R512[d % 8][j],
        _ => R1024[d % 8][j],
    };
    let mut k = [0u64; 17];
    k[..N].copy_from_slice(key);
    k[N] = key.iter().fold(C240, |a, w| a ^ w);
    let t = [tweak[0], tweak[1], tweak[0] ^ tweak[1]];
    let subkey = |s: usize| -> [u64; N] {
        core::array::from_fn(|i| {
            let mut w = k[(s + i) % (N + 1)];
            if i == N - 3 {
                w = w.wrapping_add(t[s % 3]);
            } else if i == N - 2 {
                w = w.wrapping_add(t[(s + 1) % 3]);
            } else if i == N - 1 {
                w = w.wrapping_add(s as u64);
            }
            w
        })
    };
    let mut v = *block;
    for d in 0..rounds {
        if d % 4 == 0 {
            let key = subkey(d / 4);
            for (x, y) in v.iter_mut().zip(key) {
                *x = x.wrapping_add(y);
            }
        }
        for j in 0..N / 2 {
            let (a, b) = (v[2 * j], v[2 * j + 1]);
            let sum = a.wrapping_add(b);
            v[2 * j] = sum;
            v[2 * j + 1] = b.rotate_left(rotation(d, j)) ^ sum;
        }
        let before = v;
        for i in 0..N {
            v[i] = before[pi[i]];
        }
    }
    let key = subkey(rounds / 4);
    for (x, y) in v.iter_mut().zip(key) {
        *x = x.wrapping_add(y);
    }
    v
}

/// Skein in progress, on `N` 64 bit words, `B = 8 N` bytes a block.
#[derive(Clone)]
pub struct Skein<const N: usize, const B: usize> {
    chain: [u64; N],
    buffer: BlockBuffer<B>,
    /// The last whole block, not yet processed: the last block of the
    /// message is processed differently, and only `digest` knows which
    /// that is.
    held: Option<[u8; B]>,
    /// Message bytes processed so far, up to 2^96.
    position: u128,
    digest_len: usize,
}

pub type Skein256 = Skein<4, 32>;
pub type Skein512 = Skein<8, 64>;
pub type Skein1024 = Skein<16, 128>;

fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().expect("8 bytes"))
    })
}

impl<const N: usize, const B: usize> Skein<N, B> {
    /// Skein on `64 N` bits of state with `digest_len` bytes of output.
    ///
    /// # Errors
    /// An output of no bytes.
    pub fn new(digest_len: usize) -> Result<Skein<N, B>, String> {
        assert_eq!(B, 8 * N, "a block is the state");
        if digest_len == 0 {
            return Err("Skein gives at least one byte of output.".to_string());
        }
        let mut config = [0u8; 32];
        config[..4].copy_from_slice(b"SHA3");
        config[4..6].copy_from_slice(&1u16.to_le_bytes());
        config[8..16].copy_from_slice(&(8 * digest_len as u64).to_le_bytes());
        let mut chain = [0u64; N];
        Self::ubi(&mut chain, &config, 32, true, true, CFG);
        Ok(Skein { chain, buffer: BlockBuffer::default(), held: None, position: 0, digest_len })
    }

    /// One UBI block: `block` (zero-padded to a whole one) ending at
    /// `position` bytes into its pass, of type `kind`.
    fn ubi(chain: &mut [u64; N], block: &[u8], position: u128, first: bool, last: bool,
           kind: u64) {
        let mut padded = [0u8; 128];
        padded[..block.len()].copy_from_slice(block);
        let m = words::<N>(&padded);
        let tweak = [position as u64,
                     (position >> 64) as u64 | kind << 56 | u64::from(first) << 62
                         | u64::from(last) << 63];
        let e = threefish(chain, tweak, &m);
        for i in 0..N {
            chain[i] = e[i] ^ m[i];
        }
    }

    /// A message block that is not the last.
    fn absorb(chain: &mut [u64; N], position: &mut u128, block: &[u8; B]) {
        let first = *position == 0;
        *position = position.wrapping_add(B as u128);
        Self::ubi(chain, block, *position, first, false, MSG);
    }
}

impl<const N: usize, const B: usize> HashFunction for Skein<N, B> {
    fn name(&self) -> String {
        format!("skein{}_{}", 64 * N, 8 * self.digest_len)
    }

    fn digest_len(&self) -> usize {
        self.digest_len
    }

    fn block_size(&self) -> usize {
        B
    }

    fn update(&mut self, input: &[u8]) {
        let (chain, held, position) = (&mut self.chain, &mut self.held, &mut self.position);
        self.buffer.feed(input, |block| {
            if let Some(previous) = held.replace(*block) {
                Self::absorb(chain, position, &previous);
            }
        });
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut chain = self.chain;
        let mut position = self.position;
        // The last block is the bytes waiting if there are any, else the
        // held block, else - for an empty message - no bytes at all.
        let last: Vec<u8> = match (self.buffer.is_empty(), self.held) {
            (false, held) => {
                if let Some(previous) = held {
                    Self::absorb(&mut chain, &mut position, &previous);
                }
                self.buffer.buffered().to_vec()
            }
            (true, Some(previous)) => previous.to_vec(),
            (true, None) => Vec::new(),
        };
        let first = position == 0;
        position = position.wrapping_add(last.len() as u128);
        Self::ubi(&mut chain, &last, position, first, true, MSG);
        let mut out = Vec::with_capacity(self.digest_len + B);
        let mut counter = 0u64;
        while out.len() < self.digest_len {
            let mut block = chain;
            Self::ubi(&mut block, &counter.to_le_bytes(), 8, true, true, OUT);
            out.extend(block.iter().flat_map(|w| w.to_le_bytes()));
            counter += 1;
        }
        out.truncate(self.digest_len);
        out
    }
}
