/*!
Simon, Speck's sibling from the same NSA team (2013), built for
hardware: a Feistel network whose round function is ANDs, rotations
and XORs on one word. Every size the paper gives, one type per word
size, the key length choosing the variant, its round count and its
sequence:

| type, catalogue name | word | key bytes | rounds | sequence |
|---|---|---|---|---|
| `Simon32`, `simon32` | 16 bits | 8 | 32 | z0 |
| `Simon48`, `simon48` | 24 bits | 9 or 12 | 36 | z0 or z1 |
| `Simon64`, `simon64` | 32 bits | 12 or 16 | 42 or 44 | z2 or z3 |
| `Simon96`, `simon96` | 48 bits | 12 or 18 | 52 or 54 | z2 or z3 |
| `Simon128`, `simon128` | 64 bits | 16, 24 or 32 | 68, 69 or 72 | z2, z3 or z4 |

The 24- and 48-bit words are held in a 32- and a 64-bit integer and
masked after every rotation and complement.

## A round

`(x, y)` becomes `(y ^ f(x) ^ k, x)`, with
`f(x) = (x <<< 1 & x <<< 8) ^ x <<< 2`.

## The key schedule

The key's `m` words are the first `m` round keys. Each later one is the
one `m` before, complemented, XORed with the previous word rotated right
by 3 - and, with four key words, the one three before - then with that
rotated right by 1, with the constant 3, and with one bit of the
variant's 62-bit sequence. The five sequences are read from
`simon_table.rs`, generated from three implementations' tables, each
sequence from at least two, which must agree.

## Byte order

As Speck: the paper's numbers, each word little-endian, the block's `y`
before its `x` and the key's first word first. The paper's printed
vectors are these byte strings reversed.

## Constant time

ANDs, rotations and XORs only, with no table and no branch on data.

## Where the vectors come from

`vectors/simon_speck.vec`, written by `scripts/make_simon_speck_vectors.py`:
at 64 and 128 bits, blocks on which Crypto++ 8.9.0, jedisct1/rust-lwbc
(at 64 bits) and inmcm's Python reference agree, with the published
tests they carry; at 32, 48 and 96 bits, inmcm's and lwbc's, with the
paper's tests. lwbc has one key length at each of those sizes, 8, 12
and 18 bytes, so Simon48/72 and Simon96/96 rest on inmcm and the paper
alone.
*/

use super::simon_table::Z;
use super::BlockCipher;

macro_rules! simon {
    ($name:ident, $word:ty, $bits:expr, $variants:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            round_keys: Vec<$word>,
        }

        impl $name {
            /// The key lengths, in bytes, each one's round count and its
            /// sequence: `j` for `z_j`, an index into `Z`.
            pub const VARIANTS: &'static [(usize, usize, usize)] = $variants;
            /// A word's bytes, and the bits of the type holding it that it uses.
            const BYTES: usize = $bits / 8;
            const MASK: $word = <$word>::MAX >> (<$word>::BITS - $bits);

            fn rol(x: $word, r: u32) -> $word {
                ((x << r) | (x >> ($bits - r))) & Self::MASK
            }

            fn ror(x: $word, r: u32) -> $word {
                ((x >> r) | (x << ($bits - r))) & Self::MASK
            }

            fn f(x: $word) -> $word {
                (Self::rol(x, 1) & Self::rol(x, 8)) ^ Self::rol(x, 2)
            }

            /// A little-endian word.
            fn word(bytes: &[u8]) -> $word {
                bytes.iter().rev().fold(0, |w, &b| w << 8 | <$word>::from(b))
            }

            pub fn new(key: &[u8]) -> Result<$name, String> {
                let Some(&(_, rounds, z)) = Self::VARIANTS.iter().find(|v| v.0 == key.len())
                else {
                    let lengths: Vec<String> =
                        Self::VARIANTS.iter().map(|v| v.0.to_string()).collect();
                    return Err(format!("Wrong key length {}. {} takes a {} byte key.",
                                       key.len(), stringify!($name), lengths.join(" or ")));
                };
                let mut round_keys: Vec<$word> =
                    key.chunks_exact(Self::BYTES).map(Self::word).collect();
                let m = round_keys.len();
                for i in m..rounds {
                    let mut t = Self::ror(round_keys[i - 1], 3);
                    if m == 4 {
                        t ^= round_keys[i - 3];
                    }
                    t ^= Self::ror(t, 1);
                    let bit = ((Z[z] >> ((i - m) % 62)) & 1) as $word;
                    round_keys.push((!round_keys[i - m] & Self::MASK) ^ t ^ bit ^ 3);
                }
                Ok($name { round_keys })
            }

            pub fn rounds(&self) -> usize {
                self.round_keys.len()
            }

            fn load(input: &[u8]) -> ($word, $word) {
                let y = Self::word(&input[..Self::BYTES]);
                let x = Self::word(&input[Self::BYTES..2 * Self::BYTES]);
                (x, y)
            }

            fn store(x: $word, y: $word, result: &mut Vec<u8>) {
                result.extend_from_slice(&y.to_le_bytes()[..Self::BYTES]);
                result.extend_from_slice(&x.to_le_bytes()[..Self::BYTES]);
            }
        }

        impl BlockCipher for $name {
            fn blocksize(&self) -> usize {
                2 * Self::BYTES
            }

            fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
                let (mut x, mut y) = Self::load(input);
                for &k in &self.round_keys {
                    (x, y) = (y ^ Self::f(x) ^ k, x);
                }
                Self::store(x, y, result);
            }

            fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
                let (mut x, mut y) = Self::load(input);
                for &k in self.round_keys.iter().rev() {
                    (x, y) = (y, x ^ Self::f(y) ^ k);
                }
                Self::store(x, y, result);
            }
        }
    };
}

simon!(Simon32, u16, 16, &[(8, 32, 0)],
       "Simon32/64: a 32-bit block and an 8 byte key.");
simon!(Simon48, u32, 24, &[(9, 36, 0), (12, 36, 1)],
       "Simon48/72 and Simon48/96: a 48-bit block and a 9 or 12 byte key.");
simon!(Simon64, u32, 32, &[(12, 42, 2), (16, 44, 3)],
       "Simon64/96 and Simon64/128: a 64-bit block and a 12 or 16 byte key.");
simon!(Simon96, u64, 48, &[(12, 52, 2), (18, 54, 3)],
       "Simon96/96 and Simon96/144: a 96-bit block and a 12 or 18 byte key.");
simon!(Simon128, u64, 64, &[(16, 68, 2), (24, 69, 3), (32, 72, 4)],
       "Simon128/128, /192 and /256: a 128-bit block and a 16, 24 or 32 byte key.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_lengths_choose_the_rounds() {
        for len in [0, 8, 11, 13, 15, 17, 24, 32] {
            assert!(Simon64::new(&vec![0u8; len]).is_err(), "{len}");
        }
        for len in [0, 8, 12, 15, 17, 23, 25, 31, 33, 64] {
            assert!(Simon128::new(&vec![0u8; len]).is_err(), "{len}");
        }
        for (len, rounds) in [(12, 42), (16, 44)] {
            assert_eq!(Simon64::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
        for (len, rounds) in [(16, 68), (24, 69), (32, 72)] {
            assert_eq!(Simon128::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
    }

    /// The sequences are 62 bits, and none is another's rotation or
    /// complement: each variant's schedule is its own.
    #[test]
    fn test_the_sequences_are_distinct() {
        for (i, &z) in Z.iter().enumerate() {
            assert_eq!(z >> 62, 0, "{i}");
            for (j, &w) in Z.iter().enumerate().skip(i + 1) {
                for r in 0..62 {
                    let rotated = ((w >> r) | (w << (62 - r))) & ((1 << 62) - 1);
                    assert_ne!(z, rotated, "{i} {j} {r}");
                    assert_ne!(z, !rotated & ((1 << 62) - 1), "{i} {j} {r}");
                }
            }
        }
    }

    /// The 32, 48 and 96 bit blocks: their key lengths and round counts,
    /// and decryption inverting encryption, with every byte 0xff too, so
    /// a 24- or 48-bit word that kept a stray bit would show.
    #[test]
    fn test_the_other_block_sizes() {
        fn check<C: BlockCipher>(new: fn(&[u8]) -> Result<C, String>, block: usize,
                                 lengths: &[usize]) {
            for len in 0..40 {
                assert_eq!(new(&vec![0u8; len]).is_ok(), lengths.contains(&len), "{len}");
            }
            for &len in lengths {
                for byte in [0x00, 0x5a, 0xff] {
                    let mut c = new(&vec![byte; len]).unwrap();
                    let (mut out, mut back) = (Vec::new(), Vec::new());
                    c.block_encrypt(&vec![byte; block], &mut out);
                    assert_eq!(out.len(), block);
                    c.block_decrypt(&out, &mut back);
                    assert_eq!(back, vec![byte; block]);
                }
            }
        }
        check(Simon32::new, 4, &[8]);
        check(Simon48::new, 6, &[9, 12]);
        check(Simon96::new, 12, &[12, 18]);
        assert_eq!(Simon32::new(&[0u8; 8]).unwrap().rounds(), 32);
        for (len, rounds) in [(9, 36), (12, 36)] {
            assert_eq!(Simon48::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
        for (len, rounds) in [(12, 52), (18, 54)] {
            assert_eq!(Simon96::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
    }

    /// The first `m` round keys are the key's words as they stand.
    #[test]
    fn test_the_first_round_keys_are_the_key() {
        let key: Vec<u8> = (1..=32).collect();
        let c = Simon128::new(&key).unwrap();
        for i in 0..4 {
            assert_eq!(c.round_keys[i], u64::from_le_bytes(key[8 * i..8 * i + 8].try_into().unwrap()));
        }
    }

    /// Decryption inverts encryption at every size.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x5130_2013u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..16 {
            for len in [12, 16] {
                let key: Vec<u8> = (0..len).map(|_| next()).collect();
                let block: Vec<u8> = (0..8).map(|_| next()).collect();
                let mut c = Simon64::new(&key).unwrap();
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block);
            }
            for len in [16, 24, 32] {
                let key: Vec<u8> = (0..len).map(|_| next()).collect();
                let block: Vec<u8> = (0..16).map(|_| next()).collect();
                let mut c = Simon128::new(&key).unwrap();
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block);
            }
        }
    }
}
