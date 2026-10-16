/*!
Speck, the NSA's lightweight ARX ciphers (Beaulieu, Shors, Smith,
Treatman-Clark, Weeks and Wingers, 2013): additions, rotations and XORs
on two words. Every size the paper gives, one type per word size, the
key length choosing the variant and its round count:

| type, catalogue name | word | key bytes | rounds |
|---|---|---|---|
| `Speck32`, `speck32` | 16 bits | 8 | 22 |
| `Speck48`, `speck48` | 24 bits | 9 or 12 | 22 or 23 |
| `Speck64`, `speck64` | 32 bits | 12 or 16 | 26 or 27 |
| `Speck96`, `speck96` | 48 bits | 12 or 18 | 28 or 29 |
| `Speck128`, `speck128` | 64 bits | 16, 24 or 32 | 32, 33 or 34 |

## A round

`x = ((x >>> 8) + y) ^ k`, then `y = (y <<< 3) ^ x`, on words of the
type's size - Speck32 rotates by 7 and 2 instead. The 24- and 48-bit
words are held in a 32- and a 64-bit integer and masked after every
addition and rotation. The key schedule runs the same round on the key's
words with the round number as the key, so a round key is the first word
after `i` rounds.

## Byte order

The paper writes words most significant first, the block as `(x, y)`
and the key as `(l_{m-2}, ..., l_0, k_0)`, and prints its test vectors
that way. The designers have since said the bytes are the
little-endian encoding of those numbers - each word little-endian, `y`
before `x`, `k_0` first - which is how the Linux kernel, Crypto++ and
this module read them. The paper's printed vectors are those byte
strings reversed.

## Constant time

Additions, rotations and XORs only, with no table and no branch on
data.

## Where the vectors come from

`vectors/simon_speck.vec`, written by `scripts/make_simon_speck_vectors.py`:
at 64 and 128 bits, blocks on which Crypto++ 8.9.0, the Linux kernel's
Speck (v4.19), jedisct1/rust-lwbc (at 64 bits) and inmcm's Python
reference agree, with the published tests they carry; at 32, 48 and 96
bits, inmcm's and lwbc's, with the paper's tests. lwbc has one key
length at each of those sizes, 8, 12 and 18 bytes, so Speck48/72 and
Speck96/96 rest on inmcm and the paper alone.
*/

use super::BlockCipher;

macro_rules! speck {
    ($name:ident, $word:ty, $bits:expr, $alpha:expr, $beta:expr, $variants:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            round_keys: Vec<$word>,
        }

        impl $name {
            /// The key lengths, in bytes, and each one's round count.
            pub const VARIANTS: &'static [(usize, usize)] = $variants;
            /// A word's bytes, and the bits of the type holding it that it uses.
            const BYTES: usize = $bits / 8;
            const MASK: $word = <$word>::MAX >> (<$word>::BITS - $bits);

            fn rol(x: $word, r: u32) -> $word {
                ((x << r) | (x >> ($bits - r))) & Self::MASK
            }

            fn ror(x: $word, r: u32) -> $word {
                ((x >> r) | (x << ($bits - r))) & Self::MASK
            }

            /// A little-endian word.
            fn word(bytes: &[u8]) -> $word {
                bytes.iter().rev().fold(0, |w, &b| w << 8 | <$word>::from(b))
            }

            pub fn new(key: &[u8]) -> Result<$name, String> {
                let Some(&(_, rounds)) = Self::VARIANTS.iter().find(|(len, _)| *len == key.len())
                else {
                    let lengths: Vec<String> =
                        Self::VARIANTS.iter().map(|(len, _)| len.to_string()).collect();
                    return Err(format!("Wrong key length {}. {} takes a {} byte key.",
                                       key.len(), stringify!($name), lengths.join(" or ")));
                };
                let words: Vec<$word> = key.chunks_exact(Self::BYTES).map(Self::word).collect();
                let (mut k, mut l) = (words[0], words[1..].to_vec());
                let mut round_keys = Vec::with_capacity(rounds);
                for i in 0..rounds {
                    round_keys.push(k);
                    let at = i % l.len();
                    l[at] = (Self::ror(l[at], $alpha).wrapping_add(k) & Self::MASK) ^ (i as $word);
                    k = Self::rol(k, $beta) ^ l[at];
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
                    x = (Self::ror(x, $alpha).wrapping_add(y) & Self::MASK) ^ k;
                    y = Self::rol(y, $beta) ^ x;
                }
                Self::store(x, y, result);
            }

            fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
                let (mut x, mut y) = Self::load(input);
                for &k in self.round_keys.iter().rev() {
                    y = Self::ror(y ^ x, $beta);
                    x = Self::rol((x ^ k).wrapping_sub(y) & Self::MASK, $alpha);
                }
                Self::store(x, y, result);
            }
        }
    };
}

speck!(Speck32, u16, 16, 7, 2, &[(8, 22)],
       "Speck32/64: a 32-bit block and an 8 byte key.");
speck!(Speck48, u32, 24, 8, 3, &[(9, 22), (12, 23)],
       "Speck48/72 and Speck48/96: a 48-bit block and a 9 or 12 byte key.");
speck!(Speck64, u32, 32, 8, 3, &[(12, 26), (16, 27)],
       "Speck64/96 and Speck64/128: a 64-bit block and a 12 or 16 byte key.");
speck!(Speck96, u64, 48, 8, 3, &[(12, 28), (18, 29)],
       "Speck96/96 and Speck96/144: a 96-bit block and a 12 or 18 byte key.");
speck!(Speck128, u64, 64, 8, 3, &[(16, 32), (24, 33), (32, 34)],
       "Speck128/128, /192 and /256: a 128-bit block and a 16, 24 or 32 byte key.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_lengths_choose_the_rounds() {
        for len in [0, 8, 11, 13, 15, 17, 24, 32] {
            assert!(Speck64::new(&vec![0u8; len]).is_err(), "{len}");
        }
        for len in [0, 8, 12, 15, 17, 23, 25, 31, 33, 64] {
            assert!(Speck128::new(&vec![0u8; len]).is_err(), "{len}");
        }
        for (len, rounds) in [(12, 26), (16, 27)] {
            assert_eq!(Speck64::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
        for (len, rounds) in [(16, 32), (24, 33), (32, 34)] {
            assert_eq!(Speck128::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
    }

    /// The 32, 48 and 96 bit blocks: their key lengths and round counts,
    /// and decryption inverting encryption, with every byte 0xff too, so
    /// a 24- or 48-bit word that kept a carry would show.
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
        check(Speck32::new, 4, &[8]);
        check(Speck48::new, 6, &[9, 12]);
        check(Speck96::new, 12, &[12, 18]);
        for (len, rounds) in [(9, 22), (12, 23)] {
            assert_eq!(Speck48::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
        for (len, rounds) in [(12, 28), (18, 29)] {
            assert_eq!(Speck96::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
        assert_eq!(Speck32::new(&[0u8; 8]).unwrap().rounds(), 22);
    }

    /// The first round key is the key's first word as it stands.
    #[test]
    fn test_the_first_round_key_is_the_first_word() {
        let key: Vec<u8> = (1..=32).collect();
        assert_eq!(Speck128::new(&key).unwrap().round_keys[0],
                   u64::from_le_bytes(key[..8].try_into().unwrap()));
        assert_eq!(Speck64::new(&key[..16]).unwrap().round_keys[0],
                   u32::from_le_bytes(key[..4].try_into().unwrap()));
    }

    /// Decryption inverts encryption at every size.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x5bec_2013u32;
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
                let mut c = Speck64::new(&key).unwrap();
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block);
            }
            for len in [16, 24, 32] {
                let key: Vec<u8> = (0..len).map(|_| next()).collect();
                let block: Vec<u8> = (0..16).map(|_| next()).collect();
                let mut c = Speck128::new(&key).unwrap();
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block);
            }
        }
    }
}
