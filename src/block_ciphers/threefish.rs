/*!
Threefish (Ferguson, Lucks, Schneier, Whiting, Bellare, Kohno, Callas
and Walker, 2008), the tweakable block cipher under Skein, as Skein 1.3
defines it: a block and a key of 4, 8 or 16 64-bit words
(`Threefish256`, `Threefish512`, `Threefish1024`; the catalogue's
`threefish256`, `threefish512`, `threefish1024`) and a 16 byte tweak.

## A round

72 rounds, 80 at 1024 bits. A round adds each pair of words, rotates
the pair's second word by a distance that depends on the round modulo 8
and the pair (`skein_tables.rs`, read by `scripts/make_skein_tables.py`
out of the Skein team's own header and Bouncy Castle), XORs the sum into
it, and permutes the words. Every four rounds, and after the last, a
subkey is added.

## The key schedule

The key's words and a parity word - the XOR of them all and the
constant `0x1BD11BDAA9FC1A22` - and the tweak's two words and their XOR
are each read cyclically: subkey `s` is key words `s` to `s + N - 1`,
with tweak word `s` added to the third word from the end, tweak word
`s + 1` to the second, and `s` itself to the last. Nothing is expanded
ahead: a subkey is a handful of additions, and changing the tweak costs
nothing.

## The tweak and the key

`new` takes the key alone, with a tweak of zero, or the key followed by
the 16 byte tweak - 32 or 48 bytes at 256 bits, 64 or 80 at 512, 128 or
144 at 1024 - which is how the catalogue and the bindings reach the
tweak. `with_tweak` takes them apart and `set_tweak` changes the tweak
of a keyed cipher.

## Byte order

Every word little-endian: the key, the tweak and the block are the
words' bytes from the first word to the last, as Skein reads them.

## Constant time

Additions, rotations by fixed distances and XORs, with no table indexed
by data and no branch on it.

## Where the vectors come from

`vectors/threefish.vec`, written by `scripts/make_threefish_vectors.py`:
blocks on which Crypto++ 8.9.0, Bouncy Castle 1.77 and Skein3Fish's C
agree, with the published tests they carry. Skein, which encrypts with
`encrypt_words` and nothing else, checks it against the Skein team's
known answers as well.
*/

use super::BlockCipher;
use crate::hash_functions::skein_tables::{R1024, R256, R512};

/// The key schedule's parity constant.
const C240: u64 = 0x1BD1_1BDA_A9FC_1A22;

/// The word permutation after each round, at 4, 8 and 16 words: word `i`
/// takes the value of word `PI[i]`.
const PI4: [usize; 4] = [0, 3, 2, 1];
const PI8: [usize; 8] = [2, 1, 4, 7, 6, 5, 0, 3];
const PI16: [usize; 16] = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1];

/// Threefish on `N` 64-bit words: 4, 8 or 16.
#[derive(Clone)]
pub struct Threefish<const N: usize> {
    /// The key's words and the parity word.
    key: [u64; 17],
    /// The tweak's words and their XOR.
    tweak: [u64; 3],
}

pub type Threefish256 = Threefish<4>;
pub type Threefish512 = Threefish<8>;
pub type Threefish1024 = Threefish<16>;

impl<const N: usize> Threefish<N> {
    /// The rounds: 72, and 80 at 1024 bits. Any other `N` fails to compile
    /// where this is used.
    const ROUNDS: usize = match N {
        4 | 8 => 72,
        16 => 80,
        _ => panic!("Threefish has 4, 8 or 16 words"),
    };
    const PI: &'static [usize] = match N {
        4 => &PI4,
        8 => &PI8,
        _ => &PI16,
    };

    /// The key alone (`8 N` bytes), with a tweak of zero, or the key and
    /// then the tweak (`8 N + 16`).
    pub fn new(key: &[u8]) -> Result<Self, String> {
        let bytes = 8 * N;
        if key.len() == bytes {
            Self::with_tweak(key, &[0; 16])
        } else if key.len() == bytes + 16 {
            let tweak: &[u8; 16] = key[bytes..].try_into().expect("16 bytes");
            Self::with_tweak(&key[..bytes], tweak)
        } else {
            Err(format!("Wrong key length {}. Threefish-{} takes a {} byte key, or the key \
                         followed by the 16 byte tweak, {} bytes.",
                        key.len(), 64 * N, bytes, bytes + 16))
        }
    }

    /// The key (`8 N` bytes) and the tweak.
    pub fn with_tweak(key: &[u8], tweak: &[u8; 16]) -> Result<Self, String> {
        if key.len() != 8 * N {
            return Err(format!("Wrong key length {}. Threefish-{} takes a {} byte key.",
                               key.len(), 64 * N, 8 * N));
        }
        let words: [u64; N] = core::array::from_fn(|i| {
            u64::from_le_bytes(key[8 * i..8 * i + 8].try_into().expect("a word"))
        });
        Ok(Self::from_words(&words, tweak_words(tweak)))
    }

    /// The key and the tweak as words, as Skein has them.
    pub(crate) fn from_words(key: &[u64; N], tweak: [u64; 2]) -> Self {
        let mut k = [0u64; 17];
        k[..N].copy_from_slice(key);
        k[N] = key.iter().fold(C240, |a, w| a ^ w);
        Threefish { key: k, tweak: [tweak[0], tweak[1], tweak[0] ^ tweak[1]] }
    }

    /// Change the tweak, keeping the key.
    pub fn set_tweak(&mut self, tweak: &[u8; 16]) {
        let [t0, t1] = tweak_words(tweak);
        self.tweak = [t0, t1, t0 ^ t1];
    }

    fn rotation(d: usize, j: usize) -> u32 {
        match N {
            4 => R256[d % 8][j],
            8 => R512[d % 8][j],
            _ => R1024[d % 8][j],
        }
    }

    /// Subkey `s`.
    fn subkey(&self, s: usize) -> [u64; N] {
        core::array::from_fn(|i| {
            let w = self.key[(s + i) % (N + 1)];
            if i == N - 3 {
                w.wrapping_add(self.tweak[s % 3])
            } else if i == N - 2 {
                w.wrapping_add(self.tweak[(s + 1) % 3])
            } else if i == N - 1 {
                w.wrapping_add(s as u64)
            } else {
                w
            }
        })
    }

    pub(crate) fn encrypt_words(&self, block: &[u64; N]) -> [u64; N] {
        let mut v = *block;
        for d in 0..Self::ROUNDS {
            if d % 4 == 0 {
                for (x, y) in v.iter_mut().zip(self.subkey(d / 4)) {
                    *x = x.wrapping_add(y);
                }
            }
            for j in 0..N / 2 {
                let sum = v[2 * j].wrapping_add(v[2 * j + 1]);
                v[2 * j] = sum;
                v[2 * j + 1] = v[2 * j + 1].rotate_left(Self::rotation(d, j)) ^ sum;
            }
            let before = v;
            for i in 0..N {
                v[i] = before[Self::PI[i]];
            }
        }
        for (x, y) in v.iter_mut().zip(self.subkey(Self::ROUNDS / 4)) {
            *x = x.wrapping_add(y);
        }
        v
    }

    pub(crate) fn decrypt_words(&self, block: &[u64; N]) -> [u64; N] {
        let mut v = *block;
        for (x, y) in v.iter_mut().zip(self.subkey(Self::ROUNDS / 4)) {
            *x = x.wrapping_sub(y);
        }
        for d in (0..Self::ROUNDS).rev() {
            let after = v;
            for i in 0..N {
                v[Self::PI[i]] = after[i];
            }
            for j in 0..N / 2 {
                let b = (v[2 * j + 1] ^ v[2 * j]).rotate_right(Self::rotation(d, j));
                v[2 * j] = v[2 * j].wrapping_sub(b);
                v[2 * j + 1] = b;
            }
            if d % 4 == 0 {
                for (x, y) in v.iter_mut().zip(self.subkey(d / 4)) {
                    *x = x.wrapping_sub(y);
                }
            }
        }
        v
    }
}

fn tweak_words(tweak: &[u8; 16]) -> [u64; 2] {
    [u64::from_le_bytes(tweak[..8].try_into().expect("a word")),
     u64::from_le_bytes(tweak[8..].try_into().expect("a word"))]
}

fn load<const N: usize>(input: &[u8]) -> [u64; N] {
    core::array::from_fn(|i| u64::from_le_bytes(input[8 * i..8 * i + 8].try_into().expect("a word")))
}

fn store(words: &[u64], result: &mut Vec<u8>) {
    for w in words {
        result.extend_from_slice(&w.to_le_bytes());
    }
}

impl<const N: usize> BlockCipher for Threefish<N> {
    fn blocksize(&self) -> usize {
        8 * N
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        store(&self.encrypt_words(&load::<N>(input)), result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        store(&self.decrypt_words(&load::<N>(input)), result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(seed: &mut u32, n: usize) -> Vec<u8> {
        (0..n).map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 17;
            *seed ^= *seed << 5;
            *seed as u8
        }).collect()
    }

    fn roundtrip<const N: usize>(seed: &mut u32) {
        let key = bytes(seed, 8 * N + 16);
        let block = bytes(seed, 8 * N);
        let mut c = Threefish::<N>::new(&key).unwrap();
        let (mut out, mut back) = (Vec::new(), Vec::new());
        c.block_encrypt(&block, &mut out);
        c.block_decrypt(&out, &mut back);
        assert_eq!(back, block);
        assert_ne!(out, block);
    }

    /// Decryption inverts encryption at every size.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x3f15_2008u32;
        for _ in 0..16 {
            roundtrip::<4>(&mut seed);
            roundtrip::<8>(&mut seed);
            roundtrip::<16>(&mut seed);
        }
    }

    #[test]
    fn test_the_key_lengths() {
        for (n, ok) in [(4usize, [32usize, 48]), (8, [64, 80]), (16, [128, 144])] {
            for len in [0, 16, 31, 32, 33, 47, 48, 49, 64, 80, 96, 128, 144, 160] {
                let accepted = match n {
                    4 => Threefish256::new(&vec![0; len]).is_ok(),
                    8 => Threefish512::new(&vec![0; len]).is_ok(),
                    _ => Threefish1024::new(&vec![0; len]).is_ok(),
                };
                assert_eq!(accepted, ok.contains(&len), "{n} words, {len} bytes");
            }
        }
        assert!(Threefish512::with_tweak(&[0; 80], &[0; 16]).is_err());
    }

    /// The key followed by the tweak, `with_tweak` and `set_tweak` are the
    /// same cipher; the key alone is the tweak of zero; and the tweak
    /// changes the result.
    #[test]
    fn test_the_three_ways_to_give_the_tweak_agree() {
        let mut seed = 0x7eea_c001u32;
        let key = bytes(&mut seed, 64);
        let tweak: [u8; 16] = bytes(&mut seed, 16).try_into().unwrap();
        let block = bytes(&mut seed, 64);
        let encrypt = |mut c: Threefish512| {
            let mut out = Vec::new();
            c.block_encrypt(&block, &mut out);
            out
        };
        let joined = encrypt(Threefish512::new(&[key.as_slice(), &tweak].concat()).unwrap());
        assert_eq!(joined, encrypt(Threefish512::with_tweak(&key, &tweak).unwrap()));
        let mut set = Threefish512::new(&key).unwrap();
        set.set_tweak(&tweak);
        assert_eq!(joined, encrypt(set));
        let untweaked = encrypt(Threefish512::new(&key).unwrap());
        assert_eq!(untweaked, encrypt(Threefish512::with_tweak(&key, &[0; 16]).unwrap()));
        assert_ne!(joined, untweaked);
    }

    /// The last subkey's tweak words: at 1024 bits it is subkey 20, which
    /// takes tweak words 2 and 0, at the others subkey 18, words 0 and 1;
    /// with a zero key, the parity word is the constant.
    #[test]
    fn test_the_last_subkey() {
        let c = Threefish1024::from_words(&[0; 16], [1, 2]);
        let k = c.subkey(20);
        assert_eq!((k[13], k[14], k[15]), (C240 + 3, 1, 20));
        let c = Threefish256::from_words(&[0; 4], [1, 2]);
        let k = c.subkey(18);
        assert_eq!((k[0], k[1], k[2], k[3]), (0, C240 + 1, 2, 18));
    }
}
