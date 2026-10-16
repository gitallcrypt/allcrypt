/*!
SAFER+, Massey, Khachatrian and Kuregian's AES candidate for Cylink
(1998), and the cipher inside Bluetooth's E1, E21 and E22: a 128-bit
block, a key of 16, 24 or 32 bytes and 8, 12 or 16 rounds to match.

## A round

Like SAFER's, widened to sixteen bytes: the first subkey mixed in - XOR
on bytes 0, 3, 4, 7, 8, 11, 12 and 15, addition on the rest - then `exp`
(`45^x mod 257`, 256 written as 0) on those eight bytes and `log` on the
others, the second subkey mixed the other way round, and a linear layer
of four Pseudo-Hadamard layers, `(2a + b, a + b)` on adjacent pairs,
with the "Armenian shuffle" between them. A final subkey is mixed in
after the last round.

## The key schedule

`1 + 2r` subkeys. The key with the XOR of its bytes appended is a
register of `n + 1` bytes; the first subkey is its first sixteen. For
each later subkey `k` every register byte is rotated left by 3, and the
subkey is sixteen register bytes starting at `k`, wrapping, plus a bias.
The bias is `exp(exp(17k + 35 + j))` for the first sixteen subkeys after
the first and `exp(17k + 35 + j)` - one `exp` - for the rest, which only
the longer keys reach; it is computed here from that rule.

## Two word orders

libtomcrypt reads the key and the block as byte strings in order, as
the submission's own tests are written; that is `SaferPlus::new`, the
catalogue's `saferplus`. libmcrypt - and so PHP's `mcrypt` extension -
takes them as arrays of 32-bit words and reverses the order of the
words, leaving each word's bytes alone, for the key, the block and the
result. `SaferPlus::new_reversed_words`, `saferplus-reversed-words`, is
that order.

## Not constant time

`exp` and `log` are tables indexed by data mixed with key bytes.

## Where the vectors come from

`vectors/saferplus.vec`, written by `scripts/make_saferplus_vectors.py`:
blocks on which libtomcrypt 1.18.2 and libmcrypt 2.5.8 agree at every
key length once libmcrypt's word order is accounted for, with
libtomcrypt's published tests.
*/

use super::BlockCipher;

const BLOCK: usize = 16;

/// `exp[x] = 45^x mod 257`, with 256 as 0, and `log` its inverse.
const fn tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut value: u32 = 1;
    let mut x = 0;
    while x < 256 {
        let byte = (value & 0xff) as u8;
        exp[x] = byte;
        log[byte as usize] = x as u8;
        value = value * 45 % 257;
        x += 1;
    }
    (exp, log)
}
const EXP: [u8; 256] = tables().0;
const LOG: [u8; 256] = tables().1;

/// The bytes the first subkey of a round, and the last subkey, XOR
/// rather than add; the same positions take `exp` rather than `log`.
const XORED: [bool; BLOCK] = [true, false, false, true, true, false, false, true,
                              true, false, false, true, true, false, false, true];

/// The Armenian shuffle: output byte `i` is input byte `SHUFFLE[i]`.
const SHUFFLE: [usize; BLOCK] = [8, 11, 12, 15, 2, 1, 6, 5, 10, 9, 14, 13, 0, 7, 4, 3];

const UNSHUFFLE: [usize; BLOCK] = {
    let mut inverse = [0usize; BLOCK];
    let mut i = 0;
    while i < BLOCK {
        inverse[SHUFFLE[i]] = i;
        i += 1;
    }
    inverse
};

/// Subkey `k`'s bias byte `j`, for `k` from 1 to 32.
fn bias(k: usize, j: usize) -> u8 {
    let e = EXP[(17 * (k - 1) + 35 + j) & 0xff];
    if k <= 16 {
        EXP[usize::from(e)]
    } else {
        e
    }
}

#[derive(Clone)]
pub struct SaferPlus {
    /// `1 + 2 * rounds` subkeys.
    keys: Vec<[u8; BLOCK]>,
    /// libmcrypt's order: the 32-bit words of the key, the block and the
    /// result reversed.
    reversed_words: bool,
}

/// `data` with its 32-bit words in the opposite order, each word's bytes
/// kept as they are.
fn reverse_words(data: &[u8]) -> Vec<u8> {
    data.chunks_exact(4).rev().flatten().copied().collect()
}

impl SaferPlus {
    fn check_key_length(n: usize) -> Result<(), String> {
        if matches!(n, 16 | 24 | 32) {
            Ok(())
        } else {
            Err(format!("Wrong key length {n}. SAFER+ takes a 16, 24 or 32 byte key."))
        }
    }

    pub fn new(key: &[u8]) -> Result<SaferPlus, String> {
        let n = key.len();
        SaferPlus::check_key_length(n)?;
        let mut register = key.to_vec();
        register.push(key.iter().fold(0, |acc, b| acc ^ b));
        let mut keys = vec![register[..BLOCK].try_into().expect("16 bytes")];
        for k in 1..=n {
            for byte in register.iter_mut() {
                *byte = byte.rotate_left(3);
            }
            keys.push(std::array::from_fn(|j| {
                register[(k + j) % (n + 1)].wrapping_add(bias(k, j))
            }));
        }
        Ok(SaferPlus { keys, reversed_words: false })
    }

    /// SAFER+ as libmcrypt computes it: the 32-bit words of the key, each
    /// block and each result in reverse order.
    pub fn new_reversed_words(key: &[u8]) -> Result<SaferPlus, String> {
        // Before reordering: `reverse_words` drops a partial last word,
        // so a 17 byte key would otherwise arrive at `new` as 16.
        SaferPlus::check_key_length(key.len())?;
        let mut cipher = SaferPlus::new(&reverse_words(key))?;
        cipher.reversed_words = true;
        Ok(cipher)
    }

    /// Whether this is `new_reversed_words`'s order.
    pub fn is_reversed_words(&self) -> bool {
        self.reversed_words
    }

    fn load(&self, input: &[u8]) -> [u8; BLOCK] {
        let block = &input[..BLOCK];
        if self.reversed_words {
            reverse_words(block).try_into().expect("one block")
        } else {
            block.try_into().expect("one block")
        }
    }

    fn store(&self, block: &[u8; BLOCK], result: &mut Vec<u8>) {
        if self.reversed_words {
            result.extend(reverse_words(block));
        } else {
            result.extend_from_slice(block);
        }
    }

    pub fn rounds(&self) -> usize {
        (self.keys.len() - 1) / 2
    }
}

fn mix(block: &mut [u8; BLOCK], key: &[u8; BLOCK]) {
    for ((b, k), xored) in block.iter_mut().zip(key).zip(XORED) {
        *b = if xored { *b ^ k } else { b.wrapping_add(*k) };
    }
}

fn unmix(block: &mut [u8; BLOCK], key: &[u8; BLOCK]) {
    for ((b, k), xored) in block.iter_mut().zip(key).zip(XORED) {
        *b = if xored { *b ^ k } else { b.wrapping_sub(*k) };
    }
}

/// One Pseudo-Hadamard layer: each pair `(a, b)` to `(2a + b, a + b)`.
fn pht(block: &mut [u8; BLOCK]) {
    for pair in block.chunks_exact_mut(2) {
        pair[1] = pair[1].wrapping_add(pair[0]);
        pair[0] = pair[0].wrapping_add(pair[1]);
    }
}

fn ipht(block: &mut [u8; BLOCK]) {
    for pair in block.chunks_exact_mut(2) {
        pair[0] = pair[0].wrapping_sub(pair[1]);
        pair[1] = pair[1].wrapping_sub(pair[0]);
    }
}

/// The linear layer: PHT, shuffle, PHT, shuffle, PHT, shuffle, PHT.
fn linear(block: &mut [u8; BLOCK]) {
    for layer in 0..4 {
        if layer > 0 {
            *block = std::array::from_fn(|i| block[SHUFFLE[i]]);
        }
        pht(block);
    }
}

fn linear_inverse(block: &mut [u8; BLOCK]) {
    for layer in 0..4 {
        if layer > 0 {
            *block = std::array::from_fn(|i| block[UNSHUFFLE[i]]);
        }
        ipht(block);
    }
}

impl BlockCipher for SaferPlus {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut s = self.load(input);
        for pair in self.keys[..self.keys.len() - 1].chunks_exact(2) {
            mix(&mut s, &pair[0]);
            for ((b, k), xored) in s.iter_mut().zip(&pair[1]).zip(XORED) {
                *b = if xored {
                    EXP[usize::from(*b)].wrapping_add(*k)
                } else {
                    LOG[usize::from(*b)] ^ k
                };
            }
            linear(&mut s);
        }
        mix(&mut s, self.keys.last().expect("1 + 2r subkeys"));
        self.store(&s, result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut s = self.load(input);
        unmix(&mut s, self.keys.last().expect("1 + 2r subkeys"));
        for pair in self.keys[..self.keys.len() - 1].chunks_exact(2).rev() {
            linear_inverse(&mut s);
            for ((b, k), xored) in s.iter_mut().zip(&pair[1]).zip(XORED) {
                *b = if xored {
                    LOG[usize::from(b.wrapping_sub(*k))]
                } else {
                    EXP[usize::from(*b ^ k)]
                };
            }
            unmix(&mut s, &pair[0]);
        }
        self.store(&s, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_length_is_checked() {
        // Both constructors: the reversed order reorders whole 32-bit
        // words, and a reordering that dropped a partial word accepted
        // 17 and 33 byte keys as 16 and 32.
        for len in [0, 8, 15, 17, 18, 19, 20, 23, 25, 31, 33, 34, 35, 64] {
            assert!(SaferPlus::new(&vec![0u8; len]).is_err(), "{len}");
            assert!(SaferPlus::new_reversed_words(&vec![0u8; len]).is_err(), "{len}");
        }
        for (len, rounds) in [(16, 8), (24, 12), (32, 16)] {
            assert_eq!(SaferPlus::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
    }

    /// The shuffle is a permutation and the inverse inverts it, and the
    /// linear layer's inverse undoes it.
    #[test]
    fn test_the_linear_layer_inverts() {
        let mut seen = [false; BLOCK];
        for &i in &SHUFFLE {
            assert!(!seen[i]);
            seen[i] = true;
        }
        for x in 0..=255u8 {
            let block: [u8; BLOCK] = std::array::from_fn(|i| x.wrapping_mul(i as u8 + 7));
            let mut b = block;
            linear(&mut b);
            linear_inverse(&mut b);
            assert_eq!(b, block);
        }
    }

    /// Decryption inverts encryption at every key length.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x5afe_1998u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for len in [16, 24, 32] {
            for _ in 0..16 {
                let key: Vec<u8> = (0..len).map(|_| next()).collect();
                let block: Vec<u8> = (0..BLOCK).map(|_| next()).collect();
                for mut c in [SaferPlus::new(&key).unwrap(),
                              SaferPlus::new_reversed_words(&key).unwrap()] {
                    let (mut out, mut back) = (Vec::new(), Vec::new());
                    c.block_encrypt(&block, &mut out);
                    c.block_decrypt(&out, &mut back);
                    assert_eq!(back, block, "{len}");
                    assert_ne!(out, block);
                }
            }
        }
    }

    /// The reversed-words order is the other on the key and block with
    /// their words reversed, the result's words reversed - and not the
    /// same cipher.
    #[test]
    fn test_the_reversed_word_order() {
        let key: Vec<u8> = (1..=24).collect();
        let block: Vec<u8> = (100..116).collect();
        let (mut straight, mut reversed, mut plain) = (Vec::new(), Vec::new(), Vec::new());
        SaferPlus::new(&reverse_words(&key)).unwrap()
            .block_encrypt(&reverse_words(&block), &mut straight);
        SaferPlus::new_reversed_words(&key).unwrap().block_encrypt(&block, &mut reversed);
        SaferPlus::new(&key).unwrap().block_encrypt(&block, &mut plain);
        assert_eq!(reversed, reverse_words(&straight));
        assert_ne!(reversed, plain);
    }
}
