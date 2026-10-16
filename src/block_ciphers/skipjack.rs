/*!
Skipjack, the NSA's cipher for the Clipper and Fortezza devices,
declassified in 1998: a 64-bit block, an 80-bit key and 32 rounds of two
stepping rules over four 16-bit words, with a four-round Feistel
permutation `G` on 16 bits inside each.

## The two byte orders

The specification reads the block as four big-endian words, `w1` first,
and the key as the bytes `cv0` to `cv9` in order, and its test vector is
printed that way. libtomcrypt and Bouncy Castle follow it; that is
`Skipjack::new`, the catalogue's `skipjack`. Crypto++ and Botan read the
block as little-endian words in reverse order and the key from its last
byte - every byte string the other way round - so their own test vector
is the specification's written backwards. Neither reading is the other
with a word or two swapped: a key, a block or a result in the wrong order
is a different input or a wrong answer. `Skipjack::new_reversed`, the
catalogue's `skipjack-reversed`, is the second, for data Crypto++ or
Botan wrote.

## The rounds

Rule A replaces `w1` with `G(w1) ^ w4 ^ counter` and moves the old
`G(w1)` into `w2`; rule B puts `w1 ^ w2 ^ counter` into `w3` and `w4`
into `w1`. Eight of A, eight of B, eight of A, eight of B, the counter
running from 1 to 32. The `k`-th `G` uses the key bytes `4k` to `4k + 3`
modulo 10, so the key schedule is the key itself, read cyclically.

## Not constant time

`G` indexes the F-table by data XORed with key bytes, as every
implementation does, so a cache-timing observer learns about both. The
table is `skipjack_table.rs`, written by `scripts/make_oldcipher_tables.py`
from four implementations that agree on it.

## Where the vectors come from

`vectors/skipjack.vec`, written by `scripts/make_skipjack_vectors.py`:
blocks on which libtomcrypt 1.18.2 and Bouncy Castle 1.77 agree, and on
which Crypto++ 8.9.0 and Botan 1.10.17 agree under the reversed order,
with the published tests the four carry.
*/

use super::skipjack_table::F;
use super::BlockCipher;

const BLOCK: usize = 8;
const KEY: usize = 10;

#[derive(Clone)]
pub struct Skipjack {
    /// `cv0` to `cv9`, in the specification's order.
    cv: [u8; KEY],
    /// Crypto++'s and Botan's order: key, block and result reversed.
    reversed: bool,
}

impl Skipjack {
    /// Skipjack in the specification's byte order: a 10-byte key.
    pub fn new(key: &[u8]) -> Result<Skipjack, String> {
        let cv: [u8; KEY] = key.try_into().map_err(|_| format!(
            "Wrong key length {}. Skipjack takes a 10 byte key.", key.len()))?;
        Ok(Skipjack { cv, reversed: false })
    }

    /// Skipjack as Crypto++ and Botan compute it: the key, each block
    /// and each result read in reverse byte order.
    pub fn new_reversed(key: &[u8]) -> Result<Skipjack, String> {
        let mut cipher = Skipjack::new(key)?;
        cipher.cv.reverse();
        cipher.reversed = true;
        Ok(cipher)
    }

    /// Whether this is `new_reversed`'s order.
    pub fn is_reversed(&self) -> bool {
        self.reversed
    }

    /// The permutation `G` for the `k`-th use, 0-based.
    fn g(&self, k: usize, w: u16) -> u16 {
        let [g1, g2] = w.to_be_bytes();
        let cv = |i: usize| self.cv[(4 * k + i) % KEY];
        let g3 = F[usize::from(g2 ^ cv(0))] ^ g1;
        let g4 = F[usize::from(g3 ^ cv(1))] ^ g2;
        let g5 = F[usize::from(g4 ^ cv(2))] ^ g3;
        let g6 = F[usize::from(g5 ^ cv(3))] ^ g4;
        u16::from_be_bytes([g5, g6])
    }

    /// `G`'s inverse for the same `k`: the four steps backwards.
    fn g_inverse(&self, k: usize, w: u16) -> u16 {
        let [g5, g6] = w.to_be_bytes();
        let cv = |i: usize| self.cv[(4 * k + i) % KEY];
        let g4 = F[usize::from(g5 ^ cv(3))] ^ g6;
        let g3 = F[usize::from(g4 ^ cv(2))] ^ g5;
        let g2 = F[usize::from(g3 ^ cv(1))] ^ g4;
        let g1 = F[usize::from(g2 ^ cv(0))] ^ g3;
        u16::from_be_bytes([g1, g2])
    }

    fn load(&self, input: &[u8]) -> [u16; 4] {
        let mut block: [u8; BLOCK] = input[..BLOCK].try_into().expect("one block");
        if self.reversed {
            block.reverse();
        }
        std::array::from_fn(|i| u16::from_be_bytes([block[2 * i], block[2 * i + 1]]))
    }

    fn store(&self, w: [u16; 4], result: &mut Vec<u8>) {
        let mut block = [0u8; BLOCK];
        for (i, word) in w.iter().enumerate() {
            block[2 * i..2 * i + 2].copy_from_slice(&word.to_be_bytes());
        }
        if self.reversed {
            block.reverse();
        }
        result.extend_from_slice(&block);
    }
}

/// Rounds 1-8 and 17-24 are rule A; 9-16 and 25-32 rule B.
fn is_rule_a(counter: u16) -> bool {
    ((counter - 1) / 8).is_multiple_of(2)
}

impl BlockCipher for Skipjack {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let [mut w1, mut w2, mut w3, mut w4] = self.load(input);
        for counter in 1..=32u16 {
            let g = self.g(usize::from(counter - 1), w1);
            if is_rule_a(counter) {
                (w1, w2, w3, w4) = (g ^ w4 ^ counter, g, w2, w3);
            } else {
                (w1, w2, w3, w4) = (w4, g, w1 ^ w2 ^ counter, w3);
            }
        }
        self.store([w1, w2, w3, w4], result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let [mut w1, mut w2, mut w3, mut w4] = self.load(input);
        for counter in (1..=32u16).rev() {
            // Both rules put G(old w1) into w2, so old w1 comes back
            // from w2 either way; they differ in what else they mixed.
            let old_w1 = self.g_inverse(usize::from(counter - 1), w2);
            if is_rule_a(counter) {
                (w1, w2, w3, w4) = (old_w1, w3, w4, w1 ^ w2 ^ counter);
            } else {
                (w1, w2, w3, w4) = (old_w1, w3 ^ old_w1 ^ counter, w4, w1);
            }
        }
        self.store([w1, w2, w3, w4], result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(seed: &mut u32) -> u8 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 17;
        *seed ^= *seed << 5;
        *seed as u8
    }

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 9, 11, 16] {
            assert!(Skipjack::new(&vec![0u8; len]).is_err(), "{len}");
            assert!(Skipjack::new_reversed(&vec![0u8; len]).is_err(), "{len}");
        }
    }

    /// Decryption inverts encryption in both orders, and changes the
    /// block.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x5eed_1998u32;
        for _ in 0..64 {
            let key: Vec<u8> = (0..KEY).map(|_| next(&mut seed)).collect();
            let block: Vec<u8> = (0..BLOCK).map(|_| next(&mut seed)).collect();
            for mut c in [Skipjack::new(&key).unwrap(), Skipjack::new_reversed(&key).unwrap()] {
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block);
                assert_ne!(out, block);
            }
        }
    }

    /// The reversed order is the specification's on the reversed key and
    /// block, with the result reversed - and not the same cipher.
    #[test]
    fn test_the_reversed_order_is_every_string_reversed() {
        let mut seed = 0x0c11_99e4u32;
        for _ in 0..16 {
            let key: Vec<u8> = (0..KEY).map(|_| next(&mut seed)).collect();
            let block: Vec<u8> = (0..BLOCK).map(|_| next(&mut seed)).collect();
            let (mut straight, mut reversed) = (Vec::new(), Vec::new());
            let rkey: Vec<u8> = key.iter().rev().copied().collect();
            let rblock: Vec<u8> = block.iter().rev().copied().collect();
            Skipjack::new(&rkey).unwrap().block_encrypt(&rblock, &mut straight);
            Skipjack::new_reversed(&key).unwrap().block_encrypt(&block, &mut reversed);
            straight.reverse();
            assert_eq!(reversed, straight);
            let mut plain = Vec::new();
            Skipjack::new(&key).unwrap().block_encrypt(&block, &mut plain);
            assert_ne!(plain, reversed);
        }
    }
}
