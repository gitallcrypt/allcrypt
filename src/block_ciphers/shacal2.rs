/*!
SHACAL-2, Handschuh and Naccache's NESSIE submission: SHA-256's
compression function used as a block cipher. The block is the eight
32-bit words of SHA-256's chaining value, 256 bits; the key is the
message block, up to 512 bits; and the cipher is SHA-256's 64 rounds
with the round keys `W[i] + K[i]` from SHA-256's message schedule -
without the feed-forward that makes the compression function one-way.
NESSIE selected it.

## The key

The key is read as up to sixteen big-endian words and **zero-padded to
512 bits**, which is the definition rather than a convention: a key of
any length from 16 to 64 bytes is the 64-byte key with zeros after it.
Shorter keys than 128 bits are refused, as the submission does. Crypto++
takes every length in that range; Bouncy Castle takes multiples of 8
bytes and Botan multiples of 4, which are the same keys padded.

## Decryption

Each round is invertible: from the round's output the two new words are
`a` and `e`, and the rest are the old words shifted. Decryption undoes
the rounds in reverse order, subtracting what each added.

## Constant time

Additions, rotations and Boolean functions of words; nothing indexes
memory by the key or the data. `scripts/ct_check.py` has the case
`shacal2_blocks`.

## Where the vectors come from

`vectors/shacal2.vec`, written by `scripts/make_shacal2_vectors.py`:
blocks on which Crypto++ 8.9.0 and Bouncy Castle 1.77 agree, at every
key length both take and the others through padding, and the published
NESSIE tests Crypto++ and Botan carry.
*/

use super::BlockCipher;
use crate::hash_functions::sha2::K_32;

const BLOCK: usize = 32;
const ROUNDS: usize = 64;

fn big_s0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn big_s1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
fn small_s0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
fn small_s1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
fn ch(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (z & (x | y))
}

#[derive(Clone)]
pub struct Shacal2 {
    /// `W[i] + K[i]`, SHA-256's message schedule over the key plus its
    /// round constants.
    round_keys: [u32; ROUNDS],
}

impl Shacal2 {
    pub fn new(key: &[u8]) -> Result<Shacal2, String> {
        if key.len() < 16 || key.len() > 64 {
            return Err(format!("Wrong key length {}. SHACAL-2 takes 16 to 64 bytes.",
                               key.len()));
        }
        let mut padded = [0u8; 64];
        padded[..key.len()].copy_from_slice(key);
        let mut w = [0u32; ROUNDS];
        for (i, chunk) in padded.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(chunk.try_into().expect("4 bytes"));
        }
        for i in 16..ROUNDS {
            w[i] = small_s1(w[i - 2]).wrapping_add(w[i - 7]).wrapping_add(small_s0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }
        let mut round_keys = [0u32; ROUNDS];
        for (r, (w, k)) in round_keys.iter_mut().zip(w.iter().zip(K_32)) {
            *r = w.wrapping_add(k);
        }
        Ok(Shacal2 { round_keys })
    }
}

fn load(bytes: &[u8]) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4")))
}

impl BlockCipher for Shacal2 {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = load(&input[..BLOCK]);
        for &k in &self.round_keys {
            let t1 = h.wrapping_add(big_s1(e)).wrapping_add(ch(e, f, g)).wrapping_add(k);
            let t2 = big_s0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for w in [a, b, c, d, e, f, g, h] {
            result.extend_from_slice(&w.to_be_bytes());
        }
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = load(&input[..BLOCK]);
        for &k in self.round_keys.iter().rev() {
            // The round wrote a = t1 + t2 and e = d + t1 and shifted the
            // rest; b, c, f and g are the old a, b, e and f.
            let t2 = big_s0(b).wrapping_add(maj(b, c, d));
            let t1 = a.wrapping_sub(t2);
            let old_d = e.wrapping_sub(t1);
            let old_h = t1.wrapping_sub(big_s1(f)).wrapping_sub(ch(f, g, h)).wrapping_sub(k);
            a = b;
            b = c;
            c = d;
            d = old_d;
            e = f;
            f = g;
            g = h;
            h = old_h;
        }
        for w in [a, b, c, d, e, f, g, h] {
            result.extend_from_slice(&w.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key shorter than 64 bytes is the 64-byte key with zeros after it.
    #[test]
    fn test_a_short_key_is_the_padded_key() {
        let key: Vec<u8> = (1..=20).collect();
        let mut padded = key.clone();
        padded.resize(64, 0);
        let block: Vec<u8> = (0..32).collect();
        let (mut short, mut long) = (Shacal2::new(&key).unwrap(), Shacal2::new(&padded).unwrap());
        let (mut x, mut y) = (Vec::new(), Vec::new());
        short.block_encrypt(&block, &mut x);
        long.block_encrypt(&block, &mut y);
        assert_eq!(x, y);
    }

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 15, 65, 128] {
            assert!(Shacal2::new(&vec![0u8; len]).is_err(), "{len}");
        }
        for len in [16, 17, 33, 63, 64] {
            assert!(Shacal2::new(&vec![0u8; len]).is_ok(), "{len}");
        }
    }

    /// Decryption inverts encryption, under keys of several lengths.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x2545_f491u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for len in [16, 24, 41, 64] {
            let key: Vec<u8> = (0..len).map(|_| next()).collect();
            let block: Vec<u8> = (0..32).map(|_| next()).collect();
            let mut c = Shacal2::new(&key).unwrap();
            let mut out = Vec::new();
            c.block_encrypt(&block, &mut out);
            let mut back = Vec::new();
            c.block_decrypt(&out, &mut back);
            assert_eq!(back, block);
            assert_ne!(out, block);
        }
    }
}
