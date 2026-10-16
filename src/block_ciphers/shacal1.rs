/*!
SHACAL-1, Handschuh and Naccache's NESSIE submission: SHA-1's
compression function used as a block cipher. The block is the five
32-bit words of SHA-1's chaining value, 160 bits; the key is the message
block, up to 512 bits; and the cipher is SHA-1's 80 rounds with the
round keys `W[i] + K[i / 20]` from SHA-1's message schedule - without
the feed-forward that makes the compression function one-way. NESSIE
did not select it; SHACAL-2 is its sibling on SHA-256.

## The key

As SHACAL-2: read as up to sixteen big-endian words and **zero-padded to
512 bits**, which is the definition, so a key of any length from 16 to
64 bytes is the 64-byte key with zeros after it. Shorter keys than 128
bits are refused, as the submission does.

## Decryption

Each round is invertible: its output's `b`, `c` rotated back, `d` and
`e` are the old `a`, `b`, `c` and `d`, and the old `e` is the new `a`
less what the round added to it. Decryption undoes the rounds in
reverse order.

## Constant time

Additions, rotations and Boolean functions of words; nothing indexes
memory by the key or the data.

## Where the vectors come from

`vectors/shacal1.vec`, written by `scripts/make_shacal1_vectors.py`:
blocks on which two SHA-1 compression functions, Crypto++ 8.9.0's and
OpenSSL's, agree once the feed-forward is taken off, with the published
tests Project Nayuki's library carries. Both witnesses encrypt only; a
decryption that gives every witnessed block back is the inverse of a
witnessed encryption on those blocks, and the tests require it of
every row.
*/

use super::BlockCipher;
use crate::hash_functions::sha1::K;

const BLOCK: usize = 20;
const ROUNDS: usize = 80;

/// The round's Boolean function: choose, parity, majority, parity.
fn f(i: usize, b: u32, c: u32, d: u32) -> u32 {
    match i / 20 {
        0 => d ^ (b & (c ^ d)),
        2 => (b & c) | (d & (b | c)),
        _ => b ^ c ^ d,
    }
}

#[derive(Clone)]
pub struct Shacal1 {
    /// `W[i] + K[i / 20]`, SHA-1's message schedule over the key plus its
    /// round constants.
    round_keys: [u32; ROUNDS],
}

impl Shacal1 {
    pub fn new(key: &[u8]) -> Result<Shacal1, String> {
        if key.len() < 16 || key.len() > 64 {
            return Err(format!("Wrong key length {}. SHACAL-1 takes 16 to 64 bytes.",
                               key.len()));
        }
        let mut padded = [0u8; 64];
        padded[..key.len()].copy_from_slice(key);
        let mut w = [0u32; ROUNDS];
        for (i, chunk) in padded.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(chunk.try_into().expect("4 bytes"));
        }
        for i in 16..ROUNDS {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let round_keys = std::array::from_fn(|i| w[i].wrapping_add(K[i / 20]));
        Ok(Shacal1 { round_keys })
    }
}

fn load(bytes: &[u8]) -> [u32; 5] {
    std::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4")))
}

impl BlockCipher for Shacal1 {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let [mut a, mut b, mut c, mut d, mut e] = load(&input[..BLOCK]);
        for (i, &k) in self.round_keys.iter().enumerate() {
            let t = a.rotate_left(5).wrapping_add(f(i, b, c, d)).wrapping_add(e).wrapping_add(k);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for w in [a, b, c, d, e] {
            result.extend_from_slice(&w.to_be_bytes());
        }
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let [mut a, mut b, mut c, mut d, mut e] = load(&input[..BLOCK]);
        for (i, &k) in self.round_keys.iter().enumerate().rev() {
            // The round wrote a = t and shifted the rest, rotating the
            // old b into c.
            let t = a;
            a = b;
            b = c.rotate_right(30);
            c = d;
            d = e;
            e = t.wrapping_sub(a.rotate_left(5)).wrapping_sub(f(i, b, c, d)).wrapping_sub(k);
        }
        for w in [a, b, c, d, e] {
            result.extend_from_slice(&w.to_be_bytes());
        }
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

    #[test]
    fn test_the_key_lengths() {
        for len in 0..=80 {
            assert_eq!(Shacal1::new(&vec![0; len]).is_ok(), (16..=64).contains(&len), "{len}");
        }
    }

    /// A shorter key is the 64 byte key with zeros after it.
    #[test]
    fn test_a_short_key_is_zero_padded() {
        let mut seed = 0x5aca_1001u32;
        for len in [16, 20, 33, 63] {
            let key = bytes(&mut seed, len);
            let mut padded = key.clone();
            padded.resize(64, 0);
            let block = bytes(&mut seed, BLOCK);
            let (mut a, mut b) = (Vec::new(), Vec::new());
            Shacal1::new(&key).unwrap().block_encrypt(&block, &mut a);
            Shacal1::new(&padded).unwrap().block_encrypt(&block, &mut b);
            assert_eq!(a, b, "{len}");
        }
    }

    /// Encryption with the block added back is SHA-1's compression
    /// function, the block as the chaining value and the key as the
    /// message block: the two share only the round constants.
    #[test]
    fn test_encryption_is_sha1_compression_without_the_feed_forward() {
        let mut seed = 0x0005_ac01u32;
        for _ in 0..32 {
            let key: [u8; 64] = bytes(&mut seed, 64).try_into().unwrap();
            let block = bytes(&mut seed, BLOCK);
            let mut out = Vec::new();
            Shacal1::new(&key).unwrap().block_encrypt(&block, &mut out);
            let mut state = load(&block);
            crate::hash_functions::sha1::compress::<false>(&mut state, &key);
            let encrypted = load(&out);
            for i in 0..5 {
                assert_eq!(encrypted[i].wrapping_add(load(&block)[i]), state[i]);
            }
        }
    }

    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x1de5_0001u32;
        for len in 16..=64 {
            let key = bytes(&mut seed, len);
            let block = bytes(&mut seed, BLOCK);
            let mut c = Shacal1::new(&key).unwrap();
            let (mut out, mut back) = (Vec::new(), Vec::new());
            c.block_encrypt(&block, &mut out);
            c.block_decrypt(&out, &mut back);
            assert_eq!(back, block, "{len}");
        }
    }
}
