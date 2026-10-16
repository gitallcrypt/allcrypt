/*!
KASUMI, the 3GPP cipher inside UMTS's f8 and f9 and GSM's A5/3 and
GEA3 (3GPP TS 35.202): a 64-bit block, a 128-bit key and an eight-round
Feistel network, a modified MISTY1.

## A round

Odd rounds apply `FL` and then `FO` to the left half, even rounds `FO`
and then `FL`, and XOR the result into the right half, which then swaps
in. `FL` mixes the two 16-bit halves with an AND and an OR of round-key
words, each rotated by one. `FO` is three rounds of a 16-bit Feistel
network whose round function `FI` is itself a four-round network over a
nine-bit and a seven-bit half, through the S-boxes S9 and S7.

## The key schedule

The key is eight 16-bit words `Kⱼ`, read big-endian; `K'ⱼ` is each XOR
a constant. Round `i`'s eight subkeys are rotations of `K` and words of
`K'` at offsets from `i` modulo 8.

## The tables

S7, S9 and the eight constants are `kasumi_table.rs`, written by
`scripts/make_oldcipher_tables.py` from libtomcrypt 1.18.2 and Botan
1.10.17, which agree on every entry.

## Not constant time

S7 and S9 are tables indexed by data mixed with key words.

## Where the vectors come from

`vectors/kasumi.vec`, written by `scripts/make_kasumi_vectors.py`:
blocks on which libtomcrypt and Botan agree, with the published tests
both carry.
*/

use super::kasumi_table::{C, S7, S9};
use super::BlockCipher;

const BLOCK: usize = 8;
const ROUNDS: usize = 8;

#[derive(Clone, Default)]
struct RoundKey {
    kl1: u16,
    kl2: u16,
    ko: [u16; 3],
    ki: [u16; 3],
}

#[derive(Clone)]
pub struct Kasumi {
    keys: [RoundKey; ROUNDS],
}

impl Kasumi {
    pub fn new(key: &[u8]) -> Result<Kasumi, String> {
        if key.len() != 16 {
            return Err(format!("Wrong key length {}. KASUMI takes a 16 byte key.", key.len()));
        }
        let k: [u16; 8] = std::array::from_fn(|j| u16::from_be_bytes([key[2 * j], key[2 * j + 1]]));
        let kp: [u16; 8] = std::array::from_fn(|j| k[j] ^ C[j]);
        let keys = std::array::from_fn(|i| RoundKey {
            kl1: k[i].rotate_left(1),
            kl2: kp[(i + 2) % 8],
            ko: [k[(i + 1) % 8].rotate_left(5), k[(i + 5) % 8].rotate_left(8),
                 k[(i + 6) % 8].rotate_left(13)],
            ki: [kp[(i + 4) % 8], kp[(i + 3) % 8], kp[(i + 7) % 8]],
        });
        Ok(Kasumi { keys })
    }
}

/// `FI`: a nine-bit and a seven-bit half, through S9 and S7 twice with
/// the subkey between.
fn fi(input: u16, subkey: u16) -> u16 {
    let mut nine = input >> 7;
    let mut seven = input & 0x7f;
    nine = S9[usize::from(nine)] ^ seven;
    seven = u16::from(S7[usize::from(seven)]) ^ (nine & 0x7f);
    seven ^= subkey >> 9;
    nine ^= subkey & 0x1ff;
    nine = S9[usize::from(nine)] ^ seven;
    seven = u16::from(S7[usize::from(seven)]) ^ (nine & 0x7f);
    (seven << 9) | nine
}

fn fo(input: u32, k: &RoundKey) -> u32 {
    let (mut left, mut right) = ((input >> 16) as u16, input as u16);
    left = fi(left ^ k.ko[0], k.ki[0]) ^ right;
    right = fi(right ^ k.ko[1], k.ki[1]) ^ left;
    left = fi(left ^ k.ko[2], k.ki[2]) ^ right;
    (u32::from(right) << 16) | u32::from(left)
}

fn fl(input: u32, k: &RoundKey) -> u32 {
    let (mut left, mut right) = ((input >> 16) as u16, input as u16);
    right ^= (left & k.kl1).rotate_left(1);
    left ^= (right | k.kl2).rotate_left(1);
    (u32::from(left) << 16) | u32::from(right)
}

/// Round `i`'s function, 0-based: FL then FO in the odd rounds (even
/// `i`), FO then FL in the even ones.
fn round(i: usize, input: u32, k: &RoundKey) -> u32 {
    if i.is_multiple_of(2) {
        fo(fl(input, k), k)
    } else {
        fl(fo(input, k), k)
    }
}

impl BlockCipher for Kasumi {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut left = u32::from_be_bytes(input[..4].try_into().expect("4 bytes"));
        let mut right = u32::from_be_bytes(input[4..BLOCK].try_into().expect("4 bytes"));
        for (i, k) in self.keys.iter().enumerate() {
            (left, right) = (right ^ round(i, left, k), left);
        }
        result.extend_from_slice(&left.to_be_bytes());
        result.extend_from_slice(&right.to_be_bytes());
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut left = u32::from_be_bytes(input[..4].try_into().expect("4 bytes"));
        let mut right = u32::from_be_bytes(input[4..BLOCK].try_into().expect("4 bytes"));
        for (i, k) in self.keys.iter().enumerate().rev() {
            (left, right) = (right, left ^ round(i, right, k));
        }
        result.extend_from_slice(&left.to_be_bytes());
        result.extend_from_slice(&right.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S7 and S9 are permutations of seven and nine bits.
    #[test]
    fn test_the_sboxes_are_permutations() {
        let mut seven = S7.to_vec();
        seven.sort_unstable();
        assert!(seven.iter().copied().eq(0..128u8));
        let mut nine = S9.to_vec();
        nine.sort_unstable();
        assert!(nine.iter().copied().eq(0..512u16));
    }

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 8, 15, 17, 24, 32] {
            assert!(Kasumi::new(&vec![0u8; len]).is_err(), "{len}");
        }
    }

    /// Decryption inverts encryption.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x3699_2001u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..32 {
            let key: Vec<u8> = (0..16).map(|_| next()).collect();
            let block: Vec<u8> = (0..8).map(|_| next()).collect();
            let mut c = Kasumi::new(&key).unwrap();
            let (mut out, mut back) = (Vec::new(), Vec::new());
            c.block_encrypt(&block, &mut out);
            c.block_decrypt(&out, &mut back);
            assert_eq!(back, block);
            assert_ne!(out, block);
        }
    }
}
