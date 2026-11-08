//! The Chaskey-LTS block cipher: Chaskey-LTS's keyless 16 round
//! permutation `pi` (`mac::chaskey`) as an Even-Mansour cipher with one
//! key, `E(K, x) = pi(x ^ K) ^ K`, a 128 bit block and a 128 bit key.
//!
//! Chaskey's designers describe the MAC; the block cipher is the
//! construction volexity's chaskey-lts package and sacundim's chaskey
//! crate implement, and the FELIX block sacundim's tests carry. It is
//! not a NIST or ISO cipher, and Even-Mansour with one key is secure only
//! up to about 2^64 encryptions under one key.
//!
//! Words are little endian, as in the MAC. Decryption runs the rounds
//! backwards: each step of a round undone in the opposite order, a
//! rotation by `r` left undone by one by `r` right, an addition by a
//! subtraction. Nothing branches on or indexes by the key or the data.

use super::BlockCipher;
use crate::mac::chaskey::permute;

const BLOCK: usize = 16;
const ROUNDS: usize = 16;

/// One round of `pi`, backwards.
fn inverse_round(v: &mut [u32; 4]) {
    v[2] = v[2].rotate_right(16);
    v[1] = (v[1] ^ v[2]).rotate_right(7);
    v[2] = v[2].wrapping_sub(v[1]);
    v[3] = (v[3] ^ v[0]).rotate_right(13);
    v[0] = v[0].wrapping_sub(v[3]);
    v[3] = (v[3] ^ v[2]).rotate_right(8);
    v[2] = v[2].wrapping_sub(v[3]);
    v[0] = v[0].rotate_right(16);
    v[1] = (v[1] ^ v[0]).rotate_right(5);
    v[0] = v[0].wrapping_sub(v[1]);
}

fn load(bytes: &[u8]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

fn store(v: &[u32; 4], result: &mut Vec<u8>) {
    for w in v {
        result.extend_from_slice(&w.to_le_bytes());
    }
}

/// The Chaskey-LTS block cipher under one key.
#[derive(Clone)]
pub struct ChaskeyLts {
    k: [u32; 4],
}

impl core::fmt::Debug for ChaskeyLts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaskeyLts").finish_non_exhaustive()
    }
}

impl ChaskeyLts {
    /// The cipher under a 16 byte key.
    ///
    /// # Errors
    /// A key of another length.
    pub fn new(key: &[u8]) -> Result<ChaskeyLts, String> {
        if key.len() != 16 {
            return Err(format!("A Chaskey-LTS key is 16 bytes, not {}.", key.len()));
        }
        Ok(ChaskeyLts { k: load(key) })
    }

    fn whiten(&self, v: &mut [u32; 4]) {
        for (w, k) in v.iter_mut().zip(&self.k) {
            *w ^= k;
        }
    }
}

impl BlockCipher for ChaskeyLts {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut v = load(&input[..BLOCK]);
        self.whiten(&mut v);
        permute(&mut v, ROUNDS);
        self.whiten(&mut v);
        store(&v, result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut v = load(&input[..BLOCK]);
        self.whiten(&mut v);
        for _ in 0..ROUNDS {
            inverse_round(&mut v);
        }
        self.whiten(&mut v);
        store(&v, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::chaskey::round;

    /// Each round is undone by its inverse, over states that set every
    /// carry and rotation apart.
    #[test]
    fn test_the_inverse_round_undoes_the_round() {
        let mut v = [0x0123_4567u32, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210];
        for _ in 0..1000 {
            let before = v;
            round(&mut v);
            let after = v;
            inverse_round(&mut v);
            assert_eq!(v, before);
            v = after;
        }
    }

    #[test]
    fn test_decryption_undoes_encryption() {
        let mut c = ChaskeyLts::new(&(0..16).collect::<Vec<u8>>()).expect("16 bytes");
        let mut block: Vec<u8> = (100..116).collect();
        for _ in 0..100 {
            let mut out = Vec::new();
            c.block_encrypt(&block, &mut out);
            let mut back = Vec::new();
            c.block_decrypt(&out, &mut back);
            assert_eq!(back, block);
            block = out;
        }
    }

    #[test]
    fn test_other_key_lengths_are_refused() {
        for n in [0, 8, 15, 17, 32] {
            assert_eq!(ChaskeyLts::new(&vec![0; n]).unwrap_err(),
                       format!("A Chaskey-LTS key is 16 bytes, not {n}."));
        }
    }
}
