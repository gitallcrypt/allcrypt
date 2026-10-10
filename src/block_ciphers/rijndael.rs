/*
Rijndael with any of its block sizes: AES is the 128 bit block, and the
cipher Daemen and Rijmen submitted also takes 160, 192, 224 and 256 bit
blocks, each with a key of 128, 160, 192, 224 or 256 bits.

FIPS 197 standardised only the 128 bit block. The wider ones survive in
software that predates it or chose them anyway - PHP's mcrypt
`MCRYPT_RIJNDAEL_256`, which a generation of web applications used for
"AES-256" and which is not AES at all, is the best known.

## How the sizes change the cipher

With `Nb` the block and `Nk` the key in 32 bit words:

- the round count is `max(Nb, Nk) + 6`, so a 256 bit block takes 14
  rounds even under a 128 bit key;
- ShiftRows rotates rows 1, 2 and 3 left by (1, 2, 3) bytes for
  `Nb` of 4, 5 and 6, by (1, 2, 4) for 7 and by (1, 3, 4) for 8 - the
  offsets of *The Design of Rijndael*, table 3.1;
- the key expansion is AES's, run until there are `Nb * (rounds + 1)`
  words, with the extra SubWord when `Nk > 6`.

SubBytes and MixColumns are AES's and act column by column, whatever
the width. With a 128 bit block this module computes exactly AES, and a
test requires it to match `aes` under all three AES key sizes.

## Not constant time

This is the textbook byte-oriented cipher with a table S-box, so its
memory accesses depend on the key and the data. AES itself has a
bitsliced path (and AES-NI) for that reason; the wide blocks have
neither, and `docs/pitfalls.md` records it as accepted.

## In the catalogue

`rijndael-128`, `rijndael-160`, `rijndael-192`, `rijndael-224` and
`rijndael-256`, named by block size in bits as mcrypt named them; each
takes any of the five key lengths. `rijndael-128` is AES under a 16, 24
or 32 byte key and is there for the 20 and 28 byte keys AES does not
have. The chaining modes take any block size. CMAC and the AEADs do
not: SP 800-38B and the AEADs' own specifications give their field
constants for 64 and 128 bit blocks only, so `Cmac::new` refuses the
wider ones rather than guess a polynomial.

## Where the vectors come from

`vectors/rijndael.vec`, written by `scripts/make_rijndael_vectors.py`:
eleven rows for each of the 25 pairs of block and key size, every one
an answer on which Bouncy Castle 1.77's `RijndaelEngine` and phpseclib
1.0.23's pure-PHP `Crypt_Rijndael` agree. The two share no code, and
both reproduce FIPS 197's Appendix C first.
*/

use crate::block_ciphers::aes::{INV_SBOX, SBOX};
use crate::block_ciphers::BlockCipher;

/// ShiftRows' left rotations of rows 1, 2 and 3, by `Nb - 4`.
const SHIFTS: [[usize; 3]; 5] = [[1, 2, 3], [1, 2, 3], [1, 2, 3], [1, 2, 4], [1, 3, 4]];

#[derive(Clone)]
pub struct Rijndael {
    nb: usize,
    rounds: usize,
    /// The expanded key as bytes, column by column: `4 * Nb` per round.
    w: Vec<u8>,
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (0x1b & 0u8.wrapping_sub(x >> 7))
}

fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

impl Rijndael {
    /// Rijndael with a block and key each of 16, 20, 24, 28 or 32 bytes.
    ///
    /// # Errors
    /// Either length outside those five.
    pub fn new(block_bytes: usize, key: &[u8]) -> Result<Rijndael, String> {
        if !matches!(block_bytes, 16 | 20 | 24 | 28 | 32) {
            return Err(format!("Rijndael's block is 16, 20, 24, 28 or 32 bytes, not {block_bytes}."));
        }
        if !matches!(key.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(format!("Wrong key length {}. Rijndael takes 16, 20, 24, 28 or 32 bytes.",
                               key.len()));
        }
        let nb = block_bytes / 4;
        let nk = key.len() / 4;
        let rounds = nb.max(nk) + 6;
        let total = nb * (rounds + 1);
        let mut w = key.to_vec();
        w.resize(4 * total, 0);
        let mut rcon = 1u8;
        for i in nk..total {
            let mut t = [w[4 * i - 4], w[4 * i - 3], w[4 * i - 2], w[4 * i - 1]];
            if i % nk == 0 {
                t = [SBOX[t[1] as usize] ^ rcon, SBOX[t[2] as usize], SBOX[t[3] as usize],
                     SBOX[t[0] as usize]];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|b| SBOX[b as usize]);
            }
            for j in 0..4 {
                w[4 * i + j] = w[4 * (i - nk) + j] ^ t[j];
            }
        }
        Ok(Rijndael { nb, rounds, w })
    }

    /// The block size in bytes.
    pub fn block_bytes(&self) -> usize {
        4 * self.nb
    }

    fn add_round_key(&self, s: &mut [u8], round: usize) {
        let k = &self.w[4 * self.nb * round..4 * self.nb * (round + 1)];
        for (b, k) in s.iter_mut().zip(k) {
            *b ^= k;
        }
    }

    /// Row `r` of column `c` is byte `4c + r`, as in FIPS 197.
    fn shift_rows(&self, s: &mut [u8], inverse: bool) {
        let nb = self.nb;
        // The state is at most 32 bytes, so the copy a rotation needs
        // sits on the stack.
        let mut before = [0u8; 32];
        before[..s.len()].copy_from_slice(s);
        for r in 1..4 {
            let shift = SHIFTS[nb - 4][r - 1];
            for c in 0..nb {
                let from = if inverse { (c + nb - shift) % nb } else { (c + shift) % nb };
                s[4 * c + r] = before[4 * from + r];
            }
        }
    }

    fn mix_columns(s: &mut [u8], inverse: bool) {
        let m: [u8; 4] = if inverse { [14, 11, 13, 9] } else { [2, 3, 1, 1] };
        for col in s.chunks_exact_mut(4) {
            let a = [col[0], col[1], col[2], col[3]];
            for r in 0..4 {
                col[r] = mul(a[r], m[0]) ^ mul(a[(r + 1) % 4], m[1])
                    ^ mul(a[(r + 2) % 4], m[2]) ^ mul(a[(r + 3) % 4], m[3]);
            }
        }
    }
}

impl BlockCipher for Rijndael {
    fn blocksize(&self) -> usize {
        4 * self.nb
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut state = [0u8; 32];
        let s = &mut state[..4 * self.nb];
        s.copy_from_slice(&input[..4 * self.nb]);
        self.add_round_key(s, 0);
        for round in 1..=self.rounds {
            for b in s.iter_mut() {
                *b = SBOX[*b as usize];
            }
            self.shift_rows(s, false);
            if round != self.rounds {
                Rijndael::mix_columns(s, false);
            }
            self.add_round_key(s, round);
        }
        result.extend_from_slice(s);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut state = [0u8; 32];
        let s = &mut state[..4 * self.nb];
        s.copy_from_slice(&input[..4 * self.nb]);
        for round in (1..=self.rounds).rev() {
            self.add_round_key(s, round);
            if round != self.rounds {
                Rijndael::mix_columns(s, true);
            }
            self.shift_rows(s, true);
            for b in s.iter_mut() {
                *b = INV_SBOX[*b as usize];
            }
        }
        self.add_round_key(s, 0);
        result.extend_from_slice(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::aes::AesCrypto;

    /// With a 128 bit block this is AES; under each AES key size it must
    /// agree with the `aes` module, which FIPS 197's vectors pin.
    #[test]
    fn test_a_128_bit_block_is_aes() {
        for key_len in [16, 24, 32] {
            let key: Vec<u8> = (0..key_len as u8).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
            let mut r = Rijndael::new(16, &key).unwrap();
            let mut a = AesCrypto::new(&key).unwrap();
            for n in 0..20u8 {
                let block: Vec<u8> = (0..16u8).map(|i| i ^ n.wrapping_mul(29)).collect();
                let (mut x, mut y) = (Vec::new(), Vec::new());
                r.block_encrypt(&block, &mut x);
                a.block_encrypt(&block, &mut y);
                assert_eq!(x, y, "key {key_len}");
            }
        }
    }

    #[test]
    fn test_sizes_and_round_trips() {
        for nb in [16, 20, 24, 28, 32] {
            for nk in [16, 20, 24, 28, 32] {
                let mut r = Rijndael::new(nb, &vec![3; nk]).unwrap();
                assert_eq!(r.rounds, nb.max(nk) / 4 + 6);
                let block: Vec<u8> = (0..nb as u8).collect();
                let mut ct = vec![0xee];
                r.block_encrypt(&block, &mut ct);
                assert_eq!(ct.len(), nb + 1);
                let mut back = Vec::new();
                r.block_decrypt(&ct[1..], &mut back);
                assert_eq!(back, block);
            }
        }
        assert!(Rijndael::new(12, &[0; 16]).is_err());
        assert!(Rijndael::new(16, &[0; 12]).is_err());
    }
}
