/*!
PRESENT (Bogdanov, Knudsen, Leander, Paar, Poschmann, Robshaw, Seurin
and Vikkelsoe, CHES 2007), the lightweight cipher of ISO/IEC 29192-2: a
64-bit block, an 80 or 128 bit key, and 31 rounds of a round key, sixteen
4-bit S-boxes and a bit permutation, with a last round key after them.

## A round

The state is one 64-bit number. A round XORs the round key in, puts
every nibble through the S-box (`present_table.rs`, generated from three
implementations that agree), and moves bit `i` to bit `16 i mod 63`, bit
63 staying where it is.

## The key schedule

The key is a register of 80 or 128 bits; each round key is its top 64.
Between round keys the register is rotated left 61 bits, its top
nibble (at 128 bits its top two) goes through the S-box, and the
round's counter, 1 to 31, is XORed into bits 19 to 15 (at 128 bits, 66
to 62). The key length chooses which: 10 or 16 bytes.

## Byte order

The specification's: the key, the block and the result are the numbers'
bytes, most significant first, as the paper prints them.

## Not constant time

Each S-box is a lookup in a 16-byte table, indexed by data. The table
fits in one cache line, which leaves little to measure, but nothing here
guarantees it.

## Where the vectors come from

`vectors/present.vec`, written by `scripts/make_present_vectors.py`:
blocks on which Nirusu/PRESENT.go, kurtfu/present and OpenTitan's Python
PRESENT agree, with the paper's test vectors and PRESENT.go's 128 bit
ones.
*/

use super::present_table::S;
use super::BlockCipher;

const ROUNDS: usize = 31;

const fn invert(s: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[s[i] as usize] = i as u8;
        i += 1;
    }
    out
}

const S_INV: [u8; 16] = invert(S);

/// Where bit `i` of the state goes.
fn position(i: u32) -> u32 {
    if i == 63 {
        63
    } else {
        (16 * i) % 63
    }
}

fn substitute(state: u64, table: &[u8; 16]) -> u64 {
    (0..16).fold(0, |out, i| out | u64::from(table[(state >> (4 * i) & 0xf) as usize]) << (4 * i))
}

fn permute(state: u64) -> u64 {
    (0..64).fold(0, |out, i| out | (state >> i & 1) << position(i))
}

fn unpermute(state: u64) -> u64 {
    (0..64).fold(0, |out, i| out | (state >> position(i) & 1) << i)
}

#[derive(Clone)]
pub struct Present {
    round_keys: [u64; ROUNDS + 1],
}

impl Present {
    /// An 80 bit key (10 bytes) or a 128 bit one (16).
    pub fn new(key: &[u8]) -> Result<Present, String> {
        let mut round_keys = [0u64; ROUNDS + 1];
        match key.len() {
            10 => {
                // The register in the low 80 bits.
                let mut k = key.iter().fold(0u128, |a, &b| a << 8 | u128::from(b));
                let mask = (1u128 << 80) - 1;
                for (i, rk) in round_keys.iter_mut().enumerate() {
                    *rk = (k >> 16) as u64;
                    k = ((k << 61) | (k >> 19)) & mask;
                    k = (k & !(0xf << 76)) | u128::from(S[(k >> 76) as usize]) << 76;
                    k ^= ((i + 1) as u128) << 15;
                }
            }
            16 => {
                let mut k = u128::from_be_bytes(key.try_into().expect("16 bytes"));
                for (i, rk) in round_keys.iter_mut().enumerate() {
                    *rk = (k >> 64) as u64;
                    k = k.rotate_left(61);
                    k = (k & !(0xff << 120))
                        | u128::from(S[(k >> 124) as usize]) << 124
                        | u128::from(S[(k >> 120 & 0xf) as usize]) << 120;
                    k ^= ((i + 1) as u128) << 62;
                }
            }
            other => {
                return Err(format!("Wrong key length {other}. PRESENT takes a 10 or 16 byte \
                                    key, 80 or 128 bits."));
            }
        }
        Ok(Present { round_keys })
    }
}

impl BlockCipher for Present {
    fn blocksize(&self) -> usize {
        8
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut state = u64::from_be_bytes(input[..8].try_into().expect("8 bytes"));
        for &k in &self.round_keys[..ROUNDS] {
            state = permute(substitute(state ^ k, &S));
        }
        state ^= self.round_keys[ROUNDS];
        result.extend_from_slice(&state.to_be_bytes());
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut state = u64::from_be_bytes(input[..8].try_into().expect("8 bytes"));
        state ^= self.round_keys[ROUNDS];
        for &k in self.round_keys[..ROUNDS].iter().rev() {
            state = substitute(unpermute(state), &S_INV) ^ k;
        }
        result.extend_from_slice(&state.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_lengths() {
        for len in 0..=40 {
            assert_eq!(Present::new(&vec![0; len]).is_ok(), len == 10 || len == 16, "{len}");
        }
    }

    /// The permutation is one: every bit lands on a different bit, and
    /// the inverse brings each back.
    #[test]
    fn test_the_permutation() {
        let mut seen = 0u64;
        for i in 0..64 {
            seen |= 1 << position(i);
            assert_eq!(unpermute(permute(1 << i)), 1 << i);
        }
        assert_eq!(seen, u64::MAX);
        assert_eq!((position(1), position(4), position(62)), (16, 1, 47));
    }

    #[test]
    fn test_the_inverse_sbox() {
        for x in 0..16u8 {
            assert_eq!(S_INV[S[x as usize] as usize], x);
        }
    }

    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x9e5e_2007u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..32 {
            for len in [10, 16] {
                let key: Vec<u8> = (0..len).map(|_| next()).collect();
                let block: Vec<u8> = (0..8).map(|_| next()).collect();
                let mut c = Present::new(&key).unwrap();
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block);
            }
        }
    }
}
