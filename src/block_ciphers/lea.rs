/*!
LEA, the Korean standard KS X 3246 (2013): a 128-bit block, a key of 16,
24 or 32 bytes, and 24, 28 or 32 rounds to match - additions, rotations
and XORs on four 32-bit words, with no table.

## Byte order

The key and the block are read as little-endian 32-bit words, as the
standard and its test vectors write them.

## A round

Each round key is six words, and the state's four words become
`((X0 ^ K0) + (X1 ^ K1)) <<< 9`, `((X1 ^ K2) + (X2 ^ K3)) >>> 5`,
`((X2 ^ K4) + (X3 ^ K5)) >>> 3` and `X0`.

## The key schedule

The key's words are a register `T` of four, six or eight words. Round
`i` adds `delta[i mod n] <<< i+j` to six of them, rotates each by 1, 3,
6, 11, 13 and 17, and takes them as the round key; with a 16 byte key,
whose register has four words, `T1` stands in three times. The eight
constants are the hexadecimal digits of the square root of 766965,
"LEA" written in decimal ASCII, after the point - read here from a
generated file, `lea_table.rs`, which checks two implementations'
tables against that rule.

## Constant time

Every step is an addition, rotation or XOR of words, with no table and
no branch on data.

## Where the vectors come from

`vectors/lea.vec`, written by `scripts/make_lea_vectors.py`: blocks on
which Crypto++ 8.9.0 and go-krypto agree, with KISA's known-answer
tests and Crypto++'s published vectors.
*/

use super::lea_table::DELTA;
use super::BlockCipher;

const BLOCK: usize = 16;

#[derive(Clone)]
pub struct Lea {
    round_keys: Vec<[u32; 6]>,
}

fn words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4")))
}

impl Lea {
    pub fn new(key: &[u8]) -> Result<Lea, String> {
        // Round i's constant for register word j, with an n-word register.
        let delta = |n: usize, i: usize, j: usize| DELTA[i % n].rotate_left((i + j) as u32);
        let round_keys = match key.len() {
            16 => {
                let mut t: [u32; 4] = words(key);
                (0..24).map(|i| {
                    for (j, rotation) in [1, 3, 6, 11].into_iter().enumerate() {
                        t[j] = t[j].wrapping_add(delta(4, i, j)).rotate_left(rotation);
                    }
                    [t[0], t[1], t[2], t[1], t[3], t[1]]
                }).collect()
            }
            24 => {
                let mut t: [u32; 6] = words(key);
                (0..28).map(|i| {
                    for (j, rotation) in [1, 3, 6, 11, 13, 17].into_iter().enumerate() {
                        t[j] = t[j].wrapping_add(delta(6, i, j)).rotate_left(rotation);
                    }
                    t
                }).collect()
            }
            32 => {
                let mut t: [u32; 8] = words(key);
                (0..32).map(|i| {
                    let mut round_key = [0u32; 6];
                    for (j, rotation) in [1, 3, 6, 11, 13, 17].into_iter().enumerate() {
                        let at = (6 * i + j) % 8;
                        t[at] = t[at].wrapping_add(delta(8, i, j)).rotate_left(rotation);
                        round_key[j] = t[at];
                    }
                    round_key
                }).collect()
            }
            n => return Err(format!("Wrong key length {n}. LEA takes a 16, 24 or 32 byte key.")),
        };
        Ok(Lea { round_keys })
    }

    pub fn rounds(&self) -> usize {
        self.round_keys.len()
    }
}

fn store(x: [u32; 4], result: &mut Vec<u8>) {
    for w in x {
        result.extend_from_slice(&w.to_le_bytes());
    }
}

impl BlockCipher for Lea {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut x: [u32; 4] = words(&input[..BLOCK]);
        for k in &self.round_keys {
            x = [
                ((x[0] ^ k[0]).wrapping_add(x[1] ^ k[1])).rotate_left(9),
                ((x[1] ^ k[2]).wrapping_add(x[2] ^ k[3])).rotate_right(5),
                ((x[2] ^ k[4]).wrapping_add(x[3] ^ k[5])).rotate_right(3),
                x[0],
            ];
        }
        store(x, result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut x: [u32; 4] = words(&input[..BLOCK]);
        for k in self.round_keys.iter().rev() {
            let x0 = x[3];
            let x1 = x[0].rotate_right(9).wrapping_sub(x0 ^ k[0]) ^ k[1];
            let x2 = x[1].rotate_left(5).wrapping_sub(x1 ^ k[2]) ^ k[3];
            let x3 = x[2].rotate_left(3).wrapping_sub(x2 ^ k[4]) ^ k[5];
            x = [x0, x1, x2, x3];
        }
        store(x, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 8, 15, 17, 20, 23, 25, 31, 33, 64] {
            assert!(Lea::new(&vec![0u8; len]).is_err(), "{len}");
        }
        for (len, rounds) in [(16, 24), (24, 28), (32, 32)] {
            assert_eq!(Lea::new(&vec![0u8; len]).unwrap().rounds(), rounds);
        }
    }

    /// The 16 byte schedule repeats T1 in three places, and the others
    /// take six distinct register words.
    #[test]
    fn test_the_round_key_shapes() {
        let key: Vec<u8> = (1..=32).collect();
        for k in Lea::new(&key[..16]).unwrap().round_keys {
            assert_eq!((k[1], k[1]), (k[3], k[5]));
        }
        for len in [24, 32] {
            let keys = Lea::new(&key[..len]).unwrap().round_keys;
            assert!(keys.iter().all(|k| k[1] != k[3]), "{len}");
        }
    }

    /// Decryption inverts encryption at every key length.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x1ea_2013u32;
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
                let mut c = Lea::new(&key).unwrap();
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block, "{len}");
                assert_ne!(out, block);
            }
        }
    }
}
