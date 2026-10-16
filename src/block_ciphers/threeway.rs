/*!
3-Way, Joan Daemen's 1994 cipher: a 96-bit block, a 96-bit key and
eleven rounds, all of it on three 32-bit words.

## A round

The round key - the key, with a round constant XORed into the top half
of the first word and the bottom half of the third - is XORed in, then
`rho`: the linear mixing `theta`, a rotation of the first and third
words (`pi_1`), the nonlinear `gamma`, `a ^ (b | !c)` on each word with
the other two, and the opposite rotations (`pi_2`). After the eleventh
round the key and a twelfth constant are XORed in and `theta` applied
once more.

## Decryption is encryption

Decryption runs the same rounds with a different key and different
constants: the key passed through `theta` and then `mu`, which reverses
the order of all 96 bits, and constants generated from `0xb1b1` rather
than `0x0b0b`. The block is passed through `mu` before and after. The
constants step as a 16-bit linear feedback shift register,
`x << 1`, reduced by `0x11011`.

## Byte order

The key and the block are read as three big-endian 32-bit words, which
is how the specification's C does it on a big-endian machine, and how
Crypto++ and libmcrypt both read them.

## Constant time

Every step is a shift, rotation or logical operation on the three
words, with no table and no branch on data.

## Where the vectors come from

`vectors/threeway.vec`, written by `scripts/make_threeway_vectors.py`:
blocks on which Crypto++ 8.9.0 and libmcrypt 2.5.8 agree, with the
published tests both carry.
*/

use super::BlockCipher;

const BLOCK: usize = 12;
const ROUNDS: usize = 11;
const START_ENCRYPT: u32 = 0x0b0b;
const START_DECRYPT: u32 = 0xb1b1;

/// The twelve round constants starting from `start`.
fn round_constants(start: u32) -> [u32; ROUNDS + 1] {
    let mut constants = [0; ROUNDS + 1];
    let mut c = start;
    for constant in constants.iter_mut() {
        *constant = c;
        c <<= 1;
        if c & 0x10000 != 0 {
            c ^= 0x11011;
        }
    }
    constants
}

/// The linear step, as the specification writes it: every output word
/// is its own input and fourteen shifted halves and bytes of all three.
fn theta(a: &mut [u32; 3]) {
    let [a0, a1, a2] = *a;
    let mix = |x: u32, y: u32, z: u32| {
        x ^ (x >> 16) ^ (y << 16) ^ (y >> 16) ^ (z << 16)
            ^ (y >> 24) ^ (z << 8) ^ (z >> 8) ^ (x << 24) ^ (z >> 16)
            ^ (x << 16) ^ (z >> 24) ^ (x << 8)
    };
    *a = [mix(a0, a1, a2), mix(a1, a2, a0), mix(a2, a0, a1)];
}

/// The order of all 96 bits reversed: each word's bits reversed, and the
/// first and third words exchanged.
fn mu(a: &mut [u32; 3]) {
    *a = [a[2].reverse_bits(), a[1].reverse_bits(), a[0].reverse_bits()];
}

/// The nonlinear step.
fn gamma(a: &mut [u32; 3]) {
    let [a0, a1, a2] = *a;
    *a = [a0 ^ (a1 | !a2), a1 ^ (a2 | !a0), a2 ^ (a0 | !a1)];
}

fn rho(a: &mut [u32; 3]) {
    theta(a);
    a[0] = a[0].rotate_right(10);
    a[2] = a[2].rotate_left(1);
    gamma(a);
    a[0] = a[0].rotate_left(1);
    a[2] = a[2].rotate_right(10);
}

/// The eleven rounds and the output transformation, under `key` and the
/// constants starting from `start`.
fn rounds(a: &mut [u32; 3], key: &[u32; 3], start: u32) {
    let constants = round_constants(start);
    for (i, &c) in constants.iter().enumerate() {
        a[0] ^= key[0] ^ (c << 16);
        a[1] ^= key[1];
        a[2] ^= key[2] ^ c;
        if i < ROUNDS {
            rho(a);
        }
    }
    theta(a);
}

fn words(bytes: &[u8]) -> [u32; 3] {
    std::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4")))
}

#[derive(Clone)]
pub struct ThreeWay {
    key: [u32; 3],
    /// The key decryption uses: `mu(theta(key))`.
    inverse_key: [u32; 3],
}

impl ThreeWay {
    pub fn new(key: &[u8]) -> Result<ThreeWay, String> {
        if key.len() != BLOCK {
            return Err(format!("Wrong key length {}. 3-Way takes a 12 byte key.", key.len()));
        }
        let key = words(key);
        let mut inverse_key = key;
        theta(&mut inverse_key);
        mu(&mut inverse_key);
        Ok(ThreeWay { key, inverse_key })
    }
}

impl BlockCipher for ThreeWay {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut a = words(&input[..BLOCK]);
        rounds(&mut a, &self.key, START_ENCRYPT);
        for w in a {
            result.extend_from_slice(&w.to_be_bytes());
        }
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut a = words(&input[..BLOCK]);
        mu(&mut a);
        rounds(&mut a, &self.inverse_key, START_DECRYPT);
        mu(&mut a);
        for w in a {
            result.extend_from_slice(&w.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 8, 11, 13, 16, 24] {
            assert!(ThreeWay::new(&vec![0u8; len]).is_err(), "{len}");
        }
        assert!(ThreeWay::new(&[0u8; 12]).is_ok());
    }

    /// The constants are a 16-bit register: every one fits sixteen bits,
    /// and stepping with the top bit set reduces.
    #[test]
    fn test_the_round_constants() {
        for start in [START_ENCRYPT, START_DECRYPT] {
            let c = round_constants(start);
            assert_eq!(c[0], start);
            for pair in c.windows(2) {
                assert!(pair[1] < 0x10000);
                let expected = if pair[0] & 0x8000 != 0 { (pair[0] << 1) ^ 0x11011 } else { pair[0] << 1 };
                assert_eq!(pair[1], expected);
            }
        }
        // 0xb1b1 has its top bit set, so its first step reduces.
        assert_eq!(round_constants(START_DECRYPT)[1], (0xb1b1 << 1) ^ 0x11011);
    }

    /// `mu` reverses all 96 bits: applied to a single set bit at
    /// position `p`, counting from the top of the first word, it gives
    /// the bit at `95 - p`.
    #[test]
    fn test_mu_reverses_all_96_bits() {
        for p in 0..96 {
            let mut a = [0u32; 3];
            a[p / 32] = 1 << (31 - p % 32);
            mu(&mut a);
            let q = 95 - p;
            let mut expected = [0u32; 3];
            expected[q / 32] = 1 << (31 - q % 32);
            assert_eq!(a, expected, "{p}");
        }
    }

    /// `theta` is linear: theta(x ^ y) = theta(x) ^ theta(y).
    #[test]
    fn test_theta_is_linear() {
        let x = [0x0123_4567, 0x89ab_cdef, 0xfedc_ba98];
        let y = [0x7654_3210, 0x0f1e_2d3c, 0x4b5a_6978];
        let (mut tx, mut ty) = (x, y);
        theta(&mut tx);
        theta(&mut ty);
        let mut txy = [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2]];
        theta(&mut txy);
        assert_eq!(txy, [tx[0] ^ ty[0], tx[1] ^ ty[1], tx[2] ^ ty[2]]);
    }

    /// Decryption inverts encryption.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x3a7_1994u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..64 {
            let key: Vec<u8> = (0..BLOCK).map(|_| next()).collect();
            let block: Vec<u8> = (0..BLOCK).map(|_| next()).collect();
            let mut c = ThreeWay::new(&key).unwrap();
            let (mut out, mut back) = (Vec::new(), Vec::new());
            c.block_encrypt(&block, &mut out);
            c.block_decrypt(&out, &mut back);
            assert_eq!(back, block);
            assert_ne!(out, block);
        }
    }
}
