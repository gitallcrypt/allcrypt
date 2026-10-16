/*!
HIGHT, the Korean standard TTAS.KO-12.0040/R1 and ISO/IEC 18033-3's
lightweight 64-bit cipher: a 64-bit block, a 128-bit key and 32 rounds
of byte additions, XORs and rotations - an 8-branch generalised Feistel
network built for small hardware.

## Byte order

The standard numbers the bytes of the key and the block from 15 and 7
down to 0, most significant first, and prints its test vectors that
way. Implementations, and this one, keep byte `i` at array index `i`,
so the standard's printed vectors are reversed byte strings here.

## A round

Four of the eight state bytes change, each from its neighbour: `F0`
(`x <<< 1 ^ x <<< 2 ^ x <<< 7`) added to a subkey and XORed in, or `F1`
(`x <<< 3 ^ x <<< 4 ^ x <<< 6`) XORed with a subkey and added. The
positions move round by round, so the eight bytes rotate one place each
round. Whitening keys - four key bytes, half added and half XORed -
come before the first round and after the last.

## The key schedule

128 subkeys, each a key byte plus a constant. The constants are a 7-bit
linear feedback shift register from `0x5a`; both they and `F0` and `F1`
are computed here from their rules.

## Constant time

It has no tables in this form - `F0` and `F1` are rotations - and no
branch on data, so it is constant time.

## Where the vectors come from

`vectors/hight.vec`, written by `scripts/make_hight_vectors.py`: blocks
on which Crypto++ 8.9.0 and go-krypto agree, with KISA's known-answer
tests and the standard's own examples.
*/

use super::BlockCipher;

const BLOCK: usize = 8;
const ROUNDS: usize = 32;

/// The 128 subkey constants: `0x5a`, and each next one the previous
/// shifted right with bit 3 XOR bit 0 of it as the new bit 6.
const DELTA: [u8; 128] = {
    let mut delta = [0u8; 128];
    let mut d = 0x5au8;
    let mut i = 0;
    while i < 128 {
        delta[i] = d;
        d = (d >> 1) | ((((d >> 3) ^ d) & 1) << 6);
        i += 1;
    }
    delta
};

fn f0(x: u8) -> u8 {
    x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(7)
}

fn f1(x: u8) -> u8 {
    x.rotate_left(3) ^ x.rotate_left(4) ^ x.rotate_left(6)
}

#[derive(Clone)]
pub struct Hight {
    /// Whitening keys: the first four before the rounds, the last four
    /// after.
    whitening: [u8; 8],
    subkeys: [u8; 4 * ROUNDS],
}

impl Hight {
    pub fn new(key: &[u8]) -> Result<Hight, String> {
        if key.len() != 16 {
            return Err(format!("Wrong key length {}. HIGHT takes a 16 byte key.", key.len()));
        }
        let whitening = std::array::from_fn(|i| if i < 4 { key[i + 12] } else { key[i - 4] });
        let mut subkeys = [0u8; 4 * ROUNDS];
        for i in 0..8 {
            for j in 0..8 {
                let k = (j + 8 - i) % 8;
                subkeys[16 * i + j] = key[k].wrapping_add(DELTA[16 * i + j]);
                subkeys[16 * i + j + 8] = key[k + 8].wrapping_add(DELTA[16 * i + j + 8]);
            }
        }
        Ok(Hight { whitening, subkeys })
    }
}

/// The positions round `r` reads and writes: `[i0, ..., i7]` with `i0`
/// the byte first changed and each next one place lower, mod 8.
fn positions(r: usize) -> [usize; 8] {
    std::array::from_fn(|j| (7 + 16 - r % 8 - j) % 8)
}

impl BlockCipher for Hight {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let w = &self.whitening;
        let p = &input[..BLOCK];
        let mut x = [p[0].wrapping_add(w[0]), p[1], p[2] ^ w[1], p[3],
                     p[4].wrapping_add(w[2]), p[5], p[6] ^ w[3], p[7]];
        for r in 0..ROUNDS {
            let i = positions(r);
            let k = &self.subkeys[4 * r..4 * r + 4];
            x[i[0]] ^= f0(x[i[1]]).wrapping_add(k[3]);
            x[i[2]] = x[i[2]].wrapping_add(f1(x[i[3]]) ^ k[2]);
            x[i[4]] ^= f0(x[i[5]]).wrapping_add(k[1]);
            x[i[6]] = x[i[6]].wrapping_add(f1(x[i[7]]) ^ k[0]);
        }
        result.extend_from_slice(&[x[1].wrapping_add(w[4]), x[2], x[3] ^ w[5], x[4],
                                   x[5].wrapping_add(w[6]), x[6], x[7] ^ w[7], x[0]]);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let w = &self.whitening;
        let c = &input[..BLOCK];
        let mut x = [c[7], c[0].wrapping_sub(w[4]), c[1], c[2] ^ w[5],
                     c[3], c[4].wrapping_sub(w[6]), c[5], c[6] ^ w[7]];
        for r in (0..ROUNDS).rev() {
            let i = positions(r);
            let k = &self.subkeys[4 * r..4 * r + 4];
            x[i[6]] = x[i[6]].wrapping_sub(f1(x[i[7]]) ^ k[0]);
            x[i[4]] ^= f0(x[i[5]]).wrapping_add(k[1]);
            x[i[2]] = x[i[2]].wrapping_sub(f1(x[i[3]]) ^ k[2]);
            x[i[0]] ^= f0(x[i[1]]).wrapping_add(k[3]);
        }
        result.extend_from_slice(&[x[0].wrapping_sub(w[0]), x[1], x[2] ^ w[1], x[3],
                                   x[4].wrapping_sub(w[2]), x[5], x[6] ^ w[3], x[7]]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 8, 15, 17, 24, 32] {
            assert!(Hight::new(&vec![0u8; len]).is_err(), "{len}");
        }
    }

    /// The constants are a 7-bit register of period 127: the 128th is the
    /// first again, and none repeats before that.
    #[test]
    fn test_the_constants_are_a_register() {
        assert_eq!(DELTA[127], DELTA[0]);
        let mut seen = [false; 128];
        for &d in &DELTA[..127] {
            assert!(d < 0x80 && d != 0);
            assert!(!seen[usize::from(d)]);
            seen[usize::from(d)] = true;
        }
    }

    /// The round positions: round 0 starts at byte 7 and each round one
    /// lower, as the standard's round function moves the eight bytes.
    #[test]
    fn test_the_positions_rotate() {
        assert_eq!(positions(0), [7, 6, 5, 4, 3, 2, 1, 0]);
        assert_eq!(positions(1), [6, 5, 4, 3, 2, 1, 0, 7]);
        assert_eq!(positions(31), [0, 7, 6, 5, 4, 3, 2, 1]);
    }

    /// Decryption inverts encryption.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x4167_4854u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..64 {
            let key: Vec<u8> = (0..16).map(|_| next()).collect();
            let block: Vec<u8> = (0..BLOCK).map(|_| next()).collect();
            let mut c = Hight::new(&key).unwrap();
            let (mut out, mut back) = (Vec::new(), Vec::new());
            c.block_encrypt(&block, &mut out);
            c.block_decrypt(&out, &mut back);
            assert_eq!(back, block);
            assert_ne!(out, block);
        }
    }
}
