//! SOSEMANUK (Berbain, Billet, Canteaut, Courtois, Gilbert, Goubin,
//! Gouget, Granboulan, Lauradoux, Minier, Pornin and Sibert): an eSTREAM
//! software-profile stream cipher built from Serpent and SNOW 2.0.
//!
//! A key of 1 to 32 bytes - the designers claim 128 bits of security
//! whatever its length - a 16 byte IV, and 16 bytes of keystream per
//! four steps.
//!
//! ## Initialisation: Serpent24
//!
//! The key goes through Serpent's key schedule (padded with a 1 bit to
//! 256 bits, as Serpent pads), of which 25 subkeys are used. The IV, as
//! four little-endian words, is encrypted by 24 Serpent rounds - each
//! one complete, the linear transform included - and a final XOR with
//! the 25th subkey. The state is read from the block at three points:
//!
//! ```text
//! after round 12:  (s7, s8, s9, s10) = (Y3, Y2, Y1, Y0)
//! after round 18:  (s5, s6) = (Y1, Y3),   R1 = Y0,   R2 = Y2
//! after round 24:  (s1, s2, s3, s4) = (Y3, Y2, Y1, Y0)   (the subkey added)
//! ```
//!
//! ## A step
//!
//! An LFSR of ten 32 bit words over GF(2^32) and a two-word state
//! machine. Step `t`, with `s(t) .. s(t+9)` in the register:
//!
//! ```text
//! R1 = R2 + (s(t+1), or s(t+1) ^ s(t+8) when the old R1 is odd)
//! R2 = (old R1 * 0x54655307) <<< 7
//! s(t+10) = s(t+9) ^ α^-1 s(t+3) ^ α s(t)        (s(t) leaves)
//! f(t) = (s(t+9) + R1) ^ R2
//! ```
//!
//! Four steps give `f(t..t+3)` and the departed `s(t..t+3)`, and the
//! keystream words are Serpent's S2, bitsliced, over `f(t)..f(t+3)` -
//! `f(t)` the low input word - XORed with `s(t)..s(t+3)`, written
//! little endian from `t` up.
//!
//! `α` is a root of `X^4 + β^23 X^3 + β^245 X^2 + β^48 X + β^239` over
//! GF(2^8) = GF(2)[β]/(β^8 + β^7 + β^5 + β^3 + 1); a word is
//! `a3 α^3 + a2 α^2 + a1 α + a0` with `a0` its least significant byte.
//! Multiplying by `α` shifts a byte up and folds the top byte back in;
//! by `α^-1`, down and the bottom byte.
//!
//! ## Constant time
//!
//! Serpent's S-boxes are the bitsliced normal forms of
//! `block_ciphers::serpent`. The foldings by `α` and `α^-1` are linear in
//! the byte folded, so each is eight masked XORs of a precomputed word
//! per bit, not a table look-up; the reference implementation's 256-word
//! tables would index on the secret state. The multiplexer is a mask.

use crate::block_ciphers::serpent::{apply_sbox, key_schedule, linear};
use crate::stream_ciphers::StreamCipher;

/// Multiplication in GF(2^8) modulo `x^8 + x^7 + x^5 + x^3 + 1`.
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0u8;
    while b != 0 {
        if b & 1 == 1 {
            out ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0xa9; // x^7 + x^5 + x^3 + 1, the x^8 term dropped
        }
        b >>= 1;
    }
    out
}

const fn beta_pow(n: u32) -> u8 {
    let mut out = 1u8;
    let mut i = 0;
    while i < n {
        out = gf_mul(out, 2);
        i += 1;
    }
    out
}

/// `β^255 = 1`, so `β^-n = β^(255 - n)`.
const fn beta_inv_pow(n: u32) -> u8 {
    beta_pow((255 - n % 255) % 255)
}

/// What a top byte `c` contributes when a word is multiplied by `α`:
/// `c α^4`, with `α^4 = β^23 α^3 + β^245 α^2 + β^48 α + β^239`.
const fn fold_a(c: u8) -> u32 {
    (gf_mul(c, beta_pow(23)) as u32) << 24 | (gf_mul(c, beta_pow(245)) as u32) << 16
        | (gf_mul(c, beta_pow(48)) as u32) << 8 | gf_mul(c, beta_pow(239)) as u32
}

/// What a bottom byte `c` contributes when a word is multiplied by
/// `α^-1`: `c α^-1 = c β^-239 (α^3 + β^23 α^2 + β^245 α + β^48)`.
const fn fold_ia(c: u8) -> u32 {
    let d = gf_mul(c, beta_inv_pow(239));
    (d as u32) << 24 | (gf_mul(d, beta_pow(23)) as u32) << 16
        | (gf_mul(d, beta_pow(245)) as u32) << 8 | gf_mul(d, beta_pow(48)) as u32
}

/// The folds of each single bit; any byte's fold is the XOR of its
/// bits'.
const FOLD_A: [u32; 8] = {
    let mut t = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        t[i] = fold_a(1 << i);
        i += 1;
    }
    t
};
const FOLD_IA: [u32; 8] = {
    let mut t = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        t[i] = fold_ia(1 << i);
        i += 1;
    }
    t
};

/// The fold of byte `c` from its bits' folds, by mask: no index on `c`.
fn fold(basis: &[u32; 8], c: u32) -> u32 {
    let mut out = 0u32;
    for (i, word) in basis.iter().enumerate() {
        out ^= word & ((c >> i) & 1).wrapping_neg();
    }
    out
}

fn mul_alpha(x: u32) -> u32 {
    x << 8 ^ fold(&FOLD_A, x >> 24)
}

fn div_alpha(x: u32) -> u32 {
    x >> 8 ^ fold(&FOLD_IA, x & 0xff)
}

/// SOSEMANUK under one key and IV.
#[derive(Clone)]
pub struct Sosemanuk {
    /// `s(t) .. s(t+9)`, `s(t)` at `s[head]`.
    s: [u32; 10],
    head: usize,
    r1: u32,
    r2: u32,
    block: [u8; 16],
    used: usize,
}

impl core::fmt::Debug for Sosemanuk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sosemanuk").finish_non_exhaustive()
    }
}

impl Sosemanuk {
    /// SOSEMANUK under a key of 1 to 32 bytes and a 16 byte IV.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Sosemanuk, String> {
        if key.is_empty() || key.len() > 32 {
            return Err(format!("A SOSEMANUK key is 1 to 32 bytes, not {}.", key.len()));
        }
        if iv.len() != 16 {
            return Err(format!("A SOSEMANUK IV is 16 bytes, not {}.", iv.len()));
        }
        let subkeys = key_schedule(key);
        let mut y: [u32; 4] = core::array::from_fn(|i| {
            u32::from_le_bytes(iv[4 * i..4 * i + 4].try_into().expect("4 bytes"))
        });
        let mut s = [0u32; 10];
        let (mut r1, mut r2) = (0, 0);
        for (round, subkey) in subkeys.iter().take(24).enumerate() {
            for (word, k) in y.iter_mut().zip(subkey) {
                *word ^= k;
            }
            apply_sbox(round % 8, &mut y);
            linear(&mut y);
            match round + 1 {
                // s7..s10 are s[6..10], counting from s1 = s[0].
                12 => (s[6], s[7], s[8], s[9]) = (y[3], y[2], y[1], y[0]),
                18 => {
                    (s[4], s[5]) = (y[1], y[3]);
                    (r1, r2) = (y[0], y[2]);
                }
                _ => {}
            }
        }
        for (word, k) in y.iter_mut().zip(&subkeys[24]) {
            *word ^= k;
        }
        (s[0], s[1], s[2], s[3]) = (y[3], y[2], y[1], y[0]);
        Ok(Sosemanuk { s, head: 0, r1, r2, block: [0; 16], used: 16 })
    }

    fn at(&self, i: usize) -> u32 {
        self.s[(self.head + i) % 10]
    }

    /// One step: the word that left the register, `s(t)`, and `f(t)`.
    fn step(&mut self) -> (u32, u32) {
        let odd = (self.r1 & 1).wrapping_neg();
        let chosen = self.at(1) ^ (self.at(8) & odd);
        let old_r1 = self.r1;
        self.r1 = self.r2.wrapping_add(chosen);
        self.r2 = old_r1.wrapping_mul(0x5465_5307).rotate_left(7);
        let leaving = self.at(0);
        let entering = self.at(9) ^ div_alpha(self.at(3)) ^ mul_alpha(leaving);
        self.s[self.head] = entering;
        self.head = (self.head + 1) % 10;
        // s(t+9) is now one place from the end, the new word at the end.
        let f = self.at(8).wrapping_add(self.r1) ^ self.r2;
        (leaving, f)
    }

    fn next_block(&mut self) -> [u8; 16] {
        let mut v = [0u32; 4];
        let mut f = [0u32; 4];
        for i in 0..4 {
            (v[i], f[i]) = self.step();
        }
        apply_sbox(2, &mut f);
        let mut out = [0u8; 16];
        for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
            chunk.copy_from_slice(&(f[i] ^ v[i]).to_le_bytes());
        }
        out
    }

    /// XOR the keystream onto `data`, continuing where the last call
    /// stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == 16 {
                self.block = self.next_block();
                self.used = 0;
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

impl StreamCipher for Sosemanuk {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The folds by mask equal the products they stand for, for every
    /// byte.
    #[test]
    fn test_the_masked_folds_are_the_products() {
        for c in 0..=255u8 {
            assert_eq!(fold(&FOLD_A, u32::from(c)), fold_a(c), "{c}");
            assert_eq!(fold(&FOLD_IA, u32::from(c)), fold_ia(c), "{c}");
        }
    }

    /// `α^-1` undoes `α`, both ways, and `α` is a root of its
    /// polynomial: `α^4 = β^23 α^3 + β^245 α^2 + β^48 α + β^239`.
    #[test]
    fn test_alpha() {
        let mut x = 0x0123_4567u32;
        for _ in 0..1000 {
            assert_eq!(div_alpha(mul_alpha(x)), x);
            assert_eq!(mul_alpha(div_alpha(x)), x);
            x = x.wrapping_mul(0x9e37_79b9).rotate_left(5) ^ 0x3c;
        }
        let alpha = 1u32 << 8;
        let alpha4 = mul_alpha(mul_alpha(mul_alpha(alpha)));
        assert_eq!(alpha4, u32::from_be_bytes([beta_pow(23), beta_pow(245), beta_pow(48),
                                                beta_pow(239)]));
    }

    /// β generates the field: its order is 255, not a divisor of it.
    #[test]
    fn test_beta_is_primitive() {
        for n in [1, 3, 5, 15, 17, 51, 85] {
            assert_ne!(beta_pow(n), 1, "{n}");
        }
        assert_eq!(beta_pow(255), 1);
    }

    #[test]
    fn test_streaming_equals_one_call() {
        let key: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(29) ^ 0x5c).collect();
        let iv = [7u8; 16];
        let mut whole = vec![0u8; 200];
        Sosemanuk::new(&key, &iv).expect("key").apply_keystream(&mut whole);
        for piece in [1, 3, 15, 16, 17, 33] {
            let mut c = Sosemanuk::new(&key, &iv).expect("key");
            let mut got = vec![0u8; 200];
            for chunk in got.chunks_mut(piece) {
                c.apply_keystream(chunk);
            }
            assert_eq!(got, whole, "pieces of {piece}");
        }
    }

    #[test]
    fn test_other_lengths_are_refused() {
        for n in [0, 33, 40] {
            assert_eq!(Sosemanuk::new(&vec![1; n], &[0; 16]).unwrap_err(),
                       format!("A SOSEMANUK key is 1 to 32 bytes, not {n}."));
        }
        for n in [0, 8, 15, 17, 32] {
            assert_eq!(Sosemanuk::new(&[1; 16], &vec![0; n]).unwrap_err(),
                       format!("A SOSEMANUK IV is 16 bytes, not {n}."));
        }
    }
}
