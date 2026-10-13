//! Strumok, DSTU 8845:2019: Ukraine's stream cipher.
//!
//! A 256 or 512-bit key, a 256-bit IV, and a keystream of 64-bit words.
//!
//! ## The generator
//!
//! A linear feedback shift register of sixteen 64-bit words `S0..S15`
//! over GF(2^64), and a finite state machine of two words `r1, r2`
//! (`r0, r1` here). One step:
//!
//! ```text
//! S16 = α·S0 ⊕ α⁻¹·S11 ⊕ S13
//! r2' = T(r1),   r1' = r2 ⊞ S13
//! ```
//!
//! and the keystream word after a step is `(S15 ⊞ r1) ⊕ r2 ⊕ S0` over the
//! new state, `⊞` being addition modulo 2^64.
//!
//! - `α` is multiplication by a root of
//!   x^8 + d7·x^7 + 3f·x^6 + 04·x^5 + 12·x^4 + 5e·x^3 + 04 over GF(2^8)
//!   modulo x^8 + x^4 + x^3 + x^2 + 1, the field of Kalyna, with a word's
//!   least significant byte the constant coefficient. Multiplying by
//!   `α` shifts the word up a byte and adds the top byte times the
//!   polynomial's low coefficients; `α⁻¹` shifts down a byte and adds the
//!   bottom byte times them divided by the constant coefficient. Both
//!   are 256-entry tables of words, built here from those eight
//!   coefficients.
//! - `T` is one column of Kalyna's round without its key: byte `r` of
//!   the little-endian word through `π[r mod 4]`, then the column times
//!   Kalyna's MDS matrix. It is eight 256-entry tables of words, built
//!   here from Kalyna's S-boxes and multiplication tables.
//!
//! ## Initialisation
//!
//! The key words and IV words are loaded into `S` in the arrangement
//! the standard gives for each key length, some complemented, the IV
//! words XORed onto four of them. Then 32 steps in which the feedback
//! also takes `(S15 ⊞ r1) ⊕ r2`. `r1` and `r2` start at zero.
//!
//! ## Byte order
//!
//! The standard prints keys, IVs and keystream as 64-bit words, the key
//! and IV from the most significant word down (K3..K0, IV3..IV0). As
//! bytes, here, **each word is little endian and word 0 comes first**,
//! in the key, the IV and the keystream alike. That is UAPKI's and
//! uacrypt's convention, which the vectors are checked against.
//! `docs/pitfalls.md` records an implementation that writes each word
//! big endian instead.
//!
//! ## Not constant time
//!
//! `T` and the `α` multiplications are tables indexed by the state, as
//! in the standard and in both witnesses. `scripts/ct_check.py` has the
//! case `strumok_keystream`, which allows leaks in `alpha`, `alpha_inv`
//! and `t` and nowhere else.
//!
//! ## In the catalogue
//!
//! `strumok`, a stream cipher taking a 32 or 64-byte key and a 32-byte
//! nonce (the IV). There is no counter, so it does not seek.
//!
//! ## Where the vectors come from
//!
//! `vectors/strumok.vec`, written by `scripts/make_strumok_vectors.py`:
//! the standard's Annex D examples, UAPKI's self-test, the two examples
//! of the conformance letter uacrypt carries, and rows on which UAPKI's
//! `dstu8845.c` and uacrypt's `hazmat/strumok.rs` agree.

use crate::block_ciphers::kalyna::{gf_mul, MUL, SBOX};
use crate::stream_ciphers::StreamCipher;

/// The coefficients of `α`'s minimal polynomial below x^8, constant
/// first: x^8 = Σ C[k]·x^k.
const C: [u8; 8] = [0x04, 0x00, 0x00, 0x5e, 0x12, 0x04, 0x3f, 0xd7];

const fn gf_inv(a: u8) -> u8 {
    // a^254 in GF(2^8).
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u32;
    while e != 0 {
        if e & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

/// `ALPHA[b]`: the word added when `α` shifts byte `b` out of the top.
const ALPHA: [u64; 256] = {
    let mut t = [0u64; 256];
    let mut b = 0;
    while b < 256 {
        let mut k = 0;
        while k < 8 {
            t[b] |= (gf_mul(b as u8, C[k]) as u64) << (8 * k);
            k += 1;
        }
        b += 1;
    }
    t
};

/// `ALPHA_INV[b]`: the word added when `α⁻¹` shifts byte `b` out of the
/// bottom: `b / C[0]` times x^7 + Σ C[k]·x^(k-1).
const ALPHA_INV: [u64; 256] = {
    let c0_inv = gf_inv(C[0]);
    let mut t = [0u64; 256];
    let mut b = 0;
    while b < 256 {
        let q = gf_mul(b as u8, c0_inv);
        t[b] = (q as u64) << 56;
        let mut k = 1;
        while k < 8 {
            t[b] |= (gf_mul(q, C[k]) as u64) << (8 * (k - 1));
            k += 1;
        }
        b += 1;
    }
    t
};

/// `TABLES[k][x]`: the column Kalyna's MixColumns makes of byte `k`
/// holding `π[k mod 4][x]` and every other byte zero.
const TABLES: [[u64; 256]; 8] = {
    let mut t = [[0u64; 256]; 8];
    let mut k = 0;
    while k < 8 {
        let mut x = 0;
        while x < 256 {
            let s = SBOX[k % 4][x] as usize;
            let mut r = 0;
            while r < 8 {
                t[k][x] |= (MUL[(k + 8 - r) % 8][s] as u64) << (8 * r);
                r += 1;
            }
            x += 1;
        }
        k += 1;
    }
    t
};

fn alpha(w: u64) -> u64 {
    (w << 8) ^ ALPHA[(w >> 56) as usize]
}

fn alpha_inv(w: u64) -> u64 {
    (w >> 8) ^ ALPHA_INV[(w & 0xff) as usize]
}

fn t(w: u64) -> u64 {
    let mut out = 0;
    for (k, table) in TABLES.iter().enumerate() {
        out ^= table[((w >> (8 * k)) & 0xff) as usize];
    }
    out
}

#[derive(Clone)]
pub struct Strumok {
    /// The register, `S0` at `s[head]`.
    s: [u64; 16],
    head: usize,
    r0: u64,
    r1: u64,
    /// The current keystream word as bytes, and how many are used.
    word: [u8; 8],
    used: usize,
}

impl Strumok {
    /// Strumok keyed with a 32 or 64-byte key and a 32-byte IV.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Strumok, String> {
        if iv.len() != 32 {
            return Err(format!("Strumok takes a 32 byte IV, not {}.", iv.len()));
        }
        let words = |b: &[u8]| -> Vec<u64> {
            b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes"))).collect()
        };
        let k = words(key);
        let v = words(iv);
        let s = match key.len() {
            32 => [
                k[3] ^ v[0], k[2], k[1] ^ v[1], k[0] ^ v[2],
                k[3], k[2] ^ v[3], !k[1], !k[0],
                k[3], k[2], !k[1], k[0],
                k[3], !k[2], k[1], !k[0],
            ],
            64 => [
                k[7] ^ v[0], k[6], k[5], k[4] ^ v[1],
                k[3], k[2] ^ v[2], k[1], !k[0],
                k[4] ^ v[3], !k[6], k[5], !k[7],
                k[3], k[2], !k[1], k[0],
            ],
            n => return Err(format!("Strumok takes a 32 or 64 byte key, not {n}.")),
        };
        let mut cipher = Strumok { s, head: 0, r0: 0, r1: 0, word: [0; 8], used: 8 };
        for _ in 0..32 {
            cipher.step(true);
        }
        Ok(cipher)
    }

    fn at(&self, i: usize) -> u64 {
        self.s[(self.head + i) & 15]
    }

    /// One clock of the register and the state machine; during
    /// initialisation the machine's output joins the feedback.
    fn step(&mut self, init: bool) {
        let mut feedback = alpha(self.at(0)) ^ alpha_inv(self.at(11)) ^ self.at(13);
        if init {
            feedback ^= self.r0.wrapping_add(self.at(15)) ^ self.r1;
        }
        let r0 = self.r1.wrapping_add(self.at(13));
        self.r1 = t(self.r0);
        self.r0 = r0;
        // The new word is S16, which after the shift is S15.
        self.s[self.head] = feedback;
        self.head = (self.head + 1) & 15;
    }

    /// The next 64-bit keystream word, the standard's Z.
    fn next_word(&mut self) -> u64 {
        self.step(false);
        self.r0.wrapping_add(self.at(15)) ^ self.r1 ^ self.at(0)
    }

    /// XOR the keystream onto `data`, continuing where the last call
    /// stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut rest = data;
        // The rest of a word a previous call began.
        while self.used < 8 && !rest.is_empty() {
            rest[0] ^= self.word[self.used];
            self.used += 1;
            rest = &mut rest[1..];
        }
        let mut chunks = rest.chunks_exact_mut(8);
        for chunk in &mut chunks {
            let z = self.next_word().to_le_bytes();
            for (b, k) in chunk.iter_mut().zip(z) {
                *b ^= k;
            }
        }
        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            self.word = self.next_word().to_le_bytes();
            for (i, b) in tail.iter_mut().enumerate() {
                *b ^= self.word[i];
            }
            self.used = tail.len();
        }
    }
}

impl StreamCipher for Strumok {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpha_inv_undoes_alpha() {
        let mut w = 0x0123_4567_89ab_cdefu64;
        for _ in 0..1000 {
            assert_eq!(alpha_inv(alpha(w)), w);
            assert_eq!(alpha(alpha_inv(w)), w);
            w = w.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17) ^ 0x55;
        }
    }

    #[test]
    fn test_alpha_is_the_polynomial() {
        // α^8 times 1 reduces to the polynomial's low coefficients.
        let mut w = 1u64;
        for _ in 0..8 {
            w = alpha(w);
        }
        assert_eq!(w.to_le_bytes(), C);
    }

    #[test]
    fn test_t_is_kalynas_column() {
        let w = 0x0011_2233_4455_6677u64;
        let mut column = w.to_le_bytes();
        crate::block_ciphers::kalyna::sub_bytes(&mut column, &SBOX);
        crate::block_ciphers::kalyna::mix_columns(&mut column, &MUL);
        assert_eq!(t(w), u64::from_le_bytes(column));
    }

    #[test]
    fn test_pieces_are_one_stream() {
        let key = [7u8; 64];
        let iv = [9u8; 32];
        let mut whole = vec![0u8; 300];
        Strumok::new(&key, &iv).unwrap().apply_keystream(&mut whole);
        let mut cipher = Strumok::new(&key, &iv).unwrap();
        let mut pieces = vec![0u8; 300];
        let mut at = 0;
        for n in [1, 7, 8, 9, 0, 3, 64, 5, 128, 75] {
            cipher.apply_keystream(&mut pieces[at..at + n]);
            at += n;
        }
        assert_eq!(at, 300);
        assert_eq!(pieces, whole);
    }

    #[test]
    fn test_wrong_lengths_are_refused() {
        assert!(Strumok::new(&[0; 16], &[0; 32]).is_err());
        assert!(Strumok::new(&[0; 48], &[0; 32]).is_err());
        assert!(Strumok::new(&[0; 32], &[0; 16]).is_err());
        assert!(Strumok::new(&[0; 32], &[0; 32]).is_ok());
        assert!(Strumok::new(&[0; 64], &[0; 32]).is_ok());
    }
}
