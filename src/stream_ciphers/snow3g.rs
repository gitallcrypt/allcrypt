//! SNOW 3G (ETSI/SAGE, the core of 3GPP's UEA2 and UIA2, and of LTE's
//! and 5G's 128-EEA1 and 128-EIA1). The modes are in `mobile`.
//!
//! A 128 bit key `k0..k3` and IV `IV0..IV3`, four 32 bit words each, and
//! a state of sixteen 32 bit LFSR stages `s0..s15` over GF(2^32) and three
//! FSM registers `R1..R3`. Per clock:
//!
//! ```text
//! F  = (s15 + R1) ^ R2                     (+ is addition mod 2^32)
//! r  = R2 + (R3 ^ s5)
//! R3 = S2(R2),  R2 = S1(R1),  R1 = r
//! v  = (s0 << 8) ^ MULα(s0 >> 24) ^ s2 ^ (s11 >> 8) ^ DIVα(s11 & 0xff)
//! (s0 .. s15) <- (s1 .. s15, v)            (v ^ F during set-up)
//! ```
//!
//! and the keystream word is `F ^ s0` taken before the LFSR moves. Set-up
//! is 32 clocks with `F` fed back into the LFSR, then one clock whose
//! output is discarded (`rfcs/snow3gspec.txt`, sections 3 and 4).
//!
//! The key and IV here are bytes, `k0` the first four, big endian, as
//! the implementors' test data's section 3 lists them. UEA2 and UIA2 load
//! their key the other way round - the first 32 bits of CK are `k3` -
//! and `mobile` does that.
//!
//! ## Nothing indexes memory by the state
//!
//! S1 and S2 are the 8 bit S-boxes SR (Rijndael's) and SQ applied to each
//! byte, followed by a MixColumn over GF(2^8) mod 0x11b or 0x169. Both
//! S-boxes are read out of the specification's tables at compile time and
//! looked up by a masked scan of all 256 entries (`spec_tables`), so each
//! of the eight lookups per word touches every entry; the tests check SR
//! against AES's and SQ against the Dickson polynomial annex 1.3 defines
//! it by. MULα and DIVα are linear maps from a byte to a word: each is
//! the XOR, under a mask per input bit, of its value at the eight powers
//! of two, computed at compile time from their definitions by MULxPOW.

use crate::stream_ciphers::spec_tables::{parse, scan};
use crate::stream_ciphers::StreamCipher;

const SPEC: &str = include_str!("../../rfcs/snow3gspec.txt");

/// Rijndael's S-box, section 5.1.
pub(crate) const SR: [u8; 256] = parse(SPEC, "The S-box SR maps 8 bit to 8 bit");
/// SQ, section 5.2.
pub(crate) const SQ: [u8; 256] = parse(SPEC, "The S-box SQ maps 8 bit to 8 bit");

/// MULx(V, c), section 3.1.1. For building constants: it branches.
const fn mulx_const(v: u8, c: u8) -> u8 {
    if v & 0x80 != 0 { (v << 1) ^ c } else { v << 1 }
}

/// MULxPOW(V, i, c), section 3.1.2.
const fn mulx_pow(mut v: u8, i: u32, c: u8) -> u8 {
    let mut k = 0;
    while k < i {
        v = mulx_const(v, c);
        k += 1;
    }
    v
}

/// The word a map of the shape MULα and DIVα have - four MULxPOWs by
/// 0xA9 - gives for each single input bit.
const fn basis(powers: [u32; 4]) -> [u32; 8] {
    let mut out = [0u32; 8];
    let mut bit = 0;
    while bit < 8 {
        let c = 1u8 << bit;
        out[bit] = (mulx_pow(c, powers[0], 0xa9) as u32) << 24
            | (mulx_pow(c, powers[1], 0xa9) as u32) << 16
            | (mulx_pow(c, powers[2], 0xa9) as u32) << 8
            | mulx_pow(c, powers[3], 0xa9) as u32;
        bit += 1;
    }
    out
}

/// MULα, section 3.4.2, at each power of two.
const MUL_ALPHA: [u32; 8] = basis([23, 245, 48, 239]);
/// DIVα, section 3.4.3, at each power of two.
const DIV_ALPHA: [u32; 8] = basis([16, 39, 6, 64]);

/// A linear map from a byte to a word, from its values at the powers of
/// two, with no branch or index on the byte.
#[inline]
fn fold(basis: &[u32; 8], c: u32) -> u32 {
    let mut out = 0u32;
    for (bit, &word) in basis.iter().enumerate() {
        out ^= word & 0u32.wrapping_sub((c >> bit) & 1);
    }
    out
}

/// MULx(V, c) with the reduction masked in.
#[inline]
fn mulx(v: u8, c: u8) -> u8 {
    (v << 1) ^ (c & 0u8.wrapping_sub(v >> 7))
}

/// S1 or S2: the S-box on each byte, then the MixColumn of section 3.3
/// with MULx by `c`.
#[inline]
fn s_box(table: &[u8; 256], c: u8, w: u32) -> u32 {
    let [w0, w1, w2, w3] = w.to_be_bytes();
    let (a0, a1, a2, a3) = (scan(table, w0), scan(table, w1), scan(table, w2), scan(table, w3));
    let (m0, m1, m2, m3) = (mulx(a0, c), mulx(a1, c), mulx(a2, c), mulx(a3, c));
    u32::from_be_bytes([
        m0 ^ a1 ^ a2 ^ m3 ^ a3,
        m0 ^ a0 ^ m1 ^ a2 ^ a3,
        a0 ^ m1 ^ a1 ^ m2 ^ a3,
        a0 ^ a1 ^ m2 ^ a2 ^ m3,
    ])
}

fn s1(w: u32) -> u32 {
    s_box(&SR, 0x1b, w)
}

fn s2(w: u32) -> u32 {
    s_box(&SQ, 0x69, w)
}

/// SNOW 3G under one key and IV.
#[derive(Clone)]
pub struct Snow3g {
    s: [u32; 16],
    r1: u32,
    r2: u32,
    r3: u32,
    block: [u8; 4],
    used: usize,
}

impl core::fmt::Debug for Snow3g {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Snow3g").finish_non_exhaustive()
    }
}

fn words(bytes: &[u8]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

impl Snow3g {
    /// SNOW 3G under a 16 byte key `k0..k3` and a 16 byte IV `IV0..IV3`,
    /// each word big endian.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Snow3g, String> {
        if key.len() != 16 {
            return Err(format!("A SNOW 3G key is 16 bytes, not {}.", key.len()));
        }
        if iv.len() != 16 {
            return Err(format!("A SNOW 3G IV is 16 bytes, not {}.", iv.len()));
        }
        Ok(Snow3g::from_words(words(key), words(iv)))
    }

    /// SNOW 3G under `k0..k3` and `IV0..IV3`, section 4.1.
    pub fn from_words(k: [u32; 4], iv: [u32; 4]) -> Snow3g {
        let one = u32::MAX;
        let s = [
            k[0] ^ one, k[1] ^ one, k[2] ^ one, k[3] ^ one,
            k[0], k[1], k[2], k[3],
            k[0] ^ one, k[1] ^ one ^ iv[3], k[2] ^ one ^ iv[2], k[3] ^ one,
            k[0] ^ iv[1], k[1], k[2], k[3] ^ iv[0],
        ];
        let mut g = Snow3g { s, r1: 0, r2: 0, r3: 0, block: [0; 4], used: 4 };
        for _ in 0..32 {
            let f = g.clock_fsm();
            g.clock_lfsr(f);
        }
        g.clock_fsm();
        g.clock_lfsr(0);
        g
    }

    /// Section 3.4.6: the FSM's output `F`, then its update.
    fn clock_fsm(&mut self) -> u32 {
        let f = self.s[15].wrapping_add(self.r1) ^ self.r2;
        let r = self.r2.wrapping_add(self.r3 ^ self.s[5]);
        self.r3 = s2(self.r2);
        self.r2 = s1(self.r1);
        self.r1 = r;
        f
    }

    /// Sections 3.4.4 and 3.4.5: the LFSR, `input` the FSM's output in
    /// set-up and zero after.
    fn clock_lfsr(&mut self, input: u32) {
        let (s0, s11) = (self.s[0], self.s[11]);
        let v = (s0 << 8) ^ fold(&MUL_ALPHA, s0 >> 24) ^ self.s[2] ^ (s11 >> 8)
            ^ fold(&DIV_ALPHA, s11 & 0xff) ^ input;
        self.s.copy_within(1.., 0);
        self.s[15] = v;
    }

    /// The next keystream word, section 4.2.
    pub fn next_word(&mut self) -> u32 {
        let z = self.clock_fsm() ^ self.s[0];
        self.clock_lfsr(0);
        z
    }

    /// XOR the keystream onto `data`, each word big endian, continuing
    /// where the last call stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == 4 {
                self.block = self.next_word().to_be_bytes();
                self.used = 0;
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

impl StreamCipher for Snow3g {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MULx in GF(2^8) mod x^8 + x^6 + x^5 + x^3 + 1, branching, for the
    /// annex's definition of SQ.
    fn mul_169(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        while b != 0 {
            if b & 1 != 0 {
                p ^= a;
            }
            a = mulx_const(a, 0x69);
            b >>= 1;
        }
        p
    }

    #[test]
    fn test_sr_is_the_aes_s_box() {
        assert_eq!(SR, crate::block_ciphers::aes::SBOX);
    }

    /// Annex 1.3: SQ(x) = g49(x) ^ 0x25, the Dickson polynomial
    /// x + x^9 + x^13 + x^15 + x^33 + x^41 + x^45 + x^47 + x^49 over
    /// GF(2^8) mod 0x169 - a second reading of the table section 5.2
    /// prints.
    #[test]
    fn test_sq_is_the_dickson_polynomial() {
        for x in 0..=255u8 {
            let mut power = [0u8; 50];
            power[1] = x;
            for e in 2..50 {
                power[e] = mul_169(power[e - 1], x);
            }
            let g = [1, 9, 13, 15, 33, 41, 45, 47, 49].iter().fold(0, |acc, &e| acc ^ power[e]);
            assert_eq!(SQ[x as usize], g ^ 0x25, "SQ({x:#04x})");
        }
    }

    /// The specification's own worked values: SR(0x2A) = 0xE5,
    /// SQ(0x2A) = 0xAC and MULx(0x96, 0x1B) = 0x37.
    #[test]
    fn test_the_examples_in_the_text() {
        assert_eq!(SR[0x2a], 0xe5);
        assert_eq!(SQ[0x2a], 0xac);
        assert_eq!(mulx(0x96, 0x1b), 0x37);
        assert_eq!(mulx_const(0x96, 0x1b), 0x37);
    }

    /// Section 3.1.1's first example is misprinted: 0x69 has its top bit
    /// clear, so MULx(0x69, 0x1B) is the shift alone, 0xD2, and the text
    /// says 0xC2. Every test set passes with 0xD2; this pins both, so a
    /// corrected document is noticed here.
    #[test]
    fn test_the_first_mulx_example_is_misprinted() {
        assert!(SPEC.contains("MULx(0x69,0x1B) = 0xC2"));
        assert_eq!(mulx(0x69, 0x1b), 0xd2);
        assert_eq!(mulx_const(0x69, 0x1b), 0xd2);
    }

    /// MULα and DIVα are multiplication by α and α^-1 after the byte
    /// shift (annex 1.5), so DIVα undoes MULα: for any word w,
    /// (w * α) * α^-1 = w.
    #[test]
    fn test_div_alpha_undoes_mul_alpha() {
        let times_alpha = |w: u32| (w << 8) ^ fold(&MUL_ALPHA, w >> 24);
        let over_alpha = |w: u32| (w >> 8) ^ fold(&DIV_ALPHA, w & 0xff);
        let mut w = 0x0123_4567u32;
        for _ in 0..1000 {
            assert_eq!(over_alpha(times_alpha(w)), w);
            assert_eq!(times_alpha(over_alpha(w)), w);
            w = w.wrapping_mul(0x9e37_79b9).rotate_left(7) ^ 0x5a5a;
        }
    }

    /// The masked folds are the definitions, at every byte.
    #[test]
    fn test_the_folds_are_the_definitions() {
        for c in 0..=255u8 {
            let mul = (mulx_pow(c, 23, 0xa9) as u32) << 24 | (mulx_pow(c, 245, 0xa9) as u32) << 16
                | (mulx_pow(c, 48, 0xa9) as u32) << 8 | mulx_pow(c, 239, 0xa9) as u32;
            let div = (mulx_pow(c, 16, 0xa9) as u32) << 24 | (mulx_pow(c, 39, 0xa9) as u32) << 16
                | (mulx_pow(c, 6, 0xa9) as u32) << 8 | mulx_pow(c, 64, 0xa9) as u32;
            assert_eq!(fold(&MUL_ALPHA, u32::from(c)), mul);
            assert_eq!(fold(&DIV_ALPHA, u32::from(c)), div);
        }
    }

    #[test]
    fn test_streaming_equals_one_call() {
        let (key, iv): (Vec<u8>, Vec<u8>) = ((0..16).collect(), (16..32).collect());
        let mut whole = vec![0u8; 200];
        Snow3g::new(&key, &iv).expect("lengths").apply_keystream(&mut whole);
        for piece in [1, 2, 3, 4, 5, 7, 63, 64, 65] {
            let mut c = Snow3g::new(&key, &iv).expect("lengths");
            let mut got = vec![0u8; 200];
            for chunk in got.chunks_mut(piece) {
                c.apply_keystream(chunk);
            }
            assert_eq!(got, whole, "pieces of {piece}");
        }
    }

    #[test]
    fn test_other_lengths_are_refused() {
        for n in [0, 15, 17, 32] {
            assert_eq!(Snow3g::new(&vec![1; n], &[0; 16]).unwrap_err(),
                       format!("A SNOW 3G key is 16 bytes, not {n}."));
            assert_eq!(Snow3g::new(&[1; 16], &vec![0; n]).unwrap_err(),
                       format!("A SNOW 3G IV is 16 bytes, not {n}."));
        }
    }
}
