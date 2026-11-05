//! Grain v1 and Grain-128 (Hell, Johansson, Maximov and Meier): eSTREAM
//! hardware-profile stream ciphers, each an LFSR `s` and an NFSR `b` of
//! the key's length with a filter over both.
//!
//! **Grain v1**: an 80 bit key and a 64 bit IV, 80 bit registers.
//!
//! ```text
//! s(i+80) = s(i+62) + s(i+51) + s(i+38) + s(i+23) + s(i+13) + s(i)
//! b(i+80) = s(i) + b(i+62) + b(i+60) + b(i+52) + b(i+45) + b(i+37)
//!         + b(i+33) + b(i+28) + b(i+21) + b(i+14) + b(i+9) + b(i)
//!         + b63 b60 + b37 b33 + b15 b9 + b60 b52 b45 + b33 b28 b21
//!         + b63 b45 b28 b9 + b60 b52 b37 b33 + b63 b60 b21 b15
//!         + b63 b60 b52 b45 b37 + b33 b28 b21 b15 b9
//!         + b52 b45 b37 b33 b28 b21                   (each b at i+)
//! h  = x1 + x4 + x0 x3 + x2 x3 + x3 x4 + x0 x1 x2 + x0 x2 x3
//!    + x0 x2 x4 + x1 x2 x4 + x2 x3 x4,
//!      (x0 .. x4) = (s(i+3), s(i+25), s(i+46), s(i+64), b(i+63))
//! z  = b(i+1) + b(i+2) + b(i+4) + b(i+10) + b(i+31) + b(i+43) + b(i+56) + h
//! ```
//!
//! 160 clocks of set-up, in which `z` is not output but added to both
//! registers' new bits.
//!
//! **Grain-128**: a 128 bit key and a 96 bit IV, 128 bit registers.
//!
//! ```text
//! s(i+128) = s(i) + s(i+7) + s(i+38) + s(i+70) + s(i+81) + s(i+96)
//! b(i+128) = s(i) + b(i) + b(i+26) + b(i+56) + b(i+91) + b(i+96)
//!          + b3 b67 + b11 b13 + b17 b18 + b27 b59 + b40 b48 + b61 b65
//!          + b68 b84                                  (each b at i+)
//! h  = b12 s8 + s13 s20 + b95 s42 + s60 s79 + b12 b95 s95
//! z  = b(i+2) + b(i+15) + b(i+36) + b(i+45) + b(i+64) + b(i+73)
//!    + b(i+89) + h + s(i+93)
//! ```
//!
//! 256 clocks of set-up, the same way. Grain-128a's `h` has `s94` in its
//! last term where Grain-128 has `s95`; the two are different ciphers, and
//! this is Grain-128.
//!
//! Both load the key into `b` and the IV into the low end of `s`, the
//! rest of `s` ones, and both read and write bit sequences least
//! significant bit first: `b0` is the low bit of the key's first byte,
//! and the first keystream bit the low bit of the first keystream byte -
//! the reference implementations' order, which the eSTREAM test vectors
//! were made with.
//!
//! ## Many clocks at once
//!
//! Each register is a `u128` with `s(i)` at bit 0. No tap is nearer the
//! input end than 16 positions for Grain v1 or 32 for Grain-128 - which
//! the designers arranged so - so the next 16 or 32 values of every tap
//! are already in the register, and that many clocks are a handful of
//! word operations: tap `j`'s values are bits `j ..`, in clock order, and
//! the new bits enter at the top as as many shift out at the bottom.
//! Nothing branches on or indexes by the state.

use crate::stream_ciphers::StreamCipher;

/// Bytes, least significant first, as one integer.
fn le_integer(bytes: &[u8]) -> u128 {
    bytes.iter().rev().fold(0u128, |acc, &b| acc << 8 | u128::from(b))
}

/// Grain v1 under one key and IV.
#[derive(Clone)]
pub struct GrainV1 {
    s: u128,
    b: u128,
    block: [u8; 2],
    used: usize,
}

impl core::fmt::Debug for GrainV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GrainV1").finish_non_exhaustive()
    }
}

impl GrainV1 {
    /// Grain v1 under a 10 byte key and an 8 byte IV.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<GrainV1, String> {
        if key.len() != 10 {
            return Err(format!("A Grain v1 key is 10 bytes, not {}.", key.len()));
        }
        if iv.len() != 8 {
            return Err(format!("A Grain v1 IV is 8 bytes, not {}.", iv.len()));
        }
        let mut g = GrainV1 {
            s: le_integer(iv) | (0xffff << 64),
            b: le_integer(key),
            block: [0; 2],
            used: 2,
        };
        for _ in 0..160 / 16 {
            let z = g.output16();
            g.clock16(z);
        }
        Ok(g)
    }

    /// The next 16 outputs, without clocking.
    fn output16(&self) -> u16 {
        let (s, b) = (self.s, self.b);
        let s = |j: u32| (s >> j) as u16;
        let b = |j: u32| (b >> j) as u16;
        let (x0, x1, x2, x3, x4) = (s(3), s(25), s(46), s(64), b(63));
        let h = x1 ^ x4 ^ (x0 & x3) ^ (x2 & x3) ^ (x3 & x4) ^ (x0 & x1 & x2) ^ (x0 & x2 & x3)
            ^ (x0 & x2 & x4) ^ (x1 & x2 & x4) ^ (x2 & x3 & x4);
        b(1) ^ b(2) ^ b(4) ^ b(10) ^ b(31) ^ b(43) ^ b(56) ^ h
    }

    /// 16 clocks, each new bit of both registers XORed with the matching
    /// bit of `feed` - the outputs during set-up, zero afterwards.
    fn clock16(&mut self, feed: u16) {
        let (sr, br) = (self.s, self.b);
        let s = |j: u32| (sr >> j) as u16;
        let b = |j: u32| (br >> j) as u16;
        let ns = s(62) ^ s(51) ^ s(38) ^ s(23) ^ s(13) ^ s(0);
        let nb = s(0) ^ b(62) ^ b(60) ^ b(52) ^ b(45) ^ b(37) ^ b(33) ^ b(28) ^ b(21)
            ^ b(14) ^ b(9) ^ b(0)
            ^ (b(63) & b(60)) ^ (b(37) & b(33)) ^ (b(15) & b(9))
            ^ (b(60) & b(52) & b(45)) ^ (b(33) & b(28) & b(21))
            ^ (b(63) & b(45) & b(28) & b(9)) ^ (b(60) & b(52) & b(37) & b(33))
            ^ (b(63) & b(60) & b(21) & b(15))
            ^ (b(63) & b(60) & b(52) & b(45) & b(37))
            ^ (b(33) & b(28) & b(21) & b(15) & b(9))
            ^ (b(52) & b(45) & b(37) & b(33) & b(28) & b(21));
        self.s = (sr >> 16) | (u128::from(ns ^ feed) << 64);
        self.b = (br >> 16) | (u128::from(nb ^ feed) << 64);
    }

    /// XOR the keystream onto `data`, continuing where the last call
    /// stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == 2 {
                let z = self.output16();
                self.clock16(0);
                self.block = z.to_le_bytes();
                self.used = 0;
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

impl StreamCipher for GrainV1 {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

/// Grain-128 under one key and IV.
#[derive(Clone)]
pub struct Grain128 {
    s: u128,
    b: u128,
    block: [u8; 4],
    used: usize,
}

impl core::fmt::Debug for Grain128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Grain128").finish_non_exhaustive()
    }
}

impl Grain128 {
    /// Grain-128 under a 16 byte key and a 12 byte IV.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Grain128, String> {
        if key.len() != 16 {
            return Err(format!("A Grain-128 key is 16 bytes, not {}.", key.len()));
        }
        if iv.len() != 12 {
            return Err(format!("A Grain-128 IV is 12 bytes, not {}.", iv.len()));
        }
        let mut g = Grain128 {
            s: le_integer(iv) | (0xffff_ffff << 96),
            b: le_integer(key),
            block: [0; 4],
            used: 4,
        };
        for _ in 0..256 / 32 {
            let z = g.output32();
            g.clock32(z);
        }
        Ok(g)
    }

    /// The next 32 outputs, without clocking.
    fn output32(&self) -> u32 {
        let (sr, br) = (self.s, self.b);
        let s = |j: u32| (sr >> j) as u32;
        let b = |j: u32| (br >> j) as u32;
        let h = (b(12) & s(8)) ^ (s(13) & s(20)) ^ (b(95) & s(42)) ^ (s(60) & s(79))
            ^ (b(12) & b(95) & s(95));
        b(2) ^ b(15) ^ b(36) ^ b(45) ^ b(64) ^ b(73) ^ b(89) ^ h ^ s(93)
    }

    /// 32 clocks, each new bit of both registers XORed with the matching
    /// bit of `feed` - the outputs during set-up, zero afterwards.
    fn clock32(&mut self, feed: u32) {
        let (sr, br) = (self.s, self.b);
        let s = |j: u32| (sr >> j) as u32;
        let b = |j: u32| (br >> j) as u32;
        let ns = s(0) ^ s(7) ^ s(38) ^ s(70) ^ s(81) ^ s(96);
        let nb = s(0) ^ b(0) ^ b(26) ^ b(56) ^ b(91) ^ b(96)
            ^ (b(3) & b(67)) ^ (b(11) & b(13)) ^ (b(17) & b(18)) ^ (b(27) & b(59))
            ^ (b(40) & b(48)) ^ (b(61) & b(65)) ^ (b(68) & b(84));
        self.s = (sr >> 32) | (u128::from(ns ^ feed) << 96);
        self.b = (br >> 32) | (u128::from(nb ^ feed) << 96);
    }

    /// XOR the keystream onto `data`, continuing where the last call
    /// stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == 4 {
                let z = self.output32();
                self.clock32(0);
                self.block = z.to_le_bytes();
                self.used = 0;
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

impl StreamCipher for Grain128 {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of the ciphers, a bit at a time: the register length, the
    /// set-up clocks, the output and the two registers' new bits.
    struct Spec {
        n: usize,
        setup: usize,
        z: fn(&[u8], &[u8]) -> u8,
        next_s: fn(&[u8]) -> u8,
        next_b: fn(&[u8], &[u8]) -> u8,
    }

    const V1: Spec = Spec { n: 80, setup: 160, z: v1_z, next_s: v1_s, next_b: v1_b };
    const G128: Spec = Spec { n: 128, setup: 256, z: g128_z, next_s: g128_s, next_b: g128_b };

    /// The registers one clock at a time, a bit per byte, from the module
    /// comment's equations - a second reading, for the word-wide clocks to
    /// be compared with.
    fn bitwise(spec: &Spec, key: &[u8], iv: &[u8], len: usize) -> Vec<u8> {
        let Spec { n, setup, z, next_s, next_b } = *spec;
        let bit = |bytes: &[u8], m: usize| (bytes[m / 8] >> (m % 8)) & 1;
        let mut s: Vec<u8> = (0..n).map(|m| if m < 8 * iv.len() { bit(iv, m) } else { 1 }).collect();
        let mut b: Vec<u8> = (0..n).map(|m| bit(key, m)).collect();
        let clock = |s: &mut Vec<u8>, b: &mut Vec<u8>, feed: bool| {
            let out = z(s, b);
            let (ns, nb) = (next_s(s), next_b(s, b));
            let f = if feed { out } else { 0 };
            s.remove(0);
            b.remove(0);
            s.push(ns ^ f);
            b.push(nb ^ f);
            out
        };
        for _ in 0..setup {
            clock(&mut s, &mut b, true);
        }
        (0..len).map(|_| (0..8).fold(0u8, |byte, k| byte | clock(&mut s, &mut b, false) << k))
            .collect()
    }

    fn v1_z(s: &[u8], b: &[u8]) -> u8 {
        let (x0, x1, x2, x3, x4) = (s[3], s[25], s[46], s[64], b[63]);
        let h = x1 ^ x4 ^ (x0 & x3) ^ (x2 & x3) ^ (x3 & x4) ^ (x0 & x1 & x2) ^ (x0 & x2 & x3)
            ^ (x0 & x2 & x4) ^ (x1 & x2 & x4) ^ (x2 & x3 & x4);
        b[1] ^ b[2] ^ b[4] ^ b[10] ^ b[31] ^ b[43] ^ b[56] ^ h
    }

    fn v1_s(s: &[u8]) -> u8 {
        s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0]
    }

    fn v1_b(s: &[u8], b: &[u8]) -> u8 {
        s[0] ^ b[62] ^ b[60] ^ b[52] ^ b[45] ^ b[37] ^ b[33] ^ b[28] ^ b[21] ^ b[14] ^ b[9]
            ^ b[0] ^ (b[63] & b[60]) ^ (b[37] & b[33]) ^ (b[15] & b[9])
            ^ (b[60] & b[52] & b[45]) ^ (b[33] & b[28] & b[21])
            ^ (b[63] & b[45] & b[28] & b[9]) ^ (b[60] & b[52] & b[37] & b[33])
            ^ (b[63] & b[60] & b[21] & b[15]) ^ (b[63] & b[60] & b[52] & b[45] & b[37])
            ^ (b[33] & b[28] & b[21] & b[15] & b[9])
            ^ (b[52] & b[45] & b[37] & b[33] & b[28] & b[21])
    }

    fn g128_z(s: &[u8], b: &[u8]) -> u8 {
        let h = (b[12] & s[8]) ^ (s[13] & s[20]) ^ (b[95] & s[42]) ^ (s[60] & s[79])
            ^ (b[12] & b[95] & s[95]);
        b[2] ^ b[15] ^ b[36] ^ b[45] ^ b[64] ^ b[73] ^ b[89] ^ h ^ s[93]
    }

    fn g128_s(s: &[u8]) -> u8 {
        s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96]
    }

    fn g128_b(s: &[u8], b: &[u8]) -> u8 {
        s[0] ^ b[0] ^ b[26] ^ b[56] ^ b[91] ^ b[96] ^ (b[3] & b[67]) ^ (b[11] & b[13])
            ^ (b[17] & b[18]) ^ (b[27] & b[59]) ^ (b[40] & b[48]) ^ (b[61] & b[65])
            ^ (b[68] & b[84])
    }

    fn sample(len: usize, seed: u8) -> Vec<u8> {
        (0..len as u8).map(|i| i.wrapping_mul(113).wrapping_add(seed) ^ 0xa5).collect()
    }

    #[test]
    fn test_the_word_wide_clocks_are_the_bitwise_ones() {
        for seed in 0..4u8 {
            let (key, iv) = (sample(10, seed), sample(8, seed ^ 0x40));
            let mut got = vec![0u8; 100];
            GrainV1::new(&key, &iv).expect("lengths").apply_keystream(&mut got);
            assert_eq!(got, bitwise(&V1, &key, &iv, 100), "v1 {seed}");
            let (key, iv) = (sample(16, seed), sample(12, seed ^ 0x40));
            let mut got = vec![0u8; 100];
            Grain128::new(&key, &iv).expect("lengths").apply_keystream(&mut got);
            assert_eq!(got, bitwise(&G128, &key, &iv, 100), "128 {seed}");
        }
    }

    /// Grain-128a's `s94` in place of `s95` gives another keystream: the
    /// two differ in the output function, and this module is Grain-128.
    #[test]
    fn test_grain_128_is_not_grain_128a() {
        fn g128a_z(s: &[u8], b: &[u8]) -> u8 {
            let h = (b[12] & s[8]) ^ (s[13] & s[20]) ^ (b[95] & s[42]) ^ (s[60] & s[79])
                ^ (b[12] & b[95] & s[94]);
            b[2] ^ b[15] ^ b[36] ^ b[45] ^ b[64] ^ b[73] ^ b[89] ^ h ^ s[93]
        }
        let (key, iv) = (sample(16, 3), sample(12, 9));
        let mut got = vec![0u8; 64];
        Grain128::new(&key, &iv).expect("lengths").apply_keystream(&mut got);
        assert_ne!(got, bitwise(&Spec { z: g128a_z, ..G128 }, &key, &iv, 64));
    }

    #[test]
    fn test_streaming_equals_one_call() {
        let (key, iv) = (sample(16, 1), sample(12, 2));
        let mut whole = vec![0u8; 150];
        Grain128::new(&key, &iv).expect("lengths").apply_keystream(&mut whole);
        let (key1, iv1) = (sample(10, 1), sample(8, 2));
        let mut whole1 = vec![0u8; 150];
        GrainV1::new(&key1, &iv1).expect("lengths").apply_keystream(&mut whole1);
        for piece in [1, 2, 3, 4, 5, 31, 33] {
            let mut c = Grain128::new(&key, &iv).expect("lengths");
            let mut c1 = GrainV1::new(&key1, &iv1).expect("lengths");
            let (mut got, mut got1) = (vec![0u8; 150], vec![0u8; 150]);
            for chunk in got.chunks_mut(piece) {
                c.apply_keystream(chunk);
            }
            for chunk in got1.chunks_mut(piece) {
                c1.apply_keystream(chunk);
            }
            assert_eq!(got, whole, "Grain-128 in pieces of {piece}");
            assert_eq!(got1, whole1, "Grain v1 in pieces of {piece}");
        }
    }

    #[test]
    fn test_other_lengths_are_refused() {
        for n in [0, 8, 9, 11, 16] {
            assert_eq!(GrainV1::new(&vec![1; n], &[0; 8]).unwrap_err(),
                       format!("A Grain v1 key is 10 bytes, not {n}."));
        }
        for n in [0, 4, 7, 9, 10, 12] {
            assert_eq!(GrainV1::new(&[1; 10], &vec![0; n]).unwrap_err(),
                       format!("A Grain v1 IV is 8 bytes, not {n}."));
        }
        for n in [0, 10, 15, 17, 32] {
            assert_eq!(Grain128::new(&vec![1; n], &[0; 12]).unwrap_err(),
                       format!("A Grain-128 key is 16 bytes, not {n}."));
        }
        for n in [0, 8, 11, 13, 16] {
            assert_eq!(Grain128::new(&[1; 16], &vec![0; n]).unwrap_err(),
                       format!("A Grain-128 IV is 12 bytes, not {n}."));
        }
    }
}
