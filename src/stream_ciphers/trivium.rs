//! Trivium (De Cannière and Preneel): an eSTREAM hardware-profile stream
//! cipher, ISO/IEC 29192-3.
//!
//! An 80 bit key, an IV of 32, 48, 64 or 80 bits, and a 288 bit state
//! in three shift registers - `s1..s93`, `s94..s177` and `s178..s288` -
//! clocked one bit at a time:
//!
//! ```text
//! t1 = s66 + s93      t2 = s162 + s177      t3 = s243 + s288
//! z  = t1 + t2 + t3                          (the keystream bit)
//! t1 = t1 + s91 s92 + s171
//! t2 = t2 + s175 s176 + s264
//! t3 = t3 + s286 s287 + s69
//! (s1 .. s93)    <- (t3, s1 .. s92)
//! (s94 .. s177)  <- (t1, s94 .. s176)
//! (s178 .. s288) <- (t2, s178 .. s287)
//! ```
//!
//! after `4 * 288` clocks of set-up whose output is discarded.
//!
//! ## Which bit goes where
//!
//! This follows the eSTREAM submission, whose test vectors every other
//! implementation is checked against, and not the order the
//! specification writes: the submission loads
//!
//! ```text
//! (s1 .. s93)    <- (K80 .. K1, 0 .. 0)
//! (s94 .. s177)  <- (IV80 .. IV1, 0 .. 0)
//! (s178 .. s288) <- (0 .. 0, 1, 1, 1)
//! ```
//!
//! where the specification has `K1 .. K80` and `IV1 .. IV80`, and bit
//! sequences are bytes least significant bit first: `K1` is the low bit
//! of the key's first byte, and the first keystream bit is the low bit of
//! the first keystream byte. Its comment calls this order "more natural
//! than the reversed one used in the original specs". An implementation
//! written from the specification gives different keystreams from the
//! same bytes; the two are the same cipher with the key and IV bytes
//! reversed and each byte's bits reversed.
//!
//! A shorter IV is the 80 bit one with zero bytes before it, as the
//! submission reads it: it places the IV at the end of its buffer.
//!
//! ## 64 clocks at once
//!
//! No tap is nearer the input end of its register than position 66, so
//! the next 64 values of every tap are already in the state and 64 clocks
//! are a handful of word operations. Each register is a `u128` holding
//! `s_j` of an `n` bit register at bit `n - j`, newest bit highest; the
//! 64 values tap `j` takes in the next 64 clocks are bits `n - j ..
//! n - j + 63`, in clock order, and the 64 new bits enter at the top as
//! 64 bits shift out at the bottom. Nothing branches on or indexes by the
//! state.

use crate::stream_ciphers::StreamCipher;

/// The three registers' lengths.
const A: u32 = 93;
const B: u32 = 84;
const C: u32 = 111;

/// Trivium under one key and IV.
#[derive(Clone)]
pub struct Trivium {
    a: u128,
    b: u128,
    c: u128,
    block: [u8; 8],
    used: usize,
}

impl core::fmt::Debug for Trivium {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Trivium").finish_non_exhaustive()
    }
}

/// The 64 values tap `j` of an `n` bit register takes in the next 64
/// clocks, the first in the low bit.
fn tap(register: u128, n: u32, j: u32) -> u64 {
    (register >> (n - j)) as u64
}

/// Bytes, least significant first, as one integer.
fn le_integer(bytes: &[u8]) -> u128 {
    bytes.iter().rev().fold(0u128, |acc, &b| acc << 8 | u128::from(b))
}

impl Trivium {
    /// Trivium under a 10 byte key and a 4, 6, 8 or 10 byte IV.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Trivium, String> {
        if key.len() != 10 {
            return Err(format!("A Trivium key is 10 bytes, not {}.", key.len()));
        }
        if ![4, 6, 8, 10].contains(&iv.len()) {
            return Err(format!("A Trivium IV is 4, 6, 8 or 10 bytes, not {}.", iv.len()));
        }
        // s_j = K_(81-j) for j <= 80 sits at bit 93 - j, so K_m is at bit
        // 12 + m: the key as a little-endian integer, shifted up 13. The
        // IV likewise in the second register, at bit 3 + m, after the zero
        // bytes that make a short one ten. s286..s288 are bits 2, 1 and 0
        // of the third.
        let mut padded = [0u8; 10];
        padded[10 - iv.len()..].copy_from_slice(iv);
        let mut t = Trivium {
            a: le_integer(key) << 13,
            b: le_integer(&padded) << 4,
            c: 0b111,
            block: [0; 8],
            used: 8,
        };
        for _ in 0..(4 * 288 / 64) {
            t.clock64();
        }
        Ok(t)
    }

    /// 64 clocks: the 64 keystream bits, the first in the low bit.
    fn clock64(&mut self) -> u64 {
        let (a, b, c) = (self.a, self.b, self.c);
        let mut t1 = tap(a, A, 66) ^ tap(a, A, 93);
        let mut t2 = tap(b, B, 69) ^ tap(b, B, 84);
        let mut t3 = tap(c, C, 66) ^ tap(c, C, 111);
        let z = t1 ^ t2 ^ t3;
        t1 ^= (tap(a, A, 91) & tap(a, A, 92)) ^ tap(b, B, 78);
        t2 ^= (tap(b, B, 82) & tap(b, B, 83)) ^ tap(c, C, 87);
        t3 ^= (tap(c, C, 109) & tap(c, C, 110)) ^ tap(a, A, 69);
        self.a = (a >> 64) | (u128::from(t3) << (A - 64));
        self.b = (b >> 64) | (u128::from(t1) << (B - 64));
        self.c = (c >> 64) | (u128::from(t2) << (C - 64));
        z
    }

    /// XOR the keystream onto `data`, continuing where the last call
    /// stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.used == 8 {
                self.block = self.clock64().to_le_bytes();
                self.used = 0;
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}

impl StreamCipher for Trivium {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivium one clock at a time, as the module comment writes it, over
    /// `s[1..=288]` - a second reading of the cipher, for the word-wide one
    /// to be compared with.
    fn bitwise(key: &[u8], iv: &[u8], n: usize) -> Vec<u8> {
        let bit = |bytes: &[u8], m: usize| (bytes[(m - 1) / 8] >> ((m - 1) % 8)) & 1;
        let mut padded = vec![0u8; 10 - iv.len()];
        padded.extend_from_slice(iv);
        let mut s = [0u8; 289];
        for j in 1..=80 {
            s[j] = bit(key, 81 - j);
            s[93 + j] = bit(&padded, 81 - j);
        }
        s[286] = 1;
        s[287] = 1;
        s[288] = 1;
        let clock = |s: &mut [u8; 289]| {
            let mut t1 = s[66] ^ s[93];
            let mut t2 = s[162] ^ s[177];
            let mut t3 = s[243] ^ s[288];
            let z = t1 ^ t2 ^ t3;
            t1 ^= (s[91] & s[92]) ^ s[171];
            t2 ^= (s[175] & s[176]) ^ s[264];
            t3 ^= (s[286] & s[287]) ^ s[69];
            s.copy_within(178..288, 179);
            s.copy_within(94..177, 95);
            s.copy_within(1..93, 2);
            s[1] = t3;
            s[94] = t1;
            s[178] = t2;
            z
        };
        for _ in 0..4 * 288 {
            clock(&mut s);
        }
        (0..n).map(|_| (0..8).fold(0u8, |byte, k| byte | clock(&mut s) << k)).collect()
    }

    fn sample(len: usize, seed: u8) -> Vec<u8> {
        (0..len as u8).map(|i| i.wrapping_mul(97).wrapping_add(seed) ^ 0x3c).collect()
    }

    #[test]
    fn test_the_word_wide_clock_is_the_bitwise_one() {
        for (seed, iv_len) in [(1u8, 10), (2, 8), (3, 6), (4, 4)] {
            let (key, iv) = (sample(10, seed), sample(iv_len, seed.wrapping_mul(7)));
            let mut got = vec![0u8; 300];
            Trivium::new(&key, &iv).expect("lengths").apply_keystream(&mut got);
            assert_eq!(got, bitwise(&key, &iv, 300), "IV of {iv_len}");
        }
    }

    /// A short IV is the 10 byte one with zero bytes before it, not after.
    #[test]
    fn test_a_short_iv_is_padded_in_front() {
        let key = sample(10, 9);
        let mut short = vec![0u8; 32];
        Trivium::new(&key, &[1, 2, 3, 4]).expect("lengths").apply_keystream(&mut short);
        let mut front = vec![0u8; 32];
        Trivium::new(&key, &[0, 0, 0, 0, 0, 0, 1, 2, 3, 4]).expect("lengths")
            .apply_keystream(&mut front);
        let mut back = vec![0u8; 32];
        Trivium::new(&key, &[1, 2, 3, 4, 0, 0, 0, 0, 0, 0]).expect("lengths")
            .apply_keystream(&mut back);
        assert_eq!(short, front);
        assert_ne!(short, back);
    }

    #[test]
    fn test_streaming_equals_one_call() {
        let (key, iv) = (sample(10, 5), sample(10, 6));
        let mut whole = vec![0u8; 200];
        Trivium::new(&key, &iv).expect("lengths").apply_keystream(&mut whole);
        for piece in [1, 3, 7, 8, 9, 63, 64, 65] {
            let mut c = Trivium::new(&key, &iv).expect("lengths");
            let mut got = vec![0u8; 200];
            for chunk in got.chunks_mut(piece) {
                c.apply_keystream(chunk);
            }
            assert_eq!(got, whole, "pieces of {piece}");
        }
    }

    #[test]
    fn test_other_lengths_are_refused() {
        for n in [0, 8, 9, 11, 16] {
            assert_eq!(Trivium::new(&vec![1; n], &[0; 10]).unwrap_err(),
                       format!("A Trivium key is 10 bytes, not {n}."));
        }
        for n in [0, 3, 5, 7, 9, 11, 16] {
            assert_eq!(Trivium::new(&[1; 10], &vec![0; n]).unwrap_err(),
                       format!("A Trivium IV is 4, 6, 8 or 10 bytes, not {n}."));
        }
    }
}
