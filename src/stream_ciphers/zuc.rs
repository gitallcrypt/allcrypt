//! ZUC (the core of LTE's and 5G's 128-EEA3 and 128-EIA3) and ZUC-256,
//! with the MACs each defines over a raw IV. The 3GPP modes are in
//! `mobile`.
//!
//! A state of sixteen 31 bit cells `s0..s15` over GF(2^31 - 1) and two 32
//! bit registers `R1`, `R2` (`rfcs/eea3eia3zucv16.txt`, section 3):
//!
//! ```text
//! X0 = s15H || s14L   X1 = s11L || s9H   X2 = s7L || s5H   X3 = s2L || s0H
//! W  = (X0 ^ R1) + R2                              (+ is mod 2^32)
//! W1 = R1 + X1,  W2 = R2 ^ X2
//! R1 = S(L1(W1L || W2H)),  R2 = S(L2(W2L || W1H))
//! s16 = 2^15 s15 + 2^17 s13 + 2^21 s10 + 2^20 s4 + (1 + 2^8) s0  mod 2^31 - 1
//! ```
//!
//! where `xH` is bits 30..15 of a cell, `S` applies the 8 bit S-boxes S0,
//! S1, S0, S1 to a word's bytes, and `L1`, `L2` are XORs of rotations.
//! The keystream word is `W ^ X3`. Set-up is 32 clocks with `W >> 1`
//! added to `s16`, then one clock whose output is discarded. A zero cell
//! is replaced by 2^31 - 1, which `add31` does by construction.
//!
//! ZUC-128 loads `s_i = k_i || d_i || iv_i` from its 16 byte key and IV
//! and the 15 bit constants `d_i` of section 3.5. ZUC-256 ("The ZUC-256
//! Stream Cipher", the ZUC design team, 2018) loads a 32 byte key, a 25
//! byte IV - 17 bytes and eight six bit values - and seven bit constants,
//! a different set for the keystream and for each MAC tag size, by the
//! layout in `load_256`. That paper is not vendored; its constants come
//! from `zuc256_constants.rs`, which `scripts/make_zuc256_constants.py`
//! writes from two implementations, and the vectors are Intel's
//! (`vectors/zuc256/`). A 23 byte IV is the same 25 with the eight six bit
//! values packed into the last six bytes, first value highest, which is
//! how GmSSL and the zuc crate take it.
//!
//! 3GPP's ZUC-256 (TS 35.246 V20.0.0, section 6, `rfcs/35246-k00.txt`),
//! the keystream of 256-NEA6, 256-NIA6 and 256-NCA6 (`mobile`), is a
//! third loading over the same core: a 32 byte key `K`, a 16 byte IV and
//! sixteen seven bit constants `d_i` of its own,
//!
//! ```text
//! s_i  = K_i || d_i || K_16+i || K_24+i     i = 0 .. 6
//! s_i  = K_i || d_i || IV_i-7 || IV_i+1     i = 7 .. 14
//! s_15 = K_15 || d_15 || K_23 || K_31
//! ```
//!
//! and 48 set-up clocks rather than 32 (version 19.0.0 of the
//! specification fixed the number; 18.0.0 left it open).
//!
//! ## The MACs
//!
//! ZUC-128's MAC over a raw IV is 128-EIA3's computation (EIA3 is it with
//! the IV built from COUNT, BEARER and DIRECTION): with `z` the keystream
//! as a bit string and `z[i..i+32]` the word at bit `i`,
//!
//! ```text
//! T = XOR of z[i .. i+32] over the message bits i that are 1
//! MAC = T ^ z[L .. L+32] ^ z[32(N-1) .. 32N],   N = ceil(L/32) + 2
//! ```
//!
//! ZUC-256's MAC of `t` = 32, 64 or 128 bits starts its tag at
//! `z[0 .. t]` and adds `z[t+i .. 2t+i]` for each message bit `i` that is
//! 1, and `z[t+L .. 2t+L]` at the end.
//!
//! ## Nothing indexes memory by the state
//!
//! S0 and S1 are read out of the specification's tables at compile time
//! and looked up by a masked scan of all 256 entries (`spec_tables`).
//! The additions mod 2^31 - 1 fold the carry back in rather than
//! comparing, and the MACs add each window under a mask of its message
//! bit.

use crate::stream_ciphers::spec_tables::{parse, scan};
use crate::stream_ciphers::zuc256_constants;
use crate::stream_ciphers::StreamCipher;

const SPEC: &str = include_str!("../../rfcs/eea3eia3zucv16.txt");

/// S0, table 3.1.
pub(crate) const S0: [u8; 256] = parse(SPEC, "Table 3.1. The S-box S0");
/// S1, table 3.2.
pub(crate) const S1: [u8; 256] = parse(SPEC, "Table 3.2. The S-box S1");
/// ZUC-128's `d_0 .. d_15`, section 3.5.
pub(crate) const D: [u32; 16] = parse_d(SPEC);

const SPEC_3GPP: &str = include_str!("../../rfcs/35246-k00.txt");
/// 3GPP's ZUC-256 `d_0 .. d_15`, TS 35.246 section 6.2.7.
pub(crate) const D_3GPP: [u8; 16] = parse_d_3gpp(SPEC_3GPP);

/// TS 35.246 section 6.2.7's constants, each written twice - `d0 =
/// 1100100 (0x64)`, seven binary digits and then hexadecimal - with the
/// `d`, the `x` and any hex letter in mathematical italic: four bytes of
/// UTF-8 each, a to f being F0 9D 91 8E to 93. Both forms are read and
/// must agree.
const fn parse_d_3gpp(text: &str) -> [u8; 16] {
    let bytes = text.as_bytes();
    let marker = b"The key and IV loading will expand a 256-bit key";
    let mut at = 0;
    loop {
        if at + marker.len() > bytes.len() {
            panic!("TS 35.246 no longer describes its key and IV loading where expected");
        }
        let mut i = 0;
        while i < marker.len() && bytes[at + i] == marker[i] {
            i += 1;
        }
        if i == marker.len() {
            break;
        }
        at += 1;
    }
    let mut out = [0u8; 16];
    let mut found = 0;
    while found < 16 {
        if at + 16 >= bytes.len() {
            panic!("TS 35.246 has fewer than sixteen ZUC-256 constants");
        }
        // " = " then exactly seven binary digits then " (0".
        if bytes[at] == b' ' && bytes[at + 1] == b'=' && bytes[at + 2] == b' ' {
            let mut p = at + 3;
            let mut value = 0u8;
            let mut digits = 0;
            while bytes[p] == b'0' || bytes[p] == b'1' {
                value = value << 1 | (bytes[p] - b'0');
                digits += 1;
                p += 1;
            }
            if digits == 7 && bytes[p] == b' ' && bytes[p + 1] == b'(' && bytes[p + 2] == b'0'
                    && bytes[p + 3] == 0xf0 && bytes[p + 6] == 0xa5 {
                p += 7;
                let mut hex = 0u8;
                let mut hex_digits = 0;
                while bytes[p] != b')' {
                    let digit = if bytes[p].is_ascii_digit() {
                        p += 1;
                        bytes[p - 1] - b'0'
                    } else if bytes[p] == 0xf0 && bytes[p + 1] == 0x9d && bytes[p + 2] == 0x91
                            && bytes[p + 3] >= 0x8e && bytes[p + 3] <= 0x93 {
                        p += 4;
                        bytes[p - 1] - 0x8e + 10
                    } else {
                        panic!("a TS 35.246 constant's hexadecimal form has a digit not read")
                    };
                    hex = hex << 4 | digit;
                    hex_digits += 1;
                }
                if hex_digits != 2 || hex != value {
                    panic!("a TS 35.246 constant's binary and hexadecimal forms differ");
                }
                out[found] = value;
                found += 1;
                at = p;
            }
        }
        at += 1;
    }
    out
}

/// Section 3.5's constants, which the document writes in binary with the
/// radix as a subscript - `d0 = 100010011010111₂` - and the text renders
/// with the subscript as a trailing `2`: fifteen binary digits and a `2`.
const fn parse_d(text: &str) -> [u32; 16] {
    let bytes = text.as_bytes();
    let marker = b"Let D be a 240-bit long constant string";
    let mut at = 0;
    loop {
        if at + marker.len() > bytes.len() {
            panic!("the ZUC specification no longer defines D where expected");
        }
        let mut i = 0;
        while i < marker.len() && bytes[at + i] == marker[i] {
            i += 1;
        }
        if i == marker.len() {
            break;
        }
        at += 1;
    }
    let mut out = [0u32; 16];
    let mut found = 0;
    while found < 16 {
        if at + 1 >= bytes.len() {
            panic!("the ZUC specification's D has fewer than sixteen values");
        }
        if bytes[at] == b'd' && bytes[at + 1].is_ascii_digit() {
            let mut p = at + 1;
            let mut n = 0usize;
            while bytes[p].is_ascii_digit() {
                n = n * 10 + (bytes[p] - b'0') as usize;
                p += 1;
            }
            while bytes[p] == b' ' {
                p += 1;
            }
            if bytes[p] == b'=' {
                p += 1;
                while bytes[p] == b' ' {
                    p += 1;
                }
                let mut value = 0u32;
                let mut digits = 0;
                while bytes[p] == b'0' || bytes[p] == b'1' {
                    value = value << 1 | (bytes[p] - b'0') as u32;
                    digits += 1;
                    p += 1;
                }
                // The last digit read is the subscript's 2 only if a 2
                // follows fifteen binary digits.
                if n != found || digits != 15 || bytes[p] != b'2' {
                    panic!("a ZUC constant d_i is not fifteen binary digits and a subscript");
                }
                out[found] = value;
                found += 1;
                at = p;
            }
        }
        at += 1;
    }
    out
}

const P: u32 = 0x7fff_ffff;

/// `a + b mod 2^31 - 1` for cells: the carry out of bit 31 folded back
/// in, which needs no comparison.
///
/// It also is the specification's zero rule - "if s16 = 0, set s16 =
/// 2^31 - 1" - with nothing added: a sum that is a multiple of the prime
/// comes out as 2^31 - 1, never 0, unless both operands are 0. Every
/// loaded cell is non-zero (each holds a non-zero constant), a rotation of
/// a non-zero cell is non-zero, and so no cell is ever 0. A masked
/// replacement written after the additions was dead code: removing it
/// changed no answer, which is how that was found.
#[inline]
fn add31(a: u32, b: u32) -> u32 {
    let c = a + b;
    (c & P) + (c >> 31)
}

/// `x * 2^k mod 2^31 - 1`: a rotation within 31 bits.
#[inline]
fn rot31(x: u32, k: u32) -> u32 {
    ((x << k) | (x >> (31 - k))) & P
}

#[inline]
fn l1(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

#[inline]
fn l2(x: u32) -> u32 {
    x ^ x.rotate_left(8) ^ x.rotate_left(14) ^ x.rotate_left(22) ^ x.rotate_left(30)
}

/// The 32 bit S-box S of section 3.4.1.
#[inline]
fn sbox(x: u32) -> u32 {
    let [a, b, c, d] = x.to_be_bytes();
    u32::from_be_bytes([scan(&S0, a), scan(&S1, b), scan(&S0, c), scan(&S1, d)])
}

/// ZUC-128 or ZUC-256 under one key and IV.
#[derive(Clone)]
pub struct Zuc {
    s: [u32; 16],
    r1: u32,
    r2: u32,
    block: [u8; 4],
    used: usize,
}

impl core::fmt::Debug for Zuc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Zuc").finish_non_exhaustive()
    }
}

/// A ZUC-256 IV as the 25 bytes the paper writes - a 23 byte one has its
/// last six bytes unpacked into eight six bit values, first highest.
fn iv_25(iv: &[u8]) -> Result<[u8; 25], String> {
    let mut out = [0u8; 25];
    match iv.len() {
        25 => {
            if iv[17..].iter().any(|b| b & 0xc0 != 0) {
                return Err("A 25 byte ZUC-256 IV holds six bits in each of its last eight \
                            bytes; a top bit is set."
                    .to_string());
            }
            out.copy_from_slice(iv);
        }
        23 => {
            out[..17].copy_from_slice(&iv[..17]);
            let bits = iv[17..].iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
            for (i, o) in out[17..].iter_mut().enumerate() {
                *o = (bits >> (42 - 6 * i)) as u8 & 0x3f;
            }
        }
        n => return Err(format!("A ZUC-256 IV is 25 bytes, or 23 packed, not {n}.")),
    }
    Ok(out)
}

/// What a ZUC-256 state is for: the keystream, or a MAC of 32, 64 or 128
/// bits, each with its own loading constants.
#[derive(Clone, Copy)]
pub(crate) enum Use256 {
    Keystream,
    Mac(u32),
}

impl Zuc {
    /// ZUC-128 under a 16 byte key and a 16 byte IV.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn zuc128(key: &[u8], iv: &[u8]) -> Result<Zuc, String> {
        if key.len() != 16 {
            return Err(format!("A ZUC-128 key is 16 bytes, not {}.", key.len()));
        }
        if iv.len() != 16 {
            return Err(format!("A ZUC-128 IV is 16 bytes, not {}.", iv.len()));
        }
        let s = core::array::from_fn(|i| u32::from(key[i]) << 23 | D[i] << 8 | u32::from(iv[i]));
        Ok(Zuc::start(s))
    }

    /// ZUC-256 under a 32 byte key and a 25 byte IV (or 23, packed), for
    /// the keystream.
    ///
    /// # Errors
    /// A key or IV of another length, or a 25 byte IV with a top bit set
    /// in one of its six bit values.
    pub fn zuc256(key: &[u8], iv: &[u8]) -> Result<Zuc, String> {
        Zuc::zuc256_for(key, iv, Use256::Keystream)
    }

    pub(crate) fn zuc256_for(key: &[u8], iv: &[u8], purpose: Use256) -> Result<Zuc, String> {
        let key: &[u8; 32] = key.try_into()
            .map_err(|_| format!("A ZUC-256 key is 32 bytes, not {}.", key.len()))?;
        let iv = iv_25(iv)?;
        let d = match purpose {
            Use256::Keystream => &zuc256_constants::KEYSTREAM,
            Use256::Mac(32) => &zuc256_constants::MAC32,
            Use256::Mac(64) => &zuc256_constants::MAC64,
            Use256::Mac(128) => &zuc256_constants::MAC128,
            Use256::Mac(t) => return Err(format!(
                "A ZUC-256 MAC is 32, 64 or 128 bits, not {t}.")),
        };
        Ok(Zuc::start(load_256(key, &iv, d)))
    }

    /// 3GPP's ZUC-256 (TS 35.246 section 6) under a 32 byte key and a 16
    /// byte IV: 256-NEA6's, 256-NIA6's and 256-NCA6's keystream generator,
    /// with the IV `mobile::make_5g_iv` builds.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn zuc256_3gpp(key: &[u8], iv: &[u8]) -> Result<Zuc, String> {
        let key: &[u8; 32] = key.try_into()
            .map_err(|_| format!("A 3GPP ZUC-256 key is 32 bytes, not {}.", key.len()))?;
        let iv: &[u8; 16] = iv.try_into()
            .map_err(|_| format!("A 3GPP ZUC-256 IV is 16 bytes, not {}.", iv.len()))?;
        Ok(Zuc::start_rounds(load_3gpp(key, iv), 48))
    }

    /// Section 3.6: set-up from the loaded cells.
    fn start(s: [u32; 16]) -> Zuc {
        Zuc::start_rounds(s, 32)
    }

    /// Set-up of `rounds` clocks with `W >> 1` fed back, then one whose
    /// output is discarded.
    fn start_rounds(s: [u32; 16], rounds: usize) -> Zuc {
        let mut z = Zuc { s, r1: 0, r2: 0, block: [0; 4], used: 4 };
        for _ in 0..rounds {
            let w = z.f();
            z.clock(w >> 1);
        }
        z.f();
        z.clock(0);
        z
    }

    /// The bit reorganisation's X0..X2 through F: its output W, and the
    /// update of R1 and R2.
    #[inline]
    fn f(&mut self) -> u32 {
        let s = &self.s;
        let x0 = ((s[15] & 0x7fff_8000) << 1) | (s[14] & 0xffff);
        let x1 = ((s[11] & 0xffff) << 16) | (s[9] >> 15);
        let x2 = ((s[7] & 0xffff) << 16) | (s[5] >> 15);
        let w = (x0 ^ self.r1).wrapping_add(self.r2);
        let w1 = self.r1.wrapping_add(x1);
        let w2 = self.r2 ^ x2;
        self.r1 = sbox(l1((w1 << 16) | (w2 >> 16)));
        self.r2 = sbox(l2((w2 << 16) | (w1 >> 16)));
        w
    }

    /// The LFSR, with `u` added in set-up and zero after.
    #[inline]
    fn clock(&mut self, u: u32) {
        let s = &self.s;
        let mut v = add31(rot31(s[15], 15), rot31(s[13], 17));
        v = add31(v, rot31(s[10], 21));
        v = add31(v, rot31(s[4], 20));
        v = add31(v, rot31(s[0], 8));
        v = add31(v, s[0]);
        v = add31(v, u);
        self.s.copy_within(1.., 0);
        self.s[15] = v;
    }

    /// The next keystream word.
    pub fn next_word(&mut self) -> u32 {
        let x3 = ((self.s[2] & 0xffff) << 16) | (self.s[0] >> 15);
        let z = self.f() ^ x3;
        self.clock(0);
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

    /// `n` keystream words.
    pub(crate) fn words(&mut self, n: usize) -> Vec<u32> {
        (0..n).map(|_| self.next_word()).collect()
    }
}

impl StreamCipher for Zuc {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

/// ZUC-256's loading of the key `k`, the IV `iv` (the 25 byte form) and
/// the constants `d`: each cell `a || b || c || e`, of 8, 7, 8 and 8 bits.
fn load_256(k: &[u8; 32], iv: &[u8; 25], d: &[u8; 16]) -> [u32; 16] {
    let cell = |a: u8, b: u8, c: u8, e: u8| {
        u32::from(a) << 23 | u32::from(b) << 16 | u32::from(c) << 8 | u32::from(e)
    };
    [
        cell(k[0], d[0], k[21], k[16]),
        cell(k[1], d[1], k[22], k[17]),
        cell(k[2], d[2], k[23], k[18]),
        cell(k[3], d[3], k[24], k[19]),
        cell(k[4], d[4], k[25], k[20]),
        cell(iv[0], d[5] | iv[17], k[5], k[26]),
        cell(iv[1], d[6] | iv[18], k[6], k[27]),
        cell(iv[10], d[7] | iv[19], k[7], iv[2]),
        cell(k[8], d[8] | iv[20], iv[3], iv[11]),
        cell(k[9], d[9] | iv[21], iv[12], iv[4]),
        cell(iv[5], d[10] | iv[22], k[10], k[28]),
        cell(k[11], d[11] | iv[23], iv[6], iv[13]),
        cell(k[12], d[12] | iv[24], iv[7], iv[14]),
        cell(k[13], d[13], iv[15], iv[8]),
        cell(k[14], d[14] | (k[31] >> 4), iv[16], iv[9]),
        cell(k[15], d[15] | (k[31] & 0x0f), k[30], k[29]),
    ]
}

/// 3GPP's ZUC-256 loading of the key `k` and the IV `iv`: each cell
/// `K_i || d_i || b || c` of 8, 7, 8 and 8 bits, TS 35.246 section 6.2.7.
fn load_3gpp(k: &[u8; 32], iv: &[u8; 16]) -> [u32; 16] {
    core::array::from_fn(|i| {
        let (b, c) = match i {
            0..=6 => (k[16 + i], k[24 + i]),
            7..=14 => (iv[i - 7], iv[i + 1]),
            _ => (k[23], k[31]),
        };
        u32::from(k[i]) << 23 | u32::from(D_3GPP[i]) << 16 | u32::from(b) << 8 | u32::from(c)
    })
}

/// The `t` bits of the keystream `z` from bit `bit` on, `t` at most 128,
/// in the low bits of the result. `z` must hold the words they fall in
/// and one more.
fn window(z: &[u32], bit: usize, t: u32) -> u128 {
    let (j, r) = (bit / 32, (bit % 32) as u32);
    let mut wide = 0u128;
    for k in 0..4 {
        wide = wide << 32 | u128::from(z[j + k]);
    }
    // The top r bits of the fifth word come in at the bottom; for r = 0
    // none, without a shift by 32.
    let fifth = (u64::from(z[j + 4]) << r) >> 32;
    wide = wide << r | u128::from(fifth);
    wide >> (128 - t)
}

/// Message bit `i` of `data` as a mask of all ones or zero.
#[inline]
fn bit_mask(data: &[u8], i: usize) -> u128 {
    0u128.wrapping_sub(u128::from((data[i / 8] >> (7 - i % 8)) & 1))
}

/// Check a message's length against its bit count.
pub(crate) fn check_bits(data: &[u8], bits: u64) -> Result<usize, String> {
    let need = bits.div_ceil(8);
    if need != data.len() as u64 {
        return Err(format!("{bits} bits of message are {need} bytes, not {}.", data.len()));
    }
    Ok(bits as usize)
}

/// 128-EIA3's computation over the keystream of `zuc`, an initialised
/// ZUC-128: the first `bits` bits of `data`, the 32 bit MAC.
pub(crate) fn eia3_core(mut zuc: Zuc, data: &[u8], bits: usize) -> [u8; 4] {
    let n = bits.div_ceil(32) + 2;
    // Four words past the last one used, for `window`'s reads.
    let z = zuc.words(n + 4);
    let mut t = 0u128;
    for i in 0..bits {
        t ^= window(&z, i, 32) & bit_mask(data, i);
    }
    t ^= window(&z, bits, 32);
    ((t as u32) ^ z[n - 1]).to_be_bytes()
}

/// ZUC-128's MAC over a 16 byte key and a raw 16 byte IV: the first
/// `bits` bits of `data`, 4 bytes.
///
/// # Errors
/// A key or IV of another length, or `data` not `ceil(bits / 8)` bytes.
pub fn zuc128_mac(key: &[u8], iv: &[u8], data: &[u8], bits: u64) -> Result<[u8; 4], String> {
    let bits = check_bits(data, bits)?;
    Ok(eia3_core(Zuc::zuc128(key, iv)?, data, bits))
}

/// ZUC-256's MAC over a 32 byte key and a 25 byte IV (or 23, packed): the
/// first `bits` bits of `data`, a tag of `tag_bits` = 32, 64 or 128 bits.
///
/// # Errors
/// A key or IV of another length, another tag size, or `data` not
/// `ceil(bits / 8)` bytes.
pub fn zuc256_mac(key: &[u8], iv: &[u8], tag_bits: u32, data: &[u8], bits: u64)
                  -> Result<Vec<u8>, String> {
    let bits = check_bits(data, bits)?;
    let mut zuc = Zuc::zuc256_for(key, iv, Use256::Mac(tag_bits))?;
    let t = tag_bits as usize;
    let z = zuc.words((2 * t + bits).div_ceil(32) + 5);
    let mut tag = window(&z, 0, tag_bits);
    for i in 0..bits {
        tag ^= window(&z, t + i, tag_bits) & bit_mask(data, i);
    }
    tag ^= window(&z, t + bits, tag_bits);
    Ok(tag.to_be_bytes()[16 - t / 8..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hexadecimal tokens between the `{` after `label` and its `}`.
    fn braced<'a>(text: &'a str, label: &str) -> Vec<&'a str> {
        let at = text.find(label).unwrap_or_else(|| panic!("no {label:?}"));
        let open = at + text[at..].find('{').expect("a brace");
        let close = open + text[open..].find('}').expect("a closing brace");
        text[open + 1..close].split_whitespace().collect()
    }

    fn word(token: &str) -> u32 {
        u32::from_str_radix(token.trim_start_matches("0x"), 16).unwrap()
    }

    /// TS 35.247 section 5.3's three ZUC-256 traces: the LFSR as loaded,
    /// the state after each initialisation clock it prints - the 48 that
    /// feed `W >> 1` back and the 49th, whose output is discarded - and 32
    /// keystream words.
    #[test]
    fn test_3gpp_zuc256_traces() {
        let text = include_str!("../../rfcs/35247-k00.txt");
        let tests: Vec<&str> = text.split("=== ZUC-256 TEST #").skip(1).collect();
        assert_eq!(tests.len(), 3);
        let mut states = 0;
        for test in tests {
            // Past this test's own "N ===", to the next test's heading.
            let test = &test[test.find('\n').unwrap()..];
            let test = &test[..test.find("===").unwrap_or(test.len())];
            let bytes = |label| -> Vec<u8> {
                braced(test, label).iter().map(|t| u8::from_str_radix(t, 16).unwrap()).collect()
            };
            let (key, iv) = (bytes("KEY ="), bytes("IV ="));
            let mut z = Zuc { s: load_3gpp(&key.clone().try_into().unwrap(),
                                           &iv.clone().try_into().unwrap()),
                              r1: 0, r2: 0, block: [0; 4], used: 4 };
            let loaded: Vec<u32> = braced(test, "State after (Key, IV) loading").iter()
                .map(|t| word(t)).collect();
            assert_eq!(z.s.to_vec(), loaded);
            for n in 1..=49 {
                if n <= 48 {
                    let w = z.f();
                    z.clock(w >> 1);
                } else {
                    z.f();
                    z.clock(0);
                }
                let label = format!("State after {n} initialisation clocks\n");
                let Some(at) = test.find(&label) else { continue };
                let state = &test[at..];
                let lfsr: Vec<u32> = braced(state, "LFSR =").iter().map(|t| word(t)).collect();
                assert_eq!(z.s.to_vec(), lfsr, "after {n} clocks");
                let register = |name: &str| {
                    let line = &state[state.find(name).unwrap()..];
                    word(line.split_whitespace().nth(2).unwrap())
                };
                assert_eq!((z.r1, z.r2), (register("FSM_R1"), register("FSM_R2")),
                           "after {n} clocks");
                states += 1;
            }
            // "Ks =" in two tests and "ks =" in the third.
            let keystream: Vec<u32> = braced(test, "Keystream mode:").iter()
                .map(|t| word(t)).collect();
            assert_eq!(keystream.len(), 32);
            assert_eq!(z.words(32), keystream);
            // And through the public constructor.
            let mut again = Zuc::zuc256_3gpp(&key, &iv).unwrap();
            assert_eq!(again.words(32), keystream);
        }
        assert!(states >= 30, "{states} states compared");
    }

    /// Section 3.4.1's examples: S0(0x12) = 0xF9, S1(0x34) = 0xC0 and
    /// S(0x12345678) = 0xF9C05A4E.
    #[test]
    fn test_the_examples_in_the_text() {
        assert_eq!(S0[0x12], 0xf9);
        assert_eq!(S1[0x34], 0xc0);
        assert_eq!(sbox(0x1234_5678), 0xf9c0_5a4e);
    }

    #[test]
    fn test_the_s_boxes_are_permutations() {
        for table in [&S0, &S1] {
            let mut seen = [false; 256];
            for &v in table.iter() {
                assert!(!seen[v as usize]);
                seen[v as usize] = true;
            }
        }
    }

    /// The test data's section 3 prints the LFSR as loaded for an all-zero
    /// key and IV: s0 = 0x0044d700, so d0 = 0x44d7, and the rest follow
    /// the same way; and its words are the constants' own.
    #[test]
    fn test_d_is_the_loaded_state() {
        let text = include_str!("../../rfcs/eea3eia3testdatav11.txt");
        let after = &text[text.find("LFSR-state at the beginning").expect("table")..];
        let cells: Vec<u32> = after.split_whitespace()
            .filter(|t| t.len() == 8 && t.bytes().all(|b| b.is_ascii_hexdigit()))
            .take(16)
            .map(|t| u32::from_str_radix(t, 16).unwrap())
            .collect();
        assert_eq!(cells.len(), 16);
        for (i, cell) in cells.iter().enumerate() {
            assert_eq!(*cell, D[i] << 8, "d{i}");
        }
    }

    /// add31 is addition mod 2^31 - 1 on cells, including the sums that
    /// reach the modulus, which it leaves as 2^31 - 1 rather than 0 - the
    /// specification's zero rule.
    #[test]
    fn test_add31_is_addition_mod_the_prime() {
        let p = u64::from(P);
        for &(a, b) in &[(1u32, 2u32), (P, 1), (P - 1, 1), (P, P), (0x4000_0000, 0x4000_0000),
                         (0x1234_5678, 0x7000_0000), (0, 0)] {
            let got = u64::from(add31(a, b));
            assert_eq!(got % p, (u64::from(a) + u64::from(b)) % p, "{a:#x} + {b:#x}");
            assert!(got <= p);
        }
        assert_eq!(add31(P - 1, 1), P);
    }

    #[test]
    fn test_window_reads_any_bit_offset() {
        let z: Vec<u32> = (0..12u32).map(|i| i.wrapping_mul(0x9e37_79b9) ^ 0xa5a5_5a5a).collect();
        let bits: Vec<u8> = z.iter().flat_map(|w| (0..32).rev().map(move |k| (w >> k) as u8 & 1))
            .collect();
        for t in [32u32, 64, 128] {
            for bit in [0usize, 1, 7, 31, 32, 33, 63, 100, 200] {
                let want = bits[bit..bit + t as usize].iter()
                    .fold(0u128, |acc, &b| acc << 1 | u128::from(b));
                assert_eq!(window(&z, bit, t), want, "{t} bits at {bit}");
            }
        }
    }

    #[test]
    fn test_iv_forms() {
        let mut iv25 = [0u8; 25];
        for (i, b) in iv25.iter_mut().enumerate() {
            *b = if i < 17 { (i as u8).wrapping_mul(11) } else { (i as u8).wrapping_mul(23) & 0x3f };
        }
        let bits = iv25[17..].iter().fold(0u64, |acc, &b| acc << 6 | u64::from(b));
        let mut iv23 = iv25[..17].to_vec();
        iv23.extend((0..6).map(|i| (bits >> (40 - 8 * i)) as u8));
        assert_eq!(iv_25(&iv23).expect("23"), iv25);
        let key = [7u8; 32];
        let mut a = Zuc::zuc256(&key, &iv25).expect("25");
        let mut b = Zuc::zuc256(&key, &iv23).expect("23");
        assert_eq!(a.words(8), b.words(8));
        iv25[20] |= 0x40;
        assert!(Zuc::zuc256(&key, &iv25).is_err());
        assert!(Zuc::zuc256(&key, &[0; 24]).is_err());
    }

    #[test]
    fn test_streaming_equals_one_call() {
        let (key, iv): (Vec<u8>, Vec<u8>) = ((0..16).collect(), (16..32).collect());
        let mut whole = vec![0u8; 200];
        Zuc::zuc128(&key, &iv).expect("lengths").apply_keystream(&mut whole);
        for piece in [1, 2, 3, 4, 5, 7, 63, 64, 65] {
            let mut c = Zuc::zuc128(&key, &iv).expect("lengths");
            let mut got = vec![0u8; 200];
            for chunk in got.chunks_mut(piece) {
                c.apply_keystream(chunk);
            }
            assert_eq!(got, whole, "pieces of {piece}");
        }
    }

    #[test]
    fn test_other_lengths_are_refused() {
        assert_eq!(Zuc::zuc128(&[0; 15], &[0; 16]).unwrap_err(),
                   "A ZUC-128 key is 16 bytes, not 15.");
        assert_eq!(Zuc::zuc128(&[0; 16], &[0; 17]).unwrap_err(),
                   "A ZUC-128 IV is 16 bytes, not 17.");
        assert_eq!(Zuc::zuc256(&[0; 16], &[0; 25]).unwrap_err(),
                   "A ZUC-256 key is 32 bytes, not 16.");
        assert_eq!(zuc256_mac(&[0; 32], &[0; 25], 48, &[], 0).unwrap_err(),
                   "A ZUC-256 MAC is 32, 64 or 128 bits, not 48.");
        assert_eq!(zuc128_mac(&[0; 16], &[0; 16], &[0; 2], 17).unwrap_err(),
                   "17 bits of message are 3 bytes, not 2.");
    }
}
