//! ISAAC and ISAAC-64 (Bob Jenkins, 1996): array-based generators
//! designed as stream ciphers, 32 and 64 bit words.
//!
//! ## The generator
//!
//! The state is a 256 word array `m` and three words `a`, `b`, `c`. Each
//! call fills a 256 word results array `r`:
//!
//! ```text
//! c += 1; b += c
//! for i in 0..256:
//!     x = m[i]
//!     a = f(a, i) + m[i + 128 mod 256]
//!     m[i] = y = m[x >> 2 mod 256] + a + b          (x >> 3 in ISAAC-64)
//!     r[i] = b = m[y >> 10 mod 256] + x             (y >> 11)
//! ```
//!
//! `f` depends on `i mod 4`: `a ^ a << 13`, `a ^ a >> 6`, `a ^ a << 2`,
//! `a ^ a >> 16` in ISAAC; `!(a ^ a << 21)`, `a ^ a >> 5`, `a ^ a << 12`,
//! `a ^ a >> 33` in ISAAC-64.
//!
//! ## Keying
//!
//! The key is up to 1024 bytes (2048 for ISAAC-64), read as little-endian
//! words into a 256 word seed and zero-padded, which is what Bouncy
//! Castle, rand_isaac and the C code on a little-endian machine do with
//! bytes. `randinit` with its flag set then starts eight words at the
//! golden ratio, scrambles them four times with `mix`, and folds the seed
//! into `m` in two passes of `mix`; `a`, `b` and `c` start at zero, and
//! the first call above fills block 0. **Keys that differ only in
//! trailing zero bytes are the same key**, the empty key included:
//! nothing records the length, which Jenkins suggests putting in the last
//! word and no implementation does.
//!
//! ## Reading the keystream
//!
//! The generator gives words; the readings of it as bytes differ.
//!
//! - `Isaac` and `Isaac64`, catalogued as `isaac` and `isaac64`: the
//!   reference's `rand()` order - block 0 first, each block's words from
//!   index 255 down to 0 - each word little endian. This is rand_isaac's
//!   `fill_bytes`, and the reference's `rand()` written out little
//!   endian.
//! - `IsaacBouncyCastle`, `isaac-bouncycastle`: Bouncy Castle's
//!   `ISAACEngine`, which calls the generator again before its first byte,
//!   so block 0 is never used: blocks 1, 2, .. with each block's words in
//!   index order and each word big endian.
//!
//! ## Timing
//!
//! Both indirections, `m[x >> 2]` and `m[y >> 10]`, are reads at indices
//! taken from the secret state. That is the design, as with RC4 and HC-128,
//! and every implementation does it; this one is not constant time.

use crate::stream_ciphers::StreamCipher;

const WORDS: usize = 256;

/// `m[v mod 256]`: the generator's reads at indices from the state, the
/// one place it is not constant time. Out of line, as `hc.rs`'s `h`
/// functions are, so `ct_check.py` can name them: inlined, the compiler
/// folds the load into the addition that uses it and the report names
/// `wrapping_add`.
#[inline(never)]
fn ind32(m: &[u32; WORDS], v: u32) -> u32 {
    m[v as usize % WORDS]
}

#[inline(never)]
fn ind64(m: &[u64; WORDS], v: u64) -> u64 {
    m[v as usize % WORDS]
}

/// The 32 bit generator: `m`, `a`, `b`, `c`.
#[derive(Clone)]
struct Core32 {
    m: [u32; WORDS],
    a: u32,
    b: u32,
    c: u32,
}

fn mix32(s: &mut [u32; 8]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *s;
    a ^= b << 11; d = d.wrapping_add(a); b = b.wrapping_add(c);
    b ^= c >> 2; e = e.wrapping_add(b); c = c.wrapping_add(d);
    c ^= d << 8; f = f.wrapping_add(c); d = d.wrapping_add(e);
    d ^= e >> 16; g = g.wrapping_add(d); e = e.wrapping_add(f);
    e ^= f << 10; h = h.wrapping_add(e); f = f.wrapping_add(g);
    f ^= g >> 4; a = a.wrapping_add(f); g = g.wrapping_add(h);
    g ^= h << 8; b = b.wrapping_add(g); h = h.wrapping_add(a);
    h ^= a >> 9; c = c.wrapping_add(h); a = a.wrapping_add(b);
    *s = [a, b, c, d, e, f, g, h];
}

impl Core32 {
    /// `randinit` with its flag set, over `seed`.
    fn new(seed: &[u32; WORDS]) -> Core32 {
        let mut s = [0x9e37_79b9u32; 8];
        for _ in 0..4 {
            mix32(&mut s);
        }
        let mut m = [0u32; WORDS];
        for pass in 0..2 {
            for i in (0..WORDS).step_by(8) {
                for k in 0..8 {
                    let fold = if pass == 0 { seed[i + k] } else { m[i + k] };
                    s[k] = s[k].wrapping_add(fold);
                }
                mix32(&mut s);
                m[i..i + 8].copy_from_slice(&s);
            }
        }
        Core32 { m, a: 0, b: 0, c: 0 }
    }

    /// One call of the generator: the next results array, in index order.
    fn refill(&mut self, r: &mut [u32; WORDS]) {
        self.c = self.c.wrapping_add(1);
        let (mut a, mut b) = (self.a, self.b.wrapping_add(self.c));
        let m = &mut self.m;
        for i in 0..WORDS {
            let x = m[i];
            a = match i % 4 {
                0 => a ^ (a << 13),
                1 => a ^ (a >> 6),
                2 => a ^ (a << 2),
                _ => a ^ (a >> 16),
            }
            .wrapping_add(m[(i + WORDS / 2) % WORDS]);
            let y = ind32(m, x >> 2).wrapping_add(a).wrapping_add(b);
            m[i] = y;
            b = ind32(m, y >> 10).wrapping_add(x);
            r[i] = b;
        }
        self.a = a;
        self.b = b;
    }
}

/// The 64 bit generator.
#[derive(Clone)]
struct Core64 {
    m: [u64; WORDS],
    a: u64,
    b: u64,
    c: u64,
}

fn mix64(s: &mut [u64; 8]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *s;
    a = a.wrapping_sub(e); f ^= h >> 9; h = h.wrapping_add(a);
    b = b.wrapping_sub(f); g ^= a << 9; a = a.wrapping_add(b);
    c = c.wrapping_sub(g); h ^= b >> 23; b = b.wrapping_add(c);
    d = d.wrapping_sub(h); a ^= c << 15; c = c.wrapping_add(d);
    e = e.wrapping_sub(a); b ^= d >> 14; d = d.wrapping_add(e);
    f = f.wrapping_sub(b); c ^= e << 20; e = e.wrapping_add(f);
    g = g.wrapping_sub(c); d ^= f >> 17; f = f.wrapping_add(g);
    h = h.wrapping_sub(d); e ^= g << 14; g = g.wrapping_add(h);
    *s = [a, b, c, d, e, f, g, h];
}

impl Core64 {
    fn new(seed: &[u64; WORDS]) -> Core64 {
        let mut s = [0x9e37_79b9_7f4a_7c13u64; 8];
        for _ in 0..4 {
            mix64(&mut s);
        }
        let mut m = [0u64; WORDS];
        for pass in 0..2 {
            for i in (0..WORDS).step_by(8) {
                for k in 0..8 {
                    let fold = if pass == 0 { seed[i + k] } else { m[i + k] };
                    s[k] = s[k].wrapping_add(fold);
                }
                mix64(&mut s);
                m[i..i + 8].copy_from_slice(&s);
            }
        }
        Core64 { m, a: 0, b: 0, c: 0 }
    }

    fn refill(&mut self, r: &mut [u64; WORDS]) {
        self.c = self.c.wrapping_add(1);
        let (mut a, mut b) = (self.a, self.b.wrapping_add(self.c));
        let m = &mut self.m;
        for i in 0..WORDS {
            let x = m[i];
            a = match i % 4 {
                0 => !(a ^ (a << 21)),
                1 => a ^ (a >> 5),
                2 => a ^ (a << 12),
                _ => a ^ (a >> 33),
            }
            .wrapping_add(m[(i + WORDS / 2) % WORDS]);
            let y = ind64(m, x >> 3).wrapping_add(a).wrapping_add(b);
            m[i] = y;
            b = ind64(m, y >> 11).wrapping_add(x);
            r[i] = b;
        }
        self.a = a;
        self.b = b;
    }
}

/// The key's bytes as `N`-byte little-endian words, zero-padded to 256.
fn seed_words<const N: usize>(key: &[u8], name: &str) -> Result<[u64; WORDS], String> {
    if key.len() > WORDS * N {
        return Err(format!("An {name} key is at most {} bytes, not {}.", WORDS * N, key.len()));
    }
    let mut seed = [0u64; WORDS];
    for (i, byte) in key.iter().enumerate() {
        seed[i / N] |= u64::from(*byte) << (8 * (i % N));
    }
    Ok(seed)
}

/// Keystream bytes taken from a buffer that `next` refills, XORed onto
/// the input.
fn xor_from(input: &[u8], result: &mut Vec<u8>, buf: &mut Vec<u8>, used: &mut usize,
            mut next: impl FnMut(&mut Vec<u8>)) {
    result.reserve(input.len());
    for byte in input {
        if *used == buf.len() {
            buf.clear();
            next(buf);
            *used = 0;
        }
        result.push(byte ^ buf[*used]);
        *used += 1;
    }
}

/// ISAAC with the reference's `rand()` order, each word little endian.
#[derive(Clone)]
pub struct Isaac {
    core: Box<Core32>,
    first: Option<Box<[u32; WORDS]>>,
    buf: Vec<u8>,
    used: usize,
}

impl core::fmt::Debug for Isaac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Isaac").finish_non_exhaustive()
    }
}

fn new_core32(key: &[u8], name: &str) -> Result<Box<Core32>, String> {
    let wide = seed_words::<4>(key, name)?;
    let seed: [u32; WORDS] = core::array::from_fn(|i| wide[i] as u32);
    Ok(Box::new(Core32::new(&seed)))
}

impl Isaac {
    /// ISAAC under a key of up to 1024 bytes.
    ///
    /// # Errors
    /// A key over 1024 bytes.
    pub fn new(key: &[u8]) -> Result<Isaac, String> {
        let mut core = new_core32(key, "ISAAC")?;
        let mut first = Box::new([0u32; WORDS]);
        core.refill(&mut first);
        Ok(Isaac { core, first: Some(first), buf: Vec::new(), used: 0 })
    }

    /// The next block of the generator in index order: block 0 on the
    /// first call. Independent of the byte stream only until it is used;
    /// mixing the two skips blocks.
    pub fn next_block(&mut self) -> [u32; WORDS] {
        if let Some(block) = self.first.take() {
            return *block;
        }
        let mut r = [0u32; WORDS];
        self.core.refill(&mut r);
        r
    }
}

impl StreamCipher for Isaac {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut buf = core::mem::take(&mut self.buf);
        let mut used = self.used;
        xor_from(input, result, &mut buf, &mut used, |buf| {
            for w in self.next_block().iter().rev() {
                buf.extend_from_slice(&w.to_le_bytes());
            }
        });
        self.buf = buf;
        self.used = used;
    }
}

/// ISAAC as Bouncy Castle's `ISAACEngine` reads it: from block 1, each
/// block's words in index order, each word big endian.
#[derive(Clone)]
pub struct IsaacBouncyCastle {
    core: Box<Core32>,
    buf: Vec<u8>,
    used: usize,
}

impl core::fmt::Debug for IsaacBouncyCastle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IsaacBouncyCastle").finish_non_exhaustive()
    }
}

impl IsaacBouncyCastle {
    /// The cipher under a key of up to 1024 bytes. Bouncy Castle 1.77
    /// throws on a key of odd length; here such a key is zero-padded like
    /// any other.
    ///
    /// # Errors
    /// A key over 1024 bytes.
    pub fn new(key: &[u8]) -> Result<IsaacBouncyCastle, String> {
        let mut core = new_core32(key, "ISAAC")?;
        let mut unused = [0u32; WORDS];
        core.refill(&mut unused);
        Ok(IsaacBouncyCastle { core, buf: Vec::new(), used: 0 })
    }
}

impl StreamCipher for IsaacBouncyCastle {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let core = &mut self.core;
        xor_from(input, result, &mut self.buf, &mut self.used, |buf| {
            let mut r = [0u32; WORDS];
            core.refill(&mut r);
            for w in &r {
                buf.extend_from_slice(&w.to_be_bytes());
            }
        });
    }
}

/// ISAAC-64 with the reference's `rand()` order, each word little endian.
#[derive(Clone)]
pub struct Isaac64 {
    core: Box<Core64>,
    first: Option<Box<[u64; WORDS]>>,
    buf: Vec<u8>,
    used: usize,
}

impl core::fmt::Debug for Isaac64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Isaac64").finish_non_exhaustive()
    }
}

impl Isaac64 {
    /// ISAAC-64 under a key of up to 2048 bytes.
    ///
    /// # Errors
    /// A key over 2048 bytes.
    pub fn new(key: &[u8]) -> Result<Isaac64, String> {
        let mut core = Box::new(Core64::new(&seed_words::<8>(key, "ISAAC-64")?));
        let mut first = Box::new([0u64; WORDS]);
        core.refill(&mut first);
        Ok(Isaac64 { core, first: Some(first), buf: Vec::new(), used: 0 })
    }

    /// The next block of the generator in index order, as
    /// `Isaac::next_block`.
    pub fn next_block(&mut self) -> [u64; WORDS] {
        if let Some(block) = self.first.take() {
            return *block;
        }
        let mut r = [0u64; WORDS];
        self.core.refill(&mut r);
        r
    }
}

impl StreamCipher for Isaac64 {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut buf = core::mem::take(&mut self.buf);
        let mut used = self.used;
        xor_from(input, result, &mut buf, &mut used, |buf| {
            for w in self.next_block().iter().rev() {
                buf.extend_from_slice(&w.to_le_bytes());
            }
        });
        self.buf = buf;
        self.used = used;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(c: &mut impl StreamCipher, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        c.crypt(&vec![0; n], &mut out);
        out
    }

    /// The byte stream is the blocks reversed word by word, little
    /// endian; Bouncy Castle's is the same generator from block 1, forward
    /// and big endian; pieces equal one call.
    #[test]
    fn test_the_readings_are_one_generator() {
        let key: Vec<u8> = (0..37).collect();
        let mut blocks = Isaac::new(&key).unwrap();
        let b0 = blocks.next_block();
        let b1 = blocks.next_block();
        let ours = stream(&mut Isaac::new(&key).unwrap(), 2048);
        let expect: Vec<u8> = b0.iter().rev().chain(b1.iter().rev())
            .flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(ours, expect);
        let bc = stream(&mut IsaacBouncyCastle::new(&key).unwrap(), 1024);
        let expect: Vec<u8> = b1.iter().flat_map(|w| w.to_be_bytes()).collect();
        assert_eq!(bc, expect);
        let mut pieces = Vec::new();
        let mut c = Isaac64::new(&key).unwrap();
        for n in [1, 7, 2040, 3, 2048, 100] {
            c.crypt(&vec![0; n], &mut pieces);
        }
        assert_eq!(pieces, stream(&mut Isaac64::new(&key).unwrap(), pieces.len()));
    }

    #[test]
    fn test_trailing_zeros_and_long_keys() {
        let a = stream(&mut Isaac::new(&[5, 6]).unwrap(), 64);
        assert_eq!(a, stream(&mut Isaac::new(&[5, 6, 0, 0, 0]).unwrap(), 64));
        assert_eq!(stream(&mut Isaac::new(&[]).unwrap(), 64),
                   stream(&mut Isaac::new(&[0; 1024]).unwrap(), 64));
        assert!(Isaac::new(&[0; 1025]).is_err());
        assert!(IsaacBouncyCastle::new(&[0; 1025]).is_err());
        assert!(Isaac64::new(&[0; 2048]).is_ok());
        assert_eq!(Isaac64::new(&[0; 2049]).unwrap_err(),
                   "An ISAAC-64 key is at most 2048 bytes, not 2049.");
    }
}
