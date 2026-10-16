//! HC-128 and HC-256 (Hongjun Wu, FSE 2004 and the eSTREAM submission):
//! table-driven stream ciphers, HC-128 in the eSTREAM software
//! portfolio.
//!
//! HC-128 takes a 128 bit key and a 128 bit IV, HC-256 256 bits of
//! each, and both give 32 bits of keystream per step.
//!
//! ## The state
//!
//! Two tables of 32 bit words, `P` and `Q`: 512 each in HC-128, 1024 in
//! HC-256. Step `i` updates one word, `j = i mod n`, of `P` for the first
//! `n` steps of every `2n` and of `Q` for the next `n`, every index taken
//! mod `n`:
//!
//! ```text
//! HC-128  P[j] += g1(P[j-3], P[j-10], P[j-511])     s = h1(P[j-12]) ^ P[j]
//!         g1(x, y, z) = (x >>> 10 ^ z >>> 23) + (y >>> 8)
//!         h1(x) = Q[x0] + Q[256 + x2]
//! HC-256  P[j] += P[j-10] + g1(P[j-3], P[j-1023])   s = h1(P[j-12]) ^ P[j]
//!         g1(x, y) = (x >>> 10 ^ y >>> 23) + Q[(x ^ y) mod 1024]
//!         h1(x) = Q[x0] + Q[256 + x1] + Q[512 + x2] + Q[768 + x3]
//! ```
//!
//! `x0` is a word's least significant byte. The `Q` steps are the mirror
//! image with `P` and `Q` exchanged - and in HC-128 the rotations of
//! `g2` turned left, where HC-256's `g2` rotates right like its `g1`.
//!
//! ## Initialisation
//!
//! `W[0..]` is the key's words, then the IV's (HC-128 repeats each of its
//! four words twice), then `W[i] = f2(W[i-2]) + W[i-7] + f1(W[i-15]) +
//! W[i-16] + i`, the step number added in. `P` and `Q` are taken from
//! `W` past its first 256 (HC-128) or 512 (HC-256) words, and the cipher
//! runs `2n` steps with no output. **In HC-128 each of those steps
//! leaves its output word in place of the word it updated** - the update
//! XORed with `h1` - and in HC-256 they do not. Both are self-consistent
//! when wrong.
//!
//! ## Byte order
//!
//! Key, IV and keystream words are little endian, as the eSTREAM
//! submissions, Crypto++, Bouncy Castle and RustCrypto all read them.
//!
//! ## Not constant time
//!
//! Every step looks words up in a table at indices taken from the
//! secret state, which is the design: a cache-timing observer learns
//! about the state. `docs/pitfalls.md` records it.

use crate::stream_ciphers::StreamCipher;

fn f1(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3
}

fn f2(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10
}

/// The expansion shared by both: `W[i] = f2(W[i-2]) + W[i-7] +
/// f1(W[i-15]) + W[i-16] + i` from 16 on.
fn expand(w: &mut [u32]) {
    for i in 16..w.len() {
        w[i] = f2(w[i - 2]).wrapping_add(w[i - 7]).wrapping_add(f1(w[i - 15]))
            .wrapping_add(w[i - 16]).wrapping_add(i as u32);
    }
}

/// HC-128's `h`: two words of the other table, at indices from bytes 0
/// and 2 of `x`. The table look-ups are the cipher's design, and its
/// timing; they are kept to these three functions, out of line, so
/// `ct_check.py` can name them - inlined, the compiler folds a load into
/// the addition that uses it and the report names the addition. The sums
/// are taken in 64 bits for the same reason: `wrapping_add` would be the
/// innermost frame of every report.
#[inline(never)]
fn h128(table: &[u32; 512], x: u32) -> u32 {
    let (a, b) = (table[(x & 0xff) as usize], table[256 + (x >> 16 & 0xff) as usize]);
    (u64::from(a) + u64::from(b)) as u32
}

/// HC-256's `h`: four words of the other table, one per byte of `x`.
#[inline(never)]
fn h256(table: &[u32; 1024], x: u32) -> u32 {
    let (a, b) = (table[(x & 0xff) as usize], table[256 + (x >> 8 & 0xff) as usize]);
    let (c, d) = (table[512 + (x >> 16 & 0xff) as usize], table[768 + (x >> 24) as usize]);
    (u64::from(a) + u64::from(b) + u64::from(c) + u64::from(d)) as u32
}

/// HC-256's `g`: the rotations and one word of the other table.
#[inline(never)]
fn g256(table: &[u32; 1024], x: u32, y: u32) -> u32 {
    let word = table[((x ^ y) & 1023) as usize];
    (u64::from(x.rotate_right(10) ^ y.rotate_right(23)) + u64::from(word)) as u32
}

fn words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4 bytes")))
}

/// The byte-at-a-time keystream buffer both ciphers share.
#[derive(Clone)]
struct Buffer {
    word: [u8; 4],
    used: usize,
}

impl Buffer {
    fn apply(&mut self, data: &mut [u8], mut next: impl FnMut() -> u32) {
        let mut rest = data;
        while self.used < 4 && !rest.is_empty() {
            rest[0] ^= self.word[self.used];
            self.used += 1;
            rest = &mut rest[1..];
        }
        let mut chunks = rest.chunks_exact_mut(4);
        for chunk in &mut chunks {
            for (b, k) in chunk.iter_mut().zip(next().to_le_bytes()) {
                *b ^= k;
            }
        }
        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            self.word = next().to_le_bytes();
            for (i, b) in tail.iter_mut().enumerate() {
                *b ^= self.word[i];
            }
            self.used = tail.len();
        }
    }
}

/// HC-128 under one key and IV.
#[derive(Clone)]
pub struct Hc128 {
    p: Box<[u32; 512]>,
    q: Box<[u32; 512]>,
    /// The step counter, mod 1024.
    i: usize,
    buffer: Buffer,
}

impl core::fmt::Debug for Hc128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hc128").finish_non_exhaustive()
    }
}

impl Hc128 {
    /// HC-128 under a 16 byte key and a 16 byte IV.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Hc128, String> {
        if key.len() != 16 {
            return Err(format!("An HC-128 key is 16 bytes, not {}.", key.len()));
        }
        if iv.len() != 16 {
            return Err(format!("An HC-128 IV is 16 bytes, not {}.", iv.len()));
        }
        let (k, v) = (words::<4>(key), words::<4>(iv));
        let mut w = vec![0u32; 1280];
        for i in 0..8 {
            w[i] = k[i % 4];
            w[i + 8] = v[i % 4];
        }
        expand(&mut w);
        let mut c = Hc128 {
            p: Box::new(w[256..768].try_into().expect("512 words")),
            q: Box::new(w[768..1280].try_into().expect("512 words")),
            i: 0,
            buffer: Buffer { word: [0; 4], used: 4 },
        };
        // During initialisation the word a step updates becomes
        // `(P[j] + g1(..)) ^ h1(P[j-12])`, which is the step's output.
        for _ in 0..1024 {
            let on_p = c.i < 512;
            let (j, s) = c.step();
            if on_p {
                c.p[j] = s;
            } else {
                c.q[j] = s;
            }
        }
        Ok(c)
    }

    /// One step: the index of the table word it updated, and the output.
    fn step(&mut self) -> (usize, u32) {
        let j = self.i & 511;
        let back = |k: usize| (j + 512 - k) & 511;
        let s = if self.i < 512 {
            let (x, y, z) = (self.p[back(3)], self.p[back(10)], self.p[back(511)]);
            let g = (x.rotate_right(10) ^ z.rotate_right(23)).wrapping_add(y.rotate_right(8));
            self.p[j] = self.p[j].wrapping_add(g);
            h128(&self.q, self.p[back(12)]) ^ self.p[j]
        } else {
            let (x, y, z) = (self.q[back(3)], self.q[back(10)], self.q[back(511)]);
            let g = (x.rotate_left(10) ^ z.rotate_left(23)).wrapping_add(y.rotate_left(8));
            self.q[j] = self.q[j].wrapping_add(g);
            h128(&self.p, self.q[back(12)]) ^ self.q[j]
        };
        self.i = (self.i + 1) & 1023;
        (j, s)
    }

    /// XOR the keystream onto `data`, continuing where the last call
    /// stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut buffer = self.buffer.clone();
        buffer.apply(data, || self.step().1);
        self.buffer = buffer;
    }
}

/// HC-256 under one key and IV.
#[derive(Clone)]
pub struct Hc256 {
    p: Box<[u32; 1024]>,
    q: Box<[u32; 1024]>,
    /// The step counter, mod 2048.
    i: usize,
    buffer: Buffer,
}

impl core::fmt::Debug for Hc256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hc256").finish_non_exhaustive()
    }
}

impl Hc256 {
    /// HC-256 under a 32 byte key and a 32 byte IV.
    ///
    /// # Errors
    /// A key or IV of another length.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Hc256, String> {
        if key.len() != 32 {
            return Err(format!("An HC-256 key is 32 bytes, not {}.", key.len()));
        }
        if iv.len() != 32 {
            return Err(format!("An HC-256 IV is 32 bytes, not {}.", iv.len()));
        }
        let mut w = vec![0u32; 2560];
        w[..8].copy_from_slice(&words::<8>(key));
        w[8..16].copy_from_slice(&words::<8>(iv));
        expand(&mut w);
        let mut c = Hc256 {
            p: Box::new(w[512..1536].try_into().expect("1024 words")),
            q: Box::new(w[1536..2560].try_into().expect("1024 words")),
            i: 0,
            buffer: Buffer { word: [0; 4], used: 4 },
        };
        for _ in 0..4096 {
            c.step();
        }
        Ok(c)
    }

    fn step(&mut self) -> u32 {
        let j = self.i & 1023;
        let back = |k: usize| (j + 1024 - k) & 1023;
        let (own, other) = if self.i < 1024 { (&mut self.p, &self.q) } else { (&mut self.q, &self.p) };
        let g = g256(other, own[back(3)], own[back(1023)]);
        own[j] = own[j].wrapping_add(own[back(10)]).wrapping_add(g);
        let s = h256(other, own[back(12)]) ^ own[j];
        self.i = (self.i + 1) & 2047;
        s
    }

    /// XOR the keystream onto `data`, continuing where the last call
    /// stopped.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut buffer = self.buffer.clone();
        buffer.apply(data, || self.step());
        self.buffer = buffer;
    }
}

impl StreamCipher for Hc128 {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

impl StreamCipher for Hc256 {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply_keystream(&mut result[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keystream(cipher: &str, key: &[u8], iv: &[u8], pieces: usize, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        match cipher {
            "hc128" => {
                let mut c = Hc128::new(key, iv).expect("key");
                out.chunks_mut(pieces).for_each(|chunk| c.apply_keystream(chunk));
            }
            _ => {
                let mut c = Hc256::new(key, iv).expect("key");
                out.chunks_mut(pieces).for_each(|chunk| c.apply_keystream(chunk));
            }
        }
        out
    }

    /// Past one whole cycle of both tables - 1024 and 2048 steps, so
    /// 4096 and 8192 bytes - in pieces of every awkward size.
    #[test]
    fn test_streaming_equals_one_call() {
        for (cipher, size, n) in [("hc128", 16, 4096 + 20), ("hc256", 32, 8192 + 20)] {
            let key: Vec<u8> = (0..size as u8).map(|i| i.wrapping_mul(29) ^ 0x5c).collect();
            let iv: Vec<u8> = (0..size as u8).map(|i| i.wrapping_mul(7) ^ 0xa3).collect();
            let whole = keystream(cipher, &key, &iv, n, n);
            for piece in [1, 3, 4, 5, 15, 16, 17, 1000] {
                assert_eq!(keystream(cipher, &key, &iv, piece, n), whole, "{cipher} by {piece}");
            }
        }
    }

    #[test]
    fn test_other_lengths_are_refused() {
        for n in [0, 8, 15, 17, 32] {
            assert_eq!(Hc128::new(&vec![0; n], &[0; 16]).unwrap_err(),
                       format!("An HC-128 key is 16 bytes, not {n}."));
            assert_eq!(Hc128::new(&[0; 16], &vec![0; n]).unwrap_err(),
                       format!("An HC-128 IV is 16 bytes, not {n}."));
        }
        for n in [0, 16, 31, 33, 64] {
            assert_eq!(Hc256::new(&vec![0; n], &[0; 32]).unwrap_err(),
                       format!("An HC-256 key is 32 bytes, not {n}."));
            assert_eq!(Hc256::new(&[0; 32], &vec![0; n]).unwrap_err(),
                       format!("An HC-256 IV is 32 bytes, not {n}."));
        }
    }
}
