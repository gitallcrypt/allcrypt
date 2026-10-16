//! xxHash, Yann Collet's: XXH32, XXH64, and XXH3 at 64 and 128 bits.
//!
//! Fast hashes for hash tables, checksums of files and data
//! deduplication, written for speed and not for an adversary: anyone can
//! make collisions, and XXH3's secret does not make it a MAC. Written from
//! the specification (`doc/xxhash_spec.md`, version 0.2.0, in the
//! reference repository); the primes and XXH3's default secret are in
//! `xxhash_tables.rs`, which `scripts/make_xxhash_tables.py` reads out of
//! three implementations that agree.
//!
//! Every value is little endian inside and big endian outside: the
//! canonical form the specification gives, and what `xxhsum` and PHP's
//! `hash` print. XXH3-128's value is the high half then the low half.
//!
//! XXH32 takes a 32 bit seed and XXH64 a 64 bit one. XXH3 takes a 64 bit
//! seed or a secret of at least 136 bytes, not both: a seed selects the
//! default secret for inputs of 240 bytes or fewer and a secret derived
//! from it for longer ones, and a secret is used with the seed zero.

use super::xxhash_tables::{DEFAULT_SECRET, PRIME32_1, PRIME32_2, PRIME32_3, PRIME32_4, PRIME32_5,
                           PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME64_5, PRIME_MX1,
                           PRIME_MX2};

fn read32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn read64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

/// The full product, low half and high half.
fn multiply(a: u64, b: u64) -> (u64, u64) {
    let product = u128::from(a) * u128::from(b);
    (product as u64, (product >> 64) as u64)
}

/// The product folded: low half XOR high half.
fn fold(a: u64, b: u64) -> u64 {
    let (low, high) = multiply(a, b);
    low ^ high
}

// ------------------------------------------------------------- XXH32 ---

fn round32(acc: u32, lane: u32) -> u32 {
    acc.wrapping_add(lane.wrapping_mul(PRIME32_2)).rotate_left(13).wrapping_mul(PRIME32_1)
}

/// XXH32 in progress.
#[derive(Clone)]
pub struct Xxh32 {
    seed: u32,
    acc: [u32; 4],
    buffer: [u8; 16],
    buffered: usize,
    total: u64,
}

impl Xxh32 {
    pub fn new(seed: u32) -> Xxh32 {
        Xxh32 {
            seed,
            acc: [seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
                  seed.wrapping_add(PRIME32_2), seed, seed.wrapping_sub(PRIME32_1)],
            buffer: [0; 16],
            buffered: 0,
            total: 0,
        }
    }

    fn stripe(acc: &mut [u32; 4], stripe: &[u8]) {
        for (i, lane) in acc.iter_mut().enumerate() {
            *lane = round32(*lane, read32(stripe, 4 * i));
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.total += input.len() as u64;
        if self.buffered > 0 {
            let take = (16 - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered < 16 {
                return;
            }
            let full = self.buffer;
            Xxh32::stripe(&mut self.acc, &full);
            self.buffered = 0;
        }
        let mut stripes = input.chunks_exact(16);
        for stripe in &mut stripes {
            Xxh32::stripe(&mut self.acc, stripe);
        }
        let rest = stripes.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    pub fn value(&self) -> u32 {
        let [a, b, c, d] = self.acc;
        let mut acc = if self.total >= 16 {
            a.rotate_left(1).wrapping_add(b.rotate_left(7)).wrapping_add(c.rotate_left(12))
                .wrapping_add(d.rotate_left(18))
        } else {
            self.seed.wrapping_add(PRIME32_5)
        };
        acc = acc.wrapping_add(self.total as u32);
        let rest = &self.buffer[..self.buffered];
        let mut words = rest.chunks_exact(4);
        for word in &mut words {
            acc = acc.wrapping_add(read32(word, 0).wrapping_mul(PRIME32_3)).rotate_left(17)
                .wrapping_mul(PRIME32_4);
        }
        for &byte in words.remainder() {
            acc = acc.wrapping_add(u32::from(byte).wrapping_mul(PRIME32_5)).rotate_left(11)
                .wrapping_mul(PRIME32_1);
        }
        acc ^= acc >> 15;
        acc = acc.wrapping_mul(PRIME32_2);
        acc ^= acc >> 13;
        acc = acc.wrapping_mul(PRIME32_3);
        acc ^ (acc >> 16)
    }
}

// ------------------------------------------------------------- XXH64 ---

fn round64(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(PRIME64_2)).rotate_left(31).wrapping_mul(PRIME64_1)
}

fn merge64(acc: u64, lane: u64) -> u64 {
    (acc ^ round64(0, lane)).wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4)
}

/// XXH64's final mix, which XXH3 uses too.
fn avalanche_xxh64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(PRIME64_2);
    x ^= x >> 29;
    x = x.wrapping_mul(PRIME64_3);
    x ^ (x >> 32)
}

/// XXH64 in progress.
#[derive(Clone)]
pub struct Xxh64 {
    seed: u64,
    acc: [u64; 4],
    buffer: [u8; 32],
    buffered: usize,
    total: u64,
}

impl Xxh64 {
    pub fn new(seed: u64) -> Xxh64 {
        Xxh64 {
            seed,
            acc: [seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2),
                  seed.wrapping_add(PRIME64_2), seed, seed.wrapping_sub(PRIME64_1)],
            buffer: [0; 32],
            buffered: 0,
            total: 0,
        }
    }

    fn stripe(acc: &mut [u64; 4], stripe: &[u8]) {
        for (i, lane) in acc.iter_mut().enumerate() {
            *lane = round64(*lane, read64(stripe, 8 * i));
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.total += input.len() as u64;
        if self.buffered > 0 {
            let take = (32 - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered < 32 {
                return;
            }
            let full = self.buffer;
            Xxh64::stripe(&mut self.acc, &full);
            self.buffered = 0;
        }
        let mut stripes = input.chunks_exact(32);
        for stripe in &mut stripes {
            Xxh64::stripe(&mut self.acc, stripe);
        }
        let rest = stripes.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    pub fn value(&self) -> u64 {
        let [a, b, c, d] = self.acc;
        let mut acc = if self.total >= 32 {
            let mut acc = a.rotate_left(1).wrapping_add(b.rotate_left(7))
                .wrapping_add(c.rotate_left(12)).wrapping_add(d.rotate_left(18));
            for lane in self.acc {
                acc = merge64(acc, lane);
            }
            acc
        } else {
            self.seed.wrapping_add(PRIME64_5)
        };
        acc = acc.wrapping_add(self.total);
        let mut rest = &self.buffer[..self.buffered];
        while rest.len() >= 8 {
            acc = (acc ^ round64(0, read64(rest, 0))).rotate_left(27).wrapping_mul(PRIME64_1)
                .wrapping_add(PRIME64_4);
            rest = &rest[8..];
        }
        if rest.len() >= 4 {
            acc = (acc ^ u64::from(read32(rest, 0)).wrapping_mul(PRIME64_1)).rotate_left(23)
                .wrapping_mul(PRIME64_2).wrapping_add(PRIME64_3);
            rest = &rest[4..];
        }
        for &byte in rest {
            acc = (acc ^ u64::from(byte).wrapping_mul(PRIME64_5)).rotate_left(11)
                .wrapping_mul(PRIME64_1);
        }
        avalanche_xxh64(acc)
    }
}

// -------------------------------------------------------------- XXH3 ---

/// The shortest secret XXH3 takes.
pub const XXH3_SECRET_MIN: usize = 136;

/// Inputs up to this long are hashed whole, without stripes.
const MIDSIZE_MAX: usize = 240;

fn avalanche(mut x: u64) -> u64 {
    x ^= x >> 37;
    x = x.wrapping_mul(PRIME_MX1);
    x ^ (x >> 32)
}

/// 16 bytes of input against 16 of the secret.
fn mix16(input: &[u8], secret: &[u8], at: usize, seed: u64) -> u64 {
    fold(read64(input, 0) ^ read64(secret, at).wrapping_add(seed),
         read64(input, 8) ^ read64(secret, at + 8).wrapping_sub(seed))
}

/// XXH3-128's pair of accumulators taking two 16 byte pieces.
fn mix32(acc: &mut [u64; 2], first: &[u8], second: &[u8], secret: &[u8], at: usize, seed: u64) {
    acc[0] = acc[0].wrapping_add(mix16(first, secret, at, seed));
    acc[1] = acc[1].wrapping_add(mix16(second, secret, at + 16, seed));
    acc[0] ^= read64(second, 0).wrapping_add(read64(second, 8));
    acc[1] ^= read64(first, 0).wrapping_add(read64(first, 8));
}

/// The secret a seed gives for long inputs: the default one, read as 24
/// words, with the seed added to the even ones and taken from the odd.
fn derived_secret(seed: u64) -> Vec<u8> {
    let mut secret = DEFAULT_SECRET.to_vec();
    for (i, word) in secret.chunks_exact_mut(8).enumerate() {
        let value = read64(word, 0);
        let value = if i % 2 == 0 { value.wrapping_add(seed) } else { value.wrapping_sub(seed) };
        word.copy_from_slice(&value.to_le_bytes());
    }
    secret
}

/// XXH3-64 of up to 240 bytes.
fn short_64(input: &[u8], secret: &[u8], seed: u64) -> u64 {
    let len = input.len();
    match len {
        0 => avalanche_xxh64(seed ^ read64(secret, 56) ^ read64(secret, 64)),
        1..=3 => {
            let combined = u32::from(input[len - 1]) | ((len as u32) << 8)
                | (u32::from(input[0]) << 16) | (u32::from(input[len >> 1]) << 24);
            let value = u64::from(read32(secret, 0) ^ read32(secret, 4)).wrapping_add(seed)
                ^ u64::from(combined);
            avalanche_xxh64(value)
        }
        4..=8 => {
            let first = read32(input, 0);
            let last = read32(input, len - 4);
            let seed = seed ^ (u64::from((seed as u32).swap_bytes()) << 32);
            let combined = u64::from(last) | (u64::from(first) << 32);
            let mut value = (read64(secret, 8) ^ read64(secret, 16)).wrapping_sub(seed) ^ combined;
            value ^= value.rotate_left(49) ^ value.rotate_left(24);
            value = value.wrapping_mul(PRIME_MX2);
            value ^= (value >> 35).wrapping_add(len as u64);
            value = value.wrapping_mul(PRIME_MX2);
            value ^ (value >> 28)
        }
        9..=16 => {
            let low = (read64(secret, 24) ^ read64(secret, 32)).wrapping_add(seed)
                ^ read64(input, 0);
            let high = (read64(secret, 40) ^ read64(secret, 48)).wrapping_sub(seed)
                ^ read64(input, len - 8);
            avalanche((len as u64).wrapping_add(low.swap_bytes()).wrapping_add(high)
                .wrapping_add(fold(low, high)))
        }
        17..=128 => {
            let mut acc = (len as u64).wrapping_mul(PRIME64_1);
            for i in (0..(len - 1) / 32 + 1).rev() {
                acc = acc.wrapping_add(mix16(&input[16 * i..], secret, 32 * i, seed));
                acc = acc.wrapping_add(mix16(&input[len - 16 * i - 16..], secret, 32 * i + 16,
                                             seed));
            }
            avalanche(acc)
        }
        _ => {
            let mut acc = (len as u64).wrapping_mul(PRIME64_1);
            for i in 0..8 {
                acc = acc.wrapping_add(mix16(&input[16 * i..], secret, 16 * i, seed));
            }
            acc = avalanche(acc);
            for i in 8..len / 16 {
                acc = acc.wrapping_add(mix16(&input[16 * i..], secret, 16 * (i - 8) + 3, seed));
            }
            acc = acc.wrapping_add(mix16(&input[len - 16..], secret, 119, seed));
            avalanche(acc)
        }
    }
}

/// XXH3-128 of up to 240 bytes, as (low, high).
fn short_128(input: &[u8], secret: &[u8], seed: u64) -> (u64, u64) {
    let len = input.len();
    match len {
        0 => (avalanche_xxh64(seed ^ read64(secret, 64) ^ read64(secret, 72)),
              avalanche_xxh64(seed ^ read64(secret, 80) ^ read64(secret, 88))),
        1..=3 => {
            let combined = u32::from(input[len - 1]) | ((len as u32) << 8)
                | (u32::from(input[0]) << 16) | (u32::from(input[len >> 1]) << 24);
            let low = u64::from(read32(secret, 0) ^ read32(secret, 4)).wrapping_add(seed)
                ^ u64::from(combined);
            let high = u64::from(read32(secret, 8) ^ read32(secret, 12)).wrapping_sub(seed)
                ^ u64::from(combined.swap_bytes().rotate_left(13));
            (avalanche_xxh64(low), avalanche_xxh64(high))
        }
        4..=8 => {
            let first = read32(input, 0);
            let last = read32(input, len - 4);
            let seed = seed ^ (u64::from((seed as u32).swap_bytes()) << 32);
            let combined = u64::from(first) | (u64::from(last) << 32);
            let value = (read64(secret, 16) ^ read64(secret, 24)).wrapping_add(seed) ^ combined;
            let (mut low, mut high) = multiply(value,
                                               PRIME64_1.wrapping_add((len as u64) << 2));
            high = high.wrapping_add(low << 1);
            low ^= high >> 3;
            low ^= low >> 35;
            low = low.wrapping_mul(PRIME_MX2);
            low ^= low >> 28;
            (low, avalanche(high))
        }
        9..=16 => {
            let first = read64(input, 0);
            let last = read64(input, len - 8);
            let one = (read64(secret, 32) ^ read64(secret, 40)).wrapping_sub(seed) ^ first ^ last;
            let two = (read64(secret, 48) ^ read64(secret, 56)).wrapping_add(seed) ^ last;
            let (mut low, mut high) = multiply(one, PRIME64_1);
            low = low.wrapping_add(((len as u64) - 1) << 54);
            high = high.wrapping_add(two & 0xffff_ffff_0000_0000)
                .wrapping_add((two & 0xffff_ffff).wrapping_mul(u64::from(PRIME32_2)));
            low ^= high.swap_bytes();
            let (product_low, product_high) = multiply(low, PRIME64_2);
            let high = product_high.wrapping_add(high.wrapping_mul(PRIME64_2));
            (avalanche(product_low), avalanche(high))
        }
        17..=128 => {
            let mut acc = [(len as u64).wrapping_mul(PRIME64_1), 0];
            for i in (0..(len - 1) / 32 + 1).rev() {
                mix32(&mut acc, &input[16 * i..], &input[len - 16 * i - 16..], secret, 32 * i,
                      seed);
            }
            finish_mid_128(acc, len, seed)
        }
        _ => {
            let mut acc = [(len as u64).wrapping_mul(PRIME64_1), 0];
            for i in 0..4 {
                mix32(&mut acc, &input[32 * i..], &input[32 * i + 16..], secret, 32 * i, seed);
            }
            acc = [avalanche(acc[0]), avalanche(acc[1])];
            for i in 4..len / 32 {
                mix32(&mut acc, &input[32 * i..], &input[32 * i + 16..], secret,
                      32 * (i - 4) + 3, seed);
            }
            // The last 32 bytes, halves swapped and the seed negated.
            mix32(&mut acc, &input[len - 16..], &input[len - 32..], secret, 103,
                  0u64.wrapping_sub(seed));
            finish_mid_128(acc, len, seed)
        }
    }
}

fn finish_mid_128(acc: [u64; 2], len: usize, seed: u64) -> (u64, u64) {
    let low = acc[0].wrapping_add(acc[1]);
    let high = acc[0].wrapping_mul(PRIME64_1).wrapping_add(acc[1].wrapping_mul(PRIME64_4))
        .wrapping_add((len as u64).wrapping_sub(seed).wrapping_mul(PRIME64_2));
    (avalanche(low), 0u64.wrapping_sub(avalanche(high)))
}

/// One 64 byte stripe against the secret at `at`.
fn accumulate(acc: &mut [u64; 8], stripe: &[u8], secret: &[u8], at: usize) {
    for i in 0..8 {
        let lane = read64(stripe, 8 * i);
        let value = lane ^ read64(secret, at + 8 * i);
        acc[i ^ 1] = acc[i ^ 1].wrapping_add(lane);
        acc[i] = acc[i].wrapping_add((value & 0xffff_ffff).wrapping_mul(value >> 32));
    }
}

fn scramble(acc: &mut [u64; 8], secret: &[u8]) {
    let at = secret.len() - 64;
    for (i, lane) in acc.iter_mut().enumerate() {
        *lane ^= *lane >> 47;
        *lane ^= read64(secret, at + 8 * i);
        *lane = lane.wrapping_mul(u64::from(PRIME32_1));
    }
}

fn merge(acc: &[u64; 8], secret: &[u8], at: usize, start: u64) -> u64 {
    let mut result = start;
    for i in 0..4 {
        result = result.wrapping_add(fold(acc[2 * i] ^ read64(secret, at + 16 * i),
                                          acc[2 * i + 1] ^ read64(secret, at + 16 * i + 8)));
    }
    avalanche(result)
}

/// XXH3 in progress, at 64 or 128 bits.
///
/// Up to one block of input is held back: a block is folded in only when
/// more input follows it, because the last one is treated differently,
/// and the last 64 bytes folded in are kept, because the final stripe can
/// reach back into them.
#[derive(Clone)]
pub struct Xxh3 {
    bits: usize,
    /// The seed for inputs of 240 bytes or fewer; zero with a secret.
    seed: u64,
    /// The secret for those inputs: the default one, or the one given.
    short_secret: Vec<u8>,
    /// The secret for longer ones: the given one, or derived from the seed.
    secret: Vec<u8>,
    acc: [u64; 8],
    buffer: Vec<u8>,
    tail: [u8; 64],
    total: u64,
}

impl Xxh3 {
    fn with(bits: usize, seed: u64, short_secret: Vec<u8>, secret: Vec<u8>) -> Xxh3 {
        Xxh3 {
            bits,
            seed,
            short_secret,
            secret,
            acc: [u64::from(PRIME32_3), PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4,
                  u64::from(PRIME32_2), PRIME64_5, u64::from(PRIME32_1)],
            buffer: Vec::new(),
            tail: [0; 64],
            total: 0,
        }
    }

    /// XXH3 at `bits`, 64 or 128, with `seed` (0 for the plain hash).
    ///
    /// # Errors
    /// Any other width.
    pub fn new(bits: usize, seed: u64) -> Result<Xxh3, String> {
        Xxh3::check_bits(bits)?;
        Ok(Xxh3::with(bits, seed, DEFAULT_SECRET.to_vec(), derived_secret(seed)))
    }

    /// XXH3 at `bits` with a secret of its own, at least 136 bytes.
    ///
    /// # Errors
    /// Another width, or a shorter secret.
    pub fn with_secret(bits: usize, secret: &[u8]) -> Result<Xxh3, String> {
        Xxh3::check_bits(bits)?;
        if secret.len() < XXH3_SECRET_MIN {
            return Err(format!("An XXH3 secret is at least {XXH3_SECRET_MIN} bytes, not {}.",
                               secret.len()));
        }
        Ok(Xxh3::with(bits, 0, secret.to_vec(), secret.to_vec()))
    }

    fn check_bits(bits: usize) -> Result<(), String> {
        if bits == 64 || bits == 128 {
            Ok(())
        } else {
            Err(format!("XXH3 is 64 or 128 bits, not {bits}."))
        }
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    fn block_len(&self) -> usize {
        64 * ((self.secret.len() - 64) / 8)
    }

    fn round(acc: &mut [u64; 8], block: &[u8], secret: &[u8]) {
        for (n, stripe) in block.chunks_exact(64).enumerate() {
            accumulate(acc, stripe, secret, 8 * n);
        }
        scramble(acc, secret);
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.total += input.len() as u64;
        let block = self.block_len();
        while !input.is_empty() {
            if self.buffer.len() == block {
                Xxh3::round(&mut self.acc, &self.buffer, &self.secret);
                self.tail.copy_from_slice(&self.buffer[block - 64..]);
                self.buffer.clear();
            }
            if self.buffer.is_empty() {
                while input.len() > block {
                    Xxh3::round(&mut self.acc, &input[..block], &self.secret);
                    self.tail.copy_from_slice(&input[block - 64..block]);
                    input = &input[block..];
                }
            }
            let take = (block - self.buffer.len()).min(input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
        }
    }

    /// The accumulators with the held back input folded in, for an input
    /// longer than 240 bytes.
    fn long_acc(&self) -> [u64; 8] {
        let mut acc = self.acc;
        let rest = &self.buffer;
        let len = rest.len();
        for n in 0..(len - 1) / 64 {
            accumulate(&mut acc, &rest[64 * n..], &self.secret, 8 * n);
        }
        let mut last = [0u8; 64];
        if len >= 64 {
            last.copy_from_slice(&rest[len - 64..]);
        } else {
            last[..64 - len].copy_from_slice(&self.tail[len..]);
            last[64 - len..].copy_from_slice(rest);
        }
        accumulate(&mut acc, &last, &self.secret, self.secret.len() - 71);
        acc
    }

    /// XXH3-64's value, or XXH3-128's low half.
    pub fn value_64(&self) -> u64 {
        if self.bits == 128 {
            return self.value_128() as u64;
        }
        if self.total <= MIDSIZE_MAX as u64 {
            return short_64(&self.buffer, &self.short_secret, self.seed);
        }
        merge(&self.long_acc(), &self.secret, 11, self.total.wrapping_mul(PRIME64_1))
    }

    /// XXH3-128's value, high half above; at 64 bits, XXH3-64's value.
    pub fn value_128(&self) -> u128 {
        if self.bits == 64 {
            return u128::from(self.value_64());
        }
        let (low, high) = if self.total <= MIDSIZE_MAX as u64 {
            short_128(&self.buffer, &self.short_secret, self.seed)
        } else {
            let acc = self.long_acc();
            (merge(&acc, &self.secret, 11, self.total.wrapping_mul(PRIME64_1)),
             merge(&acc, &self.secret, self.secret.len() - 64 - 11,
                   !self.total.wrapping_mul(PRIME64_2)))
        };
        (u128::from(high) << 64) | u128::from(low)
    }

    /// The value, big endian: 8 bytes or 16.
    pub fn value(&self) -> Vec<u8> {
        if self.bits == 64 {
            self.value_64().to_be_bytes().to_vec()
        } else {
            self.value_128().to_be_bytes().to_vec()
        }
    }
}

/// XXH32 of `data`.
pub fn xxh32(data: &[u8], seed: u32) -> u32 {
    let mut hash = Xxh32::new(seed);
    hash.update(data);
    hash.value()
}

/// XXH64 of `data`.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut hash = Xxh64::new(seed);
    hash.update(data);
    hash.value()
}

/// XXH3-64 of `data`.
pub fn xxh3_64(data: &[u8], seed: u64) -> u64 {
    if data.len() <= MIDSIZE_MAX {
        return short_64(data, &DEFAULT_SECRET, seed);
    }
    let mut hash = Xxh3::new(64, seed).expect("64 bits");
    hash.update(data);
    hash.value_64()
}

/// XXH3-128 of `data`, high half above.
pub fn xxh3_128(data: &[u8], seed: u64) -> u128 {
    let mut hash = Xxh3::new(128, seed).expect("128 bits");
    hash.update(data);
    hash.value_128()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_derived_secret_of_seed_zero_is_the_default() {
        assert_eq!(derived_secret(0), DEFAULT_SECRET.to_vec());
        let derived = derived_secret(1);
        assert_eq!(read64(&derived, 0), read64(&DEFAULT_SECRET, 0).wrapping_add(1));
        assert_eq!(read64(&derived, 8), read64(&DEFAULT_SECRET, 8).wrapping_sub(1));
    }

    #[test]
    fn test_a_short_secret_and_another_width_are_refused() {
        assert!(Xxh3::with_secret(64, &[0; XXH3_SECRET_MIN - 1]).is_err());
        assert!(Xxh3::with_secret(64, &[0; XXH3_SECRET_MIN]).is_ok());
        assert!(Xxh3::new(32, 0).is_err());
    }

    /// The default secret is 192 bytes, so a block is 16 stripes; a
    /// secret of 136 bytes makes it 9, the fewest.
    #[test]
    fn test_the_block_follows_the_secret() {
        assert_eq!(Xxh3::new(64, 0).unwrap().block_len(), 1024);
        assert_eq!(Xxh3::with_secret(64, &[7; 136]).unwrap().block_len(), 576);
    }
}
