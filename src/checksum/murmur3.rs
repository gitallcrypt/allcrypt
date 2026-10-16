//! MurmurHash3, Austin Appleby's: x86_32, x86_128 and x64_128.
//!
//! Fast hashes for hash tables, the one Guava, Cassandra's partitioner,
//! Kafka's and Elasticsearch's routing and many Bloom filters use. Not
//! for an adversary: collisions for any seed are easy to make, which is
//! what HashDoS against it was about. Written from the reference,
//! SMHasher's `MurmurHash3.cpp`.
//!
//! The three are different functions, not one at three widths: x86_32
//! and x86_128 work in 32 bit words, x64_128 in 64 bit ones, and the two
//! 128 bit ones give unrelated values. Each takes a 32 bit seed. The
//! input is read as little endian words; the value is given as PHP's
//! `hash` gives it, each word big endian, first word first. The
//! reference writes the words in the machine's order, so its bytes on a
//! little endian machine are each word reversed.

const C1_32: u32 = 0xcc9e_2d51;
const C2_32: u32 = 0x1b87_3593;

const C1_X86: u32 = 0x239b_961b;
const C2_X86: u32 = 0xab0e_9789;
const C3_X86: u32 = 0x38b3_4ae5;
const C4_X86: u32 = 0xa1e3_8b93;

const C1_X64: u64 = 0x87c3_7b91_1142_53d5;
const C2_X64: u64 = 0x4cf5_ad43_2745_937f;

fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^ (k >> 33)
}

/// A word mixed before it goes into the state: times one constant,
/// rotated, times another.
fn scramble32(k: u32, c: u32, r: u32, d: u32) -> u32 {
    k.wrapping_mul(c).rotate_left(r).wrapping_mul(d)
}

fn scramble64(k: u64, c: u64, r: u32, d: u64) -> u64 {
    k.wrapping_mul(c).rotate_left(r).wrapping_mul(d)
}

/// Bytes as a little endian number, the short last word included.
fn le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0, |acc, &b| (acc << 8) | u64::from(b))
}

/// Which MurmurHash3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Murmur3Variant {
    /// 32 bits, in 4 byte blocks: PHP's `murmur3a`.
    X86_32,
    /// 128 bits, in 16 byte blocks of four 32 bit words: PHP's `murmur3c`.
    X86_128,
    /// 128 bits, in 16 byte blocks of two 64 bit words: PHP's `murmur3f`.
    X64_128,
}

impl Murmur3Variant {
    fn block(self) -> usize {
        if self == Murmur3Variant::X86_32 { 4 } else { 16 }
    }
}

/// MurmurHash3 in progress.
#[derive(Clone)]
pub struct Murmur3 {
    variant: Murmur3Variant,
    /// x86's four words, or x64's two in the first two; x86_32 uses one.
    h: [u64; 4],
    buffer: [u8; 16],
    buffered: usize,
    total: u64,
}

impl Murmur3 {
    pub fn new(variant: Murmur3Variant, seed: u32) -> Murmur3 {
        let seed = u64::from(seed);
        Murmur3 { variant, h: [seed; 4], buffer: [0; 16], buffered: 0, total: 0 }
    }

    pub fn variant(&self) -> Murmur3Variant {
        self.variant
    }

    fn block(variant: Murmur3Variant, h: &mut [u64; 4], block: &[u8]) {
        match variant {
            Murmur3Variant::X86_32 => {
                let h1 = h[0] as u32 ^ scramble32(le(block) as u32, C1_32, 15, C2_32);
                h[0] = u64::from(h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64));
            }
            Murmur3Variant::X86_128 => {
                let k: Vec<u32> = block.chunks_exact(4).map(|w| le(w) as u32).collect();
                let mut s = h.map(|w| w as u32);
                s[0] ^= scramble32(k[0], C1_X86, 15, C2_X86);
                s[0] = s[0].rotate_left(19).wrapping_add(s[1]).wrapping_mul(5)
                    .wrapping_add(0x561c_cd1b);
                s[1] ^= scramble32(k[1], C2_X86, 16, C3_X86);
                s[1] = s[1].rotate_left(17).wrapping_add(s[2]).wrapping_mul(5)
                    .wrapping_add(0x0bca_a747);
                s[2] ^= scramble32(k[2], C3_X86, 17, C4_X86);
                s[2] = s[2].rotate_left(15).wrapping_add(s[3]).wrapping_mul(5)
                    .wrapping_add(0x96cd_1c35);
                s[3] ^= scramble32(k[3], C4_X86, 18, C1_X86);
                s[3] = s[3].rotate_left(13).wrapping_add(s[0]).wrapping_mul(5)
                    .wrapping_add(0x32ac_3b17);
                *h = s.map(u64::from);
            }
            Murmur3Variant::X64_128 => {
                let (k1, k2) = (le(&block[..8]), le(&block[8..]));
                h[0] ^= scramble64(k1, C1_X64, 31, C2_X64);
                h[0] = h[0].rotate_left(27).wrapping_add(h[1]).wrapping_mul(5)
                    .wrapping_add(0x52dc_e729);
                h[1] ^= scramble64(k2, C2_X64, 33, C1_X64);
                h[1] = h[1].rotate_left(31).wrapping_add(h[0]).wrapping_mul(5)
                    .wrapping_add(0x3849_5ab5);
            }
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.total += input.len() as u64;
        let size = self.variant.block();
        if self.buffered > 0 {
            let take = (size - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered < size {
                return;
            }
            let full = self.buffer;
            Murmur3::block(self.variant, &mut self.h, &full[..size]);
            self.buffered = 0;
        }
        let mut blocks = input.chunks_exact(size);
        for block in &mut blocks {
            Murmur3::block(self.variant, &mut self.h, block);
        }
        let rest = blocks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// The words, first word first.
    fn words(&self) -> Vec<u64> {
        let tail = &self.buffer[..self.buffered];
        match self.variant {
            Murmur3Variant::X86_32 => {
                let mut h1 = self.h[0] as u32;
                if !tail.is_empty() {
                    h1 ^= scramble32(le(tail) as u32, C1_32, 15, C2_32);
                }
                vec![u64::from(fmix32(h1 ^ self.total as u32))]
            }
            Murmur3Variant::X86_128 => {
                let mut s = self.h.map(|w| w as u32);
                let consts = [(C1_X86, 15, C2_X86), (C2_X86, 16, C3_X86), (C3_X86, 17, C4_X86),
                              (C4_X86, 18, C1_X86)];
                for (i, word) in tail.chunks(4).enumerate() {
                    let (c, r, d) = consts[i];
                    s[i] ^= scramble32(le(word) as u32, c, r, d);
                }
                let len = self.total as u32;
                for w in &mut s {
                    *w ^= len;
                }
                s[0] = s[0].wrapping_add(s[1]).wrapping_add(s[2]).wrapping_add(s[3]);
                for i in 1..4 {
                    s[i] = s[i].wrapping_add(s[0]);
                }
                s = s.map(fmix32);
                s[0] = s[0].wrapping_add(s[1]).wrapping_add(s[2]).wrapping_add(s[3]);
                for i in 1..4 {
                    s[i] = s[i].wrapping_add(s[0]);
                }
                s.iter().map(|&w| u64::from(w)).collect()
            }
            Murmur3Variant::X64_128 => {
                let (mut h1, mut h2) = (self.h[0], self.h[1]);
                if tail.len() > 8 {
                    h2 ^= scramble64(le(&tail[8..]), C2_X64, 33, C1_X64);
                }
                if !tail.is_empty() {
                    h1 ^= scramble64(le(&tail[..tail.len().min(8)]), C1_X64, 31, C2_X64);
                }
                h1 ^= self.total;
                h2 ^= self.total;
                h1 = h1.wrapping_add(h2);
                h2 = h2.wrapping_add(h1);
                h1 = fmix64(h1);
                h2 = fmix64(h2);
                h1 = h1.wrapping_add(h2);
                h2 = h2.wrapping_add(h1);
                vec![h1, h2]
            }
        }
    }

    /// The value, each word big endian, first word first: 4 bytes or 16.
    pub fn value(&self) -> Vec<u8> {
        let words = self.words();
        match self.variant {
            Murmur3Variant::X64_128 => words.iter().flat_map(|w| w.to_be_bytes()).collect(),
            _ => words.iter().flat_map(|&w| (w as u32).to_be_bytes()).collect(),
        }
    }

    /// The value as one number, the first word on top: the bytes of
    /// [`Murmur3::value`] read big endian. x86_32's fits in 32 bits.
    pub fn value_number(&self) -> u128 {
        self.value().iter().fold(0, |acc, &b| (acc << 8) | u128::from(b))
    }
}

/// MurmurHash3's x86_32 of `data`.
pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    let mut hash = Murmur3::new(Murmur3Variant::X86_32, seed);
    hash.update(data);
    hash.value_number() as u32
}

/// MurmurHash3's x86_128 of `data`, the first word on top.
pub fn murmur3_x86_128(data: &[u8], seed: u32) -> u128 {
    let mut hash = Murmur3::new(Murmur3Variant::X86_128, seed);
    hash.update(data);
    hash.value_number()
}

/// MurmurHash3's x64_128 of `data`, the first word on top.
pub fn murmur3_x64_128(data: &[u8], seed: u32) -> u128 {
    let mut hash = Murmur3::new(Murmur3Variant::X64_128, seed);
    hash.update(data);
    hash.value_number()
}
