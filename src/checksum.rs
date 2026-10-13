//! Checksums: CRC-32 (IEEE 802.3), CRC-32C (Castagnoli), Adler-32,
//! Fletcher's, and the FNV hashes.
//!
//! Checksums, not cryptographic functions: they are linear, and anybody
//! can make data with any value they like. CRC-32 is here because ciphers
//! in this library use it as part of their state (ZipCrypto's first and
//! third keys are CRC registers) and because the formats around them
//! check it - ZIP, Kerberos's `des-cbc-crc`, TrueCrypt's headers and
//! keyfile pool. CRC-32C is iSCSI's, SCTP's, ext4's and Btrfs's, and the
//! one the SSE 4.2 instruction computes.
//!
//! Both are reflected - the low bit of each byte first - with the
//! register starting at all ones and inverted at the end; they differ
//! only in the polynomial, 0xEDB88320 and 0x82F63B78 reversed. `crc32`
//! is the checksum every tool prints; `crc32_update` is the bare
//! register, with neither inversion, which is what ZipCrypto, RFC 3961's
//! modified CRC-32 and TrueCrypt's keyfile pool use.
//! `crc32(data) == !crc32_update(!0, data)`, and the same for CRC-32C.
//!
//! Adler-32 (RFC 1950, zlib's) is two sums modulo 65521, the largest
//! prime below 2^16: one of the bytes plus one, and one of the first
//! sum after each byte; the value is the second above the first.
//! `adler32_update` continues from an earlier value, as zlib's `adler32`
//! does, and starts from 1.
//!
//! Fletcher's checksums are Adler-32's shape over words: Fletcher-16 sums
//! bytes modulo 255, Fletcher-32 16 bit words modulo 65535 and
//! Fletcher-64 32 bit words modulo 2^32 - 1, both sums starting at zero,
//! the second above the first. The words are little endian and the last
//! is padded with zero bytes, as the usual C code reads them through a
//! `uint16_t` or `uint32_t` pointer on a little endian machine.
//!
//! FNV (Fowler, Noll and Vo; RFC 9923) multiplies by a prime and XORs in
//! each byte, at 32, 64, 128, 256, 512 or 1024 bits: FNV-1 multiplies
//! first, FNV-1a XORs first, and FNV-0, the original, is FNV-1 from zero.
//! FNV-1 and FNV-1a start from the offset basis, which is FNV-0 of
//! "chongo <Landon Curt Noll> /\../\" and is computed here; the primes
//! are 2^TOP + 2^8 + LOW, with TOP and LOW from `fnv_tables.rs`, which
//! `scripts/make_fnv_tables.py` finds by the rule that defines them.
//!
//! [`Checksum`] streams any of them by name, as `api::AnyHash` carries
//! it, with the value big endian, as PHP's `hash` and Go's `Sum` give it.

use crate::hash_functions::HashFunction;

mod fnv_tables;

/// The reflected CRC-32 table for a reversed polynomial.
const fn table(polynomial: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 { polynomial ^ (c >> 1) } else { c >> 1 };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = table(0xEDB8_8320);
static TABLE_C: [u32; 256] = table(0x82F6_3B78);

/// The register after one byte.
#[inline]
pub fn crc32_byte(register: u32, byte: u8) -> u32 {
    TABLE[((register ^ u32::from(byte)) & 0xff) as usize] ^ (register >> 8)
}

/// The register after `data`, with no inversion before or after.
pub fn crc32_update(mut register: u32, data: &[u8]) -> u32 {
    for &byte in data {
        register = crc32_byte(register, byte);
    }
    register
}

/// The CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0, data)
}

/// The CRC-32C register after `data`, with no inversion before or after.
pub fn crc32c_update(mut register: u32, data: &[u8]) -> u32 {
    for &byte in data {
        register = TABLE_C[((register ^ u32::from(byte)) & 0xff) as usize] ^ (register >> 8);
    }
    register
}

/// The CRC-32C of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    !crc32c_update(!0, data)
}

/// Adler-32's modulus: the largest prime below 2^16.
const ADLER_MODULUS: u32 = {
    let mut m = 65535;
    'candidates: loop {
        let mut d = 2;
        while d * d <= m {
            if m % d == 0 {
                m -= 1;
                continue 'candidates;
            }
            d += 1;
        }
        break m;
    }
};

/// How many bytes Adler-32's sums can take before they must be reduced:
/// the most for which the second sum, starting below the modulus with
/// the first below it too, cannot pass 2^32 - 1 on bytes of 255 (zlib's
/// NMAX).
const ADLER_RUN: usize = {
    let m = ADLER_MODULUS as u64;
    let mut n = 0u64;
    while 255 * (n + 1) * (n + 2) / 2 + (n + 2) * (m - 1) <= u32::MAX as u64 {
        n += 1;
    }
    n as usize
};

/// Adler-32 after `data`, continuing from `value` (1 to start).
pub fn adler32_update(value: u32, data: &[u8]) -> u32 {
    let (mut a, mut b) = (value & 0xffff, value >> 16);
    for run in data.chunks(ADLER_RUN) {
        for &byte in run {
            a += u32::from(byte);
            b += a;
        }
        a %= ADLER_MODULUS;
        b %= ADLER_MODULUS;
    }
    b << 16 | a
}

/// The Adler-32 of `data`.
pub fn adler32(data: &[u8]) -> u32 {
    adler32_update(1, data)
}

/// Fletcher's checksum in progress over words of `width` bytes.
#[derive(Clone)]
struct Fletcher {
    width: usize,
    sums: [u64; 2],
    /// The start of a word, not yet whole.
    pending: Vec<u8>,
}

impl Fletcher {
    fn new(width: usize) -> Fletcher {
        Fletcher { width, sums: [0, 0], pending: Vec::with_capacity(width) }
    }

    /// The modulus: a word of all ones.
    fn modulus(&self) -> u64 {
        (1 << (8 * self.width)) - 1
    }

    fn word(&mut self, word: &[u8]) {
        let value = word.iter().rev().fold(0u64, |acc, &byte| acc << 8 | u64::from(byte));
        let m = self.modulus();
        self.sums[0] = (self.sums[0] + value) % m;
        self.sums[1] = (self.sums[1] + self.sums[0]) % m;
    }

    fn update(&mut self, mut data: &[u8]) {
        if !self.pending.is_empty() {
            let take = (self.width - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.pending.len() < self.width {
                return;
            }
            let word = core::mem::take(&mut self.pending);
            self.word(&word);
        }
        let words = data.chunks_exact(self.width);
        self.pending.extend_from_slice(words.remainder());
        for word in words {
            self.word(word);
        }
    }

    /// The checksum so far, the last word padded with zeros.
    fn value(&self) -> u64 {
        let mut last = self.clone();
        if !last.pending.is_empty() {
            let mut word = core::mem::take(&mut last.pending);
            word.resize(self.width, 0);
            last.word(&word);
        }
        last.sums[1] << (8 * self.width) | last.sums[0]
    }
}

fn fletcher(width: usize, data: &[u8]) -> u64 {
    let mut f = Fletcher::new(width);
    f.update(data);
    f.value()
}

/// Fletcher-16 of `data`: bytes, modulo 255.
pub fn fletcher16(data: &[u8]) -> u16 {
    fletcher(1, data) as u16
}

/// Fletcher-32 of `data`: 16 bit little endian words, modulo 65535.
pub fn fletcher32(data: &[u8]) -> u32 {
    fletcher(2, data) as u32
}

/// Fletcher-64 of `data`: 32 bit little endian words, modulo 2^32 - 1.
pub fn fletcher64(data: &[u8]) -> u64 {
    fletcher(4, data)
}

/// Which FNV.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FnvVariant {
    /// The original: FNV-1 from zero.
    Fnv0,
    /// Multiply, then XOR.
    Fnv1,
    /// XOR, then multiply.
    Fnv1a,
}

/// An FNV hash in progress, at any of its six sizes.
#[derive(Clone)]
pub struct Fnv {
    variant: FnvVariant,
    bits: usize,
    top: u32,
    low: u8,
    /// Little endian 64 bit words; one at 32 bits, whose top half is
    /// never read, since multiplying carries only upward.
    hash: Vec<u64>,
}

impl Fnv {
    /// FNV of `variant` at `bits` bits: 32, 64, 128, 256, 512 or 1024.
    ///
    /// # Errors
    /// Any other size.
    pub fn new(variant: FnvVariant, bits: usize) -> Result<Fnv, String> {
        let &(_, top, low) = fnv_tables::PRIMES.iter().find(|p| p.0 == bits).ok_or_else(|| {
            format!("FNV comes in 32, 64, 128, 256, 512 and 1024 bits, not {bits}.")
        })?;
        let mut fnv = Fnv { variant: FnvVariant::Fnv0, bits, top, low,
                            hash: vec![0; bits.div_ceil(64)] };
        if variant != FnvVariant::Fnv0 {
            fnv.update(b"chongo <Landon Curt Noll> /\\../\\");
        }
        fnv.variant = variant;
        Ok(fnv)
    }

    /// The hash times the prime, modulo 2^bits: shifted by TOP, plus
    /// shifted by eight, plus times LOW.
    fn multiply(&mut self) {
        let n = self.hash.len();
        let mut sum = vec![0u64; n];
        let mut add = |term: &[u64]| {
            let mut carry = 0u128;
            for (s, &t) in sum.iter_mut().zip(term) {
                let total = u128::from(*s) + u128::from(t) + carry;
                *s = total as u64;
                carry = total >> 64;
            }
        };
        for shift in [self.top as usize, 8] {
            let (words, bits) = (shift / 64, shift % 64);
            let shifted: Vec<u64> = (0..n).map(|i| {
                let at = |j: usize| if j < words || j - words >= n { 0 } else { self.hash[j - words] };
                let high = at(i) << bits;
                let low = if bits == 0 || i == 0 { 0 } else { at(i - 1) >> (64 - bits) };
                high | low
            }).collect();
            add(&shifted);
        }
        let mut carry = 0u128;
        let times_low: Vec<u64> = self.hash.iter().map(|&w| {
            let product = u128::from(w) * u128::from(self.low) + carry;
            carry = product >> 64;
            product as u64
        }).collect();
        add(&times_low);
        self.hash = sum;
    }

    /// Takes more input.
    pub fn update(&mut self, input: &[u8]) {
        for &byte in input {
            if self.variant == FnvVariant::Fnv1a {
                self.hash[0] ^= u64::from(byte);
                self.multiply();
            } else {
                self.multiply();
                self.hash[0] ^= u64::from(byte);
            }
        }
    }

    /// The hash so far, big endian.
    pub fn value(&self) -> Vec<u8> {
        let bytes: Vec<u8> = self.hash.iter().rev().flat_map(|w| w.to_be_bytes()).collect();
        bytes[bytes.len() - self.bits / 8..].to_vec()
    }

    fn name(&self) -> String {
        let variant = match self.variant {
            FnvVariant::Fnv0 => "0",
            FnvVariant::Fnv1 => "1",
            FnvVariant::Fnv1a => "1a",
        };
        format!("fnv{variant}_{}", self.bits)
    }

    /// The FNV a name stands for, `fnvVARIANT_BITS` or one of PHP's
    /// `fnv132`, `fnv1a32`, `fnv164` and `fnv1a64`.
    fn from_name(name: &str) -> Option<Fnv> {
        let (variant, bits) = match name {
            "fnv132" => ("1", "32"),
            "fnv1a32" => ("1a", "32"),
            "fnv164" => ("1", "64"),
            "fnv1a64" => ("1a", "64"),
            other => {
                let rest = other.strip_prefix("fnv")?;
                rest.strip_prefix('_').unwrap_or(rest).split_once('_')?
            }
        };
        let variant = match variant {
            "0" => FnvVariant::Fnv0,
            "1" => FnvVariant::Fnv1,
            "1a" => FnvVariant::Fnv1a,
            _ => return None,
        };
        let bits: usize = bits.parse().ok().filter(|_| bits.bytes().all(|b| b.is_ascii_digit()))?;
        Fnv::new(variant, bits).ok()
    }
}

/// The checksums' names, as `api::AnyHash::new` takes them.
pub const NAMES: &[&str] = &[
    "crc32", "crc32c", "adler32", "fletcher16", "fletcher32", "fletcher64",
    "fnv0_32", "fnv0_64", "fnv0_128", "fnv0_256", "fnv0_512", "fnv0_1024",
    "fnv1_32", "fnv1_64", "fnv1_128", "fnv1_256", "fnv1_512", "fnv1_1024",
    "fnv1a_32", "fnv1a_64", "fnv1a_128", "fnv1a_256", "fnv1a_512", "fnv1a_1024",
];

#[derive(Clone)]
enum State {
    Crc32(u32),
    Crc32c(u32),
    Adler32(u32),
    Fletcher(Fletcher),
    Fnv(Fnv),
}

/// A checksum in progress, by name.
#[derive(Clone)]
pub struct Checksum {
    state: State,
}

impl Checksum {
    /// The checksum a name stands for, lowercase with underscores: one of
    /// [`NAMES`], or PHP's `crc32b` for CRC-32. `None` for any other.
    pub fn from_name(name: &str) -> Option<Checksum> {
        let state = match name {
            "crc32" | "crc32b" => State::Crc32(!0),
            "crc32c" => State::Crc32c(!0),
            "adler32" => State::Adler32(1),
            "fletcher16" => State::Fletcher(Fletcher::new(1)),
            "fletcher32" => State::Fletcher(Fletcher::new(2)),
            "fletcher64" => State::Fletcher(Fletcher::new(4)),
            other => State::Fnv(Fnv::from_name(other)?),
        };
        Some(Checksum { state })
    }

    /// The value so far.
    fn value(&self) -> Vec<u8> {
        match &self.state {
            State::Crc32(register) | State::Crc32c(register) => (!register).to_be_bytes().to_vec(),
            State::Adler32(value) => value.to_be_bytes().to_vec(),
            State::Fletcher(f) => f.value().to_be_bytes()[8 - 2 * f.width..].to_vec(),
            State::Fnv(f) => f.value(),
        }
    }
}

impl HashFunction for Checksum {
    fn name(&self) -> String {
        match &self.state {
            State::Crc32(_) => "crc32".to_string(),
            State::Crc32c(_) => "crc32c".to_string(),
            State::Adler32(_) => "adler32".to_string(),
            State::Fletcher(f) => format!("fletcher{}", 16 * f.width),
            State::Fnv(f) => f.name(),
        }
    }

    fn digest_len(&self) -> usize {
        match &self.state {
            State::Crc32(_) | State::Crc32c(_) | State::Adler32(_) => 4,
            State::Fletcher(f) => 2 * f.width,
            State::Fnv(f) => f.bits / 8,
        }
    }

    /// The value's length, as PHP's ext/hash records it.
    fn block_size(&self) -> usize {
        self.digest_len()
    }

    fn update(&mut self, input: &[u8]) {
        match &mut self.state {
            State::Crc32(register) => *register = crc32_update(*register, input),
            State::Crc32c(register) => *register = crc32c_update(*register, input),
            State::Adler32(value) => *value = adler32_update(*value, input),
            State::Fletcher(f) => f.update(input),
            State::Fnv(f) => f.update(input),
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        self.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_catalogue_check_values() {
        // The CRC catalogue's check value: CRC-32 of "123456789". The
        // others are in vectors/checksums.vec.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn test_the_register_continues_across_calls() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 167 + 13) as u8).collect();
        for split in [0, 1, 7, 150, 299, 300] {
            let (a, b) = data.split_at(split);
            assert_eq!(!crc32_update(crc32_update(!0, a), b), crc32(&data));
            assert_eq!(!crc32c_update(crc32c_update(!0, a), b), crc32c(&data));
            assert_eq!(adler32_update(adler32_update(1, a), b), adler32(&data));
        }
    }

    #[test]
    fn test_adler_takes_any_value_without_overflowing() {
        // Values above the modulus are not Adler-32 values, but zlib
        // takes them, and so does this, without an overflow.
        let ones = vec![0xffu8; 3 * ADLER_RUN + 1];
        for value in [0, 1, 0xfff0_fff0, u32::MAX] {
            let whole = adler32_update(value, &ones);
            assert_eq!(adler32_update(adler32_update(value, &ones[..7]), &ones[7..]), whole);
        }
    }
}
