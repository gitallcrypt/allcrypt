//! AES (FIPS 197) with 128, 192 and 256 bit keys, by two routes.
//!
//! - **One block at a time** (`block_encrypt`, `block_decrypt`): the
//!   classic 32-bit table implementation, one 1 KB table each way plus the
//!   S-boxes. Fast for a single block, and **not constant time**: every
//!   round indexes the tables with bytes of the state, so which cache
//!   lines are touched depends on the key and the data.
//! - **Many blocks at once** (`encrypt_blocks`, `decrypt_blocks`):
//!   bitsliced and fixsliced, in `aes_bitsliced`. No lookups and no
//!   branches on key or data; sixteen blocks per pass. A single block
//!   costs as much as four, which is why the table route is kept for the
//!   modes that can only ever offer one.
//!
//! The modes that have several independent blocks in hand - CTR, GCM,
//! XTS, ECB and CBC decryption - go through the second route. The chained
//! ones - CBC encryption, CFB, OFB, CMAC, CCM's CBC-MAC - cannot, and use
//! the first. `docs/pitfalls.md` lists which operations are constant time
//! and which are not.
//!
//! The key schedule is computed once for both routes, with `SubWord`
//! through the bitsliced S-box and the decryption keys' InvMixColumns in
//! branch-free arithmetic, so setting a key does not index a table with
//! key bytes either.
//!
//! All tables are computed at compile time from the field arithmetic
//! rather than typed.

use super::aes_bitsliced::{self, Keys};
use crate::block_ciphers::BlockCipher;

/// Multiplication in AES's field, GF(2^8) mod x^8 + x^4 + x^3 + x + 1.
/// Branches on its operands, so it is for building constant tables only.
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

/// The S-box at `x`: the field inverse (`x^254`, zero to zero), then the
/// affine map with constant 0x63.
const fn sbox_entry(x: u8) -> u8 {
    let mut inverse = 1u8;
    let mut power = x;
    let mut e = 254u32;
    while e != 0 {
        if e & 1 != 0 {
            inverse = gf_mul(inverse, power);
        }
        power = gf_mul(power, power);
        e >>= 1;
    }
    inverse ^ inverse.rotate_left(1) ^ inverse.rotate_left(2) ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4) ^ 0x63
}

pub(crate) const SBOX: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = sbox_entry(i as u8);
        i += 1;
    }
    table
};

pub(crate) const INV_SBOX: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        table[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// SubBytes and MixColumns for one byte in row 0: the column `(2s, s, s,
/// 3s)` as a little-endian word. Rows 1 to 3 are this rotated by 8, 16
/// and 24 bits.
const TE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        table[i] = u32::from_le_bytes([gf_mul(s, 2), s, s, gf_mul(s, 3)]);
        i += 1;
    }
    table
};

/// InvSubBytes and InvMixColumns: `(14s, 9s, 13s, 11s)` for `s` the
/// inverse S-box's entry.
const TD: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = INV_SBOX[i];
        table[i] = u32::from_le_bytes([gf_mul(s, 14), gf_mul(s, 9), gf_mul(s, 13),
                                       gf_mul(s, 11)]);
        i += 1;
    }
    table
};

/// Multiplication by x in GF(2^8), branch-free.
#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (0x1b & 0u8.wrapping_sub(x >> 7))
}

/// InvMixColumns on one column held as a little-endian word, by
/// arithmetic: the decryption round keys of the equivalent inverse cipher.
fn inv_mix_column(word: u32) -> u32 {
    let a = word.to_le_bytes();
    let mut out = [0u8; 4];
    for (r, o) in out.iter_mut().enumerate() {
        let [a0, a1, a2, a3] = [a[r], a[(r + 1) % 4], a[(r + 2) % 4], a[(r + 3) % 4]];
        let m = |x: u8, two: bool, four: bool, eight: bool| {
            let x2 = xtime(x);
            let x4 = xtime(x2);
            let x8 = xtime(x4);
            let mut v = 0u8;
            if two { v ^= x2; }
            if four { v ^= x4; }
            if eight { v ^= x8; }
            v
        };
        // 14 = 8+4+2, 11 = 8+2+1, 13 = 8+4+1, 9 = 8+1. The flags are the
        // fixed coefficients, not data.
        *o = m(a0, true, true, true) ^ m(a1, true, false, true) ^ a1
            ^ m(a2, false, true, true) ^ a2 ^ m(a3, false, false, true) ^ a3;
    }
    u32::from_le_bytes(out)
}

/// One FIPS 197 key, expanded for both routes.
struct Schedule {
    rounds: usize,
    /// Encryption round keys, little-endian words, `4 * (rounds + 1)` used.
    ek: [u32; 60],
    /// The equivalent inverse cipher's round keys, in encryption order.
    dk: [u32; 60],
    bitsliced: Keys,
    /// The same keys for AES-NI, present only when the `aes-ni` feature
    /// is on and the processor has the instructions. When it is here,
    /// both routes above are bypassed.
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    hardware: Option<super::aes_ni::Keys>,
}

/// Whether this build and this processor encrypt AES with AES-NI: the
/// `aes-ni` feature is on, the target is x86-64, and the CPU has AES-NI,
/// PCLMULQDQ and SSE2. When false, AES is the portable code described at
/// the top of this module.
pub fn hardware_aes() -> bool {
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    {
        super::aes_ni::available()
    }
    #[cfg(not(all(feature = "aes-ni", target_arch = "x86_64")))]
    {
        false
    }
}

pub struct AesCrypto {
    schedule: Box<Schedule>,
}

impl AesCrypto {
    pub fn new(key: &[u8]) -> Result<AesCrypto, String> {
        Ok(AesCrypto { schedule: Box::new(expand(key)?) })
    }

    /// Replace the key.
    pub fn setup_key(&mut self, key: &[u8]) -> Result<(), String> {
        *self.schedule = expand(key)?;
        Ok(())
    }

    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let schedule = &*self.schedule;
        let k = &schedule.ek;
        let rounds = schedule.rounds;
        let mut s = [0u32; 4];
        for (i, word) in s.iter_mut().enumerate() {
            *word = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap()) ^ k[i];
        }
        let column = |a: u32, b: u32, c: u32, d: u32| {
            TE[(a & 0xff) as usize]
                ^ TE[((b >> 8) & 0xff) as usize].rotate_left(8)
                ^ TE[((c >> 16) & 0xff) as usize].rotate_left(16)
                ^ TE[(d >> 24) as usize].rotate_left(24)
        };
        for r in 1..rounds {
            s = [column(s[0], s[1], s[2], s[3]) ^ k[4 * r],
                 column(s[1], s[2], s[3], s[0]) ^ k[4 * r + 1],
                 column(s[2], s[3], s[0], s[1]) ^ k[4 * r + 2],
                 column(s[3], s[0], s[1], s[2]) ^ k[4 * r + 3]];
        }
        let last = |a: u32, b: u32, c: u32, d: u32| {
            u32::from_le_bytes([SBOX[(a & 0xff) as usize], SBOX[((b >> 8) & 0xff) as usize],
                                SBOX[((c >> 16) & 0xff) as usize], SBOX[(d >> 24) as usize]])
        };
        let r = rounds;
        let out = [last(s[0], s[1], s[2], s[3]) ^ k[4 * r],
                   last(s[1], s[2], s[3], s[0]) ^ k[4 * r + 1],
                   last(s[2], s[3], s[0], s[1]) ^ k[4 * r + 2],
                   last(s[3], s[0], s[1], s[2]) ^ k[4 * r + 3]];
        let mut result = [0u8; 16];
        for (i, word) in out.iter().enumerate() {
            result[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        result
    }

    fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let schedule = &*self.schedule;
        let k = &schedule.dk;
        let rounds = schedule.rounds;
        let mut s = [0u32; 4];
        for (i, word) in s.iter_mut().enumerate() {
            *word = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap())
                ^ k[4 * rounds + i];
        }
        // InvShiftRows takes row r from the column r to the left.
        let column = |a: u32, b: u32, c: u32, d: u32| {
            TD[(a & 0xff) as usize]
                ^ TD[((b >> 8) & 0xff) as usize].rotate_left(8)
                ^ TD[((c >> 16) & 0xff) as usize].rotate_left(16)
                ^ TD[(d >> 24) as usize].rotate_left(24)
        };
        for r in (1..rounds).rev() {
            s = [column(s[0], s[3], s[2], s[1]) ^ k[4 * r],
                 column(s[1], s[0], s[3], s[2]) ^ k[4 * r + 1],
                 column(s[2], s[1], s[0], s[3]) ^ k[4 * r + 2],
                 column(s[3], s[2], s[1], s[0]) ^ k[4 * r + 3]];
        }
        let last = |a: u32, b: u32, c: u32, d: u32| {
            u32::from_le_bytes([INV_SBOX[(a & 0xff) as usize],
                                INV_SBOX[((b >> 8) & 0xff) as usize],
                                INV_SBOX[((c >> 16) & 0xff) as usize],
                                INV_SBOX[(d >> 24) as usize]])
        };
        let out = [last(s[0], s[3], s[2], s[1]) ^ k[0],
                   last(s[1], s[0], s[3], s[2]) ^ k[1],
                   last(s[2], s[1], s[0], s[3]) ^ k[2],
                   last(s[3], s[2], s[1], s[0]) ^ k[3]];
        let mut result = [0u8; 16];
        for (i, word) in out.iter().enumerate() {
            result[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        result
    }
}

fn expand(key: &[u8]) -> Result<Schedule, String> {
    let rounds = match key.len() {
        16 => 10,
        24 => 12,
        32 => 14,
        n => return Err(format!("Incorrect key length {n}. Must be 16, 24 or 32.")),
    };
    let nk = key.len() / 4;
    let total = 4 * (rounds + 1);
    let mut ek = [0u32; 60];
    for (i, word) in ek.iter_mut().enumerate().take(nk) {
        *word = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut rcon = 1u32;
    for i in nk..total {
        let mut t = ek[i - 1];
        if i % nk == 0 {
            t = aes_bitsliced::sub_word(t.rotate_right(8)) ^ rcon;
            rcon = u32::from(xtime(rcon as u8));
        } else if nk > 6 && i % nk == 4 {
            t = aes_bitsliced::sub_word(t);
        }
        ek[i] = ek[i - nk] ^ t;
    }
    let mut dk = ek;
    for word in dk.iter_mut().take(4 * rounds).skip(4) {
        *word = inv_mix_column(*word);
    }
    let bitsliced = Keys::new(&ek[..total], rounds);
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    let hardware = if super::aes_ni::available() {
        // SAFETY: `available()` has checked that this processor has
        // AES-NI and SSE2, which is all `keys` requires.
        Some(unsafe { super::aes_ni::keys(&ek, rounds) })
    } else {
        None
    };
    Ok(Schedule {
        rounds, ek, dk, bitsliced,
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        hardware,
    })
}

impl BlockCipher for AesCrypto {
    fn blocksize(&self) -> usize {
        16
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut block: [u8; 16] = input[..16].try_into().unwrap();
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(keys) = &self.schedule.hardware {
            // SAFETY: `hardware` is only set after `available()` checked
            // for AES-NI and SSE2.
            unsafe { super::aes_ni::encrypt_one(keys, &mut block) };
            result.extend_from_slice(&block);
            return;
        }
        block = self.encrypt_block(&block);
        result.extend_from_slice(&block);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut block: [u8; 16] = input[..16].try_into().unwrap();
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(keys) = &self.schedule.hardware {
            // SAFETY: as in `block_encrypt`.
            unsafe { super::aes_ni::decrypt_one(keys, &mut block) };
            result.extend_from_slice(&block);
            return;
        }
        block = self.decrypt_block(&block);
        result.extend_from_slice(&block);
    }

    fn encrypt_block_in_place(&mut self, block: &mut [u8], _scratch: &mut Vec<u8>)
                              -> Result<(), String> {
        let length = block.len();
        let block: &mut [u8; 16] = block.try_into()
            .map_err(|_| format!("An AES block is 16 bytes, not {length}."))?;
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(keys) = &self.schedule.hardware {
            // SAFETY: as in `block_encrypt`.
            unsafe { super::aes_ni::encrypt_one(keys, block) };
            return Ok(());
        }
        *block = self.encrypt_block(block);
        Ok(())
    }

    fn decrypt_block_in_place(&mut self, block: &mut [u8], _scratch: &mut Vec<u8>)
                              -> Result<(), String> {
        let length = block.len();
        let block: &mut [u8; 16] = block.try_into()
            .map_err(|_| format!("An AES block is 16 bytes, not {length}."))?;
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(keys) = &self.schedule.hardware {
            // SAFETY: as in `block_encrypt`.
            unsafe { super::aes_ni::decrypt_one(keys, block) };
            return Ok(());
        }
        *block = self.decrypt_block(block);
        Ok(())
    }

    fn ctr_xor(&mut self, counter: &mut [u8], data: &mut [u8], counter32: bool)
               -> Result<bool, String> {
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(keys) = &self.schedule.hardware {
            if !data.len().is_multiple_of(16) {
                return Err(format!("{} bytes is not a whole number of 16 byte blocks.",
                                   data.len()));
            }
            let counter: &mut [u8; 16] = counter.try_into()
                .map_err(|_| "An AES counter block is 16 bytes.".to_string())?;
            // SAFETY: as in `block_encrypt`.
            unsafe { super::aes_ni::ctr_xor(keys, counter, data, counter32) };
            return Ok(true);
        }
        let _ = (counter, data, counter32);
        Ok(false)
    }

    fn xts_blocks(&mut self, tweak: &mut [u8; 16], data: &mut [u8], encrypt: bool)
                  -> Result<bool, String> {
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(keys) = &self.schedule.hardware {
            if !data.len().is_multiple_of(16) {
                return Err(format!("{} bytes is not a whole number of 16 byte blocks.",
                                   data.len()));
            }
            // SAFETY: as in `block_encrypt`.
            unsafe {
                if encrypt {
                    super::aes_ni::xts_encrypt(keys, tweak, data);
                } else {
                    super::aes_ni::xts_decrypt(keys, tweak, data);
                }
            }
            return Ok(true);
        }
        let _ = (tweak, data, encrypt);
        Ok(false)
    }

    fn encrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
        if !blocks.len().is_multiple_of(16) {
            return Err(format!("{} bytes is not a whole number of 16 byte blocks.",
                               blocks.len()));
        }
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(keys) = &self.schedule.hardware {
            // SAFETY: as in `block_encrypt`.
            unsafe { super::aes_ni::encrypt(keys, blocks) };
            return Ok(());
        }
        self.schedule.bitsliced.encrypt(blocks);
        Ok(())
    }

    fn decrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
        if !blocks.len().is_multiple_of(16) {
            return Err(format!("{} bytes is not a whole number of 16 byte blocks.",
                               blocks.len()));
        }
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(keys) = &self.schedule.hardware {
            // SAFETY: as in `block_encrypt`.
            unsafe { super::aes_ni::decrypt(keys, blocks) };
            return Ok(());
        }
        self.schedule.bitsliced.decrypt(blocks);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ctr_xor`, AES's one-pass counter mode, against counter blocks made
    /// one at a time, encrypted with `encrypt_blocks` and XORed in: both
    /// counters, from values where they wrap - the last four bytes for
    /// GCM's, the low and then all sixteen for the whole-block one - at
    /// every block count to past two groups of eight. Without the
    /// hardware `ctr_xor` declines, and the test says so.
    #[test]
    fn test_one_pass_counter_mode_agrees_with_three_passes() {
        let mut aes = AesCrypto::new(&(0..16).collect::<Vec<u8>>()).unwrap();
        let data: Vec<u8> = (0..20 * 16).map(|i| (i * 13 + 5) as u8).collect();
        let starts: [[u8; 16]; 4] = [
            [0xAA; 16],
            *b"twelve bytes\xff\xff\xff\xfd",
            *b"\x00\x00\x00\x00\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xfe",
            [0xFF; 16],
        ];
        for counter32 in [true, false] {
            for start in starts {
                for blocks in 0..=20 {
                    let mut counter = start;
                    let mut ours = data[..16 * blocks].to_vec();
                    if !aes.ctr_xor(&mut counter, &mut ours, counter32).unwrap() {
                        eprintln!("skipped: no one-pass counter mode in this build");
                        return;
                    }
                    let mut expected = vec![0u8; 16 * blocks];
                    let mut value = u128::from_be_bytes(start);
                    for block in expected.chunks_exact_mut(16) {
                        block.copy_from_slice(&value.to_be_bytes());
                        value = if counter32 {
                            (value & !0xFFFF_FFFF) | u128::from((value as u32).wrapping_add(1))
                        } else {
                            value.wrapping_add(1)
                        };
                    }
                    aes.encrypt_blocks(&mut expected).unwrap();
                    for (byte, plain) in expected.iter_mut().zip(&data) {
                        *byte ^= plain;
                    }
                    assert_eq!(ours, expected, "counter32 {counter32}, {blocks} blocks");
                    assert_eq!(counter, value.to_be_bytes(), "the counter left behind");
                }
            }
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The tables against their definition's best-known entries, and the
    /// two S-boxes against each other.
    #[test]
    fn test_tables() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7c);
        assert_eq!(SBOX[0x53], 0xed);
        assert_eq!(INV_SBOX[0x63], 0x00);
        assert_eq!(TE[0], 0xa56363c6);
        assert_eq!(TD[0], 0x50a7f451);
        for i in 0..256 {
            assert_eq!(INV_SBOX[SBOX[i] as usize] as usize, i);
        }
    }

    /// `inv_mix_column` undoes MixColumns, computed from the forward table.
    #[test]
    fn test_inv_mix_column() {
        let column = 0xdb13_5345u32.swap_bytes();
        // FIPS 197's worked MixColumns column: db 13 53 45 -> 8e 4d a1 bc.
        let mixed = u32::from_le_bytes([0x8e, 0x4d, 0xa1, 0xbc]);
        assert_eq!(inv_mix_column(mixed), column);
    }

    /// FIPS 197 Appendix C, through both routes, all three key sizes.
    #[test]
    fn test_fips_197_appendix_c() {
        let plaintext = unhex("00112233445566778899aabbccddeeff");
        for (key, ciphertext) in [
            ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617",
             "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            let mut aes = AesCrypto::new(&unhex(key)).unwrap();
            let mut out = Vec::new();
            aes.block_encrypt(&plaintext, &mut out);
            assert_eq!(out, unhex(ciphertext), "table encrypt, key {key}");
            let mut back = Vec::new();
            aes.block_decrypt(&out, &mut back);
            assert_eq!(back, plaintext, "table decrypt, key {key}");

            let mut batch = plaintext.clone();
            aes.encrypt_blocks(&mut batch).unwrap();
            assert_eq!(batch, unhex(ciphertext), "bitsliced encrypt, key {key}");
            aes.decrypt_blocks(&mut batch).unwrap();
            assert_eq!(batch, plaintext, "bitsliced decrypt, key {key}");
        }
    }

    /// The two routes are independent implementations; they must agree on
    /// every block of every batch length, which also exercises the
    /// sixteen-block path, the four-block path and the padded tail.
    #[test]
    fn test_the_routes_agree() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for key_len in [16, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|_| next()).collect();
            let mut aes = AesCrypto::new(&key).unwrap();
            for blocks in [1, 2, 3, 4, 5, 15, 16, 17, 20, 33, 64] {
                let data: Vec<u8> = (0..16 * blocks).map(|_| next()).collect();
                let mut want = Vec::new();
                for block in data.chunks(16) {
                    aes.block_encrypt(block, &mut want);
                }
                let mut got = data.clone();
                aes.encrypt_blocks(&mut got).unwrap();
                assert_eq!(got, want, "encrypt, key {key_len}, {blocks} blocks");

                let mut want_back = Vec::new();
                for block in got.chunks(16) {
                    aes.block_decrypt(block, &mut want_back);
                }
                assert_eq!(want_back, data);
                aes.decrypt_blocks(&mut got).unwrap();
                assert_eq!(got, data, "decrypt, key {key_len}, {blocks} blocks");
            }
        }
    }

    /// With the `aes-ni` feature on a processor that has it: the hardware
    /// route against the bitsliced and the table routes, every key size,
    /// lengths across the eight-block batches.
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    #[test]
    fn test_the_hardware_route_is_the_software_routes() {
        if !hardware_aes() {
            eprintln!("no AES-NI on this processor; nothing to compare");
            return;
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for key_len in [16, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|_| next()).collect();
            let mut aes = AesCrypto::new(key).unwrap();
            assert!(aes.schedule.hardware.is_some());
            for blocks in [1, 7, 8, 9, 16, 17, 33] {
                let data: Vec<u8> = (0..16 * blocks).map(|_| next()).collect();
                let mut table = Vec::new();
                for block in data.chunks(16) {
                    table.extend_from_slice(&aes.encrypt_block(block.try_into().unwrap()));
                }
                let mut bitsliced = data.clone();
                aes.schedule.bitsliced.encrypt(&mut bitsliced);
                assert_eq!(bitsliced, table);
                let mut hardware = data.clone();
                aes.encrypt_blocks(&mut hardware).unwrap();
                assert_eq!(hardware, table, "encrypt, key {key_len}, {blocks} blocks");
                let mut one = Vec::new();
                aes.block_encrypt(&data[..16], &mut one);
                assert_eq!(one, table[..16]);
                aes.decrypt_blocks(&mut hardware).unwrap();
                assert_eq!(hardware, data, "decrypt, key {key_len}, {blocks} blocks");
                let mut back = Vec::new();
                aes.block_decrypt(&table[..16], &mut back);
                assert_eq!(back, data[..16]);
            }
        }
    }

    #[test]
    fn test_bad_lengths_are_refused() {
        assert!(AesCrypto::new(&[0; 15]).is_err());
        assert!(AesCrypto::new(&[0; 20]).is_err());
        let mut aes = AesCrypto::new(&[0; 16]).unwrap();
        assert!(aes.encrypt_blocks(&mut [0u8; 17]).is_err());
        assert!(aes.decrypt_blocks(&mut [0u8; 8]).is_err());
        assert!(aes.encrypt_blocks(&mut []).is_ok());
    }
}
