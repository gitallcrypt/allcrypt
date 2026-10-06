//! BitLocker's sector encryption: the six methods a volume's metadata
//! names, each a function of the volume key and the sector's position.
//!
//! - **AES-CBC with the Elephant diffuser** (0x8000 with a 128-bit key,
//!   0x8001 with 256; Windows Vista and 7). Niels Ferguson, "AES-CBC +
//!   Elephant diffuser: A Disk Encryption Algorithm for Windows Vista",
//!   Microsoft, August 2006. The sector is XORed with a sector key,
//!   mixed by two diffusers, then AES-CBC encrypted. The volume key is
//!   two keys: one for CBC, one (the "tweak" key) for the sector key.
//! - **AES-CBC** (0x8002, 0x8003; Windows 8 and later, before XTS):
//!   the same without the sector key and the diffusers.
//! - **AES-XTS** (0x8004, 0x8005; Windows 10 1511 and later), with the
//!   sector number as the tweak.
//!
//! Both CBC methods take their IV from the sector's **byte offset**:
//! AES under the CBC key of the offset as a 64-bit little-endian number,
//! zero-padded to a block (dm-crypt calls this `eboiv`). XTS numbers
//! sectors in units of the sector size, 512 or 4096 bytes.
//!
//! The sector key is two AES encryptions under the tweak key: of the
//! offset block, and of the same block with its last byte 0x80. The 32
//! bytes are XORed into every 32 bytes of the sector.
//!
//! The diffusers work on the sector as 32-bit little-endian words.
//! Diffuser A runs five cycles of `d[i] += d[i-2] ^ rotl(d[i-5], Ra[i %
//! 4])`, Ra = (9, 0, 13, 0); diffuser B three of `d[i] += d[i+2] ^
//! rotl(d[i+5], Rb[i % 4])`, Rb = (0, 10, 0, 25), indices modulo the
//! word count. That direction is decryption, as Linux's dm-crypt names
//! it; encryption runs each from the last word down with subtraction.
//! Writing applies A then B before CBC; reading undoes CBC, then B,
//! then A.
//!
//! The diffuser has no key and is not a cipher. What it adds is that a
//! change to one ciphertext bit changes the whole decrypted sector, not
//! just two blocks of it, which CBC alone would allow an attacker to
//! steer.

use crate::block_ciphers::aes::AesCrypto;
use crate::block_ciphers::{xts, BlockCipher};

const RA: [u32; 4] = [9, 0, 13, 0];
const RB: [u32; 4] = [0, 10, 0, 25];

/// The encryption methods, by the code in the FVE metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    AesCbcElephant128,
    AesCbcElephant256,
    AesCbc128,
    AesCbc256,
    AesXts128,
    AesXts256,
}

impl Method {
    pub fn from_code(code: u16) -> Result<Method, String> {
        Ok(match code {
            0x8000 => Method::AesCbcElephant128,
            0x8001 => Method::AesCbcElephant256,
            0x8002 => Method::AesCbc128,
            0x8003 => Method::AesCbc256,
            0x8004 => Method::AesXts128,
            0x8005 => Method::AesXts256,
            other => return Err(format!("BitLocker encryption method {other:#06x} is not one of \
                                         0x8000 to 0x8005.")),
        })
    }

    pub fn code(self) -> u16 {
        match self {
            Method::AesCbcElephant128 => 0x8000,
            Method::AesCbcElephant256 => 0x8001,
            Method::AesCbc128 => 0x8002,
            Method::AesCbc256 => 0x8003,
            Method::AesXts128 => 0x8004,
            Method::AesXts256 => 0x8005,
        }
    }

    /// By a short name: `aes-cbc-elephant-128`, `aes-cbc-256`,
    /// `aes-xts-128` and so on.
    pub fn from_name(name: &str) -> Result<Method, String> {
        Ok(match name {
            "aes-cbc-elephant-128" => Method::AesCbcElephant128,
            "aes-cbc-elephant-256" => Method::AesCbcElephant256,
            "aes-cbc-128" => Method::AesCbc128,
            "aes-cbc-256" => Method::AesCbc256,
            "aes-xts-128" => Method::AesXts128,
            "aes-xts-256" => Method::AesXts256,
            other => return Err(format!("Unknown BitLocker method {other:?}: aes-cbc-elephant-128, \
                                         aes-cbc-elephant-256, aes-cbc-128, aes-cbc-256, \
                                         aes-xts-128 or aes-xts-256.")),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Method::AesCbcElephant128 => "AES-CBC 128 with Elephant diffuser",
            Method::AesCbcElephant256 => "AES-CBC 256 with Elephant diffuser",
            Method::AesCbc128 => "AES-CBC 128",
            Method::AesCbc256 => "AES-CBC 256",
            Method::AesXts128 => "AES-XTS 128",
            Method::AesXts256 => "AES-XTS 256",
        }
    }

    /// Bytes of volume key: the CBC key and the tweak key together for
    /// Elephant, XTS's two keys together for XTS.
    pub fn key_len(self) -> usize {
        match self {
            Method::AesCbc128 => 16,
            Method::AesCbc256 | Method::AesCbcElephant128 | Method::AesXts128 => 32,
            Method::AesCbcElephant256 | Method::AesXts256 => 64,
        }
    }
}

/// The diffusers' decryption direction, on 32-bit words.
pub fn diffuser_a_decrypt(d: &mut [u32]) {
    let n = d.len();
    for _ in 0..5 {
        for i in 0..n {
            let mix = d[(i + n - 2) % n] ^ d[(i + n - 5) % n].rotate_left(RA[i % 4]);
            d[i] = d[i].wrapping_add(mix);
        }
    }
}

/// The inverse of `diffuser_a_decrypt`.
pub fn diffuser_a_encrypt(d: &mut [u32]) {
    let n = d.len();
    for _ in 0..5 {
        for i in (0..n).rev() {
            let mix = d[(i + n - 2) % n] ^ d[(i + n - 5) % n].rotate_left(RA[i % 4]);
            d[i] = d[i].wrapping_sub(mix);
        }
    }
}

pub fn diffuser_b_decrypt(d: &mut [u32]) {
    let n = d.len();
    for _ in 0..3 {
        for i in 0..n {
            let mix = d[(i + 2) % n] ^ d[(i + 5) % n].rotate_left(RB[i % 4]);
            d[i] = d[i].wrapping_add(mix);
        }
    }
}

/// The inverse of `diffuser_b_decrypt`.
pub fn diffuser_b_encrypt(d: &mut [u32]) {
    let n = d.len();
    for _ in 0..3 {
        for i in (0..n).rev() {
            let mix = d[(i + 2) % n] ^ d[(i + 5) % n].rotate_left(RB[i % 4]);
            d[i] = d[i].wrapping_sub(mix);
        }
    }
}

fn words(sector: &[u8]) -> Vec<u32> {
    sector.chunks(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect()
}

fn unwords(words: &[u32], sector: &mut [u8]) {
    for (out, w) in sector.chunks_mut(4).zip(words) {
        out.copy_from_slice(&w.to_le_bytes());
    }
}

/// The byte offset as an AES block: 64 bits little endian, then zeros.
fn offset_block(byte_offset: u64) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&byte_offset.to_le_bytes());
    block
}

/// A volume key, ready to encrypt and decrypt sectors.
pub struct SectorCipher {
    method: Method,
    data: AesCrypto,
    /// Elephant's tweak key, or XTS's tweak key.
    tweak: Option<AesCrypto>,
}

impl SectorCipher {
    /// `key` is the volume key as dm-crypt takes it: for Elephant, the
    /// CBC key followed by the tweak key, each 16 or 32 bytes.
    pub fn new(method: Method, key: &[u8]) -> Result<SectorCipher, String> {
        if key.len() != method.key_len() {
            return Err(format!("{} takes a {}-byte volume key, not {}.", method.name(),
                               method.key_len(), key.len()));
        }
        let (data, tweak) = match method {
            Method::AesCbc128 | Method::AesCbc256 => (key, None),
            _ => {
                let (data, tweak) = key.split_at(key.len() / 2);
                (data, Some(AesCrypto::new(tweak.to_vec())?))
            }
        };
        Ok(SectorCipher { method, data: AesCrypto::new(data.to_vec())?, tweak })
    }

    pub fn method(&self) -> Method {
        self.method
    }

    fn eboiv(&mut self, byte_offset: u64) -> Vec<u8> {
        let mut iv = Vec::with_capacity(16);
        self.data.block_encrypt(&offset_block(byte_offset), &mut iv);
        iv
    }

    /// Elephant's 32-byte sector key, XORed into every 32 bytes.
    fn xor_sector_key(&mut self, byte_offset: u64, sector: &mut [u8]) {
        let tweak = self.tweak.as_mut().expect("Elephant has a tweak key");
        let mut block = offset_block(byte_offset);
        let mut key = Vec::with_capacity(32);
        tweak.block_encrypt(&block, &mut key);
        block[15] = 0x80;
        tweak.block_encrypt(&block, &mut key);
        for chunk in sector.chunks_mut(32) {
            chunk.iter_mut().zip(&key).for_each(|(a, b)| *a ^= b);
        }
    }

    fn check(sector: &[u8]) -> Result<(), String> {
        if sector.len() < 32 || !sector.len().is_multiple_of(32) {
            return Err(format!("A BitLocker sector is a multiple of 32 bytes (512 or 4096), \
                                not {}.", sector.len()));
        }
        Ok(())
    }

    /// Encrypt one sector in place. `byte_offset` is the sector's offset
    /// on the volume; the sector size is the length of `sector`.
    pub fn encrypt_sector(&mut self, byte_offset: u64, sector: &mut [u8]) -> Result<(), String> {
        Self::check(sector)?;
        match self.method {
            Method::AesXts128 | Method::AesXts256 => {
                let tweak = xts::sector_tweak(u128::from(byte_offset / sector.len() as u64));
                let out = xts::encrypt(&mut self.data, self.tweak.as_mut().unwrap(), &tweak,
                                       sector)?;
                sector.copy_from_slice(&out);
                return Ok(());
            }
            Method::AesCbcElephant128 | Method::AesCbcElephant256 => {
                self.xor_sector_key(byte_offset, sector);
                let mut d = words(sector);
                diffuser_a_encrypt(&mut d);
                diffuser_b_encrypt(&mut d);
                unwords(&d, sector);
            }
            Method::AesCbc128 | Method::AesCbc256 => {}
        }
        let iv = self.eboiv(byte_offset);
        let mut out = Vec::with_capacity(sector.len());
        self.data.cbc_encrypt(sector, &mut out, iv)?;
        sector.copy_from_slice(&out);
        Ok(())
    }

    /// Decrypt one sector in place.
    pub fn decrypt_sector(&mut self, byte_offset: u64, sector: &mut [u8]) -> Result<(), String> {
        Self::check(sector)?;
        if let Method::AesXts128 | Method::AesXts256 = self.method {
            let tweak = xts::sector_tweak(u128::from(byte_offset / sector.len() as u64));
            let out = xts::decrypt(&mut self.data, self.tweak.as_mut().unwrap(), &tweak, sector)?;
            sector.copy_from_slice(&out);
            return Ok(());
        }
        let iv = self.eboiv(byte_offset);
        let mut out = Vec::with_capacity(sector.len());
        self.data.cbc_decrypt(sector, &mut out, iv)?;
        sector.copy_from_slice(&out);
        if let Method::AesCbcElephant128 | Method::AesCbcElephant256 = self.method {
            let mut d = words(sector);
            diffuser_b_decrypt(&mut d);
            diffuser_a_decrypt(&mut d);
            unwords(&d, sector);
            self.xor_sector_key(byte_offset, sector);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    #[test]
    fn test_the_diffusers_invert() {
        for n in [8usize, 128, 1024] {
            let original: Vec<u32> = (0..n as u32).map(|i| i.wrapping_mul(0x9e37_79b9)).collect();
            let mut d = original.clone();
            diffuser_a_encrypt(&mut d);
            assert_ne!(d, original);
            diffuser_a_decrypt(&mut d);
            assert_eq!(d, original);
            diffuser_b_encrypt(&mut d);
            assert_ne!(d, original);
            diffuser_b_decrypt(&mut d);
            assert_eq!(d, original);
        }
    }

    /// The point of the diffuser: one changed bit anywhere in a sector
    /// changes every word of the decryption. A, then B, as reading runs
    /// them in reverse.
    #[test]
    fn test_one_bit_reaches_every_word() {
        for at in [0usize, 1, 63, 64, 127] {
            let mut a = vec![0u32; 128];
            let mut b = a.clone();
            b[at] ^= 1;
            for d in [&mut a, &mut b] {
                diffuser_b_decrypt(d);
                diffuser_a_decrypt(d);
            }
            assert!(a.iter().zip(&b).all(|(x, y)| x != y), "bit in word {at}");
        }
    }

    /// Linux's dm-crypt (`drivers/md/dm-crypt.c`) writes the diffusers
    /// as four statements per loop turn, three running indices and the
    /// wrap-around tested only where each index can wrap. That is a
    /// different shape from the modular indexing above, so it is written
    /// out here in that shape, for decryption and encryption, and both
    /// must agree on every word count dm-crypt uses.
    fn kernel_a_decrypt(d: &mut [u32]) {
        let n = d.len() as isize;
        let rotl = |x: u32, r: u32| x.rotate_left(r);
        for _ in 0..5 {
            let (mut i1, mut i2, mut i3) = (0isize, n - 2, n - 5);
            while i1 < n - 1 {
                d[i1 as usize] = d[i1 as usize].wrapping_add(d[i2 as usize] ^ rotl(d[i3 as usize], 9));
                i1 += 1; i2 += 1; i3 += 1;
                if i3 >= n { i3 -= n; }
                d[i1 as usize] = d[i1 as usize].wrapping_add(d[i2 as usize] ^ d[i3 as usize]);
                i1 += 1; i2 += 1; i3 += 1;
                if i2 >= n { i2 -= n; }
                d[i1 as usize] = d[i1 as usize].wrapping_add(d[i2 as usize] ^ rotl(d[i3 as usize], 13));
                i1 += 1; i2 += 1; i3 += 1;
                d[i1 as usize] = d[i1 as usize].wrapping_add(d[i2 as usize] ^ d[i3 as usize]);
                i1 += 1; i2 += 1; i3 += 1;
            }
        }
    }

    fn kernel_a_encrypt(d: &mut [u32]) {
        let n = d.len() as isize;
        let rotl = |x: u32, r: u32| x.rotate_left(r);
        for _ in 0..5 {
            let (mut i1, mut i2, mut i3) = (n - 1, n - 3, n - 6);
            while i1 > 0 {
                d[i1 as usize] = d[i1 as usize].wrapping_sub(d[i2 as usize] ^ d[i3 as usize]);
                i1 -= 1; i2 -= 1; i3 -= 1;
                d[i1 as usize] = d[i1 as usize].wrapping_sub(d[i2 as usize] ^ rotl(d[i3 as usize], 13));
                i1 -= 1; i2 -= 1; i3 -= 1;
                if i2 < 0 { i2 += n; }
                d[i1 as usize] = d[i1 as usize].wrapping_sub(d[i2 as usize] ^ d[i3 as usize]);
                i1 -= 1; i2 -= 1; i3 -= 1;
                if i3 < 0 { i3 += n; }
                d[i1 as usize] = d[i1 as usize].wrapping_sub(d[i2 as usize] ^ rotl(d[i3 as usize], 9));
                i1 -= 1; i2 -= 1; i3 -= 1;
            }
        }
    }

    fn kernel_b_decrypt(d: &mut [u32]) {
        let n = d.len() as isize;
        let rotl = |x: u32, r: u32| x.rotate_left(r);
        for _ in 0..3 {
            let (mut i1, mut i2, mut i3) = (0isize, 2isize, 5isize);
            while i1 < n - 1 {
                d[i1 as usize] = d[i1 as usize].wrapping_add(d[i2 as usize] ^ d[i3 as usize]);
                i1 += 1; i2 += 1; i3 += 1;
                d[i1 as usize] = d[i1 as usize].wrapping_add(d[i2 as usize] ^ rotl(d[i3 as usize], 10));
                i1 += 1; i2 += 1; i3 += 1;
                if i2 >= n { i2 -= n; }
                d[i1 as usize] = d[i1 as usize].wrapping_add(d[i2 as usize] ^ d[i3 as usize]);
                i1 += 1; i2 += 1; i3 += 1;
                if i3 >= n { i3 -= n; }
                d[i1 as usize] = d[i1 as usize].wrapping_add(d[i2 as usize] ^ rotl(d[i3 as usize], 25));
                i1 += 1; i2 += 1; i3 += 1;
            }
        }
    }

    fn kernel_b_encrypt(d: &mut [u32]) {
        let n = d.len() as isize;
        let rotl = |x: u32, r: u32| x.rotate_left(r);
        for _ in 0..3 {
            let (mut i1, mut i2, mut i3) = (n - 1, 1isize, 4isize);
            while i1 > 0 {
                d[i1 as usize] = d[i1 as usize].wrapping_sub(d[i2 as usize] ^ rotl(d[i3 as usize], 25));
                i1 -= 1; i2 -= 1; i3 -= 1;
                if i3 < 0 { i3 += n; }
                d[i1 as usize] = d[i1 as usize].wrapping_sub(d[i2 as usize] ^ d[i3 as usize]);
                i1 -= 1; i2 -= 1; i3 -= 1;
                if i2 < 0 { i2 += n; }
                d[i1 as usize] = d[i1 as usize].wrapping_sub(d[i2 as usize] ^ rotl(d[i3 as usize], 10));
                i1 -= 1; i2 -= 1; i3 -= 1;
                d[i1 as usize] = d[i1 as usize].wrapping_sub(d[i2 as usize] ^ d[i3 as usize]);
                i1 -= 1; i2 -= 1; i3 -= 1;
            }
        }
    }

    #[test]
    fn test_the_diffusers_agree_with_dm_crypts_shape() {
        type Pair = (fn(&mut [u32]), fn(&mut [u32]));
        let pairs: [(&str, Pair); 4] = [
            ("A decrypt", (diffuser_a_decrypt, kernel_a_decrypt)),
            ("A encrypt", (diffuser_a_encrypt, kernel_a_encrypt)),
            ("B decrypt", (diffuser_b_decrypt, kernel_b_decrypt)),
            ("B encrypt", (diffuser_b_encrypt, kernel_b_encrypt)),
        ];
        for words in [128usize, 1024] {
            let d0: Vec<u32> = (0..words as u32).map(|i| i.wrapping_mul(0x9e37_79b9) ^ 0x5bd1_e995)
                .collect();
            for (name, (ours, theirs)) in pairs {
                let (mut a, mut b) = (d0.clone(), d0.clone());
                ours(&mut a);
                theirs(&mut b);
                assert_eq!(a, b, "{name}, {words} words");
            }
        }
    }

    #[test]
    fn test_every_method_round_trips_at_both_sector_sizes() {
        for code in 0x8000..=0x8005u16 {
            let method = Method::from_code(code).unwrap();
            assert_eq!(method.code(), code);
            let key = pattern(method.key_len(), 3);
            let mut cipher = SectorCipher::new(method, &key).unwrap();
            for size in [512usize, 4096] {
                let plain = pattern(size, 7);
                let mut sector = plain.clone();
                cipher.encrypt_sector(1 << 20, &mut sector).unwrap();
                assert_ne!(sector, plain);
                let mut other = plain.clone();
                cipher.encrypt_sector((1 << 20) + size as u64, &mut other).unwrap();
                assert_ne!(sector, other, "{method:?}: the position must matter");
                cipher.decrypt_sector(1 << 20, &mut sector).unwrap();
                assert_eq!(sector, plain, "{method:?} {size}");
            }
        }
        assert!(Method::from_code(0x8006).is_err());
        for (name, code) in [("aes-cbc-elephant-128", 0x8000), ("aes-cbc-elephant-256", 0x8001),
                             ("aes-cbc-128", 0x8002), ("aes-cbc-256", 0x8003),
                             ("aes-xts-128", 0x8004), ("aes-xts-256", 0x8005)] {
            assert_eq!(Method::from_name(name).unwrap().code(), code, "{name}");
        }
        assert!(Method::from_name("aes-ctr-128").is_err());
    }

    /// AES-CBC alone: the IV is AES of the byte offset, and nothing else
    /// is done to the sector.
    #[test]
    fn test_plain_cbc_is_cbc_under_the_encrypted_offset() {
        let key = pattern(16, 1);
        let plain = pattern(512, 2);
        let mut sector = plain.clone();
        SectorCipher::new(Method::AesCbc128, &key).unwrap()
            .encrypt_sector(0x1234_5600, &mut sector).unwrap();
        let mut aes = AesCrypto::new(key).unwrap();
        let mut iv = Vec::new();
        aes.block_encrypt(&offset_block(0x1234_5600), &mut iv);
        let mut want = Vec::new();
        aes.cbc_encrypt(&plain, &mut want, iv).unwrap();
        assert_eq!(sector, want);
    }

    /// Elephant without its diffusers would be CBC over the plaintext
    /// XOR the sector key; it is not, so a ciphertext bit flipped in the
    /// first block disturbs the last plaintext block too, which CBC alone
    /// never does.
    #[test]
    fn test_elephant_spreads_a_ciphertext_change() {
        let mut cipher = SectorCipher::new(Method::AesCbcElephant128, &pattern(32, 5)).unwrap();
        let plain = pattern(512, 9);
        let mut sector = plain.clone();
        cipher.encrypt_sector(4096, &mut sector).unwrap();
        sector[3] ^= 1;
        cipher.decrypt_sector(4096, &mut sector).unwrap();
        assert_ne!(sector[496..], plain[496..]);
    }

    /// XTS numbers sectors in units of the sector size, the CBC methods
    /// use the byte offset.
    #[test]
    fn test_xts_takes_the_sector_number() {
        let key = pattern(32, 4);
        let plain = pattern(4096, 6);
        let mut sector = plain.clone();
        SectorCipher::new(Method::AesXts128, &key).unwrap().encrypt_sector(3 * 4096, &mut sector)
            .unwrap();
        let want = xts::encrypt(&mut AesCrypto::new(key[..16].to_vec()).unwrap(),
                                &mut AesCrypto::new(key[16..].to_vec()).unwrap(),
                                &xts::sector_tweak(3), &plain).unwrap();
        assert_eq!(sector, want);
    }

    #[test]
    fn test_bad_keys_and_sectors_are_refused() {
        assert!(SectorCipher::new(Method::AesXts256, &[0; 32]).is_err());
        let mut cipher = SectorCipher::new(Method::AesCbc128, &[0; 16]).unwrap();
        assert!(cipher.decrypt_sector(0, &mut [0; 100]).is_err());
        // Whole AES blocks, but not whole 32-byte sector-key strides:
        // CBC alone would take 48 bytes, so the message says who refused.
        let mut elephant = SectorCipher::new(Method::AesCbcElephant128, &[1; 32]).unwrap();
        let error = elephant.encrypt_sector(0, &mut [0; 48]).unwrap_err();
        assert!(error.contains("multiple of 32"), "{error}");
        assert!(cipher.decrypt_sector(0, &mut []).is_err());
    }
}
