//! TrueCrypt and VeraCrypt volumes, built from this library's
//! primitives.
//!
//!     cargo run --release --example veracrypt -- open VOLUME PASSWORD [--keyfile FILE]...
//!     cargo run --release --example veracrypt -- open VOLUME --password-stdin [...]
//!         [--pim N] [--hash NAME] [--hidden] [--system] [--truecrypt] [--master-key]
//!         [--decrypt OUT [--limit BYTES]]
//!     cargo run --release --example veracrypt -- format VOLUME PASSWORD --size BYTES
//!         [--cipher AES|Serpent-Twofish-AES|...] [--hash sha512] [--pim N]
//!         [--keyfile FILE]... [--truecrypt] [--data FILE] [--seed N]
//!
//! `open` tries every key derivation and every cipher, as VeraCrypt
//! does - the header does not say which were used - and checks the
//! decrypted header's magic and both CRCs; `--hash` and `--pim` narrow
//! the search. `format` writes a new volume: the header at the start,
//! its backup at the end, the data between, encrypted.
//!
//! The header: 64 bytes of salt, then 448 bytes encrypted under a key
//! derived from the password (and keyfiles) and the salt. Decrypted, it
//! holds the magic `TRUE` or `VERA`, the volume's geometry, and the
//! master keys that encrypt the data.
//!
//! Cipher names are VeraCrypt's: `AES-Twofish-Serpent` encrypts with
//! Serpent first and AES last, and holds its keys in that order.
//!
//! What has checked it is in `examples/products/README.md`.

use allcrypt::api::{AnyBlockCipher, AnyHash};
use allcrypt::block_ciphers::{lrw, xts, BlockCipher};
use allcrypt::hash_functions::HashFunction;
use allcrypt::kdf::argon2::{Argon2, Variant};
use allcrypt::kdf::password::pbkdf2;

#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

const SALT: usize = 64;
const HEADER: usize = 512;
const HEADER_KEY: usize = 192;
const UNIT: usize = 512;
/// Where the headers are, and the data area of a current volume.
const HIDDEN_HEADER: usize = 65536;
const DATA_START: usize = 131072;
const SYSTEM_HEADER: usize = 31744;
const KEYFILE_READ: usize = 1 << 20;

type Random<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

// ------------------------------------------------- key derivation ---

/// One way a header key is derived.
#[derive(Clone, Copy, Debug)]
struct Kdf {
    name: &'static str,
    /// The library's hash name; `None` for Argon2id.
    hash: Option<&'static str>,
    iterations: u32,
    veracrypt: bool,
    /// Only for system (pre-boot) encryption.
    boot: bool,
    /// Iterations with a PIM: `constant + multiplier * pim`.
    pim: Option<(u32, u32)>,
}

const fn kdf(name: &'static str, hash: Option<&'static str>, iterations: u32, veracrypt: bool,
             boot: bool, pim: Option<(u32, u32)>) -> Kdf {
    Kdf { name, hash, iterations, veracrypt, boot, pim }
}

/// TrueCrypt's, then VeraCrypt's.
const KDFS: &[Kdf] = &[
    kdf("ripemd160", Some("ripemd160"), 2000, false, false, None),
    kdf("ripemd160", Some("ripemd160"), 1000, false, true, None),
    kdf("sha512", Some("sha512"), 1000, false, false, None),
    kdf("whirlpool", Some("whirlpool"), 1000, false, false, None),
    // TrueCrypt 1.0 to 4.x.
    kdf("sha1", Some("sha1"), 2000, false, false, None),
    kdf("sha512", Some("sha512"), 500_000, true, false, Some((15000, 1000))),
    kdf("whirlpool", Some("whirlpool"), 500_000, true, false, Some((15000, 1000))),
    kdf("sha256", Some("sha256"), 500_000, true, false, Some((15000, 1000))),
    kdf("sha256", Some("sha256"), 200_000, true, true, Some((0, 2048))),
    kdf("blake2s", Some("blake2s"), 500_000, true, false, Some((15000, 1000))),
    kdf("blake2s", Some("blake2s"), 200_000, true, true, Some((0, 2048))),
    kdf("ripemd160", Some("ripemd160"), 655_331, true, false, Some((15000, 1000))),
    kdf("ripemd160", Some("ripemd160"), 327_661, true, true, Some((0, 2048))),
    kdf("streebog", Some("streebog512"), 500_000, true, false, Some((15000, 1000))),
    kdf("argon2id", None, 0, true, false, None),
];

/// VeraCrypt's Argon2id cost for a PIM (0 meaning the default, 12):
/// 64 MiB plus 32 per step to a 1 GiB cap, and passes 3 + (pim - 1) / 3
/// to PIM 31, one more per step beyond.
fn argon2_cost(pim: u32) -> (u32, u32) {
    let pim = if pim == 0 { 12 } else { pim };
    let memory_mib = (64 + (pim - 1) * 32).min(1024);
    let passes = if pim <= 31 { 3 + (pim - 1) / 3 } else { 13 + (pim - 31) };
    (passes, memory_mib * 1024)
}

impl Kdf {
    fn iterations(&self, pim: u32) -> u32 {
        match self.pim {
            Some((constant, multiplier)) if pim > 0 => constant + multiplier * pim,
            _ => self.iterations,
        }
    }

    fn derive(&self, password: &[u8], salt: &[u8], pim: u32) -> Result<Vec<u8>, String> {
        match self.hash {
            Some(hash) => pbkdf2(AnyHash::new(hash)?, password, salt, self.iterations(pim),
                                 HEADER_KEY),
            None => {
                let (passes, memory) = argon2_cost(pim);
                let mut argon = Argon2::new(Variant::Id);
                argon.passes = passes;
                argon.memory_kib = memory;
                argon.lanes = 1;
                argon.derive(password, salt, HEADER_KEY)
            }
        }
    }

    fn describe(&self, pim: u32) -> String {
        match self.hash {
            Some(_) => format!("PBKDF2-HMAC-{} {} iterations", self.name, self.iterations(pim)),
            None => {
                let (passes, memory) = argon2_cost(pim);
                format!("Argon2id {passes} passes, {} MiB", memory / 1024)
            }
        }
    }
}

/// TrueCrypt's keyfile pool: each keyfile's first megabyte run through
/// CRC-32, every intermediate register added byte by byte into a pool
/// of 64 bytes - 128 in VeraCrypt when the password is longer than 64 -
/// and the password added on top. With keyfiles the pool's full length
/// is what the KDF sees.
fn password_with_keyfiles(password: &[u8], keyfiles: &[Vec<u8>], veracrypt: bool)
                          -> Result<Vec<u8>, String> {
    let pool_size = if veracrypt && password.len() > 64 { 128 } else { 64 };
    if password.len() > pool_size {
        return Err(format!("The password is longer than {pool_size} bytes."));
    }
    if keyfiles.is_empty() {
        return Ok(password.to_vec());
    }
    let mut pool = vec![0u8; pool_size];
    for keyfile in keyfiles {
        let mut crc = !0u32;
        let mut at = 0;
        for &byte in keyfile.iter().take(KEYFILE_READ) {
            crc = allcrypt::checksum::crc32_update(crc, &[byte]);
            for b in crc.to_be_bytes() {
                pool[at] = pool[at].wrapping_add(b);
                at = (at + 1) % pool_size;
            }
        }
    }
    for (p, b) in pool.iter_mut().zip(password) {
        *p = p.wrapping_add(*b);
    }
    Ok(pool)
}

// ---------------------------------------------------------- ciphers ---

/// TrueCrypt's Blowfish, which reads its block as little-endian words,
/// is the library's `blowfish-le`; cryptsetup spells it `blowfish_le`,
/// and so do the tables here.
fn cipher(name: &str, key: &[u8]) -> Result<Box<dyn BlockCipher>, String> {
    Ok(Box::new(AnyBlockCipher::new(name, key, None)?))
}

fn key_size(name: &str) -> usize {
    match name {
        "cast5" => 16,
        "3des" => 24,
        "blowfish_le" => 56,
        _ => 32,
    }
}

fn block_size(name: &str) -> usize {
    match name {
        "cast5" | "3des" | "blowfish_le" => 8,
        _ => 16,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    /// TrueCrypt 5 and later, every VeraCrypt.
    Xts,
    /// TrueCrypt 4.1 to 4.3.
    Lrw,
    /// TrueCrypt 1.0 to 4.0: CBC with an IV and "whitening" derived from
    /// the sector number. One cipher, or a cascade with each cipher
    /// doing its own CBC pass.
    Cbc,
    /// The same era's cascades of 128 bit ciphers: one CBC around the
    /// whole chain ("outer CBC").
    OuterCbc,
}

/// An encryption algorithm: a mode and its ciphers in the order they
/// are applied, which is also the order of their keys.
#[derive(Clone, Copy, Debug)]
struct Ea {
    mode: Mode,
    ciphers: &'static [&'static str],
}

const fn ea(mode: Mode, ciphers: &'static [&'static str]) -> Ea {
    Ea { mode, ciphers }
}

const EAS: &[Ea] = &[
    ea(Mode::Xts, &["aes"]),
    ea(Mode::Xts, &["serpent"]),
    ea(Mode::Xts, &["twofish"]),
    ea(Mode::Xts, &["camellia"]),
    ea(Mode::Xts, &["kuznyechik"]),
    ea(Mode::Xts, &["twofish", "aes"]),
    ea(Mode::Xts, &["serpent", "twofish", "aes"]),
    ea(Mode::Xts, &["aes", "serpent"]),
    ea(Mode::Xts, &["aes", "twofish", "serpent"]),
    ea(Mode::Xts, &["serpent", "twofish"]),
    ea(Mode::Xts, &["kuznyechik", "camellia"]),
    ea(Mode::Xts, &["twofish", "kuznyechik"]),
    ea(Mode::Xts, &["serpent", "camellia"]),
    ea(Mode::Xts, &["aes", "kuznyechik"]),
    ea(Mode::Xts, &["camellia", "serpent", "kuznyechik"]),
    ea(Mode::Lrw, &["aes"]),
    ea(Mode::Lrw, &["serpent"]),
    ea(Mode::Lrw, &["twofish"]),
    ea(Mode::Lrw, &["twofish", "aes"]),
    ea(Mode::Lrw, &["serpent", "twofish", "aes"]),
    ea(Mode::Lrw, &["aes", "serpent"]),
    ea(Mode::Lrw, &["aes", "twofish", "serpent"]),
    ea(Mode::Lrw, &["serpent", "twofish"]),
    ea(Mode::Cbc, &["aes"]),
    ea(Mode::Cbc, &["serpent"]),
    ea(Mode::Cbc, &["twofish"]),
    ea(Mode::Cbc, &["cast5"]),
    ea(Mode::Cbc, &["3des"]),
    ea(Mode::Cbc, &["blowfish_le"]),
    ea(Mode::Cbc, &["blowfish_le", "aes"]),
    ea(Mode::Cbc, &["serpent", "blowfish_le", "aes"]),
    ea(Mode::OuterCbc, &["twofish", "aes"]),
    ea(Mode::OuterCbc, &["serpent", "twofish", "aes"]),
    ea(Mode::OuterCbc, &["aes", "serpent"]),
    ea(Mode::OuterCbc, &["aes", "twofish", "serpent"]),
    ea(Mode::OuterCbc, &["serpent", "twofish"]),
];

fn display_name(cipher: &str) -> &str {
    match cipher {
        "aes" => "AES",
        "serpent" => "Serpent",
        "twofish" => "Twofish",
        "camellia" => "Camellia",
        "kuznyechik" => "Kuznyechik",
        "cast5" => "CAST5",
        "3des" => "Triple DES",
        "blowfish_le" => "Blowfish",
        other => other,
    }
}

impl Ea {
    /// VeraCrypt's name: the last cipher applied first.
    fn name(&self) -> String {
        let names: Vec<&str> = self.ciphers.iter().rev().map(|c| display_name(c)).collect();
        let mode = match self.mode {
            Mode::Xts => "XTS",
            Mode::Lrw => "LRW",
            Mode::Cbc | Mode::OuterCbc => "CBC",
        };
        format!("{} ({mode})", names.join("-"))
    }

    /// Where cipher `i`'s key starts in a key area (the header key, or
    /// the master key area): XTS holds every primary key and then every
    /// secondary one; the legacy modes keep their first 32 bytes for the
    /// LRW tweak key or the CBC IV and whitening seeds.
    fn key_offset(&self, i: usize) -> usize {
        match self.mode {
            Mode::Xts => 32 * i,
            _ => 32 + self.ciphers[..i].iter().map(|c| key_size(c)).sum::<usize>(),
        }
    }

    /// The master key bytes this algorithm uses, in cryptsetup's order:
    /// each cipher's key, with XTS's secondary key after its primary.
    fn master_key(&self, keys: &[u8]) -> Vec<u8> {
        let n = self.ciphers.len();
        let mut out = Vec::new();
        for (i, name) in self.ciphers.iter().enumerate() {
            let at = self.key_offset(i);
            out.extend_from_slice(&keys[at..at + key_size(name)]);
            match self.mode {
                Mode::Xts => out.extend_from_slice(&keys[32 * n + at..32 * n + at + 32]),
                Mode::Lrw => out.extend_from_slice(&keys[..16]),
                Mode::Cbc | Mode::OuterCbc => {
                    out.extend_from_slice(&keys[..block_size(name) + 16]);
                }
            }
        }
        out
    }
}

/// XTS over one data unit with every cipher of the chain, each its own
/// pass with its own two keys.
fn xts_units(ea: &Ea, keys: &[u8], first_unit: u64, data: &mut [u8], encrypt: bool)
             -> Result<(), String> {
    let n = ea.ciphers.len();
    let order: Vec<usize> = if encrypt { (0..n).collect() } else { (0..n).rev().collect() };
    for i in order {
        let at = ea.key_offset(i);
        let mut primary = AnyBlockCipher::new(ea.ciphers[i], &keys[at..at + 32], None)?;
        let mut secondary = AnyBlockCipher::new(ea.ciphers[i],
                                                &keys[32 * n + at..32 * n + at + 32], None)?;
        let unit_size = data.len().min(UNIT);
        for (index, unit) in data.chunks_mut(unit_size).enumerate() {
            let tweak = xts::sector_tweak(u128::from(first_unit + index as u64));
            let out = if encrypt {
                xts::encrypt(&mut primary, &mut secondary, &tweak, unit)?
            } else {
                xts::decrypt(&mut primary, &mut secondary, &tweak, unit)?
            };
            unit.copy_from_slice(&out);
        }
    }
    Ok(())
}

/// LRW: one tweak key for the whole chain, block indices from
/// `first_block`.
fn lrw_blocks(ea: &Ea, keys: &[u8], first_block: u128, data: &mut [u8], encrypt: bool)
              -> Result<(), String> {
    let tweak: [u8; 16] = keys[..16].try_into().map_err(|_| "length".to_string())?;
    let n = ea.ciphers.len();
    let order: Vec<usize> = if encrypt { (0..n).collect() } else { (0..n).rev().collect() };
    for i in order {
        let at = ea.key_offset(i);
        let mut c = AnyBlockCipher::new(ea.ciphers[i], &keys[at..at + 32], None)?;
        let out = if encrypt {
            lrw::encrypt(&mut c, &tweak, &first_block.to_be_bytes(), data)?
        } else {
            lrw::decrypt(&mut c, &tweak, &first_block.to_be_bytes(), data)?
        };
        data.copy_from_slice(&out);
    }
    Ok(())
}

fn cbc_decrypt(c: &mut dyn BlockCipher, iv: &[u8], data: &mut [u8]) {
    let size = c.blocksize();
    let mut previous = iv[..size].to_vec();
    let mut out = Vec::with_capacity(size);
    for block in data.chunks_mut(size) {
        out.clear();
        c.block_decrypt(block, &mut out);
        out.iter_mut().zip(&previous).for_each(|(a, b)| *a ^= b);
        previous.copy_from_slice(block);
        block.copy_from_slice(&out);
    }
}

/// Decrypt the 448 encrypted header bytes in place under `key`.
fn decrypt_header(ea: &Ea, key: &[u8], buf: &mut [u8]) -> Result<(), String> {
    match ea.mode {
        Mode::Xts => xts_units(ea, key, 0, buf, false),
        // The header is block 1 onwards.
        Mode::Lrw => lrw_blocks(ea, key, 1, buf, false),
        Mode::Cbc => {
            // Each cipher, last applied first: remove the whitening (the
            // key's bytes 8 to 15, repeated), then CBC under the key's
            // first block as IV.
            for i in (0..ea.ciphers.len()).rev() {
                buf.iter_mut().enumerate().for_each(|(j, b)| *b ^= key[8 + j % 8]);
                let at = ea.key_offset(i);
                let mut c = cipher(ea.ciphers[i], &key[at..at + key_size(ea.ciphers[i])])?;
                cbc_decrypt(c.as_mut(), &key[..block_size(ea.ciphers[i])], buf);
            }
            Ok(())
        }
        Mode::OuterCbc => {
            buf.iter_mut().enumerate().for_each(|(j, b)| *b ^= key[8 + j % 8]);
            let mut chain: Vec<Box<dyn BlockCipher>> = Vec::new();
            for (i, name) in ea.ciphers.iter().enumerate() {
                let at = ea.key_offset(i);
                chain.push(cipher(name, &key[at..at + key_size(name)])?);
            }
            let mut previous = key[..16].to_vec();
            let mut out = Vec::with_capacity(16);
            for block in buf.chunks_mut(16) {
                let saved = block.to_vec();
                for c in chain.iter_mut().rev() {
                    out.clear();
                    c.block_decrypt(block, &mut out);
                    block.copy_from_slice(&out);
                }
                block.iter_mut().zip(&previous).for_each(|(a, b)| *a ^= b);
                previous = saved;
            }
            Ok(())
        }
    }
}

fn encrypt_header(ea: &Ea, key: &[u8], buf: &mut [u8]) -> Result<(), String> {
    match ea.mode {
        Mode::Xts => xts_units(ea, key, 0, buf, true),
        _ => Err("Only XTS volumes are written; the legacy modes are read.".to_string()),
    }
}

/// The CBC data sector transform dm-crypt calls `tcw`: an IV and an
/// eight byte whitening, both from the sector number and the master
/// key area's seeds, the whitening mixed through CRC-32.
fn tcw_decrypt(ea: &Ea, keys: &[u8], sector: u64, data: &mut [u8]) -> Result<(), String> {
    let name = ea.ciphers[0];
    let bs = block_size(name);
    let iv_seed = &keys[..bs];
    let whitening_seed = &keys[bs..bs + 16];
    let sector_le = sector.to_le_bytes();
    let mut w = [0u8; 16];
    for i in 0..16 {
        w[i] = whitening_seed[i] ^ sector_le[i % 8];
    }
    for part in w.chunks_mut(4) {
        let crc = allcrypt::checksum::crc32_update(0, part);
        part.copy_from_slice(&crc.to_le_bytes());
    }
    for i in 0..4 {
        w[i] ^= w[12 + i];
        w[4 + i] ^= w[8 + i];
    }
    for chunk in data.chunks_mut(8) {
        chunk.iter_mut().zip(&w[..8]).for_each(|(a, b)| *a ^= b);
    }
    let mut iv = vec![0u8; bs];
    for i in 0..bs {
        iv[i] = iv_seed[i] ^ sector_le[i % 8];
    }
    let mut c = cipher(name, &keys[32..32 + key_size(name)])?;
    cbc_decrypt(c.as_mut(), &iv, data);
    Ok(())
}

// ---------------------------------------------------------- headers ---

struct Header {
    magic: [u8; 4],
    version: u16,
    required_version: u16,
    hidden_volume_size: u64,
    volume_size: u64,
    data_offset: u64,
    data_size: u64,
    flags: u32,
    sector_size: u32,
    keys: Vec<u8>,
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}
fn be64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap())
}

impl Header {
    /// `plain` is the 512 byte header with bytes 64 on decrypted. `None`
    /// unless the magic and the CRCs hold.
    fn check(plain: &[u8]) -> Option<Header> {
        let magic: [u8; 4] = plain[64..68].try_into().ok()?;
        if &magic != b"TRUE" && &magic != b"VERA" {
            return None;
        }
        let version = be16(plain, 68);
        if allcrypt::checksum::crc32(&plain[256..512]) != be32(plain, 72) {
            return None;
        }
        // Header version 4 and later protect the header itself as well.
        if version > 3 && allcrypt::checksum::crc32(&plain[64..252]) != be32(plain, 252) {
            return None;
        }
        Some(Header {
            magic,
            version,
            required_version: be16(plain, 70),
            hidden_volume_size: be64(plain, 92),
            volume_size: be64(plain, 100),
            data_offset: be64(plain, 108),
            data_size: be64(plain, 116),
            flags: be32(plain, 124),
            sector_size: match be32(plain, 128) { 0 => 512, size => size },
            keys: plain[256..512].to_vec(),
        })
    }
}

struct Opened {
    kdf: Kdf,
    ea: Ea,
    header: Header,
    header_offset: usize,
}

struct Options {
    password: Vec<u8>,
    keyfiles: Vec<Vec<u8>>,
    pim: u32,
    hash: Option<String>,
    hidden: bool,
    system: bool,
    /// TrueCrypt's key derivations only, as cryptsetup's
    /// `--disable-veracrypt`.
    truecrypt: bool,
}

fn try_header(raw: &[u8], options: &Options) -> Result<Option<(Kdf, Ea, Header)>, String> {
    let salt = &raw[..SALT];
    for kdf in KDFS {
        if let Some(hash) = &options.hash {
            if kdf.name != hash {
                continue;
            }
        }
        // A PIM is VeraCrypt's; boot KDFs only for system volumes.
        // Pre-boot counts are for system encryption only; a system
        // volume can use the others too (SHA-512 and Whirlpool have no
        // pre-boot count of their own).
        if (options.pim > 0 && !kdf.veracrypt) || (kdf.boot && !options.system)
            || (options.truecrypt && kdf.veracrypt) {
            continue;
        }
        // A password over 64 bytes is VeraCrypt's alone.
        let Ok(password) = password_with_keyfiles(&options.password, &options.keyfiles,
                                                  kdf.veracrypt) else { continue };
        let key = kdf.derive(&password, salt, options.pim)?;
        for ea in EAS {
            let mut plain = raw[..HEADER].to_vec();
            if decrypt_header(ea, &key, &mut plain[SALT..]).is_err() {
                continue;
            }
            if let Some(header) = Header::check(&plain) {
                return Ok(Some((*kdf, *ea, header)));
            }
        }
    }
    Ok(None)
}

fn open(volume: &[u8], options: &Options) -> Result<Opened, String> {
    let mut places = Vec::new();
    if options.system {
        places.push(SYSTEM_HEADER);
    } else if options.hidden {
        places.push(HIDDEN_HEADER);
        // TrueCrypt before 6.0 put the hidden header 1536 bytes from
        // the end.
        if volume.len() >= 1536 {
            places.push(volume.len() - 1536);
        }
    } else {
        places.push(0);
    }
    for offset in places {
        let Some(raw) = volume.get(offset..offset + HEADER) else { continue };
        if let Some((kdf, ea, header)) = try_header(raw, options)? {
            return Ok(Opened { kdf, ea, header, header_offset: offset });
        }
    }
    Err("No header opens with this password: wrong password, keyfiles, PIM or hash; \
         or not a TrueCrypt or VeraCrypt volume.".to_string())
}

impl Opened {
    /// Where the data area starts, in bytes, and the sector number the
    /// first data sector's IV is computed from.
    ///
    /// The header's fields are under the password, so a wrong one is
    /// never seen here; a volume made to be opened with a known
    /// password can still carry an offset outside itself, and that is
    /// refused rather than sliced.
    fn data_area(&self, volume_len: usize) -> Result<(usize, u64), String> {
        let h = &self.header;
        let legacy_hidden = self.header_offset + 1536 == volume_len;
        let outside = || format!("The header puts the data outside the {volume_len} byte \
                                  volume.");
        let offset = if legacy_hidden {
            usize::try_from(h.hidden_volume_size).ok()
                .and_then(|size| volume_len.checked_sub(size)?.checked_sub(1536))
                .ok_or_else(outside)?
        } else if h.data_offset == 0 {
            512
        } else {
            usize::try_from(h.data_offset).map_err(|_| outside())?
        };
        if offset > volume_len {
            return Err(outside());
        }
        // XTS numbers data units from the start of the volume; LRW
        // from the start of the data; TrueCrypt's CBC from the header's
        // data offset field, 512 when it is empty - so a legacy hidden
        // volume's IVs start at sector 1 wherever its data lies.
        let first_iv = match self.ea.mode {
            Mode::Xts => (offset / UNIT) as u64,
            Mode::Lrw => 0,
            Mode::Cbc | Mode::OuterCbc => (if h.data_offset == 0 { 512 }
                                           else { h.data_offset } / UNIT as u64),
        };
        Ok((offset, first_iv))
    }

    fn decrypt_data(&self, volume: &[u8], limit: Option<usize>) -> Result<Vec<u8>, String> {
        let (offset, first_iv) = self.data_area(volume.len())?;
        // Headers before version 3 record no size: the data runs to
        // the end of the volume.
        let size = match (self.header.data_size, self.header.volume_size) {
            (0, 0) => volume.len().saturating_sub(offset),
            (0, size) | (size, _) => size as usize,
        };
        let mut length = size.min(volume.len().saturating_sub(offset));
        if let Some(limit) = limit {
            length = length.min(limit);
        }
        length -= length % UNIT;
        let mut data = volume.get(offset..offset + length).ok_or_else(|| {
            format!("The data area, {length} bytes at {offset}, is not in the volume.")
        })?.to_vec();
        let keys = &self.header.keys;
        match self.ea.mode {
            Mode::Xts => xts_units(&self.ea, keys, first_iv, &mut data, false)?,
            Mode::Lrw => {
                for (i, sector) in data.chunks_mut(UNIT).enumerate() {
                    lrw_blocks(&self.ea, keys, ((first_iv + i as u64) as u128) * 32 + 1, sector,
                               false)?;
                }
            }
            // TrueCrypt 1.0's Blowfish data is not what the same IV and
            // whitening give under its header's Blowfish; nothing here
            // can say what it is, so it is not guessed.
            Mode::Cbc if self.ea.ciphers.len() == 1 && self.ea.ciphers[0] != "blowfish_le" => {
                for (i, sector) in data.chunks_mut(UNIT).enumerate() {
                    tcw_decrypt(&self.ea, keys, first_iv + i as u64, sector)?;
                }
            }
            _ => return Err("Data in this legacy cascade is not decrypted; the header and \
                             master keys are.".to_string()),
        }
        Ok(data)
    }
}

// --------------------------------------------------------- creating ---

struct Format {
    ea: Ea,
    kdf: Kdf,
    pim: u32,
    truecrypt: bool,
}

/// A new volume of `size` bytes holding `data`. Returns the volume and
/// the master key in cryptsetup's order.
fn format(params: &Format, password: &[u8], keyfiles: &[Vec<u8>], size: usize, data: &[u8],
          random: Random<'_>) -> Result<(Vec<u8>, Vec<u8>), String> {
    if params.ea.mode != Mode::Xts {
        return Err("Only XTS volumes are written.".to_string());
    }
    if size < 2 * DATA_START + UNIT || !size.is_multiple_of(UNIT) {
        return Err(format!("A volume is whole 512 byte sectors and at least {} bytes.",
                           2 * DATA_START + UNIT));
    }
    let data_size = size - 2 * DATA_START;
    if data.len() > data_size {
        return Err(format!("{} bytes of data do not fit in {data_size}.", data.len()));
    }
    let mut volume = vec![0u8; size];
    // Everything not written below is random, as VeraCrypt leaves it:
    // the unused header areas, and the data area's free space.
    random(&mut volume)?;

    let mut keys = vec![0u8; 256];
    random(&mut keys)?;
    let mut plain = vec![0u8; HEADER];
    plain[64..68].copy_from_slice(if params.truecrypt { b"TRUE" } else { b"VERA" });
    plain[68..70].copy_from_slice(&5u16.to_be_bytes());
    plain[70..72].copy_from_slice(&(if params.truecrypt { 0x0700u16 } else { 0x010b })
        .to_be_bytes());
    plain[100..108].copy_from_slice(&(data_size as u64).to_be_bytes());
    plain[108..116].copy_from_slice(&(DATA_START as u64).to_be_bytes());
    plain[116..124].copy_from_slice(&(data_size as u64).to_be_bytes());
    plain[128..132].copy_from_slice(&512u32.to_be_bytes());
    plain[256..512].copy_from_slice(&keys);
    let keys_crc = allcrypt::checksum::crc32(&plain[256..512]);
    plain[72..76].copy_from_slice(&keys_crc.to_be_bytes());
    let header_crc = allcrypt::checksum::crc32(&plain[64..252]);
    plain[252..256].copy_from_slice(&header_crc.to_be_bytes());

    let password = password_with_keyfiles(password, keyfiles, !params.truecrypt)?;
    // The header and its backup, each under its own salt.
    for at in [0, size - DATA_START] {
        let mut header = plain.clone();
        random(&mut header[..SALT])?;
        let key = params.kdf.derive(&password, &header[..SALT], params.pim)?;
        encrypt_header(&params.ea, &key, &mut header[SALT..])?;
        volume[at..at + HEADER].copy_from_slice(&header);
    }

    let mut payload = data.to_vec();
    payload.resize(data.len().div_ceil(UNIT) * UNIT, 0);
    xts_units(&params.ea, &keys, (DATA_START / UNIT) as u64, &mut payload, true)?;
    volume[DATA_START..DATA_START + payload.len()].copy_from_slice(&payload);
    Ok((volume, params.ea.master_key(&keys)))
}

// -------------------------------------------------------------- CLI ---

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn counter_stream(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), String> {
    let mut counter = 0u64;
    let mut pool: Vec<u8> = Vec::new();
    move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            if pool.is_empty() {
                let mut h = AnyHash::new("sha256")?;
                h.update(&seed.to_be_bytes());
                h.update(&counter.to_be_bytes());
                pool = h.digest();
                counter += 1;
                pool.reverse();
            }
            *byte = pool.pop().unwrap_or(0);
        }
        Ok(())
    }
}

/// An algorithm by VeraCrypt's name: `AES`, `Serpent-Twofish-AES`.
fn ea_by_name(name: &str) -> Result<Ea, String> {
    let wanted: Vec<String> = name.split('-').rev().map(|s| s.to_ascii_lowercase()).collect();
    EAS.iter().find(|ea| ea.mode == Mode::Xts && ea.ciphers.len() == wanted.len()
                    && ea.ciphers.iter().zip(&wanted).all(|(a, b)| *a == b))
        .copied().ok_or_else(|| format!("unknown cipher {name}"))
}

fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: veracrypt open VOLUME PASSWORD [options] | format VOLUME PASSWORD --size N; \
                 --password-stdin in place of PASSWORD";
    let command = args.first().ok_or(usage)?;
    let path = args.get(1).ok_or(usage)?;
    // The password is the third argument unless it is an option, when
    // `--password-stdin` is expected among the options. An empty
    // password with keyfiles is `""`.
    let positional = args.get(2).filter(|a| !a.starts_with("--"));
    let mut keyfiles = Vec::new();
    let mut values = std::collections::HashMap::new();
    let mut flags = std::collections::HashSet::new();
    let mut i = if positional.is_some() { 3 } else { 2 };
    while i < args.len() {
        let name = args[i].trim_start_matches("--").to_string();
        if ["hidden", "system", "master-key", "truecrypt", "password-stdin"]
            .contains(&name.as_str()) {
            flags.insert(name);
            i += 1;
            continue;
        }
        let value = args.get(i + 1).ok_or_else(|| format!("--{name} needs a value"))?;
        if name == "keyfile" {
            keyfiles.push(std::fs::read(value).map_err(|e| format!("{value}: {e}"))?);
        } else {
            values.insert(name, value.clone());
        }
        i += 2;
    }
    let password = match (positional, flags.contains("password-stdin")) {
        (Some(p), false) => p.as_bytes().to_vec(),
        (None, true) => passphrase::read_line("Password: ")?,
        (Some(_), true) => return Err("a password and --password-stdin both".to_string()),
        (None, false) => return Err(usage.to_string()),
    };
    let pim: u32 = values.get("pim").map(|v| v.parse().map_err(|e| format!("--pim: {e}")))
        .transpose()?.unwrap_or(0);
    match command.as_str() {
        "open" => {
            let volume = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let options = Options { password, keyfiles, pim, hash: values.get("hash").cloned(),
                                    hidden: flags.contains("hidden"),
                                    system: flags.contains("system"),
                                    truecrypt: flags.contains("truecrypt") };
            let opened = open(&volume, &options)?;
            let h = &opened.header;
            println!("{} header version {} (needs {:#06x}), {}; {}; data at {} for {} bytes; \
                      sector {}, flags {:#x}{}",
                     String::from_utf8_lossy(&h.magic), h.version, h.required_version,
                     opened.kdf.describe(pim), opened.ea.name(),
                     opened.data_area(volume.len())?.0,
                     if h.data_size > 0 { h.data_size } else { h.volume_size },
                     h.sector_size, h.flags,
                     if h.hidden_volume_size > 0 { "; holds a hidden volume" } else { "" });
            if flags.contains("master-key") {
                println!("master key: {}", hex(&opened.ea.master_key(&h.keys)));
            }
            if let Some(out) = values.get("decrypt") {
                let limit = values.get("limit").map(|v| v.parse::<usize>()
                    .map_err(|e| format!("--limit: {e}"))).transpose()?;
                std::fs::write(out, opened.decrypt_data(&volume, limit)?)
                    .map_err(|e| format!("{out}: {e}"))?;
            }
            Ok(())
        }
        "format" => {
            let size: usize = values.get("size").ok_or("--size is required")?.parse()
                .map_err(|e| format!("--size: {e}"))?;
            let truecrypt = flags.contains("truecrypt");
            let hash = values.get("hash").map(String::as_str).unwrap_or("sha512");
            let kdf = *KDFS.iter().find(|k| k.name == hash && k.veracrypt != truecrypt && !k.boot)
                .ok_or_else(|| format!("no {} KDF {hash}",
                                       if truecrypt { "TrueCrypt" } else { "VeraCrypt" }))?;
            let params = Format {
                ea: ea_by_name(values.get("cipher").map(String::as_str).unwrap_or("AES"))?,
                kdf, pim, truecrypt,
            };
            let data = match values.get("data") {
                Some(file) => std::fs::read(file).map_err(|e| format!("{file}: {e}"))?,
                None => Vec::new(),
            };
            let (volume, key) = match values.get("seed") {
                Some(seed) => format(&params, &password, &keyfiles, size, &data,
                                     &mut counter_stream(seed.parse().map_err(|e| format!("{e}"))?))?,
                None => format(&params, &password, &keyfiles, size, &data,
                               &mut |b: &mut [u8]| allcrypt::random::fill(b))?,
            };
            std::fs::write(path, volume).map_err(|e| format!("{path}: {e}"))?;
            println!("master key: {}", hex(&key));
            Ok(())
        }
        _ => Err(usage.to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("veracrypt: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(password: &[u8], pim: u32, hash: &str, truecrypt: bool) -> Options {
        Options { password: password.to_vec(), keyfiles: Vec::new(), pim,
                  hash: Some(hash.to_string()), hidden: false, system: false, truecrypt }
    }

    fn kdf_named(name: &str, veracrypt: bool) -> Kdf {
        *KDFS.iter().find(|k| k.name == name && k.veracrypt == veracrypt && !k.boot).unwrap()
    }

    fn round_trip(ea: &Ea, kdf: Kdf, pim: u32, seed: u64) {
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 253) as u8).collect();
        let truecrypt = !kdf.veracrypt;
        let params = Format { ea: *ea, kdf, pim, truecrypt };
        let size = 2 * DATA_START + 8192;
        let (volume, key) = format(&params, b"pw", &[], size, &data, &mut counter_stream(seed))
            .unwrap();
        let what = format!("{} {}", ea.name(), kdf.describe(pim));
        let opened = open(&volume, &options(b"pw", pim, kdf.name, truecrypt))
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(opened.ea.ciphers, ea.ciphers, "{what}");
        assert_eq!(opened.ea.master_key(&opened.header.keys), key, "{what}");
        assert_eq!(&opened.decrypt_data(&volume, None).unwrap()[..data.len()], &data[..]);
        // The backup header opens too, and a wrong password does not.
        let backup = &volume[size - DATA_START..];
        assert!(try_header(backup, &options(b"pw", pim, kdf.name, truecrypt)).unwrap().is_some());
        assert!(open(&volume, &options(b"pW", pim, kdf.name, truecrypt)).is_err(), "{what}");
    }

    /// A header's data offset, or a legacy hidden volume's size, was
    /// turned into a slice of the volume without a check: an offset past
    /// the end made `volume[offset..offset]` panic, and a hidden size
    /// larger than the volume underflowed. The header is under the
    /// password, so every fixture that opens has its data inside the
    /// volume; the case is a volume handed over with its password.
    #[test]
    fn test_a_data_area_outside_the_volume_is_refused() {
        let ea = EAS.iter().find(|e| e.mode == Mode::Xts).unwrap();
        let kdf = kdf_named("sha512", false);
        let params = Format { ea: *ea, kdf, pim: 0, truecrypt: true };
        let size = 2 * DATA_START + 8192;
        let (volume, _) = format(&params, b"pw", &[], size, &[7u8; 3000], &mut counter_stream(1))
            .unwrap();
        let mut opened = open(&volume, &options(b"pw", 0, kdf.name, true)).unwrap();
        assert!(opened.decrypt_data(&volume, None).is_ok());
        for offset in [size as u64 + 1, size as u64 + 512, u64::MAX] {
            opened.header.data_offset = offset;
            let error = opened.decrypt_data(&volume, None).err().unwrap_or_else(|| panic!("{offset}"));
            assert!(error.contains("outside"), "{offset}: {error}");
        }
        // The last 1536 bytes of a legacy hidden volume are its header,
        // and the data lies `hidden_volume_size` before them.
        opened.header.data_offset = 0;
        opened.header_offset = size - 1536;
        opened.header.hidden_volume_size = size as u64;
        let error = opened.decrypt_data(&volume, None).err().unwrap();
        assert!(error.contains("outside"), "{error}");
        opened.header.hidden_volume_size = 4096;
        assert_eq!(opened.data_area(size).unwrap().0, size - 1536 - 4096);
    }

    /// Every XTS algorithm, cascades included, written and read back
    /// under TrueCrypt's cheap key derivations - in a debug build every
    /// single cipher and two cascades, the rest optimised. Round trips
    /// only; the fixtures are the test that means something.
    #[test]
    fn test_format_then_open() {
        let xts: Vec<&Ea> = EAS.iter().filter(|e| e.mode == Mode::Xts).collect();
        assert_eq!(xts.len(), 15);
        for (i, ea) in xts.iter().enumerate() {
            if cfg!(debug_assertions) && i >= 7 {
                break;
            }
            let hash = if cfg!(debug_assertions) { "sha512" }
                       else { ["sha512", "whirlpool", "ripemd160"][i % 3] };
            round_trip(ea, kdf_named(hash, false), 0, i as u64);
        }
    }

    /// VeraCrypt's key derivations, at the smallest PIM: sixteen
    /// thousand iterations each, a minute and more without optimisation.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow without optimisation; run with --release")]
    fn test_veracrypt_key_derivations() {
        for (i, hash) in ["sha512", "sha256", "whirlpool", "blake2s", "streebog", "ripemd160",
                          "argon2id"].iter().enumerate() {
            round_trip(&EAS[0], kdf_named(hash, true), 1, 100 + i as u64);
        }
    }

    /// VeraCrypt's Argon2id cost table, from its source's examples.
    #[test]
    fn test_argon2_cost() {
        assert_eq!(argon2_cost(0), (6, 416 * 1024));
        assert_eq!(argon2_cost(12), (6, 416 * 1024));
        assert_eq!(argon2_cost(1), (3, 64 * 1024));
        assert_eq!(argon2_cost(31), (13, 1024 * 1024));
        assert_eq!(argon2_cost(32), (14, 1024 * 1024));
    }

    /// Keyfiles alone, a keyfile with a password, and the 128 byte pool
    /// VeraCrypt uses for a long password.
    #[test]
    fn test_keyfile_pool() {
        let pool = password_with_keyfiles(b"", &[vec![0u8]], true).unwrap();
        assert_eq!(pool.len(), 64);
        let crc = allcrypt::checksum::crc32_update(!0, &[0]).to_be_bytes();
        assert_eq!(&pool[..4], &crc);
        assert!(pool[4..].iter().all(|&b| b == 0));
        let long = vec![b'a'; 70];
        assert_eq!(password_with_keyfiles(&long, &[vec![1]], true).unwrap().len(), 128);
        assert!(password_with_keyfiles(&long, &[vec![1]], false).is_err());
    }

    fn cryptsetup_opened(veracrypt: bool) {
        let records = fixtures::records("veracrypt.vec", "cryptsetup");
        assert!(records.len() >= 4);
        let mut checked = 0;
        for record in &records {
            let name = fixtures::field(record, "name");
            if name.starts_with("vc-") != veracrypt {
                continue;
            }
            let volume = fixtures::expand(fixtures::field(record, "volume"));
            let options = Options {
                password: fixtures::field(record, "password").as_bytes().to_vec(),
                keyfiles: Vec::new(), pim: fixtures::field(record, "pim").parse().unwrap(),
                hash: Some(fixtures::field(record, "hash").into()), hidden: false,
                system: false, truecrypt: !veracrypt,
            };
            let opened = open(&volume, &options).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(hex(&opened.ea.master_key(&opened.header.keys)),
                       fixtures::field(record, "master_key"), "{name}");
            let data = opened.decrypt_data(&volume, Some(65536)).unwrap();
            let length: usize = fixtures::field(record, "data_length").parse().unwrap();
            let mut h = AnyHash::new("sha256").unwrap();
            h.update(&data[..length]);
            assert_eq!(fixtures::hex(&h.digest()), fixtures::field(record, "data_sha256"),
                       "{name}");
            checked += 1;
        }
        assert!(checked >= 2);
    }

    /// TrueCrypt volumes this example wrote that cryptsetup opened, with
    /// the master key `cryptsetup tcryptDump --dump-master-key` printed
    /// and data python-cryptography decrypted under it.
    #[test]
    fn test_truecrypt_volumes_cryptsetup_opened() {
        cryptsetup_opened(false);
    }

    /// The same for VeraCrypt volumes, whose key derivation is sixteen
    /// times the work at the smallest PIM.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow without optimisation; run with --release")]
    fn test_veracrypt_volumes_cryptsetup_opened() {
        cryptsetup_opened(true);
    }
}
