//! LUKS1 and LUKS2 disk encryption, the format Linux's `cryptsetup`
//! writes, built from this library's primitives.
//!
//!     cargo run --release --example luks -- dump IMAGE
//!     cargo run --release --example luks -- open IMAGE PASSPHRASE [--volume-key] [--decrypt OUT]
//!     cargo run --release --example luks -- open IMAGE --passphrase-stdin [...]
//!     cargo run --release --example luks -- open IMAGE --key-file FILE [...]
//!     cargo run --release --example luks -- open IMAGE --volume-key-file FILE
//!         [--new-volume-key-file FILE] [...]
//!     cargo run --release --example luks -- format IMAGE PASSPHRASE [--type luks1|luks2]
//!         [--cipher aes-xts-plain64] [--key-size BITS] [--hash sha256]
//!         [--pbkdf pbkdf2|argon2i|argon2id] [--iterations N] [--memory KIB]
//!         [--parallel N] [--sector-size 512|4096] [--data FILE] [--seed N]
//!
//! `open` finds the keyslot the passphrase unlocks, recovers the volume
//! key, checks it against the header's digest, and with `--decrypt`
//! writes the decrypted data area; given the volume key in a file
//! instead, it checks that. A LUKS2 volume stopped in the middle of
//! `cryptsetup reencrypt` is read as cryptsetup's recovery would leave
//! it, without writing to it - with both keys, which the passphrase
//! unlocks or `--volume-key-file` and `--new-volume-key-file` give (see
//! `Reencryption`). `format` writes a new image holding
//! `--data` (zeros if absent), encrypted. Both work on image files; a
//! block device is a file too, given the permissions.
//!
//! How a passphrase becomes a volume key, both versions:
//!
//! 1. PBKDF2 (or, in LUKS2, Argon2) of the passphrase and the keyslot's
//!    salt gives a key for the keyslot's area.
//! 2. That area holds the volume key run through the anti-forensic
//!    splitter - 4000 stripes, so a 64 byte key occupies 256000 bytes -
//!    encrypted as disk sectors with the volume's own cipher.
//! 3. Merging the stripes gives a candidate volume key; PBKDF2 of the
//!    candidate must equal the header's digest.
//!
//! What has checked it is in `examples/products/README.md`.

use allcrypt::api::{AnyBlockCipher, AnyHash};
use allcrypt::block_ciphers::{lrw, xts, BlockCipher};
use allcrypt::hash_functions::HashFunction;
use allcrypt::kdf::argon2::{Argon2, Variant};
use allcrypt::kdf::password::pbkdf2;

mod json;
#[path = "../shared/json.rs"]
mod shared_json;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/cli.rs"]
mod cli;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use cli::hex;
use json::{n, obj, s, Header, Value};

const SECTOR: usize = 512;
const STRIPES: usize = 4000;
const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
const LUKS2_SECONDARY_MAGIC: &[u8; 6] = b"SKUL\xba\xbe";
const LUKS1_ACTIVE: u32 = 0x00AC_71F3;
const LUKS1_DISABLED: u32 = 0x0000_DEAD;

type Random<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

// ------------------------------------------------------------ hashing ---

fn hash(name: &str, parts: &[&[u8]]) -> Result<Vec<u8>, String> {
    let (library_name, cut) = hash_name(name);
    let mut h = AnyHash::new(library_name)?;
    for part in parts {
        h.update(part);
    }
    let mut digest = h.digest();
    if let Some(length) = cut {
        digest.truncate(length);
    }
    Ok(digest)
}

/// LUKS names hashes the way the Linux kernel does: the library's
/// names but for RIPEMD-160's and Whirlpool's spellings, and `wp256` and
/// `wp384`, Whirlpool cut short.
use allcrypt::kdf::luks_af::kernel_hash_name as hash_name;

fn pbkdf2_any(hash: &str, password: &[u8], salt: &[u8], iterations: u32, length: usize)
              -> Result<Vec<u8>, String> {
    let (library_name, cut) = hash_name(hash);
    if cut.is_some() {
        return Err(format!("LUKS: PBKDF2 with {hash}, a truncated hash, is not supported."));
    }
    pbkdf2(AnyHash::new(library_name)?, password, salt, iterations, length)
}

// -------------------------------------------------- the AF splitter ---

use allcrypt::kdf::luks_af::{af_merge, af_split};

// ---------------------------------------------- sector encryption ---

/// How an IV is made from a sector number: dm-crypt's IV generators.
#[derive(Clone, Debug, PartialEq)]
enum IvMode {
    /// The sector number, 32 bits, little endian, zero padded.
    Plain,
    /// The index of the sector's first block counting from 1, 64 bits
    /// big endian, in the IV's last eight bytes: LRW's natural IV.
    Benbi,
    /// 64 bits, little endian, zero padded.
    Plain64,
    /// 64 bits, big endian, in the IV's last eight bytes.
    Plain64Be,
    /// The plain64 IV encrypted under a key that is the hash of the
    /// volume key - so IVs are not predictable from sector numbers.
    Essiv(String),
    /// No IV at all: every sector starts from zero.
    Null,
}

#[derive(Clone, Debug, PartialEq)]
enum Chain {
    Xts,
    /// The mode XTS replaced: dm-crypt's `lrw-benbi` and `lrw-plain64`.
    Lrw,
    Cbc,
    Ecb,
}

/// A dm-crypt cipher specification: `aes-xts-plain64`,
/// `aes-cbc-essiv:sha256`, `serpent-cbc-plain`, `twofish-ecb`.
#[derive(Clone, Debug, PartialEq)]
struct CipherSpec {
    cipher: String,
    chain: Chain,
    iv: IvMode,
}

impl CipherSpec {
    fn parse(cipher: &str, mode: &str) -> Result<CipherSpec, String> {
        let (chain, iv) = mode.split_once('-').unwrap_or((mode, ""));
        let chain = match chain {
            "xts" => Chain::Xts,
            "lrw" => Chain::Lrw,
            "cbc" => Chain::Cbc,
            "ecb" => Chain::Ecb,
            other => return Err(format!("LUKS: the {other} chaining mode is not supported; \
                                         xts, lrw, cbc and ecb are.")),
        };
        let iv = match iv {
            "plain" => IvMode::Plain,
            "plain64" => IvMode::Plain64,
            "plain64be" => IvMode::Plain64Be,
            "benbi" => IvMode::Benbi,
            "null" => IvMode::Null,
            "" if chain == Chain::Ecb => IvMode::Null,
            other => match other.strip_prefix("essiv:") {
                Some(hash) => IvMode::Essiv(hash.to_string()),
                None => return Err(format!("LUKS: the IV mode {other:?} is not supported.")),
            },
        };
        // The library's names are dm-crypt's but for the DES family.
        let cipher = match cipher {
            "des3_ede" => "3des",
            other => other,
        }.to_string();
        AnyBlockCipher::new(&cipher, &[0u8; 32], None)
            .or_else(|_| AnyBlockCipher::new(&cipher, &[0u8; 16], None))
            .or_else(|_| AnyBlockCipher::new(&cipher, &[0u8; 24], None))
            .map_err(|e| format!("LUKS: cipher {cipher}: {e}"))?;
        Ok(CipherSpec { cipher, chain, iv })
    }

    /// From one string, the way LUKS2 writes it: `aes-xts-plain64`.
    fn parse_joined(spec: &str) -> Result<CipherSpec, String> {
        let (cipher, mode) = spec.split_once('-')
            .ok_or_else(|| format!("LUKS2: {spec:?} is not cipher-mode-iv."))?;
        CipherSpec::parse(cipher, mode)
    }

    /// The two halves LUKS1 stores: `aes` and `xts-plain64`.
    fn mode_string(&self) -> String {
        let chain = match self.chain {
            Chain::Xts => "xts",
            Chain::Lrw => "lrw",
            Chain::Cbc => "cbc",
            Chain::Ecb => return "ecb".to_string(),
        };
        let iv = match &self.iv {
            IvMode::Plain => "plain".to_string(),
            IvMode::Plain64 => "plain64".to_string(),
            IvMode::Plain64Be => "plain64be".to_string(),
            IvMode::Benbi => "benbi".to_string(),
            IvMode::Null => "null".to_string(),
            IvMode::Essiv(hash) => format!("essiv:{hash}"),
        };
        format!("{chain}-{iv}")
    }

    fn cipher_name(&self) -> &str {
        if self.cipher == "3des" { "des3_ede" } else { &self.cipher }
    }

    fn joined(&self) -> String {
        format!("{}-{}", self.cipher_name(), self.mode_string())
    }
}

/// A keyed sector cipher.
struct SectorCipher {
    spec: CipherSpec,
    data: AnyBlockCipher,
    /// XTS's second key.
    xts_tweak: Option<AnyBlockCipher>,
    /// LRW's tweak key: the key's last 16 bytes.
    lrw_tweak: Option<[u8; 16]>,
    /// ESSIV's cipher, keyed with the hash of the whole key.
    essiv: Option<AnyBlockCipher>,
}

impl SectorCipher {
    fn new(spec: &CipherSpec, key: &[u8]) -> Result<SectorCipher, String> {
        let essiv = match &spec.iv {
            IvMode::Essiv(hash_) => Some(AnyBlockCipher::new(&spec.cipher, &hash(hash_, &[key])?,
                                                             None)?),
            _ => None,
        };
        let (data, xts_tweak, lrw_tweak) = match spec.chain {
            Chain::Xts => {
                if !key.len().is_multiple_of(2) {
                    return Err("LUKS: an XTS key is two keys of equal length.".to_string());
                }
                let (k1, k2) = key.split_at(key.len() / 2);
                (AnyBlockCipher::new(&spec.cipher, k1, None)?,
                 Some(AnyBlockCipher::new(&spec.cipher, k2, None)?), None)
            }
            Chain::Lrw => {
                let (k1, k2) = key.split_at(key.len().checked_sub(16)
                    .ok_or("LUKS: an LRW key is a cipher key and 16 bytes more.")?);
                (AnyBlockCipher::new(&spec.cipher, k1, None)?, None,
                 Some(k2.try_into().map_err(|_| "length".to_string())?))
            }
            _ => (AnyBlockCipher::new(&spec.cipher, key, None)?, None, None),
        };
        Ok(SectorCipher { spec: spec.clone(), data, xts_tweak, lrw_tweak, essiv })
    }

    fn iv(&mut self, sector: u64) -> Vec<u8> {
        let size = self.data.blocksize();
        let mut iv = vec![0u8; size];
        match &self.spec.iv {
            IvMode::Plain => iv[..4].copy_from_slice(&(sector as u32).to_le_bytes()),
            IvMode::Plain64 => {
                let n = size.min(8);
                iv[..n].copy_from_slice(&sector.to_le_bytes()[..n]);
            }
            IvMode::Plain64Be => {
                let n = size.min(8);
                iv[size - n..].copy_from_slice(&sector.to_be_bytes()[8 - n..]);
            }
            IvMode::Benbi => {
                // log2(512 / block size): 5 for a 16 byte block.
                let shift = 9 - size.trailing_zeros();
                let value = (sector << shift) + 1;
                let n = size.min(8);
                iv[size - n..].copy_from_slice(&value.to_be_bytes()[8 - n..]);
            }
            IvMode::Essiv(_) => {
                let n = size.min(8);
                iv[..n].copy_from_slice(&sector.to_le_bytes()[..n]);
                let mut out = Vec::with_capacity(size);
                if let Some(essiv) = self.essiv.as_mut() {
                    essiv.block_encrypt(&iv, &mut out);
                }
                return out;
            }
            IvMode::Null => {}
        }
        iv
    }

    /// One sector (of any size the block divides), in place. `iv_sector`
    /// is the IV's sector number - in 512 byte units, whatever the
    /// sector size.
    fn crypt(&mut self, iv_sector: u64, data: &mut [u8], encrypt: bool) -> Result<(), String> {
        let iv = self.iv(iv_sector);
        let size = self.data.blocksize();
        if !data.len().is_multiple_of(size) {
            return Err(format!("LUKS: a sector of {} bytes is not whole {size} byte blocks.",
                               data.len()));
        }
        match self.spec.chain {
            Chain::Xts => {
                let tweak: [u8; 16] = iv.as_slice().try_into()
                    .map_err(|_| "LUKS: XTS needs a 128 bit block cipher.".to_string())?;
                let second = self.xts_tweak.as_mut().ok_or("state")?;
                let out = if encrypt {
                    xts::encrypt(&mut self.data, second, &tweak, data)?
                } else {
                    xts::decrypt(&mut self.data, second, &tweak, data)?
                };
                data.copy_from_slice(&out);
            }
            Chain::Lrw => {
                let index: [u8; 16] = iv.as_slice().try_into()
                    .map_err(|_| "LUKS: LRW needs a 128 bit block cipher.".to_string())?;
                let tweak_key = self.lrw_tweak.ok_or("state")?;
                let out = if encrypt {
                    lrw::encrypt(&mut self.data, &tweak_key, &index, data)?
                } else {
                    lrw::decrypt(&mut self.data, &tweak_key, &index, data)?
                };
                data.copy_from_slice(&out);
            }
            // The library's modes, not a loop of single blocks: CBC
            // decryption and ECB have every block of the sector in hand,
            // and the modes hand them to `decrypt_blocks` together, which
            // is where AES's constant-time path lives.
            Chain::Cbc => {
                let mut out = Vec::with_capacity(data.len());
                if encrypt {
                    self.data.cbc_encrypt(data, &mut out, &iv)?;
                } else {
                    self.data.cbc_decrypt(data, &mut out, &iv)?;
                }
                data.copy_from_slice(&out);
            }
            Chain::Ecb => {
                if encrypt {
                    self.data.encrypt_blocks(data)?;
                } else {
                    self.data.decrypt_blocks(data)?;
                }
            }
        }
        Ok(())
    }

    /// A run of `sector_size` sectors, the first with IV sector
    /// `first_iv`, each next one `sector_size / 512` further on.
    fn crypt_area(&mut self, first_iv: u64, data: &mut [u8], sector_size: usize, encrypt: bool)
                  -> Result<(), String> {
        let step = (sector_size / SECTOR) as u64;
        for (index, sector) in data.chunks_mut(sector_size).enumerate() {
            self.crypt(first_iv + index as u64 * step, sector, encrypt)?;
        }
        Ok(())
    }
}

// --------------------------------------------------------- the image ---

fn read_at(image: &[u8], offset: usize, length: usize) -> Result<&[u8], String> {
    offset.checked_add(length).and_then(|end| image.get(offset..end)).ok_or_else(|| format!(
        "LUKS: the image ends before byte {} + {length} - truncated, or not this header's \
         disk.", offset))
}

/// The sector sizes the kernel's dm-crypt and cryptsetup accept.
fn check_sector_size(sector_size: usize) -> Result<(), String> {
    if ![512, 1024, 2048, 4096].contains(&sector_size) {
        return Err(format!("LUKS: a sector size of {sector_size}; 512, 1024, 2048 and 4096 are \
                            possible."));
    }
    Ok(())
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn be64(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn put_c_string(out: &mut [u8], text: &str) -> Result<(), String> {
    if text.len() >= out.len() {
        return Err(format!("LUKS: {text:?} does not fit its {} byte field.", out.len()));
    }
    out[..text.len()].copy_from_slice(text.as_bytes());
    Ok(())
}

/// Decrypt a keyslot's area and merge it into a candidate volume key.
fn unlock_area(image: &[u8], offset: usize, spec: &CipherSpec, area_key: &[u8], key_len: usize,
               stripes: usize, af_hash: &str) -> Result<Vec<u8>, String> {
    // Both counts come from the header, and their product sizes the
    // read; the library's AF merge checks them again.
    let length = key_len.checked_mul(stripes).and_then(|n| n.checked_add(SECTOR - 1))
        .map(|n| n / SECTOR * SECTOR)
        .ok_or("LUKS: a keyslot's key size and stripes multiply past memory.")?;
    let mut material = read_at(image, offset, length)?.to_vec();
    SectorCipher::new(spec, area_key)?.crypt_area(0, &mut material, SECTOR, false)?;
    af_merge(&material, key_len, stripes, af_hash)
}

/// What `open` found.
struct Unlocked {
    version: u16,
    /// The keyslot that gave the volume key; `None` when the key was
    /// given rather than unlocked.
    keyslot: Option<usize>,
    volume_key: Vec<u8>,
    spec: CipherSpec,
    data_offset: usize,
    data_length: Option<usize>,
    sector_size: usize,
    iv_tweak: u64,
    /// A LUKS2 volume stopped in the middle of `cryptsetup reencrypt`:
    /// its data is under two keys, and the fields above are the new
    /// key's.
    reencryption: Option<Reencryption>,
}

/// The bytes of a segment: `length` from `offset`, or with `None`
/// ("dynamic") whole sectors to the end of the image.
fn segment_bytes(image: &[u8], offset: usize, length: Option<usize>, sector_size: usize)
                 -> Result<&[u8], String> {
    check_sector_size(sector_size)?;
    if offset > image.len() {
        return Err(format!("LUKS: the data starts at byte {offset}, past the end of the {} \
                            byte image.", image.len()));
    }
    let length = match length {
        Some(length) => {
            offset.checked_add(length).ok_or("LUKS: the segment's offset and size add past \
                                              memory.")?;
            length
        }
        None => (image.len() - offset) / sector_size * sector_size,
    };
    read_at(image, offset, length)
}

impl Unlocked {
    fn decrypt_data(&self, image: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(reencryption) = &self.reencryption {
            return reencryption.decrypt_data(image);
        }
        let mut data = segment_bytes(image, self.data_offset, self.data_length,
                                     self.sector_size)?.to_vec();
        SectorCipher::new(&self.spec, &self.volume_key)?
            .crypt_area(self.iv_tweak, &mut data, self.sector_size, false)?;
        Ok(data)
    }
}

// ------------------------------------------------- LUKS2 reencryption ---

/// `cryptsetup reencrypt` moves a LUKS2 volume to a new volume key (and
/// cipher, and sector size) a *hotzone* at a time, in place, while the
/// header records how far it has got: the data segments are the part
/// already under the new key, the hotzone, and the part still under the
/// old one, each bound to the digest of its key. Stopped cleanly, it
/// leaves no hotzone. Stopped by a crash, the hotzone may be partly
/// rewritten, and the reencrypt keyslot's area says how to tell: under
/// `checksum` resilience it holds a hash of each old block, taken before
/// the hotzone was rewritten, so a block that still hashes to it is old;
/// under `journal` it holds a copy of the hotzone's old ciphertext; under
/// `none`, nothing.
///
/// This reads such a volume as cryptsetup's recovery would leave it,
/// without writing: `reencrypt_recover_segment` in cryptsetup's
/// `lib/luks2/luks2_reencrypt.c` is what it follows.
struct Reencryption {
    direction: String,
    protection: Protection,
    /// The keys, with the cipher and sector size of the segments cryptsetup
    /// keeps as `backup-previous` and `backup-final`: what the volume was
    /// and what it is becoming.
    old: Layer,
    new: Layer,
    /// The data segments in order.
    pieces: Vec<Piece>,
}

struct Layer {
    spec: CipherSpec,
    key: Vec<u8>,
    sector_size: usize,
}

enum Protection {
    None,
    Checksum { area: usize, area_size: usize, hash: String, block: usize },
    Journal { area: usize, area_size: usize },
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Part {
    Old,
    New,
    Hotzone,
}

struct Piece {
    part: Part,
    offset: usize,
    length: Option<usize>,
    iv_tweak: u64,
    spec: CipherSpec,
    sector_size: usize,
}

impl Reencryption {
    fn decrypt_data(&self, image: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for piece in &self.pieces {
            let mut data = segment_bytes(image, piece.offset, piece.length, piece.sector_size)?
                .to_vec();
            match piece.part {
                Part::Old | Part::New => {
                    let key = if piece.part == Part::Old { &self.old.key } else { &self.new.key };
                    SectorCipher::new(&piece.spec, key)?
                        .crypt_area(piece.iv_tweak, &mut data, piece.sector_size, false)?;
                }
                Part::Hotzone => self.recover(image, piece.iv_tweak, &mut data)?,
            }
            out.extend_from_slice(&data);
        }
        Ok(out)
    }

    /// The hotzone's plaintext. Both keys' IVs count from the hotzone's
    /// `iv_tweak`, as cryptsetup's recovery has them.
    fn recover(&self, image: &[u8], iv: u64, data: &mut [u8]) -> Result<(), String> {
        for layer in [&self.old, &self.new] {
            if !data.len().is_multiple_of(layer.sector_size) {
                return Err(format!("LUKS2: a hotzone of {} bytes is not whole {} byte \
                                    sectors.", data.len(), layer.sector_size));
            }
        }
        match &self.protection {
            Protection::None => Err("LUKS2: the reencryption stopped inside a hotzone, with \
                                     resilience \"none\": nothing records which of its blocks \
                                     were rewritten, and cryptsetup cannot recover it either."
                .to_string()),
            Protection::Checksum { area, area_size, hash: hash_name, block } => {
                let block = *block;
                if block == 0 || !data.len().is_multiple_of(block)
                    || !block.is_multiple_of(self.old.sector_size)
                    || !block.is_multiple_of(self.new.sector_size) {
                    return Err(format!("LUKS2: a checksum block of {block} bytes does not \
                                        divide the {} byte hotzone into whole sectors.",
                                       data.len()));
                }
                let width = hash(hash_name, &[])?.len();
                let length = data.len() / block * width;
                if length > *area_size {
                    return Err(format!("LUKS2: the hotzone's checksums take {length} bytes, \
                                        more than the {area_size} byte area holds."));
                }
                let sums = read_at(image, *area, length)?;
                let mut old = SectorCipher::new(&self.old.spec, &self.old.key)?;
                let mut new = SectorCipher::new(&self.new.spec, &self.new.key)?;
                for (index, chunk) in data.chunks_mut(block).enumerate() {
                    let first_iv = iv + (index * block / SECTOR) as u64;
                    // A block that hashes to what was recorded before the
                    // hotzone was rewritten is the old ciphertext still.
                    if hash(hash_name, &[chunk])? == sums[index * width..(index + 1) * width] {
                        old.crypt_area(first_iv, chunk, self.old.sector_size, false)?;
                    } else {
                        new.crypt_area(first_iv, chunk, self.new.sector_size, false)?;
                    }
                }
                Ok(())
            }
            Protection::Journal { area, area_size } => {
                if data.len() > *area_size {
                    return Err(format!("LUKS2: a hotzone of {} bytes does not fit the {} byte \
                                        journal.", data.len(), area_size));
                }
                // The journal is the hotzone's old ciphertext; the hotzone
                // itself may be old, new or torn, and is not looked at.
                data.copy_from_slice(read_at(image, *area, data.len())?);
                SectorCipher::new(&self.old.spec, &self.old.key)?
                    .crypt_area(iv, data, self.old.sector_size, false)
            }
        }
    }

    fn summary(&self) -> String {
        let protection = match self.protection {
            Protection::None => "none",
            Protection::Checksum { .. } => "checksum",
            Protection::Journal { .. } => "journal",
        };
        let pieces: Vec<String> = self.pieces.iter().map(|piece| {
            let length = match piece.length {
                Some(length) => format!("{length} bytes"),
                None => "the rest".to_string(),
            };
            match piece.part {
                Part::Old => format!("{length} under the old key"),
                Part::New => format!("{length} under the new key"),
                Part::Hotzone => format!("a hotzone of {length}"),
            }
        }).collect();
        format!("reencryption in progress, {}, resilience {protection}: {}", self.direction,
                pieces.join(", "))
    }
}

/// The reencryption metadata as cryptsetup serializes it for the digest
/// that binds it to both volume keys (`luks2_reencrypt_digest.c`): JSON
/// strings as their bytes (64 at most), 64 bit quantities - which LUKS2
/// writes as decimal strings - as 8 bytes big endian, a segment size of
/// "dynamic" as that word, 32 bit JSON integers as 4 bytes big endian.
/// Anything missing or of another kind and cryptsetup's serialization
/// fails, and so the digest does; here it is an error.
struct DigestInput(Vec<u8>);

impl DigestInput {
    fn missing(object: &Value, key: &str, kind: &str) -> String {
        format!("LUKS2: the reencryption metadata's {key:?} is not {kind}: {:?}.",
                object.get(key))
    }

    fn text(&mut self, object: &Value, key: &str) -> Result<(), String> {
        match object.get(key) {
            Some(Value::String(text)) if text.len() <= 64 => {
                self.0.extend_from_slice(text.as_bytes());
                Ok(())
            }
            _ => Err(DigestInput::missing(object, key, "a string of at most 64 bytes")),
        }
    }

    fn u64(&mut self, object: &Value, key: &str) -> Result<(), String> {
        match object.get(key) {
            Some(Value::String(text)) if text.parse::<u64>().is_ok() => {
                self.0.extend_from_slice(&text.parse::<u64>().unwrap_or(0).to_be_bytes());
                Ok(())
            }
            _ => Err(DigestInput::missing(object, key, "a 64 bit number in a string")),
        }
    }

    fn size(&mut self, object: &Value, key: &str) -> Result<(), String> {
        if object.get(key).and_then(Value::as_str) == Some("dynamic") {
            self.0.extend_from_slice(b"dynamic");
            return Ok(());
        }
        self.u64(object, key)
    }

    fn u32(&mut self, object: &Value, key: &str) -> Result<(), String> {
        match object.get(key) {
            Some(Value::Number(text)) if text.parse::<u32>().is_ok() => {
                self.0.extend_from_slice(&text.parse::<u32>().unwrap_or(0).to_be_bytes());
                Ok(())
            }
            _ => Err(DigestInput::missing(object, key, "a 32 bit JSON integer")),
        }
    }

    fn segment(&mut self, segment: &Value) -> Result<(), String> {
        self.text(segment, "type")?;
        self.u64(segment, "offset")?;
        self.size(segment, "size")?;
        match segment.field("type")?.string()? {
            "crypt" => {
                self.u64(segment, "iv_tweak")?;
                self.text(segment, "encryption")?;
                self.u32(segment, "sector_size")
            }
            "linear" => Ok(()),
            other => Err(format!("LUKS2: a backup segment of type {other:?}.")),
        }
    }
}

// ------------------------------------------------------------- LUKS1 ---

/// The 592 byte LUKS1 header, big endian throughout.
struct Luks1 {
    spec: CipherSpec,
    hash: String,
    payload_offset: u32,
    key_bytes: u32,
    mk_digest: [u8; 20],
    mk_salt: [u8; 32],
    mk_iterations: u32,
    uuid: String,
    slots: Vec<Luks1Slot>,
}

struct Luks1Slot {
    active: bool,
    iterations: u32,
    salt: [u8; 32],
    material_offset: u32,
    stripes: u32,
}

impl Luks1 {
    fn parse(image: &[u8]) -> Result<Luks1, String> {
        let h = read_at(image, 0, 592)?;
        if &h[..6] != LUKS_MAGIC || u16::from_be_bytes([h[6], h[7]]) != 1 {
            return Err("LUKS: not a LUKS1 header.".to_string());
        }
        let spec = CipherSpec::parse(&c_string(&h[8..40]), &c_string(&h[40..72]))?;
        let mut slots = Vec::new();
        for i in 0..8 {
            let s = &h[208 + 48 * i..208 + 48 * (i + 1)];
            let state = be32(s, 0);
            if state != LUKS1_ACTIVE && state != LUKS1_DISABLED {
                return Err(format!("LUKS1: keyslot {i} has the state {state:#x}, which is \
                                    neither active nor disabled."));
            }
            slots.push(Luks1Slot {
                active: state == LUKS1_ACTIVE,
                iterations: be32(s, 4),
                salt: s[8..40].try_into().unwrap(),
                material_offset: be32(s, 40),
                stripes: be32(s, 44),
            });
        }
        Ok(Luks1 {
            spec,
            hash: c_string(&h[72..104]),
            payload_offset: be32(h, 104),
            key_bytes: be32(h, 108),
            mk_digest: h[112..132].try_into().unwrap(),
            mk_salt: h[132..164].try_into().unwrap(),
            mk_iterations: be32(h, 164),
            uuid: c_string(&h[168..208]),
            slots,
        })
    }

    fn open(&self, image: &[u8], passphrase: &[u8]) -> Result<Unlocked, String> {
        let key_len = self.key_bytes as usize;
        for (index, slot) in self.slots.iter().enumerate().filter(|(_, s)| s.active) {
            let area_key = pbkdf2_any(&self.hash, passphrase, &slot.salt, slot.iterations,
                                      key_len)?;
            let candidate = unlock_area(image, slot.material_offset as usize * SECTOR, &self.spec,
                                        &area_key, key_len, slot.stripes as usize, &self.hash)?;
            let digest = pbkdf2_any(&self.hash, &candidate, &self.mk_salt, self.mk_iterations, 20)?;
            if digest == self.mk_digest {
                return Ok(self.unlocked(Some(index), candidate));
            }
        }
        Err("LUKS1: no keyslot opens with this passphrase.".to_string())
    }

    /// The volume key given rather than unlocked: it must match the
    /// header's digest.
    fn open_with_key(&self, key: &[u8]) -> Result<Unlocked, String> {
        let digest = pbkdf2_any(&self.hash, key, &self.mk_salt, self.mk_iterations, 20)?;
        if key.len() != self.key_bytes as usize || digest != self.mk_digest {
            return Err("LUKS1: the volume key does not match the header's digest.".to_string());
        }
        Ok(self.unlocked(None, key.to_vec()))
    }

    fn unlocked(&self, keyslot: Option<usize>, volume_key: Vec<u8>) -> Unlocked {
        Unlocked {
            version: 1, keyslot, volume_key, spec: self.spec.clone(),
            data_offset: self.payload_offset as usize * SECTOR, data_length: None,
            sector_size: SECTOR, iv_tweak: 0, reencryption: None,
        }
    }

    fn dump(&self) -> String {
        let mut out = format!(
            "LUKS1\ncipher: {}-{}\nhash: {}\npayload offset: {} sectors\nkey: {} bits\n\
             uuid: {}\ndigest iterations: {}\n", self.spec.cipher_name(),
            self.spec.mode_string(), self.hash, self.payload_offset, self.key_bytes * 8,
            self.uuid, self.mk_iterations);
        for (i, slot) in self.slots.iter().enumerate().filter(|(_, s)| s.active) {
            out.push_str(&format!("keyslot {i}: pbkdf2 {} iterations, material at sector {}, \
                                   {} stripes\n", slot.iterations, slot.material_offset,
                                  slot.stripes));
        }
        out
    }
}

// ------------------------------------------------------------- LUKS2 ---

/// LUKS2: two copies of a 4096 byte binary header and a JSON area each,
/// then the keyslots area, then data. The binary header: magic (0),
/// version (6), header size (8), sequence id (16), label (24),
/// checksum algorithm (72), salt (104), UUID (168), subsystem (208),
/// this header's offset (256), checksum (448).
struct Luks2 {
    json: Value,
    /// The binary header's size field: header plus JSON area.
    hdr_size: usize,
}

const LUKS2_BINARY: usize = 4096;
/// The checksum field's place in the binary header.
const LUKS2_CSUM: core::ops::Range<usize> = 448..512;
/// The header sizes cryptsetup allows: binary header plus JSON area,
/// 16 KiB to 4 MiB in powers of two. The secondary copy sits right
/// after the primary's area, so these are also where to look for it.
const LUKS2_HEADER_SIZES: [usize; 9] = [16384, 32768, 65536, 131072, 262144, 524288, 1048576,
                                        2097152, 4194304];

impl Luks2 {
    /// The primary header, or the secondary if the primary is damaged.
    fn parse(image: &[u8]) -> Result<Luks2, String> {
        match Luks2::parse_at(image, 0) {
            Ok(header) => Ok(header),
            Err(primary) => {
                for size in LUKS2_HEADER_SIZES {
                    if let Ok(header) = Luks2::parse_at(image, size) {
                        return Ok(header);
                    }
                }
                Err(primary)
            }
        }
    }

    fn parse_at(image: &[u8], offset: usize) -> Result<Luks2, String> {
        let b = read_at(image, offset, LUKS2_BINARY)?;
        let magic = if offset == 0 { LUKS_MAGIC } else { LUKS2_SECONDARY_MAGIC };
        if &b[..6] != magic || u16::from_be_bytes([b[6], b[7]]) != 2 {
            return Err("LUKS: not a LUKS2 header.".to_string());
        }
        // The checksum is computed over `hdr_size` bytes, so the size
        // has to be checked before it sizes anything: a small one would
        // not even hold the checksum field or the JSON area.
        let hdr_size = usize::try_from(be64(b, 8)).ok()
            .filter(|size| LUKS2_HEADER_SIZES.contains(size))
            .ok_or_else(|| format!("LUKS2: a header size of {} is not one cryptsetup writes \
                                    (16 KiB to 4 MiB, powers of two).", be64(b, 8)))?;
        if be64(b, 256) as usize != offset {
            return Err("LUKS2: the header's offset field disagrees with where it is.".to_string());
        }
        let checksum_alg = c_string(&b[72..104]);
        let whole = read_at(image, offset, hdr_size)?;
        let mut copy = whole.to_vec();
        copy[LUKS2_CSUM].fill(0);
        let digest = hash(&checksum_alg, &[&copy])?;
        if digest[..] != b[LUKS2_CSUM][..digest.len()] {
            return Err(format!("LUKS2: the header at {offset} fails its {checksum_alg} \
                                checksum."));
        }
        let json_text = c_string(&whole[LUKS2_BINARY..]);
        Ok(Luks2 { json: json::parse(&json_text)?, hdr_size })
    }

    /// `config.requirements.mandatory`: features a reader must implement
    /// before it may use the volume, cryptsetup's own rule. Empty when
    /// the header has none.
    fn mandatory_requirements(&self) -> Result<Vec<String>, String> {
        let Some(requirements) = self.json.field("config")?.get("requirements") else {
            return Ok(Vec::new());
        };
        match requirements.get("mandatory") {
            None => Ok(Vec::new()),
            Some(list) => list.items()?.iter().map(|r| r.string().map(str::to_string))
                .collect(),
        }
    }

    /// Whether the header is mid-reencryption, from its requirements;
    /// an error for any requirement this does not implement.
    fn reencrypting(&self) -> Result<bool, String> {
        let mut reencrypting = false;
        for required in self.mandatory_requirements()? {
            match required.as_str() {
                "online-reencrypt-v2" => reencrypting = true,
                "online-reencrypt" => return Err(
                    "LUKS2: the header requires \"online-reencrypt\": reencryption as \
                     cryptsetup 2.2 and 2.3 recorded it, without the digest that binds its \
                     metadata to the keys. This does not read it; cryptsetup 2.4 and later \
                     upgrade it when given the passphrase.".to_string()),
                "online-reencrypt-v3" => return Err(
                    "LUKS2: the header requires \"online-reencrypt-v3\": a decryption that \
                     moves the data as it goes, which this does not read.".to_string()),
                other => return Err(format!(
                    "LUKS2: the header requires {other:?}, which this does not implement - its \
                     data cannot be read correctly without it.")),
            }
        }
        Ok(reencrypting)
    }

    /// The digests bound to `field`'s entry `id` (a keyslot or segment).
    fn digests_binding(&self, field: &str, id: &str) -> Result<Vec<(&str, &Value)>, String> {
        let mut bound = Vec::new();
        for (digest_id, digest) in self.json.field("digests")?.entries()? {
            if digest.field(field)?.items()?.iter().any(|k| k.as_str() == Some(id)) {
                bound.push((digest_id.as_str(), digest));
            }
        }
        Ok(bound)
    }

    /// Whether PBKDF2 of `key` is the digest.
    fn digest_matches(digest: &Value, key: &[u8]) -> Result<bool, String> {
        if digest.field("type")?.string()? != "pbkdf2" {
            return Ok(false);
        }
        let expected = allcrypt::pem::decode(digest.field("digest")?.string()?)?;
        let got = pbkdf2_any(digest.field("hash")?.string()?, key,
                             &allcrypt::pem::decode(digest.field("salt")?.string()?)?,
                             digest.field("iterations")?.uint()? as u32, expected.len())?;
        Ok(got == expected)
    }

    fn first_segment(digest: &Value) -> Result<&str, String> {
        digest.field("segments")?.items()?.first()
            .ok_or("LUKS2: the digest is bound to no segment.")?.string()
    }

    /// The volume keys given rather than unlocked - one, or a volume
    /// mid-reencryption's old and new - each matched to its digest.
    fn open_with_keys(&self, keys: &[Vec<u8>]) -> Result<Unlocked, String> {
        let reencrypting = self.reencrypting()?;
        let mut found = Vec::new();
        for key in keys {
            let mut matched = None;
            for (id, digest) in self.json.field("digests")?.entries()? {
                if !digest.field("segments")?.items()?.is_empty()
                    && Luks2::digest_matches(digest, key)? {
                    matched = Some(id.clone());
                    break;
                }
            }
            let id = matched.ok_or("LUKS2: a volume key matches none of the header's \
                                    digests.")?;
            if !reencrypting {
                let digest = self.json.field("digests")?.field(&id)?;
                return self.unlocked(None, Luks2::first_segment(digest)?, key.clone());
            }
            found.push((id, None, key.clone()));
        }
        self.reencryption(found)
    }

    fn open(&self, image: &[u8], passphrase: &[u8]) -> Result<Unlocked, String> {
        let reencrypting = self.reencrypting()?;
        let keyslots = self.json.field("keyslots")?.entries()?;
        // Mid-reencryption the passphrase must give both keys - the old
        // keyslots' and the new ones cryptsetup added beside them - so
        // every keyslot is tried; otherwise the first that opens decides.
        let mut found: Vec<(String, Option<usize>, Vec<u8>)> = Vec::new();
        for (id, slot) in keyslots {
            if slot.field("type")?.string()? != "luks2" {
                continue;
            }
            let key_len = slot.field("key_size")?.uint()? as usize;
            let area = slot.field("area")?;
            let af = slot.field("af")?;
            let kdf = slot.field("kdf")?;
            let area_spec = CipherSpec::parse_joined(area.field("encryption")?.string()?)?;
            let area_key_len = area.field("key_size")?.uint()? as usize;
            let salt = allcrypt::pem::decode(kdf.field("salt")?.string()?)?;
            let area_key = match kdf.field("type")?.string()? {
                "pbkdf2" => pbkdf2_any(kdf.field("hash")?.string()?, passphrase, &salt,
                                       kdf.field("iterations")?.uint()? as u32, area_key_len)?,
                variant @ ("argon2i" | "argon2id") => {
                    let mut argon = Argon2::new(if variant == "argon2i" { Variant::I }
                                                else { Variant::Id });
                    argon.passes = kdf.field("time")?.uint()? as u32;
                    argon.memory_kib = kdf.field("memory")?.uint()? as u32;
                    argon.lanes = kdf.field("cpus")?.uint()? as u32;
                    argon.derive(passphrase, &salt, area_key_len)?
                }
                other => return Err(format!("LUKS2: keyslot {id} uses the KDF {other}.")),
            };
            let candidate = unlock_area(image, area.field("offset")?.uint()? as usize,
                                        &area_spec, &area_key, key_len,
                                        af.field("stripes")?.uint()? as usize,
                                        af.field("hash")?.string()?)?;
            // The digest bound to this keyslot decides.
            for (digest_id, digest) in self.digests_binding("keyslots", id)? {
                if !Luks2::digest_matches(digest, &candidate)? {
                    continue;
                }
                if !reencrypting {
                    return self.unlocked(id.parse().ok(), Luks2::first_segment(digest)?,
                                         candidate);
                }
                if !found.iter().any(|(d, _, _)| d == digest_id) {
                    found.push((digest_id.to_string(), id.parse().ok(), candidate));
                }
                break;
            }
        }
        if found.is_empty() {
            return Err("LUKS2: no keyslot opens with this passphrase.".to_string());
        }
        self.reencryption(found)
    }

    fn unlocked(&self, keyslot: Option<usize>, segment_id: &str, volume_key: Vec<u8>)
                -> Result<Unlocked, String> {
        let segment = self.json.field("segments")?.field(segment_id)?;
        if segment.field("type")?.string()? != "crypt" {
            return Err("LUKS2: the segment is not a crypt segment.".to_string());
        }
        let (length, sector_size) = Luks2::extent(segment)?;
        Ok(Unlocked {
            version: 2,
            keyslot,
            volume_key,
            spec: CipherSpec::parse_joined(segment.field("encryption")?.string()?)?,
            data_offset: segment.field("offset")?.uint()? as usize,
            data_length: length,
            sector_size,
            iv_tweak: segment.field("iv_tweak")?.uint()?,
            reencryption: None,
        })
    }

    /// A crypt segment's size (`None`: "dynamic") and sector size, the
    /// sector size checked.
    fn extent(segment: &Value) -> Result<(Option<usize>, usize), String> {
        let size = segment.field("size")?;
        let sector_size = usize::try_from(segment.field("sector_size")?.uint()?).unwrap_or(0);
        check_sector_size(sector_size)?;
        let length = if size.as_str() == Some("dynamic") { None }
                     else { Some(usize::try_from(size.uint()?)
                                 .map_err(|_| "LUKS2: a segment size past memory.")?) };
        Ok((length, sector_size))
    }

    fn has_flag(segment: &Value, flag: &str) -> bool {
        segment.get("flags").and_then(|f| f.items().ok())
            .is_some_and(|flags| flags.iter().any(|f| f.as_str() == Some(flag)))
    }

    /// What the reencryption digest is taken over, version 2 (the
    /// requirement "online-reencrypt-v2"): the two bytes 0x76 0x32, the
    /// old volume key, the new one unless it is the same key, the
    /// reencrypt keyslot's mode, direction and area (with a checksum
    /// area's hash and block size), then the backup-previous and
    /// backup-final segments. See `DigestInput`.
    fn reencryption_digest_input(keyslot: &Value, previous: &Value, last: &Value,
                                 old_key: &[u8], new_key: Option<&[u8]>)
                                 -> Result<Vec<u8>, String> {
        let mut input = DigestInput(vec![0x76, 0x30 + 2]);
        input.0.extend_from_slice(old_key);
        if let Some(new_key) = new_key {
            input.0.extend_from_slice(new_key);
        }
        let area = keyslot.field("area")?;
        input.text(keyslot, "mode")?;
        input.text(keyslot, "direction")?;
        input.text(area, "type")?;
        input.u64(area, "offset")?;
        input.u64(area, "size")?;
        if area.field("type")?.string()? == "checksum" {
            input.text(area, "hash")?;
            input.u32(area, "sector_size")?;
        }
        input.segment(previous)?;
        input.segment(last)?;
        Ok(input.0)
    }

    /// A volume stopped mid-reencryption, from the keys the passphrase
    /// (or the caller) gave, each as (digest, keyslot, key): see
    /// `Reencryption`. What cryptsetup checks before it touches such a
    /// volume is checked here before anything is read: a change of key
    /// rather than an encryption or decryption in place, both keys, and
    /// the digest over the reencryption metadata.
    fn reencryption(&self, found: Vec<(String, Option<usize>, Vec<u8>)>)
                    -> Result<Unlocked, String> {
        let no_keyslot = "LUKS2: the header requires \"online-reencrypt-v2\" but has no \
                          reencrypt keyslot.";
        let (keyslot_id, keyslot) = self.json.field("keyslots")?.entries()?.iter()
            .find(|(_, k)| k.get("type").and_then(Value::as_str) == Some("reencrypt"))
            .ok_or(no_keyslot)?;
        match keyslot.field("mode")?.string()? {
            "reencrypt" => {}
            "encrypt" => return Err("LUKS2: the volume is in the middle of being encrypted in \
                                     place, which this does not read; a change of key is."
                .to_string()),
            "decrypt" => return Err("LUKS2: the volume is in the middle of being decrypted in \
                                     place, which this does not read; a change of key is."
                .to_string()),
            other => return Err(format!("LUKS2: a reencryption of mode {other:?}.")),
        }
        let direction = keyslot.field("direction")?.string()?;
        if direction != "forward" && direction != "backward" {
            return Err(format!("LUKS2: a reencryption of direction {direction:?}."));
        }
        let area = keyslot.field("area")?;
        let area_offset = usize::try_from(area.field("offset")?.uint()?).unwrap_or(usize::MAX);
        let area_size = usize::try_from(area.field("size")?.uint()?).unwrap_or(usize::MAX);
        let protection = match area.field("type")?.string()? {
            "none" => Protection::None,
            "journal" => Protection::Journal { area: area_offset, area_size },
            "checksum" => Protection::Checksum {
                area: area_offset, area_size,
                hash: area.field("hash")?.string()?.to_string(),
                block: usize::try_from(area.field("sector_size")?.uint()?).unwrap_or(0),
            },
            other => return Err(format!("LUKS2: reencryption with resilience {other:?}, which \
                                         moves the data, is not read here.")),
        };

        let segments = self.json.field("segments")?.entries()?;
        let flagged = |flag: &str| segments.iter().find(|(_, s)| Luks2::has_flag(s, flag));
        if flagged("backup-moved-segment").is_some() {
            return Err("LUKS2: the reencryption moves a segment, which this does not read."
                .to_string());
        }
        let mut layers = Vec::new();
        for (flag, which) in [("backup-previous", "old"), ("backup-final", "new")] {
            let (id, segment) = flagged(flag).ok_or_else(|| format!(
                "LUKS2: the volume is mid-reencryption but has no {flag} segment."))?;
            if segment.field("type")?.string()? != "crypt" {
                return Err(format!("LUKS2: the {flag} segment is not a crypt segment."));
            }
            let digest = match self.digests_binding("segments", id)?.as_slice() {
                [(digest, _)] => digest.to_string(),
                other => return Err(format!("LUKS2: the {flag} segment is bound to {} \
                                             digests, not one.", other.len())),
            };
            let key = found.iter().find(|(d, _, _)| *d == digest).map(|(_, _, k)| k.clone())
                .ok_or_else(|| format!(
                    "LUKS2: the volume is mid-reencryption, and the {which} volume key (digest \
                     {digest}) is not unlocked; reading it takes both keys."))?;
            let (_, sector_size) = Luks2::extent(segment)?;
            layers.push((digest, Layer {
                spec: CipherSpec::parse_joined(segment.field("encryption")?.string()?)?,
                key, sector_size,
            }));
        }
        let (new_digest, new) = layers.pop().ok_or("layers")?;
        let (old_digest, old) = layers.pop().ok_or("layers")?;

        // The digest over both keys and the metadata that says how the
        // data is laid out: without it, anyone could rewrite the header
        // to make the data read differently.
        let input = Luks2::reencryption_digest_input(
            keyslot, &flagged("backup-previous").ok_or("flagged")?.1,
            &flagged("backup-final").ok_or("flagged")?.1, &old.key,
            (new_digest != old_digest).then_some(&new.key[..]))?;
        let verified = match self.digests_binding("keyslots", keyslot_id)?.as_slice() {
            [(_, digest)] => Luks2::digest_matches(digest, &input)?,
            _ => false,
        };
        if !verified {
            return Err("LUKS2: the reencryption metadata does not match its digest: the header \
                        was changed by something without the volume keys, or is damaged."
                .to_string());
        }

        // The data segments, in the order of their numbers, which is
        // their order on the volume.
        let mut data: Vec<(u64, &str, &Value)> = Vec::new();
        for (id, segment) in segments {
            if segment.get("flags").and_then(|f| f.items().ok()).is_some_and(|flags| flags.iter()
                .any(|f| f.as_str().is_some_and(|f| f.starts_with("backup-")))) {
                continue;
            }
            let number = id.parse().map_err(|_| format!("LUKS2: a segment numbered {id:?}."))?;
            data.push((number, id, segment));
        }
        data.sort_by_key(|(number, _, _)| *number);
        let mut pieces = Vec::new();
        for (index, (number, id, segment)) in data.iter().enumerate() {
            if *number != index as u64 {
                return Err(format!("LUKS2: segment {index} is missing."));
            }
            if segment.field("type")?.string()? != "crypt" {
                return Err(format!("LUKS2: segment {id} is not a crypt segment."));
            }
            let bound: Vec<String> = self.digests_binding("segments", id)?.iter()
                .map(|(d, _)| d.to_string()).collect();
            let part = if Luks2::has_flag(segment, "in-reencryption") {
                if pieces.iter().any(|p: &Piece| p.part == Part::Hotzone) {
                    return Err("LUKS2: two segments are in reencryption.".to_string());
                }
                Part::Hotzone
            } else if bound == [old_digest.clone()]
                || (old_digest == new_digest && bound.contains(&old_digest)) {
                Part::Old
            } else if bound == [new_digest.clone()] {
                Part::New
            } else {
                return Err(format!("LUKS2: segment {id} is bound to the digests {bound:?}, \
                                    not the old key's or the new key's alone."));
            };
            let (length, sector_size) = Luks2::extent(segment)?;
            if length.is_none() && index + 1 != data.len() {
                return Err(format!("LUKS2: segment {id} runs to the end of the volume, but \
                                    another follows it."));
            }
            pieces.push(Piece {
                part,
                offset: usize::try_from(segment.field("offset")?.uint()?).unwrap_or(usize::MAX),
                length,
                iv_tweak: segment.field("iv_tweak")?.uint()?,
                spec: CipherSpec::parse_joined(segment.field("encryption")?.string()?)?,
                sector_size,
            });
        }
        let keyslot = found.iter().find(|(d, _, _)| *d == new_digest).and_then(|(_, k, _)| *k);
        let backup_final = &flagged("backup-final").ok_or("flagged")?.1;
        Ok(Unlocked {
            version: 2,
            keyslot,
            volume_key: new.key.clone(),
            spec: new.spec.clone(),
            data_offset: usize::try_from(backup_final.field("offset")?.uint()?)
                .unwrap_or(usize::MAX),
            data_length: None,
            sector_size: new.sector_size,
            iv_tweak: 0,
            reencryption: Some(Reencryption { direction: direction.to_string(), protection,
                                              old, new, pieces }),
        })
    }

    fn dump(&self) -> String {
        let mut text = String::new();
        self.json.write(&mut text);
        format!("LUKS2\nheader size: {}\n{text}\n", self.hdr_size)
    }
}

// ------------------------------------------------------- formatting ---

struct Format {
    version: u16,
    spec: CipherSpec,
    key_bytes: usize,
    hash: String,
    pbkdf: String,
    iterations: u32,
    memory_kib: u32,
    parallel: u32,
    sector_size: usize,
}

impl Default for Format {
    /// cryptsetup's defaults, but for the cost: a test or an example
    /// should not take a second per keyslot.
    fn default() -> Format {
        Format {
            version: 2,
            spec: CipherSpec::parse("aes", "xts-plain64").unwrap(),
            key_bytes: 64,
            hash: "sha256".to_string(),
            pbkdf: "argon2id".to_string(),
            iterations: 4,
            memory_kib: 65536,
            parallel: 4,
            sector_size: 512,
        }
    }
}

fn uuid(random: Random<'_>) -> Result<String, String> {
    let mut b = [0u8; 16];
    random(&mut b)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

fn align(value: usize, to: usize) -> usize {
    value.div_ceil(to) * to
}

/// A new image holding `data`, encrypted under a fresh volume key that
/// `passphrase` unlocks in keyslot 0. Returns the image and the key.
fn format(params: &Format, passphrase: &[u8], data: &[u8], random: Random<'_>)
          -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut volume_key = vec![0u8; params.key_bytes];
    random(&mut volume_key)?;
    let mut salt = [0u8; 32];
    random(&mut salt)?;
    let material = af_split(&volume_key, STRIPES, &params.hash, random)?;
    let material_sectors = align(material.len(), SECTOR) / SECTOR;
    let mut padded = material;
    padded.resize(material_sectors * SECTOR, 0);
    let digest_salt = {
        let mut s = [0u8; 32];
        random(&mut s)?;
        s
    };
    let digest_iterations = 1000;

    let (mut image, data_offset) = if params.version == 1 {
        if params.pbkdf != "pbkdf2" {
            return Err("LUKS1 keyslots use PBKDF2 only.".to_string());
        }
        // cryptsetup's layout: keyslot areas from sector 8, each aligned
        // to 4096 bytes, the payload aligned to 1 MiB.
        let slot_sectors = align(material_sectors, 8);
        let payload = align(8 + 8 * slot_sectors, 2048);
        let mut h = vec![0u8; payload * SECTOR];
        h[..6].copy_from_slice(LUKS_MAGIC);
        h[6..8].copy_from_slice(&1u16.to_be_bytes());
        put_c_string(&mut h[8..40], params.spec.cipher_name())?;
        put_c_string(&mut h[40..72], &params.spec.mode_string())?;
        put_c_string(&mut h[72..104], &params.hash)?;
        h[104..108].copy_from_slice(&(payload as u32).to_be_bytes());
        h[108..112].copy_from_slice(&(params.key_bytes as u32).to_be_bytes());
        let mk_digest = pbkdf2_any(&params.hash, &volume_key, &digest_salt, digest_iterations,
                                   20)?;
        h[112..132].copy_from_slice(&mk_digest);
        h[132..164].copy_from_slice(&digest_salt);
        h[164..168].copy_from_slice(&digest_iterations.to_be_bytes());
        put_c_string(&mut h[168..208], &uuid(random)?)?;
        for i in 0..8 {
            let at = 208 + 48 * i;
            let offset = 8 + i * slot_sectors;
            h[at..at + 4].copy_from_slice(&(if i == 0 { LUKS1_ACTIVE } else { LUKS1_DISABLED })
                .to_be_bytes());
            if i == 0 {
                h[at + 4..at + 8].copy_from_slice(&params.iterations.to_be_bytes());
                h[at + 8..at + 40].copy_from_slice(&salt);
            }
            h[at + 40..at + 44].copy_from_slice(&(offset as u32).to_be_bytes());
            h[at + 44..at + 48].copy_from_slice(&(STRIPES as u32).to_be_bytes());
        }
        let area_key = pbkdf2_any(&params.hash, passphrase, &salt, params.iterations,
                                  params.key_bytes)?;
        SectorCipher::new(&params.spec, &area_key)?.crypt_area(0, &mut padded, SECTOR, true)?;
        h[8 * SECTOR..8 * SECTOR + padded.len()].copy_from_slice(&padded);
        (h, payload * SECTOR)
    } else {
        let hdr_size = 16384usize;
        let keyslots_offset = 2 * hdr_size;
        let keyslots_size = align(padded.len(), 4096);
        let data_offset = align(keyslots_offset + keyslots_size, 4096);
        let area_key = match params.pbkdf.as_str() {
            "pbkdf2" => pbkdf2_any(&params.hash, passphrase, &salt, params.iterations,
                                   params.key_bytes)?,
            "argon2i" | "argon2id" => {
                let mut argon = Argon2::new(if params.pbkdf == "argon2i" { Variant::I }
                                            else { Variant::Id });
                argon.passes = params.iterations;
                argon.memory_kib = params.memory_kib;
                argon.lanes = params.parallel;
                argon.derive(passphrase, &salt, params.key_bytes)?
            }
            other => return Err(format!("LUKS2: unknown PBKDF {other}.")),
        };
        let kdf = if params.pbkdf == "pbkdf2" {
            obj(vec![("type", s("pbkdf2")), ("hash", s(params.hash.as_str())),
                     ("iterations", n(u64::from(params.iterations))),
                     ("salt", s(allcrypt::pem::encode(&salt)))])
        } else {
            obj(vec![("type", s(params.pbkdf.as_str())), ("time", n(u64::from(params.iterations))),
                     ("memory", n(u64::from(params.memory_kib))),
                     ("cpus", n(u64::from(params.parallel))),
                     ("salt", s(allcrypt::pem::encode(&salt)))])
        };
        let digest = pbkdf2_any(&params.hash, &volume_key, &digest_salt, digest_iterations, 32)?;
        let header = obj(vec![
            ("keyslots", obj(vec![("0", obj(vec![
                ("type", s("luks2")), ("key_size", n(params.key_bytes as u64)),
                ("af", obj(vec![("type", s("luks1")), ("stripes", n(STRIPES as u64)),
                                ("hash", s(params.hash.as_str()))])),
                ("area", obj(vec![("type", s("raw")),
                                  ("offset", s(keyslots_offset.to_string())),
                                  ("size", s(keyslots_size.to_string())),
                                  ("encryption", s(params.spec.joined())),
                                  ("key_size", n(params.key_bytes as u64))])),
                ("kdf", kdf)]))])),
            ("tokens", obj(vec![])),
            ("segments", obj(vec![("0", obj(vec![
                ("type", s("crypt")), ("offset", s(data_offset.to_string())),
                ("size", s("dynamic")), ("iv_tweak", s("0")),
                ("encryption", s(params.spec.joined())),
                ("sector_size", n(params.sector_size as u64))]))])),
            ("digests", obj(vec![("0", obj(vec![
                ("type", s("pbkdf2")), ("keyslots", Value::Array(vec![s("0")])),
                ("segments", Value::Array(vec![s("0")])), ("hash", s(params.hash.as_str())),
                ("iterations", n(u64::from(digest_iterations))),
                ("salt", s(allcrypt::pem::encode(&digest_salt))),
                ("digest", s(allcrypt::pem::encode(&digest)))]))])),
            ("config", obj(vec![("json_size", s((hdr_size - LUKS2_BINARY).to_string())),
                                ("keyslots_size", s(keyslots_size.to_string()))])),
        ]);
        let mut text = String::new();
        header.write(&mut text);
        if text.len() >= hdr_size - LUKS2_BINARY {
            return Err("LUKS2: the JSON does not fit its area.".to_string());
        }
        let mut image = vec![0u8; data_offset];
        let uuid = uuid(random)?;
        let mut header_salt = [0u8; 64];
        random(&mut header_salt)?;
        for (copy, magic) in [(0usize, LUKS_MAGIC), (1, LUKS2_SECONDARY_MAGIC)] {
            let at = copy * hdr_size;
            let h = &mut image[at..at + hdr_size];
            h[..6].copy_from_slice(magic);
            h[6..8].copy_from_slice(&2u16.to_be_bytes());
            h[8..16].copy_from_slice(&(hdr_size as u64).to_be_bytes());
            h[16..24].copy_from_slice(&1u64.to_be_bytes());
            put_c_string(&mut h[72..104], "sha256")?;
            h[104..168].copy_from_slice(&header_salt);
            put_c_string(&mut h[168..208], &uuid)?;
            h[256..264].copy_from_slice(&(at as u64).to_be_bytes());
            h[LUKS2_BINARY..LUKS2_BINARY + text.len()].copy_from_slice(text.as_bytes());
            let checksum = hash("sha256", &[h])?;
            h[LUKS2_CSUM][..32].copy_from_slice(&checksum);
        }
        SectorCipher::new(&params.spec, &area_key)?.crypt_area(0, &mut padded, SECTOR, true)?;
        image[keyslots_offset..keyslots_offset + padded.len()].copy_from_slice(&padded);
        (image, data_offset)
    };

    let sector_size = if params.version == 1 { SECTOR } else { params.sector_size };
    let mut payload = data.to_vec();
    payload.resize(align(data.len().max(sector_size), sector_size), 0);
    SectorCipher::new(&params.spec, &volume_key)?
        .crypt_area(0, &mut payload, sector_size, true)?;
    image.truncate(data_offset);
    image.extend_from_slice(&payload);
    Ok((image, volume_key))
}

// ------------------------------------------------------------ open ---

fn open(image: &[u8], passphrase: &[u8]) -> Result<Unlocked, String> {
    if image.len() < 8 || &image[..6] != LUKS_MAGIC {
        return Err("LUKS: no LUKS header at the start of the image.".to_string());
    }
    match u16::from_be_bytes([image[6], image[7]]) {
        1 => Luks1::parse(image)?.open(image, passphrase),
        2 => Luks2::parse(image)?.open(image, passphrase),
        v => Err(format!("LUKS: version {v} is not 1 or 2.")),
    }
}

/// `open` with the volume keys given rather than a passphrase: one key,
/// or for a LUKS2 volume mid-reencryption its old and new keys.
fn open_with_keys(image: &[u8], keys: &[Vec<u8>]) -> Result<Unlocked, String> {
    if image.len() < 8 || &image[..6] != LUKS_MAGIC {
        return Err("LUKS: no LUKS header at the start of the image.".to_string());
    }
    match u16::from_be_bytes([image[6], image[7]]) {
        1 => match keys {
            [key] => Luks1::parse(image)?.open_with_key(key),
            _ => Err("LUKS1: one volume key.".to_string()),
        },
        2 => Luks2::parse(image)?.open_with_keys(keys),
        v => Err(format!("LUKS: version {v} is not 1 or 2.")),
    }
}

fn dump(image: &[u8]) -> Result<String, String> {
    match image.get(6..8) {
        Some([0, 1]) => Ok(Luks1::parse(image)?.dump()),
        Some([0, 2]) => Ok(Luks2::parse(image)?.dump()),
        _ => Err("LUKS: no LUKS header at the start of the image.".to_string()),
    }
}

// -------------------------------------------------------------- CLI ---

/// SHA-256 of the seed and a counter, as a stream: reproducible output
/// for tests and fixtures, and not random.
fn counter_stream(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), String> {
    let mut counter = 0u64;
    let mut pool: Vec<u8> = Vec::new();
    move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            if pool.is_empty() {
                pool = hash("sha256", &[&seed.to_be_bytes(), &counter.to_be_bytes()])?;
                counter += 1;
                pool.reverse();
            }
            *byte = pool.pop().unwrap_or(0);
        }
        Ok(())
    }
}

/// The third argument; or with `--passphrase-stdin`, a line of standard
/// input; or with `--key-file FILE`, the file's bytes (`-` for all of
/// standard input, which may hold any bytes).
fn passphrase(args: &[String], options: &std::collections::HashMap<String, String>,
              flags: &[String]) -> Result<Vec<u8>, String> {
    if flags.iter().any(|f| f == "passphrase-stdin") {
        return passphrase::read_line("Passphrase: ");
    }
    match options.get("key-file").map(String::as_str) {
        Some("-") => passphrase::read_all(),
        Some(file) => std::fs::read(file).map_err(|e| format!("{file}: {e}")),
        None => args.get(2).filter(|a| !a.starts_with("--")).map(|a| a.as_bytes().to_vec())
            .ok_or_else(|| "a passphrase, --passphrase-stdin, or --key-file FILE".to_string()),
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: luks dump IMAGE | open IMAGE PASSPHRASE [--volume-key] [--decrypt OUT] \
                 | format IMAGE PASSPHRASE [options]; --passphrase-stdin or --key-file FILE \
                 in place of PASSPHRASE, or for open --volume-key-file FILE \
                 [--new-volume-key-file FILE]";
    let command = args.first().ok_or(usage)?;
    let path = args.get(1).ok_or(usage)?;
    let mut options = std::collections::HashMap::new();
    let mut flags = Vec::new();
    // The passphrase is the third argument, or `--passphrase-stdin` or
    // `--key-file FILE` in its place - a key file is any bytes at all.
    let mut i = if args.get(2).is_some_and(|a| a.starts_with("--")) { 2 } else { 3 };
    while i < args.len() {
        let name = args[i].trim_start_matches("--").to_string();
        if matches!(name.as_str(), "volume-key" | "passphrase-stdin") {
            flags.push(name);
            i += 1;
        } else {
            let value = args.get(i + 1).ok_or_else(|| format!("--{name} needs a value"))?;
            options.insert(name, value.clone());
            i += 2;
        }
    }
    match command.as_str() {
        "dump" => {
            let image = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            print!("{}", dump(&image)?);
            Ok(())
        }
        "open" => {
            let image = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            // cryptsetup's names: the volume key, and mid-reencryption
            // the new one too, as files of the key's bytes.
            let mut keys = Vec::new();
            for name in ["volume-key-file", "new-volume-key-file"] {
                if let Some(file) = options.get(name) {
                    keys.push(std::fs::read(file).map_err(|e| format!("{file}: {e}"))?);
                }
            }
            let unlocked = if keys.is_empty() {
                open(&image, &passphrase(args, &options, &flags)?)?
            } else {
                open_with_keys(&image, &keys)?
            };
            let by = match unlocked.keyslot {
                Some(keyslot) => format!("keyslot {keyslot}"),
                None => "volume key".to_string(),
            };
            println!("LUKS{} {by} opened: {} sectors of {} bytes from byte {}",
                     unlocked.version, unlocked.spec.joined(), unlocked.sector_size,
                     unlocked.data_offset);
            if let Some(reencryption) = &unlocked.reencryption {
                println!("{}", reencryption.summary());
            }
            if flags.iter().any(|f| f == "volume-key") {
                if let Some(reencryption) = &unlocked.reencryption {
                    println!("old volume key: {}", hex(&reencryption.old.key));
                }
                println!("volume key: {}", hex(&unlocked.volume_key));
            }
            if let Some(out) = options.get("decrypt") {
                std::fs::write(out, unlocked.decrypt_data(&image)?)
                    .map_err(|e| format!("{out}: {e}"))?;
            }
            Ok(())
        }
        "format" => {
            let passphrase = passphrase(args, &options, &flags)?;
            let mut params = Format::default();
            if let Some(kind) = options.get("type") {
                params.version = match kind.as_str() {
                    "luks1" => {
                        params.pbkdf = "pbkdf2".to_string();
                        params.iterations = 1000;
                        1
                    }
                    "luks2" => 2,
                    other => return Err(format!("--type {other}: luks1 or luks2")),
                };
            }
            let number = |name: &str| -> Result<Option<u64>, String> {
                options.get(name).map(|v| v.parse::<u64>().map_err(|e| format!("--{name}: {e}")))
                    .transpose()
            };
            if let Some(spec) = options.get("cipher") {
                params.spec = CipherSpec::parse_joined(spec)?;
            }
            if let Some(bits) = number("key-size")? {
                params.key_bytes = bits as usize / 8;
            }
            if let Some(hash_) = options.get("hash") {
                params.hash = hash_.clone();
            }
            if let Some(pbkdf) = options.get("pbkdf") {
                params.pbkdf = pbkdf.clone();
                if pbkdf == "pbkdf2" && number("iterations")?.is_none() {
                    params.iterations = 1000;
                }
            }
            if let Some(v) = number("iterations")? { params.iterations = v as u32; }
            if let Some(v) = number("memory")? { params.memory_kib = v as u32; }
            if let Some(v) = number("parallel")? { params.parallel = v as u32; }
            if let Some(v) = number("sector-size")? { params.sector_size = v as usize; }
            let data = match options.get("data") {
                Some(file) => std::fs::read(file).map_err(|e| format!("{file}: {e}"))?,
                None => vec![0u8; 1 << 20],
            };
            let (image, key) = match number("seed")? {
                Some(seed) => format(&params, &passphrase, &data,
                                     &mut counter_stream(seed))?,
                None => format(&params, &passphrase, &data,
                               &mut |b: &mut [u8]| allcrypt::random::fill(b))?,
            };
            std::fs::write(path, &image).map_err(|e| format!("{path}: {e}"))?;
            println!("volume key: {}", hex(&key));
            Ok(())
        }
        _ => Err(usage.to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("luks: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(version: u16, spec: &str, pbkdf: &str, sector_size: usize) -> Format {
        Format {
            version,
            spec: CipherSpec::parse_joined(spec).unwrap(),
            key_bytes: if spec.contains("xts") || spec.contains("lrw") { 32 } else { 16 },
            hash: "sha256".to_string(),
            pbkdf: pbkdf.to_string(),
            iterations: if pbkdf == "pbkdf2" { 1000 } else { 1 },
            memory_kib: 64,
            parallel: 1,
            sector_size,
        }
    }

    /// Our own images, every supported shape, round trip - which settles
    /// only that format and open agree. `test_cryptsetups_images` is the
    /// test that means something.
    #[test]
    fn test_format_then_open() {
        let data: Vec<u8> = (0..20000u32).map(|i| (i % 251) as u8).collect();
        for (version, spec, pbkdf, sector) in [
                (1, "aes-xts-plain64", "pbkdf2", 512), (1, "aes-cbc-essiv:sha256", "pbkdf2", 512),
                (1, "serpent-cbc-plain", "pbkdf2", 512), (1, "twofish-ecb", "pbkdf2", 512),
                (2, "aes-xts-plain64", "argon2id", 4096), (2, "camellia-xts-plain", "argon2i", 512),
                (2, "aes-cbc-plain64be", "pbkdf2", 1024), (1, "aes-lrw-benbi", "pbkdf2", 512),
                (2, "twofish-xts-essiv:sha256", "pbkdf2", 512)] {
            let params = small(version, spec, pbkdf, sector);
            let (image, key) = format(&params, b"secret", &data, &mut counter_stream(9)).unwrap();
            let unlocked = open(&image, b"secret").unwrap_or_else(|e| panic!("{spec}: {e}"));
            assert_eq!(unlocked.volume_key, key);
            assert_eq!(&unlocked.decrypt_data(&image).unwrap()[..data.len()], &data[..], "{spec}");
            assert!(open(&image, b"Secret").is_err());
            assert!(dump(&image).unwrap().starts_with(&format!("LUKS{version}")));
        }
    }

    /// CBC and ECB sectors went through `block_encrypt` one block at a
    /// time, which bypasses the cipher's `encrypt_blocks` and with it
    /// AES's constant-time path; the result was right, so the fixtures
    /// could not tell. The sector cipher now goes through the library's
    /// modes, and this pins each chain and IV mode to the mode called
    /// directly on the same cipher, both ways round.
    #[test]
    fn test_cbc_and_ecb_sectors_are_the_library_modes() {
        let key = [7u8; 32];
        let sector: Vec<u8> = (0..512u32).map(|i| (i * 3 % 251) as u8).collect();
        for spec in ["aes-cbc-essiv:sha256", "aes-cbc-plain64", "serpent-cbc-plain",
                     "aes-ecb", "twofish-ecb"] {
            let spec = CipherSpec::parse_joined(spec).unwrap();
            let mut ours = SectorCipher::new(&spec, &key).unwrap();
            let iv = ours.iv(5);
            let mut sealed = sector.clone();
            ours.crypt(5, &mut sealed, true).unwrap();
            let mut expected = Vec::new();
            let mut cipher = AnyBlockCipher::new(&spec.cipher, &key, None).unwrap();
            if spec.chain == Chain::Cbc {
                cipher.cbc_encrypt(&sector, &mut expected, &iv).unwrap();
            } else {
                cipher.ecb_encrypt(&sector, &mut expected).unwrap();
            }
            assert_eq!(sealed, expected, "{}", spec.joined());
            ours.crypt(5, &mut sealed, false).unwrap();
            assert_eq!(sealed, sector, "{}", spec.joined());
        }
    }

    /// Images `cryptsetup` 2.8 made, kept sparse in `fixtures/luks/`:
    /// LUKS1 and LUKS2, PBKDF2 and Argon2, 512 and 4096 byte sectors,
    /// with data `cryptsetup reencrypt --encrypt` wrote in userspace.
    /// The volume key must be the one `cryptsetup luksDump
    /// --dump-volume-key` printed, and the data what was encrypted.
    #[test]
    fn test_cryptsetups_images() {
        let records = fixtures::records("luks.vec", "cryptsetup");
        assert!(records.len() >= 4);
        for record in &records {
            let name = fixtures::field(record, "name");
            let image = fixtures::expand(fixtures::field(record, "image"));
            let unlocked = open(&image, fixtures::field(record, "passphrase").as_bytes())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(hex(&unlocked.volume_key), fixtures::field(record, "volume_key"), "{name}");
            assert_eq!(unlocked.spec.joined(), fixtures::field(record, "cipher"), "{name}");
            let data = unlocked.decrypt_data(&image).unwrap();
            let length: usize = fixtures::field(record, "data_length").parse().unwrap();
            assert_eq!(hex(&hash("sha256", &[&data[..length]]).unwrap()),
                       fixtures::field(record, "data_sha256"), "{name}");
            assert!(open(&image, b"not the passphrase").is_err(), "{name}");
        }
    }

    /// A damaged primary LUKS2 header falls back to the secondary; a
    /// damaged secondary as well is refused by its checksum.
    #[test]
    fn test_luks2_secondary_header() {
        let params = small(2, "aes-xts-plain64", "pbkdf2", 512);
        let (mut image, key) = format(&params, b"pw", &[1u8; 4096], &mut counter_stream(3))
            .unwrap();
        image[300] ^= 1;
        assert_eq!(open(&image, b"pw").unwrap().volume_key, key);
        image[16384 + 300] ^= 1;
        assert!(open(&image, b"pw").err().unwrap().contains("checksum"));
    }

    /// The binary header's size field says how many bytes the checksum
    /// covers, and the buffer of that size was read and checksummed
    /// before the size was looked at. A size under 512 panicked on the
    /// checksum field's slice; one between 512 and 4095 passed a
    /// checksum computed over those bytes - which the writer of the
    /// header controls - and panicked on the JSON area's slice. Every
    /// fixture and every image `format` writes has a 16 KiB header, so
    /// no test had another size. The size is now checked against the
    /// values cryptsetup allows before any read it sizes.
    #[test]
    fn test_luks2_header_size_is_checked_before_it_sizes_anything() {
        let params = small(2, "aes-xts-plain64", "pbkdf2", 512);
        let (image, key) = format(&params, b"pw", &[1u8; 4096], &mut counter_stream(3))
            .unwrap();
        // Both copies, the checksum made right where its field is in
        // the bytes it covers.
        let with_size = |size: u64| {
            let mut image = image.clone();
            for at in [0usize, 16384] {
                image[at + 8..at + 16].copy_from_slice(&size.to_be_bytes());
                if (512..=image.len() as u64 - at as u64).contains(&size) {
                    let mut copy = image[at..at + size as usize].to_vec();
                    copy[LUKS2_CSUM].fill(0);
                    let checksum = hash("sha256", &[&copy]).unwrap();
                    image[at + 448..at + 480].copy_from_slice(&checksum);
                }
            }
            image
        };
        for size in [0u64, 256, 512, 1024, 4096, 8192, 12288, 16383, 24576, u64::MAX] {
            let error = open(&with_size(size), b"pw").err().unwrap_or_else(|| panic!("{size}"));
            assert!(error.contains("header size"), "{size}: {error}");
        }
        // A primary header with a wrong size is damaged, and the
        // secondary stands in for it.
        let mut primary_only = image.clone();
        primary_only[8..16].copy_from_slice(&8192u64.to_be_bytes());
        assert_eq!(open(&primary_only, b"pw").unwrap().volume_key, key);
    }

    /// `from` replaced by `to` in both copies of a LUKS2 header's JSON,
    /// the checksums made right again. The JSON area is zero padded,
    /// so the text may change length.
    fn with_json(image: &[u8], from: &str, to: &str) -> Vec<u8> {
        let mut image = image.to_vec();
        for at in [0usize, 16384] {
            let json = c_string(&image[at + LUKS2_BINARY..at + 16384]);
            assert!(json.contains(from), "{from}");
            let json = json.replace(from, to);
            image[at + LUKS2_BINARY..at + 16384].fill(0);
            image[at + LUKS2_BINARY..at + LUKS2_BINARY + json.len()]
                .copy_from_slice(json.as_bytes());
            image[at + 448..at + 512].fill(0);
            let checksum = hash("sha256", &[&image[at..at + 16384]]).unwrap();
            image[at + 448..at + 480].copy_from_slice(&checksum);
        }
        image
    }

    /// The segment's `sector_size` and `offset` came out of the JSON
    /// unchecked: a sector size of 0 panicked in `chunks_mut`, an offset
    /// past the image underflowed `image.len() - data_offset`, and an
    /// offset plus a size could overflow. The fixtures are cryptsetup's
    /// and this example's own images, whose segments are all in range,
    /// so no test had a segment outside it.
    #[test]
    fn test_a_segment_outside_the_image_or_the_format_is_refused() {
        let params = small(2, "aes-xts-plain64", "pbkdf2", 512);
        let (image, key) = format(&params, b"pw", &[1u8; 4096], &mut counter_stream(3))
            .unwrap();
        let data_offset = open(&image, b"pw").unwrap().data_offset;
        for bad in ["0", "513", "8192", "18446744073709551615"] {
            let changed = with_json(&image, "\"sector_size\":512", &format!("\"sector_size\":{bad}"));
            let error = open(&changed, b"pw").err().unwrap_or_else(|| panic!("{bad}"));
            assert!(error.contains("sector size"), "{bad}: {error}");
        }
        let offset = format!("\"offset\":\"{data_offset}\"");
        let beyond = with_json(&image, &offset, &format!("\"offset\":\"{}\"", image.len() + 1));
        let unlocked = open(&beyond, b"pw").unwrap();
        assert_eq!(unlocked.volume_key, key);
        let error = unlocked.decrypt_data(&image).err().unwrap();
        assert!(error.contains("past the end"), "{error}");
        let huge = with_json(&image, "\"size\":\"dynamic\"",
                             "\"size\":\"18446744073709551615\"");
        let error = open(&huge, b"pw").unwrap().decrypt_data(&image).err().unwrap();
        assert!(error.contains("past memory"), "{error}");

        // LUKS1's stripes count multiplies into the keyslot area's
        // length, which has to lie inside the image.
        let params = small(1, "aes-xts-plain64", "pbkdf2", 512);
        let (mut image, _) = format(&params, b"pw", &[1u8; 4096], &mut counter_stream(3))
            .unwrap();
        image[208 + 44..208 + 48].copy_from_slice(&u32::MAX.to_be_bytes());
        let error = open(&image, b"pw").err().unwrap();
        assert!(error.contains("the image ends before"), "{error}");
    }

    /// A mandatory requirement (`config.requirements.mandatory`) is a
    /// feature cryptsetup refuses to open a volume without, and this
    /// example read past it: on a volume in the middle of reencryption it
    /// unlocked one key and decrypted the segment that key's digest names
    /// first - the hotzone, 1 MiB - as if it were the whole volume. No
    /// image here had a requirement, so nothing showed it. Reencryption
    /// ("online-reencrypt-v2") is read now, but a header that requires it
    /// must also have its reencrypt keyslot.
    #[test]
    fn test_a_mandatory_requirement_is_refused() {
        let params = small(2, "aes-xts-plain64", "pbkdf2", 512);
        let (image, _) = format(&params, b"pw", &[1u8; 4096], &mut counter_stream(3)).unwrap();
        let config = "\"config\":{";
        for (requirement, list) in [("online-reencrypt-v2", "[\"online-reencrypt-v2\"]"),
                                    ("something-new", "[\"something-new\"]")] {
            let changed = with_json(&image, config, &format!(
                "\"config\":{{\"requirements\":{{\"mandatory\":{list}}},"));
            let error = open(&changed, b"pw").err().unwrap();
            assert!(error.contains(requirement), "{error}");
        }
        // Present and empty, or without a mandatory list: nothing required.
        for empty in ["{\"mandatory\":[]}", "{}"] {
            let changed = with_json(&image, config, &format!(
                "\"config\":{{\"requirements\":{empty},"));
            assert!(open(&changed, b"pw").is_ok(), "{empty}");
        }
    }

    /// The volumes in `fixtures/luks-reencrypt.vec`: cryptsetup stopped
    /// in the middle of reencrypting them - cleanly, and by a crash
    /// before, during and after a hotzone's write, under checksum and
    /// journal resilience - and then repaired, finished and decrypted
    /// each to the recorded plaintext. Read as they were left, they must
    /// give that plaintext, with the old and new keys cryptsetup was given.
    #[test]
    fn test_cryptsetups_volumes_stopped_mid_reencryption() {
        let records = fixtures::records("luks-reencrypt.vec", "cryptsetup");
        assert_eq!(records.len(), 7);
        for record in &records {
            let name = fixtures::field(record, "name");
            let image = fixtures::expand(fixtures::field(record, "image"));
            let keys = [fixtures::unhex(fixtures::field(record, "old_key")),
                        fixtures::unhex(fixtures::field(record, "new_key"))];
            let mut ways = vec![open_with_keys(&image, &keys)];
            let passphrase = fixtures::field(record, "passphrase");
            if passphrase != "-" {
                ways.push(open(&image, passphrase.as_bytes()));
                assert!(open(&image, b"not the passphrase").is_err(), "{name}");
            }
            for unlocked in ways {
                let unlocked = unlocked.unwrap_or_else(|e| panic!("{name}: {e}"));
                let reencryption = unlocked.reencryption.as_ref().unwrap();
                assert_eq!((&reencryption.old.key, &unlocked.volume_key), (&keys[0], &keys[1]),
                           "{name}");
                let hotzone = reencryption.pieces.iter().any(|p| p.part == Part::Hotzone);
                assert_eq!(hotzone, fixtures::field(record, "state") != "no hotzone", "{name}");
                let data = unlocked.decrypt_data(&image).unwrap_or_else(|e| panic!("{name}: {e}"));
                let length: usize = fixtures::field(record, "data_length").parse().unwrap();
                assert_eq!(data.len(), length, "{name}");
                assert_eq!(hex(&hash("sha256", &[&data]).unwrap()),
                           fixtures::field(record, "data_sha256"), "{name}");
            }
        }
    }

    fn reencrypt_fixture(name: &str) -> (Vec<u8>, [Vec<u8>; 2]) {
        let record = fixtures::records("luks-reencrypt.vec", "cryptsetup").into_iter()
            .find(|r| fixtures::field(r, "name") == name).unwrap();
        (fixtures::expand(fixtures::field(&record, "image")),
         [fixtures::unhex(fixtures::field(&record, "old_key")),
          fixtures::unhex(fixtures::field(&record, "new_key"))])
    }

    /// The reencryption digest made again over the header as it now
    /// stands, with the keys: what someone holding them could write.
    fn redigest(image: &[u8], keys: &[Vec<u8>; 2]) -> Vec<u8> {
        let header = Luks2::parse(image).unwrap();
        let keyslots = header.json.field("keyslots").unwrap().entries().unwrap();
        let (id, keyslot) = keyslots.iter()
            .find(|(_, k)| k.field("type").unwrap().string().unwrap() == "reencrypt").unwrap();
        let segments = header.json.field("segments").unwrap().entries().unwrap();
        let flagged = |flag| &segments.iter().find(|(_, s)| Luks2::has_flag(s, flag)).unwrap().1;
        let input = Luks2::reencryption_digest_input(keyslot, flagged("backup-previous"),
                                                     flagged("backup-final"), &keys[0],
                                                     Some(&keys[1])).unwrap();
        let (_, digest) = header.digests_binding("keyslots", id).unwrap()[0];
        let old = digest.field("digest").unwrap().string().unwrap().to_string();
        let new = pbkdf2_any(digest.field("hash").unwrap().string().unwrap(), &input,
                             &allcrypt::pem::decode(digest.field("salt").unwrap().string()
                                 .unwrap()).unwrap(),
                             digest.field("iterations").unwrap().uint().unwrap() as u32,
                             32).unwrap();
        with_json(image, &format!("\"digest\":\"{old}\""),
                  &format!("\"digest\":\"{}\"", allcrypt::pem::encode(&new)))
    }

    /// The metadata the digest covers cannot be changed without the
    /// keys - the reencrypt keyslot's mode, direction and area, the backup
    /// segments - and the check is the digest, not the change: the same
    /// header with the digest made again over it opens.
    #[test]
    fn test_reencryption_metadata_is_bound_by_its_digest() {
        let (image, keys) = reencrypt_fixture("checksum-torn");
        assert!(open_with_keys(&image, &keys).is_ok());
        assert_eq!(open_with_keys(&redigest(&image, &keys), &keys).unwrap()
                       .decrypt_data(&image).unwrap(),
                   open_with_keys(&image, &keys).unwrap().decrypt_data(&image).unwrap());
        for (from, to) in [("\"direction\":\"forward\"", "\"direction\":\"backward\""),
                           ("\"hash\":\"sha512\"", "\"hash\":\"sha256\""),
                           ("\"type\":\"checksum\",\"hash\"", "\"type\":\"journal\",\"hash\""),
                           ("\"sector_size\":4096,\"flags\":[\"backup-final\"]",
                            "\"sector_size\":512,\"flags\":[\"backup-final\"]"),
                           ("\"iv_tweak\":\"0\",\"encryption\":\"aes-cbc-essiv:sha256\"",
                            "\"iv_tweak\":\"8\",\"encryption\":\"aes-cbc-essiv:sha256\"")] {
            let changed = with_json(&image, from, to);
            let error = open_with_keys(&changed, &keys).err().unwrap_or_else(|| panic!("{to}"));
            assert!(error.contains("does not match its digest"), "{to}: {error}");
            assert!(open_with_keys(&redigest(&changed, &keys), &keys).is_ok(), "{to}");
        }
        // A field the digest does not cover changes nothing.
        let extra = with_json(&image, "\"flags\":[\"backup-final\"]",
                              "\"flags\":[\"backup-final\"],\"x\":1");
        assert!(open_with_keys(&extra, &keys).is_ok());
    }

    /// What this does not read is refused by name, before any data is: an
    /// encryption or decryption in place, a reencryption that moves the
    /// data, the earlier and later requirement versions; and a volume
    /// stopped inside a hotzone with nothing to say which blocks were
    /// rewritten.
    #[test]
    fn test_reencryption_it_cannot_read_is_refused() {
        let (image, keys) = reencrypt_fixture("checksum-torn");
        for (from, to, expected) in [
                ("\"mode\":\"reencrypt\"", "\"mode\":\"encrypt\"", "being encrypted"),
                ("\"mode\":\"reencrypt\"", "\"mode\":\"decrypt\"", "being decrypted"),
                ("\"type\":\"checksum\"", "\"type\":\"datashift\"", "moves the data"),
                ("\"online-reencrypt-v2\"", "\"online-reencrypt\"", "cryptsetup 2.2"),
                ("\"online-reencrypt-v2\"", "\"online-reencrypt-v3\"", "moves the data"),
                ("\"online-reencrypt-v2\"", "\"online-reencrypt-v2\",\"x\"", "\"x\"")] {
            let error = open_with_keys(&with_json(&image, from, to), &keys).err()
                .unwrap_or_else(|| panic!("{to}"));
            assert!(error.contains(expected), "{to}: {error}");
        }
        // Resilience "none" with a hotzone, the digest made again so that
        // it is the hotzone that is refused.
        let none = with_json(&image, "\"type\":\"checksum\",\"hash\":\"sha512\",\"sector_size\":4096",
                             "\"type\":\"none\"");
        let unlocked = open_with_keys(&redigest(&none, &keys), &keys).unwrap();
        let error = unlocked.decrypt_data(&image).err().unwrap();
        assert!(error.contains("resilience \"none\""), "{error}");
    }

    /// Both keys are needed, each must match a digest, and the hotzone's
    /// protection data must fit its area.
    #[test]
    fn test_reencryption_needs_both_keys_and_its_area() {
        let (image, keys) = reencrypt_fixture("journal-torn");
        let error = open_with_keys(&image, &keys[..1]).err().unwrap();
        assert!(error.contains("new volume key") && error.contains("both keys"), "{error}");
        let error = open_with_keys(&image, &keys[1..]).err().unwrap();
        assert!(error.contains("old volume key"), "{error}");
        let error = open_with_keys(&image, &[keys[0].clone(), vec![7u8; 32]]).err().unwrap();
        assert!(error.contains("matches none"), "{error}");
        let small = redigest(&with_json(&image, "\"size\":\"294912\",\"type\":\"journal\"",
                                        "\"size\":\"4096\",\"type\":\"journal\""), &keys);
        let error = open_with_keys(&small, &keys).unwrap().decrypt_data(&image).err().unwrap();
        assert!(error.contains("does not fit"), "{error}");
    }
}
