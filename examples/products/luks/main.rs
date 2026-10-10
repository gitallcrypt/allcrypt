//! LUKS1 and LUKS2 disk encryption, the format Linux's `cryptsetup`
//! writes, built from this library's primitives.
//!
//!     cargo run --release --example luks -- dump IMAGE
//!     cargo run --release --example luks -- open IMAGE PASSPHRASE [--volume-key] [--decrypt OUT]
//!     cargo run --release --example luks -- open IMAGE --passphrase-stdin [...]
//!     cargo run --release --example luks -- open IMAGE --key-file FILE [...]
//!     cargo run --release --example luks -- open IMAGE --key-file FILE ...
//!     cargo run --release --example luks -- format IMAGE PASSPHRASE [--type luks1|luks2]
//!         [--cipher aes-xts-plain64] [--key-size BITS] [--hash sha256]
//!         [--pbkdf pbkdf2|argon2i|argon2id] [--iterations N] [--memory KIB]
//!         [--parallel N] [--sector-size 512|4096] [--data FILE] [--seed N]
//!
//! `open` finds the keyslot the passphrase unlocks, recovers the volume
//! key, checks it against the header's digest, and with `--decrypt`
//! writes the decrypted data area. `format` writes a new image holding
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
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use json::{n, obj, s, Value};

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
                    self.data.cbc_encrypt(data, &mut out, iv)?;
                } else {
                    self.data.cbc_decrypt(data, &mut out, iv)?;
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
    keyslot: usize,
    volume_key: Vec<u8>,
    spec: CipherSpec,
    data_offset: usize,
    data_length: Option<usize>,
    sector_size: usize,
    iv_tweak: u64,
}

impl Unlocked {
    fn decrypt_data(&self, image: &[u8]) -> Result<Vec<u8>, String> {
        check_sector_size(self.sector_size)?;
        if self.data_offset > image.len() {
            return Err(format!("LUKS: the data starts at byte {}, past the end of the {} byte \
                                image.", self.data_offset, image.len()));
        }
        let end = match self.data_length {
            Some(length) => self.data_offset.checked_add(length)
                .ok_or("LUKS: the segment's offset and size add past memory.")?,
            None => image.len() - (image.len() - self.data_offset) % self.sector_size,
        };
        let mut data = read_at(image, self.data_offset, end - self.data_offset)?.to_vec();
        SectorCipher::new(&self.spec, &self.volume_key)?
            .crypt_area(self.iv_tweak, &mut data, self.sector_size, false)?;
        Ok(data)
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
                return Ok(Unlocked {
                    version: 1, keyslot: index, volume_key: candidate, spec: self.spec.clone(),
                    data_offset: self.payload_offset as usize * SECTOR, data_length: None,
                    sector_size: SECTOR, iv_tweak: 0,
                });
            }
        }
        Err("LUKS1: no keyslot opens with this passphrase.".to_string())
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

    fn open(&self, image: &[u8], passphrase: &[u8]) -> Result<Unlocked, String> {
        let keyslots = self.json.field("keyslots")?.entries()?;
        let digests = self.json.field("digests")?.entries()?;
        for (id, slot) in keyslots {
            if slot.field("type")?.as_str()? != "luks2" {
                continue;
            }
            let key_len = slot.field("key_size")?.as_u64()? as usize;
            let area = slot.field("area")?;
            let af = slot.field("af")?;
            let kdf = slot.field("kdf")?;
            let area_spec = CipherSpec::parse_joined(area.field("encryption")?.as_str()?)?;
            let area_key_len = area.field("key_size")?.as_u64()? as usize;
            let salt = allcrypt::pem::decode(kdf.field("salt")?.as_str()?)?;
            let area_key = match kdf.field("type")?.as_str()? {
                "pbkdf2" => pbkdf2_any(kdf.field("hash")?.as_str()?, passphrase, &salt,
                                       kdf.field("iterations")?.as_u64()? as u32, area_key_len)?,
                variant @ ("argon2i" | "argon2id") => {
                    let mut argon = Argon2::new(if variant == "argon2i" { Variant::I }
                                                else { Variant::Id });
                    argon.passes = kdf.field("time")?.as_u64()? as u32;
                    argon.memory_kib = kdf.field("memory")?.as_u64()? as u32;
                    argon.lanes = kdf.field("cpus")?.as_u64()? as u32;
                    argon.derive(passphrase, &salt, area_key_len)?
                }
                other => return Err(format!("LUKS2: keyslot {id} uses the KDF {other}.")),
            };
            let candidate = unlock_area(image, area.field("offset")?.as_u64()? as usize,
                                        &area_spec, &area_key, key_len,
                                        af.field("stripes")?.as_u64()? as usize,
                                        af.field("hash")?.as_str()?)?;
            // The digest bound to this keyslot decides.
            for (_, digest) in digests {
                let bound = digest.field("keyslots")?.items()?.iter()
                    .any(|k| k.as_str().ok() == Some(id.as_str()));
                if !bound || digest.field("type")?.as_str()? != "pbkdf2" {
                    continue;
                }
                let expected = allcrypt::pem::decode(digest.field("digest")?.as_str()?)?;
                let got = pbkdf2_any(digest.field("hash")?.as_str()?, &candidate,
                                     &allcrypt::pem::decode(digest.field("salt")?.as_str()?)?,
                                     digest.field("iterations")?.as_u64()? as u32,
                                     expected.len())?;
                if got == expected {
                    let segment_id = digest.field("segments")?.items()?.first()
                        .ok_or("LUKS2: the digest is bound to no segment.")?.as_str()?;
                    return self.unlocked(id, segment_id, candidate);
                }
            }
        }
        Err("LUKS2: no keyslot opens with this passphrase.".to_string())
    }

    fn unlocked(&self, keyslot: &str, segment_id: &str, volume_key: Vec<u8>)
                -> Result<Unlocked, String> {
        let segment = self.json.field("segments")?.field(segment_id)?;
        if segment.field("type")?.as_str()? != "crypt" {
            return Err("LUKS2: the segment is not a crypt segment.".to_string());
        }
        let size = segment.field("size")?;
        let sector_size = segment.field("sector_size")?.as_u64()?;
        check_sector_size(usize::try_from(sector_size).unwrap_or(0))?;
        Ok(Unlocked {
            version: 2,
            keyslot: keyslot.parse().unwrap_or(0),
            volume_key,
            spec: CipherSpec::parse_joined(segment.field("encryption")?.as_str()?)?,
            data_offset: segment.field("offset")?.as_u64()? as usize,
            data_length: if size.as_str().ok() == Some("dynamic") { None }
                         else { Some(size.as_u64()? as usize) },
            sector_size: sector_size as usize,
            iv_tweak: segment.field("iv_tweak")?.as_u64()?,
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
                 in place of PASSPHRASE";
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
            let passphrase = passphrase(args, &options, &flags)?;
            let unlocked = open(&image, &passphrase)?;
            println!("LUKS{} keyslot {} opened: {} sectors of {} bytes from byte {}",
                     unlocked.version, unlocked.keyslot, unlocked.spec.joined(),
                     unlocked.sector_size, unlocked.data_offset);
            if flags.iter().any(|f| f == "volume-key") {
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
                cipher.cbc_encrypt(&sector, &mut expected, iv).unwrap();
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
}
