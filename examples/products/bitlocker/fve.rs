//! BitLocker's on-disk metadata: the boot sector, the three copies of
//! the FVE ("full volume encryption") metadata block, the datums inside
//! them, and how a password, a recovery password, a startup key file or
//! a clear key opens the volume master key (VMK), which opens the full
//! volume encryption key (FVEK).
//!
//! The layout as Windows writes it, version 2 (Windows 7 and later):
//!
//! - The boot sector starts `EB 58 90 "-FVE-FS-"`, or `"MSWIN4.1"` for
//!   BitLocker To Go on a FAT volume; the sector size is at byte 11. At
//!   byte 160 (To Go: 424) are a GUID and the three metadata offsets.
//! - Each metadata block: a 64-byte block header (signature, size in
//!   16-byte units, version 2, the current and next state, the volume
//!   size, the volume header's size and offset, the three offsets
//!   again), a 48-byte metadata header (size, the volume GUID, the
//!   encryption method, the creation time), then datums to the end.
//!   After the block, a validation structure: a CRC-32 of the block, and
//!   an AES-CCM-encrypted SHA-256 of it that only the VMK opens.
//! - A datum is `size, type, value type, version`, 16 bits each little
//!   endian, then its payload. A VMK datum holds nested datums: a
//!   stretch key's salt, and the VMK encrypted with AES-256-CCM (a
//!   12-byte nonce, the 16-byte tag, then the ciphertext).
//! - A decrypted key is itself a datum: 8 bytes of header, the 4-byte
//!   method, then the key.
//!
//! The volume as a reader sees it: the three metadata areas (64 KiB
//! each) and the area holding the relocated volume header read as zeros;
//! the first `volume_header_size` bytes are decrypted from that
//! relocated copy, at its own position's IV; everything else is
//! decrypted where it lies.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::bitlocker::Method;
use allcrypt::block_ciphers::ccm;
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::hash_functions::HashFunction;
use allcrypt::kdf::password::{bitlocker_password_hash, bitlocker_recovery_key, bitlocker_stretch};

pub const SIGNATURE: &[u8; 8] = b"-FVE-FS-";
pub const SIGNATURE_TOGO: &[u8; 8] = b"MSWIN4.1";
pub const METADATA_AREA: u64 = 64 * 1024;
const BLOCK_HEADER: usize = 64;
const METADATA_HEADER: usize = 48;
pub const STATE_NORMAL: u16 = 4;

pub const GUID_NORMAL: [u8; 16] = [0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a,
                                   0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01];
pub const GUID_EOW: [u8; 16] = [0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d,
                                0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8];

// Datum types and value types.
const ENTRY_PROPERTY: u16 = 0x0000;
const ENTRY_VMK: u16 = 0x0002;
const ENTRY_FVEK: u16 = 0x0003;
const ENTRY_STARTUP_KEY: u16 = 0x0006;
const ENTRY_DESCRIPTION: u16 = 0x0007;
const ENTRY_VOLUME_HEADER: u16 = 0x000f;
const ENTRY_VOLUME_GUID: u16 = 0x0019;
const VALUE_KEY: u16 = 0x0001;
const VALUE_STRING: u16 = 0x0002;
const VALUE_STRETCH_KEY: u16 = 0x0003;
const VALUE_ENCRYPTED_KEY: u16 = 0x0005;
const VALUE_EXTERNAL_KEY: u16 = 0x0009;
const VALUE_GUID: u16 = 0x0017;

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("Truncated at byte {at}."))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("Truncated at byte {at}."))
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, String> {
    b.get(at..at + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("Truncated at byte {at}."))
}

fn slice(b: &[u8], at: usize, len: usize) -> Result<&[u8], String> {
    b.get(at..at.checked_add(len).ok_or("Too long.")?)
        .ok_or_else(|| format!("{len} bytes at {at} run past the end."))
}

/// A GUID as Windows prints it: the first three fields little endian.
pub fn guid_string(g: &[u8]) -> String {
    format!("{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
            u32::from_le_bytes(g[0..4].try_into().unwrap()),
            u16::from_le_bytes([g[4], g[5]]), u16::from_le_bytes([g[6], g[7]]), g[8], g[9],
            g[10..16].iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks(2).filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units).trim_end_matches('\0').to_string()
}

/// One datum: its type, value type and payload (after the 8-byte header).
#[derive(Clone, Debug)]
pub struct Datum {
    pub entry: u16,
    pub value: u16,
    pub payload: Vec<u8>,
}

/// The datums in `bytes`, up to the end or a zero size.
pub fn datums(bytes: &[u8]) -> Result<Vec<Datum>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while bytes.len() - at >= 8 {
        let size = u16_at(bytes, at)? as usize;
        if size == 0 {
            break;
        }
        if size < 8 || size > bytes.len() - at {
            return Err(format!("A datum of {size} bytes at {at} does not fit."));
        }
        out.push(Datum { entry: u16_at(bytes, at + 2)?, value: u16_at(bytes, at + 4)?,
                         payload: bytes[at + 8..at + size].to_vec() });
        at += size;
    }
    Ok(out)
}

/// An AES-CCM-encrypted key: nonce, tag, ciphertext.
#[derive(Clone, Debug)]
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    fn parse(payload: &[u8]) -> Result<Sealed, String> {
        if payload.len() < 12 + 16 {
            return Err("An encrypted key datum shorter than its nonce and tag.".to_string());
        }
        Ok(Sealed { nonce: payload[..12].to_vec(), tag: payload[12..28].to_vec(),
                    ciphertext: payload[28..].to_vec() })
    }

    /// AES-256-CCM, no associated data.
    pub fn open(&self, key: &[u8]) -> Result<Vec<u8>, String> {
        let mut aes = AesCrypto::new(key)?;
        ccm::decrypt(&mut aes, &self.nonce, &[], &self.ciphertext, &self.tag)
            .map_err(|_| "The key does not open this (its AES-CCM tag does not verify).".to_string())
    }

    /// The key inside, which is a datum of its own: its size, which must
    /// be the whole of it, then 4 more bytes of header (the method), then
    /// the key.
    pub fn open_key(&self, key: &[u8]) -> Result<Vec<u8>, String> {
        let plain = self.open(key)?;
        if plain.len() < 12 || u16_at(&plain, 0)? as usize != plain.len() {
            return Err("The decrypted key's own size does not match.".to_string());
        }
        Ok(plain[12..].to_vec())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    ClearKey,
    Tpm,
    StartupKey,
    TpmPin,
    RecoveryPassword,
    SmartCard,
    Password,
    Other(u16),
}

impl Protection {
    fn from_code(code: u16) -> Protection {
        match code {
            0x0000 => Protection::ClearKey,
            0x0100 => Protection::Tpm,
            0x0200 => Protection::StartupKey,
            0x0500 => Protection::TpmPin,
            0x0800 => Protection::RecoveryPassword,
            0x1000 => Protection::SmartCard,
            0x2000 => Protection::Password,
            other => Protection::Other(other),
        }
    }

    pub fn describe(self) -> String {
        match self {
            Protection::ClearKey => "clear key".to_string(),
            Protection::Tpm => "TPM".to_string(),
            Protection::StartupKey => "startup key".to_string(),
            Protection::TpmPin => "TPM and PIN".to_string(),
            Protection::RecoveryPassword => "recovery password".to_string(),
            Protection::SmartCard => "smart card".to_string(),
            Protection::Password => "password".to_string(),
            Protection::Other(code) => format!("unknown ({code:#06x})"),
        }
    }
}

/// One protector of the volume master key.
#[derive(Clone)]
pub struct Vmk {
    pub guid: [u8; 16],
    pub protection: Protection,
    pub name: Option<String>,
    pub salt: Option<[u8; 16]>,
    pub sealed: Option<Sealed>,
    /// A clear key protector's key, which opens `sealed` with no secret.
    pub clear_key: Option<Vec<u8>>,
}

/// A clear key opens the volume, so it is not printed.
impl std::fmt::Debug for Vmk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vmk").field("guid", &self.guid).field("protection", &self.protection)
            .field("name", &self.name).field("salt", &self.salt).field("sealed", &self.sealed)
            .field("clear_key", &self.clear_key.as_deref().map(crate::hidden::HiddenBytes))
            .finish()
    }
}

impl Vmk {
    fn parse(payload: &[u8]) -> Result<Vmk, String> {
        // GUID, an 8-byte FILETIME, 2 unknown bytes, the protection.
        let header = slice(payload, 0, 28)?;
        let mut vmk = Vmk { guid: header[..16].try_into().unwrap(),
                            protection: Protection::from_code(u16_at(header, 26)?),
                            name: None, salt: None, sealed: None, clear_key: None };
        for datum in datums(&payload[28..])? {
            match datum.value {
                VALUE_STRETCH_KEY => {
                    // The stretch key's method (4 bytes), then the salt.
                    vmk.salt = Some(slice(&datum.payload, 4, 16)?.try_into().unwrap());
                }
                VALUE_ENCRYPTED_KEY => vmk.sealed = Some(Sealed::parse(&datum.payload)?),
                VALUE_KEY => vmk.clear_key = Some(slice(&datum.payload, 4, datum.payload.len()
                    .checked_sub(4).ok_or("A key datum too short for its method.")?)?.to_vec()),
                VALUE_STRING => vmk.name = Some(utf16le(&datum.payload)),
                _ => {}
            }
        }
        Ok(vmk)
    }
}

/// The parsed metadata.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub togo: bool,
    pub sector_size: u64,
    pub type_guid: [u8; 16],
    pub version: u16,
    pub current_state: u16,
    pub next_state: u16,
    pub volume_size: u64,
    pub offsets: [u64; 3],
    /// Which copy was read.
    pub copy: usize,
    pub volume_header_offset: u64,
    pub volume_header_size: u64,
    pub guid: [u8; 16],
    pub method_code: u16,
    pub creation_time: u64,
    pub description: Option<String>,
    pub vmks: Vec<Vmk>,
    pub fvek: Option<Sealed>,
    /// SHA-256 of the metadata block, which the validation hash must
    /// match.
    pub block_sha256: Vec<u8>,
    pub validation: Option<Sealed>,
}

impl Metadata {
    pub fn method(&self) -> Result<Method, String> {
        Method::from_code(self.method_code)
    }

    pub fn is_normal(&self) -> bool {
        self.type_guid == GUID_NORMAL
    }
}

/// Read the boot sector and the first metadata copy whose signature,
/// version, size and CRC-32 check, at the place its own offsets say.
pub fn read(image: &[u8]) -> Result<Metadata, String> {
    let boot = slice(image, 0, 512)?;
    let togo = match &boot[3..11] {
        s if s == SIGNATURE => false,
        s if s == SIGNATURE_TOGO => true,
        _ => return Err("Not a BitLocker volume: no -FVE-FS- or MSWIN4.1 signature.".to_string()),
    };
    match &boot[..3] {
        [0xeb, 0x58, 0x90] => {}
        [0xeb, 0x52, 0x90] => return Err("This is Windows Vista's BitLocker (version 1), which \
                                          is not read here.".to_string()),
        _ => return Err("Not a BitLocker boot sector: an unknown jump.".to_string()),
    }
    let sector_size = match u16_at(boot, 11)? {
        0 => 512,
        size @ (512 | 4096) => u64::from(size),
        other => return Err(format!("Sector size {other} is neither 512 nor 4096.")),
    };
    let at = if togo { 424 } else { 160 };
    let superblock = slice(boot, at, 40)?;
    let type_guid: [u8; 16] = superblock[..16].try_into().unwrap();
    let offsets = [u64_at(superblock, 16)?, u64_at(superblock, 24)?, u64_at(superblock, 32)?];

    let mut last = String::new();
    for (copy, &offset) in offsets.iter().enumerate() {
        match read_copy(image, offset, copy) {
            Ok(metadata) => {
                return Ok(Metadata { togo, sector_size, type_guid, ..metadata });
            }
            Err(reason) => last = format!("copy {copy} at {offset}: {reason}"),
        }
    }
    Err(format!("No metadata copy is valid ({last})."))
}

fn read_copy(image: &[u8], offset: u64, copy: usize) -> Result<Metadata, String> {
    let offset = usize::try_from(offset).map_err(|_| "An offset past the image.")?;
    let header = slice(image, offset, BLOCK_HEADER + METADATA_HEADER)?;
    if &header[..8] != SIGNATURE {
        return Err("no -FVE-FS- signature".to_string());
    }
    let size = u16_at(header, 8)? as usize * 16;
    let version = u16_at(header, 10)?;
    if version != 2 {
        return Err(format!("version {version}, where 2 is read"));
    }
    if size > METADATA_AREA as usize || size < BLOCK_HEADER + METADATA_HEADER {
        return Err(format!("a block of {size} bytes"));
    }
    let block = slice(image, offset, size)?;
    let validation = slice(image, offset + size, 8)?;
    if u16_at(validation, 0)? < 8 || u16_at(validation, 2)? > 2 {
        return Err("an unknown validation structure".to_string());
    }
    if allcrypt::checksum::crc32(block) != u32_at(validation, 4)? {
        return Err("its CRC-32 does not match".to_string());
    }
    let offsets = [u64_at(block, 32)?, u64_at(block, 40)?, u64_at(block, 48)?];
    if offsets[copy] != offset as u64 {
        return Err("it is not where its own offsets say it is".to_string());
    }
    // The validation hash, sealed with the VMK: a nested structure's
    // 8-byte header, then nonce, tag and 44 bytes.
    let validation_size = u16_at(validation, 0)? as usize;
    let sealed_validation = if validation_size >= 8 + 8 + 72 {
        let nested = slice(image, offset + size + 8, 8 + 72)?;
        Some(Sealed::parse(&nested[8..])?)
    } else {
        None
    };

    let metadata_size = u32_at(block, BLOCK_HEADER)? as usize;
    if metadata_size < METADATA_HEADER || BLOCK_HEADER + metadata_size > size {
        return Err(format!("metadata of {metadata_size} bytes in a {size}-byte block"));
    }
    let mut metadata = Metadata {
        togo: false, sector_size: 512, type_guid: [0; 16], version,
        current_state: u16_at(block, 12)?, next_state: u16_at(block, 14)?,
        volume_size: u64_at(block, 16)?, offsets, copy,
        // The block header's offset agrees with the volume header datum;
        // its size field counts sectors, so the datum's byte count is
        // what is used.
        volume_header_offset: u64_at(block, 56)?,
        volume_header_size: 0,
        guid: block[BLOCK_HEADER + 16..BLOCK_HEADER + 32].try_into().unwrap(),
        method_code: u16_at(block, BLOCK_HEADER + 36)?,
        creation_time: u64_at(block, BLOCK_HEADER + 40)?,
        description: None, vmks: Vec::new(), fvek: None,
        block_sha256: {
            let mut h = SHA256::new(&[]);
            h.update(block);
            h.digest()
        },
        validation: sealed_validation,
    };
    let entries = &block[BLOCK_HEADER + METADATA_HEADER..BLOCK_HEADER + metadata_size];
    for datum in datums(entries)? {
        match datum.entry {
            ENTRY_VMK => metadata.vmks.push(Vmk::parse(&datum.payload)?),
            ENTRY_FVEK if metadata.fvek.is_none() => {
                metadata.fvek = Some(Sealed::parse(&datum.payload)?);
            }
            ENTRY_VOLUME_HEADER => {
                metadata.volume_header_offset = u64_at(&datum.payload, 0)?;
                metadata.volume_header_size = u64_at(&datum.payload, 8)?;
            }
            ENTRY_DESCRIPTION if metadata.description.is_none() => {
                metadata.description = Some(utf16le(&datum.payload));
            }
            _ => {}
        }
    }
    Ok(metadata)
}

/// What a protector is opened with.
pub enum Secret<'a> {
    Password(&'a str),
    RecoveryPassword(&'a str),
    /// A `.BEK` startup key file's contents.
    StartupKey(&'a [u8]),
    /// No secret: a clear key protector, as a suspended or partly
    /// decrypted volume has.
    ClearKey,
}

/// A startup key file: a 48-byte header naming the protector's GUID,
/// then one datum holding the external key.
fn startup_key(file: &[u8], vmk: &Vmk, volume_guid: &[u8; 16]) -> Result<Option<Vec<u8>>, String> {
    let header = slice(file, 0, 48)?;
    if header[16..32] != vmk.guid {
        return Ok(None);
    }
    if u32_at(header, 4)? != 1 {
        return Err(format!("A startup key file of version {}, where 1 is read.",
                           u32_at(header, 4)?));
    }
    if u32_at(header, 0)? as usize != file.len() {
        return Err("The startup key file's stated size is not its length.".to_string());
    }
    let datum = datums(&file[48..])?.into_iter().next()
        .ok_or("A startup key file with no key in it.")?;
    if datum.entry != ENTRY_STARTUP_KEY || datum.value != VALUE_EXTERNAL_KEY {
        return Err("A startup key file whose datum is not an external key.".to_string());
    }
    // A 24-byte header (a GUID and a FILETIME), then the nested datums.
    for nested in datums(slice(&datum.payload, 24, datum.payload.len().saturating_sub(24))?)? {
        if nested.entry != ENTRY_PROPERTY && nested.entry != ENTRY_VOLUME_GUID {
            return Err("An unexpected datum in the startup key file.".to_string());
        }
        match nested.value {
            VALUE_KEY => return Ok(Some(slice(&nested.payload, 4, nested.payload.len()
                .checked_sub(4).ok_or("A key datum too short for its method.")?)?.to_vec())),
            VALUE_GUID if nested.payload.get(..16) != Some(&volume_guid[..]) => {
                return Err("The startup key file is for a different volume.".to_string());
            }
            _ => {}
        }
    }
    Err("A startup key file with no key in it.".to_string())
}

/// The key that opens this protector's sealed VMK, if the secret is the
/// right kind for it.
fn protector_key(vmk: &Vmk, secret: &Secret<'_>, volume_guid: &[u8; 16])
                 -> Result<Option<Vec<u8>>, String> {
    let salt = || vmk.salt.ok_or("A password protector with no salt.".to_string());
    Ok(match (vmk.protection, secret) {
        (Protection::Password, Secret::Password(password)) =>
            Some(bitlocker_stretch(&bitlocker_password_hash(password), &salt()?).to_vec()),
        (Protection::RecoveryPassword, Secret::RecoveryPassword(recovery)) => {
            let key = bitlocker_recovery_key(recovery)?;
            let mut h = SHA256::new(&[]);
            h.update(&key);
            let initial: [u8; 32] = h.digest().try_into().unwrap();
            Some(bitlocker_stretch(&initial, &salt()?).to_vec())
        }
        (Protection::StartupKey, Secret::StartupKey(file)) => startup_key(file, vmk, volume_guid)?,
        (Protection::ClearKey, Secret::ClearKey) => vmk.clear_key.clone(),
        _ => None,
    })
}

/// What opening found: which protector opened, and the volume key in
/// dm-crypt's form (for Elephant 128, the CBC key and the tweak
/// key from their separate halves of the stored 64 bytes).
pub struct Opened {
    pub protector: usize,
    pub volume_key: Vec<u8>,
}

/// Open the volume key with `secret`, trying every protector it fits.
/// The VMK must also open the validation hash, and that must be the
/// metadata block's own hash: a VMK that opens is the right one, and the
/// metadata it came from is what Windows wrote.
pub fn open(metadata: &Metadata, secret: &Secret<'_>) -> Result<Opened, String> {
    let fvek = metadata.fvek.as_ref().ok_or("No volume key in the metadata.")?;
    let method = metadata.method()?;
    let mut tried = 0;
    let mut last = String::from("no protector of that kind");
    for (index, vmk) in metadata.vmks.iter().enumerate() {
        let Some(key) = protector_key(vmk, secret, &metadata.guid)? else { continue };
        tried += 1;
        let Some(sealed) = &vmk.sealed else { continue };
        let vmk_key = match sealed.open_key(&key) {
            Ok(k) => k,
            Err(reason) => {
                last = reason;
                continue;
            }
        };
        if let Some(validation) = &metadata.validation {
            let hash = validation.open(&vmk_key)?;
            // size, role, type, flags, hash type, unknown; then SHA-256.
            if hash.len() < 44 || u16_at(&hash, 8)? != 0x2005 {
                return Err("An unknown kind of validation hash.".to_string());
            }
            if hash[12..44] != metadata.block_sha256[..] {
                return Err("The metadata's validation hash does not match: the metadata was \
                            changed after Windows wrote it.".to_string());
            }
        }
        let stored = fvek.open_key(&vmk_key)?;
        let volume_key = match method {
            // 16 bytes of CBC key, 16 unused, 16 of tweak key, 16 unused.
            allcrypt::block_ciphers::bitlocker::Method::AesCbcElephant128 if stored.len() >= 48 =>
                [&stored[..16], &stored[32..48]].concat(),
            _ => stored.get(..method.key_len())
                .ok_or("The stored volume key is shorter than its method needs.")?.to_vec(),
        };
        return Ok(Opened { protector: index, volume_key });
    }
    if tried == 0 {
        return Err("No protector of this volume takes that kind of secret.".to_string());
    }
    Err(format!("The secret opens no protector ({last})."))
}
