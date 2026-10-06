//! Writing a BitLocker volume from a plaintext filesystem image: the
//! layout `fve.rs` reads, with a password protector, a recovery
//! password protector, a clear key, or any of them together.
//!
//! The three metadata copies and the relocated volume header go at the
//! end of the volume, in its last 200 KiB; the plaintext has to end
//! before them, since a reader sees zeros there. Everything else is
//! encrypted in place, the first `HEADER_SIZE` bytes at the relocated
//! header's position.
//!
//! Only the datums `fve.rs` and cryptsetup read are written. Windows
//! writes more (the protectors' timestamps, a stretch key's own
//! encrypted copy, a backup of the volume key) and nothing here has
//! shown that Windows accepts a volume without them.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::bitlocker::{Method, SectorCipher};
use allcrypt::block_ciphers::ccm;
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::hash_functions::HashFunction;
use allcrypt::kdf::password::{bitlocker_password_hash, bitlocker_recovery_key, bitlocker_stretch};

use crate::fve;

pub type Random<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

/// The relocated volume header's size, as Windows uses for NTFS.
pub const HEADER_SIZE: u64 = 8192;
/// What the end of the volume holds: three metadata areas and the
/// relocated header, all of which a reader sees as zeros.
pub const RESERVED: u64 = 3 * fve::METADATA_AREA + HEADER_SIZE;

const PROTECTION_PASSWORD: u16 = 0x2000;
const PROTECTION_RECOVERY: u16 = 0x0800;
const PROTECTION_CLEAR_KEY: u16 = 0x0000;
/// The encryption method recorded for a stretch key and for the VMK
/// itself: AES-CCM with a 256-bit key.
const METHOD_AES_CCM_256: u32 = 0x2005;

pub struct Format<'a> {
    pub method: Method,
    pub sector_size: u64,
    pub volume_size: u64,
    pub password: Option<&'a str>,
    pub recovery: Option<&'a str>,
    /// A clear key protector: the VMK sealed under a key stored beside
    /// it, which is what Windows writes while protection is suspended.
    /// Anyone holding the volume can read it.
    pub clear_key: bool,
    pub description: &'a str,
    /// 100 ns since 1601.
    pub created: u64,
}

fn datum(entry: u16, value: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&entry.to_le_bytes());
    out.extend_from_slice(&value.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// A key as BitLocker stores it before sealing: a key datum, with the
/// method the key is for.
fn key_datum(method: u32, key: &[u8]) -> Vec<u8> {
    datum(0, 1, &[&method.to_le_bytes()[..], key].concat())
}

/// AES-256-CCM, no associated data, laid out nonce, tag, ciphertext.
fn seal(key: &[u8], nonce: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    let (ciphertext, tag) = ccm::encrypt(&mut AesCrypto::new(key.to_vec())?, nonce, &[], plain,
                                         16)?;
    Ok([nonce, &tag, &ciphertext].concat())
}

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// A recovery password from 16 random bytes: each 16-bit word times 11,
/// six digits.
pub fn recovery_password(bytes: &[u8; 16]) -> String {
    bytes.chunks(2).map(|w| format!("{:06}", u32::from(u16::from_le_bytes([w[0], w[1]])) * 11))
        .collect::<Vec<_>>().join("-")
}

/// Write the volume. Returns it and the volume key in dm-crypt's form.
pub fn format(params: &Format<'_>, plain: &[u8], random: Random<'_>)
              -> Result<(Vec<u8>, Vec<u8>), String> {
    let (size, sector) = (params.volume_size, params.sector_size);
    if sector != 512 && sector != 4096 {
        return Err("The sector size is 512 or 4096.".to_string());
    }
    if !size.is_multiple_of(sector) || size < RESERVED + HEADER_SIZE + sector {
        return Err(format!("A volume of {size} bytes is not whole sectors with room for the \
                            metadata."));
    }
    let end = size - RESERVED;
    if plain.len() as u64 > end {
        return Err(format!("The data is {} bytes and {end} fit before the metadata.",
                           plain.len()));
    }
    if params.password.is_none() && params.recovery.is_none() && !params.clear_key {
        return Err("A volume needs a password, a recovery password or a clear key.".to_string());
    }
    let mut take = |n: usize| -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; n];
        random(&mut out)?;
        Ok(out)
    };
    let method = params.method;
    let vmk = take(32)?;
    let volume_key = take(method.key_len())?;
    // Elephant 128 is stored as CBC key, 16 unused, tweak key, 16 unused.
    let stored_key = if method == Method::AesCbcElephant128 {
        [&volume_key[..16], &[0; 16], &volume_key[16..], &[0; 16]].concat()
    } else {
        volume_key.clone()
    };
    let volume_guid = take(16)?;
    let offsets = [end, end + fve::METADATA_AREA, end + 2 * fve::METADATA_AREA];
    let header_offset = end + 3 * fve::METADATA_AREA;

    // Nonces: the creation time, then a counter, as Windows makes them.
    let mut counter = 0u32;
    let mut nonce = || {
        counter += 1;
        [&params.created.to_le_bytes()[..], &counter.to_le_bytes()].concat()
    };

    let mut entries = Vec::new();
    for (secret, protection) in [(params.password, PROTECTION_PASSWORD),
                                 (params.recovery, PROTECTION_RECOVERY)] {
        let Some(secret) = secret else { continue };
        let salt: [u8; 16] = take(16)?.try_into().unwrap();
        let initial = if protection == PROTECTION_PASSWORD {
            bitlocker_password_hash(secret)
        } else {
            let mut h = SHA256::new(&[]);
            h.update(&bitlocker_recovery_key(secret)?);
            h.digest().try_into().unwrap()
        };
        let key = bitlocker_stretch(&initial, &salt);
        let mut payload = take(16)?;
        payload.extend_from_slice(&params.created.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&protection.to_le_bytes());
        payload.extend(datum(0, 3, &[&METHOD_AES_CCM_256.to_le_bytes()[..], &salt].concat()));
        payload.extend(datum(0, 5, &seal(&key, &nonce(), &key_datum(METHOD_AES_CCM_256, &vmk))?));
        entries.extend(datum(2, 8, &payload));
    }
    if params.clear_key {
        let key = take(32)?;
        let mut payload = take(16)?;
        payload.extend_from_slice(&params.created.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&PROTECTION_CLEAR_KEY.to_le_bytes());
        payload.extend(datum(0, 1, &[&METHOD_AES_CCM_256.to_le_bytes()[..], &key].concat()));
        payload.extend(datum(0, 5, &seal(&key, &nonce(), &key_datum(METHOD_AES_CCM_256, &vmk))?));
        entries.extend(datum(2, 8, &payload));
    }
    entries.extend(datum(3, 5, &seal(&vmk, &nonce(),
                                     &key_datum(u32::from(method.code()), &stored_key))?));
    entries.extend(datum(0x000f, 0x000f, &[header_offset.to_le_bytes(),
                                           HEADER_SIZE.to_le_bytes()].concat()));
    entries.extend(datum(7, 2, &utf16z(params.description)));

    let metadata_size = 48 + entries.len();
    let block_size = (64 + metadata_size).next_multiple_of(16);
    let mut block = Vec::with_capacity(block_size);
    block.extend_from_slice(fve::SIGNATURE);
    block.extend_from_slice(&u16::try_from(block_size / 16).unwrap().to_le_bytes());
    block.extend_from_slice(&2u16.to_le_bytes());
    block.extend_from_slice(&fve::STATE_NORMAL.to_le_bytes());
    block.extend_from_slice(&fve::STATE_NORMAL.to_le_bytes());
    block.extend_from_slice(&size.to_le_bytes());
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&u32::try_from(HEADER_SIZE / sector).unwrap().to_le_bytes());
    for offset in offsets {
        block.extend_from_slice(&offset.to_le_bytes());
    }
    block.extend_from_slice(&header_offset.to_le_bytes());
    let metadata_size = u32::try_from(metadata_size).unwrap();
    block.extend_from_slice(&metadata_size.to_le_bytes());
    block.extend_from_slice(&1u32.to_le_bytes());
    block.extend_from_slice(&48u32.to_le_bytes());
    block.extend_from_slice(&metadata_size.to_le_bytes());
    block.extend_from_slice(&volume_guid);
    let next_nonce = nonce();
    block.extend_from_slice(&next_nonce[8..12]);
    block.extend_from_slice(&method.code().to_le_bytes());
    block.extend_from_slice(&0u16.to_le_bytes());
    block.extend_from_slice(&params.created.to_le_bytes());
    block.extend_from_slice(&entries);
    block.resize(block_size, 0);

    // The validation: the CRC-32, and the block's SHA-256 sealed with the
    // VMK in a nested structure of role 0, type 5.
    let mut h = SHA256::new(&[]);
    h.update(&block);
    let mut hash = Vec::with_capacity(44);
    for word in [44u16, 0, 1, 1, 0x2005, 0] {
        hash.extend_from_slice(&word.to_le_bytes());
    }
    hash.extend(h.digest());
    let sealed_hash = seal(&vmk, &nonce(), &hash)?;
    let mut area = block.clone();
    for word in [88u16, 2] {
        area.extend_from_slice(&word.to_le_bytes());
    }
    area.extend_from_slice(&allcrypt::checksum::crc32(&block).to_le_bytes());
    for word in [80u16, 0, 5, 1] {
        area.extend_from_slice(&word.to_le_bytes());
    }
    area.extend(sealed_hash);
    if area.len() as u64 > fve::METADATA_AREA {
        return Err("The metadata does not fit its 64 KiB.".to_string());
    }

    let mut image = vec![0u8; size as usize];
    let mut cipher = SectorCipher::new(method, &volume_key)?;
    let mut buffer = vec![0u8; sector as usize];
    let plain_sector = |position: u64, buffer: &mut [u8]| {
        buffer.fill(0);
        let start = (position as usize).min(plain.len());
        let stop = ((position + sector) as usize).min(plain.len());
        buffer[..stop - start].copy_from_slice(&plain[start..stop]);
    };
    // The filesystem's first sectors, at the relocated header's place.
    let mut position = 0;
    while position < HEADER_SIZE {
        plain_sector(position, &mut buffer);
        cipher.encrypt_sector(header_offset + position, &mut buffer)?;
        let at = (header_offset + position) as usize;
        image[at..at + sector as usize].copy_from_slice(&buffer);
        position += sector;
    }
    let mut position = HEADER_SIZE;
    while position < end {
        plain_sector(position, &mut buffer);
        cipher.encrypt_sector(position, &mut buffer)?;
        image[position as usize..(position + sector) as usize].copy_from_slice(&buffer);
        position += sector;
    }
    for offset in offsets {
        image[offset as usize..offset as usize + area.len()].copy_from_slice(&area);
    }
    // The boot sector: the jump, the signature, the sector size, and at
    // 160 the type GUID and the three offsets.
    image[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    image[3..11].copy_from_slice(fve::SIGNATURE);
    image[11..13].copy_from_slice(&u16::try_from(sector).unwrap().to_le_bytes());
    image[160..176].copy_from_slice(&fve::GUID_NORMAL);
    for (i, offset) in offsets.iter().enumerate() {
        image[176 + 8 * i..184 + 8 * i].copy_from_slice(&offset.to_le_bytes());
    }
    image[510..512].copy_from_slice(&[0x55, 0xaa]);
    Ok((image, volume_key))
}
