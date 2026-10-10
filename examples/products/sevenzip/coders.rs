//! The methods a 7z folder chains together (`DOC/Methods.txt`): the
//! compressors, the branch and delta filters that go in front of them,
//! and 7zAES.
//!
//! 7zAES is AES-256-CBC under a key that is SHA-256 over 2^cycles
//! repetitions of salt, password and a counter. The password is UTF-16LE,
//! the counter eight bytes little endian, and there is no MAC: a wrong
//! password is noticed only when the data after it fails to decompress
//! or its CRC does not match.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::kdf::password::sevenzip_aes_key;

use crate::archive::{Coder, Folder, LIMIT};
use crate::{bunzip2, inflate, lzma};

pub const AES_ID: [u8; 4] = [0x06, 0xf1, 0x07, 0x01];
/// The most 7-Zip derives: 2^24 rounds.
const MAX_CYCLES: u8 = 24;
/// A raw key: salt and password copied in, no hashing at all.
const RAW_KEY: u8 = 0x3f;
/// What 7-Zip writes.
pub const DEFAULT_CYCLES: u8 = 19;

pub fn name(id: &[u8]) -> &'static str {
    match id {
        [0x00] => "Copy",
        [0x03, 0x01, 0x01] => "LZMA",
        [0x21] => "LZMA2",
        [0x03] => "Delta",
        [0x04] | [0x03, 0x03, 0x01, 0x03] => "BCJ",
        [0x05] | [0x03, 0x03, 0x02, 0x05] => "PPC",
        [0x06] | [0x03, 0x03, 0x04, 0x01] => "IA64",
        [0x07] | [0x03, 0x03, 0x05, 0x01] => "ARM",
        [0x08] | [0x03, 0x03, 0x07, 0x01] => "ARMT",
        [0x09] | [0x03, 0x03, 0x08, 0x05] => "SPARC",
        [0x0a] => "ARM64",
        [0x03, 0x03, 0x01, 0x1b] => "BCJ2",
        [0x03, 0x04, 0x01] => "PPMD",
        [0x04, 0x01, 0x08] => "Deflate",
        [0x04, 0x01, 0x09] => "Deflate64",
        [0x04, 0x02, 0x02] => "BZip2",
        [0x06, 0xf1, 0x07, 0x01] => "7zAES",
        _ => "unknown",
    }
}

pub fn is_aes(coder: &Coder) -> bool {
    coder.id == AES_ID
}

/// Decode a folder: start from the output nothing else consumes and
/// follow each coder's input either to another coder's output (a bind)
/// or to one of the folder's packed streams.
pub fn decode_folder(folder: &Folder, packed: &[&[u8]], password: Option<&[u8]>)
                     -> Result<Vec<u8>, String> {
    decode_output(folder, folder.main_output()?, packed, password, 0)
}

fn decode_output(folder: &Folder, output: usize, packed: &[&[u8]], password: Option<&[u8]>,
                 depth: usize) -> Result<Vec<u8>, String> {
    if depth > folder.coders.len() {
        return Err("7z: a folder whose binds form a loop.".to_string());
    }
    // Every coder here has one output, so output n is coder n's.
    let coder = folder.coders.get(output).ok_or("7z: a bind to an output that is not there.")?;
    if coder.inputs != 1 {
        return Err(format!("7z: {} takes {} inputs, and only single-input coders are \
                            supported.", name(&coder.id), coder.inputs));
    }
    let input: usize = folder.coders[..output].iter().map(|c| c.inputs).sum();
    let data = if let Some(&(_, from)) = folder.binds.iter().find(|(i, _)| *i == input) {
        decode_output(folder, from, packed, password, depth + 1)?
    } else {
        let at = folder.packed.iter().position(|&p| p == input)
            .ok_or("7z: a coder input that is neither bound nor packed.")?;
        packed.get(at).ok_or("7z: fewer packed streams than the folder uses.")?.to_vec()
    };
    let size = usize::try_from(folder.unpack_sizes[output]).ok().filter(|&s| s <= LIMIT)
        .ok_or("7z: a stream larger than this unpacks.")?;
    decode(coder, data, size, password)
}

fn decode(coder: &Coder, mut data: Vec<u8>, size: usize, password: Option<&[u8]>)
          -> Result<Vec<u8>, String> {
    let props = coder.properties.as_slice();
    let out = match name(&coder.id) {
        "Copy" => data,
        "LZMA" => lzma::decode_lzma(props, &data, size)?,
        "LZMA2" => lzma::decode_lzma2(props, &data, size)?,
        "Deflate" => inflate::inflate(&data, size)?.0,
        "BZip2" => bunzip2::decompress(&data, size)?,
        "7zAES" => {
            let password = password.ok_or("The archive is encrypted: give a password.")?;
            let mut out = aes_decrypt(props, password, &data)?;
            if out.len() < size {
                return Err("7zAES: less data than the declared size.".to_string());
            }
            out.truncate(size);
            out
        }
        "Delta" => {
            let [distance] = props else {
                return Err("Delta: properties are one byte.".to_string());
            };
            delta_decode(&mut data, usize::from(*distance) + 1);
            data
        }
        filter @ ("BCJ" | "PPC" | "IA64" | "ARM" | "ARMT" | "SPARC" | "ARM64") => {
            let pc = match props {
                [] => 0,
                [a, b, c, d] => u32::from_le_bytes([*a, *b, *c, *d]),
                _ => return Err(format!("{filter}: {} bytes of properties.", props.len())),
            };
            match filter {
                "BCJ" => x86_decode(&mut data, pc),
                "PPC" => ppc_decode(&mut data, pc),
                "ARM" => arm_decode(&mut data, pc),
                "ARMT" => armt_decode(&mut data, pc),
                "SPARC" => sparc_decode(&mut data, pc),
                "ARM64" => arm64_decode(&mut data, pc),
                _ => return Err("IA64: the branch filter is not supported.".to_string()),
            }
            data
        }
        "unknown" => {
            let id: String = coder.id.iter().map(|b| format!("{b:02x}")).collect();
            return Err(format!("7z: method {id} is not one this reads."));
        }
        other => return Err(format!("7z: the {other} method is not supported.")),
    };
    if out.len() != size {
        return Err(format!("{}: {} bytes where {size} were declared.", name(&coder.id),
                           out.len()));
    }
    Ok(out)
}

// -------------------------------------------------------------------- 7zAES --

struct AesParams {
    cycles: u8,
    salt: Vec<u8>,
    iv: [u8; 16],
}

/// The properties as `7zAes.cpp`'s decoder reads them: byte 0 is the
/// cycle count with 0x80 for a salt and 0x40 for an IV; byte 1's high
/// nibble adds to the salt's size and its low nibble to the IV's. An IV
/// shorter than sixteen bytes is padded with zeros.
fn aes_params(props: &[u8]) -> Result<AesParams, String> {
    let mut params = AesParams { cycles: 0, salt: Vec::new(), iv: [0; 16] };
    let Some(&b0) = props.first() else { return Ok(params) };
    params.cycles = b0 & 0x3f;
    if b0 & 0xc0 == 0 {
        if props.len() != 1 {
            return Err("7zAES: properties of the wrong length.".to_string());
        }
    } else {
        let b1 = *props.get(1).ok_or("7zAES: properties of the wrong length.")?;
        let salt_len = usize::from(b0 >> 7) + usize::from(b1 >> 4);
        let iv_len = usize::from((b0 >> 6) & 1) + usize::from(b1 & 0x0f);
        if props.len() != 2 + salt_len + iv_len {
            return Err("7zAES: properties of the wrong length.".to_string());
        }
        params.salt = props[2..2 + salt_len].to_vec();
        params.iv[..iv_len].copy_from_slice(&props[2 + salt_len..]);
    }
    if params.cycles > MAX_CYCLES && params.cycles != RAW_KEY {
        return Err(format!("7zAES: 2^{} rounds is more than 7-Zip allows.", params.cycles));
    }
    Ok(params)
}

fn utf16(password: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(password)
        .map_err(|_| "7zAES: the password is not UTF-8.".to_string())?;
    Ok(text.encode_utf16().flat_map(u16::to_le_bytes).collect())
}

/// Keys already derived, most recent first, as 7-Zip keeps them
/// (`CKeyInfoCache`): an archive stored with Copy has a folder per file,
/// each under the same salt and password, and the encrypted header is
/// under the same key as the data. Without it every folder pays for
/// 2^19 rounds again.
type CachedKey = (u8, Vec<u8>, Vec<u8>, [u8; 32]);
static KEYS: std::sync::Mutex<Vec<CachedKey>> = std::sync::Mutex::new(Vec::new());
const KEYS_KEPT: usize = 32;

/// The key: SHA-256 over 2^cycles copies of salt, password and the
/// round number, or for 0x3F the salt and password themselves, padded
/// with zeros to 32 bytes.
fn derive_key(cycles: u8, salt: &[u8], password: &[u8]) -> Result<[u8; 32], String> {
    let password = utf16(password)?;
    let found = KEYS.lock().ok().and_then(|keys| {
        keys.iter().find(|(c, s, p, _)| *c == cycles && s == salt && *p == password)
            .map(|k| k.3)
    });
    if let Some(key) = found {
        return Ok(key);
    }
    let key = sevenzip_aes_key(&password, salt, cycles)?;
    if let Ok(mut keys) = KEYS.lock() {
        keys.insert(0, (cycles, salt.to_vec(), password, key));
        keys.truncate(KEYS_KEPT);
    }
    Ok(key)
}

fn aes_decrypt(props: &[u8], password: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let params = aes_params(props)?;
    if !data.len().is_multiple_of(16) {
        return Err("7zAES: the data is not a whole number of blocks.".to_string());
    }
    let key = derive_key(params.cycles, &params.salt, password)?;
    let mut out = Vec::with_capacity(data.len());
    AesCrypto::new(&key)?.cbc_decrypt(data, &mut out, &params.iv)?;
    Ok(out)
}

/// Encrypt as 7-Zip does: no salt, a random sixteen-byte IV, the data
/// padded with zeros to a whole block. Returns the coder's properties
/// and the ciphertext.
pub fn aes_encrypt(data: &[u8], password: &[u8], cycles: u8) -> Result<(Vec<u8>, Vec<u8>), String> {
    if cycles > MAX_CYCLES && cycles != RAW_KEY {
        return Err(format!("7zAES: 2^{cycles} rounds is more than 7-Zip reads."));
    }
    let iv = allcrypt::api::random_bytes(16)?;
    let key = derive_key(cycles, &[], password)?;
    let mut padded = data.to_vec();
    padded.resize(data.len().next_multiple_of(16), 0);
    let mut out = Vec::with_capacity(padded.len());
    AesCrypto::new(&key)?.cbc_encrypt(&padded, &mut out, &iv)?;
    let mut props = vec![cycles | 0x40, 0x0f];
    props.extend_from_slice(&iv);
    Ok((props, out))
}

// ------------------------------------------------------------------ filters --

/// Delta: each byte was replaced by its difference from the byte
/// `distance` before it.
fn delta_decode(data: &mut [u8], distance: usize) {
    for i in distance..data.len() {
        data[i] = data[i].wrapping_add(data[i - distance]);
    }
}

/// x86 BCJ: the 32-bit operand of a CALL (E8) or JMP (E9) was made
/// absolute by adding its position; decoding subtracts it again. The
/// mask remembers E8/E9 bytes among the last three, which decide whether
/// an operand is converted - the classic `x86_Convert` of the LZMA SDK.
fn x86_decode(data: &mut [u8], start: u32) {
    const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
    const BIT: [usize; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
    let ms_byte = |b: u8| b == 0 || b == 0xff;
    if data.len() < 5 {
        return;
    }
    let ip = start.wrapping_add(5);
    let mut mask = 0usize;
    let mut pos = 0usize;
    let mut prev = usize::MAX;
    let limit = data.len() - 4;
    loop {
        while pos < limit && data[pos] & 0xfe != 0xe8 {
            pos += 1;
        }
        if pos >= limit {
            break;
        }
        let gap = pos.wrapping_sub(prev);
        if gap > 3 {
            mask = 0;
        } else {
            mask = (mask << (gap - 1)) & 7;
            if mask != 0 && (!ALLOWED[mask] || ms_byte(data[pos + 4 - BIT[mask]])) {
                prev = pos;
                mask = ((mask << 1) & 7) | 1;
                pos += 1;
                continue;
            }
        }
        prev = pos;
        if ms_byte(data[pos + 4]) {
            let mut src = u32::from_le_bytes([data[pos + 1], data[pos + 2], data[pos + 3],
                                              data[pos + 4]]);
            let mut dest;
            loop {
                dest = src.wrapping_sub(ip.wrapping_add(pos as u32));
                if mask == 0 {
                    break;
                }
                let index = BIT[mask] * 8;
                if !ms_byte((dest >> (24 - index)) as u8) {
                    break;
                }
                src = dest ^ ((1u32 << (32 - index)) - 1);
            }
            let top = if (dest >> 24) & 1 != 0 { 0xff } else { 0 };
            data[pos + 1..pos + 4].copy_from_slice(&dest.to_le_bytes()[..3]);
            data[pos + 4] = top;
            pos += 5;
        } else {
            mask = ((mask << 1) & 7) | 1;
            pos += 1;
        }
    }
}

/// ARM: BL instructions (top byte EB), a 24-bit word offset relative to
/// the instruction plus 8.
fn arm_decode(data: &mut [u8], start: u32) {
    for i in (0..data.len() & !3).step_by(4) {
        if data[i + 3] != 0xeb {
            continue;
        }
        let v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], 0]);
        let pc = start.wrapping_add(i as u32).wrapping_add(8);
        let v = (v.wrapping_sub(pc >> 2) & 0x00ff_ffff) | 0xeb00_0000;
        data[i..i + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// ARM Thumb: the BL pair, two halfwords F000-F7FF then F800-FFFF,
/// a 22-bit halfword offset relative to the instruction plus 4.
fn armt_decode(data: &mut [u8], start: u32) {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data[i + 1] & 0xf8 != 0xf0 || data[i + 3] & 0xf8 != 0xf8 {
            i += 2;
            continue;
        }
        let v = (u32::from(data[i + 1] & 7) << 19) | (u32::from(data[i]) << 11)
            | (u32::from(data[i + 3] & 7) << 8) | u32::from(data[i + 2]);
        let pc = start.wrapping_add(i as u32).wrapping_add(4);
        let v = v.wrapping_sub(pc >> 1);
        data[i + 1] = 0xf0 | ((v >> 19) & 7) as u8;
        data[i] = (v >> 11) as u8;
        data[i + 3] = 0xf8 | ((v >> 8) & 7) as u8;
        data[i + 2] = v as u8;
        i += 4;
    }
}

/// PowerPC, big endian: `bl` (opcode 18 with AA=0, LK=1), a 24-bit
/// word offset relative to the instruction.
fn ppc_decode(data: &mut [u8], start: u32) {
    for i in (0..data.len() & !3).step_by(4) {
        let v = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if v & 0xfc00_0003 != 0x4800_0001 {
            continue;
        }
        let pc = start.wrapping_add(i as u32);
        let v = (v.wrapping_sub(pc) & 0x03ff_ffff) | 0x4800_0000;
        data[i..i + 4].copy_from_slice(&v.to_be_bytes());
    }
}

/// SPARC: `call` whose 30-bit displacement is a sign-extended 22-bit
/// value, so only near calls are converted; `C/Bra.c`'s
/// `BranchConv_SPARC` without its rotate.
fn sparc_decode(data: &mut [u8], start: u32) {
    const FLAG: u32 = 1 << 22;
    for i in (0..data.len() & !3).step_by(4) {
        let mut v = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        // Top byte 0x40 with the next two bits clear, or 0x7F with them
        // set: the displacement's sign extension reaches bit 22.
        v = (v.wrapping_add(5 << 29) ^ (7 << 29)).wrapping_add(FLAG);
        if v & 0u32.wrapping_sub(FLAG << 1) != 0 {
            continue;
        }
        let pc = start.wrapping_add(i as u32);
        v = ((v << 2).wrapping_sub(pc) & ((FLAG << 3) - 1)).wrapping_sub(FLAG << 2);
        v = (v >> 2) | (1 << 30);
        data[i..i + 4].copy_from_slice(&v.to_be_bytes());
    }
}

/// ARM64: BL (a 26-bit word offset) and ADRP (a 21-bit page offset),
/// the latter converted only when it is within +-1 GiB; `C/Bra.c`'s
/// `BranchConv_ARM64`.
fn arm64_decode(data: &mut [u8], start: u32) {
    const FLAG: u32 = 1 << 20;
    const MASK: u32 = (1 << 24) - (FLAG << 1);
    for i in (0..data.len() & !3).step_by(4) {
        let mut v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let pc = start.wrapping_add(i as u32);
        if v.wrapping_sub(0x9400_0000) & 0xfc00_0000 == 0 {
            v = (v.wrapping_sub(pc >> 2) & 0x03ff_ffff) | 0x9400_0000;
            data[i..i + 4].copy_from_slice(&v.to_le_bytes());
            continue;
        }
        v = v.wrapping_sub(0x9000_0000);
        if v & 0x9f00_0000 != 0 {
            continue;
        }
        v = v.wrapping_add(FLAG);
        if v & MASK != 0 {
            continue;
        }
        let mut z = (v & 0xffff_ffe0) | (v >> 26);
        z = z.wrapping_sub((pc >> (12 - 3)) & !7);
        let out = (v & 0x1f) | 0x9000_0000 | (z << 26)
            | (0x00ff_ffe0 & (z & ((FLAG << 1) - 1)).wrapping_sub(FLAG));
        data[i..i + 4].copy_from_slice(&out.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_round_trips_and_a_wrong_password_gives_other_bytes() {
        let data: Vec<u8> = (0..100u8).collect();
        let (props, sealed) = aes_encrypt(&data, "pässword".as_bytes(), 4).unwrap();
        assert_eq!(props.len(), 18);
        assert_eq!(props[0], 0x44);
        assert_eq!(sealed.len(), 112);
        let mut opened = aes_decrypt(&props, "pässword".as_bytes(), &sealed).unwrap();
        opened.truncate(100);
        assert_eq!(opened, data);
        let mut wrong = aes_decrypt(&props, b"password", &sealed).unwrap();
        wrong.truncate(100);
        assert_ne!(wrong, data);
        // Zero is one round, not a default.
        let (props, sealed) = aes_encrypt(&data, b"pw", 0).unwrap();
        assert_eq!(props[0], 0x40);
        assert!(aes_decrypt(&props, b"pw", &sealed).unwrap().starts_with(&data));
        assert!(aes_encrypt(&data, b"pw", 25).is_err());
        assert_eq!(aes_encrypt(&data, b"pw", RAW_KEY).unwrap().0[0], 0x7f);
    }

    #[test]
    fn test_a_raw_key_is_salt_and_password_padded() {
        let key = derive_key(RAW_KEY, &[9, 8], b"ab").unwrap();
        let mut expected = [0u8; 32];
        expected[..6].copy_from_slice(&[9, 8, b'a', 0, b'b', 0]);
        assert_eq!(key, expected);
        // Cut at 32 bytes: with no salt, only sixteen characters count.
        // 7-Zip agrees (`scripts/check_sevenzip.py`, "AES raw key").
        assert_eq!(derive_key(RAW_KEY, &[], b"0123456789abcdefX").unwrap(),
                   derive_key(RAW_KEY, &[], b"0123456789abcdefY").unwrap());
    }

    /// The cache answers only for the same rounds, salt and password.
    #[test]
    fn test_the_key_cache_is_keyed_on_everything_that_makes_the_key() {
        let cases: [(u8, &[u8], &[u8]); 4] = [(5, b"salt", b"pw"), (5, b"salT", b"pw"),
                                               (6, b"salt", b"pw"), (5, b"salt", b"pW")];
        for _ in 0..2 {
            for (cycles, salt, password) in cases {
                let want = sevenzip_aes_key(&utf16(password).unwrap(), salt, cycles).unwrap();
                assert_eq!(derive_key(cycles, salt, password).unwrap(), want);
            }
        }
    }

    #[test]
    fn test_property_lengths_must_add_up() {
        assert!(aes_params(&[0x13]).is_ok());
        assert!(aes_params(&[0x13, 0]).is_err());
        assert!(aes_params(&[0x53, 0x0f]).is_err());
        let mut props = vec![0xd3, 0x3f];
        props.extend_from_slice(&[0; 4 + 16]);
        let params = aes_params(&props).unwrap();
        assert_eq!((params.cycles, params.salt.len()), (0x13, 4));
        assert!(aes_params(&[0x19]).is_err(), "2^25 rounds");
    }

    /// Each decoder checks its own length, and inflate stops where its
    /// stream does; the size a folder declares is checked once more
    /// here, whatever the method.
    #[test]
    fn test_a_stream_shorter_or_longer_than_declared_is_refused() {
        let copy = Coder { id: vec![0], inputs: 1, outputs: 1, properties: Vec::new() };
        assert!(decode(&copy, vec![1, 2, 3], 3, None).is_ok());
        for size in [2, 4] {
            let error = decode(&copy, vec![1, 2, 3], size, None).unwrap_err();
            assert!(error.contains("were declared"), "{error}");
        }
        // A stored deflate block of three bytes, declared as four.
        let deflate = Coder { id: vec![4, 1, 8], inputs: 1, outputs: 1, properties: Vec::new() };
        let stream = vec![1, 3, 0, 0xfc, 0xff, 7, 8, 9];
        assert_eq!(decode(&deflate, stream.clone(), 3, None).unwrap(), [7, 8, 9]);
        assert!(decode(&deflate, stream, 4, None).unwrap_err().contains("were declared"));
    }

    #[test]
    fn test_delta_undoes_differences() {
        let original: Vec<u8> = (0..50u32).map(|i| (i * i) as u8).collect();
        for distance in [1usize, 2, 4, 7] {
            let mut coded = original.clone();
            for i in (distance..coded.len()).rev() {
                coded[i] = coded[i].wrapping_sub(original[i - distance]);
            }
            delta_decode(&mut coded, distance);
            assert_eq!(coded, original);
        }
    }
}
