//! Password-protected ZIP archives - traditional PKWARE encryption
//! ("ZipCrypto") and WinZip AES (AE-1 and AE-2) - built from this
//! library's primitives.
//!
//!     cargo run --release --example zip -- list ARCHIVE
//!     cargo run --release --example zip -- extract ARCHIVE DIR [--password PW]
//!     cargo run --release --example zip -- create OUT FILE... [--password PW]
//!             [--encryption none|zipcrypto|aes128|aes192|aes256] [--ae 1|2]
//!
//! `--password-stdin` in place of `--password PW` reads it from
//! standard input. `create` stores the files uncompressed; `extract`
//! reads stored, deflated and bzip2 entries, ZIP64 included, and
//! refuses a name that would land outside DIR.
//!
//! What has checked it is in `examples/products/README.md`.

mod crypto;

#[path = "../shared/bunzip2.rs"]
mod bunzip2;
#[path = "../shared/inflate.rs"]
mod inflate;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use std::path::{Component, Path, PathBuf};

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const END64: u32 = 0x0606_4b50;
const LOCATOR64: u32 = 0x0706_4b50;
const AES_METHOD: u16 = 99;
const AES_EXTRA: u16 = 0x9901;
const ZIP64_EXTRA: u16 = 0x0001;
/// Larger than this is refused rather than allocated.
const LIMIT: usize = 1 << 31;

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], at: usize) -> Cursor<'a> {
        Cursor { data, at }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.data.len())
            .ok_or("The archive ends early.")?;
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap_or([0; 2])))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap_or([0; 4])))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap_or([0; 8])))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Encryption {
    None,
    ZipCrypto,
    /// Vendor version (1 = AE-1, 2 = AE-2), strength (1, 2, 3) and the
    /// real compression method.
    Aes { version: u16, strength: u8, method: u16 },
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub flags: u16,
    pub method: u16,
    pub time: u16,
    pub crc: u32,
    pub compressed: u64,
    pub size: u64,
    pub offset: u64,
    pub encryption: Encryption,
}

fn extras(data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(data, 0);
    while let (Ok(id), Ok(len)) = (cursor.u16(), cursor.u16()) {
        match cursor.take(usize::from(len)) {
            Ok(value) => out.push((id, value)),
            Err(_) => break,
        }
    }
    out
}

/// The central directory, read from the end-of-central-directory
/// record (and its ZIP64 counterpart when a field is saturated).
pub fn entries(archive: &[u8]) -> Result<Vec<Entry>, String> {
    let lowest = archive.len().saturating_sub(22 + 0xffff);
    let end = (lowest..archive.len().saturating_sub(21)).rev()
        .find(|&at| archive[at..at + 4] == END.to_le_bytes())
        .ok_or("No end-of-central-directory record: not a ZIP archive.")?;
    let mut cursor = Cursor::new(archive, end + 4);
    let (disk, _, _, total) = (cursor.u16()?, cursor.u16()?, cursor.u16()?, cursor.u16()?);
    let (mut size, mut offset) = (u64::from(cursor.u32()?), u64::from(cursor.u32()?));
    let mut count = u64::from(total);
    if disk != 0 && disk != 0xffff {
        return Err("A multi-disk (spanned) archive, which is not supported.".to_string());
    }
    if total == 0xffff || size == 0xffff_ffff || offset == 0xffff_ffff {
        let locator = end.checked_sub(20).ok_or("A ZIP64 archive with no locator.")?;
        let mut cursor = Cursor::new(archive, locator);
        if cursor.u32()? != LOCATOR64 {
            return Err("A saturated end record and no ZIP64 locator.".to_string());
        }
        cursor.u32()?;
        let record = cursor.u64()? as usize;
        let mut cursor = Cursor::new(archive, record);
        if cursor.u32()? != END64 {
            return Err("The ZIP64 locator points at no ZIP64 end record.".to_string());
        }
        cursor.take(8 + 2 + 2 + 4 + 4 + 8)?;
        count = cursor.u64()?;
        size = cursor.u64()?;
        offset = cursor.u64()?;
    }
    let directory = archive.get(offset as usize..(offset + size) as usize)
        .ok_or("The central directory lies outside the archive.")?;
    let mut cursor = Cursor::new(directory, 0);
    let mut out = Vec::new();
    for _ in 0..count {
        if cursor.u32()? != CENTRAL {
            return Err("A central directory entry without its signature.".to_string());
        }
        cursor.take(4)?;
        let flags = cursor.u16()?;
        let method = cursor.u16()?;
        let time = cursor.u16()?;
        cursor.u16()?;
        let crc = cursor.u32()?;
        let mut compressed = u64::from(cursor.u32()?);
        let mut size = u64::from(cursor.u32()?);
        let (name_len, extra_len, comment_len) = (cursor.u16()?, cursor.u16()?, cursor.u16()?);
        cursor.take(8)?;
        let mut offset = u64::from(cursor.u32()?);
        let raw_name = cursor.take(usize::from(name_len))?;
        let extra = cursor.take(usize::from(extra_len))?;
        cursor.take(usize::from(comment_len))?;
        // UTF-8 when flag 11 says so; otherwise CP437, which agrees
        // with UTF-8 on ASCII and is shown lossily beyond it.
        let name = String::from_utf8_lossy(raw_name).into_owned();
        let mut encryption = if flags & 1 != 0 { Encryption::ZipCrypto } else { Encryption::None };
        for (id, value) in extras(extra) {
            if id == ZIP64_EXTRA {
                let mut z = Cursor::new(value, 0);
                if size == 0xffff_ffff {
                    size = z.u64()?;
                }
                if compressed == 0xffff_ffff {
                    compressed = z.u64()?;
                }
                if offset == 0xffff_ffff {
                    offset = z.u64()?;
                }
            }
            if id == AES_EXTRA && method == AES_METHOD {
                let mut a = Cursor::new(value, 0);
                let version = a.u16()?;
                if a.take(2)? != b"AE" {
                    return Err(format!("{name}: an AES extra field without \"AE\"."));
                }
                let strength = a.take(1)?[0];
                encryption = Encryption::Aes { version, strength, method: a.u16()? };
            }
        }
        if flags & 0x40 != 0 {
            return Err(format!("{name}: PKWARE strong encryption, which is not supported."));
        }
        if method == AES_METHOD && !matches!(encryption, Encryption::Aes { .. }) {
            return Err(format!("{name}: method 99 without its AES extra field."));
        }
        out.push(Entry { name, flags, method, time, crc, compressed, size, offset, encryption });
    }
    Ok(out)
}

/// An entry's plaintext, decrypted, decompressed and checked.
pub fn read(archive: &[u8], entry: &Entry, password: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut cursor = Cursor::new(archive, entry.offset as usize);
    if cursor.u32()? != LOCAL {
        return Err(format!("{}: no local header where the directory says.", entry.name));
    }
    cursor.take(22)?;
    let (name_len, extra_len) = (cursor.u16()?, cursor.u16()?);
    cursor.take(usize::from(name_len) + usize::from(extra_len))?;
    let raw = cursor.take(usize::try_from(entry.compressed).map_err(|_| "Too large.")?)?;

    let need = || password.ok_or(format!("{} is encrypted: give a password.", entry.name));
    let (data, method, check_crc) = match &entry.encryption {
        Encryption::None => (raw.to_vec(), entry.method, true),
        Encryption::ZipCrypto => {
            // With a data descriptor the CRC was not known when the
            // header was encrypted, so the check byte is the time's.
            let check = if entry.flags & 8 != 0 { (entry.time >> 8) as u8 }
                        else { (entry.crc >> 24) as u8 };
            (crypto::zipcrypto_open(need()?, raw, check)
                .map_err(|e| format!("{}: {e}", entry.name))?, entry.method, true)
        }
        Encryption::Aes { version, strength, method } => {
            (crypto::aes_open(need()?, *strength, raw).map_err(|e| format!("{}: {e}", entry.name))?,
             *method, *version != 2)
        }
    };
    let plain = match method {
        0 => data,
        8 => inflate::inflate(&data, LIMIT)?.0,
        12 => bunzip2::decompress(&data, LIMIT)?,
        other => return Err(format!("{}: compression method {other} is not supported.",
                                    entry.name)),
    };
    if plain.len() as u64 != entry.size {
        return Err(format!("{}: {} bytes, where the directory says {}.", entry.name,
                           plain.len(), entry.size));
    }
    if check_crc && allcrypt::checksum::crc32(&plain) != entry.crc {
        return Err(format!("{}: the CRC-32 does not match{}.", entry.name,
                           if entry.encryption == Encryption::ZipCrypto
                           { " - most likely a wrong password that passed the one-byte check" }
                           else { "" }));
    }
    Ok(plain)
}

/// Where an entry may be written under `root`, or an error for a name
/// that is absolute or climbs out with `..` ("zip slip").
fn destination(root: &Path, name: &str) -> Result<PathBuf, String> {
    let relative = Path::new(name);
    let mut out = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(format!("{name}: a name that leaves the destination.")),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- write --

pub enum Sealing {
    None,
    ZipCrypto,
    Aes { version: u16, strength: u8 },
}

fn dos_time() -> (u16, u16) {
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let days = (unix / 86400) as i64;
    let seconds = unix % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = (yoe + era * 400 + i64::from(month <= 2)).clamp(1980, 2107);
    let time = ((seconds / 3600) << 11) | ((seconds / 60 % 60) << 5) | (seconds % 60 / 2);
    let date = ((year - 1980) << 9) | (month << 5) | day;
    (time as u16, date as u16)
}

/// A whole archive of stored entries.
pub fn write(files: &[(String, Vec<u8>)], sealing: &Sealing, password: &[u8])
             -> Result<Vec<u8>, String> {
    let (time, date) = dos_time();
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (name, data) in files {
        let crc = allcrypt::checksum::crc32(data);
        let (body, method, flags, version, stored_crc, extra) = match sealing {
            Sealing::None => (data.clone(), 0u16, 0u16, 10u16, crc, Vec::new()),
            Sealing::ZipCrypto => (crypto::zipcrypto_seal(password, data, crc)?, 0, 1, 20, crc,
                                   Vec::new()),
            Sealing::Aes { version, strength } => {
                let mut extra = Vec::new();
                extra.extend_from_slice(&AES_EXTRA.to_le_bytes());
                extra.extend_from_slice(&7u16.to_le_bytes());
                extra.extend_from_slice(&version.to_le_bytes());
                extra.extend_from_slice(b"AE");
                extra.push(*strength);
                extra.extend_from_slice(&0u16.to_le_bytes());
                (crypto::aes_seal(password, *strength, data)?, AES_METHOD, 1, 51,
                 if *version == 2 { 0 } else { crc }, extra)
            }
        };
        let flags = flags | if name.is_ascii() { 0 } else { 0x800 };
        let compressed = u32::try_from(body.len()).map_err(|_| "Entries over 4 GiB need ZIP64, \
                                                              which this does not write.")?;
        let size = data.len() as u32;
        let offset = u32::try_from(out.len()).map_err(|_| "An archive over 4 GiB.")?;
        let mut fields = Vec::new();
        for value in [flags, method, time, date] {
            fields.extend_from_slice(&value.to_le_bytes());
        }
        for value in [stored_crc, compressed, size] {
            fields.extend_from_slice(&value.to_le_bytes());
        }
        fields.extend_from_slice(&(name.len() as u16).to_le_bytes());
        fields.extend_from_slice(&(extra.len() as u16).to_le_bytes());

        out.extend_from_slice(&LOCAL.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&fields);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&extra);
        out.extend_from_slice(&body);

        directory.extend_from_slice(&CENTRAL.to_le_bytes());
        directory.extend_from_slice(&(0x0300 | version).to_le_bytes()); // made by Unix
        directory.extend_from_slice(&version.to_le_bytes());
        directory.extend_from_slice(&fields);
        directory.extend_from_slice(&0u16.to_le_bytes()); // comment
        directory.extend_from_slice(&0u16.to_le_bytes()); // disk
        directory.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        directory.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
        directory.extend_from_slice(&extra);
    }
    let start = out.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(&END.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    let count = u16::try_from(files.len()).map_err(|_| "Over 65535 entries need ZIP64.")?;
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

// ------------------------------------------------------------------ CLI --

fn password(args: &[String]) -> Result<Option<Vec<u8>>, String> {
    if args.iter().any(|a| a == "--password-stdin") {
        return passphrase::read_line("Password: ").map(Some);
    }
    Ok(args.iter().position(|a| a == "--password")
        .and_then(|i| args.get(i + 1)).map(|p| p.as_bytes().to_vec()))
}

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn positional(args: &[String]) -> Vec<&String> {
    let mut out = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
        } else if arg == "--password-stdin" {
        } else if arg.starts_with("--") {
            skip = true;
        } else {
            out.push(arg);
        }
    }
    out
}

fn describe(entry: &Entry) -> String {
    let method = |m: u16| match m {
        0 => "stored".to_string(),
        8 => "deflate".to_string(),
        12 => "bzip2".to_string(),
        other => format!("method {other}"),
    };
    match &entry.encryption {
        Encryption::None => method(entry.method),
        Encryption::ZipCrypto => format!("{}, ZipCrypto", method(entry.method)),
        Encryption::Aes { version, strength, method: m } => {
            format!("{}, AES-{} (AE-{version})", method(*m), 64 + 64 * u32::from(*strength))
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let archive_path = names.first().ok_or("Name the archive.")?;
    match command {
        "list" => {
            let archive = std::fs::read(archive_path).map_err(|e| format!("{archive_path}: {e}"))?;
            for entry in entries(&archive)? {
                println!("{:>10}  {:<28}  {}", entry.size, describe(&entry), entry.name);
            }
            Ok(())
        }
        "extract" => {
            let archive = std::fs::read(archive_path).map_err(|e| format!("{archive_path}: {e}"))?;
            let root = Path::new(names.get(1).ok_or("Name the destination directory.")?);
            let password = password(rest)?;
            for entry in entries(&archive)? {
                let target = destination(root, &entry.name)?;
                if entry.name.ends_with('/') {
                    std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
                    continue;
                }
                let data = read(&archive, &entry, password.as_deref())?;
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                std::fs::write(&target, data).map_err(|e| format!("{}: {e}", target.display()))?;
                println!("{}", entry.name);
            }
            Ok(())
        }
        "create" => {
            let sealing = match value(rest, "--encryption").unwrap_or("aes256") {
                "none" => Sealing::None,
                "zipcrypto" => Sealing::ZipCrypto,
                bits @ ("aes128" | "aes192" | "aes256") => Sealing::Aes {
                    version: value(rest, "--ae").unwrap_or("2").parse()
                        .map_err(|_| "--ae is 1 or 2")?,
                    strength: match bits { "aes128" => 1, "aes192" => 2, _ => 3 },
                },
                other => return Err(format!("Unknown encryption {other}.")),
            };
            let password = password(rest)?.unwrap_or_default();
            if !matches!(sealing, Sealing::None) && password.is_empty() {
                return Err("Encryption needs a --password or --password-stdin.".to_string());
            }
            let mut files = Vec::new();
            for name in &names[1..] {
                let data = std::fs::read(name).map_err(|e| format!("{name}: {e}"))?;
                files.push((name.trim_start_matches('/').to_string(), data));
            }
            let bytes = write(&files, &sealing, &password)?;
            std::fs::write(archive_path, bytes).map_err(|e| format!("{archive_path}: {e}"))
        }
        _ => Err("usage: zip list|extract|create ...".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("zip: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<(String, Vec<u8>)> {
        vec![
            ("empty".to_string(), Vec::new()),
            ("one".to_string(), b"x".to_vec()),
            ("dir/sixteen".to_string(), (0..16).collect()),
            ("caf\u{e9}.txt".to_string(), (0..1000u32).map(|i| (i * 7) as u8).collect()),
        ]
    }

    #[test]
    fn test_every_sealing_round_trips() {
        for sealing in [Sealing::None, Sealing::ZipCrypto,
                        Sealing::Aes { version: 1, strength: 1 },
                        Sealing::Aes { version: 2, strength: 2 },
                        Sealing::Aes { version: 2, strength: 3 }] {
            let archive = write(&sample(), &sealing, b"pw").unwrap();
            let listed = entries(&archive).unwrap();
            assert_eq!(listed.len(), 4);
            for (entry, (name, data)) in listed.iter().zip(sample()) {
                assert_eq!(entry.name, name);
                assert_eq!(read(&archive, entry, Some(b"pw")).unwrap(), data);
                if !matches!(sealing, Sealing::None) {
                    assert!(read(&archive, entry, Some(b"wrong")).is_err());
                    assert!(read(&archive, entry, None).is_err());
                }
            }
        }
    }

    fn sha256(data: &[u8]) -> String {
        use allcrypt::hash_functions::HashFunction;
        let mut hash = allcrypt::hash_functions::sha2::SHA256::new(&[]);
        hash.update(data);
        hash.digest().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Every archive `scripts/check_zip.py --record` kept - Info-ZIP's,
    /// libarchive's and 7-Zip's, under ZipCrypto (with and without data
    /// descriptors) and WinZip AES at each strength, stored, deflated
    /// and bzip2 - extracts to the files they were made from, and a
    /// wrong password is refused for every entry.
    #[test]
    fn test_the_witnesses_archives_extract_byte_for_byte() {
        let archives = fixtures::records("zip.vec", "archive");
        let files = fixtures::records("zip.vec", "file");
        assert_eq!((archives.len(), files.len()), (23, 7));
        let password = b"correct horse battery staple";
        let mut seen = std::collections::BTreeSet::new();
        for record in &archives {
            let name = fixtures::field(record, "name");
            let archive = std::fs::read(fixtures::dir().join("zip").join(name)).unwrap();
            let listed = entries(&archive).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut found = 0;
            for entry in listed.iter().filter(|e| !e.name.ends_with('/')) {
                seen.insert(describe(entry));
                let data = read(&archive, entry, Some(password))
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                let expected = files.iter().find(|f| fixtures::field(f, "name") == entry.name)
                    .unwrap_or_else(|| panic!("{name}: an unexpected {}", entry.name));
                assert_eq!(sha256(&data), fixtures::field(expected, "sha256"),
                           "{name}: {}", entry.name);
                // ZipCrypto's check is one byte, so one wrong password in
                // 256 passes it; then only the CRC refuses - and an empty
                // entry's CRC is zero whatever the key. This one does pass.
                // `test_an_empty_zipcrypto_entry_cannot_refuse_every_wrong_password`;
                // and libarchive writes an empty file unencrypted, so
                // there is no password to be wrong.
                let open = entry.encryption == Encryption::None;
                let lucky = data.is_empty() && entry.encryption == Encryption::ZipCrypto;
                if !(open || lucky) {
                    assert!(read(&archive, entry, Some(b"correct horse battery stapler"))
                                .is_err(), "{name}: {} under a wrong password", entry.name);
                }
                found += 1;
            }
            assert_eq!(found, 7, "{name}");
        }
        // Stored, deflate and bzip2 under ZipCrypto, and AES at all
        // three strengths in both versions.
        assert!(seen.len() >= 12, "{seen:?}");
    }

    /// Found by the recorded archives: libarchive's empty entry opened
    /// under a wrong password. The check byte lets one wrong password
    /// in 256 through, and an empty entry has nothing for the CRC to
    /// catch. AES's 16-bit verifier and its HMAC leave no such gap.
    #[test]
    fn test_an_empty_zipcrypto_entry_cannot_refuse_every_wrong_password() {
        let archive = write(&[("empty".to_string(), Vec::new())], &Sealing::ZipCrypto, b"pw")
            .unwrap();
        let entry = &entries(&archive).unwrap()[0];
        let accepted = (0..2000u32)
            .filter(|i| read(&archive, entry, Some(format!("wrong {i}").as_bytes())).is_ok())
            .count();
        assert!((1..30).contains(&accepted), "{accepted} of 2000");

        let archive = write(&[("empty".to_string(), Vec::new())],
                            &Sealing::Aes { version: 2, strength: 1 }, b"pw").unwrap();
        let entry = &entries(&archive).unwrap()[0];
        assert!((0..200u32)
            .all(|i| read(&archive, entry, Some(format!("wrong {i}").as_bytes())).is_err()));
    }

    #[test]
    fn test_a_name_that_leaves_the_destination_is_refused() {
        let root = Path::new("/tmp/out");
        assert_eq!(destination(root, "a/b.txt").unwrap(), Path::new("/tmp/out/a/b.txt"));
        for bad in ["../x", "a/../../x", "/etc/passwd"] {
            assert!(destination(root, bad).is_err(), "{bad}");
        }
    }
}
