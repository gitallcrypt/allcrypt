//! BitLocker volumes, read with this library's primitives.
//!
//!     cargo run --release --example bitlocker -- dump IMAGE
//!     cargo run --release --example bitlocker -- open IMAGE
//!         (--password-stdin | --recovery-password GROUPS | --startup-key FILE.BEK
//!          | --clear-key | --volume-key HEX)
//!         [--decrypt OUT]
//!     cargo run --release --example bitlocker -- format OUT --size BYTES [--data FILE]
//!         [--method aes-xts-128|aes-xts-256|aes-cbc-128|aes-cbc-256|
//!                   aes-cbc-elephant-128|aes-cbc-elephant-256]
//!         [--sector-size 512|4096] [--password-stdin] [--recovery-password GROUPS
//!          | --new-recovery-password] [--clear-key] [--description TEXT]
//!
//! `dump` prints the metadata: the method, the volume and its GUIDs,
//! the protectors, where the metadata and the relocated volume header
//! are. `open` opens the volume key with one secret, prints it as
//! `cryptsetup bitlkDump --dump-volume-key` does, and with `--decrypt`
//! writes the volume as a reader sees it - the filesystem's boot sector
//! in place and the metadata areas zeroed. `format` writes a volume
//! holding the data, with a password protector, a recovery password
//! protector, a clear key (protection suspended) or several; its layout
//! is in `write.rs`.
//!
//! Every method is read: AES-CBC with the Elephant diffuser (Windows
//! Vista's and 7's), AES-CBC (8), AES-XTS (10 and 11), each at 128 and
//! 256 bits, with 512 and 4096 byte sectors, and BitLocker To Go. The
//! sector encryption is the library's `block_ciphers::bitlocker`, the
//! key stretching `kdf::password::bitlocker_stretch`.
//!
//! What has checked it is in `examples/products/README.md`.

use std::io::Write;

use allcrypt::block_ciphers::bitlocker::{Method, SectorCipher};

#[path = "fve.rs"]
mod fve;
#[path = "write.rs"]
mod write;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/cli.rs"]
mod cli;
#[path = "../shared/hidden.rs"]
mod hidden;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use cli::hex;
use fve::{Metadata, Secret};

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    cli::unhex(text, &[' ', '\t', '\r', '\n'])
}

/// A FILETIME (100 ns since 1601) as a UTC date and time.
fn filetime(value: u64) -> String {
    let seconds = (value / 10_000_000) as i64 - 11_644_473_600;
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Days since 1970 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC", rest / 3600, rest / 60 % 60,
            rest % 60)
}

fn dump(metadata: &Metadata) -> String {
    let mut out = String::new();
    let kind = if metadata.is_normal() {
        "normal"
    } else if metadata.type_guid == fve::GUID_EOW {
        "encrypt-on-write"
    } else {
        "unknown"
    };
    let method = metadata.method().map(|m| m.name().to_string())
        .unwrap_or_else(|_| format!("unknown ({:#06x})", metadata.method_code));
    out += &format!("BitLocker{} volume, metadata version {}\n",
                    if metadata.togo { " To Go" } else { "" }, metadata.version);
    out += &format!("GUID:            {}\n", fve::guid_string(&metadata.guid));
    out += &format!("Type:            {kind}\n");
    out += &format!("Sector size:     {}\n", metadata.sector_size);
    out += &format!("Volume size:     {}\n", metadata.volume_size);
    out += &format!("Created:         {}\n", filetime(metadata.creation_time));
    if let Some(description) = &metadata.description {
        out += &format!("Description:     {description}\n");
    }
    out += &format!("Method:          {method}\n");
    if let Ok(m) = metadata.method() {
        let mode = match m.code() {
            0x8000 | 0x8001 => "aes-cbc-elephant",
            0x8002 | 0x8003 => "aes-cbc-eboiv",
            _ => "aes-xts-plain64",
        };
        out += &format!("dm-crypt:        {mode}, {} bit key\n", m.key_len() * 8);
    }
    out += &format!("State:           {} (next {}){}\n", metadata.current_state,
                    metadata.next_state,
                    if metadata.current_state == fve::STATE_NORMAL
                        && metadata.next_state == fve::STATE_NORMAL { "" }
                    else { ", not fully encrypted" });
    for (i, vmk) in metadata.vmks.iter().enumerate() {
        out += &format!("Protector {i}:     {} {}{}\n", fve::guid_string(&vmk.guid),
                        vmk.protection.describe(),
                        vmk.name.as_ref().map(|n| format!(" ({n})")).unwrap_or_default());
        out += &format!("  salt           {}\n", vmk.salt.map_or("-".to_string(), |s| hex(&s)));
    }
    for (i, offset) in metadata.offsets.iter().enumerate() {
        out += &format!("Metadata {i}:      {offset}{}\n",
                        if i == metadata.copy { " (read)" } else { "" });
    }
    out += &format!("Volume header:   {} bytes at {}\n", metadata.volume_header_size,
                    metadata.volume_header_offset);
    out
}

/// The regions a reader sees as zeros, and the relocated header.
struct Layout {
    sector: u64,
    length: u64,
    header: (u64, u64),
    zeroed: Vec<(u64, u64)>,
}

impl Layout {
    fn new(image: &[u8], metadata: &Metadata) -> Result<Layout, String> {
        if !metadata.is_normal() {
            return Err("Only a fully encrypted (normal) volume is decrypted here; this one is \
                        encrypt-on-write.".to_string());
        }
        if metadata.current_state != fve::STATE_NORMAL
            || metadata.next_state != fve::STATE_NORMAL {
            return Err(format!("The volume is in state {} (next {}): partly encrypted or being \
                                converted, which is not decrypted here.",
                               metadata.current_state, metadata.next_state));
        }
        if metadata.volume_header_size == 0 {
            return Err("The metadata does not say where the volume header went.".to_string());
        }
        let sector = metadata.sector_size;
        let length = image.len() as u64;
        let header = (metadata.volume_header_offset, metadata.volume_header_size);
        let zeroed: Vec<(u64, u64)> = metadata.offsets.iter()
            .map(|&o| (o, fve::METADATA_AREA)).chain([header]).collect();
        for &(start, size) in zeroed.iter().chain([&(0, header.1)]) {
            if !start.is_multiple_of(sector) || !size.is_multiple_of(sector)
                || start.checked_add(size).is_none_or(|end| end > length) {
                return Err(format!("A region of {size} bytes at {start} is not whole sectors \
                                    inside the volume."));
            }
        }
        if !length.is_multiple_of(sector) {
            return Err(format!("The image is not whole {sector}-byte sectors."));
        }
        Ok(Layout { sector, length, header, zeroed })
    }
}

/// `length` bytes of the volume as a reader sees it, from `start`: the
/// metadata areas and the relocated header's area zeroed, the relocated
/// header decrypted back to the start, the rest decrypted in place.
fn decrypt_range(image: &[u8], layout: &Layout, cipher: &mut SectorCipher, start: u64,
                 length: u64) -> Result<Vec<u8>, String> {
    let sector = layout.sector;
    if !start.is_multiple_of(sector) || !length.is_multiple_of(sector)
        || start.checked_add(length).is_none_or(|end| end > layout.length) {
        return Err(format!("{length} bytes at {start} are not whole sectors of the volume."));
    }
    let header = layout.header;
    let mut out = vec![0u8; length as usize];
    for (index, buffer) in out.chunks_mut(sector as usize).enumerate() {
        let position = start + index as u64 * sector;
        if position >= header.1 && layout.zeroed.iter()
            .any(|&(at, size)| position >= at && position < at + size) {
            continue;
        }
        let from = if position < header.1 { header.0 + position } else { position };
        buffer.copy_from_slice(&image[from as usize..(from + sector) as usize]);
        cipher.decrypt_sector(from, buffer)?;
    }
    Ok(out)
}

fn decrypt_volume(image: &[u8], metadata: &Metadata, volume_key: &[u8], out: &mut dyn Write)
                  -> Result<(), String> {
    let layout = Layout::new(image, metadata)?;
    let mut cipher = SectorCipher::new(metadata.method()?, volume_key)?;
    const CHUNK: u64 = 1 << 20;
    let mut position = 0;
    while position < layout.length {
        let length = CHUNK.min(layout.length - position);
        let plain = decrypt_range(image, &layout, &mut cipher, position, length)?;
        out.write_all(&plain).map_err(|e| e.to_string())?;
        position += length;
    }
    Ok(())
}

fn usage() -> String {
    "usage: bitlocker dump IMAGE\n       bitlocker open IMAGE (--password-stdin | \
     --recovery-password GROUPS | --startup-key FILE.BEK | --clear-key | --volume-key HEX) \
     [--decrypt OUT]\n       bitlocker format OUT --size BYTES [--data FILE] [--method NAME] \
     [--sector-size 512|4096] [--password-stdin] [--recovery-password GROUPS | \
     --new-recovery-password] [--clear-key] [--description TEXT]".to_string()
}

fn os_random(buffer: &mut [u8]) -> Result<(), String> {
    buffer.copy_from_slice(&allcrypt::api::random_bytes(buffer.len())?);
    Ok(())
}

fn run_format(args: &[String]) -> Result<(), String> {
    let out = args.first().ok_or_else(usage)?;
    let mut size = None;
    let mut data = Vec::new();
    let mut method = Method::AesXts128;
    let mut sector_size = 512;
    let mut password = None;
    let mut recovery = None;
    let mut description = "allcrypt".to_string();
    let mut clear_key = false;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        let mut value = || rest.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--size" => size = Some(value()?.parse::<u64>().map_err(|e| e.to_string())?),
            "--data" => {
                let file = value()?;
                data = std::fs::read(&file).map_err(|e| format!("{file}: {e}"))?;
            }
            "--method" => method = Method::from_name(&value()?)?,
            "--sector-size" => sector_size = value()?.parse().map_err(|_| "a number")?,
            "--password-stdin" => {
                let line = passphrase::read_line("Password: ")?;
                password = Some(String::from_utf8(line)
                    .map_err(|_| "The password is not UTF-8.".to_string())?);
            }
            "--recovery-password" => recovery = Some(value()?),
            "--new-recovery-password" => {
                let mut bytes = [0u8; 16];
                os_random(&mut bytes)?;
                recovery = Some(write::recovery_password(&bytes));
            }
            "--description" => description = value()?,
            "--clear-key" => clear_key = true,
            other => return Err(format!("unknown option {other}\n{}", usage())),
        }
    }
    let size = size.ok_or("--size is needed")?;
    let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?.as_secs() * 10_000_000 + 116_444_736_000_000_000;
    let params = write::Format { method, sector_size, volume_size: size,
                                 password: password.as_deref(), recovery: recovery.as_deref(),
                                 clear_key, description: &description, created };
    let (image, key) = write::format(&params, &data, &mut os_random)?;
    std::fs::write(out, &image).map_err(|e| format!("{out}: {e}"))?;
    println!("Volume key:      {}", hex(&key));
    if let Some(recovery) = recovery {
        println!("Recovery:        {recovery}");
    }
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let (command, path) = match args {
        [command, path, ..] => (command.as_str(), path),
        _ => return Err(usage()),
    };
    if command == "format" {
        return run_format(&args[1..]);
    }
    let image = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let metadata = fve::read(&image)?;
    if command == "dump" {
        print!("{}", dump(&metadata));
        return Ok(());
    }
    if command != "open" {
        return Err(usage());
    }
    let mut password = None;
    let mut recovery = None;
    let mut startup = None;
    let mut clear = false;
    let mut volume_key = None;
    let mut decrypt = None;
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        let mut value = || rest.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--password-stdin" => {
                let line = passphrase::read_line("Password: ")?;
                password = Some(String::from_utf8(line)
                    .map_err(|_| "The password is not UTF-8.".to_string())?);
            }
            "--recovery-password" => recovery = Some(value()?),
            "--startup-key" => {
                let file = value()?;
                startup = Some(std::fs::read(&file).map_err(|e| format!("{file}: {e}"))?);
            }
            "--clear-key" => clear = true,
            "--volume-key" => volume_key = Some(unhex(&value()?)?),
            "--decrypt" => decrypt = Some(value()?),
            other => return Err(format!("unknown option {other}\n{}", usage())),
        }
    }
    let key = match (password, recovery, startup, clear, volume_key) {
        (_, _, _, _, Some(key)) => key,
        (Some(p), None, None, false, None) => opened(&metadata, &Secret::Password(&p))?,
        (None, Some(r), None, false, None) => opened(&metadata, &Secret::RecoveryPassword(&r))?,
        (None, None, Some(f), false, None) => opened(&metadata, &Secret::StartupKey(&f))?,
        (None, None, None, true, None) => opened(&metadata, &Secret::ClearKey)?,
        _ => return Err(format!("one secret, please\n{}", usage())),
    };
    println!("Volume key:      {}", hex(&key));
    if let Some(out) = decrypt {
        let file = std::fs::File::create(&out).map_err(|e| format!("{out}: {e}"))?;
        let mut writer = std::io::BufWriter::new(file);
        decrypt_volume(&image, &metadata, &key, &mut writer)?;
        writer.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn opened(metadata: &Metadata, secret: &Secret<'_>) -> Result<Vec<u8>, String> {
    let opened = fve::open(metadata, secret)?;
    let vmk = &metadata.vmks[opened.protector];
    println!("Opened by:       protector {} ({}), {}", opened.protector,
             vmk.protection.describe(), fve::guid_string(&vmk.guid));
    Ok(opened.volume_key)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("bitlocker: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime() {
        assert_eq!(filetime(116_444_736_000_000_000), "1970-01-01 00:00:00 UTC");
        // A leap day's neighbour, and a time of day.
        assert_eq!(filetime(125_963_876_960_000_000), "2000-03-01 12:34:56 UTC");
    }

    fn record(name: &str) -> Vec<(String, String)> {
        fixtures::records("bitlocker.vec", "windows").into_iter()
            .find(|r| fixtures::field(r, "name") == name)
            .unwrap_or_else(|| panic!("no record {name}"))
    }

    fn sha256(data: &[u8]) -> String {
        use allcrypt::hash_functions::HashFunction;
        let mut h = allcrypt::hash_functions::sha2::SHA256::new(&[]);
        h.update(data);
        hex(&h.digest())
    }

    /// Every volume Windows made, decrypted with the volume key
    /// cryptsetup dumped: the stretches of it recorded from a decryption
    /// whose whole SHA-256 matched cryptsetup's images.conf, and a boot
    /// sector at the start. The whole volume is 100 MiB, a quarter of a
    /// minute unoptimised; `scripts/check_bitlocker.py` decrypts all of
    /// it.
    #[test]
    fn test_windows_volumes_decrypt() {
        let records = fixtures::records("bitlocker.vec", "windows");
        assert!(records.len() >= 19);
        let mut methods = std::collections::BTreeSet::new();
        let mut decrypted = 0;
        for record in &records {
            let name = fixtures::field(record, "name");
            let image = fixtures::expand(fixtures::field(record, "image"));
            let metadata = fve::read(&image).unwrap_or_else(|e| panic!("{name}: {e}"));
            let key = fixtures::unhex(fixtures::field(record, "volume_key"));
            let samples = fixtures::field(record, "samples");
            if fixtures::field(record, "sha256") == "-" {
                // Encrypt-on-write, or not yet fully encrypted: cryptsetup
                // will not activate these and neither will this.
                assert!(Layout::new(&image, &metadata).is_err(), "{name}");
                continue;
            }
            methods.insert((metadata.method_code, metadata.sector_size, metadata.togo));
            let layout = Layout::new(&image, &metadata).unwrap();
            let mut cipher = SectorCipher::new(metadata.method().unwrap(), &key).unwrap();
            let first = decrypt_range(&image, &layout, &mut cipher, 0, layout.sector).unwrap();
            assert_eq!(first[510..512], [0x55, 0xaa], "{name}: no boot sector");
            for sample in samples.split_whitespace() {
                let parts: Vec<&str> = sample.split(':').collect();
                let (start, length) = (parts[0].parse().unwrap(), parts[1].parse().unwrap());
                let plain = decrypt_range(&image, &layout, &mut cipher, start, length).unwrap();
                assert_eq!(sha256(&plain), parts[2], "{name}: {length} bytes at {start}");
            }
            decrypted += 1;
        }
        assert!(decrypted >= 17);
        // Every method, both sector sizes, and To Go on CBC and XTS.
        let codes: std::collections::BTreeSet<u16> = methods.iter().map(|m| m.0).collect();
        assert_eq!(codes.len(), 6, "{methods:?}");
        assert!(methods.iter().any(|m| m.1 == 4096));
        assert_eq!(methods.iter().filter(|m| m.2).count(), 2);
    }

    /// The secrets that cost nothing to try: a clear key, and the startup
    /// key file of the right protector - the other volume's is refused.
    #[test]
    fn test_clear_and_startup_keys_open() {
        let r = record("bitlk-aes-xts-128-clearkey-only");
        let image = fixtures::expand(fixtures::field(&r, "image"));
        let metadata = fve::read(&image).unwrap();
        let opened = fve::open(&metadata, &Secret::ClearKey).unwrap();
        assert_eq!(hex(&opened.volume_key), fixtures::field(&r, "volume_key"));

        for name in ["bitlk-aes-xts-128-startup-key", "bitlk-aes-xts-128-startup-key-win11"] {
            let r = record(name);
            let image = fixtures::expand(fixtures::field(&r, "image"));
            let metadata = fve::read(&image).unwrap();
            // Each volume's startup key is one of the two files; the
            // file names are the protectors' GUIDs.
            let mut opened = 0;
            for bek in ["4381F759-C4F8-4DE0-BB61-FC33A831BDA5.BEK",
                        "AA80A52B-9B66-47AE-B097-33F536FFBB07.BEK"] {
                let file = std::fs::read(fixtures::dir().join("bitlocker").join(bek)).unwrap();
                match fve::open(&metadata, &Secret::StartupKey(&file)) {
                    Ok(o) => {
                        assert_eq!(hex(&o.volume_key), fixtures::field(&r, "volume_key"));
                        let vmk = &metadata.vmks[o.protector];
                        assert_eq!(fve::guid_string(&vmk.guid).to_uppercase(), bek[..36]);
                        opened += 1;
                    }
                    Err(error) => assert!(error.contains("No protector")
                                          || error.contains("opens no"), "{name}: {error}"),
                }
            }
            assert_eq!(opened, 1, "{name}");
            assert!(fve::open(&metadata, &Secret::ClearKey).is_err(), "{name}");
        }
    }

    /// A password, and a recovery password: 2^20 SHA-256 each, nine
    /// seconds unoptimised, so one of each, on the method nothing but
    /// Windows and dm-crypt reads (Elephant). The rest are in
    /// `scripts/check_bitlocker.py`.
    #[test]
    fn test_a_password_and_a_recovery_password_open() {
        let r = record("bitlk-aes-cbc-elephant-128");
        let image = fixtures::expand(fixtures::field(&r, "image"));
        let metadata = fve::read(&image).unwrap();
        let password = fixtures::field(&r, "password");
        let opened = fve::open(&metadata, &Secret::Password(password)).unwrap();
        assert_eq!(hex(&opened.volume_key), fixtures::field(&r, "volume_key"));
        let r = record("bitlk-aes-xts-256");
        let image = fixtures::expand(fixtures::field(&r, "image"));
        let metadata = fve::read(&image).unwrap();
        let recovery = fixtures::field(&r, "recovery");
        let opened = fve::open(&metadata, &Secret::RecoveryPassword(recovery)).unwrap();
        assert_eq!(hex(&opened.volume_key), fixtures::field(&r, "volume_key"));
        // A recovery password with a group that is not a multiple of 11
        // is refused before any hashing.
        let mut typo = recovery.to_string();
        typo.replace_range(0..1, if &typo[..1] == "9" { "8" } else { "9" });
        assert!(fve::open(&metadata, &Secret::RecoveryPassword(&typo)).is_err());
    }

    /// A damaged first metadata copy is passed over for the second; all
    /// three damaged is an error. And a block whose CRC-32 was redone
    /// after a change is still refused, by the validation hash only the
    /// volume master key opens.
    #[test]
    fn test_damaged_and_altered_metadata() {
        let r = record("bitlk-aes-xts-128-clearkey-only");
        let image = fixtures::expand(fixtures::field(&r, "image"));
        let metadata = fve::read(&image).unwrap();
        let [first, second, third] = metadata.offsets.map(|o| o as usize);
        let mut damaged = image.clone();
        damaged[first + 200] ^= 1;
        let read = fve::read(&damaged).unwrap();
        assert_eq!(read.copy, 1);
        assert!(fve::open(&read, &Secret::ClearKey).is_ok());
        for offset in [second, third] {
            damaged[offset + 200] ^= 1;
        }
        assert!(fve::read(&damaged).is_err());

        // A copy found where another copy's offset points is not that
        // copy: the boot sector's first offset aimed at the second copy
        // reads the second copy as the second.
        let mut moved = image.clone();
        moved[176..184].copy_from_slice(&(second as u64).to_le_bytes());
        assert_eq!(fve::read(&moved).unwrap().copy, 1);

        // The description's first character changed, the CRC redone.
        let size = u16::from_le_bytes([image[first + 8], image[first + 9]]) as usize * 16;
        let mut altered = image.clone();
        let description = metadata.description.clone().unwrap();
        let utf16: Vec<u8> = description.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let at = first + altered[first..first + size].windows(utf16.len())
            .position(|w| w == utf16).unwrap();
        altered[at] ^= 1;
        let crc = allcrypt::checksum::crc32(&altered[first..first + size]);
        altered[first + size + 4..first + size + 8].copy_from_slice(&crc.to_le_bytes());
        let read = fve::read(&altered).unwrap();
        assert_eq!(read.copy, 0);
        let error = fve::open(&read, &Secret::ClearKey).err().unwrap();
        assert!(error.contains("validation hash"), "{error}");
    }

    fn counter_stream(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), String> {
        let mut n = seed;
        move |buffer: &mut [u8]| {
            for b in buffer {
                *b = n;
                n = n.wrapping_mul(13).wrapping_add(17);
            }
            Ok(())
        }
    }

    /// Our volumes, every method at both sector sizes, read back with
    /// the volume key `format` returned and through a clear key: the
    /// data in place, the metadata areas zero, the metadata valid. One
    /// has a password too (2^20 SHA-256 to write it, as many to read it
    /// and as many to refuse a wrong one). cryptsetup reading them is
    /// `scripts/check_bitlocker.py`.
    #[test]
    fn test_our_volumes_read_back() {
        let plain: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + i / 509) as u8).collect();
        let size = 2 << 20;
        let mut opened_one = false;
        for code in 0x8000..=0x8005u16 {
            for sector in [512, 4096] {
                let method = Method::from_code(code).unwrap();
                let password = if opened_one { None } else { Some("pässword") };
                let params = write::Format { method, sector_size: sector, volume_size: size,
                                             password, recovery: None, clear_key: true,
                                             description: "test", created: 1 << 56 };
                let (image, key) = write::format(&params, &plain, &mut counter_stream(code as u8))
                    .unwrap();
                let metadata = fve::read(&image).unwrap();
                assert_eq!(metadata.method().unwrap(), method);
                assert_eq!(metadata.sector_size, sector);
                assert_eq!(metadata.description.as_deref(), Some("test"));
                let mut out = Vec::new();
                decrypt_volume(&image, &metadata, &key, &mut out).unwrap();
                assert_eq!(out.len() as u64, size);
                assert_eq!(out[..plain.len()], plain[..], "{method:?} {sector}");
                assert!(out[(size - write::RESERVED) as usize..].iter().all(|&b| b == 0));
                assert_eq!(fve::open(&metadata, &Secret::ClearKey).unwrap().volume_key, key);
                if let Some(password) = password {
                    let opened = fve::open(&metadata, &Secret::Password(password)).unwrap();
                    assert_eq!(opened.volume_key, key);
                    assert!(fve::open(&metadata, &Secret::Password("password")).is_err());
                    opened_one = true;
                }
            }
        }
        // Data that would run into the metadata is refused.
        let params = write::Format { method: Method::AesXts128, sector_size: 512,
                                     volume_size: 1 << 20, password: None, recovery: None,
                                     clear_key: true, description: "", created: 0 };
        assert!(write::format(&params, &vec![1; (1 << 20) - write::RESERVED as usize + 1],
                              &mut counter_stream(1)).is_err());
    }

    #[test]
    fn test_recovery_password_from_bytes() {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&[1, 0, 0xff, 0xff]);
        let text = write::recovery_password(&bytes);
        assert_eq!(text, "000011-720885-000000-000000-000000-000000-000000-000000");
        assert_eq!(allcrypt::kdf::password::bitlocker_recovery_key(&text).unwrap(), bytes);
    }

    #[test]
    fn test_guid_string() {
        let g = [0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a,
                 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01];
        assert_eq!(fve::guid_string(&g), "4967d63b-2e29-4ad8-8399-f6a339e3d001");
    }
}
