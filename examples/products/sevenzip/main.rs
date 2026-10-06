//! 7z archives - LZMA, LZMA2, Deflate, BZip2, the branch and delta
//! filters, and 7zAES with or without the header encrypted - built from
//! this library's primitives.
//!
//!     cargo run --release --example sevenzip -- list ARCHIVE [--password PW]
//!     cargo run --release --example sevenzip -- extract ARCHIVE DIR [--password PW]
//!     cargo run --release --example sevenzip -- create OUT PATH... [--password PW]
//!             [--encrypt-header] [--cycles N]
//!
//! `--password-stdin` in place of `--password PW` reads it from
//! standard input. `create` stores the files uncompressed in one solid
//! folder, under 7zAES when there is a password, with 2^N rounds of key
//! derivation - N is 19, 7-Zip's own, unless `--cycles` gives 0 to 24,
//! or 63 for 7-Zip's raw key, which is no derivation at all;
//! directories named on the command line are added with everything
//! under them. `extract` refuses a name that would land outside DIR.
//!
//! What has checked it is in `examples/products/README.md`.

mod archive;
mod coders;
mod lzma;

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

use archive::{Archive, NewFile, WriteOptions};

/// Where an entry may be written under `root`, or an error for a name
/// that is absolute or climbs out with `..`. 7-Zip writes `/`
/// between components, and a `\` is read as one too, since that is what
/// an archive made elsewhere means by it.
fn destination(root: &Path, name: &str) -> Result<PathBuf, String> {
    let mut out = root.to_path_buf();
    if name.is_empty() {
        return Err("An entry with no name.".to_string());
    }
    if name.starts_with(['/', '\\']) {
        return Err(format!("{name}: a name that leaves the destination."));
    }
    for part in name.split(['/', '\\']) {
        match Path::new(part).components().next() {
            None => {}
            Some(Component::Normal(p)) if Path::new(part).components().count() == 1 => out.push(p),
            Some(Component::CurDir) => {}
            _ => return Err(format!("{name}: a name that leaves the destination.")),
        }
    }
    Ok(out)
}

/// Seconds since 1970 as a Windows FILETIME: 100 ns units since 1601.
fn filetime(seconds: u64) -> u64 {
    (seconds + 11_644_473_600) * 10_000_000
}

fn mtime(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(filetime(modified.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs()))
}

/// `path` and, for a directory, everything under it, named relative to
/// where the command line named them.
fn gather(path: &Path, name: String, out: &mut Vec<NewFile>) -> Result<(), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.is_dir() {
        out.push(NewFile { name: name.clone(), data: None, mtime: mtime(path) });
        let mut children: Vec<_> = std::fs::read_dir(path).map_err(|e| e.to_string())?
            .collect::<Result<_, _>>().map_err(|e| e.to_string())?;
        children.sort_by_key(|c| c.file_name());
        for child in children {
            let child_name = format!("{name}/{}", child.file_name().to_string_lossy());
            gather(&child.path(), child_name, out)?;
        }
    } else {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        out.push(NewFile { name, data: Some(data), mtime: mtime(path) });
    }
    Ok(())
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

const SWITCHES: [&str; 2] = ["--password-stdin", "--encrypt-header"];

fn positional(args: &[String]) -> Vec<&String> {
    let mut out = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
        } else if SWITCHES.contains(&arg.as_str()) {
        } else if arg.starts_with("--") {
            skip = true;
        } else {
            out.push(arg);
        }
    }
    out
}

fn open(path: &str, password: Option<&[u8]>) -> Result<Archive, String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    archive::open(data, password)
}

fn list(archive: &Archive) {
    for (index, folder) in archive.streams.folders.iter().enumerate() {
        let methods: Vec<String> = folder.coders.iter().map(archive::describe_coder).collect();
        println!("folder {index}: {}", methods.join(" "));
    }
    if archive.header_encrypted {
        println!("header: encrypted");
    }
    for entry in &archive.entries {
        let kind = if entry.is_anti { "anti" } else if entry.is_dir { "dir" } else { "file" };
        println!("{:>10}  {kind:<4}  {}", entry.size, entry.name);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let archive_path = names.first().ok_or("Name the archive.")?;
    match command {
        "list" => {
            let password = password(rest)?;
            list(&open(archive_path, password.as_deref())?);
            Ok(())
        }
        "extract" => {
            let root = Path::new(names.get(1).ok_or("Name the destination directory.")?);
            let password = password(rest)?;
            let archive = open(archive_path, password.as_deref())?;
            // Every name is checked before anything is written.
            let targets = archive.entries.iter().map(|e| destination(root, &e.name))
                .collect::<Result<Vec<_>, _>>()?;
            let contents = archive.extract(password.as_deref())?;
            for ((entry, target), data) in archive.entries.iter().zip(&targets).zip(contents) {
                if entry.is_anti {
                    continue;
                }
                if entry.is_dir {
                    std::fs::create_dir_all(target).map_err(|e| e.to_string())?;
                    continue;
                }
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                std::fs::write(target, data.unwrap_or_default())
                    .map_err(|e| format!("{}: {e}", target.display()))?;
                println!("{}", entry.name);
            }
            Ok(())
        }
        "create" => {
            let password = password(rest)?;
            let encrypt_header = rest.iter().any(|a| a == "--encrypt-header");
            if encrypt_header && password.is_none() {
                return Err("--encrypt-header needs a --password or --password-stdin.".to_string());
            }
            if password.as_ref().is_some_and(Vec::is_empty) {
                return Err("The password is empty.".to_string());
            }
            let cycles = match value(rest, "--cycles") {
                Some(n) => n.parse().map_err(|_| "--cycles is a number of doublings.")?,
                None => coders::DEFAULT_CYCLES,
            };
            let mut files = Vec::new();
            for name in &names[1..] {
                let clean = name.trim_start_matches('/').trim_end_matches('/').to_string();
                gather(Path::new(name.as_str()), clean, &mut files)?;
            }
            let options = WriteOptions { password: password.as_deref(), encrypt_header,
                                         cycles_power: cycles };
            let bytes = archive::write(&files, &options)?;
            std::fs::write(archive_path, bytes).map_err(|e| format!("{archive_path}: {e}"))
        }
        _ => Err("usage: sevenzip list|extract|create ...".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("sevenzip: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<NewFile> {
        vec![
            NewFile { name: "dir".to_string(), data: None, mtime: Some(filetime(0)) },
            NewFile { name: "dir/empty".to_string(), data: Some(Vec::new()), mtime: None },
            NewFile { name: "dir/one".to_string(), data: Some(b"x".to_vec()), mtime: None },
            NewFile { name: "caf\u{e9}.bin".to_string(),
                      data: Some((0..1000u32).map(|i| (i * 7) as u8).collect()),
                      mtime: Some(filetime(1_700_000_000)) },
        ]
    }

    fn check(bytes: Vec<u8>, password: Option<&[u8]>) -> Archive {
        let archive = archive::open(bytes, password).unwrap();
        let sample = sample();
        assert_eq!(archive.entries.len(), sample.len());
        let contents = archive.extract(password).unwrap();
        for ((entry, file), data) in archive.entries.iter().zip(&sample).zip(contents) {
            assert_eq!(entry.name, file.name);
            assert_eq!(entry.is_dir, file.data.is_none(), "{}", file.name);
            assert_eq!(data.unwrap_or_default(), file.data.clone().unwrap_or_default());
        }
        archive
    }

    #[test]
    fn test_what_is_written_reads_back() {
        let plain = archive::write(&sample(), &WriteOptions {
            password: None, encrypt_header: false, cycles_power: 6 }).unwrap();
        assert!(!check(plain, None).header_encrypted);

        let sealed = archive::write(&sample(), &WriteOptions {
            password: Some(b"pw"), encrypt_header: false, cycles_power: 6 }).unwrap();
        let archive = check(sealed.clone(), Some(b"pw"));
        assert!(!archive.header_encrypted);
        // The names are readable without the password; the data is not.
        let opened = archive::open(sealed.clone(), None).unwrap();
        assert!(opened.extract(None).unwrap_err().contains("give a password"));
        assert!(opened.extract(Some(b"pW")).is_err());

        let hidden = archive::write(&sample(), &WriteOptions {
            password: Some(b"pw"), encrypt_header: true, cycles_power: 6 }).unwrap();
        let archive = check(hidden.clone(), Some(b"pw"));
        assert!(archive.header_encrypted);
        // Directories carry FILE_ATTRIBUTE_DIRECTORY and files
        // FILE_ATTRIBUTE_ARCHIVE, as 7-Zip writes them.
        let attributes: Vec<_> = archive.entries.iter().map(|e| e.attributes).collect();
        assert_eq!(attributes, [Some(0x10), Some(0x20), Some(0x20), Some(0x20)]);
        assert!(archive::open(hidden.clone(), None).is_err());
        assert!(archive::open(hidden, Some(b"pW")).is_err());
    }

    fn sha256(data: &[u8]) -> String {
        use allcrypt::hash_functions::HashFunction;
        let mut hash = allcrypt::hash_functions::sha2::SHA256::new(&[]);
        hash.update(data);
        fixtures::hex(&hash.digest())
    }

    const PASSWORD: &str = "correct horse battery st\u{e4}ple";

    /// Every archive `scripts/check_sevenzip.py --record` kept extracts
    /// to the files it was made from: each method and filter, solid and
    /// not, the header packed, plain or encrypted, LZMA2 in 4 KiB blocks
    /// that each reset the dictionary, and liblzma's LZMA2, which resets
    /// the state after a stored chunk where 7-Zip's never does. A wrong
    /// password is refused, and said to be the likely cause.
    #[test]
    fn test_7_zips_archives_extract_byte_for_byte() {
        let archives = fixtures::records("sevenzip.vec", "archive");
        let files = fixtures::records("sevenzip.vec", "file");
        assert_eq!((archives.len(), files.len()), (38, 16));
        let mut methods = std::collections::BTreeSet::new();
        for record in &archives {
            let name = fixtures::field(record, "name");
            let encrypted = fixtures::field(record, "made_by").contains("AES");
            let password = encrypted.then_some(PASSWORD.as_bytes());
            let data = std::fs::read(fixtures::dir().join("sevenzip").join(name)).unwrap();
            let archive = archive::open(data.clone(), password)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            for folder in &archive.streams.folders {
                for coder in &folder.coders {
                    methods.insert(coders::name(&coder.id));
                }
            }
            let contents = archive.extract(password).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut found = 0;
            for (entry, content) in archive.entries.iter().zip(contents) {
                if entry.is_dir {
                    assert!(entry.name == "hollow" || ["dir", "code"].contains(&&*entry.name),
                            "{name}: {}", entry.name);
                    continue;
                }
                let expected = files.iter().find(|f| fixtures::field(f, "name") == entry.name)
                    .unwrap_or_else(|| panic!("{name}: an unexpected {}", entry.name));
                assert_eq!(sha256(&content.unwrap_or_default()), fixtures::field(expected, "sha256"),
                           "{name}: {}", entry.name);
                found += 1;
            }
            let alone = name.starts_with("xz-") || name == "LZMA2-blocks.7z";
            assert_eq!(found, if alone { 1 } else { 13 }, "{name}");
            if encrypted {
                // Whatever notices it - LZMA, inflate, the header parser, a
                // CRC - the error says what most likely happened.
                let wrong = Some(b"correct horse battery staple".as_slice());
                let error = archive::open(data, wrong).and_then(|a| a.extract(wrong))
                    .expect_err(name);
                assert!(error.starts_with("Wrong password"), "{name}: {error}");
            }
        }
        let expected = ["7zAES", "ARM", "ARM64", "ARMT", "BCJ", "BZip2", "Copy", "Deflate",
                        "Delta", "LZMA", "LZMA2", "PPC", "SPARC"];
        assert_eq!(methods.into_iter().collect::<Vec<_>>(), expected);
    }

    /// 7-Zip gives an encrypted header's folder a CRC, which catches a
    /// wrong password before the header is parsed. Without one the
    /// parser is what fails, on decrypted noise, and that too is
    /// reported as the likely wrong password.
    #[test]
    fn test_a_wrong_password_is_named_when_the_header_has_no_crc() {
        let data = std::fs::read(fixtures::dir().join("sevenzip").join("AES-header-Copy.7z"))
            .unwrap();
        let offset = 32 + u64::from_le_bytes(data[12..20].try_into().unwrap()) as usize;
        let mut header = data[offset..].to_vec();
        assert_eq!(header[0], 0x17, "an encoded header");
        // It ends with the folder's CRC - 0A 01 and four bytes - and two
        // END tags.
        let n = header.len();
        assert_eq!((header[n - 8], header[n - 7], header[n - 2], header[n - 1]), (0x0a, 1, 0, 0));
        header.drain(n - 8..n - 2);
        let mut start = Vec::new();
        start.extend_from_slice(&data[12..20]);
        start.extend_from_slice(&(header.len() as u64).to_le_bytes());
        start.extend_from_slice(&allcrypt::checksum::crc32(&header).to_le_bytes());
        let mut changed = data[..8].to_vec();
        changed.extend_from_slice(&allcrypt::checksum::crc32(&start).to_le_bytes());
        changed.extend_from_slice(&start);
        changed.extend_from_slice(&data[32..offset]);
        changed.extend_from_slice(&header);
        let password = Some(PASSWORD.as_bytes());
        assert_eq!(archive::open(changed.clone(), password).unwrap().entries.len(), 16);
        // The one wrong password the other tests use, so its key is
        // derived once.
        let error = archive::open(changed, Some(b"correct horse battery staple")).err().unwrap();
        assert!(error.starts_with("Wrong password"), "{error}");
    }

    /// A folder's CRC is checked on what its coders produced. 7-Zip
    /// writes one only for a packed header - files' CRCs go with the
    /// files - so the case is a damaged encrypted header, which would
    /// otherwise reach the parser as noise.
    #[test]
    fn test_a_changed_byte_in_a_folder_is_refused_by_its_crc() {
        let data = std::fs::read(fixtures::dir().join("sevenzip").join("AES-header-Copy.7z"))
            .unwrap();
        let offset = 32 + u64::from_le_bytes(data[12..20].try_into().unwrap()) as usize;
        let mut changed = data;
        // In the encrypted header, which is the last packed stream; two
        // blocks from its end, clear of the padding.
        changed[offset - 20] ^= 1;
        let error = archive::open(changed, Some(PASSWORD.as_bytes())).err().unwrap();
        assert_eq!(error, "Wrong password, or the archive is damaged: 7z: a folder's CRC does \
                           not match.");
    }

    /// The start header's CRC covers the header's, and the header's
    /// covers every byte of it.
    #[test]
    fn test_a_changed_header_byte_is_refused() {
        let plain = archive::write(&sample(), &WriteOptions {
            password: None, encrypt_header: false, cycles_power: 6 }).unwrap();
        let header_len = u64::from_le_bytes(plain[20..28].try_into().unwrap()) as usize;
        for back in 1..=header_len {
            let mut changed = plain.clone();
            let at = plain.len() - back;
            changed[at] ^= 0x40;
            let error = archive::open(changed, None).err().unwrap_or_else(|| panic!("{back}"));
            assert!(error.contains("header's CRC"), "{back}: {error}");
        }
        for at in 8..32 {
            let mut changed = plain.clone();
            changed[at] ^= 1;
            assert!(archive::open(changed, None).is_err(), "{at}");
        }
    }

    #[test]
    fn test_a_name_that_leaves_the_destination_is_refused() {
        let root = Path::new("out");
        assert_eq!(destination(root, "a/b").unwrap(), root.join("a").join("b"));
        assert_eq!(destination(root, "a\\b").unwrap(), root.join("a").join("b"));
        assert_eq!(destination(root, "./a").unwrap(), root.join("a"));
        for bad in ["../x", "a/../../x", "/etc/passwd", "a\\..\\..\\x", ""] {
            assert!(destination(root, bad).is_err(), "{bad}");
        }
    }
}
