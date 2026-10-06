//! Encrypted Microsoft Office documents, built from this library's
//! primitives.
//!
//!     cargo run --release --example office -- info FILE [--password PW]
//!     cargo run --release --example office -- decrypt IN OUT [--password PW]
//!     cargo run --release --example office -- encrypt IN OUT --password PW
//!             [--method agile|standard] [--key-bits 128|192|256]
//!             [--hash SHA1|SHA256|SHA384|SHA512] [--spin-count N]
//!
//! `--password-stdin` reads the password from standard input instead.
//!
//! The Office Open XML formats (`.docx`, `.xlsx`, `.pptx`) are
//! encrypted whole: `decrypt` writes the ZIP package, `encrypt` takes
//! one. Agile encryption defaults to what Office writes, AES-256 and
//! SHA-512 with 100,000 hashes; standard encryption is AES with
//! SHA-1, as Office 2007 and LibreOffice write it.
//!
//! The binary formats `.doc` and `.xls` (RC4, RC4 CryptoAPI, and XOR
//! obfuscation for `.xls`) are decrypted in place: `decrypt` writes the
//! same compound file with its streams decrypted. Encrypting them is
//! not here.
//!
//! What has checked it is in `examples/products/README.md`.

mod binary;
mod cfb;
mod ooxml;

#[path = "../shared/base64.rs"]
mod base64;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/xml.rs"]
mod xml;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use ooxml::{AgileOptions, Info};

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

fn password(args: &[String]) -> Result<Option<Vec<u8>>, String> {
    if args.iter().any(|a| a == "--password-stdin") {
        return passphrase::read_line("Password: ").map(Some);
    }
    Ok(value(args, "--password").map(|p| p.as_bytes().to_vec()))
}

/// What sort of encrypted document a compound file holds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Ooxml,
    Word,
    Excel,
}

pub fn kind(root: &cfb::Storage) -> Result<Kind, String> {
    if root.stream("EncryptionInfo").is_some() {
        Ok(Kind::Ooxml)
    } else if root.stream("WordDocument").is_some() {
        Ok(Kind::Word)
    } else if root.stream("Workbook").is_some() {
        Ok(Kind::Excel)
    } else if root.stream("PowerPoint Document").is_some() {
        Err("A PowerPoint 97-2003 presentation: its encryption is not supported.".to_string())
    } else {
        Err("Not an Office document this example knows.".to_string())
    }
}

/// Decrypt a document: the package of an OOXML one, the compound file
/// of a binary one.
pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let root = cfb::read(data)?;
    match kind(&root)? {
        Kind::Ooxml => {
            let opened = ooxml::decrypt(&root, password)?;
            if opened.integrity == Some(false) {
                return Err("The data integrity check failed: the encrypted package was \
                            changed.".to_string());
            }
            Ok(opened.package)
        }
        Kind::Word => cfb::write(&binary::decrypt_word(&root, password)?),
        Kind::Excel => cfb::write(&binary::decrypt_excel(&root, password)?),
    }
}

/// A description of how a document is encrypted, one fact a line.
pub fn describe(root: &cfb::Storage) -> Result<Vec<String>, String> {
    match kind(root)? {
        Kind::Word => return Ok(vec!["Word 97-2003 document".to_string(),
                                     binary::word_info(root)?.scheme.describe()]),
        Kind::Excel => return Ok(vec!["Excel 97-2003 workbook".to_string(),
                                      binary::excel_info(root)?.describe()]),
        Kind::Ooxml => {}
    }
    Ok(match ooxml::info(root)? {
        Info::Standard(s) => vec![
            format!("OOXML standard encryption, version {}.{}", s.version.0, s.version.1),
            format!("AES-{} in ECB, SHA-1 x 50000", s.key_bits),
            format!("provider {:?}", s.csp_name),
        ],
        Info::Agile(a) => vec![
            "OOXML agile encryption, version 4.4".to_string(),
            format!("{}-{} in CBC, {} for the data", a.key_data.cipher, a.key_data.key_bits,
                    a.key_data.hash),
            format!("password key: {}-{}, {} x {}", a.password.params.cipher,
                    a.password.params.key_bits, a.password.params.hash, a.password.spin_count),
            format!("{} other key encryptor(s), which are not used", a.other_encryptors),
        ],
    })
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let input = names.first().ok_or("Name the input file.")?;
    let data = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    match command {
        "info" => {
            let root = cfb::read(&data)?;
            for line in describe(&root)? {
                println!("{line}");
            }
            if let Some(password) = password(rest)? {
                if kind(&root)? == Kind::Ooxml {
                    let opened = ooxml::decrypt(&root, &password)?;
                    println!("password correct, package {} bytes", opened.package.len());
                    if let Some(ok) = opened.integrity {
                        println!("integrity {}", if ok { "verified" } else { "FAILED" });
                    }
                } else {
                    decrypt(&data, &password)?;
                    println!("password correct");
                }
            }
            Ok(())
        }
        "decrypt" => {
            let output = names.get(1).ok_or("Name the output file.")?;
            let password = password(rest)?.ok_or("Give --password or --password-stdin.")?;
            let plain = decrypt(&data, &password)?;
            std::fs::write(output, plain).map_err(|e| format!("{output}: {e}"))
        }
        "encrypt" => {
            let output = names.get(1).ok_or("Name the output file.")?;
            let password = password(rest)?.ok_or("Give --password or --password-stdin.")?;
            let options = AgileOptions {
                key_bits: value(rest, "--key-bits").unwrap_or("256").parse()
                    .map_err(|_| "--key-bits is 128, 192 or 256")?,
                hash: value(rest, "--hash").unwrap_or("SHA512").to_string(),
                spin_count: value(rest, "--spin-count").unwrap_or("100000").parse()
                    .map_err(|_| "--spin-count is a number")?,
            };
            if cfb::is_compound(&data) {
                return Err("The input is a compound file. Encrypting is for the OOXML \
                            formats, a ZIP package; the binary formats are not encrypted here."
                    .to_string());
            }
            let method = value(rest, "--method").unwrap_or("agile");
            let bytes = ooxml::encrypt(&data, &password, method, &options)?;
            std::fs::write(output, bytes).map_err(|e| format!("{output}: {e}"))
        }
        _ => Err("usage: office info|decrypt|encrypt ...".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("office: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{field, records, unhex};

    fn sha256(data: &[u8]) -> String {
        let mut hash = allcrypt::api::AnyHash::new("sha256").unwrap();
        allcrypt::hash_functions::HashFunction::update(&mut hash, data);
        crate::fixtures::hex(&allcrypt::hash_functions::HashFunction::digest(&mut hash))
    }

    fn fixture(name: &str) -> cfb::Storage {
        cfb::read(&std::fs::read(fixtures::dir().join("office").join(name)).unwrap()).unwrap()
    }

    /// Every recorded document - Office's, LibreOffice's,
    /// msoffcrypto-tool's and ours - decrypts to what the witnesses
    /// decrypted: an OOXML package whole, a `.doc` or `.xls` stream by
    /// stream.
    #[test]
    fn test_every_document_decrypts_to_the_recorded_package() {
        let documents = records("office.vec", "document");
        assert_eq!(documents.len(), 23);
        let mut binary = 0;
        for record in &documents {
            let name = field(record, "name");
            let data = std::fs::read(fixtures::dir().join("office").join(name)).unwrap();
            let password = unhex(field(record, "password"));
            let plain = decrypt(&data, &password).unwrap_or_else(|e| panic!("{name}: {e}"));
            let streams: Vec<&str> = record.iter().filter(|(k, _)| k == "stream")
                .map(|(_, v)| v.as_str()).collect();
            if streams.is_empty() {
                assert_eq!(plain.len().to_string(), field(record, "size"), "{name}");
                assert_eq!(sha256(&plain), field(record, "sha256"), "{name}");
            } else {
                binary += 1;
                let ours = cfb::read(&plain).unwrap();
                let ours: Vec<(String, &Vec<u8>)> = ours.streams().into_iter()
                    .map(|(path, data)| (path.join("/"), data)).collect();
                assert_eq!(ours.len(), streams.len(), "{name}");
                for line in streams {
                    let parts: Vec<&str> = line.split(' ').collect();
                    let path = String::from_utf8(unhex(parts[0])).unwrap();
                    let skip: usize = parts[1].parse().unwrap();
                    let data = ours.iter().find(|(p, _)| *p == path)
                        .unwrap_or_else(|| panic!("{name}: no stream {path:?}")).1;
                    assert_eq!(sha256(&data[skip..]), parts[2], "{name} {path:?}");
                    // The bytes not compared are the Word encryption
                    // header, which decrypting zeroes.
                    assert!(data[..skip].iter().all(|&b| b == 0), "{name} {path:?}");
                }
            }
            // A wrong password costs as much as the right one - 100,000
            // hashes, in a debug build - so the ones Office wrote stand
            // for the rest.
            if name.starts_with("office-") {
                assert!(decrypt(&data, b"not the password").is_err(), "{name}");
            }
        }
        assert_eq!(binary, 6);
    }

    /// The `\x06DataSpaces` storage written here is the one Office
    /// writes, stream for stream.
    #[test]
    fn test_the_data_spaces_are_the_ones_office_writes() {
        let root = fixture("office-example_password.docx");
        let office = root.storage("\u{6}DataSpaces").unwrap();
        let ours = ooxml::data_spaces();
        let streams = |s: &cfb::Storage| {
            let mut v: Vec<(Vec<String>, Vec<u8>)> = s.streams().into_iter()
                .map(|(p, d)| (p, d.clone())).collect();
            v.sort();
            v
        };
        assert_eq!(streams(&ours).len(), 4);
        assert_eq!(streams(&ours), streams(office));
    }

    /// An agile package's HMAC covers the encrypted stream: one changed
    /// bit anywhere in it, size field included, is noticed.
    #[test]
    fn test_a_changed_agile_package_fails_its_integrity_check() {
        let root = fixture("office-example_password.docx");
        let length = root.stream("EncryptedPackage").unwrap().len();
        for at in [0, 9, length / 2, length - 1] {
            let mut changed = root.clone();
            changed.stream_mut("EncryptedPackage").unwrap()[at] ^= 0x10;
            match ooxml::decrypt(&changed, b"Password1234_") {
                Ok(opened) => assert_eq!(opened.integrity, Some(false), "byte {at}"),
                // A changed size field can also make the package too
                // short for what it claims.
                Err(error) => assert!(at < 8, "byte {at}: {error}"),
            }
        }
    }

    /// Every scheme round-trips packages either side of a segment and an
    /// AES block, through the compound file.
    #[test]
    fn test_every_scheme_round_trips() {
        let lengths = [0, 1, 15, 16, 17, 4095, 4096, 4097, 9000];
        let mut schemes: Vec<(&str, usize, &str)> = Vec::new();
        for bits in [128, 192, 256] {
            for hash in ["SHA1", "SHA256", "SHA384", "SHA512"] {
                schemes.push(("agile", bits, hash));
            }
            schemes.push(("standard", bits, "SHA1"));
        }
        for (method, bits, hash) in schemes {
            // Standard encryption's 50,000 hashes are fixed, and slow in
            // a debug build; its ECB has no segments to straddle.
            let lengths = if method == "standard" { &lengths[..5] } else { &lengths[..] };
            for (k, &length) in lengths.iter().enumerate() {
                let package: Vec<u8> = (0..length).map(|i| (i * 31 + 7) as u8).collect();
                let options = AgileOptions { key_bits: bits, hash: hash.to_string(), spin_count: 3 };
                let file = ooxml::encrypt(&package, "pässword".as_bytes(), method, &options)
                    .unwrap();
                let root = cfb::read(&file).unwrap();
                let opened = ooxml::decrypt(&root, "pässword".as_bytes()).unwrap();
                assert_eq!(opened.package, package, "{method} {bits} {hash} {length}");
                assert_ne!(opened.integrity, Some(false), "{method} {bits} {hash} {length}");
                if k == 0 {
                    assert!(ooxml::decrypt(&root, b"password").is_err());
                }
            }
        }
    }
}
