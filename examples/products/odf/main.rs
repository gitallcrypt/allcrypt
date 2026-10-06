//! Encrypted OpenDocument files (`.odt`, `.ods`, `.odp` and the rest),
//! built from this library's primitives.
//!
//!     cargo run --release --example odf -- info FILE
//!     cargo run --release --example odf -- decrypt IN OUT --password PW
//!     cargo run --release --example odf -- encrypt IN OUT --password PW
//!             [--scheme aes|blowfish|gcm] [--iterations N] [--argon2 PASSES,KIB,LANES]
//!
//! `--password-stdin` reads the password from standard input instead.
//!
//! `decrypt` writes the plain package; `encrypt` takes one. The schemes
//! are ODF 1.2's AES-256-CBC (what LibreOffice writes by default, with
//! 100,000 PBKDF2 iterations), ODF 1.0's Blowfish, and LibreOffice's
//! whole-package AES-256-GCM under Argon2id (3 passes, 64 MiB, 4 lanes
//! by default, as LibreOffice writes it).
//!
//! What has checked it is in `examples/products/README.md`.

mod package;

#[path = "../shared/base64.rs"]
mod base64;
#[path = "../shared/inflate.rs"]
mod inflate;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/xml.rs"]
mod xml;
#[path = "../shared/ziparchive.rs"]
mod ziparchive;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

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

fn password(args: &[String]) -> Result<Vec<u8>, String> {
    if args.iter().any(|a| a == "--password-stdin") {
        return passphrase::read_line("Password: ");
    }
    value(args, "--password").map(|p| p.as_bytes().to_vec())
        .ok_or_else(|| "Give --password or --password-stdin.".to_string())
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let input = names.first().ok_or("Name the input file.")?;
    let data = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    match command {
        "info" => {
            for line in package::describe(&package::open(&data)?)? {
                println!("{line}");
            }
            Ok(())
        }
        "decrypt" => {
            let output = names.get(1).ok_or("Name the output file.")?;
            let plain = package::decrypt(&data, &password(rest)?)?;
            std::fs::write(output, plain).map_err(|e| format!("{output}: {e}"))
        }
        "encrypt" => {
            let output = names.get(1).ok_or("Name the output file.")?;
            let argon2: Vec<u32> = value(rest, "--argon2").unwrap_or("3,65536,4").split(',')
                .map(|n| n.parse().map_err(|_| "--argon2 is PASSES,KIB,LANES"))
                .collect::<Result<_, _>>()?;
            if argon2.len() != 3 {
                return Err("--argon2 is PASSES,KIB,LANES".to_string());
            }
            let options = package::Options {
                scheme: value(rest, "--scheme").unwrap_or("aes").to_string(),
                iterations: value(rest, "--iterations").unwrap_or("100000").parse()
                    .map_err(|_| "--iterations is a number")?,
                argon2: (argon2[0], argon2[1], argon2[2]),
            };
            let sealed = package::encrypt(&data, &password(rest)?, &options)?;
            std::fs::write(output, sealed).map_err(|e| format!("{output}: {e}"))
        }
        _ => Err("usage: odf info|decrypt|encrypt ...".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("odf: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{field, hex, records, unhex};

    fn sha256(data: &[u8]) -> String {
        let mut hash = allcrypt::api::AnyHash::new("sha256").unwrap();
        allcrypt::hash_functions::HashFunction::update(&mut hash, data);
        hex(&allcrypt::hash_functions::HashFunction::digest(&mut hash))
    }

    /// Every file of a plain package but the manifest, by name.
    fn files(package_bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<(String, Vec<u8>)> = ziparchive::read(package_bytes).unwrap().iter()
            .filter(|e| e.name != "META-INF/manifest.xml")
            .map(|e| (e.name.clone(), ziparchive::content(e).unwrap())).collect();
        out.sort();
        out
    }

    /// Every recorded package - LibreOffice's under each scheme, and
    /// ours that LibreOffice opened - decrypts to the files the check's
    /// independent decryption found, and a wrong password is refused.
    #[test]
    fn test_every_document_decrypts_to_the_recorded_files() {
        let documents = records("odf.vec", "document");
        assert_eq!(documents.len(), 6);
        for record in &documents {
            let name = field(record, "name");
            let data = std::fs::read(fixtures::dir().join("odf").join(name)).unwrap();
            let plain = package::decrypt(&data, &unhex(field(record, "password")))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let ours: Vec<(String, String)> = files(&plain).into_iter()
                .map(|(n, d)| (hex(n.as_bytes()), sha256(&d))).collect();
            let recorded: Vec<(String, String)> = record.iter().filter(|(k, _)| k == "file")
                .map(|(_, v)| {
                    let (n, d) = v.split_once(' ').unwrap();
                    (n.to_string(), d.to_string())
                }).collect();
            assert_eq!(ours, recorded, "{name}");
            // LibreOffice's 100,000 iterations and 64 MiB of Argon2 cost
            // seconds in a debug build; ours, made cheap, stand for
            // them.
            if name.starts_with("ours-") {
                assert!(package::decrypt(&data, b"not the password").is_err(), "{name}");
            }
        }
    }

    fn sample_package() -> Vec<u8> {
        let content: Vec<u8> = (0..5000u32).map(|i| b"<text:p>odf</text:p>"[i as usize % 20])
            .collect();
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
 <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>"#;
        ziparchive::write(&[
            ziparchive::stored("mimetype", b"application/vnd.oasis.opendocument.text".to_vec()),
            ziparchive::deflated("content.xml", &content),
            ziparchive::stored("empty.bin", Vec::new()),
            ziparchive::stored("small.bin", vec![7; 15]),
            ziparchive::deflated("META-INF/manifest.xml", manifest),
        ])
    }

    /// Each scheme round-trips, including a file the manifest did not
    /// list and an empty one, and refuses the wrong password.
    #[test]
    fn test_every_scheme_round_trips() {
        let plain = sample_package();
        for scheme in ["aes", "blowfish", "gcm"] {
            let options = package::Options { scheme: scheme.to_string(), iterations: 10,
                                             argon2: (1, 64, 1) };
            let sealed = package::encrypt(&plain, "pässword".as_bytes(), &options).unwrap();
            let opened = package::decrypt(&sealed, "pässword".as_bytes()).unwrap();
            assert_eq!(files(&opened), files(&plain), "{scheme}");
            assert!(package::decrypt(&sealed, b"password").is_err(), "{scheme}");
            assert!(package::encrypt(&sealed, b"x", &options).is_err(), "{scheme}: twice");
        }
    }

    /// The whole-package GCM tag covers every byte; the per-file
    /// schemes check only the first kilobyte of each file, so a change
    /// past it surfaces, if at all, as a broken deflate stream.
    #[test]
    fn test_a_changed_gcm_package_is_refused() {
        let options = package::Options { scheme: "gcm".to_string(), iterations: 10,
                                         argon2: (1, 64, 1) };
        let sealed = package::encrypt(&sample_package(), b"pw", &options).unwrap();
        let mut entries = ziparchive::read(&sealed).unwrap();
        let whole = entries.iter_mut().find(|e| e.name == "encrypted-package").unwrap();
        for at in [12, whole.data.len() / 2, whole.data.len() - 1] {
            let mut changed = entries.clone();
            let target = changed.iter_mut().find(|e| e.name == "encrypted-package").unwrap();
            target.data[at] ^= 1;
            assert!(package::decrypt(&ziparchive::write(&changed), b"pw").is_err(), "byte {at}");
        }
    }

    /// The manifest ours writes names its attributes as LibreOffice's
    /// does, element for element, for each scheme - LibreOffice reads
    /// them by name, and a reader that only reads its own writer's
    /// names would never notice a misspelling.
    #[test]
    fn test_the_manifest_attributes_are_libreoffice_s() {
        fn names(package_bytes: &[u8]) -> Vec<(String, Vec<String>)> {
            let package = package::open(package_bytes).unwrap();
            let entry = package.manifest.elements()
                .find(|e| e.elements().any(|c| c.local_name() == "encryption-data")).unwrap();
            let data = entry.elements().find(|c| c.local_name() == "encryption-data").unwrap();
            let mut out = vec![(data.name.clone(), data.attributes.iter().map(|a| a.0.clone())
                .collect::<Vec<_>>())];
            for child in data.elements() {
                let mut attributes: Vec<String> = child.attributes.iter().map(|a| a.0.clone())
                    .collect();
                attributes.sort();
                out.push((child.name.clone(), attributes));
            }
            out.iter_mut().for_each(|(_, a)| a.sort());
            out
        }
        for scheme in ["aes", "blowfish", "gcm"] {
            let theirs = std::fs::read(fixtures::dir().join("odf")
                .join(format!("libreoffice-{scheme}.odt"))).unwrap();
            let options = package::Options { scheme: scheme.to_string(), iterations: 10,
                                             argon2: (1, 64, 1) };
            let ours = package::encrypt(&sample_package(), b"pw", &options).unwrap();
            assert_eq!(names(&ours), names(&theirs), "{scheme}");
        }
    }

    fn encrypted(scheme: &str) -> Vec<ziparchive::Entry> {
        let options = package::Options { scheme: scheme.to_string(), iterations: 10,
                                         argon2: (1, 64, 1) };
        ziparchive::read(&package::encrypt(&sample_package(), b"pw", &options).unwrap()).unwrap()
    }

    /// AES-CBC's padding is checked before the checksum: a last byte
    /// that cannot be a pad length is refused for that, here made by
    /// flipping the byte of the previous ciphertext block that CBC XORs
    /// into it.
    #[test]
    fn test_a_bad_aes_pad_is_refused_for_its_padding() {
        let mut entries = encrypted("aes");
        let small = entries.iter_mut().find(|e| e.name == "small.bin").unwrap();
        let n = small.data.len();
        // The last plaintext byte is a pad length of at most 16; XORed
        // with 0xef it is more than 16 whatever it was.
        small.data[n - 17] ^= 0xef;
        let error = package::decrypt(&ziparchive::write(&entries), b"pw").unwrap_err();
        assert!(error.contains("padding"), "{error}");
    }

    /// The GCM data repeats the manifest's IV in front of the
    /// ciphertext; a package where the two disagree is refused rather
    /// than decrypted under either.
    #[test]
    fn test_a_gcm_iv_that_disagrees_with_the_manifest_is_refused() {
        let mut entries = encrypted("gcm");
        entries.iter_mut().find(|e| e.name == "encrypted-package").unwrap().data[0] ^= 1;
        let error = package::decrypt(&ziparchive::write(&entries), b"pw").unwrap_err();
        assert!(error.contains("IV"), "{error}");
    }

    /// The decrypted package's manifest says nothing of encryption: no
    /// encryption data and no sizes, which belong to it alone.
    #[test]
    fn test_the_decrypted_manifest_is_plain() {
        for scheme in ["aes", "blowfish"] {
            let entries = encrypted(scheme);
            let plain = package::decrypt(&ziparchive::write(&entries), b"pw").unwrap();
            let manifest = ziparchive::read(&plain).unwrap().into_iter()
                .find(|e| e.name == "META-INF/manifest.xml").unwrap();
            let text = String::from_utf8(ziparchive::content(&manifest).unwrap()).unwrap();
            assert!(!text.contains("encryption-data") && !text.contains("manifest:size"),
                    "{scheme}: {text}");
            assert!(text.contains("content.xml"), "{scheme}");
        }
    }
}

