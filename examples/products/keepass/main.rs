//! KeePass databases (KDBX 3.1, 4.0 and 4.1), built from this library's
//! primitives.
//!
//!     cargo run --release --example keepass -- dump DATABASE [--password PW] [--key-file FILE]
//!             [--show-passwords | --canonical]
//!     cargo run --release --example keepass -- create OUT [--password PW] [--key-file FILE]
//!             [--format 3|40|41] [--cipher aes|chacha20|twofish] [--kdf aes|argon2d|argon2id]
//!             [--rounds N] [--iterations N] [--memory KIB] [--parallelism N] [--no-compress]
//!
//! `--password-stdin` in place of `--password PW` reads it from
//! standard input. Leaving out both the password and the key file is
//! an error; a database protected by a key file alone has no password.
//!
//! `dump` lists the groups and entries; `--canonical` prints the form
//! `scripts/witness/kdbxwitness` prints, with every value as hex, for
//! `scripts/check_keepass.py` to compare. `create` writes a sample
//! database - the same content the witness writes - under the chosen
//! format, cipher and key derivation.
//!
//! What has checked it is in `examples/products/README.md`.

mod database;
mod kdbx;

#[path = "../shared/inflate.rs"]
mod inflate;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/cli.rs"]
mod cli;
#[path = "../shared/hidden.rs"]
mod hidden;
#[path = "../shared/xml.rs"]
mod xml;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

pub use cli::hex;
use kdbx::{Cipher, Credentials, Kdf, Plan};

/// `YYYY-MM-DDTHH:MM:SSZ`, how KDBX 3.1 writes a time.
pub fn iso8601(unix: u64) -> String {
    let days = unix / 86400;
    let seconds = unix % 86400;
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", seconds / 3600,
            seconds / 60 % 60, seconds % 60)
}

#[path = "../shared/base64.rs"]
pub mod base64;

struct Options {
    positional: Vec<String>,
    values: std::collections::HashMap<String, String>,
    flags: std::collections::HashSet<String>,
}

const FLAGS: &[&str] = &["password-stdin", "show-passwords", "canonical", "no-compress"];

fn options(args: &[String]) -> Result<Options, String> {
    let mut out = Options { positional: Vec::new(), values: Default::default(),
                            flags: Default::default() };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(name) = arg.strip_prefix("--") {
            if FLAGS.contains(&name) {
                out.flags.insert(name.to_string());
            } else {
                let value = iter.next().ok_or(format!("--{name} needs a value"))?;
                out.values.insert(name.to_string(), value.clone());
            }
        } else {
            out.positional.push(arg.clone());
        }
    }
    Ok(out)
}

fn credentials(options: &Options) -> Result<Credentials, String> {
    let password = if options.flags.contains("password-stdin") {
        let bytes = passphrase::read_line("Password: ")?;
        Some(String::from_utf8(bytes).map_err(|_| "The password is not UTF-8.")?)
    } else {
        options.values.get("password").cloned()
    };
    let key_file = match options.values.get("key-file") {
        Some(path) => {
            let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            Some(kdbx::key_file(&data)?)
        }
        None => None,
    };
    if password.is_none() && key_file.is_none() {
        return Err("Give a password (--password or --password-stdin), a --key-file, or both."
            .to_string());
    }
    Ok(Credentials { password, key_file })
}

fn number<T: std::str::FromStr>(options: &Options, name: &str, default: T) -> Result<T, String> {
    match options.values.get(name) {
        Some(text) => text.parse().map_err(|_| format!("--{name} is not a number")),
        None => Ok(default),
    }
}

fn print_group(group: &database::Group, depth: usize, show: bool) {
    let indent = "  ".repeat(depth);
    println!("{indent}[{}]", group.name);
    for entry in &group.entries {
        println!("{indent}  {}", entry.field("Title"));
        for field in &entry.fields {
            if field.key == "Title" || field.value.is_empty() {
                continue;
            }
            let value = if field.protected && !show { "********" } else { &field.value };
            println!("{indent}    {}: {}", field.key, value.replace('\n', "\n        "));
        }
        for (name, data) in &entry.attachments {
            println!("{indent}    attachment {name}: {} bytes", data.len());
        }
        if entry.history > 0 {
            println!("{indent}    history: {} earlier versions", entry.history);
        }
    }
    for child in &group.groups {
        print_group(child, depth + 1, show);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let options = options(args.get(1..).unwrap_or(&[]))?;
    let path = options.positional.first().ok_or("Name the database file.")?;
    match command {
        "dump" => {
            let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let opened = kdbx::open(&data, &credentials(&options)?)?;
            let header = opened.header.clone();
            let read = database::read(opened)?;
            if options.flags.contains("canonical") {
                print!("{}", database::canonical(&header, &read.database));
                return Ok(());
            }
            println!("KDBX {}.{}, {}, key derivation {}{}", header.major, header.minor,
                     header.cipher.name(), header.kdf.name(),
                     if header.compressed { ", compressed" } else { "" });
            if read.header_hash_checked {
                println!("header hash checked against Meta/HeaderHash");
            }
            println!("database {:?}", read.database.name);
            for group in &read.database.groups {
                print_group(group, 0, options.flags.contains("show-passwords"));
            }
            Ok(())
        }
        "create" => {
            let format = options.values.get("format").map(String::as_str).unwrap_or("41");
            let (major, minor) = match format {
                "3" | "31" => (3, 1),
                "4" | "40" => (4, 0),
                "41" => (4, 1),
                other => return Err(format!("Unknown format {other}; 3, 40 or 41.")),
            };
            let cipher = match options.values.get("cipher").map(String::as_str).unwrap_or("aes") {
                "aes" => Cipher::Aes,
                "chacha20" => Cipher::ChaCha20,
                "twofish" => Cipher::Twofish,
                other => return Err(format!("Unknown cipher {other}.")),
            };
            let random = |n| allcrypt::api::random_bytes(n);
            let default_kdf = if major >= 4 { "argon2id" } else { "aes" };
            let kdf_name = options.values.get("kdf").map(String::as_str).unwrap_or(default_kdf);
            let kdf = match kdf_name {
                "aes" => Kdf::Aes { seed: random(32)?, rounds: number(&options, "rounds", 100_000)? },
                "argon2d" | "argon2id" if major >= 4 => Kdf::Argon2 {
                    id: kdf_name == "argon2id",
                    salt: random(32)?,
                    iterations: number(&options, "iterations", 10)?,
                    memory: number::<u64>(&options, "memory", 65536)? * 1024,
                    parallelism: number(&options, "parallelism", 2)?,
                    version: 0x13,
                    secret: Vec::new(),
                    associated: Vec::new(),
                },
                "argon2d" | "argon2id" => {
                    return Err("KDBX 3.1 has only AES-KDF; use --format 40 or 41 for Argon2."
                        .to_string())
                }
                other => return Err(format!("Unknown key derivation {other}.")),
            };
            let plan = Plan { major, minor, cipher, kdf,
                              compressed: !options.flags.contains("no-compress"),
                              inner_stream: if major >= 4 { 3 } else { 2 } };
            let bytes = database::write(&database::sample(), &plan, &credentials(&options)?)?;
            std::fs::write(path, bytes).map_err(|e| format!("{path}: {e}"))
        }
        _ => Err("usage: keepass dump DATABASE ... | keepass create OUT ...".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("keepass: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(text: &str) -> Credentials {
        Credentials { password: Some(text.to_string()), key_file: None }
    }

    fn quick(major: u16, minor: u16, cipher: Cipher, kdf: Kdf) -> Plan {
        Plan { major, minor, cipher, kdf, compressed: true,
               inner_stream: if major >= 4 { 3 } else { 2 } }
    }

    fn aes(rounds: u64) -> Kdf {
        Kdf::Aes { seed: vec![7; 32], rounds }
    }

    /// Every format and cipher writes a database that reads back as the
    /// same content.
    #[test]
    fn test_what_is_written_reads_back() {
        for (major, minor) in [(3, 1), (4, 0), (4, 1)] {
            for cipher in [Cipher::Aes, Cipher::Twofish, Cipher::ChaCha20] {
                let plan = quick(major, minor, cipher, aes(10));
                let bytes = database::write(&database::sample(), &plan, &password("pw")).unwrap();
                let opened = kdbx::open(&bytes, &password("pw")).unwrap();
                let read = database::read(opened).unwrap();
                assert_eq!(read.database, database::sample(), "{major}.{minor} {cipher:?}");
                assert_eq!(read.header_hash_checked, major == 3);
                assert!(kdbx::open(&bytes, &password("wrong")).is_err());
            }
        }
    }

    /// Every database `scripts/check_keepass.py --record` kept - those
    /// KeePass, KeePassXC and kdbxweb wrote for gokeepasslib's tests, and
    /// those gokeepasslib wrote in every format, cipher and key
    /// derivation it has, under a key file of each kind - listed exactly
    /// as gokeepasslib listed it.
    #[test]
    fn test_the_recorded_databases_list_as_gokeepasslib_listed_them() {
        let records = fixtures::records("keepass.vec", "database");
        assert_eq!(records.len(), 28);
        let dir = fixtures::dir().join("keepass");
        let mut versions = std::collections::BTreeSet::new();
        for record in &records {
            let name = fixtures::field(record, "name");
            let password = String::from_utf8(fixtures::unhex(fixtures::field(record, "password")))
                .unwrap();
            let key_file = record.iter().find(|(k, _)| k == "key_file").map(|(_, file)| {
                kdbx::key_file(&std::fs::read(dir.join(file)).unwrap()).unwrap()
            });
            let data = std::fs::read(dir.join(format!("{name}.kdbx"))).unwrap();
            let opened = kdbx::open(&data, &Credentials { password: Some(password), key_file })
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let header = opened.header.clone();
            versions.insert((header.major, header.minor, header.cipher.name(), header.kdf.name()));
            let read = database::read(opened).unwrap_or_else(|e| panic!("{name}: {e}"));
            let expected = String::from_utf8(fixtures::unhex(fixtures::field(record, "listing")))
                .unwrap();
            assert_eq!(database::canonical(&header, &read.database), expected, "{name}");
        }
        // Three formats, three ciphers, two key derivations among them.
        assert!(versions.len() >= 12, "{versions:?}");
    }

    /// KDBX 3.1 authenticates its header only through the hash the XML
    /// repeats. A comment field inserted into the header changes nothing
    /// the decryption uses, so only that check can refuse it.
    #[test]
    fn test_a_changed_kdbx3_header_is_refused_by_its_hash() {
        let plan = quick(3, 1, Cipher::Aes, aes(10));
        let bytes = database::write(&database::sample(), &plan, &password("pw")).unwrap();
        let mut changed = bytes[..12].to_vec();
        changed.extend_from_slice(&[1, 3, 0, b'h', b'i', b'!']);
        changed.extend_from_slice(&bytes[12..]);
        let opened = kdbx::open(&changed, &password("pw")).unwrap();
        let error = database::read(opened).unwrap_err();
        assert!(error.contains("HeaderHash"), "{error}");
    }

    /// A version 2.0 key file carries the first four bytes of its key's
    /// SHA-256; a wrong one is refused rather than giving a wrong key.
    #[test]
    fn test_a_version_2_key_file_with_a_wrong_hash_is_refused() {
        let path = fixtures::dir().join("keepass").join("w-kdbx40-chacha20-aes-xml_v2.0.key");
        let text = std::fs::read_to_string(path).unwrap();
        assert!(kdbx::key_file(text.as_bytes()).is_ok());
        let start = text.find("Hash=\"").unwrap() + 6;
        let mut bent = text.clone();
        let flipped = if &text[start..start + 1] == "0" { "1" } else { "0" };
        bent.replace_range(start..start + 1, flipped);
        assert_eq!(kdbx::key_file(bent.as_bytes()).unwrap_err(),
                   "The key file's hash does not match its key.");
    }

    #[test]
    fn test_base64_round_trips_and_refuses_junk() {
        for length in 0..10 {
            let data: Vec<u8> = (0..length).map(|i: u8| i.wrapping_mul(37)).collect();
            assert_eq!(base64::decode(&base64::encode(&data)).unwrap(), data);
        }
        // Python's base64.b64encode(b"any carnal pleas").
        assert_eq!(base64::encode(b"any carnal pleas"), "YW55IGNhcm5hbCBwbGVhcw==");
        assert!(base64::decode("YW=5").is_none());
        assert!(base64::decode("YW5").is_none());
        assert!(base64::decode("Y!==").is_none());
    }

    /// Expected values from Python's
    /// `datetime.fromtimestamp(t, timezone.utc).isoformat()`.
    #[test]
    fn test_iso8601() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_790_000_000), "2026-09-21T14:13:20Z");
    }
}
