//! DNSSEC (RFC 4033 to 4035, with RFC 5155's NSEC3), built from this
//! library's primitives: keys, DS records, zone signing and zone
//! checking, for every DNSSEC algorithm the IANA registry has assigned
//! a signing scheme, the deprecated ones included.
//!
//!     cargo run --release --example dnssec -- keygen ZONE --algorithm A [--ksk]
//!             [--bits N] [--directory DIR]
//!     cargo run --release --example dnssec -- ds KEYFILE [--digest N]...
//!     cargo run --release --example dnssec -- sign ZONEFILE --origin ZONE --key PRIVATE...
//!             [--inception T] [--expiration T] [--nsec3 SALT ITERATIONS] [--out FILE]
//!     cargo run --release --example dnssec -- verify ZONEFILE --origin ZONE [--now T]
//!     cargo run --release --example dnssec -- nsec3-hash NAME SALT ITERATIONS
//!     cargo run --release --example dnssec -- key-tag KEYFILE
//!     cargo run --release --example dnssec -- algorithms
//!
//! `keygen` writes BIND's pair of files, `K<zone>+<alg>+<tag>.key` (the
//! DNSKEY record) and `.private` (format v1.3). `sign` takes those
//! `.private` files; each one's `.key` beside it gives the flags, and
//! without one the key is a zone-signing key. A time `T` is
//! `YYYYMMDDHHmmSS` or seconds since 1970; signing defaults to an hour ago
//! until thirty days on. `ds` defaults to SHA-256. A SALT of `-` is
//! empty.
//!
//! What has checked it is in `examples/products/README.md`.

mod keys;
mod name;
mod rr;
mod sign;
mod zone;

#[path = "../shared/base64.rs"]
mod base64;
#[path = "../shared/cli.rs"]
mod cli;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use std::path::{Path, PathBuf};

use cli::value;
use keys::Key;
use name::Name;
use rr::{Dnskey, Nsec3Param, Record};

const SWITCHES: [&str; 1] = ["--ksk"];

fn positional(args: &[String]) -> Vec<&String> {
    cli::positional(args, &SWITCHES, &[("--nsec3", 2)])
}

fn values<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.iter().enumerate().filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| args.get(i + 1).map(String::as_str)).collect()
}

fn now() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32).unwrap_or(0)
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The DNSKEY record in a `.key` file: its first record line.
fn read_key_file(path: &str) -> Result<Record, String> {
    let records = zone::parse(&read(path)?, &Name::root())?;
    records.into_iter().find(|r| r.rtype == rr::DNSKEY)
        .ok_or_else(|| format!("{path}: no DNSKEY record."))
}

fn salt(text: &str) -> Result<Vec<u8>, String> {
    if text == "-" { Ok(Vec::new()) } else { rr::unhex(text) }
}

// ----------------------------------------------------------------- commands --

fn keygen(args: &[String]) -> Result<(), String> {
    let zone_name = positional(args).get(1).map(|s| s.as_str()).ok_or("keygen ZONE")?;
    let zone = Name::parse(zone_name, Some(&Name::root()))?;
    let algorithm = keys::algorithm_named(value(args, "--algorithm")
        .ok_or("keygen needs --algorithm.")?)?;
    let bits: usize = value(args, "--bits").unwrap_or("2048").parse()
        .map_err(|_| "--bits takes a number.")?;
    let key = Key::generate(algorithm, bits)?;
    let flags = rr::ZONE_KEY | if args.iter().any(|a| a == "--ksk") { rr::SEP } else { 0 };
    let dnskey = Dnskey { flags, protocol: 3, algorithm: algorithm.number,
                          public_key: key.public_key()? };
    let rdata = dnskey.to_rdata();
    let tag = keys::key_tag(&rdata);
    let record = Record { owner: zone.clone(), ttl: 3600, class: rr::CLASS_IN,
                          rtype: rr::DNSKEY, rdata };
    let base = format!("K{}+{:03}+{:05}", zone, algorithm.number, tag);
    let directory = PathBuf::from(value(args, "--directory").unwrap_or("."));
    let kind = if flags & rr::SEP != 0 { "key-signing" } else { "zone-signing" };
    write(&directory.join(format!("{base}.key")),
          &format!("; This is a {kind} key, keyid {tag}, for {zone}\n{}\n", record.to_text()))?;
    write(&directory.join(format!("{base}.private")), &key.to_private_file()?)?;
    println!("{base}");
    Ok(())
}

fn ds(args: &[String]) -> Result<(), String> {
    let path = positional(args).get(1).map(|s| s.as_str()).ok_or("ds KEYFILE")?;
    let record = read_key_file(path)?;
    let digests = values(args, "--digest");
    let digests: Vec<u8> = if digests.is_empty() { vec![2] } else {
        digests.iter().map(|d| d.parse().map_err(|_| format!("{d}: not a digest type.")))
            .collect::<Result<_, _>>()?
    };
    let dnskey = Dnskey::parse(&record.rdata)?;
    for digest_type in digests {
        let digest = keys::ds_digest(&record.owner, &record.rdata, digest_type)?;
        let mut rdata = keys::key_tag(&record.rdata).to_be_bytes().to_vec();
        rdata.extend([dnskey.algorithm, digest_type]);
        rdata.extend(digest);
        println!("{}", Record { rtype: rr::DS, rdata, ..record.clone() }.to_text());
    }
    Ok(())
}

fn sign_command(args: &[String]) -> Result<(), String> {
    let path = positional(args).get(1).map(|s| s.as_str()).ok_or("sign ZONEFILE")?;
    let origin = Name::parse(value(args, "--origin").ok_or("sign needs --origin.")?,
                             Some(&Name::root()))?;
    let records = zone::parse(&read(path)?, &origin)?;
    let mut keys = Vec::new();
    for private in values(args, "--key") {
        let key = Key::from_private_file(&read(private)?)?;
        let public = private.strip_suffix(".private").map(|b| format!("{b}.key"));
        let flags = match public.filter(|p| Path::new(p).exists()) {
            Some(p) => Dnskey::parse(&read_key_file(&p)?.rdata)?.flags,
            None => rr::ZONE_KEY,
        };
        keys.push((key, flags));
    }
    if keys.is_empty() {
        return Err("sign needs at least one --key.".to_string());
    }
    let now = now();
    let inception = value(args, "--inception").map(rr::parse_time).transpose()?
        .unwrap_or(now.wrapping_sub(3600));
    let expiration = value(args, "--expiration").map(rr::parse_time).transpose()?
        .unwrap_or(now.wrapping_add(30 * 86400));
    let nsec3 = match args.iter().position(|a| a == "--nsec3") {
        None => None,
        Some(i) => {
            let s = args.get(i + 1).ok_or("--nsec3 SALT ITERATIONS")?;
            let n = args.get(i + 2).ok_or("--nsec3 SALT ITERATIONS")?;
            Some(Nsec3Param { hash_algorithm: 1, flags: 0, salt: salt(s)?,
                              iterations: n.parse().map_err(|_| "Iterations is a number.")? })
        }
    };
    let options = sign::Options { inception, expiration, nsec3 };
    let signed = sign::sign_zone(records, &keys, &options)?;
    let text: String = signed.iter().map(|r| r.to_text() + "\n").collect();
    match value(args, "--out") {
        Some(out) => write(Path::new(out), &text),
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

fn verify_command(args: &[String]) -> Result<bool, String> {
    let path = positional(args).get(1).map(|s| s.as_str()).ok_or("verify ZONEFILE")?;
    let origin = Name::parse(value(args, "--origin").ok_or("verify needs --origin.")?,
                             Some(&Name::root()))?;
    let records = zone::parse(&read(path)?, &origin)?;
    let now = value(args, "--now").map(rr::parse_time).transpose()?.unwrap_or_else(now);
    let report = sign::verify_zone(records, now)?;
    for problem in &report.problems {
        println!("{problem}");
    }
    println!("{} RRsets, {} signatures, {} valid, {}: {}", report.rrsets, report.signatures,
             report.valid, report.denial,
             if report.problems.is_empty() { "good" } else { "BAD" });
    Ok(report.problems.is_empty())
}

fn run(args: &[String]) -> Result<bool, String> {
    let positional = positional(args);
    match positional.first().map(|s| s.as_str()) {
        Some("keygen") => keygen(args)?,
        Some("ds") => ds(args)?,
        Some("key-tag") => {
            let path = positional.get(1).ok_or("key-tag KEYFILE")?;
            println!("{}", keys::key_tag(&read_key_file(path)?.rdata));
        }
        Some("sign") => sign_command(args)?,
        Some("verify") => return verify_command(args),
        Some("nsec3-hash") => {
            let [_, name, s, n] = positional[..] else {
                return Err("nsec3-hash NAME SALT ITERATIONS".to_string());
            };
            let name = Name::parse(name, Some(&Name::root()))?;
            let hash = keys::nsec3_hash(&name, 1, &salt(s)?,
                                        n.parse().map_err(|_| "Iterations is a number.")?)?;
            println!("{}", rr::base32hex(&hash));
        }
        Some("algorithms") => {
            for a in keys::ALGORITHMS {
                println!("{:>2} {}", a.number, a.mnemonic);
            }
            for (n, name, _) in keys::DIGEST_TYPES {
                println!("DS {n} {name}");
            }
        }
        _ => return Err("Commands: keygen, ds, key-tag, sign, verify, nsec3-hash, \
                         algorithms. See the top of examples/products/dnssec/main.rs."
                        .to_string()),
    }
    Ok(true)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("dnssec: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests;
