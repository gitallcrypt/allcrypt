//! OpenPGP messages (RFC 9580, its predecessors RFC 4880 and 2440, and
//! LibrePGP), built from this library's primitives.
//!
//!     cargo run --release --example openpgp -- decrypt IN OUT (--passphrase PW | --passphrase-stdin)...
//!     cargo run --release --example openpgp -- decrypt IN OUT --session-key CIPHER[.AEAD]:HEX
//!     cargo run --release --example openpgp -- encrypt IN OUT (--passphrase PW | --passphrase-stdin)...
//!         [--cipher NAME] [--format v4|no-mdc|librepgp|rfc9580] [--aead ocb|eax|gcm]
//!         [--compress none|zip|zlib] [--s2k iterated|argon2] [--chunk-size N]
//!         [--esk] [--armor] [--seed N]
//!     cargo run --release --example openpgp -- decrypt IN OUT --secret-key FILE [--passphrase PW]
//!     cargo run --release --example openpgp -- encrypt IN OUT --recipient FILE [options]
//!     cargo run --release --example openpgp -- sign IN OUT --secret-key FILE [--detached | --clearsign]
//!         [--text] [--hash NAME] [--armor] [--passphrase PW | --passphrase-stdin]
//!     cargo run --release --example openpgp -- verify IN [--signature SIG] --key FILE...
//!     cargo run --release --example openpgp -- gen-key SECRET PUBLIC --algo NAME [--v6]
//!         --uid "Name <address>" [--passphrase PW | --passphrase-stdin] [--expire DAYS]
//!     cargo run --release --example openpgp -- list-keys FILE
//!     cargo run --release --example openpgp -- list-packets IN
//!     cargo run --release --example openpgp -- dearmor IN OUT
//!
//! `decrypt` reads armored or binary input, prints what it found to
//! standard output and writes the literal data to OUT. `encrypt`'s
//! formats: `v4` (SKESK v4 and SEIPD v1 with its MDC - what every reader
//! takes, and the default), `no-mdc` (SKESK v4 and the Symmetrically
//! Encrypted Data packet, with no integrity protection), `librepgp`
//! (SKESK v5 and the OCB Encrypted Data packet GnuPG 2.3 and later
//! write) and `rfc9580` (SKESK v6 and SEIPD v2).
//!
//! What has checked it is in `examples/products/README.md`.

mod algo;
mod armor;
mod keygen;
mod keys;
mod message;
mod packet;
mod pubkey;
mod s2k;
mod sig;
mod verify;

#[path = "../shared/inflate.rs"]
mod inflate;
#[path = "../shared/bunzip2.rs"]
mod bunzip2;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use allcrypt::hash_functions::HashFunction;
use message::{Format, Options, Passphrases, Recipient, S2kChoice};

/// SHA-256 of a seed and a counter, as a stream: reproducible output
/// for tests and fixtures. Not a random number generator anyone should
/// use.
fn counter_stream(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), String> {
    let mut counter = 0u64;
    let mut pool: Vec<u8> = Vec::new();
    move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            if pool.is_empty() {
                let mut input = seed.to_be_bytes().to_vec();
                input.extend_from_slice(&counter.to_be_bytes());
                pool = algo::digest(algo::hash(8)?, &[&input]);
                counter += 1;
            }
            *byte = pool.remove(0);
        }
        Ok(())
    }
}

fn list_packets(packets: &[packet::Packet], depth: usize, out: &mut String) {
    for p in packets {
        out.push_str(&format!("{:indent$}{} (tag {}), {} bytes{}{}\n", "",
                              packet::tag_name(p.tag), p.tag, p.body.len(),
                              if p.legacy { ", legacy header" } else { "" },
                              if p.partial { ", partial lengths" } else { "" },
                              indent = depth * 2));
        if p.tag == packet::COMPRESSED {
            if let Ok(data) = message_decompress(&p.body) {
                if let Ok(inner) = packet::parse(&data) {
                    list_packets(&inner, depth + 1, out);
                }
            }
        }
    }
}

fn message_decompress(body: &[u8]) -> Result<Vec<u8>, String> {
    let (algorithm, data) = body.split_first().ok_or("an empty compressed packet")?;
    match algorithm {
        0 => Ok(data.to_vec()),
        1 => Ok(inflate::inflate(data, 1 << 31)?.0),
        2 => inflate::zlib_decompress(data, 1 << 31),
        3 => bunzip2::decompress(data, 1 << 31),
        other => Err(format!("compression algorithm {other}")),
    }
}

struct Args {
    positional: Vec<String>,
    values: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn parse(args: &[String]) -> Result<Args, String> {
        const FLAGS: &[&str] = &["armor", "esk", "passphrase-stdin", "detached", "clearsign",
                                 "text", "v6", "binary"];
        let mut parsed = Args { positional: Vec::new(), values: Vec::new(), flags: Vec::new() };
        let mut i = 0;
        while i < args.len() {
            if let Some(name) = args[i].strip_prefix("--") {
                if FLAGS.contains(&name) {
                    parsed.flags.push(name.to_string());
                    i += 1;
                } else {
                    let value = args.get(i + 1).ok_or(format!("--{name} needs a value"))?;
                    parsed.values.push((name.to_string(), value.clone()));
                    i += 2;
                }
            } else {
                parsed.positional.push(args[i].clone());
                i += 1;
            }
        }
        Ok(parsed)
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.values.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }

    fn one(&self, name: &str) -> Option<&str> {
        self.all(name).last().copied()
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    fn passphrases(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut all: Vec<Vec<u8>> = self.all("passphrase").iter()
            .map(|p| p.as_bytes().to_vec()).collect();
        if self.flag("passphrase-stdin") {
            all.push(passphrase::read_line("Passphrase: ")?);
        }
        Ok(all)
    }
}

/// Every transferable key in the files named.
fn read_certs(paths: &[&str]) -> Result<Vec<keys::Cert>, String> {
    let mut certs = Vec::new();
    for path in paths {
        let raw = read_file(path)?;
        let packets = if armor::is_armored(&raw) {
            let text = std::str::from_utf8(&raw).map_err(|_| "armor that is not text")?;
            let mut all = Vec::new();
            for block in armor::decode_all(text)? {
                all.extend(packet::parse(&block.data)?);
            }
            all
        } else {
            packet::parse(&raw)?
        };
        let found = keys::Cert::read_all(&packets)?;
        if found.is_empty() {
            return Err(format!("{path}: no keys"));
        }
        certs.extend(found);
    }
    Ok(certs)
}

fn now(args: &Args) -> Result<u32, String> {
    match args.one("date") {
        Some(d) => d.parse().map_err(|e| format!("--date: {e}")),
        None => Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?.as_secs() as u32),
    }
}

/// The signing key of the first certificate, unlocked with whichever
/// passphrase opens it.
fn unlock_signer(certs: &[keys::Cert], passphrases: &[Vec<u8>], now: u32)
                 -> Result<(keys::PublicKey, keys::Secret), String> {
    let cert = certs.first().ok_or("no signing key given")?;
    let key = verify::signing_key(cert, now)?;
    let secret = key.secret.as_ref().expect("signing_key requires a secret part");
    let attempts: Vec<&[u8]> = if secret.is_protected() {
        passphrases.iter().map(Vec::as_slice).collect()
    } else {
        vec![&[]]
    };
    let mut last = "the signing key is protected; give its passphrase".to_string();
    for passphrase in attempts {
        match secret.unlock(passphrase) {
            Ok(s) => return Ok((key.public.clone(), s)),
            Err(why) => last = why,
        }
    }
    Err(last)
}

/// The hash to sign with: what was asked, or what suits the key.
fn signing_hash(args: &Args, key: &keys::PublicKey) -> Result<algo::Hash, String> {
    if let Some(name) = args.one("hash") {
        return algo::hash_by_name(name);
    }
    let id = match key.curve().map(|c| c.name) {
        Some("NIST P-384" | "brainpoolP384r1") => 9,
        Some("NIST P-521" | "brainpoolP512r1" | "Ed448") => 10,
        _ if key.algorithm == keys::ED448 => 10,
        _ => 8,
    };
    algo::hash(id)
}

fn print_verdicts(verdicts: &[verify::Verdict]) -> Result<(), String> {
    for v in verdicts {
        println!("{}", v.text);
    }
    if verdicts.is_empty() {
        return Err("no signatures".to_string());
    }
    if verdicts.iter().any(|v| !v.good) {
        return Err("not every signature is good".to_string());
    }
    Ok(())
}

fn flag_letters(flags: Option<u8>) -> String {
    match flags {
        None => String::new(),
        Some(f) => [(0x01, 'C'), (sig::FLAG_SIGN, 'S'), (sig::FLAG_ENCRYPT, 'E'),
                    (0x20, 'A')].iter().filter(|(bit, _)| f & bit != 0)
            .map(|(_, c)| *c).collect(),
    }
}

fn list_keys(certs: &[keys::Cert], now: u32) -> String {
    let mut out = String::new();
    for cert in certs {
        let checked = verify::check(cert, now);
        let key_checks = std::iter::once(&checked.primary).chain(&checked.subkeys);
        for (i, (key, c)) in cert.keys().zip(key_checks).enumerate() {
            let p = &key.public;
            out.push_str(&format!(
                "{} v{} {} created {} fingerprint {} key ID {}{} [{}]{}\n",
                if i == 0 { "key" } else { "  subkey" }, p.version, p.describe(), p.created,
                keys::hex_upper(&p.fingerprint()), keys::hex_upper(&p.key_id()),
                match &key.secret {
                    None => "",
                    Some(s) if s.is_stub() => ", secret part elsewhere",
                    Some(s) if s.is_protected() => ", secret (protected)",
                    Some(_) => ", secret",
                },
                flag_letters(c.flags),
                if c.usable { String::new() } else { format!(" unusable: {}",
                                                             c.problems.join("; ")) }));
            if i == 0 {
                for (uid, valid) in cert.user_ids.iter().zip(&checked.user_ids) {
                    let name = if uid.packet.tag == packet::USER_ID {
                        format!("user ID {}", String::from_utf8_lossy(&uid.packet.body))
                    } else {
                        "user attribute".to_string()
                    };
                    out.push_str(&format!("  {name}{}\n",
                                          if *valid { "" } else { " (no valid self-signature)" }));
                }
            }
        }
    }
    out
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| format!("{path}: {e}"))
}

fn options(args: &Args) -> Result<Options, String> {
    let mut options = Options::new(algo::cipher_by_name(args.one("cipher").unwrap_or("aes256"))?);
    if let Some(format) = args.one("format") {
        options.format = match format {
            "v4" => Format::V4,
            "no-mdc" => Format::NoMdc,
            "librepgp" => Format::LibrePgp,
            "rfc9580" => Format::Rfc9580,
            other => return Err(format!("unknown format {other}")),
        };
    }
    if let Some(aead) = args.one("aead") {
        options.aead = algo::aead_by_name(aead)?;
    }
    if let Some(compress) = args.one("compress") {
        options.compression = match compress {
            "none" => 0,
            "zip" => 1,
            "zlib" => 2,
            other => return Err(format!("unknown compression {other} (none, zip, zlib)")),
        };
    }
    if let Some(s2k) = args.one("s2k") {
        options.s2k = match s2k {
            "iterated" => options.s2k,
            // RFC 9106's second recommended option: 64 MiB, three passes.
            "argon2" => S2kChoice::Argon2 { passes: 3, parallelism: 4, encoded_memory: 16 },
            other => return Err(format!("unknown S2K {other} (iterated, argon2)")),
        };
    }
    if let Some(octets) = args.one("s2k-octets") {
        if let S2kChoice::Iterated { hash, .. } = options.s2k {
            options.s2k = S2kChoice::Iterated {
                hash, octets: octets.parse().map_err(|e| format!("--s2k-octets: {e}"))? };
        }
    }
    if let Some(hash) = args.one("s2k-hash") {
        if let S2kChoice::Iterated { octets, .. } = options.s2k {
            options.s2k = S2kChoice::Iterated { hash: algo::hash_by_name(hash)?, octets };
        }
    }
    if let Some(n) = args.one("chunk-size") {
        options.chunk_byte = n.parse().map_err(|e| format!("--chunk-size: {e}"))?;
    }
    options.esk = args.flag("esk");
    Ok(options)
}

fn run(raw: &[String]) -> Result<(), String> {
    let usage = "usage: openpgp decrypt IN OUT (--passphrase P | --passphrase-stdin | \
                 --secret-key FILE | --session-key K)... [--key FILE] \
                 | encrypt IN OUT (--passphrase P | --passphrase-stdin | --recipient FILE)... \
                 [--sign-with FILE] [options] \
                 | sign IN OUT --secret-key FILE [--detached | --clearsign] [--text] [options] \
                 | verify IN [--signature SIG] --key FILE... \
                 | gen-key SECRET PUBLIC --algo NAME [--v6] --uid UID [--passphrase P] \
                 | list-keys FILE | list-packets IN | dearmor IN OUT";
    let command = raw.first().ok_or(usage)?;
    let args = Args::parse(&raw[1..])?;
    let seed = args.one("seed").map(|s| s.parse::<u64>().map_err(|e| e.to_string()))
        .transpose()?;
    let mut os_random = |b: &mut [u8]| allcrypt::random::fill(b);
    let mut seeded = seed.map(counter_stream);
    let random: message::Random<'_> = match seeded.as_mut() {
        Some(s) => s,
        None => &mut os_random,
    };
    let now = now(&args)?;
    match (command.as_str(), &args.positional[..]) {
        ("list-packets", [input]) => {
            let raw = read_file(input)?;
            let mut out = String::new();
            if armor::is_armored(&raw) {
                let text = std::str::from_utf8(&raw).map_err(|_| "armor that is not text")?;
                for block in armor::decode_all(text)? {
                    out.push_str(&format!("armor: {}\n", block.label));
                    for (key, value) in &block.headers {
                        out.push_str(&format!("  {key}: {value}\n"));
                    }
                }
            }
            let data = armor::dearmor(&raw)?;
            list_packets(&packet::parse(&data)?, 0, &mut out);
            print!("{out}");
            Ok(())
        }
        ("list-keys", [input]) => {
            print!("{}", list_keys(&read_certs(&[input])?, now));
            Ok(())
        }
        ("dearmor", [input, output]) => write_file(output, &armor::dearmor(&read_file(input)?)?),
        ("decrypt", [input, output]) => {
            let data = armor::dearmor(&read_file(input)?)?;
            let session_keys = args.all("session-key").iter()
                .map(|k| message::parse_session_key(k)).collect::<Result<Vec<_>, _>>()?;
            let secret_keys = read_certs(&args.all("secret-key"))?;
            let mut verifying = read_certs(&args.all("key"))?;
            verifying.extend(secret_keys.iter().cloned());
            let unlocker: Box<dyn message::Unlocker> = if !session_keys.is_empty() {
                Box::new(message::SessionKeys(session_keys))
            } else if !secret_keys.is_empty() {
                let mut passphrases = args.passphrases()?;
                passphrases.extend(args.all("key-passphrase").iter().map(|p| p.as_bytes().to_vec()));
                Box::new(message::Keys::new(secret_keys, passphrases))
            } else {
                Box::new(Passphrases(args.passphrases()?))
            };
            let message = message::read(&packet::parse(&data)?, unlocker.as_ref())?;
            for line in &message.log {
                println!("{line}");
            }
            if message.unprotected {
                println!("warning: the message has no integrity protection");
            }
            let verdicts = verify::verify_message(&message, &verifying, now);
            let literal = message.literal.as_ref().expect("read requires literal data");
            println!("literal data: format {:?}, name {:?}, {} bytes",
                     literal.format as char, String::from_utf8_lossy(&literal.filename),
                     literal.data.len());
            write_file(output, &literal.data)?;
            if message.signatures.is_empty() {
                return Ok(());
            }
            print_verdicts(&verdicts)
        }
        ("encrypt", [input, output]) => {
            let data = read_file(input)?;
            let mut options = options(&args)?;
            options.filename = std::path::Path::new(input).file_name()
                .map(|n| n.to_string_lossy().as_bytes().to_vec()).unwrap_or_default();
            options.filename.truncate(255);
            let mut recipients: Vec<Recipient> = args.passphrases()?.into_iter()
                .map(Recipient::Passphrase).collect();
            for cert in read_certs(&args.all("recipient"))? {
                recipients.push(Recipient::Key(verify::encryption_key(&cert, now)?));
            }
            let signers = read_certs(&args.all("sign-with"))?;
            let inner = if signers.is_empty() {
                message::literal_packets(&data, &options)
            } else {
                let passphrases: Vec<Vec<u8>> = args.all("key-passphrase").iter()
                    .map(|p| p.as_bytes().to_vec()).collect();
                let (key, secret) = unlock_signer(&signers, &passphrases, now)?;
                let hash = signing_hash(&args, &key)?;
                message::signed_packets(&data, &options, &message::Signer { key: &key, secret },
                                        hash, args.flag("text"), now, random)?
            };
            let encrypted = message::encrypt(&inner, &recipients, &options, random)?;
            if args.flag("armor") {
                write_file(output, armor::encode("MESSAGE", &encrypted).as_bytes())
            } else {
                write_file(output, &encrypted)
            }
        }
        ("sign", [input, output]) => {
            let data = read_file(input)?;
            let mut passphrases = args.passphrases()?;
            passphrases.extend(args.all("key-passphrase").iter().map(|p| p.as_bytes().to_vec()));
            let (key, secret) = unlock_signer(&read_certs(&args.all("secret-key"))?,
                                              &passphrases, now)?;
            let hash = signing_hash(&args, &key)?;
            let text = args.flag("text") || args.flag("clearsign");
            let signer = message::Signer { key: &key, secret };
            if args.flag("detached") || args.flag("clearsign") {
                let signed = if args.flag("clearsign") { verify::cleartext_signed_form(&data) }
                             else if text { sig::canonical_text(&data) } else { data.clone() };
                let (hashed, unhashed) = sig::standard_subpackets(&key, now);
                let metadata = args.flag("clearsign").then_some(&verify::CLEARTEXT_METADATA[..]);
                let body = sig::make(&key, &signer.secret, if text { sig::TEXT } else { sig::BINARY },
                                     hash, hashed, unhashed, metadata, &|h| h.update(&signed),
                                     random)?;
                let packet = packet::write(packet::SIGNATURE, &body);
                if args.flag("clearsign") {
                    let header = (key.version < 6).then_some(hash.display);
                    write_file(output, verify::write_cleartext(&data, &packet, header).as_bytes())
                } else if args.flag("armor") {
                    write_file(output, armor::encode("SIGNATURE", &packet).as_bytes())
                } else {
                    write_file(output, &packet)
                }
            } else {
                let mut options = options(&args)?;
                options.filename = std::path::Path::new(input).file_name()
                    .map(|n| n.to_string_lossy().as_bytes().to_vec()).unwrap_or_default();
                options.filename.truncate(255);
                let signed = message::signed_packets(&data, &options, &signer, hash, text, now,
                                                     random)?;
                if args.flag("armor") {
                    write_file(output, armor::encode("MESSAGE", &signed).as_bytes())
                } else {
                    write_file(output, &signed)
                }
            }
        }
        ("gen-key", [secret_out, public_out]) => {
            let v6 = args.flag("v6");
            let plan = keygen::plan(&args.one("algo").unwrap_or("ed25519").to_ascii_lowercase(),
                                    v6)?;
            let user_id = args.one("uid").ok_or("--uid \"Name <address>\" is needed")?;
            let passphrases = args.passphrases()?;
            let passphrase = passphrases.first().cloned().unwrap_or_default();
            // Argon2 for version 6 keys (RFC 9580's recommendation), the
            // iterated S2K GnuPG reads for version 4, unless asked.
            let s2k = if v6 && args.one("s2k").is_none() {
                S2kChoice::Argon2 { passes: 3, parallelism: 4, encoded_memory: 16 }
            } else {
                options(&args)?.s2k
            };
            let s2k = message::new_s2k(s2k, random)?;
            let expires = args.one("expire").map(|d| d.parse::<u32>()
                .map_err(|e| format!("--expire: {e}"))).transpose()?;
            let generated = keygen::generate(&plan, v6, user_id, &passphrase, now, expires, s2k,
                                             random)?;
            if args.flag("binary") {
                write_file(secret_out, &generated.secret)?;
                write_file(public_out, &generated.public)?;
            } else {
                write_file(secret_out,
                           armor::encode("PRIVATE KEY BLOCK", &generated.secret).as_bytes())?;
                write_file(public_out,
                           armor::encode("PUBLIC KEY BLOCK", &generated.public).as_bytes())?;
            }
            println!("{}", keys::hex_upper(&generated.fingerprint));
            Ok(())
        }
        ("verify", [input]) => {
            let certs = read_certs(&args.all("key"))?;
            let raw = read_file(input)?;
            let verdicts = if let Some(signature) = args.one("signature") {
                let packets = packet::parse(&armor::dearmor(&read_file(signature)?)?)?;
                verify::verify_document(&packets, &raw, None, &certs, now)
            } else if raw.windows(34).any(|w| w == b"-----BEGIN PGP SIGNED MESSAGE-----") {
                let text = std::str::from_utf8(&raw).map_err(|_| "a cleartext message that is \
                                                                  not UTF-8")?;
                let (signed, packets) = verify::read_cleartext(text)?;
                verify::verify_document(&packets, &signed, Some(&verify::CLEARTEXT_METADATA),
                                        &certs, now)
            } else {
                let message = message::read(&packet::parse(&armor::dearmor(&raw)?)?,
                                            &Passphrases(args.passphrases()?))?;
                verify::verify_message(&message, &certs, now)
            };
            print_verdicts(&verdicts)
        }
        _ => Err(usage.to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("openpgp: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC9580: &str = include_str!("../../../rfcs/rfc9580.txt");
    const LIBREPGP: &str = include_str!("../../../rfcs/draft-koch-librepgp-04.txt");

    fn unhex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits.chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// The text of one appendix section: from its heading to the next
    /// heading, page furniture removed.
    fn section<'a>(document: &'a str, heading: &str) -> Vec<&'a str> {
        let start = document.find(&format!("\n{heading}  ")).unwrap_or_else(|| {
            panic!("{heading} is not in the document")
        });
        document[start + 1..].lines().skip(1)
            .filter(|l| !l.starts_with("RFC 9580") && !l.starts_with("Wouters, et al.")
                        && !l.starts_with("Koch & Tse") && !l.starts_with("Internet-Draft")
                        && !l.starts_with('\x0c'))
            .take_while(|l| !(l.starts_with(|c: char| c.is_ascii_uppercase()
                                            || c.is_ascii_digit())
                              && l.contains(".  ")))
            .collect()
    }

    /// The hex lines under `label` within a section, up to the next line
    /// that is not hex.
    fn value(lines: &[&str], label: &str) -> Vec<u8> {
        let at = lines.iter().position(|l| l.trim() == label)
            .unwrap_or_else(|| panic!("{label} not found"));
        hex_after(&lines[at + 1..], label)
    }

    /// The same for a label that starts with `start` and may run onto a
    /// second line ending in a colon.
    fn value_from(lines: &[&str], start: &str) -> Vec<u8> {
        let at = lines.iter().position(|l| l.trim().starts_with(start))
            .unwrap_or_else(|| panic!("{start} not found"));
        let end = (at..lines.len()).find(|&i| lines[i].trim_end().ends_with(':')).unwrap();
        hex_after(&lines[end + 1..], start)
    }

    fn hex_after(lines: &[&str], label: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for line in lines {
            let t = line.trim();
            let is_hex = !t.is_empty() && t.split(' ').filter(|w| !w.is_empty())
                .all(|w| w.len() % 2 == 0 && w.bytes().all(|b| b.is_ascii_hexdigit()));
            if !is_hex {
                if out.is_empty() && t.is_empty() {
                    continue;
                }
                break;
            }
            out.extend(unhex(t));
        }
        assert!(!out.is_empty(), "{label} has no value");
        out
    }

    fn certs(lines: &[&str]) -> Vec<keys::Cert> {
        keys::Cert::read_all(&packet::parse(&armored(lines)).unwrap()).unwrap()
    }

    /// RFC 9580 A.1 to A.5 and A.8: the version 4 EdDSA key's
    /// fingerprint; the version 6 certificate and secret key, the second
    /// unlocked and then locked with AEAD and Argon2; and a message to
    /// the certificate's X25519 subkey, decrypted with the secret key,
    /// with the X25519 values the appendix prints.
    #[test]
    fn test_rfc9580_keys_and_x25519_sample() {
        let a1 = section(RFC9580, "A.1.");
        let cert = &certs(&a1)[0];
        let at = a1.iter().position(|l| l.contains("fingerprint of the OpenPGP Key is")).unwrap();
        let printed = a1[at + 1..].iter().find(|l| !l.trim().is_empty()).unwrap();
        assert_eq!(cert.primary.public.fingerprint(), unhex(printed));
        assert_eq!(cert.primary.public.version, 4);

        let public = certs(&section(RFC9580, "A.3."));
        let secret = certs(&section(RFC9580, "A.4."));
        assert_eq!(public.len(), 1);
        assert_eq!(secret[0].primary.public, public[0].primary.public);
        assert_eq!(secret[0].subkeys[0].key.public, public[0].subkeys[0].key.public);
        assert_eq!((secret[0].primary.public.algorithm, secret[0].subkeys[0].key.public.algorithm),
                   (keys::ED25519, keys::X25519));

        // A.8: the PKESK names the subkey by its v6 fingerprint.
        let message = armored(&section(RFC9580, "A.8.5."));
        let packets = packet::parse(&message).unwrap();
        let pkesk = pubkey::Pkesk::parse(&packets[0].body).unwrap();
        let subkey = &secret[0].subkeys[0].key;
        assert_eq!(pkesk.fingerprint, subkey.public.fingerprint());
        assert!(pkesk.is_for(&subkey.public));

        let x = section(RFC9580, "A.8.2.");
        let keys::Secret::Native(private) = subkey.secret.as_ref().unwrap().unlock(b"").unwrap()
            else { panic!("an X25519 secret is native") };
        assert_eq!(private, value_from(&x, "The corresponding long-lived X25519 private key"));
        let ephemeral = value(&x, "Ephemeral key:");
        assert_eq!(allcrypt::api::x25519_exchange(&private, &ephemeral).unwrap(),
                   value(&x, "Shared point:"));
        assert_eq!(allcrypt::api::x25519_public_key(
            &value_from(&x, "This ephemeral key is derived")).unwrap(), ephemeral);

        let unlocker = message::Keys::new(secret.clone(), Vec::new());
        let read = message::read(&packets, &unlocker).unwrap();
        assert_eq!(read.literal.unwrap().data, b"Hello, world!");
        assert!(read.log.iter().any(|l| l.starts_with("PKESK v6: X25519")));
        let session = pkesk.decrypt(&subkey.public, &keys::Secret::Native(private)).unwrap();
        assert_eq!(session.key, value(&x, "Decrypted session key:"));

        // A.5: the same key locked. Its Argon2 takes two gigabytes, so
        // here the S2K output comes from A.5.1 and A.5.2, and
        // `test_rfc9580_locked_key_passphrase` derives it.
        let locked = certs(&section(RFC9580, "A.5."));
        for (key, unlocked, letter) in [(&locked[0].primary, &secret[0].primary, "1"),
                                        (&locked[0].subkeys[0].key, subkey, "2")] {
            let lines = section(RFC9580, &format!("A.5.{letter}."));
            let derived = value_from(&lines, "The S2K-derived");
            let sk = key.secret.as_ref().unwrap();
            let keys::Protection::Aead { cipher, aead, .. } = sk.protection else {
                panic!("A.5 is AEAD-protected")
            };
            let (kek, aad) = sk.aead_parameters(&derived, cipher, aead);
            assert_eq!(kek, value_from(&lines, "After HKDF"));
            assert_eq!(aad, value_from(&lines, "The additional data"));
            let got = format!("{:?}", sk.unlock_derived(&derived).unwrap());
            assert_eq!(got, format!("{:?}", unlocked.secret.as_ref().unwrap().unlock(b"").unwrap()));
            assert!(sk.unlock_derived(&[0u8; 32]).is_err());
        }
    }

    /// A.5's keys from the passphrase: Argon2 at two gigabytes, twice.
    /// Release builds only, about twenty seconds there.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "2 GiB of Argon2 per key; run with --release")]
    fn test_rfc9580_locked_key_passphrase() {
        let locked = certs(&section(RFC9580, "A.5."));
        let lines = section(RFC9580, "A.5.");
        let at = lines.iter().position(|l| l.contains("The passphrase is")).unwrap();
        let passphrase = lines[at + 1..].iter().find(|l| !l.trim().is_empty()).unwrap().trim();
        assert_eq!(passphrase, "correct horse battery staple");
        for key in locked[0].keys() {
            key.secret.as_ref().unwrap().unlock(passphrase.as_bytes()).unwrap();
        }
    }

    /// An armored message in a section.
    fn armored(lines: &[&str]) -> Vec<u8> {
        let text = lines.join("\n");
        let blocks = armor::decode_all(&text).unwrap();
        assert_eq!(blocks.len(), 1);
        blocks.into_iter().next().unwrap().data
    }

    fn password() -> Passphrases {
        Passphrases(vec![b"password".to_vec()])
    }

    /// A v6 PKESK's key identifier is a version octet and a
    /// fingerprint, 21 or 33 bytes, or nothing for an anonymous
    /// recipient. The parser took any length above one and then cut
    /// the key ID out of the fingerprint's first or last 8 bytes, so a
    /// length of 2 to 8 underflowed the slice and panicked - on every
    /// PKESK of a message, before any key is tried. The RFC's sample and
    /// every recorded message carry a 33, so no test had another
    /// length.
    #[test]
    fn test_a_v6_pkesk_identifier_of_the_wrong_length_is_refused() {
        let message = armored(&section(RFC9580, "A.8.5."));
        let packets = packet::parse(&message).unwrap();
        let body = packets[0].body.clone();
        assert_eq!((body[0], body[1], body[2]), (6, 33, 6));
        assert!(pubkey::Pkesk::parse(&body).is_ok());
        for n in [1, 2, 5, 8, 20, 22, 32, 34] {
            let mut short = body.clone();
            short[1] = n;
            let error = pubkey::Pkesk::parse(&short).err().unwrap_or_else(|| panic!("{n}"));
            assert!(error.contains("key identifier"), "{n}: {error}");
        }
        // 21 bytes belong to a v4 key, 33 to v5 and v6, not the other
        // way round.
        let mut mismatched = body.clone();
        mismatched[1] = 21;
        assert!(pubkey::Pkesk::parse(&mismatched).is_err());
        mismatched[2] = 4;
        assert!(pubkey::Pkesk::parse(&mismatched).is_ok());
        let mut anonymous = body.clone();
        anonymous[1] = 0;
        let pkesk = pubkey::Pkesk::parse(&anonymous).unwrap();
        assert!(pkesk.fingerprint.is_empty() && pkesk.key_id == [0; 8]);
    }

    /// RFC 9580 A.9 to A.11: SKESK v6 and SEIPD v2 under EAX, OCB and
    /// GCM, with every intermediate value the appendix prints. The S2K
    /// hashes 65 MB of SHA-256, a few seconds unoptimised.
    #[test]
    fn test_rfc9580_aead_samples() {
        for (letter, aead) in [("9", 1u8), ("10", 2), ("11", 3)] {
            let skesk_lines = section(RFC9580, &format!("A.{letter}.1."));
            let skesk = unhex(&skesk_lines.iter()
                .take_while(|l| !l.contains("broken out"))
                .filter_map(|l| l.trim().strip_prefix("0x").map(|r| &r[4..]))
                .collect::<Vec<_>>().join(" "));
            let packets = packet::parse(&skesk).unwrap();
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].body[3], aead);

            // The session key, from the derived key the appendix prints;
            // deriving it is 65 MB of SHA-256, a release build's job
            // (`test_rfc9580_s2k_samples`).
            let keys = section(RFC9580, &format!("A.{letter}.2."));
            let skesk = message::Skesk::parse(&packets[0].body).unwrap();
            let derived = value(&keys, "The derived key is:");
            let session = skesk.unlock(&derived).unwrap();
            assert_eq!(session.key, value(&keys, "Decrypted session key:"), "A.{letter}");
            assert_eq!(algo::hkdf_sha256(&[], &derived, &value(&keys, "HKDF info:"), 16),
                       value(&keys, "HKDF output:"));
            assert!(skesk.unlock(&[0u8; 16]).is_err());

            // The message key and IV.
            let data = section(RFC9580, &format!("A.{letter}.4."));
            let info = value(&data, "HKDF info:");
            let message_key = value(&data, "Message key:");
            let iv = value(&data, "Initialization vector:");
            let mut expected = message_key.clone();
            expected.extend_from_slice(&iv);
            assert_eq!(value(&data, "HKDF output:"), expected);
            assert_eq!(info[0], 0xD2);

            // And the whole message, from its armor, under that key.
            let message_bytes = armored(&section(RFC9580, &format!("A.{letter}.5.")));
            let unlocker = message::SessionKeys(vec![session]);
            let message = message::read(&packet::parse(&message_bytes).unwrap(), &unlocker)
                .unwrap();
            assert_eq!(message.literal.unwrap().data, b"Hello, world!");
            assert!(message.log.iter().any(|l| l.contains(["EAX", "OCB", "GCM"]
                                                           [aead as usize - 1])));
        }
    }

    /// The same three messages from the passphrase: the S2K's 65 MB of
    /// SHA-256 each, and a wrong passphrase refused. About 15 seconds
    /// unoptimised, so release builds only; well under one there.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "65 MB of SHA-256 per case; run with --release")]
    fn test_rfc9580_s2k_samples() {
        for letter in ["9", "10", "11"] {
            let keys = section(RFC9580, &format!("A.{letter}.2."));
            let message_bytes = armored(&section(RFC9580, &format!("A.{letter}.5.")));
            let packets = packet::parse(&message_bytes).unwrap();
            let skesk = message::Skesk::parse(&packets[0].body).unwrap();
            assert_eq!(skesk.s2k.derive(b"password", 16).unwrap(),
                       value(&keys, "The derived key is:"));
            let message = message::read(&packets, &password()).unwrap();
            assert_eq!(message.literal.unwrap().data, b"Hello, world!");
            let wrong = Passphrases(vec![b"passw0rd".to_vec()]);
            assert!(message::read(&packets, &wrong).is_err());
        }
    }

    /// RFC 9580 A.12: SKESK v4 with Argon2 (t = 1, p = 4, m = 2 GiB) and
    /// SEIPD v1, at three key sizes, each with the session key its
    /// armor's comment states. Two gigabytes of memory each: release
    /// builds only, about two seconds each there.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "2 GiB of Argon2 per case; run with --release")]
    fn test_rfc9580_argon2_samples() {
        for (letter, key_len) in [("1", 16), ("2", 24), ("3", 32)] {
            let lines = section(RFC9580, &format!("A.12.{letter}."));
            let blocks = armor::decode_all(&lines.join("\n")).unwrap();
            let stated: String = blocks[0].headers.iter()
                .filter(|(k, v)| k == "Comment" && v.starts_with("Session key: "))
                .map(|(_, v)| v["Session key: ".len()..].trim_matches('.').to_string())
                .collect();
            let packets = packet::parse(&blocks[0].data).unwrap();
            let mut log = Vec::new();
            let session = message::skesk_session_key(&packets[0].body, b"password", &mut log)
                .unwrap();
            assert_eq!(session.key.len(), key_len);
            assert_eq!(session.key, unhex(&stated), "A.12.{letter}");
            let message = message::read(&packets, &password()).unwrap();
            assert_eq!(message.literal.unwrap().data, b"Hello, world!");
        }
    }

    /// LibrePGP A.3: SKESK v5 and the OCB Encrypted Data packet, as
    /// GnuPG writes them, with the derived key and the session key.
    #[test]
    fn test_librepgp_ocb_sample() {
        let lines = section(LIBREPGP, "A.3.6.");
        let sequence = unhex(&lines.iter().filter(|l| !l.contains(':')).cloned()
            .collect::<Vec<_>>().join(" "));
        let packets = packet::parse(&sequence).unwrap();
        assert_eq!(packets.iter().map(|p| p.tag).collect::<Vec<_>>(), [3, 20]);
        let keys = section(LIBREPGP, "A.3.3.");
        let mut log = Vec::new();
        let session = message::skesk_session_key(&packets[0].body, b"password", &mut log)
            .unwrap();
        assert_eq!(session.key, value(&keys, "Decrypted CEK:"));
        let s2k = s2k::S2k::read(&mut packet::Reader::new(&packets[0].body[3..])).unwrap();
        assert_eq!(s2k.derive(b"password", 16).unwrap(), value(&keys, "The derived key is:"));
        let message = message::read(&packets, &password()).unwrap();
        assert_eq!(message.literal.unwrap().data, b"Hello, world!\n");
    }

    /// `plaintext(size, seed)` of scripts/check_openpgp.py.
    fn plaintext(size: usize, seed: usize) -> Vec<u8> {
        (0..size).map(|i| ((i * 31 + i / 251 + seed) & 0xff) as u8).collect()
    }

    /// Messages GnuPG 2.4 wrote: every container it writes, IDEA, CAST5,
    /// Twofish and Camellia, bzip2 and zlib, simple and RIPEMD-160 S2K,
    /// partial body lengths (written from a pipe), many small OCB
    /// chunks and armor. Each opens with its passphrase and with the
    /// session key GnuPG printed, and not with another passphrase.
    #[test]
    fn test_messages_gnupg_wrote() {
        let records = fixtures::records("openpgp.vec", "gnupg");
        assert_eq!(records.len(), 15);
        let mut containers = std::collections::HashSet::new();
        for record in &records {
            let name = fixtures::field(record, "name");
            let data = armor::dearmor(&std::fs::read(
                fixtures::dir().join(fixtures::field(record, "file"))).unwrap()).unwrap();
            let length: usize = fixtures::field(record, "data_length").parse().unwrap();
            let seed: usize = fixtures::field(record, "data_seed").parse().unwrap();
            let expected = plaintext(length, seed);
            assert_eq!(fixtures::hex(&algo::digest(algo::hash(8).unwrap(), &[&expected])),
                       fixtures::field(record, "data_sha256"));
            let packets = packet::parse(&data).unwrap();
            containers.extend(packets.iter().filter(|p| [9, 18, 20].contains(&p.tag))
                .map(|p| (p.tag, p.partial)));
            let unlocker = Passphrases(vec![fixtures::field(record, "passphrase")
                .as_bytes().to_vec()]);
            let message = message::read(&packets, &unlocker)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(message.literal.unwrap().data, expected, "{name}");
            let key = message::parse_session_key(fixtures::field(record, "session_key"))
                .unwrap();
            let message = message::read(&packets, &message::SessionKeys(vec![key])).unwrap();
            assert_eq!(message.literal.unwrap().data, expected, "{name}");
            assert!(message::read(&packets, &Passphrases(vec![b"wrong".to_vec()])).is_err());
        }
        // SED, SEIPD and OCB packets, and partial lengths among them.
        assert!(containers.iter().any(|c| c.0 == 9));
        assert!(containers.iter().any(|c| c.0 == 18 && c.1));
        assert!(containers.iter().any(|c| c.0 == 20 && c.1));
    }

    /// Keys GnuPG 2.4 made - RSA, DSA with ElGamal, ECDSA and ECDH on
    /// the NIST, Brainpool and secp256k1 curves, Ed25519 with Curve25519,
    /// and version 5 Ed448 with X448 - each exported under a passphrase,
    /// with a message GnuPG encrypted to it. Our fingerprints are GnuPG's,
    /// the passphrase unlocks the key, the key opens the message, and a
    /// wrong passphrase does not.
    #[test]
    fn test_keys_gnupg_made() {
        let records = fixtures::records("openpgp-keys.vec", "gnupg-keys");
        assert_eq!(records.len(), 14);
        let mut algorithms = std::collections::HashSet::new();
        for record in &records {
            let name = fixtures::field(record, "name");
            let path = fixtures::dir().join(fixtures::field(record, "key"));
            let certs = read_certs(&[path.to_str().unwrap()]).unwrap();
            let fingerprints: Vec<String> = certs[0].keys()
                .map(|k| keys::hex_upper(&k.public.fingerprint())).collect();
            assert_eq!(fingerprints.join(" "), fixtures::field(record, "fingerprints"), "{name}");
            for key in certs[0].keys() {
                algorithms.insert((key.public.version, key.public.algorithm,
                                   key.public.curve().map(|c| c.name)));
            }
            let passphrase = fixtures::field(record, "passphrase").as_bytes().to_vec();
            let message = std::fs::read(fixtures::dir().join(fixtures::field(record, "message")))
                .unwrap();
            let packets = packet::parse(&message).unwrap();
            let expected = plaintext(fixtures::field(record, "data_length").parse().unwrap(),
                                     fixtures::field(record, "data_seed").parse().unwrap());
            let unlocker = message::Keys::new(certs.clone(), vec![passphrase]);
            let read = message::read(&packets, &unlocker).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(read.literal.unwrap().data, expected, "{name}");
            let wrong = message::Keys::new(certs, vec![b"wrong".to_vec()]);
            assert!(message::read(&packets, &wrong).is_err(), "{name}");
        }
        // Every family GnuPG makes, the version 5 keys among them.
        for (version, algorithm) in [(4, keys::RSA), (4, keys::DSA), (4, keys::ELGAMAL),
                                     (4, keys::ECDSA), (4, keys::ECDH), (4, keys::EDDSA_LEGACY),
                                     (5, keys::EDDSA_LEGACY), (5, keys::ECDH)] {
            assert!(algorithms.iter().any(|a| (a.0, a.1) == (version, algorithm)),
                    "no v{version} algorithm {algorithm} key");
        }
        assert_eq!(algorithms.iter().filter(|a| a.2.is_some_and(|c| c.starts_with("brainpool")))
                   .count(), 6);
    }

    /// Our encryption to each of those keys opens again with it - the
    /// encrypting half, which GnuPG checks live in check_openpgp.py.
    #[test]
    fn test_encrypting_to_gnupg_keys() {
        for record in fixtures::records("openpgp-keys.vec", "gnupg-keys") {
            let name = fixtures::field(&record, "name");
            let path = fixtures::dir().join(fixtures::field(&record, "key"));
            let certs = read_certs(&[path.to_str().unwrap()]).unwrap();
            let recipient = verify::encryption_key(&certs[0], NOW).unwrap();
            for format in [Format::V4, Format::LibrePgp, Format::Rfc9580] {
                let mut options = Options::new(algo::cipher(9).unwrap());
                options.format = format;
                if format == Format::Rfc9580 && recipient.algorithm == keys::ELGAMAL {
                    continue;
                }
                let inner = message::literal_packets(b"to a key", &options);
                let encrypted = message::encrypt(&inner, &[Recipient::Key(recipient.clone())],
                                                 &options, &mut seeded())
                    .unwrap_or_else(|e| panic!("{name} {format:?}: {e}"));
                let unlocker = message::Keys::new(
                    certs.clone(), vec![fixtures::field(&record, "passphrase").into()]);
                let read = message::read(&packet::parse(&encrypted).unwrap(), &unlocker)
                    .unwrap_or_else(|e| panic!("{name} {format:?}: {e}"));
                assert_eq!(read.literal.unwrap().data, b"to a key");
            }
        }
    }

    /// The curve OIDs, against RFC 9580's table 19 and LibrePGP's table
    /// 7: each name's dotted OID and the octets the table prints.
    #[test]
    fn test_curve_oids_are_the_documents() {
        let mut checked = 0;
        for (document, table_end) in [(RFC9580, "Table 19:"), (LIBREPGP, "Table 7\n")] {
            let end = document.find(table_end).unwrap();
            let start = document[..end].rfind("+====").unwrap();
            // Rows run between `+---` rules; a row's cells continue over
            // several lines.
            for row in document[start..end].split("+-") {
                let mut cells: Vec<String> = Vec::new();
                for line in row.lines().filter(|l| l.trim_start().starts_with('|')) {
                    for (i, cell) in line.trim().trim_matches('|').split('|').enumerate() {
                        if cells.len() <= i {
                            cells.push(String::new());
                        }
                        cells[i].push_str(cell.trim());
                    }
                }
                if cells.len() < 4 || !cells[0].starts_with("1.") {
                    continue;
                }
                let (dotted, octets) = (&cells[0], unhex(&cells[2].replace(' ', "")));
                let name = cells[3].trim_end_matches("(1)");
                let curve = keys::CURVES.iter().find(|c| c.dotted == dotted.as_str())
                    .unwrap_or_else(|| panic!("{dotted} ({name}) is not in our table"));
                assert_eq!(keys::oid_bytes(curve.dotted), octets, "{name}");
                checked += 1;
            }
        }
        assert_eq!(checked, 8 + 12);
    }

    /// Brainpool's parameters come out of RFC 5639 and make curves the
    /// library accepts: G on the curve, n prime, n * G the identity.
    #[test]
    fn test_brainpool_from_rfc5639() {
        for name in ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"] {
            let parameters = keys::brainpool_parameters(name).unwrap();
            let bits = parameters.p.bit_len();
            assert_eq!(bits, name[10..13].parse::<usize>().unwrap());
            let curve = allcrypt::ec::curves::from_parameters(parameters).unwrap();
            assert!(curve.is_on_curve(&curve.g));
        }
        keys::register_brainpool().unwrap();
        assert!(allcrypt::api::EcKey::generate("brainpoolP384r1").is_ok());
    }

    /// A time after every fixture was made.
    const NOW: u32 = 1_800_000_000;

    /// RFC 9580 A.2, A.3.1, A.6 and A.7: a version 4 EdDSA signature with
    /// the hash input and digest the appendix prints; the version 6
    /// certificate's self-signatures, one of them against the hashed data
    /// stream A.3.1 prints; and the same version 6 text signature as a
    /// cleartext signed message and inline. Each refuses altered text.
    #[test]
    fn test_rfc9580_signatures() {
        let a2 = section(RFC9580, "A.2.");
        let field = |name: &str| unhex(a2.iter().find_map(|l| l.trim().strip_prefix(name))
                                        .unwrap());
        let key = certs(&section(RFC9580, "A.1."))[0].primary.public.clone();
        let packets = packet::parse(&armored(&a2)).unwrap();
        let s = sig::Signature::parse(&packets[0].body).unwrap();
        let mut h = s.hasher();
        h.update(b"OpenPGP");
        let digest = s.finish(h, None);
        assert_eq!(digest, field("d:"));
        // m is the data and the trailer.
        assert_eq!(&field("m:")[..7], b"OpenPGP");
        assert_eq!(algo::digest(s.hash, &[&field("m:")]), digest);
        s.verify_digest(&key, &digest).unwrap();
        let mut rs = field("r:");
        rs.extend(field("s:"));
        assert_eq!(s.fields.len(), 2 + 32 + 2 + 32);
        let mut h = s.hasher();
        h.update(b"OpenPGp");
        assert!(s.verify_digest(&key, &s.finish(h, None)).is_err());

        // The critical bit was read and never consulted, so a signature
        // whose signer said "do not accept this unless you understand
        // subpacket X" verified as good when X was not understood - a
        // signature target, say. No fixture carries a critical
        // subpacket of a type this program ignores, so the bit was never
        // exercised. The trailer is fixed at parse time, so a subpacket
        // added to the struct changes nothing else about the check.
        let mut marked = s.clone();
        marked.hashed.push(sig::Subpacket { kind: 31, critical: false, data: vec![1, 8, 0] });
        marked.verify_digest(&key, &digest).unwrap();
        marked.hashed.last_mut().unwrap().critical = true;
        let error = marked.verify_digest(&key, &digest).unwrap_err();
        assert!(error.contains("critical subpacket of type 31"), "{error}");
        // A critical subpacket of a kind this program does act on is fine.
        let mut known = s.clone();
        known.hashed.iter_mut().for_each(|p| p.critical = true);
        known.verify_digest(&key, &digest).unwrap();
        // The values were read from the front of the fields and the rest
        // never looked at, so a signature packet with bytes after its
        // last MPI verified; no fixture has any.
        let mut trailing = s.clone();
        trailing.fields.push(0);
        let error = trailing.verify_digest(&key, &digest).unwrap_err();
        assert!(error.contains("follow the signature"), "{error}");

        // A.3: every self-signature verifies, so the subkey is usable
        // and is where mail goes.
        let cert = &certs(&section(RFC9580, "A.3."))[0];
        let checked = verify::check(cert, NOW);
        assert!(checked.primary.usable, "{:?}", checked.primary.problems);
        assert!(checked.subkeys[0].usable, "{:?}", checked.subkeys[0].problems);
        assert_eq!(verify::encryption_key(cert, NOW).unwrap(), cert.subkeys[0].key.public);
        // A.3.1 prints the data each self-signature is made over, each
        // as a plain dump and then broken out; the plain dumps hash to
        // the signatures' digests.
        let stream_lines = section(RFC9580, "A.3.1.");
        let streams: Vec<Vec<u8>> = stream_lines.split(|l| l.contains("broken out"))
            .take(2).map(|chunk| {
                let start = chunk.iter().rposition(|l| l.contains("sequence of data")).unwrap();
                unhex(&chunk[start..].iter()
                    .filter_map(|l| l.trim().strip_prefix("0x").map(|r| &r[4..]))
                    .collect::<Vec<_>>().join(" "))
            }).collect();
        assert_eq!(streams.len(), 2);
        let direct = sig::Signature::parse(&cert.direct[0].body).unwrap();
        let mut h = direct.hasher();
        sig::hash_key(&mut h, &cert.primary.public);
        assert_eq!(direct.finish(h, None), algo::digest(direct.hash, &[&streams[0]]));
        let binding = sig::Signature::parse(&cert.subkeys[0].signatures[0].body).unwrap();
        let mut h = binding.hasher();
        sig::hash_key(&mut h, &cert.primary.public);
        sig::hash_key(&mut h, &cert.subkeys[0].key.public);
        assert_eq!(binding.finish(h, None), algo::digest(binding.hash, &[&streams[1]]));
        // A certificate with its binding signature removed has no subkey
        // to encrypt to, and none to verify with.
        let mut unbound = cert.clone();
        unbound.subkeys[0].signatures.clear();
        assert!(verify::encryption_key(&unbound, NOW).is_err());

        // A.6 and A.7.
        // The document indents everything by three spaces.
        let a6 = section(RFC9580, "A.6.").iter().map(|l| l.strip_prefix("   ").unwrap_or(l))
            .collect::<Vec<_>>().join("\n");
        let (signed, packets) = verify::read_cleartext(&a6).unwrap();
        assert!(signed.starts_with(b"What we need from the grocery store:\r\n\r\n- tofu\r\n"));
        let verdicts = verify::verify_document(&packets, &signed, None, std::slice::from_ref(cert), NOW);
        assert!(verdicts.len() == 1 && verdicts[0].good, "{verdicts:?}");
        let altered = a6.replace("tofu", "tafu");
        let (signed, packets) = verify::read_cleartext(&altered).unwrap();
        assert!(!verify::verify_document(&packets, &signed, None, std::slice::from_ref(cert), NOW)[0].good);
        let inline = armored(&section(RFC9580, "A.7."));
        let m = message::read(&packet::parse(&inline).unwrap(), &Passphrases(Vec::new())).unwrap();
        let verdicts = verify::verify_message(&m, std::slice::from_ref(cert), NOW);
        assert!(verdicts.len() == 1 && verdicts[0].good, "{verdicts:?}");
        assert!(verdicts[0].text.starts_with("good v6 text document signature"));
    }

    /// GnuPG's signatures with each of its keys: inline and detached over
    /// the data, text-mode and cleartext over a text with trailing spaces
    /// and dashes. Each verifies; each altered does not.
    #[test]
    fn test_signatures_gnupg_made() {
        for record in fixtures::records("openpgp-keys.vec", "gnupg-keys") {
            let name = fixtures::field(&record, "name");
            let key = fixtures::dir().join(fixtures::field(&record, "key"));
            let certs = read_certs(&[key.to_str().unwrap()]).unwrap();
            let data = plaintext(fixtures::field(&record, "data_length").parse().unwrap(),
                                 fixtures::field(&record, "data_seed").parse().unwrap());
            let text = unhex(fixtures::field(&record, "text"));
            let read = |mode: &str| std::fs::read(fixtures::dir().join(
                fixtures::field(&record, mode))).unwrap();
            for mode in ["inline", "text-mode"] {
                let packets = packet::parse(&armor::dearmor(&read(mode)).unwrap()).unwrap();
                let m = message::read(&packets, &Passphrases(Vec::new())).unwrap();
                let verdicts = verify::verify_message(&m, &certs, NOW);
                assert!(verdicts.len() == 1 && verdicts[0].good, "{name} {mode}: {verdicts:?}");
                let expected = if mode == "inline" { data.clone() }
                               else { sig::canonical_text(&text) };
                assert_eq!(m.literal.unwrap().data, expected, "{name} {mode}");
            }
            let detached = packet::parse(&armor::dearmor(&read("detached")).unwrap()).unwrap();
            assert!(verify::verify_document(&detached, &data, None, &certs, NOW)[0].good, "{name}");
            let mut altered = data.clone();
            altered[100] ^= 1;
            assert!(!verify::verify_document(&detached, &altered, None, &certs, NOW)[0].good);
            let clear = String::from_utf8(read("cleartext")).unwrap();
            let (signed, packets) = verify::read_cleartext(&clear).unwrap();
            assert_eq!(signed, verify::cleartext_signed_form(&text), "{name}");
            let verdicts = verify::verify_document(&packets, &signed,
                                                   Some(&verify::CLEARTEXT_METADATA), &certs, NOW);
            assert!(verdicts[0].good, "{name} cleartext: {verdicts:?}");
        }
    }

    /// Signing and verifying our own way round, for every kind of key
    /// GnuPG made: inline, detached, text and cleartext, and an altered
    /// document refused each time. GnuPG and go-crypto judge the bytes in
    /// check_openpgp.py.
    #[test]
    fn test_signing_with_gnupg_keys() {
        let text = b"line one  \nline two\n-dash line\n";
        for record in fixtures::records("openpgp-keys.vec", "gnupg-keys") {
            let name = fixtures::field(&record, "name");
            let path = fixtures::dir().join(fixtures::field(&record, "key"));
            let certs = read_certs(&[path.to_str().unwrap()]).unwrap();
            let passphrase = fixtures::field(&record, "passphrase").as_bytes().to_vec();
            let Ok((key, secret)) = unlock_signer(&certs, &[passphrase], NOW) else {
                panic!("{name}: no signing key")
            };
            let hash = algo::hash(if key.version == 5 { 10 } else { 8 }).unwrap();
            let signer = message::Signer { key: &key, secret };
            let options = Options::new(algo::cipher(9).unwrap());
            let signed = message::signed_packets(text, &options, &signer, hash, false, NOW,
                                                 &mut seeded()).unwrap();
            let m = message::read(&packet::parse(&signed).unwrap(), &Passphrases(Vec::new()))
                .unwrap();
            let verdicts = verify::verify_message(&m, &certs, NOW);
            assert!(verdicts[0].good, "{name}: {verdicts:?}");
            let (hashed, unhashed) = sig::standard_subpackets(&key, NOW);
            let cleartext = verify::cleartext_signed_form(text);
            let body = sig::make(&key, &signer.secret, sig::TEXT, hash, hashed, unhashed,
                                 Some(&verify::CLEARTEXT_METADATA), &|h| h.update(&cleartext),
                                 &mut seeded()).unwrap();
            let written = verify::write_cleartext(text, &packet::write(packet::SIGNATURE, &body),
                                                  Some(hash.display));
            assert!(written.contains("\n- -dash line\n"), "dash-escaping");
            let (back, packets) = verify::read_cleartext(&written).unwrap();
            assert_eq!(back, cleartext);
            let verdicts = verify::verify_document(&packets, &back,
                                                   Some(&verify::CLEARTEXT_METADATA), &certs, NOW);
            assert!(verdicts[0].good, "{name} cleartext: {verdicts:?}");
            let (back, packets) = verify::read_cleartext(&written.replace("two", "tw0")).unwrap();
            assert!(!verify::verify_document(&packets, &back, Some(&verify::CLEARTEXT_METADATA),
                                             &certs, NOW)[0].good);
        }
    }

    fn seeded() -> impl FnMut(&mut [u8]) -> Result<(), String> {
        counter_stream(7)
    }

    /// Every format, cipher and compression our own way round, with a
    /// cheap S2K; the vectors above and GnuPG are what say the bytes are
    /// right.
    #[test]
    fn test_round_trips() {
        // Several AEAD chunks of 1 KiB and a short last one.
        let data: Vec<u8> = (0..2_500u32).map(|i| (i * 31 + i / 251) as u8).collect();
        for format in [Format::V4, Format::NoMdc, Format::LibrePgp, Format::Rfc9580] {
            for cipher in algo::CIPHERS {
                if matches!(format, Format::LibrePgp | Format::Rfc9580) && cipher.block_len != 16 {
                    continue;
                }
                for aead in algo::AEADS {
                    if !matches!(format, Format::LibrePgp | Format::Rfc9580) && aead.id != 2
                        || format == Format::LibrePgp && aead.id == 3 {
                        continue;
                    }
                    for compression in [0u8, 1, 2] {
                        let mut options = Options::new(*cipher);
                        options.format = format;
                        options.aead = *aead;
                        options.compression = compression;
                        options.chunk_byte = 4;
                        options.s2k = S2kChoice::Iterated { hash: algo::hash(2).unwrap(),
                                                            octets: 1024 };
                        let inner = message::literal_packets(&data, &options);
                        let mut random = seeded();
                        let encrypted = message::encrypt(
                            &inner, &[Recipient::Passphrase(b"pw".to_vec()),
                                      Recipient::Passphrase(b"other".to_vec())],
                            &options, &mut random).unwrap();
                        let label = format!("{format:?} {} {} {compression}", cipher.display,
                                            aead.display);
                        for pw in [&b"pw"[..], b"other"] {
                            let unlocker = Passphrases(vec![pw.to_vec()]);
                            let m = message::read(&packet::parse(&encrypted).unwrap(),
                                                  &unlocker).unwrap_or_else(|e| {
                                panic!("{label}: {e}")
                            });
                            assert_eq!(m.literal.unwrap().data, data, "{label}");
                            assert_eq!(m.unprotected, format == Format::NoMdc);
                        }
                        // Altering a byte of the container is noticed,
                        // except without integrity protection.
                        if format != Format::NoMdc {
                            let mut altered = encrypted.clone();
                            let n = altered.len();
                            altered[n - 40] ^= 1;
                            let unlocker = Passphrases(vec![b"pw".to_vec()]);
                            assert!(message::read(&packet::parse(&altered).unwrap(), &unlocker)
                                .is_err(), "{label}");
                        }
                    }
                }
            }
        }
    }

    /// A single passphrase in v4 makes the S2K output the session key,
    /// with no encrypted session key in the SKESK - what `gpg -c` does.
    #[test]
    fn test_a_single_passphrase_is_the_session_key() {
        let mut options = Options::new(algo::cipher(9).unwrap());
        options.s2k = S2kChoice::Iterated { hash: algo::hash(8).unwrap(), octets: 1024 };
        let inner = message::literal_packets(b"x", &options);
        let one = message::encrypt(&inner, &[Recipient::Passphrase(b"pw".to_vec())],
                                   &options, &mut seeded()).unwrap();
        let packets = packet::parse(&one).unwrap();
        assert_eq!(packets[0].body.len(), 2 + 11);
        options.esk = true;
        let with_esk = message::encrypt(&inner, &[Recipient::Passphrase(b"pw".to_vec())],
                                        &options, &mut seeded()).unwrap();
        assert_eq!(packet::parse(&with_esk).unwrap()[0].body.len(), 2 + 11 + 33);
    }

    #[test]
    fn test_packet_lengths() {
        // Each length encoding at its boundaries, and partial lengths.
        for n in [0usize, 1, 191, 192, 8383, 8384, 70_000] {
            let body: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let p = packet::parse(&packet::write(packet::LITERAL, &body)).unwrap();
            assert_eq!(p[0].body, body);
            let p = packet::parse(&packet::write_legacy(packet::LITERAL, &body)).unwrap();
            assert_eq!((p[0].body.clone(), p[0].legacy), (body.clone(), true));
            if n >= 512 {
                let p = packet::parse(&packet::write_partial(packet::LITERAL, &body, 512))
                    .unwrap();
                assert_eq!((p[0].body.clone(), p[0].partial), (body, true));
            }
        }
        // Lengths for the two byte form, as RFC 9580 4.2.3 gives them.
        let mut out = Vec::new();
        packet::encode_length(1723, &mut out);
        assert_eq!(out, [0xC5, 0xFB]);
        out.clear();
        packet::encode_length(100_000, &mut out);
        assert_eq!(out, [0xFF, 0x00, 0x01, 0x86, 0xA0]);
        assert!(packet::parse(&[0xCB, 0xE0, 0]).is_err(), "a first partial length under 512");
        assert!(packet::parse(&[0xCB, 5, 1, 2]).is_err(), "a body past the end");
    }

    /// A generated key, read back: both parts usable with the flags
    /// they were given, a message to it opens with it, a signature by it
    /// verifies, and its passphrase is needed.
    fn exercise_generated(name: &str, v6: bool) {
        let plan = keygen::plan(name, v6).unwrap();
        let s2k = s2k::S2k::Iterated { hash: algo::hash(8).unwrap(), salt: [7; 8],
                                       coded_count: 0 };
        let label = format!("{name} v{}", if v6 { 6 } else { 4 });
        let generated = keygen::generate(&plan, v6, "Test <test@example.org>", b"key pass",
                                         NOW - 100, Some(365), s2k, &mut seeded())
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        let secret = keys::Cert::read_all(&packet::parse(&generated.secret).unwrap()).unwrap();
        let public = keys::Cert::read_all(&packet::parse(&generated.public).unwrap()).unwrap();
        assert_eq!(public[0].primary.public.fingerprint(), generated.fingerprint);
        assert_eq!(public[0].primary.public.version, if v6 { 6 } else { 4 });
        let checked = verify::check(&public[0], NOW);
        assert!(checked.primary.usable && checked.subkeys[0].usable, "{label}: {:?} {:?}",
                checked.primary.problems, checked.subkeys[0].problems);
        assert_eq!((checked.primary.flags, checked.subkeys[0].flags),
                   (Some(0x03), Some(sig::FLAG_ENCRYPT)), "{label}");
        // Expired a year on.
        assert!(verify::encryption_key(&public[0], NOW + 366 * 86400).is_err(), "{label}");

        let recipient = verify::encryption_key(&public[0], NOW).unwrap();
        let mut options = Options::new(algo::cipher(9).unwrap());
        options.format = if v6 { Format::Rfc9580 } else { Format::V4 };
        let (key, unlocked) = unlock_signer(&secret, &[b"key pass".to_vec()], NOW).unwrap();
        assert!(unlock_signer(&secret, &[b"wrong".to_vec()], NOW).is_err());
        let signer = message::Signer { key: &key, secret: unlocked };
        let inner = message::signed_packets(b"hello", &options, &signer,
                                            algo::hash(10).unwrap(), false, NOW,
                                            &mut seeded()).unwrap();
        let encrypted = message::encrypt(&inner, &[Recipient::Key(recipient)], &options,
                                         &mut seeded()).unwrap();
        let unlocker = message::Keys::new(secret.clone(), vec![b"key pass".to_vec()]);
        let m = message::read(&packet::parse(&encrypted).unwrap(), &unlocker)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(m.literal.as_ref().unwrap().data, b"hello");
        let verdicts = verify::verify_message(&m, &public, NOW);
        assert!(verdicts.len() == 1 && verdicts[0].good, "{label}: {verdicts:?}");
    }

    /// Keys made here, for every algorithm quick to make unoptimised.
    #[test]
    fn test_generated_keys() {
        for (name, v6) in [("nistp256", false), ("nistp521", true), ("brainpoolp256r1", false),
                           ("secp256k1", false), ("ed25519-legacy", false), ("ed25519", false),
                           ("ed25519", true), ("ed448", true)] {
            exercise_generated(name, v6);
        }
        assert!(keygen::plan("ed25519-legacy", true).is_err(), "legacy OIDs in a v6 key");
        assert!(keygen::plan("dsa2048", true).is_err(), "DSA in a v6 key");
    }

    /// RSA and DSA, whose prime searches are a release build's job: a
    /// few seconds there, minutes unoptimised.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "RSA and DSA key generation; run with --release")]
    fn test_generated_rsa_and_dsa_keys() {
        for (name, v6) in [("rsa2048", false), ("rsa3072", true), ("dsa2048", false)] {
            exercise_generated(name, v6);
        }
    }

    /// GnuPG writes Ed448 and X448 values at their full length, a
    /// leading zero byte included; an MPI would drop it.
    #[test]
    fn test_sos_keeps_a_leading_zero() {
        let mut out = Vec::new();
        keys::write_sos(&[0, 1, 2], &mut out);
        assert_eq!(out, [0, 24, 0, 1, 2]);
        out.clear();
        keys::write_sos(&[3, 1, 2], &mut out);
        assert_eq!(out, [0, 18, 3, 1, 2]);
        out.clear();
        keys::write_mpi(&[0, 1, 2], &mut out);
        assert_eq!(out, [0, 9, 1, 2]);
    }

    #[test]
    fn test_armor() {
        let data: Vec<u8> = (0..200u8).collect();
        let text = armor::encode("MESSAGE", &data);
        assert_eq!(armor::dearmor(text.as_bytes()).unwrap(), data);
        let damaged = text.replacen("AAEC", "AAED", 1);
        assert!(armor::dearmor(damaged.as_bytes()).is_err(), "the CRC-24 must be checked");
        // RFC 9580 6.1's CRC of nothing is its initial value.
        assert_eq!(armor::crc24(b""), 0xB704CE);
    }

    #[test]
    fn test_s2k_counts() {
        // RFC 9580 3.7.1.3's coded count, at its two ends and A.9's 0xff.
        assert_eq!(s2k::decode_count(0), 1024);
        assert_eq!(s2k::decode_count(0xff), 65011712);
        assert_eq!(s2k::encode_count(65011712), 0xff);
        assert_eq!(s2k::decode_count(s2k::encode_count(1_000_000)), 1_015_808);
    }

    /// The deflate writer's stored blocks read back through the
    /// inflater, at the 65535 byte block boundary.
    #[test]
    fn test_stored_deflate() {
        for n in [0usize, 1, 65535, 65536, 140_000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            let raw = message::stored_deflate(&data, false);
            assert_eq!(inflate::inflate(&raw, 1 << 20).unwrap().0, data);
            let zlib = message::stored_deflate(&data, true);
            assert_eq!(inflate::zlib_decompress(&zlib, 1 << 20).unwrap(), data);
        }
    }
}
