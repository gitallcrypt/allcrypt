//! Signed git commits and tags, SSH and OpenPGP, built from this
//! library's primitives: the objects themselves, and stand-ins for the two
//! programs git runs to sign and verify them.
//!
//!     cargo run --release --example gitsign -- sign OBJECT --ssh-key FILE
//!     cargo run --release --example gitsign -- sign OBJECT --pgp-key FILE [--user ID]
//!     cargo run --release --example gitsign -- verify OBJECT --allowed-signers FILE
//!             [--principal NAME]
//!     cargo run --release --example gitsign -- verify OBJECT --keyring FILE...
//!     cargo run --release --example gitsign -- payload OBJECT
//!     cargo run --release --example gitsign -- ssh-keygen -Y sign|verify|find-principals|
//!             check-novalidate ...
//!     cargo run --release --example gitsign -- gpg --status-fd=N (-bsau KEY | --verify SIG -)
//!
//! An OBJECT is what `git cat-file commit` or `git cat-file tag` prints,
//! or `-` for standard input; `sign` writes the signed object to standard
//! output, ready for `git hash-object -t commit -w --stdin`. A commit's
//! signature goes in its `gpgsig` header (`--sha256` for a SHA-256
//! repository's `gpgsig-sha256`); a tag's follows its message.
//! `--passphrase-stdin` reads a key's passphrase.
//!
//! `ssh-keygen` takes the arguments git passes `gpg.ssh.program`, and
//! `gpg` the ones it passes `gpg.program`, so that a wrapper script
//! `exec gitsign ssh-keygen "$@"` or `exec gitsign gpg "$@"` signs and
//! verifies for git itself. The `gpg` stand-in has no keyring of its own:
//! `GITSIGN_KEYRING` names the files of keys, colon-separated, which `-u`
//! picks from and `--verify` checks against, and a key protected by a
//! passphrase takes it from the first line of `GITSIGN_PASSPHRASE_FILE`,
//! since git's payload is on standard input.
//!
//! What has checked it is in `examples/products/README.md`.

mod object;
mod pgp;
mod ssh;

// OpenPGP, from the OpenPGP example: the same packets, keys and
// signatures, compiled in rather than copied.
#[path = "../openpgp/algo.rs"]
#[allow(dead_code)]
mod algo;
#[path = "../openpgp/armor.rs"]
#[allow(dead_code)]
mod armor;
#[path = "../openpgp/keys.rs"]
#[allow(dead_code)]
mod keys;
#[path = "../openpgp/message.rs"]
#[allow(dead_code)]
mod message;
#[path = "../openpgp/packet.rs"]
#[allow(dead_code)]
mod packet;
#[path = "../openpgp/pubkey.rs"]
#[allow(dead_code)]
mod pubkey;
#[path = "../openpgp/s2k.rs"]
#[allow(dead_code)]
mod s2k;
#[path = "../openpgp/sig.rs"]
#[allow(dead_code)]
mod sig;
#[path = "../openpgp/verify.rs"]
#[allow(dead_code)]
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

use std::io::{Read, Write};

const SWITCHES: [&str; 3] = ["--passphrase-stdin", "--sha256", "-"];

fn positional(args: &[String]) -> Vec<&String> {
    let mut out = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
        } else if SWITCHES.contains(&arg.as_str()) {
            if arg == "-" {
                out.push(arg);
            }
        } else if arg.starts_with("--") {
            skip = true;
        } else {
            out.push(arg);
        }
    }
    out
}

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn values(args: &[String], name: &str) -> Vec<String> {
    args.iter().enumerate().filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| args.get(i + 1).cloned()).collect()
}

fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data).map_err(|e| e.to_string())?;
        Ok(data)
    } else {
        std::fs::read(path).map_err(|e| format!("{path}: {e}"))
    }
}

fn now() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32).unwrap_or(0)
}

fn passphrase(args: &[String]) -> Result<Vec<u8>, String> {
    if args.iter().any(|a| a == "--passphrase-stdin") {
        passphrase::read_line("Passphrase: ")
    } else {
        Ok(Vec::new())
    }
}

/// The committer's or tagger's time, which git also passes ssh-keygen
/// as `verify-time`: a key's validity is judged at signing time.
fn signing_time(payload: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(payload);
    let line = text.lines().take_while(|l| !l.is_empty())
        .find(|l| l.starts_with("committer ") || l.starts_with("tagger "))?;
    let mut fields = line.rsplitn(3, ' ');
    let _zone = fields.next()?;
    fields.next()?.parse().ok()
}

// ----------------------------------------------------------------- objects --

fn sign_object(args: &[String]) -> Result<(), String> {
    let path = positional(args).get(1).map(|s| s.as_str()).ok_or("sign OBJECT")?;
    let object = read_input(path)?;
    let sha256 = args.iter().any(|a| a == "--sha256");
    // git signs the object as it will be stored, without a signature.
    let signature = if let Some(key) = value(args, "--ssh-key") {
        ssh::sign(&ssh::read_private(key, Some(&passphrase(args)?).filter(|p| !p.is_empty())
                                     .map(|p| p.as_slice()))?, "git", &object)?
    } else if let Some(file) = value(args, "--pgp-key") {
        let certs = pgp::read_certs(&[file.to_string()])?;
        let cert = match value(args, "--user") {
            Some(name) => pgp::find(&certs, name).ok_or_else(|| format!("No key {name}."))?,
            None => certs.first().ok_or("No key in the file.")?,
        };
        pgp::sign(cert, &passphrase(args)?, &object, now())?.armoured
    } else {
        return Err("sign needs --ssh-key or --pgp-key.".to_string());
    };
    let signed = object::insert(&object, signature.as_bytes(), sha256)?;
    std::io::stdout().write_all(&signed).map_err(|e| e.to_string())
}

fn verify_object(args: &[String]) -> Result<bool, String> {
    let path = positional(args).get(1).map(|s| s.as_str()).ok_or("verify OBJECT")?;
    let object = read_input(path)?;
    let sha256 = args.iter().any(|a| a == "--sha256");
    let (payload, signature) = object::split(&object, sha256)?
        .ok_or("The object is not signed.")?;
    match object::format_of(&signature) {
        Some("ssh") => {
            let signers = ssh::read_allowed_signers(&std::fs::read_to_string(
                value(args, "--allowed-signers").ok_or("An SSH signature needs \
                                                        --allowed-signers.")?)
                .map_err(|e| e.to_string())?)?;
            let armoured = String::from_utf8_lossy(&signature).to_string();
            let time = signing_time(&payload);
            let principals = match value(args, "--principal") {
                Some(p) => vec![p.to_string()],
                None => ssh::find_principals(&signers, &armoured, time)?,
            };
            let mut last = String::new();
            for principal in principals {
                match ssh::verify(&signers, &principal, "git", &armoured, &payload, time) {
                    Ok(line) => {
                        println!("{line}");
                        return Ok(true);
                    }
                    Err(e) => last = e,
                }
            }
            println!("BAD: {last}");
            Ok(false)
        }
        Some("openpgp") => {
            let certs = pgp::read_certs(&values(args, "--keyring"))?;
            let checked = pgp::check(&signature, &payload, &certs, now())?;
            println!("{}", checked.text);
            Ok(checked.good)
        }
        Some(other) => Err(format!("{other} signatures are not implemented here.")),
        None => Err("The signature is in no format git writes.".to_string()),
    }
}

// --------------------------------------------------------------- ssh-keygen --

/// `-Y` and the flags git passes: `-n NAMESPACE`, `-f FILE`, `-I
/// PRINCIPAL`, `-s SIGFILE`, `-O option`, `-U`, `-r REVOCATIONS`.
fn ssh_keygen(args: &[String]) -> Result<bool, String> {
    let flag = |name: &str| -> Option<&str> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
            .or_else(|| args.iter().find_map(|a| a.strip_prefix(name)).filter(|v| !v.is_empty()))
    };
    let options: Vec<&str> = args.iter().enumerate()
        .filter_map(|(i, a)| if a == "-O" { args.get(i + 1).map(String::as_str) }
                             else { a.strip_prefix("-O").filter(|v| !v.is_empty()) })
        .collect();
    let verify_time = options.iter().find_map(|o| o.strip_prefix("verify-time="))
        .map(ssh::parse_time).transpose()?;
    let namespace = flag("-n").unwrap_or("git");
    let mut stdin = Vec::new();
    match flag("-Y").ok_or("ssh-keygen: only -Y is implemented here.")? {
        "sign" => {
            let key = flag("-f").ok_or("-Y sign needs -f KEY")?;
            if args.iter().any(|a| a == "-U") {
                return Err("-U signs with an agent, and there is no agent here.".to_string());
            }
            // The key file git names may be the .pub of a private key
            // beside it, which ssh-keygen then signs with.
            let private = key.strip_suffix(".pub").unwrap_or(key);
            let file = args.last().ok_or("-Y sign needs a file")?;
            let data = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
            let signature = ssh::sign(&ssh::read_private(private, None)?, namespace, &data)?;
            std::fs::write(format!("{file}.sig"), signature).map_err(|e| e.to_string())?;
            Ok(true)
        }
        command @ ("verify" | "check-novalidate") => {
            let sigfile = flag("-s").ok_or("needs -s SIGNATURE")?;
            let armoured = std::fs::read_to_string(sigfile).map_err(|e| e.to_string())?;
            std::io::stdin().read_to_end(&mut stdin).map_err(|e| e.to_string())?;
            let line = if command == "verify" {
                let allowed = flag("-f").ok_or("-Y verify needs -f ALLOWED_SIGNERS")?;
                let signers = ssh::read_allowed_signers(&std::fs::read_to_string(allowed)
                                                        .map_err(|e| e.to_string())?)?;
                if let Some(revoked) = flag("-r") {
                    let key = allcrypt::ssh::signature::sshsig_public_key(&armoured)?;
                    let text = std::fs::read_to_string(revoked).unwrap_or_default();
                    if text.lines().filter_map(|l| allcrypt::ssh::keys::parse_line(l).ok())
                        .any(|l| l.key.to_blob() == key.to_blob()) {
                        return Err("The signing key is revoked.".to_string());
                    }
                }
                ssh::verify(&signers, flag("-I").ok_or("-Y verify needs -I PRINCIPAL")?,
                            namespace, &armoured, &stdin, verify_time)
            } else {
                ssh::check_novalidate(namespace, &armoured, &stdin)
            };
            match line {
                Ok(line) => {
                    println!("{line}");
                    Ok(true)
                }
                Err(e) => {
                    eprintln!("Could not verify signature: {e}");
                    Ok(false)
                }
            }
        }
        "find-principals" => {
            let allowed = flag("-f").ok_or("-Y find-principals needs -f ALLOWED_SIGNERS")?;
            let signers = ssh::read_allowed_signers(&std::fs::read_to_string(allowed)
                                                    .map_err(|e| e.to_string())?)?;
            let armoured = std::fs::read_to_string(flag("-s").ok_or("needs -s SIGNATURE")?)
                .map_err(|e| e.to_string())?;
            match ssh::find_principals(&signers, &armoured, verify_time) {
                Ok(found) => {
                    for p in found {
                        println!("{p}");
                    }
                    Ok(true)
                }
                Err(e) => {
                    eprintln!("{e}");
                    Ok(false)
                }
            }
        }
        other => Err(format!("ssh-keygen -Y {other} is not implemented here.")),
    }
}

// ---------------------------------------------------------------------- gpg --

fn keyring() -> Result<Vec<keys::Cert>, String> {
    let paths: Vec<String> = std::env::var("GITSIGN_KEYRING").unwrap_or_default()
        .split(':').filter(|p| !p.is_empty()).map(str::to_string).collect();
    pgp::read_certs(&paths)
}

/// Write status lines where `--status-fd` says: 1 or 2.
fn status(fd: &str, line: &str) {
    let text = format!("[GNUPG:] {line}\n");
    if fd == "1" {
        print!("{text}");
    } else {
        eprint!("{text}");
    }
}

fn gpg(args: &[String]) -> Result<bool, String> {
    let fd = args.iter().find_map(|a| a.strip_prefix("--status-fd=")).unwrap_or("2").to_string();
    let certs = keyring()?;
    let mut stdin = Vec::new();
    // `-bsau KEY`: detached, signed, armoured, user KEY.
    if let Some(i) = args.iter().position(|a| a.starts_with('-') && !a.starts_with("--")
                                          && a.contains('b') && a.contains('s')) {
        let name = if args[i].ends_with('u') { args.get(i + 1) } else { None }
            .map(String::as_str).or_else(|| value(args, "-u")).ok_or("-bsau needs a key")?;
        let cert = pgp::find(&certs, name)
            .ok_or_else(|| format!("gpg: skipped \"{name}\": No secret key"))?;
        std::io::stdin().read_to_end(&mut stdin).map_err(|e| e.to_string())?;
        // git gives gpg the payload on standard input, so a passphrase
        // comes from a file named in GITSIGN_PASSPHRASE_FILE: its first
        // line, without the line ending.
        let passphrase = match std::env::var("GITSIGN_PASSPHRASE_FILE") {
            Ok(path) => std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?
                .lines().next().unwrap_or("").as_bytes().to_vec(),
            Err(_) => Vec::new(),
        };
        let signed = pgp::sign(cert, &passphrase, &stdin, now())?;
        print!("{}", signed.armoured);
        status(&fd, &format!("KEY_CONSIDERED {} 2", signed.fingerprint));
        status(&fd, "BEGIN_SIGNING H{}");
        status(&fd, &format!("SIG_CREATED D {} {} 00 {} {}", signed.algorithm, signed.hash,
                             signed.created, signed.fingerprint));
        return Ok(true);
    }
    if let Some(i) = args.iter().position(|a| a == "--verify") {
        let sigfile = args.get(i + 1).ok_or("--verify needs a signature file")?;
        let signature = std::fs::read(sigfile).map_err(|e| format!("{sigfile}: {e}"))?;
        std::io::stdin().read_to_end(&mut stdin).map_err(|e| e.to_string())?;
        let checked = pgp::check(&signature, &stdin, &certs, now())?;
        status(&fd, "NEWSIG");
        match (&checked.signer, checked.good) {
            (Some((fpr, primary, uid)), true) => {
                status(&fd, &format!("GOODSIG {} {uid}", pgp::long_key_id(fpr)));
                status(&fd, &format!("VALIDSIG {fpr} - 0 0 4 0 0 0 00 {primary}"));
                // The keyring is the keys the caller named as theirs to
                // trust, so a good signature by one is fully trusted. git
                // reads anything less as `U`, good but of unknown validity.
                status(&fd, "TRUST_FULLY 0 pgp");
                eprintln!("gpg: Good signature from \"{uid}\"");
                Ok(true)
            }
            (Some((fpr, _, uid)), false) => {
                status(&fd, &format!("BADSIG {} {uid}", pgp::long_key_id(fpr)));
                eprintln!("gpg: BAD signature from \"{uid}\": {}", checked.text);
                Ok(false)
            }
            (None, _) => {
                status(&fd, "ERRSIG - 0 0 00 0 9 -");
                status(&fd, "NO_PUBKEY -");
                eprintln!("gpg: Can't check signature: {}", checked.text);
                Ok(false)
            }
        }
    } else {
        Err("gpg: only -bsau and --verify are implemented here.".to_string())
    }
}

fn run(args: &[String]) -> Result<bool, String> {
    match args.first().map(String::as_str) {
        Some("sign") => sign_object(args).map(|()| true),
        Some("verify") => verify_object(args),
        Some("payload") => {
            let path = positional(args).get(1).map(|s| s.as_str()).ok_or("payload OBJECT")?;
            let object = read_input(path)?;
            let sha256 = args.iter().any(|a| a == "--sha256");
            let (payload, _) = object::split(&object, sha256)?.ok_or("The object is not signed.")?;
            std::io::stdout().write_all(&payload).map_err(|e| e.to_string())?;
            Ok(true)
        }
        Some("ssh-keygen") => ssh_keygen(&args[1..]),
        Some("gpg") => gpg(&args[1..]),
        _ => Err("Commands: sign, verify, payload, ssh-keygen, gpg. See the top of \
                  examples/products/gitsign/main.rs.".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("gitsign: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests;
