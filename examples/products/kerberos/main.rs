//! Kerberos 5's cryptography (RFC 3961, 3962, 4757, 6803, 8009) and the
//! files MIT Kerberos keeps keys and tickets in, built from this
//! library's primitives.
//!
//!     cargo run --release --example kerberos -- string2key --enctype E --principal P
//!             [--salt S] [--iterations N]
//!     cargo run --release --example kerberos -- keytab list KEYTAB [--keys]
//!     cargo run --release --example kerberos -- keytab add KEYTAB --principal P [--kvno N]
//!             [--enctype E]... [--salt S] [--iterations N]
//!     cargo run --release --example kerberos -- keytab add KEYTAB --principal P [--kvno N]
//!             --enctype E --key HEX
//!     cargo run --release --example kerberos -- encrypt IN OUT --enctype E --key HEX --usage N
//!     cargo run --release --example kerberos -- decrypt IN OUT --enctype E --key HEX --usage N
//!     cargo run --release --example kerberos -- checksum IN [--cksumtype T]
//!             [--enctype E --key HEX --usage N] [--verify HEX]
//!     cargo run --release --example kerberos -- prf HEX --enctype E --key HEX
//!     cargo run --release --example kerberos -- ccache list CCACHE
//!     cargo run --release --example kerberos -- ticket CCACHE --keytab KEYTAB
//!     cargo run --release --example kerberos -- enctypes
//!
//! `checksum` makes the encryption type's mandatory checksum unless
//! `--cksumtype` names another, and checks one given with `--verify`.
//! A password is `--password PW` or `--password-stdin`. A principal
//! without a realm takes `--realm`. `IN` or `OUT` of `-` is standard
//! input or output. `ticket` decrypts every ticket in a credential cache
//! with the service's key from a keytab and checks that the session key
//! inside is the one the cache holds.
//!
//! What has checked it is in `examples/products/README.md`.

mod crypto;
mod files;

#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/cli.rs"]
mod cli;
#[path = "../shared/hidden.rs"]
mod hidden;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use std::io::{Read, Write};

use cli::{has, hex, value};

use crypto::Enctype;
use files::{Ccache, KeytabEntry, Principal};

/// The enctypes `keytab add` writes when none is named: the four AES
/// types, as MIT Kerberos 1.21's default `permitted_enctypes` has them.
const DEFAULT_ENCTYPES: [&str; 4] = ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96",
                                     "aes256-cts-hmac-sha384-192",
                                     "aes128-cts-hmac-sha256-128"];

// ----------------------------------------------------------------- arguments --

const SWITCHES: [&str; 2] = ["--password-stdin", "--keys"];

fn positional(args: &[String]) -> Vec<&String> {
    cli::positional(args, &SWITCHES, &[])
}

fn values<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.iter().enumerate().filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| args.get(i + 1).map(String::as_str)).collect()
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    value(args, name).ok_or_else(|| format!("{name} is required."))
}

fn password(args: &[String]) -> Result<Vec<u8>, String> {
    passphrase::required_from_args(args)
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    cli::unhex(text, &[' ', '\t', '\r', '\n', ':'])
}

fn number<T: std::str::FromStr>(args: &[String], name: &str) -> Result<Option<T>, String> {
    value(args, name).map(|v| v.parse().map_err(|_| format!("{name}: not a number: {v}")))
        .transpose()
}

fn principal(args: &[String]) -> Result<Principal, String> {
    Principal::parse(required(args, "--principal")?, value(args, "--realm"))
}

fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        let mut data = Vec::new();
        std::io::stdin().lock().read_to_end(&mut data).map_err(|e| format!("stdin: {e}"))?;
        return Ok(data);
    }
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn write_output(path: &str, data: &[u8]) -> Result<(), String> {
    if path == "-" {
        return std::io::stdout().lock().write_all(data).map_err(|e| format!("stdout: {e}"));
    }
    std::fs::write(path, data).map_err(|e| format!("{path}: {e}"))
}

/// `--enctype`, `--key` and `--usage`, the three every raw operation
/// takes.
fn keyed(args: &[String]) -> Result<(&'static Enctype, Vec<u8>), String> {
    Ok((crypto::by_name(required(args, "--enctype")?)?, unhex(required(args, "--key")?)?))
}

fn usage(args: &[String]) -> Result<u32, String> {
    number(args, "--usage")?.ok_or_else(|| "--usage is required.".to_string())
}

/// String-to-key parameters from `--iterations`, for the types that
/// take a count.
fn params(enctype: &Enctype, args: &[String]) -> Result<Option<Vec<u8>>, String> {
    let Some(count) = number::<u32>(args, "--iterations")? else { return Ok(None) };
    if enctype.default_params().is_none() {
        return Err(format!("{} takes no iteration count.", enctype.name));
    }
    Ok(Some(count.to_be_bytes().to_vec()))
}

fn derive_key(enctype: &Enctype, principal: &Principal, password: &[u8], args: &[String])
              -> Result<Vec<u8>, String> {
    let salt = value(args, "--salt").map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| principal.salt());
    enctype.string_to_key(password, &salt, params(enctype, args)?.as_deref())
}

// ------------------------------------------------------------------- output --

fn enctype_name(id: i32) -> String {
    crypto::by_id(id).map(|e| e.name.to_string()).unwrap_or_else(|_| format!("enctype {id}"))
}

/// Seconds since 1970 as `YYYY-MM-DD HH:MM:SS` UTC.
fn time(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}", rest / 3600, rest / 60 % 60,
            rest % 60)
}

fn list_keytab(entries: &[KeytabEntry], keys: bool) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&format!("{:>4}  {}  {}  {}", e.kvno, time(i64::from(e.timestamp)),
                              e.principal, enctype_name(e.enctype)));
        if keys {
            out.push_str(&format!("  {}", hex(&e.key)));
        }
        out.push('\n');
    }
    out
}

fn list_ccache(cache: &Ccache) -> String {
    let mut out = format!("default principal: {}\n", cache.default_principal);
    for c in &cache.credentials {
        out.push_str(&format!("{}  {}  {}\n", time(i64::from(c.starttime.max(c.authtime))),
                              time(i64::from(c.endtime)), c.server));
        if c.client != cache.default_principal {
            out.push_str(&format!("    for {}\n", c.client));
        }
        if c.renew_till != 0 {
            out.push_str(&format!("    renew until {}\n", time(i64::from(c.renew_till))));
        }
        out.push_str(&format!("    session key: {}; flags: {}\n", enctype_name(c.enctype),
                              files::flag_names(c.flags).join(" ")));
    }
    out
}

/// Every ticket in a cache, opened with the service's key from a keytab.
fn open_tickets(cache: &Ccache, keytab: &[KeytabEntry]) -> Result<String, String> {
    let mut out = String::new();
    for c in &cache.credentials {
        let ticket = files::parse_ticket(&c.ticket)?;
        let enctype = crypto::by_id(ticket.enctype)?;
        let entry = keytab.iter()
            .filter(|e| e.principal.realm == ticket.server.realm
                    && e.principal.components == ticket.server.components
                    && e.enctype == ticket.enctype)
            .filter(|e| ticket.kvno.is_none_or(|k| k == e.kvno))
            .max_by_key(|e| e.kvno)
            .ok_or_else(|| format!("{}: no {} key{} in the keytab.", ticket.server, enctype.name,
                                   ticket.kvno.map(|k| format!(" of version {k}"))
                                       .unwrap_or_default()))?;
        // Key usage 2: a ticket's encrypted part (RFC 4120 7.5.1).
        let plain = enctype.decrypt(&entry.key, 2, &ticket.cipher)
            .map_err(|e| format!("{}: {e}", ticket.server))?;
        let contents = files::parse_enc_ticket_part(&plain)?;
        if contents.session_key != c.session_key || contents.enctype != c.enctype {
            return Err(format!("{}: the ticket's session key is not the one in the cache.",
                               ticket.server));
        }
        out.push_str(&format!("{} (kvno {}, {})\n", ticket.server, entry.kvno, enctype.name));
        out.push_str(&format!("    client: {}\n", contents.client));
        out.push_str(&format!("    authtime: {}; starts: {}; ends: {}\n",
                              time(contents.authtime),
                              time(contents.starttime.unwrap_or(contents.authtime)),
                              time(contents.endtime)));
        if let Some(renew) = contents.renew_till {
            out.push_str(&format!("    renew till: {}\n", time(renew)));
        }
        out.push_str(&format!("    flags: {}\n", files::flag_names(contents.flags).join(" ")));
        out.push_str(&format!("    session key: {} {}, as in the cache\n",
                              enctype_name(contents.enctype), hex(&contents.session_key)));
    }
    Ok(out)
}

// ----------------------------------------------------------------------- CLI --

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let name = |i: usize, what: &str| names.get(i).map(|s| s.as_str())
        .ok_or_else(|| format!("Name the {what}."));
    match command {
        "string2key" => {
            let enctype = crypto::by_name(required(rest, "--enctype")?)?;
            let principal = principal(rest)?;
            let key = derive_key(enctype, &principal, &password(rest)?, rest)?;
            println!("{}", hex(&key));
        }
        "keytab" => {
            let path = name(1, "keytab")?;
            match name(0, "keytab command (list or add)")? {
                "list" => print!("{}", list_keytab(&files::read_keytab(&read_input(path)?)?,
                                                   has(rest, "--keys"))),
                "add" => {
                    let mut entries = match std::fs::read(path) {
                        Ok(data) => files::read_keytab(&data)?,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                        Err(e) => return Err(format!("{path}: {e}")),
                    };
                    let principal = principal(rest)?;
                    let kvno = number(rest, "--kvno")?.unwrap_or(1);
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32)
                        .unwrap_or(0);
                    let mut named = values(rest, "--enctype");
                    let given_key = value(rest, "--key").map(unhex).transpose()?;
                    if given_key.is_some() && named.len() != 1 {
                        return Err("--key needs exactly one --enctype.".to_string());
                    }
                    if named.is_empty() {
                        named = DEFAULT_ENCTYPES.to_vec();
                    }
                    let pw = if given_key.is_none() { Some(password(rest)?) } else { None };
                    for n in named {
                        let enctype = crypto::by_name(n)?;
                        let key = match (&given_key, &pw) {
                            (Some(k), _) => k.clone(),
                            (None, Some(pw)) => derive_key(enctype, &principal, pw, rest)?,
                            (None, None) => unreachable!("a password or a key"),
                        };
                        if key.len() != enctype.key_len() {
                            return Err(format!("A {} key is {} bytes.", enctype.name,
                                               enctype.key_len()));
                        }
                        entries.push(KeytabEntry { principal: principal.clone(), timestamp, kvno,
                                                   enctype: enctype.id, key });
                    }
                    std::fs::write(path, files::write_keytab(&entries))
                        .map_err(|e| format!("{path}: {e}"))?;
                }
                other => return Err(format!("No keytab command {other}.")),
            }
        }
        "encrypt" | "decrypt" => {
            let (enctype, key) = keyed(rest)?;
            let data = read_input(name(0, "input")?)?;
            let out = if command == "encrypt" { enctype.encrypt(&key, usage(rest)?, &data, None)? }
                      else { enctype.decrypt(&key, usage(rest)?, &data)? };
            write_output(name(1, "output")?, &out)?;
        }
        "checksum" => {
            let data = read_input(name(0, "input")?)?;
            let kind = match value(rest, "--cksumtype") {
                Some(n) => crypto::cksumtype_by_name(n)?,
                None => crypto::by_name(required(rest, "--enctype")?)?.mandatory_cksumtype(),
            };
            let (key, usage) = if kind.keyed() {
                (unhex(required(rest, "--key")?)?, usage(rest)?)
            } else {
                (Vec::new(), 0)
            };
            match value(rest, "--verify") {
                Some(sum) => {
                    if !kind.verify(&key, usage, &data, &unhex(sum)?)? {
                        return Err(format!("The {} checksum does not match.", kind.name));
                    }
                    println!("{}: good", kind.name);
                }
                None => println!("{} {}", kind.id, hex(&kind.make(&key, usage, &data, None)?)),
            }
        }
        "prf" => {
            let (enctype, key) = keyed(rest)?;
            println!("{}", hex(&enctype.prf(&key, &unhex(name(0, "input, in hex")?)?)?));
        }
        "ccache" => {
            if name(0, "ccache command (list)")? != "list" {
                return Err("The ccache command is list.".to_string());
            }
            print!("{}", list_ccache(&files::read_ccache(&read_input(name(1, "cache")?)?)?));
        }
        "ticket" => {
            let cache = files::read_ccache(&read_input(name(0, "cache")?)?)?;
            let keytab = files::read_keytab(&read_input(required(rest, "--keytab")?)?)?;
            print!("{}", open_tickets(&cache, &keytab)?);
        }
        "enctypes" => {
            for e in crypto::ENCTYPES {
                println!("{:>4}  {:<28}  checksum {}", e.id, e.name, e.mandatory_cksumtype().name);
            }
            for c in crypto::CKSUMTYPES {
                println!("{:>4}  {}{}", c.id, c.name, if c.keyed() { "" } else { " (unkeyed)" });
            }
        }
        "" => return Err("Name a command: string2key, keytab, encrypt, decrypt, checksum, prf, \
                          ccache, ticket or enctypes.".to_string()),
        other => return Err(format!("No command {other}.")),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("kerberos: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::{field, records};

    fn plain(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    fn key_for(e: &Enctype, seed: u8) -> Vec<u8> {
        (0..e.key_len()).map(|i| (i as u8).wrapping_mul(17).wrapping_add(seed)).collect()
    }

    #[test]
    fn every_type_round_trips_at_every_length() {
        for e in crypto::ENCTYPES {
            let key = key_for(e, 1);
            for len in 0..70 {
                for usage in [1, 2, 3, 9, 23, 1024] {
                    let data = plain(len);
                    let c = e.encrypt(&key, usage, &data, None).unwrap();
                    let back = e.decrypt(&key, usage, &c).unwrap();
                    // The DES types pad with zeros to a block and cannot
                    // say how many; Kerberos's ASN.1 is self-delimiting.
                    if e.id <= 16 {
                        assert!(back.starts_with(&data) && back.len() - data.len() < 8
                                && back[len..].iter().all(|&b| b == 0), "{} {len}", e.name);
                        assert!((back.len() + if e.id == 1 { 12 } else if e.id <= 3 { 24 }
                                 else { 8 }).is_multiple_of(8));
                    } else {
                        assert_eq!(back, data, "{} {len}", e.name);
                    }
                }
            }
        }
    }

    #[test]
    fn a_different_usage_is_a_different_key() {
        for e in crypto::ENCTYPES {
            let key = key_for(e, 2);
            let c = e.encrypt(&key, 5, b"usage", None).unwrap();
            let other = e.decrypt(&key, 6, &c);
            // Single DES has no usages: the key is the key.
            if e.id <= 3 {
                assert!(other.is_ok(), "{}", e.name);
            } else {
                assert!(other.is_err(), "{}", e.name);
            }
            // RC4-HMAC maps the AS-REP's usage, 3, onto the TGS-REP's, 8
            // (RFC 4757 3). It does not map 9 onto 8, as the RFC also
            // says, because MIT and Heimdal do not.
            if e.id == 23 || e.id == 24 {
                let c = e.encrypt(&key, 3, b"usage", None).unwrap();
                assert_eq!(e.decrypt(&key, 8, &c).unwrap(), b"usage");
                let c = e.encrypt(&key, 9, b"usage", None).unwrap();
                assert!(e.decrypt(&key, 8, &c).is_err());
            }
        }
    }

    #[test]
    fn every_bit_of_a_ciphertext_is_checked() {
        for e in crypto::ENCTYPES {
            let key = key_for(e, 3);
            let c = e.encrypt(&key, 7, &plain(21), None).unwrap();
            for bit in 0..c.len() * 8 {
                let mut bad = c.clone();
                bad[bit / 8] ^= 1 << (bit % 8);
                assert!(e.decrypt(&key, 7, &bad).is_err(), "{} bit {bit}", e.name);
            }
            assert!(e.decrypt(&key, 7, &c[..c.len() - 1]).is_err());
            assert!(e.decrypt(&key_for(e, 4), 7, &c).is_err());
        }
    }

    #[test]
    fn the_export_variant_keys_rc4_with_forty_bits() {
        // Two base keys whose usage keys K1 differ only past the seventh
        // byte encrypt identically under arcfour-hmac-exp; that is the
        // whole point of the variant. Shown here through the one place
        // the difference is visible: the ciphertexts of the same message
        // under the export type and the full type are unrelated.
        let full = crypto::by_name("arcfour-hmac").unwrap();
        let export = crypto::by_name("arcfour-hmac-exp").unwrap();
        let key = key_for(full, 5);
        let confounder = [1u8; 8];
        let a = full.encrypt(&key, 1, b"message", Some(&confounder)).unwrap();
        let b = export.encrypt(&key, 1, b"message", Some(&confounder)).unwrap();
        assert_ne!(a, b);
        assert!(full.decrypt(&key, 1, &b).is_err());
    }

    #[test]
    fn every_checksum_type_verifies_and_refuses_a_change() {
        for kind in crypto::CKSUMTYPES {
            let key = match kind.id {
                3..=8 => vec![0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1],
                _ if kind.keyed() => {
                    let e = crypto::ENCTYPES.iter()
                        .find(|e| e.mandatory_cksumtype().id == kind.id).unwrap();
                    key_for(e, 9)
                }
                _ => Vec::new(),
            };
            for len in [0, 1, 8, 13, 64] {
                let data = plain(len);
                let sum = kind.make(&key, 4, &data, None).unwrap();
                assert!(kind.verify(&key, 4, &data, &sum).unwrap(), "{} {len}", kind.name);
                for bit in 0..sum.len() * 8 {
                    let mut bad = sum.clone();
                    bad[bit / 8] ^= 1 << (bit % 8);
                    assert!(!kind.verify(&key, 4, &data, &bad).unwrap(), "{} bit {bit}",
                            kind.name);
                }
                let mut other = data.clone();
                other.push(1);
                assert!(!kind.verify(&key, 4, &other, &sum).unwrap(), "{} {len}", kind.name);
                if kind.keyed() {
                    let mut wrong = key.clone();
                    wrong[1] ^= 0x10;
                    assert!(!kind.verify(&wrong, 4, &data, &sum).unwrap(), "{}", kind.name);
                }
            }
        }
    }

    /// RFC 3961 6.2.7 and 6.2.8 pad with zeros and record no length, so
    /// a message and the same message with zeros added up to the block
    /// boundary have one MAC. That is the construction, not a fault here.
    #[test]
    fn the_des_macs_cannot_see_zero_padding() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
        for name in ["des-mac", "des-mac-k"] {
            let kind = crypto::cksumtype_by_name(name).unwrap();
            let sum = kind.make(&key, 0, b"abc", None).unwrap();
            assert!(kind.verify(&key, 0, b"abc\0\0", &sum).unwrap(), "{name}");
        }
    }

    #[test]
    fn the_confounded_des_checksums_are_random_and_carry_their_confounder() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
        for name in ["rsa-md4-des", "rsa-md5-des", "des-mac"] {
            let kind = crypto::cksumtype_by_name(name).unwrap();
            let a = kind.make(&key, 0, b"text", None).unwrap();
            let b = kind.make(&key, 0, b"text", None).unwrap();
            assert_ne!(a, b, "{name}");
            let fixed = kind.make(&key, 0, b"text", Some(&[7; 8])).unwrap();
            assert_eq!(fixed, kind.make(&key, 0, b"text", Some(&[7; 8])).unwrap());
            assert_eq!(fixed.len(), if name == "des-mac" { 16 } else { 24 });
        }
    }

    // ------------------------------------------- MIT Kerberos's answers --

    fn bytes(text: &str) -> Vec<u8> {
        if text == "-" { Vec::new() } else { fixtures::unhex(text) }
    }

    #[test]
    fn mit_string_to_key() {
        let rows = records("kerberos.vec", "s2k");
        assert!(rows.len() >= 30, "{}", rows.len());
        for r in &rows {
            let e = crypto::by_name(field(r, "enctype")).unwrap();
            let params = bytes(field(r, "params"));
            let key = e.string_to_key(&bytes(field(r, "password")), &bytes(field(r, "salt")),
                                      (!params.is_empty()).then_some(params.as_slice()))
                .unwrap();
            assert_eq!(fixtures::hex(&key), field(r, "key"), "{}", field(r, "name"));
        }
        // The empty password with the empty salt, for single DES: the
        // CBC checksum of nothing (see des_string_to_key).
        assert!(rows.iter().any(|r| field(r, "key") == "01010101010101f1"));
    }

    #[test]
    fn mit_ciphertexts_decrypt() {
        let rows = records("kerberos.vec", "decrypt");
        assert!(rows.len() >= 100, "{}", rows.len());
        for r in &rows {
            let e = crypto::by_name(field(r, "enctype")).unwrap();
            let key = bytes(field(r, "key"));
            let usage: u32 = field(r, "usage").parse().unwrap();
            let cipher = bytes(field(r, "cipher"));
            let plain = bytes(field(r, "plain"));
            let got = e.decrypt(&key, usage, &cipher).unwrap();
            assert!(got.starts_with(&plain) && got[plain.len()..].iter().all(|&b| b == 0)
                    && got.len() - plain.len() < 8, "{}", field(r, "name"));
            let mut bad = cipher.clone();
            let at = bad.len() / 2;
            bad[at] ^= 0x40;
            assert!(e.decrypt(&key, usage, &bad).is_err(), "{}", field(r, "name"));
            // Ours encrypts to the same length.
            assert_eq!(e.encrypt(&key, usage, &plain, None).unwrap().len(), cipher.len());
        }
    }

    #[test]
    fn mit_checksums() {
        let rows = records("kerberos.vec", "checksum");
        assert!(rows.len() >= 25, "{}", rows.len());
        let mut confounded = 0;
        for r in &rows {
            let kind = crypto::cksumtype_by_id(field(r, "cksumtype").parse().unwrap()).unwrap();
            let e = crypto::by_name(field(r, "enctype")).unwrap();
            if field(r, "mandatory") == "yes" {
                assert_eq!(e.mandatory_cksumtype().id, kind.id, "{}", field(r, "name"));
            }
            let key = bytes(field(r, "key"));
            let usage: u32 = field(r, "usage").parse().unwrap();
            let data = bytes(field(r, "data"));
            let sum = bytes(field(r, "checksum"));
            assert!(kind.verify(&key, usage, &data, &sum).unwrap(), "{}", field(r, "name"));
            if kind.id == 3 || kind.id == 8 {
                confounded += 1;
            } else {
                assert_eq!(kind.make(&key, usage, &data, None).unwrap(), sum);
            }
            let mut other = data.clone();
            other.push(0x80);
            assert!(!kind.verify(&key, usage, &other, &sum).unwrap(), "{}", field(r, "name"));
        }
        assert!(confounded >= 6, "{confounded}");
    }

    /// RFC 3961 6.2.4 to 6.2.8's DES checksums, built from the formulas
    /// with OpenSSL's DES, MD4 and MD5 by scripts/check_kerberos.py:
    /// MIT has only two of them, and its number 4 is another
    /// construction.
    #[test]
    fn des_checksums_built_with_openssl() {
        let rows = records("kerberos.vec", "des-checksum");
        assert_eq!(rows.len(), 15);
        let mut kinds = std::collections::BTreeSet::new();
        for r in &rows {
            let kind = crypto::cksumtype_by_id(field(r, "cksumtype").parse().unwrap()).unwrap();
            let key = bytes(field(r, "key"));
            let data = bytes(field(r, "data"));
            let sum = bytes(field(r, "checksum"));
            assert!(kind.verify(&key, 0, &data, &sum).unwrap(), "{}", field(r, "name"));
            if kind.id == 5 || kind.id == 6 {
                assert_eq!(kind.make(&key, 0, &data, None).unwrap(), sum);
            }
            kinds.insert(kind.id);
        }
        assert_eq!(kinds.into_iter().collect::<Vec<_>>(), [3, 4, 5, 6, 8]);
    }

    #[test]
    fn mit_prf() {
        let rows = records("kerberos.vec", "prf");
        assert_eq!(rows.len(), 24);
        for r in &rows {
            let e = crypto::by_name(field(r, "enctype")).unwrap();
            assert_eq!(fixtures::hex(&e.prf(&bytes(field(r, "key")), &bytes(field(r, "input")))
                                          .unwrap()),
                       field(r, "output"), "{}", field(r, "name"));
        }
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixtures::dir().join("kerberos").join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    #[test]
    fn ktutil_keytabs_read_back_byte_for_byte() {
        for (version, types) in [("1.21", 9), ("1.17", 12)] {
            let data = fixture(&format!("ktutil-{version}.keytab"));
            let entries = files::read_keytab(&data).unwrap();
            assert_eq!(entries.len(), types, "{version}");
            assert_eq!(files::write_keytab(&entries), data, "{version}");
            for (i, entry) in entries.iter().enumerate() {
                assert_eq!(entry.principal.to_string(), "host/a\\/b.example.com@EXAMPLE.COM");
                assert_eq!(entry.kvno, i as u32 + 2);
                let e = crypto::by_id(entry.enctype).unwrap();
                assert_eq!(e.string_to_key("pässwörd".as_bytes(), &entry.principal.salt(), None)
                               .unwrap(), entry.key, "{version} {}", e.name);
            }
        }
    }

    const TICKETS: [&str; 6] = ["aes256-cts-hmac-sha1-96-v4", "aes256-cts-hmac-sha384-192-v4",
                                "arcfour-hmac-v4", "camellia256-cts-cmac-v4",
                                "des-cbc-md5-v3", "des3-cbc-sha1-v3"];

    #[test]
    fn tickets_from_mit_kdcs_open() {
        for name in TICKETS {
            let cache = files::read_ccache(&fixture(&format!("{name}.ccache"))).unwrap();
            let keytab = files::read_keytab(&fixture(&format!("{name}.keytab"))).unwrap();
            assert_eq!(cache.default_principal.to_string(), "user@EXAMPLE.COM");
            assert_eq!(cache.credentials.len(), 2, "{name}");
            let out = open_tickets(&cache, &keytab).unwrap();
            assert_eq!(out.matches("as in the cache").count(), 2, "{name}: {out}");
            assert!(out.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM (kvno"), "{out}");
            assert!(out.contains("HTTP/www.example.com@EXAMPLE.COM (kvno"), "{out}");
            assert!(out.contains("client: user@EXAMPLE.COM"), "{out}");
            // The TGT came from an AS exchange; the service ticket did not.
            // MIT's klist shows the same: I on one, T on the other.
            assert_eq!(out.matches(" initial").count(), 1, "{out}");
            assert_eq!(out.matches("transited-policy-checked").count(), 1, "{out}");
            assert!(!out.contains("anonymous"), "{out}");
            let listed = list_ccache(&cache);
            assert!(listed.starts_with("default principal: user@EXAMPLE.COM\n"), "{listed}");
        }
    }

    #[test]
    fn a_ticket_under_the_wrong_key_or_altered_is_refused() {
        let name = TICKETS[0];
        let mut cache = files::read_ccache(&fixture(&format!("{name}.ccache"))).unwrap();
        let mut keytab = files::read_keytab(&fixture(&format!("{name}.keytab"))).unwrap();
        // A changed byte in the encrypted part.
        let ticket = &mut cache.credentials[0].ticket;
        let at = ticket.len() - 20;
        ticket[at] ^= 1;
        assert!(open_tickets(&cache, &keytab).unwrap_err().contains("Integrity check"));
        let mut cache = files::read_ccache(&fixture(&format!("{name}.ccache"))).unwrap();
        // A session key in the cache that is not the ticket's.
        cache.credentials[1].session_key[0] ^= 1;
        assert!(open_tickets(&cache, &keytab).unwrap_err().contains("not the one in the cache"));
        // No key of the ticket's version.
        let cache = files::read_ccache(&fixture(&format!("{name}.ccache"))).unwrap();
        for e in &mut keytab {
            e.kvno += 1;
        }
        assert!(open_tickets(&cache, &keytab).unwrap_err().contains("no aes256"));
    }

    #[test]
    fn principals_parse_and_print_with_escapes() {
        let p = Principal::parse("host/a\\/b@EXAMPLE.COM", None).unwrap();
        assert_eq!(p.components, ["host", "a/b"]);
        assert_eq!(p.realm, "EXAMPLE.COM");
        assert_eq!(p.to_string(), "host/a\\/b@EXAMPLE.COM");
        assert_eq!(p.salt(), b"EXAMPLE.COMhosta/b");
        assert_eq!(Principal::parse("user", Some("R")).unwrap().to_string(), "user@R");
        assert!(Principal::parse("user", None).is_err());
        assert!(Principal::parse("a//b@R", None).is_err());
        assert!(Principal::parse("a@", None).is_err());
    }

    #[test]
    fn a_keytab_round_trips() {
        let principal = Principal::parse("HTTP/www.example.com@EXAMPLE.COM", None).unwrap();
        let entries: Vec<KeytabEntry> = crypto::ENCTYPES.iter().enumerate()
            .map(|(i, e)| KeytabEntry { principal: principal.clone(), timestamp: 1_700_000_000,
                                         kvno: 300 + i as u32, enctype: e.id,
                                         key: key_for(e, i as u8) }).collect();
        let bytes = files::write_keytab(&entries);
        assert_eq!(files::read_keytab(&bytes).unwrap(), entries);
        let listed = list_keytab(&entries, true);
        assert!(listed.contains(" 300  2023-11-14 22:13:20  HTTP/www.example.com@EXAMPLE.COM  \
                                 des-cbc-crc  "), "{listed}");
    }

    /// A deleted entry is a negative length followed by that many bytes,
    /// which MIT's kdestroy-like tools leave as holes for reuse.
    #[test]
    fn a_keytab_hole_is_skipped() {
        let principal = Principal::parse("a@B", None).unwrap();
        let entry = |kvno| KeytabEntry { principal: principal.clone(), timestamp: 1, kvno,
                                         enctype: 18, key: vec![kvno as u8; 32] };
        let mut bytes = files::write_keytab(&[entry(1), entry(2), entry(3)]);
        // The second entry's length, negated.
        let first = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
        let at = 2 + 4 + first;
        let len = i32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
        bytes[at..at + 4].copy_from_slice(&(-len).to_be_bytes());
        let read = files::read_keytab(&bytes).unwrap();
        assert_eq!(read, [entry(1), entry(3)]);
    }

    #[test]
    fn dates_print_in_utc() {
        assert_eq!(time(0), "1970-01-01 00:00:00");
        assert_eq!(time(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(time(4_102_444_799), "2099-12-31 23:59:59");
    }

    #[test]
    fn a_zero_iteration_count_is_refused() {
        let e = crypto::by_name("aes128").unwrap();
        assert!(e.string_to_key(b"p", b"s", Some(&[0; 4])).unwrap_err().contains("2^32"));
        assert!(e.string_to_key(b"p", b"s", Some(&[0; 3])).is_err());
    }

    #[test]
    fn the_command_line_refuses_what_it_cannot_do() {
        let args = |s: &str| s.split(' ').map(str::to_string).collect::<Vec<_>>();
        assert!(run(&args("string2key --enctype des3 --principal a@B --password x"))
            .unwrap_err().contains("des3"));
        assert!(run(&args("string2key --enctype des-cbc-md5 --principal a@B --password x \
                           --iterations 5")).unwrap_err().contains("no iteration count"));
        assert!(run(&args("checksum Cargo.toml --cksumtype rsa-md5-des --key 01010101 --usage 1"))
            .is_err());
        assert!(run(&args("frobnicate")).unwrap_err().contains("frobnicate"));
    }
}
