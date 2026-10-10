//! Key stores - PKCS#12 (`.p12`, `.pfx`) and Java's JKS and JCEKS -
//! built from this library's primitives.
//!
//!     cargo run --release --example keystore -- list FILE --password PW
//!             [--key-password PW] [--canonical]
//!     cargo run --release --example keystore -- convert IN OUT --password PW
//!             --format pkcs12|jks|jceks [--key-password PW] [--out-password PW]
//!             [--key-scheme aes-256|3des|rc2-40|none] [--cert-scheme aes-256|3des|rc2-40|none]
//!             [--mac sha256|sha1|pbmac1|none] [--iterations N]
//!
//! `--password-stdin` reads the store password from standard input; the
//! key password is the store password unless given. `--out-password`
//! re-encrypts under a new one.
//!
//! `list` says how the store is protected and lists its entries;
//! `--canonical` prints one line per entry with the key, certificate or
//! secret in hex, for `scripts/check_keystore.py` to compare. `convert`
//! writes the same entries in another format - PKCS#12 to JKS, JKS to
//! PKCS#12, or a PKCS#12 re-encrypted under other schemes.
//!
//! What has checked it is in `examples/products/README.md`.

#[path = "../shared/ber.rs"]
mod ber;
mod javaser;
mod jks;
mod pkcs12;

#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/cli.rs"]
mod cli;
#[path = "../shared/hidden.rs"]
mod hidden;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use pkcs12::{Bag, Kind};
use cli::value;

pub use cli::hex;

/// One store's entries, whichever format it came from.
#[derive(Clone, Debug, PartialEq)]
pub enum Store {
    Pkcs12(Vec<Bag>, pkcs12::Report),
    Java(u32, Vec<jks::Named>),
}

impl PartialEq for pkcs12::Report {
    fn eq(&self, other: &Self) -> bool {
        self.mac == other.mac && self.schemes == other.schemes
    }
}

pub fn open(data: &[u8], password: &[u8], key_password: &[u8]) -> Result<Store, String> {
    let magic = data.get(..4).map(|b| u32::from_be_bytes(b.try_into().expect("four")));
    if magic == Some(jks::JKS_MAGIC) || magic == Some(jks::JCEKS_MAGIC) {
        let (magic, entries) = jks::open(data, password, key_password)?;
        return Ok(Store::Java(magic, entries));
    }
    if data.first() != Some(&0x30) {
        return Err("Neither a Java key store nor a PKCS#12 file.".to_string());
    }
    let (bags, report) = pkcs12::open(data, password)?;
    Ok(Store::Pkcs12(bags, report))
}

/// The canonical listing: what each entry holds, in hex, in the order
/// stored.
pub fn canonical(store: &Store) -> Vec<String> {
    let mut out = Vec::new();
    match store {
        Store::Pkcs12(bags, _) => {
            for bag in bags {
                let name = bag.friendly_name.clone().unwrap_or_else(|| "-".to_string());
                let id = bag.local_key_id.as_deref().map(hex).unwrap_or_else(|| "-".to_string());
                let line = match &bag.kind {
                    Kind::Key { pkcs8, .. } => format!("key {name} {id} {}", hex(pkcs8)),
                    Kind::Certificate(der) => format!("cert {name} {id} {}", hex(der)),
                    Kind::Crl(der) => format!("crl {name} {id} {}", hex(der)),
                    Kind::Secret { kind, value } => format!("secret {name} {id} {kind} {}",
                                                            hex(value)),
                };
                out.push(line);
            }
        }
        Store::Java(_, entries) => {
            for named in entries {
                match &named.entry {
                    jks::Entry::PrivateKey { pkcs8, chain } => {
                        out.push(format!("key {} {}", named.alias, hex(pkcs8)));
                        for der in chain {
                            out.push(format!("chain {} {}", named.alias, hex(der)));
                        }
                    }
                    jks::Entry::Certificate(der) => {
                        out.push(format!("cert {} {}", named.alias, hex(der)))
                    }
                    jks::Entry::Secret { algorithm, key } => {
                        out.push(format!("secret {} {algorithm} {}", named.alias, hex(key)))
                    }
                }
            }
        }
    }
    out
}

fn sha256(data: &[u8]) -> String {
    let mut h = allcrypt::api::AnyHash::new("sha256").expect("built in");
    allcrypt::hash_functions::HashFunction::update(&mut h, data);
    hex(&allcrypt::hash_functions::HashFunction::digest(&mut h))
}

pub fn describe(store: &Store) -> Vec<String> {
    let mut out = Vec::new();
    match store {
        Store::Pkcs12(bags, report) => {
            out.push(format!("PKCS#12, MAC {}", report.mac.as_deref().unwrap_or("none")));
            for scheme in &report.schemes {
                out.push(format!("encrypted {scheme}"));
            }
            for bag in bags {
                let name = bag.friendly_name.as_deref().unwrap_or("-");
                let (what, data) = match &bag.kind {
                    Kind::Key { pkcs8, shrouded } => {
                        (if *shrouded { "private key (shrouded)" } else { "private key" }, pkcs8)
                    }
                    Kind::Certificate(der) => ("certificate", der),
                    Kind::Crl(der) => ("CRL", der),
                    Kind::Secret { value, .. } => ("secret", value),
                };
                out.push(format!("  {what:<22} {name:<16} sha256 {}", &sha256(data)[..16]));
            }
        }
        Store::Java(magic, entries) => {
            out.push(if *magic == jks::JKS_MAGIC { "JKS" } else { "JCEKS" }.to_string());
            for named in entries {
                let (what, detail) = match &named.entry {
                    jks::Entry::PrivateKey { pkcs8, chain } => {
                        ("private key", format!("sha256 {}, chain of {}",
                                                &sha256(pkcs8)[..16], chain.len()))
                    }
                    jks::Entry::Certificate(der) => {
                        ("trusted certificate", format!("sha256 {}", &sha256(der)[..16]))
                    }
                    jks::Entry::Secret { algorithm, key } => {
                        ("secret key", format!("{algorithm}, {} bits", key.len() * 8))
                    }
                };
                out.push(format!("  {what:<20} {:<16} {detail}", named.alias));
            }
        }
    }
    out
}

/// A store's entries as PKCS#12 bags.
fn to_bags(store: &Store) -> Result<Vec<Bag>, String> {
    match store {
        Store::Pkcs12(bags, _) => Ok(bags.clone()),
        Store::Java(_, entries) => {
            let mut out = Vec::new();
            for named in entries {
                match &named.entry {
                    jks::Entry::PrivateKey { pkcs8, chain } => {
                        // As keytool names them.
                        let id = format!("Time {}", named.date).into_bytes();
                        out.push(Bag { kind: Kind::Key { pkcs8: pkcs8.clone(), shrouded: true },
                                       friendly_name: Some(named.alias.clone()),
                                       local_key_id: Some(id.clone()),
                                       other_attributes: Vec::new() });
                        for (i, der) in chain.iter().enumerate() {
                            out.push(Bag {
                                kind: Kind::Certificate(der.clone()),
                                friendly_name: (i == 0).then(|| named.alias.clone()),
                                local_key_id: (i == 0).then(|| id.clone()),
                                other_attributes: Vec::new(),
                            });
                        }
                    }
                    jks::Entry::Certificate(der) => out.push(Bag {
                        kind: Kind::Certificate(der.clone()),
                        friendly_name: Some(named.alias.clone()), local_key_id: None,
                        other_attributes: vec![pkcs12::ORACLE_TRUSTED_KEY_USAGE.to_string()],
                    }),
                    jks::Entry::Secret { algorithm, key } => out.push(Bag {
                        kind: Kind::Secret {
                            kind: pkcs12::SHROUDED_KEY_BAG.to_string(),
                            value: pkcs12::secret_key_info(algorithm, key)
                                .map_err(|e| format!("{}: {e}", named.alias))?,
                        },
                        friendly_name: Some(named.alias.clone()),
                        local_key_id: Some(format!("Time {}", named.date).into_bytes()),
                        other_attributes: Vec::new(),
                    }),
                }
            }
            Ok(out)
        }
    }
}

/// A store's entries as Java entries: each key with the certificates
/// that share its local key ID, every other certificate trusted.
fn to_java(store: &Store) -> Result<Vec<jks::Named>, String> {
    match store {
        Store::Java(_, entries) => Ok(entries.clone()),
        Store::Pkcs12(bags, _) => {
            let mut out = Vec::new();
            let mut used = vec![false; bags.len()];
            for (i, bag) in bags.iter().enumerate() {
                let Kind::Key { pkcs8, .. } = &bag.kind else { continue };
                used[i] = true;
                let mut chain = Vec::new();
                for (j, other) in bags.iter().enumerate() {
                    if let Kind::Certificate(der) = &other.kind {
                        if other.local_key_id.is_some() && other.local_key_id == bag.local_key_id {
                            chain.push(der.clone());
                            used[j] = true;
                        }
                    }
                }
                let alias = bag.friendly_name.clone().unwrap_or_else(|| format!("key{i}"));
                out.push(jks::Named { alias, date: 0, entry: jks::Entry::PrivateKey {
                    pkcs8: pkcs8.clone(), chain } });
            }
            for (i, bag) in bags.iter().enumerate() {
                if used[i] {
                    continue;
                }
                match &bag.kind {
                    Kind::Certificate(der) => out.push(jks::Named {
                        alias: bag.friendly_name.clone().unwrap_or_else(|| format!("cert{i}")),
                        date: 0, entry: jks::Entry::Certificate(der.clone()) }),
                    Kind::Secret { kind, value } if kind == pkcs12::SHROUDED_KEY_BAG => {
                        let alias = bag.friendly_name.clone()
                            .unwrap_or_else(|| format!("secret{i}"));
                        let (algorithm, key) = pkcs12::read_secret_key_info(value)
                            .map_err(|e| format!("{alias}: {e}"))?;
                        out.push(jks::Named { alias, date: 0,
                                              entry: jks::Entry::Secret { algorithm, key } });
                    }
                    // Named by type only: the bag's contents are secret.
                    Kind::Secret { kind, .. } => {
                        return Err(format!("A secret bag of type {kind} has no Java \
                                            equivalent here."));
                    }
                    Kind::Crl(_) => return Err("A CRL has no Java equivalent here.".to_string()),
                    Kind::Key { .. } => {} // taken above, with their chains
                }
            }
            Ok(out)
        }
    }
}

fn positional(args: &[String]) -> Vec<&String> {
    cli::positional(args, &["--password-stdin", "--canonical"], &[])
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let input = names.first().ok_or("Name the input file.")?;
    let data = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    let password = if rest.iter().any(|a| a == "--password-stdin") {
        passphrase::read_line("Password: ")?
    } else {
        value(rest, "--password").ok_or("Give --password or --password-stdin.")?.as_bytes()
            .to_vec()
    };
    let key_password = value(rest, "--key-password").map(|p| p.as_bytes().to_vec())
        .unwrap_or_else(|| password.clone());
    let store = open(&data, &password, &key_password)?;
    match command {
        "list" => {
            let lines = if rest.iter().any(|a| a == "--canonical") {
                canonical(&store)
            } else {
                describe(&store)
            };
            for line in lines {
                println!("{line}");
            }
            Ok(())
        }
        "convert" => {
            let output = names.get(1).ok_or("Name the output file.")?;
            let out_password = value(rest, "--out-password").map(|p| p.as_bytes().to_vec())
                .unwrap_or_else(|| password.clone());
            let iterations: u32 = value(rest, "--iterations").unwrap_or("10000").parse()
                .map_err(|_| "--iterations is a number")?;
            let bytes = match value(rest, "--format").ok_or("Give --format.")? {
                "pkcs12" => {
                    let options = pkcs12::Options {
                        key_scheme: value(rest, "--key-scheme").unwrap_or("aes-256").to_string(),
                        cert_scheme: value(rest, "--cert-scheme").unwrap_or("aes-256").to_string(),
                        mac: value(rest, "--mac").unwrap_or("sha256").to_string(),
                        iterations,
                    };
                    pkcs12::write(&to_bags(&store)?, &out_password, &options)?
                }
                format @ ("jks" | "jceks") => {
                    let magic = if format == "jks" { jks::JKS_MAGIC } else { jks::JCEKS_MAGIC };
                    let mut entries = to_java(&store)?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    for named in entries.iter_mut().filter(|n| n.date == 0) {
                        named.date = now;
                    }
                    jks::write(magic, &entries, &out_password, &out_password, iterations)?
                }
                other => return Err(format!("Unknown format {other}: pkcs12, jks or jceks.")),
            };
            std::fs::write(output, bytes).map_err(|e| format!("{output}: {e}"))
        }
        _ => Err("usage: keystore list|convert ...".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("keystore: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{dir, field, records, unhex};

    type Opened = (String, Store, Vec<u8>, Vec<String>);

    /// Each recorded store, opened once for every test: its name, the
    /// store, its password and the entries the witness agreed it holds.
    /// NSS's MAC is 600,000 iterations, which a debug build takes
    /// seconds over.
    fn stores() -> &'static [Opened] {
        static STORES: std::sync::OnceLock<Vec<Opened>> = std::sync::OnceLock::new();
        STORES.get_or_init(open_all)
    }

    /// A record's password: hex, or "-" for the empty one.
    fn password(record: &[(String, String)]) -> Vec<u8> {
        match field(record, "password") {
            "-" => Vec::new(),
            hex => unhex(hex),
        }
    }

    fn open_all() -> Vec<Opened> {
        let records = records("keystore.vec", "store");
        assert_eq!(records.len(), 27);
        records.iter().map(|record| {
            let name = field(record, "name").to_string();
            let data = std::fs::read(dir().join("keystore").join(&name)).unwrap();
            let password = password(record);
            let store = open(&data, &password, &password)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let entries = record.iter().filter(|(k, _)| k == "entry")
                .map(|(_, v)| v.clone()).collect();
            (name, store, password, entries)
        }).collect()
    }

    /// The listing as the record has it: each entry's kind and the
    /// SHA-256 of its contents.
    fn summary(store: &Store) -> Vec<String> {
        canonical(store).iter().map(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            format!("{} {}", parts[0], sha256(&unhex(parts[parts.len() - 1])))
        }).collect()
    }

    /// Every store the witnesses wrote - OpenSSL 3.0 and 3.5, python-
    /// cryptography, NSS, keytool - and every one of ours they read,
    /// opens to the entries they agreed on.
    #[test]
    fn test_every_store_opens_to_the_recorded_entries() {
        for (name, store, _, entries) in stores() {
            assert_eq!(&summary(store), entries, "{name}");
        }
    }

    /// And refuses another password: by the MAC or the store digest
    /// where there is one, by the padding of the keys where there is not.
    /// NSS's store is left out for its cost; its MAC is checked the way
    /// every other store's is.
    #[test]
    fn test_a_wrong_password_is_refused() {
        for record in records("keystore.vec", "store") {
            let name = field(&record, "name");
            if name.starts_with("nss-") {
                continue;
            }
            let data = std::fs::read(dir().join("keystore").join(name)).unwrap();
            assert!(open(&data, b"store passwort", b"store passwort").is_err(), "{name}");
        }
    }

    /// A bag as everything but its encryption: what a round trip keeps.
    fn view(bag: &Bag) -> String {
        let kind = match &bag.kind {
            Kind::Key { pkcs8, .. } => format!("key {}", sha256(pkcs8)),
            Kind::Certificate(der) => format!("cert {}", sha256(der)),
            Kind::Crl(der) => format!("crl {}", sha256(der)),
            Kind::Secret { kind, value } => format!("secret {kind} {}", sha256(value)),
        };
        format!("{kind} {:?} {:?} {:?}", bag.friendly_name, bag.local_key_id,
                bag.other_attributes)
    }

    fn views(bags: &[Bag]) -> Vec<String> {
        let mut out: Vec<String> = bags.iter().map(view).collect();
        out.sort();
        out
    }

    /// A Java store's entries become the bags keytool itself writes for
    /// them: a key's certificate named and tied to it by a "Time ..."
    /// local key ID, a trusted certificate named and marked with Oracle's
    /// trusted-key-usage attribute, a secret key named and identified
    /// like a key. keytool's JKS and JCEKS against its own PKCS#12 of
    /// the same entries - the IDs carry each store's own timestamps, so
    /// those are compared by shape, and its secret keys by their place.
    #[test]
    fn test_java_entries_become_the_bags_java_writes() {
        let shape = |bags: Vec<Bag>| {
            views(&bags.into_iter().map(|mut bag| {
                if let Some(id) = &bag.local_key_id {
                    let digits = id.strip_prefix(b"Time ").expect("a Time ID");
                    assert!(digits.iter().all(u8::is_ascii_digit));
                    bag.local_key_id = Some(b"Time".to_vec());
                }
                // keytool generated each store's secret key afresh.
                if let Kind::Secret { value, .. } = &mut bag.kind {
                    value.clear();
                }
                bag
            }).collect::<Vec<_>>())
        };
        let find = |name: &str| &stores().iter().find(|s| s.0 == name).unwrap().1;
        let Store::Pkcs12(keytool_bags, _) = find("keytool-pkcs12.pkcs12") else { panic!() };
        let keytool = shape(keytool_bags.clone());
        assert_eq!(shape(to_bags(find("keytool-jceks.jceks")).unwrap()), keytool);
        let without_secret: Vec<String> = keytool.iter().filter(|v| !v.starts_with("secret"))
            .cloned().collect();
        assert_eq!(shape(to_bags(find("keytool-jks.jks")).unwrap()), without_secret);
    }

    /// Every store converts to PKCS#12 under each scheme - and to JCEKS,
    /// and to JKS where it has no secret key - and reads back to the same
    /// entries.
    #[test]
    fn test_every_store_converts_and_reads_back() {
        let sorted = |store: &Store| {
            let mut lines = canonical(store);
            lines.sort();
            lines
        };
        for (name, store, _, _) in stores() {
            let bags = to_bags(store).unwrap();
            // Ours writes the keys' safe first, so the order may change.
            let original = views(&bags);
            for (key_scheme, cert_scheme, mac) in [("aes-256", "aes-256", "sha256"),
                                                   ("3des", "rc2-40", "sha1"),
                                                   ("aes-256", "none", "pbmac1"),
                                                   ("3des", "3des", "none")] {
                let options = pkcs12::Options { key_scheme: key_scheme.to_string(),
                                                cert_scheme: cert_scheme.to_string(),
                                                mac: mac.to_string(), iterations: 3 };
                let written = pkcs12::write(&bags, "pässword".as_bytes(), &options).unwrap();
                let Store::Pkcs12(back, _) = open(&written, "pässword".as_bytes(), b"").unwrap()
                else { panic!() };
                assert!(views(&back) == original, "{name} {key_scheme} {cert_scheme} {mac}");
            }
            let java = to_java(store).unwrap();
            let has_secret = java.iter().any(|n| matches!(n.entry, jks::Entry::Secret { .. }));
            let expected = sorted(&Store::Java(0, java.clone()));
            for magic in [jks::JCEKS_MAGIC, jks::JKS_MAGIC] {
                let written = jks::write(magic, &java, b"store", b"key", 3);
                if magic == jks::JKS_MAGIC && has_secret {
                    assert!(written.is_err(), "{name}: JKS has no secret keys");
                    continue;
                }
                let back = open(&written.unwrap(), b"store", b"key").unwrap();
                assert!(sorted(&back) == expected, "{name} {magic:#x}");
                assert!(open(&jks::write(magic, &java, b"store", b"key", 3).unwrap(),
                             b"store", b"other").is_err() || java.iter().all(
                             |n| matches!(n.entry, jks::Entry::Certificate(_))),
                        "{name}: the key password is the keys'");
            }
        }
    }
}
