//! Cryptocurrency wallets: BIP-39 mnemonics, BIP-32 key derivation,
//! Bitcoin's keys, addresses and signed messages, BIP-38 encrypted keys,
//! and Ethereum's keystore files, addresses and signed messages - over
//! secp256k1, SHA-256, RIPEMD-160, Keccak-256, HMAC-SHA512, PBKDF2,
//! scrypt and AES from this library.
//!
//!     cargo run --release --example wallet -- mnemonic new [--words 24]
//!     cargo run --release --example wallet -- mnemonic from-entropy HEX
//!     cargo run --release --example wallet -- mnemonic check "WORDS"
//!     cargo run --release --example wallet -- mnemonic seed "WORDS" [--passphrase P]
//!             [--unchecked]
//!     cargo run --release --example wallet -- derive (--mnemonic "WORDS" | --seed HEX | --key XPRV)
//!             [--path m/84'/0'/0'/0/0] [--version zprv] [--passphrase P]
//!     cargo run --release --example wallet -- address (--wif WIF | --pubkey HEX) [--testnet]
//!     cargo run --release --example wallet -- check-address ADDRESS
//!     cargo run --release --example wallet -- sign-message WIF MESSAGE [--kind p2wpkh]
//!     cargo run --release --example wallet -- verify-message ADDRESS SIGNATURE MESSAGE
//!     cargo run --release --example wallet -- bip38 encrypt WIF [--password P]
//!     cargo run --release --example wallet -- bip38 decrypt 6P... [--password P]
//!     cargo run --release --example wallet -- bip38 intermediate [--lot N --sequence N]
//!     cargo run --release --example wallet -- bip38 generate passphrase... [--compressed]
//!     cargo run --release --example wallet -- bip38 confirm cfrm38... [--password P]
//!     cargo run --release --example wallet -- eth address (--key HEX | --pubkey HEX)
//!     cargo run --release --example wallet -- eth keystore-decrypt FILE [--password P]
//!     cargo run --release --example wallet -- eth keystore-encrypt OUT --key HEX
//!             [--kdf scrypt|pbkdf2] [--n N --r R --p P | --iterations C] [--password P]
//!     cargo run --release --example wallet -- eth sign-message --key HEX MESSAGE
//!     cargo run --release --example wallet -- eth recover SIGNATURE MESSAGE
//!
//! Passwords and passphrases are `--password`/`--passphrase` or
//! `--password-stdin`/`--passphrase-stdin`. BIP-39 hashes its mnemonic and
//! passphrase in Unicode NFKD and BIP-38 its passphrase in NFC, and both
//! are normalized here (`unicode.rs`, from Unicode 16.0's tables); an
//! Ethereum keystore's password is used as given, as geth uses it.
//!
//! Only the English word list is here, so `mnemonic seed` refuses words
//! outside it unless `--unchecked`: BIP-39 makes a seed from any
//! mnemonic text, and that is how one in another language's list is
//! hashed.
//!
//! What has checked it is in `examples/products/README.md`.

mod bip32;
mod bip38;
mod bip39;
mod bitcoin;
mod encoding;
mod ethereum;
mod hash;
mod keys;
// All four normalization forms, which the conformance test checks
// together, and the tables' Unicode version, which it checks the test
// file against; the wallet itself uses NFC and NFKD.
#[allow(dead_code)]
mod unicode;
#[allow(dead_code)]
mod unicode_tables;

#[path = "../shared/base64.rs"]
mod base64;
#[path = "../shared/json.rs"]
mod json;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/inflate.rs"]
#[cfg(test)]
mod inflate;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use allcrypt::api;

use bip32::ExtendedKey;
use bitcoin::{AddressKind, Network};

// ----------------------------------------------------------------- arguments --

const SWITCHES: [&str; 6] = ["--password-stdin", "--passphrase-stdin",
                             "--testnet", "--compressed", "--uncompressed", "--unchecked"];

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

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn number<T: std::str::FromStr>(args: &[String], name: &str) -> Result<Option<T>, String> {
    value(args, name).map(|v| v.parse().map_err(|_| format!("{name}: not a number: {v}")))
        .transpose()
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.len().is_multiple_of(2) || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Not hex: {text}"));
    }
    Ok((0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0)).collect())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A password or passphrase: `--NAME P`, `--NAME-stdin`, or (when
/// `required` is false) empty. Normalizing it is the format's business.
fn secret(args: &[String], name: &str, required: bool) -> Result<String, String> {
    let text = if has(args, &format!("--{name}-stdin")) {
        String::from_utf8(passphrase::read_line(&format!("{}: ", capitalize(name)))?)
            .map_err(|_| format!("The {name} is not UTF-8."))?
    } else {
        match value(args, &format!("--{name}")) {
            Some(p) => p.to_string(),
            None if required => return Err(format!("Give --{name} or --{name}-stdin.")),
            None => String::new(),
        }
    };
    Ok(text)
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
}

// ------------------------------------------------------------------ commands --

fn mnemonic(args: &[String]) -> Result<String, String> {
    let names = positional(args);
    Ok(match names.first().map(|s| s.as_str()) {
        Some("new") => {
            let words: usize = number(args, "--words")?.unwrap_or(24);
            if !(12..=24).contains(&words) || !words.is_multiple_of(3) {
                return Err("--words is 12, 15, 18, 21 or 24.".to_string());
            }
            bip39::to_mnemonic(&api::random_bytes(words * 4 / 3)?)? + "\n"
        }
        Some("from-entropy") => bip39::to_mnemonic(&unhex(names.get(1)
            .ok_or("Give the entropy in hex.")?)?)? + "\n",
        Some("check") => {
            let entropy = bip39::to_entropy(names.get(1).ok_or("Give the words.")?)?;
            format!("valid; entropy {}\n", hex(&entropy))
        }
        Some("seed") => {
            let words = names.get(1).ok_or("Give the words.")?;
            let passphrase = secret(args, "passphrase", false)?;
            hex(&bip39::to_seed(words, &passphrase, !has(args, "--unchecked"))?) + "\n"
        }
        _ => return Err("mnemonic new, from-entropy, check or seed.".to_string()),
    })
}

/// Everything about one key: the extended keys and the private key, the
/// public key, and its addresses of every kind.
fn describe(key: &ExtendedKey, path: &str) -> Result<String, String> {
    let network = Network { testnet: key.version.testnet };
    let mut out = format!("path: {path}\n");
    if key.private_key().is_some() {
        out.push_str(&format!("{}: {}\n", key.version.private_name, key.serialize()));
    }
    out.push_str(&format!("{}: {}\n", key.version.public_name, key.neuter().serialize()));
    let point = key.public_point();
    if let Some(k) = key.private_key() {
        out.push_str(&format!("private key: {}\n", hex(&keys::private_bytes(k))));
        out.push_str(&format!("WIF: {}\n", bitcoin::wif_encode(k, true, network)));
    }
    let compressed = keys::ser_p(&point);
    out.push_str(&format!("public key: {}\n", hex(&compressed)));
    out.push_str(&format!("P2PKH: {}\n", bitcoin::p2pkh(&compressed, network)));
    out.push_str(&format!("P2SH-P2WPKH: {}\n", bitcoin::p2sh_p2wpkh(&compressed, network)));
    out.push_str(&format!("P2WPKH: {}\n", bitcoin::p2wpkh(&compressed, network)));
    out.push_str(&format!("P2TR: {}\n", bitcoin::p2tr(&point, network)?));
    out.push_str(&format!("Ethereum: {}\n", ethereum::checksummed(&ethereum::address(&point))));
    Ok(out)
}

fn derive(args: &[String]) -> Result<String, String> {
    let version = bip32::version_named(value(args, "--version").unwrap_or("xprv"))?;
    let root = if let Some(text) = value(args, "--key") {
        ExtendedKey::parse(text)?
    } else {
        let seed = match (value(args, "--mnemonic"), value(args, "--seed")) {
            (Some(words), None) => bip39::to_seed(words, &secret(args, "passphrase", false)?,
                                                  true)?,
            (None, Some(seed)) => unhex(seed)?,
            _ => return Err("Give one of --mnemonic, --seed or --key.".to_string()),
        };
        ExtendedKey::master(&seed, version)?
    };
    let path = bip32::parse_path(value(args, "--path").unwrap_or("m"))?;
    describe(&root.derive(&path)?, &bip32::path_text(&path))
}

fn address(args: &[String]) -> Result<String, String> {
    let (point, compressed, network) = if let Some(wif) = value(args, "--wif") {
        let (k, compressed, network) = bitcoin::wif_decode(wif)?;
        (keys::public_key(&k), compressed, network)
    } else if let Some(public) = value(args, "--pubkey") {
        let bytes = unhex(public)?;
        (keys::curve().decode_point(&bytes)?, bytes.len() == 33,
         Network { testnet: has(args, "--testnet") })
    } else {
        return Err("Give --wif or --pubkey.".to_string());
    };
    let public = bitcoin::public_bytes(&point, compressed);
    let mut out = format!("P2PKH: {}\n", bitcoin::p2pkh(&public, network));
    if compressed {
        out.push_str(&format!("P2SH-P2WPKH: {}\n", bitcoin::p2sh_p2wpkh(&public, network)));
        out.push_str(&format!("P2WPKH: {}\n", bitcoin::p2wpkh(&public, network)));
        out.push_str(&format!("P2TR: {}\n", bitcoin::p2tr(&point, network)?));
    }
    Ok(out)
}

fn kind_named(name: &str) -> Result<AddressKind, String> {
    Ok(match name {
        "p2pkh" => AddressKind::P2pkh,
        "p2sh-p2wpkh" => AddressKind::P2shP2wpkh,
        "p2wpkh" => AddressKind::P2wpkh,
        other => return Err(format!("--kind {other}: p2pkh, p2sh-p2wpkh or p2wpkh.")),
    })
}

fn bip38_command(args: &[String]) -> Result<String, String> {
    let names = positional(args);
    let arg = |i: usize, what: &str| names.get(i).map(|s| s.as_str())
        .ok_or_else(|| format!("Give the {what}."));
    let password = || secret(args, "password", true).map(|p| bip38::passphrase(&p));
    Ok(match arg(0, "bip38 command")? {
        "encrypt" => {
            let (k, compressed, _) = bitcoin::wif_decode(arg(1, "WIF key")?)?;
            bip38::encrypt(&k, compressed, &password()?)? + "\n"
        }
        "decrypt" => {
            let d = bip38::decrypt(arg(1, "encrypted key")?, &password()?)?;
            let mut out = format!("WIF: {}\naddress: {}\n",
                                  bitcoin::wif_encode(&d.key, d.compressed,
                                                      Network { testnet: false }), d.address);
            if let Some((lot, sequence)) = d.lot_sequence {
                out.push_str(&format!("lot {lot}, sequence {sequence}\n"));
            }
            out
        }
        "intermediate" => {
            let lot = match (number::<u32>(args, "--lot")?, number::<u32>(args, "--sequence")?) {
                (Some(l), Some(s)) => Some((l, s)),
                (None, None) => None,
                _ => return Err("--lot and --sequence go together.".to_string()),
            };
            bip38::intermediate(&password()?, lot, None)? + "\n"
        }
        "generate" => {
            let (key, address, cfrm) = bip38::generate(arg(1, "intermediate code")?,
                                                       has(args, "--compressed"), None)?;
            format!("encrypted key: {key}\naddress: {address}\nconfirmation: {cfrm}\n")
        }
        "confirm" => {
            let (address, lot) = bip38::confirm(arg(1, "confirmation code")?, &password()?)?;
            let mut out = format!("confirmed: {address} depends on this passphrase\n");
            if let Some((lot, sequence)) = lot {
                out.push_str(&format!("lot {lot}, sequence {sequence}\n"));
            }
            out
        }
        other => return Err(format!("No bip38 command {other}.")),
    })
}

fn eth_command(args: &[String]) -> Result<String, String> {
    let names = positional(args);
    let arg = |i: usize, what: &str| names.get(i).map(|s| s.as_str())
        .ok_or_else(|| format!("Give the {what}."));
    let key = || -> Result<_, String> {
        keys::private_from_bytes(&unhex(value(args, "--key").ok_or("Give --key.")?)?)
    };
    Ok(match arg(0, "eth command")? {
        "address" => {
            let point = match value(args, "--pubkey") {
                Some(p) => keys::curve().decode_point(&unhex(p)?)?,
                None => keys::public_key(&key()?),
            };
            ethereum::checksummed(&ethereum::address(&point)) + "\n"
        }
        "keystore-decrypt" => {
            let path = arg(1, "keystore file")?;
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let account = ethereum::decrypt_keystore(&text,
                                                     secret(args, "password", true)?.as_bytes())?;
            format!("{} ({})\nprivate key: {}\n", ethereum::checksummed(&account.address),
                    account.format, hex(&keys::private_bytes(&account.key)))
        }
        "keystore-encrypt" => {
            let path = arg(1, "output file")?;
            let kdf = match value(args, "--kdf").unwrap_or("scrypt") {
                "scrypt" => ethereum::Kdf::Scrypt {
                    n: number(args, "--n")?.unwrap_or(262_144),
                    r: number(args, "--r")?.unwrap_or(8),
                    p: number(args, "--p")?.unwrap_or(1),
                },
                "pbkdf2" => ethereum::Kdf::Pbkdf2 {
                    iterations: number(args, "--iterations")?.unwrap_or(262_144),
                },
                other => return Err(format!("--kdf {other}: scrypt or pbkdf2.")),
            };
            let text = ethereum::encrypt_keystore(&key()?,
                                                  secret(args, "password", true)?.as_bytes(),
                                                  &kdf, None)?;
            std::fs::write(path, text + "\n").map_err(|e| format!("{path}: {e}"))?;
            String::new()
        }
        "sign-message" => {
            hex(&ethereum::sign_message(&key()?, arg(1, "message")?.as_bytes())?) + "\n"
        }
        "recover" => {
            let signer = ethereum::recover_signer(&unhex(arg(1, "signature")?)?,
                                                  arg(2, "message")?.as_bytes())?;
            ethereum::checksummed(&signer) + "\n"
        }
        other => return Err(format!("No eth command {other}.")),
    })
}

fn run(args: &[String]) -> Result<String, String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let arg = |i: usize, what: &str| names.get(i).map(|s| s.as_str())
        .ok_or_else(|| format!("Give the {what}."));
    match command {
        "mnemonic" => mnemonic(rest),
        "derive" => derive(rest),
        "address" => address(rest),
        "check-address" => Ok(bitcoin::check_address(arg(0, "address")?)? + "\n"),
        "sign-message" => {
            let (k, compressed, _) = bitcoin::wif_decode(arg(0, "WIF key")?)?;
            let kind = match value(rest, "--kind") {
                Some(name) => kind_named(name)?,
                None if compressed => AddressKind::P2pkh,
                None => AddressKind::P2pkhUncompressed,
            };
            if !compressed && kind != AddressKind::P2pkhUncompressed {
                return Err("A segwit address needs a compressed key.".to_string());
            }
            let signature = bitcoin::sign_message(&k, kind, arg(1, "message")?.as_bytes())?;
            Ok(base64::encode(&signature) + "\n")
        }
        "verify-message" => {
            let signature = base64::decode(arg(1, "signature")?)
                .ok_or("The signature is not base64.")?;
            bitcoin::verify_message(arg(0, "address")?, &signature, arg(2, "message")?.as_bytes())?;
            Ok("good\n".to_string())
        }
        "bip38" => bip38_command(rest),
        "eth" => eth_command(rest),
        "" => Err("Name a command: mnemonic, derive, address, check-address, sign-message, \
                   verify-message, bip38 or eth.".to_string()),
        other => Err(format!("No command {other}.")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => print!("{out}"),
        Err(error) => {
            eprintln!("wallet: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::{field, records};

    const BIP32: &str = include_str!("../../../rfcs/bip-0032.mediawiki");
    const BIP38: &str = include_str!("../../../rfcs/bip-0038.mediawiki");
    const BIP49: &str = include_str!("../../../rfcs/bip-0049.mediawiki");
    const BIP84: &str = include_str!("../../../rfcs/bip-0084.mediawiki");
    const BIP86: &str = include_str!("../../../rfcs/bip-0086.mediawiki");
    const BIP350: &str = include_str!("../../../rfcs/bip-0350.mediawiki");
    const ERC55: &str = include_str!("../../../rfcs/erc-55.md");

    fn run_text(args: &[&str]) -> Result<String, String> {
        run(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(fixtures::dir().join("wallet").join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    /// The text between two markers in a document.
    fn between<'a>(doc: &'a str, start: &str, end: &str) -> &'a str {
        let from = doc.find(start).unwrap_or_else(|| panic!("no {start}"));
        let rest = &doc[from..];
        &rest[..rest.find(end).unwrap_or(rest.len())]
    }

    fn mainnet() -> Network {
        Network { testnet: false }
    }

    // ------------------------------------------------------------ BIP-32 --

    /// BIP-32's vectors 1 to 4: a seed, then chains whose extended keys
    /// are printed. The chain is written `m/0<sub>H</sub>/1`.
    #[test]
    fn bip32_test_vectors() {
        let text = between(BIP32, "==Test Vectors==", "===Test vector 5===");
        let (mut seed, mut key, mut found) = (Vec::new(), None::<ExtendedKey>, 0);
        for line in text.lines() {
            if let Some(hex_seed) = line.strip_prefix("Seed (hex): ") {
                seed = unhex(hex_seed.trim()).unwrap();
            } else if let Some(chain) = line.strip_prefix("* Chain ") {
                let path = bip32::parse_path(&chain.replace("<sub>H</sub>", "'")).unwrap();
                let master = ExtendedKey::master(&seed, bip32::VERSIONS[0]).unwrap();
                key = Some(master.derive(&path).unwrap());
            } else if let Some(xpub) = line.strip_prefix("** ext pub: ") {
                assert_eq!(key.as_ref().unwrap().neuter().serialize(), xpub.trim());
                found += 1;
            } else if let Some(xprv) = line.strip_prefix("** ext prv: ") {
                let k = key.as_ref().unwrap();
                assert_eq!(k.serialize(), xprv.trim());
                // And it reads back to the same key.
                assert_eq!(ExtendedKey::parse(xprv.trim()).unwrap().serialize(), xprv.trim());
                found += 1;
            }
        }
        assert_eq!(found, 2 * (6 + 6 + 2 + 3));
    }

    #[test]
    fn bip32_public_derivation_matches_private() {
        let text = between(BIP32, "===Test vector 1===", "===Test vector 2===");
        let seed = unhex(text.lines().find_map(|l| l.strip_prefix("Seed (hex): ")).unwrap())
            .unwrap();
        let master = ExtendedKey::master(&seed, bip32::VERSIONS[0]).unwrap();
        let parent = master.derive(&bip32::parse_path("m/0'/1/2'").unwrap()).unwrap();
        let via_public = parent.neuter().derive(&[2, 1_000_000_000]).unwrap();
        let via_private = parent.derive(&[2, 1_000_000_000]).unwrap().neuter();
        assert_eq!(via_public.serialize(), via_private.serialize());
        assert!(parent.neuter().child(bip32::HARDENED).unwrap_err().contains("hardened"));
    }

    /// Vector 5: every key there is invalid, each for its stated reason.
    #[test]
    fn bip32_invalid_keys_are_refused() {
        let text = between(BIP32, "===Test vector 5===", "==Acknowledgements==");
        // Each stated reason, and what ours says for it.
        let reasons = [("pubkey version / prvkey mismatch", "holding a private key"),
                       ("prvkey version / pubkey mismatch", "not a private key"),
                       ("invalid pubkey prefix 04", "prefix 04"),
                       ("invalid prvkey prefix 04", "not a private key"),
                       ("invalid pubkey prefix 01", "prefix 01"),
                       ("invalid prvkey prefix 01", "not a private key"),
                       ("non-zero parent fingerprint", "parent fingerprint"),
                       ("non-zero index", "child number"),
                       ("unknown extended key version", "Unknown extended key version"),
                       ("private key 0 not in 1..n-1", "not in [1, n)"),
                       ("private key n not in 1..n-1", "not in [1, n)"),
                       ("invalid pubkey 02", "not a point"),
                       ("invalid checksum", "checksum")];
        let mut found = 0;
        for line in text.lines().filter(|l| l.starts_with("* ")) {
            let key = line[2..].split_whitespace().next().unwrap();
            let error = ExtendedKey::parse(key).unwrap_err();
            let (_, expected) = reasons.iter().find(|(r, _)| line.contains(r))
                .unwrap_or_else(|| panic!("no reason for {line}"));
            assert!(error.contains(expected), "{line}: {error}");
            found += 1;
        }
        assert_eq!(found, 16);
    }

    #[test]
    fn paths_parse() {
        assert_eq!(bip32::parse_path("m/44'/0h/1H/2").unwrap(),
                   [44 | bip32::HARDENED, bip32::HARDENED, 1 | bip32::HARDENED, 2]);
        assert_eq!(bip32::parse_path("m").unwrap(), Vec::<u32>::new());
        for bad in ["44'/0", "m/-1", "m/2147483648", "m//1", "m/1''"] {
            assert!(bip32::parse_path(bad).is_err(), "{bad}");
        }
        assert_eq!(bip32::path_text(&bip32::parse_path("m/84h/0H/0'/1").unwrap()),
                   "m/84'/0'/0'/1");
    }

    // -------------------------------------------- BIP-39, -49, -84, -86 --

    #[test]
    fn the_english_word_list_is_bip39s() {
        let words = bip39::wordlist();
        assert_eq!(words.len(), 2048);
        assert!(words.windows(2).all(|w| w[0] < w[1]), "sorted, for the binary search");
        assert_eq!(hash::sha256(words.join("\n").as_bytes()).len(), 32);
    }

    /// python-mnemonic's vectors: entropy, mnemonic, the seed under the
    /// passphrase "TREZOR", and the BIP-32 master key of that seed.
    #[test]
    fn trezor_vectors() {
        let json = json::parse(&fixture("trezor-vectors.json")).unwrap();
        let Some(json::Json::Array(english)) = json.get("english") else { panic!("english") };
        assert_eq!(english.len(), 24);
        for v in english {
            let json::Json::Array(items) = v else { panic!("a vector") };
            let s: Vec<&str> = items.iter().map(|i| i.as_str().unwrap()).collect();
            let entropy = unhex(s[0]).unwrap();
            assert_eq!(bip39::to_mnemonic(&entropy).unwrap(), s[1]);
            assert_eq!(bip39::to_entropy(s[1]).unwrap(), entropy);
            let seed = bip39::to_seed(s[1], "TREZOR", true).unwrap();
            assert_eq!(hex(&seed), s[2]);
            assert_eq!(ExtendedKey::master(&seed, bip32::VERSIONS[0]).unwrap().serialize(),
                       s[3]);
        }
    }

    #[test]
    fn a_wrong_word_or_count_is_refused() {
        let good = bip39::to_mnemonic(&[7; 16]).unwrap();
        let mut words: Vec<&str> = good.split(' ').collect();
        words.swap(0, 1);
        assert!(bip39::to_entropy(&words.join(" ")).unwrap_err().contains("checksum"));
        assert!(bip39::to_entropy(&good.replacen("abandon", "abandons", 1)).is_err()
                || !good.contains("abandon"));
        assert!(bip39::to_entropy("abandon abandon abandon").unwrap_err().contains("12"));
        assert!(bip39::to_entropy(&format!("{good} zoo")).is_err());
        assert!(bip39::to_mnemonic(&[0; 17]).is_err());
        // An unknown word is named.
        let bad = good.replacen(words[0], "xylophone", 1);
        assert!(bip39::to_entropy(&bad).unwrap_err().contains("xylophone"));
        // A passphrase is NFKD-normalized: a precomposed é and e with a
        // combining acute are one passphrase, and one wallet.
        let seed = |passphrase: &str| {
            run_text(&["mnemonic", "seed", good.as_str(), "--passphrase", passphrase]).unwrap()
        };
        assert_eq!(seed("caf\u{e9}"), seed("cafe\u{301}"));
        assert_ne!(seed("caf\u{e9}"), seed("cafe"));
        // And the mnemonic: in full-width letters it is the same words,
        // which NFKD tells apart from NFD.
        let wide: String = good.chars()
            .map(|c| if c == ' ' { c } else { char::from_u32(c as u32 - 0x41 + 0xff21).unwrap() })
            .collect();
        assert_eq!(bip39::to_seed(&wide, "", false).unwrap(),
                   bip39::to_seed(&good, "", false).unwrap());
    }

    /// The `key = value` lines of a BIP's `<pre>` vectors.
    fn assignments(doc: &str) -> Vec<(String, String)> {
        between(doc, "==Test vectors==", "</pre>").lines()
            .filter_map(|l| l.split_once(" = ").or_else(|| l.split_once("= ")))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect()
    }

    fn mnemonic_root(doc: &str, version: &str) -> ExtendedKey {
        let a = assignments(doc);
        let words = &a.iter().find(|(k, _)| k.contains("mnemonic") || k == "masterseedWords")
            .unwrap().1;
        ExtendedKey::master(&bip39::to_seed(words, "", true).unwrap(),
                            bip32::version_named(version).unwrap()).unwrap()
    }

    #[test]
    fn bip84_vectors() {
        let root = mnemonic_root(BIP84, "zprv");
        let a = assignments(BIP84);
        let value = |name: &str, n: usize| a.iter().filter(|(k, _)| k == name).nth(n)
            .unwrap().1.clone();
        assert_eq!(root.serialize(), value("rootpriv", 0));
        assert_eq!(root.neuter().serialize(), value("rootpub", 0));
        let account = root.derive(&bip32::parse_path("m/84'/0'/0'").unwrap()).unwrap();
        assert_eq!(account.serialize(), value("xpriv", 0));
        assert_eq!(account.neuter().serialize(), value("xpub", 0));
        for (n, path) in ["m/84'/0'/0'/0/0", "m/84'/0'/0'/0/1", "m/84'/0'/0'/1/0"]
            .iter().enumerate() {
            let key = root.derive(&bip32::parse_path(path).unwrap()).unwrap();
            let k = key.private_key().unwrap();
            assert_eq!(bitcoin::wif_encode(k, true, mainnet()), value("privkey", n));
            let public = keys::ser_p(&key.public_point());
            assert_eq!(hex(&public), value("pubkey", n));
            assert_eq!(bitcoin::p2wpkh(&public, mainnet()), value("address", n));
        }
    }

    #[test]
    fn bip49_vectors() {
        let root = mnemonic_root(BIP49, "uprv");
        let a = assignments(BIP49);
        let value = |name: &str| a.iter().find(|(k, _)| k == name).unwrap().1
            .trim_end_matches(" (testnet)").to_string();
        assert_eq!(root.serialize(), value("masterseed"));
        let account = root.derive(&bip32::parse_path("m/49'/1'/0'").unwrap()).unwrap();
        assert_eq!(account.serialize(), value("account0Xpriv"));
        assert_eq!(account.neuter().serialize(), value("account0Xpub"));
        let key = account.derive(&[0, 0]).unwrap();
        let testnet = Network { testnet: true };
        assert_eq!(bitcoin::wif_encode(key.private_key().unwrap(), true, testnet),
                   value("account0recvPrivateKey"));
        let public = keys::ser_p(&key.public_point());
        assert_eq!(format!("0x{}", hex(&public)), value("account0recvPublicKeyHex"));
        let address = a.iter().find(|(k, _)| k == "address").unwrap().1.clone();
        assert!(address.ends_with(&format!("= {} (testnet)",
                                           bitcoin::p2sh_p2wpkh(&public, testnet))),
                "{address}");
    }

    #[test]
    fn bip86_taproot_vectors() {
        let root = mnemonic_root(BIP86, "xprv");
        let a = assignments(BIP86);
        let value = |name: &str, n: usize| a.iter().filter(|(k, _)| k == name).nth(n)
            .unwrap().1.clone();
        assert_eq!(root.serialize(), value("rootpriv", 0));
        for (n, path) in ["m/86'/0'/0'/0/0", "m/86'/0'/0'/0/1", "m/86'/0'/0'/1/0"]
            .iter().enumerate() {
            let key = root.derive(&bip32::parse_path(path).unwrap()).unwrap();
            assert_eq!(key.serialize(), value("xprv", n + 1));
            let point = key.public_point();
            assert_eq!(hex(&keys::ser_p(&point)[1..]), value("internal_key", n));
            assert_eq!(hex(&bitcoin::taproot_output_key(&point).unwrap()),
                       value("output_key", n));
            assert_eq!(bitcoin::p2tr(&point, mainnet()).unwrap(), value("address", n));
        }
    }

    // ------------------------------------------------------- addresses --

    /// BIP-350's segwit vectors, which supersede BIP-173's for versions
    /// above 0: each valid address decodes to its scriptPubKey and
    /// encodes back, and each invalid one is refused.
    #[test]
    fn bip350_segwit_addresses() {
        let text = between(BIP350, "===Test vectors for v0-v16", "==Appendix");
        let (valid, invalid) = text.split_once("invalid segwit addresses").unwrap();
        let tt = |line: &str| line.split("<tt>").nth(1).and_then(|r| r.split("</tt>").next())
            .map(str::to_string);
        let mut found = 0;
        for line in valid.lines().filter(|l| l.starts_with("* ")) {
            let address = tt(line).unwrap();
            let script = line.split("<tt>").nth(2).unwrap().split("</tt>").next().unwrap();
            let hrp = &address.to_ascii_lowercase()[..2];
            let (version, program) = encoding::segwit_decode(hrp, &address).unwrap();
            let mut spk = vec![if version == 0 { 0 } else { 0x50 + version },
                               program.len() as u8];
            spk.extend_from_slice(&program);
            assert_eq!(hex(&spk), script);
            assert_eq!(encoding::segwit_encode(hrp, version, &program).unwrap(),
                       address.to_ascii_lowercase());
            found += 1;
        }
        for line in invalid.lines().filter(|l| l.starts_with("* ")) {
            let address = tt(line).unwrap();
            for hrp in ["bc", "tb"] {
                assert!(encoding::segwit_decode(hrp, &address).is_err(), "{line}");
            }
            found += 1;
        }
        assert_eq!(found, 8 + 15);
    }

    #[test]
    fn base58_round_trips_and_keeps_leading_zeros() {
        for data in [vec![], vec![0], vec![0, 0, 1], vec![0xff; 40], (0..=255).collect()] {
            assert_eq!(encoding::base58_decode(&encoding::base58_encode(&data)).unwrap(), data);
        }
        assert_eq!(encoding::base58_encode(&[0, 0, 0x28, 0x7f, 0xb4, 0xcd]), "11233QC4");
        assert!(encoding::base58_decode("0OIl").is_err());
        let address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        assert!(encoding::base58check_decode(address).is_ok());
        assert!(encoding::base58check_decode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3").is_err());
        assert_eq!(bitcoin::check_address(address).unwrap(), "P2PKH (mainnet)");
    }

    /// ERC-55's test cases: each is its own checksummed form, and a
    /// changed case is refused.
    #[test]
    fn erc55_checksums() {
        let cases: Vec<&str> = between(ERC55, "# Test Cases", "# Copyright").lines()
            .filter(|l| l.starts_with("0x")).collect();
        assert_eq!(cases.len(), 8);
        for case in cases {
            let bytes = ethereum::parse_address(case).unwrap();
            assert_eq!(ethereum::checksummed(&bytes), case);
            let flipped: String = case.char_indices().map(|(i, c)| {
                if i == case.rfind(|c: char| c.is_ascii_alphabetic() && c != 'x').unwrap() {
                    if c.is_ascii_uppercase() { c.to_ascii_lowercase() }
                    else { c.to_ascii_uppercase() }
                } else { c }
            }).collect();
            let all_one_case = flipped[2..].chars().all(|c| !c.is_ascii_lowercase())
                || flipped[2..].chars().all(|c| !c.is_ascii_uppercase());
            assert_eq!(ethereum::parse_address(&flipped).is_err(), !all_one_case, "{flipped}");
        }
    }

    // ------------------------------------------------------------ BIP-38 --

    /// A vector's passphrase, as BIP-38 hashes it, and its
    /// `*Name: value` lines.
    type Bip38Vector = (Vec<u8>, Vec<(String, String)>);

    /// The text between `<tt>` and `</tt>` in a line of the document.
    fn teletype(line: &str) -> &str {
        let start = line.find("<tt>").unwrap() + 4;
        &line[start..start + line[start..].find("</tt>").unwrap()]
    }

    /// `\uXXXX` and `\UXXXXXXXX` escapes, as test 3 writes its
    /// passphrase.
    fn unescape(escaped: &str) -> String {
        let mut out = String::new();
        let mut rest = escaped;
        while !rest.is_empty() {
            let width = match &rest[..2] { "\\u" => 4, "\\U" => 8, other => panic!("{other}") };
            let code = u32::from_str_radix(&rest[2..2 + width], 16).unwrap();
            out.push(char::from_u32(code).unwrap());
            rest = &rest[2 + width..];
        }
        out
    }

    /// BIP-38's test vectors: (passphrase, fields) per test, in order.
    /// Test 3's passphrase is read from its escapes, unnormalized, and
    /// goes through `bip38::passphrase`; the document's note gives the
    /// normalized bytes, and the two must agree.
    fn bip38_document() -> Vec<Bip38Vector> {
        let text = &BIP38[BIP38.find("==Test vectors==").unwrap()..];
        let mut out: Vec<Bip38Vector> = Vec::new();
        let mut current: Vec<(String, String)> = Vec::new();
        let mut flush = |current: &mut Vec<(String, String)>| {
            if let Some((k, p)) = current.iter().find(|(k, _)| k.starts_with("Passphrase")
                                                       && !k.contains("code")) {
                let passphrase = if k.contains("<tt>") {
                    // "*Passphrase ϓ␀𐐀💩 (<tt>escapes</tt>; [http://...":
                    // no colon after the name, so the first one is the URL's.
                    let typed = unescape(teletype(k));
                    assert_eq!(typed.chars().count(), 5);
                    let normalized = bip38::passphrase(&typed);
                    let note = current.iter().find(|(k, _)| k.contains("Note")).unwrap();
                    let note = teletype(&note.1).strip_prefix("0x").unwrap();
                    assert_eq!(hex(&normalized), note, "test 3's NFC");
                    normalized
                } else {
                    bip38::passphrase(p)
                };
                out.push((passphrase, std::mem::take(current)));
            }
            current.clear();
        };
        for line in text.lines() {
            if line.starts_with("Test ") || line.starts_with("===") {
                flush(&mut current);
            } else if let Some(item) = line.strip_prefix('*') {
                // Test 3's passphrase line has no colon of its own.
                let (key, value) = item.split_once(':').unwrap_or((item, ""));
                current.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
        flush(&mut current);
        assert_eq!(out.len(), 9);
        out
    }

    fn get(fields: &[(String, String)], prefix: &str) -> Option<String> {
        fields.iter().find(|(k, _)| k.starts_with(prefix)).map(|(_, v)| v.clone())
    }

    /// One BIP-38 vector: it decrypts to its key and address, and with
    /// `everything` also encrypts back (without EC multiply), rebuilds
    /// its intermediate code from the salt inside it, confirms its
    /// confirmation code, and refuses a wrong passphrase.
    fn bip38_vector(passphrase: &[u8], fields: &[(String, String)], everything: bool) {
        let encrypted = get(fields, "Encrypted").unwrap();
        let wif = get(fields, "Unencrypted private key (WIF)")
            .or_else(|| get(fields, "Unencrypted (WIF)")).unwrap();
        let d = bip38::decrypt(&encrypted, passphrase).unwrap();
        let (k, compressed, _) = bitcoin::wif_decode(&wif).unwrap();
        assert_eq!(d.key, k, "{encrypted}");
        assert_eq!(d.compressed, compressed);
        if let Some(address) = get(fields, "Bitcoin address")
            .or_else(|| get(fields, "Bitcoin Address")) {
            assert_eq!(d.address, address);
        }
        let lot = get(fields, "Lot/Sequence").map(|t| {
            let (l, s) = t.split_once('/').unwrap();
            (l.parse().unwrap(), s.parse().unwrap())
        });
        assert_eq!(d.lot_sequence, lot);
        if !everything {
            return;
        }
        if encrypted.starts_with("6PR") || encrypted.starts_with("6PY") {
            assert_eq!(bip38::encrypt(&k, compressed, passphrase).unwrap(), encrypted);
        }
        if let Some(code) = get(fields, "Passphrase code") {
            let data = encoding::base58check_decode(&code).unwrap();
            let salt = if lot.is_some() { &data[8..12] } else { &data[8..16] };
            assert_eq!(bip38::intermediate(passphrase, lot, Some(salt)).unwrap(), code);
        }
        if let Some(cfrm) = get(fields, "Confirmation code") {
            assert_eq!(bip38::confirm(&cfrm, passphrase).unwrap(), (d.address.clone(), lot));
        }
        assert!(bip38::decrypt(&encrypted, b"wrong").unwrap_err().contains("Wrong"));
    }

    // BIP-38 fixes scrypt at N = 16384, r = 8, p = 8 for the passphrase,
    // about 10 seconds in a debug build and 0.3 in release. So the four
    // tests below each take one vector of a different kind, and
    // `bip38_every_vector_and_operation` does the rest.

    #[test]
    fn bip38_vector_without_ec_multiply() {
        let doc = bip38_document();
        let (passphrase, fields) = &doc[0];
        bip38_vector(passphrase, fields, false);
        // And encrypting gives the document's string back.
        let (k, compressed, _) = bitcoin::wif_decode(&get(fields, "Unencrypted (WIF)").unwrap())
            .unwrap();
        assert_eq!(bip38::encrypt(&k, compressed, passphrase).unwrap(),
                   get(fields, "Encrypted").unwrap());
    }

    #[test]
    fn bip38_vector_compressed_and_a_wrong_passphrase() {
        let doc = bip38_document();
        let (passphrase, fields) = &doc[3];
        let encrypted = get(fields, "Encrypted").unwrap();
        assert!(encrypted.starts_with("6PY"));
        bip38_vector(passphrase, fields, false);
        assert!(bip38::decrypt(&encrypted, b"wrong").unwrap_err().contains("Wrong"));
    }

    #[test]
    fn bip38_vector_with_ec_multiply() {
        let doc = bip38_document();
        let (passphrase, fields) = &doc[5];
        assert!(get(fields, "Encrypted").unwrap().starts_with("6Pf"));
        bip38_vector(passphrase, fields, false);
    }

    #[test]
    fn bip38_vector_with_lot_and_confirmation() {
        let doc = bip38_document();
        let (passphrase, fields) = &doc[7];
        bip38_vector(passphrase, fields, false);
        let (address, lot) = bip38::confirm(&get(fields, "Confirmation code").unwrap(),
                                            passphrase).unwrap();
        assert_eq!(Some(address), get(fields, "Bitcoin address"));
        assert_eq!(lot, Some((263_183, 1)));
    }

    /// The command line NFC-normalizes the password: test 3's passphrase
    /// typed as the document's escapes, with the combining acute apart,
    /// opens its key.
    #[test]
    fn bip38_the_command_line_normalizes_the_password() {
        let line = BIP38.lines().find(|l| l.starts_with("*Passphrase ") && l.contains("<tt>"))
            .unwrap();
        let typed = unescape(teletype(line));
        assert!(typed.contains('\u{301}'));
        let doc = bip38_document();
        let fields = &doc[2].1;
        let out = run_text(&["bip38", "decrypt", &get(fields, "Encrypted").unwrap(),
                             "--password", &typed]).unwrap();
        assert!(out.contains(&format!("WIF: {}\n",
                                      get(fields, "Unencrypted private key (WIF)").unwrap())),
                "{out}");
    }

    /// All nine vectors and every operation on each: encryption back,
    /// the intermediate code, the confirmation, a wrong passphrase.
    /// Ignored for cost only: 29 derivations at BIP-38's scrypt cost,
    /// measured at 267 seconds in a debug build and 9 in release. The
    /// four tests above run one vector of each kind on every build. Run
    /// it with `cargo test --release --example wallet -- --ignored bip38_every`.
    #[test]
    #[ignore]
    fn bip38_every_vector_and_operation() {
        for (passphrase, fields) in bip38_document() {
            bip38_vector(&passphrase, &fields, true);
        }
    }

    /// Keys made from intermediate codes by scripts/check_wallet.py's
    /// reading of the specification over pycoin's arithmetic, with the
    /// seed recorded: ours makes the same key and address, using only the
    /// cheap scrypt.
    #[test]
    fn recorded_bip38_generation() {
        let rows = records("wallet/wallet.vec", "bip38");
        assert_eq!(rows.len(), 4);
        for r in &rows {
            let seed = unhex(field(r, "seedb")).unwrap();
            let (key, address, cfrm) = bip38::generate(field(r, "intermediate"),
                                                       field(r, "compressed") == "yes",
                                                       Some(&seed)).unwrap();
            assert_eq!(key, field(r, "encrypted"));
            assert_eq!(address, field(r, "address"));
            assert_eq!(cfrm, field(r, "confirmation"));
        }
    }

    // ---------------------------------------------------------- Ethereum --

    fn geth_vector(name: &str, v: &json::Json, wrong_too: bool) {
        let password = v.str("password").unwrap();
        let key = v.str("priv").unwrap();
        let file = v.get("json").unwrap().to_text();
        let account = ethereum::decrypt_keystore(&file, password.as_bytes()).unwrap();
        assert_eq!(hex(&keys::private_bytes(&account.key)), format!("{key:0>64}"), "{name}");
        if wrong_too {
            assert!(ethereum::decrypt_keystore(&file, b"not it").unwrap_err().contains("MAC"));
        }
    }

    /// go-ethereum's version 3 vectors but the wiki's scrypt one, and its
    /// version 1 vector, which is scrypt at N = 2^18, r = 8 - about 20
    /// seconds in a debug build, and the only version 1 file there is.
    #[test]
    fn geth_test_vectors() {
        let v3 = json::parse(&fixture("geth/v3_test_vector.json")).unwrap();
        let names: Vec<&str> = v3.members().iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["wikipage_test_vector_scrypt", "wikipage_test_vector_pbkdf2",
                           "31_byte_key", "30_byte_key"]);
        for (name, v) in &v3.members()[1..] {
            geth_vector(name, v, true);
        }
        let v1 = json::parse(&fixture("geth/v1_test_vector.json")).unwrap();
        geth_vector("test1", v1.get("test1").unwrap(), false);
    }

    #[test]
    fn geth_keystore_files_and_the_presale_wallet() {
        for (file, password, address) in [
            ("presale.json", "foo", "d4584b5f6229b7be90727b0fc8c6b91bb427821f"),
            ("aaa", "foobar", "f466859ead1932d743d622cb74fc058882e8648a"),
            ("zzz", "foobar", "289d485d9771714cce91d3393d764e1311907acc"),
            ("UTC--2016-03-22T12-57-55.920751759Z--7ef5a6135f1fd6a02593eedc869c6d41d934aef8",
             "foobar", "7ef5a6135f1fd6a02593eedc869c6d41d934aef8"),
            ("very-light-scrypt.json", "", "45dea0fb0bba44f4fcf290bba71fd57d7117cbb8"),
        ] {
            let text = fixture(&format!("geth/{file}"));
            let account = ethereum::decrypt_keystore(&text, password.as_bytes()).unwrap();
            assert_eq!(hex(&account.address), address, "{file}");
            assert!(ethereum::decrypt_keystore(&text, b"bad").is_err(), "{file}");
        }
    }

    /// The wiki's scrypt vector (N = 2^18, r = 1, p = 8) with a wrong
    /// password too, and the second version 1 file (N = 2^18, r = 8).
    /// Ignored for cost only: measured at 79 seconds in a debug build
    /// and 4 in release. `geth_test_vectors` covers both formats on every
    /// build. Run it with
    /// `cargo test --release --example wallet -- --ignored geth_heavy`.
    #[test]
    #[ignore]
    fn geth_heavy_vectors() {
        let v3 = json::parse(&fixture("geth/v3_test_vector.json")).unwrap();
        let (name, v) = &v3.members()[0];
        geth_vector(name, v, true);
        let text = fixture("geth/v1-cb61d5a9.json");
        let account = ethereum::decrypt_keystore(&text, b"g").unwrap();
        assert_eq!(hex(&account.address), "cb61d5a9c4896fb9658090b597ef0e7be6f7b67e");
        assert!(ethereum::decrypt_keystore(&text, b"bad").is_err());
    }

    /// A version 3 file whose plaintext is longer than a key, with a
    /// correct MAC: refused, not padded or cut.
    #[test]
    fn a_keystore_holding_more_than_a_key_is_refused() {
        let key = keys::private_from_bytes(&[0x11; 32]).unwrap();
        let text = ethereum::encrypt_keystore(&key, b"pw",
                                              &ethereum::Kdf::Pbkdf2 { iterations: 1 },
                                              Some((&[1; 32], &[2; 16], &[3; 16]))).unwrap();
        let derived = api::pbkdf2("sha256", b"pw", &[1; 32], 1, 32).unwrap();
        let mut long = Vec::new();
        use allcrypt::block_ciphers::BlockCipher;
        allcrypt::api::AnyBlockCipher::new("aes", &derived[..16], None).unwrap()
            .ctr_encrypt(&[0x11; 33], &mut long, &[2; 16]).unwrap();
        let mut mac_input = derived[16..32].to_vec();
        mac_input.extend_from_slice(&long);
        let json = json::parse(&text).unwrap();
        let crypto = json.get("crypto").unwrap();
        let edited = text.replace(crypto.str("ciphertext").unwrap(), &hex(&long))
            .replace(crypto.str("mac").unwrap(), &hex(&hash::keccak256(&mac_input)));
        assert!(ethereum::decrypt_keystore(&edited, b"pw").unwrap_err().contains("33-byte"));
    }

    #[test]
    fn a_keystore_round_trips_and_states_its_address() {
        let key = keys::private_from_bytes(&[0x11; 32]).unwrap();
        for kdf in [ethereum::Kdf::Scrypt { n: 1024, r: 8, p: 1 },
                    ethereum::Kdf::Pbkdf2 { iterations: 100 }] {
            let text = ethereum::encrypt_keystore(&key, b"pw", &kdf, None).unwrap();
            let account = ethereum::decrypt_keystore(&text, b"pw").unwrap();
            assert_eq!(account.key, key);
            // A file whose stated address is someone else's is refused.
            let other = text.replace(&hex(&account.address), &"00".repeat(20));
            assert!(ethereum::decrypt_keystore(&other, b"pw").unwrap_err()
                .contains("address"));
        }
        let huge = ethereum::encrypt_keystore(&key, b"pw",
                                              &ethereum::Kdf::Scrypt { n: 2, r: 1, p: 1 }, None)
            .unwrap().replace("\"n\":2", "\"n\":67108864");
        assert!(ethereum::decrypt_keystore(&huge, b"pw").unwrap_err().contains("2 GiB"));
    }

    // ------------------------------------------- recorded witness answers --

    #[test]
    fn recorded_bip39_and_bip32() {
        let rows = records("wallet/wallet.vec", "bip39");
        assert_eq!(rows.len(), 10);
        for r in &rows {
            let mnemonic = field(r, "mnemonic");
            assert_eq!(bip39::to_mnemonic(&unhex(field(r, "entropy")).unwrap()).unwrap(),
                       mnemonic);
            let passphrase = match field(r, "passphrase") { "-" => "", p => p };
            assert_eq!(hex(&bip39::to_seed(mnemonic, passphrase, true).unwrap()),
                       field(r, "seed"));
        }
        let rows = records("wallet/wallet.vec", "bip32");
        assert_eq!(rows.len(), 12);
        for r in &rows {
            let version = bip32::version_named(field(r, "version")).unwrap();
            let root = ExtendedKey::master(&unhex(field(r, "seed")).unwrap(), version).unwrap();
            let key = root.derive(&bip32::parse_path(field(r, "path")).unwrap()).unwrap();
            let out = fields(&describe(&key, field(r, "path")).unwrap());
            assert_eq!(out[version.private_name], field(r, "prv"));
            assert_eq!(out[version.public_name], field(r, "pub"));
            for (ours, theirs) in [("WIF", "wif"), ("P2PKH", "p2pkh"),
                                   ("P2SH-P2WPKH", "p2sh-p2wpkh"), ("P2WPKH", "p2wpkh"),
                                   ("P2TR", "p2tr"), ("Ethereum", "ethereum")] {
                assert_eq!(out[ours], field(r, theirs), "{}", field(r, "name"));
            }
        }
    }

    /// Mnemonics in python-mnemonic's other word lists, half of them in
    /// NFC rather than the list's own form, with passphrases written the
    /// ways scripts/check_wallet.py lists: python-mnemonic's seeds, which
    /// it makes from the NFKD form of both.
    #[test]
    fn recorded_bip39_in_other_languages_and_unnormalized() {
        let rows = records("wallet/wallet.vec", "bip39-unicode");
        assert_eq!(rows.len(), 24);
        let text = |r: &[(String, String)], name: &str| {
            String::from_utf8(unhex(field(r, name)).unwrap()).unwrap()
        };
        let mut unnormalized = 0;
        for r in &rows {
            let (mnemonic, passphrase) = (text(r, "mnemonic"), text(r, "passphrase"));
            unnormalized += usize::from(unicode::nfkd(&mnemonic) != mnemonic)
                + usize::from(unicode::nfkd(&passphrase) != passphrase);
            assert_eq!(hex(&bip39::to_seed(&mnemonic, &passphrase, false).unwrap()),
                       field(r, "seed"), "{}", field(r, "name"));
            assert_eq!(run_text(&["mnemonic", "seed", &mnemonic, "--unchecked",
                                  "--passphrase", &passphrase]).unwrap().trim(),
                       field(r, "seed"));
        }
        // What the rows are for: about half of the 48 texts change under
        // NFKD (25 when recorded).
        assert!(unnormalized >= 20, "{unnormalized}");
        // And the checksum is the English list's, which these are not.
        assert!(run_text(&["mnemonic", "seed", &text(&rows[0], "mnemonic")]).is_err());
    }

    fn fields(text: &str) -> std::collections::HashMap<String, String> {
        text.lines().filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn message(r: &[(String, String)]) -> Vec<u8> {
        match field(r, "message") { "-" => Vec::new(), m => unhex(m).unwrap() }
    }

    #[test]
    fn recorded_signed_messages() {
        let rows = records("wallet/wallet.vec", "btc-message");
        assert_eq!(rows.len(), 8);
        for r in &rows {
            let (k, compressed, _) = bitcoin::wif_decode(field(r, "wif")).unwrap();
            let kind = if compressed { AddressKind::P2pkh } else { AddressKind::P2pkhUncompressed };
            let signature = bitcoin::sign_message(&k, kind, &message(r)).unwrap();
            assert_eq!(base64::encode(&signature), field(r, "signature"));
            bitcoin::verify_message(field(r, "address"), &signature, &message(r)).unwrap();
            let mut other = message(r);
            other.push(b'!');
            assert!(bitcoin::verify_message(field(r, "address"), &signature, &other).is_err());
        }
        let rows = records("wallet/wallet.vec", "eth-message");
        assert_eq!(rows.len(), 8);
        for r in &rows {
            let k = keys::private_from_bytes(&unhex(field(r, "key")).unwrap()).unwrap();
            let signature = ethereum::sign_message(&k, &message(r)).unwrap();
            assert_eq!(hex(&signature), field(r, "signature"));
            let signer = ethereum::recover_signer(&signature, &message(r)).unwrap();
            assert_eq!(ethereum::checksummed(&signer), field(r, "address"));
            // The same signature in the upper half of the group is refused.
            let mut high = signature.clone();
            let s = allcrypt::bignum::BigUint::from_bytes_be(&signature[32..64]);
            high[32..64].copy_from_slice(&keys::curve().n.sub(&s).unwrap()
                .to_bytes_be_padded(32).unwrap());
            high[64] = if high[64] == 27 { 28 } else { 27 };
            assert!(ethereum::recover_signer(&high, &message(r)).unwrap_err().contains("EIP-2"));
        }
    }

    #[test]
    fn recorded_keystores() {
        let rows = records("wallet/wallet.vec", "keystore");
        assert_eq!(rows.len(), 4);
        for r in &rows {
            let password = match field(r, "password") { "-" => Vec::new(), p => unhex(p).unwrap() };
            let account = ethereum::decrypt_keystore(field(r, "json"), &password).unwrap();
            assert_eq!(hex(&keys::private_bytes(&account.key)), field(r, "key"));
        }
    }

    /// Electrum and Bitcoin Core sign for a segwit address under the
    /// compressed P2PKH header, so that header verifies against the
    /// key's segwit addresses too - and against nobody else's.
    #[test]
    fn a_p2pkh_header_verifies_for_the_keys_segwit_addresses() {
        for r in records("wallet/wallet.vec", "btc-message") {
            let (k, compressed, network) = bitcoin::wif_decode(field(&r, "wif")).unwrap();
            let signature = base64::decode(field(&r, "signature")).unwrap();
            let point = keys::public_key(&k);
            let segwit = [AddressKind::P2wpkh.address(&point, network),
                          AddressKind::P2shP2wpkh.address(&point, network)];
            for address in &segwit {
                assert_eq!(bitcoin::verify_message(address, &signature, &message(&r)).is_ok(),
                           compressed, "{address}");
            }
            let someone = keys::private_from_bytes(&[2; 32]).unwrap();
            let other = AddressKind::P2wpkh.address(&keys::public_key(&someone), network);
            assert!(bitcoin::verify_message(&other, &signature, &message(&r)).is_err());
        }
    }

    #[test]
    fn malformed_wif_keys_are_refused() {
        let k = keys::private_from_bytes(&[1; 32]).unwrap();
        let good = encoding::base58check_decode(&bitcoin::wif_encode(&k, true, mainnet()))
            .unwrap();
        let mut flag = good.clone();
        flag[33] = 2;
        let mut zero = good.clone();
        zero[1..33].fill(0);
        let mut n = good.clone();
        n[1..33].copy_from_slice(&keys::curve().n.to_bytes_be_padded(32).unwrap());
        let mut prefix = good.clone();
        prefix[0] = 0x81;
        for bad in [flag, zero, n, prefix, good[..32].to_vec()] {
            assert!(bitcoin::wif_decode(&encoding::base58check_encode(&bad)).is_err());
        }
        let (k2, compressed, network) = bitcoin::wif_decode(
            &bitcoin::wif_encode(&k, false, Network { testnet: true })).unwrap();
        assert_eq!((k2, compressed, network.testnet), (k, false, true));
    }

    /// A flag byte BIP-38 does not allow is refused before any scrypt.
    #[test]
    fn bip38_flags_are_checked() {
        let doc = bip38_document();
        for (index, bad_flags) in [(0, [0xc1u8, 0x80, 0xc4].as_slice()),
                                   (5, [0x01, 0x10, 0x08].as_slice())] {
            let encrypted = get(&doc[index].1, "Encrypted").unwrap();
            let data = encoding::base58check_decode(&encrypted).unwrap();
            for &flag in bad_flags {
                let mut bad = data.clone();
                bad[2] = flag;
                let err = bip38::decrypt(&encoding::base58check_encode(&bad), b"x").unwrap_err();
                assert!(err.contains("Flag byte"), "{flag:02x}: {err}");
            }
        }
    }

    #[test]
    fn the_command_line_refuses_what_it_cannot_do() {
        assert!(run_text(&["derive", "--seed", "00"]).unwrap_err().contains("16 to 64"));
        assert!(run_text(&["derive", "--seed", "000102030405060708090a0b0c0d0e0f",
                           "--version", "qprv"]).unwrap_err().contains("qprv"));
        assert!(run_text(&["sign-message", "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
                           "m", "--kind", "p2wpkh"]).unwrap_err().contains("compressed"));
        assert!(run_text(&["frobnicate"]).unwrap_err().contains("frobnicate"));
    }
}
