//! JOSE - JSON Web Keys, Signatures and Encryption (RFC 7515 to 7518,
//! 7638, 7797, 8037, 8812) - built from this library's primitives.
//!
//!     cargo run --release --example jose -- keygen --kty RSA|EC|OKP|oct --param P
//!             [--kid K] [--alg A]
//!     cargo run --release --example jose -- public KEY
//!     cargo run --release --example jose -- thumbprint KEY
//!     cargo run --release --example jose -- sign PAYLOAD --key KEY --alg ALG [--key ...]
//!             [--format compact|json|flat] [--unencoded] [--protected JSON]
//!     cargo run --release --example jose -- verify JWS [--key KEY] [--kid K]
//!             [--allow-none] [--detached PAYLOAD]
//!     cargo run --release --example jose -- encrypt PLAIN --alg ALG --enc ENC
//!             (--key KEY | --password-stdin) [--key ... --alg ...]
//!             [--format compact|json|flat] [--zip] [--aad FILE] [--p2c N]
//!             [--apu TEXT] [--apv TEXT] [--protected JSON] [--unprotected JSON]
//!     cargo run --release --example jose -- decrypt JWE (--key KEY | --password-stdin)
//!             [--kid K] [--max-p2c N]
//!
//! Keys are JWK files, or JWK Sets with `--kid` choosing a member.
//! `verify` and `decrypt` write the payload to standard output; the
//! others write JSON or a compact serialization. `--password-stdin` is
//! for PBES2, and reads one line.
//!
//! What has checked it is in `examples/products/README.md`.

mod jwe;
mod jwk;
mod jws;

#[path = "../shared/inflate.rs"]
mod inflate;
#[path = "../shared/json.rs"]
mod json;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/cli.rs"]
mod cli;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod rfc;

use json::Json;
use cli::value;
use jwk::Jwk;
use std::io::Write;

/// SHA-2 at a bit length.
pub fn sha(bits: usize, data: &[u8]) -> Vec<u8> {
    hash(match bits { 256 => "sha256", 384 => "sha384", _ => "sha512" }, data)
}

pub fn hash(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h = allcrypt::api::AnyHash::new(name).expect("a built-in hash");
    allcrypt::hash_functions::HashFunction::update(&mut h, data);
    allcrypt::hash_functions::HashFunction::digest(&mut h)
}

/// Equal, without stopping at the first difference: a MAC compared
/// byte by byte with an early exit tells a forger how many bytes were
/// right.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn values<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.iter().enumerate().filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| args.get(i + 1).map(String::as_str)).collect()
}

const FLAGS: [&str; 5] = ["--password-stdin", "--unencoded", "--allow-none", "--zip", "--help"];

fn positional(args: &[String]) -> Vec<&String> {
    cli::positional(args, &FLAGS, &[])
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn read_text(path: &str) -> Result<String, String> {
    String::from_utf8(read(path)?).map_err(|_| format!("{path}: not UTF-8."))
}

fn key(path: &str, kid: Option<&str>) -> Result<Jwk, String> {
    jwk::select(&read_text(path)?, kid)
}

fn object(text: Option<&str>) -> Result<Json, String> {
    match text {
        None => Ok(Json::object()),
        Some(text) => match json::parse(text)? {
            value @ Json::Object(_) => Ok(value),
            _ => Err(format!("{text} is not a JSON object.")),
        },
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let input = || names.first().map(|s| s.as_str()).ok_or("Name the input file.");
    let format = value(rest, "--format").unwrap_or("compact");
    let output = |text: String| println!("{text}");
    match command {
        "keygen" => {
            let mut key = Jwk::generate(value(rest, "--kty").ok_or("Give --kty.")?,
                                        value(rest, "--param").ok_or("Give --param.")?)?;
            key.kid = value(rest, "--kid").map(str::to_string);
            key.alg = value(rest, "--alg").map(str::to_string);
            output(key.to_json(true).to_text());
        }
        "public" => output(key(input()?, value(rest, "--kid"))?.to_json(false).to_text()),
        "thumbprint" => output(key(input()?, value(rest, "--kid"))?.thumbprint()),
        "sign" => {
            let payload = read(input()?)?;
            let keys: Vec<Jwk> = values(rest, "--key").iter().map(|p| key(p, None))
                .collect::<Result<_, _>>()?;
            let algs = values(rest, "--alg");
            if keys.len() != algs.len() || keys.is_empty() {
                return Err("Give one --alg for each --key.".to_string());
            }
            let protected = object(value(rest, "--protected"))?;
            let header = value(rest, "--header").map(|t| object(Some(t))).transpose()?;
            let signers: Vec<jws::Signer> = keys.iter().zip(&algs).map(|(key, alg)| {
                jws::Signer { key, alg, protected: protected.clone(), header: header.clone() }
            }).collect();
            let signed = jws::sign(&payload, &signers, !rest.iter().any(|a| a == "--unencoded"))?;
            output(match format {
                "compact" => signed.compact()?,
                "json" => signed.json(false)?,
                "flat" => signed.json(true)?,
                other => return Err(format!("No format {other:?}.")),
            });
        }
        "verify" => {
            let parsed = jws::Jws::parse(&read_text(input()?)?)?;
            let key = value(rest, "--key").map(|p| key(p, value(rest, "--kid"))).transpose()?;
            let detached = value(rest, "--detached").map(read).transpose()?;
            let payload = jws::verify(&parsed, key.as_ref(),
                                      rest.iter().any(|a| a == "--allow-none"),
                                      detached.as_deref())?;
            std::io::stdout().write_all(&payload).map_err(|e| e.to_string())?;
        }
        "encrypt" => {
            let plaintext = read(input()?)?;
            let password = if rest.iter().any(|a| a == "--password-stdin") {
                Some(passphrase::read_line("Password: ")?)
            } else {
                value(rest, "--password").map(|p| p.as_bytes().to_vec())
            };
            let algs = values(rest, "--alg");
            let keys: Vec<Jwk> = values(rest, "--key").iter().map(|p| key(p, None))
                .collect::<Result<_, _>>()?;
            let mut header = Json::object();
            for name in ["apu", "apv"] {
                if let Some(text) = value(rest, &format!("--{name}")) {
                    header.set(name, Json::string(&jwk::b64(text.as_bytes())));
                }
            }
            let mut to = Vec::new();
            let mut keys = keys.iter();
            for alg in &algs {
                let secret = if alg.starts_with("PBES2") {
                    jwe::Secret::Password(password.as_deref()
                        .ok_or("PBES2 needs --password-stdin or --password.")?)
                } else {
                    jwe::Secret::Key(keys.next().ok_or("One --key for each --alg that is \
                                                        not PBES2.")?)
                };
                let mut header = header.clone();
                if let jwe::Secret::Key(Jwk { kid: Some(kid), .. }) = &secret {
                    header.set("kid", Json::string(kid));
                }
                to.push(jwe::To { alg, secret, header });
            }
            if keys.next().is_some() {
                return Err("More --key than --alg.".to_string());
            }
            let aad = value(rest, "--aad").map(read).transpose()?;
            let options = jwe::Options {
                enc: value(rest, "--enc").ok_or("Give --enc.")?,
                zip: rest.iter().any(|a| a == "--zip"),
                protected: object(value(rest, "--protected"))?,
                unprotected: value(rest, "--unprotected").map(|t| object(Some(t))).transpose()?,
                aad: aad.as_deref(),
                p2c: value(rest, "--p2c").unwrap_or("600000").parse()
                    .map_err(|_| "--p2c is a number.")?,
            };
            let sealed = jwe::encrypt(&plaintext, &to, &options)?;
            output(match format {
                "compact" => sealed.compact()?,
                "json" => sealed.json(false)?,
                "flat" => sealed.json(true)?,
                other => return Err(format!("No format {other:?}.")),
            });
        }
        "decrypt" => {
            let parsed = jwe::Jwe::parse(&read_text(input()?)?)?;
            let max_p2c: u32 = value(rest, "--max-p2c").unwrap_or("10000000").parse()
                .map_err(|_| "--max-p2c is a number.")?;
            let plaintext = if rest.iter().any(|a| a == "--password-stdin") {
                let password = passphrase::read_line("Password: ")?;
                jwe::decrypt(&parsed, &jwe::Secret::Password(&password), max_p2c)?
            } else if let Some(password) = value(rest, "--password") {
                jwe::decrypt(&parsed, &jwe::Secret::Password(password.as_bytes()), max_p2c)?
            } else {
                let key = key(value(rest, "--key").ok_or("Give --key or a password.")?,
                              value(rest, "--kid"))?;
                jwe::decrypt(&parsed, &jwe::Secret::Key(&key), max_p2c)?
            };
            std::io::stdout().write_all(&plaintext).map_err(|e| e.to_string())?;
        }
        _ => return Err("usage: jose keygen|public|thumbprint|sign|verify|encrypt|decrypt ..."
            .to_string()),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("jose: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{field, records, unhex};
    use crate::jwe::{Jwe, Secret};
    use crate::jws::Jws;

    fn payload() -> Vec<u8> {
        unhex(field(&records("jose.vec", "payload")[0], "hex"))
    }

    /// Change one character of the part of a compact serialization at
    /// `index` - a base64url character for another, so it still parses.
    fn change(compact: &str, index: usize) -> String {
        let mut parts: Vec<String> = compact.split('.').map(str::to_string).collect();
        let part = &mut parts[index];
        let c = if part.starts_with('A') { "B" } else { "A" };
        part.replace_range(0..1, c);
        parts.join(".")
    }

    /// Every JWS jwcrypto signed - each algorithm, compact - verifies,
    /// and a changed signature does not.
    #[test]
    fn test_every_recorded_jws_verifies() {
        let records = records("jose.vec", "jws");
        assert_eq!(records.len(), 17);
        for record in &records {
            let name = field(record, "name");
            let key = Jwk::from_text(field(record, "key")).unwrap();
            let token = field(record, "token");
            let parsed = Jws::parse(token).unwrap();
            assert_eq!(jws::verify(&parsed, Some(&key), false, None).unwrap(), payload(), "{name}");
            let changed = Jws::parse(&change(token, 2)).unwrap();
            assert!(jws::verify(&changed, Some(&key), false, None).is_err(), "{name}");
        }
    }

    /// Every JWE jwcrypto encrypted - each key management algorithm with
    /// each content encryption, ECDH-ES on five curves, two recipients
    /// with zip and AAD - decrypts, and a changed tag does not.
    #[test]
    fn test_every_recorded_jwe_decrypts() {
        let records = records("jose.vec", "jwe");
        assert_eq!(records.len(), 120);
        // A changed tag is tried once per algorithm, and each key parsed
        // once: an RSA private key or a PBES2 derivation is a large part
        // of a second in a debug build, and there are 120 of these.
        let mut tampered = std::collections::HashSet::new();
        let mut parsed_keys: std::collections::HashMap<String, Jwk> = Default::default();
        for record in &records {
            let name = field(record, "name");
            let token = field(record, "token");
            if let Some((_, text)) = record.iter().find(|(k, _)| k == "key") {
                if !parsed_keys.contains_key(text) {
                    parsed_keys.insert(text.clone(), Jwk::from_text(text).unwrap());
                }
            }
            let key = record.iter().find(|(k, _)| k == "key").map(|(_, v)| &parsed_keys[v]);
            let password = record.iter().find(|(k, _)| k == "password").map(|(_, v)| unhex(v));
            let secret = match (key, &password) {
                (Some(key), _) => Secret::Key(key),
                (None, Some(password)) => Secret::Password(password),
                _ => panic!("{name}: no key"),
            };
            let parsed = Jwe::parse(token).unwrap();
            assert_eq!(jwe::decrypt(&parsed, &secret, 100_000).unwrap(), payload(), "{name}");
            if !token.starts_with('{') && tampered.insert(name.split(' ').next().unwrap()) {
                let changed = Jwe::parse(&change(token, 4)).unwrap();
                assert!(jwe::decrypt(&changed, &secret, 100_000).is_err(), "{name}");
            }
        }
    }

    /// The private keys the JWE fixtures carry, by type: an RSA key, and
    /// EC and OKP keys for ECDH.
    fn recorded_key(name: &str) -> Jwk {
        let record = records("jose.vec", "jwe").into_iter()
            .find(|r| field(r, "name") == name).unwrap_or_else(|| panic!("{name}"));
        Jwk::from_text(field(&record, "key")).unwrap()
    }

    fn signer<'a>(key: &'a Jwk, alg: &'a str) -> jws::Signer<'a> {
        jws::Signer { key, alg, protected: Json::object(), header: None }
    }

    /// Every algorithm, every serialization, encoded and not: ours signs
    /// and ours verifies, and a key of the wrong type is refused rather
    /// than tried.
    #[test]
    fn test_every_jws_algorithm_round_trips() {
        let rsa = recorded_key("RSA-OAEP A128GCM");
        let keys: Vec<(&str, Jwk)> = vec![
            ("HS256", Jwk::generate("oct", "32").unwrap()),
            ("HS384", Jwk::generate("oct", "48").unwrap()),
            ("HS512", Jwk::generate("oct", "64").unwrap()),
            ("ES256", Jwk::generate("EC", "P-256").unwrap()),
            ("ES384", Jwk::generate("EC", "P-384").unwrap()),
            ("ES512", Jwk::generate("EC", "P-521").unwrap()),
            ("ES256K", Jwk::generate("EC", "secp256k1").unwrap()),
            ("EdDSA", Jwk::generate("OKP", "Ed25519").unwrap()),
            ("Ed448", Jwk::generate("OKP", "Ed448").unwrap()),
        ];
        let payload = payload();
        let mut all: Vec<(&str, &Jwk)> = keys.iter().map(|(a, k)| (*a, k)).collect();
        for alg in ["RS256", "PS384", "PS512", "RS512"] {
            all.push((alg, &rsa));
        }
        for (alg, key) in &all {
            for encode in [true, false] {
                let signed = jws::sign(&payload, &[signer(key, alg)], encode).unwrap();
                for text in [signed.json(false).unwrap(), signed.json(true).unwrap()] {
                    let parsed = Jws::parse(&text).unwrap();
                    assert_eq!(jws::verify(&parsed, Some(key), false, None).unwrap(), payload,
                               "{alg} {encode}");
                }
            }
            let compact = jws::sign(&payload, &[signer(key, alg)], true).unwrap().compact()
                .unwrap();
            let other = if alg.starts_with("HS") { &rsa } else { &keys[0].1 };
            assert!(jws::verify(&Jws::parse(&compact).unwrap(), Some(other), false, None)
                .is_err(), "{alg} with a key of another type");
            // The algorithm comes from the header the signature covers: a
            // header naming another algorithm is another signing input.
            let changed = change(&compact, 0);
            assert!(jws::verify(&Jws::parse(&changed).unwrap(), Some(key), false, None).is_err());
        }
        // Several signers, each verified alone by its own key.
        let signers: Vec<jws::Signer> = all.iter().map(|(a, k)| signer(k, a)).collect();
        let general = Jws::parse(&jws::sign(&payload, &signers, true).unwrap().json(false)
            .unwrap()).unwrap();
        for (_, key) in &all {
            assert_eq!(jws::verify(&general, Some(key), false, None).unwrap(), payload);
        }
    }

    /// Every key management algorithm with every content encryption: ours
    /// encrypts, ours decrypts, the wrong key is refused.
    #[test]
    fn test_every_jwe_algorithm_round_trips() {
        let payload = payload();
        let rsa = recorded_key("RSA-OAEP A128GCM");
        let ec = recorded_key("ECDH-ES A256CBC-HS512 P-384");
        let x448 = recorded_key("ECDH-ES A256CBC-HS512 X448");
        let password = b"correct horse".to_vec();
        for enc in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM",
                    "A256GCM"] {
            let dir = Jwk::generate("oct", &jwe::cek_length(enc).unwrap().to_string()).unwrap();
            let kw: Vec<Jwk> = ["16", "24", "32"].iter()
                .map(|n| Jwk::generate("oct", n).unwrap()).collect();
            let cases: Vec<(&str, Secret)> = vec![
                ("RSA1_5", Secret::Key(&rsa)), ("RSA-OAEP", Secret::Key(&rsa)),
                ("RSA-OAEP-256", Secret::Key(&rsa)),
                ("A128KW", Secret::Key(&kw[0])), ("A192KW", Secret::Key(&kw[1])),
                ("A256KW", Secret::Key(&kw[2])), ("A128GCMKW", Secret::Key(&kw[0])),
                ("A256GCMKW", Secret::Key(&kw[2])), ("dir", Secret::Key(&dir)),
                ("ECDH-ES", Secret::Key(&ec)), ("ECDH-ES+A192KW", Secret::Key(&x448)),
                ("PBES2-HS384+A192KW", Secret::Password(&password)),
            ];
            for (alg, secret) in cases {
                let to = [jwe::To { alg, secret: match &secret {
                    Secret::Key(k) => Secret::Key(k),
                    Secret::Password(p) => Secret::Password(p),
                }, header: Json::object() }];
                let options = jwe::Options { enc, zip: alg.ends_with("KW"),
                                             protected: Json::object(), unprotected: None,
                                             aad: None, p2c: 1000 };
                let sealed = jwe::encrypt(&payload, &to, &options).unwrap();
                let parsed = Jwe::parse(&sealed.compact().unwrap()).unwrap();
                assert_eq!(jwe::decrypt(&parsed, &secret, 1000).unwrap(), payload,
                           "{alg} {enc}");
                let wrong = Jwk::generate("oct", "32").unwrap();
                assert!(jwe::decrypt(&parsed, &Secret::Key(&wrong), 1000).is_err());
            }
        }
    }

    /// RSA1_5's failure is the tag's failure: an encrypted key that does
    /// not decrypt is replaced by a random one (RFC 7516 11.5), so it
    /// fails exactly as a wrong key does.
    #[test]
    fn test_an_rsa1_5_padding_failure_looks_like_a_wrong_key() {
        let rsa = recorded_key("RSA1_5 A128GCM");
        let to = [jwe::To { alg: "RSA1_5", secret: Secret::Key(&rsa), header: Json::object() }];
        let options = jwe::Options { enc: "A128GCM", zip: false, protected: Json::object(),
                                     unprotected: None, aad: None, p2c: 1 };
        let mut sealed = jwe::encrypt(b"x", &to, &options).unwrap();
        let good_tag = jwe::decrypt(&sealed, &Secret::Key(&rsa), 1).unwrap();
        assert_eq!(good_tag, b"x");
        sealed.recipients[0].encrypted_key[10] ^= 1;
        let padding = jwe::decrypt(&sealed, &Secret::Key(&rsa), 1).unwrap_err();
        sealed.recipients[0].encrypted_key[10] ^= 1;
        sealed.tag[0] ^= 1;
        let tag = jwe::decrypt(&sealed, &Secret::Key(&rsa), 1).unwrap_err();
        assert_eq!(padding, tag);
    }

    /// Two recipients, a shared unprotected header, zip and AAD; the
    /// AAD and every header are covered, and each recipient's key
    /// opens it.
    #[test]
    fn test_a_jwe_with_two_recipients_zip_and_aad() {
        let rsa = recorded_key("RSA-OAEP-256 A128GCM");
        let kw = Jwk::generate("oct", "32").unwrap();
        let mut unprotected = Json::object();
        unprotected.set("jku", Json::string("https://example.invalid/keys"));
        let to = [jwe::To { alg: "RSA-OAEP-256", secret: Secret::Key(&rsa), header: Json::object() },
                  jwe::To { alg: "A256KW", secret: Secret::Key(&kw), header: Json::object() }];
        let long = payload().repeat(3000);
        let options = jwe::Options { enc: "A256CBC-HS512", zip: true, protected: Json::object(),
                                     unprotected: Some(unprotected), aad: Some(b"aad"),
                                     p2c: 1 };
        let text = jwe::encrypt(&long, &to, &options).unwrap().json(false).unwrap();
        let parsed = Jwe::parse(&text).unwrap();
        for key in [&rsa, &kw] {
            assert_eq!(jwe::decrypt(&parsed, &Secret::Key(key), 1).unwrap(), long);
        }
        let mut changed = Jwe::parse(&text).unwrap();
        changed.aad = Some(jwk::b64(b"AAD"));
        assert!(jwe::decrypt(&changed, &Secret::Key(&kw), 1).is_err());
        // zip outside the protected header is refused: it changes what
        // the plaintext means and nothing would cover it.
        let mut moved = Jwe::parse(&text).unwrap();
        let mut header = Json::object();
        header.set("zip", Json::string("DEF"));
        moved.recipients[1].header = Some(header);
        assert!(jwe::decrypt(&moved, &Secret::Key(&kw), 1).is_err());
    }

    /// The header rules: names in two headers, `crit` that is not
    /// understood or not protected, `b64` outside `crit`, `none` without
    /// asking, a PBES2 count over the cap, a private `epk`.
    #[test]
    fn test_the_header_rules_are_enforced() {
        let key = Jwk::generate("oct", "32").unwrap();
        let payload = payload();
        let signed = |protected: &str, header: Option<&str>| {
            let protected = jwk::b64(protected.as_bytes());
            let mut input = protected.clone().into_bytes();
            input.push(b'.');
            input.extend_from_slice(jwk::b64(&payload).as_bytes());
            Jws { payload_text: jwk::b64(&payload).into_bytes(),
                  signatures: vec![jws::Signature {
                      protected, header: header.map(|h| json::parse(h).unwrap()),
                      signature: jws::sign_input("HS256", &key, &input).unwrap() }] }
        };
        let ok = signed(r#"{"alg":"HS256"}"#, Some(r#"{"kid":"x"}"#));
        assert!(jws::verify(&ok, Some(&key), false, None).is_ok());
        for (protected, header) in [
            (r#"{"alg":"HS256"}"#, Some(r#"{"alg":"HS256"}"#)),
            (r#"{"alg":"HS256","crit":["exp"],"exp":1}"#, None),
            (r#"{"alg":"HS256","exp":1}"#, Some(r#"{"crit":["exp"]}"#)),
            (r#"{"alg":"HS256","b64":true}"#, None),
            (r#"{"alg":"HS256"}"#, Some(r#"{"b64":true}"#)),
            (r#"{"alg":"HS256","crit":[]}"#, None),
        ] {
            let jws_ = signed(protected, header);
            assert!(jws::verify(&jws_, Some(&key), false, None).is_err(), "{protected} {header:?}");
        }
        let none = signed(r#"{"alg":"none"}"#, None);
        assert!(jws::verify(&none, None, false, None).is_err());
        assert!(jws::verify(&none, Some(&key), true, None).is_err());

        let to = [jwe::To { alg: "PBES2-HS256+A128KW", secret: Secret::Password(b"pw"),
                            header: Json::object() }];
        let options = jwe::Options { enc: "A128GCM", zip: false, protected: Json::object(),
                                     unprotected: None, aad: None, p2c: 5000 };
        let sealed = jwe::encrypt(b"x", &to, &options).unwrap();
        assert!(jwe::decrypt(&sealed, &Secret::Password(b"pw"), 5000).is_ok());
        assert!(jwe::decrypt(&sealed, &Secret::Password(b"pw"), 4999).unwrap_err()
            .contains("more than"));

        let ec = recorded_key("ECDH-ES A256CBC-HS512 P-256");
        let mut header = Json::object();
        header.set("alg", Json::string("ECDH-ES"));
        header.set("epk", ec.to_json(true));
        assert!(jwe::unwrap(&header, &Secret::Key(&ec), "A128GCM", &[], 1).unwrap_err()
            .contains("private"));
    }

    /// jwcrypto's RFC 7638 thumbprint of one key of every type: the
    /// member order differs by type, and only RFC 7638's own RSA example
    /// and RFC 8037's OKP one are in the documents.
    #[test]
    fn test_thumbprints_agree_with_jwcrypto() {
        let records = records("jose.vec", "thumbprint");
        assert_eq!(records.len(), 10);
        for record in &records {
            let key = Jwk::from_text(field(record, "key")).unwrap();
            assert_eq!(key.thumbprint(), field(record, "thumbprint"), "{}", field(record, "name"));
        }
    }

    /// A JWS that names a header in `crit` must carry it; signatures must
    /// agree on `b64`; a signature naming another key's `kid` is not
    /// tried with this one; an unencoded payload with a '.' cannot be
    /// compact.
    #[test]
    fn test_more_jws_rules() {
        let mut key = Jwk::generate("oct", "32").unwrap();
        let payload = payload();
        let sign_with = |protected: &str, encoded: bool, key: &Jwk| {
            let protected = jwk::b64(protected.as_bytes());
            let payload_text = if encoded { jwk::b64(&payload).into_bytes() }
                               else { payload.clone() };
            let mut input = protected.clone().into_bytes();
            input.push(b'.');
            input.extend_from_slice(&payload_text);
            (jws::Signature { protected, header: None,
                              signature: jws::sign_input("HS256", key, &input).unwrap() },
             payload_text)
        };
        let (absent, text) = sign_with(r#"{"alg":"HS256","crit":["b64"]}"#, true, &key);
        let jws_ = Jws { payload_text: text, signatures: vec![absent] };
        assert!(jws::verify(&jws_, Some(&key), false, None).unwrap_err().contains("not in the"));

        let (encoded, text) = sign_with(r#"{"alg":"HS256"}"#, true, &key);
        let (raw, _) = sign_with(r#"{"alg":"HS256","b64":false,"crit":["b64"]}"#, false, &key);
        let mixed = Jws { payload_text: text, signatures: vec![encoded, raw] };
        assert!(jws::verify(&mixed, Some(&key), false, None).unwrap_err().contains("disagree"));

        key.kid = Some("ours".into());
        let (other, text) = sign_with(r#"{"alg":"HS256","kid":"theirs"}"#, true, &key);
        let named = Jws { payload_text: text, signatures: vec![other] };
        assert!(jws::verify(&named, Some(&key), false, None).unwrap_err().contains("kid"));
        key.kid = None;
        assert!(jws::verify(&named, Some(&key), false, None).is_ok());

        let unencoded = jws::sign(b"a.b", &[signer(&key, "HS256")], false).unwrap();
        assert!(unencoded.compact().is_err());
        assert!(unencoded.json(true).is_ok());
    }

    /// `zip` only from the protected header; no name in two headers;
    /// nothing after the compressed plaintext; GCMKW's IV is 96 bits.
    #[test]
    fn test_more_jwe_rules() {
        let key = Jwk::generate("oct", "16").unwrap();
        let to = |alg| [jwe::To { alg, secret: Secret::Key(&key), header: Json::object() }];
        let options = |protected: Json, unprotected: Option<Json>| jwe::Options {
            enc: "A128GCM", zip: false, protected, unprotected, aad: None, p2c: 1 };
        // A plaintext that is already DEFLATE, with zip unprotected.
        let deflated = [1u8, 3, 0, 0xfc, 0xff, b'a', b'b', b'c'];
        let mut zip = Json::object();
        zip.set("zip", Json::string("DEF"));
        let unprotected = jwe::encrypt(&deflated, &to("A128KW"),
                                       &options(Json::object(), Some(zip.clone()))).unwrap();
        assert!(jwe::decrypt(&unprotected, &Secret::Key(&key), 1).unwrap_err()
            .contains("protected header"));
        let protected = jwe::encrypt(&deflated, &to("A128KW"), &options(zip.clone(), None))
            .unwrap();
        assert_eq!(jwe::decrypt(&protected, &Secret::Key(&key), 1).unwrap(), b"abc");
        let mut trailing = deflated.to_vec();
        trailing.push(0);
        let junk = jwe::encrypt(&trailing, &to("A128KW"), &options(zip, None)).unwrap();
        assert!(jwe::decrypt(&junk, &Secret::Key(&key), 1).unwrap_err().contains("after"));

        let mut kid = Json::object();
        kid.set("kid", Json::string("a"));
        let twice = jwe::encrypt(b"x", &to("A128KW"), &options(kid.clone(), Some(kid))).unwrap();
        assert!(jwe::decrypt(&twice, &Secret::Key(&key), 1).unwrap_err().contains("two"));

        // GCMKW with a 128-bit IV, wrapped under it so the only thing
        // wrong is its length.
        let gcm = jwe::encrypt(b"x", &to("A128GCMKW"), &options(Json::object(), None)).unwrap();
        let mut header = crate::json::parse(std::str::from_utf8(
            &unb64(&gcm.protected).unwrap()).unwrap()).unwrap();
        let jwk::Key::Oct(kek) = &key.key else { unreachable!() };
        let cek = jwe::unwrap(&header, &Secret::Key(&key), "A128GCM",
                              &gcm.recipients[0].encrypted_key, 1).unwrap().unwrap();
        let iv = [5u8; 16];
        let (wrapped, tag) = allcrypt::api::aead_encrypt("aes-gcm", kek, &iv, &[], &cek).unwrap();
        header.set("iv", Json::string(&jwk::b64(&iv)));
        header.set("tag", Json::string(&jwk::b64(&tag)));
        assert!(jwe::unwrap(&header, &Secret::Key(&key), "A128GCM", &wrapped, 1).unwrap_err()
            .contains("12 bytes"));
    }

    /// An RSA key's `d` may be written modulo lcm(p-1, q-1) or
    /// (p-1)(q-1) - this library writes the first, RFC 7516's A.1 key
    /// the second - and either is taken; one that is wrong modulo either
    /// prime is not.
    #[test]
    fn test_an_rsa_private_exponent_is_checked_against_each_prime() {
        use allcrypt::bignum::BigUint;
        let json = recorded_key("RSA1_5 A128GCM").to_json(true);
        let number = |name| BigUint::from_bytes_be(&unb64(json.str(name).unwrap()).unwrap());
        let (d, p, q) = (number("d"), number("p"), number("q"));
        let one = BigUint::one();
        let (p1, q1) = (p.sub(&one).unwrap(), q.sub(&one).unwrap());
        let with_d = |value: &BigUint| {
            let mut changed = json.clone();
            changed.set("d", Json::string(&jwk::b64(&value.to_bytes_be())));
            Jwk::parse(&changed)
        };
        assert!(with_d(&d.add(&p1.mul(&q1))).is_ok());
        assert!(with_d(&d.add(&p1)).is_err(), "wrong modulo q - 1");
        assert!(with_d(&d.add(&q1)).is_err(), "wrong modulo p - 1");
    }

    /// Keys that are not what they claim are refused on the way in.
    #[test]
    fn test_jwk_checks() {
        let ec = recorded_key("ECDH-ES A256CBC-HS512 P-256").to_json(true);
        let with = |name: &str, value: Json| {
            let mut json = ec.clone();
            json.set(name, value);
            Jwk::parse(&json)
        };
        assert!(Jwk::parse(&ec).is_ok());
        let x = unb64(ec.str("x").unwrap()).unwrap();
        let mut off_curve = x.clone();
        off_curve[31] ^= 1;
        assert!(with("x", Json::string(&jwk::b64(&off_curve))).is_err(), "off the curve");
        assert!(with("x", Json::string(&jwk::b64(&x[1..]))).is_err(), "short");
        assert!(with("crv", Json::string("P-384")).is_err(), "the wrong curve");
        let mut d = unb64(ec.str("d").unwrap()).unwrap();
        d[31] ^= 1;
        assert!(with("d", Json::string(&jwk::b64(&d))).is_err(), "another key's d");

        let rsa = recorded_key("RSA1_5 A128GCM").to_json(true);
        let mut no_primes = Json::object();
        for (name, value) in rsa.members() {
            if !["p", "q", "dp", "dq", "qi"].contains(&name.as_str()) {
                no_primes.set(name, value.clone());
            }
        }
        assert!(Jwk::parse(&no_primes).err().unwrap().contains("primes"));

        let okp = Jwk::generate("OKP", "X25519").unwrap().to_json(true);
        let mut other = okp.clone();
        other.set("x", Json::string(&jwk::b64(&[9; 32])));
        assert!(Jwk::parse(&other).is_err());

        // A set, chosen by kid.
        let mut a = Jwk::generate("oct", "16").unwrap();
        a.kid = Some("a".into());
        let mut b = Jwk::generate("oct", "16").unwrap();
        b.kid = Some("b".into());
        let set = format!(r#"{{"keys":[{},{}]}}"#, a.to_json(true).to_text(),
                          b.to_json(true).to_text());
        assert_eq!(jwk::select(&set, Some("b")).unwrap().thumbprint(), b.thumbprint());
        assert!(jwk::select(&set, None).is_err());
        assert!(jwk::select(&set, Some("c")).is_err());
    }

    /// Base64url, strictly: one spelling for each value.
    #[test]
    fn test_base64url_is_strict() {
        for n in 0..70usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(unb64(&jwk::b64(&data)).unwrap(), data);
        }
        assert_eq!(jwk::b64(b"\xfb\xff"), "-_8");
        for bad in ["A", "AB=", "A+", "A/", "AB C", "AR", "AAB"] {
            assert!(unb64(bad).is_err(), "{bad}");
        }
    }

    use crate::jwk::unb64;
}
