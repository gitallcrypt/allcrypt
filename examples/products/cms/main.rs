//! CMS and S/MIME (RFC 5652, RFC 8551): signed, enveloped,
//! authenticated-enveloped, encrypted, digested and compressed data,
//! built from this library's primitives.
//!
//!     cargo run --release --example cms -- sign IN OUT --signer CERT KEY [--signer CERT KEY]...
//!             [--hash sha256] [--pss] [--detached] [--no-attributes] [--keyid]
//!             [--certfile CERTS] [--smime | --pem]
//!     cargo run --release --example cms -- verify IN [OUT] [--content FILE] [--certfile CERTS]
//!             [--roots CERTS] [--allow-weak] [--binary]
//!     cargo run --release --example cms -- encrypt IN OUT [--recipient CERT]...
//!             [--password PW] [--kek-id HEX --kek HEX] [--secret-key HEX]
//!             [--cipher aes-256-cbc] [--oaep sha256] [--kdf-hash sha256] [--keyid]
//!             [--iterations N] [--smime | --pem]
//!     cargo run --release --example cms -- decrypt IN OUT [--key KEY [--cert CERT]]
//!             [--password PW] [--kek-id HEX --kek HEX] [--secret-key HEX]
//!             [--max-iterations N]
//!     cargo run --release --example cms -- info IN
//!
//! `--password-stdin` in place of `--password PW` reads it from
//! standard input, and `--key-password PW` opens an encrypted private
//! key. Input may be DER, BER, PEM or S/MIME, whichever it is. A
//! clear-signed S/MIME message is verified over its content in
//! canonical form (CRLF line endings) unless `--binary` says it was
//! signed as it is; `sign --smime --detached` writes it that way too.
//!
//! What has checked it is in `examples/products/README.md`.

mod asn;
mod enveloped;
mod keys;
mod signed;
mod smime;

#[path = "../shared/base64.rs"]
mod base64;
#[path = "../shared/ber.rs"]
mod ber;
#[path = "../shared/inflate.rs"]
mod inflate;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use allcrypt::asn1::{Reader, Tag};
use allcrypt::x509::verify::{verify_chain, Policy, Purpose};
use allcrypt::x509::Certificate;

use asn::AlgId;
use enveloped::{Credentials, RecipientSpec};
use keys::Key;

/// The most a compressed message may inflate to.
const INFLATE_LIMIT: usize = 1 << 30;

// ----------------------------------------------------------------- reading --

/// What came in: the ContentInfo's DER, and for a clear-signed S/MIME
/// message the content that was signed.
struct Input {
    der: Vec<u8>,
    clear_content: Option<Vec<u8>>,
}

fn read_input(data: &[u8], binary: bool) -> Result<Input, String> {
    let trimmed = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
    let (der, clear_content) = if data.get(trimmed) == Some(&0x30) {
        (data[trimmed..].to_vec(), None)
    } else if data[trimmed..].starts_with(b"-----BEGIN") {
        let text = std::str::from_utf8(data).map_err(|_| "PEM that is not text.")?;
        let body: String = text.lines().skip_while(|l| !l.starts_with("-----BEGIN")).skip(1)
            .take_while(|l| !l.starts_with("-----END")).collect();
        (base64::decode(&body).ok_or("The PEM's base64 does not decode.")?, None)
    } else {
        match smime::read(data)? {
            smime::Message::Opaque(der) => (der, None),
            smime::Message::ClearSigned { content, signature } => {
                let content = if binary { content } else { smime::canonical(&content) };
                (signature, Some(content))
            }
        }
    };
    Ok(Input { der: ber::to_der(&der)?, clear_content })
}

/// A ContentInfo's type and its content's DER.
fn content_info(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut r = Reader::new(der);
    let mut seq = r.read_sequence()?;
    r.finish()?;
    let content_type = seq.read_oid()?.as_bytes().to_vec();
    let explicit = seq.read_tagged(Tag::context(0, true))?;
    seq.finish()?;
    let mut inner = Reader::new(explicit);
    let content = inner.read_raw()?.to_vec();
    inner.finish()?;
    Ok((content_type, content))
}

fn type_name(oid: &[u8]) -> String {
    asn::ALL.iter().find(|(_, d)| asn::is(oid, d)).map(|(n, _)| n.to_string())
        .unwrap_or_else(|| asn::dotted(oid))
}

/// DigestedData (RFC 5652 7): the content and its digest, checked.
fn digested(der: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(der);
    let mut seq = r.read_sequence()?;
    seq.read_u32()?;
    let alg = AlgId::read(&mut seq)?;
    let (_, content) = signed::read_encapsulated(&mut seq)?;
    let digest = seq.read_octet_string()?;
    seq.finish()?;
    let content = content.ok_or("DigestedData without its content.")?;
    if asn::digest(asn::digest_name(&alg)?, &content)? != digest {
        return Err("The content does not match its digest.".to_string());
    }
    Ok(content)
}

/// CompressedData (RFC 3274): zlib, the only algorithm it defines.
fn compressed(der: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(der);
    let mut seq = r.read_sequence()?;
    seq.read_u32()?;
    let alg = AlgId::read(&mut seq)?;
    if !alg.is(asn::ZLIB) {
        return Err(format!("Compression {} is not zlib.", asn::dotted(&alg.oid)));
    }
    let (_, content) = signed::read_encapsulated(&mut seq)?;
    seq.finish()?;
    inflate::zlib_decompress(&content.ok_or("CompressedData without its content.")?,
                             INFLATE_LIMIT)
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The chain from a signer's certificate up through the certificates
/// at hand, as far as issuers can be found.
fn chain_of<'a>(leaf: &Certificate<'a>, pool: &[Certificate<'a>]) -> Vec<Certificate<'a>> {
    let mut chain = vec![leaf.clone()];
    while chain.len() < 10 {
        let last = chain.last().unwrap_or(leaf);
        if last.is_self_issued() {
            break;
        }
        match pool.iter().find(|c| c.is_issuer_of(last) && c.raw != last.raw) {
            Some(issuer) => chain.push(issuer.clone()),
            None => break,
        }
    }
    chain
}

struct Verified {
    content: Vec<u8>,
    lines: Vec<String>,
    ok: bool,
}

fn verify(input: &Input, detached: Option<Vec<u8>>, extra: &[Vec<u8>], roots: &[Vec<u8>],
          policy: &Policy) -> Result<Verified, String> {
    let (kind, content) = content_info(&input.der)?;
    if asn::is(&kind, asn::DIGESTED_DATA) {
        return Ok(Verified { content: digested(&content)?, ok: true,
                             lines: vec!["digest: verified".to_string()] });
    }
    if asn::is(&kind, asn::COMPRESSED_DATA) {
        return Ok(Verified { content: compressed(&content)?, ok: true, lines: Vec::new() });
    }
    if !asn::is(&kind, asn::SIGNED_DATA) {
        return Err(format!("A {} message, not a signed one.", type_name(&kind)));
    }
    let sd = signed::parse(&content)?;
    let detached = detached.or_else(|| input.clear_content.clone());
    let (content, reports) = signed::verify_all(&sd, detached.as_deref(), extra, policy)?;
    let pool_der: Vec<&Vec<u8>> = sd.certificates.iter().chain(extra).collect();
    let pool: Vec<Certificate> = pool_der.iter().filter_map(|d| Certificate::parse(d).ok())
        .collect();
    let trusted: Vec<Certificate> = roots.iter().filter_map(|d| Certificate::parse(d).ok())
        .collect();
    let mut ok = true;
    let mut lines = Vec::new();
    for report in &reports {
        let mut line = format!("signer {} ({}): {}", report.subject.as_deref()
                                   .unwrap_or(&report.id), report.algorithm,
                               match &report.result {
                                   Ok(()) => "signature verified".to_string(),
                                   Err(e) => format!("FAILED - {e}"),
                               });
        ok &= report.result.is_ok();
        if let Some(time) = report.signing_time {
            line.push_str(&format!(", signed {}", allcrypt::asn1::format_time(time)));
        }
        if !roots.is_empty() && report.result.is_ok() {
            let cert = report.certificate.as_deref().map(Certificate::parse).transpose()?;
            if let Some(cert) = cert {
                let chain = chain_of(&cert, &pool);
                match verify_chain(&chain, &trusted, policy, Purpose::Any) {
                    Ok(()) => line.push_str(", certificate chain verified"),
                    Err(e) => {
                        ok = false;
                        line.push_str(&format!(", certificate chain FAILED - {e}"));
                    }
                }
            }
        }
        lines.push(line);
    }
    Ok(Verified { content, lines, ok })
}

fn decrypt(input: &Input, creds: &Credentials, secret_key: Option<&[u8]>)
           -> Result<(Vec<u8>, Vec<u8>), String> {
    let (kind, content) = content_info(&input.der)?;
    if asn::is(&kind, asn::ENCRYPTED_DATA) {
        let key = secret_key.ok_or("EncryptedData: give the key with --secret-key.")?;
        return enveloped::decrypt_with_key(&content, key);
    }
    let auth = asn::is(&kind, asn::AUTH_ENVELOPED_DATA);
    if !auth && !asn::is(&kind, asn::ENVELOPED_DATA) {
        return Err(format!("A {} message, not an encrypted one.", type_name(&kind)));
    }
    let env = enveloped::parse(&content, auth)?;
    Ok((env.content_type.clone(), env.decrypt(creds)?))
}

fn info(input: &Input) -> Result<Vec<String>, String> {
    let (kind, content) = content_info(&input.der)?;
    let mut lines = vec![format!("content type: {}", type_name(&kind))];
    if asn::is(&kind, asn::SIGNED_DATA) {
        let sd = signed::parse(&content)?;
        lines.push(format!("version {}, content {}{}", sd.version, type_name(&sd.content_type),
                           if sd.content.is_none() { " (detached)" } else { "" }));
        lines.push(format!("digests {}", sd.digest_algs.iter()
                               .map(|a| asn::digest_name(a).unwrap_or("?"))
                               .collect::<Vec<_>>().join(", ")));
        lines.push(format!("{} certificates, {} CRLs", sd.certificates.len(), sd.crl_count));
        for s in &sd.signers {
            lines.push(format!("signer {} v{}: digest {}, signature {}{}", s.sid.describe(),
                               s.version, asn::digest_name(&s.digest_alg).unwrap_or("?"),
                               type_name(&s.sig_alg.oid),
                               if s.signed_attrs.is_some() { ", signed attributes" }
                               else { "" }));
        }
    } else if asn::is(&kind, asn::ENVELOPED_DATA) || asn::is(&kind, asn::AUTH_ENVELOPED_DATA) {
        let env = enveloped::parse(&content, asn::is(&kind, asn::AUTH_ENVELOPED_DATA))?;
        lines.push(format!("content {} under {}", type_name(&env.content_type),
                           type_name(&env.cipher_alg.oid)));
        for r in &env.recipients {
            lines.push(format!("recipient: {}", r.describe()));
        }
    }
    Ok(lines)
}

// ------------------------------------------------------------------ the CLI --

/// The arguments: positional ones, and each option with its values.
struct Args {
    positional: Vec<String>,
    options: Vec<(String, Vec<String>)>,
}

impl Args {
    fn parse(args: &[String]) -> Result<Args, String> {
        let arity = |name: &str| match name {
            "--signer" | "--kek-id" => 2,
            "--detached" | "--no-attributes" | "--keyid" | "--pss" | "--smime" | "--pem"
                | "--allow-weak" | "--binary" | "--password-stdin" => 0,
            _ => 1,
        };
        let mut out = Args { positional: Vec::new(), options: Vec::new() };
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if arg.starts_with("--") {
                // `--kek-id` takes the id; `--kek` the key.
                let n = if arg == "--kek-id" { 1 } else { arity(arg) };
                let values = args.get(i + 1..i + 1 + n)
                    .ok_or_else(|| format!("{arg} needs {n} value(s)."))?.to_vec();
                out.options.push((arg.clone(), values));
                i += 1 + n;
            } else {
                out.positional.push(arg.clone());
                i += 1;
            }
        }
        Ok(out)
    }

    fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(n, _)| n == name)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.options.iter().find(|(n, _)| n == name).and_then(|(_, v)| v.first())
            .map(String::as_str)
    }

    fn all(&self, name: &str) -> Vec<&[String]> {
        self.options.iter().filter(|(n, _)| n == name).map(|(_, v)| v.as_slice()).collect()
    }

    fn password(&self) -> Result<Option<Vec<u8>>, String> {
        if self.flag("--password-stdin") {
            return passphrase::read_line("Password: ").map(Some);
        }
        Ok(self.value("--password").map(|p| p.as_bytes().to_vec()))
    }

    fn hex(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        self.value(name).map(|h| unhex(h).ok_or_else(|| format!("{name} is hex."))).transpose()
    }

    fn number(&self, name: &str, default: u32) -> Result<u32, String> {
        self.value(name).map_or(Ok(default),
                                |v| v.parse().map_err(|_| format!("{name} is a number.")))
    }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        return passphrase::read_all();
    }
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    if path == "-" {
        use std::io::Write;
        return std::io::stdout().write_all(data).map_err(|e| e.to_string());
    }
    std::fs::write(path, data).map_err(|e| format!("{path}: {e}"))
}

fn certs_from(args: &Args, name: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    for values in args.all(name) {
        out.extend(keys::load_certificates(&values[0])?);
    }
    Ok(out)
}

fn output(der: Vec<u8>, args: &Args, smime_type: &str) -> Vec<u8> {
    if args.flag("--smime") {
        smime::write_opaque(&der, smime_type)
    } else if args.flag("--pem") {
        allcrypt::api::pem_wrap("CMS", &der).into_bytes()
    } else {
        der
    }
}

fn run(argv: &[String]) -> Result<bool, String> {
    let command = argv.first().map(String::as_str).unwrap_or("");
    let args = Args::parse(argv.get(1..).unwrap_or(&[]))?;
    let input_path = || args.positional.first().map(String::as_str).ok_or("Name the input.");
    let output_path = || args.positional.get(1).map(String::as_str).unwrap_or("-");
    let key_password = args.value("--key-password").map(str::as_bytes);
    match command {
        "sign" => {
            let content = read_file(input_path()?)?;
            let mut loaded = Vec::new();
            for pair in args.all("--signer") {
                let certs = keys::load_certificates(&pair[0])?;
                loaded.push((certs[0].clone(), Key::load(&pair[1], key_password)?));
            }
            if loaded.is_empty() {
                return Err("sign needs at least one --signer CERT KEY.".to_string());
            }
            let detached = args.flag("--detached");
            let smime_clear = args.flag("--smime") && detached;
            // A clear-signed message is signed in canonical form, the
            // form a verifier will check.
            let content = if smime_clear && !args.flag("--binary") {
                smime::canonical(&content)
            } else {
                content
            };
            let hash = args.value("--hash").unwrap_or("sha256").to_string();
            let options = signed::SignOptions {
                hash: hash.clone(), attributes: !args.flag("--no-attributes"), detached,
                key_id: args.flag("--keyid"), pss: args.flag("--pss"), now: now(),
            };
            let signers: Vec<signed::Signer> = loaded.iter()
                .map(|(c, k)| signed::Signer { certificate: c, key: k }).collect();
            let der = signed::sign(&content, &signers, &certs_from(&args, "--certfile")?,
                                   &options)?;
            let out = if smime_clear {
                let boundary = format!("----{}", asn::hex(&allcrypt::api::random_bytes(16)?));
                smime::write_clear_signed(&content, &der, &hash, &boundary)
            } else {
                output(der, &args, "signed-data")
            };
            write_file(output_path(), &out)?;
            Ok(true)
        }
        "verify" => {
            let input = read_input(&read_file(input_path()?)?, args.flag("--binary"))?;
            let detached = args.value("--content").map(read_file).transpose()?;
            let policy = if args.flag("--allow-weak") { Policy::legacy(now()) }
                         else { Policy::at(now()) };
            let result = verify(&input, detached, &certs_from(&args, "--certfile")?,
                                &certs_from(&args, "--roots")?, &policy)?;
            for line in &result.lines {
                eprintln!("{line}");
            }
            if result.ok {
                write_file(output_path(), &result.content)?;
            }
            Ok(result.ok)
        }
        "encrypt" => {
            let content = read_file(input_path()?)?;
            let cipher = args.value("--cipher").unwrap_or("aes-256-cbc");
            if let Some(key) = args.hex("--secret-key")? {
                let der = enveloped::encrypt_with_key(&content, &key, cipher)?;
                write_file(output_path(), &output(der, &args, "encrypted-data"))?;
                return Ok(true);
            }
            let mut recipients = Vec::new();
            for der in certs_from(&args, "--recipient")? {
                recipients.push(RecipientSpec::Certificate {
                    der, oaep: args.value("--oaep").map(str::to_string),
                    key_id: args.flag("--keyid"),
                    kdf_hash: args.value("--kdf-hash").unwrap_or("sha256").to_string(),
                });
            }
            if let Some(password) = args.password()? {
                recipients.push(RecipientSpec::Password {
                    password,
                    iterations: args.number("--iterations",
                                            allcrypt::api::pbkdf2_recommended_iterations("sha256"))?,
                    prf: "sha256".to_string(),
                });
            }
            if let (Some(id), Some(key)) = (args.hex("--kek-id")?, args.hex("--kek")?) {
                recipients.push(RecipientSpec::Kek { id, key });
            }
            let der = enveloped::encrypt(&content, &recipients, cipher)?;
            let kind = if cipher.ends_with("gcm") { "authEnveloped-data" } else { "enveloped-data" };
            write_file(output_path(), &output(der, &args, kind))?;
            Ok(true)
        }
        "decrypt" => {
            let input = read_input(&read_file(input_path()?)?, false)?;
            let key = args.value("--key").map(|k| Key::load(k, key_password)).transpose()?;
            let cert = args.value("--cert").map(keys::load_certificates).transpose()?
                .map(|c| c[0].clone());
            let password = args.password()?;
            let kek_id = args.hex("--kek-id")?;
            let kek = args.hex("--kek")?;
            let creds = Credentials {
                key: key.as_ref(), cert: cert.as_deref(), password: password.as_deref(),
                kek: kek_id.as_deref().zip(kek.as_deref()),
                max_iterations: args.number("--max-iterations",
                                            enveloped::DEFAULT_MAX_ITERATIONS)?,
            };
            let (content_type, plain) = decrypt(&input, &creds,
                                                args.hex("--secret-key")?.as_deref())?;
            // Anything but data is the DER of another CMS content, which
            // is written as a ContentInfo so that it can be read again.
            let out = if asn::is(&content_type, asn::DATA) {
                plain
            } else {
                let name = asn::ALL.iter().find(|(_, d)| asn::is(&content_type, d))
                    .map(|(_, d)| *d).ok_or("Encrypted content of an unknown type.")?;
                eprintln!("The content is {}: written as a ContentInfo.", type_name(&content_type));
                signed::content_info(name, &plain)
            };
            write_file(output_path(), &out)?;
            Ok(true)
        }
        "info" => {
            let input = read_input(&read_file(input_path()?)?, false)?;
            for line in info(&input)? {
                println!("{line}");
            }
            Ok(true)
        }
        "oids" => {
            for (name, dotted) in asn::ALL {
                println!("{dotted} {name}");
            }
            Ok(true)
        }
        _ => Err("usage: cms sign|verify|encrypt|decrypt|info ...".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("cms: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// RFC 4134 appendix A's files, extracted from the document as its
    /// own program does: `|>` starts a file, `|<` ends it, `|*` is a
    /// comment and any other `|` line is base64.
    fn rfc_4134() -> BTreeMap<String, Vec<u8>> {
        let text = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rfcs").join("rfc4134.txt")).unwrap();
        let mut files = BTreeMap::new();
        let mut current: Option<(String, String)> = None;
        for line in text.lines().map(str::trim_start).filter(|l| l.starts_with('|')) {
            if let Some(name) = line.strip_prefix("|>") {
                current = Some((name.trim().to_string(), String::new()));
            } else if let Some(name) = line.strip_prefix("|<") {
                let (open, body) = current.take().expect("a file to end");
                assert_eq!(open, name.trim());
                files.insert(open, base64::decode(&body).expect("base64"));
            } else if !line.starts_with("|*") {
                current.as_mut().expect("a file open").1.push_str(line[1..].trim());
            }
        }
        files
    }

    fn weak() -> Policy {
        Policy::legacy(0)
    }

    /// Every signed example in RFC 4134 verifies - DSA with SHA-1, RSA,
    /// detached content, several signers, a key identifier, S/MIME in
    /// both forms - and a changed byte of content does not.
    #[test]
    fn test_rfc_4134_signed_examples() {
        let files = rfc_4134();
        assert_eq!(files.len(), 40);
        let content = &files["ExContent.bin"];
        assert_eq!(content, b"This is some sample content.");
        let carl = files["CarlDSSSelf.cer"].clone();
        for name in ["4.1.bin", "4.2.bin", "4.3.bin", "4.4.bin", "4.5.bin", "4.6.bin", "4.7.bin",
                     "4.8.eml", "4.9.eml", "4.10.bin"] {
            let input = read_input(&files[name], false).unwrap();
            let detached = (name == "4.3.bin").then(|| content.clone());
            let result = verify(&input, detached.clone(), std::slice::from_ref(&carl), &[],
                                &weak()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(result.ok, "{name}: {:?}", result.lines);
            // The S/MIME examples sign a MIME entity, headers and all.
            if name.ends_with(".eml") {
                assert!(result.content.ends_with(content), "{name}");
            } else {
                assert_eq!(&result.content, content, "{name}");
            }
            assert_eq!(result.lines.len(), if name == "4.6.bin" { 2 } else { 1 }, "{name}");
            // The modern policy refuses SHA-1 rather than verifying it.
            let strict = verify(&input, detached, std::slice::from_ref(&carl), &[],
                                &Policy::at(0)).unwrap();
            assert!(!strict.ok, "{name} under the default policy");
        }
        // Diane's DSA key inherits Carl's group; without Carl it cannot be
        // checked, and says so.
        let input = read_input(&files["4.6.bin"], false).unwrap();
        let result = verify(&input, None, &[], &[], &weak()).unwrap();
        assert!(!result.ok && result.lines[1].contains("inherits its group"), "{:?}", result.lines);
        // The changed content: 4.2 is signed without attributes, so the
        // signature itself fails; 4.4 with them, so the digest does.
        for (name, why) in [("4.2.bin", "does not verify"), ("4.4.bin", "content has changed")] {
            let mut changed = files[name].clone();
            let at = changed.windows(content.len()).position(|w| w == content.as_slice())
                .unwrap();
            changed[at] ^= 1;
            let result = verify(&read_input(&changed, false).unwrap(), None, &[], &[], &weak())
                .unwrap();
            assert!(!result.ok && result.lines[0].contains(why), "{name}: {:?}", result.lines);
        }
        // 4.11 carries Alice's and Carl's certificates, a CRL, and no
        // signers.
        let sd = signed::parse(&content_info(&files["4.11.bin"]).unwrap().1).unwrap();
        assert_eq!((sd.signers.len(), sd.certificates.len(), sd.crl_count, sd.content.is_none()),
                   (0, 2, 1, true));
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixtures::dir().join("cms").join(name)).unwrap()
    }

    fn fixture_key(name: &str) -> Key {
        Key::from_private(allcrypt::x509::private_key::parse(&fixture(&format!("{name}.key")))
            .unwrap()).unwrap()
    }

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const KEK_ID: &[u8] = b"kek-1";

    /// Every signed message `scripts/check_cms.py --record` kept - OpenSSL
    /// with each key type and option, python-cryptography and NSS -
    /// verifies, with its chain, to the content it was made from.
    #[test]
    fn test_the_witnesses_signatures_verify() {
        let records = fixtures::records("cms.vec", "signed");
        assert_eq!(records.len(), 73);
        let roots = keys::certificates(&fixture("ca.crt")).unwrap();
        let mut kinds = std::collections::BTreeSet::new();
        for record in &records {
            let name = fixtures::field(record, "name");
            let input = read_input(&fixture(name), false).unwrap_or_else(|e| panic!("{name}: {e}"));
            let detached = match fixtures::field(record, "detached") {
                "no" => None,
                file => Some(fixture(file)),
            };
            let policy = if fixtures::field(record, "weak") == "yes" { Policy::legacy(now()) }
                         else { Policy::at(now()) };
            let result = verify(&input, detached, &[], &roots, &policy)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(result.ok, "{name} ({}): {:?}", fixtures::field(record, "made_by"),
                    result.lines);
            let mut expected = fixture(fixtures::field(record, "expect"));
            if fixtures::field(record, "canonical") == "yes" {
                expected = smime::canonical(&expected);
            }
            assert!(result.content == expected, "{name}");
            for line in &result.lines {
                kinds.insert(line.split(['(', ')']).nth(1).unwrap_or("").to_string());
            }
        }
        // RSA, RSA-PSS, ECDSA, DSA, Ed25519 and Ed448, over five digests.
        assert!(kinds.len() >= 12, "{kinds:?}");
    }

    /// Every encrypted message kept opens to its content under the
    /// credentials it was made for, and not under the wrong ones.
    #[test]
    fn test_the_witnesses_encryptions_decrypt() {
        let records = fixtures::records("cms.vec", "sealed");
        assert_eq!(records.len(), 48);
        let keys: BTreeMap<&str, Key> = ["rsa", "ec", "ec384"].into_iter()
            .map(|n| (n, fixture_key(n))).collect();
        for record in &records {
            let name = fixtures::field(record, "name");
            let input = read_input(&fixture(name), false).unwrap_or_else(|e| panic!("{name}: {e}"));
            let field = |k: &str| record.iter().find(|(f, _)| f == k).map(|(_, v)| v.as_str());
            let kek = field("kek").map(fixtures::unhex);
            let secret = field("secret").map(fixtures::unhex);
            let creds = Credentials {
                key: field("key").map(|k| &keys[k]),
                cert: None,
                password: field("password").map(|_| PASSWORD),
                kek: kek.as_deref().map(|k| (KEK_ID, k)),
                max_iterations: enveloped::DEFAULT_MAX_ITERATIONS,
            };
            let (_, plain) = decrypt(&input, &creds, secret.as_deref())
                .unwrap_or_else(|e| panic!("{name} ({}): {e}", fixtures::field(record, "made_by")));
            let expected = fixture(fixtures::field(record, "expect"));
            assert!(smime::canonical(&plain) == smime::canonical(&expected), "{name}");
            // The wrong key of the same kind, a wrong password, a wrong KEK.
            // Another EC key for an EC recipient: some messages are also
            // addressed to the RSA key.
            let other = match field("key") {
                Some("ec") => Some(&keys["ec384"]),
                Some("ec384") => Some(&keys["ec"]),
                _ => None,
            };
            let wrong_kek = kek.as_ref().map(|k| { let mut k = k.clone(); k[0] ^= 1; k });
            let wrong_secret = secret.as_ref().map(|k| { let mut k = k.clone(); k[0] ^= 1; k });
            let wrong = Credentials {
                key: other, cert: None,
                password: field("password").map(|_| &b"correct horse battery stapler"[..]),
                kek: wrong_kek.as_deref().map(|k| (KEK_ID, k)),
                max_iterations: enveloped::DEFAULT_MAX_ITERATIONS,
            };
            // An RSA PKCS#1 v1.5 recipient opened with the wrong RSA key
            // goes on with a random content key (RFC 3218), which fails
            // at the padding - except about once in 256, when the last
            // byte happens to be valid padding. The ec keys are wrong
            // deterministically, so they are the ones tried here.
            if field("key") != Some("rsa") {
                assert!(decrypt(&input, &wrong, wrong_secret.as_deref()).is_err(), "{name}");
            }
        }
    }

    fn sign_options(hash: &str) -> signed::SignOptions {
        signed::SignOptions { hash: hash.to_string(), attributes: true, detached: false,
                              key_id: false, pss: false, now: 1_700_000_000 }
    }

    /// Ours signs with every key type and option and reads it back; a
    /// change to the content, the signed attributes or the signature is
    /// refused.
    #[test]
    fn test_signatures_round_trip() {
        let content = fixture("binary.bin");
        let roots = keys::certificates(&fixture("ca.crt")).unwrap();
        for name in ["rsa", "ec", "ec384", "dsa", "ed25519", "ed448"] {
            let key = fixture_key(name);
            let cert = keys::certificates(&fixture(&format!("{name}.crt"))).unwrap().remove(0);
            for (attributes, detached, key_id, pss) in [(true, false, false, false),
                                                       (false, true, true, false),
                                                       (true, true, false, true)] {
                if pss && name != "rsa" {
                    continue;
                }
                let options = signed::SignOptions { attributes, detached, key_id, pss,
                                                    ..sign_options("sha384") };
                let signer = signed::Signer { certificate: &cert, key: &key };
                let der = signed::sign(&content, &[signer], &[], &options).unwrap();
                let input = read_input(&der, false).unwrap();
                let given = detached.then(|| content.clone());
                let result = verify(&input, given.clone(), &[], &roots, &Policy::at(now()))
                    .unwrap();
                assert!(result.ok && result.content == content, "{name}: {:?}", result.lines);
                let sd = signed::parse(&content_info(&input.der).unwrap().1).unwrap();
                assert_eq!(sd.version, if key_id { 3 } else { 1 });
                let signature = &sd.signers[0].signature;
                // The signature's last byte, and a byte of the content.
                let mut changed = der.clone();
                let at = der.windows(signature.len()).position(|w| w == signature.as_slice())
                    .unwrap() + signature.len() - 1;
                changed[at] ^= 1;
                let result = verify(&read_input(&changed, false).unwrap(), given.clone(), &[],
                                    &roots, &Policy::at(now())).unwrap();
                assert!(!result.ok, "{name}: a changed signature");
                let mut other = content.clone();
                other[0] ^= 1;
                let (changed, given) = if detached {
                    (der.clone(), Some(other))
                } else {
                    let mut changed = der.clone();
                    let at = der.windows(content.len()).position(|w| w == content.as_slice())
                        .unwrap();
                    changed[at] ^= 1;
                    (changed, None)
                };
                let result = verify(&read_input(&changed, false).unwrap(), given, &[], &roots,
                                    &Policy::at(now())).unwrap();
                assert!(!result.ok, "{name}: changed content");
            }
        }
    }

    /// Two signers, of different key types, in one message.
    #[test]
    fn test_two_signers() {
        let content = b"signed twice";
        let rsa = fixture_key("rsa");
        let ec = fixture_key("ec");
        let rsa_cert = keys::certificates(&fixture("rsa.crt")).unwrap().remove(0);
        let ec_cert = keys::certificates(&fixture("ec.crt")).unwrap().remove(0);
        let signers = [signed::Signer { certificate: &rsa_cert, key: &rsa },
                       signed::Signer { certificate: &ec_cert, key: &ec }];
        let der = signed::sign(content, &signers, &[], &sign_options("sha256")).unwrap();
        let result = verify(&read_input(&der, false).unwrap(), None, &[], &[],
                            &Policy::at(now())).unwrap();
        assert!(result.ok && result.lines.len() == 2, "{:?}", result.lines);
    }

    /// Every content cipher to every kind of recipient, and the S/MIME
    /// and PEM wrappings, round trip; the wrong credentials do not.
    #[test]
    fn test_encryption_round_trips() {
        let content = fixture("text.txt");
        let rsa = fixture_key("rsa");
        let ec = fixture_key("ec384");
        let rsa_cert = keys::certificates(&fixture("rsa.crt")).unwrap().remove(0);
        let ec_cert = keys::certificates(&fixture("ec384.crt")).unwrap().remove(0);
        let kek = vec![7u8; 32];
        let ciphers = ["aes-128-cbc", "aes-192-cbc", "aes-256-cbc", "des-ede3-cbc", "des-cbc",
                       "rc2-40-cbc", "rc2-64-cbc", "rc2-128-cbc", "aes-128-gcm", "aes-192-gcm",
                       "aes-256-gcm"];
        for cipher in ciphers {
            let short_key = ["des-cbc", "rc2-40-cbc", "rc2-64-cbc"].contains(&cipher);
            let mut recipients = vec![
                RecipientSpec::Certificate { der: rsa_cert.clone(), oaep: Some("sha256".into()),
                                             key_id: false, kdf_hash: "sha256".into() },
                RecipientSpec::Password { password: PASSWORD.to_vec(), iterations: 10,
                                          prf: "sha256".into() },
            ];
            if !short_key {
                recipients.push(RecipientSpec::Certificate {
                    der: ec_cert.clone(), oaep: None, key_id: true, kdf_hash: "sha384".into() });
                recipients.push(RecipientSpec::Kek { id: KEK_ID.to_vec(), key: kek.clone() });
            }
            let der = enveloped::encrypt(&content, &recipients, cipher).unwrap();
            for wrapped in [der.clone(), smime::write_opaque(&der, "enveloped-data"),
                            allcrypt::api::pem_wrap("CMS", &der).into_bytes()] {
                let input = read_input(&wrapped, false).unwrap();
                let base = Credentials { key: None, cert: None, password: None, kek: None,
                                         max_iterations: 1000 };
                let mut ways = vec![Credentials { key: Some(&rsa), ..base },
                                    Credentials { password: Some(PASSWORD), ..base }];
                if !short_key {
                    ways.push(Credentials { key: Some(&ec), cert: Some(&ec_cert), ..base });
                    ways.push(Credentials { kek: Some((KEK_ID, &kek)), ..base });
                }
                for creds in &ways {
                    assert_eq!(decrypt(&input, creds, None).unwrap_or_else(|e| panic!("{cipher}: {e}")).1, content, "{cipher}");
                }
                let wrong_kek = vec![8u8; 32];
                let wrongs = [Credentials { password: Some(b"wrong"), ..base },
                              Credentials { kek: Some((KEK_ID, &wrong_kek)), ..base },
                              Credentials { kek: Some((b"other", &kek)), ..base },
                              Credentials { password: Some(PASSWORD), max_iterations: 9, ..base }];
                for creds in &wrongs {
                    assert!(decrypt(&input, creds, None).is_err(), "{cipher}");
                }
            }
        }
        let sealed = enveloped::encrypt_with_key(&content, &[9; 16], "aes-128-cbc").unwrap();
        let input = read_input(&sealed, false).unwrap();
        let none = Credentials { key: None, cert: None, password: None, kek: None,
                                 max_iterations: 0 };
        assert_eq!(decrypt(&input, &none, Some(&[9; 16])).unwrap().1, content);
        assert!(decrypt(&input, &none, Some(&[8; 16])).is_err());
    }

    /// A clear-signed S/MIME message verifies over its canonical form,
    /// and a changed line does not.
    #[test]
    fn test_clear_signed_smime() {
        let content = fixture("text.txt");
        let key = fixture_key("ec");
        let cert = keys::certificates(&fixture("ec.crt")).unwrap().remove(0);
        let canonical = smime::canonical(&content);
        let options = signed::SignOptions { detached: true, ..sign_options("sha256") };
        let der = signed::sign(&canonical, &[signed::Signer { certificate: &cert, key: &key }],
                               &[], &options).unwrap();
        let message = smime::write_clear_signed(&canonical, &der, "sha256", "----b");
        let result = verify(&read_input(&message, false).unwrap(), None, &[], &[],
                            &Policy::at(now())).unwrap();
        assert!(result.ok && result.content == canonical, "{:?}", result.lines);
        // The same message with LF line endings throughout still verifies:
        // the reader canonicalises.
        let lf: Vec<u8> = message.iter().copied().filter(|&b| b != b'\r').collect();
        let result = verify(&read_input(&lf, false).unwrap(), None, &[], &[],
                            &Policy::at(now())).unwrap();
        assert!(result.ok, "{:?}", result.lines);
        let mut changed = message.clone();
        let at = message.windows(4).position(|w| w == b"Line").unwrap();
        changed[at] = b'l';
        let result = verify(&read_input(&changed, false).unwrap(), None, &[], &[],
                            &Policy::at(now())).unwrap();
        assert!(!result.ok);
    }

    /// Replace the first occurrence of `from` in `data` with `to`, of the
    /// same length, so that every length around it still holds.
    fn replaced(data: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let at = data.windows(from.len()).position(|w| w == from).expect("found");
        let mut out = data.to_vec();
        out[at..at + to.len()].copy_from_slice(to);
        out
    }

    /// Without signed attributes nothing signed says what the content
    /// is, so RFC 5652 5.3 allows that only for data. OpenSSL's unsigned-
    /// attribute message, relabelled as some other content type, would
    /// otherwise verify unchanged.
    #[test]
    fn test_unattributed_content_must_be_data() {
        let roots = keys::certificates(&fixture("ca.crt")).unwrap();
        let der = read_input(&fixture("signed-004.p7"), false).unwrap().der;
        let (_, body) = content_info(&der).unwrap();
        let sd = signed::parse(&body).unwrap();
        assert!(sd.signers[0].signed_attrs.is_none());
        // The eContentType: the ContentInfo's own type is signedData.
        let relabelled = replaced(&der, &asn::oid(asn::DATA), &asn::oid(asn::DIGESTED_DATA));
        let result = verify(&read_input(&relabelled, false).unwrap(), None, &[], &roots,
                            &Policy::at(now())).unwrap();
        assert!(!result.ok && result.lines[0].contains("RFC 5652 5.3"), "{:?}", result.lines);
    }

    /// With signed attributes the content type is signed, and must be the
    /// content's: OpenSSL's message relabelled as another type verifies
    /// otherwise, its digest and signature untouched.
    #[test]
    fn test_the_signed_content_type_must_match() {
        let der = read_input(&fixture("signed-010.p7"), false).unwrap().der;
        let relabelled = replaced(&der, &asn::oid(asn::DATA), &asn::oid(asn::DIGESTED_DATA));
        let result = verify(&read_input(&relabelled, false).unwrap(), None, &[], &[],
                            &Policy::at(now())).unwrap();
        assert!(!result.ok && result.lines[0].contains("signed content type"), "{:?}",
                result.lines);
    }

    /// A DigestedData whose digest is not its content's is refused.
    #[test]
    fn test_a_digested_message_is_checked() {
        let files = rfc_4134();
        let digest = &asn::digest("sha1", &files["ExContent.bin"]).unwrap();
        let mut other = digest.clone();
        other[0] ^= 1;
        let changed = replaced(&files["6.0.bin"], digest, &other);
        let error = verify(&read_input(&changed, false).unwrap(), None, &[], &[], &weak())
            .err().unwrap();
        assert!(error.contains("does not match its digest"), "{error}");
    }

    /// With a certificate given, a key transport recipient that is not
    /// for it is not tried: a message only to Bob, opened with our key
    /// and certificate, finds no recipient rather than failing at the
    /// content.
    #[test]
    fn test_a_certificate_picks_the_recipient() {
        let files = rfc_4134();
        let spec = RecipientSpec::Certificate { der: files["BobRSASignByCarl.cer"].clone(),
                                                oaep: None, key_id: false,
                                                kdf_hash: "sha256".into() };
        let der = enveloped::encrypt(b"for Bob", &[spec], "aes-128-gcm").unwrap();
        let rsa = fixture_key("rsa");
        let cert = keys::certificates(&fixture("rsa.crt")).unwrap().remove(0);
        let creds = Credentials { key: Some(&rsa), cert: Some(&cert), password: None, kek: None,
                                  max_iterations: 0 };
        let error = decrypt(&read_input(&der, false).unwrap(), &creds, None).unwrap_err();
        assert!(error.starts_with("None of the recipients"), "{error}");
    }

    /// EnvelopedData's version follows its recipients (RFC 5652 6.1): 0
    /// for key transport by issuer and serial, 2 for anything else, 3 with
    /// a password recipient.
    #[test]
    fn test_enveloped_data_versions() {
        let rsa = keys::certificates(&fixture("rsa.crt")).unwrap().remove(0);
        let ec = keys::certificates(&fixture("ec.crt")).unwrap().remove(0);
        let ktri = |der: &Vec<u8>, key_id| RecipientSpec::Certificate {
            der: der.clone(), oaep: None, key_id, kdf_hash: "sha256".into() };
        let password = RecipientSpec::Password { password: b"pw".to_vec(), iterations: 1,
                                                 prf: "sha256".into() };
        for (recipients, version) in [(vec![ktri(&rsa, false)], 0), (vec![ktri(&rsa, true)], 2),
                                      (vec![ktri(&ec, false)], 2),
                                      (vec![ktri(&rsa, false), password], 3)] {
            let der = enveloped::encrypt(b"x", &recipients, "aes-128-cbc").unwrap();
            let body = content_info(&der).unwrap().1;
            let mut seq = Reader::new(&body).read_sequence().unwrap();
            assert_eq!(seq.read_u32().unwrap(), version);
        }
    }

    /// An RSA-PSS signer whose digestAlgorithm says one hash and whose
    /// PSS parameters another is refused, rather than verified under the
    /// parameters while the message claims the other.
    #[test]
    fn test_pss_parameters_must_agree_with_the_digest() {
        let rsa = fixture_key("rsa");
        let cert = keys::certificates(&fixture("rsa.crt")).unwrap().remove(0);
        let options = signed::SignOptions { attributes: false, pss: true,
                                            ..sign_options("sha256") };
        let der = signed::sign(b"pss", &[signed::Signer { certificate: &cert, key: &rsa }], &[],
                               &options).unwrap();
        assert!(verify(&read_input(&der, false).unwrap(), None, &[], &[], &Policy::at(now()))
                    .unwrap().ok);
        // Every SHA-256 identifier becomes SHA-512's: the digest algorithms,
        // not the PSS parameters, which are wrapped differently.
        let sha256 = asn::digest_alg("sha256").unwrap().to_der();
        let sha512 = asn::digest_alg("sha512").unwrap().to_der();
        let sd_der = content_info(&der).unwrap().1;
        let sd = signed::parse(&sd_der).unwrap();
        assert_eq!(sd.signers[0].digest_alg.to_der(), sha256);
        // The SignedData's digest set and the SignerInfo's digest, both
        // before the signature algorithm; the PSS parameters' own copies
        // come after its OID and are left alone.
        let pss = asn::oid(asn::RSASSA_PSS);
        let end = der.windows(pss.len()).position(|w| w == pss.as_slice()).unwrap();
        let mut lying = der.clone();
        let mut changed = 0;
        for at in 0..end {
            if lying[at..].starts_with(&sha256) {
                lying[at..at + sha512.len()].copy_from_slice(&sha512);
                changed += 1;
            }
        }
        assert_eq!(changed, 2);
        let result = verify(&read_input(&lying, false).unwrap(), None, &[], &[],
                            &Policy::at(now())).unwrap();
        assert!(!result.ok && result.lines[0].contains("one hash throughout"), "{:?}",
                result.lines);
    }

    /// What ours writes is DER: the signed attributes and the
    /// certificates in sorted order, the signing time a UTCTime that reads
    /// back as the time given, the versions as RFC 5652 sets them.
    #[test]
    fn test_what_ours_signs_is_der() {
        let ec = fixture_key("ec");
        let cert = keys::certificates(&fixture("ec.crt")).unwrap().remove(0);
        let ca = keys::certificates(&fixture("ca.crt")).unwrap();
        let der = signed::sign(b"x", &[signed::Signer { certificate: &cert, key: &ec }], &ca,
                               &sign_options("sha256")).unwrap();
        let sd = signed::parse(&content_info(&der).unwrap().1).unwrap();
        assert_eq!((sd.version, sd.signers[0].version), (1, 1));
        let sorted = |items: &[Vec<u8>]| items.windows(2).all(|w| w[0] <= w[1]);
        assert!(sorted(&sd.certificates) && sd.certificates.len() == 2);
        let attrs = sd.signers[0].signed_attrs.as_ref().unwrap();
        let mut r = Reader::new(attrs);
        let mut elements = Vec::new();
        while !r.is_empty() {
            elements.push(r.read_raw().unwrap().to_vec());
        }
        assert!(elements.len() == 3 && sorted(&elements));
        let attributes = asn::read_attributes(attrs).unwrap();
        let time = asn::single(&attributes, asn::SIGNING_TIME).unwrap().unwrap();
        assert_eq!(time[0], 0x17, "UTCTime before 2050");
        assert_eq!(Reader::new(time).read_time().unwrap(), 1_700_000_000);
        let mut w = allcrypt::asn1::Writer::new();
        signed::write_time(&mut w, 2_600_000_000);
        assert_eq!(w.finish()[0], 0x18, "GeneralizedTime from 2050");
        let options = signed::SignOptions { key_id: true, ..sign_options("sha256") };
        let der = signed::sign(b"x", &[signed::Signer { certificate: &cert, key: &ec }], &[],
                               &options).unwrap();
        let sd = signed::parse(&content_info(&der).unwrap().1).unwrap();
        assert_eq!((sd.version, sd.signers[0].version), (3, 3));
    }

    /// A chain that does not reach the roots given is refused.
    #[test]
    fn test_the_chain_must_reach_the_roots() {
        let input = read_input(&fixture("signed-000.p7"), false).unwrap();
        let not_the_ca = keys::certificates(&fixture("ec.crt")).unwrap();
        let result = verify(&input, None, &[], &not_the_ca, &Policy::at(now())).unwrap();
        assert!(!result.ok && result.lines[0].contains("chain FAILED"), "{:?}", result.lines);
    }

    /// AuthEnvelopedData must use an authenticating cipher: the same
    /// recipients and CBC content relabelled, with a MAC field nothing
    /// checks, are refused.
    #[test]
    fn test_auth_enveloped_data_needs_an_aead() {
        let rsa = fixture_key("rsa");
        let rsa_cert = keys::certificates(&fixture("rsa.crt")).unwrap().remove(0);
        let spec = RecipientSpec::Certificate { der: rsa_cert, oaep: None, key_id: false,
                                                kdf_hash: "sha256".into() };
        let der = enveloped::encrypt(b"plain", &[spec], "aes-256-cbc").unwrap();
        let (_, body) = content_info(&der).unwrap();
        let mut seq = Reader::new(&body).read_sequence().unwrap();
        let mut inner = Vec::new();
        while !seq.is_empty() {
            inner.extend_from_slice(seq.read_raw().unwrap());
        }
        let mut w = allcrypt::asn1::Writer::new();
        w.write_sequence(|w| {
            w.write_raw(&inner);
            w.write_octet_string(&[0; 16]);
        });
        let relabelled = signed::content_info(asn::AUTH_ENVELOPED_DATA, &w.finish());
        let creds = Credentials { key: Some(&rsa), cert: None, password: None, kek: None,
                                  max_iterations: 0 };
        let error = decrypt(&read_input(&relabelled, false).unwrap(), &creds, None).unwrap_err();
        assert!(error.contains("does not authenticate"), "{error}");
    }

    /// A PKCS#1 v1.5 key transport that fails goes on with a random key
    /// (RFC 3218), so a wrong key fails exactly as damaged content does.
    /// Under AES-GCM the random key always fails at the tag.
    #[test]
    fn test_a_key_transport_failure_looks_like_a_wrong_key() {
        let rsa_cert = keys::certificates(&fixture("rsa.crt")).unwrap().remove(0);
        let spec = RecipientSpec::Certificate { der: rsa_cert.clone(), oaep: None,
                                                key_id: false, kdf_hash: "sha256".into() };
        let der = enveloped::encrypt(b"plain", &[spec], "aes-128-gcm").unwrap();
        let input = read_input(&der, false).unwrap();
        let files = rfc_4134();
        let bob = Key::from_private(allcrypt::x509::private_key::parse(
            &files["BobPrivRSAEncrypt.pri"]).unwrap()).unwrap();
        // Bob's key, presented with our certificate so that the recipient
        // is taken as his.
        let creds = Credentials { key: Some(&bob), cert: Some(&rsa_cert), password: None,
                                  kek: None, max_iterations: 0 };
        let error = decrypt(&input, &creds, None).unwrap_err();
        assert_eq!(error, "Decryption failed: wrong key, or the message is damaged.");
    }

    /// RFC 4134's enveloped examples open with Bob's key - Triple DES and
    /// RC2/128 under RSA, and S/MIME - and its digested one checks; the
    /// two BER/DER data ContentInfos read alike.
    #[test]
    fn test_rfc_4134_enveloped_and_other_examples() {
        let files = rfc_4134();
        let bob = Key::from_private(allcrypt::x509::private_key::parse(
            &files["BobPrivRSAEncrypt.pri"]).unwrap()).unwrap();
        let creds = Credentials { key: Some(&bob), cert: None, password: None, kek: None,
                                  max_iterations: 1000 };
        for name in ["5.1.bin", "5.2.bin", "5.3.eml"] {
            let input = read_input(&files[name], false).unwrap();
            let (kind, plain) = decrypt(&input, &creds, None).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(asn::is(&kind, asn::DATA));
            assert_eq!(plain, files["ExContent.bin"], "{name}");
        }
        let alice = Key::from_private(allcrypt::x509::private_key::parse(
            &files["AlicePrivRSASign.pri"]).unwrap()).unwrap();
        let wrong = Credentials { key: Some(&alice), ..creds };
        assert!(decrypt(&read_input(&files["5.1.bin"], false).unwrap(), &wrong, None).is_err());
        let digested = verify(&read_input(&files["6.0.bin"], false).unwrap(), None, &[], &[],
                              &weak()).unwrap();
        assert_eq!(digested.content, files["ExContent.bin"]);
        for name in ["3.1.bin", "3.2.bin"] {
            let (kind, data) = content_info(&read_input(&files[name], false).unwrap().der)
                .unwrap();
            assert!(asn::is(&kind, asn::DATA));
            assert_eq!(Reader::new(&data).read_octet_string().unwrap(), files["ExContent.bin"]);
        }
        // 7.1 and 7.2 parse; the document does not give their key.
        for name in ["7.1.bin", "7.2.bin"] {
            let input = read_input(&files[name], false).unwrap();
            let error = decrypt(&input, &creds, Some(&[0x11; 24])).unwrap_err();
            assert!(error.starts_with("Decryption failed"), "{name}: {error}");
        }
    }
}
