//! Encrypted PDF documents - the standard security handler, revisions 2
//! to 6, RC4 and AES - built from this library's primitives.
//!
//!     cargo run --release --example pdf -- info FILE [--password PW]
//!     cargo run --release --example pdf -- decrypt IN OUT [--password PW]
//!     cargo run --release --example pdf -- encrypt IN OUT --user PW --owner PW
//!             [--scheme rc4-40|rc4-128|rc4-128-r4|aes-128|aes-256-r5|aes-256]
//!             [--permissions N] [--password PW]
//!
//! `--password-stdin` reads the password from standard input instead;
//! for `encrypt`, `--passwords-stdin` reads two lines, the user password
//! and then the owner's. Without a password the empty one is tried,
//! which opens every file that has no user password.
//!
//! `decrypt` writes the document with every string and stream decrypted
//! and the `/Encrypt` dictionary gone, keeping each object's number;
//! `encrypt` does the reverse, from a plain file or (given its password)
//! an encrypted one. Both write a classic cross-reference table, with
//! the objects that lived in object streams written out on their own.
//!
//! What has checked it is in `examples/products/README.md`.

mod file;
mod object;
mod security;

#[path = "../shared/inflate.rs"]
mod inflate;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use std::collections::BTreeMap;

use file::{transform, Direction, Document};
use object::{get, Dict, Object};
use security::{Security, Which};

/// Open a document and authenticate, trying the empty password when
/// none is given.
pub fn open(data: Vec<u8>, password: Option<&[u8]>) -> Result<(Document, Option<Which>), String> {
    let mut doc = Document::parse(data)?;
    let encrypt = match get(&doc.trailer, "Encrypt") {
        None => return Ok((doc, None)),
        Some(Object::Reference(n, _)) => {
            doc.encrypt_object = Some(*n);
            doc.object(*n)?.0
        }
        Some(direct) => direct.clone(),
    };
    let dict = encrypt.as_dict().ok_or("/Encrypt is not a dictionary.")?.clone();
    // Without a password the empty one is tried, and only its being
    // wrong means a password is needed: any other refusal - an
    // unsupported handler or revision - is reported as itself.
    let (security, which) = Security::open(&dict, &doc.id(), password.unwrap_or(b""))
        .map_err(|e| if password.is_none() && e == "Wrong password." {
            "The document has a user password: give it with --password.".to_string()
        } else { e })?;
    doc.security = Some(security);
    Ok((doc, Some(which)))
}

/// Every object, decrypted, except the ones that only describe the
/// file's own structure: cross-reference streams, object streams and
/// the `/Encrypt` dictionary.
pub fn plain_objects(doc: &Document) -> Result<BTreeMap<u32, (u16, Object)>, String> {
    let mut out = BTreeMap::new();
    for &number in doc.xref.keys() {
        if Some(number) == doc.encrypt_object {
            continue;
        }
        let (object, generation) = doc.object(number)
            .map_err(|e| format!("Object {number}: {e}"))?;
        if let Object::Stream(dict, _) = &object {
            if matches!(get(dict, "Type").and_then(Object::as_name), Some(b"XRef" | b"ObjStm")) {
                continue;
            }
        }
        out.insert(number, (generation, object));
    }
    Ok(out)
}

fn plain_trailer(doc: &Document) -> Dict {
    let mut trailer = Dict::new();
    for key in ["Root", "Info", "ID"] {
        if let Some(value) = get(&doc.trailer, key) {
            trailer.push((key.as_bytes().to_vec(), value.clone()));
        }
    }
    trailer
}

pub fn decrypt(data: Vec<u8>, password: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let (doc, _) = open(data, password)?;
    Ok(file::write_file(&doc.version, &plain_objects(&doc)?, &plain_trailer(&doc)))
}

fn later(a: &str, b: &str) -> String {
    let parse = |v: &str| -> (u32, u32) {
        let mut parts = v.split('.').map(|p| p.parse().unwrap_or(0));
        (parts.next().unwrap_or(1), parts.next().unwrap_or(0))
    };
    if parse(a) >= parse(b) { a.to_string() } else { b.to_string() }
}

pub fn encrypt(data: Vec<u8>, password: Option<&[u8]>, scheme: &str, user: &[u8], owner: &[u8],
               permissions: i32) -> Result<Vec<u8>, String> {
    let (doc, _) = open(data, password)?;
    let mut objects = plain_objects(&doc)?;
    let mut trailer = plain_trailer(&doc);
    // The first /ID element goes into every pre-revision-5 key, so a
    // file without one gets one.
    let mut id = doc.id();
    if id.is_empty() {
        id = allcrypt::api::random_bytes(16)?;
        trailer.push((b"ID".to_vec(), Object::Array(vec![Object::String(id.clone()),
                                                           Object::String(id.clone())])));
    }
    let (security, dict) = Security::create(scheme, user, owner, permissions, &id)?;
    for (number, (generation, object)) in objects.iter_mut() {
        let taken = std::mem::replace(object, Object::Null);
        *object = transform(&security, *number, *generation, taken, Direction::Encrypt)?;
    }
    let encrypt_number = objects.keys().next_back().map_or(1, |n| n + 1);
    objects.insert(encrypt_number, (0, Object::Dictionary(dict)));
    trailer.push((b"Encrypt".to_vec(), Object::Reference(encrypt_number, 0)));
    let needed = match security.r {
        2 => "1.3",
        3 => "1.4",
        4 => "1.6",
        _ => "1.7",
    };
    Ok(file::write_file(&later(&doc.version, needed), &objects, &trailer))
}

// ------------------------------------------------------------------ CLI --

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn positional(args: &[String]) -> Vec<&String> {
    let mut out = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
        } else if arg == "--password-stdin" || arg == "--passwords-stdin" {
        } else if arg.starts_with("--") {
            skip = true;
        } else {
            out.push(arg);
        }
    }
    out
}

fn password(args: &[String]) -> Result<Option<Vec<u8>>, String> {
    if args.iter().any(|a| a == "--password-stdin") {
        return passphrase::read_line("Password: ").map(Some);
    }
    Ok(value(args, "--password").map(|p| p.as_bytes().to_vec()))
}

fn permissions_text(p: i32) -> String {
    let bits = [(3, "print"), (4, "modify"), (5, "copy"), (6, "annotate"), (9, "fill forms"),
                (10, "extract for accessibility"), (11, "assemble"), (12, "print high quality")];
    let allowed: Vec<&str> = bits.iter().filter(|(bit, _)| p & (1 << (bit - 1)) != 0)
        .map(|(_, name)| *name).collect();
    if allowed.is_empty() { "nothing".to_string() } else { allowed.join(", ") }
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let names = positional(rest);
    let input = names.first().ok_or("Name the input file.")?;
    let data = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    match command {
        "info" => {
            let (doc, which) = open(data, password(rest)?.as_deref())?;
            println!("PDF {}, {} objects", doc.version, doc.xref.len());
            match (&doc.security, which) {
                (Some(s), Some(which)) => {
                    let bits = if s.r >= 5 { 256 } else { s.key.len() * 8 };
                    println!("standard security handler, V {} R {}, {}-bit key", s.v, s.r, bits);
                    println!("streams {}, strings {}{}", s.streams.name(), s.strings.name(),
                             if s.encrypt_metadata { "" } else { ", metadata in the clear" });
                    println!("opened with the {} password",
                             if which == Which::User { "user" } else { "owner" });
                    println!("permissions {} ({})", s.permissions, permissions_text(s.permissions));
                    if s.perms_match == Some(false) {
                        println!("warning: /Perms does not match /P - the permissions were changed");
                    }
                }
                _ => println!("not encrypted"),
            }
            Ok(())
        }
        "decrypt" => {
            let output = names.get(1).ok_or("Name the output file.")?;
            let bytes = decrypt(data, password(rest)?.as_deref())?;
            std::fs::write(output, bytes).map_err(|e| format!("{output}: {e}"))
        }
        "encrypt" => {
            let output = names.get(1).ok_or("Name the output file.")?;
            let (user, owner) = if rest.iter().any(|a| a == "--passwords-stdin") {
                (passphrase::read_line("User password: ")?,
                 passphrase::read_line("Owner password: ")?)
            } else {
                (value(rest, "--user").unwrap_or("").as_bytes().to_vec(),
                 value(rest, "--owner").ok_or("Give --owner (or --passwords-stdin).")?
                     .as_bytes().to_vec())
            };
            let permissions = value(rest, "--permissions").unwrap_or("-4").parse()
                .map_err(|_| "--permissions is a signed 32-bit number")?;
            let bytes = encrypt(data, password(rest)?.as_deref(),
                                value(rest, "--scheme").unwrap_or("aes-256"), &user, &owner,
                                permissions)?;
            std::fs::write(output, bytes).map_err(|e| format!("{output}: {e}"))
        }
        _ => Err("usage: pdf info|decrypt|encrypt ...".to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("pdf: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{field, hex, records, unhex};
    use allcrypt::hash_functions::sha2::SHA256;
    use allcrypt::hash_functions::HashFunction;

    fn sha256(data: &[u8]) -> String {
        let mut hash = SHA256::new(&[]);
        hash.update(data);
        hex(&hash.digest())
    }

    /// What `scripts/check_pdf.py` lists of an object: its strings and
    /// its stream data, keys sorted, arrays in order, a stream's
    /// dictionary before its data.
    enum Item<'a> {
        String(&'a [u8]),
        Data(&'a [u8]),
    }

    fn items<'a>(object: &'a Object, out: &mut Vec<Item<'a>>) {
        fn dict<'a>(d: &'a Dict, out: &mut Vec<Item<'a>>) {
            let mut sorted: Vec<&(Vec<u8>, Object)> = d.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, value) in sorted {
                items(value, out);
            }
        }
        match object {
            Object::String(bytes) => out.push(Item::String(bytes)),
            Object::Array(list) => list.iter().for_each(|o| items(o, out)),
            Object::Dictionary(d) => dict(d, out),
            Object::Stream(d, data) => {
                dict(d, out);
                out.push(Item::Data(data));
            }
            _ => {}
        }
    }

    /// Whether `bytes` is one of the encodings of `text` that qpdf
    /// writes as `u:` text: UTF-16 with a byte order mark either way
    /// round, UTF-8 with one, or one byte per character. The last is
    /// Latin-1, which PDFDocEncoding agrees with on every such string
    /// in the fixtures; a string where they part would fail here, and
    /// say so.
    fn spells(bytes: &[u8], text: &str) -> bool {
        let be: Vec<u8> = [0xfe, 0xff].into_iter()
            .chain(text.encode_utf16().flat_map(u16::to_be_bytes)).collect();
        let le: Vec<u8> = [0xff, 0xfe].into_iter()
            .chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect();
        let utf8: Vec<u8> = [0xef, 0xbb, 0xbf].iter().chain(text.as_bytes()).copied().collect();
        let single: Option<Vec<u8>> = text.chars().map(|c| u8::try_from(u32::from(c)).ok())
            .collect();
        bytes == be || bytes == le || bytes == utf8 || single.as_deref() == Some(bytes)
    }

    /// Every recorded document, opened with each password qpdf opened it
    /// with: the same password must be reported (owner or user), the
    /// same objects listed, and every string and every stream's data
    /// must be what qpdf decrypted.
    #[test]
    fn test_every_document_decrypts_as_qpdf_decrypted_it() {
        let documents = records("pdf.vec", "document");
        assert_eq!(documents.len(), 72);
        let mut opened = 0;
        for record in &documents {
            let name = field(record, "name");
            let data = std::fs::read(fixtures::dir().join("pdf").join(name)).unwrap();
            let expected: Vec<(&str, &str)> = record.iter()
                .filter(|(k, _)| k == "string" || k == "data")
                .map(|(k, v)| (k.as_str(), v.as_str())).collect();
            for (key, value) in record {
                if key != "open" {
                    continue;
                }
                let (password, which) = value.split_once(' ').unwrap();
                let (doc, reported) = open(data.clone(), Some(&unhex(password)))
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                let reported = if reported == Some(Which::Owner) { "owner" } else { "user" };
                assert_eq!(reported, which, "{name}");
                let objects = plain_objects(&doc).unwrap();
                assert_eq!(objects.len().to_string(), field(record, "objects"), "{name}");
                let mut ours = Vec::new();
                for (number, (_, object)) in &objects {
                    let mut found = Vec::new();
                    items(object, &mut found);
                    ours.extend(found.into_iter().map(|item| (*number, item)));
                }
                assert_eq!(ours.len(), expected.len(), "{name}: strings and streams");
                for ((number, item), (key, value)) in ours.iter().zip(&expected) {
                    let mut parts = value.splitn(3, ' ');
                    let at = parts.next().unwrap();
                    assert_eq!(number.to_string(), at, "{name}");
                    match (item, *key) {
                        (Item::Data(bytes), "data") => {
                            assert_eq!(sha256(bytes), parts.next().unwrap(), "{name} {at}")
                        }
                        (Item::String(bytes), "string") => {
                            let (form, recorded) = (parts.next().unwrap(), parts.next().unwrap_or(""));
                            match form {
                                "b" => assert_eq!(hex(bytes), recorded, "{name} {at}"),
                                "sha256" => assert_eq!(sha256(bytes), recorded, "{name} {at}"),
                                "u" => {
                                    let text = String::from_utf8(unhex(recorded)).unwrap();
                                    assert!(spells(bytes, &text), "{name} {at}: {} is not {text:?}",
                                            hex(bytes));
                                }
                                other => panic!("{name}: string form {other}"),
                            }
                        }
                        _ => panic!("{name} {at}: a {key} where ours has the other kind"),
                    }
                }
                opened += 1;
            }
        }
        assert_eq!(opened, 107);
    }

    /// Passwords one character short of what the revision reads.
    #[test]
    fn test_a_password_one_character_short_is_refused() {
        let refused = records("pdf.vec", "refused");
        assert_eq!(refused.len(), 2);
        for record in &refused {
            let name = field(record, "name");
            let data = std::fs::read(fixtures::dir().join("pdf").join(name)).unwrap();
            let password = unhex(field(record, "password"));
            assert!(open(data.clone(), Some(&password)).is_err(), "{name}");
            assert!(open(data, Some(b"not the password")).is_err(), "{name}");
        }
    }

    /// With no password given, every refusal from the security handler
    /// was reported as "the document has a user password", so a file
    /// under an unsupported handler asked for a password it would then
    /// refuse for the real reason. The fixtures are all under the
    /// standard handler, and the ones with a user password are opened
    /// with it, so the substitution was never seen on another error.
    #[test]
    fn test_only_a_wrong_empty_password_asks_for_one() {
        let data = std::fs::read(fixtures::dir().join("pdf").join("qpdf-R2-plain.pdf")).unwrap();
        // The same length, so that nothing after the dictionary moves.
        let at = object::find(&data, b"/Filter /Standard").unwrap();
        let mut other = data[..at].to_vec();
        other.extend_from_slice(b"/Filter /NoSuchSH");
        other.extend_from_slice(&data[at + 17..]);
        let error = open(other, None).err().unwrap();
        assert!(error.contains("NoSuchSH") && !error.contains("user password"), "{error}");
        let refused = records("pdf.vec", "refused");
        let name = field(&refused[0], "name");
        let locked = std::fs::read(fixtures::dir().join("pdf").join(name)).unwrap();
        assert!(open(locked, None).err().unwrap().contains("user password"));
    }

    /// Re-encrypting a recorded document under every scheme and
    /// decrypting it again gives back what qpdf listed, for both
    /// passwords.
    #[test]
    fn test_re_encryption_round_trips_under_every_scheme() {
        let name = "qpdf-tests-enc-XI-R6_V5_U-attachment_encrypted-attachments.pdf";
        let data = std::fs::read(fixtures::dir().join("pdf").join(name)).unwrap();
        let (doc, _) = open(data.clone(), Some(b"attachment")).unwrap();
        let original = plain_objects(&doc).unwrap();
        for scheme in ["rc4-40", "rc4-128", "rc4-128-r4", "aes-128", "aes-256-r5", "aes-256"] {
            let sealed = encrypt(data.clone(), Some(b"attachment"), scheme, b"u", b"o", -4)
                .unwrap();
            assert_ne!(sealed, decrypt(data.clone(), Some(b"attachment")).unwrap());
            for (password, which) in [(&b"u"[..], Which::User), (b"o", Which::Owner)] {
                let (doc, reported) = open(sealed.clone(), Some(password)).unwrap();
                assert_eq!(reported, Some(which), "{scheme}");
                let objects = plain_objects(&doc).unwrap();
                for (number, (_, object)) in &original {
                    let (mut a, mut b) = (Vec::new(), Vec::new());
                    items(object, &mut a);
                    items(&objects[number].1, &mut b);
                    let flat = |v: &[Item]| -> Vec<Vec<u8>> {
                        v.iter().map(|i| match i { Item::String(s) | Item::Data(s) => s.to_vec() })
                            .collect()
                    };
                    assert_eq!(flat(&a), flat(&b), "{scheme} object {number}");
                }
            }
        }
    }
}
