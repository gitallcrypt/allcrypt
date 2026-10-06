/*!
`vectors/ssh_keys.vec` against `allcrypt::ssh`: what OpenSSH's
`ssh-keygen` said about keys it generated, read back by this library.

The file is written by `scripts/make_ssh_vectors.py` from OpenSSH 10.0;
see its header. This test needs neither OpenSSH nor the network.

Every section's record count is asserted against the file's header, so a
parser that silently finds nothing fails rather than passing an empty
loop.
*/

use allcrypt::ssh::keys::{parse_line, PublicKey};
use allcrypt::ssh::private_key;

const VECTORS: &str = include_str!("../vectors/ssh_keys.vec");

/// One record's `key = value` fields.
type Record = Vec<(String, String)>;

fn field<'a>(record: &'a Record, name: &str) -> &'a str {
    record.iter().find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .unwrap_or_else(|| panic!("no {name} in {record:?}"))
}

fn section(name: &str) -> Vec<Record> {
    let heading = format!("[{name}]");
    let mut inside = false;
    let mut records = Vec::new();
    let mut fields = Record::new();
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if inside && !fields.is_empty() {
                records.push(std::mem::take(&mut fields));
            }
            inside = line == heading;
            continue;
        }
        if !inside || line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !fields.is_empty() {
                records.push(std::mem::take(&mut fields));
            }
            continue;
        }
        let (key, value) = line.split_once(" = ")
            .unwrap_or_else(|| panic!("not a field: {line:?}"));
        fields.push((key.to_string(), value.to_string()));
    }
    if inside && !fields.is_empty() {
        records.push(fields);
    }
    records
}

/// The count the header claims for a section.
fn declared(name: &str) -> usize {
    VECTORS.lines()
        .filter_map(|line| line.strip_prefix("#   "))
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next() == Some(name)).then(|| parts.next().unwrap().parse().unwrap())
        })
        .unwrap_or_else(|| panic!("no count for {name} in the header"))
}

#[test]
fn test_the_header_agrees_with_the_body() {
    for name in ["key", "encrypted", "sshsig"] {
        assert_eq!(section(name).len(), declared(name), "[{name}]");
    }
    assert_eq!(declared("key"), 9);
}

/// Each `.pub` line parses, its blob re-encodes to the same bytes, and
/// both fingerprints and the size are what `ssh-keygen -l` printed.
#[test]
fn test_public_keys_and_fingerprints_match_ssh_keygen() {
    let records = section("key");
    for record in &records {
        let name = field(record, "name");
        let line = field(record, "line");
        let read = parse_line(line).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(read.comment, format!("{name}@allcrypt"), "{name}");
        assert_eq!(read.options, "", "{name}");
        assert_eq!(read.key.to_openssh(read.comment), line, "{name}: re-encoded");
        let blob = read.key.to_blob();
        assert_eq!(PublicKey::from_blob(&blob).unwrap(), read.key, "{name}");
        assert_eq!(read.key.fingerprint_sha256(), field(record, "sha256"), "{name}");
        assert_eq!(read.key.fingerprint_md5(), field(record, "md5"), "{name}");
        assert_eq!(read.key.bits().to_string(), field(record, "bits"), "{name}");
    }
    assert_eq!(records.len(), 9);
}

fn base64_text(record: &Record, name: &str) -> String {
    String::from_utf8(allcrypt::pem::decode(field(record, name)).unwrap()).unwrap()
}

/// Each unencrypted private key file `ssh-keygen` wrote reads, and its
/// key is the one on the `.pub` line.
#[test]
fn test_plain_private_keys_read() {
    for record in &section("key") {
        let name = field(record, "name");
        let (key, comment) = private_key::read(&base64_text(record, "private"), None)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(comment, format!("{name}@allcrypt"), "{name}");
        let line = parse_line(field(record, "line")).unwrap();
        assert_eq!(key.public(), line.key, "{name}");
    }
}

/// Every key, under every cipher OpenSSH will encrypt one with, through
/// bcrypt_pbkdf: OpenSSH 10.0's seventy files, and thirteen from 7.4 -
/// a DSA key, and the ciphers 7.6 removed. Each decrypts only if the KDF,
/// the cipher and the AEAD tag placement all match OpenSSH's.
#[test]
fn test_encrypted_private_keys_read_under_every_cipher() {
    let keys = section("key");
    let records = section("encrypted");
    let mut ciphers = std::collections::BTreeSet::new();
    for record in &records {
        let name = field(record, "name");
        let cipher = field(record, "cipher");
        let text = base64_text(record, "private");
        let passphrase = field(record, "passphrase").as_bytes();
        let (key, _) = private_key::read(&text, Some(passphrase))
            .unwrap_or_else(|e| panic!("{name} {cipher}: {e}"));
        let plain = keys.iter().find(|k| field(k, "name") == name).unwrap();
        let line = parse_line(field(plain, "line")).unwrap();
        assert_eq!(key.public(), line.key, "{name} {cipher}");
        assert!(private_key::read(&text, Some(b"not it")).is_err(), "{name} {cipher}");
        ciphers.insert(cipher.to_string());
    }
    assert_eq!(records.len(), 83);
    // OpenSSH 10.0's ten, and the six 7.x also wrote keys with.
    assert_eq!(ciphers.len(), 16, "{ciphers:?}");
}

/// `ssh-keygen -Y sign` output verifies here, under its namespace and
/// not another - and where the signature is deterministic (Ed25519, and
/// RSA's PKCS#1 v1.5) signing the same message with the same key here
/// produces the same bytes OpenSSH did.
#[test]
fn test_sshsig_signatures_from_ssh_keygen() {
    use allcrypt::ssh::signature::{sshsig_sign, sshsig_verify};
    let keys = section("key");
    let records = section("sshsig");
    let mut identical = 0;
    for record in &records {
        let name = field(record, "name");
        let namespace = field(record, "namespace");
        let hash = field(record, "hash");
        let message: Vec<u8> = (0..field(record, "message").len()).step_by(2)
            .map(|i| u8::from_str_radix(&field(record, "message")[i..i + 2], 16).unwrap())
            .collect();
        let armoured = base64_text(record, "signature");
        let plain = keys.iter().find(|k| field(k, "name") == name).unwrap();
        let (key, _) = private_key::read(&base64_text(plain, "private"), None).unwrap();

        let signer = sshsig_verify(&armoured, namespace, &message)
            .unwrap_or_else(|e| panic!("{name} {hash}: {e}"));
        assert_eq!(signer, key.public(), "{name} {hash}");
        assert!(sshsig_verify(&armoured, "not-the-namespace", &message).is_err());
        let mut altered = message.clone();
        altered[0] ^= 1;
        assert!(sshsig_verify(&armoured, namespace, &altered).is_err(), "{name}");

        let ours = sshsig_sign(&key, namespace, &message, hash).unwrap();
        if !name.starts_with("ecdsa") {
            assert_eq!(ours, armoured, "{name} {hash}: OpenSSH's bytes");
            identical += 1;
        }
        assert_eq!(sshsig_verify(&ours, namespace, &message).unwrap(), key.public());
    }
    assert_eq!(records.len(), 14);
    assert_eq!(identical, 8, "Ed25519 and three RSA sizes, two hashes each");
}
