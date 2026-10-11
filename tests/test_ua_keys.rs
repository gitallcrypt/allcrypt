/*!
Ukrainian key containers, against the files in `tests/keys/ua/` and what
dstu-engine's keylib found in them, recorded in `vectors/ua_keys.vec` by
`scripts/check_ua_keys.py`.

The containers are IIT's `Key-6.dat` (dstu-engine's test file, which
holds a signing key and a key-agreement key), jkurwa's encrypted PKCS#8
(PBES2 with GOST 28147 CFB and HMAC-GOST 34.311) and plain keys in DER
and PEM, and ours: a key on each of the ten named curves, half of them
with a second key in the attributes, and both encrypted forms on three:
under a password, under one longer than HMAC-GOST 34.311's block, and
under the empty one, whose GOST 34.311 is the hash of the empty
message. keylib read every one of
ours, so each is also evidence that the writer produces what Ukrainian
software reads.

The keys are compared as numbers - the curve's degree, `d`, the public
point - because that is what the two libraries share; the encodings
around them differ in the details this module exists to absorb. One of
jkurwa's keys (`KeyE54B.cer`) stores a `d` above the order; keylib keeps
it as it is, the record and ours hold it reduced.

jkurwa's self-signed certificates name their key by the subject key
identifier, which is the key identifier IIT's software computes, so the
certificates check `key_id` without any recorded value.
*/

use std::collections::HashMap;

use allcrypt::api::{self, Dstu4145Key};
use allcrypt::asn1::{Reader, Tag};
use allcrypt::x509::ua_key;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/keys/ua").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

struct Row {
    file: String,
    format: String,
    password: Vec<u8>,
    keys: Vec<String>,
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/ua_keys.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows: Vec<Row> = text.lines().filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let fields: HashMap<&str, &str> = line.split(' ')
                .map(|w| w.split_once('=').unwrap()).collect();
            Row {
                file: fields["file"].to_string(),
                format: fields["format"].to_string(),
                password: if fields["password"] == "-" { Vec::new() }
                          else { unhex(fields["password"]) },
                keys: fields["keys"].split(',').map(str::to_string).collect(),
            }
        }).collect();
    assert_eq!(rows.len(), declared);
    rows
}

/// A key as the record has it: `m:d:qx:qy`, each number as wide as the
/// field.
fn numbers(key: &Dstu4145Key) -> String {
    let m: usize = key.curve_name().rsplit('m').next().unwrap().parse().unwrap();
    let width = m.div_ceil(8);
    let d = key.private_bytes().unwrap();
    let q = key.public_key().to_bytes(false).unwrap();
    let pad = |b: &[u8]| format!("{}{}", "00".repeat(width - b.len()), hex(b));
    format!("{m}:{}:{}:{}", pad(&d), pad(&q[..q.len() / 2]), pad(&q[q.len() / 2..]))
}

#[test]
fn test_every_container_opens_to_the_keys_keylib_found() {
    let rows = rows();
    assert_eq!(rows.len(), 24);
    for row in &rows {
        let keys = api::dstu4145_keys_open(&fixture(&row.file), &row.password)
            .unwrap_or_else(|e| panic!("{}: {e}", row.file));
        let ours: Vec<String> = keys.iter().map(numbers).collect();
        assert_eq!(ours, row.keys, "{}", row.file);
    }
}

#[test]
fn test_a_wrong_password_is_refused() {
    let mut checked = 0;
    for row in rows().iter().filter(|r| r.format != "pkcs8") {
        let mut wrong = row.password.clone();
        wrong.push(b'x');
        let error = match api::dstu4145_keys_open(&fixture(&row.file), &wrong) {
            Err(e) => e,
            Ok(_) => panic!("{}: a wrong password was accepted", row.file),
        };
        // Key-6.dat has a MAC, so says so; PBES2 has none, and fails on
        // what the wrong key decrypts to.
        if row.format == "key6" {
            assert!(error.contains("Wrong password"), "{}: {error}", row.file);
        }
        checked += 1;
    }
    assert_eq!(checked, 9);
}

/// `Key-6.dat` has no salt and no IV, so sealing what one opens to under
/// the same password has to give the file back - dstu-engine's (written
/// by IIT's software) and ours.
#[test]
fn test_key6_seals_back_byte_for_byte() {
    let mut checked = 0;
    for row in rows().iter().filter(|r| r.format == "key6") {
        let data = fixture(&row.file);
        let plain = ua_key::key6_open(&data, &row.password).unwrap();
        assert_eq!(ua_key::key6_seal(&plain, &row.password).unwrap(), data, "{}", row.file);
        checked += 1;
    }
    assert_eq!(checked, 4);
}

/// Our plain keys are what the writer makes of the keys in them: the
/// writer has no randomness, so the file comes back exactly.
#[test]
fn test_our_plain_keys_are_written_again_exactly() {
    let mut checked = 0;
    for row in rows().iter().filter(|r| r.file.starts_with("ours-") && r.format == "pkcs8"
                                       && r.password.is_empty()) {
        let data = fixture(&row.file);
        let keys = api::dstu4145_keys_open(&data, b"").unwrap();
        assert_eq!(keys[0].private_key_info(keys.get(1)).unwrap(), data, "{}", row.file);
        checked += 1;
    }
    assert_eq!(checked, 10);
}

/// The subject key identifier of a certificate: tbsCertificate's
/// extensions, read field by field. These certificates' authority key
/// identifiers are a bare OCTET STRING where RFC 5280 has a SEQUENCE,
/// so the certificate parser rightly refuses them whole.
fn subject_key_identifier(der: &[u8]) -> Vec<u8> {
    let mut outer = Reader::new(der);
    let mut certificate = outer.read_sequence().unwrap();
    let mut tbs = certificate.read_sequence().unwrap();
    while !tbs.is_empty() {
        let (tag, body) = tbs.read_any().unwrap();
        if tag != Tag::context(3, true) {
            continue;
        }
        let mut wrapper = Reader::new(body);
        let mut extensions = wrapper.read_sequence().unwrap();
        while !extensions.is_empty() {
            let mut extension = extensions.read_sequence().unwrap();
            let oid = extension.read_oid().unwrap();
            let (mut tag, mut value) = extension.read_any().unwrap();
            if tag == Tag::universal(1) {
                (tag, value) = extension.read_any().unwrap();
            }
            assert_eq!(tag, Tag::universal(4));
            if oid.as_bytes() == allcrypt::x509::oids::SUBJECT_KEY_ID {
                return Reader::new(value).read_octet_string().unwrap().to_vec();
            }
        }
    }
    panic!("no subject key identifier");
}

#[test]
fn test_a_certificates_key_identifier_is_its_keys() {
    for (certificate, key) in [("SELF_SIGNED1.cer", "PRIV1.cer"),
                               ("SELF_SIGNED_ENC_40A0.cer", "Key40A0.cer"),
                               ("SELF_SIGNED_ENC_6929.cer", "Key6929.cer"),
                               ("SELF_SIGNED_ENC_E54B.cer", "KeyE54B.cer")] {
        let keys = api::dstu4145_keys_open(&fixture(key), b"").unwrap();
        let expected = subject_key_identifier(&fixture(certificate));
        assert_eq!(keys[0].key_id().unwrap(), expected, "{certificate}");
        assert_eq!(keys[0].public_key().key_id().unwrap(), expected, "{certificate}");
    }
}

/// The CAs' software encrypts with PBKDF2 over HMAC-GOST 34.311, 10,000
/// iterations and a 32-byte salt, and GOST 28147 CFB with an 8-byte IV;
/// those are the defaults for this scheme.
#[test]
fn test_gost_encryption_defaults_to_what_the_cas_write() {
    let info = Dstu4145Key::generate("dstu4145-m163").unwrap().private_key_info(None).unwrap();
    let sealed = api::encrypt_private_key(&info, b"pw", "gost28147-cfb", None, None, None, None)
        .unwrap();
    let p = api::private_key_encryption(&sealed).unwrap();
    assert_eq!((p.scheme, p.prf, p.iterations, p.salt.len(), p.iv.len()),
               ("gost28147-cfb", Some("gost34311"), 10_000, 32, 8));
}

/// A container written now reads back to its keys, whichever form: a
/// plain key, PBES2 and Key-6.dat, with and without a second key.
#[test]
fn test_written_containers_read_back() {
    let first = Dstu4145Key::generate("dstu4145-m233").unwrap();
    let second = Dstu4145Key::generate("dstu4145-m431").unwrap();
    for with_second in [false, true] {
        let second = with_second.then_some(&second);
        let expected: Vec<String> = std::iter::once(&first).chain(second).map(numbers).collect();
        let plain = first.private_key_info(second).unwrap();
        let encrypted = api::encrypt_private_key(&plain, "пароль".as_bytes(), "gost28147-cfb",
                                                 None, Some(3), None, None).unwrap();
        let key6 = api::dstu4145_key6(&first, second, "пароль".as_bytes()).unwrap();
        for (data, password) in [(&plain, &b""[..]), (&encrypted, "пароль".as_bytes()),
                                 (&key6, "пароль".as_bytes())] {
            let back = api::dstu4145_keys_open(data, password).unwrap();
            assert_eq!(back.iter().map(numbers).collect::<Vec<_>>(), expected);
        }
    }
}
