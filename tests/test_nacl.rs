//! NaCl's boxes against `vectors/nacl.vec`: NaCl's own examples, and
//! libsodium's answers (with golang.org/x/crypto agreeing where it can)
//! over many lengths and keys. `scripts/make_nacl_vectors.py` writes the
//! file; nothing here needs either implementation.

use std::collections::HashMap;

use allcrypt::api;
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::hash_functions::HashFunction;
use allcrypt::nacl;
use allcrypt::stream_ciphers::salsa20;

struct Row {
    kind: String,
    fields: HashMap<String, String>,
}

impl Row {
    fn text(&self, name: &str) -> &str {
        self.fields.get(name).unwrap_or_else(|| panic!("{} has no {name}", self.kind))
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        let text = self.text(name);
        if text == "-" {
            return Vec::new();
        }
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn refused(&self, name: &str) -> bool {
        self.text(name) == "refused"
    }

    fn construction(&self) -> &str {
        self.text("construction")
    }
}

fn rows(kind: &str) -> Vec<Row> {
    let all: Vec<Row> = include_str!("../vectors/nacl.vec").lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let mut parts = line.split(' ');
            let kind = parts.next().unwrap().to_string();
            let fields = parts.map(|part| {
                let (name, value) = part.split_once('=').unwrap();
                (name.to_string(), value.to_string())
            }).collect();
            Row { kind, fields }
        })
        .collect();
    all.into_iter().filter(|row| row.kind == kind).collect()
}

/// The rows of a kind, asserting how many there are: a parser that finds
/// none turns every test below into an empty loop.
fn expect(kind: &str, count: usize) -> Vec<Row> {
    let found = rows(kind);
    assert_eq!(found.len(), count, "{kind} rows");
    found
}

fn from_nacl(row: &Row) -> bool {
    row.fields.get("source").map(String::as_str) == Some("nacl")
}

#[test]
fn test_hsalsa20() {
    let rows = expect("hsalsa20", 26);
    assert_eq!(rows.iter().filter(|r| from_nacl(r)).count(), 2);
    for row in rows {
        assert_eq!(api::hsalsa20(&row.bytes("key"), &row.bytes("input")).unwrap(),
                   row.bytes("out"));
    }
}

/// The keystream from a block number, including across the low counter
/// word's end - the 64 bit counter has to carry rather than wrap.
#[test]
fn test_xsalsa20_keystream() {
    for row in expect("xsalsa20", 5) {
        let mut cipher = salsa20::xsalsa20(&row.bytes("key"), &row.bytes("nonce")).unwrap();
        cipher.seek_block(row.text("block").parse().unwrap());
        let mut out = Vec::new();
        cipher.try_crypt(&[0u8; 192], &mut out).unwrap();
        assert_eq!(out, row.bytes("out"), "block {}", row.text("block"));
    }
}

/// NaCl's four megabytes of XSalsa20, hashed.
#[test]
fn test_xsalsa20_four_megabytes() {
    for row in expect("xsalsa20_sha256", 1) {
        let length: usize = row.text("length").parse().unwrap();
        let mut cipher = api::AnyStreamCipher::new("xsalsa20", &row.bytes("key"),
                                                   &row.bytes("nonce")).unwrap();
        let keystream = cipher.update(&vec![0u8; length]).unwrap();
        assert_eq!(SHA256::new(&keystream).digest(), row.bytes("sha256"));
    }
}

#[test]
fn test_secretbox() {
    let rows = expect("secretbox", 175);
    assert_eq!(rows.iter().filter(|r| from_nacl(r)).count(), 1);
    for row in rows {
        let (key, nonce, message) = (row.bytes("key"), row.bytes("nonce"), row.bytes("message"));
        let boxed = row.bytes("boxed");
        let what = format!("{} {}", row.construction(), message.len());
        assert_eq!(api::secretbox_encrypt(&key, &nonce, &message, row.construction()).unwrap(),
                   boxed, "{what}");
        assert_eq!(api::secretbox_decrypt(&key, &nonce, &boxed, row.construction()).unwrap(),
                   message, "{what}");
        let (ciphertext, tag) = api::secretbox_encrypt_detached(&key, &nonce, &message,
                                                                row.construction()).unwrap();
        assert_eq!(tag, boxed[..16]);
        assert_eq!(ciphertext, boxed[16..]);
        assert_eq!(api::secretbox_decrypt_detached(&key, &nonce, &ciphertext, &tag,
                                                   row.construction()).unwrap(), message);
        let mut bad = boxed.clone();
        bad[0] ^= 0x80;
        assert!(api::secretbox_decrypt(&key, &nonce, &bad, row.construction()).is_err());
    }
}

/// The box key, and the low-order peer keys libsodium refuses: all seven
/// of its list, for both constructions.
#[test]
fn test_beforenm() {
    let rows = expect("beforenm", 47);
    assert_eq!(rows.iter().filter(|r| r.refused("key")).count(), 14);
    for row in rows {
        let result = api::box_beforenm(&row.bytes("public"), &row.bytes("private"),
                                       row.construction());
        if row.refused("key") {
            assert!(result.is_err(), "{} accepted", row.text("public"));
        } else {
            assert_eq!(result.unwrap(), row.bytes("key"));
        }
    }
}

#[test]
fn test_box() {
    let rows = expect("box", 33);
    for row in rows {
        let (public, private) = (row.bytes("public"), row.bytes("private"));
        let (nonce, message, boxed) = (row.bytes("nonce"), row.bytes("message"),
                                       row.bytes("boxed"));
        assert_eq!(api::box_encrypt(&public, &private, &nonce, &message, row.construction())
                   .unwrap(), boxed);
        // The key is the same from either side, so the pair that sealed it
        // can open it too.
        assert_eq!(api::box_decrypt(&public, &private, &nonce, &boxed, row.construction())
                   .unwrap(), message);
    }
}

/// NaCl's box opened by Bob, the other side of the paper's example.
#[test]
fn test_box_opened_by_the_recipient() {
    for row in expect("box_open", 1) {
        assert_eq!(api::box_decrypt(&row.bytes("public"), &row.bytes("private"),
                                    &row.bytes("nonce"), &row.bytes("boxed"),
                                    row.construction()).unwrap(),
                   row.bytes("message"));
    }
}

/// Sealed boxes with a known ephemeral key: ours byte for byte, and
/// libsodium's opened here.
#[test]
fn test_sealed_boxes() {
    for row in expect("seal", 32) {
        let construction = nacl::Construction::from_name(row.construction()).unwrap();
        let (public, private) = (row.bytes("public"), row.bytes("private"));
        let (message, sealed) = (row.bytes("message"), row.bytes("sealed"));
        assert_eq!(nacl::box_seal_with_ephemeral(construction, &public, &message,
                                                 &row.bytes("ephemeral_private")).unwrap(),
                   sealed);
        assert_eq!(api::box_seal_open(&public, &private, &sealed, row.construction()).unwrap(),
                   message);
    }
}

#[test]
fn test_seed_key_pairs() {
    for (kind, derive) in [("box_seed_keypair", api::box_seed_keypair as fn(&[u8]) -> _),
                           ("kx_seed_keypair", api::kx_seed_keypair)] {
        for row in expect(kind, 16) {
            let (private, public) = derive(&row.bytes("seed")).unwrap();
            assert_eq!(private, row.bytes("private"), "{kind}");
            assert_eq!(public, row.bytes("public"), "{kind}");
        }
    }
}

#[test]
fn test_kx_session_keys() {
    for row in expect("kx", 16) {
        let (client_public, client_private) = (row.bytes("client_public"),
                                               row.bytes("client_private"));
        let (server_public, server_private) = (row.bytes("server_public"),
                                               row.bytes("server_private"));
        let (rx, tx) = api::kx_client_session_keys(&client_public, &client_private,
                                                   &server_public).unwrap();
        assert_eq!((rx.clone(), tx.clone()), (row.bytes("client_rx"), row.bytes("client_tx")));
        assert_eq!(api::kx_server_session_keys(&server_public, &server_private,
                                               &client_public).unwrap(), (tx, rx));
    }
}

#[test]
fn test_auth() {
    for row in expect("auth", 8) {
        let (key, message, tag) = (row.bytes("key"), row.bytes("message"), row.bytes("tag"));
        assert_eq!(api::nacl_auth(&key, &message).unwrap(), tag);
        assert!(api::nacl_auth_verify(&key, &message, &tag).unwrap());
        let mut bad = tag.clone();
        bad[31] ^= 1;
        assert!(!api::nacl_auth_verify(&key, &message, &bad).unwrap());
    }
}

#[test]
fn test_combined_signatures() {
    for row in expect("sign", 8) {
        let (seed, public) = (row.bytes("seed"), row.bytes("public"));
        let signed = row.bytes("signed");
        assert_eq!(api::nacl_sign(&seed, &row.bytes("message")).unwrap(), signed);
        // libsodium's 64 byte form of the same key.
        let mut long = seed.clone();
        long.extend_from_slice(&public);
        assert_eq!(api::nacl_sign(&long, &row.bytes("message")).unwrap(), signed);
        assert_eq!(api::nacl_sign_open(&public, &signed).unwrap(), row.bytes("message"));
    }
}

#[test]
fn test_ed25519_key_conversion() {
    for row in expect("ed25519_to_x25519", 16) {
        assert_eq!(api::ed25519_private_to_x25519(&row.bytes("seed")).unwrap(),
                   row.bytes("x_private"));
        assert_eq!(api::ed25519_public_to_x25519(&row.bytes("ed_public")).unwrap(),
                   row.bytes("x_public"));
        assert_eq!(api::x25519_public_key(&row.bytes("x_private")).unwrap(),
                   row.bytes("x_public"));
    }
}

/// Inputs that are not ordinary keys: strings that are not points, the
/// small-order points, a non-canonical `y`, and keys with a torsion
/// component - accepted and refused exactly where libsodium does.
#[test]
fn test_ed25519_public_conversion_refusals() {
    let rows = expect("ed25519_public_to_x25519", 33);
    let refused = rows.iter().filter(|r| r.refused("x_public")).count();
    assert!(refused > 0 && refused < rows.len(), "{refused} of {} refused", rows.len());
    for row in rows {
        let result = api::ed25519_public_to_x25519(&row.bytes("ed_public"));
        if row.refused("x_public") {
            assert!(result.is_err(), "{} accepted", row.text("ed_public"));
        } else {
            assert_eq!(result.unwrap(), row.bytes("x_public"), "{}", row.text("ed_public"));
        }
    }
}
