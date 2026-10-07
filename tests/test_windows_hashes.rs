/*!
`vectors/windows_hashes.vec` against the NT and LM hashes. The LM rows are
Samba 4.9's and impacket's answers, kept where the two agree; the NT rows
are OpenSSL's MD4 of the UTF-16LE password. The file's header says how
each was made.
*/

use allcrypt::api;
use allcrypt::kdf::windows::{lm_hash, nt_hash};

const VECTORS: &str = include_str!("../vectors/windows_hashes.vec");

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// (section, password, hash) for every row.
fn rows() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut section = String::new();
    let mut password = None;
    let mut out = Vec::new();
    for line in VECTORS.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(|c| c == '[' || c == ']').to_string();
            continue;
        }
        let (key, value) = line.split_once(" = ").unwrap();
        match key {
            "password" => password = Some(unhex(value)),
            "hash" => out.push((section.clone(), password.take().unwrap(), unhex(value))),
            other => panic!("unexpected field {other}"),
        }
    }
    out
}

#[test]
fn test_samba_and_impackets_lm_hashes() {
    let lm: Vec<_> = rows().into_iter().filter(|(s, _, _)| s == "LM").collect();
    assert_eq!(lm.len(), 78);
    for (_, password, hash) in lm {
        assert_eq!(lm_hash(&password).unwrap().to_vec(), hash, "{password:02x?}");
        assert_eq!(api::lm_hash(&password).unwrap(), hash, "{password:02x?}");
    }
}

#[test]
fn test_openssls_md4_of_the_utf16_password() {
    let nt: Vec<_> = rows().into_iter().filter(|(s, _, _)| s == "NT").collect();
    assert_eq!(nt.len(), 10);
    for (_, password, hash) in nt {
        let text = String::from_utf8(password).unwrap();
        assert_eq!(nt_hash(&text).to_vec(), hash, "{text}");
        assert_eq!(api::nt_hash(&text), hash, "{text}");
    }
}

/// The empty password's LM hash is the value Windows stores in place of
/// one, and the file has it.
#[test]
fn test_the_no_lm_hash_value_is_in_the_file() {
    assert!(rows().iter().any(|(s, p, h)| s == "LM" && p.is_empty()
                                    && h[..] == unhex("aad3b435b51404eeaad3b435b51404ee")[..]));
}
