//! The PKCS#12 KDF against OpenSSL's `PKCS12KDF`, recorded in
//! `vectors/pkcs12_kdf.vec` by `scripts/make_pkcs12_kdf_vectors.py` and
//! read here offline, through the facade Python calls. The rows cross
//! the hash's block in the salt and password and its output in the
//! length, over five hashes and all three IDs.

use std::collections::HashMap;

use allcrypt::api;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_pkcs12_kdf_against_openssl() {
    let text = include_str!("../vectors/pkcs12_kdf.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let mut checked = 0;
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let fields: HashMap<&str, &str> = line.split(' ')
            .map(|w| w.split_once('=').unwrap()).collect();
        let expected = unhex(fields["out"]);
        let ours = api::pkcs12_kdf(fields["hash"], &unhex(fields["password"]),
                                   &unhex(fields["salt"]), fields["id"].parse().unwrap(),
                                   fields["iterations"].parse().unwrap(), expected.len())
            .unwrap();
        assert_eq!(ours, expected, "{line}");

        // The BMPString is what `pkcs12_bmp_password` makes of the text,
        // for every row with a password.
        let bmp = unhex(fields["password"]);
        if !bmp.is_empty() {
            let units: Vec<u16> = bmp.chunks(2).map(|p| u16::from_be_bytes([p[0], p[1]]))
                .take_while(|&u| u != 0).collect();
            let text = String::from_utf16(&units).unwrap();
            assert_eq!(api::pkcs12_bmp_password(&text), bmp, "{line}");
        }
        checked += 1;
    }
    assert_eq!(checked, declared);
    assert!(checked >= 40);
}
