//! Kerberos RC4-HMAC (RFC 4757) against `vectors/rc4_hmac.vec`, written by
//! `scripts/make_rc4_hmac_vectors.py`: ciphertexts MIT Kerberos 1.21.3 and
//! Apache Kerby made under their own confounders and the others opened,
//! with impacket making the type 23 ones again from the confounder; and
//! the -138 checksum, the PRF and string-to-key, all three agreeing.
//! Through the API, as Python and C reach it. Offline.

use std::collections::HashMap;

use allcrypt::api::{kerberos_rc4_hmac_checksum, kerberos_rc4_hmac_decrypt,
                    kerberos_rc4_hmac_encrypt, kerberos_rc4_hmac_prf,
                    kerberos_rc4_hmac_string_to_key};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    let text = include_str!("../vectors/rc4_hmac.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: ")).unwrap()
        .parse().unwrap();
    assert_eq!(text.lines().filter(|l| !l.starts_with('#')).count(), declared);
    text.lines().filter(|l| l.starts_with(&format!("{kind} ")))
        .map(|l| l.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

#[test]
fn test_every_ciphertext() {
    let (mut by_type, mut usages) = (HashMap::new(), Vec::new());
    for r in rows("encrypt") {
        let export = match r["enctype"] { "23" => false, "24" => true, other => panic!("{other}") };
        let (key, usage) = (unhex(r["key"]), r["usage"].parse::<u32>().unwrap());
        let (plain, cipher) = (unhex(r["plain"]), unhex(r["cipher"]));
        let confounder = unhex(r["confounder"]);
        assert_eq!(kerberos_rc4_hmac_encrypt(&key, usage, &plain, Some(&confounder), export)
                       .unwrap(), cipher, "{} {usage} {}", r["enctype"], plain.len());
        assert_eq!(kerberos_rc4_hmac_decrypt(&key, usage, &cipher, export).unwrap(), plain);
        // The other type, and a changed byte, do not open it.
        assert!(kerberos_rc4_hmac_decrypt(&key, usage, &cipher, !export).is_err());
        let mut bad = cipher.clone();
        let at = (usage as usize + plain.len()) % bad.len();
        bad[at] ^= 0x10;
        assert!(kerberos_rc4_hmac_decrypt(&key, usage, &bad, export).is_err());
        // At least two implementations stand behind every row.
        assert!(r["witnesses"].split(',').count() >= 2);
        *by_type.entry(r["enctype"]).or_insert(0) += 1;
        if !usages.contains(&usage) {
            usages.push(usage);
        }
    }
    assert_eq!((by_type["23"], by_type["24"]), (182, 182));
    for usage in [3, 9, 13, 23] {
        assert!(usages.contains(&usage), "{usage}");
    }
}

#[test]
fn test_checksums_prf_and_keys() {
    let sums = rows("checksum");
    assert_eq!(sums.len(), 70);
    for r in sums {
        let usage = r["usage"].parse().unwrap();
        assert_eq!(kerberos_rc4_hmac_checksum(&unhex(r["key"]), usage, &unhex(r["data"]))
                       .unwrap(), unhex(r["checksum"]));
    }
    let prfs = rows("prf");
    assert_eq!(prfs.len(), 8);
    for r in prfs {
        assert_eq!(kerberos_rc4_hmac_prf(&unhex(r["key"]), &unhex(r["input"])).unwrap(),
                   unhex(r["output"]));
    }
    let keys = rows("s2k");
    assert_eq!(keys.len(), 16);
    let mut outside_the_bmp = 0;
    for r in keys {
        let password = String::from_utf8(unhex(r["password"])).unwrap();
        outside_the_bmp += usize::from(password.chars().any(|c| c as u32 > 0xffff));
        assert_eq!(kerberos_rc4_hmac_string_to_key(&password), unhex(r["key"]), "{password:?}");
    }
    // A surrogate pair in the UTF-16 is part of what the rows check.
    assert!(outside_the_bmp >= 2);
}

#[test]
fn test_a_drawn_confounder() {
    let key = kerberos_rc4_hmac_string_to_key("password");
    let a = kerberos_rc4_hmac_encrypt(&key, 7, b"message", None, false).unwrap();
    let b = kerberos_rc4_hmac_encrypt(&key, 7, b"message", None, false).unwrap();
    assert_ne!(a, b);
    assert_eq!(kerberos_rc4_hmac_decrypt(&key, 7, &a, false).unwrap(), b"message");
    assert_eq!(kerberos_rc4_hmac_decrypt(&key, 7, &b, false).unwrap(), b"message");
    assert!(kerberos_rc4_hmac_encrypt(&key, 7, b"m", Some(&[0; 7]), false).is_err());
}
