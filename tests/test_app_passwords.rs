//! The database and forum password hashes against
//! `vectors/app_passwords.vec`: MariaDB's compiled `hash_password`,
//! WordPress 6.4's `class-phpass.php`, and PHP's own md5/sha1 in each
//! scheme's construction, recorded by
//! `scripts/make_app_password_vectors.py`. Offline.

use std::collections::HashMap;

use allcrypt::kdf::app_passwords::{
    mysql_old_password, mysql_password, phpass, phpass_verify, postgres_md5, vbulletin,
};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_app_password_vectors() {
    let text = include_str!("../vectors/app_passwords.vec");
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let mut words = line.split(' ');
        let scheme = words.next().unwrap();
        let f: HashMap<&str, &str> = words.map(|w| w.split_once('=').unwrap()).collect();
        let pw = unhex(f["password"]);
        match scheme {
            "mysql_old" => assert_eq!(mysql_old_password(&pw), f["hash"], "{line}"),
            "mysql_password" => assert_eq!(mysql_password(&pw), f["hash"], "{line}"),
            "postgres_md5" => assert_eq!(postgres_md5(&pw, &unhex(f["user"])), f["hash"], "{line}"),
            "vbulletin" => assert_eq!(vbulletin(&pw, &unhex(f["salt"])), f["hash"], "{line}"),
            "phpass" => {
                let got = phpass(&pw, f["setting"]).unwrap_or_else(|e| panic!("{line}: {e}"));
                assert_eq!(got, f["hash"], "{line}");
                // verify() reads the setting out of the stored hash.
                assert!(phpass_verify(&pw, f["hash"]), "verify {line}");
            }
            other => panic!("unknown scheme {other}"),
        }
        *counts.entry(scheme).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    for scheme in ["mysql_old", "mysql_password", "postgres_md5", "vbulletin", "phpass"] {
        assert!(counts.get(scheme).copied().unwrap_or(0) >= 8,
                "too few {scheme} rows: {:?}", counts.get(scheme));
    }
}

/// A one-byte change in the password must change every scheme's output -
/// the positive vectors alone would pass a function that ignored its
/// input past the salt.
#[test]
fn test_a_different_password_gives_a_different_hash() {
    assert_ne!(mysql_old_password(b"secret"), mysql_old_password(b"Secret"));
    assert_ne!(mysql_password(b"secret"), mysql_password(b"Secret"));
    assert_ne!(postgres_md5(b"secret", b"u"), postgres_md5(b"Secret", b"u"));
    // Same password, same salt, different salt -> different hash.
    assert_ne!(vbulletin(b"secret", b"s"), vbulletin(b"secret", b"t"));
    assert!(!phpass_verify(b"Secret", &phpass(b"secret", "$P$Bsaltsalt").unwrap()));
}

/// PostgreSQL's token binds the username: the same password under two
/// names hashes differently, which is why a renamed role must have its
/// password reset.
#[test]
fn test_postgres_binds_the_username() {
    assert_ne!(postgres_md5(b"hunter2", b"alice"), postgres_md5(b"hunter2", b"bob"));
}
