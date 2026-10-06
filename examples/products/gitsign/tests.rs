//! Commits and tags OpenSSH's `ssh-keygen` and GnuPG signed through git,
//! replayed: `scripts/check_gitsign.py` recorded them with the keys that
//! check them.

use super::*;

use crate::fixtures;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixtures::dir().join("gitsign").join(name)).unwrap()
}

/// Every recorded object: its file, the file of what checks it, and its
/// format.
fn objects() -> Vec<(String, Vec<u8>, String, &'static str)> {
    let mut out = Vec::new();
    for section in ["ssh", "openpgp"] {
        for record in fixtures::records("gitsign/gitsign.vec", section) {
            let keys = String::from_utf8(fixture(fixtures::field(&record, "keys"))).unwrap();
            for kind in ["commit", "tag"] {
                let name = fixtures::field(&record, kind).to_string();
                out.push((name.clone(), fixture(&name), keys.clone(), section));
            }
        }
    }
    out
}

/// Ours's verdict on an object, with the keys recorded beside it.
fn verdict(object: &[u8], keys: &str, format: &str) -> Result<bool, String> {
    let (payload, signature) = object::split(object, false)?.ok_or("unsigned")?;
    assert_eq!(object::format_of(&signature), Some(format));
    if format == "ssh" {
        let signers = ssh::read_allowed_signers(keys)?;
        let armoured = String::from_utf8_lossy(&signature).to_string();
        let time = signing_time(&payload);
        let principals = ssh::find_principals(&signers, &armoured, time)?;
        Ok(principals.iter().any(|p| ssh::verify(&signers, p, "git", &armoured, &payload, time)
                                    .is_ok()))
    } else {
        let packets = packet::parse(&armor::dearmor(keys.as_bytes())?)?;
        let certs = keys::Cert::read_all(&packets)?;
        Ok(pgp::check(&signature, &payload, &certs, now())?.good)
    }
}

#[test]
fn test_objects_git_signed_verify() {
    let all = objects();
    assert_eq!(all.len(), 24);
    for (name, object, keys, format) in all {
        assert!(verdict(&object, &keys, format).unwrap(), "{name}");
    }
}

/// Taking the signature out and putting it back gives git's bytes: the
/// header's continuation lines and the tag's tail are where git puts
/// them.
#[test]
fn test_objects_reassemble_byte_for_byte() {
    for (name, object, _, _) in objects() {
        let (payload, signature) = object::split(&object, false).unwrap().unwrap();
        assert_eq!(object::insert(&payload, &signature, false).unwrap(), object, "{name}");
    }
}

#[test]
fn test_a_changed_object_is_refused() {
    for (name, object, keys, format) in objects() {
        // The committer's or tagger's name changed: in the payload, not
        // the signature.
        let text = String::from_utf8(object.clone()).unwrap();
        let changed = text.replacen("Alice", "Alicf", 1);
        assert_ne!(changed, text);
        assert!(!verdict(changed.as_bytes(), &keys, format).unwrap_or(false), "{name}");
    }
}

/// An allowed signers file's dates are judged at the commit's time, as
/// git passes it in `verify-time`.
#[test]
fn test_validity_is_judged_at_signing_time() {
    let (_, object, keys, _) = objects().into_iter().find(|o| o.3 == "ssh").unwrap();
    let (payload, signature) = object::split(&object, false).unwrap().unwrap();
    let time = signing_time(&payload).unwrap();
    let armoured = String::from_utf8_lossy(&signature).to_string();
    let line = keys.trim_end();
    let (principal, rest) = line.split_once(' ').unwrap();
    let dated = |after: u64, before: u64| {
        let date = |t: u64| {
            let days = (t / 86400) as i64 + 719468;
            let era = days.div_euclid(146097);
            let doe = days - era * 146097;
            let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let y = yoe + era * 400 + i64::from(m <= 2);
            format!("{y:04}{m:02}{d:02}")
        };
        format!("{principal} valid-after=\"{}\",valid-before=\"{}\" {}", date(after),
                date(before), rest.split_once(' ').map_or(rest, |(_, k)| k))
    };
    let around = dated(time - 86400 * 2, time + 86400 * 2);
    let signers = ssh::read_allowed_signers(&around).unwrap();
    assert!(ssh::verify(&signers, "alice@example.com", "git", &armoured, &payload, Some(time))
        .is_ok(), "{around}");
    let later = dated(time + 86400 * 2, time + 86400 * 9);
    let signers = ssh::read_allowed_signers(&later).unwrap();
    assert!(ssh::verify(&signers, "alice@example.com", "git", &armoured, &payload, Some(time))
        .is_err(), "{later}");
}

#[test]
fn test_the_signing_time_is_the_committers() {
    let commit = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                   author A <a@example.com> 1000 +0000\n\
                   committer C <c@example.com> 2000 -0700\n\nmessage 3000 +0000\n";
    assert_eq!(signing_time(commit), Some(2000));
}

/// OpenSSH's `ssh-keygen -Y sign` of a payload, with the key it used:
/// Ed25519 is deterministic and SSHSIG hashes with SHA-512 by default,
/// so ours gives the same bytes.
#[test]
fn test_an_ssh_signature_is_openssh_s_byte_for_byte() {
    let dir = fixtures::dir().join("gitsign");
    let key = ssh::read_private(dir.join("ssh-signing.key").to_str().unwrap(), None).unwrap();
    let payload = fixture("ssh-signing.payload");
    let theirs = String::from_utf8(fixture("ssh-signing.sig")).unwrap();
    assert_eq!(ssh::sign(&key, "git", &payload).unwrap(), theirs);
}

#[test]
fn test_verify_needs_the_principal() {
    let (_, object, keys, _) = objects().into_iter().find(|o| o.3 == "ssh").unwrap();
    let (payload, signature) = object::split(&object, false).unwrap().unwrap();
    let signers = ssh::read_allowed_signers(&keys).unwrap();
    let armoured = String::from_utf8_lossy(&signature).to_string();
    assert!(ssh::verify(&signers, "alice@example.com", "git", &armoured, &payload, None).is_ok());
    assert!(ssh::verify(&signers, "mallory@example.com", "git", &armoured, &payload, None)
        .is_err());
    assert!(ssh::verify(&signers, "alice@example.com", "file", &armoured, &payload, None)
        .is_err());
}

/// git's `parse_signed_buffer` takes the last line that starts a
/// signature: a message may quote one.
#[test]
fn test_a_tag_quoting_a_signature_splits_at_the_last() {
    let (_, object, _, _) = objects().into_iter().find(|o| o.0.ends_with(".tag")).unwrap();
    let (payload, signature) = object::split(&object, false).unwrap().unwrap();
    let quoting = [&payload[..], b"-----BEGIN SSH SIGNATURE-----\nquoted\n"].concat();
    let signed = [&quoting[..], &signature[..]].concat();
    assert_eq!(object::split(&signed, false).unwrap(), Some((quoting, signature)));
}

/// GOODSIG names the long key ID: a version 4 fingerprint's last 16 hex
/// digits (RFC 9580 section 5.5.4.2), as the key's own ID says.
#[test]
fn test_the_long_key_id() {
    for record in fixtures::records("gitsign/gitsign.vec", "openpgp") {
        let text = fixture(fixtures::field(&record, "keys"));
        let certs = keys::Cert::read_all(&packet::parse(&armor::dearmor(&text).unwrap()).unwrap())
            .unwrap();
        let public = &certs[0].primary.public;
        let fingerprint = keys::hex_upper(&public.fingerprint());
        assert_eq!(pgp::long_key_id(&fingerprint), keys::hex_upper(&public.key_id()));
    }
}
