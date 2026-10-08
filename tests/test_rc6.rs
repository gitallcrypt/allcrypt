//! RC6-32/20/b against `vectors/rc6.vec`: the submission's six vectors
//! and 513 rows from Bouncy Castle's RC6Engine over every key length
//! from 1 to 64 bytes and forty-one more up to 255, written by
//! `scripts/make_rc6_vectors.py`. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::rc6::Rc6;
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_rc6_vectors() {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut lengths = std::collections::BTreeSet::new();
    for line in include_str!("../vectors/rc6.vec").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let (key, pt, ct) = (unhex(f["key"]), unhex(f["pt"]), unhex(f["ct"]));
        let mut c = Rc6::new(key.clone()).unwrap();
        let mut out = Vec::new();
        c.block_encrypt(&pt, &mut out);
        assert_eq!(out, ct, "encrypt: {line}");
        let mut back = Vec::new();
        c.block_decrypt(&ct, &mut back);
        assert_eq!(back, pt, "decrypt: {line}");
        lengths.insert(key.len());
        *counts.entry(f["source"]).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(counts.get("paper"), Some(&6));
    assert!(counts.get("bouncycastle").copied().unwrap_or(0) >= 500, "{counts:?}");
    assert!((1..=64).all(|n| lengths.contains(&n)) && lengths.contains(&255));
}

/// Through the catalogue, in every mode and at lengths around the block,
/// encrypting in irregular pieces must equal one call, and decrypting
/// must give the message back.
#[test]
fn test_rc6_through_the_catalogue_in_every_mode() {
    let key: Vec<u8> = (0..24).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 16] };
            let one = {
                let mut s = match CipherStream::new(
                    AnyBlockCipher::new("rc6", &key, None).unwrap(), mode, &iv, false) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut out = s.update(&message).unwrap();
                match s.finish() {
                    Ok(tail) => out.extend(tail),
                    // A mode that cannot take this length says so; that
                    // is checked for every cipher elsewhere.
                    Err(_) => continue,
                }
                out
            };
            let mut s = CipherStream::new(AnyBlockCipher::new("rc6", &key, None).unwrap(),
                                          mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(7) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(AnyBlockCipher::new("rc6", &key, None).unwrap(),
                                          mode, &iv, true).unwrap();
            let mut back = d.update(&one).unwrap();
            back.extend(d.finish().unwrap());
            assert_eq!(back, message, "{mode_name} {len}");
            checked += 1;
        }
    }
    // The `continue`s skip lengths a mode cannot take; most must remain.
    assert!(checked >= 60, "only {checked} mode and length pairs ran");
}
