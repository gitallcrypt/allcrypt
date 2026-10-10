//! CAST-256 against `vectors/cast256.vec`: 410 rows from Bouncy Castle's
//! CAST6Engine over all five key lengths, written by
//! `scripts/make_cast256_vectors.py`, which first requires Bouncy Castle
//! to reproduce RFC 2612's Appendix A. The appendix itself, with every
//! quad-round's keys and output, is checked in `src/block_ciphers/cast256.rs`.
//! Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::cast256::Cast256;
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_cast256_vectors() {
    let mut per_length: BTreeMap<usize, usize> = BTreeMap::new();
    for line in include_str!("../vectors/cast256.vec").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let (key, pt, ct) = (unhex(f["key"]), unhex(f["pt"]), unhex(f["ct"]));
        let mut c = Cast256::new(&key).unwrap();
        let mut out = Vec::new();
        c.block_encrypt(&pt, &mut out);
        assert_eq!(out, ct, "encrypt: {line}");
        let mut back = Vec::new();
        c.block_decrypt(&ct, &mut back);
        assert_eq!(back, pt, "decrypt: {line}");
        *per_length.entry(key.len()).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(per_length.keys().copied().collect::<Vec<_>>(), vec![16, 20, 24, 28, 32]);
    assert!(per_length.values().all(|&n| n >= 80), "{per_length:?}");
}

/// Through the catalogue, in every mode and at lengths around the block,
/// encrypting in irregular pieces must equal one call, and decrypting
/// must give the message back.
#[test]
fn test_cast256_through_the_catalogue_in_every_mode() {
    let key: Vec<u8> = (0..28).collect();
    let mut checked = 0;
    for mode_name in allcrypt::api::MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
            let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
            let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; 16] };
            let one = {
                let mut s = match CipherStream::new(
                    AnyBlockCipher::new("cast256", &key, None).unwrap(), mode, &iv, false) {
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
            let mut s = CipherStream::new(AnyBlockCipher::new("cast256", &key, None).unwrap(),
                                          mode, &iv, false).unwrap();
            let mut pieces = Vec::new();
            for chunk in message.chunks(7) {
                pieces.extend(s.update(chunk).unwrap());
            }
            pieces.extend(s.finish().unwrap());
            assert_eq!(pieces, one, "{mode_name} {len}");
            let mut d = CipherStream::new(AnyBlockCipher::new("cast256", &key, None).unwrap(),
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
