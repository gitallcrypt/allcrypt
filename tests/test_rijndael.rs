//! Rijndael against `vectors/rijndael.vec`: eleven rows for each of the
//! 25 pairs of block and key size, every one an answer Bouncy Castle
//! 1.77 and phpseclib 1.0.23 agree on, written by
//! `scripts/make_rijndael_vectors.py`. That the 128 bit block is AES is
//! checked in `src/block_ciphers/rijndael.rs`. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::rijndael::Rijndael;
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

const SIZES: [usize; 5] = [16, 20, 24, 28, 32];

#[test]
fn test_rijndael_vectors() {
    let mut per_pair: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    for line in include_str!("../vectors/rijndael.vec").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let block: usize = f["block"].parse().unwrap();
        let (key, pt, ct) = (unhex(f["key"]), unhex(f["pt"]), unhex(f["ct"]));
        assert_eq!((pt.len(), ct.len()), (block, block), "{line}");

        let mut c = Rijndael::new(block, key.clone()).unwrap();
        let mut out = Vec::new();
        c.block_encrypt(&pt, &mut out);
        assert_eq!(out, ct, "encrypt: {line}");
        let mut back = Vec::new();
        c.block_decrypt(&ct, &mut back);
        assert_eq!(back, pt, "decrypt: {line}");

        // And the same row through the catalogue name.
        let name = format!("rijndael-{}", block * 8);
        let mut any = AnyBlockCipher::new(&name, &key, None).unwrap();
        assert_eq!(any.name(), name);
        assert_eq!(any.blocksize(), block);
        let mut via = Vec::new();
        any.block_encrypt(&pt, &mut via);
        assert_eq!(via, ct, "catalogue: {line}");

        *per_pair.entry((block, key.len())).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    let want: Vec<(usize, usize)> = SIZES.iter()
        .flat_map(|&b| SIZES.iter().map(move |&k| (b, k))).collect();
    assert_eq!(per_pair.keys().copied().collect::<Vec<_>>(), want);
    assert!(per_pair.values().all(|&n| n >= 11), "{per_pair:?}");
}

/// Every block size through the catalogue, in every mode and at lengths
/// around the block: encrypting in irregular pieces equals one call, and
/// decrypting gives the message back. The IV is one block, so a mode
/// that assumed sixteen bytes fails here.
#[test]
fn test_rijndael_through_the_catalogue_in_every_mode() {
    let key: Vec<u8> = (0..20).collect();
    let mut checked = 0;
    for block in SIZES {
        let name = format!("rijndael-{}", block * 8);
        for mode_name in allcrypt::api::MODES {
            let mode = Mode::from_name(mode_name).unwrap();
            for len in [0usize, 1, block - 1, block, block + 1, 2 * block + 3, 100] {
                let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
                let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; block] };
                let new = || AnyBlockCipher::new(&name, &key, None).unwrap();
                let one = {
                    let mut s = CipherStream::new(new(), mode, &iv, false).unwrap();
                    let mut out = s.update(&message).unwrap();
                    match s.finish() {
                        Ok(tail) => out.extend(tail),
                        // ECB and CBC take whole blocks only.
                        Err(_) => continue,
                    }
                    out
                };
                assert_eq!(one.len(), len, "{name} {mode_name} {len}");
                let mut s = CipherStream::new(new(), mode, &iv, false).unwrap();
                let mut pieces = Vec::new();
                for chunk in message.chunks(7) {
                    pieces.extend(s.update(chunk).unwrap());
                }
                pieces.extend(s.finish().unwrap());
                assert_eq!(pieces, one, "{name} {mode_name} {len}");
                let mut d = CipherStream::new(new(), mode, &iv, true).unwrap();
                let mut back = d.update(&one).unwrap();
                back.extend(d.finish().unwrap());
                assert_eq!(back, message, "{name} {mode_name} {len}");
                checked += 1;
            }
        }
    }
    assert!(checked >= 120, "only {checked} cases ran");
}

/// A block size wider than 128 bits has no CMAC: SP 800-38B defines Rb
/// for 64 and 128 bit blocks only, and a guessed polynomial would be a
/// MAC nobody else computes.
#[test]
fn test_cmac_refuses_the_wide_blocks() {
    use allcrypt::mac::cmac::Cmac;
    for bits in [160, 192, 224, 256] {
        let cipher = AnyBlockCipher::new(&format!("rijndael-{bits}"), &[0u8; 16], None).unwrap();
        assert!(Cmac::new(cipher).is_err(), "{bits}");
    }
    let cipher = AnyBlockCipher::new("rijndael-128", &[0u8; 16], None).unwrap();
    assert!(Cmac::new(cipher).is_ok());
}

#[test]
fn test_rijndael_refuses_other_key_lengths() {
    for length in [0usize, 8, 15, 17, 21, 33] {
        assert!(AnyBlockCipher::new("rijndael-256", &vec![0u8; length], None).is_err(),
                "{length}");
    }
    assert!(Rijndael::new(36, vec![0; 16]).is_err());
}
