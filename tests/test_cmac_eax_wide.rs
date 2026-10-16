//! CMAC and EAX over 160 to 1024 bit blocks against
//! `vectors/cmac_eax_wide.vec`, written by
//! `scripts/make_wide_cmac_eax_vectors.py`: Botan 3.6.1's published
//! Threefish-512 tests, and rows on which every one of Botan, Crypto++
//! 8.9.0 and Bouncy Castle 1.77 that has the cipher agrees. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api;
use allcrypt::block_ciphers::eax::Eax;
use allcrypt::mac::Cmac;
use allcrypt::Mac;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_cmac_eax_wide_vectors() {
    // (kind, cipher) -> (rows, witnesses as written)
    let mut seen: BTreeMap<(String, String), (usize, String)> = BTreeMap::new();
    let mut published = 0;
    for line in include_str!("../vectors/cmac_eax_wide.vec").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let kind = line.split(' ').next().unwrap();
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let cipher = f["cipher"];
        let key = unhex(f["key"]);
        let tag = unhex(f["tag"]);
        match kind {
            "cmac" => {
                let msg = unhex(f["msg"]);
                assert_eq!(api::cmac(cipher, &key, &msg).unwrap(), tag, "{line}");
                // In pieces that straddle the block boundary.
                let mut mac = Cmac::with_key(cipher, &key).unwrap();
                for chunk in msg.chunks(13) {
                    mac.update(chunk);
                }
                assert_eq!(mac.digest(), tag, "{line}");
                assert_eq!(tag.len(), mac.tag_len(), "the tag is a whole block");
            }
            "eax" => {
                let (nonce, ad, pt, ct) =
                    (unhex(f["nonce"]), unhex(f["ad"]), unhex(f["pt"]), unhex(f["ct"]));
                let name = format!("{cipher}-eax");
                let (got_ct, got_tag) = api::aead_encrypt(&name, &key, &nonce, &ad, &pt).unwrap();
                assert_eq!((&got_ct, &got_tag), (&ct, &tag), "{line}");
                assert_eq!(api::aead_decrypt(&name, &key, &nonce, &ad, &ct, &tag).unwrap(), pt);
                assert_eq!(api::aead_tag_len(&name, &key).unwrap(), tag.len());
                // A changed tag, ciphertext or header is refused.
                let mut wrong = tag.clone();
                wrong[tag.len() - 1] ^= 1;
                assert!(api::aead_decrypt(&name, &key, &nonce, &ad, &ct, &wrong).is_err());
                if !ct.is_empty() {
                    let mut wrong = ct.clone();
                    wrong[0] ^= 0x80;
                    assert!(api::aead_decrypt(&name, &key, &nonce, &ad, &wrong, &tag).is_err());
                }
                let mut other = ad.clone();
                other.push(0);
                assert!(api::aead_decrypt(&name, &key, &nonce, &other, &ct, &tag).is_err());
                // A truncated tag is the first bytes of the full one.
                let mut short = Eax::with_tag_len(cipher, &key, 8).unwrap();
                let (short_ct, short_tag) = short.encrypt(&nonce, &ad, &pt).unwrap();
                assert_eq!((short_ct, short_tag), (ct.clone(), tag[..8].to_vec()), "{line}");
            }
            other => panic!("unknown row kind {other}"),
        }
        if f["source"] == "botan-tests" {
            published += 1;
        }
        let entry = seen.entry((kind.to_string(), cipher.to_string()))
            .or_insert((0, f["witnesses"].to_string()));
        entry.0 += 1;
        assert_eq!(entry.1, f["witnesses"], "{line}");
    }

    // A parser that found nothing would pass every assertion above.
    assert_eq!(published, 2, "Botan's CMAC(Threefish-512) and Threefish-512/EAX");
    let witnesses = [
        ("threefish256", "cryptopp,bc"), ("threefish512", "botan,cryptopp,bc"),
        ("threefish1024", "cryptopp,bc"), ("shacal2", "botan,cryptopp,bc"),
        ("kalyna-256", "cryptopp,bc"), ("kalyna-512", "cryptopp,bc"),
        ("rijndael-160", "bc"), ("rijndael-192", "bc"), ("rijndael-224", "bc"),
        ("rijndael-256", "bc"),
    ];
    for (cipher, who) in witnesses {
        for kind in ["cmac", "eax"] {
            let (rows, written) = &seen[&(kind.to_string(), cipher.to_string())];
            assert!(*rows >= 8, "{kind} {cipher}: {rows} rows");
            assert_eq!(written, who, "{kind} {cipher}");
        }
    }
    assert_eq!(seen.len(), 20, "{seen:?}");
}

/// The wide names are in the AEAD catalogue, and a block size with no
/// polynomial is still refused rather than guessed: Simon's and Speck's
/// 48 and 96 bit blocks have none.
#[test]
fn test_the_catalogue_and_the_refusals() {
    for name in ["threefish256-eax", "threefish512-eax", "threefish1024-eax", "shacal2-eax",
                 "kalyna-256-eax", "kalyna-512-eax", "rijndael-160-eax", "rijndael-192-eax",
                 "rijndael-224-eax", "rijndael-256-eax"] {
        assert!(api::AEADS.contains(&name), "{name}");
    }
    for (cipher, key_len) in [("simon48", 9), ("speck96", 12)] {
        let error = api::cmac(cipher, &vec![0u8; key_len], b"x").unwrap_err();
        assert!(error.contains("bit block"), "{error}");
    }
}
