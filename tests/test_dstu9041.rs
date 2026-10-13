//! DSTU 9041:2020 against `vectors/dstu9041.vec`, written by
//! `scripts/make_dstu9041_vectors.py`: the standard's worked examples Г.1
//! and Г.3, public keys, and ciphertexts at every whole number of bytes
//! on which uacrypt's `hazmat::dstu9041` and li0ard's `dstu9041` agree,
//! messages of lengths in bits that uacrypt encrypts and li0ard decrypts,
//! and ciphertexts both refuse. Offline.

use std::collections::BTreeMap;

use allcrypt::bignum::BigUint;
use allcrypt::ec::dstu9041::{Curve, NAMES};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rows() -> Vec<BTreeMap<&'static str, &'static str>> {
    include_str!("../vectors/dstu9041.vec").lines()
        .filter(|l| l.starts_with("dstu9041 "))
        .map(|l| l.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

#[test]
fn test_dstu9041_vectors() {
    let mut counts: BTreeMap<(&str, &str, &str), usize> = BTreeMap::new();
    for f in rows() {
        let curve = Curve::by_name(f["curve"]).unwrap();
        let private = unhex(f["private"]);
        let kind = if f.contains_key("refused") {
            let refused = curve.decrypt(&private, &unhex(f["ciphertext"]));
            assert!(refused.is_err(), "{} {}", f["curve"], f["refused"]);
            "refused"
        } else if f.contains_key("ciphertext") {
            let (public, message) = (unhex(f["public"]), unhex(f["message"]));
            let bits: usize = f["bits"].parse().unwrap();
            let ciphertext = unhex(f["ciphertext"]);
            assert_eq!(curve.public_key(&private).unwrap(), public);
            assert_eq!(curve.encrypt(&public, &message, bits, &unhex(f["epsilon"])).unwrap(),
                       ciphertext, "{} {bits} bits", f["curve"]);
            assert_eq!(curve.decrypt(&private, &ciphertext).unwrap(), (message, bits));
            "ciphertext"
        } else {
            assert_eq!(curve.public_key(&private).unwrap(), unhex(f["public"]));
            "public"
        };
        *counts.entry((f["curve"], kind, f["source"])).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    for (name, whole_bytes) in [("dstu9041-e256-1", 25), ("dstu9041-e512-1", 53)] {
        assert_eq!(counts[&(name, "public", "standard")], 1);
        assert_eq!(counts[&(name, "ciphertext", "standard")], 1);
        assert_eq!(counts[&(name, "public", "both")], 12);
        assert_eq!(counts[&(name, "ciphertext", "both")], whole_bytes + 4);
        assert_eq!(counts[&(name, "ciphertext", "uacrypt")], 7);
        assert_eq!(counts[&(name, "refused", "both")], 10);
    }
}

/// A ciphertext with one bit flipped is refused, with the one error:
/// the low and high bit of `r`'s first and last bytes and of every
/// eighth byte of `t`.
#[test]
fn test_flipped_bits_are_refused() {
    for f in rows().into_iter().filter(|f| f["source"] == "standard"
                                          && f.contains_key("ciphertext")) {
        let curve = Curve::by_name(f["curve"]).unwrap();
        let private = unhex(f["private"]);
        let good = unhex(f["ciphertext"]);
        let mut errors = std::collections::BTreeSet::new();
        let width = curve.field_bytes();
        let bytes = [0, width - 1].into_iter().chain((width..good.len()).step_by(8));
        for (byte, bit) in bytes.flat_map(|i| [(i, 0), (i, 7)]) {
            let mut bad = good.clone();
            bad[byte] ^= 1 << bit;
            errors.insert(curve.decrypt(&private, &bad).unwrap_err());
        }
        assert_eq!(errors.len(), 1, "{}: {errors:?}", f["curve"]);
    }
}

#[test]
fn test_round_trips_at_lengths_in_bits() {
    let curve = Curve::by_name("dstu9041-e256-1").unwrap();
    let private = [0x2au8; 32];
    let public = curve.public_key(&private).unwrap();
    // Each length up to two bytes and more, and the longest ones.
    let lengths = (1..=curve.max_message_bits()).filter(|&b| b <= 17 || b % 23 == 0 || b >= 193);
    for bits in lengths {
        let mut message = vec![0xa5u8; bits.div_ceil(8)];
        message[0] &= 0xff >> ((8 - bits % 8) % 8);
        let mut epsilon = [0x33u8; 32];
        epsilon[31] = bits as u8;
        let ciphertext = curve.encrypt(&public, &message, bits, &epsilon).unwrap();
        assert_eq!(ciphertext.len(), curve.ciphertext_bytes());
        assert_eq!(curve.decrypt(&private, &ciphertext).unwrap(), (message, bits));
    }
}

#[test]
fn test_public_keys_are_checked() {
    for name in NAMES {
        let curve = Curve::by_name(name).unwrap();
        let width = curve.field_bytes();
        let public = curve.public_key(&[7]).unwrap();
        assert!(curve.check_public_key(&public).is_ok());
        // Off the curve.
        let mut off = public.clone();
        off[2 * width - 1] ^= 1;
        assert!(curve.check_public_key(&off).is_err());
        // The identity, (1, 0).
        let mut identity = vec![0u8; 2 * width];
        identity[width - 1] = 1;
        assert!(curve.check_public_key(&identity).is_err());
        // The point of order 2, (p - 1, 0): on the curve, not of order n.
        let p_minus_1 = curve.modulus().sub(&BigUint::one()).unwrap()
            .to_bytes_be_padded(width).unwrap();
        let mut two = p_minus_1.clone();
        two.resize(2 * width, 0);
        assert!(curve.check_public_key(&two).is_err());
        // Wrong lengths.
        assert!(curve.check_public_key(&public[1..]).is_err());
        assert!(curve.encrypt(&off, &[1], 8, &[9]).is_err());
    }
}

#[test]
fn test_the_names() {
    assert!(Curve::by_name("E256/1").is_ok());
    assert!(Curve::by_name("e512/1").is_ok());
    assert!(Curve::by_name("dstu9041-e384-1").is_err());
    for name in NAMES {
        assert_eq!(Curve::by_name(name).unwrap().name(), name);
    }
}

/// The key objects: a short private key comes back at the field's width,
/// and a fresh key pair round trips.
#[test]
fn test_the_api_keys() {
    use allcrypt::api::{Dstu9041Key, Dstu9041PublicKey, DSTU9041_CURVES};
    assert_eq!(DSTU9041_CURVES, NAMES);
    for (name, width) in [("dstu9041-e256-1", 32), ("dstu9041-e512-1", 64)] {
        let key = Dstu9041Key::from_private(name, &[0x25]).unwrap();
        let private = key.private_bytes();
        assert_eq!(private.len(), width);
        assert_eq!(private[width - 1], 0x25);
        assert!(private[..width - 1].iter().all(|&b| b == 0));
        let fresh = Dstu9041Key::generate(name).unwrap();
        let public = Dstu9041PublicKey::from_bytes(name, &fresh.public_key().to_bytes()).unwrap();
        let ciphertext = public.encrypt(b"key").unwrap();
        assert_eq!(fresh.decrypt(&ciphertext).unwrap(), b"key");
        assert!(key.decrypt(&ciphertext).is_err());
    }
}
