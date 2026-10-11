//! GOST R 34.11-94's two readings of the empty message, against Bouncy
//! Castle 1.77 and gost89 in `vectors/gost94_readings.vec`
//! (`scripts/make_gost94_vectors.py`), read offline.
//!
//! The `_bc` names are those witnesses' reading and match every row,
//! the empty message included. The plain names are RFC 5831's step 2
//! read literally, as today's gost-engine computes it
//! (`tests/test_gost_engine_vectors.rs` holds the engine's empty
//! message): they match every non-empty row and must differ on the
//! empty one, or the file would not be separating anything.

use std::collections::HashMap;

use allcrypt::api::AnyHash;
use allcrypt::hash_functions::HashFunction;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn digest(name: &str, message: &[u8]) -> Vec<u8> {
    let mut hash = AnyHash::new(name).unwrap();
    hash.update(message);
    hash.digest()
}

#[test]
fn test_both_readings_against_bouncy_castle_and_gost89() {
    let text = include_str!("../vectors/gost94_readings.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let names = HashMap::from([("id-GostR3411-94-CryptoProParamSet", "gost94"),
                               ("id-GostR3411-94-TestParamSet", "gost94_test"),
                               ("dstu4145-default-dke", "gost34311")]);
    let (mut checked, mut empty) = (0, 0);
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let fields: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let name = names[fields["params"]];
        let (message, expected) = (unhex(fields["msg"]), unhex(fields["digest"]));

        let bc = format!("{name}_bc");
        assert_eq!(digest(&bc, &message), expected, "{line}");
        assert_eq!(AnyHash::new(&bc).unwrap().name(), bc);
        if message.is_empty() {
            assert_ne!(digest(name, &message), expected, "{line}");
            empty += 1;
        } else {
            assert_eq!(digest(name, &message), expected, "{line}");
        }
        checked += 1;
    }
    assert_eq!((checked, empty), (declared, 3));
}

/// The difference is the one block, for the empty message alone: an
/// empty update is no message, and a block-sized message still gets
/// its padded block under both.
#[test]
fn test_the_readings_differ_only_on_the_empty_message() {
    for (name, bc) in [("gost94", "gost94_bc"), ("gost34311", "gost34311_bc")] {
        let mut fed_nothing = AnyHash::new(bc).unwrap();
        fed_nothing.update(&[]);
        assert_eq!(fed_nothing.digest(), digest(bc, &[]));
        for length in [1usize, 31, 32, 33, 64] {
            let message: Vec<u8> = (0..length as u8).collect();
            assert_eq!(digest(name, &message), digest(bc, &message), "{name} {length}");
        }
        // A digest taken mid-stream and continued agrees with one shot.
        let mut streamed = AnyHash::new(bc).unwrap();
        let before = streamed.digest();
        streamed.update(b"abc");
        assert_eq!(before, digest(bc, &[]));
        assert_eq!(streamed.digest(), digest(name, b"abc"));
    }
}
