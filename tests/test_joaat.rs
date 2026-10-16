//! Jenkins's one-at-a-time against `vectors/joaat.vec`: from zero as
//! PHP, Perl 5.24 and gVisor agree on it, and from seeds as Perl and
//! gVisor do (`scripts/make_joaat_vectors.py`). Offline.

use std::collections::HashMap;

use allcrypt::api::{self, AnyHash};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/joaat.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn fields(line: &str) -> HashMap<&str, &str> {
    line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect()
}

fn messages() -> Vec<Vec<u8>> {
    let messages: Vec<Vec<u8>> = VECTORS.lines().filter(|l| l.starts_with("msg ")).enumerate()
        .map(|(i, line)| {
            let f = fields(line);
            assert_eq!(f["n"], i.to_string());
            match f.get("fill") {
                Some(byte) => vec![unhex(byte)[0]; f["len"].parse().unwrap()],
                None => unhex(f["data"]),
            }
        }).collect();
    assert_eq!(messages.len(), 28);
    messages
}

#[test]
fn test_every_row() {
    let messages = messages();
    let mut seeds: HashMap<u32, usize> = HashMap::new();
    for line in VECTORS.lines().filter(|l| l.starts_with("hash ")) {
        let f = fields(line);
        let message = &messages[f["msg"].parse::<usize>().unwrap()];
        let seed = u32::from_str_radix(f["seed"], 16).unwrap();
        let expected = u32::from_str_radix(f["value"], 16).unwrap();
        let label = format!("seed {seed:08x}, {} bytes", message.len());
        *seeds.entry(seed).or_default() += 1;

        assert_eq!(api::joaat(message, seed), expected, "{label}");
        let half = message.len() / 3;
        let state = api::joaat_update(api::joaat_update(seed, &message[..half]), &message[half..]);
        assert_eq!(api::joaat_finish(state), expected, "{label} in two");

        if seed == 0 {
            let mut by_name = AnyHash::new("joaat").unwrap();
            assert_eq!((by_name.name(), by_name.digest_len()), ("joaat".to_string(), 4));
            for piece in message.chunks(7) {
                by_name.update(piece);
                let _ = by_name.digest();
            }
            assert_eq!(by_name.digest(), expected.to_be_bytes(), "{label} by name");
        }
    }
    assert_eq!(seeds.len(), 5);
    assert!(seeds.values().all(|&n| n == 28));
}

#[test]
fn test_its_other_names() {
    let messages = messages();
    for name in ["one_at_a_time", "OAAT", "Joaat", "one-at-a-time"] {
        let mut h = AnyHash::new(name).unwrap();
        assert_eq!(h.name(), "joaat", "{name}");
        h.update(&messages[20]);
        assert_eq!(h.digest(), api::joaat(&messages[20], 0).to_be_bytes(), "{name}");
    }
    for name in ["jenkins", "lookup3", "joaat64"] {
        assert!(AnyHash::new(name).is_err(), "{name}");
    }
}
