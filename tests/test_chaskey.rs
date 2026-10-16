//! Chaskey against `vectors/chaskey.vec`, written by
//! `scripts/make_chaskey_vectors.py`: go-chaskey's published tags for 8
//! and 12 rounds, and rows at 8, 12 and 16 rounds on which go-chaskey's
//! two builds and sacundim's crate agree, each as one call and streamed
//! in pieces. The block cipher rows are `src/mac/chaskey.rs`'s. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::api;
use allcrypt::mac::chaskey::Chaskey;
use allcrypt::Mac;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_chaskey_vectors() {
    let mut seen: BTreeMap<(usize, String), usize> = BTreeMap::new();
    for line in include_str!("../vectors/chaskey.vec").lines() {
        if !line.starts_with("chaskey ") {
            continue;
        }
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let rounds: usize = f["rounds"].parse().unwrap();
        let (key, msg, tag) = (unhex(f["key"]), unhex(f["msg"]), unhex(f["tag"]));
        assert_eq!(api::chaskey(&key, &msg, rounds).unwrap(), tag, "{line}");
        // Pieces of 1, 2, 3 .. bytes, with the state reset from a
        // different message first.
        let mut mac = Chaskey::new(&key, rounds).unwrap();
        mac.update(b"something else entirely, longer than a block");
        mac.reset();
        let (mut at, mut piece) = (0, 1);
        while at < msg.len() {
            let end = (at + piece).min(msg.len());
            mac.update(&msg[at..end]);
            at = end;
            piece += 1;
        }
        assert_eq!(mac.digest(), tag, "{line}");
        *seen.entry((rounds, f["source"].to_string())).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(seen[&(8, "go-chaskey-tests".to_string())], 64, "{seen:?}");
    assert_eq!(seen[&(12, "go-chaskey-tests".to_string())], 64, "{seen:?}");
    for rounds in [8, 12, 16] {
        assert!(seen[&(rounds, "generated".to_string())] >= 20, "{seen:?}");
    }
}

#[test]
fn test_the_api_refuses_what_the_type_refuses() {
    assert_eq!(api::chaskey(&[0; 15], b"", 8).unwrap_err(),
               "A Chaskey key is 16 bytes, not 15.");
    assert!(api::chaskey(&[0; 16], b"", 10).unwrap_err().contains("not 10."));
}
