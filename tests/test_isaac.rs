//! ISAAC, ISAAC-64 and Bouncy Castle's reading of ISAAC against
//! `vectors/isaac.vec`, written by `scripts/make_isaac_vectors.py`: the
//! values rand_isaac's tests give as the reference implementation's, and
//! random, single-bit and deep rows on which Jenkins's code, coreutils's,
//! rand_isaac and (for keys it takes) Bouncy Castle agree. Offline.

use std::collections::HashMap;

use allcrypt::api::AnyStreamCipher;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Row {
    cipher: String,
    key: Vec<u8>,
    skip: usize,
    stream: Vec<u8>,
    source: String,
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/isaac.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows: Vec<Row> = text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let cipher = line.split(' ').next().unwrap().to_string();
            let f: HashMap<&str, &str> = line.split(' ').skip(1)
                .map(|w| w.split_once('=').unwrap()).collect();
            Row { cipher, key: unhex(f["key"]), skip: f["skip"].parse().unwrap(),
                  stream: unhex(f["stream"]), source: f["source"].to_string() }
        })
        .collect();
    assert_eq!(rows.len(), declared);
    rows
}

fn keystream(c: &mut AnyStreamCipher, n: usize) -> Vec<u8> {
    c.update(&vec![0; n]).unwrap()
}

#[test]
fn test_isaac_vectors() {
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for r in rows() {
        let mut c = AnyStreamCipher::new(&r.cipher, &r.key, &[]).unwrap();
        keystream(&mut c, r.skip);
        assert_eq!(keystream(&mut c, r.stream.len()), r.stream,
                   "{} {:02x?} from {}", r.cipher, &r.key[..r.key.len().min(8)], r.skip);
        *counts.entry((r.cipher, r.source)).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    let count = |c: &str, s: &str| counts.get(&(c.to_string(), s.to_string())).copied();
    assert_eq!(count("isaac", "rand_isaac"), Some(2));
    assert_eq!(count("isaac64", "rand_isaac"), Some(2));
    assert_eq!(count("isaac", "random"), Some(23));
    assert_eq!(count("isaac64", "random"), Some(27));
    assert_eq!(count("isaac-bouncycastle", "random"), Some(23));
    for cipher in ["isaac", "isaac64", "isaac-bouncycastle"] {
        assert_eq!(count(cipher, "single-bit"), Some(5), "{cipher}");
        assert_eq!(count(cipher, "deep"), Some(2), "{cipher}");
    }
}

/// The keystream in uneven pieces is the keystream in one call, across
/// block boundaries.
#[test]
fn test_isaac_in_pieces() {
    for r in rows().iter().filter(|r| r.source == "random" && r.skip == 0) {
        let mut c = AnyStreamCipher::new(&r.cipher, &r.key, &[]).unwrap();
        let mut got = Vec::new();
        let mut piece = 1;
        while got.len() < r.stream.len() {
            let take = piece.min(r.stream.len() - got.len());
            got.extend(keystream(&mut c, take));
            piece = piece * 3 + 1;
        }
        assert_eq!(got, r.stream, "{} {}", r.cipher, r.key.len());
        let mut c = AnyStreamCipher::new(&r.cipher, &r.key, &[]).unwrap();
        let sealed = c.encrypt(b"attack at dawn").unwrap();
        let mut d = AnyStreamCipher::new(&r.cipher, &r.key, &[]).unwrap();
        assert_eq!(d.decrypt(&sealed).unwrap(), b"attack at dawn");
    }
}

#[test]
fn test_isaac_refusals() {
    for name in ["isaac", "isaac64", "isaac-bouncycastle"] {
        assert!(AnyStreamCipher::new(name, &[1; 16], &[0; 8]).is_err(), "{name} took a nonce");
        assert!(AnyStreamCipher::new(name, &[1; 16], &[]).unwrap().seek(1).is_err());
    }
    for (name, max) in [("isaac", 1024), ("isaac64", 2048), ("isaac-bouncycastle", 1024)] {
        assert!(AnyStreamCipher::new(name, &vec![0; max], &[]).is_ok());
        let err = AnyStreamCipher::new(name, &vec![0; max + 1], &[]).err().unwrap();
        assert!(err.contains(&format!("at most {max} bytes")), "{err}");
    }
}
