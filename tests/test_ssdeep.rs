//! ssdeep and CTPH against `vectors/ssdeep.vec`, written by
//! `scripts/make_ssdeep_vectors.py`: digests libfuzzy 2.14.1 and ppdeep
//! agree on, libfuzzy's scores, and ctph.js 0.0.5's digests and
//! similarities. The messages are described in the file and built here
//! by the rule that script states. Offline.

use std::collections::HashMap;

use allcrypt::api::{self, Ssdeep};
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/ssdeep.vec");

fn rows(kind: &str) -> Vec<HashMap<&'static str, &'static str>> {
    VECTORS.lines()
        .filter(|line| line.split(' ').next() == Some(kind))
        .map(|line| line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

fn random_bytes(seed: u32, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut i = 0u32;
    while out.len() < length {
        let block = [&b"allcrypt ssdeep"[..], &seed.to_be_bytes(), &i.to_be_bytes()].concat();
        out.extend(SHA256::new(&block).digest());
        i += 1;
    }
    out.truncate(length);
    out
}

/// The message a row describes, by `make_ssdeep_vectors.py`'s rule.
fn message(spec: &str) -> Vec<u8> {
    let f: Vec<&str> = spec.split(':').collect();
    let n = |i: usize| f[i].parse::<usize>().unwrap();
    match f[0] {
        "random" => random_bytes(n(1) as u32, n(2)),
        "zeros" => vec![0; n(1)],
        "repeat" => {
            let unit: Vec<u8> = (0..f[1].len()).step_by(2)
                .map(|i| u8::from_str_radix(&f[1][i..i + 2], 16).unwrap()).collect();
            unit.iter().copied().cycle().take(n(2)).collect()
        }
        "counting" => (0..).flat_map(|i: u64| format!("{i}\n").into_bytes()).take(n(1)).collect(),
        "edited" => {
            let mut base = random_bytes(n(1) as u32, n(2));
            base[n(3)..n(3) + n(4)].copy_from_slice(&random_bytes(n(5) as u32, n(4)));
            base
        }
        "spliced" => {
            let mut base = random_bytes(n(1) as u32, n(2));
            let patch: Vec<u8> = (0..f[4].len()).step_by(2)
                .map(|i| u8::from_str_radix(&f[4][i..i + 2], 16).unwrap()).collect();
            base[n(3)..n(3) + patch.len()].copy_from_slice(&patch);
            base
        }
        other => panic!("no message kind {other}"),
    }
}

#[test]
fn test_digests_against_libfuzzy_ppdeep_and_ctph_js() {
    let rows = rows("hash");
    assert_eq!(rows.len(), 56);
    for r in rows {
        let data = message(r["msg"]);
        assert_eq!(api::ssdeep(&data).unwrap(), r["ssdeep"], "{}", r["msg"]);
        assert_eq!(api::ctph(&data).unwrap(), r["ctph"], "{}", r["msg"]);

        // In irregular pieces, with a digest taken midway that must not
        // disturb the state.
        let mut state = Ssdeep::new();
        let (mut at, mut step) = (0, 1);
        while at < data.len() {
            let end = (at + step).min(data.len());
            state.update(&data[at..end]);
            if at < data.len() / 2 && end >= data.len() / 2 {
                state.digest().unwrap();
            }
            at = end;
            step = step * 5 + 3;
        }
        assert_eq!(state.digest().unwrap(), r["ssdeep"], "{} in pieces", r["msg"]);
        assert_eq!(state.clone().digest().unwrap(), r["ssdeep"]);
    }
}

#[test]
fn test_scores_against_libfuzzy() {
    let rows = rows("compare");
    assert_eq!(rows.len(), 184);
    assert!(rows.iter().any(|r| r["source"] == "libfuzzy") && rows.iter().any(|r| r["source"] == "both"));
    for r in rows {
        let got = api::ssdeep_compare(r["a"], r["b"]);
        match r["score"] {
            "error" => assert!(got.is_err(), "{} {} gave {got:?}", r["a"], r["b"]),
            score => assert_eq!(got.unwrap(), score.parse::<u32>().unwrap(), "{} {}", r["a"], r["b"]),
        }
    }
}

#[test]
fn test_ctph_similarity_against_ctph_js() {
    let rows = rows("similarity");
    assert_eq!(rows.len(), 175);
    for r in rows {
        let got = api::ctph_similarity(r["a"], r["b"]);
        match r["score"] {
            "error" => assert!(got.is_err(), "{} {}", r["a"], r["b"]),
            "NaN" => assert!(got.unwrap().is_nan()),
            // The shortest decimal that reads back as the double, so the
            // comparison is exact.
            score => assert_eq!(got.unwrap(), score.parse::<f64>().unwrap(), "{} {}", r["a"], r["b"]),
        }
    }
}
