//! TurboSHAKE and KangarooTwelve against RFC 9861 section 5's 67 test
//! vectors, read out of `rfcs/rfc9861.txt`, and against pycryptodome
//! 3.24.1 and the Keccak team's XKCP K12: `vectors/turboshake_k12.vec`,
//! written by `scripts/make_turboshake_k12_vectors.py`.

use std::collections::HashMap;

use allcrypt::api;
use allcrypt::hash_functions::HashFunction;

const RFC: &str = include_str!("../rfcs/rfc9861.txt");

/// RFC 9861's `ptn(n)`: `00 01 .. FA` repeated, cut to `n` bytes.
fn ptn(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// The bytes between a pair of backticks: `00`^0, or hex bytes.
fn literal(spec: &str) -> Vec<u8> {
    if spec == "`00`^0" {
        return Vec::new();
    }
    spec.trim_matches('`').split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

/// A message or customization string as the RFC writes it: a literal, or
/// `ptn(17**6 bytes)`, `ptn(41 bytes)` and the like.
fn input(spec: &str) -> Vec<u8> {
    match spec.strip_prefix("ptn(") {
        Some(rest) => {
            let n = rest.trim_end_matches(" bytes)");
            let n = match n.split_once("**") {
                Some((base, power)) => base.parse::<usize>().unwrap()
                    .pow(power.parse::<u32>().unwrap()),
                None => n.parse().unwrap(),
            };
            ptn(n)
        }
        None => literal(spec),
    }
}

#[test]
fn test_rfc_9861_vectors() {
    let body = &RFC[RFC.rfind("\n5.  Test Vectors").unwrap()..];
    let body = &body[..body.find("\n6.  IANA Considerations").unwrap()];
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut at = 0;
    while let Some(found) = ["TurboSHAKE128(", "TurboSHAKE256(", "KT128(", "KT256("].iter()
        .filter_map(|name| body[at..].find(name).map(|i| (at + i, *name)))
        .min()
    {
        let (start, name) = found;
        let line_end = start + body[start..].find('\n').unwrap();
        let heading = &body[start..line_end];
        at = line_end;
        let args = &heading[name.len()..heading.rfind(')').unwrap()];
        let last: Option<usize> = heading.split_once("), last ")
            .map(|(_, rest)| rest.trim_end_matches(" bytes:").parse().unwrap());
        let parts: Vec<&str> = args.splitn(3, ", ").collect();
        let message = input(parts[0].trim_start_matches("M="));
        let length: usize = parts[2].parse().unwrap();
        // The expected output: the next backtick pair.
        let open = at + body[at..].find('`').unwrap();
        let close = open + 1 + body[open + 1..].find('`').unwrap();
        let expected: Vec<u8> = body[open + 1..close].split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap()).collect();
        at = close + 1;
        let got = match name {
            "TurboSHAKE128(" | "TurboSHAKE256(" => {
                let domain = literal(parts[1].trim_start_matches("D="))[0];
                api::turboshake(name.trim_end_matches('('), &message, length, domain).unwrap()
            }
            _ => {
                let custom = input(parts[1].trim_start_matches("C="));
                api::kangarootwelve(name.trim_end_matches('('), &message, length, &custom)
                    .unwrap()
            }
        };
        let tail = &got[got.len() - last.unwrap_or(length)..];
        assert_eq!(tail, &expected[..], "{heading}");
        *counts.entry(name).or_default() += 1;
    }
    assert_eq!(counts["TurboSHAKE128("], 16);
    assert_eq!(counts["TurboSHAKE256("], 15);
    assert_eq!(counts["KT128("], 18);
    assert_eq!(counts["KT256("], 18);
}

/// The catalogue names agree with the functions: TurboSHAKE at its
/// default domain byte, KT with no customization, and lengths in bits.
#[test]
fn test_the_catalogue_names() {
    let data = ptn(9000);
    for (name, xof, len) in [("turboshake_128", "turboshake128", 32),
                             ("turboshake_256", "turboshake256", 64)] {
        let mut h = api::AnyHash::new(name).unwrap();
        h.update(&data);
        assert_eq!(h.digest(), api::turboshake(xof, &data, len, 0x1f).unwrap());
        let mut h = api::AnyHash::new(&format!("{name}_200")).unwrap();
        h.update(&data);
        assert_eq!(h.digest(), api::turboshake(xof, &data, 25, 0x1f).unwrap());
    }
    for (name, len) in [("kt128", 32), ("kt256", 64)] {
        let mut h = api::AnyHash::new(name).unwrap();
        h.update(&data);
        assert_eq!(h.digest(), api::kangarootwelve(name, &data, len, b"").unwrap());
        let mut h = api::AnyHash::new(&format!("{name}_1000")).unwrap();
        h.update(&data);
        assert_eq!(h.digest(), api::kangarootwelve(name, &data, 125, b"").unwrap());
    }
}

/// The domain byte must be 0x01 to 0x7F, and the names are the four.
#[test]
fn test_what_is_refused() {
    assert!(api::turboshake("turboshake128", b"", 32, 0x00).is_err());
    assert!(api::turboshake("turboshake128", b"", 32, 0x80).is_err());
    assert!(api::turboshake("turboshake128", b"", 32, 0x7f).is_ok());
    assert!(api::turboshake("turboshake512", b"", 32, 0x1f).is_err());
    assert!(api::kangarootwelve("kt512", b"", 32, b"").is_err());
    assert!(api::kangarootwelve("KT-128", b"", 32, b"").is_ok());
}

fn rows() -> Vec<(String, HashMap<String, String>)> {
    include_str!("../vectors/turboshake_k12.vec").lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let mut parts = line.split(' ');
            let kind = parts.next().unwrap().to_string();
            (kind, parts.map(|p| {
                let (k, v) = p.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            }).collect())
        })
        .collect()
}

fn hex(v: &str) -> Vec<u8> {
    if v == "-" {
        return Vec::new();
    }
    (0..v.len()).step_by(2).map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap()).collect()
}

/// The witnesses' rows. A message is `ptn(n)` with `n` given, to keep the
/// file small; the long ones sit either side of the 8192 byte chunks.
#[test]
fn test_the_witnesses_rows() {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (kind, f) in rows() {
        let message = ptn(f["message_len"].parse().unwrap());
        let length: usize = f["length"].parse().unwrap();
        let got = match kind.as_str() {
            "turboshake128" | "turboshake256" => api::turboshake(
                &kind, &message, length, u8::from_str_radix(&f["domain"], 16).unwrap()),
            "kt128" | "kt256" => api::kangarootwelve(&kind, &message, length,
                                                     &ptn(f["custom_len"].parse().unwrap())),
            other => panic!("unknown row kind {other}"),
        }.unwrap();
        assert_eq!(got, hex(&f["output"]), "{kind} {f:?}");
        *counts.entry(kind).or_default() += 1;
    }
    for kind in ["turboshake128", "turboshake256", "kt128", "kt256"] {
        assert!(counts.get(kind).copied().unwrap_or(0) >= 200, "{kind}: {counts:?}");
    }
}
