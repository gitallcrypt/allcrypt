//! UEA1 and UIA1, KASUMI's f8 and f9 (3GPP TS 35.201), against Intel's
//! tests as intel-ipsec-mb 2.0.3 carries them (`vectors/kasumi_3gpp/`,
//! read from the C initialisers) and `vectors/uea1_uia1.vec`, written by
//! `scripts/make_uea1_uia1_vectors.py`: random inputs either side of the
//! byte and block steps, every row agreed by the reference code from the
//! specification's annex, as CryptoMobile carries it, and intel-ipsec-mb.
//! Offline.

use std::collections::HashMap;

use allcrypt::api;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The bytes of a C string literal sequence: `"\x00\x01" "\x02"`.
fn c_bytes(literals: &str) -> Vec<u8> {
    literals.split("\\x").skip(1).map(|h| u8::from_str_radix(&h[..2], 16).unwrap()).collect()
}

/// The fields of each `{ ... }` initialiser in an intel-ipsec-mb test
/// file: numbers and string literals in order, the terminating all-zero
/// entry left out. Comments are dropped first; the UIA1 file has one in
/// front of its first entry.
fn initialisers(text: &str) -> Vec<Vec<String>> {
    let mut plain = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        plain.push_str(&rest[..start]);
        rest = &rest[start + rest[start..].find("*/").unwrap() + 2..];
    }
    plain.push_str(rest);
    let body = &plain[plain.find("[] = {").unwrap() + 6..];
    let mut out = Vec::new();
    for entry in body.split("},").map(|e| e.trim()) {
        let Some(entry) = entry.strip_prefix('{') else { continue };
        if entry.contains("NULL") {
            continue;
        }
        let mut fields = Vec::new();
        let mut current = String::new();
        let mut in_string = false;
        for c in entry.chars() {
            match c {
                '"' => in_string = !in_string,
                ',' if !in_string => {
                    fields.push(current.trim().to_string());
                    current.clear();
                }
                _ => current.push(c),
            }
        }
        if !current.trim().is_empty() {
            fields.push(current.trim().trim_end_matches('}').trim().to_string());
        }
        out.push(fields);
    }
    out
}

/// Intel's UEA1 tests: key, an IV of COUNT and BEARER << 3 | DIRECTION
/// << 2 then three zero bytes, the message and its encryption, the length
/// in bits.
#[test]
fn test_intel_uea1() {
    let entries = initialisers(include_str!("../vectors/kasumi_3gpp/kasumi_f8.json.c"));
    assert_eq!(entries.len(), 34);
    let mut odd_lengths = 0;
    for e in &entries {
        let (key, iv, msg, ct) = (c_bytes(&e[3]), c_bytes(&e[4]), c_bytes(&e[5]), c_bytes(&e[6]));
        let bits: u64 = e[8].parse().unwrap();
        assert_eq!((iv.len(), &iv[5..]), (8, &[0u8, 0, 0][..]), "test {}", e[2]);
        assert_eq!(iv[4] & 3, 0);
        let count = u32::from_be_bytes(iv[..4].try_into().unwrap());
        let (bearer, direction) = (iv[4] >> 3, (iv[4] >> 2) & 1);
        let n = bits.div_ceil(8) as usize;
        let got = api::mobile_cipher("uea1", &key, count, bearer, direction, &msg[..n],
                                     Some(bits)).unwrap();
        // The bits past the length are cleared here; Intel's ciphertext
        // keeps the message's.
        let mut want = ct[..n].to_vec();
        if !bits.is_multiple_of(8) {
            want[n - 1] &= 0xffu8 << (8 - bits % 8);
            odd_lengths += 1;
        }
        assert_eq!(got, want, "test {}", e[2]);
    }
    assert_eq!(odd_lengths, 4);
}

/// Intel's UIA1 tests, in two forms. Those with no IV give 3GPP's whole
/// padded input, COUNT || FRESH || MESSAGE || DIRECTION || 1 || 0..: the
/// last one bit ends the message and the bit before it is DIRECTION.
/// Those with an IV give DIRECTION, COUNT and FRESH in it and the message
/// on its own.
#[test]
fn test_intel_uia1() {
    let entries = initialisers(include_str!("../vectors/kasumi_3gpp/kasumi_f9.json.c"));
    assert_eq!(entries.len(), 15);
    let (mut padded, mut with_iv) = (0, 0);
    for e in &entries {
        let (key, msg, tag, iv) = (c_bytes(&e[3]), c_bytes(&e[4]), c_bytes(&e[5]), c_bytes(&e[8]));
        let bits: usize = e[7].parse().unwrap();
        let (count, fresh, direction, message, length) = if iv.is_empty() {
            let total = bits;
            let bit = |i: usize| (msg[i / 8] >> (7 - i % 8)) & 1;
            let stop = (0..total).rev().find(|&i| bit(i) == 1).unwrap();
            let length = stop - 1 - 64;
            let mut message = msg[8..8 + length.div_ceil(8)].to_vec();
            if !length.is_multiple_of(8) {
                let last = message.len() - 1;
                message[last] &= 0xffu8 << (8 - length % 8);
            }
            padded += 1;
            (u32::from_be_bytes(msg[..4].try_into().unwrap()),
             u32::from_be_bytes(msg[4..8].try_into().unwrap()), bit(stop - 1), message, length)
        } else {
            with_iv += 1;
            assert_eq!(iv.len(), 9);
            (u32::from_be_bytes(iv[1..5].try_into().unwrap()),
             u32::from_be_bytes(iv[5..9].try_into().unwrap()), iv[0], msg[..bits.div_ceil(8)]
                 .to_vec(), bits)
        };
        let got = api::uia1(&key, count, fresh, direction, &message, Some(length as u64))
            .unwrap();
        assert_eq!(got, tag, "test {}", e[2]);
    }
    // Ten of Intel's fifteen give the padded form, five the IV form.
    assert_eq!((padded, with_iv), (10, 5));
}

struct Row {
    kind: String,
    f: HashMap<String, String>,
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/uea1_uia1.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows: Vec<Row> = text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| Row {
            kind: line.split(' ').next().unwrap().to_string(),
            f: line.split(' ').skip(1).map(|w| {
                let (k, v) = w.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            }).collect(),
        })
        .collect();
    assert_eq!(rows.len(), declared);
    rows
}

#[test]
fn test_uea1_uia1_vectors() {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in rows() {
        let f = &r.f;
        let key = unhex(&f["key"]);
        let count = u32::from_str_radix(&f["count"], 16).unwrap();
        let direction: u8 = f["dir"].parse().unwrap();
        let bits: u64 = f["bits"].parse().unwrap();
        let data = unhex(&f["data"]);
        match r.kind.as_str() {
            "uea1" => {
                let bearer: u8 = f["bearer"].parse().unwrap();
                let got = api::mobile_cipher("uea1", &key, count, bearer, direction, &data,
                                             Some(bits)).unwrap();
                assert_eq!(got, unhex(&f["out"]), "uea1 at {bits}");
                // Decryption is the same operation, and gives the message
                // back with the bits past the length cleared.
                let back = api::mobile_cipher("uea1", &key, count, bearer, direction, &got,
                                              Some(bits)).unwrap();
                let mut want = data.clone();
                if !bits.is_multiple_of(8) {
                    let last = want.len() - 1;
                    want[last] &= 0xffu8 << (8 - bits % 8);
                }
                assert_eq!(back, want, "uea1 back at {bits}");
            }
            "uia1" => {
                let fresh = u32::from_str_radix(&f["fresh"], 16).unwrap();
                let got = api::uia1(&key, count, fresh, direction, &data, Some(bits)).unwrap();
                assert_eq!(got, unhex(&f["out"]), "uia1 at {bits}");
            }
            other => panic!("{other}"),
        }
        *counts.entry(r.kind).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert!(counts["uea1"] >= 100, "{counts:?}");
    assert!(counts["uia1"] >= 100, "{counts:?}");
}

/// The bits past the length are not the message's: setting them changes
/// neither a ciphertext nor a MAC.
#[test]
fn test_the_bits_past_the_length_are_ignored() {
    let key: Vec<u8> = (0..16).collect();
    for bits in [1u64, 7, 9, 63, 65, 127, 129] {
        let n = bits.div_ceil(8) as usize;
        let clear = vec![0u8; n];
        let mut set = clear.clone();
        set[n - 1] |= 0xffu8 >> (bits % 8);
        assert_eq!(api::mobile_cipher("uea1", &key, 1, 2, 1, &clear, Some(bits)).unwrap(),
                   api::mobile_cipher("uea1", &key, 1, 2, 1, &set, Some(bits)).unwrap());
        assert_eq!(api::uia1(&key, 1, 2, 1, &clear, Some(bits)).unwrap(),
                   api::uia1(&key, 1, 2, 1, &set, Some(bits)).unwrap());
    }
}

#[test]
fn test_uea1_uia1_refusals() {
    let key = [0u8; 16];
    assert_eq!(api::mobile_cipher("uea1", &key, 0, 32, 0, b"x", None).unwrap_err(),
               "BEARER is five bits: 0 to 31, not 32.");
    assert_eq!(api::uia1(&key, 0, 0, 2, b"x", None).unwrap_err(),
               "DIRECTION is one bit: 0 or 1, not 2.");
    assert_eq!(api::mobile_cipher("uea1", &key[..15], 0, 0, 0, b"x", None).unwrap_err(),
               "A UEA1 key is 16 bytes, not 15.");
    assert_eq!(api::uia1(&key[..15], 0, 0, 0, b"x", None).unwrap_err(),
               "A UIA1 key is 16 bytes, not 15.");
    assert!(api::uia1(&key, 0, 0, 0, b"xy", Some(17)).is_err());
}
