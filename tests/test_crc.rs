//! CRCs from their parameters against `vectors/crc.vec`, written by
//! `scripts/make_crc_vectors.py`: every entry of the catalogue of
//! parametrised CRC algorithms over every message, and random parameters
//! at every width from 1 to 128, every row agreed by pycrc's algorithms,
//! crccheck, crcmod and the crc crate, each where it takes the row.
//! Offline.

use std::collections::HashMap;

use allcrypt::api::{self, AnyHash, Crc, CrcParams, CHECKSUMS, CRC_CATALOGUE};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/crc.vec");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn fields(line: &str) -> HashMap<&str, &str> {
    line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect()
}

struct File {
    messages: Vec<Vec<u8>>,
    /// (name, or "-" outside the catalogue; parameters)
    models: Vec<(String, CrcParams)>,
    /// (model, message, value, witnesses)
    rows: Vec<(usize, usize, Vec<u8>, Vec<String>)>,
}

fn file() -> File {
    let mut file = File { messages: Vec::new(), models: Vec::new(), rows: Vec::new() };
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let f = fields(line);
        match line.split(' ').next().unwrap() {
            "msg" => {
                assert_eq!(f["n"], file.messages.len().to_string());
                file.messages.push(unhex(f["data"]));
            }
            "model" => {
                assert_eq!(f["n"], file.models.len().to_string());
                let hex = |k: &str| u128::from_str_radix(f[k], 16).unwrap();
                file.models.push((f["name"].to_string(), CrcParams {
                    width: f["width"].parse().unwrap(),
                    poly: hex("poly"),
                    init: hex("init"),
                    refin: f["refin"] == "1",
                    refout: f["refout"] == "1",
                    xorout: hex("xorout"),
                }));
            }
            "crc" => file.rows.push((f["model"].parse().unwrap(), f["msg"].parse().unwrap(),
                                     unhex(f["value"]),
                                     f["witnesses"].split(',').map(String::from).collect())),
            _ => panic!("{line}"),
        }
    }
    assert_eq!(file.messages.len(), 26);
    assert_eq!(file.messages[0], b"123456789");
    assert_eq!(file.models.len(), 368);
    assert_eq!(file.rows.len(), 4960);
    file
}

#[test]
fn test_the_file_covers_the_catalogue_and_every_width() {
    let file = file();
    let named: Vec<&str> = file.models.iter().map(|m| m.0.as_str()).filter(|n| *n != "-")
        .collect();
    assert_eq!(named.len(), CRC_CATALOGUE.len());
    for (entry, name) in CRC_CATALOGUE.iter().zip(&named) {
        assert_eq!(entry.name.to_ascii_lowercase(), *name);
    }
    for (name, params) in &file.models {
        if name != "-" {
            // The parameters the witnesses were given are the catalogue's.
            assert_eq!(CrcParams::named(name).unwrap().params, *params, "{name}");
        }
    }
    for width in 1..=128 {
        assert!(file.models.iter().any(|m| m.0 == "-" && m.1.width == width), "{width}");
    }
    // Both reflections, each way, below and above 64 bits, and an even
    // polynomial, which pycrc's bit-by-bit algorithm cannot take.
    for refin in [false, true] {
        for refout in [false, true] {
            for wide in [false, true] {
                assert!(file.models.iter().any(|(_, p)| p.refin == refin && p.refout == refout
                                                && (p.width > 64) == wide));
            }
        }
    }
    assert!(file.models.iter().any(|(_, p)| p.poly % 2 == 0 && p.init != 0));
    for (_, _, _, witnesses) in &file.rows {
        assert!(witnesses.len() >= 3, "{witnesses:?}");
        for w in ["pycrc-bbf", "crccheck", "rust-crc"] {
            assert!(witnesses.iter().any(|x| x == w));
        }
    }
    // The catalogue's names follow the other checksums'.
    assert_eq!(CHECKSUMS.len(), 32 + CRC_CATALOGUE.len());
    assert_eq!(CHECKSUMS[32..], named[..]);
}

#[test]
fn test_every_row() {
    let file = file();
    for (model, msg, value, _) in &file.rows {
        let (name, params) = &file.models[*model];
        let message = &file.messages[*msg];
        let number = value.iter().fold(0u128, |acc, &b| acc << 8 | u128::from(b));
        assert_eq!(value.len(), params.width.div_ceil(8) as usize);

        assert_eq!(api::crc(*params, message).unwrap(), number, "{}", params.model());
        let mut crc = Crc::new(*params).unwrap();
        let mut rest = &message[..];
        let mut step = 1;
        while !rest.is_empty() {
            let take = step.min(rest.len());
            crc.update(&rest[..take]);
            rest = &rest[take..];
            step = step * 2 + 1;
            let _ = crc.value();
        }
        assert_eq!(crc.value(), number, "{} in pieces", params.model());
        assert_eq!(crc.digest(), *value);

        // By name: the catalogue's, or the model line.
        let canonical = if name == "-" { params.model() } else { name.clone() };
        let mut h = AnyHash::new(&canonical).unwrap();
        assert_eq!(h.name(), canonical);
        assert_eq!(h.digest_len(), value.len());
        let half = message.len() / 2;
        h.update(&message[..half]);
        let _ = h.digest();
        h.update(&message[half..]);
        assert_eq!(h.digest(), *value, "{canonical}");
        assert_eq!(h.digest(), *value, "{canonical} digested twice");
        let mut built = AnyHash::crc(*params).unwrap();
        assert_eq!(built.name(), params.model());
        built.update(message);
        assert_eq!(built.digest(), *value);
        if name != "-" {
            let mut upper = AnyHash::new(&name.to_ascii_uppercase()).unwrap();
            upper.update(message);
            assert_eq!(upper.digest(), *value);
            assert_eq!(upper.name(), *name);
        }
    }
}

#[test]
fn test_bad_parameters_are_errors_not_panics() {
    let ok = CrcParams { width: 8, poly: 0x07, init: 0, refin: false, refout: false, xorout: 0 };
    assert!(api::crc(ok, b"x").is_ok());
    for bad in [CrcParams { width: 0, ..ok }, CrcParams { width: 129, ..ok },
                CrcParams { poly: 0x107, ..ok }, CrcParams { init: 0x100, ..ok },
                CrcParams { xorout: 0x100, ..ok }] {
        assert!(api::crc(bad, b"x").is_err(), "{bad:?}");
        assert!(AnyHash::crc(bad).is_err());
    }
    for name in ["width=8 poly=0x107 init=0x00 refin=false refout=false xorout=0x00",
                 "width=8 poly=0x07", "crc-8/nonesuch", "crc-16"] {
        assert!(AnyHash::new(name).is_err(), "{name}");
    }
}
