//! 256-NEA6, 256-NIA6 and 256-NCA6 against TS 35.246 Annex A's reference
//! code: `vectors/zuc256_3gpp.vec`, written by
//! `scripts/make_zuc256_3gpp_vectors.py` from the reference built by
//! `scripts/witness/zuc256_3gpp`. Every length from 0 bits up, both key
//! sizes, every MAC size, refused MACs and ignored tail bits. The
//! specification's own test data is read in `stream_ciphers::mobile`'s
//! and `zuc`'s unit tests.

use std::collections::HashMap;

use allcrypt::api;

fn rows() -> Vec<(String, HashMap<String, String>)> {
    include_str!("../vectors/zuc256_3gpp.vec").lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let mut parts = line.split(' ');
            let kind = parts.next().unwrap().to_string();
            let fields = parts.map(|p| {
                let (k, v) = p.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            }).collect();
            (kind, fields)
        })
        .collect()
}

fn bytes(f: &HashMap<String, String>, name: &str) -> Vec<u8> {
    let v = &f[name];
    if v == "-" {
        return Vec::new();
    }
    (0..v.len()).step_by(2).map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap()).collect()
}

fn number(f: &HashMap<String, String>, name: &str) -> u64 {
    f[name].parse().unwrap()
}

#[test]
fn test_the_reference_codes_rows() {
    let rows = rows();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut short_keys = 0;
    for (kind, f) in &rows {
        let key = bytes(f, "key");
        short_keys += usize::from(key.len() == 16);
        let (count, bearer, direction) =
            (number(f, "count") as u32, number(f, "bearer") as u8, number(f, "direction") as u8);
        let extra = bytes(f, "extra_iv");
        let bits = Some(number(f, "bits"));
        let data = bytes(f, "data");
        match kind.as_str() {
            "nea" => {
                let out = api::nea6(&key, count, bearer, direction, &extra, &data, bits).unwrap();
                assert_eq!(out, bytes(f, "out"), "{f:?}");
            }
            "nia" => {
                let mac = api::nia6(&key, count, bearer, direction, &extra, &data, bits,
                                    number(f, "mac_bytes") as u8).unwrap();
                assert_eq!(mac, bytes(f, "mac"), "{f:?}");
            }
            "nca" => {
                let (out, mac) = api::nca6_encrypt(&key, count, bearer, direction, &extra,
                                                   &bytes(f, "aad"), Some(number(f, "aad_bits")),
                                                   &data, bits, number(f, "mac_bytes") as u8)
                    .unwrap();
                assert_eq!((out, mac), (bytes(f, "out"), bytes(f, "mac")), "{f:?}");
            }
            "ncad" => {
                let got = api::nca6_decrypt(&key, count, bearer, direction, &extra,
                                            &bytes(f, "aad"), Some(number(f, "aad_bits")), &data,
                                            bits, &bytes(f, "mac"));
                if f["refused"] == "1" {
                    assert!(got.is_err(), "{f:?}");
                } else {
                    assert_eq!(got.unwrap(), bytes(f, "out"), "{f:?}");
                }
            }
            other => panic!("unknown row kind {other}"),
        }
        *counts.entry(match kind.as_str() {
            "nea" => "nea", "nia" => "nia", "nca" => "nca", _ => "ncad" }).or_default() += 1;
    }
    assert_eq!(counts["nea"], 601);
    assert_eq!(counts["nia"], 401);
    assert_eq!(counts["nca"], 300);
    assert!(counts["ncad"] >= 600);
    assert!(short_keys > 100, "{short_keys} rows with a 16 byte key");
}

/// The inputs each algorithm refuses: key and EXTRA_IV lengths, BEARER and
/// DIRECTION out of range, a MAC size outside 4 to 16, a length that is
/// not the data's, and one past 2^32 - 1 bits.
#[test]
fn test_what_is_refused() {
    let key = [7u8; 32];
    assert!(api::nea6(&key, 0, 0, 0, &[], b"abc", None).is_ok());
    assert!(api::nea6(&key[..24], 0, 0, 0, &[], b"abc", None).is_err());
    assert!(api::nea6(&key, 0, 32, 0, &[], b"abc", None).is_err());
    assert!(api::nea6(&key, 0, 0, 2, &[], b"abc", None).is_err());
    assert!(api::nea6(&key, 0, 0, 0, &[1; 5], b"abc", None).is_err());
    assert!(api::nea6(&key, 0, 0, 0, &[], b"abc", Some(25)).is_err());
    assert!(api::nea6(&key, 0, 0, 0, &[], b"abc", Some(17)).is_ok());
    // Past 2^32 - 1 bits the data's own length would refuse it too, so
    // the message says which check did: a real message that long is half a
    // gigabyte.
    let long = api::nea6(&key, 0, 0, 0, &[], &[], Some(1 << 32)).unwrap_err();
    assert!(long.contains("at most 2^32 - 1 bits"), "{long}");
    let long = api::nca6_encrypt(&key, 0, 0, 0, &[], &[], Some(1 << 32), &[], None, 4)
        .unwrap_err();
    assert!(long.contains("at most 2^32 - 1 bits"), "{long}");
    for mac_bytes in [0, 3, 17] {
        assert!(api::nia6(&key, 0, 0, 0, &[], b"abc", None, mac_bytes).is_err());
        assert!(api::nca6_encrypt(&key, 0, 0, 0, &[], b"", None, b"abc", None, mac_bytes)
            .is_err());
    }
    let (out, mac) = api::nca6_encrypt(&key, 0, 0, 0, &[], b"ad", None, b"abc", None, 16)
        .unwrap();
    assert!(api::nca6_decrypt(&key, 0, 0, 0, &[], b"ad", None, &out, None, &mac[..3]).is_err());
    assert!(api::nca6_decrypt(&key, 0, 0, 0, &[], b"ad", None, &out, None, &mac[..4]).is_err());
    assert_eq!(api::nca6_decrypt(&key, 0, 0, 0, &[], b"ad", None, &out, None, &mac).unwrap(),
               b"abc");
    assert!(api::nca6_decrypt(&key, 0, 0, 0, &[], b"ae", None, &out, None, &mac).is_err());
    assert!(api::nca6_decrypt(&key, 1, 0, 0, &[], b"ad", None, &out, None, &mac).is_err());
}

/// The keystream through the stream cipher name is NEA6's over zeros:
/// NEA6 asks for no MAC, so its keystream starts at the first word.
#[test]
fn test_the_stream_cipher_name() {
    let key: Vec<u8> = (0..32).collect();
    let (count, bearer, direction, extra) = (0x1234_5678u32, 9u8, 1u8, [1u8, 2, 3, 4, 5, 6]);
    let mut iv = [0u8; 16];
    iv[1] = bearer << 1 | direction;
    iv[2..8].copy_from_slice(&extra);
    iv[8..12].copy_from_slice(&count.to_be_bytes());
    let mut stream = api::AnyStreamCipher::new("zuc256-3gpp", &key, &iv).unwrap();
    let mut keystream = vec![0u8; 100];
    stream.apply(&mut keystream).unwrap();
    assert_eq!(api::nea6(&key, count, bearer, direction, &extra, &[0u8; 100], None).unwrap(),
               keystream);
}
