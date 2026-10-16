//! The checksums against `vectors/checksums.vec` (PHP, Go,
//! java.util.zip, and zlib or the SSE 4.2 instruction; the R package
//! fletcher's C, hashlib-additional and the fletcher crate; fnv-es,
//! fnv-plus, hashlib-additional, PHP and Go - agreeing on every row; written by `scripts/make_checksum_vectors.py`). Offline.

use std::collections::HashMap;

use allcrypt::api::{self, AnyHash, CHECKSUMS, HASHES};
use allcrypt::checksum;
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/checksums.vec");

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
    assert_eq!(messages.len(), 31);
    assert_eq!(messages[0], b"123456789");
    messages
}

fn rows() -> Vec<(String, usize, Vec<u8>)> {
    let rows: Vec<_> = VECTORS.lines().filter(|l| l.starts_with("sum ")).map(|line| {
        let f = fields(line);
        (f["name"].to_string(), f["msg"].parse().unwrap(), unhex(f["value"]))
    }).collect();
    assert_eq!(rows.len(), 744);
    rows
}

#[test]
fn test_every_checksum_against_its_witnesses() {
    let messages = messages();
    let rows = rows();
    // The rest are the fast hashes, each in a file of its own: xxHash's in
    // vectors/xxhash.vec, MurmurHash3's in vectors/murmur3.vec and
    // one-at-a-time's in vectors/joaat.vec.
    assert_eq!(CHECKSUMS.len(), 32);
    assert_eq!(CHECKSUMS[..6], ["crc32", "crc32c", "adler32", "fletcher16", "fletcher32",
                                "fletcher64"]);
    assert_eq!(CHECKSUMS[24..], ["xxh32", "xxh64", "xxh3", "xxh128", "murmur3_32",
                                 "murmur3_x86_128", "murmur3_x64_128", "joaat"]);
    for name in &CHECKSUMS[..24] {
        assert!(!HASHES.contains(name), "{name} is a checksum, not a hash");
        assert_eq!(rows.iter().filter(|r| r.0 == *name).count(), 31, "{name}");
    }
    for (name, msg, value) in rows {
        let message = &messages[msg];
        let mut h = AnyHash::new(&name).unwrap();
        assert_eq!(h.name(), name);
        assert_eq!(h.digest_len(), value.len());
        assert_eq!(h.block_size(), value.len());
        h.update(message);
        assert_eq!(h.digest(), value, "{name} of {} bytes", message.len());
        assert_eq!(h.digest(), value, "{name} digested twice");
        // Carrying on after a digest: Fletcher's pads its last word only
        // in the value it gives, not in the state.
        let mut twice = AnyHash::new(&name).unwrap();
        let half = message.len() / 2;
        twice.update(&message[..half]);
        let _ = twice.digest();
        twice.update(&message[half..]);
        assert_eq!(twice.digest(), value, "{name} carried on after a digest");

        // In irregular pieces, with a value taken midway.
        let mut pieces = AnyHash::new(&name).unwrap();
        let mut rest = &message[..];
        let mut step = 1;
        while !rest.is_empty() {
            let take = step.min(rest.len());
            pieces.update(&rest[..take]);
            rest = &rest[take..];
            step = step * 3 + 1;
            let _ = pieces.digest();
        }
        assert_eq!(pieces.digest(), value, "{name} in pieces");

        // A byte at a time, which leaves every part of a word there can be.
        let mut bytes = AnyHash::new(&name).unwrap();
        for byte in message.chunks(1) {
            bytes.update(byte);
        }
        assert_eq!(bytes.digest(), value, "{name} a byte at a time");

        // The functions that give the value as a number.
        let number = value.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
        match name.as_str() {
            "crc32" => assert_eq!(u64::from(checksum::crc32(message)), number),
            "crc32c" => {
                assert_eq!(u64::from(checksum::crc32c(message)), number);
                assert_eq!(u64::from(api::crc32c(message, 0)), number);
                let half = message.len() / 2;
                assert_eq!(u64::from(api::crc32c(&message[half..],
                                                 api::crc32c(&message[..half], 0))), number);
            }
            "adler32" => {
                assert_eq!(u64::from(checksum::adler32(message)), number);
                let half = message.len() / 2;
                assert_eq!(u64::from(checksum::adler32_update(
                    checksum::adler32_update(1, &message[..half]), &message[half..])), number);
            }
            "fletcher16" => assert_eq!(u64::from(checksum::fletcher16(message)), number),
            "fletcher32" => assert_eq!(u64::from(checksum::fletcher32(message)), number),
            "fletcher64" => assert_eq!(checksum::fletcher64(message), number),
            fnv if fnv.starts_with("fnv") => {}
            other => panic!("no number for {other}"),
        }
    }
}

#[test]
fn test_phps_name_for_crc32() {
    let rows = rows();
    let mut h = AnyHash::new("CRC32B").unwrap();
    assert_eq!(h.name(), "crc32");
    h.update(b"123456789");
    assert_eq!(h.digest(), rows.iter().find(|r| r.0 == "crc32" && r.1 == 0).unwrap().2);
}

#[test]
fn test_what_is_not_a_checksum_is_refused() {
    for name in ["crc", "crc32d", "crc32_c", "crc16", "crc64"] {
        let error = AnyHash::new(name).err().unwrap();
        assert!(error.contains("crc32c"), "{name}: {error}");
    }
}

#[test]
fn test_fnv_by_its_type_and_by_other_spellings() {
    use checksum::{Fnv, FnvVariant};
    let messages = messages();
    let rows = rows();
    let find = |name: &str| rows.iter().find(|r| r.0 == name && r.1 == 0).unwrap().2.clone();
    for (variant, prefix) in [(FnvVariant::Fnv0, "fnv0"), (FnvVariant::Fnv1, "fnv1"),
                              (FnvVariant::Fnv1a, "fnv1a")] {
        for bits in [32, 64, 128, 256, 512, 1024] {
            let mut f = Fnv::new(variant, bits).unwrap();
            f.update(&messages[0]);
            assert_eq!(f.value(), find(&format!("{prefix}_{bits}")), "{prefix}_{bits}");
        }
        for bits in [0, 16, 48, 96, 2048] {
            assert!(Fnv::new(variant, bits).is_err(), "{prefix} at {bits} bits");
        }
    }
    // PHP's names, and FNV-1a-64 as it is often written.
    for (spelling, name) in [("fnv132", "fnv1_32"), ("FNV1A32", "fnv1a_32"),
                             ("fnv164", "fnv1_64"), ("fnv1a64", "fnv1a_64"),
                             ("FNV-1a-64", "fnv1a_64"), ("FNV-0-1024", "fnv0_1024")] {
        let mut h = AnyHash::new(spelling).unwrap();
        assert_eq!(h.name(), name);
        h.update(&messages[0]);
        assert_eq!(h.digest(), find(name), "{spelling}");
    }
    for name in ["fnv2_32", "fnv1_48", "fnv1a_", "fnv_32", "fnv1a_+64", "fnv1a_064x", "fnv1128",
                 "fnv0a_32", "fnv"] {
        assert!(AnyHash::new(name).is_err(), "{name}");
    }
}
