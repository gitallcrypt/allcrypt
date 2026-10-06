//! Reading what `scripts/record_products.py` wrote for the product
//! examples' offline tests: `.vec` files of `name = value` records, and
//! disk images stored sparsely.
//!
//! A disk image is mostly zeros - unused keyslot areas, alignment
//! padding - around a few hundred kilobytes of key material and data
//! that look random. The sparse form keeps only the non-zero runs:
//!
//!     magic "SPARSE01", u64 image length,
//!     then (u64 offset, u32 length, bytes) for each run,
//!
//! all big endian. `expand` gives back the image byte for byte.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The directory the fixtures live in.
pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples").join("products").join("fixtures")
}

/// One `[section]`'s records: each a list of `(key, value)` in order,
/// a record starting at each `name = ` line.
pub fn records(file: &str, section: &str) -> Vec<Vec<(String, String)>> {
    let text = std::fs::read_to_string(dir().join(file))
        .unwrap_or_else(|e| panic!("{file}: {e}"));
    let mut out: Vec<Vec<(String, String)>> = Vec::new();
    let mut current_section = String::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current_section = name.to_string();
            continue;
        }
        if current_section != section {
            continue;
        }
        let (key, value) = line.split_once(" = ")
            .unwrap_or_else(|| panic!("{file}: not a field: {line}"));
        if key == "name" {
            out.push(Vec::new());
        }
        out.last_mut().unwrap_or_else(|| panic!("{file}: a field before any name"))
            .push((key.to_string(), value.to_string()));
    }
    out
}

/// A field of a record.
pub fn field<'a>(record: &'a [(String, String)], key: &str) -> &'a str {
    record.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no field {key} in {record:?}"))
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A sparse image, expanded.
pub fn expand(file: &str) -> Vec<u8> {
    let bytes = std::fs::read(dir().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    assert_eq!(&bytes[..8], b"SPARSE01", "{file}: not a sparse image");
    let length = u64::from_be_bytes(bytes[8..16].try_into().unwrap()) as usize;
    let mut image = vec![0u8; length];
    let mut at = 16;
    while at < bytes.len() {
        let offset = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
        let run = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
        image[offset..offset + run].copy_from_slice(&bytes[at + 12..at + 12 + run]);
        at += 12 + run;
    }
    image
}
