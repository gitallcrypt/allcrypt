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
    expand_bytes(&bytes, file)
}

/// `expand` on bytes already read. A fixture is a file like any other
/// and can be damaged; a run that does not fit names the file rather
/// than panicking on a slice.
pub fn expand_bytes(bytes: &[u8], file: &str) -> Vec<u8> {
    let field = |range: std::ops::Range<usize>| bytes.get(range.clone())
        .unwrap_or_else(|| panic!("{file}: a sparse image cut short at byte {}", range.start));
    assert_eq!(field(0..8), b"SPARSE01", "{file}: not a sparse image");
    let length = u64::from_be_bytes(field(8..16).try_into().unwrap()) as usize;
    let mut image = vec![0u8; length];
    let mut at = 16;
    while at < bytes.len() {
        let offset = u64::from_be_bytes(field(at..at + 8).try_into().unwrap()) as usize;
        let run = u32::from_be_bytes(field(at + 8..at + 12).try_into().unwrap()) as usize;
        let end = offset.checked_add(run).filter(|end| *end <= length).unwrap_or_else(|| {
            panic!("{file}: a run of {run} bytes at {offset} is past the {length} byte image")
        });
        image[offset..end].copy_from_slice(field(at + 12..at + 12 + run));
        at += 12 + run;
    }
    image
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `expand` sliced the image by the runs' own offsets and lengths,
    /// so a damaged fixture panicked on a slice bound instead of naming
    /// itself; the fixtures on disk are all well formed.
    #[test]
    fn test_a_damaged_sparse_image_is_named() {
        let mut sparse = b"SPARSE01".to_vec();
        sparse.extend_from_slice(&64u64.to_be_bytes());
        sparse.extend_from_slice(&60u64.to_be_bytes());
        sparse.extend_from_slice(&4u32.to_be_bytes());
        sparse.extend_from_slice(&[1, 2, 3, 4]);
        let image = expand_bytes(&sparse, "good");
        assert_eq!((image.len(), &image[60..]), (64, &[1, 2, 3, 4][..]));
        let message = |bytes: Vec<u8>| -> String {
            let caught = std::panic::catch_unwind(|| expand_bytes(&bytes, "damaged.sparse"))
                .err().unwrap();
            caught.downcast_ref::<String>().cloned()
                .or_else(|| caught.downcast_ref::<&str>().map(|s| s.to_string())).unwrap()
        };
        let mut past = sparse.clone();
        past[16..24].copy_from_slice(&61u64.to_be_bytes());
        assert!(message(past).contains("damaged.sparse: a run of 4 bytes at 61"));
        let mut short = sparse.clone();
        short.truncate(sparse.len() - 1);
        assert!(message(short).contains("damaged.sparse: a sparse image cut short"));
    }
}
