/*!
UMAC checked against Nettle.

RFC 4418's appendix has eight messages, so it says little about the
lengths where UMAC's layers change behaviour: NH pads the last chunk to
32 bytes, L2 is skipped at 1024 bytes or fewer, and past 2^24 bytes
POLY moves the rest of the input to a 128 bit prime with its own
padding. The one RFC row that reaches that last stage was misprinted
(erratum 3507), so the document alone could not settle it either.

`vectors/umac_nettle.vec` holds Nettle's tags, at all four tag lengths,
for 203 lengths from 0 to 2^25 + 11, with keys and nonces that change on
every row. `scripts/make_umac_vectors.py` regenerates it through
`libnettle.so.8`; this file needs neither Nettle nor the network.

Messages are described rather than stored - `length` bytes of a
Fibonacci-hashing stream under `seed` - so each one is built here and
shared between the rows of the same length.
*/

use allcrypt::mac::umac::Umac;
use std::collections::HashMap;

const VECTORS: &str = include_str!("../vectors/umac_nettle.vec");

type Record = Vec<(String, String)>;

fn section(name: &str) -> Vec<Record> {
    let header = format!("[{name}]");
    let start = VECTORS.lines().position(|line| line == header)
        .unwrap_or_else(|| panic!("no {header}"));
    let mut records = Vec::new();
    let mut current: Record = Vec::new();
    for line in VECTORS.lines().skip(start + 1) {
        if line.starts_with('[') {
            break;
        }
        if line.trim().is_empty() {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            continue;
        }
        let (key, value) = line.split_once(" = ").unwrap_or_else(|| panic!("{line}"));
        current.push((key.to_string(), value.to_string()));
    }
    if !current.is_empty() {
        records.push(current);
    }
    records
}

fn field<'a>(record: &'a Record, name: &str) -> &'a str {
    &record.iter().find(|(key, _)| key == name).unwrap_or_else(|| panic!("{name}")).1
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// The script's message: byte `i` is the top byte of
/// `(i + seed) * 0x9E3779B1 mod 2^32`.
fn message(seed: u32, length: usize) -> Vec<u8> {
    (0..length).map(|i| ((i as u32).wrapping_add(seed).wrapping_mul(0x9E37_79B1) >> 24) as u8)
        .collect()
}

/// The count the generator wrote into the header for `name`.
fn declared(name: &str) -> usize {
    VECTORS.lines()
        .filter_map(|line| line.strip_prefix("#   "))
        .find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(name)).then(|| words.next().unwrap().parse().unwrap())
        })
        .unwrap_or_else(|| panic!("no count for {name}"))
}

fn check(records: &[Record]) -> usize {
    let mut messages: HashMap<(u32, usize), Vec<u8>> = HashMap::new();
    let mut checked = 0;
    for record in records {
        let tag_len: usize = field(record, "bytes").parse().unwrap();
        let length: usize = field(record, "length").parse().unwrap();
        let seed: u32 = field(record, "seed").parse().unwrap();
        let data = messages.entry((seed, length)).or_insert_with(|| message(seed, length));
        let mut umac = Umac::new(&hex(field(record, "key")), tag_len).unwrap();
        let tag = umac.tag(data, &hex(field(record, "nonce"))).unwrap();
        assert_eq!(tag, hex(field(record, "tag")),
                   "length {length}, {tag_len} byte tag, nonce {}", field(record, "nonce"));
        checked += 1;
        // Long messages are built once per length; the rest are cheap.
        if length > 1 << 20 {
            messages.retain(|(_, l), _| *l == length);
        }
    }
    checked
}

#[test]
fn test_every_length_at_every_tag_size() {
    let records = section("umac");
    assert_eq!(records.len(), declared("umac"));
    assert!(records.len() > 800);
    // The 128 bit POLY stage must be in the file, at every tag size.
    let past = records.iter().filter(|r| field(r, "length").parse::<usize>().unwrap() > 1 << 24)
        .count();
    assert!(past >= 4 * 4, "{past} rows past 2^24 bytes");
    assert_eq!(check(&records), records.len());
}

/// SSH's nonce is the packet sequence number, eight bytes big endian, so
/// consecutive packets share a PDF block at 4 and 8 byte tags.
#[test]
fn test_sequence_numbers_as_nonces() {
    let records = section("ssh");
    assert_eq!(records.len(), declared("ssh"));
    assert!(records.iter().all(|r| field(r, "nonce").len() == 16));
    assert_eq!(check(&records), records.len());
}
