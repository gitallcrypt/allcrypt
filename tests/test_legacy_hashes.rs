/*!
`vectors/legacy_hashes.vec` against RIPEMD-128, -256 and -320, HAS-160,
Whirlpool-0, Whirlpool-T and MD6, through `api::AnyHash` by name. Every
digest in the file is one on which the reference implementations agree;
the file's header lists them.
*/

use allcrypt::api::AnyHash;
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/legacy_hashes.vec");
const NAMES: [&str; 11] = ["ripemd128", "ripemd256", "ripemd320", "has160", "whirlpool_0",
                           "whirlpool_t", "md6_128", "md6_224", "md6_256", "md6_384",
                           "md6_512"];

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// An input and the (name, digest) pairs under it.
type Record = (Vec<u8>, Vec<(String, String)>);

fn records() -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    for line in VECTORS.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once(" = ").unwrap();
        let input = match key {
            "message" => Some(unhex(value)),
            "pattern" => {
                let n: usize = value.parse().unwrap();
                Some((0..n).map(|i| ((i * 167 + 29) & 0xff) as u8).collect())
            }
            "repeat" => {
                let (byte, count) = value.split_once(' ').unwrap();
                Some(vec![u8::from_str_radix(byte, 16).unwrap(); count.parse().unwrap()])
            }
            _ => None,
        };
        match input {
            Some(input) => out.push((input, Vec::new())),
            None => out.last_mut().unwrap().1.push((key.to_string(), value.to_string())),
        }
    }
    out
}

#[test]
fn test_the_reference_implementations_answers() {
    let all = records();
    assert_eq!(all.len(), 317);
    let mut checked = 0;
    for (input, digests) in &all {
        assert_eq!(digests.len(), NAMES.len());
        for (name, want) in digests {
            let mut hash = AnyHash::new(name).unwrap();
            hash.update(input);
            let got: String = hash.digest().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&got, want, "{name} of {} bytes", input.len());
            checked += 1;
        }
    }
    assert_eq!(checked, 317 * NAMES.len());
}

/// The names are in the API's list of hashes.
#[test]
fn test_the_names_are_listed() {
    for name in NAMES {
        assert!(allcrypt::api::HASHES.contains(&name), "{name}");
    }
}
