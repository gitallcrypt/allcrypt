//! SNOW 3G, ZUC-128, ZUC-256 and the 3GPP modes over them, against three
//! sources, offline.
//!
//! ETSI/SAGE's implementors' test data, read here out of the vendored
//! documents' text at test time: SNOW 3G, UEA2 and UIA2 from
//! `rfcs/Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.txt`, ZUC, 128-EEA3 and
//! 128-EIA3 from `rfcs/eea3eia3testdatav11.txt`. Nothing is transcribed;
//! each parser asserts how many sets it found.
//!
//! Intel's ZUC-256 keystream and MAC vectors, as intel-ipsec-mb 2.0.3
//! carries them (`vectors/zuc256/`), read from the C initialisers.
//!
//! `vectors/snow3g_zuc.vec`, written by `scripts/make_snow3g_zuc_vectors.py`:
//! random inputs either side of the word, byte and block steps, every row
//! agreed by every witness that implements it.

use std::collections::HashMap;

use allcrypt::api::{self, AnyStreamCipher};

const DOC3: &str = include_str!("../rfcs/Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.txt");
const ZUCDATA: &str = include_str!("../rfcs/eea3eia3testdatav11.txt");

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn is_hex(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The test sets of `section` in a document: each "N.M Test Set K"
/// heading's text up to the next heading. The table of contents lists the
/// same headings followed by dot leaders, which are not taken.
fn test_sets(text: &str, section: char) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut heads = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        let mut words = t.split_whitespace();
        let (Some(number), Some("Test"), Some("Set"), Some(_), None) =
            (words.next(), words.next(), words.next(), words.next(), words.next()) else {
            continue;
        };
        let number = number.trim_end_matches('.');
        if number.len() == 3 && number.as_bytes()[1] == b'.' {
            heads.push((i, number.starts_with(section)));
        }
    }
    let mut out = Vec::new();
    for (k, &(i, ours)) in heads.iter().enumerate() {
        if !ours {
            continue;
        }
        let end = heads.get(k + 1).map_or(lines.len(), |&(j, _)| j);
        let mut body = Vec::new();
        for line in &lines[i + 1..end] {
            // A numbered section heading ends the set too: "5. INTEGRITY
            // ..." in one document, "5       INTEGRITY ..." in the other.
            let mut words = line.split_whitespace();
            let first = words.next().unwrap_or("").trim_end_matches('.');
            if first.len() == 1 && first.as_bytes()[0].is_ascii_digit()
                && words.next().is_some_and(|w| w.len() > 3
                    && w.bytes().all(|b| b.is_ascii_uppercase())) {
                break;
            }
            body.push(*line);
        }
        out.push(body.join("\n"));
    }
    out
}

/// The value after `label` - "Count-C    = 72A4F20F", "Key: 2B D6 ..." -
/// without a "(hex)" in front.
fn field<'a>(body: &'a str, label: &str) -> &'a str {
    for line in body.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix(label) else { continue };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')) else {
            continue;
        };
        let rest = rest.trim();
        return rest.strip_prefix("(hex)").map_or(rest, str::trim);
    }
    panic!("no {label} in a test set");
}

fn number(body: &str, label: &str, radix: u32) -> u32 {
    let value = field(body, label).split_whitespace().next().unwrap();
    u32::from_str_radix(value, radix).unwrap_or_else(|_| panic!("{label} = {value}"))
}

fn length(body: &str, label: &str) -> usize {
    field(body, label).split_whitespace().next().unwrap().parse().unwrap()
}

/// The hex block under `label` ("Plaintext:", "MESSAGE:"), up to the first
/// line that is not hex, skipping page furniture and a "(hex)" prefix,
/// stopping at a "(bin)" one; `ceil(bits / 8)` bytes, the document's
/// padding past them dropped and asserted to be under a word.
fn block(body: &str, label: &str, bits: usize) -> Vec<u8> {
    let mut lines = body.lines().skip_while(|l| l.trim() != label);
    lines.next().unwrap_or_else(|| panic!("no {label}"));
    let mut tokens = Vec::new();
    for line in lines {
        let mut t = line.trim();
        if t.is_empty() || t.contains("3GPP Confidentiality") || t.contains("Implementor")
            || t.contains(" of 2") {
            continue;
        }
        if t.starts_with("(bin)") {
            break;
        }
        if let Some(rest) = t.strip_prefix("(hex)") {
            t = rest.trim();
        }
        let words: Vec<&str> = t.split_whitespace().collect();
        if !words.iter().all(|w| is_hex(w)) {
            break;
        }
        tokens.extend(words.iter().map(|w| w.to_string()));
    }
    // UEA2 test set 5 prints the word 060876A0 as 60876A0; the printed
    // keystream and result settle it, and test_uea2 checks that.
    if let Some(at) = tokens.iter().position(|t| t == "60876A0") {
        tokens[at] = "060876A0".to_string();
    }
    let data = unhex(&tokens.concat());
    let need = bits.div_ceil(8);
    assert!(data.len() >= need && data.len() - need < 4, "{label}: {} bytes for {bits} bits",
            data.len());
    data[..need].to_vec()
}

fn clear_tail(data: &[u8], bits: usize) -> Vec<u8> {
    let mut out = data[..bits.div_ceil(8)].to_vec();
    if !bits.is_multiple_of(8) {
        *out.last_mut().unwrap() &= 0xffu8 << (8 - bits % 8);
    }
    out
}

/// The keystream words a keystream test set prints before its tables:
/// "z1: AB EE 97 04" in Doc3, "z1: 27bede74" and "Z2000: 7a574cdb" in the
/// ZUC data.
fn keystream_words(head: &str) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    for line in head.lines() {
        let t = line.trim();
        let Some((label, value)) = t.split_once(':') else { continue };
        let Some(index) = label.strip_prefix('z').or_else(|| label.strip_prefix('Z')) else {
            continue;
        };
        let Ok(index) = index.parse::<usize>() else { continue };
        let value: String = value.split_whitespace().collect();
        out.push((index, u32::from_str_radix(&value, 16).unwrap()));
    }
    out
}

fn check_keystream(name: &str, key: &[u8], iv: &[u8], words: &[(usize, u32)], label: &str) {
    let n = words.iter().map(|w| w.0).max().unwrap();
    let mut c = AnyStreamCipher::new(name, key, iv).unwrap();
    let z = c.update(&vec![0u8; 4 * n]).unwrap();
    for &(i, w) in words {
        assert_eq!(u32::from_be_bytes(z[4 * (i - 1)..4 * i].try_into().unwrap()), w,
                   "{label} z{i}");
    }
}

#[test]
fn test_snow3g_keystreams() {
    let sets = test_sets(DOC3, '3');
    assert_eq!(sets.len(), 4);
    let mut counts = Vec::new();
    for (k, body) in sets.iter().enumerate() {
        let head = body.split("K0").next().unwrap();
        let words = keystream_words(head);
        counts.push(words.len());
        check_keystream("snow3g", &unhex(field(head, "Key")), &unhex(field(head, "IV")), &words,
                        &format!("SNOW 3G set {}", k + 1));
    }
    // The fourth set's z2500 covers every table entry, the document says.
    assert_eq!(counts, [2, 2, 2, 4]);
}

#[test]
fn test_uea2() {
    let sets = test_sets(DOC3, '4');
    assert_eq!(sets.len(), 5);
    for (k, body) in sets.iter().enumerate() {
        let bits = length(body, "Length");
        let plaintext = block(body, "Plaintext:", bits);
        // The table beside the data: word number, keystream, result.
        let (mut keystream, mut result) = (String::new(), String::new());
        let table = body.split("Wordnumber").nth(1).unwrap();
        for line in table.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.is_empty() || !f[0].bytes().all(|b| b.is_ascii_digit())
                || !f[1..].iter().all(|w| is_hex(w)) {
                continue;
            }
            let half = (f.len() - 1) / 2;
            keystream += &f[1..1 + half].concat();
            result += &f[1 + half..].concat();
        }
        let (keystream, result) = (unhex(&keystream), unhex(&result));
        // The document agrees with itself, which is also what settles set
        // 5's misprinted plaintext word.
        let xored: Vec<u8> = plaintext.iter().zip(&keystream).map(|(a, b)| a ^ b).collect();
        assert_eq!(clear_tail(&xored, bits), clear_tail(&result, bits), "UEA2 set {}", k + 1);
        let key = unhex(field(body, "CK"));
        let count = number(body, "Count-C", 16);
        let bearer = number(body, "Bearer", 16) as u8;
        let direction = number(body, "Direction", 10) as u8;
        for name in ["uea2", "eea1", "128-NEA1"] {
            let got = api::mobile_cipher(name, &key, count, bearer, direction, &plaintext,
                                         Some(bits as u64)).unwrap();
            assert_eq!(got, clear_tail(&result, bits), "{name} set {}", k + 1);
        }
        // And back.
        let back = api::mobile_cipher("uea2", &key, count, bearer, direction,
                                      &clear_tail(&result, bits), Some(bits as u64)).unwrap();
        assert_eq!(back, clear_tail(&plaintext, bits));
    }
}

#[test]
fn test_uia2() {
    let sets = test_sets(DOC3, '5');
    assert_eq!(sets.len(), 6);
    let mut longest = 0;
    for (k, body) in sets.iter().enumerate() {
        let bits = length(body, "LENGTH");
        longest = longest.max(bits);
        let message = block(body, "MESSAGE:", bits);
        let mac = unhex(field(body, "MAC-I"));
        let got = api::uia2(&unhex(field(body, "IK")), number(body, "COUNT-I", 16),
                            number(body, "FRESH", 16), number(body, "DIRECTION", 10) as u8,
                            &message, Some(bits as u64)).unwrap();
        assert_eq!(got, mac, "UIA2 set {}", k + 1);
    }
    assert_eq!(longest, 16448);
}

#[test]
fn test_zuc_keystreams() {
    let sets = test_sets(ZUCDATA, '3');
    assert_eq!(sets.len(), 4);
    let mut counts = Vec::new();
    for (k, body) in sets.iter().enumerate() {
        let head = body.split("Initialisation Mode").next().unwrap();
        let words = keystream_words(head);
        counts.push(words.len());
        check_keystream("zuc128", &unhex(field(head, "Key")), &unhex(field(head, "IV")), &words,
                        &format!("ZUC set {}", k + 1));
    }
    assert_eq!(counts, [2, 2, 2, 3]);
}

#[test]
fn test_eea3() {
    let sets = test_sets(ZUCDATA, '4');
    assert_eq!(sets.len(), 5);
    for (k, body) in sets.iter().enumerate() {
        let bits = length(body, "Length");
        let plaintext = block(body, "Plaintext:", bits);
        let ciphertext = block(body, "Ciphertext:", bits);
        let key = unhex(field(body, "Key").split("(bin)").next().unwrap());
        let (count, bearer) = (number(body, "Count", 16), number(body, "Bearer", 16) as u8);
        let direction = number(body, "Direction", 16) as u8;
        for name in ["eea3", "nea3", "128-EEA3"] {
            let got = api::mobile_cipher(name, &key, count, bearer, direction, &plaintext,
                                         Some(bits as u64)).unwrap();
            assert_eq!(got, clear_tail(&ciphertext, bits), "{name} set {}", k + 1);
        }
    }
}

#[test]
fn test_eia3() {
    let sets = test_sets(ZUCDATA, '5');
    assert_eq!(sets.len(), 5);
    for (k, body) in sets.iter().enumerate() {
        let bits = length(body, "Length");
        let message = block(body, "Message:", bits);
        let key = unhex(field(body, "Key"));
        let mac = unhex(field(body, "MAC"));
        let got = api::mobile_mac("eia3", &key, number(body, "Count", 16),
                                  number(body, "Bearer", 16) as u8,
                                  number(body, "Direction", 16) as u8, &message,
                                  Some(bits as u64)).unwrap();
        assert_eq!(got, mac, "EIA3 set {}", k + 1);
    }
}

/// The bytes of a C string literal sequence: `"\x00\x01" "\x02"`.
fn c_bytes(literals: &str) -> Vec<u8> {
    literals.split("\\x").skip(1).map(|h| u8::from_str_radix(&h[..2], 16).unwrap()).collect()
}

/// The fields of each `{ ... }` initialiser in an intel-ipsec-mb test
/// file: numbers and string literals in order, the terminating all-zero
/// entry left out.
fn initialisers(text: &str) -> Vec<Vec<String>> {
    let body = &text[text.find("[] = {").unwrap() + 6..];
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

/// Intel's ZUC-256 keystreams: every message is zeros, so the ciphertext
/// is the keystream. IVs of 25 bytes and of 23, packed.
#[test]
fn test_zuc256_keystreams() {
    let entries = initialisers(include_str!("../vectors/zuc256/zuc_eea3_256.json.c"));
    assert_eq!(entries.len(), 10);
    let mut iv_lengths = HashMap::new();
    for e in &entries {
        let (key, iv, msg, ct) = (c_bytes(&e[3]), c_bytes(&e[4]), c_bytes(&e[5]), c_bytes(&e[6]));
        assert!(msg.iter().all(|&b| b == 0));
        assert_eq!(ct.len() * 8, e[8].parse::<usize>().unwrap());
        *iv_lengths.entry(iv.len()).or_insert(0) += 1;
        let mut c = AnyStreamCipher::new("zuc256", &key, &iv).unwrap();
        assert_eq!(c.update(&msg).unwrap(), ct, "ZUC-256 keystream test {}", e[2]);
    }
    assert_eq!(iv_lengths, HashMap::from([(25, 5), (23, 5)]));
}

#[test]
fn test_zuc256_macs() {
    let entries = initialisers(include_str!("../vectors/zuc256/zuc_eia3_256.json.c"));
    assert_eq!(entries.len(), 36);
    let mut tags = HashMap::new();
    for e in &entries {
        let (key, msg, tag) = (c_bytes(&e[3]), c_bytes(&e[4]), c_bytes(&e[5]));
        let (bits, iv) = (e[7].parse::<u64>().unwrap(), c_bytes(&e[8]));
        let tag_bits: u32 = e[1].parse().unwrap();
        *tags.entry(tag_bits).or_insert(0) += 1;
        assert_eq!(api::zuc_mac(&key, &iv, tag_bits, &msg, Some(bits)).unwrap(), tag,
                   "ZUC-256 MAC test {}", e[2]);
    }
    assert_eq!(tags, HashMap::from([(32, 12), (64, 12), (128, 12)]));
}

/// One row of vectors/snow3g_zuc.vec.
fn rows() -> Vec<(String, HashMap<String, String>)> {
    let text = include_str!("../vectors/snow3g_zuc.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .unwrap().parse().unwrap();
    let out: Vec<_> = text.lines().filter(|l| !l.starts_with('#')).map(|line| {
        let mut words = line.split_whitespace();
        let kind = words.next().unwrap().to_string();
        let fields = words.map(|w| {
            let (k, v) = w.split_once('=').unwrap();
            (k.to_string(), v.to_string())
        }).collect();
        (kind, fields)
    }).collect();
    assert_eq!(out.len(), declared);
    out
}

fn bytes_of(v: &str) -> Vec<u8> {
    if v == "-" { Vec::new() } else { unhex(v) }
}

#[test]
fn test_the_witnesses_rows() {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (kind, f) in rows() {
        let label = format!("{kind} {:?}", f.get("cipher").or(f.get("alg")).or(f.get("tag")));
        *seen.entry(label.clone()).or_insert(0) += 1;
        let key = unhex(&f["key"]);
        match kind.as_str() {
            "stream" => {
                let iv = unhex(&f["iv"]);
                let want = bytes_of(&f["keystream"]);
                let mut c = AnyStreamCipher::new(&f["cipher"], &key, &iv).unwrap();
                assert_eq!(c.update(&vec![0u8; want.len()]).unwrap(), want, "{label}");
                // In pieces of 1, 2, 3 .. bytes.
                let mut c = AnyStreamCipher::new(&f["cipher"], &key, &iv).unwrap();
                let (mut got, mut step) = (Vec::new(), 1);
                while got.len() < want.len() {
                    let n = step.min(want.len() - got.len());
                    got.extend(c.update(&vec![0u8; n]).unwrap());
                    step += 1;
                }
                assert_eq!(got, want, "{label} in pieces");
            }
            "f8" | "f9" => {
                let count = u32::from_str_radix(&f["count"], 16).unwrap();
                let direction: u8 = f["direction"].parse().unwrap();
                let bits: u64 = f["bits"].parse().unwrap();
                let data = bytes_of(&f["data"]);
                let got = match (kind.as_str(), f["alg"].as_str()) {
                    ("f8", alg) => api::mobile_cipher(alg, &key, count,
                                                      f["bearer"].parse().unwrap(), direction,
                                                      &data, Some(bits)).unwrap(),
                    ("f9", "uia2") => api::uia2(&key, count,
                                                u32::from_str_radix(&f["fresh"], 16).unwrap(),
                                                direction, &data, Some(bits)).unwrap(),
                    (_, alg) => api::mobile_mac(alg, &key, count, f["fresh"].parse().unwrap(),
                                                direction, &data, Some(bits)).unwrap(),
                };
                let want = bytes_of(f.get("result").unwrap_or_else(|| &f["mac"]));
                assert_eq!(got, want, "{label} {bits} bits");
            }
            "zucmac" => {
                let got = api::zuc_mac(&key, &unhex(&f["iv"]), f["tag"].parse().unwrap(),
                                       &bytes_of(&f["data"]),
                                       Some(f["bits"].parse().unwrap())).unwrap();
                assert_eq!(got, unhex(&f["mac"]), "{label} {} bits", f["bits"]);
            }
            other => panic!("unknown row {other}"),
        }
    }
    for label in ["stream Some(\"snow3g\")", "stream Some(\"zuc128\")", "stream Some(\"zuc256\")",
                  "f8 Some(\"uea2\")", "f8 Some(\"eea3\")", "f9 Some(\"uia2\")",
                  "f9 Some(\"eia1\")", "f9 Some(\"eia3\")", "zucmac Some(\"32\")",
                  "zucmac Some(\"64\")", "zucmac Some(\"128\")"] {
        assert!(seen.get(label).copied().unwrap_or(0) >= 20, "{label}: {seen:?}");
    }
}

/// The bits past the length in the last byte are not part of the
/// message: a MAC ignores them, and a cipher clears them.
#[test]
fn test_bits_past_the_length() {
    let key = [0x5au8; 16];
    for bits in [1u64, 7, 9, 63, 65, 100] {
        let n = bits.div_ceil(8) as usize;
        let clear = vec![0u8; n];
        let mut set = clear.clone();
        set[n - 1] |= 0xffu8 >> (bits % 8);
        for alg in api::MOBILE_MACS {
            assert_eq!(api::mobile_mac(alg, &key, 1, 2, 1, &clear, Some(bits)).unwrap(),
                       api::mobile_mac(alg, &key, 1, 2, 1, &set, Some(bits)).unwrap(),
                       "{alg} at {bits}");
        }
        assert_eq!(api::uia2(&key, 1, 2, 1, &clear, Some(bits)).unwrap(),
                   api::uia2(&key, 1, 2, 1, &set, Some(bits)).unwrap());
        assert_eq!(api::zuc_mac(&key, &[3; 16], 32, &clear, Some(bits)).unwrap(),
                   api::zuc_mac(&key, &[3; 16], 32, &set, Some(bits)).unwrap());
        for tag in [32, 64, 128] {
            assert_eq!(api::zuc_mac(&[4; 32], &[0; 25], tag, &clear, Some(bits)).unwrap(),
                       api::zuc_mac(&[4; 32], &[0; 25], tag, &set, Some(bits)).unwrap());
        }
        for alg in api::MOBILE_CIPHERS {
            let a = api::mobile_cipher(alg, &key, 1, 2, 1, &clear, Some(bits)).unwrap();
            let b = api::mobile_cipher(alg, &key, 1, 2, 1, &set, Some(bits)).unwrap();
            assert_eq!(a, b, "{alg} at {bits}");
        }
    }
}

#[test]
fn test_inputs_out_of_range_are_refused() {
    let key = [0u8; 16];
    assert_eq!(api::mobile_cipher("uea2", &key, 0, 32, 0, b"x", None).unwrap_err(),
               "BEARER is five bits: 0 to 31, not 32.");
    assert_eq!(api::mobile_mac("eia3", &key, 0, 0, 2, b"x", None).unwrap_err(),
               "DIRECTION is one bit: 0 or 1, not 2.");
    assert_eq!(api::uia2(&key, 0, 0, 2, b"x", None).unwrap_err(),
               "DIRECTION is one bit: 0 or 1, not 2.");
    assert_eq!(api::mobile_cipher("eea3", &key[..15], 0, 0, 0, b"x", None).unwrap_err(),
               "A 128-EEA3 key is 16 bytes, not 15.");
    assert_eq!(api::mobile_mac("eia1", &key[..15], 0, 0, 0, b"x", None).unwrap_err(),
               "A 128-EIA1 key is 16 bytes, not 15.");
    assert_eq!(api::mobile_cipher("eea3", &key, 0, 0, 0, b"xy", Some(17)).unwrap_err(),
               "17 bits of message are 3 bytes, not 2.");
    // More bytes than the bits fill is refused too, rather than the rest
    // dropped.
    assert_eq!(api::mobile_mac("eia3", &key, 0, 0, 0, b"xyz", Some(16)).unwrap_err(),
               "16 bits of message are 2 bytes, not 3.");
    assert!(api::mobile_cipher("eea2", &key, 0, 0, 0, b"x", None).unwrap_err()
        .starts_with("Unknown 3GPP confidentiality algorithm"));
    assert!(api::mobile_mac("uia2", &key, 0, 0, 0, b"x", None).unwrap_err()
        .contains("UIA1 and UIA2, which take a FRESH, are uia1 and uia2."));
    assert_eq!(api::zuc_mac(&key, &[0; 16], 64, b"x", None).unwrap_err(),
               "ZUC-128's MAC is 32 bits, not 64; ZUC-256's, with a 32 byte key, is 32, 64 \
                or 128.");
    assert_eq!(api::zuc_mac(&[0; 24], &[0; 16], 32, b"x", None).unwrap_err(),
               "A ZUC MAC key is 16 bytes (ZUC-128) or 32 (ZUC-256), not 24.");
}
