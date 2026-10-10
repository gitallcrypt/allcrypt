/*
RSA-OAEP against Wycheproof's decryption vectors.

`vectors/rsa_oaep.vec`, written by `scripts/make_oaep_vectors.py` from
C2SP/wycheproof: 898 tests over 86 keys, every hash from SHA-1 to
SHA-512/256, MGF1 under its own hash and under every other, labels, the
longest message a key takes, and 389 ciphertexts that must be refused -
each part of the padding changed in turn, a leading byte of 1, `m` of 0,
1 and `n - 1`, and ciphertexts that are not a reduced integer of the
modulus' length.

The decoding is checked against every `em` the script derived; the whole
decryption runs, private operation included, on every ciphertext that has
no `em` and on the 2048-bit SHA-256 group. Running all of them would be
several hundred private operations, most of a minute in a debug build,
over arithmetic that does not depend on the hashes and that the RSA unit
tests and `diff_check.py` already cover.
*/

use allcrypt::bignum::BigUint;
use allcrypt::publickey_ciphers::rsa::{self, RsaPrivateKey};
use std::collections::HashMap;

const VECTORS: &str = include_str!("../vectors/rsa_oaep.vec");
const FAILURE: &str = "RSA decryption failed.";

struct Group {
    file: &'static str,
    bits: usize,
    hash: &'static str,
    mgf: &'static str,
    key: HashMap<&'static str, &'static str>,
    tests: Vec<HashMap<&'static str, &'static str>>,
}

fn bytes(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert!(text.len().is_multiple_of(2), "odd hex: {text}");
    (0..text.len()).step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// Every group, with each section's declared count checked.
fn groups() -> Vec<Group> {
    let mut out: Vec<Group> = Vec::new();
    let mut declared = Vec::new();
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let parts: Vec<&str> = header.split(' ').collect();
            assert_eq!(parts.len(), 6, "{line}");
            declared.push(parts[5].parse::<usize>().unwrap());
            out.push(Group { file: parts[0], bits: parts[2].parse().unwrap(), hash: parts[3],
                             mgf: parts[4], key: HashMap::new(), tests: Vec::new() });
            continue;
        }
        let (name, value) = line.split_once(" = ").unwrap_or_else(|| panic!("{line}"));
        let group = out.last_mut().expect("a field before any section");
        if name == "tcId" {
            group.tests.push(HashMap::new());
        }
        match group.tests.last_mut() {
            Some(test) => {
                test.insert(name, value);
            }
            None => {
                group.key.insert(name, value);
            }
        }
    }
    let counted: Vec<usize> = out.iter().map(|g| g.tests.len()).collect();
    assert_eq!(counted, declared);
    assert_eq!(out.len(), 86);
    assert_eq!(counted.iter().sum::<usize>(), 898);
    out
}

fn key(group: &Group) -> RsaPrivateKey {
    let number = |name| BigUint::from_bytes_be(&bytes(group.key[name]));
    let key = RsaPrivateKey::from_primes(number("p"), number("q"), number("e")).unwrap();
    assert_eq!(key.public.n, number("n"), "{}", group.file);
    assert_eq!(key.public.n.bit_len(), group.bits);
    key
}

fn describe(group: &Group, test: &HashMap<&str, &str>) -> String {
    format!("{} tcId {} ({}; {})", group.file, test["tcId"], test["flags"], test["comment"])
}

/// The decoding, against every derived `em`: a valid test gives its
/// message, an invalid one the single refusal and nothing that says why.
#[test]
fn test_the_decoding_agrees_with_wycheproof() {
    let mut checked = 0;
    let mut refused = 0;
    let mut pairs = std::collections::BTreeSet::new();
    for group in groups() {
        for test in &group.tests {
            let Some(em) = test.get("em") else { continue };
            let found = rsa::eme_oaep_decode(&bytes(em), group.hash, group.mgf,
                                             &bytes(test["label"]));
            match test["result"] {
                "valid" => assert_eq!(found.as_deref(), Ok(&bytes(test["msg"])[..]),
                                      "{}", describe(&group, test)),
                "invalid" => {
                    assert_eq!(found, Err(FAILURE.to_string()), "{}", describe(&group, test));
                    refused += 1;
                }
                other => panic!("result {other}"),
            }
            pairs.insert((group.hash, group.mgf));
            checked += 1;
        }
    }
    assert_eq!((checked, refused), (782, 273));
    // The misc file pairs SHA-1 to SHA-512 with each other, 25; the
    // SHA-512/224 and /256 files pair each with itself and with SHA-1.
    assert_eq!(pairs.len(), 29, "{pairs:?}");
}

/// The whole decryption: every ciphertext with no `em` - wrong length,
/// not reduced, empty - must be refused with the same error, and the
/// 2048-bit SHA-256 group must decrypt end to end, which also checks the
/// script's `em` against the private operation. One group, because the
/// private operation does not depend on the hashes and costs about 90 ms
/// a time in a debug build; the decoding test covers every pairing.
#[test]
fn test_the_whole_decryption_agrees_with_wycheproof() {
    let mut whole = 0;
    let mut chosen = 0;
    for group in groups() {
        let everything = group.file == "rsa_oaep_2048_sha256_mgf1sha256_test";
        chosen += everything as usize;
        if !everything && group.tests.iter().all(|t| t.contains_key("em")) {
            continue;
        }
        let key = key(&group);
        for test in &group.tests {
            if !everything && test.contains_key("em") {
                continue;
            }
            let found = rsa::decrypt_oaep(&key, group.hash, group.mgf, &bytes(test["label"]),
                                          &bytes(test["ct"]));
            match test["result"] {
                "valid" => assert_eq!(found.as_deref(), Ok(&bytes(test["msg"])[..]),
                                      "{}", describe(&group, test)),
                _ => assert_eq!(found, Err(FAILURE.to_string()), "{}", describe(&group, test)),
            }
            if let Some(em) = test.get("em") {
                let c = BigUint::from_bytes_be(&bytes(test["ct"]));
                assert_eq!(key.raw(&c).unwrap().to_bytes_be_padded(key.size()).unwrap(),
                           bytes(em), "{}: the script's em", describe(&group, test));
            }
            whole += 1;
        }
    }
    assert_eq!(chosen, 1);
    assert!(whole > 100, "{whole}");
}

/// Unpadded RSA against the same data. `em` is what the script got from
/// the private key with Python's integers, so RSAEP of `em` must give the
/// Wycheproof ciphertext back byte for byte - every group, since the
/// public operation is cheap - and RSADP of that ciphertext must give
/// `em`, through the blinded CRT path, on the 2048-bit SHA-256 group.
/// Both directions keep the leading zero a valid encoded message starts
/// with.
#[test]
fn test_unpadded_rsa_agrees_with_wycheproof() {
    let mut encrypted = 0;
    let mut stripped = 0;
    let mut decrypted = 0;
    for group in groups() {
        let with_em: Vec<_> = group.tests.iter().filter(|t| t.contains_key("em")).collect();
        if with_em.is_empty() {
            continue;
        }
        let key = key(&group);
        let public = key.public_key();
        let everything = group.file == "rsa_oaep_2048_sha256_mgf1sha256_test";
        for test in with_em {
            let (em, ct) = (bytes(test["em"]), bytes(test["ct"]));
            assert_eq!(rsa::encrypt_raw(&public, &em).unwrap(), ct,
                       "{}", describe(&group, test));
            // The same integer without its leading zero byte, where it has
            // one - an invalid test's block may start with anything.
            if em[0] == 0 {
                assert_eq!(rsa::encrypt_raw(&public, &em[1..]).unwrap(), ct);
                stripped += 1;
            }
            encrypted += 1;
            if everything {
                assert_eq!(rsa::decrypt_raw(&key, &ct).unwrap(), em,
                           "{}", describe(&group, test));
                decrypted += 1;
            }
        }
    }
    assert_eq!(encrypted, 782);
    assert!(stripped > 500, "{stripped}");
    assert!(decrypted > 10, "{decrypted}");
}
