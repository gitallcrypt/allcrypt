/*
RSA Laboratories' PKCS #1 v2.1 test vectors, `oaep-vect.txt` and
`pss-vect.txt`, read out of the documents at test time
(`rfcs/pkcs-1v2-1-oaep-vect.txt`, `rfcs/pkcs-1v2-1-pss-vect.txt`).

Each file has ten keys - 1024 to 1031 bits, then 1536 and 2048 - and six
operations per key, all under SHA-1 with MGF1-SHA-1, each printed with
the randomness it used: OAEP's seed and PSS's salt. That is what makes
them the check on `encrypt_oaep_with_seed` and `sign_pss_with_salt`:
given the document's seed or salt, the ciphertext or signature must come
out byte for byte. The odd sizes matter for PSS, whose encoded message is
a byte shorter than the modulus whenever the modulus is one bit past a
multiple of eight, and has its top bits cleared otherwise.

The private keys are rebuilt from the primes and checked against the
printed modulus, so a key the parser assembled wrongly fails there
rather than as a wrong signature.
*/

use allcrypt::bignum::BigUint;
use allcrypt::hash_functions::{sha1::SHA1, HashFunction};
use allcrypt::publickey_ciphers::rsa::{self, RsaPrivateKey};
use std::collections::HashMap;

const OAEP: &str = include_str!("../rfcs/pkcs-1v2-1-oaep-vect.txt");
const PSS: &str = include_str!("../rfcs/pkcs-1v2-1-pss-vect.txt");

type Fields = HashMap<String, Vec<u8>>;

struct Key {
    fields: Fields,
    cases: Vec<(String, Fields)>,
}

/// The keys and their cases. A `# label:` line names the field the hex
/// lines under it fill; `# Example N` starts a key and `# OAEP Example`
/// or `# PSS Example` a case under it. Both keys' sections print a
/// field called `Exponent` - `e` under the public key, `d` under the
/// private - so a key keeps only the first of each name, and `d` is
/// never read: the key is rebuilt from the primes.
fn parse(document: &str, case_marker: &str) -> Vec<Key> {
    let mut keys: Vec<Key> = Vec::new();
    let mut label: Option<String> = None;
    let mut in_case = false;
    for line in document.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# ") {
            if rest.starts_with("Example ") && rest.contains("RSA key pair") {
                keys.push(Key { fields: Fields::new(), cases: Vec::new() });
                in_case = false;
                label = None;
            } else if rest.starts_with(case_marker) {
                let key = keys.last_mut().expect("a case before any key");
                key.cases.push((rest.to_string(), Fields::new()));
                in_case = true;
                label = None;
            } else if let Some(name) = rest.strip_suffix(':') {
                let name = name.trim().to_string();
                let seen = !in_case && keys.last().is_some_and(|k| k.fields.contains_key(&name));
                label = if seen { None } else { Some(name) };
            } else {
                label = None;
            }
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.is_empty() || !words.iter().all(|w| w.len() == 2
                                                  && w.chars().all(|c| c.is_ascii_hexdigit())) {
            label = None;
            continue;
        }
        let Some(name) = &label else { continue };
        let bytes = words.iter().map(|w| u8::from_str_radix(w, 16).unwrap());
        let key = keys.last_mut().expect("hex before any key");
        let fields = if in_case { &mut key.cases.last_mut().unwrap().1 } else { &mut key.fields };
        fields.entry(name.clone()).or_default().extend(bytes);
    }
    keys
}

/// The key from its primes, checked against the printed modulus.
fn key(fields: &Fields) -> RsaPrivateKey {
    let number = |name: &str| BigUint::from_bytes_be(&fields[name]);
    let key = RsaPrivateKey::from_primes(number("Prime 1"), number("Prime 2"),
                                         number("Public exponent")).unwrap();
    assert_eq!(key.public.n, number("Modulus"));
    key
}

fn sizes(keys: &[Key]) -> Vec<usize> {
    keys.iter().map(|k| BigUint::from_bytes_be(&k.fields["Modulus"]).bit_len()).collect()
}

#[test]
fn test_oaep_with_the_documents_seeds() {
    let keys = parse(OAEP, "OAEP Example");
    assert_eq!(keys.len(), 10);
    assert_eq!(sizes(&keys), [1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1536, 2048]);
    let mut checked = 0;
    for entry in &keys {
        assert_eq!(entry.cases.len(), 6);
        let key = key(&entry.fields);
        for (name, case) in &entry.cases {
            let (message, seed, ciphertext) = (&case["Message"], &case["Seed"],
                                               &case["Encryption"]);
            assert_eq!(seed.len(), 20, "{name}");
            assert_eq!(&rsa::encrypt_oaep_with_seed(&key.public, "sha1", "sha1", b"",
                                                    message, seed).unwrap(),
                       ciphertext, "{name}");
            assert_eq!(&rsa::decrypt_oaep(&key, "sha1", "sha1", b"", ciphertext).unwrap(),
                       message, "{name}");
            // The same through the two halves: unpadded decryption, then
            // the decoding alone.
            let block = rsa::decrypt_raw(&key, ciphertext).unwrap();
            assert_eq!(&rsa::eme_oaep_decode(&block, "sha1", "sha1", b"").unwrap(),
                       message, "{name}");
            checked += 1;
        }
    }
    assert_eq!(checked, 60);
}

#[test]
fn test_pss_with_the_documents_salts() {
    let keys = parse(PSS, "PSS Example");
    assert_eq!(keys.len(), 10);
    assert_eq!(sizes(&keys), [1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1536, 2048]);
    let mut checked = 0;
    for entry in &keys {
        assert_eq!(entry.cases.len(), 6);
        let key = key(&entry.fields);
        for (name, case) in &entry.cases {
            let (message, salt, signature) = (&case["Message to be signed"], &case["Salt"],
                                              &case["Signature"]);
            assert_eq!(salt.len(), 20, "{name}");
            let digest = SHA1::new(message).digest();
            assert_eq!(&rsa::sign_pss_with_salt(&key, "sha1", &digest, salt).unwrap(),
                       signature, "{name}");
            assert!(rsa::verify_pss(&key.public, "sha1", &digest, signature, 20).unwrap(),
                    "{name}");
            checked += 1;
        }
    }
    assert_eq!(checked, 60);
}
