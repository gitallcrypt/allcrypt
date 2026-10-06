/*
ML-DSA against NIST's own validation vectors.

`vectors/ml_dsa.vec` (key generation, signing) and
`vectors/ml_dsa_sigver.vec` (verification), written by
`scripts/make_ml_dsa_vectors.py` from `usnistgov/ACVP-Server`.

Nothing on this machine implements ML-DSA, so these are the independent
opinion, and every section header's count is asserted before anything is
read from it.

## What each part reaches

Key generation reaches `ExpandA` (its index order and its three-byte
rejection), `ExpandS` (half-byte rejection at both `eta`), the NTT,
`Power2Round`, and both encodings.

**Deterministic signing reaches the whole rejection loop**, which is
what makes these vectors more than a check of the arithmetic: a skipped
or mis-bounded rejection check changes *which attempt* is returned, and
with it every byte of the signature - even though the signature it
returns instead would still verify. So would an attempt counter that
advanced by one rather than by `l`. Nothing a verifier does can see
either; only a signer's vectors can.

Verification's 48 refusals reach the commitment comparison, the bound on
`z`, the hint decoding and the message binding, each named.
*/

use allcrypt::pq::ml_dsa;
use std::collections::HashMap;

const VECTORS: &str = include_str!("../vectors/ml_dsa.vec");
const SIGVER: &str = include_str!("../vectors/ml_dsa_sigver.vec");

struct Case {
    mode: &'static str,
    parameter_set: &'static str,
    tc_id: u32,
    fields: HashMap<&'static str, &'static str>,
}

impl Case {
    fn text(&self, name: &str) -> &'static str {
        self.fields.get(name).copied().unwrap_or_else(|| panic!(
            "{} {} tcId {}: no field {name:?}", self.mode, self.parameter_set,
            self.tc_id))
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        let text = self.text(name);
        assert!(text.len().is_multiple_of(2), "tcId {}: {name}", self.tc_id);
        (0..text.len()).step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    }

    fn number(&self, name: &str) -> usize {
        self.text(name).parse().expect("a number")
    }

    fn set(&self) -> &'static ml_dsa::Parameters {
        ml_dsa::parameters(self.parameter_set).unwrap()
    }
}

/// Every case in `text`, with each section's declared count checked.
fn read(text: &'static str) -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let mut section: Option<(&'static str, &'static str)> = None;
    let mut declared: Vec<(usize, usize)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let parts: Vec<&str> = header.trim_end_matches(']')
                .split_whitespace().collect();
            assert_eq!(parts.len(), 3, "section header {line:?}");
            section = Some((parts[0], parts[1]));
            declared.push((parts[2].parse().expect("count"), cases.len()));
            continue;
        }
        let (name, value) = line.split_once(" = ")
            .or_else(|| line.strip_suffix(" =").map(|name| (name, "")))
            .unwrap_or_else(|| panic!("not a field: {line:?}"));
        if name == "tcId" {
            let (mode, parameter_set) = section.expect("a case outside any section");
            cases.push(Case { mode, parameter_set,
                              tc_id: value.parse().expect("tcId"),
                              fields: HashMap::new() });
        } else {
            let case = cases.last_mut().expect("a field before any tcId");
            assert!(case.fields.insert(name, value).is_none(),
                    "tcId {}: {name} twice", case.tc_id);
        }
    }
    for (index, (count, start)) in declared.iter().enumerate() {
        let end = declared.get(index + 1).map_or(cases.len(), |next| next.1);
        assert_eq!(end - start, *count, "section {index} declares {count}");
    }
    cases
}

fn sha256_hex(bytes: &[u8]) -> String {
    use allcrypt::hash_functions::HashFunction;
    allcrypt::to_hex(&allcrypt::hash_functions::sha2::SHA256::new(bytes).digest())
}

/// Length, prefix, digest: the order that localises a mismatch.
fn assert_derived(case: &Case, name: &str, got: &[u8]) {
    assert_eq!(got.len(), case.number(&format!("{name}Length")),
               "{} {} tcId {}: {name} length", case.mode, case.parameter_set,
               case.tc_id);
    assert_eq!(allcrypt::to_hex(&got[..64]),
               allcrypt::to_hex(&case.bytes(&format!("{name}Prefix"))),
               "{} {} tcId {}: the first 64 bytes of {name} differ",
               case.mode, case.parameter_set, case.tc_id);
    assert_eq!(sha256_hex(got),
               allcrypt::to_hex(&case.bytes(&format!("{name}Digest"))),
               "{} {} tcId {}: {name} differs after its first 64 bytes",
               case.mode, case.parameter_set, case.tc_id);
}

#[test]
fn test_the_vector_files_parse_to_what_they_should() {
    let cases = read(VECTORS);
    let mut by_mode: std::collections::BTreeMap<&str, usize> = Default::default();
    for case in &cases {
        let family = case.mode.split('-').next().unwrap();
        *by_mode.entry(family).or_insert(0) += 1;
    }
    assert_eq!(by_mode.get("keyGen"), Some(&75));
    assert_eq!(by_mode.get("sigGen"), Some(&72));
    assert_eq!(cases.len(), 147);

    // All twelve pre-hash functions are reached by the signing cases.
    let hashes: std::collections::BTreeSet<&str> = cases.iter()
        .filter(|c| c.mode.contains("preHash")).map(|c| c.text("hashAlg"))
        .collect();
    assert_eq!(hashes.len(), 12, "{hashes:?}");

    let sigver = read(SIGVER);
    assert_eq!(sigver.len(), 60);
    assert_eq!(sigver.iter().filter(|c| c.text("testPassed") == "false")
                   .count(), 48);
}

#[test]
fn test_every_key_generation_vector() {
    let mut done = 0;
    for case in read(VECTORS).iter().filter(|c| c.mode == "keyGen") {
        let (pk, sk) = ml_dsa::key_gen_internal(case.set(), &case.bytes("seed"))
            .unwrap();
        assert_derived(case, "pk", &pk);
        assert_derived(case, "sk", &sk);
        done += 1;
    }
    assert_eq!(done, 75);
}

/// All 72 signing cases, through whichever interface their section names.
#[test]
fn test_every_signing_vector() {
    let mut done = 0;
    for case in read(VECTORS).iter().filter(|c| c.mode.starts_with("sigGen-")) {
        let set = case.set();
        let sk = case.bytes("sk");
        let rnd = if case.mode.ends_with("-hedged") {
            case.bytes("rnd")
        } else {
            vec![0u8; 32]
        };
        let interface = case.mode.trim_start_matches("sigGen-")
            .trim_end_matches("-deterministic").trim_end_matches("-hedged");
        let signature = match interface {
            "internal" => ml_dsa::sign_internal(set, &sk, &case.bytes("message"),
                                                &rnd),
            "internal-externalMu" => ml_dsa::sign_mu(set, &sk, &case.bytes("mu"),
                                                     &rnd),
            "external-pure" => ml_dsa::sign(set, &sk, &case.bytes("message"),
                                            &case.bytes("context"), None, &rnd),
            "external-preHash" => ml_dsa::sign(
                set, &sk, &case.bytes("message"), &case.bytes("context"),
                Some(ml_dsa::PreHash::by_name(case.text("hashAlg")).unwrap()),
                &rnd),
            other => panic!("unknown interface {other:?}"),
        }.unwrap_or_else(|error| panic!("{} tcId {}: {error}", case.mode,
                                        case.tc_id));
        assert_derived(case, "signature", &signature);
        done += 1;
    }
    assert_eq!(done, 72);
}

/// All 60 verification cases: twelve accepted and forty-eight refused,
/// each for its stated reason, and refused as `Ok(false)`.
#[test]
fn test_every_verification_vector() {
    let mut refused: std::collections::BTreeMap<&str, usize> = Default::default();
    for case in read(SIGVER) {
        let set = case.set();
        let pk = case.bytes("pk");
        let signature = case.bytes("signature");
        let interface = case.mode.trim_start_matches("sigVer-");
        let verdict = match interface {
            "internal" => ml_dsa::verify_internal(set, &pk, &case.bytes("message"),
                                                  &signature),
            "internal-externalMu" => ml_dsa::verify_mu(set, &pk, &case.bytes("mu"),
                                                       &signature),
            "external-pure" => ml_dsa::verify(set, &pk, &case.bytes("message"),
                                              &case.bytes("context"), None,
                                              &signature),
            "external-preHash" => ml_dsa::verify(
                set, &pk, &case.bytes("message"), &case.bytes("context"),
                Some(ml_dsa::PreHash::by_name(case.text("hashAlg")).unwrap()),
                &signature),
            other => panic!("unknown interface {other:?}"),
        };
        let reason = case.text("reason");
        let want = case.text("testPassed") == "true";
        match verdict {
            Ok(got) => assert_eq!(got, want,
                "{} {} tcId {}: {reason:?} - {}", set.name, interface,
                case.tc_id,
                if want { "a valid signature was refused" }
                else { "accepted, so that part of the signature is not checked" }),
            Err(error) => panic!("{} {} tcId {}: {reason:?} should be \
                                  Ok({want}), not an error: {error}",
                                 set.name, interface, case.tc_id),
        }
        if !want {
            *refused.entry(reason).or_insert(0) += 1;
        }
    }
    assert_eq!(refused.len(), 4);
    assert!(refused.values().all(|count| *count == 12), "{refused:?}");
}

/// `api::MlDsaKey` and `api::MlDsaPublicKey` against the same vectors.
///
/// `from_seed` must give NIST's keys; `from_private` must recompute
/// NIST's public key from NIST's private key and sign as NIST does; the
/// public key must refuse what NIST refuses.
#[test]
fn test_the_api_layer() {
    use allcrypt::api::{MlDsaKey, MlDsaPublicKey};

    assert_eq!(allcrypt::api::ml_dsa_parameter_sets(),
               ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]);

    let cases = read(VECTORS);
    for case in cases.iter().filter(|c| c.mode == "keyGen").step_by(25) {
        let key = MlDsaKey::from_seed(case.parameter_set, &case.bytes("seed"))
            .unwrap();
        assert_derived(case, "pk", key.public_bytes());
        assert_derived(case, "sk", key.private_bytes());
        assert_eq!(key.seed(), Some(case.bytes("seed").as_slice()));

        // Imported in expanded form, the public key is recomputed.
        let again = MlDsaKey::from_private(case.parameter_set,
                                           key.private_bytes()).unwrap();
        assert_eq!(again.public_bytes(), key.public_bytes());
        assert_eq!(again.seed(), None);

        // Hedged signatures differ and verify; deterministic ones repeat.
        let one = key.sign(b"m", b"ctx", None).unwrap();
        let two = key.sign(b"m", b"ctx", None).unwrap();
        assert_ne!(one, two);
        let public = MlDsaPublicKey::from_public(case.parameter_set,
                                                 key.public_bytes()).unwrap();
        assert!(public.verify(b"m", b"ctx", None, &one).unwrap());
        assert!(public.verify(b"m", b"ctx", None, &two).unwrap());
        assert!(!public.verify(b"m", b"other", None, &one).unwrap());
        assert!(!public.verify(b"m", b"ctx", Some("SHA2-256"), &one).unwrap());
        assert_eq!(key.sign_deterministic(b"m", b"", Some("SHA3-256")).unwrap(),
                   key.sign_deterministic(b"m", b"", Some("SHA3-256")).unwrap());
    }

    // NIST's deterministic external signatures, through the facade.
    let mut signed = 0;
    for case in cases.iter().filter(|c| c.mode.starts_with("sigGen-external")
                                         && c.mode.ends_with("-deterministic")) {
        let key = MlDsaKey::from_private(case.parameter_set, &case.bytes("sk"))
            .unwrap_or_else(|error| panic!("tcId {}: {error}", case.tc_id));
        let pre_hash = case.fields.get("hashAlg").copied();
        let signature = key.sign_deterministic(&case.bytes("message"),
                                               &case.bytes("context"), pre_hash)
            .unwrap();
        assert_derived(case, "signature", &signature);
        assert!(key.verify(&case.bytes("message"), &case.bytes("context"),
                           pre_hash, &signature).unwrap());
        signed += 1;
    }
    assert_eq!(signed, 18);

    // NIST's external refusals, through the public key.
    let mut refused = 0;
    for case in read(SIGVER).iter().filter(|c| c.mode.starts_with("sigVer-external")) {
        let public = MlDsaPublicKey::from_public(case.parameter_set,
                                                 &case.bytes("pk")).unwrap();
        let got = public.verify(&case.bytes("message"), &case.bytes("context"),
                                case.fields.get("hashAlg").copied(),
                                &case.bytes("signature")).unwrap();
        assert_eq!(got, case.text("testPassed") == "true", "tcId {}", case.tc_id);
        refused += usize::from(!got);
    }
    assert_eq!(refused, 24);

    // Both directions, by message: a check written as `< 32` would pass a
    // 33 byte seed to key generation, which refuses it for its own reason.
    for length in [31usize, 33] {
        assert!(MlDsaKey::from_seed("ML-DSA-44", &vec![0; length]).err()
                    .expect("a seed of the wrong length is refused")
                    .contains(&format!("32 bytes, and this is {length}")));
    }
    assert!(MlDsaKey::generate("Dilithium2").is_err());
    assert!(MlDsaPublicKey::from_public("ML-DSA-44", &[0; 1311]).is_err());
    let key = MlDsaKey::generate("ML-DSA-44").unwrap();
    assert!(key.sign(b"m", &[0u8; 256], None).unwrap_err()
                .contains("at most 255"));
    assert!(key.sign(b"m", b"", Some("MD5")).unwrap_err()
                .contains("Unknown pre-hash"));
}
