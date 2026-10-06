/*
ML-KEM against NIST's own validation vectors.

`vectors/ml_kem.vec`, written by `scripts/make_ml_kem_vectors.py` from
`usnistgov/ACVP-Server`: key generation (25 cases per parameter set),
encapsulation (10), decapsulation (10), and the two key checks (10 each,
half of them keys NIST decided must be refused).

## These vectors are the entire independent opinion

Nothing on this machine implements ML-KEM: python-cryptography 46 has no
KEM module, OpenSSL here is 3.0 and grew ML-KEM in 3.5, and PyPI is
unreachable from the development container so no Python reference can be
installed either. All three were checked rather than assumed.

So the same bar applies as for SLH-DSA, and for the same reason: a parser
that silently finds nothing turns every loop below into a pass, so the
section headers carry their counts and the reader asserts them.

## What each part reaches

Key generation depends on the matrix `A` - and therefore on `SampleNTT`,
its rejection loop, its twelve bit split and the order of its two index
bytes - on `SamplePolyCBD`, on the NTT and the base-case multiply, on
`ByteEncode_12`, and on `G` being fed the `k` domain separator.

Encapsulation adds the transpose of `A`, the compression widths `du` and
`dv`, and the order the PRF counter runs in. Decapsulation adds the
Fujisaki-Okamoto transform, and **the decapsulation test measures that
NIST's cases take both of its paths** - an implementation that always
returned the implicit-rejection secret, or never did, would otherwise be
checked only on the path it happened to take.
*/

const VECTORS: &str = include_str!("../vectors/ml_kem.vec");

/// One ACVP case, of whichever function its section named.
///
/// The fields are kept by name rather than as one struct member each,
/// because five functions with different fields would otherwise be five
/// structs or one struct full of empty members. The accessors are what
/// keep that honest: [`Case::bytes`] and [`Case::text`] **panic** on a
/// field the case does not have, so a field renamed in the vector file
/// fails loudly instead of reading as empty and comparing against
/// nothing.
struct Case {
    mode: &'static str,
    parameter_set: &'static str,
    tc_id: u32,
    fields: std::collections::HashMap<String, String>,
}

impl Case {
    fn text(&self, name: &str) -> &str {
        self.fields.get(name).unwrap_or_else(|| panic!(
            "{} {} tcId {}: no field {name:?}", self.mode, self.parameter_set,
            self.tc_id))
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        unhex(self.text(name))
    }

    fn number(&self, name: &str) -> usize {
        self.text(name).parse().unwrap_or_else(|_| panic!(
            "{} tcId {}: {name} is not a number", self.mode, self.tc_id))
    }

    /// `true` or `false`, and nothing else - a key check whose verdict did
    /// not parse must not quietly become one of the two.
    fn verdict(&self, name: &str) -> bool {
        match self.text(name) {
            "true" => true,
            "false" => false,
            other => panic!("{} tcId {}: {name} is {other:?}, not a boolean",
                            self.mode, self.tc_id),
        }
    }
}

/// Every function this reader understands.
///
/// Checked rather than ignored: an unknown section would parse into
/// cases nothing reads, and the count assertions further down would then
/// be the only thing standing between it and silence.
const KNOWN_MODES: [&str; 5] = ["keyGen", "encapsulation", "decapsulation",
                                "encapsulationKeyCheck",
                                "decapsulationKeyCheck"];

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "not a hex string: {text:?}");
    (0..text.len()).step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16)
                      .unwrap_or_else(|_| panic!("not hex: {text:?}")))
        .collect()
}

/// Every case in the file, with each section's declared count checked.
fn vectors() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let mut counted: Vec<(&'static str, &'static str, usize, usize)> =
        Vec::new();
    let mut section: Option<(&'static str, &'static str, usize)> = None;
    let mut fields: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    fn flush(cases: &mut Vec<Case>,
             section: &Option<(&'static str, &'static str, usize)>,
             fields: &mut std::collections::HashMap<String, String>) {
        if fields.is_empty() {
            return;
        }
        let (mode, parameter_set, _) =
            section.expect("a case outside any section");
        let tc_id = fields.get("tcId").expect("a case with no tcId")
            .parse().expect("tcId is a number");
        cases.push(Case { mode, parameter_set, tc_id,
                          fields: std::mem::take(fields) });
    }

    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            flush(&mut cases, &section, &mut fields);
            if let Some((mode, name, count)) = section {
                counted.push((mode, name, count, cases.len()));
            }
            let header = header.strip_suffix(']')
                .unwrap_or_else(|| panic!("unterminated section: {line:?}"));
            let words: Vec<&str> = header.split_whitespace().collect();
            assert_eq!(words.len(), 3,
                       "a section header is `[mode parameterSet count]`, not \
                        {header:?}");
            assert!(KNOWN_MODES.contains(&words[0]),
                    "unknown section {:?}; add it to KNOWN_MODES with a test \
                     that reads it", words[0]);
            let mode: &'static str = words[0].to_string().leak();
            let name: &'static str = words[1].to_string().leak();
            section = Some((mode, name, words[2].parse().expect("a count")));
            continue;
        }
        let (key, value) = line.split_once(" = ")
            .unwrap_or_else(|| panic!("not `key = value`: {line:?}"));
        if key == "tcId" && !fields.is_empty() {
            flush(&mut cases, &section, &mut fields);
        }
        fields.insert(key.trim().to_string(), value.trim().to_string());
    }
    flush(&mut cases, &section, &mut fields);
    if let Some((mode, name, count)) = section {
        counted.push((mode, name, count, cases.len()));
    }

    let mut start = 0;
    for (mode, name, declared, end) in &counted {
        let read = end - start;
        assert_eq!(read, *declared,
                   "vectors/ml_kem.vec: section {mode} {name} says {declared} \
                    cases and holds {read}. Re-run \
                    scripts/make_ml_kem_vectors.py rather than editing the \
                    file.");
        start = *end;
    }
    assert_eq!(counted.len(), 15,
               "vectors/ml_kem.vec should hold five functions for each of \
                the three parameter sets");
    cases
}

/// The cases for one function.
fn cases_of(mode: &str) -> Vec<Case> {
    vectors().into_iter().filter(|case| case.mode == mode).collect()
}

/// What was read, before anything is done with it.
#[test]
fn test_the_vector_file_parses_to_what_it_should() {
    let cases = vectors();
    assert_eq!(cases.len(), 195,
               "75 keyGen, 30 encapsulation, 30 decapsulation, and 30 of \
                each key check");

    let mut per_mode: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for case in &cases {
        *per_mode.entry(case.mode).or_insert(0) += 1;
        let set = allcrypt::pq::ml_kem::parameters(case.parameter_set)
            .unwrap_or_else(|error| panic!("{error}"));

        match case.mode {
            "keyGen" => {
                assert_eq!(case.bytes("d").len(), 32);
                assert_eq!(case.bytes("z").len(), 32);
                // **The lengths NIST states must be the ones this
                // library's parameter table predicts** - the first
                // independent word on the table.
                assert_eq!(case.number("ekLength"),
                           set.encapsulation_key_len(), "{} ek", set.name);
                assert_eq!(case.number("dkLength"),
                           set.decapsulation_key_len(), "{} dk", set.name);
                assert_eq!(case.bytes("ekDigest").len(), 32);
                assert_eq!(case.bytes("dkDigest").len(), 32);
            }
            "encapsulation" => {
                assert_eq!(case.bytes("ek").len(), set.encapsulation_key_len());
                assert_eq!(case.bytes("m").len(), 32);
                assert_eq!(case.bytes("k").len(), 32);
                // The first independent word on `du` and `dv`, which only
                // a ciphertext uses.
                assert_eq!(case.number("cLength"), set.ciphertext_len(),
                           "{}: NIST says a ciphertext is {} bytes",
                           set.name, case.number("cLength"));
            }
            "decapsulation" => {
                assert_eq!(case.bytes("dk").len(), set.decapsulation_key_len());
                assert_eq!(case.bytes("c").len(), set.ciphertext_len());
                assert_eq!(case.bytes("k").len(), 32);
            }
            "encapsulationKeyCheck" => {
                let _ = case.verdict("testPassed");
                case.bytes("ek");
            }
            "decapsulationKeyCheck" => {
                let _ = case.verdict("testPassed");
                case.bytes("dk");
            }
            other => panic!("unhandled mode {other}"),
        }
    }
    let expected: std::collections::BTreeMap<&str, usize> = [
        ("decapsulation", 30), ("decapsulationKeyCheck", 30),
        ("encapsulation", 30), ("encapsulationKeyCheck", 30),
        ("keyGen", 75)].into_iter().collect();
    assert_eq!(per_mode, expected);

    // The key checks are half negative, and that is what they are for:
    // if a regeneration ever produced only valid keys, the tests below
    // would pass on a check that accepts everything.
    for mode in ["encapsulationKeyCheck", "decapsulationKeyCheck"] {
        let refused = cases.iter().filter(|case| case.mode == mode
                                          && !case.verdict("testPassed"))
            .count();
        assert_eq!(refused, 15, "{mode}: half of the 30 should be invalid");
    }
}

/// All 75 cases: `(d, z)` in, `ek` and `dk` out.
///
/// Fast - a key is one matrix of 256-coefficient polynomials and a handful
/// of NTTs, nothing like SLH-DSA's Merkle trees - so there is no subset
/// here and no `#[ignore]`.
#[test]
fn test_every_key_generation_vector() {
    use allcrypt::hash_functions::HashFunction;

    let mut done = 0;
    for case in cases_of("keyGen") {
        let set = allcrypt::pq::ml_kem::parameters(case.parameter_set).unwrap();
        let (ek, dk) = allcrypt::pq::ml_kem::key_gen_internal(
            set, &case.bytes("d"), &case.bytes("z"))
            .unwrap_or_else(|error| panic!("{} tcId {}: {error}",
                                           set.name, case.tc_id));

        assert_eq!(ek.len(), case.number("ekLength"), "{} tcId {}: ek length",
                   set.name, case.tc_id);
        assert_eq!(dk.len(), case.number("dkLength"), "{} tcId {}: dk length",
                   set.name, case.tc_id);

        // The prefix first, because it localises: ek begins with the
        // encoding of t_hat, so a mismatch in the first 64 bytes points at
        // A, at s and e, or at the NTT, while a matching prefix and a
        // wrong digest points further in.
        assert_eq!(allcrypt::to_hex(&ek[..64]),
                   allcrypt::to_hex(&case.bytes("ekPrefix")),
                   "{} tcId {}: the first 64 bytes of ek differ, so the fault \
                    is in t_hat - the matrix A, the secrets s and e, or the \
                    transform",
                   set.name, case.tc_id);
        assert_eq!(allcrypt::to_hex(&dk[..64]),
                   allcrypt::to_hex(&case.bytes("dkPrefix")),
                   "{} tcId {}: the first 64 bytes of dk differ, so the fault \
                    is in s rather than in t_hat", set.name, case.tc_id);

        let digest = |bytes: &[u8]| {
            allcrypt::to_hex(&allcrypt::hash_functions::sha2::SHA256::new(bytes)
                                 .digest())
        };
        assert_eq!(digest(&ek), allcrypt::to_hex(&case.bytes("ekDigest")),
                   "{} tcId {}: ek", set.name, case.tc_id);
        assert_eq!(digest(&dk), allcrypt::to_hex(&case.bytes("dkDigest")),
                   "{} tcId {}: dk", set.name, case.tc_id);
        done += 1;
    }
    assert_eq!(done, 75);
}

/// The keys this library generates pass FIPS 203's own two key checks,
/// and keys altered in known ways fail them.
///
/// Weaker than it looks on its own - a key we made should pass checks we
/// wrote - which is why NIST's own negatives are tested separately, in
/// `test_the_key_check_vectors`. These are the alterations whose reason
/// for failing is known exactly, including one that must *not* fail.
#[test]
fn test_the_key_checks_accept_real_keys_and_refuse_altered_ones() {
    for case in cases_of("keyGen").into_iter().step_by(25) {
        let set = allcrypt::pq::ml_kem::parameters(case.parameter_set).unwrap();
        let (ek, dk) = allcrypt::pq::ml_kem::key_gen_internal(
            set, &case.bytes("d"), &case.bytes("z")).unwrap();

        assert!(allcrypt::pq::ml_kem::modulus_check(set, &ek).unwrap(),
                "{}: a real key should pass the modulus check", set.name);
        assert!(allcrypt::pq::ml_kem::hash_check(set, &dk).unwrap(),
                "{}: a real key should pass the hash check", set.name);

        // A twelve bit field raised above q. 0x0fff in the first field is
        // 4095, well above q, so decoding reduces it and re-encoding
        // differs - which is the whole content of the modulus check.
        let mut bad = ek.clone();
        bad[0] = 0xff;
        bad[1] |= 0x0f;
        assert!(!allcrypt::pq::ml_kem::modulus_check(set, &bad).unwrap(),
                "{}: a non-canonical coefficient should be refused", set.name);

        // The seed `rho` is outside the packed coefficients, so changing
        // it must *not* fail the modulus check - that check is about the
        // encoding, not about authenticity, and a test that passed here
        // for the wrong reason would be checking the wrong thing.
        let mut other_seed = ek.clone();
        let last = other_seed.len() - 1;
        other_seed[last] ^= 1;
        assert!(allcrypt::pq::ml_kem::modulus_check(set, &other_seed).unwrap(),
                "{}: the modulus check covers the coefficients only",
                set.name);

        // The hash check does cover the embedded ek, so the same change
        // inside dk fails it.
        let mut bad = dk.clone();
        bad[384 * set.k] ^= 1;
        assert!(!allcrypt::pq::ml_kem::hash_check(set, &bad).unwrap(),
                "{}: an altered embedded ek should be caught", set.name);

        // And so does altering the embedded hash itself.
        let mut bad = dk.clone();
        bad[768 * set.k + 32] ^= 1;
        assert!(!allcrypt::pq::ml_kem::hash_check(set, &bad).unwrap());

        // A wrong length is `false`, not an error.
        assert!(!allcrypt::pq::ml_kem::modulus_check(set, &ek[..ek.len() - 1])
                    .unwrap());
        assert!(!allcrypt::pq::ml_kem::hash_check(set, &dk[..dk.len() - 1])
                    .unwrap());
    }
}

/// The three parameter sets differ in every field that should differ.
#[test]
fn test_the_parameter_table_is_what_fips_203_publishes() {
    let sets = allcrypt::pq::ml_kem::PARAMETER_SETS;
    assert_eq!(sets.len(), 3);

    // The published key and ciphertext sizes, which are the one place the
    // table meets a number a reader can look up. `ek` and `dk` are also
    // checked against NIST's own statement of them above, so these two
    // agree with ACVP, and the ciphertext length is checked against NIST's
    // statement of it in `test_the_vector_file_parses_to_what_it_should`.
    let expected = [("ML-KEM-512", 800, 1632, 768),
                    ("ML-KEM-768", 1184, 2400, 1088),
                    ("ML-KEM-1024", 1568, 3168, 1568)];
    for (name, ek, dk, ciphertext) in expected {
        let set = allcrypt::pq::ml_kem::parameters(name).unwrap();
        assert_eq!(set.encapsulation_key_len(), ek, "{name} ek");
        assert_eq!(set.decapsulation_key_len(), dk, "{name} dk");
        assert_eq!(set.ciphertext_len(), ciphertext, "{name} ciphertext");
    }

    assert!(allcrypt::pq::ml_kem::parameters("ML-KEM-640").unwrap_err()
                .contains("Unknown ML-KEM parameter set"));
    assert!(allcrypt::pq::ml_kem::parameters("Kyber768").is_err());
}

/// `J(z ‖ c)`, computed here from SHAKE-256 directly rather than through
/// the module's own helper, so the test's idea of the rejection secret
/// does not share a fault with the code it is checking.
fn rejection_secret(dk: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    use allcrypt::hash_functions::HashFunction;
    let z = &dk[dk.len() - 32..];
    let mut sponge = allcrypt::hash_functions::keccak::Keccak::shake(256, 32)
        .unwrap();
    sponge.update(z);
    sponge.update(ciphertext);
    sponge.squeeze(32)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use allcrypt::hash_functions::HashFunction;
    allcrypt::to_hex(&allcrypt::hash_functions::sha2::SHA256::new(bytes)
                         .digest())
}

/// All 30 encapsulation cases: `(ek, m)` in, the shared secret and the
/// ciphertext out.
///
/// The ciphertext is checked by length, then its first 64 bytes, then its
/// digest. The prefix is the start of `u`, compressed to `du` bits, so a
/// mismatch there points at the transpose of `A`, at `y` and `e1`, or at
/// `du`; a matching prefix and a wrong digest points at `v` - the message
/// encoding, `e2`, or `dv`.
#[test]
fn test_every_encapsulation_vector() {
    let mut done = 0;
    for case in cases_of("encapsulation") {
        let set = allcrypt::pq::ml_kem::parameters(case.parameter_set).unwrap();
        let (shared, ciphertext) = allcrypt::pq::ml_kem::encapsulate_internal(
            set, &case.bytes("ek"), &case.bytes("m"))
            .unwrap_or_else(|error| panic!("{} tcId {}: {error}",
                                           set.name, case.tc_id));

        assert_eq!(ciphertext.len(), case.number("cLength"),
                   "{} tcId {}: ciphertext length", set.name, case.tc_id);
        assert_eq!(allcrypt::to_hex(&ciphertext[..64]),
                   allcrypt::to_hex(&case.bytes("cPrefix")),
                   "{} tcId {}: the first 64 bytes of the ciphertext differ, \
                    so the fault is in u - the transpose of A, y and e1, or \
                    du", set.name, case.tc_id);
        assert_eq!(sha256_hex(&ciphertext),
                   allcrypt::to_hex(&case.bytes("cDigest")),
                   "{} tcId {}: the ciphertext differs after its first 64 \
                    bytes", set.name, case.tc_id);
        assert_eq!(allcrypt::to_hex(&shared),
                   allcrypt::to_hex(&case.bytes("k")),
                   "{} tcId {}: shared secret", set.name, case.tc_id);
        done += 1;
    }
    assert_eq!(done, 30);
}

/// All 30 decapsulation cases, and **which path each one took**.
///
/// The answer is checked first; then the case is classified by whether
/// NIST's answer is `J(z ‖ c)`. Both kinds must be present in every
/// parameter set. If NIST's cases were all honest ciphertexts, an
/// implementation whose comparison always said "equal" would pass every
/// one of them while having no implicit rejection at all - the property
/// FIPS 203 depends on most.
#[test]
fn test_every_decapsulation_vector() {
    let mut paths: std::collections::BTreeMap<(&str, bool), usize> =
        std::collections::BTreeMap::new();
    for case in cases_of("decapsulation") {
        let set = allcrypt::pq::ml_kem::parameters(case.parameter_set).unwrap();
        let dk = case.bytes("dk");
        let ciphertext = case.bytes("c");
        let shared = allcrypt::pq::ml_kem::decapsulate_internal(
            set, &dk, &ciphertext)
            .unwrap_or_else(|error| panic!("{} tcId {}: {error}",
                                           set.name, case.tc_id));
        let expected = case.bytes("k");
        assert_eq!(allcrypt::to_hex(&shared), allcrypt::to_hex(&expected),
                   "{} tcId {}: shared secret", set.name, case.tc_id);

        let rejected = expected == rejection_secret(&dk, &ciphertext);
        *paths.entry((case.parameter_set, rejected)).or_insert(0) += 1;
    }
    for set in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        let accepted = paths.get(&(set, false)).copied().unwrap_or(0);
        let rejected = paths.get(&(set, true)).copied().unwrap_or(0);
        assert_eq!(accepted + rejected, 10, "{set}");
        assert!(accepted > 0 && rejected > 0,
                "{set}: NIST's decapsulation cases took one path only \
                 ({accepted} accepted, {rejected} implicitly rejected), so \
                 the other is not being tested by them");
    }
}

/// NIST's 60 key checks, half of them keys that must be refused.
///
/// Each verdict is checked twice: against the check function itself, and
/// against what encapsulation or decapsulation does with the key. The
/// second is the one that matters - a correct check that the operation
/// forgot to call would pass the first and fail the second.
#[test]
fn test_the_key_check_vectors() {
    let mut refused = 0;
    for case in cases_of("encapsulationKeyCheck") {
        let set = allcrypt::pq::ml_kem::parameters(case.parameter_set).unwrap();
        let ek = case.bytes("ek");
        let valid = case.verdict("testPassed");
        assert_eq!(allcrypt::pq::ml_kem::modulus_check(set, &ek).unwrap(),
                   valid, "{} tcId {}: modulus check", set.name, case.tc_id);
        let used = allcrypt::pq::ml_kem::encapsulate_internal(set, &ek,
                                                              &[7u8; 32]);
        assert_eq!(used.is_ok(), valid,
                   "{} tcId {}: encapsulation should {} this key", set.name,
                   case.tc_id, if valid { "accept" } else { "refuse" });
        refused += usize::from(!valid);
    }
    assert_eq!(refused, 15);

    let mut refused = 0;
    for case in cases_of("decapsulationKeyCheck") {
        let set = allcrypt::pq::ml_kem::parameters(case.parameter_set).unwrap();
        let dk = case.bytes("dk");
        let valid = case.verdict("testPassed");
        assert_eq!(allcrypt::pq::ml_kem::hash_check(set, &dk).unwrap(), valid,
                   "{} tcId {}: hash check", set.name, case.tc_id);
        // Any ciphertext of the right length will do: the key check comes
        // before the ciphertext is looked at, and an all-zero one simply
        // takes the implicit-rejection path when the key is good.
        let ciphertext = vec![0u8; set.ciphertext_len()];
        let used = allcrypt::pq::ml_kem::decapsulate_internal(set, &dk,
                                                              &ciphertext);
        assert_eq!(used.is_ok(), valid,
                   "{} tcId {}: decapsulation should {} this key", set.name,
                   case.tc_id, if valid { "accept" } else { "refuse" });
        refused += usize::from(!valid);
    }
    assert_eq!(refused, 15);
}

/// Encapsulate to a key, decapsulate with it, and get the same secret -
/// then alter the ciphertext and get `J(z ‖ c)` instead, **as `Ok`**.
///
/// The alterations are placed at the start of `u`, the last byte of `u`,
/// and the last byte of `v`, because a comparison that only covered part
/// of the ciphertext would let a change in the rest through, and these
/// are the three places a truncated loop would stop short of.
#[test]
fn test_round_trip_and_implicit_rejection() {
    for case in cases_of("keyGen").into_iter().step_by(25) {
        let set = allcrypt::pq::ml_kem::parameters(case.parameter_set).unwrap();
        let (ek, dk) = allcrypt::pq::ml_kem::key_gen_internal(
            set, &case.bytes("d"), &case.bytes("z")).unwrap();
        let (shared, ciphertext) =
            allcrypt::pq::ml_kem::encapsulate_internal(set, &ek, &[0x5a; 32])
                .unwrap();
        assert_eq!(allcrypt::pq::ml_kem::decapsulate_internal(set, &dk,
                                                              &ciphertext)
                       .unwrap(),
                   shared, "{}: round trip", set.name);

        let u_len = 32 * set.du as usize * set.k;
        for at in [0, u_len - 1, ciphertext.len() - 1] {
            let mut altered = ciphertext.clone();
            altered[at] ^= 0x01;
            let got = allcrypt::pq::ml_kem::decapsulate_internal(set, &dk,
                                                                 &altered)
                .unwrap_or_else(|error| panic!(
                    "{}: an altered ciphertext must not be an error - that \
                     would be a decryption oracle - but was: {error}",
                    set.name));
            assert_ne!(got, shared, "{}: byte {at} altered", set.name);
            assert_eq!(got, rejection_secret(&dk, &altered),
                       "{}: byte {at} altered should give J(z || c)",
                       set.name);
        }
    }
}

/// The input checks that are errors, with messages that say which input.
#[test]
fn test_malformed_inputs_are_errors() {
    let set = allcrypt::pq::ml_kem::parameters("ML-KEM-768").unwrap();
    let case = &cases_of("keyGen")[25];
    assert_eq!(case.parameter_set, "ML-KEM-768");
    let (ek, dk) = allcrypt::pq::ml_kem::key_gen_internal(
        set, &case.bytes("d"), &case.bytes("z")).unwrap();

    let error = allcrypt::pq::ml_kem::encapsulate_internal(set, &ek, &[0; 31])
        .unwrap_err();
    assert!(error.contains("m is 31 bytes"), "{error}");

    let error = allcrypt::pq::ml_kem::encapsulate_internal(
        set, &ek[..ek.len() - 1], &[0; 32]).unwrap_err();
    assert!(error.contains("input check"), "{error}");

    let error = allcrypt::pq::ml_kem::decapsulate_internal(set, &dk, &[0; 1087])
        .unwrap_err();
    assert!(error.contains("1087 bytes and should be 1088"), "{error}");

    let error = allcrypt::pq::ml_kem::decapsulate_internal(
        set, &dk[..dk.len() - 1], &[0; 1088]).unwrap_err();
    assert!(error.contains("input check"), "{error}");
}

/// `api::MlKemKey` and `api::MlKemPublicKey`: the layer that draws the
/// randomness, checked against the same vectors as the layer under it.
///
/// `from_seed(d ‖ z)` must give NIST's key - which is what ties the
/// facade to the vectors rather than only to itself - and both import
/// functions must refuse exactly the keys NIST's key-check cases say to
/// refuse.
#[test]
fn test_the_api_layer() {
    use allcrypt::api::{MlKemKey, MlKemPublicKey};

    assert_eq!(allcrypt::api::ml_kem_parameter_sets(),
               ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]);

    for case in cases_of("keyGen").into_iter().step_by(25) {
        let mut seed = case.bytes("d");
        seed.extend_from_slice(&case.bytes("z"));
        let key = MlKemKey::from_seed(case.parameter_set, &seed).unwrap();
        assert_eq!(key.parameter_set(), case.parameter_set);
        assert_eq!(sha256_hex(key.private_bytes()),
                   allcrypt::to_hex(&case.bytes("dkDigest")),
                   "{}: from_seed", case.parameter_set);
        assert_eq!(sha256_hex(key.public_bytes()),
                   allcrypt::to_hex(&case.bytes("ekDigest")),
                   "{}: the ek inside dk", case.parameter_set);

        // Fresh randomness each time: two encapsulations to one key give
        // two different secrets, and the key recovers both.
        let public = key.public_key();
        let (first, first_ciphertext) = public.encapsulate().unwrap();
        let (second, second_ciphertext) = public.encapsulate().unwrap();
        assert_ne!(first, second);
        assert_ne!(first_ciphertext, second_ciphertext);
        assert_eq!(key.decapsulate(&first_ciphertext).unwrap(), first);
        assert_eq!(key.decapsulate(&second_ciphertext).unwrap(), second);

        // Round trip through the byte forms.
        let again = MlKemKey::from_private(case.parameter_set,
                                           key.private_bytes()).unwrap();
        assert_eq!(again.decapsulate(&first_ciphertext).unwrap(), first);
        let public_again = MlKemPublicKey::from_public(
            case.parameter_set, public.public_bytes()).unwrap();
        assert_eq!(public_again.public_bytes(), key.public_bytes());

        // Another key's ciphertext decapsulates, to something else.
        let stranger = MlKemKey::generate(case.parameter_set).unwrap();
        let (theirs, ciphertext) = stranger.public_key().encapsulate().unwrap();
        assert_ne!(key.decapsulate(&ciphertext).unwrap(), theirs);
    }

    for case in cases_of("encapsulationKeyCheck") {
        let valid = case.verdict("testPassed");
        assert_eq!(MlKemPublicKey::from_public(case.parameter_set,
                                               &case.bytes("ek")).is_ok(),
                   valid, "{} tcId {}", case.parameter_set, case.tc_id);
    }
    for case in cases_of("decapsulationKeyCheck") {
        let valid = case.verdict("testPassed");
        assert_eq!(MlKemKey::from_private(case.parameter_set,
                                          &case.bytes("dk")).is_ok(),
                   valid, "{} tcId {}", case.parameter_set, case.tc_id);
    }

    // `.err().expect(..)` rather than `unwrap_err`, which needs `Debug` -
    // and a key type deliberately has none, so it cannot print itself.
    assert!(MlKemKey::from_seed("ML-KEM-768", &[0; 63]).err()
                .expect("a 63 byte seed is refused")
                .contains("64 bytes, and this is 63"));
    // Too long as well as too short. A check written as `< 64` would let
    // this through to key generation, which refuses it only because `z`
    // comes out 33 bytes - the right answer for the wrong reason, and a
    // message that names the wrong input.
    assert!(MlKemKey::from_seed("ML-KEM-768", &[0; 65]).err()
                .expect("a 65 byte seed is refused")
                .contains("64 bytes, and this is 65"));
    assert!(MlKemKey::generate("ML-KEM-123").is_err());
    let error = MlKemPublicKey::from_public("ML-KEM-512", &[0; 799]).err()
        .expect("a 799 byte key is refused");
    assert!(error.contains("799 bytes and should be 800"), "{error}");
}
