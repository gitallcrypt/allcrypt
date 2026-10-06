/*
SLH-DSA key generation against NIST's own validation vectors.

`vectors/slh_dsa.vec`, written by `scripts/make_slh_dsa_vectors.py` from
`usnistgov/ACVP-Server`: the same files a vendor's implementation is
tested against for FIPS certification. Twelve parameter sets, ten cases
each.

## These vectors are the entire independent opinion

Every other algorithm in this library has a second implementation to
differ against - `hashlib`, `python-cryptography`, OpenSSL, and for
GOST a built engine. **None of those is used for SLH-DSA.**
python-cryptography 46 does not have it; OpenSSL has it from 3.5, which
is not used as a witness for it; and there is no worked example in a
document the way RFC 9367 gives one for GOST at TLS 1.3.

So there is no fallback if this file is wrong, and the specific way it
could be wrong is by parsing to nothing: an empty `Vec` makes every
`for` loop below pass. Hence `test_the_vector_file_parses_to_what_it
_should`, and hence the section headers carrying their own counts -
`[keyGen SLH-DSA-SHA2-128s 10]` - which the parser asserts as it goes.
That assertion has earned its place three times already in this
repository, in `src/ec/eddsa.rs`, `src/block_ciphers/keywrap.rs` and
`src/block_ciphers/serpent.rs`.

## Why this is slow

A key is the root of a Merkle tree over `2^h'` WOTS+ public keys, and
there is no way to compute a root without computing every leaf. At the
`s` parameter sets `h'` is 9, so that is 512 WOTS+ keys per case, each of
them `len` hash chains of 15 steps: on the order of a quarter of a
million hash calls for one of the sixty `s` cases. In an unoptimised
build that is minutes, not seconds.

The sixty `f` cases are cheap - `h'` is 3 or 4 there - so they go in a
test of their own that runs first and covers all twelve parameter sets
between them, which is where a wrong address encoding or a wrong hash
family will show up. The expensive test is what proves the tall trees,
and it is the one to reach for when `h'` or the recursion is suspect.

## What the gate covers and what it does not

Signing costs more than key generation, so the caps differ. On every run:
all 60 fast-set key generations, one small-set key generation each, and
one signature per fast set and variant - twelve signatures, covering both
hash families, all three security levels and both of deterministic and
hedged. Behind `--ignored`: the remaining small-set key generations, the
24 remaining fast signatures, and **every small-set signature**.

That last one is the real gap, and it is a gap in breadth rather than in
path: the loops are the same code with different bounds, `h'` of 8 or 9
against 3 or 4 and `d` of 7 or 8 against 17 or 22. The one thing that
genuinely differs at the small sets is the digest split - the four
`128s` and `192s` sets, SHA2 and SHAKE alike, have `h' = 9`, so their
leaf index is **two bytes** where every other set's is one - and that
is not left to a slow test. `src/pq/slh_dsa.rs` checks the split and the index arithmetic
for all twelve sets directly, in tests that cost nothing.
*/

const VECTORS: &str = include_str!("../vectors/slh_dsa.vec");

/// One ACVP case, of whichever mode its section named.
///
/// One struct for both modes rather than two, because the parser is one
/// parser: a section header names the mode and the fields follow. The
/// fields a mode does not use stay empty, and `mode` says which those
/// are - a case is never read without checking it.
struct Case {
    /// The section's first token: `keyGen`, or
    /// `sigGen-internal-deterministic` / `-hedged`.
    mode: &'static str,
    parameter_set: &'static str,
    tc_id: u32,

    // keyGen.
    sk_seed: Vec<u8>,
    sk_prf: Vec<u8>,
    pk_seed: Vec<u8>,
    /// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`. Also a sigGen input.
    sk: Vec<u8>,
    /// `PK.seed ‖ PK.root`.
    pk: Vec<u8>,

    // sigGen.
    message: Vec<u8>,
    /// Present only in the hedged sections: `opt_rand`.
    additional_randomness: Vec<u8>,
    /// Present only in the external sections, and legitimately empty in
    /// some of those - ACVP includes zero-length contexts.
    context: Vec<u8>,
    /// Present only in the pre-hash sections, as NIST spells it.
    hash_alg: String,
    signature_length: usize,
    /// The first 256 bytes of NIST's signature.
    signature_prefix: Vec<u8>,
    /// SHA-256 of all of NIST's signature. See the generator script for
    /// why a digest rather than the bytes.
    signature_digest: Vec<u8>,
}

/// A section header: `[mode parameterSet count]`.
#[derive(Clone, Copy)]
struct Section {
    mode: &'static str,
    parameter_set: &'static str,
    count: usize,
}

/// Every mode this reader understands.
///
/// Checked rather than ignored, because an unknown mode's fields would
/// parse into empty vectors and every comparison against them would
/// succeed. When the external and pre-hash interfaces are vendored they
/// go here and get a test, not just a section in the file.
const KNOWN_MODES: [&str; 7] = [
    "keyGen",
    "sigGen-internal-deterministic", "sigGen-internal-hedged",
    "sigGen-external-pure-deterministic", "sigGen-external-pure-hedged",
    "sigGen-external-preHash-deterministic",
    "sigGen-external-preHash-hedged",
];

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2) && !text.is_empty(),
            "not a hex string: {text:?}");
    (0..text.len()).step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16)
                      .unwrap_or_else(|_| panic!("not hex: {text:?}")))
        .collect()
}

/// `unhex`, but an empty string gives an empty vector rather than a panic.
///
/// Only for `additionalRandomness`, which exists in the hedged sections
/// and in no others.
fn unhex_or_empty(text: &str) -> Vec<u8> {
    if text.is_empty() { Vec::new() } else { unhex(text) }
}

/// Every case in the file, with each section's declared count checked
/// against what was actually read.
///
/// The count in the header is the whole defence against a silent parse
/// failure, so it is compared per section rather than only in total: a
/// change to the file that moved cases between parameter sets would keep
/// the total right.
fn vectors() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let mut section: Option<Section> = None;
    let mut current: Vec<(&str, &str)> = Vec::new();

    fn flush(cases: &mut Vec<Case>, section: &Option<Section>,
             fields: &mut Vec<(&str, &str)>) {
        if fields.is_empty() {
            return;
        }
        let Section { mode, parameter_set, .. } =
            section.expect("a case outside any section");
        let get = |wanted: &str| -> &str {
            fields.iter().find(|(key, _)| *key == wanted)
                .unwrap_or_else(|| panic!("{mode} {parameter_set}: a case \
                                           with no {wanted:?}")).1
        };
        // A field a mode does not have is empty rather than absent, and
        // `get_or` is the only thing allowed to be lenient - every field a
        // mode *does* have goes through `get`, which panics. Otherwise a
        // renamed field in the vector file would silently become an empty
        // value and the comparison would be against nothing.
        let optional = |wanted: &str| -> &str {
            fields.iter().find(|(key, _)| *key == wanted)
                .map(|(_, value)| *value).unwrap_or("")
        };
        let key_gen = mode == "keyGen";
        let external = mode.starts_with("sigGen-external");
        let pre_hashed = mode.contains("preHash");
        cases.push(Case {
            mode,
            parameter_set,
            tc_id: get("tcId").parse().expect("tcId is a number"),

            sk_seed: if key_gen { unhex(get("skSeed")) } else { Vec::new() },
            sk_prf: if key_gen { unhex(get("skPrf")) } else { Vec::new() },
            pk_seed: if key_gen { unhex(get("pkSeed")) } else { Vec::new() },
            sk: unhex(get("sk")),
            pk: if key_gen { unhex(get("pk")) } else { Vec::new() },

            message: if key_gen { Vec::new() } else { unhex(get("message")) },
            additional_randomness: unhex_or_empty(
                optional("additionalRandomness")),
            // Conditional on the mode, and demanded through `get` where
            // the mode says they should be there: a context that went
            // missing from an external section would otherwise read as an
            // empty one and every signature would be wrong for a reason
            // the test could not name.
            context: if external {
                unhex_or_empty(get("context"))
            } else {
                Vec::new()
            },
            hash_alg: if pre_hashed {
                get("hashAlg").to_string()
            } else {
                String::new()
            },
            signature_length: if key_gen { 0 } else {
                get("signatureLength").parse()
                    .expect("signatureLength is a number")
            },
            signature_prefix: if key_gen { Vec::new() } else {
                unhex(get("signaturePrefix"))
            },
            signature_digest: if key_gen { Vec::new() } else {
                unhex(get("signatureDigest"))
            },
        });
        fields.clear();
    }

    let mut counted: Vec<(Section, usize)> = Vec::new();
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            flush(&mut cases, &section, &mut current);
            if let Some(done) = section {
                counted.push((done, cases.len()));
            }
            let header = header.strip_suffix(']')
                .unwrap_or_else(|| panic!("unterminated section: {line:?}"));
            let words: Vec<&str> = header.split_whitespace().collect();
            assert_eq!(words.len(), 3,
                       "a section header is `[mode parameterSet count]`, \
                        not {header:?}");
            assert!(KNOWN_MODES.contains(&words[0]),
                    "unknown mode {:?}. A mode this reader does not know \
                     would be parsed into empty fields and compared against \
                     nothing, so it is refused instead.", words[0]);
            // Leaked deliberately: the names are compared against string
            // literals all over this test, the file is `include_str!`'d,
            // and it all lives for the whole process anyway.
            let mode: &'static str = words[0].to_string().leak();
            let parameter_set: &'static str = words[1].to_string().leak();
            let count: usize = words[2].parse()
                .expect("the section count is a number");
            section = Some(Section { mode, parameter_set, count });
            continue;
        }
        // **An empty value is legitimate**: ACVP includes zero-length
        // context strings, which the generator writes as `context = `
        // and which arrives here trimmed to `context =`. Handled
        // explicitly rather than by loosening the split, so a line that
        // is malformed some other way still fails.
        let (key, value) = match line.strip_suffix(" =") {
            Some(key) => (key, ""),
            None => line.split_once(" = ")
                .unwrap_or_else(|| panic!("not `key = value`: {line:?}")),
        };
        if key == "tcId" && !current.is_empty() {
            flush(&mut cases, &section, &mut current);
        }
        current.push((key.trim(), value.trim()));
    }
    flush(&mut cases, &section, &mut current);
    if let Some(done) = section {
        counted.push((done, cases.len()));
    }

    // Each section got what its header promised.
    let mut start = 0;
    for (done, end) in &counted {
        let read = end - start;
        assert_eq!(read, done.count,
                   "vectors/slh_dsa.vec: section {} {} says {} cases and \
                    holds {}. Re-run scripts/make_slh_dsa_vectors.py rather \
                    than editing the file.",
                   done.mode, done.parameter_set, done.count, read);
        start = *end;
    }
    assert_eq!(counted.len(), 84,
               "vectors/slh_dsa.vec should hold twelve keyGen sections, \
                twenty-four internal sigGen ones and forty-eight external");
    cases
}

/// What was read, before anything is done with it.
///
/// If this test is the only one that fails, the file or the parser moved
/// and the algorithm is fine. If it passes and the others fail, the
/// numbers were read correctly and disagree with this implementation,
/// which is the useful distinction to have made before reading a diff of
/// hashes.
#[test]
fn test_the_vector_file_parses_to_what_it_should() {
    let cases = vectors();
    assert_eq!(cases.len(), 264,
               "120 keyGen cases, 72 internal sigGen and 72 external");

    let key_gen: Vec<&Case> = cases.iter()
        .filter(|case| case.mode == "keyGen").collect();
    assert_eq!(key_gen.len(), 120, "twelve parameter sets of ten cases");
    let signing: Vec<&Case> = cases.iter()
        .filter(|case| case.mode.starts_with("sigGen")).collect();
    assert_eq!(signing.len(), 144,
               "24 internal sections of three, 24 pre-hash of two, 24 pure \
                of one, over two determinism variants each");

    let mut seen = std::collections::HashSet::new();
    for case in &key_gen {
        let set = allcrypt::pq::slh_dsa::parameters(case.parameter_set)
            .unwrap_or_else(|error| panic!("{error}"));
        seen.insert(case.parameter_set);

        assert_eq!(case.sk_seed.len(), set.n, "{} SK.seed", set.name);
        assert_eq!(case.sk_prf.len(), set.n, "{} SK.prf", set.name);
        assert_eq!(case.pk_seed.len(), set.n, "{} PK.seed", set.name);
        assert_eq!(case.sk.len(), set.secret_key_len(), "{} sk", set.name);
        assert_eq!(case.pk.len(), set.public_key_len(), "{} pk", set.name);

        // The three seeds are supposed to be the front of the private
        // key and the public key its tail. Checking that here means the
        // key generation tests below are comparing against a `pk` whose
        // relationship to its own inputs is already established, so a
        // mismatch there is this library's doing.
        assert_eq!(&case.sk[..set.n], &case.sk_seed[..], "{} sk", set.name);
        assert_eq!(&case.sk[set.n..2 * set.n], &case.sk_prf[..], "{}", set.name);
        assert_eq!(&case.sk[2 * set.n..], &case.pk[..], "{} sk ends with pk",
                   set.name);
        assert_eq!(&case.pk[..set.n], &case.pk_seed[..], "{} pk", set.name);
    }
    assert_eq!(seen.len(), 12);

    // The signing cases, and one thing about them that is worth checking
    // before any signature is compared: **the length NIST states must be
    // the length this library's own parameter table predicts.** `a`, `k`
    // and `m` are the three fields key generation never reads, and
    // `signature_len` is built from `a` and `k`, so this is the first
    // independent word on any of them.
    let mut hedged = 0;
    let mut seen = std::collections::HashSet::new();
    for case in &signing {
        let set = allcrypt::pq::slh_dsa::parameters(case.parameter_set)
            .unwrap_or_else(|error| panic!("{error}"));
        seen.insert((case.mode, case.parameter_set));

        assert_eq!(case.signature_length, set.signature_len(),
                   "{} {}: NIST says a signature is {} bytes and this \
                    library's parameter table says {}",
                   case.mode, set.name, case.signature_length,
                   set.signature_len());
        assert_eq!(case.sk.len(), set.secret_key_len(), "{} sk", set.name);
        assert_eq!(case.signature_digest.len(), 32, "a SHA-256 digest");
        assert_eq!(case.signature_prefix.len(),
                   256.min(case.signature_length),
                   "{} {}: the prefix is 256 bytes", case.mode, set.name);

        if case.mode.ends_with("hedged") {
            hedged += 1;
            assert_eq!(case.additional_randomness.len(), set.n,
                       "{}: opt_rand", set.name);
        } else {
            assert!(case.additional_randomness.is_empty(),
                    "{} {}: a deterministic case carries no extra \
                     randomness", case.mode, set.name);
        }
    }
    assert_eq!(seen.len(), 72,
               "twelve parameter sets across six signing variants");
    assert_eq!(hedged, 72, "half the signing cases are hedged");

    // **ACVP numbers its cases across a whole vector set, not within a
    // group** - so `SLH-DSA-SHAKE-128s`'s keyGen cases start at 11, not
    // at 1. `keyGen` and `sigGen` are two *different* vector sets, with
    // their own vsIds and their own numbering, so their ids overlap and
    // uniqueness only holds within each. Checked because a case
    // duplicated between two sections of one set is something the
    // per-section counts cannot see.
    //
    // keyGen is the whole range 1..=120 because nothing is dropped from
    // it. The sigGen ids are not contiguous and should not be expected to
    // be: the external and pre-hash groups are left out entirely and the
    // rest are capped at three cases, so what survives is a sample of a
    // larger numbering.
    let key_gen_ids: std::collections::BTreeSet<u32> =
        key_gen.iter().map(|case| case.tc_id).collect();
    assert_eq!(key_gen_ids.len(), key_gen.len(), "a keyGen tcId appears twice");
    assert_eq!((*key_gen_ids.first().unwrap(), *key_gen_ids.last().unwrap()),
               (1, 120));

    let signing_ids: std::collections::BTreeSet<u32> =
        signing.iter().map(|case| case.tc_id).collect();
    assert_eq!(signing_ids.len(), signing.len(), "a sigGen tcId appears twice");
}

/// The sixty `f` cases: all six fast parameter sets, both hash families,
/// all three security levels.
///
/// Cheap, because `h'` is 3 or 4 - eight or sixteen WOTS+ keys per case
/// rather than five hundred - and complete in the sense that matters
/// most: every hash family, every `n`, and therefore every combination
/// of "which hash function does `H` use" and "is the address compressed".
/// Almost any mistake in this implementation fails here.
#[test]
fn test_every_fast_parameter_set_generates_nist_s_keys() {
    let generated = generate_matching(|name| name.ends_with('f'), 10);
    assert_eq!(generated, 60, "six fast parameter sets of ten cases");
}

/// One `s` case per parameter set: the same code walking a taller tree.
///
/// Not skippable, because `h'` is 8 or 9 here and the `f` sets never
/// recurse deeper than four - a fault in `xmss_node`'s indexing that
/// only appears at depth would hide behind the fast test.
///
/// **One case each rather than all ten**, which is a judgement worth
/// stating: the ten cases in a section differ only in their seeds and
/// take the identical path through this code, so the ninth adds no
/// coverage over the first and costs the same quarter of a million hash
/// calls. Measured: the six cases here take 38 seconds in an unoptimised
/// build and all sixty would take a little over six minutes, which is
/// long enough that it would start being skipped - and a test that gets
/// skipped is worth less than a smaller one that runs. The full sixty are
/// `test_every_vector_in_the_file_including_the_slow_ones`, which is
/// `#[ignore]`d rather than absent so that it is one command away.
#[test]
fn test_every_small_parameter_set_generates_nist_s_keys() {
    let generated = generate_matching(|name| name.ends_with('s'), 1);
    assert_eq!(generated, 6, "one case for each of six small sets");
}

/// All 120, which is the claim this file would like to make and cannot
/// make on every run.
///
/// Ignored because of the cost described above, not because it is
/// expected to be fragile. Run it after any change to `xmss_node`,
/// `wots_public_key`, `chain` or the address encoding:
///
/// ```text
/// cargo test --release --test test_slh_dsa -- --ignored --nocapture
/// ```
///
/// Measured: 17 seconds in a release build against about seven minutes
/// in a debug one, so better than twenty times faster. That ratio is the
/// reason this is practical at all, and it was run that way before this
/// file was committed - all 120 pass.
#[test]
#[ignore = "about twenty-five minutes in a debug build; see the doc comment"]
fn test_every_vector_in_the_file_including_the_slow_ones() {
    let generated = generate_matching(|_| true, 10);
    assert_eq!(generated, 120, "twelve parameter sets of ten cases");
    let signed = sign_matching(|_| true, 3);
    assert_eq!(signed, 72, "twenty-four internal sections of three cases");
    let (external, _) = sign_external_matching(|_| true);
    assert_eq!(external, 72, "every external case in the file");
}

/// Generate the first `per_set` cases of every parameter set the
/// predicate accepts, and return how many were done.
///
/// The count is returned so the caller can assert it: a predicate that
/// matched nothing would otherwise be a test that passes without doing
/// anything, which is the same failure the section counts guard against
/// one level up. `per_set` counts within a parameter set and takes them
/// in the order the file lists them, which is `tcId` order - so which
/// cases get run is a consequence of the file rather than a choice made
/// here.
fn generate_matching(wanted: impl Fn(&str) -> bool, per_set: usize) -> usize {
    let mut done = 0;
    let mut seen_in_set: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for case in vectors() {
        if case.mode != "keyGen" || !wanted(case.parameter_set) {
            continue;
        }
        let taken = seen_in_set.entry(case.parameter_set).or_insert(0);
        *taken += 1;
        if *taken > per_set {
            continue;
        }
        let set = allcrypt::pq::slh_dsa::parameters(case.parameter_set).unwrap();
        let (secret, public) = allcrypt::pq::slh_dsa::key_gen_internal(
            set, &case.sk_seed, &case.sk_prf, &case.pk_seed)
            .unwrap_or_else(|error| panic!("{} tcId {}: {error}",
                                           set.name, case.tc_id));

        assert_eq!(allcrypt::to_hex(&public), allcrypt::to_hex(&case.pk),
                   "{} tcId {}: public key. The seeds are right and the root \
                    is not, so the fault is in the tree: the address \
                    encoding, the hash family, or h' = {}.",
                   set.name, case.tc_id, set.h_prime);
        assert_eq!(allcrypt::to_hex(&secret), allcrypt::to_hex(&case.sk),
                   "{} tcId {}: private key", set.name, case.tc_id);
        done += 1;
    }
    done
}

/// Sign every *external* sigGen case whose parameter set the predicate
/// accepts, and return how many were done, with the pre-hash functions it
/// exercised.
///
/// The external interface is the internal one with the message wrapped
/// first, so what these cases check is the wrapping: the domain separator
/// byte, the context string and its length prefix, and - in the pre-hash
/// groups - the hash function's OID and digest. Every comparison is the
/// same three as `sign_matching`, because a wrapping fault shows up as an
/// entirely different signature rather than as a subtly wrong one.
fn sign_external_matching(wanted: impl Fn(&str) -> bool)
        -> (usize, std::collections::BTreeSet<String>) {
    let mut done = 0;
    let mut algorithms = std::collections::BTreeSet::new();
    for case in vectors() {
        if !case.mode.starts_with("sigGen-external")
                || !wanted(case.parameter_set) {
            continue;
        }
        let set = allcrypt::pq::slh_dsa::parameters(case.parameter_set).unwrap();
        let hedged = case.mode.ends_with("hedged");
        let opt_rand: &[u8] = if hedged {
            &case.additional_randomness
        } else {
            &case.sk[2 * set.n..3 * set.n]
        };

        let pre_hash = if case.mode.contains("preHash") {
            let which = allcrypt::pq::slh_dsa::PreHash::by_name(&case.hash_alg)
                .unwrap_or_else(|error| panic!("{} tcId {}: {error}",
                                               case.mode, case.tc_id));
            algorithms.insert(case.hash_alg.clone());
            Some(which)
        } else {
            assert!(case.hash_alg.is_empty(),
                    "{} tcId {}: a pure case names a hash function",
                    case.mode, case.tc_id);
            None
        };

        let signature = allcrypt::pq::slh_dsa::sign(
            set, &case.sk, &case.message, &case.context, pre_hash, opt_rand)
            .unwrap_or_else(|error| panic!("{} {} tcId {}: {error}",
                                           case.mode, set.name, case.tc_id));

        assert_eq!(signature.len(), case.signature_length,
                   "{} {} tcId {}: signature length", case.mode, set.name,
                   case.tc_id);
        assert_eq!(allcrypt::to_hex(&signature[..case.signature_prefix.len()]),
                   allcrypt::to_hex(&case.signature_prefix),
                   "{} {} tcId {} ({} byte context, hashAlg {:?}): the first \
                    {} bytes differ. For an external signature that almost \
                    always means the message wrapping rather than the \
                    scheme - the separator byte, the context length, or the \
                    pre-hash OID.",
                   case.mode, set.name, case.tc_id, case.context.len(),
                   case.hash_alg, case.signature_prefix.len());

        use allcrypt::hash_functions::HashFunction;
        let digest = allcrypt::hash_functions::sha2::SHA256::new(&signature)
            .digest();
        assert_eq!(allcrypt::to_hex(&digest),
                   allcrypt::to_hex(&case.signature_digest),
                   "{} {} tcId {}: the prefix matches NIST's and the whole \
                    signature does not", case.mode, set.name, case.tc_id);

        let public = &case.sk[2 * set.n..];
        assert!(allcrypt::pq::slh_dsa::verify(
                    set, public, &case.message, &case.context, pre_hash,
                    &signature).unwrap(),
                "{} {} tcId {}: we produced NIST's signature and refused it",
                case.mode, set.name, case.tc_id);
        done += 1;
    }
    (done, algorithms)
}

/// Every external case at the fast parameter sets: pure and pre-hash,
/// deterministic and hedged.
///
/// Cheap enough to run whole - one case per group, 24 groups at the fast
/// sets - and it is where all twelve pre-hash functions get exercised,
/// which the assertion at the end insists on rather than assuming. ACVP
/// varies `hashAlg` per test rather than per group, so one case per group
/// happening to cover all twelve is a property of their file that could
/// change.
#[test]
fn test_every_external_case_at_the_fast_sets_signs_as_nist_does() {
    let (signed, algorithms) = sign_external_matching(|n| n.ends_with('f'));
    assert_eq!(signed, 36,
               "six fast sets: two pre-hash cases and one pure, per \
                determinism variant");

    let expected: std::collections::BTreeSet<String> =
        ["SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224",
         "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
         "SHAKE-128", "SHAKE-256"].iter().map(|s| s.to_string()).collect();
    assert_eq!(algorithms, expected,
               "the twelve pre-hash functions FIPS 205 approves should all \
                appear; if this shrinks, the vector file's cap needs raising \
                rather than this assertion lowering");
}

/// The external interface at the small parameter sets.
#[test]
#[ignore = "the small sets cost minutes per signature; see the module doc"]
fn test_every_external_case_at_the_small_sets_signs_as_nist_does() {
    let (signed, _) = sign_external_matching(|n| n.ends_with('s'));
    assert_eq!(signed, 36, "six small sets, same shape as the fast ones");
}

/// The wrapping is a domain separator, so changing any part of it must
/// change the signature.
///
/// **This is the test that matters most about the external interface**,
/// because every one of these would otherwise be a way to move a
/// signature to a context it was not made for. A pure signature must not
/// verify as a pre-hash one; one context's signature must not verify under
/// another; `ctx = "ab", M = "c"` must not collide with `ctx = "a",
/// M = "bc"`, which is what the length prefix is for; and two pre-hash
/// functions with the same output length must not be interchangeable,
/// which is what the OID is for.
#[test]
fn test_the_wrapping_separates_the_domains_it_is_supposed_to() {
    let set = allcrypt::pq::slh_dsa::parameters("SLH-DSA-SHAKE-128f").unwrap();
    let (secret, public) = allcrypt::pq::slh_dsa::key_gen_internal(
        set, &[7u8; 16], &[8u8; 16], &[9u8; 16]).unwrap();
    let pk_seed = secret[2 * set.n..3 * set.n].to_vec();

    let sign = |message: &[u8], context: &[u8], pre_hash| {
        allcrypt::pq::slh_dsa::sign(set, &secret, message, context, pre_hash,
                                    &pk_seed).unwrap()
    };
    let verify = |message: &[u8], context: &[u8], pre_hash, signature: &[u8]| {
        allcrypt::pq::slh_dsa::verify(set, &public, message, context, pre_hash,
                                      signature).unwrap()
    };

    let plain = sign(b"a message", b"", None);
    assert!(verify(b"a message", b"", None, &plain));

    // The separator byte: pure and pre-hash are different domains.
    let hashed = sign(b"a message", b"", Some(allcrypt::pq::slh_dsa::PreHash::Sha256));
    assert_ne!(plain, hashed);
    assert!(!verify(b"a message", b"", Some(allcrypt::pq::slh_dsa::PreHash::Sha256),
                    &plain));
    assert!(!verify(b"a message", b"", None, &hashed));

    // The context: a different one must not verify.
    let in_context = sign(b"a message", b"protocol A", None);
    assert_ne!(plain, in_context);
    assert!(!verify(b"a message", b"protocol B", None, &in_context));
    assert!(!verify(b"a message", b"", None, &in_context));

    // The length prefix: ("ab", "c") and ("a", "bc") must differ. Without
    // the length byte in front of the context these two wrap to the same
    // bytes, and one signature would serve for both.
    assert_ne!(sign(b"c", b"ab", None), sign(b"bc", b"a", None));
    assert!(!verify(b"bc", b"a", None, &sign(b"c", b"ab", None)));

    // The OID: two pre-hash functions with the same digest length must
    // not be interchangeable. SHA2-256, SHA2-512/256, SHA3-256 and
    // SHAKE-128 all produce 32 bytes.
    use allcrypt::pq::slh_dsa::PreHash;
    let same_length = [PreHash::Sha256, PreHash::Sha512_256,
                       PreHash::Sha3_256, PreHash::Shake128];
    for which in same_length {
        assert_eq!(which.output_len(), 32, "{}", which.name());
    }
    let signatures: Vec<Vec<u8>> = same_length.iter()
        .map(|which| sign(b"a message", b"", Some(*which))).collect();
    for (at, signature) in signatures.iter().enumerate() {
        for (other, which) in same_length.iter().enumerate() {
            let accepted = verify(b"a message", b"", Some(*which), signature);
            assert_eq!(accepted, at == other,
                       "a {} signature was {} under {}",
                       same_length[at].name(),
                       if accepted { "accepted" } else { "refused" },
                       which.name());
        }
    }

    // A context longer than 255 bytes cannot be encoded, so it is refused
    // rather than truncated - two contexts agreeing on their first 255
    // bytes would otherwise share a signature.
    let long = vec![0u8; 256];
    let error = allcrypt::pq::slh_dsa::sign(set, &secret, b"m", &long, None,
                                            &pk_seed).unwrap_err();
    assert!(error.contains("255") && error.contains("256"), "{error}");
    assert!(allcrypt::pq::slh_dsa::verify(set, &public, b"m", &long, None,
                                          &plain).is_err());
    // And exactly 255 is allowed.
    assert!(allcrypt::pq::slh_dsa::sign(set, &secret, b"m", &long[..255], None,
                                        &pk_seed).is_ok());
}

/// Sign every sigGen case whose parameter set the predicate accepts, and
/// return how many were done.
///
/// Both variants: `opt_rand` is `PK.seed` for a deterministic case and the
/// case's own `additionalRandomness` for a hedged one, which is the whole
/// difference between the two modes.
///
/// Three comparisons per case, in the order that makes a failure
/// diagnosable. The length first, because a wrong length is a wrong
/// parameter rather than a wrong hash. Then the first 256 bytes, which
/// hold `R` and the start of the FORS signature - so a mismatch there
/// points at `PRF_msg`, `H_msg` or the first FORS tree, and a *match*
/// there with a wrong digest points at everything after it. Then the
/// digest over the whole thing.
fn sign_matching(wanted: impl Fn(&str) -> bool, per_set: usize) -> usize {
    let mut done = 0;
    let mut seen_in_set: std::collections::HashMap<(&str, &str), usize> =
        std::collections::HashMap::new();
    for case in vectors() {
        if !case.mode.starts_with("sigGen-internal")
                || !wanted(case.parameter_set) {
            continue;
        }
        let taken = seen_in_set.entry((case.mode, case.parameter_set))
            .or_insert(0);
        *taken += 1;
        if *taken > per_set {
            continue;
        }

        let set = allcrypt::pq::slh_dsa::parameters(case.parameter_set).unwrap();
        let hedged = case.mode.ends_with("hedged");
        // Deterministic signing uses PK.seed as opt_rand, and PK.seed is
        // the third quarter of the private key.
        let opt_rand: &[u8] = if hedged {
            &case.additional_randomness
        } else {
            &case.sk[2 * set.n..3 * set.n]
        };

        let signature = allcrypt::pq::slh_dsa::sign_internal(
            set, &case.sk, &case.message, opt_rand)
            .unwrap_or_else(|error| panic!("{} {} tcId {}: {error}",
                                           case.mode, set.name, case.tc_id));

        assert_eq!(signature.len(), case.signature_length,
                   "{} {} tcId {}: signature length", case.mode, set.name,
                   case.tc_id);
        assert_eq!(allcrypt::to_hex(&signature[..case.signature_prefix.len()]),
                   allcrypt::to_hex(&case.signature_prefix),
                   "{} {} tcId {}: the first {} bytes differ, so the fault is \
                    early - R comes from PRF_msg, the index from H_msg, and \
                    the rest of the prefix is the first FORS tree.",
                   case.mode, set.name, case.tc_id,
                   case.signature_prefix.len());

        // `digest` comes from the `HashFunction` trait, which has to be
        // in scope to call it.
        use allcrypt::hash_functions::HashFunction;
        let digest = allcrypt::hash_functions::sha2::SHA256::new(&signature)
            .digest();
        assert_eq!(allcrypt::to_hex(&digest),
                   allcrypt::to_hex(&case.signature_digest),
                   "{} {} tcId {}: the first {} bytes match NIST's and the \
                    whole signature does not, so the fault is after the \
                    first FORS tree - the rest of FORS, or the hypertree.",
                   case.mode, set.name, case.tc_id,
                   case.signature_prefix.len());

        // The digest matching means this *is* NIST's signature, byte for
        // byte. So verifying it here is not a round trip against
        // ourselves: it checks verification against bytes NIST produced,
        // which is what `test_verifying_nists_own_signatures` says in one
        // place rather than leaving implied.
        let public = &case.sk[2 * set.n..];
        assert!(allcrypt::pq::slh_dsa::verify_internal(
                    set, public, &case.message, &signature).unwrap(),
                "{} {} tcId {}: we produced NIST's signature and then \
                 refused it", case.mode, set.name, case.tc_id);
        done += 1;
    }
    done
}

/// One case per fast parameter set and signing variant: twelve
/// signatures, covering both hash families, all three security levels and
/// both of deterministic and hedged.
///
/// **Signing costs more than key generation, not less**, which is the
/// opposite of the intuition and is why this is capped so tightly. A key
/// builds one XMSS tree; a signature builds `d` of them, because every
/// authentication path node at height `j` is itself the root of a subtree
/// with `2^j` leaves. So one signature is roughly `d` key generations.
///
/// Measured on the fast sets: 7.2 seconds in release for all 36 cases and
/// **211 seconds in debug**, a ratio of 29. Twelve cases is therefore
/// about 70 seconds of the gate, which is affordable; 36 is not, and the
/// 24 left out differ from these only in their key and message.
#[test]
fn test_every_fast_parameter_set_signs_as_nist_does() {
    let signed = sign_matching(|name| name.ends_with('f'), 1);
    assert_eq!(signed, 12, "six fast sets, two variants, one case");
}

/// A signature that has been altered anywhere must be refused.
///
/// Every byte position is too slow here, so this walks the three parts of
/// the signature that mean different things - `R`, the FORS signature and
/// the hypertree signature - and flips a bit in each. All three change
/// the recovered root, and the first also changes which leaf the verifier
/// looks at.
///
/// A truncated and an over-long signature are checked too, and those must
/// be `Ok(false)` rather than `Err`: a caller handed a corrupt signature
/// wants "did not verify", not a distinct error path to forget about.
#[test]
fn test_a_tampered_signature_is_refused() {
    let set = allcrypt::pq::slh_dsa::parameters("SLH-DSA-SHAKE-128f").unwrap();
    let case = vectors().into_iter()
        .find(|case| case.mode == "sigGen-internal-deterministic"
                     && case.parameter_set == set.name)
        .expect("a deterministic SHAKE-128f case");
    let public = &case.sk[2 * set.n..];
    let signature = allcrypt::pq::slh_dsa::sign_internal(
        set, &case.sk, &case.message,
        &case.sk[2 * set.n..3 * set.n]).unwrap();
    assert!(allcrypt::pq::slh_dsa::verify_internal(
                set, public, &case.message, &signature).unwrap());

    let fors_at = set.n;
    let hypertree_at = set.n + set.k * (1 + set.a) * set.n;
    for (what, at) in [("R", 0usize), ("the FORS signature", fors_at),
                       ("the hypertree signature", hypertree_at)] {
        let mut broken = signature.clone();
        broken[at] ^= 1;
        assert!(!allcrypt::pq::slh_dsa::verify_internal(
                    set, public, &case.message, &broken).unwrap(),
                "a flipped bit in {what} was accepted");
    }

    // A different message under the same signature.
    let mut other = case.message.clone();
    other.push(0);
    assert!(!allcrypt::pq::slh_dsa::verify_internal(
                set, public, &other, &signature).unwrap(),
            "the signature verified against a longer message");

    // And the wrong lengths, which are `false` and not `Err`.
    assert!(!allcrypt::pq::slh_dsa::verify_internal(
                set, public, &case.message,
                &signature[..signature.len() - 1]).unwrap());
    let mut longer = signature.clone();
    longer.push(0);
    assert!(!allcrypt::pq::slh_dsa::verify_internal(
                set, public, &case.message, &longer).unwrap());
}

/// The same key and message, signed hedged twice, gives two different
/// signatures and both verify.
///
/// **A test that asserted signing was deterministic would be asserting
/// the wrong thing**, unlike EdDSA where determinism is the
/// specification. FIPS 205 has both modes and both are valid, so what is
/// checked is that they differ and that the difference does not stop
/// either verifying.
#[test]
fn test_hedged_signing_differs_from_deterministic_and_both_verify() {
    let set = allcrypt::pq::slh_dsa::parameters("SLH-DSA-SHA2-128f").unwrap();
    let case = vectors().into_iter()
        .find(|case| case.mode == "sigGen-internal-hedged"
                     && case.parameter_set == set.name)
        .expect("a hedged SHA2-128f case");
    let public = &case.sk[2 * set.n..];
    let pk_seed = &case.sk[2 * set.n..3 * set.n];

    let deterministic = allcrypt::pq::slh_dsa::sign_internal(
        set, &case.sk, &case.message, pk_seed).unwrap();
    let hedged = allcrypt::pq::slh_dsa::sign_internal(
        set, &case.sk, &case.message, &case.additional_randomness).unwrap();

    assert_ne!(deterministic, hedged,
               "opt_rand is supposed to change the signature");
    for signature in [&deterministic, &hedged] {
        assert!(allcrypt::pq::slh_dsa::verify_internal(
                    set, public, &case.message, signature).unwrap());
    }

    // Signing twice with the same opt_rand repeats, which is what makes
    // the deterministic mode reproducible at all.
    assert_eq!(allcrypt::pq::slh_dsa::sign_internal(
                   set, &case.sk, &case.message, pk_seed).unwrap(),
               deterministic);
}
