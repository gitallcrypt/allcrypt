/*
SLH-DSA verification against NIST's `sigVer` vectors: signatures that must
be accepted, and signatures that must be refused.

`vectors/slh_dsa_sigver.vec`, written by
`scripts/make_slh_dsa_sigver_vectors.py`. Two parameter sets - the
smallest signature in each hash family - with all three of their groups
(internal, external pure, external pre-hash) and one case per ACVP reason
per group: 42 cases, 36 of them refusals.

## Why the reason matters

Each reason reaches a different part of verification. "Modified message"
changes `H_msg`'s input; "modified signature - R" the randomiser;
"SIGFORS" the FORS signature, and so the FORS public key that the
hypertree signs; "SIGHT" the hypertree itself; "too small" and "too large"
the length check before anything is parsed. A verifier that skipped one
of those would refuse every case but one kind, so a failure here names
the reason - which part of verification did not notice.

Refusals must be `Ok(false)`, not `Err`. A signature of the wrong length
is a signature that does not verify, and the function's contract is that
`Err` is for inputs that could never be interpreted - a public key of the
wrong length, an unknown pre-hash name.
*/

use allcrypt::pq::slh_dsa;

const VECTORS: &str = include_str!("../vectors/slh_dsa_sigver.vec");

const REASONS: [&str; 7] = [
    "valid signature and message - signature should verify successfully",
    "modified message",
    "modified signature - R",
    "modified signature - SIGFORS",
    "modified signature - SIGHT",
    "invalid signature - too small",
    "invalid signature - too large",
];

struct Case {
    interface: &'static str,
    parameter_set: &'static str,
    tc_id: u32,
    fields: std::collections::HashMap<&'static str, &'static str>,
}

impl Case {
    fn text(&self, name: &str) -> &'static str {
        self.fields.get(name).copied().unwrap_or_else(|| panic!(
            "{} {} tcId {}: no field {name:?}", self.interface,
            self.parameter_set, self.tc_id))
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        let text = self.text(name);
        assert!(text.len().is_multiple_of(2), "tcId {}: {name}", self.tc_id);
        (0..text.len()).step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16)
                          .expect("hex"))
            .collect()
    }
}

/// Every case, with each section's declared count asserted as it is read.
fn vectors() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let mut section: Option<(&'static str, &'static str)> = None;
    let mut declared: Vec<(usize, usize)> = Vec::new();   // (count, start)

    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let parts: Vec<&str> = header.trim_end_matches(']')
                .split_whitespace().collect();
            assert_eq!(parts.len(), 3, "section header {line:?}");
            let interface = parts[0].strip_prefix("sigVer-")
                .unwrap_or_else(|| panic!("not a sigVer section: {line:?}"));
            section = Some((interface, parts[1]));
            declared.push((parts[2].parse().expect("count"), cases.len()));
            continue;
        }
        let (name, value) = line.split_once(" = ")
            .or_else(|| line.strip_suffix(" =").map(|name| (name, "")))
            .unwrap_or_else(|| panic!("not a field: {line:?}"));
        if name == "tcId" {
            let (interface, parameter_set) =
                section.expect("a case outside any section");
            cases.push(Case { interface, parameter_set,
                              tc_id: value.parse().expect("tcId"),
                              fields: Default::default() });
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
    assert_eq!(declared.len(), 6);
    cases
}

#[test]
fn test_the_vector_file_parses_to_what_it_should() {
    let cases = vectors();
    assert_eq!(cases.len(), 42);
    let refusals = cases.iter().filter(|c| c.text("testPassed") == "false")
        .count();
    assert_eq!(refusals, 36);

    // Every reason in every section, and the verdict ACVP attaches to it.
    for chunk in cases.chunks(7) {
        let reasons: Vec<&str> = chunk.iter().map(|c| c.text("reason"))
            .collect();
        assert_eq!(reasons, REASONS, "{} {}", chunk[0].interface,
                   chunk[0].parameter_set);
        for case in chunk {
            let valid = case.text("reason") == REASONS[0];
            assert_eq!(case.text("testPassed"),
                       if valid { "true" } else { "false" });
        }
    }

    // The two length cases are what they say: one byte either side.
    for case in &cases {
        let set = slh_dsa::parameters(case.parameter_set).unwrap();
        let expected = set.signature_len();
        let got = case.bytes("signature").len();
        match case.text("reason") {
            "invalid signature - too small" => assert_eq!(got, expected - 1),
            "invalid signature - too large" => assert_eq!(got, expected + 1),
            _ => assert_eq!(got, expected, "tcId {}", case.tc_id),
        }
    }
}

/// All 42: six accepted, thirty-six refused, each for its stated reason.
#[test]
fn test_every_verification_vector() {
    let mut refused_for: std::collections::BTreeMap<&str, usize> =
        Default::default();
    for case in vectors() {
        let set = slh_dsa::parameters(case.parameter_set).unwrap();
        let pk = case.bytes("pk");
        let message = case.bytes("message");
        let signature = case.bytes("signature");
        let verdict = match case.interface {
            "internal" => slh_dsa::verify_internal(set, &pk, &message,
                                                   &signature),
            "external-pure" => slh_dsa::verify(
                set, &pk, &message, &case.bytes("context"), None, &signature),
            "external-preHash" => slh_dsa::verify(
                set, &pk, &message, &case.bytes("context"),
                Some(slh_dsa::PreHash::by_name(case.text("hashAlg")).unwrap()),
                &signature),
            other => panic!("unknown interface {other:?}"),
        };
        let reason = case.text("reason");
        let want = case.text("testPassed") == "true";
        match verdict {
            Ok(got) => assert_eq!(
                got, want,
                "{} {} tcId {}: {reason:?} - verification {}", set.name,
                case.interface, case.tc_id,
                if want { "refused a valid signature" }
                else { "accepted it, so that part of the signature is not \
                        being checked" }),
            Err(error) => panic!(
                "{} {} tcId {}: {reason:?} should be Ok({want}), not an \
                 error: {error}", set.name, case.interface, case.tc_id),
        }
        if !want {
            *refused_for.entry(reason).or_insert(0) += 1;
        }
    }
    // Six of each refusal: two parameter sets times three interfaces.
    assert_eq!(refused_for.len(), 6);
    assert!(refused_for.values().all(|count| *count == 6), "{refused_for:?}");
}
