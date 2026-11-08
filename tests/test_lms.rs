//! LMS and HSS against the RFCs' worked examples, read out of the vendored
//! texts: RFC 8554 Appendix F's two hierarchies, and RFC 9858 Appendix A's
//! four single trees over the added hash functions. Where a document gives
//! the private seeds, the signature is made again here and compared byte
//! for byte, which settles the key derivation and the randomiser as well
//! as the verifier. Offline.

use allcrypt::pq::lms::{hss_verify, lmots_public_key, lmots_sign, lmots_verify, lms_verify,
                        HssPrivateKey, LmotsParams, LmsParams, LmsPrivateKey,
                        LMOTS_PARAMETER_SETS, LMS_PARAMETER_SETS};

const RFC8554: &str = include_str!("../rfcs/rfc8554.txt");

/// One worked example: its labelled private values in order, and its
/// public key, message and signature, each the concatenation of the hex
/// in its block.
#[derive(Default, Debug)]
struct Example {
    private: Vec<(String, Vec<u8>)>,
    public: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// `(label, hex)` from a line of a worked example: indented, an optional
/// label, then lowercase hex, then an optional `#` comment or `|ascii|`.
/// Page headers and footers are not indented and never match.
fn value(line: &str) -> Option<(String, String)> {
    if !line.starts_with("   ") {
        return None;
    }
    let body = line.split(['#', '|']).next().unwrap().trim_end();
    let mut words: Vec<&str> = body.split_whitespace().collect();
    let hex = *words.last()?;
    let is_hex = hex.len() >= 2 && hex.len() % 2 == 0
        && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !is_hex {
        return None;
    }
    words.pop();
    Some((words.join(" "), hex.to_string()))
}

/// The examples in `section`, split at each heading that starts one.
fn examples(section: &str, starts: &[&str]) -> Vec<Example> {
    let mut out: Vec<Example> = Vec::new();
    let mut block = "";
    for line in section.lines() {
        let trimmed = line.trim();
        if starts.iter().any(|s| trimmed.starts_with(s)) && !trimmed.contains("Private Key")
            && !trimmed.contains("Public Key") && !trimmed.contains("Message")
            && !trimmed.contains("Signature") {
            out.push(Example::default());
            block = "";
            continue;
        }
        let Some(example) = out.last_mut() else { continue };
        if trimmed.starts_with("(note: procedure") {
            block = "private";
        } else if trimmed == "HSS public key" {
            block = "public";
        } else if trimmed == "HSS signature" {
            block = "signature";
        } else if trimmed.starts_with("Message ") {
            block = "message";
        }
        let Some((label, hex)) = value(line) else { continue };
        let bytes = unhex(&hex);
        match block {
            "private" if label.is_empty() => example.private.last_mut().unwrap().1.extend(bytes),
            "private" => example.private.push((label, bytes)),
            "public" => example.public.extend(bytes),
            "message" => example.message.extend(bytes),
            "signature" => example.signature.extend(bytes),
            _ => {}
        }
    }
    out
}

fn rfc8554_examples() -> Vec<Example> {
    let at = RFC8554.rfind("Appendix F.  Test Cases").unwrap();
    // Each case has four headings; the first, "Test Case N Private Key"
    // or "Public Key", starts it.
    let mut out = Vec::new();
    for case in ["Test Case 1", "Test Case 2"] {
        let start = RFC8554[at..].find(case).unwrap() + at;
        let text = &RFC8554[start..];
        // Everything up to the next case's first heading.
        let next = if case == "Test Case 1" { text.find("Test Case 2").unwrap() } else {
            text.len()
        };
        let mut found = examples(&format!("   X\n{}", &text[..next]), &["X"]);
        assert_eq!(found.len(), 1);
        out.push(found.remove(0));
    }
    out
}

fn rfc9858_examples() -> Vec<Example> {
    let text = include_str!("../rfcs/rfc9858.txt");
    let at = text.rfind("Appendix A.  Test Cases").unwrap();
    let end = text[at..].find("\nAcknowledgements").map_or(text.len(), |e| e + at);
    examples(&text[at..end], &["A.1.", "A.2.", "A.3.", "A.4."])
}

#[test]
fn test_the_rfc_vectors_parse() {
    let a = rfc8554_examples();
    assert_eq!(a.len(), 2);
    assert!(a[0].private.is_empty());
    assert_eq!(a[1].private.iter().map(|p| p.0.as_str()).collect::<Vec<_>>(),
               ["SEED", "I", "SEED", "I"]);
    let b = rfc9858_examples();
    assert_eq!(b.len(), 4);
    for e in a.iter().chain(&b) {
        assert!(!e.public.is_empty() && !e.message.is_empty() && !e.signature.is_empty());
    }
    assert_eq!(a[0].message.len(), 162);
    // The hex reads "SHA256-192"; the ASCII column beside it says otherwise.
    assert!(b[0].message.starts_with(b"Test message for SHA256-192"));
}

#[test]
fn test_rfc_8554_hierarchies_verify() {
    for e in rfc8554_examples() {
        assert!(hss_verify(&e.public, &e.message, &e.signature));
        let mut other = e.message.clone();
        other[0] ^= 1;
        assert!(!hss_verify(&e.public, &other, &e.signature));
        for at in [4, 8, 40, e.signature.len() / 2, e.signature.len() - 1] {
            let mut bad = e.signature.clone();
            bad[at] ^= 0x10;
            assert!(!hss_verify(&e.public, &e.message, &bad), "byte {at}");
        }
        assert!(!hss_verify(&e.public, &e.message, &e.signature[..e.signature.len() - 1]));
        let mut longer = e.signature.clone();
        longer.push(0);
        assert!(!hss_verify(&e.public, &e.message, &longer));
    }
}

/// Each level's LMS signature and the public key it signs.
type Chain = Vec<(Vec<u8>, Vec<u8>)>;

/// The LMS signature and the public key that follow `u32str(Nspk)` in an
/// HSS signature, level by level, and the last signature.
fn split_hss(signature: &[u8], levels: &[(&'static LmsParams, &'static LmotsParams)])
             -> (Chain, Vec<u8>) {
    let mut rest = &signature[4..];
    let mut out = Vec::new();
    for (i, &(lms, ots)) in levels.iter().enumerate().take(levels.len() - 1) {
        let (sig, after) = rest.split_at(lms.signature_len(ots));
        let next = levels[i + 1].0;
        let (public, after) = after.split_at(next.public_key_len());
        out.push((sig.to_vec(), public.to_vec()));
        rest = after;
    }
    (out, rest.to_vec())
}

fn types(public: &[u8]) -> (&'static LmsParams, &'static LmotsParams) {
    (LmsParams::by_id(u32::from_be_bytes(public[..4].try_into().unwrap())).unwrap(),
     LmotsParams::by_id(u32::from_be_bytes(public[4..8].try_into().unwrap())).unwrap())
}

#[test]
fn test_rfc_8554_test_case_2_is_signed_again_from_its_seeds() {
    let e = &rfc8554_examples()[1];
    let top = types(&e.public[4..]);
    let (chain, last) = split_hss(&e.signature, &[top, types(&e.signature[4 + top.0
        .signature_len(top.1)..])]);
    let (top_sig, second_public) = &chain[0];
    let second = types(second_public);
    let seed = |i: usize| e.private[i].1.clone();
    let id = |i: usize| -> [u8; 16] { e.private[i].1.clone().try_into().unwrap() };
    let q = |sig: &[u8]| u32::from_be_bytes(sig[..4].try_into().unwrap());

    let mut upper = LmsPrivateKey::from_seed(top.0, top.1, &seed(0), &id(1), q(top_sig)).unwrap();
    assert_eq!(upper.public_key(), e.public[4..]);
    assert_eq!(upper.sign(second_public).unwrap(), *top_sig);
    let mut lower = LmsPrivateKey::from_seed(second.0, second.1, &seed(2), &id(3), q(&last))
        .unwrap();
    assert_eq!(lower.public_key(), *second_public);
    assert_eq!(lower.sign(&e.message).unwrap(), last);
}

#[test]
fn test_rfc_9858_trees_are_signed_again_from_their_seeds() {
    let mut seen = Vec::new();
    for e in rfc9858_examples() {
        assert_eq!(e.public[..4], 1u32.to_be_bytes());
        let (lms, ots) = types(&e.public[4..]);
        seen.push((lms.name, ots.name));
        assert_eq!(e.private.iter().map(|p| p.0.as_str()).collect::<Vec<_>>(), ["SEED", "I"]);
        let seed = &e.private[0].1;
        let id: [u8; 16] = e.private[1].1.clone().try_into().unwrap();
        let q = u32::from_be_bytes(e.signature[4..8].try_into().unwrap());

        // The one-time signature alone, at every height.
        let ots_sig = lmots_sign(ots, seed, &id, q, &e.message).unwrap();
        assert_eq!(ots_sig, e.signature[8..8 + ots.signature_len()], "{}", ots.name);
        let ots_public = lmots_public_key(ots, seed, &id, q).unwrap();
        assert!(lmots_verify(&ots_public, &e.message, &ots_sig));
        assert!(!lmots_verify(&ots_public, b"another message", &ots_sig));
        // The whole signature where the tree is low enough to build here:
        // the fourth example's is 2^20 leaves.
        if lms.h <= 10 {
            let mut key = HssPrivateKey::from_seed(&[(lms, ots)], seed, &id, u64::from(q))
                .unwrap();
            assert_eq!(key.public_key(), e.public);
            assert_eq!(key.sign(&e.message).unwrap(), e.signature, "{}", lms.name);
            assert_eq!(key.count(), u64::from(q) + 1);
        }
        assert!(hss_verify(&e.public, &e.message, &e.signature));
        assert!(lms_verify(&e.public[4..], &e.message, &e.signature[4..]));
        assert!(!hss_verify(&e.public, b"another message", &e.signature));
    }
    assert_eq!(seen, [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8"),
                      ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8"),
                      ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W8"),
                      ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W4")]);
}

/// The rows of a parameter table: the cells of each line that starts with
/// `| LMOTS_` or `| LMS_`.
fn table_rows(text: &str, prefix: &str) -> Vec<Vec<String>> {
    text.lines().map(str::trim).filter(|l| l.starts_with(&format!("| {prefix}")))
        .map(|l| l.trim_matches('|').split('|').map(|c| c.trim().to_string()).collect())
        .collect()
}

#[test]
fn test_the_parameter_tables_are_the_rfcs() {
    let rfc9858 = include_str!("../rfcs/rfc9858.txt");
    // RFC 8554 Table 1: name, H, n, w, p, ls, sig_len; Table 4 has the
    // codes. RFC 9858 Table 1: name, H, n, w, p, ls, id.
    let mut ots_rows = 0;
    for row in table_rows(RFC8554, "LMOTS_").into_iter().chain(table_rows(rfc9858, "LMOTS_")) {
        let p = LmotsParams::named(&row[0].replace("SHAKE256", "SHAKE")).unwrap();
        if row.len() == 7 {
            assert_eq!(row[2].parse::<usize>().unwrap(), p.n, "{}", p.name);
            assert_eq!(row[3].parse::<usize>().unwrap(), p.w, "{}", p.name);
            assert_eq!(row[4].parse::<usize>().unwrap(), p.p, "{}", p.name);
            assert_eq!(row[5].parse::<u32>().unwrap(), p.ls, "{}", p.name);
            if row[6].starts_with("0x") {
                assert_eq!(u32::from_str_radix(&row[6][2..], 16).unwrap(), p.id, "{}", p.name);
            } else {
                assert_eq!(row[6].parse::<usize>().unwrap(), p.signature_len(), "{}", p.name);
            }
            assert_eq!(row[1].starts_with("SHAKE"), p.hash == allcrypt::pq::lms::LmsHash::Shake256);
            ots_rows += 1;
        } else if row.len() == 3 {
            assert_eq!(u32::from_str_radix(&row[2][2..], 16).unwrap(), p.id, "{}", p.name);
            ots_rows += 1;
        }
    }
    assert_eq!(ots_rows, 4 + 4 + 12);
    let mut lms_rows = 0;
    for row in table_rows(RFC8554, "LMS_").into_iter().chain(table_rows(rfc9858, "LMS_")) {
        let p = LmsParams::named(&row[0]).unwrap();
        if row.len() == 4 || row.len() == 5 {
            assert_eq!(row[2].parse::<usize>().unwrap(), p.m, "{}", p.name);
            assert_eq!(row[3].parse::<u32>().unwrap(), p.h, "{}", p.name);
            if row.len() == 5 {
                assert_eq!(u32::from_str_radix(&row[4][2..], 16).unwrap(), p.id, "{}", p.name);
            }
            lms_rows += 1;
        } else if row.len() == 3 {
            assert_eq!(u32::from_str_radix(&row[2][2..], 16).unwrap(), p.id, "{}", p.name);
            lms_rows += 1;
        }
    }
    assert_eq!(lms_rows, 5 + 5 + 15);
    assert_eq!(LMOTS_PARAMETER_SETS.len(), 16);
    assert_eq!(LMS_PARAMETER_SETS.len(), 20);
}
