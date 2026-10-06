/*!
RFC 7748's test vectors, read out of the document at test time.

Nothing here is transcribed: the vectors are parsed out of the document
at test time, which is the rule in docs/extending.md, "Where test vectors
come from".

`x25519.rs` predates that rule and has its vectors typed into its test
module; the tests here read the same section of the same document, so
those numbers now have a source as well - see
`x448::tests::test_the_parser_reads_the_x25519_vectors_too`.

## What makes this document awkward

**X448's hex is split across two lines and X25519's is not.** Section
5.2 prints a 56 byte value as two 56-digit runs on consecutive lines and
a 32 byte value as one 64-digit run, so a parser that handles either
shape alone is silently wrong about the other: it finds nothing for one
curve, or truncates every value of the other to its first line. Both
failures produce a test that passes.

So the hex is gathered by **continuation** - a label line, then every
following line that is nothing but hex digits - and each caller asserts
the count and the width it expected. That count assertion has earned its
place three times in this repository already, in three different
documents.

**Two labelled sections share the same field names.** `Input scalar:`
appears under both `X25519:` and `X448:`, and under section 6's
Diffie-Hellman example the fields are named differently again. So
`single_vectors` takes the heading to start at and stops at the next
heading, the way the `[Name]` readers in `block_ciphers` do.

The document also prints each value a second time as a decimal number
across two or three lines - `Input scalar as a number (base 10):`. Those
lines are skipped by the same rule that gathers the hex: a decimal run is
not all hex digits unless it happens to contain no digit above 9 and no
letters, which for a 135 digit number is not a case that arises. The
counts are what would notice if it ever did.
*/

const RFC_7748: &str = include_str!("../../rfcs/rfc7748.txt");

/// Is this line nothing but hex digits, and long enough to be a value?
///
/// The length floor matters: the document's prose contains short runs
/// that are accidentally all hex (`a`, `abort`, `added`), and a body
/// line of a vector is never shorter than 56 digits.
fn is_hex_run(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.len() >= 56
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
        // A decimal continuation line is all digits and could be long
        // enough. Requiring at least one letter would reject a hex value
        // that happens to be all digits, which is one in a vast number
        // but not impossible - so instead the callers check the width,
        // which a decimal run of 45 digits fails.
        && trimmed.len().is_multiple_of(2)
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16)
             .unwrap_or_else(|_| panic!("not hex: {text:?}")))
        .collect()
}

/// Gather the hex value that follows a label, across as many lines as it
/// takes.
fn value_after(lines: &[&str], mut index: usize, width: usize) -> Vec<u8> {
    let mut digits = String::new();
    index += 1;
    while index < lines.len() && is_hex_run(lines[index]) {
        digits.push_str(lines[index].trim());
        index += 1;
    }
    let bytes = unhex(&digits);
    assert_eq!(bytes.len(), width,
               "expected {width} bytes after a label, got {} from {:?}",
               bytes.len(), digits);
    bytes
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    let mut out = [0u8; N];
    assert_eq!(bytes.len(), N);
    out.copy_from_slice(&bytes);
    out
}

/// The `(scalar, u, output)` triples under one heading of section 5.2.
///
/// `heading` is `"X25519:"` or `"X448:"`, and reading stops at the next
/// heading so the two cannot run together. `width` is the byte width
/// this curve's values have, which is checked on every one - that is
/// what catches a value whose continuation line was missed.
pub fn single_vectors(heading: &str, width: usize)
                      -> Vec<([u8; 56], [u8; 56], [u8; 56])> {
    assert!(width <= 56, "no curve here is wider than X448");
    let lines: Vec<&str> = RFC_7748.lines().collect();
    // **Anchored at section 5.2, not at the first matching line.**
    // `X448:` appears three times in this document: at line 371 inside
    // section 5's `<CODE BEGINS>` reference implementation, at 623 over
    // the vectors, and at 703 over the iterated results. The first
    // version of this searched from the top, landed in the pseudocode,
    // ran into section 5.2's `X25519:` heading and stopped - finding
    // **zero** vectors, which is the failure this file's own header
    // warns about and which the count assertion caught on the first run.
    let section = lines.iter()
        .position(|line| line.trim() == "5.2.  Test Vectors")
        .expect("RFC 7748 has no section 5.2 heading");
    let start = lines[section..].iter()
        .position(|line| line.trim() == heading)
        .map(|offset| section + offset)
        .unwrap_or_else(|| panic!("no {heading} heading in section 5.2"));

    let mut vectors = Vec::new();
    let (mut scalar, mut point) = (None, None);
    for index in start + 1..lines.len() {
        let trimmed = lines[index].trim();
        // The other curve's heading, or the start of the iterated
        // section, ends this one.
        if index != start
            && (trimmed == "X25519:" || trimmed == "X448:")
            && trimmed != heading
        {
            break;
        }
        if trimmed.starts_with("The second type of test vector") {
            break;
        }
        if trimmed == "Input scalar:" {
            scalar = Some(value_after(&lines, index, width));
        } else if trimmed == "Input u-coordinate:" {
            point = Some(value_after(&lines, index, width));
        } else if trimmed == "Output u-coordinate:" {
            let output = value_after(&lines, index, width);
            let (s, p) = (scalar.take(), point.take());
            let (s, p) = (s.expect("a scalar before an output"),
                          p.expect("a u coordinate before an output"));
            // Padded to 56 in the common return type; the callers slice
            // back to their own width. A fixed-size array per curve
            // would mean two copies of this function.
            let pad = |mut v: Vec<u8>| { v.resize(56, 0); fixed::<56>(v) };
            vectors.push((pad(s), pad(p), pad(output)));
        }
    }
    vectors
}

/// Section 6.2's five values, in the order the document names them.
///
/// A named type rather than a bare five-tuple, because clippy is right
/// about that one and because two of the five are private keys and two
/// are public: a caller who mixes up the order of a tuple gets a test
/// that compares Alice's public key against Bob's and fails for the
/// wrong reason.
pub type ExchangeVectors = ([u8; 56], [u8; 56], [u8; 56], [u8; 56], [u8; 56]);

/// Section 6.2's Diffie-Hellman example:
/// `(alice, alice_public, bob, bob_public, secret)`.
pub fn exchange_vectors() -> ExchangeVectors {
    let lines: Vec<&str> = RFC_7748.lines().collect();
    // Start at the Curve448 subsection, so section 6.1's X25519 example
    // - whose labels are worded identically - cannot be read instead.
    let start = lines.iter().position(|line| line.trim() == "6.2.  Curve448")
        .expect("RFC 7748 has no section 6.2");

    let mut found: Vec<(String, Vec<u8>)> = Vec::new();
    for index in start..lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.starts_with("7.  Security Considerations") {
            break;
        }
        // The labels name the party, so `Alice's private key, a:` and
        // `Bob's private key, b:` are distinguishable - which matters,
        // because reading them in document order and trusting the order
        // is how the two ends get swapped.
        for label in ["Alice's private key, a:", "Alice's public key, X448(a, 5):",
                      "Bob's private key, b:", "Bob's public key, X448(b, 5):",
                      "Their shared secret, K:"] {
            if trimmed == label {
                found.push((label.to_string(), value_after(&lines, index, 56)));
            }
        }
    }
    assert_eq!(found.len(), 5,
               "RFC 7748 6.2 names five values; the parser found {}",
               found.len());

    let get = |label: &str| -> [u8; 56] {
        let bytes = found.iter().find(|(name, _)| name == label)
            .unwrap_or_else(|| panic!("no {label} in section 6.2"))
            .1.clone();
        fixed::<56>(bytes)
    };
    (get("Alice's private key, a:"),
     get("Alice's public key, X448(a, 5):"),
     get("Bob's private key, b:"),
     get("Bob's public key, X448(b, 5):"),
     get("Their shared secret, K:"))
}

/// The iterated results after one and a thousand rounds, from the X448
/// half of section 5.2's second test.
///
/// The million-round value is in the document too and is deliberately not
/// returned: it is the same code a thousand times over and takes minutes
/// on `BigUint`.
pub fn iterated() -> ([u8; 56], [u8; 56]) {
    let lines: Vec<&str> = RFC_7748.lines().collect();
    // The iterated section repeats the `X448:` heading, so this looks
    // for the one *after* the sentence that introduces it - reading the
    // first `X448:` would land in section 5.2's single vectors, where
    // there is no "After one iteration" at all and the parser would find
    // nothing.
    let intro = lines.iter()
        .position(|line| line.trim().starts_with("The second type of test vector"))
        .expect("RFC 7748 has no iterated test");
    let start = lines[intro..].iter().position(|line| line.trim() == "X448:")
        .map(|offset| intro + offset)
        .expect("no X448 heading in the iterated section");

    let mut one = None;
    let mut thousand = None;
    for index in start..lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.starts_with("6.  Diffie-Hellman") {
            break;
        }
        if trimmed == "After one iteration:" {
            one = Some(value_after(&lines, index, 56));
        } else if trimmed == "After 1,000 iterations:" {
            thousand = Some(value_after(&lines, index, 56));
        }
    }
    (fixed::<56>(one.expect("no one-iteration value")),
     fixed::<56>(thousand.expect("no thousand-iteration value")))
}
