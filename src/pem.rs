/*
Base64 and PEM.

Both are here because certificates arrive as PEM far more often than as DER,
and because adding a dependency for forty lines of base64 would be the wrong
trade in a library whose point is that every fault is ours.

The decoder is strict in the ways that matter for a security boundary:

  * Characters outside the alphabet are an error, not skipped. A decoder
    that skips them will happily decode two different texts to the same
    bytes, and one that skips them *inside* a line lets an attacker hide
    something in a certificate that one parser sees and another does not.
    Whitespace between lines is the one exception, because that is what PEM
    is made of.

  * Padding must be right. `=` only at the end, only one or two, and the
    bits it pads over must be zero - otherwise `SGVsbG9=` and `SGVsbG9+`
    would decode to the same thing, which is a second encoding again.

  * A truncated group is an error. Three base64 characters is 18 bits and
    there is no 18-bit unit; accepting it means inventing bits.

PEM itself is simple enough to be dangerous: the label in the BEGIN line has
to match the END line, because a file that says BEGIN CERTIFICATE and ends
END PRIVATE KEY should not quietly load as either.
*/

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The inverse of `ALPHABET`: 255 marks a character that is not base64.
fn decode_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut index = 0;
    while index < 64 {
        table[ALPHABET[index] as usize] = index as u8;
        index += 1;
    }
    table
}

/// Standard base64, with padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0],
                 *chunk.get(1).unwrap_or(&0),
                 *chunk.get(2).unwrap_or(&0)];
        let packed = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(packed >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(packed >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(packed >> 6) as usize & 0x3f] as char
        } else { '=' });
        out.push(if chunk.len() > 2 {
            ALPHABET[packed as usize & 0x3f] as char
        } else { '=' });
    }
    out
}

/// Standard base64, rejecting anything that is not exactly that.
///
/// Whitespace between groups is allowed, because PEM is base64 with line
/// breaks in it. Everything else that is not in the alphabet is an error.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let table = decode_table();
    let mut out = Vec::with_capacity(text.len() / 4 * 3);

    let mut group = [0u8; 4];
    let mut have = 0usize;
    let mut padding = 0usize;

    for &byte in text.as_bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            // Padding closes the group; nothing may follow it but more
            // padding and whitespace.
            if have + padding < 2 {
                return Err("Base64 padding where there is nothing to pad."
                           .to_string());
            }
            padding += 1;
            if padding > 2 {
                return Err("More than two base64 padding characters.".to_string());
            }
            continue;
        }
        if padding > 0 {
            return Err("Base64 data after the padding.".to_string());
        }

        let value = table[byte as usize];
        if value == 255 {
            return Err(format!("Character {:?} is not base64.", byte as char));
        }
        group[have] = value;
        have += 1;

        if have == 4 {
            let packed = ((group[0] as u32) << 18) | ((group[1] as u32) << 12)
                | ((group[2] as u32) << 6) | group[3] as u32;
            out.push((packed >> 16) as u8);
            out.push((packed >> 8) as u8);
            out.push(packed as u8);
            have = 0;
        }
    }

    match (have, padding) {
        (0, 0) => Ok(out),
        (2, 2) | (2, 0) => {
            // Two characters carry 12 bits and encode one byte, so the
            // bottom four bits must be zero or they are bits nobody can
            // represent - which would give two encodings of one value.
            if group[1] & 0x0f != 0 {
                return Err("Base64 group has non-zero padding bits.".to_string());
            }
            out.push(((group[0] as u32) << 2 | (group[1] as u32) >> 4) as u8);
            Ok(out)
        }
        (3, 1) | (3, 0) => {
            if group[2] & 0x03 != 0 {
                return Err("Base64 group has non-zero padding bits.".to_string());
            }
            let packed = ((group[0] as u32) << 12) | ((group[1] as u32) << 6)
                | group[2] as u32;
            out.push((packed >> 10) as u8);
            out.push((packed >> 2) as u8);
            Ok(out)
        }
        (1, _) => Err("Base64 ends with a single leftover character.".to_string()),
        (have, padding) => Err(format!(
            "Base64 ends with {} characters and {} padding.", have, padding)),
    }
}

/// One PEM block: its label, its RFC 1421 encapsulated headers, and
/// its decoded contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub label: String,
    /// The `Key: value` lines between the BEGIN line and the first blank
    /// line, in order, when the block has any. OpenSSL's traditional
    /// encrypted keys carry `Proc-Type: 4,ENCRYPTED` and `DEK-Info:
    /// <cipher>,<hex IV>` here; a certificate carries none.
    pub headers: Vec<(String, String)>,
    pub contents: Vec<u8>,
}

impl Block {
    /// The value of the first header named `name`, compared without
    /// regard to case as RFC 1421 section 4.6 has it.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Every PEM block in a document, in order.
///
/// Text outside the blocks is ignored, which is what every other
/// implementation does and what makes a CA bundle with comments in it work.
/// What is *not* ignored is a block whose END label does not match its
/// BEGIN, or one with no END at all - a truncated file should be an error
/// rather than a silently shorter list of roots - or one whose body is
/// not base64. `parse_lenient` is the form that keeps going.
///
/// Encapsulated headers (RFC 1421 section 4.4, RFC 7468 section 5.2):
/// when the first line after BEGIN holds a `:`, which no base64 line
/// can, every line up to the first blank line is a `Key: value` header
/// and is kept on the block rather than decoded. That is the shape of
/// OpenSSL's traditional encrypted keys, and refusing it refused every
/// file that carried one.
pub fn parse(text: &str) -> Result<Vec<Block>, String> {
    let (blocks, failures) = scan(text);
    match failures.into_iter().next() {
        Some(skipped) => Err(skipped.reason),
        None => Ok(blocks),
    }
}

/// A block `parse_lenient` could not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    /// The label on its BEGIN line.
    pub label: String,
    /// Why, as `parse` would have reported it.
    pub reason: String,
    /// The block had no matching END line (the file ends, or another
    /// BEGIN, inside it). A flag rather than a reading of `reason`,
    /// because a caller deciding whether a bundle is truncated should
    /// not parse an error message to find out.
    pub truncated: bool,
}

/// Every PEM block that could be read, and the ones that could not, in
/// document order.
///
/// For a CA bundle, or a combined certificate-and-key file, one block
/// that does not decode should not drop every other block in the file;
/// but it should not vanish either, so the skipped blocks come back
/// beside the read ones for the caller to record. `certificates` uses
/// this.
pub fn parse_lenient(text: &str) -> (Vec<Block>, Vec<Skipped>) {
    scan(text)
}

/// The scanner behind `parse` and `parse_lenient`: blocks in order, and
/// the skipped blocks in order.
fn scan(text: &str) -> (Vec<Block>, Vec<Skipped>) {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";
    const DASHES: &str = "-----";

    let mut blocks = Vec::new();
    let mut failures = Vec::new();
    let mut lines = text.lines().peekable();

    while let Some(line) = lines.next() {
        let line = line.trim();
        let label = match line.strip_prefix(BEGIN).and_then(|r| r.strip_suffix(DASHES)) {
            Some(label) => label.to_string(),
            None => continue,
        };

        // Headers: only if the first line of the block has one. A line
        // starting with whitespace continues the previous header, joined
        // by a single space as RFC 822 folding has it (RFC 1421 section
        // 4.6; `trim` has not yet run on the line here).
        let mut headers: Vec<(String, String)> = Vec::new();
        if lines.peek().is_some_and(|first| first.contains(':') && !first.starts_with(DASHES)) {
            while let Some(raw) = lines.peek() {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    lines.next();
                    break;
                }
                if trimmed.starts_with(DASHES) {
                    // No blank line before END: the body is empty and
                    // the END line is left for the loop below.
                    break;
                }
                if raw.starts_with([' ', '\t']) {
                    if let Some((_, value)) = headers.last_mut() {
                        value.push(' ');
                        value.push_str(trimmed);
                        lines.next();
                        continue;
                    }
                }
                match trimmed.split_once(':') {
                    Some((key, value)) => {
                        headers.push((key.trim().to_string(), value.trim().to_string()));
                        lines.next();
                    }
                    // A line with no colon ends the header section
                    // without a blank line; the body starts here.
                    None => break,
                }
            }
        }

        let mut body = String::new();
        let mut outcome = Ok(());
        let mut closed = false;
        let mut truncated = false;
        while let Some(line) = lines.peek() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix(END) {
                match rest.strip_suffix(DASHES) {
                    Some(closing) if closing == label => {}
                    Some(closing) => outcome = Err(format!(
                        "PEM block opens as {:?} and closes as {:?}.", label, closing)),
                    None => outcome = Err("Malformed PEM END line.".to_string()),
                }
                lines.next();
                closed = true;
                break;
            }
            if line.starts_with(BEGIN) {
                // Left for the outer loop, so the block that starts here
                // is still read.
                outcome = Err(format!("PEM block {:?} was never closed.", label));
                closed = true;
                truncated = true;
                break;
            }
            body.push_str(line);
            lines.next();
        }
        if !closed {
            outcome = Err(format!("PEM block {:?} has no END line.", label));
            truncated = true;
        }

        let decoded = outcome.and_then(|()| decode(&body)
            .map_err(|e| format!("In PEM block {:?}: {}", label, e)));
        match decoded {
            Ok(contents) => blocks.push(Block { label, headers, contents }),
            Err(reason) => failures.push(Skipped { label, reason, truncated }),
        }
    }
    (blocks, failures)
}

const CERTIFICATE_LABELS: [&str; 3] =
    ["CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"];

/// Just the certificates, which is what a CA bundle is.
///
/// A block that is not a certificate and does not decode is left out
/// rather than failing the call: a combined certificate-and-key file
/// with a key in a form this parser cannot read is still a certificate
/// source. A *certificate* block that does not decode is an error, as
/// is a block that never closes, because a truncated bundle is a
/// shorter list of roots with nothing to say so. `parse_lenient` has
/// the reasons when a caller wants to record the skipped blocks.
pub fn certificates(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let (blocks, skipped) = parse_lenient(text);
    if let Some(fatal) = skipped.iter().find(|skipped|
            skipped.truncated || CERTIFICATE_LABELS.contains(&skipped.label.as_str())) {
        return Err(fatal.reason.clone());
    }
    Ok(blocks
        .into_iter()
        .filter(|block| CERTIFICATE_LABELS.contains(&block.label.as_str()))
        .map(|block| block.contents)
        .collect())
}

/// Wrap DER as a PEM block, 64 characters to a line as the spec says.
pub fn wrap(label: &str, der: &[u8]) -> String {
    let encoded = encode(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 section 10, which is the whole point of having vectors.
    #[test]
    fn test_rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "encoding {:?}", plain);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes(),
                       "decoding {:?}", encoded);
        }
    }

    #[test]
    fn test_round_trip_over_every_length() {
        for length in 0..300usize {
            let data: Vec<u8> = (0..length).map(|i| ((i * 167 + 13) & 0xff) as u8).collect();
            let encoded = encode(&data);
            assert_eq!(encoded.len(), data.len().div_ceil(3) * 4, "length {}", length);
            assert_eq!(decode(&encoded).unwrap(), data, "round trip at {}", length);
        }
    }

    #[test]
    fn test_every_byte_value_round_trips() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn test_whitespace_between_groups_is_allowed() {
        assert_eq!(decode("Zm9v\nYmFy").unwrap(), b"foobar");
        assert_eq!(decode("Zm9v YmFy").unwrap(), b"foobar");
        assert_eq!(decode("  Zm9vYmFy  \r\n").unwrap(), b"foobar");
    }

    /// Each of these is a second encoding of something, or an invention of
    /// bits. A lenient decoder accepts them, and a lenient decoder on a
    /// security boundary means two parsers can disagree about a file.
    #[test]
    fn test_malformed_base64_is_rejected() {
        for (text, why) in [
            ("Zm9vYmF", "a single leftover character"),
            ("Zm9!", "a character outside the alphabet"),
            ("Zm-9", "URL-safe alphabet, which this is not"),
            ("Zm9vYg===", "three padding characters"),
            ("=", "padding with nothing to pad"),
            ("==", "padding with nothing to pad"),
            ("Zg==Zg==", "data after the padding"),
            ("Zg=x", "a character after padding"),
            ("Zh==", "non-zero bits under the padding"),
            ("Zm9x=", "non-zero bits under the padding"),
        ] {
            assert!(decode(text).is_err(), "{:?} ({}) should be rejected", text, why);
        }
    }

    #[test]
    fn test_pem_round_trip() {
        let der: Vec<u8> = (0..200u8).collect();
        let text = wrap("CERTIFICATE", &der);
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        // Lines are 64 characters, as the spec says.
        for line in text.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64, "line of {} characters", line.len());
        }

        let blocks = parse(&text).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].contents, der);
    }

    /// A CA bundle is many blocks with human-readable junk between them.
    #[test]
    fn test_a_bundle_with_comments_between_blocks() {
        let one = wrap("CERTIFICATE", b"first");
        let two = wrap("CERTIFICATE", b"second");
        let text = format!(
            "# A comment\nSome Root CA\n==============\n{}\n\
             Another Root\n=============\n{}\ntrailing junk\n", one, two);

        let certificates = certificates(&text).unwrap();
        assert_eq!(certificates, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn test_only_certificate_blocks_come_back_from_certificates() {
        let text = format!("{}{}{}",
                           wrap("PRIVATE KEY", b"secret"),
                           wrap("CERTIFICATE", b"public"),
                           wrap("RSA PRIVATE KEY", b"also secret"));
        assert_eq!(certificates(&text).unwrap(), vec![b"public".to_vec()]);
        assert_eq!(parse(&text).unwrap().len(), 3);
    }

    /// A file that says one thing at the top and another at the bottom is
    /// not a block that happens to be mislabelled; it is a file somebody
    /// assembled wrong, or on purpose.
    #[test]
    fn test_mismatched_and_truncated_blocks_are_rejected() {
        let mismatched = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END PRIVATE KEY-----\n";
        assert!(parse(mismatched).unwrap_err().contains("closes as"));

        let truncated = "-----BEGIN CERTIFICATE-----\nZm9v\n";
        assert!(parse(truncated).unwrap_err().contains("no END"));

        let nested = "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n";
        assert!(parse(nested).is_err());

        // Bad base64 inside a block must name the block.
        let bad = "-----BEGIN CERTIFICATE-----\nZm9!\n-----END CERTIFICATE-----\n";
        assert!(parse(bad).unwrap_err().contains("CERTIFICATE"));
    }

    /// Every line between BEGIN and END went into the base64 body, so a
    /// block with RFC 1421 headers - OpenSSL's traditional encrypted
    /// keys, `Proc-Type` and `DEK-Info` - failed with "Character ':' is
    /// not base64". Every fixture in the tree is PKCS#8 or a
    /// certificate, neither of which carries headers. The block here is
    /// built from a real body with the two header lines OpenSSL writes
    /// in front of it; `tests/test_pem_headers.rs` has the whole file.
    #[test]
    fn test_encapsulated_headers_are_kept_not_decoded() {
        let der: Vec<u8> = (0..100u8).collect();
        let body: String = wrap("RSA PRIVATE KEY", &der).lines()
            .filter(|line| !line.starts_with("-----"))
            .map(|line| format!("{line}\n"))
            .collect();
        let text = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n\
             Proc-Type: 4,ENCRYPTED\n\
             DEK-Info: AES-128-CBC,473C23087C2FC0306FAE4F884802BE0F\n\
             \n{body}-----END RSA PRIVATE KEY-----\n");
        let blocks = parse(&text).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].contents, der);
        assert_eq!(blocks[0].headers, vec![
            ("Proc-Type".to_string(), "4,ENCRYPTED".to_string()),
            ("DEK-Info".to_string(), "AES-128-CBC,473C23087C2FC0306FAE4F884802BE0F".to_string()),
        ]);
        assert_eq!(blocks[0].header("dek-info"),
                   Some("AES-128-CBC,473C23087C2FC0306FAE4F884802BE0F"));
        assert_eq!(blocks[0].header("Content-Domain"), None);

        // A continuation line (leading whitespace) extends the previous
        // header, joined by one space as RFC 822 folding has it, and a
        // block without headers has none.
        let folded = text.replace("DEK-Info: AES-128-CBC,", "DEK-Info: AES-128-CBC,\n  ");
        let folded = parse(&folded).unwrap();
        assert_eq!(folded[0].headers.len(), 2);
        assert_eq!(folded[0].header("DEK-Info"),
                   Some("AES-128-CBC, 473C23087C2FC0306FAE4F884802BE0F"));
        assert_eq!(folded[0].contents, der);
        assert!(parse(&wrap("CERTIFICATE", &der)).unwrap()[0].headers.is_empty());
    }

    /// `parse` was all-or-nothing, so `certificates` - and through it
    /// `TrustStore::add_pem` - returned `Err` for a bundle in which one
    /// non-certificate block did not decode, dropping every root in the
    /// file. The existing bundle tests held only well-formed blocks.
    #[test]
    fn test_one_bad_block_does_not_drop_the_others() {
        let text = format!("{}-----BEGIN RSA PRIVATE KEY-----\nZm9!\n\
                            -----END RSA PRIVATE KEY-----\n{}",
                           wrap("CERTIFICATE", b"first"), wrap("CERTIFICATE", b"second"));
        // Strict: still an error, naming the block.
        assert!(parse(&text).unwrap_err().contains("RSA PRIVATE KEY"));
        // Lenient: both certificates, and the key reported beside them.
        let (blocks, skipped) = parse_lenient(&text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].label, "RSA PRIVATE KEY");
        assert!(!skipped[0].truncated);
        assert!(skipped[0].reason.contains("not base64"));
        assert_eq!(certificates(&text).unwrap(),
                   vec![b"first".to_vec(), b"second".to_vec()]);

        // A certificate block that does not decode is still an error
        // for `certificates`: a bundle must not silently shrink.
        let bad_cert = text.replace("RSA PRIVATE KEY", "CERTIFICATE");
        assert!(certificates(&bad_cert).is_err());
        assert_eq!(parse_lenient(&bad_cert).0.len(), 2);

        // And so is a truncated one, whatever its label: the block that
        // follows the cut is still read, and the cut is reported.
        let cut = format!("{}-----BEGIN RSA PRIVATE KEY-----\nZm9v\n{}",
                          wrap("CERTIFICATE", b"first"), wrap("CERTIFICATE", b"second"));
        let (blocks, skipped) = parse_lenient(&cut);
        assert_eq!(blocks.len(), 2);
        assert!(skipped[0].truncated);
        assert!(certificates(&cut).is_err());
    }

    #[test]
    fn test_text_with_no_blocks_is_empty_not_an_error() {
        assert!(parse("nothing to see here\n").unwrap().is_empty());
        assert!(parse("").unwrap().is_empty());
        assert!(certificates("# just a comment").unwrap().is_empty());
    }
}
