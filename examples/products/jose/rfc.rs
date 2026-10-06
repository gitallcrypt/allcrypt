//! The JOSE documents' own examples, read out of `rfcs/` at test time:
//! RFC 7515 appendix A (every JWS example, both JSON serializations and
//! the `crit` negative case of appendix E), RFC 7516 appendix A (the
//! RSA-OAEP, RSA1_5 and AES key wrap JWEs and the two-recipient one),
//! RFC 7518 appendices B and C (CBC-HMAC and the ECDH-ES Concat KDF),
//! RFC 7638's thumbprint, RFC 7797's unencoded payload and RFC 8037's
//! Ed25519, X25519 and X448 examples. Nothing is transcribed: a value
//! the parser cannot find fails the test that wanted it.

use crate::json::Json;
use crate::jwe::{self, Jwe, Secret};
use crate::jwk::{b64, unb64, Jwk};
use crate::jws::{self, Jws};

const RFC7515: &str = include_str!("../../../rfcs/rfc7515.txt");
const RFC7516: &str = include_str!("../../../rfcs/rfc7516.txt");
const RFC7518: &str = include_str!("../../../rfcs/rfc7518.txt");
const RFC7638: &str = include_str!("../../../rfcs/rfc7638.txt");
const RFC7797: &str = include_str!("../../../rfcs/rfc7797.txt");
const RFC8037: &str = include_str!("../../../rfcs/rfc8037.txt");

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The document's lines without its page furniture. A page break inside
/// a display - two indented lines either side of it - is joined up; any
/// other becomes one blank line, so it still ends a paragraph.
fn lines(document: &str) -> Vec<&str> {
    let raw: Vec<&str> = document.lines().map(|l| l.trim_end_matches('\u{c}')).collect();
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let line = raw[i];
        if line.contains("[Page ") {
            // Drop the blank lines before the footer, the header after
            // it and the blank lines after that.
            while out.last().is_some_and(|l| l.trim().is_empty()) {
                out.pop();
            }
            i += 1;
            while i < raw.len() && (raw[i].trim().is_empty() || raw[i].starts_with("RFC ")) {
                i += 1;
            }
            let before = out.last().map(|l| indent(l)).unwrap_or(0);
            let after = raw.get(i).map(|l| indent(l)).unwrap_or(0);
            if before < 5 || after < 5 {
                out.push("");
            }
            continue;
        }
        out.push(line);
        i += 1;
    }
    out
}

/// The lines from the one starting with `heading` to the end.
fn from<'a>(lines: &'a [&'a str], heading: &str) -> &'a [&'a str] {
    let start = lines.iter().position(|l| l.starts_with(heading))
        .unwrap_or_else(|| panic!("no heading {heading:?}"));
    &lines[start..]
}

/// The paragraph after the one containing `phrase`, with every bit of
/// whitespace removed - which is how the documents' "line breaks for
/// display purposes only" come out.
fn block(lines: &[&str], phrase: &str) -> String {
    let mut at = lines.iter().position(|l| l.contains(phrase))
        .unwrap_or_else(|| panic!("no phrase {phrase:?}"));
    while at < lines.len() && !lines[at].trim().is_empty() {
        at += 1;
    }
    while at < lines.len() && lines[at].trim().is_empty() {
        at += 1;
    }
    let mut out = String::new();
    while at < lines.len() && !lines[at].trim().is_empty() {
        out.extend(lines[at].chars().filter(|c| !c.is_whitespace()));
        at += 1;
    }
    assert!(!out.is_empty(), "an empty block after {phrase:?}");
    out
}

/// The octets in the JSON array notation that starts after `phrase`.
fn octets(lines: &[&str], phrase: &str) -> Vec<u8> {
    let at = lines.iter().position(|l| l.contains(phrase))
        .unwrap_or_else(|| panic!("no phrase {phrase:?}"));
    let text: String = lines[at..].join(" ");
    let start = text.find('[').expect("an array");
    let end = start + text[start..].find(']').expect("the array's end");
    let out: Vec<u8> = text[start + 1..end].split(',')
        .map(|n| n.trim().parse().unwrap_or_else(|_| panic!("not an octet: {n:?}")))
        .collect();
    assert!(!out.is_empty());
    out
}

/// RFC 7518 appendix B's `NAME = hex hex ...`, continued on the lines
/// below until a blank one.
fn hex_field(lines: &[&str], name: &str) -> Vec<u8> {
    let at = lines.iter().position(|l| l.trim_start().starts_with(&format!("{name} =")))
        .unwrap_or_else(|| panic!("no field {name}"));
    let mut text = lines[at].split_once('=').unwrap().1.to_string();
    for line in &lines[at + 1..] {
        if line.trim().is_empty() || line.contains('=') {
            break;
        }
        text.push(' ');
        text.push_str(line);
    }
    hex_words(&text)
}

/// RFC 8037's hex dumps: the first run of lines of hex pairs after the
/// line containing `phrase` - which may end with "(hex):" on a line of
/// its own.
fn hex_dump(lines: &[&str], phrase: &str) -> Vec<u8> {
    let at = lines.iter().position(|l| l.contains(phrase))
        .unwrap_or_else(|| panic!("no phrase {phrase:?}"));
    let is_hex = |line: &str| !line.trim().is_empty() && line.split_whitespace()
        .all(|w| w.len() == 2 && w.bytes().all(|b| b.is_ascii_hexdigit()));
    let text: Vec<&str> = lines[at + 1..].iter().copied().skip_while(|l| !is_hex(l))
        .take_while(|l| is_hex(l)).collect();
    hex_words(&text.join(" "))
}

fn hex_words(text: &str) -> Vec<u8> {
    let out: Vec<u8> = text.split_whitespace()
        .map(|w| u8::from_str_radix(w, 16).unwrap_or_else(|_| panic!("not hex: {w:?}")))
        .collect();
    assert!(!out.is_empty());
    out
}

fn key(text: &str) -> Jwk {
    Jwk::from_text(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// The two halves of a compact JWS's signing input, and its signature.
fn split(compact: &str) -> (&str, &str, Vec<u8>) {
    let parts: Vec<&str> = compact.split('.').collect();
    (parts[0], parts[1], unb64(parts[2]).unwrap())
}

// ---------------------------------------------------------------- RFC 7515 --

/// A.1 and A.2 are deterministic - HMAC and PKCS#1 v1.5 - so ours must
/// produce their signatures byte for byte over their signing input, as
/// well as verify them; A.3 and A.4 (ECDSA, randomised) are verified.
#[test]
fn test_rfc_7515_compact_examples() {
    let lines = lines(RFC7515);
    let payload = octets(from(&lines, "A.1.1."), "is the JWS Payload:");
    assert!(payload.starts_with(b"{\"iss\":\"joe\""), "{payload:?}");
    for (section, alg, deterministic) in [("A.1.1.", "HS256", true), ("A.2.1.", "RS256", true),
                                          ("A.3.1.", "ES256", false),
                                          ("A.4.1.", "ES512", false)] {
        let section = from(&lines, section);
        let key = key(&block(section, "represented in JSON Web Key"));
        let compact = block(section, "Concatenating these values in the order");
        let parsed = Jws::parse(&compact).unwrap();
        // A.4 signs a payload of its own, named in its text.
        let payload = if alg == "ES512" {
            quoted(section, "The JWS Payload used in this example is").into_bytes()
        } else {
            payload.clone()
        };
        assert_eq!(jws::verify(&parsed, Some(&key), false, None).unwrap(), payload, "{alg}");
        let (protected, encoded, signature) = split(&compact);
        let input = format!("{protected}.{encoded}");
        if deterministic {
            assert_eq!(jws::sign_input(alg, &key, input.as_bytes()).unwrap(), signature, "{alg}");
        } else {
            let ours = jws::sign_input(alg, &key, input.as_bytes()).unwrap();
            assert!(jws::verify_input(alg, &key, input.as_bytes(), &ours).unwrap());
        }
        // One flipped bit anywhere in the signature, and it is refused.
        for index in [0, signature.len() / 2, signature.len() - 1] {
            let mut changed = signature.clone();
            changed[index] ^= 1;
            assert!(!jws::verify_input(alg, &key, input.as_bytes(), &changed).unwrap(), "{alg}");
        }
    }
}

/// A.5's unsecured JWS: read only when asked to, and with no key.
#[test]
fn test_rfc_7515_unsecured_example() {
    let lines = lines(RFC7515);
    let compact = block(from(&lines, "A.5."), "representation using the JWS Compact");
    let parsed = Jws::parse(&compact).unwrap();
    assert!(jws::verify(&parsed, None, true, None).unwrap().starts_with(b"{\"iss\""));
    assert!(jws::verify(&parsed, None, false, None).is_err());
    let hmac = key(&block(from(&lines, "A.1.1."), "represented in JSON Web Key"));
    assert!(jws::verify(&parsed, Some(&hmac), true, None).is_err());
}

/// A.6 and A.7: the general serialization with two signatures under
/// unprotected `kid`s, and the flattened one.
#[test]
fn test_rfc_7515_json_examples() {
    let lines = lines(RFC7515);
    let rsa = key(&block(from(&lines, "A.2.1."), "represented in JSON Web Key"));
    let ec = key(&block(from(&lines, "A.3.1."), "represented in JSON Web Key"));
    let general = Jws::parse(&block(from(&lines, "A.6.4."), "The complete JWS JSON")).unwrap();
    assert_eq!(general.signatures.len(), 2);
    let flattened = Jws::parse(&block(from(&lines, "A.7."), "The complete JWS JSON")).unwrap();
    for (jws_, key) in [(&general, &rsa), (&general, &ec), (&flattened, &ec)] {
        assert!(jws::verify(jws_, Some(key), false, None).unwrap().starts_with(b"{\"iss\""));
    }
    // Ours writes the same JSON back out.
    let text = general.json(false).unwrap();
    assert_eq!(crate::json::parse(&text).unwrap(),
               crate::json::parse(&block(from(&lines, "A.6.4."), "The complete JWS JSON"))
                   .unwrap());
}

/// Appendix E: a critical extension nobody understands is refused,
/// even on an unsecured JWS a caller has said it will take.
#[test]
fn test_rfc_7515_crit_negative_case() {
    let lines = lines(RFC7515);
    let compact = block(from(&lines, "Appendix E."), "The complete JWS that must be rejected");
    let parsed = Jws::parse(&compact).unwrap();
    let error = jws::verify(&parsed, None, true, None).expect_err("refused");
    assert!(error.contains("not understood"), "{error}");
}

// ---------------------------------------------------------------- RFC 7797 --

/// RFC 7797 section 4: the same payload with and without `b64`, the
/// second detached because its payload has a '.' in it.
#[test]
fn test_rfc_7797_examples() {
    let lines = lines(RFC7797);
    let key = key(&block(from(&lines, "4.  Examples"), "represented below as a JSON"));
    let payload = octets(from(&lines, "4.  Examples"), "Payload value");
    assert_eq!(payload, b"$.02");
    let control = Jws::parse(&block(from(&lines, "4.1."), "The complete JWS")).unwrap();
    assert_eq!(jws::verify(&control, Some(&key), false, None).unwrap(), payload);
    let detached = Jws::parse(&block(from(&lines, "4.2."), "The complete JWS")).unwrap();
    assert_eq!(jws::verify(&detached, Some(&key), false, Some(&payload)).unwrap(), payload);
    // Ours, unencoded, gives the same signature: HMAC is deterministic.
    let ours = jws::sign(&payload, &[jws::Signer { key: &key, alg: "HS256",
                                                   protected: Json::object(), header: None }],
                         false).unwrap();
    assert_eq!(ours.signatures[0].signature, detached.signatures[0].signature);
    assert_eq!(ours.signatures[0].protected, detached.signatures[0].protected);
}

// ---------------------------------------------------------------- RFC 7638 --

#[test]
fn test_rfc_7638_thumbprint() {
    let lines = lines(RFC7638);
    let section = from(&lines, "3.1.");
    let key = key(&block(section, "computation for the JWK"));
    assert_eq!(key.thumbprint(), block(section, "JWK SHA-256 Thumbprint value"));
}

// ---------------------------------------------------------------- RFC 8037 --

/// The text between the first pair of double quotes in the paragraph
/// starting at the line containing `phrase`.
fn quoted(lines: &[&str], phrase: &str) -> String {
    let at = lines.iter().position(|l| l.contains(phrase))
        .unwrap_or_else(|| panic!("no phrase {phrase:?}"));
    let paragraph: String = lines[at..].iter().take_while(|l| !l.trim().is_empty())
        .copied().collect::<Vec<_>>().join(" ");
    let start = paragraph.find('"').expect("a quote") + 1;
    paragraph[start..start + paragraph[start..].find('"').expect("its end")].to_string()
}

#[test]
fn test_rfc_8037_ed25519() {
    let lines = lines(RFC8037);
    let private = key(&block(from(&lines, "A.1."), "A.1."));
    let public = key(&block(from(&lines, "A.2."), "This is the public part"));
    assert_eq!(private.to_json(false), public.to_json(false));
    let section = from(&lines, "A.3.");
    assert_eq!(private.thumbprint(), quoted(section, "which results in the base64url"));
    let compact = block(from(&lines, "A.4."), "So the compact serialization");
    let (protected, payload, signature) = split(&compact);
    assert_eq!(signature, hex_dump(from(&lines, "A.4."), "yields the signature (hex)"));
    let input = format!("{protected}.{payload}");
    assert_eq!(jws::sign_input("EdDSA", &private, input.as_bytes()).unwrap(), signature);
    let parsed = Jws::parse(&compact).unwrap();
    assert_eq!(jws::verify(&parsed, Some(&public), false, None).unwrap(),
               b"Example of Ed25519 signing");
    // RFC 9864's fully-specified name is the same signature; the other
    // curve's name is not.
    assert!(jws::verify_input("Ed25519", &public, input.as_bytes(), &signature).unwrap());
    assert!(jws::verify_input("Ed448", &public, input.as_bytes(), &signature).is_err());
}

/// A.6 and A.7: the ephemeral key's public half and the shared Z, from
/// the ephemeral secret and the recipient's public key the appendix
/// gives.
#[test]
fn test_rfc_8037_ecdh() {
    let lines = lines(RFC8037);
    for (section, crv) in [("A.6.", "X25519"), ("A.7.", "X448")] {
        let section = from(&lines, section);
        let secret = hex_dump(section, "The ephemeral secret happens to be");
        let public = hex_dump(section, "So the ephemeral public key is");
        let z = hex_dump(section, "the sender computes the DH Z value");
        assert_eq!(z, hex_dump(section, "The receiver computes the DH Z value"));
        let recipient = key(&block(section, "The public key to encrypt to"));
        let mut json = Json::object();
        json.set("kty", Json::string("OKP"));
        json.set("crv", Json::string(crv));
        json.set("x", Json::string(&b64(&public)));
        json.set("d", Json::string(&b64(&secret)));
        let ephemeral = Jwk::parse(&json).expect("the secret's public half is the appendix's");
        assert_eq!(ephemeral.to_json(false),
                   key(&block(section, "ephemeral public key value")).to_json(false));
        assert_eq!(jwe::agree(&ephemeral, &recipient).unwrap(), z, "{crv}");
    }
}

// ---------------------------------------------------------------- RFC 7518 --

/// Appendix B: the three CBC-HMAC compositions, from K, P, IV and A to
/// E and T.
#[test]
fn test_rfc_7518_cbc_hmac() {
    let lines = lines(RFC7518);
    for (section, enc) in [("B.1.", "A128CBC-HS256"), ("B.2.", "A192CBC-HS384"),
                           ("B.3.", "A256CBC-HS512")] {
        let section = from(&lines, section);
        let field = |name| hex_field(section, name);
        let jwe::Sealed { iv, ciphertext, tag } =
            jwe::seal(enc, &field("K"), &field("A"), &field("P"), Some(&field("IV"))).unwrap();
        assert_eq!((iv.clone(), ciphertext.clone(), tag.clone()),
                   (field("IV"), field("E"), field("T")), "{enc}");
        assert_eq!(jwe::open(enc, &field("K"), &field("A"), &iv, &ciphertext, &tag).unwrap(),
                   field("P"));
        let mut changed = tag.clone();
        changed[0] ^= 1;
        assert!(jwe::open(enc, &field("K"), &field("A"), &iv, &ciphertext, &changed).is_err());
    }
}

/// Appendix C: ECDH-ES between the two keys it gives, then the Concat
/// KDF with its party information, to its derived key.
#[test]
fn test_rfc_7518_ecdh_es() {
    let lines = lines(RFC7518);
    let section = from(&lines, "Appendix C.");
    let alice = key(&block(section, "Alice's ephemeral key (in JWK format)"));
    let bob = key(&block(section, "The consumer's (Bob's) key"));
    let header = crate::json::parse(&block(section, "public key value to the consumer")).unwrap();
    let z = octets(section, "example, Z is following the octet sequence");
    let derived = block(section, "The base64url-encoded representation of this derived key");
    let cek = jwe::unwrap(&header, &Secret::Key(&bob), "A128GCM", &[], 1).unwrap().unwrap();
    assert_eq!(b64(&cek), derived);
    // And from Alice's side: her private key and Bob's public one.
    let mut from_alice = header.clone();
    from_alice.set("epk", bob.to_json(false));
    assert_eq!(jwe::unwrap(&from_alice, &Secret::Key(&alice), "A128GCM", &[], 1).unwrap(),
               Some(cek.clone()));
    assert_eq!(jwe::concat_kdf(&z, "A128GCM", b"Alice", b"Bob", 16), cek);
}

// ---------------------------------------------------------------- RFC 7516 --

/// A.1 to A.3, compact: RSA-OAEP with A256GCM, RSA1_5 with
/// A128CBC-HS256, A128KW with A128CBC-HS256 - each decrypted with the
/// appendix's key to the appendix's plaintext. A.4 and A.5: the two
/// recipient general serialization and the flattened one.
#[test]
fn test_rfc_7516_examples() {
    let lines = lines(RFC7516);
    let mut keys = Vec::new();
    for section in ["A.1.", "A.2.", "A.3."] {
        let section = from(&lines, section);
        let plaintext = octets(section, "of this plaintext (using JSON array notation)");
        let key = key(&block(section, "represented in JSON Web Key"));
        let compact = block(section, "The final result in this example");
        let parsed = Jwe::parse(&compact).unwrap();
        assert_eq!(jwe::decrypt(&parsed, &Secret::Key(&key), 1).unwrap(), plaintext);
        // The tag covers the protected header: change one character of it.
        let mut changed = parsed;
        changed.protected.insert(changed.protected.len() - 2, 'X');
        assert!(jwe::decrypt(&changed, &Secret::Key(&key), 1).is_err());
        keys.push((key, plaintext));
    }
    let general = Jwe::parse(&block(from(&lines, "A.4.7."), "The complete JWE JSON")).unwrap();
    let flattened = Jwe::parse(&block(from(&lines, "A.5."), "The complete JWE JSON")).unwrap();
    assert_eq!(general.recipients.len(), 2);
    for (key, plaintext) in &keys[1..] {
        assert_eq!(&jwe::decrypt(&general, &Secret::Key(key), 1).unwrap(), plaintext);
    }
    let (kw, plaintext) = &keys[2];
    assert_eq!(&jwe::decrypt(&flattened, &Secret::Key(kw), 1).unwrap(), plaintext);
    // A.1's RSA-OAEP key unwraps nothing in A.4: the wrong recipient.
    assert!(jwe::decrypt(&general, &Secret::Key(&keys[0].0), 1).is_err());
}
