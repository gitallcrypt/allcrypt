/*
RFC 9189's own handshake, replayed at our client.

`tests/test_gost_handshake.rs` next door runs the client against a
server written here, and says so about itself: a misreading shared by
both ends round trips perfectly. This file is the other half of that
question. Appendix A.2.2 of RFC 9189 prints an entire
TLS_GOSTR341112_256_WITH_28147_CNT_IMIT handshake - every record, in
hex, as it went over a wire between two implementations that are not
ours - and the server's flight from it is fed to a `ClientConnection`
here. Nothing in it was chosen by us: not the session id, not the
extensions, not the certificate, not the curve it is on.

**What this is for.** A report came in of a server offering 0xC102
where, after the ServerHello, the client sent FIN and nothing else.
The proxy's part of that is fixed elsewhere - the alert was being
built and dropped - but "does our client accept what a real GOST
server actually sends" is a question our own server cannot answer,
because it sends what we thought it would send. The RFC's bytes can.

**What it cannot check.** The client's ephemeral key is drawn fresh,
so our ClientKeyExchange is not the document's and the Finished
messages cannot match. The flight up to ServerHelloDone is entirely
determined by the server, though, and that is the flight the report is
about. The pieces after it - the PMS, the key export, the key block -
are checked against this same appendix in `src/tls/gost_kex_28147.rs`
and `src/tls/keys.rs`, where the inputs can be pinned.

The bytes are parsed out of the document at test time rather than
transcribed, for the reason in docs/extending.md ("Where test vectors
come from"): a vector typed into a source file is a vector that was
typed. The parser asserts what it found.
*/

use allcrypt::tls::client::{ClientConfig, ClientConnection};
use allcrypt::tls::suites::Selection;
use allcrypt::tls::Version;
use allcrypt::trust::TrustStore;

/// The document.
const RFC9189: &str = include_str!("../rfcs/rfc9189.txt");

/// One labelled hex dump out of an appendix.
struct Dump {
    label: String,
    bytes: Vec<u8>,
}

/// Every labelled dump in a section, in the order they are printed.
///
/// The format is a label line ending in a colon, then some fields, then
/// a block of `00000:   16 03 03 ...` lines. A dump is taken to belong
/// to the last label seen before it.
///
/// **Elisions are refused rather than stitched over.** Some dumps in
/// this appendix - the 8 KB ciphertexts in A.1.2 - print the first
/// rows, then `. . .`, then the last, and a parser that just
/// concatenated the rows would produce a shorter value that looked
/// whole. The offset on each row is checked against how much has been
/// collected, and a jump marks the dump as incomplete.
fn dumps_in_section(document: &str, section: &str, until: &str) -> Vec<Dump> {
    // The heading appears twice: once in the table of contents and once
    // where the section is. The one that counts is the last.
    let mut body: Vec<&str> = Vec::new();
    let mut seen = 0;
    let mut collecting = false;
    for line in document.lines() {
        if line.trim_start().starts_with(section) {
            seen += 1;
            body.clear();
            collecting = true;
            continue;
        }
        // **Where the section stops matters as much as where it
        // starts.** Without this, A.1.3.2 ran to the end of the
        // document and swept up A.2.2's records as though they were
        // its own - a Kuznyechik flight with the 28147 one glued to
        // the end of it, which would have been noticed only by the
        // count.
        if collecting && line.trim_start().starts_with(until) {
            collecting = false;
        }
        if collecting {
            body.push(line);
        }
    }
    assert!(seen >= 2, "{} is not in the document twice - the table of \
                        contents and the section itself", section);

    let mut found = Vec::new();
    let mut label = String::new();
    let mut current: Option<(String, Vec<u8>, bool)> = None;

    for line in body {
        match parse_dump_line(line) {
            Some((offset, bytes)) => {
                let entry = current.get_or_insert_with(
                    || (label.clone(), Vec::new(), true));
                if offset != entry.1.len() {
                    // A gap: the document elided the middle.
                    entry.2 = false;
                }
                entry.1.extend_from_slice(&bytes);
            }
            None => {
                if let Some((label, bytes, whole)) = current.take() {
                    if whole {
                        found.push(Dump { label, bytes });
                    }
                }
                if let Some(name) = label_on(line) {
                    label = name;
                }
            }
        }
    }
    if let Some((label, bytes, true)) = current {
        found.push(Dump { label, bytes });
    }
    found
}

/// What a line names, if it names something.
///
/// A label is a line that *ends* with a colon - `Record layer message:`,
/// `PMS:` - with the value on the lines below it. A field line carries
/// its value after the colon (`length:  0051`) and is not a label, so
/// ending with the colon is most of the rule.
///
/// The rest is a stop list, because the message structures are printed
/// as nested fields and the structural ones - `version:`, `body:`,
/// `vector:`, `extensions:` - do end with a colon and name nothing a
/// test would want. Without it the label sitting over a record's dump
/// was `fragment`, every record was filtered out by name, and the test
/// passed by finding nothing to check. That is why the count below is
/// asserted.
fn label_on(line: &str) -> Option<String> {
    const STRUCTURE: &[&str] = &["msg", "length", "type", "version", "major",
                                 "minor", "body", "vector", "extensions",
                                 "fragment"];
    let name = line.trim().strip_suffix(':')?;
    if name.is_empty() || STRUCTURE.iter().any(|field| name.starts_with(field)) {
        return None;
    }
    Some(name.to_string())
}

/// `   00000:   16 03 03 00 51 02 ...`, or nothing.
fn parse_dump_line(line: &str) -> Option<(usize, Vec<u8>)> {
    let (head, tail) = line.trim().split_once(':')?;
    if head.len() != 5 || !head.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let offset = usize::from_str_radix(head, 16).ok()?;
    let mut bytes = Vec::new();
    for word in tail.split_whitespace() {
        if word.len() != 2 || !word.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        bytes.push(u8::from_str_radix(word, 16).ok()?);
    }
    if bytes.is_empty() { None } else { Some((offset, bytes)) }
}

/// The records of A.2.2, in order: every dump labelled "Record layer
/// message".
///
/// The count is asserted because the parser above decides what a label
/// is by looking at punctuation, and a change in how the document is
/// formatted would otherwise silently produce fewer records and a test
/// that checked less.
fn records_of(section: &str, until: &str) -> Vec<Vec<u8>> {
    dumps_in_section(RFC9189, section, until).into_iter()
        // One of these labels is `Record layer message:` rather than
        // `Record layer message` - the document prints that one
        // heading with two colons. Matched by prefix so the typo does
        // not lose a record.
        .filter(|dump| dump.label.starts_with("Record layer message"))
        .map(|dump| dump.bytes)
        .collect()
}

fn cnt_imit_records() -> Vec<Vec<u8>> {
    let records = records_of("A.2.2.", "Authors' Addresses");
    assert_eq!(records.len(), 13,
               "A.2.2 prints thirteen records: the two hellos, the \
                certificate, the ServerHelloDone, the ClientKeyExchange, \
                two ChangeCipherSpecs and two Finisheds, two application \
                data records and two alerts");
    for record in &records {
        assert!(record.len() >= 5 && record[1] == 0x03,
                "a record does not start with a TLS header: {:02x?}",
                &record[..record.len().min(5)]);
    }
    records
}

/// A client set up the way the proxy sets one up for an old box.
///
/// Verification off, because the document's certificate expired in 2022
/// and the question here is what the *handshake* makes of the flight.
/// The proxy does the same and judges the chain afterwards, which is
/// the only way a failure can be reported rather than dropped.
fn client_for_cnt_imit() -> ClientConnection {
    let mut config = ClientConfig::new(TrustStore::new(), 1_600_000_000);
    config.suites = Selection::named(
        &["TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"]).unwrap();
    config.min_version = Version::TLS12;
    config.max_version = Version::TLS12;
    config.verify_certificate = false;
    config.verify_hostname = false;
    let mut connection = ClientConnection::new(config, "localhost").unwrap();
    // The ClientHello, which is ours rather than the document's - the
    // client will not accept a flight it did not ask for.
    connection.take_outgoing();
    connection
}

/// The server's first flight: ServerHello, Certificate, ServerHelloDone.
///
/// Records 1, 2 and 3; record 0 is the client's ClientHello and record
/// 4 is its answer.
fn server_flight(records: &[Vec<u8>]) -> Vec<u8> {
    let mut flight = Vec::new();
    for record in &records[1..=3] {
        flight.extend_from_slice(record);
    }
    flight
}

#[test]
fn test_the_documents_server_flight_is_accepted() {
    let records = cnt_imit_records();
    let mut client = client_for_cnt_imit();
    client.push_incoming(&server_flight(&records));

    client.process().expect(
        "RFC 9189 A.2.2's own server flight was refused by this client. \
         That is the shape of the bug this file was written for: a real \
         GOST server's ServerHello, Certificate and ServerHelloDone, \
         refused after the ServerHello");

    assert_eq!(client.negotiated_suite().map(|suite| suite.code), Some(0xc102),
               "the suite from the document's ServerHello");
    assert_eq!(client.negotiated_version(), Some(Version::TLS12));
    assert_eq!(client.peer_certificates().len(), 1,
               "the one certificate the document's server sent");
}

#[test]
fn test_the_answer_to_that_flight_is_a_key_exchange() {
    // Accepting the flight is not the same as being able to answer it:
    // the answer needs the certificate's key, the curve its parameter
    // set names, and a VKO against it. A client that parsed the flight
    // and then had nothing to say would look identical from outside.
    let records = cnt_imit_records();
    let mut client = client_for_cnt_imit();
    client.push_incoming(&server_flight(&records));
    client.process().expect("the flight");

    let answer = client.take_outgoing();
    assert!(!answer.is_empty(), "the client answered with nothing");

    // ClientKeyExchange, ChangeCipherSpec, Finished - in that order and
    // as separate records, which is what the document shows.
    assert_eq!(answer[0], 0x16, "the answer starts with a handshake record");
    let body_at = 5;
    assert_eq!(answer[body_at], 0x10,
               "the first handshake message of the answer is a \
                ClientKeyExchange (16)");
    assert!(answer.windows(3).any(|window| window == [0x14, 0x03, 0x03]),
            "the answer carries a ChangeCipherSpec");
}

/// A.1.3.2's flight, which is the one with a CertificateRequest in it.
///
/// A GOST server asking for a client certificate is ordinary - the
/// equipment this library exists for often does - and nothing else
/// here exercises it, because the server in
/// `tests/test_gost_handshake.rs` does not ask. The request names
/// certificate types 67 and 68 (`gost_sign256`, `gost_sign512`) and
/// signature algorithms (8, 64) and (8, 65), none of which any other
/// test has seen.
fn ctr_omac_records() -> Vec<Vec<u8>> {
    let records = records_of("A.1.3.2.", "A.2.");
    assert_eq!(records.len(), 16,
               "A.1.3.2 prints sixteen records - three more than A.2.2, \
                being the CertificateRequest and the client's answer to \
                it: a Certificate and a CertificateVerify");
    records
}

#[test]
fn test_a_certificate_request_from_a_real_server_is_answered() {
    // ServerHello, Certificate, CertificateRequest, ServerHelloDone.
    let records = ctr_omac_records();
    let mut config = ClientConfig::new(TrustStore::new(), 1_600_000_000);
    config.suites = Selection::named(
        &["TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"]).unwrap();
    config.min_version = Version::TLS12;
    config.max_version = Version::TLS12;
    config.verify_certificate = false;
    config.verify_hostname = false;
    let mut client = ClientConnection::new(config, "localhost").unwrap();
    client.take_outgoing();

    let mut flight = Vec::new();
    for record in &records[1..=4] {
        flight.extend_from_slice(record);
    }
    client.push_incoming(&flight);
    client.process().expect(
        "RFC 9189 A.1.3.2's server flight, CertificateRequest and all, \
         was refused");

    // We have no GOST client certificate here, so the answer is an
    // empty Certificate message followed by the key exchange - which
    // is what RFC 5246 section 7.4.6 says to send rather than nothing.
    let answer = client.take_outgoing();
    assert_eq!(answer[5], 0x0b,
               "the answer opens with a Certificate message (11), even \
                though it is empty: a client that skips it is refused by \
                servers that asked");
    assert_eq!(&answer[5..9], &[0x0b, 0x00, 0x00, 0x03],
               "an empty certificate_list is three bytes of length");
}

#[test]
fn test_the_documents_certificate_is_a_gost_512_key_we_can_read() {
    // The certificate in this appendix is on
    // id-tc26-gost-3410-12-512-paramSetA, which is not the curve our
    // own test server uses and not one a 256 bit suite would suggest:
    // the suite's hash is Streebog-256 and the key is 512 bits. A
    // reader that assumed the two matched would fail exactly here, and
    // only against a real server.
    let records = cnt_imit_records();
    let mut client = client_for_cnt_imit();
    client.push_incoming(&server_flight(&records));
    client.process().expect("the flight");

    let der = &client.peer_certificates()[0];
    let certificate = allcrypt::x509::Certificate::parse(der)
        .expect("the document's certificate parses");
    match &certificate.public_key {
        allcrypt::x509::PublicKey::Gost { curve, x, y, param_set, legacy, .. } => {
            assert!(!legacy, "the document's certificate is a 2012 one");
            assert!(curve.contains("512"), "curve was {}", curve);
            assert_eq!(x.to_bytes_be().len().max(1), 64, "a 512 bit x");
            assert_eq!(y.to_bytes_be().len().max(1), 64, "a 512 bit y");
            // **The OID as the document wrote it, not the curve's
            // canonical one.** `curve` is a name this library chose and
            // several OIDs map onto it; what has to go back out in a
            // ClientKeyExchange is the OID that came in. This is the
            // one certificate here written by somebody else, so it is
            // the only place that claim can be checked against a third
            // party.
            // `1.2.643.7.1.2.1.2.1` is
            // `id-tc26-gost-3410-12-512-paramSetA`, which is what
            // `curve` reports as `gost512-a`. Read off the document
            // rather than recalled: the first version of this assertion
            // said paramSetC, from a comment about a *different* pair of
            // curves, and the test said so immediately.
            assert_eq!(param_set.to_string(), "1.2.643.7.1.2.1.2.1",
                       "A.1.3.2's parameter set OID");
            assert_eq!(*curve, "gost512-a");
        }
        other => panic!("not a GOST key: {:?}", other),
    }
}
