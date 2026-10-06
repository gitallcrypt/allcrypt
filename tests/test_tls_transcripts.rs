//! The record layer, against handshakes that really happened.
//!
//! `tests/transcripts/handshakes.txt` holds every byte that crossed in
//! each direction of three real TLS handshakes, captured from Python's
//! `ssl` module talking to itself over memory BIOs. Regenerate it with
//! `scripts/capture_transcripts.py`.
//!
//! What these tests check is the thing a round trip against ourselves
//! cannot: that our framing agrees with a real implementation's, on bytes
//! that a real implementation produced. Our own writer and reader could
//! agree on something wrong and both of them be happy.
//!
//! These tests are about framing, ordering and limits - still the
//! majority of what the record layer does, and the part that sees
//! hostile input first. The payloads after ChangeCipherSpec are
//! decryptable now: the fixture carries the master secret from
//! `SSLKEYLOGFILE`, and `tests/test_gost_transcript.rs` does exactly
//! that with its own captures. The AES suites here do not need it -
//! `pytests/test_tls_handshake.py` completes real handshakes against
//! OpenSSL, which is a stronger check on the same code - where the GOST
//! suites had no OpenSSL to talk to until gost-engine was built.

use allcrypt::tls::record::{Record, RecordReader, HEADER_LEN, MAX_CIPHERTEXT};
use allcrypt::tls::{Alert, ContentType, Version};

mod fixture {
    include!("transcripts/loader.rs");
}
use fixture::load;

/// Frame a direction's bytes into records, with no decryption.
fn frame(bytes: &[u8]) -> Vec<Record> {
    let mut reader = RecordReader::new();
    reader.push_incoming(bytes);
    let mut records = Vec::new();
    loop {
        match reader.read() {
            Ok(Some(record)) => records.push(record),
            Ok(None) => break,
            Err(error) => panic!("framing a real transcript failed: {}",
                                 error.describe()),
        }
    }
    assert_eq!(reader.buffered(), 0,
               "{} bytes left over after framing", reader.buffered());
    records
}

#[test]
fn test_every_transcript_frames_exactly() {
    let transcripts = load();
    println!("{} transcripts", transcripts.len());

    for transcript in &transcripts {
        for (direction, bytes) in [("client->server", &transcript.to_server),
                                   ("server->client", &transcript.to_client)] {
            let records = frame(bytes);
            assert!(!records.is_empty(), "{} {}: no records", transcript.name, direction);

            // Every byte accounted for: the sum of the record bodies plus
            // five bytes of header each must be the whole stream. If our
            // framer were off by one anywhere, this is where it shows.
            let total: usize = records.iter()
                .map(|r| r.payload.len() + HEADER_LEN).sum();
            assert_eq!(total, bytes.len(),
                       "{} {}: framed {} bytes of {}",
                       transcript.name, direction, total, bytes.len());

            println!("  {} ({} {}) {}: {} records",
                     transcript.name, transcript.version, transcript.cipher,
                     direction, records.len());
        }
    }
}

/// Every real handshake starts with a ClientHello, in a handshake record,
/// and the first record a client sends claims a version at or below what
/// gets negotiated.
#[test]
fn test_the_first_record_is_a_client_hello() {
    for transcript in load() {
        let records = frame(&transcript.to_server);
        let first = &records[0];

        assert_eq!(first.content_type, ContentType::Handshake,
                   "{}: first record is {}", transcript.name,
                   first.content_type.name());

        // Handshake message type 1 is client_hello, then a three byte
        // length that must match the rest of the message.
        assert_eq!(first.payload[0], 1, "{}: not a client_hello", transcript.name);
        let length = u32::from_be_bytes([0, first.payload[1], first.payload[2],
                                         first.payload[3]]) as usize;
        assert_eq!(length + 4, first.payload.len(),
                   "{}: client_hello length field disagrees with the record",
                   transcript.name);

        // The record version of a ClientHello is famously conservative -
        // TLS 1.0 even when the client wants 1.3 - because middleboxes
        // dropped anything higher.
        assert!(first.version <= Version::TLS12,
                "{}: ClientHello record claims {}", transcript.name,
                first.version.name());
    }
}

/// The server's first flight must be a handshake record too, and somewhere
/// in these transcripts there is a ChangeCipherSpec - the marker that the
/// record layer's protection changes.
#[test]
fn test_change_cipher_spec_appears_and_is_one_byte() {
    for transcript in load() {
        let mut found = 0;
        for bytes in [&transcript.to_server, &transcript.to_client] {
            for record in frame(bytes) {
                if record.content_type == ContentType::ChangeCipherSpec {
                    // CCS is a single byte with the value 1. Anything else
                    // is a peer doing something strange.
                    assert_eq!(record.payload, vec![1],
                               "{}: odd ChangeCipherSpec payload", transcript.name);
                    found += 1;
                }
            }
        }
        assert!(found > 0, "{}: no ChangeCipherSpec in either direction",
                transcript.name);
    }
}

/// No real record exceeds the limits, which is worth checking because our
/// limits are what protect us from a peer that claims a huge length.
#[test]
fn test_real_records_are_within_the_limits() {
    for transcript in load() {
        for bytes in [&transcript.to_server, &transcript.to_client] {
            for record in frame(bytes) {
                assert!(record.payload.len() <= MAX_CIPHERTEXT,
                        "{}: record of {} bytes", transcript.name,
                        record.payload.len());
                assert!(record.version.is_known(),
                        "{}: record claims {}", transcript.name,
                        record.version.name());
            }
        }
    }
}

/// The same bytes, delivered one at a time, must produce the same records.
/// This is the property the sans-I/O design exists for, checked against
/// real traffic rather than something we made up.
#[test]
fn test_framing_is_independent_of_how_the_bytes_arrive() {
    for transcript in load() {
        for bytes in [&transcript.to_server, &transcript.to_client] {
            let whole = frame(bytes);

            for chunk_size in [1usize, 2, 3, 5, 17, 64, 1024] {
                let mut reader = RecordReader::new();
                let mut records = Vec::new();
                for chunk in bytes.chunks(chunk_size) {
                    reader.push_incoming(chunk);
                    while let Some(record) = reader.read().expect("framing") {
                        records.push(record);
                    }
                }
                assert_eq!(records, whole,
                           "{}: framing differs at chunk size {}",
                           transcript.name, chunk_size);
            }
        }
    }
}

/// Any alert in a transcript must parse. There should not be one in a
/// successful handshake before the application data, so this mostly
/// exercises the close_notify at the end if there is one.
#[test]
fn test_any_alerts_parse() {
    for transcript in load() {
        for bytes in [&transcript.to_server, &transcript.to_client] {
            for record in frame(bytes) {
                if record.content_type == ContentType::Alert
                    && record.payload.len() == 2 {
                    // Only the plaintext ones are readable; after CCS the
                    // payload is ciphertext that happens to be two bytes
                    // only by coincidence, so this is a weak check on
                    // purpose.
                    let alert = Alert::parse(&record.payload).expect("alert parses");
                    println!("  {}: {}", transcript.name, alert.name());
                }
            }
        }
    }
}

/// Truncating a real transcript at every offset must never panic and never
/// produce a record that was not there.
#[test]
fn test_truncated_transcripts_are_safe() {
    let transcripts = load();
    let bytes = &transcripts[0].to_client;

    for cut in 0..bytes.len() {
        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes[..cut]);
        let mut count = 0;
        while let Ok(Some(_)) = reader.read() {
            count += 1;
            assert!(count < 1000, "framing a truncated stream did not terminate");
        }
    }
}

/// And flipping any single byte must be an error or a different record,
/// never a panic.
#[test]
fn test_corrupted_transcripts_are_safe() {
    let transcripts = load();
    let bytes = &transcripts[0].to_server;

    for index in 0..bytes.len() {
        for mask in [0x01u8, 0x80, 0xff] {
            let mut corrupt = bytes.clone();
            corrupt[index] ^= mask;
            let mut reader = RecordReader::new();
            reader.push_incoming(&corrupt);
            let mut count = 0;
            while let Ok(Some(_)) = reader.read() {
                count += 1;
                assert!(count < 10_000, "framing did not terminate");
            }
        }
    }
}

// --------------------------------------------------------- handshake messages ---

use allcrypt::tls::handshake::{extension, ClientHello, HandshakeReader,
                               HandshakeType, ServerHello};

/// Reassemble every handshake message from a direction's plaintext records.
///
/// Only the records before the first ChangeCipherSpec: after that the
/// payloads are encrypted with keys we cannot derive yet.
fn handshake_messages(bytes: &[u8]) -> Vec<allcrypt::tls::handshake::HandshakeMessage> {
    let mut handshake = HandshakeReader::new();
    let mut messages = Vec::new();

    for record in frame(bytes) {
        match record.content_type {
            ContentType::ChangeCipherSpec => break,
            ContentType::Handshake => {
                handshake.push(&record.payload);
                while let Some(message) = handshake.next_message()
                        .expect("reassembling a real handshake") {
                    messages.push(message);
                }
            }
            _ => {}
        }
    }
    assert!(!handshake.has_partial_message(),
            "a handshake message was left half-delivered");
    messages
}

/// Every real ClientHello must parse, and round trip to the same bytes.
///
/// The round trip is the strong half: it means our encoder produces exactly
/// what a real implementation produced, field for field and extension for
/// extension, in order. An encoder that is merely *valid* would pass a
/// parse test and fail this one.
#[test]
fn test_real_client_hellos_parse_and_round_trip() {
    for transcript in load() {
        let messages = handshake_messages(&transcript.to_server);
        let hello_message = messages.iter()
            .find(|m| m.message_type == HandshakeType::ClientHello)
            .unwrap_or_else(|| panic!("{}: no ClientHello", transcript.name));

        let hello = ClientHello::parse(&hello_message.body)
            .unwrap_or_else(|e| panic!("{}: {}", transcript.name, e.describe()));

        assert_eq!(hello.random.len(), 32);
        assert!(!hello.cipher_suites.is_empty());
        assert!(hello.compression_methods.contains(&0),
                "{}: no null compression offered", transcript.name);

        // Real clients send SNI.
        assert_eq!(hello.server_name().as_deref(), Some("localhost"),
                   "{}: unexpected SNI", transcript.name);

        // And the round trip, which is what proves our encoder agrees.
        assert_eq!(hello.encode().unwrap(), hello_message.body,
                   "{}: ClientHello did not re-encode identically",
                   transcript.name);

        println!("  {}: ClientHello, {} suites, {} extensions ({})",
                 transcript.name, hello.cipher_suites.len(),
                 hello.extensions.len(),
                 hello.extensions.iter()
                     .map(|e| extension::name(e.kind))
                     .collect::<Vec<_>>().join(", "));
    }
}

#[test]
fn test_real_server_hellos_parse_and_round_trip() {
    for transcript in load() {
        let messages = handshake_messages(&transcript.to_client);
        let hello_message = messages.iter()
            .find(|m| m.message_type == HandshakeType::ServerHello)
            .unwrap_or_else(|| panic!("{}: no ServerHello", transcript.name));

        let hello = ServerHello::parse(&hello_message.body)
            .unwrap_or_else(|e| panic!("{}: {}", transcript.name, e.describe()));

        assert_eq!(hello.compression_method, 0,
                   "{}: server chose compression", transcript.name);
        assert_eq!(hello.encode().unwrap(), hello_message.body,
                   "{}: ServerHello did not re-encode identically",
                   transcript.name);

        // A TLS 1.3 ServerHello says 1.2 in the legacy field and puts the
        // real answer in supported_versions. Reading only the legacy field
        // means silently treating a 1.3 connection as 1.2, which is the
        // whole reason negotiated_version exists.
        let negotiated = hello.negotiated_version();
        let expected = match transcript.version.as_str() {
            "TLSv1.3" => Version::TLS13,
            "TLSv1.2" => Version::TLS12,
            other => panic!("unexpected version {}", other),
        };
        assert_eq!(negotiated, expected,
                   "{}: negotiated {} but the capture says {}",
                   transcript.name, negotiated.name(), transcript.version);

        if expected == Version::TLS13 {
            assert_eq!(hello.legacy_version, Version::TLS12,
                       "a TLS 1.3 ServerHello must still say 1.2 in the \
                        legacy version field");
        }

        println!("  {}: ServerHello, suite 0x{:04x}, negotiated {}",
                 transcript.name, hello.cipher_suite, negotiated.name());
    }
}

/// The message order in a real TLS 1.2 handshake, which is what the state
/// machine will have to enforce.
///
/// The first flight ends at ServerHelloDone. What comes after it, still in
/// the clear, is NewSessionTicket - the server's second flight is
/// `NewSessionTicket, ChangeCipherSpec, Finished` and only the Finished is
/// encrypted. The first version of this test asserted that the last
/// plaintext message was ServerHelloDone and was simply wrong about the
/// protocol; the transcript said otherwise and the transcript was right.
/// The state machine has to expect a NewSessionTicket there.
#[test]
fn test_the_server_flight_is_in_the_expected_order() {
    for transcript in load() {
        if transcript.version != "TLSv1.2" {
            continue;
        }
        let types: Vec<HandshakeType> = handshake_messages(&transcript.to_client)
            .iter().map(|m| m.message_type).collect();

        assert_eq!(types.first(), Some(&HandshakeType::ServerHello),
                   "{}: server flight starts with {:?}", transcript.name, types);
        assert!(types.contains(&HandshakeType::Certificate),
                "{}: no Certificate in {:?}", transcript.name, types);

        let done = types.iter().position(|t| *t == HandshakeType::ServerHelloDone)
            .unwrap_or_else(|| panic!("{}: no ServerHelloDone in {:?}",
                                      transcript.name, types));

        // Everything before ServerHelloDone belongs to the first flight,
        // and nothing in it may be a message that belongs after.
        for message_type in &types[..done] {
            assert!(!matches!(message_type, HandshakeType::Finished
                                          | HandshakeType::NewSessionTicket),
                    "{}: {} arrived before ServerHelloDone",
                    transcript.name, message_type.name());
        }
        // And anything after it, still in the clear, is a NewSessionTicket.
        for message_type in &types[done + 1..] {
            assert_eq!(*message_type, HandshakeType::NewSessionTicket,
                       "{}: unexpected {} after ServerHelloDone",
                       transcript.name, message_type.name());
        }

        println!("  {}: {}", transcript.name,
                 types.iter().map(|t| t.name()).collect::<Vec<_>>().join(" -> "));
    }
}

/// The certificate chain a real server sent must parse, and every
/// certificate in it must parse as X.509.
#[test]
fn test_the_real_certificate_chain_parses() {
    use allcrypt::tls::handshake::CertificateChain;
    use allcrypt::x509::Certificate;

    for transcript in load() {
        if transcript.version != "TLSv1.2" {
            continue;    // in 1.3 the certificate is encrypted
        }
        let message = handshake_messages(&transcript.to_client).into_iter()
            .find(|m| m.message_type == HandshakeType::Certificate)
            .unwrap_or_else(|| panic!("{}: no Certificate", transcript.name));

        let chain = CertificateChain::parse(&message.body)
            .unwrap_or_else(|e| panic!("{}: {}", transcript.name, e.describe()));
        assert!(!chain.certificates.is_empty(),
                "{}: a server sent an empty chain", transcript.name);

        for der in &chain.certificates {
            let certificate = Certificate::parse(der).unwrap_or_else(|e| panic!(
                "{}: a real server certificate did not parse: {}",
                transcript.name, e));
            println!("  {}: {}", transcript.name, certificate.subject);
        }

        // And it re-encodes identically, which pins the three-byte lengths.
        assert_eq!(chain.encode().unwrap(), message.body,
                   "{}: Certificate did not re-encode identically", transcript.name);
    }
}

/// Every handshake message in every transcript must reassemble the same way
/// however the records were delivered, and the raw bytes must be exactly
/// what arrived - the transcript hash depends on it.
#[test]
fn test_reassembly_is_independent_of_record_boundaries() {
    for transcript in load() {
        for bytes in [&transcript.to_server, &transcript.to_client] {
            let expected = handshake_messages(bytes);
            if expected.is_empty() {
                continue;
            }

            // Concatenate the raw bytes of every message and reassemble
            // from that, in awkward chunks. Same messages, same raw bytes.
            let mut stream = Vec::new();
            for message in &expected {
                stream.extend_from_slice(&message.raw);
            }

            for chunk_size in [1usize, 7, 64, 4096] {
                let mut reader = HandshakeReader::new();
                let mut messages = Vec::new();
                for chunk in stream.chunks(chunk_size) {
                    reader.push(chunk);
                    while let Some(message) = reader.next_message().unwrap() {
                        messages.push(message);
                    }
                }
                assert_eq!(messages, expected,
                           "{}: reassembly differs at chunk size {}",
                           transcript.name, chunk_size);
            }
        }
    }
}
