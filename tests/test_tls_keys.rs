//! The key schedule, against a session that really happened.
//!
//! `scripts/capture_transcripts.py` records the master secret alongside the
//! bytes, the way `SSLKEYLOGFILE` does. That turns the transcript from a
//! framing fixture into something much stronger: our key schedule has to
//! derive a key block that decrypts records Python's `ssl` encrypted, and
//! produce verify_data that matches the Finished a real implementation
//! sent.
//!
//! This is the test that catches the two mistakes a round trip cannot. The
//! randoms go into the master secret client-first and into the key block
//! server-first; the key block splits into both MAC keys, then both
//! encryption keys, then both IVs. Get either wrong consistently and your
//! own code still agrees with itself. It just cannot talk to anything.

use allcrypt::tls::handshake::{extension, find_extension, ClientHello,
                              HandshakeReader, HandshakeType, ServerHello};
use allcrypt::tls::keys::{self, Side, Transcript};
use allcrypt::tls::record::{AeadKeys, CbcHmac, Protection, RecordReader};
use allcrypt::tls::suites;
use allcrypt::tls::{ContentType, Version};

mod fixture {
    include!("transcripts/loader.rs");
}
use fixture::{load, Transcript as Capture};

/// Everything needed to replay one direction of a captured session.
struct Session {
    capture: Capture,
    /// Whether the server agreed to RFC 7366. Real OpenSSL does, by
    /// default, for every CBC suite - which is how this library found out
    /// it needed to implement it.
    encrypt_then_mac: bool,
    client_random: [u8; 32],
    server_random: [u8; 32],
    master: Vec<u8>,
    suite: &'static suites::CipherSuite,
    /// Every record, in order, from each direction.
    to_server: Vec<allcrypt::tls::record::Record>,
    to_client: Vec<allcrypt::tls::record::Record>,
}

fn frame(bytes: &[u8]) -> Vec<allcrypt::tls::record::Record> {
    let mut reader = RecordReader::new();
    reader.push_incoming(bytes);
    let mut records = Vec::new();
    while let Some(record) = reader.read().expect("framing a real capture") {
        records.push(record);
    }
    records
}

/// Rebuild a session from a capture, or `None` if it is not one we can
/// replay. TLS 1.3 has a different key schedule entirely; anything else
/// whose suite is not implemented is skipped by `is_implemented`, so this
/// file picks up new suites as they land rather than having to be told.
fn replayable(capture: Capture) -> Option<Session> {
    if capture.version != "TLSv1.2" {
        return None;
    }

    let to_server = frame(&capture.to_server);
    let to_client = frame(&capture.to_client);

    // The randoms come out of the hellos, not out of the key log - which
    // means this also checks that our parser read them correctly.
    let mut handshake = HandshakeReader::new();
    for record in &to_server {
        if record.content_type == ContentType::Handshake {
            handshake.push(&record.payload);
        } else {
            break;
        }
    }
    let hello = handshake.next_message().ok()??;
    let client_hello = ClientHello::parse(&hello.body).ok()?;

    let mut handshake = HandshakeReader::new();
    for record in &to_client {
        if record.content_type == ContentType::Handshake {
            handshake.push(&record.payload);
        } else {
            break;
        }
    }
    let hello = handshake.next_message().ok()??;
    let server_hello = ServerHello::parse(&hello.body).ok()?;

    let suite = suites::by_code(server_hello.cipher_suite)?;
    if !suite.is_implemented() {
        return None;
    }

    // The key log indexes the master secret by the client random, which is
    // how a capture is matched to a session.
    let wanted = hex(&client_hello.random);
    let master = capture.secrets.iter()
        .find(|(label, random, _)| label == "CLIENT_RANDOM" && *random == wanted)
        .map(|(_, _, secret)| unhex(secret))?;

    let encrypt_then_mac = find_extension(&server_hello.extensions,
                                          extension::ENCRYPT_THEN_MAC).is_some();

    Some(Session {
        encrypt_then_mac,
        client_random: client_hello.random,
        server_random: server_hello.random,
        master,
        suite,
        to_server,
        to_client,
        capture,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// The client's write protection for a session, as the handshake agreed it.
fn client_protection(session: &Session, block: &keys::KeyBlock) -> Protection {
    let cipher = session.suite.cipher.algorithm().expect("cipher name");

    // An AEAD authenticates itself, so there is no MAC key and no separate
    // hash - and the "IV" from the key block is the nonce's fixed half
    // rather than a CBC initialisation vector.
    if session.suite.cipher.is_aead() {
        let state = AeadKeys::new("aes-gcm", &block.client.key, &block.client.iv,
                                  session.suite.cipher.explicit_iv_len(),
                                  session.suite.cipher.tag_len())
            .expect("building the AEAD protection");
        return Protection::Aead(state);
    }

    let hash = session.suite.mac.hash_name().expect("mac name");
    let state = CbcHmac::new(cipher, hash, &block.client.key, &block.client.mac_key,
                             &block.client.iv, Version::TLS12)
        .expect("building the protection");
    Protection::CbcHmac(if session.encrypt_then_mac {
        state.with_encrypt_then_mac()
    } else {
        state
    })
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// At least one capture must be replayable, or this whole file is passing
/// vacuously.
#[test]
fn test_there_is_something_to_replay() {
    let replayable: Vec<Session> = load().into_iter().filter_map(replayable).collect();
    assert!(!replayable.is_empty(),
            "no captured session is replayable - recapture with a suite this \
             library implements, or this file tests nothing");
    for session in &replayable {
        println!("  {} {} 0x{:04x} {}", session.capture.name,
                 session.capture.version, session.suite.code, session.suite.name);
    }
}

/// **The test this file exists for.** Derive the key block from the real
/// master secret and decrypt records that Python's `ssl` encrypted.
///
/// If the randoms go into the key block in the wrong order, or the block
/// splits wrongly, or the MAC input is assembled differently, this fails.
/// Nothing else in the suite would notice any of it.
#[test]
fn test_our_key_block_decrypts_real_records() {
    let mut decrypted_any = false;
    let mut kinds = Vec::new();

    for session in load().into_iter().filter_map(replayable) {
        let block = keys::key_block(Version::TLS12, session.suite, &session.master,
                                    &session.client_random, &session.server_random)
            .expect("deriving the key block");

        // The client's keys protect what went to the server, so that is the
        // direction to read. Records after the ChangeCipherSpec are the
        // encrypted ones.
        let mut reader = RecordReader::new();
        reader.expect_version(Version::TLS12);

        let mut seen_ccs = false;
        let mut payloads = Vec::new();

        for record in &session.to_server {
            if record.content_type == ContentType::ChangeCipherSpec {
                seen_ccs = true;
                // From here the client's records are protected.
                reader.change_cipher_spec(client_protection(&session, &block));
                continue;
            }
            if !seen_ccs {
                continue;
            }

            // Re-frame this one record through a reader that has the keys.
            let mut bytes = Vec::with_capacity(record.payload.len() + 5);
            bytes.push(record.content_type.to_byte());
            bytes.extend_from_slice(&record.version.to_bytes());
            bytes.extend_from_slice(&(record.payload.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&record.payload);

            reader.push_incoming(&bytes);
            let plain = reader.read()
                .unwrap_or_else(|e| panic!(
                    "{}: our keys could not decrypt a real record: {}",
                    session.capture.name, e.describe()))
                .expect("a whole record");
            payloads.push((plain.content_type, plain.payload));
        }

        assert!(!payloads.is_empty(),
                "{}: no protected records to decrypt", session.capture.name);

        // The first protected record from the client is its Finished.
        let (content_type, first) = &payloads[0];
        assert_eq!(*content_type, ContentType::Handshake,
                   "{}: first protected record is not a handshake message",
                   session.capture.name);
        assert_eq!(first[0], HandshakeType::Finished.to_byte(),
                   "{}: first protected message is {} not finished",
                   session.capture.name,
                   HandshakeType::from_byte(first[0]).name());
        assert_eq!(first.len(), 4 + keys::VERIFY_DATA_LEN,
                   "{}: Finished is {} bytes", session.capture.name, first.len());

        // And the application data the capture script sent.
        let application: Vec<&Vec<u8>> = payloads.iter()
            .filter(|(kind, _)| *kind == ContentType::ApplicationData)
            .map(|(_, payload)| payload)
            .collect();
        assert!(application.iter().any(|p| p.as_slice() == b"hello from the client"),
                "{}: the application data did not come back: {:?}",
                session.capture.name,
                application.iter().map(|p| String::from_utf8_lossy(p)).collect::<Vec<_>>());

        println!("  {}: {} real records decrypted with our own key schedule ({})",
                 session.capture.name, payloads.len(), session.suite.name);
        kinds.push(session.suite.cipher.is_aead());
        decrypted_any = true;
    }

    // Both record constructions have to be exercised, not just whichever
    // capture happens to come first. They share almost nothing: one is
    // MAC-then-encrypt with padding, the other is an AEAD with a split
    // nonce and a length field that counts different bytes. A file that
    // silently covered only one of them would look exactly like this one.
    assert!(kinds.iter().any(|aead| *aead),
            "no AEAD session was replayed; the GCM record path is untested here");
    assert!(kinds.iter().any(|aead| !*aead),
            "no CBC session was replayed; the MAC-then-encrypt path is untested here");

    assert!(decrypted_any, "nothing was decrypted");
}

/// The other half: our verify_data must equal the Finished a real
/// implementation computed over the same transcript.
///
/// This checks the transcript hash, the PRF, the label and the truncation
/// all at once - and it is the check that would catch a transcript fed with
/// a re-encoding rather than the bytes that arrived.
#[test]
fn test_our_verify_data_matches_the_real_finished() {
    let mut checked = 0;

    for session in load().into_iter().filter_map(replayable) {
        let block = keys::key_block(Version::TLS12, session.suite, &session.master,
                                    &session.client_random, &session.server_random)
            .expect("key block");

        // Rebuild the transcript from every handshake message before the
        // client's ChangeCipherSpec, in the order they were exchanged.
        //
        // The order is: the client's first flight, then the server's, then
        // the client's second - so the two directions interleave and the
        // transcript is not simply one direction after the other.
        let mut transcript = Transcript::new(Version::TLS12, session.suite.prf)
            .expect("transcript");

        let client_messages = plaintext_messages(&session.to_server);
        let server_messages = plaintext_messages(&session.to_client);

        // ClientHello, then everything the server sent up to
        // ServerHelloDone, then the client's ClientKeyExchange.
        transcript.update(&client_messages[0].1);
        for (message_type, raw) in &server_messages {
            transcript.update(raw);
            if *message_type == HandshakeType::ServerHelloDone {
                break;
            }
        }
        for (message_type, raw) in &client_messages[1..] {
            transcript.update(raw);
            if *message_type == HandshakeType::ClientKeyExchange {
                break;
            }
        }

        let expected = keys::verify_data(Version::TLS12, session.suite,
                                         &session.master, Side::Client,
                                         &transcript.hash())
            .expect("verify_data");

        // Pull the real Finished out by decrypting it, as above.
        let real = real_client_finished(&session, &block);

        assert!(keys::verify_data_matches(&expected, &real),
                "{}: our verify_data is {} but the real Finished carried {}",
                session.capture.name, hex(&expected), hex(&real));

        println!("  {}: verify_data matches the real Finished ({})",
                 session.capture.name, hex(&expected));
        checked += 1;
    }

    assert!(checked > 0, "no session was checked");
}

/// Handshake messages from the plaintext records of one direction.
fn plaintext_messages(records: &[allcrypt::tls::record::Record])
                      -> Vec<(HandshakeType, Vec<u8>)> {
    let mut handshake = HandshakeReader::new();
    let mut messages = Vec::new();
    for record in records {
        match record.content_type {
            ContentType::ChangeCipherSpec => break,
            ContentType::Handshake => {
                handshake.push(&record.payload);
                while let Some(message) = handshake.next_message().expect("reassembly") {
                    messages.push((message.message_type, message.raw));
                }
            }
            _ => {}
        }
    }
    messages
}

/// Decrypt the client's Finished out of a captured session.
fn real_client_finished(session: &Session, block: &keys::KeyBlock) -> Vec<u8> {
    let mut reader = RecordReader::new();
    reader.expect_version(Version::TLS12);
    let mut seen_ccs = false;

    for record in &session.to_server {
        if record.content_type == ContentType::ChangeCipherSpec {
            seen_ccs = true;
            reader.change_cipher_spec(client_protection(session, block));
            continue;
        }
        if !seen_ccs {
            continue;
        }
        let mut bytes = Vec::new();
        bytes.push(record.content_type.to_byte());
        bytes.extend_from_slice(&record.version.to_bytes());
        bytes.extend_from_slice(&(record.payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&record.payload);
        reader.push_incoming(&bytes);

        let plain = reader.read().expect("decrypt").expect("record");
        if plain.content_type == ContentType::Handshake
            && plain.payload[0] == HandshakeType::Finished.to_byte() {
            return plain.payload[4..].to_vec();
        }
    }
    panic!("{}: no Finished found", session.capture.name);
}

/// A master secret that is wrong by one bit must not decrypt anything. This
/// is the control: without it, a test that "decrypts successfully" could be
/// passing because the MAC check is not happening.
#[test]
fn test_a_wrong_master_secret_fails() {
    for session in load().into_iter().filter_map(replayable) {
        let mut wrong = session.master.clone();
        wrong[0] ^= 0x01;

        let block = keys::key_block(Version::TLS12, session.suite, &wrong,
                                    &session.client_random, &session.server_random)
            .expect("key block");

        let mut reader = RecordReader::new();
        reader.expect_version(Version::TLS12);
        let mut seen_ccs = false;
        let mut outcome = None;

        for record in &session.to_server {
            if record.content_type == ContentType::ChangeCipherSpec {
                seen_ccs = true;
                reader.change_cipher_spec(client_protection(&session, &block));
                continue;
            }
            if !seen_ccs {
                continue;
            }
            let mut bytes = Vec::new();
            bytes.push(record.content_type.to_byte());
            bytes.extend_from_slice(&record.version.to_bytes());
            bytes.extend_from_slice(&(record.payload.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&record.payload);
            reader.push_incoming(&bytes);
            outcome = Some(reader.read());
            break;
        }

        let outcome = outcome.expect("a protected record to try");
        assert!(outcome.is_err(),
                "{}: a master secret wrong by one bit still decrypted a record - \
                 the MAC is not being checked", session.capture.name);
    }
}
