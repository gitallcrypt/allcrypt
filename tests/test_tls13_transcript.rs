//! TLS 1.3, against a handshake that really happened.
//!
//! `tests/transcripts/handshakes.txt` holds a complete TLS 1.3 handshake
//! between two instances of Python's `ssl` over memory BIOs, together with
//! the four traffic secrets from `SSLKEYLOGFILE`. Regenerate with
//! `scripts/capture_transcripts.py`.
//!
//! That makes this the test the unit tests cannot be. Everything in
//! `keys13.rs` and `record13.rs` produces output that is self-consistent
//! when it is wrong - a mistyped label prefix, a nonce XORed at the wrong
//! offset, an AAD built from the plaintext length - and every one of those
//! decrypts its own records perfectly. Here the records were encrypted by
//! OpenSSL, so the only way to read them is to have got all of it right:
//!
//!   * `HKDF-Expand-Label` with the `"tls13 "` prefix and the length byte
//!     that counts it, since `key` and `iv` come out of it;
//!   * the nonce as the static IV XOR the sequence number in its last
//!     eight bytes;
//!   * the AAD as the five byte wire header with the *fragment's* length;
//!   * the padding stripped by scanning back for the content type;
//!   * the sequence number starting at zero for each epoch.
//!
//! And then the messages inside have to parse: EncryptedExtensions, a
//! Certificate in the 1.3 shape with per-entry extensions, a
//! CertificateVerify, and a Finished.

use allcrypt::tls::handshake::{HandshakeReader, HandshakeType};
use allcrypt::tls::handshake13::{Certificate13, CertificateVerify, EncryptedExtensions};
// `NONCE_LEN` is twelve, which is right for every AEAD in these
// captures - they are OpenSSL AES-GCM and ChaCha20-Poly1305 sessions.
// RFC 9367's suites are the ones whose IV is a different length, and
// nothing here can capture one: gost-engine reaches TLS 1.2's GOST
// suites - `tests/test_gost_transcript.rs` has five of those, captured
// from it - and implements none of RFC 9367's TLS 1.3 ones. Those stay
// on RFC 9367's own worked flights, replayed by
// `tests/test_rfc9367_flight.rs`.
use allcrypt::tls::keys13::{TrafficKeys, NONCE_LEN};
use allcrypt::tls::record::RecordReader;
use allcrypt::tls::record13::Aead13;
use allcrypt::tls::ContentType;

mod fixture {
    include!("transcripts/loader.rs");
}
use fixture::{load, Transcript};

/// The captured TLS 1.3 session.
///
/// A panic rather than a skip. A skip here would be a test that passes
/// while checking nothing, which is the failure mode this project keeps
/// finding - and the fixture is committed, so its absence is a mistake
/// rather than a machine that cannot do TLS 1.3.
fn session() -> Transcript {
    load().into_iter().find(|t| t.version == "TLSv1.3")
        .expect("tests/transcripts/handshakes.txt has no TLS 1.3 handshake; \
                 rerun scripts/capture_transcripts.py")
}

fn secret(capture: &Transcript, label: &str) -> Vec<u8> {
    let text = capture.secrets.iter()
        .find(|(name, _, _)| name == label)
        .unwrap_or_else(|| panic!("the capture has no {}", label))
        .2.clone();
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The suite the capture negotiated, as (AEAD name, hash, key length).
///
/// Read from the capture rather than assumed: the fixture is regenerated
/// by whatever OpenSSL is to hand, and a test that hard-coded one suite
/// would start silently checking nothing the day that changed.
fn suite(capture: &Transcript) -> (&'static str, &'static str, usize) {
    match capture.cipher.as_str() {
        "TLS_AES_128_GCM_SHA256" => ("aes-gcm", "sha256", 16),
        "TLS_AES_256_GCM_SHA384" => ("aes-gcm", "sha384", 32),
        "TLS_CHACHA20_POLY1305_SHA256" => ("chacha20-poly1305", "sha256", 32),
        other => panic!("the capture negotiated {}, which this test does not \
                         know how to key", other),
    }
}

/// Every record in one direction, framed but not decrypted.
fn frame(bytes: &[u8]) -> Vec<(ContentType, Vec<u8>)> {
    let mut reader = RecordReader::new();
    reader.push_incoming(bytes);
    let mut records = Vec::new();
    while let Some(record) = reader.read().expect("framing a real transcript") {
        records.push((record.content_type, record.payload));
    }
    assert_eq!(reader.buffered(), 0, "a trailing partial record");
    records
}

/// Decrypt the server's flight with the *real* handshake traffic secret.
///
/// This is the whole point of the file. The secret came out of OpenSSL's
/// key log; everything between it and the plaintext is ours.
#[test]
fn test_the_servers_handshake_flight_decrypts_under_the_real_secret() {
    let capture = session();
    let (aead, hash, key_len) = suite(&capture);
    let keys = TrafficKeys::derive(hash, &secret(&capture, "SERVER_HANDSHAKE_TRAFFIC_SECRET"),
                                   key_len, NONCE_LEN)
        .expect("derive traffic keys");
    let mut state = Aead13::new(aead, hash_static(hash), keys, 16)
        .expect("build the record protection");

    let mut messages = Vec::new();
    for (content_type, fragment) in frame(&capture.to_client) {
        match content_type {
            // Before the keys start, and the middlebox compatibility
            // ChangeCipherSpec. Neither is protected.
            ContentType::Handshake | ContentType::ChangeCipherSpec => continue,
            ContentType::ApplicationData => {
                let (inner_type, plaintext) = match state.decrypt(&fragment) {
                    Ok(pair) => pair,
                    // The flight ends where the application keys begin;
                    // records past that point are under a different
                    // secret and are not this test's business.
                    Err(_) => break,
                };
                assert_eq!(inner_type, ContentType::Handshake,
                           "the server's flight is handshake messages");
                messages.extend_from_slice(&plaintext);
            }
            other => panic!("unexpected record type {:?}", other),
        }
    }

    assert!(!messages.is_empty(),
            "nothing decrypted - the key schedule or the record layer is wrong");

    // And the bytes that came out have to be real handshake messages.
    let mut reader = HandshakeReader::new();
    reader.push(&messages);
    let mut seen = Vec::new();
    while let Some(message) = reader.next_message().expect("a decrypted handshake message") {
        match message.message_type {
            HandshakeType::EncryptedExtensions => {
                EncryptedExtensions::parse(&message.body)
                    .expect("EncryptedExtensions");
            }
            HandshakeType::Certificate => {
                let chain = Certificate13::parse(&message.body)
                    .expect("a TLS 1.3 Certificate message");
                assert!(!chain.entries.is_empty(), "an empty chain");
                assert!(chain.request_context.is_empty(),
                        "a server's Certificate has no request context");
                // Each entry must be a certificate our X.509 parser reads.
                for der in chain.chain() {
                    allcrypt::x509::Certificate::parse(&der)
                        .expect("a certificate from a real server");
                }
            }
            HandshakeType::CertificateVerify => {
                CertificateVerify::parse(&message.body).expect("CertificateVerify");
            }
            HandshakeType::Finished => {}
            other => panic!("unexpected message {} in the server's flight",
                            other.name()),
        }
        seen.push(message.message_type);
    }
    assert_eq!(reader.buffered(), 0, "a trailing partial message");

    // The order is fixed by RFC 8446 section 4.
    assert_eq!(seen, vec![HandshakeType::EncryptedExtensions,
                          HandshakeType::Certificate,
                          HandshakeType::CertificateVerify,
                          HandshakeType::Finished],
               "the server's flight is not in the order the RFC gives");
}

/// The application data the capture sent after the handshake, under the
/// client's application traffic secret.
///
/// A separate epoch, so the sequence number starts at zero again. A record
/// layer that carried the handshake count across would compute a nonce
/// nothing else uses, and nothing on this side would notice.
#[test]
fn test_the_application_data_decrypts_under_its_own_epoch() {
    let capture = session();
    let (aead, hash, key_len) = suite(&capture);
    let keys = TrafficKeys::derive(hash, &secret(&capture, "CLIENT_TRAFFIC_SECRET_0"),
                                   key_len, NONCE_LEN)
        .expect("derive traffic keys");
    let mut state = Aead13::new(aead, hash_static(hash), keys, 16).unwrap();

    // The client's own handshake flight comes first under the *handshake*
    // secret, so the application records are the ones at the end. Try each
    // in turn and keep what the application keys can read.
    let mut found = Vec::new();
    for (content_type, fragment) in frame(&capture.to_server) {
        if content_type != ContentType::ApplicationData {
            continue;
        }
        // A fresh state per attempt: a failed decrypt still consumed a
        // sequence number, and the real epoch starts at zero.
        let mut attempt = Aead13::new(
            aead, hash_static(hash),
            TrafficKeys::derive(hash, &secret(&capture, "CLIENT_TRAFFIC_SECRET_0"),
                                key_len, NONCE_LEN).unwrap(), 16).unwrap();
        if let Ok((inner_type, plaintext)) = attempt.decrypt(&fragment) {
            if inner_type == ContentType::ApplicationData {
                found.push(plaintext);
                // Once the right record is located, carry on with the
                // sequential state so the counter is exercised properly.
                let _ = state.decrypt(&fragment);
            }
        }
    }

    assert_eq!(found.len(), 1, "expected exactly one application data record");
    assert_eq!(found[0], b"hello from the client",
               "the capture writes this string after the handshake");
}

/// The handshake secret must not read the application epoch, and vice
/// versa. Both are 32 or 48 bytes of pseudorandom data derived the same
/// way, so a schedule that used one label where the other belonged would
/// look entirely healthy.
#[test]
fn test_the_two_epochs_do_not_read_each_other() {
    let capture = session();
    let (aead, hash, key_len) = suite(&capture);

    let handshake_record = frame(&capture.to_client).into_iter()
        .filter(|(content_type, _)| *content_type == ContentType::ApplicationData)
        .map(|(_, fragment)| fragment)
        .next()
        .expect("the server's flight has a protected record");

    let wrong = TrafficKeys::derive(hash, &secret(&capture, "SERVER_TRAFFIC_SECRET_0"),
                                    key_len, NONCE_LEN).unwrap();
    let mut state = Aead13::new(aead, hash_static(hash), wrong, 16).unwrap();
    assert!(state.decrypt(&handshake_record).is_err(),
            "the application secret read a handshake record");
}

/// `Aead13` wants a `&'static str` for the hash, so the name from `suite`
/// has to be one.
fn hash_static(name: &str) -> &'static str {
    match name {
        "sha256" => "sha256",
        "sha384" => "sha384",
        other => panic!("unexpected hash {}", other),
    }
}
