/*!
The engine's own ClientKeyExchange, unwrapped under the server's key.

`tests/test_gost_transcript.rs` decrypts the records in
`tests/transcripts/gost_handshakes.txt` from the master secret in the key
log, which settles the record layers and says nothing about how that
master secret was reached. This file settles the other half. Each capture
also records the server's private key, so the ClientKeyExchange that
OpenSSL's client built with gost-engine can be unwrapped here, through
this library's own server-side functions. The premaster that comes out
has to give the master secret in the key log.

Which hash makes the UKM, which VKO runs, and which S-box wraps the
secret are each self-consistent when wrong. A client and server that
share a wrong reading agree with each other, which is why
`tests/test_gost_handshake.rs` cannot decide them. Only somebody else's
ClientKeyExchange can.

The captures that motivated this put a 2012 CNT_IMIT suite on a GOST R
34.10-2001 certificate. OpenSSL serves 0xC102 and 0xFF85 on either
generation of key, and then its client hashes the randoms with the
suite's Streebog-256 while gost-engine runs the key's VKO GOST R
34.10-2001 over CryptoPro-A. This library's client took all three from the
suite and was refused. The server side of the engine reads the UKM out of
the message rather than deriving it, so it would have accepted either
hash; the engine's client is what pins it.
*/

use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, Curve, Point};
use allcrypt::tls::gost_kex_28147::{KeyGeneration, KeyTransportBlob, Transport, UkmHash};
use allcrypt::tls::handshake::{extension, ServerHello};
use allcrypt::tls::suites::{self, CipherSuite, KeyExchange};
use allcrypt::tls::{gost_kex, gost_kex_28147, keys, Version};
use allcrypt::x509::{Certificate, PublicKey};

mod fixture {
    include!("transcripts/loader.rs");
}
use fixture::{load_gost, Transcript};

/// The handshake messages of one direction before its ChangeCipherSpec,
/// whole: type, length and body.
fn handshake_messages(stream: &[u8]) -> Vec<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut index = 0;
    while index + 5 <= stream.len() {
        let kind = stream[index];
        let length = u16::from_be_bytes([stream[index + 3], stream[index + 4]]) as usize;
        let payload = &stream[index + 5..index + 5 + length];
        index += 5 + length;
        match kind {
            0x16 => bytes.extend_from_slice(payload),
            0x14 => break,
            _ => {}
        }
    }
    let mut messages = Vec::new();
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let size = u32::from_be_bytes([0, bytes[at + 1], bytes[at + 2], bytes[at + 3]])
            as usize;
        messages.push(bytes[at..at + 4 + size].to_vec());
        at += 4 + size;
    }
    messages
}

/// Everything one capture's key exchange needs.
struct Exchange {
    suite: &'static CipherSuite,
    curve: Curve,
    private: BigUint,
    key: KeyGeneration,
    client_random: [u8; 32],
    server_random: [u8; 32],
    client_key_exchange: Vec<u8>,
    /// The transcript hash through the ClientKeyExchange.
    session_hash: Vec<u8>,
    extended: bool,
    /// From the key log.
    master: Vec<u8>,
}

fn exchange(transcript: &Transcript) -> Exchange {
    let name = &transcript.name;
    let suite = suites::by_name(&transcript.cipher)
        .unwrap_or_else(|| panic!("{name}: no suite {}", transcript.cipher));

    let client = handshake_messages(&transcript.to_server);
    let server = handshake_messages(&transcript.to_client);
    let types = |messages: &[Vec<u8>]| messages.iter().map(|m| m[0]).collect::<Vec<_>>();
    // ClientHello then ClientKeyExchange, and ServerHello, Certificate,
    // ServerHelloDone: no client certificate, no ServerKeyExchange. The
    // server's NewSessionTicket also precedes its ChangeCipherSpec, and
    // comes after the ClientKeyExchange, so the session hash stops short
    // of it.
    assert_eq!(types(&client), [1, 16], "{name}: the client's messages");
    assert_eq!(types(&server)[..3], [2, 11, 14], "{name}: the server's messages");

    let mut hash = keys::Transcript::new(Version::TLS12, suite.prf).unwrap();
    for message in [&client[0], &server[0], &server[1], &server[2], &client[1]] {
        hash.update(message);
    }

    let hello = ServerHello::parse(&server[0][4..])
        .unwrap_or_else(|e| panic!("{name}: the ServerHello: {e:?}"));
    assert_eq!(hello.cipher_suite, suite.code, "{name}: the ServerHello's suite");
    let extended = hello.extensions.iter()
        .any(|e| e.kind == extension::EXTENDED_MASTER_SECRET);
    let client_random: [u8; 32] = client[0][6..38].try_into().unwrap();

    // A three byte list length, then a three byte length per entry.
    let certificates = &server[1][4..];
    let size = u32::from_be_bytes([0, certificates[3], certificates[4], certificates[5]])
        as usize;
    let leaf = Certificate::parse(&certificates[6..6 + size])
        .unwrap_or_else(|e| panic!("{name}: the certificate: {e}"));
    let (curve, x, y, legacy) = match &leaf.public_key {
        PublicKey::Gost { curve, x, y, legacy, .. } => (*curve, x.clone(), y.clone(), *legacy),
        other => panic!("{name}: not a GOST key: {other:?}"),
    };
    let curve = curves::by_name(curve).unwrap();

    // The recorded key has to be the certificate's: a key from another
    // capture would unwrap nothing, and the failure would read as a
    // derivation bug.
    assert!(!transcript.server_key.is_empty(),
            "{name}: no server_key - recapture with scripts/capture_gost_transcripts.py");
    // Whole bytes: the engine prints the scalar as a number and drops a
    // leading zero nibble, which the capture puts back.
    assert!(transcript.server_key.len().is_multiple_of(2),
            "{name}: the server key is not whole bytes");
    let private = BigUint::from_bytes_be(&unhex(&transcript.server_key));
    assert!(curve.generator_mul(&private) == Point::new(x, y),
            "{name}: the recorded server key is not the certificate's");

    let wanted: String = client_random.iter().map(|b| format!("{b:02x}")).collect();
    let (_, _, secret) = transcript.secrets.iter()
        .find(|(label, random, _)| label == "CLIENT_RANDOM" && *random == wanted)
        .unwrap_or_else(|| panic!("{name}: the key log has no secret for this session"));

    Exchange {
        suite, curve, private,
        key: if legacy { KeyGeneration::Gost2001 } else { KeyGeneration::Gost2012 },
        client_random, server_random: hello.random,
        client_key_exchange: client[1][4..].to_vec(),
        session_hash: hash.session_hash(),
        extended,
        master: unhex(secret),
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

impl Exchange {
    fn is_2001_suite(&self) -> bool {
        self.suite.key_exchange == KeyExchange::GostVko2001
    }

    /// The premaster through this library's server side: KEG for the
    /// CTR_OMAC suites, and for CNT_IMIT the transport `transport` names.
    fn unwrap(&self, transport: Option<Transport>) -> Result<Vec<u8>, String> {
        match (self.suite.cipher.ctr_omac(), transport) {
            (Some(gost), _) => gost_kex::unwrap_secret(
                gost, &self.curve, &self.private, &self.client_random,
                &self.server_random, &self.client_key_exchange),
            (None, Some(transport)) => gost_kex_28147::unwrap_secret_with(
                transport, &self.curve, &self.private, &self.client_random,
                &self.server_random, &self.client_key_exchange),
            (None, None) => Err("a CNT_IMIT suite needs a transport".to_string()),
        }
    }

    /// The transport the library chooses for this suite and this key.
    fn chosen(&self) -> Option<Transport> {
        match self.suite.cipher.ctr_omac() {
            Some(_) => None,
            None => Some(Transport::for_suite(self.is_2001_suite(), self.key)
                .expect("the pairing was captured, so it exists")),
        }
    }

    fn master_from(&self, premaster: &[u8]) -> Vec<u8> {
        if self.extended {
            keys::extended_master_secret(Version::TLS12, self.suite.prf, premaster,
                                         &self.session_hash).unwrap()
        } else {
            keys::master_secret(Version::TLS12, self.suite.prf, premaster,
                                &self.client_random, &self.server_random).unwrap()
        }
    }
}

/// Every capture: the engine's ClientKeyExchange, unwrapped with the
/// transport this library picks, gives the master secret in the key log.
#[test]
fn test_the_engine_s_key_exchange_unwraps_to_its_master_secret() {
    for transcript in &load_gost() {
        let exchange = exchange(transcript);
        let premaster = exchange.unwrap(exchange.chosen())
            .unwrap_or_else(|e| panic!("{}: {e}", transcript.name));
        assert_eq!(premaster.len(), 32, "{}", transcript.name);
        assert!(exchange.master_from(&premaster) == exchange.master,
                "{}: the premaster does not give the key log's master secret",
                transcript.name);
    }
}

/// The UKM in the engine's blob is the suite's hash, and the S-box it
/// names is the key's.
///
/// `unwrap_secret_with` already refuses a UKM that is not the one it
/// derived. This says which fields decided what, in the engine's own
/// bytes, on every CNT_IMIT capture.
#[test]
fn test_the_ukm_follows_the_suite_and_the_s_box_the_key() {
    let mut seen = 0;
    for transcript in &load_gost() {
        let exchange = exchange(transcript);
        let Some(transport) = exchange.chosen() else { continue };
        seen += 1;
        let blob = KeyTransportBlob::parse(&exchange.client_key_exchange).unwrap();
        let wanted_hash = if exchange.is_2001_suite() { UkmHash::Gost94 }
                          else { UkmHash::Streebog256 };
        assert_eq!(transport.ukm_hash, wanted_hash, "{}", transcript.name);
        assert_eq!(transport.key, exchange.key, "{}", transcript.name);
        assert_eq!(blob.ukm, transport.ukm(&exchange.client_random,
                                           &exchange.server_random),
                   "{}: the engine's UKM is not the suite's hash", transcript.name);
        assert_eq!(blob.encryption_param_set, transport.encryption_param_set(),
                   "{}: the engine named another S-box", transcript.name);
    }
    assert!(seen >= 5, "only {seen} CNT_IMIT captures");
}

/// On a 2001 key under a 2012 suite, both readings that take everything
/// from one side fail on the engine's bytes. Without this the test above
/// could pass on a capture where the two sides happen to agree.
#[test]
fn test_neither_one_sided_reading_unwraps_a_mixed_pairing() {
    let mut seen = Vec::new();
    for transcript in &load_gost() {
        let exchange = exchange(transcript);
        if exchange.suite.cipher.ctr_omac().is_some() || exchange.is_2001_suite()
            || exchange.key != KeyGeneration::Gost2001 {
            continue;
        }
        seen.push(exchange.suite.code);
        // Everything from the suite: Streebog-256, VKO_256 and param-Z.
        assert!(exchange.unwrap(Some(Transport::RFC_9189)).is_err(),
                "{}: the suite's reading unwrapped it", transcript.name);
        // Everything from the key: GOST R 34.11-94, VKO 2001, CryptoPro-A.
        assert!(exchange.unwrap(Some(Transport::GOST_2001)).is_err(),
                "{}: the key's reading unwrapped it", transcript.name);
    }
    for code in [0xc102, 0xff85] {
        assert!(seen.contains(&code), "no capture of {code:#06x} on a 2001 key: {seen:x?}");
    }
}

/// The pairings this file exists for, by name: each 2012 CNT_IMIT suite
/// on a 2001 key, and a 512 bit key under each key exchange.
#[test]
fn test_the_capture_has_the_pairings() {
    let mut seen: Vec<String> = load_gost().iter().map(|transcript| {
        let exchange = exchange(transcript);
        let bits = exchange.curve.n.bit_len().div_ceil(256) * 256;
        format!("{:#06x} {:?} {bits}", exchange.suite.code, exchange.key)
    }).collect();
    seen.sort();
    seen.dedup();
    for wanted in ["0xc100 Gost2012 256", "0xc100 Gost2012 512", "0xc101 Gost2012 256",
                   "0xc102 Gost2012 256", "0xc102 Gost2012 512", "0xc102 Gost2001 256",
                   "0xff85 Gost2012 256", "0xff85 Gost2001 256", "0x0081 Gost2001 256"] {
        assert!(seen.iter().any(|s| s == wanted), "no capture of {wanted}: {seen:?}");
    }
}
