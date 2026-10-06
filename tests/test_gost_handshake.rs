/*
A whole RFC 9189 CTR_OMAC handshake, client against a server written here.

Why a server. Nothing on this machine speaks these suites - OpenSSL is
built without the GOST engine - so the Python harness that drives every
other handshake test cannot reach them. RFC 9189's own vectors cover the
pieces (`src/kdf/gost.rs`, `src/tls/record_gost.rs`, `src/tls/gost_kex.rs`
and `src/tls/keys.rs` each reproduce part of Appendix A byte for byte),
but a vector is one precomputed value at one point. What it cannot show
is that the *client* asks for the right thing at the right moment: that
it refuses a ServerKeyExchange, reaches the certificate's key, derives
the same master secret the other end does, turns the key block into a
record layer that the other end can read, and does all of it with the
directions the right way round.

What this does not prove, and cannot: the server here is ours, so a
misreading shared by both ends round trips perfectly. The byte orders
and the framing are settled by the RFC's vectors and by
`scripts/diff_check.py`; this settles the wiring. Those are different
questions and both need answering.

The server is deliberately minimal - one flight each way, no client
authentication, no resumption - because every line of it is a line that
could be wrong in a way that makes the client look right.
*/

use allcrypt::ec::{curves, Curve};
use allcrypt::tls::client::{ClientConfig, ClientConnection};
use allcrypt::tls::codec::Reader;
use allcrypt::tls::handshake::{extension, CertificateChain, Extension, Finished,
                               HandshakeMessage, HandshakeReader, HandshakeType,
                               Random, ServerHello};
use allcrypt::tls::keys::{self, Side};
use allcrypt::tls::record::{Protection, RecordReader, RecordWriter};
use allcrypt::tls::record_cnt_imit::CntImit;
use allcrypt::tls::record_gost::CtrOmac;
use allcrypt::tls::suites::{self, CipherSuite};
use allcrypt::tls::{gost_kex, gost_kex_28147, ContentType, Version};
use allcrypt::trust::TrustStore;
use allcrypt::x509::builder::{CertificateBuilder, SanEntry, SigningKey, SubjectKey};
use allcrypt::x509::oids;

/// A GOST certificate authority and a leaf it issued, on one curve.
struct Pki {
    curve: Curve,
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_private: allcrypt::bignum::BigUint,
}

fn pki(curve_name: &str, hostname: &str) -> Pki {
    pki_of(curve_name, hostname, false)
}

/// `legacy` builds a GOST R 34.10-2001 certificate instead: the same
/// key on the same curve, under the 2001 algorithm OID and signed over
/// a GOST R 34.11-94 digest. The 0x0081 suite refuses anything else,
/// and a 2012 certificate presented for it must be refused rather than
/// used - which is what `test_a_2012_certificate_is_refused_for_the_
/// 2001_suite` checks.
fn pki_of(curve_name: &str, hostname: &str, legacy: bool) -> Pki {
    let curve = curves::by_name(curve_name).unwrap();
    let (root_private, root_public) = curve.generate_key_pair().unwrap();
    let (leaf_private, leaf_public) = curve.generate_key_pair().unwrap();
    // The leaf's public point goes into its certificate and is read back
    // from there by the client, so it is not kept separately - the
    // client must reach it through the certificate or not at all.

    fn subject<'a>(legacy: bool, curve: &'a Curve,
                   point: &'a allcrypt::ec::Point) -> SubjectKey<'a> {
        if legacy { SubjectKey::Gost2001 { curve, point } }
        else { SubjectKey::Gost { curve, point } }
    }
    fn signer<'a>(legacy: bool, curve: &'a Curve,
                  private: &'a allcrypt::bignum::BigUint) -> SigningKey<'a> {
        if legacy { SigningKey::Gost2001 { curve, private } }
        else { SigningKey::Gost { curve, private } }
    }

    let mut root = CertificateBuilder::new(
        "GOST Test Root", subject(legacy, &curve, &root_public));
    root.serial = vec![1];
    root.issuer = vec![(oids::COMMON_NAME, "GOST Test Root".to_string())];
    root.subject = vec![(oids::COMMON_NAME, "GOST Test Root".to_string())];
    root.not_before = "20200101000000Z";
    root.not_after = "20400101000000Z";
    root.is_ca = Some((true, None));
    let root_der = root.sign(&signer(legacy, &curve, &root_private)).unwrap();

    let mut leaf = CertificateBuilder::new(hostname,
                                           subject(legacy, &curve, &leaf_public));
    leaf.serial = vec![2];
    leaf.issuer = vec![(oids::COMMON_NAME, "GOST Test Root".to_string())];
    leaf.subject = vec![(oids::COMMON_NAME, hostname.to_string())];
    leaf.not_before = "20200101000000Z";
    leaf.not_after = "20400101000000Z";
    leaf.sans = vec![SanEntry::Dns(hostname.to_string())];
    let leaf_der = leaf.sign(&signer(legacy, &curve, &root_private)).unwrap();

    Pki { curve, root_der, leaf_der, leaf_private }
}

/// Everything the server learns as it goes.
struct Server {
    pki: Pki,
    suite: &'static CipherSuite,
    reader: RecordReader,
    writer: RecordWriter,
    transcript: keys::Transcript,
    client_random: [u8; 32],
    server_random: Random,
    master: Vec<u8>,
    /// Set once the client's Finished has been checked, so a test cannot
    /// mistake "we never got there" for success.
    saw_client_finished: bool,
    messages: HandshakeReader,
    /// Send a ServerKeyExchange the suite has no place for, between the
    /// Certificate and the ServerHelloDone - which is where a real one
    /// would sit, and the only position that tests the suite-based
    /// refusal rather than the state machine's ordering.
    inject_server_key_exchange: bool,
    /// The transcript hash as it stood before the client's Finished,
    /// which is what that message's verify_data covers.
    before_client_finished: Vec<u8>,
}

impl Server {
    fn new(pki: Pki, suite_code: u16) -> Server {
        let suite = suites::by_code(suite_code).unwrap();
        let mut server_random = [0u8; 32];
        for (i, byte) in server_random.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(5);
        }
        Server {
            pki, suite,
            reader: RecordReader::new(),
            writer: RecordWriter::new(Version::TLS12),
            transcript: keys::Transcript::new(Version::TLS12, suite.prf).unwrap(),
            client_random: [0u8; 32],
            server_random,
            master: Vec::new(),
            saw_client_finished: false,
            messages: HandshakeReader::new(),
            inject_server_key_exchange: false,
            before_client_finished: Vec::new(),
        }
    }

    /// One turn: consume whatever the client sent, produce the reply.
    fn turn(&mut self, incoming: &[u8]) -> Vec<u8> {
        self.reader.push_incoming(incoming);
        let mut out = Vec::new();
        while let Some(record) = self.reader.read().expect("server: bad record") {
            out.extend_from_slice(&self.handle(record));
        }
        out
    }

    fn handle(&mut self, record: allcrypt::tls::record::Record) -> Vec<u8> {
        match record.content_type {
            ContentType::Handshake => {
                let mut out = Vec::new();
                self.messages.push(&record.payload);
                while let Some(message) = self.messages.next_message()
                                              .expect("server: bad handshake") {
                    // The transcript hash the client's Finished covers
                    // stops *before* that message, so it is taken here
                    // rather than rewound afterwards - a hash cannot be
                    // rewound, and a server that tried would be checking
                    // the wrong thing.
                    if message.message_type == HandshakeType::Finished {
                        self.before_client_finished = self.transcript.hash();
                    }
                    self.transcript.update(&message.raw);
                    out.extend_from_slice(&self.handshake(&message));
                }
                out
            }
            ContentType::ChangeCipherSpec => {
                // From here the client's records are protected. The
                // server's are not, until it sends its own.
                let keys = self.key_block();
                let protection = self.protection(&keys.client);
                self.reader.change_cipher_spec(protection);
                Vec::new()
            }
            ContentType::ApplicationData => {
                // Echo it back, so the test can check both directions of
                // the record layer rather than only the client's sending
                // half.
                let mut reply = record.payload.clone();
                reply.extend_from_slice(b" (echoed)");
                self.writer.write(ContentType::ApplicationData, &reply)
                    .expect("server: cannot write")
            }
            other => panic!("server got an unexpected {:?}", other),
        }
    }

    fn handshake(&mut self, message: &HandshakeMessage) -> Vec<u8> {
        match message.message_type {
            HandshakeType::ClientHello => self.client_hello(message),
            HandshakeType::ClientKeyExchange => {
                let secret = if self.is_2001() {
                    gost_kex_28147::unwrap_secret_2001(
                        &self.pki.curve, &self.pki.leaf_private,
                        &self.client_random, &self.server_random, &message.body)
                } else {
                    match self.suite.cipher.ctr_omac() {
                        Some(gost) => gost_kex::unwrap_secret(
                            gost, &self.pki.curve, &self.pki.leaf_private,
                            &self.client_random, &self.server_random,
                            &message.body),
                        None => gost_kex_28147::unwrap_secret(
                            &self.pki.curve, &self.pki.leaf_private,
                            &self.client_random, &self.server_random,
                            &message.body),
                    }
                }.expect("server: cannot unwrap the preliminary secret");

                // The session hash is the transcript through the
                // ClientKeyExchange, which `handle` has already added.
                self.master = keys::extended_master_secret(
                    Version::TLS12, self.suite.prf, &secret,
                    &self.transcript.session_hash()).unwrap();
                Vec::new()
            }
            HandshakeType::Finished => self.client_finished(message),
            other => panic!("server got an unexpected {:?}", other),
        }
    }

    fn client_hello(&mut self, message: &HandshakeMessage) -> Vec<u8> {
        let hello = allcrypt::tls::handshake::ClientHello::parse(&message.body)
            .expect("server: bad ClientHello");
        assert!(hello.cipher_suites.contains(&self.suite.code),
                "the client did not offer {}", self.suite.name);
        self.client_random = hello.random;

        // RFC 9189 4.2.1: the extension is required, and must carry the
        // GOST pairs. Asserted rather than assumed, because a client that
        // omitted them would still complete this handshake - our server
        // has no reason to care - and would then fail against a real one.
        let signature_algorithms = hello.extensions.iter()
            .find(|e| e.kind == extension::SIGNATURE_ALGORITHMS)
            .expect("the ClientHello has no signature_algorithms extension");
        let mut reader = Reader::new(&signature_algorithms.body);
        let offered = reader.u16_list().unwrap();
        assert!(offered.contains(&0x0840), "no gostr34102012_256 (8,64)");
        assert!(offered.contains(&0x0841), "no gostr34102012_512 (8,65)");
        // And the private-use spellings a box older than RFC 9189
        // understands - section 10 of that document. A server that
        // speaks only those sees an extension with nothing in it that
        // it recognises.
        assert!(offered.contains(&0xeeee), "no legacy gostr34102012_256");
        assert!(offered.contains(&0xefef), "no legacy gostr34102012_512");
        assert!(offered.contains(&0xeded), "no gostr34102001 (0xeded)");

        // Extended master secret if the client asked; this server always
        // does, which is what RFC 9189's own example uses.
        assert!(hello.extensions.iter()
                     .any(|e| e.kind == extension::EXTENDED_MASTER_SECRET),
                "the client did not ask for the extended master secret");

        let server_hello = ServerHello {
            legacy_version: Version::TLS12,
            random: self.server_random,
            session_id: Vec::new(),
            cipher_suite: self.suite.code,
            compression_method: 0,
            extensions: vec![
                Extension { kind: extension::EXTENDED_MASTER_SECRET,
                            body: Vec::new() },
                // RFC 9189 4.2.1: a server choosing CTR_OMAC MUST NOT
                // send encrypt_then_mac, so this one does not.
            ],
        };

        let mut messages = vec![
            (HandshakeType::ServerHello, server_hello.encode().unwrap()),
            (HandshakeType::Certificate,
             CertificateChain { certificates: vec![self.pki.leaf_der.clone(),
                                                   self.pki.root_der.clone()] }
                 .encode().unwrap()),
        ];
        if self.inject_server_key_exchange {
            // A plausible ECDHE-shaped body: named_curve, secp256r1, a
            // one byte point. The contents do not matter - the client
            // must refuse the message for the suite it is in, before
            // anything parses it.
            messages.push((HandshakeType::ServerKeyExchange,
                           vec![0x03, 0x00, 0x17, 0x01, 0x04]));
        }
        messages.push((HandshakeType::ServerHelloDone, Vec::new()));

        let mut flight = Vec::new();
        for (kind, body) in messages {
            let message = HandshakeMessage::new(kind, body).unwrap();
            self.transcript.update(&message.raw);
            flight.extend_from_slice(&message.raw);
        }
        self.writer.write(ContentType::Handshake, &flight)
            .expect("server: cannot write the flight")
    }

    fn client_finished(&mut self, message: &HandshakeMessage) -> Vec<u8> {
        // The client's verify_data covers the transcript *before* its own
        // Finished, and `handle` added that message already - so the hash
        // has to be taken from a transcript that excludes it. Rebuilt
        // rather than rewound, because rewinding a hash is not a thing.
        let expected = keys::verify_data(Version::TLS12, self.suite,
                                         &self.master, Side::Client,
                                         &self.before_client_finished).unwrap();
        assert!(keys::verify_data_matches(&expected, &message.body),
                "the client's Finished does not match");
        self.saw_client_finished = true;

        let mut out = self.writer.write(ContentType::ChangeCipherSpec, &[1])
                          .expect("server: cannot write CCS");
        let keys = self.key_block();
        let protection = self.protection(&keys.server);
        self.writer.change_cipher_spec(protection);

        // The server's verify_data covers the transcript including the
        // client's Finished.
        let verify = keys::verify_data(Version::TLS12, self.suite,
                                       &self.master, Side::Server,
                                       &self.transcript.hash()).unwrap();
        let finished = HandshakeMessage::new(HandshakeType::Finished,
                                             Finished { verify_data: verify }
                                                 .encode()).unwrap();
        out.extend_from_slice(&self.writer.write(ContentType::Handshake,
                                                 &finished.raw)
                                  .expect("server: cannot write Finished"));
        out
    }

    /// The record protection for one direction, chosen by the suite -
    /// the same way the client chooses, which is the point: a server
    /// that picked by anything else could agree with a client that had
    /// picked wrongly.
    fn protection(&self, direction: &keys::DirectionKeys) -> Protection {
        if self.is_2001() {
            // The same record layer on a different S-box, which is the
            // only thing separating this suite's records from 0xC102's.
            return Protection::CntImit(
                CntImit::new_2001(&direction.key, &direction.mac_key,
                                  &direction.iv).unwrap());
        }
        match self.suite.cipher.ctr_omac() {
            Some(gost) => Protection::CtrOmac(
                CtrOmac::new(gost, &direction.key, &direction.mac_key,
                             &direction.iv).unwrap()),
            None => Protection::CntImit(
                CntImit::new(&direction.key, &direction.mac_key,
                             &direction.iv).unwrap()),
        }
    }

    fn is_2001(&self) -> bool {
        self.suite.key_exchange
            == allcrypt::tls::suites::KeyExchange::GostVko2001
    }

    fn key_block(&self) -> keys::KeyBlock {
        keys::key_block(Version::TLS12, self.suite, &self.master,
                        &self.client_random, &self.server_random).unwrap()
    }
}

fn handshake(curve_name: &str, suite_code: u16) -> (ClientConnection, bool) {
    let legacy = suite_code == 0x0081;
    handshake_with(pki_of(curve_name, "gost.test", legacy), suite_code)
}

fn handshake_with(pki: Pki, suite_code: u16) -> (ClientConnection, bool) {
    let (client, finished, failure) = try_handshake(pki, suite_code);
    if let Some(reason) = failure {
        panic!("client failed: {}", reason);
    }
    (client, finished)
}

/// The same, but a client that refuses is an outcome rather than a
/// panic - which is what the tests about refusals need.
fn try_handshake(pki: Pki, suite_code: u16)
                 -> (ClientConnection, bool, Option<String>) {

    let mut store = TrustStore::new();
    store.add_der(&pki.root_der).unwrap();
    let mut config = ClientConfig::new(store, 1_700_000_000);
    // One suite, so the server's choice is not a choice: these tests
    // are about a particular suite completing, and a client offering
    // five of them would still be testing whichever the server picked.
    config.suites = allcrypt::tls::suites::Selection::from_codes(
        vec![suite_code]).unwrap();
    config.min_version = Version::TLS12;
    config.max_version = Version::TLS12;

    let mut client = ClientConnection::new(config, "gost.test").unwrap();
    let mut server = Server::new(pki, suite_code);

    let mut failure = None;
    for _ in 0..8 {
        if let Err(error) = client.process() {
            failure = Some(error.describe());
            break;
        }
        let out = client.take_outgoing();
        if out.is_empty() && client.is_established() {
            break;
        }
        assert!(!out.is_empty(), "the client stopped without finishing");
        let reply = server.turn(&out);
        client.push_incoming(&reply);
    }

    (client, server.saw_client_finished, failure)
}

/// The whole handshake, on every GOST suite and every curve each one
/// can be on.
#[test]
fn test_a_gost_handshake_completes() {
    for (code, name) in [(0xc101u16, "magma"), (0xc100, "kuznyechik"),
                         (0xc102, "28147-cnt-imit"),
                         (0xff85, "28147-cnt-imit at its old code point")] {
        for curve in ["gost256-a", "gost256-b", "gost256-c",
                      "gost256-tc26-a", "gost512-a", "gost512-b",
                      "gost512-c"] {
            let (client, saw_finished) = handshake(curve, code);
            assert!(saw_finished,
                    "{} on {}: the server never checked a Finished", name, curve);
            assert!(client.is_established(), "{} on {}", name, curve);
            assert_eq!(client.negotiated_suite().unwrap().code, code);
            assert_eq!(client.negotiated_version(), Some(Version::TLS12));
            // The chain must have been verified, not merely parsed - a
            // handshake that completed without checking the certificate
            // is the failure this library exists to avoid.
            assert!(client.certificate_verified(), "{} on {}", name, curve);
            assert!(client.uses_extended_master_secret());
        }
    }
}

/// The 2001 suite, on the three curves a GOST R 34.10-2001 key can be
/// on.
///
/// Separate from the loop above because everything about it differs: a
/// 2001 certificate rather than a 2012 one, GOST R 34.11-94 as the
/// transcript hash and the PRF, VKO GOST R 34.10-2001, and the
/// CryptoPro-A S-box under the record layer. The 512 bit curves and
/// the TC 26 sets are not in the list because a 2001 key cannot be on
/// them - they arrived with the 2012 standard.
#[test]
fn test_the_2001_handshake_completes() {
    for curve in ["gost256-a", "gost256-b", "gost256-c"] {
        let (client, saw_finished) = handshake(curve, 0x0081);
        assert!(saw_finished,
                "2001 on {}: the server never checked a Finished", curve);
        assert!(client.is_established(), "2001 on {}", curve);
        assert_eq!(client.negotiated_suite().unwrap().code, 0x0081);
        assert!(client.certificate_verified(), "2001 on {}", curve);
    }
}

/// A 2012 certificate presented for the 2001 suite is refused.
///
/// The two suites' certificates carry the same key on the same curve
/// and differ in their algorithm OID and in what signed them, so a
/// client that did not look would complete the handshake and be
/// talking to a server it had not authenticated the way the suite
/// says. The refusal has to come from the certificate's own contents,
/// which is why this test swaps only that.
#[test]
fn test_a_2012_certificate_is_refused_for_the_2001_suite() {
    // The PKI is built the 2012 way and handed to a 2001 handshake.
    let pki = pki_of("gost256-a", "gost.test", false);
    let (client, saw_finished, failure) = try_handshake(pki, 0x0081);
    assert!(!saw_finished, "the server checked a Finished it should not have");
    assert!(!client.is_established(),
            "the client accepted a 2012 certificate for the 2001 suite");
    let reason = failure.expect("the client did not refuse");
    assert!(reason.contains("needs a GOST R 34.10-2001 certificate"),
            "refused for the wrong reason: {}", reason);

    // And the mirror image: a 2001 certificate for a 2012 suite.
    let pki = pki_of("gost256-a", "gost.test", true);
    let (_, _, failure) = try_handshake(pki, 0xc102);
    let reason = failure.expect("the client did not refuse");
    assert!(reason.contains("needs a GOST R 34.10-2012 certificate"),
            "refused for the wrong reason: {}", reason);
}

/// The two CNT_IMIT suites do not produce the same records.
///
/// They share the whole record layer and differ in one table, which is
/// the sort of difference a refactor loses. Stated as a comparison of
/// the bytes, because both are valid records and only a peer can tell
/// which is which.
#[test]
fn test_the_two_cnt_imit_suites_encrypt_differently() {
    use allcrypt::tls::record_cnt_imit::CntImit;
    use allcrypt::tls::{ContentType, Version};

    let (key, mac_key, iv) = ([7u8; 32], [9u8; 32], [3u8; 8]);
    let mut modern = CntImit::new(&key, &mac_key, &iv).unwrap();
    let mut legacy = CntImit::new_2001(&key, &mac_key, &iv).unwrap();

    let one = allcrypt::tls::record_cnt_imit::encrypt(
        &mut modern, allcrypt::tls::record::SequenceNumber::zero(),
        ContentType::ApplicationData,
        Version::TLS12, b"the same plaintext").unwrap();
    let two = allcrypt::tls::record_cnt_imit::encrypt(
        &mut legacy, allcrypt::tls::record::SequenceNumber::zero(),
        ContentType::ApplicationData,
        Version::TLS12, b"the same plaintext").unwrap();
    assert_ne!(one, two,
               "param-Z and CryptoPro-A produced the same record");
}

/// Application data both ways, over records the other end protects.
///
/// Run for all three suites, because CNT_IMIT's state is cumulative in
/// both halves: its keystream and its MAC run for the connection rather
/// than the record, so a bug there shows on the *second* exchange and
/// never on the first.
#[test]
fn test_application_data_flows_both_ways() {
    for code in [0xc101u16, 0xc100, 0xc102, 0xff85, 0x0081] {
        application_data_for(code);
    }
}

fn application_data_for(code: u16) {
    let pki = pki_of("gost256-a", "gost.test", code == 0x0081);
    let mut store = TrustStore::new();
    store.add_der(&pki.root_der).unwrap();
    let mut config = ClientConfig::new(store, 1_700_000_000);
    config.suites = allcrypt::tls::suites::Selection::from_codes(
        vec![code]).unwrap();
    config.min_version = Version::TLS12;
    config.max_version = Version::TLS12;
    let mut client = ClientConnection::new(config, "gost.test").unwrap();
    let mut server = Server::new(pki, code);

    for _ in 0..8 {
        client.process().unwrap();
        let out = client.take_outgoing();
        if out.is_empty() && client.is_established() {
            break;
        }
        let reply = server.turn(&out);
        client.push_incoming(&reply);
    }
    assert!(client.is_established());

    // Several records, long enough to cross a re-keying boundary in
    // every suite: 1 KB for Magma's ACPKM sections and for CryptoPro
    // meshing, 4 KB for Kuznyechik's. A short exchange reaches none of
    // them, and the repeated short payloads at the end are what catches
    // a keystream that restarts per record.
    for payload in [b"hello".to_vec(), vec![0x41; 1500], vec![0x5a; 5000],
                    Vec::new(), b"same".to_vec(), b"same".to_vec(),
                    b"last".to_vec()] {
        client.write(&payload).unwrap();
        client.process().unwrap();
        let out = client.take_outgoing();
        let reply = server.turn(&out);
        client.push_incoming(&reply);
        client.process().unwrap();

        let mut expected = payload.clone();
        expected.extend_from_slice(b" (echoed)");
        assert_eq!(client.take_incoming(), expected,
                   "suite {:#06x}: a {} byte payload did not come back",
                   code, payload.len());
    }
}

/// A ServerKeyExchange must be refused. RFC 9189 section 4.2 says one
/// MUST NOT be sent, and accepting it would mean agreeing a key with
/// whoever sent the message rather than with the certificate's owner -
/// there is no signature here to tell them apart, which is exactly the
/// shape of FREAK.
#[test]
fn test_a_server_key_exchange_is_refused() {
    let pki = pki("gost256-a", "gost.test");
    let mut store = TrustStore::new();
    store.add_der(&pki.root_der).unwrap();
    let mut client = ClientConnection::new(
        ClientConfig::new(store, 1_700_000_000), "gost.test").unwrap();
    let mut server = Server::new(pki, 0xc101);

    server.inject_server_key_exchange = true;

    client.process().unwrap();
    let hello = client.take_outgoing();
    let flight = server.turn(&hello);
    client.push_incoming(&flight);
    let error = client.process().unwrap_err();
    let message = error.describe();
    assert!(message.contains("ServerKeyExchange"), "{}", message);
    assert!(message.contains("9189"), "{}", message);
    assert!(!client.is_established());
}

/// A certificate on the wrong kind of key is refused by name.
///
/// The suite decides what the certificate must carry, and an EC
/// certificate cannot do a GOST key agreement - so this has to fail with
/// a message about the key rather than somewhere deeper with a message
/// about arithmetic.
#[test]
fn test_an_ec_certificate_is_refused_for_a_gost_suite() {
    use allcrypt::ec::curves;

    let curve = curves::p256();
    let (private, public) = curve.generate_key_pair().unwrap();
    let point = curve.encode_point(&public, false).unwrap();
    let mut root = CertificateBuilder::new("EC Root",
                                           SubjectKey::Ec { curve: &curve,
                                                            point: &point });
    root.serial = vec![1];
    root.issuer = vec![(oids::COMMON_NAME, "EC Root".to_string())];
    root.subject = vec![(oids::COMMON_NAME, "EC Root".to_string())];
    root.not_before = "20200101000000Z";
    root.not_after = "20400101000000Z";
    root.is_ca = Some((true, None));
    root.sans = vec![];
    let root_der = root.sign(&SigningKey::Ec { curve: &curve,
                                               private: &private }).unwrap();

    let mut leaf = CertificateBuilder::new("gost.test",
                                           SubjectKey::Ec { curve: &curve,
                                                            point: &point });
    leaf.serial = vec![2];
    leaf.issuer = vec![(oids::COMMON_NAME, "EC Root".to_string())];
    leaf.subject = vec![(oids::COMMON_NAME, "gost.test".to_string())];
    leaf.not_before = "20200101000000Z";
    leaf.not_after = "20400101000000Z";
    leaf.sans = vec![SanEntry::Dns("gost.test".to_string())];
    let leaf_der = leaf.sign(&SigningKey::Ec { curve: &curve,
                                               private: &private }).unwrap();

    let mut store = TrustStore::new();
    store.add_der(&root_der).unwrap();
    let mut client = ClientConnection::new(
        ClientConfig::new(store, 1_700_000_000), "gost.test").unwrap();

    // A GOST server whose certificates are the EC ones above.
    let mut pki = pki("gost256-a", "gost.test");
    pki.root_der = root_der;
    pki.leaf_der = leaf_der;
    let mut server = Server::new(pki, 0xc101);

    client.process().unwrap();
    let hello = client.take_outgoing();
    let flight = server.turn(&hello);
    client.push_incoming(&flight);

    let message = client.process().unwrap_err().describe();
    assert!(message.contains("GOST"), "{}", message);
    assert!(!client.is_established());
}
