/*!
The GOST record layers, against handshakes that really happened.

`tests/transcripts/gost_handshakes.txt` holds every byte that crossed in
each direction of four real GOST TLS 1.2 handshakes - **both ends
OpenSSL with gost-engine**, recorded by a relay that sat between them -
together with the master secret from `s_server -keylogfile`. Regenerate
it with `scripts/capture_gost_transcripts.py`.

This is the test `tests/test_gost_handshake.rs` cannot be, and
`docs/pitfalls.md` said so for as long as there was no way to write it:

> It settles the *wiring* - directions, ordering, which key comes from
> where - and cannot settle byte orders, since both ends are ours.

Here the records were encrypted by somebody else, so the only way to
read one is to have got all of it right at once:

  * the key block from `PRF(master, "key expansion", server_random +
    client_random)` - **server random first**, and the GOST PRF is
    HMAC-Streebog-256, not HMAC-SHA-256;
  * the split - both MAC keys, both encryption keys, both IVs, client
    first in each pair - with a **32 byte OMAC key** whatever the
    block size (RFC 9189 4.3.2);
  * for CTR_OMAC: TLSTREE per record from the sequence number,
    CTR-ACPKM's keystream restarted for each record and its ACPKM
    counter running across the section boundary, the IV *added to* the
    sequence number, and OMAC over the header the record layer builds
    rather than the one on the wire;
  * for CNT_IMIT: GOST 28147-89's counter with its `mod 2^32-1` high
    word, CryptoPro key meshing after 1024 octets with the MAC's
    chaining state left alone, and a cumulative four byte MAC that
    carries across records.

Every one of those is self-consistent when wrong. A handshake between
two copies of this library agrees with itself whichever way round any of
them is, which is why this file exists and why the fixture's bytes are
not ours.

**No network.** The capture needed loopback and the engine; this needs
neither. Nothing in the test gate builds gost-engine or opens a socket.
*/

use allcrypt::tls::keys::{key_block, DirectionKeys};
use allcrypt::tls::record::{protection_for, Protection, RecordReader,
                            SequenceNumber};
use allcrypt::tls::suites;
use allcrypt::tls::{ContentType, Version};

mod fixture {
    include!("transcripts/loader.rs");
}
use fixture::{load_gost, Transcript};

/// The client and server randoms, read out of the recorded hellos.
///
/// Taken from the bytes rather than from the key log, which carries only
/// the client's. That also means the hello parsing is on the hook: a
/// random read from the wrong offset gives a key block that decrypts
/// nothing, and the error would look like a cipher bug.
fn randoms(transcript: &Transcript) -> ([u8; 32], [u8; 32]) {
    // ClientHello: 5 byte record header, 4 byte handshake header,
    // 2 byte legacy_version, then the 32 byte random.
    let client = &transcript.to_server[11..43];
    // ServerHello is laid out the same way and is the first message in
    // the server's direction.
    let server = &transcript.to_client[11..43];
    (client.try_into().expect("32 bytes"), server.try_into().expect("32 bytes"))
}

/// The master secret for this transcript, from the key log.
///
/// Checked against the recorded ClientHello's random rather than taken
/// on trust: a key log from a *previous* capture left in place would
/// otherwise give a plausible secret for the wrong session, and the only
/// symptom would be that nothing decrypts.
fn master_secret(transcript: &Transcript, client_random: &[u8; 32]) -> Vec<u8> {
    let wanted: String = client_random.iter()
        .map(|byte| format!("{byte:02x}")).collect();
    let (_, _, secret) = transcript.secrets.iter()
        .find(|(label, random, _)| label == "CLIENT_RANDOM" && *random == wanted)
        .unwrap_or_else(|| panic!(
            "{}: the key log has no CLIENT_RANDOM for this session's random - \
             it is from a different capture", transcript.name));
    assert_eq!(secret.len(), 96, "{}: a master secret is 48 bytes",
               transcript.name);
    (0..secret.len()).step_by(2)
        .map(|i| u8::from_str_radix(&secret[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Split one direction into records, refusing to guess.
fn frame(bytes: &[u8], name: &str) -> Vec<allcrypt::tls::record::Record> {
    let mut reader = RecordReader::new();
    reader.push_incoming(bytes);
    let mut records = Vec::new();
    loop {
        match reader.read() {
            Ok(Some(record)) => records.push(record),
            Ok(None) => break,
            Err(error) => panic!("{name}: framing failed: {}", error.describe()),
        }
    }
    assert_eq!(reader.buffered(), 0, "{name}: {} bytes left over",
               reader.buffered());
    records
}

/// The records after this direction's ChangeCipherSpec - the protected
/// ones.
///
/// **Not "everything after the first handshake record"**: the Finished
/// is protected too and is the first thing under the new keys, so it has
/// to be included or the sequence numbers start at one and every
/// subsequent record fails. That mistake decrypts nothing and looks like
/// a key error.
fn protected(records: &[allcrypt::tls::record::Record], name: &str)
             -> Vec<allcrypt::tls::record::Record> {
    let change = records.iter().position(|r| r.content_type == ContentType::ChangeCipherSpec)
        .unwrap_or_else(|| panic!("{name}: no ChangeCipherSpec in this direction"));
    records[change + 1..].to_vec()
}

struct Session {
    suite: &'static suites::CipherSuite,
    client: DirectionKeys,
    server: DirectionKeys,
}

fn session(transcript: &Transcript) -> Session {
    let suite = suites::by_name(&transcript.cipher).unwrap_or_else(|| panic!(
        "{}: this library does not know the suite {:?}",
        transcript.name, transcript.cipher));
    let (client_random, server_random) = randoms(transcript);
    let master = master_secret(transcript, &client_random);
    let block = key_block(Version::TLS12, suite, &master,
                          &client_random, &server_random)
        .unwrap_or_else(|e| panic!("{}: key block: {e}", transcript.name));
    Session { suite, client: block.client, server: block.server }
}

fn open_direction(session: &Session, keys: &DirectionKeys,
                  records: &[allcrypt::tls::record::Record], name: &str,
                  direction: &str) -> Vec<(ContentType, Vec<u8>)> {
    let mut protection = protection_for(session.suite, Version::TLS12, keys,
                                        false)
        .unwrap_or_else(|e| panic!("{name} {direction}: protection: {e}"));
    let mut out = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let plaintext = match &mut protection {
            Protection::CtrOmac(state) => allcrypt::tls::record_gost::decrypt(
                state, SequenceNumber::at(index as u64),
                record.content_type, record.version,
                &record.payload),
            Protection::CntImit(state) =>
                allcrypt::tls::record_cnt_imit::decrypt(
                    state, SequenceNumber::at(index as u64),
                record.content_type, record.version,
                    &record.payload),
            _ => panic!("{name} {direction}: {} is not a GOST record layer, \
                         so the suite table sent this transcript to the \
                         wrong code", protection.name()),
        };
        let plaintext = plaintext.unwrap_or_else(|error| panic!(
            "{name} {direction}: record {index} ({} bytes, type {:?}) did not \
             open: {}", record.payload.len(), record.content_type,
            error.describe()));
        out.push((record.content_type, plaintext));
    }
    out
}

#[test]
fn test_every_gost_transcript_decrypts_in_both_directions() {
    let transcripts = load_gost();
    println!("{} GOST transcripts", transcripts.len());
    assert!(transcripts.len() >= 3,
            "only {} transcripts - the capture covers four suites",
            transcripts.len());

    let mut with_several_records = 0;
    for transcript in &transcripts {
        let state = session(transcript);
        let name = &transcript.name;

        for (direction, bytes, keys) in
            [("client->server", &transcript.to_server, &state.client),
             ("server->client", &transcript.to_client, &state.server)] {
            let records = frame(bytes, name);
            let sealed = protected(&records, name);
            assert!(!sealed.is_empty(), "{name} {direction}: nothing protected");
            let opened = open_direction(&state, keys, &sealed, name, direction);

            // The first protected message is the Finished: a handshake
            // record whose body starts with 0x14.
            let (first_type, first) = &opened[0];
            assert_eq!(*first_type, ContentType::Handshake,
                       "{name} {direction}: the first protected record is not \
                        a handshake message");
            assert_eq!(first[0], 0x14,
                       "{name} {direction}: the first protected message is \
                        not a Finished");
            // 32 bytes of verify_data for the CTR_OMAC suites, 12 for
            // CNT_IMIT - RFC 9189 4.2.6. The length is in the message's
            // own header, so a wrong one here is a wrong decryption.
            let declared = u32::from_be_bytes([0, first[1], first[2], first[3]])
                as usize;
            assert_eq!(declared, state.suite.cipher.verify_data_len(),
                       "{name} {direction}: the Finished declares {declared} \
                        bytes of verify_data");
            assert_eq!(first.len(), 4 + declared,
                       "{name} {direction}: the Finished is the wrong length");

            if sealed.len() >= 3 {
                with_several_records += 1;
            }
        }
    }

    // **One record proves almost nothing here.** Every re-keying
    // mistake in these suites is right for the first record and wrong
    // afterwards: CTR-ACPKM restarts its keystream per record, TLSTREE
    // changes the key at a sequence boundary, and CryptoPro meshing
    // fires after 1024 octets. The capture pads both directions to
    // several records for that reason.
    assert!(with_several_records >= 6,
            "only {with_several_records} directions had three or more \
             protected records, so the re-keying is barely covered");
}

#[test]
fn test_the_server_really_answered() {
    // Decryption succeeding is not by itself evidence that the right
    // plaintext came out: a MAC that was not checked, or one checked
    // over the wrong header, would let a wrong key through. The server
    // was `openssl s_server -www`, so its application data is an HTTP
    // response - bytes that cannot appear by accident.
    for transcript in &load_gost() {
        let state = session(transcript);
        let records = frame(&transcript.to_client, &transcript.name);
        let opened = open_direction(&state, &state.server,
                                    &protected(&records, &transcript.name),
                                    &transcript.name, "server->client");
        let body: Vec<u8> = opened.iter()
            .filter(|(kind, _)| *kind == ContentType::ApplicationData)
            .flat_map(|(_, bytes)| bytes.clone())
            .collect();
        assert!(!body.is_empty(), "{}: no application data", transcript.name);
        let text = String::from_utf8_lossy(&body);
        assert!(text.starts_with("HTTP/1.0 200 ok"),
                "{}: the server's plaintext does not start with its status \
                 line: {:?}", transcript.name,
                &text[..text.len().min(64)]);
        // `s_server -www` prints the negotiated suite into its own page,
        // so the plaintext names the suite it was encrypted under. A
        // transcript decrypted with another session's keys could not say
        // this.
        assert!(text.contains(&transcript.cipher),
                "{}: the page does not name {}", transcript.name,
                transcript.cipher);
    }
}

#[test]
fn test_the_client_request_comes_back_out() {
    // The other direction, which uses the other half of the key block.
    // Swapping the two halves gives two sides that each encrypt
    // correctly and cannot read one another - and a test that only ever
    // decrypted the server would not notice.
    for transcript in &load_gost() {
        let state = session(transcript);
        let records = frame(&transcript.to_server, &transcript.name);
        let opened = open_direction(&state, &state.client,
                                    &protected(&records, &transcript.name),
                                    &transcript.name, "client->server");
        let body: Vec<u8> = opened.iter()
            .filter(|(kind, _)| *kind == ContentType::ApplicationData)
            .flat_map(|(_, bytes)| bytes.clone())
            .collect();
        let text = String::from_utf8_lossy(&body);
        assert!(text.starts_with("GET / HTTP/1.0"),
                "{}: the client's plaintext is not its request: {:?}",
                transcript.name, &text[..text.len().min(64)]);
        // The capture pads the request past 1024 octets on purpose, so
        // that CryptoPro meshing and ACPKM re-keying are inside this
        // direction rather than only in the server's.
        assert!(body.len() > 1024,
                "{}: the client sent only {} bytes, which is inside one \
                 re-keying section", transcript.name, body.len());
    }
}

#[test]
fn test_the_wrong_direction_s_keys_do_not_work() {
    // What says the two halves of the key block are actually different
    // and that the MAC is being checked. Opening the server's records
    // with the client's keys must fail - if it succeeded, either the
    // halves are the same or nothing is being authenticated.
    //
    // The client's *first* protected record is its Finished, so this
    // uses the server's records under the client's keys rather than the
    // reverse, which keeps the two sequences comparable.
    for transcript in &load_gost() {
        let state = session(transcript);
        let records = frame(&transcript.to_client, &transcript.name);
        let sealed = protected(&records, &transcript.name);

        let mut protection = protection_for(state.suite, Version::TLS12,
                                            &state.client, false)
            .expect("protection");
        let record = &sealed[0];
        let opened = match &mut protection {
            Protection::CtrOmac(inner) => allcrypt::tls::record_gost::decrypt(
                inner, SequenceNumber::zero(), record.content_type,
                record.version,
                &record.payload).is_ok(),
            Protection::CntImit(inner) =>
                allcrypt::tls::record_cnt_imit::decrypt(
                    inner, SequenceNumber::zero(), record.content_type,
                record.version,
                    &record.payload).is_ok(),
            _ => panic!("{} is not a GOST record layer", protection.name()),
        };
        assert!(!opened,
                "{}: the server's record opened under the client's keys",
                transcript.name);
    }
}

#[test]
fn test_the_capture_covers_every_distinct_gost_stack() {
    // **Four things wear the GOST name and share almost nothing**, so a
    // fixture covering one would leave the rest tested by nothing but
    // themselves. Listed by name rather than counted, because the count
    // is a property of the capture and the names are a property of what
    // is covered - the substitution this repository has had to make
    // three times after a count broke.
    //
    // The pairs that differ in one thing only are the ones that carry
    // information:
    //
    //   * Kuznyechik's CTR_OMAC against Magma's - the same record layer
    //     over a 128 bit and a 64 bit block, with different TLSTREE
    //     constants, a different ACPKM section size and a tag of a
    //     different length.
    //   * 0xC102's CNT_IMIT against 0x0081's - **the same record layer
    //     under a different S-box and a different PRF.** A GOST cipher
    //     *is* its S-box, so these two produce entirely different bytes
    //     from the same key material, and the 2001 one is the only
    //     transcript here whose PRF is GOST R 34.11-94 rather than
    //     Streebog-256.
    let mut seen: Vec<String> = Vec::new();
    for transcript in &load_gost() {
        let suite = suites::by_name(&transcript.cipher).expect("the suite");
        let layer = match suite.cipher {
            suites::BulkCipher::Kuznyechik => "CTR_OMAC/kuznyechik",
            suites::BulkCipher::Magma => "CTR_OMAC/magma",
            suites::BulkCipher::Gost28147Cnt =>
                if suite.key_exchange == suites::KeyExchange::GostVko2001 {
                    "CNT_IMIT/cryptopro-a"
                } else {
                    "CNT_IMIT/tc26-z"
                },
            other => panic!("{}'s cipher {other:?} is not a GOST record \
                             layer", transcript.cipher),
        };
        let entry = format!("{layer} prf={:?}", suite.prf);
        if !seen.contains(&entry) {
            seen.push(entry);
        }
    }
    seen.sort();
    assert_eq!(seen, ["CNT_IMIT/cryptopro-a prf=Gost94",
                      "CNT_IMIT/tc26-z prf=Streebog256",
                      "CTR_OMAC/kuznyechik prf=Streebog256",
                      "CTR_OMAC/magma prf=Streebog256"],
               "the capture covers only {seen:?}");
}
