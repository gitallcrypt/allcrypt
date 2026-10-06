//! RFC 9367's own worked TLS 1.3 handshake, replayed offline.
//!
//! **This is the only independent opinion that exists.** Nothing on a
//! normal machine speaks these four cipher suites: OpenSSL has GOST only
//! through an engine and that engine does not do TLS 1.3, and
//! `python-cryptography` has never had Streebog, Kuznyechik, Magma or
//! MGM. Our own client talking to our own server proves the wiring and
//! nothing else, because every mistake in this stack is self-consistent.
//!
//! What the document gives is better than a live server anyway: appendix
//! A prints two complete handshakes with **every intermediate value** -
//! the ECDHE shared secret, each secret of the key schedule, the
//! transcript hashes, both directions' write keys and IVs, the TLSTREE
//! output at each sequence number used, the Finished MACs, and for every
//! record its sequence number, its nonce, its additional data, its
//! plaintext and its ciphertext. So each layer is checked against the
//! document separately rather than only the handshake succeeding.
//!
//! Nothing here is transcribed. The appendix is parsed out of
//! `rfcs/rfc9367.txt` at test time, which is the rule in docs/extending.md
//! ("Where test vectors come from"), and every parse asserts the count it
//! expects before anything uses what it found - a parser that silently
//! found nothing would turn all of this into empty loops that pass.
//!
//! What it covers that no other test here can:
//!
//!   * **Streebog-256 as the TLS 1.3 PRF.** The whole schedule -
//!     HKDF-Extract, Derive-Secret, HKDF-Expand-Label, the Finished
//!     HMACs - under a hash RFC 8446 never mentions.
//!   * **A sixteen byte static IV.** RFC 8446's AEADs all take a twelve
//!     byte nonce, so twelve was a constant here. The length is an input
//!     to the expansion, so a wrong one is a different IV rather than a
//!     length error.
//!   * **TLSTREE per record.** The example's sequence numbers are chosen
//!     by the document to cross the `_S` suite's re-keying boundary,
//!     which a connection would otherwise reach only after eight
//!     records - and after 8192 for the `_L` suites.
//!   * **The nonce's top bit, cleared before MGM sees it.**

use allcrypt::api::AnyHash;
use allcrypt::hash_functions::HashFunction;
use allcrypt::kdf;
use allcrypt::tls::keys13::{Schedule, TrafficKeys};
use allcrypt::tls::record13::Aead13;
use allcrypt::tls::record::SequenceNumber;
use allcrypt::tls::record_mgm::MgmSuite;
use allcrypt::tls::suites::MacAlgorithm;
use allcrypt::tls::ContentType;

const RFC_9367: &str = include_str!("../rfcs/rfc9367.txt");

/// The two worked examples, which are two different suites.
///
/// A.1 is `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S` over a 512 bit
/// curve; A.2 is `TLS_GOSTR341112_256_WITH_MAGMA_MGM_L` with an
/// external PSK, client authentication and a HelloRetryRequest. They
/// are not variations on each other: **Magma's block is eight bytes**,
/// so example 2 exercises a different field polynomial inside MGM, an
/// eight byte static IV, an eight byte tag, and the other pair of
/// TLSTREE constants. An implementation that hard-coded sixteen
/// anywhere passes example 1 and fails example 2.
struct Example {
    name: &'static str,
    heading: &'static str,
    suite: MgmSuite,
    /// How many of its records the document prints in full, and how
    /// many it abbreviates with `[...]`.
    whole: usize,
    abbreviated: usize,
    /// How many record keys carry the other direction's label.
    mislabelled: usize,
    /// Whether the early secret's input keying material is an external
    /// PSK rather than zeros.
    external_psk: bool,
}

const EXAMPLES: [Example; 2] = [
    Example {
        name: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
        heading: "\nA.1.  Example 1",
        suite: MgmSuite::KUZNYECHIK_S,
        whole: 9,
        abbreviated: 8,
        mislabelled: 2,
        external_psk: false,
    },
    Example {
        name: "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
        heading: "\nA.2.  Example 2",
        suite: MgmSuite::MAGMA_L,
        whole: 5,
        abbreviated: 4,
        mislabelled: 0,
        external_psk: true,
    },
];

const HASH: &str = "streebog256";

// --------------------------------------------------------------- parsing ---

/// The appendix, from the heading over the text rather than the one in
/// the table of contents.
fn appendix() -> &'static str {
    let start = RFC_9367.rfind("\nAppendix A.  Test Examples")
        .expect("RFC 9367 has an appendix A");
    &RFC_9367[start..]
}

/// One example's text, from its heading to the next one's.
fn text_of(example: &Example) -> &'static str {
    let text = appendix();
    let start = text.find(example.heading)
        .unwrap_or_else(|| panic!("{} is missing", example.heading));
    let end = EXAMPLES.iter()
        .filter_map(|other| text.find(other.heading))
        .filter(|&at| at > start)
        .min()
        .unwrap_or(text.len());
    assert!(end > start, "the examples are out of order");
    &text[start..end]
}

/// Is this line one row of a hex dump: `00000:   AB CD ...`?
fn dump_row(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let (offset, rest) = trimmed.split_once(':')?;
    if offset.len() != 5 || !offset.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(rest)
}

fn bytes_from(rows: &str) -> Vec<u8> {
    rows.split_whitespace()
        .map(|pair| u8::from_str_radix(pair, 16)
            .unwrap_or_else(|_| panic!("{pair:?} is not a byte")))
        .collect()
}

/// What a labelled dump in this document turned out to be.
///
/// **Eight of the seventeen records are abbreviated.** Their payloads
/// are sixteen kilobytes, and the document prints them with eight digit
/// offsets and `[...]` in place of runs of identical lines. Those bytes
/// are not in the file, so they cannot be replayed - and reconstructing
/// them from the elision's convention would be inventing a test vector,
/// which is the one thing this repository does not do. They are counted
/// and skipped, loudly.
enum Dump {
    Whole(Vec<u8>),
    Abbreviated,
}

/// The hex dump following the first line that *contains* `needle`.
///
/// A substring rather than the whole line, because several labels in
/// this document are split across two lines - `Derived #0 = ... =` then
/// `HKDF-Expand-Label(...)`: - and the dump follows the second.
fn dump_after_raw(section: &str, needle: &str) -> Option<Dump> {
    let mut lines = section.lines();
    while let Some(line) = lines.next() {
        if dump_row(line).is_some() || !line.contains(needle) {
            continue;
        }
        let mut bytes = Vec::new();
        for following in lines.by_ref() {
            let trimmed = following.trim();
            if trimmed.starts_with("[...]") {
                return Some(Dump::Abbreviated);
            }
            // An eight digit offset marks the long form, which is only
            // used for the dumps that are also elided.
            if let Some((offset, _)) = trimmed.split_once(':') {
                if offset.len() == 8 && offset.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(Dump::Abbreviated);
                }
            }
            match dump_row(following) {
                Some(rest) => bytes.extend(bytes_from(rest)),
                None if bytes.is_empty() => continue,
                None => break,
            }
        }
        return Some(Dump::Whole(bytes));
    }
    None
}

/// The whole dump, for a label the document never abbreviates.
fn dump_after(section: &str, needle: &str) -> Option<Vec<u8>> {
    match dump_after_raw(section, needle) {
        Some(Dump::Whole(bytes)) => Some(bytes),
        Some(Dump::Abbreviated) => panic!("{needle:?} is abbreviated here"),
        None => None,
    }
}

fn need(section: &str, needle: &str) -> Vec<u8> {
    dump_after(section, needle)
        .unwrap_or_else(|| panic!("the document has no {needle:?}"))
}

/// One protected record, with everything the document printed about it.
struct Record {
    /// The direction the document's *label* claims. Not to be trusted:
    /// two of the seventeen are copy-pasted from the other direction.
    labelled_side: &'static str,
    /// The sequence number, printed as an IV-width big-endian block.
    sequence: u64,
    record_key: Vec<u8>,
    nonce: Vec<u8>,
    additional_data: Vec<u8>,
    /// `content || real type || padding`, RFC 8446 section 5.2, or
    /// `None` where the document abbreviated it.
    inner: Option<Vec<u8>>,
    /// Header and protected fragment together, as it goes on the wire.
    ciphertext: Option<Vec<u8>>,
}

/// Every "Record payload protection:" block of example 1, in order.
fn records(example: &Example) -> Vec<Record> {
    let text = text_of(example);
    let mut found = Vec::new();
    let blocks: Vec<&str> = text.split("Record payload protection:").collect();
    // The first piece is everything before the first block.
    for block in blocks.iter().skip(1) {
        let (side, key) = match (dump_after(block, "server_record_write_key"),
                                 dump_after(block, "client_record_write_key")) {
            (Some(key), None) => ("server", key),
            (None, Some(key)) => ("client", key),
            // A block naming both would mean the splitter ran two
            // records together, which is worth failing on rather than
            // taking the first.
            (Some(_), Some(_)) => panic!("one block names both directions"),
            (None, None) => panic!("a record block names no write key"),
        };
        let seqnum = need(block, "seqnum:");
        // Printed as a full IV-width block, big endian.
        assert_eq!(seqnum.len(), example.suite.block,
                   "the sequence number is IV-wide");
        let mut sequence = 0u64;
        for byte in &seqnum[seqnum.len() - 8..] {
            sequence = (sequence << 8) | *byte as u64;
        }
        assert!(seqnum[..seqnum.len() - 8].iter().all(|&b| b == 0),
                "a sequence number past 2^64");

        let whole = |needle: &str| match dump_after_raw(block, needle) {
            Some(Dump::Whole(bytes)) => Some(bytes),
            Some(Dump::Abbreviated) => None,
            None => panic!("a record block has no {needle:?}"),
        };
        let inner = whole("TLSInnerPlaintext:");
        let ciphertext = whole("TLSCiphertext:");
        // One abbreviated and the other not would mean the detection is
        // wrong rather than the document being short.
        assert_eq!(inner.is_some(), ciphertext.is_some(),
                   "a record is abbreviated in one field and not the other");

        found.push(Record {
            labelled_side: side,
            sequence,
            record_key: key,
            nonce: need(block, "nonce:"),
            additional_data: need(block, "additional_data:"),
            inner,
            ciphertext,
        });
    }
    found
}

// ----------------------------------------------------------------- tests ---

/// The parse, before anything uses it.
#[test]
fn test_the_document_parses() {
    for example in &EXAMPLES {
        let text = text_of(example);
        assert!(text.len() > 20_000, "{}: the example is too short",
                example.name);
        assert!(text.contains(example.name),
                "{} is not the suite this example negotiates", example.name);

        let found = records(example);
        assert_eq!(found.len(), example.whole + example.abbreviated,
                   "{}: wrong number of records", example.name);
        let from_server = found.iter().filter(|r| r.labelled_side == "server").count();
        assert!(from_server > 0 && from_server < found.len(),
                "the records are all one direction, so nothing checks the other");

        for record in &found {
            assert_eq!(record.record_key.len(), 32, "a record key is 32 bytes");
            assert_eq!(record.nonce.len(), example.suite.block, "the nonce is one block");
            assert_eq!(record.additional_data.len(), 5,
                       "the additional data is the five byte header");
            if let (Some(inner), Some(ciphertext)) =
                (&record.inner, &record.ciphertext) {
                assert!(!inner.is_empty());
                // Header plus fragment, and the fragment is the plaintext
                // plus one block of tag.
                assert_eq!(ciphertext.len(), 5 + inner.len() + example.suite.block,
                           "the ciphertext is header + plaintext + tag");
            }
        }

        // **Eight of the seventeen are abbreviated**, and the count is
        // pinned so that a change in how the document is read cannot
        // quietly turn the replay below into nine records, or one.
        let whole = found.iter().filter(|r| r.inner.is_some()).count();
        assert_eq!(whole, example.whole,
                   "{}: records printed in full", example.name);
        assert_eq!(found.len() - whole, example.abbreviated,
                   "{}: records whose payload the document elides with \
                    `[...]`", example.name);

        // The document says it chose sequence numbers to exercise TLSTREE,
        // so the corpus must actually contain a re-keying boundary. The `_S`
        // suite's third level changes every eight records.
        assert!(found.iter().any(|r| r.sequence >= 8),
                "no record crosses this suite's re-keying boundary, which is \
                 most of what this example is for");
    }
}

/// The key schedule, from the ECDHE shared secret down, under
/// Streebog-256.
///
/// Each value is compared with the document's before the next is derived
/// from it, so a failure names the step rather than the end.
#[test]
fn test_the_key_schedule_under_streebog() {
    for example in &EXAMPLES {
        let text = text_of(example);

        let ecdhe = need(text, "ECDHE:");
        // 64 bytes on A.1's 512 bit curve and 32 on A.2's 256 bit one.
        assert!(ecdhe.len() == 32 || ecdhe.len() == 64,
                "{}: an ECDHE secret of {} bytes", example.name, ecdhe.len());

        // --- Early secret ----------------------------------------------
        //
        // A.1 has no PSK, so the IKM is zeros; A.2 authenticates both
        // ends with an **external** PSK and the IKM is that. One
        // argument apart, and the difference reaches every later
        // secret.
        let psk = example.external_psk.then(|| need(text, "ePSK:"));
        let schedule = Schedule::early(MacAlgorithm::Streebog256, psk.as_deref())
            .expect("a Streebog-256 schedule");
        assert_eq!(schedule.hash_name(), HASH);
        assert_eq!(schedule.secret(),
                   need(text, "EarlySecret = HKDF-Extract").as_slice(),
                   "EarlySecret");

        // --- Handshake secret -------------------------------------------
        let handshake = schedule.handshake(&ecdhe).expect("the handshake secret");
        assert_eq!(handshake.secret(),
                   need(text, "HandshakeSecret = HKDF-Extract").as_slice(),
                   "HandshakeSecret");

        // --- Both handshake traffic epochs ------------------------------
        let th1 = need(text, "TH1 = Transcript-Hash(HM1):");
        let (client, server) = handshake.handshake_traffic(&th1, 32, example.suite.block)
            .expect("handshake traffic keys");

        assert_eq!(server.key,
                   need(text, "server_write_key_hs = HKDF-Expand-Label"),
                   "server_write_key_hs");
        // **The IV is sixteen bytes, and that is the point of this line.**
        // The length goes into what HKDF-Expand-Label hashes, so a twelve
        // byte request does not give the first twelve bytes of this - it
        // gives an unrelated value.
        assert_eq!(server.iv,
                   need(text, "server_write_iv_hs = HKDF-Expand-Label"),
                   "{}: server_write_iv_hs", example.name);
        assert_eq!(server.iv.len(), example.suite.block);
        assert_eq!(client.key,
                   need(text, "client_write_key_hs = HKDF-Expand-Label"),
                   "client_write_key_hs");
        assert_eq!(client.iv,
                   need(text, "client_write_iv_hs = HKDF-Expand-Label"),
                   "client_write_iv_hs");

        assert_eq!(server.finished_key,
                   need(text, "server_finished_key = HKDF-Expand-Label"),
                   "server_finished_key");
        assert_eq!(client.finished_key,
                   need(text, "client_finished_key = HKDF-Expand-Label"),
                   "client_finished_key");

        // --- The two Finished MACs --------------------------------------
        //
        // HMAC-Streebog-256 over a transcript hash, which is the one place
        // the Finished construction is visible separately from a handshake
        // succeeding.
        let server_finished = need(text, "Transcript-Hash(HMFinished):");
        assert_eq!(hmac(&server.finished_key, &server_finished),
                   need(text, "HMAC(server_finished_key,Transcript-Hash(HMFinished)):"),
                   "the server's Finished");

        let th2 = need(text, "TH2 = Transcript-Hash(HM2):");
        assert_eq!(hmac(&client.finished_key, &th2),
                   need(text, "HMAC(client_finished_key, TH2):"),
                   "the client's Finished");

        // --- Master secret and the application epoch ---------------------
        let master = handshake.master().expect("the master secret");
        assert_eq!(master.secret(),
                   need(text, "MainSecret = HKDF-Extract").as_slice(),
                   "MainSecret");

        let (client_ap, server_ap) = master.application_traffic(&th2, 32, example.suite.block)
            .expect("application traffic keys");
        assert_eq!(server_ap.key,
                   need(text, "server_write_key_ap = HKDF-Expand-Label"),
                   "server_write_key_ap");
        assert_eq!(server_ap.iv,
                   need(text, "server_write_iv_ap = HKDF-Expand-Label"),
                   "server_write_iv_ap");
        assert_eq!(client_ap.key,
                   need(text, "client_write_key_ap = HKDF-Expand-Label"),
                   "client_write_key_ap");
        assert_eq!(client_ap.iv,
                   need(text, "client_write_iv_ap = HKDF-Expand-Label"),
                   "client_write_iv_ap");
    }
}

fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = allcrypt::mac::Hmac::new(AnyHash::new(HASH).unwrap(), key);
    use allcrypt::Mac;
    mac.update(message);
    mac.digest()
}

/// TLSTREE, at every sequence number the document prints one for.
///
/// The example's numbers are 0..3 for the handshake epoch and 0, 1, 2,
/// 3, 8, 9, 10 for the application one - and 8 is where this suite's
/// third level changes, which is the whole reason the document chose
/// them. A schedule using another suite's constants agrees up to there
/// and diverges after.
///
/// **The values are matched to a key rather than read off the label**,
/// because one label in the document is wrong. See
/// `test_the_document_mislabels_one_record_key` below.
#[test]
fn test_tlstree_at_every_printed_sequence() {
    for example in &EXAMPLES {
        let text = text_of(example);
        let keys = epoch_keys(example);

        let mut checked = 0;
        let mut distinct = std::collections::HashSet::new();
        let mut mislabelled = 0;
        // The sequence numbers the example actually uses, rather than a
        // range: A.2's records are at 0, 1, 128, 129 and 130, which the
        // document chose to cross `MAGMA_MGM_L`'s boundary at 128.
        let mut sequences: Vec<u64> =
            records(example).iter().map(|r| r.sequence).collect();
        sequences.sort_unstable();
        sequences.dedup();
        assert!(sequences.len() >= 4, "{}: too few distinct sequence numbers \
                to see a re-keying boundary", example.name);

        for (side, epoch, write_key, _) in &keys {
            for &sequence in &sequences {
                let needle = format!("TLSTREE({side}_write_key_{epoch}, {sequence}):");
                // The same label appears more than once when two records
                // share a key, so every occurrence is checked rather than
                // the first.
                for want in every_dump_after(text, &needle) {
                    let ours = example.suite.record_key(write_key, sequence);
                    if ours == want {
                        distinct.insert(want);
                        checked += 1;
                        continue;
                    }
                    // Not this key. It must be some other epoch's, or the
                    // derivation is wrong rather than the label.
                    let owner = keys.iter().find(|(_, _, key, _)| {
                        example.suite.record_key(key, sequence) == want
                    });
                    assert!(owner.is_some(),
                            "TLSTREE({side}_write_key_{epoch}, {sequence}) matches \
                             no write key in the document");
                    mislabelled += 1;

                }
            }
        }
        assert!(checked >= 8, "{}: only {checked} TLSTREE values were \
                checked", example.name);
        assert_eq!(mislabelled, example.mislabelled,
                   "{}: mislabelled record keys (see \
                    `test_the_document_mislabels_two_record_keys`)",
                   example.name);
        // The point of re-keying is that the keys differ. If every printed
        // value were the same this test would pass on an implementation that
        // ignored the sequence number entirely.
        assert!(distinct.len() > 4,
                "only {} distinct record keys, so the sequence number may not \
                 be reaching the derivation", distinct.len());
    }
}

/// **RFC 9367's appendix A.1 mislabels two record keys.**
///
/// Two of the seventeen record blocks carry the other direction's
/// label, copy-pasted:
///
///   * a block headed `---Client---`, protecting 16 KB of application
///     data, is labelled `server_record_write_key =
///     TLSTREE(server_write_key_ap, 1)`;
///   * a block headed `---Server---`, protecting the server's
///     `close_notify`, is labelled `client_record_write_key =
///     TLSTREE(client_write_key_ap, 10)`.
///
/// In each case three things agree against the label, and they come
/// from three different derivations: the `---Client---`/`---Server---`
/// heading, the printed record key (which is `TLSTREE` of the *other*
/// side's write key), and the printed nonce (which is the other side's
/// IV). Both labels also appear a second time in the document, on the
/// right block, with the right value - so the document contradicts
/// itself rather than being consistently wrong, which is what makes it
/// a misprint rather than a reading this implementation got backwards.
///
/// Pinned rather than worked around silently, exactly as
/// `hash_functions::gost94` pins RFC 5831's transposed `K[1]`: if a
/// refetched document fixes them, this test fails and says so, and
/// `epoch_of` above can stop ignoring the labels.
#[test]
fn test_the_document_mislabels_two_record_keys() {
    for example in &EXAMPLES {
        let text = text_of(example);
        let mut wrong = Vec::new();
        for record in records(example) {
            let (side, epoch, _, _) = epoch_of(example, &record);
            if side != record.labelled_side {
                wrong.push((record.labelled_side, side, epoch, record.sequence));
            }
        }
        assert_eq!(wrong.len(), example.mislabelled,
                   "{}: expected {} mislabelled record keys; found {wrong:?}",
                   example.name, example.mislabelled);
        if example.mislabelled == 0 {
            continue;
        }

        // Named, so that a *different* pair of misprints cannot pass as
        // this one.
        assert!(wrong.contains(&("server", "client", "ap", 1)),
                "the client's 16 KB record is not the one labelled as the \
                 server's: {wrong:?}");
        assert!(wrong.contains(&("client", "server", "ap", 10)),
                "the server's close_notify is not the one labelled as the \
                 client's: {wrong:?}");

        // And each wrong label has a right printing elsewhere.
        for needle in ["TLSTREE(server_write_key_ap, 1):",
                       "TLSTREE(client_write_key_ap, 10):"] {
            let printed = every_dump_after(text, needle);
            assert_eq!(printed.len(), 2, "{needle} does not appear twice");
            assert_ne!(printed[0], printed[1],
                       "{needle}: the two printings agree, so nothing is wrong");
        }
    }
}

/// Every dump under a label that occurs more than once.
fn every_dump_after(section: &str, needle: &str) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    let mut rest = section;
    while let Some(at) = rest.find(needle) {
        let after = &rest[at..];
        if let Some(Dump::Whole(bytes)) = dump_after_raw(after, needle) {
            found.push(bytes);
        }
        rest = &after[needle.len()..];
    }
    found
}

/// Every protected record: decrypt the document's ciphertext, and
/// re-encrypt its plaintext back to the same bytes.
///
/// Both directions matter and they fail differently. Decrypting proves
/// we reach the same keystream and the same tag as whoever produced the
/// document; re-encrypting proves we would put the same bytes on the
/// wire, which decryption alone does not - a record layer that padded
/// differently, or built the additional data from the plaintext's length
/// rather than the fragment's, still decrypts what it is given.
#[test]
fn test_every_record_decrypts_and_re_encrypts() {
    for example in &EXAMPLES {
        let _text = text_of(example);
        let mut decrypted = 0;
        let mut skipped = 0;
        for (index, record) in records(example).into_iter().enumerate() {
            let (Some(inner), Some(ciphertext)) =
                (record.inner.clone(), record.ciphertext.clone()) else {
                // Abbreviated: its key, nonce and additional data are still
                // checked by the other tests here, but its bytes are not in
                // the file.
                skipped += 1;
                continue;
            };
            // The keys come from the document here rather than from our
            // schedule, so this test isolates the record layer: a key
            // schedule failure belongs to the test above.
            let keys = TrafficKeys {
                secret: Vec::new(),
                // `record_key` is TLSTREE's output. The record layer takes
                // the *write* key and derives it, so the derivation has to
                // be reversed out - which is exactly what cannot be done, so
                // the write key is looked up instead.
                key: epoch_of(example, &record).2,
                iv: epoch_of(example, &record).3,
                finished_key: Vec::new(),
            };

            // The suite re-keys per record, so the record's own key must be
            // what our layer computes from the write key.
            assert_eq!(example.suite.record_key(&keys.key, record.sequence),
                       record.record_key,
                       "record {index}: the record key");

            let header = &ciphertext[..5];
            let fragment = &ciphertext[5..];
            assert_eq!(header, record.additional_data.as_slice(),
                       "record {index}: the header is the additional data");

            let mut reader = Aead13::starting_at_with_rekeying(
                example.suite.aead, "streebog256", keys.clone(), example.suite.block,
                SequenceNumber::at(record.sequence), Some(example.suite))
                .expect("build the record protection");

            let (content_type, plaintext) = reader.decrypt(fragment)
                .unwrap_or_else(|e| panic!("record {index}: {}", e.describe()));

            // The document's TLSInnerPlaintext is `content || type ||
            // padding`; ours comes back split.
            let real_type = ContentType::from_byte(
                *inner.iter().rev().find(|&&b| b != 0)
                    .expect("an all-zero inner plaintext"));
            assert_eq!(content_type, real_type, "record {index}: content type");
            let content_len = inner.iter().rposition(|&b| b != 0)
                .expect("a type byte");
            assert_eq!(plaintext, inner[..content_len],
                       "record {index}: plaintext");

            // And back again, byte for byte including the padding the
            // document used.
            let padding = inner.len() - content_len - 1;
            let mut writer = Aead13::starting_at_with_rekeying(
                example.suite.aead, "streebog256", keys, example.suite.block,
                SequenceNumber::at(record.sequence), Some(example.suite)).unwrap();
            let produced = writer.encrypt(content_type, &plaintext, padding)
                .unwrap_or_else(|e| panic!("record {index}: {}", e.describe()));
            assert_eq!(produced, fragment, "record {index}: re-encrypted");

            decrypted += 1;
        }
        assert_eq!(decrypted, example.whole, "{}: replayed", example.name);
        assert_eq!(skipped, example.abbreviated);
        // Both directions and both epochs, or a whole half of the record
        // layer would be untested by rows that all happened to be one way.
        let sides: std::collections::HashSet<&str> =
            records(example).iter().filter(|r| r.inner.is_some())
                .map(|r| epoch_of(example, r).0).collect();
        assert_eq!(sides.len(), 2, "the replayed records are all one direction");
    }
}

/// Which of the four epochs a record belongs to, worked out from its
/// bytes rather than from its label.
///
/// **The label cannot be used**, because two of the seventeen are
/// wrong - see `test_the_document_mislabels_two_record_keys`. Two
/// independent derivations have to agree instead: the record key must
/// be `TLSTREE(write_key, seqnum)` for that epoch, *and* the printed
/// nonce must be that epoch's IV XOR the sequence number. Either alone
/// could coincide; both together identify the epoch.
fn epoch_of(example: &Example, record: &Record)
            -> (&'static str, &'static str, Vec<u8>, Vec<u8>) {
    let mut found: Vec<_> = epoch_keys(example).into_iter()
        .filter(|(_, _, key, iv)| {
            example.suite.record_key(key, record.sequence) == record.record_key
                && nonce_from(iv, record.sequence) == record.nonce
        }).collect();
    assert_eq!(found.len(), 1,
               "{} epochs fit this record's key and nonce, so it cannot be \
                identified", found.len());
    found.pop().unwrap()
}

/// RFC 8446 section 5.3's nonce, with RFC 9367's top-bit mask.
fn nonce_from(iv: &[u8], sequence: u64) -> Vec<u8> {
    let mut nonce = iv.to_vec();
    let counter = sequence.to_be_bytes();
    let offset = nonce.len() - counter.len();
    for (byte, value) in nonce[offset..].iter_mut().zip(counter.iter()) {
        *byte ^= value;
    }
    MgmSuite::mask_nonce(&mut nonce);
    nonce
}

/// The four epochs' write keys and IVs, from the document.
fn epoch_keys(example: &Example) -> Vec<(&'static str, &'static str, Vec<u8>, Vec<u8>)> {
    let text = text_of(example);
    let mut all = Vec::new();
    for (side, epoch) in [("server", "hs"), ("client", "hs"),
                          ("server", "ap"), ("client", "ap")] {
        let key = need(text, &format!("{side}_write_key_{epoch} = HKDF-Expand-Label"));
        let iv = need(text, &format!("{side}_write_iv_{epoch} = HKDF-Expand-Label"));
        all.push((side, epoch, key, iv));
    }
    all
}

/// The nonce the document prints for each record is the one our record
/// layer builds - including the cleared top bit.
///
/// Worth its own test because a wrong nonce fails `decrypt` the same way
/// a wrong key does, and the two are fixed in different places.
#[test]
fn test_every_nonce_matches_the_document() {
    for example in &EXAMPLES {
        let _text = text_of(example);
        let mut checked = 0;
        for (index, record) in records(example).into_iter().enumerate() {
            // `epoch_of` already requires the nonce to match, so this
            // asserts the top bit separately: without the mask the nonce
            // would differ only in that bit, and only for an IV that has it
            // set - which is three of the four epochs here.
            let (_, _, _, iv) = epoch_of(example, &record);
            assert_eq!(nonce_from(&iv, record.sequence), record.nonce,
                       "record {index}: nonce");
            if iv[0] & 0x80 != 0 {
                let mut unmasked = record.nonce.clone();
                unmasked[0] |= 0x80;
                assert_ne!(unmasked, record.nonce,
                           "record {index}: the mask changed nothing");
                checked += 1;
            }
        }
        assert!(checked > 0,
                "no epoch's IV has the top bit set, so nothing here tests the \
                 mask RFC 9367 section 4.1.1 applies");
    }
}

/// HKDF-Extract over Streebog-256 is HMAC with the salt as the key,
/// which is the one step of the schedule that is not Expand-Label.
///
/// Checked directly because `Schedule` hides it, and because a wrong
/// argument order there produces a perfectly good secret that agrees
/// with nothing.
#[test]
fn test_extract_is_hmac_with_the_salt_as_key() {
    for example in &EXAMPLES {
        let text = text_of(example);
        let zeros = [0u8; 32];
        let ikm = if example.external_psk { need(text, "ePSK:") } else { zeros.to_vec() };
        let early = kdf::hkdf_extract(AnyHash::new(HASH).unwrap(), &zeros, &ikm);
        assert_eq!(early, need(text, "EarlySecret = HKDF-Extract"),
                   "{}: EarlySecret", example.name);
        // The other order gives the same value here only because both
        // arguments are zeros - which is why the handshake secret, whose
        // arguments differ, is the one that settles it.
        let derived = need(text, r#"HKDF-Expand-Label(EarlySecret, "derived", "", 32):"#);
        let ecdhe = need(text, "ECDHE:");
        let handshake = kdf::hkdf_extract(AnyHash::new(HASH).unwrap(), &derived, &ecdhe);
        assert_eq!(handshake, need(text, "HandshakeSecret = HKDF-Extract"));
        let swapped = kdf::hkdf_extract(AnyHash::new(HASH).unwrap(), &ecdhe, &derived);
        assert_ne!(swapped, handshake,
                   "the two arguments are interchangeable, so this proves nothing");
    }
}

/// **The document's IV labels disagree with its IV values in example
/// 2.**
///
/// A.2 negotiates `TLS_GOSTR341112_256_WITH_MAGMA_MGM_L`, whose block
/// is eight bytes, so RFC 9367 section 4.1.1's `IVlen = n` makes every
/// static IV eight bytes - and all four of them are printed as eight.
/// Two of the four labels nevertheless say `HKDF-Expand-Label(SHTS,
/// "iv", "", 16)`, carried over from example 1.
///
/// It matters more than a typo usually would, because **the length is
/// an input to the expansion**: asking for sixteen bytes does not give
/// sixteen bytes of which the first eight are these, it gives an
/// unrelated value. An implementation that followed the label rather
/// than the value would disagree with the document's own records, which
/// is what `test_every_record_decrypts_and_re_encrypts` would then
/// catch - so the two readings are distinguishable, and this test says
/// which one is right.
#[test]
fn test_the_documents_iv_labels_disagree_with_its_iv_values() {
    let magma = &EXAMPLES[1];
    assert_eq!(magma.suite.block, 8);
    let text = text_of(magma);

    let mut said_sixteen = 0;
    for (side, epoch) in [("server", "hs"), ("client", "hs"),
                          ("server", "ap"), ("client", "ap")] {
        let label = format!("{side}_write_iv_{epoch} = HKDF-Expand-Label");
        let line = text.lines().find(|l| l.contains(&label))
            .unwrap_or_else(|| panic!("{label} is missing"));
        let value = need(text, &label);

        // Whatever the label says, the value is one block.
        assert_eq!(value.len(), magma.suite.block,
                   "{label}: the printed value is not one block");
        if line.contains("\"iv\", \"\", 16)") {
            said_sixteen += 1;
        }
    }
    assert_eq!(said_sixteen, 2,
               "exactly two of A.2's four IV labels say 16 where the value \
                is 8; this run found {said_sixteen}");
}

/// The external PSK's binder, which is the other thing example 2 has
/// that example 1 does not.
///
/// `binder_key = Derive-Secret(EarlySecret, "ext binder", "")` and the
/// binder is `HMAC(HKDF-Expand-Label(binder_key, "finished", "", 32),
/// Hash(Truncate(ClientHello1)))`. **A binder is self-consistent
/// whatever it got wrong** - only a peer that computed the same one can
/// say otherwise - so the document is the only check there is.
///
/// `"ext binder"` rather than `"res binder"` is the part that is silent:
/// the two labels are the same length and produce equally valid keys,
/// and an external PSK bound with the resumption label is refused by
/// every server with no explanation beyond `decrypt_error`.
#[test]
fn test_the_external_psk_binder() {
    let magma = &EXAMPLES[1];
    let text = text_of(magma);

    let epsk = need(text, "ePSK:");
    let schedule = Schedule::early(MacAlgorithm::Streebog256, Some(&epsk))
        .expect("an early schedule over the external PSK");

    let binder_key = schedule.binder_key(true)
        .expect("the external binder key");
    assert_eq!(binder_key,
               need(text, r#"HKDF-Expand-Label(EarlySecret, "ext binder", "", 32):"#),
               "binder_key");

    let finished_key = need(text, "finished_binder_key:");
    assert_eq!(finished_key,
               need(text, r#"HKDF-Expand-Label(binder_key, "finished", "", 32):"#),
               "the document's two printings of the binder's finished key");

    // And the resumption label gives a different key, so "ext binder"
    // is doing something rather than being decoration.
    assert_ne!(schedule.binder_key(false).expect("the resumption binder key"),
               binder_key,
               "the two binder labels produce the same key");
}

/// **The CertificateVerify signature, against the document's own.**
///
/// RFC 9367 section 5.3 encodes it as `str_l(r) | str_l(s)`, and `str_l`
/// is the **little endian** one - so it differs from RFC 9215's
/// certificate encoding in two ways at once: the components are the
/// other way round *and* each is reversed.
///
/// Neither change is visible on its own. Swapping the order alone, or
/// reversing the bytes alone, each gives a signature of exactly the
/// right length that verifies against nothing - and two implementations
/// making the same mistake interoperate perfectly. The only thing that
/// can settle it is a signature somebody else produced, which is what
/// this appendix is.
///
/// Example 1 signs with `gostr34102012_256b`, which RFC 9367 section
/// 5.2 binds to `id-GostR3410-2001-CryptoPro-A-ParamSet` - this
/// library's `gost256-a`. The certificate is the one in the document's
/// own Certificate message.
#[test]
fn test_the_certificate_verify_signature() {
    use allcrypt::tls::handshake13::{self as hs13, scheme, Side13};
    use allcrypt::x509::{Certificate, PublicKey};

    let example = &EXAMPLES[0];
    let text = text_of(example);

    // The transcript hash the document signs over, and the signature.
    let transcript = need(text, "Transcript-Hash(HMCertificateVerify):");
    let sgn = need(text, "sgn:");
    assert_eq!(sgn.len(), 64, "a 256 bit scheme signs 64 bytes");

    // The server's certificate, out of the Certificate message.
    let der = certificate_der(text);
    let leaf = Certificate::parse(&der).expect("parse the server certificate");
    let (curve, x, y) = match &leaf.public_key {
        PublicKey::Gost { curve, x, y, .. } => (*curve, x.clone(), y.clone()),
        other => panic!("the certificate carries {other:?}"),
    };
    // RFC 9367 section 5.2 binds the scheme to the curve, so the
    // certificate's curve must be the one `gostr34102012_256b` names -
    // otherwise the signature would be checked under a curve nobody
    // used, which is the gap that binding exists to close.
    assert_eq!(scheme::curve_name(scheme::GOSTR34102012_256B), Some("gost256-a"));
    assert_eq!(curve, "gost256-a", "the certificate is on another curve");

    // The content is RFC 8446's: 64 spaces, the context string, a zero
    // byte, then the transcript hash.
    let content = hs13::certificate_verify_content(Side13::Server, &transcript);

    let curve = allcrypt::ec::curves::by_name(curve).unwrap();
    let point = allcrypt::ec::Point::new(x, y);

    let hash_name = scheme::hash_name(scheme::GOSTR34102012_256B).unwrap();
    assert_eq!(hash_name, "streebog256");
    let mut hasher = AnyHash::new(hash_name).unwrap();
    hasher.update(&content);
    let digest = hasher.digest();

    let signature = curve.gost_signature_from_bytes_13(&sgn)
        .expect("decode the signature");
    assert!(curve.gost_verify(&point, &digest, &signature).unwrap(),
            "the document's own signature does not verify");

    // ---- and each wrong reading must fail --------------------------
    //
    // Without these the test would pass on an implementation that had
    // the encoding backwards, because a wrong decoding of a valid
    // signature is still two integers in range.

    // RFC 9215's encoding: `s || r`, big endian. That is what a
    // certificate carries, and it is what this would be if the 1.3
    // profile reused it.
    let as_certificate = curve.gost_signature_from_bytes(&sgn).unwrap();
    assert!(!curve.gost_verify(&point, &digest, &as_certificate).unwrap(),
            "the certificate encoding also verifies, so this proves nothing");

    // The order right and the bytes not reversed.
    let mut big_endian = sgn.clone();
    let (r, s) = big_endian.split_at_mut(32);
    r.reverse();
    s.reverse();
    let unreversed = curve.gost_signature_from_bytes_13(&big_endian).unwrap();
    assert!(!curve.gost_verify(&point, &digest, &unreversed).unwrap(),
            "the byte order does not matter, so this proves nothing");

    // The bytes reversed and the components not swapped.
    let mut swapped = sgn.clone();
    swapped.rotate_left(32);
    let wrong_order = curve.gost_signature_from_bytes_13(&swapped).unwrap();
    assert!(!curve.gost_verify(&point, &digest, &wrong_order).unwrap(),
            "the component order does not matter, so this proves nothing");

    // And the round trip: our encoder produces the document's bytes.
    assert_eq!(curve.gost_signature_bytes_13(&signature).unwrap(), sgn,
               "our encoder does not reproduce the document's signature");
}

/// The server certificate, out of example 1's Certificate message.
///
/// It is printed as a continuation-indented `vector:` rather than as a
/// hex dump, so it is read from the `ASN.1Cert` field rather than by
/// `dump_after`.
fn certificate_der(text: &str) -> Vec<u8> {
    let at = text.find("ASN.1Cert:").expect("a certificate in the document");
    let after = &text[at..];
    let start = after.find("vector:").expect("the certificate's bytes");
    let mut hex = String::new();
    for line in after[start..].lines() {
        let piece = line.trim().trim_start_matches("vector:").trim();
        // **The whole field must be hex, not its first characters.**
        // The line after the certificate is `extensions:`, whose `e` is
        // a perfectly good hex digit - so a `take_while` here appends
        // one nibble and every byte after it is read one nibble off.
        // Found by the odd length rather than by a wrong certificate,
        // which is the lucky version of this mistake.
        if piece.is_empty() || !piece.chars().all(|c| c.is_ascii_hexdigit()) {
            if hex.is_empty() {
                continue;
            }
            break;
        }
        hex.push_str(piece);
    }
    assert!(hex.len().is_multiple_of(2),
            "the certificate parsed as an odd number of hex digits");
    assert!(hex.len() > 500, "the certificate parsed as {} hex digits", hex.len());
    (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}
