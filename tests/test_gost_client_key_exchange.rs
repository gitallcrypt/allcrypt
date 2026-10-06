/*!
Our ClientKeyExchange against the one OpenSSL sent.

`tests/transcripts/gost_handshakes.txt` already held five real GOST
handshakes with gost-engine at both ends, and each one contains the
engine's own ClientKeyExchange in the clear - it goes out before
ChangeCipherSpec. **Nothing compared ours to it**, and that is why a
real server refused us with `decode_error` while every test here passed.

And those five would not have been enough. gost-engine's `genpkey`
writes the *canonical* parameter set OID, so its certificates agreed
with our canonicalisation by accident; reverting the fix leaves the
comparison passing on all five. Two more handshakes were captured for
that reason - one on `XchA` and one on TC 26's `paramSetB`, both the same
curve as CryptoPro-A under other names - and the comparison fails on
those. A fixture that happens to agree is the shape of test this
repository has been bitten by before.

The bug: `oids::gost_curve_for` is many-to-one. Eleven parameter set
OIDs name seven curves, because RFC 4357's CryptoPro sets, TC 26's 2012
renumbering (shifted by one, so `paramSetB` is CryptoPro-A) and RFC
4357's two *exchange* sets are three namings of overlapping curves -
`XchA` is CryptoPro-A to the digit. The client rebuilt the ephemeral
key's OID from the curve, which inverts that map, and **the inverse of a
many-to-one map is a choice.** It chose the CryptoPro spelling, so a
server whose certificate said `XchA` got a different OID back than it had
sent. Identical curve, different bytes, `decode_error`.

What these tests check is the property that makes the whole class
impossible: **the ephemeral key's `AlgorithmIdentifier` is the server's,
copied.** Every one of the five captures shows OpenSSL doing exactly
that - the algorithm OID, the parameter set and the `digestParamSet`,
byte for byte, with only the point changed - and that single rule settles
three separate decisions that used to be made independently:

  * which of the several OIDs naming this curve to write;
  * whether the algorithm is `id-GostR3410-2001` or a 2012 one;
  * whether to include the `digestParamSet` that RFC 9215 4.2 deprecates
    and RFC 9189's own example carries.

The answer to all three is "whatever the server said", which is not a
thing a client can get wrong.
*/

use allcrypt::ec::{curves, Point};
use allcrypt::tls::suites;

mod fixture {
    include!("transcripts/loader.rs");
}
use fixture::{load_gost, Transcript};

/// Every handshake message of one type, out of one direction's bytes.
fn messages(stream: &[u8], wanted: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut index = 0;
    while index + 5 <= stream.len() {
        let kind = stream[index];
        let length = u16::from_be_bytes([stream[index + 3], stream[index + 4]])
            as usize;
        let payload = &stream[index + 5..index + 5 + length];
        index += 5 + length;
        if kind != 0x16 {
            continue;
        }
        let mut at = 0;
        while at + 4 <= payload.len() {
            let handshake = payload[at];
            let size = u32::from_be_bytes([0, payload[at + 1], payload[at + 2],
                                           payload[at + 3]]) as usize;
            if handshake == wanted {
                out.push(payload[at + 4..at + 4 + size].to_vec());
            }
            at += 4 + size;
        }
    }
    out
}

/// The server's leaf certificate, out of its Certificate message.
fn leaf_certificate(transcript: &Transcript) -> Vec<u8> {
    let message = messages(&transcript.to_client, 11)
        .into_iter().next()
        .unwrap_or_else(|| panic!("{}: no Certificate message",
                                  transcript.name));
    // A three byte list length, then a three byte length per entry.
    let size = u32::from_be_bytes([0, message[3], message[4], message[5]])
        as usize;
    message[6..6 + size].to_vec()
}

fn client_key_exchange(transcript: &Transcript) -> Vec<u8> {
    messages(&transcript.to_server, 16)
        .into_iter().next()
        .unwrap_or_else(|| panic!("{}: no ClientKeyExchange",
                                  transcript.name))
}

/// Every OID in some DER, in document order, as dotted strings.
fn oids(der: &[u8]) -> Vec<String> {
    fn walk(data: &[u8], out: &mut Vec<String>) {
        let mut index = 0;
        while index + 2 <= data.len() {
            let tag = data[index];
            index += 1;
            let mut length = data[index] as usize;
            index += 1;
            if length & 0x80 != 0 {
                let count = length & 0x7f;
                length = data[index..index + count].iter()
                    .fold(0usize, |acc, byte| (acc << 8) | *byte as usize);
                index += count;
            }
            if index + length > data.len() {
                return;
            }
            let body = &data[index..index + length];
            index += length;
            if tag == 0x06 {
                if let Ok(oid) = allcrypt::asn1::Oid::new(body) {
                    out.push(oid.to_string());
                }
            } else if tag & 0x20 != 0 {
                walk(body, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(der, &mut out);
    out
}

/// The server's SPKI, and the ephemeral SPKI inside its
/// ClientKeyExchange.
fn both_keys(transcript: &Transcript) -> (Vec<u8>, Vec<u8>) {
    let certificate = leaf_certificate(transcript);
    let parsed = allcrypt::x509::Certificate::parse(&certificate)
        .unwrap_or_else(|e| panic!("{}: the certificate: {e}", transcript.name));
    let server_algid = match &parsed.public_key {
        allcrypt::x509::PublicKey::Gost { algorithm_id, .. } =>
            algorithm_id.to_vec(),
        other => panic!("{}: not a GOST key: {other:?}", transcript.name),
    };

    // The ephemeral key is the one SPKI inside the ClientKeyExchange, so
    // its AlgorithmIdentifier is the second `SEQUENCE` under the one
    // `BIT STRING`. Rather than navigate that, the OID list is compared -
    // which is what a server checks anyway.
    let cke = client_key_exchange(transcript);
    (server_algid, cke)
}

#[test]
fn test_the_engine_puts_its_own_algorithm_identifier_in_the_ephemeral_key() {
    // **The measurement the fix is built on.** Every OID in the server's
    // key must appear, in order, inside the ClientKeyExchange the engine
    // sent. If this ever stops holding, copying is the wrong rule and
    // `gost_kex::encode_public_key_like` needs revisiting - so it is
    // asserted rather than assumed.
    let transcripts = load_gost();
    assert!(transcripts.len() >= 3, "only {} transcripts", transcripts.len());
    for transcript in &transcripts {
        let (server_algid, cke) = both_keys(transcript);
        assert!(cke.windows(server_algid.len()).any(|w| w == server_algid),
                "{}: the engine's ClientKeyExchange does not carry the \
                 certificate's AlgorithmIdentifier verbatim", transcript.name);
    }
}

#[test]
fn test_our_client_key_exchange_carries_the_same_oids_as_the_engines() {
    // Built from the same certificate key, then compared by OID list.
    //
    // The bytes cannot match: the ephemeral point and the wrapped secret
    // are random. The OIDs are the whole of what a server parses before
    // it can do anything, and they are what `decode_error` was about.
    let mut checked = 0;
    for transcript in &load_gost() {
        let suite = suites::by_name(&transcript.cipher).expect("the suite");
        let certificate = leaf_certificate(transcript);
        let parsed = allcrypt::x509::Certificate::parse(&certificate)
            .expect("the certificate");
        let (curve_name, x, y, algorithm_id) = match &parsed.public_key {
            allcrypt::x509::PublicKey::Gost { curve, x, y, algorithm_id, .. } =>
                (*curve, x.clone(), y.clone(), *algorithm_id),
            other => panic!("not a GOST key: {other:?}"),
        };
        let curve = curves::by_name(curve_name).expect("the curve");
        let server_public = Point::new(x, y);

        let (ours, _) = match (suite.key_exchange, suite.cipher.ctr_omac()) {
            (suites::KeyExchange::GostVko2001, _) =>
                allcrypt::tls::gost_kex_28147::client_key_exchange_2001(
                    &curve, algorithm_id, &server_public, &[1u8; 32], &[2u8; 32]),
            (_, Some(gost)) => allcrypt::tls::gost_kex::client_key_exchange(
                gost, &curve, algorithm_id, &server_public,
                &[1u8; 32], &[2u8; 32]),
            (_, None) => allcrypt::tls::gost_kex_28147::client_key_exchange(
                &curve, algorithm_id, &server_public, &[1u8; 32], &[2u8; 32]),
        }.expect("our ClientKeyExchange");

        let theirs = client_key_exchange(transcript);
        assert_eq!(oids(&ours), oids(&theirs),
                   "{}: our ClientKeyExchange's OIDs differ from the \
                    engine's", transcript.name);
        checked += 1;
    }
    assert!(checked >= 3, "only {checked} suites compared");
}

#[test]
fn test_an_exchange_parameter_set_is_echoed_rather_than_canonicalised() {
    // **The reported bug, as a test.** `XchA` and CryptoPro-A are the
    // same curve under two OIDs, so a client that rebuilt the OID from
    // the curve answered a server on one with the other. Nothing here
    // noticed, because our own reader accepts both and our own server
    // is the only peer the offline tests have.
    //
    // The capture covers this too now -
    // `kuznyechik_ctr_omac_xcha` is a real handshake against a server
    // whose certificate is on `XchA`, and the engine echoes it - so this
    // test is the cheap always-on version of that, useful because it
    // states the property directly and fails with a message about the
    // property rather than about a list of OIDs.
    //
    // Both are needed. With only the five original captures, reverting
    // the fix fails *this* test and not the comparison, because
    // gost-engine's `genpkey` writes the canonical OID and its
    // certificates agreed with our canonicalisation by accident. That
    // near-miss is the reason the two extra handshakes were captured.
    use allcrypt::asn1::Writer;

    // id-GostR3410-2001-CryptoPro-XchA-ParamSet, 1.2.643.2.2.36.0.
    const XCHA: &[u8] = &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00];
    // id-tc26-gost3410-12-256 and id-tc26-gost3411-12-256.
    const ALGORITHM: &[u8] = &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01];
    const DIGEST: &[u8] = &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02];

    let mut writer = Writer::new();
    writer.write_sequence(|algid| {
        algid.write_oid(ALGORITHM);
        algid.write_sequence(|params| {
            params.write_oid(XCHA);
            params.write_oid(DIGEST);
        });
    });
    let algorithm_id = writer.finish();

    let curve = curves::by_name("gost256-a").expect("XchA is CryptoPro-A");
    let (_, server_public) = curve.generate_key_pair().expect("a server key");
    let (body, _) = allcrypt::tls::gost_kex::client_key_exchange(
        allcrypt::tls::record_gost::CtrOmacSuite::KUZNYECHIK, &curve,
        &algorithm_id, &server_public, &[3u8; 32], &[4u8; 32])
        .expect("the ClientKeyExchange");

    assert!(oids(&body).iter().any(|oid| oid == "1.2.643.2.2.36.0"),
            "the ephemeral key did not echo XchA; it carries {:?}",
            oids(&body));
    assert!(!oids(&body).iter().any(|oid| oid == "1.2.643.2.2.35.1"),
            "the ephemeral key canonicalised XchA to CryptoPro-A, which is \
             the bug a real server refused with decode_error");
}

#[test]
fn test_a_mismatched_algorithm_identifier_is_refused() {
    // Copying the peer's bytes must not become forwarding them
    // unexamined. An AlgorithmIdentifier naming a different curve from
    // the point being written would produce a key that is internally
    // inconsistent - and it is the peer who supplied those bytes.
    use allcrypt::asn1::Writer;

    // id-tc26-gost-3410-12-512-paramSetA on a 256 bit curve.
    const ALGORITHM_512: &[u8] =
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x02];
    const PARAMSET_512_A: &[u8] =
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01];
    const DIGEST_512: &[u8] = &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03];

    let mut writer = Writer::new();
    writer.write_sequence(|algid| {
        algid.write_oid(ALGORITHM_512);
        algid.write_sequence(|params| {
            params.write_oid(PARAMSET_512_A);
            params.write_oid(DIGEST_512);
        });
    });
    let mismatched = writer.finish();

    let curve = curves::by_name("gost256-a").expect("the curve");
    let (_, point) = curve.generate_key_pair().expect("a key");
    let refused = allcrypt::tls::gost_kex::encode_public_key_like(
        &mismatched, &curve, &point).unwrap_err();
    assert!(refused.contains("gost256-a"), "{refused}");

    // And nonsense that is not an AlgorithmIdentifier at all.
    for rubbish in [&b""[..], &b"\x30\x00"[..], &b"not der"[..]] {
        assert!(allcrypt::tls::gost_kex::encode_public_key_like(
                    rubbish, &curve, &point).is_err(),
                "{rubbish:?} was accepted as an AlgorithmIdentifier");
    }
}

#[test]
fn test_the_canonical_encoders_still_agree_with_themselves() {
    // `encode_public_key` and `encode_public_key_2001` are still right
    // for the case they are for: writing a certificate, where *we* choose
    // the curve and so may choose its OID. Both now go through
    // `encode_public_key_like`, so this is the check that the delegation
    // did not change what they produce.
    for name in ["gost256-a", "gost256-b", "gost256-c", "gost256-tc26-a",
                 "gost512-a", "gost512-b", "gost512-c"] {
        let curve = curves::by_name(name).expect("the curve");
        let (_, point) = curve.generate_key_pair().expect("a key");
        let der = allcrypt::tls::gost_kex::encode_public_key(&curve, &point)
            .expect("the 2012 encoding");
        let (back, decoded) = allcrypt::tls::gost_kex::decode_public_key(&der)
            .expect("it reads back");
        assert_eq!(back.name, name);
        assert!(curve.is_on_curve(&decoded));

        if curve.n.bit_len() <= 256 && name != "gost256-tc26-a" {
            let der = allcrypt::tls::gost_kex::encode_public_key_2001(
                &curve, &point).expect("the 2001 encoding");
            let (back, _) = allcrypt::tls::gost_kex::decode_public_key(&der)
                .expect("it reads back");
            assert_eq!(back.name, name);
            assert!(oids(&der).iter().any(|oid| oid == "1.2.643.2.2.19"),
                    "the 2001 encoding does not name id-GostR3410-2001");
        }
    }
}
