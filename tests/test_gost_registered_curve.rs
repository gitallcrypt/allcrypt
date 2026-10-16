/*!
A curve this library does not carry, registered and then used everywhere.

`register_oid(oid, curve_parameters=...)` supplies a curve, and
`register_oid(oid, curve=name)` gives another OID to a curve this library
already has. Either is meant to make the curve work in every place a
built-in one does. Reading went through the registry and several writers
did not: `gost_kex`'s parameter-set tables matched the built-in names and
refused the rest, so a GOST key on a registered curve could be verified
and could not be issued. An alias spelled any way but the curve's own,
such as `GOST256_A`, was accepted at registration and then answered
nowhere.

The curves here are RFC 4357's id-GostR3410-2001-TestParamSet and TC 26's
512 bit paramSetTest, as gost-engine holds them in memory:
`scripts/capture_gost_transcripts.py` records each next to the handshakes
the engine made on it, four in all, and `tests/transcripts/loader.rs`
registers them before any other test reads those rows. So `tests/test_gost_transcript.rs`,
`tests/test_gost_key_transport.rs` and
`tests/test_gost_client_key_exchange.rs` already run it through the
certificate reader, the key exchange, our client's ClientKeyExchange and
the record layer, against the engine. This file holds what those cannot:
the certificate before the registration, the engine's CA signature, and
the writers.

Registrations are process-wide and the tests in one file run on threads
of one process, so every test here takes `SERIAL` first.
*/

use std::sync::Mutex;

use allcrypt::ec::curves;
use allcrypt::registry::{self, Meaning};
use allcrypt::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
use allcrypt::x509::verify::{self, Policy};
use allcrypt::x509::{oids, Certificate, PublicKey};

mod fixture {
    include!("transcripts/loader.rs");
}
use fixture::Transcript;

static SERIAL: Mutex<()> = Mutex::new(());

/// The handshake messages of type `wanted`, out of one direction.
fn messages(stream: &[u8], wanted: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut index = 0;
    while index + 5 <= stream.len() {
        let kind = stream[index];
        let length = u16::from_be_bytes([stream[index + 3], stream[index + 4]]) as usize;
        let payload = &stream[index + 5..index + 5 + length];
        index += 5 + length;
        if kind == 0x14 {
            break;
        }
        if kind != 0x16 {
            continue;
        }
        let mut at = 0;
        while at + 4 <= payload.len() {
            let size = u32::from_be_bytes([0, payload[at + 1], payload[at + 2],
                                           payload[at + 3]]) as usize;
            if payload[at] == wanted {
                out.push(payload[at + 4..at + 4 + size].to_vec());
            }
            at += 4 + size;
        }
    }
    out
}

/// The certificates the server sent, leaf first.
fn chain(transcript: &Transcript) -> Vec<Vec<u8>> {
    let message = messages(&transcript.to_client, 11).into_iter().next()
        .unwrap_or_else(|| panic!("{}: no Certificate message", transcript.name));
    let mut out = Vec::new();
    let mut at = 3;
    while at + 3 <= message.len() {
        let size = u32::from_be_bytes([0, message[at], message[at + 1], message[at + 2]])
            as usize;
        out.push(message[at + 3..at + 3 + size].to_vec());
        at += 3 + size;
    }
    out
}

/// The rows on a curve this library does not carry, as recorded and not
/// yet registered.
fn rows_on_an_unknown_curve() -> Vec<Transcript> {
    let rows: Vec<Transcript> = fixture::load_gost_as_recorded().into_iter()
        .filter(|transcript| !transcript.curve.is_empty())
        .collect();
    assert_eq!(rows.len(), 4, "the capture has {} rows on the test curves", rows.len());
    rows
}

fn oid_of(transcript: &Transcript) -> &str {
    transcript.curve.split_whitespace().next().expect("an OID")
}

/// Before the registration the certificate names a curve nobody here
/// knows; after it, the same bytes are a GOST key on the registered
/// curve, and the engine's CA signature over them verifies.
#[test]
fn test_the_engine_s_certificates_read_and_verify_once_the_curve_is_registered() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for transcript in rows_on_an_unknown_curve() {
        let name = &transcript.name;
        let certificates = chain(&transcript);
        assert_eq!(certificates.len(), 2, "{name}: the leaf and its CA");

        registry::forget(oid_of(&transcript));
        let leaf = Certificate::parse(&certificates[0]).unwrap();
        assert!(matches!(leaf.public_key, PublicKey::UnsupportedCurve { .. }),
                "{name}: the test curve read before it was registered: {:?}",
                leaf.public_key);

        fixture::register_curve(&transcript.curve);
        let leaf = Certificate::parse(&certificates[0]).unwrap();
        let ca = Certificate::parse(&certificates[1]).unwrap();
        match &leaf.public_key {
            PublicKey::Gost { curve, .. } =>
                assert_eq!(*curve, format!("engine-{}", oid_of(&transcript)), "{name}"),
            other => panic!("{name}: {other:?}"),
        }
        verify::verify_signature(&leaf, &ca, &Policy::legacy(1_800_000_000))
            .unwrap_or_else(|e| panic!("{name}: the engine's signature: {e}"));
        verify::verify_signature(&ca, &ca, &Policy::legacy(1_800_000_000))
            .unwrap_or_else(|e| panic!("{name}: the CA's own signature: {e}"));
    }
}

/// Every alias spelling `register` accepts answers under the curve's own
/// name.
#[test]
fn test_an_alias_answers_under_the_curve_s_own_name() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    const ALIAS: &str = "1.3.6.1.4.1.99999.31.1";
    let der = allcrypt::asn1::encode_oid(ALIAS).unwrap();
    for spelling in ["gost256-a", "GOST256_A", "Gost256 A"] {
        registry::register(ALIAS, Meaning::curve(spelling)).unwrap();
        assert_eq!(registry::lookup(ALIAS), Some(Meaning::curve("gost256-a")),
                   "{spelling}");
        assert_eq!(oids::gost_curve_for(&der), Some("gost256-a"), "{spelling}");
    }
    // A registered curve's alias, spelled another way, as well.
    let transcript = &rows_on_an_unknown_curve()[0];
    fixture::register_curve(&transcript.curve);
    let registered = format!("ENGINE_{}", oid_of(transcript));
    registry::register(ALIAS, Meaning::curve(&registered)).unwrap();
    assert_eq!(oids::gost_curve_for(&der).map(str::to_string),
               Some(format!("engine-{}", oid_of(transcript))));
    registry::forget(ALIAS);
    assert_eq!(oids::gost_curve_for(&der), None);
}

/// A GOST certificate can be issued on a registered curve, under either
/// generation's algorithm where the curve allows both, and reads back as
/// itself. Both writers matched the built-in curve names and refused the
/// rest.
#[test]
fn test_a_certificate_can_be_issued_on_the_registered_curve() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut seen = Vec::new();
    for transcript in rows_on_an_unknown_curve() {
        if seen.contains(&transcript.curve) {
            continue;
        }
        seen.push(transcript.curve.clone());
        fixture::register_curve(&transcript.curve);
        let curve = curves::by_name(&format!("engine-{}", oid_of(&transcript))).unwrap();
        let wanted_oid = allcrypt::asn1::encode_oid(oid_of(&transcript)).unwrap();
        let (private, public) = curve.generate_key_pair().unwrap();
        // A 2001 key is 256 bits; the 512 bit curve takes the 2012 form only.
        let generations: &[bool] = if curve.n.bit_len() > 256 { &[false] } else { &[false, true] };
        for &legacy in generations {
            let der = issue(&curve, &private, &public, legacy)
                .unwrap_or_else(|e| panic!("{} legacy={legacy}: {e}", curve.name));
            let parsed = Certificate::parse(&der).unwrap();
            match &parsed.public_key {
                PublicKey::Gost { curve: name, param_set, legacy: read, .. } => {
                    assert_eq!(*name, curve.name, "legacy={legacy}");
                    assert_eq!(param_set.as_bytes(), wanted_oid.as_slice(), "legacy={legacy}");
                    assert_eq!(*read, legacy);
                }
                other => panic!("{} legacy={legacy}: {other:?}", curve.name),
            }
            verify::verify_signature(&parsed, &parsed, &Policy::legacy(1_800_000_000))
                .unwrap_or_else(|e| panic!("{} legacy={legacy}: {e}", curve.name));
        }

        // Under two OIDs the curve has no one name to write, and issuing
        // says so rather than choosing.
        const SECOND: &str = "1.3.6.1.4.1.99999.31.2";
        registry::register(SECOND, Meaning::curve(curve.name)).unwrap();
        let failure = issue(&curve, &private, &public, false).unwrap_err();
        registry::forget(SECOND);
        assert!(failure.contains("registered under 2 OIDs"), "{failure}");
    }
    assert_eq!(seen.len(), 2, "the test curves are not both captured");
}

fn issue(curve: &allcrypt::ec::Curve, private: &allcrypt::bignum::BigUint,
         public: &allcrypt::ec::Point, legacy: bool) -> Result<Vec<u8>, String> {
    let (subject, signer) = if legacy {
        (SubjectKey::Gost2001 { curve, point: public },
         SigningKey::Gost2001 { curve, private })
    } else {
        (SubjectKey::Gost { curve, point: public }, SigningKey::Gost { curve, private })
    };
    let mut builder = CertificateBuilder::new("registered", subject);
    builder.serial = vec![1];
    builder.issuer = vec![(oids::COMMON_NAME, "registered".to_string())];
    builder.subject = vec![(oids::COMMON_NAME, "registered".to_string())];
    builder.not_before = "20200101000000Z";
    builder.not_after = "20400101000000Z";
    builder.sign(&signer)
}
