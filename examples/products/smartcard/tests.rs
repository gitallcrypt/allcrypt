//! Offline tests: the encodings against the documents and against
//! yubikit, and recorded conversations with a card replayed byte for
//! byte. No card and no network.

use super::*;
use crate::card::Replay;

fn rfc(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rfcs").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ------------------------------------------------------------------ TLV --

#[test]
fn test_tlv_round_trips_every_length_form_and_tag_width() {
    for (tag, length) in [(0x53u32, 0usize), (0x53, 0x7F), (0x70, 0x80), (0x70, 0xFF),
                          (0x7F49, 0x100), (0x5F48, 0xFFFF), (0x5FC105, 0x1_0000)] {
        let value: Vec<u8> = (0..length).map(|i| i as u8).collect();
        let encoded = tlv::encode(tag, &value);
        let parsed = tlv::parse(&encoded).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tag, tag, "tag {tag:x}");
        assert_eq!(parsed[0].value, value.as_slice(), "length {length}");
    }
    // The length forms are the shortest: 81 only from 0x80, 82 from 0x100.
    assert_eq!(&tlv::encode(0x53, &[0; 0x7F])[..2], &[0x53, 0x7F]);
    assert_eq!(&tlv::encode(0x53, &[0; 0x80])[..3], &[0x53, 0x81, 0x80]);
    assert_eq!(&tlv::encode(0x53, &[0; 0x100])[..4], &[0x53, 0x82, 0x01, 0x00]);
}

#[test]
fn test_tlv_refuses_what_runs_past_the_end() {
    assert!(tlv::parse(&[0x53, 0x05, 1, 2]).is_err());
    assert!(tlv::parse(&[0x53, 0x82, 0x01]).is_err());
    assert!(tlv::parse(&[0x7F]).is_err());
    assert!(tlv::parse(&[0x53, 0x84, 0, 0, 0, 1]).is_err());
    // Padding between objects is skipped (ISO 7816-4 5.2.2).
    assert_eq!(tlv::parse(&[0x00, 0xFF, 0x53, 0x01, 0x07]).unwrap()[0].value, &[0x07]);
}

// ----------------------------------------------------------------- card --

fn card_with(exchanges: Vec<(&str, &str)>) -> (Card, Replay) {
    let replay = Replay::new(exchanges.into_iter()
        .map(|(apdu, answer)| (unhex(apdu).unwrap(), unhex(answer).unwrap())).collect());
    let card = Card::new(Box::new(replay.clone()));
    (card, replay)
}

#[test]
fn test_long_commands_are_chained() {
    let data = vec![0xAB; 300];
    let first = format!("10DB3FFFFF{}", "AB".repeat(255));
    let second = format!("00DB3FFF2D{}", "AB".repeat(45));
    let (mut card, replay) = card_with(vec![(&first, "9000"), (&second, "9000")]);
    card.call(0x00, 0xDB, 0x3F, 0xFF, &data, "chaining").unwrap();
    assert_eq!(replay.remaining(), 0);

    // A refusal part-way stops the chain and is reported.
    let (mut card, _) = card_with(vec![(&first, "6A80")]);
    assert!(card.call(0x00, 0xDB, 0x3F, 0xFF, &data, "chaining").unwrap_err()
        .contains("6A80"));
}

#[test]
fn test_continued_answers_are_fetched_and_joined() {
    let (mut card, replay) = card_with(vec![("00CB3FFF", "01026103"), ("00C0000003",
                                                                      "0304059000")]);
    let answer = card.call(0x00, 0xCB, 0x3F, 0xFF, &[], "continuation").unwrap();
    assert_eq!(answer, vec![1, 2, 3, 4, 5]);
    assert_eq!(replay.remaining(), 0);

    // A continuation can itself be continued; every piece is fetched.
    let (mut card, replay) = card_with(vec![("00CB3FFF", "016101"), ("00C0000001", "026101"),
                                            ("00C0000001", "039000")]);
    assert_eq!(card.call(0x00, 0xCB, 0x3F, 0xFF, &[], "continuation").unwrap(), vec![1, 2, 3]);
    assert_eq!(replay.remaining(), 0);

    // OATH continues with SEND REMAINING instead of GET RESPONSE.
    let (mut card, replay) = card_with(vec![("00A10000", "016100"), ("00A5000000", "029000")]);
    card.get_response = 0xA5;
    assert_eq!(card.call(0x00, 0xA1, 0, 0, &[], "list").unwrap(), vec![1, 2]);
    assert_eq!(replay.remaining(), 0);
}

/// The `61 xx` loop ran as long as the card kept answering `61 xx`,
/// growing the answer without bound; a simulator over TCP is as able
/// to do that as a card. The recordings all end their continuations.
#[test]
fn test_an_answer_continued_without_end_is_refused() {
    let piece = format!("{}61FF", "AA".repeat(255));
    let mut exchanges = vec![("00CB3FFF".to_string(), piece.clone())];
    for _ in 0..1000 {
        exchanges.push(("00C00000FF".to_string(), piece.clone()));
    }
    let (mut card, replay) = card_with(exchanges.iter().map(|(a, b)| (a.as_str(), b.as_str()))
                                           .collect());
    let error = card.call(0x00, 0xCB, 0x3F, 0xFF, &[], "continuation").unwrap_err();
    assert!(error.contains("keeps answering 61"), "{error}");
    assert!(replay.remaining() > 0);
}

#[test]
fn test_a_wrong_expected_length_is_asked_again() {
    let (mut card, replay) = card_with(vec![("00CA006E", "6C10"), ("00CA006E10",
                                                                 &format!("{}9000", "11".repeat(16)))]);
    assert_eq!(card.call(0x00, 0xCA, 0x00, 0x6E, &[], "6C").unwrap(), vec![0x11; 16]);
    assert_eq!(replay.remaining(), 0);
}

#[test]
fn test_the_replay_refuses_a_command_it_did_not_record() {
    let (mut card, _) = card_with(vec![("00A4040005A000000308", "9000")]);
    let error = card.send(0x00, 0xA4, 0x04, 0x00, &[0xA0, 0, 0, 3, 9]).unwrap_err();
    assert!(error.contains("where the recording has"), "{error}");
}

// ----------------------------------------------------------------- OATH --

/// RFC 4226 appendix D, read out of the document: HOTP of the ASCII
/// secret "12345678901234567890" for counts 0 to 9.
#[test]
fn test_hotp_matches_rfc_4226_appendix_d() {
    let text = rfc("rfc4226.txt");
    // Table 2's header: the line naming all four columns.
    let header = text.lines().position(|line| {
        ["Count", "Hexadecimal", "Decimal", "HOTP"].iter().all(|column| line.contains(column))
    }).expect("table 2");
    let rows: Vec<(u64, String)> = text.lines().skip(header + 1)
        .map(str::split_whitespace).map(Iterator::collect::<Vec<_>>)
        .take_while(|fields| fields.len() == 4)
        .map(|fields| (fields[0].parse().unwrap(), fields[3].to_string())).collect();
    assert_eq!(rows.len(), 10, "RFC 4226 table 2 has ten rows; the parser found {}", rows.len());
    for (count, code) in rows {
        assert_eq!(oath::compute_code(b"12345678901234567890", "sha1", count, 6).unwrap(), code,
                   "count {count}");
    }
}

/// RFC 6238 appendix B, read out of the document. The table says every
/// mode used the 20-byte seed; the reference code in appendix A (and
/// erratum 2866) uses 32 bytes for SHA-256 and 64 for SHA-512, and the
/// table's values are those. The seeds are read out of that code.
#[test]
fn test_totp_matches_rfc_6238_appendix_b() {
    let text = rfc("rfc6238.txt");
    let seed = |name: &str| -> Vec<u8> {
        let start = text.find(&format!("String {name} = ")).expect("seed in appendix A");
        let declaration = &text[start..start + text[start..].find(';').unwrap()];
        let hex: String = declaration.split('"').skip(1).step_by(2).collect();
        unhex(&hex).unwrap()
    };
    let seeds = [("SHA1", seed("seed"), "sha1"), ("SHA256", seed("seed32"), "sha256"),
                 ("SHA512", seed("seed64"), "sha512")];
    assert_eq!((seeds[0].1.len(), seeds[1].1.len(), seeds[2].1.len()), (20, 32, 64));
    let mut checked = 0;
    for line in text.lines() {
        let fields: Vec<&str> = line.split('|').map(str::trim).collect();
        if fields.len() != 7 || fields[1].parse::<u64>().is_err() {
            continue;
        }
        let time: u64 = fields[1].parse().unwrap();
        let (_, secret, hash) = seeds.iter().find(|(mode, _, _)| *mode == fields[5]).unwrap();
        assert_eq!(oath::compute_code(secret, hash, time / 30, 8).unwrap(), fields[4],
                   "{time} {hash}");
        checked += 1;
    }
    assert_eq!(checked, 18, "RFC 6238 table 1 has eighteen rows; the parser found {checked}");
}

#[test]
fn test_base32_and_credential_names() {
    assert_eq!(oath::base32_decode("JBSWY3DPEHPK3PXP").unwrap(), b"Hello!\xde\xad\xbe\xef");
    assert_eq!(oath::base32_decode("jbsw y3dp ehpk 3pxp").unwrap(), b"Hello!\xde\xad\xbe\xef");
    assert!(oath::base32_decode("JBSW1").is_err());
    assert_eq!(oath::credential_name(Some("Example"), "alice", true, 30), "Example:alice");
    assert_eq!(oath::credential_name(Some("Example"), "alice", true, 60), "60/Example:alice");
    assert_eq!(oath::credential_name(None, "alice", false, 60), "alice");
}

// ------------------------------------------------------------------ PIV --

/// The block a PIV card is handed for an RSA signature is the one the
/// library's own PKCS#1 v1.5 signer signs: the library's signature,
/// raised to `e`, gives it back. Both widths a PIV key has at the small
/// end, and every hash.
#[test]
fn test_pkcs1_blocks_are_what_the_library_signs() {
    use allcrypt::bignum::BigUint;
    let key = api::RsaKey::generate(1024).unwrap();
    let numbers: std::collections::HashMap<_, _> = key.numbers().into_iter().collect();
    let (n, e) = (BigUint::from_bytes_be(&numbers["n"]), BigUint::from_bytes_be(&numbers["e"]));
    for hash in ["sha1", "sha256", "sha384", "sha512"] {
        let digest = hash_bytes(hash, b"message").unwrap();
        let block = piv::pkcs1_block(hash, &digest, 128).unwrap();
        let signature = key.sign(hash, &digest).unwrap();
        let opened = BigUint::from_bytes_be(&signature).mod_pow(&e, &n).unwrap();
        let mut padded = vec![0u8; 128 - opened.to_bytes_be().len()];
        padded.extend_from_slice(&opened.to_bytes_be());
        assert_eq!(block, padded, "{hash}");
    }
}

/// Encryption padding comes off, and a signature block is not it.
#[test]
fn test_encryption_padding_comes_off() {
    let digest = hash_bytes("sha256", b"message").unwrap();
    let block = piv::pkcs1_block("sha256", &digest, 128).unwrap();
    assert!(piv::unpad_pkcs1_encryption(&block).is_err());
    let mut encryption = vec![0, 2];
    encryption.extend_from_slice(&[0x55; 9]);
    encryption.push(0);
    encryption.extend_from_slice(b"secret");
    assert_eq!(piv::unpad_pkcs1_encryption(&encryption).unwrap(), b"secret");
}

#[test]
fn test_an_rsa_key_compares_equal_however_it_was_padded() {
    let template = |n: &[u8], e: &[u8]| {
        let mut body = tlv::encode(0x81, n);
        body.extend_from_slice(&tlv::encode(0x82, e));
        body
    };
    let padded = piv::PublicKey::parse(piv::KeyType::Rsa2048,
                                       &template(&[0, 0xC1, 0x02], &[0, 1, 0, 1])).unwrap();
    let bare = piv::PublicKey::parse(piv::KeyType::Rsa2048,
                                     &template(&[0xC1, 0x02], &[1, 0, 1])).unwrap();
    assert_eq!(padded, bare);
}

#[test]
fn test_slots_and_objects() {
    assert_eq!(piv::parse_slot("9a").unwrap(), 0x9A);
    assert_eq!(piv::parse_slot("signature").unwrap(), 0x9C);
    assert_eq!(piv::object_for_slot(0x82), Some(0x5FC10D));
    assert_eq!(piv::object_for_slot(0x95), Some(0x5FC120));
    assert!(piv::parse_slot("9b").is_err(), "9b is the management key, not a key slot");
    assert!(piv::parse_slot("96").is_err());
}

// ------------------------------------------------------------------ OTP --

#[test]
fn test_otp_crc_leaves_yubikits_residual() {
    // A configuration with its complemented CRC appended checks to the
    // fixed residual 0xF0B8 (yubikit's CRC_OK_RESIDUAL).
    let config = otp::hmac_configuration(&[0x42; 20], false).unwrap();
    assert_eq!(otp::crc16(&config[..52]), 0xF0B8);
}

#[test]
fn test_otp_challenge_padding_differs_from_the_last_byte() {
    assert_eq!(otp::pad_challenge(b"ab").unwrap()[2..], [0u8; 62]);
    assert_eq!(otp::pad_challenge(b"a\0").unwrap()[2..], [1u8; 62]);
    assert_eq!(otp::pad_challenge(&[]).unwrap(), vec![0u8; 64]);
    assert!(otp::pad_challenge(&[0; 65]).is_err());
}

// ------------------------------------------------------ recorded cards --

/// `oath add` asks the card for a TOTP code and compares it with the one
/// the secret gives here; a card that stored something else is refused.
/// The recorded conversation is the virtual card's, with one digit of its
/// answer changed.
#[test]
fn test_oath_add_refuses_a_card_whose_code_disagrees() {
    let records = fixtures::records("smartcard.vec", "conversations");
    let record = records.iter().find(|r| fixtures::field(r, "name") == "oath add alice")
        .expect("the fixture has oath add alice");
    let words: Vec<String> = record.iter().filter(|(key, _)| key == "arg")
        .map(|(_, word)| word.clone()).collect();
    let mut exchanges = card::decode_recording(fixtures::field(record, "exchanges")).unwrap();
    let calculate = exchanges.iter_mut().find(|(apdu, _)| apdu[1] == 0xA2)
        .expect("the conversation has a CALCULATE");
    let at = calculate.1.len() - 3;
    calculate.1[at] ^= 1;
    let error = run(words, Some(Card::new(Box::new(Replay::new(exchanges))))).unwrap_err();
    assert!(error.contains("where the secret gives"), "{error}");
}

/// Every conversation `scripts/check_smartcard.py --record` captured with
/// the virtual card, replayed: the example runs the same command against
/// a card that answers from the recording and refuses anything else, so
/// it must send the same bytes in the same order, print the same thing,
/// and write the same files. The host's challenges come from the
/// recorded `--random-seed`.
#[test]
fn test_recorded_conversations_replay_byte_for_byte() {
    let records = fixtures::records("smartcard.vec", "conversations");
    assert!(records.len() >= 80, "the fixture has {} conversations", records.len());
    let work = std::env::temp_dir().join(format!("smartcard-replay-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    for record in &records {
        let name = fixtures::field(record, "name");
        let mut files = Vec::new();
        for (key, value) in record {
            if key == "file" || key == "written" {
                let (file, data) = value.split_once(' ').unwrap_or((value, ""));
                files.push(file.to_string());
                if key == "file" {
                    std::fs::write(work.join(file), fixtures::unhex(data)).unwrap();
                }
            }
        }
        let words: Vec<String> = record.iter().filter(|(key, _)| key == "arg")
            .map(|(_, word)| if files.contains(word) {
                work.join(word).to_string_lossy().into_owned()
            } else if word == "\"\"" {
                String::new()
            } else {
                word.clone()
            })
            .collect();
        let exchanges = card::decode_recording(fixtures::field(record, "exchanges")).unwrap();
        let replay = Replay::new(exchanges);
        let result = run(words, Some(Card::new(Box::new(replay.clone()))));
        let expected = match fixtures::field(record, "output") {
            "-" => String::new(),
            hex => String::from_utf8(fixtures::unhex(hex)).unwrap(),
        };
        match (fixtures::field(record, "ok"), result) {
            ("true", Ok(output)) => assert_eq!(output, expected, "{name}"),
            // Standard error also had whatever was said before the error.
            ("false", Err(error)) => assert!(expected.ends_with(&error), "{name}: {error}"),
            (ok, other) => panic!("{name}: recorded ok = {ok}, replayed {other:?}"),
        }
        assert_eq!(replay.remaining(), 0, "{name}: the recording went further");
        for (key, value) in record {
            if key == "written" {
                let (file, data) = value.split_once(' ').unwrap_or((value, ""));
                assert_eq!(std::fs::read(work.join(file)).unwrap(), fixtures::unhex(data),
                           "{name}: {file}");
            }
        }
    }
    std::fs::remove_dir_all(&work).ok();
}
