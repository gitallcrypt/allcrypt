/*!
`vectors/xeddsa.vec` against `allcrypt::ec::xeddsa`: libsignal-protocol-c's
signatures reproduced byte for byte, and its verifiers' verdicts matched.

The file is written by `scripts/make_xeddsa_vectors.py` from
libsignal-protocol-c 2.3.3; see its header. This test needs neither
libsignal nor the network.

Byte equality is the strong half. Both forms take their randomness as an
argument, so the same key, message and `Z` must give the same 64 bytes -
which checks the nonce's prefix and its key bytes, the sign bit's
placement and the negation, none of which a round trip against ourselves
can see. The verdicts are the other half: each row says what *both*
libsignal verifiers said, and the file's generator refuses to write a
file in which the two never disagree.
*/

use allcrypt::ec::xeddsa::{self, Form};

const VECTORS: &str = include_str!("../vectors/xeddsa.vec");

type Record = Vec<(String, String)>;

fn field<'a>(record: &'a Record, name: &str) -> &'a str {
    record.iter().find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .unwrap_or_else(|| panic!("no {name} in {record:?}"))
}

fn bytes<const N: usize>(record: &Record, name: &str) -> [u8; N] {
    let value = hex(field(record, name));
    value.try_into().unwrap_or_else(|v: Vec<u8>| panic!("{name} is {} bytes", v.len()))
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn section(name: &str) -> Vec<Record> {
    let heading = format!("[{name}]");
    let mut inside = false;
    let mut records = Vec::new();
    let mut fields = Record::new();
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if inside && !fields.is_empty() {
                records.push(std::mem::take(&mut fields));
            }
            inside = line == heading;
            continue;
        }
        if !inside || line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !fields.is_empty() {
                records.push(std::mem::take(&mut fields));
            }
            continue;
        }
        let (key, value) = line.split_once(" = ")
            .unwrap_or_else(|| panic!("not a field: {line:?}"));
        fields.push((key.to_string(), value.to_string()));
    }
    if inside && !fields.is_empty() {
        records.push(fields);
    }
    records
}

fn declared(name: &str) -> usize {
    VECTORS.lines()
        .filter_map(|line| line.strip_prefix("#   "))
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next() == Some(name)).then(|| parts.next().unwrap().parse().unwrap())
        })
        .unwrap_or_else(|| panic!("no count for {name} in the header"))
}

#[test]
fn test_the_header_agrees_with_the_body() {
    for name in ["sign", "verify"] {
        assert_eq!(section(name).len(), declared(name), "[{name}]");
    }
    assert_eq!(declared("sign"), 40);
    assert_eq!(declared("verify"), 77);
}

#[test]
fn test_signatures_are_libsignals_byte_for_byte() {
    let rows = section("sign");
    let mut forms = [0, 0];
    for row in &rows {
        let form = Form::by_name(field(row, "form")).unwrap();
        forms[usize::from(form == Form::Specification)] += 1;
        let private: [u8; 32] = bytes(row, "private");
        let random: [u8; 64] = bytes(row, "random");
        let message = hex(field(row, "message"));
        let expected: [u8; 64] = bytes(row, "signature");
        assert_eq!(xeddsa::sign(form, &private, &message, &random), expected,
                   "{} signature over {} bytes", form.name(), message.len());
    }
    assert_eq!(forms, [20, 20]);
}

#[test]
fn test_verdicts_are_libsignals() {
    let rows = section("verify");
    let mut disagreements = 0;
    for row in &rows {
        let public: [u8; 32] = bytes(row, "public");
        let signature: [u8; 64] = bytes(row, "signature");
        let message = hex(field(row, "message"));
        let mut verdicts = Vec::new();
        for form in [Form::Signal, Form::Specification] {
            let expected = field(row, form.name()) == "1";
            let actual = xeddsa::verify(form, &public, &message, &signature);
            assert_eq!(actual.is_ok(), expected, "{}: {} verifier said {:?}",
                       field(row, "case"), form.name(), actual);
            verdicts.push(expected);
        }
        disagreements += usize::from(verdicts[0] != verdicts[1]);
    }
    // The rows that separate the two verifiers: twelve with bit 255 of
    // u set, six Signal signatures by a negative key (with and without
    // S + L), and the two at u = p + 9.
    assert_eq!(disagreements, 20);
}
