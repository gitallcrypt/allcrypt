/*!
`vectors/office_xor.vec` against `allcrypt`'s Office XOR obfuscation:
msoffcrypto-tool's verifiers, keys, arrays and decryptions, written by
`scripts/make_office_xor_vectors.py`, for a password of every length from
1 to 15 and Excel's default, "VelvetSweatshop".
*/

use allcrypt::api;
use allcrypt::stream_ciphers::office_xor::{password_verifier, xor_key, OfficeXor};

const VECTORS: &str = include_str!("../vectors/office_xor.vec");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Each password's lines, as field lists.
fn records() -> Vec<Vec<(String, String)>> {
    let mut out: Vec<Vec<(String, String)>> = Vec::new();
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(" = ").unwrap();
        if key == "Password" {
            out.push(Vec::new());
        }
        out.last_mut().unwrap().push((key.to_string(), value.to_string()));
    }
    out
}

fn get<'a>(record: &'a [(String, String)], name: &str) -> &'a str {
    &record.iter().find(|(k, _)| k == name).unwrap().1
}

#[test]
fn test_msoffcrypto_tools_answers() {
    let all = records();
    assert_eq!(all.len(), 16);
    let mut decryptions = 0;
    for record in &all {
        let password = get(record, "Password").as_bytes();
        let verifier = u16::from_str_radix(get(record, "Verifier"), 16).unwrap();
        let key = u16::from_str_radix(get(record, "Key"), 16).unwrap();
        assert_eq!(password_verifier(password).unwrap(), verifier);
        assert_eq!(xor_key(password).unwrap(), key);
        let xor = OfficeXor::new(password).unwrap();
        assert_eq!(xor.array().to_vec(), hex(get(record, "Array")));
        assert_eq!((xor.verifier(), xor.key()), (verifier, key));
        let ins = record.iter().filter(|(k, _)| k == "In").map(|(_, v)| hex(v));
        let outs = record.iter().filter(|(k, _)| k == "Decrypted").map(|(_, v)| hex(v));
        for (input, output) in ins.zip(outs) {
            let index = input.len() % 16;
            let mut data = input.clone();
            xor.decrypt(&mut data, index);
            assert_eq!(data, output);
            xor.encrypt(&mut data, index);
            assert_eq!(data, input);
            // And through the facade.
            assert_eq!(api::office_xor_decrypt(password, &input, index).unwrap(), output);
            assert_eq!(api::office_xor_encrypt(password, &output, index).unwrap(), input);
            decryptions += 1;
        }
    }
    assert_eq!(decryptions, 80);
}
