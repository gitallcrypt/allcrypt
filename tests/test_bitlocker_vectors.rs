//! BitLocker sector encryption against `vectors/bitlocker.vec`, written by
//! `scripts/make_bitlocker_vectors.py` from OpenSSL's AES and the
//! diffusers in Linux dm-crypt's loop shape: every method, offsets either
//! side of 2^32, and 4096-byte Elephant sectors.

use allcrypt::block_ciphers::bitlocker::{Method, SectorCipher};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 167 + 13) & 0xff) as u8).collect()
}

fn key(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 89 + 7) & 0xff) as u8).collect()
}

#[test]
fn test_bitlocker_vectors() {
    let text = include_str!("../vectors/bitlocker.vec");
    let mut rows = 0;
    for record in text.split("\n\n").filter(|r| r.contains("method = ")) {
        let field = |name: &str| record.lines()
            .find_map(|l| l.strip_prefix(&format!("{name} = ")))
            .unwrap_or_else(|| panic!("no {name} in {record}"));
        let method = Method::from_name(field("method")).unwrap();
        let size: usize = field("size").parse().unwrap();
        let offset: u64 = field("offset").parse().unwrap();
        let want = unhex(field("ciphertext"));
        let mut cipher = SectorCipher::new(method, &key(method.key_len())).unwrap();
        let mut sector = data(size);
        cipher.encrypt_sector(offset, &mut sector).unwrap();
        assert_eq!(sector, want, "{method:?} {size} at {offset}");
        cipher.decrypt_sector(offset, &mut sector).unwrap();
        assert_eq!(sector, data(size));
        rows += 1;
    }
    assert_eq!(rows, 14);
}
