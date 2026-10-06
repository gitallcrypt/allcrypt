use allcrypt::hash_functions::{HashFunction, sha1};



#[test]
fn test_sha1_empty() {
    let mut hash = sha1::SHA1::new(&[]);
    let result = vec![0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
                               0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
                               0xaf, 0xd8, 0x07, 0x09];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_sha1_63() {
    let mut hash = sha1::SHA1::new(&[]);
    hash.update(&[0; 63]);
    let result = vec![0x0b, 0x8b, 0xf9, 0xfc, 0x37, 0xad, 0x80, 0x2c,
                                0xef, 0xa6, 0x73, 0x3e, 0xc6, 0x2b, 0x09, 0xd5,
                                0xf4, 0x3a, 0x1b, 0x75];
assert_eq!(hash.digest(), result);
}

#[test]
fn test_sha0_empty() {
    let mut hash = sha1::SHA1::new(&[]);
    hash.set_to_sha0();
    let result = vec![0xf9, 0x6c, 0xea, 0x19, 0x8a, 0xd1, 0xdd, 0x56,
                               0x17, 0xac, 0x08, 0x4a, 0x3d, 0x92, 0xc6, 0x10,
                               0x77, 0x08, 0xc0, 0xef];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_sha0_63() {
    let mut hash = sha1::SHA1::new(&[]);
    hash.set_to_sha0();
    hash.update(&[0; 63]);
    let result = vec![0xb4, 0xb8, 0x11, 0xc3, 0x87, 0xed, 0xb0, 0x83,
                               0x00, 0x68, 0x97, 0x8f, 0xbb, 0x96, 0xcd, 0x23,
                               0xb9, 0x9e, 0x6c, 0x43];
assert_eq!(hash.digest(), result);
}
/// Regression: the final block reserved a 16 byte length field (the SHA-512
/// rule) instead of 8 bytes, so every message whose length is 48..=55 mod 64
/// spilled into an extra block and hashed wrong. Lengths outside that window
/// were unaffected, which is why the original empty/63 byte tests passed.
/// Reference digests from Python hashlib.
#[test]
fn test_sha1_final_block_length_field() {
    let cases: [(usize, &str); 15] = [
        (47, "25883f7a0e732e9ab10e594ea59425dfe4d90359"),
        (48, "3e3d6e12b933133de2caa248ea12bd193a67f206"),
        (49, "1e666934c5a35f509aa31bbd9af8a37a1ed13ba6"),
        (50, "6c177354157989a2c6cd7bac80465b13bea25832"),
        (51, "aca32b501c231ef8e2d8703e71415bfbe4ccbc64"),
        (52, "e6479c70bbac662e4cc134cb8bdaade59ff55b66"),
        (53, "d9b66a0801459c8094398ef8f04700a8569c9906"),
        (54, "b05d71c64979cb95fa74a33cdb31a40d258ae02e"),
        (55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
        (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
        (111, "ac877859d427d9192054eea8feb3b8a403ef83a5"),
        (112, "689993727ba37386bb032495e9dbdfb4dd1ba744"),
        (113, "3bcfff44cf3237b9b63c661a530077f794872efc"),
        (119, "ee971065aaa017e0632a8ca6c77bb3bf8b1dfc56"),
        (120, "f34c1488385346a55709ba056ddd08280dd4c6d6"),
    ];
    for (n, expected) in cases {
        let msg = vec![b'a'; n];
        let mut hash = sha1::SHA1::new(&msg);
        assert_eq!(allcrypt::to_hex(&hash.digest()).to_lowercase(), expected,
                   "SHA1 of {} bytes", n);
    }
}
