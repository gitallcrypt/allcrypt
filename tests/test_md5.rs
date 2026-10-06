use allcrypt::hash_functions::{HashFunction, md5};

#[test]
fn test_md5_empty() {
    let mut hash = md5::MD5::new(&[]);
    let result = vec![0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                               0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_md5_small() {
    let mut hash = md5::MD5::new(&[]);
    hash.update("The quick brown fox jumps over the lazy dog".as_bytes());

    let result = vec![0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 
                               0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_md5_multi() {
    let mut hash = md5::MD5::new(&[]);
    hash.update("01234567890abcdef01234567890abcdef".as_bytes());

    let result = vec![0x98, 0x69, 0x25, 0x17, 0x5b, 0x56, 0x35, 0x61,
                               0x20, 0x9e, 0x9a, 0x9d, 0xa8, 0x60, 0x92, 0xcd];
    assert_eq!(hash.digest(), result);

    hash.update("01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef".as_bytes());
    let result = vec![0x64, 0xac, 0x0c, 0x35, 0xb1, 0x8e, 0x55, 0xf0,
                               0x7a, 0xa1, 0xe6, 0xbc, 0xfb, 0xd2, 0xee, 0xac];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_md5_63() {
    let mut hash = md5::MD5::new(&[0; 63]);
    let result = vec![0x65, 0xce, 0xcf, 0xb9, 0x80, 0xd7, 0x2f, 0xde,
                                0x57, 0xd1, 0x75, 0xd6, 0xec, 0x1c, 0x3f, 0x64];
    assert_eq!(hash.digest(), result);
}