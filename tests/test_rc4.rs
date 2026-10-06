use allcrypt::stream_ciphers::{rc4::RC4, StreamCipher};

#[test]
fn test_rc4() {
    let key: Vec<u8> = vec![b'K', b'e', b'y'];
    let keystream: Vec<u8> = vec![0xeb, 0x9f, 0x77, 0x81, 0xb7, 0x34, 0xca, 0x72, 0xa7, 0x19];
    let plain = "Plaintext".as_bytes();
    let ciphertext: Vec<u8> = vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3];

    let mut crypto = RC4::new(key).unwrap();

    let mut result = vec![];
    let empty = vec![0; 256];
    
    crypto.crypt(&empty, &mut result);
    assert_eq!(result[0..keystream.len()], keystream);

    result.clear();
    crypto.reset();
    crypto.crypt(plain, &mut result);
    assert_eq!(result, ciphertext);

    result.clear();
    crypto.reset();
    crypto.crypt(&ciphertext, &mut result);
    assert_eq!(result, plain);

    result.clear();
    let ciphertext1: Vec<u8> = vec![0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3];
    let ciphertext2: Vec<u8> = vec![0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5];
    let plain1 = "Attack".as_bytes();
    let plain2 = " at dawn".as_bytes();
    let key = "Secret".as_bytes();
    let mut crypto = RC4::new(key.to_vec()).unwrap();
    crypto.crypt(plain1, &mut result);
    assert_eq!(result, ciphertext1);
    result.clear();
    crypto.crypt(plain2, &mut result);
    assert_eq!(result, ciphertext2);
}
/// An empty key divided by zero in the key schedule; keys over 256 bytes had
/// their tail silently ignored.
#[test]
fn test_rc4_rejects_bad_key_length() {
    assert!(RC4::new(vec![]).is_err());
    assert!(RC4::new(vec![0; 257]).is_err());
    assert!(RC4::new(vec![0; 1]).is_ok());
    assert!(RC4::new(vec![0; 256]).is_ok());
}

/// RFC 6229 test vectors, key 0102030405 (40 bit) and 0102030405060708090a
/// 0b0c0d0e0f10 (128 bit), keystream at offset 0.
#[test]
fn test_rc4_rfc6229() {
    let mut c = RC4::new(vec![0x01,0x02,0x03,0x04,0x05]).unwrap();
    let mut out = vec![];
    c.crypt(&[0u8; 16], &mut out);
    assert_eq!(allcrypt::to_hex(&out).to_lowercase(), "b2396305f03dc027ccc3524a0a1118a8");

    let key: Vec<u8> = (1..=16).collect();
    let mut c = RC4::new(key).unwrap();
    let mut out = vec![];
    c.crypt(&[0u8; 16], &mut out);
    assert_eq!(allcrypt::to_hex(&out).to_lowercase(), "9ac7cc9a609d1ef7b2932899cde41b97");
}
