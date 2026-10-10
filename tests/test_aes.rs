use allcrypt::block_ciphers::{aes, BlockCipher};

#[test]
fn test_aes_block(){
    let key128: Vec<u8> = vec![0; 16];
    let key192: Vec<u8> = vec![0; 24];
    let key256: Vec<u8> = vec![0; 32];
    let plain: Vec<u8> = vec![0; 16];
    let cipher128: Vec<u8> = vec![0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                                  0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
    let cipher192: Vec<u8> = vec![0xaa, 0xe0, 0x69, 0x92, 0xac, 0xbf, 0x52, 0xa3,
                                  0xe8, 0xf4, 0xa9, 0x6e, 0xc9, 0x30, 0x0b, 0xd7];
    let cipher256: Vec<u8> = vec![0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
                                  0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87];
    let mut result = vec![];

    let mut crypto = aes::AesCrypto::new(&key128).unwrap();

    result.clear();
    crypto.block_encrypt(&plain, &mut result);
    assert_eq!(result, cipher128);
    result.clear();
    crypto.block_decrypt(&cipher128, &mut result);
    assert_eq!(result, plain);

    crypto.setup_key(&key192).unwrap();
    result.clear();
    crypto.block_encrypt(&plain, &mut result);
    assert_eq!(result, cipher192);
    result.clear();
    crypto.block_decrypt(&cipher192, &mut result);
    assert_eq!(result, plain);

    crypto.setup_key(&key256).unwrap();
    result.clear();
    crypto.block_encrypt(&plain, &mut result);
    assert_eq!(result, cipher256);
    result.clear();
    crypto.block_decrypt(&cipher256, &mut result);
    assert_eq!(result, plain);
}

#[test]
fn test_aes_block2(){
    let key128: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
                               0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,];
    let plain: Vec<u8> = vec![0xff; 16];
    let cipher128: Vec<u8> = vec![0x09, 0x84, 0xcc, 0xc0, 0x05, 0xd2, 0xc4, 0xb2,
                                  0x9d, 0x16, 0x9f, 0x77, 0x35, 0xaa, 0x89, 0xe4];
    let mut result = vec![];

    let mut crypto = aes::AesCrypto::new(&key128).unwrap();

    result.clear();
    crypto.block_encrypt(&plain, &mut result);
    assert_eq!(result, cipher128);
    result.clear();
    crypto.block_decrypt(&cipher128, &mut result);
    assert_eq!(result, plain);

}

/*
#[test]
fn test_aes_ctr() {
    let key128: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
                               0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,];
    let plain: Vec<u8> = vec![0xff; 32];
    let cipher128: Vec<u8> = vec![0x5b, 0x6c, 0x3f, 0xc3, 0xb1, 0x34, 0xce, 0x77,
                                  0x8c, 0x66, 0x7d, 0x73, 0x35, 0x71, 0x83, 0xe7,
                                  0x5d, 0x1a, 0xa6, 0xd7, 0xc6, 0x13, 0xbb, 0x8d,
                                  0x86, 0x6f, 0x12, 0x48, 0x7b, 0x5b, 0xc3, 0x60];
    let iv = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut result = vec![];

    let mut crypto = aes::AesCrypto::new(key128).unwrap();

    result.clear();
    crypto.ctr_encrypt(&plain, &mut result, &iv);
    assert_eq!(result, cipher128);
}
*/

/// AES-CCM is `block_ciphers::ccm`, checked there against RFC 3610 and
/// SP 800-38C. The `BlockCipher` trait once carried a `ccm_encrypt`
/// stub that answered "not implemented" and a `cbcmac_calc` whose
/// header and tag mask were not RFC 3610's, with the only test of them
/// commented out here; this round trip is what that test was for.
#[test]
fn test_aes_ccm() {
    use allcrypt::block_ciphers::ccm;
    let mut crypto = aes::AesCrypto::new(&[0; 16]).unwrap();
    let nonce = [0u8; 11];
    let aad = b"header";
    let plaintext = [0u8; 16];
    let (ciphertext, tag) = ccm::encrypt(&mut crypto, &nonce, aad, &plaintext, 16).unwrap();
    assert_eq!(ciphertext.len(), 16);
    assert_eq!(tag.len(), 16);
    assert_eq!(ccm::decrypt(&mut crypto, &nonce, aad, &ciphertext, &tag).unwrap(), plaintext);
    assert!(ccm::decrypt(&mut crypto, &nonce, b"", &ciphertext, &tag).is_err());
}