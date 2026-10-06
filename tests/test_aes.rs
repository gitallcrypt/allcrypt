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

    let mut crypto = aes::AesCrypto::new(key128).unwrap();

    result.clear();
    crypto.block_encrypt(&plain, &mut result);
    assert_eq!(result, cipher128);
    result.clear();
    crypto.block_decrypt(&cipher128, &mut result);
    assert_eq!(result, plain);

    crypto.setup_key(key192).unwrap();
    result.clear();
    crypto.block_encrypt(&plain, &mut result);
    assert_eq!(result, cipher192);
    result.clear();
    crypto.block_decrypt(&cipher192, &mut result);
    assert_eq!(result, plain);

    crypto.setup_key(key256).unwrap();
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

    let mut crypto = aes::AesCrypto::new(key128).unwrap();

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

/*
#[test]
fn test_aes_ccm() {
    let key = vec![0; 16];
    let nonce = vec![0;11];
    let mut crypto = aes::AesCrypto::new(key).unwrap();
    let mut result: Vec<u8> = vec![];
    let mut tag: Vec<u8> = vec![];
    let additional_data: Vec<u8> = vec![];

    crypto.ccm_encrypt(&[], &mut result, &mut tag, &nonce, &additional_data).unwrap();

    assert_eq!(tag, vec![0xcb, 0x97, 0xfe, 0xcc, 0x25, 0xbc, 0x19, 0xd0,
                         0x9a, 0x87, 0x1d, 0x33, 0xdc, 0x20, 0x05, 0xa1]);

    result.clear();
    let mut crypto = aes::AesCrypto::new(vec![0;16]).unwrap();
    crypto.ccm_encrypt(&[0;16], &mut result, &mut tag, &nonce, &additional_data).unwrap();
    println!("{:x?}", result);
    assert_eq!(tag, vec![0xb3, 0xb4, 0xd9, 0x80, 0xa5, 0x80, 0x70, 0x0f,
                         0x68, 0xb4, 0xdb, 0x64, 0x8d, 0x17, 0xc6, 0x25]);
    assert_eq!(result, vec![0x2e, 0x9a, 0xca, 0x6b, 0xda, 0x54, 0xfc, 0x6f,
                            0x12, 0x50, 0xe8, 0xde, 0x81, 0x3c, 0x63, 0x08]);

}
*/