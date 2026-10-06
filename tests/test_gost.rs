use allcrypt::block_ciphers::{gost, BlockCipher};
use allcrypt::Mac;

#[test]
fn test_gost_ecb() {
    let key: Vec<u8> = vec![0xBE, 0x5E, 0xC2, 0x00, 0x6C, 0xFF, 0x9D, 0xCF,
                            0x52, 0x35, 0x49, 0x59, 0xF1, 0xFF, 0x0C, 0xBF,
                            0xE9, 0x50, 0x61, 0xB5, 0xA6, 0x48, 0xC1, 0x03,
                            0x87, 0x06, 0x9C, 0x25, 0x99, 0x7C, 0x06, 0x72];
    let plain: Vec<u8> = vec![0x0D, 0xF8, 0x28, 0x02, 0xB7, 0x41, 0xA2, 0x92];
    let crypt: [u8; 8] = [0x07, 0xF9, 0x02, 0x7D, 0xF7, 0xF7, 0xDF, 0x89];
 
    let mut result = vec![]; 
    let mut crypto = gost::GostCrypto::new(key, String::from("id-GostR3411-94-TestParamSet")).unwrap();
    crypto.ecb_encrypt(&plain, &mut result).unwrap();

    assert_eq!(result, crypt);
 
    let mut result_dec = vec![]; 
    crypto.ecb_decrypt(&result, &mut result_dec).unwrap();

    assert_eq!(result_dec, plain);
}

#[test]
fn test_gost_cbc() {
    let key: Vec<u8> = vec![0xBE, 0x5E, 0xC2, 0x00, 0x6C, 0xFF, 0x9D, 0xCF,
                            0x52, 0x35, 0x49, 0x59, 0xF1, 0xFF, 0x0C, 0xBF,
                            0xE9, 0x50, 0x61, 0xB5, 0xA6, 0x48, 0xC1, 0x03,
                            0x87, 0x06, 0x9C, 0x25, 0x99, 0x7C, 0x06, 0x72];
    let mut crypto = gost::GostCrypto::new(key, String::from(gost::GostCrypto::DEFAULT_PARAM_SET)).unwrap();
    let plain: Vec<u8> = vec![0;16];
    let crypt = vec![0x0b, 0x28, 0xfa, 0xb3, 0x4d, 0xd1, 0xfe, 0x56, 
                               0x36, 0xe1, 0xd9, 0x72, 0xe9, 0xa0, 0xd0, 0x81];
    let iv = vec![1,2,3,4,5,6,7,8];
    let mut result = vec![];
    crypto.cbc_encrypt(&plain, &mut result, iv.to_owned()).unwrap();
    assert_eq!(result, crypt);
    let mut result_dec = vec![]; 
    crypto.cbc_decrypt(&result, &mut result_dec, iv).unwrap();

    assert_eq!(result_dec, plain);
}

#[test]
fn test_gost_cfb() {
    let key: Vec<u8> = vec![0xBE, 0x5E, 0xC2, 0x00, 0x6C, 0xFF, 0x9D, 0xCF,
                            0x52, 0x35, 0x49, 0x59, 0xF1, 0xFF, 0x0C, 0xBF,
                            0xE9, 0x50, 0x61, 0xB5, 0xA6, 0x48, 0xC1, 0x03,
                            0x87, 0x06, 0x9C, 0x25, 0x99, 0x7C, 0x06, 0x72];
    let mut crypto = gost::GostCrypto::new(key, String::from(gost::GostCrypto::DEFAULT_PARAM_SET)).unwrap();
    let plain: Vec<u8> = vec![0;15];
    let crypt = vec![0x0b, 0x28, 0xfa, 0xb3, 0x4d, 0xd1, 0xfe, 0x56,
                                0x36, 0xe1, 0xd9, 0x72, 0xe9, 0xa0, 0xd0];
    let iv = vec![1,2,3,4,5,6,7,8];
    let mut result = vec![];
    crypto.cfb_encrypt(&plain, &mut result, iv.to_owned()).unwrap();
    assert_eq!(result, crypt);
    let mut result_dec = vec![]; 
    crypto.cfb_decrypt(&result, &mut result_dec, iv).unwrap();

    assert_eq!(result_dec, plain);
}
#[test]
fn test_gost_ctr() {
    let key: Vec<u8> = vec![0xBE, 0x5E, 0xC2, 0x00, 0x6C, 0xFF, 0x9D, 0xCF,
                            0x52, 0x35, 0x49, 0x59, 0xF1, 0xFF, 0x0C, 0xBF,
                            0xE9, 0x50, 0x61, 0xB5, 0xA6, 0x48, 0xC1, 0x03,
                            0x87, 0x06, 0x9C, 0x25, 0x99, 0x7C, 0x06, 0x72];
    let mut crypto = gost::GostCrypto::new(key, String::from(gost::GostCrypto::DEFAULT_PARAM_SET)).unwrap();
    let plain: Vec<u8> = vec![0;15];
    let crypt = vec![0x3b, 0x23, 0x45, 0x15, 0xad, 0x4f, 0xa0, 0x40,
                              0x5d, 0x2f, 0x3c, 0xf1, 0x67, 0x76, 0x97];
    let iv = vec![1,2,3,4,5,6,7,8];
    let mut result = vec![];
    crypto.ctr_encrypt(&plain, &mut result, &iv).unwrap();
    assert_eq!(result, crypt);
    let mut result_dec = vec![];
    crypto.ctr_decrypt(&result, &mut result_dec, &iv).unwrap();

    assert_eq!(result_dec, plain);
}

#[test]
fn test_mac() {
    let key: Vec<u8> = vec![0xBE, 0x5E, 0xC2, 0x00, 0x6C, 0xFF, 0x9D, 0xCF,
                            0x52, 0x35, 0x49, 0x59, 0xF1, 0xFF, 0x0C, 0xBF,
                            0xE9, 0x50, 0x61, 0xB5, 0xA6, 0x48, 0xC1, 0x03,
                            0x87, 0x06, 0x9C, 0x25, 0x99, 0x7C, 0x06, 0x72];
    let mut crypto = gost::GostCrypto::new(key, String::from(gost::GostCrypto::DEFAULT_PARAM_SET)).unwrap();
    let input: Vec<u8> = vec![0;14];
    let iv = vec![1,2,3,4,5,6,7,8];
    crypto.set_mac_iv(&iv); 
    crypto.update(&input);
    assert_eq!(vec![0xd8, 0xb5, 0xa9, 0x78, 0xdf, 0x19, 0x17, 0xcb], crypto.digest());
}
/// RFC 5830 defines the gamma counter as N3 += C2 mod 2^32 and
/// N4 += C1 mod (2^32 - 1). The original code wrote the second as
/// `wrapping_add(C1) % 0xffffffff`, which drops the carry and lands one too
/// low whenever the sum passes 2^32. Checked here against the modulus
/// arithmetic computed independently in u64.
#[test]
fn test_gost_counter_modulus() {
    let key: Vec<u8> = vec![0; 32];
    let crypto = gost::GostCrypto::new(key, String::from(gost::GostCrypto::DEFAULT_PARAM_SET)).unwrap();

    const C1: u64 = 0x01010104;
    const C2: u64 = 0x01010101;
    // Values chosen to sit either side of the 2^32 boundary for N4.
    for n4_start in [0u32, 1, 0x7fff_ffff, 0xfefe_fefe, 0xffff_fefb,
                     0xffff_fefc, 0xffff_fffe, 0xffff_ffff] {
        let n3_start: u32 = 0x1234_5678;
        let mut counter = vec![];
        counter.extend_from_slice(&n3_start.to_le_bytes());
        counter.extend_from_slice(&n4_start.to_le_bytes());
        crypto.ctr_next(&mut counter);

        let got_n3 = u32::from_le_bytes(counter[0..4].try_into().unwrap());
        let got_n4 = u32::from_le_bytes(counter[4..8].try_into().unwrap());

        let want_n3 = (n3_start as u64 + C2) as u32; // mod 2^32
        // mod 2^32-1, in the 1..=2^32-1 representation RFC 5830 uses
        let m = u32::MAX as u64;
        let want_n4 = (((n4_start as u64 + C1 - 1) % m) + 1) as u32;

        assert_eq!(got_n3, want_n3, "N3 for start {:08x}", n4_start);
        assert_eq!(got_n4, want_n4, "N4 for start {:08x}", n4_start);
    }
}
