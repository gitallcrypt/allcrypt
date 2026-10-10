//! Known answer tests for the modes of operation, and for the streaming mode
//! objects in `block_ciphers::modes`.
//!
//! The AES vectors are the NIST SP 800-38A appendix F inputs (key
//! 2b7e1516..., IV 000102..., counter block f0f1f2..., the four standard
//! plaintext blocks). The Blowfish vectors use the Eric Young test key and
//! plaintext. Expected ciphertexts were cross-checked against OpenSSL.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::blowfish::Blowfish;
use allcrypt::block_ciphers::{BlockCipher, Cbc, Cfb, Ctr, Ofb};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

const KEY128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const CTRBLK: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const PT: &str = "6bc1bee22e409f96e93d7e117393172a\
                  ae2d8a571e03ac9c9eb76fac45af8e51\
                  30c81c46a35ce411e5fbc1191a0a52ef\
                  f69f2445df4f9b17ad2b417be66c3710";

fn aes(key: &str) -> AesCrypto {
    AesCrypto::new(&hex(key)).unwrap()
}

fn check_all_modes(key: &str, ecb: &str, cbc: &str, cfb: &str, ofb: &str, ctr: &str) {
    let pt = hex(PT);
    let iv = hex(IV);
    let ctrblk = hex(CTRBLK);

    let mut out = vec![];
    aes(key).ecb_encrypt(&pt, &mut out).unwrap();
    assert_eq!(to_hex(&out), ecb, "ECB encrypt");
    let mut back = vec![];
    aes(key).ecb_decrypt(&out, &mut back).unwrap();
    assert_eq!(back, pt, "ECB decrypt");

    let mut out = vec![];
    aes(key).cbc_encrypt(&pt, &mut out, &iv).unwrap();
    assert_eq!(to_hex(&out), cbc, "CBC encrypt");
    let mut back = vec![];
    aes(key).cbc_decrypt(&out, &mut back, &iv).unwrap();
    assert_eq!(back, pt, "CBC decrypt");

    let mut out = vec![];
    aes(key).cfb_encrypt(&pt, &mut out, &iv).unwrap();
    assert_eq!(to_hex(&out), cfb, "CFB encrypt");
    let mut back = vec![];
    aes(key).cfb_decrypt(&out, &mut back, &iv).unwrap();
    assert_eq!(back, pt, "CFB decrypt");

    let mut out = vec![];
    aes(key).ofb_encrypt(&pt, &mut out, &iv).unwrap();
    assert_eq!(to_hex(&out), ofb, "OFB encrypt");
    let mut back = vec![];
    aes(key).ofb_decrypt(&out, &mut back, &iv).unwrap();
    assert_eq!(back, pt, "OFB decrypt");

    let mut out = vec![];
    aes(key).ctr_encrypt(&pt, &mut out, &ctrblk).unwrap();
    assert_eq!(to_hex(&out), ctr, "CTR encrypt");
    let mut back = vec![];
    aes(key).ctr_decrypt(&out, &mut back, &ctrblk).unwrap();
    assert_eq!(back, pt, "CTR decrypt");
}

#[test]
fn test_aes128_sp800_38a() {
    check_all_modes(KEY128,
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
        "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
}

#[test]
fn test_aes192_sp800_38a() {
    check_all_modes(KEY192,
        "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e",
        "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
        "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff",
        "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a",
        "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050");
}

#[test]
fn test_aes256_sp800_38a() {
    check_all_modes(KEY256,
        "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471",
        "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484",
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
}

/// A length that is not a whole number of blocks: pins the handling of the
/// final short block in each stream-like mode.
#[test]
fn test_aes128_partial_final_block() {
    let pt = hex(PT)[..37].to_vec();
    let iv = hex(IV);
    let ctrblk = hex(CTRBLK);

    let mut out = vec![];
    aes(KEY128).cfb_encrypt(&pt, &mut out, &iv).unwrap();
    assert_eq!(to_hex(&out), "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3");

    let mut out = vec![];
    aes(KEY128).ofb_encrypt(&pt, &mut out, &iv).unwrap();
    assert_eq!(to_hex(&out), "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c");

    let mut out = vec![];
    aes(KEY128).ctr_encrypt(&pt, &mut out, &ctrblk).unwrap();
    assert_eq!(to_hex(&out), "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edb");
}

/// CBC must refuse an input that is not a whole number of blocks.
#[test]
fn test_cbc_rejects_partial_input() {
    let mut out = vec![];
    assert!(aes(KEY128).cbc_encrypt(&hex(PT)[..37], &mut out, &hex(IV)).is_err());
    assert!(out.is_empty());
}

#[test]
fn test_blowfish_modes() {
    let key = hex("0123456789abcdeff0e1d2c3b4a59687");
    let iv = hex("fedcba9876543210");
    let pt = hex("37363534333231204e6f77206973207468652074696d6520666f722000000000");

    let mut out = vec![];
    Blowfish::new(&key).unwrap().ecb_encrypt(&pt, &mut out).unwrap();
    assert_eq!(to_hex(&out), "2afd7daa60626ba38616468cc29cf6e1291e817cc740982d6f87ac5f171aabea");

    let mut out = vec![];
    Blowfish::new(&key).unwrap().cbc_encrypt(&pt, &mut out, &iv).unwrap();
    assert_eq!(to_hex(&out), "6b77b4d63006dee605b156e27403979358deb9e7154616d959f1652bd5ff92cc");

    let mut out = vec![];
    Blowfish::new(&key).unwrap().cfb_encrypt(&pt, &mut out, &iv).unwrap();
    assert_eq!(to_hex(&out), "e73214a2822139caf26ecf6d2eb9e76e3da3de04d1517200519d57a6c3384ece");

    let mut out = vec![];
    Blowfish::new(&key).unwrap().ofb_encrypt(&pt, &mut out, &iv).unwrap();
    assert_eq!(to_hex(&out), "e73214a2822139ca62b343cc5b65587310dd908d0c241b2263c2cf80da46fbb8");
}

// ------------------------------------------------------------- streaming ---

/// Feeding a stream in awkwardly sized pieces must give byte-identical output
/// to one call. This is the property the mode objects exist for.
#[test]
fn test_streaming_matches_one_shot() {
    let pt: Vec<u8> = (0..640).map(|i| ((i*167+13) & 0xff) as u8).collect();
    let iv = hex(IV);

    for &first in &[1usize, 2, 3, 7, 15, 16, 17, 31, 33, 63, 64, 65, 100] {
        // irregular, ever growing chunks
        let mut chunks: Vec<&[u8]> = vec![];
        let (mut i, mut step) = (0usize, first);
        while i < pt.len() {
            let e = std::cmp::min(pt.len(), i + step);
            chunks.push(&pt[i..e]);
            i = e;
            step = step * 2 + 1;
        }

        let mut one = vec![];
        aes(KEY128).ctr_encrypt(&pt, &mut one, &iv).unwrap();
        let mut c = aes(KEY128);
        let mut streamed = vec![];
        {
            let mut m = Ctr::new(&mut c, &iv).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
        }
        assert_eq!(one, streamed, "CTR streaming, first chunk {}", first);

        let mut one = vec![];
        aes(KEY128).cfb_encrypt(&pt, &mut one, &iv).unwrap();
        let mut c = aes(KEY128);
        let mut streamed = vec![];
        {
            let mut m = Cfb::encryptor(&mut c, &iv).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
        }
        assert_eq!(one, streamed, "CFB streaming, first chunk {}", first);

        let mut c = aes(KEY128);
        let mut back = vec![];
        {
            let mut m = Cfb::decryptor(&mut c, &iv).unwrap();
            for ch in one.chunks(first) { m.update(ch, &mut back).unwrap(); }
        }
        assert_eq!(back, pt, "CFB streaming decrypt, chunk {}", first);

        let mut one = vec![];
        aes(KEY128).ofb_encrypt(&pt, &mut one, &iv).unwrap();
        let mut c = aes(KEY128);
        let mut streamed = vec![];
        {
            let mut m = Ofb::new(&mut c, &iv).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
        }
        assert_eq!(one, streamed, "OFB streaming, first chunk {}", first);

        // CBC buffers a partial block between calls.
        let mut one = vec![];
        aes(KEY128).cbc_encrypt(&pt, &mut one, &iv).unwrap();
        let mut c = aes(KEY128);
        let mut streamed = vec![];
        {
            let mut m = Cbc::encryptor(&mut c, &iv).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
            m.finish().unwrap();
        }
        assert_eq!(one, streamed, "CBC streaming, first chunk {}", first);

        let mut c = aes(KEY128);
        let mut back = vec![];
        {
            let mut m = Cbc::decryptor(&mut c, &iv).unwrap();
            for ch in one.chunks(first) { m.update(ch, &mut back).unwrap(); }
            m.finish().unwrap();
        }
        assert_eq!(back, pt, "CBC streaming decrypt, chunk {}", first);
    }
}

/// A CBC stream that ends mid-block must report it rather than silently
/// dropping the tail.
#[test]
fn test_cbc_stream_finish_detects_partial_block() {
    let iv = hex(IV);
    let mut c = aes(KEY128);
    let mut out = vec![];
    let mut m = Cbc::encryptor(&mut c, &iv).unwrap();
    m.update(&[0u8; 20], &mut out).unwrap();
    assert_eq!(out.len(), 16, "only the first whole block should have emerged");
    assert!(m.finish().is_err());
}

/// In-place `apply` must agree with the appending `update`.
#[test]
fn test_apply_in_place_matches_update() {
    let pt: Vec<u8> = (0..300).map(|i| (i as u8).wrapping_mul(7)).collect();
    let iv = hex(IV);

    let mut appended = vec![];
    aes(KEY128).ctr_encrypt(&pt, &mut appended, &iv).unwrap();
    let mut buf = pt.clone();
    let mut c = aes(KEY128);
    Ctr::new(&mut c, &iv).unwrap().apply(&mut buf).unwrap();
    assert_eq!(appended, buf);

    let mut appended = vec![];
    aes(KEY128).ofb_encrypt(&pt, &mut appended, &iv).unwrap();
    let mut buf = pt.clone();
    let mut c = aes(KEY128);
    Ofb::new(&mut c, &iv).unwrap().apply(&mut buf).unwrap();
    assert_eq!(appended, buf);

    let mut appended = vec![];
    aes(KEY128).cfb_encrypt(&pt, &mut appended, &iv).unwrap();
    let mut buf = pt.clone();
    let mut c = aes(KEY128);
    Cfb::encryptor(&mut c, &iv).unwrap().apply(&mut buf).unwrap();
    assert_eq!(appended, buf);
}

/// The generic CTR counter is a big endian increment of the whole block, so
/// it must carry correctly out of the low byte and across the whole block.
#[test]
fn test_ctr_counter_carries() {
    let c = aes(KEY128);

    let mut counter = hex("000000000000000000000000000000ff");
    c.ctr_next(&mut counter);
    assert_eq!(to_hex(&counter), "00000000000000000000000000000100");

    let mut counter = hex("00000000000000000000000000ffffff");
    c.ctr_next(&mut counter);
    assert_eq!(to_hex(&counter), "00000000000000000000000001000000");

    // Wraps all the way round rather than panicking.
    let mut counter = hex("ffffffffffffffffffffffffffffffff");
    c.ctr_next(&mut counter);
    assert_eq!(to_hex(&counter), "00000000000000000000000000000000");
}

/// The mode objects must not assume the output buffer starts empty.
#[test]
fn test_modes_append_to_non_empty_output() {
    let pt: Vec<u8> = (0..100).map(|i| i as u8).collect();
    let iv = hex(IV);
    let prefix = vec![0xde, 0xad, 0xbe, 0xef];

    for mode in ["ctr", "cfb", "ofb"] {
        let mut fresh = vec![];
        let mut prefixed = prefix.clone();
        match mode {
            "ctr" => {
                aes(KEY128).ctr_encrypt(&pt, &mut fresh, &iv).unwrap();
                aes(KEY128).ctr_encrypt(&pt, &mut prefixed, &iv).unwrap();
            }
            "cfb" => {
                aes(KEY128).cfb_encrypt(&pt, &mut fresh, &iv).unwrap();
                aes(KEY128).cfb_encrypt(&pt, &mut prefixed, &iv).unwrap();
            }
            _ => {
                aes(KEY128).ofb_encrypt(&pt, &mut fresh, &iv).unwrap();
                aes(KEY128).ofb_encrypt(&pt, &mut prefixed, &iv).unwrap();
            }
        }
        assert_eq!(&prefixed[..4], &prefix[..], "{} clobbered the prefix", mode);
        assert_eq!(&prefixed[4..], &fresh[..], "{} output changed", mode);
    }
}
