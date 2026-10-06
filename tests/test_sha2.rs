use allcrypt::hash_functions::{HashFunction, sha2};



#[test]
fn test_sha224_empty() {
    let mut hash = sha2::SHA224::new(&[]);
    let result = vec![0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9,
                               0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
                               0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
                               0xc5, 0xb3, 0xe4, 0x2f];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_sha256_empty() {
    let mut hash = sha2::SHA256::new(&[]);
    let result = vec![0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                               0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                               0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                               0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_sha384_empty() {
    let mut hash = sha2::SHA384::new(&[]);
    let result = vec![0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
                               0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
                               0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
                               0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
                               0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
                               0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_sha512_empty() {
    let mut hash = sha2::SHA512::new(&[], 512);
    let result = vec![0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                               0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                               0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                               0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                               0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                               0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                               0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                               0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_sha512t_empty() {
    let mut hash = sha2::SHA512::new(&[], 224);
    let result = vec![0x6e, 0xd0, 0xdd, 0x02, 0x80, 0x6f, 0xa8, 0x9e,
                               0x25, 0xde, 0x06, 0x0c, 0x19, 0xd3, 0xac, 0x86,
                               0xca, 0xbb, 0x87, 0xd6, 0xa0, 0xdd, 0xd0, 0x5c,
                               0x33, 0x3b, 0x84, 0xf4];
    assert_eq!(hash.digest(), result);

    let mut hash = sha2::SHA512::new(&[], 256);
    let result = vec![0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28,
                               0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51, 0x14, 0x06,
                               0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74,
                               0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a];
    assert_eq!(hash.digest(), result);
}

#[test]
fn test_sha256_63() {
    let mut hash = sha2::SHA256::new(&[]);
    hash.update(&[0; 63]);
    let result = vec![0xc7, 0x72, 0x3f, 0xa1, 0xe0, 0x12, 0x79, 0x75,
                               0xe4, 0x9e, 0x62, 0xe7, 0x53, 0xdb, 0x53, 0x92,
                               0x4c, 0x1b, 0xd8, 0x4b, 0x8a, 0xc1, 0xac, 0x08,
                               0xdf, 0x78, 0xd0, 0x92, 0x70, 0xf3, 0xd9, 0x71];
assert_eq!(hash.digest(), result);
}
/// Regression: SHA-224 and SHA-256 had the same 16-byte length field bug as
/// SHA-1 (SHA-384/512 were correct, since a 128 byte block really does use a
/// 16 byte field). Broken window is length 48..=55 mod 64.
/// Reference digests from Python hashlib.
#[test]
fn test_sha256_final_block_length_field() {
    let cases: [(usize, &str); 15] = [
        (47, "11eaed932c6c6fddfc2efc394e609facf4abe814fc6180d03b14fce13a07d0e5"),
        (48, "97daac0ee9998dfcad6c9c0970da5ca411c86233a944c25b47566f6a7bc1ddd5"),
        (49, "8f9bec6a62dd28ebd36d1227745592de6658b36974a3bb98a4c582f683ea6c42"),
        (50, "160b4e433e384e05e537dc59b467f7cb2403f0214db15c5db58862a3f1156d2e"),
        (51, "bfc5fe0e360152ca98c50fab4ed7e3078c17debc2917740d5000913b686ca129"),
        (52, "6c1b3dc7a706b9dc81352a6716b9c666c608d8626272c64b914ab05572fc6e84"),
        (53, "abe346a7259fc90b4c27185419628e5e6af6466b1ae9b5446cac4bfc26cf05c4"),
        (54, "a3f01b6939256127582ac8ae9fb47a382a244680806a3f613a118851c1ca1d47"),
        (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
        (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
        (111, "6374f73208854473827f6f6a3f43b1f53eaa3b82c21c1a6d69a2110b2a79baad"),
        (112, "f54353008a2553262ecdc4a34749563ba0950e8b0fc8652780b0a614b99683c1"),
        (113, "ba02731ae695aae5cd49b49d84330b63995733eb22102aca755f0179b1e0e20f"),
        (119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"),
        (120, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c"),
    ];
    for (n, expected) in cases {
        let msg = vec![b'a'; n];
        let mut hash = sha2::SHA256::new(&msg);
        assert_eq!(allcrypt::to_hex(&hash.digest()).to_lowercase(), expected,
                   "SHA256 of {} bytes", n);
    }
}

#[test]
fn test_sha224_final_block_length_field() {
    let cases: [(usize, &str); 15] = [
        (47, "58756e846cce4e08b2ae1103ec3dd2c5755c15f94c1127782dde82c5"),
        (48, "73e0009122e9f4d311459277b81009e9cecc4b3dccf785d4ad476a14"),
        (49, "c0af565a56aeccfd2d40455f20d2c9431a7ab88c61e94973c97cff91"),
        (50, "df427221dc453d5c1466081d9d6e9da3155d5d0dff2a90eb0425036c"),
        (51, "7820fc9fc80c5ed788738da53fbfa6cf1fa981d656a3bb1e68cdf281"),
        (52, "163a72bc0462179bf0486f8a139da514913670d12bbe1d84efc44556"),
        (53, "3fae7c2d692c1610c4a20a17a790d256c3b0071bcdf6fb7fb9538681"),
        (54, "282e1dec88fa36a1070631cca69e3c08a5e18e29fb0b6f6927fbcc0d"),
        (55, "fb0bd626a70c28541dfa781bb5cc4d7d7f56622a58f01a0b1ddd646f"),
        (56, "d40854fc9caf172067136f2e29e1380b14626bf6f0dd06779f820dcd"),
        (111, "4aeec1a49b2c1bc663abf2809b36faaa64359523d4f26d02dbc2cba3"),
        (112, "0336b66821946e7f1052102e3b9c29f3039efe9b261746370305f894"),
        (113, "e623caedb98b77b63f4e2f5316ea3f48b9b864fc852e1e6eb97aa101"),
        (119, "e000e6709d26667b631faa7fc1bd404eb4774003c5fb4f51a0184875"),
        (120, "66924e30a9929327e7a6cf03747397226ed2efc180ebe3dea7132a79"),
    ];
    for (n, expected) in cases {
        let msg = vec![b'a'; n];
        let mut hash = sha2::SHA224::new(&msg);
        assert_eq!(allcrypt::to_hex(&hash.digest()).to_lowercase(), expected,
                   "SHA224 of {} bytes", n);
    }
}
