// Written by scripts/make_oldcipher_tables.py from the witness sources
// cryptopp/lea.cpp
// go-krypto/lea/generic_const.go
// which agree on every entry; do not edit.

/// LEA's key schedule constants: the square root of 766965, after the
/// point, in 32-bit words.
pub(crate) const DELTA: [u32; 8] = [
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957,
];
