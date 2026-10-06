//! The hashes wallets are built from, through the library's facade.

use allcrypt::api;
use allcrypt::hash_functions::HashFunction;

pub fn digest(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h = api::AnyHash::new(name).expect("a known hash");
    h.update(data);
    h.digest()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest("sha256", data)
}

/// SHA-256 twice: Bitcoin's checksums, message hashes and BIP-38's
/// address hash.
pub fn sha256d(data: &[u8]) -> Vec<u8> {
    sha256(&sha256(data))
}

/// RIPEMD-160 of SHA-256: a Bitcoin key or script hash.
pub fn hash160(data: &[u8]) -> Vec<u8> {
    digest("ripemd160", &sha256(data))
}

/// Keccak-256 as Ethereum uses it: the original Keccak padding, not
/// FIPS 202's SHA3-256.
pub fn keccak256(data: &[u8]) -> Vec<u8> {
    digest("keccak_256", data)
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    api::hmac("sha512", key, data).expect("a known hash")
}

/// BIP-340's tagged hash: SHA-256 over SHA-256(tag) twice, then the data.
pub fn tagged_hash(tag: &str, data: &[u8]) -> Vec<u8> {
    let t = sha256(tag.as_bytes());
    let mut input = t.clone();
    input.extend_from_slice(&t);
    input.extend_from_slice(data);
    sha256(&input)
}
