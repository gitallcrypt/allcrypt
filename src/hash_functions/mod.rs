use std::collections::HashMap;

pub mod blake2;
pub mod buffer;
pub mod gost94;
pub mod keccak;
pub mod kupyna;
pub mod md2;
pub mod md4;
pub mod md5;
pub mod has160;
pub mod md6;
pub mod ripemd;
pub mod ripemd160;
pub mod sha1;
pub mod sha2;
#[cfg(all(feature = "sha-ni", target_arch = "x86_64"))]
mod sha_ni;
pub mod sm3;
pub mod streebog;
pub mod whirlpool;

/*
Many hash functions are defined with bits rather than bytes as input. 
This might be fixed for these implementations later.
*/

pub trait HashFunction {
    /// The name `api::AnyHash::new` reads back as this same function: the
    /// catalogue's spelling (`api::HASHES`), lowercase, with the length in
    /// the name for a family that takes one at a length the catalogue does
    /// not list (`blake2b_256`, `md6_200`, `kupyna128`, `shake_128_512`).
    fn name(&self) -> String;
    fn digest_len(&self) -> usize;
    /// The compression function's input block size in bytes: 64 for the
    /// 32 bit hashes, 128 for SHA-384/512. HMAC needs this, so it is part of
    /// the trait rather than something callers have to know per algorithm.
    fn block_size(&self) -> usize;
    fn update(&mut self, input: &[u8]);
    fn digest(&mut self) -> Vec<u8>;
}

pub fn hash_all(input: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut hashes = HashMap::new();
    let mut hash = md5::MD5::new(input);
    hashes.insert(hash.name(), hash.digest());

    let mut hash = sha1::SHA1::new(input);
    hashes.insert(hash.name(), hash.digest());

    let mut hash = sha1::SHA1::new(&[]);
    hash.set_to_sha0();
    hash.update(input);
    hashes.insert(hash.name(), hash.digest());

    let mut hash = sha2::SHA224::new(input);
    hashes.insert(hash.name(), hash.digest());

    let mut hash = sha2::SHA256::new(input);
    hashes.insert(hash.name(), hash.digest());
    
    let mut hash = sha2::SHA384::new(input);
    hashes.insert(hash.name(), hash.digest());

    let mut hash = sha2::SHA512::new(input, 512);
    hashes.insert(hash.name(), hash.digest());
    let mut hash = sha2::SHA512::new(input, 224);
    hashes.insert(hash.name(), hash.digest());
    let mut hash = sha2::SHA512::new(input, 256);
    hashes.insert(hash.name(), hash.digest());

    hashes
}