/*
HMAC (RFC 2104), generic over any hash in this library.

    HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))

where K' is the key padded to the hash's block size, or the hash of the key
if it is longer than a block.

The implementation keeps two hash states: `inner`, which has already been fed
`K' ^ ipad` and then the message as it arrives, and `outer`, which has been
fed `K' ^ opad` and is waiting for the inner digest. Finalising clones the
outer state rather than consuming it, so `digest()` is repeatable and you can
keep calling `update` afterwards - the same contract the hashes have.
*/

use crate::hash_functions::HashFunction;
use crate::Mac;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// `Clone` because PBKDF2 needs it and the alternative is much worse.
///
/// `new` does the expensive part of HMAC — padding the key to a block and
/// pushing `K' ^ ipad` and `K' ^ opad` through the compression function —
/// and PBKDF2 calls the PRF once per iteration with the *same* key,
/// hundreds of thousands of times. Cloning a primed `Hmac` reuses that
/// work; constructing a fresh one each time repeats it, which roughly
/// doubles the cost of every PBKDF2 in the library.
#[derive(Clone)]
pub struct Hmac<H: HashFunction + Clone> {
    inner: H,
    outer: H,
    digest_len: usize,
}

impl<H: HashFunction + Clone> Hmac<H> {
    /// `hash` must be a freshly constructed, empty hash of the type you want;
    /// it is used as the template for both halves.
    pub fn new(hash: H, key: &[u8]) -> Hmac<H> {
        let block_size = hash.block_size();
        let digest_len = hash.digest_len();

        // K': the key, hashed first if it is longer than a block, then zero
        // padded out to a full block.
        let mut k = if key.len() > block_size {
            let mut h = hash.clone();
            h.update(key);
            h.digest()
        } else {
            key.to_vec()
        };
        k.resize(block_size, 0);

        let mut inner = hash.clone();
        let mut outer = hash;

        let ipad: Vec<u8> = k.iter().map(|b| b ^ IPAD).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ OPAD).collect();
        inner.update(&ipad);
        outer.update(&opad);

        Hmac { inner, outer, digest_len }
    }

    pub fn digest_len(&self) -> usize {
        self.digest_len
    }

    /// One shot, for callers that have the whole message already.
    pub fn mac(hash: H, key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut m = Hmac::new(hash, key);
        m.update(message);
        m.digest()
    }
}

impl<H: HashFunction + Clone> Mac for Hmac<H> {
    fn update(&mut self, input: &[u8]) {
        self.inner.update(input);
    }

    fn digest(&mut self) -> Vec<u8> {
        let inner_digest = self.inner.digest();
        // Clone so the outer state stays pristine and this stays repeatable.
        let mut outer = self.outer.clone();
        outer.update(&inner_digest);
        outer.digest()
    }
}

// Convenience constructors for the common cases.

use crate::hash_functions::{md5::MD5, sha1::SHA1, sha2};

pub fn hmac_md5(key: &[u8]) -> Hmac<MD5> { Hmac::new(MD5::new(&[]), key) }
pub fn hmac_sha1(key: &[u8]) -> Hmac<SHA1> { Hmac::new(SHA1::new(&[]), key) }
pub fn hmac_sha224(key: &[u8]) -> Hmac<sha2::SHA224> { Hmac::new(sha2::SHA224::new(&[]), key) }
pub fn hmac_sha256(key: &[u8]) -> Hmac<sha2::SHA256> { Hmac::new(sha2::SHA256::new(&[]), key) }
pub fn hmac_sha384(key: &[u8]) -> Hmac<sha2::SHA384> { Hmac::new(sha2::SHA384::new(&[]), key) }
pub fn hmac_sha512(key: &[u8]) -> Hmac<sha2::SHA512> { Hmac::new(sha2::SHA512::new(&[], 512), key) }

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2, the "Jefe" key, across the SHA-2 family.
    #[test]
    fn test_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        assert_eq!(crate::to_hex(&Hmac::mac(sha2::SHA224::new(&[]), key, data)).to_lowercase(),
                   "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44");
        assert_eq!(crate::to_hex(&Hmac::mac(sha2::SHA256::new(&[]), key, data)).to_lowercase(),
                   "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(crate::to_hex(&Hmac::mac(sha2::SHA384::new(&[]), key, data)).to_lowercase(),
                   "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                    8e2240ca5e69e2c78b3239ecfab21649");
        assert_eq!(crate::to_hex(&Hmac::mac(sha2::SHA512::new(&[], 512), key, data)).to_lowercase(),
                   "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                    9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    }

    /// A key longer than the block size must be hashed first.
    #[test]
    fn test_long_key_is_hashed() {
        // RFC 4231 case 4 uses a 131 byte key, longer than SHA-256's 64.
        let key = vec![0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(crate::to_hex(&Hmac::mac(sha2::SHA256::new(&[]), &key, data)).to_lowercase(),
                   "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    /// Streaming must equal one shot, and digest() must be repeatable.
    #[test]
    fn test_streaming_and_repeatable() {
        let key = b"a key of some length";
        let message: Vec<u8> = (0..500).map(|i| (i & 0xff) as u8).collect();

        let mut streamed = hmac_sha256(key);
        let (mut i, mut step) = (0usize, 1usize);
        while i < message.len() {
            let e = core::cmp::min(message.len(), i + step);
            streamed.update(&message[i..e]);
            i = e;
            step = step * 2 + 1;
        }
        let one_shot = Hmac::mac(sha2::SHA256::new(&[]), key, &message);
        assert_eq!(streamed.digest(), one_shot);

        // twice in a row is the same answer
        assert_eq!(streamed.digest(), one_shot);
        // and it can keep going afterwards
        streamed.update(b"more");
        let mut expected_more = message.clone();
        expected_more.extend_from_slice(b"more");
        assert_eq!(streamed.digest(),
                   Hmac::mac(sha2::SHA256::new(&[]), key, &expected_more));
    }

    /// An empty key and an empty message are both legal.
    #[test]
    fn test_empty_inputs() {
        let mac = Hmac::mac(sha2::SHA256::new(&[]), &[], &[]);
        assert_eq!(crate::to_hex(&mac).to_lowercase(),
                   "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    }
}
