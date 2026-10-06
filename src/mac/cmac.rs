/*
CMAC (NIST SP 800-38B, RFC 4493), which GOST calls OMAC.

CBC-MAC with the one fix that makes it safe for variable-length messages:
the last block is XORed with a subkey derived from the cipher, and which
of two subkeys depends on whether the message needed padding.

Plain CBC-MAC over variable lengths is forgeable in one line. Given
`T = CBC-MAC(M)` for a one-block `M`, the two-block message
`M || (M xor T)` has the same tag, and no key is needed to work that out.
CMAC's two subkeys are what stop it: a padded message and an unpadded one
can never collide, because they were finished under different keys.

Three things to get right, and the first two are silent:

  * **Rb depends on the block size**, because it is the low coefficients
    of the irreducible polynomial for GF(2^b): 0x87 for a 128 bit block,
    0x1b for a 64 bit one. Using 0x87 everywhere gives a MAC that is
    perfectly consistent with itself over DES, 3DES, Blowfish and Magma,
    and agrees with nothing.

  * **An empty message is padded**, so it uses K2 and not K1. The "is it
    a whole number of blocks" test is `len > 0 && len % b == 0`, and
    leaving the first half off makes the empty message's tag wrong and
    every other tag right.

  * **The subkey doubling is over GF(2^b), not a plain shift.** Shift
    left by one and, if the bit that fell off the top was set, XOR Rb in.

Checked against OpenSSL through `python-cryptography`, which has CMAC over
AES, Triple DES and Blowfish - so both Rb values are covered by a real
independent implementation, over a 128 bit block and a 64 bit one.
Kuznyechik and Magma then use the same construction with ciphers that are
themselves checked, which is as close to an independent check as an
algorithm nothing here implements can get.
*/

use crate::api::AnyBlockCipher;
use crate::block_ciphers::BlockCipher;
use crate::Mac;

/// The low coefficients of the irreducible polynomial for the block size.
///
/// Not a constant: a 64 bit block and a 128 bit block have different
/// fields, and the same value for both is a MAC that agrees with itself
/// and with nobody.
fn rb(block_size: usize) -> Result<u8, String> {
    match block_size {
        16 => Ok(0x87),     // x^128 + x^7 + x^2 + x + 1
        8 => Ok(0x1b),      // x^64 + x^4 + x^3 + x + 1
        other => Err(format!(
            "CMAC needs a 64 or 128 bit block; this cipher's is {} bits. The \
             field's polynomial is not defined for other sizes.", other * 8)),
    }
}

/// Multiply by x in GF(2^b): shift left one bit, and fold in `rb` if the
/// bit that fell off the top was set.
fn double(block: &mut [u8], rb: u8) {
    let carry = block[0] >> 7;
    for index in 0..block.len() - 1 {
        block[index] = (block[index] << 1) | (block[index + 1] >> 7);
    }
    let last = block.len() - 1;
    block[last] <<= 1;
    // Branchless: `carry` is a bit of the cipher's output under the key,
    // and this is the one place in the construction where branching on it
    // would leak. `carry.wrapping_neg()` is 0x00 or 0xff.
    block[last] ^= rb & carry.wrapping_neg();
}

/// CMAC over any block cipher this library has.
pub struct Cmac {
    cipher: AnyBlockCipher,
    block_size: usize,
    subkey_one: Vec<u8>,
    subkey_two: Vec<u8>,
    /// The running CBC chain.
    chain: Vec<u8>,
    /// Bytes not yet in a full block. Held back deliberately: the *last*
    /// block is treated differently, and a streaming MAC does not know
    /// which block is last until it is asked for the tag.
    pending: Vec<u8>,
    /// Scratch for one block, allocated once rather than per block.
    scratch: Vec<u8>,
}

impl core::fmt::Debug for Cmac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cmac {{ {}, keys redacted }}", self.cipher.name())
    }
}

impl Cmac {
    /// `cipher` must already be keyed.
    pub fn new(mut cipher: AnyBlockCipher) -> Result<Cmac, String> {
        let block_size = cipher.blocksize();
        let rb = rb(block_size)?;

        // L = E_K(0^b), then K1 = L.x and K2 = K1.x.
        let mut subkey_one = Vec::with_capacity(block_size);
        cipher.block_encrypt(&vec![0u8; block_size], &mut subkey_one);
        if subkey_one.len() != block_size {
            return Err(format!(
                "{} produced {} bytes for a {} byte block.",
                cipher.name(), subkey_one.len(), block_size));
        }
        double(&mut subkey_one, rb);
        let mut subkey_two = subkey_one.clone();
        double(&mut subkey_two, rb);

        Ok(Cmac {
            cipher,
            block_size,
            subkey_one,
            subkey_two,
            chain: vec![0u8; block_size],
            pending: Vec::with_capacity(block_size),
            scratch: Vec::with_capacity(block_size),
        })
    }

    /// Build one from a cipher name and a key.
    pub fn with_key(cipher_name: &str, key: &[u8]) -> Result<Cmac, String> {
        Cmac::new(AnyBlockCipher::new(cipher_name, key, None)?)
    }

    pub fn tag_len(&self) -> usize {
        self.block_size
    }

    /// One CBC step over a whole block.
    fn absorb(&mut self, block: &[u8]) {
        for (chained, byte) in self.chain.iter_mut().zip(block.iter()) {
            *chained ^= byte;
        }
        self.scratch.clear();
        let chain = core::mem::take(&mut self.chain);
        self.cipher.block_encrypt(&chain, &mut self.scratch);
        self.chain = chain;
        self.chain.copy_from_slice(&self.scratch);
    }
}

impl Mac for Cmac {
    fn update(&mut self, input: &[u8]) {
        let mut rest = input;

        if !self.pending.is_empty() {
            let take = core::cmp::min(self.block_size - self.pending.len(), rest.len());
            self.pending.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            // Only absorb once there is *more* to come: a full `pending`
            // with nothing after it is the last block, and the last block
            // is finished differently.
            if self.pending.len() == self.block_size && !rest.is_empty() {
                let block = core::mem::take(&mut self.pending);
                self.absorb(&block);
                self.pending = block;
                self.pending.clear();
            }
        }

        while rest.len() > self.block_size {
            let (block, remaining) = rest.split_at(self.block_size);
            self.absorb(block);
            rest = remaining;
        }
        self.pending.extend_from_slice(rest);
    }

    /// The tag, without consuming the state - the same contract every
    /// other MAC here has.
    fn digest(&mut self) -> Vec<u8> {
        let mut last = self.pending.clone();
        // A whole number of non-zero blocks uses K1; anything else is
        // padded and uses K2. The empty message is *padded*, which is the
        // half of this condition an implementation leaves out.
        let complete = !last.is_empty() && last.len() == self.block_size;
        let subkey = if complete { &self.subkey_one } else { &self.subkey_two };
        if !complete {
            last.push(0x80);
            last.resize(self.block_size, 0);
        }
        for (byte, k) in last.iter_mut().zip(subkey.iter()) {
            *byte ^= k;
        }

        let saved_chain = self.chain.clone();
        let saved_pending = core::mem::take(&mut self.pending);
        self.absorb(&last);
        let tag = self.chain.clone();
        self.chain = saved_chain;
        self.pending = saved_pending;
        tag
    }
}

/// The tag over one message, for callers with all of it in hand.
pub fn cmac(cipher_name: &str, key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = Cmac::with_key(cipher_name, key)?;
    mac.update(message);
    Ok(mac.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 4493 section 4: AES-128 CMAC, all four published vectors.
    ///
    /// These cover the two cases that differ - a whole number of blocks
    /// and a partial one - and the empty message, which is the one an
    /// implementation gets wrong by testing `len % b == 0` alone.
    #[test]
    fn test_rfc_4493_aes128() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let message = unhex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710");

        for (length, want) in [
            (0usize, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ] {
            assert_eq!(hex(&cmac("aes", &key, &message[..length]).unwrap()), want,
                       "message of {} bytes", length);
        }
    }

    /// The subkeys from the same RFC, because a key schedule that is
    /// wrong still produces a MAC.
    #[test]
    fn test_rfc_4493_subkeys() {
        let mac = Cmac::with_key("aes", &unhex("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        assert_eq!(hex(&mac.subkey_one), "fbeed618357133667c85e08f7236a8de");
        assert_eq!(hex(&mac.subkey_two), "f7ddac306ae266ccf90bc11ee46d513b");
    }

    /// Rb is not a constant. A 64 bit block uses 0x1b, and using 0x87
    /// there gives a MAC that is self-consistent over every 64 bit cipher
    /// in this library.
    #[test]
    fn test_the_polynomial_depends_on_the_block_size() {
        assert_eq!(rb(16).unwrap(), 0x87);
        assert_eq!(rb(8).unwrap(), 0x1b);
        assert!(rb(7).is_err());

        // A block whose top bit is set must fold; one without must not.
        let mut high = vec![0x80u8, 0, 0, 0, 0, 0, 0, 0];
        double(&mut high, 0x1b);
        assert_eq!(hex(&high), "000000000000001b");

        let mut low = vec![0x01u8, 0, 0, 0, 0, 0, 0, 0];
        double(&mut low, 0x1b);
        assert_eq!(hex(&low), "0200000000000000");

        let mut wide = vec![0x80u8; 16];
        double(&mut wide, 0x87);
        assert_eq!(hex(&wide), "010101010101010101010101010101" .to_string() + "87");
    }

    /// The empty message is padded and uses K2. An implementation testing
    /// only `len % b == 0` gets every other length right and this one
    /// wrong.
    #[test]
    fn test_the_empty_message_is_padded() {
        let key = vec![0x11u8; 16];
        let empty = cmac("aes", &key, &[]).unwrap();

        // A single 0x80 byte is padded to the *same* block as the empty
        // message would be if the padding rule were skipped - so these
        // must differ.
        let one = cmac("aes", &key, &[0x80]).unwrap();
        assert_ne!(empty, one);

        // And a full block of zeros is not the same as the empty message
        // either: one uses K1, the other K2.
        let block = cmac("aes", &key, &[0u8; 16]).unwrap();
        assert_ne!(empty, block);
    }

    /// The length-extension forgery that plain CBC-MAC allows must not
    /// work. Given T over a one-block M, the message `M || (M xor T)` has
    /// the same CBC-MAC tag and a different CMAC tag.
    #[test]
    fn test_the_cbc_mac_forgery_does_not_work() {
        let key = vec![0x2au8; 16];
        let message = vec![0x42u8; 16];
        let tag = cmac("aes", &key, &message).unwrap();

        let mut forged = message.clone();
        forged.extend(message.iter().zip(tag.iter()).map(|(m, t)| m ^ t));
        assert_ne!(cmac("aes", &key, &forged).unwrap(), tag);
    }

    /// Streaming in ragged pieces must equal one call - and the last
    /// block is special, so a streaming implementation that absorbed
    /// every full block as it arrived would get the final one wrong.
    #[test]
    fn test_streaming_equals_one_call() {
        let key = vec![0x5cu8; 16];
        let message: Vec<u8> = (0..200u32).map(|i| (i * 13 + 7) as u8).collect();

        for length in 0..=100usize {
            let whole = cmac("aes", &key, &message[..length]).unwrap();
            for chunk in [1usize, 5, 15, 16, 17, 32] {
                let mut mac = Cmac::with_key("aes", &key).unwrap();
                for piece in message[..length].chunks(chunk) {
                    mac.update(piece);
                }
                assert_eq!(mac.digest(), whole,
                           "length {} in chunks of {}", length, chunk);
            }
        }
    }

    #[test]
    fn test_digest_does_not_consume_the_state() {
        let mut mac = Cmac::with_key("aes", &[0x33u8; 16]).unwrap();
        mac.update(b"abc");
        let first = mac.digest();
        assert_eq!(mac.digest(), first);
        mac.update(b"def");
        assert_eq!(mac.digest(), cmac("aes", &[0x33u8; 16], b"abcdef").unwrap());
    }

    /// Over the GOST ciphers, which is what this is for. The tags are
    /// whatever they are - the check that they are *right* is
    /// `scripts/diff_check.py` - but the shapes have to be right here.
    #[test]
    fn test_it_works_over_the_gost_ciphers() {
        let key = vec![0x77u8; 32];
        let kuznyechik = cmac("kuznyechik", &key, b"message").unwrap();
        let magma = cmac("magma", &key, b"message").unwrap();

        assert_eq!(kuznyechik.len(), 16, "Kuznyechik's block is 128 bits");
        assert_eq!(magma.len(), 8, "Magma's block is 64 bits");
        assert_ne!(kuznyechik[..8], magma[..]);
    }

    /// Blowfish and DES have 64 bit blocks, so they exercise the other
    /// Rb. 3DES too, which is what the differential corpus compares
    /// against OpenSSL.
    #[test]
    fn test_the_64_bit_block_ciphers_work() {
        for name in ["des", "3des", "blowfish", "magma"] {
            let key = match name {
                "des" => vec![0x01u8; 8],
                "3des" => vec![0x01u8; 24],
                "blowfish" => vec![0x01u8; 16],
                _ => vec![0x01u8; 32],
            };
            let tag = cmac(name, &key, b"sixty four bit block").unwrap();
            assert_eq!(tag.len(), 8, "{}", name);
        }
    }
}
