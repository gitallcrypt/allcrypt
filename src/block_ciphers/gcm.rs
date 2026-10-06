/*
Galois/Counter Mode (NIST SP 800-38D).

GCM is CTR encryption plus a GHASH authentication tag, sharing one key. It
follows the same split as the other modes here - a `GcmState` that owns the
state and takes the cipher per call, and a `Gcm` wrapper that pairs the two
- with one difference forced by what GCM is: it authenticates, so it has a
tag, and decryption can **fail**.

## The rules this mode has that the others do not

**128 bit blocks only.** GHASH is defined in GF(2^128) and nowhere else.
Blowfish and GOST have 64 bit blocks, so GCM on them is refused rather than
improvised. A 64 bit block AEAD is not a smaller version of this one; it is
a different construction that does not exist.

**A nonce must never repeat under one key.** This is not a preference. Two
messages encrypted under the same key and nonce give away their XOR *and*
allow the authentication key H to be recovered from the two tags, after
which anything can be forged under that key forever. There is no recovery,
no "only the affected messages", and no warning that it happened. Every
other rule in this file is ordinary care; this one is the mode's single
catastrophic failure. `docs/pitfalls.md` section 1 has the long version.

Nothing here can enforce it - the caller supplies the nonce and only the
caller knows what was used before - so the honest thing is to say so
loudly and to make the counter arithmetic incapable of producing an
overlap within one message.

**The tag must be checked before the plaintext is used.** `decrypt` returns
the plaintext or an error, never both, and on failure it leaves nothing
behind. Releasing unverified plaintext is how a padding oracle becomes a
plaintext oracle, and it is the reason the streaming decryption API here
makes you call `verify` to get anything at all.

## The counter that is not the CTR counter

GCM increments only the **rightmost 32 bits** of the counter block, wrapping
within those 32 bits and leaving the first 12 bytes alone. The mode's
generic `ctr_next` increments the whole block, and GOST overrides it with
something else again, so GCM does its own counter arithmetic rather than
going through the cipher's. Using the cipher's would be silently wrong for
GOST and silently right for AES, which is the worst possible combination.

The first counter block J0 depends on the nonce's length:

  * 96 bits, the usual case: J0 = nonce || 0^31 || 1.
  * anything else: J0 = GHASH(nonce, zero padded, then a length block).

Encryption starts at inc32(J0); J0 itself is reserved for masking the tag.
*/

use super::ghash::Ghash;
use super::BlockCipher;
use core::cmp::min;

/// The block size GCM is defined for, in bytes.
const BLOCK: usize = 16;

/// Counter blocks encrypted per call to the cipher: sixteen is AES's
/// bitsliced batch.
const KEYSTREAM_BLOCKS: usize = 16;

/// The largest plaintext GCM may protect under one key and nonce:
/// 2^39 - 256 bits, from SP 800-38D. Past it the 32 bit counter wraps back
/// onto blocks it has already used, and the keystream repeats.
const MAX_TEXT_LEN: u64 = (1 << 36) - 32;

/// Which direction a stream is going. Encryption hashes the ciphertext it
/// just produced; decryption hashes the ciphertext before turning it into
/// plaintext. Same bytes, opposite order relative to the XOR.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// GCM state, owning no cipher.
pub struct GcmState {
    ghash: Ghash,
    /// `E_K(J0)`, the pre-counter block encrypted: it masks the tag.
    tag_mask: [u8; BLOCK],
    counter: [u8; BLOCK],
    keystream: Vec<u8>,
    pos: usize,
    aad_len: u64,
    text_len: u64,
    direction: Direction,
    /// Set once the tag has been produced or checked, so that a stream
    /// cannot be quietly continued afterwards.
    done: bool,
}

impl GcmState {
    /// Start an encryption. `aad` is authenticated but not encrypted.
    pub fn encryptor<C: BlockCipher + ?Sized>(cipher: &mut C, nonce: &[u8],
                                              aad: &[u8]) -> Result<GcmState, String> {
        GcmState::new(cipher, nonce, aad, Direction::Encrypt)
    }

    /// Start a decryption. Nothing it produces is trustworthy until
    /// `verify` has returned `Ok`.
    pub fn decryptor<C: BlockCipher + ?Sized>(cipher: &mut C, nonce: &[u8],
                                              aad: &[u8]) -> Result<GcmState, String> {
        GcmState::new(cipher, nonce, aad, Direction::Decrypt)
    }

    fn new<C: BlockCipher + ?Sized>(cipher: &mut C, nonce: &[u8], aad: &[u8],
                                    direction: Direction) -> Result<GcmState, String> {
        if cipher.blocksize() != BLOCK {
            return Err(format!(
                "GCM needs a 128 bit block cipher; this one has {} bit blocks. \
                 GHASH is defined in GF(2^128) and has no smaller counterpart.",
                cipher.blocksize() * 8));
        }
        if nonce.is_empty() {
            // GHASH of nothing is zero, so an empty nonce makes J0 zero for
            // every key - one fixed counter stream, shared by everyone.
            return Err("GCM nonce must not be empty.".to_string());
        }

        // H = E_K(0^128), the GHASH key, and E_K(J0), the tag mask - in one
        // call when J0 does not depend on H. Both go through
        // `encrypt_blocks`, the cipher's constant-time path where it has
        // one: H is the authentication key.
        let mut pair = [0u8; 2 * BLOCK];
        let short_nonce = nonce.len() == 12;
        if short_nonce {
            pair[BLOCK..BLOCK + 12].copy_from_slice(nonce);
            pair[2 * BLOCK - 1] = 1;
            cipher.encrypt_blocks(&mut pair)?;
        } else {
            cipher.encrypt_blocks(&mut pair[..BLOCK])?;
        }
        let h = &pair[..BLOCK];
        let mut ghash = Ghash::new(h)?;

        let j0 = if short_nonce {
            let mut j0 = [0u8; BLOCK];
            j0[..12].copy_from_slice(nonce);
            j0[15] = 1;
            j0
        } else {
            // GHASH(nonce || 0^s || 0^64 || [len(nonce)]_64). The length
            // block is what stops two nonces of different lengths that
            // share a prefix from colliding.
            let mut derive = Ghash::new(h)?;
            derive.update(nonce);
            derive.pad();
            let mut length_block = [0u8; BLOCK];
            length_block[8..].copy_from_slice(&((nonce.len() as u64) * 8).to_be_bytes());
            derive.update_block(&length_block);
            derive.digest()
        };

        ghash.update(aad);
        // The additional data is padded to a block boundary on its own,
        // before the ciphertext starts. Running the two together without
        // this padding would let bytes move between them without changing
        // the tag.
        ghash.pad();

        let mut tag_mask = [0u8; BLOCK];
        if short_nonce {
            tag_mask.copy_from_slice(&pair[BLOCK..]);
        } else {
            tag_mask = j0;
            cipher.encrypt_blocks(&mut tag_mask)?;
        }

        let mut counter = j0;
        inc32(&mut counter);

        Ok(GcmState {
            ghash,
            tag_mask,
            counter,
            keystream: Vec::with_capacity(KEYSTREAM_BLOCKS * BLOCK),
            // The refill condition is `pos == keystream.len()`, so an empty
            // keystream and pos 0 is what asks for the first block. Setting
            // pos to BLOCK here instead looks like "nothing buffered" and
            // is not: it makes the condition false against an empty
            // keystream, skips the refill, and then subtracts 16 from 0.
            pos: 0,
            aad_len: aad.len() as u64,
            text_len: 0,
            direction,
            done: false,
        })
    }

    /// Transform `buf` in place and absorb it into the tag.
    pub fn apply<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C,
                                          buf: &mut [u8]) -> Result<(), String> {
        if self.done {
            return Err("This GCM stream is finished; start another.".to_string());
        }
        self.text_len = self.text_len.checked_add(buf.len() as u64)
            .ok_or("GCM message length overflowed.")?;
        if self.text_len > MAX_TEXT_LEN {
            return Err(format!(
                "GCM refuses more than {} bytes under one key and nonce; past \
                 that the 32 bit counter wraps and the keystream repeats.",
                MAX_TEXT_LEN));
        }

        if self.direction == Direction::Decrypt {
            self.ghash.update(buf);
        }

        let mut done = 0;
        while done < buf.len() {
            if self.pos == self.keystream.len() && buf.len() - done >= BLOCK {
                // Whole blocks in one pass, where the cipher has one.
                let whole = (buf.len() - done) / BLOCK * BLOCK;
                if cipher.ctr_xor(&mut self.counter, &mut buf[done..done + whole], true)? {
                    done += whole;
                    continue;
                }
            }
            if self.pos == self.keystream.len() {
                // As many counter blocks as the rest of `buf` needs, up to
                // KEYSTREAM_BLOCKS, encrypted in one call. Unused keystream
                // is kept for the next call, so the counter always names
                // the next block not yet generated.
                let wanted = (buf.len() - done).div_ceil(BLOCK).min(KEYSTREAM_BLOCKS);
                self.keystream.clear();
                self.keystream.resize(wanted * BLOCK, 0);
                for block in self.keystream.chunks_exact_mut(BLOCK) {
                    let block: &mut [u8; BLOCK] = block.try_into().expect("a whole block");
                    *block = self.counter;
                    inc32(&mut self.counter);
                }
                cipher.encrypt_blocks(&mut self.keystream)?;
                self.pos = 0;
            }
            let n = min(buf.len() - done, self.keystream.len() - self.pos);
            for (b, k) in buf[done..done + n].iter_mut()
                             .zip(&self.keystream[self.pos..self.pos + n]) {
                *b ^= k;
            }
            done += n;
            self.pos += n;
        }

        if self.direction == Direction::Encrypt {
            self.ghash.update(buf);
        }
        Ok(())
    }

    /// Append the transform of `input` to `out`.
    pub fn update<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, input: &[u8],
                                           out: &mut Vec<u8>) -> Result<(), String> {
        let start = out.len();
        out.extend_from_slice(input);
        let result = self.apply(cipher, &mut out[start..]);
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    /// The tag over everything absorbed so far.
    fn compute_tag(&mut self) -> Result<[u8; BLOCK], String> {
        self.ghash.pad();
        let mut length_block = [0u8; BLOCK];
        length_block[..8].copy_from_slice(&(self.aad_len * 8).to_be_bytes());
        length_block[8..].copy_from_slice(&(self.text_len * 8).to_be_bytes());
        self.ghash.update_block(&length_block);
        let hash = self.ghash.digest();

        // The tag is the hash masked with E_K(J0) - the one counter block
        // the keystream never used.
        let mut tag = [0u8; BLOCK];
        for i in 0..BLOCK {
            tag[i] = hash[i] ^ self.tag_mask[i];
        }
        Ok(tag)
    }

    /// Finish an encryption and produce the tag.
    ///
    /// The cipher is not consulted - the tag mask was computed when
    /// the stream started - and is taken so that every `GcmState` call has
    /// the same shape.
    pub fn tag<C: BlockCipher + ?Sized>(&mut self, _cipher: &mut C)
                                        -> Result<[u8; BLOCK], String> {
        if self.direction != Direction::Encrypt {
            return Err("tag() is for encryption; a decryption calls verify()."
                       .to_string());
        }
        if self.done {
            return Err("This GCM stream is already finished.".to_string());
        }
        self.done = true;
        self.compute_tag()
    }

    /// Finish a decryption by checking the tag.
    ///
    /// A shorter tag than 16 bytes is accepted and compared over its own
    /// length, because the protocols that use one specify it. Anything
    /// under 12 bytes is refused: at that point a forgery succeeds often
    /// enough to be worth trying, and SP 800-38D permits 8 and 4 byte tags
    /// only for specific applications that can bound the number of
    /// attempts. Nothing here can bound that, so it does not offer them.
    pub fn verify<C: BlockCipher + ?Sized>(&mut self, _cipher: &mut C,
                                           expected: &[u8]) -> Result<(), String> {
        if self.direction != Direction::Decrypt {
            return Err("verify() is for decryption; an encryption calls tag()."
                       .to_string());
        }
        if self.done {
            return Err("This GCM stream is already finished.".to_string());
        }
        if expected.len() < 12 || expected.len() > BLOCK {
            return Err(format!(
                "GCM tag must be 12 to 16 bytes; got {}.", expected.len()));
        }
        self.done = true;
        let tag = self.compute_tag()?;

        // Constant time over the whole tag. An early return on the first
        // differing byte turns forgery into a byte-at-a-time search, which
        // is 16 * 256 tries instead of 2^128.
        let mut difference = 0u8;
        for i in 0..expected.len() {
            difference |= tag[i] ^ expected[i];
        }
        if difference != 0 {
            // One message, with nothing in it about where or how it
            // differed, and no plaintext.
            return Err("GCM authentication failed: the tag does not match. \
                        The data has been altered, or the key, nonce or \
                        additional data is not the one that protected it."
                       .to_string());
        }
        Ok(())
    }
}

/// Increment the rightmost 32 bits of a counter block, wrapping within
/// them. The first 12 bytes never change.
#[inline]
fn inc32(counter: &mut [u8; BLOCK]) {
    let n = u32::from_be_bytes(counter[12..].try_into().unwrap());
    counter[12..].copy_from_slice(&n.wrapping_add(1).to_be_bytes());
}

/// GCM paired with the cipher it drives.
pub struct Gcm<'a, C: BlockCipher + ?Sized> {
    cipher: &'a mut C,
    state: GcmState,
}

impl<'a, C: BlockCipher + ?Sized> Gcm<'a, C> {
    pub fn encryptor(cipher: &'a mut C, nonce: &[u8], aad: &[u8])
                     -> Result<Gcm<'a, C>, String> {
        let state = GcmState::encryptor(cipher, nonce, aad)?;
        Ok(Gcm { cipher, state })
    }

    pub fn decryptor(cipher: &'a mut C, nonce: &[u8], aad: &[u8])
                     -> Result<Gcm<'a, C>, String> {
        let state = GcmState::decryptor(cipher, nonce, aad)?;
        Ok(Gcm { cipher, state })
    }

    pub fn apply(&mut self, buf: &mut [u8]) -> Result<(), String> {
        self.state.apply(self.cipher, buf)
    }

    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        self.state.update(self.cipher, input, out)
    }

    pub fn tag(&mut self) -> Result<[u8; BLOCK], String> {
        self.state.tag(self.cipher)
    }

    pub fn verify(&mut self, expected: &[u8]) -> Result<(), String> {
        self.state.verify(self.cipher, expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::aes::AesCrypto;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn seal(key: &str, nonce: &str, aad: &str, plaintext: &str) -> (String, String) {
        let mut cipher = AesCrypto::new(unhex(key)).unwrap();
        let mut gcm = Gcm::encryptor(&mut cipher, &unhex(nonce), &unhex(aad)).unwrap();
        let mut out = Vec::new();
        gcm.update(&unhex(plaintext), &mut out).unwrap();
        let tag = gcm.tag().unwrap();
        (hex(&out), hex(&tag))
    }

    /// The test cases from the GCM specification (McGrew and Viega, and
    /// SP 800-38D's companion vectors). Cases 1 through 6, which between
    /// them cover: empty plaintext, one block, a long plaintext with no
    /// additional data, additional data with a truncated final block, a
    /// 64 bit nonce, and a nonce long enough to be hashed rather than
    /// used directly.
    #[test]
    fn test_the_specification_vectors() {
        // 1: everything empty.
        let (ciphertext, tag) = seal("00000000000000000000000000000000",
                                     "000000000000000000000000", "", "");
        assert_eq!(ciphertext, "");
        assert_eq!(tag, "58e2fccefa7e3061367f1d57a4e7455a");

        // 2: one block of zeros, no additional data.
        let (ciphertext, tag) = seal("00000000000000000000000000000000",
                                     "000000000000000000000000", "",
                                     "00000000000000000000000000000000");
        assert_eq!(ciphertext, "0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(tag, "ab6e47d42cec13bdf53a67b21257bddf");

        // 3: four blocks, a real key, no additional data.
        let (ciphertext, tag) = seal(
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888", "",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39\
             1aafd255");
        assert_eq!(ciphertext,
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
             473f5985");
        assert_eq!(tag, "4d5c2af327cd64a62cf35abd2ba6fab4");

        // 4: additional data, and a plaintext whose last block is partial.
        let (ciphertext, tag) = seal(
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        assert_eq!(ciphertext,
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
        assert_eq!(tag, "5bc94fbc3221a5db94fae95ae7121a47");

        // 5: a 64 bit nonce, so J0 comes from GHASH rather than directly.
        let (ciphertext, tag) = seal(
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbad",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        assert_eq!(ciphertext,
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423\
             73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598");
        assert_eq!(tag, "3612d2e79e3b0785561be14aaca2fccb");

        // 6: a 60 byte nonce, well past a block.
        let (ciphertext, tag) = seal(
            "feffe9928665731c6d6a8f9467308308",
            "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728\
             c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        assert_eq!(ciphertext,
            "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7\
             01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5");
        assert_eq!(tag, "619cc5aefffe0bfa462af43c1699d050");
    }

    /// AES-256 and AES-192, so the mode is not quietly tied to one key size.
    #[test]
    fn test_other_key_sizes() {
        let (ciphertext, tag) = seal(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888", "",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39\
             1aafd255");
        assert_eq!(ciphertext,
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662\
             898015ad");
        assert_eq!(tag, "b094dac5d93471bdec1a502270e3cc6c");

        let (ciphertext, tag) = seal(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            "cafebabefacedbaddecaf888", "",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39\
             1aafd255");
        assert_eq!(ciphertext,
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
             7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710\
             acade256");
        assert_eq!(tag, "9924a7c8587336bfb118024db8674a14");
    }

    #[test]
    fn test_round_trip() {
        let key = unhex("feffe9928665731c6d6a8f9467308308");
        let nonce = unhex("cafebabefacedbaddecaf888");
        let aad = b"headers that travel in the clear";
        let message = b"the payload, of an awkward length";

        let mut cipher = AesCrypto::new(key.clone()).unwrap();
        let mut sealing = Gcm::encryptor(&mut cipher, &nonce, aad).unwrap();
        let mut sealed = Vec::new();
        sealing.update(message, &mut sealed).unwrap();
        let tag = sealing.tag().unwrap();

        let mut cipher = AesCrypto::new(key.clone()).unwrap();
        let mut opening = Gcm::decryptor(&mut cipher, &nonce, aad).unwrap();
        let mut opened = Vec::new();
        opening.update(&sealed, &mut opened).unwrap();
        opening.verify(&tag).unwrap();
        assert_eq!(opened, message);
    }

    /// Every single-bit change anywhere must be caught: in the ciphertext,
    /// in the tag, in the additional data, and in the nonce.
    #[test]
    fn test_nothing_gets_past_the_tag() {
        let key = unhex("feffe9928665731c6d6a8f9467308308");
        let nonce = unhex("cafebabefacedbaddecaf888");
        let aad = b"authenticated".to_vec();
        let message = b"a message worth protecting".to_vec();

        let mut cipher = AesCrypto::new(key.clone()).unwrap();
        let mut sealing = Gcm::encryptor(&mut cipher, &nonce, &aad).unwrap();
        let mut sealed = Vec::new();
        sealing.update(&message, &mut sealed).unwrap();
        let tag = sealing.tag().unwrap();

        let open = |ciphertext: &[u8], tag: &[u8], aad: &[u8], nonce: &[u8]| {
            let mut cipher = AesCrypto::new(key.clone()).unwrap();
            let mut gcm = Gcm::decryptor(&mut cipher, nonce, aad)?;
            let mut out = Vec::new();
            gcm.update(ciphertext, &mut out)?;
            gcm.verify(tag)?;
            Ok::<Vec<u8>, String>(out)
        };

        assert!(open(&sealed, &tag, &aad, &nonce).is_ok());

        for index in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[index] ^= 0x01;
            assert!(open(&altered, &tag, &aad, &nonce).is_err(),
                    "a flipped ciphertext byte at {} was accepted", index);
        }
        for index in 0..tag.len() {
            let mut altered = tag;
            altered[index] ^= 0x01;
            assert!(open(&sealed, &altered, &aad, &nonce).is_err(),
                    "a flipped tag byte at {} was accepted", index);
        }
        for index in 0..aad.len() {
            let mut altered = aad.clone();
            altered[index] ^= 0x01;
            assert!(open(&sealed, &tag, &altered, &nonce).is_err(),
                    "a flipped aad byte at {} was accepted", index);
        }
        for index in 0..nonce.len() {
            let mut altered = nonce.clone();
            altered[index] ^= 0x01;
            assert!(open(&sealed, &tag, &aad, &altered).is_err(),
                    "a flipped nonce byte at {} was accepted", index);
        }

        // Truncation, which a length-unaware MAC would miss.
        assert!(open(&sealed[..sealed.len() - 1], &tag, &aad, &nonce).is_err());
        // And moving a byte from the additional data into the ciphertext,
        // which is what the padding between the two sections prevents.
        assert!(open(&sealed, &tag, &aad[..aad.len() - 1], &nonce).is_err());
    }

    /// A failed decryption must leave no plaintext in the caller's buffer.
    /// Returning the bytes alongside the error is how unverified plaintext
    /// gets used by a caller that checks the error one line too late.
    #[test]
    fn test_a_failure_leaves_nothing_behind() {
        let key = unhex("feffe9928665731c6d6a8f9467308308");
        let nonce = unhex("cafebabefacedbaddecaf888");

        let mut cipher = AesCrypto::new(key.clone()).unwrap();
        let mut sealing = Gcm::encryptor(&mut cipher, &nonce, b"").unwrap();
        let mut sealed = Vec::new();
        sealing.update(b"secret", &mut sealed).unwrap();
        let mut tag = sealing.tag().unwrap();
        tag[0] ^= 0xff;

        let mut cipher = AesCrypto::new(key.clone()).unwrap();
        let mut gcm = Gcm::decryptor(&mut cipher, &nonce, b"").unwrap();
        let mut out = Vec::new();
        gcm.update(&sealed, &mut out).unwrap();
        assert!(gcm.verify(&tag).is_err());

        // `out` does hold the decrypted bytes here, because streaming
        // decryption cannot avoid that - which is precisely why `verify`
        // exists as a separate, mandatory step and why the one-shot
        // `gcm_decrypt` on the trait clears the buffer itself.
        let mut one_shot = Vec::new();
        let mut cipher = AesCrypto::new(key.clone()).unwrap();
        assert!(cipher.gcm_decrypt(&sealed, &mut one_shot, &nonce, &tag, b"").is_err());
        assert!(one_shot.is_empty(), "the one-shot API leaked unverified plaintext");
    }

    /// Streaming in awkward pieces must equal one call, in both directions.
    #[test]
    fn test_streaming_equals_one_call() {
        let key = unhex("feffe9928665731c6d6a8f9467308308");
        let nonce = unhex("cafebabefacedbaddecaf888");
        let message: Vec<u8> = (0..300u32).map(|i| (i * 11 + 5) as u8).collect();

        let mut cipher = AesCrypto::new(key.clone()).unwrap();
        let mut whole = Gcm::encryptor(&mut cipher, &nonce, b"aad").unwrap();
        let mut expected = Vec::new();
        whole.update(&message, &mut expected).unwrap();
        let expected_tag = whole.tag().unwrap();

        for size in [1usize, 5, 15, 16, 17, 33, 128] {
            let mut cipher = AesCrypto::new(key.clone()).unwrap();
            let mut gcm = Gcm::encryptor(&mut cipher, &nonce, b"aad").unwrap();
            let mut out = Vec::new();
            for piece in message.chunks(size) {
                gcm.update(piece, &mut out).unwrap();
            }
            assert_eq!(out, expected, "encrypting in {} byte pieces", size);
            assert_eq!(gcm.tag().unwrap(), expected_tag, "tag, {} byte pieces", size);

            let mut cipher = AesCrypto::new(key.clone()).unwrap();
            let mut gcm = Gcm::decryptor(&mut cipher, &nonce, b"aad").unwrap();
            let mut back = Vec::new();
            for piece in expected.chunks(size) {
                gcm.update(piece, &mut back).unwrap();
            }
            gcm.verify(&expected_tag).unwrap();
            assert_eq!(back, message, "decrypting in {} byte pieces", size);
        }
    }

    /// GCM is GF(2^128) or nothing. A 64 bit block cipher must be refused
    /// rather than given some improvised smaller construction.
    #[test]
    fn test_a_64_bit_block_cipher_is_refused() {
        use crate::block_ciphers::blowfish::Blowfish;
        let mut cipher = Blowfish::new(vec![0x2b; 16]);
        match GcmState::encryptor(&mut cipher, &[0u8; 12], b"") {
            Ok(_) => panic!("GCM accepted a 64 bit block cipher"),
            Err(error) => assert!(error.contains("128 bit"), "{}", error),
        }
    }

    #[test]
    fn test_the_nonce_and_tag_lengths_are_checked() {
        let mut cipher = AesCrypto::new(vec![0u8; 16]).unwrap();
        assert!(GcmState::encryptor(&mut cipher, &[], b"").is_err());

        // A tag short enough to be guessable is refused rather than
        // compared over its first few bytes.
        for length in [0usize, 1, 4, 8, 11, 17, 32] {
            let mut cipher = AesCrypto::new(vec![0u8; 16]).unwrap();
            let mut gcm = Gcm::decryptor(&mut cipher, &[0u8; 12], b"").unwrap();
            assert!(gcm.verify(&vec![0u8; length]).is_err(), "tag length {}", length);
        }
    }

    /// Finishing twice, or carrying on after finishing, is a mistake rather
    /// than something with a defined answer.
    #[test]
    fn test_a_finished_stream_stays_finished() {
        let mut cipher = AesCrypto::new(vec![0u8; 16]).unwrap();
        let mut gcm = Gcm::encryptor(&mut cipher, &[0u8; 12], b"").unwrap();
        let mut out = Vec::new();
        gcm.update(b"data", &mut out).unwrap();
        assert!(gcm.tag().is_ok());
        assert!(gcm.tag().is_err());
        assert!(gcm.update(b"more", &mut out).is_err());
    }

    /// The counter increments 32 bits, not 128. The distinction only shows
    /// up when those 32 bits carry, which never happens in a test vector
    /// or in any message short enough to write down.
    #[test]
    fn test_the_keystream_counter_wraps_within_32_bits() {
        // A counter four blocks from wrapping, set directly: no nonce a
        // test can choose puts GCM's counter there. With AES-NI the
        // keystream comes from `ctr_xor`, which must be told the counter
        // is GCM's; without it, from `inc32`.
        let mut aes = crate::block_ciphers::aes::AesCrypto::new(vec![9; 16]).unwrap();
        let mut state = GcmState::encryptor(&mut aes, &[1; 12], b"").unwrap();
        let mut start = [0xAAu8; 16];
        start[12..].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFD]);
        state.counter = start;
        let mut data = vec![0u8; 16 * 9];
        state.apply(&mut aes, &mut data).unwrap();
        let mut counter = start;
        let mut expected = Vec::new();
        for _ in 0..9 {
            expected.extend_from_slice(&counter);
            inc32(&mut counter);
        }
        aes.encrypt_blocks(&mut expected).unwrap();
        assert_eq!(data, expected);
        assert_eq!(state.counter, counter);
    }

    #[test]
    fn test_the_counter_wraps_within_32_bits() {
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(&[0xaa; 12]);
        counter[12..].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);

        inc32(&mut counter);

        // Wrapped to zero, and the first twelve bytes untouched. A whole
        // block increment would have carried into byte 11.
        assert_eq!(&counter[..12], &[0xaa; 12]);
        assert_eq!(&counter[12..], &[0, 0, 0, 0]);
    }
}
