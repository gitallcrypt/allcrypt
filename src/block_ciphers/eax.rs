/*
EAX, an authenticated mode by Bellare, Rogaway and Wagner (2003).

CTR for confidentiality and OMAC for authenticity, over any block
cipher. It was designed as an answer to CCM's awkwardness and does three
things CCM cannot:

  * **it streams.** CCM's MAC begins with the message's length, so
    nothing can be encrypted until the length is known and `AeadStream`
    has to buffer the whole message. EAX authenticates the *ciphertext*,
    so both passes run forwards and `buffers_everything()` is false.
  * **the nonce is any length.** CCM's is 7..13 bytes and trades off
    against the maximum message size. EAX hashes the nonce through OMAC,
    so any length works and none of them collide by construction.
  * **it is online in the associated data too.**

It is in a good deal of software - notably as one of the two modes in
the original OCB patent workaround era - and it is a mode any block
cipher here gets for free, which is the point of `BlockCipher`.

## The construction

    N = OMAC(0, nonce)
    H = OMAC(1, header)
    C = CTR(key, N, plaintext)
    T = OMAC(2, C)
    tag = N ^ H ^ T

where `OMAC(i, M)` is CMAC over `[i]_blocksize || M` - the index written
as **a whole block**, big endian, not a single byte. For a 16 byte block
that is fifteen zeros and then `i`.

Four things are silent when wrong:

  * **the three tweaks must differ.** Using one index for all three
    makes `N`, `H` and `T` interchangeable, and a forger can move bytes
    between the nonce and the header.
  * **the index is a full block**, not one byte. Both encodings produce
    a tag; only one interoperates.
  * **the CTR nonce is `N`, not the nonce.** `N` is the OMAC of it.
  * **the MAC covers the ciphertext**, not the plaintext. Authenticating
    the plaintext is encrypt-and-MAC, which is the composition with the
    worst reputation, and it round-trips against itself perfectly.

## The tag may be truncated

EAX's tag is the block size, and a shorter one is the first bytes of it.
`Eax::with_tag_len` takes that; the vectors carry an `EAX(8)` section
for exactly this. A truncated tag is a weaker forgery bound and is the
caller's decision, so it is a parameter rather than a default.
*/

use crate::block_ciphers::modes::CtrState;
use crate::mac::cmac::Cmac;
use crate::Mac;

/// One EAX operation over a named cipher.
pub struct Eax {
    cipher_name: String,
    key: Vec<u8>,
    block_size: usize,
    tag_len: usize,
}

impl Eax {
    pub fn new(cipher_name: &str, key: &[u8]) -> Result<Eax, String> {
        // CMAC's tag is one block, so its length is the block size -
        // and asking CMAC rather than the cipher means one place decides
        // what block size this key implies.
        let block_size = Cmac::with_key(cipher_name, key)?.tag_len();
        Ok(Eax {
            cipher_name: cipher_name.to_string(),
            key: key.to_vec(),
            block_size,
            tag_len: block_size,
        })
    }

    /// A truncated tag. `tag_len` is in bytes and must not exceed the
    /// block size - a "tag" longer than the value it comes from would
    /// have to invent bytes.
    pub fn with_tag_len(cipher_name: &str, key: &[u8], tag_len: usize)
                        -> Result<Eax, String> {
        let mut eax = Eax::new(cipher_name, key)?;
        if tag_len == 0 || tag_len > eax.block_size {
            return Err(format!(
                "An EAX tag is 1..={} bytes for this cipher; {} was asked for.",
                eax.block_size, tag_len));
        }
        eax.tag_len = tag_len;
        Ok(eax)
    }

    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// `OMAC(index, message)`: CMAC over the index as a whole block,
    /// then the message.
    fn omac(&self, index: u8, message: &[u8]) -> Result<Vec<u8>, String> {
        let mut mac = Cmac::with_key(&self.cipher_name, &self.key)?;
        // **A whole block, not a byte.** Fifteen zeros then the index,
        // for a 16 byte block.
        let mut prefix = vec![0u8; self.block_size];
        prefix[self.block_size - 1] = index;
        mac.update(&prefix);
        mac.update(message);
        Ok(mac.digest())
    }

    /// Encrypt, returning `(ciphertext, tag)`.
    pub fn encrypt(&self, nonce: &[u8], header: &[u8], plaintext: &[u8])
                   -> Result<(Vec<u8>, Vec<u8>), String> {
        let n = self.omac(0, nonce)?;
        let h = self.omac(1, header)?;

        let mut cipher = crate::api::AnyBlockCipher::new(&self.cipher_name, &self.key, None)?;
        // The CTR nonce is `N`, the OMAC of the nonce - not the nonce.
        let mut ciphertext = plaintext.to_vec();
        let mut ctr = CtrState::new(&mut cipher, &n)?;
        ctr.apply(&mut cipher, &mut ciphertext)?;

        // Over the **ciphertext**. Authenticating the plaintext here
        // round-trips perfectly and is encrypt-and-MAC.
        let t = self.omac(2, &ciphertext)?;

        let mut tag = vec![0u8; self.block_size];
        for i in 0..self.block_size {
            tag[i] = n[i] ^ h[i] ^ t[i];
        }
        tag.truncate(self.tag_len);
        Ok((ciphertext, tag))
    }

    /// Decrypt, checking the tag **before** returning any plaintext.
    pub fn decrypt(&self, nonce: &[u8], header: &[u8], ciphertext: &[u8],
                   tag: &[u8]) -> Result<Vec<u8>, String> {
        if tag.len() != self.tag_len {
            return Err(format!("An EAX tag is {} bytes here; got {}.",
                               self.tag_len, tag.len()));
        }
        let n = self.omac(0, nonce)?;
        let h = self.omac(1, header)?;
        let t = self.omac(2, ciphertext)?;

        let mut expected = vec![0u8; self.block_size];
        for i in 0..self.block_size {
            expected[i] = n[i] ^ h[i] ^ t[i];
        }
        expected.truncate(self.tag_len);

        // Constant time, and the whole tag. A comparison that stops at
        // the first differing byte is a forgery oracle.
        if crate::bignum::ct::bytes_differ(&expected, tag) {
            return Err("The EAX tag does not match; the message was altered \
                        or was not for this key.".to_string());
        }

        // **Only now.** Returning plaintext before the tag is checked is
        // the release-unverified-plaintext mistake, and it is the one
        // thing an AEAD exists to prevent.
        let mut cipher = crate::api::AnyBlockCipher::new(&self.cipher_name, &self.key, None)?;
        let mut plaintext = ciphertext.to_vec();
        let mut ctr = CtrState::new(&mut cipher, &n)?;
        ctr.apply(&mut cipher, &mut plaintext)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../vectors/eax.vec");

    fn unhex(value: &str) -> Vec<u8> {
        let cleaned: Vec<char> = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        cleaned.chunks(2)
            .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), 16).unwrap())
            .collect()
    }

    struct Vector {
        cipher: String,
        tag_len: Option<usize>,
        key: Vec<u8>,
        nonce: Vec<u8>,
        header: Vec<u8>,
        input: Vec<u8>,
        output: Vec<u8>,
    }

    /// Botan's AEAD format, which carries `AD` as well and states the
    /// cipher and tag length in the section heading:
    /// `[AES-128/EAX]` or `[AES-128/EAX(8)]`.
    ///
    /// Sections naming a cipher this library does not have are skipped,
    /// and `test_the_vector_file_parses` asserts which ones were used -
    /// a skip that grew to cover everything is how a file quietly stops
    /// testing anything.
    fn vectors() -> Vec<Vector> {
        let mut out = Vec::new();
        let mut cipher = String::new();
        let mut tag_len = None;
        let (mut key, mut nonce, mut header, mut input) =
            (Vec::new(), Vec::new(), Vec::new(), None);

        for line in VECTORS.lines() {
            let line = line.trim();
            if let Some(heading) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let (name, rest) = heading.split_once('/').unwrap_or((heading, ""));
                cipher = match name {
                    "AES-128" | "AES-192" | "AES-256" => "aes".to_string(),
                    "Blowfish" => "blowfish".to_string(),
                    "DES" => "des".to_string(),
                    "TripleDES" => "3des".to_string(),
                    "Twofish" => "twofish".to_string(),
                    // Threefish-512 is not implemented here.
                    _ => String::new(),
                };
                tag_len = rest.strip_prefix("EAX(")
                    .and_then(|r| r.strip_suffix(')'))
                    .map(|n| n.parse().unwrap());
                continue;
            }
            if cipher.is_empty() || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((name, value)) = line.split_once('=') else { continue };
            match name.trim() {
                "Key" => key = unhex(value),
                "Nonce" => nonce = unhex(value),
                "AD" => header = unhex(value),
                "In" => input = Some(unhex(value)),
                "Out" => {
                    if let Some(plain) = input.take() {
                        out.push(Vector {
                            cipher: cipher.clone(), tag_len,
                            key: key.clone(), nonce: nonce.clone(),
                            header: core::mem::take(&mut header),
                            input: plain, output: unhex(value),
                        });
                    }
                }
                _ => continue,
            }
        }
        out
    }

    #[test]
    fn test_the_vector_file_parses() {
        let parsed = vectors();
        assert_eq!(parsed.len(), 190, "vectors/eax.vec should give 190 usable cases");

        let ciphers: std::collections::HashSet<&str> =
            parsed.iter().map(|v| v.cipher.as_str()).collect();
        // Five ciphers, three block sizes between them - so the block
        // size is exercised rather than assumed to be 16.
        assert_eq!(ciphers, ["aes", "blowfish", "des", "3des", "twofish"]
                   .into_iter().collect());
        assert!(parsed.iter().any(|v| v.tag_len == Some(8)),
                "no truncated-tag case, so with_tag_len is untested");
        assert!(parsed.iter().any(|v| !v.header.is_empty()),
                "no case with associated data, so OMAC(1, header) is untested");
        assert!(parsed.iter().any(|v| v.input.is_empty()),
                "no empty-message case");
    }

    #[test]
    fn test_every_vector() {
        for (index, vector) in vectors().iter().enumerate() {
            let eax = match vector.tag_len {
                Some(n) => Eax::with_tag_len(&vector.cipher, &vector.key, n).unwrap(),
                None => Eax::new(&vector.cipher, &vector.key).unwrap(),
            };
            let (ciphertext, tag) = eax
                .encrypt(&vector.nonce, &vector.header, &vector.input)
                .unwrap();

            // Botan's `Out` is ciphertext followed by the tag.
            let mut combined = ciphertext.clone();
            combined.extend_from_slice(&tag);
            assert_eq!(combined, vector.output,
                       "vector {} ({}, {} byte message)",
                       index, vector.cipher, vector.input.len());

            let back = eax.decrypt(&vector.nonce, &vector.header, &ciphertext, &tag)
                .unwrap_or_else(|e| panic!("vector {index} did not decrypt: {e}"));
            assert_eq!(back, vector.input);
        }
    }

    /// The three OMAC tweaks must differ, or the nonce, header and
    /// ciphertext MACs become interchangeable and a forger can move
    /// bytes between them. No round trip can see it.
    #[test]
    fn test_the_three_tweaks_give_different_macs() {
        let eax = Eax::new("aes", &[0x11; 16]).unwrap();
        let message = b"the same message";
        let zero = eax.omac(0, message).unwrap();
        let one = eax.omac(1, message).unwrap();
        let two = eax.omac(2, message).unwrap();
        assert_ne!(zero, one);
        assert_ne!(one, two);
        assert_ne!(zero, two);
    }

    /// The index is a whole block, not a byte. Both encodings produce a
    /// tag; only one interoperates, and the vectors are the only other
    /// thing that would notice.
    #[test]
    fn test_the_tweak_is_a_whole_block() {
        let eax = Eax::new("aes", &[0x22; 16]).unwrap();
        let by_omac = eax.omac(2, b"abc").unwrap();

        let mut mac = Cmac::with_key("aes", &[0x22; 16]).unwrap();
        let mut expected = vec![0u8; 16];
        expected[15] = 2;
        mac.update(&expected);
        mac.update(b"abc");
        assert_eq!(by_omac, mac.digest());

        // And *not* the one-byte encoding.
        let mut mac = Cmac::with_key("aes", &[0x22; 16]).unwrap();
        mac.update(&[2u8]);
        mac.update(b"abc");
        assert_ne!(by_omac, mac.digest());
    }

    #[test]
    fn test_altering_anything_is_refused() {
        let eax = Eax::new("aes", &[0x33; 16]).unwrap();
        let nonce = b"a nonce";
        let header = b"associated data";
        let message = b"the plaintext message";
        let (ciphertext, tag) = eax.encrypt(nonce, header, message).unwrap();
        assert_eq!(eax.decrypt(nonce, header, &ciphertext, &tag).unwrap(), message);

        for index in 0..ciphertext.len() {
            let mut altered = ciphertext.clone();
            altered[index] ^= 0x01;
            assert!(eax.decrypt(nonce, header, &altered, &tag).is_err());
        }
        for index in 0..tag.len() {
            let mut altered = tag.clone();
            altered[index] ^= 0x01;
            assert!(eax.decrypt(nonce, header, &ciphertext, &altered).is_err());
        }
        assert!(eax.decrypt(b"b nonce", header, &ciphertext, &tag).is_err());
        assert!(eax.decrypt(nonce, b"other data", &ciphertext, &tag).is_err());
    }

    /// The nonce may be any length, which is one of the two things EAX
    /// has over CCM. Each one must give a different ciphertext.
    #[test]
    fn test_a_nonce_of_any_length_works_and_matters() {
        let eax = Eax::new("aes", &[0x44; 16]).unwrap();
        let mut seen = std::collections::HashSet::new();
        for length in [0usize, 1, 7, 13, 16, 17, 100] {
            let nonce = vec![0x5au8; length];
            let (ciphertext, tag) = eax.encrypt(&nonce, b"", b"message").unwrap();
            assert_eq!(eax.decrypt(&nonce, b"", &ciphertext, &tag).unwrap(), b"message");
            assert!(seen.insert((ciphertext, tag)), "length {length} collided");
        }
    }

    #[test]
    fn test_a_truncated_tag_is_a_prefix_of_the_full_one() {
        let full = Eax::new("aes", &[0x55; 16]).unwrap();
        let short = Eax::with_tag_len("aes", &[0x55; 16], 8).unwrap();
        let (c1, t1) = full.encrypt(b"n", b"h", b"m").unwrap();
        let (c2, t2) = short.encrypt(b"n", b"h", b"m").unwrap();
        assert_eq!(c1, c2, "truncating the tag must not change the ciphertext");
        assert_eq!(&t1[..8], &t2[..]);

        // And a full tag is not accepted where a short one is expected,
        // nor the reverse - a length mismatch is a refusal rather than a
        // silent prefix comparison.
        assert!(short.decrypt(b"n", b"h", &c2, &t1).is_err());
        assert!(full.decrypt(b"n", b"h", &c1, &t2).is_err());
    }

    #[test]
    fn test_bad_tag_lengths_are_refused() {
        for length in [0usize, 17, 100] {
            assert!(Eax::with_tag_len("aes", &[0u8; 16], length).is_err(),
                    "accepted a {length} byte tag");
        }
        // A 64 bit block cipher has an 8 byte tag at most.
        assert!(Eax::with_tag_len("des", &[0u8; 8], 16).is_err());
        assert!(Eax::with_tag_len("des", &[0u8; 8], 8).is_ok());
    }

    /// The MAC covers the ciphertext. Authenticating the plaintext
    /// instead is encrypt-and-MAC and round-trips perfectly, so this
    /// asserts the property directly.
    #[test]
    fn test_the_mac_covers_the_ciphertext() {
        let eax = Eax::new("aes", &[0x66; 16]).unwrap();
        let (ciphertext, tag) = eax.encrypt(b"nonce", b"", b"plaintext").unwrap();

        let n = eax.omac(0, b"nonce").unwrap();
        let h = eax.omac(1, b"").unwrap();
        let over_ciphertext = eax.omac(2, &ciphertext).unwrap();
        let over_plaintext = eax.omac(2, b"plaintext").unwrap();

        let combine = |t: &[u8]| -> Vec<u8> {
            (0..16).map(|i| n[i] ^ h[i] ^ t[i]).collect()
        };
        assert_eq!(tag, combine(&over_ciphertext));
        assert_ne!(tag, combine(&over_plaintext));
    }
}
