/*
ChaCha20-Poly1305 (RFC 8439 section 2.8).

The other AEAD, and the one to reach for when there is no AES instruction
in the hardware: ChaCha and Poly1305 are both built from 32 bit adds, XORs
and rotations, so a software implementation is fast and constant time
without effort. Software AES has to choose between lookup tables, which
leak through the cache, and bitslicing, which is slower; see
`block_ciphers/aes.rs`.

The construction:

    poly_key   = first 32 bytes of ChaCha20(key, nonce, counter = 0)
    ciphertext = ChaCha20(key, nonce, counter = 1) XOR plaintext
    tag        = Poly1305(poly_key, aad || pad || ct || pad || lengths)

Three details that are easy to get self-consistently wrong:

**Block zero is the Poly1305 key and block one starts the payload.** They
must not overlap. Encrypting from block zero would hand out, as the
authentication key, the very keystream that protects the first 32 bytes of
the message - after which forging anything is arithmetic.

**Each section is padded to a 16 byte boundary before the next begins.**
Without that padding a byte can move between the additional data and the
ciphertext without changing what Poly1305 sees.

**The lengths are little-endian byte counts.** GCM's are big-endian *bit*
counts. Both trailers are 16 bytes, both hold two numbers, and swapping
the conventions produces something that round-trips perfectly and
interoperates with nothing.

**The Poly1305 key is per-message by construction**, which is what makes
this safe to use at all: Poly1305 is a one-time authenticator, and two
messages under one r give away r. Here r comes from the nonce, so the
nonce rule is the same as GCM's and just as sharp. See docs/pitfalls.md.
*/

use crate::mac::Poly1305;
use crate::stream_ciphers::chacha::Chacha;
use crate::stream_ciphers::StreamCipher;
use crate::Mac;

/// The tag length, and the only one this AEAD has.
pub const TAG_LEN: usize = 16;

/// The largest plaintext one key and nonce may protect: blocks 1 to
/// 2^32 - 1 of the keystream, block zero being the Poly1305 key (RFC 8439
/// section 2.8). Past it the 32 bit counter wraps and the payload is
/// XORed with keystream already used - with the Poly1305 key's own block
/// first, so the tag then protects nothing. Checked up front, like GCM's
/// limit, because the trait the cipher streams through has no error.
pub const MAX_TEXT_LEN: u64 = ((1u64 << 32) - 1) * 64;

/// Which direction a stream is going.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// One ChaCha20-Poly1305 message in progress.
pub struct ChaCha20Poly1305 {
    cipher: Chacha,
    mac: Poly1305,
    aad_len: u64,
    text_len: u64,
    direction: Direction,
    done: bool,
}

impl ChaCha20Poly1305 {
    pub fn encryptor(key: &[u8], nonce: &[u8], aad: &[u8])
                     -> Result<ChaCha20Poly1305, String> {
        ChaCha20Poly1305::new(key, nonce, aad, Direction::Encrypt)
    }

    pub fn decryptor(key: &[u8], nonce: &[u8], aad: &[u8])
                     -> Result<ChaCha20Poly1305, String> {
        ChaCha20Poly1305::new(key, nonce, aad, Direction::Decrypt)
    }

    /// AEAD_XChaCha20_Poly1305 (draft-irtf-cfrg-xchacha section 2): the
    /// same AEAD under HChaCha20's subkey, with a 24 byte nonce. A random
    /// nonce of that length can be drawn per message without counting
    /// messages, which a 12 byte one cannot.
    pub fn x_encryptor(key: &[u8], nonce: &[u8], aad: &[u8])
                       -> Result<ChaCha20Poly1305, String> {
        let (subkey, short) = crate::stream_ciphers::chacha::xchacha20_subkey(key, nonce)?;
        ChaCha20Poly1305::new(&subkey, &short, aad, Direction::Encrypt)
    }

    pub fn x_decryptor(key: &[u8], nonce: &[u8], aad: &[u8])
                       -> Result<ChaCha20Poly1305, String> {
        let (subkey, short) = crate::stream_ciphers::chacha::xchacha20_subkey(key, nonce)?;
        ChaCha20Poly1305::new(&subkey, &short, aad, Direction::Decrypt)
    }

    fn new(key: &[u8], nonce: &[u8], aad: &[u8], direction: Direction)
           -> Result<ChaCha20Poly1305, String> {
        if key.len() != 32 {
            return Err(format!(
                "ChaCha20-Poly1305 takes a 32 byte key, got {}.", key.len()));
        }
        if nonce.len() != 12 {
            // The 8 byte nonce is the original DJB construction, and the
            // AEAD is not defined over it: RFC 8439 fixes the nonce at 96
            // bits so that the block counter is a full 32 bits.
            return Err(format!(
                "ChaCha20-Poly1305 takes a 12 byte nonce, got {}.", nonce.len()));
        }

        // Block zero, of which the first 32 bytes are the one-time
        // Poly1305 key. The rest of the block is discarded - it is not
        // keystream for anything, and reusing it would be exactly the
        // overlap this construction exists to avoid.
        let mut key_stream = Chacha::new(key, nonce, 20)?;
        let mut block = Vec::with_capacity(64);
        key_stream.crypt(&[0u8; 64], &mut block);
        let mac = Poly1305::new(&block[..32])?;

        // The payload starts at block one.
        let mut cipher = Chacha::new(key, nonce, 20)?;
        cipher.set_counter(1)?;

        let mut state = ChaCha20Poly1305 {
            cipher,
            mac,
            aad_len: aad.len() as u64,
            text_len: 0,
            direction,
            done: false,
        };
        state.mac.update(aad);
        state.pad_mac(aad.len());
        Ok(state)
    }

    /// Pad the MAC input up to a 16 byte boundary with zeros.
    fn pad_mac(&mut self, written: usize) {
        let remainder = written % 16;
        if remainder != 0 {
            self.mac.update(&[0u8; 16][..16 - remainder]);
        }
    }

    /// Transform `buf` in place and absorb the ciphertext into the tag.
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<(), String> {
        if self.done {
            return Err("This stream is finished; start another.".to_string());
        }
        let text_len = self.text_len.checked_add(buf.len() as u64)
            .ok_or("Message length overflowed.")?;
        if text_len > MAX_TEXT_LEN {
            return Err(format!(
                "ChaCha20-Poly1305 refuses more than {} bytes under one key and \
                 nonce; past that the 32 bit counter wraps and the keystream \
                 repeats.", MAX_TEXT_LEN));
        }
        self.text_len = text_len;

        if self.direction == Direction::Decrypt {
            self.mac.update(buf);
        }

        // In place, continuing the cipher's own streaming position, which
        // is what makes updating in pieces equal one call. The length
        // check above keeps the counter short of its wrap, so the
        // cipher's own refusal cannot fire here.
        self.cipher.apply(buf).map_err(|(_, e)| e)?;

        if self.direction == Direction::Encrypt {
            self.mac.update(buf);
        }
        Ok(())
    }

    /// Append the transform of `input` to `out`.
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        let start = out.len();
        out.extend_from_slice(input);
        let result = self.apply(&mut out[start..]);
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    fn compute_tag(&mut self) -> [u8; TAG_LEN] {
        let text_len = self.text_len as usize;
        self.pad_mac(text_len);

        // The lengths: two little-endian 64 bit byte counts. Not GCM's
        // big-endian bit counts, which is the single easiest thing to
        // carry across from the other AEAD by mistake.
        let mut trailer = [0u8; 16];
        trailer[..8].copy_from_slice(&self.aad_len.to_le_bytes());
        trailer[8..].copy_from_slice(&self.text_len.to_le_bytes());
        self.mac.update(&trailer);

        self.mac.tag()
    }

    /// Finish an encryption and produce the tag.
    pub fn tag(&mut self) -> Result<[u8; TAG_LEN], String> {
        if self.direction != Direction::Encrypt {
            return Err("tag() is for encryption; a decryption calls verify()."
                       .to_string());
        }
        if self.done {
            return Err("This stream is already finished.".to_string());
        }
        self.done = true;
        Ok(self.compute_tag())
    }

    /// Finish a decryption by checking the tag, in constant time.
    pub fn verify(&mut self, expected: &[u8]) -> Result<(), String> {
        if self.direction != Direction::Decrypt {
            return Err("verify() is for decryption; an encryption calls tag()."
                       .to_string());
        }
        if self.done {
            return Err("This stream is already finished.".to_string());
        }
        if expected.len() != TAG_LEN {
            return Err(format!(
                "ChaCha20-Poly1305 tags are {} bytes; got {}.",
                TAG_LEN, expected.len()));
        }
        self.done = true;
        let tag = self.compute_tag();

        // Through the one constant-time comparison the library has.
        if crate::bignum::ct::bytes_differ(&tag, expected) {
            return Err("ChaCha20-Poly1305 authentication failed: the tag does \
                        not match. The data has been altered, or the key, nonce \
                        or additional data is not the one that protected it."
                       .to_string());
        }
        Ok(())
    }
}

/// Seal in one call: ciphertext and tag.
pub fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8])
            -> Result<(Vec<u8>, [u8; TAG_LEN]), String> {
    let mut state = ChaCha20Poly1305::encryptor(key, nonce, aad)?;
    let mut out = Vec::with_capacity(plaintext.len());
    state.update(plaintext, &mut out)?;
    let tag = state.tag()?;
    Ok((out, tag))
}

/// Open in one call. Returns the plaintext, or an error and nothing else.
pub fn open(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8])
            -> Result<Vec<u8>, String> {
    let mut state = ChaCha20Poly1305::decryptor(key, nonce, aad)?;
    let mut out = Vec::with_capacity(ciphertext.len());
    state.update(ciphertext, &mut out)?;
    state.verify(tag)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// draft-irtf-cfrg-xchacha appendix A.3.1, read out of the draft.
    #[test]
    fn test_xchacha20_poly1305_appendix_a_3_1() {
        let draft = include_str!("../../rfcs/draft-irtf-cfrg-xchacha-03.txt");
        let start = draft.find("\nA.3.1.  AEAD_XCHACHA20_POLY1305").unwrap();
        let end = draft.find("\nA.3.2.  XChaCha20").unwrap();
        let section = &draft[start..end];
        let field = |label: &str| -> Vec<u8> {
            let at = section.find(label).unwrap_or_else(|| panic!("no {label}")) + label.len();
            let mut text = String::new();
            for line in section[at..].lines() {
                let line = line.trim();
                if line.is_empty() {
                    if text.is_empty() { continue } else { break }
                }
                if !line.chars().all(|c| c.is_ascii_hexdigit()) {
                    break;
                }
                text.push_str(line);
            }
            unhex(&text)
        };
        let (plaintext, aad, key, iv) = (field("Plaintext:"), field("AAD:"), field("Key:"),
                                         field("IV:"));
        let (ciphertext, tag) = (field("Ciphertext:"), field("Tag:"));
        assert_eq!((plaintext.len(), iv.len(), tag.len()), (114, 24, 16));

        let mut state = ChaCha20Poly1305::x_encryptor(&key, &iv, &aad).unwrap();
        let mut out = Vec::new();
        state.update(&plaintext, &mut out).unwrap();
        assert_eq!(out, ciphertext);
        assert_eq!(state.tag().unwrap().to_vec(), tag);

        let mut state = ChaCha20Poly1305::x_decryptor(&key, &iv, &aad).unwrap();
        let mut back = Vec::new();
        state.update(&ciphertext, &mut back).unwrap();
        state.verify(&tag).unwrap();
        assert_eq!(back, plaintext);

        // The 12 byte AEAD refuses a 24 byte nonce rather than reading part
        // of it, and the 24 byte one refuses 12.
        assert!(ChaCha20Poly1305::encryptor(&key, &iv, &aad).is_err());
        assert!(ChaCha20Poly1305::x_encryptor(&key, &iv[..12], &aad).is_err());
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 8439 section 2.8.2: the specification's worked example, with
    /// additional data that is not a multiple of 16 and a plaintext that
    /// is not either - so both paddings are exercised.
    #[test]
    fn test_the_rfc_vector() {
        let key = unhex("808182838485868788898a8b8c8d8e8f\
                         909192939495969798999a9b9c9d9e9f");
        let nonce = unhex("070000004041424344454647");
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could \
offer you only one tip for the future, sunscreen would be it.";

        let (ciphertext, tag) = seal(&key, &nonce, &aad, plaintext).unwrap();
        assert_eq!(hex(&ciphertext),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116");
        assert_eq!(hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");

        assert_eq!(open(&key, &nonce, &aad, &ciphertext, &tag).unwrap(),
                   plaintext);
    }

    /// RFC 8439 appendix A.5, the decryption direction's own vector.
    #[test]
    fn test_the_rfc_decryption_vector() {
        let key = unhex("1c9240a5eb55d38af333888604f6b5f0\
                         473917c1402b80099dca5cbc207075c0");
        let nonce = unhex("000000000102030405060708");
        let aad = unhex("f33388860000000000004e91");
        let ciphertext = unhex(
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2\
             4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf\
             332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855\
             9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4\
             b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e\
             af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a\
             0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10\
             49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29\
             a6ad5cb4022b02709b");
        let tag = unhex("eead9d67890cbb22392336fea1851f38");

        let plaintext = open(&key, &nonce, &aad, &ciphertext, &tag).unwrap();
        assert!(String::from_utf8_lossy(&plaintext)
                    .starts_with("Internet-Drafts are draft documents"));

        // And a single flipped bit anywhere must break it.
        let mut altered = tag.clone();
        altered[0] ^= 1;
        assert!(open(&key, &nonce, &aad, &ciphertext, &altered).is_err());
    }

    /// The Poly1305 key is block zero and the payload starts at block one.
    ///
    /// If the payload started at zero, the first 32 bytes of keystream
    /// would be the authentication key - so encrypting 32 zero bytes would
    /// hand it straight back. This checks they differ, which is the
    /// cheapest way to pin the counter offset.
    #[test]
    fn test_the_payload_does_not_reuse_the_mac_key_block() {
        let key = unhex(&"5a".repeat(32));
        let nonce = unhex("000102030405060708090a0b");

        let mut block_zero = Chacha::new(&key, &nonce, 20).unwrap();
        let mut zero_stream = Vec::new();
        block_zero.crypt(&[0u8; 64], &mut zero_stream);

        let (ciphertext, _) = seal(&key, &nonce, b"", &[0u8; 64]).unwrap();

        assert_ne!(&ciphertext[..], &zero_stream[..],
                   "the payload was encrypted with the Poly1305 key's own block");
        // Specifically, it should equal block one.
        let mut from_one = Chacha::new(&key, &nonce, 20).unwrap();
        from_one.set_counter(1).unwrap();
        let mut expected = Vec::new();
        from_one.crypt(&[0u8; 64], &mut expected);
        assert_eq!(ciphertext, expected);
    }

    /// Moving a byte between the additional data and the ciphertext must
    /// change the tag. That is what the padding between the sections is
    /// for, and without it these two would authenticate identically.
    #[test]
    fn test_the_sections_cannot_be_confused() {
        let key = unhex(&"31".repeat(32));
        let nonce = unhex("000000000000000000000001");

        let (_, first) = seal(&key, &nonce, b"aaaabbbb", b"cccc").unwrap();
        let (_, second) = seal(&key, &nonce, b"aaaabbbbc", b"ccc").unwrap();
        assert_ne!(first, second);

        // And the length trailer catches the case where both sections are
        // empty but in different amounts.
        let (_, a) = seal(&key, &nonce, b"", b"").unwrap();
        let (_, b) = seal(&key, &nonce, b"\0", b"").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_nothing_gets_past_the_tag() {
        let key = unhex(&"7c".repeat(32));
        let nonce = unhex("0b0a090807060504030201ff");
        let aad = b"authenticated".to_vec();
        let message = b"a message worth protecting".to_vec();

        let (sealed, tag) = seal(&key, &nonce, &aad, &message).unwrap();
        assert!(open(&key, &nonce, &aad, &sealed, &tag).is_ok());

        for index in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[index] ^= 0x01;
            assert!(open(&key, &nonce, &aad, &altered, &tag).is_err(),
                    "ciphertext byte {} was accepted", index);
        }
        for index in 0..tag.len() {
            let mut altered = tag;
            altered[index] ^= 0x01;
            assert!(open(&key, &nonce, &aad, &sealed, &altered).is_err(),
                    "tag byte {} was accepted", index);
        }
        for index in 0..aad.len() {
            let mut altered = aad.clone();
            altered[index] ^= 0x01;
            assert!(open(&key, &nonce, &altered, &sealed, &tag).is_err(),
                    "aad byte {} was accepted", index);
        }
        for index in 0..nonce.len() {
            let mut altered = nonce.clone();
            altered[index] ^= 0x01;
            assert!(open(&key, &altered, &aad, &sealed, &tag).is_err(),
                    "nonce byte {} was accepted", index);
        }
        assert!(open(&key, &nonce, &aad, &sealed[..sealed.len() - 1], &tag).is_err());
    }

    #[test]
    fn test_streaming_equals_one_call() {
        let key = unhex(&"44".repeat(32));
        let nonce = unhex("0102030405060708090a0b0c");
        let message: Vec<u8> = (0..400u32).map(|i| (i * 17 + 3) as u8).collect();

        let (expected, expected_tag) = seal(&key, &nonce, b"aad", &message).unwrap();

        for size in [1usize, 7, 16, 17, 63, 64, 65, 200] {
            let mut state = ChaCha20Poly1305::encryptor(&key, &nonce, b"aad").unwrap();
            let mut out = Vec::new();
            for piece in message.chunks(size) {
                state.update(piece, &mut out).unwrap();
            }
            assert_eq!(out, expected, "encrypting in {} byte pieces", size);
            assert_eq!(state.tag().unwrap(), expected_tag, "tag, {} pieces", size);

            let mut state = ChaCha20Poly1305::decryptor(&key, &nonce, b"aad").unwrap();
            let mut back = Vec::new();
            for piece in expected.chunks(size) {
                state.update(piece, &mut back).unwrap();
            }
            state.verify(&expected_tag).unwrap();
            assert_eq!(back, message, "decrypting in {} byte pieces", size);
        }
    }

    #[test]
    fn test_the_lengths_are_checked() {
        for key_len in [0usize, 16, 31, 33] {
            assert!(ChaCha20Poly1305::encryptor(&vec![0; key_len], &[0; 12], b"")
                        .is_err(), "key length {}", key_len);
        }
        // The 8 byte nonce is ChaCha's original construction and not this
        // AEAD's; accepting it would give a 64 bit counter and a different
        // function.
        for nonce_len in [0usize, 8, 11, 13, 16] {
            assert!(ChaCha20Poly1305::encryptor(&[0; 32], &vec![0; nonce_len], b"")
                        .is_err(), "nonce length {}", nonce_len);
        }
        let mut state = ChaCha20Poly1305::decryptor(&[0; 32], &[0; 12], b"").unwrap();
        assert!(state.verify(&[0; 15]).is_err());
    }

    /// The payload runs on keystream blocks 1 to 2^32 - 1, and nothing
    /// refused a message that needed more: the counter wrapped to block
    /// zero, the Poly1305 key's own block, and the bytes past 256 GiB
    /// went out under keystream already used, with a tag that still
    /// verified. The length tests only checked the key and nonce, and
    /// no test could afford a 256 GiB message, which is why the limit is
    /// pinned here by moving the count rather than the data: at the
    /// limit one more byte is refused, one byte short of it is taken,
    /// and the refusal leaves the output as it was. GCM has the same
    /// check at the same place.
    #[test]
    fn test_the_block_counter_limit_is_enforced() {
        assert_eq!(MAX_TEXT_LEN, (1 << 38) - 64);
        for direction in [Direction::Encrypt, Direction::Decrypt] {
            let mut state = ChaCha20Poly1305::new(&[0; 32], &[0; 12], b"", direction).unwrap();
            state.text_len = MAX_TEXT_LEN - 1;
            let mut out = Vec::new();
            assert!(state.update(&[0u8; 2], &mut out).is_err(), "{direction:?}");
            assert!(out.is_empty(), "a refused update left output behind");
            assert!(state.update(&[0u8; 1], &mut out).is_ok());
            assert_eq!(state.text_len, MAX_TEXT_LEN);
            assert!(state.update(&[0u8; 1], &mut out).is_err());
            assert_eq!(out.len(), 1);
        }
    }

    #[test]
    fn test_the_halves_are_not_interchangeable() {
        let mut encrypting =
            ChaCha20Poly1305::encryptor(&[0; 32], &[0; 12], b"").unwrap();
        assert!(encrypting.verify(&[0; 16]).is_err());
        assert!(encrypting.tag().is_ok());
        assert!(encrypting.tag().is_err(), "finishing twice should fail");

        let mut decrypting =
            ChaCha20Poly1305::decryptor(&[0; 32], &[0; 12], b"").unwrap();
        assert!(decrypting.tag().is_err());
    }

    /// The counter cannot be moved once the keystream has started, because
    /// that would skip or repeat keystream in the middle of a message.
    #[test]
    fn test_the_counter_is_fixed_before_the_stream_starts() {
        let mut cipher = Chacha::new(&[0; 32], &[0; 12], 20).unwrap();
        assert!(cipher.set_counter(1).is_ok());
        let mut out = Vec::new();
        cipher.crypt(b"some data", &mut out);
        assert!(cipher.set_counter(9).is_err());
    }
}
