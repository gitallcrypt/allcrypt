/*
Counter with CBC-MAC (RFC 3610, NIST SP 800-38C).

CCM authenticates with a CBC-MAC and encrypts with CTR, both under the same
key. It predates GCM, needs no field arithmetic and no precomputed tables,
and is what constrained hardware uses - which is why it is in TLS
(RFC 6655) and in every 802.15.4 radio.

## It cannot stream, and this module does not pretend otherwise

The first block of the CBC-MAC encodes the *length of the plaintext*. So
the length has to be known before the first byte is processed, and a
genuine streaming interface - feed bytes, get bytes, finish - is
impossible. GCM has no such constraint.

Everything here is therefore one shot: whole message in, whole message
out. The alternative, buffering internally behind an `update`/`finish`
pair, would be an interface that promises constant memory and does not
deliver it. Where this library's AEAD facade needs that shape, the
buffering is visible at the facade rather than hidden here.

## The parameters are entangled, on purpose

`L` is the number of bytes used for the length counter, and the nonce is
`15 - L` bytes. So a longer nonce means a shorter maximum message: a 13
byte nonce (L = 2) caps the message at 65535 bytes, and a 7 byte nonce
(L = 8) allows more than any real message. TLS uses a 12 byte nonce, so
L = 3 and the cap is 16MB - comfortably above a TLS record.

`M`, the tag length, is 4 to 16 bytes and even. TLS uses 16, or 8 for the
`_8` suites, where the saving matters more than the forgery margin: an 8
byte tag means a blind forgery succeeds once in 2^64 attempts rather than
once in 2^128, which is a real trade rather than a free one.

## The failure that matters

Like every counter-based AEAD, **a repeated nonce under one key is
catastrophic**. Two messages give away their XOR, and for CCM the
authentication is also broken by it. Nothing here can check - only the
caller knows what it used before. `docs/pitfalls.md` section 1.

The tag is compared in constant time and decryption returns the plaintext
or an error, never both.
*/

use super::BlockCipher;

const BLOCK: usize = 16;

/// Encode the length of the additional data, per RFC 3610 section 2.2.
///
/// Three cases, and the middle one is the one that gets forgotten: a
/// length of 2^16 - 2^8 or more is escaped with `0xff 0xfe` and a four
/// byte length. An implementation that always uses the two byte form
/// works until somebody authenticates 65280 bytes of headers.
fn encode_aad_length(len: usize, out: &mut Vec<u8>) -> Result<(), String> {
    if len == 0 {
        return Ok(());
    }
    if len < 0xff00 {
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= u32::MAX as usize {
        out.extend_from_slice(&[0xff, 0xfe]);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&[0xff, 0xff]);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    Ok(())
}

/// Validate the three parameters and return `L`, the length field's width.
fn parameters(nonce_len: usize, tag_len: usize, message_len: usize)
              -> Result<usize, String> {
    if !(7..=13).contains(&nonce_len) {
        return Err(format!(
            "A CCM nonce is 7 to 13 bytes; this one is {}. The nonce and the \
             message length field share 15 bytes, which is why the range is \
             not open ended.", nonce_len));
    }
    if !(4..=16).contains(&tag_len) || !tag_len.is_multiple_of(2) {
        return Err(format!(
            "A CCM tag is 4, 6, 8, 10, 12, 14 or 16 bytes; {} is not one of \
             them.", tag_len));
    }
    let l = 15 - nonce_len;
    // The message length must fit in L bytes. For L >= 8 every usize does.
    if l < 8 {
        let limit = 1u64 << (8 * l as u64);
        if message_len as u64 >= limit {
            return Err(format!(
                "A {} byte nonce leaves {} bytes for the length, so the \
                 message cannot exceed {} bytes; this one is {}.",
                nonce_len, l, limit - 1, message_len));
        }
    }
    Ok(l)
}

/// The counter block `A_i`, per RFC 3610 section 2.3.
fn counter_block(nonce: &[u8], l: usize, index: u64) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    block[0] = (l - 1) as u8;
    block[1..1 + nonce.len()].copy_from_slice(nonce);
    let counter = index.to_be_bytes();
    // The counter occupies the last L bytes, big endian. Taking the low L
    // bytes of a u64 is the same thing and says so.
    block[BLOCK - l..].copy_from_slice(&counter[8 - l..]);
    block
}

/// The CBC-MAC over B0, the encoded additional data and the plaintext.
fn cbc_mac<C: BlockCipher + ?Sized>(cipher: &mut C, nonce: &[u8], aad: &[u8],
                                    plaintext: &[u8], tag_len: usize, l: usize)
                                    -> Result<[u8; BLOCK], String> {
    // B0: flags, nonce, then the message length in L bytes.
    let mut b0 = [0u8; BLOCK];
    b0[0] = (if aad.is_empty() { 0 } else { 0x40 })
        | (((tag_len as u8 - 2) / 2) << 3)
        | (l as u8 - 1);
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    let length = (plaintext.len() as u64).to_be_bytes();
    b0[BLOCK - l..].copy_from_slice(&length[8 - l..]);

    // The MAC input is B0 || encoded(aad) || plaintext, each of the last
    // two zero padded to a block boundary. Built as one buffer rather than
    // chained by hand: the padding rule is per *section*, not per input,
    // and doing it inline is where implementations drift.
    let mut input = Vec::with_capacity(BLOCK * 2 + aad.len() + plaintext.len() + 32);
    input.extend_from_slice(&b0);
    if !aad.is_empty() {
        let start = input.len();
        encode_aad_length(aad.len(), &mut input)?;
        input.extend_from_slice(aad);
        let written = input.len() - start;
        input.resize(input.len() + (BLOCK - written % BLOCK) % BLOCK, 0);
    }
    input.extend_from_slice(plaintext);
    if !plaintext.len().is_multiple_of(BLOCK) {
        input.resize(input.len() + BLOCK - plaintext.len() % BLOCK, 0);
    }

    if cipher.blocksize() != BLOCK {
        return Err(format!("CCM needs a 16 byte block cipher; this one's block is {} \
                            bytes.", cipher.blocksize()));
    }
    let mut chain = [0u8; BLOCK];
    let mut scratch = Vec::with_capacity(BLOCK);
    for chunk in input.chunks(BLOCK) {
        for (slot, byte) in chain.iter_mut().zip(chunk) {
            *slot ^= byte;
        }
        cipher.encrypt_block_in_place(&mut chain, &mut scratch)?;
    }
    Ok(chain)
}

/// CTR over the message, starting at counter 1. Counter 0 masks the tag.
/// The counter blocks are independent, so they go through
/// `encrypt_blocks` sixteen at a time.
fn apply_keystream<C: BlockCipher + ?Sized>(cipher: &mut C, nonce: &[u8],
                                            l: usize, buffer: &mut [u8])
                                            -> Result<(), String> {
    const BATCH: usize = 16;
    let mut keystream = Vec::with_capacity(BATCH * BLOCK);
    for (batch, chunk) in buffer.chunks_mut(BATCH * BLOCK).enumerate() {
        keystream.clear();
        let first = (batch * BATCH) as u64 + 1;
        for index in 0..chunk.len().div_ceil(BLOCK) as u64 {
            keystream.extend_from_slice(&counter_block(nonce, l, first + index));
        }
        cipher.encrypt_blocks(&mut keystream)?;
        for (byte, key) in chunk.iter_mut().zip(&keystream) {
            *byte ^= key;
        }
    }
    Ok(())
}

/// S0, the encryption of counter block 0, which masks the tag.
fn tag_mask<C: BlockCipher + ?Sized>(cipher: &mut C, nonce: &[u8], l: usize)
                                     -> Result<[u8; BLOCK], String> {
    let mut s0 = counter_block(nonce, l, 0);
    cipher.encrypt_blocks(&mut s0)?;
    Ok(s0)
}

/// Encrypt and authenticate. Returns `(ciphertext, tag)`.
///
/// One shot, for the reason in the module comment: the CBC-MAC needs the
/// plaintext's length before it starts.
pub fn encrypt<C: BlockCipher + ?Sized>(cipher: &mut C, nonce: &[u8], aad: &[u8],
                                        plaintext: &[u8], tag_len: usize)
                                        -> Result<(Vec<u8>, Vec<u8>), String> {
    if cipher.blocksize() != BLOCK {
        return Err(format!(
            "CCM is defined for 128 bit blocks only; this cipher has {}. A 64 \
             bit block AEAD is a different construction, not a smaller one.",
            cipher.blocksize() * 8));
    }
    let l = parameters(nonce.len(), tag_len, plaintext.len())?;

    let mac = cbc_mac(cipher, nonce, aad, plaintext, tag_len, l)?;

    // S0 masks the tag, and is the one counter block never used for data.
    let s0 = tag_mask(cipher, nonce, l)?;
    let tag: Vec<u8> = mac.iter().zip(&s0).take(tag_len)
        .map(|(a, b)| a ^ b).collect();

    let mut ciphertext = plaintext.to_vec();
    apply_keystream(cipher, nonce, l, &mut ciphertext)?;
    Ok((ciphertext, tag))
}

/// Verify and decrypt. Returns the plaintext, or an error and nothing.
///
/// The order is forced and is the whole point: the tag cannot be checked
/// until the plaintext exists, because the MAC is over the plaintext
/// rather than the ciphertext. So the plaintext is computed, the tag is
/// checked, and it is **dropped** if the check fails. A caller never sees
/// unverified bytes - which is exactly the discipline
/// MAC-then-encrypt in TLS got wrong, at the cost of a decade of padding
/// oracles.
pub fn decrypt<C: BlockCipher + ?Sized>(cipher: &mut C, nonce: &[u8], aad: &[u8],
                                        ciphertext: &[u8], tag: &[u8])
                                        -> Result<Vec<u8>, String> {
    if cipher.blocksize() != BLOCK {
        return Err(format!(
            "CCM is defined for 128 bit blocks only; this cipher has {}.",
            cipher.blocksize() * 8));
    }
    let l = parameters(nonce.len(), tag.len(), ciphertext.len())?;

    let mut plaintext = ciphertext.to_vec();
    apply_keystream(cipher, nonce, l, &mut plaintext)?;

    let mac = cbc_mac(cipher, nonce, aad, &plaintext, tag.len(), l)?;
    let s0 = tag_mask(cipher, nonce, l)?;

    // Constant time, through the one comparison the library has: one
    // that stops at the first wrong byte makes the number of correct
    // leading bytes measurable, and a tag can then be found one byte at
    // a time.
    let mut expected = [0u8; BLOCK];
    for (e, (m, s)) in expected.iter_mut().zip(mac.iter().zip(&s0)) {
        *e = m ^ s;
    }
    if crate::bignum::ct::bytes_differ(&expected[..tag.len()], tag) {
        // Nothing is returned. The plaintext here is real, and returning
        // it "just this once, for debugging" is how unverified plaintext
        // gets used.
        plaintext.iter_mut().for_each(|byte| *byte = 0);
        return Err("The CCM tag does not match, so this ciphertext was not \
                    produced by whoever holds the key - or was modified \
                    after it was.".to_string());
    }
    Ok(plaintext)
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

    /// RFC 3610 section 8, packet vectors 1, 2 and 3: the same key and a
    /// 13 byte nonce, with 8 bytes of additional data and an 8 byte tag.
    ///
    /// These are stated as "packets", with the tag appended to the
    /// ciphertext, which is how the vectors are written in the RFC.
    #[test]
    fn test_the_rfc_3610_packet_vectors() {
        let key = unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        for (nonce, input, aad_len, tag_len, want) in [
            ("00000003020100a0a1a2a3a4a5",
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
             8, 8,
             "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0"),
            ("00000004030201a0a1a2a3a4a5",
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             8, 8,
             "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916"),
            ("00000005040302a0a1a2a3a4a5",
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
             8, 8,
             "51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da8596574adaa76fbd9fb0c5"),
        ] {
            let input = unhex(input);
            let (aad, plaintext) = input.split_at(aad_len);
            let mut cipher = AesCrypto::new(key.clone()).unwrap();

            let (ciphertext, tag) =
                encrypt(&mut cipher, &unhex(nonce), aad, plaintext, tag_len).unwrap();
            let mut packet = ciphertext.clone();
            packet.extend_from_slice(&tag);
            assert_eq!(hex(&packet), want, "nonce {}", nonce);

            let back = decrypt(&mut cipher, &unhex(nonce), aad, &ciphertext, &tag).unwrap();
            assert_eq!(back, plaintext);
        }
    }

    /// NIST SP 800-38C's example 1: a 7 byte nonce, a 4 byte tag, and no
    /// padding anywhere - the other end of the parameter range from the
    /// RFC vectors, which is the point of having both.
    #[test]
    fn test_the_sp_800_38c_example() {
        let key = unhex("404142434445464748494a4b4c4d4e4f");
        let nonce = unhex("10111213141516");
        let aad = unhex("0001020304050607");
        let plaintext = unhex("20212223");

        let mut cipher = AesCrypto::new(key).unwrap();
        let (ciphertext, tag) = encrypt(&mut cipher, &nonce, &aad, &plaintext, 4).unwrap();
        assert_eq!(hex(&ciphertext), "7162015b");
        assert_eq!(hex(&tag), "4dac255d");
    }

    /// A modified tag, a modified ciphertext and modified additional data
    /// must each fail, and the failure must produce nothing.
    #[test]
    fn test_every_kind_of_tampering_is_caught() {
        let key = vec![0x42; 16];
        let nonce = vec![7u8; 12];
        let aad = b"header".to_vec();
        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();

        let mut cipher = AesCrypto::new(key).unwrap();
        let (ciphertext, tag) =
            encrypt(&mut cipher, &nonce, &aad, &plaintext, 16).unwrap();
        assert_eq!(decrypt(&mut cipher, &nonce, &aad, &ciphertext, &tag).unwrap(),
                   plaintext);

        for index in 0..tag.len() {
            let mut broken = tag.clone();
            broken[index] ^= 1;
            assert!(decrypt(&mut cipher, &nonce, &aad, &ciphertext, &broken).is_err());
        }
        for index in 0..ciphertext.len() {
            let mut broken = ciphertext.clone();
            broken[index] ^= 1;
            assert!(decrypt(&mut cipher, &nonce, &aad, &broken, &tag).is_err());
        }
        assert!(decrypt(&mut cipher, &nonce, b"headeR", &ciphertext, &tag).is_err());

        // And a nonce that is merely different, which is the case that
        // looks like a bug rather than an attack.
        let mut other_nonce = nonce.clone();
        other_nonce[0] ^= 1;
        assert!(decrypt(&mut cipher, &other_nonce, &aad, &ciphertext, &tag).is_err());
    }

    /// Every legal tag length, and the illegal ones refused rather than
    /// silently rounded.
    #[test]
    fn test_tag_lengths() {
        let mut cipher = AesCrypto::new(vec![1u8; 16]).unwrap();
        let nonce = vec![2u8; 12];
        for tag_len in [4usize, 6, 8, 10, 12, 14, 16] {
            let (ciphertext, tag) =
                encrypt(&mut cipher, &nonce, b"a", b"message", tag_len).unwrap();
            assert_eq!(tag.len(), tag_len);
            assert_eq!(decrypt(&mut cipher, &nonce, b"a", &ciphertext, &tag).unwrap(),
                       b"message");
        }
        for bad in [0usize, 1, 2, 3, 5, 15, 17, 32] {
            assert!(encrypt(&mut cipher, &nonce, b"a", b"message", bad).is_err(),
                    "tag length {} was accepted", bad);
        }
    }

    /// The nonce and the message length share fifteen bytes, so a long
    /// nonce means a short message limit. Refused rather than truncated:
    /// a length that does not fit in L bytes would be silently wrapped and
    /// the MAC would cover the wrong length.
    #[test]
    fn test_the_nonce_length_bounds_the_message() {
        let mut cipher = AesCrypto::new(vec![3u8; 16]).unwrap();
        for bad in [0usize, 6, 14, 16] {
            assert!(encrypt(&mut cipher, &vec![0; bad], b"", b"x", 16).is_err(),
                    "a {} byte nonce was accepted", bad);
        }

        // 13 bytes of nonce leaves 2 for the length, so 65535 is the cap.
        let nonce = vec![4u8; 13];
        assert!(encrypt(&mut cipher, &nonce, b"", &vec![0; 65535], 16).is_ok());
        assert!(encrypt(&mut cipher, &nonce, b"", &vec![0; 65536], 16).is_err());
    }

    /// The additional data length has three encodings and the middle one
    /// is the one that gets forgotten. 65279 bytes uses the short form and
    /// 65280 uses the escaped one, so a round trip across that boundary is
    /// what says both are implemented.
    #[test]
    fn test_the_additional_data_length_boundary() {
        let mut cipher = AesCrypto::new(vec![5u8; 16]).unwrap();
        let nonce = vec![6u8; 12];
        for aad_len in [0usize, 1, 15, 16, 0xfeff, 0xff00, 0xff01] {
            let aad = vec![0xa5; aad_len];
            let (ciphertext, tag) =
                encrypt(&mut cipher, &nonce, &aad, b"payload", 16).unwrap();
            assert_eq!(decrypt(&mut cipher, &nonce, &aad, &ciphertext, &tag).unwrap(),
                       b"payload");
        }
    }

    /// An empty message and empty additional data are both legal, and both
    /// are where an off-by-one in the padding shows up.
    #[test]
    fn test_empty_inputs() {
        let mut cipher = AesCrypto::new(vec![7u8; 16]).unwrap();
        let nonce = vec![8u8; 12];
        for (aad, plaintext) in [(&b""[..], &b""[..]), (b"a", b""), (b"", b"b")] {
            let (ciphertext, tag) =
                encrypt(&mut cipher, &nonce, aad, plaintext, 16).unwrap();
            assert_eq!(ciphertext.len(), plaintext.len());
            assert_eq!(decrypt(&mut cipher, &nonce, aad, &ciphertext, &tag).unwrap(),
                       plaintext);
        }
    }
}
