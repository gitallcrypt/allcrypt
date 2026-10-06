//! CBC-MAC: the last block of the data's CBC encryption (ISO/IEC 9797-1
//! MAC algorithm 1; ANSI X9.9 and FIPS 113 with DES).
//!
//! Secure only for messages of one fixed length. Given the MAC of a
//! one-block message `M`, the two-block message `M || (M XOR tag)` has
//! the same MAC, so a CBC-MAC over messages of varying length is
//! forgeable by anyone who has seen two. CMAC (`mac::cmac`) is the fix;
//! this is here because DES-MAC, Kerberos's DES checksums and banking
//! MACs are CBC-MACs and were computed this way.
//!
//! `cbc_mac` takes whole blocks, at least one. `cbc_mac_zero_padded`
//! first pads with zero bytes to a whole number of blocks, an empty
//! message to one block of zeros: ISO/IEC 9797-1 padding method 1. That
//! padding is ambiguous - a message and the same message with trailing
//! zeros have one MAC - which is why method 2 exists; method 1 is what
//! the old protocols used.

use crate::block_ciphers::{BlockCipher, CbcState};

/// The last block of the CBC encryption of `data` under `iv` (zeros in
/// most uses). `data` is a whole, non-zero number of blocks.
pub fn cbc_mac<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8], data: &[u8])
                                        -> Result<Vec<u8>, String> {
    let bs = cipher.blocksize();
    if data.is_empty() || !data.len().is_multiple_of(bs) {
        return Err(format!("CBC-MAC takes a whole number of {bs}-byte blocks, at least one; \
                            this is {} bytes.", data.len()));
    }
    let mut state = CbcState::new(cipher, iv, false)?;
    let mut out = Vec::with_capacity(bs);
    // Only the last block is kept, one block at a time, so a long
    // message costs one block of memory.
    for block in data.chunks(bs) {
        out.clear();
        state.update(cipher, block, &mut out)?;
    }
    Ok(out)
}

/// `cbc_mac` after ISO/IEC 9797-1 padding method 1: zero bytes to a
/// whole number of blocks, and an empty message to one zero block.
pub fn cbc_mac_zero_padded<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8], data: &[u8])
                                                    -> Result<Vec<u8>, String> {
    let bs = cipher.blocksize();
    let mut padded = data.to_vec();
    padded.resize(data.len().next_multiple_of(bs).max(bs), 0);
    cbc_mac(cipher, iv, &padded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::des::Des;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The tag is the last block of the CBC encryption.
    #[test]
    fn test_the_tag_is_the_last_cbc_block() {
        let key = unhex("0123456789abcdef");
        let data: Vec<u8> = (0..40u8).collect();
        let mut ct = Vec::new();
        Des::new(key.clone()).unwrap().cbc_encrypt(&data, &mut ct, vec![0; 8]).unwrap();
        let tag = cbc_mac(&mut Des::new(key).unwrap(), &[0; 8], &data).unwrap();
        assert_eq!(tag, ct[32..]);
    }

    #[test]
    fn test_whole_blocks_only_and_zero_padding() {
        let mut des = Des::new(unhex("0123456789abcdef")).unwrap();
        assert!(cbc_mac(&mut des, &[0; 8], &[]).is_err());
        assert!(cbc_mac(&mut des, &[0; 8], &[1; 9]).is_err());
        assert_eq!(cbc_mac_zero_padded(&mut des, &[0; 8], &[]).unwrap(),
                   cbc_mac(&mut des, &[0; 8], &[0; 8]).unwrap());
        assert_eq!(cbc_mac_zero_padded(&mut des, &[0; 8], &[1; 9]).unwrap(),
                   cbc_mac(&mut des, &[0; 8], &[[1u8; 9].as_slice(), &[0; 7]].concat()).unwrap());
    }

    /// The forgery that makes CBC-MAC unsafe over varying lengths, stated
    /// as a test: `M || (M XOR tag)` has the tag of `M`.
    #[test]
    fn test_the_length_extension_forgery() {
        let mut des = Des::new(unhex("133457799bbcdff1")).unwrap();
        let m = b"8 bytes!";
        let tag = cbc_mac(&mut des, &[0; 8], m).unwrap();
        let mut forged = m.to_vec();
        forged.extend(m.iter().zip(&tag).map(|(a, b)| a ^ b));
        assert_eq!(cbc_mac(&mut des, &[0; 8], &forged).unwrap(), tag);
    }
}
