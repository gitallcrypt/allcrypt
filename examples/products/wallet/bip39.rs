//! BIP-39 mnemonics: entropy to words with a SHA-256 checksum, and words
//! to a 64-byte seed through PBKDF2-HMAC-SHA512.
//!
//! BIP-39 normalizes the mnemonic and the passphrase to Unicode NFKD
//! before hashing, so that the same text typed two ways is one wallet:
//! hashing an unnormalized passphrase would give a different wallet with
//! nothing to say so. Only the English word list is here, which NFKD
//! leaves alone; a seed is made from any mnemonic text.

use allcrypt::api;

use crate::hash::sha256;

const ENGLISH: &str = include_str!("../../../rfcs/bip-0039/english.txt");

pub fn wordlist() -> Vec<&'static str> {
    ENGLISH.lines().collect()
}

/// Entropy of 16 to 32 bytes, a multiple of 4, to 12 to 24 words.
pub fn to_mnemonic(entropy: &[u8]) -> Result<String, String> {
    if !(16..=32).contains(&entropy.len()) || !entropy.len().is_multiple_of(4) {
        return Err(format!("BIP-39 entropy is 16, 20, 24, 28 or 32 bytes, not {}.",
                           entropy.len()));
    }
    let words = wordlist();
    let check_bits = entropy.len() / 4;
    let mut bits: Vec<bool> = entropy.iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1)).collect();
    let check = sha256(entropy);
    bits.extend((0..check_bits).map(|i| (check[i / 8] >> (7 - i % 8)) & 1 == 1));
    Ok(bits.chunks(11)
        .map(|c| words[c.iter().fold(0usize, |acc, &b| (acc << 1) | usize::from(b))])
        .collect::<Vec<_>>().join(" "))
}

/// The words back to their entropy, refusing an unknown word, a count
/// that is not 12 to 24 in steps of 3, or a checksum that does not match.
pub fn to_entropy(mnemonic: &str) -> Result<Vec<u8>, String> {
    let words = wordlist();
    let given: Vec<&str> = mnemonic.split_whitespace().collect();
    if !(12..=24).contains(&given.len()) || !given.len().is_multiple_of(3) {
        return Err(format!("A BIP-39 mnemonic is 12, 15, 18, 21 or 24 words, not {}.",
                           given.len()));
    }
    let mut bits = Vec::with_capacity(given.len() * 11);
    for word in &given {
        let index = words.binary_search(&word.to_ascii_lowercase().as_str())
            .map_err(|_| format!("'{word}' is not in the BIP-39 English word list."))?;
        bits.extend((0..11).rev().map(|i| (index >> i) & 1 == 1));
    }
    let check_bits = given.len() / 3;
    let entropy_bits = bits.len() - check_bits;
    let entropy: Vec<u8> = bits[..entropy_bits].chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | u8::from(b))).collect();
    let check = sha256(&entropy);
    let expected = (0..check_bits).map(|i| (check[i / 8] >> (7 - i % 8)) & 1 == 1);
    if !expected.eq(bits[entropy_bits..].iter().copied()) {
        return Err("The mnemonic's checksum does not match: a word is wrong or out of \
                    order.".to_string());
    }
    Ok(entropy)
}

/// The seed: PBKDF2-HMAC-SHA512 over the words joined by single spaces,
/// salted with "mnemonic" and the passphrase, 2048 rounds. The checksum
/// is not required here, as BIP-39 does not require it of a seed; `check`
/// asks for it.
pub fn to_seed(mnemonic: &str, passphrase: &str, check: bool) -> Result<Vec<u8>, String> {
    if check {
        to_entropy(mnemonic)?;
    }
    // The Japanese list's mnemonics are written with an ideographic space
    // (U+3000), which NFKD makes U+0020; rejoining the words with single
    // spaces gives the bytes the reference hashes.
    let mnemonic = crate::unicode::nfkd(mnemonic);
    let words: Vec<String> = mnemonic.split_whitespace().map(str::to_ascii_lowercase).collect();
    let mut salt = b"mnemonic".to_vec();
    salt.extend_from_slice(crate::unicode::nfkd(passphrase).as_bytes());
    api::pbkdf2("sha512", words.join(" ").as_bytes(), &salt, 2048, 64)
}
