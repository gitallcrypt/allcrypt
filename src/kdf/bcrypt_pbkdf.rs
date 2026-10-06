/*
bcrypt_pbkdf: the key derivation OpenSSH uses to encrypt `openssh-key-v1`
private keys, from OpenBSD's `lib/libutil/bcrypt_pbkdf.c`.

It is PBKDF2's shape with bcrypt's core in place of HMAC: each block of
output is a running XOR of `rounds` applications of `bcrypt_hash`, a
bcrypt variant that takes SHA-512 of the password and of the salt and
encrypts the constant "OxychromaticBlowfishSwatDynamite" with a Blowfish
whose key schedule has been run 129 times over both.

There is no RFC. The C file is the definition, and OpenSSH's encrypted
key files are the vectors: `vectors/ssh_keys.vec` holds seventy of them,
each decrypting only if this matches to the byte.

# Pitfalls

**The output is interleaved, not concatenated.** PBKDF2 writes block 1,
then block 2. bcrypt_pbkdf writes byte `i` of block `n` to position
`i * stride + n`, where `stride` is the number of blocks - so every
block contributes to the whole key and a short derivation cannot be
extended into a longer one. An implementation that concatenates matches
OpenSSH for every key of 32 bytes or fewer and for nothing longer, and
the common `aes256-ctr` case wants 48.

**The 32 bytes of each `bcrypt_hash` are written little-endian**, word by
word, after a Blowfish that otherwise reads and writes big-endian. The
constant goes in big-endian.

**The hash is 64 rounds of encryption over 64 rounds of key schedule**,
with the salt's schedule first in each pair - and `rounds` is the
caller's PBKDF2-style iteration count on top of that, not bcrypt's
`cost`. A file's `rounds` is typically 16 (OpenSSH's default), and each
round of each 32 byte block is one `bcrypt_hash`: 129 key schedules of
521 encryptions apiece, about sixty-seven thousand.
*/

use crate::block_ciphers::blowfish::Blowfish;
use crate::hash_functions::{sha2::SHA512, HashFunction};

const MAGIC: &[u8; 32] = b"OxychromaticBlowfishSwatDynamite";

/// OpenBSD's `bcrypt_hash`: 32 bytes from two 64 byte inputs.
fn bcrypt_hash(sha2_password: &[u8], sha2_salt: &[u8]) -> [u8; 32] {
    let mut state = Blowfish::initial();
    state.expand_state(sha2_salt, sha2_password);
    for _ in 0..64 {
        state.expand0_state(sha2_salt);
        state.expand0_state(sha2_password);
    }
    let mut words = [0u32; 8];
    for (word, bytes) in words.iter_mut().zip(MAGIC.chunks(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for _ in 0..64 {
        for pair in words.chunks_mut(2) {
            (pair[0], pair[1]) = state.encrypt_words(pair[0], pair[1]);
        }
    }
    let mut out = [0u8; 32];
    for (bytes, word) in out.chunks_mut(4).zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Derive `length` bytes. `rounds` must be at least 1, and `length` at
/// most 1024 and the salt at most 2^20 bytes, as in OpenBSD.
pub fn bcrypt_pbkdf(password: &[u8], salt: &[u8], rounds: u32, length: usize)
                    -> Result<Vec<u8>, String> {
    if rounds == 0 {
        return Err("bcrypt_pbkdf needs at least one round.".to_string());
    }
    if length == 0 || length > 32 * 32 {
        return Err(format!("bcrypt_pbkdf derives 1 to 1024 bytes, not {length}."));
    }
    if salt.is_empty() || salt.len() > 1 << 20 {
        return Err(format!("bcrypt_pbkdf takes a salt of 1 to 2^20 bytes, \
                            not {}.", salt.len()));
    }
    let stride = length.div_ceil(32);
    let per_block = length.div_ceil(stride);
    let sha2_password = SHA512::new(password, 512).digest();
    let mut key = vec![0u8; length];

    for block in 0..stride {
        let mut counted = Vec::with_capacity(salt.len() + 4);
        counted.extend_from_slice(salt);
        counted.extend_from_slice(&(block as u32 + 1).to_be_bytes());
        let mut sha2_salt = SHA512::new(&counted, 512).digest();
        let mut hashed = bcrypt_hash(&sha2_password, &sha2_salt);
        let mut output = hashed;
        for _ in 1..rounds {
            sha2_salt = SHA512::new(&hashed, 512).digest();
            hashed = bcrypt_hash(&sha2_password, &sha2_salt);
            for (out, byte) in output.iter_mut().zip(hashed) {
                *out ^= byte;
            }
        }
        // Interleaved: byte i of this block lands at i * stride + block.
        for (i, byte) in output.iter().take(per_block).enumerate() {
            let at = i * stride + block;
            if at >= length {
                break;
            }
            key[at] = *byte;
        }
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameters_out_of_range_are_refused() {
        assert!(bcrypt_pbkdf(b"pw", b"salt", 0, 32).is_err());
        assert!(bcrypt_pbkdf(b"pw", b"salt", 1, 0).is_err());
        assert!(bcrypt_pbkdf(b"pw", b"salt", 1, 1025).is_err());
        assert!(bcrypt_pbkdf(b"pw", b"", 1, 32).is_err());
    }

    /// The interleave: a longer derivation is not an extension of a
    /// shorter one, and every byte of it moves when only the last block
    /// would under concatenation.
    #[test]
    fn test_the_output_is_interleaved_rather_than_concatenated() {
        let short = bcrypt_pbkdf(b"pw", b"salt", 1, 32).unwrap();
        let long = bcrypt_pbkdf(b"pw", b"salt", 1, 64).unwrap();
        assert_ne!(&long[..32], short.as_slice());
        // Block 1's bytes are the even positions of the 64 byte key.
        let evens: Vec<u8> = long.iter().step_by(2).copied().collect();
        assert_eq!(evens, short);
    }
}
