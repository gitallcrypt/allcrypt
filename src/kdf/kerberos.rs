//! RFC 3961's key derivation building blocks, which the Kerberos
//! encryption types are made of:
//!
//! - **n-fold** (5.1): stretch or fold a byte string to `n` bytes, each
//!   copy of the input rotated right 13 bits further than the last, the
//!   copies added with end-around carry.
//! - **DR** (5.1): the derivation constant n-folded to a block and
//!   encrypted, again and again, the outputs concatenated. DK is DR
//!   followed by the encryption type's random-to-key.
//! - **random-to-key** for DES (6.2) and Triple DES (6.3.1): seven bytes
//!   become eight, the low bit of each moved into the eighth, with
//!   parity set and a weak key corrected.
//! - **DES string-to-key** (6.2, `mit_des_string_to_key`): the password
//!   and salt fan-folded into 56 bits, every other block's bits reversed,
//!   then a DES-CBC checksum of the same bytes under the result.
//!
//! RFC 3962's AES types and RFC 8009's and RFC 6803's derive with PBKDF2
//! and SP 800-108 (`kdf::nist`) instead.

use crate::block_ciphers::des::{set_odd_parity, Des};
use crate::block_ciphers::BlockCipher;

/// n-fold (RFC 3961 5.1) of `input` to `n` bytes.
pub fn nfold(input: &[u8], n: usize) -> Vec<u8> {
    let inlen = input.len();
    if inlen == 0 || n == 0 {
        return vec![0; n];
    }
    let gcd = |mut a: usize, mut b: usize| {
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    };
    let lcm = inlen * n / gcd(inlen, n);
    let bits = inlen * 8;
    let mut out = vec![0u8; n];
    let mut carry = 0u32;
    for i in (0..lcm).rev() {
        // The most significant bit of the input that lands in byte i.
        let msbit = (bits - 1 + (bits + 13) * (i / inlen) + ((inlen - i % inlen) << 3)) % bits;
        let hi = u32::from(input[(inlen - 1 - (msbit >> 3)) % inlen]);
        let lo = u32::from(input[(inlen - (msbit >> 3)) % inlen]);
        carry += (((hi << 8) | lo) >> ((msbit & 7) + 1)) & 0xff;
        carry += u32::from(out[i % n]);
        out[i % n] = carry as u8;
        carry >>= 8;
    }
    // The end-around carry: what left the top goes back in at the bottom.
    // The loop above already carries out of each chunk's top byte into
    // the next chunk's bottom one, so what is left here is at most 1,
    // and adding 1 to a value that has just overflowed cannot overflow
    // again: one pass is the whole of it.
    for byte in out.iter_mut().rev() {
        carry += u32::from(*byte);
        *byte = carry as u8;
        carry >>= 8;
    }
    debug_assert_eq!(carry, 0);
    out
}

/// DR (RFC 3961 5.1): `length` bytes from encrypting the constant,
/// n-folded to the cipher's block, and then each output in turn. A
/// constant that is already one block is unchanged by n-fold, which
/// with one copy rotates nothing.
pub fn derive_random<C: BlockCipher + ?Sized>(cipher: &mut C, constant: &[u8], length: usize)
                                              -> Result<Vec<u8>, String> {
    let bs = cipher.blocksize();
    let mut block = nfold(constant, bs);
    let mut out = Vec::with_capacity(length + bs);
    while out.len() < length {
        let mut next = Vec::with_capacity(bs);
        cipher.block_encrypt(&block, &mut next);
        if next.len() != bs {
            return Err("block_encrypt did not produce exactly one block.".to_string());
        }
        out.extend_from_slice(&next);
        block = next;
    }
    out.truncate(length);
    Ok(out)
}

/// RFC 3961 6.2's correction: a weak or semi-weak DES key has 0xF0
/// XORed into its last byte.
pub fn correct_weak_des_key(key: &mut [u8]) {
    if Des::is_weak(key) {
        key[7] ^= 0xf0;
    }
}

/// DES random-to-key (RFC 3961 6.3.1): seven bytes to an eight-byte key.
pub fn des_random_to_key(seven: &[u8]) -> Result<Vec<u8>, String> {
    if seven.len() != 7 {
        return Err(format!("DES random-to-key takes 7 bytes, not {}.", seven.len()));
    }
    let mut key = seven.to_vec();
    let last = seven.iter().enumerate().fold(0u8, |acc, (i, b)| acc | ((b & 1) << (i + 1)));
    key.push(last);
    set_odd_parity(&mut key);
    correct_weak_des_key(&mut key);
    Ok(key)
}

/// Triple-DES random-to-key: three of DES's, 21 bytes to 24.
pub fn des3_random_to_key(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() != 21 {
        return Err(format!("Triple-DES random-to-key takes 21 bytes, not {}.", bytes.len()));
    }
    let mut out = Vec::with_capacity(24);
    for seven in bytes.chunks(7) {
        out.extend(des_random_to_key(seven)?);
    }
    Ok(out)
}

/// RFC 3961 6.2's DES string-to-key (`mit_des_string_to_key`).
pub fn des_string_to_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut s = password.to_vec();
    s.extend_from_slice(salt);
    s.resize(s.len().next_multiple_of(8), 0);
    let mut temp = 0u64;
    for (i, block) in s.chunks(8).enumerate() {
        let mut bits = block.iter().fold(0u64, |acc, b| (acc << 7) | u64::from(b & 0x7f));
        if i % 2 == 1 {
            bits = bits.reverse_bits() >> 8;
        }
        temp ^= bits;
    }
    // Back to eight bytes of seven bits each, then parity and weak keys.
    let mut key: Vec<u8> = (0..8).map(|i| ((temp >> (49 - 7 * i)) as u8 & 0x7f) << 1).collect();
    set_odd_parity(&mut key);
    correct_weak_des_key(&mut key);
    des_checksum_key(key, &s)
}

/// The last step of DES string-to-key: the DES-CBC checksum of the
/// padded password and salt under the intermediate key, with the key as
/// the IV, then parity and the weak-key correction again.
fn des_checksum_key(key: Vec<u8>, padded: &[u8]) -> Result<Vec<u8>, String> {
    // The CBC checksum of nothing is its IV - the key itself - which is
    // what an empty password with an empty salt comes to, in MIT Kerberos
    // as here.
    if padded.is_empty() {
        return Ok(key);
    }
    let mut out = Vec::with_capacity(padded.len());
    Des::new(&key)?.cbc_encrypt(padded, &mut out, &key)?;
    let mut key = out[out.len() - 8..].to_vec();
    set_odd_parity(&mut key);
    correct_weak_des_key(&mut key);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::des::TripleDes;

    const RFC3961: &str = include_str!("../../rfcs/rfc3961.txt");

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn appendix(start: &str, end: &str) -> &'static str {
        let from = RFC3961.find(&format!("\n{start}  ")).unwrap();
        let to = from + RFC3961[from..].find(&format!("\n{end}  ")).unwrap();
        &RFC3961[from..to]
    }

    fn is_hex(token: &str) -> bool {
        !token.is_empty() && token.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// A.1's eleven n-folds: each `N-fold(hex) = result`, the hex input
    /// and the result possibly continued on the following lines.
    #[test]
    fn test_rfc_3961_nfold() {
        let text: String = appendix("A.1.", "A.2.").split_whitespace().collect::<Vec<_>>()
            .join(" ");
        let mut found = 0;
        let mut rest = text.as_str();
        while let Some(at) = rest.find("-fold(") {
            let bits: usize = rest[..at].rsplit(' ').next().unwrap().parse().unwrap();
            let close = at + rest[at..].find(')').unwrap();
            let inner = rest[at + 6..close].to_string();
            rest = &rest[close + 1..];
            let Some(after) = rest.trim_start().strip_prefix('=') else { continue };
            let output: String = after.split_whitespace().take_while(|t| is_hex(t)).collect();
            if output.is_empty() {
                continue;
            }
            // `64-fold("kerberos") = ...` gives its input as text only.
            let input = match inner.strip_prefix('"').and_then(|i| i.strip_suffix('"')) {
                Some(text) => text.as_bytes().to_vec(),
                None => unhex(&inner.split_whitespace().collect::<String>()),
            };
            assert_eq!(nfold(&input, bits / 8), unhex(&output), "{bits}-fold({inner})");
            found += 1;
        }
        assert_eq!(found, 11);
    }

    /// A.2's six DES string-to-keys, two of which trigger the weak-key
    /// correction on the intermediate key.
    #[test]
    fn test_rfc_3961_des_string_to_key() {
        let text = appendix("A.2.", "A.3.");
        let text = &text[..text.find("This trace").unwrap_or(text.len())];
        let lines: Vec<&str> = text.lines().collect();
        // A labelled value: the hex at the end of the line, or on the
        // next line when the quoted text fills this one.
        let value = |i: usize| -> Vec<u8> {
            let last = lines[i].split_whitespace().last().unwrap();
            if is_hex(last) && !lines[i].trim_end().ends_with('"') {
                unhex(last)
            } else {
                unhex(lines[i + 1].trim())
            }
        };
        let (mut salt, mut password, mut found) = (Vec::new(), Vec::new(), 0);
        for (i, line) in lines.iter().enumerate() {
            let line = line.trim_start();
            if line.starts_with("salt:") {
                salt = value(i);
            } else if line.starts_with("password:") {
                password = value(i);
            } else if line.starts_with("DES key:") {
                assert_eq!(des_string_to_key(&password, &salt).unwrap(), value(i),
                           "{}", String::from_utf8_lossy(&salt));
                found += 1;
            }
        }
        assert_eq!(found, 6);
    }

    /// A.3's nine Triple-DES DRs and DKs: DK is DR, then random-to-key.
    #[test]
    fn test_rfc_3961_des3_dr_and_dk() {
        let text = appendix("A.3.", "A.4.");
        let (mut key, mut usage, mut found) = (Vec::new(), Vec::new(), 0);
        for line in text.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // `usage: 6b65726265726f73 ("kerberos")` carries a note.
            match tokens.as_slice() {
                ["key:", hex, ..] => key = unhex(hex),
                ["usage:", hex, ..] => usage = unhex(hex),
                ["DR:", hex, ..] => {
                    let mut c = TripleDes::new(&key).unwrap();
                    assert_eq!(derive_random(&mut c, &usage, 21).unwrap(), unhex(hex));
                }
                ["DK:", hex, ..] => {
                    let mut c = TripleDes::new(&key).unwrap();
                    let dr = derive_random(&mut c, &usage, 21).unwrap();
                    assert_eq!(des3_random_to_key(&dr).unwrap(), unhex(hex));
                    found += 1;
                }
                _ => {}
            }
        }
        assert_eq!(found, 9);
    }

    /// n-fold by its definition: the least common multiple of the two
    /// lengths filled with copies of the input, each rotated 13 bits
    /// further right than the last, then cut into `n`-byte chunks and
    /// summed in ones' complement - all on whole bit strings rather
    /// than byte by byte as `nfold` does it.
    fn nfold_by_definition(input: &[u8], n: usize) -> Vec<u8> {
        let bits = input.len() * 8;
        let bit = |b: &[u8], i: usize| (b[i / 8] >> (7 - i % 8)) & 1;
        let lcm = (1..).map(|k| k * input.len()).find(|l| l % n == 0).unwrap();
        let mut copies = Vec::with_capacity(lcm * 8);
        for k in 0..lcm / input.len() {
            let r = (13 * k) % bits;
            copies.extend((0..bits).map(|i| bit(input, (i + bits - r) % bits)));
        }
        let mut sum = vec![0u32; n * 8];
        for chunk in copies.chunks(n * 8) {
            for (s, b) in sum.iter_mut().zip(chunk) {
                *s += u32::from(*b);
            }
        }
        // Propagate from the low bit up and round the top, until settled.
        loop {
            let mut changed = false;
            for i in (0..n * 8).rev() {
                if sum[i] > 1 {
                    let up = sum[i] / 2;
                    sum[i] %= 2;
                    sum[(i + n * 8 - 1) % (n * 8)] += up;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        sum.chunks(8).map(|b| b.iter().fold(0u8, |acc, &x| (acc << 1) | x as u8)).collect()
    }

    #[test]
    fn test_nfold_against_its_definition() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for inlen in 1..=24 {
            for n in [1, 2, 3, 5, 7, 8, 16, 21, 24] {
                for _ in 0..4 {
                    let input: Vec<u8> = (0..inlen).map(|_| next()).collect();
                    assert_eq!(nfold(&input, n), nfold_by_definition(&input, n),
                               "{inlen} to {n}");
                }
                let ones = vec![0xffu8; inlen];
                assert_eq!(nfold(&ones, n), nfold_by_definition(&ones, n));
            }
        }
        // The definition agrees with the RFC.
        assert_eq!(nfold_by_definition(b"012345", 8), unhex("be072631276b1955"));
    }

    /// One copy rotates nothing, so a constant already a block long is
    /// its own n-fold, and DR may n-fold every constant.
    #[test]
    fn test_nfold_to_its_own_length_is_the_identity() {
        for len in 1..=32 {
            let input: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37) ^ 0xa5).collect();
            assert_eq!(nfold(&input, len), input);
        }
    }

    /// The weak-key correction on the checksum's output, which no RFC
    /// vector reaches: a one-block input chosen so that the CBC output
    /// under a fixed intermediate key is the weak key 0101010101010101.
    #[test]
    fn test_the_checksum_output_is_corrected_when_weak() {
        let key = unhex("cbc22fae235298e3");
        let weak = unhex("0101010101010101");
        let mut cleared = Vec::new();
        Des::new(&key).unwrap().block_decrypt(&weak, &mut cleared);
        let block: Vec<u8> = cleared.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        assert_eq!(des_checksum_key(key, &block).unwrap(), unhex("01010101010101f1"));
    }

    #[test]
    fn test_random_to_key_lengths() {
        assert!(des_random_to_key(&[0; 6]).is_err());
        assert!(des3_random_to_key(&[0; 24]).is_err());
        // All zeros is the weak key 0101010101010101, corrected.
        assert_eq!(des_random_to_key(&[0; 7]).unwrap(), [1, 1, 1, 1, 1, 1, 1, 0xf1]);
    }
}
