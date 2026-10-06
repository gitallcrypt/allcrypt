//! Base64 (RFC 4648, the standard alphabet, padded), as KeePass and
//! Office write it in their XML.

#![allow(dead_code)]

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Whitespace is skipped, as KeePass's own reader skips it.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 4 * 3);
    for (index, chunk) in digits.chunks(4).enumerate() {
        let last = index == digits.len() / 4 - 1;
        let mut n = 0u32;
        let mut padding = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let value = match c {
                b'=' if last && i >= 2 => {
                    padding += 1;
                    0
                }
                _ if padding > 0 => return None,
                _ => ALPHABET.iter().position(|&a| a == c)? as u32,
            };
            n = (n << 6) | value;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - padding]);
    }
    Some(out)
}
