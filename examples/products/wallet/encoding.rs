//! The text encodings wallets use: Base58Check (Bitcoin's addresses,
//! keys and extended keys) and Bech32 and Bech32m (BIP-173 and BIP-350,
//! segregated witness addresses).

use crate::hash::sha256d;

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58: the bytes as one big-endian number in base 58, each leading
/// zero byte written as a `1`.
pub fn base58_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // Little-endian base-58 digits of the rest.
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in &data[zeros..] {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    out.extend(digits.iter().rev().map(|&d| BASE58[d as usize] as char));
    out
}

pub fn base58_decode(text: &str) -> Result<Vec<u8>, String> {
    let ones = text.bytes().take_while(|&b| b == b'1').count();
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes().skip(ones) {
        let value = BASE58.iter().position(|&b| b == c)
            .ok_or_else(|| format!("'{}' is not a Base58 character.", c as char))?;
        let mut carry = value as u32;
        for b in bytes.iter_mut() {
            carry += u32::from(*b) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; ones];
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// Base58 with four bytes of double SHA-256 appended.
pub fn base58check_encode(payload: &[u8]) -> String {
    let mut data = payload.to_vec();
    data.extend_from_slice(&sha256d(payload)[..4]);
    base58_encode(&data)
}

pub fn base58check_decode(text: &str) -> Result<Vec<u8>, String> {
    let data = base58_decode(text)?;
    if data.len() < 4 {
        return Err("Too short for Base58Check.".to_string());
    }
    let (payload, check) = data.split_at(data.len() - 4);
    if sha256d(payload)[..4] != *check {
        return Err("The Base58Check checksum does not match: a mistyped character, or not \
                    this kind of string.".to_string());
    }
    Ok(payload.to_vec())
}

// ------------------------------------------------------------------ Bech32 --

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Variant {
    /// BIP-173, for witness version 0.
    Bech32,
    /// BIP-350, for witness versions 1 to 16.
    Bech32m,
}

impl Variant {
    fn constant(self) -> u32 {
        match self {
            Variant::Bech32 => 1,
            Variant::Bech32m => 0x2bc8_30a3,
        }
    }
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|b| b & 31));
    out
}

/// Regroup bits: 8 to 5 (`pad` true) or 5 to 8 (`pad` false, where
/// leftover bits must be fewer than a group and zero).
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    let max = (1u32 << to) - 1;
    for &value in data {
        if u32::from(value) >> from != 0 {
            return Err("A value out of range.".to_string());
        }
        acc = (acc << from) | u32::from(value);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || (acc << (to - bits)) & max != 0 {
        return Err("Leftover bits in the data part.".to_string());
    }
    Ok(out)
}

/// A segwit address: the human-readable part, the witness version and
/// program, Bech32 for version 0 and Bech32m after (BIP-350).
pub fn segwit_encode(hrp: &str, version: u8, program: &[u8]) -> Result<String, String> {
    let variant = if version == 0 { Variant::Bech32 } else { Variant::Bech32m };
    let mut data = vec![version];
    data.extend(convert_bits(program, 8, 5, true)?);
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0; 6]);
    let check = polymod(&values) ^ variant.constant();
    let mut out = format!("{hrp}1");
    out.extend(data.iter().map(|&d| BECH32[d as usize] as char));
    out.extend((0..6).map(|i| BECH32[((check >> (5 * (5 - i))) & 31) as usize] as char));
    Ok(out)
}

/// Decode a segwit address, checking everything BIP-173 and BIP-350
/// require: one case throughout, the checksum of the right variant for the
/// version, and a program of a length the version allows.
pub fn segwit_decode(expected_hrp: &str, address: &str) -> Result<(u8, Vec<u8>), String> {
    if address.len() > 90 {
        return Err("A Bech32 string is at most 90 characters.".to_string());
    }
    if address.chars().any(|c| !(33..=126).contains(&(c as u32))) {
        return Err("A Bech32 string is printable US-ASCII.".to_string());
    }
    let lower = address.to_ascii_lowercase();
    if lower != address && address.to_ascii_uppercase() != address {
        return Err("A Bech32 string is all one case.".to_string());
    }
    let at = lower.rfind('1').ok_or("No separator in the address.")?;
    let (hrp, rest) = (&lower[..at], &lower[at + 1..]);
    if hrp != expected_hrp {
        return Err(format!("The address is for '{hrp}', not '{expected_hrp}'."));
    }
    if rest.len() < 6 {
        return Err("The checksum is missing.".to_string());
    }
    let values: Vec<u8> = rest.bytes().map(|c| BECH32.iter().position(|&b| b == c)
        .map(|p| p as u8).ok_or_else(|| format!("'{}' is not a Bech32 character.", c as char)))
        .collect::<Result<_, _>>()?;
    let mut all = hrp_expand(hrp);
    all.extend_from_slice(&values);
    let check = polymod(&all);
    let data = &values[..values.len() - 6];
    let version = *data.first().ok_or("No witness version.")?;
    if version > 16 {
        return Err("A witness version above 16.".to_string());
    }
    let variant = if version == 0 { Variant::Bech32 } else { Variant::Bech32m };
    if check != variant.constant() {
        return Err(format!("The checksum does not match (a version {version} address uses \
                            {variant:?})."));
    }
    let program = convert_bits(&data[1..], 5, 8, false)?;
    if !(2..=40).contains(&program.len()) || version == 0 && ![20, 32].contains(&program.len()) {
        return Err(format!("A version {version} witness program of {} bytes.", program.len()));
    }
    Ok((version, program))
}
