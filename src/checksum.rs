//! CRC-32 (IEEE 802.3: reflected, polynomial 0xEDB88320).
//!
//! A checksum, not a cryptographic function: it is linear, and anybody
//! can make data with any CRC they like. It is here because ciphers in
//! this library use it as part of their state (ZipCrypto's first and
//! third keys are CRC registers) and because the formats around them
//! check it - ZIP, Kerberos's `des-cbc-crc`, TrueCrypt's headers and
//! keyfile pool.
//!
//! The two functions differ in what they do around the register.
//! `crc32` is the checksum every tool prints: the register starts at all
//! ones and is inverted at the end. `crc32_update` is the bare register,
//! with neither, which is what ZipCrypto, RFC 3961's modified CRC-32 and
//! TrueCrypt's keyfile pool use. `crc32(data) == !crc32_update(!0, data)`.

const fn table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = table();

/// The register after one byte.
#[inline]
pub fn crc32_byte(register: u32, byte: u8) -> u32 {
    TABLE[((register ^ u32::from(byte)) & 0xff) as usize] ^ (register >> 8)
}

/// The register after `data`, with no inversion before or after.
pub fn crc32_update(mut register: u32, data: &[u8]) -> u32 {
    for &byte in data {
        register = crc32_byte(register, byte);
    }
    register
}

/// The CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_catalogue_check_value() {
        // The CRC catalogue's check value: CRC-32 of "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn test_the_register_continues_across_calls() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 167 + 13) as u8).collect();
        for split in [0, 1, 7, 150, 299, 300] {
            let (a, b) = data.split_at(split);
            assert_eq!(!crc32_update(crc32_update(!0, a), b), crc32(&data));
        }
    }
}
