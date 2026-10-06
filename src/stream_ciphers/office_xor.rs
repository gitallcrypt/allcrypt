//! XOR obfuscation, the password protection of the binary Office formats
//! before RC4 ([MS-OFFCRYPTO] 2.3.7, "Method 1"): what Excel 95 wrote
//! and what an `.xls` still carries when it is protected with "XOR".
//!
//! There is no cipher here worth the name. The password - 1 to 15
//! single-byte characters - gives a 16-bit verifier, a 16-bit key and a
//! 16-byte array, and the data is XORed with the array, repeating every
//! 16 bytes, with each byte's bits then rotated right by five. The
//! array is a function of the password alone, so one known 16-byte
//! stretch of plaintext gives it for the whole file.
//!
//! - `password_verifier` is `CreatePasswordVerifier_Method1`. The same
//!   16-bit hash is what Excel stores for a protected worksheet or
//!   workbook structure and Word for a "password to modify".
//! - `OfficeXor::new` is `CreateXorKey_Method1` and
//!   `CreateXorArray_Method1`.
//! - `decrypt` is `DecryptData_Method1` as Excel uses it: XOR, then
//!   rotate right by five. `encrypt` is its inverse.
//!
//! Which byte of the array a byte of data meets is the format's choice:
//! the methods take the array index of the first byte. Excel's records
//! use the stream position just past the record's end, not the byte's
//! own position.
//!
//! The tables - the padding, the initial codes and the 15 rows of the
//! key matrix - are msoffcrypto-tool's. Each matrix row is a seed
//! followed by six steps of a CRC-16 shift (polynomial 0x1021), so only
//! the seeds are written here and the rows are computed from them.

const PAD: [u8; 15] = [
    0xbb, 0xff, 0xff, 0xba, 0xff, 0xff, 0xb9, 0x80, 0x00, 0xbe, 0x0f, 0x00, 0xbf, 0x0f, 0x00,
];
const INITIAL_CODE: [u16; 15] = [
    0xe1f0, 0x1d0f, 0xcc9c, 0x84c0, 0x110c, 0x0e10, 0xf1ce, 0x313e,
    0x1872, 0xe139, 0xd40f, 0x84f9, 0x280c, 0xa96a, 0x4ec3,
];
const MATRIX_SEEDS: [u16; 15] = [
    0xaefc, 0x7b61, 0x4563, 0x0375, 0xd849, 0x6f45, 0xeb23, 0x47d3,
    0xb861, 0x45a0, 0xaa51, 0x76b4, 0x3730, 0x3331, 0x1021,
];

const fn matrix() -> [u16; 105] {
    let mut out = [0u16; 105];
    let mut row = 0;
    while row < 15 {
        let mut value = MATRIX_SEEDS[row];
        let mut step = 0;
        while step < 7 {
            out[row * 7 + step] = value;
            value = (value << 1) ^ if value & 0x8000 != 0 { 0x1021 } else { 0 };
            step += 1;
        }
        row += 1;
    }
    out
}

const XOR_MATRIX: [u16; 105] = matrix();

fn check_password(password: &[u8]) -> Result<(), String> {
    if password.is_empty() || password.len() > 15 {
        return Err(format!("An XOR obfuscation password is 1 to 15 bytes, not {}.",
                           password.len()));
    }
    Ok(())
}

/// The 16-bit password verifier (`CreatePasswordVerifier_Method1`).
pub fn password_verifier(password: &[u8]) -> Result<u16, String> {
    check_password(password)?;
    let mut verifier = 0u16;
    for &b in password.iter().rev().chain(std::iter::once(&(password.len() as u8))) {
        let high = u16::from(verifier & 0x4000 != 0);
        verifier = (((verifier << 1) & 0x7fff) | high) ^ u16::from(b);
    }
    Ok(verifier ^ 0xce4b)
}

/// The 16-bit XOR key (`CreateXorKey_Method1`): the initial code for the
/// password's length, and a matrix entry for each of the low seven bits
/// of each byte that is set, last byte first.
pub fn xor_key(password: &[u8]) -> Result<u16, String> {
    check_password(password)?;
    let mut key = INITIAL_CODE[password.len() - 1];
    let mut element = 0x68usize;
    for &b in password.iter().rev() {
        let mut c = b;
        for _ in 0..7 {
            if c & 0x40 != 0 {
                key ^= XOR_MATRIX[element];
            }
            c <<= 1;
            element = element.wrapping_sub(1);
        }
    }
    Ok(key)
}

#[derive(Clone, Debug)]
pub struct OfficeXor {
    array: [u8; 16],
    key: u16,
    verifier: u16,
}

impl OfficeXor {
    pub fn new(password: &[u8]) -> Result<OfficeXor, String> {
        let key = xor_key(password)?;
        let (high, low) = ((key >> 8) as u8, key as u8);
        let x = |a: u8, b: u8| (a ^ b).rotate_right(1);
        let mut array = [0u8; 16];
        // The password from its end, two bytes at a time, high byte of
        // the key on the odd positions; an odd length takes one byte of
        // padding first.
        let mut index = password.len();
        if index % 2 == 1 {
            array[index] = x(PAD[0], high);
            index -= 1;
            array[index] = x(password[password.len() - 1], low);
        }
        while index > 0 {
            index -= 1;
            array[index] = x(password[index], high);
            index -= 1;
            array[index] = x(password[index], low);
        }
        // The rest from the padding, two bytes at a time from the end.
        let mut index = 15usize;
        let mut pad = 15 - password.len() as isize;
        while pad > 0 {
            array[index] = x(PAD[pad as usize], high);
            index -= 1;
            pad -= 1;
            array[index] = x(PAD[pad as usize], low);
            index = index.wrapping_sub(1);
            pad -= 1;
        }
        Ok(OfficeXor { array, key, verifier: password_verifier(password)? })
    }

    pub fn array(&self) -> [u8; 16] {
        self.array
    }

    pub fn key(&self) -> u16 {
        self.key
    }

    pub fn verifier(&self) -> u16 {
        self.verifier
    }

    /// `DecryptData_Method1`, in place. `index` is the array index the
    /// first byte meets; it advances by one per byte, modulo 16.
    pub fn decrypt(&self, data: &mut [u8], index: usize) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (*byte ^ self.array[(index + i) % 16]).rotate_right(5);
        }
    }

    /// The inverse of `decrypt`: rotate left by five, then XOR.
    pub fn encrypt(&self, data: &mut [u8], index: usize) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = byte.rotate_left(5) ^ self.array[(index + i) % 16];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// msoffcrypto-tool's documented example: "VelvetSweatshop", the
    /// password Excel uses when none was given, verifies as 0x9a0a.
    #[test]
    fn test_the_verifier_of_excel_s_default_password() {
        assert_eq!(password_verifier(b"VelvetSweatshop").unwrap(), 0x9a0a);
    }

    /// The rows computed from their seeds are the rows msoffcrypto-tool
    /// prints: its first, last and two middle entries.
    #[test]
    fn test_the_matrix_rows_follow_from_their_seeds() {
        assert_eq!(XOR_MATRIX[0], 0xaefc);
        assert_eq!(XOR_MATRIX[6], 0x2a09);
        assert_eq!(XOR_MATRIX[52], 0x1eda);
        assert_eq!(XOR_MATRIX[104], 0x48c4);
    }

    #[test]
    fn test_a_password_is_one_to_fifteen_bytes() {
        assert!(OfficeXor::new(b"").is_err());
        assert!(OfficeXor::new(&[b'a'; 16]).is_err());
        for n in 1..=15 {
            assert!(OfficeXor::new(&vec![b'a'; n]).is_ok());
        }
    }

    #[test]
    fn test_round_trip_from_any_index() {
        let plain: Vec<u8> = (0..100u8).collect();
        for password in [&b"a"[..], b"ab", b"password", b"fifteen_bytes!!"] {
            let xor = OfficeXor::new(password).unwrap();
            for index in [0usize, 5, 15, 16, 1000] {
                let mut data = plain.clone();
                xor.encrypt(&mut data, index);
                assert_ne!(data, plain);
                xor.decrypt(&mut data, index);
                assert_eq!(data, plain);
            }
        }
    }

    /// The array repeats every 16 bytes and depends only on the
    /// password, so the same plaintext at index i and i + 16 encrypts
    /// alike - the whole weakness, stated as a test.
    #[test]
    fn test_the_array_repeats_every_sixteen_bytes() {
        let xor = OfficeXor::new(b"secret").unwrap();
        let mut a = *b"0123456789abcdef";
        let mut b = a;
        xor.encrypt(&mut a, 3);
        xor.encrypt(&mut b, 19);
        assert_eq!(a, b);
    }
}
