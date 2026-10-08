//! The two password hashes Windows stores: the NT hash and the LM hash
//! (MS-NLMP 3.3.1, NTOWFv1 and LMOWFv1). They are what a SAM database, an
//! `ntds.dit` and NTLM work with, and both are keys rather than
//! verifiers: whoever has one can authenticate as the user without the
//! password ("pass the hash").
//!
//! - **NT hash**: MD4 of the password as UTF-16 little endian. No salt,
//!   no iterations.
//! - **LM hash**: the password in the OEM code page, uppercased, cut to
//!   fourteen bytes and padded with zeros; each half of seven bytes is
//!   spread over eight as a DES key, which encrypts the constant
//!   `KGS!@#$%`. The two halves are hashed separately, so a fourteen
//!   byte password is two seven byte ones, and uppercase makes the
//!   alphabet smaller still. Windows has not stored it by default since
//!   Vista, and stores none for a password over fourteen bytes.
//!
//! **The uppercasing is the code page's.** `lm_hash` takes the password
//! as bytes already in the OEM code page the hash was made under (437 or
//! 850 on most Western systems) and uppercases only `a` to `z`: which
//! byte uppercases to which above 0x7f depends on that code page, so a
//! caller with non-ASCII letters uppercases them in its encoding first.

use crate::block_ciphers::des::Des;
use crate::block_ciphers::BlockCipher;
use crate::hash_functions::md4::Md4;
use crate::hash_functions::{HashFunction, md5};
use crate::mac::Hmac;

/// The NT hash (NTOWFv1): MD4 of the password as UTF-16 little endian.
pub fn nt_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut md4 = Md4::new(&utf16);
    md4.digest().try_into().expect("MD4 is 16 bytes")
}

/// The LM hash (LMOWFv1) of a password given in its OEM code page.
///
/// ASCII letters are uppercased here; bytes above 0x7f are used as they
/// are (see the module notes). A password over fourteen bytes has no LM
/// hash - Windows stores the hash of the empty password in its place -
/// and is refused rather than truncated.
pub fn lm_hash(password: &[u8]) -> Result<[u8; 16], String> {
    if password.len() > 14 {
        return Err(format!(
            "An LM hash covers at most 14 bytes of password, and this one is {}. \
             Windows stores no LM hash for a longer password: it keeps the hash \
             of the empty password in its place.", password.len()));
    }
    let mut padded = [0u8; 14];
    for (out, byte) in padded.iter_mut().zip(password) {
        *out = byte.to_ascii_uppercase();
    }
    let mut hash = [0u8; 16];
    for (half, out) in padded.chunks_exact(7).zip(hash.chunks_exact_mut(8)) {
        let mut des = Des::new(seven_to_eight(half.try_into().expect("7 bytes")).to_vec())?;
        let mut block = Vec::with_capacity(8);
        des.block_encrypt(b"KGS!@#$%", &mut block);
        out.copy_from_slice(&block);
    }
    Ok(hash)
}

//NTLMv2. Needs more testing.
pub fn ntlmv2_hash(password: &str, username: &str, domain: &str) -> Vec<u8> {
    let digest = nt_hash(password);
    let user: Vec<u8> = (username.to_uppercase() + domain).encode_utf16().flat_map(u16::to_le_bytes).collect();
    Hmac::mac(md5::MD5::new(&[]), &digest, &user)
}

/// Fifty-six key bits, seven to a byte with the low bit of each byte -
/// DES's parity bit, which it ignores - left zero. The bits run straight
/// through: key byte `i` holds bits `7i` to `7i + 6` of the seven bytes.
/// RFC 3961's DES random-to-key (`kdf::kerberos::des_random_to_key`)
/// arranges them differently.
fn seven_to_eight(seven: &[u8; 7]) -> [u8; 8] {
    let bits = seven.iter().fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    core::array::from_fn(|i| (((bits >> (49 - 7 * i)) & 0x7f) << 1) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The key spreading by its definition: bit `j` of the 56 (most
    /// significant first) lands in key byte `j / 7`, bit `7 - j % 7`.
    #[test]
    fn test_seven_to_eight_moves_each_bit_where_it_belongs() {
        for j in 0..56 {
            let mut seven = [0u8; 7];
            seven[j / 8] = 0x80 >> (j % 8);
            let mut want = [0u8; 8];
            want[j / 7] = 0x80 >> (j % 7);
            assert_eq!(seven_to_eight(&seven), want, "bit {j}");
        }
    }

    #[test]
    fn test_lm_uppercases_ascii_only_and_pads_with_zeros() {
        assert_eq!(lm_hash(b"password").unwrap(), lm_hash(b"PASSWORD").unwrap());
        assert_eq!(lm_hash(b"pass").unwrap(), lm_hash(b"PASS\0\0").unwrap());
        // 0xe9 is e-acute in code page 850; its uppercase is the caller's.
        assert_ne!(lm_hash(&[0xe9]).unwrap(), lm_hash(&[0x90]).unwrap());
    }

    /// The halves are independent: the second half of the hash is the
    /// first half of the hash of the password's last seven bytes.
    #[test]
    fn test_lm_hashes_the_two_halves_apart() {
        let whole = lm_hash(b"ABCDEFGHIJKLMN").unwrap();
        assert_eq!(whole[..8], lm_hash(b"ABCDEFG").unwrap()[..8]);
        assert_eq!(whole[8..], lm_hash(b"HIJKLMN").unwrap()[..8]);
    }

    #[test]
    fn test_lm_refuses_rather_than_truncates() {
        assert!(lm_hash(&[b'a'; 14]).is_ok());
        let error = lm_hash(&[b'a'; 15]).unwrap_err();
        assert!(error.contains("at most 14 bytes"), "{error}");
    }

    /// The empty password's LM hash is what Windows stores when it keeps
    /// none; it is two encryptions under the all-zero key.
    #[test]
    fn test_the_empty_password() {
        let mut des = Des::new(vec![0u8; 8]).unwrap();
        let mut block = Vec::new();
        des.block_encrypt(b"KGS!@#$%", &mut block);
        let empty = lm_hash(b"").unwrap();
        assert_eq!(empty[..8], block[..]);
        assert_eq!(empty[8..], block[..]);
        assert_eq!(hex(&nt_hash("")), hex(&Md4::new(b"").digest()));
    }

    #[test]
    fn test_nt_is_md4_of_utf16le() {
        let mut md4 = Md4::new(&[b'P', 0, 0xe9, 0, 0xac, 0x20, 0x3d, 0xd8, 0x00, 0xde]);
        assert_eq!(nt_hash("P\u{e9}\u{20ac}\u{1f600}").to_vec(), md4.digest());
    }

    #[test]
    fn test_ntlmv2_hash() {
        let has_hex = "0C868A403BFD7A93A3001EF22EF02E3F";
        let res = ntlmv2_hash("Password", "user", "Domain");
        assert_eq!(has_hex, crate::to_hex(&res));
    }
}
