//! CMS's older key wraps, which predate AES key wrap (RFC 3394):
//!
//! - **RFC 3217's Triple-DES and RC2 key wraps**: a SHA-1 checksum
//!   appended, CBC under a random IV, the IV and result **reversed**,
//!   then CBC again under a fixed IV. The reversal makes every bit of
//!   the output depend on every bit of the key, which one CBC pass
//!   would not. OpenSSL still writes the Triple-DES one for an EC
//!   recipient of 3DES content.
//! - **RFC 3211's password recipient wrap** (PWRI): a length byte, three
//!   check bytes and the key, padded to two blocks or more, encrypted in
//!   CBC twice - the second pass chained on from the first pass's last
//!   block. Any block cipher; the key-encryption key comes from PBKDF2.
//!
//! Each unwrap fails the same way for every failure, so that the
//! error does not say which check failed.

use crate::block_ciphers::des::{set_odd_parity, TripleDes};
#[cfg(test)]
use crate::block_ciphers::des::has_odd_parity;
use crate::block_ciphers::rc2::RC2;
use crate::block_ciphers::BlockCipher;
use crate::hash_functions::sha1::SHA1;
use crate::hash_functions::HashFunction;

/// RFC 3217 3.1's fixed IV for the outer pass.
const OUTER_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

fn checksum(data: &[u8]) -> Vec<u8> {
    let mut h = SHA1::new(&[]);
    h.update(data);
    h.digest()[..8].to_vec()
}

/// RFC 3217's two passes, common to both of its wraps: `data` (which
/// ends in its checksum) under CBC with `iv`; `iv` and that result
/// reversed; CBC again under the fixed IV.
fn two_passes<C: BlockCipher + ?Sized>(cipher: &mut C, data: &[u8], iv: &[u8])
                                       -> Result<Vec<u8>, String> {
    let mut temp2 = iv.to_vec();
    cipher.cbc_encrypt(data, &mut temp2, iv.to_vec())?;
    temp2.reverse();
    let mut out = Vec::with_capacity(temp2.len());
    cipher.cbc_encrypt(&temp2, &mut out, OUTER_IV.to_vec())?;
    Ok(out)
}

/// The inverse of `two_passes`, giving `data` with its checksum.
fn undo_two_passes<C: BlockCipher + ?Sized>(cipher: &mut C, wrapped: &[u8])
                                            -> Result<Vec<u8>, String> {
    let mut temp3 = Vec::with_capacity(wrapped.len());
    cipher.cbc_decrypt(wrapped, &mut temp3, OUTER_IV.to_vec())?;
    temp3.reverse();
    let mut data = Vec::with_capacity(temp3.len() - 8);
    cipher.cbc_decrypt(&temp3[8..], &mut data, temp3[..8].to_vec())?;
    Ok(data)
}

const WRONG_KEK: &str = "Wrong key-encryption key, or the wrapped key is damaged.";

/// RFC 3217 3.1: wrap a Triple-DES key (24 bytes, parity set on the way
/// in) under a Triple-DES key-encryption key, with an 8-byte random
/// `iv`. The result is 40 bytes.
pub fn wrap_3des(kek: &[u8], cek: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if cek.len() != 24 || iv.len() != 8 {
        return Err("The Triple-DES key wrap takes a 24-byte key and an 8-byte IV.".to_string());
    }
    let mut cekicv = cek.to_vec();
    set_odd_parity(&mut cekicv);
    let icv = checksum(&cekicv);
    cekicv.extend_from_slice(&icv);
    two_passes(&mut TripleDes::new(kek.to_vec())?, &cekicv, iv)
}

/// RFC 3217 3.2. Refuses a key whose checksum or parity is wrong.
pub fn unwrap_3des(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    if wrapped.len() != 40 {
        return Err(WRONG_KEK.to_string());
    }
    let cekicv = undo_two_passes(&mut TripleDes::new(kek.to_vec())?, wrapped)?;
    let (cek, icv) = cekicv.split_at(24);
    let mut parity = cek.to_vec();
    set_odd_parity(&mut parity);
    let mismatched = crate::bignum::ct::bytes_differ(&checksum(cek), icv);
    if mismatched || parity != cek {
        return Err(WRONG_KEK.to_string());
    }
    Ok(cek.to_vec())
}

/// RFC 3217 4.1: wrap an RC2 key of any length under an RC2
/// key-encryption key whose effective key length is `effective_bits`
/// (128 for the 128-bit key RFC 3217 requires). `pad` supplies the
/// random bytes that bring the length byte and key to whole blocks - at
/// most seven are used - and `iv` is 8 random bytes.
pub fn wrap_rc2(kek: &[u8], effective_bits: usize, cek: &[u8], pad: &[u8], iv: &[u8])
                -> Result<Vec<u8>, String> {
    if cek.is_empty() || cek.len() > 255 || iv.len() != 8 {
        return Err("The RC2 key wrap takes a 1- to 255-byte key and an 8-byte IV.".to_string());
    }
    let mut lcekpad = vec![cek.len() as u8];
    lcekpad.extend_from_slice(cek);
    let need = lcekpad.len().next_multiple_of(8) - lcekpad.len();
    if pad.len() < need {
        return Err(format!("The RC2 key wrap needs {need} bytes of padding here."));
    }
    lcekpad.extend_from_slice(&pad[..need]);
    let icv = checksum(&lcekpad);
    lcekpad.extend_from_slice(&icv);
    two_passes(&mut RC2::with_effective_bits(kek, effective_bits)?, &lcekpad, iv)
}

/// RFC 3217 4.2.
pub fn unwrap_rc2(kek: &[u8], effective_bits: usize, wrapped: &[u8])
                  -> Result<Vec<u8>, String> {
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(WRONG_KEK.to_string());
    }
    let data = undo_two_passes(&mut RC2::with_effective_bits(kek, effective_bits)?, wrapped)?;
    let (lcekpad, icv) = data.split_at(data.len() - 8);
    if crate::bignum::ct::bytes_differ(&checksum(lcekpad), icv) {
        return Err(WRONG_KEK.to_string());
    }
    let length = usize::from(lcekpad[0]);
    // At most seven bytes of padding, and the key inside the block.
    if length == 0 || 1 + length > lcekpad.len() || lcekpad.len() - 1 - length > 7 {
        return Err(WRONG_KEK.to_string());
    }
    Ok(lcekpad[1..1 + length].to_vec())
}

const WRONG_PASSWORD: &str = "Wrong password, or the wrapped key is damaged.";

/// RFC 3211 2.3.1: the key formatted as its length, the complement of
/// its first three bytes and itself, padded to whole blocks and at least
/// two, then CBC-encrypted twice: once under `iv`, and again with the
/// first pass's last block as the IV. `padding` supplies the random
/// padding bytes, as many as are needed.
pub fn pwri_wrap<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8], cek: &[u8],
                                          padding: &[u8]) -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    if cek.len() < 3 || cek.len() > 255 {
        return Err("RFC 3211 wraps a key of 3 to 255 bytes.".to_string());
    }
    let mut formatted = vec![cek.len() as u8, !cek[0], !cek[1], !cek[2]];
    formatted.extend_from_slice(cek);
    let total = formatted.len().next_multiple_of(block).max(2 * block);
    let need = total - formatted.len();
    if padding.len() < need {
        return Err(format!("RFC 3211's wrap needs {need} bytes of padding here."));
    }
    formatted.extend_from_slice(&padding[..need]);
    let mut first = Vec::with_capacity(total);
    cipher.cbc_encrypt(&formatted, &mut first, iv.to_vec())?;
    let mut second = Vec::with_capacity(total);
    cipher.cbc_encrypt(&first, &mut second, first[total - block..].to_vec())?;
    Ok(second)
}

/// RFC 3211 2.3.2. The outer pass's IV is the inner pass's last block,
/// which is recovered first: the last block decrypted and folded with
/// the one before it.
pub fn pwri_unwrap<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8], wrapped: &[u8])
                                            -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    let n = wrapped.len();
    if n < 2 * block || !n.is_multiple_of(block) {
        return Err(WRONG_PASSWORD.to_string());
    }
    let mut last = Vec::with_capacity(block);
    cipher.block_decrypt(&wrapped[n - block..], &mut last);
    for (b, p) in last.iter_mut().zip(&wrapped[n - 2 * block..n - block]) {
        *b ^= p;
    }
    let mut inner = Vec::with_capacity(n);
    cipher.cbc_decrypt(wrapped, &mut inner, last)?;
    let mut formatted = Vec::with_capacity(n);
    cipher.cbc_decrypt(&inner, &mut formatted, iv.to_vec())?;
    let length = usize::from(formatted[0]);
    let check = (formatted[1] ^ formatted[4]) & (formatted[2] ^ formatted[5])
        & (formatted[3] ^ formatted[6]);
    if check != 0xff || length < 3 || 4 + length > n {
        return Err(WRONG_PASSWORD.to_string());
    }
    Ok(formatted[4..4 + length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::des::Des;

    /// The hex after `label` and on the lines under it, in RFC 3217's
    /// four-digit groups or RFC 3211's two-digit ones, until a line with
    /// another label.
    fn field(doc: &str, from: usize, label: &str) -> (Vec<u8>, usize) {
        let at = from + doc[from..].find(label).unwrap_or_else(|| panic!("no {label}"));
        let mut hex = String::new();
        let mut end = at;
        for (i, line) in doc[at..].lines().enumerate() {
            let text = if i == 0 { &line[label.len()..] } else { line };
            let tokens: Vec<&str> = text.split_whitespace().collect();
            if tokens.is_empty() || !tokens.iter().all(|t| t.chars().all(|c| c.is_ascii_hexdigit())) {
                break;
            }
            hex.extend(tokens);
            end += line.len() + 1;
        }
        let bytes = (0..hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        (bytes, end)
    }

    #[test]
    fn test_rfc_3217_triple_des_example() {
        let doc = include_str!("../../rfcs/rfc3217.txt");
        let start = doc.find("3.4  Triple-DES Key Wrap Example").unwrap() + 40;
        let (cek, _) = field(doc, start, "CEK:");
        let (kek, _) = field(doc, start, "KEK:");
        let (icv, _) = field(doc, start, "ICV:");
        let (iv, _) = field(doc, start, "IV:");
        let (result, _) = field(doc, start, "RESULT:");
        assert_eq!((cek.len(), kek.len(), icv.len(), iv.len(), result.len()), (24, 24, 8, 8, 40));
        assert_eq!(checksum(&cek), icv);
        assert_eq!(wrap_3des(&kek, &cek, &iv).unwrap(), result);
        assert_eq!(unwrap_3des(&kek, &result).unwrap(), cek);
        let mut bent = result.clone();
        bent[20] ^= 1;
        assert!(unwrap_3des(&kek, &bent).is_err());
    }

    /// RFC 3217 4.4. **Its key-encryption key is used at 40 effective
    /// bits**, though it is 128 bits long and section 4 says a 128-bit
    /// key must be used: of 8, 32, 40, 64, 128, 256 and 1024, only 40
    /// reproduces the example's result (its checksum, which involves no
    /// RC2, matches regardless). 40 bits is the default of Microsoft's
    /// CryptoAPI RC2. The document does not say so.
    #[test]
    fn test_rfc_3217_rc2_example() {
        let doc = include_str!("../../rfcs/rfc3217.txt");
        let start = doc.find("4.4  RC2 Key Wrap Example").unwrap() + 30;
        let (cek, _) = field(doc, start, "CEK:");
        let (kek, _) = field(doc, start, "KEK:");
        let (pad, _) = field(doc, start, "PAD:");
        let (iv, _) = field(doc, start, "IV:");
        let (result, _) = field(doc, start, "RESULT:");
        assert_eq!((cek.len(), kek.len(), pad.len(), iv.len(), result.len()), (16, 16, 7, 8, 40));
        assert_eq!(wrap_rc2(&kek, 40, &cek, &pad, &iv).unwrap(), result);
        assert_eq!(unwrap_rc2(&kek, 40, &result).unwrap(), cek);
        for other in [64, 128] {
            assert_ne!(wrap_rc2(&kek, other, &cek, &pad, &iv).unwrap(), result);
            assert!(unwrap_rc2(&kek, other, &result).is_err(), "{other} effective bits");
        }
    }

    /// RFC 3211 section 3's DES example: the key wrap, given its key,
    /// its IV and its padding.
    #[test]
    fn test_rfc_3211_des_example() {
        let doc = include_str!("../../rfcs/rfc3211.txt");
        let start = doc.find("The following values are obtained when wrapping").unwrap();
        let (key, _) = field(doc, start, "output key:");
        let (cek, _) = field(doc, start, "CEK:");
        let (padding, _) = field(doc, start, "padding:");
        let (iv, after) = field(doc, start, "IV:");
        let (_, after_first) = field(doc, after, "first encr.");
        let (second, _) = field(doc, after_first, "second encr.");
        assert_eq!((key.len(), cek.len(), padding.len(), iv.len(), second.len()),
                   (8, 8, 4, 8, 16));
        let mut des = Des::new(key).unwrap();
        assert_eq!(pwri_wrap(&mut des, &iv, &cek, &padding).unwrap(), second);
        assert_eq!(pwri_unwrap(&mut des, &iv, &second).unwrap(), cek);
        let mut bent = second.clone();
        bent[3] ^= 1;
        assert!(pwri_unwrap(&mut des, &iv, &bent).is_err());
    }

    /// The Triple-DES unwrap checks the key's parity as well as its
    /// checksum (RFC 3217 3.2 step 8): a key wrapped with one parity bit
    /// wrong, under a correct checksum, is refused.
    #[test]
    fn test_a_triple_des_wrap_with_bad_parity_is_refused() {
        let kek = [0x5au8; 24];
        let mut cek = [0x2cu8; 24];
        cek[5] ^= 1;
        let mut cekicv = cek.to_vec();
        cekicv.extend_from_slice(&checksum(&cek));
        let iv = [9u8; 8];
        let wrapped = two_passes(&mut TripleDes::new(kek.to_vec()).unwrap(), &cekicv, &iv)
            .unwrap();
        assert!(unwrap_3des(&kek, &wrapped).is_err());
        let mut fixed = cek;
        set_odd_parity(&mut fixed);
        assert_eq!(unwrap_3des(&kek, &wrap_3des(&kek, &fixed, &iv).unwrap()).unwrap(), fixed);
    }

    /// RC2's unwrap refuses more than seven bytes of padding and a length
    /// byte that runs past the block, under a correct checksum.
    #[test]
    fn test_an_rc2_wrap_with_a_bad_length_is_refused() {
        let kek = [0x33u8; 16];
        for (length, body) in [(0u8, 15usize), (0, 7), (16, 15), (2, 15)] {
            let mut lcekpad = vec![length];
            lcekpad.extend(std::iter::repeat_n(7u8, body));
            let icv = checksum(&lcekpad);
            lcekpad.extend_from_slice(&icv);
            let wrapped = two_passes(&mut RC2::with_effective_bits(&kek, 128).unwrap(),
                                     &lcekpad, &[1; 8]).unwrap();
            assert!(unwrap_rc2(&kek, 128, &wrapped).is_err(), "length {length}");
        }
        let fine = wrap_rc2(&kek, 128, &[5; 9], &[0; 7], &[1; 8]).unwrap();
        assert_eq!(unwrap_rc2(&kek, 128, &fine).unwrap(), [5; 9]);
    }

    #[test]
    fn test_des_parity() {
        let mut key = [0u8, 1, 2, 3, 0xfe, 0xff, 0x80, 0x7f];
        assert!(!has_odd_parity(&key));
        set_odd_parity(&mut key);
        assert!(has_odd_parity(&key));
        assert_eq!(key, [0x01, 0x01, 0x02, 0x02, 0xfe, 0xfe, 0x80, 0x7f]);
    }

    /// A key without DES parity is wrapped with it set, so the unwrap's
    /// parity check passes; and a correct-parity key under a wrong
    /// checksum is refused by the checksum alone.
    #[test]
    fn test_triple_des_parity_is_set_and_the_checksum_checked() {
        let kek = [0x5au8; 24];
        let cek: Vec<u8> = (0..24).collect();
        let mut fixed = cek.clone();
        set_odd_parity(&mut fixed);
        assert_ne!(fixed, cek);
        let wrapped = wrap_3des(&kek, &cek, &[3; 8]).unwrap();
        assert_eq!(unwrap_3des(&kek, &wrapped).unwrap(), fixed);
        let mut bad_icv = fixed.clone();
        bad_icv.extend_from_slice(&[0; 8]);
        let wrapped = two_passes(&mut TripleDes::new(kek.to_vec()).unwrap(), &bad_icv, &[3; 8])
            .unwrap();
        assert!(unwrap_3des(&kek, &wrapped).is_err());
        // Wrong lengths are refused, not split.
        for n in [0usize, 8, 16, 24, 32, 48] {
            assert!(unwrap_3des(&kek, &vec![0; n]).is_err());
        }
    }

    /// The length byte and key fill a whole number of blocks with no
    /// padding at all when they can; seven padding bytes at most.
    #[test]
    fn test_rc2_padding_is_the_fewest_bytes() {
        let kek = [0x33u8; 16];
        for len in 1..=24usize {
            let cek = vec![0xa5u8; len];
            let wrapped = wrap_rc2(&kek, 128, &cek, &[0xee; 7], &[1; 8]).unwrap();
            // IV, length byte, key, padding to 8, checksum.
            assert_eq!(wrapped.len(), 8 + (1 + len).next_multiple_of(8) + 8, "{len}");
            assert_eq!(unwrap_rc2(&kek, 128, &wrapped).unwrap(), cek);
        }
    }

    /// RFC 3211 pads to two blocks at least, so a short key under a
    /// 16-byte cipher is two blocks, not one.
    #[test]
    fn test_pwri_is_two_blocks_at_least() {
        use crate::block_ciphers::aes::AesCrypto;
        let mut aes = AesCrypto::new(vec![7; 16]).unwrap();
        let wrapped = pwri_wrap(&mut aes, &[0; 16], &[1, 2, 3, 4, 5, 6, 7, 8], &[0; 32]).unwrap();
        assert_eq!(wrapped.len(), 32);
        assert_eq!(pwri_unwrap(&mut aes, &[0; 16], &wrapped).unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(pwri_unwrap(&mut aes, &[0; 16], &wrapped[..16]).is_err());
    }
}
