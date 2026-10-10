//! AES-CBC with HMAC-SHA-2, as an AEAD: RFC 7518 section 5.2 (JWE's
//! `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`), from
//! draft-mcgrew-aead-aes-cbc-hmac-sha2.
//!
//! Encrypt-then-MAC, spelled out exactly:
//!
//! - The key `K` is two keys of equal length, the MAC key first and the
//!   AES key second: 16 + 16, 24 + 24 or 32 + 32 bytes.
//! - The plaintext is PKCS#7-padded and encrypted with AES-CBC under a
//!   16-byte IV, which is this AEAD's nonce and must be unpredictable.
//! - The tag is HMAC over `A || IV || E || AL`, where `AL` is the length
//!   of the associated data `A` in **bits** as 64 bits big endian. It is
//!   cut to the length of the MAC key: 16, 24 or 32 bytes.
//!
//! Decryption checks the tag before it decrypts anything, so the padding
//! check never sees a ciphertext that was not authentic and cannot be
//! an oracle.

use crate::bignum::ct::bytes_differ;
use crate::block_ciphers::aes::AesCrypto;
use crate::block_ciphers::BlockCipher;
use crate::hash_functions::sha2::{SHA256, SHA384, SHA512};
use crate::mac::hmac::Hmac;

/// One of the three, by its AES key size in bits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variant {
    Aes128HmacSha256,
    Aes192HmacSha384,
    Aes256HmacSha512,
}

impl Variant {
    /// Bytes of `K`: the MAC key and the AES key together.
    pub fn key_len(self) -> usize {
        2 * self.half()
    }

    /// Bytes of tag, and of each half of the key.
    pub fn tag_len(self) -> usize {
        self.half()
    }

    fn half(self) -> usize {
        match self {
            Variant::Aes128HmacSha256 => 16,
            Variant::Aes192HmacSha384 => 24,
            Variant::Aes256HmacSha512 => 32,
        }
    }
}

pub struct CbcHmac {
    variant: Variant,
    mac_key: Vec<u8>,
    enc_key: Vec<u8>,
}

impl CbcHmac {
    pub fn new(variant: Variant, key: &[u8]) -> Result<CbcHmac, String> {
        if key.len() != variant.key_len() {
            return Err(format!("{variant:?} takes a {}-byte key (the MAC key, then the AES \
                                key), not {}.", variant.key_len(), key.len()));
        }
        let (mac_key, enc_key) = key.split_at(variant.half());
        Ok(CbcHmac { variant, mac_key: mac_key.to_vec(), enc_key: enc_key.to_vec() })
    }

    pub fn tag_len(&self) -> usize {
        self.variant.tag_len()
    }

    fn tag(&self, aad: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(aad.len() + iv.len() + ciphertext.len() + 8);
        input.extend_from_slice(aad);
        input.extend_from_slice(iv);
        input.extend_from_slice(ciphertext);
        input.extend_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        let mut tag = match self.variant {
            Variant::Aes128HmacSha256 => Hmac::mac(SHA256::new(&[]), &self.mac_key, &input),
            Variant::Aes192HmacSha384 => Hmac::mac(SHA384::new(&[]), &self.mac_key, &input),
            Variant::Aes256HmacSha512 => Hmac::mac(SHA512::new(&[], 512), &self.mac_key, &input),
        };
        tag.truncate(self.tag_len());
        tag
    }

    /// The ciphertext (whole blocks, padding included) and the tag.
    pub fn encrypt(&self, iv: &[u8], aad: &[u8], plaintext: &[u8])
                   -> Result<(Vec<u8>, Vec<u8>), String> {
        if iv.len() != 16 {
            return Err(format!("The IV is 16 bytes, not {}.", iv.len()));
        }
        let mut cipher = AesCrypto::new(&self.enc_key)?;
        let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
        cipher.cbc_encrypt(&crate::api::pad_pkcs7(plaintext, 16)?, &mut ciphertext,
                           iv)?;
        let tag = self.tag(aad, iv, &ciphertext);
        Ok((ciphertext, tag))
    }

    /// Verify, then decrypt. One error for every failure, a wrong tag
    /// and bad padding alike.
    pub fn decrypt(&self, iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8])
                   -> Result<Vec<u8>, String> {
        const FAILURE: &str = "The message does not authenticate: wrong key, or it was \
                               changed.";
        if iv.len() != 16 || ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            return Err(FAILURE.to_string());
        }
        if bytes_differ(&self.tag(aad, iv, ciphertext), tag) {
            return Err(FAILURE.to_string());
        }
        let mut cipher = AesCrypto::new(&self.enc_key)?;
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        cipher.cbc_decrypt(ciphertext, &mut plaintext, iv)?;
        crate::api::unpad_pkcs7(&plaintext, 16).map_err(|_| FAILURE.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7518 appendix B's three test cases, read out of the vendored
    /// document: each `NAME =` line and the hex lines under it.
    #[test]
    fn test_rfc_7518_appendix_b() {
        let doc = include_str!("../../rfcs/rfc7518.txt");
        let start = doc.find("B.1.  Test Cases for AES_128_CBC_HMAC_SHA_256\n").unwrap();
        let text = &doc[start..doc[start..].find("Appendix C.").map_or(doc.len(), |i| start + i)];
        let is_hex = |t: &&str| t.len() == 2 && t.chars().all(|c| c.is_ascii_hexdigit());
        let mut cases: Vec<Vec<(String, Vec<u8>)>> = Vec::new();
        let mut open = false;
        for line in text.lines() {
            if line.starts_with("B.") {
                cases.push(Vec::new());
                open = false;
                continue;
            }
            // `NAME =` and hex starts a field; a line of hex alone
            // continues the open one; anything else closes it.
            let (label, rest) = match line.trim().split_once(" =") {
                Some((l, r)) if l.chars().all(|c| c.is_ascii_uppercase() || c == '_') => (Some(l), r),
                _ => (None, line),
            };
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            let hex = !tokens.is_empty() && tokens.iter().all(is_hex);
            match (label, hex) {
                (Some(label), true) => {
                    cases.last_mut().unwrap().push((label.to_string(), Vec::new()));
                    open = true;
                }
                (None, true) if open => {}
                _ => {
                    open = false;
                    continue;
                }
            }
            let field = &mut cases.last_mut().unwrap().last_mut().unwrap().1;
            field.extend(tokens.iter().map(|t| u8::from_str_radix(t, 16).unwrap()));
        }
        assert_eq!(cases.len(), 3);
        let variants = [Variant::Aes128HmacSha256, Variant::Aes192HmacSha384,
                        Variant::Aes256HmacSha512];
        for (case, variant) in cases.iter().zip(variants) {
            let get = |name: &str| case.iter().find(|(k, _)| k == name).unwrap().1.clone();
            let aead = CbcHmac::new(variant, &get("K")).unwrap();
            let (e, t) = aead.encrypt(&get("IV"), &get("A"), &get("P")).unwrap();
            assert_eq!(e, get("E"), "{variant:?}");
            assert_eq!(t, get("T"), "{variant:?}");
            assert_eq!(aead.decrypt(&get("IV"), &get("A"), &e, &t).unwrap(), get("P"));
            let mut bent = t.clone();
            bent[0] ^= 1;
            assert!(aead.decrypt(&get("IV"), &get("A"), &e, &bent).is_err());
            assert!(aead.decrypt(&get("IV"), &get("P"), &e, &t).is_err(), "other AAD");
        }
    }

    #[test]
    fn test_the_key_is_mac_key_then_aes_key() {
        let key: Vec<u8> = (0..32).collect();
        let aead = CbcHmac::new(Variant::Aes128HmacSha256, &key).unwrap();
        let (e, _) = aead.encrypt(&[0; 16], b"", b"x").unwrap();
        let mut want = Vec::new();
        AesCrypto::new(&key[16..]).unwrap()
            .cbc_encrypt(&crate::api::pad_pkcs7(b"x", 16).unwrap(), &mut want, &[0; 16])
            .unwrap();
        assert_eq!(e, want);
        assert!(CbcHmac::new(Variant::Aes256HmacSha512, &key).is_err());
    }

    /// A ciphertext that is not whole blocks, under a tag that is right
    /// for it - which only the key's holder can make - is refused with
    /// the same words as everything else, not CBC's own length error.
    #[test]
    fn test_a_ragged_ciphertext_with_a_good_tag_is_refused_alike() {
        let aead = CbcHmac::new(Variant::Aes128HmacSha256, &[3u8; 32]).unwrap();
        for ragged in [&[][..], &[1u8; 15][..], &[1u8; 17][..]] {
            let tag = aead.tag(b"", &[0; 16], ragged);
            let error = aead.decrypt(&[0; 16], b"", ragged, &tag).unwrap_err();
            assert!(error.contains("does not authenticate"), "{error}");
        }
    }
}
