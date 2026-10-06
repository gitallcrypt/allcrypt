//! OpenPGP's algorithm identifiers (RFC 9580 section 9), and the
//! symmetric operations the message format is built from: its CFB, and
//! its AEAD modes.

use allcrypt::api::{AnyBlockCipher, AnyHash, CipherStream, Mode};
use allcrypt::block_ciphers::eax::Eax;
use allcrypt::block_ciphers::gcm::GcmState;
use allcrypt::block_ciphers::ocb::Ocb;
use allcrypt::hash_functions::HashFunction;

/// A symmetric cipher: its OpenPGP number, the library's name, and its
/// key and block sizes in bytes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Cipher {
    pub id: u8,
    pub name: &'static str,
    pub display: &'static str,
    pub key_len: usize,
    pub block_len: usize,
}

pub const CIPHERS: &[Cipher] = &[
    Cipher { id: 1, name: "idea", display: "IDEA", key_len: 16, block_len: 8 },
    Cipher { id: 2, name: "3des", display: "TripleDES", key_len: 24, block_len: 8 },
    Cipher { id: 3, name: "cast5", display: "CAST5", key_len: 16, block_len: 8 },
    Cipher { id: 4, name: "blowfish", display: "Blowfish", key_len: 16, block_len: 8 },
    Cipher { id: 7, name: "aes", display: "AES-128", key_len: 16, block_len: 16 },
    Cipher { id: 8, name: "aes", display: "AES-192", key_len: 24, block_len: 16 },
    Cipher { id: 9, name: "aes", display: "AES-256", key_len: 32, block_len: 16 },
    Cipher { id: 10, name: "twofish", display: "Twofish", key_len: 32, block_len: 16 },
    Cipher { id: 11, name: "camellia", display: "Camellia-128", key_len: 16, block_len: 16 },
    Cipher { id: 12, name: "camellia", display: "Camellia-192", key_len: 24, block_len: 16 },
    Cipher { id: 13, name: "camellia", display: "Camellia-256", key_len: 32, block_len: 16 },
];

pub fn cipher(id: u8) -> Result<Cipher, String> {
    CIPHERS.iter().find(|c| c.id == id).copied()
        .ok_or_else(|| format!("symmetric algorithm {id} is not one this program has"))
}

pub fn cipher_by_name(name: &str) -> Result<Cipher, String> {
    let wanted = name.to_ascii_lowercase().replace(['-', '_'], "");
    CIPHERS.iter().find(|c| c.display.to_ascii_lowercase().replace('-', "") == wanted
                            || (wanted == "aes" && c.id == 7)
                            || (wanted == "camellia" && c.id == 11)
                            || (wanted == "3des" && c.id == 2))
        .copied().ok_or_else(|| format!("unknown cipher {name}"))
}

/// A hash: OpenPGP number, library name, output length.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Hash {
    pub id: u8,
    pub name: &'static str,
    pub display: &'static str,
    pub len: usize,
}

pub const HASHES: &[Hash] = &[
    Hash { id: 1, name: "md5", display: "MD5", len: 16 },
    Hash { id: 2, name: "sha1", display: "SHA1", len: 20 },
    Hash { id: 3, name: "ripemd160", display: "RIPEMD160", len: 20 },
    Hash { id: 8, name: "sha256", display: "SHA256", len: 32 },
    Hash { id: 9, name: "sha384", display: "SHA384", len: 48 },
    Hash { id: 10, name: "sha512", display: "SHA512", len: 64 },
    Hash { id: 11, name: "sha224", display: "SHA224", len: 28 },
    Hash { id: 12, name: "sha3_256", display: "SHA3-256", len: 32 },
    Hash { id: 14, name: "sha3_512", display: "SHA3-512", len: 64 },
];

pub fn hash(id: u8) -> Result<Hash, String> {
    HASHES.iter().find(|h| h.id == id).copied()
        .ok_or_else(|| format!("hash algorithm {id} is not one this program has"))
}

pub fn hash_by_name(name: &str) -> Result<Hash, String> {
    let wanted = name.to_ascii_lowercase().replace(['-', '_'], "");
    HASHES.iter().find(|h| h.display.to_ascii_lowercase().replace('-', "") == wanted)
        .copied().ok_or_else(|| format!("unknown hash {name}"))
}

pub fn new_hash(h: Hash) -> AnyHash {
    AnyHash::new(h.name).expect("every hash in the table is in the library")
}

pub fn digest(h: Hash, parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = new_hash(h);
    for part in parts {
        hasher.update(part);
    }
    hasher.digest()
}

/// An AEAD mode: OpenPGP number, nonce length; the tag is 16 bytes for
/// all three.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Aead {
    pub id: u8,
    pub display: &'static str,
    pub nonce_len: usize,
}

pub const AEADS: &[Aead] = &[
    Aead { id: 1, display: "EAX", nonce_len: 16 },
    Aead { id: 2, display: "OCB", nonce_len: 15 },
    Aead { id: 3, display: "GCM", nonce_len: 12 },
];

pub const TAG_LEN: usize = 16;

pub fn aead(id: u8) -> Result<Aead, String> {
    AEADS.iter().find(|a| a.id == id).copied()
        .ok_or_else(|| format!("AEAD algorithm {id} is not one this program has"))
}

pub fn aead_by_name(name: &str) -> Result<Aead, String> {
    AEADS.iter().find(|a| a.display.eq_ignore_ascii_case(name)).copied()
        .ok_or_else(|| format!("unknown AEAD mode {name}"))
}

/// OpenPGP's CFB: full-block feedback from the IV given (all zeros for
/// the message format, a stored IV for secret keys).
pub fn cfb(c: Cipher, key: &[u8], iv: &[u8], data: &[u8], decrypting: bool)
           -> Result<Vec<u8>, String> {
    let cipher = AnyBlockCipher::new(c.name, key, None)?;
    let mut stream = CipherStream::new(cipher, Mode::Cfb, iv, decrypting)?;
    stream.update(data)
}

fn require_128(c: Cipher, a: Aead) -> Result<(), String> {
    if c.block_len != 16 {
        return Err(format!("{} needs a 128 bit block cipher; {} is not", a.display, c.display));
    }
    Ok(())
}

/// AEAD encryption: ciphertext followed by the 16 byte tag.
pub fn seal(c: Cipher, a: Aead, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8])
            -> Result<Vec<u8>, String> {
    require_128(c, a)?;
    let (mut out, tag) = match a.id {
        1 => Eax::new(c.name, key)?.encrypt(nonce, aad, plaintext)?,
        2 => Ocb::new(c.name, key)?.encrypt(nonce, aad, plaintext)?,
        _ => {
            let mut cipher = AnyBlockCipher::new(c.name, key, None)?;
            let mut state = GcmState::encryptor(&mut cipher, nonce, aad)?;
            let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
            state.update(&mut cipher, plaintext, &mut out)?;
            (out, state.tag(&mut cipher)?.to_vec())
        }
    };
    out.extend_from_slice(&tag);
    Ok(out)
}

/// AEAD decryption of ciphertext followed by its tag. Nothing is
/// returned unless the tag matches.
pub fn open(c: Cipher, a: Aead, key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8])
            -> Result<Vec<u8>, String> {
    require_128(c, a)?;
    if sealed.len() < TAG_LEN {
        return Err("an AEAD ciphertext shorter than its tag".to_string());
    }
    let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    match a.id {
        1 => Eax::new(c.name, key)?.decrypt(nonce, aad, ciphertext, tag),
        2 => Ocb::new(c.name, key)?.decrypt(nonce, aad, ciphertext, tag),
        _ => {
            let mut cipher = AnyBlockCipher::new(c.name, key, None)?;
            let mut state = GcmState::decryptor(&mut cipher, nonce, aad)?;
            let mut out = Vec::with_capacity(ciphertext.len());
            state.update(&mut cipher, ciphertext, &mut out)?;
            state.verify(&mut cipher, tag)?;
            Ok(out)
        }
    }
}

/// HKDF with SHA-256, which every version 6 derivation uses.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    allcrypt::kdf::hkdf(allcrypt::hash_functions::sha2::SHA256::new(&[]), salt, ikm, info,
                        length).expect("a length HKDF-SHA256 can produce")
}
