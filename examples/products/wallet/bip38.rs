//! BIP-38 passphrase-protected private keys: a key encrypted under
//! scrypt and AES-256 (`6PR`/`6PY`), and the EC-multiply mode, in which
//! the passphrase's owner hands out an intermediate code and somebody
//! else makes new encrypted keys from it that only the owner can open
//! (`6Pf`/`6Pn`), with the confirmation code that proves the address.
//!
//! The passphrase is NFC-normalized by BIP-38 (`passphrase`), and the
//! functions here take it so normalized.

use allcrypt::api::{self, AnyBlockCipher};
use allcrypt::bignum::BigUint;
use allcrypt::block_ciphers::BlockCipher;

use crate::bitcoin::{p2pkh, public_bytes, Network};
use crate::encoding::{base58check_decode, base58check_encode};
use crate::hash::sha256d;
use crate::keys::{curve, private_bytes, private_from_bytes, public_key, ser_p};

const MAINNET: Network = Network { testnet: false };
const INTERMEDIATE_LOT: [u8; 8] = [0x2c, 0xe9, 0xb3, 0xe1, 0xff, 0x39, 0xe2, 0x51];
const INTERMEDIATE_NO_LOT: [u8; 8] = [0x2c, 0xe9, 0xb3, 0xe1, 0xff, 0x39, 0xe2, 0x53];
const CONFIRMATION: [u8; 5] = [0x64, 0x3b, 0xf6, 0xa8, 0x9a];
const COMPRESSED: u8 = 0x20;
const LOT_SEQUENCE: u8 = 0x04;

fn address_hash(address: &str) -> [u8; 4] {
    sha256d(address.as_bytes())[..4].try_into().expect("four bytes")
}

fn aes(key: &[u8]) -> AnyBlockCipher {
    AnyBlockCipher::new("aes", key, None).expect("a 32-byte key")
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn encrypt_block(cipher: &mut AnyBlockCipher, block: &[u8], mask: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    cipher.block_encrypt(&xor(block, mask), &mut out);
    out
}

fn decrypt_block(cipher: &mut AnyBlockCipher, block: &[u8], mask: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    cipher.block_decrypt(block, &mut out);
    xor(&out, mask)
}

fn address_for(k: &BigUint, compressed: bool) -> String {
    p2pkh(&public_bytes(&public_key(k), compressed), MAINNET)
}

/// What a decryption gives back.
pub struct Decrypted {
    pub key: BigUint,
    pub compressed: bool,
    pub address: String,
    /// The lot and sequence numbers, for an EC-multiplied key that has
    /// them.
    pub lot_sequence: Option<(u32, u32)>,
}

impl std::fmt::Debug for Decrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decrypted").field("key", &crate::hidden::Hidden)
            .field("compressed", &self.compressed).field("address", &self.address)
            .field("lot_sequence", &self.lot_sequence).finish()
    }
}

/// A passphrase as BIP-38 hashes it: NFC, in UTF-8.
pub fn passphrase(text: &str) -> Vec<u8> {
    crate::unicode::nfc(text).into_bytes()
}

// --------------------------------------------------------- without EC multiply --

pub fn encrypt(k: &BigUint, compressed: bool, passphrase: &[u8]) -> Result<String, String> {
    let hash = address_hash(&address_for(k, compressed));
    let derived = api::scrypt(passphrase, &hash, 16384, 8, 8, 64)?;
    let (half1, half2) = derived.split_at(32);
    let mut c = aes(half2);
    let key = private_bytes(k);
    let mut out = vec![0x01, 0x42, 0xc0 | if compressed { COMPRESSED } else { 0 }];
    out.extend_from_slice(&hash);
    out.extend(encrypt_block(&mut c, &key[..16], &half1[..16]));
    out.extend(encrypt_block(&mut c, &key[16..], &half1[16..]));
    Ok(base58check_encode(&out))
}

pub fn decrypt(text: &str, passphrase: &[u8]) -> Result<Decrypted, String> {
    let data = base58check_decode(text)?;
    if data.len() != 39 {
        return Err(format!("A BIP-38 key is 39 bytes, not {}.", data.len()));
    }
    let flag = data[2];
    let compressed = flag & COMPRESSED != 0;
    match (data[0], data[1]) {
        (0x01, 0x42) => {
            if flag & !COMPRESSED != 0xc0 {
                return Err(format!("Flag byte {flag:02x} is not one BIP-38 allows here."));
            }
            let hash = &data[3..7];
            let derived = api::scrypt(passphrase, hash, 16384, 8, 8, 64)?;
            let (half1, half2) = derived.split_at(32);
            let mut c = aes(half2);
            let mut key = decrypt_block(&mut c, &data[7..23], &half1[..16]);
            key.extend(decrypt_block(&mut c, &data[23..39], &half1[16..]));
            finish(private_from_bytes(&key), compressed, hash, None)
        }
        (0x01, 0x43) => decrypt_ec(&data, passphrase),
        _ => Err("Not a BIP-38 key (prefix neither 0142 nor 0143).".to_string()),
    }
}

/// The address check that is BIP-38's only way to know the passphrase was
/// right.
fn finish(key: Result<BigUint, String>, compressed: bool, hash: &[u8],
          lot_sequence: Option<(u32, u32)>) -> Result<Decrypted, String> {
    let wrong = || "Wrong passphrase: the key it gives is not the address's.".to_string();
    let key = key.map_err(|_| wrong())?;
    let address = address_for(&key, compressed);
    if address_hash(&address) != hash {
        return Err(wrong());
    }
    Ok(Decrypted { key, compressed, address, lot_sequence })
}

// ---------------------------------------------------------- with EC multiply --

/// The owner's side: prefactor, then passfactor (hashed with the lot and
/// sequence when there are some), and its point.
fn passfactor(passphrase: &[u8], owner_entropy: &[u8], with_lot: bool)
              -> Result<BigUint, String> {
    let salt = if with_lot { &owner_entropy[..4] } else { owner_entropy };
    let prefactor = api::scrypt(passphrase, salt, 16384, 8, 8, 32)?;
    let factor = if with_lot {
        let mut input = prefactor;
        input.extend_from_slice(owner_entropy);
        sha256d(&input)
    } else {
        prefactor
    };
    private_from_bytes(&factor)
        .map_err(|_| "This passphrase and salt give an unusable factor; choose another \
                      salt.".to_string())
}

fn lot_numbers(owner_entropy: &[u8]) -> (u32, u32) {
    let n = u32::from_be_bytes(owner_entropy[4..8].try_into().expect("four bytes"));
    (n >> 12, n & 0xfff)
}

/// An intermediate code, with the lot and sequence numbers in it if given
/// (lot below 2^20, sequence below 4096).
pub fn intermediate(passphrase: &[u8], lot_sequence: Option<(u32, u32)>,
                    salt: Option<&[u8]>) -> Result<String, String> {
    let (magic, entropy) = match lot_sequence {
        Some((lot, sequence)) => {
            if lot >= 1 << 20 || sequence >= 4096 {
                return Err("A lot is below 1048576 and a sequence below 4096.".to_string());
            }
            let mut e = match salt {
                Some(s) if s.len() == 4 => s.to_vec(),
                Some(_) => return Err("With a lot number the owner salt is 4 bytes."
                    .to_string()),
                None => api::random_bytes(4)?,
            };
            e.extend((lot * 4096 + sequence).to_be_bytes());
            (INTERMEDIATE_LOT, e)
        }
        None => (INTERMEDIATE_NO_LOT, match salt {
            Some(s) if s.len() == 8 => s.to_vec(),
            Some(_) => return Err("Without a lot number the owner salt is 8 bytes."
                .to_string()),
            None => api::random_bytes(8)?,
        }),
    };
    let factor = passfactor(passphrase, &entropy, lot_sequence.is_some())?;
    let mut out = magic.to_vec();
    out.extend_from_slice(&entropy);
    out.extend(ser_p(&public_key(&factor)));
    Ok(base58check_encode(&out))
}

/// A new key from an intermediate code: the encrypted key, its address
/// and the confirmation code. `seed` is for known-answer tests.
pub fn generate(intermediate: &str, compressed: bool, seed: Option<&[u8]>)
                -> Result<(String, String, String), String> {
    let data = base58check_decode(intermediate)?;
    if data.len() != 49 {
        return Err(format!("An intermediate code is 49 bytes, not {}.", data.len()));
    }
    let with_lot = match data[..8].try_into() {
        Ok(INTERMEDIATE_LOT) => true,
        Ok(INTERMEDIATE_NO_LOT) => false,
        _ => return Err("Not a BIP-38 intermediate code.".to_string()),
    };
    let owner_entropy = &data[8..16];
    let passpoint_bytes = &data[16..49];
    let c = curve();
    let passpoint = c.decode_point(passpoint_bytes)?;
    let seedb = match seed {
        Some(s) if s.len() == 24 => s.to_vec(),
        Some(_) => return Err("seedb is 24 bytes.".to_string()),
        None => api::random_bytes(24)?,
    };
    let factorb = private_from_bytes(&sha256d(&seedb))
        .map_err(|_| "An unusable seed; generate again.".to_string())?;
    let generated = c.scalar_mul_ct(&passpoint, &factorb);
    let address = p2pkh(&public_bytes(&generated, compressed), MAINNET);
    let hash = address_hash(&address);
    let mut salt = hash.to_vec();
    salt.extend_from_slice(owner_entropy);
    let derived = api::scrypt(passpoint_bytes, &salt, 1024, 1, 1, 64)?;
    let (half1, half2) = derived.split_at(32);
    let mut cipher = aes(half2);
    let part1 = encrypt_block(&mut cipher, &seedb[..16], &half1[..16]);
    let mut block = part1[8..].to_vec();
    block.extend_from_slice(&seedb[16..]);
    let part2 = encrypt_block(&mut cipher, &block, &half1[16..]);
    let flag = if compressed { COMPRESSED } else { 0 } | if with_lot { LOT_SEQUENCE } else { 0 };
    let mut key = vec![0x01, 0x43, flag];
    key.extend_from_slice(&hash);
    key.extend_from_slice(owner_entropy);
    key.extend_from_slice(&part1[..8]);
    key.extend(part2);
    // The confirmation code: pointb, encrypted under the same halves.
    let pointb = ser_p(&public_key(&factorb));
    let mut cfrm = CONFIRMATION.to_vec();
    cfrm.push(flag);
    cfrm.extend_from_slice(&hash);
    cfrm.extend_from_slice(owner_entropy);
    cfrm.push(pointb[0] ^ (half2[31] & 1));
    cfrm.extend(encrypt_block(&mut cipher, &pointb[1..17], &half1[..16]));
    cfrm.extend(encrypt_block(&mut cipher, &pointb[17..], &half1[16..]));
    Ok((base58check_encode(&key), address, base58check_encode(&cfrm)))
}

fn check_ec_flag(flag: u8) -> Result<bool, String> {
    if flag & !(COMPRESSED | LOT_SEQUENCE) != 0 {
        return Err(format!("Flag byte {flag:02x} is not one BIP-38 allows here."));
    }
    Ok(flag & LOT_SEQUENCE != 0)
}

fn decrypt_ec(data: &[u8], passphrase: &[u8]) -> Result<Decrypted, String> {
    let flag = data[2];
    let with_lot = check_ec_flag(flag)?;
    let hash = &data[3..7];
    let owner_entropy = &data[7..15];
    let factor = passfactor(passphrase, owner_entropy, with_lot)?;
    let passpoint = ser_p(&public_key(&factor));
    let mut salt = hash.to_vec();
    salt.extend_from_slice(owner_entropy);
    let derived = api::scrypt(&passpoint, &salt, 1024, 1, 1, 64)?;
    let (half1, half2) = derived.split_at(32);
    let mut cipher = aes(half2);
    let block2 = decrypt_block(&mut cipher, &data[23..39], &half1[16..]);
    let mut part1 = data[15..23].to_vec();
    part1.extend_from_slice(&block2[..8]);
    let mut seedb = decrypt_block(&mut cipher, &part1, &half1[..16]);
    seedb.extend_from_slice(&block2[8..]);
    let factorb = BigUint::from_bytes_be(&sha256d(&seedb));
    let key = factor.mod_mul(&factorb, &curve().n)?;
    let lot = with_lot.then(|| lot_numbers(owner_entropy));
    finish(private_from_bytes(&private_bytes_padded(&key)), flag & COMPRESSED != 0, hash, lot)
}

fn private_bytes_padded(k: &BigUint) -> Vec<u8> {
    if k.is_zero() { vec![0; 32] } else { private_bytes(k) }
}

/// Check a confirmation code against the passphrase: the address it
/// proves depends on the passphrase, and the lot and sequence numbers.
pub fn confirm(code: &str, passphrase: &[u8]) -> Result<(String, Option<(u32, u32)>), String> {
    let data = base58check_decode(code)?;
    if data.len() != 51 || data[..5] != CONFIRMATION {
        return Err("Not a BIP-38 confirmation code.".to_string());
    }
    let flag = data[5];
    let with_lot = check_ec_flag(flag)?;
    let hash = &data[6..10];
    let owner_entropy = &data[10..18];
    let factor = passfactor(passphrase, owner_entropy, with_lot)?;
    let passpoint = ser_p(&public_key(&factor));
    let mut salt = hash.to_vec();
    salt.extend_from_slice(owner_entropy);
    let derived = api::scrypt(&passpoint, &salt, 1024, 1, 1, 64)?;
    let (half1, half2) = derived.split_at(32);
    let mut cipher = aes(half2);
    let mut pointb = vec![data[18] ^ (half2[31] & 1)];
    pointb.extend(decrypt_block(&mut cipher, &data[19..35], &half1[..16]));
    pointb.extend(decrypt_block(&mut cipher, &data[35..51], &half1[16..]));
    let wrong = || "Wrong passphrase, or the code was not made from it.".to_string();
    let point = curve().decode_point(&pointb).map_err(|_| wrong())?;
    let generated = curve().scalar_mul_ct(&point, &factor);
    let address = p2pkh(&public_bytes(&generated, flag & COMPRESSED != 0), MAINNET);
    if address_hash(&address) != hash {
        return Err(wrong());
    }
    Ok((address, with_lot.then(|| lot_numbers(owner_entropy))))
}
