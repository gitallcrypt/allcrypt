//! String-to-key specifiers (RFC 9580 section 3.7): a passphrase to a
//! key, by a hash, a salted hash, an iterated salted hash, or Argon2.

use crate::algo::{self, Hash};
use crate::packet::Reader;

#[derive(Clone, Debug, PartialEq)]
pub enum S2k {
    Simple { hash: Hash },
    Salted { hash: Hash, salt: [u8; 8] },
    Iterated { hash: Hash, salt: [u8; 8], coded_count: u8 },
    Argon2 { salt: [u8; 16], passes: u8, parallelism: u8, encoded_memory: u8 },
    /// GnuPG's extension 101: a secret key whose secret part is absent
    /// (`gnu-dummy`) or on a smartcard (`gnu-divert-to-card`).
    Gnu { hash: u8, mode: u8 },
}

/// The octet count an iterated S2K's coded count stands for.
pub use allcrypt::kdf::password::openpgp_s2k_count as decode_count;

impl S2k {
    pub fn read(r: &mut Reader<'_>) -> Result<S2k, String> {
        let kind = r.u8()?;
        Ok(match kind {
            0 => S2k::Simple { hash: algo::hash(r.u8()?)? },
            1 => S2k::Salted { hash: algo::hash(r.u8()?)?, salt: r.bytes(8)?.try_into().unwrap() },
            3 => S2k::Iterated { hash: algo::hash(r.u8()?)?,
                                 salt: r.bytes(8)?.try_into().unwrap(), coded_count: r.u8()? },
            4 => {
                let salt = r.bytes(16)?.try_into().unwrap();
                let (passes, parallelism, encoded_memory) = (r.u8()?, r.u8()?, r.u8()?);
                if passes == 0 || parallelism == 0 {
                    return Err("an Argon2 S2K with zero passes or lanes".to_string());
                }
                let floor = 3 + (parallelism as u32).next_power_of_two().trailing_zeros();
                if !(floor..=31).contains(&u32::from(encoded_memory)) {
                    return Err(format!("an Argon2 S2K's memory exponent {encoded_memory} is \
                                        outside {floor} to 31"));
                }
                S2k::Argon2 { salt, passes, parallelism, encoded_memory }
            }
            101 => {
                let hash = r.u8()?;
                if r.bytes(3)? != b"GNU" {
                    return Err("an S2K of type 101 that is not GnuPG's".to_string());
                }
                S2k::Gnu { hash, mode: r.u8()? }
            }
            other => return Err(format!("S2K type {other} is not one this program has")),
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        match self {
            S2k::Simple { hash } => out.extend_from_slice(&[0, hash.id]),
            S2k::Salted { hash, salt } => {
                out.extend_from_slice(&[1, hash.id]);
                out.extend_from_slice(salt);
            }
            S2k::Iterated { hash, salt, coded_count } => {
                out.extend_from_slice(&[3, hash.id]);
                out.extend_from_slice(salt);
                out.push(*coded_count);
            }
            S2k::Argon2 { salt, passes, parallelism, encoded_memory } => {
                out.push(4);
                out.extend_from_slice(salt);
                out.extend_from_slice(&[*passes, *parallelism, *encoded_memory]);
            }
            S2k::Gnu { hash, mode } => {
                out.extend_from_slice(&[101, *hash]);
                out.extend_from_slice(b"GNU");
                out.push(*mode);
            }
        }
    }

    pub fn describe(&self) -> String {
        match self {
            S2k::Simple { hash } => format!("simple {}", hash.display),
            S2k::Salted { hash, .. } => format!("salted {}", hash.display),
            S2k::Iterated { hash, coded_count, .. } =>
                format!("iterated {} {} octets", hash.display, decode_count(*coded_count)),
            S2k::Argon2 { passes, parallelism, encoded_memory, .. } =>
                format!("Argon2id t={passes} p={parallelism} m=2^{encoded_memory} KiB"),
            S2k::Gnu { mode, .. } => format!("GnuPG extension mode {mode}"),
        }
    }

    /// The key: `key_len` bytes from `passphrase`.
    pub fn derive(&self, passphrase: &[u8], key_len: usize) -> Result<Vec<u8>, String> {
        let (hash, salt, count): (Hash, &[u8], usize) = match self {
            S2k::Simple { hash } => (*hash, &[], 0),
            S2k::Salted { hash, salt } => (*hash, salt, 0),
            S2k::Iterated { hash, salt, coded_count } => (*hash, salt, decode_count(*coded_count)),
            S2k::Argon2 { salt, passes, parallelism, encoded_memory } => {
                return allcrypt::api::argon2("argon2id", passphrase, salt,
                                             1u32 << encoded_memory, u32::from(*passes),
                                             u32::from(*parallelism), &[], &[], key_len);
            }
            S2k::Gnu { .. } => return Err("this secret key has no secret part here (GnuPG's \
                                           gnu-dummy or card stub)".to_string()),
        };
        Ok(allcrypt::kdf::password::openpgp_s2k(algo::new_hash(hash), passphrase, salt, count,
                                                key_len))
    }
}

/// The coded count that stands for at least `octets`.
pub use allcrypt::kdf::password::openpgp_s2k_coded_count as encode_count;
