//! BIP-32 hierarchical deterministic keys over secp256k1: the master key
//! from a seed, private and public child derivation, and the 78-byte
//! extended key serialization under each of the version prefixes wallets
//! use (BIP-32's xprv, BIP-49's yprv and BIP-84's zprv, and their testnet
//! forms).

use allcrypt::bignum::BigUint;
use allcrypt::ec::Point;

use crate::encoding::{base58check_decode, base58check_encode};
use crate::hash::{hash160, hmac_sha512};
use crate::keys::{curve, public_key, ser_p};

pub const HARDENED: u32 = 0x8000_0000;

/// What an extended key's prefix says: the network, and (BIP-49 and
/// BIP-84) which kind of address its keys are for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Version {
    pub private_name: &'static str,
    pub public_name: &'static str,
    pub private: u32,
    pub public: u32,
    pub testnet: bool,
}

pub const VERSIONS: [Version; 6] = [
    Version { private_name: "xprv", public_name: "xpub", private: 0x0488_ade4,
              public: 0x0488_b21e, testnet: false },
    Version { private_name: "yprv", public_name: "ypub", private: 0x049d_7878,
              public: 0x049d_7cb2, testnet: false },
    Version { private_name: "zprv", public_name: "zpub", private: 0x04b2_430c,
              public: 0x04b2_4746, testnet: false },
    Version { private_name: "tprv", public_name: "tpub", private: 0x0435_8394,
              public: 0x0435_87cf, testnet: true },
    Version { private_name: "uprv", public_name: "upub", private: 0x044a_4e28,
              public: 0x044a_5262, testnet: true },
    Version { private_name: "vprv", public_name: "vpub", private: 0x045f_18bc,
              public: 0x045f_1cf6, testnet: true },
];

pub fn version_named(name: &str) -> Result<Version, String> {
    VERSIONS.iter().find(|v| v.private_name == name || v.public_name == name).copied()
        .ok_or_else(|| format!("No extended key version {name}; the known ones are xprv, \
                                yprv, zprv, tprv, uprv and vprv."))
}

#[derive(Clone)]
pub enum KeyPart {
    Private(BigUint),
    Public(Point),
}

impl std::fmt::Debug for KeyPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyPart::Private(_) => f.debug_tuple("Private").field(&crate::hidden::Hidden).finish(),
            KeyPart::Public(point) => f.debug_tuple("Public").field(point).finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExtendedKey {
    pub version: Version,
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub key: KeyPart,
}

fn split(i: &[u8]) -> (BigUint, [u8; 32]) {
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&i[32..]);
    (BigUint::from_bytes_be(&i[..32]), chain)
}

impl ExtendedKey {
    /// The master key: HMAC-SHA512 keyed with "Bitcoin seed". A left half
    /// of zero or at least n - about one seed in 2^127 - is an invalid
    /// master key, and BIP-32 says to refuse the seed.
    pub fn master(seed: &[u8], version: Version) -> Result<ExtendedKey, String> {
        if !(16..=64).contains(&seed.len()) {
            return Err(format!("A BIP-32 seed is 16 to 64 bytes, not {}.", seed.len()));
        }
        let (k, chain_code) = split(&hmac_sha512(b"Bitcoin seed", seed));
        if k.is_zero() || k >= curve().n {
            return Err("This seed gives an invalid master key; BIP-32 says to use \
                        another.".to_string());
        }
        Ok(ExtendedKey { version, depth: 0, parent_fingerprint: [0; 4], child_number: 0,
                         chain_code, key: KeyPart::Private(k) })
    }

    pub fn public_point(&self) -> Point {
        match &self.key {
            KeyPart::Private(k) => public_key(k),
            KeyPart::Public(p) => p.clone(),
        }
    }

    pub fn private_key(&self) -> Option<&BigUint> {
        match &self.key {
            KeyPart::Private(k) => Some(k),
            KeyPart::Public(_) => None,
        }
    }

    /// The first four bytes of HASH160 of the compressed public key.
    pub fn fingerprint(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out.copy_from_slice(&hash160(&ser_p(&self.public_point()))[..4]);
        out
    }

    /// CKDpriv or CKDpub. An index whose derivation is invalid (IL >= n,
    /// or a zero key) is refused, and BIP-32 says to go on to the next.
    pub fn child(&self, index: u32) -> Result<ExtendedKey, String> {
        let c = curve();
        let hardened = index & HARDENED != 0;
        let mut data = match (&self.key, hardened) {
            (KeyPart::Private(k), true) => {
                let mut d = vec![0u8];
                d.extend_from_slice(&k.to_bytes_be_padded(32)?);
                d
            }
            (KeyPart::Public(_), true) => {
                return Err("A hardened child needs the private key.".to_string());
            }
            _ => ser_p(&self.public_point()),
        };
        data.extend_from_slice(&index.to_be_bytes());
        let (il, chain_code) = split(&hmac_sha512(&self.chain_code, &data));
        let invalid = || format!("Child {} is invalid (one index in about 2^127); BIP-32 \
                                  says to use the next.", index_text(index));
        if il >= c.n {
            return Err(invalid());
        }
        let key = match &self.key {
            KeyPart::Private(k) => {
                let child = il.mod_add(k, &c.n)?;
                if child.is_zero() {
                    return Err(invalid());
                }
                KeyPart::Private(child)
            }
            KeyPart::Public(p) => {
                let point = c.add(&c.generator_mul(&il), p);
                if point.is_identity() {
                    return Err(invalid());
                }
                KeyPart::Public(point)
            }
        };
        let depth = self.depth.checked_add(1).ok_or("A depth beyond 255.")?;
        Ok(ExtendedKey { version: self.version, depth, parent_fingerprint: self.fingerprint(),
                         child_number: index, chain_code, key })
    }

    pub fn derive(&self, path: &[u32]) -> Result<ExtendedKey, String> {
        path.iter().try_fold(self.clone(), |key, &i| key.child(i))
    }

    /// The public extended key, N(k).
    pub fn neuter(&self) -> ExtendedKey {
        ExtendedKey { key: KeyPart::Public(self.public_point()), ..self.clone() }
    }

    pub fn serialize(&self) -> String {
        let (version, key) = match &self.key {
            KeyPart::Private(k) => {
                let mut b = vec![0u8];
                b.extend(k.to_bytes_be_padded(32).expect("below n"));
                (self.version.private, b)
            }
            KeyPart::Public(p) => (self.version.public, ser_p(p)),
        };
        let mut out = version.to_be_bytes().to_vec();
        out.push(self.depth);
        out.extend_from_slice(&self.parent_fingerprint);
        out.extend_from_slice(&self.child_number.to_be_bytes());
        out.extend_from_slice(&self.chain_code);
        out.extend(key);
        base58check_encode(&out)
    }

    /// Parse and check an extended key as BIP-32's test vector 5 requires:
    /// a known version whose kind matches the key, a valid key, and a
    /// master key that claims no parent or index.
    pub fn parse(text: &str) -> Result<ExtendedKey, String> {
        let data = base58check_decode(text)?;
        if data.len() != 78 {
            return Err(format!("An extended key is 78 bytes, not {}.", data.len()));
        }
        let number = u32::from_be_bytes(data[..4].try_into().expect("four bytes"));
        let (version, private) = VERSIONS.iter()
            .find_map(|v| if v.private == number { Some((*v, true)) }
                          else if v.public == number { Some((*v, false)) } else { None })
            .ok_or_else(|| format!("Unknown extended key version {number:08x}."))?;
        let depth = data[4];
        let parent_fingerprint: [u8; 4] = data[5..9].try_into().expect("four bytes");
        let child_number = u32::from_be_bytes(data[9..13].try_into().expect("four bytes"));
        let chain_code: [u8; 32] = data[13..45].try_into().expect("32 bytes");
        if depth == 0 && parent_fingerprint != [0; 4] {
            return Err("A master key (depth 0) with a parent fingerprint.".to_string());
        }
        if depth == 0 && child_number != 0 {
            return Err("A master key (depth 0) with a child number.".to_string());
        }
        let key_bytes = &data[45..];
        let key = match (private, key_bytes[0]) {
            (true, 0) => {
                let k = BigUint::from_bytes_be(&key_bytes[1..]);
                if k.is_zero() || k >= curve().n {
                    return Err("The private key is not in [1, n).".to_string());
                }
                KeyPart::Private(k)
            }
            (true, _) => return Err(format!("A {} whose key is not a private key.",
                                            version.private_name)),
            (false, 2 | 3) => KeyPart::Public(curve().decode_point(key_bytes)
                .map_err(|e| format!("The public key is not a point on secp256k1: {e}"))?),
            (false, 0) => return Err(format!("A {} holding a private key.",
                                             version.public_name)),
            (false, prefix) => return Err(format!("A public key with prefix {prefix:02x}; an \
                                                   extended key's is compressed.")),
        };
        Ok(ExtendedKey { version, depth, parent_fingerprint, child_number, chain_code, key })
    }
}

/// `m/44'/0'/0'/0/7`: `'`, `h` or `H` marks a hardened index.
pub fn parse_path(text: &str) -> Result<Vec<u32>, String> {
    let mut parts = text.trim().split('/');
    if parts.next() != Some("m") {
        return Err(format!("{text}: a path starts with m."));
    }
    parts.map(|p| {
        let (digits, hardened) = match p.strip_suffix(['\'', 'h', 'H']) {
            Some(d) => (d, true),
            None => (p, false),
        };
        let n: u32 = digits.parse().ok().filter(|&n| n < HARDENED)
            .ok_or_else(|| format!("{text}: '{p}' is not an index below 2^31."))?;
        Ok(if hardened { n | HARDENED } else { n })
    }).collect()
}

pub fn index_text(index: u32) -> String {
    if index & HARDENED != 0 { format!("{}'", index & !HARDENED) } else { index.to_string() }
}

pub fn path_text(path: &[u32]) -> String {
    std::iter::once("m".to_string()).chain(path.iter().map(|&i| index_text(i)))
        .collect::<Vec<_>>().join("/")
}
