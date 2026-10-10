//! The public key operations: a session key encrypted to a key and back
//! (the PKESK packet, RFC 9580 section 5.1, with ECDH as section 11.5
//! and RFC 6637 give it), and the check that a secret part belongs to
//! its public part.

use crate::algo::{self, Cipher};
use crate::keys::{self, Material, PublicKey, Secret};
use crate::message::{Random, SessionKey};
use crate::packet::Reader;
use allcrypt::api::{self, EcKey, RsaKey, RsaPublicKey};
use allcrypt::bignum::BigUint;
use allcrypt::publickey_ciphers::dh::DhGroup;
use allcrypt::publickey_ciphers::elgamal::{self, ElGamalPrivateKey, ElGamalPublicKey};

fn pad_left(value: &[u8], width: usize) -> Result<Vec<u8>, String> {
    if value.len() > width {
        return Err("a value wider than its modulus".to_string());
    }
    let mut out = vec![0u8; width - value.len()];
    out.extend_from_slice(value);
    Ok(out)
}

fn native_curve25519_secret(scalar: &[u8]) -> Result<Vec<u8>, String> {
    // Stored as a big endian integer: the native (little endian) form
    // reversed.
    let mut native = pad_left(scalar, 32)?;
    native.reverse();
    Ok(native)
}

/// The library's name for a Weierstrass curve, registering the
/// Brainpool ones first if that is what it is.
fn library_curve(curve: &keys::Curve) -> Result<Option<&'static str>, String> {
    if curve.name.starts_with("brainpool") {
        keys::register_brainpool()?;
    }
    Ok(curve.library)
}

fn prefixed(point: &[u8]) -> Result<&[u8], String> {
    match point.split_first() {
        Some((0x40, rest)) => Ok(rest),
        _ => Err("a point without its 0x40 prefix".to_string()),
    }
}

/// Check that `secret` is the secret half of `public`: a wrong
/// passphrase under the old two byte checksum gets past it one time in
/// 65536, and a key whose halves disagree is a key nobody should use.
pub fn check_pair(public: &PublicKey, secret: &Secret) -> Result<(), String> {
    let mismatch = || "the secret key does not match its public key".to_string();
    let ok = match (&public.material, secret) {
        (Material::Rsa { n, .. }, Secret::Rsa { p, q, .. }) =>
            BigUint::from_bytes_be(p).mul(&BigUint::from_bytes_be(q))
                == BigUint::from_bytes_be(n),
        (Material::Dsa { p, g, y, .. }, Secret::Scalar(x))
        | (Material::ElGamal { p, g, y }, Secret::Scalar(x)) => {
            let p = BigUint::from_bytes_be(p);
            BigUint::from_bytes_be(g).mod_pow_ct(&BigUint::from_bytes_be(x), &p)?
                == BigUint::from_bytes_be(y)
        }
        (Material::Ec { point, .. }, Secret::Scalar(d))
        | (Material::Ecdh { point, .. }, Secret::Scalar(d)) => {
            let curve = public.curve().ok_or("a curve this program does not have")?;
            match (library_curve(curve)?, curve.name) {
                (Some(name), _) => EcKey::from_private(name, d)?.public_bytes(false)? == *point,
                (None, keys::CURVE25519_LEGACY) =>
                    api::x25519_public_key(&native_curve25519_secret(d)?)? == prefixed(point)?,
                (None, "X448") => api::x448_public_key(&pad_left(d, 56)?)?
                    == keys::native_point(point, 56)?,
                (None, "X25519") => api::x25519_public_key(&pad_left(d, 32)?)?
                    == keys::native_point(point, 32)?,
                _ => return Err(format!("{} has no arithmetic here", curve.name)),
            }
        }
        (Material::Ec { point, .. }, Secret::Native(seed)) => {
            let curve = public.curve().ok_or("a curve this program does not have")?;
            let name = if curve.name == "Ed448" { "ed448" } else { "ed25519" };
            api::eddsa_public_key(name, seed)? == keys::native_point(point, curve.field)?
        }
        (Material::Native(public_bytes), Secret::Native(secret)) => *public_bytes == match
            public.algorithm {
            keys::X25519 => api::x25519_public_key(secret)?,
            keys::X448 => api::x448_public_key(secret)?,
            keys::ED25519 => api::eddsa_public_key("ed25519", secret)?,
            keys::ED448 => api::eddsa_public_key("ed448", secret)?,
            _ => return Err(mismatch()),
        },
        _ => false,
    };
    if ok { Ok(()) } else { Err(mismatch()) }
}

/// The RFC 6637 / RFC 9580 11.5 parameters the ECDH KDF hashes.
fn ecdh_param(public: &PublicKey) -> Result<Vec<u8>, String> {
    let Material::Ecdh { oid, hash, cipher, .. } = &public.material else {
        return Err("not an ECDH key".to_string());
    };
    let mut param = vec![oid.len() as u8];
    param.extend_from_slice(oid);
    param.extend_from_slice(&[keys::ECDH, 3, 1, *hash, *cipher]);
    param.extend_from_slice(b"Anonymous Sender    ");
    // RFC 6637 was written for 20 byte fingerprints. RFC 9580 puts a
    // version 6 key's whole 32 in; GnuPG puts the first 20 of a version
    // 5 key's.
    let fingerprint = public.fingerprint();
    let take = if public.version == 5 { 20 } else { fingerprint.len() };
    param.extend_from_slice(&fingerprint[..take]);
    Ok(param)
}

/// The KEK: `Hash(00 00 00 01 || shared || param)`, cut to the key
/// wrap cipher's key length.
fn ecdh_kek(public: &PublicKey, shared: &[u8]) -> Result<(Cipher, Vec<u8>), String> {
    let Material::Ecdh { hash, cipher, .. } = &public.material else { unreachable!() };
    let kek_cipher = algo::cipher(*cipher)?;
    if kek_cipher.block_len != 16 {
        return Err("an ECDH key wrap cipher without a 128 bit block".to_string());
    }
    let mut kek = algo::digest(algo::hash(*hash)?, &[&[0, 0, 0, 1], shared,
                                                    &ecdh_param(public)?]);
    if kek.len() < kek_cipher.key_len {
        return Err("an ECDH KDF hash shorter than its key wrap key".to_string());
    }
    kek.truncate(kek_cipher.key_len);
    Ok((kek_cipher, kek))
}

/// What the RSA, ElGamal and ECDH forms encrypt: (for v3) the cipher,
/// the key, and a two byte checksum.
fn session_plaintext(session: &SessionKey, v6: bool) -> Vec<u8> {
    let mut m = Vec::with_capacity(session.key.len() + 3);
    if !v6 {
        m.push(session.cipher.expect("a v3 PKESK names its cipher").id);
    }
    m.extend_from_slice(&session.key);
    let sum = session.key.iter().map(|&b| u32::from(b)).sum::<u32>() as u16;
    m.extend_from_slice(&sum.to_be_bytes());
    m
}

fn parse_session_plaintext(m: &[u8], v6: bool) -> Result<SessionKey, String> {
    let bad = || "the decrypted session key is malformed".to_string();
    let (cipher, rest) = if v6 { (None, m) } else {
        let (id, rest) = m.split_first().ok_or_else(bad)?;
        (Some(algo::cipher(*id).map_err(|_| bad())?), rest)
    };
    if rest.len() < 3 {
        return Err(bad());
    }
    let (key, sum) = rest.split_at(rest.len() - 2);
    if let Some(c) = cipher {
        if key.len() != c.key_len {
            return Err(bad());
        }
    }
    if (key.iter().map(|&b| u32::from(b)).sum::<u32>() as u16).to_be_bytes() != sum {
        return Err(bad());
    }
    Ok(SessionKey { cipher, key: key.to_vec() })
}

fn read_mpi<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], String> {
    let bits = u16::from_be_bytes(r.bytes(2)?.try_into().unwrap()) as usize;
    r.bytes(bits.div_ceil(8))
}

/// A parsed PKESK packet.
pub struct Pkesk<'a> {
    pub version: u8,
    /// v3: the key ID (all zeros for an anonymous recipient).
    pub key_id: [u8; 8],
    /// v6: the key version and fingerprint (empty for anonymous).
    pub fingerprint: Vec<u8>,
    pub algorithm: u8,
    pub fields: &'a [u8],
}

impl<'a> Pkesk<'a> {
    pub fn parse(body: &'a [u8]) -> Result<Pkesk<'a>, String> {
        let mut r = Reader::new(body);
        let version = r.u8()?;
        let (key_id, fingerprint) = match version {
            3 => (r.bytes(8)?.try_into().unwrap(), Vec::new()),
            6 => {
                // RFC 9580 section 5.1.2: zero for an anonymous recipient,
                // else the key's version and its fingerprint - 20 bytes
                // for a v4 key, 32 for v5 and v6. Anything else cannot
                // yield a key ID and is refused before one is cut out.
                let n = r.u8()? as usize;
                let id = r.bytes(n)?;
                match (n, id.first()) {
                    (0, _) => ([0; 8], Vec::new()),
                    (21, Some(4)) | (33, Some(5 | 6)) => (pkesk_key_id(id), id[1..].to_vec()),
                    _ => return Err(format!("a PKESK v6 key identifier of {n} bytes, version {:?}",
                                            id.first())),
                }
            }
            v => return Err(format!("PKESK version {v} is not one this program reads")),
        };
        let algorithm = r.u8()?;
        Ok(Pkesk { version, key_id, fingerprint, algorithm, fields: r.rest() })
    }

    /// Whether this packet is for `key` (or for anybody: anonymous).
    pub fn is_for(&self, key: &PublicKey) -> bool {
        if self.version == 3 {
            self.key_id == [0; 8] || self.key_id == key.key_id()
        } else {
            self.fingerprint.is_empty() || self.fingerprint == key.fingerprint()
        }
    }

    /// The session key, with `secret`, the secret half of `key`.
    pub fn decrypt(&self, key: &PublicKey, secret: &Secret) -> Result<SessionKey, String> {
        let v6 = self.version == 6;
        let mut r = Reader::new(self.fields);
        match (self.algorithm, &key.material, secret) {
            (keys::RSA | keys::RSA_ENCRYPT, Material::Rsa { e, .. }, Secret::Rsa { p, q, .. }) => {
                let c = read_mpi(&mut r)?;
                let private = RsaKey::from_primes(p, q, e)?;
                let m = private.decrypt(&pad_left(c, private.size())?)?;
                parse_session_plaintext(&m, v6)
            }
            (keys::ELGAMAL | keys::ELGAMAL_SIGN, Material::ElGamal { p, g, .. },
             Secret::Scalar(x)) => {
                let (c1, c2) = (read_mpi(&mut r)?, read_mpi(&mut r)?);
                let group = DhGroup::from_bytes(p, g)?;
                let private = ElGamalPrivateKey::from_private(group, BigUint::from_bytes_be(x))?;
                let width = p.len();
                let mut c = pad_left(c1, width)?;
                c.extend(pad_left(c2, width)?);
                parse_session_plaintext(&elgamal::decrypt_pkcs1v15(&private, &c)?, v6)
            }
            (keys::ECDH, Material::Ecdh { .. }, Secret::Scalar(d)) => {
                let ephemeral = read_mpi(&mut r)?;
                let len = r.u8()? as usize;
                let wrapped = r.bytes(len)?;
                let curve = key.curve().ok_or("an ECDH curve this program does not have")?;
                let shared = match (library_curve(curve)?, curve.name) {
                    (Some(name), _) => EcKey::from_private(name, d)?.exchange(ephemeral)?,
                    (None, keys::CURVE25519_LEGACY) => api::x25519_exchange(
                        &native_curve25519_secret(d)?, prefixed(ephemeral)?)?,
                    (None, "X448") => api::x448_exchange(
                        &pad_left(d, 56)?, &keys::native_point(ephemeral, 56)?)?,
                    (None, "X25519") => api::x25519_exchange(
                        &pad_left(d, 32)?, &keys::native_point(ephemeral, 32)?)?,
                    _ => return Err(format!("{} has no arithmetic here", curve.name)),
                };
                let (kek_cipher, kek) = ecdh_kek(key, &shared)?;
                let padded = api::key_unwrap(kek_cipher.name, &kek, wrapped)?;
                // PKCS#5 padding to a multiple of eight.
                let n = *padded.last().ok_or("an empty unwrapped key")? as usize;
                if n == 0 || n > 8 || n > padded.len()
                    || padded[padded.len() - n..].iter().any(|&b| b as usize != n) {
                    return Err("the unwrapped session key's padding is wrong".to_string());
                }
                parse_session_plaintext(&padded[..padded.len() - n], v6)
            }
            (keys::X25519 | keys::X448, Material::Native(public), Secret::Native(secret)) => {
                let x448 = self.algorithm == keys::X448;
                let ephemeral = r.bytes(if x448 { 56 } else { 32 })?;
                let len = r.u8()? as usize;
                let mut rest = r.bytes(len)?;
                let cipher = if v6 { None } else {
                    let (id, wrapped) = rest.split_first().ok_or("an empty X25519 field")?;
                    rest = wrapped;
                    let c = algo::cipher(*id)?;
                    if !matches!(c.id, 7..=9) {
                        return Err("X25519 and X448 session keys are AES only".to_string());
                    }
                    Some(c)
                };
                let shared = if x448 { api::x448_exchange(secret, ephemeral)? }
                             else { api::x25519_exchange(secret, ephemeral)? };
                let kek = native_kek(x448, ephemeral, public, &shared);
                let key = api::key_unwrap("aes", &kek, rest)?;
                if let Some(c) = cipher {
                    if key.len() != c.key_len {
                        return Err("the unwrapped session key is not its cipher's length"
                            .to_string());
                    }
                }
                Ok(SessionKey { cipher, key })
            }
            _ => Err(format!("a {} PKESK cannot be opened with a {} key",
                             keys::algorithm_name(self.algorithm),
                             keys::algorithm_name(key.algorithm))),
        }
    }
}

/// The key ID from a v6 PKESK's identifier, which `Pkesk::parse` has
/// checked is a key version and a fingerprint of that version's length.
fn pkesk_key_id(id: &[u8]) -> [u8; 8] {
    let fingerprint = &id[1..];
    if id[0] == 4 {
        fingerprint[fingerprint.len() - 8..].try_into().unwrap()
    } else {
        fingerprint[..8].try_into().unwrap()
    }
}

/// HKDF over ephemeral, recipient and shared value, as section 5.1.6
/// and 5.1.7 give it: SHA-256 to a 16 byte AES key for X25519, SHA-512
/// to a 32 byte one for X448.
fn native_kek(x448: bool, ephemeral: &[u8], public: &[u8], shared: &[u8]) -> Vec<u8> {
    let mut ikm = ephemeral.to_vec();
    ikm.extend_from_slice(public);
    ikm.extend_from_slice(shared);
    if x448 {
        allcrypt::kdf::hkdf(allcrypt::hash_functions::sha2::SHA512::new(&[], 512), &[], &ikm,
                            b"OpenPGP X448", 32).expect("HKDF-SHA512 to 32 bytes")
    } else {
        algo::hkdf_sha256(&[], &ikm, b"OpenPGP X25519", 16)
    }
}

/// A PKESK packet body carrying `session` to `recipient`: version 3,
/// or version 6 for a v2 SEIPD.
pub fn encrypt_session_key(session: &SessionKey, recipient: &PublicKey, v6: bool,
                           random: Random<'_>) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    if v6 {
        let fingerprint = recipient.fingerprint();
        body.extend_from_slice(&[6, fingerprint.len() as u8 + 1, recipient.version]);
        body.extend_from_slice(&fingerprint);
    } else {
        body.push(3);
        body.extend_from_slice(&recipient.key_id());
    }
    body.push(recipient.algorithm);
    match (&recipient.material, recipient.algorithm) {
        (Material::Rsa { n, e }, keys::RSA | keys::RSA_ENCRYPT) => {
            let c = RsaPublicKey::new(n, e)?.encrypt(&session_plaintext(session, v6))?;
            keys::write_mpi(&c, &mut body);
        }
        (Material::ElGamal { p, g, y }, keys::ELGAMAL | keys::ELGAMAL_SIGN) => {
            if v6 {
                return Err("RFC 9580 forbids ElGamal in a version 6 PKESK".to_string());
            }
            let public = ElGamalPublicKey::new(DhGroup::from_bytes(p, g)?,
                                               BigUint::from_bytes_be(y))?;
            let c = elgamal::encrypt_pkcs1v15(&public, &session_plaintext(session, v6))?;
            let (c1, c2) = c.split_at(c.len() / 2);
            keys::write_mpi(c1, &mut body);
            keys::write_mpi(c2, &mut body);
        }
        (Material::Ecdh { point, .. }, keys::ECDH) => {
            let curve = recipient.curve().ok_or("an ECDH curve this program does not have")?;
            let (ephemeral, shared) = match (library_curve(curve)?, curve.name) {
                (Some(name), _) => {
                    let ephemeral = EcKey::generate(name)?;
                    (ephemeral.public_bytes(false)?, ephemeral.exchange(point)?)
                }
                (None, keys::CURVE25519_LEGACY) => {
                    let mut secret = [0u8; 32];
                    random(&mut secret)?;
                    let mut ephemeral = vec![0x40];
                    ephemeral.extend(api::x25519_public_key(&secret)?);
                    (ephemeral, api::x25519_exchange(&secret, prefixed(point)?)?)
                }
                (None, "X448") => {
                    let mut secret = [0u8; 56];
                    random(&mut secret)?;
                    (api::x448_public_key(&secret)?,
                     api::x448_exchange(&secret, &keys::native_point(point, 56)?)?)
                }
                (None, "X25519") => {
                    let mut secret = [0u8; 32];
                    random(&mut secret)?;
                    (api::x25519_public_key(&secret)?,
                     api::x25519_exchange(&secret, &keys::native_point(point, 32)?)?)
                }
                _ => return Err(format!("{} has no arithmetic here", curve.name)),
            };
            let (kek_cipher, kek) = ecdh_kek(recipient, &shared)?;
            let mut m = session_plaintext(session, v6);
            let n = 8 - m.len() % 8;
            m.extend(std::iter::repeat_n(n as u8, n));
            let wrapped = api::key_wrap(kek_cipher.name, &kek, &m)?;
            if curve.library.is_none() && curve.name != keys::CURVE25519_LEGACY {
                keys::write_sos(&ephemeral, &mut body);
            } else {
                keys::write_mpi(&ephemeral, &mut body);
            }
            body.push(wrapped.len() as u8);
            body.extend_from_slice(&wrapped);
        }
        (Material::Native(public), keys::X25519 | keys::X448) => {
            let x448 = recipient.algorithm == keys::X448;
            let mut secret = vec![0u8; if x448 { 56 } else { 32 }];
            random(&mut secret)?;
            let (ephemeral, shared) = if x448 {
                (api::x448_public_key(&secret)?, api::x448_exchange(&secret, public)?)
            } else {
                (api::x25519_public_key(&secret)?, api::x25519_exchange(&secret, public)?)
            };
            let kek = native_kek(x448, &ephemeral, public, &shared);
            let wrapped = api::key_wrap("aes", &kek, &session.key)?;
            body.extend_from_slice(&ephemeral);
            if v6 {
                body.push(wrapped.len() as u8);
            } else {
                let cipher = session.cipher.expect("a v3 PKESK names its cipher");
                if !matches!(cipher.id, 7..=9) {
                    return Err(format!("{} carries AES session keys only; use --cipher aes128, \
                                        aes192 or aes256", keys::algorithm_name(recipient.algorithm)));
                }
                body.push(wrapped.len() as u8 + 1);
                body.push(cipher.id);
            }
            body.extend_from_slice(&wrapped);
        }
        _ => return Err(format!("cannot encrypt to a {} key",
                                keys::algorithm_name(recipient.algorithm))),
    }
    Ok(body)
}
