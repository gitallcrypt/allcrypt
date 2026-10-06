//! Making keys: the key material for each algorithm, and the
//! transferable key around it - primary key, user ID, the
//! self-signatures that give them meaning, and an encryption subkey.

use crate::algo;
use crate::keys::{self, PublicKey, Secret, SecretKey};
use crate::message::Random;
use crate::packet;
use crate::s2k::S2k;
use crate::sig::{self, Subpacket};
use allcrypt::api::{self, EcKey, RsaKey};
use allcrypt::bignum::BigUint;
use allcrypt::publickey_ciphers::dh;
use allcrypt::publickey_ciphers::dsa::{DsaParameters, DsaPrivateKey};
use allcrypt::publickey_ciphers::elgamal::ElGamalPrivateKey;

/// What `gen-key --algo` names: the primary (signing) key and the
/// encryption subkey.
pub struct Plan {
    pub primary: Kind,
    pub subkey: Kind,
}

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Rsa(usize),
    Dsa(usize),
    ElGamal(usize),
    Ecdsa(&'static str),
    Ecdh(&'static str),
    EddsaLegacy,
    Curve25519Legacy,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

pub fn plan(name: &str, v6: bool) -> Result<Plan, String> {
    let ec = |curve: &'static str| Plan { primary: Kind::Ecdsa(curve), subkey: Kind::Ecdh(curve) };
    Ok(match name {
        "rsa2048" => Plan { primary: Kind::Rsa(2048), subkey: Kind::Rsa(2048) },
        "rsa3072" => Plan { primary: Kind::Rsa(3072), subkey: Kind::Rsa(3072) },
        "rsa4096" => Plan { primary: Kind::Rsa(4096), subkey: Kind::Rsa(4096) },
        "dsa2048" if !v6 => Plan { primary: Kind::Dsa(2048), subkey: Kind::ElGamal(2048) },
        "dsa3072" if !v6 => Plan { primary: Kind::Dsa(3072), subkey: Kind::ElGamal(3072) },
        "nistp256" => ec("NIST P-256"),
        "nistp384" => ec("NIST P-384"),
        "nistp521" => ec("NIST P-521"),
        "brainpoolp256r1" => ec("brainpoolP256r1"),
        "brainpoolp384r1" => ec("brainpoolP384r1"),
        "brainpoolp512r1" => ec("brainpoolP512r1"),
        "secp256k1" if !v6 => ec("secp256k1"),
        // GnuPG's default: EdDSA and ECDH over the legacy 25519 OIDs,
        // which RFC 9580 allows in version 4 keys only.
        "ed25519-legacy" if !v6 => Plan { primary: Kind::EddsaLegacy,
                                          subkey: Kind::Curve25519Legacy },
        "ed25519" => Plan { primary: Kind::Ed25519, subkey: Kind::X25519 },
        "ed448" => Plan { primary: Kind::Ed448, subkey: Kind::X448 },
        other => return Err(format!(
            "unknown key algorithm {other}{} (rsa2048, rsa3072, rsa4096, dsa2048, dsa3072, \
             nistp256, nistp384, nistp521, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, \
             secp256k1, ed25519-legacy, ed25519, ed448)",
            if v6 { " for a version 6 key" } else { "" })),
    })
}

fn curve(name: &str) -> &'static keys::Curve {
    keys::CURVES.iter().find(|c| c.name == name).expect("a curve in the table")
}

fn mpi(value: &[u8], out: &mut Vec<u8>) {
    keys::write_mpi(value, out);
}

/// Fresh key material: the public key packet body's algorithm-specific
/// part, the algorithm, and the secret.
fn material(kind: Kind, random: Random<'_>) -> Result<(u8, Vec<u8>, Secret), String> {
    let mut public = Vec::new();
    let (algorithm, secret) = match kind {
        Kind::Rsa(bits) => {
            let key = RsaKey::generate(bits)?;
            let numbers: std::collections::HashMap<&str, Vec<u8>> =
                key.numbers().into_iter().collect();
            // OpenPGP wants p < q, and u = p^-1 mod q.
            let (mut p, mut q) = (numbers["p"].clone(), numbers["q"].clone());
            if BigUint::from_bytes_be(&p) > BigUint::from_bytes_be(&q) {
                std::mem::swap(&mut p, &mut q);
            }
            mpi(&numbers["n"], &mut public);
            mpi(&numbers["e"], &mut public);
            (keys::RSA, Secret::Rsa { p, q })
        }
        Kind::Dsa(bits) => {
            let parameters = DsaParameters::generate(bits, 256)?;
            let private = DsaPrivateKey::generate(parameters)?;
            let p = &private.public;
            for value in [&p.parameters.p, &p.parameters.q, &p.parameters.g, &p.y] {
                mpi(&value.to_bytes_be(), &mut public);
            }
            (keys::DSA, Secret::Scalar(private.x().to_bytes_be()))
        }
        Kind::ElGamal(bits) => {
            // A fixed safe-prime group (RFC 3526) with g = 2, rather than
            // a fresh prime per key as GnuPG makes.
            let group = dh::modp_group(match bits { 3072 => dh::MODP_3072, _ => dh::MODP_2048 })?;
            let private = ElGamalPrivateKey::generate(group)?;
            let p = private.public();
            for value in [p.group().p(), p.group().g(), p.y()] {
                mpi(&value.to_bytes_be(), &mut public);
            }
            (keys::ELGAMAL, Secret::Scalar(private.private_bytes()?))
        }
        Kind::Ecdsa(name) | Kind::Ecdh(name) => {
            let c = curve(name);
            if name.starts_with("brainpool") {
                keys::register_brainpool()?;
            }
            let key = EcKey::generate(c.library.expect("a Weierstrass curve"))?;
            let oid = keys::oid_bytes(c.dotted);
            public.push(oid.len() as u8);
            public.extend_from_slice(&oid);
            mpi(&key.public_bytes(false)?, &mut public);
            let algorithm = if matches!(kind, Kind::Ecdh(_)) {
                public.extend_from_slice(&ecdh_kdf(c.field));
                keys::ECDH
            } else {
                keys::ECDSA
            };
            (algorithm, Secret::Scalar(key.private_bytes()?))
        }
        Kind::EddsaLegacy => {
            let (seed, point) = api::eddsa_generate("ed25519")?;
            let oid = keys::oid_bytes(curve("Ed25519Legacy").dotted);
            public.push(oid.len() as u8);
            public.extend_from_slice(&oid);
            let mut prefixed = vec![0x40];
            prefixed.extend(point);
            mpi(&prefixed, &mut public);
            (keys::EDDSA_LEGACY, Secret::Native(seed))
        }
        Kind::Curve25519Legacy => {
            // RFC 9580 5.5.5.6.1.1: clamped, stored big endian.
            let mut native = [0u8; 32];
            random(&mut native)?;
            native[0] &= 248;
            native[31] &= 127;
            native[31] |= 64;
            let c = curve(keys::CURVE25519_LEGACY);
            let oid = keys::oid_bytes(c.dotted);
            public.push(oid.len() as u8);
            public.extend_from_slice(&oid);
            let mut prefixed = vec![0x40];
            prefixed.extend(api::x25519_public_key(&native)?);
            mpi(&prefixed, &mut public);
            public.extend_from_slice(&ecdh_kdf(32));
            let mut stored = native.to_vec();
            stored.reverse();
            (keys::ECDH, Secret::Scalar(stored))
        }
        Kind::Ed25519 | Kind::Ed448 => {
            let name = if matches!(kind, Kind::Ed448) { "ed448" } else { "ed25519" };
            let (seed, point) = api::eddsa_generate(name)?;
            public.extend(point);
            (if name == "ed448" { keys::ED448 } else { keys::ED25519 }, Secret::Native(seed))
        }
        Kind::X25519 => {
            let mut secret = vec![0u8; 32];
            random(&mut secret)?;
            public.extend(api::x25519_public_key(&secret)?);
            (keys::X25519, Secret::Native(secret))
        }
        Kind::X448 => {
            let mut secret = vec![0u8; 56];
            random(&mut secret)?;
            public.extend(api::x448_public_key(&secret)?);
            (keys::X448, Secret::Native(secret))
        }
    };
    Ok((algorithm, public, secret))
}

/// RFC 9580 table 30's KDF hash and key wrap cipher for a field size.
fn ecdh_kdf(field: usize) -> [u8; 4] {
    match field {
        48 => [3, 1, 9, 8],
        64 | 66 => [3, 1, 10, 9],
        _ => [3, 1, 8, 7],
    }
}

fn public_key(version: u8, created: u32, algorithm: u8, material: &[u8])
              -> Result<PublicKey, String> {
    let mut body = vec![version];
    body.extend_from_slice(&created.to_be_bytes());
    body.push(algorithm);
    if version == 6 {
        body.extend_from_slice(&(material.len() as u32).to_be_bytes());
    }
    body.extend_from_slice(material);
    let (key, used) = PublicKey::read(&body)?;
    debug_assert_eq!(used, body.len());
    Ok(key)
}

/// The preferences a self-signature states: ciphers, hashes,
/// compression, features (SEIPD v1 and, for version 6, v2) and AEAD
/// ciphersuites.
fn preferences(v6: bool) -> Vec<Subpacket> {
    let mut out = vec![Subpacket::new(11, &[9, 8, 7]), Subpacket::new(21, &[10, 9, 8]),
                       Subpacket::new(22, &[2, 1, 0]),
                       Subpacket::new(30, &[if v6 { 0x09 } else { 0x01 }])];
    if v6 {
        out.push(Subpacket::new(39, &[9, 2, 9, 1, 7, 2]));
    }
    out
}

/// A new transferable secret key and its public half, as packet
/// sequences.
pub struct Generated {
    pub secret: Vec<u8>,
    pub public: Vec<u8>,
    pub fingerprint: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn generate(plan: &Plan, v6: bool, user_id: &str, passphrase: &[u8], created: u32,
                expires_days: Option<u32>, s2k: S2k, random: Random<'_>)
                -> Result<Generated, String> {
    let version = if v6 { 6 } else { 4 };
    let (algorithm, material_bytes, primary_secret) = material(plan.primary, random)?;
    let primary = public_key(version, created, algorithm, &material_bytes)?;
    crate::pubkey::check_pair(&primary, &primary_secret)?;
    let (sub_algorithm, sub_bytes, sub_secret) = material(plan.subkey, random)?;
    let subkey = public_key(version, created, sub_algorithm, &sub_bytes)?;
    crate::pubkey::check_pair(&subkey, &sub_secret)?;
    let hash = algo::hash(match primary.curve().map(|c| c.field) {
        Some(48) => 9,
        Some(64 | 66) => 10,
        _ if algorithm == keys::ED448 => 10,
        _ => 8,
    })?;
    let expiry = expires_days.map(|d| Subpacket::new(sig::KEY_EXPIRATION,
                                                     &(d * 86400).to_be_bytes()));

    let uid = packet::Packet { tag: packet::USER_ID, body: user_id.as_bytes().to_vec(),
                               legacy: false, partial: false };
    let certify = |sig_type: u8, flags: u8, with_preferences: bool, extra: Vec<Subpacket>,
                       feed: &dyn Fn(&mut allcrypt::api::AnyHash), random: Random<'_>|
                       -> Result<Vec<u8>, String> {
        let (mut hashed, unhashed) = sig::standard_subpackets(&primary, created);
        hashed.push(Subpacket::new(sig::KEY_FLAGS, &[flags]));
        if with_preferences {
            hashed.extend(preferences(v6));
        }
        hashed.extend(expiry.iter().cloned());
        hashed.extend(extra);
        sig::make(&primary, &primary_secret, sig_type, hash, hashed, unhashed, None, feed, random)
    };

    let mut public = Vec::new();
    let mut secret = Vec::new();
    let primary_tag = SecretKey::write(&primary, &primary_secret, packet::SECRET_KEY, passphrase,
                                       s2k.clone(), random)?;
    secret.extend(packet::write(packet::SECRET_KEY, &primary_tag));
    public.extend(packet::write(packet::PUBLIC_KEY, &primary.body));
    let both = |p: Vec<u8>, public: &mut Vec<u8>, secret: &mut Vec<u8>| {
        public.extend(&p);
        secret.extend(p);
    };

    if v6 {
        // A version 6 key's flags and preferences live on a direct key
        // signature over the primary key alone.
        let direct = certify(sig::DIRECT_KEY, 0x03, true, Vec::new(),
                             &|h| sig::hash_key(h, &primary), random)?;
        both(packet::write(packet::SIGNATURE, &direct), &mut public, &mut secret);
    }
    let uid_feed = |h: &mut allcrypt::api::AnyHash| {
        sig::hash_key(h, &primary);
        sig::hash_user_id(h, &uid, version);
    };
    let certification = certify(0x13, 0x03, !v6, vec![Subpacket::new(sig::PRIMARY_USER_ID, &[1])],
                                &uid_feed, random)?;
    both(packet::write(packet::USER_ID, &uid.body), &mut public, &mut secret);
    both(packet::write(packet::SIGNATURE, &certification), &mut public, &mut secret);

    let binding_feed = |h: &mut allcrypt::api::AnyHash| {
        sig::hash_key(h, &primary);
        sig::hash_key(h, &subkey);
    };
    let (mut hashed, unhashed) = sig::standard_subpackets(&primary, created);
    hashed.push(Subpacket::new(sig::KEY_FLAGS, &[sig::FLAG_ENCRYPT]));
    hashed.extend(expiry.iter().cloned());
    let binding = sig::make(&primary, &primary_secret, sig::SUBKEY_BINDING, hash, hashed,
                            unhashed, None, &binding_feed, random)?;
    let sub_tag = SecretKey::write(&subkey, &sub_secret, packet::SECRET_SUBKEY, passphrase, s2k,
                                   random)?;
    secret.extend(packet::write(packet::SECRET_SUBKEY, &sub_tag));
    public.extend(packet::write(packet::PUBLIC_SUBKEY, &subkey.body));
    both(packet::write(packet::SIGNATURE, &binding), &mut public, &mut secret);
    Ok(Generated { secret, public, fingerprint: primary.fingerprint() })
}
