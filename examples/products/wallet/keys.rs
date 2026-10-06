//! secp256k1 keys and the recoverable signatures Bitcoin's and Ethereum's
//! signed messages carry.

use std::sync::OnceLock;

use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, Curve, Point};
use allcrypt::hash_functions::sha2::SHA256;

pub fn curve() -> &'static Curve {
    static CURVE: OnceLock<Curve> = OnceLock::new();
    CURVE.get_or_init(|| curves::by_name("secp256k1").expect("secp256k1 is built in"))
}

/// k * G, through the constant-time ladder: k is a private key.
pub fn public_key(k: &BigUint) -> Point {
    curve().scalar_mul_ct(&curve().g, k)
}

/// The compressed SEC1 encoding, BIP-32's serP.
pub fn ser_p(point: &Point) -> Vec<u8> {
    curve().encode_point(point, true).expect("a point on the curve")
}

pub fn uncompressed(point: &Point) -> Vec<u8> {
    curve().encode_point(point, false).expect("a point on the curve")
}

/// A private key from 32 bytes, refusing 0 and anything not below n.
pub fn private_from_bytes(bytes: &[u8]) -> Result<BigUint, String> {
    if bytes.len() != 32 {
        return Err(format!("A secp256k1 private key is 32 bytes, not {}.", bytes.len()));
    }
    let k = BigUint::from_bytes_be(bytes);
    if k.is_zero() || k >= curve().n {
        return Err("The private key is not in [1, n).".to_string());
    }
    Ok(k)
}

pub fn private_bytes(k: &BigUint) -> Vec<u8> {
    k.to_bytes_be_padded(32).expect("below n")
}

/// A signature with its recovery id: (r, s), s in the lower half of the
/// group as Bitcoin Core and Ethereum (EIP-2) require, and which of the
/// four candidate points R was - bit 0 its y parity, bit 1 whether its x
/// was r + n.
pub struct Recoverable {
    pub r: BigUint,
    pub s: BigUint,
    pub recid: u8,
}

/// Sign a 32-byte digest with RFC 6979's deterministic nonce (HMAC-SHA256,
/// as libsecp256k1 uses), then normalize s and find the recovery id by
/// recovering each candidate key.
pub fn sign_recoverable(k: &BigUint, digest: &[u8]) -> Result<Recoverable, String> {
    let c = curve();
    let sig = c.sign(k, digest, SHA256::new(&[]))?;
    let half = c.n.shr(1);
    let s = if sig.s > half { c.n.sub(&sig.s)? } else { sig.s };
    let public = public_key(k);
    for recid in 0..4 {
        if let Ok(q) = recover(&sig.r, &s, recid, digest) {
            if q == public {
                return Ok(Recoverable { r: sig.r, s, recid });
            }
        }
    }
    Err("No recovery id reproduces the key.".to_string())
}

/// The public key a signature was made with: Q = r^-1 (sR - eG), where R
/// is the point the recovery id names.
pub fn recover(r: &BigUint, s: &BigUint, recid: u8, digest: &[u8]) -> Result<Point, String> {
    let c = curve();
    if r.is_zero() || *r >= c.n || s.is_zero() || *s >= c.n || recid > 3 {
        return Err("A signature value out of range.".to_string());
    }
    let x = if recid & 2 != 0 { r.add(&c.n) } else { r.clone() };
    if x >= c.p {
        return Err("The recovery id names an x beyond the field.".to_string());
    }
    let mut encoded = vec![2 | (recid & 1)];
    encoded.extend(x.to_bytes_be_padded(32)?);
    let big_r = c.decode_point(&encoded)?;
    let e = BigUint::from_bytes_be(digest).rem(&c.n)?;
    let r_inv = r.mod_inverse_prime(&c.n)?;
    let s_r = c.scalar_mul(&big_r, s);
    let e_g = c.generator_mul(&e);
    let q = c.scalar_mul(&c.add(&s_r, &c.negate(&e_g)), &r_inv);
    if q.is_identity() {
        return Err("The signature recovers no key.".to_string());
    }
    Ok(q)
}
