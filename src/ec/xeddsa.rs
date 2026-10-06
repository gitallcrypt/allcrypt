/*
XEdDSA: Ed25519 signatures made with an X25519 key.

Signal's identity key is a single Curve25519 key that both agrees keys
(X3DH, as X25519) and signs (the signed prekey, and group messages). A
Montgomery key carries only `u`, so the Edwards point it signs as has to
be reconstructed: `y = (u - 1) / (u + 1)`, and `x` is one of two roots.
Which root is the whole problem, and the two forms here are the two
answers that are in use.

## The two forms

**`Form::Signal`** is what libsignal signs with - `curve25519_sign` in
libsignal-protocol-c and `calculate_signature` in the Rust libsignal.
The signer computes `A = kB` and stores A's sign bit in the top bit of
`S`, which is always zero in a reduced scalar (`S < L < 2^253`). The
verifier takes the bit back out of the signature and puts it on the
point. Every key signs as itself.

**`Form::Specification`** is the XEdDSA document's (signal.org,
revision 1, 2016-10-20): the Edwards key always has sign bit zero, and a
signer whose `kB` has sign bit one signs with `-k` instead, whose point
is the mirror image. Nothing is stored in `S`.

A specification signature verifies under the Signal verifier - its top
bit is zero, which is the sign the specification forces. The converse
holds only for keys whose `kB` happens to have sign bit zero: for half of
all keys a Signal signature fails the specification verifier, because
its `S` has bit 255 set and `S < 2^253` is checked first. Both
directions are rows in `scripts/check_signal.py`.

## Where this follows libsignal rather than the document

**The nonce hashes the clamped key bytes, not `k mod L`.** The
document's `calculate_key_pair` reduces `a`, and `hash1(a || M || Z)`
then hashes the reduced value. libsignal-protocol-c's `xed25519_sign`
negates with `sc_neg` (which reduces) but otherwise passes the 32
clamped bytes through unchanged, and `curve25519_sign` never reduces.
`r` only has to be secret and different per message, so both give valid
signatures - but only libsignal's choice gives *its* bytes, and a byte
comparison against it is the only check of the arithmetic here that is
independent of this file. This file follows libsignal in both forms.

**`S` is checked against `2^253`, not `L`.** Both libsignal
implementations reject `S` with any of its top three bits set and
otherwise use it unreduced, so `S + L` verifies wherever `S` does. RFC
8032 requires `S < L` for Ed25519 and `eddsa::verify` enforces it; the
XEdDSA document says `s >= 2^|q|`, which is the same bound libsignal
uses. This module accepts what libsignal accepts, and a test pins that
`S + L` verifies, so the leniency is recorded rather than accidental.
The consequence is malleability: a third party can turn one valid
signature into a second. It forges nothing.

**`R` is compared as bytes.** The check is `encode(sB - hA) == R`, so an
`R` that decodes to the right point from a non-canonical encoding is
refused. Comparing points instead would accept it.

## The key

The private key is clamped before use, exactly as X25519 clamps it, so
the key that signs is the key `x25519::public_key` describes. A
libsignal private key is stored clamped already, which makes this a
no-op there; an unclamped one would otherwise sign as a different point
from the public key everyone has.

The public key's `u` follows each implementation's reading. The Signal
form masks bit 255 and reduces modulo `p`, as `fe_frombytes` does; the
specification form refuses a `u` that is not already reduced, as its
document and `xed25519_verify` both do.

Signing is constant time: the scalar multiplications are
`ec::edwards`'s, the arithmetic mod L is `eddsa::Order`'s, and the
specification form's choice between the key and its negation - which
depends on the sign of the secret point's `x` - is a mask rather than a
branch. The Signal form publishes that sign bit in `S` by design.
*/

use crate::bignum::ct::{mask_is_nonzero, select};
use crate::bignum::Secret;
use crate::ec::eddsa::{self, Order, Variant};
use crate::ec::edwards;
use crate::ec::field25519::Fe;
use crate::ec::x25519;
use crate::hash_functions::{sha2, HashFunction};

/// Which way the sign of the Edwards key is settled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// libsignal's: the sign bit travels in the top bit of `S`.
    Signal,
    /// The XEdDSA document's: the sign bit is always zero, and a key
    /// whose point is negative signs with its negation.
    Specification,
}

impl Form {
    pub fn name(self) -> &'static str {
        match self {
            Form::Signal => "signal",
            Form::Specification => "xeddsa",
        }
    }

    /// The form by the name `name()` gives it.
    ///
    /// # Errors
    /// Any other name.
    pub fn by_name(name: &str) -> Result<Form, String> {
        match name.to_ascii_lowercase().as_str() {
            "signal" => Ok(Form::Signal),
            "xeddsa" => Ok(Form::Specification),
            other => Err(format!(
                "{} is not an XEdDSA form. Try signal (libsignal's, the sign bit \
                 in S) or xeddsa (the specification's, the sign bit zero).",
                other
            )),
        }
    }
}

const SIGNATURE_LEN: usize = 64;

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = sha2::SHA512::new(&[], 512);
    for part in parts {
        hash.update(part);
    }
    hash.digest()
}

/// `hash_1`: SHA-512 behind the prefix `FE FF .. FF`, 32 bytes.
///
/// The prefix is `2^256 - 2` little endian, which no encoded point can
/// begin with, so a nonce hash can never be confused with the
/// challenge hash `SHA-512(R || A || M)`.
fn nonce(order: &Order, key: &[u8], message: &[u8], random: &[u8; 64])
         -> Result<Secret, String> {
    let mut prefix = [0xffu8; 32];
    prefix[0] = 0xfe;
    order.reduce(&sha512(&[&prefix, key, message, random]))
}

/// Sign `message` with an X25519 private key.
///
/// `random` is the 64 bytes `Z` that both forms mix into the nonce.
/// The scheme stays sound if it repeats - the nonce also hashes the key
/// and the message - but a fresh one per signature is what libsignal
/// does and what the specification asks for.
pub fn sign(form: Form, private: &[u8; 32], message: &[u8], random: &[u8; 64]) -> [u8; 64] {
    // The only failures are in setting up arithmetic mod L, whose
    // modulus is a constant; a zero signature verifies against nothing.
    signature(form, private, message, random).unwrap_or([0u8; SIGNATURE_LEN])
}

fn signature(form: Form, private: &[u8; 32], message: &[u8], random: &[u8; 64])
             -> Result<[u8; 64], String> {
    let order = eddsa::order(Variant::Ed25519)?;
    let clamped = x25519::clamp(private);
    let mut public = eddsa::base_multiple(Variant::Ed25519, &clamped);
    let sign_bit = public[31] & 0x80;

    // The scalar, and the 32 bytes that go into the nonce, as
    // libsignal-protocol-c computes them: the clamped key as it stands,
    // or (specification form, negative point) its negation reduced
    // modulo L. Which one is the sign of the secret point's x, so both
    // are computed and one kept by a mask.
    let k = order.reduce(&clamped)?;
    let (scalar, scalar_bytes) = match form {
        Form::Signal => (k, clamped.to_vec()),
        Form::Specification => {
            public[31] &= 0x7f;
            let negative = mask_is_nonzero(u64::from(sign_bit));
            let negated = order.negate(&k);
            let negated_bytes = order.encode(&negated, 32);
            let bytes = clamped.iter().zip(&negated_bytes)
                .map(|(&kept, &other)| select(u64::from(other), u64::from(kept), negative) as u8)
                .collect();
            (Secret::select(&negated, &k, negative), bytes)
        }
    };

    let r = nonce(order, &scalar_bytes, message, random)?;
    let big_r = eddsa::base_multiple(Variant::Ed25519, &order.encode(&r, 32));
    let h = order.reduce(&sha512(&[&big_r, &public, message]))?;
    let s = order.mul_add(&h, &scalar, &r);

    let mut signature = [0u8; SIGNATURE_LEN];
    signature[..32].copy_from_slice(&big_r);
    signature[32..].copy_from_slice(&order.encode(&s, 32));
    if form == Form::Signal {
        signature[63] = (signature[63] & 0x7f) | sign_bit;
    }
    Ok(signature)
}

/// A point from `y` and a sign bit, the way ref10's decoder reads it:
/// `x = 0` with the sign bit set is `(0, y)` rather than a refusal.
///
/// RFC 8032 refuses that encoding and `edwards::Curve::decode` follows
/// it. Here the encoding was not received but built from `u` and a bit
/// the signature carries, and libsignal accepts it, so this does. Strict
/// decoding refuses a `y` with a set sign bit only when the `y` is on no
/// point or when `x = 0`, and the same `y` with the bit clear decodes
/// only in the second case - so retrying without the bit accepts exactly
/// that one.
fn decode_lenient(curve: &edwards::Curve<Fe>, bytes: &[u8; 32]) -> Option<edwards::Point<Fe>> {
    let mut cleared = *bytes;
    cleared[31] &= 0x7f;
    curve.decode(bytes).or_else(|| curve.decode(&cleared))
}

/// Whether `bytes`, little endian, is below `2^255 - 19`: whether it
/// survives decoding and canonical re-encoding unchanged. That covers
/// bit 255 too, which `from_bytes` drops and `to_bytes` never sets.
fn is_reduced(bytes: &[u8; 32]) -> bool {
    Fe::from_bytes(bytes).to_bytes() == *bytes
}

/// Verify a signature against an X25519 public key.
///
/// # Errors
/// Anything other than a valid signature: a `u` the form refuses, an
/// `S` with any of its top three bits set, a key that is not a point,
/// or a signature that does not verify. Each says which.
pub fn verify(form: Form, public: &[u8; 32], message: &[u8], signature: &[u8; 64])
              -> Result<(), String> {
    let curve = edwards::ed25519();

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    // `Fe::from_bytes` masks bit 255 and reduces modulo p, which is the
    // Signal form's reading of u; the specification's refuses instead.
    match form {
        Form::Signal => s_bytes[31] &= 0x7f,
        Form::Specification => {
            if !is_reduced(public) {
                return Err("The public key's u is not reduced modulo p, which the \
                            XEdDSA specification refuses."
                    .to_string());
            }
        }
    }
    if s_bytes[31] & 0xe0 != 0 {
        return Err("The signature's S is not below 2^253.".to_string());
    }

    let mut edwards = [0u8; 32];
    edwards.copy_from_slice(&curve.edwards_y(public));
    if form == Form::Signal {
        edwards[31] |= signature[63] & 0x80;
    }
    let a = decode_lenient(curve, &edwards)
        .ok_or_else(|| "The public key is not the u of a point on the curve.".to_string())?;

    let big_r = &signature[..32];
    let order = eddsa::order(Variant::Ed25519)?;
    let h = order.encode(&order.reduce(&sha512(&[big_r, &edwards, message]))?, 32);
    // S*B - h*A, encoded and compared with R as bytes: a non-canonical
    // R that names the right point is refused.
    let check = curve.multiply_two(&s_bytes, &curve.base(), &h, &curve.negate(&a));
    if curve.encode(&check) == big_r {
        Ok(())
    } else {
        Err("The signature does not verify.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::BigUint;
    use crate::ec::eddsa::reference::{self as bignum, Curve};

    fn le_to_int(bytes: &[u8]) -> BigUint {
        let mut big_endian = bytes.to_vec();
        big_endian.reverse();
        BigUint::from_bytes_be(&big_endian)
    }

    fn key(byte: u8) -> [u8; 32] {
        x25519::clamp(&[byte; 32])
    }

    /// A key whose `kB` has the given sign, found by search rather than
    /// assumed, so both branches of the specification's negation run.
    fn key_with_sign(negative: bool) -> [u8; 32] {
        let curve = Curve::new(Variant::Ed25519);
        for byte in 1..=255u8 {
            let k = key(byte);
            let point = bignum::multiply(&curve, &le_to_int(&k), &bignum::base(&curve));
            if (bignum::encode(&curve, &point)[31] & 0x80 != 0) == negative {
                return k;
            }
        }
        panic!("no key of that sign among 255 candidates");
    }

    fn public(private: &[u8; 32]) -> [u8; 32] {
        x25519::public_key(private).unwrap()
    }

    #[test]
    fn test_each_form_verifies_its_own_signatures_for_both_signs() {
        for negative in [false, true] {
            let private = key_with_sign(negative);
            for form in [Form::Signal, Form::Specification] {
                let signature = sign(form, &private, b"message", &[7u8; 64]);
                assert_eq!(verify(form, &public(&private), b"message", &signature), Ok(()),
                           "{:?}, negative = {}", form, negative);
                assert!(verify(form, &public(&private), b"messagf", &signature).is_err());
            }
        }
    }

    #[test]
    fn test_the_signal_form_carries_the_sign_bit_in_s() {
        let negative = key_with_sign(true);
        let positive = key_with_sign(false);
        assert_eq!(sign(Form::Signal, &negative, b"m", &[1; 64])[63] & 0x80, 0x80);
        assert_eq!(sign(Form::Signal, &positive, b"m", &[1; 64])[63] & 0x80, 0);
        // The specification never sets it.
        assert_eq!(sign(Form::Specification, &negative, b"m", &[1; 64])[63] & 0x80, 0);
    }

    /// The asymmetry in the module comment: a specification signature
    /// verifies under the Signal verifier for every key, and a Signal
    /// signature under the specification's only when the key's point
    /// is positive - for which the two forms sign identically.
    #[test]
    fn test_which_forms_verify_under_which_verifier() {
        for negative in [false, true] {
            let private = key_with_sign(negative);
            let specification = sign(Form::Specification, &private, b"m", &[2; 64]);
            assert_eq!(verify(Form::Signal, &public(&private), b"m", &specification), Ok(()));
            let signal = sign(Form::Signal, &private, b"m", &[2; 64]);
            assert_eq!(verify(Form::Specification, &public(&private), b"m", &signal).is_ok(),
                       !negative);
            assert_eq!(signal == specification, !negative);
        }
    }

    #[test]
    fn test_the_random_input_changes_the_signature_and_not_its_validity() {
        let private = key(9);
        let one = sign(Form::Signal, &private, b"m", &[0; 64]);
        let two = sign(Form::Signal, &private, b"m", &[1; 64]);
        assert_ne!(one, two);
        assert_eq!(verify(Form::Signal, &public(&private), b"m", &two), Ok(()));
    }

    /// The key is clamped before signing, so an unclamped key signs as
    /// the point its X25519 public key names.
    #[test]
    fn test_an_unclamped_key_signs_as_its_clamped_self() {
        let unclamped = [0xffu8; 32];
        let signature = sign(Form::Signal, &unclamped, b"m", &[3; 64]);
        assert_eq!(signature, sign(Form::Signal, &x25519::clamp(&unclamped), b"m", &[3; 64]));
        assert_eq!(verify(Form::Signal, &public(&unclamped), b"m", &signature), Ok(()));
    }

    /// libsignal accepts `S + L` wherever it accepts `S`, because it
    /// checks only the top three bits; so does this, deliberately.
    #[test]
    fn test_s_plus_l_verifies_and_s_above_2_to_253_does_not() {
        let curve = Curve::new(Variant::Ed25519);
        let private = key_with_sign(false);
        let signature = sign(Form::Signal, &private, b"m", &[4; 64]);
        let s = le_to_int(&signature[32..]);
        let mut malleated = signature;
        malleated[32..].copy_from_slice(&bignum::encode_scalar(&curve, &s.add(&curve.order)));
        assert_eq!(verify(Form::Signal, &public(&private), b"m", &malleated), Ok(()));
        assert_eq!(verify(Form::Specification, &public(&private), b"m", &malleated), Ok(()));

        let mut high = signature;
        high[63] |= 0x20;
        assert_eq!(verify(Form::Signal, &public(&private), b"m", &high),
                   Err("The signature's S is not below 2^253.".to_string()));
    }

    /// The two forms read `u` differently: the Signal form masks bit
    /// 255 as `fe_frombytes` does, the specification refuses it.
    #[test]
    fn test_the_top_bit_of_u_is_masked_by_one_form_and_refused_by_the_other() {
        let private = key_with_sign(false);
        let signature = sign(Form::Specification, &private, b"m", &[5; 64]);
        let mut flagged = public(&private);
        flagged[31] |= 0x80;
        assert_eq!(verify(Form::Signal, &flagged, b"m", &signature), Ok(()));
        assert!(verify(Form::Specification, &flagged, b"m", &signature)
            .unwrap_err()
            .contains("not reduced"));
    }

    /// A flipped bit in any byte of R or S is refused: one bit per
    /// byte, walking the bit position so all eight are used. Bits 253
    /// and 254 of S fail the range check and 255 is the sign bit, which
    /// moves the key instead - each a different refusal.
    #[test]
    fn test_every_byte_of_the_signature_matters() {
        let private = key(11);
        let signature = sign(Form::Signal, &private, b"message", &[6; 64]);
        let public = public(&private);
        for byte in 0..64 {
            let bit = byte * 8 + byte % 8;
            let mut flipped = signature;
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert!(verify(Form::Signal, &public, b"message", &flipped).is_err(), "bit {}", bit);
        }
    }

    /// `x = 0` with the sign bit set is refused by RFC 8032 decoding and
    /// accepted here, as ref10 accepts it; any other point that fails
    /// strict decoding is still refused.
    #[test]
    fn test_x_zero_with_the_sign_bit_decodes_leniently() {
        let curve = edwards::ed25519();
        // y = -1: the point (0, -1).
        let mut minus_one = [0xffu8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0xff; // y = p - 1 with the sign bit set
        assert!(curve.decode(&minus_one).is_none());
        assert!(decode_lenient(curve, &minus_one).is_some());
        // y = 2 is on no point, with or without the bit.
        let mut two = [0u8; 32];
        two[0] = 2;
        two[31] = 0x80;
        assert!(decode_lenient(curve, &two).is_none());
    }

    #[test]
    fn test_the_form_names_round_trip() {
        for form in [Form::Signal, Form::Specification] {
            assert_eq!(Form::by_name(form.name()), Ok(form));
        }
        assert!(Form::by_name("vxeddsa").is_err());
    }
}
