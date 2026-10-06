/*
GOST R 34.10-2012 signatures.

Close enough to ECDSA to be mistaken for it and different in four places,
every one of which is silent:

  * **The digest is read little endian.** GOST writes hash values as
    numbers with the most significant byte on the left, while Streebog -
    like every implementation of it - emits a byte string in the other
    order. So the integer is `int_le(digest)`, which is what OpenSSL's
    GOST engine does (`BN_lebin2bn`) and what makes the two conventions
    cancel out. Reading it big endian gives signatures that verify
    against themselves and against nothing else.

  * **The signing equation has no inverse in it.** ECDSA computes
    `s = k^-1 (e + r d)`; this computes `s = r d + k e`, with the
    multiplication by `e` on the nonce rather than an inversion. That is
    why verification needs `e^-1` where ECDSA needs `s^-1`.

  * **The wire order is `s || r`**, not `r || s`. CryptoPro packs them
    that way and so does every GOST container; ECDSA packs the other.
    Two fixed-width integers of the same size swapped is a signature that
    is the right length, parses cleanly and verifies against nothing.

  * **The width comes from the group order**, not the field. They happen
    to match on every curve here, and writing the one that happens to be
    right is how it stops being right on the next curve.

The nonce is **not** taken from the random source. GOST R 34.10 says to
generate `k` randomly and does not standardise a deterministic scheme,
but the failure mode is identical to ECDSA's - two signatures sharing a
nonce hand over the private key in four modular operations - so the RFC
6979 generator already in `ecdsa.rs` is used here instead. That is a
deliberate deviation: the signatures are still valid GOST signatures and
any verifier accepts them, but they are reproducible, which also makes
them testable. Nothing in this file calls `random`.

The verification side is the standard's exactly, so a signature produced
by anybody - deterministic nonce or not - verifies here.
*/

use super::{Curve, Point};
use crate::bignum::BigUint;
use crate::ec::ecdsa::{NonceGenerator, Signature};
use crate::hash_functions::HashFunction;

impl Curve {
    /// How wide each half of a GOST signature is.
    ///
    /// From the **group order**, not the field. Those are the same on
    /// every curve here and are not the same thing.
    pub fn gost_component_bytes(&self) -> usize {
        self.scalar_bytes()
    }

    /// The digest as GOST reads it: a little endian integer, reduced
    /// modulo the group order, with zero replaced by one.
    ///
    /// The zero case is in the standard and is not a rounding of it: an
    /// `e` of zero makes `s = r*d`, which leaks the private key from one
    /// signature.
    fn gost_digest(&self, digest: &[u8]) -> Result<BigUint, String> {
        let mut reversed = digest.to_vec();
        reversed.reverse();
        let e = BigUint::from_bytes_be(&reversed).rem(&self.n)?;
        Ok(if e.is_zero() { BigUint::one() } else { e })
    }

    /// Sign a digest under GOST R 34.10-2012.
    ///
    /// `hash` must be a fresh, empty hash of the algorithm that produced
    /// `digest` - it drives the RFC 6979 nonce chain. See the note at the
    /// top about why the nonce is derived rather than drawn.
    pub fn gost_sign<H: HashFunction + Clone>(&self, private: &BigUint,
                                              digest: &[u8], hash: H)
                                              -> Result<Signature, String> {
        if private.is_zero() || *private >= self.n {
            return Err("Private scalar is not in [1, n).".to_string());
        }
        let e = self.gost_digest(digest)?;
        let mut nonces = NonceGenerator::new(hash, private, digest, &self.n)?;

        for _ in 0..1000 {
            let k = nonces.next();
            if k.is_zero() || k >= self.n {
                continue;
            }

            // The nonce is secret, so this is the constant-time path.
            let point = self.scalar_mul_ct(&self.g, &k);
            if point.is_identity() {
                continue;
            }
            let r = point.x()
                .ok_or("the identity has no x coordinate")?
                .rem(&self.n)?;
            if r.is_zero() {
                continue;
            }

            // s = r*d + k*e mod n. No inversion: that is the whole
            // difference from ECDSA's signing equation.
            let s = r.mod_mul(private, &self.n)?
                .mod_add(&k.mod_mul(&e, &self.n)?, &self.n)?;
            if s.is_zero() {
                continue;
            }
            return Ok(Signature { r, s });
        }
        Err("Could not find a usable nonce in a thousand tries, which should \
             not be possible and means something above is wrong.".to_string())
    }

    /// Verify a GOST R 34.10-2012 signature.
    pub fn gost_verify(&self, public: &Point, digest: &[u8],
                       signature: &Signature) -> Result<bool, String> {
        // The public key has to be a real point of the right order, and
        // checking that is not optional: an invalid-curve point makes the
        // arithmetic below happen in a group the attacker chose.
        self.validate(public)?;

        // Both components must be in (0, n). Zero or n is not a small
        // detail - r = 0 makes the check below independent of the key.
        if signature.r.is_zero() || signature.r >= self.n
            || signature.s.is_zero() || signature.s >= self.n {
            return Ok(false);
        }

        let e = self.gost_digest(digest)?;
        let v = e.mod_inverse(&self.n)?;
        let z1 = signature.s.mod_mul(&v, &self.n)?;
        // z2 = -r * v mod n, written as (n - r) * v so the subtraction
        // stays inside the unsigned type.
        let z2 = self.n.sub(&signature.r)?.mod_mul(&v, &self.n)?;

        // Everything here is public, so double-and-add is fine.
        let point = self.add(&self.scalar_mul(&self.g, &z1),
                             &self.scalar_mul(public, &z2));
        if point.is_identity() {
            return Ok(false);
        }
        let x = point.x().ok_or("the identity has no x coordinate")?;
        Ok(x.rem(&self.n)? == signature.r)
    }

    /// `s || r`, each padded to the group order's width.
    ///
    /// **`s` first.** CryptoPro packs it that way and so does every GOST
    /// container; ECDSA packs `r || s`. Two integers of the same width
    /// swapped gives a signature of the right length that parses cleanly
    /// and verifies against nothing.
    pub fn gost_signature_bytes(&self, signature: &Signature)
                                -> Result<Vec<u8>, String> {
        let width = self.gost_component_bytes();
        let mut out = signature.s.to_bytes_be_padded(width)?;
        out.extend_from_slice(&signature.r.to_bytes_be_padded(width)?);
        Ok(out)
    }

    /// The inverse. Refuses a wrong length rather than guessing where the
    /// split is.
    pub fn gost_signature_from_bytes(&self, bytes: &[u8])
                                     -> Result<Signature, String> {
        let width = self.gost_component_bytes();
        if bytes.len() != 2 * width {
            return Err(format!(
                "A GOST signature on {} is {} bytes, got {}.",
                self.name, 2 * width, bytes.len()));
        }
        Ok(Signature {
            s: BigUint::from_bytes_be(&bytes[..width]),
            r: BigUint::from_bytes_be(&bytes[width..]),
        })
    }

    /// **RFC 9367's encoding, which is not the one above.**
    ///
    /// Section 5.3 writes the TLS 1.3 CertificateVerify signature as
    /// `sgn = str_l(r) | str_l(s)`,
    /// and `str_l` is the **little endian** one (RFC 9189 section 3
    /// defines `STR_n` big endian and `str_n` little endian, and both
    /// documents use both). So it differs from RFC 9215's certificate
    /// encoding in *two* ways at once: the components are the other way
    /// round **and** each is reversed.
    ///
    /// Two wrongs here do not make a right and they are not
    /// independent: swapping only the order, or reversing only the
    /// bytes, each produces a signature of exactly the right length
    /// that verifies against nothing. Two implementations making the
    /// same mistake would interoperate, which is why the only thing
    /// that settles this is the worked example in RFC 9367 appendix A -
    /// `tests/test_rfc9367_flight.rs` verifies the document's own `sgn`
    /// against the document's own certificate.
    pub fn gost_signature_bytes_13(&self, signature: &Signature)
                                   -> Result<Vec<u8>, String> {
        let width = self.gost_component_bytes();
        let mut out = signature.r.to_bytes_be_padded(width)?;
        out.reverse();
        let mut tail = signature.s.to_bytes_be_padded(width)?;
        tail.reverse();
        out.extend_from_slice(&tail);
        Ok(out)
    }

    /// The inverse of `gost_signature_bytes_13`.
    pub fn gost_signature_from_bytes_13(&self, bytes: &[u8])
                                        -> Result<Signature, String> {
        let width = self.gost_component_bytes();
        if bytes.len() != 2 * width {
            return Err(format!(
                "An RFC 9367 signature on {} is {} bytes, got {}.",
                self.name, 2 * width, bytes.len()));
        }
        let mut r = bytes[..width].to_vec();
        r.reverse();
        let mut s = bytes[width..].to_vec();
        s.reverse();
        Ok(Signature {
            r: BigUint::from_bytes_be(&r),
            s: BigUint::from_bytes_be(&s),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves;
    use crate::hash_functions::streebog::Streebog;

    fn key(curve: &Curve, seed: u8) -> (BigUint, Point) {
        let mut bytes = vec![seed; curve.gost_component_bytes()];
        bytes[0] &= 0x3f;                       // keep it below n
        let private = BigUint::from_bytes_be(&bytes);
        let public = curve.scalar_mul(&curve.g, &private);
        (private, public)
    }

    fn digest_of(message: &[u8], bits: usize) -> Vec<u8> {
        use crate::hash_functions::HashFunction;
        if bits == 256 {
            Streebog::new_256(message).digest()
        } else {
            Streebog::new(message).digest()
        }
    }

    fn fresh(bits: usize) -> Streebog {
        if bits == 256 { Streebog::new_256(&[]) } else { Streebog::new(&[]) }
    }

    /// Sign and verify on every GOST curve, at both digest sizes.
    #[test]
    fn test_sign_and_verify() {
        for name in curves::gost_names() {
            let curve = curves::by_name(name).unwrap();
            for bits in [256usize, 512] {
                let (private, public) = key(&curve, 0x5b);
                let digest = digest_of(b"a message", bits);
                let signature = curve.gost_sign(&private, &digest, fresh(bits))
                    .unwrap();
                assert!(curve.gost_verify(&public, &digest, &signature).unwrap(),
                        "{} with a {} bit digest", name, bits);
            }
        }
    }

    /// The nonce is derived, so signing twice gives the same signature.
    /// That is deliberate - see the note at the top - and it is also what
    /// makes these testable.
    #[test]
    fn test_signatures_are_reproducible() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (private, _) = key(&curve, 0x11);
        let digest = digest_of(b"twice", 256);
        let first = curve.gost_sign(&private, &digest, fresh(256)).unwrap();
        let second = curve.gost_sign(&private, &digest, fresh(256)).unwrap();
        assert_eq!(first, second);

        // And a different message gives a different nonce, so a different r.
        let other = curve.gost_sign(&private, &digest_of(b"once", 256),
                                    fresh(256)).unwrap();
        assert_ne!(first.r, other.r, "the nonce did not depend on the message");
    }

    /// Every part of the input must matter.
    #[test]
    fn test_verification_rejects_tampering() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (private, public) = key(&curve, 0x22);
        let digest = digest_of(b"authentic", 256);
        let signature = curve.gost_sign(&private, &digest, fresh(256)).unwrap();
        assert!(curve.gost_verify(&public, &digest, &signature).unwrap());

        // A different digest.
        assert!(!curve.gost_verify(&public, &digest_of(b"forged", 256), &signature)
                .unwrap());
        // A different key.
        let (_, other) = key(&curve, 0x33);
        assert!(!curve.gost_verify(&other, &digest, &signature).unwrap());
        // r and s swapped, which is the wire-order mistake.
        let swapped = Signature { r: signature.s.clone(), s: signature.r.clone() };
        assert!(!curve.gost_verify(&public, &digest, &swapped).unwrap());
        // And each component nudged.
        for change in [1u64, 2] {
            let bumped = Signature {
                r: signature.r.add(&BigUint::from_u64(change)).rem(&curve.n).unwrap(),
                s: signature.s.clone(),
            };
            assert!(!curve.gost_verify(&public, &digest, &bumped).unwrap());
        }
    }

    /// Zero and n are not valid components. `r = 0` in particular makes
    /// the verification independent of the public key.
    #[test]
    fn test_out_of_range_components_are_refused() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (private, public) = key(&curve, 0x44);
        let digest = digest_of(b"bounds", 256);
        let good = curve.gost_sign(&private, &digest, fresh(256)).unwrap();

        for bad in [BigUint::zero(), curve.n.clone(),
                    curve.n.add(&BigUint::one())] {
            assert!(!curve.gost_verify(&public, &digest,
                                       &Signature { r: bad.clone(), s: good.s.clone() })
                    .unwrap(), "r = {:?} accepted", bad);
            assert!(!curve.gost_verify(&public, &digest,
                                       &Signature { r: good.r.clone(), s: bad.clone() })
                    .unwrap(), "s = {:?} accepted", bad);
        }
    }

    /// The digest is read little endian. Reading it the other way gives a
    /// different `e` and therefore a different signature - so this pins
    /// the convention rather than trusting it.
    #[test]
    fn test_the_digest_is_read_little_endian() {
        let curve = curves::by_name("gost256-a").unwrap();
        // A digest that is not a palindrome, so the two readings differ.
        let digest: Vec<u8> = (0..32u8).collect();
        let e = curve.gost_digest(&digest).unwrap();

        let mut reversed = digest.clone();
        reversed.reverse();
        assert_eq!(e, BigUint::from_bytes_be(&reversed).rem(&curve.n).unwrap());
        assert_ne!(e, BigUint::from_bytes_be(&digest).rem(&curve.n).unwrap(),
                   "the two readings must differ, or this test proves nothing");
    }

    /// A digest that reduces to zero becomes one, because `e = 0` makes
    /// `s = r*d` and one signature hands over the private key.
    #[test]
    fn test_a_zero_digest_becomes_one() {
        let curve = curves::by_name("gost256-a").unwrap();
        assert_eq!(curve.gost_digest(&[0u8; 32]).unwrap(), BigUint::one());

        // And n itself, read little endian, also reduces to zero.
        let mut n_le = curve.n.to_bytes_be_padded(32).unwrap();
        n_le.reverse();
        assert_eq!(curve.gost_digest(&n_le).unwrap(), BigUint::one());
    }

    /// `s || r`, not `r || s`. Written out because the two are the same
    /// length and a signature with them swapped parses cleanly.
    #[test]
    fn test_the_wire_order_is_s_then_r() {
        let curve = curves::by_name("gost256-a").unwrap();
        let signature = Signature {
            r: BigUint::from_u64(0x1111),
            s: BigUint::from_u64(0x2222),
        };
        let bytes = curve.gost_signature_bytes(&signature).unwrap();
        assert_eq!(bytes.len(), 64);
        assert_eq!(&bytes[30..32], &[0x22, 0x22], "s comes first");
        assert_eq!(&bytes[62..64], &[0x11, 0x11], "r comes second");
        assert_eq!(curve.gost_signature_from_bytes(&bytes).unwrap(), signature);

        // The ECDSA encoding of the same pair is a different string, and
        // decoding one as the other swaps the components.
        let ecdsa = signature.to_bytes(&curve).unwrap();
        assert_ne!(ecdsa, bytes);
        let misread = curve.gost_signature_from_bytes(&ecdsa).unwrap();
        assert_eq!(misread.s, signature.r);
        assert_eq!(misread.r, signature.s);
    }

    #[test]
    fn test_a_wrong_length_signature_is_refused() {
        let curve = curves::by_name("gost512-a").unwrap();
        assert_eq!(curve.gost_component_bytes(), 64);
        for length in [0usize, 63, 64, 127, 129] {
            assert!(curve.gost_signature_from_bytes(&vec![0u8; length]).is_err(),
                    "{} bytes accepted", length);
        }
        assert!(curve.gost_signature_from_bytes(&[1u8; 128]).is_ok());
    }

    /// A private scalar outside [1, n) is not a key.
    #[test]
    fn test_a_bad_private_scalar_is_refused() {
        let curve = curves::by_name("gost256-a").unwrap();
        let digest = digest_of(b"x", 256);
        for bad in [BigUint::zero(), curve.n.clone(),
                    curve.n.add(&BigUint::one())] {
            assert!(curve.gost_sign(&bad, &digest, fresh(256)).is_err());
        }
    }

    /// GOST and ECDSA over the same curve and key produce signatures that
    /// do not verify as each other. They are different equations, and a
    /// library carrying both must not confuse them.
    #[test]
    fn test_gost_and_ecdsa_do_not_verify_as_each_other() {
        use crate::hash_functions::sha2::SHA256;
        let curve = curves::by_name("gost256-a").unwrap();
        let (private, public) = key(&curve, 0x66);
        let digest = digest_of(b"which one", 256);

        let gost = curve.gost_sign(&private, &digest, fresh(256)).unwrap();
        let ecdsa = curve.sign(&private, &digest, SHA256::new(&[])).unwrap();

        assert!(curve.gost_verify(&public, &digest, &gost).unwrap());
        assert!(!curve.gost_verify(&public, &digest, &ecdsa).unwrap(),
                "an ECDSA signature verified as GOST");
        assert!(!curve.verify(&public, &digest, &gost).unwrap(),
                "a GOST signature verified as ECDSA");
    }
}
