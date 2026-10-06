/*
ECDSA, with deterministic nonces per RFC 6979.

The nonce is the whole problem with ECDSA. Reuse it across two signatures and
the private key falls out of two linear equations. Bias it — even by a few
bits, even across thousands of signatures — and lattice reduction recovers it.
This is how the PS3 signing key went and how a run of Bitcoin wallets were
drained, and in both cases the code looked fine.

So we do not generate nonces at all. RFC 6979 derives k from the private key
and the message hash through HMAC, which means:

  - the same message and key always produce the same signature, so the
    signatures themselves are a test vector,
  - a broken random source cannot produce a repeat, because randomness is
    not involved,
  - the RFC's own appendix A.2.5 vectors pin the construction exactly, and
    we check against them.

Nothing here calls `random`. That is deliberate and should stay that way.

The signature is a pair (r, s) of integers. DER encoding of that pair is
ASN.1 and belongs in the X.509 work; `Signature::to_bytes` gives the
fixed-width r||s form in the meantime, which is what TLS 1.3 and JWS use and
what the differential tests compare.
*/

use super::{Curve, Point};
use crate::bignum::{BigUint, Montgomery, Secret};
use crate::hash_functions::HashFunction;
use crate::mac::Hmac;

/// An ECDSA signature: two integers modulo the group order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: BigUint,
    pub s: BigUint,
}

impl Signature {
    /// Fixed-width `r || s`, each padded to the curve's field size. This is
    /// the form TLS 1.3, JWS and the NIST test vectors use.
    pub fn to_bytes(&self, curve: &Curve) -> Result<Vec<u8>, String> {
        let width = curve.field_bytes();
        let mut out = self.r.to_bytes_be_padded(width)?;
        out.extend_from_slice(&self.s.to_bytes_be_padded(width)?);
        Ok(out)
    }

    /// The inverse of [`Signature::to_bytes`]. Rejects a wrong length rather
    /// than guessing where the split is.
    pub fn from_bytes(curve: &Curve, bytes: &[u8]) -> Result<Signature, String> {
        let width = curve.field_bytes();
        if bytes.len() != 2 * width {
            return Err(format!("Signature for {} must be {} bytes, got {}.",
                               curve.name, 2 * width, bytes.len()));
        }
        Ok(Signature {
            r: BigUint::from_bytes_be(&bytes[..width]),
            s: BigUint::from_bytes_be(&bytes[width..]),
        })
    }
}

/// RFC 6979 `bits2int`: take the leftmost `qlen` bits of the digest.
///
/// The digest may be longer or shorter than the group order. Longer means
/// truncate from the *left* — that is, shift right by the excess, keeping the
/// high bits — which is not the same as reducing mod n, and getting it
/// backwards produces signatures that verify against nothing.
fn bits2int(digest: &[u8], qlen: usize) -> BigUint {
    let value = BigUint::from_bytes_be(digest);
    let blen = digest.len() * 8;
    if blen > qlen {
        value.shr(blen - qlen)
    } else {
        value
    }
}

/// The same, on bytes and staying there.
///
/// `bits2int` above returns a `BigUint`, which normalises - and normalising
/// a secret taints its *length*, which then spreads to every loop bound
/// derived from it. The nonce must never take that trip, so this is the
/// version the signing path uses: `rlen` bytes in, `rlen` bytes out, no
/// value ever measured.
///
/// `test_the_two_bits2int_agree` pins it to the one above, which is the
/// version RFC 6979's own vectors check.
fn bits2int_bytes(digest: &[u8], qlen: usize) -> Vec<u8> {
    let rlen = qlen.div_ceil(8);
    let blen = digest.len() * 8;
    let mut out = vec![0u8; rlen];

    if blen <= qlen {
        // Shorter than the field: right-align it, which is what reading it
        // as a big-endian integer of `rlen` bytes does.
        let start = rlen.saturating_sub(digest.len());
        let from = digest.len().saturating_sub(rlen);
        out[start..].copy_from_slice(&digest[from..]);
        return out;
    }

    // Longer: keep the leftmost `qlen` bits, which is a right shift by the
    // excess - not a reduction mod n, and getting that backwards produces
    // signatures that verify against nothing.
    let shift = blen - qlen;
    let take = digest.len() - shift / 8;
    let bits = shift % 8;
    let mut shifted = vec![0u8; take];
    let mut carry = 0u8;
    for index in 0..take {
        let byte = digest[index];
        shifted[index] = (byte >> bits) | carry;
        // `byte << 8` is not a shift in Rust, it is a panic, so the zero
        // case has to be written out.
        carry = if bits == 0 { 0 } else { byte << (8 - bits) };
    }
    if take >= rlen {
        out.copy_from_slice(&shifted[take - rlen..]);
    } else {
        out[rlen - take..].copy_from_slice(&shifted);
    }
    out
}

/// RFC 6979 `int2octets`: fixed width, big endian, `ceil(qlen/8)` bytes.
///
/// For a **public** value. `to_bytes_be_padded` scans for the first non-zero
/// byte, which is a branch on the value.
fn int2octets(value: &BigUint, rlen: usize) -> Result<Vec<u8>, String> {
    value.to_bytes_be_padded(rlen)
}

/// The same, for the private scalar.
///
/// RFC 6979 feeds `int2octets(x)` into the HMAC chain that derives every
/// nonce, so the private key goes through this on every signature. The
/// public version would scan it for its first non-zero byte; `Secret`
/// serialises at a fixed width by construction and never looks.
///
/// The one thing it does read is the value's limb count, in
/// `Secret::from_biguint` - unavoidable while the key arrives as a
/// `BigUint`, and the same on every call with the same key, so it is not a
/// channel that accumulates.
fn int2octets_secret(value: &BigUint, rlen: usize) -> Result<Vec<u8>, String> {
    let limbs = rlen.div_ceil(8);
    let mut bytes = Secret::from_biguint(value, limbs)?.to_bytes_be();
    if bytes.len() < rlen {
        return Err(format!("Scalar needs {} bytes, have {}.", rlen, bytes.len()));
    }
    // Whole limbs may be wider than the field - P-521 is nine limbs and
    // sixty-six bytes. The extra leading bytes are zeros of a value below
    // `n`, and how many there are is fixed by the curve, so dropping them is
    // not a measurement.
    bytes.drain(..bytes.len() - rlen);
    Ok(bytes)
}

/// RFC 6979 `bits2octets`: `bits2int`, reduced mod n, then fixed width.
fn bits2octets(digest: &[u8], n: &BigUint, qlen: usize, rlen: usize)
               -> Result<Vec<u8>, String> {
    let z1 = bits2int(digest, qlen);
    // One conditional subtraction is enough: z1 < 2^qlen < 2n.
    let z2 = if z1 < *n { z1 } else { z1.sub(n)? };
    int2octets(&z2, rlen)
}

/// The RFC 6979 HMAC_DRBG, as a generator of candidate nonces.
///
/// Kept as a struct rather than a loop body because the retry path — when a
/// candidate is out of range, or produces r = 0 or s = 0 — has to continue
/// the same K/V chain rather than start over. Restarting would make the
/// nonce depend on how many times we retried, which is exactly the kind of
/// subtle bias this construction exists to avoid.
pub(crate) struct NonceGenerator<H: HashFunction + Clone> {
    hash: H,
    k: Vec<u8>,
    v: Vec<u8>,
    qlen: usize,
    first: bool,
}

impl<H: HashFunction + Clone> NonceGenerator<H> {
    pub(crate) fn new(hash: H, private: &BigUint, digest: &[u8], n: &BigUint)
           -> Result<NonceGenerator<H>, String> {
        let hlen = hash.digest_len();
        let qlen = n.bit_len();
        let rlen = qlen.div_ceil(8);

        let x = int2octets_secret(private, rlen)?;
        let h1 = bits2octets(digest, n, qlen, rlen)?;

        // Step b and c.
        let mut v = vec![0x01u8; hlen];
        let mut k = vec![0x00u8; hlen];

        // Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
        let mut message = v.clone();
        message.push(0x00);
        message.extend_from_slice(&x);
        message.extend_from_slice(&h1);
        k = Hmac::mac(hash.clone(), &k, &message);

        // Step e: V = HMAC_K(V)
        v = Hmac::mac(hash.clone(), &k, &v);

        // Step f: the same again with 0x01.
        let mut message = v.clone();
        message.push(0x01);
        message.extend_from_slice(&x);
        message.extend_from_slice(&h1);
        k = Hmac::mac(hash.clone(), &k, &message);

        // Step g.
        v = Hmac::mac(hash.clone(), &k, &v);

        Ok(NonceGenerator { hash, k, v, qlen, first: true })
    }

    /// The next candidate, as `ceil(qlen/8)` bytes.
    ///
    /// **Bytes rather than a `BigUint`.** The nonce is the one value in
    /// ECDSA whose leak is the key - recovering it is one subtraction away
    /// from recovering `d` - and a normalised `BigUint` measures itself.
    /// It stays fixed width from here to `Secret`.
    pub(crate) fn next_bytes(&mut self) -> Vec<u8> {
        if !self.first {
            // Step h3 on failure: K = HMAC_K(V || 0x00), V = HMAC_K(V).
            let mut message = self.v.clone();
            message.push(0x00);
            self.k = Hmac::mac(self.hash.clone(), &self.k, &message);
            self.v = Hmac::mac(self.hash.clone(), &self.k, &self.v);
        }
        self.first = false;

        let want = self.qlen.div_ceil(8);
        let mut t = Vec::with_capacity(want + self.v.len());
        while t.len() < want {
            self.v = Hmac::mac(self.hash.clone(), &self.k, &self.v);
            t.extend_from_slice(&self.v);
        }
        t.truncate(want);
        bits2int_bytes(&t, self.qlen)
    }

    /// The candidate as a number, for callers that are not signing - the
    /// GOST path, whose nonce handling is its own.
    pub(crate) fn next(&mut self) -> BigUint {
        BigUint::from_bytes_be(&self.next_bytes())
    }
}

impl Curve {
    /// Sign a digest. `hash` must be a fresh, empty hash of the same
    /// algorithm that produced `digest` — RFC 6979 uses it for the HMAC
    /// chain that derives the nonce.
    ///
    /// The digest goes in already computed, rather than the message, because
    /// that is the shape every protocol needs: TLS signs a transcript hash,
    /// X.509 signs a hash of the TBS certificate.
    pub fn sign<H: HashFunction + Clone>(&self, private: &BigUint, digest: &[u8], hash: H)
                                         -> Result<Signature, String> {
        let qlen = self.n.bit_len();
        let e = bits2int(digest, qlen);
        let e = e.rem(&self.n)?;

        // Built once: `Montgomery::new` divides to get R^2 mod n, and the
        // modulus is public so doing it here costs nothing and leaks nothing.
        let order = Montgomery::new(&self.n)?;
        let width = order.limbs();
        // `n` is public - it is a curve parameter - so widening it measures
        // nothing.
        let n_s = Secret::from_biguint(&self.n, width)?;
        // The private scalar crosses into fixed width **once**, here, rather
        // than inside the loop. The one length it reads is the same on every
        // call with this key, so it is not a channel that accumulates.
        let d_s = Secret::from_biguint(private, width)?;
        let e_s = Secret::from_biguint(&e, width)?;

        // The key's range check, as a mask rather than as two comparisons.
        // `private.is_zero() || *private >= self.n` reads the same and runs
        // `BigUint::cmp`, which returns on the first differing limb - on the
        // private key, on every signature.
        let unusable = d_s.ct_is_zero() | !d_s.ct_lt(&n_s);
        if crate::bignum::montgomery::unmask(unusable) {
            return Err("Private scalar is not in [1, n).".to_string());
        }

        let mut nonces = NonceGenerator::new(hash, private, digest, &self.n)?;

        // The RFC's loop. In practice it succeeds on the first candidate for
        // every curve we support; the retries are here because "in practice"
        // is not "always", and a signature with r = 0 or s = 0 is invalid.
        for _ in 0..1000 {
            // Bytes, never a `BigUint`: see `NonceGenerator::next_bytes`.
            let k_s = Secret::from_bytes_be(&nonces.next_bytes(), width)?;

            // **The one accepted leak left in this function.** Rejection
            // sampling branches on the candidate by construction: how many
            // times round the loop we went is visible. The two conditions
            // fold into one mask first, so what is visible is "it was out of
            // range" and not which of the two - and for every curve here `n`
            // is within a hair's breadth of 2^qlen, so a rejection is around
            // a one-in-2^32 event and has never been observed. Removing it
            // would mean not following RFC 6979.
            let unusable = k_s.ct_is_zero() | !k_s.ct_lt(&n_s);
            if crate::bignum::montgomery::unmask(unusable) {
                continue;
            }

            // The nonce is secret, so this is the constant-time path, and
            // it takes the `Secret` rather than a number.
            let point = self.scalar_mul_secret_bytes(&self.g, &k_s)?;
            let x = match point.x() {
                Some(x) => x,
                None => continue, // k*G was the identity; impossible for k in range
            };
            // `r` is half the signature, so it is public from here.
            let r = x.rem(&self.n)?;
            if r.is_zero() {
                continue;
            }

            // s = k^-1 (e + r*d) mod n
            //
            // Every step here touches a secret - `k` is the nonce and
            // `private` is the key - so none of it can go through
            // `mod_inverse` and `mod_mul`. Those reduce by division, whose
            // loop count depends on the value; and recovering the nonce from
            // a signature is recovering the key, in one subtraction.
            //
            // So: Fermat inversion, and the rest in the Montgomery domain
            // over `n`, which is prime because ECDSA requires it.
            let r_s = Secret::from_biguint(&r, width)?;
            // `s` is the other half, so declassifying it is the point.
            let s = match super::fixed::signature_s(&self.n, k_s.limbs(), d_s.limbs(),
                                                    e_s.limbs(), r_s.limbs()) {
                Some(s) => Secret::from_limbs(s?).declassify(),
                None => {
                    let k_inv = order.inverse_prime(&k_s, order.modulus_bits());
                    let rd = order.mul_mod(&r_s, &d_s);
                    let sum = order.add_mod(&e_s, &rd);
                    order.mul_mod(&k_inv, &sum).declassify()
                }
            };
            if s.is_zero() {
                continue;
            }

            return Ok(Signature { r, s });
        }
        Err("ECDSA nonce generation failed 1000 times; this should be impossible.".to_string())
    }

    /// Verify a signature against a public point.
    ///
    /// Everything here is public, so this is variable time on purpose. The
    /// public key is validated first: a caller who hands us a point off the
    /// curve should get an error, not a verdict.
    ///
    /// Unlike `sign`, this takes no hash: verification does not derive a
    /// nonce, so the hash algorithm never enters the arithmetic. The caller
    /// is responsible for having hashed with the algorithm the signature
    /// claims — which, in a protocol, means checking the signature algorithm
    /// identifier rather than trusting it.
    pub fn verify(&self, public: &Point, digest: &[u8], signature: &Signature)
                  -> Result<bool, String> {
        self.validate(public)?;

        // r and s must be in [1, n-1]. A zero or out-of-range value is not a
        // signature, and accepting one has been a real CVE in more than one
        // library.
        if signature.r.is_zero() || signature.r >= self.n
            || signature.s.is_zero() || signature.s >= self.n {
            return Ok(false);
        }

        let qlen = self.n.bit_len();
        let e = bits2int(digest, qlen).rem(&self.n)?;

        let w = signature.s.mod_inverse(&self.n)?;
        let u1 = e.mod_mul(&w, &self.n)?;
        let u2 = signature.r.mod_mul(&w, &self.n)?;

        let point = match super::fixed::verify_sum(self, u1.limbs(), u2.limbs(), public) {
            Some(point) => point?,
            None => self.add(&self.scalar_mul(&self.g, &u1), &self.scalar_mul(public, &u2)),
        };
        let x = match point.x() {
            Some(x) => x,
            None => return Ok(false), // u1*G + u2*Q is the identity
        };
        Ok(x.rem(&self.n)? == signature.r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two `bits2int`s must agree, on every shape of input that matters:
    /// digest shorter than the field, exactly equal, and longer by a whole
    /// number of bytes and by a part of one.
    ///
    /// The byte version exists only so the nonce never becomes a normalised
    /// `BigUint`. If it drifted from the one RFC 6979's vectors check, every
    /// signature would still verify against itself and against nobody else.
    #[test]
    fn test_the_two_bits2int_agree() {
        let digests: &[&[u8]] = &[
            &[],
            &[0x01],
            &[0xff; 20],
            &[0xab; 32],
            &[0x7f; 48],
            &[0x80; 64],
            &[0x00, 0x00, 0x01, 0x02],
        ];
        // qlen values covering a byte boundary (256), one that is not
        // (521), and a small one where the digest is much longer.
        for qlen in [8usize, 16, 63, 64, 160, 163, 256, 384, 521] {
            for digest in digests {
                let want = bits2int(digest, qlen);
                let bytes = bits2int_bytes(digest, qlen);
                assert_eq!(bytes.len(), qlen.div_ceil(8),
                           "width is the field's, not the digest's");
                assert_eq!(BigUint::from_bytes_be(&bytes), want,
                           "qlen {} over {} bytes", qlen, digest.len());
            }
        }
    }
    use crate::ec::curves;
    use crate::hash_functions::sha2::{SHA256, SHA512};

    fn sha256() -> SHA256 { SHA256::new(b"") }

    fn digest_of(message: &[u8]) -> Vec<u8> {
        let mut h = SHA256::new(message);
        h.digest()
    }

    /// RFC 6979 appendix A.2.5: P-256 with SHA-256, key and messages fixed
    /// by the RFC. If the nonce construction is wrong in any detail — the
    /// truncation direction, the order of the HMAC rounds, the extra 0x00 —
    /// these do not match.
    #[test]
    fn test_rfc6979_p256_sha256_vectors() {
        let curve = curves::p256();
        let private = BigUint::from_hex(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721").unwrap();

        for (message, want_r, want_s) in [
            ("sample",
             "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
             "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
            ("test",
             "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
             "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
        ] {
            let digest = digest_of(message.as_bytes());
            let signature = curve.sign(&private, &digest, sha256()).unwrap();

            assert_eq!(signature.r.to_hex().to_uppercase().trim_start_matches('0'),
                       want_r.trim_start_matches('0'), "r for {:?}", message);
            assert_eq!(signature.s.to_hex().to_uppercase().trim_start_matches('0'),
                       want_s.trim_start_matches('0'), "s for {:?}", message);

            let public = curve.scalar_mul(&curve.g, &private);
            assert!(curve.verify(&public, &digest, &signature).unwrap());
        }
    }

    /// All of RFC 6979's prime-curve vectors this library has a curve
    /// for - P-256, P-384 and P-521, five hashes and two messages each -
    /// read out of the vendored RFC rather than typed: the key, the
    /// public point, and every signature's k, r and s. The typed pair
    /// above is the same document's first two rows, kept because they
    /// were the first check this module had.
    #[test]
    fn test_the_rfc_6979_prime_curve_vectors() {
        use crate::api::AnyHash;
        use crate::publickey_ciphers::dsa::rfc6979;
        for (heading, curve) in [("A.2.5.  ECDSA, 256 Bits (Prime Field)", curves::p256()),
                                 ("A.2.6.  ECDSA, 384 Bits (Prime Field)", curves::p384()),
                                 ("A.2.7.  ECDSA, 521 Bits (Prime Field)", curves::p521())] {
            let (fields, signatures) = rfc6979::section(heading);
            let get = |name: &str| rfc6979::field(&fields, name);
            assert_eq!(get("q"), curve.n, "{heading}: q");
            let private = get("x");
            let public = curve.scalar_mul(&curve.g, &private);
            assert_eq!(public.x(), Some(&get("Ux")), "{heading}: Ux");
            assert_eq!(public.y(), Some(&get("Uy")), "{heading}: Uy");
            assert_eq!(signatures.len(), 10, "{heading}");
            for signature in signatures {
                let label = format!("{heading} {} {:?}", signature.hash, signature.message);
                let mut hash = AnyHash::new(&signature.hash).unwrap();
                hash.update(signature.message.as_bytes());
                let digest = hash.digest();
                let mut nonces = NonceGenerator::new(AnyHash::new(&signature.hash).unwrap(),
                                                     &private, &digest, &curve.n).unwrap();
                assert_eq!(nonces.next(), signature.k, "{label}: k");
                let ours = curve.sign(&private, &digest,
                                      AnyHash::new(&signature.hash).unwrap()).unwrap();
                assert_eq!((&ours.r, &ours.s), (&signature.r, &signature.s), "{label}");
                assert!(curve.verify(&public, &digest, &ours).unwrap(), "{label}");
            }
        }
    }

    /// Determinism is the property the whole construction exists for.
    #[test]
    fn test_signatures_are_deterministic() {
        for curve in curves::all() {
            let (private, _) = curve.generate_key_pair().unwrap();
            let digest = digest_of(b"the same message");
            let a = curve.sign(&private, &digest, sha256()).unwrap();
            let b = curve.sign(&private, &digest, sha256()).unwrap();
            assert_eq!(a, b, "{} signed the same message two ways", curve.name);

            // And a different message must give a different nonce, which
            // shows up as a different r.
            let other = curve.sign(&private, &digest_of(b"a different message"),
                                   sha256()).unwrap();
            assert_ne!(a.r, other.r, "{} reused a nonce across messages", curve.name);
        }
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        for curve in curves::all() {
            let (private, public) = curve.generate_key_pair().unwrap();
            for message in [b"".as_slice(), b"x", b"a longer message to sign"] {
                let digest = digest_of(message);
                let signature = curve.sign(&private, &digest, sha256()).unwrap();
                assert!(curve.verify(&public, &digest, &signature).unwrap(),
                        "{} failed to verify its own signature", curve.name);

                // Fixed-width encoding must round trip.
                let bytes = signature.to_bytes(&curve).unwrap();
                assert_eq!(bytes.len(), 2 * curve.field_bytes());
                assert_eq!(Signature::from_bytes(&curve, &bytes).unwrap(), signature);
            }
        }
    }

    /// Every way a signature can be wrong must come back false rather than
    /// true or an error.
    #[test]
    fn test_verification_rejects_tampering() {
        for curve in curves::all() {
            let (private, public) = curve.generate_key_pair().unwrap();
            let digest = digest_of(b"authentic");
            let signature = curve.sign(&private, &digest, sha256()).unwrap();

            // Wrong message.
            assert!(!curve.verify(&public, &digest_of(b"forged"), &signature).unwrap());

            // Wrong key.
            let (_, other_public) = curve.generate_key_pair().unwrap();
            assert!(!curve.verify(&other_public, &digest, &signature).unwrap());

            // Swapped halves.
            let swapped = Signature { r: signature.s.clone(), s: signature.r.clone() };
            assert!(!curve.verify(&public, &digest, &swapped).unwrap());

            // Out of range values are not signatures.
            for bad in [Signature { r: BigUint::zero(), s: signature.s.clone() },
                        Signature { r: signature.r.clone(), s: BigUint::zero() },
                        Signature { r: curve.n.clone(), s: signature.s.clone() },
                        Signature { r: signature.r.clone(), s: curve.n.clone() }] {
                assert!(!curve.verify(&public, &digest, &bad).unwrap(),
                        "{} accepted an out of range signature", curve.name);
            }

            // A public key that is not on the curve is an error, not a verdict.
            let off_curve = Point::new(BigUint::from_u64(1), BigUint::from_u64(1));
            assert!(curve.verify(&off_curve, &digest, &signature).is_err());
        }
    }

    /// A digest longer than the group order is truncated from the left, not
    /// reduced. P-256 with SHA-512 is the case that catches it.
    #[test]
    fn test_digest_longer_than_the_order() {
        let curve = curves::p256();
        let (private, public) = curve.generate_key_pair().unwrap();
        let mut h = SHA512::new(b"a message", 512);
        let digest = h.digest();
        assert_eq!(digest.len(), 64);

        let signature = curve.sign(&private, &digest, SHA512::new(b"", 512)).unwrap();
        assert!(curve.verify(&public, &digest, &signature).unwrap());
    }

    #[test]
    fn test_bad_scalars_are_refused() {
        let curve = curves::p256();
        let digest = digest_of(b"anything");
        assert!(curve.sign(&BigUint::zero(), &digest, sha256()).is_err());
        assert!(curve.sign(&curve.n.clone(), &digest, sha256()).is_err());
    }

    #[test]
    fn test_signature_bytes_reject_wrong_length() {
        let curve = curves::p256();
        assert!(Signature::from_bytes(&curve, &[0u8; 63]).is_err());
        assert!(Signature::from_bytes(&curve, &[0u8; 65]).is_err());
        assert!(Signature::from_bytes(&curve, &[]).is_err());
    }
}
