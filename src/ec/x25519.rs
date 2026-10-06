/*
X25519: Diffie-Hellman on Curve25519 (RFC 7748).

A different shape from the curves in `ec::curves`, and the differences are
the interesting part rather than an implementation detail:

  * The curve is a **Montgomery** curve, `v^2 = u^3 + 486662u^2 + u` over
    `p = 2^255 - 19`, and the ladder works on the `u` coordinate alone.
    There is no point encoding to get wrong, no compression, and no
    "is this on the curve" question of the usual kind - every 32 byte
    string is a valid input.

  * Which means invalid-curve attacks do not apply, and are replaced by a
    different property: for the `u` values that are *not* on the curve,
    the arithmetic lands on the quadratic twist, which was chosen to have
    a large prime order subgroup too. That is a design decision of the
    curve rather than a check in the code, and it is why there is no
    validation function here.

  * The scalar is **clamped**: the bottom three bits cleared, the top bit
    cleared, and the second-from-top set. Clearing the low bits forces the
    scalar into the large subgroup, which removes the small-subgroup
    problem; setting the high bit fixes the length so the ladder runs the
    same number of iterations whatever the scalar is. Skipping the
    clamping produces an implementation that interoperates with itself and
    nothing else, which is the sort of bug that survives a round-trip
    test.

  * Everything is **little-endian**, in a field otherwise made entirely of
    big-endian encodings. Getting this backwards produces a working key
    exchange that agrees with nobody.

The all-zero output is refused. RFC 7748 section 6.1 says an implementation
"MAY" check for it; it means the peer sent a low-order point and every
session key would be the same known value, so this one does.

The arithmetic is `ec::field25519`: five 51-bit limbs with no branch or
memory index that depends on a value, so the ladder - scalar bits, swaps,
field operations and the final inversion - takes the same path for every
scalar and every point. An earlier version ran on `BigUint`, which is
neither constant time nor fast, and swapped its registers with an `if` on
the scalar bit; it is kept in the tests as the reference this one is
checked against.
*/

use super::field25519::Fe;

/// `(486662 - 2) / 4`, the constant the ladder actually uses.
const A24: u32 = 121665;

/// The u coordinate of the base point: 9.
pub const BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Clamp a scalar, per RFC 7748 section 5.
///
/// Three low bits cleared so the scalar is a multiple of the cofactor,
/// which puts the result in the large prime order subgroup whatever the
/// peer sent. Top bit cleared and the next one set so every scalar has
/// exactly the same bit length, which is what makes the ladder's
/// iteration count independent of the secret.
pub fn clamp(scalar: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    clamped
}

/// The Montgomery ladder: `scalar * u`, on the u coordinate alone.
///
/// 255 iterations whatever the scalar, and the conditional swaps are a
/// mask (`Fe::cswap`) rather than a branch - the branch would be on a bit
/// of the private scalar. The formula is RFC 7748 section 5's, with named
/// intermediates rather than the document's reused variables: every
/// transcription bug in this shape is a reuse in the wrong order.
///
/// `Fe::from_bytes` ignores the top bit of `u`, which is RFC 7748's
/// decoding rule and not cosmetic: implementations differ on whether a
/// non-canonical encoding (a value at or above p, or with the spare bit
/// set) is an error, and the RFC settles it by saying the bit is ignored
/// and the value reduced. Treating it as an error makes a handshake fail
/// against a peer doing exactly what the specification says.
fn ladder(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swapped = 0u64;

    for i in (0..255).rev() {
        let bit = u64::from((scalar[i / 8] >> (i % 8)) & 1);
        Fe::cswap(&mut x2, &mut x3, swapped ^ bit);
        Fe::cswap(&mut z2, &mut z3, swapped ^ bit);
        swapped = bit;

        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);

        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        // z_2 = E * (AA + a24 * E). `AA`, not `BB` - they are the two
        // squares either side of E and swapping them gives a ladder that
        // agrees with itself and with no published vector, which is
        // exactly what the first version of this line did.
        z2 = e.mul(aa.add(e.mul_small(A24)));
    }
    Fe::cswap(&mut x2, &mut x3, swapped);
    Fe::cswap(&mut z2, &mut z3, swapped);

    // z2^(p-2) is the inverse: Fermat rather than the extended Euclidean
    // algorithm, whose steps depend on the value. z2 = 0 (a low-order
    // point) gives 0, and the result is the all-zero output that
    // `exchange` refuses.
    x2.mul(z2.invert()).to_bytes()
}

/// `scalar * point`, the raw primitive of RFC 7748 section 5.
///
/// The scalar is clamped here, so callers cannot forget. Clamping an
/// already-clamped scalar changes nothing, which is what makes that safe.
///
/// It cannot fail; the `Result` is the signature every caller was written
/// against when the arithmetic underneath could.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> Result<[u8; 32], String> {
    Ok(ladder(&clamp(scalar), point))
}

/// The public key for a private one: `scalar * 9`.
pub fn public_key(private: &[u8; 32]) -> Result<[u8; 32], String> {
    x25519(private, &BASE_POINT)
}

/// A fresh key pair from the OS generator.
pub fn generate_key_pair() -> Result<([u8; 32], [u8; 32]), String> {
    let mut private = [0u8; 32];
    crate::random::fill(&mut private)?;
    // Stored clamped, so the private bytes and the public key cannot
    // disagree about which scalar this is.
    let private = clamp(&private);
    let public = public_key(&private)?;
    Ok((private, public))
}

/// The shared secret, with the all-zero result refused.
///
/// Zero means the peer sent a point of small order, so the secret is a
/// constant every observer can compute. RFC 7748 section 6.1 makes the
/// check optional; skipping it turns an active attacker's degenerate key
/// into a working session with a known key, which is not a thing to leave
/// optional.
pub fn exchange(private: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], String> {
    let shared = x25519(private, peer)?;
    if shared.iter().all(|byte| *byte == 0) {
        return Err("The X25519 shared secret is all zero, so the peer sent a \
                    low-order point and the secret is a constant anybody \
                    can compute.".to_string());
    }
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 7748 section 5.2, both test vectors.
    #[test]
    fn test_the_rfc_7748_vectors() {
        let scalar = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let point = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(hex(&x25519(&scalar, &point).unwrap()),
                   "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        let scalar = unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let point = unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(hex(&x25519(&scalar, &point).unwrap()),
                   "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    }

    /// RFC 7748 section 6.1: Alice and Bob's keys, and the secret they
    /// reach. This is the vector that catches a byte-order mistake, since
    /// it fixes the public keys as well as the secret.
    #[test]
    fn test_the_rfc_7748_key_exchange() {
        let alice_private = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_private = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        assert_eq!(hex(&public_key(&alice_private).unwrap()),
                   "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(hex(&public_key(&bob_private).unwrap()),
                   "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        let alice_public = public_key(&alice_private).unwrap();
        let bob_public = public_key(&bob_private).unwrap();
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(hex(&exchange(&alice_private, &bob_public).unwrap()), shared);
        assert_eq!(hex(&exchange(&bob_private, &alice_public).unwrap()), shared);
    }

    /// RFC 7748 section 5.2's iterated test, one and a thousand rounds.
    /// The million-round case takes about a minute in a release build and
    /// is left out.
    #[test]
    fn test_the_iterated_vector() {
        let mut k = BASE_POINT;
        let mut u = k;
        for round in 1..=1000 {
            let next = x25519(&k, &u).unwrap();
            u = k;
            k = next;
            if round == 1 {
                assert_eq!(hex(&k),
                    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
            }
        }
        assert_eq!(hex(&k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    }

    /// The `BigUint` ladder this module used before `field25519`, kept as
    /// an independent reference: different arithmetic, the same formula.
    fn reference(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
        use crate::bignum::BigUint;
        let p = BigUint::one().shl(255).sub(&BigUint::from_u64(19)).unwrap();
        let a24 = BigUint::from_u64(121665);
        let scalar = clamp(scalar);
        let mut masked = *point;
        masked[31] &= 127;
        masked.reverse();
        let x1 = BigUint::from_bytes_be(&masked).rem(&p).unwrap();
        let (mut x2, mut z2) = (BigUint::one(), BigUint::zero());
        let (mut x3, mut z3) = (x1.clone(), BigUint::one());
        let mut swapped = false;
        for i in (0..255).rev() {
            let bit = (scalar[i / 8] >> (i % 8)) & 1 == 1;
            if bit != swapped {
                core::mem::swap(&mut x2, &mut x3);
                core::mem::swap(&mut z2, &mut z3);
            }
            swapped = bit;
            let a = x2.mod_add(&z2, &p).unwrap();
            let aa = a.mod_mul(&a, &p).unwrap();
            let b = x2.mod_sub(&z2, &p).unwrap();
            let bb = b.mod_mul(&b, &p).unwrap();
            let e = aa.mod_sub(&bb, &p).unwrap();
            let c = x3.mod_add(&z3, &p).unwrap();
            let d = x3.mod_sub(&z3, &p).unwrap();
            let da = d.mod_mul(&a, &p).unwrap();
            let cb = c.mod_mul(&b, &p).unwrap();
            let sum = da.mod_add(&cb, &p).unwrap();
            x3 = sum.mod_mul(&sum, &p).unwrap();
            let difference = da.mod_sub(&cb, &p).unwrap();
            z3 = x1.mod_mul(&difference.mod_mul(&difference, &p).unwrap(), &p).unwrap();
            x2 = aa.mod_mul(&bb, &p).unwrap();
            let scaled = a24.mod_mul(&e, &p).unwrap();
            z2 = e.mod_mul(&aa.mod_add(&scaled, &p).unwrap(), &p).unwrap();
        }
        if swapped {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }
        let inverse = z2.mod_pow(&p.sub(&BigUint::from_u64(2)).unwrap(), &p).unwrap();
        let mut out = x2.mod_mul(&inverse, &p).unwrap().to_bytes_be_padded(32).unwrap();
        out.reverse();
        out.try_into().unwrap()
    }

    /// Random scalars against random points, and against the encodings a
    /// random draw will not produce: zero, one, p - 1, p, p + 1 and
    /// 2^255 - 1, with and without the ignored top bit.
    #[test]
    fn test_the_ladder_agrees_with_the_bignum_reference() {
        let random = || {
            let mut bytes = [0u8; 32];
            crate::random::fill(&mut bytes).unwrap();
            bytes
        };
        let mut points: Vec<[u8; 32]> = (0..40).map(|_| random()).collect();
        for low in [0u8, 1, 0xec, 0xed, 0xee] {
            let mut point = if low < 2 { [0u8; 32] } else { [0xff; 32] };
            point[0] = low;
            if low >= 2 {
                point[31] = 0x7f;
            }
            points.push(point);
            point[31] |= 0x80;
            points.push(point);
        }
        points.push([0xff; 32]);
        for point in &points {
            let scalar = random();
            assert_eq!(hex(&x25519(&scalar, point).unwrap()), hex(&reference(&scalar, point)),
                       "point {}", hex(point));
        }
    }

    /// Clamping is not optional and not invisible: an unclamped scalar
    /// gives a different answer, so an implementation that skips it
    /// interoperates with itself and nothing else.
    #[test]
    fn test_clamping_changes_the_scalar_and_is_idempotent() {
        let raw = [0xffu8; 32];
        let clamped = clamp(&raw);
        assert_ne!(clamped, raw);
        assert_eq!(clamped[0] & 7, 0, "the low three bits must be clear");
        assert_eq!(clamped[31] & 128, 0, "the top bit must be clear");
        assert_eq!(clamped[31] & 64, 64, "the second bit must be set");
        assert_eq!(clamp(&clamped), clamped, "clamping must be idempotent");

        // And the public key is the clamped scalar's, which is why
        // `generate_key_pair` stores the clamped form.
        assert_eq!(public_key(&raw).unwrap(), public_key(&clamped).unwrap());
    }

    /// The low-order points from RFC 7748 section 6.1's warning. Each one
    /// makes the shared secret zero, which is a constant everybody knows.
    #[test]
    fn test_low_order_points_are_refused() {
        let (private, _public) = generate_key_pair().unwrap();
        for point in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let point = unhex(point);
            assert!(exchange(&private, &point).is_err(),
                    "a low-order point produced a secret: {}", hex(&point));
            // The raw primitive still computes, because it is the
            // primitive - the refusal belongs to the key exchange.
            assert!(x25519(&private, &point).is_ok());
        }
    }

    /// A non-canonical encoding must be masked rather than refused: RFC
    /// 7748 says the top bit is ignored, and a peer that sets it is doing
    /// what the specification says.
    #[test]
    fn test_the_top_bit_of_the_u_coordinate_is_ignored() {
        let (private, _) = generate_key_pair().unwrap();
        let mut point = public_key(&[7u8; 32]).unwrap();
        let plain = exchange(&private, &point).unwrap();
        point[31] |= 0x80;
        assert_eq!(exchange(&private, &point).unwrap(), plain);
    }

    #[test]
    fn test_two_generated_pairs_agree() {
        let (a_private, a_public) = generate_key_pair().unwrap();
        let (b_private, b_public) = generate_key_pair().unwrap();
        assert_ne!(a_public, b_public);
        assert_eq!(exchange(&a_private, &b_public).unwrap(),
                   exchange(&b_private, &a_public).unwrap());
    }
}
