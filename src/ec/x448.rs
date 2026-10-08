/*!
X448, the key agreement on Curve448 (RFC 7748 section 5).

The last of RFC 7748 and RFC 8032's four to land here: X25519, Ed25519
and Ed448 were already in place. It is the key-agreement half of the
same curve Ed448 signs on, which is the only thing the two share - a
Montgomery u coordinate and an Edwards point are different
representations, and nothing in `eddsa.rs` is reused.

**Not X25519 with bigger numbers.** Four things differ, and three of
them are silent:

  * `p = 2^448 - 2^224 - 1`, a "Goldilocks" prime: the reduction is
    `2^448 = 2^224 + 1` rather than X25519's multiply by 19, so the field
    is its own module, `ec::field448`.
  * `a24 = 39081`, from `A = 156326`. `(A - 2) / 4` as X25519 writes it
    gives the same number, but the two constants are far apart and a
    copied `121665` produces a curve that agrees with itself.
  * **The scalar is clamped differently.** X25519 clears three low bits
    and sets bit 254; X448 clears **two** low bits and sets bit
    **447** - the cofactor is 4 rather than 8, and the field is a
    different width. A scalar clamped the 25519 way is a perfectly good
    scalar of the wrong value.
  * **There is no spare bit to mask.** X25519's u coordinate is 255 bits
    in 32 bytes, so RFC 7748 says to ignore the top bit; X448's is 448
    bits in exactly 56 bytes, so there is no such bit and no masking
    step. Adding one by analogy would clear a real bit of the peer's
    coordinate.

The ladder itself is the same shape as X25519's, and constant time the
same way: the conditional swaps are masked rather than branched, because
the branch would be on a bit of the private scalar, and `field448` has no
branch or memory index that depends on a value. An earlier version ran
on `BigUint` and swapped with an `if`; it is kept in the tests as the
reference this one is checked against.

This is reachable from TLS as supported group 30, through
`tls::kex::EphemeralKey::X448`, at 1.2 and 1.3 on both sides. `ED448` is
still not offered as a signature scheme, which is a separate decision:
advertising either is promising to complete a handshake with it.

**`EphemeralKey` has a variant for this rather than sharing X25519's with
a width parameter**, and the four differences above are why. Three of
them are constants that produce a curve which round-trips and agrees with
nothing; the fourth is the absence of a spare high bit, so a masking step
carried over from X25519 clears a real bit of the peer's coordinate. What
the two do share is the TLS-side shape - generate, exchange, write the
raw value with a one-byte length - and that part *is* written once.
*/

use super::field448::Fe;

/// The number of bytes in a scalar, a u coordinate and a shared secret.
///
/// All three are the same width, which they are not for every curve -
/// the field is 448 bits and 448 is a whole number of bytes, so nothing
/// here is padded and nothing has a spare bit.
pub const KEY_LEN: usize = 56;

/// `(156326 - 2) / 4`, the constant the ladder actually uses.
///
/// **39081, not 121665.** X25519's is the same expression over a
/// different `A`, and a ladder built with the wrong one is
/// self-consistent - it round-trips, the shared secrets agree between
/// two copies of it, and no published vector matches.
const A24: u32 = 39081;

/// The u coordinate of the base point: 5.
///
/// Five, where X25519's is nine. Encoded little endian, so it is the
/// first byte.
pub const BASE_POINT: [u8; KEY_LEN] = {
    let mut base = [0u8; KEY_LEN];
    base[0] = 5;
    base
};

/// Clamp a scalar, per RFC 7748 section 5.
///
/// **Two low bits cleared, not three**, because Curve448's cofactor is
/// 4 where Curve25519's is 8 - that is what puts the result in the
/// large prime-order subgroup whatever the peer sent. And the top *byte*
/// is set to 0x80 rather than having one bit cleared and another set:
/// the field is exactly 448 bits, so bit 447 is the highest there is and
/// there is nothing above it to clear. Setting it is what makes every
/// scalar the same bit length, which is what makes the ladder's
/// iteration count independent of the secret.
///
/// Clamping the X25519 way - three bits and bit 254 - gives a valid
/// scalar of a different value, so it agrees with itself and with
/// nobody.
pub fn clamp(scalar: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut out = *scalar;
    out[0] &= 252;
    out[KEY_LEN - 1] |= 128;
    out
}

/// The Montgomery ladder: `scalar * u`, on the u coordinate alone.
///
/// 448 iterations, one per bit, with the swaps masked rather than
/// branched. The formula is RFC 7748 section 5's, with named
/// intermediates rather than the document's reused variables - every
/// transcription bug in this shape is a reuse in the wrong order.
fn ladder(scalar: &[u8; KEY_LEN], u: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swapped = 0u64;

    // **448, not 447.** X25519 runs 255 iterations over a 255 bit field;
    // here the field is 448 bits and the clamped scalar's top bit is
    // bit 447, so the loop covers 0..448. One fewer drops the highest
    // bit of every scalar, which is the bit clamping just set - so every
    // answer would be wrong and every answer would still be a point.
    for i in (0..448).rev() {
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
        // `z_2 = E * (AA + a24 * E)` - `AA`, not `BB`. They are the two
        // squares either side of `E`, and swapping them gives a ladder
        // that agrees with itself and with no published vector.
        z2 = e.mul(aa.add(e.mul_small(A24)));
    }
    Fe::cswap(&mut x2, &mut x3, swapped);
    Fe::cswap(&mut z2, &mut z3, swapped);

    // Fermat rather than the extended Euclidean algorithm, whose steps
    // depend on the value. z2 = 0 gives 0, the all-zero output.
    x2.mul(z2.invert()).to_bytes()
}

/// `scalar * point`, the raw primitive of RFC 7748 section 5.
///
/// The scalar is clamped here, so callers cannot forget; clamping an
/// already-clamped scalar changes nothing, which is what makes that
/// safe.
///
/// **The u coordinate is taken as it stands.** X25519 masks the top bit
/// of the peer's coordinate because its field is 255 bits in 32 bytes
/// and RFC 7748 says the spare bit is ignored. 448 is a whole number of
/// bytes, so there is no spare bit; masking one by analogy would clear a
/// real bit of the peer's value. A coordinate at or above `p` is reduced
/// rather than refused, which is the same choice and for the same
/// reason - implementations differ, and being stricter than the document
/// breaks handshakes against peers doing exactly what it says.
pub fn x448(scalar: &[u8; KEY_LEN], point: &[u8; KEY_LEN])
            -> Result<[u8; KEY_LEN], String> {
    Ok(ladder(&clamp(scalar), point))
}

/// The public key for a private one: `scalar * 5`.
pub fn public_key(private: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], String> {
    x448(private, &BASE_POINT)
}

/// A fresh key pair from the OS generator.
pub fn generate_key_pair() -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), String> {
    let mut private = [0u8; KEY_LEN];
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
/// constant every observer can compute. RFC 7748 section 6.2 makes the
/// check optional; skipping it turns an active attacker's degenerate key
/// into a working session with a known key, which is not a thing to
/// leave optional. Same decision as `x25519::exchange`.
pub fn exchange(private: &[u8; KEY_LEN], peer: &[u8; KEY_LEN])
                -> Result<[u8; KEY_LEN], String> {
    let shared = x448(private, peer)?;
    // Every byte ORed together, then one branch on the verdict. `all`
    // stops at the first non-zero byte, so its running time said where
    // that byte was - a leak of the secret beyond the verdict, which
    // `scripts/ct_check.py`'s exchange rows report by name.
    let folded = shared.iter().fold(0u8, |acc, byte| acc | byte);
    if folded == 0 {
        return Err("The X448 shared secret is all zero, so the peer sent a \
                    low-order point and the secret is a constant anybody \
                    can compute.".to_string());
    }
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::BigUint;
    use crate::ec::x448_vectors::{exchange_vectors, iterated, single_vectors};

    /// `2^448 - 2^224 - 1`, built rather than typed: a 56 byte constant
    /// is 112 hex digits with one interesting feature in the middle.
    fn field() -> BigUint {
        let one = BigUint::one();
        one.shl(448).sub(&one.shl(224)).unwrap().sub(&one).unwrap()
    }

    /// The `BigUint` ladder this module used before `field448`, kept as
    /// an independent reference: different arithmetic, the same formula.
    fn reference(scalar: &[u8; KEY_LEN], point: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        let p = field();
        let a24 = BigUint::from_u64(39081);
        let scalar = clamp(scalar);
        let mut reversed = *point;
        reversed.reverse();
        let x1 = BigUint::from_bytes_be(&reversed).rem(&p).unwrap();
        let (mut x2, mut z2) = (BigUint::one(), BigUint::zero());
        let (mut x3, mut z3) = (x1.clone(), BigUint::one());
        let mut swapped = false;
        for i in (0..448).rev() {
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
        let mut out = x2.mod_mul(&inverse, &p).unwrap().to_bytes_be_padded(KEY_LEN).unwrap();
        out.reverse();
        out.try_into().unwrap()
    }

    /// Random scalars against random points, and against encodings a
    /// random draw will not produce: zero, one, p - 1, p, p + 1 and
    /// 2^448 - 1, which must reduce rather than be refused.
    #[test]
    fn test_the_ladder_agrees_with_the_bignum_reference() {
        let random = || {
            let mut bytes = [0u8; KEY_LEN];
            crate::random::fill(&mut bytes).unwrap();
            bytes
        };
        let p = field();
        let one = BigUint::one();
        let mut points: Vec<[u8; KEY_LEN]> = (0..30).map(|_| random()).collect();
        for value in [BigUint::zero(), one.clone(), p.sub(&one).unwrap(), p.clone(),
                      p.add(&one), one.shl(448).sub(&one).unwrap()] {
            let mut bytes = value.to_bytes_be_padded(KEY_LEN).unwrap();
            bytes.reverse();
            points.push(bytes.try_into().unwrap());
        }
        for point in &points {
            let scalar = random();
            assert_eq!(hex(&x448(&scalar, point).unwrap()), hex(&reference(&scalar, point)),
                       "point {}", hex(point));
        }
    }

    fn hex(bytes: &[u8; KEY_LEN]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 7748 section 5.2's two X448 vectors, **read out of the
    /// document** rather than typed. See `x448_vectors`.
    #[test]
    fn test_the_rfc_7748_vectors() {
        let vectors = single_vectors("X448:", KEY_LEN);
        assert_eq!(vectors.len(), 2,
                   "RFC 7748 5.2 prints two X448 vectors; the parser found {}",
                   vectors.len());
        for (scalar, point, expected) in &vectors {
            assert_eq!(hex(&x448(scalar, point).unwrap()), hex(expected));
        }
    }

    /// The same section's X25519 vectors, through the same parser.
    ///
    /// Here rather than in `x25519.rs` because the parser is here, and
    /// because it is the check on the parser: it reads a section whose
    /// hex is on **one** line where X448's is split over two, so a
    /// parser that only handled the continuation would find nothing and
    /// a parser that only handled one line would truncate every X448
    /// value. Both failures are silent without a count assertion.
    #[test]
    fn test_the_parser_reads_the_x25519_vectors_too() {
        let vectors = single_vectors("X25519:", 32);
        assert_eq!(vectors.len(), 2,
                   "RFC 7748 5.2 prints two X25519 vectors; found {}",
                   vectors.len());
        for (scalar, point, expected) in &vectors {
            let scalar: [u8; 32] = scalar[..32].try_into().unwrap();
            let point: [u8; 32] = point[..32].try_into().unwrap();
            assert_eq!(crate::ec::x25519::x25519(&scalar, &point).unwrap()[..],
                       expected[..32]);
        }
    }

    /// RFC 7748 section 6.2: Alice and Bob's keys and the secret they
    /// reach.
    ///
    /// The vector that catches a byte-order mistake, because it fixes
    /// the **public keys** as well as the secret - two implementations
    /// that both encoded big endian would agree on a shared secret and
    /// disagree with this.
    #[test]
    fn test_the_rfc_7748_key_exchange() {
        let (alice, alice_public, bob, bob_public, secret) = exchange_vectors();

        assert_eq!(hex(&public_key(&alice).unwrap()), hex(&alice_public));
        assert_eq!(hex(&public_key(&bob).unwrap()), hex(&bob_public));
        assert_eq!(hex(&exchange(&alice, &bob_public).unwrap()), hex(&secret));
        assert_eq!(hex(&exchange(&bob, &alice_public).unwrap()), hex(&secret));
    }

    /// RFC 7748 section 5.2's iterated test, to a thousand rounds.
    ///
    /// The one that catches a ladder which is right for some scalars: a
    /// thousand chained calls feed each answer back in as the next
    /// coordinate, so one wrong bit anywhere wrecks everything after it
    /// rather than one row. The million-round value is in the document
    /// and is not run - it is the same code a thousand times over, at
    /// minutes per run even in a release build.
    ///
    /// Do not shrink the count to speed it up: 1, 1,000 and 1,000,000 are the
    /// only checkpoints RFC 7748 publishes, so a chain of any other
    /// length is a test of this code against itself. If it has to go, it
    /// goes whole and with a note - not quietly to 100 rounds, which
    /// would look like a published vector and be nothing of the kind.
    #[test]
    fn test_the_rfc_7748_iterated_vector() {
        let (after_one, after_thousand) = iterated();
        let mut k = BASE_POINT;
        let mut u = BASE_POINT;
        for round in 1..=1000 {
            let next = x448(&k, &u).unwrap();
            u = k;
            k = next;
            if round == 1 {
                assert_eq!(hex(&k), hex(&after_one),
                           "the first iteration already disagrees");
            }
        }
        assert_eq!(hex(&k), hex(&after_thousand));
    }

    /// Two key pairs reach the same secret, and it is not the public key
    /// of either.
    #[test]
    fn test_a_generated_exchange_agrees() {
        let (alice, alice_public) = generate_key_pair().unwrap();
        let (bob, bob_public) = generate_key_pair().unwrap();
        let one = exchange(&alice, &bob_public).unwrap();
        let two = exchange(&bob, &alice_public).unwrap();
        assert_eq!(one, two);
        assert_ne!(one, alice_public);
        assert_ne!(one, bob_public);
    }

    /// The clamping, asserted as bit positions rather than as an output.
    ///
    /// **Two low bits and bit 447**, which is the single most likely
    /// thing to be copied from X25519 - and a scalar clamped that way is
    /// still a valid scalar, so every round trip and every self-exchange
    /// would pass.
    #[test]
    fn test_the_clamping_is_x448_s_and_not_x25519_s() {
        let clamped = clamp(&[0xffu8; KEY_LEN]);
        assert_eq!(clamped[0] & 0b0000_0011, 0,
                   "the two low bits must be cleared");
        assert_eq!(clamped[0] & 0b0000_0100, 0b0000_0100,
                   "the third bit must be left alone - clearing it is \
                    X25519's cofactor of eight, not Curve448's four");
        assert_eq!(clamped[KEY_LEN - 1] & 0x80, 0x80, "bit 447 must be set");

        // And a zero scalar comes out with only that bit set, which
        // pins the direction: a version that set the *first* byte's top
        // bit would pass the assertions above on an all-ones input.
        let from_zero = clamp(&[0u8; KEY_LEN]);
        assert_eq!(from_zero[KEY_LEN - 1], 0x80);
        assert!(from_zero[..KEY_LEN - 1].iter().all(|b| *b == 0),
                "clamping zero set a bit somewhere else");
    }

    /// Clamping is idempotent, which is what lets `x448` do it for every
    /// caller without asking whether it has been done.
    #[test]
    fn test_clamping_twice_changes_nothing() {
        let scalar = [0x5au8; KEY_LEN];
        assert_eq!(clamp(&clamp(&scalar)), clamp(&scalar));
    }

    /// The field and the curve constant, checked against their
    /// definitions rather than against a transcription.
    #[test]
    fn test_the_constants_are_curve448_s() {
        let p = field();
        let a24 = || BigUint::from_u64(u64::from(A24));
        // `p = 2^448 - 2^224 - 1`, so `p + 2^224 + 1 == 2^448`.
        let one = BigUint::one();
        assert_eq!(p.add(&one.shl(224)).add(&one), one.shl(448));
        assert_eq!(p.bit_len(), 448);
        // p is 3 mod 4, unlike one of the GOST curves - not used here,
        // but it is the property every "take a square root" shortcut
        // elsewhere in this crate assumes.
        assert_eq!(p.rem(&BigUint::from_u64(4)).unwrap(),
                   BigUint::from_u64(3));

        // a24 = (A - 2) / 4 with A = 156326.
        assert_eq!(a24().mod_mul(&BigUint::from_u64(4), &p).unwrap()
                   .add(&BigUint::from_u64(2)),
                   BigUint::from_u64(156326));
        // And it is not X25519's, which is the copy that would be made.
        assert_ne!(a24(), BigUint::from_u64(121665));
    }

    /// A low-order peer key gives zero, and `exchange` refuses it where
    /// the raw primitive does not.
    #[test]
    fn test_a_low_order_point_is_refused_by_exchange() {
        // u = 0 is the point of order 1: every scalar sends it to the
        // identity, whose u coordinate encodes as zero.
        let zero = [0u8; KEY_LEN];
        let (private, _) = generate_key_pair().unwrap();
        assert_eq!(x448(&private, &zero).unwrap(), zero,
                   "u = 0 must give the identity");
        let refused = exchange(&private, &zero).unwrap_err();
        assert!(refused.contains("all zero"), "{refused}");

        // u = 1 is the other one RFC 7748 section 7 names.
        let mut one = [0u8; KEY_LEN];
        one[0] = 1;
        assert!(exchange(&private, &one).is_err(),
                "u = 1 has order 2 and must also be refused");
    }

    /// The base point is 5, and it is the *first* byte.
    ///
    /// Little endian, so a big-endian encoding puts it last - and a
    /// public key computed from the wrong base point is still a point,
    /// on the same curve, that nobody else will agree with.
    #[test]
    fn test_the_base_point_is_five_little_endian() {
        assert_eq!(BASE_POINT[0], 5);
        assert!(BASE_POINT[1..].iter().all(|b| *b == 0));
        let mut big_endian = BASE_POINT;
        big_endian.reverse();
        assert_eq!(BigUint::from_bytes_be(&big_endian), BigUint::from_u64(5));
    }

    /// X448 and X25519 must not be interchangeable by accident.
    ///
    /// Same shape, same function names, different constants - so the one
    /// mistake no vector catches is calling the wrong `a24` or the wrong
    /// clamp. This asserts the two modules' constants differ, which is
    /// the property that makes them two curves.
    #[test]
    fn test_the_two_montgomery_curves_share_no_constant() {
        assert_ne!(BASE_POINT[0], crate::ec::x25519::BASE_POINT[0],
                   "the base points are 5 and 9");
        assert_ne!(KEY_LEN, 32);
        // X25519's clamp on a 32 byte scalar clears three low bits; ours
        // clears two. A shared implementation would have to pick one.
        let ours = clamp(&[0xffu8; KEY_LEN]);
        let theirs = crate::ec::x25519::clamp(&[0xffu8; 32]);
        assert_ne!(ours[0], theirs[0],
                   "the two clampings agree on the low byte, so one of \
                    them is wrong");
    }
}
