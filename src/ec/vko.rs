/*
VKO: the GOST key agreement, RFC 7836 section 4.3.

Diffie-Hellman with a nonce mixed into the scalar and a hash over the
result:

    KEK(d, Q, ukm) = Streebog( le(P.x) || le(P.y) ),  P = (ukm * d mod n) * Q

Both sides reach the same P, because `ukm * da * db * G` does not care
which order the multiplications happen in. That symmetry is the problem
with testing it: **two wrong implementations agree perfectly.** Get the
byte order wrong at any of the three places below and a round trip
against yourself still produces a matching key on both ends, and a real
peer gets a different one.

Three little endian conventions, in one function:

  * **The UKM is read little endian.** It is a byte string on the wire
    and an integer here, and GOST reads it the way it reads everything
    else.

  * **Both coordinates are written little endian** before hashing, x then
    y, each padded to the *field's* width - not the group order's, which
    is a different number that happens to have the same byte length on
    every curve here.

  * **Streebog's own convention** is already in the digest: the hash
    emits a byte string in array order, and that is what goes out.

And a fourth thing, which is not a byte order and is not settled by
any document: **the cofactor**.

RFC 7836 writes `K = (m/q * UKM * x mod q) * (y*P)`, where `m` is the
order of the whole group and `q` the order of the subgroup, so `m/q`
is the cofactor `h`.

On every curve with `h = 1` the term changes nothing, and seven of the
nine GOST curves are like that. Two are not - `gost256-tc26-a` and
`gost512-c`, both with `m = 4q` - and there `4P` and `P` are different
points, so an implementation that drops the term agrees with nobody.

**This was got wrong here, and the way it was got wrong is worth
keeping.** `VKO_compute_key` in gost-engine's `gost_ec_keyx.c` reads

    BN_mod_mul(scalar, scalar, priv, order);   /* no m/q here */
    gost_ec_point_mul(grp, pnt, NULL, pub, scalar);

which was taken as gost-engine omitting the cofactor, and a
`Cofactor::AsDeployed` variant was added to match it - with the TLS key
exchange using it, on the argument that its job is to reach a box and
the box runs gost-engine. **The reading was wrong.** Three lines below
that `BN_mod_mul` there is a disabled block and a comment saying so:

    #if 0
        /* These two curves have cofactor 4; the rest have cofactor 1.
         * But currently gost_ec_point_mul takes care of the cofactor
         * clearing, hence this code is not needed. */
        case NID_id_tc26_gost_3410_2012_256_paramSetA:
        case NID_id_tc26_gost_3410_2012_512_paramSetC:
            BN_lshift(scalar, scalar, 2);
    #endif

The cofactor is applied - inside the point multiplication, which is
generated code. So gost-engine computes RFC 7836's scalar after all, on
both of the curves that the disabled block names, which are exactly the
two with `h = 4`.

**Settled by measurement, not by a third reading.** `vectors/
gost_engine.vec`'s `vko-*` sections hold what
`openssl pkeyutl -derive` produces on all nine curves at both digest
sizes, and `tests/test_gost_engine_vectors.rs` shows that every one of
the eighteen rows is the document's reading. That is why the file
exists: a function read carefully is still a guess, and this one was a
wrong guess that would have derived a key no peer shares.

So `vko` follows the document, the TLS key exchange follows the
document, and `Cofactor::WithoutCofactor` stays only as the other
arithmetic - a negative control the tests use to show the rows can tell
the two apart, and a thing to try if some other implementation turns
out to have made the same mistake this one did.

`docs/pitfalls.md` 7o has the rest.

The digest size follows the key size: Streebog-256 for the 256 bit
curves, Streebog-512 for the 512 bit ones, which is what RFC 9189's
suites use.

Nothing on this machine implements VKO, so the check in
`scripts/diff_check.py` is a second reading of RFC 7836 - and it is worth
more here than usual, precisely because the symmetry means our two ends
agreeing proves nothing at all.
*/

use super::{Curve, Point};
use crate::bignum::BigUint;
use crate::hash_functions::streebog::Streebog;
use crate::hash_functions::HashFunction;

/// Whether the cofactor is part of VKO's scalar.
///
/// Two readings of the same agreement, and they differ only on a curve
/// whose cofactor is not one. Named as an enum rather than a boolean
/// because `vko(.., true)` at a call site says nothing about which
/// answer `true` is.
///
/// **`AsSpecified` is the one to use.** It is RFC 7836's and it is what
/// OpenSSL's GOST engine computes, which the `vko-*` rows of
/// `vectors/gost_engine.vec` establish on all nine curves. The variant
/// below is kept as the other arithmetic, not as anybody's behaviour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cofactor {
    /// `(m/q * UKM * x) mod q`, as RFC 7836 section 4.3 writes it, and
    /// as gost-engine computes it.
    AsSpecified,
    /// `(UKM * x) mod q` - the cofactor left out.
    ///
    /// **Named for the arithmetic and not for an implementation**,
    /// because it was previously called `AsDeployed` on the strength of
    /// a misreading of gost-engine's source, and a name that claims
    /// somebody does this is a name that can be false. Nothing known
    /// here does. It is kept because the distinction is real - the two
    /// give different keys on the two cofactor-four curves - so it
    /// serves as the negative control that stops a vector test passing
    /// on an implementation where the readings had collapsed into one.
    WithoutCofactor,
}

impl Cofactor {
    /// By name, for the API and the Python bindings.
    ///
    /// An unknown name is an error rather than a default. A default
    /// here is the whole bug: a caller who cannot say which reading
    /// they meant gets one silently, and finds out on a curve where
    /// the two differ, against a peer they cannot debug.
    pub fn by_name(name: &str) -> Result<Cofactor, String> {
        match name {
            "as-specified" => Ok(Cofactor::AsSpecified),
            "without-cofactor" => Ok(Cofactor::WithoutCofactor),
            // **Refused rather than aliased.** The old name claimed
            // that omitting the cofactor is what deployments do, and
            // it is not - gost-engine applies it. Accepting the name
            // silently would hand a caller who asked for "what the
            // equipment does" the one reading the equipment does not.
            "as-deployed" => Err(
                "The cofactor reading \"as-deployed\" no longer exists, and \
                 it was wrong: OpenSSL's GOST engine does apply RFC 7836's \
                 m/q term - inside its point multiplication, not in \
                 VKO_compute_key, where reading the source suggested \
                 otherwise. Use \"as-specified\", which is both the \
                 document's reading and the engine's; \"without-cofactor\" \
                 is the other arithmetic and matches nothing known."
                .to_string()),
            other => Err(format!(
                "Unknown cofactor reading {:?}. It is \"as-specified\" \
                 (RFC 7836, with the m/q term, and what OpenSSL's GOST \
                 engine computes) or \"without-cofactor\" (the term left \
                 out, which matches nothing known and exists to test the \
                 distinction). They differ only on a curve whose cofactor \
                 is not one.", other)),
        }
    }

    /// The name `by_name` takes, for a listing or an error message.
    pub fn name(self) -> &'static str {
        match self {
            Cofactor::AsSpecified => "as-specified",
            Cofactor::WithoutCofactor => "without-cofactor",
        }
    }
}

impl Curve {
    /// The VKO key encryption key.
    ///
    /// `ukm` is the user keying material: a nonce both sides know, which
    /// is what stops the same key pair producing the same KEK twice. It
    /// must not be zero - a zero UKM makes the scalar zero and the point
    /// the identity, which every pair of keys agrees on.
    ///
    /// `digest_bits` is 256 or 512, and follows the key rather than the
    /// curve: RFC 9189's 256 bit suites use Streebog-256 on a 256 bit
    /// curve, and its 512 bit ones use Streebog-512.
    pub fn vko(&self, private: &BigUint, peer: &Point, ukm: &[u8],
               digest_bits: usize) -> Result<Vec<u8>, String> {
        self.vko_using(private, peer, ukm, digest_bits, Cofactor::AsSpecified)
    }

    /// The same, saying which reading of the cofactor to use.
    pub fn vko_using(&self, private: &BigUint, peer: &Point, ukm: &[u8],
                     digest_bits: usize, cofactor: Cofactor)
                     -> Result<Vec<u8>, String> {
        if ukm.is_empty() {
            return Err("VKO needs a user keying material value.".to_string());
        }
        // Little endian, like everything else GOST reads as a number.
        // This is the only place that decision is made: `vko_with_ukm`
        // takes the integer, so a caller whose UKM is already a number
        // cannot pick up this convention by accident.
        let mut reversed = ukm.to_vec();
        reversed.reverse();
        self.vko_with_ukm_using(private, peer,
                                &BigUint::from_bytes_be(&reversed),
                                digest_bits, cofactor)
    }

    /// **VKO GOST R 34.10-2001**, RFC 4357 section 5.2 - the older key
    /// agreement, and what the 0x0081 cipher suite uses.
    ///
    /// Three differences from the 2012 one above, all of them silent:
    ///
    ///   * **The hash is GOST R 34.11-94**, with the CryptoPro
    ///     parameter set, not Streebog. Both are 256 bits, so the wrong
    ///     one produces a key of the right length that agrees with
    ///     nobody.
    ///   * **There is no cofactor.** RFC 4357 writes
    ///     `K = ((UKM*x) mod q) . (y.P)` with no `m/q` term, where RFC
    ///     7836 has one. Every curve a 2001 key can be on has cofactor
    ///     one, so the two agree in practice - and the term is left out
    ///     here because the document leaves it out, not because it
    ///     cannot matter.
    ///   * **The UKM is eight bytes** and comes from the handshake
    ///     rather than being drawn: the same value is the key wrap's
    ///     UKM, which is why RFC 4357 section 6.3 says to reuse it
    ///     rather than generate one.
    ///
    /// The point is encoded for hashing exactly as the 2012 version
    /// does - both coordinates little endian, padded to the field's
    /// width, x then y - because that is the convention the whole
    /// family shares and RFC 4357 does not restate it.
    pub fn vko_2001(&self, private: &BigUint, peer: &Point, ukm: &[u8])
                    -> Result<Vec<u8>, String> {
        use crate::hash_functions::gost94::Gost94;
        use crate::hash_functions::HashFunction;

        if ukm.is_empty() {
            return Err("VKO needs a user keying material value.".to_string());
        }
        if self.n.bit_len() > 256 {
            return Err(format!(
                "VKO GOST R 34.10-2001 is for 256 bit keys; {} is not.",
                self.name));
        }
        if private.is_zero() || *private >= self.n {
            return Err("Private scalar is not in [1, n).".to_string());
        }
        self.validate(peer)?;

        // Little endian, like every other GOST integer on a wire.
        let mut reversed = ukm.to_vec();
        reversed.reverse();
        let value = BigUint::from_bytes_be(&reversed).rem(&self.n)?;
        if value.is_zero() {
            return Err("The user keying material is zero modulo the group \
                        order, which makes the shared point the identity."
                       .to_string());
        }

        let scalar = value.mod_mul(private, &self.n)?;
        if scalar.is_zero() {
            return Err("The VKO scalar is zero, so there is no shared point."
                       .to_string());
        }
        let point = self.scalar_mul_ct(peer, &scalar);
        if point.is_identity() {
            return Err("The VKO exchange produced the identity, which is a \
                        shared secret an observer also has.".to_string());
        }

        let width = self.field_bytes();
        let x = point.x().ok_or("the identity has no x coordinate")?;
        let y = point.y().ok_or("the identity has no y coordinate")?;
        let mut input = x.to_bytes_be_padded(width)?;
        input.reverse();
        let mut y_bytes = y.to_bytes_be_padded(width)?;
        y_bytes.reverse();
        input.extend_from_slice(&y_bytes);

        Ok(Gost94::new(&input).digest())
    }

    /// VKO with the user keying material already an integer.
    ///
    /// RFC 9189's KEG takes `UKM = INT(H[1..16])` - a **big endian**
    /// reading of a hash prefix, the opposite convention from the wire
    /// form above. Having both callers go through a function that takes
    /// the number means each one states its own byte order once, rather
    /// than one of them inheriting the other's.
    pub fn vko_with_ukm(&self, private: &BigUint, peer: &Point, ukm: &BigUint,
                        digest_bits: usize) -> Result<Vec<u8>, String> {
        self.vko_with_ukm_using(private, peer, ukm, digest_bits,
                                Cofactor::AsSpecified)
    }

    /// The same, saying which reading of the cofactor to use.
    pub fn vko_with_ukm_using(&self, private: &BigUint, peer: &Point,
                              ukm: &BigUint, digest_bits: usize,
                              cofactor: Cofactor) -> Result<Vec<u8>, String> {
        if private.is_zero() || *private >= self.n {
            return Err("Private scalar is not in [1, n).".to_string());
        }
        // The peer's point is checked before any arithmetic touches it.
        // An invalid-curve point moves the whole exchange into a group
        // the peer chose, which is the attack this check exists for.
        self.validate(peer)?;
        if peer.is_identity() {
            return Err("The peer's public key is the identity, which makes \
                        every shared secret the same.".to_string());
        }
        if !matches!(digest_bits, 256 | 512) {
            return Err(format!(
                "VKO hashes with Streebog-256 or Streebog-512; {} is neither.",
                digest_bits));
        }

        let ukm_value = ukm.rem(&self.n)?;
        if ukm_value.is_zero() {
            return Err("The user keying material is zero modulo the group \
                        order, which makes the shared point the identity."
                       .to_string());
        }

        // **The cofactor, when the caller asked for the document's
        // reading** - which is the one to ask for. See the note at the
        // top of this file: RFC 7836 has `m/q` in the scalar, and so
        // does gost-engine, which was established by measuring it
        // rather than by reading `VKO_compute_key` a third time.
        //
        // Reduced modulo `n` rather than multiplied out, which is the
        // same point: the peer's key has order `n`, so a scalar and
        // its residue send it to the same place.
        let scalar = match cofactor {
            Cofactor::AsSpecified => ukm_value.mod_mul(private, &self.n)?
                                              .mod_mul(&self.h, &self.n)?,
            Cofactor::WithoutCofactor => ukm_value.mod_mul(private, &self.n)?,
        };
        if scalar.is_zero() {
            return Err("The VKO scalar is zero, so there is no shared point."
                       .to_string());
        }

        // The scalar is secret, so this is the constant-time path.
        let point = self.scalar_mul_ct(peer, &scalar);
        if point.is_identity() {
            return Err("The VKO exchange produced the identity, which is a \
                        shared secret an observer also has.".to_string());
        }

        // Both coordinates little endian, padded to the *field's* width -
        // not the group order's, which is a different number.
        let width = self.field_bytes();
        let x = point.x().ok_or("the identity has no x coordinate")?;
        let y = point.y().ok_or("the identity has no y coordinate")?;

        let mut input = x.to_bytes_be_padded(width)?;
        input.reverse();
        let mut y_bytes = y.to_bytes_be_padded(width)?;
        y_bytes.reverse();
        input.extend_from_slice(&y_bytes);

        Ok(if digest_bits == 256 {
            Streebog::new_256(&input).digest()
        } else {
            Streebog::new(&input).digest()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves;

    fn key(curve: &Curve, seed: u8) -> (BigUint, Point) {
        let mut bytes = vec![seed; curve.field_bytes()];
        bytes[0] &= 0x3f;
        let private = BigUint::from_bytes_be(&bytes);
        (private.clone(), curve.scalar_mul(&curve.g, &private))
    }

    /// The 2001 agreement, both ends, on the curves a 2001 key can be
    /// on.
    #[test]
    fn test_the_2001_agreement_agrees() {
        for name in ["gost256-a", "gost256-b", "gost256-c"] {
            let curve = curves::by_name(name).unwrap();
            let (da, qa) = key(&curve, 0x2b);
            let (db, qb) = key(&curve, 0x7d);
            let ukm = b"8 bytes!";
            let ours = curve.vko_2001(&da, &qb, ukm).unwrap();
            let theirs = curve.vko_2001(&db, &qa, ukm).unwrap();
            assert_eq!(ours, theirs, "{}", name);
            assert_eq!(ours.len(), 32);

            // **And it is not the 2012 one.** The two differ only in
            // which hash covers the shared point, so a key exchange
            // that reached for the wrong one would produce 32 bytes
            // either way and fail much later, in a Finished that does
            // not check. Stated as a comparison because that is the
            // mistake worth catching.
            let modern = curve.vko(&da, &qb, ukm, 256).unwrap();
            assert_ne!(ours, modern, "{}: 2001 and 2012 VKO agree", name);
        }
    }

    /// A 512 bit curve is refused rather than hashed with the wrong
    /// thing: GOST R 34.10-2001 has one key size.
    #[test]
    fn test_the_2001_agreement_refuses_a_512_bit_curve() {
        let curve = curves::by_name("gost512-a").unwrap();
        let (d, q) = key(&curve, 0x11);
        assert!(curve.vko_2001(&d, &q, b"8 bytes!").is_err());
    }

    /// Both sides must reach the same key. Necessary, and nowhere near
    /// sufficient - two implementations that read the UKM backwards
    /// together also pass this, which is what the differential corpus is
    /// for.
    #[test]
    fn test_both_sides_agree() {
        for name in curves::gost_names() {
            let curve = curves::by_name(name).unwrap();
            let (da, qa) = key(&curve, 0x2b);
            let (db, qb) = key(&curve, 0x7d);
            let ukm = b"shared nonce";

            for bits in [256usize, 512] {
                let ours = curve.vko(&da, &qb, ukm, bits).unwrap();
                let theirs = curve.vko(&db, &qa, ukm, bits).unwrap();
                assert_eq!(ours, theirs, "{} at {} bits", name, bits);
                assert_eq!(ours.len(), bits / 8);
            }
        }
    }

    /// The UKM is what stops one key pair producing one key forever.
    #[test]
    fn test_the_ukm_changes_the_key() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (da, _) = key(&curve, 0x11);
        let (_, qb) = key(&curve, 0x22);

        let first = curve.vko(&da, &qb, b"one", 256).unwrap();
        let second = curve.vko(&da, &qb, b"two", 256).unwrap();
        assert_ne!(first, second);

        // And it is read little endian, so a reversed UKM is a different
        // nonce. This is the check a round trip cannot make.
        let forwards = curve.vko(&da, &qb, &[1, 2, 3, 4], 256).unwrap();
        let backwards = curve.vko(&da, &qb, &[4, 3, 2, 1], 256).unwrap();
        assert_ne!(forwards, backwards,
                   "the UKM's byte order made no difference, so it is not \
                    being read as a number");
    }

    /// A UKM that is zero - empty, all zeros, or the group order - makes
    /// the scalar zero and the point the identity, which every pair of
    /// keys agrees on. That is a shared secret an observer also has.
    #[test]
    fn test_a_zero_ukm_is_refused() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (da, _) = key(&curve, 0x33);
        let (_, qb) = key(&curve, 0x44);

        assert!(curve.vko(&da, &qb, &[], 256).is_err());
        assert!(curve.vko(&da, &qb, &[0u8; 16], 256).is_err());

        let mut n_le = curve.n.to_bytes_be_padded(32).unwrap();
        n_le.reverse();
        assert!(curve.vko(&da, &qb, &n_le, 256).is_err(),
                "a UKM equal to the group order reduces to zero");
    }

    /// A peer point that is not on the curve moves the exchange into a
    /// group the peer chose.
    #[test]
    fn test_a_bad_peer_point_is_refused() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (da, _) = key(&curve, 0x55);

        assert!(curve.vko(&da, &Point::identity(), b"ukm", 256).is_err());

        // A point with the right shape and the wrong curve.
        let off = Point::new(BigUint::from_u64(2), BigUint::from_u64(3));
        assert!(curve.vko(&da, &off, b"ukm", 256).is_err());
    }

    #[test]
    fn test_the_parameters_are_checked() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (da, _) = key(&curve, 0x66);
        let (_, qb) = key(&curve, 0x77);

        assert!(curve.vko(&BigUint::zero(), &qb, b"u", 256).is_err());
        assert!(curve.vko(&curve.n, &qb, b"u", 256).is_err());
        assert!(curve.vko(&da, &qb, b"u", 384).is_err(), "only 256 and 512");
        assert!(curve.vko(&da, &qb, b"u", 0).is_err());
    }

    /// The two digest sizes are different hashes over the same input, not
    /// one truncated.
    #[test]
    fn test_the_two_digest_sizes_are_not_truncations() {
        let curve = curves::by_name("gost512-a").unwrap();
        let (da, _) = key(&curve, 0x88);
        let (_, qb) = key(&curve, 0x99);

        let short = curve.vko(&da, &qb, b"ukm", 256).unwrap();
        let long = curve.vko(&da, &qb, b"ukm", 512).unwrap();
        assert_eq!(short.len(), 32);
        assert_eq!(long.len(), 64);
        assert_ne!(short, long[..32].to_vec());
        assert_ne!(short, long[32..].to_vec());
    }

    /// VKO is not plain ECDH. The scalar carries the UKM and the output
    /// is a hash of both coordinates, so the two must not coincide.
    #[test]
    fn test_vko_is_not_ecdh() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (da, _) = key(&curve, 0xaa);
        let (_, qb) = key(&curve, 0xbb);

        let vko = curve.vko(&da, &qb, b"ukm", 256).unwrap();
        let ecdh = curve.ecdh(&da, &qb).unwrap();
        assert_ne!(vko, ecdh);
        // ECDH is the x coordinate alone; VKO hashes both.
        assert_eq!(ecdh.len(), curve.field_bytes());
    }

    /// The two readings of the scalar, swept over every GOST curve.
    ///
    /// Both halves matter. Agreeing wherever `h = 1` is what says
    /// `WithoutCofactor` is the same agreement and not some third
    /// thing; disagreeing wherever `h = 4` is what says the argument is
    /// read at all - without it, a `vko_using` that ignored its last
    /// parameter would pass on every curve but two, which is every
    /// curve anybody tests on.
    #[test]
    fn test_the_cofactor_readings_differ_exactly_where_the_cofactor_does() {
        let mut with_four = 0;
        for name in curves::gost_names() {
            let curve = curves::by_name(name).unwrap();
            let (da, _) = key(&curve, 0xc1);
            let (db, qb) = key(&curve, 0xd2);
            let qa = curve.scalar_mul(&curve.g, &da);

            let spec = curve.vko_using(&da, &qb, b"ukm", 256,
                                       Cofactor::AsSpecified).unwrap();
            let deployed = curve.vko_using(&da, &qb, b"ukm", 256,
                                           Cofactor::WithoutCofactor).unwrap();

            assert_eq!(curve.vko(&da, &qb, b"ukm", 256).unwrap(), spec,
                       "{name}: the default is no longer the document's");
            // Each reading is an agreement in its own right: the other
            // side reaches the same key under the same reading.
            assert_eq!(curve.vko_using(&db, &qa, b"ukm", 256,
                                       Cofactor::WithoutCofactor).unwrap(),
                       deployed,
                       "{name}: the cofactor-less reading is one-sided");

            if curve.h.is_one() {
                assert_eq!(spec, deployed,
                           "{name}: h = 1 and the readings differ");
            } else {
                assert_ne!(spec, deployed,
                           "{name}: h = {} and the cofactor changed nothing",
                           curve.h);
                with_four += 1;
            }
        }
        assert_eq!(with_four, 2,
                   "the cofactor-four curves are what this test is about");
    }

    /// The names the API and the Python bindings take.
    #[test]
    fn test_the_readings_are_named_and_an_unknown_name_is_refused() {
        assert_eq!(Cofactor::by_name("as-specified").unwrap(),
                   Cofactor::AsSpecified);
        assert_eq!(Cofactor::by_name("without-cofactor").unwrap(),
                   Cofactor::WithoutCofactor);
        for name in ["", "rfc7836", "WITHOUT-COFACTOR", "as specified",
                     "openssl"] {
            assert!(Cofactor::by_name(name).is_err(), "{name} was accepted");
        }
        // **The old name is refused, and the refusal says why.** It
        // meant "what the equipment does" and named the one reading the
        // equipment does not, so a silent alias would be worse than an
        // error - it would hand such a caller the wrong key.
        let refused = Cofactor::by_name("as-deployed").unwrap_err();
        assert!(refused.contains("does apply"), "{refused}");
        assert!(refused.contains("as-specified"), "{refused}");
        // Round trip, so the two tables cannot drift apart.
        for reading in [Cofactor::AsSpecified, Cofactor::WithoutCofactor] {
            assert_eq!(Cofactor::by_name(reading.name()).unwrap(), reading);
        }
    }
}
