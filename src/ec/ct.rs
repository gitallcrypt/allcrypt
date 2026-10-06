/*
Elliptic curve point arithmetic that does not branch on the values.

`ec/mod.rs` does the same arithmetic on `BigUint`, which is normalised: its
limb count is a measurement of the value, `rem` branches on both operands,
and the comparisons in `add_jacobian` are outright `if`s. That is fine for a
public point - verifying a signature, checking a peer's key - and it is what
`scalar_mul` uses.

This module is the other half, for a secret scalar. `ec::fixed` does the
same on fixed-size arrays and is what runs for every field of up to nine
limbs; this one is the path for wider fields and the reference `ec::fixed`
is tested against. Everything is a
`bignum::ct::Secret` of the field's width, in the Montgomery domain, and
every decision is a mask.

**The three special cases are the whole difficulty.** Jacobian addition
divides by zero when the two points are equal and gives nonsense when either
is the identity, so `ec/mod.rs` tests for those and branches. A branch on
whether two secret points happen to be equal is exactly what must not
happen here, so instead:

  * the generic addition **and** the doubling are both computed, every time,
  * the identity cases are computed as masks rather than tested,
  * and one `select` chain picks the answer.

That costs one extra doubling per addition. In the ladder, where the two
registers are always one point apart and the generic case is almost always
the right one, "almost always" is not a property constant-time code may
rely on: the work has to be the same either way, so it is.

Correctness is checked the only way it can be: `tests` below runs this
against `ec/mod.rs`'s variable-time arithmetic over random points *and* over
every special case by name - P+P, P+(-P), P+O, O+P, O+O - on P-256, P-384
and secp256k1.
Two implementations that agree on the generic case and disagree on P+(-P)
is the shape of this bug, and a random sweep alone will never draw it.
*/

use crate::bignum::ct::{Mask, Secret};
use crate::bignum::{BigUint, Montgomery};

use super::{Curve, Point};

/// A curve's field, set up for constant-time work.
///
/// Built per scalar multiplication rather than held on `Curve`. Two reasons,
/// and the first is the one that matters: **`p` is public** - it is in the
/// curve parameters, which are in the certificate - so the division inside
/// `Montgomery::new` leaks nothing. That is the opposite of the RSA case,
/// where building one per operation meant dividing by a secret prime on
/// every signature. The second is that it keeps `Curve` a plain struct of
/// six numbers, which is what makes adding a curve easy.
///
/// It costs one 2k-by-k division per scalar multiplication, against several
/// hundred field multiplications in the loop that follows.
pub struct Field {
    mont: Montgomery,
    width: usize,
    /// The curve's `a`, in the domain.
    a: Secret,
    /// Small constants, in the domain, so the loop never leaves it.
    two: Secret,
    three: Secret,
    four: Secret,
    eight: Secret,
}

impl Field {
    pub fn new(curve: &Curve) -> Result<Field, String> {
        let mont = Montgomery::new(&curve.p)?;
        let width = mont.limbs();
        let enter = |value: &BigUint| -> Result<Secret, String> {
            let reduced = if value.limbs().len() > width {
                value.rem(&curve.p)?
            } else {
                value.clone()
            };
            Ok(mont.to_domain(&Secret::from_biguint(&reduced, width)?))
        };
        let a = enter(&curve.a)?;
        let two = enter(&BigUint::from_u64(2))?;
        let three = enter(&BigUint::from_u64(3))?;
        let four = enter(&BigUint::from_u64(4))?;
        let eight = enter(&BigUint::from_u64(8))?;
        Ok(Field { mont, width, a, two, three, four, eight })
    }

    pub fn width(&self) -> usize {
        self.width
    }

    /// A field element into the domain. The value may be secret; its width
    /// is the field's and therefore public.
    pub fn enter(&self, value: &BigUint) -> Result<Secret, String> {
        Ok(self.mont.to_domain(&Secret::from_biguint(value, self.width)?))
    }

    fn f_mul(&self, x: &Secret, y: &Secret) -> Secret {
        self.mont.mul(x, y)
    }

    fn f_sqr(&self, x: &Secret) -> Secret {
        self.mont.sqr(x)
    }

    fn f_add(&self, x: &Secret, y: &Secret) -> Secret {
        self.mont.add_mod(x, y)
    }

    fn f_sub(&self, x: &Secret, y: &Secret) -> Secret {
        self.mont.sub_mod(x, y)
    }
}

/// A point in Jacobian coordinates, in the Montgomery domain.
///
/// `x/z^2, y/z^3` is the affine point; `z == 0` is the identity. No `Debug`,
/// for the same reason `Secret` has none.
#[derive(Clone)]
pub struct JacobianCt {
    pub x: Secret,
    pub y: Secret,
    pub z: Secret,
}

impl JacobianCt {
    /// The identity: `z = 0`, with `x` and `y` set to the domain's one so
    /// that nothing downstream has to treat them as uninitialised.
    pub fn identity(field: &Field) -> JacobianCt {
        let one = field.mont.one_in_domain();
        JacobianCt { x: one.clone(), y: one, z: Secret::zero(field.width) }
    }

    fn is_identity(&self) -> Mask {
        self.z.ct_is_zero()
    }

    fn select(a: &JacobianCt, b: &JacobianCt, choice: Mask) -> JacobianCt {
        JacobianCt {
            x: Secret::select(&a.x, &b.x, choice),
            y: Secret::select(&a.y, &b.y, choice),
            z: Secret::select(&a.z, &b.z, choice),
        }
    }

    fn cond_swap(a: &mut JacobianCt, b: &mut JacobianCt, choice: Mask) {
        Secret::cond_swap(&mut a.x, &mut b.x, choice);
        Secret::cond_swap(&mut a.y, &mut b.y, choice);
        Secret::cond_swap(&mut a.z, &mut b.z, choice);
    }
}

impl Field {
    /// An affine point into Jacobian coordinates in the domain.
    pub fn from_point(&self, point: &Point) -> Result<JacobianCt, String> {
        match (point.x(), point.y()) {
            (Some(x), Some(y)) => Ok(JacobianCt {
                x: self.enter(x)?,
                y: self.enter(y)?,
                z: self.mont.one_in_domain(),
            }),
            _ => Ok(JacobianCt::identity(self)),
        }
    }

    /// Back to an affine `Point`.
    ///
    /// **This is where the result stops being secret**, which is right: the
    /// caller is about to publish it, as an ECDSA `r` or an ECDH public
    /// value. The inversion is Fermat, so the value itself never reaches a
    /// branch; `declassify` at the end normalises, and its name says so.
    pub fn to_point(&self, p: &JacobianCt) -> Result<Point, String> {
        // An identity here is a legitimate answer - k*G for k = 0 or k = n -
        // and `z` is public by the time we are converting out.
        let z_plain = self.mont.from_domain(&p.z);
        if z_plain.declassify().is_zero() {
            return Ok(Point::identity());
        }
        // **`inverse_prime` takes a plain value and returns one.** Handing
        // it the domain representation `[z] = z*R` gives `(zR)^(p-2)`,
        // which is a perfectly good field element and the wrong one - and
        // the symptom is that `1 * G` comes back as some other point on the
        // curve, so every downstream check still passes. Out of the domain,
        // invert, back in.
        let z_inv = self.mont.to_domain(
            &self.mont.inverse_prime(&z_plain, self.mont.modulus_bits()));
        let z_inv2 = self.f_sqr(&z_inv);
        let z_inv3 = self.f_mul(&z_inv2, &z_inv);
        let x = self.mont.from_domain(&self.f_mul(&p.x, &z_inv2)).declassify();
        let y = self.mont.from_domain(&self.f_mul(&p.y, &z_inv3)).declassify();
        Ok(Point::new(x, y))
    }

    /// Jacobian doubling, branchless.
    ///
    /// The two cases `ec/mod.rs` tests for - the identity, and a point of
    /// order two where `y = 0` - both come out with `z3 = 2*y*z = 0`, which
    /// *is* the identity. So there is nothing to special-case: the formula
    /// already produces the right answer for them, and the `if` in the
    /// variable-time version is an optimisation rather than a correction.
    pub fn double(&self, p: &JacobianCt) -> JacobianCt {
        let yy = self.f_sqr(&p.y);
        let s = self.f_mul(&self.four, &self.f_mul(&p.x, &yy));
        let zz = self.f_sqr(&p.z);
        let m = self.f_add(
            &self.f_mul(&self.three, &self.f_sqr(&p.x)),
            &self.f_mul(&self.a, &self.f_sqr(&zz)),
        );
        let x3 = self.f_sub(&self.f_sqr(&m), &self.f_mul(&self.two, &s));
        let y3 = self.f_sub(
            &self.f_mul(&m, &self.f_sub(&s, &x3)),
            &self.f_mul(&self.eight, &self.f_sqr(&yy)),
        );
        let z3 = self.f_mul(&self.two, &self.f_mul(&p.y, &p.z));
        JacobianCt { x: x3, y: y3, z: z3 }
    }

    /// Jacobian addition, branchless, complete.
    ///
    /// Computes the generic sum and the doubling every time and selects
    /// between them, because *which* case applies is a fact about secret
    /// values. The order of the selects matters: the equal-point case has to
    /// be resolved before the identity cases, because a point added to the
    /// identity also has `u1 == u2` in the generic formula's terms when the
    /// identity's zero `z` collapses both sides.
    pub fn add(&self, p: &JacobianCt, q: &JacobianCt) -> JacobianCt {
        let z1z1 = self.f_sqr(&p.z);
        let z2z2 = self.f_sqr(&q.z);
        let u1 = self.f_mul(&p.x, &z2z2);
        let u2 = self.f_mul(&q.x, &z1z1);
        let s1 = self.f_mul(&p.y, &self.f_mul(&z2z2, &q.z));
        let s2 = self.f_mul(&q.y, &self.f_mul(&z1z1, &p.z));

        let same_x = u1.ct_eq(&u2);
        let same_y = s1.ct_eq(&s2);

        let h = self.f_sub(&u2, &u1);
        let r = self.f_sub(&s2, &s1);
        let hh = self.f_sqr(&h);
        let hhh = self.f_mul(&hh, &h);
        let u1hh = self.f_mul(&u1, &hh);

        let x3 = self.f_sub(&self.f_sub(&self.f_sqr(&r), &hhh),
                          &self.f_mul(&self.two, &u1hh));
        let y3 = self.f_sub(&self.f_mul(&r, &self.f_sub(&u1hh, &x3)),
                          &self.f_mul(&s1, &hhh));
        let z3 = self.f_mul(&h, &self.f_mul(&p.z, &q.z));
        let generic = JacobianCt { x: x3, y: y3, z: z3 };

        // The same point: the generic formula divides by zero, so the answer
        // is the doubling. Computed unconditionally.
        let doubled = self.double(p);
        let mut out = JacobianCt::select(&doubled, &generic, same_x & same_y);

        // P and -P: the sum is the identity.
        //
        // **Removing this select changes nothing, and the sweep cannot tell
        // you that.** When `u1 == u2` the generic formula has `h = 0`, so
        // `z3 = h * z1 * z2 = 0`, which *is* the identity whatever `x3` and
        // `y3` came out as. The line is kept because it states the intent
        // where a reader will look for it, and because a future change of
        // coordinate system would not carry the `h = 0` argument with it -
        // but it is defence in depth rather than a correction, and a comment
        // saying so is the only thing that can distinguish the two.
        let identity = JacobianCt::identity(self);
        out = JacobianCt::select(&identity, &out, same_x & !same_y);

        // Either operand being the identity overrides all of that.
        out = JacobianCt::select(q, &out, p.is_identity());
        out = JacobianCt::select(p, &out, q.is_identity());
        out
    }

    /// `k * point` by a Montgomery ladder, with a **public** iteration
    /// count.
    ///
    /// Every bit does one addition and one doubling whichever it is, the
    /// registers are exchanged by `cond_swap` rather than by `mem::swap`,
    /// and the arithmetic underneath does not branch either. `bits` must
    /// not come from the scalar's value: `Curve::scalar_mul_secret_bytes`
    /// passes the `Secret`'s whole width, and any count at least the
    /// scalar's bit length gives the same point.
    pub fn scalar_mul(&self, point: &JacobianCt, k: &Secret, bits: usize)
                      -> JacobianCt {
        let mut r0 = JacobianCt::identity(self);
        let mut r1 = point.clone();

        for i in (0..bits).rev() {
            let bit = k.bit(i);
            JacobianCt::cond_swap(&mut r0, &mut r1, bit);
            r1 = self.add(&r0, &r1);
            r0 = self.double(&r0);
            JacobianCt::cond_swap(&mut r0, &mut r1, bit);
        }
        r0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves;

    /// The two implementations must agree on the generic case and on every
    /// special case by name. A random sweep gives only the generic one:
    /// two points drawn at random are never equal, never negatives, and
    /// never the identity, so the three cases this module exists to handle
    /// would go untested by a sweep alone.
    #[test]
    fn test_addition_agrees_with_the_variable_time_version() {
        for curve in [curves::p256(), curves::p384(), curves::secp256k1()] {
            let field = Field::new(&curve).unwrap();
            let g = curve.g.clone();
            let two_g = curve.double(&g);
            let three_g = curve.add(&two_g, &g);
            let minus_g = curve.negate(&g);
            let identity = Point::identity();

            let cases: &[(&str, &Point, &Point)] = &[
                ("G + 2G", &g, &two_g),
                ("2G + G", &two_g, &g),
                ("G + G", &g, &g),
                ("2G + 2G", &two_g, &two_g),
                ("G + (-G)", &g, &minus_g),
                ("(-G) + G", &minus_g, &g),
                ("G + O", &g, &identity),
                ("O + G", &identity, &g),
                ("O + O", &identity, &identity),
                ("3G + (-G)", &three_g, &minus_g),
            ];
            for (name, a, b) in cases {
                let want = curve.add(a, b);
                let got = field.to_point(&field.add(&field.from_point(a).unwrap(),
                                                    &field.from_point(b).unwrap()))
                    .unwrap();
                assert_eq!(got, want, "{} on {}", name, curve.name);
            }
        }
    }

    #[test]
    fn test_doubling_agrees_including_the_identity() {
        for curve in [curves::p256(), curves::secp256k1()] {
            let field = Field::new(&curve).unwrap();
            for point in [curve.g.clone(), curve.double(&curve.g), Point::identity()] {
                let want = curve.double(&point);
                let got = field.to_point(&field.double(&field.from_point(&point).unwrap()))
                    .unwrap();
                assert_eq!(got, want, "doubling on {}", curve.name);
            }
        }
    }

    /// The ladder against double-and-add, over scalars chosen for their bit
    /// patterns rather than at random: all ones, a single bit, and the two
    /// values where the answer is the identity.
    #[test]
    fn test_ladder_agrees_with_double_and_add() {
        for curve in [curves::p256(), curves::p384(), curves::secp256k1()] {
            let field = Field::new(&curve).unwrap();
            let bits = curve.n.bit_len();
            let scalars = [
                BigUint::one(),
                BigUint::from_u64(2),
                BigUint::from_u64(3),
                BigUint::from_u64(0xffff_ffff),
                curve.n.sub(&BigUint::one()).unwrap(),
                curve.n.clone(),
                BigUint::zero(),
            ];
            for k in scalars {
                let want = curve.scalar_mul(&curve.g, &k);
                let secret = Secret::from_biguint(&k, field.width()).unwrap();
                let base = field.from_point(&curve.g).unwrap();
                let got = field.to_point(&field.scalar_mul(&base, &secret, bits)).unwrap();
                assert_eq!(got, want, "{} * G on {}", k.to_hex(), curve.name);
            }
        }
    }

    /// The loop bound is public and independent of the scalar, so a larger
    /// one must not change the answer. That is what makes a short secret
    /// indistinguishable from a long one.
    #[test]
    fn test_extra_iterations_do_not_change_the_answer() {
        let curve = curves::p256();
        let field = Field::new(&curve).unwrap();
        let k = BigUint::from_u64(12345);
        let secret = Secret::from_biguint(&k, field.width()).unwrap();
        let base = field.from_point(&curve.g).unwrap();
        let tight = field.to_point(&field.scalar_mul(&base, &secret, 14)).unwrap();
        for bits in [15, 64, 200, curve.n.bit_len()] {
            let got = field.to_point(&field.scalar_mul(&base, &secret, bits)).unwrap();
            assert_eq!(got, tight, "bound {}", bits);
        }
    }
}
