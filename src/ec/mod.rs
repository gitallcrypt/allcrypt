/*
Elliptic curves over prime fields, short Weierstrass form:

    y^2 = x^3 + a*x + b   (mod p)

Points are stored affine and computed in Jacobian coordinates, where the
affine (x, y) is (X/Z^2, Y/Z^3). That trades one modular inversion per
operation for a handful of multiplications, and the single inversion is paid
once at the end when converting back.

Built against docs/pitfalls.md section 2, which was written before this file
existed. The three things it warns about, and what is done here:

  * **Invalid curve attacks.** Every point that comes from outside is checked:
    coordinates in [0, p), satisfies the curve equation, not the identity.
    `Curve::validate` is that check and `decode_point` always calls it.

  * **Incomplete addition formulas.** The Jacobian addition formula silently
    computes the wrong answer when the two inputs are equal, and cannot
    represent the identity as an input. Both cases are branched on explicitly
    in `add_jacobian`, and there are tests for P+P, P+(-P) and P+O.

  * **Scalar leakage.** `scalar_mul` is double-and-add and is variable time,
    which is correct for a public scalar. `scalar_mul_ct` is a Montgomery
    ladder that does one addition and one doubling per bit regardless of its
    value; use that for a private key.

The arithmetic in this file is `BigUint`'s modular operations: readable,
variable time, and kept as the reference the other two implementations are
tested against, and as the path for public scalars on fields wider than
nine limbs. Scalar multiplication goes to `ec::fixed` (fixed-size arrays in
the Montgomery domain, every field up to 576 bits) and otherwise to `ec::ct`
(the same on `bignum::ct::Secret`, for any width).
*/

pub mod ct;
pub mod curves;
pub mod ecdsa;
pub mod eddsa;
mod edwards;
mod field25519;
mod fixed;
mod field448;
pub mod gost3410;
pub mod sm2;
pub mod vko;
pub mod x25519;
pub mod x448;
pub mod xeddsa;
#[cfg(test)]
mod x448_vectors;

pub use ecdsa::Signature;

use crate::bignum::ct::Secret;
use crate::bignum::BigUint;

/// A point in affine coordinates. `None` is the point at infinity, the group
/// identity, which has no affine representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    coords: Option<(BigUint, BigUint)>,
}

impl Point {
    pub fn identity() -> Point {
        Point { coords: None }
    }

    pub fn new(x: BigUint, y: BigUint) -> Point {
        Point { coords: Some((x, y)) }
    }

    pub fn is_identity(&self) -> bool {
        self.coords.is_none()
    }

    pub fn x(&self) -> Option<&BigUint> {
        self.coords.as_ref().map(|(x, _)| x)
    }

    pub fn y(&self) -> Option<&BigUint> {
        self.coords.as_ref().map(|(_, y)| y)
    }
}

/// Jacobian coordinates. `z == 0` is the identity.
#[derive(Clone, Debug)]
struct Jacobian {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl Jacobian {
    fn identity() -> Jacobian {
        Jacobian { x: BigUint::one(), y: BigUint::one(), z: BigUint::zero() }
    }
    fn is_identity(&self) -> bool {
        self.z.is_zero()
    }
}

/// A curve and its parameters.
#[derive(Clone, Debug)]
pub struct Curve {
    pub name: &'static str,
    /// Field characteristic.
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    /// Base point.
    pub g: Point,
    /// Order of the base point.
    pub n: BigUint,
    /// Cofactor.
    pub h: BigUint,
}

impl Curve {
    // ------------------------------------------------- field arithmetic ---

    fn f_add(&self, x: &BigUint, y: &BigUint) -> BigUint {
        x.mod_add(y, &self.p).expect("p is non-zero")
    }
    fn f_sub(&self, x: &BigUint, y: &BigUint) -> BigUint {
        x.mod_sub(y, &self.p).expect("p is non-zero")
    }
    fn f_mul(&self, x: &BigUint, y: &BigUint) -> BigUint {
        x.mod_mul(y, &self.p).expect("p is non-zero")
    }
    fn f_sqr(&self, x: &BigUint) -> BigUint {
        self.f_mul(x, x)
    }
    /// Field inversion, by Fermat rather than by Euclid.
    ///
    /// This is called once per scalar multiplication, from `to_affine`, and
    /// its argument is the Jacobian Z coordinate - a value derived from the
    /// secret scalar. `mod_inverse` would run a number of iterations that
    /// depends on it. `p` is a prime by definition of a prime field, so
    /// `mod_inverse_prime` applies, and one extra exponentiation per scalar
    /// multiplication is a price worth paying.
    fn f_inv(&self, x: &BigUint) -> Result<BigUint, String> {
        x.mod_inverse_prime(&self.p)
    }

    // ----------------------------------------------------- validation ---

    /// Is the point on the curve? The identity counts as on the curve.
    pub fn is_on_curve(&self, point: &Point) -> bool {
        let (x, y) = match &point.coords {
            None => return true,
            Some(c) => c,
        };
        if x >= &self.p || y >= &self.p {
            return false;
        }
        // y^2 == x^3 + a*x + b
        let lhs = self.f_sqr(y);
        let x3 = self.f_mul(&self.f_sqr(x), x);
        let ax = self.f_mul(&self.a, x);
        let rhs = self.f_add(&self.f_add(&x3, &ax), &self.b);
        lhs == rhs
    }

    /// The check that must run on every point received from a peer.
    ///
    /// Skipping this is the invalid curve attack: arithmetic with a point
    /// that is not on the stated curve happens in a different, often much
    /// weaker group, and the result leaks the private scalar. Cheap, and
    /// non-negotiable.
    pub fn validate(&self, point: &Point) -> Result<(), String> {
        let (x, y) = match &point.coords {
            None => return Err("Point is the identity, which is not a valid peer key.".to_string()),
            Some(c) => c,
        };
        if x >= &self.p {
            return Err("Point x coordinate is not less than p.".to_string());
        }
        if y >= &self.p {
            return Err("Point y coordinate is not less than p.".to_string());
        }
        if !self.is_on_curve(point) {
            return Err(format!("Point is not on curve {}.", self.name));
        }
        // For a cofactor > 1 curve the point could still sit in a small
        // subgroup, and two here do: `gost256-tc26-a` and `gost512-c` have
        // h = 4. For h = 1, being on the curve and not the identity is
        // enough.
        if !self.h.is_one() {
            let scaled = self.scalar_mul(point, &self.n);
            if !scaled.is_identity() {
                return Err("Point is not in the prime order subgroup.".to_string());
            }
        }
        Ok(())
    }

    // ------------------------------------------------ point arithmetic ---

    fn to_jacobian(&self, point: &Point) -> Jacobian {
        match &point.coords {
            None => Jacobian::identity(),
            Some((x, y)) => Jacobian { x: x.clone(), y: y.clone(), z: BigUint::one() },
        }
    }

    fn to_affine(&self, j: &Jacobian) -> Result<Point, String> {
        if j.is_identity() {
            return Ok(Point::identity());
        }
        let z_inv = self.f_inv(&j.z)?;
        let z_inv2 = self.f_sqr(&z_inv);
        let z_inv3 = self.f_mul(&z_inv2, &z_inv);
        Ok(Point::new(self.f_mul(&j.x, &z_inv2), self.f_mul(&j.y, &z_inv3)))
    }

    /// Jacobian doubling.
    fn double_jacobian(&self, p: &Jacobian) -> Jacobian {
        // The identity doubles to itself, and so does a point with y = 0,
        // which is its own negation and therefore of order two.
        if p.is_identity() || p.y.is_zero() {
            return Jacobian::identity();
        }
        let yy = self.f_sqr(&p.y);
        let s = self.f_mul(&BigUint::from_u64(4), &self.f_mul(&p.x, &yy));
        let zz = self.f_sqr(&p.z);
        let m = self.f_add(
            &self.f_mul(&BigUint::from_u64(3), &self.f_sqr(&p.x)),
            &self.f_mul(&self.a, &self.f_sqr(&zz)),
        );
        let x3 = self.f_sub(&self.f_sqr(&m), &self.f_mul(&BigUint::from_u64(2), &s));
        let y3 = self.f_sub(
            &self.f_mul(&m, &self.f_sub(&s, &x3)),
            &self.f_mul(&BigUint::from_u64(8), &self.f_sqr(&yy)),
        );
        let z3 = self.f_mul(&BigUint::from_u64(2), &self.f_mul(&p.y, &p.z));
        Jacobian { x: x3, y: y3, z: z3 }
    }

    /// Jacobian addition.
    ///
    /// The three special cases below are the whole reason this is not a
    /// straight-line formula. Getting any of them wrong produces a function
    /// that is right for most inputs and wrong for a few, which a single test
    /// vector will not catch.
    fn add_jacobian(&self, p: &Jacobian, q: &Jacobian) -> Jacobian {
        if p.is_identity() {
            return q.clone();
        }
        if q.is_identity() {
            return p.clone();
        }

        let z1z1 = self.f_sqr(&p.z);
        let z2z2 = self.f_sqr(&q.z);
        let u1 = self.f_mul(&p.x, &z2z2);
        let u2 = self.f_mul(&q.x, &z1z1);
        let s1 = self.f_mul(&p.y, &self.f_mul(&z2z2, &q.z));
        let s2 = self.f_mul(&q.y, &self.f_mul(&z1z1, &p.z));

        if u1 == u2 {
            if s1 == s2 {
                // Same point: the addition formula divides by zero here, so
                // it has to become a doubling.
                return self.double_jacobian(p);
            }
            // P and -P: the sum is the identity.
            return Jacobian::identity();
        }

        let h = self.f_sub(&u2, &u1);
        let r = self.f_sub(&s2, &s1);
        let hh = self.f_sqr(&h);
        let hhh = self.f_mul(&hh, &h);
        let u1hh = self.f_mul(&u1, &hh);

        let x3 = self.f_sub(
            &self.f_sub(&self.f_sqr(&r), &hhh),
            &self.f_mul(&BigUint::from_u64(2), &u1hh),
        );
        let y3 = self.f_sub(
            &self.f_mul(&r, &self.f_sub(&u1hh, &x3)),
            &self.f_mul(&s1, &hhh),
        );
        let z3 = self.f_mul(&h, &self.f_mul(&p.z, &q.z));
        Jacobian { x: x3, y: y3, z: z3 }
    }

    pub fn add(&self, p: &Point, q: &Point) -> Point {
        let sum = self.add_jacobian(&self.to_jacobian(p), &self.to_jacobian(q));
        self.to_affine(&sum).expect("z is invertible unless the result is the identity")
    }

    pub fn double(&self, p: &Point) -> Point {
        let doubled = self.double_jacobian(&self.to_jacobian(p));
        self.to_affine(&doubled).expect("z is invertible unless the result is the identity")
    }

    /// The negation of a point: same x, negated y.
    pub fn negate(&self, p: &Point) -> Point {
        match &p.coords {
            None => Point::identity(),
            Some((x, y)) => {
                if y.is_zero() {
                    Point::new(x.clone(), BigUint::zero())
                } else {
                    Point::new(x.clone(), self.f_sub(&self.p, y))
                }
            }
        }
    }

    /// `k * point` for a public scalar: verification, validation, and
    /// anything else where `k` is not a secret.
    ///
    /// The four-bit window of `ec::fixed`, which is constant time though
    /// nothing here needs it to be; it is simply the fast path. Fields
    /// wider than `ec::fixed` handles go to `scalar_mul_double_and_add`.
    pub fn scalar_mul(&self, point: &Point, k: &BigUint) -> Point {
        if k.is_zero() || point.is_identity() {
            return Point::identity();
        }
        match fixed::scalar_mul(self, point, k.limbs()) {
            Some(Ok(product)) => product,
            _ => self.scalar_mul_double_and_add(point, k),
        }
    }

    /// `k * point`, double-and-add on `BigUint`.
    ///
    /// **Variable time in `k`**: the addition is skipped on a zero bit,
    /// and the arithmetic is `BigUint`'s. The fallback for public scalars
    /// on fields wider than nine limbs, and the reference the
    /// fixed-width and constant-time paths are tested against.
    pub(crate) fn scalar_mul_double_and_add(&self, point: &Point, k: &BigUint) -> Point {
        if k.is_zero() || point.is_identity() {
            return Point::identity();
        }
        let base = self.to_jacobian(point);
        let mut acc = Jacobian::identity();
        for i in (0..k.bit_len()).rev() {
            acc = self.double_jacobian(&acc);
            if k.bit(i) {
                acc = self.add_jacobian(&acc, &base);
            }
        }
        self.to_affine(&acc).expect("z is invertible unless the result is the identity")
    }

    /// `k * point` with neither the operation count nor the values
    /// depending on `k`.
    ///
    /// `ec::fixed`'s four-bit window on fixed-size arrays for every field
    /// of up to nine limbs, and `ec::ct`'s Montgomery ladder on `Secret`
    /// above that. Both read the table or swap the registers by mask, and
    /// neither's field arithmetic branches on a value. Use this for a
    /// private scalar.
    ///
    /// The loop runs over every bit of the scalar's **fixed width** - the
    /// field's - rather than the scalar's length, so a short secret costs
    /// what a long one does. It ran over the group order's bit length
    /// once, which is the same number on every curve here but P-521, whose
    /// order has 521 bits in a 576-bit width: there a scalar of 522 bits
    /// or more lost its top bits without a word, and (2^521 + 5)G came
    /// back as 5G.
    ///
    /// The width is the field's, or the group order's when that is wider.
    /// Hasse's bound lets n exceed p, and on a registered curve whose p
    /// sits just below a multiple of 2^64 a reduced scalar can need one
    /// more limb than the field; such a scalar was refused here, and
    /// `scalar_mul_ct` turned the refusal into a panic.
    ///
    /// It errors when the curve's parameters are unusable - an even `p`,
    /// which is not a prime field - and when `k` is wider than both. A
    /// caller with a real curve and a reduced scalar can treat it as
    /// infallible, and `scalar_mul_ct` below does.
    pub fn scalar_mul_secret(&self, point: &Point, k: &BigUint)
                             -> Result<Point, String> {
        let width = self.p.limbs().len().max(self.n.limbs().len());
        let scalar = Secret::from_biguint(k, width)?;
        self.scalar_mul_secret_bytes(point, &scalar)
    }

    /// `k * point` where the scalar is **already** a fixed-width `Secret`.
    ///
    /// The one to reach for when the scalar never was a `BigUint` - an
    /// RFC 6979 nonce, say, which comes out of an HMAC chain as bytes.
    /// Converting it to a number first would normalise it, and normalising
    /// a secret taints its length.
    pub fn scalar_mul_secret_bytes(&self, point: &Point, k: &Secret)
                                   -> Result<Point, String> {
        // The base point has a table of its multiples, which the scalar
        // must be below the order to use. That comparison is one bit
        // turned into a branch; for a key or a nonce, which are below the
        // order by construction, it is the same bit every time.
        if *point == self.g {
            if let Ok(order) = Secret::from_biguint(&self.n, k.width()) {
                if crate::bignum::montgomery::unmask(k.ct_lt(&order)) {
                    if let Some(product) = fixed::base_mul(self, k.limbs()) {
                        return product;
                    }
                }
            }
        }
        if let Some(product) = fixed::scalar_mul(self, point, k.limbs()) {
            return product;
        }
        let field = ct::Field::new(self)?;
        let base = field.from_point(point)?;
        let product = field.scalar_mul(&base, k, 64 * k.width());
        field.to_point(&product)
    }

    /// [`Curve::scalar_mul_secret`], panicking rather than erroring.
    ///
    /// Kept because every caller in this crate has a real curve and a
    /// scalar below the order, and the `Result` was noise at each of them.
    /// The failures it hides are a malformed curve and a scalar wider than
    /// both the field and the order, both construction bugs rather than
    /// anything a peer can cause: a scalar from outside is range-checked or
    /// reduced first. A public function that takes a scalar from its
    /// caller calls `scalar_mul_secret` instead and returns the error.
    pub fn scalar_mul_ct(&self, point: &Point, k: &BigUint) -> Point {
        self.scalar_mul_secret(point, k)
            .expect("a prime field curve, and a scalar no wider than its field or order")
    }

    /// `k * G`.
    pub fn generator_mul(&self, k: &BigUint) -> Point {
        self.scalar_mul(&self.g, k)
    }

    // ---------------------------------------------------------- keys ---

    /// A fresh key pair: a private scalar in `[1, n)` and its public point.
    ///
    /// The scalar comes from the OS generator through `random::below`, which
    /// is rejection sampled rather than reduced, so it is unbiased.
    pub fn generate_key_pair(&self) -> Result<(BigUint, Point), String> {
        let d = crate::random::below(&self.n)?;
        let q = self.scalar_mul_ct(&self.g, &d);
        Ok((d, q))
    }

    /// The shared secret x coordinate, for ECDH. Validates the peer's point
    /// first, and uses the constant-time ladder because the scalar is secret.
    ///
    /// The private scalar must be in `[1, n)`. Without the check, n + 1
    /// gave the same secret as 1 and a scalar wider than the field
    /// panicked in the ladder.
    pub fn ecdh(&self, private: &BigUint, peer: &Point) -> Result<Vec<u8>, String> {
        if private.is_zero() || *private >= self.n {
            return Err("The ECDH private scalar is not in [1, n).".to_string());
        }
        self.validate(peer)?;
        let shared = self.scalar_mul_secret(peer, private)?;
        match shared.x() {
            None => Err("Shared secret is the identity; the peer key was degenerate.".to_string()),
            Some(x) => x.to_bytes_be_padded(self.field_bytes()),
        }
    }

    // ------------------------------------------------------ encoding ---

    /// Bytes needed for one field element.
    pub fn field_bytes(&self) -> usize {
        self.p.bit_len().div_ceil(8)
    }

    /// Bytes in a private scalar: `ceil(log2(n) / 8)`, RFC 5915 section 3.
    ///
    /// From the group order, not the field. The two agree on every
    /// built-in curve, but Hasse's bound lets n exceed p, and a large
    /// cofactor makes it much smaller. At the field's width a scalar of
    /// the first kind did not fit, and one of the second kind was longer
    /// than the SEC1 parser accepts back.
    pub fn scalar_bytes(&self) -> usize {
        self.n.bit_len().div_ceil(8)
    }

    /// SEC1 encoding. Uncompressed is `04 || X || Y`; compressed is
    /// `02 || X` or `03 || X` depending on the parity of Y.
    pub fn encode_point(&self, point: &Point, compressed: bool) -> Result<Vec<u8>, String> {
        let (x, y) = match &point.coords {
            None => return Ok(vec![0x00]), // SEC1 encodes the identity as a single zero byte
            Some(c) => c,
        };
        let width = self.field_bytes();
        let mut out = Vec::with_capacity(1 + 2 * width);
        if compressed {
            out.push(if y.is_even() { 0x02 } else { 0x03 });
            out.extend_from_slice(&x.to_bytes_be_padded(width)?);
        } else {
            out.push(0x04);
            out.extend_from_slice(&x.to_bytes_be_padded(width)?);
            out.extend_from_slice(&y.to_bytes_be_padded(width)?);
        }
        Ok(out)
    }

    /// Decode a SEC1 point and **validate it**. Anything that arrives from a
    /// peer comes through here.
    pub fn decode_point(&self, bytes: &[u8]) -> Result<Point, String> {
        let width = self.field_bytes();
        if bytes.is_empty() {
            return Err("Empty point encoding.".to_string());
        }
        let point = match bytes[0] {
            0x00 => {
                if bytes.len() != 1 {
                    return Err("Identity encoding must be a single byte.".to_string());
                }
                return Ok(Point::identity());
            }
            0x04 => {
                if bytes.len() != 1 + 2 * width {
                    return Err(format!("Uncompressed point must be {} bytes, got {}.",
                                       1 + 2 * width, bytes.len()));
                }
                Point::new(BigUint::from_bytes_be(&bytes[1..1 + width]),
                           BigUint::from_bytes_be(&bytes[1 + width..]))
            }
            tag @ (0x02 | 0x03) => {
                if bytes.len() != 1 + width {
                    return Err(format!("Compressed point must be {} bytes, got {}.",
                                       1 + width, bytes.len()));
                }
                let x = BigUint::from_bytes_be(&bytes[1..]);
                if x >= self.p {
                    return Err("Point x coordinate is not less than p.".to_string());
                }
                // y^2 = x^3 + ax + b, then take the root with the right parity.
                let x3 = self.f_mul(&self.f_sqr(&x), &x);
                let rhs = self.f_add(&self.f_add(&x3, &self.f_mul(&self.a, &x)), &self.b);
                let mut y = self.sqrt(&rhs)?;
                let want_odd = tag == 0x03;
                if y.is_even() == want_odd {
                    y = self.f_sub(&self.p, &y);
                }
                Point::new(x, y)
            }
            other => return Err(format!("Unknown point encoding tag 0x{:02x}.", other)),
        };
        self.validate(&point)?;
        Ok(point)
    }

    /// Whether a compressed point can be decoded on this curve.
    ///
    /// Decompression needs a square root modulo p, and the one here is
    /// the `p = 3 mod 4` shortcut. Every NIST curve satisfies that and
    /// `gost256-b` does not - its p ends in `...c99`, which is 1 mod 4.
    /// So compression is a property of the curve rather than something
    /// every caller can assume, and asking for it on a curve that cannot
    /// do it is an error rather than a wrong point.
    pub fn supports_compression(&self) -> bool {
        self.p.rem(&BigUint::from_u64(4)).map(|r| r == BigUint::from_u64(3))
            .unwrap_or(false)
    }

    /// Modular square root, for `p = 3 mod 4` where it is `a^((p+1)/4)`.
    ///
    /// Most curves here satisfy that; `gost256-b` does not. A curve with
    /// `p = 1 mod 4` would need Tonelli-Shanks, so this errors rather
    /// than returning a wrong answer.
    fn sqrt(&self, a: &BigUint) -> Result<BigUint, String> {
        let three = BigUint::from_u64(3);
        let four = BigUint::from_u64(4);
        if self.p.rem(&four)? != three {
            return Err(format!("Square root on {} needs Tonelli-Shanks, which is not \
                                implemented.", self.name));
        }
        let exp = self.p.add(&BigUint::one()).div(&four)?;
        let root = a.mod_pow(&exp, &self.p)?;
        // The exponentiation always produces something; it is only a square
        // root if squaring it gets back where we started.
        if self.f_sqr(&root) != *a {
            return Err("Value is not a square modulo p; no such point exists.".to_string());
        }
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves;

    /// Above nine limbs there is no fixed-width path, and `scalar_mul`
    /// falls back to double-and-add. No registered curve is that wide, so
    /// the test makes one: `y^2 = x^3 + x - 1` over the Mersenne prime
    /// `2^607 - 1` (ten limbs), through `(1, 1)`. Its order is not known
    /// and not needed - five times a point is four additions of it.
    #[test]
    fn test_a_field_wider_than_nine_limbs_takes_double_and_add() {
        let p = BigUint::one().shl(607).sub(&BigUint::one()).unwrap();
        let mut curve = curves::p256();
        curve.name = "mersenne-607";
        curve.a = BigUint::one();
        curve.b = p.sub(&BigUint::one()).unwrap();
        curve.g = Point::new(BigUint::one(), BigUint::one());
        curve.p = p;
        assert!(curve.is_on_curve(&curve.g));
        let mut expected = curve.g.clone();
        for _ in 0..4 {
            expected = curve.add(&expected, &curve.g);
        }
        assert_eq!(curve.scalar_mul(&curve.g, &BigUint::from_u64(5)), expected);
    }

    /// The base point's table is only for scalars below the order; at
    /// and above it `scalar_mul_secret` must take the general path and
    /// still be right.
    #[test]
    fn test_a_secret_multiple_of_the_base_point_at_and_above_the_order() {
        for curve in [curves::p256(), curves::secp256k1(), curves::p521(),
                      curves::gost256_tc26_a()] {
            let n = &curve.n;
            let one = BigUint::one();
            // The widest scalar the call takes: all ones over its width.
            let width = curve.p.limbs().len().max(n.limbs().len());
            let widest = one.shl(64 * width).sub(&one).unwrap();
            for k in [n.sub(&one).unwrap(), n.clone(), n.add(&one), widest] {
                assert_eq!(curve.scalar_mul_secret(&curve.g, &k).unwrap(),
                           curve.scalar_mul_double_and_add(&curve.g, &k),
                           "{}: {}", curve.name, k.to_hex());
            }
        }
    }

    /// The strongest check that the hardcoded curve parameters are right:
    /// the base point must be on the curve, and multiplying it by the group
    /// order must give the identity. A typo in any parameter fails one of
    /// these.
    #[test]
    fn test_curve_parameters_are_self_consistent() {
        for curve in curves::all() {
            assert!(curve.is_on_curve(&curve.g), "{}: G is not on the curve", curve.name);
            assert!(curve.validate(&curve.g).is_ok(), "{}: G fails validation", curve.name);
            let should_be_identity = curve.scalar_mul(&curve.g, &curve.n);
            assert!(should_be_identity.is_identity(),
                    "{}: n*G is not the identity, so n or G is wrong", curve.name);
            // Compression needs a square root, and ours is the
            // `p = 3 mod 4` shortcut. `gost256-b` does not satisfy it -
            // so this asserts that `supports_compression` agrees with the
            // arithmetic rather than that every curve is the easy case.
            let easy = curve.p.rem(&BigUint::from_u64(4)).unwrap()
                == BigUint::from_u64(3);
            assert_eq!(curve.supports_compression(), easy,
                       "{}: supports_compression disagrees with p mod 4", curve.name);
        }
    }

    /// The edge scalars the pitfalls document calls out by name.
    #[test]
    fn test_edge_scalars() {
        for curve in curves::all() {
            let g = &curve.g;
            let n = &curve.n;

            assert!(curve.scalar_mul(g, &BigUint::zero()).is_identity(), "0*G");
            assert_eq!(curve.scalar_mul(g, &BigUint::one()), *g, "1*G");
            assert!(curve.scalar_mul(g, n).is_identity(), "n*G");

            // (n-1)*G == -G
            let n_minus_1 = n.sub(&BigUint::one()).unwrap();
            assert_eq!(curve.scalar_mul(g, &n_minus_1), curve.negate(g), "(n-1)*G == -G");

            // (n+1)*G == G
            let n_plus_1 = n.add(&BigUint::one());
            assert_eq!(curve.scalar_mul(g, &n_plus_1), *g, "(n+1)*G == G");

            // 2*G computed three ways must agree
            let two_g = curve.double(g);
            assert_eq!(curve.scalar_mul(g, &BigUint::from_u64(2)), two_g, "2*G via scalar_mul");
            assert_eq!(curve.add(g, g), two_g, "G+G must become a doubling");
        }
    }

    /// The addition formula's special cases, which a single test vector
    /// would sail straight past.
    #[test]
    fn test_addition_special_cases() {
        for curve in curves::all() {
            let g = &curve.g;
            let identity = Point::identity();

            assert_eq!(curve.add(g, &identity), *g, "P + O == P");
            assert_eq!(curve.add(&identity, g), *g, "O + P == P");
            assert_eq!(curve.add(&identity, &identity), identity, "O + O == O");
            assert!(curve.add(g, &curve.negate(g)).is_identity(), "P + (-P) == O");
            assert!(curve.double(&identity).is_identity(), "2*O == O");

            // P + P must route to doubling, not divide by zero.
            assert_eq!(curve.add(g, g), curve.double(g), "P + P == 2P");

            // Associativity on a few points, which catches sign and
            // coordinate mistakes the simpler identities miss.
            let p2 = curve.double(g);
            let p3 = curve.add(&p2, g);
            let p5 = curve.add(&p3, &p2);
            assert_eq!(p5, curve.scalar_mul(g, &BigUint::from_u64(5)), "5G two ways");
            assert_eq!(curve.add(&p3, &p2), curve.add(&p2, &p3), "addition commutes");
        }
    }

    /// The constant-time ladder must agree with the fast path everywhere.
    #[test]
    fn test_ladder_agrees_with_double_and_add() {
        for curve in curves::all() {
            for k in ["1", "2", "3", "7", "8", "ff", "100", "deadbeef",
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
                let k = BigUint::from_hex(k).unwrap();
                assert_eq!(curve.scalar_mul_double_and_add(&curve.g, &k),
                           curve.scalar_mul_ct(&curve.g, &k),
                           "{}: ladder disagrees for k={}", curve.name, k.to_hex());
            }
            // and for the edges
            assert!(curve.scalar_mul_ct(&curve.g, &BigUint::zero()).is_identity(), "0*G ladder");
            assert!(curve.scalar_mul_ct(&curve.g, &curve.n).is_identity(), "n*G ladder");
            // A scalar above the order, as wide as the field allows: the
            // ladder reads every bit of it. On P-521 the order is 521 bits
            // in a 576-bit width, and the top 55 were once ignored.
            let width = 64 * curve.field_bytes().div_ceil(8);
            let wide = BigUint::one().shl(width - 1).add(&BigUint::from_u64(5));
            assert_eq!(curve.scalar_mul_ct(&curve.g, &wide),
                       curve.scalar_mul_double_and_add(&curve.g, &wide),
                       "{}: a scalar of {width} bits", curve.name);
            // And one wider than the field is an error, not a wrong point.
            assert!(curve.scalar_mul_secret(&curve.g, &BigUint::one().shl(width)).is_err());
        }
    }

    /// Points that must be refused. This is the invalid curve attack check.
    #[test]
    fn test_validation_rejects_bad_points() {
        let curve = curves::p256();

        // On the curve in x but with a wrong y.
        let gx = curve.g.x().unwrap().clone();
        let bad_y = curve.f_add(curve.g.y().unwrap(), &BigUint::one());
        let off_curve = Point::new(gx.clone(), bad_y);
        assert!(!curve.is_on_curve(&off_curve));
        assert!(curve.validate(&off_curve).is_err(), "a point off the curve must be rejected");

        // Coordinates outside the field.
        assert!(curve.validate(&Point::new(curve.p.clone(), BigUint::one())).is_err());
        assert!(curve.validate(&Point::new(BigUint::one(), curve.p.clone())).is_err());

        // The identity is not a valid peer key.
        assert!(curve.validate(&Point::identity()).is_err());

        // And decoding must refuse it too, not just validate.
        let mut encoded = curve.encode_point(&curve.g, false).unwrap();
        encoded[40] ^= 0x01; // corrupt a y byte
        assert!(curve.decode_point(&encoded).is_err(), "decode must validate");
    }

    /// **The range check and the curve check are separate, and each must
    /// say what it found.**
    ///
    /// Removing `validate`'s `x >= p` test fails nothing, because
    /// `is_on_curve` bounds its coordinates too and reports "not on
    /// curve" for an out-of-range one. That is defence in depth rather
    /// than a hole - but a breakage sweep cannot tell the two apart, so
    /// the *reason* is pinned here. A caller told "not on curve" about
    /// a coordinate that is simply too large goes looking for the wrong
    /// bug.
    #[test]
    fn test_an_out_of_range_coordinate_says_so() {
        let curve = curves::p256();
        let y = curve.g.y().unwrap().clone();

        let reason = curve.validate(&Point::new(curve.p.clone(), y.clone()))
            .unwrap_err();
        assert!(reason.contains("x coordinate"), "{}", reason);

        let x = curve.g.x().unwrap().clone();
        let reason = curve.validate(&Point::new(x, curve.p.clone())).unwrap_err();
        assert!(reason.contains("y coordinate"), "{}", reason);

        // And a coordinate one below p is in range, so the message is
        // about the curve rather than the range - the boundary, not a
        // value far outside it.
        let just_under = sub_one(&curve.p);
        let reason = curve.validate(&Point::new(just_under.clone(), just_under))
            .unwrap_err();
        assert!(reason.contains("not on curve"), "{}", reason);
    }

    fn sub_one(value: &BigUint) -> BigUint {
        value.sub(&BigUint::one()).unwrap()
    }

    /// n*G is the identity on every curve, which is what makes `n` the
    /// order of the subgroup G generates.
    ///
    /// **This used to also assert that every curve had cofactor one**,
    /// and said why: with `h = 1`, `validate`'s subgroup branch is dead
    /// code, and a reader seeing the branch would otherwise assume
    /// small-subgroup attacks were covered by something tested. It said
    /// that adding a curve with `h > 1` would turn the branch on and
    /// that this test would be the first to fail. That is exactly what
    /// happened when `gost256-tc26-a` and `gost512-c` arrived, and the
    /// test below is the one it asked for.
    #[test]
    fn test_the_base_point_has_the_stated_order() {
        for curve in curves::all() {
            assert!(curve.scalar_mul(&curve.g, &curve.n).is_identity(),
                    "{}: n*G is not the identity, so n is not the order",
                    curve.name);
        }
    }

    /// A point on a cofactor-four curve that is not in the prime order
    /// subgroup is refused.
    ///
    /// The attack: on a curve whose group has order `h*n`, a peer can
    /// send a point of order 2 or 4 instead of one of order `n`. It is
    /// on the curve and it is not the identity, so the cheap checks
    /// pass - and the shared secret then lies in a group with four
    /// elements, which is the private scalar modulo 4 handed over for
    /// nothing. `validate` multiplies by `n` and insists on the
    /// identity, which is the only check that sees it.
    ///
    /// The point is **found rather than typed**: a curve here has order
    /// `4n`, so a point taken at random is outside the prime order
    /// subgroup three times in four. The search walks x upwards from 1
    /// and takes the first x that is on the curve and fails `n*P = O`,
    /// which is deterministic and needs no constant anybody could
    /// mistype.
    #[test]
    fn test_a_small_subgroup_point_is_refused() {
        let mut tried = 0;
        for curve in curves::all() {
            if curve.h.is_one() {
                continue;
            }
            assert!(curve.supports_compression(),
                    "{}: the search below needs a square root", curve.name);
            let mut found = None;
            for candidate in 1u64..200 {
                // `decode_point` validates, and a point outside the
                // subgroup is exactly what it refuses - which is the
                // thing being tested. So the point is built here
                // directly, without that check in the way.
                let x = BigUint::from_u64(candidate);
                let x3 = curve.f_mul(&curve.f_sqr(&x), &x);
                let rhs = curve.f_add(&curve.f_add(&x3, &curve.f_mul(&curve.a, &x)),
                                      &curve.b);
                let y = match curve.sqrt(&rhs) {
                    Ok(y) => y,
                    Err(_) => continue,
                };
                let point = Point::new(x, y);
                if !curve.is_on_curve(&point) {
                    continue;
                }
                if curve.scalar_mul(&point, &curve.n).is_identity() {
                    // In the prime order subgroup, and so a perfectly
                    // good peer key. Not what this test wants.
                    continue;
                }
                found = Some(point);
                break;
            }
            let point = found.unwrap_or_else(
                || panic!("{}: no point outside the prime order subgroup in \
                           200 tries, which on a cofactor {} curve means the \
                           search is broken rather than the curve",
                          curve.name, curve.h.to_u64().unwrap_or(0)));
            let reason = curve.validate(&point).unwrap_err();
            assert!(reason.contains("prime order subgroup"),
                    "{}: refused for the wrong reason: {}", curve.name, reason);
            tried += 1;
        }
        assert!(tried >= 2,
                "the two cofactor-four GOST curves are what this test is \
                 for; it found {}", tried);
    }

    /// **`ecdh` cannot produce the identity once `validate` has passed**,
    /// and the check for it is unreachable.
    ///
    /// With cofactor 1 and a validated non-identity peer point, `d * P`
    /// is the identity only when `d` is a multiple of `n` - and `d` is
    /// our own scalar, drawn below `n` and never zero. Removing the
    /// refusal fails no test for that reason.
    ///
    /// Kept as defence in depth, because the alternative is returning a
    /// shared secret of zeros, which is the single worst thing this
    /// function could do. Asserted here directly so the intent survives
    /// a future reader who runs a sweep and sees dead code.
    #[test]
    fn test_ecdh_refuses_a_degenerate_secret() {
        let curve = curves::p256();
        // `n * G` is the identity, so a scalar of n would produce it -
        // reachable only by calling the ladder directly. Through `ecdh`
        // the range check refuses n before the identity check is reached.
        assert!(curve.scalar_mul_ct(&curve.g, &curve.n).is_identity());
        assert!(curve.ecdh(&curve.n, &curve.g).is_err(),
                "a scalar that annihilates the peer point must not return a \
                 secret");

        // And the ordinary path still works, so this is not refusing
        // everything.
        let (private, _public) = curve.generate_key_pair().unwrap();
        assert!(curve.ecdh(&private, &curve.g).is_ok());
    }

    /// `ecdh` takes its scalar from the caller, so it checks `[1, n)`
    /// itself. Before the check, n + 1 returned the secret for 1, and a
    /// scalar wider than the field panicked in the ladder.
    #[test]
    fn test_ecdh_refuses_a_scalar_outside_the_group() {
        for curve in [curves::p256(), curves::p521()] {
            let (_, peer) = curve.generate_key_pair().unwrap();
            let wide = BigUint::one().shl(64 * 10);
            for scalar in [BigUint::zero(), curve.n.clone(), curve.n.add(&BigUint::one()),
                           wide] {
                let reason = curve.ecdh(&scalar, &peer).unwrap_err();
                assert!(reason.contains("[1, n)"), "{}: {}", curve.name, reason);
            }
            assert!(curve.ecdh(&curve.n.sub(&BigUint::one()).unwrap(), &peer).is_ok());
        }
    }

    #[test]
    fn test_point_encoding_roundtrip() {
        for curve in curves::all() {
            for k in [1u64, 2, 3, 1000, 65537] {
                let point = curve.scalar_mul(&curve.g, &BigUint::from_u64(k));
                for compressed in [false, true] {
                    let encoded = curve.encode_point(&point, compressed).unwrap();
                    let expected_len = if compressed { 1 + curve.field_bytes() }
                                       else { 1 + 2 * curve.field_bytes() };
                    assert_eq!(encoded.len(), expected_len, "{} encoding length", curve.name);

                    if compressed && !curve.supports_compression() {
                        // Not a skip: the point must fail to decode with a
                        // reason, rather than decoding to something else.
                        // Encoding one is still fine - it is a valid
                        // encoding, we simply cannot read it back.
                        assert!(curve.decode_point(&encoded).is_err(),
                                "{} decompressed a point it has no square root for",
                                curve.name);
                        continue;
                    }
                    assert_eq!(curve.decode_point(&encoded).unwrap(), point,
                               "{} roundtrip k={} compressed={}", curve.name, k, compressed);
                }
            }
            // identity
            let encoded = curve.encode_point(&Point::identity(), false).unwrap();
            assert_eq!(encoded, vec![0x00]);
            assert!(curve.decode_point(&encoded).unwrap().is_identity());
        }
    }

    #[test]
    fn test_decode_rejects_malformed() {
        let curve = curves::p256();
        assert!(curve.decode_point(&[]).is_err(), "empty");
        assert!(curve.decode_point(&[0x04, 0x01]).is_err(), "truncated uncompressed");
        assert!(curve.decode_point(&[0x02, 0x01]).is_err(), "truncated compressed");
        assert!(curve.decode_point(&[0x05; 65]).is_err(), "unknown tag");
        assert!(curve.decode_point(&[0x00, 0x00]).is_err(), "over long identity");
        // A compressed x with no square root must be refused, not fudged.
        let mut found_non_residue = false;
        for candidate in 1u64..40 {
            let mut enc = vec![0x02];
            enc.extend_from_slice(&BigUint::from_u64(candidate).to_bytes_be_padded(32).unwrap());
            if curve.decode_point(&enc).is_err() {
                found_non_residue = true;
                break;
            }
        }
        assert!(found_non_residue, "expected at least one x with no corresponding point");
    }

    /// ECDH: both sides must arrive at the same secret, and a bad peer key
    /// must be refused rather than used.
    #[test]
    fn test_ecdh_agrees_and_validates() {
        let curve = curves::p256();
        let (d_a, q_a) = curve.generate_key_pair().unwrap();
        let (d_b, q_b) = curve.generate_key_pair().unwrap();

        let secret_a = curve.ecdh(&d_a, &q_b).unwrap();
        let secret_b = curve.ecdh(&d_b, &q_a).unwrap();
        assert_eq!(secret_a, secret_b, "both sides must derive the same secret");
        assert_eq!(secret_a.len(), curve.field_bytes());

        // Two key pairs must differ; this would catch a broken random source.
        assert_ne!(d_a, d_b);

        let off_curve = Point::new(q_b.x().unwrap().clone(),
                                   curve.f_add(q_b.y().unwrap(), &BigUint::one()));
        assert!(curve.ecdh(&d_a, &off_curve).is_err(),
                "ECDH must refuse a peer point that is not on the curve");
    }
}
