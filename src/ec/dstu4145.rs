/*!
DSTU 4145-2002: Ukraine's elliptic-curve signature, over binary fields.

The curves are `y^2 + xy = x^3 + a·x^2 + b` over `GF(2^m)` in a
polynomial basis, `a` zero or one, with a base point `G` of prime order
`n` and a cofactor of 2 or 4. The standard names ten, `m` from 163 to
431 (`dstu4145-m163` to `dstu4145-m431`, numbered 0 to 9 as the last arc
of their object identifiers); a curve can also be given whole, as the
standard's own worked example and some certificates do. Its other
representation, the optimal normal basis, is not here.

## The signature

- The private key is `d` in `[1, n)`; the public key is **`Q = −d·G`**,
  the negation of what ECDSA would store.
- The hash, whatever its length, is read **little endian** - its bytes
  reversed - and the bits at and above `m` dropped, to give a field
  element `h`; zero becomes one.
- Signing: a random `e`, `F = x(e·G)`, `y = h·F` in the field, `r` the
  integer of `y`'s bits cut to `bit_len(n) − 1` bits, `s = (e + d·r) mod
  n`. Any of `F`, `r` or `s` zero means a new `e`.
- Verifying: `R = s·G + r·Q`, which is `e·G` when the signature is right,
  and `r` again from `h·x(R)`.

There is no inversion anywhere and no hash of the public key; the
multiplication that combines the hash with the point is in the field,
not modulo `n`.

## Arithmetic

`ec::gf2m` for the field. Scalar multiplication is a Montgomery ladder
on `x` alone in López and Dahab's projective coordinates - one addition
and one doubling for every bit, the two points swapped under a mask -
followed by their recovery of `y`. The scalar is first made `k + n` or
`k + 2n`, whichever has bit `bit_len(n)` set, so every ladder runs the
same number of steps for any scalar. The nonce, the private key and the
products with them stay in fixed-width `Secret`s and the Montgomery
domain over `n`, as `ec::gost3410`'s do. Verification adds two ladders'
results in affine coordinates, on public values.

## Point compression

The standard compresses a point to `x` with its **lowest bit replaced**
by the trace of `y/x`: every point of order `n` has `Tr(x) = a`, so that
bit can be recovered, and `y/x` is the solution of `z^2 + z = x + a +
b/x^2` that has the stored trace. The bytes are big endian here; a
certificate stores them reversed.

## Where the vectors come from

`src/ec/dstu4145_params.rs` is written by
`scripts/make_dstu4145_params.py` from Bouncy Castle's and cryptonite's
tables, which agree on every value. `vectors/dstu4145.vec`, written by
`scripts/make_dstu4145_vectors.py`, holds the standard's worked example,
public keys, compressions and signatures from Bouncy Castle 1.77 and
cryptonite, and both checking this library's own signatures.
*/

use crate::bignum::{BigUint, Montgomery, Secret};
use crate::ec::dstu4145_params::CURVES;
use crate::ec::gf2m::{Fe, Field};

/// A point: the identity, or affine coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Point {
    Infinity,
    Affine(Fe, Fe),
}

/// A curve and its base point.
#[derive(Clone, Debug)]
pub struct Curve {
    field: Field,
    a: u8,
    b: Fe,
    n: BigUint,
    h: u32,
    g: Point,
    number: Option<usize>,
}

/// The names of the standard's curves, by number.
pub const NAMES: [&str; 10] = ["dstu4145-m163", "dstu4145-m167", "dstu4145-m173",
                               "dstu4145-m179", "dstu4145-m191", "dstu4145-m233",
                               "dstu4145-m257", "dstu4145-m307", "dstu4145-m367",
                               "dstu4145-m431"];

/// Where a ladder's result stops being secret: it is returned to the
/// caller as a point, and whether it is the identity is a branch here.
/// For a scalar in `[1, n)` and a point of order `n` it never is. Not
/// inlined, so that `scripts/ct_check.py` can name the boundary.
#[inline(never)]
fn publish(infinity: u64, x: Fe, y: Fe) -> Point {
    if infinity == 1 {
        return Point::Infinity;
    }
    Point::Affine(x, y)
}

/// Where `r` stops being secret: it is half the signature, and
/// `BigUint` normalises it. Not inlined, for the same reason as
/// `publish`.
#[inline(never)]
fn publish_integer(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

fn hex_fe(field: &Field, hex: &str) -> Result<Fe, String> {
    field.from_bytes(&BigUint::from_hex(hex)?.to_bytes_be())
}

impl Curve {
    /// The standard's curve number `number`, 0 to 9.
    ///
    /// # Errors
    /// Any other number.
    pub fn named(number: usize) -> Result<Curve, String> {
        let p = CURVES.get(number).ok_or_else(|| format!(
            "DSTU 4145's named curves are numbered 0 to 9, not {number}."))?;
        let field = Field::new(p.m, p.terms)?;
        let b = hex_fe(&field, p.b)?;
        let g = Point::Affine(hex_fe(&field, p.gx)?, hex_fe(&field, p.gy)?);
        Ok(Curve { a: p.a, b, n: BigUint::from_hex(p.n)?, h: u32::from(p.h), g, field,
                   number: Some(number) })
    }

    /// A named curve by its name, `dstu4145-m163` to `dstu4145-m431`.
    ///
    /// # Errors
    /// Any other name.
    pub fn by_name(name: &str) -> Result<Curve, String> {
        let lower = name.to_ascii_lowercase();
        let number = NAMES.iter().position(|n| *n == lower).ok_or_else(|| format!(
            "Unknown DSTU 4145 curve {name:?}. Known: {}.", NAMES.join(", ")))?;
        Curve::named(number)
    }

    /// A curve given whole: the field's degree and reduction polynomial's
    /// exponents, `a` (0 or 1), `b`, the order `n` and the base point,
    /// field elements as big-endian bytes. The base point must be on the
    /// curve, of order `n`, and `n` must be prime-sized for the field;
    /// the cofactor is taken as the nearest `2^m / n`.
    ///
    /// # Errors
    /// Any of those failing.
    pub fn custom(m: usize, terms: &[usize], a: u8, b: &[u8], n: &BigUint, gx: &[u8],
                  gy: &[u8]) -> Result<Curve, String> {
        let mut curve = Curve::without_base_point(m, terms, a, b, n)?;
        let g = Point::Affine(curve.field.from_bytes(gx)?, curve.field.from_bytes(gy)?);
        curve.validate(&g)?;
        curve.g = g;
        Ok(curve)
    }

    /// A curve given whole but for its base point, which is the
    /// identity until `custom` is given one: what is needed to
    /// decompress a base point the parameters carry compressed. Nothing
    /// but `decompress` and `validate` belongs on it.
    ///
    /// # Errors
    /// As `custom`, but for the base point.
    pub fn without_base_point(m: usize, terms: &[usize], a: u8, b: &[u8], n: &BigUint)
                              -> Result<Curve, String> {
        let field = Field::new(m, terms)?;
        if a > 1 {
            return Err(format!("A DSTU 4145 curve's a is 0 or 1, not {a}."));
        }
        if n.bit_len() + 3 < m || n.bit_len() > m + 1 {
            return Err(format!("An order of {} bits does not belong to GF(2^{m}).",
                               n.bit_len()));
        }
        let b = field.from_bytes(b)?;
        // The cofactor that brings h·n nearest to 2^m (Hasse's bound puts
        // the group's order within 2^(m/2 + 1) of 2^m + 1).
        let h = BigUint::one().shl(m).add(&n.shr(1)).div(n)?;
        let h = u32::try_from(h.to_u64().ok_or("The cofactor is too large.")?)
            .map_err(|_| "The cofactor is too large.".to_string())?;
        Ok(Curve { field, a, b, n: n.clone(), h, g: Point::Infinity, number: None })
    }

    /// The standard's number for this curve when it is one of the ten,
    /// whether it was named or given whole: the same field, `a`, `b`,
    /// order and base point.
    pub fn matching_named(&self) -> Option<usize> {
        if self.number.is_some() {
            return self.number;
        }
        (0..CURVES.len()).find(|&i| {
            let named = Curve::named(i).expect("a named curve");
            named.field == self.field && named.a == self.a && named.b == self.b
                && named.n == self.n && named.g == self.g
        })
    }

    pub fn field(&self) -> &Field {
        &self.field
    }

    pub fn order(&self) -> &BigUint {
        &self.n
    }

    pub fn cofactor(&self) -> u32 {
        self.h
    }

    pub fn generator(&self) -> &Point {
        &self.g
    }

    pub fn a(&self) -> u8 {
        self.a
    }

    pub fn b(&self) -> &Fe {
        &self.b
    }

    /// The standard's number for a named curve.
    pub fn number(&self) -> Option<usize> {
        self.number
    }

    pub fn name(&self) -> Option<&'static str> {
        self.number.map(|i| NAMES[i])
    }

    fn a_fe(&self) -> Fe {
        let mut a = self.field.zero();
        a[0] = u64::from(self.a);
        a
    }

    /// Whether an affine point satisfies `y^2 + xy = x^3 + a·x^2 + b`.
    pub fn is_on_curve(&self, p: &Point) -> bool {
        let Point::Affine(x, y) = p else { return true };
        let f = &self.field;
        let x2 = f.square(x);
        let left = f.add(&f.square(y), &f.mul(x, y));
        let mut right = f.add(&f.mul(&x2, x), &self.b);
        if self.a == 1 {
            right = f.add(&right, &x2);
        }
        left == right
    }

    /// A point from outside: on the curve, not the identity, and in the
    /// subgroup of order `n` - which the cofactor makes a real check,
    /// since a point of order 2 or 4 gives away the private key modulo
    /// it in any exchange.
    ///
    /// # Errors
    /// Any of those failing.
    pub fn validate(&self, p: &Point) -> Result<(), String> {
        if *p == Point::Infinity {
            return Err("The point at infinity is not a public key.".to_string());
        }
        if !self.is_on_curve(p) {
            return Err("The point is not on the curve.".to_string());
        }
        if let Point::Affine(x, _) = p {
            if self.field.is_zero(x) {
                return Err("A point with x = 0 has order 2.".to_string());
            }
        }
        // A point whose order divides the cofactor is refused first, so
        // that the ladder below, which cannot pass through the identity,
        // never meets it before the end.
        let mut small = p.clone();
        for _ in 0..self.h.trailing_zeros() {
            small = self.double(&small);
        }
        if small == Point::Infinity {
            return Err("The point's order divides the cofactor.".to_string());
        }
        if self.ladder(&self.n, self.n.bit_len(), p) != Point::Infinity {
            return Err("The point is not in the subgroup of order n.".to_string());
        }
        Ok(())
    }

    pub fn neg(&self, p: &Point) -> Point {
        match p {
            Point::Infinity => Point::Infinity,
            Point::Affine(x, y) => Point::Affine(*x, self.field.add(x, y)),
        }
    }

    /// `p + q` in affine coordinates, every case; variable time, for
    /// public points.
    pub fn add(&self, p: &Point, q: &Point) -> Point {
        let f = &self.field;
        let (Point::Affine(x1, y1), Point::Affine(x2, y2)) = (p, q) else {
            return if *p == Point::Infinity { q.clone() } else { p.clone() };
        };
        if x1 == x2 {
            // Either the same point, or each other's negation; the
            // point with x = 0 is its own, and `double` answers for it.
            if *y2 != *y1 {
                return Point::Infinity;
            }
            return self.double(p);
        }
        let lambda = f.mul(&f.add(y1, y2), &f.invert(&f.add(x1, x2)));
        let mut x3 = f.add(&f.add(&f.square(&lambda), &lambda), &f.add(x1, x2));
        x3 = f.add(&x3, &self.a_fe());
        let y3 = f.add(&f.add(&f.mul(&lambda, &f.add(x1, &x3)), &x3), y1);
        Point::Affine(x3, y3)
    }

    /// `2p`.
    pub fn double(&self, p: &Point) -> Point {
        let f = &self.field;
        let Point::Affine(x, y) = p else { return Point::Infinity };
        if f.is_zero(x) {
            return Point::Infinity;
        }
        let lambda = f.add(x, &f.mul(y, &f.invert(x)));
        let x3 = f.add(&f.add(&f.square(&lambda), &lambda), &self.a_fe());
        let y3 = f.add(&f.square(x), &f.mul(&f.add(&lambda, &f.one()), &x3));
        Point::Affine(x3, y3)
    }

    /// The scalar's width in limbs: room for `k + 2n`.
    fn width(&self) -> usize {
        (self.n.bit_len() + 2).div_ceil(64)
    }

    /// `k·p` for a public `k` of any size; the ladder, reduced first.
    pub fn mul(&self, k: &BigUint, p: &Point) -> Point {
        let k = k.rem(&self.n).expect("n is not zero");
        let secret = Secret::from_biguint(&k, self.width()).expect("k is below n");
        self.mul_secret(&secret, p)
    }

    /// `k·p` for a secret `k` below `n`, by the ladder: the same steps for
    /// every `k`. `p` must not have `x = 0` (order 2), which `validate`
    /// refuses.
    pub fn mul_secret(&self, k: &Secret, p: &Point) -> Point {
        let f = &self.field;
        let Point::Affine(x, _) = p else { return Point::Infinity };
        if f.is_zero(x) {
            // Order two: k·p is p or the identity, by k's parity. Only a
            // caller that skipped `validate` gets here.
            return if k.bit(0) != 0 { p.clone() } else { Point::Infinity };
        }
        let width = self.width();
        let n = Secret::from_biguint(&self.n, width).expect("n fits its own width");
        let k = k.resize(width).expect("k fits");
        // k + n or k + 2n, whichever has bit `top` set: the ladder then
        // always starts at that bit. Adding multiples of n changes
        // nothing for a point of order n, which is every point that has
        // been through `validate`.
        let top = self.n.bit_len();
        let (k1, _) = k.add(&n);
        let (k2, _) = k1.add(&n);
        let scalar = Secret::select(&k1, &k2, k1.bit(top));
        self.ladder_bits(|i| scalar.bit(i) & 1, top + 1, p)
    }

    /// `k·p` for a public `k` exactly as given, not reduced modulo `n`:
    /// the ladder from `k`'s top bit, `bits` of them.
    fn ladder(&self, k: &BigUint, bits: usize, p: &Point) -> Point {
        if k.is_zero() {
            return Point::Infinity;
        }
        self.ladder_bits(|i| u64::from(k.bit(i)), bits, p)
    }

    /// The ladder over a scalar whose bit `bits − 1` is set, read by
    /// `bit`, on `p` with `x ≠ 0`.
    fn ladder_bits(&self, bit: impl Fn(usize) -> u64, bits: usize, p: &Point) -> Point {
        let f = &self.field;
        let Point::Affine(x, y) = p else { return Point::Infinity };
        let top = bits - 1;
        let one = f.one();
        let (mut x1, mut z1) = (*x, one);
        let x_sq = f.square(x);
        let (mut x2, mut z2) = (f.add(&f.square(&x_sq), &self.b), x_sq);
        let mut swapped = 0u64;
        for i in (0..top).rev() {
            let bit = bit(i);
            f.cswap(&mut x1, &mut x2, swapped ^ bit);
            f.cswap(&mut z1, &mut z2, swapped ^ bit);
            swapped = bit;
            // (x2, z2) = R0 + R1, whose difference is p.
            let t1 = f.mul(&x1, &z2);
            let t2 = f.mul(&x2, &z1);
            z2 = f.square(&f.add(&t1, &t2));
            x2 = f.add(&f.mul(x, &z2), &f.mul(&t1, &t2));
            // (x1, z1) = 2 R0.
            let x1_sq = f.square(&x1);
            let z1_sq = f.square(&z1);
            z1 = f.mul(&x1_sq, &z1_sq);
            x1 = f.add(&f.square(&x1_sq), &f.mul(&self.b, &f.square(&z1_sq)));
        }
        f.cswap(&mut x1, &mut x2, swapped);
        f.cswap(&mut z1, &mut z2, swapped);

        // R0 = k·p and R1 = (k + 1)·p; y from the two x's and p. The two
        // special cases - k·p the identity (z1 = 0), and (k + 1)·p the
        // identity so that k·p = −p (z2 = 0) - are chosen by mask, since
        // k may be secret; an inverse of zero is zero, so the general
        // formula's answer in those cases is computed and discarded. In
        // the second, R0's x is already p's - −p shares it - so only y is
        // chosen.
        let infinity = f.zero_bit(&z1);
        let minus_p = f.zero_bit(&z2);
        let xa = f.mul(&x1, &f.invert(&z1));
        let xb = f.mul(&x2, &f.invert(&z2));
        let u = f.add(&xa, x);
        let v = f.add(&f.add(&f.mul(&u, &f.add(&xb, x)), &x_sq), y);
        let ya = f.add(&f.mul(&f.mul(&u, &v), &f.invert(x)), y);
        let yr = f.select(&ya, &f.add(x, y), minus_p);
        publish(infinity, xa, yr)
    }

    /// The private scalar's checks and fixed-width form.
    ///
    /// The key crosses into fixed width first, reading its limb count -
    /// the same on every call with one key - and the range test is a
    /// mask: `d.is_zero() || *d >= n` would run `BigUint::cmp`, which
    /// returns at the first limb that differs.
    fn private(&self, d: &BigUint) -> Result<Secret, String> {
        let d = Secret::from_biguint(d, self.width())
            .map_err(|_| "A DSTU 4145 private key is in [1, n).".to_string())?;
        self.check_scalar(&d, "A DSTU 4145 private key is in [1, n).")?;
        Ok(d)
    }

    /// A secret scalar's range test, `[1, n)`, folded into one mask so that
    /// what is visible is the verdict alone.
    fn check_scalar(&self, k: &Secret, message: &str) -> Result<(), String> {
        let n = Secret::from_biguint(&self.n, self.width())?;
        if crate::bignum::montgomery::unmask(k.ct_is_zero() | !k.ct_lt(&n)) {
            return Err(message.to_string());
        }
        Ok(())
    }

    /// The public key, `Q = −d·G`.
    ///
    /// # Errors
    /// `d` outside `[1, n)`.
    pub fn public_key(&self, d: &BigUint) -> Result<Point, String> {
        let d = self.private(d)?;
        Ok(self.neg(&self.mul_secret(&d, &self.g)))
    }

    /// A new private key, uniform in `[1, n)`, and its public key.
    ///
    /// # Errors
    /// The system random source failing.
    pub fn generate(&self) -> Result<(BigUint, Point), String> {
        let bits = self.n.bit_len();
        loop {
            // Rejection sampling below 2^bit_len(n), on the bytes: the
            // verdict is the one thing that leaves.
            let mut bytes = crate::random::bytes(bits.div_ceil(8))?;
            bytes[0] &= 0xff >> (8 * bytes.len() - bits);
            let d = Secret::from_bytes_be(&bytes, self.width())?;
            if self.check_scalar(&d, "").is_ok() {
                let q = self.neg(&self.mul_secret(&d, &self.g));
                return Ok((BigUint::from_bytes_be(&bytes), q));
            }
        }
    }

    /// The hash as a field element: its bytes reversed, the bits at and
    /// above `m` dropped, and zero made one.
    pub fn hash_to_field(&self, hash: &[u8]) -> Fe {
        let f = &self.field;
        let mut out = f.zero();
        for (i, &byte) in hash.iter().enumerate() {
            for bit in 0..8 {
                let at = 8 * i + bit;
                if at < f.degree() && (byte >> bit) & 1 == 1 {
                    out[at / 64] |= 1 << (at % 64);
                }
            }
        }
        if f.is_zero(&out) { f.one() } else { out }
    }

    /// `r` from `y = h·x(e·G)`: the integer of `y`'s bits cut to
    /// `bit_len(n) − 1`. The cut is on the bytes, at positions that depend
    /// on `n` alone, and then `r` is half the signature and public.
    fn truncate(&self, y: &Fe) -> BigUint {
        let mut bytes = self.field.to_bytes(y);
        let bits = self.n.bit_len() - 1;
        let keep = bits.div_ceil(8);
        let drop = bytes.len() - keep;
        for byte in &mut bytes[..drop] {
            *byte = 0;
        }
        bytes[drop] &= 0xff >> (8 * keep - bits);
        publish_integer(&bytes)
    }

    /// Sign with an explicit `e`, big endian, as the standard's worked
    /// example does.
    ///
    /// **A caller that passes an `e` it did not choose uniformly, or
    /// passes one twice, gives away the private key**: `s − e = d·r`.
    /// `sign` is the one to use.
    ///
    /// # Errors
    /// `d` or `e` outside `[1, n)`, or an `e` that makes `r` or `s` zero,
    /// which `sign` retries and this cannot.
    pub fn sign_with_nonce(&self, d: &BigUint, hash: &[u8], e: &[u8])
                           -> Result<(BigUint, BigUint), String> {
        let d_s = self.private(d)?;
        let message = "The DSTU 4145 nonce is in [1, n).";
        // Bytes into fixed width, never a `BigUint`, whose limb count
        // would measure the nonce.
        let e_s = Secret::from_bytes_be(e, self.width()).map_err(|_| message.to_string())?;
        self.check_scalar(&e_s, message)?;
        self.sign_secret(&d_s, hash, &e_s)
    }

    fn sign_secret(&self, d: &Secret, hash: &[u8], e: &Secret)
                   -> Result<(BigUint, BigUint), String> {
        let f = &self.field;
        // The standard takes another e when x(e·G) is zero. For e in
        // [1, n) it cannot be: G has odd prime order n, and the point
        // with x = 0 has order two. So there is no test on the secret
        // x here, and none is needed.
        let Point::Affine(fe, _) = self.mul_secret(e, &self.g) else {
            return Err("e·G is the identity.".to_string());
        };
        let r = self.truncate(&f.mul(&self.hash_to_field(hash), &fe));
        if r.is_zero() {
            return Err("r is zero; the standard takes another e.".to_string());
        }
        // s = e + d·r mod n, both products on secrets in the Montgomery
        // domain, as `ec::gost3410` does it.
        let order = Montgomery::new(&self.n)?;
        let width = order.limbs();
        let r_s = Secret::from_biguint(&r, width)?;
        // Both are below n, so the limbs dropped are zero; the widths
        // are public.
        let d_w = Secret::from_limbs(d.limbs()[..width].to_vec());
        let e_w = Secret::from_limbs(e.limbs()[..width].to_vec());
        let s = order.add_mod(&order.mul_mod(&r_s, &d_w), &e_w).declassify();
        if s.is_zero() {
            return Err("s is zero; the standard takes another e.".to_string());
        }
        Ok((r, s))
    }

    /// Sign a hash with the private key `d`: `(r, s)`.
    ///
    /// # Errors
    /// `d` outside `[1, n)`, or the system random source failing.
    pub fn sign(&self, d: &BigUint, hash: &[u8]) -> Result<(BigUint, BigUint), String> {
        let d_s = self.private(d)?;
        let bits = self.n.bit_len() - 1;
        for _ in 0..1000 {
            // e below 2^(bit_len(n) - 1), so below n, as Bouncy Castle
            // draws it; zero is drawn again.
            let mut bytes = crate::random::bytes(bits.div_ceil(8))?;
            let spare = 8 * bytes.len() - bits;
            bytes[0] &= 0xff >> spare;
            let e = Secret::from_bytes_be(&bytes, self.width())?;
            if crate::bignum::montgomery::unmask(e.ct_is_zero()) {
                continue;
            }
            if let Ok(signature) = self.sign_secret(&d_s, hash, &e) {
                return Ok(signature);
            }
        }
        Err("Could not find a usable e in a thousand tries, which should not be \
             possible and means something above is wrong.".to_string())
    }

    /// Whether `(r, s)` is a signature of `hash` under the public key `q`.
    /// A `q` that is not a point of order `n` on the curve is refused
    /// rather than answered.
    ///
    /// # Errors
    /// An invalid public key.
    pub fn verify(&self, q: &Point, hash: &[u8], r: &BigUint, s: &BigUint)
                  -> Result<bool, String> {
        self.validate(q)?;
        // `s` at or above n would be reduced by the multiplication, so
        // `s + n` would verify wherever `s` does. `r` at or above n, or
        // either of them zero, cannot match the comparison below - the
        // r computed there is below 2^(bit_len(n) − 1) - and is refused
        // here before any arithmetic, as the standard says.
        if r.is_zero() || s.is_zero() || *r >= self.n || *s >= self.n {
            return Ok(false);
        }
        let point = self.add(&self.mul(s, &self.g), &self.mul(r, q));
        let Point::Affine(x, _) = point else { return Ok(false) };
        let y = self.field.mul(&self.hash_to_field(hash), &x);
        Ok(self.truncate(&y) == *r)
    }

    /// The shared point of a Diffie-Hellman exchange with a peer's public
    /// key: `d·Q`, or `(h·d mod n)·Q` with the cofactor, as cryptonite's
    /// `dstu4145_dh` and Bouncy Castle's EC agreements compute it. The
    /// peer's point is validated first, so it is of order `n` and the
    /// result is never the identity.
    ///
    /// # Errors
    /// `d` outside `[1, n)`, or a peer point that is not a public key.
    pub fn shared_point(&self, d: &BigUint, peer: &Point, cofactor: bool)
                        -> Result<Point, String> {
        let d = self.private(d)?;
        self.validate(peer)?;
        let scalar = if cofactor {
            let order = Montgomery::new(&self.n)?;
            let width = order.limbs();
            let h = Secret::from_biguint(&BigUint::from_u64(u64::from(self.h)), width)?;
            let d_w = Secret::from_limbs(d.limbs()[..width].to_vec());
            order.mul_mod(&h, &d_w).resize(self.width())?
        } else {
            d
        };
        Ok(self.mul_secret(&scalar, peer))
    }

    /// The standard's compression: `x`, big endian, its lowest bit the
    /// trace of `y/x`.
    ///
    /// # Errors
    /// The identity, which has no compression.
    pub fn compress(&self, p: &Point) -> Result<Vec<u8>, String> {
        let f = &self.field;
        let Point::Affine(x, y) = p else {
            return Err("The point at infinity has no compressed form.".to_string());
        };
        let mut bytes = f.to_bytes(x);
        let last = bytes.len() - 1;
        if !f.is_zero(x) {
            let bit = f.trace(&f.mul(y, &f.invert(x))) as u8;
            bytes[last] = (bytes[last] & 0xfe) | bit;
        }
        Ok(bytes)
    }

    /// The inverse of `compress`, for a point of order `n`.
    ///
    /// # Errors
    /// Bytes that are no such point.
    pub fn decompress(&self, bytes: &[u8]) -> Result<Point, String> {
        let f = &self.field;
        let k = u64::from(bytes.last().copied().unwrap_or(0) & 1);
        let mut x = f.from_bytes(bytes)?;
        // Every point of order n has Tr(x) = a; that is how the stored
        // bit's place in x is recovered.
        if f.trace(&x) != u64::from(self.a) {
            x[0] ^= 1;
        }
        let point = if f.is_zero(&x) {
            Point::Affine(x, f.sqrt(&self.b))
        } else {
            // y = x·z, with z^2 + z = x + a + b/x^2.
            let x_inv = f.invert(&x);
            let beta = f.add(&f.add(&x, &self.a_fe()), &f.mul(&self.b, &f.square(&x_inv)));
            let mut z = f.solve_quadratic(&beta)
                .ok_or("These bytes are not a compressed point on this curve.")?;
            if f.trace(&z) != k {
                z[0] ^= 1;
            }
            Point::Affine(x, f.mul(&x, &z))
        };
        self.validate(&point)?;
        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each named curve: the base point on the curve and of order n,
    /// `n` odd, and `h·n` within Hasse's bound of `2^m + 1`.
    #[test]
    fn test_the_named_curves_are_consistent() {
        for (number, name) in NAMES.iter().enumerate() {
            let c = Curve::named(number).unwrap();
            assert!(c.is_on_curve(&c.g), "{number}");
            // `validate` runs the ladder on n itself; `mul` would reduce
            // it to zero first and prove nothing.
            c.validate(&c.g).unwrap();
            assert_ne!(c.mul(&c.n.sub(&BigUint::one()).unwrap(), &c.g), Point::Infinity);
            assert!(c.n.bit(0));
            let order = c.n.mul(&BigUint::from_u64(u64::from(c.h)));
            let two_m = BigUint::one().shl(c.field.degree());
            let diff = if order > two_m { order.sub(&two_m) } else { two_m.sub(&order) }
                .unwrap();
            assert!(diff.bit_len() <= c.field.degree() / 2 + 2, "{number}");
            assert_eq!(Curve::by_name(name).unwrap().number(), Some(number));
        }
        assert!(Curve::named(10).is_err());
        assert!(Curve::by_name("dstu4145-m164").is_err());
    }

    /// The ladder against repeated affine addition, and the group law's
    /// special cases.
    #[test]
    fn test_the_ladder_and_the_group_law() {
        let c = Curve::named(0).unwrap();
        let g = c.g.clone();
        let mut sum = Point::Infinity;
        for k in 1u64..40 {
            sum = c.add(&sum, &g);
            assert_eq!(c.mul(&BigUint::from_u64(k), &g), sum, "{k}");
            assert!(c.is_on_curve(&sum));
        }
        assert_eq!(c.add(&g, &c.neg(&g)), Point::Infinity);
        assert_eq!(c.add(&g, &g), c.double(&g));
        assert_eq!(c.add(&Point::Infinity, &g), g);
        // (n − 1)·G is −G, the ladder's other edge.
        let n1 = c.n.sub(&BigUint::one()).unwrap();
        assert_eq!(c.mul(&n1, &g), c.neg(&g));
        assert_eq!(c.mul(&BigUint::zero(), &g), Point::Infinity);
    }

    /// Signing and verifying with this library alone, on every curve:
    /// what one signs the other accepts, and a changed hash, `r`, `s` or
    /// key is refused.
    #[test]
    fn test_sign_and_verify_on_every_curve() {
        for number in 0..10 {
            let c = Curve::named(number).unwrap();
            let (d, q) = c.generate().unwrap();
            let hash: Vec<u8> = (0..32u8).collect();
            let (r, s) = c.sign(&d, &hash).unwrap();
            assert!(c.verify(&q, &hash, &r, &s).unwrap(), "{number}");
            let mut other = hash.clone();
            other[0] ^= 1;
            assert!(!c.verify(&q, &other, &r, &s).unwrap());
            assert!(!c.verify(&q, &hash, &s, &r).unwrap());
            assert!(!c.verify(&c.neg(&q), &hash, &r, &s).unwrap());
            assert!(!c.verify(&q, &hash, &r, &c.n).unwrap());
            // s + n is s to the multiplication; only the range test
            // refuses it.
            assert!(!c.verify(&q, &hash, &r, &s.add(&c.n)).unwrap(), "{number}");
            assert_eq!(c.decompress(&c.compress(&q).unwrap()).unwrap(), q, "{number}");
        }
    }

    /// On a curve with cofactor 4 there are points of order 4, halves of
    /// the point of order two: `x^4 = b`, and `y` from the curve. Such a
    /// point, and its sum with `G` (order `4n`), are refused, and a curve
    /// given whole with a base point off the curve is refused too.
    #[test]
    fn test_points_of_order_four_and_a_bad_base_point() {
        let c = Curve::named(2).unwrap();
        assert_eq!(c.h, 4);
        let f = &c.field;
        let x = f.sqrt(&f.sqrt(&c.b));
        let beta = f.add(&f.add(&x, &c.a_fe()), &f.mul(&c.b, &f.square(&f.invert(&x))));
        let z = f.solve_quadratic(&beta).expect("a curve with cofactor 4 has points of order 4");
        let four = Point::Affine(x, f.mul(&x, &z));
        assert!(c.is_on_curve(&four));
        assert_eq!(c.double(&c.double(&four)), Point::Infinity);
        assert!(c.validate(&four).unwrap_err().contains("cofactor"));
        let outside = c.add(&c.g, &four);
        assert!(c.validate(&outside).unwrap_err().contains("subgroup"));
        let (d, _) = c.generate().unwrap();
        assert!(c.shared_point(&d, &four, true).is_err());
        // G plus the point of order two has order 2n and is a double, so
        // it has the trace a compressed point needs; decompressing it
        // has to refuse it rather than return it.
        let two = c.double(&four);
        let twice_n = c.add(&c.g, &two);
        assert!(c.is_on_curve(&twice_n));
        let packed = c.compress(&twice_n).unwrap();
        assert!(c.decompress(&packed).unwrap_err().contains("subgroup"));
        // On this curve a = 0, so x = 0 has the trace a compressed point
        // needs: it decompresses to the point of order two, refused.
        assert_eq!(c.a, 0);
        let zeros = vec![0u8; c.field.byte_len()];
        assert!(c.decompress(&zeros).unwrap_err().contains("x = 0"));

        let p = &CURVES[0];
        let field = Field::new(p.m, p.terms).unwrap();
        let (gx, gy) = (hex_fe(&field, p.gx).unwrap(), hex_fe(&field, p.gy).unwrap());
        let b = field.to_bytes(&hex_fe(&field, p.b).unwrap());
        let n = BigUint::from_hex(p.n).unwrap();
        let mut off = gy;
        off[0] ^= 1;
        assert!(Curve::custom(p.m, p.terms, p.a, &b, &n, &field.to_bytes(&gx),
                              &field.to_bytes(&gy)).is_ok());
        assert!(Curve::custom(p.m, p.terms, p.a, &b, &n, &field.to_bytes(&gx),
                              &field.to_bytes(&off)).is_err());
        let small = BigUint::from_u64(3);
        assert!(Curve::custom(p.m, p.terms, p.a, &b, &small, &field.to_bytes(&gx),
                              &field.to_bytes(&gy)).unwrap_err().contains("does not belong"));
    }

    /// Both sides of an exchange reach the same point, the cofactor's
    /// form is `h` times the other, and a peer outside the subgroup is
    /// refused rather than multiplied.
    #[test]
    fn test_the_exchange() {
        for number in [0, 2] {
            let c = Curve::named(number).unwrap();
            let (d1, q1) = c.generate().unwrap();
            let (d2, q2) = c.generate().unwrap();
            for cofactor in [false, true] {
                assert_eq!(c.shared_point(&d1, &q2, cofactor).unwrap(),
                           c.shared_point(&d2, &q1, cofactor).unwrap());
            }
            let plain = c.shared_point(&d1, &q2, false).unwrap();
            let h = BigUint::from_u64(u64::from(c.h));
            assert_eq!(c.shared_point(&d1, &q2, true).unwrap(), c.mul(&h, &plain));
            let two = Point::Affine(c.field.zero(), c.field.sqrt(&c.b));
            assert!(c.shared_point(&d1, &c.add(&q2, &two), true).is_err());
            assert!(c.shared_point(&BigUint::zero(), &q2, true).is_err());
            assert!(c.shared_point(&c.n, &q2, true).is_err());
        }
    }

    /// The nonce's range, and the standard's rule that a zero hash is
    /// read as one: the empty hash and the hash `01` sign alike.
    #[test]
    fn test_the_nonce_and_the_zero_hash() {
        let c = Curve::named(0).unwrap();
        let (d, _) = c.generate().unwrap();
        let e = [0x2au8; 20];
        assert_eq!(c.sign_with_nonce(&d, b"", &e).unwrap(),
                   c.sign_with_nonce(&d, b"\x01", &e).unwrap());
        assert_ne!(c.sign_with_nonce(&d, b"\x02", &e).unwrap(),
                   c.sign_with_nonce(&d, b"\x01", &e).unwrap());
        assert!(c.sign_with_nonce(&d, b"h", &[0]).is_err());
        assert!(c.sign_with_nonce(&d, b"h", &c.n.to_bytes_be()).is_err());
        let n1 = c.n.sub(&BigUint::one()).unwrap();
        assert!(c.sign_with_nonce(&d, b"h", &n1.to_bytes_be()).is_ok());
        assert!(c.sign_with_nonce(&d, b"h", &[0u8; 64]).is_err());
    }

    #[test]
    fn test_points_from_outside_are_checked() {
        let c = Curve::named(0).unwrap();
        let (_, q) = c.generate().unwrap();
        let Point::Affine(x, y) = q.clone() else { panic!() };
        let mut off = y;
        off[0] ^= 1;
        assert!(c.validate(&Point::Affine(x, off)).is_err());
        assert!(c.validate(&Point::Infinity).is_err());
        // The point of order two, (0, sqrt(b)).
        let two = Point::Affine(c.field.zero(), c.field.sqrt(&c.b));
        assert!(c.is_on_curve(&two));
        assert!(c.validate(&two).unwrap_err().contains("x = 0"));
        // A point on the curve outside the subgroup: G plus the point of
        // order two has order 2n.
        let outside = c.add(&c.g, &two);
        assert!(c.is_on_curve(&outside));
        assert!(c.validate(&outside).unwrap_err().contains("subgroup"));
        assert!(c.verify(&outside, b"h", &BigUint::one(), &BigUint::one()).is_err());
    }
}
