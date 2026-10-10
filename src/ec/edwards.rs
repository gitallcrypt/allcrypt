/*!
The group arithmetic under Ed25519 and Ed448, on the fixed-limb fields
`field25519` and `field448`.

`eddsa.rs` has a second copy of the same group on `BigUint`,
`eddsa::reference`, kept for the tests here to compare against. This one
is what signing, key derivation and verification run on, for two
reasons: it is about a hundred times faster, and it is constant time,
which the `BigUint` version cannot be - its double-and-add branched on
every bit of the secret scalar.

## Coordinates and formulas

Extended twisted Edwards coordinates `(X : Y : Z : T)` with `x = X/Z`,
`y = Y/Z` and `xy = T/Z` (Hisil, Wong, Carter and Dawson, 2008). The
addition is their unified formula `add-2008-hwcd`, the doubling
`dbl-2008-hwcd`, both written for a general `a` so that the same code
serves Ed25519 (`a = -1`) and Ed448 (`a = 1`); which one is a public
property of the curve and is the only branch here.

Both formulas are **complete** on these curves - `a` is a square and `d`
is not, on each - so there is no special case for doubling, for the
identity or for `P + (-P)`, and nothing to branch on.

## Scalar multiplication

A fixed window of four bits: a table of `0P .. 15P`, then four doublings
and one addition per nibble of the scalar, most significant first. The
number of nibbles is the scalar's byte length, which is public, and the
table entry is chosen by reading **every** entry and keeping the right
one with a mask (`lookup`), so neither the memory addresses nor the
branches depend on the scalar. Verification uses the same window for
`s*B + k*(-A)` together, sharing the doublings.
*/

use std::sync::OnceLock;

use crate::bignum::BigUint;

use super::field25519;
use super::field448;

/// What the group needs from a field. Implemented by the two fixed-limb
/// fields; every function is constant time.
pub(crate) trait Field: Copy {
    const ZERO: Self;
    const ONE: Self;
    /// Bytes in the encoding of an element.
    const BYTES: usize;
    fn add(self, other: Self) -> Self;
    fn sub(self, other: Self) -> Self;
    fn mul(self, other: Self) -> Self;
    fn square(self) -> Self;
    fn invert(self) -> Self;
    /// From exactly `BYTES` little-endian bytes. Field25519 ignores the
    /// top bit; neither refuses a value at or above `p`.
    fn from_le(bytes: &[u8]) -> Self;
    /// The canonical encoding, `BYTES` long.
    fn to_le(self) -> Vec<u8>;
    fn cswap(a: &mut Self, b: &mut Self, choice: u64);

    fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    /// `other` when `choice` is 1, `self` when it is 0.
    fn select(self, other: Self, choice: u64) -> Self {
        let (mut kept, mut spare) = (self, other);
        Self::cswap(&mut kept, &mut spare, choice);
        kept
    }

    /// Whether two elements are equal as field elements, by their
    /// canonical encodings. Variable time: for public values only.
    fn equals(self, other: Self) -> bool {
        self.to_le() == other.to_le()
    }

    /// `self^e` for a **public** exponent given as little-endian bytes,
    /// by square-and-multiply; it branches on the exponent's bits.
    fn pow_public(self, exponent: &[u8]) -> Self {
        let mut result = Self::ONE;
        for byte in exponent.iter().rev() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }
}

impl Field for field25519::Fe {
    const ZERO: Self = field25519::Fe::ZERO;
    const ONE: Self = field25519::Fe::ONE;
    const BYTES: usize = 32;
    fn add(self, other: Self) -> Self {
        field25519::Fe::add(self, other)
    }
    fn sub(self, other: Self) -> Self {
        field25519::Fe::sub(self, other)
    }
    fn mul(self, other: Self) -> Self {
        field25519::Fe::mul(self, other)
    }
    fn square(self) -> Self {
        field25519::Fe::square(self)
    }
    fn invert(self) -> Self {
        field25519::Fe::invert(self)
    }
    fn from_le(bytes: &[u8]) -> Self {
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        field25519::Fe::from_bytes(&array)
    }
    fn to_le(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
    fn cswap(a: &mut Self, b: &mut Self, choice: u64) {
        field25519::Fe::cswap(a, b, choice)
    }
}

impl Field for field448::Fe {
    const ZERO: Self = field448::Fe::ZERO;
    const ONE: Self = field448::Fe::ONE;
    const BYTES: usize = 56;
    fn add(self, other: Self) -> Self {
        field448::Fe::add(self, other)
    }
    fn sub(self, other: Self) -> Self {
        field448::Fe::sub(self, other)
    }
    fn mul(self, other: Self) -> Self {
        field448::Fe::mul(self, other)
    }
    fn square(self) -> Self {
        field448::Fe::square(self)
    }
    fn invert(self) -> Self {
        field448::Fe::invert(self)
    }
    fn from_le(bytes: &[u8]) -> Self {
        let mut array = [0u8; 56];
        array.copy_from_slice(bytes);
        field448::Fe::from_bytes(&array)
    }
    fn to_le(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
    fn cswap(a: &mut Self, b: &mut Self, choice: u64) {
        field448::Fe::cswap(a, b, choice)
    }
}

/// A point in extended coordinates. See the module comment.
#[derive(Clone, Copy)]
pub(crate) struct Point<F> {
    x: F,
    y: F,
    z: F,
    t: F,
}

impl<F: Field> Point<F> {
    /// `(0, 1)`, an ordinary point on an Edwards curve.
    fn identity() -> Self {
        Point { x: F::ZERO, y: F::ONE, z: F::ONE, t: F::ZERO }
    }

    fn from_affine(x: F, y: F) -> Self {
        Point { x, y, z: F::ONE, t: x.mul(y) }
    }

    /// `-(x, y) = (-x, y)`.
    fn negate(self) -> Self {
        Point { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    fn select(self, other: Self, choice: u64) -> Self {
        Point {
            x: self.x.select(other.x, choice),
            y: self.y.select(other.y, choice),
            z: self.z.select(other.z, choice),
            t: self.t.select(other.t, choice),
        }
    }
}

/// `table[index]`, reading all sixteen entries. `index` is below 16.
fn lookup<F: Field>(table: &[Point<F>; 16], index: u8) -> Point<F> {
    let mut out = Point::identity();
    for (i, entry) in (0u8..).zip(table.iter()) {
        // 1 when i == index: the difference is 0..15, and only 0 wraps
        // when one is subtracted.
        let difference = u64::from(i ^ index);
        let hit = difference.wrapping_sub(1) >> 63;
        out = out.select(*entry, hit);
    }
    out
}

/// Little-endian bytes as signed base-16 digits in `-8..=8`, two per
/// byte, low digit first. The carry out of the top digit is lost, so the
/// digits sum to the value only when the top nibble plus its incoming
/// carry is below 8; a zero top byte guarantees that, and the one caller
/// pads with one. Arithmetic only: the carry is an arithmetic shift, not
/// a comparison.
fn signed_digits(bytes: &[u8]) -> Vec<i8> {
    let mut digits = Vec::with_capacity(2 * bytes.len());
    let mut carry = 0i8;
    for &byte in bytes {
        for nibble in [byte & 15, byte >> 4] {
            let value = nibble as i8 + carry;
            // value is in 0..=16; carry 1 from 8 upwards.
            carry = (value + 8) >> 4;
            digits.push(value - (carry << 4));
        }
    }
    digits
}

/// `digit * row[0]` for a digit in `-8..=8`, where `row[i]` is
/// `(i + 1) * row[0]`: the entry for `|digit|` read with every entry
/// touched, then negated or not by a mask.
fn lookup_signed<F: Field>(row: &[Point<F>; 8], digit: i8) -> Point<F> {
    let negative = (digit >> 7) as u8; // all ones or zero
    let magnitude = ((digit as u8) ^ negative).wrapping_sub(negative);
    let mut out = Point::identity();
    for (i, entry) in (1u8..).zip(row.iter()) {
        let hit = u64::from(i ^ magnitude).wrapping_sub(1) >> 63;
        out = out.select(*entry, hit);
    }
    out.select(out.negate(), u64::from(negative & 1))
}

/// One of the two curves, with its constants computed once.
pub(crate) struct Curve<F> {
    /// `a = -1` (Ed25519) rather than `a = 1` (Ed448).
    twisted: bool,
    d: F,
    /// Bytes in a point encoding: the field's, plus one for Ed448,
    /// whose 448-bit `y` leaves no spare bit for the sign of `x`.
    key_len: usize,
    base: Point<F>,
    /// `table[j][i] = (i + 1) * 256^j * B` for `i` in `0..8`, with
    /// `key_len + 1` rows. See `multiply_base`.
    table: Vec<[Point<F>; 8]>,
    /// The exponent of the square root, little endian: `(p + 3) / 8`
    /// for Ed25519 and `(p + 1) / 4` for Ed448.
    sqrt_exponent: Vec<u8>,
    /// `sqrt(-1) = 2^((p - 1) / 4)`, for Ed25519's root; unused for Ed448.
    sqrt_minus_one: F,
}

/// Little-endian bytes of a value known to fit `length`: the curve
/// constants below, and test inputs below the field. A value that does
/// not fit is a wrong constant, and the panic names it where it is
/// rather than letting an empty vector become a zero field element.
fn le_bytes(value: &BigUint, length: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_be_padded(length)
        .expect("a curve constant that fits its field's width");
    bytes.reverse();
    bytes
}

fn small<F: Field>(value: u64) -> F {
    let mut bytes = vec![0u8; F::BYTES];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    F::from_le(&bytes)
}

/// Ed25519: `-x^2 + y^2 = 1 + d x^2 y^2` over `2^255 - 19`.
pub(crate) fn ed25519() -> &'static Curve<field25519::Fe> {
    static CURVE: OnceLock<Curve<field25519::Fe>> = OnceLock::new();
    CURVE.get_or_init(|| {
        let one = BigUint::one();
        let p = one.shl(255).sub(&BigUint::from_u64(19)).expect("2^255 - 19");
        let exponent = |shifted: BigUint| le_bytes(&shifted, 32);
        let sqrt_exponent = exponent(p.add(&BigUint::from_u64(3)).shr(3));
        let quarter = exponent(p.sub(&one).expect("p - 1 for p = 2^255 - 19").shr(2));
        let sqrt_minus_one = small::<field25519::Fe>(2).pow_public(&quarter);
        // d = -121665 / 121666
        let d = small::<field25519::Fe>(121665).neg()
            .mul(small::<field25519::Fe>(121666).invert());
        let mut curve = Curve {
            twisted: true, d, key_len: 32, base: Point::identity(), table: Vec::new(),
            sqrt_exponent, sqrt_minus_one,
        };
        // The base point is y = 4/5 with the even x, RFC 8032 5.1. A
        // failure to decode it would be a wrong `d` or a wrong square
        // root chain, and the panic says so here; substituting the
        // identity would make a curve whose every signature is over the
        // identity, noticed only as vector mismatches elsewhere.
        let y = small::<field25519::Fe>(4).mul(small::<field25519::Fe>(5).invert());
        let mut encoded = y.to_le();
        encoded[31] &= 0x7f;
        curve.base = curve.decode(&encoded)
            .expect("RFC 8032 section 5.1 base point, y = 4/5 with the even x");
        curve.table = curve.base_table();
        curve
    })
}

/// Ed448: `x^2 + y^2 = 1 + d x^2 y^2` over `2^448 - 2^224 - 1`.
pub(crate) fn ed448() -> &'static Curve<field448::Fe> {
    static CURVE: OnceLock<Curve<field448::Fe>> = OnceLock::new();
    CURVE.get_or_init(|| {
        let one = BigUint::one();
        let p = one.shl(448).sub(&one.shl(224)).and_then(|v| v.sub(&one))
            .expect("2^448 - 2^224 - 1");
        let sqrt_exponent = le_bytes(&p.add(&one).shr(2), 56);
        let d = small::<field448::Fe>(39081).neg();
        // RFC 8032 section 5.2 gives the base point in decimal; these are
        // the same numbers, and the tests check the point against the
        // `BigUint` copy in `eddsa.rs` and its order. A coordinate that
        // does not parse is a typo in the hex, and the panic names it
        // here rather than making the base point (0, 0).
        let coordinate = |hex: &str| {
            field448::Fe::from_le(&le_bytes(
                &BigUint::from_hex(hex).expect("RFC 8032 section 5.2 base point coordinate"),
                56))
        };
        let x = coordinate("4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324\
                            a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e");
        let y = coordinate("693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e\
                            05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14");
        let mut curve = Curve {
            twisted: false, d, key_len: 57, base: Point::from_affine(x, y), table: Vec::new(),
            sqrt_exponent, sqrt_minus_one: field448::Fe::ZERO,
        };
        curve.table = curve.base_table();
        curve
    })
}

impl<F: Field> Curve<F> {
    /// `a * value`, for `a` of -1 or 1.
    fn times_a(&self, value: F) -> F {
        if self.twisted { value.neg() } else { value }
    }

    /// `add-2008-hwcd`, nine multiplications:
    ///
    /// ```text
    /// A = X1*X2  B = Y1*Y2  C = d*T1*T2  D = Z1*Z2
    /// E = (X1+Y1)*(X2+Y2) - A - B   F = D - C   G = D + C   H = B - a*A
    /// X3 = E*F   Y3 = G*H   T3 = E*H   Z3 = F*G
    /// ```
    pub(crate) fn add(&self, p: &Point<F>, q: &Point<F>) -> Point<F> {
        let a = p.x.mul(q.x);
        let b = p.y.mul(q.y);
        let c = p.t.mul(q.t).mul(self.d);
        let d = p.z.mul(q.z);
        let e = p.x.add(p.y).mul(q.x.add(q.y)).sub(a).sub(b);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.sub(self.times_a(a));
        Point { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h) }
    }

    /// `dbl-2008-hwcd`, four squarings and four multiplications:
    ///
    /// ```text
    /// A = X^2  B = Y^2  C = 2*Z^2  D = a*A
    /// E = (X+Y)^2 - A - B   G = D + B   F = G - C   H = D - B
    /// X3 = E*F   Y3 = G*H   T3 = E*H   Z3 = F*G
    /// ```
    pub(crate) fn double(&self, p: &Point<F>) -> Point<F> {
        let a = p.x.square();
        let b = p.y.square();
        let z2 = p.z.square();
        let c = z2.add(z2);
        let d = self.times_a(a);
        let e = p.x.add(p.y).square().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Point { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h) }
    }

    fn table(&self, p: &Point<F>) -> [Point<F>; 16] {
        let mut table = [Point::identity(); 16];
        table[1] = *p;
        for i in 2..16 {
            table[i] = self.add(&table[i - 1], p);
        }
        table
    }

    /// `scalar * p` for a scalar given as little-endian bytes, constant
    /// time in the scalar: its length is the only thing that steers.
    pub(crate) fn multiply(&self, scalar: &[u8], p: &Point<F>) -> Point<F> {
        let table = self.table(p);
        let mut acc = Point::identity();
        for &byte in scalar.iter().rev() {
            for nibble in [byte >> 4, byte & 15] {
                for _ in 0..4 {
                    acc = self.double(&acc);
                }
                acc = self.add(&acc, &lookup(&table, nibble));
            }
        }
        acc
    }

    /// The rows of `table`: `key_len + 1` of them, so that a scalar of
    /// `key_len` bytes always has a zero byte above it to absorb the
    /// carry out of its signed digits.
    fn base_table(&self) -> Vec<[Point<F>; 8]> {
        let mut rows = Vec::with_capacity(self.key_len + 1);
        let mut row_base = self.base;
        for _ in 0..=self.key_len {
            let mut row = [row_base; 8];
            for i in 1..8 {
                row[i] = self.add(&row[i - 1], &row_base);
            }
            rows.push(row);
            for _ in 0..8 {
                row_base = self.double(&row_base);
            }
        }
        rows
    }

    /// `scalar * B` from the precomputed table, constant time in the
    /// scalar.
    ///
    /// The scalar is rewritten in signed base-16 digits `e_i` in
    /// `-8..=8`, so `scalar = sum(e_i * 16^i)`. Digit `2j` contributes
    /// `e_2j * 256^j * B`, a table entry or its negation, and digit
    /// `2j + 1` sixteen times that, so the odd digits are summed first,
    /// multiplied by 16 with four doublings, and the even digits added:
    /// one addition per digit and four doublings in all, against four
    /// doublings per digit in `multiply`. Bernstein, Duif, Lange,
    /// Schwabe and Yang, "High-speed high-security signatures", 4.2.
    ///
    /// A scalar longer than `key_len` bytes goes to `multiply` instead;
    /// that is a property of the length, which is public.
    pub(crate) fn multiply_base(&self, scalar: &[u8]) -> Point<F> {
        if scalar.len() >= self.table.len() {
            return self.multiply(scalar, &self.base);
        }
        let mut padded = scalar.to_vec();
        padded.resize(self.table.len(), 0);
        let digits = signed_digits(&padded);
        let mut acc = Point::identity();
        for (j, row) in self.table.iter().enumerate() {
            acc = self.add(&acc, &lookup_signed(row, digits[2 * j + 1]));
        }
        for _ in 0..4 {
            acc = self.double(&acc);
        }
        for (j, row) in self.table.iter().enumerate() {
            acc = self.add(&acc, &lookup_signed(row, digits[2 * j]));
        }
        acc
    }

    /// `first * p + second * q`, both scalars the same length, with the
    /// doublings shared (Straus).
    pub(crate) fn multiply_two(&self, first: &[u8], p: &Point<F>,
                               second: &[u8], q: &Point<F>) -> Point<F> {
        let (p_table, q_table) = (self.table(p), self.table(q));
        let mut acc = Point::identity();
        for (&a, &b) in first.iter().rev().zip(second.iter().rev()) {
            for (x, y) in [(a >> 4, b >> 4), (a & 15, b & 15)] {
                for _ in 0..4 {
                    acc = self.double(&acc);
                }
                acc = self.add(&acc, &lookup(&p_table, x));
                acc = self.add(&acc, &lookup(&q_table, y));
            }
        }
        acc
    }

    pub(crate) fn base(&self) -> Point<F> {
        self.base
    }

    pub(crate) fn negate(&self, p: &Point<F>) -> Point<F> {
        p.negate()
    }

    /// `y` of `(u - 1) / (u + 1)` for a Montgomery `u` given as
    /// little-endian bytes, canonical. The birational map from Curve25519
    /// to Ed25519; `u = -1` has no image and gives 0, since the inverse
    /// is by exponentiation.
    pub(crate) fn edwards_y(&self, u: &[u8]) -> Vec<u8> {
        let u = F::from_le(u);
        u.sub(F::ONE).mul(u.add(F::ONE).invert()).to_le()
    }

    /// The Montgomery `u = (1 + y) / (1 - y)` of a point, little endian:
    /// the inverse of `edwards_y`. The identity (`y = 1`) has no image
    /// and gives 0, since the inverse is by exponentiation.
    pub(crate) fn montgomery_u(&self, p: &Point<F>) -> Vec<u8> {
        let y = p.y.mul(p.z.invert());
        F::ONE.add(y).mul(F::ONE.sub(y).invert()).to_le()
    }

    /// Whether `p` is the identity. Variable time, as `equals` is.
    pub(crate) fn is_identity(&self, p: &Point<F>) -> bool {
        self.equals(p, &Point::identity())
    }

    /// Projective equality: `X1*Z2 == X2*Z1` and `Y1*Z2 == Y2*Z1`.
    /// Variable time; for verification, where everything is public.
    pub(crate) fn equals(&self, p: &Point<F>, q: &Point<F>) -> bool {
        p.x.mul(q.z).equals(q.x.mul(p.z)) && p.y.mul(q.z).equals(q.y.mul(p.z))
    }

    /// RFC 8032's encoding: `y` little endian, with the low bit of `x` in
    /// the top bit of the last byte. Constant time; the point may be a
    /// secret multiple of the base until it is encoded.
    pub(crate) fn encode(&self, p: &Point<F>) -> Vec<u8> {
        let inverse = p.z.invert();
        let x = p.x.mul(inverse).to_le();
        let mut out = p.y.mul(inverse).to_le();
        out.resize(self.key_len, 0);
        out[self.key_len - 1] |= (x[0] & 1) << 7;
        out
    }

    /// Decode a point, or `None` if the bytes are not the canonical
    /// encoding of one. The same rules as `eddsa::reference::decode`, which the
    /// tests check: `y` below `p`, a square root that exists, and no
    /// set sign bit on `x = 0`. Variable time; points are public.
    pub(crate) fn decode(&self, bytes: &[u8]) -> Option<Point<F>> {
        if bytes.len() != self.key_len {
            return None;
        }
        let sign = bytes[self.key_len - 1] >> 7;
        let mut y_bytes = bytes[..F::BYTES].to_vec();
        if self.key_len == F::BYTES {
            y_bytes[F::BYTES - 1] &= 0x7f;
        } else if bytes[self.key_len - 1] & 0x7f != 0 {
            // Ed448's last byte is the sign alone; anything else in it
            // is a y of 2^448 or more.
            return None;
        }
        let y = F::from_le(&y_bytes);
        if y.to_le() != y_bytes {
            return None; // y >= p
        }

        // x^2 = (y^2 - 1) / (d*y^2 - a)
        let y2 = y.square();
        let numerator = y2.sub(F::ONE);
        let denominator = y2.mul(self.d).sub(self.times_a(F::ONE));
        if denominator.equals(F::ZERO) {
            return None;
        }
        let x2 = numerator.mul(denominator.invert());
        if x2.equals(F::ZERO) {
            // x = 0 with the sign bit set is a non-canonical encoding of
            // (0, y), which RFC 8032 section 5.1.3 rejects.
            return if sign == 0 { Some(Point::from_affine(F::ZERO, y)) } else { None };
        }
        let mut x = x2.pow_public(&self.sqrt_exponent);
        if self.twisted && !x.square().equals(x2) {
            // p = 5 mod 8: the candidate is a root of x2 or of -x2.
            x = x.mul(self.sqrt_minus_one);
        }
        if !x.square().equals(x2) {
            return None; // y is not the y of a point
        }
        if x.to_le()[0] & 1 != sign {
            x = x.neg();
        }
        Some(Point::from_affine(x, y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::eddsa;
    use crate::ec::eddsa::reference as bignum;

    fn random(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        crate::random::fill(&mut bytes).unwrap();
        bytes
    }

    /// Both curves against `eddsa.rs`'s `BigUint` arithmetic: scalar
    /// multiples of the base, the joint multiplication, and the
    /// decoding of every one of them.
    fn agrees_with_the_bignum<F: Field>(curve: &Curve<F>, variant: eddsa::Variant) {
        let reference = bignum::Curve::new(variant);
        let base = bignum::base(&reference);
        let length = curve.key_len;
        assert_eq!(curve.encode(&curve.base()), bignum::encode(&reference, &base));
        for round in 0..12 {
            let mut scalar = random(length);
            if round == 0 {
                scalar.iter_mut().for_each(|b| *b = 0xff);
            }
            let ours = curve.encode(&curve.multiply_base(&scalar));
            let mut big_endian = scalar.clone();
            big_endian.reverse();
            let big = BigUint::from_bytes_be(&big_endian);
            let theirs = bignum::encode(&reference,
                &bignum_multiply(&reference, &big, &base, 8 * length));
            assert_eq!(ours, theirs, "scalar {round}");

            let decoded = curve.decode(&ours).expect("an encoded point decodes");
            assert_eq!(curve.encode(&decoded), ours);

            let other = random(length);
            let joint = curve.multiply_two(&scalar, &curve.base(), &other, &decoded);
            let separate = curve.add(&curve.multiply_base(&scalar),
                                     &curve.multiply(&other, &decoded));
            assert!(curve.equals(&joint, &separate));
        }
    }

    /// Double-and-add with an explicit bit count, so a scalar wider than
    /// the variant's bound is multiplied in full.
    fn bignum_multiply(curve: &bignum::Curve, scalar: &BigUint, point: &bignum::Point,
                       bits: usize) -> bignum::Point {
        let mut result = bignum::Point::identity();
        let mut addend = point.clone();
        for bit in 0..bits {
            if scalar.bit(bit) {
                result = bignum::add(curve, &result, &addend);
            }
            addend = bignum::add(curve, &addend, &addend);
        }
        result
    }

    /// The base points are real points, checked at the constant.
    ///
    /// `ed25519()` substituted the identity when the base point's
    /// encoding failed to decode, and `ed448()` the zero field element
    /// when a coordinate's hex failed to parse, so a wrong constant made
    /// a curve whose every signature was over the identity - reported
    /// only as a mismatch in the tests above, far from the constant that
    /// caused it. Both now panic at construction naming the constant.
    /// This checks the two directly: each base point is on its curve,
    /// is not the identity, and matches the `BigUint` reference's.
    #[test]
    fn test_the_base_points_are_real_points() {
        fn check<F: Field>(curve: &Curve<F>, variant: eddsa::Variant) {
            let base = curve.base();
            assert!(!curve.is_identity(&base), "{variant:?}: the base point is the identity");
            assert!(!base.x.equals(F::ZERO), "{variant:?}: the base point has x = 0");
            let reference = bignum::Curve::new(variant);
            assert_eq!(curve.encode(&base),
                       bignum::encode(&reference, &bignum::base(&reference)),
                       "{variant:?}: the base point is not RFC 8032's");
        }
        check(ed25519(), eddsa::Variant::Ed25519);
        check(ed448(), eddsa::Variant::Ed448);
    }

    #[test]
    fn test_ed25519_agrees_with_the_bignum() {
        agrees_with_the_bignum(ed25519(), eddsa::Variant::Ed25519);
    }

    #[test]
    fn test_ed448_agrees_with_the_bignum() {
        agrees_with_the_bignum(ed448(), eddsa::Variant::Ed448);
    }

    /// Decoding against `eddsa::reference::decode` on strings that are mostly not
    /// points, and on the encodings at the edges: y = 0, 1, p - 1, p,
    /// and x = 0 with each sign.
    fn decodes_like_the_bignum<F: Field>(curve: &Curve<F>, variant: eddsa::Variant) {
        let reference = bignum::Curve::new(variant);
        let length = curve.key_len;
        let mut inputs: Vec<Vec<u8>> = (0..300).map(|_| random(length)).collect();
        // Ed448's last byte must be 0 or 0x80 to have any chance.
        for input in inputs.iter_mut().skip(100) {
            if length == 57 {
                input[56] &= 0x80;
            }
        }
        let p = reference.p.clone();
        let one = BigUint::one();
        for y in [BigUint::zero(), one.clone(), p.sub(&one).unwrap(), p.clone(), p.add(&one)] {
            for sign in [0u8, 0x80] {
                let mut bytes = le_bytes(&y, F::BYTES);
                bytes.resize(length, 0);
                bytes[length - 1] |= sign;
                inputs.push(bytes);
            }
        }
        let mut points = 0;
        for input in &inputs {
            let ours = curve.decode(input).map(|point| curve.encode(&point));
            let theirs = bignum::decode(&reference, input)
                .map(|point| bignum::encode(&reference, &point));
            assert_eq!(ours, theirs, "input {input:02x?}");
            points += usize::from(ours.is_some());
        }
        // About half of all y are the y of a point; make sure the
        // comparison was not between two Nones throughout.
        assert!(points > 50, "only {points} of the inputs decoded");
    }

    #[test]
    fn test_ed25519_decodes_like_the_bignum() {
        decodes_like_the_bignum(ed25519(), eddsa::Variant::Ed25519);
    }

    #[test]
    fn test_ed448_decodes_like_the_bignum() {
        decodes_like_the_bignum(ed448(), eddsa::Variant::Ed448);
    }

    /// The special cases a complete formula has to get right without a
    /// branch: P + P against doubling, P + (-P), and the identity on
    /// either side.
    fn the_formulas_are_complete<F: Field>(curve: &Curve<F>) {
        let p = curve.multiply_base(&random(curve.key_len));
        let identity = Point::identity();
        assert!(curve.equals(&curve.add(&p, &p), &curve.double(&p)));
        assert!(curve.equals(&curve.add(&p, &curve.negate(&p)), &identity));
        assert!(curve.equals(&curve.add(&p, &identity), &p));
        assert!(curve.equals(&curve.add(&identity, &p), &p));
        assert!(curve.equals(&curve.double(&identity), &identity));
        // Equality looks at x as well as y: P and -P share a y.
        assert!(!curve.equals(&p, &curve.negate(&p)));
        assert!(!p.x.equals(F::ZERO));
        assert!(identity.x.equals(F::ZERO));
        // (0, -1), the point of order two, has x = 0 and is not the identity.
        let order_two = Point::from_affine(F::ZERO, F::ONE.neg());
        assert!(order_two.x.equals(F::ZERO));
        assert!(!curve.equals(&order_two, &identity));
    }

    #[test]
    fn test_the_formulas_are_complete() {
        the_formulas_are_complete(ed25519());
        the_formulas_are_complete(ed448());
    }

    /// The fixed-base path against the generic one, for scalars of
    /// every length up to the table's, all-ones scalars (the largest
    /// carries) and the scalars the signers actually pass.
    fn the_base_table_agrees<F: Field>(curve: &Curve<F>) {
        for length in [0, 1, 2, curve.key_len - 1, curve.key_len, curve.key_len + 1] {
            for round in 0..4 {
                let mut scalar = random(length);
                if round == 0 {
                    scalar.iter_mut().for_each(|b| *b = 0xff);
                }
                assert!(curve.equals(&curve.multiply_base(&scalar),
                                     &curve.multiply(&scalar, &curve.base())),
                        "{length} bytes, round {round}");
            }
        }
        // Longer than the table, or as long: the generic path. A scalar
        // as long as the table would have no zero byte above it to take
        // the last carry.
        let long = random(curve.key_len + 3);
        assert!(curve.equals(&curve.multiply_base(&long), &curve.multiply(&long, &curve.base())));
    }

    #[test]
    fn test_the_base_table_agrees_with_the_generic_multiply() {
        the_base_table_agrees(ed25519());
        the_base_table_agrees(ed448());
    }

    #[test]
    fn test_signed_digits_sum_to_the_value() {
        for mut bytes in [vec![0u8; 4], vec![0x7f; 4], vec![0x88, 0x88, 0x08],
                          vec![0xff; 14], random(14)] {
            bytes.push(0);
            let digits = signed_digits(&bytes);
            assert!(digits.iter().all(|d| (-8..=8).contains(d)), "{digits:?}");
            let mut expected = bytes.clone();
            expected.reverse();
            let value = digits.iter().rev().fold(0i128, |acc, &d| acc * 16 + i128::from(d));
            let mut be = vec![0u8; 16];
            be[16 - expected.len().min(16)..].copy_from_slice(&expected[expected.len().saturating_sub(16)..]);
            assert_eq!(value, i128::from_be_bytes(be.try_into().unwrap()), "{bytes:02x?}");
        }
    }

    #[test]
    fn test_lookup_returns_each_entry() {
        let curve = ed25519();
        let table = curve.table(&curve.base());
        for (i, entry) in (0u8..).zip(table.iter()) {
            assert!(curve.equals(&lookup(&table, i), entry), "entry {i}");
        }
    }
}
