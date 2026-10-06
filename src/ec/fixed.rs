/*!
Scalar multiplication on short Weierstrass curves over `bignum::fixed`.

`ec::ct` does the same job on `bignum::ct::Secret`, whose limbs live in a
`Vec`: every field operation allocates, and its Montgomery ladder does an
addition and two doublings per scalar bit (its constant-time addition
computes a doubling too). This is the fast path in front of it, for
every field of up to nine limbs - 576 bits, which covers every curve
in `ec::curves`. `ec::ct` stays as the path for wider fields and as the
reference the tests compare against.

## The arithmetic

Jacobian coordinates `(X : Y : Z)`, `x = X/Z^2`, `y = Y/Z^3`, `Z = 0` the
identity, in the Montgomery domain. Doubling is `dbl-2007-bl` for a
general `a`, or `dbl-2001-b` when `a = -3` (the NIST curves, SM2): which
one is a property of the curve and public. Addition is `add-2007-bl`,
made complete the way `ec::ct` makes it: the generic sum and the
doubling are both computed, and masks pick the doubling for `P + P`,
the identity for `P + (-P)`, and the other operand when either is the
identity. Which case applies is a fact about secret values, so it is
never a branch.

## The scalar

A fixed window of four bits over every limb of the scalar: a table of
`0P .. 15P`, then per nibble four doublings and one addition of the
entry, read by touching all sixteen with masks. The number of limbs is
the scalar's fixed width, which is public. Per bit that is 1.25
doublings and a quarter of an addition, against `ec::ct`'s ladder's two
and one.
*/

use crate::bignum::fixed::{is_zero, select, Arith, Mont, P256};
use crate::bignum::BigUint;

use super::{Curve, Point};

/// A point with `Z = 1`, in the domain: what the base-point table holds.
#[derive(Clone, Copy)]
struct Affine<const N: usize> {
    x: [u64; N],
    y: [u64; N],
}

#[derive(Clone, Copy)]
struct Jacobian<const N: usize> {
    x: [u64; N],
    y: [u64; N],
    z: [u64; N],
}

impl<const N: usize> Jacobian<N> {
    /// `other` when `choice` is 1, `self` when it is 0.
    fn select(&self, other: &Self, choice: u64) -> Self {
        Jacobian {
            x: select(&self.x, &other.x, choice),
            y: select(&self.y, &other.y, choice),
            z: select(&self.z, &other.z, choice),
        }
    }
}

/// A curve's field arithmetic: `Mont<N>` for a modulus known at run
/// time, or a type whose modulus is a constant (`P256`).
struct Field<const N: usize, A: Arith<N>> {
    f: A,
    /// The curve's `a`, in the domain.
    a: [u64; N],
    minus_three: bool,
}

/// A public number as exactly `N` limbs, or an error when it is wider.
fn limbs<const N: usize>(value: &BigUint) -> Result<[u64; N], String> {
    let source = value.limbs();
    if source.len() > N {
        return Err(format!("A value of {} limbs does not fit in {}.", source.len(), N));
    }
    let mut out = [0u64; N];
    out[..source.len()].copy_from_slice(source);
    Ok(out)
}

impl<const N: usize> Field<N, Mont<N>> {
    fn new(curve: &Curve) -> Result<Field<N, Mont<N>>, String> {
        Field::with(curve, Mont::new(limbs(&curve.p)?)?)
    }
}

impl<const N: usize, A: Arith<N>> Field<N, A> {
    /// The field for `curve` over `f`, whose modulus is the curve's `p`.
    fn with(curve: &Curve, f: A) -> Result<Field<N, A>, String> {
        if f.modulus() != limbs::<N>(&curve.p)? {
            return Err("The field arithmetic is for another modulus.".to_string());
        }
        let a = curve.a.rem(&curve.p)?;
        let minus_three = curve.p.sub(&BigUint::from_u64(3)).map(|m| m == a).unwrap_or(false);
        Ok(Field { a: f.enter(&limbs(&a)?), f, minus_three })
    }

    fn identity(&self) -> Jacobian<N> {
        Jacobian { x: self.f.one(), y: self.f.one(), z: [0; N] }
    }

    /// An affine point into the domain. Coordinates are public here -
    /// a base point or a peer's validated key - and reduced first.
    fn enter(&self, curve: &Curve, point: &Point) -> Result<Jacobian<N>, String> {
        match (point.x(), point.y()) {
            (Some(x), Some(y)) => Ok(Jacobian {
                x: self.f.enter(&limbs(&x.rem(&curve.p)?)?),
                y: self.f.enter(&limbs(&y.rem(&curve.p)?)?),
                z: self.f.one(),
            }),
            _ => Ok(self.identity()),
        }
    }

    /// Back to an affine point. The inversion is Fermat's, and the
    /// coordinates are computed whether or not the point is the identity;
    /// `publish` then decides.
    fn leave(&self, p: &Jacobian<N>) -> Point {
        let f = &self.f;
        let z_inverse = f.invert(&p.z);
        let z_inverse2 = f.square(&z_inverse);
        let x = f.leave(&f.mul(&p.x, &z_inverse2));
        let y = f.leave(&f.mul(&p.y, &f.mul(&z_inverse2, &z_inverse)));
        publish(is_zero(&p.z), &x, &y)
    }

    /// `dbl-2007-bl`, or `dbl-2001-b`'s `M` when `a = -3`. The identity
    /// doubles to `Z3 = 2YZ = 0`, and a point of order two (`Y = 0`) to
    /// the same, so neither needs a case of its own.
    fn double(&self, p: &Jacobian<N>) -> Jacobian<N> {
        let f = &self.f;
        let xx = f.square(&p.x);
        let yy = f.square(&p.y);
        let yyyy = f.square(&yy);
        let zz = f.square(&p.z);
        // S = 2 * ((X + YY)^2 - XX - YYYY) = 4 * X * YY
        let s = f.sub(&f.sub(&f.square(&f.add(&p.x, &yy)), &xx), &yyyy);
        let s = f.add(&s, &s);
        // M = 3 * XX + a * ZZ^2
        let m = if self.minus_three {
            // 3 * (X - ZZ) * (X + ZZ) = 3 * XX - 3 * ZZ^2
            let product = f.mul(&f.sub(&p.x, &zz), &f.add(&p.x, &zz));
            f.add(&f.add(&product, &product), &product)
        } else {
            let three_xx = f.add(&f.add(&xx, &xx), &xx);
            f.add(&three_xx, &f.mul(&self.a, &f.square(&zz)))
        };
        let x3 = f.sub(&f.square(&m), &f.add(&s, &s));
        let yyyy2 = f.add(&yyyy, &yyyy);
        let yyyy4 = f.add(&yyyy2, &yyyy2);
        let yyyy8 = f.add(&yyyy4, &yyyy4);
        let y3 = f.sub(&f.mul(&m, &f.sub(&s, &x3)), &yyyy8);
        // Z3 = (Y + Z)^2 - YY - ZZ = 2 * Y * Z
        let z3 = f.sub(&f.sub(&f.square(&f.add(&p.y, &p.z)), &yy), &zz);
        Jacobian { x: x3, y: y3, z: z3 }
    }

    /// `add-2007-bl` with the special cases selected by mask.
    fn add(&self, p: &Jacobian<N>, q: &Jacobian<N>) -> Jacobian<N> {
        let (generic, same_x, same_y) = self.sum(p, q);
        // The same point: the generic formula has h = 0 and gives the
        // identity, so the doubling is computed and chosen. P + (-P) is
        // the identity, which h = 0 also gives, selected anyway so the
        // intent does not rest on that. Either operand the identity
        // overrides both.
        let mut out = generic.select(&self.double(p), same_x & same_y);
        out = out.select(&self.identity(), same_x & (same_y ^ 1));
        out = out.select(q, is_zero(&p.z));
        out.select(p, is_zero(&q.z))
    }

    /// `add-2007-bl` itself, right whenever neither operand is the
    /// identity and `x` differs, and whether `x` and `y` agree (1 or 0),
    /// which says which special case applies otherwise.
    fn sum(&self, p: &Jacobian<N>, q: &Jacobian<N>) -> (Jacobian<N>, u64, u64) {
        let f = &self.f;
        let z1z1 = f.square(&p.z);
        let z2z2 = f.square(&q.z);
        let u1 = f.mul(&p.x, &z2z2);
        let u2 = f.mul(&q.x, &z1z1);
        let s1 = f.mul(&p.y, &f.mul(&q.z, &z2z2));
        let s2 = f.mul(&q.y, &f.mul(&p.z, &z1z1));
        let h = f.sub(&u2, &u1);
        let s_difference = f.sub(&s2, &s1);
        let same_x = is_zero(&h);
        let same_y = is_zero(&s_difference);

        let h2 = f.add(&h, &h);
        let i = f.square(&h2);
        let j = f.mul(&h, &i);
        let r = f.add(&s_difference, &s_difference);
        let v = f.mul(&u1, &i);
        let x3 = f.sub(&f.sub(&f.square(&r), &j), &f.add(&v, &v));
        let s1j = f.mul(&s1, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&s1j, &s1j));
        let z1_plus_z2 = f.square(&f.add(&p.z, &q.z));
        let z3 = f.mul(&f.sub(&f.sub(&z1_plus_z2, &z1z1), &z2z2), &h);
        (Jacobian { x: x3, y: y3, z: z3 }, same_x, same_y)
    }

    /// `p + q` for an affine `q`, `madd-2007-bl`: seven multiplications
    /// and four squarings. When `p` is the identity the sum is `q`, and
    /// when `q_identity` is 1 it is `p`, both by mask. `P = Q` and
    /// `P = -Q` are **not** handled: the one caller, `base_multiply`,
    /// cannot meet them, and says why.
    fn add_affine(&self, p: &Jacobian<N>, q: &Affine<N>, q_identity: u64) -> Jacobian<N> {
        let f = &self.f;
        let z1z1 = f.square(&p.z);
        let u2 = f.mul(&q.x, &z1z1);
        let s2 = f.mul(&q.y, &f.mul(&p.z, &z1z1));
        let h = f.sub(&u2, &p.x);
        let hh = f.square(&h);
        let hh2 = f.add(&hh, &hh);
        let i = f.add(&hh2, &hh2);
        let j = f.mul(&h, &i);
        let r = f.sub(&s2, &p.y);
        let r = f.add(&r, &r);
        let v = f.mul(&p.x, &i);
        let x3 = f.sub(&f.sub(&f.square(&r), &j), &f.add(&v, &v));
        let y1j = f.mul(&p.y, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&y1j, &y1j));
        let z3 = f.sub(&f.sub(&f.square(&f.add(&p.z, &h)), &z1z1), &hh);
        let sum = Jacobian { x: x3, y: y3, z: z3 };
        let lifted = Jacobian { x: q.x, y: q.y, z: f.one() };
        sum.select(&lifted, is_zero(&p.z)).select(p, q_identity)
    }

    /// The base-point table for a generator `g` of prime order with
    /// `bits`-bit order: row `i` holds `j * 16^i * g` for `j` in 1..16,
    /// affine, as `x` then `y` limbs. Everything here is public, and the
    /// affine conversion shares one inversion across the table
    /// (Montgomery's trick).
    fn base_table(&self, g: &Jacobian<N>, bits: usize) -> Vec<u64> {
        let f = &self.f;
        let rows = bits.div_ceil(4);
        let mut points = Vec::with_capacity(15 * rows);
        let mut row_base = *g;
        for _ in 0..rows {
            let mut multiple = row_base;
            for _ in 1..16 {
                points.push(multiple);
                multiple = self.add(&multiple, &row_base);
            }
            // `multiple` is now 16 times the row's base.
            row_base = multiple;
        }
        // Prefix products of the Z coordinates, one inversion, and back.
        let mut prefix = Vec::with_capacity(points.len());
        let mut running = f.one();
        for point in &points {
            running = f.mul(&running, &point.z);
            prefix.push(running);
        }
        let mut inverse = f.invert(&running);
        let mut table = vec![0u64; points.len() * 2 * N];
        for index in (0..points.len()).rev() {
            let before = if index == 0 { f.one() } else { prefix[index - 1] };
            let z_inverse = f.mul(&inverse, &before);
            inverse = f.mul(&inverse, &points[index].z);
            let z_inverse2 = f.square(&z_inverse);
            let at = index * 2 * N;
            table[at..at + N].copy_from_slice(&f.mul(&points[index].x, &z_inverse2));
            table[at + N..at + 2 * N]
                .copy_from_slice(&f.mul(&points[index].y, &f.mul(&z_inverse2, &z_inverse)));
        }
        table
    }

    /// `k * g` from `g`'s table, for `k` below the group order: one
    /// affine addition per nibble and no doublings, each entry read by
    /// touching all fifteen in its row with masks.
    ///
    /// Why the sum never meets `P = Q` or `P = -Q`: after row `i` the
    /// accumulator is `m * g` with `m` the low `4i` bits of `k`, and the
    /// entry is `j * 16^i * g`. Equal would need `m = j * 16^i` (mod the
    /// order), but `m < 16^i`; opposite would need `m + j * 16^i`, the
    /// low `4i + 4` bits of `k`, to be a multiple of the order, but it is
    /// at most `k`, which is below it. Zero digits are the identity
    /// cases, which are handled.
    fn base_multiply(&self, table: &[u64], k: &[u64]) -> Jacobian<N> {
        let rows = table.len() / (30 * N);
        let mut acc = self.identity();
        for row in 0..rows {
            let nibble = k.get(row / 16).map_or(0, |limb| (limb >> (4 * (row % 16))) & 15);
            let mut entry = Affine { x: [0; N], y: [0; N] };
            for j in 1..16u64 {
                let hit = (j ^ nibble).wrapping_sub(1) >> 63;
                let at = (row * 15 + j as usize - 1) * 2 * N;
                let x: &[u64; N] = table[at..at + N].try_into().expect("N limbs");
                let y: &[u64; N] = table[at + N..at + 2 * N].try_into().expect("N limbs");
                entry.x = select(&entry.x, x, hit);
                entry.y = select(&entry.y, y, hit);
            }
            let zero = ((nibble | nibble.wrapping_neg()) >> 63) ^ 1;
            acc = self.add_affine(&acc, &entry, zero);
        }
        acc
    }

    /// `p + q` for **public** points: `add`'s formula, with its special
    /// cases taken by branching instead of computing the doubling every
    /// time.
    fn add_public(&self, p: &Jacobian<N>, q: &Jacobian<N>) -> Jacobian<N> {
        if is_zero(&p.z) == 1 {
            return *q;
        }
        if is_zero(&q.z) == 1 {
            return *p;
        }
        match self.sum(p, q) {
            (sum, 0, _) => sum,
            (_, _, 1) => self.double(p),
            _ => self.identity(),
        }
    }

    /// `k * p` for a **public** `k`: a sliding window over the odd
    /// multiples `p, 3p, .. 15p`, which branches on the scalar's bits.
    /// For verification, where both scalars are public.
    fn multiply_public(&self, p: &Jacobian<N>, k: &[u64]) -> Jacobian<N> {
        let twice = self.double(p);
        let mut odd = [*p; 8];
        for i in 1..8 {
            odd[i] = self.add_public(&odd[i - 1], &twice);
        }
        let bit = |i: usize| (k[i / 64] >> (i % 64)) & 1;
        let mut acc = self.identity();
        let mut i = 64 * k.len();
        while i > 0 {
            let top = i - 1;
            if bit(top) == 0 {
                acc = self.double(&acc);
                i -= 1;
                continue;
            }
            let mut low = top.saturating_sub(3);
            while bit(low) == 0 {
                low += 1;
            }
            let mut value = 0;
            for position in (low..=top).rev() {
                acc = self.double(&acc);
                value = (value << 1) | bit(position);
            }
            acc = self.add_public(&acc, &odd[(value >> 1) as usize]);
            i = low;
        }
        acc
    }

    /// `k * p`, the scalar as little-endian limbs, every limb used.
    fn multiply(&self, p: &Jacobian<N>, k: &[u64]) -> Jacobian<N> {
        let mut table = [self.identity(); 16];
        table[1] = *p;
        for i in 2..16 {
            table[i] = self.add(&table[i - 1], p);
        }
        let mut acc = self.identity();
        for i in (0..16 * k.len()).rev() {
            for _ in 0..4 {
                acc = self.double(&acc);
            }
            let nibble = (k[i / 16] >> (4 * (i % 16))) & 15;
            let mut entry = table[0];
            for (index, candidate) in (0u64..).zip(table.iter()) {
                let hit = (index ^ nibble).wrapping_sub(1) >> 63;
                entry = entry.select(candidate, hit);
            }
            acc = self.add(&acc, &entry);
        }
        acc
    }
}

/// Where the result stops being secret: the caller publishes it, or
/// hashes its x as a shared secret through `BigUint`. Whether it is the
/// identity is a branch here, and `BigUint` normalises the coordinates.
/// One function, not generic and never inlined, so that
/// `scripts/ct_check.py` can name the boundary.
#[inline(never)]
fn publish(identity: u64, x: &[u64], y: &[u64]) -> Point {
    if identity == 1 {
        return Point::identity();
    }
    Point::new(BigUint::from_limbs(x.to_vec()), BigUint::from_limbs(y.to_vec()))
}

/// Calls `$run(field, args..)` with the field the curve's modulus
/// needs: the constant P-256 arithmetic for P-256, `Mont<N>` for the
/// limb count otherwise, `None` above nine limbs.
macro_rules! with_field {
    ($curve:expr, $run:ident($($arg:expr),*)) => {{
        let curve: &Curve = $curve;
        let size = curve.p.limbs().len();
        if size == 4 && curve.p.limbs() == P256::P {
            return Some(Field::with(curve, P256).and_then(|f| $run::<4, P256>(f, $($arg),*)));
        }
        Some(match size {
            1 => Field::<1, Mont<1>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            2 => Field::<2, Mont<2>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            3 => Field::<3, Mont<3>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            4 => Field::<4, Mont<4>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            5 => Field::<5, Mont<5>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            6 => Field::<6, Mont<6>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            7 => Field::<7, Mont<7>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            8 => Field::<8, Mont<8>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            9 => Field::<9, Mont<9>>::new(curve).and_then(|f| $run(f, $($arg),*)),
            _ => return None,
        })
    }};
}

/// The base-point tables built so far, one per curve, keyed by every
/// parameter that goes into one. Built on first use: 960 points for
/// P-256, 64 KiB, a few milliseconds. At most `KEPT` are held, so a
/// program cycling through registered curves does not grow without
/// bound.
static TABLES: std::sync::Mutex<Vec<(Key, Table)>> = std::sync::Mutex::new(Vec::new());
/// Every parameter a table depends on, as limbs with their counts.
type Key = Vec<u64>;
/// One curve's table, shared by whoever is using it.
type Table = std::sync::Arc<Vec<u64>>;
const KEPT: usize = 16;

fn table_for<const N: usize, A: Arith<N>>(curve: &Curve, field: &Field<N, A>)
                                          -> Result<Table, String> {
    let mut key = Vec::new();
    for value in [&curve.p, &curve.a, &curve.b, &curve.n] {
        key.push(value.limbs().len() as u64);
        key.extend_from_slice(value.limbs());
    }
    for value in [curve.g.x(), curve.g.y()] {
        let value = value.ok_or("The base point is the identity.")?;
        key.push(value.limbs().len() as u64);
        key.extend_from_slice(value.limbs());
    }
    let mut tables = TABLES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, table)) = tables.iter().find(|(k, _)| *k == key) {
        return Ok(table.clone());
    }
    let g = field.enter(curve, &curve.g)?;
    let table = std::sync::Arc::new(field.base_table(&g, curve.n.bit_len()));
    if tables.len() == KEPT {
        tables.remove(0);
    }
    tables.push((key, table.clone()));
    Ok(table)
}

fn run_base<const N: usize, A: Arith<N>>(field: Field<N, A>, curve: &Curve, k: &[u64])
                                          -> Result<Point, String> {
    let table = table_for(curve, &field)?;
    Ok(field.leave(&field.base_multiply(&table, k)))
}

fn run_verify<const N: usize, A: Arith<N>>(field: Field<N, A>, curve: &Curve, u1: &[u64],
                                            u2: &[u64], q: &Point) -> Result<Point, String> {
    let table = table_for(curve, &field)?;
    let from_g = field.base_multiply(&table, u1);
    let from_q = field.multiply_public(&field.enter(curve, q)?, u2);
    Ok(field.leave(&field.add_public(&from_g, &from_q)))
}

/// `k * G` for the curve's own base point, from a table of its
/// multiples, **for `k` below the group order** - the caller checks,
/// and `base_multiply` says why the arithmetic depends on it. Constant
/// time in `k`; `None` when the field is wider than nine limbs.
pub(crate) fn base_mul(curve: &Curve, k: &[u64]) -> Option<Result<Point, String>> {
    with_field!(curve, run_base(curve, k))
}

/// `u1 * G + u2 * q`, ECDSA verification's sum, for public scalars with
/// `u1` below the group order. Not constant time: everything in it is
/// public. `None` when the field is wider than nine limbs.
pub(crate) fn verify_sum(curve: &Curve, u1: &[u64], u2: &[u64], q: &Point)
                         -> Option<Result<Point, String>> {
    with_field!(curve, run_verify(curve, u1, u2, q))
}

fn run_signature<const N: usize>(n: &BigUint, k: &[u64], d: &[u64], e: &[u64], r: &[u64])
                                 -> Result<Vec<u64>, String> {
    let order = Mont::<N>::new(limbs(n)?)?;
    let fit = |value: &[u64]| -> Result<[u64; N], String> {
        if value.len() > N && value[N..].iter().any(|&limb| limb != 0) {
            return Err("A scalar is wider than the group order.".to_string());
        }
        let mut out = [0u64; N];
        let used = N.min(value.len());
        out[..used].copy_from_slice(&value[..used]);
        Ok(out)
    };
    // Montgomery's product of a domain value and a plain one is plain:
    // `mul(rR, d) = r * d`, and `mul(k^-1 R, sum) = k^-1 * sum`.
    let rd = order.mul(&order.enter(&fit(r)?), &fit(d)?);
    let sum = order.add(&fit(e)?, &rd);
    let k_inverse = order.invert(&order.enter(&fit(k)?));
    Ok(order.mul(&k_inverse, &sum).to_vec())
}

/// ECDSA's `s = k^-1 (e + r d) mod n` for a prime `n`, every input below
/// `n` and given as little-endian limbs; constant time in all of them.
/// `None` when `n` is wider than nine limbs.
pub(crate) fn signature_s(n: &BigUint, k: &[u64], d: &[u64], e: &[u64], r: &[u64])
                          -> Option<Result<Vec<u64>, String>> {
    Some(match n.limbs().len() {
        1 => run_signature::<1>(n, k, d, e, r),
        2 => run_signature::<2>(n, k, d, e, r),
        3 => run_signature::<3>(n, k, d, e, r),
        4 => run_signature::<4>(n, k, d, e, r),
        5 => run_signature::<5>(n, k, d, e, r),
        6 => run_signature::<6>(n, k, d, e, r),
        7 => run_signature::<7>(n, k, d, e, r),
        8 => run_signature::<8>(n, k, d, e, r),
        9 => run_signature::<9>(n, k, d, e, r),
        _ => return None,
    })
}

fn run<const N: usize, A: Arith<N>>(field: Field<N, A>, curve: &Curve, point: &Point,
                                     k: &[u64]) -> Result<Point, String> {
    let base = field.enter(curve, point)?;
    Ok(field.leave(&field.multiply(&base, k)))
}

/// `k * point` for a scalar given as little-endian limbs, constant time
/// in the scalar, or `None` when the field is wider than nine limbs and
/// the caller has to use `ec::ct`. The scalar's limb count is taken as
/// public.
pub(crate) fn scalar_mul(curve: &Curve, point: &Point, k: &[u64])
                         -> Option<Result<Point, String>> {
    with_field!(curve, run(curve, point, k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::{ct, curves};

    fn random_below(bound: &BigUint) -> BigUint {
        crate::random::below(bound).unwrap()
    }

    /// Every registered curve, against both other implementations: the
    /// `BigUint` double-and-add and `ec::ct`'s ladder. The scalars include
    /// the ones whose window steps meet the special cases - n - 1, n,
    /// n + 1 and 2n end in `P + (-P)` or pass through the identity - and
    /// the points include a random multiple as well as the generator.
    #[test]
    fn test_every_curve_agrees_with_both_references() {
        for curve in curves::all() {
            let n = &curve.n;
            let one = BigUint::one();
            let other = curve.scalar_mul_double_and_add(&curve.g, &random_below(n));
            let mut scalars = vec![
                BigUint::zero(), one.clone(), BigUint::from_u64(2), BigUint::from_u64(16),
                BigUint::from_u64(17), n.sub(&one).unwrap(), n.clone(), n.add(&one),
                n.add(n), BigUint::from_u64(0x1111_1111),
            ];
            scalars.extend((0..4).map(|_| random_below(n)));
            for point in [&curve.g, &other] {
                for k in &scalars {
                    let width = curve.p.limbs().len().max(n.limbs().len()) + 1;
                    let secret = crate::bignum::Secret::from_biguint(k, width).unwrap();
                    let ours = scalar_mul(&curve, point, secret.limbs()).unwrap().unwrap();
                    assert_eq!(ours, curve.scalar_mul_double_and_add(point, k),
                               "{}: {} * P against double-and-add", curve.name, k.to_hex());
                    let field = ct::Field::new(&curve).unwrap();
                    let base = field.from_point(point).unwrap();
                    let ladder = field.to_point(&field.scalar_mul(&base, &secret, 64 * width))
                        .unwrap();
                    assert_eq!(ours, ladder, "{}: against ec::ct", curve.name);
                }
            }
            // The identity as the point.
            assert!(scalar_mul(&curve, &Point::identity(), &[5]).unwrap().unwrap().is_identity());
        }
    }

    /// The addition's special cases by name, on P-256 (with both its
    /// arithmetics) and on curves with a general `a`, through the
    /// Jacobian functions directly.
    #[test]
    fn test_the_special_cases_of_addition() {
        special_cases(&curves::p256(), Field::with(&curves::p256(), P256).unwrap());
        for curve in [curves::p256(), curves::secp256k1(), curves::gost256_a()] {
            special_cases(&curve, Field::<4, Mont<4>>::new(&curve).unwrap());
        }
    }

    fn special_cases<A: Arith<4>>(curve: &Curve, field: Field<4, A>) {
        {
            let g = field.enter(curve, &curve.g).unwrap();
            let identity = field.identity();
            let minus_g = field.enter(curve, &curve.negate(&curve.g)).unwrap();
            let leave = |p: &Jacobian<4>| field.leave(p);
            assert_eq!(leave(&field.add(&g, &g)), curve.double(&curve.g), "{}", curve.name);
            assert_eq!(leave(&field.add(&g, &g)), leave(&field.double(&g)));
            assert!(leave(&field.add(&g, &minus_g)).is_identity());
            assert_eq!(leave(&field.add(&g, &identity)), curve.g);
            assert_eq!(leave(&field.add(&identity, &g)), curve.g);
            assert!(leave(&field.add(&identity, &identity)).is_identity());
            assert!(leave(&field.double(&identity)).is_identity());
        }
    }

    /// Scalars below the order whose nibbles exercise the table: zero,
    /// one, single nibbles in every position, all-ones runs, the order
    /// minus one, and random ones.
    fn scalars_below(n: &BigUint) -> Vec<BigUint> {
        let mut out = vec![BigUint::zero(), BigUint::one(), BigUint::from_u64(15),
                           BigUint::from_u64(16), n.sub(&BigUint::one()).unwrap(),
                           n.sub(&BigUint::from_u64(16)).unwrap()];
        for shift in [4, 60, 64, 128, n.bit_len() - 5] {
            out.push(BigUint::from_u64(0xF).shl(shift));
            out.push(BigUint::one().shl(shift + 1).sub(&BigUint::one()).unwrap());
        }
        out.extend((0..6).map(|_| random_below(n)));
        out.into_iter().filter(|k| k < n).collect()
    }

    /// `base_mul`, the table path, against double-and-add on every curve.
    #[test]
    fn test_the_base_point_table_agrees_with_double_and_add() {
        for curve in curves::all() {
            for k in scalars_below(&curve.n) {
                let width = curve.n.limbs().len();
                let secret = crate::bignum::Secret::from_biguint(&k, width).unwrap();
                let ours = base_mul(&curve, secret.limbs()).unwrap().unwrap();
                assert_eq!(ours, curve.scalar_mul_double_and_add(&curve.g, &k),
                           "{}: {}", curve.name, k.to_hex());
            }
        }
    }

    /// The table is per curve: two curves with the same field size, used
    /// alternately, each get their own.
    #[test]
    fn test_each_curve_gets_its_own_table() {
        let (a, b) = (curves::p256(), curves::secp256k1());
        for _ in 0..2 {
            for curve in [&a, &b] {
                let k = BigUint::from_u64(0x1234_5678_9ABC);
                assert_eq!(base_mul(curve, k.limbs()).unwrap().unwrap(),
                           curve.scalar_mul_double_and_add(&curve.g, &k), "{}", curve.name);
            }
        }
    }

    /// The table belongs to the generator as well as the field: the same
    /// curve with `2G`, or with `-G` - the same x - as its base point
    /// gets a table of its own.
    #[test]
    fn test_another_generator_on_the_same_curve_gets_another_table() {
        let curve = curves::p256();
        let mut doubled = curves::p256();
        doubled.g = curve.double(&curve.g);
        let mut negated = curves::p256();
        negated.g = curve.negate(&curve.g);
        let k = BigUint::from_u64(0xDEAD_BEEF_1234);
        for _ in 0..2 {
            for c in [&curve, &doubled, &negated] {
                assert_eq!(base_mul(c, k.limbs()).unwrap().unwrap(),
                           curve.scalar_mul_double_and_add(&c.g, &k));
            }
        }
    }

    /// No more than `KEPT` tables are held, however many base points
    /// pass through.
    #[test]
    fn test_the_table_cache_is_bounded() {
        let mut curve = curves::secp256k1();
        for _ in 0..KEPT + 2 {
            curve.g = curve.double(&curve.g);
            base_mul(&curve, &[3]).unwrap().unwrap();
            assert!(TABLES.lock().unwrap().len() <= KEPT);
        }
    }

    /// `verify_sum` against the two products added by the reference, with
    /// the cases where the two halves meet: `q` the base point itself and
    /// its negation, with equal scalars, so the final addition is a
    /// doubling or reaches the identity.
    #[test]
    fn test_the_verification_sum_agrees_with_double_and_add() {
        for curve in curves::all() {
            let n = &curve.n;
            let other = curve.scalar_mul_double_and_add(&curve.g, &random_below(n));
            for (u1, u2, q) in [
                (random_below(n), random_below(n), other.clone()),
                (BigUint::zero(), random_below(n), other.clone()),
                (random_below(n), BigUint::zero(), other.clone()),
                (BigUint::from_u64(7), BigUint::from_u64(7), curve.g.clone()),
                (BigUint::from_u64(7), BigUint::from_u64(7), curve.negate(&curve.g)),
                (n.sub(&BigUint::one()).unwrap(), BigUint::one(), curve.g.clone()),
            ] {
                let ours = verify_sum(&curve, u1.limbs(), u2.limbs(), &q).unwrap().unwrap();
                let reference = curve.add(&curve.scalar_mul_double_and_add(&curve.g, &u1),
                                          &curve.scalar_mul_double_and_add(&q, &u2));
                assert_eq!(ours, reference, "{}: {} {}", curve.name, u1.to_hex(), u2.to_hex());
            }
        }
    }

    /// ECDSA's `s` against the same arithmetic done with `BigUint`.
    #[test]
    fn test_the_signature_scalar_agrees_with_biguint() {
        for curve in curves::all() {
            let n = &curve.n;
            for _ in 0..4 {
                let [k, d, e, r] = [(); 4].map(|_| random_below(n));
                if k.is_zero() {
                    continue;
                }
                let ours = signature_s(n, k.limbs(), d.limbs(), e.limbs(), r.limbs())
                    .unwrap().unwrap();
                let expected = k.mod_inverse(n).unwrap()
                    .mod_mul(&e.add(&r.mod_mul(&d, n).unwrap()).rem(n).unwrap(), n).unwrap();
                assert_eq!(BigUint::from_limbs(ours), expected, "{}", curve.name);
            }
        }
    }

    /// Wider than nine limbs is not handled here.
    #[test]
    fn test_a_wide_field_is_declined() {
        let mut curve = curves::p256();
        curve.p = BigUint::one().shl(640).add(&BigUint::one());
        assert!(scalar_mul(&curve, &curve.g.clone(), &[1]).is_none());
    }
}
