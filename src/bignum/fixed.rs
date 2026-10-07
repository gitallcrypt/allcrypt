/*!
Montgomery arithmetic modulo an odd `n < 2^(64N)` on `[u64; N]`.

The same CIOS algorithm as `Montgomery` in `montgomery.rs`, on fixed-size
arrays rather than `Secret`'s vectors: no allocation, loop bounds the
compiler knows, and the whole element in registers or on the stack. The
width is a const parameter, so each field size is its own compiled
copy; `ec::fixed` picks one by the curve's limb count.

Constant time in the same sense as `bignum::ct`: no function here
branches on, or indexes memory by, an element's value. The exponent of
`pow_public` is the one exception, and its name says so - it is used
with `n - 2`, which is public.

Elements are kept fully reduced, below `n`, in and out of every
function; the Montgomery product needs `a * b < n * R`, which that
guarantees.
*/

/// `a + b + carry`, and the carry out.
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = u128::from(a) + u128::from(b) + u128::from(carry);
    (t as u64, (t >> 64) as u64)
}

/// `a - b - borrow`, and the borrow out (0 or 1).
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = u128::from(a).wrapping_sub(u128::from(b)).wrapping_sub(u128::from(borrow));
    (t as u64, (t >> 127) as u64)
}

/// `acc + a * b + carry`, and the high word.
#[inline(always)]
fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = u128::from(acc) + u128::from(a) * u128::from(b) + u128::from(carry);
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
fn add_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut out = [0u64; N];
    let mut carry = 0;
    for i in 0..N {
        (out[i], carry) = adc(a[i], b[i], carry);
    }
    (out, carry)
}

#[inline(always)]
fn sub_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u64) {
    let mut out = [0u64; N];
    let mut borrow = 0;
    for i in 0..N {
        (out[i], borrow) = sbb(a[i], b[i], borrow);
    }
    (out, borrow)
}

/// `b` when `choice` is 1, `a` when it is 0, by a mask.
#[inline(always)]
pub(crate) fn select<const N: usize>(a: &[u64; N], b: &[u64; N], choice: u64) -> [u64; N] {
    let mask = 0u64.wrapping_sub(choice);
    let mut out = [0u64; N];
    for i in 0..N {
        out[i] = a[i] ^ (mask & (a[i] ^ b[i]));
    }
    out
}

/// 1 when every limb is zero, 0 otherwise.
#[inline(always)]
pub(crate) fn is_zero<const N: usize>(a: &[u64; N]) -> u64 {
    let any = a.iter().fold(0, |acc, limb| acc | limb);
    ((any | any.wrapping_neg()) >> 63) ^ 1
}

/// Arithmetic modulo one odd `n`, in the Montgomery domain. Everything
/// is a provided method over four accessors, so that an implementation
/// whose accessors return constants - `P256` - gets every operation
/// compiled with its modulus folded in, from the same source as the
/// general one.
pub(crate) trait Arith<const N: usize>: Copy {
    /// The modulus.
    fn modulus(&self) -> [u64; N];
    /// `-n^-1 mod 2^64`.
    fn n0inv(&self) -> u64;
    /// `R mod n`, `R = 2^(64N)`: one in the domain.
    fn one(&self) -> [u64; N];
    /// `R^2 mod n`: multiplying by it enters the domain.
    fn r2(&self) -> [u64; N];

    /// `x - n` unless that borrows, for `(carry, x)` below `2n`.
    #[inline(always)]
    fn reduce_once(&self, x: [u64; N], carry: u64) -> [u64; N] {
        let (difference, borrow) = sub_limbs(&x, &self.modulus());
        select(&difference, &x, borrow & (carry ^ 1))
    }

    #[inline(always)]
    fn add(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let (sum, carry) = add_limbs(a, b);
        self.reduce_once(sum, carry)
    }

    #[inline(always)]
    fn sub(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let (difference, borrow) = sub_limbs(a, b);
        let (wrapped, _) = add_limbs(&difference, &self.modulus());
        select(&difference, &wrapped, borrow)
    }

    /// The Montgomery product `a * b * R^-1 mod n`, CIOS: each pass adds
    /// `a * b[i]`, then the multiple of `n` that clears the low limb, and
    /// shifts down a limb. The running value stays below `2n`, in `N`
    /// limbs and a carry word.
    #[inline(always)]
    fn mul(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let n = self.modulus();
        let n0inv = self.n0inv();
        let mut t = [0u64; N];
        let mut high = 0u64;
        for &b_i in b {
            let mut carry = 0;
            for j in 0..N {
                (t[j], carry) = mac(t[j], a[j], b_i, carry);
            }
            let (sum, top) = adc(high, carry, 0);
            high = sum;

            let m = t[0].wrapping_mul(n0inv);
            let (_, mut carry) = mac(t[0], m, n[0], 0);
            for j in 1..N {
                (t[j - 1], carry) = mac(t[j], m, n[j], carry);
            }
            let (sum, more) = adc(high, carry, 0);
            t[N - 1] = sum;
            high = top + more;
        }
        self.reduce_once(t, high)
    }

    /// `a * a * R^-1 mod n`, separated (SOS): the double-width square
    /// first, each cross product computed once and doubled, then `N`
    /// reduction passes - `N(N-1)/2` fewer products than `mul(a, a)`.
    #[inline(always)]
    fn square(&self, a: &[u64; N]) -> [u64; N] {
        // Two limbs per input limb, up to the nine `ec::fixed` uses.
        const WIDE: usize = 18;
        assert!(2 * N <= WIDE, "squaring is for up to nine limbs");
        let n = self.modulus();
        let mut wide = [0u64; WIDE];
        for i in 0..N {
            let mut carry = 0;
            for j in i + 1..N {
                (wide[i + j], carry) = mac(wide[i + j], a[i], a[j], carry);
            }
            wide[i + N] = carry;
        }
        let mut top = 0;
        for limb in wide[..2 * N].iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | top;
            top = next;
        }
        let mut carry = 0;
        for i in 0..N {
            let product = u128::from(a[i]) * u128::from(a[i]);
            let low;
            (low, carry) = adc(wide[2 * i], product as u64, carry);
            wide[2 * i] = low;
            let high;
            (high, carry) = adc(wide[2 * i + 1], (product >> 64) as u64, carry);
            wide[2 * i + 1] = high;
        }
        // Montgomery reduction, a limb at a time; `extra` is the carry
        // out of the top limb, which keeps the running value below 2n.
        let mut extra = 0;
        for i in 0..N {
            let m = wide[i].wrapping_mul(self.n0inv());
            let mut carry = 0;
            for j in 0..N {
                (wide[i + j], carry) = mac(wide[i + j], m, n[j], carry);
            }
            (wide[i + N], extra) = adc(wide[i + N], carry, extra);
        }
        let mut out = [0u64; N];
        out.copy_from_slice(&wide[N..2 * N]);
        self.reduce_once(out, extra)
    }

    /// Into the domain: `a * R mod n`, for any `a` below `R`.
    #[inline(always)]
    fn enter(&self, a: &[u64; N]) -> [u64; N] {
        self.mul(a, &self.r2())
    }

    /// Out of the domain.
    #[inline(always)]
    fn leave(&self, a: &[u64; N]) -> [u64; N] {
        let mut one = [0u64; N];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// `a^e` in the domain for a **public** exponent: a fixed window of
    /// four bits, `a^0 .. a^15` indexed by the exponent's nibbles, which
    /// are public. `a` may be secret: what is read depends on `e` alone.
    fn pow_public(&self, a: &[u64; N], e: &[u64; N]) -> [u64; N] {
        let mut table = [self.one(); 16];
        for i in 1..16 {
            table[i] = self.mul(&table[i - 1], a);
        }
        let mut result = self.one();
        for i in (0..16 * N).rev() {
            for _ in 0..4 {
                result = self.square(&result);
            }
            let nibble = (e[i / 16] >> (4 * (i % 16))) & 15;
            if nibble != 0 {
                result = self.mul(&result, &table[nibble as usize]);
            }
        }
        result
    }

    /// `a^(n-2)`: the inverse modulo a prime `n`, and zero for zero.
    fn invert(&self, a: &[u64; N]) -> [u64; N] {
        let mut two = [0u64; N];
        two[0] = 2;
        let (exponent, _) = sub_limbs(&self.modulus(), &two);
        self.pow_public(a, &exponent)
    }
}

/// The arithmetic modulo one odd `n` given at run time.
#[derive(Clone, Copy)]
pub(crate) struct Mont<const N: usize> {
    n: [u64; N],
    n0inv: u64,
    r2: [u64; N],
    one: [u64; N],
}

impl<const N: usize> Arith<N> for Mont<N> {
    #[inline(always)]
    fn modulus(&self) -> [u64; N] {
        self.n
    }
    #[inline(always)]
    fn n0inv(&self) -> u64 {
        self.n0inv
    }
    #[inline(always)]
    fn one(&self) -> [u64; N] {
        self.one
    }
    #[inline(always)]
    fn r2(&self) -> [u64; N] {
        self.r2
    }
}

impl<const N: usize> Mont<N> {
    /// The context for `n`, which must be odd and above 1 - a prime
    /// field's modulus. Everything here is public.
    pub(crate) fn new(n: [u64; N]) -> Result<Mont<N>, String> {
        if n[0] & 1 == 0 || (n[0] == 1 && n[1..].iter().all(|&limb| limb == 0)) {
            return Err("A Montgomery modulus must be odd and above 1.".to_string());
        }
        // -n^-1 mod 2^64 by Newton's iteration, which doubles the number
        // of correct low bits each step: 1, 2, 4, ... 64 after six.
        let mut inverse = 1u64;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inverse)));
        }
        let mut context = Mont { n, n0inv: inverse.wrapping_neg(), r2: [0; N], one: [0; N] };
        // R mod n by doubling 1 64N times: no division, and n is public, so
        // the time it takes says nothing.
        let mut x = [0u64; N];
        x[0] = 1;
        for _ in 0..64 * N {
            x = context.add(&x, &x);
        }
        context.one = x;
        // R^2 mod n without another 64N doublings: in the domain, 2 is
        // `2R`, and raising it to the 64N-th power there gives the domain
        // form of 2^(64N), which is `R * R` - about nine squarings. The
        // products need only `n` and `n0inv`, both set above.
        let two = context.add(&x, &x);
        let exponent = 64 * N;
        let mut r2 = context.one;
        for bit in (0..usize::BITS - exponent.leading_zeros()).rev() {
            r2 = context.square(&r2);
            if (exponent >> bit) & 1 == 1 {
                r2 = context.mul(&r2, &two);
            }
        }
        context.r2 = r2;
        Ok(context)
    }
}

/// P-256's field, `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`, with the
/// modulus and its constants as constants: the same code as `Mont<4>`,
/// compiled with `p`'s zero limb and its `n0inv` of 1 folded in, which
/// takes a third off every product. A test checks the constants against
/// `Mont::new`.
#[derive(Clone, Copy)]
pub(crate) struct P256;

impl P256 {
    pub(crate) const P: [u64; 4] =
        [0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_FFFF_FFFF, 0, 0xFFFF_FFFF_0000_0001];
}

impl Arith<4> for P256 {
    #[inline(always)]
    fn modulus(&self) -> [u64; 4] {
        P256::P
    }
    #[inline(always)]
    fn n0inv(&self) -> u64 {
        1
    }
    #[inline(always)]
    fn one(&self) -> [u64; 4] {
        [1, 0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_FFFF_FFFE]
    }
    #[inline(always)]
    fn r2(&self) -> [u64; 4] {
        [3, 0xFFFF_FFFB_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFE, 0x0000_0004_FFFF_FFFD]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants `P256` carries are the ones `Mont::new` derives.
    #[test]
    fn test_p256_constants_are_derived_ones() {
        let general = Mont::new(P256::P).unwrap();
        assert_eq!(general.n0inv(), P256.n0inv());
        assert_eq!(general.one(), P256.one());
        assert_eq!(general.r2(), P256.r2());
        let a = [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210, 0x1111_2222_3333_4444, 7];
        let b = [5, 0xFFFF_FFFF_FFFF_FFFF, 0, 0xFFFF_FFFF_0000_0000];
        assert_eq!(general.mul(&a, &b), P256.mul(&a, &b));
        assert_eq!(general.invert(&a), P256.invert(&a));
    }

    /// Squaring is its own code; it must equal `mul(a, a)` for every
    /// width, at the values that carry most - `n - 1`, all ones below
    /// `n` - and at random ones.
    #[test]
    fn test_squaring_equals_multiplying_by_itself() {
        fn check<const N: usize>(n: [u64; N]) {
            let f = Mont::new(n).unwrap();
            let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ n[0];
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let mut values = vec![[0u64; N], f.one(), f.sub(&[0; N], &f.one())];
            for _ in 0..200 {
                let mut x = [0u64; N];
                x.iter_mut().for_each(|limb| *limb = next());
                // Below n: the elements are reduced.
                x[N - 1] %= n[N - 1].max(1);
                values.push(x);
            }
            for x in values {
                assert_eq!(f.square(&x), f.mul(&x, &x), "{N} limbs: {x:x?}");
            }
        }
        check([0xFFFF_FFFF_FFFF_FFC5]);
        check([0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF]);
        check([u64::MAX - 188, u64::MAX, u64::MAX, u64::MAX]);
        check(P256::P);
        check([u64::MAX - 0x1_0000_03D0, u64::MAX, u64::MAX, u64::MAX]);
        check([u64::MAX; 6].map(|limb| limb ^ 0x10));
        check([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX,
               0x1FF]);
        let x = [5, 0xFFFF_FFFF_0000_0000, 3, 0xFFFF_FFFF_0000_0000];
        assert_eq!(P256.square(&x), P256.mul(&x, &x));
    }
}
