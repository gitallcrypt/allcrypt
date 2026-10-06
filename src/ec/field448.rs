/*!
Arithmetic modulo `p = 2^448 - 2^224 - 1` in eight 56-bit limbs.

An element is `sum(l_i * 2^(56 i))` for `i` in `0..8`, each limb a `u64`.
As in `field25519.rs` the form is redundant - limbs may run past 56 bits
between operations and the value may exceed `p` - and only `to_bytes`
produces the canonical one. Nothing here branches on or indexes by the
value of an element.

**Why 56-bit limbs.** The reduction identity is `2^448 = 2^224 + 1
(mod p)`, and `224 = 4 * 56`. With this limb size a column of the product
at position `k >= 8` folds back as a plain addition into columns `k - 8`
and `k - 4`, with no shifts and no multiplier: the whole reduction is
fourteen `u128` additions and a carry chain.

**Limb bounds.** Everything returned has passed through a carry and has
limbs below 2^57. Everything taken assumes no more. Under that bound a
limb product is below 2^114, a column of eight below 2^117, and after
folding a column is below 2^120, which a `u128` holds.
*/

const MASK: u64 = (1 << 56) - 1;

/// `p` as limbs: all ones except limb 4, which is missing bit 224.
const P: [u64; 8] = [MASK, MASK, MASK, MASK, MASK - 1, MASK, MASK, MASK];

/// An element of GF(2^448 - 2^224 - 1). See the module comment.
#[derive(Clone, Copy)]
pub(crate) struct Fe([u64; 8]);

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 8]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0]);

    /// From 56 little-endian bytes. Every bit is used - there is no spare
    /// one - and a value at or above `p` behaves as itself reduced.
    pub(crate) fn from_bytes(bytes: &[u8; 56]) -> Fe {
        let mut limbs = [0u64; 8];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(7)) {
            let mut word = [0u8; 8];
            word[..7].copy_from_slice(chunk);
            *limb = u64::from_le_bytes(word);
        }
        Fe(limbs)
    }

    /// The canonical little-endian encoding, below `p`.
    pub(crate) fn to_bytes(self) -> [u8; 56] {
        // Three carries leave every limb below 2^56 and the value below
        // 2^448. The first brings limbs under 2^56 except 0 and 4, which
        // take the folded carry. The second can carry 1 out of the top,
        // and only when what remains is below 2^233, so adding it back
        // can overflow limb 0 and nothing above limb 4. The third
        // absorbs that.
        let h = self.carry().carry().carry().0;

        // h < 2^448 < 2p, so subtract p once and keep the difference
        // unless it borrowed.
        let mut difference = [0u64; 8];
        let mut borrow = 0i64;
        for ((d, &limb), &prime) in difference.iter_mut().zip(&h).zip(&P) {
            let value = limb as i64 - prime as i64 + borrow;
            *d = value as u64 & MASK;
            borrow = value >> 56;
        }
        // All ones when h < p (keep h), zero otherwise (keep h - p).
        let keep = borrow as u64;
        let mut out = [0u8; 56];
        for ((chunk, &d), &limb) in out.chunks_exact_mut(7).zip(&difference).zip(&h) {
            let chosen = d ^ (keep & (d ^ limb));
            chunk.copy_from_slice(&chosen.to_le_bytes()[..7]);
        }
        out
    }

    /// Every limb back below 2^56, the carry out of limb 7 added to limbs
    /// 0 and 4 (`2^448 = 2^224 + 1`). Those two can end above 2^56 by the
    /// carry, which for inputs below 2^64 is under 2^8.
    #[inline(always)]
    fn carry(self) -> Fe {
        let mut h = self.0;
        let mut c = 0;
        for limb in h.iter_mut() {
            let sum = *limb + c;
            *limb = sum & MASK;
            c = sum >> 56;
        }
        h[0] += c;
        h[4] += c;
        Fe(h)
    }

    #[inline(always)]
    pub(crate) fn add(self, other: Fe) -> Fe {
        let mut h = self.0;
        for (x, y) in h.iter_mut().zip(other.0) {
            *x += y;
        }
        Fe(h).carry()
    }

    /// `self - other`, with `4p` added first so that no limb goes below
    /// zero: each limb of `4p` is at least `4(2^56 - 2)`, above the 2^57
    /// bound on `other`.
    #[inline(always)]
    pub(crate) fn sub(self, other: Fe) -> Fe {
        let mut h = self.0;
        for ((x, y), prime) in h.iter_mut().zip(other.0).zip(P) {
            *x = *x + 4 * prime - y;
        }
        Fe(h).carry()
    }

    #[inline(always)]
    pub(crate) fn mul(self, other: Fe) -> Fe {
        let (a, b) = (self.0, other.0);
        let mut z = [0u128; 15];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                z[i + j] += u128::from(x) * u128::from(y);
            }
        }
        Fe::reduce(z)
    }

    /// The product with the symmetric terms counted once and doubled:
    /// thirty-six products instead of sixty-four.
    #[inline(always)]
    pub(crate) fn square(self) -> Fe {
        let a = self.0;
        let mut z = [0u128; 15];
        for i in 0..8 {
            for j in i + 1..8 {
                z[i + j] += u128::from(a[i]) * u128::from(a[j]);
            }
        }
        for (i, &x) in a.iter().enumerate() {
            z[2 * i] = 2 * z[2 * i] + u128::from(x) * u128::from(x);
        }
        for k in (1..15).step_by(2) {
            z[k] *= 2;
        }
        Fe::reduce(z)
    }

    /// `self * k` for a public constant `k` below 2^32.
    #[inline(always)]
    pub(crate) fn mul_small(self, k: u32) -> Fe {
        let mut z = [0u128; 15];
        for (column, &x) in z.iter_mut().zip(&self.0) {
            *column = u128::from(x) * u128::from(k);
        }
        Fe::reduce(z)
    }

    /// Fifteen columns to eight limbs. Columns 8..15 fold into `k - 8`
    /// and `k - 4`, from the top down so that 12..15, which fold into
    /// 8..11, are folded again on the way past.
    #[inline(always)]
    fn reduce(mut z: [u128; 15]) -> Fe {
        for k in (8..15).rev() {
            z[k - 4] += z[k];
            z[k - 8] += z[k];
        }
        let mask = u128::from(MASK);
        let mut r = [0u64; 8];
        let mut c = 0u128;
        for (limb, &column) in r.iter_mut().zip(&z[..8]) {
            let sum = column + c;
            *limb = (sum & mask) as u64;
            c = sum >> 56;
        }
        // c is below 2^64 by the bound in the module comment.
        let c = c as u64;
        r[0] += c;
        r[4] += c;
        r[1] += r[0] >> 56;
        r[0] &= MASK;
        r[5] += r[4] >> 56;
        r[4] &= MASK;
        Fe(r)
    }

    /// Swap `a` and `b` when `choice` is 1 and leave them when it is 0,
    /// with a mask.
    #[inline(always)]
    pub(crate) fn cswap(a: &mut Fe, b: &mut Fe, choice: u64) {
        let mask = 0u64.wrapping_sub(choice);
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }

    fn square_n(self, n: usize) -> Fe {
        let mut x = self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    /// `self^(p - 2)`: the inverse, or zero for zero. In binary
    /// `p - 2 = 2^448 - 2^224 - 3` is 223 ones, a zero, 222 ones, a zero
    /// and a one, and the chain builds exactly that. `ones(k)` is
    /// `self^(2^k - 1)`.
    pub(crate) fn invert(self) -> Fe {
        let ones = |shorter: Fe, by: usize, with: Fe| shorter.square_n(by).mul(with);
        let x1 = self;
        let x2 = ones(x1, 1, x1);
        let x3 = ones(x2, 1, x1);
        let x6 = ones(x3, 3, x3);
        let x12 = ones(x6, 6, x6);
        let x24 = ones(x12, 12, x12);
        let x30 = ones(x24, 6, x6);
        let x48 = ones(x24, 24, x24);
        let x96 = ones(x48, 48, x48);
        let x192 = ones(x96, 96, x96);
        let x222 = ones(x192, 30, x30);
        let x223 = ones(x222, 1, x1);
        // 223 ones, then a zero and 222 ones: shift by 223, add x222.
        let high = x223.square_n(223).mul(x222);
        // Then a zero and a one.
        high.square_n(2).mul(x1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::BigUint;

    fn p() -> BigUint {
        let one = BigUint::one();
        one.shl(448).sub(&one.shl(224)).unwrap().sub(&one).unwrap()
    }

    fn to_big(x: Fe) -> BigUint {
        let mut bytes = x.to_bytes();
        bytes.reverse();
        BigUint::from_bytes_be(&bytes)
    }

    fn from_big(x: &BigUint) -> Fe {
        let mut bytes = x.to_bytes_be_padded(56).unwrap();
        bytes.reverse();
        Fe::from_bytes(bytes.as_slice().try_into().unwrap())
    }

    fn random_bytes() -> [u8; 56] {
        let mut bytes = [0u8; 56];
        crate::random::fill(&mut bytes).unwrap();
        bytes
    }

    /// The ends of the range, the encodings at and above p, and the
    /// values on either side of the 2^224 gap in p.
    fn awkward() -> Vec<[u8; 56]> {
        let p = p();
        let one = BigUint::one();
        let mut values = vec![
            BigUint::zero(), one.clone(),
            p.sub(&one).unwrap(), p.clone(), p.add(&one),
            one.shl(448).sub(&one).unwrap(),
            one.shl(224), one.shl(224).sub(&one).unwrap(),
            one.shl(448).sub(&one.shl(224)).unwrap(),
        ];
        values.push(p.sub(&one.shl(224)).unwrap());
        values.iter().map(|v| {
            let mut bytes = v.to_bytes_be_padded(56).unwrap();
            bytes.reverse();
            bytes.try_into().unwrap()
        }).collect()
    }

    #[test]
    fn test_the_arithmetic_agrees_with_the_bignum() {
        let p = p();
        let mut inputs = awkward();
        inputs.extend((0..200).map(|_| random_bytes()));
        for (i, x) in inputs.iter().enumerate() {
            let y = &inputs[(i * 7 + 3) % inputs.len()];
            let (fx, fy) = (Fe::from_bytes(x), Fe::from_bytes(y));
            let (bx, by) = (to_big(fx), to_big(fy));
            let mut raw = *x;
            raw.reverse();
            assert_eq!(bx, BigUint::from_bytes_be(&raw).rem(&p).unwrap(),
                       "the encoding did not reduce");
            assert_eq!(to_big(fx.add(fy)), bx.mod_add(&by, &p).unwrap());
            assert_eq!(to_big(fx.sub(fy)), bx.mod_sub(&by, &p).unwrap());
            assert_eq!(to_big(fx.mul(fy)), bx.mod_mul(&by, &p).unwrap());
            assert_eq!(to_big(fx.square()), bx.mod_mul(&bx, &p).unwrap());
            assert_eq!(to_big(fx.mul_small(39081)),
                       bx.mod_mul(&BigUint::from_u64(39081), &p).unwrap());
            if !bx.is_zero() {
                assert_eq!(to_big(fx.invert().mul(fx)), BigUint::one());
            }
        }
        assert_eq!(to_big(Fe::ZERO.invert()), BigUint::zero());
    }

    /// Long chains with no canonical round trip in between, so the
    /// redundant limbs reach their bounds.
    #[test]
    fn test_long_chains_stay_in_bounds() {
        let p = p();
        let mut x = Fe::from_bytes(&[0xff; 56]);
        let mut big = to_big(x);
        let minus_one = p.sub(&BigUint::one()).unwrap();
        let fe_minus_one = from_big(&minus_one);
        for _ in 0..2000 {
            x = x.sub(fe_minus_one);
            x = x.add(x).square();
            big = big.mod_sub(&minus_one, &p).unwrap();
            big = big.mod_add(&big, &p).unwrap();
            big = big.mod_mul(&big, &p).unwrap();
        }
        assert_eq!(to_big(x), big);
    }

    fn value(x: Fe) -> BigUint {
        x.0.iter().rev().fold(BigUint::zero(), |acc, &limb| {
            acc.shl(56).add(&BigUint::from_u64(limb))
        })
    }

    /// The one input shape that needs the third carry in `to_bytes`: the
    /// first carry's fold makes limb 4 overflow through 5, 6 and 7 on
    /// the second, whose fold then overflows limb 0.
    #[test]
    fn test_to_bytes_takes_three_carries() {
        let p = p();
        let ones = MASK;
        let x = Fe([ones - 1, 12345, 0, ones, ones, ones, ones, 2 * ones + 1]);
        assert_eq!(to_big(x), value(x).rem(&p).unwrap());
    }

    /// `sub` at the documented bound: `other`'s limbs just under 2^57.
    /// A smaller multiple of p than 4 would go below zero here.
    #[test]
    fn test_sub_takes_the_documented_bound() {
        let p = p();
        let other = Fe([(1 << 57) - 1; 8]);
        let expected = BigUint::zero().mod_sub(&value(other).rem(&p).unwrap(), &p).unwrap();
        assert_eq!(to_big(Fe::ZERO.sub(other)), expected);
    }

    #[test]
    fn test_cswap_swaps_on_one_only() {
        let (a, b) = (Fe::from_bytes(&random_bytes()), Fe::from_bytes(&random_bytes()));
        let (mut x, mut y) = (a, b);
        Fe::cswap(&mut x, &mut y, 0);
        assert_eq!((x.to_bytes(), y.to_bytes()), (a.to_bytes(), b.to_bytes()));
        Fe::cswap(&mut x, &mut y, 1);
        assert_eq!((x.to_bytes(), y.to_bytes()), (b.to_bytes(), a.to_bytes()));
    }
}
