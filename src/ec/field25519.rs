/*!
Arithmetic modulo `p = 2^255 - 19` in five 51-bit limbs.

An element is `l0 + l1*2^51 + l2*2^102 + l3*2^153 + l4*2^204` with every
limb a `u64`. The representation is redundant: limbs may run a little
past 51 bits between operations, and a value may sit anywhere below
`2^256` rather than below `p`. Only `to_bytes` produces the canonical
form.

Nothing here branches on, or indexes memory by, the value of an element.
Every function runs the same instructions whatever its inputs, which is
the property `BigUint` cannot give - its length is a measurement of the
value. The ladder in `x25519.rs` is built on this for that reason.

**Why five limbs of 51 bits.** `2^255 = 19 (mod p)`, so the part of a
product that lands above limb 4 folds back into the low limbs multiplied
by 19. With 51-bit limbs a product of two limbs is under 2^102, five of
them plus the factor of 19 stay under 2^109, and the whole column sum
fits a `u128` with room to spare. 64-bit limbs would need the 19 folded
in after a carry, which is slower and harder to bound.

**Limb bounds.** Every function that returns an element has passed it
through a carry, so its limbs are below `2^51 + 2^18`. Every function
that takes one assumes no more than that, and the bounds that follow from
it are stated where they are used. `sub` relies on it most directly: it
adds `16p` before subtracting so no limb can go below zero.
*/

const MASK: u64 = (1 << 51) - 1;

/// An element of GF(2^255 - 19). See the module comment for the form.
#[derive(Clone, Copy)]
pub(crate) struct Fe([u64; 5]);

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// From 32 little-endian bytes, ignoring the top bit. A value at or
    /// above `p` is accepted and behaves as itself reduced.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        // Limb i starts at bit 51i: byte 51i/8, shifted by 51i mod 8.
        Fe([
            load(0) & MASK,
            (load(6) >> 3) & MASK,
            (load(12) >> 6) & MASK,
            (load(19) >> 1) & MASK,
            (load(24) >> 12) & MASK,
        ])
    }

    /// The canonical little-endian encoding, below `p`.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        // One carry leaves limbs 1..4 below 2^51 and limb 0 below
        // 2^51 + 19 * 2^13, so the value is below 2p and one conditional
        // subtraction of p is enough. The q chain below computes the
        // carries of h + 19 exactly, whatever limb 0's excess.
        let mut h = self.carry().0;
        // q = 1 exactly when h >= p, i.e. when h + 19 reaches 2^255.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        // h - q*p = h + 19q - q*2^255: add 19q, carry, drop bit 255.
        h[0] += 19 * q;
        h[1] += h[0] >> 51;
        h[0] &= MASK;
        h[2] += h[1] >> 51;
        h[1] &= MASK;
        h[3] += h[2] >> 51;
        h[2] &= MASK;
        h[4] += h[3] >> 51;
        h[3] &= MASK;
        h[4] &= MASK;

        let words = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Every limb back below 2^51, the carry out of limb 4 folded into
    /// limb 0 times 19. Limb 0 can end up to `19 * (carry)` over, which
    /// for inputs below 2^64 is under 2^51 + 2^18.
    #[inline(always)]
    fn carry(self) -> Fe {
        let mut h = self.0;
        let c = h[0] >> 51;
        h[0] &= MASK;
        h[1] += c;
        let c = h[1] >> 51;
        h[1] &= MASK;
        h[2] += c;
        let c = h[2] >> 51;
        h[2] &= MASK;
        h[3] += c;
        let c = h[3] >> 51;
        h[3] &= MASK;
        h[4] += c;
        let c = h[4] >> 51;
        h[4] &= MASK;
        h[0] += 19 * c;
        Fe(h)
    }

    #[inline(always)]
    pub(crate) fn add(self, other: Fe) -> Fe {
        let (a, b) = (self.0, other.0);
        Fe([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]]).carry()
    }

    /// `self - other`. `16p` is added first, limb by limb, so that no
    /// limb goes negative: each limb of `16p` is at least `16(2^51 - 19)`,
    /// above any limb `other` can have.
    #[inline(always)]
    pub(crate) fn sub(self, other: Fe) -> Fe {
        const LOW: u64 = 16 * 0x7_FFFF_FFFF_FFED;
        const HIGH: u64 = 16 * 0x7_FFFF_FFFF_FFFF;
        let (a, b) = (self.0, other.0);
        Fe([
            a[0] + LOW - b[0],
            a[1] + HIGH - b[1],
            a[2] + HIGH - b[2],
            a[3] + HIGH - b[3],
            a[4] + HIGH - b[4],
        ])
        .carry()
    }

    /// Schoolbook product, the high columns folded by 19 as they are
    /// formed. Each term is below `19 * 2^102.1`, so a column of five is
    /// below 2^109.
    #[inline(always)]
    pub(crate) fn mul(self, other: Fe) -> Fe {
        let (a, b) = (self.0, other.0);
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let (b1, b2, b3, b4) = (19 * b[1], 19 * b[2], 19 * b[3], 19 * b[4]);
        Fe::reduce([
            m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1),
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2),
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3),
            m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4),
            m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
        ])
    }

    /// `mul(self, self)` with the symmetric terms counted once and
    /// doubled: fifteen products instead of twenty-five.
    #[inline(always)]
    pub(crate) fn square(self) -> Fe {
        let a = self.0;
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let (a3_19, a4_19) = (19 * a[3], 19 * a[4]);
        Fe::reduce([
            m(a[0], a[0]) + 2 * (m(a[1], a4_19) + m(a[2], a3_19)),
            m(a[3], a3_19) + 2 * (m(a[0], a[1]) + m(a[2], a4_19)),
            m(a[1], a[1]) + 2 * (m(a[0], a[2]) + m(a[4], a3_19)),
            m(a[4], a4_19) + 2 * (m(a[0], a[3]) + m(a[1], a[2])),
            m(a[2], a[2]) + 2 * (m(a[0], a[4]) + m(a[1], a[3])),
        ])
    }

    /// `self * k` for a public constant `k` below 2^32.
    #[inline(always)]
    pub(crate) fn mul_small(self, k: u32) -> Fe {
        let m = |x: u64| u128::from(x) * u128::from(k);
        let a = self.0;
        Fe::reduce([m(a[0]), m(a[1]), m(a[2]), m(a[3]), m(a[4])])
    }

    /// Column sums to limbs. The columns are below 2^110, so the carry
    /// out of the top one is below 2^59 and `19` times it fits a `u64`.
    #[inline(always)]
    fn reduce(t: [u128; 5]) -> Fe {
        let mask = u128::from(MASK);
        let mut r = [0u64; 5];
        let mut c = 0u128;
        for (limb, column) in r.iter_mut().zip(t) {
            let sum = column + c;
            *limb = (sum & mask) as u64;
            c = sum >> 51;
        }
        r[0] += 19 * c as u64;
        r[1] += r[0] >> 51;
        r[0] &= MASK;
        Fe(r)
    }

    /// Swap `a` and `b` when `choice` is 1 and leave them when it is 0,
    /// with a mask: the same loads, stores and XORs either way.
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

    /// `self^(p - 2)`, which is the inverse for non-zero `self` and zero
    /// for zero. The exponent is public, so this is a fixed chain: 254
    /// squarings and 11 multiplications. The names say which power of
    /// `self` each one holds, `z2_k_0` being `self^(2^k - 1)`.
    pub(crate) fn invert(self) -> Fe {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(z2);
        let z2_5_0 = z11.square().mul(z9);
        let z2_10_0 = z2_5_0.square_n(5).mul(z2_5_0);
        let z2_20_0 = z2_10_0.square_n(10).mul(z2_10_0);
        let z2_40_0 = z2_20_0.square_n(20).mul(z2_20_0);
        let z2_50_0 = z2_40_0.square_n(10).mul(z2_10_0);
        let z2_100_0 = z2_50_0.square_n(50).mul(z2_50_0);
        let z2_200_0 = z2_100_0.square_n(100).mul(z2_100_0);
        let z2_250_0 = z2_200_0.square_n(50).mul(z2_50_0);
        // 2^255 - 21 = (2^250 - 1) * 2^5 + 11.
        z2_250_0.square_n(5).mul(z11)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::BigUint;

    fn p() -> BigUint {
        BigUint::one().shl(255).sub(&BigUint::from_u64(19)).unwrap()
    }

    fn to_big(x: Fe) -> BigUint {
        let mut bytes = x.to_bytes();
        bytes.reverse();
        BigUint::from_bytes_be(&bytes)
    }

    fn from_big(x: &BigUint) -> Fe {
        let mut bytes = x.to_bytes_be_padded(32).unwrap();
        bytes.reverse();
        Fe::from_bytes(bytes.as_slice().try_into().unwrap())
    }

    fn random_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        crate::random::fill(&mut bytes).unwrap();
        bytes
    }

    /// Values a random draw will not produce: the ends of the range, and
    /// the encodings at and above p that must reduce.
    fn awkward() -> Vec<[u8; 32]> {
        let mut out = vec![[0u8; 32], [0xff; 32]];
        let mut one = [0u8; 32];
        one[0] = 1;
        out.push(one);
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        out.push(p);
        let mut p_minus_one = p;
        p_minus_one[0] = 0xec;
        out.push(p_minus_one);
        let mut p_plus_one = p;
        p_plus_one[0] = 0xee;
        out.push(p_plus_one);
        out
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
            assert!(bx < p && by < p, "to_bytes left a value at or above p");
            assert_eq!(to_big(fx.add(fy)), bx.mod_add(&by, &p).unwrap());
            assert_eq!(to_big(fx.sub(fy)), bx.mod_sub(&by, &p).unwrap());
            assert_eq!(to_big(fx.mul(fy)), bx.mod_mul(&by, &p).unwrap());
            assert_eq!(to_big(fx.square()), bx.mod_mul(&bx, &p).unwrap());
            assert_eq!(to_big(fx.mul_small(121665)),
                       bx.mod_mul(&BigUint::from_u64(121665), &p).unwrap());
            if !bx.is_zero() {
                assert_eq!(to_big(fx.invert().mul(fx)), BigUint::one());
            }
        }
        assert_eq!(to_big(Fe::ZERO.invert()), BigUint::zero());
    }

    /// Long chains without a canonical round trip in between, so the
    /// redundant limbs are exercised at their bounds rather than reset
    /// after every step.
    #[test]
    fn test_long_chains_stay_in_bounds() {
        let p = p();
        let mut x = Fe::from_bytes(&[0xff; 32]);
        let mut big = to_big(x);
        let minus_one = from_big(&p.sub(&BigUint::one()).unwrap());
        for _ in 0..2000 {
            x = x.sub(minus_one);
            x = x.add(x).square();
            big = big.mod_sub(&p.sub(&BigUint::one()).unwrap(), &p).unwrap();
            big = big.mod_add(&big, &p).unwrap();
            big = big.mod_mul(&big, &p).unwrap();
        }
        assert_eq!(to_big(x), big);
    }

    /// `sub` at the documented bound: `other`'s limbs as large as the
    /// module comment allows, against a zero `self`.
    #[test]
    fn test_sub_takes_the_documented_bound() {
        let p = p();
        let top = (1u64 << 51) + (1 << 18) - 1;
        let other = Fe([top; 5]);
        let value = |x: Fe| x.0.iter().rev().fold(BigUint::zero(), |acc, &limb| {
            acc.shl(51).add(&BigUint::from_u64(limb))
        });
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
