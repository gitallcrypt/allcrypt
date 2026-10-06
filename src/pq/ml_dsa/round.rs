/*
FIPS 204's rounding: `Power2Round`, `Decompose`, `HighBits`, `LowBits`,
`MakeHint` and `UseHint`, and the centred reduction they are built on.

These are where ML-DSA's signatures get small. A public key carries only
the high bits of `t`; a signature carries a *hint* - one bit per
coefficient, mostly zero - that lets the verifier recover the high bits
of `w` from a value that is close to `w` but not equal to it.

# Pitfalls

**Two different centred reductions.** `r mod± a` is the representative of
`r mod a` in `(-a/2, a/2]` when `a` is even. Both `Power2Round` (with
`a = 2^d`) and `Decompose` (with `a = 2*gamma2`) use it, and the upper end
is **inclusive**: `a/2` maps to `a/2`, not to `-a/2`. Getting that end
wrong changes one value in `a`, which the vectors hit eventually and a
round trip never does.

**`Decompose` has a special case at the top.** When `r+ - r0 = q - 1`,
the high part would be `(q-1)/(2*gamma2)`, one past the largest value
`w1Encode` can write. FIPS 204 sets `r1 = 0` and `r0 = r0 - 1` instead.
Omitting it gives a high part that wraps in `w1Encode` and a signature
that the standard's verifier rejects - for one value of `r` in about
`2*gamma2`, which is rare enough to survive a lot of testing. Pinned by
`test_decompose_wraps_the_top_value_to_zero`.

**`UseHint` moves the high part by one, and which way depends on the
sign of the low part**: up when `r0 > 0`, down when `r0 <= 0`, both mod
`m = (q-1)/(2*gamma2)`. Zero counts as "not positive".

**Signed values are carried as `i32` and converted at the boundary.** The
ring holds `[0, q)`; these functions take ring values and return signed
low parts, so a negative number never reaches a `Poly`. That is the
convention `ring.rs` states, kept on purpose.
*/

use super::ring::Q;

/// `d`: the number of bits `Power2Round` drops from `t`.
pub const D: u32 = 13;

/// FIPS 204's two values of `gamma2`, as a type rather than a number.
///
/// **Why not a `u32` parameter:** every function here divides or
/// reduces by `2*gamma2`, and those functions run on secrets while
/// signing. A division by a value only known at run time compiles to a
/// `div` instruction, whose latency depends on its operands - the
/// KyberSlash class of leak that `scripts/ct_check.py`'s division scan
/// exists for. With an enum, each value reaches the arithmetic as a
/// compile-time constant through a const generic, and the compiler turns
/// every division into a multiply. The match that picks one is on a
/// public parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gamma2 {
    /// `(q-1)/88 = 95232`, ML-DSA-44.
    QMinusOneOver88,
    /// `(q-1)/32 = 261888`, ML-DSA-65 and ML-DSA-87.
    QMinusOneOver32,
}

const TWO_GAMMA2_88: u32 = 2 * ((Q - 1) / 88);
const TWO_GAMMA2_32: u32 = 2 * ((Q - 1) / 32);

impl Gamma2 {
    pub fn value(self) -> u32 {
        match self {
            Gamma2::QMinusOneOver88 => TWO_GAMMA2_88 / 2,
            Gamma2::QMinusOneOver32 => TWO_GAMMA2_32 / 2,
        }
    }

    /// `m = (q-1)/(2*gamma2)`: how many values the high part takes. 44
    /// or 16, so `w1` is six or four bits.
    pub fn high_values(self) -> u32 {
        (Q - 1) / (2 * self.value())
    }
}

/// 1 if `a > b`, else 0, for `a` and `b` below `2^31` - by arithmetic,
/// not a comparison the compiler may turn into a branch.
///
/// **Everything below that runs while signing is written this way**,
/// because the values are secret: `w`, its low bits, `c*t0`. A branch on
/// one of them is a timing signal, and `scripts/ct_check.py`'s
/// `ml_dsa_sign` row is what checks that none is left outside the places
/// it names.
///
/// The result goes through `bignum::ct::opaque`, for the reason that
/// function gives: without it, the optimiser can recognise a mask built
/// from a comparison and turn the arithmetic back into a branch or a
/// conditional move. It did, here - `Decompose` came back from the first
/// valgrind run with a conditional move on the top-value test.
#[inline]
pub(crate) fn greater(a: u32, b: u32) -> u32 {
    crate::bignum::ct::opaque(((b.wrapping_sub(a) >> 31) & 1) as u64) as u32
}

/// All ones if `a == b`, else zero.
#[inline]
fn equal_mask(a: u32, b: u32) -> u32 {
    crate::bignum::ct::mask_is_zero((a ^ b) as u64) as u32
}

/// `|value|`, without a branch.
#[inline]
pub(crate) fn magnitude(value: i32) -> u32 {
    let sign = value >> 31;
    ((value ^ sign) - sign) as u32
}

/// `r mod± A` for an even constant `A`: the representative in
/// `(-A/2, A/2]`. The upper end is inclusive.
fn centred<const A: u32>(r: u32) -> i32 {
    let reduced = r % A;
    reduced as i32 - (greater(reduced, A / 2) * A) as i32
}

/// `mod±` by `2^d`, public for the tests and for `Power2Round`'s
/// callers that want only the low part.
pub fn centred_power2(r: u32) -> i32 {
    centred::<{ 1 << D }>(r)
}

/// FIPS 204 algorithm 35, `Power2Round`: `(r1, r0)` with
/// `r = r1 * 2^d + r0` and `r0` in `(-2^(d-1), 2^(d-1)]`.
pub fn power2round(r: u32) -> (u32, i32) {
    let r0 = centred_power2(r);
    let r1 = ((r as i64 - r0 as i64) >> D) as u32;
    (r1, r0)
}

/// FIPS 204 algorithm 36 with `2*gamma2` as a constant.
///
/// The top-value case is a mask rather than an `if`: `r - r0` is never
/// negative (`r0` is at most `r mod 2*gamma2`) and is below `2^24`, so it
/// fits a `u32` and the comparison with `q - 1` folds into one.
fn decompose_by<const TWO_GAMMA2: u32>(r: u32) -> (u32, i32) {
    let r0 = centred::<TWO_GAMMA2>(r);
    let difference = (r as i32 - r0) as u32;
    let top = equal_mask(difference, Q - 1);
    ((difference / TWO_GAMMA2) & !top, r0 - (top & 1) as i32)
}

/// FIPS 204 algorithm 36, `Decompose`: `(r1, r0)` with
/// `r = r1 * 2*gamma2 + r0 mod q`, except at the top - see the module
/// documentation.
pub fn decompose(r: u32, gamma2: Gamma2) -> (u32, i32) {
    match gamma2 {
        Gamma2::QMinusOneOver88 => decompose_by::<TWO_GAMMA2_88>(r),
        Gamma2::QMinusOneOver32 => decompose_by::<TWO_GAMMA2_32>(r),
    }
}

/// FIPS 204 algorithm 37.
pub fn high_bits(r: u32, gamma2: Gamma2) -> u32 {
    decompose(r, gamma2).0
}

/// FIPS 204 algorithm 38.
pub fn low_bits(r: u32, gamma2: Gamma2) -> i32 {
    decompose(r, gamma2).1
}

/// FIPS 204 algorithm 39, `MakeHint`: whether adding `z` to `r` changes
/// the high bits. Both are ring values in `[0, q)`.
pub fn make_hint(z: u32, r: u32, gamma2: Gamma2) -> bool {
    high_bits(r, gamma2) != high_bits((r + z) % Q, gamma2)
}

/// FIPS 204 algorithm 40, `UseHint`. Runs on public values only - the
/// verifier's - so the reduction by `m` is not a concern, but it is a
/// constant anyway.
pub fn use_hint(hint: bool, r: u32, gamma2: Gamma2) -> u32 {
    let (r1, r0) = decompose(r, gamma2);
    let m = gamma2.high_values();
    if hint && r0 > 0 {
        if r1 + 1 == m { 0 } else { r1 + 1 }
    } else if hint {
        if r1 == 0 { m - 1 } else { r1 - 1 }
    } else {
        r1
    }
}

/// A ring value as a signed integer in `(-q/2, q/2]` - `mod± q` - which
/// is what the infinity norm measures.
pub fn signed(r: u32) -> i32 {
    r as i32 - (greater(r, Q / 2) * Q) as i32
}

/// A signed value back into `[0, q)`.
pub fn unsigned(value: i32) -> u32 {
    (value + (Q as i32 & (value >> 31))) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAMMA2_44: Gamma2 = Gamma2::QMinusOneOver88;
    const GAMMA2_65: Gamma2 = Gamma2::QMinusOneOver32;

    #[test]
    fn test_the_two_gamma2_are_what_fips_204_tabulates() {
        assert_eq!(GAMMA2_44.value(), 95_232);
        assert_eq!(GAMMA2_65.value(), 261_888);
        assert_eq!(GAMMA2_44.high_values(), 44);
        assert_eq!(GAMMA2_65.high_values(), 16);
    }

    fn centred(r: u32, a: u32) -> i32 {
        match a {
            8 => super::centred::<8>(r),
            16 => super::centred::<16>(r),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_centred_includes_the_upper_end_and_excludes_the_lower() {
        assert_eq!(centred(4, 8), 4, "a/2 maps to a/2");
        assert_eq!(centred(5, 8), -3);
        assert_eq!(centred(0, 8), 0);
        assert_eq!(centred(12, 8), 4);
        for r in 0..64u32 {
            let c = centred(r, 16);
            assert!(c > -8 && c <= 8, "{r} -> {c}");
            assert_eq!((r as i32 - c).rem_euclid(16), 0);
        }
    }

    /// `Power2Round` reconstructs `r` exactly, and `r0` is in range.
    #[test]
    fn test_power2round_reconstructs() {
        for r in (0..Q).step_by(997).chain([0, 1, 4096, 4097, Q - 1]) {
            let (r1, r0) = power2round(r);
            assert_eq!((r1 as i64) * (1 << D) + r0 as i64, r as i64, "{r}");
            assert!(r0 > -(1 << (D - 1)) && r0 <= 1 << (D - 1), "{r} -> {r0}");
            assert!(r1 < 1 << 10, "t1 fits ten bits");
        }
    }

    /// `Decompose` reconstructs `r` mod q, `r1` is below `m`, and `r0` is
    /// in `(-gamma2, gamma2]` - except the top case, where it is one lower.
    #[test]
    fn test_decompose_reconstructs_at_both_gamma2() {
        for which in [GAMMA2_44, GAMMA2_65] {
            let (gamma2, m) = (which.value(), which.high_values());
            for r in (0..Q).step_by(1009).chain([0, 1, gamma2, gamma2 + 1,
                                                 Q - gamma2, Q - 1]) {
                let (r1, r0) = decompose(r, which);
                assert!(r1 < m, "{r}: r1 = {r1}");
                assert_eq!(unsigned(((r1 * 2 * gamma2) as i64 + r0 as i64)
                                        .rem_euclid(Q as i64) as i32),
                           r, "{r}");
                assert!(r0 >= -(gamma2 as i32) && r0 <= gamma2 as i32,
                        "{r}: r0 = {r0}");
            }
        }
    }

    /// The special case: values within `gamma2` of `q - 1` from below
    /// would have high part `m`, and are wrapped to 0 with `r0` lowered.
    #[test]
    fn test_decompose_wraps_the_top_value_to_zero() {
        for which in [GAMMA2_44, GAMMA2_65] {
            let gamma2 = which.value();
            let r = Q - 1;
            let (r1, r0) = decompose(r, which);
            assert_eq!(r1, 0, "the top value's high part wraps to 0");
            assert_eq!(r0, -1, "and its low part is r - q = -1");
            // Just below the band, the ordinary case applies.
            let below = Q - 1 - gamma2 - 1;
            assert_ne!(decompose(below, which).0, 0);
        }
    }

    /// The property the hint exists for: with `h = MakeHint(z, r)`,
    /// `UseHint(h, r) = HighBits(r + z)` whenever `|z| <= gamma2`.
    #[test]
    fn test_use_hint_recovers_what_make_hint_hid() {
        for which in [GAMMA2_44, GAMMA2_65] {
            let gamma2 = which.value();
            let mut state = 0x1234_5678u64;
            for _ in 0..20_000 {
                state = state.wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let r = ((state >> 33) % Q as u64) as u32;
                let z_signed = ((state >> 13) % (2 * gamma2 as u64 + 1)) as i32
                    - gamma2 as i32;
                let z = unsigned(z_signed);
                let hint = make_hint(z, r, which);
                assert_eq!(use_hint(hint, r, which),
                           high_bits((r + z) % Q, which),
                           "r {r}, z {z_signed}");
            }
        }
    }

    /// `UseHint` treats a low part of exactly zero as "not positive" and
    /// moves the high part down. The case is reached when `r0 = 0` and the
    /// hint says adding `-gamma2` crossed a boundary - which a random
    /// sample essentially never produces, so it is built here.
    #[test]
    fn test_use_hint_treats_zero_as_not_positive() {
        for which in [GAMMA2_44, GAMMA2_65] {
            let gamma2 = which.value();
            let r = 5 * 2 * gamma2;                 // r1 = 5, r0 = 0
            assert_eq!(decompose(r, which), (5, 0));
            let z = unsigned(-(gamma2 as i32));
            assert!(make_hint(z, r, which), "adding -gamma2 to r0 = 0 \
                                             crosses into the block below");
            assert_eq!(high_bits((r + z) % Q, which), 4);
            assert_eq!(use_hint(true, r, which), 4, "down, not up");
            // And the wrap at the bottom: r1 = 0 moves to m - 1.
            assert_eq!(use_hint(true, 0, which), which.high_values() - 1);
        }
    }

    /// The arithmetic comparisons agree with the ordinary ones over the
    /// whole range they are used on, including both ends.
    #[test]
    fn test_the_branchless_helpers_agree_with_comparisons() {
        let samples = (0..Q).step_by(4099).chain([0, 1, Q / 2 - 1, Q / 2,
                                                  Q / 2 + 1, Q - 2, Q - 1]);
        for a in samples {
            for b in [0, 1, Q / 2, Q - 1, a, a.saturating_sub(1), a + 1] {
                assert_eq!(greater(a, b) == 1, a > b, "{a} > {b}");
                assert_eq!(equal_mask(a, b) == u32::MAX, a == b, "{a} == {b}");
                assert!(equal_mask(a, b) == 0 || equal_mask(a, b) == u32::MAX);
            }
            let s = signed(a);
            assert_eq!(magnitude(s), s.unsigned_abs());
        }
        assert_eq!(magnitude(i32::MIN + 1), (i32::MAX) as u32);
    }

    #[test]
    fn test_signed_is_centred_on_zero() {
        assert_eq!(signed(0), 0);
        assert_eq!(signed(Q - 1), -1);
        assert_eq!(signed(Q / 2), (Q / 2) as i32);
        assert_eq!(signed(Q / 2 + 1), -((Q / 2) as i32));
        assert_eq!(unsigned(-1), Q - 1);
        assert_eq!(unsigned(signed(12345)), 12345);
    }
}
