/*
The ring `Z_q[X]/(X^256 + 1)` with `q = 3329`, and the NTT over it.

Everything in ML-KEM (FIPS 203) is arithmetic in this one ring. A
polynomial is 256 coefficients of twelve bits; a key or a ciphertext is a
vector or a matrix of them. There is no arbitrary precision integer
anywhere, and `bignum` would be actively wrong here: it is variable width
and normalised, and these coefficients are fixed width by construction.

`q = 3329` is prime and `q - 1 = 2^8 * 13`, so the multiplicative group has
an element of order 256. That is the whole reason the NTT works: it turns
a multiplication in the ring, which is a 256-term convolution, into 128
independent multiplications of pairs.

ML-DSA's ring is **not** this one - `q = 8380417`, 23 bit coefficients, a
different root of unity and different reduction constants. When it arrives
it gets its own module rather than a parameter here.

# Pitfalls

**The twiddle table is its own inverse.** `intt(ntt(f)) == f` holds for
*any* consistent pair of tables, including a wrong one, so it is close to
worthless as a test. What catches a wrong table is
`intt(ntt(f) * ntt(g)) == f * g`, with the right-hand multiply written
separately as a schoolbook convolution - the same shape as
`scripts/diff_check.py`'s Kuznyechik, where the fast path is checked
against the slow one. That is
[`tests::test_the_ntt_multiplies_the_same_way_the_schoolbook_does`], and
it is the load-bearing test in this file.

**The table is computed here, not typed.** FIPS 203 prints all 128
values; typing them would be 128 chances to be wrong in a way that is
self-consistent, and the rule in `docs/extending.md` about never typing
a vector applies to constants for the same reason. They are
`17^BitRev7(i) mod q`, built by a `const fn` at compile time, and three
separate tests check the *properties* that make 17 the right generator
rather than checking the numbers against a copy of themselves.

**`BitRev7` is a seven bit reversal, not a general one.** Reversing eight
bits, or reversing within a `usize`, gives a permutation of the table that
is also a valid-looking table. It is used in two different places - the
NTT's twiddles and the base-case multiply's `gamma` - and a mismatch
between those two is invisible to a round trip.

**The base-case multiply is where `X^256 + 1` shows up.** After the NTT
the ring is 128 copies of `Z_q[X]/(X^2 - gamma_i)`, so multiplying two
transformed polynomials is 128 multiplications of linear polynomials, each
reducing `X^2` to its own `gamma_i`. Using one `gamma` for all of them, or
the wrong one for some, gives a product that is a polynomial in the right
ring and not the right polynomial.

**The coefficients are kept in `[0, q)` and nothing here is centred.**
FIPS 203's `Compress`/`Decompress` are defined on that representation, and
a centred representative (`[-q/2, q/2]`) is a different convention that
some implementations use internally. Mixing the two is silent: every
operation still works, and the compressed output differs.

**Reduction is `% Q` on a compile-time constant, which is constant
time.** LLVM turns it into a multiply and a shift - there is no division
instruction and no data-dependent branch. That is worth stating because
the obvious worry here is a modulus reduction leaking a secret
coefficient, and the obvious *fix* - a hand-written Barrett or Montgomery
reduction - would be new code to get wrong for no gain. If profiling ever
asks for Montgomery form, it arrives with its own tests. What must not
happen is `%` by a modulus that is not a constant.
*/

/// The modulus. Prime, and `q - 1 = 2^8 * 13`, which is what gives an
/// element of order 256.
pub const Q: u16 = 3329;

/// Coefficients per polynomial. Fixed by FIPS 203 at every parameter set;
/// only `k`, the number of polynomials in a vector, varies.
pub const N: usize = 256;

/// The 256th root of unity FIPS 203 uses.
const ZETA: u16 = 17;

/// `base^exp mod Q`, at compile time.
///
/// Square and multiply, written without iterators because a `const fn`
/// cannot use them. Every intermediate is under `Q^2 = 11,082,241`, which
/// fits a `u32` with room to spare.
const fn pow_mod(base: u16, exp: u32) -> u16 {
    let mut result: u32 = 1;
    let mut square = base as u32 % Q as u32;
    let mut remaining = exp;
    while remaining > 0 {
        if remaining & 1 == 1 {
            result = result * square % Q as u32;
        }
        square = square * square % Q as u32;
        remaining >>= 1;
    }
    result as u16
}

/// `BitRev7`: reverse the low **seven** bits.
///
/// Seven because the table has 128 entries. An eight bit reversal gives a
/// different permutation of the same numbers, which is a table that looks
/// entirely plausible.
const fn bit_rev7(mut value: usize) -> usize {
    let mut out = 0usize;
    let mut bit = 0;
    while bit < 7 {
        out = (out << 1) | (value & 1);
        value >>= 1;
        bit += 1;
    }
    out
}

/// `zeta^BitRev7(i) mod q`, for `i` in `0..128`.
///
/// Index 0 is 1 and is never used: FIPS 203's NTT starts at `i = 1`. Kept
/// so the indices match the standard's, because an off-by-one in a
/// twiddle table is exactly the mistake this file is most exposed to.
pub const ZETAS: [u16; 128] = {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = pow_mod(ZETA, bit_rev7(i) as u32);
        i += 1;
    }
    table
};

/// `zeta^(2 * BitRev7(i) + 1) mod q`, the base-case multiply's modulus for
/// each of the 128 quadratic factors.
///
/// A second table rather than an expression at the call site, because it
/// is a *different* exponent from [`ZETAS`] and deriving one from the
/// other at the call site is where the two get confused.
pub const GAMMAS: [u16; 128] = {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = pow_mod(ZETA, 2 * bit_rev7(i) as u32 + 1);
        i += 1;
    }
    table
};

/// `128^-1 mod q`, the factor the inverse NTT finishes with.
///
/// Computed rather than written as 3303, for the same reason as the
/// tables. `test_the_inverse_of_128_is_what_the_standard_says` checks it
/// against the standard's published value, which is the one number here
/// small enough to be worth stating twice.
pub const INVERSE_128: u16 = pow_mod(128, Q as u32 - 2);

/// A polynomial: `N` coefficients in `[0, q)`.
///
/// Not `Copy`: it is 512 bytes, and an accidental copy of one in a loop is
/// the kind of thing this library avoids. `Clone` is explicit where a copy
/// is wanted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Poly {
    /// Always reduced into `[0, q)`. Every function here maintains that,
    /// and `is_reduced` is what the tests check it with.
    pub coefficients: [u16; N],
}

impl Default for Poly {
    fn default() -> Poly { Poly::zero() }
}

impl Poly {
    pub fn zero() -> Poly { Poly { coefficients: [0u16; N] } }

    /// A polynomial from coefficients that are already reduced.
    ///
    /// Refuses anything at or above `q` rather than reducing it: a caller
    /// with an out-of-range coefficient has either read a malformed
    /// encoding or made an arithmetic mistake, and quietly reducing hides
    /// both. FIPS 203's `ByteDecode_12` has exactly this check for the
    /// first of those reasons.
    pub fn from_coefficients(coefficients: [u16; N]) -> Result<Poly, String> {
        for (at, value) in coefficients.iter().enumerate() {
            if *value >= Q {
                return Err(format!(
                    "Coefficient {} is {}, which is not below q = {}.",
                    at, value, Q));
            }
        }
        Ok(Poly { coefficients })
    }

    /// Whether every coefficient is in `[0, q)`.
    pub fn is_reduced(&self) -> bool {
        self.coefficients.iter().all(|value| *value < Q)
    }

    /// Coefficient-wise addition mod `q`.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for at in 0..N {
            // Both inputs are below q, so the sum is below 2q and one
            // conditional subtraction is enough - but `% Q` says so
            // without the reader having to check the bound.
            out.coefficients[at] =
                ((self.coefficients[at] as u32 + other.coefficients[at] as u32)
                 % Q as u32) as u16;
        }
        out
    }

    /// Coefficient-wise subtraction mod `q`.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] = ((self.coefficients[at] as u32
                                     + Q as u32
                                     - other.coefficients[at] as u32)
                                    % Q as u32) as u16;
        }
        out
    }

    /// Multiply every coefficient by a scalar mod `q`.
    pub fn scale(&self, factor: u16) -> Poly {
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] = mul(self.coefficients[at], factor);
        }
        out
    }

    /// FIPS 203 algorithm 9, `NTT`: into the transformed domain, in place.
    ///
    /// Seven layers of butterflies, halving the block length each time and
    /// consuming one twiddle per block. The twiddle index runs forward
    /// from 1 through 127 across the whole transform - it is **not** reset
    /// per layer, which is the easiest thing to get wrong here and gives a
    /// transform that inverts correctly and multiplies wrongly.
    pub fn ntt(&mut self) {
        let mut twiddle = 1usize;
        let mut length = 128usize;
        while length >= 2 {
            let mut start = 0usize;
            while start < N {
                let zeta = ZETAS[twiddle];
                twiddle += 1;
                for at in start..start + length {
                    let t = mul(zeta, self.coefficients[at + length]);
                    self.coefficients[at + length] =
                        sub_mod(self.coefficients[at], t);
                    self.coefficients[at] = add_mod(self.coefficients[at], t);
                }
                start += 2 * length;
            }
            length /= 2;
        }
    }

    /// FIPS 203 algorithm 10, `NTT^-1`: back out of the transformed
    /// domain, in place.
    ///
    /// The mirror image - lengths growing, twiddles consumed backwards
    /// from 127 - and then every coefficient scaled by `128^-1`. Leaving
    /// the scaling out gives a result 128 times too large, which is
    /// *invisible* in a round trip through a linear function and shows up
    /// only once a multiplication is involved.
    pub fn inverse_ntt(&mut self) {
        let mut twiddle = 127usize;
        let mut length = 2usize;
        while length <= 128 {
            let mut start = 0usize;
            while start < N {
                let zeta = ZETAS[twiddle];
                twiddle -= 1;
                for at in start..start + length {
                    let t = self.coefficients[at];
                    self.coefficients[at] =
                        add_mod(t, self.coefficients[at + length]);
                    self.coefficients[at + length] =
                        mul(zeta, sub_mod(self.coefficients[at + length], t));
                }
                start += 2 * length;
            }
            length *= 2;
        }
        for at in 0..N {
            self.coefficients[at] = mul(self.coefficients[at], INVERSE_128);
        }
    }

    /// FIPS 203 algorithm 11, `MultiplyNTTs`: multiply in the transformed
    /// domain.
    ///
    /// 128 independent products of linear polynomials, each in
    /// `Z_q[X]/(X^2 - gamma_i)`. This is the only place `X^256 + 1`
    /// appears explicitly: the `gamma_i` are the 128 roots of
    /// `Y^128 + 1`, which is what the quadratic factors of `X^256 + 1`
    /// reduce `X^2` to. (Each `gamma_i` is *not* the square root of a
    /// twiddle - a claim an earlier test made and the arithmetic refuted.)
    pub fn multiply_ntt(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for (i, gamma) in GAMMAS.iter().enumerate() {
            let (a0, a1) = (self.coefficients[2 * i], self.coefficients[2 * i + 1]);
            let (b0, b1) = (other.coefficients[2 * i], other.coefficients[2 * i + 1]);
            let gamma = *gamma;
            // c0 = a0*b0 + a1*b1*gamma, c1 = a0*b1 + a1*b0.
            out.coefficients[2 * i] =
                add_mod(mul(a0, b0), mul(mul(a1, b1), gamma));
            out.coefficients[2 * i + 1] =
                add_mod(mul(a0, b1), mul(a1, b0));
        }
        out
    }

    /// `Compress_d` applied to every coefficient.
    ///
    /// The result's coefficients are below `2^d`, not below `q` - so the
    /// polynomial it returns is **not reduced** in the sense
    /// [`Poly::is_reduced`] means, and must go to `ByteEncode_d` rather
    /// than into any arithmetic. Keeping it a `Poly` rather than a new type
    /// is a convenience with that one cost, and the encoder's own width
    /// check is what catches a compressed polynomial passed at the wrong
    /// `d`.
    pub fn compress(&self, bits: u32) -> Result<Poly, String> {
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] = compress(self.coefficients[at], bits)?;
        }
        Ok(out)
    }

    /// `Decompress_d` applied to every coefficient: back into `[0, q)`.
    pub fn decompress(&self, bits: u32) -> Result<Poly, String> {
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] = decompress(self.coefficients[at], bits)?;
        }
        Ok(out)
    }

    /// [`Poly::compress`] without the per-coefficient range check, for a
    /// polynomial that is reduced by construction.
    ///
    /// ML-KEM's own algorithms use this one, because the range check is a
    /// branch on each coefficient and on their paths the coefficients are
    /// secret. `d` is still checked - it is public. The range is asserted
    /// in debug builds, so a caller that broke the precondition fails the
    /// tests rather than compressing garbage.
    pub(crate) fn compress_unchecked(&self, bits: u32) -> Result<Poly, String> {
        check_width("Compress", bits)?;
        debug_assert!(self.is_reduced(), "Compress: not reduced");
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] = compress_value(self.coefficients[at], bits);
        }
        Ok(out)
    }

    /// [`Poly::decompress`] without the per-coefficient range check, for
    /// a polynomial whose coefficients fit `d` bits by construction - one
    /// that came out of `ByteDecode_d`.
    pub(crate) fn decompress_unchecked(&self, bits: u32)
            -> Result<Poly, String> {
        check_width("Decompress", bits)?;
        debug_assert!(self.coefficients.iter()
                          .all(|v| (*v as u32) < (1u32 << bits)),
                      "Decompress: a coefficient does not fit {bits} bits");
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] =
                decompress_value(self.coefficients[at], bits);
        }
        Ok(out)
    }

    /// Multiply in the ring directly, by the 256-term negacyclic
    /// convolution.
    ///
    /// **Not used by ML-KEM**, which multiplies in the transformed domain
    /// throughout. It is here to check that the transform does what it
    /// claims: the fast path and the slow path are different algorithms,
    /// so agreeing over random inputs is evidence rather than a
    /// tautology. Kept in the library rather than in the test module so
    /// that it is compiled and read like everything else, and so a future
    /// reader can use it to check a change to the NTT.
    ///
    /// `X^256 = -1` is the whole content: a product term landing at or
    /// past degree 256 wraps round and **changes sign**. Wrapping without
    /// the sign change is the cyclic convolution, a different ring, and a
    /// perfectly consistent wrong answer.
    pub fn multiply_schoolbook(&self, other: &Poly) -> Poly {
        let mut wide = [0u32; 2 * N];
        for i in 0..N {
            for j in 0..N {
                wide[i + j] = (wide[i + j]
                               + self.coefficients[i] as u32
                                 * other.coefficients[j] as u32)
                              % Q as u32;
            }
        }
        let mut out = Poly::zero();
        for at in 0..N {
            // The upper half folds down with a minus sign.
            out.coefficients[at] =
                ((wide[at] + Q as u32 - wide[at + N] % Q as u32) % Q as u32) as u16;
        }
        out
    }
}

/// `a * b mod q`.
///
/// The product is under `q^2`, which fits a `u32`. `% Q` with `Q` a
/// constant compiles to a multiply and a shift, so there is no division
/// and no data-dependent branch - see the note at the top of this file
/// about why that matters and why a hand-rolled Barrett reduction is not
/// an improvement.
#[inline]
pub fn mul(a: u16, b: u16) -> u16 {
    (a as u32 * b as u32 % Q as u32) as u16
}

/// `a + b mod q`, for values already in `[0, q)`.
#[inline]
pub fn add_mod(a: u16, b: u16) -> u16 {
    let sum = a + b;
    if sum >= Q { sum - Q } else { sum }
}

/// `a - b mod q`, for values already in `[0, q)`.
#[inline]
pub fn sub_mod(a: u16, b: u16) -> u16 {
    if a >= b { a - b } else { a + Q - b }
}

/// FIPS 203 `Compress_d`: round a coefficient to `d` bits.
///
/// `round(2^d / q * x) mod 2^d`, and the rounding is the whole
/// difficulty: it is round-half-up, which integer division truncates. So
/// the numerator carries `+ q/2` before dividing - written here as
/// `2 * 2^d * x + q` over `2 * q`, which is the same thing without a
/// division by two that would itself truncate.
///
/// Lossy on purpose. This is what makes an ML-KEM ciphertext smaller than
/// the polynomial it encodes, and what the scheme's decryption failure
/// probability is computed from.
pub fn compress(value: u16, bits: u32) -> Result<u16, String> {
    check_width("Compress", bits)?;
    if value >= Q {
        return Err(format!(
            "Compress: {value} is not below q = {Q}."));
    }
    Ok(compress_value(value, bits))
}

/// `d` is public, so this branch is free.
fn check_width(what: &str, bits: u32) -> Result<(), String> {
    if bits == 0 || bits > 12 {
        return Err(format!("{what} takes 1 to 12 bits, not {bits}."));
    }
    Ok(())
}

/// The arithmetic of `Compress_d`, with no checks and no branches.
///
/// **The division is by a constant**, `2q`, which compiles to a multiply
/// and a shift. That matters: this runs on secret coefficients, and a
/// `div` instruction's latency depends on its operands on many
/// processors. The KyberSlash leak was a division by `q` in exactly this
/// function, in implementations whose compiler emitted one.
fn compress_value(value: u16, bits: u32) -> u16 {
    let numerator = 2 * (1u32 << bits) * value as u32 + Q as u32;
    let rounded = numerator / (2 * Q as u32);
    (rounded & ((1u32 << bits) - 1)) as u16
}

/// FIPS 203 `Decompress_d`: back from `d` bits to a coefficient.
///
/// `round(q / 2^d * y)`, rounded the same way. Not the inverse of
/// [`compress`] and not meant to be - it lands within `q / 2^(d+1)` of
/// the original, which is what
/// `test_compression_loses_no_more_than_the_standard_allows` checks.
pub fn decompress(value: u16, bits: u32) -> Result<u16, String> {
    check_width("Decompress", bits)?;
    if value as u32 >= (1u32 << bits) {
        return Err(format!(
            "Decompress: {value} does not fit {bits} bits."));
    }
    Ok(decompress_value(value, bits))
}

/// The arithmetic of `Decompress_d`. Dividing by `2^(d+1)` is written as
/// the shift it is, rather than as a division by a value computed at run
/// time and left for the optimiser to recognise.
fn decompress_value(value: u16, bits: u32) -> u16 {
    let numerator = 2 * Q as u32 * value as u32 + (1u32 << bits);
    (numerator >> (bits + 1)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random polynomial, so a failure names its
    /// input.
    ///
    /// Deliberately not the OS random source: a test that fails one run in
    /// a hundred with no way to reproduce it is worse than one that fails
    /// always or never. The generator is a plain LCG - it needs to spread
    /// values over `[0, q)`, not to be unpredictable.
    fn sample(seed: u64) -> Poly {
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut out = Poly::zero();
        for at in 0..N {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            out.coefficients[at] = ((state >> 33) % Q as u64) as u16;
        }
        out
    }

    /// 17 is a primitive 256th root of unity mod q, which is the property
    /// the whole transform rests on.
    ///
    /// Checked rather than taken on faith: `17^128 = -1` is what makes the
    /// negacyclic convolution split, and if 17 had a smaller order the
    /// twiddles would repeat and the transform would not be invertible.
    #[test]
    fn test_seventeen_has_order_256() {
        assert_eq!(pow_mod(ZETA, 256), 1, "17^256 should be 1");
        assert_eq!(pow_mod(ZETA, 128), Q - 1,
                   "17^128 should be -1, which is what splits X^256 + 1");
        // No smaller power is 1, so the order is exactly 256. It suffices
        // to check the prime divisors of 256, which is only 2.
        assert_ne!(pow_mod(ZETA, 128), 1);
        // And q is prime, without which none of this holds. 3329 = 13*256+1.
        assert_eq!((Q - 1) % 256, 0, "q - 1 must be divisible by 256");
        for divisor in 2..Q {
            if divisor * divisor > Q {
                break;
            }
            assert_ne!(Q % divisor, 0, "q should be prime; {divisor} divides it");
        }
    }

    /// The twiddle table is 128 distinct values and a permutation of the
    /// powers of 17.
    ///
    /// A table with a repeat in it is a table with a wrong exponent, and
    /// this says so without comparing the numbers against a copy of
    /// themselves.
    #[test]
    fn test_the_twiddle_table_is_a_permutation_of_the_odd_powers() {
        let distinct: std::collections::HashSet<u16> = ZETAS.iter().copied().collect();
        assert_eq!(distinct.len(), 128, "the twiddles should all differ");
        assert_eq!(ZETAS[0], 1, "BitRev7(0) is 0, so this entry is 17^0");
        assert_eq!(ZETAS[1], pow_mod(ZETA, 64), "BitRev7(1) is 64");

        // Every entry is a power of 17, and the exponents are exactly
        // 0..128 - so the table is the first 128 powers, reordered.
        let mut exponents: Vec<u32> = Vec::new();
        for entry in ZETAS {
            let found = (0..256u32).find(|e| pow_mod(ZETA, *e) == entry)
                .expect("every twiddle is a power of 17");
            exponents.push(found);
        }
        exponents.sort_unstable();
        assert_eq!(exponents, (0..128).collect::<Vec<u32>>());

        // The gammas are the odd powers `17^1, 17^3, ... 17^255`, which
        // is a different *set* of exponents from the twiddles' `0..128`.
        //
        // They are not disjoint as sets of values, and a first version of
        // this test asserted they were - wrongly. The twiddle exponents
        // `0..128` include the odd numbers below 128, so those powers
        // appear in both tables. What has to hold is that the exponents
        // are the right two sets and that the tables are not the same
        // table, since using the twiddles as gammas would give a
        // base-case multiply in the wrong quotient ring.
        let gammas: std::collections::HashSet<u16> = GAMMAS.iter().copied().collect();
        assert_eq!(gammas.len(), 128, "the gammas should all differ");
        assert_ne!(GAMMAS, ZETAS, "the two tables must not be the same one");

        let mut gamma_exponents: Vec<u32> = GAMMAS.iter()
            .map(|entry| (0..256u32).find(|e| pow_mod(ZETA, *e) == *entry)
                     .expect("every gamma is a power of 17"))
            .collect();
        gamma_exponents.sort_unstable();
        assert_eq!(gamma_exponents, (0..128).map(|k| 2 * k + 1)
                                            .collect::<Vec<u32>>(),
                   "the gammas are exactly the odd powers 1, 3, .. 255");

        // **Every gamma is itself a primitive 256th root of unity**, and
        // that is the property the factorisation rests on: the odd powers
        // of a generator of a cyclic group of order 256 are exactly its
        // generators, so `gamma^128 = -1` for all 128 of them. After the
        // transform the ring is 128 copies of `Z_q[X]/(X^2 - gamma_i)`,
        // and it is `gamma_i` having order 256 rather than any smaller
        // order that makes those factors the right ones.
        //
        // A first version of this asserted that each gamma was the square
        // root of a twiddle. That is not true and there was no reason to
        // think it was: `gamma_i^2 = 17^(4*BitRev7(i)+2)`, whose exponent
        // is usually outside the twiddles' `0..128`. The test failed, which
        // is what it is for.
        for (i, gamma) in GAMMAS.iter().enumerate() {
            assert_eq!(pow_mod(*gamma, 128), Q - 1,
                       "gamma[{i}] should have order 256");
        }
        // The twiddles with an even exponent do not: they square to +1
        // over 128 steps, which is how the two tables differ in kind
        // rather than only in content.
        assert_eq!(pow_mod(ZETAS[1], 128), 1,
                   "ZETAS[1] is 17^64, an even power, so it is not a \
                    generator");
    }

    /// `BitRev7` reverses seven bits and nothing else.
    #[test]
    fn test_bit_rev7_reverses_exactly_seven_bits() {
        assert_eq!(bit_rev7(0), 0);
        assert_eq!(bit_rev7(1), 64, "0000001 -> 1000000");
        assert_eq!(bit_rev7(64), 1);
        assert_eq!(bit_rev7(127), 127, "all ones is its own reversal");
        assert_eq!(bit_rev7(0b0000011), 0b1100000);
        // It is an involution on 0..128, and a permutation of it.
        let mut seen = std::collections::HashSet::new();
        for i in 0..128 {
            assert_eq!(bit_rev7(bit_rev7(i)), i);
            assert!(seen.insert(bit_rev7(i)));
            assert!(bit_rev7(i) < 128);
        }
    }

    #[test]
    fn test_the_inverse_of_128_is_what_the_standard_says() {
        assert_eq!(INVERSE_128, 3303);
        assert_eq!(mul(INVERSE_128, 128), 1);
    }

    /// **The load-bearing test.** The transform multiplies the same way a
    /// schoolbook convolution does.
    ///
    /// `intt(ntt(f) * ntt(g))` against `f * g` computed as a negacyclic
    /// convolution. The two are different algorithms - one is 128 pairwise
    /// products with a twiddle table, the other is 65,536 term products
    /// with a sign flip - so agreeing over many inputs is evidence about
    /// the twiddles, the layer structure, the gammas and the final scaling
    /// all at once.
    ///
    /// A round trip would catch none of it: a wrong twiddle table is its
    /// own inverse.
    #[test]
    fn test_the_ntt_multiplies_the_same_way_the_schoolbook_does() {
        for seed in 0..12u64 {
            let f = sample(seed);
            let g = sample(seed + 1000);

            let mut f_hat = f.clone();
            let mut g_hat = g.clone();
            f_hat.ntt();
            g_hat.ntt();
            let mut product = f_hat.multiply_ntt(&g_hat);
            product.inverse_ntt();

            let expected = f.multiply_schoolbook(&g);
            assert_eq!(product, expected, "seed {seed}");
            assert!(product.is_reduced());
        }
    }

    /// The schoolbook multiply really is negacyclic: `X^255 * X = -1`.
    ///
    /// Without this the test above could pass with *both* implementations
    /// doing a cyclic convolution, which is a different ring.
    #[test]
    fn test_the_schoolbook_multiply_wraps_with_a_sign_change() {
        let mut top = Poly::zero();
        top.coefficients[255] = 1;                  // X^255
        let mut x = Poly::zero();
        x.coefficients[1] = 1;                      // X

        let product = top.multiply_schoolbook(&x);  // X^256 = -1
        let mut expected = Poly::zero();
        expected.coefficients[0] = Q - 1;
        assert_eq!(product, expected,
                   "X^255 * X should be -1, not +1 - the sign is the whole \
                    difference between this ring and the cyclic one");

        // And the NTT agrees, which ties the two conventions together.
        let mut a = top.clone();
        let mut b = x.clone();
        a.ntt();
        b.ntt();
        let mut viantt = a.multiply_ntt(&b);
        viantt.inverse_ntt();
        assert_eq!(viantt, expected);
    }

    /// The transform inverts. Weak on its own, and here to localise a
    /// failure rather than to find one.
    #[test]
    fn test_the_transform_inverts() {
        for seed in 0..8u64 {
            let original = sample(seed);
            let mut round = original.clone();
            round.ntt();
            assert_ne!(round, original, "the transform did nothing");
            round.inverse_ntt();
            assert_eq!(round, original, "seed {seed}");
        }
    }

    /// Multiplication by 1 and by 0, and that multiplying in the
    /// transformed domain is commutative.
    #[test]
    fn test_the_multiplicative_identity_survives_the_transform() {
        let mut one = Poly::zero();
        one.coefficients[0] = 1;
        let f = sample(7);

        let mut one_hat = one.clone();
        let mut f_hat = f.clone();
        one_hat.ntt();
        f_hat.ntt();

        let mut product = f_hat.multiply_ntt(&one_hat);
        product.inverse_ntt();
        assert_eq!(product, f);

        assert_eq!(f_hat.multiply_ntt(&one_hat), one_hat.multiply_ntt(&f_hat));

        let zero_hat = {
            let mut z = Poly::zero();
            z.ntt();
            z
        };
        let mut product = f_hat.multiply_ntt(&zero_hat);
        product.inverse_ntt();
        assert_eq!(product, Poly::zero());
    }

    /// Addition and subtraction are inverse, and stay reduced.
    #[test]
    fn test_addition_and_subtraction_stay_in_range() {
        let f = sample(3);
        let g = sample(4);
        assert_eq!(f.add(&g).sub(&g), f);
        assert!(f.add(&g).is_reduced());
        assert!(f.sub(&g).is_reduced());

        // The edge the helpers exist for: q - 1 plus q - 1.
        assert_eq!(add_mod(Q - 1, Q - 1), Q - 2);
        assert_eq!(sub_mod(0, Q - 1), 1);
        assert_eq!(sub_mod(0, 0), 0);
        assert_eq!(mul(Q - 1, Q - 1), 1, "(-1)^2 = 1");
    }

    #[test]
    fn test_a_coefficient_at_or_above_q_is_refused() {
        let mut bad = [0u16; N];
        bad[17] = Q;
        let error = Poly::from_coefficients(bad).unwrap_err();
        assert!(error.contains("17") && error.contains("3329"), "{error}");
        bad[17] = Q - 1;
        assert!(Poly::from_coefficients(bad).is_ok());
    }

    /// Compression loses no more than FIPS 203 allows.
    ///
    /// The bound is the point: `Decompress(Compress(x))` must be within
    /// `ceil(q / 2^(d+1))` of `x`, and that bound is what ML-KEM's
    /// decryption failure probability is computed from. A rounding written
    /// as truncation passes a round trip at `d = 12` and drifts at every
    /// smaller `d`, which is where the ciphertext actually lives.
    #[test]
    fn test_compression_loses_no_more_than_the_standard_allows() {
        for bits in 1..=12u32 {
            let bound = (Q as u32).div_ceil(1u32 << (bits + 1));
            let mut worst = 0u32;
            for value in 0..Q {
                let small = compress(value, bits).unwrap();
                assert!((small as u32) < (1u32 << bits));
                let back = decompress(small, bits).unwrap();
                // The distance is measured in the ring, so it wraps.
                let direct = (back as i32 - value as i32).unsigned_abs();
                let distance = direct.min(Q as u32 - direct);
                worst = worst.max(distance);
                assert!(distance <= bound,
                        "d = {bits}: {value} -> {small} -> {back} is {distance} \
                         away, bound is {bound}");
            }
            // And the bound is reached rather than merely respected,
            // which is what says the rounding is round-half rather than
            // truncation: a truncating implementation *exceeds* it, and a
            // bound computed too generously would never be approached.
            //
            // Twelve bits is the exception and not a special case to
            // explain away: `2^12 > q`, so the encoding is a bijection and
            // the error really is zero. That is
            // `test_twelve_bit_compression_is_lossless`.
            if bits < 12 {
                assert!(worst * 2 >= bound,
                        "d = {bits}: worst error {worst} is far below the \
                         bound {bound}, which suggests the bound is being \
                         computed wrongly rather than the rounding being \
                         unusually good");
            } else {
                assert_eq!(worst, 0, "12 bits should be lossless");
            }
        }
    }

    /// At 12 bits compression is lossless, which is the one case where it
    /// is a re-encoding rather than a rounding.
    #[test]
    fn test_twelve_bit_compression_is_lossless() {
        for value in 0..Q {
            assert_eq!(decompress(compress(value, 12).unwrap(), 12).unwrap(),
                       value, "12 bits should round trip exactly");
        }
    }

    /// One bit is the extreme case, and the one ML-KEM uses for the
    /// message: everything nearer 0 than q/2 compresses to 0.
    #[test]
    fn test_one_bit_compression_is_the_message_encoding() {
        assert_eq!(compress(0, 1).unwrap(), 0);
        assert_eq!(compress(Q / 2, 1).unwrap(), 1);
        assert_eq!(compress(Q - 1, 1).unwrap(), 0, "just below q wraps to 0");
        assert_eq!(decompress(0, 1).unwrap(), 0);
        // `Decompress_1(1) = round(q/2)`, which is 1665. Written as
        // `div_ceil` because clippy asks and because it is the same value:
        // q is odd, so rounding half up and rounding up agree.
        assert_eq!(decompress(1, 1).unwrap(), Q.div_ceil(2));
        assert_eq!(decompress(1, 1).unwrap(), 1665);
    }

    #[test]
    fn test_the_compression_widths_are_checked() {
        assert!(compress(0, 0).unwrap_err().contains("1 to 12"));
        assert!(compress(0, 13).unwrap_err().contains("1 to 12"));
        assert!(compress(Q, 4).unwrap_err().contains("3329"));
        assert!(decompress(16, 4).unwrap_err().contains("does not fit"));
        assert!(decompress(15, 4).is_ok());
    }
}
