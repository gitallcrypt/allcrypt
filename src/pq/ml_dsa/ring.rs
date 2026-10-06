/*
The ring `Z_q[X]/(X^256 + 1)` with `q = 8380417`, and the NTT over it.

ML-DSA's ring (FIPS 204). It is **not** ML-KEM's: the modulus is 23 bits
rather than 12, the root of unity is 1753 rather than 17, and - the
difference that changes the shape of the code - `q - 1 = 2^13 * 1023` has
an element of order **512**, so the NTT splits `X^256 + 1` all the way
into 256 linear factors `X - zeta^(2*BitRev8(i)+1)`. A transformed
polynomial is 256 independent residues, and multiplication in the
transformed domain is coefficient by coefficient. ML-KEM's stops one
layer short and multiplies pairs.

So the two rings share an idea and no code. A shared generic ring would
have to be parameterised over the coefficient width, the number of
layers and the shape of the base-case multiply - which is to say, over
everything - and the place the two differ is exactly where a shared
implementation would hide a mistake.

# Pitfalls

**The twiddle table is its own inverse**, exactly as in ML-KEM:
`intt(ntt(f)) == f` holds for any consistent table, a wrong one included.
What carries the verdict is `intt(ntt(f) * ntt(g)) == f * g` against a
schoolbook negacyclic convolution written separately -
[`tests::test_the_ntt_multiplies_the_same_way_the_schoolbook_does`].

**`BitRev8`, not `BitRev7`.** 256 twiddles, eight bit indices. A seven bit
reversal here gives a permutation of half the table, repeated - and the
round trip still works.

**The inverse uses `-zeta`.** FIPS 204's `NTT^-1` multiplies by
`-zetas[m]`, walking `m` down from 256. Using `+zeta` there gives an
inverse that is wrong by a sign pattern, and a round trip through it
fails - so this one, unusually, the round trip does catch.

**`256^-1`, not `128^-1`.** Eight layers, so the final scaling is by the
inverse of 256: 8347681. ML-KEM's seven layers scale by `128^-1`.

**Products are 46 bits.** Two coefficients below `q < 2^23` multiply to
under `2^46`, so the product is a `u64` and reduced by `% Q` on a
constant, which compiles to a multiply and a shift. A `u32` product
would wrap silently. `ct_check.py`'s division scan covers this module
along with ML-KEM's.

**Coefficients are kept in `[0, q)`.** FIPS 204 uses centred
representatives (`mod±`) in several places - `Power2Round`,
`Decompose`, the infinity norm - and those functions convert at their
boundary. The ring itself never holds a negative value.
*/

/// The modulus: `2^23 - 2^13 + 1`, prime.
pub const Q: u32 = 8_380_417;

/// Coefficients per polynomial.
pub const N: usize = 256;

/// The 512th root of unity FIPS 204 uses.
const ZETA: u32 = 1753;

/// `base^exp mod Q`, at compile time.
const fn pow_mod(base: u32, exp: u64) -> u32 {
    let mut result: u64 = 1;
    let mut square = base as u64 % Q as u64;
    let mut remaining = exp;
    while remaining > 0 {
        if remaining & 1 == 1 {
            result = result * square % Q as u64;
        }
        square = square * square % Q as u64;
        remaining >>= 1;
    }
    result as u32
}

/// `BitRev8`: reverse the low **eight** bits.
const fn bit_rev8(mut value: usize) -> usize {
    let mut out = 0usize;
    let mut bit = 0;
    while bit < 8 {
        out = (out << 1) | (value & 1);
        value >>= 1;
        bit += 1;
    }
    out
}

/// `zeta^BitRev8(k) mod q` for `k` in `0..256`: FIPS 204's `zetas`.
///
/// Index 0 is 1 and the forward transform never reads it (it starts at
/// `m = 1`); kept so the indices are the standard's.
pub const ZETAS: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut k = 0;
    while k < 256 {
        table[k] = pow_mod(ZETA, bit_rev8(k) as u64);
        k += 1;
    }
    table
};

/// `256^-1 mod q`, which the inverse transform finishes with. FIPS 204
/// writes it as 8347681; `test_the_inverse_of_256_is_what_the_standard_says`
/// checks the computed value against that.
pub const INVERSE_256: u32 = pow_mod(256, Q as u64 - 2);

/// `a * b mod q`.
#[inline]
pub fn mul(a: u32, b: u32) -> u32 {
    (a as u64 * b as u64 % Q as u64) as u32
}

#[inline]
fn add_mod(a: u32, b: u32) -> u32 {
    (a + b) % Q
}

#[inline]
fn sub_mod(a: u32, b: u32) -> u32 {
    (a + Q - b) % Q
}

/// A polynomial: `N` coefficients in `[0, q)`.
///
/// Not `Copy` - it is a kilobyte.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Poly {
    /// Always reduced into `[0, q)`.
    pub coefficients: [u32; N],
}

impl Default for Poly {
    fn default() -> Poly { Poly::zero() }
}

impl Poly {
    pub fn zero() -> Poly { Poly { coefficients: [0u32; N] } }

    /// Whether every coefficient is in `[0, q)`.
    pub fn is_reduced(&self) -> bool {
        self.coefficients.iter().all(|value| *value < Q)
    }

    pub fn add(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] =
                add_mod(self.coefficients[at], other.coefficients[at]);
        }
        out
    }

    pub fn sub(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] =
                sub_mod(self.coefficients[at], other.coefficients[at]);
        }
        out
    }

    /// FIPS 204 algorithm 41, `NTT`, in place.
    ///
    /// Eight layers. The twiddle index `m` runs forward from 1 to 255
    /// across the whole transform and is not reset per layer.
    pub fn ntt(&mut self) {
        let mut m = 0usize;
        let mut length = 128usize;
        while length >= 1 {
            let mut start = 0usize;
            while start < N {
                m += 1;
                let zeta = ZETAS[m];
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

    /// FIPS 204 algorithm 42, `NTT^-1`, in place: `m` runs down from 256,
    /// each twiddle is **negated**, and the result is scaled by `256^-1`.
    pub fn inverse_ntt(&mut self) {
        let mut m = 256usize;
        let mut length = 1usize;
        while length < N {
            let mut start = 0usize;
            while start < N {
                m -= 1;
                let zeta = Q - ZETAS[m];
                for at in start..start + length {
                    let t = self.coefficients[at];
                    self.coefficients[at] =
                        add_mod(t, self.coefficients[at + length]);
                    self.coefficients[at + length] = mul(
                        zeta, sub_mod(t, self.coefficients[at + length]));
                }
                start += 2 * length;
            }
            length *= 2;
        }
        for value in self.coefficients.iter_mut() {
            *value = mul(*value, INVERSE_256);
        }
    }

    /// FIPS 204 algorithm 45, `MultiplyNTT`: coefficient by coefficient,
    /// because the transform split the ring all the way into linear
    /// factors.
    pub fn multiply_ntt(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] =
                mul(self.coefficients[at], other.coefficients[at]);
        }
        out
    }

    /// The 256-term negacyclic convolution, written directly.
    ///
    /// Not used by ML-DSA. It is the slow path the NTT is checked
    /// against: `X^256 = -1`, so a product term at degree `256 + i`
    /// folds down to degree `i` with its sign changed.
    pub fn multiply_schoolbook(&self, other: &Poly) -> Poly {
        let mut wide = [0u64; 2 * N];
        for i in 0..N {
            for j in 0..N {
                wide[i + j] = (wide[i + j]
                               + self.coefficients[i] as u64
                                 * other.coefficients[j] as u64)
                              % Q as u64;
            }
        }
        let mut out = Poly::zero();
        for at in 0..N {
            out.coefficients[at] =
                ((wide[at] + Q as u64 - wide[at + N]) % Q as u64) as u32;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random polynomial, so a failure names its
    /// input.
    fn sample(seed: u64) -> Poly {
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut out = Poly::zero();
        for at in 0..N {
            state = state.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.coefficients[at] = ((state >> 33) % Q as u64) as u32;
        }
        out
    }

    /// 1753 is a primitive 512th root of unity mod q, and q is prime.
    #[test]
    fn test_1753_has_order_512() {
        assert_eq!(pow_mod(ZETA, 512), 1);
        assert_eq!(pow_mod(ZETA, 256), Q - 1,
                   "zeta^256 should be -1, which is what splits X^256 + 1");
        assert_eq!((Q - 1) % 512, 0);
        assert_eq!(Q, (1 << 23) - (1 << 13) + 1);
        let mut divisor = 2u32;
        while divisor * divisor <= Q {
            assert_ne!(Q % divisor, 0, "q should be prime; {divisor} divides it");
            divisor += 1;
        }
    }

    /// The table is 256 distinct powers of zeta with exponents exactly
    /// `0..256` - the first half of the group zeta generates, reordered by
    /// `BitRev8`.
    #[test]
    fn test_the_twiddle_table_is_a_permutation_of_the_first_256_powers() {
        let distinct: std::collections::HashSet<u32> =
            ZETAS.iter().copied().collect();
        assert_eq!(distinct.len(), 256);
        assert_eq!(ZETAS[0], 1);
        assert_eq!(ZETAS[1], pow_mod(ZETA, 128), "BitRev8(1) is 128");
        // Build the discrete log table once rather than searching per entry.
        let mut log = std::collections::HashMap::new();
        let mut power = 1u32;
        for exponent in 0..512u32 {
            log.insert(power, exponent);
            power = mul(power, ZETA);
        }
        let mut exponents: Vec<u32> = ZETAS.iter()
            .map(|z| *log.get(z).expect("every twiddle is a power of zeta"))
            .collect();
        exponents.sort_unstable();
        assert_eq!(exponents, (0..256).collect::<Vec<u32>>());
    }

    /// FIPS 204 states `256^-1 mod q` as 8347681 in algorithm 42; the one
    /// constant here small enough to be worth comparing with the printed
    /// value, and computed rather than typed everywhere else.
    #[test]
    fn test_the_inverse_of_256_is_what_the_standard_says() {
        assert_eq!(INVERSE_256, 8_347_681);
        assert_eq!(mul(INVERSE_256, 256), 1);
    }

    /// The load-bearing test: the transform multiplies the way the ring
    /// does.
    #[test]
    fn test_the_ntt_multiplies_the_same_way_the_schoolbook_does() {
        for seed in 0..8u64 {
            let (f, g) = (sample(2 * seed), sample(2 * seed + 1));
            let mut f_hat = f.clone();
            let mut g_hat = g.clone();
            f_hat.ntt();
            g_hat.ntt();
            let mut product = f_hat.multiply_ntt(&g_hat);
            product.inverse_ntt();
            assert_eq!(product, f.multiply_schoolbook(&g), "seed {seed}");
        }
    }

    /// `X^255 * X = -1`: the sign convention pinned on its own, so that a
    /// schoolbook multiply sharing a mistake with the NTT cannot hide it.
    #[test]
    fn test_the_schoolbook_multiply_wraps_with_a_sign_change() {
        let mut a = Poly::zero();
        a.coefficients[255] = 1;
        let mut b = Poly::zero();
        b.coefficients[1] = 1;
        let product = a.multiply_schoolbook(&b);
        let mut expected = Poly::zero();
        expected.coefficients[0] = Q - 1;
        assert_eq!(product, expected);
    }

    /// The round trip, for what it is worth - and the forward transform
    /// of `X` evaluated directly: the residue of `f` modulo
    /// `X - zeta^(2*BitRev8(i)+1)` is `f(zeta^(2*BitRev8(i)+1))`, so the
    /// transform of `X` is the list of those roots, in that order.
    #[test]
    fn test_the_transform_of_x_is_the_list_of_roots() {
        for seed in 0..4u64 {
            let f = sample(100 + seed);
            let mut g = f.clone();
            g.ntt();
            assert!(g.is_reduced());
            g.inverse_ntt();
            assert_eq!(g, f);
        }
        let mut x = Poly::zero();
        x.coefficients[1] = 1;
        x.ntt();
        for i in 0..N {
            assert_eq!(x.coefficients[i],
                       pow_mod(ZETA, 2 * bit_rev8(i) as u64 + 1), "index {i}");
        }
    }

    /// Products of two values near q do not wrap.
    #[test]
    fn test_products_are_wide_enough() {
        assert_eq!(mul(Q - 1, Q - 1), 1, "(-1)^2 = 1");
        assert_eq!(mul(Q - 1, 2), Q - 2);
    }
}
