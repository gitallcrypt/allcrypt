/*!
Binary fields `GF(2^m)` in a polynomial basis, for DSTU 4145-2002's
curves: `m` up to 448 bits, a reduction polynomial with three or five
terms, `x^m + x^k3 + x^k2 + x^k1 + 1` or `x^m + x^k + 1`.

An element is a polynomial over `GF(2)` of degree below `m`, stored as
seven 64-bit words, bit `i` of the whole the coefficient of `x^i`. Every
operation runs the same instructions whatever the values: multiplication
adds one operand under a mask for every bit of the
other, reduction folds the high words down a word at a time, and the
exponents of the reduction polynomial - which are public - are the only
thing that decides an index.

Inversion is Fermat's, `a^(2^m - 2)`, square roots are `2^(m-1)` powers,
and the trace and half-trace are sums of squares, so each has a fixed
operation count. `solve_quadratic` finds `z` with `z^2 + z = c` by the
half-trace, which needs `m` odd; every DSTU 4145 field is.
*/

use crate::bignum::ct::opaque;

/// Words per element: 448 bits, enough for every DSTU 4145 field.
pub const LIMBS: usize = 7;

/// An element, or any polynomial of fewer than 448 bits.
pub type Fe = [u64; LIMBS];

/// `GF(2^m)` with its reduction polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    m: usize,
    /// The polynomial's exponents below `m`, highest first, zero last:
    /// `[k3, k2, k1, 0]` or `[k, 0]`.
    terms: Vec<usize>,
}

fn mask(bit: u64) -> u64 {
    opaque(bit & 1).wrapping_neg()
}

impl Field {
    /// The field of `x^m` plus `x^t` for each `t` in `terms`, which must
    /// include 0 and be below `m`.
    ///
    /// # Errors
    /// `m` above 447, or terms that do not make a trinomial or a
    /// pentanomial ending in 1.
    pub fn new(m: usize, terms: &[usize]) -> Result<Field, String> {
        let mut terms = terms.to_vec();
        terms.sort_unstable_by(|a, b| b.cmp(a));
        terms.dedup();
        // The word-at-a-time reduction folds a word of high bits down by
        // m - k, and needs that to land below m in one step: k + 64 < m.
        if !(2..64 * LIMBS).contains(&m) || !(terms.len() == 2 || terms.len() == 4)
            || terms[terms.len() - 1] != 0 || terms[0] >= m || terms[0] + 64 >= m {
            return Err(format!("GF(2^{m}) needs a trinomial or pentanomial reduction \
                                polynomial below x^{m}, ending in 1, whose middle terms \
                                are below x^(m - 64), and m below 448; got {terms:?}."));
        }
        Ok(Field { m, terms })
    }

    pub fn degree(&self) -> usize {
        self.m
    }

    /// The exponents below `m`, highest first, ending in 0.
    pub fn terms(&self) -> &[usize] {
        &self.terms
    }

    /// The bytes an element occupies, big endian: `ceil(m / 8)`.
    pub fn byte_len(&self) -> usize {
        self.m.div_ceil(8)
    }

    pub fn zero(&self) -> Fe {
        [0; LIMBS]
    }

    pub fn one(&self) -> Fe {
        let mut one = [0; LIMBS];
        one[0] = 1;
        one
    }

    /// An element from big-endian bytes, which must hold a polynomial of
    /// degree below `m`.
    ///
    /// # Errors
    /// More bytes than `byte_len`, or a bit at or above `m`.
    pub fn from_bytes(&self, bytes: &[u8]) -> Result<Fe, String> {
        let bytes = {
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            &bytes[skip.min(bytes.len())..]
        };
        if bytes.len() > self.byte_len() {
            return Err(format!("{} bytes do not fit GF(2^{}).", bytes.len(), self.m));
        }
        let mut out = [0u64; LIMBS];
        for (i, &b) in bytes.iter().rev().enumerate() {
            out[i / 8] |= u64::from(b) << (8 * (i % 8));
        }
        if self.high_bits(&out) != 0 {
            return Err(format!("This value has a bit at or above x^{}, outside \
                                GF(2^{}).", self.m, self.m));
        }
        Ok(out)
    }

    /// The element's big-endian bytes, `byte_len` of them.
    pub fn to_bytes(&self, a: &Fe) -> Vec<u8> {
        let n = self.byte_len();
        (0..n).rev().map(|i| (a[i / 8] >> (8 * (i % 8))) as u8).collect()
    }

    /// The bits at and above `m`, ORed together; zero for an element.
    fn high_bits(&self, a: &Fe) -> u64 {
        let (word, bit) = (self.m / 64, self.m % 64);
        let mut high = a[word] >> bit;
        for w in &a[word + 1..] {
            high |= w;
        }
        high
    }

    pub fn add(&self, a: &Fe, b: &Fe) -> Fe {
        let mut out = *a;
        for (o, x) in out.iter_mut().zip(b) {
            *o ^= x;
        }
        out
    }

    /// XOR `value` into `c` starting at bit `at`.
    fn xor_at(c: &mut [u64; 2 * LIMBS], at: usize, value: u64) {
        let (word, shift) = (at / 64, at % 64);
        c[word] ^= value << shift;
        if shift != 0 {
            c[word + 1] ^= value >> (64 - shift);
        }
    }

    /// Reduce a polynomial of up to `2m - 1` bits modulo the reduction
    /// polynomial, a word at a time from the top: the word's bits, which
    /// stand for `x^(64w + i)`, are replaced by the same bits times
    /// `x^(64w - m)` times the polynomial's low terms. Every position
    /// written is a function of `m` and the terms alone.
    fn reduce(&self, c: &mut [u64; 2 * LIMBS]) -> Fe {
        let top_word = self.m / 64;
        for w in (top_word + 1..2 * LIMBS).rev() {
            let t = c[w];
            c[w] = 0;
            for term in &self.terms {
                Field::xor_at(c, 64 * w - self.m + term, t);
            }
        }
        // The bits at and above m in the word that holds x^m.
        let shift = self.m % 64;
        let t = c[top_word] >> shift;
        c[top_word] &= (1u64 << shift).wrapping_sub(1);
        for term in &self.terms {
            Field::xor_at(c, *term, t);
        }
        let mut out = [0u64; LIMBS];
        out.copy_from_slice(&c[..LIMBS]);
        out
    }

    /// The words an element can occupy.
    fn words(&self) -> usize {
        self.m.div_ceil(64)
    }

    /// `a · b`: for each of the `m` bits of `a`, `b` shifted to it is
    /// added under a mask.
    pub fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        let words = self.words();
        let mut c = [0u64; 2 * LIMBS];
        // The comb: bit k of every word of a, from the top, adds b at that
        // word; the product so far moves up one bit between columns.
        for k in (0..64).rev() {
            for i in 0..words {
                let bit = mask(a[i] >> k);
                for j in 0..words {
                    c[i + j] ^= b[j] & bit;
                }
            }
            if k != 0 {
                for w in (1..2 * words).rev() {
                    c[w] = (c[w] << 1) | (c[w - 1] >> 63);
                }
                c[0] <<= 1;
            }
        }
        self.reduce(&mut c)
    }

    /// The 32 bits of `x` spread to the even bits of a word: squaring in
    /// characteristic two puts each coefficient at twice its exponent.
    fn spread(x: u64) -> u64 {
        let mut x = x & 0xffff_ffff;
        x = (x | (x << 16)) & 0x0000_ffff_0000_ffff;
        x = (x | (x << 8)) & 0x00ff_00ff_00ff_00ff;
        x = (x | (x << 4)) & 0x0f0f_0f0f_0f0f_0f0f;
        x = (x | (x << 2)) & 0x3333_3333_3333_3333;
        (x | (x << 1)) & 0x5555_5555_5555_5555
    }

    /// `a^2`: the bits spread apart, then reduced.
    pub fn square(&self, a: &Fe) -> Fe {
        let mut c = [0u64; 2 * LIMBS];
        for (i, &w) in a.iter().enumerate() {
            c[2 * i] = Field::spread(w);
            c[2 * i + 1] = Field::spread(w >> 32);
        }
        self.reduce(&mut c)
    }

    /// `a^(2^k)`.
    fn square_times(&self, a: &Fe, k: usize) -> Fe {
        let mut out = *a;
        for _ in 0..k {
            out = self.square(&out);
        }
        out
    }

    /// `a^(-1)` as `a^(2^m - 2)`, by Itoh and Tsujii's chain: with
    /// `β_k = a^(2^k - 1)`, `β_(j+k) = β_j^(2^k) · β_k`, built up along
    /// the bits of `m - 1`, and the inverse is `β_(m-1)^2`. Zero for zero,
    /// which the callers check for.
    pub fn invert(&self, a: &Fe) -> Fe {
        let target = self.m - 1;
        // β_1 = a, then along the bits of m - 1 from the top.
        let mut beta = *a;
        let mut k = 1usize;
        for bit in (0..usize::BITS - target.leading_zeros() - 1).rev() {
            // β_(2k) = β_k^(2^k) · β_k.
            beta = self.mul(&self.square_times(&beta, k), &beta);
            k *= 2;
            if (target >> bit) & 1 == 1 {
                // β_(k+1) = β_k^2 · a.
                beta = self.mul(&self.square(&beta), a);
                k += 1;
            }
        }
        debug_assert_eq!(k, target);
        self.square(&beta)
    }

    /// The square root, `a^(2^(m-1))`; every element has exactly one.
    pub fn sqrt(&self, a: &Fe) -> Fe {
        self.square_times(a, self.m - 1)
    }

    /// The trace, `a + a^2 + a^4 + ... + a^(2^(m-1))`: zero or one.
    pub fn trace(&self, a: &Fe) -> u64 {
        let mut power = *a;
        let mut sum = *a;
        for _ in 1..self.m {
            power = self.square(&power);
            sum = self.add(&sum, &power);
        }
        sum[0] & 1
    }

    /// The half-trace, `a + a^4 + a^16 + ... + a^(2^(m-1))`, for odd `m`.
    pub fn half_trace(&self, a: &Fe) -> Fe {
        let mut power = *a;
        let mut sum = *a;
        for _ in 0..(self.m - 1) / 2 {
            power = self.square_times(&power, 2);
            sum = self.add(&sum, &power);
        }
        sum
    }

    /// A `z` with `z^2 + z = c`, or `None` when there is none (the trace
    /// of `c` is one). The other solution is `z + 1`.
    pub fn solve_quadratic(&self, c: &Fe) -> Option<Fe> {
        debug_assert!(self.m % 2 == 1, "the half-trace solves only for odd m");
        if self.trace(c) != 0 {
            return None;
        }
        let z = self.half_trace(c);
        let check = self.add(&self.square(&z), &z);
        (check == *c).then_some(z)
    }

    /// Whether `a` is zero, as a `bool`: for public values.
    pub fn is_zero(&self, a: &Fe) -> bool {
        a.iter().fold(0, |acc, w| acc | w) == 0
    }

    /// One when `a` is zero and zero otherwise, without a branch: for
    /// secret values.
    pub fn zero_bit(&self, a: &Fe) -> u64 {
        let acc = opaque(a.iter().fold(0, |acc, w| acc | w));
        ((acc | acc.wrapping_neg()) >> 63) ^ 1
    }

    /// `b` when `bit` is one, `a` when it is zero, without a branch.
    pub fn select(&self, a: &Fe, b: &Fe, bit: u64) -> Fe {
        let m = mask(bit);
        let mut out = *a;
        for (o, x) in out.iter_mut().zip(b) {
            *o ^= (*o ^ x) & m;
        }
        out
    }

    /// Swap `a` and `b` when `bit` is one, without a branch.
    pub fn cswap(&self, a: &mut Fe, b: &mut Fe, bit: u64) {
        let m = mask(bit);
        for (x, y) in a.iter_mut().zip(b.iter_mut()) {
            let t = (*x ^ *y) & m;
            *x ^= t;
            *y ^= t;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A product computed the slow way: polynomial multiplication bit by
    /// bit into a vector of bits, then division by the polynomial bit by
    /// bit - the definition, with no word arithmetic to get wrong.
    fn reference_mul(f: &Field, a: &Fe, b: &Fe) -> Fe {
        let bit = |x: &Fe, i: usize| (x[i / 64] >> (i % 64)) & 1 == 1;
        let mut product = vec![false; 2 * f.m];
        for i in 0..f.m {
            for j in 0..f.m {
                if bit(a, i) && bit(b, j) {
                    product[i + j] ^= true;
                }
            }
        }
        for i in (f.m..2 * f.m).rev() {
            if product[i] {
                product[i] = false;
                for t in &f.terms {
                    product[i - f.m + t] ^= true;
                }
            }
        }
        let mut out = [0u64; LIMBS];
        for (i, &set) in product.iter().enumerate().take(f.m) {
            if set {
                out[i / 64] |= 1 << (i % 64);
            }
        }
        out
    }

    fn element(f: &Field, seed: u64) -> Fe {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut out = [0u64; LIMBS];
        for w in out.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *w = x;
        }
        // Clear everything at and above m.
        for i in f.m..64 * LIMBS {
            out[i / 64] &= !(1 << (i % 64));
        }
        out
    }

    fn fields() -> Vec<Field> {
        vec![Field::new(163, &[7, 6, 3, 0]).unwrap(), Field::new(167, &[6, 0]).unwrap(),
             Field::new(257, &[12, 0]).unwrap(), Field::new(431, &[5, 3, 1, 0]).unwrap(),
             Field::new(97, &[6, 0]).unwrap()]
    }

    #[test]
    fn test_mul_against_the_definition() {
        for f in fields() {
            for seed in 0..12 {
                let (a, b) = (element(&f, seed), element(&f, seed + 100));
                assert_eq!(f.mul(&a, &b), reference_mul(&f, &a, &b), "{} {seed}", f.m);
            }
            // The top coefficient times itself is the largest reduction.
            let mut top = [0u64; LIMBS];
            top[(f.m - 1) / 64] = 1 << ((f.m - 1) % 64);
            assert_eq!(f.mul(&top, &top), reference_mul(&f, &top, &top));
        }
    }

    #[test]
    fn test_inverse_sqrt_and_quadratic() {
        for f in fields() {
            for seed in 1..6 {
                let a = element(&f, seed);
                assert_eq!(f.mul(&a, &f.invert(&a)), f.one(), "{}", f.m);
                assert_eq!(f.square(&f.sqrt(&a)), a);
                let t = f.trace(&a);
                assert!(t <= 1);
                // Tr(a^2) = Tr(a), and Tr is additive.
                assert_eq!(f.trace(&f.square(&a)), t);
                let b = element(&f, seed + 50);
                assert_eq!(f.trace(&f.add(&a, &b)), t ^ f.trace(&b));
                match f.solve_quadratic(&a) {
                    Some(z) => {
                        assert_eq!(t, 0);
                        assert_eq!(f.add(&f.square(&z), &z), a);
                    }
                    None => assert_eq!(t, 1),
                }
            }
            assert_eq!(f.invert(&f.zero()), f.zero());
            assert_eq!(f.trace(&f.zero()), 0);
            // Tr(1) = m mod 2.
            assert_eq!(f.trace(&f.one()), (f.m % 2) as u64);
        }
    }

    #[test]
    fn test_bytes() {
        let f = Field::new(163, &[7, 6, 3, 0]).unwrap();
        let a = element(&f, 3);
        let bytes = f.to_bytes(&a);
        assert_eq!(bytes.len(), 21);
        assert_eq!(f.from_bytes(&bytes).unwrap(), a);
        // Leading zero bytes are allowed; a bit at x^163 is not.
        let mut padded = vec![0, 0];
        padded.extend_from_slice(&bytes);
        assert_eq!(f.from_bytes(&padded).unwrap(), a);
        let mut over = vec![0u8; 21];
        over[0] = 0x08;
        assert!(f.from_bytes(&over).is_err());
        over[0] = 0x04;
        assert!(f.from_bytes(&over).is_ok());
        assert!(f.from_bytes(&[1u8; 22]).unwrap_err().contains("do not fit"));
        // Past the seven words an element is stored in, too.
        assert!(f.from_bytes(&[1u8; 64]).unwrap_err().contains("do not fit"));
    }

    #[test]
    fn test_polynomials_are_checked() {
        assert!(Field::new(163, &[7, 6, 3, 0]).is_ok());
        assert!(Field::new(163, &[7, 6, 3]).is_err());
        assert!(Field::new(163, &[7, 6, 0]).is_err());
        assert!(Field::new(163, &[163, 0]).is_err());
        assert!(Field::new(448, &[1, 0]).is_err());
        // A middle term within 64 of m cannot be folded in one word.
        assert!(Field::new(100, &[40, 0]).is_err());
        assert!(Field::new(100, &[35, 0]).is_ok());
    }
}
