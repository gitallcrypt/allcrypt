/*
Montgomery modular arithmetic.

Modular reduction by division is the expensive part of exponentiation, and it
is also the part that branches on its inputs. Montgomery's trick replaces it
with multiplication and shifting: work with values in the "Montgomery domain"
where `a` is represented as `a*R mod n` for `R = 2^(64k)`, and the reduction
after each multiply becomes a fixed sequence of multiply-add-shift steps with
no division anywhere.

That buys two things at once, which is why this is worth doing now:

  * a path to constant time, because nothing in the reduction depends on the
    values any more, and
  * some speed.

On the speed: measure before believing. The schoolbook path here is already
reasonable, because Knuth division does less limb work than CIOS - it wins
mainly by avoiding the slow hardware divide. Measured on this codebase it is
about 1.6x for a 2048 bit private exponent and roughly break even for a small
public one. The constant-time story, not the speed, is the reason this exists.

Requires an odd modulus. Every modulus we care about is odd: RSA moduli are
products of odd primes, and the prime field characteristics for elliptic
curves are primes above 2. `Montgomery::new` errors on an even one rather
than silently producing nonsense.

Operands are `bignum::ct::Secret` - exactly `k` limbs, zero padded, never
normalised - because the normalised `BigUint` representation leaks its
magnitude through its length and no amount of branchless arithmetic fixes
that. The modulus and the width are public; the values are not.

**What is still variable time here**, because it cannot be otherwise: the
*width* `k`, the loop bound handed to `pow_ct`, and `Montgomery::new` itself,
which computes `R^2 mod n` with ordinary division. The modulus is public in
every use, so that is fine - but it is why `new` takes a `&BigUint` and
everything after it takes a `Secret`.
*/

use super::ct::{self, Mask, Secret};
use super::BigUint;

/// Cloneable so a key can hold one, and `Debug` by hand because `Secret` has
/// none on purpose - a derived one would print the modulus, and for an RSA
/// prime that is the key.
#[derive(Clone)]
pub struct Montgomery {
    /// The modulus, fixed width. Public, but held as a `Secret` so it can be
    /// fed to the same arithmetic as everything else.
    n: Secret,
    /// Limb count, which is the width everything in the domain uses.
    k: usize,
    /// -n^-1 mod 2^64, the magic constant that makes the reduction work.
    n0inv: u64,
    /// R^2 mod n, used to enter the domain.
    r2: Secret,
    /// R mod n, which is the domain's representation of 1.
    r1: Secret,
    /// `n - 2`, precomputed for Fermat inversion. Only meaningful when the
    /// modulus is prime, which `inverse_prime` says in its name.
    n_minus_2: Secret,
}

impl Montgomery {
    pub fn new(modulus: &BigUint) -> Result<Montgomery, String> {
        if modulus.is_zero() {
            return Err("Montgomery modulus is zero.".to_string());
        }
        if modulus.is_even() {
            return Err("Montgomery arithmetic requires an odd modulus.".to_string());
        }
        let k = modulus.limbs().len();
        let n = Secret::from_biguint(modulus, k)?;

        // n0inv = -n[0]^-1 mod 2^64, by Newton iteration. Each step doubles
        // the number of correct bits: 1, 2, 4, 8, 16, 32, 64.
        let n0 = n.limbs()[0];
        let mut inv: u64 = 1;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
        }
        debug_assert_eq!(n0.wrapping_mul(inv), 1, "Newton iteration failed to invert n[0]");
        let n0inv = inv.wrapping_neg();

        // R^2 mod n and R mod n, computed once with the slow path. The
        // modulus is public, so the division here leaks nothing.
        let r2 = Secret::from_biguint(&BigUint::one().shl(2 * k * 64).rem(modulus)?, k)?;
        let r1 = Secret::from_biguint(&BigUint::one().shl(k * 64).rem(modulus)?, k)?;

        // n - 2 cannot borrow: n is odd and at least 3 unless it is 1, and a
        // modulus of 1 makes every value zero anyway.
        let two = {
            let mut t = Secret::zero(k);
            t.limbs_mut()[0] = 2;
            t
        };
        let (n_minus_2, _) = n.sub(&two);

        Ok(Montgomery { n, k, n0inv, r2, r1, n_minus_2 })
    }

    pub fn limbs(&self) -> usize {
        self.k
    }

    /// The modulus this was built for.
    pub fn modulus(&self) -> &Secret {
        &self.n
    }

    /// The Montgomery product: `a * b * R^-1 mod n`.
    ///
    /// CIOS (Coarsely Integrated Operand Scanning): interleave the
    /// multiplication with the reduction so only one pass over the operands
    /// is needed and the intermediate never exceeds k+2 limbs.
    ///
    /// Correct whenever `a * b < n * R`, which is what lets `to_domain` hand
    /// it an arbitrary k-limb value against `r2 < n`.
    pub fn mul(&self, a: &Secret, b: &Secret) -> Secret {
        debug_assert_eq!(a.width(), self.k);
        debug_assert_eq!(b.width(), self.k);
        let mut t = vec![0u64; self.k + 2];
        let mut out = Secret::zero(self.k);
        self.mul_into(a.limbs(), b.limbs(), &mut t, out.limbs_mut());
        wipe(&mut t);
        out
    }

    /// The product of `mul`, into `out`, with `t` (`k + 2` limbs) as the
    /// scratch. No allocation, so a loop that holds its own buffers - the
    /// exponentiation below - makes none. `t` holds the full product on
    /// return; the caller wipes it when it is done.
    fn mul_into(&self, a: &[u64], b: &[u64], t: &mut [u64], out: &mut [u64]) {
        // The same kernel compiled per limb count: with the count a
        // constant the loops have known bounds, so the slice checks go and
        // the inner loops unroll. Every other width takes the generic copy.
        let n = self.n.limbs();
        match self.k {
            4 => cios(4, a, b, n, self.n0inv, t, out),
            6 => cios(6, a, b, n, self.n0inv, t, out),
            8 => cios(8, a, b, n, self.n0inv, t, out),
            16 => cios(16, a, b, n, self.n0inv, t, out),
            24 => cios(24, a, b, n, self.n0inv, t, out),
            32 => cios(32, a, b, n, self.n0inv, t, out),
            k => cios(k, a, b, n, self.n0inv, t, out),
        }
    }

    /// `a^2 * R^-1 mod n`.
    pub fn sqr(&self, a: &Secret) -> Secret {
        let mut wide = vec![0u64; 2 * self.k + 1];
        let mut out = Secret::zero(self.k);
        self.sqr_into(a.limbs(), &mut wide, out.limbs_mut());
        wipe(&mut wide);
        out
    }

    /// The square of `sqr`, into `out`, with `wide` (`2k + 1` limbs) as
    /// the scratch. The full square first, each cross product `a_i a_j`
    /// formed once and the sum doubled, then a separate Montgomery
    /// reduction: about `1.5 k^2` multiplications against CIOS's `2 k^2`.
    /// Exponentiation is almost all squarings, so this is most of its
    /// time. `wide` holds the square on return; the caller wipes it.
    fn sqr_into(&self, a: &[u64], wide: &mut [u64], out: &mut [u64]) {
        // Per limb count, as in `mul_into`.
        let n = self.n.limbs();
        match self.k {
            4 => square(4, a, n, self.n0inv, wide, out),
            6 => square(6, a, n, self.n0inv, wide, out),
            8 => square(8, a, n, self.n0inv, wide, out),
            16 => square(16, a, n, self.n0inv, wide, out),
            24 => square(24, a, n, self.n0inv, wide, out),
            32 => square(32, a, n, self.n0inv, wide, out),
            k => square(k, a, n, self.n0inv, wide, out),
        }
    }

    /// Subtract `n` from `t` when `t >= n`, where `t` may also carry an extra
    /// high limb from the reduction.
    ///
    /// The overflow limb is not a special case to branch on: a non-zero one
    /// means the value is certainly above `n`, so it simply forces the
    /// subtraction. The previous version wrote that as `if t[k] != 0`, which
    /// is a branch on a secret and was one of the things ctgrind found.
    fn conditional_subtract(&self, t: &mut Secret, overflow: u64) {
        let (diff, borrow) = t.sub(&self.n);
        // Take the difference when the subtraction did not go negative, or
        // when the value had an extra limb to begin with.
        let take_diff = ct::mask_is_zero(borrow) | ct::mask_is_nonzero(overflow);
        t.cond_assign(&diff, take_diff);
    }

    /// Montgomery reduction of a `2k` limb value: `x * R^-1 mod n`.
    ///
    /// The scratch is consumed and zeroed, because it held a secret.
    ///
    /// Correct for `x < n * R`, which is what the callers guarantee - in the
    /// RSA case `x < n = p*q` and the domain is `p`, so `x < p * R` follows
    /// from `q < R`.
    fn redc(&self, wide: &mut [u64]) -> (Secret, u64) {
        let k = self.k;
        debug_assert_eq!(wide.len(), 2 * k);
        let n = self.n.limbs();
        // Carries past the top of the window. One word is enough: the carry
        // produced at limb `i + k` is added in at limb `i + 1 + k` on the
        // next pass, which is exactly where the next one lands.
        let mut extra = 0u64;
        for i in 0..k {
            let m = wide[i].wrapping_mul(self.n0inv);
            let mut carry: u128 = 0;
            for j in 0..k {
                let sum = wide[i + j] as u128 + m as u128 * n[j] as u128 + carry;
                wide[i + j] = sum as u64;
                carry = sum >> 64;
            }
            debug_assert_eq!(wide[i], 0, "limb {} must cancel", i);
            let sum = wide[i + k] as u128 + carry + extra as u128;
            wide[i + k] = sum as u64;
            extra = (sum >> 64) as u64;
        }

        let mut out = Secret::zero(k);
        out.limbs_mut().copy_from_slice(&wide[k..]);
        for limb in wide.iter_mut() {
            unsafe { core::ptr::write_volatile(limb, 0) };
        }
        self.conditional_subtract(&mut out, extra);
        (out, extra)
    }

    /// `x mod n` for a `2k` limb `x`, without a division.
    ///
    /// `redc` gives `x * R^-1`; multiplying by `R^2` and reducing again puts
    /// the `R` back. Two passes instead of Knuth's loop, and neither of them
    /// looks at a value to decide what to do next.
    ///
    /// This is what replaced `c.rem(&p)` in the RSA CRT path, where the
    /// divisor was a secret prime.
    pub fn reduce_wide(&self, wide: &[u64]) -> Result<Secret, String> {
        if wide.len() != 2 * self.k {
            return Err(format!("reduce_wide wants {} limbs, got {}.",
                               2 * self.k, wide.len()));
        }
        let mut scratch = wide.to_vec();
        let (reduced, _) = self.redc(&mut scratch);
        Ok(self.mul(&reduced, &self.r2))
    }

    /// `(a * b) mod n` for values **outside** the domain, which is what a
    /// caller doing one multiplication rather than a chain of them wants.
    ///
    /// Only one conversion is needed, not two: `to_domain(a)` is `aR`, and
    /// `mul(aR, b)` is `aR * b * R^-1 = ab`.
    pub fn mul_mod(&self, a: &Secret, b: &Secret) -> Secret {
        self.mul(&self.to_domain(a), b)
    }

    /// One conditional subtraction of `n`, for a value known to be below
    /// `2n` - the sum of two reduced values, or a CRT recombination.
    ///
    /// `carry` is the bit that fell off the top of the addition, and is not a
    /// special case: a set carry means the value is certainly above `n`.
    pub fn reduce_once(&self, mut value: Secret, carry: u64) -> Secret {
        self.conditional_subtract(&mut value, carry);
        value
    }

    /// `(a + b) mod n`, for `a` and `b` already below `n`.
    pub fn add_mod(&self, a: &Secret, b: &Secret) -> Secret {
        let (mut sum, carry) = a.add(b);
        self.conditional_subtract(&mut sum, carry);
        sum
    }

    /// `(a - b) mod n`, for `a` and `b` already below `n`.
    pub fn sub_mod(&self, a: &Secret, b: &Secret) -> Secret {
        let (diff, borrow) = a.sub(b);
        // On a borrow the true answer is `diff + n`; the carry out of that
        // addition is the borrow coming back and is discarded.
        let (wrapped, _) = diff.add(&self.n);
        Secret::select(&wrapped, &diff, ct::mask_is_nonzero(borrow))
    }

    /// Enter the Montgomery domain: `a -> a*R mod n`.
    ///
    /// Takes any `k` limb value, including one at or above `n`, and reduces
    /// it on the way in. There is no division: `mul(a, r2)` computes
    /// `a * R^2 * R^-1 = a * R mod n`, and CIOS only needs `a * r2 < n * R`,
    /// which holds for every `a < R` because `r2 < n`.
    ///
    /// The previous version reduced with `a.rem(&modulus)` first, which was
    /// both a variable-time division on a possibly secret value and
    /// unnecessary.
    pub fn to_domain(&self, a: &Secret) -> Secret {
        self.mul(a, &self.r2)
    }

    /// Convenience for a value that is still a `BigUint`. The width check is
    /// the only thing that can fail.
    pub fn to_domain_biguint(&self, a: &BigUint) -> Result<Secret, String> {
        // A value wider than the modulus has to come down first, and that
        // needs division. The caller is handing us a `BigUint`, so it is
        // already public by this module's convention.
        let reduced = if a.limbs().len() > self.k {
            a.rem(&self.n.declassify())?
        } else {
            a.clone()
        };
        Ok(self.to_domain(&Secret::from_biguint(&reduced, self.k)?))
    }

    /// Leave the domain: `aR -> a`.
    pub fn from_domain(&self, a: &Secret) -> Secret {
        self.mul(a, &Secret::one(self.k))
    }

    /// The domain's representation of 1, which is `R mod n`. Precomputed.
    pub fn one_in_domain(&self) -> Secret {
        self.r1.clone()
    }

    /// `base^exp mod n`, square and multiply.
    ///
    /// Fast, and **variable time in the exponent**: the multiply is skipped
    /// on a zero bit, so the running time tracks the exponent's Hamming
    /// weight. Correct choice for public exponents - signature verification,
    /// the `e` in an RSA public key. Use [`Montgomery::pow_ct`] for secrets.
    pub fn pow(&self, base: &BigUint, exp: &BigUint) -> Result<BigUint, String> {
        if exp.is_zero() {
            return Ok(if self.n.declassify().is_one() { BigUint::zero() } else { BigUint::one() });
        }
        let base_m = self.to_domain_biguint(base)?;
        Ok(self.from_domain(&self.square_and_multiply(&base_m, exp)).declassify())
    }

    /// `base^exp mod n` for a **public exponent** and a base that is not.
    ///
    /// Square and multiply, so the operation count follows `exp` - which is
    /// fine when `exp` is the RSA public exponent, and the base is what must
    /// not leak. `pow` does the same thing but takes and returns `BigUint`,
    /// which normalises at both ends; this one keeps the value fixed width.
    ///
    /// The RSA Bellcore check is the caller this exists for: it raises the
    /// *plaintext* to the public exponent, and a fault check that leaks the
    /// value it is checking is a poor trade.
    pub fn pow_public(&self, base: &Secret, exp: &BigUint) -> Secret {
        if exp.is_zero() {
            return self.from_domain(&self.one_in_domain());
        }
        let base_m = self.to_domain(base);
        self.from_domain(&self.square_and_multiply(&base_m, exp))
    }

    /// `base^exp` in the domain, the multiplication skipped on a zero bit
    /// of the **public** exponent; the base may be secret. The buffers are
    /// allocated once for the whole exponentiation.
    fn square_and_multiply(&self, base: &Secret, exp: &BigUint) -> Secret {
        let k = self.k;
        let mut t = vec![0u64; k + 2];
        let mut wide = vec![0u64; 2 * k + 1];
        let mut acc = self.r1.limbs().to_vec();
        let mut product = vec![0u64; k];
        for i in (0..exp.bit_len()).rev() {
            self.sqr_into(&acc, &mut wide, &mut product);
            core::mem::swap(&mut acc, &mut product);
            if exp.bit(i) {
                self.mul_into(&acc, base.limbs(), &mut t, &mut product);
                core::mem::swap(&mut acc, &mut product);
            }
        }
        let result = Secret::from_limbs(acc.clone());
        for buffer in [&mut t, &mut wide, &mut acc, &mut product] {
            wipe(buffer);
        }
        result
    }

    /// `base^exp mod n` with a **caller supplied, public** count of
    /// exponent bits, in constant time.
    ///
    /// A fixed window of four bits: a table of `base^0 .. base^15`, then per
    /// window four squarings and one multiplication by the entry the
    /// window's bits select. The entry is read by touching all sixteen and
    /// keeping one with a mask, so neither the operation count nor the
    /// memory addresses depend on the exponent. That is 1.25
    /// multiplications per bit against the two of the Montgomery ladder
    /// this replaced, and the loop allocates nothing.
    ///
    /// `bits` is where an earlier version leaked. It used `exp.bit_len()`,
    /// which is a measurement of the secret: two private exponents of
    /// different lengths ran different numbers of iterations. It must be a
    /// public bound - the modulus's bit length, or the group order's - and
    /// bits above the exponent's real top are read as zero and cost a full
    /// iteration each. Bits at and above `bits` are not read at all.
    pub fn pow_ct(&self, base: &Secret, exp: &Secret, bits: usize) -> Secret {
        let k = self.k;
        let mut t = vec![0u64; k + 2];
        let mut wide = vec![0u64; 2 * k + 1];
        let mut table = vec![0u64; 16 * k];
        table[..k].copy_from_slice(self.r1.limbs());
        table[k..2 * k].copy_from_slice(self.to_domain(base).limbs());
        for i in 2..16 {
            let (done, rest) = table.split_at_mut(i * k);
            self.mul_into(&done[(i - 1) * k..], &done[k..2 * k], &mut t, &mut rest[..k]);
        }

        let mut acc = self.r1.limbs().to_vec();
        let mut product = vec![0u64; k];
        let mut entry = vec![0u64; k];
        for window in (0..bits.div_ceil(4)).rev() {
            for _ in 0..4 {
                self.sqr_into(&acc, &mut wide, &mut product);
                core::mem::swap(&mut acc, &mut product);
            }
            let mut index = 0u64;
            for j in 0..4 {
                let i = 4 * window + j;
                if i < bits {
                    index |= (exp.bit(i) & 1) << j;
                }
            }
            entry.fill(0);
            for (candidate, row) in (0u64..).zip(table.chunks_exact(k)) {
                let hit = ct::mask_is_zero(candidate ^ index);
                for (limb, &value) in entry.iter_mut().zip(row) {
                    *limb |= value & hit;
                }
            }
            self.mul_into(&acc, &entry, &mut t, &mut product);
            core::mem::swap(&mut acc, &mut product);
        }

        let result = self.from_domain(&Secret::from_limbs(acc.clone()));
        for buffer in [&mut t, &mut wide, &mut table, &mut acc, &mut product, &mut entry] {
            wipe(buffer);
        }
        result
    }

    /// `a^-1 mod n` for a **prime** `n`, by Fermat's little theorem:
    /// `a^(n-2) = a^-1` when `n` is prime and `a` is not a multiple of it.
    ///
    /// The extended Euclidean algorithm is the fast way and cannot be made
    /// constant time without replacing it wholesale (the "safegcd" approach);
    /// an exponentiation is a few hundred times the work and is already
    /// constant time. Every inverse this library takes of a secret is modulo
    /// a prime - the group order in ECDSA, the field characteristic in EC
    /// point arithmetic - so this covers them.
    ///
    /// **Primality is the caller's claim, not a check.** With a composite
    /// modulus this returns a value that is not an inverse, silently. It is
    /// named `inverse_prime` so the claim has to be made at the call site.
    ///
    /// Zero has no inverse and this returns zero for it, which is wrong in
    /// the same way `0^-1` is wrong; a caller who can be handed zero has to
    /// check for it, and `ct_is_zero` is there for that.
    pub fn inverse_prime(&self, a: &Secret, bits: usize) -> Secret {
        let exponent = self.n_minus_2.clone();
        self.pow_ct(a, &exponent, bits)
    }

    /// The bit length of the modulus, which is the natural public bound for
    /// `pow_ct` when the exponent is reduced modulo it.
    pub fn modulus_bits(&self) -> usize {
        self.k * 64
    }
}

impl core::fmt::Debug for Montgomery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Montgomery({} limbs)", self.k)
    }
}

/// CIOS for `mul_into`, with the limb count an argument so each caller
/// in `mul_into` gets a copy compiled for a constant one.
#[inline(always)]
fn cios(k: usize, a: &[u64], b: &[u64], n: &[u64], n0inv: u64, t: &mut [u64], out: &mut [u64]) {
    let (a, b, n, t, out) = (&a[..k], &b[..k], &n[..k], &mut t[..k + 2], &mut out[..k]);
    t.fill(0);
    for &b_i in &b[..k] {
        // t += a * b[i]
        let mut carry: u128 = 0;
        for j in 0..k {
            let sum = t[j] as u128 + a[j] as u128 * b_i as u128 + carry;
            t[j] = sum as u64;
            carry = sum >> 64;
        }
        let sum = t[k] as u128 + carry;
        t[k] = sum as u64;
        t[k + 1] = (sum >> 64) as u64;

        // m makes the low limb of t vanish, so the whole thing can shift
        // down by one limb, which is the division by R.
        let m = t[0].wrapping_mul(n0inv);

        let sum = t[0] as u128 + m as u128 * n[0] as u128;
        debug_assert_eq!(sum as u64, 0, "the low limb must cancel");
        let mut carry: u128 = sum >> 64;
        for j in 1..k {
            let sum = t[j] as u128 + m as u128 * n[j] as u128 + carry;
            t[j - 1] = sum as u64;
            carry = sum >> 64;
        }
        let sum = t[k] as u128 + carry;
        t[k - 1] = sum as u64;
        t[k] = t[k + 1] + (sum >> 64) as u64;
    }

    // The result so far is below 2n but may not be below n, and it may
    // have spilled into the extra limb. Subtract n into `out` and keep
    // the difference unless it borrowed with nothing spilled.
    let borrow = ct::sub_borrow(&t[..k], n, out);
    let take_difference = ct::mask_is_zero(borrow) | ct::mask_is_nonzero(t[k]);
    for (limb, &kept) in out.iter_mut().zip(&t[..k]) {
        *limb = ct::select(*limb, kept, take_difference);
    }
    
}

/// The squaring and reduction for `sqr_into`, compiled per limb count
/// the same way.
#[inline(always)]
fn square(k: usize, a: &[u64], n: &[u64], n0inv: u64, wide: &mut [u64], out: &mut [u64]) {
    let (a, n, wide, out) = (&a[..k], &n[..k], &mut wide[..2 * k + 1], &mut out[..k]);
    wide.fill(0);
    // The cross products, each once.
    for i in 0..k {
        let mut carry: u128 = 0;
        for j in i + 1..k {
            let sum = wide[i + j] as u128 + a[i] as u128 * a[j] as u128 + carry;
            wide[i + j] = sum as u64;
            carry = sum >> 64;
        }
        wide[i + k] = carry as u64;
    }
    // Doubled, by a one-bit shift across the 2k limbs.
    let mut top = 0u64;
    for limb in wide[..2 * k].iter_mut() {
        let next = *limb >> 63;
        *limb = (*limb << 1) | top;
        top = next;
    }
    // Plus the squares on the diagonal.
    let mut carry: u128 = 0;
    for i in 0..k {
        let square = a[i] as u128 * a[i] as u128;
        let low = wide[2 * i] as u128 + (square as u64) as u128 + carry;
        wide[2 * i] = low as u64;
        let high = wide[2 * i + 1] as u128 + (square >> 64) + (low >> 64);
        wide[2 * i + 1] = high as u64;
        carry = high >> 64;
    }

    // Montgomery reduction of the 2k limbs, word by word: each pass
    // clears the lowest remaining limb, and its carry runs into the
    // limb above the window, which the next pass then includes.
    let mut extra = 0u64;
    for i in 0..k {
        let m = wide[i].wrapping_mul(n0inv);
        let mut carry: u128 = 0;
        for j in 0..k {
            let sum = wide[i + j] as u128 + m as u128 * n[j] as u128 + carry;
            wide[i + j] = sum as u64;
            carry = sum >> 64;
        }
        let sum = wide[i + k] as u128 + carry + extra as u128;
        wide[i + k] = sum as u64;
        extra = (sum >> 64) as u64;
    }

    let borrow = ct::sub_borrow(&wide[k..2 * k], n, out);
    let take_difference = ct::mask_is_zero(borrow) | ct::mask_is_nonzero(extra);
    for (limb, &kept) in out.iter_mut().zip(&wide[k..2 * k]) {
        *limb = ct::select(*limb, kept, take_difference);
    }
    
}

/// Zero a buffer that held a secret, with stores the compiler may not
/// remove as dead.
fn wipe(buffer: &mut [u64]) {
    for limb in buffer.iter_mut() {
        unsafe { core::ptr::write_volatile(limb, 0) };
    }
}

/// True when the mask is set. **Only for a value that is not secret** - a
/// loop bound, a test assertion, an error path on public data. Converting a
/// mask to a `bool` is how a branch gets back in.
pub fn unmask(m: Mask) -> bool {
    m != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(hex: &str) -> BigUint {
        BigUint::from_hex(hex).unwrap()
    }

    fn secret(m: &Montgomery, hex: &str) -> Secret {
        Secret::from_biguint(&n(hex), m.limbs()).unwrap()
    }

    #[test]
    fn test_rejects_even_and_zero_modulus() {
        assert!(Montgomery::new(&n("10")).is_err(), "even modulus must be rejected");
        assert!(Montgomery::new(&BigUint::zero()).is_err());
        assert!(Montgomery::new(&n("f")).is_ok());
    }

    #[test]
    fn test_domain_roundtrip() {
        let m = Montgomery::new(&n("fffffffffffffffffffffffffffffffeffffffffffffffff")).unwrap();
        for v in ["0", "1", "2", "deadbeef", "fffffffffffffffffffffffffffffffefffffffffffffffe"] {
            let a = n(v);
            let there = m.to_domain_biguint(&a).unwrap();
            assert_eq!(m.from_domain(&there).declassify(), a, "roundtrip {}", v);
        }
    }

    /// `to_domain` no longer reduces its input with a division, so a value at
    /// or above the modulus has to come out right by the CIOS bound alone.
    /// This is the case the removed `widen` used to handle.
    #[test]
    fn test_to_domain_reduces_a_value_above_the_modulus() {
        let modulus = n("fffffffffffffffffffffffffffffffeffffffffffffffff");
        let m = Montgomery::new(&modulus).unwrap();
        // Every k-limb value, including the largest one, must land correctly.
        for v in ["ffffffffffffffffffffffffffffffffffffffffffffffff",
                  "fffffffffffffffffffffffffffffffeffffffffffffffff",
                  "ffffffffffffffffffffffffffffffff00000000000000000"] {
            let raw = n(v);
            if raw.limbs().len() > m.limbs() {
                continue;
            }
            let wide = Secret::from_biguint(&raw, m.limbs()).unwrap();
            let got = m.from_domain(&m.to_domain(&wide)).declassify();
            assert_eq!(got, raw.rem(&modulus).unwrap(), "to_domain({})", v);
        }
    }

    #[test]
    fn test_mul_matches_plain_modmul() {
        let modulus = n("fffffffffffffffffffffffffffffffeffffffffffffffff");
        let m = Montgomery::new(&modulus).unwrap();
        for (x, y) in [("2", "3"), ("deadbeef", "cafebabe"),
                       ("fffffffffffffffffffffffffffffffefffffffffffffffe", "2"),
                       ("123456789abcdef0123456789abcdef", "fedcba9876543210fedcba987654321")] {
            let (a, b) = (n(x), n(y));
            let got = m.from_domain(&m.mul(&m.to_domain_biguint(&a).unwrap(),
                                           &m.to_domain_biguint(&b).unwrap()));
            assert_eq!(got.declassify(), a.mod_mul(&b, &modulus).unwrap(), "{} * {}", x, y);
        }
    }

    /// The squaring is its own routine, so it is checked against the
    /// product, and against division, on every width from one limb to
    /// thirty-two - RSA-4096's halves - at the values whose cross products
    /// carry the most: n - 1 and all ones below it, as well as random ones.
    #[test]
    fn test_sqr_agrees_with_mul_and_with_division() {
        for limbs in [1usize, 2, 3, 4, 5, 8, 9, 16, 17, 32] {
            let mut modulus = n(&"f".repeat(16 * limbs));
            if limbs > 1 {
                let mut bytes = vec![0u8; 8 * limbs];
                crate::random::fill(&mut bytes).unwrap();
                bytes[0] |= 0x80;
                bytes[8 * limbs - 1] |= 1;
                modulus = BigUint::from_bytes_be(&bytes);
            }
            let m = Montgomery::new(&modulus).unwrap();
            let one = BigUint::one();
            let mut values = vec![modulus.sub(&one).unwrap(), BigUint::zero(), one.clone(),
                                  one.shl(64 * limbs - 1).sub(&one).unwrap().rem(&modulus).unwrap()];
            for _ in 0..8 {
                values.push(crate::random::below(&modulus).unwrap());
            }
            for value in values {
                let domain = m.to_domain_biguint(&value).unwrap();
                let squared = m.sqr(&domain);
                assert_eq!(m.from_domain(&squared).declassify(),
                           value.mod_mul(&value, &modulus).unwrap(), "{limbs} limbs");
                assert_eq!(squared.declassify(), m.mul(&domain, &domain).declassify());
            }
        }
    }

    /// `reduce_wide` has to agree with ordinary division on every shape of
    /// input, including one that is already reduced and one just below the
    /// `n*R` bound where the CIOS argument is tightest.
    #[test]
    fn test_reduce_wide_agrees_with_division() {
        for modulus_hex in ["fffffffffffffffffffffffffffffffeffffffffffffffff",
                            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43",
                            "fffffffffffffffd"] {
            let modulus = n(modulus_hex);
            let m = Montgomery::new(&modulus).unwrap();
            let k = m.limbs();
            for value_hex in ["0", "1", "2", "deadbeefcafebabe",
                              "123456789abcdef0123456789abcdef0123456789abcdef",
                              "fffffffffffffffffffffffffffffffefffffffffffffffe"] {
                let value = n(value_hex);
                // Skip anything at or above n*R, which is outside the
                // contract rather than a case to get right.
                let bound = modulus.shl(k * 64);
                if value >= bound {
                    continue;
                }
                let mut wide = value.limbs().to_vec();
                if wide.len() > 2 * k {
                    continue;
                }
                wide.resize(2 * k, 0);
                let got = m.reduce_wide(&wide).unwrap().declassify();
                assert_eq!(got, value.rem(&modulus).unwrap(),
                           "reduce_wide({}) mod {}", value_hex, modulus_hex);
            }
        }
    }

    /// The case the RSA CRT path actually hands it: a value just below a
    /// product of two primes, reduced modulo one of them.
    #[test]
    fn test_reduce_wide_on_a_crt_shaped_input() {
        let p = n("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43");
        let q = n("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeed");
        let product = p.mul(&q);
        let m = Montgomery::new(&p).unwrap();
        let k = m.limbs();
        // Something large and awkward below p*q.
        let value = product.sub(&n("1234567")).unwrap();
        let mut wide = value.limbs().to_vec();
        wide.resize(2 * k, 0);
        assert_eq!(m.reduce_wide(&wide).unwrap().declassify(),
                   value.rem(&p).unwrap());
    }

    #[test]
    fn test_mul_wide_matches_biguint() {
        for (x, y) in [("0", "0"), ("1", "1"), ("deadbeef", "cafebabe"),
                       ("ffffffffffffffff", "ffffffffffffffff"),
                       ("ffffffffffffffffffffffffffffffff",
                        "ffffffffffffffffffffffffffffffff")] {
            let (a, b) = (n(x), n(y));
            let k = 2;
            let (sa, sb) = (Secret::from_biguint(&a, k).unwrap(),
                            Secret::from_biguint(&b, k).unwrap());
            // A `Secret`, wiped on drop: the product of two secrets is one.
            let wide: Secret = sa.mul_wide(&sb);
            assert_eq!(wide.width(), 2 * k, "the width is fixed, not the value's");
            assert_eq!(BigUint::from_limbs(wide.limbs().to_vec()), a.mul(&b), "{} * {}", x, y);
        }
    }

    #[test]
    fn test_add_and_sub_mod() {
        let modulus = n("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43");
        let m = Montgomery::new(&modulus).unwrap();
        let cases = [("2", "3"), ("0", "0"),
                     ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff42", "1"),
                     ("1", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff42")];
        for (x, y) in cases {
            let (a, b) = (secret(&m, x), secret(&m, y));
            assert_eq!(m.add_mod(&a, &b).declassify(),
                       n(x).mod_add(&n(y), &modulus).unwrap(), "{} + {}", x, y);
            assert_eq!(m.sub_mod(&a, &b).declassify(),
                       n(x).mod_sub(&n(y), &modulus).unwrap(), "{} - {}", x, y);
        }
    }

    #[test]
    fn test_pow_matches_slow_path() {
        let modulus = n("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43");
        let m = Montgomery::new(&modulus).unwrap();
        for (b, e) in [("2", "10"), ("deadbeef", "10001"),
                       ("3", "0"), ("0", "5"), ("1", "ffffffff")] {
            let (base, exp) = (n(b), n(e));
            let want = base.mod_pow_schoolbook(&exp, &modulus).unwrap();
            assert_eq!(m.pow(&base, &exp).unwrap(), want, "pow {}^{}", b, e);
            let got = m.pow_ct(&secret(&m, b), &secret(&m, e), m.modulus_bits());
            assert_eq!(got.declassify(), want, "pow_ct {}^{}", b, e);
        }
    }

    /// The ladder and the fast path must agree for every exponent, including
    /// the all-ones and single-bit patterns where their control flow differs
    /// most.
    #[test]
    fn test_ladder_agrees_with_fast_path() {
        let modulus = n("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43");
        let m = Montgomery::new(&modulus).unwrap();
        let base = n("123456789abcdef");
        for e in ["1", "2", "3", "7", "8", "ff", "100", "101",
                  "ffffffffffffffff", "10000000000000000",
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
            let exp = n(e);
            let ladder = m.pow_ct(&secret(&m, "123456789abcdef"), &secret(&m, e), m.modulus_bits());
            assert_eq!(m.pow(&base, &exp).unwrap(), ladder.declassify(), "exponent {}", e);
        }
    }

    /// The loop bound is public and independent of the exponent, so running
    /// the *same* exponent with a larger bound must give the same answer.
    /// That is the property that replaced `bit_len()`, and it is what makes
    /// a short secret indistinguishable from a long one.
    #[test]
    fn test_extra_iterations_do_not_change_the_answer() {
        let modulus = n("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43");
        let m = Montgomery::new(&modulus).unwrap();
        let base = secret(&m, "123456789abcdef");
        let exp = secret(&m, "10001");
        let tight = m.pow_ct(&base, &exp, 17);
        for bits in [18, 64, 128, m.modulus_bits()] {
            assert_eq!(m.pow_ct(&base, &exp, bits).declassify(), tight.declassify(),
                       "bound {} must not change the result", bits);
        }
    }

    /// An exponent wider than the modulus.
    ///
    /// `BigUint::mod_pow_ct` briefly refused these, because it padded the
    /// exponent to the *modulus's* width and `from_biguint` errors rather
    /// than truncating. `pow_ct` never does arithmetic on the exponent - it
    /// only reads bits out of it - so there was no reason for the two widths
    /// to agree. `tools/src/bin/diff_bignum.rs` found it within a minute of the
    /// change, because its random moduli sometimes come out narrower than
    /// the bit size they were asked for while the exponent does not; no test
    /// in this file had the two widths differ.
    #[test]
    fn test_an_exponent_wider_than_the_modulus() {
        let modulus = n("fffffffffffffffd");
        let base = n("123456789");
        let exponent = n("fedcba9876543210fedcba9876543210");
        assert!(exponent.limbs().len() > modulus.limbs().len(), "the point of the test");
        assert_eq!(base.mod_pow_ct(&exponent, &modulus).unwrap(),
                   base.mod_pow_schoolbook(&exponent, &modulus).unwrap());
    }

    /// `pow_ct` reads exactly `bits` bits of the exponent: a bit at
    /// position `bits` or above changes nothing, whether or not `bits` is
    /// a multiple of the window's four.
    #[test]
    fn test_exponent_bits_at_and_above_the_bound_are_not_read() {
        let modulus = n("fffffffffffffffd");
        let m = Montgomery::new(&modulus).unwrap();
        let base = secret(&m, "123456789");
        for bits in [5usize, 8, 13, 64] {
            let low = BigUint::from_u64(0b10110).rem(&BigUint::one().shl(bits)).unwrap();
            for high in [bits, bits + 1, bits + 3] {
                let exponent = low.add(&BigUint::one().shl(high));
                let wide = Secret::from_biguint(&exponent, 2).unwrap();
                let narrow = Secret::from_biguint(&low, 2).unwrap();
                assert_eq!(m.pow_ct(&base, &wide, bits).declassify(),
                           m.pow_ct(&base, &narrow, bits).declassify(),
                           "bits {bits}, a bit at {high}");
            }
        }
    }

    #[test]
    fn test_inverse_prime() {
        // A prime modulus, so Fermat applies.
        let modulus = n("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43");
        let m = Montgomery::new(&modulus).unwrap();
        for v in ["2", "3", "deadbeef", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff42"] {
            let a = secret(&m, v);
            let inverse = m.inverse_prime(&a, m.modulus_bits());
            let product = n(v).mod_mul(&inverse.declassify(), &modulus).unwrap();
            assert!(product.is_one(), "{} * inverse != 1, got {}", v, product);
            // And it must agree with the variable-time version.
            assert_eq!(inverse.declassify(), n(v).mod_inverse(&modulus).unwrap(), "inverse of {}", v);
        }
    }

    /// A single limb modulus exercises the k=1 edge of CIOS, where the
    /// reduction loop body never runs.
    #[test]
    fn test_single_limb_modulus() {
        let modulus = n("fffffffffffffffd");
        let m = Montgomery::new(&modulus).unwrap();
        let a = n("123456789");
        let e = n("10001");
        assert_eq!(m.pow(&a, &e).unwrap(), a.mod_pow_schoolbook(&e, &modulus).unwrap());
        let ladder = m.pow_ct(&secret(&m, "123456789"), &secret(&m, "10001"), m.modulus_bits());
        assert_eq!(ladder.declassify(), a.mod_pow_schoolbook(&e, &modulus).unwrap());
    }

    #[test]
    fn test_unmask() {
        assert!(unmask(ct::TRUE));
        assert!(!unmask(ct::FALSE));
    }
}
