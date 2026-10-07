/*
Arbitrary precision unsigned integers.

Written from scratch rather than pulled in, so every bug here is ours to find.
The representation is a little endian vector of u64 limbs, normalised so the
most significant limb is never zero and zero is the empty vector. Intermediate
products use u128, which Rust gives us natively.

Correctness first, and **`BigUint` is not constant time** - not in any
particular function, but in its representation. It is normalised: the top
limb is never zero, so the limb count is a measurement of the value. Every
loop over `limbs` then runs a number of times that depends on it, `add`
decides whether to push a carry limb, and `normalise` pops zeros in a loop.
Under ctgrind, `a.add(&b)` reports before it reaches anything interesting.
`divrem`, `mod_inverse` and the comparison operators branch outright, and
`mod_pow` is square-and-multiply, so it leaks the exponent's Hamming weight.

That is the right trade for public values - verifying a signature, parsing a
certificate, checking a chain - which is most of what this library does.

For secrets there is `bignum::ct::Secret`: fixed width, never normalised, no
`Ord` or `PartialEq` so a comparison cannot compile, and `Montgomery` on top
of it for modular arithmetic. `rsa.rs`, `dh.rs` and the arithmetic half of
`ecdsa.rs` go through that path, and `scripts/ct_check.py` runs the whole
thing under valgrind to check that they still do.

The two entry points here that lead into it are `mod_pow_ct` and
`mod_inverse_prime`. Both return a `BigUint`, which normalises the result -
fine for a value about to be published, wrong for one that stays secret, and
the reason `dh.rs` calls `Montgomery::pow_ct` directly instead.
*/

pub mod ct;
pub(crate) mod fixed;
pub mod montgomery;
pub use ct::Secret;
pub use montgomery::Montgomery;

use core::cmp::Ordering;

/// Bits per limb.
const LIMB_BITS: usize = 64;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct BigUint {
    /// Little endian limbs, normalised: no trailing zero limb, empty is zero.
    limbs: Vec<u64>,
}

impl BigUint {
    // ------------------------------------------------------ construction ---

    pub fn zero() -> BigUint {
        BigUint { limbs: Vec::new() }
    }

    pub fn one() -> BigUint {
        BigUint { limbs: vec![1] }
    }

    pub fn from_u64(v: u64) -> BigUint {
        if v == 0 { BigUint::zero() } else { BigUint { limbs: vec![v] } }
    }

    /// From limbs in little endian order. Normalises.
    pub fn from_limbs(limbs: Vec<u64>) -> BigUint {
        let mut n = BigUint { limbs };
        n.normalise();
        n
    }

    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    /// Big endian bytes, which is how every crypto format on the wire stores
    /// integers. Leading zeros are ignored.
    pub fn from_bytes_be(bytes: &[u8]) -> BigUint {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        // Walk from the least significant end, eight bytes at a time.
        let mut i = bytes.len();
        while i > 0 {
            let start = i.saturating_sub(8);
            let n = i - start;
            let mut chunk = [0u8; 8];
            chunk[8 - n..].copy_from_slice(&bytes[start..i]);
            limbs.push(u64::from_be_bytes(chunk));
            i = start;
        }
        BigUint::from_limbs(limbs)
    }

    /// Big endian bytes, minimal length. Zero produces an empty slice, which
    /// is what most wire formats want; use `to_bytes_be_padded` for a fixed
    /// width field.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.limbs.len() * 8);
        for limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        // Trim the leading zeros introduced by the top limb.
        let first_nonzero = out.iter().position(|&b| b != 0).unwrap_or(out.len());
        out.drain(..first_nonzero);
        out
    }

    /// Big endian bytes, left padded with zeros to exactly `len` bytes.
    /// Errors if the value does not fit, rather than silently truncating.
    pub fn to_bytes_be_padded(&self, len: usize) -> Result<Vec<u8>, String> {
        let minimal = self.to_bytes_be();
        if minimal.len() > len {
            return Err(format!("Integer needs {} bytes, field is {}.", minimal.len(), len));
        }
        let mut out = vec![0u8; len - minimal.len()];
        out.extend_from_slice(&minimal);
        Ok(out)
    }

    pub fn from_hex(s: &str) -> Result<BigUint, String> {
        let s = s.trim().trim_start_matches("0x");
        if s.is_empty() {
            return Ok(BigUint::zero());
        }
        if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("Not a hex string: {:?}", s));
        }
        // Pad to an even number of digits so it maps onto whole bytes.
        let padded = if s.len() % 2 == 1 { format!("0{}", s) } else { s.to_string() };
        let bytes: Vec<u8> = (0..padded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).unwrap())
            .collect();
        Ok(BigUint::from_bytes_be(&bytes))
    }

    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let mut s = String::new();
        for (i, limb) in self.limbs.iter().enumerate().rev() {
            if i == self.limbs.len() - 1 {
                s.push_str(&format!("{:x}", limb));
            } else {
                s.push_str(&format!("{:016x}", limb));
            }
        }
        s
    }

    // ------------------------------------------------------- inspection ---

    fn normalise(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    pub fn is_even(&self) -> bool {
        self.limbs.first().is_none_or(|l| l & 1 == 0)
    }

    /// Position of the highest set bit, plus one. Zero has length 0.
    pub fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => self.limbs.len() * LIMB_BITS - top.leading_zeros() as usize,
        }
    }

    pub fn bit(&self, i: usize) -> bool {
        let limb = i / LIMB_BITS;
        if limb >= self.limbs.len() {
            return false;
        }
        (self.limbs[limb] >> (i % LIMB_BITS)) & 1 == 1
    }

    /// Fits in a u64?
    pub fn to_u64(&self) -> Option<u64> {
        match self.limbs.len() {
            0 => Some(0),
            1 => Some(self.limbs[0]),
            _ => None,
        }
    }

    // -------------------------------------------------------- arithmetic ---

    pub fn add(&self, other: &BigUint) -> BigUint {
        let n = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let a = *self.limbs.get(i).unwrap_or(&0) as u128;
            let b = *other.limbs.get(i).unwrap_or(&0) as u128;
            let sum = a + b + carry as u128;
            out.push(sum as u64);
            carry = (sum >> LIMB_BITS) as u64;
        }
        if carry != 0 {
            out.push(carry);
        }
        BigUint::from_limbs(out)
    }

    /// `self - other`, erroring rather than wrapping if it would go negative.
    /// Unsigned subtraction that silently wraps is a classic source of
    /// nonsense results, so it is a hard error here.
    pub fn sub(&self, other: &BigUint) -> Result<BigUint, String> {
        if self < other {
            return Err("Subtraction would be negative.".to_string());
        }
        Ok(self.sub_unchecked(other))
    }

    /// Caller must have checked `self >= other`.
    fn sub_unchecked(&self, other: &BigUint) -> BigUint {
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i128;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i128;
            let b = *other.limbs.get(i).unwrap_or(&0) as i128;
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1i128 << LIMB_BITS;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(diff as u64);
        }
        debug_assert_eq!(borrow, 0, "sub_unchecked called with self < other");
        BigUint::from_limbs(out)
    }

    pub fn mul(&self, other: &BigUint) -> BigUint {
        if self.is_zero() || other.is_zero() {
            return BigUint::zero();
        }
        // Schoolbook. O(n^2) is fine at the sizes we care about; Karatsuba
        // would be the next step if modexp turns out too slow.
        let mut out = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let t = a as u128 * b as u128 + out[i + j] as u128 + carry;
                out[i + j] = t as u64;
                carry = t >> LIMB_BITS;
            }
            let mut k = i + other.limbs.len();
            while carry != 0 {
                let t = out[k] as u128 + carry;
                out[k] = t as u64;
                carry = t >> LIMB_BITS;
                k += 1;
            }
        }
        BigUint::from_limbs(out)
    }

    pub fn shl(&self, bits: usize) -> BigUint {
        if self.is_zero() {
            return BigUint::zero();
        }
        let whole = bits / LIMB_BITS;
        let part = bits % LIMB_BITS;
        let mut out = vec![0u64; whole];
        if part == 0 {
            out.extend_from_slice(&self.limbs);
        } else {
            let mut carry = 0u64;
            for &limb in &self.limbs {
                out.push((limb << part) | carry);
                carry = limb >> (LIMB_BITS - part);
            }
            if carry != 0 {
                out.push(carry);
            }
        }
        BigUint::from_limbs(out)
    }

    pub fn shr(&self, bits: usize) -> BigUint {
        let whole = bits / LIMB_BITS;
        if whole >= self.limbs.len() {
            return BigUint::zero();
        }
        let part = bits % LIMB_BITS;
        let src = &self.limbs[whole..];
        let mut out = Vec::with_capacity(src.len());
        if part == 0 {
            out.extend_from_slice(src);
        } else {
            for i in 0..src.len() {
                let low = src[i] >> part;
                let high = src.get(i + 1).map_or(0, |&h| h << (LIMB_BITS - part));
                out.push(low | high);
            }
        }
        BigUint::from_limbs(out)
    }

    // ---------------------------------------------------------- division ---

    /// Divide by a single limb, returning (quotient, remainder).
    fn divrem_limb(&self, d: u64) -> (BigUint, u64) {
        debug_assert!(d != 0);
        let mut q = vec![0u64; self.limbs.len()];
        let mut rem = 0u128;
        for i in (0..self.limbs.len()).rev() {
            let cur = (rem << LIMB_BITS) | self.limbs[i] as u128;
            q[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        (BigUint::from_limbs(q), rem as u64)
    }

    /// Truncating division with remainder: `(self / other, self % other)`.
    ///
    /// Knuth's Algorithm D (TAOCP 4.2, section 4.3.1). The fiddly parts are
    /// the normalisation shift, which guarantees the top divisor limb has its
    /// high bit set so the quotient estimate is within one, and the "add back"
    /// correction for the rare case where the estimate is still one too big.
    pub fn divrem(&self, other: &BigUint) -> Result<(BigUint, BigUint), String> {
        if other.is_zero() {
            return Err("Division by zero.".to_string());
        }
        if self < other {
            return Ok((BigUint::zero(), self.clone()));
        }
        if other.limbs.len() == 1 {
            let (q, r) = self.divrem_limb(other.limbs[0]);
            return Ok((q, BigUint::from_u64(r)));
        }

        let n = other.limbs.len();
        let m = self.limbs.len() - n;

        // D1: normalise so the divisor's top bit is set.
        let shift = other.limbs[n - 1].leading_zeros() as usize;
        let v = other.shl(shift);
        let v = v.limbs;
        debug_assert_eq!(v.len(), n);

        let mut u = self.shl(shift).limbs;
        u.resize(self.limbs.len() + 1, 0); // room for the extra high limb

        let mut q = vec![0u64; m + 1];
        let base = 1u128 << LIMB_BITS;

        // D2..D7: one quotient limb per iteration, from the top down.
        for j in (0..=m).rev() {
            // D3: estimate q̂ from the top two limbs of the running remainder.
            let numerator = ((u[j + n] as u128) << LIMB_BITS) | u[j + n - 1] as u128;
            let mut qhat = numerator / v[n - 1] as u128;
            let mut rhat = numerator % v[n - 1] as u128;

            while qhat >= base
                || qhat * v[n - 2] as u128 > (rhat << LIMB_BITS) + u[j + n - 2] as u128
            {
                qhat -= 1;
                rhat += v[n - 1] as u128;
                if rhat >= base {
                    break;
                }
            }

            // D4: multiply and subtract.
            let mut borrow = 0i128;
            let mut carry = 0u128;
            for i in 0..n {
                let p = qhat * v[i] as u128 + carry;
                carry = p >> LIMB_BITS;
                let sub = u[i + j] as i128 - (p & (base - 1)) as i128 - borrow;
                if sub < 0 {
                    u[i + j] = (sub + base as i128) as u64;
                    borrow = 1;
                } else {
                    u[i + j] = sub as u64;
                    borrow = 0;
                }
            }
            let sub = u[j + n] as i128 - carry as i128 - borrow;
            if sub < 0 {
                u[j + n] = (sub + base as i128) as u64;
                borrow = 1;
            } else {
                u[j + n] = sub as u64;
                borrow = 0;
            }

            // D5/D6: the estimate was one too large, so add the divisor back.
            if borrow != 0 {
                qhat -= 1;
                let mut carry = 0u128;
                for i in 0..n {
                    let t = u[i + j] as u128 + v[i] as u128 + carry;
                    u[i + j] = t as u64;
                    carry = t >> LIMB_BITS;
                }
                u[j + n] = (u[j + n] as u128 + carry) as u64;
            }

            q[j] = qhat as u64;
        }

        // D8: undo the normalisation shift on the remainder.
        u.truncate(n);
        let rem = BigUint::from_limbs(u).shr(shift);
        Ok((BigUint::from_limbs(q), rem))
    }

    pub fn div(&self, other: &BigUint) -> Result<BigUint, String> {
        Ok(self.divrem(other)?.0)
    }

    pub fn rem(&self, other: &BigUint) -> Result<BigUint, String> {
        Ok(self.divrem(other)?.1)
    }

    // ------------------------------------------------------------ modular ---

    pub fn mod_add(&self, other: &BigUint, m: &BigUint) -> Result<BigUint, String> {
        self.add(other).rem(m)
    }

    /// `(self - other) mod m`, handling the wrap without going negative.
    pub fn mod_sub(&self, other: &BigUint, m: &BigUint) -> Result<BigUint, String> {
        let a = self.rem(m)?;
        let b = other.rem(m)?;
        if a >= b {
            Ok(a.sub_unchecked(&b))
        } else {
            Ok(a.add(m).sub_unchecked(&b))
        }
    }

    pub fn mod_mul(&self, other: &BigUint, m: &BigUint) -> Result<BigUint, String> {
        self.mul(other).rem(m)
    }

    /// `self^exp mod m`.
    ///
    /// Takes the Montgomery path when the modulus is odd, which is every
    /// modulus that matters in practice, and falls back to schoolbook
    /// square-and-multiply otherwise. Both are **variable time in the
    /// exponent** - the multiply is skipped on a zero bit. Fine for public
    /// exponents, NOT safe for private ones: use [`BigUint::mod_pow_ct`].
    /// See docs/pitfalls.md.
    pub fn mod_pow(&self, exp: &BigUint, m: &BigUint) -> Result<BigUint, String> {
        if m.is_zero() {
            return Err("Modulus is zero.".to_string());
        }
        if m.is_even() {
            return self.mod_pow_schoolbook(exp, m);
        }
        Montgomery::new(m)?.pow(self, exp)
    }

    /// `self^exp mod m` with the operation count independent of the
    /// exponent's value, for secret exponents. Requires an odd modulus,
    /// which every real one is.
    ///
    /// The loop runs for the **modulus's** bit width, not the exponent's, so
    /// a short secret costs the same as a long one and says nothing about
    /// which it was. Roughly twice the work of [`BigUint::mod_pow`], plus
    /// whatever the padding to a full width costs.
    ///
    /// The result comes back as a `BigUint`, which normalises it - see
    /// [`Secret::declassify`]. That is right for a value about to be
    /// published and wrong for one that stays secret; for key material go
    /// through [`Montgomery::pow_ct`] and [`Secret::to_bytes_be`] directly,
    /// which is what `dh.rs` does.
    pub fn mod_pow_ct(&self, exp: &BigUint, m: &BigUint) -> Result<BigUint, String> {
        let mont = Montgomery::new(m)?;
        let width = mont.limbs();
        // The base needs no reduction: `to_domain` takes any value of the
        // domain's width. Only an oversized one has to come down first, and
        // that division is on a value the caller made wider than the modulus.
        let base = if self.limbs().len() > width {
            Secret::from_biguint(&self.rem(m)?, width)?
        } else {
            Secret::from_biguint(self, width)?
        };
        // The exponent is *not* reduced - `a^(e mod m)` is not `a^e` - and it
        // does not have to share the modulus's width, because `pow_ct` only
        // ever reads bits out of it and never does arithmetic on it. So it
        // gets its own width, which is the modulus's unless the caller handed
        // us something larger.
        //
        // The loop bound follows that width rather than the exponent's bit
        // length, so two exponents of different lengths *within one width*
        // cost the same. A caller who hands in a secret exponent wider than
        // the modulus has already said so by the `BigUint`'s own length -
        // see the note on `Secret::declassify`.
        let exponent_width = width.max(exp.limbs().len());
        let exponent = Secret::from_biguint(exp, exponent_width)?;
        Ok(mont.pow_ct(&base, &exponent, exponent_width * 64).declassify())
    }

    /// The original schoolbook implementation. Kept because it works for
    /// even moduli, and because having a second independent implementation
    /// to differential test the Montgomery path against is worth more than
    /// the few lines it costs.
    pub fn mod_pow_schoolbook(&self, exp: &BigUint, m: &BigUint) -> Result<BigUint, String> {
        if m.is_zero() {
            return Err("Modulus is zero.".to_string());
        }
        if m.is_one() {
            return Ok(BigUint::zero());
        }
        let mut result = BigUint::one();
        let base = self.rem(m)?;
        if exp.is_zero() {
            return Ok(result);
        }
        for i in (0..exp.bit_len()).rev() {
            result = result.mod_mul(&result.clone(), m)?;
            if exp.bit(i) {
                result = result.mod_mul(&base, m)?;
            }
        }
        Ok(result)
    }

    /// `self^-1 mod p` for a **prime** `p`, in constant time.
    ///
    /// [`BigUint::mod_inverse`] is the extended Euclidean algorithm, whose
    /// iteration count is the continued-fraction expansion of its input -
    /// about as direct a readout of a secret as a side channel gets. It is
    /// the right choice for public values and wrong for the two places this
    /// library inverts a secret: the ECDSA nonce, and a point's Z coordinate
    /// during scalar multiplication. Both moduli are prime, so Fermat's
    /// little theorem gives the inverse as `a^(p-2)` and the whole thing is
    /// an exponentiation, which is already constant time.
    ///
    /// Two or three hundred times the work of Euclid. That is the price, and
    /// at one inversion per signature or per scalar multiplication it does
    /// not show.
    ///
    /// **`p` being prime is the caller's claim.** With a composite modulus
    /// this returns a value that is not an inverse and says nothing, which is
    /// why the name carries the condition. `mod_inverse` errors instead, and
    /// is the one to use when the modulus is not known to be prime.
    pub fn mod_inverse_prime(&self, p: &BigUint) -> Result<BigUint, String> {
        let mont = Montgomery::new(p)?;
        let width = mont.limbs();
        // No reduction unless the caller handed us something wider than the
        // modulus: `to_domain` reduces anything of the domain's own width,
        // and `rem` on a secret is the operation being avoided.
        let value = if self.limbs().len() > width {
            Secret::from_biguint(&self.rem(p)?, width)?
        } else {
            Secret::from_biguint(self, width)?
        };
        Ok(mont.inverse_prime(&value, mont.modulus_bits()).declassify())
    }

    pub fn gcd(&self, other: &BigUint) -> BigUint {
        let mut a = self.clone();
        let mut b = other.clone();
        while !b.is_zero() {
            let r = a.rem(&b).expect("b is non-zero inside the loop");
            a = b;
            b = r;
        }
        a
    }

    /// Modular inverse via the extended Euclidean algorithm.
    ///
    /// Returns an error when the inverse does not exist, i.e. when
    /// `gcd(self, m) != 1`. **Variable time**, in both operands.
    ///
    /// The coefficient of `self` alternates in sign from one step to the
    /// next - `0, 1, -q1, 1 + q1 q2, ...` - so only its magnitude is kept,
    /// and the next one is `|t| + q |new_t|`, an addition; the sign is the
    /// parity of the step. The magnitudes never exceed `m`. An earlier
    /// version reduced each coefficient modulo `m` with a multiplication
    /// and a division at every step, which made one 2048-bit inverse cost
    /// about a third of an RSA signature.
    pub fn mod_inverse(&self, m: &BigUint) -> Result<BigUint, String> {
        if m.is_zero() {
            return Err("Modulus is zero.".to_string());
        }
        if m.is_one() {
            return Ok(BigUint::zero());
        }
        if !m.is_even() {
            return self.rem(m)?.mod_inverse_odd(m);
        }
        // |t| and |new_t|, and whether new_t is negative.
        let mut t = BigUint::zero();
        let mut new_t = BigUint::one();
        let mut new_t_negative = false;
        let mut r = m.clone();
        let mut new_r = self.rem(m)?;

        while !new_r.is_zero() {
            let (q, rem) = r.divrem(&new_r)?;
            let next_t = t.add(&q.mul(&new_t));
            t = new_t;
            new_t = next_t;
            new_t_negative = !new_t_negative;
            r = new_r;
            new_r = rem;
        }

        if !r.is_one() {
            return Err("No modular inverse: the values are not coprime.".to_string());
        }
        // `t` is the coefficient that went with the final `r = 1`, and its
        // sign is the opposite of `new_t`'s.
        if new_t_negative || t.is_zero() {
            Ok(t)
        } else {
            m.sub(&t)
        }
    }

    /// `mod_inverse` for an odd `m` and `self < m`: the binary extended
    /// Euclidean algorithm, in place on arrays of `m`'s width. No division,
    /// no allocation inside the loop - halvings and subtractions, with the
    /// coefficients kept in `[0, m)`; halving an odd coefficient adds `m`
    /// first, which is why `m` must be odd. Variable time.
    ///
    /// Invariants: `x1 * self = u` and `x2 * self = v` modulo `m`, with
    /// `u, v` starting at `self, m`; they shrink to the gcd, and when one
    /// reaches 1 its coefficient is the inverse.
    fn mod_inverse_odd(&self, m: &BigUint) -> Result<BigUint, String> {
        let k = m.limbs.len();
        let widen = |x: &BigUint| {
            let mut out = x.limbs.clone();
            out.resize(k + 1, 0);
            out
        };
        let modulus = widen(m);
        let (mut u, mut v) = (widen(self), modulus.clone());
        let (mut x1, mut x2) = (widen(&BigUint::one()), vec![0u64; k + 1]);

        fn is_zero(a: &[u64]) -> bool { a.iter().all(|&l| l == 0) }
        fn is_one(a: &[u64]) -> bool { a[0] == 1 && a[1..].iter().all(|&l| l == 0) }
        fn halve(a: &mut [u64]) {
            let last = a.len() - 1;
            for i in 0..last {
                a[i] = (a[i] >> 1) | (a[i + 1] << 63);
            }
            a[last] >>= 1;
        }
        /// `a += b`, both `k + 1` limbs, no carry out (the values fit).
        fn add(a: &mut [u64], b: &[u64]) {
            let mut carry = 0u64;
            for (x, &y) in a.iter_mut().zip(b) {
                let (sum, c1) = x.overflowing_add(y);
                let (sum, c2) = sum.overflowing_add(carry);
                *x = sum;
                carry = (c1 | c2) as u64;
            }
        }
        /// `a -= b`, returning the borrow.
        fn sub(a: &mut [u64], b: &[u64]) -> bool {
            let mut borrow = false;
            for (x, &y) in a.iter_mut().zip(b) {
                let (diff, b1) = x.overflowing_sub(y);
                let (diff, b2) = diff.overflowing_sub(borrow as u64);
                *x = diff;
                borrow = b1 | b2;
            }
            borrow
        }
        fn at_least(a: &[u64], b: &[u64]) -> bool {
            for (x, y) in a.iter().rev().zip(b.iter().rev()) {
                if x != y {
                    return x > y;
                }
            }
            true
        }
        /// Halve a coefficient modulo `m`: add `m` first when it is odd.
        fn halve_mod(x: &mut [u64], m: &[u64]) {
            if x[0] & 1 == 1 {
                add(x, m);
            }
            halve(x);
        }

        if is_zero(&u) {
            return Err("No modular inverse: the values are not coprime.".to_string());
        }
        while !is_one(&u) && !is_one(&v) {
            while u[0] & 1 == 0 {
                halve(&mut u);
                halve_mod(&mut x1, &modulus);
            }
            while v[0] & 1 == 0 {
                halve(&mut v);
                halve_mod(&mut x2, &modulus);
            }
            if at_least(&u, &v) {
                sub(&mut u, &v);
                if sub(&mut x1, &x2) {
                    add(&mut x1, &modulus);
                }
                if is_zero(&u) {
                    // u = v: the gcd is v, which is not 1 here.
                    return Err("No modular inverse: the values are not coprime.".to_string());
                }
            } else {
                sub(&mut v, &u);
                if sub(&mut x2, &x1) {
                    add(&mut x2, &modulus);
                }
            }
        }
        Ok(BigUint::from_limbs(if is_one(&u) { x1 } else { x2 }))
    }
}

// --------------------------------------------------------------- ordering ---

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        // Normalised, so limb count orders first.
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
        for i in (0..self.limbs.len()).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl core::fmt::Display for BigUint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(hex: &str) -> BigUint {
        BigUint::from_hex(hex).unwrap()
    }

    #[test]
    fn test_roundtrip_hex_and_bytes() {
        for s in ["0", "1", "ff", "100", "ffffffffffffffff", "10000000000000000",
                  "deadbeefdeadbeefdeadbeefdeadbeef",
                  "fedcba98765432100123456789abcdef0011223344556677"] {
            let v = n(s);
            let expected = s.trim_start_matches('0');
            let expected = if expected.is_empty() { "0" } else { expected };
            assert_eq!(v.to_hex(), expected, "hex roundtrip {}", s);
            assert_eq!(BigUint::from_bytes_be(&v.to_bytes_be()), v, "bytes roundtrip {}", s);
        }
        assert_eq!(BigUint::zero().to_bytes_be(), Vec::<u8>::new());
        // leading zeros on input must not change the value
        assert_eq!(BigUint::from_bytes_be(&[0, 0, 1]), BigUint::one());
    }

    #[test]
    fn test_padded_bytes() {
        let v = n("0102");
        assert_eq!(v.to_bytes_be_padded(4).unwrap(), vec![0, 0, 1, 2]);
        assert_eq!(v.to_bytes_be_padded(2).unwrap(), vec![1, 2]);
        assert!(v.to_bytes_be_padded(1).is_err(), "must not silently truncate");
        assert_eq!(BigUint::zero().to_bytes_be_padded(3).unwrap(), vec![0, 0, 0]);
    }

    #[test]
    fn test_add_sub_carry_chains() {
        let max = n("ffffffffffffffff");
        assert_eq!(max.add(&BigUint::one()).to_hex(), "10000000000000000");
        let two_limbs = n("ffffffffffffffffffffffffffffffff");
        assert_eq!(two_limbs.add(&BigUint::one()).to_hex(), "100000000000000000000000000000000");
        assert_eq!(two_limbs.add(&BigUint::one()).sub(&BigUint::one()).unwrap(), two_limbs);
        assert!(BigUint::one().sub(&n("2")).is_err(), "must not wrap");
        assert!(BigUint::zero().sub(&BigUint::zero()).unwrap().is_zero());
    }

    #[test]
    fn test_shifts() {
        let v = n("1");
        assert_eq!(v.shl(64).to_hex(), "10000000000000000");
        assert_eq!(v.shl(65).to_hex(), "20000000000000000");
        assert_eq!(v.shl(64).shr(64), v);
        assert_eq!(v.shl(200).shr(200), v);
        assert!(v.shr(1).is_zero());
        assert!(BigUint::zero().shl(100).is_zero());
        // shifting by a whole number of limbs and by a partial amount agree
        let x = n("123456789abcdef0fedcba9876543210");
        assert_eq!(x.shl(64).shr(64), x);
        assert_eq!(x.shl(7).shr(7), x);
    }

    #[test]
    fn test_divrem_add_back_path() {
        // The "add back" correction in Algorithm D is rare; this pattern is
        // the classic one that triggers it.
        let a = n("7fffffffffffffff0000000000000000");
        let b = n("800000000000000000000000ffffffff");
        let (q, r) = a.divrem(&b).unwrap();
        assert_eq!(q.mul(&b).add(&r), a, "q*b + r must reconstruct a");
        assert!(r < b);
    }

    #[test]
    fn test_mod_inverse() {
        // 3 * 5 = 15 = 1 mod 7
        assert_eq!(n("3").mod_inverse(&n("7")).unwrap(), n("5"));
        // no inverse when not coprime
        assert!(n("4").mod_inverse(&n("8")).is_err());
        // a * a^-1 == 1 for a larger modulus
        let m = n("fffffffffffffffffffffffffffffffeffffffffffffffff");
        let a = n("123456789abcdef0123456789abcdef0123456789abcdef");
        let inv = a.mod_inverse(&m).unwrap();
        assert!(a.mod_mul(&inv, &m).unwrap().is_one());
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(n("2").mod_pow(&n("10"), &n("3e8")).unwrap(), n("218"));  // 2^16 mod 0x3e8 = 0x218
        assert!(n("5").mod_pow(&BigUint::zero(), &n("7")).unwrap().is_one());
        assert!(n("5").mod_pow(&n("3"), &BigUint::one()).unwrap().is_zero());
        // Fermat: a^(p-1) == 1 mod p for prime p. This one is 2^256 - 189;
        // the first constant tried here was 2^256 - 159, which is composite,
        // and the test correctly refused to pass.
        let p = n("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43");
        let a = n("deadbeef");
        let e = p.sub(&BigUint::one()).unwrap();
        assert!(a.mod_pow(&e, &p).unwrap().is_one());
    }

    #[test]
    fn test_division_by_zero_errors() {
        assert!(BigUint::one().divrem(&BigUint::zero()).is_err());
        assert!(BigUint::one().mod_pow(&BigUint::one(), &BigUint::zero()).is_err());
    }
}

/// Values tests across the crate compute rather than copy.
#[cfg(test)]
pub(crate) mod test_support {
    use super::BigUint;

    /// `arctan(1/x)` scaled by `one`, its positive and negative terms
    /// summed apart so nothing goes below zero.
    fn arctan_inverse(x: u64, one: &BigUint) -> BigUint {
        let x_squared = BigUint::from_u64(x * x);
        let mut power = one.div(&BigUint::from_u64(x)).unwrap();
        let (mut plus, mut minus) = (BigUint::zero(), BigUint::zero());
        let mut n = 1u64;
        while !power.is_zero() {
            let term = power.div(&BigUint::from_u64(n)).unwrap();
            if n % 4 == 1 { plus = plus.add(&term) } else { minus = minus.add(&term) }
            power = power.div(&x_squared).unwrap();
            n += 2;
        }
        plus.sub(&minus).unwrap()
    }

    /// `floor(pi * 2^bits)`, by Machin's formula
    /// `pi = 16 atan(1/5) - 4 atan(1/239)`, with 64 guard bits to absorb
    /// the series' truncations. Blowfish's tables and the MODP primes are
    /// both made from these digits, and both are checked against them.
    pub(crate) fn pi_scaled(bits: usize) -> BigUint {
        let one = BigUint::one().shl(bits + 64);
        arctan_inverse(5, &one).mul(&BigUint::from_u64(16))
            .sub(&arctan_inverse(239, &one).mul(&BigUint::from_u64(4))).unwrap()
            .shr(64)
    }
}
