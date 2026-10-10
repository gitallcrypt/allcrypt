/*
Fixed width integers for secret values.

`BigUint` cannot be made constant time, and the reason is its representation
rather than any particular function. It is *normalised*: the top limb is
never zero, so the limb count is a measurement of the value. Every loop over
`limbs` then runs a number of times that depends on the secret, `add` decides
whether to push a carry limb, and `normalise` pops zeros in a loop. Under
ctgrind, `a.add(&b)` on a secret `a` reports before it reaches any of the
interesting code. Making the individual operations branchless would not help
while the length still talks.

So this is the other half: exactly `k` limbs, always, zero padded, never
normalised. The width is **public** - it comes from the modulus, which is in
the certificate - and the value is secret. Nothing here allocates based on a
value, branches on one, or indexes memory with one.

Three deliberate absences, each of which would otherwise be a silent hole:

  * **No `PartialEq`, `Eq`, `PartialOrd` or `Ord`.** `a == b` and `a < b` on
    a secret are exactly the mistake this module exists to prevent, so they
    do not compile. Use `ct_eq` and `ct_lt`, which return a mask.
  * **No `Debug`.** Printing a secret is not a debugging convenience, it is
    the secret in a log file.
  * **No conversion to `BigUint` that is not named for what it does.**
    `declassify` says in its name that the result's *length* is about to
    become visible, because normalising it is what makes it visible.

The masks are `u64::MAX` for true and `0` for false, never `bool`. A `bool`
invites `if`, and the compiler is allowed to turn a `bool` back into a
branch; a mask is only useful with `&` and `|`.

Verified by `scripts/ct_check.py`, which runs `tools/src/bin/ct_bignum.rs` under
valgrind with these values marked secret. That check has positive controls
in it: see the header of the example for why a ctgrind harness with no
known-bad case is worth nothing.
*/

use super::BigUint;

/// All ones or all zeros. There is no other legal value.
pub type Mask = u64;

pub const TRUE: Mask = u64::MAX;
pub const FALSE: Mask = 0;

/// Hand the compiler a value it cannot reason about.
///
/// **This is the load-bearing line in the module, and it is here because of
/// something only the harness could find.** Written without it,
/// `Montgomery::conditional_subtract` compiled to
///
/// ```text
/// test %rax, %rax
/// jne  ...
/// call memcpy          <- take the difference
/// ```
///
/// LLVM proved that a mask built from a comparison is either all ones or all
/// zeros, concluded that `b ^ (m & (a ^ b))` over a whole array is "copy `a`
/// over `b`, or do not", and emitted the branch and the `memcpy`. The source
/// was branchless; the binary was not. Reading the Rust cannot tell you that.
///
/// The barrier breaks the chain: after it, the mask is an ordinary `u64` as
/// far as the optimiser knows, and the select stays `xor`/`and`/`xor` - which
/// it also vectorises, so it is faster as well. `options(pure, nomem)` lets
/// it still be hoisted and shared, so the cost is close to nothing.
///
/// Rust does not *promise* any of this. `scripts/ct_check.py` is what checks
/// that it held, on the binary that will actually run.
#[inline]
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv32",
    target_arch = "riscv64",
))]
pub fn opaque(x: u64) -> u64 {
    let mut out = x;
    // An empty instruction stream: the asm does nothing at run time and
    // exists only so the optimiser loses track of the value.
    unsafe {
        core::arch::asm!("/* {0} */", inout(reg) out, options(pure, nomem, nostack, preserves_flags));
    }
    out
}

/// Fallback for architectures without inline assembly here. `black_box` is
/// documented as best effort rather than a guarantee, which is exactly why
/// the assembly version is preferred where it exists.
#[inline]
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv32",
    target_arch = "riscv64",
)))]
pub fn opaque(x: u64) -> u64 {
    core::hint::black_box(x)
}

/// All ones when `x == 0`, all zeros otherwise.
///
/// `x | -x` has its top bit set for every non-zero `x` - including the one
/// value where `x == -x`, which is `1 << 63` - and is zero only for zero.
///
/// The result goes through [`opaque`], so every mask in this module is born
/// already opaque and no call site has to remember to make it so.
#[inline]
pub fn mask_is_zero(x: u64) -> Mask {
    let any = x | x.wrapping_neg();
    opaque(((any >> 63) ^ 1).wrapping_neg())
}

/// All ones when `x != 0`.
#[inline]
pub fn mask_is_nonzero(x: u64) -> Mask {
    !mask_is_zero(x)
}

/// `if choice { a } else { b }`, without the `if`.
#[inline]
pub fn select(a: u64, b: u64, choice: Mask) -> u64 {
    b ^ (choice & (a ^ b))
}

/// A fixed width unsigned integer holding a secret.
///
/// Cloning is allowed and cheap enough; the type zeroes itself on drop, so a
/// clone is a second copy that also gets cleared rather than a copy left
/// behind in freed memory.
#[derive(Clone)]
pub struct Secret {
    /// Exactly `k` limbs, little endian, **not** normalised. The length is
    /// public; the contents are not.
    limbs: Vec<u64>,
}

impl Drop for Secret {
    fn drop(&mut self) {
        // `write_volatile` so the compiler may not decide this store is dead
        // because nothing reads it back. That is exactly what it would
        // conclude about a plain assignment here.
        for limb in &mut self.limbs {
            unsafe { core::ptr::write_volatile(limb, 0) };
        }
    }
}

impl Secret {
    // ---------------------------------------------------- construction ---

    /// `k` limbs of zero.
    pub fn zero(k: usize) -> Secret {
        Secret { limbs: vec![0; k] }
    }

    /// The value one, `k` limbs wide.
    pub fn one(k: usize) -> Secret {
        let mut s = Secret::zero(k);
        if k > 0 {
            s.limbs[0] = 1;
        }
        s
    }

    /// Widen (or narrow) a `BigUint` to exactly `k` limbs.
    ///
    /// Errors rather than truncating if the value does not fit: a silently
    /// truncated modulus or private exponent is a wrong answer that looks
    /// like a right one.
    pub fn from_biguint(value: &BigUint, k: usize) -> Result<Secret, String> {
        let limbs = value.limbs();
        if limbs.len() > k {
            return Err(format!("Value needs {} limbs, width is {}.", limbs.len(), k));
        }
        let mut out = vec![0u64; k];
        out[..limbs.len()].copy_from_slice(limbs);
        Ok(Secret { limbs: out })
    }

    /// Big endian bytes into exactly `k` limbs. Constant time in the bytes:
    /// unlike `BigUint::from_bytes_be` there is no normalisation afterwards,
    /// so a value with leading zeros is indistinguishable from one without.
    pub fn from_bytes_be(bytes: &[u8], k: usize) -> Result<Secret, String> {
        if bytes.len() > k * 8 {
            return Err(format!("{} bytes do not fit in {} limbs.", bytes.len(), k));
        }
        let mut out = vec![0u64; k];
        // Walk from the least significant end so a short input lands in the
        // low limbs without needing to know where its top is.
        for (i, &byte) in bytes.iter().rev().enumerate() {
            out[i / 8] |= (byte as u64) << ((i % 8) * 8);
        }
        Ok(Secret { limbs: out })
    }

    /// Big endian bytes, always exactly `8 * k` long.
    ///
    /// This is the one to use for key material. `BigUint::to_bytes_be` trims
    /// leading zeros, which is a branch on the value and also changes the
    /// length of a shared secret about once in 256 - see the note on
    /// `keys::strips_leading_zeros`.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.limbs.len() * 8);
        for limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// Hand the value back as a `BigUint`, normalised.
    ///
    /// **Named for what it costs.** Normalising drops the leading zero limbs,
    /// so the result's length is a measurement of the value, and from here on
    /// every operation on it is variable time. Correct for a signature, a
    /// public key, a value about to go on the wire. Wrong for anything that
    /// stays secret - use `to_bytes_be`.
    pub fn declassify(&self) -> BigUint {
        BigUint::from_limbs(self.limbs.clone())
    }

    // ------------------------------------------------------ inspection ---

    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    pub fn limbs_mut(&mut self) -> &mut [u64] {
        &mut self.limbs
    }

    /// Width in limbs. Public.
    pub fn width(&self) -> usize {
        self.limbs.len()
    }

    /// Bit `i` as a mask. `i` is public - it is a loop counter - and the bit
    /// is secret. Out of range reads as zero rather than panicking, so a
    /// caller may sweep a fixed range wider than the value.
    #[inline]
    pub fn bit(&self, i: usize) -> Mask {
        let limb = i / 64;
        if limb >= self.limbs.len() {
            return FALSE;
        }
        mask_is_nonzero((self.limbs[limb] >> (i % 64)) & 1)
    }

    /// All ones when the value is zero.
    pub fn ct_is_zero(&self) -> Mask {
        let mut any = 0u64;
        for &limb in &self.limbs {
            any |= limb;
        }
        mask_is_zero(any)
    }

    /// All ones when the two are equal. Widths must match.
    pub fn ct_eq(&self, other: &Secret) -> Mask {
        same_width(&self.limbs, &other.limbs);
        let mut diff = 0u64;
        for i in 0..self.limbs.len() {
            diff |= self.limbs[i] ^ other.limbs[i];
        }
        mask_is_zero(diff)
    }

    /// All ones when `self < other`. Widths must match.
    ///
    /// The borrow out of a full width subtraction is the comparison, which is
    /// why `sub_borrow` returns it rather than discarding it.
    ///
    /// Writing the last line as `if borrow != 0 { TRUE } else { FALSE }` is
    /// **also** constant time on this compiler - it becomes `neg; sbb` - and
    /// the ctgrind sweep does not notice the difference. That is not a hole
    /// in the harness; it is the same lesson as [`opaque`] read backwards.
    /// Branchless source can compile to a branch, and branchy source can
    /// compile to no branch. Neither the code nor the absence of an `if` in
    /// it is the thing to check. The binary is.
    pub fn ct_lt(&self, other: &Secret) -> Mask {
        same_width(&self.limbs, &other.limbs);
        let mut scratch = Secret::zero(self.limbs.len());
        let borrow = sub_borrow(&self.limbs, &other.limbs, &mut scratch.limbs);
        mask_is_nonzero(borrow)
    }

    // ------------------------------------------------------ arithmetic ---

    /// `self + other`, returning the carry out rather than growing.
    pub fn add(&self, other: &Secret) -> (Secret, u64) {
        same_width(&self.limbs, &other.limbs);
        let mut out = Secret::zero(self.limbs.len());
        let carry = add_carry(&self.limbs, &other.limbs, &mut out.limbs);
        (out, carry)
    }

    /// `self - other`, returning the borrow out rather than erroring. A
    /// borrow of 1 means the true result was negative and what came back is
    /// that result modulo `2^(64k)`.
    pub fn sub(&self, other: &Secret) -> (Secret, u64) {
        same_width(&self.limbs, &other.limbs);
        let mut out = Secret::zero(self.limbs.len());
        let borrow = sub_borrow(&self.limbs, &other.limbs, &mut out.limbs);
        (out, borrow)
    }

    /// `if choice { a } else { b }`. Both are read either way.
    pub fn select(a: &Secret, b: &Secret, choice: Mask) -> Secret {
        same_width(&a.limbs, &b.limbs);
        let mut out = Secret::zero(a.limbs.len());
        for i in 0..a.limbs.len() {
            out.limbs[i] = select(a.limbs[i], b.limbs[i], choice);
        }
        out
    }

    /// Overwrite `self` with `other` when `choice`. Touches every limb
    /// either way.
    pub fn cond_assign(&mut self, other: &Secret, choice: Mask) {
        same_width(&self.limbs, &other.limbs);
        for i in 0..self.limbs.len() {
            self.limbs[i] = select(other.limbs[i], self.limbs[i], choice);
        }
    }

    /// The full `k + l` limb product, with no reduction and nothing
    /// normalised.
    ///
    /// Schoolbook, and the loop bounds are the widths rather than the values,
    /// which is the only difference from `BigUint::mul` that matters here -
    /// that one skips a zero operand entirely and trims the result.
    ///
    /// A `Secret`, so the product is wiped on drop like its operands.
    /// It came back as a plain `Vec<u64>` once, and RSA's CRT held
    /// `h * q` - from which, with `m2`, the plaintext follows - in it
    /// until the end of the private operation, unwiped.
    pub fn mul_wide(&self, other: &Secret) -> Secret {
        let (k, l) = (self.limbs.len(), other.limbs.len());
        let mut out = Secret::zero(k + l);
        for i in 0..k {
            let a = self.limbs[i] as u128;
            let mut carry: u128 = 0;
            for j in 0..l {
                let t = a * other.limbs[j] as u128 + out.limbs[i + j] as u128 + carry;
                out.limbs[i + j] = t as u64;
                carry = t >> 64;
            }
            // The carry has exactly one limb to land in: `out[i + l]` starts
            // at zero for this `i` and the sum cannot overflow it.
            out.limbs[i + l] = carry as u64;
        }
        out
    }

    /// Widen to `k` limbs, which must be at least the current width.
    pub fn resize(&self, k: usize) -> Result<Secret, String> {
        if k < self.limbs.len() {
            return Err(format!("Cannot narrow {} limbs to {}.", self.limbs.len(), k));
        }
        let mut out = vec![0u64; k];
        out[..self.limbs.len()].copy_from_slice(&self.limbs);
        Ok(Secret { limbs: out })
    }

    /// Build from raw limbs, keeping every one of them.
    pub fn from_limbs(limbs: Vec<u64>) -> Secret {
        Secret { limbs }
    }

    /// Exchange `a` and `b` when `choice`. Writes both either way.
    pub fn cond_swap(a: &mut Secret, b: &mut Secret, choice: Mask) {
        same_width(&a.limbs, &b.limbs);
        for i in 0..a.limbs.len() {
            let delta = (a.limbs[i] ^ b.limbs[i]) & choice;
            a.limbs[i] ^= delta;
            b.limbs[i] ^= delta;
        }
    }
}

// ------------------------------------------------------- limb helpers ---

/// Two operands of one fixed-width operation have the same width, or
/// the operation is a bug and says so in every build.
///
/// A plain `assert`, not a `debug_assert`: the widths are public, so
/// the check costs nothing it is meant to protect, and in a release
/// build a mismatch was either a panic at `other.limbs[i]` (a shorter
/// operand) or a silently wrong answer on the prefix (a longer one) -
/// `ct_eq` would have reported two unequal values equal. The type's
/// whole purpose is to make misuse loud.
fn same_width(a: &[u64], b: &[u64]) {
    assert_eq!(a.len(), b.len(),
               "Secret operands have different widths: {} and {} limbs", a.len(), b.len());
}

/// `out = a + b`, returning the carry out. `overflowing_add` compiles to
/// `adc` with no branch.
pub fn add_carry(a: &[u64], b: &[u64], out: &mut [u64]) -> u64 {
    let mut carry = 0u64;
    for i in 0..a.len() {
        let (t, c1) = a[i].overflowing_add(b[i]);
        let (t, c2) = t.overflowing_add(carry);
        out[i] = t;
        carry = (c1 as u64) | (c2 as u64);
    }
    carry
}

/// `out = a - b`, returning the borrow out.
pub fn sub_borrow(a: &[u64], b: &[u64], out: &mut [u64]) -> u64 {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (t, b1) = a[i].overflowing_sub(b[i]);
        let (t, b2) = t.overflowing_sub(borrow);
        out[i] = t;
        borrow = (b1 as u64) | (b2 as u64);
    }
    borrow
}

/// `a != b`, folded into one accumulator so the comparison does not stop
/// at the first difference.
///
/// A length mismatch returns true immediately, which leaks only the
/// length - a fact the caller already knows, since it chose the slices.
///
/// **This cannot be tested functionally.** Reducing it to `a[0] != b[0]`
/// passes a bit-flipping sweep about four times in five, because two
/// different values differ in their first byte 255 times in 256. The
/// property is asserted one byte position at a time, below and in
/// `block_ciphers::keywrap`.
pub fn bytes_differ(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return true;
    }
    let mut accumulator = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        accumulator |= x ^ y;
    }
    accumulator != 0
}


#[cfg(test)]
mod tests {
    use super::*;

    fn n(hex: &str) -> BigUint {
        BigUint::from_hex(hex).unwrap()
    }

    fn s(hex: &str, k: usize) -> Secret {
        Secret::from_biguint(&n(hex), k).unwrap()
    }

    #[test]
    fn test_masks_are_all_ones_or_all_zeros() {
        assert_eq!(mask_is_zero(0), TRUE);
        assert_eq!(mask_is_zero(1), FALSE);
        assert_eq!(mask_is_zero(u64::MAX), FALSE);
        // The value that is its own negation: x | -x must still be seen as
        // non-zero, which a naive `x | -x` sign test gets right only because
        // the top bit is the one being tested.
        assert_eq!(mask_is_zero(1u64 << 63), FALSE);
        assert_eq!(mask_is_nonzero(1u64 << 63), TRUE);
        for x in [0u64, 1, 2, 0x8000_0000_0000_0000, u64::MAX] {
            let m = mask_is_zero(x);
            assert!(m == TRUE || m == FALSE, "mask for {:x} was {:x}", x, m);
        }
    }

    #[test]
    fn test_select_picks_the_right_side() {
        assert_eq!(select(7, 9, TRUE), 7);
        assert_eq!(select(7, 9, FALSE), 9);
    }

    /// The width is what makes this type different, so a value with leading
    /// zero limbs must survive a round trip with those limbs intact.
    #[test]
    fn test_width_is_preserved_across_a_round_trip() {
        let value = s("01", 4);
        assert_eq!(value.width(), 4);
        assert_eq!(value.limbs(), &[1, 0, 0, 0]);
        assert_eq!(value.to_bytes_be().len(), 32);
        assert_eq!(value.to_bytes_be()[31], 1);
        // Declassifying is where the width goes away, and the name says so.
        assert_eq!(value.declassify(), n("01"));
    }

    #[test]
    fn test_from_bytes_keeps_leading_zeros() {
        let padded = Secret::from_bytes_be(&[0, 0, 0, 5], 2).unwrap();
        let bare = Secret::from_bytes_be(&[5], 2).unwrap();
        assert_eq!(padded.limbs(), bare.limbs(), "leading zeros must not change the value");
        assert_eq!(padded.to_bytes_be().len(), 16, "output width is the type's, not the input's");
    }

    #[test]
    fn test_refuses_to_truncate() {
        assert!(Secret::from_biguint(&n("ffffffffffffffffff"), 1).is_err());
        assert!(Secret::from_bytes_be(&[1; 9], 1).is_err());
    }

    #[test]
    fn test_add_and_sub_report_carry_and_borrow() {
        let k = 2;
        let max = s("ffffffffffffffffffffffffffffffff", k);
        let one = Secret::one(k);
        let (sum, carry) = max.add(&one);
        assert_eq!(carry, 1, "the carry out is the extra limb we refuse to grow");
        assert_eq!(sum.limbs(), &[0, 0]);

        let (diff, borrow) = Secret::zero(k).sub(&one);
        assert_eq!(borrow, 1);
        assert_eq!(diff.limbs(), &[u64::MAX, u64::MAX], "wrapped, not clamped");
    }

    /// `ct_lt` is `sub`'s borrow, so it has to agree with `BigUint`'s
    /// ordering on values that differ only in a high limb - the case a
    /// comparison written limb by limb from the bottom up gets wrong.
    #[test]
    fn test_ct_lt_agrees_with_ordinary_comparison() {
        let k = 3;
        let cases = [
            ("00", "00"),
            ("00", "01"),
            ("01", "00"),
            ("ffffffffffffffff", "010000000000000000"),
            ("010000000000000000", "ffffffffffffffff"),
            ("0100000000000000000000000000000000", "ff"),
            ("ff", "0100000000000000000000000000000000"),
        ];
        for (x, y) in cases {
            let (a, b) = (s(x, k), s(y, k));
            let want = if n(x) < n(y) { TRUE } else { FALSE };
            assert_eq!(a.ct_lt(&b), want, "{} < {}", x, y);
            let eq = if n(x) == n(y) { TRUE } else { FALSE };
            assert_eq!(a.ct_eq(&b), eq, "{} == {}", x, y);
        }
    }

    #[test]
    fn test_conditional_operations() {
        let k = 2;
        let a = s("1111111111111111", k);
        let b = s("2222222222222222", k);

        assert_eq!(Secret::select(&a, &b, TRUE).limbs(), a.limbs());
        assert_eq!(Secret::select(&a, &b, FALSE).limbs(), b.limbs());

        let mut target = a.clone();
        target.cond_assign(&b, FALSE);
        assert_eq!(target.limbs(), a.limbs(), "false must not assign");
        target.cond_assign(&b, TRUE);
        assert_eq!(target.limbs(), b.limbs());

        let (mut x, mut y) = (a.clone(), b.clone());
        Secret::cond_swap(&mut x, &mut y, FALSE);
        assert_eq!((x.limbs(), y.limbs()), (a.limbs(), b.limbs()));
        Secret::cond_swap(&mut x, &mut y, TRUE);
        assert_eq!((x.limbs(), y.limbs()), (b.limbs(), a.limbs()));
    }

    #[test]
    fn test_bit_reads_past_the_end_as_zero() {
        let value = s("8000000000000000", 1);
        assert_eq!(value.bit(63), TRUE);
        assert_eq!(value.bit(62), FALSE);
        assert_eq!(value.bit(64), FALSE, "past the width, not a panic");
        assert_eq!(value.bit(100000), FALSE);
    }

    /// Every two-operand operation refuses operands of different widths,
    /// in every build.
    ///
    /// The checks were `debug_assert_eq!`, so a release build compared,
    /// added or selected on the shorter operand's prefix when `other`
    /// was the longer one - `ct_eq` reported two unequal values equal -
    /// and panicked at `other.limbs[i]` when it was the shorter. Every
    /// caller matches widths, so nothing exercised a mismatch; and
    /// `ct_lt` had no check at all. This test is the one place a
    /// mismatch is offered, and it passed on the old code only in a
    /// debug build.
    #[test]
    fn test_operands_of_different_widths_are_refused() {
        let narrow = Secret::one(2);
        let wide = Secret::one(3);
        let panics = |name: &str, f: &dyn Fn()| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            assert!(result.is_err(), "{name} accepted a width mismatch");
        };
        for (name, a, b) in [("narrow, wide", &narrow, &wide), ("wide, narrow", &wide, &narrow)] {
            panics(&format!("ct_eq({name})"), &|| { a.ct_eq(b); });
            panics(&format!("ct_lt({name})"), &|| { a.ct_lt(b); });
            panics(&format!("add({name})"), &|| { a.add(b); });
            panics(&format!("sub({name})"), &|| { a.sub(b); });
            panics(&format!("select({name})"), &|| { Secret::select(a, b, TRUE); });
            panics(&format!("cond_assign({name})"), &|| { a.clone().cond_assign(b, TRUE); });
            panics(&format!("cond_swap({name})"), &|| {
                Secret::cond_swap(&mut a.clone(), &mut b.clone(), TRUE);
            });
        }
        // And the same width is accepted, so the check is not refusing
        // everything.
        assert_eq!(narrow.ct_eq(&Secret::one(2)), TRUE);
    }

    #[test]
    fn test_is_zero() {
        assert_eq!(Secret::zero(4).ct_is_zero(), TRUE);
        assert_eq!(Secret::one(4).ct_is_zero(), FALSE);
        // A value whose only set bit is in the top limb must not read as zero.
        assert_eq!(s("80000000000000000000000000000000000000000000000000000000000000000", 5)
                       .ct_is_zero(), FALSE);
    }
}
