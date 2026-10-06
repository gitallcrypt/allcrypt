/*
Cryptographically secure randomness, from the operating system.

We do not implement a CSPRNG. Nobody should: the OS generator is seeded from
hardware entropy, reseeded as more arrives, and maintained by people who
think about it full time. This module is a thin shim onto it with no
dependencies - `std::fs` on unix, a `BCryptGenRandom` declaration on Windows.

Three rules, each of which has been somebody's CVE:

  1. **Never fall back.** If the OS source cannot be reached, return an error.
     Silently degrading to a time-seeded PRNG when a file descriptor cannot
     be opened is the classic way this goes wrong, and it fails silently -
     the output still looks like bytes.

  2. **Never buffer.** Cached OS bytes survive a `fork()` into both parent and
     child, which then generate identical keys. We read fresh every time. The
     syscall costs nothing next to the curve operation it feeds.

  3. **Not `prng`.** That module is a linear congruential generator for
     simulation and testing. It is fully predictable from a handful of
     outputs and must never be used for anything keyed. Keeping the two in
     separate modules is deliberate.

See docs/pitfalls.md section 4.
*/

/// Fill `buf` with cryptographically secure random bytes from the OS.
///
/// Errors rather than falling back to anything weaker. A caller that gets an
/// error here must abort whatever it was doing, not continue with whatever
/// happened to be in the buffer.
pub fn fill(buf: &mut [u8]) -> Result<(), String> {
    if buf.is_empty() {
        return Ok(());
    }
    imp::fill(buf)
}

/// A fresh vector of `n` random bytes.
pub fn bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; n];
    fill(&mut out)?;
    Ok(out)
}

/// A uniform integer in `[1, max)`, which is the shape key generation and
/// ECDSA nonces need: a private scalar must be in `[1, n)` for the group
/// order `n`.
///
/// Uses rejection sampling, not `mod max`. Taking a random value modulo the
/// bound biases the result towards small values, and for ECDSA even a few
/// bits of bias across enough signatures leaks the private key through
/// lattice reduction. The rejection loop is the reason this is a function
/// rather than something each caller writes.
pub fn below(max: &crate::bignum::BigUint) -> Result<crate::bignum::BigUint, String> {
    use crate::bignum::BigUint;
    if max.is_zero() || max.is_one() {
        return Err("Upper bound must be greater than 1.".to_string());
    }
    let bits = max.bit_len();
    let byte_len = bits.div_ceil(8);
    // Mask off the bits above the bound so rejection succeeds quickly: at
    // most two attempts on average, rather than up to 256.
    let top_mask: u8 = if bits.is_multiple_of(8) { 0xff } else { (1u8 << (bits % 8)) - 1 };

    // Bounded so a broken OS source cannot spin here forever.
    for _ in 0..256 {
        let mut candidate = bytes(byte_len)?;
        candidate[0] &= top_mask;
        let value = BigUint::from_bytes_be(&candidate);
        if !value.is_zero() && &value < max {
            return Ok(value);
        }
    }
    Err("Rejection sampling failed 256 times; the random source looks broken.".to_string())
}

/// Which OS facility the bytes come from on this build: `"/dev/urandom"`,
/// `"BCryptGenRandom"`, or `"none"` on a platform with neither.
///
/// Exposed so a test can say which path it exercised. A cross-platform
/// backend that is only ever built on one platform is a backend nobody has
/// run, and "all the tests passed" does not distinguish the two - which is
/// exactly the question this answers.
pub fn source() -> &'static str {
    imp::SOURCE
}

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::io::Read;

    pub const SOURCE: &str = "/dev/urandom";

    /// `/dev/urandom` is the right source on every unix we care about: after
    /// the pool is initialised it never blocks and never runs out. The
    /// `getrandom(2)` syscall would additionally block until the pool is
    /// seeded at very early boot, which is a real distinction for an initramfs
    /// and irrelevant for a userspace library on a running system.
    pub fn fill(buf: &mut [u8]) -> Result<(), String> {
        let mut file = File::open("/dev/urandom")
            .map_err(|e| format!("Cannot open /dev/urandom: {}", e))?;
        file.read_exact(buf)
            .map_err(|e| format!("Cannot read from /dev/urandom: {}", e))
    }
}

#[cfg(windows)]
mod imp {
    // BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG needs no algorithm
    // handle, which keeps this to a single call and no state.
    pub const SOURCE: &str = "BCryptGenRandom";

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32; // NTSTATUS: negative is failure, 0 is STATUS_SUCCESS
    }

    pub fn fill(buf: &mut [u8]) -> Result<(), String> {
        // The count is a u32, so very large requests go in chunks.
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return Err(format!("BCryptGenRandom failed with NTSTATUS 0x{:08x}", status));
            }
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub const SOURCE: &str = "none";

    pub fn fill(_buf: &mut [u8]) -> Result<(), String> {
        // Deliberately an error rather than a weak fallback.
        Err("No OS random source is available on this platform.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::BigUint;
    use std::collections::HashSet;

    /// Which source this build actually uses, asserted rather than assumed.
    ///
    /// The tests in this file are not `cfg`-gated, so on Windows every one
    /// of them goes through `BCryptGenRandom` - as does every key this
    /// library generates. This test exists so that the *test output* says
    /// so, because "all 335 tests passed" does not tell you which platform
    /// branch ran, and that was a real open question about this module for
    /// most of its life.
    #[test]
    fn test_the_source_is_the_one_this_platform_should_use() {
        let name = source();
        println!("random source on this build: {}", name);

        if cfg!(windows) {
            assert_eq!(name, "BCryptGenRandom");
        } else if cfg!(unix) {
            assert_eq!(name, "/dev/urandom");
        } else {
            assert_eq!(name, "none");
            return;                 // and then nothing below can work
        }

        // And it produces bytes, so the name is not merely a label on a
        // branch that fails the moment it is called.
        assert_eq!(bytes(32).unwrap().len(), 32);
    }

    #[test]
    fn test_fill_produces_different_bytes() {
        let a = bytes(32).unwrap();
        let b = bytes(32).unwrap();
        assert_ne!(a, b, "two reads must not be identical");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn test_empty_and_odd_lengths() {
        assert!(fill(&mut []).is_ok());
        for n in [1usize, 7, 8, 63, 64, 65, 1000] {
            assert_eq!(bytes(n).unwrap().len(), n);
        }
    }

    /// Not a statistical test - just enough to catch a source that is stuck,
    /// returning a constant, or leaving the buffer untouched.
    #[test]
    fn test_output_is_not_obviously_broken() {
        let sample = bytes(4096).unwrap();
        assert!(sample.iter().any(|&b| b != 0), "all zeros");
        assert!(sample.iter().any(|&b| b != sample[0]), "all the same byte");

        let distinct: HashSet<u8> = sample.iter().copied().collect();
        assert!(distinct.len() > 200, "only {} distinct byte values in 4096", distinct.len());

        // Bit balance should be near half; this window is wide enough never
        // to flake but narrow enough to catch a stuck source.
        let ones: u32 = sample.iter().map(|b| b.count_ones()).sum();
        let total = (sample.len() * 8) as u32;
        assert!(ones > total / 3 && ones < 2 * total / 3,
                "bit balance {} of {} looks wrong", ones, total);
    }

    #[test]
    fn test_below_stays_in_range() {
        for bound in ["2", "3", "ff", "100", "10001",
                      "ffffffff00000001000000000000000000000000ffffffffffffffff00000000"] {
            let max = BigUint::from_hex(bound).unwrap();
            for _ in 0..50 {
                let v = below(&max).unwrap();
                assert!(!v.is_zero(), "must not return zero for bound {}", bound);
                assert!(v < max, "{} out of range for bound {}", v.to_hex(), bound);
            }
        }
    }

    #[test]
    fn test_below_rejects_degenerate_bounds() {
        assert!(below(&BigUint::zero()).is_err());
        assert!(below(&BigUint::one()).is_err());
    }

    /// With bound 3 the only legal outputs are 1 and 2. Over many draws both
    /// must appear, which catches a rejection loop that always lands on the
    /// same value.
    #[test]
    fn test_below_covers_its_range() {
        let three = BigUint::from_u64(3);
        let mut seen = HashSet::new();
        for _ in 0..200 {
            seen.insert(below(&three).unwrap().to_hex());
        }
        assert_eq!(seen.len(), 2, "expected both 1 and 2, saw {:?}", seen);
    }
}
