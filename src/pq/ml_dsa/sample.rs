/*
FIPS 204's samplers: `RejNTTPoly`, `RejBoundedPoly`, `SampleInBall`, and
the three expansions built on them - `ExpandA`, `ExpandS`, `ExpandMask`.

All of them read a SHAKE stream and turn it into coefficients, and the
first two reject some of what they read. Every one has an exact byte
discipline - how many bytes per attempt, which bits, in what order - and
getting it wrong produces a perfectly good distribution and a different
key, with nothing anywhere to say so. The key generation vectors are what
settle them; the tests here check the properties that do not need a
vector.

# Pitfalls

**`RejNTTPoly` takes three bytes and clears the top bit of the third.**
23 bits, so `b2 & 0x7f`. Keeping the top bit gives a 24 bit value that is
rejected about half the time instead of almost never, and a different
matrix.

**`RejBoundedPoly` reads half-bytes, low nibble first, and rejects each
on its own.** At `eta = 2` a nibble below 15 becomes `2 - (b mod 5)`; at
`eta = 4` one below 9 becomes `4 - b`. The `mod 5` is what makes the
`eta = 2` distribution uniform over five values from fifteen nibbles.

**`ExpandA` puts the column index first**: `A[r][s]` is sampled from
`rho ‖ s ‖ r`. The same trap as ML-KEM's, in the opposite order to the
obvious one.

**`ExpandS` and `ExpandMask` take two-byte little-endian counters**, and
`ExpandS`'s second vector continues from `l` rather than restarting.

**`SampleInBall` reads eight bytes of signs before any position**, and
consumes one sign bit per non-zero coefficient, in order from bit 0. The
positions are rejection-sampled one byte at a time against `i`, so the
number of bytes read depends on the stream.

**`SampleInBall` takes the whole of `c-tilde`.** The final FIPS 204 hashes
all `lambda/4` bytes; the draft took only the first 32. At ML-DSA-44
those are the same thing and at the other two they are not.
*/

use super::ring::{Poly, N, Q};
use super::round::unsigned;
use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::HashFunction;

/// A SHAKE stream read incrementally - squeezing more when it runs out.
///
/// `Keccak::squeeze` returns a prefix of the stream for a given length,
/// so "more" means asking for a longer prefix and continuing from where
/// the last one ended. Rejection sampling cannot know in advance how much
/// it will need.
struct Stream {
    sponge: Keccak,
    buffer: Vec<u8>,
    at: usize,
}

impl Stream {
    fn new(security_bits: usize, input: &[&[u8]]) -> Result<Stream, String> {
        let mut sponge = Keccak::shake(security_bits, 0)?;
        for part in input {
            sponge.update(part);
        }
        Ok(Stream { sponge, buffer: Vec::new(), at: 0 })
    }

    fn take(&mut self, count: usize) -> &[u8] {
        if self.at + count > self.buffer.len() {
            let want = (self.buffer.len() + count).max(2 * self.buffer.len())
                .max(840);
            self.buffer = self.sponge.squeeze(want);
        }
        let out = &self.buffer[self.at..self.at + count];
        self.at += count;
        out
    }
}

/// FIPS 204 algorithm 14, `CoeffFromThreeBytes`.
fn coefficient_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<u32> {
    let value = ((b2 & 0x7f) as u32) << 16 | (b1 as u32) << 8 | b0 as u32;
    if value < Q { Some(value) } else { None }
}

/// FIPS 204 algorithm 15, `CoeffFromHalfByte`, as a ring value.
fn coefficient_from_half_byte(nibble: u8, eta: u32) -> Option<u32> {
    match eta {
        2 if nibble < 15 => Some(unsigned(2 - (nibble % 5) as i32)),
        4 if nibble < 9 => Some(unsigned(4 - nibble as i32)),
        _ => None,
    }
}

/// FIPS 204 algorithm 30, `RejNTTPoly`: a uniform polynomial, already in
/// the transformed domain.
pub fn rej_ntt_poly(seed: &[u8]) -> Result<Poly, String> {
    let mut stream = Stream::new(128, &[seed])?;
    let mut poly = Poly::zero();
    let mut j = 0;
    while j < N {
        let bytes = stream.take(3);
        if let Some(value) = coefficient_from_three_bytes(bytes[0], bytes[1],
                                                          bytes[2]) {
            poly.coefficients[j] = value;
            j += 1;
        }
    }
    Ok(poly)
}

/// FIPS 204 algorithm 31, `RejBoundedPoly`: coefficients in `[-eta, eta]`.
pub fn rej_bounded_poly(seed: &[u8], eta: u32) -> Result<Poly, String> {
    if eta != 2 && eta != 4 {
        return Err(format!("RejBoundedPoly: eta is 2 or 4, not {eta}."));
    }
    let mut stream = Stream::new(256, &[seed])?;
    let mut poly = Poly::zero();
    let mut j = 0;
    while j < N {
        let byte = stream.take(1)[0];
        if let Some(value) = coefficient_from_half_byte(byte & 0x0f, eta) {
            poly.coefficients[j] = value;
            j += 1;
        }
        if j < N {
            if let Some(value) = coefficient_from_half_byte(byte >> 4, eta) {
                poly.coefficients[j] = value;
                j += 1;
            }
        }
    }
    Ok(poly)
}

/// FIPS 204 algorithm 29, `SampleInBall`: `tau` coefficients of `±1`,
/// the rest zero.
pub fn sample_in_ball(seed: &[u8], tau: usize) -> Result<Poly, String> {
    let mut stream = Stream::new(256, &[seed])?;
    let mut signs = 0u64;
    for (at, byte) in stream.take(8).iter().enumerate() {
        signs |= (*byte as u64) << (8 * at);
    }
    let mut poly = Poly::zero();
    for (count, i) in (N - tau..N).enumerate() {
        let mut j = stream.take(1)[0] as usize;
        while j > i {
            j = stream.take(1)[0] as usize;
        }
        poly.coefficients[i] = poly.coefficients[j];
        poly.coefficients[j] = if (signs >> count) & 1 == 1 { Q - 1 } else { 1 };
    }
    Ok(poly)
}

/// FIPS 204 algorithm 32, `ExpandA`: `A_hat[r][s]` from `rho ‖ s ‖ r`.
pub fn expand_a(rho: &[u8], k: usize, l: usize)
        -> Result<Vec<Vec<Poly>>, String> {
    let mut matrix = Vec::with_capacity(k);
    for r in 0..k {
        let mut row = Vec::with_capacity(l);
        for s in 0..l {
            let mut seed = Vec::with_capacity(rho.len() + 2);
            seed.extend_from_slice(rho);
            seed.push(s as u8);
            seed.push(r as u8);
            row.push(rej_ntt_poly(&seed)?);
        }
        matrix.push(row);
    }
    Ok(matrix)
}

/// FIPS 204 algorithm 33, `ExpandS`: `(s1, s2)`, `l` and `k` polynomials,
/// with one counter running across both.
pub fn expand_s(rho_prime: &[u8], eta: u32, k: usize, l: usize)
        -> Result<(Vec<Poly>, Vec<Poly>), String> {
    let mut draw = |counter: usize| {
        let mut seed = Vec::with_capacity(rho_prime.len() + 2);
        seed.extend_from_slice(rho_prime);
        seed.extend_from_slice(&(counter as u16).to_le_bytes());
        rej_bounded_poly(&seed, eta)
    };
    let s1 = (0..l).map(&mut draw).collect::<Result<Vec<_>, _>>()?;
    let s2 = (l..l + k).map(&mut draw).collect::<Result<Vec<_>, _>>()?;
    Ok((s1, s2))
}

/// FIPS 204 algorithm 34, `ExpandMask`: `l` polynomials with coefficients
/// in `[-gamma1 + 1, gamma1]`, from counter `kappa` onwards.
pub fn expand_mask(rho_double_prime: &[u8], kappa: usize, gamma1: u32,
                   l: usize) -> Result<Vec<Poly>, String> {
    let width = 1 + super::encode::bitlen(gamma1 - 1);
    let mut out = Vec::with_capacity(l);
    for r in 0..l {
        let mut sponge = Keccak::shake(256, 0)?;
        sponge.update(rho_double_prime);
        sponge.update(&((kappa + r) as u16).to_le_bytes());
        let bytes = sponge.squeeze(32 * width as usize);
        out.push(super::encode::bit_unpack(&bytes, gamma1 - 1, gamma1)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::round::signed;

    #[test]
    fn test_three_bytes_drop_the_top_bit() {
        assert_eq!(coefficient_from_three_bytes(0x01, 0x00, 0x80), Some(1),
                   "the top bit of the third byte is not part of the value");
        assert_eq!(coefficient_from_three_bytes(0xff, 0xff, 0x7f), None,
                   "2^23 - 1 is above q");
        assert_eq!(coefficient_from_three_bytes(0x00, 0xe0, 0x7f), Some(Q - 1));
        assert_eq!(coefficient_from_three_bytes(0x01, 0xe0, 0x7f), None, "q");
    }

    #[test]
    fn test_half_bytes_map_as_the_standard_says() {
        let two: Vec<i32> = (0..16u8)
            .map(|b| coefficient_from_half_byte(b, 2).map_or(99, signed))
            .collect();
        assert_eq!(two, [2, 1, 0, -1, -2, 2, 1, 0, -1, -2, 2, 1, 0, -1, -2, 99]);
        let four: Vec<i32> = (0..16u8)
            .map(|b| coefficient_from_half_byte(b, 4).map_or(99, signed))
            .collect();
        assert_eq!(four, [4, 3, 2, 1, 0, -1, -2, -3, -4,
                          99, 99, 99, 99, 99, 99, 99]);
    }

    #[test]
    fn test_samples_are_in_range_and_depend_on_the_seed() {
        let a = rej_ntt_poly(&[1u8; 34]).unwrap();
        assert!(a.is_reduced());
        assert_ne!(a, rej_ntt_poly(&[2u8; 34]).unwrap());
        for eta in [2u32, 4] {
            let s = rej_bounded_poly(&[3u8; 66], eta).unwrap();
            assert!(s.coefficients.iter()
                        .all(|v| signed(*v).unsigned_abs() <= eta));
            // Both signs, in quantity.
            let negative = s.coefficients.iter().filter(|v| signed(**v) < 0)
                .count();
            assert!(negative > 60 && negative < 160, "{negative}");
        }
        assert!(rej_bounded_poly(&[0u8; 66], 3).is_err());
    }

    /// Exactly `tau` non-zero coefficients, each `±1`, and both signs.
    #[test]
    fn test_sample_in_ball_has_tau_signs() {
        for (tau, seed) in [(39usize, [5u8; 32].to_vec()), (49, [6u8; 48].to_vec()),
                            (60, [7u8; 64].to_vec())] {
            let c = sample_in_ball(&seed, tau).unwrap();
            let nonzero: Vec<i32> = c.coefficients.iter()
                .map(|v| signed(*v)).filter(|v| *v != 0).collect();
            assert_eq!(nonzero.len(), tau);
            assert!(nonzero.iter().all(|v| v.abs() == 1));
            assert!(nonzero.contains(&1) && nonzero.contains(&-1));
        }
    }

    /// `A[r][s]` and `A[s][r]` come from different seeds.
    #[test]
    fn test_expand_a_is_not_symmetric() {
        let a = expand_a(&[9u8; 32], 2, 2).unwrap();
        assert_ne!(a[0][1], a[1][0]);
        let mut seed = [9u8; 32].to_vec();
        seed.extend_from_slice(&[1, 0]);        // s = 1, r = 0
        assert_eq!(a[0][1], rej_ntt_poly(&seed).unwrap(), "column first");
    }

    #[test]
    fn test_expand_mask_is_in_range() {
        for gamma1 in [1u32 << 17, 1 << 19] {
            let y = expand_mask(&[4u8; 64], 0, gamma1, 3).unwrap();
            for poly in &y {
                assert!(poly.coefficients.iter().all(|v| {
                    let w = signed(*v);
                    w > -(gamma1 as i32) && w <= gamma1 as i32
                }));
            }
            assert_ne!(y[0], y[1]);
            // The counter is kappa + r, so starting one later shifts by one.
            let later = expand_mask(&[4u8; 64], 1, gamma1, 2).unwrap();
            assert_eq!(later[0], y[1]);
        }
    }
}
