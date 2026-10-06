/*
FIPS 204's bit packing: `SimpleBitPack`, `BitPack`, their inverses, and
the hint encoding.

Every key and signature is polynomials packed at some width: `t1` at 10
bits, `t0` at 13, `s1` and `s2` at 3 or 4, `z` at 18 or 20, `w1` at 6 or
4. The bit order is ML-KEM's - little-endian within each byte, integers
running across byte boundaries - and so is the risk: a packer that gets
it backwards round-trips against itself perfectly.

# Pitfalls

**`BitPack` stores `b - w`, not `w`.** A coefficient in `[-a, b]` is
packed as the non-negative `b - w`, so the *largest* value packs as 0.
Packing `w + a` instead is equally invertible and matches nothing.
Pinned by `test_bit_pack_stores_b_minus_w`.

**The width is `bitlen(a + b)`, which is not always tight.** For
`eta = 2` it is 3 bits holding values up to 4, so a malformed encoding can
unpack to `-5`. FIPS 204 does not require `skDecode` to check that and
this does not; `sigDecode`'s `z` cannot overflow, because
`bitlen(2*gamma1 - 1)` is exact.

**The hint encoding is the one place a malformed signature has to be
refused while parsing.** `HintBitUnpack` returns "invalid" for indices
that are not strictly increasing within a polynomial, a cumulative count
that goes backwards or past `omega`, and any non-zero byte in the unused
tail. Each of those is a second encoding of the same hint, so accepting
it makes signatures malleable - a known class of bug in early
implementations, and the reason every check below has its own test.
*/

use super::ring::{Poly, N};

/// `bitlen(b)`: the number of bits needed to write `b`.
pub fn bitlen(b: u32) -> u32 {
    32 - b.leading_zeros()
}

/// Bytes a polynomial occupies at `width` bits per coefficient.
pub fn packed_len(width: u32) -> usize {
    32 * width as usize
}

/// Append 256 values of `width` bits, least significant bit first.
fn pack(values: impl Iterator<Item = u32>, width: u32, out: &mut Vec<u8>) {
    let mut accumulator: u64 = 0;
    let mut filled = 0u32;
    for value in values {
        accumulator |= (value as u64) << filled;
        filled += width;
        while filled >= 8 {
            out.push(accumulator as u8);
            accumulator >>= 8;
            filled -= 8;
        }
    }
    debug_assert_eq!(filled, 0);
}

/// 256 values of `width` bits from exactly `32 * width` bytes.
fn unpack(bytes: &[u8], width: u32) -> Result<[u32; N], String> {
    if bytes.len() != packed_len(width) {
        return Err(format!("a polynomial packed at {width} bits is {} bytes, \
                            and this is {}.", packed_len(width), bytes.len()));
    }
    let mut out = [0u32; N];
    let mut accumulator: u64 = 0;
    let mut filled = 0u32;
    let mut at = 0usize;
    let mask = (1u64 << width) - 1;
    for byte in bytes {
        accumulator |= (*byte as u64) << filled;
        filled += 8;
        while filled >= width && at < N {
            out[at] = (accumulator & mask) as u32;
            at += 1;
            accumulator >>= width;
            filled -= width;
        }
    }
    Ok(out)
}

/// FIPS 204 algorithm 16, `SimpleBitPack`: coefficients in `[0, b]` at
/// `bitlen(b)` bits.
pub fn simple_bit_pack(poly: &Poly, b: u32, out: &mut Vec<u8>) {
    debug_assert!(poly.coefficients.iter().all(|v| *v <= b));
    pack(poly.coefficients.iter().copied(), bitlen(b), out);
}

/// FIPS 204 algorithm 18, `SimpleBitUnpack`.
pub fn simple_bit_unpack(bytes: &[u8], b: u32) -> Result<Poly, String> {
    Ok(Poly { coefficients: unpack(bytes, bitlen(b))? })
}

/// FIPS 204 algorithm 17, `BitPack`: coefficients in `[-a, b]` - held as
/// ring values - packed as `b - w` at `bitlen(a + b)` bits.
pub fn bit_pack(poly: &Poly, a: u32, b: u32, out: &mut Vec<u8>) {
    use super::round::signed;
    let width = bitlen(a + b);
    pack(poly.coefficients.iter().map(|value| {
        let w = signed(*value);
        debug_assert!(w >= -(a as i32) && w <= b as i32, "{w} not in [-{a}, {b}]");
        (b as i32 - w) as u32
    }), width, out);
}

/// FIPS 204 algorithm 19, `BitUnpack`: `w = b - z`, back into the ring.
pub fn bit_unpack(bytes: &[u8], a: u32, b: u32) -> Result<Poly, String> {
    use super::round::unsigned;
    let raw = unpack(bytes, bitlen(a + b))?;
    let mut poly = Poly::zero();
    for (out, z) in poly.coefficients.iter_mut().zip(raw.iter()) {
        *out = unsigned(b as i32 - *z as i32);
    }
    Ok(poly)
}

/// FIPS 204 algorithm 20, `HintBitPack`: `omega + k` bytes - the
/// positions of the ones, then each polynomial's cumulative count.
pub fn hint_bit_pack(hints: &[[bool; N]], omega: usize, out: &mut Vec<u8>)
        -> Result<(), String> {
    let k = hints.len();
    let mut packed = vec![0u8; omega + k];
    let mut index = 0usize;
    for (i, hint) in hints.iter().enumerate() {
        for (j, set) in hint.iter().enumerate() {
            if *set {
                if index == omega {
                    return Err(format!("HintBitPack: more than omega = \
                                        {omega} ones."));
                }
                packed[index] = j as u8;
                index += 1;
            }
        }
        packed[omega + i] = index as u8;
    }
    out.extend_from_slice(&packed);
    Ok(())
}

/// FIPS 204 algorithm 21, `HintBitUnpack`, or `None` for an encoding the
/// standard says is invalid.
pub fn hint_bit_unpack(bytes: &[u8], omega: usize, k: usize)
        -> Option<Vec<[bool; N]>> {
    if bytes.len() != omega + k {
        return None;
    }
    let mut hints = vec![[false; N]; k];
    let mut index = 0usize;
    for (i, hint) in hints.iter_mut().enumerate() {
        let end = bytes[omega + i] as usize;
        if end < index || end > omega {
            return None;
        }
        let first = index;
        while index < end {
            // Strictly increasing within one polynomial: a repeated or
            // out-of-order position is a second encoding of the same hint.
            if index > first && bytes[index - 1] >= bytes[index] {
                return None;
            }
            hint[bytes[index] as usize] = true;
            index += 1;
        }
    }
    // The unused tail must be zero, for the same reason.
    if bytes[index..omega].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(hints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::round::{signed, unsigned};
    use super::super::ring::Q;

    fn sample(seed: u64, low: i32, high: i32) -> Poly {
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(7);
        let mut poly = Poly::zero();
        let span = (high - low + 1) as u64;
        for value in poly.coefficients.iter_mut() {
            state = state.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *value = unsigned(low + ((state >> 33) % span) as i32);
        }
        poly
    }

    #[test]
    fn test_bitlen() {
        assert_eq!(bitlen(0), 0);
        assert_eq!(bitlen(1), 1);
        assert_eq!(bitlen(4), 3);
        assert_eq!(bitlen(8), 4);
        assert_eq!(bitlen(1023), 10);
        assert_eq!(bitlen((1 << 17) * 2 - 1), 18);
        assert_eq!(bitlen((Q - 1) / 88 - 1), 17);
    }

    /// Round trips at every width ML-DSA uses.
    #[test]
    fn test_packing_round_trips_at_every_width() {
        let gamma1_17 = 1u32 << 17;
        let gamma1_19 = 1u32 << 19;
        for (a, b) in [(2, 2), (4, 4), ((1 << 12) - 1, 1 << 12),
                       (gamma1_17 - 1, gamma1_17), (gamma1_19 - 1, gamma1_19)] {
            let poly = sample(a as u64, -(a as i32), b as i32);
            let mut out = Vec::new();
            bit_pack(&poly, a, b, &mut out);
            assert_eq!(out.len(), packed_len(bitlen(a + b)));
            assert_eq!(bit_unpack(&out, a, b).unwrap(), poly, "a {a} b {b}");
        }
        for b in [1023u32, 43, 15] {
            let poly = sample(b as u64, 0, b as i32);
            let mut out = Vec::new();
            simple_bit_pack(&poly, b, &mut out);
            assert_eq!(out.len(), packed_len(bitlen(b)));
            assert_eq!(simple_bit_unpack(&out, b).unwrap(), poly);
        }
    }

    /// `b - w`: the largest coefficient packs as zero and the smallest as
    /// `a + b`.
    #[test]
    fn test_bit_pack_stores_b_minus_w() {
        let mut poly = Poly::zero();
        poly.coefficients[0] = 2;                 // b
        poly.coefficients[1] = unsigned(-2);      // -a
        let mut out = Vec::new();
        bit_pack(&poly, 2, 2, &mut out);
        // Three bits each, little-endian: 0 then 4, so the first byte is
        // 0b00_100_000 and the third coefficient (w = 0, packed 2) starts
        // at bit 6.
        assert_eq!(out[0] & 0b0011_1111, 0b0010_0000);
        assert_eq!(signed(bit_unpack(&out, 2, 2).unwrap().coefficients[1]), -2);
    }

    /// Little-endian within each byte: the first value's low bit is bit 0.
    #[test]
    fn test_the_bit_order_is_little_endian() {
        let mut poly = Poly::zero();
        poly.coefficients[0] = 1;
        poly.coefficients[1] = 0x3ff;
        let mut out = Vec::new();
        simple_bit_pack(&poly, 1023, &mut out);
        assert_eq!(out[0], 0x01);
        assert_eq!(out[1], 0xfc, "the second value's low six bits fill the \
                                 top of byte 1");
        assert_eq!(out[2], 0x0f);
    }

    #[test]
    fn test_unpacking_refuses_the_wrong_length() {
        assert!(simple_bit_unpack(&[0u8; 319], 1023).is_err());
        assert!(bit_unpack(&[0u8; 97], 2, 2).is_err());
    }

    fn hints(ones: &[(usize, usize)], k: usize) -> Vec<[bool; N]> {
        let mut out = vec![[false; N]; k];
        for (i, j) in ones {
            out[*i][*j] = true;
        }
        out
    }

    #[test]
    fn test_hints_round_trip() {
        let h = hints(&[(0, 3), (0, 200), (2, 0), (3, 255)], 4);
        let mut out = Vec::new();
        hint_bit_pack(&h, 80, &mut out).unwrap();
        assert_eq!(out.len(), 84);
        assert_eq!(&out[..4], &[3, 200, 0, 255]);
        assert_eq!(&out[80..], &[2, 2, 3, 4], "cumulative counts");
        assert_eq!(hint_bit_unpack(&out, 80, 4).unwrap(), h);
    }

    #[test]
    fn test_too_many_hints_are_refused_when_packing() {
        let ones: Vec<(usize, usize)> = (0..81).map(|j| (0, j)).collect();
        assert!(hint_bit_pack(&hints(&ones, 4), 80, &mut Vec::new()).is_err());
    }

    /// Each malformed encoding is refused, and each is a second encoding
    /// of a hint that has a proper one - which is why it matters.
    #[test]
    fn test_every_malformed_hint_encoding_is_refused() {
        let good = {
            let mut out = Vec::new();
            hint_bit_pack(&hints(&[(0, 3), (0, 9), (1, 4)], 4), 80, &mut out)
                .unwrap();
            out
        };
        assert!(hint_bit_unpack(&good, 80, 4).is_some());

        let mut repeated = good.clone();
        repeated[1] = 3;                       // 3, 3 within polynomial 0
        assert!(hint_bit_unpack(&repeated, 80, 4).is_none(), "repeat");

        let mut descending = good.clone();
        descending[0] = 9;
        descending[1] = 3;                     // 9, 3
        assert!(hint_bit_unpack(&descending, 80, 4).is_none(), "order");

        let mut backwards = good.clone();
        backwards[81] = 1;                     // count 2 then 1
        assert!(hint_bit_unpack(&backwards, 80, 4).is_none(), "count down");

        let mut past_omega = good.clone();
        past_omega[83] = 81;
        assert!(hint_bit_unpack(&past_omega, 80, 4).is_none(), "past omega");

        let mut dirty_tail = good.clone();
        dirty_tail[50] = 7;
        assert!(hint_bit_unpack(&dirty_tail, 80, 4).is_none(), "tail");

        // Across a polynomial boundary the order resets: 9 in polynomial 0
        // followed by 4 in polynomial 1 is fine, as `good` already shows.
        assert!(hint_bit_unpack(&good[..83], 80, 4).is_none(), "length");
    }
}
