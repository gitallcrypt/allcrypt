/*
FIPS 203's `ByteEncode_d` and `ByteDecode_d`: polynomials to bytes.

A polynomial is 256 integers of `d` bits, packed into `32 * d` bytes. `d`
is 12 for a key, and 1, 4, 5, 10 or 11 for the compressed pieces of a
ciphertext.

# Pitfalls

**The bit order is little-endian within each byte, and the integers run
across byte boundaries.** `BytesToBits` in the standard is
`b[8i + j] = (B[i] >> j) & 1`, so bit 0 of a byte is the *first* bit of
the stream. At `d = 12` that puts a coefficient's low eight bits in one
byte and its high four in the low nibble of the next. Packing most
significant bit first gives an encoding that round-trips perfectly
against itself and matches nothing.

**`ByteDecode_12` reduces mod `q` and the smaller widths do not**, and
this is not a detail. FIPS 203 decodes with modulus `2^d` for `d < 12` and
with modulus `q` for `d = 12`, because at 12 bits the value could be up to
4095 while a coefficient must be below 3329. So a 12 bit field holding
3400 decodes to 71, and `ByteEncode_12(ByteDecode_12(ek))` then differs
from `ek`.

That difference is exactly what FIPS 203's **encapsulation key check** is:
a key whose coefficients are not canonical is rejected by re-encoding and
comparing. Implementing `ByteDecode_12` without the reduction makes the
check pass on every input - it compares a value with itself - and the
malleability it exists to stop comes back. See
[`super::modulus_check`], and the ACVP `encapsulationKeyCheck` vectors,
half of which are keys that must be refused.

**`ByteEncode_d` is not told the width to use by its input.** A `Poly`
whose coefficients happen to be small does not encode more tightly; `d` is
a property of the parameter set and the field being encoded. Passing the
wrong `d` produces a buffer of the wrong length, which is why every
function here checks the length it was handed rather than trusting it.
*/

use super::ring::{Poly, Q, N};

/// Bytes a single polynomial occupies at `d` bits per coefficient.
pub const fn encoded_len(bits: u32) -> usize {
    32 * bits as usize
}

/// FIPS 203 algorithm 5, `ByteEncode_d`.
///
/// Appends `32 * d` bytes. Refuses a coefficient that does not fit, rather
/// than truncating it: a value too large for `d` bits means the caller
/// compressed with a different width, and silently dropping the high bits
/// would produce a ciphertext that decrypts to noise.
pub fn byte_encode(poly: &Poly, bits: u32, out: &mut Vec<u8>)
        -> Result<(), String> {
    check_width("ByteEncode", bits)?;
    let limit = limit(bits);
    for (at, value) in poly.coefficients.iter().enumerate() {
        if *value as u32 >= limit {
            return Err(format!(
                "ByteEncode_{bits}: coefficient {at} is {value}, which is not \
                 below {limit}."));
        }
    }
    pack(poly, bits, out);
    Ok(())
}

/// [`byte_encode`] without the per-coefficient range check, for a
/// polynomial that is in range by construction.
///
/// **This is the one ML-KEM's own algorithms use**, because the range
/// check is a branch on every coefficient and on their secret paths -
/// `s_hat` in key generation, the message and `w` in decryption, `u` and
/// `v` before they are published - the coefficients are secret.
/// `scripts/ct_check.py` measures that those paths reach no such branch;
/// the checked version is its positive control.
///
/// The range is still asserted in debug builds, so a caller that broke
/// the precondition fails every test rather than encoding garbage.
pub(crate) fn byte_encode_unchecked(poly: &Poly, bits: u32, out: &mut Vec<u8>)
        -> Result<(), String> {
    check_width("ByteEncode", bits)?;
    debug_assert!(poly.coefficients.iter().all(|v| (*v as u32) < limit(bits)),
                  "ByteEncode_{bits}: a coefficient is out of range");
    pack(poly, bits, out);
    Ok(())
}

/// `d` is public - a property of the parameter set and the field - so
/// branching on it is free.
fn check_width(what: &str, bits: u32) -> Result<(), String> {
    if bits == 0 || bits > 12 {
        return Err(format!("{what} takes 1 to 12 bits, not {bits}."));
    }
    Ok(())
}

/// The bound a `d` bit field must stay below: `2^d`, or `q` at twelve.
fn limit(bits: u32) -> u32 {
    if bits == 12 { Q as u32 } else { 1u32 << bits }
}

fn pack(poly: &Poly, bits: u32, out: &mut Vec<u8>) {
    // One bit at a time into an accumulator, flushed every eight. Written
    // this way rather than with per-width shifting because the widths that
    // do not divide eight - 5, 11 - are where a clever version goes wrong,
    // and this is the same code for all of them.
    let mut accumulator: u32 = 0;
    let mut filled = 0u32;
    for value in poly.coefficients.iter() {
        accumulator |= (*value as u32) << filled;
        filled += bits;
        while filled >= 8 {
            out.push((accumulator & 0xff) as u8);
            accumulator >>= 8;
            filled -= 8;
        }
    }
    // 256 * d is always a whole number of bytes, so nothing is left over.
    debug_assert_eq!(filled, 0);
    debug_assert_eq!(accumulator, 0);
}

/// FIPS 203 algorithm 6, `ByteDecode_d`.
///
/// **Reduces mod `q` at `d = 12` and mod `2^d` below it**, exactly as the
/// standard does. See the note at the top of this file: that asymmetry is
/// what makes the encapsulation key check meaningful, and removing it
/// turns the check into a comparison of a value with itself.
///
/// **The reduction is never a division by a variable.** It used to be
/// `value % modulus` with `modulus` chosen at run time, which compiles to
/// a `div` instruction - and this function decodes secrets: `s_hat` from
/// `dk`, and the message during decapsulation. Division latency depends
/// on its operands on many processors; that is the KyberSlash class of
/// leak. Now the branch is on `d`, which is public: at twelve bits the
/// reduction is `% Q` on a constant, which compiles to a multiply, and
/// below twelve the field is already below `2^d` and needs no reduction.
/// `scripts/ct_check.py` disassembles ML-KEM and fails on any `div`.
pub fn byte_decode(bytes: &[u8], bits: u32) -> Result<Poly, String> {
    check_width("ByteDecode", bits)?;
    if bytes.len() != encoded_len(bits) {
        return Err(format!(
            "ByteDecode_{}: expected {} bytes and got {}.",
            bits, encoded_len(bits), bytes.len()));
    }
    let mut poly = Poly::zero();
    let mut accumulator: u32 = 0;
    let mut filled = 0u32;
    let mut at = 0usize;
    for byte in bytes {
        accumulator |= (*byte as u32) << filled;
        filled += 8;
        while filled >= bits && at < N {
            let value = accumulator & ((1u32 << bits) - 1);
            poly.coefficients[at] = if bits == 12 {
                (value % Q as u32) as u16
            } else {
                value as u16
            };
            at += 1;
            accumulator >>= bits;
            filled -= bits;
        }
    }
    debug_assert_eq!(at, N);
    Ok(poly)
}

/// Encode `k` polynomials one after another, which is what a key or the
/// `u` half of a ciphertext is.
pub fn byte_encode_vector(polys: &[Poly], bits: u32)
        -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(polys.len() * encoded_len(bits));
    for poly in polys {
        byte_encode(poly, bits, &mut out)?;
    }
    Ok(out)
}

/// [`byte_encode_vector`] over [`byte_encode_unchecked`].
pub(crate) fn byte_encode_vector_unchecked(polys: &[Poly], bits: u32)
        -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(polys.len() * encoded_len(bits));
    for poly in polys {
        byte_encode_unchecked(poly, bits, &mut out)?;
    }
    Ok(out)
}

/// Decode `count` polynomials from a concatenation of them.
pub fn byte_decode_vector(bytes: &[u8], bits: u32, count: usize)
        -> Result<Vec<Poly>, String> {
    let each = encoded_len(bits);
    if bytes.len() != count * each {
        return Err(format!(
            "ByteDecode_{}: expected {} polynomials in {} bytes and got {}.",
            bits, count, count * each, bytes.len()));
    }
    let mut out = Vec::with_capacity(count);
    for chunk in bytes.chunks(each) {
        out.push(byte_decode(chunk, bits)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ring;

    fn sample(seed: u64, limit: u16) -> Poly {
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut out = Poly::zero();
        for at in 0..N {
            state = state.wrapping_mul(6364136223846793005)
                         .wrapping_add(1442695040888963407);
            out.coefficients[at] = ((state >> 33) % limit as u64) as u16;
        }
        out
    }

    /// Every width round trips, and the encoding is the length the
    /// standard says.
    #[test]
    fn test_every_width_round_trips_at_the_documented_length() {
        for bits in 1..=12u32 {
            let limit = if bits == 12 { Q } else { 1u16 << bits };
            let poly = sample(bits as u64, limit);

            let mut encoded = Vec::new();
            byte_encode(&poly, bits, &mut encoded).unwrap();
            assert_eq!(encoded.len(), 32 * bits as usize,
                       "d = {bits}: a polynomial is 32*d bytes");

            let back = byte_decode(&encoded, bits).unwrap();
            assert_eq!(back, poly, "d = {bits}");
        }
    }

    /// The bit order is little-endian within each byte.
    ///
    /// Checked against a hand-worked case rather than only by round
    /// tripping, because a most-significant-bit-first implementation round
    /// trips against itself perfectly.
    #[test]
    fn test_the_bit_order_is_little_endian_within_each_byte() {
        // d = 1: coefficient i goes to bit i of the stream, so
        // coefficients 1 and 0 set 0x02 in the first byte.
        let mut poly = Poly::zero();
        poly.coefficients[1] = 1;
        let mut encoded = Vec::new();
        byte_encode(&poly, 1, &mut encoded).unwrap();
        assert_eq!(encoded[0], 0x02, "bit 1 of the first byte");
        assert_eq!(encoded.len(), 32);

        // d = 12: coefficient 0 = 0x123 occupies the whole of byte 0 and
        // the low nibble of byte 1.
        let mut poly = Poly::zero();
        poly.coefficients[0] = 0x123;
        let mut encoded = Vec::new();
        byte_encode(&poly, 12, &mut encoded).unwrap();
        assert_eq!(encoded[0], 0x23, "the low eight bits come first");
        assert_eq!(encoded[1] & 0x0f, 0x01, "then the high four");

        // And two coefficients share the middle byte: 0x123 then 0x456
        // packs as 23 61 45.
        let mut poly = Poly::zero();
        poly.coefficients[0] = 0x123;
        poly.coefficients[1] = 0x456;
        let mut encoded = Vec::new();
        byte_encode(&poly, 12, &mut encoded).unwrap();
        assert_eq!(&encoded[..3], &[0x23, 0x61, 0x45]);
    }

    /// **`ByteDecode_12` reduces mod q, and the narrower widths do not.**
    ///
    /// This is the asymmetry the encapsulation key check depends on. A
    /// decoder that reduced mod `2^12` would make the check compare a
    /// value with itself and accept every key.
    #[test]
    fn test_twelve_bit_decoding_reduces_mod_q() {
        // 3400 is representable in twelve bits and is not a coefficient.
        let mut raw = vec![0u8; 32 * 12];
        raw[0] = 0x48;                 // 3400 = 0xD48
        raw[1] = 0x0d;
        let decoded = byte_decode(&raw, 12).unwrap();
        assert_eq!(decoded.coefficients[0], 3400 - Q,
                   "a 12 bit field above q reduces");
        assert!(decoded.is_reduced());

        // So re-encoding does not give the original bytes back, which is
        // precisely what makes a non-canonical key detectable.
        let mut again = Vec::new();
        byte_encode(&decoded, 12, &mut again).unwrap();
        assert_ne!(again, raw,
                   "a non-canonical encoding must not survive a round trip, \
                    or the modulus check cannot work");

        // Below twelve bits there is no reduction: 2^d - 1 stays itself.
        //
        // **Two bytes of 0xff, not one.** A first version of this set only
        // the first byte and expected `2^d - 1`, which is true up to eight
        // bits and false above it: at d = 9 the field's top bit comes from
        // the second byte, so the value was 255 where the test wanted 511.
        // The code was right and the test was wrong.
        for bits in 1..12u32 {
            let mut raw = vec![0u8; 32 * bits as usize];
            raw[0] = 0xff;
            raw[1] = 0xff;
            let decoded = byte_decode(&raw, bits).unwrap();
            assert_eq!(decoded.coefficients[0], (1u16 << bits) - 1,
                       "d = {bits} should not reduce mod q");
        }
    }

    /// A coefficient too large for its width is refused, not truncated.
    #[test]
    fn test_a_coefficient_that_does_not_fit_is_refused() {
        let mut poly = Poly::zero();
        poly.coefficients[5] = 16;
        let error = byte_encode(&poly, 4, &mut Vec::new()).unwrap_err();
        assert!(error.contains("coefficient 5") && error.contains("16"),
                "{error}");

        // At twelve bits the limit is q, not 4096 - encoding a coefficient
        // between q and 4096 would produce a key our own decoder reduces.
        poly.coefficients[5] = Q;
        let error = byte_encode(&poly, 12, &mut Vec::new()).unwrap_err();
        assert!(error.contains("3329"), "{error}");
        poly.coefficients[5] = Q - 1;
        assert!(byte_encode(&poly, 12, &mut Vec::new()).is_ok());
    }

    #[test]
    fn test_the_widths_and_lengths_are_checked() {
        assert!(byte_encode(&Poly::zero(), 0, &mut Vec::new())
                    .unwrap_err().contains("1 to 12"));
        assert!(byte_encode(&Poly::zero(), 13, &mut Vec::new())
                    .unwrap_err().contains("1 to 12"));
        assert!(byte_decode(&[0u8; 10], 12).unwrap_err().contains("384"));
        assert!(byte_decode(&[0u8; 384], 13).unwrap_err().contains("1 to 12"));
    }

    /// A vector of polynomials is their concatenation, in order.
    #[test]
    fn test_a_vector_is_the_concatenation_in_order() {
        let polys = vec![sample(1, Q), sample(2, Q), sample(3, Q)];
        let encoded = byte_encode_vector(&polys, 12).unwrap();
        assert_eq!(encoded.len(), 3 * 384);

        let back = byte_decode_vector(&encoded, 12, 3).unwrap();
        assert_eq!(back, polys);

        // The order matters, which a symmetric test would not notice.
        let reversed: Vec<Poly> = polys.iter().rev().cloned().collect();
        assert_ne!(byte_encode_vector(&reversed, 12).unwrap(), encoded);

        assert!(byte_decode_vector(&encoded, 12, 2).unwrap_err()
                    .contains("got"));
    }

    /// Encoding a compressed polynomial and decompressing it back lands
    /// where the compression left it.
    ///
    /// The two halves of a ciphertext are compressed *and then* encoded, so
    /// this is the composition that actually ships. Checked at the widths
    /// FIPS 203 uses - `du` is 10 or 11 and `dv` is 4 or 5 - rather than at
    /// all twelve, because those are the ones a ciphertext can contain.
    #[test]
    fn test_compression_and_encoding_compose() {
        for bits in [4u32, 5, 10, 11] {
            let poly = sample(bits as u64 + 100, Q);
            let mut compressed = Poly::zero();
            for at in 0..N {
                compressed.coefficients[at] =
                    ring::compress(poly.coefficients[at], bits).unwrap();
            }

            let encoded = byte_encode_vector(&[compressed.clone()], bits)
                .unwrap();
            let decoded = byte_decode(&encoded, bits).unwrap();
            assert_eq!(decoded, compressed, "d = {bits}");

            // And decompressing lands within the bound, which ties this
            // file to `ring`'s own compression test.
            let bound = (Q as u32).div_ceil(1u32 << (bits + 1));
            for at in 0..N {
                let back = ring::decompress(decoded.coefficients[at], bits)
                    .unwrap();
                let direct = (back as i32 - poly.coefficients[at] as i32)
                    .unsigned_abs();
                assert!(direct.min(Q as u32 - direct) <= bound, "d = {bits}");
            }
        }
    }
}
