/*
IDEA, the International Data Encryption Algorithm.

64 bit block, 128 bit key, eight rounds and an output transform. Designed
in 1991, patented until 2012, and for most of the 1990s the cipher PGP
used - which is why files encrypted with it still exist and why a library
that keeps the old things needs it. `python-cryptography` has moved it to
`hazmat.decrepit`.

No S-boxes and no tables at all. Its non-linearity comes from mixing three
group operations that do not distribute over each other:

  * XOR on 16 bit words,
  * addition modulo 2^16,
  * **multiplication modulo 2^16 + 1**, which is the interesting one.

## The multiplication, which is where implementations go wrong

65537 is prime, so the non-zero residues form a group - but the words
being multiplied are 16 bits and so cannot represent 65536. IDEA's
convention is that **a stored zero means 65536**, at both ends:

    mul(0, y) = (65536 * y) mod 65537
    mul(x, 0) = (x * 65536) mod 65537
    mul(0, 0) = (65536 * 65536) mod 65537 = 1

An implementation that treats zero as zero gets a multiplication that is
no longer a bijection, so decryption stops being the inverse of
encryption - which at least fails loudly. An implementation that handles
`mul(0, y)` but not `mul(x, 0)` is wrong only for the keys and blocks
that happen to contain a zero word, which is about one block in a
thousand. `test_zero_means_65536_at_both_ends` pins all three cases.

## Decryption is not the same round keys backwards

Unlike SM4, reversing the subkeys is not enough: each one has to be
*inverted* in its own group - the multiplicative ones modulo 65537 and
the additive ones modulo 2^16 - and the two middle keys of each round
stay where they are while the outer four are permuted. Getting the
permutation wrong gives something that round-trips for the zero key and
nothing else.
*/

use crate::block_ciphers::BlockCipher;

/// Multiplication modulo 65537, with zero standing for 65536.
///
/// Without a division: for `x, y` in `1..65536` the product is
/// `hi * 2^16 + lo`, and `2^16 = -1` modulo 65537, so it is `lo - hi`,
/// plus 65537 when that is negative. Zero is 65536, which is -1, so a
/// zero operand makes the answer the other's negation, `1 - y` in the
/// 16 bit convention - including `mul(0, 0) = 1`.
#[inline]
fn mul(a: u16, b: u16) -> u16 {
    if a == 0 {
        return 1u16.wrapping_sub(b);
    }
    if b == 0 {
        return 1u16.wrapping_sub(a);
    }
    let product = a as u32 * b as u32;
    let (lo, hi) = (product & 0xffff, product >> 16);
    lo.wrapping_sub(hi).wrapping_add(u32::from(lo < hi)) as u16
}

/// The definition, by `%` on 64 bit values: the reference `mul` is
/// tested against.
#[cfg(test)]
fn mul_reference(a: u16, b: u16) -> u16 {
    // **u64, not u32.** Both operands can be 65536, and 65536 * 65536
    // is 2^32 - which does not fit in a u32 and wraps to zero in a
    // release build, silently. The first version of this used u32 and
    // its own `mul(0, 0)` test caught it; every other case fits
    // comfortably, so only the one input that the whole zero
    // convention exists for would have been wrong.
    let x = if a == 0 { 0x1_0000u64 } else { a as u64 };
    let y = if b == 0 { 0x1_0000u64 } else { b as u64 };
    let product = (x * y) % 0x1_0001;
    // And back: 65536 is stored as zero.
    (product & 0xffff) as u16
}

/// The multiplicative inverse modulo 65537, in the same convention.
///
/// By exponentiation rather than the extended Euclidean algorithm:
/// 65537 is prime, so `a^65535` is `a^-1`, and squaring up is eleven
/// lines shorter than the alternative with no chance of a sign mistake.
fn mul_inverse(a: u16) -> u16 {
    if a == 0 {
        // 65536 is its own inverse: 65536^2 mod 65537 = 1.
        return 0;
    }
    let mut result = 1u16;
    let mut base = a;
    let mut exponent = 0xffffu32;      // 65537 - 2
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exponent >>= 1;
    }
    result
}

/// The additive inverse modulo 2^16.
#[inline]
fn add_inverse(a: u16) -> u16 {
    a.wrapping_neg()
}

/// IDEA with its 52 subkeys expanded.
#[derive(Clone)]
pub struct Idea {
    encrypt_keys: [u16; 52],
    decrypt_keys: [u16; 52],
}

impl Idea {
    pub fn new(key: Vec<u8>) -> Result<Idea, String> {
        if key.len() != 16 {
            return Err(format!("An IDEA key is 16 bytes; this one is {}.", key.len()));
        }

        // The first eight subkeys are the key itself, big endian. Each
        // following group of eight comes from rotating the whole 128
        // bit key left by 25 bits - not by 16, which would just
        // reshuffle the same words.
        let mut encrypt_keys = [0u16; 52];
        let mut material = [0u16; 8];
        for (index, word) in material.iter_mut().enumerate() {
            *word = u16::from_be_bytes([key[index * 2], key[index * 2 + 1]]);
        }
        let mut produced = 0;
        while produced < 52 {
            let take = core::cmp::min(8, 52 - produced);
            encrypt_keys[produced..produced + take].copy_from_slice(&material[..take]);
            produced += take;
            if produced >= 52 {
                break;
            }
            material = rotate_left_25(&material);
        }

        Ok(Idea { encrypt_keys, decrypt_keys: invert(&encrypt_keys) })
    }

    fn transform(&self, input: &[u8], result: &mut Vec<u8>, keys: &[u16; 52]) {
        let mut x = [0u16; 4];
        for (index, word) in x.iter_mut().enumerate() {
            *word = u16::from_be_bytes([input[index * 2], input[index * 2 + 1]]);
        }

        for round in 0..8 {
            let k = &keys[round * 6..round * 6 + 6];
            x[0] = mul(x[0], k[0]);
            x[1] = x[1].wrapping_add(k[1]);
            x[2] = x[2].wrapping_add(k[2]);
            x[3] = mul(x[3], k[3]);

            let t0 = mul(k[4], x[0] ^ x[2]);
            let t1 = mul(k[5], t0.wrapping_add(x[1] ^ x[3]));
            let t2 = t0.wrapping_add(t1);

            x[0] ^= t1;
            x[3] ^= t2;
            let swapped = x[1] ^ t2;
            x[1] = x[2] ^ t1;
            x[2] = swapped;
        }

        // The output transform, where x[1] and x[2] are exchanged -
        // undoing the swap the last round left behind.
        let k = &keys[48..52];
        let out = [
            mul(x[0], k[0]),
            x[2].wrapping_add(k[1]),
            x[1].wrapping_add(k[2]),
            mul(x[3], k[3]),
        ];
        for word in out {
            result.extend_from_slice(&word.to_be_bytes());
        }
    }
}

/// Rotate the 128 bit key left by 25 bits, as eight 16 bit words.
fn rotate_left_25(words: &[u16; 8]) -> [u16; 8] {
    let mut whole: u128 = 0;
    for word in words {
        whole = (whole << 16) | *word as u128;
    }
    let rotated = whole.rotate_left(25);
    let mut out = [0u16; 8];
    for (index, word) in out.iter_mut().enumerate() {
        *word = ((rotated >> (112 - index * 16)) & 0xffff) as u16;
    }
    out
}

/// The decryption subkeys.
///
/// Each round's keys are inverted in their own group and the rounds are
/// taken in reverse - but the two middle keys (`k5`, `k6`) are *not*
/// inverted and *not* moved relative to each other, and the two
/// additive keys swap places in every round but the first and last.
/// That asymmetry is the part worth reading twice.
fn invert(keys: &[u16; 52]) -> [u16; 52] {
    let mut out = [0u16; 52];
    let mut at = 0;

    // The output transform becomes the first round's outer four.
    out[at] = mul_inverse(keys[48]); at += 1;
    out[at] = add_inverse(keys[49]); at += 1;
    out[at] = add_inverse(keys[50]); at += 1;
    out[at] = mul_inverse(keys[51]); at += 1;

    for round in (1..8).rev() {
        let k = round * 6;
        out[at] = keys[k + 4]; at += 1;
        out[at] = keys[k + 5]; at += 1;
        out[at] = mul_inverse(keys[k]); at += 1;
        // Swapped: the second additive key of the round comes first.
        out[at] = add_inverse(keys[k + 2]); at += 1;
        out[at] = add_inverse(keys[k + 1]); at += 1;
        out[at] = mul_inverse(keys[k + 3]); at += 1;
    }

    // The first round, whose additive keys are *not* swapped.
    out[at] = keys[4]; at += 1;
    out[at] = keys[5]; at += 1;
    out[at] = mul_inverse(keys[0]); at += 1;
    out[at] = add_inverse(keys[1]); at += 1;
    out[at] = add_inverse(keys[2]); at += 1;
    out[at] = mul_inverse(keys[3]);

    out
}

impl BlockCipher for Idea {
    fn blocksize(&self) -> usize { 8 }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        self.transform(input, result, &self.encrypt_keys);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        self.transform(input, result, &self.decrypt_keys);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// **The zero convention, at both ends and together.**
    ///
    /// A stored zero means 65536. Handling that on the left and not the
    /// right is wrong only for the blocks and keys that contain a zero
    /// word - roughly one in a thousand - so a round-trip test over a
    /// handful of vectors passes.
    #[test]
    fn test_mul_is_the_definition() {
        for a in (0..=65535u32).step_by(7).chain([0, 1, 2, 65535, 65534, 32768]) {
            for b in [0u32, 1, 2, 3, 255, 256, 32767, 32768, 65534, 65535, a, 65535 - a] {
                assert_eq!(mul(a as u16, b as u16), mul_reference(a as u16, b as u16),
                           "{a} * {b}");
            }
        }
    }

    #[test]
    fn test_zero_means_65536_at_both_ends() {
        // 65536 * 1 mod 65537 = 65536, stored as 0.
        assert_eq!(mul(0, 1), 0);
        assert_eq!(mul(1, 0), 0);
        // 65536 * 65536 mod 65537 = 1.
        assert_eq!(mul(0, 0), 1);
        // 65536 * 2 mod 65537 = 65535.
        assert_eq!(mul(0, 2), 65535);
        assert_eq!(mul(2, 0), 65535);
        // And an ordinary case, to show the modulus is 65537 and not
        // 65536: 2 * 32769 mod 65537 = 1.
        assert_eq!(mul(2, 32769), 1);
    }

    /// Every value has a multiplicative inverse, including zero.
    #[test]
    fn test_every_value_has_an_inverse() {
        for value in 0..=u16::MAX {
            assert_eq!(mul(value, mul_inverse(value)), 1,
                       "{} times its inverse is not 1", value);
            assert_eq!(add_inverse(value).wrapping_add(value), 0);
        }
    }

    /// The key rotation is by 25 bits, not 24 or 32.
    ///
    /// A rotation by a whole number of words would only reshuffle the
    /// eight subkeys, so every group of eight would be a permutation of
    /// the first - which is exactly the degenerate schedule IDEA's 25
    /// avoids.
    #[test]
    fn test_the_key_rotation_is_not_a_whole_number_of_words() {
        let words: [u16; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let rotated = rotate_left_25(&words);
        let mut sorted_original = words;
        let mut sorted_rotated = rotated;
        sorted_original.sort_unstable();
        sorted_rotated.sort_unstable();
        assert_ne!(sorted_original, sorted_rotated,
                   "the rotation only permuted the words, so it is a whole \\
                    number of 16 bit steps");
    }

    /// Round trip, over blocks and keys that contain zero words.
    #[test]
    fn test_round_trip_including_zero_words() {
        let keys: [[u8; 16]; 4] = [
            [0; 16],
            [0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7],
            [0xff; 16],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        ];
        let blocks: [[u8; 8]; 4] = [
            [0; 8],
            [0, 0, 0, 0, 0, 0, 0, 1],
            [0xff; 8],
            [1, 2, 3, 4, 5, 6, 7, 8],
        ];
        for key in keys {
            for block in blocks {
                let mut cipher = Idea::new(key.to_vec()).unwrap();
                let mut encrypted = Vec::new();
                cipher.block_encrypt(&block, &mut encrypted);
                let mut decrypted = Vec::new();
                cipher.block_decrypt(&encrypted, &mut decrypted);
                assert_eq!(hex(&decrypted), hex(&block),
                           "round trip failed for key {:?} block {:?}", key, block);
            }
        }
    }

    /// Encrypting is not decrypting.
    #[test]
    fn test_encryption_is_not_symmetric() {
        let mut cipher = Idea::new((1..=16).collect()).unwrap();
        let block = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut encrypted = Vec::new();
        let mut decrypted = Vec::new();
        cipher.block_encrypt(&block, &mut encrypted);
        cipher.block_decrypt(&block, &mut decrypted);
        assert_ne!(hex(&encrypted), hex(&decrypted));
    }

    #[test]
    fn test_a_wrong_key_length_is_an_error() {
        assert!(Idea::new(vec![0; 15]).is_err());
        assert!(Idea::new(vec![0; 17]).is_err());
        assert!(Idea::new(vec![]).is_err());
    }
}
