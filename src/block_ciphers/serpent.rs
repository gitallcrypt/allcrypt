/*
Serpent, an AES finalist by Anderson, Biham and Knudsen.

128 bit block, 128/192/256 bit key, thirty-two rounds. It came second to
Rijndael and is generally reckoned the most conservative of the five
finalists - twice the rounds anyone could break then, and nobody has
closed the gap since. It is in GnuPG, in TrueCrypt's descendants and in
a good deal of disk encryption chosen by people who wanted margin rather
than speed.

Nothing in reach implements it: not OpenSSL, not `python-cryptography`.
The reference is Botan's vendored vector file, which carries the
designers' own numbers.

## The bitslice form is the cipher

Serpent is specified two ways and they are the same function. The
"standard" form applies a 4-bit S-box to each nibble of a 128 bit block;
the **bitslice** form applies the same S-box to one bit taken from each
of four 32 bit words, thirty-two S-boxes at a time in parallel. The
bitslice form is what every implementation uses and what the test
vectors are stated in - and the two differ by an initial and final
permutation, so an implementation that mixes them produces a
self-consistent cipher that matches nothing.

This is the bitslice form throughout. There is no IP/FP here, and there
should not be: the vectors are bitslice vectors.

## Eight S-boxes, used in rotation, and their inverses are separate

`S0..S7` are applied in order and repeat every eight rounds. Decryption
needs `S0^-1..S7^-1`, which are eight *different* tables - deriving them
at run time from the forward ones is possible and is a fifth place to
get an index backwards, so they are stated and then **checked against
each other** at test time: `test_the_inverse_boxes_invert` composes
every box with its inverse over all sixteen inputs.

## The last round is different

Rounds 0 to 30 are `S_i(X ^ K_i)` then the linear transform. Round 31
applies `S7`, then XORs `K32` instead of the linear transform - so there
are **33** subkeys, not 32. An implementation with 32 and a linear
transform on the end is a different cipher, and nothing about it looks
wrong.
*/

use crate::block_ciphers::BlockCipher;

/// The eight S-boxes, as 4-bit lookup tables.
const SBOX: [[u8; 16]; 8] = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
];

/// The inverses. Stated rather than derived, and checked against the
/// forward boxes by `test_the_inverse_boxes_invert`.
const SBOX_INVERSE: [[u8; 16]; 8] = [
    [13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2],
    [5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0],
    [12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7],
    [0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1],
    [5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1],
    [8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0],
    [15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11],
    [3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2],
];

/// PHI, the golden-ratio constant the key schedule mixes in.
const PHI: u32 = 0x9e37_79b9;

/// Each output bit of a 4-bit S-box as its algebraic normal form: bit `m`
/// of `anf[b]` set means the monomial "the product of the inputs named by
/// the bits of `m`" is in output bit `b`'s XOR. Computed at compile time
/// from the table by the Moebius transform, so the S-box is still read
/// from the specification's table and nowhere else.
const fn anf(table: &[u8; 16]) -> [u16; 4] {
    let mut out = [0u16; 4];
    let mut b = 0;
    while b < 4 {
        let mut a = [0u8; 16];
        let mut x = 0;
        while x < 16 {
            a[x] = (table[x] >> b) & 1;
            x += 1;
        }
        let mut i = 0;
        while i < 4 {
            let mut x = 0;
            while x < 16 {
                if x & (1 << i) != 0 {
                    a[x] ^= a[x ^ (1 << i)];
                }
                x += 1;
            }
            i += 1;
        }
        let mut m = 0;
        while m < 16 {
            out[b] |= (a[m] as u16) << m;
            m += 1;
        }
        b += 1;
    }
    out
}

const fn anf_all(tables: &[[u8; 16]; 8]) -> [[u16; 4]; 8] {
    let mut out = [[0u16; 4]; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = anf(&tables[i]);
        i += 1;
    }
    out
}

const ANF: [[u16; 4]; 8] = anf_all(&SBOX);
const ANF_INVERSE: [[u16; 4]; 8] = anf_all(&SBOX_INVERSE);

/// One S-box over four words, bitsliced, from its normal form: the
/// fifteen non-constant monomials of `x0..x3` (eleven ANDs), and each
/// output word the XOR of its monomials. `forms` is a constant at every
/// call site, so the compiler keeps only the terms that are present and
/// the result is straight-line AND/XOR/NOT - no lookup, no branch on the
/// data.
#[inline(always)]
fn sbox_from_anf(forms: [u16; 4], x: &mut [u32; 4]) {
    let [x0, x1, x2, x3] = *x;
    let mut m = [0u32; 16];
    m[0] = !0;
    m[1] = x0;
    m[2] = x1;
    m[3] = x0 & x1;
    m[4] = x2;
    m[5] = x0 & x2;
    m[6] = x1 & x2;
    m[7] = m[3] & x2;
    // m[8] is m[0] & x3, which is x3.
    for i in 0..8 {
        m[8 + i] = m[i] & x3;
    }
    for (b, form) in forms.iter().enumerate() {
        let mut y = 0u32;
        for (k, monomial) in m.iter().enumerate() {
            if (form >> k) & 1 == 1 {
                y ^= monomial;
            }
        }
        x[b] = y;
    }
}

/// Apply one S-box across four words, bitsliced: bit `i` of each of the
/// four words forms one nibble, `x0` the low bit.
fn apply_sbox(box_index: usize, x: &mut [u32; 4]) {
    match box_index {
        0 => sbox_from_anf(ANF[0], x),
        1 => sbox_from_anf(ANF[1], x),
        2 => sbox_from_anf(ANF[2], x),
        3 => sbox_from_anf(ANF[3], x),
        4 => sbox_from_anf(ANF[4], x),
        5 => sbox_from_anf(ANF[5], x),
        6 => sbox_from_anf(ANF[6], x),
        _ => sbox_from_anf(ANF[7], x),
    }
}

fn apply_sbox_inverse(box_index: usize, x: &mut [u32; 4]) {
    match box_index {
        0 => sbox_from_anf(ANF_INVERSE[0], x),
        1 => sbox_from_anf(ANF_INVERSE[1], x),
        2 => sbox_from_anf(ANF_INVERSE[2], x),
        3 => sbox_from_anf(ANF_INVERSE[3], x),
        4 => sbox_from_anf(ANF_INVERSE[4], x),
        5 => sbox_from_anf(ANF_INVERSE[5], x),
        6 => sbox_from_anf(ANF_INVERSE[6], x),
        _ => sbox_from_anf(ANF_INVERSE[7], x),
    }
}

/// The S-box one bit position at a time, by table lookup: the reference
/// the normal forms are tested against.
///
/// The nibble is `x0` bit i as the **low** bit through `x3` bit i as the
/// high one. Reading it the other way round gives a cipher that is
/// perfectly invertible and is not Serpent.
#[cfg(test)]
fn slice_through(table: &[u8; 16], x: &mut [u32; 4]) {
    let (mut y0, mut y1, mut y2, mut y3) = (0u32, 0u32, 0u32, 0u32);
    for bit in 0..32 {
        let nibble = (((x[0] >> bit) & 1)
                      | (((x[1] >> bit) & 1) << 1)
                      | (((x[2] >> bit) & 1) << 2)
                      | (((x[3] >> bit) & 1) << 3)) as usize;
        let out = table[nibble] as u32;
        y0 |= (out & 1) << bit;
        y1 |= ((out >> 1) & 1) << bit;
        y2 |= ((out >> 2) & 1) << bit;
        y3 |= ((out >> 3) & 1) << bit;
    }
    *x = [y0, y1, y2, y3];
}

/// The linear transform, applied after every round but the last.
fn linear(x: &mut [u32; 4]) {
    x[0] = x[0].rotate_left(13);
    x[2] = x[2].rotate_left(3);
    x[1] ^= x[0] ^ x[2];
    x[3] ^= x[2] ^ (x[0] << 3);
    x[1] = x[1].rotate_left(1);
    x[3] = x[3].rotate_left(7);
    x[0] ^= x[1] ^ x[3];
    x[2] ^= x[3] ^ (x[1] << 7);
    x[0] = x[0].rotate_left(5);
    x[2] = x[2].rotate_left(22);
}

fn linear_inverse(x: &mut [u32; 4]) {
    x[2] = x[2].rotate_right(22);
    x[0] = x[0].rotate_right(5);
    x[2] ^= x[3] ^ (x[1] << 7);
    x[0] ^= x[1] ^ x[3];
    x[3] = x[3].rotate_right(7);
    x[1] = x[1].rotate_right(1);
    x[3] ^= x[2] ^ (x[0] << 3);
    x[1] ^= x[0] ^ x[2];
    x[2] = x[2].rotate_right(3);
    x[0] = x[0].rotate_right(13);
}

pub struct Serpent {
    /// **Thirty-three** subkeys of four words. The last round XORs a
    /// subkey where the others apply the linear transform.
    subkeys: [[u32; 4]; 33],
}

impl Serpent {
    pub fn new(key: Vec<u8>) -> Result<Serpent, String> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(format!(
                "A Serpent key is 16, 24 or 32 bytes; this one is {}.", key.len()));
        }

        // **A short key is padded with a single 1 bit, not with
        // zeros.** The specification extends any key below 256 bits by
        // appending `1` and then zeros, so a 128 bit key of all zeros
        // is *not* the same as a 256 bit key of all zeros - and an
        // implementation that zero-pads produces a cipher that agrees
        // with itself and with nothing else. Only the multi-key-size
        // vectors catch it.
        let mut padded = key.clone();
        if padded.len() < 32 {
            padded.push(0x01);
            padded.resize(32, 0);
        }

        let mut w = [0u32; 140];
        for (i, word) in w.iter_mut().take(8).enumerate() {
            *word = u32::from_le_bytes([padded[4 * i], padded[4 * i + 1],
                                        padded[4 * i + 2], padded[4 * i + 3]]);
        }
        // w[8..140] are the real schedule; the first eight are the key
        // itself and are consumed by the recurrence.
        for i in 8..140 {
            let value = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1]
                        ^ PHI ^ (i as u32 - 8);
            w[i] = value.rotate_left(11);
        }

        let mut subkeys = [[0u32; 4]; 33];
        for (round, subkey) in subkeys.iter_mut().enumerate() {
            // The S-box used for round `i`'s subkey is `(3 - i) mod 8`,
            // counting *backwards* - not the same index as the round
            // uses on the data.
            let which = (3 + 8 - (round % 8)) % 8;
            let mut block = [w[8 + 4 * round], w[9 + 4 * round],
                             w[10 + 4 * round], w[11 + 4 * round]];
            apply_sbox(which, &mut block);
            *subkey = block;
        }

        Ok(Serpent { subkeys })
    }

    fn encrypt_block(&self, input: &[u8], result: &mut Vec<u8>) {
        let mut x = read_words(input);
        for round in 0..31 {
            for (i, value) in x.iter_mut().enumerate() {
                *value ^= self.subkeys[round][i];
            }
            apply_sbox(round % 8, &mut x);
            linear(&mut x);
        }
        // The last round: S7, then a subkey where the linear transform
        // would be. This is why there are 33 subkeys.
        for (i, value) in x.iter_mut().enumerate() {
            *value ^= self.subkeys[31][i];
        }
        apply_sbox(7, &mut x);
        for (i, value) in x.iter_mut().enumerate() {
            *value ^= self.subkeys[32][i];
        }
        write_words(&x, result);
    }

    fn decrypt_block(&self, input: &[u8], result: &mut Vec<u8>) {
        let mut x = read_words(input);
        for (i, value) in x.iter_mut().enumerate() {
            *value ^= self.subkeys[32][i];
        }
        apply_sbox_inverse(7, &mut x);
        for (i, value) in x.iter_mut().enumerate() {
            *value ^= self.subkeys[31][i];
        }
        for round in (0..31).rev() {
            linear_inverse(&mut x);
            apply_sbox_inverse(round % 8, &mut x);
            for (i, value) in x.iter_mut().enumerate() {
                *value ^= self.subkeys[round][i];
            }
        }
        write_words(&x, result);
    }
}

fn read_words(input: &[u8]) -> [u32; 4] {
    let word = |at: usize| u32::from_le_bytes(
        [input[at], input[at + 1], input[at + 2], input[at + 3]]);
    [word(0), word(4), word(8), word(12)]
}

fn write_words(x: &[u32; 4], result: &mut Vec<u8>) {
    for value in x {
        result.extend_from_slice(&value.to_le_bytes());
    }
}

impl BlockCipher for Serpent {
    fn blocksize(&self) -> usize { 16 }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        self.encrypt_block(input, result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        self.decrypt_block(input, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::vector_file;

    /// The normal forms against the tables, every box both ways, on
    /// words that put all sixteen nibbles in every bit position.
    #[test]
    fn test_the_normal_forms_are_the_tables() {
        let mut state = 0x9e37_79b9u32;
        for _ in 0..64 {
            let mut x = [0u32; 4];
            for word in x.iter_mut() {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *word = state;
            }
            for b in 0..8 {
                let (mut fast, mut slow) = (x, x);
                apply_sbox(b, &mut fast);
                slice_through(&SBOX[b], &mut slow);
                assert_eq!(fast, slow, "S{b}");
                let (mut fast, mut slow) = (x, x);
                apply_sbox_inverse(b, &mut fast);
                slice_through(&SBOX_INVERSE[b], &mut slow);
                assert_eq!(fast, slow, "S{b} inverse");
            }
        }
    }

    const VECTORS: &str = include_str!("../../vectors/serpent.vec");

    #[test]
    fn test_the_vector_file_parses_to_what_it_should() {
        let vectors = vector_file(VECTORS, "Serpent");
        assert_eq!(vectors.len(), 1047, "vectors/serpent.vec should hold 1047 cases");
        for (key, input, output) in &vectors {
            assert!(matches!(key.len(), 16 | 24 | 32));
            assert_eq!(input.len(), output.len());
            assert!(input.len().is_multiple_of(16));
        }
    }

    #[test]
    fn test_every_vector() {
        let mut sizes = std::collections::HashSet::new();
        for (index, (key, input, expected)) in vector_file(VECTORS, "Serpent").iter().enumerate() {
            sizes.insert(key.len());
            let mut cipher = Serpent::new(key.clone()).unwrap();
            let mut out = Vec::new();
            cipher.ecb_encrypt(input, &mut out).unwrap();
            assert_eq!(&out, expected, "vector {} ({} byte key)", index, key.len());

            let mut back = Vec::new();
            cipher.ecb_decrypt(expected, &mut back).unwrap();
            assert_eq!(&back, input, "decrypting vector {}", index);
        }
        assert_eq!(sizes, [16usize, 24, 32].into_iter().collect());
    }

    /// The inverse tables are stated rather than derived, so they are
    /// checked against the forward ones. Two tables that do not compose
    /// to the identity give a cipher that encrypts correctly and
    /// decrypts to noise - which is exactly the failure Twofish's
    /// decryption had, found the same way.
    #[test]
    fn test_the_inverse_boxes_invert() {
        for which in 0..8 {
            for input in 0..16u8 {
                let forward = SBOX[which][input as usize];
                assert_eq!(SBOX_INVERSE[which][forward as usize], input,
                           "S{which} does not invert at {input}");
            }
            // And each is a permutation in its own right.
            let seen: std::collections::HashSet<u8> = SBOX[which].iter().copied().collect();
            assert_eq!(seen.len(), 16, "S{which} is not a permutation");
        }
    }

    /// The linear transform and its inverse, likewise - written out
    /// separately, in opposite order, with every rotation reversed.
    #[test]
    fn test_the_linear_transform_inverts() {
        for seed in 0..64u32 {
            let original = [seed.wrapping_mul(0x9e37_79b9),
                            seed.wrapping_mul(0x8542_1234) ^ 0xdead_beef,
                            !seed, seed.rotate_left(17)];
            let mut x = original;
            linear(&mut x);
            assert_ne!(x, original, "the transform did nothing at seed {seed}");
            linear_inverse(&mut x);
            assert_eq!(x, original, "the transform did not invert at seed {seed}");
        }
    }

    /// **A short key is padded with a 1 bit, not with zeros.** So a 16
    /// byte zero key and a 32 byte zero key are different keys, and an
    /// implementation that zero-pads makes them the same.
    #[test]
    fn test_a_short_key_is_not_the_same_as_a_zero_padded_long_one() {
        let mut short = Serpent::new(vec![0u8; 16]).unwrap();
        let mut long = Serpent::new(vec![0u8; 32]).unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        short.block_encrypt(&[0u8; 16], &mut a);
        long.block_encrypt(&[0u8; 16], &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn test_a_wrong_key_length_is_an_error() {
        for length in [0usize, 1, 15, 17, 23, 25, 31, 33, 64] {
            match Serpent::new(vec![0; length]) {
                Err(error) => assert!(error.contains("16, 24 or 32"), "{error}"),
                Ok(_) => panic!("accepted a {length} byte key"),
            }
        }
    }

    #[test]
    fn test_a_one_bit_key_change_changes_everything() {
        let mut base = Serpent::new(vec![0u8; 32]).unwrap();
        let mut first = Vec::new();
        base.block_encrypt(&[0u8; 16], &mut first);
        for bit in 0..256 {
            let mut key = vec![0u8; 32];
            key[bit / 8] ^= 1 << (bit % 8);
            let mut other = Serpent::new(key).unwrap();
            let mut out = Vec::new();
            other.block_encrypt(&[0u8; 16], &mut out);
            assert_ne!(out, first, "bit {bit} of the key changed nothing");
        }
    }
}
