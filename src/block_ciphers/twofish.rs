/*
Twofish, an AES finalist by Schneier, Kelsey, Whiting, Wagner, Hall and
Ferguson.

128 bit block, 128/192/256 bit key, sixteen Feistel rounds. It lost to
Rijndael and never went away: it is in GnuPG, in TrueCrypt and its
descendants, in KeePass, and in a good deal of disk encryption chosen in
the years when people wanted something that was not AES. There is no
practical attack on the full cipher.

Here because nothing else in reach implements it. OpenSSL does not,
`python-cryptography` does not, and the reference for the tests is
therefore Botan's vector file, vendored - which carries the designers'
own numbers rather than Botan's.

## The key schedule is most of the cipher

Twofish's round function is small; what makes it Twofish is that the
S-boxes are **derived from the key**. Two 32 bit words `S0`/`S1` (four
for a 256 bit key) come out of a Reed-Solomon code over GF(2^8) applied
to the key bytes, and those words then select which of two fixed
permutations `q0`/`q1` is applied at each stage of `h`.

So there is no S-box table to check against a document. What can be
checked is `q0` and `q1`, which are fixed, and then the whole thing
against vectors.

## Three fields, three different polynomials

This is the trap, and each one is silent:

  * the **MDS matrix** multiply is in GF(2^8) mod `0x169`;
  * the **Reed-Solomon** key schedule is in GF(2^8) mod `0x14D`;
  * neither is AES's `0x11B`, and neither is the other.

Using one polynomial for both gives a cipher that encrypts,
round-trips, avalanches and matches nothing. `test_the_two_fields_are_
different` pins them apart directly, because no functional test can.

## `h` is used twice and differently

The same function `h` computes the round subkeys (at key-schedule time,
over the odd/even key words) and the round function's output (at
encryption time, over the key-derived `S` words). Writing one and
reusing it is correct and is why the code has one `h`; writing two that
drift apart is the other way this goes wrong.

## The whitening is not the rounds

Four subkeys are XORed in before the first round and four after the
last, and the output halves are **swapped** relative to the input before
the final whitening. An implementation that forgets the swap decrypts
its own ciphertext perfectly.
*/

use crate::block_ciphers::BlockCipher;

/// `q0`, from the Twofish specification's table.
const Q0: [u8; 256] = [
    0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78,
    0xe4, 0xdd, 0xd1, 0x38, 0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c,
    0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48, 0xf2, 0xd0, 0x8b, 0x30,
    0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
    0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe,
    0x16, 0x0c, 0xe3, 0x61, 0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b,
    0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1, 0xe1, 0xe6, 0xbd, 0x45,
    0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
    0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea, 0x77, 0x39, 0xaf,
    0x33, 0xc9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8,
    0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7, 0xa1, 0x1d, 0xaa, 0xed,
    0x06, 0x70, 0xb2, 0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
    0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b,
    0x5f, 0x93, 0x0a, 0xef, 0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b,
    0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64, 0x2a, 0xce, 0xcb, 0x2f,
    0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
    0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17,
    0x55, 0x1f, 0x8a, 0x7d, 0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72,
    0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6e, 0x50, 0xde, 0x68,
    0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
    0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42,
    0x4a, 0x5e, 0xc1, 0xe0,
];

/// `q1`, the other fixed permutation. **Not `q0` reordered.**
const Q1: [u8; 256] = [
    0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b,
    0x45, 0x7d, 0xe8, 0x4b, 0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1,
    0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f, 0x5e, 0xba, 0xae, 0x5b,
    0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
    0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54,
    0x92, 0x74, 0x36, 0x51, 0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96,
    0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c, 0x13, 0x95, 0x9c, 0xc7,
    0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
    0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03, 0x6f, 0x08, 0xbf,
    0x40, 0xe7, 0x2b, 0xe2, 0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9,
    0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17, 0x66, 0x94, 0xa1, 0x1d,
    0x3d, 0xf0, 0xde, 0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
    0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 0x81, 0x88, 0xee, 0x21,
    0xc4, 0x1a, 0xeb, 0xd9, 0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01,
    0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48, 0x4f, 0xf2, 0x65, 0x8e,
    0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
    0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44,
    0xe0, 0x4d, 0x43, 0x69, 0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e,
    0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc, 0x22, 0xc9, 0xc0, 0x9b,
    0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
    0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56,
    0x55, 0x09, 0xbe, 0x91,
];

/// The MDS matrix's field: GF(2^8) mod x^8 + x^6 + x^5 + x^3 + 1.
const MDS_POLYNOMIAL: u32 = 0x169;
/// The Reed-Solomon field: GF(2^8) mod x^8 + x^6 + x^3 + x^2 + 1.
/// **A different field**, and using one for both is silent.
const RS_POLYNOMIAL: u32 = 0x14d;

/// Multiply in GF(2^8) modulo `polynomial`.
const fn gf_mul(mut a: u32, mut b: u32, polynomial: u32) -> u32 {
    let mut result = 0u32;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= polynomial;
        }
    }
    result & 0xff
}

/// The MDS matrix, applied to four bytes to make a 32 bit word.
///
/// Row constants 0x01, 0xEF and 0x5B, in the arrangement the
/// specification gives. The result is little endian, which is the
/// convention Twofish uses throughout and the opposite of AES's.
const MDS: [[u32; 4]; 4] = [
    [0x01, 0xef, 0x5b, 0x5b],
    [0x5b, 0xef, 0xef, 0x01],
    [0xef, 0x5b, 0x01, 0xef],
    [0xef, 0x01, 0xef, 0x5b],
];

/// Column `j` of the MDS matrix times every byte value, as the 32 bit
/// word it contributes: the matrix is linear, so `mds(y)` is the XOR of
/// `MDS_COLUMNS[j][y[j]]` over `j`. Built at compile time from `MDS`.
const MDS_COLUMNS: [[u32; 256]; 4] = {
    let mut table = [[0u32; 256]; 4];
    let mut j = 0;
    while j < 4 {
        let mut v = 0;
        while v < 256 {
            let mut word = 0u32;
            let mut i = 0;
            while i < 4 {
                word |= gf_mul(v as u32, MDS[i][j], MDS_POLYNOMIAL) << (8 * i);
                i += 1;
            }
            table[j][v] = word;
            v += 1;
        }
        j += 1;
    }
    table
};

fn mds(y: [u8; 4]) -> u32 {
    MDS_COLUMNS[0][y[0] as usize] ^ MDS_COLUMNS[1][y[1] as usize]
        ^ MDS_COLUMNS[2][y[2] as usize] ^ MDS_COLUMNS[3][y[3] as usize]
}

/// The MDS product the way the specification writes it, row by row: the
/// reference `MDS_COLUMNS` is tested against.
#[cfg(test)]
fn mds_by_rows(y: [u8; 4]) -> u32 {
    let mut out = 0u32;
    for (i, row) in MDS.iter().enumerate() {
        let mut byte = 0u32;
        for (j, coefficient) in row.iter().enumerate() {
            byte ^= gf_mul(y[j] as u32, *coefficient, MDS_POLYNOMIAL);
        }
        out |= byte << (8 * i);
    }
    out
}

/// The Reed-Solomon step of the key schedule: eight key bytes to four.
fn rs(key: &[u8]) -> u32 {
    const MATRIX: [[u32; 8]; 4] = [
        [0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e],
        [0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5],
        [0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19],
        [0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03],
    ];
    let mut out = 0u32;
    for (i, row) in MATRIX.iter().enumerate() {
        let mut byte = 0u32;
        for (j, coefficient) in row.iter().enumerate() {
            byte ^= gf_mul(key[j] as u32, *coefficient, RS_POLYNOMIAL);
        }
        out |= byte << (8 * i);
    }
    out
}

/// `h`, used for both the subkeys and the round function.
///
/// `words` is `S` at encryption time and the odd-or-even key words at
/// schedule time; `k` is how many of them there are (2, 3 or 4).
fn h(x: u32, words: &[u32], k: usize) -> u32 {
    mds(h_bytes(x, words, k))
}

/// `h` before the MDS matrix: each byte through its own chain of `q0`/`q1`
/// lookups and key bytes. Byte `j` of the result depends only on byte `j`
/// of `x`.
fn h_bytes(x: u32, words: &[u32], k: usize) -> [u8; 4] {
    let mut y = x.to_le_bytes();

    // The stages run from the top down, and each key size adds a stage
    // on the front rather than changing the ones below it.
    if k == 4 {
        let w = words[3].to_le_bytes();
        y[0] = Q1[y[0] as usize] ^ w[0];
        y[1] = Q0[y[1] as usize] ^ w[1];
        y[2] = Q0[y[2] as usize] ^ w[2];
        y[3] = Q1[y[3] as usize] ^ w[3];
    }
    if k >= 3 {
        let w = words[2].to_le_bytes();
        y[0] = Q1[y[0] as usize] ^ w[0];
        y[1] = Q1[y[1] as usize] ^ w[1];
        y[2] = Q0[y[2] as usize] ^ w[2];
        y[3] = Q0[y[3] as usize] ^ w[3];
    }
    let w1 = words[1].to_le_bytes();
    let w0 = words[0].to_le_bytes();
    // **The key words are XORed *between* the lookups, not after
    // them.** Written with the XORs on the outside it still compiles,
    // still permutes and still round-trips - and matches nothing.
    y[0] = Q1[(Q0[(Q0[y[0] as usize] ^ w1[0]) as usize] ^ w0[0]) as usize];
    y[1] = Q0[(Q0[(Q1[y[1] as usize] ^ w1[1]) as usize] ^ w0[1]) as usize];
    y[2] = Q1[(Q1[(Q0[y[2] as usize] ^ w1[2]) as usize] ^ w0[2]) as usize];
    y[3] = Q0[(Q1[(Q1[y[3] as usize] ^ w1[3]) as usize] ^ w0[3]) as usize];
    y
}

pub struct Twofish {
    /// Eight whitening subkeys and thirty-two round subkeys.
    subkeys: [u32; 40],
    /// `g` as four tables, one per input byte: that byte's chain through
    /// `q0`, `q1` and the key-derived S words, times its MDS column. `h`
    /// is byte-wise and then linear, so `g(x)` is the XOR of the four
    /// entries. Boxed so the 4 KB is not carried inline by every cipher
    /// enum that can hold a Twofish.
    g_tables: Box<[[u32; 256]; 4]>,
}

impl Twofish {
    pub fn new(key: &[u8]) -> Result<Twofish, String> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(format!(
                "A Twofish key is 16, 24 or 32 bytes; this one is {}.", key.len()));
        }
        let k = key.len() / 8;

        // The key words, split into evens and odds.
        let word = |at: usize| u32::from_le_bytes(
            [key[at], key[at + 1], key[at + 2], key[at + 3]]);
        let mut me = [0u32; 4];
        let mut mo = [0u32; 4];
        for i in 0..k {
            me[i] = word(8 * i);
            mo[i] = word(8 * i + 4);
        }

        // The S words, from the Reed-Solomon code **in reverse order**:
        // the first eight key bytes give the *last* S word. Getting the
        // order right is invisible to anything but a vector.
        let mut s = [0u32; 4];
        for i in 0..k {
            s[k - 1 - i] = rs(&key[8 * i..8 * i + 8]);
        }

        const RHO: u32 = 0x0101_0101;
        let mut subkeys = [0u32; 40];
        for i in 0..20 {
            let a = h(2 * i as u32 * RHO, &me, k);
            let b = h((2 * i as u32 + 1) * RHO, &mo, k).rotate_left(8);
            subkeys[2 * i] = a.wrapping_add(b);
            subkeys[2 * i + 1] = a.wrapping_add(b.wrapping_mul(2)).rotate_left(9);
        }

        // Byte j of h_bytes(v replicated) is byte j's chain at v.
        let mut g_tables = Box::new([[0u32; 256]; 4]);
        for v in 0..256usize {
            let y = h_bytes(v as u32 * RHO, &s, k);
            for (j, table) in g_tables.iter_mut().enumerate() {
                table[v] = MDS_COLUMNS[j][y[j] as usize];
            }
        }

        Ok(Twofish { subkeys, g_tables })
    }

    #[inline(always)]
    fn g(&self, x: u32) -> u32 {
        let t = &*self.g_tables;
        t[0][(x & 0xff) as usize] ^ t[1][((x >> 8) & 0xff) as usize]
            ^ t[2][((x >> 16) & 0xff) as usize] ^ t[3][(x >> 24) as usize]
    }

    /// Encryption and decryption are two loops rather than one with a
    /// flag, because **the inverse round reads its inputs from the
    /// other half of the state**.
    ///
    /// The encryption round computes `g` over `R0` and `R1` and writes
    /// `R2`, `R3`; run backwards, the round's inputs `R0`, `R1` are the
    /// state's `R2`, `R3`, so `g` is applied to those. A shared body
    /// with `if encrypt` around only the rotations looks right, passes
    /// every encryption vector, and decrypts to noise - which is what
    /// this did first, and what the vector file caught.
    fn encrypt_block(&self, input: &[u8], result: &mut Vec<u8>) {
        let mut r = read_words(input);
        for (i, value) in r.iter_mut().enumerate() {
            *value ^= self.subkeys[i];
        }
        for round in 0..16 {
            let t0 = self.g(r[0]);
            let t1 = self.g(r[1].rotate_left(8));
            let f0 = t0.wrapping_add(t1).wrapping_add(self.subkeys[8 + 2 * round]);
            let f1 = t0.wrapping_add(t1.wrapping_mul(2))
                       .wrapping_add(self.subkeys[9 + 2 * round]);
            r = [(r[2] ^ f0).rotate_right(1),
                 r[3].rotate_left(1) ^ f1,
                 r[0], r[1]];
        }
        // **The halves swap before the output whitening.** Forgetting
        // this gives a cipher that decrypts its own ciphertext and
        // nobody else's.
        let swapped = [r[2], r[3], r[0], r[1]];
        for (i, value) in swapped.iter().enumerate() {
            result.extend_from_slice(&(value ^ self.subkeys[4 + i]).to_le_bytes());
        }
    }

    fn decrypt_block(&self, input: &[u8], result: &mut Vec<u8>) {
        let mut r = read_words(input);
        for (i, value) in r.iter_mut().enumerate() {
            *value ^= self.subkeys[4 + i];
        }
        // Undo the swap the encryption ended with, so what follows is
        // the state after the last round rather than a permutation of
        // it. Doing this explicitly rather than folding it into the
        // loop is what makes the round below readable as the inverse of
        // the one above.
        r = [r[2], r[3], r[0], r[1]];

        for round in (0..16).rev() {
            // `r` holds the round's *output*, so the inputs `R0` and
            // `R1` that `g` was applied to are `r[2]` and `r[3]`.
            let t0 = self.g(r[2]);
            let t1 = self.g(r[3].rotate_left(8));
            let f0 = t0.wrapping_add(t1).wrapping_add(self.subkeys[8 + 2 * round]);
            let f1 = t0.wrapping_add(t1.wrapping_mul(2))
                       .wrapping_add(self.subkeys[9 + 2 * round]);
            r = [r[2], r[3],
                 r[0].rotate_left(1) ^ f0,
                 (r[1] ^ f1).rotate_right(1)];
        }

        for (i, value) in r.iter().enumerate() {
            result.extend_from_slice(&(value ^ self.subkeys[i]).to_le_bytes());
        }
    }
}

fn read_words(input: &[u8]) -> [u32; 4] {
    let word = |at: usize| u32::from_le_bytes(
        [input[at], input[at + 1], input[at + 2], input[at + 3]]);
    [word(0), word(4), word(8), word(12)]
}

impl BlockCipher for Twofish {
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

    const VECTORS: &str = include_str!("../../vectors/twofish.vec");

    #[test]
    fn test_the_vector_file_parses_to_what_it_should() {
        let vectors = vector_file(VECTORS, "Twofish");
        assert_eq!(vectors.len(), 723, "vectors/twofish.vec should hold 723 cases");
        for (key, input, output) in &vectors {
            assert!(matches!(key.len(), 16 | 24 | 32), "odd key length {}", key.len());
            assert_eq!(input.len(), output.len());
            assert!(input.len().is_multiple_of(16));
        }
    }

    #[test]
    fn test_every_vector() {
        let mut sizes = std::collections::HashSet::new();
        for (index, (key, input, expected)) in vector_file(VECTORS, "Twofish").iter().enumerate() {
            sizes.insert(key.len());
            let mut cipher = Twofish::new(key).unwrap();
            let mut out = Vec::new();
            cipher.ecb_encrypt(input, &mut out).unwrap();
            assert_eq!(&out, expected, "vector {} ({} byte key)", index, key.len());

            let mut back = Vec::new();
            cipher.ecb_decrypt(expected, &mut back).unwrap();
            assert_eq!(&back, input, "decrypting vector {}", index);
        }
        // All three key sizes, or the file is only exercising one and
        // the other two paths through `h` are untested.
        assert_eq!(sizes, [16usize, 24, 32].into_iter().collect());
    }

    /// The two fields are different polynomials and no functional test
    /// can see a swap - the cipher still encrypts and round-trips.
    /// The MDS columns are the matrix, and the tabled `g` is `h` over the
    /// S words, for all three key lengths.
    #[test]
    fn test_the_tables_are_h() {
        let mut x = 0x0123_4567u32;
        for _ in 0..1000 {
            x = x.wrapping_mul(0x9e37_79b9).wrapping_add(0x7f4a_7c15);
            let y = x.to_le_bytes();
            assert_eq!(mds(y), mds_by_rows(y));
        }
        for key_len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..key_len as u8).map(|b| b.wrapping_mul(37)).collect();
            let cipher = Twofish::new(&key).unwrap();
            let k = key_len / 8;
            let mut s = [0u32; 4];
            for i in 0..k {
                s[k - 1 - i] = rs(&key[8 * i..8 * i + 8]);
            }
            for _ in 0..1000 {
                x = x.wrapping_mul(0x9e37_79b9).wrapping_add(0x7f4a_7c15);
                assert_eq!(cipher.g(x), h(x, &s, k), "key {key_len}, x {x:08x}");
            }
        }
    }

    #[test]
    fn test_the_two_fields_are_different() {
        assert_ne!(MDS_POLYNOMIAL, RS_POLYNOMIAL);
        // And neither is AES's.
        assert_ne!(MDS_POLYNOMIAL, 0x11b);
        assert_ne!(RS_POLYNOMIAL, 0x11b);
        // They disagree on an actual product, not just as numbers.
        let differing = (1u32..256)
            .filter(|a| gf_mul(*a, 0xef, MDS_POLYNOMIAL) != gf_mul(*a, 0xef, RS_POLYNOMIAL))
            .count();
        assert!(differing > 200, "only {differing} of 255 products differ");
    }

    /// `q0` and `q1` are both permutations, and are not each other.
    #[test]
    fn test_the_two_permutations_are_permutations_and_differ() {
        for table in [&Q0, &Q1] {
            let seen: std::collections::HashSet<u8> = table.iter().copied().collect();
            assert_eq!(seen.len(), 256, "not a permutation");
        }
        assert_ne!(Q0, Q1);
        let agreeing = (0..256).filter(|i| Q0[*i] == Q1[*i]).count();
        assert!(agreeing < 8, "q0 and q1 agreed in {agreeing} places");
    }

    #[test]
    fn test_a_wrong_key_length_is_an_error() {
        for length in [0usize, 1, 8, 15, 17, 23, 25, 31, 33, 64] {
            let error = match Twofish::new(&vec![0; length]) { Err(e) => e, Ok(_) => panic!("accepted a {length} byte key") };
            assert!(error.contains("16, 24 or 32"), "{error}");
        }
    }

    /// The output halves swap before the final whitening. An
    /// implementation that forgets it decrypts its own ciphertext
    /// perfectly, so only a foreign vector sees it - this asserts the
    /// property directly as well.
    #[test]
    fn test_encryption_is_not_its_own_inverse() {
        let mut cipher = Twofish::new(&[0x2b; 16]).unwrap();
        let plain = [0x11u8; 16];
        let mut once = Vec::new();
        cipher.block_encrypt(&plain, &mut once);
        let mut twice = Vec::new();
        cipher.block_encrypt(&once, &mut twice);
        assert_ne!(twice, plain);
    }

    #[test]
    fn test_a_one_bit_key_change_changes_everything() {
        let mut base = Twofish::new(&[0u8; 32]).unwrap();
        let mut first = Vec::new();
        base.block_encrypt(&[0u8; 16], &mut first);
        for bit in 0..256 {
            let mut key = vec![0u8; 32];
            key[bit / 8] ^= 1 << (bit % 8);
            let mut other = Twofish::new(&key).unwrap();
            let mut out = Vec::new();
            other.block_encrypt(&[0u8; 16], &mut out);
            assert_ne!(out, first, "bit {bit} of the key changed nothing");
        }
    }
}

