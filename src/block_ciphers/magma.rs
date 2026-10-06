/*
Magma (GOST R 34.12-2015), the 64 bit Russian block cipher.

The same Feistel network as GOST 28147-89, which is in `gost.rs`, with two
differences that make it a different cipher:

  * **The S-box is fixed.** 28147-89 left it as a parameter, which meant
    two implementations could both be correct and not interoperate. Magma
    fixes it at `id-tc26-gost-28147-param-Z`.

  * **Everything is big endian.** 28147-89 reads its key words and its
    block little endian; Magma reads both big endian, because
    GOST R 34.12-2015 defines them as 64 and 256 bit *numbers* rather than
    as byte strings. Nothing else changes - which is exactly why it is
    worth saying: the same key and the same plaintext produce two
    different ciphertexts under the two standards, and each is correct
    under its own.

That is the whole of it. The Feistel function is `rotl32(S(a + k mod
2^32), 11)`, the key schedule is the eight subkeys three times forwards
and once backwards, and the last round does not swap.

Two things an implementation gets wrong:

  * **The S-box is applied with `pi_0` to the *least significant* nibble.**
    Reversing the rows produces a cipher that is self-consistent and
    agrees with nothing.

  * **The addition is modulo 2^32, not XOR.** That is what makes this a
    Feistel network rather than an SP-network, and a wrong one still
    round-trips.

Checked against GOST R 34.12-2015 section A.2, and by
`tools/src/bin/diff_gost_ciphers.rs` against a reference written from the
standard - nothing on this machine implements Magma, so the second
implementation is a second reading of the specification rather than
somebody else's code.

The S-box is not typed from memory: it is byte-identical to the
`id-tc26-gost-28147-param-Z` table already in `gost.rs` and to the one in
the `gostcrypto` Python package, and `tests` pins the two together so
they cannot drift.
*/

use crate::block_ciphers::BlockCipher;

pub const BLOCK_SIZE: usize = 8;
pub const KEY_SIZE: usize = 32;

/// `id-tc26-gost-28147-param-Z`, the substitution GOST R 34.12-2015 fixes.
///
/// Row `j` is applied to nibble `j` counting from the **least
/// significant**. Row 0 first is not a convention that can be guessed at:
/// the reversed order produces a cipher that works perfectly against
/// itself.
const SBOX: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

/// The substitution, applied nibble by nibble.
const fn substitute(value: u32) -> u32 {
    let mut out = 0u32;
    let mut index = 0;
    while index < 8 {
        let nibble = ((value >> (4 * index)) & 0xf) as usize;
        out |= (SBOX[index][nibble] as u32) << (4 * index);
        index += 1;
    }
    out
}

/// The substitution and the rotation for one input byte at a time:
/// `TABLE[i][v]` is `substitute` of `v` in byte `i`, rotated left eleven.
/// Each S-box reads its own nibble, so the round is the XOR of four
/// entries. Built at compile time from `substitute`.
const TABLE: [[u32; 256]; 4] = {
    let mut table = [[0u32; 256]; 4];
    let mut i = 0;
    while i < 4 {
        let mut v = 0;
        while v < 256 {
            // The other bytes are zero, and every S-box's output for zero
            // is in `substitute(0)`; masking to this byte's two nibbles
            // keeps only this byte's contribution.
            let mask = 0xffu32 << (8 * i);
            table[i][v] = (substitute((v as u32) << (8 * i)) & mask).rotate_left(11);
            v += 1;
        }
        i += 1;
    }
    table
};

/// The round function: add the key modulo 2^32, substitute, rotate left
/// eleven.
///
/// The addition is what makes the round non-linear over GF(2). Using XOR
/// instead gives a cipher that encrypts and decrypts correctly against
/// itself and is much weaker.
#[inline]
fn round(value: u32, key: u32) -> u32 {
    let x = value.wrapping_add(key);
    TABLE[0][(x & 0xff) as usize] ^ TABLE[1][((x >> 8) & 0xff) as usize]
        ^ TABLE[2][((x >> 16) & 0xff) as usize] ^ TABLE[3][(x >> 24) as usize]
}

#[derive(Clone)]
pub struct Magma {
    /// The eight subkeys, big endian from the start of the key.
    subkeys: [u32; 8],
}

impl core::fmt::Debug for Magma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Magma {{ key redacted }}")
    }
}

impl Magma {
    /// A 256 bit key, and only that.
    pub fn new(key: &[u8]) -> Result<Magma, String> {
        if key.len() != KEY_SIZE {
            return Err(format!(
                "Magma takes a {} byte key; got {}.", KEY_SIZE, key.len()));
        }
        let mut subkeys = [0u32; 8];
        for (index, subkey) in subkeys.iter_mut().enumerate() {
            // Big endian. GOST 28147-89 reads these little endian, and the
            // same bytes are then a different key.
            *subkey = u32::from_be_bytes([key[4 * index], key[4 * index + 1],
                                          key[4 * index + 2], key[4 * index + 3]]);
        }
        Ok(Magma { subkeys })
    }

    /// The 32 round keys in order: the eight subkeys three times forwards,
    /// then once backwards.
    ///
    /// The reversal in the last eight is what makes decryption the same
    /// function with the schedule reversed. A schedule that ran forwards
    /// four times would give a cipher that cannot be decrypted at all,
    /// which at least fails loudly - unlike most of the mistakes here.
    fn schedule(&self, index: usize) -> u32 {
        if index < 24 {
            self.subkeys[index % 8]
        } else {
            self.subkeys[7 - (index - 24)]
        }
    }

    fn transform(&self, input: &[u8], forward: bool) -> [u8; BLOCK_SIZE] {
        let mut left = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        let mut right = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);

        for step in 0..31 {
            let key = self.schedule(if forward { step } else { 31 - step });
            let next = left ^ round(right, key);
            left = right;
            right = next;
        }
        // The last round does not swap. Leaving the swap in gives a cipher
        // that is its own inverse, which is not what a Feistel network is
        // for and is not what the standard says.
        let key = self.schedule(if forward { 31 } else { 0 });
        left ^= round(right, key);

        let mut out = [0u8; BLOCK_SIZE];
        out[..4].copy_from_slice(&left.to_be_bytes());
        out[4..].copy_from_slice(&right.to_be_bytes());
        out
    }
}

impl BlockCipher for Magma {
    fn blocksize(&self) -> usize {
        BLOCK_SIZE
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&self.transform(input, true));
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&self.transform(input, false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tabled round is substitute-then-rotate.
    #[test]
    fn test_the_table_is_the_round() {
        let mut x = 0x0123_4567u32;
        for _ in 0..20000 {
            x = x.wrapping_mul(0x9e37_79b9).wrapping_add(0x7f4a_7c15);
            assert_eq!(round(x, 0x1357_9bdf), substitute(x.wrapping_add(0x1357_9bdf)).rotate_left(11));
        }
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    const KEY: &str = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    /// GOST R 34.12-2015 section A.2.
    #[test]
    fn test_the_standards_vector() {
        let mut cipher = Magma::new(&unhex(KEY)).unwrap();
        let plaintext = unhex("fedcba9876543210");

        let mut out = Vec::new();
        cipher.block_encrypt(&plaintext, &mut out);
        assert_eq!(hex(&out), "4ee901e5c2d8ca3d");

        let mut back = Vec::new();
        cipher.block_decrypt(&out, &mut back);
        assert_eq!(back, plaintext);
    }

    /// The S-box must stay identical to the one `gost.rs` already carries
    /// for the same parameter set. Two copies of a table drift; this makes
    /// the drift a test failure rather than a cipher that disagrees with
    /// the other half of the same library.
    #[test]
    fn test_the_sbox_matches_the_one_in_gost_rs() {
        let cipher = crate::block_ciphers::gost::GostCrypto::new(
            vec![0u8; 32], "id-tc26-gost-28147-param-Z".to_string()).unwrap();
        let theirs = cipher.sbox_rows();
        assert_eq!(theirs.len(), 8);
        for (index, row) in SBOX.iter().enumerate() {
            assert_eq!(theirs[index], row.to_vec(), "S-box row {}", index);
        }
    }

    /// The nibble order is not guessable and reversing it gives a cipher
    /// that works perfectly against itself, so it is pinned: row `j` acts
    /// on nibble `j` counting from the least significant end.
    #[test]
    fn test_the_substitution_applies_row_zero_to_the_low_nibble() {
        let base = substitute(0);
        for (position, row) in SBOX.iter().enumerate() {
            for value in 0..16u32 {
                let input = value << (4 * position);
                let output = substitute(input);

                // Only this nibble may differ from substitute(0)...
                let changed = output ^ base;
                assert_eq!(changed & !(0xf << (4 * position)), 0,
                           "row {} value {} changed another nibble", position, value);
                // ...and it must become what this row says.
                assert_eq!((output >> (4 * position)) & 0xf, row[value as usize] as u32,
                           "row {} value {}", position, value);
            }
        }

        // The reversed order would be a different function. If it were
        // not, the ordering would not matter and this test would be
        // proving nothing.
        let reversed: u32 = (0..8)
            .map(|j| (SBOX[7 - j][((0x1234_5678u32 >> (4 * j)) & 0xf) as usize] as u32)
                     << (4 * j))
            .fold(0, |a, b| a | b);
        assert_ne!(substitute(0x1234_5678), reversed);
    }

    /// Magma is GOST 28147-89 read the other way round, so the same key
    /// and block must give a *different* answer under the two.
    #[test]
    fn test_magma_is_not_gost_28147_with_the_same_bytes() {
        let key = unhex(KEY);
        let plaintext = unhex("fedcba9876543210");

        let mut magma = Magma::new(&key).unwrap();
        let mut ours = Vec::new();
        magma.block_encrypt(&plaintext, &mut ours);

        let mut old = crate::block_ciphers::gost::GostCrypto::new(
            key, "id-tc26-gost-28147-param-Z".to_string()).unwrap();
        let mut theirs = Vec::new();
        old.block_encrypt(&plaintext, &mut theirs);

        assert_ne!(ours, theirs,
                   "the byte order is the whole difference; if these agree, \
                    one of the two is reading its words the wrong way");
    }

    #[test]
    fn test_only_a_256_bit_key_is_accepted() {
        for length in [0usize, 8, 16, 31, 33] {
            assert!(Magma::new(&vec![0u8; length]).is_err(), "{} bytes", length);
        }
        assert!(Magma::new(&[0u8; 32]).is_ok());
    }

    #[test]
    fn test_it_round_trips_through_cbc() {
        let mut cipher = Magma::new(&unhex(KEY)).unwrap();
        let plaintext: Vec<u8> = (0..48u8).collect();
        let iv = vec![0x3cu8; BLOCK_SIZE];

        let mut ciphertext = Vec::new();
        cipher.cbc_encrypt(&plaintext, &mut ciphertext, iv.clone()).unwrap();
        let mut back = Vec::new();
        cipher.cbc_decrypt(&ciphertext, &mut back, iv).unwrap();
        assert_eq!(back, plaintext);
    }

    /// The final round has no swap. With one, the cipher becomes its own
    /// inverse and `block_encrypt` twice returns the plaintext - which
    /// round-trips perfectly and is a different, broken cipher.
    #[test]
    fn test_encrypting_twice_is_not_the_identity() {
        let mut cipher = Magma::new(&unhex(KEY)).unwrap();
        let plaintext = unhex("fedcba9876543210");
        let mut once = Vec::new();
        cipher.block_encrypt(&plaintext, &mut once);
        let mut twice = Vec::new();
        cipher.block_encrypt(&once, &mut twice);
        assert_ne!(twice, plaintext);
    }
}
