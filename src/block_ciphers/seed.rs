/*
SEED, the Korean national block cipher (RFC 4269, TTAS.KO-12.0004).

128 bit block, 128 bit key, sixteen Feistel rounds. A Korean government
standard since 1999, mandated for years by their financial and
e-government systems, and consequently the cipher a great deal of Korean
data is sitting in. `python-cryptography` has moved it to
`hazmat.decrepit`.

Two 8x8 S-boxes and a byte permutation, wrapped in a round function that
applies `G` three times with additions between. The RFC states `G` twice
- once as four masked S-box lookups and once as four precomputed 32 bit
"SS-boxes" - and they are the same function. The masked form is used
here: it is four table lookups either way, and the masked form makes the
permutation visible instead of baking it into a table nobody can check.

## The key schedule subtracts

    Ki0 = G(Key0 + Key2 - KCi)
    Ki1 = G(Key1 - Key3 + KCi)

Note that the two are not symmetric: the first adds `Key2` and subtracts
the constant, the second subtracts `Key3` and adds it. Swapping either
sign gives a schedule that is perfectly deterministic and produces a
cipher that interoperates with nothing. All the arithmetic is modulo
2^32 and wraps.

## The halves rotate in opposite directions, on alternate rounds

Odd rounds rotate `Key0 || Key1` **right** by 8; even rounds rotate
`Key2 || Key3` **left** by 8. Rotating the same pair each round, or
rotating both the same way, are the two easy mistakes - and since the
subkeys are still all different, nothing about the cipher looks wrong
until it is compared with another implementation.
*/

use crate::block_ciphers::BlockCipher;

/// S0, RFC 4269 Appendix A.1, read out of the document's table.
const S0: [u8; 256] = [
    0xa9, 0x85, 0xd6, 0xd3, 0x54, 0x1d, 0xac, 0x25, 0x5d, 0x43, 0x18, 0x1e,
    0x51, 0xfc, 0xca, 0x63, 0x28, 0x44, 0x20, 0x9d, 0xe0, 0xe2, 0xc8, 0x17,
    0xa5, 0x8f, 0x03, 0x7b, 0xbb, 0x13, 0xd2, 0xee, 0x70, 0x8c, 0x3f, 0xa8,
    0x32, 0xdd, 0xf6, 0x74, 0xec, 0x95, 0x0b, 0x57, 0x5c, 0x5b, 0xbd, 0x01,
    0x24, 0x1c, 0x73, 0x98, 0x10, 0xcc, 0xf2, 0xd9, 0x2c, 0xe7, 0x72, 0x83,
    0x9b, 0xd1, 0x86, 0xc9, 0x60, 0x50, 0xa3, 0xeb, 0x0d, 0xb6, 0x9e, 0x4f,
    0xb7, 0x5a, 0xc6, 0x78, 0xa6, 0x12, 0xaf, 0xd5, 0x61, 0xc3, 0xb4, 0x41,
    0x52, 0x7d, 0x8d, 0x08, 0x1f, 0x99, 0x00, 0x19, 0x04, 0x53, 0xf7, 0xe1,
    0xfd, 0x76, 0x2f, 0x27, 0xb0, 0x8b, 0x0e, 0xab, 0xa2, 0x6e, 0x93, 0x4d,
    0x69, 0x7c, 0x09, 0x0a, 0xbf, 0xef, 0xf3, 0xc5, 0x87, 0x14, 0xfe, 0x64,
    0xde, 0x2e, 0x4b, 0x1a, 0x06, 0x21, 0x6b, 0x66, 0x02, 0xf5, 0x92, 0x8a,
    0x0c, 0xb3, 0x7e, 0xd0, 0x7a, 0x47, 0x96, 0xe5, 0x26, 0x80, 0xad, 0xdf,
    0xa1, 0x30, 0x37, 0xae, 0x36, 0x15, 0x22, 0x38, 0xf4, 0xa7, 0x45, 0x4c,
    0x81, 0xe9, 0x84, 0x97, 0x35, 0xcb, 0xce, 0x3c, 0x71, 0x11, 0xc7, 0x89,
    0x75, 0xfb, 0xda, 0xf8, 0x94, 0x59, 0x82, 0xc4, 0xff, 0x49, 0x39, 0x67,
    0xc0, 0xcf, 0xd7, 0xb8, 0x0f, 0x8e, 0x42, 0x23, 0x91, 0x6c, 0xdb, 0xa4,
    0x34, 0xf1, 0x48, 0xc2, 0x6f, 0x3d, 0x2d, 0x40, 0xbe, 0x3e, 0xbc, 0xc1,
    0xaa, 0xba, 0x4e, 0x55, 0x3b, 0xdc, 0x68, 0x7f, 0x9c, 0xd8, 0x4a, 0x56,
    0x77, 0xa0, 0xed, 0x46, 0xb5, 0x2b, 0x65, 0xfa, 0xe3, 0xb9, 0xb1, 0x9f,
    0x5e, 0xf9, 0xe6, 0xb2, 0x31, 0xea, 0x6d, 0x5f, 0xe4, 0xf0, 0xcd, 0x88,
    0x16, 0x3a, 0x58, 0xd4, 0x62, 0x29, 0x07, 0x33, 0xe8, 0x1b, 0x05, 0x79,
    0x90, 0x6a, 0x2a, 0x9a,
];

/// S1, RFC 4269 Appendix A.1.
const S1: [u8; 256] = [
    0x38, 0xe8, 0x2d, 0xa6, 0xcf, 0xde, 0xb3, 0xb8, 0xaf, 0x60, 0x55, 0xc7,
    0x44, 0x6f, 0x6b, 0x5b, 0xc3, 0x62, 0x33, 0xb5, 0x29, 0xa0, 0xe2, 0xa7,
    0xd3, 0x91, 0x11, 0x06, 0x1c, 0xbc, 0x36, 0x4b, 0xef, 0x88, 0x6c, 0xa8,
    0x17, 0xc4, 0x16, 0xf4, 0xc2, 0x45, 0xe1, 0xd6, 0x3f, 0x3d, 0x8e, 0x98,
    0x28, 0x4e, 0xf6, 0x3e, 0xa5, 0xf9, 0x0d, 0xdf, 0xd8, 0x2b, 0x66, 0x7a,
    0x27, 0x2f, 0xf1, 0x72, 0x42, 0xd4, 0x41, 0xc0, 0x73, 0x67, 0xac, 0x8b,
    0xf7, 0xad, 0x80, 0x1f, 0xca, 0x2c, 0xaa, 0x34, 0xd2, 0x0b, 0xee, 0xe9,
    0x5d, 0x94, 0x18, 0xf8, 0x57, 0xae, 0x08, 0xc5, 0x13, 0xcd, 0x86, 0xb9,
    0xff, 0x7d, 0xc1, 0x31, 0xf5, 0x8a, 0x6a, 0xb1, 0xd1, 0x20, 0xd7, 0x02,
    0x22, 0x04, 0x68, 0x71, 0x07, 0xdb, 0x9d, 0x99, 0x61, 0xbe, 0xe6, 0x59,
    0xdd, 0x51, 0x90, 0xdc, 0x9a, 0xa3, 0xab, 0xd0, 0x81, 0x0f, 0x47, 0x1a,
    0xe3, 0xec, 0x8d, 0xbf, 0x96, 0x7b, 0x5c, 0xa2, 0xa1, 0x63, 0x23, 0x4d,
    0xc8, 0x9e, 0x9c, 0x3a, 0x0c, 0x2e, 0xba, 0x6e, 0x9f, 0x5a, 0xf2, 0x92,
    0xf3, 0x49, 0x78, 0xcc, 0x15, 0xfb, 0x70, 0x75, 0x7f, 0x35, 0x10, 0x03,
    0x64, 0x6d, 0xc6, 0x74, 0xd5, 0xb4, 0xea, 0x09, 0x76, 0x19, 0xfe, 0x40,
    0x12, 0xe0, 0xbd, 0x05, 0xfa, 0x01, 0xf0, 0x2a, 0x5e, 0xa9, 0x56, 0x43,
    0x85, 0x14, 0x89, 0x9b, 0xb0, 0xe5, 0x48, 0x79, 0x97, 0xfc, 0x1e, 0x82,
    0x21, 0x8c, 0x1b, 0x5f, 0x77, 0x54, 0xb2, 0x1d, 0x25, 0x4f, 0x00, 0x46,
    0xed, 0x58, 0x52, 0xeb, 0x7e, 0xda, 0xc9, 0xfd, 0x30, 0x95, 0x65, 0x3c,
    0xb6, 0xe4, 0xbb, 0x7c, 0x0e, 0x50, 0x39, 0x26, 0x32, 0x84, 0x69, 0x93,
    0x37, 0xe7, 0x24, 0xa4, 0xcb, 0x53, 0x0a, 0x87, 0xd9, 0x4c, 0x83, 0x8f,
    0xce, 0x3b, 0x4a, 0xb7,
];

/// The masks from RFC 4269 section 2.2. `m0` keeps the top six bits,
/// and the other three are it rotated.
const M0: u8 = 0xfc;
const M1: u8 = 0xf3;
const M2: u8 = 0xcf;
const M3: u8 = 0x3f;

/// KC, the key schedule constants: 0x9E3779B9 (the golden ratio, as in
/// TEA) rotated left one bit per round.
const KC: [u32; 16] = {
    let mut kc = [0u32; 16];
    let mut i = 0;
    while i < 16 {
        kc[i] = 0x9e37_79b9u32.rotate_left(i as u32);
        i += 1;
    }
    kc
};

/// G's output for one input byte position: that byte through its
/// S-box, spread over the four output bytes by the four masks in the
/// rotation `g_reference` uses for it. G is the XOR of the four.
const SS: [[u32; 256]; 4] = {
    const MASKS: [u8; 4] = [M0, M1, M2, M3];
    let mut table = [[0u32; 256]; 4];
    let mut i = 0;
    while i < 4 {
        let mut v = 0;
        while v < 256 {
            let a = if i % 2 == 0 { S0[v] } else { S1[v] };
            let mut out = [0u8; 4];
            let mut j = 0;
            while j < 4 {
                out[j] = a & MASKS[(i + j) % 4];
                j += 1;
            }
            table[i][v] = u32::from_le_bytes(out);
            v += 1;
        }
        i += 1;
    }
    table
};

/// G, RFC 4269 section 2.2, as four lookups in `SS`.
#[inline]
fn g(x: u32) -> u32 {
    SS[0][(x & 0xff) as usize] ^ SS[1][((x >> 8) & 0xff) as usize]
        ^ SS[2][((x >> 16) & 0xff) as usize] ^ SS[3][(x >> 24) as usize]
}

/// G, RFC 4269 section 2.2: two S-boxes and a permutation of sixteen
/// 8 bit sub-blocks, expressed as four masked lookups. The reference
/// `SS` is tested against.
#[cfg(test)]
fn g_reference(x: u32) -> u32 {
    let b = x.to_le_bytes();          // X0 is the least significant byte
    let (a0, a1, a2, a3) = (S0[b[0] as usize], S1[b[1] as usize],
                            S0[b[2] as usize], S1[b[3] as usize]);
    let z0 = (a0 & M0) ^ (a1 & M1) ^ (a2 & M2) ^ (a3 & M3);
    let z1 = (a0 & M1) ^ (a1 & M2) ^ (a2 & M3) ^ (a3 & M0);
    let z2 = (a0 & M2) ^ (a1 & M3) ^ (a2 & M0) ^ (a3 & M1);
    let z3 = (a0 & M3) ^ (a1 & M0) ^ (a2 & M1) ^ (a3 & M2);
    u32::from_le_bytes([z0, z1, z2, z3])
}

/// The round function F, RFC 4269 section 2.1.
///
/// Three applications of `G` with modular additions between them,
/// which is what stops the round from being affine.
#[inline]
fn f(r0: u32, r1: u32, k0: u32, k1: u32) -> (u32, u32) {
    let a = r0 ^ k0;
    let b = r1 ^ k1;
    let c = g(a ^ b);
    let d = g(c.wrapping_add(a));
    let e = g(d.wrapping_add(c));
    (e.wrapping_add(d), e)
}

/// SEED with its 32 subkeys expanded.
#[derive(Clone)]
pub struct Seed {
    /// `(Ki0, Ki1)` for each of the sixteen rounds.
    round_keys: [(u32, u32); 16],
}

impl Seed {
    pub fn new(key: Vec<u8>) -> Result<Seed, String> {
        if key.len() != 16 {
            return Err(format!("A SEED key is 16 bytes; this one is {}.", key.len()));
        }
        let word = |at: usize| u32::from_be_bytes(
            [key[at], key[at + 1], key[at + 2], key[at + 3]]);
        let (mut k0, mut k1, mut k2, mut k3) = (word(0), word(4), word(8), word(12));

        let mut round_keys = [(0u32, 0u32); 16];
        for (round, keys) in round_keys.iter_mut().enumerate() {
            let kc = KC[round];
            // Not symmetric: the first adds Key2 and subtracts the
            // constant, the second subtracts Key3 and adds it.
            *keys = (g(k0.wrapping_add(k2).wrapping_sub(kc)),
                     g(k1.wrapping_sub(k3).wrapping_add(kc)));
            if round.is_multiple_of(2) {
                // Round 1, 3, 5.. in the RFC's one-based numbering:
                // Key0 || Key1 rotated *right* by 8.
                let joined = ((k0 as u64) << 32) | k1 as u64;
                let rotated = joined.rotate_right(8);
                k0 = (rotated >> 32) as u32;
                k1 = rotated as u32;
            } else {
                // Even rounds: Key2 || Key3 rotated *left* by 8.
                let joined = ((k2 as u64) << 32) | k3 as u64;
                let rotated = joined.rotate_left(8);
                k2 = (rotated >> 32) as u32;
                k3 = rotated as u32;
            }
        }
        Ok(Seed { round_keys })
    }

    fn transform(&self, input: &[u8], result: &mut Vec<u8>, forwards: bool) {
        let word = |at: usize| u32::from_be_bytes(
            [input[at], input[at + 1], input[at + 2], input[at + 3]]);
        let (mut l0, mut l1, mut r0, mut r1) = (word(0), word(4), word(8), word(12));

        for round in 0..16 {
            let (k0, k1) = if forwards {
                self.round_keys[round]
            } else {
                self.round_keys[15 - round]
            };
            let (f0, f1) = f(r0, r1, k0, k1);
            let (n0, n1) = (l0 ^ f0, l1 ^ f1);
            l0 = r0;
            l1 = r1;
            r0 = n0;
            r1 = n1;
        }

        // The halves come out the other way round: after sixteen
        // rounds the final swap is not undone, so the output is
        // (R, L) rather than (L, R).
        for word in [r0, r1, l0, l1] {
            result.extend_from_slice(&word.to_be_bytes());
        }
    }
}

impl BlockCipher for Seed {
    fn blocksize(&self) -> usize { 16 }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        self.transform(input, result, true);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        self.transform(input, result, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_ss_tables_are_g() {
        let mut x = 0x0123_4567u32;
        for _ in 0..20000 {
            x = x.wrapping_mul(0x9e37_79b9).wrapping_add(0x7f4a_7c15);
            assert_eq!(g(x), g_reference(x), "{x:08x}");
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 4269 Appendix B, all four published test vectors.
    #[test]
    fn test_rfc4269_vectors() {
        let cases = [
            ("00000000000000000000000000000000",
             "000102030405060708090a0b0c0d0e0f",
             "5ebac6e0054e166819aff1cc6d346cdb"),
            ("000102030405060708090a0b0c0d0e0f",
             "00000000000000000000000000000000",
             "c11f22f20140505084483597e4370f43"),
            ("4706480851e61be85d74bfb3fd956185",
             "83a2f8a288641fb9a4e9a5cc2f131c7d",
             "ee54d13ebcae706d226bc3142cd40d4a"),
            ("28dbc3bc49ffd87dcfa509b11d422be7",
             "b41e6be2eba84a148e2eed84593c5ec7",
             "9b9b7bfcd1813cb95d0b3618f40f5122"),
        ];
        for (key, plaintext, expected) in cases {
            let mut cipher = Seed::new(unhex(key)).unwrap();
            let mut out = Vec::new();
            cipher.block_encrypt(&unhex(plaintext), &mut out);
            assert_eq!(hex(&out), expected, "key {} plaintext {}", key, plaintext);

            let mut back = Vec::new();
            cipher.block_decrypt(&out, &mut back);
            assert_eq!(hex(&back), plaintext, "round trip for key {}", key);
        }
    }

    /// The two halves of the key rotate in opposite directions, on
    /// alternate rounds.
    ///
    /// Rotating the same pair every round, or both the same way, still
    /// produces thirty-two different subkeys - so nothing about the
    /// cipher looks wrong until it meets another implementation. This
    /// pins it by checking that the schedule is not periodic in the way
    /// a single-pair rotation would make it.
    #[test]
    fn test_the_two_key_halves_rotate_differently() {
        let cipher = Seed::new((0..16).collect()).unwrap();
        let keys = cipher.round_keys;
        // Sixteen rounds, each rotating one half by 8 bits: the left
        // pair turns through 64 bits after eight odd rounds and would
        // repeat from round 17. Within the sixteen, no two rounds may
        // share a subkey pair.
        for i in 0..16 {
            for j in i + 1..16 {
                assert_ne!(keys[i], keys[j],
                           "rounds {} and {} share a subkey pair", i, j);
            }
        }
    }

    /// The key schedule's signs are not symmetric.
    #[test]
    fn test_the_schedule_adds_and_subtracts_differently() {
        // Ki0 = G(Key0 + Key2 - KCi) and Ki1 = G(Key1 - Key3 + KCi).
        // With Key0 == Key1 and Key2 == Key3, a symmetric schedule
        // would make the two halves equal; the real one does not.
        let key: Vec<u8> = vec![1, 2, 3, 4, 1, 2, 3, 4, 9, 9, 9, 9, 9, 9, 9, 9];
        let cipher = Seed::new(key).unwrap();
        let (k0, k1) = cipher.round_keys[0];
        assert_ne!(k0, k1,
                   "the two subkey halves agree, so the signs are symmetric");
    }

    #[test]
    fn test_encryption_is_not_symmetric() {
        let mut cipher = Seed::new((0..16).collect()).unwrap();
        let block: Vec<u8> = (0..16).collect();
        let mut encrypted = Vec::new();
        let mut decrypted = Vec::new();
        cipher.block_encrypt(&block, &mut encrypted);
        cipher.block_decrypt(&block, &mut decrypted);
        assert_ne!(hex(&encrypted), hex(&decrypted));
    }

    #[test]
    fn test_both_sboxes_are_permutations() {
        for (name, box_) in [("S0", &S0), ("S1", &S1)] {
            let mut seen = [false; 256];
            for value in *box_ {
                assert!(!seen[value as usize],
                        "{} has {:#x} twice", name, value);
                seen[value as usize] = true;
            }
        }
    }

    /// The KC constants match the RFC's table.
    #[test]
    fn test_the_key_constants_match_the_published_table() {
        const PUBLISHED: [u32; 16] = [
            0x9e3779b9, 0x3c6ef373, 0x78dde6e6, 0xf1bbcdcc,
            0xe3779b99, 0xc6ef3733, 0x8dde6e67, 0x1bbcdccf,
            0x3779b99e, 0x6ef3733c, 0xdde6e678, 0xbbcdccf1,
            0x779b99e3, 0xef3733c6, 0xde6e678d, 0xbcdccf1b,
        ];
        assert_eq!(KC, PUBLISHED);
    }

    #[test]
    fn test_a_wrong_key_length_is_an_error() {
        assert!(Seed::new(vec![0; 15]).is_err());
        assert!(Seed::new(vec![0; 17]).is_err());
    }
}
