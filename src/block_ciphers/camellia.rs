/*
Camellia, RFC 3713.

128 bit block; 128, 192 or 256 bit key; eighteen Feistel rounds for the
short key and twenty-four for the long ones, with an `FL`/`FL^-1` layer
every six. Designed jointly by NTT and Mitsubishi in 2000, selected by
NESSIE and by the Japanese CRYPTREC, and named in TLS by RFC 5932 - so
it is out there, and `python-cryptography` still has it while having
moved its neighbours to `hazmat.decrepit`.

One S-box, used four ways. `SBOX2`, `SBOX3` and `SBOX4` are `SBOX1`
rotated - the output left by one, the output left by seven, and the
*input* left by one respectively. That last one is the odd member:
`SBOX4[x] = SBOX1[x <<< 1]`, rotating the index rather than the value,
and writing it as an output rotation like its two siblings gives a
cipher that is wrong in a quarter of the byte positions.

## The 192 and 256 bit keys are not just longer

For 128 bits, `KR` is zero and `KB` is never computed. For 192,
`KR` is the last 64 bits of the key followed by **the complement of
those same 64 bits** - not zero padding, and not a repeat. For 256 it is
simply the second half. Three different constructions behind one
parameter, and the 192 bit one is the only place in this library where a
key is extended by complementing part of itself.

## `k9` and `k10` do not come from the same rotation

In the 128 bit schedule every subkey pair is the two halves of one
rotated value - except `k9`, which is the high half of `KA <<< 45`,
while `k10` is the low half of `KL <<< 60`. It reads like a typo in the
RFC and it is not; every implementation has it. Writing the "obvious"
symmetric version gives a cipher that fails only the vectors, and only
at rounds 9 and 10.
*/

use crate::block_ciphers::BlockCipher;

/// SBOX1, RFC 3713 section 2.4.1. Read out of the document's table,
/// which states it in decimal.
const SBOX1: [u8; 256] = [
    0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35,
    0xea, 0x0c, 0xae, 0x41, 0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21,
    0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd, 0x86, 0xb8, 0xaf, 0x8f,
    0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
    0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6,
    0x51, 0x56, 0x6c, 0x4d, 0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d,
    0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99, 0xdf, 0x4c, 0xcb, 0xc2,
    0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
    0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16,
    0x53, 0x18, 0xf2, 0x22, 0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91,
    0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50, 0xaa, 0xd0, 0xa0, 0x7d,
    0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
    0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda,
    0x09, 0x3f, 0xdd, 0x94, 0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33,
    0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2, 0x52, 0x9b, 0xd8, 0x26,
    0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
    0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6,
    0x2f, 0xfd, 0xb4, 0x59, 0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba,
    0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa, 0x72, 0x07, 0xb9, 0x55,
    0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
    0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4,
    0x77, 0xc7, 0x80, 0x9e,
];

/// The six 64 bit constants used as keys in the schedule's F calls.
/// The hexadecimal expansion of the square root of 2, 3, 5, 7, 10 and
/// 13 - the same idea as SHA-2's, stated as a table by the RFC.
const SIGMA: [u64; 6] = [
    0xa09e667f3bcc908b, 0xb67ae8584caa73b2, 0xc6ef372fe94f82be,
    0x54ff53a5f1d36f1c, 0x10e527fade682d1d, 0xb05688c2b3e6c1fd,
];

#[inline]
const fn sbox2(x: u8) -> u8 { SBOX1[x as usize].rotate_left(1) }
#[inline]
const fn sbox3(x: u8) -> u8 { SBOX1[x as usize].rotate_left(7) }
/// **The index is rotated, not the value.** The one asymmetric member
/// of the four.
#[inline]
const fn sbox4(x: u8) -> u8 { SBOX1[x.rotate_left(1) as usize] }

/// The eight S-box applications of F, byte `i` of its input through
/// the S-box RFC 3713 section 2.4.1 assigns to position `i`.
const fn s_layer(i: usize, x: u8) -> u8 {
    match i {
        0 | 7 => SBOX1[x as usize],
        1 | 4 => sbox2(x),
        2 | 5 => sbox3(x),
        _ => sbox4(x),
    }
}

/// The P-function, RFC 3713 section 2.4.1: each output byte the XOR of
/// six or five of the S-box outputs.
const fn p_layer(t: [u8; 8]) -> u64 {
    u64::from_be_bytes([
        t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7],
        t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7],
        t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7],
        t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6],
        t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7],
        t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7],
        t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7],
        t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6],
    ])
}

/// S then P for one input byte position: P is a XOR of bytes, so F's
/// output is the XOR of `SP[i][x[i]]` over the eight positions. Built
/// at compile time from `s_layer` and `p_layer`.
const SP: [[u64; 256]; 8] = {
    let mut table = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 8 {
        let mut v = 0;
        while v < 256 {
            let mut t = [0u8; 8];
            t[i] = s_layer(i, v as u8);
            table[i][v] = p_layer(t);
            v += 1;
        }
        i += 1;
    }
    table
};

/// The F-function, RFC 3713 section 2.4.1, from `SP`.
#[inline]
fn f(input: u64, key: u64) -> u64 {
    let x = (input ^ key).to_be_bytes();
    SP[0][x[0] as usize] ^ SP[1][x[1] as usize] ^ SP[2][x[2] as usize]
        ^ SP[3][x[3] as usize] ^ SP[4][x[4] as usize] ^ SP[5][x[5] as usize]
        ^ SP[6][x[6] as usize] ^ SP[7][x[7] as usize]
}

/// F as the RFC writes it, S-boxes then P: the reference `f` is tested
/// against.
#[cfg(test)]
fn f_reference(input: u64, key: u64) -> u64 {
    let x = (input ^ key).to_be_bytes();
    let mut t = [0u8; 8];
    for (i, byte) in t.iter_mut().enumerate() {
        *byte = s_layer(i, x[i]);
    }
    p_layer(t)
}

/// FL, RFC 3713 section 2.4.2.
fn fl(input: u64, key: u64) -> u64 {
    let (mut x1, mut x2) = ((input >> 32) as u32, input as u32);
    let (k1, k2) = ((key >> 32) as u32, key as u32);
    x2 ^= (x1 & k1).rotate_left(1);
    x1 ^= x2 | k2;
    ((x1 as u64) << 32) | x2 as u64
}

/// FL inverse. The same two steps in the other order, with the same
/// signs - not with the operations inverted, because XOR is its own
/// inverse and the order is the whole of it.
fn fl_inverse(input: u64, key: u64) -> u64 {
    let (mut y1, mut y2) = ((input >> 32) as u32, input as u32);
    let (k1, k2) = ((key >> 32) as u32, key as u32);
    y1 ^= y2 | k2;
    y2 ^= (y1 & k1).rotate_left(1);
    ((y1 as u64) << 32) | y2 as u64
}

/// Camellia with its subkeys expanded.
#[derive(Clone)]
pub struct Camellia {
    /// kw1..kw4, the pre- and post-whitening keys.
    kw: [u64; 4],
    /// k1..k18 or k1..k24.
    k: Vec<u64>,
    /// ke1..ke4 or ke1..ke6.
    ke: Vec<u64>,
    /// The three lists in decryption order, built once with the key (see
    /// `transform`).
    dkw: [u64; 4],
    dk: Vec<u64>,
    dke: Vec<u64>,
}

impl Camellia {
    pub fn new(key: Vec<u8>) -> Result<Camellia, String> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(format!("A Camellia key is 16, 24 or 32 bytes; this one \
                                is {}.", key.len()));
        }

        let word = |at: usize| u64::from_be_bytes([
            key[at], key[at + 1], key[at + 2], key[at + 3],
            key[at + 4], key[at + 5], key[at + 6], key[at + 7]]);

        let kl = ((word(0) as u128) << 64) | word(8) as u128;
        let kr: u128 = match key.len() {
            16 => 0,
            // The last 64 bits, then **the complement of those same
            // bits**. Not padding, and not a repeat.
            24 => ((word(16) as u128) << 64) | (!word(16)) as u128,
            _ => ((word(16) as u128) << 64) | word(24) as u128,
        };

        let mut d1 = ((kl ^ kr) >> 64) as u64;
        let mut d2 = (kl ^ kr) as u64;
        d2 ^= f(d1, SIGMA[0]);
        d1 ^= f(d2, SIGMA[1]);
        d1 ^= (kl >> 64) as u64;
        d2 ^= kl as u64;
        d2 ^= f(d1, SIGMA[2]);
        d1 ^= f(d2, SIGMA[3]);
        let ka = ((d1 as u128) << 64) | d2 as u128;

        let kb = if key.len() == 16 {
            0
        } else {
            let mut d1 = ((ka ^ kr) >> 64) as u64;
            let mut d2 = (ka ^ kr) as u64;
            d2 ^= f(d1, SIGMA[4]);
            d1 ^= f(d2, SIGMA[5]);
            ((d1 as u128) << 64) | d2 as u128
        };

        // `(source, rotation, take the high half)`, straight from the
        // RFC's tables. Written as data rather than as forty lines of
        // assignment so that the two schedules can be read side by side
        // and so that `k9`'s irregularity is visible rather than buried.
        let high = true;
        let low = false;
        let (kw_spec, k_spec, ke_spec): (&[_], &[_], &[_]) = if key.len() == 16 {
            (&[(kl, 0, high), (kl, 0, low), (ka, 111, high), (ka, 111, low)],
             &[(ka, 0, high), (ka, 0, low), (kl, 15, high), (kl, 15, low),
               (ka, 15, high), (ka, 15, low), (kl, 45, high), (kl, 45, low),
               // k9 from KA <<< 45, k10 from KL <<< 60. Not a typo.
               (ka, 45, high), (kl, 60, low),
               (ka, 60, high), (ka, 60, low), (kl, 94, high), (kl, 94, low),
               (ka, 94, high), (ka, 94, low), (kl, 111, high), (kl, 111, low)],
             &[(ka, 30, high), (ka, 30, low), (kl, 77, high), (kl, 77, low)])
        } else {
            (&[(kl, 0, high), (kl, 0, low), (kb, 111, high), (kb, 111, low)],
             &[(kb, 0, high), (kb, 0, low), (kr, 15, high), (kr, 15, low),
               (ka, 15, high), (ka, 15, low), (kb, 30, high), (kb, 30, low),
               (kl, 45, high), (kl, 45, low), (ka, 45, high), (ka, 45, low),
               (kr, 60, high), (kr, 60, low), (kb, 60, high), (kb, 60, low),
               (kl, 77, high), (kl, 77, low), (kr, 94, high), (kr, 94, low),
               (ka, 94, high), (ka, 94, low), (kl, 111, high), (kl, 111, low)],
             &[(kr, 30, high), (kr, 30, low), (kl, 60, high), (kl, 60, low),
               (ka, 77, high), (ka, 77, low)])
        };

        let take = |(value, rotation, want_high): &(u128, u32, bool)| -> u64 {
            let rotated = value.rotate_left(*rotation);
            if *want_high { (rotated >> 64) as u64 } else { rotated as u64 }
        };

        let mut kw = [0u64; 4];
        for (slot, spec) in kw.iter_mut().zip(kw_spec) {
            *slot = take(spec);
        }
        let k: Vec<u64> = k_spec.iter().map(take).collect();
        let ke: Vec<u64> = ke_spec.iter().map(take).collect();
        // Decryption is encryption with the subkeys reversed, RFC 3713
        // section 2.3.3: `kw1 <-> kw3`, `kw2 <-> kw4`, and both the `k`
        // and `ke` lists simply reversed end to end - `ke1 <-> ke4`,
        // `ke2 <-> ke3` for the short key, and `ke1 <-> ke6` and so on
        // for the long ones.
        //
        // Plainly reversed, with no pairwise swap inside. The first
        // version of this exchanged the two halves of each `ke` pair as
        // well, on the reasoning that `FL` and `FL^-1` change places -
        // they do, but that is already what reversing the list does,
        // and doing it twice puts them back. Encryption was unaffected,
        // so every vector passed until the round trip.
        let dkw = [kw[2], kw[3], kw[0], kw[1]];
        let dk = k.iter().rev().copied().collect();
        let dke = ke.iter().rev().copied().collect();
        Ok(Camellia { kw, k, ke, dkw, dk, dke })
    }

    /// The number of Feistel rounds: eighteen or twenty-four.
    ///
    /// Used by the tests rather than by the cipher, which iterates the
    /// round-key list directly - but the count is the thing worth
    /// asserting, so it stays.
    #[cfg(test)]
    fn rounds(&self) -> usize { self.k.len() }

    fn transform(&self, input: &[u8], result: &mut Vec<u8>, forwards: bool) {
        let half = |at: usize| u64::from_be_bytes([
            input[at], input[at + 1], input[at + 2], input[at + 3],
            input[at + 4], input[at + 5], input[at + 6], input[at + 7]]);

        let (kw, k, ke) = if forwards {
            (&self.kw, &self.k, &self.ke)
        } else {
            (&self.dkw, &self.dk, &self.dke)
        };

        let mut d1 = half(0) ^ kw[0];
        let mut d2 = half(8) ^ kw[1];

        for (round, round_key) in k.iter().enumerate() {
            if round > 0 && round.is_multiple_of(6) {
                let at = (round / 6 - 1) * 2;
                d1 = fl(d1, ke[at]);
                d2 = fl_inverse(d2, ke[at + 1]);
            }
            if round.is_multiple_of(2) {
                d2 ^= f(d1, *round_key);
            } else {
                d1 ^= f(d2, *round_key);
            }
        }

        d2 ^= kw[2];
        d1 ^= kw[3];
        result.extend_from_slice(&d2.to_be_bytes());
        result.extend_from_slice(&d1.to_be_bytes());
    }
}

impl BlockCipher for Camellia {
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The tabled F is the RFC's S-boxes followed by its P-function.
    #[test]
    fn test_the_sp_tables_are_f() {
        let mut x = 0x0123_4567_89ab_cdefu64;
        for _ in 0..5000 {
            x = x.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(0x1405_7b7e_f767_814f);
            let key = x.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
            assert_eq!(f(x, key), f_reference(x, key));
        }
    }

    /// RFC 3713 section 4, all three published vectors - one per key
    /// length, so this also pins the three different ways `KR` is
    /// built.
    #[test]
    fn test_rfc3713_vectors() {
        let plaintext = "0123456789abcdeffedcba9876543210";
        let cases = [
            ("0123456789abcdeffedcba9876543210",
             "67673138549669730857065648eabe43"),
            ("0123456789abcdeffedcba98765432100011223344556677",
             "b4993401b3e996f84ee5cee7d79b09b9"),
            ("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
             "9acc237dff16d76c20ef7c919e3a7509"),
        ];
        for (key, expected) in cases {
            let mut cipher = Camellia::new(unhex(key)).unwrap();
            let mut out = Vec::new();
            cipher.block_encrypt(&unhex(plaintext), &mut out);
            assert_eq!(hex(&out), expected, "key {}", key);

            let mut back = Vec::new();
            cipher.block_decrypt(&out, &mut back);
            assert_eq!(hex(&back), plaintext, "round trip, key {}", key);
        }
    }

    /// `SBOX4` rotates its **index**, the others rotate the value.
    #[test]
    fn test_sbox4_rotates_the_index() {
        // If SBOX4 rotated the value like its siblings it would be a
        // permutation of SBOX1's outputs in SBOX1's order. It is not -
        // it is SBOX1's outputs in a different order.
        for x in 0..=255u8 {
            assert_eq!(sbox4(x), SBOX1[x.rotate_left(1) as usize]);
        }
        assert_ne!((0..=255u8).map(sbox4).collect::<Vec<_>>(),
                   (0..=255u8).map(|x| SBOX1[x as usize].rotate_left(1))
                       .collect::<Vec<_>>(),
                   "SBOX4 behaved as an output rotation");
    }

    /// A 192 bit key's `KR` complements its own second half.
    #[test]
    fn test_a_192_bit_key_complements_its_tail() {
        // Two keys differing only in the last 64 bits must give
        // different results - which they would even with zero padding.
        // What this pins is the complement specifically: a key whose
        // last 64 bits are all zero must *not* behave as a 128 bit key
        // extended with zeros, because the complement makes KR nonzero.
        let short = Camellia::new(unhex("0123456789abcdeffedcba9876543210")).unwrap();
        let long = Camellia::new(
            unhex("0123456789abcdeffedcba98765432100000000000000000")).unwrap();
        assert_ne!(short.k[0], long.k[0],
                   "a 192 bit key with a zero tail behaved as a 128 bit key, \
                    so KR is being zero padded rather than complemented");
    }

    /// FL and its inverse really are inverses.
    #[test]
    fn test_fl_and_its_inverse_undo_each_other() {
        for (value, key) in [(0u64, 0u64), (1, 1), (0x0123_4567_89ab_cdef, 0xfedc),
                             (u64::MAX, u64::MAX), (0xa5a5_a5a5_a5a5_a5a5, 0x1234)] {
            assert_eq!(fl_inverse(fl(value, key), key), value,
                       "FL^-1(FL(x)) != x for {:#x}", value);
        }
    }

    /// The round count follows the key length.
    #[test]
    fn test_the_round_count_follows_the_key_length() {
        assert_eq!(Camellia::new(vec![0; 16]).unwrap().rounds(), 18);
        assert_eq!(Camellia::new(vec![0; 24]).unwrap().rounds(), 24);
        assert_eq!(Camellia::new(vec![0; 32]).unwrap().rounds(), 24);
    }

    #[test]
    fn test_encryption_is_not_symmetric() {
        let mut cipher = Camellia::new(vec![7; 16]).unwrap();
        let block: Vec<u8> = (0..16).collect();
        let mut encrypted = Vec::new();
        let mut decrypted = Vec::new();
        cipher.block_encrypt(&block, &mut encrypted);
        cipher.block_decrypt(&block, &mut decrypted);
        assert_ne!(hex(&encrypted), hex(&decrypted));
    }

    #[test]
    fn test_the_sbox_is_a_permutation() {
        let mut seen = [false; 256];
        for value in SBOX1 {
            assert!(!seen[value as usize], "{:#x} appears twice", value);
            seen[value as usize] = true;
        }
    }

    #[test]
    fn test_a_wrong_key_length_is_an_error() {
        for length in [0usize, 8, 15, 17, 20, 23, 25, 31, 33] {
            assert!(Camellia::new(vec![0; length]).is_err(),
                    "{} bytes should be refused", length);
        }
    }
}
