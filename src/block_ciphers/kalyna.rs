/*!
Kalyna, DSTU 7624:2014: Ukraine's block cipher, the successor to its
adoption of GOST 28147-89.

Five variants, written Kalyna-b/k for block and key in bits: 128/128,
128/256, 256/256, 256/512 and 512/512. A key is the block's length or
twice it. The round count is 10, 14, 14, 18 and 18.

## The round

The state is `Nb` 64-bit words (2, 4 or 8), each a column of eight
bytes, **little endian throughout**: byte `r` of column `c` is byte
`8c + r` of the block, and the words are read and added as little-endian
integers. A round is SubBytes (four S-boxes, byte `r` of every column
through `π[r mod 4]`), ShiftRows (row `r` rotated right by `r·Nb/8`
columns), and MixColumns, a circulant MDS matrix over GF(2^8) modulo
x^8 + x^4 + x^3 + x^2 + 1 whose first row is `01 01 05 01 08 06 07 04`.

The round key is **added modulo 2^64 per column** before the first round
and after the last, and XORed in between; decryption subtracts. A
version that XORs all of them is a different cipher that still inverts.

## The key schedule

Three steps, each built from the round:

1. `Kt`: a state of `Nb + Nk + 1` in its first word, then three rounds
   with the key's halves (or the key twice, when `Nk = Nb`) added, XORed
   and added in turn.
2. The even round keys: `Kt` plus a constant `tmv` that starts as
   `0x0001000100010001` in every word and doubles each time, added to,
   XORed with and added to the key - its first or second half in turn
   when the key is twice the block - with two rounds between, the key's
   words rotating by one word after each pair.
3. The odd round keys: the even key before it rotated left by `2·Nb + 3`
   bytes.

## Not constant time

The S-boxes are tables indexed by the data, as in the standard. The
cipher is not on `scripts/ct_check.py`'s list; `docs/pitfalls.md`
records it.

## In the catalogue

`kalyna-128`, `kalyna-256` and `kalyna-512`, by block size, each taking
the key lengths its block allows. ECB, CBC, CFB and OFB are the generic
modes, which DSTU 7624 shares; **`ctr` is DSTU 7624's own counter
mode**, which starts from the encrypted IV and counts little endian, as
GOST's `ctr` is GOST's. The standard's MAC and key wrap are in
`kalyna_modes`; its CCM, GMAC and XTS are not here yet.

## Where the vectors come from

`vectors/kalyna.vec`, written by `scripts/make_kalyna_vectors.py`:
the standard's ten worked examples, as the reference implementation by
the cipher's authors carries them, and rows for every variant on which
that reference and Bouncy Castle 1.77's `DSTU7624Engine` agree. The
S-boxes here are pinned to both of theirs through the same file.
*/

use crate::block_ciphers::BlockCipher;

/// The four S-boxes `π0..π3` of DSTU 7624:2014.
pub const SBOX: [[u8; 256]; 4] = [
    [
        0xa8, 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, 0xdf, 0x87, 0x95, 0x17, 0xf0, 0xd8, 0x09,
        0x6d, 0xf3, 0x1d, 0xcb, 0xc9, 0x4d, 0x2c, 0xaf, 0x79, 0xe0, 0x97, 0xfd, 0x6f, 0x4b, 0x45, 0x39,
        0x3e, 0xdd, 0xa3, 0x4f, 0xb4, 0xb6, 0x9a, 0x0e, 0x1f, 0xbf, 0x15, 0xe1, 0x49, 0xd2, 0x93, 0xc6,
        0x92, 0x72, 0x9e, 0x61, 0xd1, 0x63, 0xfa, 0xee, 0xf4, 0x19, 0xd5, 0xad, 0x58, 0xa4, 0xbb, 0xa1,
        0xdc, 0xf2, 0x83, 0x37, 0x42, 0xe4, 0x7a, 0x32, 0x9c, 0xcc, 0xab, 0x4a, 0x8f, 0x6e, 0x04, 0x27,
        0x2e, 0xe7, 0xe2, 0x5a, 0x96, 0x16, 0x23, 0x2b, 0xc2, 0x65, 0x66, 0x0f, 0xbc, 0xa9, 0x47, 0x41,
        0x34, 0x48, 0xfc, 0xb7, 0x6a, 0x88, 0xa5, 0x53, 0x86, 0xf9, 0x5b, 0xdb, 0x38, 0x7b, 0xc3, 0x1e,
        0x22, 0x33, 0x24, 0x28, 0x36, 0xc7, 0xb2, 0x3b, 0x8e, 0x77, 0xba, 0xf5, 0x14, 0x9f, 0x08, 0x55,
        0x9b, 0x4c, 0xfe, 0x60, 0x5c, 0xda, 0x18, 0x46, 0xcd, 0x7d, 0x21, 0xb0, 0x3f, 0x1b, 0x89, 0xff,
        0xeb, 0x84, 0x69, 0x3a, 0x9d, 0xd7, 0xd3, 0x70, 0x67, 0x40, 0xb5, 0xde, 0x5d, 0x30, 0x91, 0xb1,
        0x78, 0x11, 0x01, 0xe5, 0x00, 0x68, 0x98, 0xa0, 0xc5, 0x02, 0xa6, 0x74, 0x2d, 0x0b, 0xa2, 0x76,
        0xb3, 0xbe, 0xce, 0xbd, 0xae, 0xe9, 0x8a, 0x31, 0x1c, 0xec, 0xf1, 0x99, 0x94, 0xaa, 0xf6, 0x26,
        0x2f, 0xef, 0xe8, 0x8c, 0x35, 0x03, 0xd4, 0x7f, 0xfb, 0x05, 0xc1, 0x5e, 0x90, 0x20, 0x3d, 0x82,
        0xf7, 0xea, 0x0a, 0x0d, 0x7e, 0xf8, 0x50, 0x1a, 0xc4, 0x07, 0x57, 0xb8, 0x3c, 0x62, 0xe3, 0xc8,
        0xac, 0x52, 0x64, 0x10, 0xd0, 0xd9, 0x13, 0x0c, 0x12, 0x29, 0x51, 0xb9, 0xcf, 0xd6, 0x73, 0x8d,
        0x81, 0x54, 0xc0, 0xed, 0x4e, 0x44, 0xa7, 0x2a, 0x85, 0x25, 0xe6, 0xca, 0x7c, 0x8b, 0x56, 0x80,
    ],
    [
        0xce, 0xbb, 0xeb, 0x92, 0xea, 0xcb, 0x13, 0xc1, 0xe9, 0x3a, 0xd6, 0xb2, 0xd2, 0x90, 0x17, 0xf8,
        0x42, 0x15, 0x56, 0xb4, 0x65, 0x1c, 0x88, 0x43, 0xc5, 0x5c, 0x36, 0xba, 0xf5, 0x57, 0x67, 0x8d,
        0x31, 0xf6, 0x64, 0x58, 0x9e, 0xf4, 0x22, 0xaa, 0x75, 0x0f, 0x02, 0xb1, 0xdf, 0x6d, 0x73, 0x4d,
        0x7c, 0x26, 0x2e, 0xf7, 0x08, 0x5d, 0x44, 0x3e, 0x9f, 0x14, 0xc8, 0xae, 0x54, 0x10, 0xd8, 0xbc,
        0x1a, 0x6b, 0x69, 0xf3, 0xbd, 0x33, 0xab, 0xfa, 0xd1, 0x9b, 0x68, 0x4e, 0x16, 0x95, 0x91, 0xee,
        0x4c, 0x63, 0x8e, 0x5b, 0xcc, 0x3c, 0x19, 0xa1, 0x81, 0x49, 0x7b, 0xd9, 0x6f, 0x37, 0x60, 0xca,
        0xe7, 0x2b, 0x48, 0xfd, 0x96, 0x45, 0xfc, 0x41, 0x12, 0x0d, 0x79, 0xe5, 0x89, 0x8c, 0xe3, 0x20,
        0x30, 0xdc, 0xb7, 0x6c, 0x4a, 0xb5, 0x3f, 0x97, 0xd4, 0x62, 0x2d, 0x06, 0xa4, 0xa5, 0x83, 0x5f,
        0x2a, 0xda, 0xc9, 0x00, 0x7e, 0xa2, 0x55, 0xbf, 0x11, 0xd5, 0x9c, 0xcf, 0x0e, 0x0a, 0x3d, 0x51,
        0x7d, 0x93, 0x1b, 0xfe, 0xc4, 0x47, 0x09, 0x86, 0x0b, 0x8f, 0x9d, 0x6a, 0x07, 0xb9, 0xb0, 0x98,
        0x18, 0x32, 0x71, 0x4b, 0xef, 0x3b, 0x70, 0xa0, 0xe4, 0x40, 0xff, 0xc3, 0xa9, 0xe6, 0x78, 0xf9,
        0x8b, 0x46, 0x80, 0x1e, 0x38, 0xe1, 0xb8, 0xa8, 0xe0, 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05,
        0xf1, 0x6e, 0x94, 0x28, 0x9a, 0x84, 0xe8, 0xa3, 0x4f, 0x77, 0xd3, 0x85, 0xe2, 0x52, 0xf2, 0x82,
        0x50, 0x7a, 0x2f, 0x74, 0x53, 0xb3, 0x61, 0xaf, 0x39, 0x35, 0xde, 0xcd, 0x1f, 0x99, 0xac, 0xad,
        0x72, 0x2c, 0xdd, 0xd0, 0x87, 0xbe, 0x5e, 0xa6, 0xec, 0x04, 0xc6, 0x03, 0x34, 0xfb, 0xdb, 0x59,
        0xb6, 0xc2, 0x01, 0xf0, 0x5a, 0xed, 0xa7, 0x66, 0x21, 0x7f, 0x8a, 0x27, 0xc7, 0xc0, 0x29, 0xd7,
    ],
    [
        0x93, 0xd9, 0x9a, 0xb5, 0x98, 0x22, 0x45, 0xfc, 0xba, 0x6a, 0xdf, 0x02, 0x9f, 0xdc, 0x51, 0x59,
        0x4a, 0x17, 0x2b, 0xc2, 0x94, 0xf4, 0xbb, 0xa3, 0x62, 0xe4, 0x71, 0xd4, 0xcd, 0x70, 0x16, 0xe1,
        0x49, 0x3c, 0xc0, 0xd8, 0x5c, 0x9b, 0xad, 0x85, 0x53, 0xa1, 0x7a, 0xc8, 0x2d, 0xe0, 0xd1, 0x72,
        0xa6, 0x2c, 0xc4, 0xe3, 0x76, 0x78, 0xb7, 0xb4, 0x09, 0x3b, 0x0e, 0x41, 0x4c, 0xde, 0xb2, 0x90,
        0x25, 0xa5, 0xd7, 0x03, 0x11, 0x00, 0xc3, 0x2e, 0x92, 0xef, 0x4e, 0x12, 0x9d, 0x7d, 0xcb, 0x35,
        0x10, 0xd5, 0x4f, 0x9e, 0x4d, 0xa9, 0x55, 0xc6, 0xd0, 0x7b, 0x18, 0x97, 0xd3, 0x36, 0xe6, 0x48,
        0x56, 0x81, 0x8f, 0x77, 0xcc, 0x9c, 0xb9, 0xe2, 0xac, 0xb8, 0x2f, 0x15, 0xa4, 0x7c, 0xda, 0x38,
        0x1e, 0x0b, 0x05, 0xd6, 0x14, 0x6e, 0x6c, 0x7e, 0x66, 0xfd, 0xb1, 0xe5, 0x60, 0xaf, 0x5e, 0x33,
        0x87, 0xc9, 0xf0, 0x5d, 0x6d, 0x3f, 0x88, 0x8d, 0xc7, 0xf7, 0x1d, 0xe9, 0xec, 0xed, 0x80, 0x29,
        0x27, 0xcf, 0x99, 0xa8, 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, 0x95, 0xd2, 0x3e, 0x5b, 0x40, 0x83,
        0xb3, 0x69, 0x57, 0x1f, 0x07, 0x1c, 0x8a, 0xbc, 0x20, 0xeb, 0xce, 0x8e, 0xab, 0xee, 0x31, 0xa2,
        0x73, 0xf9, 0xca, 0x3a, 0x1a, 0xfb, 0x0d, 0xc1, 0xfe, 0xfa, 0xf2, 0x6f, 0xbd, 0x96, 0xdd, 0x43,
        0x52, 0xb6, 0x08, 0xf3, 0xae, 0xbe, 0x19, 0x89, 0x32, 0x26, 0xb0, 0xea, 0x4b, 0x64, 0x84, 0x82,
        0x6b, 0xf5, 0x79, 0xbf, 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, 0xe8, 0x91,
        0xf6, 0xff, 0x13, 0x58, 0xf1, 0x47, 0x0a, 0x7f, 0xc5, 0xa7, 0xe7, 0x61, 0x5a, 0x06, 0x46, 0x44,
        0x42, 0x04, 0xa0, 0xdb, 0x39, 0x86, 0x54, 0xaa, 0x8c, 0x34, 0x21, 0x8b, 0xf8, 0x0c, 0x74, 0x67,
    ],
    [
        0x68, 0x8d, 0xca, 0x4d, 0x73, 0x4b, 0x4e, 0x2a, 0xd4, 0x52, 0x26, 0xb3, 0x54, 0x1e, 0x19, 0x1f,
        0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, 0x83, 0x13, 0x8a, 0xb7, 0xd5, 0x25, 0x79, 0xf5, 0xbd,
        0x58, 0x2f, 0x0d, 0x02, 0xed, 0x51, 0x9e, 0x11, 0xf2, 0x3e, 0x55, 0x5e, 0xd1, 0x16, 0x3c, 0x66,
        0x70, 0x5d, 0xf3, 0x45, 0x40, 0xcc, 0xe8, 0x94, 0x56, 0x08, 0xce, 0x1a, 0x3a, 0xd2, 0xe1, 0xdf,
        0xb5, 0x38, 0x6e, 0x0e, 0xe5, 0xf4, 0xf9, 0x86, 0xe9, 0x4f, 0xd6, 0x85, 0x23, 0xcf, 0x32, 0x99,
        0x31, 0x14, 0xae, 0xee, 0xc8, 0x48, 0xd3, 0x30, 0xa1, 0x92, 0x41, 0xb1, 0x18, 0xc4, 0x2c, 0x71,
        0x72, 0x44, 0x15, 0xfd, 0x37, 0xbe, 0x5f, 0xaa, 0x9b, 0x88, 0xd8, 0xab, 0x89, 0x9c, 0xfa, 0x60,
        0xea, 0xbc, 0x62, 0x0c, 0x24, 0xa6, 0xa8, 0xec, 0x67, 0x20, 0xdb, 0x7c, 0x28, 0xdd, 0xac, 0x5b,
        0x34, 0x7e, 0x10, 0xf1, 0x7b, 0x8f, 0x63, 0xa0, 0x05, 0x9a, 0x43, 0x77, 0x21, 0xbf, 0x27, 0x09,
        0xc3, 0x9f, 0xb6, 0xd7, 0x29, 0xc2, 0xeb, 0xc0, 0xa4, 0x8b, 0x8c, 0x1d, 0xfb, 0xff, 0xc1, 0xb2,
        0x97, 0x2e, 0xf8, 0x65, 0xf6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xe4, 0xd9, 0xb9, 0xd0, 0x42, 0xc7,
        0x6c, 0x90, 0x00, 0x8e, 0x6f, 0x50, 0x01, 0xc5, 0xda, 0x47, 0x3f, 0xcd, 0x69, 0xa2, 0xe2, 0x7a,
        0xa7, 0xc6, 0x93, 0x0f, 0x0a, 0x06, 0xe6, 0x2b, 0x96, 0xa3, 0x1c, 0xaf, 0x6a, 0x12, 0x84, 0x39,
        0xe7, 0xb0, 0x82, 0xf7, 0xfe, 0x9d, 0x87, 0x5c, 0x81, 0x35, 0xde, 0xb4, 0xa5, 0xfc, 0x80, 0xef,
        0xcb, 0xbb, 0x6b, 0x76, 0xba, 0x5a, 0x7d, 0x78, 0x0b, 0x95, 0xe3, 0xad, 0x74, 0x98, 0x3b, 0x36,
        0x64, 0x6d, 0xdc, 0xf0, 0x59, 0xa9, 0x4c, 0x17, 0x7f, 0x91, 0xb8, 0xc9, 0x57, 0x1b, 0xe0, 0x61,
    ],
];

/// Their inverses, computed rather than typed.
const INV_SBOX: [[u8; 256]; 4] = {
    let mut inv = [[0u8; 256]; 4];
    let mut s = 0;
    while s < 4 {
        let mut x = 0;
        while x < 256 {
            inv[s][SBOX[s][x] as usize] = x as u8;
            x += 1;
        }
        s += 1;
    }
    inv
};

/// MixColumns' first row, and its inverse's. Row `r` of each matrix is
/// this one rotated right by `r`.
const MDS: [u8; 8] = [0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04];
const MDS_INV: [u8; 8] = [0xad, 0x95, 0x76, 0xa8, 0x2f, 0x49, 0xd7, 0xca];

/// Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1d } else { 0 };
        b >>= 1;
    }
    r
}

/// `x` times each coefficient of a row, for every `x`.
const fn products(row: [u8; 8]) -> [[u8; 256]; 8] {
    let mut table = [[0u8; 256]; 8];
    let mut j = 0;
    while j < 8 {
        let mut x = 0;
        while x < 256 {
            table[j][x] = gf_mul(x as u8, row[j]);
            x += 1;
        }
        j += 1;
    }
    table
}

/// MixColumns' products, shared with Kupyna, which uses the same matrix.
pub(crate) const MUL: [[u8; 256]; 8] = products(MDS);
const MUL_INV: [[u8; 256]; 8] = products(MDS_INV);

/// A whole state: up to eight columns of eight bytes, of which `nb`
/// are used.
type State = [u8; 64];

#[derive(Clone)]
pub struct Kalyna {
    /// The block in 64-bit words: 2, 4 or 8.
    nb: usize,
    rounds: usize,
    /// `rounds + 1` round keys of `nb` words, the rest of each zero.
    round_keys: Vec<[u64; 8]>,
}

/// Byte `r` of every column through `table[r mod 4]`, over whole
/// columns. Shared with Kupyna.
pub(crate) fn sub_bytes(s: &mut [u8], table: &[[u8; 256]; 4]) {
    for (i, b) in s.iter_mut().enumerate() {
        *b = table[i % 4][*b as usize];
    }
}

/// Row `r` moves right by `r·nb/8` columns, or back again.
fn shift_rows(s: &mut State, nb: usize, inverse: bool) {
    let before = *s;
    for row in 0..8 {
        let shift = row * nb / 8;
        for col in 0..nb {
            let to = (col + shift) % nb;
            if inverse {
                s[row + 8 * col] = before[row + 8 * to];
            } else {
                s[row + 8 * to] = before[row + 8 * col];
            }
        }
    }
}

/// Each column times the circulant matrix `mul` tabulates, over whole
/// columns. Shared with Kupyna.
pub(crate) fn mix_columns(s: &mut [u8], mul: &[[u8; 256]; 8]) {
    for col in s.chunks_exact_mut(8) {
        let c: [u8; 8] = col.try_into().expect("eight bytes");
        for (r, out) in col.iter_mut().enumerate() {
            let mut acc = 0;
            for (b, &x) in c.iter().enumerate() {
                acc ^= mul[(b + 8 - r) % 8][x as usize];
            }
            *out = acc;
        }
    }
}

fn encrypt_round(s: &mut State, nb: usize) {
    sub_bytes(&mut s[..8 * nb], &SBOX);
    shift_rows(s, nb, false);
    mix_columns(&mut s[..8 * nb], &MUL);
}

fn decrypt_round(s: &mut State, nb: usize) {
    mix_columns(&mut s[..8 * nb], &MUL_INV);
    shift_rows(s, nb, true);
    sub_bytes(&mut s[..8 * nb], &INV_SBOX);
}

/// Each column of the state combined with the matching word of `k`.
fn combine(s: &mut State, nb: usize, k: &[u64], op: fn(u64, u64) -> u64) {
    for (col, &word) in s[..8 * nb].chunks_exact_mut(8).zip(&k[..nb]) {
        let value = u64::from_le_bytes(col.try_into().expect("eight bytes"));
        col.copy_from_slice(&op(value, word).to_le_bytes());
    }
}

fn add(s: &mut State, nb: usize, k: &[u64]) {
    combine(s, nb, k, u64::wrapping_add);
}

fn xor(s: &mut State, nb: usize, k: &[u64]) {
    combine(s, nb, k, |a, b| a ^ b);
}

fn subtract(s: &mut State, nb: usize, k: &[u64]) {
    combine(s, nb, k, u64::wrapping_sub);
}

fn words(s: &State, nb: usize) -> [u64; 8] {
    let mut w = [0u64; 8];
    for (word, col) in w.iter_mut().zip(s[..8 * nb].chunks_exact(8)) {
        *word = u64::from_le_bytes(col.try_into().expect("eight bytes"));
    }
    w
}

fn state_of(w: &[u64], nb: usize) -> State {
    let mut s = [0u8; 64];
    for (col, word) in s[..8 * nb].chunks_exact_mut(8).zip(&w[..nb]) {
        col.copy_from_slice(&word.to_le_bytes());
    }
    s
}

impl Kalyna {
    /// Kalyna with a block of 16, 32 or 64 bytes and a key the block's
    /// length or twice it (64 bytes at most).
    ///
    /// # Errors
    /// Any other block or key length.
    pub fn new(block_bytes: usize, key: &[u8]) -> Result<Kalyna, String> {
        if !matches!(block_bytes, 16 | 32 | 64) {
            return Err(format!("Kalyna's block is 16, 32 or 64 bytes, not {block_bytes}."));
        }
        if key.len() != block_bytes && (key.len() != 2 * block_bytes || block_bytes == 64) {
            return Err(format!(
                "Wrong key length {} for Kalyna's {}-byte block, which takes {}.",
                key.len(), block_bytes,
                if block_bytes == 64 { "64".to_string() }
                else { format!("{} or {}", block_bytes, 2 * block_bytes) }));
        }
        let nb = block_bytes / 8;
        let nk = key.len() / 8;
        let rounds = match nk {
            2 => 10,
            4 => 14,
            _ => 18,
        };
        let mut k = [0u64; 16];
        for (word, bytes) in k.iter_mut().zip(key.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
        }
        let key_words = &k[..nk];

        // 1. Kt.
        let (k0, k1) = if nk == nb { (key_words, key_words) }
                       else { (&key_words[..nb], &key_words[nb..]) };
        let mut s = [0u8; 64];
        s[0] = (nb + nk + 1) as u8;
        add(&mut s, nb, k0);
        encrypt_round(&mut s, nb);
        xor(&mut s, nb, k1);
        encrypt_round(&mut s, nb);
        add(&mut s, nb, k0);
        encrypt_round(&mut s, nb);
        let kt = words(&s, nb);

        // 2. The even round keys.
        let mut round_keys = vec![[0u64; 8]; rounds + 1];
        let mut tmv = [0x0001_0001_0001_0001u64; 8];
        let mut data = k;
        let even_key = |tmv: &[u64; 8], half: &[u64]| {
            let mut kt_round = kt;
            for (a, b) in kt_round[..nb].iter_mut().zip(&tmv[..nb]) {
                *a = a.wrapping_add(*b);
            }
            let mut s = state_of(half, nb);
            add(&mut s, nb, &kt_round);
            encrypt_round(&mut s, nb);
            xor(&mut s, nb, &kt_round);
            encrypt_round(&mut s, nb);
            add(&mut s, nb, &kt_round);
            words(&s, nb)
        };
        let mut round = 0;
        loop {
            round_keys[round] = even_key(&tmv, &data[..nb]);
            if round == rounds {
                break;
            }
            if nk != nb {
                round += 2;
                tmv.iter_mut().for_each(|t| *t <<= 1);
                round_keys[round] = even_key(&tmv, &data[nb..nk]);
                if round == rounds {
                    break;
                }
            }
            round += 2;
            tmv.iter_mut().for_each(|t| *t <<= 1);
            data[..nk].rotate_left(1);
        }

        // 3. The odd ones: the even key before, rotated left 2·Nb + 3 bytes.
        for odd in (1..rounds).step_by(2) {
            let mut bytes = state_of(&round_keys[odd - 1], nb);
            bytes[..8 * nb].rotate_left(2 * nb + 3);
            round_keys[odd] = words(&bytes, nb);
        }
        Ok(Kalyna { nb, rounds, round_keys })
    }

    /// The block size in bytes.
    pub fn block_bytes(&self) -> usize {
        8 * self.nb
    }
}

impl BlockCipher for Kalyna {
    fn blocksize(&self) -> usize {
        8 * self.nb
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (nb, n) = (self.nb, 8 * self.nb);
        let mut s = [0u8; 64];
        s[..n].copy_from_slice(&input[..n]);
        add(&mut s, nb, &self.round_keys[0]);
        for round in 1..self.rounds {
            encrypt_round(&mut s, nb);
            xor(&mut s, nb, &self.round_keys[round]);
        }
        encrypt_round(&mut s, nb);
        add(&mut s, nb, &self.round_keys[self.rounds]);
        result.extend_from_slice(&s[..n]);
    }

    /// DSTU 7624's counter mode (gamma): the counter starts as the
    /// **encrypted** IV, and each block it is incremented first, as one
    /// little-endian integer, and then encrypted. GOST's counter mode has
    /// the same shape and overrides these two hooks the same way.
    fn ctr_init(&mut self, iv: &[u8], counter: &mut Vec<u8>) -> Result<(), String> {
        if iv.len() != self.blocksize() {
            return Err(format!("Kalyna's counter mode takes an IV of one block, {} bytes, \
                                not {}.", self.blocksize(), iv.len()));
        }
        counter.clear();
        self.block_encrypt(iv, counter);
        self.ctr_next(counter);
        Ok(())
    }

    /// Little-endian, every byte touched: the counter starts at
    /// `E(IV)`, so where a carry stops is a fact about a secret.
    fn ctr_next(&self, counter: &mut [u8]) {
        let mut carry = 1u16;
        for b in counter.iter_mut() {
            let sum = u16::from(*b) + carry;
            *b = sum as u8;
            carry = sum >> 8;
        }
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (nb, n) = (self.nb, 8 * self.nb);
        let mut s = [0u8; 64];
        s[..n].copy_from_slice(&input[..n]);
        subtract(&mut s, nb, &self.round_keys[self.rounds]);
        for round in (1..self.rounds).rev() {
            decrypt_round(&mut s, nb);
            xor(&mut s, nb, &self.round_keys[round]);
        }
        decrypt_round(&mut s, nb);
        subtract(&mut s, nb, &self.round_keys[0]);
        result.extend_from_slice(&s[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inverse tables really are inverses, and MDS_INV inverts MDS:
    /// the product of the two circulants is the identity.
    #[test]
    fn test_the_inverses() {
        for s in 0..4 {
            for x in 0..=255u8 {
                assert_eq!(INV_SBOX[s][SBOX[s][x as usize] as usize], x);
            }
        }
        for r in 0..8 {
            for c in 0..8 {
                let mut acc = 0;
                for k in 0..8 {
                    acc ^= gf_mul(MDS[(k + 8 - r) % 8], MDS_INV[(c + 8 - k) % 8]);
                }
                assert_eq!(acc, u8::from(r == c), "({r}, {c})");
            }
        }
    }

    #[test]
    fn test_sizes_and_round_trips() {
        for (block, key, rounds) in [(16, 16, 10), (16, 32, 14), (32, 32, 14),
                                     (32, 64, 18), (64, 64, 18)] {
            let mut k = Kalyna::new(block, &(0..key as u8).collect::<Vec<u8>>()).unwrap();
            assert_eq!((k.rounds, k.block_bytes()), (rounds, block));
            let pt: Vec<u8> = (0..block as u8).map(|i| i.wrapping_mul(29)).collect();
            let mut ct = vec![0xee];
            k.block_encrypt(&pt, &mut ct);
            assert_eq!(ct.len(), block + 1);
            assert_ne!(ct[1..], pt[..]);
            let mut back = Vec::new();
            k.block_decrypt(&ct[1..], &mut back);
            assert_eq!(back, pt);
        }
        for (block, key) in [(16, 24), (16, 64), (32, 16), (64, 32), (64, 128), (24, 24), (16, 0)] {
            assert!(Kalyna::new(block, &vec![0; key]).is_err(), "{block}/{key}");
        }
    }
}
