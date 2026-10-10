/*
DES and Triple DES (FIPS 46-3).

DES is a 16-round Feistel cipher on 64 bit blocks with a 56 bit key. It was
the standard from 1977 until 2001 and it is thoroughly broken: 56 bits was
brute-forced in public in 1998 and costs very little now. Triple DES buys
back key length and nothing else - it is still a 64 bit block cipher, and
that is what Sweet32 attacks, so a long-lived connection leaks plaintext
after a few hundred gigabytes regardless of the key.

Both are here and both are marked. `DES-CBC3-SHA` is one of the most
common things on equipment nobody is going to upgrade, and refusing to
implement it does not make that equipment go away.

## Written from the tables, not from bit tricks

Every permutation here is a table from the standard, and `permute`
applies one bit by bit, exactly as the document reads. The block
operation does not call it per block: at compile time it builds, from
those same tables,

- `SP`, the eight S-boxes with P already applied to their output, so a
  round is eight lookups and XORs;
- `IP_NIBBLES` and `FP_NIBBLES`, the initial and final permutations as
  sixteen lookups each, one per input nibble - a bit permutation is
  linear, so the permutation of a word is the XOR of the permutations of
  its nibbles;

and E is eight rotations, one per six-bit group. Each derived table is
checked against `permute` and the original tables by a test, so the
document is still what the cipher is checked against. There is a
well-known way to write the initial permutation as a dozen shift-and-mask
operations; it is not used, because it cannot be read against the
standard.

Triple DES runs its three stages as forty-eight rounds between one IP and
one FP: each inner FP is undone by the next stage's IP.

## The parity bits

A DES key is eight bytes but only 56 bits are used: the low bit of each
byte is a parity bit, dropped by PC1. That means **`k` and `k` with any
parity bit flipped are the same key**, which is not a bug and is worth
knowing before wondering why two different keys agree. Nothing here checks
or sets parity, because a key that fails a parity check still works
everywhere and rejecting it would refuse keys that real equipment uses.

## Weak keys

Four keys make all sixteen subkeys identical, so encryption is its own
inverse; twelve more form semi-weak pairs. They are listed and detectable
via `is_weak`, and **not** rejected: this library does not refuse to
compute something, and a caller who wants the check can ask for it.
*/

use crate::block_ciphers::BlockCipher;

// ------------------------------------------------------------- the tables ---

/// Initial permutation. 1-indexed positions into the 64 bit block, MSB
/// first, as the standard writes them.
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// The inverse of `IP`, applied at the end.
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25,
];

/// Expansion, 32 bits to 48, by repeating the bits either side of each
/// four bit group. This is what makes one input bit affect two S-boxes.
/// The block operation does it with rotations (`round_function`); the
/// reference round function and the tests read this table.
#[cfg_attr(not(test), allow(dead_code))]
const E: [u8; 48] = [
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
];

/// The permutation applied to the S-box output, which is what spreads each
/// S-box's four bits across the next round's inputs.
const P: [u8; 32] = [
    16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25,
];

/// Permuted choice 1: 64 key bits down to 56, dropping the parity bits.
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
];

/// Permuted choice 2: 56 bits of rotated key down to a 48 bit subkey.
const PC2: [u8; 48] = [
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// How far each round rotates the two key halves. They sum to 28, which is
/// why the schedule returns to its starting point and why the same code
/// can run backwards for decryption.
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// The eight S-boxes, each 4 rows of 16. The row is the outer two bits of
/// the six and the column is the inner four - an ordering that is easy to
/// get wrong and that `test_sbox_indexing` pins.
const S: [[u8; 64]; 8] = [
    [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
      0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
      4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
     15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
      3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
     13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
      1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
     13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
      3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
     14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
      4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
     10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
      9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
      4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
     13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
      1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
      6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
      1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
      7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
      2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
];

/// The four weak keys: every subkey is identical, so `E(E(m)) == m`.
pub const WEAK_KEYS: [u64; 4] = [
    0x0101_0101_0101_0101,
    0xfefe_fefe_fefe_fefe,
    0xe0e0_e0e0_f1f1_f1f1,
    0x1f1f_1f1f_0e0e_0e0e,
];

/// The six semi-weak pairs: each pair encrypts to the other's decryption.
pub const SEMI_WEAK_KEYS: [u64; 12] = [
    0x01fe_01fe_01fe_01fe, 0xfe01_fe01_fe01_fe01,
    0x1fe0_1fe0_0ef1_0ef1, 0xe01f_e01f_f10e_f10e,
    0x01e0_01e0_01f1_01f1, 0xe001_e001_f101_f101,
    0x1ffe_1ffe_0efe_0efe, 0xfe1f_fe1f_fe0e_fe0e,
    0x011f_011f_010e_010e, 0x1f01_1f01_0e01_0e01,
    0xe0fe_e0fe_f1fe_f1fe, 0xfee0_fee0_fef1_fef1,
];

// ------------------------------------------------------------- primitives ---

/// Apply a 1-indexed permutation table, MSB first.
///
/// `input_bits` is how wide `input` is, because the tables index from the
/// left and the left depends on the width. Getting that wrong produces a
/// cipher that is perfectly self-consistent and matches nothing.
const fn permute(input: u64, table: &[u8], input_bits: usize) -> u64 {
    let mut out = 0u64;
    let mut index = 0;
    while index < table.len() {
        let bit = (input >> (input_bits - table[index] as usize)) & 1;
        out |= bit << (table.len() - 1 - index);
        index += 1;
    }
    out
}

/// The S-box at a six bit input: the row is the outer two bits, the
/// column the inner four.
const fn sbox_lookup(box_index: usize, six: usize) -> u8 {
    let row = ((six & 0b100000) >> 4) | (six & 1);
    let column = (six >> 1) & 0b1111;
    S[box_index][row * 16 + column]
}

/// S-box `i` followed by P, for every six bit input: the round function's
/// output bits from that S-box, in place.
const SP: [[u32; 64]; 8] = {
    let mut table = [[0u32; 64]; 8];
    let mut i = 0;
    while i < 8 {
        let mut six = 0;
        while six < 64 {
            let nibble = sbox_lookup(i, six) as u64;
            table[i][six] = permute(nibble << (28 - 4 * i), &P, 32) as u32;
            six += 1;
        }
        i += 1;
    }
    table
};

/// A 64 bit permutation as one table per input nibble, most significant
/// nibble first.
const fn nibble_tables(table: &[u8; 64]) -> [[u64; 16]; 16] {
    let mut out = [[0u64; 16]; 16];
    let mut position = 0;
    while position < 16 {
        let mut value = 0;
        while value < 16 {
            out[position][value] = permute((value as u64) << (60 - 4 * position), table, 64);
            value += 1;
        }
        position += 1;
    }
    out
}

const IP_NIBBLES: [[u64; 16]; 16] = nibble_tables(&IP);
const FP_NIBBLES: [[u64; 16]; 16] = nibble_tables(&FP);

#[inline(always)]
fn permute_fast(input: u64, nibbles: &[[u64; 16]; 16]) -> u64 {
    let mut out = 0u64;
    for (position, table) in nibbles.iter().enumerate() {
        out |= table[((input >> (60 - 4 * position)) & 0xf) as usize];
    }
    out
}

/// Rotate a 28 bit half-key left.
#[inline]
fn rotate28(value: u32, by: u32) -> u32 {
    ((value << by) | (value >> (28 - by))) & 0x0fff_ffff
}

/// The Feistel round function as the standard writes it: expand, XOR the
/// subkey, substitute, permute. The reference `round_function` is tested
/// against.
#[cfg(test)]
fn f(right: u32, subkey: u64) -> u32 {
    let expanded = permute(right as u64, &E, 32) ^ subkey;

    let mut substituted = 0u64;
    for box_index in 0..8 {
        // Six bits per S-box, taken from the left.
        let six = ((expanded >> (42 - 6 * box_index)) & 0x3f) as usize;
        substituted |= (sbox_lookup(box_index, six) as u64) << (28 - 4 * box_index);
    }
    permute(substituted, &P, 32) as u32
}

/// A subkey cut into the eight six bit groups the S-boxes take.
fn subkey_groups(subkey: u64) -> [u8; 8] {
    core::array::from_fn(|i| ((subkey >> (42 - 6 * i)) & 0x3f) as u8)
}

/// The round function from `SP`. E's group `i` is bits `4i` to `4i+5` of
/// the half block, 1-indexed from the left and wrapping, so rotating
/// right by `27 - 4i` puts it in the low six bits.
#[inline(always)]
fn round_function(right: u32, groups: &[u8; 8]) -> u32 {
    let mut out = 0u32;
    for i in 0..8 {
        let six = (right.rotate_right((27 + 32 - 4 * i as u32) % 32) & 0x3f) as u8 ^ groups[i];
        out |= SP[i][six as usize];
    }
    out
}

/// The sixteen 48 bit subkeys, in encryption order.
fn schedule(key: u64) -> [u64; 16] {
    let permuted = permute(key, &PC1, 64);
    let mut c = ((permuted >> 28) & 0x0fff_ffff) as u32;
    let mut d = (permuted & 0x0fff_ffff) as u32;

    let mut subkeys = [0u64; 16];
    for round in 0..16 {
        c = rotate28(c, SHIFTS[round]);
        d = rotate28(d, SHIFTS[round]);
        subkeys[round] = permute(((c as u64) << 28) | d as u64, &PC2, 56);
    }
    subkeys
}

/// The sixteen rounds on the two halves after IP. Returns `(R16, L16)`,
/// the order FP takes them in: the last round does not swap. `subkeys` in
/// reverse order is decryption - that symmetry is the whole point of a
/// Feistel network.
#[inline(always)]
fn rounds(mut left: u32, mut right: u32, keys: &[[u8; 8]; 16], forward: bool) -> (u32, u32) {
    for round in 0..16 {
        let groups = if forward { &keys[round] } else { &keys[15 - round] };
        let next = left ^ round_function(right, groups);
        left = right;
        right = next;
    }
    (right, left)
}

/// One DES block operation.
fn block(input: u64, keys: &[[u8; 8]; 16], forward: bool) -> u64 {
    let permuted = permute_fast(input, &IP_NIBBLES);
    let (high, low) = rounds((permuted >> 32) as u32, permuted as u32, keys, forward);
    // The halves are swapped once at the end: the output is R16||L16 rather
    // than L16||R16. Leave the swap out and the cipher still round-trips
    // against itself.
    permute_fast(((high as u64) << 32) | low as u64, &FP_NIBBLES)
}

/// Three DES operations with the inner FP and IP cancelled: each stage
/// hands the next its `(R16, L16)`, which is what IP would recover from
/// FP's output.
fn triple(input: u64, stages: [(&[[u8; 8]; 16], bool); 3]) -> u64 {
    let permuted = permute_fast(input, &IP_NIBBLES);
    let (mut left, mut right) = ((permuted >> 32) as u32, permuted as u32);
    for (keys, forward) in stages {
        (left, right) = rounds(left, right, keys, forward);
    }
    permute_fast(((left as u64) << 32) | right as u64, &FP_NIBBLES)
}

/// The Unix `crypt(3)` variant of DES: `count` encryptions of `block`
/// under `key`, with E perturbed by a salt. Salt bit `i` (from the least
/// significant) swaps bit `i` of E's first 24 output bits with bit `i` of
/// its last 24, counting from the left - bits 1 and 25 for the lowest. A
/// salt of zero is DES; `traditional` crypt uses 12 bits of salt and 25
/// encryptions, BSDi's extended form 24 bits and a count from the hash.
///
/// The inner FP and IP cancel between encryptions, as in `triple`.
pub(crate) fn crypt_des(key: u64, salt: u32, block: u64, count: u32) -> u64 {
    let subkeys = schedule(key);
    let keys: [[u8; 8]; 16] = core::array::from_fn(|i| subkey_groups(subkeys[i]));
    // The salt as a mask on each of E's first four six-bit groups; the
    // swap is with the group four further on.
    let masks: [u8; 4] = core::array::from_fn(|group| {
        let mut mask = 0u8;
        for bit in 0..6 {
            if salt >> (6 * group + bit) & 1 == 1 {
                mask |= 0x20 >> bit;
            }
        }
        mask
    });
    let permuted = permute_fast(block, &IP_NIBBLES);
    let (mut left, mut right) = ((permuted >> 32) as u32, permuted as u32);
    for _ in 0..count.max(1) {
        for groups in &keys {
            let mut six: [u8; 8] = core::array::from_fn(|i| {
                (right.rotate_right((27 + 32 - 4 * i as u32) % 32) & 0x3f) as u8
            });
            for (j, mask) in masks.iter().enumerate() {
                let swap = (six[j] ^ six[j + 4]) & mask;
                six[j] ^= swap;
                six[j + 4] ^= swap;
            }
            let mut out = 0u32;
            for i in 0..8 {
                out |= SP[i][(six[i] ^ groups[i]) as usize];
            }
            let next = left ^ out;
            left = right;
            right = next;
        }
        (left, right) = (right, left);
    }
    permute_fast(((left as u64) << 32) | right as u64, &FP_NIBBLES)
}

/// The block operation as the standard writes it, `permute` and all: the
/// reference the fast one is tested against.
#[cfg(test)]
fn reference_block(input: u64, subkeys: &[u64; 16], forward: bool) -> u64 {
    let permuted = permute(input, &IP, 64);
    let mut left = (permuted >> 32) as u32;
    let mut right = permuted as u32;
    for round in 0..16 {
        let subkey = if forward { subkeys[round] } else { subkeys[15 - round] };
        let next = left ^ f(right, subkey);
        left = right;
        right = next;
    }
    permute(((right as u64) << 32) | left as u64, &FP, 64)
}

fn to_u64(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for &byte in bytes.iter().take(8) {
        value = (value << 8) | byte as u64;
    }
    value
}

// ----------------------------------------------------------------- parity ---

/// Set each byte's low bit so the byte has an odd number of ones: the
/// parity DES keys are written with. The cipher ignores the bit; formats
/// check it (RFC 3217's key wrap refuses a key without it) and derive
/// keys with it set (RFC 3961's random-to-key).
pub fn set_odd_parity(key: &mut [u8]) {
    for b in key {
        *b = (*b & 0xfe) | u8::from((*b & 0xfe).count_ones().is_multiple_of(2));
    }
}

/// Whether every byte has odd parity.
pub fn has_odd_parity(key: &[u8]) -> bool {
    key.iter().all(|b| b.count_ones() % 2 == 1)
}

// -------------------------------------------------------------------- DES ---

/// Single DES. **56 bits of key**, which has been brute-forceable in
/// public since 1998.
pub struct Des {
    /// The sixteen subkeys, each as its eight six bit S-box groups.
    keys: [[u8; 8]; 16],
}

impl Des {
    pub fn new(key: &[u8]) -> Result<Des, String> {
        if key.len() != 8 {
            return Err(format!("DES takes an 8 byte key, got {}.", key.len()));
        }
        Ok(Des { keys: schedule(to_u64(key)).map(subkey_groups) })
    }

    /// Whether this key is one of the four weak or twelve semi-weak keys.
    ///
    /// Reported, not refused. The parity bits are ignored, as they are
    /// everywhere else here, so a key that differs from a weak one only in
    /// its parity bits is still weak - which is exactly the case somebody
    /// checking by eye would miss.
    pub fn is_weak(key: &[u8]) -> bool {
        if key.len() != 8 {
            return false;
        }
        let stripped = to_u64(key) & 0xfefe_fefe_fefe_fefe;
        WEAK_KEYS.iter().chain(SEMI_WEAK_KEYS.iter())
            .any(|&weak| weak & 0xfefe_fefe_fefe_fefe == stripped)
    }
}

impl BlockCipher for Des {
    fn blocksize(&self) -> usize {
        8
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&block(to_u64(input), &self.keys, true).to_be_bytes());
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&block(to_u64(input), &self.keys, false).to_be_bytes());
    }
}

// ------------------------------------------------------------- Triple DES ---

/// Triple DES in EDE mode: `E_k1(D_k2(E_k3(m)))`.
///
/// The middle operation is a **decryption**, and not for any cryptographic
/// reason: it means that setting all three keys equal reduces to single
/// DES, so a 3DES implementation can talk to a DES one. That backward
/// compatibility is the only reason EDE is not EEE.
///
/// A 16 byte key is two-key 3DES, where k3 = k1. A 24 byte key is
/// three-key. TLS uses the 24 byte form, and an 8 byte key is accepted
/// here as plain DES for the same compatibility reason EDE exists.
///
/// **Still a 64 bit block cipher.** Triple DES fixes the key length and
/// nothing else, so Sweet32 applies: birthday collisions in CBC leak
/// plaintext after around 2^32 blocks, which is 32 GB on one connection.
/// See `docs/pitfalls.md`.
pub struct TripleDes {
    first: Des,
    second: Des,
    third: Des,
}

impl TripleDes {
    pub fn new(key: &[u8]) -> Result<TripleDes, String> {
        let (k1, k2, k3) = match key.len() {
            8 => (&key[0..8], &key[0..8], &key[0..8]),
            16 => (&key[0..8], &key[8..16], &key[0..8]),
            24 => (&key[0..8], &key[8..16], &key[16..24]),
            other => return Err(format!(
                "Triple DES takes an 8, 16 or 24 byte key, got {}.", other)),
        };
        Ok(TripleDes {
            first: Des::new(k1)?,
            second: Des::new(k2)?,
            third: Des::new(k3)?,
        })
    }
}

impl BlockCipher for TripleDes {
    fn blocksize(&self) -> usize {
        8
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let out = triple(to_u64(input), [(&self.first.keys, true), (&self.second.keys, false),
                                         (&self.third.keys, true)]);
        result.extend_from_slice(&out.to_be_bytes());
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let out = triple(to_u64(input), [(&self.third.keys, false), (&self.second.keys, true),
                                         (&self.first.keys, false)]);
        result.extend_from_slice(&out.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn des(key: &str, plaintext: &str) -> String {
        let mut cipher = Des::new(&unhex(key)).unwrap();
        let mut out = Vec::new();
        cipher.block_encrypt(&unhex(plaintext), &mut out);
        hex(&out)
    }

    /// The vectors everybody uses, including the worked example from the
    /// standard's own walkthrough.
    #[test]
    fn test_the_known_vectors() {
        // The classic worked example.
        assert_eq!(des("133457799bbcdff1", "0123456789abcdef"),
                   "85e813540f0ab405");
        // All zeros, all ones.
        assert_eq!(des("0000000000000000", "0000000000000000"),
                   "8ca64de9c1b123a7");
        assert_eq!(des("ffffffffffffffff", "ffffffffffffffff"),
                   "7359b2163e4edc58");
        assert_eq!(des("3000000000000000", "1000000000000001"),
                   "958e6e627a05557b");
        assert_eq!(des("1111111111111111", "1111111111111111"),
                   "f40379ab9e0ec533");
        assert_eq!(des("0123456789abcdef", "1111111111111111"),
                   "17668dfc7292532d");
        assert_eq!(des("fedcba9876543210", "0123456789abcdef"),
                   "ed39d950fa74bcc4");
    }

    #[test]
    fn test_round_trip() {
        let key = unhex("133457799bbcdff1");
        for value in ["0000000000000000", "ffffffffffffffff",
                      "0123456789abcdef", "deadbeefcafebabe"] {
            let mut cipher = Des::new(&key).unwrap();
            let mut encrypted = Vec::new();
            cipher.block_encrypt(&unhex(value), &mut encrypted);

            let mut decrypted = Vec::new();
            cipher.block_decrypt(&encrypted, &mut decrypted);
            assert_eq!(hex(&decrypted), value);
        }
    }

    /// The parity bits are not part of the key, so flipping any of them
    /// must change nothing. Surprising, and true.
    #[test]
    fn test_parity_bits_are_ignored() {
        let base = des("133457799bbcdff1", "0123456789abcdef");
        // The low bit of every byte, flipped.
        assert_eq!(des("123456789abcdef0", "0123456789abcdef"), base);
        // And one at a time.
        for byte in 0..8 {
            let mut key = unhex("133457799bbcdff1");
            key[byte] ^= 0x01;
            let mut cipher = Des::new(&key).unwrap();
            let mut out = Vec::new();
            cipher.block_encrypt(&unhex("0123456789abcdef"), &mut out);
            assert_eq!(hex(&out), base, "parity bit in byte {} mattered", byte);
        }
    }

    /// A weak key makes encryption its own inverse, which is the whole
    /// definition and a cheap way to confirm the key schedule is right:
    /// it only holds if all sixteen subkeys really are identical.
    #[test]
    fn test_weak_keys_are_their_own_inverse() {
        let plaintext = unhex("0123456789abcdef");
        for weak in WEAK_KEYS {
            let key = weak.to_be_bytes().to_vec();
            assert!(Des::is_weak(&key), "0x{:016x} not reported weak", weak);

            let mut cipher = Des::new(&key).unwrap();
            let mut once = Vec::new();
            cipher.block_encrypt(&plaintext, &mut once);
            let mut twice = Vec::new();
            cipher.block_encrypt(&once, &mut twice);
            assert_eq!(twice, plaintext,
                       "0x{:016x} is not self-inverse", weak);
        }

        // A semi-weak pair: one's encryption is the other's.
        for pair in SEMI_WEAK_KEYS.chunks(2) {
            let mut a = Des::new(&pair[0].to_be_bytes()).unwrap();
            let mut b = Des::new(&pair[1].to_be_bytes()).unwrap();
            let mut once = Vec::new();
            a.block_encrypt(&plaintext, &mut once);
            let mut back = Vec::new();
            b.block_encrypt(&once, &mut back);
            assert_eq!(back, plaintext,
                       "0x{:016x}/0x{:016x} are not a semi-weak pair",
                       pair[0], pair[1]);
            assert!(Des::is_weak(&pair[0].to_be_bytes()));
        }

        // And an ordinary key is not weak, including one that differs from
        // a weak key only in its parity bits - which `is_weak` must catch,
        // since the parity bits are not part of the key.
        assert!(!Des::is_weak(&unhex("133457799bbcdff1")));
        assert!(Des::is_weak(&unhex("0000000000000000")),
                "all-zero differs from 0101..01 only in parity");
    }

    /// Three keys the same reduces to single DES. That is the only reason
    /// the middle operation is a decryption, so it is worth pinning.
    #[test]
    fn test_triple_des_with_one_key_is_des() {
        let key = unhex("133457799bbcdff1");
        let plaintext = unhex("0123456789abcdef");

        let mut single = Des::new(&key).unwrap();
        let mut from_des = Vec::new();
        single.block_encrypt(&plaintext, &mut from_des);

        for repeated in [key.repeat(1), key.repeat(2), key.repeat(3)] {
            let mut triple = TripleDes::new(&repeated).unwrap();
            let mut from_triple = Vec::new();
            triple.block_encrypt(&plaintext, &mut from_triple);
            assert_eq!(from_triple, from_des,
                       "{} byte key did not reduce to DES", repeated.len());
        }
    }

    #[test]
    fn test_triple_des_round_trip() {
        let plaintext = unhex("0123456789abcdef");
        for key in ["0123456789abcdef23456789abcdef01",
                    "0123456789abcdef23456789abcdef01456789abcdef0123"] {
            let mut cipher = TripleDes::new(&unhex(key)).unwrap();
            let mut encrypted = Vec::new();
            cipher.block_encrypt(&plaintext, &mut encrypted);
            assert_ne!(encrypted, plaintext);

            let mut decrypted = Vec::new();
            cipher.block_decrypt(&encrypted, &mut decrypted);
            assert_eq!(decrypted, plaintext, "key of {} bytes", key.len() / 2);
        }
    }

    /// Two-key 3DES is three-key with k3 = k1, not with k3 = k2.
    #[test]
    fn test_two_key_is_three_key_with_the_first_repeated() {
        let k1 = "0123456789abcdef";
        let k2 = "23456789abcdef01";
        let plaintext = unhex("0123456789abcdef");

        let mut two = TripleDes::new(&unhex(&format!("{}{}", k1, k2))).unwrap();
        let mut from_two = Vec::new();
        two.block_encrypt(&plaintext, &mut from_two);

        let mut three =
            TripleDes::new(&unhex(&format!("{}{}{}", k1, k2, k1))).unwrap();
        let mut from_three = Vec::new();
        three.block_encrypt(&plaintext, &mut from_three);

        assert_eq!(from_two, from_three);
    }

    #[test]
    fn test_key_lengths_are_checked() {
        for length in [0usize, 1, 7, 9, 16, 24] {
            assert!(Des::new(&vec![0; length]).is_err(), "DES took {} bytes", length);
        }
        assert!(Des::new(&[0; 8]).is_ok());

        for length in [0usize, 7, 9, 15, 17, 23, 25, 32] {
            assert!(TripleDes::new(&vec![0; length]).is_err(),
                    "3DES took {} bytes", length);
        }
        for length in [8usize, 16, 24] {
            assert!(TripleDes::new(&vec![0; length]).is_ok());
        }
    }

    /// The permutation helper indexes from the left, and the width it is
    /// told matters. This is the single easiest thing in the file to get
    /// wrong in a way that is self-consistent.
    #[test]
    fn test_permute_indexes_from_the_left() {
        // Identity over 8 bits.
        let identity: Vec<u8> = (1..=8).collect();
        assert_eq!(permute(0b1011_0010, &identity, 8), 0b1011_0010);

        // Reverse.
        let reverse: Vec<u8> = (1..=8).rev().collect();
        assert_eq!(permute(0b1000_0000, &reverse, 8), 0b0000_0001);

        // Position 1 is the most significant bit, not the least.
        assert_eq!(permute(0b1000_0000, &[1], 8), 1);
        assert_eq!(permute(0b0000_0001, &[8], 8), 1);
        assert_eq!(permute(0b0000_0001, &[1], 8), 0);
    }

    /// The S-box row is the outer two bits and the column the inner four.
    /// Swap them and DES still round-trips, still diffuses, and matches
    /// nothing.
    #[test]
    fn test_sbox_indexing() {
        // S1 with input 000000: row 0, column 0 -> 14.
        assert_eq!(S[0][0], 14);
        // S1 with input 111111: row 3, column 15 -> 13.
        assert_eq!(S[0][3 * 16 + 15], 13);
        // S1 with input 011000 = row 0, column 12 -> 5. If row and column
        // were swapped this would be row 12, which does not exist.
        let six = 0b011000usize;
        let row = ((six & 0b100000) >> 4) | (six & 1);
        let column = (six >> 1) & 0b1111;
        assert_eq!((row, column), (0, 12));
        assert_eq!(S[0][row * 16 + column], 5);
    }

    /// Every S-box row must be a permutation of 0..16. A typo in the
    /// tables almost always breaks this, and it is the only check on them
    /// that does not need another implementation.
    #[test]
    fn test_the_sboxes_are_well_formed() {
        for (index, sbox) in S.iter().enumerate() {
            for row in 0..4 {
                let mut seen = [false; 16];
                for column in 0..16 {
                    let value = sbox[row * 16 + column] as usize;
                    assert!(value < 16, "S{} has {} in it", index + 1, value);
                    assert!(!seen[value],
                            "S{} row {} repeats {}", index + 1, row, value);
                    seen[value] = true;
                }
            }
        }
    }

    /// The permutation tables must each be a permutation of their range,
    /// and the expansion must use every input bit.
    #[test]
    fn test_the_tables_are_well_formed() {
        fn is_permutation(table: &[u8], of: usize) {
            let mut seen = vec![false; of + 1];
            for &position in table {
                let position = position as usize;
                assert!(position >= 1 && position <= of, "{} out of range", position);
                assert!(!seen[position], "{} appears twice", position);
                seen[position] = true;
            }
        }
        is_permutation(&IP, 64);
        is_permutation(&FP, 64);
        is_permutation(&P, 32);
        is_permutation(&PC1, 64);

        // IP and FP must be inverses.
        for bit in 1..=64u64 {
            let value = 1u64 << (64 - bit);
            assert_eq!(permute(permute(value, &IP, 64), &FP, 64), value,
                       "IP then FP did not restore bit {}", bit);
        }

        // The expansion repeats, so it is not a permutation - but every
        // input bit must appear, twice for sixteen of them.
        let mut counts = [0usize; 33];
        for &position in &E {
            counts[position as usize] += 1;
        }
        assert_eq!(counts[0], 0);
        assert!(counts[1..].iter().all(|&n| n == 1 || n == 2));
        assert_eq!(counts[1..].iter().filter(|&&n| n == 2).count(), 16);
        assert_eq!(counts[1..].iter().sum::<usize>(), 48);

        // PC2 selects 48 of the 56 rotated bits, dropping eight.
        let mut seen = [false; 57];
        for &position in &PC2 {
            assert!(!seen[position as usize]);
            seen[position as usize] = true;
        }
    }

    /// The fast round function is the standard's - expand by E, XOR,
    /// substitute, permute by P - for every S-box input and a spread of
    /// half blocks and subkeys.
    #[test]
    fn test_the_derived_round_is_the_reference_round() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let right = next() as u32;
            let subkey = next() & 0xffff_ffff_ffff;
            assert_eq!(round_function(right, &subkey_groups(subkey)), f(right, subkey),
                       "R {right:08x} K {subkey:012x}");
        }
        // Each S-box at each input, through SP alone.
        for (i, table) in SP.iter().enumerate() {
            for (six, entry) in table.iter().enumerate() {
                let want = permute((sbox_lookup(i, six) as u64) << (28 - 4 * i), &P, 32);
                assert_eq!(*entry as u64, want);
            }
        }
    }

    /// IP and FP from nibble tables are `permute` with the standard's
    /// tables, for every single bit and random words.
    #[test]
    fn test_the_nibble_permutations_are_the_tables() {
        for bit in 0..64 {
            assert_eq!(permute_fast(1 << bit, &IP_NIBBLES), permute(1 << bit, &IP, 64));
            assert_eq!(permute_fast(1 << bit, &FP_NIBBLES), permute(1 << bit, &FP, 64));
        }
        let mut x = 0x0123_4567_89ab_cdefu64;
        for _ in 0..1000 {
            x = x.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(0x1405_7b7e_f767_814f);
            assert_eq!(permute_fast(x, &IP_NIBBLES), permute(x, &IP, 64));
            assert_eq!(permute_fast(x, &FP_NIBBLES), permute(x, &FP, 64));
        }
    }

    /// The whole fast block against the block as the standard writes it,
    /// both directions, and Triple DES's cancelled inner FP/IP against
    /// three reference blocks.
    #[test]
    fn test_the_fast_block_is_the_reference_block() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            x = x.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(0x1405_7b7e_f767_814f);
            x
        };
        for _ in 0..200 {
            let (k1, k2, k3, m) = (next(), next(), next(), next());
            let subkeys = [schedule(k1), schedule(k2), schedule(k3)];
            let keys = subkeys.map(|s| s.map(subkey_groups));
            for forward in [true, false] {
                assert_eq!(block(m, &keys[0], forward), reference_block(m, &subkeys[0], forward));
            }
            let ede = reference_block(reference_block(reference_block(m, &subkeys[0], true),
                                                      &subkeys[1], false), &subkeys[2], true);
            assert_eq!(triple(m, [(&keys[0], true), (&keys[1], false), (&keys[2], true)]), ede);
        }
    }

    /// The key schedule's rotations sum to 28, so after sixteen rounds the
    /// halves are back where they started. That is what makes running the
    /// subkeys backwards a valid decryption.
    #[test]
    fn test_the_schedule_returns_to_its_start() {
        assert_eq!(SHIFTS.iter().sum::<u32>(), 28);

        let mut c = 0x0a5a_5a5au32 & 0x0fff_ffff;
        let start = c;
        for shift in SHIFTS {
            c = rotate28(c, shift);
        }
        assert_eq!(c, start);
    }

    /// One bit changed in the plaintext must change about half the output
    /// bits, and the same for the key. Not a proof of anything, but a
    /// round function that is subtly broken usually fails it badly.
    #[test]
    fn test_the_avalanche_is_not_obviously_broken() {
        let key = unhex("133457799bbcdff1");
        let plaintext = unhex("0123456789abcdef");

        let mut cipher = Des::new(&key).unwrap();
        let mut base = Vec::new();
        cipher.block_encrypt(&plaintext, &mut base);

        for bit in 0..64 {
            let mut altered = plaintext.clone();
            altered[bit / 8] ^= 1 << (7 - bit % 8);
            let mut cipher = Des::new(&key).unwrap();
            let mut out = Vec::new();
            cipher.block_encrypt(&altered, &mut out);

            let changed: u32 = base.iter().zip(out.iter())
                .map(|(a, b)| (a ^ b).count_ones()).sum();
            assert!((16..=48).contains(&changed),
                    "flipping plaintext bit {} changed {} of 64 output bits",
                    bit, changed);
        }
    }
}
