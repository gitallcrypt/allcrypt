/*!
Khazad, Barreto and Rijmen's NESSIE finalist: a 64-bit block, a 128-bit
key and eight rounds. This is the tweaked Khazad, the version NESSIE
evaluated and every implementation still in circulation carries; the
first submission had a different S-box.

## The round

The state is eight bytes, a row vector over GF(2^8) modulo
`x^8 + x^4 + x^3 + x^2 + 1` (0x11d, Whirlpool's field and not AES's). A
round `ρ[k]` is three steps:

- `γ`, the S-box on every byte;
- `θ`, the vector times `H = had(01, 03, 04, 05, 06, 08, 0b, 07)`, the
  matrix whose entry `(i, j)` is the `(i ⊕ j)`-th of those eight: an
  involution, so `θ` is its own inverse;
- `σ[k]`, the round key XORed in.

Encryption is `σ[K⁰]`, then `ρ[Kʳ]` for `r = 1 .. 7`, then `γ` and
`σ[K⁸]` - the last round has no `θ`.

## The key schedule

The key's two halves are `K⁻²` and `K⁻¹`, and
`Kʳ = ρ[cʳ](Kʳ⁻¹) ⊕ Kʳ⁻²` for `r = 0 .. 8`, where `cʳ` is the S-box's
entries `8r .. 8r + 7`. Because `γ` and `θ` are involutions, decryption
is the same procedure with the keys reversed and the middle seven
passed through `θ`: `K⁸, θ(K⁷), …, θ(K¹), K⁰`.

## The S-box is built, not typed

The tweaked S-box is an involution built from two 4-bit boxes, `P` and
`Q`: `P` on the high nibble and `Q` on the low, the two middle bits of
the result exchanged with each other's pair, `Q` and `P`, the exchange
again, and `P` and `Q`. Those 32 nibbles are the only constants here.
The vectors hold the construction to the table libtomcrypt and the
Linux kernel carry: their rows of one byte repeated put every entry
through `γ`.

## Constant time

The S-box is computed from `P` and `Q` with each nibble looked up by a
masked scan of all sixteen entries, and `θ` multiplies by doubling with
a mask, so nothing indexes memory or branches on the key or the data.
`scripts/ct_check.py` has the case `khazad_blocks`.

## Where the vectors come from

`vectors/khazad.vec`, written by `scripts/make_khazad_vectors.py`:
blocks on which libtomcrypt 1.18.2 and the Linux kernel's
`crypto/khazad.c` agree, both derived from the designers' public-domain
code, and the published tests the two carry - libtomcrypt's self-test
and the kernel's `testmgr.h` - parsed out of their sources.
*/

use super::BlockCipher;

const BLOCK: usize = 8;
const ROUNDS: usize = 8;

/// The mini boxes. **These 32 nibbles are the only constants typed in
/// this file.**
const P: [u8; 16] = [0x3, 0xf, 0xe, 0x0, 0x5, 0x4, 0xb, 0xc,
                     0xd, 0xa, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1];
const Q: [u8; 16] = [0x9, 0xe, 0x5, 0x6, 0xa, 0x2, 0x3, 0xc,
                     0xf, 0x0, 0x4, 0xd, 0x7, 0xb, 0x1, 0x8];

/// `table[x]` for a nibble `x`, reading every entry and keeping the one
/// whose index matches: no load depends on `x`.
#[inline(always)]
fn nibble(table: &[u8; 16], x: u8) -> u8 {
    let mut out = 0u8;
    for (i, &v) in table.iter().enumerate() {
        // 0xff when i == x, else 0: (i ^ x) - 1 borrows only from zero.
        let mask = (((i as u32) ^ u32::from(x)).wrapping_sub(1) >> 8) as u8;
        out |= v & mask;
    }
    out
}

/// The two middle bits of each nibble go to the other: `(a, b)` becomes
/// the high pairs of both, and the low pairs of both.
#[inline(always)]
fn exchange(a: u8, b: u8) -> (u8, u8) {
    ((a & 0xc) | (b >> 2), ((a & 0x3) << 2) | (b & 0x3))
}

/// The S-box, by its construction, in constant time.
#[inline(always)]
pub(crate) fn sbox(x: u8) -> u8 {
    let (u, l) = (nibble(&P, x >> 4), nibble(&Q, x & 0xf));
    let (u, l) = exchange(u, l);
    let (u, l) = (nibble(&Q, u), nibble(&P, l));
    let (u, l) = exchange(u, l);
    (nibble(&P, u) << 4) | nibble(&Q, l)
}

/// The S-box as a table, for the round constants, which are public.
const fn sbox_table() -> [u8; 256] {
    const fn look(table: &[u8; 16], x: u8) -> u8 {
        table[x as usize]
    }
    let mut out = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        let (u, l) = (look(&P, (x >> 4) as u8), look(&Q, (x & 0xf) as u8));
        let (u, l) = ((u & 0xc) | (l >> 2), ((u & 0x3) << 2) | (l & 0x3));
        let (u, l) = (look(&Q, u), look(&P, l));
        let (u, l) = ((u & 0xc) | (l >> 2), ((u & 0x3) << 2) | (l & 0x3));
        out[x] = (look(&P, u) << 4) | look(&Q, l);
        x += 1;
    }
    out
}

pub(crate) const SBOX: [u8; 256] = sbox_table();

/// Doubling modulo 0x11d, with the reduction masked in.
#[inline(always)]
pub(crate) fn double(a: u8) -> u8 {
    (a << 1) ^ (0x1d & 0u8.wrapping_sub(a >> 7))
}

/// `θ`: the state times `H`. Entry `(i, j)` of `H` is `U[i ^ j]`.
fn theta(a: [u8; BLOCK]) -> [u8; BLOCK] {
    // The multiples each entry of U needs: 1, 2, 4 and 8 of every byte.
    let mut by2 = [0u8; BLOCK];
    let mut by4 = [0u8; BLOCK];
    let mut by8 = [0u8; BLOCK];
    for i in 0..BLOCK {
        by2[i] = double(a[i]);
        by4[i] = double(by2[i]);
        by8[i] = double(by4[i]);
    }
    // U = 01, 03, 04, 05, 06, 08, 0b, 07.
    let times = |i: usize, u: usize| -> u8 {
        match u {
            0 => a[i],
            1 => by2[i] ^ a[i],
            2 => by4[i],
            3 => by4[i] ^ a[i],
            4 => by4[i] ^ by2[i],
            5 => by8[i],
            6 => by8[i] ^ by2[i] ^ a[i],
            _ => by4[i] ^ by2[i] ^ a[i],
        }
    };
    let mut out = [0u8; BLOCK];
    for (j, o) in out.iter_mut().enumerate() {
        for i in 0..BLOCK {
            // `u` is i ^ j, a loop position and not data.
            *o ^= times(i, i ^ j);
        }
    }
    out
}

fn gamma(a: [u8; BLOCK]) -> [u8; BLOCK] {
    a.map(sbox)
}

fn xor(a: [u8; BLOCK], k: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = a;
    for (o, k) in out.iter_mut().zip(k) {
        *o ^= k;
    }
    out
}

/// One round, `ρ[k]`.
fn rho(a: [u8; BLOCK], k: &[u8; BLOCK]) -> [u8; BLOCK] {
    xor(theta(gamma(a)), k)
}

#[derive(Clone)]
pub struct Khazad {
    enc: [[u8; BLOCK]; ROUNDS + 1],
    dec: [[u8; BLOCK]; ROUNDS + 1],
}

impl Khazad {
    pub fn new(key: &[u8]) -> Result<Khazad, String> {
        if key.len() != 16 {
            return Err(format!("Wrong key length {}. Khazad takes 16 bytes.", key.len()));
        }
        let mut older: [u8; BLOCK] = key[..8].try_into().expect("8 bytes");
        let mut old: [u8; BLOCK] = key[8..].try_into().expect("8 bytes");
        let mut enc = [[0u8; BLOCK]; ROUNDS + 1];
        for (r, k) in enc.iter_mut().enumerate() {
            let c: [u8; BLOCK] = SBOX[8 * r..8 * r + 8].try_into().expect("8 bytes");
            *k = xor(rho(old, &c), &older);
            older = old;
            old = *k;
        }
        let mut dec = [[0u8; BLOCK]; ROUNDS + 1];
        dec[0] = enc[ROUNDS];
        for r in 1..ROUNDS {
            dec[r] = theta(enc[ROUNDS - r]);
        }
        dec[ROUNDS] = enc[0];
        Ok(Khazad { enc, dec })
    }

    fn crypt(keys: &[[u8; BLOCK]; ROUNDS + 1], input: &[u8], result: &mut Vec<u8>) {
        let block: [u8; BLOCK] = input[..BLOCK].try_into().expect("a whole block");
        let mut state = xor(block, &keys[0]);
        for k in &keys[1..ROUNDS] {
            state = rho(state, k);
        }
        state = xor(gamma(state), &keys[ROUNDS]);
        result.extend_from_slice(&state);
    }
}

impl BlockCipher for Khazad {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        Khazad::crypt(&self.enc, input, result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        Khazad::crypt(&self.dec, input, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_mini_boxes_are_permutations() {
        for table in [P, Q] {
            let mut seen = [false; 16];
            for v in table {
                seen[v as usize] = true;
            }
            assert!(seen.iter().all(|&s| s));
        }
    }

    /// The S-box is an involution, as both `γ`'s use in decryption and
    /// the design require, and the masked path is the table.
    #[test]
    fn test_the_s_box_is_an_involution() {
        for x in 0..=255u8 {
            assert_eq!(SBOX[SBOX[x as usize] as usize], x);
            assert_eq!(sbox(x), SBOX[x as usize]);
        }
    }

    /// `θ` is its own inverse, and `H` is MDS: a state with `n` non-zero
    /// bytes maps to one with at least `9 - n`.
    #[test]
    fn test_theta_is_an_involution_and_spreads() {
        let mut seed = 0x1234_5678u32;
        let mut next = || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (seed >> 16) as u8
        };
        for _ in 0..200 {
            let a: [u8; BLOCK] = std::array::from_fn(|_| next());
            assert_eq!(theta(theta(a)), a);
        }
        for position in 0..BLOCK {
            for v in 1..=255u8 {
                let mut a = [0u8; BLOCK];
                a[position] = v;
                assert!(theta(a).iter().all(|&b| b != 0));
            }
        }
    }

    #[test]
    fn test_the_key_length_is_checked() {
        assert!(Khazad::new(&[0; 15]).is_err());
        assert!(Khazad::new(&[0; 17]).is_err());
        assert!(Khazad::new(&[0; 16]).is_ok());
    }
}
