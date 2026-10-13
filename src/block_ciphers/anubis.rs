/*!
Anubis, Barreto and Rijmen's NESSIE submission: a 128-bit block, a key
of 4 to 10 words (16 to 40 bytes, a multiple of 4) and `8 + N` rounds
for a key of `N` words. This is the tweaked Anubis, whose S-box is
Khazad's; the first submission had a different one.

## The round

The state is a 4×4 matrix of bytes over GF(2^8) modulo 0x11d, row `i`
being the block's bytes `4i .. 4i + 3`. A round `ρ[k]` is

- `γ`, the S-box on every byte;
- `τ`, the transpose;
- `θ`, every row times `H = had(01, 02, 04, 06)`, an involution;
- `σ[k]`, the round key XORed in.

Encryption is `σ[K⁰]`, then `ρ[Kʳ]` for `r = 1 .. R − 1`, then `γ`, `τ`
and `σ[Kᴿ]` - the last round has no `θ`. Decryption is the same with
the keys `Kᴿ, θ(Kᴿ⁻¹), …, θ(K¹), K⁰`.

## The key schedule

The key is an `N`×4 matrix `κ⁰`, word `i` being row `i`. Each step
evolves it: `γ`; then `π`, which moves column `j` down by `j` rows,
cyclically over the `N` rows; then `θ` on every row; then the round
constant XORed into row 0 - the S-box's entries `4r .. 4r + 3`. Each
round key is extracted from the evolving state, before the step that
follows it: `Kʳ` is `γ(κʳ)` transposed and multiplied by the `N`×4
Vandermonde matrix whose column `k` is the powers of `01, 02, 06, 08`,
in that order.

## Constant time

As Khazad, whose S-box this is: the S-box from its two 4-bit boxes by
masked scans, and every multiplication by a constant through doubling
with a mask. `scripts/ct_check.py` has the case `anubis_blocks`.

## Where the vectors come from

`vectors/anubis.vec`, written by `scripts/make_anubis_vectors.py`:
blocks at every key length on which three implementations agree -
libtomcrypt 1.18.2 built with `LTC_ANUBIS_TWEAK`, the Linux kernel's
`crypto/anubis.c`, and the designers' reference as Crypt::Anubis
ships it - and the published tests libtomcrypt, the kernel and
Crypt::Anubis carry.
*/

use super::khazad::{double, sbox, SBOX};
use super::BlockCipher;

const BLOCK: usize = 16;
const MIN_N: usize = 4;
const MAX_N: usize = 10;
const MAX_ROUNDS: usize = 8 + MAX_N;

type State = [[u8; 4]; 4];

/// `x` times a public constant: the constant's bits pick which
/// doublings are added, so nothing branches on `x`.
#[inline(always)]
fn times(x: u8, c: u8) -> u8 {
    let (mut out, mut power) = (0u8, x);
    for bit in 0..8 {
        if c >> bit & 1 == 1 {
            out ^= power;
        }
        power = double(power);
    }
    out
}

/// `H = had(01, 02, 04, 06)`: entry `(i, j)` is the `(i ⊕ j)`-th.
const U: [u8; 4] = [0x01, 0x02, 0x04, 0x06];

/// A row times `H`.
fn row_theta(row: [u8; 4]) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (j, o) in out.iter_mut().enumerate() {
        for (i, &v) in row.iter().enumerate() {
            *o ^= times(v, U[i ^ j]);
        }
    }
    out
}

fn theta(a: State) -> State {
    a.map(row_theta)
}

fn gamma_tau(a: State) -> State {
    let mut out = [[0u8; 4]; 4];
    for (i, row) in out.iter_mut().enumerate() {
        for (j, o) in row.iter_mut().enumerate() {
            *o = sbox(a[j][i]);
        }
    }
    out
}

fn xor(a: State, k: &State) -> State {
    let mut out = a;
    for (row, krow) in out.iter_mut().zip(k) {
        for (o, k) in row.iter_mut().zip(krow) {
            *o ^= k;
        }
    }
    out
}

/// The Vandermonde matrix's columns: the powers of these.
const V: [u8; 4] = [0x01, 0x02, 0x06, 0x08];

#[derive(Clone)]
pub struct Anubis {
    rounds: usize,
    enc: [State; MAX_ROUNDS + 1],
    dec: [State; MAX_ROUNDS + 1],
}

impl Anubis {
    pub fn new(key: &[u8]) -> Result<Anubis, String> {
        if key.len() < 4 * MIN_N || key.len() > 4 * MAX_N || !key.len().is_multiple_of(4) {
            return Err(format!("Wrong key length {}. Anubis takes 16 to 40 bytes, a \
                                multiple of 4.", key.len()));
        }
        let n = key.len() / 4;
        let rounds = 8 + n;
        let mut kappa = [[0u8; 4]; MAX_N];
        for (row, word) in kappa.iter_mut().zip(key.chunks_exact(4)) {
            row.copy_from_slice(word);
        }
        let mut enc = [[[0u8; 4]; 4]; MAX_ROUNDS + 1];
        for (r, k) in enc.iter_mut().enumerate().take(rounds + 1) {
            // Extraction: K[j][c] = sum over i of S(kappa[i][j]) * V[c]^i,
            // by Horner's rule from the last row.
            for (j, krow) in k.iter_mut().enumerate() {
                for (c, out) in krow.iter_mut().enumerate() {
                    let mut acc = 0u8;
                    for i in (0..n).rev() {
                        acc = times(acc, V[c]) ^ sbox(kappa[i][j]);
                    }
                    *out = acc;
                }
            }
            if r == rounds {
                break;
            }
            // Evolution: gamma, pi (column j down j rows), theta, and the
            // round constant into row 0.
            let mut next = [[0u8; 4]; MAX_N];
            for (i, row) in next.iter_mut().enumerate().take(n) {
                let mut moved = [0u8; 4];
                for (j, m) in moved.iter_mut().enumerate() {
                    *m = sbox(kappa[(i + n - j % n) % n][j]);
                }
                *row = row_theta(moved);
            }
            for (j, b) in next[0].iter_mut().enumerate() {
                *b ^= SBOX[4 * r + j];
            }
            kappa = next;
        }
        let mut dec = [[[0u8; 4]; 4]; MAX_ROUNDS + 1];
        dec[0] = enc[rounds];
        for r in 1..rounds {
            dec[r] = theta(enc[rounds - r]);
        }
        dec[rounds] = enc[0];
        Ok(Anubis { rounds, enc, dec })
    }

    /// The number of rounds, `8 + N` for a key of `N` words.
    pub fn rounds(&self) -> usize {
        self.rounds
    }

    fn crypt(keys: &[State], rounds: usize, input: &[u8], result: &mut Vec<u8>) {
        let mut state = [[0u8; 4]; 4];
        for (row, word) in state.iter_mut().zip(input[..BLOCK].chunks_exact(4)) {
            row.copy_from_slice(word);
        }
        state = xor(state, &keys[0]);
        for k in &keys[1..rounds] {
            state = xor(theta(gamma_tau(state)), k);
        }
        state = xor(gamma_tau(state), &keys[rounds]);
        for row in &state {
            result.extend_from_slice(row);
        }
    }
}

impl BlockCipher for Anubis {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        Anubis::crypt(&self.enc, self.rounds, input, result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        Anubis::crypt(&self.dec, self.rounds, input, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `H` is an involution and MDS: one non-zero byte in a row gives
    /// four.
    #[test]
    fn test_theta_is_an_involution_and_spreads() {
        for v in 1..=255u8 {
            for position in 0..4 {
                let mut row = [0u8; 4];
                row[position] = v;
                assert_eq!(row_theta(row_theta(row)), row);
                assert!(row_theta(row).iter().all(|&b| b != 0));
            }
        }
    }

    #[test]
    fn test_times_is_field_multiplication() {
        for x in 0..=255u8 {
            assert_eq!(times(x, 1), x);
            assert_eq!(times(x, 2), double(x));
            assert_eq!(times(x, 6), double(double(x)) ^ double(x));
            assert_eq!(times(times(x, 3), 5), times(x, times(3, 5)));
        }
    }

    #[test]
    fn test_the_key_lengths_and_rounds() {
        for len in (16..=40).step_by(4) {
            assert_eq!(Anubis::new(&vec![0u8; len]).unwrap().rounds(), 8 + len / 4);
        }
        for len in [0, 12, 15, 17, 39, 44] {
            assert!(Anubis::new(&vec![0u8; len]).is_err(), "{len}");
        }
    }
}
