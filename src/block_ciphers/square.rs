/*!
Square, Daemen, Knudsen and Rijmen's 1997 cipher and Rijndael's direct
predecessor: a 128-bit block and key, eight rounds, a 4x4 byte state.

## A round

`ρ[k] = σ[k] ∘ π ∘ γ ∘ θ`: `θ` multiplies each row, as a polynomial with
byte coefficients, by `c(x) = 2 + x + x² + 3x³` modulo `x⁴ + 1` over
GF(2⁸) modulo `x⁸ + x⁷ + x⁶ + x⁵ + x⁴ + x² + 1` (0x1f5, not AES's
0x11b); `γ` is the S-box on every byte; `π` transposes the state; `σ[k]`
adds the round key. The cipher is `ρ[k⁸] ∘ … ∘ ρ[k¹] ∘ σ[k⁰] ∘ θ⁻¹`,
so the plaintext goes through `θ⁻¹` first. Moving each `θ` past the key
addition before it turns that into what is computed here: the plaintext
plus `θ(k⁰)`, then seven rounds of `γ`, `π`, `θ` and `θ(kᵗ)`, then a last
`γ`, `π` and `k⁸` - the same arrangement every table implementation
uses, with the round keys passed through `θ` except the last.

## The key schedule

`k⁰` is the key as four big-endian words; then `kᵗ₀ = kᵗ⁻¹₀ ⊕
rotl₈(kᵗ⁻¹₃) ⊕ Cₜ` with `Cₜ = 2ᵗ⁻¹` in the top byte, and each later word
is the previous round's word XOR the one just made.

## The S-box

`square_table.rs`, written by `scripts/make_oldcipher_tables.py` from
Crypto++ 8.9.0 and Botan 1.10.17, which agree on it; the inverse is
computed here, and `θ⁻¹` from `θ`'s matrix by elimination over the field.

## Not constant time

`γ` is a table indexed by state bytes.

## Where the vectors come from

`vectors/square.vec`, written by `scripts/make_square_vectors.py`: blocks
on which Crypto++ and Botan agree, with the published tests both carry.
*/

use super::square_table::S;
use super::BlockCipher;

const BLOCK: usize = 16;
const ROUNDS: usize = 8;

type State = [[u8; 4]; 4];

/// Multiplication in GF(2⁸) modulo 0x1f5.
const fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0xf5;
        }
        b >>= 1;
    }
    product
}

const fn inverse(a: u8) -> u8 {
    // a^254, since the multiplicative group has order 255.
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u32;
    while e != 0 {
        if e & 1 != 0 {
            result = mul(result, base);
        }
        base = mul(base, base);
        e >>= 1;
    }
    result
}

/// `θ`'s matrix: output byte `j` of a row is the XOR over `k` of input
/// byte `k` times `G[k][j]`, with `G[k][j] = c[(j - k) mod 4]`.
const C: [u8; 4] = [2, 1, 1, 3];
const G: [[u8; 4]; 4] = {
    let mut g = [[0u8; 4]; 4];
    let mut k = 0;
    while k < 4 {
        let mut j = 0;
        while j < 4 {
            g[k][j] = C[(j + 4 - k) % 4];
            j += 1;
        }
        k += 1;
    }
    g
};

/// `G`'s inverse, by Gauss-Jordan elimination over the field.
const G_INVERSE: [[u8; 4]; 4] = {
    let mut m = G;
    let mut inv = [[1u8, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]];
    let mut col = 0;
    while col < 4 {
        let mut pivot = col;
        while m[pivot][col] == 0 {
            pivot += 1;
        }
        let (row, irow) = (m[pivot], inv[pivot]);
        m[pivot] = m[col];
        inv[pivot] = inv[col];
        m[col] = row;
        inv[col] = irow;
        let scale = inverse(m[col][col]);
        let mut j = 0;
        while j < 4 {
            m[col][j] = mul(m[col][j], scale);
            inv[col][j] = mul(inv[col][j], scale);
            j += 1;
        }
        let mut r = 0;
        while r < 4 {
            if r != col && m[r][col] != 0 {
                let factor = m[r][col];
                let mut j = 0;
                while j < 4 {
                    m[r][j] ^= mul(factor, m[col][j]);
                    inv[r][j] ^= mul(factor, inv[col][j]);
                    j += 1;
                }
            }
            r += 1;
        }
        col += 1;
    }
    inv
};

const S_INVERSE: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        inv[S[x] as usize] = x as u8;
        x += 1;
    }
    inv
};

fn linear(row: [u8; 4], matrix: &[[u8; 4]; 4]) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (k, &a) in row.iter().enumerate() {
        for (j, o) in out.iter_mut().enumerate() {
            *o ^= mul(a, matrix[k][j]);
        }
    }
    out
}

fn theta(state: &State) -> State {
    state.map(|row| linear(row, &G))
}

fn theta_inverse(state: &State) -> State {
    state.map(|row| linear(row, &G_INVERSE))
}

/// `π ∘ γ`: the S-box on every byte, then the transposition.
fn gamma_pi(state: &State, sbox: &[u8; 256]) -> State {
    std::array::from_fn(|i| std::array::from_fn(|j| sbox[usize::from(state[j][i])]))
}

fn add(state: &mut State, key: &State) {
    for (row, k) in state.iter_mut().zip(key) {
        for (b, k) in row.iter_mut().zip(k) {
            *b ^= k;
        }
    }
}

#[derive(Clone)]
pub struct Square {
    /// `k⁰` to `k⁸`, as the key schedule produces them.
    keys: [State; ROUNDS + 1],
    /// `θ(kᵗ)` for `t` from 0 to 7: what the rounds add.
    theta_keys: [State; ROUNDS],
}

impl Square {
    pub fn new(key: &[u8]) -> Result<Square, String> {
        let key: [u8; 16] = key.try_into().map_err(|_| format!(
            "Wrong key length {}. Square takes a 16 byte key.", key.len()))?;
        let mut words = [[0u32; 4]; ROUNDS + 1];
        for (i, w) in words[0].iter_mut().enumerate() {
            *w = u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().expect("4 bytes"));
        }
        for t in 1..=ROUNDS {
            let p = words[t - 1];
            let w0 = p[0] ^ p[3].rotate_left(8) ^ (0x0100_0000 << (t - 1));
            let w1 = p[1] ^ w0;
            let w2 = p[2] ^ w1;
            let w3 = p[3] ^ w2;
            words[t] = [w0, w1, w2, w3];
        }
        let keys = words.map(|w| w.map(u32::to_be_bytes));
        let theta_keys = std::array::from_fn(|t| theta(&keys[t]));
        Ok(Square { keys, theta_keys })
    }
}

fn load(input: &[u8]) -> State {
    std::array::from_fn(|i| input[4 * i..4 * i + 4].try_into().expect("4 bytes"))
}

impl BlockCipher for Square {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut state = load(&input[..BLOCK]);
        add(&mut state, &self.theta_keys[0]);
        for t in 1..ROUNDS {
            state = theta(&gamma_pi(&state, &S));
            add(&mut state, &self.theta_keys[t]);
        }
        state = gamma_pi(&state, &S);
        add(&mut state, &self.keys[ROUNDS]);
        result.extend(state.iter().flatten());
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut state = load(&input[..BLOCK]);
        add(&mut state, &self.keys[ROUNDS]);
        // π is its own inverse, and γ and π commute.
        state = gamma_pi(&state, &S_INVERSE);
        for t in (1..ROUNDS).rev() {
            add(&mut state, &self.theta_keys[t]);
            state = gamma_pi(&theta_inverse(&state), &S_INVERSE);
        }
        add(&mut state, &self.theta_keys[0]);
        result.extend(state.iter().flatten());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `G_INVERSE` inverts `G`, and `θ⁻¹` undoes `θ` on every row of
    /// one byte.
    #[test]
    fn test_theta_inverse() {
        for (i, row) in G.iter().enumerate() {
            for j in 0..4 {
                let sum = row.iter().zip(&G_INVERSE).fold(0, |acc, (&g, inv)| acc ^ mul(g, inv[j]));
                assert_eq!(sum, u8::from(i == j));
            }
        }
        for x in 0..=255u8 {
            let state = [[x, 0, 0, 0], [0, x, 0, 0], [0, 0, x, 0], [x, x, x, x]];
            assert_eq!(theta_inverse(&theta(&state)), state);
        }
    }

    /// The S-box is a permutation, and the computed inverse inverts it.
    #[test]
    fn test_the_sbox_is_a_permutation() {
        for x in 0..256 {
            assert_eq!(usize::from(S_INVERSE[usize::from(S[x])]), x);
        }
    }

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 8, 15, 17, 24, 32] {
            assert!(Square::new(&vec![0u8; len]).is_err(), "{len}");
        }
    }

    /// Decryption inverts encryption.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x5917_1997u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..32 {
            let key: Vec<u8> = (0..16).map(|_| next()).collect();
            let block: Vec<u8> = (0..16).map(|_| next()).collect();
            let mut c = Square::new(&key).unwrap();
            let (mut out, mut back) = (Vec::new(), Vec::new());
            c.block_encrypt(&block, &mut out);
            c.block_decrypt(&out, &mut back);
            assert_eq!(back, block);
            assert_ne!(out, block);
        }
    }
}
