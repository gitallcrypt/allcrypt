/*!
SAFER, Massey's byte-oriented ciphers: SAFER K-64 and K-128 (Cylink's,
1993 and 1994) and the strengthened SAFER SK-64 and SK-128 (1995), which
change only the key schedule. A 64-bit block; an 8-byte key for the -64
variants, a 16-byte key for the -128 ones; and a round count, 1 to 13,
whose usual values are 6 for K-64, 8 for SK-64 and 10 for the -128
variants - the defaults here, as libtomcrypt and Crypto++ have them.

## A round

Each round mixes the eight bytes with the first of its two subkeys -
XOR on bytes 0, 3, 4 and 7, addition mod 256 on the rest - passes them
through `exp` (`45^x mod 257`, with 256 written as 0) or its inverse
`log`, mixes in the second subkey the other way round, and then runs a
three-layer Pseudo-Hadamard transform, `(2a + b, a + b)`, with the
bytes reordered between layers. After the last round a final subkey is
mixed in as at the start of a round. `exp` and `log` are computed here
from that definition.

## The key schedule

`1 + 2r` subkeys of eight bytes. The first is the second half of the
key (for the -64 variants, the key itself). The rest come from two
9-byte registers - each half of the key with its XOR appended, the first
half rotated left by 5 - rotated left by 6 for each round, with a bias
`exp(exp(18i + j + c))` added to each byte. K takes the register bytes
in order; SK starts the `n`-th subkey at register byte `n - 1 mod 9` and
wraps, which is the strengthening. For the -64 variants both halves are
the key, so K-64 is K-128 with the key repeated, and SK-64 SK-128, each
at its own round count.

## Not constant time

`exp` and `log` are tables indexed by data mixed with key bytes, as in
every implementation.

## Where the vectors come from

`vectors/safer.vec`, written by `scripts/make_safer_vectors.py`: blocks
on which libtomcrypt 1.18.2 and Crypto++ 8.9.0 agree, and Botan 1.10.17
for SK-128, at every round count they share, with the published tests
the three carry.
*/

use super::BlockCipher;

const BLOCK: usize = 8;
pub const MAX_ROUNDS: usize = 13;

/// `exp[x] = 45^x mod 257`, with 256 as 0, and `log` its inverse.
const fn tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut value: u32 = 1;
    let mut x = 0;
    while x < 256 {
        let byte = (value & 0xff) as u8; // 256 is written as 0
        exp[x] = byte;
        log[byte as usize] = x as u8;
        value = value * 45 % 257;
        x += 1;
    }
    (exp, log)
}
const EXP: [u8; 256] = tables().0;
const LOG: [u8; 256] = tables().1;

/// The four variants: the key length and whether the key schedule is
/// the strengthened one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SaferVariant {
    K64,
    K128,
    Sk64,
    Sk128,
}

impl SaferVariant {
    pub fn key_len(self) -> usize {
        match self {
            SaferVariant::K64 | SaferVariant::Sk64 => 8,
            SaferVariant::K128 | SaferVariant::Sk128 => 16,
        }
    }

    fn strengthened(self) -> bool {
        matches!(self, SaferVariant::Sk64 | SaferVariant::Sk128)
    }

    /// The usual round count: 6 for K-64, 8 for SK-64, 10 for the -128
    /// variants.
    pub fn default_rounds(self) -> usize {
        match self {
            SaferVariant::K64 => 6,
            SaferVariant::Sk64 => 8,
            SaferVariant::K128 | SaferVariant::Sk128 => 10,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            SaferVariant::K64 => "SAFER K-64",
            SaferVariant::K128 => "SAFER K-128",
            SaferVariant::Sk64 => "SAFER SK-64",
            SaferVariant::Sk128 => "SAFER SK-128",
        }
    }
}

#[derive(Clone)]
pub struct Safer {
    variant: SaferVariant,
    /// `1 + 2 * rounds` subkeys.
    keys: Vec<[u8; BLOCK]>,
}

impl Safer {
    /// `variant` at its usual round count.
    pub fn new(variant: SaferVariant, key: &[u8]) -> Result<Safer, String> {
        Safer::with_rounds(variant, key, variant.default_rounds())
    }

    /// `variant` at `rounds` rounds, 1 to 13.
    pub fn with_rounds(variant: SaferVariant, key: &[u8], rounds: usize)
                       -> Result<Safer, String> {
        if key.len() != variant.key_len() {
            return Err(format!("Wrong key length {}. {} takes a {} byte key.", key.len(),
                               variant.name(), variant.key_len()));
        }
        if !(1..=MAX_ROUNDS).contains(&rounds) {
            return Err(format!("{} takes 1 to {MAX_ROUNDS} rounds, not {rounds}.",
                               variant.name()));
        }
        let (first, second) = key.split_at(key.len() - BLOCK);
        let first = if first.is_empty() { second } else { first };
        // The two registers: each half and its XOR, the first half
        // rotated left by 5 first.
        let mut ka = [0u8; BLOCK + 1];
        let mut kb = [0u8; BLOCK + 1];
        for j in 0..BLOCK {
            ka[j] = first[j].rotate_left(5);
            ka[BLOCK] ^= ka[j];
            kb[j] = second[j];
            kb[BLOCK] ^= kb[j];
        }
        let mut keys = vec![kb[..BLOCK].try_into().expect("8 bytes")];
        for i in 1..=rounds {
            for byte in ka.iter_mut().chain(kb.iter_mut()) {
                *byte = byte.rotate_left(6);
            }
            for (register, start, offset) in [(&ka, 2 * i - 1, 1), (&kb, 2 * i, 10)] {
                let mut subkey = [0u8; BLOCK];
                for (j, byte) in subkey.iter_mut().enumerate() {
                    let at = if variant.strengthened() { (start + j) % (BLOCK + 1) } else { j };
                    let bias = EXP[usize::from(EXP[(18 * i + j + offset) & 0xff])];
                    *byte = register[at].wrapping_add(bias);
                }
                keys.push(subkey);
            }
        }
        Ok(Safer { variant, keys })
    }

    pub fn variant(&self) -> SaferVariant {
        self.variant
    }

    pub fn rounds(&self) -> usize {
        (self.keys.len() - 1) / 2
    }
}

/// XOR on bytes 0, 3, 4 and 7 and addition on the others: how the first
/// subkey of a round, and the last one, are mixed in.
fn mix(block: &mut [u8; BLOCK], key: &[u8; BLOCK]) {
    for (i, (b, k)) in block.iter_mut().zip(key).enumerate() {
        *b = if matches!(i, 0 | 3 | 4 | 7) { *b ^ k } else { b.wrapping_add(*k) };
    }
}

fn unmix(block: &mut [u8; BLOCK], key: &[u8; BLOCK]) {
    for (i, (b, k)) in block.iter_mut().zip(key).enumerate() {
        *b = if matches!(i, 0 | 3 | 4 | 7) { *b ^ k } else { b.wrapping_sub(*k) };
    }
}

/// `(x, y)` to `(2x + y, x + y)`.
fn pht(x: &mut u8, y: &mut u8) {
    *y = y.wrapping_add(*x);
    *x = x.wrapping_add(*y);
}

fn ipht(x: &mut u8, y: &mut u8) {
    *x = x.wrapping_sub(*y);
    *y = y.wrapping_sub(*x);
}

impl BlockCipher for Safer {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut s: [u8; BLOCK] = input[..BLOCK].try_into().expect("one block");
        for pair in self.keys[..self.keys.len() - 1].chunks_exact(2) {
            mix(&mut s, &pair[0]);
            for (i, (b, k)) in s.iter_mut().zip(&pair[1]).enumerate() {
                *b = if matches!(i, 0 | 3 | 4 | 7) {
                    EXP[usize::from(*b)].wrapping_add(*k)
                } else {
                    LOG[usize::from(*b)] ^ k
                };
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = s;
            pht(&mut a, &mut b);
            pht(&mut c, &mut d);
            pht(&mut e, &mut f);
            pht(&mut g, &mut h);
            pht(&mut a, &mut c);
            pht(&mut e, &mut g);
            pht(&mut b, &mut d);
            pht(&mut f, &mut h);
            pht(&mut a, &mut e);
            pht(&mut b, &mut f);
            pht(&mut c, &mut g);
            pht(&mut d, &mut h);
            s = [a, e, b, f, c, g, d, h];
        }
        mix(&mut s, self.keys.last().expect("1 + 2r subkeys"));
        result.extend_from_slice(&s);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut s: [u8; BLOCK] = input[..BLOCK].try_into().expect("one block");
        unmix(&mut s, self.keys.last().expect("1 + 2r subkeys"));
        for pair in self.keys[..self.keys.len() - 1].chunks_exact(2).rev() {
            let [mut a, mut e, mut b, mut f, mut c, mut g, mut d, mut h] = s;
            ipht(&mut a, &mut e);
            ipht(&mut b, &mut f);
            ipht(&mut c, &mut g);
            ipht(&mut d, &mut h);
            ipht(&mut a, &mut c);
            ipht(&mut e, &mut g);
            ipht(&mut b, &mut d);
            ipht(&mut f, &mut h);
            ipht(&mut a, &mut b);
            ipht(&mut c, &mut d);
            ipht(&mut e, &mut f);
            ipht(&mut g, &mut h);
            s = [a, b, c, d, e, f, g, h];
            for (i, (b, k)) in s.iter_mut().zip(&pair[1]).enumerate() {
                *b = if matches!(i, 0 | 3 | 4 | 7) {
                    LOG[usize::from(b.wrapping_sub(*k))]
                } else {
                    EXP[usize::from(*b ^ k)]
                };
            }
            unmix(&mut s, &pair[0]);
        }
        result.extend_from_slice(&s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [SaferVariant; 4] =
        [SaferVariant::K64, SaferVariant::K128, SaferVariant::Sk64, SaferVariant::Sk128];

    /// `exp` is `45^x mod 257` with 256 as 0, a permutation, and `log`
    /// inverts it.
    #[test]
    fn test_exp_and_log() {
        assert_eq!(EXP[0], 1);
        assert_eq!(EXP[1], 45);
        assert_eq!(EXP[128], 0);
        let mut seen = [false; 256];
        for x in 0..256 {
            assert!(!seen[usize::from(EXP[x])]);
            seen[usize::from(EXP[x])] = true;
            assert_eq!(usize::from(LOG[usize::from(EXP[x])]), x);
            let next = if EXP[x] == 0 { 256 } else { u32::from(EXP[x]) } * 45 % 257;
            assert_eq!(u32::from(EXP[(x + 1) % 256]), next % 256);
        }
    }

    #[test]
    fn test_key_lengths_and_round_counts_are_checked() {
        for v in ALL {
            for len in [0, 7, 9, 15, 17, 24] {
                assert!(Safer::new(v, &vec![0u8; len]).is_err(), "{v:?} {len}");
            }
            for rounds in [0, 14, 100] {
                assert!(Safer::with_rounds(v, &vec![0u8; v.key_len()], rounds).is_err());
            }
            assert_eq!(Safer::new(v, &vec![0u8; v.key_len()]).unwrap().rounds(),
                       v.default_rounds());
        }
    }

    /// Decryption inverts encryption, for every variant and round count.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x5afe_1993u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for v in ALL {
            for rounds in 1..=MAX_ROUNDS {
                let key: Vec<u8> = (0..v.key_len()).map(|_| next()).collect();
                let block: Vec<u8> = (0..BLOCK).map(|_| next()).collect();
                let mut c = Safer::with_rounds(v, &key, rounds).unwrap();
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block, "{v:?} {rounds}");
                assert_ne!(out, block);
            }
        }
    }

    /// K-64 is K-128 with the key repeated, and SK-64 SK-128, at the
    /// same round count: the -64 variants pass the key as both halves.
    #[test]
    fn test_the_64_bit_keys_are_the_128_bit_keys_repeated() {
        let key: Vec<u8> = (1..=8).collect();
        let doubled: Vec<u8> = key.iter().chain(&key).copied().collect();
        let block = [9u8, 8, 7, 6, 5, 4, 3, 2];
        for rounds in [1, 6, 13] {
            let (mut short, mut long) = (Vec::new(), Vec::new());
            Safer::with_rounds(SaferVariant::K64, &key, rounds).unwrap()
                .block_encrypt(&block, &mut short);
            Safer::with_rounds(SaferVariant::K128, &doubled, rounds).unwrap()
                .block_encrypt(&block, &mut long);
            assert_eq!(short, long);
            let (mut short, mut long) = (Vec::new(), Vec::new());
            Safer::with_rounds(SaferVariant::Sk64, &key, rounds).unwrap()
                .block_encrypt(&block, &mut short);
            Safer::with_rounds(SaferVariant::Sk128, &doubled, rounds).unwrap()
                .block_encrypt(&block, &mut long);
            assert_eq!(short, long);
        }
    }
}
