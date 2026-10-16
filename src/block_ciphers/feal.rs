/*!
FEAL (Shimizu and Miyaguchi, NTT, 1987): the Fast data Encipherment
ALgorithm, one of the first ciphers broken by differential and linear
cryptanalysis, and the reason both were found. Here FEAL-N - FEAL-4 and
FEAL-8 among them - with its 64-bit key (`Feal::new_n`, the catalogue's
`feal`, eight rounds unless asked otherwise) and FEAL-NX with a 128-bit
key (`Feal::new_nx`, `feal-nx`, 32 rounds unless asked otherwise, NTT's
recommendation). Both have a 64-bit block, and any even number of
rounds from 2 to 1024.

## A round

A Feistel network on two 32-bit halves, after the halves are whitened
with four 16-bit subkeys and the right one XORed with the left, and
before the same is undone with four more. The round function `f` mixes
a half with one 16-bit subkey through two byte functions,
`S_d(x, y) = (x + y + d mod 256) <<< 2`, d 0 or 1; there is no table.

## The key schedule

The key's left 64 bits run through `fK`, `f`'s two-word sibling,
`N / 2 + 4` times, each time with the previous output and a word taken
from the key's right 64 bits (their XOR, the first half, the second
half, in turn), and each output gives two subkeys. FEAL-N is FEAL-NX
with the right half zero, which is how the FEAL-NX specification
defines it and how this module makes it.

## Byte order

The specification's: bytes as it writes them, left to right.

## Constant time

Additions, rotations by two and XORs of bytes, with no table and no
branch on data.

## Where the vectors come from

`vectors/feal.vec`, written by `scripts/make_feal_vectors.py`: blocks on
which two FEAL-NX implementations, Donaldduck8's Python and zilijonas's
Java, agree at several round counts, with NTT's own test data for
FEAL-NX at 32 rounds - 40,960 blocks under ten keys - which
`vectors/feal_nx_ntt.txt` carries as NTT published it.
*/

use super::BlockCipher;

/// The round counts this module takes: even, from 2 to 1024.
pub const ROUNDS: core::ops::RangeInclusive<usize> = 2..=1024;

fn s(x: u8, y: u8, d: u8) -> u8 {
    x.wrapping_add(y).wrapping_add(d).rotate_left(2)
}

/// The round function: a half and a 16-bit subkey.
fn f(a: [u8; 4], b: [u8; 2]) -> [u8; 4] {
    let f1 = a[1] ^ b[0] ^ a[0];
    let f2 = a[2] ^ b[1] ^ a[3];
    let f1 = s(f1, f2, 1);
    let f2 = s(f2, f1, 0);
    [s(a[0], f1, 0), f1, f2, s(a[3], f2, 1)]
}

/// The key schedule's function: two 32-bit words.
fn fk(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    let f1 = s(a[1] ^ a[0], a[2] ^ a[3] ^ b[0], 1);
    let f2 = s(a[2] ^ a[3], f1 ^ b[1], 0);
    [s(a[0], f1 ^ b[2], 0), f1, f2, s(a[3], f2 ^ b[3], 1)]
}

fn xor4(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

#[derive(Clone)]
pub struct Feal {
    /// `K_0` to `K_{N+7}`.
    subkeys: Vec<[u8; 2]>,
    rounds: usize,
    nx: bool,
}

impl Feal {
    /// FEAL-N: an 8 byte key.
    pub fn new_n(key: &[u8], rounds: usize) -> Result<Feal, String> {
        if key.len() != 8 {
            return Err(format!("Wrong key length {}. FEAL-N takes an 8 byte key; FEAL-NX \
                                takes 16.", key.len()));
        }
        let mut full = [0u8; 16];
        full[..8].copy_from_slice(key);
        let mut feal = Feal::schedule(&full, rounds)?;
        feal.nx = false;
        Ok(feal)
    }

    /// FEAL-NX: a 16 byte key.
    pub fn new_nx(key: &[u8], rounds: usize) -> Result<Feal, String> {
        let key: &[u8; 16] = key.try_into().map_err(|_| format!(
            "Wrong key length {}. FEAL-NX takes a 16 byte key; FEAL-N takes 8.", key.len()))?;
        Feal::schedule(key, rounds)
    }

    fn schedule(key: &[u8; 16], rounds: usize) -> Result<Feal, String> {
        if !ROUNDS.contains(&rounds) || !rounds.is_multiple_of(2) {
            return Err(format!("FEAL takes an even number of rounds from {} to {}; {} is not one.",
                               ROUNDS.start(), ROUNDS.end(), rounds));
        }
        let word = |at: usize| -> [u8; 4] { key[at..at + 4].try_into().expect("4 bytes") };
        let (kr1, kr2) = (word(8), word(12));
        let (mut a, mut b, mut d) = (word(0), word(4), [0u8; 4]);
        let mut subkeys = Vec::with_capacity(rounds + 8);
        for r in 1..=rounds / 2 + 4 {
            let q = match r % 3 {
                1 => xor4(kr1, kr2),
                2 => kr1,
                _ => kr2,
            };
            let next = fk(a, xor4(xor4(b, d), q));
            d = a;
            a = b;
            b = next;
            subkeys.push([next[0], next[1]]);
            subkeys.push([next[2], next[3]]);
        }
        Ok(Feal { subkeys, rounds, nx: true })
    }

    pub fn rounds(&self) -> usize {
        self.rounds
    }

    /// Whether the key was FEAL-NX's 16 bytes rather than FEAL-N's 8.
    pub fn is_nx(&self) -> bool {
        self.nx
    }

    /// Four subkeys from `K_at`, as eight bytes.
    fn whitening(&self, at: usize) -> [u8; 8] {
        std::array::from_fn(|i| self.subkeys[at + i / 2][i % 2])
    }
}

fn halves(block: &[u8]) -> ([u8; 4], [u8; 4]) {
    (block[..4].try_into().expect("4"), block[4..8].try_into().expect("4"))
}

impl BlockCipher for Feal {
    fn blocksize(&self) -> usize {
        8
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let n = self.rounds;
        let first = self.whitening(n);
        let whitened: [u8; 8] = std::array::from_fn(|i| input[i] ^ first[i]);
        let (mut l, mut r) = halves(&whitened);
        r = xor4(r, l);
        for k in &self.subkeys[..n] {
            (l, r) = (r, xor4(l, f(r, *k)));
        }
        l = xor4(l, r);
        let last = self.whitening(n + 4);
        let out = [r, l].concat();
        result.extend(out.iter().zip(last).map(|(x, k)| x ^ k));
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let n = self.rounds;
        let last = self.whitening(n + 4);
        let unwhitened: [u8; 8] = std::array::from_fn(|i| input[i] ^ last[i]);
        let (mut r, mut l) = halves(&unwhitened);
        l = xor4(l, r);
        for k in self.subkeys[..n].iter().rev() {
            (l, r) = (xor4(r, f(l, *k)), l);
        }
        r = xor4(r, l);
        let first = self.whitening(n);
        let out = [l, r].concat();
        result.extend(out.iter().zip(first).map(|(x, k)| x ^ k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_lengths_and_round_counts() {
        for len in 0..=24 {
            assert_eq!(Feal::new_n(&vec![0; len], 8).is_ok(), len == 8, "{len}");
            assert_eq!(Feal::new_nx(&vec![0; len], 32).is_ok(), len == 16, "{len}");
        }
        for rounds in [0, 1, 3, 31, 1025, 1026, 2048] {
            assert!(Feal::new_nx(&[0; 16], rounds).is_err(), "{rounds}");
        }
        for rounds in [2, 4, 8, 16, 32, 64, 1024] {
            assert_eq!(Feal::new_nx(&[0; 16], rounds).unwrap().subkeys.len(), rounds + 8);
        }
    }

    /// FEAL-N is FEAL-NX with the key's right half zero.
    #[test]
    fn test_feal_n_is_feal_nx_with_a_zero_right_half() {
        let key: Vec<u8> = (1..=8).collect();
        let padded = [key.as_slice(), &[0; 8]].concat();
        for rounds in [4, 8, 32] {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            Feal::new_n(&key, rounds).unwrap().block_encrypt(&[7; 8], &mut a);
            Feal::new_nx(&padded, rounds).unwrap().block_encrypt(&[7; 8], &mut b);
            assert_eq!(a, b, "{rounds}");
        }
    }

    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0xfea1_1987u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for rounds in [2, 4, 8, 16, 32, 64] {
            for _ in 0..8 {
                let key: Vec<u8> = (0..16).map(|_| next()).collect();
                let block: Vec<u8> = (0..8).map(|_| next()).collect();
                let mut c = Feal::new_nx(&key, rounds).unwrap();
                let (mut out, mut back) = (Vec::new(), Vec::new());
                c.block_encrypt(&block, &mut out);
                c.block_decrypt(&out, &mut back);
                assert_eq!(back, block, "{rounds}");
            }
        }
    }
}
