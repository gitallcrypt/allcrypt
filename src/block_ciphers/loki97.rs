/*!
LOKI97, Brown, Pieprzyk and Seberry's AES candidate (1998): a 128-bit
block, a key of 16, 24 or 32 bytes, and sixteen rounds of a Feistel
network on two 64-bit halves.

## A round

The right half is added to a subkey, mod 2^64, passed through `f` with a
second subkey, and added to a third; the left half is XORed with the
`f` output. `f(A, B)` exchanges the bits of `A`'s two 32-bit words
where `B`'s low word has a one, expands the result into eight
overlapping 13- and 11-bit inputs to the S-boxes S1 and S2, transposes
their eight output bytes as an 8 by 8 bit matrix (the permutation P),
and passes each byte, with three or five bits of `B`'s high word above
it, through S2, S2, S1, S1, S2, S2, S1, S1.

## The S-boxes

`S1(x) = ((x ^ 0x1fff)^3 mod 0x2911)` in GF(2^13) and
`S2(x) = ((x ^ 0x7ff)^3 mod 0xaa7)` in GF(2^11), each keeping its low
eight bits. Both are computed here at compile time from that rule.

## The key schedule

The key is four 64-bit words; a 16 or 24 byte key makes the missing
ones with `f`. Forty-eight subkeys come from an unbalanced Feistel
network over the four, each step adding the `i`-th multiple of
`0x9e3779b97f4a7c15`.

## Two forms

`Loki97::new`, the catalogue's `loki97`, is the submission's: key and
block read as big-endian 64-bit words. libmcrypt - and so PHP's
`mcrypt` - computes something else under the same name, and
`Loki97::new_mcrypt`, `loki97-mcrypt`, is that: it reads every 32-bit
word of the key, the block and the result in the opposite byte order,
and its key schedule is the 32 byte one whatever the key's length, so a
16 or 24 byte key is the 32 byte key with zeros after it, not the
submission's shorter key.

## Not constant time

S1 and S2 are tables indexed by data mixed with key bits.

## Where the vectors come from

`vectors/loki97.vec`, written by `scripts/make_loki97_vectors.py`:
blocks on which the designers' reference C, as Crypt::Loki97 1.0.1
carries it, and libmcrypt 2.5.8 agree once libmcrypt's form is
accounted for, with the published tests both carry - except at 16 and
24 byte keys, which libmcrypt cannot compute: those rows are the
reference's alone, and the file marks them.
*/

use super::BlockCipher;

const BLOCK: usize = 16;
const ROUNDS: usize = 16;
const SUBKEYS: usize = 3 * ROUNDS;
const DELTA: u64 = 0x9e37_79b9_7f4a_7c15;

/// `a * b` in GF(2^n) modulo `g`, `n` given as the field's size `2^n`.
const fn multiply(mut a: u32, mut b: u32, g: u32, size: u32) -> u32 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a <<= 1;
        if a >= size {
            a ^= g;
        }
        b >>= 1;
    }
    p
}

/// An S-box of `size` entries: `(x ^ (size - 1))^3` modulo `g`, its low
/// eight bits.
const fn sbox<const N: usize>(g: u32) -> [u8; N] {
    let mut table = [0u8; N];
    let mut x = 0;
    while x < N {
        let b = x as u32 ^ (N as u32 - 1);
        let cube = multiply(b, multiply(b, b, g, N as u32), g, N as u32);
        table[x] = (cube & 0xff) as u8;
        x += 1;
    }
    table
}

static S1: [u8; 0x2000] = sbox::<0x2000>(0x2911);
static S2: [u8; 0x800] = sbox::<0x800>(0xaa7);

/// P on the eight S-box outputs, the first the most significant byte:
/// bit `j` of the `k`-th goes to bit `8j + k` - the bytes transposed as
/// an 8 by 8 bit matrix.
fn permute(bytes: [u8; 8]) -> u64 {
    let mut e = 0u64;
    for (k, &byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            e |= u64::from((byte >> j) & 1) << (8 * j + k);
        }
    }
    e
}

fn f(a: u64, b: u64) -> u64 {
    let (al, ar) = ((a >> 32) as u32, a as u32);
    let (bl, br) = ((b >> 32) as u32, b as u32);
    // KP: exchange the bits of A's two words where B's low word is set.
    let d = (u64::from((al & !br) | (ar & br)) << 32) | u64::from((ar & !br) | (al & br));
    // E and the first column of S-boxes: eight overlapping inputs, the
    // first wrapping round from the bottom of `d` to its top.
    let inputs = [
        S1[(d.rotate_left(8) & 0x1fff) as usize],
        S2[((d >> 48) & 0x7ff) as usize],
        S1[((d >> 40) & 0x1fff) as usize],
        S2[((d >> 32) & 0x7ff) as usize],
        S2[((d >> 24) & 0x7ff) as usize],
        S1[((d >> 16) & 0x1fff) as usize],
        S2[((d >> 8) & 0x7ff) as usize],
        S1[(d & 0x1fff) as usize],
    ];
    let e = permute(inputs);
    // The second column: each byte of `e` with bits of B's high word
    // above it, three for S2 and five for S1, from the top of the word
    // down: bits 31-29, 28-26, 25-21, 20-16, 15-13, 12-10, 9-5, 4-0.
    let byte = |n: u32| ((e >> (56 - 8 * n)) & 0xff) as usize;
    let high = |top: u32, width: u32| (((bl >> (top + 1 - width)) & ((1 << width) - 1)) << 8) as usize;
    let out = [
        S2[byte(0) | high(31, 3)],
        S2[byte(1) | high(28, 3)],
        S1[byte(2) | high(25, 5)],
        S1[byte(3) | high(20, 5)],
        S2[byte(4) | high(15, 3)],
        S2[byte(5) | high(12, 3)],
        S1[byte(6) | high(9, 5)],
        S1[byte(7) | high(4, 5)],
    ];
    u64::from_be_bytes(out)
}

#[derive(Clone)]
pub struct Loki97 {
    subkeys: [u64; SUBKEYS],
    /// libmcrypt's form: every 32-bit word byte-swapped.
    mcrypt: bool,
}

/// `data` with the bytes of each 32-bit word reversed.
fn swap_word_bytes(data: &[u8]) -> Vec<u8> {
    data.chunks_exact(4).flat_map(|w| w.iter().rev()).copied().collect()
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("8 bytes"))
}

impl Loki97 {
    fn check_key_length(n: usize) -> Result<(), String> {
        if matches!(n, 16 | 24 | 32) {
            Ok(())
        } else {
            Err(format!("Wrong key length {n}. LOKI97 takes a 16, 24 or 32 byte key."))
        }
    }

    pub fn new(key: &[u8]) -> Result<Loki97, String> {
        Loki97::check_key_length(key.len())?;
        let k4 = word(&key[0..8]);
        let k3 = word(&key[8..16]);
        let (k2, k1) = match key.len() {
            16 => (f(k3, k4), f(k4, k3)),
            24 => (word(&key[16..24]), f(k4, k3)),
            _ => (word(&key[16..24]), word(&key[24..32])),
        };
        let mut k = [k4, k3, k2, k1];
        let mut subkeys = [0u64; SUBKEYS];
        let mut delta = DELTA;
        for subkey in subkeys.iter_mut() {
            let [k4, k3, k2, k1] = k;
            *subkey = k4 ^ f(k1.wrapping_add(k3).wrapping_add(delta), k2);
            k = [k3, k2, k1, *subkey];
            delta = delta.wrapping_add(DELTA);
        }
        Ok(Loki97 { subkeys, mcrypt: false })
    }

    /// LOKI97 as libmcrypt computes it: the key zero-padded to 32 bytes,
    /// and every 32-bit word of the key, each block and each result read
    /// in the opposite byte order.
    pub fn new_mcrypt(key: &[u8]) -> Result<Loki97, String> {
        Loki97::check_key_length(key.len())?;
        let mut padded = swap_word_bytes(key);
        padded.resize(32, 0);
        let mut cipher = Loki97::new(&padded)?;
        cipher.mcrypt = true;
        Ok(cipher)
    }

    /// Whether this is `new_mcrypt`'s form.
    pub fn is_mcrypt(&self) -> bool {
        self.mcrypt
    }

    fn load(&self, input: &[u8]) -> (u64, u64) {
        let block = if self.mcrypt { swap_word_bytes(&input[..BLOCK]) } else { input[..BLOCK].to_vec() };
        (word(&block[..8]), word(&block[8..]))
    }

    fn store(&self, left: u64, right: u64, result: &mut Vec<u8>) {
        let mut block = left.to_be_bytes().to_vec();
        block.extend_from_slice(&right.to_be_bytes());
        if self.mcrypt {
            block = swap_word_bytes(&block);
        }
        result.extend(block);
    }
}

impl BlockCipher for Loki97 {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut l, mut r) = self.load(input);
        for k in self.subkeys.chunks_exact(3) {
            let n = r.wrapping_add(k[0]);
            let out = f(n, k[1]);
            r = l ^ out;
            l = n.wrapping_add(k[2]);
        }
        self.store(r, l, result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut l, mut r) = self.load(input);
        for k in self.subkeys.chunks_exact(3).rev() {
            let n = r.wrapping_sub(k[2]);
            let out = f(n, k[1]);
            r = l ^ out;
            l = n.wrapping_sub(k[0]);
        }
        self.store(r, l, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 8, 15, 17, 20, 23, 25, 31, 33, 64] {
            assert!(Loki97::new(&vec![0u8; len]).is_err(), "{len}");
            assert!(Loki97::new_mcrypt(&vec![0u8; len]).is_err(), "{len}");
        }
    }

    /// The S-boxes from their definition, entry by entry, against a
    /// cube computed the slow way: as a polynomial product reduced bit
    /// by bit from the top.
    #[test]
    fn test_the_sboxes_are_cubes() {
        fn reduce(mut x: u64, g: u64, bits: u32) -> u64 {
            for i in (bits..64).rev() {
                if x >> i & 1 != 0 {
                    x ^= g << (i - bits);
                }
            }
            x
        }
        fn clmul(a: u64, b: u64) -> u64 {
            (0..32).filter(|i| b >> i & 1 != 0).fold(0, |acc, i| acc ^ (a << i))
        }
        for (table, g, bits) in [(&S1[..], 0x2911u64, 13), (&S2[..], 0xaa7, 11)] {
            for (x, &entry) in table.iter().enumerate() {
                let b = x as u64 ^ ((1 << bits) - 1);
                let cube = reduce(clmul(clmul(b, b), b), g, bits);
                assert_eq!(u64::from(entry), cube & 0xff, "{x}");
            }
        }
    }

    /// P as the submission prints it: input bits 63 down to 0 go to
    /// output bits 56, 48, 40, 32, 24, 16, 8, 0, then 57, 49, ... 1, and
    /// so on to 63, 55, ... 7 - eight rows of eight.
    #[test]
    fn test_p_is_the_submissions_table() {
        for b in 0..64 {
            let m = 63 - b;
            let expected = 56 - 8 * (m % 8) + m / 8;
            assert_eq!(permute((1u64 << b).to_be_bytes()), 1 << expected, "{b}");
        }
    }

    /// Decryption inverts encryption, both forms, every key length.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x1097_1998u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for len in [16, 24, 32] {
            for _ in 0..8 {
                let key: Vec<u8> = (0..len).map(|_| next()).collect();
                let block: Vec<u8> = (0..BLOCK).map(|_| next()).collect();
                for mut c in [Loki97::new(&key).unwrap(), Loki97::new_mcrypt(&key).unwrap()] {
                    let (mut out, mut back) = (Vec::new(), Vec::new());
                    c.block_encrypt(&block, &mut out);
                    c.block_decrypt(&out, &mut back);
                    assert_eq!(back, block, "{len}");
                    assert_ne!(out, block);
                }
            }
        }
    }

    /// libmcrypt's form is the 32 byte cipher on the zero-padded key, its
    /// words byte-swapped - and so a 16 byte key is not the submission's
    /// 16 byte key.
    #[test]
    fn test_the_mcrypt_form() {
        let key: Vec<u8> = (1..=16).collect();
        let block: Vec<u8> = (100..116).collect();
        let mut padded = swap_word_bytes(&key);
        padded.resize(32, 0);
        let (mut direct, mut mcrypt, mut short) = (Vec::new(), Vec::new(), Vec::new());
        Loki97::new(&padded).unwrap().block_encrypt(&swap_word_bytes(&block), &mut direct);
        Loki97::new_mcrypt(&key).unwrap().block_encrypt(&block, &mut mcrypt);
        Loki97::new(&key).unwrap().block_encrypt(&block, &mut short);
        assert_eq!(mcrypt, swap_word_bytes(&direct));
        assert_ne!(mcrypt, short);
    }
}
