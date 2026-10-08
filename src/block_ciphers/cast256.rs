/*
CAST-256 (RFC 2612), Adams and Gilchrist 1998: an AES candidate built
from CAST-128's round functions and S-boxes. The RFC also names it
CAST6.

A 128 bit block, as four 32 bit words read big endian, and a key of 128,
160, 192, 224 or 256 bits. The key is zero-padded to 256 bits before
the schedule runs, so a 16 byte key is the 32 byte key that ends in
sixteen zeros - the RFC's note under section 2.4 - and the five lengths
are one cipher, not five.

## Structure

Forty-eight rounds in twelve quad-rounds: six forward (`Q`) and six
reverse (`QBAR`). The round functions `f1`, `f2` and `f3` are
CAST-128's, over CAST-128's S-boxes S1 to S4, which this module takes
from `cast5` rather than repeating; a test reads the copy printed in
RFC 2612 and requires the two to agree.

The key schedule runs the same round functions over the 256 bit key in
"octaves" of eight, keyed by constants that are generated rather than
tabulated: `Tm` steps from `2^30 * sqrt(2)` by `2^30 * sqrt(3)`, and
`Tr` from 19 by 17 mod 32. `test_the_schedule_constants` derives the
two starting values from the square roots.

**Decryption is encryption with the quad-round keys reversed** - the
RFC's "Round Key Re-Ordering" - and the forward and reverse quad-rounds
keep their positions: it is still six `Q` then six `QBAR`. Reversing the
keys and also swapping the quad-round types is self-consistent for a
round trip and wrong.

## Where the vectors come from

`rfcs/rfc2612.txt`, Appendix A, parsed at test time: one key of each of
128, 192 and 256 bits, with every quad-round's rotation keys, masking
keys and output, so a mistake is located to the quad-round that made it.
`vectors/cast256.vec` adds Bouncy Castle 1.77's CAST6Engine over all
five key lengths, written by `scripts/make_cast256_vectors.py`.
*/

use crate::block_ciphers::cast5::{S1, S2, S3, S4};
use crate::block_ciphers::BlockCipher;

const BLOCK: usize = 16;
const QUAD_ROUNDS: usize = 12;

/// `2^30 * sqrt(2)` and `2^30 * sqrt(3)`, the masking constants'
/// start and step (RFC 2612 2.4).
const CM: u32 = 0x5a82_7999;
const MM: u32 = 0x6ed9_eba1;
/// The rotation constants' start and step, mod 32.
const CR: u32 = 19;
const MR: u32 = 17;

fn f1(d: u32, kr: u32, km: u32) -> u32 {
    let i = km.wrapping_add(d).rotate_left(kr).to_be_bytes();
    ((S1[i[0] as usize] ^ S2[i[1] as usize]).wrapping_sub(S3[i[2] as usize]))
        .wrapping_add(S4[i[3] as usize])
}

fn f2(d: u32, kr: u32, km: u32) -> u32 {
    let i = (km ^ d).rotate_left(kr).to_be_bytes();
    (S1[i[0] as usize].wrapping_sub(S2[i[1] as usize]).wrapping_add(S3[i[2] as usize]))
        ^ S4[i[3] as usize]
}

fn f3(d: u32, kr: u32, km: u32) -> u32 {
    let i = km.wrapping_sub(d).rotate_left(kr).to_be_bytes();
    (S1[i[0] as usize].wrapping_add(S2[i[1] as usize]) ^ S3[i[2] as usize])
        .wrapping_sub(S4[i[3] as usize])
}

/// One quad-round's keys: rotations `kr[0..4]` (five bits each) and
/// masks `km[0..4]`.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct QuadKeys {
    pub(crate) kr: [u32; 4],
    pub(crate) km: [u32; 4],
}

#[derive(Clone)]
pub struct Cast256 {
    keys: [QuadKeys; QUAD_ROUNDS],
}

/// The forward quad-round `Q`.
fn q(b: &mut [u32; 4], k: &QuadKeys) {
    b[2] ^= f1(b[3], k.kr[0], k.km[0]);
    b[1] ^= f2(b[2], k.kr[1], k.km[1]);
    b[0] ^= f3(b[1], k.kr[2], k.km[2]);
    b[3] ^= f1(b[0], k.kr[3], k.km[3]);
}

/// The reverse quad-round `QBAR`, which is also `Q`'s inverse.
fn qbar(b: &mut [u32; 4], k: &QuadKeys) {
    b[3] ^= f1(b[0], k.kr[3], k.km[3]);
    b[0] ^= f3(b[1], k.kr[2], k.km[2]);
    b[1] ^= f2(b[2], k.kr[1], k.km[1]);
    b[2] ^= f1(b[3], k.kr[0], k.km[0]);
}

impl Cast256 {
    /// CAST-256 with a key of 16, 20, 24, 28 or 32 bytes.
    ///
    /// # Errors
    /// Any other key length.
    pub fn new(key: Vec<u8>) -> Result<Cast256, String> {
        if !matches!(key.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(format!("Wrong key length {}. CAST-256 takes 16, 20, 24, 28 or 32 \
                                bytes.", key.len()));
        }
        Ok(Cast256 { keys: Cast256::schedule(&key) })
    }

    pub(crate) fn schedule(key: &[u8]) -> [QuadKeys; QUAD_ROUNDS] {
        // The masking and rotation constants for all 24 octaves.
        let mut tm = [[0u32; 8]; 24];
        let mut tr = [[0u32; 8]; 24];
        let (mut cm, mut cr) = (CM, CR);
        for i in 0..24 {
            for j in 0..8 {
                tm[i][j] = cm;
                cm = cm.wrapping_add(MM);
                tr[i][j] = cr;
                cr = (cr + MR) % 32;
            }
        }
        // KAPPA = ABCDEFGH, the key zero-padded to 256 bits.
        let mut padded = [0u8; 32];
        padded[..key.len()].copy_from_slice(key);
        let mut k = [0u32; 8];
        for (w, chunk) in k.iter_mut().zip(padded.chunks_exact(4)) {
            *w = u32::from_be_bytes(chunk.try_into().expect("4 bytes"));
        }
        let octave = |k: &mut [u32; 8], i: usize| {
            let (m, r) = (&tm[i], &tr[i]);
            k[6] ^= f1(k[7], r[0], m[0]);
            k[5] ^= f2(k[6], r[1], m[1]);
            k[4] ^= f3(k[5], r[2], m[2]);
            k[3] ^= f1(k[4], r[3], m[3]);
            k[2] ^= f2(k[3], r[4], m[4]);
            k[1] ^= f3(k[2], r[5], m[5]);
            k[0] ^= f1(k[1], r[6], m[6]);
            k[7] ^= f2(k[0], r[7], m[7]);
        };
        let mut keys = [QuadKeys::default(); QUAD_ROUNDS];
        for (i, quad) in keys.iter_mut().enumerate() {
            octave(&mut k, 2 * i);
            octave(&mut k, 2 * i + 1);
            // Kr <- KAPPA: the low five bits of A, C, E, G.
            quad.kr = [k[0] & 31, k[2] & 31, k[4] & 31, k[6] & 31];
            // Km <- KAPPA: H, F, D, B.
            quad.km = [k[7], k[5], k[3], k[1]];
        }
        keys
    }

    fn read(input: &[u8]) -> [u32; 4] {
        let w = |n: usize| u32::from_be_bytes(input[4 * n..4 * n + 4].try_into().expect("4"));
        [w(0), w(1), w(2), w(3)]
    }

    fn write(b: [u32; 4], result: &mut Vec<u8>) {
        for w in b {
            result.extend_from_slice(&w.to_be_bytes());
        }
    }

    /// Six forward then six reverse quad-rounds under `keys` in the
    /// order given; `trace` sees the block after each.
    fn run(keys: &[QuadKeys], b: &mut [u32; 4], mut trace: impl FnMut(&[u32; 4])) {
        for (i, k) in keys.iter().enumerate() {
            if i < 6 { q(b, k) } else { qbar(b, k) }
            trace(b);
        }
    }
}

impl BlockCipher for Cast256 {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let mut b = Cast256::read(input);
        Cast256::run(&self.keys, &mut b, |_| {});
        Cast256::write(b, result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        // The same six Q then six QBAR, under the keys in reverse order:
        // QBAR with a quad-round's keys undoes Q with them, and Q undoes
        // QBAR.
        let mut reversed = self.keys;
        reversed.reverse();
        let mut b = Cast256::read(input);
        Cast256::run(&reversed, &mut b, |_| {});
        Cast256::write(b, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC: &str = include_str!("../../rfcs/rfc2612.txt");

    fn hex_word(s: &str) -> u32 {
        u32::from_str_radix(s, 16).unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn test_the_schedule_constants() {
        assert_eq!((2f64.sqrt() * (1u64 << 30) as f64) as u32, CM);
        assert_eq!((3f64.sqrt() * (1u64 << 30) as f64) as u32, MM);
    }

    /// RFC 2612 prints CAST-128's four round S-boxes again; they must be
    /// the ones `cast5` holds (read from RFC 2144), word for word.
    #[test]
    fn test_the_s_boxes_are_cast128s() {
        let start = RFC.find("2.1.1 S-Boxes").unwrap();
        let end = RFC.find("2.2 CAST-256 Notation").unwrap();
        let words: Vec<u32> = RFC[start..end].lines()
            .filter(|l| l.starts_with(' ') && l.split_whitespace().count() == 8
                    && l.split_whitespace().all(|w| w.len() == 8
                                                && w.bytes().all(|b| b.is_ascii_hexdigit())))
            .flat_map(|l| l.split_whitespace().map(hex_word).collect::<Vec<_>>())
            .collect();
        assert_eq!(words.len(), 1024);
        for (n, sbox) in [S1, S2, S3, S4].iter().enumerate() {
            assert_eq!(&words[256 * n..256 * (n + 1)], &sbox[..], "S{}", n + 1);
        }
    }

    /// Appendix A, parsed: for each key, every quad-round's keys and
    /// output on the way in, the ciphertext, and every output on the way
    /// back to the plaintext.
    #[test]
    fn test_rfc2612_appendix_a() {
        let appendix = &RFC[RFC.find("Appendix A: Test Vectors").unwrap()..];
        let mut keys_checked = 0;
        for section in appendix.split("KEYSIZE=").skip(2) {
            let field = |line: &str, name: &str| -> Option<String> {
                line.split_whitespace().find_map(|w| w.strip_prefix(name).map(str::to_string))
            };
            let mut key = None;
            let mut rounds: Vec<(QuadKeys, Vec<u8>)> = Vec::new();
            let mut current = QuadKeys::default();
            let (mut pt, mut ct) = (Vec::new(), Vec::new());
            for line in section.lines() {
                if let Some(k) = field(line, "KEY=") { key = Some(unhex(&k)); }
                for (j, name) in ["ROTK1=", "ROTK2=", "ROTK3=", "ROTK4="].iter().enumerate() {
                    if let Some(v) = field(line, name) { current.kr[j] = hex_word(&v); }
                }
                for (j, name) in ["MASK1=", "MASK2=", "MASK3=", "MASK4="].iter().enumerate() {
                    if let Some(v) = field(line, name) { current.km[j] = hex_word(&v); }
                }
                if let Some(v) = field(line, "OUT=") { rounds.push((current, unhex(&v))); }
                if let Some(v) = field(line, "PT=") { pt.push(unhex(&v)); }
                if let Some(v) = field(line, "CT=") { ct.push(unhex(&v)); }
            }
            let key = key.unwrap();
            assert_eq!(rounds.len(), 24, "{} bit key", key.len() * 8);
            assert_eq!((pt.len(), ct.len()), (2, 1));
            let schedule = Cast256::schedule(&key);

            // Encryption: the keys are the schedule's, in order.
            let mut b = Cast256::read(&pt[0]);
            let mut outs = Vec::new();
            Cast256::run(&schedule, &mut b, |s| {
                let mut v = Vec::new();
                Cast256::write(*s, &mut v);
                outs.push(v);
            });
            for i in 0..12 {
                assert_eq!(rounds[i].0, schedule[i], "keys, quad-round {}", i + 1);
                assert_eq!(rounds[i].1, outs[i], "output, quad-round {}", i + 1);
            }
            let mut cipher = Cast256::new(key.clone()).unwrap();
            let mut out = Vec::new();
            cipher.block_encrypt(&pt[0], &mut out);
            assert_eq!(out, ct[0]);

            // Decryption: the keys reversed, and the intermediate states.
            let mut b = Cast256::read(&ct[0]);
            let mut reversed = schedule;
            reversed.reverse();
            let mut outs = Vec::new();
            Cast256::run(&reversed, &mut b, |s| {
                let mut v = Vec::new();
                Cast256::write(*s, &mut v);
                outs.push(v);
            });
            for i in 0..12 {
                assert_eq!(rounds[12 + i].0, reversed[i], "decryption keys, {}", i + 1);
                assert_eq!(rounds[12 + i].1, outs[i], "decryption output, {}", i + 1);
            }
            let mut back = Vec::new();
            cipher.block_decrypt(&ct[0], &mut back);
            assert_eq!(back, pt[1]);
            keys_checked += 1;
        }
        assert_eq!(keys_checked, 3);
    }

    #[test]
    fn test_key_lengths() {
        for n in 0..40 {
            assert_eq!(Cast256::new(vec![1; n]).is_ok(), matches!(n, 16 | 20 | 24 | 28 | 32), "{n}");
        }
    }
}
