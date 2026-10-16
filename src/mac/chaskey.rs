/*
Chaskey (Mouha, Mennink, Van Herrewege, Watanabe, Preneel and
Verbauwhede, SAC 2014): a MAC for 32 bit microcontrollers, a CBC-MAC
over a keyless permutation of four 32 bit words, with an
Even-Mansour-style key at the end.

    v = K
    for each block but the last:   v = pi(v ^ M[i])
    last block whole:              v = pi(v ^ M[m] ^ K1) ^ K1
    last block short (or empty):   v = pi(v ^ (M[m] || 01 00..) ^ K2) ^ K2
    tag = v, its words little endian

    K1 = K . x,   K2 = K1 . x     in GF(2^128) mod x^128 + x^7 + x^2 + x + 1

`pi` is `rounds` rounds of add, rotate and XOR: 8 in the original
Chaskey, 12 in Chaskey-12, which the designers' 2015 status update
proposes, and 16 in Chaskey-LTS. The tag is 16 bytes; the paper
shortens one by taking its first bytes, which is a slice of this one.

Five things agree with themselves when wrong:

  * **the round is HalfSipHash's with two rotations swapped**: 7 then
    13 there, 13 then 7 here. Copying `siphash::half_round` gives a
    permutation, and a MAC, that nobody else computes.
  * **every word is little endian, and so is the doubling**: `K . x`
    shifts the 128 bit value whose least significant word is `K[0]`,
    and the carry out of the top of `K[3]` folds 0x87 into the bottom
    of `K[0]`. CMAC's doubling is big endian over bytes; borrowing it is
    another MAC.
  * **a whole final block takes K1, a short one is padded and takes
    K2**, and the empty message is a short one: the block `01 00 ..`.
    The pad is a 0x01 byte, not CMAC's 0x80.
  * **the key is XORed twice in the last block**, before and after the
    permutation. Leaving out the second gives a CBC-MAC whose last block
    is merely whitened, and every self-made round trip still holds.
  * **the state starts as the key**, not as zero: the first block's
    input is `K ^ M[1]`.

The tag depends on the key only through additions, rotations, XORs and
the doubling, whose carry is folded in with a mask; the branches are on
the message's length, which is public. `scripts/ct_check.py`'s `chaskey`
row runs all three round counts under a secret key.

Checked against `vectors/chaskey.vec`: the 64 tags for each of 8 and 12
rounds that dgryski/go-chaskey's test file publishes, and generated rows
agreed by go-chaskey's assembly and portable builds (8 and 12 rounds)
and sacundim's Rust crate (all three). Chaskey-LTS has only the one MAC
to agree with, so its permutation has a second reading of its own:
volexity's Chaskey-LTS block cipher, `pi(x ^ K) ^ K`, whose rows - the
FELIX block among them - are checked here.
*/

use crate::Mac;

/// The round counts with a name: Chaskey, Chaskey-12, Chaskey-LTS.
pub const ROUNDS: [usize; 3] = [8, 12, 16];

/// One round of the permutation.
fn round(v: &mut [u32; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(5) ^ v[0];
    v[0] = v[0].rotate_left(16);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(8) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(13) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(7) ^ v[2];
    v[2] = v[2].rotate_left(16);
}

fn permute(v: &mut [u32; 4], rounds: usize) {
    for _ in 0..rounds {
        round(v);
    }
}

/// `K . x` in GF(2^128), the words little endian: shifted left by one
/// bit across the four words, with 0x87 folded into the bottom when the
/// top bit was set. The fold is a mask, not a branch, since `K` is the
/// key.
fn times_two(k: &[u32; 4]) -> [u32; 4] {
    let carry = crate::bignum::ct::opaque(u64::from(k[3] >> 31)) as u32;
    [
        k[0] << 1 ^ (0x87 & carry.wrapping_neg()),
        k[1] << 1 | k[0] >> 31,
        k[2] << 1 | k[1] >> 31,
        k[3] << 1 | k[2] >> 31,
    ]
}

fn words(bytes: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4 bytes")))
}

fn xor(v: &mut [u32; 4], w: &[u32; 4]) {
    for (a, b) in v.iter_mut().zip(w) {
        *a ^= b;
    }
}

/// Chaskey under one key, streaming.
pub struct Chaskey {
    k: [u32; 4],
    k1: [u32; 4],
    k2: [u32; 4],
    rounds: usize,
    v: [u32; 4],
    /// The last block seen, held back until more input shows it was not
    /// the last: 0 to 16 bytes.
    pending: [u8; 16],
    pending_len: usize,
}

impl core::fmt::Debug for Chaskey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Chaskey").field("rounds", &self.rounds).finish_non_exhaustive()
    }
}

impl Chaskey {
    /// Chaskey with `rounds` rounds - 8, 12 (Chaskey-12) or 16
    /// (Chaskey-LTS) - under a 16 byte key.
    ///
    /// # Errors
    /// A key of another length, or another round count.
    pub fn new(key: &[u8], rounds: usize) -> Result<Chaskey, String> {
        let key: &[u8; 16] = key.try_into()
            .map_err(|_| format!("A Chaskey key is 16 bytes, not {}.", key.len()))?;
        if !ROUNDS.contains(&rounds) {
            return Err(format!("Chaskey is defined with 8, 12 (Chaskey-12) or 16 (Chaskey-LTS) \
                                rounds, not {rounds}."));
        }
        let k = words(key);
        let k1 = times_two(&k);
        let k2 = times_two(&k1);
        Ok(Chaskey { k, k1, k2, rounds, v: k, pending: [0; 16], pending_len: 0 })
    }

    /// The tag's length, 16 bytes.
    pub fn tag_len(&self) -> usize {
        16
    }

    /// Back to the start, under the same key.
    pub fn reset(&mut self) {
        self.v = self.k;
        self.pending = [0; 16];
        self.pending_len = 0;
    }

    fn absorb(&mut self, block: &[u8; 16]) {
        xor(&mut self.v, &words(block));
        permute(&mut self.v, self.rounds);
    }
}

impl Mac for Chaskey {
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.pending_len == 16 {
                let block = self.pending;
                self.absorb(&block);
                self.pending_len = 0;
            }
            let take = (16 - self.pending_len).min(input.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&input[..take]);
            self.pending_len += take;
            input = &input[take..];
        }
    }

    /// The tag over everything given so far. The state is left as it
    /// was, so `update` can follow and `digest` can be called again.
    fn digest(&mut self) -> Vec<u8> {
        let mut last = [0u8; 16];
        last[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
        let key = if self.pending_len == 16 {
            self.k1
        } else {
            last[self.pending_len] = 0x01;
            self.k2
        };
        let mut v = self.v;
        xor(&mut v, &words(&last));
        xor(&mut v, &key);
        permute(&mut v, self.rounds);
        xor(&mut v, &key);
        v.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}

/// One shot: the 16 byte Chaskey tag of `message` with `rounds` rounds
/// (8, 12 or 16) under a 16 byte key.
///
/// # Errors
/// As [`Chaskey::new`].
pub fn chaskey(key: &[u8], message: &[u8], rounds: usize) -> Result<Vec<u8>, String> {
    let mut mac = Chaskey::new(key, rounds)?;
    mac.update(message);
    Ok(mac.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../vectors/chaskey.vec");

    fn unhex(text: &str) -> Vec<u8> {
        if text == "-" {
            return Vec::new();
        }
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn rows(kind: &str) -> Vec<std::collections::HashMap<&'static str, &'static str>> {
        VECTORS.lines()
            .filter(|line| line.split(' ').next() == Some(kind))
            .map(|line| line.split(' ').skip(1)
                 .map(|f| f.split_once('=').expect("name=value")).collect())
            .collect()
    }

    /// The permutation as volexity's Chaskey-LTS block cipher and
    /// sacundim's cipher module use it, `pi(x ^ K) ^ K`: a reading of
    /// the 16 round permutation that does not go through any MAC.
    #[test]
    fn test_the_permutation_against_the_block_cipher_rows() {
        let rows = rows("chaskey-cipher");
        assert!(rows.len() >= 40, "{} rows", rows.len());
        assert!(rows.iter().any(|row| row["source"] == "felix"));
        for row in rows {
            let rounds: usize = row["rounds"].parse().expect("rounds");
            let key = words(&unhex(row["key"]).try_into().expect("16 bytes"));
            let mut v = words(&unhex(row["block"]).try_into().expect("16 bytes"));
            xor(&mut v, &key);
            permute(&mut v, rounds);
            xor(&mut v, &key);
            let out: Vec<u8> = v.iter().flat_map(|w| w.to_le_bytes()).collect();
            assert_eq!(out, unhex(row["out"]), "{row:?}");
        }
    }

    /// HalfSipHash's round has the same shape with 7 and 13 the other
    /// way round; the two must differ on the first round already.
    #[test]
    fn test_the_round_is_not_halfsiphashs() {
        let mut ours = [0x0123_4567, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210];
        let mut theirs = ours;
        round(&mut ours);
        theirs[0] = theirs[0].wrapping_add(theirs[1]);
        theirs[1] = theirs[1].rotate_left(5) ^ theirs[0];
        theirs[0] = theirs[0].rotate_left(16);
        theirs[2] = theirs[2].wrapping_add(theirs[3]);
        theirs[3] = theirs[3].rotate_left(8) ^ theirs[2];
        theirs[0] = theirs[0].wrapping_add(theirs[3]);
        theirs[3] = theirs[3].rotate_left(7) ^ theirs[0];
        theirs[2] = theirs[2].wrapping_add(theirs[1]);
        theirs[1] = theirs[1].rotate_left(13) ^ theirs[2];
        theirs[2] = theirs[2].rotate_left(16);
        assert_ne!(ours, theirs);
    }

    /// The doubling with and without the fold, and its carries between
    /// words.
    #[test]
    fn test_doubling() {
        assert_eq!(times_two(&[1, 0, 0, 0]), [2, 0, 0, 0]);
        assert_eq!(times_two(&[0x8000_0000, 0, 0, 0]), [0, 1, 0, 0]);
        assert_eq!(times_two(&[0, 0x8000_0000, 0x8000_0000, 0]), [0, 0, 1, 1]);
        assert_eq!(times_two(&[0, 0, 0, 0x8000_0000]), [0x87, 0, 0, 0]);
        assert_eq!(times_two(&[0xffff_ffff; 4]), [0xffff_fffe ^ 0x87, 0xffff_ffff, 0xffff_ffff,
                                                  0xffff_ffff]);
    }

    #[test]
    fn test_streaming_equals_one_call() {
        let key: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(17) ^ 3).collect();
        let message: Vec<u8> = (0..300u32).map(|i| (i * 7 + 1) as u8).collect();
        for rounds in ROUNDS {
            for length in [0, 1, 15, 16, 17, 31, 32, 33, 48, 300] {
                let whole = chaskey(&key, &message[..length], rounds).expect("tag");
                for piece in [1, 3, 15, 16, 17] {
                    let mut mac = Chaskey::new(&key, rounds).expect("key");
                    for chunk in message[..length].chunks(piece) {
                        mac.update(chunk);
                    }
                    assert_eq!(mac.digest(), whole, "{rounds} rounds, {length} bytes by {piece}");
                }
                let mut mac = Chaskey::new(&key, rounds).expect("key");
                mac.update(&message[..length]);
                mac.update(b"");
                assert_eq!(mac.digest(), whole, "an empty update changes nothing");
            }
        }
    }

    #[test]
    fn test_digest_does_not_finish_the_state() {
        let mut mac = Chaskey::new(&[7; 16], 12).expect("key");
        mac.update(&[1; 20]);
        let first = mac.digest();
        assert_eq!(mac.digest(), first);
        mac.update(&[2; 30]);
        let mut whole = [1u8; 50].to_vec();
        whole[20..].fill(2);
        assert_eq!(mac.digest(), chaskey(&[7; 16], &whole, 12).expect("tag"));
        mac.reset();
        assert_eq!(mac.digest(), chaskey(&[7; 16], b"", 12).expect("tag"));
    }

    #[test]
    fn test_other_round_counts_and_key_lengths_are_refused() {
        for rounds in [0, 1, 4, 7, 9, 20] {
            let err = Chaskey::new(&[0; 16], rounds).expect_err("refused");
            assert!(err.contains(&format!("not {rounds}.")), "{err}");
        }
        for length in [0, 8, 15, 17, 32] {
            let err = Chaskey::new(&vec![0; length], 8).expect_err("refused");
            assert_eq!(err, format!("A Chaskey key is 16 bytes, not {length}."));
        }
    }

    /// The round counts are not interchangeable, and a whole block is not
    /// the same as the same bytes padded.
    #[test]
    fn test_the_variants_differ() {
        let key = [0x5a; 16];
        let tags: Vec<_> = ROUNDS.iter().map(|&r| chaskey(&key, b"abc", r).expect("tag")).collect();
        assert_ne!(tags[0], tags[1]);
        assert_ne!(tags[1], tags[2]);
        assert_ne!(chaskey(&key, &[0; 16], 8).expect("tag"),
                   chaskey(&key, &[0; 15], 8).expect("tag"));
    }
}
