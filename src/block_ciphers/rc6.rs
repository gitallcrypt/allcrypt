/*
RC6, Rivest, Robshaw, Sidney and Yin 1998: an AES finalist, and RC5
widened to four words with a multiplication in the round.

Written RC6-w/r/b like RC5. The AES submission fixes w = 32 and r = 20,
so the block is 128 bits, and the key may be any length from 1 to 255
bytes; the AES profile is 16, 24 or 32. RC6-32/20/b is the only variant
implemented, because it is the only one with published vectors and
other implementations to agree with.

## What is unusual about it

**Each round squares a word.** `t = (B * (2B + 1)) <<< 5` is a quadratic
function of `B` modulo 2^32, which is what lets every bit of `B` reach
the rotation amount: the five bits that rotate `A` come from the top of
the product, not from `B`'s own low bits as in RC5.

**The rotation amounts are data dependent**, as in RC5, so nothing here
is constant time; `docs/pitfalls.md` says so for both.

**The decryption round is not the encryption round reversed word by
word**: the four words rotate the other way first, and `t` and `u` are
recomputed from the words that are now in `B` and `D` before either is
used. Running the encryption loop backwards with the same assignments
gives a cipher that inverts nothing.

**An empty key is refused.** The submission's key schedule handles it
with `c = max(1, ...)`, but Bouncy Castle indexes past the end of an
empty array, so there is no answer to agree with; the same reasoning as
RC5's empty key.

## Where the vectors come from

`vectors/rc6.vec`, written by `scripts/make_rc6_vectors.py`: the six
vectors from the submission (as Crypto++ carries them in
`TestData/rc6val.dat`), which Bouncy Castle 1.77 reproduces, and 513
more from Bouncy Castle over every key length from 1 to 64 bytes and
forty-one lengths up to 255.
*/

use crate::block_ciphers::BlockCipher;

/// `Odd(e - 2) * 2^32`, the same constant RC5 starts its table with.
const P32: u32 = 0xb7e1_5163;
/// `Odd(phi - 1) * 2^32`.
const Q32: u32 = 0x9e37_79b9;

/// RC6-32/**20**/b.
pub const ROUNDS: usize = 20;
/// The longest key the submission allows.
pub const MAX_KEY_BYTES: usize = 255;

const TABLE: usize = 2 * ROUNDS + 4;
const BLOCK: usize = 16;

#[derive(Clone)]
pub struct Rc6 {
    s: [u32; TABLE],
}

impl Rc6 {
    /// RC6-32/20/b with a key of 1 to 255 bytes.
    ///
    /// # Errors
    /// An empty key, or one longer than 255 bytes.
    pub fn new(key: &[u8]) -> Result<Rc6, String> {
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(format!("Wrong key length {}. RC6 takes 1 to {MAX_KEY_BYTES} bytes.",
                               key.len()));
        }
        // The key as little-endian words, the last one zero-padded.
        let c = key.len().div_ceil(4);
        let mut l = vec![0u32; c];
        for (i, &byte) in key.iter().enumerate() {
            l[i / 4] |= u32::from(byte) << (8 * (i % 4));
        }
        let mut s = [0u32; TABLE];
        s[0] = P32;
        for i in 1..TABLE {
            s[i] = s[i - 1].wrapping_add(Q32);
        }
        let (mut a, mut b) = (0u32, 0u32);
        let (mut i, mut j) = (0usize, 0usize);
        for _ in 0..3 * TABLE.max(c) {
            s[i] = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
            a = s[i];
            let ab = a.wrapping_add(b);
            l[j] = l[j].wrapping_add(ab).rotate_left(ab & 31);
            b = l[j];
            i = (i + 1) % TABLE;
            j = (j + 1) % c;
        }
        Ok(Rc6 { s })
    }

    fn words(input: &[u8]) -> [u32; 4] {
        let w = |k: usize| u32::from_le_bytes(input[4 * k..4 * k + 4].try_into().expect("4 bytes"));
        [w(0), w(1), w(2), w(3)]
    }

    fn push(words: [u32; 4], result: &mut Vec<u8>) {
        for w in words {
            result.extend_from_slice(&w.to_le_bytes());
        }
    }
}

/// `x * (2x + 1)`, rotated left five: the round's quadratic function.
fn f(x: u32) -> u32 {
    x.wrapping_mul(x.wrapping_mul(2).wrapping_add(1)).rotate_left(5)
}

impl BlockCipher for Rc6 {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let s = &self.s;
        let [mut a, mut b, mut c, mut d] = Rc6::words(input);
        b = b.wrapping_add(s[0]);
        d = d.wrapping_add(s[1]);
        for i in 1..=ROUNDS {
            let t = f(b);
            let u = f(d);
            a = (a ^ t).rotate_left(u & 31).wrapping_add(s[2 * i]);
            c = (c ^ u).rotate_left(t & 31).wrapping_add(s[2 * i + 1]);
            (a, b, c, d) = (b, c, d, a);
        }
        a = a.wrapping_add(s[2 * ROUNDS + 2]);
        c = c.wrapping_add(s[2 * ROUNDS + 3]);
        Rc6::push([a, b, c, d], result);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let s = &self.s;
        let [mut a, mut b, mut c, mut d] = Rc6::words(input);
        c = c.wrapping_sub(s[2 * ROUNDS + 3]);
        a = a.wrapping_sub(s[2 * ROUNDS + 2]);
        for i in (1..=ROUNDS).rev() {
            (a, b, c, d) = (d, a, b, c);
            let u = f(d);
            let t = f(b);
            c = c.wrapping_sub(s[2 * i + 1]).rotate_right(t & 31) ^ u;
            a = a.wrapping_sub(s[2 * i]).rotate_right(u & 31) ^ t;
        }
        d = d.wrapping_sub(s[1]);
        b = b.wrapping_sub(s[0]);
        Rc6::push([a, b, c, d], result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_magic_constants() {
        // Odd((e - 2) * 2^32) and Odd((phi - 1) * 2^32), from the
        // constants themselves rather than from the hex.
        let odd = |x: f64| {
            let v = (x * 4_294_967_296.0) as u64 as u32;
            v | 1
        };
        assert_eq!(odd(std::f64::consts::E - 2.0), P32);
        assert_eq!(odd((1.0 + 5f64.sqrt()) / 2.0 - 1.0), Q32);
    }

    #[test]
    fn test_key_lengths() {
        assert!(Rc6::new(&[]).is_err());
        assert!(Rc6::new(&[0; 256]).is_err());
        for n in [1, 16, 24, 32, 255] {
            assert!(Rc6::new(&vec![7; n]).is_ok(), "{n}");
        }
    }

    #[test]
    fn test_round_trip_and_one_block_appended() {
        let mut c = Rc6::new(&(0..32).collect::<Vec<u8>>()).unwrap();
        let pt: Vec<u8> = (100..116).collect();
        let mut ct = vec![0xaa];
        c.block_encrypt(&pt, &mut ct);
        assert_eq!(ct.len(), 17);
        let mut back = Vec::new();
        c.block_decrypt(&ct[1..], &mut back);
        assert_eq!(back, pt);
    }
}
