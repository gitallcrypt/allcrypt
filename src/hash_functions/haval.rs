/*!
HAVAL (Zheng, Pieprzyk and Seberry, 1992): three, four or five passes,
and 128, 160, 192, 224 or 256 bits out, fifteen hashes in all.

Eight 32 bit registers, 128 byte blocks of 32 little-endian words. Each
pass runs 32 steps; step `i` writes register `7 - i mod 8` from a
Boolean function of seven others, chosen and ordered by a permutation
that depends on the pass and on how many passes there are (`PHI`), the
message words in an order of the pass's own (`ORDER`), and from the
second pass on a constant. The starting value and the constants are the
first 136 words of the fraction of pi (a test computes them).

The padding ends in ten bytes: the version (1), the number of passes and
the output length, then the length in bits, little endian. A shorter
output folds the last registers into the first ones (`fold`).

The tables are the designers', in the layout sphlib's `haval.c` and
PHP's `hash_haval.c` give them; the digests of PHP, sphlib and mhash over
`vectors/tiger_haval_snefru.vec` are what check them. Names are PHP's, with
an underscore for its comma: `haval128_3` to `haval256_5`.
*/

use super::buffer::BlockBuffer;
use super::HashFunction;

/// The fraction of pi, words 0 to 7: the starting value.
pub(super) const IV: [u32; 8] = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822,
                                 0x299F31D0, 0x082EFA98, 0xEC4E6C89];

/// The fraction of pi, words 8 to 135: the constants of passes 2 to 5.
pub(super) const K: [[u32; 32]; 4] = [
    [0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
     0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
     0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
     0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5],
    [0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E,
     0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94,
     0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993,
     0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C],
    [0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991,
     0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5,
     0x0F6D6FF3, 0x83F44239, 0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
     0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4],
    [0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4,
     0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
     0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B,
     0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4],
];

/// The message word each step of passes 2 to 5 takes; pass 1 takes them
/// in order.
const ORDER: [[usize; 32]; 4] = [
    [5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
     30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27],
    [19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
     31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2],
    [24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
     22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13],
    [27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
     5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15],
];

/// For `passes` and pass `p`, `PHI[passes - 3][p]`: which of the step's
/// seven inputs `x6 .. x0` the pass's function takes as its `x6 .. x0`.
const PHI: [[[usize; 7]; 5]; 3] = [
    [[1, 0, 3, 5, 6, 2, 4], [4, 2, 1, 0, 5, 3, 6], [6, 1, 2, 3, 4, 5, 0], [0; 7], [0; 7]],
    [[2, 6, 1, 4, 5, 3, 0], [3, 5, 2, 0, 1, 6, 4], [1, 4, 3, 6, 0, 2, 5], [6, 4, 0, 5, 2, 1, 3],
     [0; 7]],
    [[3, 4, 1, 0, 5, 2, 6], [6, 2, 1, 0, 3, 4, 5], [2, 6, 0, 4, 3, 1, 5], [1, 5, 3, 2, 0, 4, 6],
     [2, 5, 0, 6, 4, 3, 1]],
];

/// The five Boolean functions, on `x[6] .. x[0]` as the paper writes them.
fn f(pass: usize, x: [u32; 7]) -> u32 {
    let [x0, x1, x2, x3, x4, x5, x6] = x;
    match pass {
        0 => (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1) ^ x0,
        1 => (x1 & x2 & x3) ^ (x2 & x4 & x5) ^ (x1 & x2) ^ (x1 & x4) ^ (x2 & x6) ^ (x3 & x5)
            ^ (x4 & x5) ^ (x0 & x2) ^ x0,
        2 => (x1 & x2 & x3) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x3) ^ x0,
        3 => (x1 & x2 & x3) ^ (x2 & x4 & x5) ^ (x3 & x4 & x6) ^ (x1 & x4) ^ (x2 & x6)
            ^ (x3 & x4) ^ (x3 & x5) ^ (x3 & x6) ^ (x4 & x5) ^ (x4 & x6) ^ (x0 & x4) ^ x0,
        _ => (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1 & x2 & x3) ^ (x0 & x5) ^ x0,
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; 128], passes: usize) {
    let w: [u32; 32] = core::array::from_fn(|i| {
        u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().expect("4 bytes"))
    });
    let mut e = *state;
    for pass in 0..passes {
        let phi = &PHI[passes - 3][pass];
        for i in 0..32 {
            // The step's inputs x0 .. x6 are the registers i places back.
            let input = |k: usize| e[(k + 8 - i % 8) % 8];
            // `phi` lists the function's arguments from x6 down to x0.
            let args: [u32; 7] = core::array::from_fn(|j| input(phi[6 - j]));
            let (word, constant) = if pass == 0 {
                (w[i], 0)
            } else {
                (w[ORDER[pass - 1][i]], K[pass - 1][i])
            };
            let target = (7 + 8 - i % 8) % 8;
            e[target] = f(pass, args).rotate_right(7)
                .wrapping_add(e[target].rotate_right(11))
                .wrapping_add(word)
                .wrapping_add(constant);
        }
    }
    for (s, v) in state.iter_mut().zip(e) {
        *s = s.wrapping_add(v);
    }
}

/// The registers folded into an output of `bits`, as the designers
/// tailor the 256 bit result.
fn fold(s: &mut [u32; 8], bits: usize) {
    match bits {
        128 => {
            s[3] = s[3].wrapping_add((s[7] & 0xFF000000) | (s[6] & 0x00FF0000)
                                     | (s[5] & 0x0000FF00) | (s[4] & 0x000000FF));
            s[2] = s[2].wrapping_add((((s[7] & 0x00FF0000) | (s[6] & 0x0000FF00)
                                       | (s[5] & 0x000000FF)) << 8) | ((s[4] & 0xFF000000) >> 24));
            s[1] = s[1].wrapping_add((((s[7] & 0x0000FF00) | (s[6] & 0x000000FF)) << 16)
                                     | (((s[5] & 0xFF000000) | (s[4] & 0x00FF0000)) >> 16));
            s[0] = s[0].wrapping_add(((s[7] & 0x000000FF) << 24)
                                     | (((s[6] & 0xFF000000) | (s[5] & 0x00FF0000)
                                         | (s[4] & 0x0000FF00)) >> 8));
        }
        160 => {
            s[4] = s[4].wrapping_add(((s[7] & 0xFE000000) | (s[6] & 0x01F80000)
                                      | (s[5] & 0x0007F000)) >> 12);
            s[3] = s[3].wrapping_add(((s[7] & 0x01F80000) | (s[6] & 0x0007F000)
                                      | (s[5] & 0x00000FC0)) >> 6);
            s[2] = s[2].wrapping_add((s[7] & 0x0007F000) | (s[6] & 0x00000FC0)
                                     | (s[5] & 0x0000003F));
            s[1] = s[1].wrapping_add(((s[7] & 0x00000FC0) | (s[6] & 0x0000003F)
                                      | (s[5] & 0xFE000000)).rotate_right(25));
            s[0] = s[0].wrapping_add(((s[7] & 0x0000003F) | (s[6] & 0xFE000000)
                                      | (s[5] & 0x01F80000)).rotate_right(19));
        }
        192 => {
            s[5] = s[5].wrapping_add(((s[7] & 0xFC000000) | (s[6] & 0x03E00000)) >> 21);
            s[4] = s[4].wrapping_add(((s[7] & 0x03E00000) | (s[6] & 0x001F0000)) >> 16);
            s[3] = s[3].wrapping_add(((s[7] & 0x001F0000) | (s[6] & 0x0000FC00)) >> 10);
            s[2] = s[2].wrapping_add(((s[7] & 0x0000FC00) | (s[6] & 0x000003E0)) >> 5);
            s[1] = s[1].wrapping_add((s[7] & 0x000003E0) | (s[6] & 0x0000001F));
            s[0] = s[0].wrapping_add(((s[7] & 0x0000001F) | (s[6] & 0xFC000000)).rotate_right(26));
        }
        224 => {
            s[6] = s[6].wrapping_add(s[7] & 0x0000000F);
            s[5] = s[5].wrapping_add((s[7] >> 4) & 0x0000001F);
            s[4] = s[4].wrapping_add((s[7] >> 9) & 0x0000000F);
            s[3] = s[3].wrapping_add((s[7] >> 13) & 0x0000001F);
            s[2] = s[2].wrapping_add((s[7] >> 18) & 0x0000000F);
            s[1] = s[1].wrapping_add((s[7] >> 22) & 0x0000001F);
            s[0] = s[0].wrapping_add((s[7] >> 27) & 0x0000001F);
        }
        _ => {}
    }
}

/// HAVAL in progress.
#[derive(Clone)]
pub struct Haval {
    state: [u32; 8],
    buffer: BlockBuffer<128>,
    length: u64,
    passes: usize,
    bits: usize,
}

impl Haval {
    /// HAVAL with `bits` of output (128, 160, 192, 224 or 256) after
    /// `passes` passes (3, 4 or 5).
    ///
    /// # Errors
    /// Any other output length or number of passes.
    pub fn new(bits: usize, passes: usize) -> Result<Haval, String> {
        if ![128, 160, 192, 224, 256].contains(&bits) || !(3..=5).contains(&passes) {
            return Err(format!("HAVAL gives 128, 160, 192, 224 or 256 bits after 3, 4 or 5 \
                                passes, not {bits} bits after {passes}."));
        }
        Ok(Haval { state: IV, buffer: BlockBuffer::default(), length: 0, passes, bits })
    }
}

impl HashFunction for Haval {
    fn name(&self) -> String {
        format!("haval{}_{}", self.bits, self.passes)
    }

    fn digest_len(&self) -> usize {
        self.bits / 8
    }

    fn block_size(&self) -> usize {
        128
    }

    fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        let (state, passes) = (&mut self.state, self.passes);
        self.buffer.feed(input, |block| compress(state, block, passes));
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut last = self.clone();
        let pad = 1 + (245 - last.buffer.len()) % 128;
        let mut tail = vec![0u8; pad];
        tail[0] = 0x01;
        // Version 1, the passes and the output length in bits, in a
        // sixteen bit field, little endian.
        let field = 1 | (last.passes << 3) | (last.bits << 6);
        tail.extend_from_slice(&(field as u16).to_le_bytes());
        tail.extend_from_slice(&last.length.wrapping_mul(8).to_le_bytes());
        let (state, passes) = (&mut last.state, last.passes);
        last.buffer.feed(&tail, |block| compress(state, block, passes));
        debug_assert!(last.buffer.is_empty());
        fold(&mut last.state, last.bits);
        last.state.iter().flat_map(|w| w.to_le_bytes()).take(self.bits / 8).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::BigUint;

    /// The fraction of pi to `words` 32 bit words, by Machin's formula
    /// in integers scaled by 2^(32 words + 64) - the 64 guard bits being
    /// far more than the series' rounding can disturb.
    fn pi_words(words: usize) -> Vec<u32> {
        let bits = 32 * words + 64;
        let one = BigUint::from_u64(1).shl(bits);
        // arctan(1/x) = sum (-1)^k / ((2k+1) x^(2k+1)).
        let over = |v: &BigUint, d: u64| v.div(&BigUint::from_u64(d)).expect("d > 0");
        let arctan = |x: u64| {
            let (mut sum_pos, mut sum_neg) = (BigUint::zero(), BigUint::zero());
            let mut power = over(&one, x);
            let x2 = x * x;
            let mut k = 0u64;
            while !power.is_zero() {
                let term = over(&power, 2 * k + 1);
                if k.is_multiple_of(2) { sum_pos = sum_pos.add(&term) } else { sum_neg = sum_neg.add(&term) }
                power = over(&power, x2);
                k += 1;
            }
            sum_pos.sub(&sum_neg).expect("the series alternates downwards")
        };
        let pi = arctan(5).mul(&BigUint::from_u64(16)).sub(&arctan(239).mul(&BigUint::from_u64(4)))
            .expect("Machin");
        // Drop the integer part 3 and the guard bits.
        let fraction = pi.sub(&BigUint::from_u64(3).shl(bits)).expect("pi > 3").shr(64);
        let bytes = fraction.to_bytes_be_padded(4 * words).expect("fits");
        bytes.chunks(4).map(|c| u32::from_be_bytes(c.try_into().expect("4"))).collect()
    }

    #[test]
    fn test_the_constants_are_pi() {
        let pi = pi_words(136);
        assert_eq!(&pi[..8], &IV[..]);
        for (p, constants) in K.iter().enumerate() {
            assert_eq!(&pi[8 + 32 * p..8 + 32 * (p + 1)], &constants[..], "pass {}", p + 2);
        }
    }

    /// Each message order is a permutation, and each choice of the
    /// function's arguments too.
    #[test]
    fn test_the_tables_are_permutations() {
        for order in ORDER {
            let mut seen = order.to_vec();
            seen.sort_unstable();
            assert_eq!(seen, (0..32).collect::<Vec<_>>());
        }
        for (n, row) in PHI.iter().enumerate() {
            for phi in &row[..n + 3] {
                let mut seen = phi.to_vec();
                seen.sort_unstable();
                assert_eq!(seen, (0..7).collect::<Vec<_>>());
            }
        }
    }
}
