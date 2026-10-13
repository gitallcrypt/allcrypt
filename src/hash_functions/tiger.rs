/*!
Tiger (Anderson and Biham, 1996), and Tiger2.

A 192 bit hash on 64 bit words: three 64 bit registers, eight message
words per 64 byte block, and four S-boxes of 256 words, which the
designers generated with Tiger itself, and so are generated here (`gen`).
Three passes over the block, the message words mixed by a key schedule
between them; PHP's `tiger192,4` and its neighbours run four.

The padding is MD4's - one byte, zeros, the length in bits little
endian - with the one byte 0x01 in Tiger and 0x80 in Tiger2, which is the
only difference between them. The digest is the three registers little
endian; the 128 and 160 bit forms are its first 16 and 20 bytes.

Names: `tiger` is Tiger at 192 bits and three passes, as everyone means
it (and `tiger192_3`, PHP's spelling); `tiger128_3`, `tiger160_3`,
`tiger128_4`, `tiger160_4` and `tiger192_4` are PHP's other five;
`tiger2` is Tiger2 at 192 bits and three passes.
*/

use std::sync::OnceLock;

use super::buffer::BlockBuffer;
use super::HashFunction;

type Sboxes = [[u64; 256]; 4];

const A0: u64 = 0x0123_4567_89AB_CDEF;
const B0: u64 = 0xFEDC_BA98_7654_3210;
const C0: u64 = 0xF096_A5B4_C3B2_E187;

/// The compression function: `passes` passes over the eight message
/// words, with the key schedule between them, under `t`.
fn compress(t: &Sboxes, state: &mut [u64; 3], block: &[u8; 64], passes: usize) {
    let mut x: [u64; 8] = core::array::from_fn(|i| {
        u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().expect("8 bytes"))
    });
    let byte = |v: u64, i: u32| usize::from((v >> (8 * i)) as u8);
    let round = |a: &mut u64, b: &mut u64, c: &mut u64, word: u64, mul: u64| {
        *c ^= word;
        *a = a.wrapping_sub(t[0][byte(*c, 0)] ^ t[1][byte(*c, 2)] ^ t[2][byte(*c, 4)]
                            ^ t[3][byte(*c, 6)]);
        *b = b.wrapping_add(t[3][byte(*c, 1)] ^ t[2][byte(*c, 3)] ^ t[1][byte(*c, 5)]
                            ^ t[0][byte(*c, 7)]);
        *b = b.wrapping_mul(mul);
    };
    let pass = |a: &mut u64, b: &mut u64, c: &mut u64, x: &[u64; 8], mul: u64| {
        round(a, b, c, x[0], mul);
        round(b, c, a, x[1], mul);
        round(c, a, b, x[2], mul);
        round(a, b, c, x[3], mul);
        round(b, c, a, x[4], mul);
        round(c, a, b, x[5], mul);
        round(a, b, c, x[6], mul);
        round(b, c, a, x[7], mul);
    };
    let schedule = |x: &mut [u64; 8]| {
        x[0] = x[0].wrapping_sub(x[7] ^ 0xA5A5_A5A5_A5A5_A5A5);
        x[1] ^= x[0];
        x[2] = x[2].wrapping_add(x[1]);
        x[3] = x[3].wrapping_sub(x[2] ^ (!x[1] << 19));
        x[4] ^= x[3];
        x[5] = x[5].wrapping_add(x[4]);
        x[6] = x[6].wrapping_sub(x[5] ^ (!x[4] >> 23));
        x[7] ^= x[6];
        x[0] = x[0].wrapping_add(x[7]);
        x[1] = x[1].wrapping_sub(x[0] ^ (!x[7] << 19));
        x[2] ^= x[1];
        x[3] = x[3].wrapping_add(x[2]);
        x[4] = x[4].wrapping_sub(x[3] ^ (!x[2] >> 23));
        x[5] ^= x[4];
        x[6] = x[6].wrapping_add(x[5]);
        x[7] = x[7].wrapping_sub(x[6] ^ 0x0123_4567_89AB_CDEF);
    };
    let [mut a, mut b, mut c] = *state;
    pass(&mut a, &mut b, &mut c, &x, 5);
    schedule(&mut x);
    pass(&mut c, &mut a, &mut b, &x, 7);
    schedule(&mut x);
    pass(&mut b, &mut c, &mut a, &x, 9);
    // Further passes multiply by 9 and turn the registers round once
    // each, as the reference's loop does.
    for _ in 3..passes {
        schedule(&mut x);
        pass(&mut a, &mut b, &mut c, &x, 9);
        (a, b, c) = (c, a, b);
    }
    state[0] ^= a;
    state[1] = b.wrapping_sub(state[1]);
    state[2] = c.wrapping_add(state[2]);
}

/// The S-boxes, as the designers made them: every entry starts as its
/// index in each of its eight bytes, and five times over, each byte of
/// each entry is swapped with the same byte of an entry another Tiger
/// state picks, the state compressing the designers' 64 byte sentence
/// under the boxes so far each time the three registers are used up.
fn gen() -> Sboxes {
    const SENTENCE: &[u8; 64] = b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham";
    let mut t: Sboxes = [[0; 256]; 4];
    for sb in &mut t {
        for (i, entry) in sb.iter_mut().enumerate() {
            *entry = u64::from_le_bytes([i as u8; 8]);
        }
    }
    let mut state = [A0, B0, C0];
    let mut abc = 2;
    for _ in 0..5 {
        for i in 0..256 {
            for sb in 0..4 {
                abc += 1;
                if abc == 3 {
                    abc = 0;
                    // compress feeds the state forward; the reference
                    // keeps the state it returns.
                    let mut next = state;
                    compress(&t, &mut next, SENTENCE, 3);
                    state = next;
                }
                for col in 0..8 {
                    let other = usize::from((state[abc] >> (8 * col)) as u8);
                    let mask = 0xffu64 << (8 * col);
                    let (here, there) = (t[sb][i] & mask, t[sb][other] & mask);
                    t[sb][i] = (t[sb][i] & !mask) | there;
                    t[sb][other] = (t[sb][other] & !mask) | here;
                }
            }
        }
    }
    t
}

fn sboxes() -> &'static Sboxes {
    static TABLES: OnceLock<Sboxes> = OnceLock::new();
    TABLES.get_or_init(gen)
}

/// Tiger or Tiger2 in progress.
#[derive(Clone)]
pub struct Tiger {
    state: [u64; 3],
    buffer: BlockBuffer<64>,
    length: u64,
    passes: usize,
    digest_len: usize,
    /// The first padding byte: 0x01 for Tiger, 0x80 for Tiger2.
    pad: u8,
}

impl Tiger {
    /// Tiger with `bits` of output (128, 160 or 192) after `passes`
    /// passes (three or more).
    ///
    /// # Errors
    /// Any other length, or fewer than three passes.
    pub fn new(bits: usize, passes: usize) -> Result<Tiger, String> {
        Tiger::make(bits, passes, 0x01)
    }

    /// Tiger2: Tiger with MD5's padding byte, at 192 bits and three passes.
    pub fn tiger2() -> Tiger {
        Tiger::make(192, 3, 0x80).expect("192 bits, three passes")
    }

    fn make(bits: usize, passes: usize, pad: u8) -> Result<Tiger, String> {
        if ![128, 160, 192].contains(&bits) || passes < 3 {
            return Err(format!("Tiger gives 128, 160 or 192 bits after three or more passes, \
                                not {bits} bits after {passes}."));
        }
        Ok(Tiger { state: [A0, B0, C0], buffer: BlockBuffer::default(), length: 0, passes,
                   digest_len: bits / 8, pad })
    }
}

impl HashFunction for Tiger {
    fn name(&self) -> String {
        match (self.pad, self.digest_len, self.passes) {
            (0x80, _, _) => "tiger2".to_string(),
            (_, 24, 3) => "tiger".to_string(),
            (_, len, passes) => format!("tiger{}_{}", len * 8, passes),
        }
    }

    fn digest_len(&self) -> usize {
        self.digest_len
    }

    fn block_size(&self) -> usize {
        64
    }

    fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        let (state, passes) = (&mut self.state, self.passes);
        let t = sboxes();
        self.buffer.feed(input, |block| compress(t, state, block, passes));
    }

    fn digest(&mut self) -> Vec<u8> {
        // On a copy, so this is repeatable and `update` may continue.
        let mut last = self.clone();
        let bits = last.length.wrapping_mul(8);
        let pad = 1 + (119 - last.buffer.len()) % 64;
        let mut tail = vec![0u8; pad];
        tail[0] = last.pad;
        tail.extend_from_slice(&bits.to_le_bytes());
        let (state, passes) = (&mut last.state, last.passes);
        let t = sboxes();
        last.buffer.feed(&tail, |block| compress(t, state, block, passes));
        debug_assert!(last.buffer.is_empty());
        let mut out: Vec<u8> = last.state.iter().flat_map(|w| w.to_le_bytes()).collect();
        out.truncate(self.digest_len);
        out
    }
}
