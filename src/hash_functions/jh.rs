/*!
JH (Hongjun Wu, 2008), the SHA-3 finalist, as finally submitted: 42
rounds, JH-224, -256, -384 and -512 on one 1024 bit state.

The compression function XORs a 512 bit block into the first half of the
state, runs the permutation E8, and XORs the same block into the second
half. E8 is 42 rounds of 4 bit S-boxes, chosen bit by bit by a round
constant, a linear map on pairs of them, and a permutation; this is the
bitsliced form the designer gave, where the state is sixteen 64 bit
words in two groups, each round is a sequence of logical operations on
eight of them (`sbox`, `linear`), and the permutation becomes swapping
bit groups of 1, 2, 4 ... 32 bits within half the words in turn, and
every seventh round the halves of four words. The 42 round constants are
`jh_tables.rs`, read by `scripts/make_jh_tables.py` out of sphlib and
the JH code SUPERCOP carries, which agree on every byte.

The starting value is the compression of an all-zero block into a state
whose first two bytes are the output length in bits, big endian. The
padding is a 1 bit, zeros, and the length in bits as 128 bits, big
endian, ending a block - and it is always at least a block: a message
that ends a block gets one of padding alone, and one that does not gets
its last block closed with the 1 bit and then another. The output is the
state's last bytes.

Names: `jh224`, `jh256`, `jh384`, `jh512`.
*/

use super::buffer::BlockBuffer;
use super::jh_tables::C;
use super::HashFunction;

/// Swaps neighbouring groups of `bits` bits in `x`; at 32, its halves.
fn swap(x: u64, bits: u32) -> u64 {
    let mask = match bits {
        1 => 0x5555_5555_5555_5555,
        2 => 0x3333_3333_3333_3333,
        4 => 0x0f0f_0f0f_0f0f_0f0f,
        8 => 0x00ff_00ff_00ff_00ff,
        16 => 0x0000_ffff_0000_ffff,
        _ => return x.rotate_left(32),
    };
    ((x & mask) << bits) | ((x >> bits) & mask)
}

/// The two S-boxes on four bitsliced nibbles at once - `m[0..4]` and
/// `m[4..8]` - each choosing S0 or S1 bit by bit by its constant.
fn sbox(m: &mut [u64; 8], c0: u64, c1: u64) {
    for (h, c) in [(0, c0), (4, c1)] {
        let [mut a, mut b, mut c2, mut d] = [m[h], m[h + 1], m[h + 2], m[h + 3]];
        // The designer's sequence, with m0 .. m3 as a, b, c2, d.
        a ^= !c2 & c;
        let t = c ^ (a & b);
        a ^= c2 & !d;
        d ^= b | !c2;
        b ^= a & c2;
        c2 ^= a & !d;
        a ^= b | d;
        d ^= b & c2;
        b ^= t & a;
        c2 ^= t;
        [m[h], m[h + 1], m[h + 2], m[h + 3]] = [a, b, c2, d];
    }
}

/// The linear map, on the two groups of four.
fn linear(m: &mut [u64; 8]) {
    m[4] ^= m[1];
    m[5] ^= m[2];
    m[6] ^= m[0] ^ m[3];
    m[7] ^= m[0];
    m[0] ^= m[5];
    m[1] ^= m[6];
    m[2] ^= m[4] ^ m[7];
    m[3] ^= m[4];
}

/// The compression function on the state `x[word][group]`.
fn compress(x: &mut [[u64; 2]; 8], block: &[u8; 64]) {
    let w: [u64; 8] = core::array::from_fn(|i| {
        u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().expect("8 bytes"))
    });
    for i in 0..4 {
        x[i][0] ^= w[2 * i];
        x[i][1] ^= w[2 * i + 1];
    }
    for r in (0..42).step_by(7) {
        for g in 0..2 {
            // The eight words a group's S-boxes take, in the designer's
            // order: x0, x2, x4, x6, x1, x3, x5, x7.
            let mut m = [x[0][g], x[2][g], x[4][g], x[6][g], x[1][g], x[3][g], x[5][g], x[7][g]];
            for (k, bits) in [1, 2, 4, 8, 16, 32, 0].into_iter().enumerate() {
                sbox(&mut m, C[r + k][g], C[r + k][g + 2]);
                linear(&mut m);
                if bits != 0 {
                    for word in &mut m[4..] {
                        *word = swap(*word, bits);
                    }
                }
            }
            [x[0][g], x[2][g], x[4][g], x[6][g], x[1][g], x[3][g], x[5][g], x[7][g]] = m;
        }
        for i in [1, 3, 5, 7] {
            x[i].swap(0, 1);
        }
    }
    for i in 0..4 {
        x[4 + i][0] ^= w[2 * i];
        x[4 + i][1] ^= w[2 * i + 1];
    }
}

/// JH in progress.
#[derive(Clone)]
pub struct Jh {
    state: [[u64; 2]; 8],
    buffer: BlockBuffer<64>,
    length: u128,
    digest_len: usize,
}

impl Jh {
    /// JH with `bits` of output: 224, 256, 384 or 512.
    ///
    /// # Errors
    /// Any other length.
    pub fn new(bits: usize) -> Result<Jh, String> {
        if ![224, 256, 384, 512].contains(&bits) {
            return Err(format!("JH gives 224, 256, 384 or 512 bits, not {bits}."));
        }
        let mut state = [[0u64; 2]; 8];
        state[0][0] = u64::from(u16::try_from(bits).expect("checked").swap_bytes());
        compress(&mut state, &[0; 64]);
        Ok(Jh { state, buffer: BlockBuffer::default(), length: 0, digest_len: bits / 8 })
    }
}

impl HashFunction for Jh {
    fn name(&self) -> String {
        format!("jh{}", 8 * self.digest_len)
    }

    fn digest_len(&self) -> usize {
        self.digest_len
    }

    fn block_size(&self) -> usize {
        64
    }

    fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u128);
        let state = &mut self.state;
        self.buffer.feed(input, |block| compress(state, block));
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut last = self.clone();
        // The 1 bit closes the message's last block, or opens a block of
        // its own if there is none to close; either way the length ends a
        // block that starts after the message's.
        let waiting = last.buffer.len();
        let mut tail = vec![0u8; if waiting > 0 { 128 - waiting } else { 64 }];
        tail[0] = 0x80;
        let end = tail.len() - 16;
        tail[end..].copy_from_slice(&last.length.wrapping_mul(8).to_be_bytes());
        let state = &mut last.state;
        last.buffer.feed(&tail, |block| compress(state, block));
        debug_assert!(last.buffer.is_empty());
        let bytes: Vec<u8> =
            last.state.iter().flat_map(|w| w.iter().flat_map(|v| v.to_le_bytes())).collect();
        bytes[128 - self.digest_len..].to_vec()
    }
}
