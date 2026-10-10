use std::ops::Shr;
use super::buffer::BlockBuffer;
use super::HashFunction;

#[derive(Clone)]
pub struct SHA224 {
    state: [u32; 8],
    buffer: BlockBuffer<64>,
    /// The message length **in bits**, as the padding carries it. A
    /// `u64` on every target: a `usize` wraps at 2^32 bits (512 MiB) on
    /// a 32-bit one, which is a wrong digest with no error.
    len: u64,
}
#[derive(Clone)]
pub struct SHA256 {
    state: [u32; 8],
    buffer: BlockBuffer<64>,
    /// The message length **in bits**, as the padding carries it. A
    /// `u64` on every target: a `usize` wraps at 2^32 bits (512 MiB) on
    /// a 32-bit one, which is a wrong digest with no error.
    len: u64,
}
#[derive(Clone)]
pub struct SHA384 {
    state: [u64; 8],
    buffer: BlockBuffer<128>,
    /// The message length **in bits**, in the 128 bit width the
    /// padding carries. A `usize` wraps at 2^32 bits (512 MiB) on a
    /// 32-bit target, which is a wrong digest with no error.
    len: u128,
}
#[derive(Clone)]
pub struct SHA512 {
    state: [u64; 8],
    output_bits: usize,
    buffer: BlockBuffer<128>,
    /// The message length **in bits**, in the 128 bit width the
    /// padding carries. A `usize` wraps at 2^32 bits (512 MiB) on a
    /// 32-bit target, which is a wrong digest with no error.
    len: u128,
}

pub(crate) const K_32: [u32; 64] = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

const K_64: [u64; 80] = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];

impl SHA224 {
    pub fn new(data: &[u8]) -> SHA224 {
        let mut sha = SHA224 {
            state: [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 
                    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
            buffer: BlockBuffer::default(),
            len: 0,
        };
        sha.update(data);
        sha
    }
}

impl SHA256 {
    pub fn new(data: &[u8]) -> SHA256 {
        let mut sha = SHA256 {
            state: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            buffer: BlockBuffer::default(),
            len: 0,
        };
        sha.update(data);
        sha
    }
}

impl SHA384 {
    pub fn new(data: &[u8]) -> SHA384 {
        let mut sha = SHA384 {
            state: [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4],
            buffer: BlockBuffer::default(),
            len: 0,
        };
        sha.update(data);
        sha
    }
}

impl SHA512 {
    /// SHA-512 (`output_bits = 512`) or SHA-512/t (FIPS 180-4 section
    /// 5.3.6) for any other `output_bits`.
    ///
    /// # Panics
    /// An `output_bits` `try_new` refuses. Every in-tree caller passes
    /// 224, 256 or 512; a length from outside goes through `try_new`.
    pub fn new(data: &[u8], output_bits: usize) -> SHA512 {
        match SHA512::try_new(data, output_bits) {
            Ok(sha) => sha,
            Err(reason) => panic!("{reason}"),
        }
    }

    /// `new`, with the output length checked: a whole number of bytes,
    /// at most 512 bits, and not 384 - FIPS 180-4 excludes t = 384 so
    /// that no "SHA-512/384" can be mistaken for SHA-384, which has
    /// its own initial values. Past 512 the digest used to slice past
    /// the eight state words and panic.
    pub fn try_new(data: &[u8], output_bits: usize) -> Result<SHA512, String> {
        if output_bits == 0 || output_bits > 512 || !output_bits.is_multiple_of(8) {
            return Err(format!(
                "SHA-512/t produces a whole number of bytes up to 512 bits; {} bits is \
                 not one.", output_bits));
        }
        if output_bits == 384 {
            return Err("SHA-512/384 is not defined (FIPS 180-4 section 5.3.6); SHA-384 \
                        is a separate function with its own initial values.".to_string());
        }
        let mut sha = SHA512 {
            state: [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179],
            output_bits,
            buffer: BlockBuffer::default(),
            len: 0,
        };
        if output_bits != 512 {
            let mut sha_inner = SHA512 {
                state: [0x6a09e667f3bcc908^0xa5a5a5a5a5a5a5a5, 0xbb67ae8584caa73b^0xa5a5a5a5a5a5a5a5,
                        0x3c6ef372fe94f82b^0xa5a5a5a5a5a5a5a5, 0xa54ff53a5f1d36f1^0xa5a5a5a5a5a5a5a5, 
                        0x510e527fade682d1^0xa5a5a5a5a5a5a5a5, 0x9b05688c2b3e6c1f^0xa5a5a5a5a5a5a5a5,
                        0x1f83d9abfb41bd6b^0xa5a5a5a5a5a5a5a5, 0x5be0cd19137e2179^0xa5a5a5a5a5a5a5a5],
                output_bits: 512,
                buffer: BlockBuffer::default(),
                len: 0,
            };
            sha_inner.update(format!("SHA-512/{}", output_bits).as_bytes());
            let result = sha_inner.digest();
            for i in 0..8 {
                sha.state[i] = u64::from_be_bytes(result[(i*8)..(i*8+8)].try_into().unwrap());
            }
        }
        sha.update(data);
        Ok(sha)
    }
}


fn process_block_32(state: &[u32; 8], block: &[u8]) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    // `digest` hands over its padded tail, which may hold two blocks;
    // this is the first.
    let mut out = *state;
    compress_256_run(&mut out, &block[..64]);
    (out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7])
}

/// A run of whole 64-byte blocks: on the SHA extensions when the build
/// has `sha-ni` and the processor has them, block by block otherwise.
fn compress_256_run(state: &mut [u32; 8], run: &[u8]) {
    #[cfg(all(feature = "sha-ni", target_arch = "x86_64"))]
    if super::sha_ni::sha256(state, run) {
        return;
    }
    for block in run.chunks_exact(64) {
        compress_256(state, block.try_into().expect("chunks_exact yields 64 bytes"));
    }
}

/// One SHA-224/256 block.
///
/// The schedule is a rolling window of sixteen words computed in the
/// round that needs it - `W[i-2]`, `W[i-7]`, `W[i-15]` and `W[i-16]` are
/// `w[(i+14) & 15]`, `w[(i+9) & 15]`, `w[(i+1) & 15]` and `w[i & 15]` -
/// so the 64-word array and its separate pass are gone. The rounds are
/// unrolled by eight with the working variables renamed rather than
/// moved: round `i` updates only `d` and `h`, and the next round reads
/// the same eight names one place along. Ch and Maj are written with one
/// fewer operation each: `g ^ (e & (f ^ g))` and `(a & b) | (c & (a | b))`.
#[inline(always)]
pub(crate) fn compress_256(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 16];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2],
                                    block[4 * i + 3]]);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    #[inline(always)]
    fn schedule(w: &mut [u32; 16], i: usize) -> u32 {
        if i < 16 {
            return w[i];
        }
        let w15 = w[(i + 1) & 15];
        let w2 = w[(i + 14) & 15];
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        let x = w[i & 15].wrapping_add(s0).wrapping_add(w[(i + 9) & 15]).wrapping_add(s1);
        w[i & 15] = x;
        x
    }

    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident,
         $i:expr) => {{
            let i: usize = $i;
            let t1 = $h
                .wrapping_add($e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25))
                .wrapping_add($g ^ ($e & ($f ^ $g)))
                .wrapping_add(K_32[i])
                .wrapping_add(schedule(&mut w, i));
            $d = $d.wrapping_add(t1);
            $h = t1
                .wrapping_add($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22))
                .wrapping_add(($a & $b) | ($c & ($a | $b)));
        }};
    }

    for i in (0..64).step_by(8) {
        round!(a, b, c, d, e, f, g, h, i);
        round!(h, a, b, c, d, e, f, g, i + 1);
        round!(g, h, a, b, c, d, e, f, i + 2);
        round!(f, g, h, a, b, c, d, e, i + 3);
        round!(e, f, g, h, a, b, c, d, i + 4);
        round!(d, e, f, g, h, a, b, c, i + 5);
        round!(c, d, e, f, g, h, a, b, i + 6);
        round!(b, c, d, e, f, g, h, a, i + 7);
    }

    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}

fn process_block_64(state: &[u64; 8], block: &[u8]) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let mut w: [u64; 80] = [0; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i*8..(i*8+8)].try_into().unwrap());
    }
    for i in 16..80 {
        let s0: u64 = w[i-15].rotate_right(1) ^ w[i-15].rotate_right(8) ^ w[i-15].shr(7);
        let s1: u64 = w[i-2].rotate_right(19) ^ w[i-2].rotate_right(61) ^ w[i-2].shr(6);
        w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = 
    (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);

    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((! e) & g);
        let temp1= h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K_64[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
 
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    a = a.wrapping_add(state[0]);
    b = b.wrapping_add(state[1]);
    c = c.wrapping_add(state[2]);
    d = d.wrapping_add(state[3]);
    e = e.wrapping_add(state[4]);
    f = f.wrapping_add(state[5]);
    g = g.wrapping_add(state[6]);
    h = h.wrapping_add(state[7]);
    (a, b, c, d, e, f, g, h)
}

impl HashFunction for SHA224 {
    fn block_size(&self) -> usize { 64 }
    fn name(&self) -> String {
        "SHA224".to_string()
    }
    fn digest_len(&self) -> usize {
        28
    }
    fn digest(&mut self) -> Vec<u8> {
        let blocksize = 64;
        let mut state = self.state;
        let mut unprocessed_data = self.buffer.buffered().to_vec();
        unprocessed_data.push(0x80);
        unprocessed_data.extend_from_slice(&vec![0; (blocksize + (blocksize-8) - unprocessed_data.len()) % blocksize]);
        unprocessed_data.extend_from_slice(&self.len.to_be_bytes());
        (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]) = 
            process_block_32(&self.state, &unprocessed_data);
        if unprocessed_data.len() > blocksize {
            (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7])  = 
                process_block_32(&state, &unprocessed_data[blocksize..(blocksize*2)]);
        }
        let mut result = vec![];
        result.extend_from_slice(&state[0].to_be_bytes());
        result.extend_from_slice(&state[1].to_be_bytes());
        result.extend_from_slice(&state[2].to_be_bytes());
        result.extend_from_slice(&state[3].to_be_bytes());
        result.extend_from_slice(&state[4].to_be_bytes());
        result.extend_from_slice(&state[5].to_be_bytes());
        result.extend_from_slice(&state[6].to_be_bytes());
        result
    }
    fn update(&mut self, input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u64 * 8);
        // The buffer is moved out for the call so the closure can borrow
        // the rest of `self`.
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.feed_blocks(input, |run| compress_256_run(&mut self.state, run));
        self.buffer = buffer;
    }
}

impl HashFunction for SHA256 {
    fn block_size(&self) -> usize { 64 }
    fn name(&self) -> String {
        "SHA256".to_string()
    }
    fn digest_len(&self) -> usize {
        32
    }
    fn digest(&mut self) -> Vec<u8> {
        let blocksize = 64;
        let mut state = self.state;
        let mut unprocessed_data = self.buffer.buffered().to_vec();
        unprocessed_data.push(0x80);
        unprocessed_data.extend_from_slice(&vec![0; (blocksize + (blocksize-8) - unprocessed_data.len()) % blocksize]);
        unprocessed_data.extend_from_slice(&self.len.to_be_bytes());
        (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]) = 
            process_block_32(&self.state, &unprocessed_data);
        if unprocessed_data.len() > blocksize {
            (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7])  = 
                process_block_32(&state, &unprocessed_data[blocksize..(blocksize*2)]);
        }
        let mut result = vec![];
        result.extend_from_slice(&state[0].to_be_bytes());
        result.extend_from_slice(&state[1].to_be_bytes());
        result.extend_from_slice(&state[2].to_be_bytes());
        result.extend_from_slice(&state[3].to_be_bytes());
        result.extend_from_slice(&state[4].to_be_bytes());
        result.extend_from_slice(&state[5].to_be_bytes());
        result.extend_from_slice(&state[6].to_be_bytes());
        result.extend_from_slice(&state[7].to_be_bytes());
        result
    }
    fn update(&mut self, input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u64 * 8);
        // The buffer is moved out for the call so the closure can borrow
        // the rest of `self`.
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.feed_blocks(input, |run| compress_256_run(&mut self.state, run));
        self.buffer = buffer;
    }
}

impl HashFunction for SHA384 {
    fn block_size(&self) -> usize { 128 }
    fn name(&self) -> String {
        "SHA384".to_string()
    }
    fn digest(&mut self) -> Vec<u8> {
        let blocksize = 128;
        let mut state = self.state;
        let mut unprocessed_data = self.buffer.buffered().to_vec();
        unprocessed_data.push(0x80);
        unprocessed_data.extend_from_slice(&vec![0; (blocksize + (blocksize-16) - unprocessed_data.len()) % blocksize]);
        unprocessed_data.extend_from_slice(&self.len.to_be_bytes());
        (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]) = 
            process_block_64(&self.state, &unprocessed_data);
        if unprocessed_data.len() > blocksize {
            (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7])  = 
                process_block_64(&state, &unprocessed_data[blocksize..(blocksize*2)]);
        }
        let mut result = vec![];
        result.extend_from_slice(&state[0].to_be_bytes());
        result.extend_from_slice(&state[1].to_be_bytes());
        result.extend_from_slice(&state[2].to_be_bytes());
        result.extend_from_slice(&state[3].to_be_bytes());
        result.extend_from_slice(&state[4].to_be_bytes());
        result.extend_from_slice(&state[5].to_be_bytes());
        result
    }
    fn digest_len(&self) -> usize {
        48
    }
    fn update(&mut self, input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u128 * 8);
        // The buffer is moved out for the call so the closure can borrow
        // the rest of `self`.
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.feed(input, |block: &[u8; 128]| {
            let block = &block[..];
            let (a, b, c, d, e, f, g, h) = 
                process_block_64(&self.state, block);
            self.state[0] = a;
            self.state[1] = b;
            self.state[2] = c;
            self.state[3] = d;
            self.state[4] = e;
            self.state[5] = f;
            self.state[6] = g;
            self.state[7] = h;
        });
        self.buffer = buffer;
    }
}

impl HashFunction for SHA512 {
    fn block_size(&self) -> usize { 128 }
    fn name(&self) -> String {
        if self.output_bits != 512 {
            return format!("SHA512/{}", self.output_bits);
        }
        "SHA512".to_string()
    }
    fn digest(&mut self) -> Vec<u8> {
        let blocksize = 128;
        let mut state = self.state;
        let mut unprocessed_data = self.buffer.buffered().to_vec();
        unprocessed_data.push(0x80);
        unprocessed_data.extend_from_slice(&vec![0; (blocksize + (blocksize-16) - unprocessed_data.len()) % blocksize]);
        unprocessed_data.extend_from_slice(&self.len.to_be_bytes());
        (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]) = 
            process_block_64(&self.state, &unprocessed_data);
        if unprocessed_data.len() > blocksize {
            (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7])  = 
                process_block_64(&state, &unprocessed_data[blocksize..(blocksize*2)]);
        }
        let mut result = vec![];
        result.extend_from_slice(&state[0].to_be_bytes());
        result.extend_from_slice(&state[1].to_be_bytes());
        result.extend_from_slice(&state[2].to_be_bytes());
        result.extend_from_slice(&state[3].to_be_bytes());
        result.extend_from_slice(&state[4].to_be_bytes());
        result.extend_from_slice(&state[5].to_be_bytes());
        result.extend_from_slice(&state[6].to_be_bytes());
        result.extend_from_slice(&state[7].to_be_bytes());
        result[0..self.digest_len()].to_vec()
    }
    fn digest_len(&self) -> usize {
        self.output_bits.div_ceil(8)
    }
    fn update(&mut self, input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u128 * 8);
        // The buffer is moved out for the call so the closure can borrow
        // the rest of `self`.
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.feed(input, |block: &[u8; 128]| {
            let block = &block[..];
            let (a, b, c, d, e, f, g, h) = 
                process_block_64(&self.state, 
                    block);
            self.state[0] = a;
            self.state[1] = b;
            self.state[2] = c;
            self.state[3] = d;
            self.state[4] = e;
            self.state[5] = f;
            self.state[6] = g;
            self.state[7] = h;
        });
        self.buffer = buffer;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit counters were `usize`, so on a 32-bit target they
    /// wrapped at 2^32 bits (512 MiB) and the `+=` overflowed in a
    /// debug build: a wrong digest with no error past that length. No
    /// test ran on such a target, and on a 64-bit one `usize` and `u64`
    /// agree for any message that fits in memory. The check is on the
    /// types themselves: 64 bits for the 32-bit-word hashes, and the
    /// full 128 bit width of the padding field for SHA-384/512.
    #[test]
    fn test_the_bit_counters_are_as_wide_as_the_length_field() {
        let mut sha224 = SHA224::new(&[0u8; 100]);
        let mut sha256 = SHA256::new(&[0u8; 100]);
        let mut sha384 = SHA384::new(&[0u8; 100]);
        let mut sha512 = SHA512::new(&[0u8; 100], 512);
        let narrow: [u64; 2] = [sha224.len, sha256.len];
        let wide: [u128; 2] = [sha384.len, sha512.len];
        assert_eq!(narrow, [800, 800]);
        assert_eq!(wide, [800, 800]);
        // And the counter is what the padding carries: the same bytes
        // in two pieces give the same digest as one call.
        for (whole, pieces) in [
            (sha224.digest(), { let mut h = SHA224::new(&[0u8; 37]); h.update(&[0u8; 63]); h.digest() }),
            (sha256.digest(), { let mut h = SHA256::new(&[0u8; 37]); h.update(&[0u8; 63]); h.digest() }),
            (sha384.digest(), { let mut h = SHA384::new(&[0u8; 37]); h.update(&[0u8; 63]); h.digest() }),
            (sha512.digest(), { let mut h = SHA512::new(&[0u8; 37], 512); h.update(&[0u8; 63]); h.digest() }),
        ] {
            assert_eq!(whole, pieces);
        }
        // `digest` is non-destructive, so the counters are unchanged.
        let still: [u64; 2] = [sha224.len, sha256.len];
        assert_eq!(still, [800, 800]);
        let _ = (&mut sha384, &mut sha512);
    }

    /// `SHA512::new(data, t)` accepted any `t`: past 512 the digest
    /// sliced `result[..t / 8]` beyond the 64 bytes of state and
    /// panicked with an index error, and `t = 384` gave a "SHA-512/384"
    /// FIPS 180-4 does not define, which is not SHA-384. Every caller
    /// in the tree passes 224, 256 or 512, so no test reached either.
    #[test]
    fn test_an_output_length_sha512_t_does_not_define_is_refused() {
        let reason = |bits| SHA512::try_new(&[], bits).err().expect("refused");
        assert!(reason(1024).contains("512 bits"));
        assert!(reason(520).contains("512 bits"));
        assert!(reason(0).contains("512 bits"));
        assert!(reason(12).contains("whole number of bytes"));
        assert!(reason(384).contains("SHA-384"));
        // The defined ones, including SHA-512 itself and a t FIPS
        // allows but nobody standardised a name for.
        for t in [8usize, 224, 256, 504, 512] {
            assert_eq!(SHA512::try_new(b"abc", t).unwrap().digest().len(), t / 8);
        }
        assert_eq!(SHA512::try_new(b"abc", 256).unwrap().digest(),
                   SHA512::new(b"abc", 256).digest());
    }
}
