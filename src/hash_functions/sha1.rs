use super::buffer::BlockBuffer;
use super::HashFunction;


#[derive(Clone)]
pub struct SHA1 {
    state: [u32; 5],
    buffer: BlockBuffer<64>,
    len: usize,
    is_sha0: bool,
}

impl SHA1 {
    pub fn new(data: &[u8]) -> SHA1 {
        let mut sha = SHA1 {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buffer: BlockBuffer::default(),
            len: 0,
            is_sha0: false,
        };
        sha.update(data);
        sha
    }
    pub fn set_to_sha0(&mut self) {
        self.is_sha0 = true;
    }
    fn process_block(&self, state: &[u32; 5], block: &[u8]) -> (u32, u32, u32, u32, u32) {
        // `digest` hands over its padded tail, which may hold two blocks;
        // this is the first.
        let mut out = *state;
        compress_run(&mut out, &block[..64], self.is_sha0);
        (out[0], out[1], out[2], out[3], out[4])
    }
}

/// A run of whole 64-byte blocks. SHA-1 goes to the SHA extensions when
/// the build has `sha-ni` and the processor has them; SHA-0 never does,
/// because its schedule has no rotation and the extensions' has one.
fn compress_run(state: &mut [u32; 5], run: &[u8], sha0: bool) {
    #[cfg(all(feature = "sha-ni", target_arch = "x86_64"))]
    if !sha0 && super::sha_ni::sha1(state, run) {
        return;
    }
    for block in run.chunks_exact(64) {
        let block: &[u8; 64] = block.try_into().expect("chunks_exact yields 64 bytes");
        if sha0 {
            compress::<true>(state, block);
        } else {
            compress::<false>(state, block);
        }
    }
}

/// One SHA-1 (or SHA-0) block. The two differ only in the message
/// schedule's one-bit rotation, which SHA-1 added; as a const parameter
/// it is decided at compile time rather than once per schedule word.
///
/// The schedule is kept as a rolling window of sixteen words, `w[i & 15]`
/// holding `W[i]`, computed in the round that needs it: `W[i-3]`,
/// `W[i-8]`, `W[i-14]` and `W[i-16]` are `w[(i+13) & 15]`,
/// `w[(i+8) & 15]`, `w[(i+2) & 15]` and `w[i & 15]`. The four groups of
/// twenty rounds are four loops, so each has its function and constant
/// fixed rather than chosen per round.
#[inline(always)]
pub(crate) fn compress<const SHA0: bool>(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 16];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2],
                                    block[4 * i + 3]]);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;

    macro_rules! round {
        ($i:expr, $f:expr, $k:expr) => {{
            let i: usize = $i;
            let wi = if i < 16 {
                w[i]
            } else {
                let x = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15];
                let x = if SHA0 { x } else { x.rotate_left(1) };
                w[i & 15] = x;
                x
            };
            let t = a.rotate_left(5).wrapping_add($f).wrapping_add(e)
                .wrapping_add($k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }};
    }
    // Ch, written with one fewer operation: (b & c) | (!b & d).
    for i in 0..20 {
        round!(i, d ^ (b & (c ^ d)), 0x5A82_7999);
    }
    for i in 20..40 {
        round!(i, b ^ c ^ d, 0x6ED9_EBA1);
    }
    // Maj: (b & c) | (b & d) | (c & d).
    for i in 40..60 {
        round!(i, (b & c) | (d & (b | c)), 0x8F1B_BCDC);
    }
    for i in 60..80 {
        round!(i, b ^ c ^ d, 0xCA62_C1D6);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

impl HashFunction for SHA1 {
    fn block_size(&self) -> usize { 64 }
    fn name(&self) -> String {
        if self.is_sha0 {
            return "SHA0".to_string();
        }
        "SHA1".to_string()
    }
    fn digest_len(&self) -> usize {
        20
    }
    fn digest(&mut self) -> Vec<u8> {
        let blocksize = 64;
        let mut state = self.state;
        let mut unprocessed_data = self.buffer.buffered().to_vec();
        unprocessed_data.push(0x80);
        unprocessed_data.extend_from_slice(&vec![0; (blocksize + (blocksize-8) - unprocessed_data.len()) % blocksize]);
        unprocessed_data.extend_from_slice(&(self.len as u64).to_be_bytes());
        (state[0], state[1], state[2], state[3], state[4]) = 
            self.process_block(&self.state, &unprocessed_data);
        if unprocessed_data.len() > blocksize {
            (state[0], state[1], state[2], state[3], state[4])  = 
                self.process_block(&state, &unprocessed_data[blocksize..(blocksize*2)]);
        }
        let mut result = vec![];
        result.extend_from_slice(&state[0].to_be_bytes());
        result.extend_from_slice(&state[1].to_be_bytes());
        result.extend_from_slice(&state[2].to_be_bytes());
        result.extend_from_slice(&state[3].to_be_bytes());
        result.extend_from_slice(&state[4].to_be_bytes());
        result
    }
    fn update(&mut self, input: &[u8]) {
        self.len += input.len() * 8;
        // The buffer is moved out for the call so the closure can borrow
        // the rest of `self`.
        let mut buffer = core::mem::take(&mut self.buffer);
        let sha0 = self.is_sha0;
        buffer.feed_blocks(input, |run| compress_run(&mut self.state, run, sha0));
        self.buffer = buffer;
    }
}