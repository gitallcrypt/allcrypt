use super::buffer::BlockBuffer;
use super::HashFunction;


#[derive(Clone)]
pub struct SHA1 {
    state: [u32; 5],
    buffer: BlockBuffer<64>,
    /// The message length **in bits**, as the padding carries it. A
    /// `u64` on every target: a `usize` wraps at 2^32 bits (512 MiB) on
    /// a 32-bit one, which is a wrong digest with no error.
    len: u64,
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
    /// SHA-0: FIPS 180's original schedule, without the one bit rotate
    /// FIPS 180-1 added. Everything else is SHA-1.
    pub fn sha0(data: &[u8]) -> SHA1 {
        let mut sha = SHA1::new(&[]);
        sha.set_to_sha0();
        sha.update(data);
        sha
    }

    /// Switch a fresh hash to SHA-0's schedule. `sha0` is the usual way
    /// to get one.
    ///
    /// # Panics
    /// After data has been fed: a block already compressed under
    /// SHA-1's schedule cannot be re-done under SHA-0's, so the result
    /// would be a value that is neither hash. `SHA1::new(&[0; 64])`
    /// then `set_to_sha0()` used to give exactly that, silently.
    pub fn set_to_sha0(&mut self) {
        assert!(self.len == 0,
                "set_to_sha0 after {} bits were fed; use SHA1::sha0 or call it first",
                self.len);
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
            return "sha0".to_string();
        }
        "sha1".to_string()
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
        unprocessed_data.extend_from_slice(&self.len.to_be_bytes());
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
        self.len = self.len.wrapping_add(input.len() as u64 * 8);
        // The buffer is moved out for the call so the closure can borrow
        // the rest of `self`.
        let mut buffer = core::mem::take(&mut self.buffer);
        let sha0 = self.is_sha0;
        buffer.feed_blocks(input, |run| compress_run(&mut self.state, run, sha0));
        self.buffer = buffer;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `set_to_sha0` after a block had been compressed under SHA-1's
    /// schedule switched the schedule for the rest, giving a value no
    /// implementation produces. `hash_all` and the tests always called
    /// it on an empty hash, so nothing reached the mixed case.
    #[test]
    fn test_sha0_cannot_be_selected_after_a_block_was_compressed() {
        let whole = SHA1::sha0(&[0u8; 64]).digest();
        let mut fresh = SHA1::new(&[]);
        fresh.set_to_sha0();
        fresh.update(&[0u8; 64]);
        assert_eq!(fresh.digest(), whole);
        assert_ne!(SHA1::new(&[0u8; 64]).digest(), whole);
        let mixed = std::panic::catch_unwind(|| {
            let mut hash = SHA1::new(&[0u8; 64]);
            hash.set_to_sha0();
            hash.digest()
        });
        assert!(mixed.is_err(), "a hash that is neither SHA-0 nor SHA-1 was produced");
    }

    /// The bit counter was a `usize`, so on a 32-bit target it wrapped
    /// at 2^32 bits (512 MiB) and the `+=` overflowed in a debug build:
    /// a wrong digest with no error past that length. No test ran on
    /// such a target, and on a 64-bit one the two types agree for any
    /// message that fits in memory. The check is on the type itself.
    #[test]
    fn test_the_bit_counter_is_64_bits_wide() {
        let mut hash = SHA1::new(&[]);
        hash.update(&[0u8; 100]);
        let bits: u64 = hash.len;
        assert_eq!(bits, 800);
        let mut pieces = SHA1::new(&[0u8; 37]);
        pieces.update(&[0u8; 63]);
        assert_eq!(pieces.digest(), hash.digest());
    }
}
