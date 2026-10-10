use super::buffer::BlockBuffer;
use super::HashFunction;


#[derive(Clone)]
pub struct MD5 {
    state: [u32; 4],
    buffer: BlockBuffer<64>,
    /// The message length **in bits**, as the padding carries it. A
    /// `u64` on every target: a `usize` wraps at 2^32 bits (512 MiB) on
    /// a 32-bit one, which is a wrong digest with no error.
    len: u64,
}

const A: u32 = 0x67452301;
const B: u32 = 0xefcdab89;
const C: u32 = 0x98badcfe;
const D: u32 = 0x10325476;

const S: [u32; 64] = [ 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                         5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                         4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                         6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21];
const K: [u32; 64] = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                      0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                      0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                      0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                      0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                      0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                      0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                      0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                      0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                      0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                      0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                      0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                      0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                      0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                      0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                      0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];

impl MD5 {
    pub fn new(data: &[u8]) -> MD5 {
        let mut md5 = MD5 {
            state: [A, B, C, D],
            buffer: BlockBuffer::default(),
            len: 0,
        };
        md5.update(data);
        md5
    }
    fn process_block(&self, block: &[u8]) -> (u32, u32, u32, u32) {
        let mut m: [u32; 16] = [0; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes(block[i*4..(i*4+4)].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (self.state[0], self.state[1], self.state[2], self.state[3]);
        for i in 0..64 {
            let mut f = 0;
            let mut g = 0;
            match i {
                0..=15 => {f = (b & c) | ((!b) & d);
                           g = i;},
                16..=31 => {f = (d & b) | ((! d) & c);
                            g = (5*i + 1) % 16;}, 
                32..=47 => {f = b ^ c ^ d;
                            g = (3*i + 5) % 16;},
                48..=63 => {f = c ^ (b | (! d));
                            g = (7 * i) % 16;},
                _ => {},
            }
            f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a = a.wrapping_add(self.state[0]);
        b = b.wrapping_add(self.state[1]);
        c = c.wrapping_add(self.state[2]);
        d = d.wrapping_add(self.state[3]);

        (a, b, c, d)
    }
}

impl HashFunction for MD5 {
    fn block_size(&self) -> usize { 64 }
    fn name(&self) -> String {
        "md5".to_string()
    }
    fn digest_len(&self) -> usize {
        16
    }
    fn update(&mut self, input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u64 * 8);
        // The buffer is moved out for the call so the closure can borrow
        // the rest of `self`.
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.feed(input, |block: &[u8; 64]| {
            let block = &block[..];
            let (a, b, c, d) = self.process_block(block);
            self.state[0] = a;
            self.state[1] = b;
            self.state[2] = c;
            self.state[3] = d;
        });
        self.buffer = buffer;
    }
    fn digest(&mut self) -> Vec<u8> {
        let old_state = self.state;
        let blocksize = 64;
        let mut unprocessed_data = self.buffer.buffered().to_vec();
        unprocessed_data.push(0x80);
        unprocessed_data.extend_from_slice(&vec![0; (64 + 56 - unprocessed_data.len()) % 64]);
        unprocessed_data.extend_from_slice(&self.len.to_le_bytes());
        (self.state[0], self.state[1], self.state[2], self.state[3]) = self.process_block(&unprocessed_data);
        if unprocessed_data.len() > blocksize {
            (self.state[0], self.state[1], self.state[2], self.state[3]) = 
                self.process_block(&unprocessed_data[blocksize..(blocksize*2)]);
        }
        let mut result = vec![];
        result.extend_from_slice(&self.state[0].to_le_bytes());
        result.extend_from_slice(&self.state[1].to_le_bytes());
        result.extend_from_slice(&self.state[2].to_le_bytes());
        result.extend_from_slice(&self.state[3].to_le_bytes());
        self.state = old_state;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit counter was a `usize`, so on a 32-bit target it wrapped
    /// at 2^32 bits (512 MiB) and the `+=` overflowed in a debug build:
    /// a wrong digest with no error past that length. No test ran on
    /// such a target, and on a 64-bit one the two types agree for any
    /// message that fits in memory. The check is on the type itself.
    #[test]
    fn test_the_bit_counter_is_64_bits_wide() {
        let mut hash = MD5::new(&[]);
        hash.update(&[0u8; 100]);
        let bits: u64 = hash.len;
        assert_eq!(bits, 800);
        // And the counter is what the padding carries: the same bytes
        // fed in two pieces give the same digest as one call.
        let mut pieces = MD5::new(&[0u8; 37]);
        pieces.update(&[0u8; 63]);
        assert_eq!(pieces.digest(), hash.digest());
    }
}
