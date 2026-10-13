/*!
Snefru (Merkle, 1990), at 128 and 256 bits, eight passes.

A compression function on sixteen 32 bit words: the chaining value (four
or eight words) and as much message as fills the rest, big endian. Each
pass runs four rounds over the sixteen words; in each, every word's low
byte selects an entry of one of the pass's two S-boxes, chosen by the
word's position, which is XORed into both neighbours, and then every
word is rotated right by 16, 8, 16 and 24 bits in the four rounds. The
new chaining value is the last words in reverse order XORed with the
first ones as they came in.

The message is zero-padded to a whole block, and a last block carries
the length in bits in its last two words. The S-boxes come from RAND's
random digits, through `scripts/make_snefru_tables.py`. Names:
`snefru128`, and `snefru256`, which PHP calls `snefru` and so may be.
*/

use super::buffer::BlockBuffer;
use super::snefru_tables::SBOXES;
use super::HashFunction;

const ROTATIONS: [u32; 4] = [16, 8, 16, 24];

/// The compression function on the sixteen words; the chaining value is
/// the first `len` of them, in and out.
fn compress(block: &mut [u32; 16], len: usize) {
    let saved = *block;
    for pass in 0..8 {
        for rotation in ROTATIONS {
            for i in 0..16 {
                let entry = SBOXES[2 * pass + (i / 2) % 2][(block[i] & 0xff) as usize];
                block[(i + 15) % 16] ^= entry;
                block[(i + 1) % 16] ^= entry;
            }
            for word in block.iter_mut() {
                *word = word.rotate_right(rotation);
            }
        }
    }
    for i in 0..len {
        block[i] = block[15 - i] ^ saved[i];
    }
}

/// Snefru with a chaining value of `LEN` words, taking `DATA` bytes of
/// message per block: 4 and 48 for Snefru-128, 8 and 32 for Snefru-256.
#[derive(Clone)]
pub struct SnefruCore<const LEN: usize, const DATA: usize> {
    hash: [u32; 8],
    buffer: BlockBuffer<DATA>,
    length: u64,
}

pub type Snefru128 = SnefruCore<4, 48>;
pub type Snefru256 = SnefruCore<8, 32>;

impl<const LEN: usize, const DATA: usize> Default for SnefruCore<LEN, DATA> {
    fn default() -> Self {
        SnefruCore { hash: [0; 8], buffer: BlockBuffer::default(), length: 0 }
    }
}

impl<const LEN: usize, const DATA: usize> SnefruCore<LEN, DATA> {
    pub fn new(input: &[u8]) -> Self {
        let mut hash = Self::default();
        hash.update(input);
        hash
    }

    fn absorb(hash: &mut [u32; 8], data: &[u8]) {
        let mut block = [0u32; 16];
        block[..LEN].copy_from_slice(&hash[..LEN]);
        for (word, bytes) in block[LEN..].iter_mut().zip(data.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("4 bytes"));
        }
        compress(&mut block, LEN);
        hash[..LEN].copy_from_slice(&block[..LEN]);
    }
}

impl<const LEN: usize, const DATA: usize> HashFunction for SnefruCore<LEN, DATA> {
    fn name(&self) -> String {
        format!("snefru{}", 32 * LEN)
    }

    fn digest_len(&self) -> usize {
        4 * LEN
    }

    fn block_size(&self) -> usize {
        DATA
    }

    fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        let hash = &mut self.hash;
        self.buffer.feed(input, |block| Self::absorb(hash, block));
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut last = self.clone();
        if !last.buffer.is_empty() {
            let zeros = vec![0u8; DATA - last.buffer.len()];
            let hash = &mut last.hash;
            last.buffer.feed(&zeros, |block| Self::absorb(hash, block));
        }
        // The length block: the chaining value, zeros, and the length in
        // bits in the last two words.
        let mut block = [0u32; 16];
        block[..LEN].copy_from_slice(&last.hash[..LEN]);
        let bits = last.length.wrapping_mul(8);
        block[14] = (bits >> 32) as u32;
        block[15] = bits as u32;
        compress(&mut block, LEN);
        block[..LEN].iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The length block past 2^32 bits, which no message the tests can
    /// hash reaches: a hash with nothing in it, told it has taken that
    /// many bytes, against RHash and mhash told the same
    /// (`vectors/tiger_haval_snefru.vec`'s `length` rows, the last of
    /// them past 2^64 bits, where all three wrap).
    #[test]
    fn test_the_length_block_past_32_bits() {
        let rows: Vec<_> = include_str!("../../vectors/tiger_haval_snefru.vec").lines()
            .filter(|l| l.starts_with("length ")).map(|line| {
                let f: std::collections::HashMap<_, _> =
                    line.split(' ').skip(1).map(|w| w.split_once('=').expect("field")).collect();
                (f["name"], f["bytes"].parse::<u64>().expect("bytes"), f["digest"])
            }).collect();
        assert_eq!(rows.len(), 6);
        for (name, bytes, digest) in rows {
            let got = if name == "snefru128" {
                Snefru128 { length: bytes, ..Default::default() }.digest()
            } else {
                Snefru256 { length: bytes, ..Default::default() }.digest()
            };
            let got: String = got.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, digest, "{name} after {bytes} bytes");
        }
    }
}
