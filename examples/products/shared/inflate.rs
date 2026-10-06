//! DEFLATE decompression (RFC 1951), with the zlib (RFC 1950) wrapper.
//! OpenPGP compresses messages with it, and some of the age test
//! vectors are stored with it. Decompression only, and not
//! cryptography: it lives with the examples.

#![allow(dead_code)]

struct Bits<'a> {
    data: &'a [u8],
    at: usize,
    bit: u32,
}

impl Bits<'_> {
    fn bit(&mut self) -> Result<u32, String> {
        let byte = *self.data.get(self.at).ok_or("inflate: the stream ends early.")?;
        let value = (u32::from(byte) >> self.bit) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.at += 1;
        }
        Ok(value)
    }

    /// `count` bits, least significant first.
    fn bits(&mut self, count: u32) -> Result<u32, String> {
        let mut value = 0;
        for i in 0..count {
            value |= self.bit()? << i;
        }
        Ok(value)
    }

    fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.at += 1;
        }
    }
}

/// A canonical Huffman code: symbols by code length, decoded bit by bit.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Huffman, String> {
        let mut counts = [0u16; 16];
        for &length in lengths {
            counts[length as usize] += 1;
        }
        counts[0] = 0;
        let mut offsets = [0u16; 16];
        for i in 1..16 {
            offsets[i] = offsets[i - 1] + counts[i - 1];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                symbols[offsets[length as usize] as usize] = symbol as u16;
                offsets[length as usize] += 1;
            }
        }
        Ok(Huffman { counts, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, String> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for length in 1..16 {
            code |= bits.bit()? as i32;
            let count = i32::from(self.counts[length]);
            if code - count < first {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err("inflate: a code longer than 15 bits.".to_string())
    }
}

const LENGTH_BASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43,
                                51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LENGTH_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4,
                                4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257,
                              385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
                              16385, 24577];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9,
                              10, 10, 11, 11, 12, 12, 13, 13];

fn block(bits: &mut Bits<'_>, out: &mut Vec<u8>, literals: &Huffman, distances: &Huffman,
         limit: usize) -> Result<(), String> {
    loop {
        let symbol = literals.decode(bits)?;
        match symbol {
            0..=255 => out.push(symbol as u8),
            256 => return Ok(()),
            257..=285 => {
                let i = (symbol - 257) as usize;
                let length = LENGTH_BASE[i] as usize
                    + bits.bits(u32::from(LENGTH_EXTRA[i]))? as usize;
                let d = distances.decode(bits)? as usize;
                if d >= 30 {
                    return Err("inflate: a distance code past 29.".to_string());
                }
                let distance = DIST_BASE[d] as usize + bits.bits(u32::from(DIST_EXTRA[d]))? as usize;
                if distance > out.len() {
                    return Err("inflate: a distance before the start of the output.".to_string());
                }
                let start = out.len() - distance;
                for i in 0..length {
                    out.push(out[start + i]);
                }
            }
            _ => return Err("inflate: a literal/length code past 285.".to_string()),
        }
        if out.len() > limit {
            return Err(format!("inflate: the output exceeds {limit} bytes."));
        }
    }
}

/// Raw DEFLATE. Returns the output and how many input bytes it used.
/// `limit` bounds the output, which a crafted stream can otherwise make
/// as large as it likes.
pub fn inflate(data: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
    let mut bits = Bits { data, at: 0, bit: 0 };
    let mut out = Vec::new();
    loop {
        let last = bits.bit()?;
        match bits.bits(2)? {
            0 => {
                bits.align();
                let header = data.get(bits.at..bits.at + 4).ok_or("inflate: short stored block")?;
                let length = u16::from_le_bytes([header[0], header[1]]) as usize;
                let check = u16::from_le_bytes([header[2], header[3]]);
                if check != !(length as u16) {
                    return Err("inflate: a stored block's length check fails.".to_string());
                }
                bits.at += 4;
                out.extend_from_slice(data.get(bits.at..bits.at + length)
                    .ok_or("inflate: short stored block")?);
                bits.at += length;
            }
            1 => {
                let mut lengths = [0u8; 288];
                lengths[..144].fill(8);
                lengths[144..256].fill(9);
                lengths[256..280].fill(7);
                lengths[280..].fill(8);
                let literals = Huffman::new(&lengths)?;
                let distances = Huffman::new(&[5u8; 30])?;
                block(&mut bits, &mut out, &literals, &distances, limit)?;
            }
            2 => {
                let hlit = bits.bits(5)? as usize + 257;
                let hdist = bits.bits(5)? as usize + 1;
                let hclen = bits.bits(4)? as usize + 4;
                const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2,
                                            14, 1, 15];
                let mut code_lengths = [0u8; 19];
                for &i in ORDER.iter().take(hclen) {
                    code_lengths[i] = bits.bits(3)? as u8;
                }
                let codes = Huffman::new(&code_lengths)?;
                let mut lengths = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < hlit + hdist {
                    let symbol = codes.decode(&mut bits)?;
                    let (value, repeat) = match symbol {
                        0..=15 => (symbol as u8, 1),
                        16 => (*lengths.get(i.wrapping_sub(1))
                                   .ok_or("inflate: a repeat with nothing before it")?,
                               3 + bits.bits(2)? as usize),
                        17 => (0, 3 + bits.bits(3)? as usize),
                        _ => (0, 11 + bits.bits(7)? as usize),
                    };
                    if i + repeat > hlit + hdist {
                        return Err("inflate: code lengths overrun.".to_string());
                    }
                    lengths[i..i + repeat].fill(value);
                    i += repeat;
                }
                let literals = Huffman::new(&lengths[..hlit])?;
                let distances = Huffman::new(&lengths[hlit..])?;
                block(&mut bits, &mut out, &literals, &distances, limit)?;
            }
            _ => return Err("inflate: block type 3 is reserved.".to_string()),
        }
        if out.len() > limit {
            return Err(format!("inflate: the output exceeds {limit} bytes."));
        }
        if last == 1 {
            bits.align();
            return Ok((out, bits.at));
        }
    }
}

/// zlib: a two byte header, DEFLATE, and an Adler-32 of the output.
pub fn zlib_decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    if data.len() < 6 || data[0] & 0x0f != 8 || (u16::from(data[0]) << 8 | u16::from(data[1])) % 31 != 0 {
        return Err("zlib: not a zlib stream.".to_string());
    }
    if data[1] & 0x20 != 0 {
        return Err("zlib: a preset dictionary is not supported.".to_string());
    }
    let (out, used) = inflate(&data[2..], limit)?;
    let trailer = data.get(2 + used..2 + used + 4).ok_or("zlib: no Adler-32")?;
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in &out {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    if (b << 16 | a).to_be_bytes() != trailer[..] {
        return Err("zlib: the Adler-32 does not match.".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_fixed_and_dynamic_blocks() {
        // zlib.compress(b"hello hello hello hello") - a fixed Huffman block
        // with a back reference - and a stored block, from Python's zlib.
        // Dynamic blocks are in the age vectors that are stored
        // compressed.
        let unhex = |t: &str| (0..t.len()).step_by(2)
            .map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap()).collect::<Vec<u8>>();
        let fixed = unhex("789ccb48cdc9c957c8402701680308b1");
        assert_eq!(zlib_decompress(&fixed, 1 << 20).unwrap(), b"hello hello hello hello");
        let stored = unhex("7801010300fcff616263024d0127");
        assert_eq!(zlib_decompress(&stored, 1 << 20).unwrap(), b"abc");
        let mut bad = fixed.clone();
        bad[15] ^= 1;
        assert!(zlib_decompress(&bad, 1 << 20).is_err());
    }
}
