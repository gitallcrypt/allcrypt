//! bzip2 decompression: OpenPGP's compression algorithm 3. Decompression
//! only, and not cryptography: it lives with the examples.
//!
//! A stream is `BZh` and a block size digit, then blocks, each the
//! Burrows-Wheeler transform of up to 900 kB that was first run-length
//! encoded, then move-to-front coded, then Huffman coded with up to six
//! tables switched every fifty symbols. Every field is read most
//! significant bit first, and each block and the whole stream carry a
//! CRC-32 in the MSB-first form (polynomial 0x04c11db7, unreflected),
//! which is not zlib's.

#![allow(dead_code)]

struct Bits<'a> {
    data: &'a [u8],
    at: usize,
    bit: u32,
}

impl Bits<'_> {
    fn bit(&mut self) -> Result<u32, String> {
        let byte = *self.data.get(self.at).ok_or("bzip2: the stream ends early.")?;
        let value = (u32::from(byte) >> (7 - self.bit)) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.at += 1;
        }
        Ok(value)
    }

    fn bits(&mut self, count: u32) -> Result<u64, String> {
        let mut value = 0u64;
        for _ in 0..count {
            value = value << 1 | u64::from(self.bit()?);
        }
        Ok(value)
    }
}

fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut c = (i as u32) << 24;
        for _ in 0..8 {
            c = if c & 0x8000_0000 != 0 { c << 1 ^ 0x04c1_1db7 } else { c << 1 };
        }
        *entry = c;
    }
    table
}

/// A canonical Huffman code given by code lengths, decoded bit by bit.
struct Huffman {
    /// (length, first code, index of its first symbol) per length.
    limits: Vec<(u32, u32, usize)>,
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Huffman, String> {
        let mut symbols = Vec::with_capacity(lengths.len());
        let mut limits = Vec::new();
        let mut code = 0u32;
        for length in 1..=20u8 {
            let start = symbols.len();
            for (symbol, &l) in lengths.iter().enumerate() {
                if l == length {
                    symbols.push(symbol as u16);
                }
            }
            limits.push((u32::from(length), code, start));
            code = (code + (symbols.len() - start) as u32) << 1;
        }
        Ok(Huffman { limits, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, String> {
        let mut code = 0u32;
        for (i, &(_, first, start)) in self.limits.iter().enumerate() {
            code = code << 1 | bits.bit()?;
            let next = self.limits.get(i + 1).map_or(self.symbols.len(), |l| l.2);
            let count = (next - start) as u32;
            if code >= first && code - first < count {
                return Ok(self.symbols[start + (code - first) as usize]);
            }
        }
        Err("bzip2: a Huffman code matches no symbol.".to_string())
    }
}

/// One block's output, before the final run-length decoding.
fn block(bits: &mut Bits<'_>, max_size: usize) -> Result<(Vec<u8>, u32), String> {
    let crc = bits.bits(32)? as u32;
    if bits.bit()? == 1 {
        return Err("bzip2: a randomised block (bzip2 0.9.0 and earlier) is not supported."
            .to_string());
    }
    let origin = bits.bits(24)? as usize;

    // The symbol map: sixteen ranges of sixteen bytes.
    let ranges = bits.bits(16)?;
    let mut in_use = Vec::new();
    for range in 0..16 {
        if ranges >> (15 - range) & 1 == 1 {
            let present = bits.bits(16)?;
            for i in 0..16 {
                if present >> (15 - i) & 1 == 1 {
                    in_use.push((range * 16 + i) as u8);
                }
            }
        }
    }
    if in_use.is_empty() {
        return Err("bzip2: a block uses no symbols.".to_string());
    }
    let alphabet = in_use.len() + 2;

    let tables = bits.bits(3)? as usize;
    if !(2..=6).contains(&tables) {
        return Err(format!("bzip2: {tables} Huffman tables; 2 to 6 are allowed."));
    }
    let selector_count = bits.bits(15)? as usize;
    if selector_count == 0 {
        return Err("bzip2: no selectors.".to_string());
    }
    // Selectors are move-to-front coded, each a unary number.
    let mut order: Vec<u8> = (0..tables as u8).collect();
    let mut selectors = Vec::with_capacity(selector_count);
    for _ in 0..selector_count {
        let mut j = 0;
        while bits.bit()? == 1 {
            j += 1;
            if j >= tables {
                return Err("bzip2: a selector past the last table.".to_string());
            }
        }
        let table = order.remove(j);
        order.insert(0, table);
        selectors.push(table);
    }
    let mut codes = Vec::with_capacity(tables);
    for _ in 0..tables {
        let mut length = bits.bits(5)? as i32;
        let mut lengths = vec![0u8; alphabet];
        for slot in lengths.iter_mut() {
            loop {
                if !(1..=20).contains(&length) {
                    return Err("bzip2: a code length outside 1 to 20.".to_string());
                }
                if bits.bit()? == 0 {
                    break;
                }
                length += if bits.bit()? == 0 { 1 } else { -1 };
            }
            *slot = length as u8;
        }
        codes.push(Huffman::new(&lengths)?);
    }

    // The symbols: move-to-front indices, with runs of the first one
    // written in bijective base 2 as RUNA (0) and RUNB (1).
    let end = (alphabet - 1) as u16;
    let mut mtf: Vec<u8> = in_use.clone();
    let mut counts = [0usize; 256];
    let mut tt: Vec<u8> = Vec::new();
    let (mut run, mut run_weight) = (0usize, 1usize);
    let mut decoded = 0usize;
    loop {
        let group = decoded / 50;
        let table = *selectors.get(group).ok_or("bzip2: the selectors ran out.")?;
        let symbol = codes[table as usize].decode(bits)?;
        decoded += 1;
        if symbol <= 1 {
            run += run_weight << symbol;
            run_weight <<= 1;
            if run > max_size {
                return Err("bzip2: a run longer than the block.".to_string());
            }
            continue;
        }
        if run > 0 {
            let byte = mtf[0];
            counts[byte as usize] += run;
            tt.extend(std::iter::repeat_n(byte, run));
            run = 0;
            run_weight = 1;
        }
        if symbol == end {
            break;
        }
        let index = (symbol - 1) as usize;
        let byte = mtf.remove(index);
        mtf.insert(0, byte);
        counts[byte as usize] += 1;
        tt.push(byte);
        if tt.len() > max_size {
            return Err("bzip2: a block larger than its stated size.".to_string());
        }
    }
    if origin >= tt.len() {
        return Err("bzip2: the origin pointer is past the block.".to_string());
    }

    // The inverse Burrows-Wheeler transform.
    let mut starts = [0usize; 256];
    let mut total = 0;
    for (start, count) in starts.iter_mut().zip(counts) {
        *start = total;
        total += count;
    }
    let mut next = vec![0u32; tt.len()];
    for (i, &byte) in tt.iter().enumerate() {
        next[starts[byte as usize]] = i as u32;
        starts[byte as usize] += 1;
    }
    let mut out = Vec::with_capacity(tt.len());
    let mut at = next[origin] as usize;
    for _ in 0..tt.len() {
        out.push(tt[at]);
        at = next[at] as usize;
    }
    Ok((out, crc))
}

/// The first stage's runs: four equal bytes are followed by a count of
/// further copies.
fn unrun(data: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), String> {
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        let mut same = 1;
        while same < 4 && i + same < data.len() && data[i + same] == byte {
            same += 1;
        }
        out.extend(std::iter::repeat_n(byte, same));
        i += same;
        if same == 4 {
            let extra = *data.get(i).ok_or("bzip2: a run without its count.")?;
            out.extend(std::iter::repeat_n(byte, extra as usize));
            i += 1;
        }
        if out.len() > limit {
            return Err(format!("bzip2: the output exceeds {limit} bytes."));
        }
    }
    Ok(())
}

/// A whole bzip2 stream (or several concatenated). `limit` bounds the
/// output.
pub fn decompress(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let table = crc_table();
    let mut out = Vec::new();
    let mut bits = Bits { data, at: 0, bit: 0 };
    loop {
        if bits.bits(24)? != 0x425a68 {
            return Err("bzip2: not a bzip2 stream.".to_string());
        }
        let level = bits.bits(8)? as u8;
        if !(b'1'..=b'9').contains(&level) {
            return Err("bzip2: the block size is not 1 to 9.".to_string());
        }
        let max_size = (level - b'0') as usize * 100_000;
        let mut combined = 0u32;
        loop {
            match bits.bits(48)? {
                0x3141_5926_5359 => {
                    let (bwt, crc) = block(&mut bits, max_size)?;
                    let start = out.len();
                    unrun(&bwt, &mut out, limit)?;
                    let mut actual = 0xffff_ffffu32;
                    for &byte in &out[start..] {
                        actual = actual << 8 ^ table[((actual >> 24) as u8 ^ byte) as usize];
                    }
                    actual = !actual;
                    if actual != crc {
                        return Err("bzip2: a block's CRC does not match.".to_string());
                    }
                    combined = combined.rotate_left(1) ^ crc;
                }
                0x1772_4538_5090 => {
                    if bits.bits(32)? as u32 != combined {
                        return Err("bzip2: the stream's CRC does not match.".to_string());
                    }
                    break;
                }
                _ => return Err("bzip2: neither a block nor the end of the stream.".to_string()),
            }
        }
        // Padding to a byte, then possibly another stream.
        if bits.bit != 0 {
            bits.bit = 0;
            bits.at += 1;
        }
        if bits.at >= data.len() {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod bunzip2_tests {
    use super::decompress;

    fn unhex(t: &str) -> Vec<u8> {
        (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap()).collect()
    }

    /// Streams Python's `bz2` module (libbz2) wrote: a short text, an
    /// empty input, and a run long enough to need the run-length
    /// stage's count byte and RUNA/RUNB.
    #[test]
    fn test_streams_libbz2_wrote() {
        // bz2.compress(b"hello hello hello hello")
        let hello = unhex("425a683931415926535902f8b0bd000003910040000244a00030cd00548696\
                           719b38a3c5dc914e142400be2c2f40");
        assert_eq!(decompress(&hello, 1 << 20).unwrap(), b"hello hello hello hello");
        // bz2.compress(b"")
        assert_eq!(decompress(&unhex("425a683917724538509000000000"), 1 << 20).unwrap(), b"");
        // bz2.compress(b"a" * 1000 + b"b" * 3)
        let runs = unhex("425a6839314159265359682c3ac40000018101b000008000082000212340cd\
                          34d1425321c5dc914e14241a0b0eb100");
        let mut expected = vec![b'a'; 1000];
        expected.extend(b"bbb");
        assert_eq!(decompress(&runs, 1 << 20).unwrap(), expected);
        let mut bad = hello.clone();
        bad[20] ^= 1;
        assert!(decompress(&bad, 1 << 20).is_err());
    }
}
