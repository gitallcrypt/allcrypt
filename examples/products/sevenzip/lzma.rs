//! LZMA and LZMA2 decoding, as 7z uses them: the unpacked size is known
//! from the archive, and the end marker is optional.
//!
//! LZMA is a range coder over adaptive binary probabilities, driving an
//! LZ77 decoder with four repeated-distance slots and a twelve-state
//! machine that remembers what the last few packets were. Everything
//! here follows Igor Pavlov's `lzma-specification.txt` decoder, which
//! the 7-Zip sources carry; LZMA2 is a chunked container around it
//! (`Lzma2Dec.c`): each chunk is stored or LZMA, and may reset the
//! dictionary, the state, or the properties.
//!
//! The whole output is held in memory and is the dictionary - a 7z
//! folder's unpacked size is known before it starts - so a distance is
//! checked against what has been written since the last dictionary
//! reset and against the declared dictionary size.

const PROB_INIT: u16 = 1024;
const TOP: u32 = 1 << 24;
const STATES: usize = 12;
const POS_BITS_MAX: usize = 4;
const LEN_TO_POS_STATES: usize = 4;
const END_POS_MODEL_INDEX: u32 = 14;
const FULL_DISTANCES: usize = 128;
const ALIGN_BITS: u32 = 4;
const MATCH_MIN_LEN: usize = 2;

struct RangeDecoder<'a> {
    data: &'a [u8],
    at: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Result<RangeDecoder<'a>, String> {
        let head = data.get(..5).ok_or("LZMA: a stream too short for its range coder.")?;
        if head[0] != 0 {
            return Err("LZMA: the range coder's first byte is not zero.".to_string());
        }
        let code = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
        if code == u32::MAX {
            return Err("LZMA: a corrupt range coder start.".to_string());
        }
        Ok(RangeDecoder { data, at: 5, range: u32::MAX, code })
    }

    fn byte(&mut self) -> Result<u8, String> {
        let b = *self.data.get(self.at).ok_or("LZMA: the compressed data ends early.")?;
        self.at += 1;
        Ok(b)
    }

    fn normalize(&mut self) -> Result<(), String> {
        if self.range < TOP {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(self.byte()?);
        }
        Ok(())
    }

    fn bit(&mut self, prob: &mut u16) -> Result<u32, String> {
        let bound = (self.range >> 11) * u32::from(*prob);
        let bit = if self.code < bound {
            *prob += (2048 - *prob) >> 5;
            self.range = bound;
            0
        } else {
            *prob -= *prob >> 5;
            self.code -= bound;
            self.range -= bound;
            1
        };
        self.normalize()?;
        Ok(bit)
    }

    fn direct(&mut self, count: u32) -> Result<u32, String> {
        let mut result = 0u32;
        for _ in 0..count {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            if self.code == self.range {
                return Err("LZMA: corrupt direct bits.".to_string());
            }
            self.normalize()?;
            result = (result << 1).wrapping_add(t.wrapping_add(1));
        }
        Ok(result)
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32) -> Result<u32, String> {
        let mut m = 1usize;
        for _ in 0..bits {
            m = (m << 1) + self.bit(&mut probs[m])? as usize;
        }
        Ok(m as u32 - (1 << bits))
    }

    fn reverse_tree(&mut self, probs: &mut [u16], bits: u32) -> Result<u32, String> {
        let mut m = 1usize;
        let mut symbol = 0u32;
        for i in 0..bits {
            let bit = self.bit(&mut probs[m])?;
            m = (m << 1) + bit as usize;
            symbol |= bit << i;
        }
        Ok(symbol)
    }
}

struct LenDecoder {
    choice: u16,
    choice2: u16,
    low: Vec<[u16; 8]>,
    mid: Vec<[u16; 8]>,
    high: [u16; 256],
}

impl LenDecoder {
    fn new() -> LenDecoder {
        LenDecoder { choice: PROB_INIT, choice2: PROB_INIT,
                     low: vec![[PROB_INIT; 8]; 1 << POS_BITS_MAX],
                     mid: vec![[PROB_INIT; 8]; 1 << POS_BITS_MAX], high: [PROB_INIT; 256] }
    }

    fn decode(&mut self, rc: &mut RangeDecoder, pos_state: usize) -> Result<usize, String> {
        if rc.bit(&mut self.choice)? == 0 {
            return Ok(rc.tree(&mut self.low[pos_state], 3)? as usize);
        }
        if rc.bit(&mut self.choice2)? == 0 {
            return Ok(8 + rc.tree(&mut self.mid[pos_state], 3)? as usize);
        }
        Ok(16 + rc.tree(&mut self.high, 8)? as usize)
    }
}

/// `lc`, `lp` and `pb`: literal context bits, literal position bits,
/// position bits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Properties {
    pub lc: u32,
    pub lp: u32,
    pub pb: u32,
}

impl Properties {
    /// The packed byte: `(pb * 5 + lp) * 9 + lc`.
    pub fn from_byte(byte: u8) -> Result<Properties, String> {
        if byte >= 9 * 5 * 5 {
            return Err(format!("LZMA: properties byte {byte} is out of range."));
        }
        let byte = u32::from(byte);
        Ok(Properties { lc: byte % 9, lp: (byte / 9) % 5, pb: byte / 45 })
    }
}

/// The decoder's state, which LZMA2 keeps across chunks.
struct State {
    props: Properties,
    literal: Vec<u16>,
    is_match: [u16; STATES << POS_BITS_MAX],
    is_rep: [u16; STATES],
    is_rep_g0: [u16; STATES],
    is_rep_g1: [u16; STATES],
    is_rep_g2: [u16; STATES],
    is_rep0_long: [u16; STATES << POS_BITS_MAX],
    pos_slot: [[u16; 64]; LEN_TO_POS_STATES],
    pos: [u16; 1 + FULL_DISTANCES - END_POS_MODEL_INDEX as usize],
    align: [u16; 16],
    len: LenDecoder,
    rep_len: LenDecoder,
    state: usize,
    reps: [usize; 4],
}

impl State {
    fn new(props: Properties) -> State {
        State {
            props,
            literal: vec![PROB_INIT; 0x300 << (props.lc + props.lp)],
            is_match: [PROB_INIT; STATES << POS_BITS_MAX],
            is_rep: [PROB_INIT; STATES],
            is_rep_g0: [PROB_INIT; STATES],
            is_rep_g1: [PROB_INIT; STATES],
            is_rep_g2: [PROB_INIT; STATES],
            is_rep0_long: [PROB_INIT; STATES << POS_BITS_MAX],
            pos_slot: [[PROB_INIT; 64]; LEN_TO_POS_STATES],
            pos: [PROB_INIT; 1 + FULL_DISTANCES - END_POS_MODEL_INDEX as usize],
            align: [PROB_INIT; 16],
            len: LenDecoder::new(),
            rep_len: LenDecoder::new(),
            state: 0,
            reps: [0; 4],
        }
    }

    fn distance(&mut self, rc: &mut RangeDecoder, len: usize) -> Result<u32, String> {
        let len_state = len.min(LEN_TO_POS_STATES - 1);
        let slot = rc.tree(&mut self.pos_slot[len_state], 6)?;
        if slot < 4 {
            return Ok(slot);
        }
        let direct = (slot >> 1) - 1;
        let mut distance = (2 | (slot & 1)) << direct;
        if slot < END_POS_MODEL_INDEX {
            let base = (distance - slot) as usize;
            distance += rc.reverse_tree(&mut self.pos[base..], direct)?;
        } else {
            distance += rc.direct(direct - ALIGN_BITS)? << ALIGN_BITS;
            distance += rc.reverse_tree(&mut self.align, ALIGN_BITS)?;
        }
        Ok(distance)
    }

    /// Decode until `out` holds `end` bytes (or an end marker), with
    /// `start` where the current dictionary begins and `dict_size` the
    /// furthest a distance may reach.
    fn run(&mut self, rc: &mut RangeDecoder, out: &mut Vec<u8>, start: usize, end: usize,
           dict_size: usize) -> Result<(), String> {
        let pb_mask = (1usize << self.props.pb) - 1;
        let lp_mask = (1usize << self.props.lp) - 1;
        while out.len() < end {
            // Positions count from the last dictionary reset, as
            // `processedPos` does in LzmaDec.c.
            let pos = out.len() - start;
            let pos_state = pos & pb_mask;
            let state = self.state;
            if rc.bit(&mut self.is_match[(state << POS_BITS_MAX) + pos_state])? == 0 {
                let previous = if out.len() > start { out[out.len() - 1] } else { 0 };
                let lit_state = ((pos & lp_mask) << self.props.lc)
                    + (usize::from(previous) >> (8 - self.props.lc));
                let probs = &mut self.literal[0x300 * lit_state..0x300 * (lit_state + 1)];
                let mut symbol = 1usize;
                if state >= 7 {
                    let at = out.len() - self.reps[0] - 1;
                    let mut match_byte = usize::from(out[at]);
                    while symbol < 0x100 {
                        let match_bit = (match_byte >> 7) & 1;
                        match_byte <<= 1;
                        let bit = rc.bit(&mut probs[((1 + match_bit) << 8) + symbol])? as usize;
                        symbol = (symbol << 1) | bit;
                        if match_bit != bit {
                            break;
                        }
                    }
                }
                while symbol < 0x100 {
                    symbol = (symbol << 1) | rc.bit(&mut probs[symbol])? as usize;
                }
                out.push((symbol - 0x100) as u8);
                self.state = if state < 4 { 0 } else if state < 10 { state - 3 } else { state - 6 };
                continue;
            }
            let len;
            if rc.bit(&mut self.is_rep[state])? != 0 {
                if out.len() == start {
                    return Err("LZMA: a repeated match before any output.".to_string());
                }
                if rc.bit(&mut self.is_rep_g0[state])? == 0 {
                    if rc.bit(&mut self.is_rep0_long[(state << POS_BITS_MAX) + pos_state])? == 0 {
                        // A short rep: one byte from rep0.
                        self.state = if state < 7 { 9 } else { 11 };
                        let byte = out[out.len() - self.reps[0] - 1];
                        out.push(byte);
                        continue;
                    }
                } else {
                    let distance;
                    if rc.bit(&mut self.is_rep_g1[state])? == 0 {
                        distance = self.reps[1];
                    } else {
                        if rc.bit(&mut self.is_rep_g2[state])? == 0 {
                            distance = self.reps[2];
                        } else {
                            distance = self.reps[3];
                            self.reps[3] = self.reps[2];
                        }
                        self.reps[2] = self.reps[1];
                    }
                    self.reps[1] = self.reps[0];
                    self.reps[0] = distance;
                }
                len = self.rep_len.decode(rc, pos_state)?;
                self.state = if state < 7 { 8 } else { 11 };
            } else {
                self.reps[3] = self.reps[2];
                self.reps[2] = self.reps[1];
                self.reps[1] = self.reps[0];
                len = self.len.decode(rc, pos_state)?;
                self.state = if state < 7 { 7 } else { 10 };
                let distance = self.distance(rc, len)?;
                if distance == u32::MAX {
                    return Err("LZMA: an end marker before the declared size.".to_string());
                }
                self.reps[0] = distance as usize;
            }
            let distance = self.reps[0];
            if distance >= out.len() - start || distance >= dict_size {
                return Err(format!("LZMA: a distance of {} reaches before the dictionary.",
                                   distance + 1));
            }
            let length = len + MATCH_MIN_LEN;
            if out.len() + length > end {
                return Err("LZMA: a match runs past the declared size.".to_string());
            }
            let from = out.len() - distance - 1;
            for i in 0..length {
                let byte = out[from + i];
                out.push(byte);
            }
        }
        Ok(())
    }
}

/// Room for the output: the declared size, but a declared size is
/// only a claim, so no more up front than the packed data could
/// plausibly expand to; the vector grows past that as needed.
fn reserve(size: usize, packed: usize) -> Vec<u8> {
    Vec::with_capacity(size.min(packed.saturating_mul(64).max(1 << 16)))
}

/// 7z's LZMA coder: five bytes of properties (the packed `lc`/`lp`/`pb`
/// byte and the dictionary size, little endian), then the stream.
pub fn decode_lzma(properties: &[u8], data: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let [byte, d0, d1, d2, d3] = properties else {
        return Err(format!("LZMA: {} bytes of properties, not 5.", properties.len()));
    };
    let props = Properties::from_byte(*byte)?;
    let dict_size = (u32::from_le_bytes([*d0, *d1, *d2, *d3]) as usize).max(4096);
    let mut out = reserve(size, data.len());
    let mut rc = RangeDecoder::new(data)?;
    State::new(props).run(&mut rc, &mut out, 0, size, dict_size)?;
    Ok(out)
}

/// LZMA2's dictionary size: one byte, `2 | (b & 1)` shifted left by
/// `b / 2 + 11`, and 40 meaning the largest.
pub fn lzma2_dict_size(properties: &[u8]) -> Result<usize, String> {
    let [byte] = properties else {
        return Err(format!("LZMA2: {} bytes of properties, not 1.", properties.len()));
    };
    match byte {
        0..=39 => Ok((2 | usize::from(byte & 1)) << (byte / 2 + 11)),
        40 => Ok(u32::MAX as usize),
        _ => Err(format!("LZMA2: dictionary size byte {byte} is out of range.")),
    }
}

/// 7z's LZMA2 coder: chunks until a zero control byte.
///
/// What a chunk may assume is tracked as Lzma2Dec.c's `needInitLevel`:
/// the first chunk must reset the dictionary - an LZMA chunk with
/// control 0xE0 or more (and new properties), or a stored chunk with
/// control 1 - and an LZMA chunk after a resetting stored chunk must
/// bring its own properties (0xC0 or more). Every LZMA chunk starts its
/// own range coder.
pub fn decode_lzma2(properties: &[u8], data: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let dict_size = lzma2_dict_size(properties)?;
    let mut out = reserve(size, data.len());
    let mut at = 0usize;
    let mut start = 0usize;
    let mut state: Option<State> = None;
    let mut need_level = 0xE0u8;
    loop {
        let control = *data.get(at).ok_or("LZMA2: the data ends without its end marker.")?;
        at += 1;
        if control == 0 {
            break;
        }
        let read = |at: usize, n: usize| -> Result<&[u8], String> {
            data.get(at..at + n).ok_or_else(|| "LZMA2: a chunk header is cut short.".to_string())
        };
        if control < 0x80 {
            // A stored chunk: 1 resets the dictionary, 2 does not.
            if control == 1 {
                need_level = 0xC0;
                start = out.len();
            } else if control > 2 || need_level == 0xE0 {
                return Err(format!("LZMA2: control byte {control:#x} here."));
            }
            let header = read(at, 2)?;
            let n = usize::from(u16::from_be_bytes([header[0], header[1]])) + 1;
            at += 2;
            if out.len() + n > size {
                return Err("LZMA2: more data than the declared size.".to_string());
            }
            out.extend_from_slice(read(at, n)?);
            at += n;
            continue;
        }
        if control < need_level {
            return Err(format!("LZMA2: control byte {control:#x} before the resets it needs."));
        }
        need_level = 0;
        let header = read(at, 4)?;
        let unpacked = (usize::from(control & 0x1f) << 16)
            + usize::from(u16::from_be_bytes([header[0], header[1]])) + 1;
        let packed = usize::from(u16::from_be_bytes([header[2], header[3]])) + 1;
        at += 4;
        if control >= 0xE0 {
            start = out.len();
        }
        if control >= 0xC0 {
            let props = Properties::from_byte(read(at, 1)?[0])?;
            at += 1;
            if props.lc + props.lp > 4 {
                return Err("LZMA2: lc + lp is more than 4.".to_string());
            }
            state = Some(State::new(props));
        } else if control >= 0xA0 {
            let props = state.as_ref().map(|s| s.props).ok_or("LZMA2: no state to reset.")?;
            state = Some(State::new(props));
        }
        let chunk = read(at, packed)?;
        at += packed;
        let decoder = state.as_mut().ok_or("LZMA2: no state.")?;
        let end = out.len() + unpacked;
        if end > size {
            return Err("LZMA2: more data than the declared size.".to_string());
        }
        let mut rc = RangeDecoder::new(chunk)?;
        decoder.run(&mut rc, &mut out, start, end, dict_size)?;
        if rc.at != chunk.len() {
            return Err("LZMA2: a chunk's packed size does not match its data.".to_string());
        }
    }
    if out.len() != size {
        return Err(format!("LZMA2: {} bytes where {size} were declared.", out.len()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive, fixtures};

    /// The properties, packed stream and unpacked size of the one coder
    /// in a recorded archive's only folder.
    fn stream(name: &str) -> (Vec<u8>, Vec<u8>, usize) {
        let data = std::fs::read(fixtures::dir().join("sevenzip").join(name)).unwrap();
        let archive = archive::open(data.clone(), None).unwrap();
        let s = &archive.streams;
        assert_eq!((s.folders.len(), s.folders[0].coders.len(), s.pack_sizes.len()), (1, 1, 1),
                   "{name}");
        let start = 32 + s.pack_pos as usize;
        let packed = data[start..start + s.pack_sizes[0] as usize].to_vec();
        let folder = &s.folders[0];
        (folder.coders[0].properties.clone(), packed, folder.unpack_sizes[0] as usize)
    }

    /// The control bytes of an LZMA2 stream's chunks.
    fn controls(packed: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0;
        while packed[at] != 0 {
            let control = packed[at];
            out.push(control);
            let size = |i: usize| usize::from(u16::from_be_bytes([packed[i], packed[i + 1]])) + 1;
            at += if control < 0x80 { 3 + size(at + 1) }
                  else { 5 + usize::from(control >= 0xc0) + size(at + 3) };
        }
        out
    }

    /// The recorded streams hold the chunk sequences the tests below
    /// rely on: liblzma resetting the state alone after a stored chunk,
    /// and a stored chunk resetting the dictionary.
    #[test]
    fn test_the_recorded_lzma2_streams_have_the_chunks_they_are_kept_for() {
        assert_eq!(controls(&stream("xz-state.7z").1), [0xe0, 0x02, 0xa0]);
        assert_eq!(controls(&stream("xz-stored.7z").1), [0x01, 0xc0]);
        let blocks = controls(&stream("LZMA2-blocks.7z").1);
        assert!(blocks.iter().filter(|&&c| c == 0xe0).count() > 2 && blocks.contains(&1),
                "{blocks:x?}");
    }

    /// LzmaDec.c counts positions - which pick the literal and match
    /// contexts through `lp` and `pb` - from the last dictionary reset,
    /// whether an LZMA chunk (0xE0 and up) or a stored one (control 1)
    /// made it. Three streams joined, the first of a length that is not
    /// a multiple of 2^pb, decode to their parts. This cannot tell that
    /// rule from counting from the start of the output: every dictionary
    /// reset is followed by fresh probabilities before the next LZMA
    /// chunk (`needInitLevel`, enforced in `decode_lzma2`), and a
    /// constant offset into fresh tables only relabels the contexts, so
    /// the other counting is an equivalent mutant.
    #[test]
    fn test_a_dictionary_reset_counts_positions_from_itself() {
        let parts = [stream("LZMA2.7z"), stream("xz-stored.7z"), stream("xz-state.7z")];
        assert_ne!(parts[0].2 % 4, 0, "the first stream must leave the positions unaligned");
        assert_eq!(parts[1].1[0], 1, "xz-stored starts with a stored chunk that resets");
        let mut joined = Vec::new();
        let mut expected = Vec::new();
        for (i, (props, packed, size)) in parts.iter().enumerate() {
            assert_eq!(packed.last(), Some(&0));
            expected.extend(decode_lzma2(props, packed, *size).unwrap());
            joined.extend_from_slice(if i < 2 { &packed[..packed.len() - 1] } else { packed });
        }
        let dict = parts.iter().map(|p| p.0[0]).max().unwrap();
        assert!(decode_lzma2(&[dict], &joined, expected.len()).unwrap() == expected);
    }

    /// A stored chunk with control 1 starts the dictionary again, so the
    /// chunk after it may refer back only into what it stored. Here the
    /// stored chunk is cut to its last 1000 bytes, and the LZMA chunk
    /// after it has a match reaching back to the stored chunk's start,
    /// 64,600 bytes; the stream before is longer than that, so the bytes
    /// it would reach are in memory.
    #[test]
    fn test_a_stored_chunk_that_resets_the_dictionary_starts_it_again() {
        let (_, before, before_size) = stream("xz-state.7z");
        assert!(before_size > 70_000);
        let (props, packed, size) = stream("xz-stored.7z");
        assert_eq!(packed[0], 1);
        let stored = usize::from(u16::from_be_bytes([packed[1], packed[2]])) + 1;
        let mut joined = before[..before.len() - 1].to_vec();
        joined.extend_from_slice(&[1, 0x03, 0xe7]);
        joined.extend_from_slice(&packed[3 + stored - 1000..]);
        let total = before_size + 1000 + size - stored;
        // Refused at that match, not later: a decoder that let it through
        // copies the wrong bytes and fails somewhere else on the noise.
        let error = decode_lzma2(&props, &joined, total).unwrap_err();
        assert_eq!(error, "LZMA: a distance of 64600 reaches before the dictionary.");
        // The whole stored chunk, and it decodes.
        let mut whole = before[..before.len() - 1].to_vec();
        whole.extend_from_slice(&packed);
        assert!(decode_lzma2(&props, &whole, before_size + size).is_ok());
    }

    /// A stream that refers further back than its declared dictionary is
    /// refused, though every byte it refers to is still in memory.
    #[test]
    fn test_a_distance_past_the_declared_dictionary_is_refused() {
        let (props, packed, size) = stream("LZMA.7z");
        assert!(decode_lzma(&props, &packed, size).is_ok());
        let mut small = props.clone();
        small[1..].copy_from_slice(&4096u32.to_le_bytes());
        let error = decode_lzma(&small, &packed, size).unwrap_err();
        assert!(error.contains("before the dictionary"), "{error}");

        let (props, packed, size) = stream("LZMA2.7z");
        assert!(decode_lzma2(&props, &packed, size).is_ok());
        let error = decode_lzma2(&[0], &packed, size).unwrap_err();
        assert!(error.contains("before the dictionary"), "{error}");
    }

    /// Each LZMA chunk starts its own range coder and must end exactly
    /// where its packed size says.
    #[test]
    fn test_a_chunk_must_use_exactly_its_packed_size() {
        let (props, packed, size) = stream("xz-state.7z");
        assert!(packed[0] >= 0xe0);
        let length = usize::from(u16::from_be_bytes([packed[3], packed[4]])) + 1;
        let mut longer = packed.clone();
        longer[3..5].copy_from_slice(&(length as u16).to_be_bytes());
        longer.insert(6 + length, 0);
        let error = decode_lzma2(&props, &longer, size).unwrap_err();
        assert!(error.contains("packed size"), "{error}");
    }

    /// Lzma2Dec.c's `needInitLevel`: the first chunk resets the
    /// dictionary, and an LZMA chunk after a stored chunk that did so
    /// brings its own properties.
    #[test]
    fn test_a_chunk_without_the_resets_it_needs_is_refused() {
        let refused = |props: &[u8], packed: &[u8], size| {
            let error = decode_lzma2(props, packed, size).unwrap_err();
            assert!(error.contains("before the resets it needs") || error.contains("control byte"),
                    "{error}");
        };
        // An LZMA chunk with properties and a state reset, but not the
        // dictionary reset a first chunk needs.
        let (props, packed, size) = stream("xz-state.7z");
        let mut first = packed.clone();
        first[0] = 0xc0 | (packed[0] & 0x1f);
        refused(&props, &first, size);
        // A first stored chunk that keeps a dictionary there is none of.
        let (stored_props, stored, stored_size) = stream("xz-stored.7z");
        let mut keeps = stored.clone();
        keeps[0] = 2;
        refused(&stored_props, &keeps, stored_size);
        // A stored chunk that resets the dictionary, then an LZMA chunk
        // that resets the state but brings no properties.
        let mut joined = vec![1, 0, 0, b'x', 0xa0 | (packed[0] & 0x1f)];
        joined.extend_from_slice(&packed[1..5]);
        joined.extend_from_slice(&packed[6..]);
        let error = decode_lzma2(&props, &joined, size + 1).unwrap_err();
        assert!(error.contains("before the resets it needs"), "{error}");
    }

    /// An end marker where the declared size says there is more data.
    #[test]
    fn test_an_early_end_marker_is_refused() {
        let (props, packed, size) = stream("LZMA-eos.7z");
        assert!(decode_lzma(&props, &packed, size).is_ok());
        let error = decode_lzma(&props, &packed, size + 1).unwrap_err();
        assert!(error.contains("end marker"), "{error}");
    }

    /// Cut short, a stream decodes to a prefix of itself or - when the
    /// cut falls inside a match - is refused, never overrun.
    #[test]
    fn test_a_match_may_not_run_past_the_declared_size() {
        let (props, packed, size) = stream("LZMA.7z");
        let full = decode_lzma(&props, &packed, size).unwrap();
        let mut refused = 0;
        for cut in size - 300..size {
            match decode_lzma(&props, &packed, cut) {
                Ok(out) => assert!(out == full[..cut], "{cut}"),
                Err(error) => {
                    assert!(error.contains("past the declared size"), "{cut}: {error}");
                    refused += 1;
                }
            }
        }
        assert!(refused > 10, "{refused}");
    }
}
