//! The 7z container (`DOC/7zFormat.txt` in the 7-Zip sources): the
//! signature header, the property-tagged header - possibly itself packed
//! and encrypted - folders of coders, and the files that the folders'
//! unpacked streams are cut into.

use allcrypt::checksum::crc32;
use crate::{coders, lzma};

pub const SIGNATURE: [u8; 6] = [b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c];

mod id {
    pub const END: u8 = 0x00;
    pub const HEADER: u8 = 0x01;
    pub const ARCHIVE_PROPERTIES: u8 = 0x02;
    pub const ADDITIONAL_STREAMS: u8 = 0x03;
    pub const MAIN_STREAMS: u8 = 0x04;
    pub const FILES: u8 = 0x05;
    pub const PACK_INFO: u8 = 0x06;
    pub const UNPACK_INFO: u8 = 0x07;
    pub const SUBSTREAMS: u8 = 0x08;
    pub const SIZE: u8 = 0x09;
    pub const CRC: u8 = 0x0a;
    pub const FOLDER: u8 = 0x0b;
    pub const UNPACK_SIZE: u8 = 0x0c;
    pub const NUM_UNPACK_STREAM: u8 = 0x0d;
    pub const EMPTY_STREAM: u8 = 0x0e;
    pub const EMPTY_FILE: u8 = 0x0f;
    pub const ANTI: u8 = 0x10;
    pub const NAME: u8 = 0x11;
    pub const MTIME: u8 = 0x14;
    pub const ATTRIBUTES: u8 = 0x15;
    pub const ENCODED_HEADER: u8 = 0x17;
}

/// The most a header, or a folder, may unpack to here.
pub const LIMIT: usize = 1 << 30;

// ------------------------------------------------------------------ reading --

pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, at: 0 }
    }

    fn byte(&mut self) -> Result<u8, String> {
        let b = *self.data.get(self.at).ok_or("7z: the header ends early.")?;
        self.at += 1;
        Ok(b)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let out = self.data.get(self.at..self.at.checked_add(n).ok_or("7z: a size overflows.")?)
            .ok_or("7z: the header ends early.")?;
        self.at += n;
        Ok(out)
    }

    /// 7z's UINT64: the first byte's leading ones say how many bytes
    /// follow, and its remaining bits are the value's top.
    fn number(&mut self) -> Result<u64, String> {
        let first = self.byte()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                let high = u64::from(first & mask.wrapping_sub(1));
                return Ok(value | (high << (8 * i)));
            }
            value |= u64::from(self.byte()?) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    fn count(&mut self, what: &str) -> Result<usize, String> {
        let n = self.number()?;
        if n > 1 << 24 {
            return Err(format!("7z: {n} {what} is more than this reads."));
        }
        Ok(n as usize)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn expect(&mut self, tag: u8) -> Result<(), String> {
        let got = self.byte()?;
        if got != tag {
            return Err(format!("7z: property {got:#04x} where {tag:#04x} belongs."));
        }
        Ok(())
    }

    /// A bit vector, most significant bit first, or "all defined".
    fn bits(&mut self, n: usize) -> Result<Vec<bool>, String> {
        let mut out = Vec::with_capacity(n);
        let mut byte = 0u8;
        for i in 0..n {
            if i % 8 == 0 {
                byte = self.byte()?;
            }
            out.push(byte & (0x80 >> (i % 8)) != 0);
        }
        Ok(out)
    }

    fn defined(&mut self, n: usize) -> Result<Vec<bool>, String> {
        if self.byte()? != 0 { Ok(vec![true; n]) } else { self.bits(n) }
    }

    fn digests(&mut self, n: usize) -> Result<Vec<Option<u32>>, String> {
        let defined = self.defined(n)?;
        defined.into_iter().map(|d| if d { self.u32().map(Some) } else { Ok(None) }).collect()
    }
}

#[derive(Clone, Debug)]
pub struct Coder {
    pub id: Vec<u8>,
    pub inputs: usize,
    pub outputs: usize,
    pub properties: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Folder {
    pub coders: Vec<Coder>,
    /// (input index, output index), across all coders' streams.
    pub binds: Vec<(usize, usize)>,
    /// The folder's inputs that are packed streams, in pack order.
    pub packed: Vec<usize>,
    /// One per coder output.
    pub unpack_sizes: Vec<u64>,
    pub crc: Option<u32>,
}

impl Folder {
    /// The output nothing consumes: the folder's result.
    pub fn main_output(&self) -> Result<usize, String> {
        let total: usize = self.coders.iter().map(|c| c.outputs).sum();
        (0..total).find(|o| !self.binds.iter().any(|(_, out)| out == o))
            .ok_or_else(|| "7z: a folder with no unbound output.".to_string())
    }

    pub fn unpack_size(&self) -> Result<u64, String> {
        Ok(self.unpack_sizes[self.main_output()?])
    }
}

#[derive(Debug, Default)]
pub struct Streams {
    pub pack_pos: u64,
    pub pack_sizes: Vec<u64>,
    pub folders: Vec<Folder>,
    /// Per folder: its files' sizes and CRCs.
    pub substream_sizes: Vec<Vec<u64>>,
    pub substream_crcs: Vec<Vec<Option<u32>>>,
}

fn folder(r: &mut Reader) -> Result<Folder, String> {
    let count = r.count("coders")?;
    if count == 0 || count > 64 {
        return Err(format!("7z: a folder with {count} coders."));
    }
    let mut coders = Vec::new();
    for _ in 0..count {
        let flags = r.byte()?;
        if flags & 0xc0 != 0 {
            return Err("7z: a coder with alternative methods or reserved bits.".to_string());
        }
        let id = r.bytes(usize::from(flags & 0x0f))?.to_vec();
        let (inputs, outputs) = if flags & 0x10 != 0 {
            (r.count("inputs")?, r.count("outputs")?)
        } else {
            (1, 1)
        };
        if inputs > 64 || outputs != 1 {
            return Err("7z: a coder with more than one output.".to_string());
        }
        let properties = if flags & 0x20 != 0 {
            let n = r.count("property bytes")?;
            r.bytes(n)?.to_vec()
        } else {
            Vec::new()
        };
        coders.push(Coder { id, inputs, outputs, properties });
    }
    let total_outputs: usize = coders.iter().map(|c| c.outputs).sum();
    let total_inputs: usize = coders.iter().map(|c| c.inputs).sum();
    let mut binds = Vec::new();
    for _ in 0..total_outputs - 1 {
        binds.push((r.count("an input index")?, r.count("an output index")?));
    }
    if total_inputs < binds.len() {
        return Err("7z: more bindings than inputs.".to_string());
    }
    let packed_count = total_inputs - binds.len();
    let packed = if packed_count == 1 {
        vec![(0..total_inputs).find(|i| !binds.iter().any(|(input, _)| input == i))
             .ok_or("7z: a folder with no packed input.")?]
    } else {
        (0..packed_count).map(|_| r.count("a packed index")).collect::<Result<_, _>>()?
    };
    Ok(Folder { coders, binds, packed, unpack_sizes: Vec::new(), crc: None })
}

fn streams(r: &mut Reader) -> Result<Streams, String> {
    let mut s = Streams::default();
    let mut tag = r.byte()?;
    if tag == id::PACK_INFO {
        s.pack_pos = r.number()?;
        let n = r.count("packed streams")?;
        loop {
            match r.byte()? {
                id::END => break,
                id::SIZE => s.pack_sizes = (0..n).map(|_| r.number()).collect::<Result<_, _>>()?,
                id::CRC => {
                    r.digests(n)?;
                }
                other => return Err(format!("7z: property {other:#04x} in PackInfo.")),
            }
        }
        if s.pack_sizes.len() != n {
            return Err("7z: PackInfo without sizes.".to_string());
        }
        tag = r.byte()?;
    }
    if tag == id::UNPACK_INFO {
        r.expect(id::FOLDER)?;
        let n = r.count("folders")?;
        if r.byte()? != 0 {
            return Err("7z: folders kept outside the header.".to_string());
        }
        s.folders = (0..n).map(|_| folder(r)).collect::<Result<_, _>>()?;
        r.expect(id::UNPACK_SIZE)?;
        for f in &mut s.folders {
            let outputs: usize = f.coders.iter().map(|c| c.outputs).sum();
            f.unpack_sizes = (0..outputs).map(|_| r.number()).collect::<Result<_, _>>()?;
        }
        loop {
            match r.byte()? {
                id::END => break,
                id::CRC => {
                    for (f, crc) in s.folders.iter_mut().zip(r.digests(n)?) {
                        f.crc = crc;
                    }
                }
                other => return Err(format!("7z: property {other:#04x} in UnpackInfo.")),
            }
        }
        tag = r.byte()?;
    }
    let folders = s.folders.len();
    let mut counts = vec![1usize; folders];
    if tag == id::SUBSTREAMS {
        tag = r.byte()?;
        if tag == id::NUM_UNPACK_STREAM {
            counts = (0..folders).map(|_| r.count("files in a folder")).collect::<Result<_, _>>()?;
            tag = r.byte()?;
        }
        let mut sizes = Vec::new();
        let read_sizes = tag == id::SIZE;
        for (f, &count) in s.folders.iter().zip(&counts) {
            if count == 0 {
                sizes.push(Vec::new());
                continue;
            }
            let total = f.unpack_size()?;
            let mut these = Vec::new();
            let mut sum = 0u64;
            if read_sizes {
                for _ in 1..count {
                    let size = r.number()?;
                    sum = sum.checked_add(size).ok_or("7z: substream sizes overflow.")?;
                    these.push(size);
                }
            }
            these.push(total.checked_sub(sum).ok_or("7z: substreams larger than the folder.")?);
            if these.len() != count {
                return Err("7z: substreams without their sizes.".to_string());
            }
            sizes.push(these);
        }
        if read_sizes {
            tag = r.byte()?;
        }
        // CRCs for the substreams whose folder's CRC does not cover them.
        let mut crcs: Vec<Vec<Option<u32>>> = s.folders.iter().zip(&counts)
            .map(|(f, &count)| if count == 1 && f.crc.is_some() { vec![f.crc] }
                               else { vec![None; count] })
            .collect();
        while tag != id::END {
            if tag == id::CRC {
                let missing: usize = s.folders.iter().zip(&counts)
                    .map(|(f, &count)| if count == 1 && f.crc.is_some() { 0 } else { count })
                    .sum();
                let mut digests = r.digests(missing)?.into_iter();
                for (i, (f, &count)) in s.folders.iter().zip(&counts).enumerate() {
                    if count == 1 && f.crc.is_some() {
                        continue;
                    }
                    for slot in crcs[i].iter_mut() {
                        *slot = digests.next().flatten();
                    }
                }
            } else {
                return Err(format!("7z: property {tag:#04x} in SubStreamsInfo."));
            }
            tag = r.byte()?;
        }
        s.substream_sizes = sizes;
        s.substream_crcs = crcs;
        tag = r.byte()?;
    } else {
        s.substream_sizes = s.folders.iter().map(|f| f.unpack_size().map(|n| vec![n]))
            .collect::<Result<_, _>>()?;
        s.substream_crcs = s.folders.iter().map(|f| vec![f.crc]).collect();
    }
    if tag != id::END {
        return Err(format!("7z: property {tag:#04x} at the end of StreamsInfo."));
    }
    Ok(s)
}

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub name: String,
    pub has_stream: bool,
    pub is_dir: bool,
    pub is_anti: bool,
    pub size: u64,
    pub crc: Option<u32>,
    pub mtime: Option<u64>,
    pub attributes: Option<u32>,
}

pub struct Archive {
    pub streams: Streams,
    pub entries: Vec<Entry>,
    /// Whether the header itself was encrypted.
    pub header_encrypted: bool,
    pub data: Vec<u8>,
}

const PACK_START: u64 = 32;

/// Decode one folder of `streams`: its packed streams out of `data`,
/// through its coders.
pub fn unpack_folder(data: &[u8], streams: &Streams, index: usize, password: Option<&[u8]>)
                     -> Result<Vec<u8>, String> {
    let folder = &streams.folders[index];
    let first_pack: usize = streams.folders[..index].iter().map(|f| f.packed.len()).sum();
    let mut offset = PACK_START + streams.pack_pos
        + streams.pack_sizes[..first_pack].iter().sum::<u64>();
    let mut packed = Vec::new();
    for size in &streams.pack_sizes[first_pack..first_pack + folder.packed.len()] {
        let start = usize::try_from(offset).map_err(|_| "7z: an offset past memory.")?;
        let end = start.checked_add(*size as usize).ok_or("7z: a size overflows.")?;
        packed.push(data.get(start..end).ok_or("7z: a packed stream past the end of the \
                                                  file.")?);
        offset += size;
    }
    // Under 7zAES a wrong password is noticed only downstream - by the
    // decompressor, a parser, or a CRC - so any failure there may be one.
    let encrypted = folder.coders.iter().any(coders::is_aes);
    let suspect = |e: String| if encrypted && password.is_some() {
        format!("Wrong password, or the archive is damaged: {e}")
    } else {
        e
    };
    let out = coders::decode_folder(folder, &packed, password).map_err(suspect)?;
    if let Some(crc) = folder.crc {
        if crc32(&out) != crc {
            return Err(suspect("7z: a folder's CRC does not match.".to_string()));
        }
    }
    Ok(out)
}

fn utf16_names(bytes: &[u8], n: usize) -> Result<Vec<String>, String> {
    if !bytes.len().is_multiple_of(2) {
        return Err("7z: names of an odd length.".to_string());
    }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let names: Vec<String> = units.split(|&u| u == 0).take(n)
        .map(|name| String::from_utf16(name).map_err(|_| "7z: a name that is not UTF-16."))
        .collect::<Result<_, _>>()?;
    if names.len() != n || units.last() != Some(&0) {
        return Err("7z: fewer names than files.".to_string());
    }
    Ok(names)
}

fn files(r: &mut Reader, streams: &Streams) -> Result<Vec<Entry>, String> {
    let n = r.count("files")?;
    let mut entries = vec![Entry::default(); n];
    let mut empty_stream = vec![false; n];
    let mut empty_file = Vec::new();
    let mut anti = Vec::new();
    loop {
        let tag = r.byte()?;
        if tag == id::END {
            break;
        }
        let size = r.count("property bytes")?;
        let body = r.bytes(size)?;
        let mut p = Reader::new(body);
        match tag {
            id::EMPTY_STREAM => empty_stream = p.bits(n)?,
            id::EMPTY_FILE => empty_file = p.bits(empty_stream.iter().filter(|&&e| e).count())?,
            id::ANTI => anti = p.bits(empty_stream.iter().filter(|&&e| e).count())?,
            id::NAME => {
                if p.byte()? != 0 {
                    return Err("7z: names kept outside the header.".to_string());
                }
                for (entry, name) in entries.iter_mut().zip(utf16_names(&body[1..], n)?) {
                    entry.name = name;
                }
            }
            id::MTIME => {
                let defined = p.defined(n)?;
                if p.byte()? != 0 {
                    return Err("7z: times kept outside the header.".to_string());
                }
                for (entry, d) in entries.iter_mut().zip(defined) {
                    if d {
                        entry.mtime = Some(p.u64()?);
                    }
                }
            }
            id::ATTRIBUTES => {
                let defined = p.defined(n)?;
                if p.byte()? != 0 {
                    return Err("7z: attributes kept outside the header.".to_string());
                }
                for (entry, d) in entries.iter_mut().zip(defined) {
                    if d {
                        entry.attributes = Some(p.u32()?);
                    }
                }
            }
            // Creation and access times, start positions, padding: not
            // needed to extract, and skipped whole.
            _ => {}
        }
    }
    let mut empties = 0;
    let mut sizes = streams.substream_sizes.iter().flatten();
    let mut crcs = streams.substream_crcs.iter().flatten();
    for (i, entry) in entries.iter_mut().enumerate() {
        if empty_stream[i] {
            entry.is_dir = !empty_file.get(empties).copied().unwrap_or(false);
            entry.is_anti = anti.get(empties).copied().unwrap_or(false);
            empties += 1;
        } else {
            entry.has_stream = true;
            entry.size = *sizes.next().ok_or("7z: more files with data than streams.")?;
            entry.crc = *crcs.next().ok_or("7z: more files with data than streams.")?;
        }
    }
    if sizes.next().is_some() {
        return Err("7z: more streams than files with data.".to_string());
    }
    Ok(entries)
}

/// Open an archive: the signature header, then the header, unpacking
/// and decrypting it when it is encoded.
pub fn open(data: Vec<u8>, password: Option<&[u8]>) -> Result<Archive, String> {
    if data.len() < 32 || data[..6] != SIGNATURE {
        return Err("Not a 7z archive.".to_string());
    }
    if data[6] != 0 {
        return Err(format!("7z version {}.{}, not 0.x.", data[6], data[7]));
    }
    if crc32(&data[12..32]) != u32::from_le_bytes(data[8..12].try_into().unwrap()) {
        return Err("7z: the start header's CRC does not match.".to_string());
    }
    let mut start = Reader::new(&data[12..32]);
    let (offset, size, crc) = (start.u64()?, start.u64()?, start.u32()?);
    let begin = 32u64.checked_add(offset).ok_or("7z: a header offset overflows.")?;
    let end = begin.checked_add(size).ok_or("7z: a header size overflows.")?;
    let header = data.get(begin as usize..end as usize)
        .ok_or("7z: the header is past the end of the file.")?;
    if crc32(header) != crc {
        return Err("7z: the header's CRC does not match.".to_string());
    }
    let mut header = header.to_vec();
    let mut header_encrypted = false;
    // Once a header has come out of 7zAES, anything wrong with what
    // follows may be the password: the decryption itself cannot fail.
    let suspect = |encrypted: bool, e: String| {
        if encrypted && !e.starts_with("Wrong password") {
            format!("Wrong password, or the archive is damaged: {e}")
        } else {
            e
        }
    };
    loop {
        let encrypted = header_encrypted;
        let next = (|| {
            let mut r = Reader::new(&header);
            match r.byte()? {
                id::HEADER => parse_header(&header).map(|(s, e)| Next::Parsed(s, e)),
                id::ENCODED_HEADER => {
                    let encoded = streams(&mut r)?;
                    if encoded.folders.len() != 1 {
                        return Err("7z: an encoded header of several folders.".to_string());
                    }
                    header_encrypted |= encoded.folders[0].coders.iter().any(coders::is_aes);
                    unpack_folder(&data, &encoded, 0, password).map(Next::Encoded)
                }
                other => Err(format!("7z: a header that starts {other:#04x}.")),
            }
        })().map_err(|e| suspect(encrypted, e))?;
        match next {
            Next::Encoded(unpacked) => header = unpacked,
            Next::Parsed(streams, entries) => {
                return Ok(Archive { streams, entries, header_encrypted, data });
            }
        }
    }
}

/// What one header holds: another header, packed, or the archive's
/// streams and files.
enum Next {
    Encoded(Vec<u8>),
    Parsed(Streams, Vec<Entry>),
}

fn parse_header(header: &[u8]) -> Result<(Streams, Vec<Entry>), String> {
    let mut r = Reader::new(header);
    r.expect(id::HEADER)?;
    let mut tag = r.byte()?;
    if tag == id::ARCHIVE_PROPERTIES {
        loop {
            if r.byte()? == 0 {
                break;
            }
            let n = r.count("property bytes")?;
            r.bytes(n)?;
        }
        tag = r.byte()?;
    }
    if tag == id::ADDITIONAL_STREAMS {
        return Err("7z: additional streams are not supported.".to_string());
    }
    let mut streams_info = Streams::default();
    if tag == id::MAIN_STREAMS {
        streams_info = streams(&mut r)?;
        tag = r.byte()?;
    }
    let mut entries = Vec::new();
    if tag == id::FILES {
        entries = files(&mut r, &streams_info)?;
        tag = r.byte()?;
    }
    if tag != id::END {
        return Err(format!("7z: property {tag:#04x} at the end of the header."));
    }
    Ok((streams_info, entries))
}

impl Archive {
    /// Every file's contents, in order, `None` for those without data.
    pub fn extract(&self, password: Option<&[u8]>) -> Result<Vec<Option<Vec<u8>>>, String> {
        let mut out = Vec::new();
        let mut entries = self.entries.iter();
        for (index, sizes) in self.streams.substream_sizes.iter().enumerate() {
            if sizes.is_empty() {
                continue;
            }
            let unpacked = unpack_folder(&self.data, &self.streams, index, password)?;
            let encrypted = self.streams.folders[index].coders.iter().any(coders::is_aes);
            let mut at = 0usize;
            for &size in sizes {
                let entry = loop {
                    let entry = entries.next().ok_or("7z: more streams than files.")?;
                    if entry.has_stream {
                        break entry;
                    }
                    out.push(None);
                };
                let piece = &unpacked[at..at + size as usize];
                at += size as usize;
                if let Some(crc) = entry.crc {
                    if crc32(piece) != crc {
                        return Err(if encrypted {
                            format!("Wrong password, or the archive is damaged: {}'s CRC does \
                                     not match.", entry.name)
                        } else {
                            format!("{}: the CRC does not match.", entry.name)
                        });
                    }
                }
                out.push(Some(piece.to_vec()));
            }
        }
        for entry in entries {
            if entry.has_stream {
                return Err("7z: a file with data and no stream.".to_string());
            }
            out.push(None);
        }
        Ok(out)
    }
}

// ------------------------------------------------------------------ writing --

fn write_number(out: &mut Vec<u8>, value: u64) {
    // The first byte's leading ones count the bytes that follow.
    let mut extra = 0;
    while extra < 8 && value >= 1u64 << (7 * (extra + 1)) {
        extra += 1;
    }
    if extra == 8 {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
        return;
    }
    let high = (value >> (8 * extra)) as u8;
    let mask = !(0xffu8 >> extra);
    out.push(mask | high);
    out.extend_from_slice(&value.to_le_bytes()[..extra]);
}

fn write_bits(out: &mut Vec<u8>, bits: &[bool]) {
    for chunk in bits.chunks(8) {
        out.push(chunk.iter().enumerate().fold(0u8, |b, (i, &on)| b | (u8::from(on) << (7 - i))));
    }
}

pub struct NewFile {
    pub name: String,
    pub data: Option<Vec<u8>>,
    pub mtime: Option<u64>,
}

/// How to write: the folder's coders and whether the header is
/// encrypted too.
pub struct WriteOptions<'a> {
    pub password: Option<&'a [u8]>,
    pub encrypt_header: bool,
    pub cycles_power: u8,
}

fn streams_info(out: &mut Vec<u8>, pack_pos: u64, pack_size: u64, coders: &[Coder],
                unpack_sizes: &[u64], folder_crc: Option<u32>, substreams: Option<&[(u64, u32)]>) {
    out.push(id::PACK_INFO);
    write_number(out, pack_pos);
    write_number(out, 1);
    out.push(id::SIZE);
    write_number(out, pack_size);
    out.push(id::END);
    out.push(id::UNPACK_INFO);
    out.push(id::FOLDER);
    write_number(out, 1);
    out.push(0);
    write_number(out, coders.len() as u64);
    for coder in coders {
        let mut flags = coder.id.len() as u8;
        if !coder.properties.is_empty() {
            flags |= 0x20;
        }
        out.push(flags);
        out.extend_from_slice(&coder.id);
        if !coder.properties.is_empty() {
            write_number(out, coder.properties.len() as u64);
            out.extend_from_slice(&coder.properties);
        }
    }
    // A chain: coder i's input is coder i+1's output.
    for i in 0..coders.len() - 1 {
        write_number(out, i as u64);
        write_number(out, i as u64 + 1);
    }
    out.push(id::UNPACK_SIZE);
    for size in unpack_sizes {
        write_number(out, *size);
    }
    if let Some(crc) = folder_crc {
        out.push(id::CRC);
        out.push(1);
        out.extend_from_slice(&crc.to_le_bytes());
    }
    out.push(id::END);
    if let Some(substreams) = substreams {
        out.push(id::SUBSTREAMS);
        out.push(id::NUM_UNPACK_STREAM);
        write_number(out, substreams.len() as u64);
        if substreams.len() > 1 {
            out.push(id::SIZE);
            for (size, _) in &substreams[..substreams.len() - 1] {
                write_number(out, *size);
            }
        }
        out.push(id::CRC);
        out.push(1);
        for (_, crc) in substreams {
            out.extend_from_slice(&crc.to_le_bytes());
        }
        out.push(id::END);
    }
    out.push(id::END);
}

/// Pack `data` with the Copy method, or under AES with the given
/// password: the coder and the packed bytes.
fn pack(data: &[u8], options: &WriteOptions) -> Result<(Coder, Vec<u8>), String> {
    match options.password {
        None => Ok((Coder { id: vec![0], inputs: 1, outputs: 1, properties: Vec::new() },
                    data.to_vec())),
        Some(password) => {
            let (properties, packed) = coders::aes_encrypt(data, password, options.cycles_power)?;
            Ok((Coder { id: coders::AES_ID.to_vec(), inputs: 1, outputs: 1, properties }, packed))
        }
    }
}

/// Write an archive of `files`, solid, stored: every file's data in one
/// folder, encrypted when there is a password.
pub fn write(files: &[NewFile], options: &WriteOptions) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut substreams = Vec::new();
    for file in files {
        if let Some(data) = &file.data {
            if !data.is_empty() {
                body.extend_from_slice(data);
                substreams.push((data.len() as u64, crc32(data)));
            }
        }
    }
    let mut packed_all = Vec::new();
    let mut header = vec![id::HEADER];
    if !substreams.is_empty() {
        let (coder, packed) = pack(&body, options)?;
        header.push(id::MAIN_STREAMS);
        streams_info(&mut header, 0, packed.len() as u64, &[coder], &[body.len() as u64], None,
                     Some(&substreams));
        packed_all = packed;
    }
    header.push(id::FILES);
    write_number(&mut header, files.len() as u64);
    let empty: Vec<bool> = files.iter().map(|f| f.data.as_ref().is_none_or(|d| d.is_empty()))
        .collect();
    if empty.iter().any(|&e| e) {
        let mut bits = Vec::new();
        write_bits(&mut bits, &empty);
        header.push(id::EMPTY_STREAM);
        write_number(&mut header, bits.len() as u64);
        header.extend_from_slice(&bits);
        // Among the empty ones: an empty file, or a directory.
        let files_among: Vec<bool> = files.iter().zip(&empty).filter(|(_, &e)| e)
            .map(|(f, _)| f.data.is_some()).collect();
        let mut bits = Vec::new();
        write_bits(&mut bits, &files_among);
        header.push(id::EMPTY_FILE);
        write_number(&mut header, bits.len() as u64);
        header.extend_from_slice(&bits);
    }
    let mut names = vec![0u8];
    for file in files {
        for unit in file.name.encode_utf16().chain(std::iter::once(0)) {
            names.extend_from_slice(&unit.to_le_bytes());
        }
    }
    header.push(id::NAME);
    write_number(&mut header, names.len() as u64);
    header.extend_from_slice(&names);
    if files.iter().any(|f| f.mtime.is_some()) {
        let mut times = Vec::new();
        let defined: Vec<bool> = files.iter().map(|f| f.mtime.is_some()).collect();
        if defined.iter().all(|&d| d) {
            times.push(1);
        } else {
            times.push(0);
            write_bits(&mut times, &defined);
        }
        times.push(0);
        for time in files.iter().filter_map(|f| f.mtime) {
            times.extend_from_slice(&time.to_le_bytes());
        }
        header.push(id::MTIME);
        write_number(&mut header, times.len() as u64);
        header.extend_from_slice(&times);
    }
    // Directories carry FILE_ATTRIBUTE_DIRECTORY, as 7-Zip writes them.
    let attributes: Vec<u32> = files.iter()
        .map(|f| if f.data.is_none() { 0x10 } else { 0x20 }).collect();
    let mut body_attributes = vec![1u8, 0];
    for a in &attributes {
        body_attributes.extend_from_slice(&a.to_le_bytes());
    }
    header.push(id::ATTRIBUTES);
    write_number(&mut header, body_attributes.len() as u64);
    header.extend_from_slice(&body_attributes);
    header.push(id::END);
    header.push(id::END);

    // The header, encoded under AES when asked to be.
    let mut tail = header;
    let mut packed_header = Vec::new();
    if options.encrypt_header {
        let password = options.password.ok_or("Encrypting the header needs a password.")?;
        let (properties, packed) = coders::aes_encrypt(&tail, password, options.cycles_power)?;
        let coders = vec![Coder { id: coders::AES_ID.to_vec(), inputs: 1, outputs: 1,
                                  properties }];
        let mut encoded = vec![id::ENCODED_HEADER];
        streams_info(&mut encoded, packed_all.len() as u64, packed.len() as u64, &coders,
                     &[tail.len() as u64], Some(crc32(&tail)), None);
        packed_header = packed;
        tail = encoded;
    }
    let mut out = Vec::with_capacity(32 + packed_all.len() + packed_header.len() + tail.len());
    out.extend_from_slice(&SIGNATURE);
    out.extend_from_slice(&[0, 4]);
    let next_offset = (packed_all.len() + packed_header.len()) as u64;
    let mut start = Vec::new();
    start.extend_from_slice(&next_offset.to_le_bytes());
    start.extend_from_slice(&(tail.len() as u64).to_le_bytes());
    start.extend_from_slice(&crc32(&tail).to_le_bytes());
    out.extend_from_slice(&crc32(&start).to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(&packed_all);
    out.extend_from_slice(&packed_header);
    out.extend_from_slice(&tail);
    Ok(out)
}

/// The LZMA2 dictionary size a coder's properties declare, for listing.
pub fn describe_coder(coder: &Coder) -> String {
    let name = coders::name(&coder.id);
    match name {
        "LZMA2" => match lzma::lzma2_dict_size(&coder.properties) {
            Ok(size) => format!("LZMA2:{}", size_name(size)),
            Err(_) => name.to_string(),
        },
        "LZMA" if coder.properties.len() == 5 => {
            let dict = u32::from_le_bytes(coder.properties[1..5].try_into().unwrap());
            format!("LZMA:{}", size_name(dict as usize))
        }
        "7zAES" if !coder.properties.is_empty() => {
            format!("7zAES:2^{}", coder.properties[0] & 0x3f)
        }
        _ => name.to_string(),
    }
}

fn size_name(size: usize) -> String {
    if size >= 1 << 20 && size.is_multiple_of(1 << 20) {
        format!("{}m", size >> 20)
    } else if size >= 1 << 10 && size.is_multiple_of(1 << 10) {
        format!("{}k", size >> 10)
    } else {
        size.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numbers_round_trip_at_every_width() {
        for shift in 0..64 {
            for value in [1u64 << shift, (1u64 << shift) - 1, (1u64 << shift) + 1] {
                let mut out = Vec::new();
                write_number(&mut out, value);
                let mut r = Reader::new(&out);
                assert_eq!(r.number().unwrap(), value, "{value:#x}");
                assert_eq!(r.at, out.len());
            }
        }
        // The format's own examples of the first byte.
        let mut r = Reader::new(&[0x7f, 0x80, 0x80, 0xc0, 0x01, 0x02]);
        assert_eq!(r.number().unwrap(), 0x7f);
        assert_eq!(r.number().unwrap(), 0x80);
        assert_eq!(r.number().unwrap(), 0x0201);
    }
}
