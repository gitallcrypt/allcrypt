//! A PDF file: its cross-reference data, its objects, and a writer.
//!
//! Objects are found through the cross-reference section the last
//! `startxref` points at and the chain of `/Prev` before it: classic
//! tables, cross-reference streams (PDF 1.5) and hybrid files that have
//! both. An object may live inside an object stream, which is itself
//! encrypted as a whole - so it is decrypted as a stream first and the
//! objects in it are not decrypted again.
//!
//! What is never encrypted: the `/Encrypt` dictionary, cross-reference
//! streams, a signature dictionary's `/Contents`, and - when
//! `/EncryptMetadata` is false - metadata streams.

use std::collections::BTreeMap;

use crate::inflate;
use crate::object::{get, remove, set, write, Dict, Object, Parser};
use crate::security::{Method, Security};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Location {
    Offset(usize, u16),
    InStream(u32, u32),
}

pub struct Document {
    pub data: Vec<u8>,
    pub version: String,
    pub xref: BTreeMap<u32, Location>,
    pub trailer: Dict,
    pub security: Option<Security>,
    /// The object number of the `/Encrypt` dictionary, if it is
    /// indirect.
    pub encrypt_object: Option<u32>,
}

fn decode_flate_with_predictor(dict: &Dict, data: &[u8]) -> Result<Vec<u8>, String> {
    let filters: Vec<&[u8]> = match get(dict, "Filter") {
        None => Vec::new(),
        Some(Object::Name(n)) => vec![n.as_slice()],
        Some(Object::Array(items)) => items.iter().filter_map(Object::as_name).collect(),
        Some(_) => return Err("A /Filter that is neither a name nor an array.".to_string()),
    };
    let mut out = data.to_vec();
    for filter in &filters {
        match *filter {
            b"FlateDecode" => out = inflate::zlib_decompress(&out, 1 << 30)?,
            other => return Err(format!("Filter /{} on a structural stream is not supported.",
                                        String::from_utf8_lossy(other))),
        }
    }
    let parms = match get(dict, "DecodeParms") {
        Some(Object::Dictionary(d)) => Some(d),
        Some(Object::Array(items)) => items.first().and_then(Object::as_dict),
        _ => None,
    };
    let predictor = parms.and_then(|p| get(p, "Predictor")).and_then(Object::as_int).unwrap_or(1);
    if predictor >= 10 {
        let columns = parms.and_then(|p| get(p, "Columns")).and_then(Object::as_int).unwrap_or(1)
            as usize;
        out = png_unpredict(&out, columns)?;
    } else if predictor != 1 {
        return Err(format!("Predictor {predictor} is not supported."));
    }
    Ok(out)
}

/// PNG predictors, one filter byte per row, one byte per pixel - the
/// only shape cross-reference streams use.
fn png_unpredict(data: &[u8], columns: usize) -> Result<Vec<u8>, String> {
    let row = columns + 1;
    if columns == 0 || !data.len().is_multiple_of(row) {
        return Err("Predicted data is not a whole number of rows.".to_string());
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut previous = vec![0u8; columns];
    for line in data.chunks(row) {
        let mut current = line[1..].to_vec();
        for i in 0..columns {
            let left = if i > 0 { current[i - 1] } else { 0 };
            let up = previous[i];
            let up_left = if i > 0 { previous[i - 1] } else { 0 };
            current[i] = current[i].wrapping_add(match line[0] {
                0 => 0,
                1 => left,
                2 => up,
                3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                4 => {
                    let p = i16::from(left) + i16::from(up) - i16::from(up_left);
                    let (pa, pb, pc) = ((p - i16::from(left)).abs(), (p - i16::from(up)).abs(),
                                        (p - i16::from(up_left)).abs());
                    if pa <= pb && pa <= pc { left } else if pb <= pc { up } else { up_left }
                }
                other => return Err(format!("PNG filter type {other}.")),
            });
        }
        out.extend_from_slice(&current);
        previous = current;
    }
    Ok(out)
}

fn be(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |acc, &b| (acc << 8) | u64::from(b))
}

/// An offset or count the file gives as an integer object: absent, or
/// a non-negative value. A negative one would become a huge `usize`
/// through `as`, so it is refused by name.
fn non_negative(object: Option<&Object>, what: &str) -> Result<Option<usize>, String> {
    match object {
        None => Ok(None),
        Some(object) => {
            let value = object.as_int().ok_or(format!("/{what} is not an integer."))?;
            usize::try_from(value).map(Some).map_err(|_| format!("/{what} is negative: {value}."))
        }
    }
}

impl Document {
    pub fn parse(mut data: Vec<u8>) -> Result<Document, String> {
        // Leading junk before the header - a mail or HTTP wrapper - is
        // tolerated within the first kilobyte. The offsets in such a
        // file count from the header, not from the first byte, so the
        // junk is dropped; qpdf reads them the same way.
        let header = crate::object::find(&data[..data.len().min(1024)], b"%PDF-")
            .ok_or("Not a PDF: no %PDF- header.")?;
        data.drain(..header);
        let version: String = data[5..].iter().take_while(|b| b.is_ascii_digit() || **b == b'.')
            .map(|&b| b as char).collect();
        let mut doc = Document { data, version, xref: BTreeMap::new(), trailer: Dict::new(),
                                 security: None, encrypt_object: None };
        let tail_start = doc.data.len().saturating_sub(2048);
        let startxref = doc.data[tail_start..].windows(9).rposition(|w| w == b"startxref")
            .map(|p| tail_start + p).ok_or("No startxref: the file is truncated.")?;
        let mut parser = Parser::new(&doc.data, startxref + 9);
        let offset: usize = std::str::from_utf8(parser.token()).ok().and_then(|t| t.parse().ok())
            .ok_or("startxref is not followed by an offset.")?;
        if offset >= doc.data.len() {
            return Err(format!("startxref points past the end of the file: {offset} of {} \
                                bytes.", doc.data.len()));
        }
        let mut next = Some(offset);
        let mut seen = std::collections::HashSet::new();
        while let Some(at) = next {
            if !seen.insert(at) {
                return Err("The /Prev chain loops.".to_string());
            }
            next = doc.read_section(at)?;
        }
        Ok(doc)
    }

    /// One cross-reference section; returns the `/Prev` offset.
    fn read_section(&mut self, at: usize) -> Result<Option<usize>, String> {
        let data = std::mem::take(&mut self.data);
        let result = self.read_section_in(&data, at);
        self.data = data;
        result
    }

    fn read_section_in(&mut self, data: &[u8], at: usize) -> Result<Option<usize>, String> {
        let mut parser = Parser::at_offset(data, at)?;
        let first_trailer = self.trailer.is_empty();
        let trailer;
        if parser.token() == b"xref" {
            loop {
                let token = parser.token();
                if token == b"trailer" {
                    break;
                }
                let start: u32 = std::str::from_utf8(token).ok().and_then(|t| t.parse().ok())
                    .ok_or("A malformed xref subsection.")?;
                let count: u32 = std::str::from_utf8(parser.token()).ok()
                    .and_then(|t| t.parse().ok()).ok_or("A malformed xref subsection count.")?;
                for i in 0..count {
                    let offset = parser.token();
                    let generation = parser.token();
                    let kind = parser.token();
                    let number = start.checked_add(i)
                        .ok_or("An xref subsection's object numbers pass 2^32.")?;
                    if kind == b"n" && !self.xref.contains_key(&number) {
                        let offset = std::str::from_utf8(offset).ok().and_then(|t| t.parse().ok())
                            .ok_or("A malformed xref entry.")?;
                        let generation = std::str::from_utf8(generation).ok()
                            .and_then(|t| t.parse().ok()).ok_or("A malformed xref entry.")?;
                        self.xref.insert(number, Location::Offset(offset, generation));
                    } else if kind != b"n" && kind != b"f" {
                        return Err("An xref entry neither in use nor free.".to_string());
                    }
                }
            }
            trailer = match parser.object(&|_, _| None)? {
                Object::Dictionary(d) => d,
                _ => return Err("The trailer is not a dictionary.".to_string()),
            };
            // A hybrid file's cross-reference stream fills in what the
            // table leaves out.
            if let Some(stream_at) = non_negative(get(&trailer, "XRefStm"), "XRefStm")? {
                let mut sub = Parser::at_offset(data, stream_at)?;
                sub.token();
                sub.token();
                sub.keyword("obj")?;
                if let Object::Stream(dict, raw) = sub.object(&|_, _| None)? {
                    self.read_xref_stream(&dict, &raw)?;
                }
            }
        } else {
            let mut parser = Parser::at_offset(data, at)?;
            parser.token();
            parser.token();
            parser.keyword("obj")?;
            match parser.object(&|_, _| None)? {
                Object::Stream(dict, raw) => {
                    self.read_xref_stream(&dict, &raw)?;
                    trailer = dict;
                }
                _ => return Err("startxref points at neither xref nor a stream.".to_string()),
            }
        }
        if first_trailer {
            self.trailer = trailer.clone();
            for key in ["Type", "W", "Index", "Filter", "DecodeParms", "Length", "Prev", "XRefStm"] {
                crate::object::remove(&mut self.trailer, key);
            }
        }
        non_negative(get(&trailer, "Prev"), "Prev")
    }

    fn read_xref_stream(&mut self, dict: &Dict, raw: &[u8]) -> Result<(), String> {
        let decoded = decode_flate_with_predictor(dict, raw)?;
        // Each field is a big-endian integer of up to 8 bytes (ISO
        // 32000-2 table 17 lets a field be absent, width 0). A negative
        // width would wrap through `as usize`, so each is checked here.
        let widths: Vec<usize> = match get(dict, "W") {
            Some(Object::Array(items)) => items.iter().filter_map(Object::as_int)
                .map(|w| usize::try_from(w).ok().filter(|w| *w <= 8)
                     .ok_or(format!("/W holds a width of {w}; 0 to 8 are possible.")))
                .collect::<Result<_, _>>()?,
            _ => return Err("A cross-reference stream without /W.".to_string()),
        };
        if widths.len() != 3 {
            return Err("/W does not have three widths.".to_string());
        }
        let size = get(dict, "Size").and_then(Object::as_int).unwrap_or(0);
        let index: Vec<i64> = match get(dict, "Index") {
            Some(Object::Array(items)) => items.iter().filter_map(Object::as_int).collect(),
            _ => vec![0, size],
        };
        let entry_len: usize = widths.iter().sum();
        let mut at = 0;
        for pair in index.chunks(2) {
            let as_u32 = |value: i64| u32::try_from(value)
                .map_err(|_| format!("/Index holds {value}, which is not an object count."));
            let (start, count) = (as_u32(pair[0])?, as_u32(*pair.get(1).unwrap_or(&0))?);
            for i in 0..count {
                let entry = decoded.get(at..at + entry_len)
                    .ok_or("A cross-reference stream shorter than its /Index.")?;
                at += entry_len;
                let kind = if widths[0] == 0 { 1 } else { be(&entry[..widths[0]]) };
                let second = be(&entry[widths[0]..widths[0] + widths[1]]);
                let third = be(&entry[widths[0] + widths[1]..]);
                let number = start.checked_add(i)
                    .ok_or("A cross-reference stream's object numbers pass 2^32.")?;
                if self.xref.contains_key(&number) {
                    continue;
                }
                match kind {
                    1 => { self.xref.insert(number, Location::Offset(second as usize, third as u16)); }
                    2 => { self.xref.insert(number, Location::InStream(second as u32, third as u32)); }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// The trailer's `/ID`, first element.
    pub fn id(&self) -> Vec<u8> {
        match get(&self.trailer, "ID") {
            Some(Object::Array(items)) => items.first().and_then(Object::as_bytes)
                .map(<[u8]>::to_vec).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// The raw object as stored, undecrypted, with its generation, and
    /// the objects whose parsing led here. Reading one object
    /// can need another: a stream's `/Length` may be a reference, and an
    /// object in an object stream needs its container. A file can make
    /// either point back at the object being read - `/Length 5 0 R` in
    /// object 5, or object 7 located inside object 7 - so the chain is
    /// refused when it repeats, and bounded in length against a long
    /// one.
    fn raw_in(&self, number: u32, chain: &[u32]) -> Result<(Object, u16), String> {
        if chain.contains(&number) {
            return Err(format!("Object {number} is needed to read itself: {chain:?}."));
        }
        if chain.len() >= 16 {
            return Err(format!("Reading object {} needs more than 16 other objects.", chain[0]));
        }
        let mut chain = chain.to_vec();
        chain.push(number);
        match self.xref.get(&number) {
            None => Ok((Object::Null, 0)),
            Some(Location::Offset(at, generation)) => {
                let mut parser = Parser::at_offset(&self.data, *at)
                    .map_err(|e| format!("Object {number}: {e}"))?;
                parser.token();
                parser.token();
                parser.keyword("obj")?;
                let lengths = |n: u32, _g: u16| -> Option<i64> {
                    self.raw_in(n, &chain).ok().and_then(|(o, _)| o.as_int())
                };
                Ok((parser.object(&lengths)?, *generation))
            }
            Some(Location::InStream(stream, index)) => {
                let (container, _) = self.object_in(*stream, &chain)?;
                let (dict, data) = match container {
                    Object::Stream(dict, data) => (dict, data),
                    _ => return Err(format!("Object {number}'s object stream is not a stream.")),
                };
                let decoded = decode_flate_with_predictor(&dict, &data)?;
                let n = non_negative(get(&dict, "N"), "N")?.unwrap_or(0);
                let first = non_negative(get(&dict, "First"), "First")?.unwrap_or(0);
                let mut header = Parser::new(&decoded, 0);
                // Each pair in the header takes at least four bytes.
                let mut offsets = Vec::with_capacity(n.min(decoded.len() / 4));
                for _ in 0..n {
                    let num: u32 = std::str::from_utf8(header.token()).ok()
                        .and_then(|t| t.parse().ok()).ok_or("A malformed object stream.")?;
                    let off: usize = std::str::from_utf8(header.token()).ok()
                        .and_then(|t| t.parse().ok()).ok_or("A malformed object stream.")?;
                    offsets.push((num, off));
                }
                let (num, off) = *offsets.get(*index as usize)
                    .ok_or(format!("Object {number} is past its object stream's end."))?;
                if num != number {
                    return Err(format!("Object stream {stream} holds {num} where {number} was \
                                        expected."));
                }
                let at = first.checked_add(off).ok_or("An object stream offset overflows.")?;
                let mut parser = Parser::at_offset(&decoded, at)
                    .map_err(|e| format!("Object {number} in object stream {stream}: {e}"))?;
                Ok((parser.object(&|_, _| None)?, 0))
            }
        }
    }

    /// An object, decrypted, with its generation.
    pub fn object(&self, number: u32) -> Result<(Object, u16), String> {
        self.object_in(number, &[])
    }

    fn object_in(&self, number: u32, chain: &[u32]) -> Result<(Object, u16), String> {
        let (object, generation) = self.raw_in(number, chain)?;
        let in_stream = matches!(self.xref.get(&number), Some(Location::InStream(..)));
        match &self.security {
            Some(security) if !in_stream && Some(number) != self.encrypt_object => {
                Ok((self.decrypt_object(security, number, generation, object)?, generation))
            }
            _ => Ok((object, generation)),
        }
    }

    fn decrypt_object(&self, security: &Security, number: u32, generation: u16, object: Object)
                      -> Result<Object, String> {
        transform(security, number, generation, object, Direction::Decrypt)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Direction {
    Decrypt,
    Encrypt,
}

/// Encryption or decryption of one string or one stream's data.
type Apply<'a> = dyn Fn(&[u8]) -> Result<Vec<u8>, String> + 'a;

/// Where a stream names a crypt filter in its own `/Filter`, the index
/// of the first `/Crypt` and the filter's name from its `/DecodeParms`
/// (`/Identity` when it gives none, ISO 32000-2 table 26).
fn crypt_filter(dict: &Dict) -> Option<(Option<usize>, Vec<u8>)> {
    let name_of = |parms: Option<&Object>| -> Vec<u8> {
        parms.and_then(Object::as_dict).and_then(|d| get(d, "Name")).and_then(Object::as_name)
            .unwrap_or(b"Identity").to_vec()
    };
    match get(dict, "Filter")? {
        Object::Name(n) if n == b"Crypt" => Some((None, name_of(get(dict, "DecodeParms")))),
        Object::Array(filters) => {
            let index = filters.iter().position(|f| f.as_name() == Some(b"Crypt"))?;
            let parms = match get(dict, "DecodeParms") {
                Some(Object::Array(parms)) => parms.get(index),
                _ => None,
            };
            Some((Some(index), name_of(parms)))
        }
        _ => None,
    }
}

/// Remove the `/Crypt` filter `crypt_filter` found, and its parameters:
/// it describes the encryption, so a decrypted file must not keep it.
/// qpdf's writer does the same.
fn without_crypt_filter(mut dict: Dict, index: Option<usize>) -> Dict {
    match index {
        None => {
            remove(&mut dict, "Filter");
            remove(&mut dict, "DecodeParms");
        }
        Some(index) => {
            for key in ["Filter", "DecodeParms"] {
                if let Some((_, Object::Array(items))) =
                    dict.iter_mut().find(|(k, _)| k == key.as_bytes()) {
                    if index < items.len() {
                        items.remove(index);
                    }
                }
            }
        }
    }
    dict
}

/// Decrypt or encrypt every string and the stream data in an object,
/// skipping what the standard exempts: cross-reference streams, and
/// metadata streams when `/EncryptMetadata` is false.
///
/// A stream's method is, in order: the crypt filter its own `/Filter`
/// names (revision 4 on), `/EFF` for an embedded file, and `/StmF`.
/// qpdf does not apply `/EFF` when decrypting; ISO 32000-2 table 20
/// says it applies to embedded file streams with no crypt filter of
/// their own, and that is followed here.
pub fn transform(security: &Security, number: u32, generation: u16, object: Object,
                 direction: Direction) -> Result<Object, String> {
    let apply = |method: Method, data: &[u8]| match direction {
        Direction::Decrypt => security.decrypt(number, generation, method, data),
        Direction::Encrypt => security.encrypt(number, generation, method, data),
    };
    fn walk(object: Object, f: &Apply)
            -> Result<Object, String> {
        Ok(match object {
            Object::String(bytes) => Object::String(f(&bytes)?),
            Object::Array(items) => Object::Array(items.into_iter().map(|o| walk(o, f))
                .collect::<Result<_, _>>()?),
            Object::Dictionary(dict) => Object::Dictionary(walk_dict(dict, f)?),
            other => other,
        })
    }
    // A signature's /Contents is never encrypted: the signature covers
    // the file's bytes, so it is written in the clear (ISO 32000-2
    // 7.6.2). qpdf recognises the dictionary by /Type /Sig and
    // /ByteRange, and so does this.
    fn walk_dict(dict: Dict, f: &Apply) -> Result<Dict, String> {
        let signature = get(&dict, "Type").and_then(Object::as_name) == Some(b"Sig")
            && get(&dict, "ByteRange").is_some();
        dict.into_iter().map(|(k, v)| {
            if signature && k == b"Contents" && matches!(v, Object::String(_)) {
                return Ok((k, v));
            }
            Ok((k, walk(v, f)?))
        }).collect()
    }
    let strings = |data: &[u8]| apply(security.strings, data);
    match object {
        Object::Stream(dict, data) => {
            let kind = get(&dict, "Type").and_then(Object::as_name);
            if kind == Some(b"XRef") {
                return Ok(Object::Stream(dict, data));
            }
            let own = if security.v >= 4 { crypt_filter(&dict) } else { None };
            let method = match &own {
                Some((_, name)) => security.named(name).ok_or(format!(
                    "Object {number}: crypt filter /{} is not in /CF.",
                    String::from_utf8_lossy(name)))?,
                None if kind == Some(b"Metadata") && !security.encrypt_metadata => Method::Identity,
                None if kind == Some(b"EmbeddedFile") => security.files,
                None => security.streams,
            };
            let mut dict = walk_dict(dict, &strings)?;
            if let (Some((index, _)), Direction::Decrypt) = (&own, direction) {
                dict = without_crypt_filter(dict, *index);
            }
            let data = apply(method, &data)?;
            Ok(Object::Stream(dict, data))
        }
        other => walk(other, &strings),
    }
}

/// A complete file: the objects in number order, a classic
/// cross-reference table, and the trailer.
pub fn write_file(version: &str, objects: &BTreeMap<u32, (u16, Object)>, trailer: &Dict)
                  -> Vec<u8> {
    let mut out = format!("%PDF-{version}\n%\u{e2}\u{e3}\u{cf}\u{d3}\n").into_bytes();
    let mut offsets = BTreeMap::new();
    for (number, (generation, object)) in objects {
        offsets.insert(*number, (out.len(), *generation));
        out.extend_from_slice(format!("{number} {generation} obj\n").as_bytes());
        write(object, &mut out);
        out.extend_from_slice(b"\nendobj\n");
    }
    let size = objects.keys().next_back().map_or(1, |n| n + 1);
    let start = out.len();
    out.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    for number in 0..size {
        match offsets.get(&number) {
            Some((offset, generation)) => {
                out.extend_from_slice(format!("{offset:010} {generation:05} n\r\n").as_bytes())
            }
            None => out.extend_from_slice(b"0000000000 65535 f\r\n"),
        }
    }
    let mut trailer = trailer.clone();
    set(&mut trailer, "Size", Object::Integer(i64::from(size)));
    out.extend_from_slice(b"trailer\n");
    write(&Object::Dictionary(trailer), &mut out);
    out.extend_from_slice(format!("\nstartxref\n{start}\n%%EOF\n").as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(kind: &str, filter: Option<Object>, parms: Option<Object>) -> Object {
        let mut dict: Dict = vec![(b"Type".to_vec(), Object::Name(kind.as_bytes().to_vec()))];
        if let Some(filter) = filter {
            dict.push((b"Filter".to_vec(), filter));
        }
        if let Some(parms) = parms {
            dict.push((b"DecodeParms".to_vec(), parms));
        }
        Object::Stream(dict, b"the data in the stream".to_vec())
    }

    fn name(n: &str) -> Object {
        Object::Name(n.as_bytes().to_vec())
    }

    /// Which method each stream gets: its own crypt filter, then `/EFF`
    /// for an embedded file, then `/StmF`. Encrypting with streams and
    /// embedded files under different methods shows which one was used.
    #[test]
    fn test_a_stream_is_encrypted_under_the_method_that_applies_to_it() {
        let (mut security, _) = Security::create("aes-128", b"u", b"o", -4, &[9; 16]).unwrap();
        security.streams = Method::Identity;
        security.files = Method::AesV2;
        let encrypted = |object: Object| match transform(&security, 4, 0, object,
                                                          Direction::Encrypt).unwrap() {
            Object::Stream(_, data) => data != b"the data in the stream",
            other => panic!("{other:?}"),
        };
        assert!(!encrypted(stream("XObject", None, None)), "/StmF is Identity");
        assert!(encrypted(stream("EmbeddedFile", None, None)), "/EFF applies");
        let own = |n: &str| Some(Object::Dictionary(vec![(b"Name".to_vec(), name(n))]));
        assert!(!encrypted(stream("EmbeddedFile", Some(name("Crypt")), own("Identity"))),
                "its own filter overrides /EFF");
        assert!(encrypted(stream("XObject", Some(name("Crypt")), own("StdCF"))),
                "its own filter overrides /StmF");
        assert!(encrypted(stream("XObject", Some(Object::Array(vec![name("Crypt"),
                                                                    name("FlateDecode")])),
                                 Some(Object::Array(vec![own("StdCF").unwrap(), Object::Null])))),
                "in an array too");
    }

    /// A decrypted stream loses its `/Crypt` filter and that filter's
    /// parameters, and keeps the rest: a reader of the plain file would
    /// look for a crypt filter that is no longer defined.
    #[test]
    fn test_decrypting_removes_the_crypt_filter() {
        let (security, _) = Security::create("aes-128", b"u", b"o", -4, &[9; 16]).unwrap();
        let own = Object::Dictionary(vec![(b"Name".to_vec(), name("StdCF"))]);
        let filters = Object::Array(vec![name("Crypt"), name("FlateDecode")]);
        let parms = Object::Array(vec![own.clone(), Object::Null]);
        let sealed = transform(&security, 4, 0, stream("XObject", Some(filters), Some(parms)),
                               Direction::Encrypt).unwrap();
        match transform(&security, 4, 0, sealed, Direction::Decrypt).unwrap() {
            Object::Stream(dict, data) => {
                assert_eq!(data, b"the data in the stream");
                assert_eq!(get(&dict, "Filter"), Some(&Object::Array(vec![name("FlateDecode")])));
                assert_eq!(get(&dict, "DecodeParms"), Some(&Object::Array(vec![Object::Null])));
            }
            other => panic!("{other:?}"),
        }
        let single = stream("XObject", Some(name("Crypt")), Some(own));
        let sealed = transform(&security, 4, 0, single, Direction::Encrypt).unwrap();
        match transform(&security, 4, 0, sealed, Direction::Decrypt).unwrap() {
            Object::Stream(dict, _) => {
                assert_eq!((get(&dict, "Filter"), get(&dict, "DecodeParms")), (None, None))
            }
            other => panic!("{other:?}"),
        }
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(crate::fixtures::dir().join("pdf").join(name)).unwrap()
    }

    /// `text` replaced by `with`, once, in a file; the file is text at
    /// that point, and nothing checksums it.
    fn replaced(data: &[u8], text: &[u8], with: &[u8]) -> Vec<u8> {
        let at = crate::object::find(data, text).unwrap_or_else(|| panic!("{text:?}"));
        let mut out = data[..at].to_vec();
        out.extend_from_slice(with);
        out.extend_from_slice(&data[at + text.len()..]);
        out
    }

    /// `Parser::new` took any offset, and `token` sliced the data from
    /// it, so an offset past the end of the file - `startxref`, `/Prev`
    /// (a negative one became huge through `as usize`), `/XRefStm`, or a
    /// cross-reference entry - panicked where a damaged file should be
    /// refused. The fixtures were all written by qpdf, pdftk or this
    /// example, with every offset inside the file, so no test reached
    /// one that was not.
    #[test]
    fn test_an_offset_past_the_end_of_the_file_is_refused() {
        // A linearized file: the first section's trailer carries /Prev.
        let data = fixture("qpdf-tests-enc-R2_V1.pdf");
        assert!(Document::parse(data.clone()).is_ok());
        let length = data.len();

        let negative = replaced(&data, b"/Prev 15195", b"/Prev -5195");
        let error = Document::parse(negative).err().unwrap();
        assert!(error.contains("/Prev is negative"), "{error}");

        let beyond = replaced(&data, b"/Prev 15195", format!("/Prev {}", length + 1).as_bytes());
        let error = Document::parse(beyond).err().unwrap();
        assert!(error.contains("past the end"), "{error}");

        let tail = crate::object::find(&data[length - 40..], b"startxref").unwrap() + length - 40;
        let digits: Vec<u8> = data[tail + 10..].iter().copied()
            .take_while(u8::is_ascii_digit).collect();
        assert!(!digits.is_empty());
        // The number may grow the file by a few bytes.
        let mut far = data[..tail + 10].to_vec();
        far.extend_from_slice(format!("{}", length + 100).as_bytes());
        far.extend_from_slice(&data[tail + 10 + digits.len()..]);
        let error = Document::parse(far).err().unwrap();
        assert!(error.contains("past the end"), "{error}");

        // One cross-reference entry's offset, its first digit made a 9.
        let entry = b"0000013970 00000 n";
        let doc = Document::parse(data.clone()).unwrap();
        let (number, _) = doc.xref.iter()
            .find(|(_, at)| **at == Location::Offset(13970, 0)).unwrap();
        let moved = replaced(&data, entry, b"9000013970 00000 n");
        let doc = Document::parse(moved).unwrap();
        let error = doc.object(*number).err().unwrap();
        assert!(error.contains("past the end"), "{error}");
    }

    /// `/W` widths came through `as usize`, so `-1` became `usize::MAX`:
    /// the entry length wrapped and the first field's slice panicked. An
    /// `/Index` start near 2^32 overflowed the object number. The
    /// fixtures' cross-reference streams all have `/W [1 2 1]` and start
    /// at 0, so no test had a width or a start outside the format.
    #[test]
    fn test_a_cross_reference_stream_with_impossible_widths_is_refused() {
        let data = fixture("qpdf-R2-plain-objstm.pdf");
        assert!(Document::parse(data.clone()).is_ok());
        let error = Document::parse(replaced(&data, b"/W [ 1 2 1 ]", b"/W [-1 2 1 ]")).err()
            .unwrap();
        assert!(error.contains("/W holds a width of -1"), "{error}");
        let error = Document::parse(replaced(&data, b"/W [ 1 2 1 ]", b"/W [ 1 9 1 ]")).err()
            .unwrap();
        assert!(error.contains("/W holds a width of 9"), "{error}");
        // The dictionary is text and nothing points past it, so it may
        // grow: an /Index whose numbers pass 2^32.
        let error = Document::parse(replaced(&data, b"/W [ 1 2 1 ]",
                                             b"/W [ 1 2 1 ] /Index [ 4294967295 2 ]")).err()
            .unwrap();
        assert!(error.contains("pass 2^32"), "{error}");
        let error = Document::parse(replaced(&data, b"/W [ 1 2 1 ]",
                                             b"/W [ 1 2 1 ] /Index [ -1 2 ]")).err().unwrap();
        assert!(error.contains("/Index holds -1"), "{error}");
    }

    /// A file of the given object bodies, numbered from 1, with a
    /// classic cross-reference table.
    fn file_of(bodies: &[&[u8]]) -> Vec<u8> {
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let start = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f\r\n", bodies.len() + 1)
                              .as_bytes());
        for offset in offsets {
            out.extend_from_slice(format!("{offset:010} 00000 n\r\n").as_bytes());
        }
        out.extend_from_slice(format!("trailer\n<</Size {}>>\nstartxref\n{start}\n%%EOF\n",
                                      bodies.len() + 1).as_bytes());
        out
    }

    /// A stream's `/Length` may be an indirect reference, resolved by
    /// reading that object; an object in an object stream is read by
    /// reading its container first. Nothing stopped either from
    /// pointing back at the object being read, so `/Length 1 0 R` in
    /// object 1, or object 2 located inside object stream 2, recursed
    /// without bound and overflowed the stack. The `/Prev` chain was
    /// guarded against loops; these two were not, and no fixture
    /// written by a real producer has one.
    #[test]
    fn test_an_object_that_refers_to_itself_is_refused() {
        let data = file_of(&[b"<</Length 1 0 R>>\nstream\nabc\nendstream",
                             b"<</Length 2 0 R /Type /ObjStm /N 1 /First 4>>\nstream\n3 0 x\n\
                               endstream"]);
        let mut doc = Document::parse(data).unwrap();
        // The length is unresolvable, so the stream ends at `endstream`.
        match doc.object(1).unwrap().0 {
            Object::Stream(_, data) => assert_eq!(data, b"abc"),
            other => panic!("{other:?}"),
        }
        doc.xref.insert(2, Location::InStream(2, 0));
        let error = doc.object(2).err().unwrap();
        assert!(error.contains("needed to read itself"), "{error}");
        // A loop through another object is a loop too.
        doc.xref.insert(2, Location::InStream(3, 0));
        doc.xref.insert(3, Location::InStream(2, 0));
        let error = doc.object(2).err().unwrap();
        assert!(error.contains("needed to read itself"), "{error}");
    }

    #[test]
    fn test_png_up_prediction() {
        // Two rows of three bytes, the second predicted from the first.
        let data = [2, 1, 2, 3, 2, 1, 1, 1];
        assert_eq!(png_unpredict(&data, 3).unwrap(), [1, 2, 3, 2, 3, 4]);
        assert!(png_unpredict(&data[..7], 3).is_err());
    }
}
