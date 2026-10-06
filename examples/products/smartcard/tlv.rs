//! BER-TLV as smart cards use it (ISO/IEC 7816-4 annex D): tags of one to
//! three bytes, lengths in the short form or `81`/`82`/`83` and one to
//! three bytes. PIV and the OpenPGP card nest these; OATH's are the
//! one-byte subset.

/// One TLV: the tag as its bytes read big-endian, and the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u32,
    pub value: &'a [u8],
}

/// The encoding of `tag` (its bytes, most significant first, leading
/// zeros dropped) and `value`.
pub fn encode(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    let tag_bytes = tag.to_be_bytes();
    let first = tag_bytes.iter().position(|&b| b != 0).unwrap_or(3);
    out.extend_from_slice(&tag_bytes[first..]);
    let n = value.len();
    match n {
        0..=0x7f => out.push(n as u8),
        0x80..=0xff => out.extend_from_slice(&[0x81, n as u8]),
        0x100..=0xffff => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        _ => out.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
    out
}

/// Every TLV in `data`, in order, or an error naming where it broke.
pub fn parse(data: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        // Some cards pad with 00 or FF between objects (ISO 7816-4 5.2.2).
        if data[at] == 0x00 || data[at] == 0xff {
            at += 1;
            continue;
        }
        let start = at;
        let mut tag = u32::from(data[at]);
        at += 1;
        if tag & 0x1f == 0x1f {
            loop {
                let byte = *data.get(at).ok_or("A TLV tag runs past the end.")?;
                tag = (tag << 8) | u32::from(byte);
                at += 1;
                if byte & 0x80 == 0 {
                    break;
                }
                if at - start >= 3 {
                    return Err("A TLV tag is longer than three bytes.".to_string());
                }
            }
        }
        let first = *data.get(at).ok_or("A TLV has no length.")?;
        at += 1;
        let length = match first {
            0..=0x7f => usize::from(first),
            0x81..=0x83 => {
                let count = usize::from(first & 0x7f);
                let bytes = data.get(at..at + count).ok_or("A TLV length runs past the end.")?;
                at += count;
                bytes.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
            }
            _ => return Err(format!("A TLV length byte of 0x{first:02x} is not one cards use.")),
        };
        let value = data.get(at..at + length)
            .ok_or_else(|| format!("A TLV of tag {tag:x} claims {length} bytes and has {}.",
                                   data.len() - at))?;
        at += length;
        out.push(Tlv { tag, value });
    }
    Ok(out)
}

/// The value of the first `tag` in `data`, which must parse.
pub fn find(data: &[u8], tag: u32) -> Result<&[u8], String> {
    parse(data)?
        .into_iter()
        .find(|t| t.tag == tag)
        .map(|t| t.value)
        .ok_or_else(|| format!("The card's answer has no tag {tag:x}."))
}

/// `find` that answers `None` rather than an error for a missing tag.
pub fn find_optional(data: &[u8], tag: u32) -> Result<Option<&[u8]>, String> {
    Ok(parse(data)?.into_iter().find(|t| t.tag == tag).map(|t| t.value))
}

/// Follow a path of tags through nested TLVs.
pub fn path<'a>(data: &'a [u8], tags: &[u32]) -> Result<&'a [u8], String> {
    tags.iter().try_fold(data, |inner, &tag| find(inner, tag))
}
