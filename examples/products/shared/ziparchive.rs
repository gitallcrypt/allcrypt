//! A ZIP archive as a container: the entries' names and their stored
//! bytes, read through the central directory, and an archive written
//! from entries whose bytes are already what is to be stored. Nothing
//! here encrypts - the ZIP example has the format's own encryption; this
//! is for formats that put their encryption inside the entries, as
//! OpenDocument does. No ZIP64, which no document needs.

#![allow(dead_code)]

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub name: String,
    /// 0 stored, 8 deflated.
    pub method: u16,
    pub crc: u32,
    pub size: u64,
    /// The bytes as stored: compressed, or not.
    pub data: Vec<u8>,
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "ZIP: truncated.".to_string())
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))
        .ok_or_else(|| "ZIP: truncated.".to_string())
}

/// Every entry, in the central directory's order.
pub fn read(archive: &[u8]) -> Result<Vec<Entry>, String> {
    let tail = archive.len().saturating_sub(22 + 65_535);
    let eocd = (tail..archive.len().saturating_sub(21)).rev()
        .find(|&i| archive[i..].starts_with(b"PK\x05\x06"))
        .ok_or("ZIP: no end of central directory record.")?;
    let count = u16_at(archive, eocd + 10)? as usize;
    let mut at = u32_at(archive, eocd + 16)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(archive, at)? != 0x0201_4b50 {
            return Err("ZIP: a central directory entry without its signature.".to_string());
        }
        let method = u16_at(archive, at + 10)?;
        let crc = u32_at(archive, at + 16)?;
        let compressed = u32_at(archive, at + 20)? as usize;
        let size = u64::from(u32_at(archive, at + 24)?);
        let name_length = u16_at(archive, at + 28)? as usize;
        let extra_length = u16_at(archive, at + 30)? as usize;
        let comment_length = u16_at(archive, at + 32)? as usize;
        let local = u32_at(archive, at + 42)? as usize;
        let name = archive.get(at + 46..at + 46 + name_length).ok_or("ZIP: truncated name.")?;
        if u32_at(archive, local)? != 0x0403_4b50 {
            return Err("ZIP: a local header without its signature.".to_string());
        }
        let start = local + 30 + u16_at(archive, local + 26)? as usize
            + u16_at(archive, local + 28)? as usize;
        let data = archive.get(start..start + compressed)
            .ok_or("ZIP: an entry runs past the end.")?.to_vec();
        out.push(Entry { name: String::from_utf8_lossy(name).into_owned(), method, crc, size,
                         data });
        at += 46 + name_length + extra_length + comment_length;
    }
    Ok(out)
}

/// An entry's content, inflated if it was deflated, with its CRC
/// checked.
pub fn content(entry: &Entry) -> Result<Vec<u8>, String> {
    let plain = match entry.method {
        0 => entry.data.clone(),
        8 => crate::inflate::inflate(&entry.data, entry.size as usize)?.0,
        other => return Err(format!("ZIP: {}: compression method {other}.", entry.name)),
    };
    if plain.len() as u64 != entry.size || allcrypt::checksum::crc32(&plain) != entry.crc {
        return Err(format!("ZIP: {}: the size or CRC does not match.", entry.name));
    }
    Ok(plain)
}

/// Raw DEFLATE of stored blocks: valid for every reader, and no smaller
/// than the input.
pub fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / 65_535 + 1));
    let mut chunks = data.chunks(65_535).peekable();
    if chunks.peek().is_none() {
        return vec![1, 0, 0, 0xff, 0xff];
    }
    while let Some(chunk) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        let n = chunk.len() as u16;
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(!n).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// An archive of `entries`, in order, their bytes stored as given.
pub fn write(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries {
        let offset = out.len() as u32;
        let name = entry.name.as_bytes();
        let mut fields = Vec::new();
        fields.extend_from_slice(&20u16.to_le_bytes()); // version needed
        // Bit 11: the name is UTF-8.
        fields.extend_from_slice(&0x0800u16.to_le_bytes());
        fields.extend_from_slice(&entry.method.to_le_bytes());
        fields.extend_from_slice(&[0, 0, 0x21, 0]); // 1980-01-01 00:00
        fields.extend_from_slice(&entry.crc.to_le_bytes());
        fields.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
        fields.extend_from_slice(&(entry.size as u32).to_le_bytes());
        fields.extend_from_slice(&(name.len() as u16).to_le_bytes());
        fields.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&fields);
        out.extend_from_slice(name);
        out.extend_from_slice(&entry.data);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&fields);
        central.extend_from_slice(&[0; 6]); // comment, disk, internal attributes
        central.extend_from_slice(&[0; 4]); // external attributes
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let start = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A stored entry for `data`.
pub fn stored(name: &str, data: Vec<u8>) -> Entry {
    Entry { name: name.to_string(), method: 0, crc: allcrypt::checksum::crc32(&data),
            size: data.len() as u64, data }
}

/// A deflated entry for `data`, in stored deflate blocks.
pub fn deflated(name: &str, data: &[u8]) -> Entry {
    Entry { name: name.to_string(), method: 8, crc: allcrypt::checksum::crc32(data),
            size: data.len() as u64, data: deflate_stored(data) }
}

#[cfg(test)]
mod ziparchive_tests {
    use super::*;

    /// Stored deflate blocks hold 65,535 bytes each, and only the last
    /// is marked final; every length either side of a block reads back.
    #[test]
    fn test_stored_deflate_reads_back_at_every_block_edge() {
        for length in [0, 1, 65_534, 65_535, 65_536, 131_070, 131_071, 200_000] {
            let data: Vec<u8> = (0..length).map(|i| (i % 253) as u8).collect();
            let (back, used) = crate::inflate::inflate(&deflate_stored(&data), length + 1).unwrap();
            assert_eq!(back, data, "{length}");
            assert_eq!(used, deflate_stored(&data).len(), "{length}");
        }
    }

    /// What is written reads back, and an entry whose bytes no longer
    /// match its CRC is refused.
    #[test]
    fn test_an_archive_reads_back_and_its_crcs_are_checked() {
        let entries = vec![stored("a", b"first".to_vec()), deflated("dir/b", &[9; 70_000]),
                           stored("empty", Vec::new())];
        let archive = write(&entries);
        let back = read(&archive).unwrap();
        assert_eq!(back, entries);
        for entry in &back {
            assert_eq!(content(entry).unwrap().len() as u64, entry.size);
        }
        let mut changed = back[0].clone();
        changed.data[0] ^= 1;
        assert!(content(&changed).is_err());
    }
}
