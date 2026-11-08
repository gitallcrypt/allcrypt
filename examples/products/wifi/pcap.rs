//! Just enough pcap to read the capture files the Wi-Fi tools write: the
//! classic `tcpdump` format and pcapng (its enhanced and simple packet
//! blocks, each interface with its own link type), with the link types
//! that carry 802.11 frames.
//!
//! - **105** (`IEEE802_11`): the frame starts at the record.
//! - **127** (`IEEE802_11_RADIOTAP`): a radiotap header comes first, its
//!   length in bytes 2-3 little endian.
//! - **119** (`PRISM_HEADER`): a 144-byte Prism capture header first.
//!
//! The file header's magic gives the byte order and whether timestamps
//! are micro- or nanoseconds; neither matters here beyond reading the
//! lengths. Writing is the Ethernet form `airdecap-ng` writes: link type
//! 1, each record a 14-byte Ethernet header and the data.

pub const LINKTYPE_ETHERNET: u32 = 1;

pub struct Reader<'a> {
    bytes: &'a [u8],
    big_endian: bool,
    pub linktype: u32,
    at: usize,
    /// pcapng: each interface's link type, in the order they were
    /// described; `None` for classic pcap.
    interfaces: Option<Vec<u32>>,
}

/// The 802.11 frame in a record of the given link type.
fn strip_link_header(linktype: u32, record: &[u8]) -> Option<&[u8]> {
    match linktype {
        105 => Some(record),
        127 if record.len() >= 4 => {
            let n = u16::from_le_bytes([record[2], record[3]]) as usize;
            record.get(n..)
        }
        119 if record.len() >= 144 => Some(&record[144..]),
        _ => None,
    }
}

fn u32_at(bytes: &[u8], at: usize, big_endian: bool) -> u32 {
    let b: [u8; 4] = bytes[at..at + 4].try_into().unwrap();
    if big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Reader<'a>, String> {
        if bytes.len() < 24 {
            return Err("A pcap file is at least its 24-byte header.".to_string());
        }
        if bytes[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
            // pcapng's section header block: its byte-order magic says
            // how every block in the section is written.
            let big_endian = match bytes[8..12] {
                [0x1a, 0x2b, 0x3c, 0x4d] => true,
                [0x4d, 0x3c, 0x2b, 0x1a] => false,
                _ => return Err("A pcapng section header with no byte-order magic.".to_string()),
            };
            return Ok(Reader { linktype: 0, big_endian, bytes, at: 0,
                               interfaces: Some(Vec::new()) });
        }
        let big_endian = match bytes[..4] {
            [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => true,
            [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => false,
            _ => return Err("Not a pcap or pcapng file (bad magic).".to_string()),
        };
        Ok(Reader { linktype: u32_at(bytes, 20, big_endian), big_endian, bytes, at: 24,
                    interfaces: None })
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = &'a [u8];

    /// The next record's captured bytes, the link-layer header stripped
    /// so the 802.11 frame is at the front.
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.interfaces.is_some() {
            return self.next_block();
        }
        while self.at + 16 <= self.bytes.len() {
            let caplen = u32_at(self.bytes, self.at + 8, self.big_endian) as usize;
            let start = self.at + 16;
            self.at = start.checked_add(caplen)?;
            if self.at > self.bytes.len() {
                return None;
            }
            let record = &self.bytes[start..start + caplen];
            match strip_link_header(self.linktype, record) {
                Some(frame) => return Some(frame),
                None => continue,
            }
        }
        None
    }
}

impl<'a> Reader<'a> {
    /// pcapng: the next enhanced or simple packet block's frame. Each
    /// block is its type, its total length, the body, and the length
    /// again; a section header starts a new section, perhaps in the other
    /// byte order, and forgets the interfaces.
    fn next_block(&mut self) -> Option<&'a [u8]> {
        while self.at + 12 <= self.bytes.len() {
            let at = self.at;
            if self.bytes[at..at + 4] == [0x0a, 0x0d, 0x0d, 0x0a] {
                self.big_endian = match self.bytes.get(at + 8..at + 12)? {
                    [0x1a, 0x2b, 0x3c, 0x4d] => true,
                    [0x4d, 0x3c, 0x2b, 0x1a] => false,
                    _ => return None,
                };
                self.interfaces = Some(Vec::new());
            }
            let kind = u32_at(self.bytes, at, self.big_endian);
            let length = u32_at(self.bytes, at + 4, self.big_endian) as usize;
            if length < 12 || !length.is_multiple_of(4) || at + length > self.bytes.len() {
                return None;
            }
            self.at = at + length;
            let body = &self.bytes[at + 8..at + length - 4];
            let interfaces = self.interfaces.as_mut()?;
            match kind {
                // Interface description: link type (2 bytes), reserved,
                // snap length.
                1 if body.len() >= 8 => {
                    let b = [body[0], body[1]];
                    interfaces.push(u32::from(if self.big_endian { u16::from_be_bytes(b) }
                                              else { u16::from_le_bytes(b) }));
                }
                // Enhanced packet: interface, time (8), captured length,
                // original length, then the data.
                6 if body.len() >= 20 => {
                    let interface = u32_at(body, 0, self.big_endian) as usize;
                    let caplen = u32_at(body, 12, self.big_endian) as usize;
                    let record = body.get(20..20usize.checked_add(caplen)?)?;
                    let linktype = *interfaces.get(interface)?;
                    if let Some(frame) = strip_link_header(linktype, record) {
                        return Some(frame);
                    }
                }
                // Simple packet: original length, then the data, on the
                // first interface.
                3 if body.len() >= 4 => {
                    let linktype = *interfaces.first()?;
                    let original = u32_at(body, 0, self.big_endian) as usize;
                    let record = &body[4..4 + original.min(body.len() - 4)];
                    if let Some(frame) = strip_link_header(linktype, record) {
                        return Some(frame);
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// A pcap file of Ethernet records: the 24-byte header, then for each
/// frame an 8-byte time (left zero), the two lengths, and the bytes.
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&[0; 8]);                     // zone, sigfigs
        out.extend_from_slice(&0x40000u32.to_le_bytes());   // snaplen
        out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        Writer { out }
    }

    pub fn write(&mut self, frame: &[u8]) {
        self.out.extend_from_slice(&[0; 8]);
        self.out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.out.extend_from_slice(frame);
    }

    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}
