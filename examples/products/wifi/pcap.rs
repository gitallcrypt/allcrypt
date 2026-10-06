//! Just enough pcap to read the capture files the Wi-Fi tools write: the
//! classic `tcpdump` format (not pcapng), with the link types that carry
//! 802.11 frames.
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
        let big_endian = match bytes[..4] {
            [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => true,
            [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => false,
            _ => return Err("Not a pcap file (bad magic); pcapng is not read here.".to_string()),
        };
        Ok(Reader { linktype: u32_at(bytes, 20, big_endian), big_endian, bytes, at: 24 })
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = &'a [u8];

    /// The next record's captured bytes, the link-layer header stripped
    /// so the 802.11 frame is at the front.
    fn next(&mut self) -> Option<&'a [u8]> {
        while self.at + 16 <= self.bytes.len() {
            let caplen = u32_at(self.bytes, self.at + 8, self.big_endian) as usize;
            let start = self.at + 16;
            self.at = start + caplen;
            if self.at > self.bytes.len() {
                return None;
            }
            let record = &self.bytes[start..start + caplen];
            let frame = match self.linktype {
                105 => record,
                127 if record.len() >= 4 => {
                    let n = u16::from_le_bytes([record[2], record[3]]) as usize;
                    if n > record.len() { continue }
                    &record[n..]
                }
                119 if record.len() >= 144 => &record[144..],
                _ => continue,
            };
            return Some(frame);
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
