//! Packet framing (RFC 9580 section 4.2): the two header formats, and
//! the four length encodings including partial body lengths.

pub const PKESK: u8 = 1;
pub const SIGNATURE: u8 = 2;
pub const SKESK: u8 = 3;
pub const ONE_PASS: u8 = 4;
pub const SECRET_KEY: u8 = 5;
pub const PUBLIC_KEY: u8 = 6;
pub const SECRET_SUBKEY: u8 = 7;
pub const COMPRESSED: u8 = 8;
pub const SED: u8 = 9;
pub const MARKER: u8 = 10;
pub const LITERAL: u8 = 11;
pub const TRUST: u8 = 12;
pub const USER_ID: u8 = 13;
pub const PUBLIC_SUBKEY: u8 = 14;
pub const USER_ATTRIBUTE: u8 = 17;
pub const SEIPD: u8 = 18;
pub const MDC: u8 = 19;
pub const OCB: u8 = 20;
pub const PADDING: u8 = 21;

#[derive(Clone, Debug)]
pub struct Packet {
    pub tag: u8,
    pub body: Vec<u8>,
    /// Whether the header was the legacy format.
    pub legacy: bool,
    /// Whether the body came in partial lengths.
    pub partial: bool,
}

pub fn tag_name(tag: u8) -> &'static str {
    match tag {
        PKESK => "public-key encrypted session key",
        SIGNATURE => "signature",
        SKESK => "symmetric-key encrypted session key",
        ONE_PASS => "one-pass signature",
        SECRET_KEY => "secret key",
        PUBLIC_KEY => "public key",
        SECRET_SUBKEY => "secret subkey",
        COMPRESSED => "compressed data",
        SED => "symmetrically encrypted data",
        MARKER => "marker",
        LITERAL => "literal data",
        TRUST => "trust",
        USER_ID => "user ID",
        PUBLIC_SUBKEY => "public subkey",
        USER_ATTRIBUTE => "user attribute",
        SEIPD => "symmetrically encrypted integrity protected data",
        MDC => "modification detection code",
        OCB => "OCB encrypted data",
        PADDING => "padding",
        _ => "unknown",
    }
}

fn take<'a>(data: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = at.checked_add(n).filter(|&e| e <= data.len())
        .ok_or("a packet runs past the end of the data")?;
    let slice = &data[*at..end];
    *at = end;
    Ok(slice)
}

fn be(bytes: &[u8]) -> usize {
    bytes.iter().fold(0usize, |v, &b| v << 8 | usize::from(b))
}

/// The packets in `data`, in order.
pub fn parse(data: &[u8]) -> Result<Vec<Packet>, String> {
    let mut packets = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let first = take(data, &mut at, 1)?[0];
        if first & 0x80 == 0 {
            return Err(format!("byte {} is not a packet header (0x{first:02x})", at - 1));
        }
        if first & 0x40 == 0 {
            // The legacy format: four bits of tag, two of length type.
            let tag = (first >> 2) & 0x0f;
            let body = match first & 3 {
                0 => { let n = be(take(data, &mut at, 1)?); take(data, &mut at, n)? }
                1 => { let n = be(take(data, &mut at, 2)?); take(data, &mut at, n)? }
                2 => { let n = be(take(data, &mut at, 4)?); take(data, &mut at, n)? }
                // Indeterminate: to the end of the data.
                _ => { let n = data.len() - at; take(data, &mut at, n)? }
            };
            packets.push(Packet { tag, body: body.to_vec(), legacy: true, partial: false });
            continue;
        }
        let tag = first & 0x3f;
        let mut body = Vec::new();
        let mut partial = false;
        loop {
            let b0 = take(data, &mut at, 1)?[0];
            match b0 {
                0..=191 => {
                    body.extend_from_slice(take(data, &mut at, b0 as usize)?);
                    break;
                }
                192..=223 => {
                    let b1 = take(data, &mut at, 1)?[0];
                    let n = ((b0 as usize - 192) << 8) + b1 as usize + 192;
                    body.extend_from_slice(take(data, &mut at, n)?);
                    break;
                }
                255 => {
                    let n = be(take(data, &mut at, 4)?);
                    body.extend_from_slice(take(data, &mut at, n)?);
                    break;
                }
                _ => {
                    // A partial body length: a power of two, then
                    // another length. The first must be at least 512.
                    let n = 1usize << (b0 & 0x1f);
                    if !partial && n < 512 {
                        return Err("a first partial body length under 512 bytes".to_string());
                    }
                    partial = true;
                    body.extend_from_slice(take(data, &mut at, n)?);
                }
            }
        }
        packets.push(Packet { tag, body, legacy: false, partial });
    }
    Ok(packets)
}

/// A new-format length.
pub fn encode_length(n: usize, out: &mut Vec<u8>) {
    if n < 192 {
        out.push(n as u8);
    } else if n < 8384 {
        let m = n - 192;
        out.push((m >> 8) as u8 + 192);
        out.push(m as u8);
    } else {
        out.push(255);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
}

/// A packet in the current (new) format with a definite length.
pub fn write(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(0xC0 | tag);
    encode_length(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

/// A packet in the legacy format, for the readers that want it (PGP
/// 2.6 knows nothing else). Tags above 15 cannot be written this way.
#[cfg(test)]
pub fn write_legacy(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    if body.len() < 256 {
        out.push(0x80 | tag << 2);
        out.push(body.len() as u8);
    } else if body.len() < 65536 {
        out.push(0x80 | tag << 2 | 1);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    } else {
        out.push(0x80 | tag << 2 | 2);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

/// A packet whose body goes out in partial lengths of `chunk` bytes (a
/// power of two, at least 512), as GnuPG writes data it is streaming.
#[cfg(test)]
pub fn write_partial(tag: u8, body: &[u8], chunk: usize) -> Vec<u8> {
    assert!(chunk.is_power_of_two() && (512..=1 << 30).contains(&chunk));
    let mut out = vec![0xC0 | tag];
    let mut rest = body;
    while rest.len() > chunk {
        out.push(224 + chunk.trailing_zeros() as u8);
        out.extend_from_slice(&rest[..chunk]);
        rest = &rest[chunk..];
    }
    encode_length(rest.len(), &mut out);
    out.extend_from_slice(rest);
    out
}

/// A reader over a packet body.
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, at: 0 }
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        take(self.data, &mut self.at, n).map_err(|_| "a packet body is too short".to_string())
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let rest = &self.data[self.at..];
        self.at = self.data.len();
        rest
    }

}
