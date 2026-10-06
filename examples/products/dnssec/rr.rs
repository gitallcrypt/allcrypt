//! Resource records: the types a signed zone holds, each converted between
//! presentation form and wire form, and the RDATA canonicalization of
//! RFC 4034 section 6.2 as RFC 6840 section 5.1 corrects it.
//!
//! RDATA is kept as uncompressed wire bytes, with the case it was given.
//! A type not listed here reads and writes in RFC 3597's generic form,
//! `\# length hex`, and is signed as it stands.

use std::fmt::Write as _;

use crate::base64;
use crate::name::Name;

pub const A: u16 = 1;
pub const NS: u16 = 2;
pub const CNAME: u16 = 5;
pub const SOA: u16 = 6;
pub const PTR: u16 = 12;
pub const HINFO: u16 = 13;
pub const MX: u16 = 15;
pub const TXT: u16 = 16;
pub const AAAA: u16 = 28;
pub const SRV: u16 = 33;
pub const DNAME: u16 = 39;
pub const DS: u16 = 43;
pub const RRSIG: u16 = 46;
pub const NSEC: u16 = 47;
pub const DNSKEY: u16 = 48;
pub const NSEC3: u16 = 50;
pub const NSEC3PARAM: u16 = 51;
pub const CDS: u16 = 59;
pub const CDNSKEY: u16 = 60;

pub const CLASS_IN: u16 = 1;

const TYPES: [(u16, &str); 19] = [
    (A, "A"), (NS, "NS"), (CNAME, "CNAME"), (SOA, "SOA"), (PTR, "PTR"), (HINFO, "HINFO"),
    (MX, "MX"), (TXT, "TXT"), (AAAA, "AAAA"), (SRV, "SRV"), (DNAME, "DNAME"), (DS, "DS"),
    (RRSIG, "RRSIG"), (NSEC, "NSEC"), (DNSKEY, "DNSKEY"), (NSEC3, "NSEC3"),
    (NSEC3PARAM, "NSEC3PARAM"), (CDS, "CDS"), (CDNSKEY, "CDNSKEY"),
];

pub fn type_name(rtype: u16) -> String {
    TYPES.iter().find(|(t, _)| *t == rtype).map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("TYPE{rtype}"))
}

pub fn type_from_name(text: &str) -> Option<u16> {
    let upper = text.to_ascii_uppercase();
    TYPES.iter().find(|(_, n)| *n == upper).map(|(t, _)| *t)
        .or_else(|| upper.strip_prefix("TYPE").and_then(|d| d.parse().ok()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub owner: Name,
    pub ttl: u32,
    pub class: u16,
    pub rtype: u16,
    pub rdata: Vec<u8>,
}

impl Record {
    pub fn to_text(&self) -> String {
        let class = if self.class == CLASS_IN { "IN".to_string() }
                    else { format!("CLASS{}", self.class) };
        format!("{}\t{}\t{}\t{}\t{}", self.owner, self.ttl, class, type_name(self.rtype),
                rdata_to_text(self.rtype, &self.rdata).unwrap_or_else(|_| generic(&self.rdata)))
    }
}

// --------------------------------------------------------------- wire reading --

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let out = self.data.get(self.at..self.at + n).ok_or("RDATA too short.")?;
        self.at += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("two")))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four")))
    }
    fn name(&mut self) -> Result<Name, String> {
        let (name, used) = Name::from_wire(&self.data[self.at..])?;
        self.at += used;
        Ok(name)
    }
    fn string(&mut self) -> Result<&'a [u8], String> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.at..];
        self.at = self.data.len();
        out
    }
    fn done(&self) -> Result<(), String> {
        if self.at == self.data.len() { Ok(()) } else { Err("RDATA too long.".to_string()) }
    }
}

/// The RRSIG fields before the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rrsig {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: Name,
    pub signature: Vec<u8>,
}

impl Rrsig {
    pub fn parse(rdata: &[u8]) -> Result<Rrsig, String> {
        let mut r = Reader::new(rdata);
        Ok(Rrsig {
            type_covered: r.u16()?, algorithm: r.u8()?, labels: r.u8()?,
            original_ttl: r.u32()?, expiration: r.u32()?, inception: r.u32()?,
            key_tag: r.u16()?, signer: r.name()?, signature: r.rest().to_vec(),
        })
    }

    /// The RDATA up to the signature, signer lowercased: the first part of
    /// what is signed (RFC 4034 section 3.1.8.1).
    pub fn header(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.type_covered.to_be_bytes());
        out.push(self.algorithm);
        out.push(self.labels);
        out.extend_from_slice(&self.original_ttl.to_be_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out.extend_from_slice(&self.inception.to_be_bytes());
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        out.extend(self.signer.canonical().to_wire());
        out
    }

    pub fn to_rdata(&self) -> Vec<u8> {
        let mut out = self.header();
        out.extend_from_slice(&self.signature);
        out
    }
}

/// DNSKEY RDATA's fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dnskey {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

pub const ZONE_KEY: u16 = 0x0100;
pub const SEP: u16 = 0x0001;

impl Dnskey {
    pub fn parse(rdata: &[u8]) -> Result<Dnskey, String> {
        let mut r = Reader::new(rdata);
        Ok(Dnskey { flags: r.u16()?, protocol: r.u8()?, algorithm: r.u8()?,
                    public_key: r.rest().to_vec() })
    }

    pub fn to_rdata(&self) -> Vec<u8> {
        let mut out = self.flags.to_be_bytes().to_vec();
        out.push(self.protocol);
        out.push(self.algorithm);
        out.extend_from_slice(&self.public_key);
        out
    }
}

/// NSEC3 and NSEC3PARAM's shared head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nsec3Param {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

impl Nsec3Param {
    fn read(r: &mut Reader<'_>) -> Result<Nsec3Param, String> {
        Ok(Nsec3Param { hash_algorithm: r.u8()?, flags: r.u8()?, iterations: r.u16()?,
                        salt: r.string()?.to_vec() })
    }

    pub fn parse(rdata: &[u8]) -> Result<Nsec3Param, String> {
        let mut r = Reader::new(rdata);
        let out = Nsec3Param::read(&mut r)?;
        r.done()?;
        Ok(out)
    }

    pub fn to_rdata(&self) -> Vec<u8> {
        let mut out = vec![self.hash_algorithm, self.flags];
        out.extend_from_slice(&self.iterations.to_be_bytes());
        out.push(self.salt.len() as u8);
        out.extend_from_slice(&self.salt);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nsec3 {
    pub param: Nsec3Param,
    pub next_hashed: Vec<u8>,
    pub types: Vec<u16>,
}

impl Nsec3 {
    pub fn parse(rdata: &[u8]) -> Result<Nsec3, String> {
        let mut r = Reader::new(rdata);
        let param = Nsec3Param::read(&mut r)?;
        let next_hashed = r.string()?.to_vec();
        let types = read_bitmap(r.rest())?;
        Ok(Nsec3 { param, next_hashed, types })
    }

    pub fn to_rdata(&self) -> Vec<u8> {
        let mut out = self.param.to_rdata();
        out.push(self.next_hashed.len() as u8);
        out.extend_from_slice(&self.next_hashed);
        out.extend(write_bitmap(&self.types));
        out
    }
}

pub fn nsec_rdata(next: &Name, types: &[u16]) -> Vec<u8> {
    let mut out = next.to_wire();
    out.extend(write_bitmap(types));
    out
}

pub fn parse_nsec(rdata: &[u8]) -> Result<(Name, Vec<u16>), String> {
    let (next, used) = Name::from_wire(rdata)?;
    Ok((next, read_bitmap(&rdata[used..])?))
}

/// The type bit map of RFC 4034 section 4.1.2: windows of 256 types, each
/// a window number, a length, and up to 32 bytes of bits, the
/// most significant bit first.
pub fn write_bitmap(types: &[u16]) -> Vec<u8> {
    let mut sorted = types.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let window = (sorted[i] >> 8) as u8;
        let mut bits = [0u8; 32];
        let mut used = 0;
        while i < sorted.len() && (sorted[i] >> 8) as u8 == window {
            let low = (sorted[i] & 0xff) as usize;
            bits[low / 8] |= 0x80 >> (low % 8);
            used = low / 8 + 1;
            i += 1;
        }
        out.push(window);
        out.push(used as u8);
        out.extend_from_slice(&bits[..used]);
    }
    out
}

pub fn read_bitmap(data: &[u8]) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    let mut last_window: Option<u8> = None;
    while r.at < data.len() {
        let window = r.u8()?;
        let len = r.u8()? as usize;
        if last_window.is_some_and(|w| window <= w) {
            return Err("Type bit map windows out of order.".to_string());
        }
        if len == 0 || len > 32 {
            return Err(format!("A type bit map window of {len} bytes."));
        }
        last_window = Some(window);
        for (i, &byte) in r.take(len)?.iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    out.push(((window as u16) << 8) | (i * 8 + bit) as u16);
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------- canonical RDATA --

/// RDATA with the names RFC 4034 section 6.2 lists lowercased. NSEC is
/// left as it is and RRSIG's signer lowercased, per RFC 6840 section
/// 5.1; HINFO holds no names.
pub fn canonical_rdata(rtype: u16, rdata: &[u8]) -> Result<Vec<u8>, String> {
    let lower = |r: &mut Reader<'_>, out: &mut Vec<u8>| -> Result<(), String> {
        out.extend(r.name()?.canonical().to_wire());
        Ok(())
    };
    let mut r = Reader::new(rdata);
    let mut out = Vec::with_capacity(rdata.len());
    match rtype {
        NS | CNAME | PTR | DNAME => lower(&mut r, &mut out)?,
        SOA => {
            lower(&mut r, &mut out)?;
            lower(&mut r, &mut out)?;
            out.extend_from_slice(r.take(20)?);
        }
        MX => {
            out.extend_from_slice(r.take(2)?);
            lower(&mut r, &mut out)?;
        }
        SRV => {
            out.extend_from_slice(r.take(6)?);
            lower(&mut r, &mut out)?;
        }
        RRSIG => {
            out.extend_from_slice(r.take(18)?);
            lower(&mut r, &mut out)?;
            out.extend_from_slice(r.rest());
        }
        _ => out.extend_from_slice(r.rest()),
    }
    r.done()?;
    Ok(out)
}

// -------------------------------------------------------- presentation form --

fn generic(rdata: &[u8]) -> String {
    format!("\\# {} {}", rdata.len(), hex(rdata))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{text}: not hex."));
    }
    Ok((0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect())
}

const BASE32HEX: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// RFC 4648's base32hex without padding, as NSEC3 owner names and Next
/// Hashed Owner fields write it (RFC 5155 section 3.3).
pub fn base32hex(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32HEX[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32HEX[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn unbase32hex(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.bytes() {
        let value = BASE32HEX.iter().position(|&d| d == c.to_ascii_uppercase())
            .ok_or_else(|| format!("{text}: not base32hex."))? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    if bits >= 5 || buffer & ((1 << bits) - 1) != 0 {
        return Err(format!("{text}: base32hex with trailing bits."));
    }
    Ok(out)
}

fn character_string(text: &str) -> Result<Vec<u8>, String> {
    let inner = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')).unwrap_or(text);
    let bytes = inner.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let rest = &bytes[i + 1..];
            if rest.len() >= 3 && rest[..3].iter().all(u8::is_ascii_digit) {
                let v: u32 = std::str::from_utf8(&rest[..3]).expect("digits").parse()
                    .expect("digits");
                out.push(u8::try_from(v).map_err(|_| format!("{text}: \\{v}"))?);
                i += 4;
            } else {
                out.push(*rest.first().ok_or("A string ends in a backslash.")?);
                i += 2;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    if out.len() > 255 {
        return Err("A character-string longer than 255 bytes.".to_string());
    }
    Ok(out)
}

fn write_character_string(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &c in bytes {
        match c {
            b'"' | b'\\' => { out.push('\\'); out.push(c as char); }
            0x20..=0x7e => out.push(c as char),
            _ => { let _ = write!(out, "\\{c:03}"); }
        }
    }
    out.push('"');
    out
}

fn number<T: std::str::FromStr>(text: &str, what: &str) -> Result<T, String> {
    text.parse().map_err(|_| format!("{text}: not a {what}."))
}

/// `YYYYMMDDHHmmSS` or a plain count of seconds (RFC 4034 section 3.2).
pub fn parse_time(text: &str) -> Result<u32, String> {
    if text.len() == 14 && text.bytes().all(|c| c.is_ascii_digit()) {
        let f = |a: usize, b: usize| -> i64 { text[a..b].parse().expect("digits") };
        let days = days_from_civil(f(0, 4), f(4, 6), f(6, 8));
        let seconds = days * 86400 + f(8, 10) * 3600 + f(10, 12) * 60 + f(12, 14);
        // Serial number arithmetic (RFC 1982): the value is mod 2^32.
        Ok(seconds.rem_euclid(1 << 32) as u32)
    } else {
        number(text, "time")
    }
}

/// Seconds as `YYYYMMDDHHmmSS`, the time read as the one within 68 years
/// of `now` (RFC 4034 section 3.2) rather than as a plain u32.
pub fn format_time(value: u32, now: i64) -> String {
    let base = now - (now.rem_euclid(1 << 32));
    let mut t = base + value as i64;
    if t - now > 1 << 31 {
        t -= 1 << 32;
    } else if now - t > 1 << 31 {
        t += 1 << 32;
    }
    let (days, rem) = (t.div_euclid(86400), t.rem_euclid(86400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 }, m, d)
}

fn types_text(types: &[u16]) -> String {
    types.iter().map(|&t| type_name(t)).collect::<Vec<_>>().join(" ")
}

fn parse_types(tokens: &[String]) -> Result<Vec<u16>, String> {
    tokens.iter().map(|t| type_from_name(t).ok_or_else(|| format!("{t}: no such type.")))
        .collect()
}

/// RDATA from its presentation tokens. Base64 and hex fields that span
/// several tokens (the zone file broke them over lines) are joined.
pub fn rdata_from_text(rtype: u16, tokens: &[String], origin: &Name)
                       -> Result<Vec<u8>, String> {
    if tokens.first().map(String::as_str) == Some("\\#") {
        let len: usize = number(tokens.get(1).ok_or("\\# with no length.")?, "length")?;
        let data = unhex(&tokens[2..].concat())?;
        if data.len() != len {
            return Err(format!("\\# says {len} bytes and has {}.", data.len()));
        }
        return Ok(data);
    }
    let need = |n: usize| -> Result<(), String> {
        if tokens.len() < n {
            Err(format!("{} needs {n} fields, got {}.", type_name(rtype), tokens.len()))
        } else { Ok(()) }
    };
    let exact = |n: usize| -> Result<(), String> {
        if tokens.len() != n {
            Err(format!("{} takes {n} fields, got {}.", type_name(rtype), tokens.len()))
        } else { Ok(()) }
    };
    let name = |t: &str| Name::parse(t, Some(origin)).map(|n| n.to_wire());
    let mut out = Vec::new();
    match rtype {
        A => {
            exact(1)?;
            let ip: std::net::Ipv4Addr = tokens[0].parse()
                .map_err(|_| format!("{}: not an IPv4 address.", tokens[0]))?;
            out.extend_from_slice(&ip.octets());
        }
        AAAA => {
            exact(1)?;
            let ip: std::net::Ipv6Addr = tokens[0].parse()
                .map_err(|_| format!("{}: not an IPv6 address.", tokens[0]))?;
            out.extend_from_slice(&ip.octets());
        }
        NS | CNAME | PTR | DNAME => {
            exact(1)?;
            out.extend(name(&tokens[0])?);
        }
        SOA => {
            exact(7)?;
            out.extend(name(&tokens[0])?);
            out.extend(name(&tokens[1])?);
            for t in &tokens[2..] {
                out.extend_from_slice(&number::<u32>(t, "number")?.to_be_bytes());
            }
        }
        MX => {
            exact(2)?;
            out.extend_from_slice(&number::<u16>(&tokens[0], "preference")?.to_be_bytes());
            out.extend(name(&tokens[1])?);
        }
        SRV => {
            exact(4)?;
            for t in &tokens[..3] {
                out.extend_from_slice(&number::<u16>(t, "number")?.to_be_bytes());
            }
            out.extend(name(&tokens[3])?);
        }
        TXT | HINFO => {
            need(1)?;
            if rtype == HINFO {
                exact(2)?;
            }
            for t in tokens {
                let s = character_string(t)?;
                out.push(s.len() as u8);
                out.extend(s);
            }
        }
        DS | CDS => {
            need(4)?;
            out.extend_from_slice(&number::<u16>(&tokens[0], "key tag")?.to_be_bytes());
            out.push(number(&tokens[1], "algorithm")?);
            out.push(number(&tokens[2], "digest type")?);
            out.extend(unhex(&tokens[3..].concat())?);
        }
        DNSKEY | CDNSKEY => {
            need(4)?;
            out.extend_from_slice(&number::<u16>(&tokens[0], "flags")?.to_be_bytes());
            out.push(number(&tokens[1], "protocol")?);
            out.push(number(&tokens[2], "algorithm")?);
            out.extend(base64::decode(&tokens[3..].concat()).ok_or("Bad base64 key.")?);
        }
        RRSIG => {
            need(9)?;
            let covered = type_from_name(&tokens[0])
                .ok_or_else(|| format!("{}: no such type.", tokens[0]))?;
            out.extend_from_slice(&covered.to_be_bytes());
            out.push(number(&tokens[1], "algorithm")?);
            out.push(number(&tokens[2], "label count")?);
            out.extend_from_slice(&number::<u32>(&tokens[3], "TTL")?.to_be_bytes());
            out.extend_from_slice(&parse_time(&tokens[4])?.to_be_bytes());
            out.extend_from_slice(&parse_time(&tokens[5])?.to_be_bytes());
            out.extend_from_slice(&number::<u16>(&tokens[6], "key tag")?.to_be_bytes());
            out.extend(name(&tokens[7])?);
            out.extend(base64::decode(&tokens[8..].concat()).ok_or("Bad base64 signature.")?);
        }
        NSEC => {
            need(1)?;
            out.extend(name(&tokens[0])?);
            out.extend(write_bitmap(&parse_types(&tokens[1..])?));
        }
        NSEC3PARAM | NSEC3 => {
            need(if rtype == NSEC3 { 5 } else { 4 })?;
            if rtype == NSEC3PARAM {
                exact(4)?;
            }
            let salt = if tokens[3] == "-" { Vec::new() } else { unhex(&tokens[3])? };
            let param = Nsec3Param { hash_algorithm: number(&tokens[0], "hash algorithm")?,
                                     flags: number(&tokens[1], "flags")?,
                                     iterations: number(&tokens[2], "iteration count")?,
                                     salt };
            if rtype == NSEC3PARAM {
                return Ok(param.to_rdata());
            }
            let next_hashed = unbase32hex(&tokens[4])?;
            let types = parse_types(&tokens[5..])?;
            return Ok(Nsec3 { param, next_hashed, types }.to_rdata());
        }
        _ => return Err(format!("{}: give it in the generic form, \\# length hex.",
                                type_name(rtype))),
    }
    Ok(out)
}

pub fn rdata_to_text(rtype: u16, rdata: &[u8]) -> Result<String, String> {
    let mut r = Reader::new(rdata);
    let text = match rtype {
        A => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).expect("4")).to_string(),
        AAAA => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(r.take(16)?).expect("16"))
            .to_string(),
        NS | CNAME | PTR | DNAME => r.name()?.to_string(),
        SOA => {
            let (m, rn) = (r.name()?, r.name()?);
            format!("{m} {rn} {} {} {} {} {}", r.u32()?, r.u32()?, r.u32()?, r.u32()?,
                    r.u32()?)
        }
        MX => format!("{} {}", r.u16()?, r.name()?),
        SRV => format!("{} {} {} {}", r.u16()?, r.u16()?, r.u16()?, r.name()?),
        TXT | HINFO => {
            let mut parts = Vec::new();
            while r.at < rdata.len() {
                parts.push(write_character_string(r.string()?));
            }
            parts.join(" ")
        }
        DS | CDS => format!("{} {} {} {}", r.u16()?, r.u8()?, r.u8()?, hex(r.rest())),
        DNSKEY | CDNSKEY => format!("{} {} {} {}", r.u16()?, r.u8()?, r.u8()?,
                                    base64::encode(r.rest())),
        RRSIG => {
            let sig = Rrsig::parse(rdata)?;
            r.rest();
            let now = sig.inception as i64;
            format!("{} {} {} {} {} {} {} {} {}", type_name(sig.type_covered), sig.algorithm,
                    sig.labels, sig.original_ttl, format_time(sig.expiration, now),
                    format_time(sig.inception, now), sig.key_tag, sig.signer,
                    base64::encode(&sig.signature))
        }
        NSEC => {
            let (next, types) = parse_nsec(rdata)?;
            r.rest();
            format!("{next} {}", types_text(&types)).trim_end().to_string()
        }
        NSEC3PARAM => {
            let p = Nsec3Param::read(&mut r)?;
            format!("{} {} {} {}", p.hash_algorithm, p.flags, p.iterations,
                    if p.salt.is_empty() { "-".to_string() } else { hex(&p.salt) })
        }
        NSEC3 => {
            let n = Nsec3::parse(rdata)?;
            r.rest();
            format!("{} {} {} {} {} {}", n.param.hash_algorithm, n.param.flags,
                    n.param.iterations,
                    if n.param.salt.is_empty() { "-".to_string() } else { hex(&n.param.salt) },
                    base32hex(&n.next_hashed), types_text(&n.types)).trim_end().to_string()
        }
        _ => return Ok(generic(r.rest())),
    };
    r.done()?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn test_presentation_round_trips() {
        let origin = Name::parse("example.", None).unwrap();
        for (rtype, text) in [
            (A, "192.0.2.1"), (AAAA, "2001:db8::1"), (NS, "ns1.example."),
            (SOA, "ns1.example. bugs.x.w.example. 1081539377 3600 300 3600000 3600"),
            (MX, "10 mail.example."), (TXT, "\"hello\" \"a\\\"b\""),
            (SRV, "0 5 5060 sip.example."),
            (DS, "60485 5 1 2bb183af5f22588179a53b0a98631fad1a292118"),
            (NSEC, "a.example. NS SOA MX RRSIG NSEC DNSKEY"),
            (NSEC3PARAM, "1 0 12 aabbccdd"), (NSEC3PARAM, "1 0 0 -"),
            (NSEC3, "1 1 12 aabbccdd 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA MX RRSIG DNSKEY NSEC3PARAM"),
            (DNSKEY, "256 3 5 AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61ek8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZIySFNsgEYvh0z2542lzMKR4Dh8uZffQ=="),
            (RRSIG, "A 5 2 3600 20040509183619 20040409183619 38519 example. OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2f9AMN1CytCd10cYISAxfAdvXSZ7xujKAtPbctvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhqe2XTjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw4kX18MMR34i8lC36SR5xBni8vHI="),
        ] {
            let wire = rdata_from_text(rtype, &tokens(text), &origin).unwrap();
            assert_eq!(rdata_to_text(rtype, &wire).unwrap(), text, "{}", type_name(rtype));
        }
    }

    #[test]
    fn test_the_type_bit_map_of_rfc_4034_section_4_3() {
        // "alfa.example.com. 86400 IN NSEC host.example.com. A MX RRSIG
        // NSEC TYPE1234", and the RDATA the section prints for it.
        let types = [A, MX, RRSIG, NSEC, 1234];
        let mut expected = vec![0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03, 0x04, 0x1b];
        expected.extend([0u8; 26]);
        expected.push(0x20);
        assert_eq!(write_bitmap(&types), expected);
        assert_eq!(read_bitmap(&expected).unwrap(), types);
    }

    #[test]
    fn test_base32hex() {
        // RFC 4648 section 10.
        for (plain, encoded) in [("", ""), ("f", "CO"), ("fo", "CPNG"), ("foo", "CPNMU"),
                                 ("foob", "CPNMUOG"), ("fooba", "CPNMUOJ1"),
                                 ("foobar", "CPNMUOJ1E8")] {
            assert_eq!(base32hex(plain.as_bytes()), encoded);
            assert_eq!(unbase32hex(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn test_times() {
        assert_eq!(parse_time("20040509183619").unwrap(), 1084127779);
        assert_eq!(format_time(1084127779, 1084127779), "20040509183619");
        // Past 2106 the u32 wraps, and the format reads it near `now`.
        let t = parse_time("21100101000000").unwrap();
        assert_eq!(format_time(t, 4_260_000_000), "21100101000000");
    }

    #[test]
    fn test_canonical_rdata_lowercases_the_listed_types_only() {
        let origin = Name::parse("example.", None).unwrap();
        let mx = rdata_from_text(MX, &tokens("10 Mail.EXAMPLE."), &origin).unwrap();
        assert_eq!(canonical_rdata(MX, &mx).unwrap(),
                   rdata_from_text(MX, &tokens("10 mail.example."), &origin).unwrap());
        let nsec = rdata_from_text(NSEC, &tokens("Next.Example. A"), &origin).unwrap();
        assert_eq!(canonical_rdata(NSEC, &nsec).unwrap(), nsec);
    }
}
