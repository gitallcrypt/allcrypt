/*
DER: Distinguished Encoding Rules, the subset of BER that certificates use.

This is a parser for hostile input. Every certificate a TLS client sees comes
from whoever it is talking to, before anything has been verified, so this
module is the single largest attack surface in the whole library - and
historically the one that gets exploited. The rules it follows come from that:

  * **Strict, not tolerant.** DER has exactly one encoding for every value.
    Accepting a second one is how signature checks get bypassed: if two
    encodings of the same certificate both parse, an attacker can find one
    that hashes differently while meaning the same thing to the verifier.
    So a non-minimal length, a redundant leading zero in an INTEGER, a
    BOOLEAN that is not 0x00 or 0xFF, a BIT STRING with unused bits set -
    all errors, not warnings.

  * **No recursion without a bound.** Nested SEQUENCEs are free to write and
    a stack overflow is a crash. `MAX_DEPTH` caps how deep one reader
    descends through `read_constructed`. A `Reader::new` over bytes found
    inside another value - an extension's OCTET STRING, a key's
    parameters - starts again at zero, so the cap is per reader and not
    per document. That is a bound because nothing here parses
    recursively on data: every `Reader::new` is reached by a fixed path
    through the code, so a document's total depth is at most `MAX_DEPTH`
    times the number of those layers in its deepest structure. A parser
    that did recurse on data - a PKCS#12 SafeContents inside a
    SafeContents, say - has to descend with `read_constructed` from the
    reader it already has, so the count carries.

  * **No panics.** Every index is checked. A parser that panics on malformed
    input is a denial of service, and in this library it is also a broken
    promise - nothing here unwraps on data that came off the wire.

  * **Nothing is consumed twice and nothing is left over.** `finish()` is an
    error if bytes remain, because trailing data after a structure is the
    classic way to smuggle a second interpretation past a verifier.

What this module deliberately does not do is interpret. It hands back tags
and bytes; `x509` decides what they mean. Keeping the two apart means the
parser can be tested against malformed input without any certificate
semantics in the way.

See docs/pitfalls.md section 6.
*/

use crate::bignum::BigUint;

/// How deeply constructed types may nest. Real certificates reach about 10;
/// anything past 32 is someone testing whether we have a stack.
pub const MAX_DEPTH: usize = 32;

// ------------------------------------------------------------------ tags ---

pub const CLASS_UNIVERSAL: u8 = 0x00;
pub const CLASS_APPLICATION: u8 = 0x40;
pub const CLASS_CONTEXT: u8 = 0x80;
pub const CLASS_PRIVATE: u8 = 0xc0;

/// Universal tag numbers, the ones certificates use.
pub mod tag {
    pub const BOOLEAN: u32 = 0x01;
    pub const INTEGER: u32 = 0x02;
    pub const BIT_STRING: u32 = 0x03;
    pub const OCTET_STRING: u32 = 0x04;
    pub const NULL: u32 = 0x05;
    pub const OID: u32 = 0x06;
    /// Used by a CRL's `reasonCode`, and by nothing else here. Same
    /// encoding as an INTEGER and a different tag, so a reader that
    /// took either would accept a CRL nobody else writes.
    pub const ENUMERATED: u32 = 0x0a;
    pub const UTF8_STRING: u32 = 0x0c;
    pub const SEQUENCE: u32 = 0x10;
    pub const SET: u32 = 0x11;
    pub const PRINTABLE_STRING: u32 = 0x13;
    pub const T61_STRING: u32 = 0x14;
    pub const IA5_STRING: u32 = 0x16;
    pub const UTC_TIME: u32 = 0x17;
    pub const GENERALIZED_TIME: u32 = 0x18;
    pub const BMP_STRING: u32 = 0x1e;
}

/// An identifier octet, taken apart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tag {
    pub class: u8,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub fn universal(number: u32) -> Tag {
        Tag { class: CLASS_UNIVERSAL, constructed: false, number }
    }

    pub fn sequence() -> Tag {
        Tag { class: CLASS_UNIVERSAL, constructed: true, number: tag::SEQUENCE }
    }

    pub fn set() -> Tag {
        Tag { class: CLASS_UNIVERSAL, constructed: true, number: tag::SET }
    }

    /// `[n]` in an ASN.1 module: a context-specific tag.
    pub fn context(number: u32, constructed: bool) -> Tag {
        Tag { class: CLASS_CONTEXT, constructed, number }
    }

    fn describe(&self) -> String {
        let class = match self.class {
            CLASS_UNIVERSAL => "universal",
            CLASS_APPLICATION => "application",
            CLASS_CONTEXT => "context",
            _ => "private",
        };
        format!("{} {}{}", class, self.number,
                if self.constructed { " constructed" } else { "" })
    }
}

// ---------------------------------------------------------------- reader ---

/// A cursor over DER bytes.
///
/// Borrows rather than copies: a certificate is parsed in place, and the
/// pieces that have to be kept - the TBS bytes to hash, a public key - are
/// slices of the original. That is also what makes signature verification
/// possible at all, since it must hash the exact bytes that arrived, not a
/// re-encoding of what we understood them to mean.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0, depth: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Error unless everything has been consumed.
    ///
    /// Trailing bytes are not harmless. A verifier that hashes the whole
    /// input but parses only the front can be shown one thing and made to
    /// sign another.
    pub fn finish(&self) -> Result<(), String> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(format!("{} trailing bytes after the DER value.",
                        self.data.len() - self.pos))
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n)
            .ok_or_else(|| "Length overflows the address space.".to_string())?;
        if end > self.data.len() {
            return Err(format!("Truncated: wanted {} bytes, {} remain.",
                               n, self.data.len() - self.pos));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_one(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    /// Read one identifier octet and any high-tag-number continuation.
    fn read_tag(&mut self) -> Result<Tag, String> {
        let first = self.take_one()?;
        let class = first & 0xc0;
        let constructed = first & 0x20 != 0;
        let low = first & 0x1f;

        if low != 0x1f {
            return Ok(Tag { class, constructed, number: low as u32 });
        }

        // High tag number form: base-128, most significant first, and DER
        // requires the minimal number of octets - so a leading 0x80 is a
        // second encoding of the same number and must be rejected.
        let mut number: u32 = 0;
        let mut count = 0;
        loop {
            let byte = self.take_one()?;
            if count == 0 && byte == 0x80 {
                return Err("Non-minimal high tag number.".to_string());
            }
            number = number.checked_mul(128)
                .and_then(|n| n.checked_add((byte & 0x7f) as u32))
                .ok_or_else(|| "Tag number is too large.".to_string())?;
            count += 1;
            if byte & 0x80 == 0 {
                break;
            }
            if count > 4 {
                return Err("Tag number is too large.".to_string());
            }
        }
        if number < 0x1f {
            return Err("High tag number form used for a low tag number.".to_string());
        }
        Ok(Tag { class, constructed, number })
    }

    /// Read a length octet group. Definite form only, minimally encoded.
    fn read_length(&mut self) -> Result<usize, String> {
        let first = self.take_one()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let count = (first & 0x7f) as usize;
        if count == 0 {
            // 0x80 is BER's indefinite length. DER forbids it, and accepting
            // it means the end of a value is decided by a sentinel that can
            // appear inside a nested value.
            return Err("Indefinite length is not valid DER.".to_string());
        }
        if count > 4 {
            return Err("Length is longer than this parser will accept.".to_string());
        }
        let bytes = self.take(count)?;
        if bytes[0] == 0 {
            return Err("Non-minimal length encoding.".to_string());
        }
        let mut length: usize = 0;
        for &byte in bytes {
            length = (length << 8) | byte as usize;
        }
        if length < 128 {
            return Err("Long form length used for a short length.".to_string());
        }
        Ok(length)
    }

    /// The next tag, without consuming anything. `None` at the end.
    pub fn peek_tag(&self) -> Option<Tag> {
        let mut probe = self.clone();
        probe.read_tag().ok()
    }

    /// Read the next value, whatever it is, returning its tag and contents.
    pub fn read_any(&mut self) -> Result<(Tag, &'a [u8]), String> {
        let tag = self.read_tag()?;
        let length = self.read_length()?;
        let content = self.take(length)?;
        Ok((tag, content))
    }

    /// Read the next value and require it to carry `expected`.
    pub fn read_tagged(&mut self, expected: Tag) -> Result<&'a [u8], String> {
        let (tag, content) = self.read_any()?;
        if tag != expected {
            return Err(format!("Expected {}, found {}.",
                               expected.describe(), tag.describe()));
        }
        Ok(content)
    }

    /// The next value with its tag and length still attached.
    ///
    /// This is what signature verification needs: the exact bytes that
    /// arrived, to hash. Re-encoding what we parsed would verify our
    /// understanding of the certificate rather than the certificate.
    pub fn read_raw(&mut self) -> Result<&'a [u8], String> {
        let start = self.pos;
        self.read_any()?;
        Ok(&self.data[start..self.pos])
    }

    /// Descend into a constructed value, returning a reader over its
    /// contents with the depth counter advanced.
    pub fn read_constructed(&mut self, expected: Tag) -> Result<Reader<'a>, String> {
        if !expected.constructed {
            return Err("read_constructed needs a constructed tag.".to_string());
        }
        if self.depth + 1 > MAX_DEPTH {
            return Err(format!("DER nesting deeper than {}.", MAX_DEPTH));
        }
        let content = self.read_tagged(expected)?;
        Ok(Reader { data: content, pos: 0, depth: self.depth + 1 })
    }

    pub fn read_sequence(&mut self) -> Result<Reader<'a>, String> {
        self.read_constructed(Tag::sequence())
    }

    pub fn read_set(&mut self) -> Result<Reader<'a>, String> {
        self.read_constructed(Tag::set())
    }

    /// An INTEGER as an unsigned value, rejecting negatives.
    ///
    /// DER integers are two's complement and signed. Certificates use them
    /// for serial numbers and key components, where a negative value is
    /// either a bug or an attempt to confuse something downstream, so this
    /// refuses rather than silently taking the absolute value.
    pub fn read_integer(&mut self) -> Result<BigUint, String> {
        let bytes = self.read_integer_bytes()?;
        if bytes[0] & 0x80 != 0 {
            return Err("Negative INTEGER where an unsigned value is required."
                       .to_string());
        }
        Ok(BigUint::from_bytes_be(bytes))
    }

    /// The raw content octets of an INTEGER, checked for minimal encoding.
    pub fn read_integer_bytes(&mut self) -> Result<&'a [u8], String> {
        let bytes = self.read_tagged(Tag::universal(tag::INTEGER))?;
        if bytes.is_empty() {
            return Err("INTEGER with no content octets.".to_string());
        }
        // Minimal form: the first nine bits must not be all zero or all one,
        // which is exactly the redundant-leading-byte rule.
        if bytes.len() > 1 {
            let redundant = (bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
                || (bytes[0] == 0xff && bytes[1] & 0x80 != 0);
            if redundant {
                return Err("Non-minimal INTEGER encoding.".to_string());
            }
        }
        Ok(bytes)
    }

    /// A small INTEGER, for versions and path lengths.
    pub fn read_u32(&mut self) -> Result<u32, String> {
        let value = self.read_integer()?;
        value.to_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| "INTEGER does not fit in 32 bits.".to_string())
    }

    /// A BOOLEAN. DER allows exactly two encodings of it.
    pub fn read_bool(&mut self) -> Result<bool, String> {
        let bytes = self.read_tagged(Tag::universal(tag::BOOLEAN))?;
        match bytes {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            [other] => Err(format!("BOOLEAN must be 0x00 or 0xFF in DER, got 0x{:02x}.",
                                   other)),
            _ => Err(format!("BOOLEAN must be one byte, got {}.", bytes.len())),
        }
    }

    pub fn read_null(&mut self) -> Result<(), String> {
        let bytes = self.read_tagged(Tag::universal(tag::NULL))?;
        if bytes.is_empty() {
            Ok(())
        } else {
            Err("NULL must have no content.".to_string())
        }
    }

    pub fn read_octet_string(&mut self) -> Result<&'a [u8], String> {
        self.read_tagged(Tag::universal(tag::OCTET_STRING))
    }

    /// A BIT STRING, as whole bytes.
    ///
    /// The unused-bit count must be zero here: every BIT STRING a
    /// certificate puts a key or a signature in is a whole number of bytes,
    /// and a nonzero count there means something has been reinterpreted.
    /// Key usage bits, which legitimately have unused bits, go through
    /// `read_bit_string_with_unused`.
    pub fn read_bit_string(&mut self) -> Result<&'a [u8], String> {
        let (bytes, unused) = self.read_bit_string_with_unused()?;
        if unused != 0 {
            return Err(format!("Expected a whole number of bytes, {} bits unused.",
                               unused));
        }
        Ok(bytes)
    }

    /// A BIT STRING with its unused-bit count.
    pub fn read_bit_string_with_unused(&mut self) -> Result<(&'a [u8], u8), String> {
        let content = self.read_tagged(Tag::universal(tag::BIT_STRING))?;
        let (first, rest) = content.split_first()
            .ok_or_else(|| "BIT STRING with no content octets.".to_string())?;
        if *first > 7 {
            return Err(format!("BIT STRING claims {} unused bits.", first));
        }
        if *first != 0 && rest.is_empty() {
            return Err("Empty BIT STRING cannot have unused bits.".to_string());
        }
        // DER: the unused bits must be zero, so there is one encoding per value.
        if let Some(&last) = rest.last() {
            if *first != 0 && last & ((1u8 << first) - 1) != 0 {
                return Err("BIT STRING unused bits are not zero.".to_string());
            }
        }
        Ok((rest, *first))
    }

    /// An OBJECT IDENTIFIER, as its encoded bytes.
    ///
    /// Kept encoded rather than decoded into arcs: comparing OIDs is what
    /// certificate code actually does, and comparing byte slices is both
    /// faster and impossible to get wrong. `Oid::to_string` decodes when a
    /// human needs to read one.
    pub fn read_oid(&mut self) -> Result<Oid<'a>, String> {
        let bytes = self.read_tagged(Tag::universal(tag::OID))?;
        Oid::new(bytes)
    }

    /// A value tagged `[n]`, if that is what comes next. Returns `None`
    /// without consuming anything otherwise, which is what OPTIONAL means.
    pub fn read_optional_context(&mut self, number: u32, constructed: bool)
                                 -> Result<Option<&'a [u8]>, String> {
        let wanted = Tag::context(number, constructed);
        match self.peek_tag() {
            Some(tag) if tag == wanted => Ok(Some(self.read_tagged(wanted)?)),
            _ => Ok(None),
        }
    }

    /// A string, from any of the types certificates use for text.
    ///
    /// Returns the bytes and the tag, because the caller sometimes cares:
    /// comparing a PrintableString with a UTF8String is not the same
    /// question as comparing two of the same type, and name matching gets
    /// this wrong in interesting ways.
    pub fn read_string(&mut self) -> Result<(u32, &'a [u8]), String> {
        let (tag, content) = self.read_any()?;
        if tag.class != CLASS_UNIVERSAL || tag.constructed {
            return Err(format!("Expected a string, found {}.", tag.describe()));
        }
        match tag.number {
            tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING
            | tag::T61_STRING | tag::BMP_STRING => Ok((tag.number, content)),
            other => Err(format!("Tag {} is not a string type.", other)),
        }
    }

    /// A UTCTime or GeneralizedTime, as seconds since the Unix epoch.
    pub fn read_time(&mut self) -> Result<i64, String> {
        let (tag, content) = self.read_any()?;
        if tag.class != CLASS_UNIVERSAL || tag.constructed {
            return Err(format!("Expected a time, found {}.", tag.describe()));
        }
        match tag.number {
            tag::UTC_TIME => parse_utc_time(content),
            tag::GENERALIZED_TIME => parse_generalized_time(content),
            other => Err(format!("Tag {} is not a time type.", other)),
        }
    }
}

// ------------------------------------------------------------------- OIDs ---

/// An object identifier, held in its encoded form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Oid<'a>(&'a [u8]);

impl<'a> Oid<'a> {
    /// Wrap encoded OID bytes, checking that they are well formed.
    ///
    /// The checks matter because a sloppy encoder can produce several byte
    /// strings for one OID, and OID comparison is how a certificate decides
    /// what an extension means. Two encodings means two meanings.
    pub fn new(bytes: &'a [u8]) -> Result<Oid<'a>, String> {
        if bytes.is_empty() {
            return Err("OID with no content octets.".to_string());
        }
        if *bytes.last().unwrap() & 0x80 != 0 {
            return Err("OID ends mid-subidentifier.".to_string());
        }
        let mut starting = true;
        for &byte in bytes {
            if starting && byte == 0x80 {
                return Err("Non-minimal OID subidentifier.".to_string());
            }
            starting = byte & 0x80 == 0;
        }
        Ok(Oid(bytes))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The arcs, for `Display`. `None` if a subidentifier does not fit
    /// in a `u128`, which no real OID does and a malformed one can.
    fn arcs(&self) -> Option<Vec<u128>> {
        let mut arcs: Vec<u128> = Vec::new();
        let mut value: u128 = 0;
        let mut overflowed = false;
        for &byte in self.0 {
            value = match value.checked_mul(128).and_then(|v| v.checked_add((byte & 0x7f) as u128)) {
                Some(v) => v,
                None => { overflowed = true; 0 }
            };
            if byte & 0x80 == 0 {
                if arcs.is_empty() {
                    // The first byte packs two arcs: 40*first + second.
                    let first = core::cmp::min(value / 40, 2);
                    arcs.push(first);
                    arcs.push(value - first * 40);
                } else {
                    arcs.push(value);
                }
                value = 0;
            }
        }
        if overflowed {
            return None;
        }
        Some(arcs)
    }
}

/// Dotted decimal, for error messages and debugging.
///
/// A `Display` impl rather than an inherent `to_string`: the inherent one
/// shadows the blanket `ToString`, so `format!("{}", oid)` would have
/// printed something else entirely - and every error message here is
/// built with `format!`.
impl core::fmt::Display for Oid<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let arcs = match self.arcs() {
            Some(arcs) => arcs,
            None => return f.write_str("<oid too large to render>"),
        };
        for (index, arc) in arcs.iter().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            write!(f, "{}", arc)?;
        }
        Ok(())
    }
}

/// Compare an OID against a constant, which is how every caller uses them.
impl<'a> PartialEq<[u8]> for Oid<'a> {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

/// Encode a dotted-decimal OID. Used by the writer and by the tests, which
/// check it against the constants the parser compares with.
pub fn encode_oid(dotted: &str) -> Result<Vec<u8>, String> {
    let arcs: Vec<u128> = dotted.split('.')
        .map(|a| a.parse::<u128>().map_err(|_| format!("Bad OID arc {:?}.", a)))
        .collect::<Result<_, _>>()?;
    if arcs.len() < 2 {
        return Err("An OID needs at least two arcs.".to_string());
    }
    if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
        return Err("First two OID arcs are out of range.".to_string());
    }

    // X.660 leaves the second arc under 2 unbounded, so the sum is not:
    // `2.<u128::MAX>` is a well-formed string whose first subidentifier
    // does not fit.
    let first = arcs[0].checked_mul(40)
        .and_then(|value| value.checked_add(arcs[1]))
        .ok_or_else(|| "The second OID arc is too large to encode.".to_string())?;
    let mut out = Vec::new();
    push_base128(&mut out, first);
    for arc in &arcs[2..] {
        push_base128(&mut out, *arc);
    }
    Ok(out)
}

fn push_base128(out: &mut Vec<u8>, mut value: u128) {
    let mut group = Vec::new();
    loop {
        group.push((value & 0x7f) as u8);
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    for (index, byte) in group.iter().rev().enumerate() {
        let last = index == group.len() - 1;
        out.push(if last { *byte } else { byte | 0x80 });
    }
}

// ------------------------------------------------------------------ times ---

/// Days from the Unix epoch to the start of `year`, handling leap years.
fn days_from_epoch(year: i64, month: i64, day: i64) -> Result<i64, String> {
    if !(1..=12).contains(&month) {
        return Err(format!("Month {} is out of range.", month));
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let lengths = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30,
                   31, 31, 30, 31, 30, 31];
    if day < 1 || day > lengths[(month - 1) as usize] {
        return Err(format!("Day {} is out of range for month {}.", day, month));
    }

    // Days from 1970-01-01, counted the long way round rather than with a
    // clever formula, because a clever formula here would need its own test.
    let mut days: i64 = 0;
    if year >= 1970 {
        for y in 1970..year {
            days += if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 366 } else { 365 };
        }
    } else {
        for y in year..1970 {
            days -= if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 366 } else { 365 };
        }
    }
    days += lengths[..(month - 1) as usize].iter().sum::<i64>();
    days += day - 1;
    Ok(days)
}

fn digits(bytes: &[u8], at: usize, count: usize) -> Result<i64, String> {
    let end = at + count;
    if end > bytes.len() {
        return Err("Time value is too short.".to_string());
    }
    let mut value: i64 = 0;
    for &byte in &bytes[at..end] {
        if !byte.is_ascii_digit() {
            return Err("Time value contains a non-digit.".to_string());
        }
        value = value * 10 + (byte - b'0') as i64;
    }
    Ok(value)
}

fn assemble(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64)
            -> Result<i64, String> {
    if hour > 23 || minute > 59 || second > 59 {
        return Err(format!("Time {}:{}:{} is out of range.", hour, minute, second));
    }
    Ok(days_from_epoch(year, month, day)? * 86400 + hour * 3600 + minute * 60 + second)
}

/// Seconds since the epoch as `YYYYMMDDHHMMSSZ` - the form
/// `x509::builder`'s validity fields take.
///
/// The inverse of `read_time`, and the only way to put a time *back*
/// into a certificate after reading one out. A proxy mirroring somebody
/// else's certificate needs exactly that: the validity window has to be
/// copied, so that an expired certificate stays expired and the client
/// makes the decision it would have made talking directly.
///
/// The builder decides between UTCTime and GeneralizedTime from the
/// year, per RFC 5280 4.1.2.5, so this always writes the four-digit
/// form and lets that rule apply.
pub fn format_time(seconds: i64) -> String {
    // Days and the time within the day, floored - so a time before 1970
    // borrows rather than rounding towards zero.
    let mut days = seconds.div_euclid(86400);
    let rest = seconds.rem_euclid(86400);

    // The inverse of `days_from_epoch`, by the same civil-calendar
    // algorithm: shift the epoch to 0000-03-01 so a leap day lands at
    // the end of a 400 year era and the arithmetic has no special case
    // for February.
    days += 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524
                       - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4
                                    - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 }
                else { shifted_month - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", year, month, day,
            rest / 3600, (rest % 3600) / 60, rest % 60)
}

/// `YYMMDDHHMMSSZ`. DER requires seconds and the Z, and nothing else.
///
/// The two digit year is the interesting part: RFC 5280 says 00..=49 means
/// 20xx and 50..=99 means 19xx. That window closes in 2049, and a
/// certificate valid past it must use GeneralizedTime. Getting this rule
/// backwards makes expired certificates look valid.
fn parse_utc_time(bytes: &[u8]) -> Result<i64, String> {
    if bytes.len() != 13 || bytes[12] != b'Z' {
        return Err("UTCTime must be exactly YYMMDDHHMMSSZ in DER.".to_string());
    }
    let two = digits(bytes, 0, 2)?;
    let year = if two < 50 { 2000 + two } else { 1900 + two };
    assemble(year, digits(bytes, 2, 2)?, digits(bytes, 4, 2)?,
             digits(bytes, 6, 2)?, digits(bytes, 8, 2)?, digits(bytes, 10, 2)?)
}

/// `YYYYMMDDHHMMSSZ`. No fractional seconds, no offset - DER allows neither.
fn parse_generalized_time(bytes: &[u8]) -> Result<i64, String> {
    if bytes.len() != 15 || bytes[14] != b'Z' {
        return Err("GeneralizedTime must be exactly YYYYMMDDHHMMSSZ in DER."
                   .to_string());
    }
    assemble(digits(bytes, 0, 4)?, digits(bytes, 4, 2)?, digits(bytes, 6, 2)?,
             digits(bytes, 8, 2)?, digits(bytes, 10, 2)?, digits(bytes, 12, 2)?)
}

// ---------------------------------------------------------------- writer ---

/// Builds DER. Used for signing (a CSR, a certificate) and for the tests,
/// which need to construct malformed input on purpose.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { out: Vec::new() }
    }

    pub fn finish(self) -> Vec<u8> {
        self.out
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.out
    }

    /// One tag-length-value, with the length in its minimal form.
    pub fn write_tlv(&mut self, tag: Tag, content: &[u8]) {
        self.write_tag(tag);
        self.write_length(content.len());
        self.out.extend_from_slice(content);
    }

    fn write_tag(&mut self, tag: Tag) {
        let constructed = if tag.constructed { 0x20 } else { 0x00 };
        if tag.number < 0x1f {
            self.out.push(tag.class | constructed | tag.number as u8);
            return;
        }
        self.out.push(tag.class | constructed | 0x1f);
        let mut group = Vec::new();
        let mut value = tag.number;
        loop {
            group.push((value & 0x7f) as u8);
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        for (index, byte) in group.iter().rev().enumerate() {
            let last = index == group.len() - 1;
            self.out.push(if last { *byte } else { byte | 0x80 });
        }
    }

    fn write_length(&mut self, length: usize) {
        if length < 128 {
            self.out.push(length as u8);
            return;
        }
        let bytes = length.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        let significant = &bytes[start..];
        self.out.push(0x80 | significant.len() as u8);
        self.out.extend_from_slice(significant);
    }

    /// Write a constructed value by building its contents first, since the
    /// length has to be known before the contents can be written.
    pub fn write_constructed<F>(&mut self, tag: Tag, body: F)
    where F: FnOnce(&mut Writer) {
        let mut inner = Writer::new();
        body(&mut inner);
        let content = inner.finish();
        self.write_tlv(tag, &content);
    }

    pub fn write_sequence<F>(&mut self, body: F) where F: FnOnce(&mut Writer) {
        self.write_constructed(Tag::sequence(), body);
    }

    pub fn write_set<F>(&mut self, body: F) where F: FnOnce(&mut Writer) {
        self.write_constructed(Tag::set(), body);
    }

    /// An unsigned INTEGER, minimally encoded, with the leading zero that
    /// keeps it positive when the top bit would otherwise be set.
    pub fn write_integer(&mut self, value: &BigUint) {
        let mut bytes = value.to_bytes_be();
        if bytes.is_empty() {
            bytes.push(0);
        } else if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        self.write_tlv(Tag::universal(tag::INTEGER), &bytes);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.write_integer(&BigUint::from_u64(value as u64));
    }

    pub fn write_bool(&mut self, value: bool) {
        self.write_tlv(Tag::universal(tag::BOOLEAN),
                       &[if value { 0xff } else { 0x00 }]);
    }

    pub fn write_null(&mut self) {
        self.write_tlv(Tag::universal(tag::NULL), &[]);
    }

    pub fn write_octet_string(&mut self, content: &[u8]) {
        self.write_tlv(Tag::universal(tag::OCTET_STRING), content);
    }

    /// A BIT STRING holding whole bytes, so no unused bits.
    pub fn write_bit_string(&mut self, content: &[u8]) {
        let mut body = Vec::with_capacity(content.len() + 1);
        body.push(0);
        body.extend_from_slice(content);
        self.write_tlv(Tag::universal(tag::BIT_STRING), &body);
    }

    pub fn write_oid(&mut self, oid: &[u8]) {
        self.write_tlv(Tag::universal(tag::OID), oid);
    }

    pub fn write_utf8_string(&mut self, text: &str) {
        self.write_tlv(Tag::universal(tag::UTF8_STRING), text.as_bytes());
    }

    /// Raw bytes that are already DER, for copying a value through unchanged.
    pub fn write_raw(&mut self, der: &[u8]) {
        self.out.extend_from_slice(der);
    }
}

#[cfg(test)]
mod tests {
    /// `format_time` is the inverse of `read_time`, everywhere it matters.
    ///
    /// Written as a round trip rather than against a table of expected
    /// strings, because a table is a second implementation of the same
    /// calendar and would agree with a wrong one. The reader already
    /// has vectors of its own; this asserts the pair composes.
    #[test]
    fn test_times_round_trip_through_the_reader() {
        use super::*;

        // Every boundary the civil-calendar arithmetic has: the epoch,
        // leap days, century non-leap years, the UTCTime/GeneralizedTime
        // cut at 2049/2050, and either side of 1970.
        let stamps = [
            "19700101000000Z", "19691231235959Z", "19000301000000Z",
            "19960229120000Z", "20000229235959Z", "21000228000000Z",
            "20240229083000Z", "20491231235959Z", "20500101000000Z",
            "20241231235959Z", "20250101000000Z", "19851026012200Z",
            "20991231235959Z", "24991231235959Z",
        ];
        for stamp in stamps {
            let mut writer = Writer::new();
            writer.write_tlv(Tag::universal(tag::GENERALIZED_TIME),
                             stamp.as_bytes());
            let der = writer.finish();
            let seconds = Reader::new(&der).read_time()
                .unwrap_or_else(|e| panic!("{} did not read: {}", stamp, e));
            assert_eq!(format_time(seconds), stamp);
        }

        // And across a long sweep of seconds, so a day-boundary or
        // leap-year mistake cannot hide between the stamps above.
        for step in 0..4000i64 {
            let seconds = -2_000_000_000 + step * 1_234_567;
            let stamp = format_time(seconds);
            let mut writer = Writer::new();
            writer.write_tlv(Tag::universal(tag::GENERALIZED_TIME),
                             stamp.as_bytes());
            let der = writer.finish();
            let back = Reader::new(&der).read_time()
                .unwrap_or_else(|e| panic!("{} ({}) did not read: {}",
                                           stamp, seconds, e));
            assert_eq!(back, seconds, "{} round tripped wrong", stamp);
        }
    }

    use super::*;

    fn der(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_reads_simple_values() {
        // SEQUENCE { INTEGER 1, BOOLEAN true, NULL }
        // My first hand-assembly of this dropped a byte, which the length check
        // caught - which is the parser doing its job on its own test.
        let bytes = der("30080201010101ff0500");
        let mut reader = Reader::new(&bytes);
        let mut sequence = reader.read_sequence().unwrap();
        assert_eq!(sequence.read_u32().unwrap(), 1);
        assert!(sequence.read_bool().unwrap());
        sequence.read_null().unwrap();
        sequence.finish().unwrap();
        reader.finish().unwrap();
    }

    #[test]
    fn test_round_trip_through_the_writer() {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_u32(65537);
            w.write_bool(false);
            w.write_octet_string(b"hello");
            w.write_oid(&encode_oid("1.2.840.113549.1.1.11").unwrap());
            w.write_bit_string(&[0xde, 0xad]);
            w.write_utf8_string("hej");
        });
        let bytes = writer.finish();

        let mut reader = Reader::new(&bytes);
        let mut sequence = reader.read_sequence().unwrap();
        assert_eq!(sequence.read_u32().unwrap(), 65537);
        assert!(!sequence.read_bool().unwrap());
        assert_eq!(sequence.read_octet_string().unwrap(), b"hello");
        assert_eq!(sequence.read_oid().unwrap().to_string(), "1.2.840.113549.1.1.11");
        assert_eq!(sequence.read_bit_string().unwrap(), &[0xde, 0xad]);
        let (tag, text) = sequence.read_string().unwrap();
        assert_eq!(tag, tag::UTF8_STRING);
        assert_eq!(text, "hej".as_bytes());
        sequence.finish().unwrap();
        reader.finish().unwrap();
    }

    /// Long lengths must round trip, and the writer must use the minimal
    /// form - which the reader then insists on.
    #[test]
    fn test_long_lengths_round_trip() {
        for size in [127usize, 128, 129, 255, 256, 65535, 65536, 100_000] {
            let content = vec![0x41u8; size];
            let mut writer = Writer::new();
            writer.write_octet_string(&content);
            let bytes = writer.finish();

            let mut reader = Reader::new(&bytes);
            assert_eq!(reader.read_octet_string().unwrap().len(), size, "size {}", size);
            reader.finish().unwrap();
        }
    }

    /// Every one of these is a second encoding of something, and every one
    /// of them has been a real parser bug somewhere.
    #[test]
    fn test_malformed_encodings_are_rejected() {
        let cases: &[(&str, &str)] = &[
            ("0480",         "indefinite length"),
            ("048200ff",     "non-minimal long length"),
            ("048101",       "long form for a short length"),
            ("0203000001",   "non-minimal positive INTEGER"),
            ("0202ffff",     "non-minimal negative INTEGER"),
            ("0200",         "empty INTEGER"),
            ("020101ff",     "trailing data"),
            ("010101",       "BOOLEAN that is not 0x00 or 0xFF"),
            ("01020000",     "two byte BOOLEAN"),
            ("050100",       "NULL with content"),
            ("030200ff00",   "trailing data after BIT STRING"),
            ("030101",       "BIT STRING with unused bits and no data"),
            ("030208ff",     "BIT STRING claiming 8 unused bits"),
            ("030203ff",     "BIT STRING with nonzero unused bits"),
            ("0600",         "empty OID"),
            ("060180",       "OID ending mid-subidentifier"),
            ("06028001",     "non-minimal OID subidentifier"),
            ("0404deadbe",   "truncated content"),
            ("1f808101",     "non-minimal high tag number"),
        ];

        for (hex, why) in cases {
            let bytes = der(hex);
            let mut reader = Reader::new(&bytes);
            let result = match &bytes[0] {
                0x01 => reader.read_bool().map(|_| ()),
                0x02 => reader.read_integer().map(|_| ()),
                0x03 => reader.read_bit_string().map(|_| ()),
                0x05 => reader.read_null(),
                0x06 => reader.read_oid().map(|_| ()),
                _ => reader.read_any().map(|_| ()),
            };
            let result = result.and_then(|_| reader.finish());
            assert!(result.is_err(), "{} ({}) should have been rejected", hex, why);
        }
    }

    /// A SEQUENCE nested a thousand deep is four bytes per level to write
    /// and a stack overflow to parse recursively.
    #[test]
    fn test_deep_nesting_is_refused_rather_than_crashing() {
        let mut bytes = vec![0x05, 0x00]; // NULL at the centre
        for _ in 0..1000 {
            let mut wrapped = vec![0x30, bytes.len() as u8];
            if bytes.len() > 127 {
                wrapped = vec![0x30, 0x82, (bytes.len() >> 8) as u8, bytes.len() as u8];
            }
            wrapped.extend_from_slice(&bytes);
            bytes = wrapped;
        }

        let mut reader = Reader::new(&bytes);
        let mut depth = 0;
        loop {
            match reader.read_sequence() {
                Ok(inner) => { reader = inner; depth += 1; }
                Err(message) => {
                    assert!(message.contains("nesting") || message.contains("Expected"),
                            "unexpected error: {}", message);
                    break;
                }
            }
        }
        assert_eq!(depth, MAX_DEPTH, "should stop at MAX_DEPTH");
    }

    #[test]
    fn test_truncation_at_every_offset_is_an_error_not_a_panic() {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_u32(1);
            w.write_octet_string(&[0u8; 200]);
            w.write_oid(&encode_oid("2.5.4.3").unwrap());
        });
        let complete = writer.finish();

        for cut in 0..complete.len() {
            let mut reader = Reader::new(&complete[..cut]);
            // Must not panic, whatever it returns.
            let _ = reader.read_sequence().and_then(|mut inner| {
                inner.read_u32()?;
                inner.read_octet_string()?;
                inner.read_oid()?;
                inner.finish()
            });
        }
    }

    #[test]
    fn test_oid_encoding_matches_known_values() {
        // The ones certificates actually use, from RFC 5280 and PKCS#1.
        for (dotted, hex) in [
            ("1.2.840.113549.1.1.11", "2a864886f70d01010b"),  // sha256WithRSA
            ("1.2.840.113549.1.1.1", "2a864886f70d010101"),   // rsaEncryption
            ("1.2.840.10045.2.1", "2a8648ce3d0201"),          // id-ecPublicKey
            ("1.2.840.10045.4.3.2", "2a8648ce3d040302"),      // ecdsa-with-SHA256
            ("1.2.840.10045.3.1.7", "2a8648ce3d030107"),      // prime256v1
            ("2.5.4.3", "550403"),                            // commonName
            ("2.5.29.19", "551d13"),                          // basicConstraints
            ("2.5.29.17", "551d11"),                          // subjectAltName
            ("0.9.2342.19200300.100.1.25", "0992268993f22c640119"),  // domainComponent
        ] {
            let encoded = encode_oid(dotted).unwrap();
            assert_eq!(encoded, der(hex), "encoding {}", dotted);
            assert_eq!(Oid::new(&encoded).unwrap().to_string(), dotted,
                       "decoding {}", dotted);
        }

        assert!(encode_oid("3.1.1").is_err(), "first arc above 2");
        assert!(encode_oid("1.40").is_err(), "second arc above 39 under arc 1");
        assert!(encode_oid("1").is_err(), "needs two arcs");
        assert!(encode_oid("1.2.x").is_err());
    }

    /// A second arc under 2 that does not fit the first subidentifier
    /// is an error, not an overflow.
    ///
    /// What was wrong: `arcs[0] * 40 + arcs[1]` was unchecked, and X.660
    /// leaves the second arc under 2 unbounded, so
    /// `"2.340282366920938463463374607431768211455"` (2 followed by
    /// `u128::MAX`) panicked in a debug build and encoded wrong bytes in
    /// a release one. The string reaches this function from
    /// `registry::register`, that is from a library user's own text. The
    /// range test above only covered the first arc and the second arc
    /// under 0 and 1, which are bounded by the standard.
    #[test]
    fn test_a_second_arc_that_overflows_the_first_subidentifier_is_an_error() {
        let dotted = format!("2.{}", u128::MAX);
        let error = encode_oid(&dotted).unwrap_err();
        assert!(error.contains("too large"), "{}", error);
        // The largest that fits under arc 2 still encodes, and decodes
        // back to the same arcs.
        let largest = format!("2.{}", u128::MAX - 80);
        let encoded = encode_oid(&largest).unwrap();
        assert_eq!(Oid::new(&encoded).unwrap().to_string(), largest);
    }

    #[test]
    fn test_times() {
        // The epoch itself, in both spellings.
        let mut writer = Writer::new();
        writer.write_tlv(Tag::universal(tag::UTC_TIME), b"700101000000Z");
        writer.write_tlv(Tag::universal(tag::GENERALIZED_TIME), b"19700101000000Z");
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.read_time().unwrap(), 0);
        assert_eq!(reader.read_time().unwrap(), 0);

        for (encoding, seconds) in [
            (b"000101000000Z".as_slice(), 946_684_800i64),   // 2000-01-01, and the
            (b"490101000000Z".as_slice(), 2_493_072_000),    // top of the UTCTime window
            (b"500101000000Z".as_slice(), -631_152_000),     // 1950, the bottom of it
            (b"990101000000Z".as_slice(), 915_148_800),      // 1999
            (b"240229120000Z".as_slice(), 1_709_208_000),    // a leap day
        ] {
            let mut writer = Writer::new();
            writer.write_tlv(Tag::universal(tag::UTC_TIME), encoding);
            let bytes = writer.finish();
            assert_eq!(Reader::new(&bytes).read_time().unwrap(), seconds,
                       "{:?}", core::str::from_utf8(encoding).unwrap());
        }

        // Everything DER does not allow, and the impossible dates.
        for bad in [b"7001010000Z".as_slice(),     // no seconds
                    b"700101000000",               // no Z
                    b"700101000000+0100",          // an offset
                    b"7001010000000Z",             // fractional seconds
                    b"701301000000Z",              // month 13
                    b"700132000000Z",              // day 32
                    b"700101240000Z",              // hour 24
                    b"230229000000Z",              // 2023 was not a leap year
                    b"7001010000x0Z"] {            // a non-digit
            let mut writer = Writer::new();
            writer.write_tlv(Tag::universal(tag::UTC_TIME), bad);
            let bytes = writer.finish();
            assert!(Reader::new(&bytes).read_time().is_err(),
                    "{:?} should be rejected", core::str::from_utf8(bad));
        }
    }

    #[test]
    fn test_optional_context_tags() {
        // SEQUENCE { [0] INTEGER 2, INTEGER 7 } - the shape of a
        // certificate's version field followed by its serial number.
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_constructed(Tag::context(0, true), |inner| inner.write_u32(2));
            w.write_u32(7);
        });
        let bytes = writer.finish();

        let mut sequence = Reader::new(&bytes).read_sequence().unwrap();
        let version = sequence.read_optional_context(0, true).unwrap().unwrap();
        assert_eq!(Reader::new(version).read_u32().unwrap(), 2);
        // Asking for a tag that is not there must not consume anything.
        assert!(sequence.read_optional_context(3, true).unwrap().is_none());
        assert_eq!(sequence.read_u32().unwrap(), 7);
        sequence.finish().unwrap();
    }

    /// `read_raw` must hand back the original bytes, tag and all. Signature
    /// verification depends on this being exact.
    #[test]
    fn test_read_raw_returns_the_original_bytes() {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_sequence(|inner| inner.write_u32(42));
            w.write_u32(99);
        });
        let bytes = writer.finish();

        let mut sequence = Reader::new(&bytes).read_sequence().unwrap();
        let raw = sequence.read_raw().unwrap();
        assert_eq!(raw, &[0x30, 0x03, 0x02, 0x01, 0x2a]);
        assert_eq!(sequence.read_u32().unwrap(), 99);
    }

    #[test]
    fn test_integer_sign_handling() {
        // The writer must add a leading zero when the top bit is set, and
        // the reader must not complain about it.
        for value in ["7f", "80", "ff", "0100", "8000",
                      "ffffffffffffffffffffffffffffffff"] {
            let number = BigUint::from_hex(value).unwrap();
            let mut writer = Writer::new();
            writer.write_integer(&number);
            let bytes = writer.finish();
            assert_eq!(Reader::new(&bytes).read_integer().unwrap(), number,
                       "round trip {}", value);
        }

        // Zero is one content octet, 0x00.
        let mut writer = Writer::new();
        writer.write_integer(&BigUint::zero());
        assert_eq!(writer.as_bytes(), &[0x02, 0x01, 0x00]);

        // A genuinely negative INTEGER must be refused, not folded.
        let bytes = der("0201ff");
        assert!(Reader::new(&bytes).read_integer().is_err());
        // But its raw bytes are readable, for a caller that knows better.
        assert_eq!(Reader::new(&bytes).read_integer_bytes().unwrap(), &[0xff]);
    }
}
