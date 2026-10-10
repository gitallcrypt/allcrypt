/*
The TLS wire format's building blocks.

TLS has its own presentation language, and almost all of it is one idea:
a vector is a length prefix followed by that many bytes, where the prefix is
one, two or three bytes wide depending on how long the vector may get.
`opaque session_id<0..32>` is a one byte prefix; `CipherSuite
cipher_suites<2..2^16-2>` is two; a certificate list is three.

This is where every length in the protocol is read, so it is where every
length is checked. A reader that trusts a length field lets a peer point at
memory it should not, or - in a language where that is not possible - claim
a megabyte and make us allocate it before anything has been authenticated.

The rule throughout: **a length that does not fit is an error, and errors do
not have partial results.** Nothing here returns a truncated vector.
*/

use crate::tls::AlertDescription;

/// A failure while reading or writing, carrying the alert to send.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CodecError {
    pub alert: AlertDescription,
    pub detail: String,
}

impl CodecError {
    pub fn decode(detail: impl Into<String>) -> CodecError {
        CodecError { alert: AlertDescription::DECODE_ERROR, detail: detail.into() }
    }

    pub fn illegal(detail: impl Into<String>) -> CodecError {
        CodecError { alert: AlertDescription::ILLEGAL_PARAMETER, detail: detail.into() }
    }

    pub fn describe(&self) -> String {
        format!("{}: {}", self.alert.name(), self.detail)
    }
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.describe())
    }
}

impl From<CodecError> for String {
    fn from(error: CodecError) -> String {
        error.describe()
    }
}

pub type Result<T> = core::result::Result<T, CodecError>;

/// A cursor over TLS-encoded bytes.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn left(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Error unless everything has been consumed.
    ///
    /// Trailing bytes inside a handshake message are not harmless: they are
    /// where an extension nobody parsed can hide, and where two
    /// implementations can be made to disagree about what a message said.
    pub fn expect_empty(&self, what: &str) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(CodecError::decode(format!(
                "{} has {} trailing bytes.", what, self.left())))
        }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n)
            .ok_or_else(|| CodecError::decode("Length overflows."))?;
        if end > self.data.len() {
            return Err(CodecError::decode(format!(
                "Wanted {} bytes, {} remain.", n, self.left())));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// The 24 bit length TLS uses for handshake bodies and certificate lists.
    pub fn u24(&mut self) -> Result<u32> {
        let bytes = self.take(3)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// A vector with a one byte length prefix.
    pub fn vector8(&mut self) -> Result<&'a [u8]> {
        let length = self.u8()? as usize;
        self.take(length)
    }

    /// A vector with a two byte length prefix.
    pub fn vector16(&mut self) -> Result<&'a [u8]> {
        let length = self.u16()? as usize;
        self.take(length)
    }

    /// A vector with a three byte length prefix.
    pub fn vector24(&mut self) -> Result<&'a [u8]> {
        let length = self.u24()? as usize;
        self.take(length)
    }

    /// A sub-reader over a length-prefixed vector, for nested structures.
    pub fn sub16(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.vector16()?))
    }

    pub fn sub8(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.vector8()?))
    }

    pub fn sub24(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.vector24()?))
    }

    /// Every `u16` in a two-byte-prefixed vector, which is how cipher
    /// suites, supported groups and signature algorithms are all carried.
    pub fn u16_list(&mut self) -> Result<Vec<u16>> {
        let body = self.vector16()?;
        if body.len() % 2 != 0 {
            return Err(CodecError::decode(
                "A list of 16 bit values has an odd length."));
        }
        Ok(body.chunks(2).map(|pair| u16::from_be_bytes([pair[0], pair[1]])).collect())
    }
}

/// Builds TLS-encoded bytes.
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

    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    pub fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u24(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes()[1..]);
    }

    pub fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    pub fn raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    /// A vector with a one byte prefix. Errors rather than truncating if the
    /// body does not fit - silently writing a short vector would produce a
    /// message that parses into something other than what was meant.
    pub fn vector8(&mut self, body: &[u8]) -> Result<()> {
        if body.len() > u8::MAX as usize {
            return Err(CodecError::decode(format!(
                "{} bytes will not fit in a one byte length.", body.len())));
        }
        self.u8(body.len() as u8);
        self.raw(body);
        Ok(())
    }

    pub fn vector16(&mut self, body: &[u8]) -> Result<()> {
        if body.len() > u16::MAX as usize {
            return Err(CodecError::decode(format!(
                "{} bytes will not fit in a two byte length.", body.len())));
        }
        self.u16(body.len() as u16);
        self.raw(body);
        Ok(())
    }

    pub fn vector24(&mut self, body: &[u8]) -> Result<()> {
        if body.len() > 0xff_ffff {
            return Err(CodecError::decode(format!(
                "{} bytes will not fit in a three byte length.", body.len())));
        }
        self.u24(body.len() as u32);
        self.raw(body);
        Ok(())
    }

    /// Build a length-prefixed vector whose contents are written by a
    /// closure, since the length is only known once they are.
    pub fn nested16<F>(&mut self, body: F) -> Result<()>
    where F: FnOnce(&mut Writer) -> Result<()> {
        let mut inner = Writer::new();
        body(&mut inner)?;
        self.vector16(&inner.finish())
    }

    pub fn nested8<F>(&mut self, body: F) -> Result<()>
    where F: FnOnce(&mut Writer) -> Result<()> {
        let mut inner = Writer::new();
        body(&mut inner)?;
        self.vector8(&inner.finish())
    }

    pub fn nested24<F>(&mut self, body: F) -> Result<()>
    where F: FnOnce(&mut Writer) -> Result<()> {
        let mut inner = Writer::new();
        body(&mut inner)?;
        self.vector24(&inner.finish())
    }

    pub fn u16_list(&mut self, values: &[u16]) -> Result<()> {
        let mut body = Vec::with_capacity(values.len() * 2);
        for value in values {
            body.extend_from_slice(&value.to_be_bytes());
        }
        self.vector16(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integers_round_trip() {
        let mut writer = Writer::new();
        writer.u8(0x12);
        writer.u16(0x3456);
        writer.u24(0x789abc);
        writer.u32(0xdeadbeef);
        let bytes = writer.finish();
        assert_eq!(bytes.len(), 1 + 2 + 3 + 4);

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 0x12);
        assert_eq!(reader.u16().unwrap(), 0x3456);
        assert_eq!(reader.u24().unwrap(), 0x789abc);
        assert_eq!(reader.u32().unwrap(), 0xdeadbeef);
        reader.expect_empty("test").unwrap();
    }

    #[test]
    fn test_vectors_round_trip() {
        let short = vec![1u8, 2, 3];
        let long: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();

        let mut writer = Writer::new();
        writer.vector8(&short).unwrap();
        writer.vector16(&long).unwrap();
        writer.vector24(&short).unwrap();
        let bytes = writer.finish();

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.vector8().unwrap(), &short[..]);
        assert_eq!(reader.vector16().unwrap(), &long[..]);
        assert_eq!(reader.vector24().unwrap(), &short[..]);
        reader.expect_empty("test").unwrap();
    }

    #[test]
    fn test_a_vector_that_does_not_fit_is_an_error_not_a_truncation() {
        let mut writer = Writer::new();
        assert!(writer.vector8(&vec![0u8; 256]).is_err());
        assert!(writer.vector8(&vec![0u8; 255]).is_ok());
        assert!(writer.vector16(&vec![0u8; 65536]).is_err());
    }

    /// The whole point of this module: a length that does not fit must be
    /// an error, not a short read.
    #[test]
    fn test_lengths_are_checked() {
        // Claims five bytes, has two.
        let mut reader = Reader::new(&[0x05, 0x01, 0x02]);
        assert!(reader.vector8().is_err());

        // Claims 65535 bytes, has none.
        let mut reader = Reader::new(&[0xff, 0xff]);
        assert!(reader.vector16().is_err());

        // A truncated length prefix.
        let mut reader = Reader::new(&[0xff]);
        assert!(reader.vector16().is_err());

        let mut reader = Reader::new(&[]);
        assert!(reader.u8().is_err());
        assert!(reader.u16().is_err());
        assert!(reader.u24().is_err());
    }

    #[test]
    fn test_u16_lists() {
        let values = vec![0x1301u16, 0xc02f, 0x002f, 0x0005];
        let mut writer = Writer::new();
        writer.u16_list(&values).unwrap();
        let bytes = writer.finish();
        assert_eq!(&bytes[..2], &[0, 8]);

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u16_list().unwrap(), values);

        // An odd length is a malformed list, not a list with a spare byte.
        let mut reader = Reader::new(&[0, 3, 1, 2, 3]);
        assert!(reader.u16_list().is_err());
    }

    #[test]
    fn test_nested_writers() {
        let mut writer = Writer::new();
        writer.nested16(|inner| {
            inner.u8(1);
            inner.nested8(|deeper| {
                deeper.u16(0x0203);
                Ok(())
            })?;
            Ok(())
        }).unwrap();

        let bytes = writer.finish();
        assert_eq!(bytes, vec![0, 4, 1, 2, 2, 3]);

        let mut reader = Reader::new(&bytes);
        let mut outer = reader.sub16().unwrap();
        assert_eq!(outer.u8().unwrap(), 1);
        let mut inner = outer.sub8().unwrap();
        assert_eq!(inner.u16().unwrap(), 0x0203);
        inner.expect_empty("inner").unwrap();
        outer.expect_empty("outer").unwrap();
    }

    #[test]
    fn test_trailing_bytes_are_refused() {
        let reader = Reader::new(&[1, 2, 3]);
        let error = reader.expect_empty("a message").unwrap_err();
        assert_eq!(error.alert, AlertDescription::DECODE_ERROR);
        assert!(error.detail.contains("3 trailing bytes"));
    }

    /// Reading a truncation of anything must be an error rather than a
    /// panic, at every offset.
    #[test]
    fn test_no_truncation_panics() {
        let mut writer = Writer::new();
        writer.u16(0x0303);
        writer.vector8(&[1, 2, 3]).unwrap();
        writer.vector16(&vec![7u8; 300]).unwrap();
        writer.u16_list(&[1, 2, 3]).unwrap();
        let bytes = writer.finish();

        for cut in 0..bytes.len() {
            let mut reader = Reader::new(&bytes[..cut]);
            let outcome = (|| -> Result<()> {
                reader.u16()?;
                reader.vector8()?;
                reader.vector16()?;
                reader.u16_list()?;
                Ok(())
            })();
            // Whatever it decided, it must not have panicked - and a
            // truncated input must not have succeeded. Every `cut` in the
            // range is a truncation, so there is no complete case to
            // exempt.
            assert!(outcome.is_err(), "a truncation at {} parsed as complete", cut);
        }
    }
}
