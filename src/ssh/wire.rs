/*
SSH's wire encoding, RFC 4251 section 5.

Five types carry everything SSH sends: `byte`, `boolean`, `uint32`,
`string` (a `uint32` length and that many bytes) and `mpint`, plus
`name-list`, which is a `string` of comma-separated ASCII names. Every
key blob, every signature, every message and every input to the
exchange hash is built from them.

# Pitfalls

**An `mpint` is two's complement, big endian, and minimal.** A positive
number whose top bit is set gets a leading zero byte, or it reads as
negative; zero is the empty string, not one zero byte; and no other
leading zero or `0xff` byte is allowed. Every SSH implementation has had
a bug here, because the exchange hash takes the shared secret `K` as an
mpint: a secret whose top bit happens to be set hashes with an extra
byte, so getting the rule wrong fails one key exchange in two - or, with
the zero rule, one in 256 - and works the rest of the time.

**Reading refuses what writing would not produce.** A non-minimal mpint,
a negative one where only unsigned values make sense, a string longer
than what is left: each is an `Err`, because SSH hashes the bytes as
received and two encodings of one value are two different hashes.

**A `name-list` has no empty names and no non-ASCII.** RFC 4251 says
so, and a peer that sends `aes128-ctr,,aes256-ctr` is sending something
nobody can negotiate against.
*/

/// Appends SSH wire types to a buffer.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { out: Vec::new() }
    }

    pub fn byte(&mut self, value: u8) -> &mut Writer {
        self.out.push(value);
        self
    }

    pub fn boolean(&mut self, value: bool) -> &mut Writer {
        self.byte(u8::from(value))
    }

    pub fn uint32(&mut self, value: u32) -> &mut Writer {
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn uint64(&mut self, value: u64) -> &mut Writer {
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// A `string`: four bytes of length, then the bytes.
    pub fn string(&mut self, value: &[u8]) -> &mut Writer {
        self.uint32(value.len() as u32);
        self.out.extend_from_slice(value);
        self
    }

    /// An unsigned `mpint` from its big-endian magnitude, which may carry
    /// leading zeros: they are stripped, and a zero byte is put back in
    /// front if the top bit is set.
    pub fn mpint(&mut self, magnitude: &[u8]) -> &mut Writer {
        let first = magnitude.iter().position(|b| *b != 0)
            .unwrap_or(magnitude.len());
        let trimmed = &magnitude[first..];
        let pad = trimmed.first().is_some_and(|b| b & 0x80 != 0);
        self.uint32((trimmed.len() + usize::from(pad)) as u32);
        if pad {
            self.out.push(0);
        }
        self.out.extend_from_slice(trimmed);
        self
    }

    /// A `name-list`. Refuses an empty or non-ASCII name, or one with a
    /// comma in it, rather than writing something no peer can parse.
    pub fn name_list(&mut self, names: &[&str]) -> Result<&mut Writer, String> {
        for name in names {
            if name.is_empty() || !name.is_ascii() || name.contains(',') {
                return Err(format!("{name:?} cannot be a name in an SSH \
                                    name-list."));
            }
        }
        Ok(self.string(names.join(",").as_bytes()))
    }

    /// Bytes as they are, with no length.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Writer {
        self.out.extend_from_slice(bytes);
        self
    }

    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Reads SSH wire types from a slice.
pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, at: 0 }
    }

    fn take(&mut self, count: usize, what: &str) -> Result<&'a [u8], String> {
        if self.data.len() - self.at < count {
            return Err(format!("SSH: {what} needs {count} bytes and {} are \
                                left.", self.data.len() - self.at));
        }
        let out = &self.data[self.at..self.at + count];
        self.at += count;
        Ok(out)
    }

    pub fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1, "a byte")?[0])
    }

    /// `count` bytes with no length before them - a KEXINIT's cookie.
    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8], String> {
        self.take(count, "a fixed-length field")
    }

    /// A `boolean`. Any non-zero byte is true (RFC 4251 5).
    pub fn boolean(&mut self) -> Result<bool, String> {
        Ok(self.byte()? != 0)
    }

    pub fn uint32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4, "a uint32")?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn uint64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8, "a uint64")?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(array))
    }

    pub fn string(&mut self) -> Result<&'a [u8], String> {
        let length = self.uint32()? as usize;
        self.take(length, "a string")
    }

    /// A string that must be UTF-8 - a name, a method, a description.
    pub fn text(&mut self) -> Result<&'a str, String> {
        let bytes = self.string()?;
        core::str::from_utf8(bytes)
            .map_err(|_| "SSH: a text field is not UTF-8.".to_string())
    }

    /// An unsigned `mpint`, as its minimal big-endian magnitude (empty for
    /// zero). Refuses a negative value and any non-minimal encoding.
    pub fn mpint(&mut self) -> Result<&'a [u8], String> {
        let bytes = self.string()?;
        match bytes {
            [] => Ok(bytes),
            [first, ..] if first & 0x80 != 0 => Err(
                "SSH: a negative mpint where an unsigned value is expected."
                    .to_string()),
            [0] => Err("SSH: zero is the empty mpint, not a zero byte."
                       .to_string()),
            [0, second, ..] if second & 0x80 == 0 => Err(
                "SSH: an mpint with a leading zero byte it does not need."
                    .to_string()),
            [0, rest @ ..] => Ok(rest),
            _ => Ok(bytes),
        }
    }

    pub fn name_list(&mut self) -> Result<Vec<&'a str>, String> {
        let text = self.text()?;
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<&str> = text.split(',').collect();
        if names.iter().any(|name| name.is_empty() || !name.is_ascii()) {
            return Err(format!("SSH: {text:?} is not a valid name-list."));
        }
        Ok(names)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.at..];
        self.at = self.data.len();
        out
    }

    pub fn is_empty(&self) -> bool {
        self.at == self.data.len()
    }

    /// Refuse trailing bytes: a blob that parses with something left over
    /// is a blob with two readings.
    pub fn finish(&self, what: &str) -> Result<(), String> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(format!("SSH: {} bytes left over after {what}.",
                        self.data.len() - self.at))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hex string as bytes, with a leading zero nibble supplied when
    /// the length is odd - RFC 4251 writes `9a378f9b2e332a7`.
    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|c| !c.is_whitespace())
            .collect();
        let text = if text.len() % 2 == 1 { format!("0{text}") } else { text };
        (0..text.len()).step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    /// The rows of an examples table in RFC 4251 section 5: the lines
    /// between the first dashed rule after the type's own heading line
    /// (`"\n   mpint\n"`) and the next blank line, each split into its
    /// value and its representation.
    fn examples(heading: &str) -> Vec<(&'static str, Vec<u8>)> {
        let text = include_str!("../../rfcs/rfc4251.txt");
        let table = &text[text.find(heading).expect(heading)..];
        let table = &table[table.find("-----").unwrap()..];
        table.lines().skip(1).take_while(|line| !line.trim().is_empty())
            .map(|line| {
                let (value, encoding) = line.trim().split_once("  ").unwrap();
                (value.trim(), hex(encoding))
            })
            .collect()
    }

    /// RFC 4251 section 5's own mpint examples, read out of the document.
    #[test]
    fn test_the_mpint_examples_in_rfc_4251() {
        let rows = examples("\n   mpint\n");
        assert_eq!(rows.len(), 5, "RFC 4251's mpint examples");
        for (value, encoding) in rows {
            if let Some(negative) = value.strip_prefix('-') {
                // SSH never sends a negative number where this library
                // reads one, and the reader refuses them - but the
                // document's encoding is still two's complement of it.
                assert!(Reader::new(&encoding).mpint().is_err(), "{value}");
                let magnitude = hex(negative);
                let mut complement: Vec<u8> = encoding[4..].iter()
                    .map(|b| !b).collect();
                for byte in complement.iter_mut().rev() {
                    let (sum, carry) = byte.overflowing_add(1);
                    *byte = sum;
                    if !carry {
                        break;
                    }
                }
                let start = complement.iter().position(|b| *b != 0)
                    .unwrap_or(complement.len());
                assert_eq!(&complement[start..], magnitude.as_slice(), "{value}");
                continue;
            }
            let magnitude = hex(value);
            let mut writer = Writer::new();
            writer.mpint(&magnitude);
            assert_eq!(writer.finish(), encoding, "{value}");
            let start = magnitude.iter().position(|b| *b != 0)
                .unwrap_or(magnitude.len());
            assert_eq!(Reader::new(&encoding).mpint().unwrap(),
                       &magnitude[start..], "{value}");
        }
    }

    /// And its name-list examples.
    #[test]
    fn test_the_name_list_examples_in_rfc_4251() {
        let rows = examples("\n   name-list\n");
        assert_eq!(rows.len(), 3, "RFC 4251's name-list examples");
        for (value, encoding) in rows {
            // `(), the empty name-list` or `("zlib,none")`.
            let names: Vec<&str> = match value.split_once('"') {
                None => Vec::new(),
                Some((_, rest)) => rest.split('"').next().unwrap()
                    .split(',').collect(),
            };
            let mut writer = Writer::new();
            writer.name_list(&names).unwrap();
            assert_eq!(writer.finish(), encoding, "{value}");
            assert_eq!(Reader::new(&encoding).name_list().unwrap(), names);
        }
    }

    #[test]
    fn test_non_minimal_mpints_are_refused() {
        assert!(Reader::new(&[0, 0, 0, 1, 0]).mpint().is_err(), "zero byte");
        assert!(Reader::new(&[0, 0, 0, 2, 0, 0x7f]).mpint().is_err(),
                "a pad byte the value did not need");
        assert!(Reader::new(&[0, 0, 0, 1, 0x80]).mpint().is_err(), "negative");
        assert_eq!(Reader::new(&[0, 0, 0, 2, 0, 0x80]).mpint().unwrap(), &[0x80]);
        assert_eq!(Reader::new(&[0, 0, 0, 0]).mpint().unwrap(), &[] as &[u8]);
    }

    /// Leading zeros in the magnitude are not part of the value - which is
    /// the case `K` from an X25519 exchange hits one time in 256.
    #[test]
    fn test_leading_zeros_are_stripped_and_the_top_bit_padded() {
        let mut writer = Writer::new();
        writer.mpint(&[0, 0, 0x80, 1]);
        assert_eq!(writer.finish(), [0, 0, 0, 3, 0, 0x80, 1]);
        let mut writer = Writer::new();
        writer.mpint(&[0, 0]);
        assert_eq!(writer.finish(), [0, 0, 0, 0]);
    }

    #[test]
    fn test_strings_and_name_lists() {
        let mut writer = Writer::new();
        writer.string(b"ssh-ed25519");
        writer.name_list(&["aes128-ctr", "aes256-ctr"]).unwrap();
        writer.name_list(&[]).unwrap();
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.string().unwrap(), b"ssh-ed25519");
        assert_eq!(reader.name_list().unwrap(), ["aes128-ctr", "aes256-ctr"]);
        assert!(reader.name_list().unwrap().is_empty());
        reader.finish("the test").unwrap();

        assert!(Writer::new().name_list(&["a,b"]).is_err());
        assert!(Writer::new().name_list(&[""]).is_err());
        assert!(Reader::new(&[0, 0, 0, 1, 0xe9]).name_list().is_err(),
                "not ASCII");
        let empty_name = [0, 0, 0, 2, b'a', b','];
        assert!(Reader::new(&empty_name).name_list().is_err());
        assert!(Reader::new(&[0, 0, 0, 5, 1]).string().is_err(), "short");
    }
}
