//! PDF objects: reading them from bytes and writing them back.
//!
//! ISO 32000 section 7.3. Eight kinds and a reference, with two traps
//! for anything that decrypts: a string's bytes are what is encrypted,
//! so both of its syntaxes - `(literal)` with its escapes and `<hex>` -
//! have to come back to the same bytes; and a stream's length may be an
//! indirect object that has to be looked up before the data can be cut
//! out of the file.

#[derive(Clone, Debug, PartialEq)]
pub enum Object {
    Null,
    Bool(bool),
    Integer(i64),
    /// Kept as written, so that writing it back changes nothing.
    Real(String),
    String(Vec<u8>),
    Name(Vec<u8>),
    Array(Vec<Object>),
    Dictionary(Dict),
    Reference(u32, u16),
    Stream(Dict, Vec<u8>),
}

pub type Dict = Vec<(Vec<u8>, Object)>;

pub fn get<'a>(dict: &'a Dict, key: &str) -> Option<&'a Object> {
    dict.iter().find(|(k, _)| k == key.as_bytes()).map(|(_, v)| v)
}

pub fn set(dict: &mut Dict, key: &str, value: Object) {
    match dict.iter_mut().find(|(k, _)| k == key.as_bytes()) {
        Some(entry) => entry.1 = value,
        None => dict.push((key.as_bytes().to_vec(), value)),
    }
}

pub fn remove(dict: &mut Dict, key: &str) {
    dict.retain(|(k, _)| k != key.as_bytes());
}

impl Object {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Object::Integer(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_name(&self) -> Option<&[u8]> {
        match self {
            Object::Name(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Object::Dictionary(d) | Object::Stream(d, _) => Some(d),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Object::String(s) => Some(s),
            _ => None,
        }
    }
}

// --------------------------------------------------------------- lexing --

pub fn is_white(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

pub fn is_delimiter(byte: u8) -> bool {
    matches!(byte, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}

pub struct Parser<'a> {
    pub data: &'a [u8],
    pub at: usize,
}

/// What a stream's `/Length` resolves to when it is a reference; the
/// parser cannot look objects up itself.
pub type Resolver<'r> = &'r dyn Fn(u32, u16) -> Option<i64>;

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8], at: usize) -> Parser<'a> {
        Parser { data, at }
    }

    fn error<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("PDF: {what} at byte {}", self.at))
    }

    pub fn skip_white(&mut self) {
        while self.at < self.data.len() {
            let byte = self.data[self.at];
            if is_white(byte) {
                self.at += 1;
            } else if byte == b'%' {
                while self.at < self.data.len() && !matches!(self.data[self.at], b'\r' | b'\n') {
                    self.at += 1;
                }
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.at).copied()
    }

    /// A bare token: a number, a keyword, `R`.
    pub fn token(&mut self) -> &'a [u8] {
        self.skip_white();
        let start = self.at;
        while self.at < self.data.len() && !is_white(self.data[self.at])
            && !is_delimiter(self.data[self.at]) {
            self.at += 1;
        }
        &self.data[start..self.at]
    }

    pub fn keyword(&mut self, word: &str) -> Result<(), String> {
        let found = self.token();
        if found == word.as_bytes() {
            Ok(())
        } else {
            self.error(&format!("expected {word}, found {:?}", String::from_utf8_lossy(found)))
        }
    }

    fn literal_string(&mut self) -> Result<Vec<u8>, String> {
        self.at += 1;
        let mut out = Vec::new();
        let mut depth = 1;
        loop {
            let byte = match self.peek() {
                Some(b) => b,
                None => return self.error("an unterminated string"),
            };
            self.at += 1;
            match byte {
                b'(' => {
                    depth += 1;
                    out.push(byte);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(out);
                    }
                    out.push(byte);
                }
                b'\\' => {
                    let next = match self.peek() {
                        Some(b) => b,
                        None => return self.error("a string ending in a backslash"),
                    };
                    self.at += 1;
                    match next {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'0'..=b'7' => {
                            let mut value = u32::from(next - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        value = value * 8 + u32::from(d - b'0');
                                        self.at += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push(value as u8);
                        }
                        // A backslash before an end of line continues the
                        // string onto the next one.
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.at += 1;
                            }
                        }
                        b'\n' => {}
                        other => out.push(other),
                    }
                }
                // An end of line in a string is a single LF, whatever
                // the file used.
                b'\r' => {
                    if self.peek() == Some(b'\n') {
                        self.at += 1;
                    }
                    out.push(b'\n');
                }
                other => out.push(other),
            }
        }
    }

    fn hex_string(&mut self) -> Result<Vec<u8>, String> {
        self.at += 1;
        let mut digits = Vec::new();
        loop {
            match self.peek() {
                Some(b'>') => {
                    self.at += 1;
                    break;
                }
                Some(b) if is_white(b) => self.at += 1,
                Some(b) if b.is_ascii_hexdigit() => {
                    digits.push(b);
                    self.at += 1;
                }
                _ => return self.error("a malformed hex string"),
            }
        }
        // An odd final digit is followed by an implied 0.
        if digits.len() % 2 == 1 {
            digits.push(b'0');
        }
        Ok(digits.chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap_or("00"), 16).unwrap_or(0))
            .collect())
    }

    fn name(&mut self) -> Result<Vec<u8>, String> {
        self.at += 1;
        let raw = self.token_after_slash();
        let mut out = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'#' {
                if let Some(v) = raw.get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(raw[i]);
            i += 1;
        }
        Ok(out)
    }

    fn token_after_slash(&mut self) -> &'a [u8] {
        let start = self.at;
        while self.at < self.data.len() && !is_white(self.data[self.at])
            && !is_delimiter(self.data[self.at]) {
            self.at += 1;
        }
        &self.data[start..self.at]
    }

    /// One object. A number followed by a number and `R` is a
    /// reference; a dictionary followed by `stream` is a stream.
    pub fn object(&mut self, resolve: Resolver) -> Result<Object, String> {
        self.object_at_depth(resolve, 0)
    }

    fn object_at_depth(&mut self, resolve: Resolver, depth: usize) -> Result<Object, String> {
        if depth > 200 {
            return self.error("objects nested more than 200 deep");
        }
        self.skip_white();
        match self.peek() {
            None => self.error("the end of the data where an object was expected"),
            Some(b'(') => Ok(Object::String(self.literal_string()?)),
            Some(b'/') => Ok(Object::Name(self.name()?)),
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_white();
                    if self.peek() == Some(b']') {
                        self.at += 1;
                        return Ok(Object::Array(items));
                    }
                    items.push(self.object_at_depth(resolve, depth + 1)?);
                }
            }
            Some(b'<') if self.data.get(self.at + 1) == Some(&b'<') => {
                self.at += 2;
                let mut dict = Dict::new();
                loop {
                    self.skip_white();
                    if self.data[self.at..].starts_with(b">>") {
                        self.at += 2;
                        break;
                    }
                    if self.peek() != Some(b'/') {
                        return self.error("a dictionary key that is not a name");
                    }
                    let key = self.name()?;
                    let value = self.object_at_depth(resolve, depth + 1)?;
                    dict.push((key, value));
                }
                // A stream?
                let save = self.at;
                if self.token() == b"stream" {
                    // The keyword is followed by CRLF or LF (a lone CR
                    // is tolerated, as every reader does).
                    if self.data[self.at..].starts_with(b"\r\n") {
                        self.at += 2;
                    } else if matches!(self.peek(), Some(b'\n' | b'\r')) {
                        self.at += 1;
                    }
                    let length = match get(&dict, "Length") {
                        Some(Object::Integer(n)) => Some(*n),
                        Some(Object::Reference(n, g)) => resolve(*n, *g),
                        _ => None,
                    };
                    let start = self.at;
                    let end = match length.and_then(|l| usize::try_from(l).ok())
                        .and_then(|l| start.checked_add(l))
                        .filter(|e| *e <= self.data.len()
                                && find(&self.data[*e..(*e + 32).min(self.data.len())],
                                        b"endstream").is_some()) {
                        Some(end) => end,
                        // A wrong or unresolvable length: find the end
                        // the way every reader does in that case.
                        None => match find(&self.data[start..], b"endstream") {
                            Some(offset) => {
                                let mut end = start + offset;
                                if self.data[..end].ends_with(b"\r\n") {
                                    end -= 2;
                                } else if self.data[..end].ends_with(b"\n")
                                    || self.data[..end].ends_with(b"\r") {
                                    end -= 1;
                                }
                                end
                            }
                            None => return self.error("a stream with no endstream"),
                        },
                    };
                    let data = self.data[start..end].to_vec();
                    self.at = end;
                    self.keyword("endstream")?;
                    return Ok(Object::Stream(dict, data));
                }
                self.at = save;
                Ok(Object::Dictionary(dict))
            }
            Some(b'<') => Ok(Object::String(self.hex_string()?)),
            Some(_) => {
                let token = self.token();
                if token.is_empty() {
                    return self.error("an unexpected delimiter");
                }
                match token {
                    b"null" => return Ok(Object::Null),
                    b"true" => return Ok(Object::Bool(true)),
                    b"false" => return Ok(Object::Bool(false)),
                    _ => {}
                }
                let text = std::str::from_utf8(token).map_err(|_| "a non-ASCII token")?;
                if let Ok(number) = text.parse::<i64>() {
                    // `n g R`?
                    let save = self.at;
                    let generation = self.token();
                    if let Ok(g) = std::str::from_utf8(generation).unwrap_or("").parse::<u16>() {
                        if self.token() == b"R" {
                            if let Ok(n) = u32::try_from(number) {
                                return Ok(Object::Reference(n, g));
                            }
                        }
                    }
                    self.at = save;
                    return Ok(Object::Integer(number));
                }
                if text.parse::<f64>().is_ok()
                    || text.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '+')) {
                    return Ok(Object::Real(text.to_string()));
                }
                self.error(&format!("an unknown token {text:?}"))
            }
        }
    }
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// -------------------------------------------------------------- writing --

fn write_name(name: &[u8], out: &mut Vec<u8>) {
    out.push(b'/');
    for &byte in name {
        if byte <= b' ' || byte > b'~' || byte == b'#' || is_delimiter(byte) {
            out.extend_from_slice(format!("#{byte:02X}").as_bytes());
        } else {
            out.push(byte);
        }
    }
}

/// Strings are always written as hex: no escaping to get wrong, and
/// encrypted bytes are mostly unprintable anyway.
pub fn write(object: &Object, out: &mut Vec<u8>) {
    match object {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Object::Real(text) => out.extend_from_slice(text.as_bytes()),
        Object::String(bytes) => {
            out.push(b'<');
            for b in bytes {
                out.extend_from_slice(format!("{b:02x}").as_bytes());
            }
            out.push(b'>');
        }
        Object::Name(name) => write_name(name, out),
        Object::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write(item, out);
            }
            out.push(b']');
        }
        Object::Dictionary(dict) => write_dict(dict, out),
        Object::Reference(n, g) => out.extend_from_slice(format!("{n} {g} R").as_bytes()),
        Object::Stream(dict, data) => {
            let mut dict = dict.clone();
            set(&mut dict, "Length", Object::Integer(data.len() as i64));
            write_dict(&dict, out);
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(data);
            out.extend_from_slice(b"\nendstream");
        }
    }
}

fn write_dict(dict: &Dict, out: &mut Vec<u8>) {
    out.extend_from_slice(b"<<");
    for (key, value) in dict {
        write_name(key, out);
        out.push(b' ');
        write(value, out);
    }
    out.extend_from_slice(b">>");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &[u8]) -> Object {
        Parser::new(text, 0).object(&|_, _| None).unwrap()
    }

    #[test]
    fn test_both_string_syntaxes_give_the_same_bytes() {
        assert_eq!(parse(b"(a\\(b\\)c\\101\\n\\\\ (nested))"),
                   Object::String(b"a(b)cA\n\\ (nested)".to_vec()));
        // White space inside is ignored, and an odd final digit is
        // followed by an implied 0.
        assert_eq!(parse(b"<6 1 6 1>"), Object::String(b"aa".to_vec()));
        assert_eq!(parse(b"<616>"), Object::String(b"a`".to_vec()));
        assert_eq!(parse(b"(line\\\r\nnext\r\nend)"), Object::String(b"linenext\nend".to_vec()));
    }

    #[test]
    fn test_references_names_and_streams() {
        let parsed = parse(b"<</A 1 0 R/B[1 2.5 -3]/N#20x true/Length 3>>stream\r\nabc\nendstream");
        match parsed {
            Object::Stream(dict, data) => {
                assert_eq!(data, b"abc");
                assert_eq!(get(&dict, "A"), Some(&Object::Reference(1, 0)));
                assert_eq!(get(&dict, "B"), Some(&Object::Array(vec![
                    Object::Integer(1), Object::Real("2.5".to_string()), Object::Integer(-3)])));
                assert_eq!(get(&dict, "N x"), Some(&Object::Bool(true)));
            }
            other => panic!("{other:?}"),
        }
        // A wrong length is recovered from `endstream`.
        match parse(b"<</Length 99>>stream\nabcd\nendstream") {
            Object::Stream(_, data) => assert_eq!(data, b"abcd"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_what_is_written_reads_back() {
        let object = parse(b"<</S(\\000\\377 x)/N/A#2fB/R 1 0 R/X[true false null 1.50]>>");
        let mut out = Vec::new();
        write(&object, &mut out);
        assert_eq!(parse(&out), object);
    }
}
