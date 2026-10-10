//! JSON (RFC 8259), read and written: what JOSE's headers, keys and
//! serializations need.
//!
//! An object keeps its members in the order they were read or added,
//! because a JWS protected header is signed as the bytes it was written
//! as, and anything that writes one back out should not reorder it. A
//! duplicate member name is refused (RFC 7515 4 requires that of a
//! header; RFC 8259 leaves it open, which is how two parsers come to
//! disagree on which value was meant).
//!
//! Numbers keep their text and are read as integers on request; nothing
//! here needs a fraction, and turning one into an `f64` would lose the
//! large integers that a JWE's `p2c` or a JWT's `exp` may carry.

#![allow(dead_code)]

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// The number's text, as written.
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(Json::String(s)) => Some(s),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(text) => text.parse().ok(),
            _ => None,
        }
    }

    pub fn members(&self) -> &[(String, Json)] {
        match self {
            Json::Object(members) => members,
            _ => &[],
        }
    }

    /// Set a member, replacing one of the same name in place or adding it
    /// at the end.
    pub fn set(&mut self, name: &str, value: Json) {
        if let Json::Object(members) = self {
            match members.iter_mut().find(|(k, _)| k == name) {
                Some(slot) => slot.1 = value,
                None => members.push((name.to_string(), value)),
            }
        }
    }

    pub fn object() -> Json {
        Json::Object(Vec::new())
    }

    pub fn string(text: &str) -> Json {
        Json::String(text.to_string())
    }

    /// Compact text: no whitespace, members in order.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        write(self, &mut out);
        out
    }
}

fn write(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(text) => out.push_str(text),
        Json::String(s) => write_string(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Json::Object(members) => {
            out.push('{');
            for (i, (name, item)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write(item, out);
            }
            out.push('}');
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse one JSON text, which must be all of `text` but for whitespace.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser { bytes: text.as_bytes(), at: 0, depth: 0 };
    p.space();
    let value = p.value()?;
    p.space();
    if p.at != p.bytes.len() {
        return Err(format!("JSON: text after the value at byte {}.", p.at));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, literal: &str) -> Result<(), String> {
        if self.bytes[self.at..].starts_with(literal.as_bytes()) {
            self.at += literal.len();
            Ok(())
        } else {
            Err(format!("JSON: expected {literal} at byte {}.", self.at))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.depth += 1;
        if self.depth > 64 {
            return Err("JSON: nested more than 64 deep.".to_string());
        }
        let value = match self.bytes.get(self.at) {
            None => Err("JSON: ends where a value should be.".to_string()),
            Some(b'n') => self.expect("null").map(|_| Json::Null),
            Some(b't') => self.expect("true").map(|_| Json::Bool(true)),
            Some(b'f') => self.expect("false").map(|_| Json::Bool(false)),
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(&other) => Err(format!("JSON: unexpected {:?} at byte {}.", other as char,
                                        self.at)),
        };
        self.depth -= 1;
        value
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.at;
        if self.bytes[self.at] == b'-' {
            self.at += 1;
        }
        let digits = |p: &mut Self| {
            let from = p.at;
            while matches!(p.bytes.get(p.at), Some(b'0'..=b'9')) {
                p.at += 1;
            }
            p.at - from
        };
        let integer_start = self.at;
        if digits(self) == 0 {
            return Err(format!("JSON: a number without digits at byte {start}."));
        }
        if self.bytes[integer_start] == b'0' && self.at - integer_start > 1 {
            return Err(format!("JSON: a number with a leading zero at byte {start}."));
        }
        if self.bytes.get(self.at) == Some(&b'.') {
            self.at += 1;
            if digits(self) == 0 {
                return Err(format!("JSON: no digits after the point at byte {start}."));
            }
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if digits(self) == 0 {
                return Err(format!("JSON: no digits in the exponent at byte {start}."));
            }
        }
        Ok(Json::Number(String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned()))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self.bytes.get(self.at..self.at + 4)
            .ok_or("JSON: a \\u escape cut short.")?;
        // Four hex digits exactly: `from_str_radix` alone would also
        // take a sign, and `"\u+1ab"` is a string no other parser reads.
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err("JSON: a bad \\u escape.".to_string());
        }
        let text = std::str::from_utf8(digits).map_err(|_| "JSON: a bad \\u escape.")?;
        let value = u32::from_str_radix(text, 16).map_err(|_| "JSON: a bad \\u escape.")?;
        self.at += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, String> {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let b = *self.bytes.get(self.at).ok_or("JSON: a string with no end.")?;
            self.at += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let e = *self.bytes.get(self.at).ok_or("JSON: an escape with no end.")?;
                    self.at += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&first) {
                                // A surrogate pair, or nothing.
                                self.expect("\\u")?;
                                let second = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&second) {
                                    return Err("JSON: a lone high surrogate.".to_string());
                                }
                                0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                            } else {
                                first
                            };
                            char::from_u32(code).ok_or("JSON: a lone low surrogate.")?
                        }
                        other => return Err(format!("JSON: unknown escape \\{}.",
                                                    other as char)),
                    };
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                }
                0x00..=0x1f => return Err("JSON: a control character in a string."
                                              .to_string()),
                other => out.push(other),
            }
        }
        String::from_utf8(out).map_err(|_| "JSON: a string that is not UTF-8.".to_string())
    }

    fn array(&mut self) -> Result<Json, String> {
        self.at += 1;
        let mut items = Vec::new();
        self.space();
        if self.bytes.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.space();
            items.push(self.value()?);
            self.space();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(format!("JSON: expected , or ] at byte {}.", self.at)),
            }
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.at += 1;
        let mut members: Vec<(String, Json)> = Vec::new();
        self.space();
        if self.bytes.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.space();
            if self.bytes.get(self.at) != Some(&b'"') {
                return Err(format!("JSON: expected a member name at byte {}.", self.at));
            }
            let name = self.string()?;
            if members.iter().any(|(k, _)| *k == name) {
                return Err(format!("JSON: the member {name:?} twice."));
            }
            self.space();
            self.expect(":")?;
            self.space();
            let value = self.value()?;
            members.push((name, value));
            self.space();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(members));
                }
                _ => return Err(format!("JSON: expected , or }} at byte {}.", self.at)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_reads_and_writes_back() {
        let text = r#"{"alg":"RS256","n":-12.5e+3,"a":[true,false,null,{}],"s":"\u00e9\ud83d\ude00\"\\\/"}"#;
        let value = parse(text).unwrap();
        assert_eq!(value.str("alg"), Some("RS256"));
        assert_eq!(value.str("s"), Some("é😀\"\\/"));
        assert_eq!(value.get("n"), Some(&Json::Number("-12.5e+3".into())));
        assert_eq!(value.to_text(),
                   r#"{"alg":"RS256","n":-12.5e+3,"a":[true,false,null,{}],"s":"é😀\"\\/"}"#);
        assert_eq!(parse(&value.to_text()).unwrap(), value);
        assert_eq!(parse(" [ 1 , 2 ] \n").unwrap().to_text(), "[1,2]");
    }

    /// `\u` escapes went through `from_str_radix`, which takes a sign,
    /// so `"\u+1ab"` and `"\u-1ab"` parsed where every other JSON
    /// parser refuses them; two readers disagreeing on a header is what
    /// this module exists to avoid. The refused list had no signed
    /// escape.
    #[test]
    fn test_json_refuses_what_it_should() {
        for bad in [r#"{"a":1,"a":2}"#, "[1,]", "{\"a\" 1}", "01", "1.", "-", "\"\\x\"",
                    "\"\\ud800\"", "\"\\udc00\"", "\"a\nb\"", "[1] x", "", "tru", "{\"a\":}",
                    "\"\\u+1ab\"", "\"\\u-1ab\"", "\"\\u 1ab\""] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(&deep).is_err());
    }
}
