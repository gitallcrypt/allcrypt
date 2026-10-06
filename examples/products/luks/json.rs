//! Just enough JSON for a LUKS2 header: parse, look up, write.
//!
//! Objects keep their keys in order, so a header read and written back
//! comes out with its fields where they were. Numbers are kept as the
//! text they were written as; LUKS2 writes every 64 bit quantity as a
//! decimal *string* ("string-uint64" in the specification) precisely so
//! that a JSON library holding numbers as doubles does not round them,
//! and `as_u64` reads either form.

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `get`, as an error naming the path when absent.
    pub fn field(&self, key: &str) -> Result<&Value, String> {
        self.get(key).ok_or_else(|| format!("LUKS2: the JSON has no {key:?} here."))
    }

    pub fn as_str(&self) -> Result<&str, String> {
        match self {
            Value::String(text) => Ok(text),
            other => Err(format!("LUKS2: expected a string, found {other:?}.")),
        }
    }

    /// A number, or a string holding one.
    pub fn as_u64(&self) -> Result<u64, String> {
        match self {
            Value::Number(text) | Value::String(text) => text.parse()
                .map_err(|_| format!("LUKS2: {text:?} is not an unsigned integer.")),
            other => Err(format!("LUKS2: expected a number, found {other:?}.")),
        }
    }

    pub fn entries(&self) -> Result<&[(String, Value)], String> {
        match self {
            Value::Object(entries) => Ok(entries),
            other => Err(format!("LUKS2: expected an object, found {other:?}.")),
        }
    }

    pub fn items(&self) -> Result<&[Value], String> {
        match self {
            Value::Array(items) => Ok(items),
            other => Err(format!("LUKS2: expected an array, found {other:?}.")),
        }
    }

    /// Compact JSON, keys in their order.
    pub fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(text) => out.push_str(text),
            Value::String(text) => write_string(text, out),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Object(entries) => {
                out.push('{');
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
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

/// Shorthands for building a header.
pub fn obj(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

pub fn s(text: impl Into<String>) -> Value {
    Value::String(text.into())
}

pub fn n(number: u64) -> Value {
    Value::Number(number.to_string())
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut parser = Parser { bytes: text.as_bytes(), at: 0, depth: 0 };
    let value = parser.value()?;
    parser.space();
    if parser.at != parser.bytes.len() {
        return Err(format!("LUKS2: JSON continues after the value, at byte {}.", parser.at));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: usize,
}

impl Parser<'_> {
    fn error(&self, what: &str) -> String {
        format!("LUKS2: bad JSON at byte {}: {what}.", self.at)
    }

    fn space(&mut self) {
        while self.at < self.bytes.len() && b" \t\r\n".contains(&self.bytes[self.at]) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        self.space();
        if self.bytes.get(self.at) == Some(&byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected {:?}", byte as char)))
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        self.space();
        // A header is a few levels deep; a crafted one should not be
        // able to exhaust the stack.
        if self.depth > 32 {
            return Err(self.error("nested too deeply"));
        }
        match self.bytes.get(self.at) {
            Some(b'{') => {
                self.at += 1;
                self.depth += 1;
                let mut entries = Vec::new();
                self.space();
                if self.bytes.get(self.at) == Some(&b'}') {
                    self.at += 1;
                } else {
                    loop {
                        self.space();
                        let key = self.string()?;
                        self.expect(b':')?;
                        entries.push((key, self.value()?));
                        self.space();
                        match self.bytes.get(self.at) {
                            Some(b',') => self.at += 1,
                            Some(b'}') => {
                                self.at += 1;
                                break;
                            }
                            _ => return Err(self.error("expected ',' or '}'")),
                        }
                    }
                }
                self.depth -= 1;
                Ok(Value::Object(entries))
            }
            Some(b'[') => {
                self.at += 1;
                self.depth += 1;
                let mut items = Vec::new();
                self.space();
                if self.bytes.get(self.at) == Some(&b']') {
                    self.at += 1;
                } else {
                    loop {
                        items.push(self.value()?);
                        self.space();
                        match self.bytes.get(self.at) {
                            Some(b',') => self.at += 1,
                            Some(b']') => {
                                self.at += 1;
                                break;
                            }
                            _ => return Err(self.error("expected ',' or ']'")),
                        }
                    }
                }
                self.depth -= 1;
                Ok(Value::Array(items))
            }
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') if self.bytes[self.at..].starts_with(b"true") => {
                self.at += 4;
                Ok(Value::Bool(true))
            }
            Some(b'f') if self.bytes[self.at..].starts_with(b"false") => {
                self.at += 5;
                Ok(Value::Bool(false))
            }
            Some(b'n') if self.bytes[self.at..].starts_with(b"null") => {
                self.at += 4;
                Ok(Value::Null)
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.at;
                self.at += 1;
                while self.at < self.bytes.len()
                    && b"0123456789.eE+-".contains(&self.bytes[self.at]) {
                    self.at += 1;
                }
                let text = std::str::from_utf8(&self.bytes[start..self.at])
                    .map_err(|_| self.error("number"))?;
                Ok(Value::Number(text.to_string()))
            }
            _ => Err(self.error("expected a value")),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.space();
        if self.bytes.get(self.at) != Some(&b'"') {
            return Err(self.error("expected a string"));
        }
        self.at += 1;
        let mut out = String::new();
        loop {
            let Some(&byte) = self.bytes.get(self.at) else {
                return Err(self.error("unterminated string"));
            };
            self.at += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = *self.bytes.get(self.at).ok_or_else(|| self.error("escape"))?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let digits = self.bytes.get(self.at..self.at + 4)
                                .ok_or_else(|| self.error("\\u escape"))?;
                            let code = u32::from_str_radix(
                                std::str::from_utf8(digits).map_err(|_| self.error("\\u"))?, 16)
                                .map_err(|_| self.error("\\u escape"))?;
                            self.at += 4;
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(self.error("unknown escape")),
                    }
                }
                _ => {
                    // Copy a run of plain bytes as UTF-8.
                    let start = self.at - 1;
                    while self.at < self.bytes.len()
                        && self.bytes[self.at] != b'"' && self.bytes[self.at] != b'\\' {
                        self.at += 1;
                    }
                    out.push_str(std::str::from_utf8(&self.bytes[start..self.at])
                        .map_err(|_| self.error("not UTF-8"))?);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_keeps_order_and_strings() {
        let text = r#"{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"stripes":4000}}},
                       "segments":{"0":{"offset":"16777216","size":"dynamic"}},"tokens":{},
                       "flags":["allow-discards"],"x":null,"y":true,"e":"a\"b\\cA"}"#;
        let value = parse(text).unwrap();
        assert_eq!(value.get("segments").unwrap().get("0").unwrap().get("offset").unwrap()
                   .as_u64().unwrap(), 16_777_216);
        assert_eq!(value.get("e").unwrap().as_str().unwrap(), "a\"b\\cA");
        let mut out = String::new();
        value.write(&mut out);
        assert_eq!(parse(&out).unwrap(), value);
        assert!(out.starts_with(r#"{"keyslots":{"0":{"type":"luks2","key_size":64"#));
    }

    #[test]
    fn test_malformed_json_is_refused() {
        for bad in ["{", "{\"a\":}", "[1,]", "{\"a\":1} x", "\"open", &"[".repeat(40)] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
