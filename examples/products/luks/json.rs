//! LUKS2's header JSON: the shared reader and writer
//! (`shared/json.rs`), with lookups that fail with a message saying what
//! the header lacks, and shorthands for building one.
//!
//! Objects keep their keys in order, so a header read and written back
//! comes out with its fields where they were. Numbers are kept as the
//! text they were written as; LUKS2 writes every 64 bit quantity as a
//! decimal *string* ("string-uint64" in the specification) precisely so
//! that a JSON library holding numbers as doubles does not round them,
//! and `uint` reads either form.

pub use crate::shared_json::{parse, Json as Value};

/// The lookups a header reader makes, each an error naming what was
/// missing or of the wrong kind rather than an `Option`.
pub trait Header {
    /// `get`, as an error naming the key when absent.
    fn field(&self, key: &str) -> Result<&Value, String>;
    fn string(&self) -> Result<&str, String>;
    /// A number, or a string holding one.
    fn uint(&self) -> Result<u64, String>;
    fn entries(&self) -> Result<&[(String, Value)], String>;
    fn items(&self) -> Result<&[Value], String>;
    /// Compact JSON, keys in their order.
    fn write(&self, out: &mut String);
}

impl Header for Value {
    fn field(&self, key: &str) -> Result<&Value, String> {
        self.get(key).ok_or_else(|| format!("LUKS2: the JSON has no {key:?} here."))
    }

    fn string(&self) -> Result<&str, String> {
        self.as_str().ok_or_else(|| format!("LUKS2: expected a string, found {self:?}."))
    }

    fn uint(&self) -> Result<u64, String> {
        match self {
            Value::Number(text) | Value::String(text) => text.parse()
                .map_err(|_| format!("LUKS2: {text:?} is not an unsigned integer.")),
            other => Err(format!("LUKS2: expected a number, found {other:?}.")),
        }
    }

    fn entries(&self) -> Result<&[(String, Value)], String> {
        match self {
            Value::Object(entries) => Ok(entries),
            other => Err(format!("LUKS2: expected an object, found {other:?}.")),
        }
    }

    fn items(&self) -> Result<&[Value], String> {
        match self {
            Value::Array(items) => Ok(items),
            other => Err(format!("LUKS2: expected an array, found {other:?}.")),
        }
    }

    fn write(&self, out: &mut String) {
        out.push_str(&self.to_text());
    }
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
                   .uint().unwrap(), 16_777_216);
        assert_eq!(value.get("e").unwrap().string().unwrap(), "a\"b\\cA");
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
