//! The protobuf subset Signal's messages use: varints (wire type 0) and
//! length-delimited bytes (wire type 2), every field optional.
//!
//! Written in field number order, which is what protobuf-c does and so
//! what libsignal-protocol-c's bytes look like; a MAC or a signature
//! covers the serialised form, so the order is part of the message.
//! Read in any order, keeping the last value of a repeated field and
//! skipping fields this module does not know - both what protobuf's
//! rules require of a reader.

pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { out: Vec::new() }
    }

    fn raw_varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        self.out.push(value as u8);
    }

    pub fn varint(&mut self, field: u32, value: u64) -> &mut Writer {
        self.raw_varint(u64::from(field) << 3);
        self.raw_varint(value);
        self
    }

    pub fn bytes(&mut self, field: u32, value: &[u8]) -> &mut Writer {
        self.raw_varint((u64::from(field) << 3) | 2);
        self.raw_varint(value.len() as u64);
        self.out.extend_from_slice(value);
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// A fixed32 or fixed64. No field here has one, but a known field
    /// sent as one must be an error rather than absent.
    Fixed,
}

pub struct Fields<'a> {
    list: Vec<(u32, Value<'a>)>,
}

/// A varint of at most `limit` bytes, accumulated as protobuf-c does:
/// bits past the top of the result are dropped, not refused.
fn read_varint(data: &[u8], at: &mut usize, limit: usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in 0..limit {
        let byte = *data.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f).checked_shl(7 * shift as u32).unwrap_or(0);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Every field of a message, or `None` if the bytes are not one, with
/// protobuf-c's limits: a key or a length of at most five bytes (32
/// bits, the excess dropped), a varint of at most ten, a length that
/// fits in what remains, and only the wire types 0, 1, 2 and 5. Field
/// number zero is not refused - protobuf-c files it as unknown - and
/// neither is any other unknown field.
pub fn parse(data: &[u8]) -> Option<Fields<'_>> {
    let mut list = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let key = read_varint(data, &mut at, 5)? as u32;
        let field = key >> 3;
        match key & 7 {
            0 => list.push((field, Value::Varint(read_varint(data, &mut at, 10)?))),
            1 => {
                at = at.checked_add(8).filter(|end| *end <= data.len())?;
                list.push((field, Value::Fixed));
            }
            2 => {
                let length = read_varint(data, &mut at, 5)? as u32 as usize;
                let end = at.checked_add(length).filter(|end| *end <= data.len())?;
                list.push((field, Value::Bytes(&data[at..end])));
                at = end;
            }
            5 => {
                at = at.checked_add(4).filter(|end| *end <= data.len())?;
                list.push((field, Value::Fixed));
            }
            _ => return None,
        }
    }
    Some(Fields { list })
}

impl<'a> Fields<'a> {
    fn last(&self, field: u32) -> Option<Value<'a>> {
        self.list.iter().rev().find(|(number, _)| *number == field).map(|(_, value)| *value)
    }

    /// A `uint32` field: the low 32 bits of the varint, as protobuf-c
    /// reads one. `Err` if the field is there with the wrong wire type.
    pub fn uint32(&self, field: u32) -> Result<Option<u32>, ()> {
        match self.last(field) {
            None => Ok(None),
            Some(Value::Varint(value)) => Ok(Some(value as u32)),
            Some(_) => Err(()),
        }
    }

    pub fn bytes(&self, field: u32) -> Result<Option<&'a [u8]>, ()> {
        match self.last(field) {
            None => Ok(None),
            Some(Value::Bytes(value)) => Ok(Some(value)),
            Some(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_message_round_trips_in_field_order() {
        let encoded = Writer::new().varint(1, 300).bytes(2, b"ab").varint(3, 0).finish();
        assert_eq!(encoded, [0x08, 0xac, 0x02, 0x12, 2, b'a', b'b', 0x18, 0]);
        let fields = parse(&encoded).unwrap();
        assert_eq!(fields.uint32(1), Ok(Some(300)));
        assert_eq!(fields.bytes(2), Ok(Some(&b"ab"[..])));
        assert_eq!(fields.uint32(3), Ok(Some(0)));
        assert_eq!(fields.uint32(4), Ok(None));
    }

    #[test]
    fn test_unknown_fields_are_skipped_and_the_last_value_wins() {
        // Field 9 as a fixed64, field 10 as a fixed32, then field 1 twice.
        let mut data = vec![0x49];
        data.extend_from_slice(&[0; 8]);
        data.push(0x55);
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&[0x08, 1, 0x08, 2]);
        assert_eq!(parse(&data).unwrap().uint32(1), Ok(Some(2)));
    }

    #[test]
    fn test_malformed_input_is_refused() {
        assert!(parse(&[0x12, 5, 1]).is_none(), "length past the end");
        assert!(parse(&[0x08]).is_none(), "a key with no value");
        assert!(parse(&[0x08, 0x80]).is_none(), "an unterminated varint");
        assert!(parse(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0])
            .is_none(), "eleven varint bytes");
        assert!(parse(&[0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]).is_some(),
                "a varint value may run to ten bytes");
        assert!(parse(&[0x88, 0x80, 0x80, 0x80, 0x80, 0x00, 0]).is_none(),
                "a key may not run past five");
        assert!(parse(&[0x12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]).is_none(),
                "nor may a length");
        assert!(parse(&[0x0b]).is_none(), "a start-group marker");
        assert!(parse(&[0x49, 0, 0]).is_none(), "a fixed64 cut short");
        assert!(parse(&[]).is_some(), "an empty message is a message");
    }

    #[test]
    fn test_a_field_with_the_wrong_wire_type_is_an_error() {
        let fields = parse(&[0x0a, 0]).unwrap();
        assert_eq!(fields.uint32(1), Err(()));
        let fields = parse(&[0x10, 0]).unwrap();
        assert_eq!(fields.bytes(2), Err(()));
        // Fixed-width encodings of known fields are errors too, not
        // skipped as unknown ones are.
        let fields = parse(&[0x15, 0, 0, 0, 0]).unwrap();
        assert_eq!(fields.uint32(2), Err(()));
        assert_eq!(fields.uint32(1), Ok(None));
    }

    /// protobuf-c files field zero with the unknown fields, so a message
    /// of zero bytes is a message with nothing in it - and so missing
    /// its required fields, rather than not a protobuf.
    #[test]
    fn test_field_zero_is_an_unknown_field() {
        let fields = parse(&[0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(fields.uint32(1), Ok(None));
    }

    #[test]
    fn test_a_uint32_takes_the_low_32_bits() {
        let encoded = Writer::new().varint(1, (1 << 32) + 5).finish();
        assert_eq!(parse(&encoded).unwrap().uint32(1), Ok(Some(5)));
    }
}
