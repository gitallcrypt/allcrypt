//! Secret values in `Debug` output: that they are there, and how long
//! they are, but never what they are.
//!
//! A derived `Debug` prints every field, so a key read from a file ends
//! up in a panic message, a log line or an `assert_eq!` failure as soon
//! as anything formats the structure holding it. A type that holds key
//! material writes its own `Debug` and passes the secret through one of
//! these instead.

#![allow(dead_code)]

use std::fmt;

/// Secret bytes: `<32 secret bytes>`.
pub struct HiddenBytes<'a>(pub &'a [u8]);

impl fmt::Debug for HiddenBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} secret bytes>", self.0.len())
    }
}

/// Any other secret value - a number, a string: `<secret>`.
pub struct Hidden;

impl fmt::Debug for Hidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_value_is_not_printed() {
        assert_eq!(format!("{:?}", HiddenBytes(b"hunter2")), "<7 secret bytes>");
        assert_eq!(format!("{:?}", Hidden), "<secret>");
    }
}
