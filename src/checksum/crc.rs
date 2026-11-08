//! CRCs from their parameters, and the catalogue of them.
//!
//! A CRC is fixed by six parameters, Ross Williams's model ("A Painless
//! Guide to CRC Error Detection Algorithms", 1993), as the catalogue of
//! parametrised CRC algorithms - Greg Cook's, the one reveng carries -
//! writes them:
//!
//! - `width`, the degree of the polynomial, here 1 to 128;
//! - `poly`, the polynomial without its top term;
//! - `init`, the register's value before the first bit;
//! - `refin`: each byte goes in low bit first, not high bit first;
//! - `refout`: the register is bit-reversed before `xorout`;
//! - `xorout`, XORed into the value at the end.
//!
//! `init` and `poly` are always written unreflected, as the catalogue
//! writes them, whichever way the bytes go in. The value is the register
//! after the message, reversed if `refin` and `refout` differ, XOR
//! `xorout`; the digest is that value in `ceil(width / 8)` bytes, big
//! endian.
//!
//! [`CATALOGUE`] holds the catalogue's entries, generated from two
//! transcriptions of it that agree; `Checksum` takes their names in
//! lowercase, with a hyphen or an underscore alike. A CRC outside it is
//! named by its model line, `width=16 poly=0x8005 init=0x0000 refin=true
//! refout=true xorout=0x0000`, which is the catalogue's own notation.
//!
//! The register is a `u128` whatever the width - left-aligned when the
//! bytes go in high bit first, so one table indexed by the top byte serves
//! every width, and kept reflected in the low bits when they go in low bit
//! first - so a width below eight or above sixty-four is not a special
//! case.

/// The six parameters of a CRC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrcParams {
    /// The polynomial's degree, 1 to 128.
    pub width: u32,
    /// The polynomial without its top term, unreflected.
    pub poly: u128,
    /// The register's value before the message, unreflected.
    pub init: u128,
    /// Each byte goes in low bit first.
    pub refin: bool,
    /// The register is bit-reversed before `xorout`.
    pub refout: bool,
    /// XORed into the value at the end.
    pub xorout: u128,
}

/// One entry of the catalogue of parametrised CRC algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogueEntry {
    /// The catalogue's name, as it writes it: `CRC-16/ARC`.
    pub name: &'static str,
    /// The parameters.
    pub params: CrcParams,
    /// The CRC of the nine bytes `123456789`.
    pub check: u128,
}

/// The catalogue, in its own order: by width, then by name.
pub const CATALOGUE: &[CatalogueEntry] = &super::crc_catalogue::ENTRIES;

/// Whether two names are the same, ignoring case and taking a hyphen and
/// an underscore as the same character, as `api::AnyHash::new` folds them.
fn same_name(a: &str, b: &str) -> bool {
    let fold = |c: u8| if c == b'-' { b'_' } else { c.to_ascii_lowercase() };
    a.len() == b.len() && a.bytes().zip(b.bytes()).all(|(x, y)| fold(x) == fold(y))
}

/// `x`'s low `width` bits in reverse order.
fn reflect(x: u128, width: u32) -> u128 {
    x.reverse_bits() >> (128 - width)
}

impl CrcParams {
    /// The catalogue entry a name stands for: its name in any case, with a
    /// hyphen or an underscore alike.
    pub fn named(name: &str) -> Option<&'static CatalogueEntry> {
        CATALOGUE.iter().find(|e| same_name(e.name, name))
    }

    /// Refuses a width outside 1 to 128, and a polynomial, init or xorout
    /// wider than the width.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=128).contains(&self.width) {
            return Err(format!("A CRC's width is 1 to 128 bits, not {}.", self.width));
        }
        let wide = |v: u128| self.width < 128 && v >> self.width != 0;
        for (field, value) in [("poly", self.poly), ("init", self.init),
                               ("xorout", self.xorout)] {
            if wide(value) {
                return Err(format!("A CRC's {field} must fit in its width, {} bits; \
                                    0x{value:x} does not.", self.width));
            }
        }
        Ok(())
    }

    /// The model line: `width=16 poly=0x8005 init=0x0000 refin=true
    /// refout=true xorout=0x0000`, each value in as many hex digits as the
    /// width needs.
    pub fn model(&self) -> String {
        let digits = self.width.div_ceil(4) as usize;
        format!("width={} poly=0x{:0d$x} init=0x{:0d$x} refin={} refout={} xorout=0x{:0d$x}",
                self.width, self.poly, self.init, self.refin, self.refout, self.xorout,
                d = digits)
    }

    /// Reads a model line back: the six fields separated by spaces, in any
    /// order and each once, the numbers in hex after `0x`, `refin` and
    /// `refout` `true` or `false`; any case.
    pub fn from_model(line: &str) -> Result<CrcParams, String> {
        let malformed = || format!("{line:?} is not a CRC model line: it is the six fields \
                                    width=, poly=, init=, refin=, refout= and xorout=, \
                                    separated by spaces, the numbers in hex after 0x and \
                                    refin and refout true or false.");
        let mut fields: [Option<&str>; 6] = [None; 6];
        const KEYS: [&str; 6] = ["width", "poly", "init", "refin", "refout", "xorout"];
        for word in line.split(' ').filter(|w| !w.is_empty()) {
            let (key, value) = word.split_once('=').ok_or_else(malformed)?;
            let at = KEYS.iter().position(|k| k.eq_ignore_ascii_case(key))
                .ok_or_else(malformed)?;
            if fields[at].replace(value).is_some() {
                return Err(malformed());
            }
        }
        let field = |i: usize| fields[i].ok_or_else(malformed);
        let number = |i: usize| -> Result<u128, String> {
            let v = field(i)?;
            let digits = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X"))
                .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or_else(malformed)?;
            u128::from_str_radix(digits, 16).map_err(|_| malformed())
        };
        let flag = |i: usize| -> Result<bool, String> {
            let v = field(i)?;
            if v.eq_ignore_ascii_case("true") {
                Ok(true)
            } else if v.eq_ignore_ascii_case("false") {
                Ok(false)
            } else {
                Err(malformed())
            }
        };
        let width = field(0)?;
        if width.is_empty() || !width.bytes().all(|b| b.is_ascii_digit()) {
            return Err(malformed());
        }
        let params = CrcParams {
            width: width.parse().map_err(|_| malformed())?,
            poly: number(1)?,
            init: number(2)?,
            refin: flag(3)?,
            refout: flag(4)?,
            xorout: number(5)?,
        };
        params.validate()?;
        Ok(params)
    }
}

/// A CRC in progress.
#[derive(Clone)]
pub struct Crc {
    params: CrcParams,
    /// The catalogue's name, when it was made by one.
    name: Option<&'static str>,
    table: Box<[u128; 256]>,
    /// Reflected in the low `width` bits when `refin`, left-aligned
    /// otherwise.
    register: u128,
}

impl Crc {
    /// A CRC from its parameters.
    pub fn new(params: CrcParams) -> Result<Crc, String> {
        params.validate()?;
        let w = params.width;
        let mut table = Box::new([0u128; 256]);
        if params.refin {
            let poly = reflect(params.poly, w);
            for (i, entry) in table.iter_mut().enumerate() {
                let mut c = i as u128;
                for _ in 0..8 {
                    c = if c & 1 != 0 { (c >> 1) ^ poly } else { c >> 1 };
                }
                *entry = c;
            }
        } else {
            let poly = params.poly << (128 - w);
            for (i, entry) in table.iter_mut().enumerate() {
                let mut c = (i as u128) << 120;
                for _ in 0..8 {
                    c = if c >> 127 != 0 { (c << 1) ^ poly } else { c << 1 };
                }
                *entry = c;
            }
        }
        let mut crc = Crc { params, name: None, table, register: 0 };
        crc.reset();
        Ok(crc)
    }

    /// The catalogue entry a name stands for, as [`CrcParams::named`]
    /// finds it.
    pub fn named(name: &str) -> Option<Crc> {
        let entry = CrcParams::named(name)?;
        let mut crc = Crc::new(entry.params).expect("every catalogue entry is valid");
        crc.name = Some(entry.name);
        Some(crc)
    }

    /// The parameters.
    pub fn params(&self) -> CrcParams {
        self.params
    }

    /// The catalogue's name in lowercase if it was made by one, otherwise
    /// the model line.
    pub fn name(&self) -> String {
        match self.name {
            Some(name) => name.to_ascii_lowercase(),
            None => self.params.model(),
        }
    }

    /// Back to the start, before any message.
    pub fn reset(&mut self) {
        let p = &self.params;
        self.register = if p.refin { reflect(p.init, p.width) } else { p.init << (128 - p.width) };
    }

    /// Takes more of the message.
    pub fn update(&mut self, data: &[u8]) {
        let mut register = self.register;
        if self.params.refin {
            for &byte in data {
                register = self.table[((register ^ u128::from(byte)) & 0xff) as usize]
                    ^ (register >> 8);
            }
        } else {
            for &byte in data {
                register = self.table[((register >> 120) as u8 ^ byte) as usize] ^ (register << 8);
            }
        }
        self.register = register;
    }

    /// The CRC of the message so far.
    pub fn value(&self) -> u128 {
        let p = &self.params;
        let crc = if p.refin { self.register } else { self.register >> (128 - p.width) };
        (if p.refin != p.refout { reflect(crc, p.width) } else { crc }) ^ p.xorout
    }

    /// The digest's length: `ceil(width / 8)`.
    pub fn digest_len(&self) -> usize {
        self.params.width.div_ceil(8) as usize
    }

    /// The value in [`digest_len`](Crc::digest_len) bytes, big endian.
    pub fn digest(&self) -> Vec<u8> {
        self.value().to_be_bytes()[16 - self.digest_len()..].to_vec()
    }
}

/// The CRC of `data` under `params`.
pub fn crc(params: CrcParams, data: &[u8]) -> Result<u128, String> {
    let mut crc = Crc::new(params)?;
    crc.update(data);
    Ok(crc.value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_entry_gives_its_check_value() {
        // The check values are the two transcriptions', not this code's.
        assert_eq!(CATALOGUE.len(), 112);
        for entry in CATALOGUE {
            let mut crc = Crc::named(entry.name).unwrap();
            crc.update(b"123456789");
            assert_eq!(crc.value(), entry.check, "{}", entry.name);
        }
    }

    #[test]
    fn test_the_dedicated_crc32_agrees() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 167 + 13) as u8).collect();
        for (name, value) in [("CRC-32/ISO-HDLC", super::super::crc32(&data)),
                              ("CRC-32/ISCSI", super::super::crc32c(&data))] {
            let mut crc = Crc::named(name).unwrap();
            crc.update(&data);
            assert_eq!(crc.value(), u128::from(value), "{name}");
        }
    }

    #[test]
    fn test_names_fold_case_and_hyphens() {
        for name in ["CRC-16/ARC", "crc-16/arc", "crc_16/arc", "Crc-16/Arc"] {
            assert_eq!(CrcParams::named(name).unwrap().name, "CRC-16/ARC");
        }
        assert!(CrcParams::named("crc-16/ar").is_none());
        assert!(CrcParams::named("crc-16/arcs").is_none());
        assert!(CrcParams::named("crc-16 arc").is_none());
    }

    #[test]
    fn test_the_model_line_reads_back() {
        for entry in CATALOGUE {
            let line = entry.params.model();
            assert_eq!(CrcParams::from_model(&line).unwrap(), entry.params, "{line}");
            assert_eq!(CrcParams::from_model(&line.to_ascii_uppercase().replace("0X", "0x"))
                       .unwrap(), entry.params);
        }
        let arc = CrcParams::named("crc-16/arc").unwrap().params;
        assert_eq!(arc.model(),
                   "width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000");
        // In any order, with extra spaces.
        assert_eq!(CrcParams::from_model(
            " xorout=0x0  refout=true refin=true init=0x0 poly=0x8005 width=16 ").unwrap(), arc);
    }

    #[test]
    fn test_a_malformed_model_line_is_refused() {
        let good = "width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000";
        assert!(CrcParams::from_model(good).is_ok());
        for bad in [
            "width=16 poly=0x8005 init=0x0000 refin=true refout=true",
            "width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000 width=16",
            "width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000 check=0xbb3d",
            "width=16 poly=8005 init=0x0000 refin=true refout=true xorout=0x0000",
            "width=16 poly=0x init=0x0000 refin=true refout=true xorout=0x0000",
            "width=16 poly=0x80g5 init=0x0000 refin=true refout=true xorout=0x0000",
            "width=16 poly=0x8005 init=0x0000 refin=yes refout=true xorout=0x0000",
            "width=+16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000",
            "width=0x10 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000",
            "width=16 poly=0x18005 init=0x0000 refin=true refout=true xorout=0x0000",
            "width=16 poly=0x8005 init=0x10000 refin=true refout=true xorout=0x0000",
            "width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x10000",
            "width=0 poly=0x0 init=0x0 refin=true refout=true xorout=0x0",
            "width=129 poly=0x1 init=0x0 refin=true refout=true xorout=0x0",
            "width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout",
        ] {
            assert!(CrcParams::from_model(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_parameters_wider_than_the_width_are_refused() {
        let base = CrcParams { width: 5, poly: 0x15, init: 0x1f, refin: false, refout: false,
                               xorout: 0x1f };
        assert!(Crc::new(base).is_ok());
        for bad in [CrcParams { poly: 0x20, ..base }, CrcParams { init: 0x20, ..base },
                    CrcParams { xorout: 0x20, ..base }, CrcParams { width: 0, ..base },
                    CrcParams { width: 129, ..base }] {
            assert!(Crc::new(bad).is_err(), "{bad:?}");
        }
        let full = CrcParams { width: 128, poly: u128::MAX, init: u128::MAX, refin: true,
                               refout: false, xorout: u128::MAX };
        assert!(Crc::new(full).is_ok());
    }

    #[test]
    fn test_the_register_continues_and_resets() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 89 + 7) as u8).collect();
        for entry in CATALOGUE {
            let whole = crc(entry.params, &data).unwrap();
            let mut c = Crc::new(entry.params).unwrap();
            for piece in data.chunks(7) {
                c.update(piece);
            }
            assert_eq!(c.value(), whole, "{}", entry.name);
            c.reset();
            c.update(&data);
            assert_eq!(c.value(), whole, "{} after a reset", entry.name);
            assert_eq!(c.name(), entry.params.model());
            assert_eq!(c.digest().len(), entry.params.width.div_ceil(8) as usize);
        }
    }
}
