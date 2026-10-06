//! Domain names: presentation form with RFC 1035's escapes, the
//! uncompressed wire form, and DNSSEC's canonical form and ordering
//! (RFC 4034 section 6.1).

use std::cmp::Ordering;
use std::fmt;

/// A fully qualified name as its labels, most specific first. The root is
/// no labels. Labels keep their case; `canonical` lowercases.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    pub fn root() -> Name {
        Name { labels: Vec::new() }
    }

    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Parse presentation form. A name without a final dot is relative to
    /// `origin`; `@` is the origin itself. `\DDD` is a decimal byte and
    /// `\X` is X literally, so `a\.b` is one label.
    pub fn parse(text: &str, origin: Option<&Name>) -> Result<Name, String> {
        if text == "@" {
            return origin.cloned().ok_or_else(|| "@ with no origin.".to_string());
        }
        if text == "." {
            return Ok(Name::root());
        }
        let bytes = text.as_bytes();
        let mut labels = Vec::new();
        let mut label = Vec::new();
        let mut absolute = false;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => {
                    let rest = &bytes[i + 1..];
                    if rest.len() >= 3 && rest[..3].iter().all(u8::is_ascii_digit) {
                        let value: u32 = std::str::from_utf8(&rest[..3]).expect("digits")
                            .parse().expect("digits");
                        if value > 255 {
                            return Err(format!("{text}: \\{} is not a byte.", value));
                        }
                        label.push(value as u8);
                        i += 4;
                    } else if let Some(&c) = rest.first() {
                        label.push(c);
                        i += 2;
                    } else {
                        return Err(format!("{text}: a name ends in a backslash."));
                    }
                }
                b'.' => {
                    if label.is_empty() {
                        return Err(format!("{text}: an empty label."));
                    }
                    labels.push(std::mem::take(&mut label));
                    i += 1;
                    if i == bytes.len() {
                        absolute = true;
                    }
                }
                c => {
                    label.push(c);
                    i += 1;
                }
            }
        }
        if !label.is_empty() {
            labels.push(label);
        }
        let mut name = Name { labels };
        if !absolute {
            let origin = origin.ok_or_else(|| format!("{text}: a relative name with no \
                                                       origin."))?;
            name.labels.extend(origin.labels.iter().cloned());
        }
        name.check()?;
        Ok(name)
    }

    fn check(&self) -> Result<(), String> {
        if self.labels.iter().any(|l| l.len() > 63) {
            return Err(format!("{self}: a label longer than 63 bytes."));
        }
        if self.wire_len() > 255 {
            return Err(format!("{self}: longer than 255 bytes in wire form."));
        }
        Ok(())
    }

    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }

    /// Uncompressed wire form, case kept.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        for label in &self.labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out
    }

    /// Read an uncompressed name. DNSSEC's signed forms never compress.
    pub fn from_wire(bytes: &[u8]) -> Result<(Name, usize), String> {
        let mut labels = Vec::new();
        let mut at = 0;
        loop {
            let len = *bytes.get(at).ok_or("A name runs off the end.")? as usize;
            at += 1;
            if len == 0 {
                break;
            }
            if len > 63 {
                return Err("A compressed or extended label in a name that may not have \
                            one.".to_string());
            }
            labels.push(bytes.get(at..at + len).ok_or("A label runs off the end.")?.to_vec());
            at += len;
        }
        let name = Name { labels };
        name.check()?;
        Ok((name, at))
    }

    /// ASCII letters lowercased (RFC 4034 section 6.2); other bytes kept.
    pub fn canonical(&self) -> Name {
        Name { labels: self.labels.iter().map(|l| l.to_ascii_lowercase()).collect() }
    }

    /// RRSIG's Labels field: the count without the root, and without a
    /// leading `*` (RFC 4034 section 3.1.3).
    pub fn rrsig_labels(&self) -> u8 {
        let wildcard = self.labels.first().is_some_and(|l| l == b"*");
        (self.labels.len() - usize::from(wildcard)) as u8
    }

    pub fn is_subdomain_of(&self, other: &Name) -> bool {
        self.labels.len() >= other.labels.len()
            && self.labels[self.labels.len() - other.labels.len()..].iter()
                .zip(&other.labels).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// The name with its first `n` labels removed.
    pub fn parent(&self, n: usize) -> Name {
        Name { labels: self.labels[n.min(self.labels.len())..].to_vec() }
    }

    /// `label.self`.
    pub fn prepend(&self, label: &[u8]) -> Result<Name, String> {
        let mut labels = vec![label.to_vec()];
        labels.extend(self.labels.iter().cloned());
        let name = Name { labels };
        name.check()?;
        Ok(name)
    }

    /// Canonical ordering (RFC 4034 section 6.1): compare label by label
    /// from the root, each label as lowercased bytes, a missing label
    /// sorting first.
    pub fn canonical_cmp(&self, other: &Name) -> Ordering {
        let a = self.labels.iter().rev();
        let b = other.labels.iter().rev();
        for (x, y) in a.zip(b) {
            let order = x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase());
            if order != Ordering::Equal {
                return order;
            }
        }
        self.labels.len().cmp(&other.labels.len())
    }

    pub fn eq_ignore_case(&self, other: &Name) -> bool {
        self.canonical_cmp(other) == Ordering::Equal
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }
        for label in &self.labels {
            for &c in label {
                match c {
                    b'.' | b'\\' | b'(' | b')' | b';' | b'"' | b'@' | b'$' =>
                        write!(f, "\\{}", c as char)?,
                    0x21..=0x7e => write!(f, "{}", c as char)?,
                    _ => write!(f, "\\{c:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(text: &str) -> Name {
        Name::parse(text, None).unwrap()
    }

    /// RFC 4034 section 6.1's own example, in the order it gives.
    #[test]
    fn test_the_rfc_4034_ordering() {
        let ordered = ["example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
                       "zABC.a.EXAMPLE.", "z.example.", "\\001.z.example.",
                       "*.z.example.", "\\200.z.example."];
        let names: Vec<Name> = ordered.iter().map(|t| n(t)).collect();
        for pair in names.windows(2) {
            assert_eq!(pair[0].canonical_cmp(&pair[1]), Ordering::Less,
                       "{} before {}", pair[0], pair[1]);
        }
    }

    #[test]
    fn test_escapes_and_relative_names() {
        let origin = n("example.");
        assert_eq!(Name::parse("a\\.b", Some(&origin)).unwrap().labels().len(), 2);
        assert_eq!(Name::parse("\\065", Some(&origin)).unwrap(), n("A.example."));
        assert_eq!(Name::parse("@", Some(&origin)).unwrap(), origin);
        assert_eq!(n("a\\.b.example.").to_string(), "a\\.b.example.");
        assert!(Name::parse("a..b.", None).is_err());
        assert!(Name::parse("\\256.", None).is_err());
        assert!(Name::parse(&format!("{}.", "x".repeat(64)), None).is_err());
    }

    #[test]
    fn test_wire_round_trip_and_labels() {
        let name = n("*.Example.COM.");
        let (back, used) = Name::from_wire(&name.to_wire()).unwrap();
        assert_eq!(back, name);
        assert_eq!(used, name.wire_len());
        assert_eq!(name.rrsig_labels(), 2);
        assert_eq!(name.canonical().to_string(), "*.example.com.");
        assert_eq!(Name::root().to_wire(), vec![0]);
    }
}
