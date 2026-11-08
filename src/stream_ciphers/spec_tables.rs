//! The 8 bit S-boxes of SNOW 3G and ZUC, read out of their specifications
//! at compile time, and a lookup that does not index memory by the input.
//!
//! Both ETSI/SAGE documents print each S-box as sixteen rows of sixteen
//! hexadecimal bytes, a row's label - its high nibble, `0` to `F` - first:
//!
//! ```text
//!        0      3E       72 5B 47 CA E0 00 33 04 D1 54 98 09 B9 6D CB
//! ```
//!
//! A line is a row when it is a single hexadecimal digit followed by
//! exactly sixteen two-digit hexadecimal tokens; everything else - the
//! column header, the `x0`/`x1` labels, a running page header - is not,
//! whatever it says. The rows must come in label order, and the parser
//! refuses at compile time when it finds fewer than sixteen.

/// The position of `needle` in `haystack` at or after `from`.
const fn find(haystack: &[u8], needle: &[u8], from: usize) -> usize {
    let mut at = from;
    while at + needle.len() <= haystack.len() {
        let mut i = 0;
        while i < needle.len() && haystack[at + i] == needle[i] {
            i += 1;
        }
        if i == needle.len() {
            return at;
        }
        at += 1;
    }
    panic!("a specification no longer contains the text an S-box is found by");
}

const fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The row in `line` (`start..end` of `bytes`) as its label and sixteen
/// entries, or `None` when the line is not a row.
const fn row(bytes: &[u8], start: usize, end: usize) -> Option<(u8, [u8; 16])> {
    let mut entries = [0u8; 16];
    let mut label = 0u8;
    let mut tokens = 0usize;
    let mut at = start;
    while at < end {
        if bytes[at] == b' ' || bytes[at] == b'\t' || bytes[at] == b'\r' || bytes[at] == 0x0c {
            at += 1;
            continue;
        }
        let token = at;
        while at < end
            && !(bytes[at] == b' ' || bytes[at] == b'\t' || bytes[at] == b'\r' || bytes[at] == 0x0c)
        {
            at += 1;
        }
        let len = at - token;
        if tokens == 0 {
            if len != 1 {
                return None;
            }
            match hex_digit(bytes[token]) {
                Some(v) => label = v,
                None => return None,
            }
        } else {
            if len != 2 || tokens > 16 {
                return None;
            }
            match (hex_digit(bytes[token]), hex_digit(bytes[token + 1])) {
                (Some(h), Some(l)) => entries[tokens - 1] = h << 4 | l,
                _ => return None,
            }
        }
        tokens += 1;
    }
    if tokens == 17 { Some((label, entries)) } else { None }
}

/// The S-box printed after `marker` in `text`.
pub(crate) const fn parse(text: &str, marker: &str) -> [u8; 256] {
    let bytes = text.as_bytes();
    let mut at = find(bytes, marker.as_bytes(), 0) + marker.len();
    let mut table = [0u8; 256];
    let mut rows = 0usize;
    while rows < 16 {
        if at >= bytes.len() {
            panic!("an S-box table ended before its sixteenth row");
        }
        let start = at;
        while at < bytes.len() && bytes[at] != b'\n' {
            at += 1;
        }
        if let Some((label, entries)) = row(bytes, start, at) {
            if label as usize != rows {
                panic!("an S-box table's rows are out of order");
            }
            let mut i = 0;
            while i < 16 {
                table[rows * 16 + i] = entries[i];
                i += 1;
            }
            rows += 1;
        }
        at += 1;
    }
    table
}

/// `table[x]`, read by visiting every entry and keeping the one whose
/// index equals `x` under a mask, so neither the memory touched nor any
/// branch depends on `x`.
#[inline]
pub(crate) fn scan(table: &[u8; 256], x: u8) -> u8 {
    let mut out = 0u8;
    for (i, &v) in table.iter().enumerate() {
        // All ones when i == x, else zero: (i ^ x) - 1 borrows into the
        // top byte only from zero.
        let mask = (((i as u32) ^ u32::from(x)).wrapping_sub(1) >> 8) as u8;
        out |= v & mask;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_is_indexing() {
        let mut table = [0u8; 256];
        for (i, v) in table.iter_mut().enumerate() {
            *v = (i as u8).wrapping_mul(167).wrapping_add(13);
        }
        for x in 0..=255u8 {
            assert_eq!(scan(&table, x), table[x as usize]);
        }
    }

    #[test]
    fn test_a_row_is_a_label_and_sixteen_bytes() {
        let ok = br"  7      3B     4B DA 46 EB C9 DE 9A 8F 87 D7 3A 80 6F 2F C8";
        assert_eq!(row(ok, 0, ok.len()).expect("a row").0, 7);
        for not in [&br"   0 1 2 3 4 5 6 7 8 9 A B C D E F"[..],
                    br"x1   0    1    2",
                    br"  7      3B     4B DA 46 EB C9 DE 9A 8F 87 D7 3A 80 6F 2F",
                    br"  7      3B     4B DA 46 EB C9 DE 9A 8F 87 D7 3A 80 6F 2F C8 00",
                    br"  12     3B     4B DA 46 EB C9 DE 9A 8F 87 D7 3A 80 6F 2F C8",
                    br"3GPP Confidentiality and Integrity Algorithms   page 10 of 37"] {
            assert!(row(not, 0, not.len()).is_none(), "{:?}", core::str::from_utf8(not));
        }
    }
}
