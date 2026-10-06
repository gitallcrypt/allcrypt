//! Unicode normalization (UAX #15): NFD, NFC, NFKD and NFKC, from the
//! tables in `unicode_tables.rs`. BIP-39 hashes its mnemonic and
//! passphrase in NFKD and BIP-38 its passphrase in NFC, so the same
//! passphrase typed with a precomposed é or with e and a combining acute
//! opens the same wallet.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::unicode_tables::{CCC, COMPOSITION_EXCLUDED, DECOMPOSITIONS};

// Hangul syllables are decomposed and composed by arithmetic (UAX #15
// section 3.12, The Unicode Standard section 3.12).
const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const L_COUNT: u32 = 19;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = L_COUNT * N_COUNT;

struct Tables {
    ccc: HashMap<u32, u8>,
    canonical: HashMap<u32, &'static [u32]>,
    compatibility: HashMap<u32, &'static [u32]>,
    compose: HashMap<(u32, u32), u32>,
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut canonical = HashMap::new();
        let mut compatibility = HashMap::new();
        let mut compose = HashMap::new();
        let excluded = |c: u32| COMPOSITION_EXCLUDED.iter().any(|&(a, b)| (a..=b).contains(&c));
        for &(code, compat, mapping) in DECOMPOSITIONS {
            if compat {
                compatibility.insert(code, mapping);
            } else {
                canonical.insert(code, mapping);
                // A primary composite: a canonical pair, not excluded.
                // Singletons and non-starter decompositions are in
                // Full_Composition_Exclusion already.
                if mapping.len() == 2 && !excluded(code) {
                    compose.insert((mapping[0], mapping[1]), code);
                }
            }
        }
        Tables { ccc: CCC.iter().map(|&(c, v)| (c, v)).collect(), canonical, compatibility,
                 compose }
    })
}

pub fn combining_class(c: u32) -> u8 {
    tables().ccc.get(&c).copied().unwrap_or(0)
}

/// The full decomposition of one code point, recursively; compatibility
/// mappings too when `compat`.
fn decompose_into(c: u32, compat: bool, out: &mut Vec<u32>) {
    if (S_BASE..S_BASE + S_COUNT).contains(&c) {
        let s = c - S_BASE;
        out.push(L_BASE + s / N_COUNT);
        out.push(V_BASE + (s % N_COUNT) / T_COUNT);
        if !s.is_multiple_of(T_COUNT) {
            out.push(T_BASE + s % T_COUNT);
        }
        return;
    }
    let t = tables();
    let mapping = t.canonical.get(&c)
        .or_else(|| if compat { t.compatibility.get(&c) } else { None });
    match mapping {
        Some(parts) => {
            for &p in parts.iter() {
                decompose_into(p, compat, out);
            }
        }
        None => out.push(c),
    }
}

/// The canonical ordering algorithm: within each run of non-starters, a
/// stable sort by combining class.
fn reorder(text: &mut [u32]) {
    let mut i = 0;
    while i < text.len() {
        if combining_class(text[i]) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < text.len() && combining_class(text[i]) != 0 {
            i += 1;
        }
        text[start..i].sort_by_key(|&c| combining_class(c));
    }
}

fn decompose(text: &str, compat: bool) -> Vec<u32> {
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        decompose_into(c as u32, compat, &mut out);
    }
    reorder(&mut out);
    out
}

fn compose_pair(a: u32, b: u32) -> Option<u32> {
    // L + V, and LV + T.
    if (L_BASE..L_BASE + L_COUNT).contains(&a) && (V_BASE..V_BASE + V_COUNT).contains(&b) {
        return Some(S_BASE + ((a - L_BASE) * V_COUNT + (b - V_BASE)) * T_COUNT);
    }
    if (S_BASE..S_BASE + S_COUNT).contains(&a) && (a - S_BASE).is_multiple_of(T_COUNT)
        && (T_BASE + 1..T_BASE + T_COUNT).contains(&b) {
        return Some(a + (b - T_BASE));
    }
    tables().compose.get(&(a, b)).copied()
}

/// The canonical composition algorithm: each character is combined with
/// the last starter unless a character between them blocks it - one of
/// class zero, or of a class no lower than its own. Canonical order makes
/// the last uncombined character's class the one to compare. An
/// uncombined starter becomes the last starter, so the characters kept
/// since the last starter are never of class zero.
fn compose(text: Vec<u32>) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::with_capacity(text.len());
    let mut starter: Option<usize> = None;
    // The class of the last character kept since the starter; -1 for
    // none, which blocks nothing.
    let mut last_class: i16 = -1;
    for c in text {
        let class = combining_class(c) as i16;
        if let Some(s) = starter {
            if last_class < class {
                if let Some(composite) = compose_pair(out[s], c) {
                    out[s] = composite;
                    continue;
                }
            }
        }
        if class == 0 {
            starter = Some(out.len());
            last_class = -1;
        } else {
            last_class = class;
        }
        out.push(c);
    }
    out
}

fn to_string(code_points: &[u32]) -> String {
    code_points.iter().map(|&c| char::from_u32(c).expect("a scalar value")).collect()
}

pub fn nfd(text: &str) -> String {
    to_string(&decompose(text, false))
}

pub fn nfkd(text: &str) -> String {
    to_string(&decompose(text, true))
}

pub fn nfc(text: &str) -> String {
    to_string(&compose(decompose(text, false)))
}

pub fn nfkc(text: &str) -> String {
    to_string(&compose(decompose(text, true)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NormalizationTest.txt, all of it: for each line's five columns,
    /// UAX #15's conformance requirements c2 = NFC(c1) = NFC(c2) =
    /// NFC(c3), c4 = NFC(c4) = NFC(c5), and the same for NFD, NFKC and
    /// NFKD. And Part 1's rule that every other code point is left alone
    /// by all four.
    #[test]
    fn test_normalization_test_txt() {
        let packed = std::fs::read(crate::fixtures::dir().join("wallet")
                                   .join("NormalizationTest.zlib")).unwrap();
        let text = String::from_utf8(crate::inflate::zlib_decompress(&packed, 8 << 20).unwrap())
            .unwrap();
        assert!(text.starts_with(&format!("# NormalizationTest-{}",
                                          crate::unicode_tables::VERSION)));
        let field = |f: &str| -> String {
            f.split_whitespace().map(|h| char::from_u32(u32::from_str_radix(h, 16).unwrap())
                                     .unwrap()).collect()
        };
        let mut part1 = std::collections::HashSet::new();
        let mut part = "";
        let mut lines = 0;
        for line in text.lines() {
            if let Some(p) = line.strip_prefix("@Part") {
                part = p.split_whitespace().next().unwrap_or("");
                continue;
            }
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let c: Vec<String> = line.split(';').take(5).map(field).collect();
            assert_eq!(c.len(), 5, "{line}");
            for x in &c[..3] {
                assert_eq!(nfc(x), c[1], "NFC {line}");
                assert_eq!(nfd(x), c[2], "NFD {line}");
            }
            for x in &c[3..] {
                assert_eq!(nfc(x), c[3], "NFC {line}");
                assert_eq!(nfd(x), c[4], "NFD {line}");
            }
            for x in &c {
                assert_eq!(nfkc(x), c[3], "NFKC {line}");
                assert_eq!(nfkd(x), c[4], "NFKD {line}");
            }
            if part == "1" {
                part1.insert(c[0].chars().next().unwrap() as u32);
            }
            lines += 1;
        }
        assert!(lines > 19_000, "{lines}");
        for code in (0..0x110000u32).filter(|c| !part1.contains(c)) {
            let Some(ch) = char::from_u32(code) else { continue };
            let s = ch.to_string();
            assert!(nfc(&s) == s && nfd(&s) == s && nfkc(&s) == s && nfkd(&s) == s,
                    "U+{code:04X} is not in Part 1 and changes");
        }
    }

    #[test]
    fn test_a_few_by_hand() {
        assert_eq!(nfd("\u{e9}"), "e\u{301}");
        assert_eq!(nfc("e\u{301}"), "\u{e9}");
        assert_eq!(nfkd("\u{fb01}"), "fi");
        assert_eq!(nfc("\u{fb01}"), "\u{fb01}");
        // Hangul: GA with a final K, and back.
        assert_eq!(nfd("\u{ac01}"), "\u{1100}\u{1161}\u{11a8}");
        assert_eq!(nfc("\u{1100}\u{1161}\u{11a8}"), "\u{ac01}");
        // A combining mark of a lower class moves before one of a higher.
        assert_eq!(nfd("a\u{301}\u{323}"), "a\u{323}\u{301}");
        // A mark that combines with nothing, then a new starter: the
        // starter clears what blocked the first.
        assert_eq!(nfc("x\u{301}e\u{301}"), "x\u{301}\u{e9}");
        // U+11A7 is one below the first trailing consonant, T_BASE + 1,
        // and does not join a syllable; as an index it would be zero.
        assert_eq!(nfc("\u{ac00}\u{11a7}"), "\u{ac00}\u{11a7}");
    }

    /// Canonical ordering is a stable sort: marks of one class keep their
    /// order. Short runs do not tell a stable sort from an unstable one,
    /// which sorts them by insertion; this run is long enough that they
    /// differ.
    #[test]
    fn test_reordering_is_stable() {
        let marks = ['\u{301}', '\u{316}', '\u{300}', '\u{317}', '\u{302}', '\u{303}'];
        let run: String = (0..60).map(|i| marks[(i * 7 + i / 3) % marks.len()]).collect();
        let class = |c: char| combining_class(c as u32);
        let by_class: String = run.chars().filter(|&c| class(c) == 220)
            .chain(run.chars().filter(|&c| class(c) == 230)).collect();
        assert_eq!(nfd(&format!("a{run}")), format!("a{by_class}"));
    }
}
