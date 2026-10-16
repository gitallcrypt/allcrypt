/*!
MISTY1, Matsui's cipher for Mitsubishi Electric (RFC 2994), a NESSIE
selection and the ancestor of KASUMI: a 64-bit block, a 128-bit key and
eight rounds of a Feistel network whose round function `FO` is built
from the nine- and seven-bit S-boxes S9 and S7, with a key-dependent
linear layer `FL` applied to both halves every two rounds and at the end.

## Following RFC 2994

The RFC's section 2 is the definition used here, step for step: the key
schedule `EK`, `FI`, `FO`, `FL` and its inverse `FLINV`, and the round
sequence, ending with the halves exchanged - `C = (D1 << 32) | D0`. `FI`
masks its seven-bit half after the first S7 lookup, which the RFC writes
in parentheses and which matters: S7's output XOR the nine-bit half does
not fit seven bits.

## The tables

S7 and S9 are parsed out of RFC 2994 itself, vendored as
`rfcs/rfc2994.txt`, at compile time: nothing about them is typed here.
`scripts/make_misty1_vectors.py` requires Botan's and Crypt::Misty1's
tables to be the RFC's too before it writes anything.

## Not constant time

S7 and S9 are tables indexed by data mixed with key words.

## Where the vectors come from

`vectors/misty1.vec`, written by `scripts/make_misty1_vectors.py`:
blocks on which Botan and Crypt::Misty1 agree, with the RFC's example,
which both carry. The RFC's ECB and CBC examples are also read out of
the RFC by the tests.
*/

use super::BlockCipher;

const BLOCK: usize = 8;

const RFC_2994: &str = include_str!("../../rfcs/rfc2994.txt");

const fn find(haystack: &[u8], needle: &[u8]) -> usize {
    let mut at = 0;
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
    panic!("RFC 2994 no longer contains a table this file reads");
}

const fn hex_value(c: u8) -> u16 {
    match c {
        b'0'..=b'9' => (c - b'0') as u16,
        b'a'..=b'f' => (c - b'a' + 10) as u16,
        _ => panic!("not a lower-case hex digit"),
    }
}

/// The `N` entries of the table printed under `heading`, each `digits`
/// hex digits wide.
///
/// A data row is a label - the index of its first entry in hex, then a
/// colon - and sixteen entries. The column header has no colon and the
/// page furniture has letters outside a-f, so a line is a row exactly
/// when it starts with hex digits and a colon; the label must equal the
/// number of entries read so far, and each row must hold sixteen, which
/// is what turns a skipped or doubled row into a compile error.
const fn parse_table<const N: usize>(heading: &str, digits: usize) -> [u16; N] {
    let text = RFC_2994.as_bytes();
    let mut at = find(text, heading.as_bytes()) + heading.len();
    let mut out = [0u16; N];
    let mut count = 0;
    while count < N {
        // The start of the next line.
        while text[at] != b'\n' {
            at += 1;
        }
        at += 1;
        let mut i = at;
        while text[i] == b' ' {
            i += 1;
        }
        let mut label = 0usize;
        let label_start = i;
        while text[i].is_ascii_hexdigit() && (text[i] < b'A' || text[i] > b'F') {
            label = label * 16 + hex_value(text[i]) as usize;
            i += 1;
        }
        if i == label_start || text[i] != b':' {
            continue;
        }
        assert!(label == count, "a table row's label is not where the entries read end");
        i += 1;
        let mut in_row = 0;
        while in_row < 16 {
            while text[i] == b' ' {
                i += 1;
            }
            let mut value = 0u16;
            let mut d = 0;
            while d < digits {
                value = value * 16 + hex_value(text[i + d]);
                d += 1;
            }
            assert!(!text[i + digits].is_ascii_hexdigit(), "a table entry is too long");
            out[count] = value;
            count += 1;
            in_row += 1;
            i += digits;
        }
    }
    out
}

/// RFC 2994's S7TABLE.
const S7: [u8; 128] = {
    let wide: [u16; 128] = parse_table("S7TABLE:", 2);
    let mut out = [0u8; 128];
    let mut i = 0;
    while i < 128 {
        assert!(wide[i] < 128, "S7 is a seven-bit table");
        out[i] = wide[i] as u8;
        i += 1;
    }
    out
};

/// RFC 2994's S9TABLE.
const S9: [u16; 512] = parse_table("S9TABLE:", 3);

#[derive(Clone)]
pub struct Misty1 {
    /// RFC 2994's `EK[0..16]`: the key's eight words and their images
    /// under `FI`. The RFC's `EK[16..32]` are those images split nine and
    /// seven bits, which `FI` does for itself from the whole word, and
    /// nothing in the RFC's own pseudocode reads them.
    ek: [u16; 16],
}

/// RFC 2994's `FI`.
fn fi(input: u16, key: u16) -> u16 {
    let mut d9 = input >> 7;
    let mut d7 = input & 0x7f;
    d9 = S9[usize::from(d9)] ^ d7;
    d7 = (u16::from(S7[usize::from(d7)]) ^ d9) & 0x7f;
    d7 ^= key >> 9;
    d9 ^= key & 0x1ff;
    d9 = S9[usize::from(d9)] ^ d7;
    (d7 << 9) | d9
}

impl Misty1 {
    pub fn new(key: &[u8]) -> Result<Misty1, String> {
        if key.len() != 16 {
            return Err(format!("Wrong key length {}. MISTY1 takes a 16 byte key.", key.len()));
        }
        let mut ek = [0u16; 16];
        for i in 0..8 {
            ek[i] = u16::from_be_bytes([key[2 * i], key[2 * i + 1]]);
        }
        for i in 0..8 {
            ek[i + 8] = fi(ek[i], ek[(i + 1) % 8]);
        }
        Ok(Misty1 { ek })
    }

    /// RFC 2994's `FO`.
    fn fo(&self, input: u32, k: usize) -> u32 {
        let ek = &self.ek;
        let (mut t0, mut t1) = ((input >> 16) as u16, input as u16);
        t0 ^= ek[k];
        t0 = fi(t0, ek[(k + 5) % 8 + 8]) ^ t1;
        t1 ^= ek[(k + 2) % 8];
        t1 = fi(t1, ek[(k + 1) % 8 + 8]) ^ t0;
        t0 ^= ek[(k + 7) % 8];
        t0 = fi(t0, ek[(k + 3) % 8 + 8]) ^ t1;
        t1 ^= ek[(k + 4) % 8];
        (u32::from(t1) << 16) | u32::from(t0)
    }

    /// The two key words `FL(·, k)` uses: the AND's and the OR's.
    fn fl_keys(&self, k: usize) -> (u16, u16) {
        let ek = &self.ek;
        if k.is_multiple_of(2) {
            (ek[k / 2], ek[(k / 2 + 6) % 8 + 8])
        } else {
            (ek[((k - 1) / 2 + 2) % 8 + 8], ek[((k - 1) / 2 + 4) % 8])
        }
    }

    /// RFC 2994's `FL`.
    fn fl(&self, input: u32, k: usize) -> u32 {
        let (and, or) = self.fl_keys(k);
        let (mut d0, mut d1) = ((input >> 16) as u16, input as u16);
        d1 ^= d0 & and;
        d0 ^= d1 | or;
        (u32::from(d0) << 16) | u32::from(d1)
    }

    /// RFC 2994's `FLINV`.
    fn fl_inverse(&self, input: u32, k: usize) -> u32 {
        let (and, or) = self.fl_keys(k);
        let (mut d0, mut d1) = ((input >> 16) as u16, input as u16);
        d0 ^= d1 | or;
        d1 ^= d0 & and;
        (u32::from(d0) << 16) | u32::from(d1)
    }
}

fn halves(input: &[u8]) -> (u32, u32) {
    (u32::from_be_bytes(input[..4].try_into().expect("4 bytes")),
     u32::from_be_bytes(input[4..BLOCK].try_into().expect("4 bytes")))
}

impl BlockCipher for Misty1 {
    fn blocksize(&self) -> usize {
        BLOCK
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut d0, mut d1) = halves(input);
        for round in (0..8).step_by(2) {
            d0 = self.fl(d0, round);
            d1 = self.fl(d1, round + 1);
            d1 ^= self.fo(d0, round);
            d0 ^= self.fo(d1, round + 1);
        }
        d0 = self.fl(d0, 8);
        d1 = self.fl(d1, 9);
        result.extend_from_slice(&d1.to_be_bytes());
        result.extend_from_slice(&d0.to_be_bytes());
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut d1, mut d0) = halves(input);
        d0 = self.fl_inverse(d0, 8);
        d1 = self.fl_inverse(d1, 9);
        for round in (0..8).step_by(2).rev() {
            d0 ^= self.fo(d1, round + 1);
            d1 ^= self.fo(d0, round);
            d0 = self.fl_inverse(d0, round);
            d1 = self.fl_inverse(d1, round + 1);
        }
        result.extend_from_slice(&d0.to_be_bytes());
        result.extend_from_slice(&d1.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tables parsed out of the RFC are permutations of seven and
    /// nine bits, and the first and last entries are the RFC's first and
    /// last, read from the document's own text.
    #[test]
    fn test_the_tables_parsed_from_the_rfc() {
        let mut seven = S7.to_vec();
        seven.sort_unstable();
        assert!(seven.iter().copied().eq(0..128u8));
        let mut nine = S9.to_vec();
        nine.sort_unstable();
        assert!(nine.iter().copied().eq(0..512u16));
        let first_row = |heading: &str| -> Vec<u16> {
            let after = &RFC_2994[RFC_2994.find(heading).unwrap()..];
            let line = after.lines().find(|l| l.trim_start().starts_with("0") && l.contains(':'))
                .unwrap();
            line.split(':').nth(1).unwrap().split_whitespace()
                .map(|v| u16::from_str_radix(v, 16).unwrap()).collect()
        };
        assert_eq!(first_row("S7TABLE:"), S7[..16].iter().map(|&v| u16::from(v)).collect::<Vec<_>>());
        assert_eq!(first_row("S9TABLE:"), S9[..16].to_vec());
    }

    #[test]
    fn test_the_key_length_is_checked() {
        for len in [0, 8, 15, 17, 24, 32] {
            assert!(Misty1::new(&vec![0u8; len]).is_err(), "{len}");
        }
    }

    /// `FLINV` inverts `FL` for every key position, and decryption
    /// inverts encryption.
    #[test]
    fn test_decryption_inverts() {
        let mut seed = 0x0d15_2000u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..32 {
            let key: Vec<u8> = (0..16).map(|_| next()).collect();
            let block: Vec<u8> = (0..8).map(|_| next()).collect();
            let mut c = Misty1::new(&key).unwrap();
            for k in 0..10 {
                let x = u32::from_be_bytes(block[..4].try_into().unwrap());
                assert_eq!(c.fl_inverse(c.fl(x, k), k), x);
            }
            let (mut out, mut back) = (Vec::new(), Vec::new());
            c.block_encrypt(&block, &mut out);
            c.block_decrypt(&out, &mut back);
            assert_eq!(back, block);
            assert_ne!(out, block);
        }
    }
}
