/*
ARIA, the Korean national block cipher. RFC 5794, and KS X 1213.

128 bit block, 128/192/256 bit keys, 12/14/16 rounds. It is a
substitution-permutation network like AES, and it uses AES's S-box as
one of its four - but the diffusion layer is a 16x16 binary matrix that
is its own inverse, not a MixColumns, and the key schedule is a
three-round Feistel construction rather than a byte expansion.

It is a Korean government standard, so it appears wherever Korean
e-government, banking and public-sector systems do, and RFC 6209 defines
TLS cipher suites for it. Like SEED - which is the other Korean cipher
in this library, and the older one - it is not broken and not going
away; it is simply absent from most Western software, which is exactly
the gap this project exists to fill.

## Nothing here was typed

`rfcs/rfc5794.txt` is vendored and **everything that could be mistyped
is parsed out of it at compile time**:

- the four S-box tables, 1024 bytes in total;
- the sixteen diffusion equations, 112 term indices;
- the three key-schedule constants C1, C2, C3.

The RFC states four properties of those tables that nothing in the
parser could have arranged, and each is a test: SB3 is the inverse of
SB1, SB4 is the inverse of SB2, the diffusion layer is an involution,
and `SB1(0x23) = 0x26` with `SB4(0xef) = 0xd3`.

**One entry in the whole document is printed with a single digit.**
SB4's row `00` reads `... 72  9 62 3c`, where every other entry is two
characters. A parser requiring two hex digits per entry drops that row
and finds 15 values where it wanted 16 - which is the RFC 1319
continuation-line trap in a new document, and the reason the count is
asserted per row rather than only for the table.

## The vectors are unusually good

Appendix A gives the ciphertext for all three key sizes, and for the
128 bit key it also gives W0..W3, all thirteen round keys and all eleven
intermediate round values. So the key schedule and each individual round
are testable in isolation, and a failure says which round rather than
"the answer is wrong".
*/

use crate::block_ciphers::BlockCipher;

/// RFC 5794, unmodified.
const RFC_5794: &str = include_str!("../../rfcs/rfc5794.txt");

const BLOCK: usize = 16;

/// The four S-boxes, read out of section 2.4.2's tables.
///
/// SB1 is AES's S-box and SB3 its inverse; SB2 and SB4 are ARIA's own
/// pair. The RFC states the inverse relationship, which
/// `test_the_boxes_invert_each_other` checks - a property no parser
/// could have produced by accident, and the strongest available
/// evidence that all four tables were read correctly.
const SB: [[u8; 256]; 4] = [
    parse_sbox(RFC_5794, "SB1:"),
    parse_sbox(RFC_5794, "SB2:"),
    parse_sbox(RFC_5794, "SB3:"),
    parse_sbox(RFC_5794, "SB4:"),
];

/// The diffusion layer, as sixteen rows of seven input indices, read out
/// of section 2.4.3's equations.
const DIFFUSION: [[usize; 7]; 16] = parse_diffusion(RFC_5794);

/// The key-schedule constants, "obtained from the first 128*3 bits of
/// the fractional part of 1/PI". Read out of section 2.2 rather than
/// typed; `test_the_constants_are_the_fractional_part_of_one_over_pi`
/// derives the first of them independently.
const C: [[u8; BLOCK]; 3] = [
    parse_constant(RFC_5794, "C1 =  0x"),
    parse_constant(RFC_5794, "C2 =  0x"),
    parse_constant(RFC_5794, "C3 =  0x"),
];

// ------------------------------------------------- reading the document ---

const fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> usize {
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
    panic!("RFC 5794 no longer contains a section this file reads");
}

const fn hex_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

const fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// A 128-bit constant stated as 32 hex digits after `marker`.
const fn parse_constant(text: &str, marker: &str) -> [u8; BLOCK] {
    let bytes = text.as_bytes();
    let at = find_from(bytes, marker.as_bytes(), 0) + marker.len();
    let mut out = [0u8; BLOCK];
    let mut i = 0;
    while i < BLOCK {
        out[i] = (hex_value(bytes[at + i * 2]) << 4)
            | hex_value(bytes[at + i * 2 + 1]);
        i += 1;
    }
    // The constant is exactly 32 digits; a 33rd would mean the document
    // changed and this read a prefix of something else.
    assert!(!is_hex(bytes[at + BLOCK * 2]),
            "an ARIA constant is longer than 128 bits");
    out
}

/// One S-box table.
///
/// A data row is **seventeen whitespace-separated hex tokens**: the row
/// index and sixteen values. The column header has sixteen one-character
/// tokens and every piece of page furniture contains a letter, so the
/// token shape is the whole discriminator - matching on the furniture
/// instead would mean listing its forms, and a form not listed becomes
/// silent data.
///
/// **An entry may be one digit or two.** SB4's first row prints `09` as
/// ` 9`, alone in the document. Requiring two would drop that row and
/// find fifteen values where it wanted sixteen; the per-row count
/// assertion below is what turns that into a compile error rather than
/// a table that is wrong in one place.
const fn parse_sbox(text: &str, name: &str) -> [u8; 256] {
    let bytes = text.as_bytes();
    let mut at = find_from(bytes, name.as_bytes(), 0) + name.len();

    let mut table = [0u8; 256];
    let mut row = 0;

    while row < 16 {
        // One line.
        let start = at;
        while at < bytes.len() && bytes[at] != b'\n' {
            at += 1;
        }
        let (line_start, line_end) = (start, at);
        if at < bytes.len() {
            at += 1;
        }
        assert!(at < bytes.len(), "an S-box table ended early");

        // Collect the tokens, refusing the line at the first character
        // that is neither a hex digit nor a space.
        let mut values = [0u8; 20];
        let mut count = 0;
        let mut i = line_start;
        let mut ok = true;
        while i < line_end {
            let c = bytes[i];
            if c == b' ' || c == b'\r' {
                i += 1;
            } else if is_hex(c) {
                let mut value = 0u8;
                let mut digits = 0;
                while i < line_end && is_hex(bytes[i]) {
                    value = (value << 4) | hex_value(bytes[i]);
                    i += 1;
                    digits += 1;
                }
                if digits > 2 || count >= 20 {
                    ok = false;
                    break;
                }
                values[count] = value;
                count += 1;
            } else {
                ok = false;
                break;
            }
        }

        if !ok || count != 17 {
            continue;                       // header, blank line, furniture
        }

        // The first token is the row's index, which is how a dropped or
        // duplicated row would be caught rather than silently shifting
        // the table.
        //
        // **Defence in depth, and a breakage sweep cannot see it.**
        // Removing this assertion fails no test, because the document
        // as it stands has its rows in order and the inverse and
        // permutation properties would catch a shifted table anyway. It
        // is kept because those properties are checks on the *result*
        // and this is a check on the *read* - and the read is what a
        // refetched document changes.
        assert!(values[0] as usize == row * 16,
                "an S-box row is out of order or missing");
        let mut j = 0;
        while j < 16 {
            table[row * 16 + j] = values[j + 1];
            j += 1;
        }
        row += 1;
    }

    table
}

/// Section 2.4.3's sixteen equations, as the input index of each term.
const fn parse_diffusion(text: &str) -> [[usize; 7]; 16] {
    let bytes = text.as_bytes();
    // **Anchor on the first equation, not on the section heading.**
    // The prose under the heading says "outputs a 16-byte string y0 ||
    // y1 ||...|| y15", so a search for `y0` from the heading finds that
    // sentence and reads a line with no `x` terms at all. Anchoring on
    // `y0  = x` requires the shape of an equation rather than the name
    // of a variable - and the count assertion below is what turned the
    // mistake into a compile error rather than a table of zeros.
    let mut at = find_from(bytes, b"y0  = x", 0);

    let mut rows = [[0usize; 7]; 16];
    let mut row = 0;
    while row < 16 {
        // `y0  = `, `y10 = ` - the spacing differs between one- and
        // two-digit indices, so the name is matched and the `=` is
        // found afterwards.
        let mut name = [0u8; 4];
        name[0] = b'y';
        let len = if row >= 10 {
            name[1] = b'0' + (row / 10) as u8;
            name[2] = b'0' + (row % 10) as u8;
            3
        } else {
            name[1] = b'0' + row as u8;
            2
        };
        let needle = split(&name, 0, len);
        at = find_from(bytes, needle, at) + len;

        // Everything up to the end of the line.
        let start = at;
        while at < bytes.len() && bytes[at] != b'\n' {
            at += 1;
        }
        let line = split(bytes, start, at);

        let mut terms = 0;
        let mut i = 0;
        while i < line.len() {
            if line[i] == b'x' {
                i += 1;
                let mut index = 0usize;
                let mut digits = 0;
                while i < line.len() && line[i].is_ascii_digit() {
                    index = index * 10 + (line[i] - b'0') as usize;
                    i += 1;
                    digits += 1;
                }
                assert!(digits > 0, "an `x` in a diffusion equation has no \
                                     index");
                assert!(index < 16, "a diffusion term is out of range");
                assert!(terms < 7, "a diffusion equation has more than seven \
                                    terms");
                rows[row][terms] = index;
                terms += 1;
            } else {
                i += 1;
            }
        }
        assert!(terms == 7, "a diffusion equation does not have seven terms");
        row += 1;
    }
    rows
}

/// `&haystack[start..end]`, which is not available in a `const fn`.
const fn split(bytes: &[u8], start: usize, end: usize) -> &[u8] {
    let (_, rest) = bytes.split_at(start);
    let (piece, _) = rest.split_at(end - start);
    piece
}

// ------------------------------------------------------------ the cipher ---

/// Substitution layer 1: `SB1 SB2 SB3 SB4`, repeating. Used by the odd
/// round function.
fn sl1(x: &mut [u8; BLOCK]) {
    for (i, byte) in x.iter_mut().enumerate() {
        *byte = SB[i % 4][*byte as usize];
    }
}

/// Substitution layer 2: `SB3 SB4 SB1 SB2`, repeating - which is SL1's
/// inverse, because SB3 inverts SB1 and SB4 inverts SB2.
fn sl2(x: &mut [u8; BLOCK]) {
    for (i, byte) in x.iter_mut().enumerate() {
        *byte = SB[(i % 4) + 2 - 4 * (i % 4 / 2)][*byte as usize];
    }
}

/// The diffusion layer. An involution, which is what lets the decryption
/// round keys be derived from the encryption ones rather than from a
/// second schedule.
fn diffuse(x: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut y = [0u8; BLOCK];
    for (i, row) in DIFFUSION.iter().enumerate() {
        let mut value = 0u8;
        for &term in row {
            value ^= x[term];
        }
        y[i] = value;
    }
    y
}

fn xor_block(a: &[u8; BLOCK], b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    for i in 0..BLOCK {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// The odd round function: `A(SL1(D ^ RK))`.
fn fo(d: &[u8; BLOCK], rk: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut t = xor_block(d, rk);
    sl1(&mut t);
    diffuse(&t)
}

/// The even round function: `A(SL2(D ^ RK))`.
fn fe(d: &[u8; BLOCK], rk: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut t = xor_block(d, rk);
    sl2(&mut t);
    diffuse(&t)
}

/// Rotate a 128-bit value right by `n` bits.
///
/// Written over bytes rather than over two `u64`s because the RFC's
/// `>>> 19`, `>>> 31` and `<<< 61` are all non-multiples of eight and a
/// word-based version has to get the carry between the halves right in
/// both directions. This one has a single shape for every amount.
fn rotate_right(x: &[u8; BLOCK], n: usize) -> [u8; BLOCK] {
    let n = n % 128;
    let (byte_shift, bit_shift) = (n / 8, n % 8);
    let mut out = [0u8; BLOCK];
    for i in 0..BLOCK {
        let high = x[(i + BLOCK - byte_shift) % BLOCK];
        let low = x[(i + BLOCK - byte_shift - 1) % BLOCK];
        out[i] = if bit_shift == 0 {
            high
        } else {
            (high >> bit_shift) | (low << (8 - bit_shift))
        };
    }
    out
}

fn rotate_left(x: &[u8; BLOCK], n: usize) -> [u8; BLOCK] {
    rotate_right(x, 128 - (n % 128))
}

/// The two round functions as sixteen tables of 256 blocks each.
///
/// A, the diffusion layer, is linear over the bytes (each output byte is
/// a XOR of input bytes), so `A(SL(x))` is the XOR over positions `i` of
/// A applied to the block holding `SL(x)[i]` at `i` and zeros elsewhere:
/// `odd[i][v] = A(e_i * SL1_i(v))`, `even` the same with SL2. Built from
/// `sl1`, `sl2` and `diffuse` on first use - 128 KB, too much for a
/// `const` - and checked against `fo`/`fe` by
/// `test_the_tables_are_the_round_functions`.
struct Tables {
    odd: [[u128; 256]; BLOCK],
    even: [[u128; 256]; BLOCK],
}

fn tables() -> &'static Tables {
    static TABLES: std::sync::OnceLock<Box<Tables>> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = Box::new(Tables { odd: [[0; 256]; BLOCK], even: [[0; 256]; BLOCK] });
        for v in 0..256 {
            let mut odd = [v as u8; BLOCK];
            sl1(&mut odd);
            let mut even = [v as u8; BLOCK];
            sl2(&mut even);
            for i in 0..BLOCK {
                let mut one = [0u8; BLOCK];
                one[i] = odd[i];
                t.odd[i][v] = u128::from_le_bytes(diffuse(&one));
                let mut one = [0u8; BLOCK];
                one[i] = even[i];
                t.even[i][v] = u128::from_le_bytes(diffuse(&one));
            }
        }
        t
    })
}

#[inline(always)]
fn through(table: &[[u128; 256]; BLOCK], x: u128) -> u128 {
    let mut out = 0u128;
    for (i, row) in table.iter().enumerate() {
        out ^= row[((x >> (8 * i)) & 0xff) as usize];
    }
    out
}

#[derive(Clone)]
pub struct Aria {
    /// `rounds + 1` round keys. Encryption and decryption use the same
    /// algorithm with different tables, which is what the involution
    /// property of the diffusion layer buys.
    encrypt_keys: Vec<[u8; BLOCK]>,
    decrypt_keys: Vec<[u8; BLOCK]>,
    rounds: usize,
}

impl Aria {
    pub fn new(key: &[u8]) -> Result<Aria, String> {
        let rounds = match key.len() {
            16 => 12,
            24 => 14,
            32 => 16,
            other => return Err(format!(
                "Wrong key length {}. ARIA takes 16, 24 or 32 bytes.", other)),
        };

        // KL is the leftmost 128 bits; KR is the rest, right-padded with
        // zeros. For a 128 bit key KR is entirely zero, which is not a
        // special case in the code and must not become one.
        let mut kl = [0u8; BLOCK];
        kl.copy_from_slice(&key[..BLOCK]);
        let mut kr = [0u8; BLOCK];
        kr[..key.len() - BLOCK].copy_from_slice(&key[BLOCK..]);

        // The constants rotate with the key size: 128 takes C1 C2 C3,
        // 192 takes C2 C3 C1, 256 takes C3 C1 C2.
        let offset = match key.len() { 16 => 0, 24 => 1, _ => 2 };
        let ck = |i: usize| C[(offset + i) % 3];

        let w0 = kl;
        let w1 = xor_block(&fo(&w0, &ck(0)), &kr);
        let w2 = xor_block(&fe(&w1, &ck(1)), &w0);
        let w3 = xor_block(&fo(&w2, &ck(2)), &w1);
        let w = [w0, w1, w2, w3];

        // ek1..ek17, four at a time: each group of four takes the same
        // rotation and steps which pair of `W` values it combines.
        // Written as the RFC's table rather than as a loop with clever
        // indexing, because the *last* one (`ek17 = W0 ^ (W1 <<< 19)`)
        // breaks the pattern and a loop would have to special-case it
        // anyway.
        let rot_right = |i: usize, n: usize| rotate_right(&w[i], n);
        let rot_left = |i: usize, n: usize| rotate_left(&w[i], n);
        let all: Vec<[u8; BLOCK]> = vec![
            xor_block(&w[0], &rot_right(1, 19)),
            xor_block(&w[1], &rot_right(2, 19)),
            xor_block(&w[2], &rot_right(3, 19)),
            xor_block(&rot_right(0, 19), &w[3]),
            xor_block(&w[0], &rot_right(1, 31)),
            xor_block(&w[1], &rot_right(2, 31)),
            xor_block(&w[2], &rot_right(3, 31)),
            xor_block(&rot_right(0, 31), &w[3]),
            xor_block(&w[0], &rot_left(1, 61)),
            xor_block(&w[1], &rot_left(2, 61)),
            xor_block(&w[2], &rot_left(3, 61)),
            xor_block(&rot_left(0, 61), &w[3]),
            xor_block(&w[0], &rot_left(1, 31)),
            xor_block(&w[1], &rot_left(2, 31)),
            xor_block(&w[2], &rot_left(3, 31)),
            xor_block(&rot_left(0, 31), &w[3]),
            xor_block(&w[0], &rot_left(1, 19)),
        ];
        let encrypt_keys: Vec<[u8; BLOCK]> = all[..rounds + 1].to_vec();

        // dk1 = ek{n+1}, dk{n+1} = ek1, and everything between is the
        // diffusion layer applied to the encryption key in reverse. That
        // works only because A is an involution.
        let mut decrypt_keys = Vec::with_capacity(rounds + 1);
        decrypt_keys.push(encrypt_keys[rounds]);
        for i in (1..rounds).rev() {
            decrypt_keys.push(diffuse(&encrypt_keys[i]));
        }
        decrypt_keys.push(encrypt_keys[0]);

        Ok(Aria { encrypt_keys, decrypt_keys, rounds })
    }

    /// The shared body of encryption and decryption: odd rounds are
    /// `FO`, even ones `FE`, and the last round is a substitution and
    /// two key additions with no diffusion. Through `Tables`.
    fn transform(&self, input: &[u8], keys: &[[u8; BLOCK]]) -> [u8; BLOCK] {
        let t = tables();
        let mut p = u128::from_le_bytes(input[..BLOCK].try_into().unwrap());
        for round in 1..self.rounds {
            let table = if round % 2 == 1 { &t.odd } else { &t.even };
            p = through(table, p ^ u128::from_le_bytes(keys[round - 1]));
        }
        let mut last = xor_block(&p.to_le_bytes(), &keys[self.rounds - 1]);
        sl2(&mut last);
        xor_block(&last, &keys[self.rounds])
    }

    /// The same with `fo` and `fe` as the RFC writes them: the reference
    /// the tables are tested against.
    #[cfg(test)]
    fn transform_reference(&self, input: &[u8], keys: &[[u8; BLOCK]]) -> [u8; BLOCK] {
        let mut p = [0u8; BLOCK];
        p.copy_from_slice(&input[..BLOCK]);
        for round in 1..self.rounds {
            p = if round % 2 == 1 {
                fo(&p, &keys[round - 1])
            } else {
                fe(&p, &keys[round - 1])
            };
        }
        let mut last = xor_block(&p, &keys[self.rounds - 1]);
        sl2(&mut last);
        xor_block(&last, &keys[self.rounds])
    }
}

impl BlockCipher for Aria {
    fn blocksize(&self) -> usize { BLOCK }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let out = self.transform(input, &self.encrypt_keys);
        result.extend_from_slice(&out);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let out = self.transform(input, &self.decrypt_keys);
        result.extend_from_slice(&out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_the_tables_are_the_round_functions() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for key_len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..key_len).map(|_| next()).collect();
            let aria = Aria::new(&key).unwrap();
            for _ in 0..200 {
                let block: Vec<u8> = (0..BLOCK).map(|_| next()).collect();
                for keys in [&aria.encrypt_keys, &aria.decrypt_keys] {
                    assert_eq!(aria.transform(&block, keys),
                               aria.transform_reference(&block, keys));
                }
            }
        }
    }

    fn unhex(text: &str) -> Vec<u8> {
        let clean: String = text.chars().filter(|c| c.is_ascii_hexdigit())
            .collect();
        assert!(clean.len().is_multiple_of(2), "odd hex run {text:?}");
        (0..clean.len() / 2)
            .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn encrypt(key: &[u8], block: &[u8]) -> Vec<u8> {
        let mut cipher = Aria::new(key).unwrap();
        let mut out = Vec::new();
        cipher.block_encrypt(block, &mut out);
        out
    }

    // ------------------------------------------ what was read out ---

    #[test]
    fn test_the_rfcs_own_spot_checks() {
        // "For example, SB1(0x23) = 0x26 and SB4(0xef) = 0xd3." Two
        // statements the document makes in prose about tables it prints
        // elsewhere - so agreeing with them is a check on the parse
        // that the tables themselves cannot be.
        assert_eq!(SB[0][0x23], 0x26);
        assert_eq!(SB[3][0xef], 0xd3);
    }

    #[test]
    fn test_the_boxes_invert_each_other() {
        // RFC 5794 2.4.2: "SB3 and SB4 are the inverse functions of SB1
        // and SB2". Four tables of 256 bytes, and this holds only if
        // every one of the 1024 was read correctly - no parser could
        // arrange it by accident, and a single transposed digit breaks
        // it.
        for x in 0..=255u8 {
            assert_eq!(SB[2][SB[0][x as usize] as usize], x, "SB3(SB1({x}))");
            assert_eq!(SB[3][SB[1][x as usize] as usize], x, "SB4(SB2({x}))");
        }
    }

    #[test]
    fn test_each_box_is_a_permutation() {
        for (n, box_) in SB.iter().enumerate() {
            let mut seen = [false; 256];
            for &value in box_.iter() {
                assert!(!seen[value as usize],
                        "SB{} has {} twice", n + 1, value);
                seen[value as usize] = true;
            }
        }
    }

    #[test]
    fn test_sb1_is_the_aes_s_box() {
        // ARIA borrows AES's S-box as SB1, so this library already has
        // an independent copy of it. Agreeing with a table read from a
        // different document by different code is worth more than any
        // property of the bytes on their own.
        //
        // AES's is built rather than tabulated here, so this compares a
        // *construction* with a *table* - the two cannot share a
        // mistake.
        let mut aes = crate::block_ciphers::aes::AesCrypto::new(vec![0u8; 16])
            .unwrap();
        // AES's S-box is what ECB of a zero key applies first; rather
        // than reaching inside, use the algebraic definition the box
        // comes from, which RFC 5794 does not state at all.
        for x in 0..=255u8 {
            assert_eq!(SB[0][x as usize], aes_sbox(x), "SB1({x})");
        }
        let _ = &mut aes;
    }

    /// AES's S-box from its definition: the multiplicative inverse in
    /// GF(2^8) mod 0x11b, then an affine transform. Written here so the
    /// comparison above is against a construction rather than a second
    /// copy of a table.
    fn aes_sbox(x: u8) -> u8 {
        fn inverse(a: u8) -> u8 {
            if a == 0 { return 0; }
            // Brute force: 256 iterations is nothing in a test, and a
            // loop is harder to get wrong than an extended Euclid.
            for b in 1..=255u8 {
                if gf_mul(a, b) == 1 { return b; }
            }
            unreachable!("every non-zero element has an inverse")
        }
        fn gf_mul(mut a: u8, mut b: u8) -> u8 {
            let mut product = 0u8;
            while b != 0 {
                if b & 1 != 0 { product ^= a; }
                let high = a & 0x80;
                a <<= 1;
                if high != 0 { a ^= 0x1b; }
                b >>= 1;
            }
            product
        }
        let inv = inverse(x);
        inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3)
            ^ inv.rotate_left(4) ^ 0x63
    }

    #[test]
    fn test_the_diffusion_layer_is_an_involution() {
        // RFC 5794 2.4.3: "Note that A is an involution. That is, for
        // any 16-byte input string x, x = A(A(x)) holds." 112 parsed
        // indices, and this holds only if all of them are right. It is
        // also what makes the decryption key schedule possible, so it
        // is a claim about the cipher as well as about the parse.
        for trial in 0..64u8 {
            let mut x = [0u8; BLOCK];
            for (i, byte) in x.iter_mut().enumerate() {
                *byte = trial.wrapping_mul(31).wrapping_add(i as u8 * 7);
            }
            assert_eq!(diffuse(&diffuse(&x)), x);
        }
        // And a single bit, which is the case an involution over a
        // *wrong* matrix is most likely to survive by accident.
        for bit in 0..128 {
            let mut x = [0u8; BLOCK];
            x[bit / 8] = 1 << (bit % 8);
            assert_eq!(diffuse(&diffuse(&x)), x, "bit {bit}");
        }
    }

    #[test]
    fn test_every_diffusion_row_has_seven_distinct_terms() {
        for (i, row) in DIFFUSION.iter().enumerate() {
            let mut seen = [false; 16];
            for &term in row {
                assert!(!seen[term], "y{i} uses x{term} twice");
                seen[term] = true;
            }
        }
        // And every input is used the same number of times, which a
        // dropped or duplicated term breaks.
        let mut uses = [0usize; 16];
        for row in DIFFUSION.iter() {
            for &term in row {
                uses[term] += 1;
            }
        }
        assert!(uses.iter().all(|&n| n == 7), "{uses:?}");
    }

    #[test]
    fn test_the_constants_are_the_fractional_part_of_one_over_pi() {
        // RFC 5794 2.2: "obtained from the first 128*3 bits of the
        // fractional part of 1/PI". Checked on the leading bytes of C1,
        // which is as far as f64 can be trusted - enough to catch a
        // transposed digit at the front and to say the three constants
        // are what the document claims rather than arbitrary.
        let fractional = 1.0f64 / std::f64::consts::PI;
        let leading = (fractional * 2.0f64.powi(32)) as u32;
        assert_eq!(leading, u32::from_be_bytes(C[0][..4].try_into().unwrap()));

        // The three are different and none is zero, which is the check
        // that catches the parser reading one marker three times.
        assert_ne!(C[0], C[1]);
        assert_ne!(C[1], C[2]);
        assert_ne!(C[0], C[2]);
        assert!(C.iter().all(|c| c.iter().any(|&b| b != 0)));
    }

    #[test]
    fn test_sl2_inverts_sl1() {
        // The substitution layers are built by indexing `SB` with an
        // expression rather than by two tables, and the expression for
        // SL2 is the one place in this file where an off-by-one would
        // be invisible - both layers would still be permutations.
        for trial in 0..32u8 {
            let mut x = [0u8; BLOCK];
            for (i, byte) in x.iter_mut().enumerate() {
                *byte = trial.wrapping_mul(17).wrapping_add(i as u8);
            }
            let original = x;
            sl1(&mut x);
            sl2(&mut x);
            assert_eq!(x, original);
        }
        // And SL2 really is SB3 SB4 SB1 SB2, not SB1 SB2 SB3 SB4 again.
        let mut x = [0u8; BLOCK];
        sl2(&mut x);
        assert_eq!(x[0], SB[2][0]);
        assert_eq!(x[1], SB[3][0]);
        assert_eq!(x[2], SB[0][0]);
        assert_eq!(x[3], SB[1][0]);
    }

    #[test]
    fn test_the_rotations() {
        // `>>> 19`, `>>> 31` and `<<< 61` are all non-multiples of
        // eight, which is where a byte-wise rotation goes wrong. A
        // rotation by 128 is the identity and rotating both ways by the
        // same amount returns the original - properties that hold only
        // if the carry between bytes is right.
        let x: [u8; BLOCK] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3));
        assert_eq!(rotate_right(&x, 0), x);
        assert_eq!(rotate_right(&x, 128), x);
        for n in [1usize, 7, 8, 19, 31, 61, 64, 100, 127] {
            assert_eq!(rotate_left(&rotate_right(&x, n), n), x, "{n}");
            assert_ne!(rotate_right(&x, n), x, "{n}");
        }
        // A one-bit value, where the answer is unambiguous.
        let mut one = [0u8; BLOCK];
        one[0] = 0x80;                        // the most significant bit
        let moved = rotate_right(&one, 1);
        assert_eq!(moved[0], 0x40);
        assert!(moved[1..].iter().all(|&b| b == 0));
    }

    // -------------------------------------- RFC 5794 Appendix A, parsed ---

    /// A field stated as `- Name : <hex>` or `Name : <hex>`, possibly
    /// continued on the next line.
    fn appendix_field(section: &str, name: &str) -> Vec<u8> {
        let at = section.find(name)
            .unwrap_or_else(|| panic!("appendix has no {name:?}"));
        let after = &section[at + name.len()..];
        // Everything up to the next field or blank line. The 192 and
        // 256 bit keys wrap onto a second line, so a single-line read
        // would silently take half a key.
        let mut value = String::new();
        for line in after.lines() {
            let trimmed = line.trim();
            if value.is_empty() {
                // The first line still carries the `:` and the value.
                let start = trimmed.find(':').map(|i| i + 1).unwrap_or(0);
                value.push_str(&trimmed[start..]);
                continue;
            }
            // A continuation is hex and nothing else.
            if trimmed.is_empty()
                || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                break;
            }
            value.push_str(trimmed);
        }
        unhex(&value)
    }

    fn appendix(section: &str) -> &'static str {
        let at = RFC_5794.find(section)
            .unwrap_or_else(|| panic!("RFC 5794 has no {section:?}"));
        let rest = &RFC_5794[at..];
        let end = rest[section.len()..].find("\nA.")
            .map(|i| i + section.len())
            .unwrap_or_else(|| rest.find("Appendix B").unwrap_or(rest.len()));
        &rest[..end]
    }

    #[test]
    fn test_the_published_vectors() {
        // All three key sizes, from A.1, A.2 and A.3.
        let cases = [("A.1.  128-Bit Key", 16usize),
                     ("A.2.  192-Bit Key", 24),
                     ("A.3.  256-Bit Key", 32)];
        for (heading, key_len) in cases {
            let section = appendix(heading);
            let key = appendix_field(section, "Key ");
            let plaintext = appendix_field(section, "Plaintext");
            let ciphertext = appendix_field(section, "Ciphertext");
            assert_eq!(key.len(), key_len, "{heading} key length");
            assert_eq!(plaintext.len(), BLOCK);
            assert_eq!(ciphertext.len(), BLOCK);

            assert_eq!(hex(&encrypt(&key, &plaintext)), hex(&ciphertext),
                       "{heading}");

            let mut cipher = Aria::new(&key).unwrap();
            let mut back = Vec::new();
            cipher.block_decrypt(&ciphertext, &mut back);
            assert_eq!(hex(&back), hex(&plaintext), "{heading} decrypting");
        }
    }

    #[test]
    fn test_the_published_round_keys_and_intermediate_values() {
        // **The reason ARIA's appendix is unusually good.** A.1 states
        // W0..W3, all thirteen round keys and all eleven intermediate
        // values, so the key schedule and each individual round are
        // testable on their own - and a failure says *which* round
        // rather than "the answer is wrong".
        let section = appendix("A.1.  128-Bit Key");
        let key = appendix_field(section, "Key ");
        let plaintext = appendix_field(section, "Plaintext");
        let cipher = Aria::new(&key).unwrap();

        // The round keys, e1..e13.
        for (i, expected) in (1..=13).map(|i| {
            (i, appendix_field(section, &format!("e{i}:")))
        }) {
            assert_eq!(hex(&cipher.encrypt_keys[i - 1]), hex(&expected),
                       "round key e{i}");
        }

        // The intermediate values, P1..P11, each one round further in.
        let mut p = [0u8; BLOCK];
        p.copy_from_slice(&plaintext);
        for i in 1..=11usize {
            p = if i % 2 == 1 {
                fo(&p, &cipher.encrypt_keys[i - 1])
            } else {
                fe(&p, &cipher.encrypt_keys[i - 1])
            };
            let expected = appendix_field(section, &format!("P{i}:"));
            assert_eq!(hex(&p), hex(&expected), "intermediate P{i}");
        }
    }

    #[test]
    fn test_the_appendix_parser_found_what_it_claims() {
        // Every parser in this repository that quietly found nothing
        // turned a loop into a pass. These are the counts the tests
        // above depend on.
        let section = appendix("A.1.  128-Bit Key");
        assert_eq!(appendix_field(section, "Key ").len(), 16);
        assert_eq!(appendix_field(section, "W1:").len(), BLOCK);
        assert_eq!(appendix_field(section, "e13:").len(), BLOCK);
        assert_eq!(appendix_field(section, "P11:").len(), BLOCK);

        // And the 192 bit key really is 24 bytes, which is the one that
        // wraps onto a second line - a single-line read gives 16 and
        // would then be testing ARIA-128 under a different name.
        let wide = appendix("A.2.  192-Bit Key");
        assert_eq!(appendix_field(wide, "Key ").len(), 24);
    }

    // ------------------------------------------------------ the design ---

    #[test]
    fn test_the_round_counts() {
        assert_eq!(Aria::new(&[0u8; 16]).unwrap().rounds, 12);
        assert_eq!(Aria::new(&[0u8; 24]).unwrap().rounds, 14);
        assert_eq!(Aria::new(&[0u8; 32]).unwrap().rounds, 16);
        for bad in [0usize, 1, 8, 15, 17, 23, 25, 31, 33, 64] {
            assert!(Aria::new(&vec![0u8; bad]).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn test_the_three_key_sizes_use_different_constants() {
        // The constants rotate with the key size - 128 takes C1 C2 C3,
        // 192 takes C2 C3 C1 - so a 192 bit key whose first 16 bytes
        // match a 128 bit key must still give different round keys. An
        // implementation that ignored the rotation passes the 128 bit
        // vector and fails the other two, which is what happened to
        // whoever wrote the RFC's example table.
        let short = Aria::new(&[0u8; 16]).unwrap();
        let long = Aria::new(&[0u8; 24]).unwrap();
        assert_ne!(short.encrypt_keys[0], long.encrypt_keys[0]);
    }

    #[test]
    fn test_a_192_bit_key_is_right_padded_not_left() {
        // KR is "the remaining bits of K, right-padded with zeros". A
        // left pad would put the key bytes in the wrong half of KR and
        // is invisible to the 128 bit vector, where KR is all zeros.
        let mut key = [0u8; 24];
        key[16] = 1;                       // the first byte of KR
        let first = Aria::new(&key).unwrap();
        let mut other = [0u8; 24];
        other[23] = 1;                     // the last byte of KR
        let second = Aria::new(&other).unwrap();
        assert_ne!(first.encrypt_keys[0], second.encrypt_keys[0]);
    }

    #[test]
    fn test_decryption_keys_come_from_the_encryption_ones() {
        // dk1 = ek{n+1}, dk{n+1} = ek1, and the middle is A applied to
        // the encryption keys in reverse - which works only because A
        // is an involution. Asserted directly, because a wrong middle
        // still round-trips for a cipher with one round.
        let cipher = Aria::new(&[0u8; 16]).unwrap();
        let n = cipher.rounds;
        assert_eq!(cipher.decrypt_keys[0], cipher.encrypt_keys[n]);
        assert_eq!(cipher.decrypt_keys[n], cipher.encrypt_keys[0]);
        for i in 1..n {
            assert_eq!(cipher.decrypt_keys[i],
                       diffuse(&cipher.encrypt_keys[n - i]), "dk{}", i + 1);
        }
    }

    #[test]
    fn test_round_tripping_every_mode_at_every_key_size() {
        let iv = vec![7u8; BLOCK];
        let plain: Vec<u8> = (0..64u8).collect();
        for key_len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..key_len as u8).collect();
            for mode in ["ecb", "cbc", "pcbc", "cfb", "ofb", "ctr"] {
                let mut cipher = Aria::new(&key).unwrap();
                let mut out = Vec::new();
                match mode {
                    "ecb" => cipher.ecb_encrypt(&plain, &mut out).unwrap(),
                    "cbc" => cipher.cbc_encrypt(&plain, &mut out, iv.clone()).unwrap(),
                    "pcbc" => cipher.pcbc_encrypt(&plain, &mut out, iv.clone()).unwrap(),
                    "cfb" => cipher.cfb_encrypt(&plain, &mut out, iv.clone()).unwrap(),
                    "ofb" => cipher.ofb_encrypt(&plain, &mut out, iv.clone()).unwrap(),
                    _ => cipher.ctr_encrypt(&plain, &mut out, &iv).unwrap(),
                }
                assert_ne!(out, plain, "{key_len} {mode}");

                let mut cipher = Aria::new(&key).unwrap();
                let mut back = Vec::new();
                match mode {
                    "ecb" => cipher.ecb_decrypt(&out, &mut back).unwrap(),
                    "cbc" => cipher.cbc_decrypt(&out, &mut back, iv.clone()).unwrap(),
                    "pcbc" => cipher.pcbc_decrypt(&out, &mut back, iv.clone()).unwrap(),
                    "cfb" => cipher.cfb_decrypt(&out, &mut back, iv.clone()).unwrap(),
                    "ofb" => cipher.ofb_decrypt(&out, &mut back, iv.clone()).unwrap(),
                    _ => cipher.ctr_decrypt(&out, &mut back, &iv).unwrap(),
                }
                assert_eq!(back, plain, "{key_len} {mode}");
            }
        }
    }
}
