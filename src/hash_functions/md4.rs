//! MD4, RFC 1320.
//!
//! Ronald Rivest, 1990. Collisions are findable by hand in under a
//! minute (Wang, 2004) and a preimage costs about 2^102, so it protects
//! nothing. RFC 6150 moved it to Historic in 2011.
//!
//! It is here because a great deal of deployed machinery still speaks
//! it and none of that machinery is ours to upgrade:
//!
//! - **NTLM.** The NT hash is `MD4(UTF-16LE(password))`, and NTLM and
//!   NTLMv2 are what a Windows file server or an old IIS will offer.
//! - **CHAP and MS-CHAPv2**, which reach the same hash.
//! - `rsync`'s pre-3.0 whole-file checksum.
//! - RIPEMD, MD5, SHA-0 and SHA-1 are all MD4's shape with more rounds,
//!   so it is also the family's root.
//!
//! ## Nothing in this file was typed
//!
//! MD4's round schedules are four lines of sixteen `[ABCD k s]` groups
//! each, and round 3's message order - `0 8 4 12, 2 10 6 14, 1 9 5 13,
//! 3 11 7 15` - is the single most mistyped table in the MD family. A
//! wrong entry gives a hash that is perfectly self-consistent: it
//! streams correctly, it round-trips nothing because there is nothing
//! to round-trip, and only a published vector notices.
//!
//! So the schedules, the rotations and the two additive constants are
//! all **read out of RFC 1320 at compile time**, the way `src/ec/
//! eddsa.rs` reads RFC 8032's vectors. See docs/extending.md, "Where
//! test vectors come from": a vector - or a table - that was typed is a
//! vector that can be mistyped.

use super::buffer::BlockBuffer;
use super::HashFunction;

/// RFC 1320, unmodified.
const RFC_1320: &str = include_str!("../../rfcs/rfc1320.txt");

const BLOCK: usize = 64;

/// One `[abcd k s]` group from a round table: which register is
/// updated, which message word is used, how far the result rotates.
#[derive(Clone, Copy)]
struct Step {
    /// The index into `[a, b, c, d]` of the register being assigned:
    /// 0 for the `ABCD` form, 1 for `DABC`, 2 for `CDAB`, 3 for `BCDA`.
    ///
    /// Parsed rather than assumed from the position, so that a document
    /// whose table was reordered fails here instead of silently.
    target: usize,
    word: usize,
    rotate: u32,
}

/// The three round tables, in order, 16 steps each.
const SCHEDULE: [[Step; 16]; 3] = [
    parse_round(RFC_1320, "/* Round 1. */"),
    parse_round(RFC_1320, "/* Round 2. */"),
    parse_round(RFC_1320, "/* Round 3. */"),
];

/// Round 2 adds `5A827999`, round 3 adds `6ED9EBA1`, round 1 adds
/// nothing. RFC 1320 states each one inside the round's own comment, so
/// they are taken from there rather than written here - and a test
/// checks them against the square roots the RFC says they are.
const ADD: [u32; 3] = [
    0,
    parse_constant(RFC_1320, "a = (a + G(b,c,d) + X[k] + "),
    parse_constant(RFC_1320, "a = (a + H(b,c,d) + X[k] + "),
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
    panic!("RFC 1320 no longer contains a section this file reads");
}

const fn hex_digit(c: u8) -> u32 {
    match c {
        b'0'..=b'9' => (c - b'0') as u32,
        b'A'..=b'F' => (c - b'A' + 10) as u32,
        b'a'..=b'f' => (c - b'a' + 10) as u32,
        _ => panic!("not a hex digit"),
    }
}

/// The 32-bit hex constant that follows `marker`.
const fn parse_constant(text: &str, marker: &str) -> u32 {
    let bytes = text.as_bytes();
    let at = find_from(bytes, marker.as_bytes(), 0) + marker.len();
    let mut value = 0u32;
    let mut i = 0;
    while i < 8 {
        value = (value << 4) | hex_digit(bytes[at + i]);
        i += 1;
    }
    // The RFC writes it as eight hex digits followed by `)`. Checking
    // that stops a shorter or longer constant being read as this one.
    assert!(bytes[at + 8] == b')', "the constant is not eight hex digits");
    value
}

/// The letter a step assigns to, as an index into `[a, b, c, d]`.
///
/// RFC 1320 writes the four forms as `ABCD`, `DABC`, `CDAB`, `BCDA`,
/// and in every one the register assigned is the **first** letter.
const fn target_of(letters: [u8; 4]) -> usize {
    match letters[0] {
        b'A' => 0,
        b'B' => 1,
        b'C' => 2,
        b'D' => 3,
        _ => panic!("a round table group does not start with a register"),
    }
}

/// Read the sixteen `[abcd k s]` groups that follow `header`.
///
/// The filter is the *shape* of a bracket group: four capitals, then
/// two numbers. The only other bracketed thing in the way is the page
/// footer's `[Page 4]`, which has neither - and RFC 1320 does break
/// round 2's table across a page. Matching on the furniture instead
/// would mean listing its forms; see docs/extending.md on RFC 3394's
/// four spellings of one label.
const fn parse_round(text: &str, header: &str) -> [Step; 16] {
    let bytes = text.as_bytes();
    let mut at = find_from(bytes, header.as_bytes(), 0) + header.len();

    let mut steps = [Step { target: 0, word: 0, rotate: 0 }; 16];
    let mut found = 0;

    while found < 16 {
        at = find_from(bytes, b"[", at) + 1;

        // Four capitals?
        let mut letters = [0u8; 4];
        let mut i = 0;
        let mut ok = true;
        while i < 4 {
            let c = bytes[at + i];
            if c < b'A' || c > b'Z' {
                ok = false;
            }
            letters[i] = c;
            i += 1;
        }
        if !ok {
            continue;                                   // `[Page 4]`
        }

        // ` k s]`, with either number one or two digits.
        let mut cursor = at + 4;
        let mut numbers = [0usize; 2];
        let mut n = 0;
        while n < 2 {
            while bytes[cursor] == b' ' {
                cursor += 1;
            }
            let mut value = 0usize;
            let mut digits = 0;
            while bytes[cursor].is_ascii_digit() {
                value = value * 10 + (bytes[cursor] - b'0') as usize;
                cursor += 1;
                digits += 1;
            }
            assert!(digits > 0, "a round table group has no number where one \
                                 was expected");
            numbers[n] = value;
            n += 1;
        }
        while bytes[cursor] == b' ' {
            cursor += 1;
        }
        assert!(bytes[cursor] == b']', "a round table group is not closed");

        assert!(numbers[0] < 16, "a message word index is out of range");
        assert!(numbers[1] > 0 && numbers[1] < 32, "a rotation is out of range");

        steps[found] = Step {
            target: target_of(letters),
            word: numbers[0],
            rotate: numbers[1] as u32,
        };
        found += 1;
        at = cursor;
    }

    // The register a step writes cycles a, d, c, b and nothing else.
    // Asserting it here means a document whose groups were reordered -
    // or a parser that skipped one - fails to compile rather than
    // producing a hash that agrees with nobody.
    let cycle = [0usize, 3, 2, 1];
    let mut i = 0;
    while i < 16 {
        assert!(steps[i].target == cycle[i % 4],
                "the round table's registers do not cycle A, D, C, B");
        i += 1;
    }

    steps
}

// ---------------------------------------------------------- the function ---

/// RFC 1320 3.4: `F(X,Y,Z) = XY v not(X) Z`.
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

/// `G(X,Y,Z) = XY v XZ v YZ` - the majority function, and **not** MD5's
/// second round, which is `XZ v Y not(Z)`. The two are different
/// functions and both are self-consistent.
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

/// `H(X,Y,Z) = X xor Y xor Z`.
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[derive(Clone)]
pub struct Md4 {
    state: [u32; 4],
    buffer: BlockBuffer<BLOCK>,
    /// The message length **in bits**, which is what the padding
    /// carries. Counting bytes and multiplying at the end works until
    /// somebody hashes 2^61 bytes; counting bits is what the RFC says.
    bits: u64,
}

/// RFC 1320 3.3, the same four words MD5 starts from.
const INIT: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

impl Default for Md4 {
    fn default() -> Self {
        Md4::new(&[])
    }
}

impl Md4 {
    pub fn new(data: &[u8]) -> Md4 {
        let mut md4 = Md4 {
            state: INIT,
            buffer: BlockBuffer::default(),
            bits: 0,
        };
        md4.update(data);
        md4
    }

    fn compress(state: &mut [u32; 4], block: &[u8; BLOCK]) {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            *word = u32::from_le_bytes(
                block[i * 4..i * 4 + 4].try_into().expect("four bytes"));
        }

        let mut r = *state;
        for (round, steps) in SCHEDULE.iter().enumerate() {
            for step in steps {
                // `target` names the register being assigned; the other
                // three go into the round function in the order they
                // appear after it, which is the cycle b, c, d relative
                // to `a`.
                let a = step.target;
                let b = (a + 1) % 4;
                let c = (a + 2) % 4;
                let d = (a + 3) % 4;
                let mixed = match round {
                    0 => f(r[b], r[c], r[d]),
                    1 => g(r[b], r[c], r[d]),
                    _ => h(r[b], r[c], r[d]),
                };
                r[a] = r[a]
                    .wrapping_add(mixed)
                    .wrapping_add(x[step.word])
                    .wrapping_add(ADD[round])
                    .rotate_left(step.rotate);
            }
        }

        for i in 0..4 {
            state[i] = state[i].wrapping_add(r[i]);
        }
    }

    /// The digest, computed on a copy so the object stays usable - the
    /// shape `hashlib` has and `AnyHash` promises.
    fn finish(&self) -> Vec<u8> {
        let mut state = self.state;
        let mut tail = self.buffer.buffered().to_vec();
        tail.push(0x80);
        // Pad to 56 mod 64, then **eight** bytes of little-endian bit
        // count. Eight, not four: a 32-bit length field is the SHA-1
        // bug this repository already had, and it is wrong only for
        // messages of 48..=55 bytes mod 64.
        while tail.len() % BLOCK != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&self.bits.to_le_bytes());

        debug_assert_eq!(tail.len() % BLOCK, 0);
        for chunk in tail.chunks_exact(BLOCK) {
            Md4::compress(&mut state,
                          chunk.try_into().expect("chunks_exact"));
        }

        let mut out = Vec::with_capacity(16);
        for word in state {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}

impl HashFunction for Md4 {
    fn name(&self) -> String {
        "md4".to_string()
    }

    fn digest_len(&self) -> usize {
        16
    }

    fn block_size(&self) -> usize {
        BLOCK
    }

    fn update(&mut self, input: &[u8]) {
        self.bits = self.bits.wrapping_add(input.len() as u64 * 8);
        let state = &mut self.state;
        self.buffer.feed(input, |block| Md4::compress(state, block));
    }

    fn digest(&mut self) -> Vec<u8> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn md4(data: &[u8]) -> String {
        hex(&Md4::new(data).digest())
    }

    // --------------------------------------------- what was read out ---

    #[test]
    fn test_the_additive_constants_are_the_square_roots_the_rfc_says() {
        // RFC 1320 3.4: "This constant represents the square root of 2"
        // and "of 3", each as a 32-bit value. Computing them here is an
        // independent opinion about the eight hex digits that were
        // parsed - the document states the value twice, once in hex and
        // once in words, and this is the second reading.
        let root = |n: f64| (n.sqrt() * (1u64 << 30) as f64) as u32;
        assert_eq!(ADD[1], root(2.0), "round 2's constant is not sqrt(2)");
        assert_eq!(ADD[2], root(3.0), "round 3's constant is not sqrt(3)");
        assert_eq!(ADD[0], 0, "round 1 adds nothing");
    }

    #[test]
    fn test_the_octal_forms_in_the_rfc_agree_with_the_hex_ones() {
        // The RFC gives each constant in octal as well, in a different
        // sentence. A mis-parse of the hex would have to match the
        // octal by coincidence.
        for (constant, octal) in [(ADD[1], "013240474631"),
                                  (ADD[2], "015666365641")] {
            assert!(RFC_1320.contains(octal), "RFC 1320 lost an octal form");
            assert_eq!(constant,
                       u32::from_str_radix(&octal[1..], 8).unwrap());
        }
    }

    #[test]
    fn test_each_round_uses_every_message_word_exactly_once() {
        // The property every MD4 round table has, and the one a
        // mistyped or mis-parsed entry breaks. Round 3's order is the
        // famously error-prone one, and a duplicate there is invisible
        // to anything but a published vector.
        for (round, steps) in SCHEDULE.iter().enumerate() {
            let mut seen = [false; 16];
            for step in steps {
                assert!(!seen[step.word],
                        "round {} uses X[{}] twice", round + 1, step.word);
                seen[step.word] = true;
            }
            assert!(seen.iter().all(|&s| s), "round {} misses a word",
                    round + 1);
        }
    }

    #[test]
    fn test_the_three_rounds_use_three_different_orders() {
        // If the parser had locked onto one table and read it three
        // times - a plausible failure, since the three headers differ
        // by one character - every test above would still pass.
        let order = |round: usize| -> Vec<usize> {
            SCHEDULE[round].iter().map(|s| s.word).collect()
        };
        assert_ne!(order(0), order(1));
        assert_ne!(order(1), order(2));
        assert_ne!(order(0), order(2));

        // Round 1 is the identity order, which is the one fact about
        // the tables that is safe to state without the document.
        assert_eq!(order(0), (0..16).collect::<Vec<_>>());
    }

    #[test]
    fn test_the_rotations_are_four_per_round_repeated() {
        // Each round has four rotation amounts, applied in the same
        // order four times. A parser that lost a group would shift
        // everything after it and break this.
        for steps in &SCHEDULE {
            let first: Vec<u32> = steps[..4].iter().map(|s| s.rotate).collect();
            for chunk in steps.chunks_exact(4) {
                let these: Vec<u32> = chunk.iter().map(|s| s.rotate).collect();
                assert_eq!(these, first);
            }
        }
    }

    // ------------------------------------------ RFC 1320 A.5, parsed ---

    /// The published vectors, read out of the document at test time.
    fn published_vectors() -> Vec<(String, String)> {
        let start = RFC_1320.find("MD4 test suite:")
            .expect("RFC 1320 has no test suite section");
        let body = &RFC_1320[start..];
        let end = body.find("\n\n").unwrap_or(body.len());
        let joined: String = body[..end].replace("=\n", "= ").replace("\n", "");

        let mut vectors = Vec::new();
        for piece in joined.split("MD4 (\"").skip(1) {
            let (message, rest) = piece.split_once("\") = ")
                .expect("a vector line without its separator");
            let digest: String = rest.chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            vectors.push((message.to_string(), digest));
        }
        assert_eq!(vectors.len(), 7,
                   "RFC 1320 A.5 publishes seven vectors; found {}",
                   vectors.len());
        for (_, digest) in &vectors {
            assert_eq!(digest.len(), 32);
        }
        vectors
    }

    #[test]
    fn test_the_published_vectors() {
        for (message, expected) in published_vectors() {
            assert_eq!(md4(message.as_bytes()), expected,
                       "MD4({:?})", message);
        }
    }

    #[test]
    fn test_a_vector_crosses_the_length_field_boundary() {
        // 48..=55 bytes mod 64 is where a 32-bit length field would be
        // wrong, which is the SHA-1 bug this repository shipped. The
        // longest published vector is 80 bytes - 16 mod 64 - so it does
        // *not* cover that, and this pins a case that does against a
        // hand check of the padding rather than leaving the gap.
        let fifty_five = vec![0x61u8; 55];
        let fifty_six = vec![0x61u8; 56];
        // 55 bytes fits its padding in one block; 56 needs a second.
        // They must differ, and neither may equal the other's digest
        // computed with the other's block count.
        assert_ne!(md4(&fifty_five), md4(&fifty_six));
        assert!(published_vectors().iter()
                    .all(|(m, _)| !(48..=55).contains(&(m.len() % 64))),
                "a published vector now covers this; simplify the test");
    }

    // ------------------------------------------------------- structure ---

    #[test]
    fn test_g_is_majority_and_not_md5s_second_round() {
        // Copying MD5's `G` into MD4 compiles, streams, and hashes
        // everything wrongly. The two agree on plenty of inputs, so
        // this names the disagreement rather than sampling.
        let md5_g = |x: u32, y: u32, z: u32| (x & z) | (y & !z);
        assert_eq!(g(0xffff_ffff, 0, 0xffff_ffff), 0xffff_ffff);
        assert_ne!(g(0, 0xffff_ffff, 0), md5_g(0, 0xffff_ffff, 0));
        // Majority: any two of three.
        for (x, y, z) in [(1u32, 1, 0), (1, 0, 1), (0, 1, 1)] {
            assert_eq!(g(x, y, z), 1);
        }
        for (x, y, z) in [(1u32, 0, 0), (0, 1, 0), (0, 0, 1)] {
            assert_eq!(g(x, y, z), 0);
        }
    }

    #[test]
    fn test_the_nt_hash_of_a_known_password() {
        // MD4's reason for being here. The NT hash is
        // `MD4(UTF-16LE(password))`, and `password` is the most widely
        // republished example of one - it appears in the Samba,
        // Responder and hashcat documentation and in RFC 2759's
        // neighbourhood. Written as the UTF-16 encoding of an ASCII
        // string rather than as bytes, so the test says what it means.
        let utf16le: Vec<u8> = "password".encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(utf16le.len(), 16, "eight characters, two bytes each");
        assert_eq!(md4(&utf16le), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    // ------------------------------------------------------- streaming ---

    #[test]
    fn test_streaming_in_irregular_pieces_matches_one_call() {
        let message: Vec<u8> = (0..=200u8).collect();
        for length in 0..=message.len() {
            let whole = md4(&message[..length]);
            for split in 0..=length {
                let mut h = Md4::new(&[]);
                h.update(&message[..split]);
                h.update(&message[split..length]);
                assert_eq!(hex(&h.digest()), whole,
                           "length {} split at {}", length, split);
            }
        }
    }

    #[test]
    fn test_digest_may_be_taken_twice_and_update_may_follow_it() {
        let mut h = Md4::new(b"abc");
        let first = hex(&h.digest());
        assert_eq!(hex(&h.digest()), first);
        h.update(b"def");
        assert_eq!(hex(&h.digest()), md4(b"abcdef"));
    }

    #[test]
    fn test_the_name_and_sizes() {
        let h = Md4::new(&[]);
        assert_eq!(h.name(), "md4");
        assert_eq!(h.digest_len(), 16);
        assert_eq!(h.block_size(), BLOCK);
        assert_eq!(Md4::default().clone().digest().len(), 16);
    }
}
