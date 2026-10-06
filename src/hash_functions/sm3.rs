/*
SM3, the Chinese national cryptographic hash.

GB/T 32905-2016, published by the State Cryptography Administration and
standardised internationally as ISO/IEC 10118-3:2018. 256 bit output,
512 bit blocks, big endian throughout, and the same Merkle-Damgard
padding as SHA-256 - a `0x80`, zeros, and a 64 bit big endian bit count.

Here because it is mandatory in China. A device certified for use there
speaks SM2/SM3/SM4 and often nothing else, and TLS 1.3's two SM suites
(RFC 8998) name SM3 as both the handshake hash and the HMAC. It is also
the hash SM2 is defined against: every signature, every key exchange and
every public key encryption in GB/T 32918 goes through this function, so
`src/ec/sm2.rs` cannot exist without it.

## It is not SHA-256 with different constants

The padding is the same and the block size is the same, and there the
resemblance stops. The differences that produce a wrong answer silently:

  * **Two words are consumed per round, not one.** The expansion makes
    68 words `W` and then 64 more `W'[j] = W[j] ^ W[j+4]`, and the round
    uses `W'[j]` in one half and `W[j]` in the other. An implementation
    that feeds `W[j]` to both is a perfectly good hash function that
    matches nothing.
  * **The state is updated by XOR, not by addition.** SHA-2 adds the
    compression output into the chaining value; SM3 XORs it. Both
    avalanche, and only a vector can tell them apart.
  * **The round constant is rotated by the round number**, `T_j <<<
    (j mod 32)`. The `mod 32` is in the standard and matters for the
    second half of the rounds. Rust's `rotate_left` masks its argument
    so writing it without the modulus happens to work here - it is
    written out anyway, because the next language will not.
  * **Two different boolean functions change shape at round 16**, and
    they do not change to the same thing: `FF` becomes the majority
    function and `GG` becomes the choice function.

## The permutations

    P0(X) = X ^ (X <<< 9)  ^ (X <<< 17)      -- used on the state word E
    P1(X) = X ^ (X <<< 15) ^ (X <<< 23)      -- used in the expansion

Swapping them gives a hash that is self-consistent, and it is the single
easiest mistake to make in this algorithm because the two lines look
alike. `test_the_two_permutations_are_not_interchangeable` pins them
apart directly, because no round-trip or streaming test can see it.
*/

use crate::hash_functions::HashFunction;

/// GB/T 32905-2016 section 4.1. Not SHA-256's initial values.
const IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

/// The two round constants. `T_j` for the first sixteen rounds and for
/// the remaining forty-eight; there is no third value.
const T0: u32 = 0x79cc4519;
const T1: u32 = 0x7a879d8a;

/// `P_0`, applied to the round's second temporary. GB/T 32905-2016 4.3.
#[inline]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

/// `P_1`, applied inside the message expansion. Different rotations from
/// `p0` and not interchangeable with it.
#[inline]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// `FF_j`: XOR for the first sixteen rounds, majority thereafter.
#[inline]
fn ff(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

/// `GG_j`: XOR for the first sixteen rounds, choice thereafter. The
/// second form differs from `ff`'s, which is why they are two functions.
#[inline]
fn gg(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

#[derive(Clone)]
pub struct Sm3 {
    h: [u32; 8],
    buffer: Vec<u8>,
    length: u64,
}

impl Default for Sm3 {
    fn default() -> Self {
        Sm3::new(&[])
    }
}

impl Sm3 {
    pub fn new(input: &[u8]) -> Sm3 {
        let mut hash = Sm3 { h: IV, buffer: Vec::with_capacity(64), length: 0 };
        hash.update(input);
        hash
    }

    /// The expansion, GB/T 32905-2016 5.3.2. Returns `W` (68 words) and
    /// `W'` (64 words); both are needed and they are not the same array.
    fn expand(block: &[u8]) -> ([u32; 68], [u32; 64]) {
        let mut w = [0u32; 68];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for j in 16..68 {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
                ^ w[j - 13].rotate_left(7)
                ^ w[j - 6];
        }
        let mut wp = [0u32; 64];
        for (j, word) in wp.iter_mut().enumerate() {
            *word = w[j] ^ w[j + 4];
        }
        (w, wp)
    }

    /// The compression function, GB/T 32905-2016 5.3.3.
    fn compress(&mut self, block: &[u8]) {
        let (w, wp) = Sm3::expand(block);

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut hh = self.h[7];

        for j in 0..64 {
            let t = if j < 16 { T0 } else { T1 };
            // The rotation is by the round number modulo the word size.
            let ss1 = a
                .rotate_left(12)
                .wrapping_add(e)
                .wrapping_add(t.rotate_left((j % 32) as u32))
                .rotate_left(7);
            let ss2 = ss1 ^ a.rotate_left(12);
            // `wp` here and `w` below: the two halves take different
            // words, and swapping them is silent.
            let tt1 = ff(j, a, b, c).wrapping_add(d).wrapping_add(ss2).wrapping_add(wp[j]);
            let tt2 = gg(j, e, f, g).wrapping_add(hh).wrapping_add(ss1).wrapping_add(w[j]);
            d = c;
            c = b.rotate_left(9);
            b = a;
            a = tt1;
            hh = g;
            g = f.rotate_left(19);
            f = e;
            e = p0(tt2);
        }

        // XOR into the chaining value. SHA-2 adds here; this does not.
        self.h[0] ^= a;
        self.h[1] ^= b;
        self.h[2] ^= c;
        self.h[3] ^= d;
        self.h[4] ^= e;
        self.h[5] ^= f;
        self.h[6] ^= g;
        self.h[7] ^= hh;
    }
}

impl HashFunction for Sm3 {
    fn name(&self) -> String {
        "sm3".to_string()
    }

    fn digest_len(&self) -> usize {
        32
    }

    fn block_size(&self) -> usize {
        64
    }

    fn update(&mut self, input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        let mut input = input;
        while !input.is_empty() {
            let take = core::cmp::min(64 - self.buffer.len(), input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.buffer.len() == 64 {
                let block = core::mem::take(&mut self.buffer);
                self.compress(&block);
                self.buffer = block;
                self.buffer.clear();
            }
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        // Finalised on a copy, so this is repeatable and `update` may
        // continue afterwards - the same rule the rest of this module
        // follows.
        let mut final_state = self.clone();

        let bits = final_state.length.wrapping_mul(8);
        final_state.update(&[0x80]);
        while final_state.buffer.len() != 56 {
            final_state.update(&[0]);
        }
        final_state.update(&bits.to_be_bytes());

        let mut out = Vec::with_capacity(32);
        for word in final_state.h {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The draft is vendored whole; nothing here is transcribed. See
    /// `rfcs/README.md` and docs/extending.md, "Where test vectors come
    /// from", for why.
    const DRAFT: &str = include_str!("../../rfcs/draft-sca-cfrg-sm3-02.txt");

    fn digest_of(input: &[u8]) -> Vec<u8> {
        let mut hash = Sm3::new(input);
        hash.digest()
    }

    fn unhex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        assert!(cleaned.len().is_multiple_of(2), "odd number of hex digits in {text:?}");
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    /// True for a line that is nothing but hex and spaces. The document
    /// indents its data blocks by one space and its prose by three,
    /// which is the only structural difference between them; the page
    /// headers and footers sit at column zero.
    ///
    /// **A data line can be two hex digits long.** The GB/T 32918.2 A.3
    /// examples are over a 257 bit binary field, so each element is 33
    /// bytes and the document writes the leading byte on a line of its
    /// own - a bare ` 00` or ` 01`. A minimum length written to exclude
    /// page numbers dropped all eleven of them, which changed the input
    /// to four examples without changing their shape.
    fn hex_line(line: &str) -> bool {
        if !line.starts_with(' ') || line.starts_with("   ") {
            return false;
        }
        let trimmed = line.trim();
        let digits = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).count();
        !trimmed.is_empty()
            && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == ' ')
            && digits >= 2
            && digits.is_multiple_of(2)
    }

    /// Appendix B is eighteen `Input:` / `Output:` pairs, each a run of
    /// hex lines. The inputs are byte strings to be hashed and the
    /// outputs are the 32 byte results.
    /// Find a heading at the start of a line. The table of contents
    /// lists every appendix by the same words, indented by three
    /// spaces, and `str::find` reaches that copy first - which parsed
    /// to nothing, passed `test_appendix_b_examples` vacuously, and was
    /// caught only by the count assertion below.
    fn heading(needle: &str) -> usize {
        let at = DRAFT.find(&format!("\n{needle}")).unwrap_or_else(|| panic!("no heading {needle}"));
        at + 1
    }

    fn appendix_b() -> Vec<(Vec<u8>, Vec<u8>)> {
        let start = heading("Appendix B.  Example Results");
        let end = heading("Appendix C.");
        let body = &DRAFT[start..end];

        let mut vectors = Vec::new();
        let mut collecting: Option<&str> = None;
        let mut input = String::new();
        let mut output = String::new();

        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed == "Input:" {
                // A new Input ends any pair that was being collected,
                // which cannot happen in a well-formed document and is
                // an error rather than something to paper over.
                assert!(output.is_empty(), "an Input followed an Output with no vector emitted");
                collecting = Some("input");
                input.clear();
                continue;
            }
            if trimmed == "Output:" {
                collecting = Some("output");
                output.clear();
                continue;
            }
            if hex_line(line) {
                match collecting {
                    Some("input") => input.push_str(trimmed),
                    Some("output") => output.push_str(trimmed),
                    _ => {}
                }
                continue;
            }
            // Any other non-blank line - prose, a page break, a section
            // heading - closes an output that is in progress.
            if !trimmed.is_empty() && collecting == Some("output") && !output.is_empty() {
                vectors.push((unhex(&input), unhex(&output)));
                input.clear();
                output.clear();
                collecting = None;
            }
        }
        if !output.is_empty() {
            vectors.push((unhex(&input), unhex(&output)));
        }
        vectors
    }

    /// A parser that finds nothing turns every loop below into a pass.
    /// Eighteen is the count in the document.
    #[test]
    fn test_the_draft_parses_to_the_expected_number_of_vectors() {
        let vectors = appendix_b();
        assert_eq!(vectors.len(), 18, "appendix B should hold eighteen examples");
        for (input, output) in &vectors {
            assert!(!input.is_empty(), "an example parsed with an empty input");
            assert_eq!(output.len(), 32, "an SM3 output must be 32 bytes");
        }
    }

    #[test]
    fn test_appendix_b_examples() {
        for (index, (input, expected)) in appendix_b().iter().enumerate() {
            assert_eq!(
                &digest_of(input),
                expected,
                "appendix B example {} ({} input bytes)",
                index + 1,
                input.len()
            );
        }
    }

    /// Appendix A works the two examples of GB/T 32905-2016 itself
    /// through, and states the input and the hash for each. They are the
    /// standard's own vectors rather than the SM2 documents'.
    fn appendix_a() -> Vec<(Vec<u8>, Vec<u8>)> {
        let start = heading("Appendix A.  Example Calculations");
        let end = heading("Appendix B.  Example Results");
        let body = &DRAFT[start..end];

        // A.1's input is stated in prose ("616263"); A.2's is a hex
        // block. Both hash values sit under a "Hash Value" heading.
        let mut hashes = Vec::new();
        let mut want_hash = false;
        for line in body.lines() {
            if line.trim_start().starts_with("A.1.5.") || line.trim_start().starts_with("A.2.3.") {
                want_hash = true;
                continue;
            }
            if want_hash && hex_line(line) {
                hashes.push(unhex(line));
                want_hash = false;
            }
        }

        let abc = b"abc".to_vec();
        let long = b"abcd".repeat(16);
        vec![(abc, hashes[0].clone()), (long, hashes[1].clone())]
    }

    #[test]
    fn test_appendix_a_examples() {
        let vectors = appendix_a();
        assert_eq!(vectors.len(), 2, "appendix A states two hash values");
        for (input, expected) in &vectors {
            assert_eq!(expected.len(), 32);
            assert_eq!(&digest_of(input), expected, "appendix A, {} input bytes", input.len());
        }
        // The second is exactly one byte over a block, so it exercises
        // the two-block path and the padding block of its own.
        assert_eq!(vectors[1].0.len(), 64);
    }

    /// `P_0` and `P_1` look alike and are the easiest thing here to
    /// swap. No functional test can see it - a hash built with them
    /// exchanged is still a hash - so they are compared directly.
    #[test]
    fn test_the_two_permutations_are_not_interchangeable() {
        for x in [1u32, 0x8000_0000, 0x0123_4567, 0xdead_beef] {
            assert_ne!(p0(x), p1(x), "p0 and p1 agreed on {x:#x}");
        }
        let agreeing = (0..10_000u32).filter(|&x| p0(x) == p1(x)).count();
        assert!(agreeing < 100, "p0 and p1 agreed on {agreeing} of the first 10000 inputs");

        // **Each is the identity on the all-zero and all-one words**,
        // and so are equal there. Both are an XOR of the word with two
        // rotations of itself - three terms, an odd number - and a word
        // whose bits are all the same is fixed by every rotation. A
        // test picking either as a witness proves nothing, which is how
        // this one was written the first time.
        assert_eq!(p0(0), 0);
        assert_eq!(p1(0), 0);
        assert_eq!(p0(u32::MAX), u32::MAX);
        assert_eq!(p1(u32::MAX), u32::MAX);
    }

    /// `FF` and `GG` diverge at round 16 and do not become the same
    /// function. Asserted because the two lines differ by one operator.
    #[test]
    fn test_the_boolean_functions_differ_after_round_fifteen() {
        assert_eq!(ff(15, 0xf0, 0xcc, 0xaa), gg(15, 0xf0, 0xcc, 0xaa));
        assert_ne!(ff(16, 0xf0, 0xcc, 0xaa), gg(16, 0xf0, 0xcc, 0xaa));
    }

    /// The expansion produces two arrays and the round uses one in each
    /// half. A test that they are not equal, because feeding `w` to both
    /// halves is the mistake and it is silent.
    #[test]
    fn test_the_expansion_produces_two_different_arrays() {
        let block: Vec<u8> = (0..64u8).collect();
        let (w, wp) = Sm3::expand(&block);
        assert_eq!(w.len(), 68);
        assert_eq!(wp.len(), 64);
        let same = (0..64).filter(|&j| w[j] == wp[j]).count();
        assert!(same < 8, "w and w' agreed in {same} of 64 positions");
    }

    /// Streaming in irregular pieces must equal a single call. This is
    /// the shape of bug that cost this repository two algorithms - see
    /// the testing checklist in docs/extending.md.
    #[test]
    fn test_streaming_in_pieces_equals_one_call() {
        let message: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        let whole = digest_of(&message);
        for chunk in [1usize, 3, 7, 31, 63, 64, 65, 127, 128, 200] {
            let mut hash = Sm3::new(&[]);
            for piece in message.chunks(chunk) {
                hash.update(piece);
            }
            assert_eq!(hash.digest(), whole, "chunked by {chunk}");
        }
    }

    /// `digest` finalises a copy, so calling it twice must give the same
    /// answer and `update` must still work afterwards.
    #[test]
    fn test_digest_does_not_consume_the_state() {
        let mut hash = Sm3::new(b"abc");
        let first = hash.digest();
        let second = hash.digest();
        assert_eq!(first, second);
        hash.update(b"d");
        assert_eq!(hash.digest(), digest_of(b"abcd"));
        assert_ne!(hash.digest(), first);
    }

    /// Every length from nothing to two full blocks, so the padding
    /// boundary at 55/56 and 119/120 bytes is crossed rather than
    /// hoped over. The reference is the appendix above; here the point
    /// is only that no length panics and every answer is 32 bytes.
    #[test]
    fn test_every_length_across_the_padding_boundaries() {
        let mut seen = std::collections::HashSet::new();
        for len in 0..=130usize {
            let message = vec![0x61u8; len];
            let out = digest_of(&message);
            assert_eq!(out.len(), 32, "length {len}");
            assert!(seen.insert(out), "two lengths hashed the same, at {len}");
        }
    }

    #[test]
    fn test_the_name_and_lengths_are_what_hmac_will_ask_for() {
        let hash = Sm3::new(&[]);
        assert_eq!(hash.name(), "sm3");
        assert_eq!(hash.digest_len(), 32);
        assert_eq!(hash.block_size(), 64);
    }
}
