//! MD2, RFC 1319.
//!
//! Ronald Rivest, 1989, designed for 8-bit machines - which is why it
//! works on bytes throughout and has no 32-bit words anywhere. It is
//! thoroughly broken: preimages at 2^73 (Knudsen et al.) and collisions
//! are known, and RFC 6149 moved it to Historic in 2011.
//!
//! It is here because **old root certificates are signed with
//! `md2WithRSAEncryption`**. Several of the CAs that anchored the early
//! web used it, and a relying party that cannot compute MD2 cannot
//! verify those signatures - which is the whole shape of this project:
//! the choice to stop using an algorithm belongs to whoever runs the
//! server, and we are the client.
//!
//! ## Three things about it that are easy to get wrong
//!
//! **The padding is never empty.** MD2 always appends 1..=16 bytes,
//! each holding the number of bytes appended. A message that is already
//! a whole number of blocks gets sixteen bytes of `0x10`, exactly as
//! PKCS#7 does - and for the same reason, which is that the padding has
//! to be removable in principle.
//!
//! **A 16-byte checksum is appended after the padding and is part of
//! the hashed message.** So the compression function runs over
//! `padded || checksum`, and the checksum is computed over the *padded*
//! message rather than the original.
//!
//! **The RFC's prose and the RFC's own reference code disagree**, and
//! the code is what the world implements. See `CHECKSUM_DISAGREEMENT`
//! below - a test pins both readings and asserts they differ, so this
//! file cannot quietly become the other one.

use super::buffer::BlockBuffer;
use super::HashFunction;

/// RFC 1319, unmodified, so the permutation below is read out of the
/// document rather than typed. This repository has been bitten twice by
/// transcribed constants; see docs/extending.md, "Where test vectors come
/// from".
const RFC_1319: &str = include_str!("../../rfcs/rfc1319.txt");

/// The 256-byte permutation "constructed from the digits of pi",
/// extracted from RFC 1319's appendix at compile time.
///
/// Parsing it rather than pasting it is the rule this repository
/// settled on after GOST, and it pays here too: the table is split
/// across a page break in the middle, with a running header and a
/// `[Page 7]` footer between two of its rows. A transcription would
/// have had to notice and drop those by hand, which is exactly the kind
/// of edit that loses a row without saying so.
pub const PI: [u8; 256] = parse_pi(RFC_1319);

/// The offset of `needle` in `haystack`, or a compile-time panic.
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
    panic!("RFC 1319 does not contain the PI_SUBST table any more");
}

/// True when a line holds table data rather than page furniture.
///
/// The discriminator is *what characters are in it*: a row of the table
/// is digits, commas and spaces and nothing else, while every piece of
/// furniture in the way - `Kaliski [Page 7]`, the running header, the
/// form feed - carries a letter or a bracket. Matching on the furniture
/// instead would mean listing its forms, and a form not listed is a row
/// of numbers silently joined to the table. RFC 3394's four spellings
/// of one label are the cautionary tale; see docs/extending.md, "Where
/// test vectors come from".
const fn is_table_row(line: &[u8]) -> bool {
    let mut i = 0;
    let mut digits = 0;
    while i < line.len() {
        let c = line[i];
        if c.is_ascii_digit() {
            digits += 1;
        } else if c != b',' && c != b' ' && c != b'\r' {
            return false;
        }
        i += 1;
    }
    digits > 0
}

const fn parse_pi(text: &str) -> [u8; 256] {
    let bytes = text.as_bytes();
    // Start just past the declaration, so the `256` in `PI_SUBST[256]`
    // is not the first number found.
    let mut at = find(bytes, b"static unsigned char PI_SUBST[256] = {")
        + "static unsigned char PI_SUBST[256] = {".len();

    let mut table = [0u8; 256];
    let mut found = 0;

    loop {
        // One line at a time, because the decision about furniture is a
        // decision about a whole line.
        let start = at;
        while at < bytes.len() && bytes[at] != b'\n' {
            at += 1;
        }
        let line = split(bytes, start, at);
        if at < bytes.len() {
            at += 1;
        }

        // `};` closes the table. It is reached only after the rows,
        // because the declaration itself was skipped above.
        let mut i = 0;
        let mut closes = false;
        while i < line.len() {
            if line[i] == b'}' {
                closes = true;
            }
            i += 1;
        }
        if closes {
            break;
        }

        if is_table_row(line) {
            let mut i = 0;
            while i < line.len() {
                if line[i].is_ascii_digit() {
                    let mut value = 0usize;
                    while i < line.len() && line[i].is_ascii_digit() {
                        value = value * 10 + (line[i] - b'0') as usize;
                        i += 1;
                    }
                    assert!(value < 256, "a PI_SUBST entry is not a byte");
                    assert!(found < 256, "RFC 1319's PI_SUBST has grown");
                    table[found] = value as u8;
                    found += 1;
                } else {
                    i += 1;
                }
            }
        }

        assert!(at < bytes.len(), "RFC 1319's PI_SUBST table is not closed");
    }

    // **The assertion that makes the parser worth having.** A parser
    // that finds nothing turns every vector test into an empty loop that
    // passes; this one refuses to compile instead. Three documents in
    // this repository have been mis-parsed in exactly that way.
    assert!(found == 256, "PI_SUBST did not yield 256 entries");
    table
}

/// `&haystack[start..end]`, which is not available in a `const fn`.
const fn split(bytes: &[u8], start: usize, end: usize) -> &[u8] {
    let (_, rest) = bytes.split_at(start);
    let (line, _) = rest.split_at(end - start);
    line
}

/// RFC 1319 section 3.2 writes the checksum step as
///
/// ```text
/// Set C[j] to S[c xor L].
/// ```
///
/// and its own reference implementation in the appendix writes
///
/// ```text
/// t = checksum[i] ^= PI_SUBST[block[i] ^ t];
/// ```
///
/// which is `C[j] ^= S[c xor L]`. They are different functions, and the
/// document's test vectors match the **code**. So does every
/// implementation in the world, which is what matters for a hash whose
/// only job here is to agree with certificates somebody else signed.
///
/// RFC 6149 records the discrepancy. This constant exists so that the
/// choice is greppable and so that
/// `test_the_two_readings_of_the_checksum_disagree` has something to
/// name: a test asserting only that our answer matches the vectors
/// would pass without anybody noticing there were two candidates.
pub const CHECKSUM_DISAGREEMENT: &str =
    "RFC 1319 3.2 assigns where its reference code XOR-assigns; \
     the vectors follow the code";

const BLOCK: usize = 16;

#[derive(Clone)]
pub struct Md2 {
    /// RFC 1319's `X`: the first sixteen bytes are the digest so far,
    /// the rest is scratch that the compression function rebuilds.
    state: [u8; 48],
    checksum: [u8; BLOCK],
    buffer: BlockBuffer<BLOCK>,
}

impl Default for Md2 {
    fn default() -> Self {
        Md2::new(&[])
    }
}

impl Md2 {
    pub fn new(data: &[u8]) -> Md2 {
        let mut md2 = Md2 {
            state: [0; 48],
            checksum: [0; BLOCK],
            buffer: BlockBuffer::default(),
        };
        md2.update(data);
        md2
    }

    /// RFC 1319 3.4, over one 16-byte block, plus 3.2's checksum step
    /// for the same block.
    ///
    /// The two are separate passes in the document and one function
    /// here because they consume the same block and nothing else ever
    /// calls either alone. `checksum` is *not* updated for the checksum
    /// block itself, which is why `finish` calls `compress_only`.
    fn compress_block(state: &mut [u8; 48], checksum: &mut [u8; BLOCK],
                      block: &[u8; BLOCK]) {
        Md2::compress_only(state, block);

        // RFC 1319's reference code carries `t` in from the previous
        // block through `checksum[15]`, which is zero before the first
        // block. Written as a field it would be a second copy of a
        // value the checksum already holds.
        let mut t = checksum[BLOCK - 1];
        for i in 0..BLOCK {
            checksum[i] ^= PI[(block[i] ^ t) as usize];
            t = checksum[i];
        }
    }

    /// The 18-round compression function alone, without the checksum.
    fn compress_only(state: &mut [u8; 48], block: &[u8; BLOCK]) {
        for i in 0..BLOCK {
            state[16 + i] = block[i];
            state[32 + i] = block[i] ^ state[i];
        }
        let mut t = 0u8;
        for round in 0..18u8 {
            for byte in state.iter_mut() {
                *byte ^= PI[t as usize];
                t = *byte;
            }
            t = t.wrapping_add(round);
        }
    }

    /// Padding, the checksum block, and the digest - on a copy, so that
    /// `digest()` can be called more than once and `update` can follow
    /// it, which is what `hashlib` objects do.
    fn finish(&self) -> Vec<u8> {
        let mut ended = self.clone();

        // **Always between 1 and 16 bytes.** An already-aligned message
        // gets a whole extra block of `0x10`, which is the same rule
        // PKCS#7 follows and the same surprise.
        let pad = BLOCK - ended.buffer.len();
        let padding = [pad as u8; BLOCK];
        ended.update(&padding[..pad]);
        debug_assert!(ended.buffer.is_empty(),
                      "padding must leave nothing buffered");

        // The checksum goes through the compression function but does
        // not feed the checksum again - `compress`, not `compress_only`,
        // would fold it into a value nobody reads and cost nothing
        // visible, which is why this is spelled out rather than left to
        // the reader.
        let checksum = ended.checksum;
        Md2::compress_only(&mut ended.state, &checksum);

        ended.state[..BLOCK].to_vec()
    }
}

impl HashFunction for Md2 {
    fn name(&self) -> String {
        "md2".to_string()
    }

    fn digest_len(&self) -> usize {
        16
    }

    /// MD2 has no HMAC block size of its own in any standard; sixteen
    /// is its compression function's input, which is what HMAC wants.
    fn block_size(&self) -> usize {
        BLOCK
    }

    fn update(&mut self, input: &[u8]) {
        // The buffering - and the early return that MD2's own first
        // version got wrong - lives in `BlockBuffer`, once, for every
        // hash here. The fields are destructured so the closure can
        // borrow the state while the buffer borrows itself.
        let Md2 { state, checksum, buffer } = self;
        buffer.feed(input, |block| Md2::compress_block(state, checksum, block));
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

    fn md2(data: &[u8]) -> String {
        hex(&Md2::new(data).digest())
    }

    // ------------------------------------------------ the parsed table ---

    #[test]
    fn test_the_table_is_a_permutation_of_every_byte() {
        // The check that catches a mis-parse, and the one the RFC's own
        // words invite: "Permutation of 0..255 constructed from the
        // digits of pi". A parser that dropped a row and picked up a
        // page number would still produce 256 entries - it would not
        // produce each byte exactly once.
        let mut seen = [false; 256];
        for value in PI {
            assert!(!seen[value as usize],
                    "{} appears twice, so the table was mis-parsed", value);
            seen[value as usize] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn test_the_table_did_not_pick_up_the_page_furniture() {
        // The specific failure the line filter exists for. RFC 1319
        // breaks the table across pages, and the running header holds
        // `1319` and `1992` while the footer holds a page number. None
        // of those is a byte, so a parser that read them would have
        // failed the permutation test too - but this one says *which*
        // mistake was made, and it fails at the boundary rather than
        // somewhere in the middle.
        assert_eq!(PI[14], 6, "the last entry before the page break");
        assert_eq!(PI[15], 19, "the first entry after it");
    }

    // ------------------------------------------- RFC 1319 A.5, parsed ---

    /// The published vectors, read out of the document at test time.
    ///
    /// Section A.5 writes them as `MD2 ("...") = <hex>`, and wraps the
    /// long ones onto a second line - both the quoted string and the
    /// digest. So the parser joins continuations before splitting, and
    /// asserts the count, because a parser that finds nothing turns the
    /// loop below into a pass.
    fn published_vectors() -> Vec<(String, String)> {
        let start = RFC_1319.find("MD2 test suite:")
            .expect("RFC 1319 has no test suite section");
        let body = &RFC_1319[start..];
        let end = body.find("\n\n").unwrap_or(body.len());
        let joined: String = body[..end].replace("=\n", "= ").replace("\n", "");

        let mut vectors = Vec::new();
        for piece in joined.split("MD2 (\"").skip(1) {
            let (message, rest) = piece.split_once("\") = ")
                .expect("a vector line without its separator");
            let digest: String = rest.chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            vectors.push((message.to_string(), digest));
        }
        assert_eq!(vectors.len(), 7,
                   "RFC 1319 A.5 publishes seven vectors; found {}",
                   vectors.len());
        for (_, digest) in &vectors {
            assert_eq!(digest.len(), 32, "a digest came out the wrong length");
        }
        vectors
    }

    #[test]
    fn test_the_published_vectors() {
        for (message, expected) in published_vectors() {
            assert_eq!(md2(message.as_bytes()), expected,
                       "MD2({:?})", message);
        }
    }

    #[test]
    fn test_the_longest_published_vector_spans_several_blocks() {
        // A.5's vectors are mostly short, and a one-block message
        // exercises neither the block loop nor the checksum carrying
        // across blocks. This asserts that at least one of them does,
        // so the suite above is not seven tests of the same path.
        let longest = published_vectors().into_iter()
            .map(|(message, _)| message.len())
            .max()
            .unwrap();
        assert!(longest > 4 * BLOCK, "longest vector is {} bytes", longest);
    }

    // --------------------------------------------------- the structure ---

    #[test]
    fn test_the_two_readings_of_the_checksum_disagree() {
        // `CHECKSUM_DISAGREEMENT`, made concrete. RFC 1319's prose
        // assigns where its reference code XOR-assigns, and a reader
        // who implemented the prose would get a self-consistent MD2
        // that matches no certificate ever signed.
        //
        // Written out here rather than left as a comment, because a
        // test that only checks our answer against the vectors cannot
        // say there was a second candidate at all - and the next person
        // to "simplify" this file will be reading the prose.
        fn by_the_prose(message: &[u8]) -> [u8; BLOCK] {
            let mut checksum = [0u8; BLOCK];
            let mut l = 0u8;
            for block in message.chunks(BLOCK) {
                for (j, &c) in block.iter().enumerate() {
                    checksum[j] = PI[(c ^ l) as usize];       // assign
                    l = checksum[j];
                }
            }
            checksum
        }
        fn by_the_code(message: &[u8]) -> [u8; BLOCK] {
            let mut checksum = [0u8; BLOCK];
            for block in message.chunks(BLOCK) {
                let mut t = checksum[BLOCK - 1];
                for (i, &c) in block.iter().enumerate() {
                    checksum[i] ^= PI[(c ^ t) as usize];      // XOR-assign
                    t = checksum[i];
                }
            }
            checksum
        }

        // They agree on a single block, because the checksum starts at
        // zero and `0 ^ x == x`. **That is why this needs two blocks**:
        // a test written with one would pass under either reading, and
        // so would a mistake.
        let one_block = [0x41u8; BLOCK];
        assert_eq!(by_the_prose(&one_block), by_the_code(&one_block));

        let two_blocks = [0x41u8; BLOCK * 2];
        assert_ne!(by_the_prose(&two_blocks), by_the_code(&two_blocks),
                   "the two readings must differ, or this file's choice \
                    is not a choice");

        // And ours is the code's.
        let mut ours = Md2::new(&[]);
        ours.update(&two_blocks);
        let mut expected = Md2::new(&[]);
        expected.update(&two_blocks);
        assert_eq!(expected.checksum, by_the_code(&two_blocks));
        assert_ne!(ours.checksum, by_the_prose(&two_blocks));
    }

    #[test]
    fn test_an_aligned_message_gets_a_whole_block_of_padding() {
        // The PKCS#7 surprise. Sixteen bytes of input are padded with
        // sixteen bytes of 0x10, so MD2 of sixteen `A`s must differ
        // from MD2 of sixteen `A`s followed by sixteen 0x10 bytes -
        // which is what an implementation that skipped the padding on
        // an aligned message would produce.
        let aligned = [0x41u8; BLOCK];
        let mut hand_padded = aligned.to_vec();
        hand_padded.extend_from_slice(&[0x10u8; BLOCK]);
        assert_ne!(md2(&aligned), md2(&hand_padded));
    }

    #[test]
    fn test_the_checksum_is_hashed_and_not_merely_appended() {
        // Removing the checksum block entirely leaves a perfectly
        // self-consistent hash, so this asserts the compression
        // function ran over it: MD2 of the empty string must not equal
        // the state after padding alone.
        let mut without_checksum = Md2::new(&[]);
        without_checksum.update(&[0x10u8; BLOCK]);
        assert_ne!(hex(&without_checksum.state[..BLOCK]), md2(b""));
    }

    // ------------------------------------------------------- streaming ---

    #[test]
    fn test_streaming_in_irregular_pieces_matches_one_call() {
        // The bug shape this repository has already had twice: a
        // buffered hash that desynchronises on the third call. Every
        // split of every length up to four blocks.
        let message: Vec<u8> = (0..=200u8).collect();
        for length in 0..=message.len() {
            let whole = md2(&message[..length]);
            for split in 0..=length {
                let mut h = Md2::new(&[]);
                h.update(&message[..split]);
                h.update(&message[split..length]);
                assert_eq!(hex(&h.digest()), whole,
                           "length {} split at {}", length, split);
            }
        }
    }

    #[test]
    fn test_byte_at_a_time_matches_one_call() {
        let message: Vec<u8> = (0..=90u8).collect();
        let mut h = Md2::new(&[]);
        for byte in &message {
            h.update(&[*byte]);
        }
        assert_eq!(hex(&h.digest()), md2(&message));
    }

    #[test]
    fn test_digest_may_be_taken_twice_and_update_may_follow_it() {
        // `hashlib` objects behave this way and `AnyHash` promises it.
        // A `digest` that consumed the state would pass every test
        // above, because each of them takes it once.
        let mut h = Md2::new(b"abc");
        let first = hex(&h.digest());
        assert_eq!(hex(&h.digest()), first);
        h.update(b"def");
        assert_eq!(hex(&h.digest()), md2(b"abcdef"));
    }

    #[test]
    fn test_the_name_and_sizes() {
        let h = Md2::new(&[]);
        assert_eq!(h.name(), "md2");
        assert_eq!(h.digest_len(), 16);
        assert_eq!(h.block_size(), BLOCK);
        assert_eq!(Md2::default().clone().digest().len(), 16);
    }
}
