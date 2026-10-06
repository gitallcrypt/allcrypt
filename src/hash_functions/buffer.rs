//! One correct implementation of "feed bytes in, get whole blocks out".
//!
//! Every Merkle-Damgård hash needs this, and it is where two of this
//! repository's real bugs lived: SHA-1/224/256 padded with a 16-byte
//! length field, and ChaCha desynchronised its keystream from the third
//! `crypt()` call. Both produced plausible output and passed the
//! vectors that happened to be in the suite, because **a known-answer
//! test is one call**.
//!
//! MD2 made the same mistake a third time while being written: its
//! `update` fell through to the tail on a call that did not fill a
//! block, so `update(b"a")` followed by `update(b"")` discarded the
//! `a`. Every published vector still passed.
//!
//! So the logic lives once, here, and the two easy ways to get it wrong
//! are both named in the code below.

/// A partial block, and the bytes not yet given to the compression
/// function.
///
/// `N` is the compression function's block size: 16 for MD2, 64 for the
/// 32-bit hashes, 128 for SHA-384/512.
#[derive(Clone)]
pub struct BlockBuffer<const N: usize> {
    /// Only the first `len` bytes are meaningful; the rest is whatever
    /// a previous block left there. A `Vec` would allocate on a caller
    /// feeding one byte at a time, which is what a streaming API is for.
    block: [u8; N],
    len: usize,
}

impl<const N: usize> Default for BlockBuffer<N> {
    fn default() -> Self {
        BlockBuffer { block: [0; N], len: 0 }
    }
}

impl<const N: usize> BlockBuffer<N> {
    /// How many bytes are waiting. Always strictly less than `N`
    /// between calls: a full block is never left here, it is compressed.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes waiting, for a padding routine that needs to know what
    /// is already there.
    pub fn buffered(&self) -> &[u8] {
        &self.block[..self.len]
    }

    /// Take `input`, calling `compress` once per complete block.
    ///
    /// Two things here are easy to get wrong and are the reason this is
    /// not written inline in each hash:
    ///
    /// 1. **A call that does not complete a block must return without
    ///    touching `len` again.** Falling through to the tail sets
    ///    `len` from the remainder of an input that has already been
    ///    consumed, which is zero - so the partial block is thrown away
    ///    and the next `digest` is of a shorter message. Single-call
    ///    vectors cannot see it.
    /// 2. **The tail must not compress.** A remainder shorter than `N`
    ///    is not a block; compressing it early is the other direction
    ///    of the same bug and shows up as a hash that is right only for
    ///    aligned inputs.
    pub fn feed(&mut self, input: &[u8], mut compress: impl FnMut(&[u8; N])) {
        self.feed_blocks(input, |run| {
            for chunk in run.chunks_exact(N) {
                compress(chunk.try_into().expect("chunks_exact yields N bytes"));
            }
        });
    }

    /// `feed`, handing over runs of whole blocks rather than one block at
    /// a time: every slice `compress` sees is a non-zero multiple of `N`
    /// bytes, in order. For a compression function that can keep its
    /// state in registers across blocks, which one call per block would
    /// make it load and store every time. `feed` is this, split up, so
    /// the two easy mistakes below are made or avoided in one place.
    pub fn feed_blocks(&mut self, mut input: &[u8], mut compress: impl FnMut(&[u8])) {
        if self.len > 0 {
            let take = core::cmp::min(N - self.len, input.len());
            self.block[self.len..self.len + take].copy_from_slice(&input[..take]);
            self.len += take;
            input = &input[take..];
            if self.len < N {
                debug_assert!(input.is_empty(),
                              "a still-partial block means `input` is spent");
                return;                                       // see (1)
            }
            compress(&self.block);
            self.len = 0;
        }

        let whole = input.len() / N * N;
        if whole > 0 {
            compress(&input[..whole]);
        }

        let rest = &input[whole..];                           // see (2)
        self.block[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `input` in the given pieces and return the blocks that came
    /// out, plus whatever is left waiting.
    fn run(pieces: &[&[u8]]) -> (Vec<[u8; 4]>, Vec<u8>) {
        let mut buffer = BlockBuffer::<4>::default();
        let mut blocks = Vec::new();
        for piece in pieces {
            buffer.feed(piece, |block| blocks.push(*block));
        }
        (blocks, buffer.buffered().to_vec())
    }

    #[test]
    fn test_every_way_of_splitting_an_input_gives_the_same_blocks() {
        // The property the whole type exists for. Two splits of every
        // length up to four blocks, which is enough to cross a boundary
        // in both directions.
        let message: Vec<u8> = (0..16u8).collect();
        for length in 0..=message.len() {
            let (whole, rest) = run(&[&message[..length]]);
            for split in 0..=length {
                let (pieces, tail) = run(&[&message[..split],
                                           &message[split..length]]);
                assert_eq!((pieces, tail), (whole.clone(), rest.clone()),
                           "length {} split at {}", length, split);
            }
        }
    }

    /// `feed_blocks` hands over the same bytes as `feed`, in runs that
    /// are each a non-zero number of whole blocks.
    #[test]
    fn test_runs_are_whole_blocks_and_join_to_the_same_bytes() {
        let message: Vec<u8> = (0..23u8).collect();
        for split in 0..=message.len() {
            let mut buffer = BlockBuffer::<4>::default();
            let mut joined = Vec::new();
            for piece in [&message[..split], &message[split..]] {
                buffer.feed_blocks(piece, |run| {
                    assert!(!run.is_empty() && run.len().is_multiple_of(4), "a run of {}", run.len());
                    joined.extend_from_slice(run);
                });
            }
            assert_eq!(joined, message[..20], "split at {}", split);
            assert_eq!(buffer.buffered(), &message[20..], "split at {}", split);
        }
    }

    #[test]
    fn test_an_empty_call_after_a_partial_block_keeps_it() {
        // **The MD2 bug, in one line.** Without the early return this
        // reports nothing buffered, and the bytes are gone.
        let (blocks, rest) = run(&[b"ab", b""]);
        assert!(blocks.is_empty());
        assert_eq!(rest, b"ab");
    }

    #[test]
    fn test_an_empty_call_after_a_whole_block_keeps_nothing() {
        // The other side of the same line: an empty call must not
        // invent a block either.
        let (blocks, rest) = run(&[b"abcd", b""]);
        assert_eq!(blocks, vec![*b"abcd"]);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_a_partial_block_is_not_compressed_early() {
        let (blocks, rest) = run(&[b"abc"]);
        assert!(blocks.is_empty(), "three bytes are not a block of four");
        assert_eq!(rest, b"abc");
    }

    #[test]
    fn test_a_full_block_is_never_left_waiting() {
        // If it were, the padding routine would see `len == N` and
        // append a whole extra block - which is the shape of the
        // SHA-1 length-field bug's neighbour.
        for length in 0..40usize {
            let message: Vec<u8> = (0..length as u8).collect();
            let mut buffer = BlockBuffer::<4>::default();
            buffer.feed(&message, |_| {});
            assert!(buffer.len() < 4, "length {} left {} waiting",
                    length, buffer.len());
            assert_eq!(buffer.len(), length % 4);
        }
    }

    #[test]
    fn test_byte_at_a_time_gives_the_same_blocks_as_one_call() {
        let message: Vec<u8> = (0..23u8).collect();
        let (whole, whole_rest) = run(&[&message]);
        let pieces: Vec<&[u8]> = message.chunks(1).collect();
        let (one_by_one, tail) = run(&pieces);
        assert_eq!(one_by_one, whole);
        assert_eq!(tail, whole_rest);
    }

    #[test]
    fn test_the_blocks_are_the_input_in_order() {
        // A buffer that reassembled the bytes wrongly would still
        // satisfy every count above.
        let message: Vec<u8> = (0..12u8).collect();
        let (blocks, rest) = run(&[&message[..1], &message[1..7], &message[7..]]);
        assert!(rest.is_empty());
        let flat: Vec<u8> = blocks.concat();
        assert_eq!(flat, message);
    }
}
