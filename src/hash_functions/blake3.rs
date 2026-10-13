/*!
BLAKE3 (O'Connor, Aumasson, Neves and Wilcox-O'Hearn, 2020): BLAKE2s's
compression function cut to seven rounds, in a binary tree of 1024 byte
chunks, with any length of output.

Each chunk is hashed alone, its 64 byte blocks chained through the
compression function with the chunk's number as the counter and flags
marking its first and last blocks. Chunks' chaining values are combined
in pairs by parent nodes, left to right, into a tree whose shape depends
only on the length; the last node to be computed - a chunk, if there is
only one - is the root, and its compression function, run again with an
output counter instead, gives as many bytes as are asked for.

Three modes, told apart by flags and by the key that starts every chunk
and parent: `hash` (SHA-256's initial values), `keyed` (a 32 byte key),
and `derive_key`, which first hashes a context string to make the key
for hashing the key material.

The constants are BLAKE2s's initial values (SHA-256's) and the message
permutation the round between rounds applies, written out because it is
the specification's definition; the team's published test vectors, read
by `tests/test_blake3.rs` out of the file itself, and two other
implementations check all of it.

Name: `blake3`, 32 bytes. `Blake3::xof` gives any length from any
offset, and `Blake3::keyed` and `Blake3::derive_key` are the other two
modes.
*/

use super::buffer::BlockBuffer;
use super::sha2::H256 as IV;
use super::HashFunction;

const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED_HASH: u32 = 16;
const DERIVE_KEY_CONTEXT: u32 = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;

/// The message words' order in the next round.
const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Blocks to a chunk.
const BLOCKS: usize = 16;

fn compress(cv: &[u32; 8], block: &[u8; 64], counter: u64, len: u32, flags: u32) -> [u32; 16] {
    let mut m: [u32; 16] = core::array::from_fn(|i| {
        u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().expect("4 bytes"))
    });
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(cv);
    v[8..12].copy_from_slice(&IV[..4]);
    v[12] = counter as u32;
    v[13] = (counter >> 32) as u32;
    v[14] = len;
    v[15] = flags;
    for round in 0..7 {
        for (i, [a, b, c, d]) in [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
                                  [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]]
            .into_iter().enumerate() {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[2 * i]);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[2 * i + 1]);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }
        if round < 6 {
            m = core::array::from_fn(|i| m[PERMUTATION[i]]);
        }
    }
    for i in 0..8 {
        v[i] ^= v[i + 8];
        v[i + 8] ^= cv[i];
    }
    v
}

fn chaining_value(words: [u32; 16]) -> [u32; 8] {
    words[..8].try_into().expect("8 words")
}

/// A node not yet compressed: whether it is the root decides its flags.
#[derive(Clone)]
struct Node {
    cv: [u32; 8],
    block: [u8; 64],
    counter: u64,
    len: u32,
    flags: u32,
}

impl Node {
    fn chaining_value(&self) -> [u32; 8] {
        chaining_value(compress(&self.cv, &self.block, self.counter, self.len, self.flags))
    }

    fn parent(left: &[u32; 8], right: &[u32; 8], key: &[u32; 8], flags: u32) -> Node {
        let mut block = [0u8; 64];
        for (i, w) in left.iter().chain(right).enumerate() {
            block[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        Node { cv: *key, block, counter: 0, len: 64, flags: flags | PARENT }
    }

    /// The root's output from byte `seek`, `length` bytes.
    fn output(&self, seek: u64, length: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(length + 64);
        let mut block = seek / 64;
        let mut skip = (seek % 64) as usize;
        while out.len() < length {
            let words = compress(&self.cv, &self.block, block, self.len, self.flags | ROOT);
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            out.extend_from_slice(&bytes[skip..]);
            skip = 0;
            block = block.wrapping_add(1);
        }
        out.truncate(length);
        out
    }
}

/// BLAKE3 in progress, in any of its three modes.
#[derive(Clone)]
pub struct Blake3 {
    key: [u32; 8],
    flags: u32,
    /// The chaining value within the current chunk.
    cv: [u32; 8],
    /// The current chunk's number.
    chunk: u64,
    /// Blocks of the current chunk compressed so far.
    blocks: usize,
    /// The last whole block, not yet compressed: the last block of a
    /// chunk is compressed differently, and so is the last of the
    /// message, and which a block is only shows when more input comes.
    held: Option<[u8; 64]>,
    /// Chaining values of complete subtrees, left to right.
    stack: Vec<[u32; 8]>,
    buffer: BlockBuffer<64>,
}

fn key_words(key: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().expect("4")))
}

impl Blake3 {
    fn make(key: [u32; 8], flags: u32) -> Blake3 {
        Blake3 { key, flags, cv: key, chunk: 0, blocks: 0, held: None, stack: Vec::new(),
                 buffer: BlockBuffer::default() }
    }

    /// BLAKE3's hash mode.
    pub fn new() -> Blake3 {
        Blake3::make(IV, 0)
    }

    /// BLAKE3's keyed mode.
    pub fn keyed(key: &[u8; 32]) -> Blake3 {
        Blake3::make(key_words(key), KEYED_HASH)
    }

    /// BLAKE3's key derivation mode: the key material goes in through
    /// `update`. The context is meant to be a hard-coded, globally
    /// unique string naming the application and the purpose.
    pub fn derive_key(context: &[u8]) -> Blake3 {
        let mut hasher = Blake3::make(IV, DERIVE_KEY_CONTEXT);
        hasher.update(context);
        let context_key: [u8; 32] = hasher.xof(32, 0).try_into().expect("32 bytes");
        Blake3::make(key_words(&context_key), DERIVE_KEY_MATERIAL)
    }

    /// One whole block, which is not the last of the message; the held
    /// one before it, if any, can now be compressed.
    fn absorb(&mut self, block: &[u8; 64]) {
        if let Some(previous) = self.held.replace(*block) {
            self.compress_held(previous);
        }
    }

    /// `block`, which is known not to be the message's last: the end of
    /// its chunk if the chunk is full, otherwise one more of its blocks.
    fn compress_held(&mut self, block: [u8; 64]) {
        let start = if self.blocks == 0 { CHUNK_START } else { 0 };
        if self.blocks == BLOCKS - 1 {
            let node = Node { cv: self.cv, block, counter: self.chunk, len: 64,
                              flags: self.flags | start | CHUNK_END };
            let mut cv = node.chaining_value();
            // Merge as many complete subtrees as the chunk count's
            // trailing zeros say this chunk completes.
            let mut total = self.chunk + 1;
            while total & 1 == 0 {
                let left = self.stack.pop().expect("a subtree for every trailing zero");
                cv = Node::parent(&left, &cv, &self.key, self.flags).chaining_value();
                total >>= 1;
            }
            self.stack.push(cv);
            self.chunk += 1;
            self.cv = self.key;
            self.blocks = 0;
        } else {
            self.cv = chaining_value(compress(&self.cv, &block, self.chunk, 64,
                                              self.flags | start));
            self.blocks += 1;
        }
    }

    /// `length` bytes of output starting at byte `seek`.
    pub fn xof(&self, length: usize, seek: u64) -> Vec<u8> {
        let mut last = self.clone();
        let (block, len) = match (last.buffer.is_empty(), last.held.take()) {
            (false, held) => {
                if let Some(previous) = held {
                    last.compress_held(previous);
                }
                let mut block = [0u8; 64];
                block[..last.buffer.len()].copy_from_slice(last.buffer.buffered());
                (block, last.buffer.len())
            }
            (true, Some(previous)) => (previous, 64),
            (true, None) => ([0u8; 64], 0),
        };
        let start = if last.blocks == 0 { CHUNK_START } else { 0 };
        let mut node = Node { cv: last.cv, block, counter: last.chunk, len: len as u32,
                              flags: last.flags | start | CHUNK_END };
        for left in last.stack.iter().rev() {
            node = Node::parent(left, &node.chaining_value(), &last.key, last.flags);
        }
        node.output(seek, length)
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Blake3::new()
    }
}

impl HashFunction for Blake3 {
    fn name(&self) -> String {
        "blake3".to_string()
    }

    fn digest_len(&self) -> usize {
        32
    }

    fn block_size(&self) -> usize {
        64
    }

    fn update(&mut self, input: &[u8]) {
        // The buffer is taken out for the call, so that each block it
        // completes can reach the rest of the state.
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.feed(input, |block| self.absorb(block));
        self.buffer = buffer;
    }

    fn digest(&mut self) -> Vec<u8> {
        self.xof(32, 0)
    }
}
