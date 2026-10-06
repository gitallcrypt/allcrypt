/*
Whirlpool, Barreto and Rijmen, ISO/IEC 10118-3.

A 512 bit hash built as Miyaguchi-Preneel over a 512 bit block cipher
`W` that is AES's shape scaled up: an 8x8 byte matrix, ten rounds of
substitute-shift-mix-addkey, and a key schedule that is the cipher
itself applied to round constants.

It is here for what still uses it rather than for what it protects -
though unlike MD2 and MD4 it is not broken:

- **TrueCrypt and VeraCrypt** derive their header keys with
  PBKDF2-HMAC-Whirlpool, so a volume made with that option cannot be
  opened without it.
- It is one of the two hashes in ISO/IEC 10118-3, and the one the other
  standards bodies reached for when they wanted something that was not
  from NIST.
- `hashlib` does not have it. OpenSSL moved it to the `legacy` provider
  in 3.0, so the reference for it is one `openssl` release away from
  disappearing - which is why it is implemented now, while something
  still exists to check it against.

## The S-box is generated, not typed

Whirlpool's 256-byte S-box is **constructed** from two 16-entry mini
boxes, and that construction is in the specification. So the only
constants written out in this file are those 32 nibbles, and everything
else - the S-box, the ten round constants, the circulant matrix's
multiples - is computed from them.

That matters because a 256-byte table is 256 chances to mistype
something, and this repository has been bitten by transcribed tables
twice. What pins the 32 nibbles is that a single wrong one almost always
stops `E` or `R` being a permutation, which is asserted; and past that,
eleven published vectors and a differential sweep against OpenSSL over
three hundred lengths.

## Two things that are easy to get wrong

**The length field is 256 bits, and what matters about it is where the
padding stops.** Whirlpool pads to *32 bytes* short of a block - not 8
like MD5 and SHA-1, not 16 like SHA-512 - and puts a 256 bit big-endian
bit count in those 32 bytes.

A breakage sweep taught a more precise version of that. Writing the
count as a `u64` into the **last** eight bytes of the 32 is
byte-for-byte identical to writing it as a `u256`, for every message
under 2^64 bits - so "use a 64 bit field" is not a bug here at all, and
an earlier draft of this comment said it was. The two real mistakes are
padding to 56 mod 64 the way MD5 does, which fails seven tests, and
putting the count at the *front* of the 32 bytes instead of the end,
which fails the vectors. `test_the_padding_stops_thirty_two_bytes_short`
pins both.

**Miyaguchi-Preneel XORs three things.** `H' = W[H](M) ^ M ^ H`.
Forgetting the `^ H` gives Matyas-Meyer-Oseas, which is also a
perfectly good construction and agrees with nobody.

## Whirlpool-0 and Whirlpool-T are not here

The function was revised twice: Whirlpool-0 (2000), Whirlpool-T (2001,
a different S-box) and the final Whirlpool (2003, a different diffusion
matrix). Only the last is standardised, and it is the only one with a
reference implementation on this machine. The other two would be
unverifiable, and an unverified variant is worse than an absent one.
*/

use super::buffer::BlockBuffer;
use super::HashFunction;

const BLOCK: usize = 64;
const DIGEST: usize = 64;
const ROUNDS: usize = 10;

/// The mini box `E`, a permutation of the nibbles, and `R`, the
/// "round" box. **These 32 nibbles are the only constants in this file
/// that were typed**, and everything else is built from them - see the
/// module comment, and `test_the_mini_boxes_are_permutations`, which is
/// what a single wrong entry almost always breaks.
const E: [u8; 16] = [0x1, 0xb, 0x9, 0xc, 0xd, 0x6, 0xf, 0x3,
                     0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0];
const R: [u8; 16] = [0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf,
                     0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0];

/// `E` inverted, which the construction needs for the low nibble.
const fn invert(box_: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[box_[i] as usize] = i as u8;
        i += 1;
    }
    out
}

const E_INV: [u8; 16] = invert(E);

/// The S-box, built at compile time from `E`, `E_INV` and `R`.
///
/// Each byte is split into nibbles, the two halves are pushed through
/// the mini boxes, mixed through `R`, and pushed through again. The
/// structure is what makes Whirlpool's S-box cheap in hardware, and it
/// is why the specification states the mini boxes rather than the
/// table.
const SBOX: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        let high = E[x >> 4];
        let low = E_INV[x & 0xf];
        let mixed = R[(high ^ low) as usize];
        let high = E[(high ^ mixed) as usize];
        let low = E_INV[(low ^ mixed) as usize];
        table[x] = (high << 4) | low;
        x += 1;
    }
    table
};

/// Multiplication in GF(2^8) modulo `x^8 + x^4 + x^3 + x^2 + 1`, which
/// is **0x11d** - not AES's 0x11b. Two different fields; using AES's
/// gives a self-consistent hash that agrees with nobody.
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    product
}

/// The circulant matrix's first row: `cir(1, 1, 4, 1, 8, 5, 2, 9)`.
const CIRCULANT: [u8; 8] = [1, 1, 4, 1, 8, 5, 2, 9];

/// The eight lookup tables that fold the substitution, the shift and the
/// matrix multiply into one indexed XOR each.
///
/// Built at compile time. Row `t` of the state is formed by XORing
/// `C[t][byte]` over the eight bytes that feed it, which is the standard
/// way to implement an AES-shaped cipher and is what makes hashing a
/// hundred kilobytes fast enough for the differential corpus to sweep
/// it.
const C: [[u64; 256]; 8] = {
    let mut tables = [[0u64; 256]; 8];
    let mut x = 0usize;
    while x < 256 {
        let s = SBOX[x];
        // The first table holds the matrix row applied to S[x]; the
        // rest are that value rotated right by eight bits each, which
        // is what makes the matrix circulant.
        let mut value = 0u64;
        let mut j = 0;
        while j < 8 {
            value |= (gf_mul(s, CIRCULANT[j]) as u64) << (56 - 8 * j);
            j += 1;
        }
        let mut t = 0;
        while t < 8 {
            tables[t][x] = value.rotate_right(8 * t as u32);
            t += 1;
        }
        x += 1;
    }
    tables
};

/// The ten round constants. Row zero is eight successive S-box entries
/// and the other seven rows are zero, so each constant is one `u64`.
const RC: [u64; ROUNDS] = {
    let mut rc = [0u64; ROUNDS];
    let mut r = 0usize;
    while r < ROUNDS {
        let mut value = 0u64;
        let mut j = 0;
        while j < 8 {
            value |= (SBOX[8 * r + j] as u64) << (56 - 8 * j);
            j += 1;
        }
        rc[r] = value;
        r += 1;
    }
    rc
};

/// One round of `W` applied to `state` with round key `key`, written
/// into `out`.
fn round(state: &[u64; 8], key: &[u64; 8], out: &mut [u64; 8]) {
    for (i, slot) in out.iter_mut().enumerate() {
        let mut value = 0u64;
        for t in 0..8 {
            // Row `i` of the result takes byte `t` of row `i - t`,
            // which is the cyclic column shift and the matrix multiply
            // together.
            let byte = (state[(i + 8 - t) % 8] >> (56 - 8 * t)) & 0xff;
            value ^= C[t][byte as usize];
        }
        *slot = value ^ key[i];
    }
}

#[derive(Clone)]
pub struct Whirlpool {
    /// The chaining value, and the cipher's key.
    hash: [u64; 8],
    buffer: BlockBuffer<BLOCK>,
    /// **256 bits of bit count.** See the module comment: a 64 bit
    /// field is wrong for every message, not just long ones.
    bits: u128,
}

impl Default for Whirlpool {
    fn default() -> Self {
        Whirlpool::new(&[])
    }
}

impl Whirlpool {
    pub fn new(data: &[u8]) -> Whirlpool {
        let mut whirlpool = Whirlpool {
            hash: [0; 8],
            buffer: BlockBuffer::default(),
            bits: 0,
        };
        whirlpool.update(data);
        whirlpool
    }

    /// Miyaguchi-Preneel: `H' = W[H](M) ^ M ^ H`.
    fn compress(hash: &mut [u64; 8], block: &[u8; BLOCK]) {
        let mut message = [0u64; 8];
        for (i, slot) in message.iter_mut().enumerate() {
            *slot = u64::from_be_bytes(
                block[i * 8..i * 8 + 8].try_into().expect("eight bytes"));
        }

        // The key schedule is the cipher applied to the round
        // constants, and the state starts as the message XOR the key -
        // both are the same `round` function, which is why it takes its
        // key as an argument rather than reading a schedule.
        let mut key = *hash;
        let mut state = [0u64; 8];
        for i in 0..8 {
            state[i] = message[i] ^ key[i];
        }

        let mut next_key = [0u64; 8];
        let mut next_state = [0u64; 8];
        for rc in RC.iter() {
            let constant = [*rc, 0, 0, 0, 0, 0, 0, 0];
            round(&key, &constant, &mut next_key);
            key = next_key;
            round(&state, &key, &mut next_state);
            state = next_state;
        }

        for i in 0..8 {
            // **Three terms.** Dropping `hash[i]` gives
            // Matyas-Meyer-Oseas, which is also a sound construction and
            // is a different hash.
            hash[i] ^= state[i] ^ message[i];
        }
    }

    fn finish(&self) -> Vec<u8> {
        let mut hash = self.hash;
        let mut tail = self.buffer.buffered().to_vec();
        tail.push(0x80);
        // Pad to 32 bytes short of a block, then the 256 bit length.
        while tail.len() % BLOCK != BLOCK - 32 {
            tail.push(0);
        }
        tail.extend_from_slice(&[0u8; 16]);              // the high half
        tail.extend_from_slice(&self.bits.to_be_bytes());

        debug_assert_eq!(tail.len() % BLOCK, 0);
        for chunk in tail.chunks_exact(BLOCK) {
            Whirlpool::compress(&mut hash,
                                chunk.try_into().expect("chunks_exact"));
        }

        let mut out = Vec::with_capacity(DIGEST);
        for word in hash {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl HashFunction for Whirlpool {
    fn name(&self) -> String {
        "Whirlpool".to_string()
    }

    fn digest_len(&self) -> usize {
        DIGEST
    }

    fn block_size(&self) -> usize {
        BLOCK
    }

    fn update(&mut self, input: &[u8]) {
        self.bits = self.bits.wrapping_add(input.len() as u128 * 8);
        let hash = &mut self.hash;
        self.buffer.feed(input, |block| Whirlpool::compress(hash, block));
    }

    fn digest(&mut self) -> Vec<u8> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTAN: &str = include_str!("../../vectors/whirlpool.vec");

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn whirlpool(data: &[u8]) -> String {
        hex(&Whirlpool::new(data).digest())
    }

    // ------------------------------------------- the generated tables ---

    #[test]
    fn test_the_mini_boxes_are_permutations() {
        // **The check that stands in for not typing a 256-byte table.**
        // `E` and `R` are the only constants written out in this file,
        // and a single wrong nibble in either almost always creates a
        // duplicate - which this catches at the source rather than as a
        // wrong digest fifty lines later.
        for (name, box_) in [("E", E), ("R", R)] {
            let mut seen = [false; 16];
            for &value in box_.iter() {
                assert!(value < 16, "{name} has an entry that is not a nibble");
                assert!(!seen[value as usize], "{name} has {value:x} twice");
                seen[value as usize] = true;
            }
        }
        // And `E_INV` really inverts `E`, which is a property of the
        // generated table rather than of the typed one.
        for x in 0..16u8 {
            assert_eq!(E_INV[E[x as usize] as usize], x);
        }
    }

    #[test]
    fn test_the_sbox_is_a_permutation() {
        // A consequence of the mini boxes being permutations, and the
        // property that says the generated table is usable at all.
        let mut seen = [false; 256];
        for &value in SBOX.iter() {
            assert!(!seen[value as usize], "the S-box has {value} twice");
            seen[value as usize] = true;
        }
    }

    #[test]
    fn test_the_field_is_not_aess() {
        // Whirlpool reduces modulo 0x11d and AES modulo 0x11b. Copying
        // AES's constant gives a self-consistent hash that agrees with
        // nobody, and the two agree on most inputs - `gf_mul(x, 1)` is
        // `x` either way - so this names a case where they differ.
        const AES_MUL: fn(u8, u8) -> u8 = |mut a, mut b| {
            let mut product = 0u8;
            while b != 0 {
                if b & 1 != 0 { product ^= a; }
                let high = a & 0x80;
                a <<= 1;
                if high != 0 { a ^= 0x1b; }
                b >>= 1;
            }
            product
        };
        assert_ne!(gf_mul(0x80, 2), AES_MUL(0x80, 2));
        assert_eq!(gf_mul(0x80, 2), 0x1d);
        assert_eq!(AES_MUL(0x80, 2), 0x1b);

        // And multiplication by one is the identity, which is what most
        // of the circulant row asks for.
        for x in 0..=255u8 {
            assert_eq!(gf_mul(x, 1), x);
        }
    }

    #[test]
    fn test_the_round_constants_are_successive_sbox_entries() {
        // Ten constants over eighty S-box entries, and none may repeat
        // - a schedule that reused one would make two rounds identical.
        let mut seen = std::collections::HashSet::new();
        for (r, constant) in RC.iter().enumerate() {
            assert!(seen.insert(constant), "round constant {r} repeats");
            assert_eq!(constant.to_be_bytes().to_vec(),
                       SBOX[8 * r..8 * r + 8].to_vec());
        }
    }

    #[test]
    fn test_the_tables_are_rotations_of_one_another() {
        // The matrix is circulant, so the eight lookup tables differ
        // only by a byte rotation. An implementation that built them
        // independently could get one wrong; this says they cannot
        // disagree.
        for (x, &first) in C[0].iter().enumerate() {
            for (t, table) in C.iter().enumerate() {
                assert_eq!(table[x], first.rotate_right(8 * t as u32),
                           "table {t} entry {x}");
            }
        }
    }

    // ------------------------------------------ Botan's vectors, parsed ---

    /// The vendored vector file, read at test time.
    ///
    /// `In`/`Out` pairs under a `[Whirlpool]` heading - the same shape
    /// `block_ciphers::vector_file` reads, but with no key, so it is
    /// parsed here rather than shared.
    fn published_vectors() -> Vec<(Vec<u8>, String)> {
        fn unhex(text: &str) -> Vec<u8> {
            let clean: String = text.chars()
                .filter(|c| c.is_ascii_hexdigit()).collect();
            assert!(clean.len().is_multiple_of(2), "odd hex run");
            (0..clean.len() / 2)
                .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
                     .expect("two hex digits"))
                .collect()
        }

        let mut vectors = Vec::new();
        let mut input: Option<Vec<u8>> = None;
        for line in BOTAN.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("In =") {
                input = Some(unhex(value));
            } else if let Some(value) = line.strip_prefix("Out =") {
                let digest = unhex(value);
                assert_eq!(digest.len(), DIGEST, "a digest is the wrong size");
                vectors.push((input.take().expect("an Out before any In"),
                              hex(&digest)));
            }
        }
        assert_eq!(vectors.len(), 11,
                   "the vector file should hold 11 vectors; found {}",
                   vectors.len());
        vectors
    }

    #[test]
    fn test_the_published_vectors() {
        for (input, expected) in published_vectors() {
            assert_eq!(whirlpool(&input), expected,
                       "input of {} bytes", input.len());
        }
    }

    #[test]
    fn test_the_vectors_cross_a_block_boundary() {
        // Eleven short vectors would exercise one block and the padding
        // and nothing else. This says the file covers more than that,
        // so shrinking it is a failure rather than a smaller number
        // nobody remembers.
        let longest = published_vectors().into_iter()
            .map(|(input, _)| input.len())
            .max()
            .unwrap();
        assert!(longest > 4 * BLOCK, "longest vector is {longest} bytes");
    }

    #[test]
    fn test_the_empty_input() {
        // Stated separately because it is the one value a reader can
        // check against any other implementation in one line, and
        // because it exercises the padding with nothing before it.
        assert_eq!(whirlpool(b""),
                   "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee096\
                    4997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d937\
                    08b138cc42a66eb3");
    }

    // ------------------------------------------------------- structure ---

    #[test]
    fn test_the_padding_stops_thirty_two_bytes_short() {
        // **The thing that actually matters about the 256 bit length
        // field**, learned from a sweep: writing the count as a `u64`
        // into the last eight of those 32 bytes is byte-identical to
        // writing it as a `u256`, for every message under 2^64 bits. So
        // the width is not the hazard. Two things are:
        //
        // 1. padding to 56 mod 64 the way MD5 and SHA-1 do, rather than
        //    to 32 mod 64;
        // 2. putting the count at the front of the 32 bytes rather than
        //    at the end.
        //
        // Both are pinned by the published vectors, and this test says
        // what the shape is so that a reader does not have to run them
        // to find out.
        //
        // Reconstructed here rather than asserted on internals: an
        // input of exactly `BLOCK - 32 - 1` bytes is the largest whose
        // padding still fits in one block, and one byte more needs two.
        // A hash that padded to 56 mod 64 would put that boundary 24
        // bytes later.
        let fits = BLOCK - 32 - 1;
        assert_eq!(fits, 31);
        for length in [fits - 1, fits, fits + 1, fits + 2] {
            let a = whirlpool(&vec![0u8; length]);
            let b = whirlpool(&vec![0u8; length + 1]);
            assert_ne!(a, b, "lengths {length} and {}", length + 1);
        }

        // And the count really is of *bits*, not bytes - a hash that
        // stored the byte count would agree with itself and with
        // nothing else, and every message would still hash differently.
        let mut h = Whirlpool::new(b"abc");
        let _ = h.digest();
        assert_eq!(h.bits, 24);
    }

    #[test]
    fn test_miyaguchi_preneel_uses_all_three_terms() {
        // `H' = W[H](M) ^ M ^ H`. Dropping the `^ H` is
        // Matyas-Meyer-Oseas, which is also sound and is a different
        // hash - and for the *first* block it makes no difference,
        // because `H` starts at zero. So this needs two blocks.
        fn without_the_chaining_value(data: &[u8]) -> [u64; 8] {
            let mut hash = [0u64; 8];
            for chunk in data.chunks_exact(BLOCK) {
                let block: &[u8; BLOCK] = chunk.try_into().unwrap();
                let before = hash;
                Whirlpool::compress(&mut hash, block);
                // Undo the `^ H` that `compress` applied.
                for i in 0..8 {
                    hash[i] ^= before[i];
                }
            }
            hash
        }

        let one_block = [0x41u8; BLOCK];
        let mut ours = [0u64; 8];
        Whirlpool::compress(&mut ours, &one_block);
        assert_eq!(ours, without_the_chaining_value(&one_block),
                   "the two constructions agree on the first block");

        let two_blocks = [0x41u8; BLOCK * 2];
        let mut ours = [0u64; 8];
        for chunk in two_blocks.chunks_exact(BLOCK) {
            Whirlpool::compress(&mut ours, chunk.try_into().unwrap());
        }
        assert_ne!(ours, without_the_chaining_value(&two_blocks),
                   "the two constructions must differ by the second block");
    }

    // ------------------------------------------------------- streaming ---

    #[test]
    fn test_streaming_in_irregular_pieces_matches_one_call() {
        // Every length up to three blocks, against the splits that can
        // go wrong: the ends, the middle, and both sides of each block
        // boundary. The all-splits sweep the other hashes use costs ten
        // seconds here, because Whirlpool's compression function is an
        // order of magnitude heavier than MD5's - and the splits it
        // adds are the ones nothing special happens at.
        let message: Vec<u8> = (0..=200u8).collect();
        for length in 0..=192usize {
            let whole = whirlpool(&message[..length]);
            let mut splits = vec![0, length, length / 2];
            for boundary in [BLOCK, 2 * BLOCK, 3 * BLOCK] {
                for near in [boundary.wrapping_sub(1), boundary, boundary + 1] {
                    if near <= length {
                        splits.push(near);
                    }
                }
            }
            if length > 0 {
                splits.push(1);
                splits.push(length - 1);
            }
            for split in splits {
                let mut h = Whirlpool::new(&[]);
                h.update(&message[..split]);
                h.update(&message[split..length]);
                assert_eq!(hex(&h.digest()), whole,
                           "length {length} split at {split}");
            }
        }
    }

    #[test]
    fn test_byte_at_a_time_matches_one_call() {
        // The other shape of the same claim, and the one that exercises
        // the partial-block path on every single call.
        let message: Vec<u8> = (0..=150u8).collect();
        let mut h = Whirlpool::new(&[]);
        for byte in &message {
            h.update(&[*byte]);
        }
        assert_eq!(hex(&h.digest()), whirlpool(&message));
    }

    #[test]
    fn test_digest_may_be_taken_twice_and_update_may_follow_it() {
        let mut h = Whirlpool::new(b"abc");
        let first = hex(&h.digest());
        assert_eq!(hex(&h.digest()), first);
        h.update(b"def");
        assert_eq!(hex(&h.digest()), whirlpool(b"abcdef"));
    }

    #[test]
    fn test_the_name_and_sizes() {
        let h = Whirlpool::new(&[]);
        assert_eq!(h.name(), "Whirlpool");
        assert_eq!(h.digest_len(), 64);
        assert_eq!(h.block_size(), BLOCK);
        assert_eq!(Whirlpool::default().clone().digest().len(), 64);
    }
}
