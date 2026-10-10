/*
Argon2, RFC 9106. All three variants.

The winner of the Password Hashing Competition and the current answer to
"what should I hash a password with". Like scrypt it is memory-hard, and
unlike scrypt it lets the caller say how much *parallelism* to allow, so
the defender can use several cores without handing the attacker the same
advantage.

Three variants, and the difference is only in **where the reference block
index comes from**:

  * **Argon2d** takes it from the previous block's contents. Fastest
    resistance to time-memory trade-offs, and data *dependent* - so the
    memory access pattern depends on the password, which is a side
    channel where an attacker can watch cache behaviour.
  * **Argon2i** takes it from a counter run through the compression
    function. Data independent, so nothing about the password leaks
    through the access pattern, at the cost of weaker trade-off
    resistance.
  * **Argon2id** is Argon2i for the first half of the first pass and
    Argon2d after that. This is what RFC 9106 tells you to use, and it
    is the default here.

All three are implemented. `Argon2d` is not "the insecure one" - it is
the right choice when nothing can observe the machine's memory, and it
is what several deployed systems already used before Argon2id existed.

## The pieces, and which of them is easy to get quietly wrong

    H0     = BLAKE2b-512(parameters || P || S || K || X)   -- once
    B[i][0]= H'(H0 || LE32(0) || LE32(i))                  -- 1024 bytes
    B[i][1]= H'(H0 || LE32(1) || LE32(i))
    B[i][j]= G(B[i][j-1], B[l][z])                         -- the filling
    tag    = H'(B[0][q-1] xor B[1][q-1] xor ..)

`H'` is a **variable-length** hash built on BLAKE2b, not BLAKE2b itself:
up to 64 bytes it is one keyless BLAKE2b of `LE32(T) || A`; beyond that
it is a chain of 64 byte digests of which only the first 32 bytes of each
are kept. Using plain BLAKE2b for the 1024 byte blocks is the single
most common way to get an Argon2 that is entirely self-consistent and
agrees with nothing.

`G` is not BLAKE2b's round function either. It uses **GB**, which adds
`2 * trunc(a) * trunc(b)` to each addition - a 64 bit multiply of the low
halves. That multiplication is deliberate: it is what makes the function
expensive to implement in hardware with a shorter critical path. Leaving
it out gives a working, fast, wrong Argon2.

And `G` is applied **twice**: once along the eight rows of the block and
then once along the eight columns of the result. Doing rows twice, or
columns twice, produces a plausible avalanche and a wrong answer.

Each of those three is pinned by a test below, because the end-to-end tag
tells you something is wrong without telling you which.
*/

use crate::hash_functions::blake2::{Blake2b, Params};
use crate::hash_functions::HashFunction;

/// Which variant, which is only a choice of where the reference index
/// comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variant {
    /// Data dependent addressing. Best trade-off resistance; the memory
    /// access pattern depends on the password.
    D,
    /// Data independent addressing. Nothing leaks through the access
    /// pattern.
    I,
    /// Argon2i for the first half of the first pass, Argon2d after.
    /// What RFC 9106 recommends.
    Id,
}

impl Variant {
    /// The `y` field of the pre-hash, RFC 9106 section 3.1.
    fn code(self) -> u32 {
        match self {
            Variant::D => 0,
            Variant::I => 1,
            Variant::Id => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Variant::D => "argon2d",
            Variant::I => "argon2i",
            Variant::Id => "argon2id",
        }
    }
}

/// The version byte. `0x13` is Argon2 1.3, which is what RFC 9106
/// specifies and what everything current writes.
///
/// `0x10` (version 1.0) exists in the wild in files written before
/// 2016 and differs in how the reference index is computed for
/// non-current lanes. It is **not** implemented: nothing here can test
/// it, and a silently wrong answer for an old file would be worse than
/// refusing it.
pub const VERSION: u32 = 0x13;

const BLOCK_WORDS: usize = 128;
const BLOCK_BYTES: usize = BLOCK_WORDS * 8;
const SLICES: usize = 4;
const ADDRESSES_PER_BLOCK: usize = 128;

type Block = [u64; BLOCK_WORDS];

/// The most memory one derivation will hold, in kibibytes: 4 GiB.
///
/// `memory_kib` is a `u32`, so the type alone allows 4 TiB, and the only
/// check was that the block count times 1024 fits in `usize` - which it
/// does, so `memory_kib: u32::MAX` reached the allocator, where failure
/// is an abort rather than an error. RFC 9106's first recommended option
/// is 2 GiB; nothing deployed asks for more than this.
pub const MAX_MEMORY_KIB: u32 = 4 << 20;

/// The most lanes RFC 9106 allows: 2^24 - 1.
pub const MAX_LANES: u32 = (1 << 24) - 1;

/// Everything Argon2 takes. Built with `Argon2::new` and adjusted, so
/// adding a field later does not break callers.
#[derive(Clone)]
pub struct Argon2 {
    pub variant: Variant,
    /// Memory in **kibibytes**, the RFC's `m`. At least `8 * p`.
    pub memory_kib: u32,
    /// Passes over the memory, the RFC's `t`. At least 1.
    pub passes: u32,
    /// Lanes, the RFC's `p`. At least 1.
    pub lanes: u32,
    /// The optional secret key, the RFC's `K`. Sometimes called a
    /// "pepper": held by the application rather than stored with the
    /// hash, so a stolen database alone does not allow guessing.
    pub secret: Vec<u8>,
    /// The optional associated data, the RFC's `X`.
    pub associated_data: Vec<u8>,
}

/// The secret is a pepper, held by the application precisely so that it
/// is never written down beside a hash, so it is shown as a length and
/// nothing else: a derived `Debug` printed it, and a `{:?}` of the
/// parameters in a log line or a panic message is how it would have
/// been written down anyway.
impl core::fmt::Debug for Argon2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Argon2")
            .field("variant", &self.variant)
            .field("memory_kib", &self.memory_kib)
            .field("passes", &self.passes)
            .field("lanes", &self.lanes)
            .field("secret", &format_args!("[{} bytes]", self.secret.len()))
            .field("associated_data", &self.associated_data)
            .finish()
    }
}

impl Argon2 {
    /// RFC 9106 section 4's first recommended option, scaled down to
    /// something a test suite can run: the *recommendation* is 2 GiB,
    /// which is not a sensible default for a library that does not know
    /// what machine it is on. 64 MiB, 3 passes, 4 lanes is the widely
    /// used "second recommended option" shape and is what most
    /// deployments pick.
    pub fn new(variant: Variant) -> Argon2 {
        Argon2 {
            variant,
            memory_kib: 65536,
            passes: 3,
            lanes: 4,
            secret: Vec::new(),
            associated_data: Vec::new(),
        }
    }

    /// Derive `length` bytes.
    ///
    /// # Errors
    /// Parameters outside the RFC's ranges, or a memory request this
    /// machine cannot address.
    pub fn derive(&self, password: &[u8], salt: &[u8], length: usize)
                  -> Result<Vec<u8>, String> {
        if self.lanes == 0 {
            return Err("Argon2 needs at least one lane.".to_string());
        }
        if self.lanes > MAX_LANES {
            return Err(format!("Argon2 allows up to {} lanes; {} is too many.",
                               MAX_LANES, self.lanes));
        }
        if self.passes == 0 {
            return Err("Argon2 needs at least one pass.".to_string());
        }
        if length < 4 {
            return Err(format!("An Argon2 tag is at least 4 bytes; {} is not.",
                               length));
        }
        // The tag length is a 32-bit field of H0, and the output is
        // reserved before the first BLAKE2b, so both bounds apply.
        if u32::try_from(length).is_err() || length > crate::kdf::MAX_OUTPUT_BYTES {
            return Err(format!("An Argon2 tag is at most {} bytes here; {} is too long.",
                               crate::kdf::MAX_OUTPUT_BYTES, length));
        }
        if salt.len() < 8 {
            return Err(format!("An Argon2 salt is at least 8 bytes (RFC 9106 \
                                recommends 16); this one is {}.", salt.len()));
        }
        // `8 * lanes` in u64: with lanes at its ceiling the product does
        // not fit a u32.
        if (self.memory_kib as u64) < 8 * self.lanes as u64 {
            return Err(format!("Argon2 needs at least 8 KiB per lane, so at \
                                least {} KiB for {} lanes; {} is not enough.",
                               8 * self.lanes as u64, self.lanes, self.memory_kib));
        }
        if self.memory_kib > MAX_MEMORY_KIB {
            return Err(format!("Argon2 may use at most {} KiB in one call; {} is \
                                too much.", MAX_MEMORY_KIB, self.memory_kib));
        }

        // m' = 4 * p * floor(m / 4p): the memory is rounded down to a
        // whole number of segments, four per lane.
        let lanes = self.lanes as usize;
        let segment_length = (self.memory_kib as usize) / (lanes * SLICES);
        let lane_length = segment_length * SLICES;
        let blocks = lane_length * lanes;

        blocks.checked_mul(BLOCK_BYTES)
            .ok_or_else(|| format!("Argon2 with m={} KiB needs more memory than \
                                    this machine can address.", self.memory_kib))?;

        let h0 = self.pre_hash(password, salt, length as u32);

        // The whole memory, as one flat vector indexed
        // `lane * lane_length + column`. Reserved with `try_reserve_exact`
        // so that a refusal is an error: `vec![..; blocks]` would abort.
        let mut memory: Vec<Block> = Vec::new();
        memory.try_reserve_exact(blocks).map_err(|_| format!(
            "Could not allocate the {} KiB Argon2 with m={} needs.",
            blocks, self.memory_kib))?;
        memory.resize(blocks, [0u64; BLOCK_WORDS]);
        for lane in 0..lanes {
            for column in 0..2u32 {
                let mut input = Vec::with_capacity(h0.len() + 8);
                input.extend_from_slice(&h0);
                input.extend_from_slice(&column.to_le_bytes());
                input.extend_from_slice(&(lane as u32).to_le_bytes());
                let bytes = variable_hash(&input, BLOCK_BYTES);
                memory[lane * lane_length + column as usize] = block_from_bytes(&bytes);
            }
        }

        self.fill(&mut memory, lanes, lane_length, segment_length, blocks);

        // The tag is the XOR of the last column of every lane, run
        // through H'.
        let mut last = memory[lane_length - 1];
        for lane in 1..lanes {
            let other = memory[lane * lane_length + lane_length - 1];
            for (word, next) in last.iter_mut().zip(other.iter()) {
                *word ^= next;
            }
        }
        Ok(variable_hash(&block_to_bytes(&last), length))
    }

    /// H0, RFC 9106 section 3.2: one BLAKE2b-512 over every parameter
    /// and every input, each length prefixed.
    ///
    /// The length prefixes are what stop two different
    /// (password, salt) pairs from producing the same pre-hash, so
    /// leaving one out is a real collision and not a formatting
    /// detail.
    fn pre_hash(&self, password: &[u8], salt: &[u8], tag_length: u32) -> Vec<u8> {
        let mut hash = Blake2b::new(&[]);
        for value in [self.lanes, tag_length, self.memory_kib, self.passes,
                      VERSION, self.variant.code()] {
            hash.update(&value.to_le_bytes());
        }
        for field in [password, salt, &self.secret[..], &self.associated_data[..]] {
            hash.update(&(field.len() as u32).to_le_bytes());
            hash.update(field);
        }
        hash.digest()
    }

    /// The filling loop, RFC 9106 section 3.4.
    fn fill(&self, memory: &mut [Block], lanes: usize, lane_length: usize,
            segment_length: usize, blocks: usize) {
        for pass in 0..self.passes as usize {
            for slice in 0..SLICES {
                for lane in 0..lanes {
                    self.fill_segment(memory, pass, lane, slice, lanes,
                                      lane_length, segment_length, blocks);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn fill_segment(&self, memory: &mut [Block], pass: usize, lane: usize,
                    slice: usize, lanes: usize, lane_length: usize,
                    segment_length: usize, blocks: usize) {
        // Argon2i always, and Argon2id for the first half of the first
        // pass - which is slices 0 and 1 of pass 0.
        let independent = self.variant == Variant::I
            || (self.variant == Variant::Id && pass == 0 && slice < SLICES / 2);

        let mut address_input = [0u64; BLOCK_WORDS];
        let mut addresses = [0u64; BLOCK_WORDS];
        if independent {
            address_input[0] = pass as u64;
            address_input[1] = lane as u64;
            address_input[2] = slice as u64;
            address_input[3] = blocks as u64;
            address_input[4] = self.passes as u64;
            address_input[5] = self.variant.code() as u64;
        }

        // The first two blocks of each lane are already filled from H0.
        let start = if pass == 0 && slice == 0 { 2 } else { 0 };
        if independent && start == 2 {
            next_addresses(&mut address_input, &mut addresses);
        }

        for index in start..segment_length {
            let column = slice * segment_length + index;
            let previous = if column == 0 { lane_length - 1 } else { column - 1 };
            let previous_block = memory[lane * lane_length + previous];

            let random = if independent {
                if index.is_multiple_of(ADDRESSES_PER_BLOCK) {
                    next_addresses(&mut address_input, &mut addresses);
                }
                addresses[index % ADDRESSES_PER_BLOCK]
            } else {
                // Argon2d: straight out of the previous block, which is
                // what makes the access pattern depend on the password.
                previous_block[0]
            };

            // J2 picks the lane, except in the very first segment,
            // where no other lane has anything yet.
            let reference_lane = if pass == 0 && slice == 0 {
                lane
            } else {
                ((random >> 32) % lanes as u64) as usize
            };
            let reference_index = reference_index(
                random & 0xffff_ffff, pass, slice, index, segment_length,
                lane_length, reference_lane == lane);

            let reference = memory[reference_lane * lane_length + reference_index];
            let mixed = g(&previous_block, &reference);

            let target = lane * lane_length + column;
            if pass == 0 {
                memory[target] = mixed;
            } else {
                // Later passes XOR into what is already there rather
                // than overwriting, so the whole history contributes.
                for (word, next) in memory[target].iter_mut().zip(mixed.iter()) {
                    *word ^= next;
                }
            }
        }
    }
}

/// Where in the reference lane to look, RFC 9106 section 3.4.1.2.
///
/// The arithmetic is deliberately odd: the relative position is squared
/// and taken from the *top* of the window, so recent blocks are far more
/// likely to be chosen than old ones. That is what makes a
/// trade-off attacker have to keep the recent history rather than
/// sampling it.
fn reference_index(j1: u64, pass: usize, slice: usize, index: usize,
                   segment_length: usize, lane_length: usize,
                   same_lane: bool) -> usize {
    // How many blocks are visible from here.
    let area = if pass == 0 {
        if slice == 0 {
            index - 1
        } else if same_lane {
            slice * segment_length + index - 1
        } else {
            slice * segment_length - usize::from(index == 0)
        }
    } else if same_lane {
        lane_length - segment_length + index - 1
    } else {
        lane_length - segment_length - usize::from(index == 0)
    };

    // relative = area - 1 - area * (J1^2 >> 32) >> 32, all in 64 bits.
    let mut relative = j1;
    relative = (relative * relative) >> 32;
    relative = (area as u64) - 1 - (((area as u64) * relative) >> 32);

    // Later passes start from the slice *after* this one, so the window
    // wraps around the lane rather than reaching backwards only. The
    // last slice wraps to zero, which is the same value the first pass
    // uses for a different reason - the first pass has nothing above it
    // yet, the last slice has wrapped past the top.
    let start = if pass == 0 || slice == SLICES - 1 {
        0
    } else {
        (slice + 1) * segment_length
    };
    ((start as u64 + relative) % lane_length as u64) as usize
}

/// Generate the next 128 data-independent addresses.
///
/// `G` applied twice to a counter block, which is what makes the
/// addresses unpredictable without being derived from the password.
fn next_addresses(input: &mut Block, addresses: &mut Block) {
    input[6] += 1;
    let zero = [0u64; BLOCK_WORDS];
    let once = g(&zero, input);
    *addresses = g(&zero, &once);
}

/// The compression function G, RFC 9106 section 3.5.
///
/// `R = X xor Y`, then the permutation `P` along the **rows** of `R`,
/// then `P` along the **columns** of that, then XOR `R` back in. Doing
/// the same direction twice produces a plausible avalanche and a wrong
/// answer; leaving out the final XOR makes it invertible.
fn g(x: &Block, y: &Block) -> Block {
    let mut r = [0u64; BLOCK_WORDS];
    for index in 0..BLOCK_WORDS {
        r[index] = x[index] ^ y[index];
    }
    let mut q = r;

    // Rows: eight groups of sixteen consecutive words.
    for row in 0..8 {
        let at = row * 16;
        let mut v: [u64; 16] = q[at..at + 16].try_into().expect("16 words");
        permute(&mut v);
        q[at..at + 16].copy_from_slice(&v);
    }

    // Columns: the block is an 8x8 grid of 16 byte registers, so column
    // `c` is words 2c, 2c+1, 2c+16, 2c+17, .. - a stride of 16, two
    // words at a time. Reading it as a stride of 8 single words is the
    // plausible misreading.
    let mut z = q;
    for column in 0..8 {
        let mut v = [0u64; 16];
        for step in 0..8 {
            v[step * 2] = z[step * 16 + column * 2];
            v[step * 2 + 1] = z[step * 16 + column * 2 + 1];
        }
        permute(&mut v);
        for step in 0..8 {
            z[step * 16 + column * 2] = v[step * 2];
            z[step * 16 + column * 2 + 1] = v[step * 2 + 1];
        }
    }

    for index in 0..BLOCK_WORDS {
        z[index] ^= r[index];
    }
    z
}

/// The permutation P: BLAKE2b's round, over sixteen words, with `GB`.
fn permute(v: &mut [u64; 16]) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// GB, RFC 9106 section 3.5.
///
/// BLAKE2b's G with one change, and it is the important one: each
/// addition also adds `2 * trunc(a) * trunc(b)`, where `trunc` is the
/// low 32 bits. That 64 bit multiply is what gives the function a long
/// critical path in hardware, which is the point of it. An
/// implementation without it is faster, self-consistent and wrong.
#[inline]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    #[inline]
    fn mix(x: u64, y: u64) -> u64 {
        let product = 2u64
            .wrapping_mul(x & 0xffff_ffff)
            .wrapping_mul(y & 0xffff_ffff);
        x.wrapping_add(y).wrapping_add(product)
    }
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// H', RFC 9106 section 3.3: BLAKE2b stretched to any length.
///
/// **Not BLAKE2b.** Up to 64 bytes it is one BLAKE2b of `LE32(T) || A`
/// at that output length; beyond that it is a chain of 64 byte digests
/// of which only the **first 32 bytes of each** are kept, with the last
/// block taking whatever remains. Using plain BLAKE2b for the 1024 byte
/// blocks gives an Argon2 that is perfectly self-consistent and agrees
/// with no other implementation.
fn variable_hash(input: &[u8], length: usize) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(input.len() + 4);
    prefixed.extend_from_slice(&(length as u32).to_le_bytes());
    prefixed.extend_from_slice(input);

    if length <= 64 {
        let mut hash = Blake2b::with_params(&Params {
            digest_len: length, ..Params::default()
        }).expect("1..=64 is always a valid BLAKE2b length");
        hash.update(&prefixed);
        return hash.digest();
    }

    let mut out = Vec::with_capacity(length);
    let mut block = {
        let mut hash = Blake2b::new(&[]);
        hash.update(&prefixed);
        hash.digest()
    };
    out.extend_from_slice(&block[..32]);

    // r = ceil(T/32) - 2 further full digests, then a final shorter one.
    let rounds = length.div_ceil(32) - 2;
    for _ in 1..rounds {
        block = {
            let mut hash = Blake2b::new(&[]);
            hash.update(&block);
            hash.digest()
        };
        out.extend_from_slice(&block[..32]);
    }

    let remaining = length - 32 * rounds;
    let mut hash = Blake2b::with_params(&Params {
        digest_len: remaining, ..Params::default()
    }).expect("the remainder is 1..=64 by construction");
    hash.update(&block);
    out.extend_from_slice(&hash.digest());
    out.truncate(length);
    out
}

fn block_from_bytes(bytes: &[u8]) -> Block {
    let mut block = [0u64; BLOCK_WORDS];
    for (index, word) in block.iter_mut().enumerate() {
        let at = index * 8;
        *word = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
    }
    block
}

fn block_to_bytes(block: &Block) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BLOCK_BYTES);
    for word in block {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// The parameters RFC 9106 section 5 uses for all three variants.
    fn rfc_parameters(variant: Variant) -> Argon2 {
        Argon2 {
            variant,
            memory_kib: 32,
            passes: 3,
            lanes: 4,
            secret: vec![0x03; 8],
            associated_data: vec![0x04; 12],
        }
    }

    const PASSWORD: [u8; 32] = [0x01; 32];
    const SALT: [u8; 16] = [0x02; 16];

    /// RFC 9106 section 5, the published tags for all three variants.
    ///
    /// Same parameters, same inputs, three answers - so this also pins
    /// that the variant reaches both the pre-hash and the addressing.
    #[test]
    fn test_rfc9106_tags() {
        for (variant, expected) in [
            (Variant::D, ARGON2D_TAG),
            (Variant::I, ARGON2I_TAG),
            (Variant::Id, ARGON2ID_TAG),
        ] {
            let got = rfc_parameters(variant)
                .derive(&PASSWORD, &SALT, 32).unwrap();
            assert_eq!(hex(&got), expected, "{}", variant.name());
        }
    }

    /// RFC 9106's "pre-hashing digest", the H0 of section 3.2.
    ///
    /// Checked separately because it is the one intermediate the RFC
    /// publishes, and because a wrong H0 fails the tag test in a way
    /// that says nothing about which of the eight length-prefixed
    /// fields was wrong.
    #[test]
    fn test_rfc9106_pre_hash() {
        for (variant, expected) in [
            (Variant::D, ARGON2D_H0),
            (Variant::I, ARGON2I_H0),
            (Variant::Id, ARGON2ID_H0),
        ] {
            let got = rfc_parameters(variant).pre_hash(&PASSWORD, &SALT, 32);
            assert_eq!(hex(&got), expected, "{} H0", variant.name());
        }
    }

    /// **H' is not BLAKE2b.**
    ///
    /// At 64 bytes and below it is one BLAKE2b with a length prefix;
    /// above that it is a chain keeping 32 bytes of each digest. An
    /// implementation that called BLAKE2b directly would pass nothing
    /// here - but would also pass every round-trip test, because it is
    /// still a deterministic function.
    #[test]
    fn test_the_variable_hash_is_not_plain_blake2b() {
        // Short: one BLAKE2b of LE32(T) || A at that length.
        let mut expected = Blake2b::with_length(32).unwrap();
        expected.update(&32u32.to_le_bytes());
        expected.update(b"input");
        assert_eq!(hex(&variable_hash(b"input", 32)), hex(&expected.digest()));

        // Long: must *not* be a BLAKE2b at all, and must not be a
        // prefix of the 64 byte answer either.
        let long = variable_hash(b"input", 1024);
        assert_eq!(long.len(), 1024);
        let sixty_four = variable_hash(b"input", 64);
        assert_ne!(&long[..64], &sixty_four[..],
                   "the long form is the short form extended, so the chain \
                    is not being used");

        // The chain keeps 32 bytes per digest, so bytes 0..32 of the
        // long output are the first 32 of a full 64 byte BLAKE2b.
        let mut first = Blake2b::new(&[]);
        first.update(&1024u32.to_le_bytes());
        first.update(b"input");
        assert_eq!(hex(&long[..32]), hex(&first.digest()[..32]));
    }

    /// The multiplication in GB is not optional.
    ///
    /// Without it GB is BLAKE2b's G, which is faster and produces a
    /// perfectly good avalanche - and a different function. This
    /// compares GB against that version directly rather than inferring
    /// it from the tag.
    #[test]
    fn test_gb_multiplies_the_low_halves() {
        let mut with = [0u64; 16];
        for (index, word) in with.iter_mut().enumerate() {
            *word = 0x0123_4567_89ab_cdefu64.wrapping_mul(index as u64 + 1);
        }
        let mut without = with;

        gb(&mut with, 0, 4, 8, 12);

        // The same rounds with plain additions.
        let (a, b, c, d) = (0usize, 4usize, 8usize, 12usize);
        without[a] = without[a].wrapping_add(without[b]);
        without[d] = (without[d] ^ without[a]).rotate_right(32);
        without[c] = without[c].wrapping_add(without[d]);
        without[b] = (without[b] ^ without[c]).rotate_right(24);
        without[a] = without[a].wrapping_add(without[b]);
        without[d] = (without[d] ^ without[a]).rotate_right(16);
        without[c] = without[c].wrapping_add(without[d]);
        without[b] = (without[b] ^ without[c]).rotate_right(63);

        assert_ne!(with, without,
                   "GB behaved as BLAKE2b's G, so the 2*trunc(a)*trunc(b) \
                    term is missing");
    }

    /// G permutes rows and then columns, not one direction twice.
    #[test]
    fn test_g_mixes_rows_and_then_columns() {
        let x: Block = core::array::from_fn(|i| i as u64);
        let y: Block = core::array::from_fn(|i| (i as u64) << 32);
        let correct = g(&x, &y);

        // Rows twice, which is the plausible mistake.
        let mut r = [0u64; BLOCK_WORDS];
        for index in 0..BLOCK_WORDS {
            r[index] = x[index] ^ y[index];
        }
        let mut wrong = r;
        for _ in 0..2 {
            for row in 0..8 {
                let at = row * 16;
                let mut v: [u64; 16] = wrong[at..at + 16].try_into().unwrap();
                permute(&mut v);
                wrong[at..at + 16].copy_from_slice(&v);
            }
        }
        for index in 0..BLOCK_WORDS {
            wrong[index] ^= r[index];
        }
        assert_ne!(correct, wrong, "G permuted rows twice instead of rows then columns");
    }

    /// G's final XOR is what makes it one-way.
    #[test]
    fn test_g_xors_its_input_back() {
        let x: Block = core::array::from_fn(|i| (i as u64).wrapping_mul(7));
        let y: Block = core::array::from_fn(|i| (i as u64).wrapping_mul(11));
        let out = g(&x, &y);
        let mut r = [0u64; BLOCK_WORDS];
        for index in 0..BLOCK_WORDS {
            r[index] = x[index] ^ y[index];
        }
        // Undoing the final XOR must change the answer.
        let mut without = out;
        for index in 0..BLOCK_WORDS {
            without[index] ^= r[index];
        }
        assert_ne!(out, without, "G did not XOR R back in");
    }

    /// The address counter advances between blocks of addresses.
    ///
    /// One address block holds 128 addresses, so a segment shorter than
    /// that needs only one and the counter is never used twice. Every
    /// RFC 9106 vector uses 32 KiB over 4 lanes, which is two blocks
    /// per segment - so an implementation that *set* the counter to 1
    /// instead of incrementing it passes all three of them, and only
    /// fails once somebody asks for a segment longer than 128 blocks.
    /// That is 2 MiB, which is the smallest parameter set anybody
    /// actually uses.
    #[test]
    fn test_the_address_counter_advances() {
        let mut input = [0u64; BLOCK_WORDS];
        let mut first = [0u64; BLOCK_WORDS];
        let mut second = [0u64; BLOCK_WORDS];
        next_addresses(&mut input, &mut first);
        next_addresses(&mut input, &mut second);
        assert_ne!(first, second,
                   "two consecutive address blocks are identical, so the \
                    counter is not advancing");
        assert_eq!(input[6], 2, "the counter is not at 2 after two calls");
    }

    /// The three variants differ, with everything else held still.
    ///
    /// Argon2id must equal neither of the others: it is Argon2i for the
    /// first half of the first pass and Argon2d after, so an
    /// implementation that got the boundary wrong in either direction
    /// collapses onto one of them.
    #[test]
    fn test_the_three_variants_are_three_functions() {
        let d = rfc_parameters(Variant::D).derive(&PASSWORD, &SALT, 32).unwrap();
        let i = rfc_parameters(Variant::I).derive(&PASSWORD, &SALT, 32).unwrap();
        let id = rfc_parameters(Variant::Id).derive(&PASSWORD, &SALT, 32).unwrap();
        assert_ne!(d, i);
        assert_ne!(d, id, "argon2id collapsed onto argon2d");
        assert_ne!(i, id, "argon2id collapsed onto argon2i");
    }

    /// Every parameter reaches the answer.
    #[test]
    fn test_every_parameter_changes_the_tag() {
        let base = rfc_parameters(Variant::Id).derive(&PASSWORD, &SALT, 32).unwrap();

        let mut more_passes = rfc_parameters(Variant::Id);
        more_passes.passes = 4;
        assert_ne!(base, more_passes.derive(&PASSWORD, &SALT, 32).unwrap(), "t");

        let mut more_memory = rfc_parameters(Variant::Id);
        more_memory.memory_kib = 64;
        assert_ne!(base, more_memory.derive(&PASSWORD, &SALT, 32).unwrap(), "m");

        let mut more_lanes = rfc_parameters(Variant::Id);
        more_lanes.lanes = 2;
        assert_ne!(base, more_lanes.derive(&PASSWORD, &SALT, 32).unwrap(), "p");

        let mut other_secret = rfc_parameters(Variant::Id);
        other_secret.secret = vec![0x05; 8];
        assert_ne!(base, other_secret.derive(&PASSWORD, &SALT, 32).unwrap(), "K");

        let mut other_ad = rfc_parameters(Variant::Id);
        other_ad.associated_data = vec![0x06; 12];
        assert_ne!(base, other_ad.derive(&PASSWORD, &SALT, 32).unwrap(), "X");

        let other_salt = rfc_parameters(Variant::Id)
            .derive(&PASSWORD, &[0x07; 16], 32).unwrap();
        assert_ne!(base, other_salt, "S");
    }

    /// A longer tag is **not** an extension of a shorter one - the
    /// length goes into H0 and into H'.
    #[test]
    fn test_the_tag_length_is_not_a_truncation() {
        let short = rfc_parameters(Variant::Id).derive(&PASSWORD, &SALT, 32).unwrap();
        let long = rfc_parameters(Variant::Id).derive(&PASSWORD, &SALT, 64).unwrap();
        assert_ne!(&short[..], &long[..32],
                   "the tag length did not reach the pre-hash");
    }

    #[test]
    fn test_bad_parameters_are_errors() {
        let mut argon = rfc_parameters(Variant::Id);
        assert!(argon.derive(&PASSWORD, &[0u8; 7], 32).is_err(), "short salt");
        assert!(argon.derive(&PASSWORD, &SALT, 3).is_err(), "short tag");
        argon.lanes = 0;
        assert!(argon.derive(&PASSWORD, &SALT, 32).is_err(), "no lanes");
        argon = rfc_parameters(Variant::Id);
        argon.passes = 0;
        assert!(argon.derive(&PASSWORD, &SALT, 32).is_err(), "no passes");
        argon = rfc_parameters(Variant::Id);
        argon.memory_kib = 8;   // needs 8 * 4 lanes
        assert!(argon.derive(&PASSWORD, &SALT, 32).is_err(), "too little memory");
    }

    /// `Argon2` derived `Debug`, so `{:?}` printed the pepper. No test
    /// formatted the parameters; nothing checked what came out.
    #[test]
    fn test_debug_does_not_print_the_secret() {
        let argon = rfc_parameters(Variant::Id);
        assert_eq!(argon.secret, vec![0x03; 8]);
        let shown = format!("{:?}", argon);
        assert!(!shown.contains("3, 3, 3"), "{shown}");
        assert!(shown.contains("secret: [8 bytes]"), "{shown}");
        assert!(shown.contains("memory_kib: 32"), "{shown}");
    }

    /// `memory_kib` is a `u32` and the only check was that the block
    /// count times 1024 fits in `usize`, so `u32::MAX` (4 TiB) passed
    /// and reached the allocator, where failure is an abort. `8 *
    /// lanes` was computed in `u32` and overflowed for a lane count
    /// past 2^29. The existing tests used the RFC's 32 KiB. Every
    /// request here is refused before any allocation.
    #[test]
    fn test_oversized_parameters_are_errors_not_aborts() {
        let mut argon = rfc_parameters(Variant::Id);
        argon.memory_kib = u32::MAX;
        let reason = argon.derive(&PASSWORD, &SALT, 32).unwrap_err();
        assert!(reason.contains("at most"), "{reason}");
        argon.memory_kib = MAX_MEMORY_KIB + 1;
        assert!(argon.derive(&PASSWORD, &SALT, 32).is_err());

        argon = rfc_parameters(Variant::Id);
        argon.lanes = u32::MAX;
        assert!(argon.derive(&PASSWORD, &SALT, 32).unwrap_err().contains("lanes"));
        argon.lanes = MAX_LANES + 1;
        assert!(argon.derive(&PASSWORD, &SALT, 32).is_err());
        // The most lanes allowed, with too little memory for them: the
        // per-lane check must not overflow on the way to its answer.
        argon.lanes = MAX_LANES;
        argon.memory_kib = u32::MAX;
        assert!(argon.derive(&PASSWORD, &SALT, 32).is_err());

        argon = rfc_parameters(Variant::Id);
        assert!(argon.derive(&PASSWORD, &SALT, usize::MAX).unwrap_err()
                    .contains("too long"));
    }

    // Read out of RFC 9106 rather than typed.
    const ARGON2D_H0: &str = "b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109";
    const ARGON2I_H0: &str = "c46065815276a0b3e731731c902f1fd80cf776907fbb7b6a5ca72e7b56011feeca446c86dd75b9469a5e6879dec4b72d0863fb939b982e5f397cc7d164fddaa9";
    const ARGON2ID_H0: &str = "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997";
    const ARGON2D_TAG: &str = "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb";
    const ARGON2I_TAG: &str = "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8";
    const ARGON2ID_TAG: &str = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
}
