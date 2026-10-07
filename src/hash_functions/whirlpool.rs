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

## Whirlpool-0 and Whirlpool-T

The function was revised twice. Whirlpool-0 (2000) had an S-box with no
structure - 256 bytes chosen at random - and the circulant row
`(1, 1, 3, 1, 5, 8, 9, 5)`. Whirlpool-T (2001) replaced the S-box with
the generated one above; the final Whirlpool (2003) then replaced the
row with `(1, 1, 4, 1, 8, 5, 2, 9)`. Round constants are taken from
each version's own S-box by the same rule. Only the final one is
standardised; the other two are in NESSIE's submissions and in older
software.

Whirlpool-0's S-box cannot be generated, so it is the one table here
that is written out. It was read programmatically out of two
implementations and the two agree: the packed string GNU Crypto's
`Whirlpool2000` carries (citing page 19 of the 2000 specification), and
the coefficient-1 column of sphlib's `old0_T0`. The rows above were
recovered from sphlib's tables the same way, coefficient by coefficient.
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
/// Whirlpool-0's and Whirlpool-T's row.
const CIRCULANT_2000: [u8; 8] = [1, 1, 3, 1, 5, 8, 9, 5];

/// Whirlpool-0's S-box; see the module notes for where it came from.
const SBOX_0: [u8; 256] = [
    0x68, 0xd0, 0xeb, 0x2b, 0x48, 0x9d, 0x6a, 0xe4, 0xe3, 0xa3, 0x56, 0x81, 0x7d, 0xf1, 0x85, 0x9e,
    0x2c, 0x8e, 0x78, 0xca, 0x17, 0xa9, 0x61, 0xd5, 0x5d, 0x0b, 0x8c, 0x3c, 0x77, 0x51, 0x22, 0x42,
    0x3f, 0x54, 0x41, 0x80, 0xcc, 0x86, 0xb3, 0x18, 0x2e, 0x57, 0x06, 0x62, 0xf4, 0x36, 0xd1, 0x6b,
    0x1b, 0x65, 0x75, 0x10, 0xda, 0x49, 0x26, 0xf9, 0xcb, 0x66, 0xe7, 0xba, 0xae, 0x50, 0x52, 0xab,
    0x05, 0xf0, 0x0d, 0x73, 0x3b, 0x04, 0x20, 0xfe, 0xdd, 0xf5, 0xb4, 0x5f, 0x0a, 0xb5, 0xc0, 0xa0,
    0x71, 0xa5, 0x2d, 0x60, 0x72, 0x93, 0x39, 0x08, 0x83, 0x21, 0x5c, 0x87, 0xb1, 0xe0, 0x00, 0xc3,
    0x12, 0x91, 0x8a, 0x02, 0x1c, 0xe6, 0x45, 0xc2, 0xc4, 0xfd, 0xbf, 0x44, 0xa1, 0x4c, 0x33, 0xc5,
    0x84, 0x23, 0x7c, 0xb0, 0x25, 0x15, 0x35, 0x69, 0xff, 0x94, 0x4d, 0x70, 0xa2, 0xaf, 0xcd, 0xd6,
    0x6c, 0xb7, 0xf8, 0x09, 0xf3, 0x67, 0xa4, 0xea, 0xec, 0xb6, 0xd4, 0xd2, 0x14, 0x1e, 0xe1, 0x24,
    0x38, 0xc6, 0xdb, 0x4b, 0x7a, 0x3a, 0xde, 0x5e, 0xdf, 0x95, 0xfc, 0xaa, 0xd7, 0xce, 0x07, 0x0f,
    0x3d, 0x58, 0x9a, 0x98, 0x9c, 0xf2, 0xa7, 0x11, 0x7e, 0x8b, 0x43, 0x03, 0xe2, 0xdc, 0xe5, 0xb2,
    0x4e, 0xc7, 0x6d, 0xe9, 0x27, 0x40, 0xd8, 0x37, 0x92, 0x8f, 0x01, 0x1d, 0x53, 0x3e, 0x59, 0xc1,
    0x4f, 0x32, 0x16, 0xfa, 0x74, 0xfb, 0x63, 0x9f, 0x34, 0x1a, 0x2a, 0x5a, 0x8d, 0xc9, 0xcf, 0xf6,
    0x90, 0x28, 0x88, 0x9b, 0x31, 0x0e, 0xbd, 0x4a, 0xe8, 0x96, 0xa6, 0x0c, 0xc8, 0x79, 0xbc, 0xbe,
    0xef, 0x6e, 0x46, 0x97, 0x5b, 0xed, 0x19, 0xd9, 0xac, 0x99, 0xa8, 0x29, 0x64, 0x1f, 0xad, 0x55,
    0x13, 0xbb, 0xf7, 0x6f, 0xb9, 0x47, 0x2f, 0xee, 0xb8, 0x7b, 0x89, 0x30, 0xd3, 0x7f, 0x76, 0x82,
];

/// The eight lookup tables that fold the substitution, the shift and the
/// matrix multiply into one indexed XOR each.
///
/// Built at compile time. Row `t` of the state is formed by XORing
/// `C[t][byte]` over the eight bytes that feed it, which is the standard
/// way to implement an AES-shaped cipher and is what makes hashing a
/// hundred kilobytes fast enough for the differential corpus to sweep
/// it.
const C: [[u64; 256]; 8] = tables(&SBOX, CIRCULANT);
const C_T: [[u64; 256]; 8] = tables(&SBOX, CIRCULANT_2000);
const C_0: [[u64; 256]; 8] = tables(&SBOX_0, CIRCULANT_2000);

const fn tables(sbox: &[u8; 256], circulant: [u8; 8]) -> [[u64; 256]; 8] {
    let mut tables = [[0u64; 256]; 8];
    let mut x = 0usize;
    while x < 256 {
        let s = sbox[x];
        // The first table holds the matrix row applied to S[x]; the
        // rest are that value rotated right by eight bits each, which
        // is what makes the matrix circulant.
        let mut value = 0u64;
        let mut j = 0;
        while j < 8 {
            value |= (gf_mul(s, circulant[j]) as u64) << (56 - 8 * j);
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
}

/// The ten round constants. Row zero is eight successive S-box entries
/// and the other seven rows are zero, so each constant is one `u64`.
const RC: [u64; ROUNDS] = constants(&SBOX);
const RC_0: [u64; ROUNDS] = constants(&SBOX_0);

const fn constants(sbox: &[u8; 256]) -> [u64; ROUNDS] {
    let mut rc = [0u64; ROUNDS];
    let mut r = 0usize;
    while r < ROUNDS {
        let mut value = 0u64;
        let mut j = 0;
        while j < 8 {
            value |= (sbox[8 * r + j] as u64) << (56 - 8 * j);
            j += 1;
        }
        rc[r] = value;
        r += 1;
    }
    rc
}

/// Which of the three versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// Whirlpool-0, 2000.
    Zero,
    /// Whirlpool-T, 2001.
    Tweaked,
    /// Whirlpool, 2003, ISO/IEC 10118-3.
    Final,
}

impl Version {
    fn tables(self) -> (&'static [[u64; 256]; 8], &'static [u64; ROUNDS]) {
        match self {
            Version::Zero => (&C_0, &RC_0),
            Version::Tweaked => (&C_T, &RC),
            Version::Final => (&C, &RC),
        }
    }
}

/// One round of `W` applied to `state` with round key `key`, written
/// into `out`.
fn round(c: &[[u64; 256]; 8], state: &[u64; 8], key: &[u64; 8], out: &mut [u64; 8]) {
    for (i, slot) in out.iter_mut().enumerate() {
        let mut value = 0u64;
        for t in 0..8 {
            // Row `i` of the result takes byte `t` of row `i - t`,
            // which is the cyclic column shift and the matrix multiply
            // together.
            let byte = (state[(i + 8 - t) % 8] >> (56 - 8 * t)) & 0xff;
            value ^= c[t][byte as usize];
        }
        *slot = value ^ key[i];
    }
}

#[derive(Clone)]
pub struct Whirlpool {
    version: Version,
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
        Whirlpool::of_version(Version::Final, data)
    }

    pub fn of_version(version: Version, data: &[u8]) -> Whirlpool {
        let mut whirlpool = Whirlpool {
            version,
            hash: [0; 8],
            buffer: BlockBuffer::default(),
            bits: 0,
        };
        whirlpool.update(data);
        whirlpool
    }

    /// Miyaguchi-Preneel: `H' = W[H](M) ^ M ^ H`.
    fn compress(version: Version, hash: &mut [u64; 8], block: &[u8; BLOCK]) {
        let (c, rcs) = version.tables();
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
        for rc in rcs.iter() {
            let constant = [*rc, 0, 0, 0, 0, 0, 0, 0];
            round(c, &key, &constant, &mut next_key);
            key = next_key;
            round(c, &state, &key, &mut next_state);
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
            Whirlpool::compress(self.version, &mut hash,
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
        match self.version {
            Version::Zero => "Whirlpool-0",
            Version::Tweaked => "Whirlpool-T",
            Version::Final => "Whirlpool",
        }.to_string()
    }

    fn digest_len(&self) -> usize {
        DIGEST
    }

    fn block_size(&self) -> usize {
        BLOCK
    }

    fn update(&mut self, input: &[u8]) {
        self.bits = self.bits.wrapping_add(input.len() as u128 * 8);
        let (version, hash) = (self.version, &mut self.hash);
        self.buffer.feed(input, |block| Whirlpool::compress(version, hash, block));
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
                Whirlpool::compress(Version::Final, &mut hash, block);
                // Undo the `^ H` that `compress` applied.
                for i in 0..8 {
                    hash[i] ^= before[i];
                }
            }
            hash
        }

        let one_block = [0x41u8; BLOCK];
        let mut ours = [0u64; 8];
        Whirlpool::compress(Version::Final, &mut ours, &one_block);
        assert_eq!(ours, without_the_chaining_value(&one_block),
                   "the two constructions agree on the first block");

        let two_blocks = [0x41u8; BLOCK * 2];
        let mut ours = [0u64; 8];
        for chunk in two_blocks.chunks_exact(BLOCK) {
            Whirlpool::compress(Version::Final, &mut ours, chunk.try_into().unwrap());
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
