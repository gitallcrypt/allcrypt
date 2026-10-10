/*
Streebog (GOST R 34.11-2012), the Russian hash, in its 256 and 512 bit
forms.

A Merkle-Damgard construction over a 512 bit state with a block cipher
compression function, plus two finalisation steps that nothing else has:
after the message, the *bit length* is hashed, and then the sum of every
block as a 512 bit integer.

    g(N, h, m) = E(LPS(h xor N), m) xor h xor m
    E(K, m)    = twelve rounds of LPS under a key schedule of its own

Four things an implementation gets wrong, and every one of them produces a
hash that is a perfectly good hash and is not Streebog:

  * **The state is a little endian 512 bit integer.** Both running sums -
    the length counter N and the checksum Sigma - are additions modulo
    2^512 over the byte array read *least significant byte first*. Reading
    it the other way gives a hash that differs only once the message is
    long enough to carry, which is to say on the second block.

  * **`pi_0` indexes the byte at position 0.** The linear layer's table is
    keyed by byte position, and the two ends are not interchangeable.

  * **The padding byte is 0x01 and it goes immediately after the
    message**, not at the end of the block. The rest of the block is
    zeros. A message that exactly fills a block still gets a whole extra
    padded block.

  * **The 256 bit digest is the *last* 32 bytes of the state**, not the
    first, and its IV is sixty-four 0x01 bytes rather than zeros. Taking
    the first half gives a hash with no collisions anybody knows about and
    no agreement with anyone.

And one that is not an implementation mistake but reads like one:

  * **The standard prints its test vectors reversed.** GOST R 34.11-2012
    writes messages and digests as 512 bit numbers, most significant byte
    on the left, while every implementation - and this one - works on byte
    strings in order. So the standard's M1, fed in as bytes, is the
    message backwards, and its expected digest is this one's output
    backwards. An implementer who does not know that cannot tell whether
    the code or the byte order is wrong, because both give the same
    symptom. `tests` uses the standard's messages *reversed* and says so.

Nothing on this machine implements Streebog: OpenSSL here has no GOST
engine, `hashlib` has never had one, and `python-cryptography` does not
offer it. So the second implementation is a second reading of the
specification, in `scripts/diff_check.py`, and the constants were not
typed from memory - `A`, `PI` and `C` together reproduce the precomputed
linear table in the gost-engine project byte for byte, and `C` matches its
constants word for word. Two implementations with no common ancestor.
*/

use crate::hash_functions::HashFunction;

/// The block and state size in bytes.
pub const BLOCK_SIZE: usize = 64;

/// The linear transform's 64 basis vectors, GOST R 34.11-2012 section 6.
const A: [u64; 64] = [
    0x641c314b2b8ee083, 0xc83862965601dd1b, 0x8d70c431ac02a736, 0x07e095624504536c,
    0x0edd37c48a08a6d8, 0x1ca76e95091051ad, 0x3853dc371220a247, 0x70a6a56e2440598e,
    0xa48b474f9ef5dc18, 0x550b8e9e21f7a530, 0xaa16012142f35760, 0x492c024284fbaec0,
    0x9258048415eb419d, 0x39b008152acb8227, 0x727d102a548b194e, 0xe4fa2054a80b329c,
    0xf97d86d98a327728, 0xeffa11af0964ee50, 0xc3e9224312c8c1a0, 0x9bcf4486248d9f5d,
    0x2b838811480723ba, 0x561b0d22900e4669, 0xac361a443d1c8cd2, 0x456c34887a3805b9,
    0x5b068c651810a89e, 0xb60c05ca30204d21, 0x71180a8960409a42, 0xe230140fc0802984,
    0xd960281e9d1d5215, 0xafc0503c273aa42a, 0x439da0784e745554, 0x86275df09ce8aaa8,
    0x0321658cba93c138, 0x0642ca05693b9f70, 0x0c84890ad27623e0, 0x18150f14b9ec46dd,
    0x302a1e286fc58ca7, 0x60543c50de970553, 0xc0a878a0a1330aa6, 0x9d4df05d5f661451,
    0xaccc9ca9328a8950, 0x4585254f64090fa0, 0x8a174a9ec8121e5d, 0x092e94218d243cba,
    0x125c354207487869, 0x24b86a840e90f0d2, 0x486dd4151c3dfdb9, 0x90dab52a387ae76f,
    0x46b60f011a83988e, 0x8c711e02341b2d01, 0x05e23c0468365a02, 0x0ad97808d06cb404,
    0x14aff010bdd87508, 0x2843fd2067adea10, 0x5086e740ce47c920, 0xa011d380818e8f40,
    0x83478b07b2468764, 0x1b8e0b0e798c13c8, 0x3601161cf205268d, 0x6c022c38f90a4c07,
    0xd8045870ef14980e, 0xad08b0e0c3282d1c, 0x47107ddd9b505a38, 0x8e20faa72ba0b470,
];

/// The `pi` substitution, GOST R 34.11-2012 section 6.
const PI: [u8; 256] = [
    0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
    0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
    0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
    0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
    0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab, 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
    0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
    0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
    0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e, 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
    0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
    0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
    0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44, 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
    0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
    0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
    0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe, 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
    0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6,
];

/// The twelve iteration constants, GOST R 34.11-2012 section 7.
const C: [[u8; 64]; 12] = [
    [
        0x07, 0x45, 0xa6, 0xf2, 0x59, 0x65, 0x80, 0xdd, 0x23, 0x4d, 0x74, 0xcc, 0x36, 0x74, 0x76, 0x05,
        0x15, 0xd3, 0x60, 0xa4, 0x08, 0x2a, 0x42, 0xa2, 0x01, 0x69, 0x67, 0x92, 0x91, 0xe0, 0x7c, 0x4b,
        0xfc, 0xc4, 0x85, 0x75, 0x8d, 0xb8, 0x4e, 0x71, 0x16, 0xd0, 0x45, 0x2e, 0x43, 0x76, 0x6a, 0x2f,
        0x1f, 0x7c, 0x65, 0xc0, 0x81, 0x2f, 0xcb, 0xeb, 0xe9, 0xda, 0xca, 0x1e, 0xda, 0x5b, 0x08, 0xb1,
    ],
    [
        0xb7, 0x9b, 0xb1, 0x21, 0x70, 0x04, 0x79, 0xe6, 0x56, 0xcd, 0xcb, 0xd7, 0x1b, 0xa2, 0xdd, 0x55,
        0xca, 0xa7, 0x0a, 0xdb, 0xc2, 0x61, 0xb5, 0x5c, 0x58, 0x99, 0xd6, 0x12, 0x6b, 0x17, 0xb5, 0x9a,
        0x31, 0x01, 0xb5, 0x16, 0x0f, 0x5e, 0xd5, 0x61, 0x98, 0x2b, 0x23, 0x0a, 0x72, 0xea, 0xfe, 0xf3,
        0xd7, 0xb5, 0x70, 0x0f, 0x46, 0x9d, 0xe3, 0x4f, 0x1a, 0x2f, 0x9d, 0xa9, 0x8a, 0xb5, 0xa3, 0x6f,
    ],
    [
        0xb2, 0x0a, 0xba, 0x0a, 0xf5, 0x96, 0x1e, 0x99, 0x31, 0xdb, 0x7a, 0x86, 0x43, 0xf4, 0xb6, 0xc2,
        0x09, 0xdb, 0x62, 0x60, 0x37, 0x3a, 0xc9, 0xc1, 0xb1, 0x9e, 0x35, 0x90, 0xe4, 0x0f, 0xe2, 0xd3,
        0x7b, 0x7b, 0x29, 0xb1, 0x14, 0x75, 0xea, 0xf2, 0x8b, 0x1f, 0x9c, 0x52, 0x5f, 0x5e, 0xf1, 0x06,
        0x35, 0x84, 0x3d, 0x6a, 0x28, 0xfc, 0x39, 0x0a, 0xc7, 0x2f, 0xce, 0x2b, 0xac, 0xdc, 0x74, 0xf5,
    ],
    [
        0x2e, 0xd1, 0xe3, 0x84, 0xbc, 0xbe, 0x0c, 0x22, 0xf1, 0x37, 0xe8, 0x93, 0xa1, 0xea, 0x53, 0x34,
        0xbe, 0x03, 0x52, 0x93, 0x33, 0x13, 0xb7, 0xd8, 0x75, 0xd6, 0x03, 0xed, 0x82, 0x2c, 0xd7, 0xa9,
        0x3f, 0x35, 0x5e, 0x68, 0xad, 0x1c, 0x72, 0x9d, 0x7d, 0x3c, 0x5c, 0x33, 0x7e, 0x85, 0x8e, 0x48,
        0xdd, 0xe4, 0x71, 0x5d, 0xa0, 0xe1, 0x48, 0xf9, 0xd2, 0x66, 0x15, 0xe8, 0xb3, 0xdf, 0x1f, 0xef,
    ],
    [
        0x57, 0xfe, 0x6c, 0x7c, 0xfd, 0x58, 0x17, 0x60, 0xf5, 0x63, 0xea, 0xa9, 0x7e, 0xa2, 0x56, 0x7a,
        0x16, 0x1a, 0x27, 0x23, 0xb7, 0x00, 0xff, 0xdf, 0xa3, 0xf5, 0x3a, 0x25, 0x47, 0x17, 0xcd, 0xbf,
        0xbd, 0xff, 0x0f, 0x80, 0xd7, 0x35, 0x9e, 0x35, 0x4a, 0x10, 0x86, 0x16, 0x1f, 0x1c, 0x15, 0x7f,
        0x63, 0x23, 0xa9, 0x6c, 0x0c, 0x41, 0x3f, 0x9a, 0x99, 0x47, 0x47, 0xad, 0xac, 0x6b, 0xea, 0x4b,
    ],
    [
        0x6e, 0x7d, 0x64, 0x46, 0x7a, 0x40, 0x68, 0xfa, 0x35, 0x4f, 0x90, 0x36, 0x72, 0xc5, 0x71, 0xbf,
        0xb6, 0xc6, 0xbe, 0xc2, 0x66, 0x1f, 0xf2, 0x0a, 0xb4, 0xb7, 0x9a, 0x1c, 0xb7, 0xa6, 0xfa, 0xcf,
        0xc6, 0x8e, 0xf0, 0x9a, 0xb4, 0x9a, 0x7f, 0x18, 0x6c, 0xa4, 0x42, 0x51, 0xf9, 0xc4, 0x66, 0x2d,
        0xc0, 0x39, 0x30, 0x7a, 0x3b, 0xc3, 0xa4, 0x6f, 0xd9, 0xd3, 0x3a, 0x1d, 0xae, 0xae, 0x4f, 0xae,
    ],
    [
        0x93, 0xd4, 0x14, 0x3a, 0x4d, 0x56, 0x86, 0x88, 0xf3, 0x4a, 0x3c, 0xa2, 0x4c, 0x45, 0x17, 0x35,
        0x04, 0x05, 0x4a, 0x28, 0x83, 0x69, 0x47, 0x06, 0x37, 0x2c, 0x82, 0x2d, 0xc5, 0xab, 0x92, 0x09,
        0xc9, 0x93, 0x7a, 0x19, 0x33, 0x3e, 0x47, 0xd3, 0xc9, 0x87, 0xbf, 0xe6, 0xc7, 0xc6, 0x9e, 0x39,
        0x54, 0x09, 0x24, 0xbf, 0xfe, 0x86, 0xac, 0x51, 0xec, 0xc5, 0xaa, 0xee, 0x16, 0x0e, 0xc7, 0xf4,
    ],
    [
        0x1e, 0xe7, 0x02, 0xbf, 0xd4, 0x0d, 0x7f, 0xa4, 0xd9, 0xa8, 0x51, 0x59, 0x35, 0xc2, 0xac, 0x36,
        0x2f, 0xc4, 0xa5, 0xd1, 0x2b, 0x8d, 0xd1, 0x69, 0x90, 0x06, 0x9b, 0x92, 0xcb, 0x2b, 0x89, 0xf4,
        0x9a, 0xc4, 0xdb, 0x4d, 0x3b, 0x44, 0xb4, 0x89, 0x1e, 0xde, 0x36, 0x9c, 0x71, 0xf8, 0xb7, 0x4e,
        0x41, 0x41, 0x6e, 0x0c, 0x02, 0xaa, 0xe7, 0x03, 0xa7, 0xc9, 0x93, 0x4d, 0x42, 0x5b, 0x1f, 0x9b,
    ],
    [
        0xdb, 0x5a, 0x23, 0x83, 0x51, 0x44, 0x61, 0x72, 0x60, 0x2a, 0x1f, 0xcb, 0x92, 0xdc, 0x38, 0x0e,
        0x54, 0x9c, 0x07, 0xa6, 0x9a, 0x8a, 0x2b, 0x7b, 0xb1, 0xce, 0xb2, 0xdb, 0x0b, 0x44, 0x0a, 0x80,
        0x84, 0x09, 0x0d, 0xe0, 0xb7, 0x55, 0xd9, 0x3c, 0x24, 0x42, 0x89, 0x25, 0x1b, 0x3a, 0x7d, 0x3a,
        0xde, 0x5f, 0x16, 0xec, 0xd8, 0x9a, 0x4c, 0x94, 0x9b, 0x22, 0x31, 0x16, 0x54, 0x5a, 0x8f, 0x37,
    ],
    [
        0xed, 0x9c, 0x45, 0x98, 0xfb, 0xc7, 0xb4, 0x74, 0xc3, 0xb6, 0x3b, 0x15, 0xd1, 0xfa, 0x98, 0x36,
        0xf4, 0x52, 0x76, 0x3b, 0x30, 0x6c, 0x1e, 0x7a, 0x4b, 0x33, 0x69, 0xaf, 0x02, 0x67, 0xe7, 0x9f,
        0x03, 0x61, 0x33, 0x1b, 0x8a, 0xe1, 0xff, 0x1f, 0xdb, 0x78, 0x8a, 0xff, 0x1c, 0xe7, 0x41, 0x89,
        0xf3, 0xf3, 0xe4, 0xb2, 0x48, 0xe5, 0x2a, 0x38, 0x52, 0x6f, 0x05, 0x80, 0xa6, 0xde, 0xbe, 0xab,
    ],
    [
        0x1b, 0x2d, 0xf3, 0x81, 0xcd, 0xa4, 0xca, 0x6b, 0x5d, 0xd8, 0x6f, 0xc0, 0x4a, 0x59, 0xa2, 0xde,
        0x98, 0x6e, 0x47, 0x7d, 0x1d, 0xcd, 0xba, 0xef, 0xca, 0xb9, 0x48, 0xea, 0xef, 0x71, 0x1d, 0x8a,
        0x79, 0x66, 0x84, 0x14, 0x21, 0x80, 0x01, 0x20, 0x61, 0x07, 0xab, 0xeb, 0xbb, 0x6b, 0xfa, 0xd8,
        0x94, 0xfe, 0x5a, 0x63, 0xcd, 0xc6, 0x02, 0x30, 0xfb, 0x89, 0xc8, 0xef, 0xd0, 0x9e, 0xcd, 0x7b,
    ],
    [
        0x20, 0xd7, 0x1b, 0xf1, 0x4a, 0x92, 0xbc, 0x48, 0x99, 0x1b, 0xb2, 0xd9, 0xd5, 0x17, 0xf4, 0xfa,
        0x52, 0x28, 0xe1, 0x88, 0xaa, 0xa4, 0x1d, 0xe7, 0x86, 0xcc, 0x91, 0x18, 0x9d, 0xef, 0x80, 0x5d,
        0x9b, 0x9f, 0x21, 0x30, 0xd4, 0x12, 0x20, 0xf8, 0x77, 0x1d, 0xdf, 0xbc, 0x32, 0x3c, 0xa4, 0xcd,
        0x7a, 0xb1, 0x49, 0x04, 0xb0, 0x80, 0x13, 0xd2, 0xba, 0x31, 0x16, 0xf1, 0x67, 0xe7, 0x8e, 0x37,
    ],
];

/// The linear table, precomputed once: `LPS[position][byte]` is the
/// contribution of `byte` at `position` to the output.
///
/// Built from `A` and `PI` rather than written out, so there is one copy
/// of the constants and the derivation is visible.
struct LinearTable([[u64; 256]; 8]);

impl LinearTable {
    const fn build() -> LinearTable {
        let mut table = [[0u64; 256]; 8];
        let mut position = 0;
        while position < 8 {
            let mut value = 0;
            while value < 256 {
                let mut accumulator = 0u64;
                let mut bit = 0;
                while bit < 8 {
                    if PI[value] & (1u8 << bit) != 0 {
                        accumulator ^= A[8 * position + bit];
                    }
                    bit += 1;
                }
                table[position][value] = accumulator;
                value += 1;
            }
            position += 1;
        }
        LinearTable(table)
    }
}

static LPS_TABLE: LinearTable = LinearTable::build();

/// The state, as eight little endian 64 bit words.
type State = [u64; 8];

fn to_state(bytes: &[u8]) -> State {
    let mut state = [0u64; 8];
    for (index, word) in state.iter_mut().enumerate() {
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&bytes[8 * index..8 * index + 8]);
        *word = u64::from_le_bytes(buffer);
    }
    state
}

fn to_bytes(state: &State) -> [u8; BLOCK_SIZE] {
    let mut out = [0u8; BLOCK_SIZE];
    for (index, word) in state.iter().enumerate() {
        out[8 * index..8 * index + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn xor(left: &State, right: &State) -> State {
    let mut out = [0u64; 8];
    for index in 0..8 {
        out[index] = left[index] ^ right[index];
    }
    out
}

/// `L(P(S(x)))`, the three transforms as one table lookup per byte.
fn lps(input: &State) -> State {
    let mut out = [0u64; 8];
    for (position, word) in input.iter().enumerate() {
        let row = &LPS_TABLE.0[position];
        for shift in 0..8 {
            out[shift] ^= row[((word >> (8 * shift)) & 0xff) as usize];
        }
    }
    out
}

fn xlps(left: &State, right: &State) -> State {
    lps(&xor(left, right))
}

/// The compression function, GOST R 34.11-2012 section 7.
fn g(h: &State, n: &State, m: &State) -> State {
    let mut key = xlps(h, n);
    let mut data = xlps(&key, m);
    for constant in C.iter().take(11) {
        key = xlps(&key, &to_state(constant));
        data = xlps(&key, &data);
    }
    key = xlps(&key, &to_state(&C[11]));
    data = xor(&key, &data);
    data = xor(&data, h);
    xor(&data, m)
}

/// Addition modulo 2^512, over the state read as a little endian integer.
///
/// The carry chain runs from word 0 upwards. Running it the other way is
/// invisible until a block sum carries out of a word, which is most
/// messages and not the short ones a first test uses.
fn add512(left: &State, right: &State) -> State {
    let mut out = [0u64; 8];
    let mut carry = 0u64;
    for index in 0..8 {
        let (sum, overflow_one) = left[index].overflowing_add(right[index]);
        let (sum, overflow_two) = sum.overflowing_add(carry);
        out[index] = sum;
        carry = u64::from(overflow_one) + u64::from(overflow_two);
    }
    out
}

/// Streebog, in whichever of its two sizes.
#[derive(Clone)]
pub struct Streebog {
    h: State,
    n: State,
    sigma: State,
    buffer: super::buffer::BlockBuffer<BLOCK_SIZE>,
    digest_bits: usize,
}

impl core::fmt::Debug for Streebog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Streebog-{}", self.digest_bits)
    }
}

impl Streebog {
    /// Streebog-512.
    pub fn new(input: &[u8]) -> Streebog {
        Streebog::with_size(512, input)
    }

    /// Streebog-256, which is a different hash rather than a truncation:
    /// its IV is sixty-four 0x01 bytes, so the two diverge from the first
    /// block.
    pub fn new_256(input: &[u8]) -> Streebog {
        Streebog::with_size(256, input)
    }

    fn with_size(digest_bits: usize, input: &[u8]) -> Streebog {
        let iv = if digest_bits == 256 { [0x01u8; BLOCK_SIZE] } else { [0u8; BLOCK_SIZE] };
        let mut hash = Streebog {
            h: to_state(&iv),
            n: [0u64; 8],
            sigma: [0u64; 8],
            buffer: super::buffer::BlockBuffer::default(),
            digest_bits,
        };
        hash.update(input);
        hash
    }

    fn absorb(&mut self, block: &[u8]) {
        let m = to_state(block);
        self.h = g(&self.h, &self.n, &m);
        let mut added = [0u64; 8];
        added[0] = (BLOCK_SIZE * 8) as u64;
        self.n = add512(&self.n, &added);
        self.sigma = add512(&self.sigma, &m);
    }
}

impl HashFunction for Streebog {
    fn name(&self) -> String {
        format!("streebog{}", self.digest_bits)
    }

    fn digest_len(&self) -> usize {
        self.digest_bits / 8
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn update(&mut self, input: &[u8]) {
        // The block logic lives in `BlockBuffer`, once, rather than as
        // another copy of the loop that has been wrong three times.
        let mut buffer = core::mem::take(&mut self.buffer);
        buffer.feed(input, |block| self.absorb(block));
        self.buffer = buffer;
    }

    /// The finalisation: pad, then hash the length, then hash the sum.
    ///
    /// Takes a copy, so the hash can be digested and carried on with -
    /// the same contract every other hash in this library has.
    fn digest(&mut self) -> Vec<u8> {
        let mut state = self.clone();

        let buffered = state.buffer.len();
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..buffered].copy_from_slice(state.buffer.buffered());
        // 0x01 immediately after the message, zeros to the end. A full
        // block still gets a whole padded block of its own: `update`
        // absorbs a block the moment it is complete, so `buffered` here is
        // 0..=63 and never 64.
        padded[buffered] = 0x01;

        let m = to_state(&padded);
        state.h = g(&state.h, &state.n, &m);
        state.sigma = add512(&state.sigma, &m);

        let mut bits = [0u64; 8];
        bits[0] = (buffered * 8) as u64;
        state.n = add512(&state.n, &bits);

        let zero = [0u64; 8];
        state.h = g(&state.h, &zero, &state.n);
        state.h = g(&state.h, &zero, &state.sigma);

        let out = to_bytes(&state.h);
        if self.digest_bits == 256 {
            // The *last* 32 bytes. The first 32 would be a hash with no
            // known weakness and no agreement with anyone.
            out[32..].to_vec()
        } else {
            out.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// GOST R 34.11-2012 section A.1, M1.
    ///
    /// The standard writes the message and the digest as 512 bit numbers,
    /// most significant byte on the left. This implementation - like every
    /// other one, and like OpenSSL's GOST engine - works on byte strings
    /// in order. So the standard's hex is **reversed** here, on both
    /// sides, and the message turns out to be the ASCII digits it was
    /// always meant to be.
    ///
    /// Nothing about this is a choice. It is written out because an
    /// implementer who feeds the standard's hex straight in gets a wrong
    /// answer and cannot tell whether the code or the byte order is at
    /// fault - the symptom is identical.
    #[test]
    fn test_the_standards_first_vector() {
        let message = b"012345678901234567890123456789012345678901234567890123456789012";
        assert_eq!(message.len(), 63);

        let mut reversed_512 = unhex(
            "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00\
             fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b");
        reversed_512.reverse();
        assert_eq!(Streebog::new(message).digest(), reversed_512);

        let mut reversed_256 = unhex(
            "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d");
        reversed_256.reverse();
        assert_eq!(Streebog::new_256(message).digest(), reversed_256);
    }

    /// The empty string, whose digests are the two values every
    /// implementation quotes - and which OpenSSL's GOST engine prints in
    /// this order rather than the standard's.
    #[test]
    fn test_the_empty_message() {
        assert_eq!(hex(&Streebog::new_256(b"").digest()),
                   "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb");
        assert_eq!(hex(&Streebog::new(b"").digest()),
                   "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7\
                    362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a");
    }

    /// Streebog-256 is not Streebog-512 truncated. Its IV differs, so the
    /// two diverge from the first compression - and an implementation that
    /// truncated would pass every length test and agree with nobody.
    #[test]
    fn test_256_is_not_a_truncation_of_512() {
        for message in [&b""[..], b"abc", &[0x55u8; 200][..]] {
            let long = Streebog::new(message).digest();
            let short = Streebog::new_256(message).digest();
            assert_eq!(short.len(), 32);
            assert_eq!(long.len(), 64);
            assert_ne!(short, long[..32].to_vec());
            assert_ne!(short, long[32..].to_vec());
        }
    }

    /// Streaming in ragged pieces must equal one call. This is the check
    /// the SHA-1 padding bug would have failed.
    #[test]
    fn test_streaming_equals_one_call() {
        let message: Vec<u8> = (0..500u32).map(|i| (i * 7 + 3) as u8).collect();
        for length in 0..=260usize {
            let slice = &message[..length];
            let whole = Streebog::new(slice).digest();
            for chunk in [1usize, 7, 63, 64, 65, 128] {
                let mut hash = Streebog::new(&[]);
                for piece in slice.chunks(chunk) {
                    hash.update(piece);
                }
                assert_eq!(hash.digest(), whole,
                           "length {} in chunks of {}", length, chunk);
            }
        }
    }

    /// A message that exactly fills a block still gets a whole padded
    /// block of its own. Skipping it is the classic Merkle-Damgard
    /// mistake and makes two different messages hash the same.
    #[test]
    fn test_a_block_aligned_message_gets_its_own_padding_block() {
        let exact = vec![0xaau8; BLOCK_SIZE];
        let mut one_more = exact.clone();
        one_more.push(0x01);

        assert_ne!(Streebog::new(&exact).digest(), Streebog::new(&one_more).digest());

        // And the digest of a full block differs from the digest of the
        // same bytes followed by nothing but the padding pattern.
        let mut padded_by_hand = exact.clone();
        padded_by_hand.extend_from_slice(&[0x01]);
        padded_by_hand.extend_from_slice(&[0u8; BLOCK_SIZE - 1]);
        assert_ne!(Streebog::new(&exact).digest(),
                   Streebog::new(&padded_by_hand).digest());
    }

    /// `digest` must not consume the hash: every other hash here can be
    /// digested and carried on with, and HMAC relies on it.
    #[test]
    fn test_digest_does_not_consume_the_state() {
        let mut hash = Streebog::new(b"abc");
        let first = hash.digest();
        assert_eq!(hash.digest(), first);
        hash.update(b"def");
        assert_eq!(hash.digest(), Streebog::new(b"abcdef").digest());
    }

    /// The length counter is a 512 bit addition, and it has to carry. A
    /// message long enough to carry out of the first word would take
    /// 2^61 bytes, so the carry is exercised directly instead.
    #[test]
    fn test_the_512_bit_addition_carries() {
        let ones = [u64::MAX; 8];
        let one = { let mut v = [0u64; 8]; v[0] = 1; v };
        assert_eq!(add512(&ones, &one), [0u64; 8], "2^512 - 1 plus 1 wraps to zero");

        let mut top = [0u64; 8];
        top[0] = u64::MAX;
        let carried = add512(&top, &one);
        assert_eq!(carried[0], 0);
        assert_eq!(carried[1], 1, "the carry must go up, not down");
    }

    #[test]
    fn test_the_substitution_is_a_bijection() {
        let mut seen = [false; 256];
        for value in PI.iter() {
            assert!(!seen[*value as usize], "pi is not a bijection");
            seen[*value as usize] = true;
        }
    }

    #[test]
    fn test_the_name_and_sizes() {
        assert_eq!(Streebog::new(b"").name(), "streebog512");
        assert_eq!(Streebog::new_256(b"").name(), "streebog256");
        assert_eq!(Streebog::new(b"").digest_len(), 64);
        assert_eq!(Streebog::new_256(b"").digest_len(), 32);
        assert_eq!(Streebog::new(b"").block_size(), 64);
    }
}
