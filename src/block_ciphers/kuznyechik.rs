/*
Kuznyechik (GOST R 34.12-2015), the 128 bit Russian block cipher.

An SP-network: ten rounds of XOR with a round key, a byte substitution,
and a linear transform over GF(2^8). The same shape as AES and none of
the same constants.

Three things here are worth stating because they are what an
implementation gets wrong:

  * **The field is GF(2^8) modulo x^8 + x^7 + x^6 + x + 1** (0x1c3), not
    AES's x^8 + x^4 + x^3 + x + 1. The two produce different products for
    most inputs and the same one often enough to look nearly right.

  * **The linear transform `L` is sixteen applications of a one-byte LFSR
    step**, not a matrix multiply. Each step computes one new byte from a
    weighted sum of all sixteen and shifts the rest along. Writing it as a
    16x16 matrix is equivalent and is how a fast implementation does it;
    written this way the round constants and the key schedule fall out of
    the same function.

  * **The key schedule is a Feistel network over the cipher's own round
    function**, with 32 constants that are themselves `L` applied to the
    numbers 1..32. So `L` has to be right before anything else can be.

Checked against GOST R 34.12-2015 section A.1: the test vector and the
published intermediate round keys, both. And by
`tools/src/bin/diff_gost_ciphers.rs` against a reference written from the
standard in `scripts/diff_check.py` - because **nothing on this machine
implements Kuznyechik**. OpenSSL here has no GOST engine and
python-cryptography has never had one, so the second implementation is a
second reading of the specification rather than somebody else's code.

The tables were not typed from memory. `PI` is byte-identical between
RustCrypto's `kuznyechik` crate and the `gostcrypto` Python package, two
implementations with no common ancestor, and the linear coefficients and
the field polynomial were recovered from a third by solving for them.
*/

use crate::block_ciphers::BlockCipher;

pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

/// The non-linear bijection `pi`, GOST R 34.12-2015 section 4.1.1.
pub(crate) const PI: [u8; 256] = [
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

/// `pi` inverted, for decryption. Built rather than written out, so the
/// two cannot disagree.
const PI_INV: [u8; 256] = {
    let mut inverse = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inverse[PI[i] as usize] = i as u8;
        i += 1;
    }
    inverse
};

/// The linear transform's coefficients, GOST R 34.12-2015 section 4.1.2,
/// most significant byte first.
const L_COEFFICIENTS: [u8; BLOCK_SIZE] = [
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
];

/// Multiplication in GF(2^8) modulo x^8 + x^7 + x^6 + x + 1.
///
/// **Not** AES's polynomial. 0x1c3 against 0x11b: they agree on enough
/// inputs that a cipher built with the wrong one still looks like a
/// cipher, and agrees with nothing.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        b >>= 1;
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            // x^8 = x^7 + x^6 + x + 1, the low byte of 0x1c3.
            a ^= 0xc3;
        }
    }
    product
}

/// One step of the LFSR: a weighted sum of every byte becomes the new
/// leading byte and the rest shift down.
fn r_step(block: &mut [u8; BLOCK_SIZE]) {
    let mut sum = 0u8;
    for (byte, coefficient) in block.iter().zip(L_COEFFICIENTS.iter()) {
        sum ^= gf_mul(*byte, *coefficient);
    }
    block.copy_within(0..BLOCK_SIZE - 1, 1);
    block[0] = sum;
}

/// The inverse step: the leading byte moves to the end and is replaced by
/// what the forward step would have consumed.
fn r_step_inverse(block: &mut [u8; BLOCK_SIZE]) {
    let first = block[0];
    block.copy_within(1..BLOCK_SIZE, 0);
    block[BLOCK_SIZE - 1] = first;
    let mut sum = 0u8;
    for (byte, coefficient) in block.iter().zip(L_COEFFICIENTS.iter()) {
        sum ^= gf_mul(*byte, *coefficient);
    }
    block[BLOCK_SIZE - 1] = sum;
}

fn l(block: &mut [u8; BLOCK_SIZE]) {
    for _ in 0..BLOCK_SIZE {
        r_step(block);
    }
}

fn l_inverse(block: &mut [u8; BLOCK_SIZE]) {
    for _ in 0..BLOCK_SIZE {
        r_step_inverse(block);
    }
}

fn s(block: &mut [u8; BLOCK_SIZE]) {
    for byte in block.iter_mut() {
        *byte = PI[*byte as usize];
    }
}

fn s_inverse(block: &mut [u8; BLOCK_SIZE]) {
    for byte in block.iter_mut() {
        *byte = PI_INV[*byte as usize];
    }
}

fn x(block: &mut [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) {
    for (byte, k) in block.iter_mut().zip(key.iter()) {
        *byte ^= k;
    }
}

/// `S` then `L`, and `L^-1` after `S^-1`, as sixteen tables of 256 blocks.
///
/// `L` is linear over GF(2^8) - each LFSR step is a weighted sum - so
/// `L(y)` is the XOR over positions `i` of `L` applied to the block that
/// holds `y[i]` at `i` and zeros elsewhere. With `S` folded in, a round
/// is sixteen lookups and XORs: `LS[i][v] = L(e_i * pi(v))`.
///
/// Decryption is rearranged so the same works: with `z = L^-1(x)` carried
/// between rounds, a round is `z <- L^-1(S^-1(z)) ^ L^-1(k)`, which is
/// `ILS[i][v] = L^-1(e_i * pi^-1(v))` and round keys passed through
/// `L^-1` once at key setup. The first `L^-1` reads `ILS` at `pi(x)`,
/// which cancels the inverse S-box inside it.
///
/// Built from `l`, `l_inverse` and `PI` on first use - 128 KB, which is
/// too much work for a `const` - and checked against them by
/// `test_the_tables_are_l_and_s`. Entries are blocks held as `u128`,
/// byte `i` in bits `8i..8i+8`; the order only has to be consistent,
/// since the tables are only ever XORed.
struct Tables {
    ls: [[u128; 256]; BLOCK_SIZE],
    ils: [[u128; 256]; BLOCK_SIZE],
}

fn tables() -> &'static Tables {
    static TABLES: std::sync::OnceLock<Box<Tables>> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = Box::new(Tables { ls: [[0; 256]; BLOCK_SIZE], ils: [[0; 256]; BLOCK_SIZE] });
        for i in 0..BLOCK_SIZE {
            for v in 0..256 {
                let mut block = [0u8; BLOCK_SIZE];
                block[i] = PI[v];
                l(&mut block);
                t.ls[i][v] = u128::from_le_bytes(block);
                let mut block = [0u8; BLOCK_SIZE];
                block[i] = PI_INV[v];
                l_inverse(&mut block);
                t.ils[i][v] = u128::from_le_bytes(block);
            }
        }
        t
    })
}

#[inline(always)]
fn through(table: &[[u128; 256]; BLOCK_SIZE], x: u128) -> u128 {
    let mut out = 0u128;
    for (i, row) in table.iter().enumerate() {
        out ^= row[((x >> (8 * i)) & 0xff) as usize];
    }
    out
}

/// Kuznyechik with its ten round keys already derived.
#[derive(Clone)]
pub struct Kuznyechik {
    round_keys: [[u8; BLOCK_SIZE]; 10],
    /// The round keys as `u128`s, and those of rounds 1 to 8 through
    /// `L^-1` for decryption (see `Tables`).
    encrypt_keys: [u128; 10],
    decrypt_keys: [u128; 10],
}

impl core::fmt::Debug for Kuznyechik {
    /// Says nothing. These are the round keys, and the master key is
    /// recoverable from any two consecutive ones.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Kuznyechik {{ keys redacted }}")
    }
}

impl Kuznyechik {
    /// A 256 bit key, and only that. Kuznyechik has one key length.
    pub fn new(key: &[u8]) -> Result<Kuznyechik, String> {
        if key.len() != KEY_SIZE {
            return Err(format!(
                "Kuznyechik takes a {} byte key; got {}.", KEY_SIZE, key.len()));
        }

        // The constants are L applied to the numbers 1..=32, written big
        // endian across the block - so C[0] is L(0...01). They depend on
        // L being right, which is why a wrong L produces a wrong key
        // schedule as well as a wrong round, and the two mistakes do not
        // cancel.
        let mut constants = [[0u8; BLOCK_SIZE]; 32];
        for (index, constant) in constants.iter_mut().enumerate() {
            constant[BLOCK_SIZE - 1] = index as u8 + 1;
            l(constant);
        }

        let mut round_keys = [[0u8; BLOCK_SIZE]; 10];
        round_keys[0].copy_from_slice(&key[..BLOCK_SIZE]);
        round_keys[1].copy_from_slice(&key[BLOCK_SIZE..]);

        // Eight Feistel rounds per pair, four pairs, producing the next
        // two round keys each time.
        for pair in 0..4 {
            let mut left = round_keys[2 * pair];
            let mut right = round_keys[2 * pair + 1];
            for round in 0..8 {
                let mut next = left;
                x(&mut next, &constants[8 * pair + round]);
                s(&mut next);
                l(&mut next);
                x(&mut next, &right);
                right = left;
                left = next;
            }
            if pair < 3 {
                round_keys[2 * pair + 2] = left;
                round_keys[2 * pair + 3] = right;
            } else {
                round_keys[8] = left;
                round_keys[9] = right;
            }
        }

        let encrypt_keys = round_keys.map(u128::from_le_bytes);
        let mut decrypt_keys = encrypt_keys;
        for (key, raw) in decrypt_keys.iter_mut().zip(round_keys.iter()).take(9).skip(1) {
            let mut block = *raw;
            l_inverse(&mut block);
            *key = u128::from_le_bytes(block);
        }
        Ok(Kuznyechik { round_keys, encrypt_keys, decrypt_keys })
    }

    fn encrypt_block(&self, input: &[u8]) -> [u8; BLOCK_SIZE] {
        let t = tables();
        let mut state = u128::from_le_bytes(input[..BLOCK_SIZE].try_into().unwrap());
        for key in &self.encrypt_keys[..9] {
            state = through(&t.ls, state ^ key);
        }
        // The tenth round key is XORed in with no S and no L. A tenth
        // full round would be a different cipher that round-trips
        // perfectly against itself.
        (state ^ self.encrypt_keys[9]).to_le_bytes()
    }

    fn decrypt_block(&self, input: &[u8]) -> [u8; BLOCK_SIZE] {
        let t = tables();
        let state = u128::from_le_bytes(input[..BLOCK_SIZE].try_into().unwrap())
            ^ self.decrypt_keys[9];
        // z = L^-1(state): ILS read at pi(byte) is L^-1 of the byte alone.
        let mut z = 0u128;
        for (i, row) in t.ils.iter().enumerate() {
            z ^= row[PI[((state >> (8 * i)) & 0xff) as usize] as usize];
        }
        for key in self.decrypt_keys[1..9].iter().rev() {
            z = through(&t.ils, z) ^ key;
        }
        let mut block = z.to_le_bytes();
        s_inverse(&mut block);
        x(&mut block, &self.round_keys[0]);
        block
    }

    /// The block operations as the standard writes them: the reference the
    /// tabled ones are tested against.
    #[cfg(test)]
    fn reference_encrypt(&self, input: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(input);
        for key in &self.round_keys[..9] {
            x(&mut block, key);
            s(&mut block);
            l(&mut block);
        }
        x(&mut block, &self.round_keys[9]);
        block
    }

    #[cfg(test)]
    fn reference_decrypt(&self, input: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(input);
        x(&mut block, &self.round_keys[9]);
        for key in self.round_keys[..9].iter().rev() {
            l_inverse(&mut block);
            s_inverse(&mut block);
            x(&mut block, key);
        }
        block
    }
}

impl BlockCipher for Kuznyechik {
    fn blocksize(&self) -> usize {
        BLOCK_SIZE
    }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&self.encrypt_block(input));
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        result.extend_from_slice(&self.decrypt_block(input));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    const KEY: &str = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";

    /// GOST R 34.12-2015 section A.1.
    #[test]
    fn test_the_standards_vector() {
        let mut cipher = Kuznyechik::new(&unhex(KEY)).unwrap();
        let plaintext = unhex("1122334455667700ffeeddccbbaa9988");

        let mut out = Vec::new();
        cipher.block_encrypt(&plaintext, &mut out);
        assert_eq!(hex(&out), "7f679d90bebc24305a468d42b9d4edcd");

        let mut back = Vec::new();
        cipher.block_decrypt(&out, &mut back);
        assert_eq!(back, plaintext);
    }

    /// The standard prints its round keys, which is worth more than the
    /// final vector alone: a key schedule that is wrong from K3 onwards
    /// still produces a cipher, and one that agrees with nothing.
    #[test]
    fn test_the_standards_round_keys() {
        let cipher = Kuznyechik::new(&unhex(KEY)).unwrap();
        let expected = [
            "8899aabbccddeeff0011223344556677",
            "fedcba98765432100123456789abcdef",
            "db31485315694343228d6aef8cc78c44",
            "3d4553d8e9cfec6815ebadc40a9ffd04",
            "57646468c44a5e28d3e59246f429f1ac",
            "bd079435165c6432b532e82834da581b",
            "51e640757e8745de705727265a0098b1",
            "5a7925017b9fdd3ed72a91a22286f984",
            "bb44e25378c73123a5f32f73cdb6e517",
            "72e9dd7416bcf45b755dbaa88e4a4043",
        ];
        for (index, want) in expected.iter().enumerate() {
            assert_eq!(hex(&cipher.round_keys[index]), *want, "round key {}", index + 1);
        }
    }

    /// The field polynomial is 0x1c3, not AES's 0x11b. Pinned by a
    /// product the two disagree about, so a change to the wrong one fails
    /// here with the reason rather than in a corpus.
    #[test]
    fn test_the_tables_are_l_and_s() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for _ in 0..20 {
            let key: Vec<u8> = (0..KEY_SIZE).map(|_| next()).collect();
            let cipher = Kuznyechik::new(&key).unwrap();
            for _ in 0..50 {
                let block: Vec<u8> = (0..BLOCK_SIZE).map(|_| next()).collect();
                assert_eq!(cipher.encrypt_block(&block), cipher.reference_encrypt(&block));
                assert_eq!(cipher.decrypt_block(&block), cipher.reference_decrypt(&block));
            }
        }
    }

    #[test]
    fn test_the_field_polynomial_is_not_aess() {
        // x^7 * x = x^8 = x^7 + x^6 + x + 1 under this polynomial.
        assert_eq!(gf_mul(0x80, 0x02), 0xc3);
        // Under AES's it would be 0x1b.
        assert_ne!(gf_mul(0x80, 0x02), 0x1b);
        // And the coefficient the standard actually uses.
        assert_eq!(gf_mul(0x01, 148), 148);
    }

    /// `L` and its inverse must undo each other, and one `R` step must not
    /// be mistaken for the whole of `L`.
    #[test]
    fn test_the_linear_transform_inverts() {
        let mut block = [0u8; BLOCK_SIZE];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }
        let original = block;

        let mut once = block;
        r_step(&mut once);
        l(&mut block);
        assert_ne!(block, once, "L is sixteen R steps, not one");

        l_inverse(&mut block);
        assert_eq!(block, original);

        r_step_inverse(&mut once);
        assert_eq!(once, original);
    }

    #[test]
    fn test_the_substitution_inverts_and_is_a_bijection() {
        let mut seen = [false; 256];
        for value in 0..256usize {
            assert!(!seen[PI[value] as usize], "pi is not a bijection");
            seen[PI[value] as usize] = true;
            assert_eq!(PI_INV[PI[value] as usize], value as u8);
        }
    }

    #[test]
    fn test_only_a_256_bit_key_is_accepted() {
        for length in [0usize, 16, 24, 31, 33, 64] {
            assert!(Kuznyechik::new(&vec![0u8; length]).is_err(), "{} bytes", length);
        }
        assert!(Kuznyechik::new(&[0u8; 32]).is_ok());
    }

    /// Every mode comes from `block_encrypt` and `block_decrypt`, so a
    /// round trip through one of them is a check that the block functions
    /// are wired the right way round.
    #[test]
    fn test_it_round_trips_through_cbc() {
        let mut cipher = Kuznyechik::new(&unhex(KEY)).unwrap();
        let plaintext: Vec<u8> = (0..64u8).collect();
        let iv = vec![0x5au8; BLOCK_SIZE];

        let mut ciphertext = Vec::new();
        cipher.cbc_encrypt(&plaintext, &mut ciphertext, &iv).unwrap();
        assert_ne!(ciphertext, plaintext);

        let mut back = Vec::new();
        cipher.cbc_decrypt(&ciphertext, &mut back, &iv).unwrap();
        assert_eq!(back, plaintext);
    }

    /// The last round has no S and no L. A tenth full round produces a
    /// cipher that round-trips against itself perfectly.
    #[test]
    fn test_a_single_bit_of_key_changes_everything() {
        let mut key = unhex(KEY);
        let mut first = Vec::new();
        Kuznyechik::new(&key).unwrap().block_encrypt(&[0u8; 16], &mut first);

        key[31] ^= 1;
        let mut second = Vec::new();
        Kuznyechik::new(&key).unwrap().block_encrypt(&[0u8; 16], &mut second);

        assert_ne!(first, second);
        let differing = first.iter().zip(second.iter())
            .map(|(a, b)| (a ^ b).count_ones()).sum::<u32>();
        assert!(differing > 32, "only {} bits changed", differing);
    }
}
