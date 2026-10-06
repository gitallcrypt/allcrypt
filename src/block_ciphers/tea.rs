/*
TEA and XTEA, David Wheeler and Roger Needham, Cambridge, 1994 and 1997.

Sixty-four bit block, 128 bit key, and small enough that the whole cipher
fits in a page - which is exactly why it is everywhere it is. TEA's
reference implementation is eleven lines of C, so it ended up in set-top
boxes, smart cards, game consoles (the original Xbox's boot ROM used
it), sensor firmware, and a great deal of one-off protocol obfuscation
written in the 1990s. None of that is ours to upgrade.

## Why both

They are two ciphers, not one with a fix, and a caller has to say which:

- **TEA** has an *equivalent-keys* property so blunt that it is a
  practical break where the cipher is used as a hash: flipping the top
  bit of `k[0]` and of `k[1]` together gives a key that encrypts
  identically, so every key has three others equivalent to it and the
  effective key length is 126 bits. That is what broke the Xbox: the
  boot ROM hashed with a TEA-based construction, and the collisions
  came for free.
- **XTEA** keeps the block, the key and the shape, and changes the key
  schedule and the round function to remove that. It does not fix the
  related-key attacks, and neither is a cipher to choose today.

XXTEA - "Corrected Block TEA", 1998 - is deliberately **not** here. It
is not a 64-bit block cipher at all: it operates on a whole message of
two or more words at once, so it has no place in `BlockCipher` and would
get the chaining modes for free while being unable to use them. It
belongs in its own module if it is ever wanted.

## Two ways to get these wrong, both silent

**The word order is big endian.** The papers work on `v[0]` and `v[1]`
as numbers and say nothing about bytes; every published vector, Botan
and Crypto++ all read the block most significant byte first. Reading it
little endian gives a cipher that encrypts, decrypts, round-trips and
agrees with nobody. Nothing but a vector from somebody else notices.

**`sum` is added before the first half-round in TEA and after it in
XTEA.** The two are one line apart in the reference code and both
produce a perfectly good Feistel cipher. TEA's decryption therefore
starts at `delta * rounds` and subtracts *after* each pair, and XTEA's
subtracts *between* them.

## Where the vectors come from

Neither cipher has an RFC and the papers publish no vectors. So:

- `vectors/cryptopp_tea.txt` is Crypto++'s file, which carries David
  Wheeler's own published set (the `teavect.htm` chain) - 64 TEA
  vectors and 64 XTEA vectors at **every** round count from 1 to 64,
  each one's plaintext and key built from the previous answer, so a
  single wrong bit anywhere propagates through the rest.
- `vectors/xtea.vec` is Botan 2.19.5's file, 68 more XTEA vectors from
  an unrelated implementation.

Both are parsed at test time and both assert their counts. Nothing here
was typed.
*/

use crate::block_ciphers::BlockCipher;

/// `2^32 / phi`, the golden-ratio constant both ciphers step `sum` by.
///
/// Stated as the number rather than derived, because deriving it needs
/// floating point - but `test_delta_is_the_golden_ratio_constant`
/// derives it anyway, so a mistyped digit fails rather than becoming
/// this cipher's definition.
const DELTA: u32 = 0x9e37_79b9;

/// The round count both ciphers were published with.
///
/// One "round" here is what the papers call a *cycle*: two Feistel
/// half-rounds, one updating each word. So the standard cipher is 32 of
/// these and 64 half-rounds, and the literature calls it both. Crypto++
/// labels the same number `Rounds`, which is why the vector files agree
/// with this reading.
pub const DEFAULT_ROUNDS: usize = 32;

fn key_words(key: &[u8], who: &str) -> Result<[u32; 4], String> {
    if key.len() != 16 {
        return Err(format!("Wrong key length {}. {} takes 16 bytes.",
                           key.len(), who));
    }
    let mut words = [0u32; 4];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u32::from_be_bytes(key[i * 4..i * 4 + 4]
                                   .try_into().expect("four bytes"));
    }
    Ok(words)
}

/// The block as two big-endian words, and back.
fn block_words(input: &[u8]) -> (u32, u32) {
    (u32::from_be_bytes(input[0..4].try_into().expect("four bytes")),
     u32::from_be_bytes(input[4..8].try_into().expect("four bytes")))
}

fn push_block(result: &mut Vec<u8>, v0: u32, v1: u32) {
    result.extend_from_slice(&v0.to_be_bytes());
    result.extend_from_slice(&v1.to_be_bytes());
}

// --------------------------------------------------------------- TEA ---

#[derive(Clone)]
pub struct Tea {
    k: [u32; 4],
    rounds: usize,
}

impl Tea {
    pub fn new(key: &[u8]) -> Result<Tea, String> {
        Tea::with_rounds(key, DEFAULT_ROUNDS)
    }

    /// TEA with a reduced or extended round count.
    ///
    /// Present because the published vectors use it and because
    /// firmware in the wild does - not because varying it is a good
    /// idea. Zero is refused: it would be the identity function, and a
    /// cipher that silently does nothing is the worst failure this
    /// library can have.
    pub fn with_rounds(key: &[u8], rounds: usize) -> Result<Tea, String> {
        if rounds == 0 {
            return Err("TEA with zero rounds is the identity function."
                       .to_string());
        }
        Ok(Tea { k: key_words(key, "TEA")?, rounds })
    }
}

impl BlockCipher for Tea {
    fn blocksize(&self) -> usize { 8 }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut v0, mut v1) = block_words(input);
        let mut sum = 0u32;
        for _ in 0..self.rounds {
            // **`sum` steps first here and second in XTEA.** One line
            // apart in the reference code, and both give a working
            // Feistel cipher.
            sum = sum.wrapping_add(DELTA);
            v0 = v0.wrapping_add(
                ((v1 << 4).wrapping_add(self.k[0]))
                ^ v1.wrapping_add(sum)
                ^ ((v1 >> 5).wrapping_add(self.k[1])));
            v1 = v1.wrapping_add(
                ((v0 << 4).wrapping_add(self.k[2]))
                ^ v0.wrapping_add(sum)
                ^ ((v0 >> 5).wrapping_add(self.k[3])));
        }
        push_block(result, v0, v1);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut v0, mut v1) = block_words(input);
        // Wrapping, so an absurd round count cannot panic in release
        // and differ in debug.
        let mut sum = DELTA.wrapping_mul(self.rounds as u32);
        for _ in 0..self.rounds {
            v1 = v1.wrapping_sub(
                ((v0 << 4).wrapping_add(self.k[2]))
                ^ v0.wrapping_add(sum)
                ^ ((v0 >> 5).wrapping_add(self.k[3])));
            v0 = v0.wrapping_sub(
                ((v1 << 4).wrapping_add(self.k[0]))
                ^ v1.wrapping_add(sum)
                ^ ((v1 >> 5).wrapping_add(self.k[1])));
            sum = sum.wrapping_sub(DELTA);
        }
        push_block(result, v0, v1);
    }
}

// -------------------------------------------------------------- XTEA ---

#[derive(Clone)]
pub struct Xtea {
    k: [u32; 4],
    rounds: usize,
}

impl Xtea {
    pub fn new(key: &[u8]) -> Result<Xtea, String> {
        Xtea::with_rounds(key, DEFAULT_ROUNDS)
    }

    /// See `Tea::with_rounds`. XTEA at a reduced count is what the
    /// cryptanalysis literature attacks and what a surprising amount of
    /// firmware ships.
    pub fn with_rounds(key: &[u8], rounds: usize) -> Result<Xtea, String> {
        if rounds == 0 {
            return Err("XTEA with zero rounds is the identity function."
                       .to_string());
        }
        Ok(Xtea { k: key_words(key, "XTEA")?, rounds })
    }
}

impl BlockCipher for Xtea {
    fn blocksize(&self) -> usize { 8 }

    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut v0, mut v1) = block_words(input);
        let mut sum = 0u32;
        for _ in 0..self.rounds {
            // The key word is chosen by two *different* slices of
            // `sum`: the low two bits before the step and bits 11 and
            // 12 after it. That is the whole of XTEA's answer to TEA's
            // equivalent keys, and using the same slice twice gives a
            // cipher that round-trips and matches nothing.
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ sum.wrapping_add(self.k[(sum & 3) as usize]));
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]));
        }
        push_block(result, v0, v1);
    }

    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let (mut v0, mut v1) = block_words(input);
        let mut sum = DELTA.wrapping_mul(self.rounds as u32);
        for _ in 0..self.rounds {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]));
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ sum.wrapping_add(self.k[(sum & 3) as usize]));
        }
        push_block(result, v0, v1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::{cryptopp_vector_file, vector_file};

    const CRYPTOPP: &str = include_str!("../../vectors/cryptopp_tea.txt");
    const BOTAN_XTEA: &str = include_str!("../../vectors/xtea.vec");

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn encrypt(cipher: &mut dyn BlockCipher, block: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        cipher.block_encrypt(block, &mut out);
        out
    }

    fn decrypt(cipher: &mut dyn BlockCipher, block: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        cipher.block_decrypt(block, &mut out);
        out
    }

    // ------------------------------------------------- the constant ---

    #[test]
    fn test_delta_is_the_golden_ratio_constant() {
        // The papers define delta as `2^32 / phi`, and this is the one
        // number in the file that is written out rather than read from
        // somewhere. Deriving it is a second opinion about eight hex
        // digits - and a mistyped delta gives a cipher that encrypts
        // and decrypts perfectly and agrees with nothing.
        let phi = (1.0 + 5.0f64.sqrt()) / 2.0;
        let derived = (2.0f64.powi(32) / phi) as u32;
        assert_eq!(DELTA, derived);

        // The same constant appears as XTEA's first-round output for a
        // zero key and a zero block, which is how the published vector
        // set starts - so this is also a claim about the cipher.
        let mut xtea = Xtea::with_rounds(&[0u8; 16], 1).unwrap();
        assert_eq!(hex(&encrypt(&mut xtea, &[0u8; 8])),
                   format!("00000000{:08x}", DELTA));
    }

    // ------------------------------------------ Wheeler's own vectors ---

    /// The Crypto++ file's TEA section: 64 vectors, chained.
    #[test]
    fn test_tea_against_wheelers_published_vectors() {
        let vectors = cryptopp_vector_file(CRYPTOPP, "TEA/ECB");
        assert_eq!(vectors.len(), 64,
                   "the TEA section should hold 64 vectors; found {}",
                   vectors.len());
        for (key, input, expected, rounds) in &vectors {
            // The TEA section states no round count, so every row is
            // the published cipher. If one ever gains one, this says so
            // rather than silently testing something else.
            assert!(rounds.is_none(), "a TEA vector carries a round count");
            let mut cipher = Tea::new(key).unwrap();
            assert_eq!(hex(&encrypt(&mut cipher, input)), hex(expected),
                       "key {} block {}", hex(key), hex(input));
            assert_eq!(hex(&decrypt(&mut cipher, expected)), hex(input),
                       "decrypting back");
        }
    }

    /// The XTEA section: 64 vectors, one per round count from 1 to 64.
    ///
    /// This is the strongest thing in the file. The round count varies
    /// over the whole range, so the key schedule's two different slices
    /// of `sum` are exercised at every value they take - and each
    /// vector's key and plaintext are built from the previous answer,
    /// so one wrong bit anywhere wrecks the rest of the chain rather
    /// than one row.
    #[test]
    fn test_xtea_at_every_round_count_from_one_to_sixty_four() {
        let vectors = cryptopp_vector_file(CRYPTOPP, "XTEA/ECB");
        assert_eq!(vectors.len(), 64,
                   "the XTEA section should hold 64 vectors; found {}",
                   vectors.len());

        let mut counts = Vec::new();
        for (key, input, expected, rounds) in &vectors {
            let rounds = rounds.expect("every XTEA vector states its rounds");
            counts.push(rounds);
            let mut cipher = Xtea::with_rounds(key, rounds).unwrap();
            assert_eq!(hex(&encrypt(&mut cipher, input)), hex(expected),
                       "{} rounds, key {}", rounds, hex(key));
            assert_eq!(hex(&decrypt(&mut cipher, expected)), hex(input),
                       "{} rounds, decrypting back", rounds);
        }
        assert_eq!(counts, (1..=64).collect::<Vec<_>>(),
                   "the file no longer sweeps every round count");
    }

    #[test]
    fn test_cryptopps_rounds_means_what_this_file_means_by_rounds() {
        // Crypto++ labels the number `Rounds` and the papers call the
        // same thing a *cycle* of two half-rounds. That the two agree
        // is a fact about the file rather than something to assume, and
        // it is settled by a source that states no round count at all:
        // Botan's vectors are the published 32-of-them cipher, and the
        // Crypto++ row at 32 must reproduce the same reading.
        let botan = vector_file(BOTAN_XTEA, "XTEA");
        assert!(!botan.is_empty());
        let (key, input, expected) = &botan[0];

        let mut standard = Xtea::new(key).unwrap();
        assert_eq!(hex(&encrypt(&mut standard, &input[..8])),
                   hex(&expected[..8]));

        let mut spelled_out = Xtea::with_rounds(key, 32).unwrap();
        assert_eq!(hex(&encrypt(&mut spelled_out, &input[..8])),
                   hex(&expected[..8]));

        // And not 64, which is the other reading.
        let mut half_rounds = Xtea::with_rounds(key, 64).unwrap();
        assert_ne!(hex(&encrypt(&mut half_rounds, &input[..8])),
                   hex(&expected[..8]));
    }

    /// Botan 2.19.5's XTEA vectors: a second implementation, unrelated
    /// to Wheeler's chain, and with multi-block rows that exercise ECB
    /// over several blocks at once.
    #[test]
    fn test_xtea_against_botans_vectors() {
        let vectors = vector_file(BOTAN_XTEA, "XTEA");
        assert_eq!(vectors.len(), 68,
                   "Botan's XTEA file should hold 68 vectors; found {}",
                   vectors.len());
        let mut multi_block = 0;
        for (key, input, expected) in &vectors {
            let mut cipher = Xtea::new(key).unwrap();
            let mut out = Vec::new();
            cipher.ecb_encrypt(input, &mut out).unwrap();
            assert_eq!(hex(&out), hex(expected), "key {}", hex(key));

            let mut back = Vec::new();
            cipher.ecb_decrypt(expected, &mut back).unwrap();
            assert_eq!(hex(&back), hex(input));

            if input.len() > 8 {
                multi_block += 1;
            }
        }
        assert!(multi_block > 0,
                "no multi-block row, so ECB over several blocks is untested \
                 here");
    }

    // ------------------------------------------------ the two ciphers ---

    #[test]
    fn test_tea_and_xtea_are_different_ciphers() {
        // They share a block size, a key size, a constant and a shape.
        // A file that implemented one twice would pass every
        // round-trip test in this module.
        let key: Vec<u8> = (0..16u8).collect();
        let block: Vec<u8> = (0..8u8).collect();
        let mut tea = Tea::new(&key).unwrap();
        let mut xtea = Xtea::new(&key).unwrap();
        assert_ne!(hex(&encrypt(&mut tea, &block)),
                   hex(&encrypt(&mut xtea, &block)));
    }

    #[test]
    fn test_teas_equivalent_keys() {
        // **TEA's published weakness, as a property of this
        // implementation.** Flipping the top bit of `k[0]` and of
        // `k[1]` together gives a key that encrypts identically, and
        // likewise for `k[2]` and `k[3]`; so every key has three
        // equivalents and the effective length is 126 bits. That is
        // what broke the original Xbox, whose boot ROM hashed with a
        // TEA-based construction.
        //
        // Asserted rather than merely written down, because it is also
        // a sharp test of the round function: it holds only if the key
        // words enter exactly where they do.
        let key: Vec<u8> = (0..16u8).collect();
        let block: Vec<u8> = (100..108u8).collect();
        let reference = hex(&encrypt(&mut Tea::new(&key).unwrap(), &block));

        let flip = |key: &[u8], words: &[usize]| -> Vec<u8> {
            let mut out = key.to_vec();
            for &w in words {
                out[w * 4] ^= 0x80;
            }
            out
        };

        for pair in [vec![0usize, 1], vec![2, 3], vec![0, 1, 2, 3]] {
            let other = flip(&key, &pair);
            assert_ne!(other, key);
            assert_eq!(hex(&encrypt(&mut Tea::new(&other).unwrap(), &block)),
                       reference, "flipping {:?} should be an equivalent key",
                       pair);
        }

        // And exactly three, not more: flipping one word alone is a
        // different key. Without this the test would pass for a cipher
        // that ignored the top bits entirely.
        for single in [0usize, 1, 2, 3] {
            let other = flip(&key, &[single]);
            assert_ne!(hex(&encrypt(&mut Tea::new(&other).unwrap(), &block)),
                       reference, "flipping only k[{}] must change the \
                                   ciphertext", single);
        }
    }

    #[test]
    fn test_xtea_has_no_such_equivalent_keys() {
        // The reason XTEA exists. The same four flips that leave TEA's
        // output unchanged must all change XTEA's.
        let key: Vec<u8> = (0..16u8).collect();
        let block: Vec<u8> = (100..108u8).collect();
        let reference = hex(&encrypt(&mut Xtea::new(&key).unwrap(), &block));
        for pair in [vec![0usize, 1], vec![2, 3], vec![0, 1, 2, 3]] {
            let mut other = key.clone();
            for &w in &pair {
                other[w * 4] ^= 0x80;
            }
            assert_ne!(hex(&encrypt(&mut Xtea::new(&other).unwrap(), &block)),
                       reference, "XTEA must not inherit TEA's equivalent \
                                   keys ({:?})", pair);
        }
    }

    #[test]
    fn test_the_block_is_read_big_endian() {
        // Nothing in the papers says so, every implementation does it,
        // and reading it the other way gives a cipher that round-trips
        // perfectly. The vectors above settle it; this says *which*
        // decision they settled, so a reader does not have to run them
        // to find out.
        let mut xtea = Xtea::with_rounds(&[0u8; 16], 1).unwrap();
        let out = encrypt(&mut xtea, &[0u8; 8]);
        // One round of XTEA on a zero block and zero key leaves the
        // first word zero and puts delta in the second. Little endian
        // would put delta's bytes in the other order.
        assert_eq!(out[4..], DELTA.to_be_bytes());
        assert_ne!(out[4..], DELTA.to_le_bytes());
    }

    // ------------------------------------------------------- the edges ---

    #[test]
    fn test_a_wrong_key_length_is_refused_by_name() {
        for length in [0usize, 1, 8, 15, 17, 32] {
            let key = vec![0u8; length];
            let tea = Tea::new(&key).err().expect("a short key is refused");
            assert!(tea.contains("TEA takes 16 bytes"), "{}", tea);
            let xtea = Xtea::new(&key).err().expect("a short key is refused");
            assert!(xtea.contains("XTEA takes 16 bytes"), "{}", xtea);
        }
        assert!(Tea::new(&[0u8; 16]).is_ok());
        assert!(Xtea::new(&[0u8; 16]).is_ok());
    }

    #[test]
    fn test_zero_rounds_is_refused_rather_than_being_the_identity() {
        // A cipher that silently returns its input is the worst failure
        // this library can have: it looks like it worked.
        for message in [Tea::with_rounds(&[0u8; 16], 0).err().unwrap(),
                        Xtea::with_rounds(&[0u8; 16], 0).err().unwrap()] {
            assert!(message.contains("identity"), "{}", message);
        }
    }

    #[test]
    fn test_round_tripping_every_mode() {
        // The point of implementing only `block_encrypt` and
        // `block_decrypt`: the modes come for free. This checks the
        // wiring rather than the modes, which have their own tests.
        let key: Vec<u8> = (0..16u8).collect();
        let iv = vec![7u8; 8];
        let plain: Vec<u8> = (0..64u8).collect();

        for name in ["tea", "xtea"] {
            let make = |name: &str| -> Box<dyn BlockCipher> {
                if name == "tea" { Box::new(Tea::new(&key).unwrap()) }
                else { Box::new(Xtea::new(&key).unwrap()) }
            };
            for mode in ["ecb", "cbc", "pcbc", "cfb", "ofb", "ctr"] {
                let mut cipher = make(name);
                let mut out = Vec::new();
                match mode {
                    "ecb" => cipher.ecb_encrypt(&plain, &mut out).unwrap(),
                    "cbc" => cipher.cbc_encrypt(&plain, &mut out, iv.clone()).unwrap(),
                    "pcbc" => cipher.pcbc_encrypt(&plain, &mut out, iv.clone()).unwrap(),
                    "cfb" => cipher.cfb_encrypt(&plain, &mut out, iv.clone()).unwrap(),
                    "ofb" => cipher.ofb_encrypt(&plain, &mut out, iv.clone()).unwrap(),
                    _ => cipher.ctr_encrypt(&plain, &mut out, &iv).unwrap(),
                }
                assert_ne!(out, plain, "{} {} did not encrypt", name, mode);

                let mut cipher = make(name);
                let mut back = Vec::new();
                match mode {
                    "ecb" => cipher.ecb_decrypt(&out, &mut back).unwrap(),
                    "cbc" => cipher.cbc_decrypt(&out, &mut back, iv.clone()).unwrap(),
                    "pcbc" => cipher.pcbc_decrypt(&out, &mut back, iv.clone()).unwrap(),
                    "cfb" => cipher.cfb_decrypt(&out, &mut back, iv.clone()).unwrap(),
                    "ofb" => cipher.ofb_decrypt(&out, &mut back, iv.clone()).unwrap(),
                    _ => cipher.ctr_decrypt(&out, &mut back, &iv).unwrap(),
                }
                assert_eq!(back, plain, "{} {} did not round-trip", name, mode);
            }
        }
    }
}
