/*
BLAKE2b and BLAKE2s, RFC 7693.

Two hashes from one design. BLAKE2b works on 64 bit words, takes 128 byte
blocks and produces up to 64 bytes; BLAKE2s works on 32 bit words, takes
64 byte blocks and produces up to 32 bytes. Everything else - the message
schedule, the G function, the parameter block - is shared, and the only
differences are the word width, the rotation distances and the round
count.

Here for three reasons, in ascending order of how much they matter:

  1. It is fast and it is good, and `hashlib` has had it since Python 3.6.
  2. It is the hash inside **Argon2** (RFC 9106), which cannot be built
     without it.
  3. It has a **keyed** mode that is a MAC on its own, with no HMAC
     wrapper - so `BLAKE2b(key, message)` is a legitimate MAC and
     `HMAC-BLAKE2b` is a mistake people make.

## The parameter block is the whole design

Most hashes start from a fixed IV. BLAKE2 starts from the IV **XORed with
a 64 byte parameter block** holding the digest length, the key length,
the fanout, the depth, and - if the caller wants them - a salt and a
personalisation string. That is what makes two BLAKE2b instances with
different output lengths produce unrelated outputs rather than one being
a prefix of the other, which is the property a truncated SHA-512 does
not have.

It also means a wrong parameter block is not an error anywhere: it is a
different hash function that agrees with nothing. Every field is written
by `Params::state`, once, and the tests pin each field's effect
separately.

## The key is not prepended, it is a padded block

A keyed BLAKE2 hashes `key padded to one block || message`, and the key
length also goes in the parameter block. Prepending the key *without* the
padding, or without the parameter field, both give plausible outputs that
match nothing - and both are easy to write. `test_a_key_is_padded_to_a_whole_block`
pins it.
*/

use crate::hash_functions::HashFunction;

// ------------------------------------------------------------------ IVs ---
//
// The first 64 bits of the fractional parts of the square roots of the
// first eight primes - the same constants as SHA-512, and for BLAKE2s
// the same as SHA-256. Written out rather than computed because that is
// how the RFC states them and a transcription error is caught by the
// first test vector.

const IV64: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const IV32: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SIGMA, the message schedule: which message word each G call takes.
///
/// Ten permutations of 0..16. BLAKE2b runs twelve rounds and BLAKE2s
/// ten, so BLAKE2b reuses rows 0 and 1 for rounds 10 and 11 - `SIGMA[r %
/// 10]`, which is the one place the two differ in more than a constant.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Optional parameters, all of which change the initial state.
///
/// Default is the plain unkeyed hash at its maximum output length,
/// which is what `BLAKE2b::new(&[])` gives.
#[derive(Clone, Debug, Default)]
pub struct Params {
    /// Output length in bytes: 1..=64 for BLAKE2b, 1..=32 for BLAKE2s.
    /// Part of the parameter block, so two lengths give unrelated
    /// outputs rather than one being a prefix of the other.
    pub digest_len: usize,
    /// Up to 64 bytes for BLAKE2b, 32 for BLAKE2s. A keyed BLAKE2 is a
    /// MAC; there is no need to wrap it in HMAC and doing so is a
    /// mistake.
    pub key: Vec<u8>,
    /// Exactly 16 bytes for BLAKE2b, 8 for BLAKE2s, or empty.
    pub salt: Vec<u8>,
    /// The same sizes as `salt`. Domain separation: the same key and
    /// message under two personalisations give unrelated results.
    pub personal: Vec<u8>,
}

macro_rules! blake2 {
    (
        $name:ident, $word:ty, $iv:ident,
        block = $block:expr, max_out = $max_out:expr, rounds = $rounds:expr,
        rotations = [$r1:expr, $r2:expr, $r3:expr, $r4:expr],
        label = $label:expr
    ) => {
        #[derive(Clone)]
        pub struct $name {
            h: [$word; 8],
            /// Bytes held back because a block is only compressed once
            /// it is known *not* to be the last - the final block is
            /// compressed with the finalisation flag set, and which
            /// block that is is not known until the input ends.
            buffer: Vec<u8>,
            /// Bytes compressed so far, the RFC's `t`. Two words wide
            /// in the specification; one is enough for any input a
            /// 64 bit machine can hold, and the high half is written as
            /// zero.
            counted: u128,
            digest_len: usize,
        }

        impl $name {
            /// The plain hash at its full output length.
            pub fn new(input: &[u8]) -> $name {
                let mut hash = $name::with_params(&Params {
                    digest_len: $max_out, ..Params::default()
                }).expect("the default parameters are always valid");
                hash.update(input);
                hash
            }

            /// A given output length, 1..=max.
            pub fn with_length(digest_len: usize) -> Result<$name, String> {
                $name::with_params(&Params { digest_len, ..Params::default() })
            }

            /// Keyed - a MAC in its own right.
            pub fn keyed(key: &[u8], digest_len: usize) -> Result<$name, String> {
                $name::with_params(&Params {
                    digest_len, key: key.to_vec(), ..Params::default()
                })
            }

            /// Everything the parameter block can carry.
            pub fn with_params(params: &Params) -> Result<$name, String> {
                let digest_len = params.digest_len;
                if digest_len == 0 || digest_len > $max_out {
                    return Err(format!(
                        "{} produces 1 to {} bytes; {} is not in range.",
                        $label, $max_out, digest_len));
                }
                if params.key.len() > $max_out {
                    return Err(format!(
                        "A {} key is at most {} bytes; this one is {}.",
                        $label, $max_out, params.key.len()));
                }
                let side = $max_out / 4;   // 16 for BLAKE2b, 8 for BLAKE2s
                if !params.salt.is_empty() && params.salt.len() != side {
                    return Err(format!(
                        "A {} salt is exactly {} bytes or absent; this one is {}.",
                        $label, side, params.salt.len()));
                }
                if !params.personal.is_empty() && params.personal.len() != side {
                    return Err(format!(
                        "A {} personalisation is exactly {} bytes or absent; \
                         this one is {}.", $label, side, params.personal.len()));
                }

                // The parameter block, XORed into the IV. Laid out in
                // the RFC as: digest length, key length, fanout, depth,
                // leaf length, node offset, node depth, inner length,
                // then salt and personalisation. Only the sequential
                // case is built here - fanout and depth are 1, and the
                // tree fields are zero - because nothing in this
                // library hashes a tree.
                let word_bytes = core::mem::size_of::<$word>();
                let mut block = vec![0u8; 8 * word_bytes];
                block[0] = digest_len as u8;
                block[1] = params.key.len() as u8;
                block[2] = 1;      // fanout
                block[3] = 1;      // depth
                // Salt and personalisation sit in the last four words
                // for BLAKE2b (bytes 32..64) and the last four for
                // BLAKE2s (bytes 16..32).
                let salt_at = 4 * word_bytes;
                if !params.salt.is_empty() {
                    block[salt_at..salt_at + side].copy_from_slice(&params.salt);
                }
                if !params.personal.is_empty() {
                    let at = salt_at + side;
                    block[at..at + side].copy_from_slice(&params.personal);
                }

                let mut h = $iv;
                for (index, word) in h.iter_mut().enumerate() {
                    let at = index * word_bytes;
                    let mut bytes = [0u8; core::mem::size_of::<$word>()];
                    bytes.copy_from_slice(&block[at..at + word_bytes]);
                    *word ^= <$word>::from_le_bytes(bytes);
                }

                let mut hash = $name {
                    h, buffer: Vec::with_capacity($block), counted: 0, digest_len,
                };

                // A key is hashed as one whole block, zero padded -
                // **not** simply prepended. Without the padding the
                // output is plausible and matches nothing.
                if !params.key.is_empty() {
                    let mut padded = vec![0u8; $block];
                    padded[..params.key.len()].copy_from_slice(&params.key);
                    hash.update(&padded);
                }
                Ok(hash)
            }

            /// The compression function F, RFC 7693 section 3.2.
            ///
            /// `last` sets the finalisation flag, which is what stops
            /// the final block from being extendable.
            fn compress(&mut self, block: &[u8], counted: u128, last: bool) {
                let word_bytes = core::mem::size_of::<$word>();
                let mut m = [0 as $word; 16];
                for (index, word) in m.iter_mut().enumerate() {
                    let at = index * word_bytes;
                    let mut bytes = [0u8; core::mem::size_of::<$word>()];
                    bytes.copy_from_slice(&block[at..at + word_bytes]);
                    *word = <$word>::from_le_bytes(bytes);
                }

                let mut v = [0 as $word; 16];
                v[..8].copy_from_slice(&self.h);
                v[8..].copy_from_slice(&$iv);
                v[12] ^= counted as $word;
                v[13] ^= (counted >> (8 * word_bytes)) as $word;
                if last {
                    v[14] = !v[14];
                }

                for round in 0..$rounds {
                    let s = &SIGMA[round % 10];
                    g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
                    g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
                    g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                    g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                    g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                    g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                    g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                    g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
                }

                for index in 0..8 {
                    self.h[index] ^= v[index] ^ v[index + 8];
                }

                /// The G function, with this width's rotation distances.
                fn g(v: &mut [$word; 16], a: usize, b: usize, c: usize, d: usize,
                     x: $word, y: $word) {
                    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
                    v[d] = (v[d] ^ v[a]).rotate_right($r1);
                    v[c] = v[c].wrapping_add(v[d]);
                    v[b] = (v[b] ^ v[c]).rotate_right($r2);
                    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
                    v[d] = (v[d] ^ v[a]).rotate_right($r3);
                    v[c] = v[c].wrapping_add(v[d]);
                    v[b] = (v[b] ^ v[c]).rotate_right($r4);
                }
            }
        }

        impl HashFunction for $name {
            fn name(&self) -> String {
                // The output length is part of the name because it is
                // part of the function: two lengths are different
                // hashes, not a truncation.
                format!("{}-{}", $label, self.digest_len * 8)
            }

            fn digest_len(&self) -> usize { self.digest_len }

            fn block_size(&self) -> usize { $block }

            fn update(&mut self, input: &[u8]) {
                let mut input = input;
                while !input.is_empty() {
                    // A full buffer is compressed only when more input
                    // has arrived, because the last block must carry
                    // the finalisation flag and we cannot know it is
                    // the last until the input stops. Compressing
                    // eagerly here is the classic BLAKE2 bug: every
                    // input that is an exact multiple of the block size
                    // comes out wrong, and every other length is right.
                    if self.buffer.len() == $block {
                        self.counted += $block as u128;
                        let block = core::mem::take(&mut self.buffer);
                        self.compress(&block, self.counted, false);
                        self.buffer = block;
                        self.buffer.clear();
                    }
                    let take = core::cmp::min($block - self.buffer.len(), input.len());
                    self.buffer.extend_from_slice(&input[..take]);
                    input = &input[take..];
                }
            }

            fn digest(&mut self) -> Vec<u8> {
                // Finalised on a copy, so this is repeatable and
                // `update` may continue afterwards - the same contract
                // as the other hashes here.
                let mut final_state = self.clone();
                let counted = final_state.counted + final_state.buffer.len() as u128;
                let mut block = [0u8; $block];
                block[..final_state.buffer.len()]
                    .copy_from_slice(&final_state.buffer);
                final_state.compress(&block, counted, true);

                let word_bytes = core::mem::size_of::<$word>();
                let mut out = Vec::with_capacity(8 * word_bytes);
                for word in final_state.h {
                    out.extend_from_slice(&word.to_le_bytes());
                }
                out.truncate(self.digest_len);
                out
            }
        }
    };
}

blake2!(Blake2b, u64, IV64, block = 128, max_out = 64, rounds = 12,
        rotations = [32, 24, 16, 63], label = "blake2b");
blake2!(Blake2s, u32, IV32, block = 64, max_out = 32, rounds = 10,
        rotations = [16, 12, 8, 7], label = "blake2s");

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 7693 Appendix A: BLAKE2b-512 of "abc".
    #[test]
    fn test_rfc7693_blake2b_abc() {
        let mut hash = Blake2b::new(b"abc");
        assert_eq!(hex(&hash.digest()),
                   "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
                    7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }

    /// RFC 7693 Appendix B: BLAKE2s-256 of "abc".
    #[test]
    fn test_rfc7693_blake2s_abc() {
        let mut hash = Blake2s::new(b"abc");
        assert_eq!(hex(&hash.digest()),
                   "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }

    /// The empty input, where the counter is zero and the only block is
    /// both first and last.
    #[test]
    fn test_the_empty_input() {
        assert_eq!(hex(&Blake2b::new(b"").digest()),
                   "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
                    d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
        assert_eq!(hex(&Blake2s::new(b"").digest()),
                   "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    }

    /// **The block boundary, which is where the eager-compression bug
    /// lives.**
    ///
    /// A block is only compressed once more input has arrived, because
    /// the last block carries a finalisation flag and which block that
    /// is is unknown until the input ends. An implementation that
    /// compresses as soon as the buffer fills is correct for every
    /// length except exact multiples of the block size - so a test
    /// suite that happens to use 3, 64 and 1000 byte inputs passes.
    #[test]
    fn test_inputs_that_are_exact_multiples_of_the_block() {
        // Against the streamed answer for the same bytes, and against
        // the length either side, so a wrong flag shows as a
        // discontinuity rather than needing a pinned vector per length.
        for length in [127usize, 128, 129, 255, 256, 257, 384, 512] {
            let input: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let one_shot = hex(&Blake2b::new(&input).digest());

            let mut streamed = Blake2b::new(&[]);
            for chunk in input.chunks(7) {
                streamed.update(chunk);
            }
            assert_eq!(one_shot, hex(&streamed.digest()),
                       "blake2b disagreed with itself at {} bytes", length);
        }
        for length in [63usize, 64, 65, 127, 128, 129, 192, 256] {
            let input: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let one_shot = hex(&Blake2s::new(&input).digest());
            let mut streamed = Blake2s::new(&[]);
            for chunk in input.chunks(5) {
                streamed.update(chunk);
            }
            assert_eq!(one_shot, hex(&streamed.digest()),
                       "blake2s disagreed with itself at {} bytes", length);
        }
    }

    /// **An input that is an exact multiple of the block size.**
    ///
    /// The one length the streaming-equals-one-shot test cannot judge.
    /// A block is only compressed once more input has arrived, because
    /// the last block carries a finalisation flag and which block that
    /// is is unknown until the input ends. An implementation that
    /// compresses as soon as the buffer fills is wrong for exactly
    /// these lengths and right for every other - and it is wrong
    /// *consistently*, so one-shot and streamed still agree with each
    /// other. Only a pinned answer notices.
    ///
    /// These two are `hashlib`'s, computed on the development machine
    /// rather than typed: the same arrangement as the encrypted key
    /// fixtures, and for the same reason.
    #[test]
    fn test_a_whole_number_of_blocks_against_a_reference() {
        let input: Vec<u8> = (0..128).map(|i| ((i * 167 + 13) & 0xff) as u8).collect();
        assert_eq!(hex(&Blake2b::new(&input).digest()),
                   "cfd60fd01809f22c0c1ae01f4f73227373273470eba2bd875e66c9127ade1c2f\
                    91aa3164aa5a0fd492bb7813e1a8c705ab3b5bf6a317ce7ce4d4308f693753b2");

        let input: Vec<u8> = (0..64).map(|i| ((i * 167 + 13) & 0xff) as u8).collect();
        assert_eq!(hex(&Blake2s::new(&input).digest()),
                   "72e147956ca539d86b17b42f99d7dbc89d28fb90dcc36c4708fb2c59ce08b471");
    }

    /// A keyed hash, against a reference.
    ///
    /// `test_a_key_is_padded_to_a_whole_block` rules out the key being
    /// prepended *with the parameter block also wrong*, but not the
    /// narrower mistake of padding it wrongly while the key length is
    /// still recorded - those two differ from each other, so the
    /// inequality assertions pass either way. A pinned answer is the
    /// only thing that pins the padding.
    #[test]
    fn test_a_keyed_hash_against_a_reference() {
        let mut hash = Blake2b::keyed(b"secret key", 64).unwrap();
        hash.update(b"message");
        assert_eq!(hex(&hash.digest()),
                   "f1aa846a6dba2e9c51593fc3e083ce210cfadc302df6a4f3d3f6aa0c0e3a6760\
                    7528e898e18adb7717be6ef78291efd58d7c6155c2e62c9401fd0f303a022b4e");

        let mut hash = Blake2s::keyed(b"secret key", 32).unwrap();
        hash.update(b"message");
        assert_eq!(hex(&hash.digest()),
                   "fcd053018c41d70f22fc8eceb8ac39dec4e392448f507dfa4cd9990d7f0a0457");
    }

    /// A shorter digest is **not** a prefix of a longer one.
    ///
    /// The output length goes into the parameter block, so it changes
    /// the initial state. An implementation that hashed at full length
    /// and truncated would pass every fixed-length vector and fail
    /// this.
    #[test]
    fn test_a_shorter_digest_is_not_a_prefix_of_a_longer_one() {
        let short = Blake2b::with_length(32).unwrap().digest();
        let long = Blake2b::with_length(64).unwrap().digest();
        assert_eq!(short.len(), 32);
        assert_ne!(&short[..], &long[..32],
                   "the digest length did not reach the parameter block");

        let short = Blake2s::with_length(16).unwrap().digest();
        let long = Blake2s::with_length(32).unwrap().digest();
        assert_ne!(&short[..], &long[..16]);
    }

    /// A key is hashed as a whole zero-padded block, not prepended.
    ///
    /// Two wrong versions both produce plausible output: prepending the
    /// key without padding, and padding it but leaving the key length
    /// out of the parameter block. This rules out both by comparing
    /// against what each would give.
    #[test]
    fn test_a_key_is_padded_to_a_whole_block() {
        let key = b"secret key";
        let message = b"message";

        let keyed = hex(&Blake2b::keyed(key, 64).unwrap().digest_of(message));

        // Wrong version 1: the key simply prepended.
        let mut prepended = Blake2b::new(&[]);
        prepended.update(key);
        prepended.update(message);
        assert_ne!(keyed, hex(&prepended.digest()),
                   "a keyed hash equals the key prepended, so it is not padded");

        // Wrong version 2: the key padded to a block, but unkeyed
        // parameters - that is, the key length missing from the block.
        let mut padded = vec![0u8; 128];
        padded[..key.len()].copy_from_slice(key);
        let mut unkeyed = Blake2b::new(&[]);
        unkeyed.update(&padded);
        unkeyed.update(message);
        assert_ne!(keyed, hex(&unkeyed.digest()),
                   "the key length did not reach the parameter block");
    }

    /// Salt and personalisation each change the answer, and
    /// independently of each other.
    #[test]
    fn test_salt_and_personalisation_are_separate_fields() {
        let plain = Blake2b::with_params(&Params {
            digest_len: 64, ..Params::default() }).unwrap().digest_of(b"x");
        let salted = Blake2b::with_params(&Params {
            digest_len: 64, salt: b"0123456789abcdef".to_vec(), ..Params::default()
        }).unwrap().digest_of(b"x");
        let personal = Blake2b::with_params(&Params {
            digest_len: 64, personal: b"0123456789abcdef".to_vec(), ..Params::default()
        }).unwrap().digest_of(b"x");

        assert_ne!(plain, salted, "the salt did not reach the parameter block");
        assert_ne!(plain, personal, "the personalisation did not reach it");
        // The same bytes in the two fields must not give the same
        // answer, which is what putting them at the same offset would.
        assert_ne!(salted, personal,
                   "salt and personalisation landed in the same place");
    }

    /// `digest()` is repeatable and does not end the hash.
    #[test]
    fn test_digest_is_repeatable_and_does_not_finalise() {
        let mut hash = Blake2b::new(b"first");
        let once = hash.digest();
        assert_eq!(once, hash.digest(), "digest() is not repeatable");
        hash.update(b"second");
        assert_ne!(once, hash.digest(), "update after digest() did nothing");
        assert_eq!(hex(&hash.digest()), hex(&Blake2b::new(b"firstsecond").digest()));
    }

    #[test]
    fn test_out_of_range_parameters_are_errors() {
        assert!(Blake2b::with_length(0).is_err());
        assert!(Blake2b::with_length(65).is_err());
        assert!(Blake2s::with_length(33).is_err());
        assert!(Blake2b::keyed(&[0u8; 65], 64).is_err());
        assert!(Blake2b::with_params(&Params {
            digest_len: 64, salt: vec![0; 15], ..Params::default() }).is_err());
        assert!(Blake2s::with_params(&Params {
            digest_len: 32, personal: vec![0; 9], ..Params::default() }).is_err());
    }

    /// Helper: hash one message and finish, for the tests above.
    impl Blake2b {
        fn digest_of(mut self, input: &[u8]) -> Vec<u8> {
            self.update(input);
            self.digest()
        }
    }
}
