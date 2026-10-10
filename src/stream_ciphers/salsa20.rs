/*
Salsa20, and the Salsa20/8 core that scrypt is built on.

Salsa20 is ChaCha's older sibling: the same 64 byte state of sixteen 32
bit words, the same shape of quarter-round, the same "expand 32-byte k"
constants. What differs is which words each quarter-round touches - Salsa
works down columns and then along rows, where ChaCha works down columns
and then along diagonals - and the order of operations inside the round.

Two things live here, and only one of them is a cipher:

  * `Salsa20`, the stream cipher. 256 or 128 bit key, 8 byte nonce,
    64 bit block counter.
  * `core`, the bare doubleround-and-add permutation, exposed because
    **scrypt's BlockMix is defined in terms of Salsa20/8's core** and
    not in terms of the cipher. Nothing about that use involves a key, a
    nonce or a counter, and pretending otherwise is how an implementation
    ends up with a "Salsa20" that only scrypt can call.

## The counter is 64 bits and it does not wrap into the nonce

Salsa20's state holds the nonce in words 6 and 7 and the counter in words
8 and 9, little endian. A counter that overflows would run into the
nonce, which would silently reuse keystream - so it saturates into an
error instead. At 64 bytes a block that is 2^64 blocks, which nothing
will reach, and the check costs nothing.
*/

use crate::stream_ciphers::StreamCipher;

/// `"expand 32-byte k"` and `"expand 16-byte k"`, as four little endian
/// words each. These are constants in the *state*, not a key schedule:
/// they are what stops the permutation from having a fixed point at
/// zero.
const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const TAU: [u32; 4] = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574];

/// The Salsa20 core: `rounds/2` double rounds, then add the input back.
///
/// **This is the primitive scrypt wants**, which is why it takes and
/// returns a bare 64 byte block rather than anything key shaped. The
/// feed-forward addition at the end is what makes it one-way; leaving it
/// out gives an invertible permutation, and scrypt built on that is
/// still self-consistent and still wrong.
///
/// `rounds` must be even. Salsa20 is 20 rounds; scrypt uses 8.
pub fn core(input: &[u8; 64], rounds: usize) -> [u8; 64] {
    let mut x = [0u32; 16];
    for (index, word) in x.iter_mut().enumerate() {
        let at = index * 4;
        *word = u32::from_le_bytes([input[at], input[at + 1],
                                    input[at + 2], input[at + 3]]);
    }
    let start = x;
    permute(&mut x, rounds);

    let mut out = [0u8; 64];
    for index in 0..16 {
        let sum = x[index].wrapping_add(start[index]);
        out[index * 4..index * 4 + 4].copy_from_slice(&sum.to_le_bytes());
    }
    out
}

/// The double rounds alone, without the feed-forward: what `core` and
/// `hsalsa20` share.
fn permute(x: &mut [u32; 16], rounds: usize) {
    for _ in 0..rounds / 2 {
        // Column round. Each quarter-round walks *down* a column,
        // starting from the diagonal element - so column 0 starts at
        // word 0, column 1 at word 5, column 2 at word 10, column 3 at
        // word 15. Starting each at the top of its column instead is a
        // plausible misreading that gives a different cipher.
        quarter(x, 4, 0, 8, 12);
        quarter(x, 9, 5, 13, 1);
        quarter(x, 14, 10, 2, 6);
        quarter(x, 3, 15, 7, 11);
        // Row round, the transpose of the above.
        quarter(x, 1, 0, 2, 3);
        quarter(x, 6, 5, 7, 4);
        quarter(x, 11, 10, 8, 9);
        quarter(x, 12, 15, 13, 14);
    }
}

/// The state Salsa20 starts from with a 32 byte key: the constants on the
/// diagonal, the key's halves in words 1-4 and 11-14, and `input` - the
/// nonce and counter for the cipher, sixteen bytes of nonce for HSalsa20 -
/// in words 6-9.
fn initial_state(key: &[u8; 32], input: &[u8; 16]) -> [u32; 16] {
    let word = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut state = [0u32; 16];
    for (index, position) in [0usize, 5, 10, 15].into_iter().enumerate() {
        state[position] = SIGMA[index];
    }
    for index in 0..4 {
        state[1 + index] = word(&key[index * 4..]);
        state[11 + index] = word(&key[16 + index * 4..]);
        state[6 + index] = word(&input[index * 4..]);
    }
    state
}

/// HSalsa20 ("Extending the Salsa20 nonce", Bernstein 2008): Salsa20's
/// twenty rounds over the key and a sixteen byte input, with **no
/// feed-forward**, and the output is the eight words the attacker could
/// otherwise compute the feed-forward from - the diagonal (0, 5, 10, 15)
/// and the input's position (6, 7, 8, 9).
///
/// It derives XSalsa20's subkey and NaCl's box key. Taking the
/// feed-forward too, or the first eight words, gives a function of the
/// key of the right length that matches nothing.
pub fn hsalsa20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let mut x = initial_state(key, input);
    permute(&mut x, 20);
    let mut out = [0u8; 32];
    for (index, position) in [0usize, 5, 10, 15, 6, 7, 8, 9].into_iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&x[position].to_le_bytes());
    }
    out
}

/// XSalsa20: Salsa20 under the subkey `hsalsa20(key, nonce[..16])`, with
/// `nonce[16..]` as its eight byte nonce. A 24 byte nonce is long enough
/// to draw at random per message, which an 8 byte one is not.
pub fn xsalsa20(key: &[u8], nonce: &[u8]) -> Result<Salsa20, String> {
    let key: &[u8; 32] = key.try_into()
        .map_err(|_| format!("XSalsa20 takes a 32 byte key, got {}.", key.len()))?;
    if nonce.len() != 24 {
        return Err(format!("XSalsa20 takes a 24 byte nonce, got {}.", nonce.len()));
    }
    let subkey = hsalsa20(key, nonce[..16].try_into().expect("sixteen"));
    Salsa20::new(subkey.to_vec(), nonce[16..].to_vec())
}

/// Salsa's quarter-round: four ARX steps with rotations 7, 9, 13, 18.
///
/// **The argument order is not the specification's.** Bernstein writes
/// `quarterround(y0, y1, y2, y3)` and assigns to y1 first; this takes
/// the word it writes first as `a`, so a spec call
/// `quarterround(w, x, y, z)` is `quarter(x, w, y, z)` here. The
/// translation is done once, at the eight call sites above.
///
/// Getting it wrong is not loud. The first version of this file swapped
/// `c` and `d` in all eight calls - a different permutation, applied
/// consistently - and every round-trip, streaming and seek test passed,
/// because a cipher that is wrong in the same way at both ends is still
/// a cipher. RFC 7914's published core vector is what caught it, which
/// is the whole argument for reading a vector out of a specification
/// rather than checking an implementation against itself.
#[inline]
fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] ^= x[b].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[a].wrapping_add(x[b]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[a]).rotate_left(13);
    x[b] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

/// Salsa20 as a stream cipher.
#[derive(Clone)]
pub struct Salsa20 {
    /// Words 0..16 of the state, with the counter kept current in
    /// words 8 and 9.
    state: [u32; 16],
    rounds: usize,
    /// Keystream already produced for the current block but not yet
    /// consumed, so `crypt` called twice gives the same bytes as one
    /// call with the concatenation - the property that hid a bug in
    /// ChaCha for a while.
    keystream: [u8; 64],
    /// Bytes of `keystream` consumed; 64 means none is left.
    used: usize,
    /// Set once the 64 bit counter has run out, so the error is raised
    /// rather than the keystream silently repeating.
    exhausted: bool,
}

impl Salsa20 {
    /// 32 or 16 byte key, 8 byte nonce, 20 rounds.
    pub fn new(key: Vec<u8>, nonce: Vec<u8>) -> Result<Salsa20, String> {
        Salsa20::with_rounds(key, nonce, 20)
    }

    /// The reduced-round variants, Salsa20/8 and Salsa20/12, which are
    /// real ciphers in the eSTREAM portfolio rather than test knobs.
    pub fn with_rounds(key: Vec<u8>, nonce: Vec<u8>, rounds: usize)
                       -> Result<Salsa20, String> {
        if key.len() != 32 && key.len() != 16 {
            return Err(format!("A Salsa20 key is 16 or 32 bytes; this one is {}.",
                               key.len()));
        }
        if nonce.len() != 8 {
            return Err(format!("A Salsa20 nonce is 8 bytes; this one is {}.",
                               nonce.len()));
        }
        if rounds == 0 || !rounds.is_multiple_of(2) {
            return Err(format!("Salsa20's round count is even and positive; \
                                {} is not.", rounds));
        }

        let word = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        // A 16 byte key is used twice, with the TAU constants rather
        // than SIGMA - the constants are what distinguish the two key
        // sizes, so a 128 bit key with SIGMA is a different cipher.
        let (constants, k0, k1) = if key.len() == 32 {
            (SIGMA, &key[0..16], &key[16..32])
        } else {
            (TAU, &key[0..16], &key[0..16])
        };

        let mut state = [0u32; 16];
        state[0] = constants[0];
        state[5] = constants[1];
        state[10] = constants[2];
        state[15] = constants[3];
        for index in 0..4 {
            state[1 + index] = word(&k0[index * 4..]);
            state[11 + index] = word(&k1[index * 4..]);
        }
        state[6] = word(&nonce[0..4]);
        state[7] = word(&nonce[4..8]);
        state[8] = 0;
        state[9] = 0;

        Ok(Salsa20 { state, rounds, keystream: [0; 64], used: 64, exhausted: false })
    }

    /// Jump to a block, for decrypting from the middle of a stream.
    pub fn seek_block(&mut self, block: u64) {
        self.state[8] = block as u32;
        self.state[9] = (block >> 32) as u32;
        self.used = 64;
        self.exhausted = false;
    }

    /// Produce the next 64 bytes of keystream and advance the counter.
    fn next_block(&mut self) -> Result<(), String> {
        if self.exhausted {
            return Err("This Salsa20 stream has produced 2^64 blocks; \
                        continuing would repeat keystream.".to_string());
        }
        let mut input = [0u8; 64];
        for index in 0..16 {
            input[index * 4..index * 4 + 4]
                .copy_from_slice(&self.state[index].to_le_bytes());
        }
        self.keystream = core(&input, self.rounds);
        self.used = 0;

        // The counter lives in words 8 and 9 and the nonce in 6 and 7.
        // Carrying past word 9 would walk into the nonce and silently
        // reuse keystream, so the overflow is recorded rather than
        // wrapped.
        let (low, carried) = self.state[8].overflowing_add(1);
        self.state[8] = low;
        if carried {
            let (high, over) = self.state[9].overflowing_add(1);
            self.state[9] = high;
            if over {
                self.exhausted = true;
            }
        }
        Ok(())
    }

    /// Encrypt or decrypt, returning an error only when the stream is
    /// exhausted.
    pub fn try_crypt(&mut self, input: &[u8], result: &mut Vec<u8>)
                     -> Result<(), String> {
        let start = result.len();
        result.extend_from_slice(input);
        match self.apply(&mut result[start..]) {
            Ok(()) => Ok(()),
            Err((done, e)) => {
                // What was produced before the stream ran out stays;
                // nothing after it is emitted.
                result.truncate(start + done);
                Err(e)
            }
        }
    }

    /// XOR the keystream into `buf` in place, continuing from wherever the
    /// previous call stopped. On exhaustion, the error carries how many
    /// bytes were transformed before it.
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<(), (usize, String)> {
        let mut at = 0;
        while at < buf.len() {
            if self.used == 64 {
                self.next_block().map_err(|e| (at, e))?;
            }
            let take = (64 - self.used).min(buf.len() - at);
            for (byte, key) in buf[at..at + take].iter_mut()
                                   .zip(&self.keystream[self.used..]) {
                *byte ^= key;
            }
            self.used += take;
            at += take;
        }
        Ok(())
    }
}

impl StreamCipher for Salsa20 {
    /// The trait's signature has no error, and exhausting a 2^64 block
    /// stream is not reachable in practice - so this stops producing
    /// output rather than repeating keystream. `try_crypt` is there for
    /// a caller that wants to know.
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let _ = self.try_crypt(input, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn crypt(cipher: &mut Salsa20, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        cipher.crypt(input, &mut out);
        out
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// **RFC 7914 section 8**, the published Salsa20/8 core vector.
    ///
    /// The one that matters, because it pins the primitive scrypt
    /// actually calls: eight rounds, a bare block in and out, no key
    /// and no counter anywhere. The two values below are transcribed
    /// from the RFC, which is not vendored in `rfcs/`; what stands
    /// behind the transcription is `kdf::scrypt`, whose BlockMix and
    /// full scrypt vectors from sections 9 and 12 of the same document
    /// run through this core and would fail with it mistyped. An
    /// invented vector for a permutation agrees with itself perfectly,
    /// which is how this project has been caught before.
    #[test]
    fn test_rfc7914_salsa20_8_core() {
        let input = unhex("7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1dee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e");
        let expected = unhex("a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81");
        let mut block = [0u8; 64];
        block.copy_from_slice(&input);
        assert_eq!(hex(&core(&block, 8)), hex(&expected));
    }

    /// The all-zero block, where the feed-forward adds nothing.
    ///
    /// Passes whether or not the addition happens, which is why
    /// `test_the_core_adds_its_input_back` exists as well - this one
    /// only pins that the permutation fixes zero.
    #[test]
    fn test_the_core_of_a_zero_block() {
        assert_eq!(core(&[0u8; 64], 20), [0u8; 64]);
    }

    /// **The feed-forward addition is what makes the core one-way.**
    ///
    /// Without it the core is an invertible permutation. Everything
    /// built on it - including scrypt - is then still self-consistent,
    /// so no round-trip test notices. The zero vector above passes
    /// either way, because adding zero changes nothing; this one does
    /// not.
    #[test]
    fn test_the_core_adds_its_input_back() {
        let mut input = [0u8; 64];
        for (index, byte) in input.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let out = core(&input, 20);

        // Run the permutation without the feed-forward, by subtracting
        // the input back off, and check it differs - which it must, or
        // the addition is not happening.
        let mut without = [0u8; 64];
        for index in 0..16 {
            let at = index * 4;
            let mixed = u32::from_le_bytes([out[at], out[at+1], out[at+2], out[at+3]]);
            let start = u32::from_le_bytes([input[at], input[at+1],
                                            input[at+2], input[at+3]]);
            without[at..at+4].copy_from_slice(&mixed.wrapping_sub(start).to_le_bytes());
        }
        assert_ne!(out, without, "the core did not add its input back");
    }

    /// Salsa20/8 and Salsa20/20 are different functions.
    ///
    /// scrypt wants the 8 round core specifically; an implementation
    /// that ignored the round count would be right for the cipher and
    /// wrong for scrypt, or the reverse.
    #[test]
    fn test_the_round_count_reaches_the_core() {
        let input: [u8; 64] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        assert_ne!(core(&input, 8), core(&input, 20),
                   "8 and 20 rounds gave the same answer");
        assert_ne!(core(&input, 8), core(&input, 12));
    }

    /// Streaming must equal one shot.
    ///
    /// The keystream position has to carry across calls. This is the
    /// exact bug that hid in ChaCha here for a while, so Salsa gets the
    /// same test - including chunk sizes that do not divide 64.
    #[test]
    fn test_streaming_equals_one_shot() {
        let message: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
        let one_shot = crypt(&mut Salsa20::new(vec![7; 32], vec![9; 8]).unwrap(),
                             &message);
        for chunk_size in [1usize, 7, 13, 63, 64, 65, 100] {
            let mut cipher = Salsa20::new(vec![7; 32], vec![9; 8]).unwrap();
            let mut streamed = Vec::new();
            for chunk in message.chunks(chunk_size) {
                cipher.crypt(chunk, &mut streamed);
            }
            assert_eq!(hex(&one_shot), hex(&streamed),
                       "salsa20 disagreed with itself in {} byte pieces", chunk_size);
        }
    }

    #[test]
    fn test_round_trip() {
        let message = b"the quick brown fox jumps over the lazy dog, twice over";
        let ciphertext = crypt(&mut Salsa20::new(vec![1; 32], vec![2; 8]).unwrap(),
                               message);
        let plaintext = crypt(&mut Salsa20::new(vec![1; 32], vec![2; 8]).unwrap(),
                              &ciphertext);
        assert_eq!(plaintext, message);
        assert_ne!(&ciphertext[..], &message[..]);
    }

    /// A 128 bit key uses the TAU constants, not SIGMA.
    ///
    /// The constants are what distinguish the two key sizes. An
    /// implementation that doubled a 16 byte key but kept SIGMA gives a
    /// cipher that round-trips perfectly and interoperates with
    /// nothing.
    #[test]
    fn test_a_128_bit_key_is_not_a_doubled_256_bit_key() {
        let short = crypt(&mut Salsa20::new(vec![5; 16], vec![0; 8]).unwrap(),
                          &[0u8; 64]);
        let doubled = crypt(&mut Salsa20::new(vec![5; 32], vec![0; 8]).unwrap(),
                            &[0u8; 64]);
        assert_ne!(hex(&short), hex(&doubled),
                   "a 16 byte key behaved as the same key repeated, \
                    so the TAU constants are not being used");
    }

    #[test]
    fn test_seeking_matches_running_through() {
        let message: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let whole = crypt(&mut Salsa20::new(vec![3; 32], vec![4; 8]).unwrap(),
                          &message);

        let mut seeked = Salsa20::new(vec![3; 32], vec![4; 8]).unwrap();
        seeked.seek_block(2);
        let from_third = crypt(&mut seeked, &message[128..192]);
        assert_eq!(hex(&from_third), hex(&whole[128..192]),
                   "seeking to block 2 did not land on the third block");
    }

    #[test]
    fn test_wrong_sizes_are_errors() {
        assert!(Salsa20::new(vec![0; 31], vec![0; 8]).is_err());
        assert!(Salsa20::new(vec![0; 32], vec![0; 7]).is_err());
        assert!(Salsa20::new(vec![0; 32], vec![0; 9]).is_err());
        assert!(Salsa20::with_rounds(vec![0; 32], vec![0; 8], 7).is_err());
        assert!(Salsa20::with_rounds(vec![0; 32], vec![0; 8], 0).is_err());
    }

    /// HSalsa20 is the core without the feed-forward, read at the diagonal
    /// and the input words: so each of its words is the core's output word
    /// at that position minus the input word there. That pins the
    /// positions against `core`, which RFC 7914's vector pins; NaCl's own
    /// values are in `tests/test_nacl.rs`.
    #[test]
    fn test_hsalsa20_is_the_core_without_its_feed_forward() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 11 + 5) as u8);
        let input: [u8; 16] = core::array::from_fn(|i| (i * 29 + 3) as u8);
        let start = initial_state(&key, &input);
        let mut block = [0u8; 64];
        for (bytes, word) in block.chunks_exact_mut(4).zip(start) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        let full = core(&block, 20);
        let sub = hsalsa20(&key, &input);
        for (index, position) in [0usize, 5, 10, 15, 6, 7, 8, 9].into_iter().enumerate() {
            let core_word = u32::from_le_bytes(full[position * 4..position * 4 + 4]
                                               .try_into().unwrap());
            let sub_word = u32::from_le_bytes(sub[index * 4..index * 4 + 4]
                                              .try_into().unwrap());
            assert_eq!(sub_word, core_word.wrapping_sub(start[position]), "word {position}");
        }
    }

    /// XSalsa20 is Salsa20 under the HSalsa20 subkey, and its first 16
    /// nonce bytes reach the keystream only through that subkey.
    #[test]
    fn test_xsalsa20_is_salsa20_under_the_subkey() {
        let key = [9u8; 32];
        let nonce: [u8; 24] = core::array::from_fn(|i| i as u8);
        let subkey = hsalsa20(&key, nonce[..16].try_into().unwrap());
        let want = crypt(&mut Salsa20::new(subkey.to_vec(), nonce[16..].to_vec()).unwrap(),
                         &[0u8; 200]);
        assert_eq!(hex(&crypt(&mut xsalsa20(&key, &nonce).unwrap(), &[0u8; 200])), hex(&want));
        assert!(xsalsa20(&key, &nonce[..23]).is_err());
        assert!(xsalsa20(&key[..16], &nonce).is_err());
    }

    /// The counter must not run into the nonce.
    #[test]
    fn test_an_exhausted_stream_is_an_error_not_repeated_keystream() {
        let mut cipher = Salsa20::new(vec![0; 32], vec![0; 8]).unwrap();
        cipher.seek_block(u64::MAX);
        let mut out = Vec::new();
        // The last block is fine.
        assert!(cipher.try_crypt(&[0u8; 64], &mut out).is_ok());
        // The one after it is not.
        assert!(cipher.try_crypt(&[0u8; 1], &mut out).is_err(),
                "the counter wrapped instead of refusing");
    }
}
