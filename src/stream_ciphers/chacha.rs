use crate::stream_ciphers::StreamCipher;

use core::cmp;
pub struct Chacha {
    _key: Vec<u8>,
    rounds: usize,
    state: [u32; 16],
    key_pos: usize,
    byte_state: [u8; 64],
    /// True for the original DJB construction (8 byte nonce), where words 12
    /// and 13 form a 64 bit counter. With a 12 byte nonce (RFC 8439) word 13
    /// is part of the nonce and the counter is 32 bits, so it must not carry.
    wide_counter: bool,
    /// Whether any keystream has been produced, for `set_counter`.
    started: bool,
}

#[inline(always)]
fn qr(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; 16]) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

impl Chacha {
    pub fn new(key: Vec<u8>, nonce: Vec<u8>, rounds: usize) -> Result<Chacha, String> {
        if key.len() != 16 && key.len() != 32 {
            return Err(format!("Wrong key length {}. Must be 16 or 32.", key.len()));
        }
        if nonce.len() != 8 && nonce.len() != 12 {
            return Err(format!("Wrong nonce length {}. Must be 8 or 12.", nonce.len()));
        }
        if rounds != 8 && rounds != 12 && rounds != 20 {
            return Err(format!("Wrong round count {}. Must be 8, 12 or 20.", rounds));
        }
        let wide_counter = nonce.len() == 8;
        let mut state: [u32; 16]  = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0];
        if nonce.len() == 8 {
            state[14] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
            state[15] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
        } else if nonce.len() == 12 {
            state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
            state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
            state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
        }
        for (state_i, key_i) in (0..key.len()).step_by(4).enumerate() {
            state[4+state_i] = u32::from_le_bytes(key[key_i..(key_i+4)].try_into().unwrap());
            if key.len() == 16 {
                state[8+state_i] = u32::from_le_bytes(key[key_i..(key_i+4)].try_into().unwrap());
            }
        }

        if key.len() == 16 {
            state[1] = 0x3120646e;
            state[2] = 0x79622d36;        
        } 
        
        Ok(Chacha{
            _key: key,
            rounds,
            state,
            key_pos: 0,
            byte_state: [0; 64],
            wide_counter,
            started: false,
        })
    }
    /// Set the block counter before any keystream is produced.
    ///
    /// ChaCha as a stream cipher starts at zero and nothing else needs
    /// this. RFC 8439's AEAD does: it takes block zero as the Poly1305
    /// key and starts the payload at block one, so the two uses of the
    /// same key and nonce must not overlap. Starting the payload at zero
    /// instead would encrypt it under the very keystream that was handed
    /// out as the authentication key.
    ///
    /// Only meaningful before the first `crypt`; afterwards it would
    /// jump the keystream mid-message, so it refuses.
    pub fn set_counter(&mut self, counter: u32) -> Result<(), String> {
        if self.started || self.key_pos != 0 || self.byte_state.iter().any(|b| *b != 0) {
            return Err("The counter cannot be moved once the keystream has \
                        started; that would skip or repeat keystream in the \
                        middle of a message.".to_string());
        }
        self.state[12] = counter;
        Ok(())
    }

    /// Advance the block counter by one: word 12, carrying into word 13
    /// only for the 64 bit counter of the 8 byte nonce construction. With a
    /// 12 byte nonce word 13 holds nonce material, and carrying into it
    /// would silently change the nonce mid-stream.
    fn advance_counter(&mut self) {
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 && self.wide_counter {
            self.state[13] = self.state[13].wrapping_add(1);
        }
    }

    /// The rounds and the feed-forward on one input state.
    #[inline(always)]
    fn permute(input: &[u32; 16], rounds: usize) -> [u32; 16] {
        let mut state = *input;
        for _i in (0..rounds).step_by(2) {
            // Odd round
            qr(0, 4,  8, 12, &mut state); // column 1
            qr(1, 5,  9, 13, &mut state); // column 2
            qr(2, 6, 10, 14, &mut state); // column 3
            qr(3, 7, 11, 15, &mut state); // column 4
            // Even round
            qr(0, 5, 10, 15, &mut state); // diagonal 1 (main diagonal)
            qr(1, 6, 11, 12, &mut state); // diagonal 2
            qr(2, 7, 8, 13, &mut state); // diagonal 3
            qr(3, 4, 9, 14, &mut state); // diagonal 4
        }
        for (word, start) in state.iter_mut().zip(input) {
            *word = word.wrapping_add(*start);
        }
        state
    }

    /// The next keystream block into `byte_state`, and the counter moved on.
    pub fn chacha_block(&mut self) {
        let block = Chacha::permute(&self.state, self.rounds);
        self.advance_counter();
        for (bytes, word) in self.byte_state.chunks_exact_mut(4).zip(block.iter()) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
    }

    /// The starting states of the next `N` blocks, word by word with the
    /// blocks side by side - `states[w][l]` is word `w` of block `l` - and
    /// the counter moved past them.
    fn next_states<const N: usize>(&mut self) -> [[u32; N]; 16] {
        let mut states = [[0u32; N]; 16];
        for lane in 0..N {
            for (word, value) in states.iter_mut().zip(self.state.iter()) {
                word[lane] = *value;
            }
            self.advance_counter();
        }
        states
    }

    /// As many whole groups of blocks as `buf` holds, on vector registers:
    /// eight at a time with AVX2, then four at a time with SSE2. Returns
    /// what is left, under 256 bytes.
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    fn simd_blocks<'a>(&mut self, mut buf: &'a mut [u8]) -> &'a mut [u8] {
        use crate::stream_ciphers::chacha_simd;
        if chacha_simd::avx2() {
            while buf.len() >= 512 {
                let (chunk, rest) = buf.split_at_mut(512);
                let input = self.next_states::<8>();
                assert!(chacha_simd::eight(&input, self.rounds, chunk));
                buf = rest;
            }
        }
        while buf.len() >= 256 {
            let (chunk, rest) = buf.split_at_mut(256);
            chacha_simd::four(&self.next_states::<4>(), self.rounds, chunk);
            buf = rest;
        }
        buf
    }

    /// Four consecutive blocks XORed into `buf`, which is 256 bytes.
    ///
    /// The four states differ only in their counters. They are held word
    /// by word with the four blocks side by side, and a double round runs
    /// on each block in turn. The compiler keeps this scalar: it does not
    /// vectorise ChaCha's rounds in any arrangement tried, `x86-64-v3`
    /// included, and the disassembly has no vector arithmetic. The `simd`
    /// feature (`chacha_simd.rs`) is the vectorised path.
    fn four_blocks(&mut self, buf: &mut [u8]) {
        let input = self.next_states::<4>();
        let mut x = input;
        for _ in (0..self.rounds).step_by(2) {
            for l in 0..4 {
                let mut w: [u32; 16] = core::array::from_fn(|i| x[i][l]);
                qr(0, 4,  8, 12, &mut w);
                qr(1, 5,  9, 13, &mut w);
                qr(2, 6, 10, 14, &mut w);
                qr(3, 7, 11, 15, &mut w);
                qr(0, 5, 10, 15, &mut w);
                qr(1, 6, 11, 12, &mut w);
                qr(2, 7,  8, 13, &mut w);
                qr(3, 4,  9, 14, &mut w);
                for (word, value) in x.iter_mut().zip(w) {
                    word[l] = value;
                }
            }
        }
        for (chunk, lane) in buf.chunks_exact_mut(64).zip(0..4) {
            for (bytes, (word, start)) in chunk.chunks_exact_mut(4).zip(x.iter().zip(&input)) {
                let key = word[lane].wrapping_add(start[lane]);
                let value = u32::from_le_bytes((&*bytes).try_into().unwrap()) ^ key;
                bytes.copy_from_slice(&value.to_le_bytes());
            }
        }
    }

    /// XOR the keystream into `buf` in place, continuing from wherever the
    /// previous call stopped.
    pub fn apply(&mut self, mut buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        self.started = true;
        // The rest of a block a previous call started.
        if self.key_pos != 0 {
            let take = cmp::min(64 - self.key_pos, buf.len());
            for (b, k) in buf[..take].iter_mut().zip(&self.byte_state[self.key_pos..]) {
                *b ^= k;
            }
            self.key_pos = (self.key_pos + take) % 64;
            buf = &mut buf[take..];
        }
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        let buf = self.simd_blocks(buf);
        let mut fours = buf.chunks_exact_mut(256);
        for chunk in &mut fours {
            self.four_blocks(chunk);
        }
        let mut rest = fours.into_remainder();
        while !rest.is_empty() {
            self.chacha_block();
            let take = cmp::min(64, rest.len());
            for (b, k) in rest[..take].iter_mut().zip(&self.byte_state) {
                *b ^= k;
            }
            self.key_pos = take % 64;
            rest = &mut rest[take..];
        }
    }
}

impl StreamCipher for Chacha {
    fn crypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        let start = result.len();
        result.extend_from_slice(input);
        self.apply(&mut result[start..]);
    }
}

/// HChaCha20 (draft-irtf-cfrg-xchacha section 2.2): the ChaCha state
/// with the 16-byte nonce where the counter and nonce go, twenty rounds,
/// and **no feed-forward** - the first and last rows of the permuted
/// state are the subkey. Adding the input state back, as a keystream
/// block does, gives 32 bytes that are a function of the key in a way
/// the construction's proof does not cover, and that match nobody.
pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state: [u32; 16] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().expect("four"));
    }
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().expect("four"));
    }
    for _ in 0..10 {
        qr(0, 4, 8, 12, &mut state);
        qr(1, 5, 9, 13, &mut state);
        qr(2, 6, 10, 14, &mut state);
        qr(3, 7, 11, 15, &mut state);
        qr(0, 5, 10, 15, &mut state);
        qr(1, 6, 11, 12, &mut state);
        qr(2, 7, 8, 13, &mut state);
        qr(3, 4, 9, 14, &mut state);
    }
    let mut out = [0u8; 32];
    for (i, word) in state[..4].iter().chain(&state[12..]).enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// The subkey and the 12-byte ChaCha20 nonce XChaCha20 runs on: HChaCha20
/// over the nonce's first 16 bytes, and four zero bytes ahead of its last
/// eight (section 2.3).
pub fn xchacha20_subkey(key: &[u8], nonce: &[u8]) -> Result<([u8; 32], [u8; 12]), String> {
    let key: &[u8; 32] = key.try_into()
        .map_err(|_| format!("XChaCha20 takes a 32 byte key, got {}.", key.len()))?;
    if nonce.len() != 24 {
        return Err(format!("XChaCha20 takes a 24 byte nonce, got {}.", nonce.len()));
    }
    let subkey = hchacha20(key, nonce[..16].try_into().expect("sixteen"));
    let mut short = [0u8; 12];
    short[4..].copy_from_slice(&nonce[16..]);
    Ok((subkey, short))
}

/// XChaCha20 as a stream cipher.
///
/// Built on the 8-byte-nonce form, whose counter is 64 bits: within the
/// first 2^32 blocks its keystream is the 12-byte form's with four zero
/// bytes of nonce, which is what the draft specifies, and past them it
/// carries on as libsodium's `crypto_stream_xchacha20` does rather than
/// wrapping.
pub fn xchacha20(key: &[u8], nonce: &[u8]) -> Result<Chacha, String> {
    let (subkey, short) = xchacha20_subkey(key, nonce)?;
    Chacha::new(subkey.to_vec(), short[4..].to_vec(), 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> &'static str {
        include_str!("../../rfcs/draft-irtf-cfrg-xchacha-03.txt")
    }

    /// The hex on the lines after `label` in a section, up to a blank line
    /// (or, with `colons`, the "o  Key = 00:01:..." form section 2.2.1
    /// uses).
    fn hex_after(section: &str, label: &str) -> Vec<u8> {
        let start = section.find(label).unwrap_or_else(|| panic!("no {label}"));
        let mut hex = String::new();
        let mut seen = false;
        for line in section[start + label.len()..].lines() {
            let line = line.trim();
            if line.is_empty() {
                if seen { break } else { continue }
            }
            let digits: String = line.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if digits.len() != line.chars().filter(|c| !c.is_whitespace()).count() {
                break;
            }
            hex.push_str(&digits);
            seen = true;
        }
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
        let from = text.match_indices(start).map(|(i, _)| i)
            .find(|&i| i == 0 || text.as_bytes()[i - 1] == b'\n')
            .unwrap_or_else(|| panic!("no heading {start}"));
        let to = text[from..].find(end).map(|i| from + i).unwrap_or(text.len());
        &text[from..to]
    }

    /// Section 2.2.1, its key and nonce given as colon-separated bytes and
    /// its subkey as the little-endian words of the state's first and
    /// last rows.
    #[test]
    fn test_hchacha20_section_2_2_1() {
        let s = section(draft(), "2.2.1.  Test Vector", "2.3.  XChaCha20");
        // "00:01:...:1f." - bytes and colons, across a line break, up to
        // the first character that is neither.
        let colon_bytes = |label: &str| -> Vec<u8> {
            let start = s.find(label).unwrap() + label.len();
            let text: String = s[start..].chars()
                .take_while(|c| c.is_ascii_hexdigit() || *c == ':' || c.is_whitespace())
                .filter(|c| !c.is_whitespace()).collect();
            text.split(':').map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
        };
        let key: [u8; 32] = colon_bytes("Key =").try_into().unwrap();
        let nonce: [u8; 16] = colon_bytes("Nonce = (").try_into().unwrap();
        // The two rows after "...the following 256-bit key:", each a
        // word's bytes in memory order.
        let words = s[s.find("256-bit key:").unwrap()..].lines()
            .filter(|l| !l.trim().is_empty()).skip(1).take(2)
            .flat_map(|l| l.split_whitespace().map(str::to_string).collect::<Vec<_>>())
            .collect::<Vec<String>>();
        let expected: Vec<u8> = words.iter().flat_map(|w| {
            (0..8).step_by(2).map(move |i| u8::from_str_radix(&w[i..i + 2], 16).unwrap())
        }).collect();
        assert_eq!(expected.len(), 32);
        assert_eq!(hchacha20(&key, &nonce).to_vec(), expected);
    }

    /// Past block 2^32 - 1 the counter carries into the next word, as
    /// libsodium's `crypto_stream_xchacha20` does, rather than wrapping
    /// to block zero and repeating the keystream. The draft's 12-byte form
    /// cannot get there; Go's x/crypto refuses to.
    #[test]
    fn test_xchacha20_does_not_wrap_its_counter() {
        let (key, nonce) = ([7u8; 32], [9u8; 24]);
        let mut late = xchacha20(&key, &nonce).unwrap();
        late.set_counter(u32::MAX).unwrap();
        let mut two = Vec::new();
        crate::stream_ciphers::StreamCipher::crypt(&mut late, &[0u8; 128], &mut two);
        let mut first = Vec::new();
        crate::stream_ciphers::StreamCipher::crypt(&mut xchacha20(&key, &nonce).unwrap(),
                                                   &[0u8; 64], &mut first);
        assert_ne!(two[64..], first[..]);
    }

    /// The four-block path against `chacha_block` one block at a time,
    /// with the counter starting two blocks before its 32 bit wrap so the
    /// wrap falls inside a group of four: carried into word 13 for the
    /// 8 byte nonce, not for the 12 byte one.
    #[test]
    fn test_four_blocks_at_a_time_is_one_at_a_time() {
        for nonce_len in [8usize, 12] {
            for rounds in [8usize, 12, 20] {
                let make = || {
                    let mut c = Chacha::new(vec![5u8; 32], vec![6u8; nonce_len], rounds).unwrap();
                    c.set_counter(u32::MAX - 1).unwrap();
                    c
                };
                let mut reference = make();
                let mut want = Vec::new();
                for _ in 0..12 {
                    reference.chacha_block();
                    want.extend_from_slice(&reference.byte_state);
                }
                let mut fast = make();
                let mut got = vec![0u8; 12 * 64];
                fast.apply(&mut got);
                assert_eq!(got, want, "nonce {nonce_len}, {rounds} rounds");
                // And the counter both left behind is the same.
                assert_eq!(fast.state, reference.state);
            }
        }
    }

    /// The vector paths against `chacha_block` one block at a time: four
    /// lanes and eight called directly, and `apply` over lengths that
    /// take eight, four and single blocks in turn. The counter starts at
    /// several distances before its 32 bit wrap, so the wrap falls at
    /// different lanes: carried into word 13 for the 8 byte nonce, not for
    /// the 12 byte one. Without AVX2 the eight-lane path refuses, and that
    /// is checked instead.
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    #[test]
    fn test_the_vector_paths_are_one_at_a_time() {
        use crate::stream_ciphers::chacha_simd;
        for nonce_len in [8usize, 12] {
            for rounds in [8usize, 12, 20] {
                for before_wrap in [0u32, 1, 3, 6] {
                    let make = || {
                        let mut c = Chacha::new(vec![5u8; 32], vec![6u8; nonce_len], rounds).unwrap();
                        c.set_counter(u32::MAX - before_wrap).unwrap();
                        c
                    };
                    let mut reference = make();
                    let mut want = Vec::new();
                    for _ in 0..32 {
                        reference.chacha_block();
                        want.extend_from_slice(&reference.byte_state);
                    }
                    let what = format!("nonce {nonce_len}, {rounds} rounds, {before_wrap}");

                    let mut got = vec![0u8; 256];
                    chacha_simd::four(&make().next_states::<4>(), rounds, &mut got);
                    assert_eq!(got, want[..256], "four lanes, {what}");
                    let mut got = vec![0u8; 512];
                    if chacha_simd::eight(&make().next_states::<8>(), rounds, &mut got) {
                        assert_eq!(got, want[..512], "eight lanes, {what}");
                    } else {
                        assert!(!chacha_simd::avx2());
                        assert_eq!(got, [0u8; 512], "nothing written without AVX2");
                    }

                    for blocks in [1usize, 4, 5, 8, 12, 13, 16, 31] {
                        let mut fast = make();
                        let mut got = vec![0u8; blocks * 64 + 7];
                        fast.apply(&mut got);
                        assert_eq!(got[..], want[..blocks * 64 + 7], "apply, {blocks} blocks, {what}");
                    }
                }
            }
        }
        if !chacha_simd::avx2() {
            eprintln!("eight lanes skipped: this processor has no AVX2");
        }
    }

    /// Appendix A.3.2's two keystream vectors, block counter 0 and 1.
    #[test]
    fn test_xchacha20_appendix_a_3_2() {
        for (start, end, counter) in [("A.3.2.1.  Block Counter = 0", "A.3.2.2.", 0u32),
                                      ("A.3.2.2.  Block Counter = 1", "Author's Address", 1)] {
            let s = section(draft(), start, end);
            let plaintext = hex_after(s, "Plaintext:");
            let key = hex_after(s, "Key:");
            let iv = hex_after(s, "IV:");
            let keystream = hex_after(s, "Keystream:");
            let ciphertext = hex_after(s, "Ciphertext:");
            let mut cipher = xchacha20(&key, &iv).unwrap();
            cipher.set_counter(counter).unwrap();
            let mut ks = Vec::new();
            crate::stream_ciphers::StreamCipher::crypt(&mut cipher, &vec![0u8; keystream.len()],
                                                       &mut ks);
            assert_eq!(ks, keystream, "{start}");
            let mut cipher = xchacha20(&key, &iv).unwrap();
            cipher.set_counter(counter).unwrap();
            let mut ct = Vec::new();
            crate::stream_ciphers::StreamCipher::crypt(&mut cipher, &plaintext, &mut ct);
            assert_eq!(ct, ciphertext, "{start}");
        }
    }
}
