pub mod acpkm;
pub mod aes;
mod aes_bitsliced;
#[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
mod aes_ni;
pub mod aria;
pub mod bitlocker;
pub mod blowfish;
pub mod camellia;
pub mod cast5;
pub mod cast256;
pub mod cbc_hmac;
pub mod ccm;
pub mod cms_wrap;
pub mod des;
pub mod eax;
pub mod gcm;
pub mod ghash;
pub mod gost;
pub mod idea;
pub mod kalyna;
pub mod kalyna_modes;
pub mod keywrap;
pub mod lrw;
pub mod kuznyechik;
pub mod magma;
pub mod meshing;
pub mod mgm;
pub mod modes;
pub mod ocb;
pub mod rc2;
pub mod rc5;
pub mod rc6;
pub mod rijndael;
pub mod seed;
pub mod serpent;
pub mod sm4;
pub mod tea;
pub mod twofish;
pub mod xts;

pub use gcm::{Gcm, GcmState};
pub use modes::{Cbc, CbcState, Cfb, CfbState, Ctr, CtrState, CtsState, CtsVariant, Ofb,
                OfbState, Pcbc, PcbcState};


/// Parse a Botan-format vector file: `Key`/`In`/`Out` triples under a
/// `[Name]` section heading.
///
/// One parser rather than one per cipher, because three of them read
/// the same shape and three copies is three chances to write the one
/// that silently finds nothing. **Every caller asserts the count it
/// expects**, which is the only thing that catches a parser returning
/// an empty list - a loop over nothing passes. That has happened here
/// in three different documents already; see docs/extending.md, "Where
/// test vectors come from".
///
/// Returns `(key, input, output)`, where input and output may be more
/// than one block.
#[cfg(test)]
pub(crate) fn vector_file(text: &str, section: &str)
                          -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    fn unhex(value: &str) -> Vec<u8> {
        let cleaned: Vec<char> = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        assert!(cleaned.len().is_multiple_of(2), "odd hex run in {value:?}");
        cleaned.chunks(2)
            .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), 16).unwrap())
            .collect()
    }

    let heading = format!("[{section}]");
    let mut in_section = false;
    let mut vectors = Vec::new();
    let (mut key, mut input, mut output) = (None, None, None);

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // A new section ends this one. Without this, a file holding
            // `[Threefish-512]` and `[Threefish-1024]` would mix them.
            in_section = line == heading;
            continue;
        }
        if !in_section || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else { continue };
        match name.trim() {
            "Key" => key = Some(unhex(value)),
            "In" => input = Some(unhex(value)),
            "Out" => output = Some(unhex(value)),
            // Tweak, Nonce and the rest belong to vectors this does not
            // claim to read. Skipped, and the count assertion at the
            // call site is what notices if that skips too much.
            _ => continue,
        }
        if let (Some(k), Some(i), Some(o)) = (&key, &input, &output) {
            vectors.push((k.clone(), i.clone(), o.clone()));
            input = None;
            output = None;
        }
    }
    vectors
}

/// Parse a Crypto++ `TestVectors/*.txt` file.
///
/// A second parser rather than a flag on `vector_file`, because it is a
/// different format from a different project and the two share nothing
/// but the idea of a key and a block:
///
/// ```text
/// Name: XTEA/ECB
/// Comment: test   1
/// Plaintext: 00000000 00000000
/// Key: 00000000 00000000 00000000 00000000
/// Rounds: 1
/// Ciphertext: 00000000 9e3779b9
/// Test: Encrypt
/// ```
///
/// `Test:` closes a record, `Name:` opens a section, hex runs are split
/// into 32-bit groups by spaces, and `Rounds` is present only where the
/// algorithm takes a round count. Returns `(key, input, output, rounds)`
/// for the records under `section`.
///
/// **The caller asserts the count.** A parser that finds nothing turns
/// every loop over it into a pass, which has happened in this repository
/// in three different documents.
/// One record: key, input, output, and the round count where the
/// algorithm takes one. Named rather than written out at the signature
/// because the tuple is four deep and a reader has no way to tell which
/// `Vec<u8>` is which.
#[cfg(test)]
pub(crate) type CryptoppVector = (Vec<u8>, Vec<u8>, Vec<u8>, Option<usize>);

#[cfg(test)]
pub(crate) fn cryptopp_vector_file(text: &str, section: &str)
                                   -> Vec<CryptoppVector> {
    fn unhex(value: &str) -> Vec<u8> {
        let cleaned: Vec<char> = value.chars()
            .filter(|c| c.is_ascii_hexdigit()).collect();
        assert!(cleaned.len().is_multiple_of(2), "odd hex run in {value:?}");
        cleaned.chunks(2)
            .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), 16)
                 .expect("two hex digits"))
            .collect()
    }

    let mut in_section = false;
    let mut vectors = Vec::new();
    let (mut key, mut input, mut output, mut rounds) = (None, None, None, None);

    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match name.trim() {
            "Name" => {
                // A new section ends this one, so `TEA/ECB` and
                // `XTEA/ECB` in one file cannot be mixed.
                in_section = value == section;
                key = None;
            }
            _ if !in_section => continue,
            "Key" => key = Some(unhex(value)),
            "Plaintext" => input = Some(unhex(value)),
            "Ciphertext" => output = Some(unhex(value)),
            "Rounds" => rounds = Some(value.parse::<usize>()
                                      .expect("Rounds is a number")),
            "Test" => {
                // Only `Encrypt` records. A `Decrypt` one states the
                // same triple the other way round, so taking both would
                // double the count without adding a case - and the
                // count is what the caller checks.
                if value == "Encrypt" {
                    if let (Some(k), Some(i), Some(o)) = (&key, &input, &output) {
                        vectors.push((k.clone(), i.clone(), o.clone(), rounds));
                    }
                }
                input = None;
                output = None;
                rounds = None;
            }
            _ => continue,
        }
    }
    vectors
}

/// `encrypt_blocks` and `decrypt_blocks` for a cipher that does not
/// override them: one block at a time, through one scratch buffer.
fn blocks_via<C: BlockCipher + ?Sized>(cipher: &mut C, blocks: &mut [u8], encrypt: bool)
                                       -> Result<(), String> {
    let bs = cipher.blocksize();
    if bs == 0 || !blocks.len().is_multiple_of(bs) {
        return Err(format!("{} bytes is not a whole number of {bs} byte blocks.",
                           blocks.len()));
    }
    let mut scratch = Vec::with_capacity(bs);
    for block in blocks.chunks_exact_mut(bs) {
        scratch.clear();
        if encrypt {
            cipher.block_encrypt(block, &mut scratch);
        } else {
            cipher.block_decrypt(block, &mut scratch);
        }
        if scratch.len() != bs {
            return Err(format!("The cipher produced {} bytes for a {bs} byte block.",
                               scratch.len()));
        }
        block.copy_from_slice(&scratch);
    }
    Ok(())
}

pub trait BlockCipher {
    fn blocksize(&self) -> usize;

    /// One block of `input`, its `blocksize()` leading bytes, appended
    /// to `result` as exactly one block. `input` holds a whole block:
    /// handing a shorter slice is a caller's mistake, and what a cipher
    /// does with one is its own - AES panics on the missing bytes, DES
    /// reads what is there as the low end of its block - so nothing in
    /// the modes does it, and the modes check that exactly one block
    /// came back.
    fn block_encrypt(&mut self, _input: &[u8], _result: &mut Vec<u8>);
    /// The inverse of `block_encrypt`, under the same contract.
    fn block_decrypt(&mut self, _input: &[u8], _result: &mut Vec<u8>);

    /// Encrypt whole blocks in place, each independently: ECB over
    /// `blocks`. The modes that have several independent blocks in hand -
    /// CTR, GCM, XTS, ECB and CBC decryption - call this rather than
    /// `block_encrypt`, so a cipher that can run blocks side by side
    /// overrides it (AES does, for its bitsliced path). The default goes a
    /// block at a time through `block_encrypt`.
    ///
    /// # Errors
    /// A length that is not a whole number of blocks, or a
    /// `block_encrypt` that did not produce exactly one block.
    fn encrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
        blocks_via(self, blocks, true)
    }

    /// The inverse of `encrypt_blocks`.
    ///
    /// # Errors
    /// As `encrypt_blocks`.
    fn decrypt_blocks(&mut self, blocks: &mut [u8]) -> Result<(), String> {
        blocks_via(self, blocks, false)
    }

    /// One block, in place: `block_encrypt` without the output `Vec`.
    /// The chained modes - CBC encryption and decryption one block at a
    /// time - call this once per block, so its overhead is per block too;
    /// a cipher with a cheaper single-block path (AES) overrides it.
    /// `scratch` is the caller's, reused across calls, for the default,
    /// which goes through `block_encrypt`.
    ///
    /// # Errors
    /// A `block_encrypt` that did not produce exactly one block.
    fn encrypt_block_in_place(&mut self, block: &mut [u8], scratch: &mut Vec<u8>)
                              -> Result<(), String> {
        scratch.clear();
        self.block_encrypt(block, scratch);
        if scratch.len() != block.len() {
            return Err("block_encrypt did not produce exactly one block.".to_string());
        }
        block.copy_from_slice(scratch);
        Ok(())
    }

    /// The inverse of `encrypt_block_in_place`.
    ///
    /// # Errors
    /// A `block_decrypt` that did not produce exactly one block.
    fn decrypt_block_in_place(&mut self, block: &mut [u8], scratch: &mut Vec<u8>)
                              -> Result<(), String> {
        scratch.clear();
        self.block_decrypt(block, scratch);
        if scratch.len() != block.len() {
            return Err("block_decrypt did not produce exactly one block.".to_string());
        }
        block.copy_from_slice(scratch);
        Ok(())
    }

    fn ecb_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) -> Result<(), String> {
        let blocksize = self.blocksize();
        if !input.len().is_multiple_of(blocksize) {
            return Err("Input length not a multiple of block size, (padding is needed).".to_string());
        }
        let start = result.len();
        result.extend_from_slice(input);
        let r = self.encrypt_blocks(&mut result[start..]);
        if r.is_err() {
            result.truncate(start);
        }
        r
    }
    fn ecb_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) -> Result<(), String> {
        let blocksize = self.blocksize();
        if !input.len().is_multiple_of(blocksize) {
            return Err("Input length not a multiple of block size, (padding is needed).".to_string());
        }
        let start = result.len();
        result.extend_from_slice(input);
        let r = self.decrypt_blocks(&mut result[start..]);
        if r.is_err() {
            result.truncate(start);
        }
        r
    }

    // The chaining modes below are thin wrappers over the streaming mode
    // objects in `modes`. Call those directly to encrypt in several chunks,
    // or in place with no copying at all.

    fn cbc_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        // The whole input is in hand here, so reject a ragged length before
        // writing anything rather than emitting whole blocks and then failing.
        if !input.len().is_multiple_of(self.blocksize()) {
            return Err("Input length not a multiple of block size, (padding is needed).".to_string());
        }
        let mut m = Cbc::encryptor(self, iv)?;
        m.update(input, result)?;
        m.finish()
    }
    fn cbc_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        if !input.len().is_multiple_of(self.blocksize()) {
            return Err("Input length not a multiple of block size, (padding is needed).".to_string());
        }
        let mut m = Cbc::decryptor(self, iv)?;
        m.update(input, result)?;
        m.finish()
    }

    /// CBC with ciphertext stealing: any length of at least one block,
    /// and no padding. `modes::CtsVariant` says which of the three
    /// orderings of the last two blocks.
    fn cbc_cs_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8],
                      variant: CtsVariant) -> Result<(), String> {
        let start = result.len();
        let mut state = CtsState::new(self, iv, variant, false)?;
        let r = state.update(self, input, result).and_then(|_| state.finish(self, result));
        if r.is_err() {
            result.truncate(start);
        }
        r
    }
    fn cbc_cs_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8],
                      variant: CtsVariant) -> Result<(), String> {
        let start = result.len();
        let mut state = CtsState::new(self, iv, variant, true)?;
        let r = state.update(self, input, result).and_then(|_| state.finish(self, result));
        if r.is_err() {
            result.truncate(start);
        }
        r
    }

    /// Propagating CBC, as used by Kerberos 4. See `modes::PcbcState`
    /// for what it propagates and why it does not achieve what it was
    /// meant to.
    fn pcbc_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        if !input.len().is_multiple_of(self.blocksize()) {
            return Err("Input length not a multiple of block size, (padding is needed).".to_string());
        }
        let mut m = Pcbc::encryptor(self, iv)?;
        m.update(input, result)?;
        m.finish()
    }
    fn pcbc_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        if !input.len().is_multiple_of(self.blocksize()) {
            return Err("Input length not a multiple of block size, (padding is needed).".to_string());
        }
        let mut m = Pcbc::decryptor(self, iv)?;
        m.update(input, result)?;
        m.finish()
    }

    fn cfb_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        Cfb::encryptor(self, iv)?.update(input, result)
    }
    fn cfb_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        Cfb::decryptor(self, iv)?.update(input, result)
    }

    fn ofb_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        Ofb::new(self, iv)?.update(input, result)
    }
    fn ofb_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        self.ofb_encrypt(input, result, iv)
    }

    /// Build the first counter block from the nonce/IV. The default is the
    /// usual "nonce, zero padded to a block" layout; a cipher whose counter
    /// works differently overrides this and `ctr_next`, and nothing else.
    ///
    /// An empty IV is refused: it would be the all-zero counter under
    /// every key, one fixed keystream shared by everyone, the same reason
    /// GCM refuses an empty nonce. A short one is padded, as the layout
    /// says.
    fn ctr_init(&mut self, iv: &[u8], counter: &mut Vec<u8>) -> Result<(), String> {
        let bs = self.blocksize();
        if iv.is_empty() {
            return Err("A CTR IV must not be empty: an empty one is the all-zero \
                        counter under every key, and the same keystream for \
                        everyone.".to_string());
        }
        if iv.len() > bs {
            return Err("IV longer than the block size.".to_string());
        }
        counter.clear();
        counter.extend_from_slice(iv);
        counter.resize(bs, 0);
        Ok(())
    }

    /// Advance the counter block by one. Default: big endian increment over
    /// the whole block.
    fn ctr_next(&self, counter: &mut [u8]) {
        // The two block sizes there are, as one integer each; the loop
        // below is the same increment for any other length.
        if let Ok(block) = <&mut [u8; 16]>::try_from(&mut *counter) {
            *block = u128::from_be_bytes(*block).wrapping_add(1).to_be_bytes();
            return;
        }
        if let Ok(block) = <&mut [u8; 8]>::try_from(&mut *counter) {
            *block = u64::from_be_bytes(*block).wrapping_add(1).to_be_bytes();
            return;
        }
        for b in counter.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
    }

    /// Consecutive counter blocks into `out`, a whole number of blocks:
    /// `counter`, then each `ctr_next` of it, leaving `counter` at the
    /// next one unused. The default is exactly that loop over `ctr_next`,
    /// so a cipher with its own counter needs nothing here. It exists so
    /// a wrapper such as `AnyBlockCipher` can forward one call per batch
    /// rather than `ctr_next` once per block, which with a hardware AES
    /// was most of CTR's time.
    fn ctr_fill(&self, counter: &mut [u8], out: &mut [u8]) {
        if let Ok(fixed) = <&mut [u8; 16]>::try_from(&mut *counter) {
            // A fixed-size copy is two moves; a slice of unknown length
            // is a call to memcpy.
            let mut value = *fixed;
            for block in out.chunks_exact_mut(16) {
                block.copy_from_slice(&value);
                self.ctr_next(&mut value);
            }
            *fixed = value;
            return;
        }
        let bs = counter.len();
        for block in out.chunks_exact_mut(bs) {
            block.copy_from_slice(counter);
            self.ctr_next(counter);
        }
    }

    /// XOR a counter-mode keystream into `data`, whole blocks of it, in
    /// one pass, and leave `counter` at the next block unused - or
    /// return `Ok(false)` and touch nothing, which is the default: the
    /// caller then builds counter blocks with `ctr_fill`, encrypts them
    /// with `encrypt_blocks` and XORs them in, which is the same thing in
    /// three passes. `counter32` selects GCM's counter, which increments
    /// only the block's last four bytes, big endian, wrapping within
    /// them; otherwise it is `ctr_next`'s default, the whole block as one
    /// big-endian integer. A cipher that overrides `ctr_next` must not
    /// override this. AES does, with its instructions, where the three
    /// passes were most of CTR's and GCM's time.
    ///
    /// # Errors
    /// A length that is not a whole number of blocks.
    fn ctr_xor(&mut self, _counter: &mut [u8], _data: &mut [u8], _counter32: bool)
               -> Result<bool, String> {
        Ok(false)
    }

    /// XTS's whole blocks in one pass - each `E(P xor T) xor T`, the
    /// tweak doubled in GF(2^128) after each, IEEE 1619 - leaving `tweak`
    /// at the next block's; or `Ok(false)` and nothing touched, the
    /// default, after which `xts.rs` masks, calls `encrypt_blocks` or
    /// `decrypt_blocks`, and masks again. AES overrides it with its
    /// instructions: masking in memory between the passes cost more than
    /// the cipher.
    ///
    /// # Errors
    /// A length that is not a whole number of blocks.
    fn xts_blocks(&mut self, _tweak: &mut [u8; 16], _data: &mut [u8], _encrypt: bool)
                  -> Result<bool, String> {
        Ok(false)
    }

    /// A streaming CTR handle over this cipher. Not available on a trait
    /// object, because it names `Self`; `ctr_encrypt` is.
    fn ctr(&mut self, iv: &[u8]) -> Result<Ctr<'_, Self>, String> where Self: Sized {
        Ctr::new(self, iv)
    }

    fn ctr_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        Ctr::new(self, iv)?.update(input, result)
    }
    fn ctr_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8]) -> Result<(), String> {
        self.ctr_encrypt(input, result, iv)
    }

    /// CTR with the whole block one little-endian counter, starting at
    /// `iv` (`modes::CtrState::new_little_endian`).
    fn ctr_le_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8])
                      -> Result<(), String> {
        let mut state = CtrState::new_little_endian(self, iv)?;
        state.update(self, input, result)
    }
    fn ctr_le_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>, iv: &[u8])
                      -> Result<(), String> {
        self.ctr_le_encrypt(input, result, iv)
    }


    /// A streaming GCM handle. Not available on a trait object, because it
    /// names `Self`; the one-shot pair below is.
    fn gcm<'a>(&'a mut self, nonce: &[u8], aad: &[u8], encrypt: bool)
               -> Result<Gcm<'a, Self>, String> where Self: Sized {
        if encrypt { Gcm::encryptor(self, nonce, aad) }
        else { Gcm::decryptor(self, nonce, aad) }
    }

    /// Encrypt and authenticate in one call, appending the ciphertext to
    /// `result` and the 16 byte tag to `tag`.
    ///
    /// The nonce must never repeat under one key. Two messages sharing one
    /// give away their XOR and the authentication key, after which anything
    /// can be forged under that key. See `block_ciphers::gcm`.
    fn gcm_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>, nonce: &[u8],
                   tag: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), String> {
        let mut state = GcmState::encryptor(self, nonce, additional_data)?;
        state.update(self, input, result)?;
        tag.extend_from_slice(&state.tag(self)?);
        Ok(())
    }

    /// Verify and decrypt in one call.
    ///
    /// On any failure `result` is left exactly as it was found. Handing
    /// back unverified plaintext alongside an error is how a caller that
    /// checks the error one line too late ends up using forged data.
    fn gcm_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>, nonce: &[u8],
                   tag: &[u8], additional_data: &[u8]) -> Result<(), String> {
        let start = result.len();
        let mut state = GcmState::decryptor(self, nonce, additional_data)?;
        let outcome = state.update(self, input, result)
            .and_then(|()| state.verify(self, tag));
        if outcome.is_err() {
            result.truncate(start);
        }
        outcome
    }

    // CCM is `block_ciphers::ccm`: one shot, because its MAC starts with
    // the message's length, so it has no place among the streaming
    // wrappers here.

    /// PKCS#7 (RFC 5652): always append 1..=blocksize bytes, each holding the
    /// pad length. Input that is already block aligned gets a whole extra
    /// block, which is what makes `unpad_pkcs7` unambiguous.
    fn pad_pkcs7(&mut self, input: &mut Vec<u8>) {
        let pad_len = self.blocksize() - (input.len() % self.blocksize());
        input.extend_from_slice(vec![pad_len as u8; pad_len].as_slice());
    }

    /// Inverse of `pad_pkcs7`. Rejects anything that is not validly padded.
    fn unpad_pkcs7(&mut self, input: &mut Vec<u8>) -> Result<(), String> {
        let blocksize = self.blocksize();
        if input.is_empty() || !input.len().is_multiple_of(blocksize) {
            return Err("Input length is not a non-zero multiple of the block size.".to_string());
        }
        let pad_len = *input.last().unwrap() as usize;
        if pad_len == 0 || pad_len > blocksize {
            return Err("Invalid PKCS#7 padding.".to_string());
        }
        // Compare every pad byte, without an early exit, so the check does not
        // leak where the padding first went wrong.
        let mut bad = 0u8;
        for b in &input[input.len()-pad_len..] {
            bad |= b ^ (pad_len as u8);
        }
        if bad != 0 {
            return Err("Invalid PKCS#7 padding.".to_string());
        }
        input.truncate(input.len() - pad_len);
        Ok(())
    }

}


#[allow(dead_code)]
#[cfg_attr(test, derive(Debug))]
struct Test{
    size: usize,
}

impl BlockCipher for Test {
    fn block_decrypt(&mut self, _input: &[u8], _result: &mut Vec<u8>) {}
    fn block_encrypt(&mut self, _input: &[u8], _result: &mut Vec<u8>) {}
    fn blocksize(&self) -> usize { self.size }
}

#[test]
fn test_pad_pkcs7() {
    let mut crypto = Test{size: 16};

    // Empty input is block aligned, so it gets a full block of padding.
    let mut input = vec![];
    crypto.pad_pkcs7(&mut input);
    assert_eq!(input, vec![16; 16]);

    input = vec![0; 1];
    crypto.pad_pkcs7(&mut input);
    assert_eq!(input,  vec![0, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf]);

    // Already a whole block: a second, all-padding block is appended.
    input = vec![0; 16];
    crypto.pad_pkcs7(&mut input);
    assert_eq!(input.len(), 32);
    assert_eq!(input[0..16], [0; 16]);
    assert_eq!(input[16..32], [16; 16]);

    input = vec![0; 31];
    crypto.pad_pkcs7(&mut input);
    assert_eq!(input,  vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,]);
}

#[test]
fn test_pad_unpad_pkcs7_roundtrip() {
    for size in [8usize, 16] {
        let mut crypto = Test{size};
        for len in 0..(3*size) {
            let original: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut buf = original.clone();
            crypto.pad_pkcs7(&mut buf);
            assert_eq!(buf.len() % size, 0, "padded length must be block aligned");
            assert!(buf.len() > original.len(), "padding must always add at least one byte");
            crypto.unpad_pkcs7(&mut buf).unwrap();
            assert_eq!(buf, original, "roundtrip failed for block size {} length {}", size, len);
        }
    }
}

#[test]
fn test_unpad_pkcs7_rejects_bad_padding() {
    let mut crypto = Test{size: 16};

    // Empty input.
    let mut input: Vec<u8> = vec![];
    assert!(crypto.unpad_pkcs7(&mut input).is_err());

    // Not block aligned.
    input = vec![1; 17];
    assert!(crypto.unpad_pkcs7(&mut input).is_err());

    // Pad byte of zero.
    input = vec![0; 16];
    assert!(crypto.unpad_pkcs7(&mut input).is_err());

    // Pad byte larger than the block size.
    input = vec![17; 16];
    assert!(crypto.unpad_pkcs7(&mut input).is_err());

    // Pad bytes that disagree with each other.
    input = vec![0; 16];
    input[14] = 3;
    input[15] = 4;
    assert!(crypto.unpad_pkcs7(&mut input).is_err());
}

/// A toy 16 byte cipher, just enough to exercise the generic mode code.
#[allow(dead_code)]
struct ToyBlock16 {
    k: u8,
}

impl BlockCipher for ToyBlock16 {
    fn blocksize(&self) -> usize { 16 }
    fn block_encrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        for (i, b) in input.iter().enumerate() {
            result.push(b ^ self.k ^ (i as u8));
        }
    }
    fn block_decrypt(&mut self, input: &[u8], result: &mut Vec<u8>) {
        self.block_encrypt(input, result)
    }
}

/// A cipher whose `block_encrypt` produces nothing must be caught by
/// every mode rather than encrypting or authenticating emptiness, and
/// the failure must leave no partial output behind.
#[test]
fn test_a_cipher_that_produces_no_block_is_an_error() {
    let mut crypto = Test{size: 16};
    let mut result = vec![];
    assert!(crypto.ctr_encrypt(&[0; 16], &mut result, &[0; 16]).is_err());
    assert!(crypto.ctr_decrypt(&[0; 16], &mut result, &[0; 16]).is_err());
    assert!(crypto.gcm_encrypt(&[0; 16], &mut result, &[0; 12], &mut vec![], &[]).is_err());
    assert!(crypto.gcm_decrypt(&[0; 16], &mut result, &[0; 12], &[0; 16], &[]).is_err());
    assert!(ccm::encrypt(&mut crypto, &[0; 13], &[], &[0; 16], 8).is_err());
    assert!(ccm::decrypt(&mut crypto, &[0; 13], &[], &[0; 16], &[0; 8]).is_err());
    assert!(result.is_empty(), "a failing mode must not leave partial output behind");
}

/// The default counter refused only an IV longer than the block, so
/// `ctr_encrypt(.., &[])` ran with an all-zero counter and produced
/// output - one keystream shared by every user of the key, which GCM
/// refuses for its nonce and plain CTR did not. The facade's own IV
/// presence check hid it from the api tests. Now the empty IV is
/// refused here; a short one is still padded, and a long one still
/// refused.
#[test]
fn test_ctr_refuses_an_empty_iv() {
    let mut crypto = ToyBlock16{k: 0x5a};
    let mut out = vec![];
    assert!(crypto.ctr_encrypt(&[0; 16], &mut out, &[]).is_err());
    assert!(out.is_empty());
    assert!(crypto.ctr_encrypt(&[0; 16], &mut out, &[1]).is_ok());
    assert!(crypto.ctr_encrypt(&[0; 16], &mut out, &[1; 16]).is_ok());
    assert!(crypto.ctr_encrypt(&[0; 16], &mut out, &[1; 17]).is_err());
}

/// A cipher whose block_encrypt misbehaves must be caught, not silently
/// truncated by `xor`.
#[test]
fn test_modes_reject_short_block_output() {
    let mut crypto = Test{size: 16}; // block_encrypt writes nothing at all
    let mut result = vec![];
    assert!(crypto.cbc_encrypt(&[0; 32], &mut result, &[0; 16]).is_err());
    result.clear();
    assert!(crypto.cfb_encrypt(&[0; 32], &mut result, &[0; 16]).is_err());
    result.clear();
    assert!(crypto.ofb_encrypt(&[0; 32], &mut result, &[0; 16]).is_err());
    result.clear();
    assert!(crypto.cbc_decrypt(&[0; 32], &mut result, &[0; 16]).is_err());
}

/// The mode helpers must not assume `result` starts out empty.
#[test]
fn test_modes_append_to_non_empty_result() {
    let mut crypto = ToyBlock16{k: 0x31};
    let plain = vec![0x77u8; 48];
    let iv = vec![0x11u8; 16];

    let mut fresh = vec![];
    crypto.cbc_encrypt(&plain, &mut fresh, &iv).unwrap();

    let mut prefixed = vec![0xde, 0xad, 0xbe, 0xef];
    crypto.cbc_encrypt(&plain, &mut prefixed, &iv).unwrap();
    assert_eq!(&prefixed[4..], &fresh[..], "CBC output changed when result was not empty");

    let mut fresh_cfb = vec![];
    crypto.cfb_encrypt(&plain, &mut fresh_cfb, &iv).unwrap();
    let mut prefixed_cfb = vec![0xde, 0xad, 0xbe, 0xef];
    crypto.cfb_encrypt(&plain, &mut prefixed_cfb, &iv).unwrap();
    assert_eq!(&prefixed_cfb[4..], &fresh_cfb[..], "CFB output changed when result was not empty");
}