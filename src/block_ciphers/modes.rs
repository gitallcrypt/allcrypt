/*
Streaming mode-of-operation wrappers.

Each mode comes in two pieces:

  * a `*State` struct that owns only the mode's own state (a counter, a
    feedback block, a keystream position) and takes the cipher as an argument
    to each call, and
  * a borrowing wrapper (`Ctr`, `Cfb`, `Ofb`, `Cbc`) that pairs that state
    with `&mut C` so Rust callers do not have to pass the cipher every time.

The split exists because a borrowing struct cannot be handed to a foreign
runtime: the Python bindings own the cipher in a `Box` and drive the `*State`
directly. It costs nothing - the wrappers are one-line delegations.

Nothing is cloned, the cipher keeps no mode state of its own, and the
per-block scratch buffers are allocated once per stream instead of once per
block. A new block cipher implements `blocksize`, `block_encrypt` and
`block_decrypt` and gets every mode here for free. Only a cipher with an
unusual counter needs to say anything more, by overriding `ctr_init` /
`ctr_next`.

CTR and CBC decryption have several independent blocks in hand and pass
them to `encrypt_blocks` / `decrypt_blocks` together - sixteen counter
blocks at a time for CTR, every whole block of the call for CBC
decryption. A cipher that overrides those (AES, with its constant-time
bitsliced path) is used that way; any other gets one `block_encrypt` per
block, as before.
*/

use super::BlockCipher;
use core::cmp::min;

/// Blocks of keystream a counter mode generates per call to the cipher:
/// sixteen is AES's bitsliced batch, and for a cipher without one it is
/// sixteen calls to `block_encrypt` as before.
const KEYSTREAM_BLOCKS: usize = 16;

/// XOR `src` into `dst` in place, over the common prefix length.
#[inline]
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

/// Shared by every `update`: copy into the output, transform in place, and
/// roll the output back if the transform failed so no plaintext is left over.
#[inline]
fn update_via<F>(input: &[u8], out: &mut Vec<u8>, apply: F) -> Result<(), String>
where F: FnOnce(&mut [u8]) -> Result<(), String> {
    let start = out.len();
    out.extend_from_slice(input);
    let r = apply(&mut out[start..]);
    if r.is_err() {
        out.truncate(start);
    }
    r
}

// ---------------------------------------------------------------- CTR ------

/// Counter mode state. Keystream is `E(counter)` for a counter that advances
/// one block at a time; encryption and decryption are the same operation.
pub struct CtrState {
    counter: Vec<u8>,
    keystream: Vec<u8>,
    pos: usize,
    /// The whole block counts as one little-endian integer.
    little_endian: bool,
}

impl CtrState {
    pub fn new<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8]) -> Result<Self, String> {
        let bs = cipher.blocksize();
        let mut counter = Vec::with_capacity(bs);
        cipher.ctr_init(iv, &mut counter)?;
        if counter.len() != bs {
            return Err("ctr_init did not produce exactly one counter block.".to_string());
        }
        Ok(CtrState { counter, keystream: Vec::with_capacity(bs * KEYSTREAM_BLOCKS), pos: 0,
                      little_endian: false })
    }

    /// Counter mode with the whole block as one **little-endian** counter:
    /// Brian Gladman's `fileenc`, which WinZip's AES encryption uses with
    /// a counter starting at 1. The IV is the first counter block, whole;
    /// a cipher's own counter (`ctr_init`, `ctr_next`) does not apply.
    pub fn new_little_endian<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8])
                                                      -> Result<Self, String> {
        let bs = cipher.blocksize();
        if iv.len() != bs {
            return Err(format!("A little-endian counter's first block is {bs} bytes, \
                                not {}.", iv.len()));
        }
        Ok(CtrState { counter: iv.to_vec(), keystream: Vec::with_capacity(bs * KEYSTREAM_BLOCKS),
                      pos: 0, little_endian: true })
    }

    fn advance<C: BlockCipher + ?Sized>(&mut self, cipher: &C) {
        if self.little_endian {
            for b in self.counter.iter_mut() {
                let (v, carry) = b.overflowing_add(1);
                *b = v;
                if !carry {
                    break;
                }
            }
        } else {
            cipher.ctr_next(&mut self.counter);
        }
    }

    /// Apply the keystream to `buf` in place. No allocation, no copying.
    pub fn apply<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, buf: &mut [u8]) -> Result<(), String> {
        let bs = cipher.blocksize();
        let mut done = 0;
        while done < buf.len() {
            if self.pos == self.keystream.len() && !self.little_endian
                && buf.len() - done >= bs {
                // Whole blocks in one pass, where the cipher has one.
                let whole = (buf.len() - done) / bs * bs;
                if cipher.ctr_xor(&mut self.counter, &mut buf[done..done + whole], false)? {
                    done += whole;
                    continue;
                }
            }
            if self.pos == self.keystream.len() {
                // As many counter blocks as the rest of `buf` needs, up to
                // KEYSTREAM_BLOCKS, encrypted in one `encrypt_blocks` call.
                // Keystream left over is used by the next call; `counter`
                // is always the next block not yet generated.
                let wanted = (buf.len() - done).div_ceil(bs).min(KEYSTREAM_BLOCKS);
                self.keystream.clear();
                self.keystream.resize(wanted * bs, 0);
                if !self.little_endian {
                    cipher.ctr_fill(&mut self.counter, &mut self.keystream);
                } else {
                    for at in (0..wanted * bs).step_by(bs) {
                        self.keystream[at..at + bs].copy_from_slice(&self.counter);
                        self.advance(cipher);
                    }
                }
                cipher.encrypt_blocks(&mut self.keystream)?;
                self.pos = 0;
            }
            let n = min(buf.len() - done, self.keystream.len() - self.pos);
            xor_into(&mut buf[done..done+n], &self.keystream[self.pos..self.pos+n]);
            done += n;
            self.pos += n;
        }
        Ok(())
    }

    pub fn update<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, input: &[u8],
                                           out: &mut Vec<u8>) -> Result<(), String> {
        update_via(input, out, |buf| self.apply(cipher, buf))
    }
}

/// CTR paired with the cipher it drives.
pub struct Ctr<'a, C: BlockCipher + ?Sized> {
    cipher: &'a mut C,
    state: CtrState,
}

impl<'a, C: BlockCipher + ?Sized> Ctr<'a, C> {
    pub fn new(cipher: &'a mut C, iv: &[u8]) -> Result<Self, String> {
        let state = CtrState::new(cipher, iv)?;
        Ok(Ctr { cipher, state })
    }
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<(), String> {
        self.state.apply(self.cipher, buf)
    }
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        self.state.update(self.cipher, input, out)
    }
}

// ---------------------------------------------------------------- OFB ------

/// Output feedback state. The keystream is `E(E(...E(IV)))`, independent of
/// the data, so encryption and decryption are again the same operation.
pub struct OfbState {
    /// Current keystream block, which is also the input to the next one.
    block: Vec<u8>,
    scratch: Vec<u8>,
    pos: usize,
}

impl OfbState {
    pub fn new<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8]) -> Result<Self, String> {
        let bs = cipher.blocksize();
        if iv.len() != bs {
            return Err("IV size not same as blocksize.".to_string());
        }
        let mut block = Vec::with_capacity(bs);
        block.extend_from_slice(iv);
        // `pos == bs` means the block currently holds the IV, not keystream.
        Ok(OfbState { block, scratch: Vec::with_capacity(bs), pos: bs })
    }

    pub fn apply<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, buf: &mut [u8]) -> Result<(), String> {
        let bs = cipher.blocksize();
        let mut done = 0;
        while done < buf.len() {
            if self.pos == bs {
                self.scratch.clear();
                cipher.block_encrypt(&self.block, &mut self.scratch);
                if self.scratch.len() != bs {
                    return Err("block_encrypt did not produce exactly one block.".to_string());
                }
                // Swap rather than copy: the new keystream block is also the
                // input that produces the one after it.
                core::mem::swap(&mut self.block, &mut self.scratch);
                self.pos = 0;
            }
            let n = min(buf.len() - done, bs - self.pos);
            xor_into(&mut buf[done..done+n], &self.block[self.pos..self.pos+n]);
            done += n;
            self.pos += n;
        }
        Ok(())
    }

    pub fn update<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, input: &[u8],
                                           out: &mut Vec<u8>) -> Result<(), String> {
        update_via(input, out, |buf| self.apply(cipher, buf))
    }
}

pub struct Ofb<'a, C: BlockCipher + ?Sized> {
    cipher: &'a mut C,
    state: OfbState,
}

impl<'a, C: BlockCipher + ?Sized> Ofb<'a, C> {
    pub fn new(cipher: &'a mut C, iv: &[u8]) -> Result<Self, String> {
        let state = OfbState::new(cipher, iv)?;
        Ok(Ofb { cipher, state })
    }
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<(), String> {
        self.state.apply(self.cipher, buf)
    }
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        self.state.update(self.cipher, input, out)
    }
}

// ---------------------------------------------------------------- CFB ------

/// Full block cipher feedback state (CFB-128 for a 16 byte cipher, CFB-64 for
/// an 8 byte one). The feedback block is the ciphertext, so the two
/// directions differ only in which byte gets fed back.
pub struct CfbState {
    feedback: Vec<u8>,
    keystream: Vec<u8>,
    pos: usize,
    decrypting: bool,
}

impl CfbState {
    pub fn new<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8], decrypting: bool) -> Result<Self, String> {
        let bs = cipher.blocksize();
        if iv.len() != bs {
            return Err("IV size not same as blocksize.".to_string());
        }
        let mut feedback = Vec::with_capacity(bs);
        feedback.extend_from_slice(iv);
        Ok(CfbState { feedback, keystream: Vec::with_capacity(bs), pos: bs, decrypting })
    }

    pub fn apply<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, buf: &mut [u8]) -> Result<(), String> {
        let bs = cipher.blocksize();
        for b in buf.iter_mut() {
            if self.pos == bs {
                self.keystream.clear();
                cipher.block_encrypt(&self.feedback, &mut self.keystream);
                if self.keystream.len() != bs {
                    return Err("block_encrypt did not produce exactly one block.".to_string());
                }
                self.pos = 0;
            }
            // The ciphertext byte is fed back either way: on the way out when
            // encrypting, on the way in when decrypting.
            if self.decrypting {
                self.feedback[self.pos] = *b;
                *b ^= self.keystream[self.pos];
            } else {
                *b ^= self.keystream[self.pos];
                self.feedback[self.pos] = *b;
            }
            self.pos += 1;
        }
        Ok(())
    }

    pub fn update<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, input: &[u8],
                                           out: &mut Vec<u8>) -> Result<(), String> {
        update_via(input, out, |buf| self.apply(cipher, buf))
    }
}

pub struct Cfb<'a, C: BlockCipher + ?Sized> {
    cipher: &'a mut C,
    state: CfbState,
}

impl<'a, C: BlockCipher + ?Sized> Cfb<'a, C> {
    pub fn encryptor(cipher: &'a mut C, iv: &[u8]) -> Result<Self, String> {
        let state = CfbState::new(cipher, iv, false)?;
        Ok(Cfb { cipher, state })
    }
    pub fn decryptor(cipher: &'a mut C, iv: &[u8]) -> Result<Self, String> {
        let state = CfbState::new(cipher, iv, true)?;
        Ok(Cfb { cipher, state })
    }
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<(), String> {
        self.state.apply(self.cipher, buf)
    }
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        self.state.update(self.cipher, input, out)
    }
}

// ---------------------------------------------------------------- CBC ------

/// Cipher block chaining state. Unlike the others this is not a stream:
/// output only appears a whole block at a time, so `update` buffers a partial
/// tail and `finish` reports if anything is left over.
pub struct CbcState {
    /// Previous ciphertext block.
    chain: Vec<u8>,
    /// Partial input block carried between calls.
    partial: Vec<u8>,
    scratch: Vec<u8>,
    decrypting: bool,
}

impl CbcState {
    pub fn new<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8], decrypting: bool) -> Result<Self, String> {
        let bs = cipher.blocksize();
        if iv.len() != bs {
            return Err("IV size not same as blocksize.".to_string());
        }
        let mut chain = Vec::with_capacity(bs);
        chain.extend_from_slice(iv);
        Ok(CbcState {
            chain,
            partial: Vec::with_capacity(bs),
            scratch: Vec::with_capacity(bs),
            decrypting,
        })
    }

    fn crunch<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, block: &[u8],
                                       out: &mut Vec<u8>) -> Result<(), String> {
        if self.decrypting {
            let from = out.len();
            out.extend_from_slice(block);
            cipher.decrypt_block_in_place(&mut out[from..], &mut self.scratch)
                .inspect_err(|_| out.truncate(from))?;
            xor_into(&mut out[from..], &self.chain);
            // The chain for the next block is this block's ciphertext.
            self.chain.copy_from_slice(block);
        } else {
            xor_into(&mut self.chain, block);
            cipher.encrypt_block_in_place(&mut self.chain, &mut self.scratch)?;
            out.extend_from_slice(&self.chain);
        }
        Ok(())
    }

    pub fn update<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, mut input: &[u8],
                                           out: &mut Vec<u8>) -> Result<(), String> {
        let bs = cipher.blocksize();
        let start = out.len();

        if !self.partial.is_empty() {
            let take = min(bs - self.partial.len(), input.len());
            self.partial.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.partial.len() < bs {
                return Ok(());
            }
            let block = core::mem::take(&mut self.partial);
            let r = self.crunch(cipher, &block, out);
            self.partial = block;
            self.partial.clear();
            if let Err(e) = r {
                out.truncate(start);
                return Err(e);
            }
        }

        let full = input.len() / bs;
        if self.decrypting && full > 1 {
            // Decryption has every ciphertext block in hand, so the block
            // decryptions are independent: one `decrypt_blocks` call, then
            // each block XORed with the ciphertext before it.
            let whole = &input[..full * bs];
            let from = out.len();
            out.extend_from_slice(whole);
            if let Err(e) = cipher.decrypt_blocks(&mut out[from..]) {
                out.truncate(start);
                return Err(e);
            }
            xor_into(&mut out[from..from + bs], &self.chain);
            // Every later block takes the ciphertext block before it: the
            // input shifted by one block, as one run.
            xor_into(&mut out[from + bs..from + full * bs], &whole[..(full - 1) * bs]);
            self.chain.clear();
            self.chain.extend_from_slice(&whole[(full - 1) * bs..]);
        } else if !self.decrypting && full > 0 {
            // Encryption is a chain, a block at a time, each written where
            // it lands in `out` and XORed into the next from there.
            let from = out.len();
            out.extend_from_slice(&input[..full * bs]);
            let mut previous = core::mem::take(&mut self.chain);
            for block in out[from..].chunks_exact_mut(bs) {
                xor_into(block, &previous);
                if let Err(e) = cipher.encrypt_block_in_place(block, &mut self.scratch) {
                    out.truncate(start);
                    self.chain = previous;
                    return Err(e);
                }
                previous.copy_from_slice(block);
            }
            self.chain = previous;
        } else {
            for i in 0..full {
                if let Err(e) = self.crunch(cipher, &input[i*bs..(i+1)*bs], out) {
                    out.truncate(start);
                    return Err(e);
                }
            }
        }
        self.partial.extend_from_slice(&input[full*bs..]);
        Ok(())
    }

    /// True if a partial block is still buffered.
    pub fn has_partial(&self) -> bool {
        !self.partial.is_empty()
    }

    pub fn finish(&self) -> Result<(), String> {
        if self.has_partial() {
            return Err("Input length not a multiple of block size, (padding is needed).".to_string());
        }
        Ok(())
    }
}

// ------------------------------------------- CBC with ciphertext stealing ---

/// Which of NIST's three orderings of the last two blocks (SP 800-38A
/// Addendum, 2010). All three are CBC with the last plaintext block
/// zero-padded and the padding's ciphertext not sent; they differ only in
/// how the final two ciphertext pieces are written:
///
/// - **CS1** keeps CBC's order: the cut-down second-to-last block, then
///   the last. A whole-block message is plain CBC.
/// - **CS2** swaps the two when the last block is partial, and is plain
///   CBC when it is whole.
/// - **CS3** always swaps them, a whole last block included. This is
///   Kerberos's (RFC 3962) and the oldest form, from Meyer and Matyas.
///
/// OpenSSL's `AES-128-CBC-CTS` takes the same three names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CtsVariant {
    Cs1,
    Cs2,
    Cs3,
}

/// CBC with ciphertext stealing. Any length of at least one block, and
/// the ciphertext is exactly as long as the plaintext.
///
/// It cannot stream all the way: the last two blocks are decided only
/// at the end, so up to two blocks (and any partial one) are held back
/// until `finish`, which writes them.
pub struct CtsState {
    cbc: CbcState,
    held: Vec<u8>,
    variant: CtsVariant,
    decrypting: bool,
}

impl CtsState {
    pub fn new<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8], variant: CtsVariant,
                                        decrypting: bool) -> Result<Self, String> {
        Ok(CtsState {
            cbc: CbcState::new(cipher, iv, decrypting)?,
            held: Vec::with_capacity(3 * cipher.blocksize()),
            variant,
            decrypting,
        })
    }

    /// Everything but the last two blocks goes through as plain CBC.
    pub fn update<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, input: &[u8],
                                           out: &mut Vec<u8>) -> Result<(), String> {
        let bs = cipher.blocksize();
        self.held.extend_from_slice(input);
        if self.held.len() > 2 * bs {
            let take = (self.held.len() - bs - 1) / bs * bs;
            let ready: Vec<u8> = self.held.drain(..take).collect();
            self.cbc.update(cipher, &ready, out)?;
        }
        Ok(())
    }

    /// The last two blocks. Refuses a message shorter than one block,
    /// which ciphertext stealing has nothing to steal from.
    pub fn finish<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, out: &mut Vec<u8>)
                                           -> Result<(), String> {
        let bs = cipher.blocksize();
        let held = core::mem::take(&mut self.held);
        if held.len() < bs {
            return Err(format!("Ciphertext stealing needs at least one {bs}-byte block; \
                                the message is shorter."));
        }
        if held.len() == bs {
            return self.cbc.update(cipher, &held, out);
        }
        let d = held.len() - bs;
        let whole = d == bs;
        // Whether the last two pieces are written swapped.
        let swapped = match self.variant {
            CtsVariant::Cs1 => false,
            CtsVariant::Cs2 => !whole,
            CtsVariant::Cs3 => true,
        };
        if !self.decrypting {
            let mut c1 = Vec::with_capacity(bs);
            self.cbc.update(cipher, &held[..bs], &mut c1)?;
            let mut last = held[bs..].to_vec();
            last.resize(bs, 0);
            let mut c2 = Vec::with_capacity(bs);
            self.cbc.update(cipher, &last, &mut c2)?;
            if swapped {
                out.extend_from_slice(&c2);
                out.extend_from_slice(&c1[..d]);
            } else {
                out.extend_from_slice(&c1[..d]);
                out.extend_from_slice(&c2);
            }
            return Ok(());
        }
        // The stolen piece is the second-to-last ciphertext block cut to
        // d bytes; the rest of that block is in D(C_n) at the padding's
        // place.
        let (stolen, cn) = if swapped { (&held[bs..], &held[..bs]) }
                           else { (&held[..d], &held[d..]) };
        let mut decrypted = Vec::with_capacity(bs);
        cipher.block_decrypt(cn, &mut decrypted);
        if decrypted.len() != bs {
            return Err("block_decrypt did not produce exactly one block.".to_string());
        }
        let mut c_prev = stolen.to_vec();
        c_prev.extend_from_slice(&decrypted[d..]);
        let last: Vec<u8> = decrypted[..d].iter().zip(stolen).map(|(a, b)| a ^ b).collect();
        self.cbc.update(cipher, &c_prev, out)?;
        out.extend_from_slice(&last);
        Ok(())
    }
}

// --------------------------------------------------------------- PCBC ------

/// Propagating CBC.
///
/// CBC chains the previous **ciphertext** into the next block. PCBC
/// chains the previous plaintext **XOR** the previous ciphertext:
///
/// ```text
/// C_i = E(P_i ^ P_{i-1} ^ C_{i-1})
/// P_i = D(C_i) ^ P_{i-1} ^ C_{i-1}
/// ```
///
/// with `P_0 ^ C_0` taken to be the IV.
///
/// **What it is for, and what it is not.** PCBC propagates a corrupted
/// block to every block after it, where CBC's damage stops after two.
/// That was the point: Kerberos 4 used it so that a truncated or
/// altered message would decrypt to garbage from the alteration
/// onwards, as a poor man's integrity check.
///
/// It does not work. **Swapping two adjacent ciphertext blocks leaves
/// everything after them intact**, because the two `P ^ C` terms
/// cancel. That is why Kerberos 5 dropped it and why nothing since has
/// used it. `test_swapping_two_blocks_is_not_detected` asserts it,
/// because a mode whose weakness is undocumented is a mode somebody
/// will reach for on the strength of its name.
///
/// It is here because Kerberos 4 traffic and files encrypted by it
/// exist, and this library's reason to exist is that they are still out
/// there. Use an AEAD.
pub struct PcbcState {
    /// `P_{i-1} ^ C_{i-1}`, starting as the IV.
    chain: Vec<u8>,
    partial: Vec<u8>,
    scratch: Vec<u8>,
    decrypting: bool,
}

impl PcbcState {
    pub fn new<C: BlockCipher + ?Sized>(cipher: &mut C, iv: &[u8], decrypting: bool)
                                        -> Result<Self, String> {
        let bs = cipher.blocksize();
        if iv.len() != bs {
            return Err("IV size not same as blocksize.".to_string());
        }
        Ok(PcbcState {
            chain: iv.to_vec(),
            partial: Vec::with_capacity(bs),
            scratch: Vec::with_capacity(bs),
            decrypting,
        })
    }

    fn crunch<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, block: &[u8],
                                       out: &mut Vec<u8>) -> Result<(), String> {
        let bs = cipher.blocksize();
        self.scratch.clear();
        if self.decrypting {
            cipher.block_decrypt(block, &mut self.scratch);
            if self.scratch.len() != bs {
                return Err("block_decrypt did not produce exactly one block.".to_string());
            }
            xor_into(&mut self.scratch, &self.chain);
            // The next chain is this plaintext XOR this ciphertext.
            for (c, (p, ct)) in self.chain.iter_mut()
                                    .zip(self.scratch.iter().zip(block.iter())) {
                *c = p ^ ct;
            }
            out.extend_from_slice(&self.scratch);
        } else {
            // `chain` is P_{i-1} ^ C_{i-1}; XOR the plaintext in and
            // encrypt.
            let mut input = self.chain.clone();
            xor_into(&mut input, block);
            cipher.block_encrypt(&input, &mut self.scratch);
            if self.scratch.len() != bs {
                return Err("block_encrypt did not produce exactly one block.".to_string());
            }
            for (c, (p, ct)) in self.chain.iter_mut()
                                    .zip(block.iter().zip(self.scratch.iter())) {
                *c = p ^ ct;
            }
            out.extend_from_slice(&self.scratch);
        }
        Ok(())
    }

    pub fn update<C: BlockCipher + ?Sized>(&mut self, cipher: &mut C, mut input: &[u8],
                                           out: &mut Vec<u8>) -> Result<(), String> {
        let bs = cipher.blocksize();
        let start = out.len();

        if !self.partial.is_empty() {
            let take = min(bs - self.partial.len(), input.len());
            self.partial.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.partial.len() < bs {
                return Ok(());
            }
            let block = core::mem::take(&mut self.partial);
            let r = self.crunch(cipher, &block, out);
            self.partial = block;
            self.partial.clear();
            if let Err(e) = r {
                out.truncate(start);
                return Err(e);
            }
        }

        let full = input.len() / bs;
        for i in 0..full {
            if let Err(e) = self.crunch(cipher, &input[i * bs..(i + 1) * bs], out) {
                out.truncate(start);
                return Err(e);
            }
        }
        self.partial.extend_from_slice(&input[full * bs..]);
        Ok(())
    }

    pub fn has_partial(&self) -> bool {
        !self.partial.is_empty()
    }

    pub fn finish(&self) -> Result<(), String> {
        if self.has_partial() {
            return Err("Input length not a multiple of block size, (padding is needed).".to_string());
        }
        Ok(())
    }
}

pub struct Pcbc<'a, C: BlockCipher + ?Sized> {
    cipher: &'a mut C,
    state: PcbcState,
}

impl<'a, C: BlockCipher + ?Sized> Pcbc<'a, C> {
    pub fn encryptor(cipher: &'a mut C, iv: &[u8]) -> Result<Self, String> {
        let state = PcbcState::new(cipher, iv, false)?;
        Ok(Pcbc { cipher, state })
    }
    pub fn decryptor(cipher: &'a mut C, iv: &[u8]) -> Result<Self, String> {
        let state = PcbcState::new(cipher, iv, true)?;
        Ok(Pcbc { cipher, state })
    }
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        self.state.update(self.cipher, input, out)
    }
    pub fn finish(self) -> Result<(), String> {
        self.state.finish()
    }
}

pub struct Cbc<'a, C: BlockCipher + ?Sized> {
    cipher: &'a mut C,
    state: CbcState,
}

impl<'a, C: BlockCipher + ?Sized> Cbc<'a, C> {
    pub fn encryptor(cipher: &'a mut C, iv: &[u8]) -> Result<Self, String> {
        let state = CbcState::new(cipher, iv, false)?;
        Ok(Cbc { cipher, state })
    }
    pub fn decryptor(cipher: &'a mut C, iv: &[u8]) -> Result<Self, String> {
        let state = CbcState::new(cipher, iv, true)?;
        Ok(Cbc { cipher, state })
    }
    pub fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        self.state.update(self.cipher, input, out)
    }
    /// Consume the stream, erroring if a partial block was left unprocessed.
    pub fn finish(self) -> Result<(), String> {
        self.state.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_ciphers::aes::AesCrypto;

    fn cipher() -> AesCrypto {
        AesCrypto::new(vec![0x2b; 16]).unwrap()
    }

    fn encrypt(plain: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        cipher().pcbc_encrypt(plain, &mut out, iv.to_vec()).unwrap();
        out
    }

    fn decrypt(ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        cipher().pcbc_decrypt(ciphertext, &mut out, iv.to_vec()).unwrap();
        out
    }

    #[test]
    fn test_round_trip() {
        for blocks in 1..=6 {
            let plain: Vec<u8> = (0..blocks * 16).map(|i| (i * 7 + 3) as u8).collect();
            let iv = [0x11u8; 16];
            let out = encrypt(&plain, &iv);
            assert_eq!(out.len(), plain.len());
            assert_eq!(decrypt(&out, &iv), plain);
        }
    }

    /// **PCBC is not CBC**, and the first block is where they agree - so
    /// a test using one block would pass for either.
    #[test]
    fn test_it_differs_from_cbc_from_the_second_block_on() {
        let plain: Vec<u8> = (0..48u8).collect();
        let iv = [0x11u8; 16];
        let pcbc = encrypt(&plain, &iv);
        let mut cbc = Vec::new();
        cipher().cbc_encrypt(&plain, &mut cbc, iv.to_vec()).unwrap();

        assert_eq!(&pcbc[..16], &cbc[..16], "the first block is the same in both");
        assert_ne!(&pcbc[16..32], &cbc[16..32]);
        assert_ne!(&pcbc[32..], &cbc[32..]);
    }

    /// The propagating property: a corrupted block ruins **every** block
    /// after it, where CBC's damage stops after two. This is what PCBC
    /// was for.
    #[test]
    fn test_corruption_propagates_to_the_end() {
        let plain = vec![0x41u8; 80];
        let iv = [0x11u8; 16];
        let mut ciphertext = encrypt(&plain, &iv);
        ciphertext[0] ^= 0x01;
        let out = decrypt(&ciphertext, &iv);

        // Every block differs, not just the first two.
        for block in 0..5 {
            assert_ne!(&out[block * 16..(block + 1) * 16], &plain[block * 16..(block + 1) * 16],
                       "block {block} survived the corruption");
        }

        // CBC, for contrast: the third block onwards is intact.
        let mut cbc = Vec::new();
        cipher().cbc_encrypt(&plain, &mut cbc, iv.to_vec()).unwrap();
        cbc[0] ^= 0x01;
        let mut recovered = Vec::new();
        cipher().cbc_decrypt(&cbc, &mut recovered, iv.to_vec()).unwrap();
        assert_eq!(&recovered[32..], &plain[32..],
                   "CBC's damage should stop after two blocks");
    }

    /// **And the reason Kerberos 5 dropped it.** Swapping two adjacent
    /// ciphertext blocks leaves everything after them intact, because
    /// the two `P ^ C` terms cancel - so the propagation PCBC was chosen
    /// for does not actually detect a reordering.
    ///
    /// Asserted rather than merely written down, because a mode whose
    /// weakness is only in a comment is a mode somebody will reach for
    /// on the strength of its name.
    #[test]
    fn test_swapping_two_blocks_is_not_detected() {
        let plain: Vec<u8> = (0..96u8).collect();
        let iv = [0x11u8; 16];
        let ciphertext = encrypt(&plain, &iv);

        // Swap blocks 1 and 2 (leaving block 0 and the tail alone).
        let mut swapped = ciphertext.clone();
        for i in 0..16 {
            swapped.swap(16 + i, 32 + i);
        }
        let out = decrypt(&swapped, &iv);

        // The two swapped blocks decrypt to garbage...
        assert_ne!(&out[16..32], &plain[16..32]);
        assert_ne!(&out[32..48], &plain[32..48]);
        // ...and everything after them comes back **intact**, which is
        // the whole failure.
        assert_eq!(&out[48..], &plain[48..],
                   "the P ^ C terms should cancel, leaving the tail readable");
    }

    #[test]
    fn test_a_ragged_length_is_refused() {
        let iv = [0x11u8; 16];
        for length in [1usize, 15, 17, 31] {
            let mut out = Vec::new();
            let error = cipher()
                .pcbc_encrypt(&vec![0u8; length], &mut out, iv.to_vec())
                .unwrap_err();
            assert!(error.contains("multiple of block size"), "{error}");
            assert!(out.is_empty(), "output was written before the refusal");
        }
    }

    #[test]
    fn test_a_wrong_iv_length_is_refused() {
        for length in [0usize, 8, 15, 17, 32] {
            let mut out = Vec::new();
            assert!(cipher().pcbc_encrypt(&[0u8; 16], &mut out, vec![0; length]).is_err(),
                    "accepted a {length} byte IV");
        }
    }

    #[test]
    fn test_streaming_in_pieces_equals_one_call() {
        let plain: Vec<u8> = (0..160u8).collect();
        let iv = [0x11u8; 16];
        let whole = encrypt(&plain, &iv);
        for chunk in [1usize, 3, 7, 16, 17, 31, 48] {
            let mut cipher = cipher();
            let mut stream = Pcbc::encryptor(&mut cipher, &iv).unwrap();
            let mut out = Vec::new();
            for piece in plain.chunks(chunk) {
                stream.update(piece, &mut out).unwrap();
            }
            stream.finish().unwrap();
            assert_eq!(out, whole, "chunked by {chunk}");
        }
    }

    /// PCBC over a 64 bit block cipher, because Kerberos 4 used DES -
    /// the block size must come from the cipher rather than being
    /// assumed to be 16.
    #[test]
    fn test_it_works_on_a_64_bit_block_cipher() {
        use crate::block_ciphers::des::Des;
        let plain: Vec<u8> = (0..32u8).collect();
        let iv = [0x22u8; 8];
        let mut out = Vec::new();
        Des::new(vec![0x13; 8]).unwrap()
            .pcbc_encrypt(&plain, &mut out, iv.to_vec()).unwrap();
        assert_eq!(out.len(), 32);
        let mut back = Vec::new();
        Des::new(vec![0x13; 8]).unwrap()
            .pcbc_decrypt(&out, &mut back, iv.to_vec()).unwrap();
        assert_eq!(back, plain);
    }

    /// RFC 3962 appendix B: six CS3 vectors under "chicken teriyaki",
    /// read out of the vendored document. Each label line is followed by
    /// `0000:`-style hex lines.
    #[test]
    fn test_rfc_3962_ciphertext_stealing() {
        use crate::block_ciphers::aes::AesCrypto;
        let doc = include_str!("../../rfcs/rfc3962.txt");
        let text = &doc[doc.find("Some test vectors for CBC with ciphertext stealing").unwrap()..];
        let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
        let mut open = false;
        for line in text.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if open && tokens.first().is_some_and(|t| t.len() == 5 && t.ends_with(':')) {
                for t in &tokens[1..] {
                    fields.last_mut().unwrap().1.push(u8::from_str_radix(t, 16).unwrap());
                }
            } else if line.trim().ends_with(':') {
                fields.push((line.trim().trim_end_matches(':').to_string(), Vec::new()));
                open = true;
            } else if !line.trim().is_empty() && !line.contains("[Page") && !line.starts_with("RFC ") {
                open = false;
            }
        }
        assert_eq!(fields[0].0, "AES 128-bit key");
        let key = fields[0].1.clone();
        let mut count = 0;
        for group in fields[1..].chunks(4) {
            let (iv, input, output) = (&group[0].1, &group[1].1, &group[2].1);
            assert_eq!((group[0].0.as_str(), group[1].0.as_str()), ("IV", "Input"));
            let mut out = Vec::new();
            AesCrypto::new(key.clone()).unwrap()
                .cbc_cs_encrypt(input, &mut out, iv, CtsVariant::Cs3).unwrap();
            assert_eq!(&out, output);
            let mut back = Vec::new();
            AesCrypto::new(key.clone()).unwrap()
                .cbc_cs_decrypt(output, &mut back, iv, CtsVariant::Cs3).unwrap();
            assert_eq!(&back, input);
            count += 1;
        }
        assert_eq!(count, 6);
    }

    /// CS1 and CS2 are CS3 with the last two pieces in CBC's order: CS1
    /// always, CS2 when the last block is whole. RFC 3962 pins CS3;
    /// `scripts/diff_check.py block` checks all three against OpenSSL.
    #[test]
    fn test_the_three_stealings_order_the_last_two() {
        use crate::block_ciphers::aes::AesCrypto;
        let iv: Vec<u8> = (100..116).collect();
        for n in [16usize, 17, 31, 32, 33, 47, 48, 100] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 1) as u8).collect();
            let encrypt = |variant| {
                let mut out = Vec::new();
                AesCrypto::new((0..16).collect()).unwrap()
                    .cbc_cs_encrypt(&data, &mut out, &iv, variant).unwrap();
                out
            };
            let cs3 = encrypt(CtsVariant::Cs3);
            // CS3 ends with C_n (16 bytes) then the stolen piece (d).
            let d = n - 16 * ((n - 1) / 16);
            let unswapped = if n == 16 {
                cs3.clone()
            } else {
                [&cs3[..n - 16 - d], &cs3[n - d..], &cs3[n - 16 - d..n - d]].concat()
            };
            assert_eq!(encrypt(CtsVariant::Cs1), unswapped, "CS1 at {n}");
            let whole = n.is_multiple_of(16);
            assert_eq!(encrypt(CtsVariant::Cs2), if whole { unswapped } else { cs3 },
                       "CS2 at {n}");
        }
    }

    #[test]
    fn test_ciphertext_stealing_needs_a_block_and_ctr_le_a_whole_iv() {
        use crate::block_ciphers::aes::AesCrypto;
        let mut aes = AesCrypto::new(vec![0; 16]).unwrap();
        for n in 0..16 {
            for variant in [CtsVariant::Cs1, CtsVariant::Cs2, CtsVariant::Cs3] {
                let mut out = Vec::new();
                assert!(aes.cbc_cs_encrypt(&vec![0; n], &mut out, &[0; 16], variant).is_err());
                assert!(aes.cbc_cs_decrypt(&vec![0; n], &mut out, &[0; 16], variant).is_err());
                assert!(out.is_empty());
            }
        }
        let mut out = Vec::new();
        assert!(aes.ctr_le_encrypt(b"x", &mut out, &[1; 8]).is_err());
        assert!(aes.ctr_le_encrypt(b"x", &mut out, &[1; 17]).is_err());
    }
}
