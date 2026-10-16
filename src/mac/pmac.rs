/*
PMAC, the parallelizable MAC of Black and Rogaway (Eurocrypt 2002).

Every block but the last is encrypted on its own, under an offset that
depends only on the key and the block's position, and the results are
XORed together; the last block goes into that sum unencrypted, and the
sum is encrypted once to give the tag. So the blocks can be processed in
any order and in parallel, which CMAC's chain cannot.

    L       = E_K(0^n)
    L(0)    = L,   L(i) = L(i-1) . x,   L(-1) = L . x^-1      (in GF(2^n))
    Offset  = 0,   Sigma = 0
    for i = 1 .. m-1:
        Offset = Offset ^ L(ntz(i))
        Sigma  = Sigma ^ E_K(M[i] ^ Offset)
    if |M[m]| = n:  Sigma = Sigma ^ M[m] ^ L(-1)
    else:           Sigma = Sigma ^ (M[m] || 10*)
    Tag = E_K(Sigma)

Four things are silent when wrong:

  * **the offsets are a Gray code**: `ntz(i)`, the number of trailing
    zero bits of the block's index, picks which `L(j)` to add. Counting
    `L(i)` straight (`i . L`) is a different MAC that agrees with itself.
  * **a whole final block takes `L(-1)`, a short one is padded**, and the
    empty message is a short one: `10*` padding of nothing, the block
    `0x80 00 ...`. The same trap as CMAC's.
  * **the final block is not encrypted before it joins the sum.** Only
    the sum is.
  * **`x^-1` is a shift right with the polynomial folded in** when the
    bit shifted out was set - the inverse of CMAC's doubling, under the
    same polynomial.

The field polynomial is CMAC's for the block size (`mac::cmac`). PMAC
is offered for 64 and 128 bit blocks, the sizes its implementations
other than this one cover: libtomcrypt 1.18.2, RustCrypto's `pmac` 0.7.1
and miscreant.go agree on every row of `vectors/pmac.vec`, with
Rogaway's published vectors among them.

Every encryption goes through `encrypt_blocks` - the independent blocks
in batches, and `L` and the final sum one block at a time - so AES's
bitsliced path is the one used, not its one-block table path;
`scripts/ct_check.py`'s `aes_pmac` row holds it there. The offsets
depend on the key and on positions, which are public, and are built
with XOR and masked doubling only.
*/

use crate::api::AnyBlockCipher;
use crate::block_ciphers::BlockCipher;
use crate::mac::cmac::{double, rb};
use crate::Mac;

/// Blocks encrypted per `encrypt_blocks` call.
const BATCH: usize = 32;

/// PMAC over a block cipher with a 64 or 128 bit block.
pub struct Pmac {
    cipher: AnyBlockCipher,
    block_size: usize,
    /// `L(0)` .. `L(63)`: an index's trailing zero count is below 64.
    l: Vec<Vec<u8>>,
    /// `L(-1)`, for a whole final block.
    l_inverse: Vec<u8>,
    offset: Vec<u8>,
    sigma: Vec<u8>,
    /// Blocks absorbed so far; the next one's index is this plus one.
    count: u64,
    /// Bytes not yet in a full block, held back because the last block
    /// is finished differently and a stream does not know which is last.
    pending: Vec<u8>,
    /// Offset-XORed blocks waiting for one `encrypt_blocks` call.
    batch: Vec<u8>,
}

impl core::fmt::Debug for Pmac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Pmac {{ {}, keys redacted }}", self.cipher.name())
    }
}

/// Multiply by `x^-1` in GF(2^n): shift right one bit and, if the bit
/// shifted out was set, fold in the polynomial's low terms shifted right
/// and set the top bit (the `x^n` term become `x^(n-1)`). Branchless: the
/// bit is a bit of `E_K(0)`.
fn halve(block: &mut [u8], rb: &[u8]) {
    let last = block.len() - 1;
    // Opaque for the reason `cmac::double`'s mask is.
    let mask = (crate::bignum::ct::opaque(u64::from(block[last] & 1)) as u8).wrapping_neg();
    // The polynomial's constant term is 1, so XORing it in clears the
    // bit being shifted out; then everything moves right together.
    for (byte, low) in block.iter_mut().zip(rb) {
        *byte ^= low & mask;
    }
    for index in (1..block.len()).rev() {
        block[index] = (block[index] >> 1) | (block[index - 1] << 7);
    }
    block[0] = (block[0] >> 1) | (mask & 0x80);
}

impl Pmac {
    /// `cipher` must already be keyed.
    pub fn new(mut cipher: AnyBlockCipher) -> Result<Pmac, String> {
        let block_size = cipher.blocksize();
        if block_size != 8 && block_size != 16 {
            return Err(format!(
                "PMAC is offered for 64 and 128 bit blocks; {} has a {} bit block.",
                cipher.name(), block_size * 8));
        }
        let rb = rb(block_size)?;
        // Through `encrypt_blocks`, single as it is: AES's one-block path
        // indexes tables with the state, and `L` is the key's secret.
        let mut l0 = vec![0u8; block_size];
        cipher.encrypt_blocks(&mut l0)?;
        let mut l = Vec::with_capacity(64);
        let mut current = l0.clone();
        for _ in 0..64 {
            l.push(current.clone());
            double(&mut current, &rb);
        }
        let mut l_inverse = l0;
        halve(&mut l_inverse, &rb);
        Ok(Pmac {
            cipher,
            block_size,
            l,
            l_inverse,
            offset: vec![0u8; block_size],
            sigma: vec![0u8; block_size],
            count: 0,
            pending: Vec::with_capacity(block_size),
            batch: Vec::with_capacity(BATCH * block_size),
        })
    }

    /// Build one from a cipher name and a key.
    pub fn with_key(cipher_name: &str, key: &[u8]) -> Result<Pmac, String> {
        Pmac::new(AnyBlockCipher::new(cipher_name, key, None)?)
    }

    /// The tag's length: one block.
    pub fn tag_len(&self) -> usize {
        self.block_size
    }

    /// Back to the start of a message under the same key.
    pub fn reset(&mut self) {
        self.offset.fill(0);
        self.sigma.fill(0);
        self.count = 0;
        self.pending.clear();
        self.batch.clear();
    }

    /// Queue one block that is not the last: XOR in its offset.
    fn queue(&mut self, block: &[u8]) {
        self.count += 1;
        let step = &self.l[self.count.trailing_zeros() as usize];
        for (o, s) in self.offset.iter_mut().zip(step) {
            *o ^= s;
        }
        let start = self.batch.len();
        self.batch.extend_from_slice(block);
        for (b, o) in self.batch[start..].iter_mut().zip(&self.offset) {
            *b ^= o;
        }
        if self.batch.len() == BATCH * self.block_size {
            self.flush();
        }
    }

    /// Encrypt the queued blocks and add them into the sum.
    fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        // `encrypt_blocks` fails only on a length that is not whole
        // blocks, which `queue` never builds.
        self.cipher.encrypt_blocks(&mut self.batch).expect("whole blocks");
        for block in self.batch.chunks(self.block_size) {
            for (s, b) in self.sigma.iter_mut().zip(block) {
                *s ^= b;
            }
        }
        self.batch.clear();
    }
}

impl Mac for Pmac {
    fn update(&mut self, input: &[u8]) {
        let mut rest = input;
        if !self.pending.is_empty() {
            let take = core::cmp::min(self.block_size - self.pending.len(), rest.len());
            self.pending.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            // A full `pending` with nothing after it may be the last block.
            if self.pending.len() == self.block_size && !rest.is_empty() {
                let block = core::mem::take(&mut self.pending);
                self.queue(&block);
                self.pending = block;
                self.pending.clear();
            }
        }
        while rest.len() > self.block_size {
            let (block, remaining) = rest.split_at(self.block_size);
            self.queue(block);
            rest = remaining;
        }
        self.pending.extend_from_slice(rest);
    }

    /// The tag, without consuming the state.
    fn digest(&mut self) -> Vec<u8> {
        self.flush();
        let mut sigma = self.sigma.clone();
        if self.pending.len() == self.block_size {
            for ((s, m), l) in sigma.iter_mut().zip(&self.pending).zip(&self.l_inverse) {
                *s ^= m ^ l;
            }
        } else {
            // Shorter, the empty message included: `10*` padding.
            for (s, m) in sigma.iter_mut().zip(&self.pending) {
                *s ^= m;
            }
            sigma[self.pending.len()] ^= 0x80;
        }
        // Through `encrypt_blocks`, as `L` is: the sum is secret too.
        self.cipher.encrypt_blocks(&mut sigma).expect("one whole block");
        sigma
    }
}

/// The tag over one message, for callers with all of it in hand.
pub fn pmac(cipher_name: &str, key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = Pmac::with_key(cipher_name, key)?;
    mac.update(message);
    Ok(mac.digest())
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

    /// `x^-1` undoes `x`, over both block sizes, whether or not the bit
    /// that falls off is set.
    #[test]
    fn test_halving_undoes_doubling() {
        for size in [8usize, 16] {
            let rb = rb(size).unwrap();
            for first in [0x00u8, 0x80, 0x7f, 0xff] {
                for last in [0x00u8, 0x01, 0xfe, 0xff] {
                    let mut block: Vec<u8> = (0..size as u8).map(|b| b.wrapping_mul(37)).collect();
                    block[0] = first;
                    block[size - 1] = last;
                    let original = block.clone();
                    halve(&mut block, &rb);
                    double(&mut block, &rb);
                    assert_eq!(block, original, "{size} {first:02x} {last:02x}");
                    double(&mut block, &rb);
                    halve(&mut block, &rb);
                    assert_eq!(block, original, "{size} {first:02x} {last:02x}");
                }
            }
        }
        // An odd block halves to the polynomial's image: x^-1 = x^(n-1) + (Rb >> 1).
        let mut one = vec![0u8; 16];
        one[15] = 1;
        halve(&mut one, &rb(16).unwrap());
        assert_eq!(hex(&one), "80000000000000000000000000000043");
    }

    /// Streaming in pieces of every size equals one call, and digest
    /// does not consume: the tag is the same twice, and more data
    /// continues the message.
    #[test]
    fn test_streaming_equals_one_call() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let message: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
        for cipher in ["aes", "blowfish"] {
            let whole = pmac(cipher, &key, &message).unwrap();
            for piece in [1usize, 3, 7, 8, 15, 16, 17, 64, 299] {
                let mut mac = Pmac::with_key(cipher, &key).unwrap();
                for chunk in message.chunks(piece) {
                    mac.update(chunk);
                }
                assert_eq!(mac.digest(), whole, "{cipher} {piece}");
                assert_eq!(mac.digest(), whole, "{cipher} {piece}, twice");
            }
            let mut mac = Pmac::with_key(cipher, &key).unwrap();
            mac.update(&message[..100]);
            let _ = mac.digest();
            mac.update(&message[100..]);
            assert_eq!(mac.digest(), whole, "{cipher}: digest, then more");
            mac.reset();
            mac.update(&message);
            assert_eq!(mac.digest(), whole, "{cipher}: after reset");
        }
    }

    /// More blocks than one batch, and a block index whose trailing
    /// zero count reaches a high `L(j)`, against the same message fed a
    /// block at a time (which flushes a batch at a different point).
    #[test]
    fn test_batches_do_not_change_the_answer() {
        let key = [7u8; 16];
        let message = vec![0x5au8; 16 * (3 * BATCH + 5) + 9];
        let whole = pmac("aes", &key, &message).unwrap();
        let mut mac = Pmac::with_key("aes", &key).unwrap();
        for chunk in message.chunks(16) {
            mac.update(chunk);
            let _ = mac.digest();
        }
        assert_eq!(mac.digest(), whole);
    }

    #[test]
    fn test_other_block_sizes_are_refused() {
        for (cipher, key) in [("shacal2", 16usize), ("rijndael-256", 32), ("threefish256", 32)] {
            let err = Pmac::with_key(cipher, &vec![0u8; key]).unwrap_err();
            assert!(err.contains("64 and 128 bit"), "{err}");
        }
    }
}
