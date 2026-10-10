/*
GHASH: the universal hash underneath GCM (NIST SP 800-38D section 6.4).

GHASH is a polynomial evaluation in GF(2^128). The message is cut into
16 byte blocks, each block is one coefficient, and the hash is the
polynomial evaluated at the secret point H = E_K(0^128):

    Y_0 = 0
    Y_i = (Y_{i-1} XOR X_i) * H
    GHASH(X) = Y_n

That is all it is. The subtlety is entirely in the field.

## The field, and why the bits look backwards

The field is GF(2^128) modulo x^128 + x^7 + x^2 + x + 1. GCM numbers the
bits of a block **left to right**: bit 0 is the most significant bit of
byte 0, and that bit is the coefficient of x^0. So the polynomial's low
order coefficient sits at the high end of the first byte, which is the
reverse of every other bit convention in this library.

The consequence is that multiplying by x - which would be a left shift in
the usual convention - is a **right** shift here, and the reduction
constant is 0xe1 in the first byte rather than 0x87 in the last. Getting
this backwards produces a perfectly self-consistent hash that no other
implementation agrees with, which is exactly the kind of bug that passes a
round-trip test and fails against OpenSSL. `diff_check.py` is what settles
it.

## Multiplication by integer multiplies

`gf_mul` below is the textbook shift-and-add, 128 iterations with both
conditionals done as masks. It is kept as the reference the fast path is
tested against.

The hash itself uses `HKey::mul`, BearSSL's `ghash_ctmul64`: a carry-less
64x64 product is computed with ordinary integer multiplications on
operands masked to every fourth bit (`bmul64`). Each bit of interest in
such a product is a sum of at most fifteen terms - sixteen only at bit
60, whose carry falls off the top of the word - so the carries land in
the three bits up to the next bit of interest, which the final mask
discards. Four masks, sixteen
multiplications per 64-bit product; Karatsuba makes a 128-bit product
three 64-bit ones; the high halves come from the same function on the
bit-reversed operands. Integer multiplication runs in constant time on
the processors this targets, so the hash makes no secret-dependent
branch or memory access - which a table-driven GHASH cannot claim, since
its tables are built from H, the authentication key.

GCM's bit order (above) is handled by reading each half big endian,
shifting the 256-bit product left by one, and folding the reduction into
shifts.
*/

/// The reduction polynomial's top byte, in the high word.
///
/// x^128 = x^7 + x^2 + x + 1, which in GCM's bit order is 0b11100001
/// followed by 120 zeros.
const R: u64 = 0xe100_0000_0000_0000;

/// One field element: 16 bytes, as a pair of big endian words.
///
/// `hi` holds bytes 0..8 - which is where the *low* order coefficients
/// live, per the note above.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Block {
    pub hi: u64,
    pub lo: u64,
}

impl Block {
    pub const ZERO: Block = Block { hi: 0, lo: 0 };

    /// Read a block. Shorter input is zero padded on the right, which is
    /// what GHASH does with a final partial block.
    pub fn from_bytes(bytes: &[u8]) -> Block {
        let mut padded = [0u8; 16];
        let n = core::cmp::min(16, bytes.len());
        padded[..n].copy_from_slice(&bytes[..n]);
        Block {
            hi: u64::from_be_bytes(padded[..8].try_into().unwrap()),
            lo: u64::from_be_bytes(padded[8..].try_into().unwrap()),
        }
    }

    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.hi.to_be_bytes());
        out[8..].copy_from_slice(&self.lo.to_be_bytes());
        out
    }

    #[inline]
    fn xor(self, other: Block) -> Block {
        Block { hi: self.hi ^ other.hi, lo: self.lo ^ other.lo }
    }

    /// Carry-less multiplication in GF(2^128), GCM's convention.
    ///
    /// Shift-and-add, 128 iterations, both conditionals done with masks.
    ///
    /// Named `gf_mul` rather than `mul`: it is not `std::ops::Mul`, and
    /// it must not be. This product is carry-less and reduced modulo
    /// GCM's polynomial, so `a * b` here is nothing like `a * b` on the
    /// integers those same 16 bytes spell - and a `*` operator would
    /// invite exactly that reading.
    pub fn gf_mul(self, other: Block) -> Block {
        let mut z = Block::ZERO;
        let mut v = other;

        for i in 0..128 {
            // Bit i of `self`, counting from the most significant bit of
            // byte 0 - the left to right order GCM specifies.
            let bit = if i < 64 {
                (self.hi >> (63 - i)) & 1
            } else {
                (self.lo >> (127 - i)) & 1
            };
            let mask = 0u64.wrapping_sub(bit);
            z.hi ^= v.hi & mask;
            z.lo ^= v.lo & mask;

            // V = V >> 1, and reduce if the bit shifted out was set. The
            // test has to happen before the shift, since that is the bit
            // that falls off the end.
            let reduce = 0u64.wrapping_sub(v.lo & 1);
            v.lo = (v.lo >> 1) | (v.hi << 63);
            v.hi = (v.hi >> 1) ^ (R & reduce);
        }
        z
    }
}

/// Carry-less product of two 64-bit words, low 64 bits, by integer
/// multiplication of operands masked to every fourth bit (BearSSL's
/// `bmul64`).
#[inline(always)]
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = u64::wrapping_mul;
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// H with the values every multiplication by it needs: its halves, their
/// XOR for Karatsuba, and the bit reversals of all three for the high
/// halves of the products.
#[derive(Clone, Copy)]
struct HKey {
    h0: u64,
    h1: u64,
    h2: u64,
    h0r: u64,
    h1r: u64,
    h2r: u64,
}

impl HKey {
    /// H itself.
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    fn h(&self) -> Block {
        Block { hi: self.h1, lo: self.h0 }
    }

    fn new(h: Block) -> HKey {
        let (h1, h0) = (h.hi, h.lo);
        let (h0r, h1r) = (h0.reverse_bits(), h1.reverse_bits());
        HKey { h0, h1, h2: h0 ^ h1, h0r, h1r, h2r: h0r ^ h1r }
    }

    /// `y * H` in GCM's field, constant time.
    #[inline]
    fn mul(&self, y: Block) -> Block {
        let (y1, y0) = (y.hi, y.lo);
        let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());
        let (y2, y2r) = (y0 ^ y1, y0r ^ y1r);

        // Karatsuba: low and high halves of the three 128-bit partial
        // products, the high halves through the reversed operands.
        let z0 = bmul64(y0, self.h0);
        let z1 = bmul64(y1, self.h1);
        let mut z2 = bmul64(y2, self.h2);
        let z0h = bmul64(y0r, self.h0r);
        let z1h = bmul64(y1r, self.h1r);
        let mut z2h = bmul64(y2r, self.h2r);
        z2 ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        let z0h = z0h.reverse_bits() >> 1;
        let z1h = z1h.reverse_bits() >> 1;
        let z2h = z2h.reverse_bits() >> 1;

        // The 256-bit product, least significant word first.
        let mut v0 = z0;
        let mut v1 = z0h ^ z2;
        let mut v2 = z1 ^ z2h;
        let mut v3 = z1h;

        // GCM's reflected bit order makes the product one bit short;
        // shift it back, then reduce mod x^128 + x^7 + x^2 + x + 1.
        v3 = (v3 << 1) | (v2 >> 63);
        v2 = (v2 << 1) | (v1 >> 63);
        v1 = (v1 << 1) | (v0 >> 63);
        v0 <<= 1;

        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

        Block { hi: v3, lo: v2 }
    }
}

/// A GHASH accumulator over a fixed key H.
///
/// Feed it whole blocks with `update_block`, or arbitrary bytes with
/// `update`, which pads the final partial block with zeros - the padding
/// GCM applies between its own sections. It does **not** insert the length
/// block; GCM does that itself, because what goes in it depends on the
/// lengths of two separate inputs.
#[derive(Clone)]
pub struct Ghash {
    /// H, H^2, H^3 and H^4: four blocks are absorbed as
    /// `(Y ^ X1)H^4 ^ X2 H^3 ^ X3 H^2 ^ X4 H`, four products that do not
    /// wait for each other, rather than four that each need the last.
    ///
    /// Boxed: inline, the four made every GCM stream 192 bytes larger,
    /// and re-expanding each power per product instead cost the portable
    /// GHASH about fifteen percent.
    powers: Box<[HKey; 4]>,
    /// `H^1 .. H^8` as `(hi, lo)` when GHASH runs on PCLMULQDQ - the
    /// `aes-ni` feature is on and the processor has the instruction -
    /// for `aes_ni::ghash_eights`, which takes eight blocks at a time.
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    hardware: Option<Box<[(u64, u64); 8]>>,
    y: Block,
    /// Bytes of a partial block carried between `update` calls, so that
    /// streaming in awkward pieces gives the same answer as one call.
    partial: [u8; 16],
    used: usize,
}

impl Ghash {
    pub fn new(h: &[u8]) -> Result<Ghash, String> {
        if h.len() != 16 {
            return Err(format!("GHASH key must be 16 bytes, got {}.", h.len()));
        }
        let h = Block::from_bytes(h);
        let key = HKey::new(h);
        let h2 = key.mul(h);
        let h3 = key.mul(h2);
        let h4 = key.mul(h3);
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        let hardware = super::aes_ni::available().then(|| {
            let mut powers = [(h.hi, h.lo); 8];
            let mut power = h;
            for slot in powers.iter_mut().skip(1) {
                power = key.mul(power);
                *slot = (power.hi, power.lo);
            }
            Box::new(powers)
        });
        Ok(Ghash {
            powers: Box::new([key, HKey::new(h2), HKey::new(h3), HKey::new(h4)]),
            #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
            hardware,
            y: Block::ZERO,
            partial: [0u8; 16],
            used: 0,
        })
    }

    /// Back to the empty input under the same H: the running value and
    /// any partial block cleared, the key's powers kept. GCM derives J0
    /// from a nonce that is not 96 bits by hashing it with the same H it
    /// then hashes the message with, and this is what lets it use one
    /// table for both.
    pub fn reset(&mut self) {
        self.y = Block::ZERO;
        self.partial = [0u8; 16];
        self.used = 0;
    }

    /// Absorb one block. A shorter `block` is zero padded.
    #[inline]
    pub fn update_block(&mut self, block: &[u8]) {
        let x = match <&[u8; 16]>::try_from(block) {
            Ok(whole) => Block {
                hi: u64::from_be_bytes(whole[..8].try_into().unwrap()),
                lo: u64::from_be_bytes(whole[8..].try_into().unwrap()),
            },
            Err(_) => Block::from_bytes(block),
        };
        self.y = self.times(self.y.xor(x), 0);
    }

    /// `x * H^(power + 1)`.
    #[inline]
    fn times(&self, x: Block, power: usize) -> Block {
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if self.hardware.is_some() {
            let h = self.powers[power].h();
            // SAFETY: `hardware` is set only when `available()` found
            // PCLMULQDQ and SSE2.
            let (hi, lo) = unsafe { super::aes_ni::gf_mul((x.hi, x.lo), (h.hi, h.lo)) };
            return Block { hi, lo };
        }
        self.powers[power].mul(x)
    }

    /// Four whole blocks at once, by the powers of H.
    #[inline]
    fn update_four(&mut self, blocks: &[u8]) {
        let x = |i: usize| Block {
            hi: u64::from_be_bytes(blocks[16 * i..16 * i + 8].try_into().unwrap()),
            lo: u64::from_be_bytes(blocks[16 * i + 8..16 * i + 16].try_into().unwrap()),
        };
        self.y = self.times(self.y.xor(x(0)), 3)
            .xor(self.times(x(1), 2))
            .xor(self.times(x(2), 1))
            .xor(self.times(x(3), 0));
    }

    /// Absorb bytes, buffering anything short of a whole block.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.used > 0 {
            let n = core::cmp::min(16 - self.used, data.len());
            self.partial[self.used..self.used + n].copy_from_slice(&data[..n]);
            self.used += n;
            data = &data[n..];
            if self.used == 16 {
                let block = self.partial;
                self.update_block(&block);
                self.used = 0;
            }
        }
        #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
        if let Some(powers) = &self.hardware {
            let whole = data.len() / 128 * 128;
            if whole > 0 {
                // SAFETY: `hardware` is set only when `available()` found
                // PCLMULQDQ, SSE2 and SSSE3.
                let (hi, lo) = unsafe {
                    super::aes_ni::ghash_eights(powers, (self.y.hi, self.y.lo), &data[..whole])
                };
                self.y = Block { hi, lo };
                data = &data[whole..];
            }
        }
        let mut fours = data.chunks_exact(64);
        for four in &mut fours {
            self.update_four(four);
        }
        let mut whole = fours.remainder().chunks_exact(16);
        for block in &mut whole {
            self.update_block(block);
        }
        data = whole.remainder();
        if !data.is_empty() {
            self.partial = [0u8; 16];
            self.partial[..data.len()].copy_from_slice(data);
            self.used = data.len();
        }
    }

    /// Finish the current section: absorb any buffered bytes, zero padded.
    ///
    /// GCM pads the additional data and the ciphertext separately, so this
    /// is called between them rather than only at the end. Calling it when
    /// nothing is buffered does nothing at all - it must not absorb a block
    /// of zeros, which would change the hash.
    pub fn pad(&mut self) {
        if self.used > 0 {
            let block = self.partial;
            self.update_block(&block);
            self.partial = [0u8; 16];
            self.used = 0;
        }
    }

    /// The hash so far, after padding whatever is buffered.
    pub fn digest(&mut self) -> [u8; 16] {
        self.pad();
        self.y.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// The field's identity and its most basic non-trivial product.
    ///
    /// `1` in GCM's bit order is 0x80 followed by zeros, not 0x00..01 -
    /// which is the whole trap this module is written around. If these two
    /// pass, the bit order is right.
    #[test]
    fn test_the_field_identity() {
        let one = Block::from_bytes(&unhex("80000000000000000000000000000000"));
        let value = Block::from_bytes(&unhex("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(one.gf_mul(value), value);
        assert_eq!(value.gf_mul(one), value);
        assert_eq!(Block::ZERO.gf_mul(value), Block::ZERO);
        assert_eq!(value.gf_mul(Block::ZERO), Block::ZERO);
    }

    /// Multiplication by x, which in this bit order is a shift *right*.
    /// One step below the reduction, and one step into it.
    #[test]
    fn test_multiplication_by_x() {
        let x = Block::from_bytes(&unhex("40000000000000000000000000000000"));

        // 0x80.. is 1; times x is x, which is 0x40...
        let one = Block::from_bytes(&unhex("80000000000000000000000000000000"));
        assert_eq!(one.gf_mul(x).to_bytes()[..], unhex("40000000000000000000000000000000")[..]);

        // x^127 times x is x^128, which reduces to x^7+x^2+x+1: the low
        // coefficients, so the leading byte, and that is 0xe1.
        let top = Block::from_bytes(&unhex("00000000000000000000000000000001"));
        assert_eq!(hex(&top.gf_mul(x).to_bytes()), "e1000000000000000000000000000000");
    }

    /// The field is commutative and distributes over XOR. Cheap to check
    /// and it catches a reduction applied on the wrong side.
    #[test]
    fn test_field_laws() {
        let a = Block::from_bytes(&unhex("952b2a56a5604ac0b32b6656a05b40b6"));
        let b = Block::from_bytes(&unhex("dfa6bf4ded81db03ffcaff95f830f061"));
        let c = Block::from_bytes(&unhex("66e94bd4ef8a2c3b884cfa59ca342b2e"));

        assert_eq!(a.gf_mul(b), b.gf_mul(a));
        assert_eq!(a.gf_mul(b).gf_mul(c), a.gf_mul(b.gf_mul(c)));
        assert_eq!(a.gf_mul(b.xor(c)), a.gf_mul(b).xor(a.gf_mul(c)));
    }

    /// GHASH from the GCM specification's own test case 2: H is
    /// E_K(0^128) for the all-zero AES-128 key, the message is one block of
    /// ciphertext plus the length block, and the result is the value the
    /// spec prints before the final masking.
    #[test]
    fn test_ghash_against_the_specification() {
        let h = unhex("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let mut ghash = Ghash::new(&h).unwrap();
        ghash.update(&unhex("0388dace60b6a392f328c2b971b2fe78"));
        ghash.pad();
        ghash.update(&unhex("00000000000000000000000000000080"));
        assert_eq!(hex(&ghash.digest()), "f38cbb1ad69223dcc3457ae5b6b0f885");
    }

    /// Streaming in awkward pieces must equal one call. This is the check
    /// that a partial block buffered across a call boundary is handled -
    /// the bug class that desynchronised ChaCha's keystream once already.
    #[test]
    fn test_streaming_equals_one_call() {
        let h = unhex("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let message: Vec<u8> = (0..200u32).map(|i| (i * 7 + 3) as u8).collect();

        let mut whole = Ghash::new(&h).unwrap();
        whole.update(&message);
        let expected = whole.digest();

        for chunk in [1usize, 3, 7, 15, 16, 17, 31, 64] {
            let mut streamed = Ghash::new(&h).unwrap();
            for piece in message.chunks(chunk) {
                streamed.update(piece);
            }
            assert_eq!(streamed.digest(), expected, "chunk size {}", chunk);
        }
    }

    /// `pad` on an empty buffer must do nothing. Absorbing a zero block
    /// instead would change the hash, and it would do it only for the
    /// messages whose additional data happens to be a whole number of
    /// blocks - which is most of the ones a test would use.
    #[test]
    fn test_padding_nothing_is_not_a_zero_block() {
        let h = unhex("66e94bd4ef8a2c3b884cfa59ca342b2e");

        let mut padded = Ghash::new(&h).unwrap();
        padded.update(&unhex("0388dace60b6a392f328c2b971b2fe78"));
        padded.pad();
        padded.pad();
        padded.pad();

        let mut plain = Ghash::new(&h).unwrap();
        plain.update(&unhex("0388dace60b6a392f328c2b971b2fe78"));

        assert_eq!(padded.digest(), plain.digest());
    }

    /// The integer-multiply product against the shift-and-add reference,
    /// over operands chosen to set every bit position and the reduction
    /// paths: random values, single bits at each end of each half, and
    /// all-ones.
    #[test]
    fn test_the_fast_product_is_the_field_product() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut values = vec![Block::ZERO, Block { hi: !0, lo: !0 }];
        for bit in [0, 1, 7, 56, 62, 63] {
            values.push(Block { hi: 1 << bit, lo: 0 });
            values.push(Block { hi: 0, lo: 1 << bit });
        }
        for _ in 0..200 {
            values.push(Block { hi: next(), lo: next() });
        }
        for a in &values {
            for b in values.iter().take(40) {
                assert_eq!(HKey::new(*b).mul(*a), a.gf_mul(*b), "{a:?} * {b:?}");
            }
        }
    }

    /// With the `aes-ni` feature on a processor that has it: the
    /// carry-less multiply against the shift-and-add reference.
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    #[test]
    fn test_the_hardware_product_is_the_field_product() {
        if !super::super::aes_ni::available() {
            return;
        }
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut values = vec![Block::ZERO, Block { hi: !0, lo: !0 }];
        for bit in [0, 1, 7, 56, 62, 63] {
            values.push(Block { hi: 1 << bit, lo: 0 });
            values.push(Block { hi: 0, lo: 1 << bit });
        }
        for _ in 0..200 {
            values.push(Block { hi: next(), lo: next() });
        }
        for a in &values {
            for b in values.iter().take(40) {
                // SAFETY: `available()` was checked above.
                let (hi, lo) = unsafe { super::super::aes_ni::gf_mul((a.hi, a.lo), (b.hi, b.lo)) };
                assert_eq!(Block { hi, lo }, a.gf_mul(*b));
            }
        }
    }

    /// The eight-block hardware path against the portable one, over
    /// every length to five groups and in uneven pieces, so the groups
    /// start at every offset relative to a streaming call.
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    #[test]
    fn test_the_eight_block_hardware_path_agrees_with_the_portable_one() {
        if !super::super::aes_ni::available() {
            eprintln!("skipped: this processor has no PCLMULQDQ");
            return;
        }
        let key: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(29) ^ 0xA5).collect();
        let data: Vec<u8> = (0..700u32).map(|i| (i * 7 + i / 13) as u8).collect();
        for length in 0..=data.len() {
            let mut hardware = Ghash::new(&key).unwrap();
            assert!(hardware.hardware.is_some());
            let mut portable = hardware.clone();
            portable.hardware = None;
            hardware.update(&data[..length]);
            portable.update(&data[..length]);
            assert_eq!(hardware.digest(), portable.digest(), "length {length}");

            let mut pieces = Ghash::new(&key).unwrap();
            for piece in data[..length].chunks(1 + length % 151) {
                pieces.update(piece);
            }
            assert_eq!(pieces.digest(), portable.digest(), "length {length} in pieces");
        }
    }

    #[test]
    fn test_the_key_must_be_a_block() {
        assert!(Ghash::new(&[0u8; 15]).is_err());
        assert!(Ghash::new(&[0u8; 17]).is_err());
        assert!(Ghash::new(&[]).is_err());
        assert!(Ghash::new(&[0u8; 16]).is_ok());
    }

    /// `reset` is a fresh GHASH under the same key, whatever was hashed
    /// before it - whole blocks or a partial one left in the buffer.
    #[test]
    fn test_reset_is_a_fresh_start() {
        let h = unhex("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let mut shared = Ghash::new(&h).unwrap();
        let mut fresh = Ghash::new(&h).unwrap();
        fresh.update(b"the message that matters");
        for length in [0usize, 7, 16, 17, 40] {
            shared.update(&vec![0xa5u8; length]);
            shared.reset();
            shared.update(b"the message that matters");
            assert_eq!(shared.digest(), fresh.digest(), "after {length} bytes");
            shared.reset();
        }
    }
}
