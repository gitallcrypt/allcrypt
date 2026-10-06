/*
Poly1305 (RFC 8439 section 2.5).

A one-time authenticator. The message is read as a sequence of 16 byte
little-endian numbers, each with a 1 bit appended above its top byte, and
those are evaluated as a polynomial at a secret point r, modulo the prime
2^130 - 5. The result is added to a secret s and truncated to 16 bytes:

    a = 0
    for each block n:  a = (a + n) * r
    tag = (a + s) mod 2^128

## One time means one time

The key is 32 bytes and is **r || s**, and it must never be used for a
second message. Poly1305 is not a PRF keyed by a secret; it is a universal
hash whose security rests entirely on r being unknown. Two tags under one
key give two equations in r and s over a small field, and r falls out - at
which point every subsequent tag can be forged.

This is why nothing here takes a long-lived key. In ChaCha20-Poly1305 the
key is the first 32 bytes of a ChaCha block generated from the nonce and
counter zero, so a fresh one exists per message by construction, and the
nonce rule that gives GCM its sharp edge gives this one the same edge for
the same reason. HMAC is the thing to reach for when a key has to be
reused; this is not a smaller HMAC.

## The clamp, and why 130 bits

r is "clamped" before use: four bits are cleared from each of four bytes,
and the top two bits of three others. That keeps r below 2^124 and makes
the limbs small enough that the carries in the multiply stay bounded -
it is an implementation affordance, not a security measure, and it is part
of the specification, so skipping it produces a different function.

The modulus is 2^130 - 5, which does not fit in two 64 bit words and is
awkward in three. This implementation uses five 26 bit limbs, which is the
usual choice: 26 * 5 = 130 exactly, products of two limbs fit in a u64
with room for the accumulated carries, and the reduction modulo 2^130 - 5
becomes "fold the top back in multiplied by 5". The alternative - a
generic bignum - would be correct and several times slower, and would put
a variable-time modular reduction in the path of a secret.

## Timing

No branch anywhere depends on the message or the key. The final
conditional subtraction of the prime is done with a mask rather than an
`if`, and the accumulate loop runs a fixed number of operations per block.
The one thing that varies is the number of blocks, which is the message
length - public in every use this library has.
*/

use crate::Mac;

/// A Poly1305 authenticator over one message.
#[derive(Clone)]
pub struct Poly1305 {
    /// The clamped r, as five 26 bit limbs.
    r: [u32; 5],
    /// r[1..5] pre-multiplied by 5, for the reduction.
    r5: [u32; 4],
    /// The accumulator, five 26 bit limbs.
    a: [u32; 5],
    /// s, the value added at the end, as four 32 bit words.
    s: [u32; 4],
    /// A partial block carried between `update` calls.
    partial: [u8; 16],
    used: usize,
    finished: bool,
}

impl Poly1305 {
    /// `key` is 32 bytes: r then s. It must be used for exactly one
    /// message - see the note at the top of this file.
    pub fn new(key: &[u8]) -> Result<Poly1305, String> {
        if key.len() != 32 {
            return Err(format!(
                "Poly1305 key must be 32 bytes (r then s), got {}.", key.len()));
        }

        // Clamp and split r into 26 bit limbs in one pass. The masks are
        // from RFC 8439 section 2.5.1: they clear the top four bits of
        // bytes 3, 7, 11 and 15 and the bottom two of bytes 4, 8 and 12.
        let word = |i: usize| u32::from_le_bytes(key[i..i + 4].try_into().unwrap());
        let mut r = [0u32; 5];
        r[0] = word(0) & 0x03ff_ffff;
        r[1] = ((word(3) >> 2) & 0x03ff_ff03) & 0x03ff_ffff;
        r[2] = ((word(6) >> 4) & 0x03ff_c0ff) & 0x03ff_ffff;
        r[3] = ((word(9) >> 6) & 0x03f0_3fff) & 0x03ff_ffff;
        r[4] = ((word(12) >> 8) & 0x000f_ffff) & 0x03ff_ffff;

        let r5 = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
        let s = [word(16), word(20), word(24), word(28)];

        Ok(Poly1305 {
            r, r5,
            a: [0; 5],
            s,
            partial: [0u8; 16],
            used: 0,
            finished: false,
        })
    }

    /// Absorb one 16 byte block. `high` is the bit appended above the
    /// block: 1 for a whole block, and for a short final block it is
    /// already in the padded bytes, so 0.
    fn block(&mut self, block: &[u8; 16], high: u32) {
        let word = |i: usize| u32::from_le_bytes(block[i..i + 4].try_into().unwrap());

        // n, as 26 bit limbs, plus the appended bit in the top limb.
        let n0 = word(0) & 0x03ff_ffff;
        let n1 = (word(3) >> 2) & 0x03ff_ffff;
        let n2 = (word(6) >> 4) & 0x03ff_ffff;
        let n3 = (word(9) >> 6) & 0x03ff_ffff;
        let n4 = (word(12) >> 8) | (high << 24);

        // a += n
        let a0 = (self.a[0] + n0) as u64;
        let a1 = (self.a[1] + n1) as u64;
        let a2 = (self.a[2] + n2) as u64;
        let a3 = (self.a[3] + n3) as u64;
        let a4 = (self.a[4] + n4) as u64;

        let (r0, r1, r2, r3, r4) = (self.r[0] as u64, self.r[1] as u64,
                                    self.r[2] as u64, self.r[3] as u64,
                                    self.r[4] as u64);
        let (s1, s2, s3, s4) = (self.r5[0] as u64, self.r5[1] as u64,
                                self.r5[2] as u64, self.r5[3] as u64);

        // a *= r, modulo 2^130 - 5. Anything above limb 4 has overflowed
        // 2^130, and 2^130 = 5 (mod 2^130 - 5), so it folds back in
        // multiplied by five - which is what r5 is for.
        let d0 = a0 * r0 + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1;
        let d1 = a0 * r1 + a1 * r0 + a2 * s4 + a3 * s3 + a4 * s2;
        let d2 = a0 * r2 + a1 * r1 + a2 * r0 + a3 * s4 + a4 * s3;
        let d3 = a0 * r3 + a1 * r2 + a2 * r1 + a3 * r0 + a4 * s4;
        let d4 = a0 * r4 + a1 * r3 + a2 * r2 + a3 * r1 + a4 * r0;

        // Carry propagation, back down to 26 bit limbs.
        let mut carry = d0 >> 26;
        let mut out = [0u32; 5];
        out[0] = (d0 & 0x03ff_ffff) as u32;

        let d = d1 + carry;
        carry = d >> 26;
        out[1] = (d & 0x03ff_ffff) as u32;

        let d = d2 + carry;
        carry = d >> 26;
        out[2] = (d & 0x03ff_ffff) as u32;

        let d = d3 + carry;
        carry = d >> 26;
        out[3] = (d & 0x03ff_ffff) as u32;

        let d = d4 + carry;
        carry = d >> 26;
        out[4] = (d & 0x03ff_ffff) as u32;

        // The carry out of the top limb wraps around times five.
        out[0] += (carry * 5) as u32;
        out[1] += out[0] >> 26;
        out[0] &= 0x03ff_ffff;

        self.a = out;
    }

    /// The 16 byte tag.
    ///
    /// Calling this twice returns the same value; it does not consume the
    /// authenticator, matching every other MAC here.
    pub fn tag(&mut self) -> [u8; 16] {
        let mut copy = self.clone();
        copy.finalize()
    }

    fn finalize(&mut self) -> [u8; 16] {
        if self.used > 0 {
            // A short final block is padded with a 1 byte and then zeros,
            // so the appended bit is already in the data and `high` is 0.
            // Padding with zeros alone would make "ab" and "ab\0" the same
            // message.
            let mut block = [0u8; 16];
            block[..self.used].copy_from_slice(&self.partial[..self.used]);
            block[self.used] = 1;
            self.used = 0;
            self.block(&block, 0);
        }
        self.finished = true;

        // Final carry, so every limb is below 2^26.
        let mut a = self.a;
        a[1] += a[0] >> 26; a[0] &= 0x03ff_ffff;
        a[2] += a[1] >> 26; a[1] &= 0x03ff_ffff;
        a[3] += a[2] >> 26; a[2] &= 0x03ff_ffff;
        a[4] += a[3] >> 26; a[3] &= 0x03ff_ffff;
        a[0] += (a[4] >> 26) * 5; a[4] &= 0x03ff_ffff;
        a[1] += a[0] >> 26; a[0] &= 0x03ff_ffff;

        // a may still be in [p, 2^130). Compute a - p and take it only if
        // it did not borrow - with a mask, not a branch, because which one
        // is taken depends on the secret.
        let mut g = [0u32; 5];
        let mut carry = 5u32;              // subtracting p = 2^130 - 5 is +5 then -2^130
        for i in 0..5 {
            let value = a[i] + carry;
            carry = value >> 26;
            g[i] = value & 0x03ff_ffff;
        }
        // carry is 1 exactly when a + 5 reached 2^130, i.e. when a >= p.
        let mask = 0u32.wrapping_sub(carry);
        for i in 0..5 {
            a[i] = (a[i] & !mask) | (g[i] & mask);
        }

        // Repack the 26 bit limbs into four 32 bit words, add s, serialise.
        let words = [
            a[0] | (a[1] << 26),
            (a[1] >> 6) | (a[2] << 20),
            (a[2] >> 12) | (a[3] << 14),
            (a[3] >> 18) | (a[4] << 8),
        ];

        let mut tag = [0u8; 16];
        let mut carry = 0u64;
        for i in 0..4 {
            let sum = words[i] as u64 + self.s[i] as u64 + carry;
            carry = sum >> 32;
            tag[i * 4..i * 4 + 4].copy_from_slice(&(sum as u32).to_le_bytes());
        }
        tag
    }

    /// Compare a tag in constant time.
    ///
    /// An early return on the first differing byte turns forgery from
    /// 2^128 work into about 4,000 tries, one byte at a time. Every caller
    /// should use this rather than `==` on the result of `tag`.
    pub fn verify(&mut self, expected: &[u8]) -> bool {
        let tag = self.tag();
        if expected.len() != tag.len() {
            return false;
        }
        let mut difference = 0u8;
        for (a, b) in tag.iter().zip(expected.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

impl Mac for Poly1305 {
    fn update(&mut self, input: &[u8]) {
        let mut data = input;

        if self.used > 0 {
            let n = core::cmp::min(16 - self.used, data.len());
            self.partial[self.used..self.used + n].copy_from_slice(&data[..n]);
            self.used += n;
            data = &data[n..];
            if self.used == 16 {
                let block = self.partial;
                self.used = 0;
                self.block(&block, 1);
            }
        }

        while data.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[..16]);
            self.block(&block, 1);
            data = &data[16..];
        }

        if !data.is_empty() {
            self.partial[..data.len()].copy_from_slice(data);
            self.used = data.len();
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        self.tag().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn poly(key: &str, message: &[u8]) -> String {
        let mut mac = Poly1305::new(&unhex(key)).unwrap();
        mac.update(message);
        hex(&mac.digest())
    }

    /// RFC 8439 section 2.5.2.
    #[test]
    fn test_the_rfc_vector() {
        let key = "85d6be7857556d337f4452fe42d506a8\
                   0103808afb0db2fd4abff6af4149f51b";
        assert_eq!(poly(key, b"Cryptographic Forum Research Group"),
                   "a8061dc1305136c6c22b8baf0c0127a9");
    }

    /// RFC 8439 appendix A.3, which is where the edge cases live: a zero
    /// key, a zero r, and the cases that exercise the final reduction.
    #[test]
    fn test_the_rfc_edge_cases() {
        // Test 1: key and message all zero. r = 0, so the tag is s = 0.
        assert_eq!(poly(&"00".repeat(32), &[0u8; 64]), "0".repeat(32));

        // Test 2: r = 0, so the polynomial vanishes and the tag is just s.
        let key = "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e";
        let message = b"Any submission to the IETF intended by the Contributor \
for publication as all or part of an IETF Internet-Draft or RFC and any statement \
made within the context of an IETF activity is considered an \"IETF Contribution\". \
Such statements include oral statements in IETF sessions, as well as written and \
electronic communications made at any time or place, which are addressed to";
        assert_eq!(poly(key, message), "36e5f6b5c5e06070f0efca96227a863e");

        // Test 3: s = 0, so only the polynomial contributes.
        let key = "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000";
        assert_eq!(poly(key, message), "f3477e7cd95417af89a6b8794c310cf0");

        // Test 4: from the RFC, a message that is not a multiple of 16.
        let key = "1c9240a5eb55d38af333888604f6b5f0\
                   473917c1402b80099dca5cbc207075c0";
        let message = unhex(
            "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665\
             730a446964206779726520616e642067696d626c6520696e2074686520776162653a\
             0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e64\
             20746865206d6f6d65207261746873206f757467726162652e");
        assert_eq!(poly(key, &message), "4541669a7eaaee61e708dc7cbcc5eb62");
    }

    /// The reduction cases from the RFC's appendix, which exist precisely
    /// because they are the ones a hand-rolled carry chain gets wrong.
    #[test]
    fn test_the_reduction_edge_cases() {
        // Test 5: adding 2^130 - 5 must wrap to zero.
        let key = "02".to_string() + &"00".repeat(31);
        assert_eq!(poly(&key, &unhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")),
                   "03000000000000000000000000000000");

        // Test 6: the second half of the key carries into the tag.
        let key = "02".to_string() + &"00".repeat(15) + &"ff".repeat(16);
        assert_eq!(poly(&key, &unhex("02000000000000000000000000000000")),
                   "03000000000000000000000000000000");

        // Test 7: 2^130 - 5 reached by accumulation across blocks.
        let key = "01".to_string() + &"00".repeat(31);
        assert_eq!(poly(&key, &unhex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
             F0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
             11000000000000000000000000000000")),
            "05000000000000000000000000000000");

        // Test 8: the same, one less.
        let key = "01".to_string() + &"00".repeat(31);
        assert_eq!(poly(&key, &unhex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
             FBFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE\
             01010101010101010101010101010101")),
            "00000000000000000000000000000000");

        // Test 9: the top limb saturated.
        let key = "02".to_string() + &"00".repeat(31);
        assert_eq!(poly(&key, &unhex("FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")),
                   "faffffffffffffffffffffffffffffff");

        // Test 10 and 11: long carry chains.
        let key = "01000000000000000400000000000000".to_string() + &"00".repeat(16);
        assert_eq!(poly(&key, &unhex(
            "E33594D7505E43B90000000000000000\
             3394D7505E4379CD0100000000000000\
             00000000000000000000000000000000\
             01000000000000000000000000000000")),
            "14000000000000005500000000000000");

        assert_eq!(poly(&key, &unhex(
            "E33594D7505E43B90000000000000000\
             3394D7505E4379CD0100000000000000\
             00000000000000000000000000000000")),
            "13000000000000000000000000000000");
    }

    /// Streaming in awkward pieces must equal one call. The partial block
    /// carried across a call boundary is the bug class that has already
    /// bitten this library twice.
    #[test]
    fn test_streaming_equals_one_call() {
        let key = unhex("85d6be7857556d337f4452fe42d506a8\
                         0103808afb0db2fd4abff6af4149f51b");
        let message: Vec<u8> = (0..300u32).map(|i| (i * 13 + 7) as u8).collect();

        let mut whole = Poly1305::new(&key).unwrap();
        whole.update(&message);
        let expected = whole.digest();

        for size in [1usize, 3, 7, 15, 16, 17, 31, 64, 128] {
            let mut streamed = Poly1305::new(&key).unwrap();
            for piece in message.chunks(size) {
                streamed.update(piece);
            }
            assert_eq!(streamed.digest(), expected, "in {} byte pieces", size);
        }
    }

    /// The final block's 1 byte is what stops a message and the same
    /// message with trailing zeros from authenticating alike.
    #[test]
    fn test_trailing_zeros_change_the_tag() {
        let key = "85d6be7857556d337f4452fe42d506a8\
                   0103808afb0db2fd4abff6af4149f51b";
        let short = poly(key, b"ab");
        assert_ne!(short, poly(key, b"ab\0"));
        assert_ne!(short, poly(key, b"ab\0\0"));
        assert_ne!(poly(key, &[]), poly(key, &[0u8]));
    }

    /// `digest` must not consume the state, matching every other MAC here.
    #[test]
    fn test_digest_is_repeatable() {
        let mut mac = Poly1305::new(&unhex(&"42".repeat(32))).unwrap();
        mac.update(b"a message");
        let first = mac.digest();
        assert_eq!(mac.digest(), first);
        assert_eq!(mac.tag().to_vec(), first);
    }

    #[test]
    fn test_verify_is_a_comparison_not_a_shortcut() {
        let key = unhex(&"7f".repeat(32));
        let mut mac = Poly1305::new(&key).unwrap();
        mac.update(b"authentic");
        let tag = mac.tag();

        let mut check = Poly1305::new(&key).unwrap();
        check.update(b"authentic");
        assert!(check.verify(&tag));

        // Every single-byte change must be caught, and a truncated tag is
        // not a prefix match.
        for index in 0..tag.len() {
            let mut altered = tag;
            altered[index] ^= 0x01;
            let mut check = Poly1305::new(&key).unwrap();
            check.update(b"authentic");
            assert!(!check.verify(&altered), "byte {} slipped through", index);
        }
        let mut check = Poly1305::new(&key).unwrap();
        check.update(b"authentic");
        assert!(!check.verify(&tag[..15]));
    }

    #[test]
    fn test_the_key_must_be_32_bytes() {
        for length in [0usize, 16, 31, 33, 64] {
            assert!(Poly1305::new(&vec![0u8; length]).is_err(), "length {}", length);
        }
        assert!(Poly1305::new(&[0u8; 32]).is_ok());
    }
}
