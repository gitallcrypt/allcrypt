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

The modulus is 2^130 - 5, which does not fit in two 64 bit words. This
implementation uses three limbs of 44, 44 and 42 bits: a product of two
limbs fits in a u128 with room for the sums, a block costs nine 64 x 64
bit multiplications where five 26 bit limbs cost twenty-five, and the
reduction modulo 2^130 - 5 is "fold the top back in multiplied by 5".
Because the top limb is 42 bits, a product that lands above it carries
a factor of 2^2 as well, which is why the folded coefficients are
r * 20 rather than r * 5. A generic bignum would be correct and several
times slower, and would put a variable-time modular reduction in the
path of a secret.

## Four blocks at a time

Block after block, each multiplication waits for the one before it, so
the speed is the latency of one multiply-and-reduce rather than the
processor's multiplier throughput - fewer multiplications per block did
not make it faster. With r^2, r^3 and r^4 computed once per key, four
blocks are absorbed as

    a = (a + n1) * r^4 + n2 * r^3 + n3 * r^2 + n4 * r

which is the same polynomial, regrouped. The four products are
independent of one another, and they are summed unreduced and reduced
once.

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
    /// r, r^2, r^3 and r^4, for one block and for four at a time.
    powers: [Multiplier; 4],
    /// The accumulator, as limbs of 44, 44 and 42 bits.
    a: [u64; 3],
    /// s, the value added at the end, as two 64 bit words.
    s: [u64; 2],
    /// A partial block carried between `update` calls.
    partial: [u8; 16],
    used: usize,
    finished: bool,
}

const LOW_44: u64 = (1 << 44) - 1;
const LOW_42: u64 = (1 << 42) - 1;

/// A value to multiply by: its limbs, and its upper two limbs times 20
/// for the reduction - 5 for 2^130 = 5, and 4 because the top limb ends
/// at bit 130 rather than 132.
#[derive(Clone, Copy)]
struct Multiplier {
    limbs: [u64; 3],
    times20: [u64; 2],
}

impl Multiplier {
    fn new(limbs: [u64; 3]) -> Multiplier {
        Multiplier { limbs, times20: [limbs[1] * 20, limbs[2] * 20] }
    }
}

/// A 16 byte little-endian number as two 64 bit words.
fn words(bytes: &[u8]) -> (u64, u64) {
    (u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
     u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")))
}

/// Two 64 bit words as limbs of 44, 44 and 42 bits.
fn limbs(low: u64, high: u64) -> [u64; 3] {
    [low & LOW_44, ((low >> 44) | (high << 20)) & LOW_44, (high >> 24) & LOW_42]
}

/// A message block as limbs, with the bit appended above it - at 2^128,
/// which is bit 40 of the top limb - when `high` is 1.
fn block_limbs(block: &[u8], high: u64) -> [u64; 3] {
    let (low_word, high_word) = words(block);
    let n = limbs(low_word, high_word);
    [n[0], n[1], n[2] | (high << 40)]
}

/// `x * m` modulo 2^130 - 5, as three column sums not yet carried. A
/// product whose limb positions add up past the top limb has overflowed
/// 2^130 and folds back in times twenty.
#[inline(always)]
fn product(x: [u64; 3], m: &Multiplier) -> [u128; 3] {
    let (x0, x1, x2) = (x[0] as u128, x[1] as u128, x[2] as u128);
    let (m0, m1, m2) = (m.limbs[0] as u128, m.limbs[1] as u128, m.limbs[2] as u128);
    let (t1, t2) = (m.times20[0] as u128, m.times20[1] as u128);
    [x0 * m0 + x1 * t2 + x2 * t1,
     x0 * m1 + x1 * m0 + x2 * t2,
     x0 * m2 + x1 * m1 + x2 * m0]
}

/// Column sums carried back down to limbs.
///
/// Bounds, for the sums of up to four products that reach here: every
/// limb multiplied is below 2^46 (an accumulator limb plus a message
/// limb) and every multiplier limb times 20 below 2^49, so each of the
/// twelve terms in a column is below 2^95 and the column below 2^99. The
/// carry out of the top limb is then below 2^57 and five times it below
/// 2^60, and what comes out is a0 below 2^44, a1 below 2^44 + 2^16 and
/// a2 below 2^42 - inside the bounds assumed for the next block and for
/// `finalize`.
#[inline(always)]
fn reduce(d: [u128; 3]) -> [u64; 3] {
    let carry = (d[0] >> 44) as u64;
    let mut out0 = d[0] as u64 & LOW_44;
    let d1 = d[1] + carry as u128;
    let carry = (d1 >> 44) as u64;
    let mut out1 = d1 as u64 & LOW_44;
    let d2 = d[2] + carry as u128;
    let carry = (d2 >> 42) as u64;
    let out2 = d2 as u64 & LOW_42;

    // The carry out of the top limb wraps around times five.
    out0 += carry * 5;
    out1 += out0 >> 44;
    out0 &= LOW_44;
    [out0, out1, out2]
}

fn add(a: [u64; 3], b: [u64; 3]) -> [u64; 3] {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2]]
}

impl Poly1305 {
    /// `key` is 32 bytes: r then s. It must be used for exactly one
    /// message - see the note at the top of this file.
    pub fn new(key: &[u8]) -> Result<Poly1305, String> {
        if key.len() != 32 {
            return Err(format!(
                "Poly1305 key must be 32 bytes (r then s), got {}.", key.len()));
        }

        // The clamp, RFC 8439 section 2.5.1: the top four bits of bytes 3,
        // 7, 11 and 15 and the bottom two of bytes 4, 8 and 12 cleared.
        let (low, high) = words(&key[..16]);
        let r = Multiplier::new(limbs(low & 0x0fff_fffc_0fff_ffff,
                                      high & 0x0fff_fffc_0fff_fffc));
        let r2 = Multiplier::new(reduce(product(r.limbs, &r)));
        let r3 = Multiplier::new(reduce(product(r2.limbs, &r)));
        let r4 = Multiplier::new(reduce(product(r3.limbs, &r)));
        let s = words(&key[16..]);

        Ok(Poly1305 {
            powers: [r, r2, r3, r4],
            a: [0; 3],
            s: [s.0, s.1],
            partial: [0u8; 16],
            used: 0,
            finished: false,
        })
    }

    /// Absorb one 16 byte block. `high` is the bit appended above the
    /// block: 1 for a whole block, and for a short final block it is
    /// already in the padded bytes, so 0.
    fn block(&mut self, block: &[u8; 16], high: u64) {
        self.a = reduce(product(add(self.a, block_limbs(block, high)), &self.powers[0]));
    }

    /// Absorb four whole blocks, 64 bytes: `(a + n1) * r^4 + n2 * r^3 +
    /// n3 * r^2 + n4 * r`, reduced once.
    fn four_blocks(&mut self, blocks: &[u8]) {
        let [r, r2, r3, r4] = &self.powers;
        let first = product(add(self.a, block_limbs(&blocks[..16], 1)), r4);
        let second = product(block_limbs(&blocks[16..32], 1), r3);
        let third = product(block_limbs(&blocks[32..48], 1), r2);
        let fourth = product(block_limbs(&blocks[48..64], 1), r);
        let mut sum = [0u128; 3];
        for (i, column) in sum.iter_mut().enumerate() {
            *column = first[i] + second[i] + third[i] + fourth[i];
        }
        self.a = reduce(sum);
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

        // One carry pass puts every limb within its width. `reduce`
        // leaves a0 below 2^44, a1 below 2^44 + 2^16 and a2 below 2^42:
        // if a1 carries, what is left of it is below 2^16; the carry can
        // lift a2 to 2^42, whose wrap adds 5 to a0, whose own carry is
        // then at most 1 into that small a1. Nothing carries a second
        // time.
        let [mut a0, mut a1, mut a2] = self.a;
        a2 += a1 >> 44; a1 &= LOW_44;
        a0 += (a2 >> 42) * 5; a2 &= LOW_42;
        a1 += a0 >> 44; a0 &= LOW_44;

        // a may still be in [p, 2^130). Compute a - p = a + 5 - 2^130 and
        // take it only if it did not go negative - with a mask, not a
        // branch, because which one is taken depends on the secret.
        let g0 = a0 + 5;
        let g1 = a1 + (g0 >> 44);
        let g2 = (a2 + (g1 >> 44)).wrapping_sub(1 << 42);
        // The top bit of g2 is set exactly when a + 5 < 2^130, i.e. a < p.
        let take = (g2 >> 63).wrapping_sub(1);
        a0 = (a0 & !take) | (g0 & LOW_44 & take);
        a1 = (a1 & !take) | (g1 & LOW_44 & take);
        a2 = (a2 & !take) | (g2 & LOW_42 & take);

        // Add s modulo 2^128 and serialise.
        let s = limbs(self.s[0], self.s[1]);
        let mut sum0 = a0 + s[0];
        let mut sum1 = a1 + s[1] + (sum0 >> 44);
        let sum2 = (a2 + s[2] + (sum1 >> 44)) & LOW_42;
        sum0 &= LOW_44;
        sum1 &= LOW_44;
        let low = sum0 | (sum1 << 44);
        let high = (sum1 >> 20) | (sum2 << 24);

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&low.to_le_bytes());
        tag[8..].copy_from_slice(&high.to_le_bytes());
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

        let mut fours = data.chunks_exact(64);
        for blocks in &mut fours {
            self.four_blocks(blocks);
        }
        data = fours.remainder();
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

    /// The final reduction from accumulators at the bounds `reduce`
    /// leaves - a0 below 2^44, a1 below 2^44 + 2^16, a2 below 2^42 - and from
    /// values either side of p, against the same arithmetic done with
    /// `BigUint`. No message is known that reaches these exact states, so
    /// they are set directly.
    #[test]
    fn test_the_final_reduction_at_the_limb_bounds() {
        use crate::bignum::BigUint;
        let p = BigUint::from_u64(1).shl(130).sub(&BigUint::from_u64(5)).unwrap();
        let top44 = (1u64 << 44) - 1;
        let top42 = (1u64 << 42) - 1;
        let states = [
            [top44, 1 << 44, top42],              // 2^130 + 2^44 - 1
            [top44, (1 << 44) + (1 << 16) - 1, top42],
            [top44, top44, top42],                // 2^130 - 1
            [top44 - 4, top44, top42],            // p
            [top44 - 5, top44, top42],            // p - 1
            [top44 - 3, top44, top42],            // p + 1
            [4, 1 << 44, top42],                  // 2^130 + 4 = p + 9
            [0, 0, 0],
        ];
        let key = unhex(&("00".repeat(16) + &"ff".repeat(16)));
        for a in states {
            let mut mac = Poly1305::new(&key).unwrap();
            mac.a = a;
            let tag = mac.tag();

            let value = BigUint::from_u64(a[0])
                .add(&BigUint::from_u64(a[1]).shl(44))
                .add(&BigUint::from_u64(a[2]).shl(88));
            let s = BigUint::from_bytes_be(&[0xffu8; 16]);
            let want = value.rem(&p).unwrap().add(&s)
                .rem(&BigUint::from_u64(1).shl(128)).unwrap();
            let mut want_bytes = want.to_bytes_be();
            want_bytes.reverse();
            want_bytes.resize(16, 0);
            assert_eq!(tag.to_vec(), want_bytes, "accumulator {a:x?}");
        }
    }

    #[test]
    fn test_the_key_must_be_32_bytes() {
        for length in [0usize, 16, 31, 33, 64] {
            assert!(Poly1305::new(&vec![0u8; length]).is_err(), "length {}", length);
        }
        assert!(Poly1305::new(&[0u8; 32]).is_ok());
    }
}
