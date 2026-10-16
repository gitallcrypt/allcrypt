/*
VMAC (draft-krovetz-vmac-01, Krovetz and Dai, 2007): a Wegman-Carter MAC
built on VHASH, a three-layer universal hash, and a pad derived from a
nonce by a 128 bit block cipher - AES unless another is named. Its tag
is 64 or 128 bits.

    VMAC(K, M, N, taglen) = PDF(K, N, taglen) +_64 VHASH(K, M, taglen)

VHASH runs once per 64 bits of tag, each time with its own keys:

  * **L1, NH**, over 128 byte segments of the message (the last zero
    padded to 16 bytes), each read as **little-endian** 64 bit words:
    the sum of `(m_i + k_i) * (m_{i+1} + k_{i+1})` mod 2^128, then mod
    2^126. The second 64 bits of a 128 bit tag use the same NH key
    shifted by two words.
  * **L2**, a polynomial over the NH outputs mod 2^127 - 1, starting at
    1, with a key whose 32 bit words have their top three bits cleared;
    then `(len mod 1024) * 2^64` is added, `len` in bits.
  * **L3**, the result split into `m div (2^64 - 2^32)` and
    `m mod (2^64 - 2^32)`, each added to a key half and multiplied mod
    2^64 - 257. Its key is drawn by rejection: a candidate half at or
    above 2^64 - 257 is skipped.

Keys come from the cipher in counter mode, the first byte of each block
being the purpose (128 for NH, 192 for L2, 224 for L3). The pad is
`E_K(N)` with `N` right-aligned in a zero block; for a 64 bit tag the
nonce's last bit picks which half, and is cleared before encrypting, so
two nonces differing only there share one encryption.

Silent when wrong, all of them, since VMAC agrees with itself however
any of these is read:

  * the message words are **little-endian** while every key, the pad
    and the tag are big-endian;
  * the length term is in **bits** and taken mod 1024, so a message of a
    whole number of 128 byte segments adds nothing;
  * the empty message skips L1 and L2's loop entirely: L2 is its key;
  * for a 64 bit tag the nonce's **last bit is an index**, not part of
    the encrypted block.

The draft's own vectors, Crypto++ 8.9.0's and the Linux kernel's
`vmac64` agree with every row of `vectors/vmac.vec`.

The arithmetic is constant time - 64x64 bit products, carries and
reductions computed rather than branched on - and every encryption
goes through `encrypt_blocks`. The one key-dependent branch is L3's
rejection, which skips a candidate with probability about 2^-55.
*/

use crate::api::AnyBlockCipher;
use crate::block_ciphers::BlockCipher;

const P64: u64 = 0xffff_ffff_ffff_feff; // 2^64 - 257
const M62: u64 = 0x3fff_ffff_ffff_ffff;
const M63: u64 = 0x7fff_ffff_ffff_ffff;
const M64: u64 = u64::MAX;
const MPOLY: u64 = 0x1fff_ffff_1fff_ffff;
const P127: u128 = (1u128 << 127) - 1;
/// L1KEYLEN in bytes: NH's segment.
const SEGMENT: usize = 128;

/// 1 if `a < b`, else 0, without a branch.
fn lt(a: u64, b: u64) -> u64 {
    crate::bignum::ct::opaque((a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b))) >> 63)
}

/// 1 if `a == b`, else 0, without a branch.
fn eq(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    crate::bignum::ct::opaque(((x | x.wrapping_neg()) >> 63) ^ 1)
}

/// `(a + b) mod 2^127 - 1` for `a, b < 2^127`, fully reduced.
fn add_p127(a: u128, b: u128) -> u128 {
    reduce_p127(a + b)
}

/// `x mod 2^127 - 1` for any `x < 2^128`, fully reduced.
fn reduce_p127(x: u128) -> u128 {
    let s = (x & P127) + (x >> 127);
    // s <= 2^127; it is p127 or more exactly when s + 1 reaches 2^127.
    let over = crate::bignum::ct::opaque(((s + 1) >> 127) as u64) as u128;
    s - over * P127
}

/// `(a * b) mod 2^127 - 1` for `a, b < 2^127`.
fn mul_p127(a: u128, b: u128) -> u128 {
    let (a0, a1) = (a as u64 as u128, (a >> 64) as u64 as u128);
    let (b0, b1) = (b as u64 as u128, (b >> 64) as u64 as u128);
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let r0 = p00 as u64;
    let mid = (p00 >> 64) + (p01 as u64 as u128) + (p10 as u64 as u128);
    let r1 = mid as u64;
    let mid2 = (p01 >> 64) + (p10 >> 64) + (p11 as u64 as u128) + (mid >> 64);
    let r2 = mid2 as u64;
    let r3 = ((p11 >> 64) + (mid2 >> 64)) as u64;
    // P = low + high * 2^127, and 2^127 = 1 here.
    let low = (((r1 & M63) as u128) << 64) | r0 as u128;
    let high = ((r3 as u128) << 65) | ((r2 as u128) << 1) | (r1 >> 63) as u128;
    reduce_p127(low + high)
}

/// L3: `y` fully reduced mod 2^127 - 1, its key `(k1, k2)`, both below
/// 2^64 - 257. Krovetz's reference `l3hash`, with every comparison
/// computed rather than branched on.
fn l3(y: u128, k1: u64, k2: u64) -> u64 {
    let (mut p1, mut p2) = ((y >> 64) as u64, y as u64);
    // `y` is below 2^127 - 1 already, so the reference's first reduction
    // is a no-op here; it is kept so the code reads as the reference.
    let t = lt(M63, p1) + (eq(p1, M63) & eq(p2, M64));
    let (sum, carry) = p2.overflowing_add(t);
    p2 = sum;
    p1 = (p1 + carry as u64) & M63;

    // (p1, p2) div and mod (2^64 - 2^32).
    let mut t = p1.wrapping_add(p2 >> 32);
    t = t.wrapping_add(t >> 32);
    t = t.wrapping_add(lt(0xffff_fffe, t & 0xffff_ffff));
    p1 = p1.wrapping_add(t >> 32);
    p2 = p2.wrapping_add(p1 << 32);

    // (p1 + k1) and (p2 + k2), with a carry out folded in as 257.
    p1 = p1.wrapping_add(k1);
    p1 = p1.wrapping_add(lt(p1, k1).wrapping_neg() & 257);
    p2 = p2.wrapping_add(k2);
    p2 = p2.wrapping_add(lt(p2, k2).wrapping_neg() & 257);

    // Their product mod 2^64 - 257, with 2^64 = 257.
    let product = (p1 as u128) * (p2 as u128);
    let (mut rh, mut rl) = ((product >> 64) as u64, product as u64);
    let mut t = rh >> 56;
    let (sum, carry) = rl.overflowing_add(rh);
    rl = sum;
    t += carry as u64;
    rh <<= 8;
    let (sum, carry) = rl.overflowing_add(rh);
    rl = sum;
    t += carry as u64;
    t = t.wrapping_add(t << 8);
    rl = rl.wrapping_add(t);
    rl = rl.wrapping_add(lt(rl, t).wrapping_neg() & 257);
    rl = rl.wrapping_add(lt(P64 - 1, rl).wrapping_neg() & 257);
    rl
}

/// NH over one segment, zero padded to 16 bytes, with `key` at least
/// as many words as the padded segment.
fn nh(segment: &[u8], key: &[u64]) -> u128 {
    let mut padded = [0u8; SEGMENT];
    padded[..segment.len()].copy_from_slice(segment);
    let words = segment.len().div_ceil(16) * 2;
    let mut sum = 0u128;
    for pair in 0..words / 2 {
        let at = pair * 16;
        let m0 = u64::from_le_bytes(padded[at..at + 8].try_into().expect("8 bytes"));
        let m1 = u64::from_le_bytes(padded[at + 8..at + 16].try_into().expect("8 bytes"));
        let a = m0.wrapping_add(key[2 * pair]) as u128;
        let b = m1.wrapping_add(key[2 * pair + 1]) as u128;
        sum = sum.wrapping_add(a * b);
    }
    // Mod 2^126.
    sum & (((M62 as u128) << 64) | M64 as u128)
}

/// VMAC under one key, over any number of messages and nonces.
pub struct Vmac {
    cipher: AnyBlockCipher,
    /// 64 bit words of tag: 1 or 2.
    words: usize,
    nh_key: Vec<u64>,
    poly_key: Vec<u128>,
    l3_key: Vec<(u64, u64)>,
}

impl core::fmt::Debug for Vmac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Vmac {{ {}, {} bit tag, keys redacted }}", self.cipher.name(), self.words * 64)
    }
}

impl Vmac {
    /// `tag_len` is 8 or 16 bytes; the cipher must have a 128 bit block.
    pub fn new(cipher_name: &str, key: &[u8], tag_len: usize) -> Result<Vmac, String> {
        if tag_len != 8 && tag_len != 16 {
            return Err(format!("A VMAC tag is 8 or 16 bytes, not {tag_len}."));
        }
        let mut cipher = AnyBlockCipher::new(cipher_name, key, None)?;
        if cipher.blocksize() != 16 {
            return Err(format!(
                "VMAC is defined here over a 128 bit block cipher; {} has a {} bit block.",
                cipher.name(), cipher.blocksize() * 8));
        }
        let words = tag_len / 8;

        // KDF(K, index, n): blocks `index || counter`, counter big-endian
        // in the other fifteen bytes, from zero.
        let kdf = |cipher: &mut AnyBlockCipher, index: u8, blocks: usize|
                   -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; 16 * blocks];
            for (i, block) in out.chunks_mut(16).enumerate() {
                block[0] = index;
                block[8..].copy_from_slice(&(i as u64).to_be_bytes());
            }
            cipher.encrypt_blocks(&mut out)?;
            Ok(out)
        };
        let be = |bytes: &[u8]| u64::from_be_bytes(bytes.try_into().expect("8 bytes"));

        let nh_bytes = kdf(&mut cipher, 128, SEGMENT / 16 + (words - 1))?;
        let nh_key = nh_bytes.chunks(8).map(be).collect();

        let poly_bytes = kdf(&mut cipher, 192, words)?;
        let poly_key = poly_bytes.chunks(16)
            .map(|b| (((be(&b[..8]) & MPOLY) as u128) << 64) | (be(&b[8..]) & MPOLY) as u128)
            .collect();

        // L3's key by rejection: each candidate block in turn, kept when
        // both halves are below 2^64 - 257. A batch of eight covers every
        // key except with probability about 2^-50; more are drawn if not.
        let mut l3_key = Vec::with_capacity(words);
        let mut drawn = 0usize;
        while l3_key.len() < words {
            let more = kdf(&mut cipher, 224, drawn + 8)?;
            for block in more[16 * drawn..].chunks(16) {
                let (k1, k2) = (be(&block[..8]), be(&block[8..]));
                if k1 < P64 && k2 < P64 && l3_key.len() < words {
                    l3_key.push((k1, k2));
                }
            }
            drawn += 8;
        }
        Ok(Vmac { cipher, words, nh_key, poly_key, l3_key })
    }

    /// The tag's length in bytes.
    pub fn tag_len(&self) -> usize {
        self.words * 8
    }

    /// VHASH's 64 bits for one iteration.
    fn vhash(&self, message: &[u8], iteration: usize) -> u64 {
        let key = &self.nh_key[2 * iteration..2 * iteration + SEGMENT / 8];
        let k = self.poly_key[iteration];
        let y = if message.is_empty() {
            k
        } else {
            let mut y = 1u128;
            for segment in message.chunks(SEGMENT) {
                y = add_p127(mul_p127(y, k), nh(segment, key));
            }
            y
        };
        let bits = ((message.len() % SEGMENT) * 8) as u128;
        let y = add_p127(y, bits << 64);
        let (k1, k2) = self.l3_key[iteration];
        l3(y, k1, k2)
    }

    /// The tag over `message` under `nonce`: 1 to 16 bytes, and a 16
    /// byte one with its top bit clear - the draft takes nonces shorter
    /// than the block, which a 16 byte nonce is when its first bit is
    /// the zero the pad derivation prepends. A nonce must never repeat
    /// under one key.
    pub fn tag(&mut self, message: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        if nonce.is_empty() || nonce.len() > 16 || (nonce.len() == 16 && nonce[0] & 0x80 != 0) {
            return Err(format!(
                "A VMAC nonce is 1 to 16 bytes, and 16 only with its top bit clear; this \
                 one is {} bytes{}.", nonce.len(),
                if nonce.len() == 16 { " with its top bit set" } else { "" }));
        }
        // PDF: the nonce right-aligned in a zero block; for a 64 bit tag
        // its last bit picks the half of E(N), and is cleared first.
        let mut block = [0u8; 16];
        block[16 - nonce.len()..].copy_from_slice(nonce);
        let index = if self.words == 1 {
            let bit = (block[15] & 1) as usize;
            block[15] &= 0xfe;
            bit
        } else {
            0
        };
        self.cipher.encrypt_blocks(&mut block)?;
        let mut tag = Vec::with_capacity(self.words * 8);
        for word in 0..self.words {
            let at = 8 * (index + word);
            let pad = u64::from_be_bytes(block[at..at + 8].try_into().expect("8 bytes"));
            tag.extend_from_slice(&pad.wrapping_add(self.vhash(message, word)).to_be_bytes());
        }
        Ok(tag)
    }
}

/// The tag over one message, for callers with all of it in hand.
pub fn vmac(cipher_name: &str, key: &[u8], nonce: &[u8], message: &[u8], tag_len: usize)
            -> Result<Vec<u8>, String> {
    Vmac::new(cipher_name, key, tag_len)?.tag(message, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The draft's own vectors, read out of its appendix: five messages,
    /// each with its 64 and 128 bit tag under the key "abcdefghijklmnop"
    /// and the nonce "bcdefghi". The message column is a description -
    /// `<empty>` or `'abc' * N` - expanded here.
    #[test]
    fn test_the_drafts_vectors() {
        let draft = include_str!("../../rfcs/draft-krovetz-vmac-01.txt");
        let table = &draft[draft.find("Appendix - Test vectors").expect("the appendix")..];
        let mut rows = 0;
        let mut aes = Vmac::new("aes", b"abcdefghijklmnop", 8).unwrap();
        let mut aes128 = Vmac::new("aes", b"abcdefghijklmnop", 16).unwrap();
        for line in table.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (message, tag64, tag128) = match fields.as_slice() {
                ["<empty>", t64, t128] => (Vec::new(), *t64, *t128),
                ["'abc'", "*", count, t64, t128] => {
                    (b"abc".repeat(count.parse().unwrap()), *t64, *t128)
                }
                _ => continue,
            };
            let hex = |t: &[u8]| t.iter().map(|b| format!("{b:02X}")).collect::<String>();
            assert_eq!(hex(&aes.tag(&message, b"bcdefghi").unwrap()), tag64, "{line}");
            assert_eq!(hex(&aes128.tag(&message, b"bcdefghi").unwrap()), tag128, "{line}");
            rows += 1;
        }
        // A parser that found nothing would pass every assertion above.
        assert_eq!(rows, 5);
    }

    /// The reference's division by 2^64 - 2^32, against `u128` division,
    /// at the edges and over a spread of values.
    #[test]
    fn test_l3_split_matches_division() {
        let d: u128 = (1u128 << 64) - (1u128 << 32);
        let mut values: Vec<u128> = vec![0, 1, d - 1, d, d + 1, P127 - 1, P127 - 2,
                                         (1u128 << 64) - 1, 1u128 << 64, (1u128 << 96) + 12345];
        let mut x: u128 = 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834;
        for _ in 0..2000 {
            x = x.wrapping_mul(0x2545_f491_4f6c_dd1d_9e37_79b9_7f4a_7c15).wrapping_add(1);
            values.push(x % P127);
        }
        for y in values {
            let (q, r) = (y / d, y % d);
            // l3 with zero keys is (q mod p64) * (r mod p64) mod p64.
            let expected = ((q % P64 as u128) * (r % P64 as u128) % P64 as u128) as u64;
            assert_eq!(l3(y, 0, 0), expected, "{y:#x}");
        }
    }

    /// The field operations against `u128` arithmetic done the slow way.
    #[test]
    fn test_p127_arithmetic() {
        let mut x: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
        let reference_mul = |a: u128, b: u128| -> u128 {
            // Shift-and-add, reducing every step.
            let mut result = 0u128;
            let mut addend = a % P127;
            let mut b = b;
            while b != 0 {
                if b & 1 == 1 {
                    result = (result + addend) % P127;
                }
                addend = (addend << 1) % P127;
                b >>= 1;
            }
            result
        };
        for _ in 0..500 {
            x = x.wrapping_mul(0x2545_f491_4f6c_dd1d_9e37_79b9_7f4a_7c15).wrapping_add(7);
            let a = x % P127;
            let b = (x.rotate_left(61)) % P127;
            assert_eq!(mul_p127(a, b), reference_mul(a, b));
            assert_eq!(add_p127(a, b), (a + b) % P127);
        }
        assert_eq!(reduce_p127(P127), 0);
        assert_eq!(reduce_p127(P127 - 1), P127 - 1);
        assert_eq!(reduce_p127(u128::MAX), u128::MAX % P127);
        assert_eq!(mul_p127(P127 - 1, P127 - 1), 1);
    }

    #[test]
    fn test_nonces_and_tag_lengths_are_checked() {
        let key = b"abcdefghijklmnop";
        assert!(vmac("aes", key, b"", b"m", 8).is_err());
        assert!(vmac("aes", key, &[0u8; 17], b"m", 8).is_err());
        assert!(vmac("aes", key, &[0x80; 16], b"m", 8).is_err());
        assert!(vmac("aes", key, &[0x7f; 16], b"m", 8).is_ok());
        assert!(vmac("aes", key, b"n", b"m", 12).is_err());
        assert!(vmac("des", &[1u8; 8], b"n", b"m", 8).is_err());
    }

    /// For a 64 bit tag, nonces differing only in the last bit share an
    /// encryption and take its two halves.
    #[test]
    fn test_sibling_nonces_share_one_pad_block() {
        let mut vmac = Vmac::new("aes", b"abcdefghijklmnop", 8).unwrap();
        let even = vmac.tag(b"", &[0x10, 0x20]).unwrap();
        let odd = vmac.tag(b"", &[0x10, 0x21]).unwrap();
        let mut aes = AnyBlockCipher::new("aes", b"abcdefghijklmnop", None).unwrap();
        let mut block = [0u8; 16];
        block[14] = 0x10;
        block[15] = 0x20;
        aes.encrypt_blocks(&mut block).unwrap();
        let hash = vmac.vhash(b"", 0);
        let half = |at: usize| u64::from_be_bytes(block[at..at + 8].try_into().unwrap());
        assert_eq!(even, half(0).wrapping_add(hash).to_be_bytes());
        assert_eq!(odd, half(8).wrapping_add(hash).to_be_bytes());
    }
}
