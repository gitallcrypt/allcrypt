/*
UMAC (RFC 4418): a Wegman-Carter MAC - a universal hash of the message,
keyed, added to a pad the block cipher makes from a nonce. OpenSSH has
offered `umac-64@openssh.com` and `umac-128@openssh.com` since 4.7 and
prefers them, ahead of every HMAC, in its default MAC list.

UHASH has three layers. NH folds 1024 byte chunks into 8 bytes each with
32 bit additions and 64 bit multiplications; POLY hashes those under
the prime 2^64 - 59 (and 2^128 - 159 past 16 MB of input); a last inner
product mod 2^36 - 5 brings each iteration to 4 bytes. UMAC-64 runs two
iterations and UMAC-128 four, with keys overlapping between them, all
derived from one 16 byte AES key.

# Pitfalls

**A nonce must never repeat under one key.** The tag is the hash xor a
pad the nonce selects; two messages under one nonce leak the xor of
their hashes, and the hash is linear enough for that to matter. SSH uses
the packet sequence number, which never repeats within one key - and
with strict key exchange resets at NEWKEYS, where the key changes too.

**The message is read in little-endian 32 bit words** (RFC 4418's
ENDIAN-SWAP), while every key, pad and output is big endian. Mixing the
two gives a MAC that is self-consistent and matches nobody.

**The bit length is added to every chunk's NH output**, and the last
chunk is zero padded to 32 bytes first - so "abc" and "abc\0" differ only
through that length.

**PDF shares one AES block between consecutive nonces** when the tag is
4 or 8 bytes: UMAC-64 takes the nonce's low bit as an index into a
block computed from the nonce with that bit cleared.

**POLY's out-of-range words are escaped**, not reduced: a word at or
above `2^64 - 2^32` is hashed as a marker and then the word minus
`2^64 - p`. Reducing it instead is a different function.
*/

use crate::api::AnyBlockCipher;
use crate::bignum::BigUint;
use crate::block_ciphers::BlockCipher;

const P36: u64 = (1 << 36) - 5;
const P64: u64 = u64::MAX - 58; // 2^64 - 59

/// UMAC with one key, for tags of `tag_len` bytes (4, 8, 12 or 16).
pub struct Umac {
    tag_len: usize,
    l1_key: Vec<u32>,
    l2_key: Vec<(u64, BigUint)>,
    l3_key1: Vec<[u64; 8]>,
    l3_key2: Vec<u32>,
    pdf: AnyBlockCipher,
}

/// RFC 4418 3.2's KDF: AES in a counter mode under `index`.
fn kdf(cipher: &mut AnyBlockCipher, index: u64, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 16);
    let mut i = 1u64;
    while out.len() < length {
        let mut block = index.to_be_bytes().to_vec();
        block.extend_from_slice(&i.to_be_bytes());
        cipher.block_encrypt(&block, &mut out);
        i += 1;
    }
    out.truncate(length);
    out
}

impl Umac {
    pub fn new(key: &[u8], tag_len: usize) -> Result<Umac, String> {
        if key.len() != 16 {
            return Err(format!("UMAC takes a 16 byte AES key, not {}.", key.len()));
        }
        if ![4, 8, 12, 16].contains(&tag_len) {
            return Err(format!("UMAC makes 4, 8, 12 or 16 byte tags, not {tag_len}."));
        }
        let iterations = tag_len / 4;
        let mut cipher = AnyBlockCipher::new("aes", key, None)?;
        let l1 = kdf(&mut cipher, 1, 1024 + (iterations - 1) * 16);
        let l2 = kdf(&mut cipher, 2, iterations * 24);
        let l3_1 = kdf(&mut cipher, 3, iterations * 64);
        let l3_2 = kdf(&mut cipher, 4, iterations * 4);
        let pdf_key = kdf(&mut cipher, 0, 16);

        let l1_key = l1.chunks(4).map(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]])).collect();
        let l2_key = (0..iterations).map(|i| {
            let k = &l2[24 * i..24 * (i + 1)];
            let k64 = u64::from_be_bytes(k[..8].try_into().unwrap()) & 0x01ff_ffff_01ff_ffff;
            let mut k128 = k[8..24].to_vec();
            for (byte, mask) in k128.iter_mut().zip([0x01, 0xff, 0xff, 0xff].iter().cycle()) {
                *byte &= mask;
            }
            (k64, BigUint::from_bytes_be(&k128))
        }).collect();
        let l3_key1 = (0..iterations).map(|i| {
            let mut words = [0u64; 8];
            for (j, word) in words.iter_mut().enumerate() {
                let at = 64 * i + 8 * j;
                *word = u64::from_be_bytes(l3_1[at..at + 8].try_into().unwrap()) % P36;
            }
            words
        }).collect();
        let l3_key2 = l3_2.chunks(4)
            .map(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]])).collect();
        Ok(Umac { tag_len, l1_key, l2_key, l3_key1, l3_key2,
                  pdf: AnyBlockCipher::new("aes", &pdf_key, None)? })
    }

    /// The tag for `message` under `nonce` (1 to 16 bytes).
    pub fn tag(&mut self, message: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        if nonce.is_empty() || nonce.len() > 16 {
            return Err("UMAC: a nonce is 1 to 16 bytes.".to_string());
        }
        let mut tag = self.uhash(message);
        let pad = self.pdf(nonce);
        for (t, p) in tag.iter_mut().zip(pad) {
            *t ^= p;
        }
        Ok(tag)
    }

    fn pdf(&mut self, nonce: &[u8]) -> Vec<u8> {
        let mut block = [0u8; 16];
        block[..nonce.len()].copy_from_slice(nonce);
        let mut index = 0;
        if self.tag_len <= 8 {
            let per_block = 16 / self.tag_len;
            // The nonce's value mod 4 or 2 is its last byte's low bits.
            index = usize::from(nonce[nonce.len() - 1]) % per_block;
            block[nonce.len() - 1] ^= index as u8;
        }
        let mut out = Vec::with_capacity(16);
        self.pdf.block_encrypt(&block, &mut out);
        if self.tag_len <= 8 {
            out[index * self.tag_len..(index + 1) * self.tag_len].to_vec()
        } else {
            out.truncate(self.tag_len);
            out
        }
    }

    fn uhash(&self, message: &[u8]) -> Vec<u8> {
        let iterations = self.tag_len / 4;
        let l1 = self.l1_hash(iterations, message);
        let mut out = Vec::with_capacity(self.tag_len);
        for (i, a) in l1.iter().enumerate() {
            let b: u128 = if message.len() <= 1024 {
                u128::from(a[0])
            } else {
                self.l2_hash(i, a)
            };
            out.extend_from_slice(&self.l3_hash(i, b).to_be_bytes());
        }
        out
    }

    /// NH of every 1024 byte chunk with the chunk's bit length added,
    /// for each iteration: iteration `i` uses the L1 key from word
    /// `4 i`. Each chunk is read into words once, for all of them.
    fn l1_hash(&self, iterations: usize, message: &[u8]) -> Vec<Vec<u64>> {
        let count = message.len().div_ceil(1024).max(1);
        let mut out: Vec<Vec<u64>> = (0..iterations).map(|_| Vec::with_capacity(count)).collect();
        let mut words = [0u32; 256];
        for index in 0..count {
            let chunk = &message[1024 * index..message.len().min(1024 * (index + 1))];
            // The last chunk is zero padded to a multiple of 32 bytes,
            // and at least 32. ENDIAN-SWAP: little-endian words.
            let used = chunk.len().div_ceil(32).max(1) * 8;
            words[..used].fill(0);
            for (word, bytes) in words.iter_mut().zip(chunk.chunks(4)) {
                let mut le = [0u8; 4];
                le[..bytes.len()].copy_from_slice(bytes);
                *word = u32::from_le_bytes(le);
            }
            for (i, hashes) in out.iter_mut().enumerate() {
                hashes.push(nh(&self.l1_key[4 * i..4 * i + 256], &words[..used])
                    .wrapping_add(8 * chunk.len() as u64));
            }
        }
        out
    }

    fn l2_hash(&self, iteration: usize, words: &[u64]) -> u128 {
        let (k64, k128) = &self.l2_key[iteration];
        // 2^17 bytes of L1 output is 2^14 words.
        if words.len() <= 1 << 14 {
            return u128::from(poly64(*k64, words));
        }
        let y = poly64(*k64, &words[..1 << 14]);
        // The rest as 16 byte words, padded with 0x80 then zeros.
        let mut rest: Vec<u8> = words[1 << 14..].iter().flat_map(|w| w.to_be_bytes()).collect();
        rest.push(0x80);
        rest.resize(rest.len().div_ceil(16) * 16, 0);
        let mut input = (u128::from(y)).to_be_bytes().to_vec();
        input.extend_from_slice(&rest);
        poly128(k128, &input)
    }

    fn l3_hash(&self, iteration: usize, b: u128) -> u32 {
        let bytes = b.to_be_bytes();
        let key = &self.l3_key1[iteration];
        let mut y: u128 = 0;
        for (j, k) in key.iter().enumerate() {
            let m = u128::from(u16::from_be_bytes([bytes[2 * j], bytes[2 * j + 1]]));
            y += m * u128::from(*k);
        }
        let y = (y % u128::from(P36)) as u64;
        (y as u32) ^ self.l3_key2[iteration]
    }
}

/// RFC 4418 5.2.2: pairs four apart, 32 bit sums, 64 bit products.
fn nh(key: &[u32], words: &[u32]) -> u64 {
    let mut y: u64 = 0;
    for start in (0..words.len()).step_by(8) {
        for j in 0..4 {
            let a = words[start + j].wrapping_add(key[start + j]);
            let b = words[start + j + 4].wrapping_add(key[start + j + 4]);
            y = y.wrapping_add(u64::from(a) * u64::from(b));
        }
    }
    y
}

fn poly64(k: u64, words: &[u64]) -> u64 {
    let p = u128::from(P64);
    let offset = u64::MAX - P64 + 1; // 2^64 - p
    let marker = u128::from(P64 - 1);
    let mut y: u128 = 1;
    let k = u128::from(k);
    for word in words {
        if *word >= u64::MAX - 0xffff_ffff {
            // At or above 2^64 - 2^32: escaped.
            y = (k * y + marker) % p;
            y = (k * y + u128::from(word - offset)) % p;
        } else {
            y = (k * y + u128::from(*word)) % p;
        }
    }
    y as u64
}

/// POLY over 2^128 - 159, which needs 256 bit products - BigUint, since
/// only messages over 16 MB come here.
fn poly128(k: &BigUint, bytes: &[u8]) -> u128 {
    let p = BigUint::one().shl(128).sub(&BigUint::from_u64(159)).unwrap();
    let offset = BigUint::from_u64(159);
    let marker = p.sub(&BigUint::one()).unwrap();
    let max_range = BigUint::one().shl(128).sub(&BigUint::one().shl(96)).unwrap();
    let mut y = BigUint::one();
    for word in bytes.chunks(16) {
        let m = BigUint::from_bytes_be(word);
        if m >= max_range {
            y = k.mul(&y).add(&marker).rem(&p).unwrap();
            y = k.mul(&y).add(&m.sub(&offset).unwrap()).rem(&p).unwrap();
        } else {
            y = k.mul(&y).add(&m).rem(&p).unwrap();
        }
    }
    let bytes = y.to_bytes_be_padded(16).unwrap();
    u128::from_be_bytes(bytes.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC: &str = include_str!("../../rfcs/rfc4418.txt");

    /// RFC 4418 erratum 3507, verified: the 2^25 row's three tags are
    /// wrong as printed. The author published the corrected values; Nettle
    /// computes them too (`vectors/umac_nettle.vec` has its rows past
    /// 2^24 bytes). The printed line must still be in the document word
    /// for word, so the correction cannot drift onto another row. Both
    /// are written with single spaces and compared word by word.
    const ERRATUM_3507: (&str, &str) = (
        "'a' * 2^25 5109A660 2E2DBC36860A0A5F 72C6388BACE3ACE6FBF062D9",
        "'a' * 2^25 85EE5CAE FACA46F856E9B45F A621C2457C0012E64F3FDAE9",
    );

    /// The appendix's table: every message, at all three tag lengths it
    /// gives, read out of the vendored RFC with erratum 3507 applied.
    /// Includes 2^25 bytes, the only row long enough to reach POLY's 128
    /// bit stage.
    #[test]
    fn test_the_rfc_4418_vectors() {
        let start = RFC.find("     Message      32-bit Tag").unwrap();
        let mut rows = 0;
        let mut corrected = 0;
        for line in RFC[start..].lines().skip(2) {
            let words = line.split_whitespace().collect::<Vec<_>>().join(" ");
            let line = if words == ERRATUM_3507.0 {
                corrected += 1;
                ERRATUM_3507.1
            } else {
                line
            };
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() {
                break;
            }
            // `<empty>`, `'a' * 2^10`, `'abc' * 500`, then three tags.
            let tags = &fields[fields.len() - 3..];
            let message: Vec<u8> = if fields[0] == "<empty>" {
                Vec::new()
            } else {
                let unit = fields[0].trim_matches('\'').as_bytes();
                let count: usize = match fields[2].split_once('^') {
                    Some((base, power)) => base.parse::<usize>().unwrap()
                        .pow(power.parse().unwrap()),
                    None => fields[2].parse().unwrap(),
                };
                unit.repeat(count)
            };
            for (tag_len, expected) in [4usize, 8, 12].into_iter().zip(tags) {
                let mut umac = Umac::new(b"abcdefghijklmnop", tag_len).unwrap();
                let tag = umac.tag(&message, b"bcdefghi").unwrap();
                let hex: String = tag.iter().map(|b| format!("{b:02X}")).collect();
                assert_eq!(&hex, expected, "{line} at {tag_len} bytes");
            }
            rows += 1;
        }
        assert_eq!((rows, corrected), (8, 1));
    }

    /// The appendix's intermediates for a 64 bit tag, read out of the
    /// RFC as well: NH key words, the L2 and L3 keys, the pad and the
    /// UHASH of 'abc' * 500. A wrong tag says something is wrong; these
    /// say where.
    #[test]
    fn test_the_rfc_4418_intermediates() {
        let section = &RFC[RFC.find("producing a 64-bit tag").unwrap()..];
        // The hex values on the line that starts with `label`.
        let row = |label: &str| -> Vec<u64> {
            let line = section.lines().find(|l| l.split_whitespace().next() == Some(label))
                .unwrap_or_else(|| panic!("{label}"));
            line.split_whitespace().skip(1)
                .map(|hex| u64::from_str_radix(hex, 16).unwrap()).collect()
        };
        let mut umac = Umac::new(b"abcdefghijklmnop", 8).unwrap();
        for (j, label) in ["K_1", "K_2", "K_3", "K_4", "K_5"].iter().enumerate() {
            let words = row(label);
            assert_eq!(u64::from(umac.l1_key[j]), words[0], "{label}, iteration 1");
            assert_eq!(u64::from(umac.l1_key[4 + j]), words[1], "{label}, iteration 2");
        }
        assert_eq!(u64::from(umac.l1_key[255]), row("K_256")[0]);
        let k64 = row("k64");
        assert_eq!((umac.l2_key[0].0, umac.l2_key[1].0), (k64[0], k64[1]));
        for (j, label) in ["k_5", "k_6", "k_7", "k_8"].iter().enumerate() {
            let keys = row(label);
            assert_eq!((umac.l3_key1[0][4 + j], umac.l3_key1[1][4 + j]), (keys[0], keys[1]),
                       "{label}");
        }
        let k2 = row("K2");
        assert_eq!(umac.l3_key2.iter().map(|k| u64::from(*k)).collect::<Vec<_>>(), k2);

        // "The pad generated for nonce N is D13745D4304F1842", and the
        // UHASH result "05F86309DF9AD858", from the prose.
        let quoted = |after: &str| -> Vec<u8> {
            let at = section.find(after).unwrap() + after.len();
            let hex: String = section[at..].split_whitespace().next().unwrap()
                .trim_end_matches(['.', ',']).to_string();
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        };
        assert_eq!(umac.pdf(b"bcdefghi"), quoted("The pad generated for nonce N is"));
        assert_eq!(umac.uhash(&b"abc".repeat(500)), quoted("final UHASH result\n   of"));
    }
}
