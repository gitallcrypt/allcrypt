/*
The GOST key derivation functions: RFC 7836's KDF, and RFC 9189's TLSTREE.

`KDF_GOSTR3411_2012_256` is one HMAC over a framed input:

    KDF(K, label, seed) =
        HMAC_Streebog256(K, 0x01 || label || 0x00 || seed || 0x01 || 0x00)

The `0x01` at the front and the `0x01 0x00` at the end are not padding.
They are the counter and the output length from the general tree KDF of
RFC 7836 section 4.4, of which this is the R = 1, L = 256 case - so the
trailing pair is `STR_2(256)` and the leading byte is block number one.
Dropping them gives a function that is perfectly deterministic and is not
this one.

**TLSTREE** (RFC 9189 section 8.1) is how the CTR_OMAC suites re-key. It
is three of those KDFs in a chain, each keyed by the last and each fed a
*masked* record sequence number:

    TLSTREE(K_root, i) = KDF_3(KDF_2(KDF_1(K_root, STR_8(i & C_1)),
                                     STR_8(i & C_2)), STR_8(i & C_3))

The masks are the point. `C_1` keeps only the high bits, `C_2` a few
more, `C_3` almost all - so the first level changes very rarely, the
second less rarely and the third every few dozen records. A sender can
cache the first two and recompute only the third, which is the whole
reason for the shape: re-keying every record without hashing three times
every record.

Two things to get right, and the RFC's own test vectors in `tests` catch
both:

  * **`STR_8` is big endian**, as RFC 9189 section 3 defines it. The same
    document also defines `str_8`, little endian, and uses both. Masking
    a counter and writing it the wrong way round gives a key schedule
    that is entirely self-consistent.

  * **The constants differ per suite**, and by a lot: Magma re-keys its
    first level after 2^38 records and Kuznyechik after 2^32. Using one
    suite's constants for the other produces keys neither peer computes.

The vectors are RFC 9189 Appendix A.1.1, which prints all three levels
for both suites at the sequence numbers either side of each boundary -
so a mask that is off by one bit fails rather than passing on the
numbers that happen not to straddle anything.
*/

use crate::hash_functions::streebog::Streebog;
use crate::mac::Hmac;
use crate::Mac;

/// `KDF_TREE_GOSTR3411_2012_256`, RFC 7836 section 4.4.
///
/// ```text
/// K(i) = HMAC_Streebog256(K_in, [i]_R | label | 0x00 | seed | [L]_b)
/// ```
///
/// `counter_bytes` is the RFC's `R`, the width of the block counter, and
/// `bits` is `L`, the total output size. `[L]_b` carries **no leading
/// zero bytes**, which is the one part of the framing that is not a
/// fixed width - so 256 bits is `0x01 0x00` and 512 is `0x02 0x00`, and
/// a caller that padded it to a fixed four bytes would get a function
/// that is deterministic, self-consistent and not this one.
pub fn kdf_tree_gostr3411_2012_256(key: &[u8], label: &[u8], seed: &[u8],
                                   counter_bytes: usize, bits: usize)
                                   -> Result<Vec<u8>, String> {
    if !(1..=4).contains(&counter_bytes) {
        return Err(format!(
            "The tree KDF's counter is 1 to 4 bytes wide (RFC 7836 section \
             4.4); {} is not.", counter_bytes));
    }
    if bits == 0 || !bits.is_multiple_of(8) {
        return Err(format!(
            "The tree KDF produces whole bytes; {} bits is not a whole \
             number of them.", bits));
    }
    // The counter arithmetic in `u64`, not `usize`: a four byte counter
    // reaches 2^32 - 1, and `1usize << 32` is an overflow on a 32-bit
    // target (a panic in debug, zero in release, so every R = 4 call
    // would be refused there), while `usize::to_be_bytes` is four bytes
    // wide and `[8 - counter_bytes..]` would index past it.
    let blocks = bits.div_ceil(256) as u64;
    let limit = (1u64 << (8 * counter_bytes)) - 1;
    if blocks > limit {
        return Err(format!(
            "{} bits needs {} blocks, and a {} byte counter reaches {}.",
            bits, blocks, counter_bytes, limit));
    }

    // [L]_b: big endian with no leading zeros. `to_be_bytes` then strip.
    let length_bytes: Vec<u8> = {
        let full = (bits as u64).to_be_bytes();
        let first = full.iter().position(|b| *b != 0).unwrap_or(full.len() - 1);
        full[first..].to_vec()
    };

    let mut out = crate::kdf::output_buffer(bits / 8, "The tree KDF")?;
    for block in 1..=blocks {
        let mut mac = Hmac::new(Streebog::new_256(&[]), key);
        mac.update(&block.to_be_bytes()[8 - counter_bytes..]);
        mac.update(label);
        mac.update(&[0x00]);
        mac.update(seed);
        mac.update(&length_bytes);
        let digest = mac.digest();
        let take = core::cmp::min(digest.len(), bits / 8 - out.len());
        out.extend_from_slice(&digest[..take]);
    }
    Ok(out)
}

/// `KDF_GOSTR3411_2012_256`, RFC 7836 section 4.5: the tree KDF with
/// `R = 1` and `L = 256`.
pub fn kdf_gostr3411_2012_256(key: &[u8], label: &[u8], seed: &[u8]) -> Vec<u8> {
    // Cannot fail: R and L are both in range by construction.
    kdf_tree_gostr3411_2012_256(key, label, seed, 1, 256)
        .expect("R = 1 and L = 256 are always in range")
}

/// The three masks a suite re-keys on, RFC 9189 section 8.1.1.
///
/// Held as a type rather than three loose arguments because they only
/// ever travel together and using one suite's with another's is the
/// mistake worth making impossible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TlsTreeParams {
    pub c1: u64,
    pub c2: u64,
    pub c3: u64,
}

impl TlsTreeParams {
    /// `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`.
    pub const KUZNYECHIK: TlsTreeParams = TlsTreeParams {
        c1: 0xFFFF_FFFF_0000_0000,
        c2: 0xFFFF_FFFF_FFF8_0000,
        c3: 0xFFFF_FFFF_FFFF_FFC0,
    };

    /// `TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`.
    ///
    /// Magma's first level lasts 2^38 records against Kuznyechik's
    /// 2^32 - a 64 bit block wears out faster, so it re-keys the *lower*
    /// levels more often and the top one less.
    pub const MAGMA: TlsTreeParams = TlsTreeParams {
        c1: 0xFFFF_FFC0_0000_0000,
        c2: 0xFFFF_FFFF_FE00_0000,
        c3: 0xFFFF_FFFF_FFFF_F000,
    };

    // RFC 9367 section 4.1.2, for the TLS 1.3 suites. The same
    // function, four more sets of constants, and **not one of them
    // repeats a set above** - a TLS 1.3 connection re-keys on a
    // different schedule from a TLS 1.2 one over the same cipher, which
    // is the kind of thing that interoperates at sequence number 0 and
    // nowhere else. `document_tests` checks all six against the two
    // RFCs rather than trusting the transcription.

    /// `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L` (0xC103).
    pub const KUZNYECHIK_MGM_L: TlsTreeParams = TlsTreeParams {
        c1: 0xF800_0000_0000_0000,
        c2: 0xFFFF_FFF0_0000_0000,
        c3: 0xFFFF_FFFF_FFFF_E000,
    };

    /// `TLS_GOSTR341112_256_WITH_MAGMA_MGM_L` (0xC104).
    pub const MAGMA_MGM_L: TlsTreeParams = TlsTreeParams {
        c1: 0xFFE0_0000_0000_0000,
        c2: 0xFFFF_FFFF_C000_0000,
        c3: 0xFFFF_FFFF_FFFF_FF80,
    };

    /// `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S` (0xC105).
    ///
    /// The `_S` suites re-key far more often than the `_L` ones: this
    /// one's third level changes every **eight** records, where the
    /// `_L` variant's changes every 8192.
    pub const KUZNYECHIK_MGM_S: TlsTreeParams = TlsTreeParams {
        c1: 0xFFFF_FFFF_E000_0000,
        c2: 0xFFFF_FFFF_FFFF_0000,
        c3: 0xFFFF_FFFF_FFFF_FFF8,
    };

    /// `TLS_GOSTR341112_256_WITH_MAGMA_MGM_S` (0xC106).
    ///
    /// `C_3` is all ones, so the third level re-keys on **every single
    /// record**. That is not a typo in the table and it is the reason
    /// `TlsTree`'s caching must key off the masked value rather than
    /// off a level index.
    pub const MAGMA_MGM_S: TlsTreeParams = TlsTreeParams {
        c1: 0xFFFF_FFFF_FC00_0000,
        c2: 0xFFFF_FFFF_FFFF_E000,
        c3: 0xFFFF_FFFF_FFFF_FFFF,
    };
}

/// The three levels of `TLSTREE`, in order.
///
/// Returned together rather than only the last because a sender caches
/// the first two: they change every 2^32-odd and 2^19-odd records, and
/// recomputing all three per record is three Streebog compressions of
/// waste. `TlsTree` below does the caching; this is the plain function
/// the test vectors check.
pub fn tlstree_levels(root: &[u8], sequence: u64, params: TlsTreeParams)
                      -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // STR_8: big endian, RFC 9189 section 3. The same document defines a
    // little endian `str_8` and uses both, so this is a choice rather
    // than a default.
    let level1 = kdf_gostr3411_2012_256(root, b"level1",
                                        &(sequence & params.c1).to_be_bytes());
    let level2 = kdf_gostr3411_2012_256(&level1, b"level2",
                                        &(sequence & params.c2).to_be_bytes());
    let level3 = kdf_gostr3411_2012_256(&level2, b"level3",
                                        &(sequence & params.c3).to_be_bytes());
    (level1, level2, level3)
}

/// `TLSTREE(K_root, i)`.
pub fn tlstree(root: &[u8], sequence: u64, params: TlsTreeParams) -> Vec<u8> {
    tlstree_levels(root, sequence, params).2
}

/// TLSTREE with the upper levels cached.
///
/// The masked sequence numbers are what the levels depend on, so a level
/// only has to be recomputed when its masked value changes. Keeping the
/// masked values - rather than a record count - is what makes that exact
/// rather than a guess: the cache is valid precisely while the mask says
/// it is.
#[derive(Clone)]
pub struct TlsTree {
    root: Vec<u8>,
    params: TlsTreeParams,
    /// The masked sequence numbers the cached levels were derived at.
    /// `None` before anything has been derived - not zero, because zero
    /// is a real masked value and starting there would serve a key for
    /// sequence 0 that was never computed.
    at: Option<(u64, u64)>,
    level1: Vec<u8>,
    level2: Vec<u8>,
}

impl core::fmt::Debug for TlsTree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TlsTree {{ keys redacted }}")
    }
}

impl TlsTree {
    pub fn new(root: &[u8], params: TlsTreeParams) -> TlsTree {
        TlsTree {
            root: root.to_vec(),
            params,
            at: None,
            level1: Vec::new(),
            level2: Vec::new(),
        }
    }

    /// The key for one record's sequence number.
    pub fn key(&mut self, sequence: u64) -> Vec<u8> {
        let masked = (sequence & self.params.c1, sequence & self.params.c2);

        if self.at != Some(masked) {
            // Only recompute the levels whose mask actually moved. The
            // first level changes once in billions of records.
            if self.at.map(|(one, _)| one) != Some(masked.0) {
                self.level1 = kdf_gostr3411_2012_256(
                    &self.root, b"level1", &masked.0.to_be_bytes());
            }
            self.level2 = kdf_gostr3411_2012_256(
                &self.level1, b"level2", &masked.1.to_be_bytes());
            self.at = Some(masked);
        }

        kdf_gostr3411_2012_256(&self.level2, b"level3",
                               &(sequence & self.params.c3).to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// The tree KDF's `[L]_b` has no leading zeros and its counter is
    /// `R` bytes wide, so `R = 1, L = 256` must be exactly the 4.5
    /// function - which is the only vector either of them has.
    #[test]
    fn test_the_special_case_is_the_general_one() {
        let key = [0x5au8; 32];
        assert_eq!(kdf_tree_gostr3411_2012_256(&key, b"label", b"seed", 1, 256)
                       .unwrap(),
                   kdf_gostr3411_2012_256(&key, b"label", b"seed"));

        // A wider counter is a different framing, not a longer number
        // with the same value.
        assert_ne!(kdf_tree_gostr3411_2012_256(&key, b"label", b"seed", 2, 256)
                       .unwrap(),
                   kdf_gostr3411_2012_256(&key, b"label", b"seed"));

        // 512 bits is two blocks whose first is *not* the 256 bit
        // answer: [L]_b is in every block's input, so the length changes
        // all of them.
        let long = kdf_tree_gostr3411_2012_256(&key, b"label", b"seed", 1, 512)
                   .unwrap();
        assert_eq!(long.len(), 64);
        assert_ne!(long[..32], kdf_gostr3411_2012_256(&key, b"label", b"seed")[..],
                   "the output length is part of every block's input");

        // And the second block differs from the first by its counter.
        assert_ne!(long[..32], long[32..]);
    }

    /// `[L]_b` carries no leading zero bytes. 256 is `01 00` and 512 is
    /// `02 00`; a fixed width encoding would be a different function
    /// that agrees with itself.
    #[test]
    fn test_the_length_has_no_leading_zeros() {
        let key = [0x11u8; 32];
        let ours = kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 1, 512).unwrap();

        let padded = {
            let mut mac = Hmac::new(Streebog::new_256(&[]), &key);
            mac.update(&[0x01]);
            mac.update(b"l");
            mac.update(&[0x00]);
            mac.update(b"s");
            mac.update(&[0x00, 0x00, 0x02, 0x00]);   // L padded to four bytes
            mac.digest()
        };
        assert_ne!(ours[..32], padded[..]);
    }

    #[test]
    fn test_the_tree_kdf_refuses_what_it_cannot_do() {
        let key = [0u8; 32];
        assert!(kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 0, 256).is_err());
        assert!(kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 5, 256).is_err());
        assert!(kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 1, 0).is_err());
        assert!(kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 1, 4).is_err());
        // One byte of counter reaches 255 blocks, so 255*256 bits is the
        // most it can produce and one more is a refusal rather than a
        // counter that wraps to 1 and repeats a block.
        assert!(kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 1, 255 * 256).is_ok());
        assert!(kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 1, 256 * 256).is_err());
    }

    /// The four byte counter's limit was `(1usize << 32) - 1`, which
    /// on a 32-bit target is a shift overflow - a panic in debug and
    /// zero in release, so every R = 4 call was refused there - and
    /// the counter bytes came from `usize::to_be_bytes`, four bytes
    /// wide on that target, indexed at `8 - counter_bytes`. No test ran
    /// on such a target; on a 64-bit one the `usize` and `u64` forms
    /// agree. The arithmetic is now `u64` on every target, and the
    /// widest counter is pinned to accept and to frame as four bytes.
    #[test]
    fn test_the_four_byte_counter_works_on_every_target() {
        let key = [0u8; 32];
        let out = kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 4, 256).unwrap();
        assert_eq!(out.len(), 32);
        let by_hand = {
            let mut mac = Hmac::new(Streebog::new_256(&[]), &key);
            mac.update(&[0, 0, 0, 1]);
            mac.update(b"l");
            mac.update(&[0x00]);
            mac.update(b"s");
            mac.update(&[0x01, 0x00]);
            mac.digest()
        };
        assert_eq!(out, by_hand);
        // An output past the KDF cap is an error before any allocation.
        assert!(kdf_tree_gostr3411_2012_256(&key, b"l", b"s", 4,
                                            (crate::kdf::MAX_OUTPUT_BYTES + 256) * 8)
                    .is_err());
    }

    /// RFC 7836 Appendix B, example 1.
    ///
    /// The `T` in that example is already the KDF's framed input - it is
    /// `0x01 || label || 0x00 || seed || 0x01 || 0x00` with a four byte
    /// label and an eight byte seed - so this pins the framing and the
    /// HMAC together, which is exactly what a wrong frame would hide.
    #[test]
    fn test_rfc_7836_kdf() {
        let key = unhex("000102030405060708090a0b0c0d0e0f\
                         101112131415161718191a1b1c1d1e1f");
        let label = unhex("26bdb878");
        let seed = unhex("af21434145656378");

        assert_eq!(hex(&kdf_gostr3411_2012_256(&key, &label, &seed)),
                   "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9");

        // And the framed input is what the RFC prints as T.
        let mut framed = vec![0x01];
        framed.extend_from_slice(&label);
        framed.push(0x00);
        framed.extend_from_slice(&seed);
        framed.extend_from_slice(&[0x01, 0x00]);
        assert_eq!(hex(&framed), "0126bdb87800af21434145656378 0100".replace(' ', ""));
    }

    const ROOT: &str = "00112233445566778899AABBCCEEFF0A\
                        11223344556677 8899AABBCCEEFF0A00";

    /// RFC 9189 Appendix A.1.1.1, all three levels.
    ///
    /// The sequence numbers straddle every boundary: 4095/4096 is the
    /// third mask, 33554431/33554432 the second. A mask off by one bit
    /// fails on the pair that brackets it rather than passing on numbers
    /// that happen not to straddle anything.
    #[test]
    fn test_rfc_9189_tlstree_magma() {
        let root = unhex(ROOT);
        let p = TlsTreeParams::MAGMA;

        let (one, two, three) = tlstree_levels(&root, 0, p);
        assert_eq!(hex(&one), "f35589f09bf801b1ca114273b95fd6c1\
                               392e78f9fb814da05a7cca089ec86542");
        assert_eq!(hex(&two), "5137d5c4a6e6be42c440d10a95eea07f\
                               089e740d3890eb52652c0cb93f207bb4");
        assert_eq!(hex(&three), "19a76ed30f4d6d1f5b7263ec491ad838\
                                 17c0b57d8a035612714 0fb4f7425494d".replace(' ', ""));

        // 4095 is still in the same third-level block as 0.
        assert_eq!(tlstree(&root, 4095, p), tlstree(&root, 0, p));
        // 4096 crosses it.
        assert_eq!(hex(&tlstree(&root, 4096, p)),
                   "fb30ee53cfcf89d748fc0c72ef160b8b\
                    53cbbbfd031282b026214ab2e07758ff");

        // 33554431/33554432 crosses the second level.
        assert_eq!(hex(&tlstree(&root, 33554431, p)),
                   "b85b36dc2282326bc035c572dc93f18d\
                    83aa0174f394209a513bb374dc0935ae");
        let (_, two_after, _) = tlstree_levels(&root, 33554432, p);
        assert_eq!(hex(&two_after), "3fea5938da2bf8ddc47ec1dc55618966\
                                     7902be420df4c37daf21753bcb1dc7f3");
        assert_ne!(two_after, two, "the second level must move at 2^25");
    }

    /// RFC 9189 Appendix A.1.1.2. Different constants, so the boundaries
    /// fall in different places: 63/64 and 524287/524288.
    #[test]
    fn test_rfc_9189_tlstree_kuznyechik() {
        let root = unhex(ROOT);
        let p = TlsTreeParams::KUZNYECHIK;

        assert_eq!(hex(&tlstree(&root, 0, p)),
                   "19a76ed30f4d6d1f5b7263ec491ad838\
                    17c0b57d8a035612714 0fb4f7425494d".replace(' ', ""));
        assert_eq!(tlstree(&root, 63, p), tlstree(&root, 0, p));
        assert_eq!(hex(&tlstree(&root, 64, p)),
                   "aebe1ef418713bf044b9fcd9e572d437\
                    fb38b5d829567a6f7918396d9f4e096b");

        assert_eq!(hex(&tlstree(&root, 524287, p)),
                   "6f18d4003ea2cb30f5fec193a234f07d\
                    7c439498 7f50758de22b220d8a105106".replace(' ', ""));
        assert_eq!(hex(&tlstree(&root, 524288, p)),
                   "e54b16415b3b663e780b062d24f736c4\
                    495463c3a891e1fa46f7ae99fff9f378");

        assert_eq!(hex(&tlstree(&root, 4294967295, p)),
                   "cf600904c71e7b88a49ac8e245774b3d\
                    beedfb81de9a0e2f4e46c35607bc2f04");
        // 2^32 crosses the first level, which is the rarest event here.
        let (one_after, _, three_after) = tlstree_levels(&root, 4294967296, p);
        assert_eq!(hex(&one_after), "55cc95e0d1fb5485af8ef69acd72b232\
                                     797cd2e85d86cdfd1de55bd1fa143778");
        assert_eq!(hex(&three_after), "16180b246454 00b836143837d86aac93\
                                       952ae3eb8244d5ec2ab02cff30781138".replace(' ', ""));
    }

    /// The two suites' constants are not interchangeable. Using one for
    /// the other gives a key neither peer computes - and at sequence 0
    /// every mask is zero, so the mistake is invisible at the only
    /// sequence number a quick test would try.
    #[test]
    fn test_the_two_suites_disagree_and_agree_at_zero() {
        let root = unhex(ROOT);
        assert_eq!(tlstree(&root, 0, TlsTreeParams::MAGMA),
                   tlstree(&root, 0, TlsTreeParams::KUZNYECHIK),
                   "every mask is zero at sequence 0, so testing only there \
                    would prove nothing");
        assert_ne!(tlstree(&root, 64, TlsTreeParams::MAGMA),
                   tlstree(&root, 64, TlsTreeParams::KUZNYECHIK));
    }

    /// `STR_8` is big endian. RFC 9189 defines a little endian `str_8`
    /// too and uses both, so this is a choice - and one that is entirely
    /// self-consistent when made wrongly.
    #[test]
    fn test_the_counter_is_big_endian() {
        let root = unhex(ROOT);
        let p = TlsTreeParams::KUZNYECHIK;
        let sequence = 64u64;

        let ours = tlstree(&root, sequence, p);
        let backwards = {
            let mut bytes = (sequence & p.c1).to_be_bytes().to_vec();
            bytes.reverse();
            let one = kdf_gostr3411_2012_256(&root, b"level1", &bytes);
            let mut bytes = (sequence & p.c2).to_be_bytes().to_vec();
            bytes.reverse();
            let two = kdf_gostr3411_2012_256(&one, b"level2", &bytes);
            let mut bytes = (sequence & p.c3).to_be_bytes().to_vec();
            bytes.reverse();
            kdf_gostr3411_2012_256(&two, b"level3", &bytes)
        };
        assert_ne!(ours, backwards);
    }

    /// The cache must serve exactly what the plain function computes, at
    /// every boundary and in whatever order it is asked.
    #[test]
    fn test_the_cache_agrees_with_the_plain_function() {
        let root = unhex(ROOT);
        for p in [TlsTreeParams::MAGMA, TlsTreeParams::KUZNYECHIK] {
            let mut tree = TlsTree::new(&root, p);
            // Ascending across several boundaries, which is the ordinary
            // case: a record layer asks in sequence.
            for sequence in (0u64..2100).chain([524_287, 524_288, 524_289,
                                                33_554_431, 33_554_432,
                                                4_294_967_295, 4_294_967_296]) {
                assert_eq!(tree.key(sequence), tlstree(&root, sequence, p),
                           "sequence {}", sequence);
            }
            // And backwards, which a record layer never does - but a
            // cache keyed on a count rather than on the masked value
            // would get this wrong, and that is the bug worth excluding.
            let mut tree = TlsTree::new(&root, p);
            for sequence in [4_294_967_296u64, 64, 524_288, 0, 33_554_432, 1] {
                assert_eq!(tree.key(sequence), tlstree(&root, sequence, p),
                           "out of order at {}", sequence);
            }
        }
    }

    /// Sequence 0 must produce a key, not the root. A cache initialised
    /// to "already at zero" would hand back whatever it started with.
    #[test]
    fn test_the_first_key_is_derived() {
        let root = unhex(ROOT);
        let mut tree = TlsTree::new(&root, TlsTreeParams::MAGMA);
        let first = tree.key(0);
        assert_ne!(first, root);
        assert_eq!(first, tlstree(&root, 0, TlsTreeParams::MAGMA));
    }
}

/// The six constant sets, read back out of the two RFCs that define
/// them.
///
/// Nothing above is transcribed on trust. Three of the twelve digits in
/// a mask are indistinguishable by eye (`0xFFFFFFF0` against
/// `0xFFFFFF00`), the masks differ between suites by a few bits, and
/// every one of them is *all ones* at sequence number 0 - so a
/// mistyped constant produces a key schedule that agrees with a real
/// peer on the first record of a connection and diverges later, which
/// is the worst shape a bug can have here.
///
/// Both documents print the table the same way, which is why one parser
/// reads both:
///
/// ```text
/// |TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC     |C_1=0xFFFFFFC000000000|
/// |                                            |C_2=0xFFFFFFFFFE000000|
/// ```
#[cfg(test)]
mod document_tests {
    use super::TlsTreeParams;

    const RFC_9189: &str = include_str!("../../rfcs/rfc9189.txt");
    const RFC_9367: &str = include_str!("../../rfcs/rfc9367.txt");

    /// `(suite, [c1, c2, c3])` for every row of every such table in one
    /// document.
    ///
    /// The suite name is on the row carrying `C_1` and the other two
    /// rows carry only their value, so the name has to be remembered
    /// across lines - the same statefulness a CRL's `certificateIssuer`
    /// needs, and the same trap: reading each line independently
    /// attributes `C_2` and `C_3` to nothing at all.
    fn table(document: &str) -> Vec<(String, [u64; 3])> {
        let mut rows: Vec<(String, [u64; 3])> = Vec::new();
        for line in document.lines() {
            let Some(at) = line.find("C_") else { continue };
            let rest = &line[at..];
            let Some(index) = rest.as_bytes().get(2)
                .and_then(|b| (*b as char).to_digit(10)) else { continue };
            // `C_1=0x...` and nothing else; the prose above the table
            // writes `C_1, C_2, C_3 are constants` with no `=0x`.
            let Some(value) = rest.split("=0x").nth(1) else { continue };
            let digits: String = value.chars()
                .take_while(|c| c.is_ascii_hexdigit()).collect();
            if digits.len() != 16 {
                continue;
            }
            let number = u64::from_str_radix(&digits, 16)
                .expect("sixteen hex digits");

            if index == 1 {
                // The name is between the first two bars on this line.
                let name: String = line.split('|').nth(1)
                    .expect("a table row has bars")
                    .trim().to_string();
                assert!(name.starts_with("TLS_"),
                        "the name column held {name:?}");
                rows.push((name, [number, 0, 0]));
            } else {
                let row = rows.last_mut()
                    .expect("a C_2 row before any C_1 row");
                row.1[index as usize - 1] = number;
            }
        }
        rows
    }

    /// The parse, before anything uses it. A parser that found nothing
    /// would make every comparison below an empty loop.
    #[test]
    fn test_both_tables_parse() {
        let old = table(RFC_9189);
        let new = table(RFC_9367);
        assert_eq!(old.len(), 2, "RFC 9189 defines two CTR_OMAC suites");
        assert_eq!(new.len(), 4, "RFC 9367 defines four TLS 1.3 suites");
        for (name, masks) in old.iter().chain(&new) {
            assert!(masks.iter().all(|&m| m != 0), "{name}: a mask is zero");
            // Each mask keeps strictly more of the sequence number than
            // the one above it, which is what makes the three levels a
            // tree rather than three independent derivations.
            assert!(masks[0] < masks[1] && masks[1] < masks[2],
                    "{name}: the masks are not nested");
        }
    }

    #[test]
    fn test_every_constant_set_is_the_documents() {
        let rows: Vec<(String, [u64; 3])> =
            table(RFC_9189).into_iter().chain(table(RFC_9367)).collect();

        let ours = [
            ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
             TlsTreeParams::KUZNYECHIK),
            ("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", TlsTreeParams::MAGMA),
            ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
             TlsTreeParams::KUZNYECHIK_MGM_L),
            ("TLS_GOSTR341112_256_WITH_MAGMA_MGM_L", TlsTreeParams::MAGMA_MGM_L),
            ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
             TlsTreeParams::KUZNYECHIK_MGM_S),
            ("TLS_GOSTR341112_256_WITH_MAGMA_MGM_S", TlsTreeParams::MAGMA_MGM_S),
        ];

        for (name, params) in ours {
            let (_, masks) = rows.iter().find(|(row, _)| row == name)
                .unwrap_or_else(|| panic!("{name} is in neither document"));
            assert_eq!([params.c1, params.c2, params.c3], *masks,
                       "{name} does not match its document");
        }
        assert_eq!(rows.len(), ours.len(),
                   "a suite is defined in a document and not here");
    }

    /// No two suites share a set.
    ///
    /// A copied row is the mistake this catches, and it is invisible
    /// otherwise: two suites with the same schedule interoperate with
    /// each other perfectly and with the real world not at all.
    #[test]
    fn test_no_two_suites_share_a_schedule() {
        let all = [TlsTreeParams::KUZNYECHIK, TlsTreeParams::MAGMA,
                   TlsTreeParams::KUZNYECHIK_MGM_L, TlsTreeParams::MAGMA_MGM_L,
                   TlsTreeParams::KUZNYECHIK_MGM_S, TlsTreeParams::MAGMA_MGM_S];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "two suites share a constant set");
            }
        }
    }

    /// `MAGMA_MGM_S`'s `C_3` is all ones, so its third level changes on
    /// every record. Asserted because it looks like a transcription
    /// error and is not.
    #[test]
    fn test_the_all_ones_mask_is_deliberate() {
        assert_eq!(TlsTreeParams::MAGMA_MGM_S.c3, u64::MAX);
        let root = [0x42u8; 32];
        assert_ne!(super::tlstree(&root, 0, TlsTreeParams::MAGMA_MGM_S),
                   super::tlstree(&root, 1, TlsTreeParams::MAGMA_MGM_S),
                   "a mask of all ones must re-key every record");
        // And the others do not, at that distance.
        assert_eq!(super::tlstree(&root, 0, TlsTreeParams::KUZNYECHIK_MGM_L),
                   super::tlstree(&root, 1, TlsTreeParams::KUZNYECHIK_MGM_L));
    }
}
