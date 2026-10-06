/*
The CTR_OMAC record protection from RFC 9189 section 4.1.1.

Two TLS 1.2 cipher suites use it:

  * `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`, 16 byte block,
     16 byte MAC, 4 KB ACPKM sections, 8 byte IV;
  * `TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`, 8 byte block, 8 byte MAC,
     1 KB ACPKM sections, 4 byte IV.

It is authenticate-then-encrypt over a stream cipher, which is the same
shape as `StreamHmac` and *not* the same as anything else here - the
CBC suites' construction is a different animal and its hazards do not
apply. RFC 7366 says a server choosing these suites must not negotiate
encrypt-then-MAC, precisely because the order is load bearing.

What is unusual, and the whole reason for a separate module:

## Every record has its own keys

The connection key material (`sender_write_key`, `sender_write_MAC_key`,
`sender_write_IV`) is not what protects a record. Both keys go through
TLSTREE at the record's sequence number first:

    K_ENC_n  = TLSTREE(sender_write_key,     n)
    K_MAC_n  = TLSTREE(sender_write_MAC_key, n)
    IV_n     = STR_{n/2}((INT(sender_write_IV) + n) mod 2^((n/2)*8))

The two trees have different roots and the same constants, so they move
at the same sequence numbers - which is why `TlsTree` caches and why
both trees are asked for a key on every record rather than one being
derived from the other.

The IV is **added to**, not XORed with, and it wraps in its own width -
four bytes for Magma, eight for Kuznyechik. A 64 bit add of the sequence
number into a 32 bit IV agrees with itself for the first four billion
records.

## The counter mode re-keys underneath as well

`ENC` is CTR-ACPKM (RFC 8645), so within one record the key changes
every section - 1 KB for Magma, 4 KB for Kuznyechik, both smaller than
the 16 KB a record may carry. Two layers of re-keying that know nothing
about each other: TLSTREE between records, ACPKM inside one.

Each record starts a fresh CTR-ACPKM stream, because its key and IV are
fresh. That is the opposite of `StreamHmac`, where the keystream runs
for the whole connection, and getting the two the wrong way round is
invisible on the first record of any connection.

## The MAC is OMAC, which is CMAC

RFC 9189 calls it OMAC, GOST R 34.13-2015 defines it, and it is CMAC
with Kuznyechik or Magma underneath. The tag is the *whole block*, so it
is 16 bytes for one suite and 8 for the other - not truncated to a
common length. Its input is the ordinary TLS 1.2 MAC input from RFC 5246
section 6.2.3.1: `seq || type || version || length || fragment`.

## SNMAX

Magma's sequence number may not exceed 2^32 - 1 (RFC 9189 section
4.3.5), a much lower ceiling than the record layer's own 2^64 wrap
check, and the reason is the 4 byte IV: past that the IV repeats while
the key does not change until the next TLSTREE boundary, which is a
repeated (key, counter) pair. The ceiling is enforced here rather than
left to the generic counter.
*/

use crate::block_ciphers::acpkm::CtrAcpkm;
use crate::kdf::gost::{TlsTree, TlsTreeParams};
use crate::mac::cmac::Cmac;
use crate::tls::record::{RecordError, SequenceNumber};
use crate::tls::{AlertDescription, ContentType, Version};
use crate::Mac;

/// Everything that differs between the two CTR_OMAC suites.
///
/// Gathered into one value because picking these individually is how a
/// suite ends up with Magma's section size under Kuznyechik: each is
/// separately plausible and the combination is what has to be right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtrOmacSuite {
    pub cipher: &'static str,
    /// The block size, which is also the MAC length.
    pub block: usize,
    /// The CTR-ACPKM section size in bytes.
    pub section: usize,
    pub tree: TlsTreeParams,
    /// The largest sequence number this suite may use (RFC 9189 4.3.5).
    pub snmax: u64,
}

impl CtrOmacSuite {
    pub const KUZNYECHIK: CtrOmacSuite = CtrOmacSuite {
        cipher: "kuznyechik",
        block: 16,
        section: 4 * 1024,
        tree: TlsTreeParams::KUZNYECHIK,
        snmax: u64::MAX,
    };

    pub const MAGMA: CtrOmacSuite = CtrOmacSuite {
        cipher: "magma",
        block: 8,
        section: 1024,
        tree: TlsTreeParams::MAGMA,
        snmax: 0xFFFF_FFFF,
    };

    /// The IV's width: half a block, because the other half is the
    /// CTR-ACPKM counter.
    pub const fn iv_len(&self) -> usize {
        self.block / 2
    }
}

/// What one record is protected with: the three values RFC 9189
/// section 4.3.5 derives per record, all of which change every time.
///
/// `Debug` is hand written and prints no key material, like
/// `CtrOmac`'s: these are the live per-record keys, and a derived
/// `Debug` would put them in any `unwrap` message or `assert` failure.
struct RecordKeys {
    /// `sender_write_key` at this sequence number.
    enc: Vec<u8>,
    /// `sender_write_MAC_key` at this sequence number.
    mac: Vec<u8>,
    /// `IV_seqnum`, the write IV plus the sequence number in the IV's
    /// own width.
    iv: Vec<u8>,
}

impl core::fmt::Debug for RecordKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RecordKeys {{ keys redacted, iv {} bytes }}", self.iv.len())
    }
}

/// One direction's CTR_OMAC keys.
pub struct CtrOmac {
    suite: CtrOmacSuite,
    /// `sender_write_key` and `sender_write_MAC_key`, each behind its own
    /// TLSTREE cache. Two trees rather than one because they have
    /// different roots; they move at the same sequence numbers, so in
    /// practice both recompute together.
    enc: TlsTree,
    mac: TlsTree,
    /// `sender_write_IV`, as an integer in the suite's IV width.
    iv: u64,
}

impl core::fmt::Debug for CtrOmac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CtrOmac {{ {}, keys redacted }}", self.suite.cipher)
    }
}

impl CtrOmac {
    pub fn new(suite: CtrOmacSuite, key: &[u8], mac_key: &[u8], iv: &[u8])
               -> Result<CtrOmac, String> {
        if key.len() != 32 || mac_key.len() != 32 {
            return Err(format!(
                "CTR_OMAC takes 32 byte keys; got {} for encryption and {} \
                 for the MAC.", key.len(), mac_key.len()));
        }
        if iv.len() != suite.iv_len() {
            return Err(format!(
                "{}'s IV is {} bytes, half its block; got {}.",
                suite.cipher, suite.iv_len(), iv.len()));
        }
        // Held as an integer because the sequence number is *added* to
        // it, and the addition wraps in the IV's own width rather than
        // in 64 bits.
        let mut value = 0u64;
        for byte in iv {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(CtrOmac { suite, enc: TlsTree::new(key, suite.tree),
                     mac: TlsTree::new(mac_key, suite.tree), iv: value })
    }

    pub fn name(&self) -> String {
        format!("{}-ctr-omac", self.suite.cipher)
    }

    pub fn suite(&self) -> CtrOmacSuite {
        self.suite
    }

    pub fn tag_len(&self) -> usize {
        self.suite.block
    }

    /// `IV_seqnum = STR_{n/2}((INT(sender_write_IV) + seqnum) mod 2^((n/2)*8))`.
    ///
    /// The modulus is the IV's width, not 64 bits. For Magma that is
    /// 2^32, and a 64 bit add is indistinguishable from this one until
    /// the four billionth record - which is past SNMAX, so the
    /// difference is only ever reached by an implementation that also
    /// ignored the ceiling.
    fn iv_for(&self, sequence: u64) -> Vec<u8> {
        let width = self.suite.iv_len();
        let sum = self.iv.wrapping_add(sequence);
        let masked = if width == 8 { sum } else { sum & ((1u64 << (width * 8)) - 1) };
        masked.to_be_bytes()[8 - width..].to_vec()
    }

    /// The record's three derived values, in the order the RFC lists
    /// them. Taken together because a caller that derived one and
    /// forgot another would produce a record only it can read.
    ///
    /// Named fields rather than a tuple: the encryption key and the MAC
    /// key are both 32 byte `Vec<u8>` and adjacent, so a tuple lets them
    /// be swapped at a call site with nothing to notice it - a record
    /// that encrypts under the MAC key and authenticates under the
    /// encryption key is entirely self-consistent, and only a peer would
    /// ever find out.
    fn record_keys(&mut self, sequence: u64) -> Result<RecordKeys, String> {
        if sequence > self.suite.snmax {
            return Err(format!(
                "{}'s sequence number may not exceed {} (RFC 9189 section \
                 4.3.5); this record is number {}. Past it the {} byte IV \
                 repeats under an unchanged key.",
                self.suite.cipher, self.suite.snmax, sequence,
                self.suite.iv_len()));
        }
        Ok(RecordKeys {
            enc: self.enc.key(sequence),
            mac: self.mac.key(sequence),
            iv: self.iv_for(sequence),
        })
    }

    /// The RFC 5246 section 6.2.3.1 MAC input, under OMAC with the
    /// record's own MAC key.
    fn mac_value(&self, key: &[u8], sequence: SequenceNumber,
                 content_type: ContentType, version: Version, fragment: &[u8])
                 -> Result<Vec<u8>, String> {
        let mut mac = Cmac::with_key(self.suite.cipher, key)?;
        mac.update(&sequence.to_bytes());
        mac.update(&[content_type.to_byte()]);
        mac.update(&version.to_bytes());
        mac.update(&(fragment.len() as u16).to_be_bytes());
        mac.update(fragment);
        Ok(mac.digest())
    }
}

/// Protect one record: `ENC(K_ENC_n, IV_n, fragment || OMAC(K_MAC_n, ...))`.
pub fn encrypt(state: &mut CtrOmac, sequence: SequenceNumber,
               content_type: ContentType, version: Version, plaintext: &[u8])
               -> Result<Vec<u8>, RecordError> {
    let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);

    let RecordKeys { enc: enc_key, mac: mac_key, iv } = state.record_keys(sequence.value())
        .map_err(internal)?;
    let tag = state.mac_value(&mac_key, sequence, content_type, version, plaintext)
        .map_err(internal)?;

    let mut out = Vec::with_capacity(plaintext.len() + tag.len());
    out.extend_from_slice(plaintext);
    out.extend_from_slice(&tag);

    // A fresh stream per record: the key and IV are the record's, so
    // continuing a previous one would be using the wrong key.
    CtrAcpkm::new(state.suite.cipher, &enc_key, &iv, state.suite.section)
        .map_err(internal)?
        .apply(&mut out).map_err(internal)?;
    Ok(out)
}

/// Unprotect one record: decrypt, then check the MAC over what came out.
///
/// The order is forced - the MAC is inside the ciphertext, so there is
/// nothing to check before decrypting. That is authenticate-then-encrypt
/// and it is why this construction is safe here and would not be under
/// CBC: a stream cipher's decryption cannot fail, has no padding, and
/// reveals nothing by its timing.
pub fn decrypt(state: &mut CtrOmac, sequence: SequenceNumber,
               content_type: ContentType, version: Version, fragment: &[u8])
               -> Result<Vec<u8>, RecordError> {
    let bad = || RecordError::new(
        AlertDescription::BAD_RECORD_MAC,
        "The record did not authenticate. It was altered in transit, or the \
         keys do not match.".to_string());
    let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);

    let RecordKeys { enc: enc_key, mac: mac_key, iv } = state.record_keys(sequence.value())
        .map_err(internal)?;
    if fragment.len() < state.suite.block {
        // Shorter than the MAC it must carry. Reported as a MAC failure
        // like every other rejection, because a length is something an
        // attacker chooses and a distinct error is a bit of oracle.
        return Err(bad());
    }

    let mut plain = fragment.to_vec();
    CtrAcpkm::new(state.suite.cipher, &enc_key, &iv, state.suite.section)
        .map_err(internal)?
        .apply(&mut plain).map_err(internal)?;

    let split = plain.len() - state.suite.block;
    let tag = plain.split_off(split);
    let want = state.mac_value(&mac_key, sequence, content_type, version, &plain)
        .map_err(internal)?;
    // Constant time over the whole MAC, as everywhere else here.
    let mut difference = 0u8;
    for (a, b) in tag.iter().zip(want.iter()) {
        difference |= a ^ b;
    }
    if difference != 0 || tag.len() != want.len() {
        return Err(bad());
    }
    Ok(plain)
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

    const MAC_KEY: &str = "00112233445566778899AABBCCEEFF0A\
                           1122334455667788 99AABBCCEEFF0A00";
    const ENC_KEY: &str = "22334455667788 99AABBCCEEFF0A0011\
                           33445566778899AABBCCEEFF0A001122";

    /// RFC 9189 Appendix A.1.2.1, sequence 0: the one example printed in
    /// full, so it pins the MAC input's framing, the IV, and the order
    /// of MAC and encryption all at once.
    #[test]
    fn test_rfc_9189_magma_record_zero() {
        let mut state = CtrOmac::new(CtrOmacSuite::MAGMA, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0, 0, 0, 0]).unwrap();
        let plaintext = [0u8; 7];

        // The record keys the RFC prints beside the example.
        let RecordKeys { enc: enc_key, mac: mac_key, iv } = state.record_keys(0).unwrap();
        assert_eq!(hex(&mac_key), "19a76ed30f4d6d1f5b7263ec491ad838\
                                   17c0b57d8a035612714 0fb4f7425494d"
                                  .replace(' ', ""));
        assert_eq!(hex(&enc_key), "58afbe9a4c3198aaabaa2692c419f179\
                                   7c9b92deb3cc7446b36357711 3f0fb56"
                                  .replace(' ', ""));
        assert_eq!(hex(&iv), "00000000");

        // And the MAC over `seq || type || version || length || fragment`.
        let tag = state.mac_value(&mac_key, SequenceNumber::at(0),
                                  ContentType::ApplicationData, Version::TLS12,
                                  &plaintext).unwrap();
        assert_eq!(hex(&tag), "f33eb6896fece286");

        let out = encrypt(&mut state, SequenceNumber::at(0),
                          ContentType::ApplicationData, Version::TLS12,
                          &plaintext).unwrap();
        assert_eq!(hex(&out), "9b420da86faf367f051443ce9c1072");
    }

    /// RFC 9189 Appendix A.1.2.1 at sequence 4095 and 4096: 1024 and 2048
    /// byte records of zeros, either side of Magma's third-level TLSTREE
    /// boundary.
    ///
    /// The RFC elides the middle of both ciphertexts, so this checks the
    /// printed head and tail. That is enough to catch what the elision
    /// could hide: a wrong ACPKM section size changes the stream from
    /// byte 1024 onward, which is inside the *tail* of both records.
    #[test]
    fn test_rfc_9189_magma_record_across_a_boundary() {
        let mut state = CtrOmac::new(CtrOmacSuite::MAGMA, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0, 0, 0, 0]).unwrap();

        // 4095: 1024 bytes of zeros. Still the same keys as record 0,
        // and the IV has moved.
        let out = encrypt(&mut state, SequenceNumber::at(4095),
                          ContentType::ApplicationData, Version::TLS12,
                          &[0u8; 0x400]).unwrap();
        assert_eq!(out.len(), 0x408);
        // The RFC prints TLSCiphertext *including* the five byte header,
        // so its offsets are five ahead of the fragment's. These are the
        // first and last rows it prints, translated.
        assert_eq!(hex(&out[..0x2b]),
                   "b711438b16201f3c49339521c9c8ca7566d4c20fd33e581f8007dc\
                    76043e2b35c8e84bb2550827661359 6f".replace(' ', ""));
        assert_eq!(hex(&out[0x3cb..]),
                   "e77770bf4517e1f8dd1b2c0564ad68fc\
                    4a889a48b8b1ff0ea4e1bb704d56a475\
                    2f51a582cc541a808f8c8b62976888c8\
                    1059de412763a3e0999acdda77");
        // The MAC the RFC prints, which is the last 8 bytes before
        // encryption - visible here only because decryption recovers it.
        let RecordKeys { mac: mac_key, .. } = state.record_keys(4095).unwrap();
        assert_eq!(hex(&state.mac_value(&mac_key, SequenceNumber::at(4095),
                                        ContentType::ApplicationData,
                                        Version::TLS12, &[0u8; 0x400]).unwrap()),
                   "58d3bb608fbc98b8");

        // 4096 crosses the boundary, so both record keys change.
        let RecordKeys { enc: enc_key, mac: mac_key, iv } = state.record_keys(4096).unwrap();
        assert_eq!(hex(&mac_key), "fb30ee53cfcf89d748fc0c72ef160b8b\
                                   53cbbbfd031282b026214ab2e07758ff");
        assert_eq!(hex(&enc_key), "edf2fd024771602383 09002d1d57df9f\
                                   d2ed18d64566c76f4bf03d3abf7bbb1e"
                                  .replace(' ', ""));
        assert_eq!(hex(&iv), "00001000");

        let out = encrypt(&mut state, SequenceNumber::at(4096),
                          ContentType::ApplicationData, Version::TLS12,
                          &[0u8; 0x800]).unwrap();
        assert_eq!(out.len(), 0x808);
        assert_eq!(hex(&out[..0x2b]),
                   "999526070347 1deda2e655b6b393835e338b1ed00edd2247a2fb88\
                    fbb7a8948062088af32caeb6aa2c4f2a".replace(' ', ""));
        assert_eq!(hex(&out[0x7cb..]),
                   "7f0b2461e75fe10634b84dc57035725a\
                    ca4f0cbca9b06cb9f76fbd2f80462b8d\
                    775ebd416f634139ac89c2ed3df19fe2\
                    4ef8c05aa890931b0186fd7ddf");
    }

    /// RFC 9189 Appendix A.1.2.2, the Kuznyechik suite: different block,
    /// different MAC length, different section size, different tree
    /// constants. Nothing is shared with the Magma example except the
    /// shape.
    #[test]
    fn test_rfc_9189_kuznyechik_record_zero() {
        let mut state = CtrOmac::new(CtrOmacSuite::KUZNYECHIK, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0u8; 8]).unwrap();
        let plaintext = [0u8; 15];

        let RecordKeys { enc: enc_key, mac: mac_key, iv } = state.record_keys(0).unwrap();
        assert_eq!(hex(&iv), "0000000000000000");
        // Sequence 0 masks to zero under either suite's constants, so
        // these match the Magma example's - which is worth asserting
        // rather than assuming, because it is why the record bytes
        // below still differ.
        assert_eq!(hex(&mac_key), "19a76ed30f4d6d1f5b7263ec491ad838\
                                   17c0b57d8a0356127140fb4f7425494d");
        assert_eq!(hex(&enc_key), "58afbe9a4c3198aaabaa2692c419f179\
                                   7c9b92deb3cc7446b363577113f0fb56");

        let tag = state.mac_value(&mac_key, SequenceNumber::at(0),
                                  ContentType::ApplicationData, Version::TLS12,
                                  &plaintext).unwrap();
        assert_eq!(tag.len(), 16, "the OMAC tag is a whole block, not truncated");
        assert_eq!(hex(&tag), "fd1719dd950837eb7c7bb8f500379981");

        let out = encrypt(&mut state, SequenceNumber::at(0),
                          ContentType::ApplicationData, Version::TLS12,
                          &plaintext).unwrap();
        assert_eq!(hex(&out), "4d1a305236573bffc14e46dcbe746db6\
                               c99a175a81c4711e2f84c392c5407c");
    }

    /// RFC 9189 Appendix A.1.2.2 at sequence 63 and 64, either side of
    /// Kuznyechik's third-level boundary - which falls in a different
    /// place from Magma's, and on records of 4 KB and 8 KB rather than
    /// 1 KB and 2 KB.
    ///
    /// 4096 bytes is exactly one ACPKM section here, so the first record
    /// re-keys once at its very end (inside the MAC) and the second
    /// re-keys twice. A section size taken from the other suite changes
    /// the stream from byte 1024, which the printed head would catch.
    #[test]
    fn test_rfc_9189_kuznyechik_record_across_a_boundary() {
        let mut state = CtrOmac::new(CtrOmacSuite::KUZNYECHIK, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0u8; 8]).unwrap();

        let RecordKeys { mac: mac_key, iv, .. } = state.record_keys(63).unwrap();
        assert_eq!(hex(&iv), "000000000000003f");
        assert_eq!(hex(&state.mac_value(&mac_key, SequenceNumber::at(63),
                                        ContentType::ApplicationData,
                                        Version::TLS12, &[0u8; 0x1000]).unwrap()),
                   "98462761d026244a2c0b7d1bcccbe7b0");

        let out = encrypt(&mut state, SequenceNumber::at(63),
                          ContentType::ApplicationData, Version::TLS12,
                          &[0u8; 0x1000]).unwrap();
        assert_eq!(out.len(), 0x1010);
        // As above: the RFC's offsets include the five byte header.
        assert_eq!(hex(&out[..0x2b]),
                   "129351d26e140713a21b376824a22317cdc0d88e01cfa3fe21415f\
                    5c5e05869ccf38a51bc2e0ed689446a8".replace(' ', ""));
        assert_eq!(hex(&out[0xfdb..]),
                   "19ad998c062521e67b6359a4f5c816f9\
                    476ba7132682bba8ce0bedad65e420a2\
                    97b6e2c61fa406d9b8ca36fd9fcd3aee\
                    2478f4d196");

        // 64 crosses the third-level boundary: both record keys move.
        let RecordKeys { enc: enc_key, mac: mac_key, iv } = state.record_keys(64).unwrap();
        assert_eq!(hex(&mac_key), "aebe1ef418713bf044b9fcd9e572d437\
                                   fb38b5d829567a6f7918396d9f4e096b");
        assert_eq!(hex(&enc_key), "64f55afc37a174d9533e708bcd14fa4a\
                                   eec37bc0e32ba49901b4669e96a63d96");
        assert_eq!(hex(&iv), "0000000000000040");

        let out = encrypt(&mut state, SequenceNumber::at(64),
                          ContentType::ApplicationData, Version::TLS12,
                          &[0u8; 0x2000]).unwrap();
        assert_eq!(out.len(), 0x2010);
        assert_eq!(hex(&out[..0x2b]),
                   "e666bb98ac5b0f3931d8551b93368596eef0eba8269cb8bdaae7eb\
                    80c830d75ab7d46c2506dc8b83e1f2d3".replace(' ', ""));
        assert_eq!(hex(&out[0x1fdb..]),
                   "b302672ccb0286cd4048fbd5381a6555\
                    261125510 14fa8edf5c21b7d1db39d6b\
                    adec0d7c0705348b5c556c4d5081691a\
                    a9ec36f8b5".replace(' ', ""));
    }

    /// A round trip, at sequence numbers that cross boundaries, over
    /// lengths that cross ACPKM section boundaries.
    ///
    /// This proves much less than the vectors above - a wrong
    /// implementation round-trips perfectly against itself - so it is
    /// here for the lengths and the ordering, not for the arithmetic.
    #[test]
    fn test_a_round_trip_across_both_kinds_of_boundary() {
        for suite in [CtrOmacSuite::MAGMA, CtrOmacSuite::KUZNYECHIK] {
            for &sequence in &[0u64, 1, 63, 64, 4095, 4096, 524_288] {
                for &len in &[0usize, 1, 7, 1023, 1024, 1025, 4095, 4096, 4097] {
                    let plaintext: Vec<u8> =
                        (0..len).map(|i| (i % 251) as u8).collect();
                    let mut out = CtrOmac::new(suite, &unhex(ENC_KEY),
                                               &unhex(MAC_KEY),
                                               &vec![7u8; suite.iv_len()]).unwrap();
                    let mut back = CtrOmac::new(suite, &unhex(ENC_KEY),
                                                &unhex(MAC_KEY),
                                                &vec![7u8; suite.iv_len()]).unwrap();
                    let wire = encrypt(&mut out, SequenceNumber::at(sequence),
                                       ContentType::ApplicationData,
                                       Version::TLS12, &plaintext).unwrap();
                    assert_eq!(wire.len(), len + suite.block);
                    let got = decrypt(&mut back, SequenceNumber::at(sequence),
                                      ContentType::ApplicationData,
                                      Version::TLS12, &wire).unwrap();
                    assert_eq!(got, plaintext, "{} at {} len {}",
                               suite.cipher, sequence, len);
                }
            }
        }
    }

    /// The MAC covers the sequence number, the type, the version and the
    /// length, so changing any of them must fail - and the *sequence
    /// number* additionally changes the keys, which is the one a replay
    /// would move.
    #[test]
    fn test_every_field_the_mac_covers_is_checked() {
        let mut state = CtrOmac::new(CtrOmacSuite::MAGMA, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0, 0, 0, 1]).unwrap();
        let wire = encrypt(&mut state, SequenceNumber::at(9),
                           ContentType::ApplicationData, Version::TLS12,
                           b"hello").unwrap();

        let fresh = || CtrOmac::new(CtrOmacSuite::MAGMA, &unhex(ENC_KEY),
                                        &unhex(MAC_KEY), &[0, 0, 0, 1]).unwrap();
        assert!(decrypt(&mut fresh(), SequenceNumber::at(10),
                        ContentType::ApplicationData, Version::TLS12,
                        &wire).is_err(), "a replayed record was accepted");
        assert!(decrypt(&mut fresh(), SequenceNumber::at(9),
                        ContentType::Handshake, Version::TLS12,
                        &wire).is_err(), "a retyped record was accepted");
        assert!(decrypt(&mut fresh(), SequenceNumber::at(9),
                        ContentType::ApplicationData, Version::TLS11,
                        &wire).is_err(), "a re-versioned record was accepted");

        for bit in 0..wire.len() * 8 {
            let mut altered = wire.clone();
            altered[bit / 8] ^= 1 << (bit % 8);
            assert!(decrypt(&mut fresh(), SequenceNumber::at(9),
                            ContentType::ApplicationData, Version::TLS12,
                            &altered).is_err(),
                    "bit {} could be flipped undetected", bit);
        }
    }

    /// The two suites' parameters are not interchangeable, and at
    /// sequence 0 the tree constants agree - so only the block, the MAC
    /// length and the section size distinguish them there.
    #[test]
    fn test_the_suites_produce_different_records() {
        let mut magma = CtrOmac::new(CtrOmacSuite::MAGMA, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0; 4]).unwrap();
        let mut kuz = CtrOmac::new(CtrOmacSuite::KUZNYECHIK, &unhex(ENC_KEY),
                                   &unhex(MAC_KEY), &[0; 8]).unwrap();
        let one = encrypt(&mut magma, SequenceNumber::at(0),
                          ContentType::ApplicationData, Version::TLS12,
                          b"same input").unwrap();
        let two = encrypt(&mut kuz, SequenceNumber::at(0),
                          ContentType::ApplicationData, Version::TLS12,
                          b"same input").unwrap();
        assert_ne!(one, two);
        assert_eq!(one.len() + 8, two.len(), "the MAC lengths differ by a block");
    }

    /// The IV is added to in its own width. Magma's is four bytes, so
    /// the sum wraps at 2^32 - and a 64 bit add would not.
    #[test]
    fn test_the_iv_wraps_in_its_own_width() {
        let state = CtrOmac::new(CtrOmacSuite::MAGMA, &unhex(ENC_KEY),
                                 &unhex(MAC_KEY), &[0xff, 0xff, 0xff, 0xff])
                    .unwrap();
        assert_eq!(hex(&state.iv_for(0)), "ffffffff");
        assert_eq!(hex(&state.iv_for(1)), "00000000");
        assert_eq!(hex(&state.iv_for(0x101)), "00000100");

        let state = CtrOmac::new(CtrOmacSuite::KUZNYECHIK, &unhex(ENC_KEY),
                                 &unhex(MAC_KEY), &[0xff; 8]).unwrap();
        assert_eq!(hex(&state.iv_for(1)), "0000000000000000");
    }

    /// Magma's ceiling is 2^32 - 1, and it is a refusal rather than a
    /// wrap. Past it the four byte IV repeats under keys that have not
    /// changed, which is a reused keystream.
    #[test]
    fn test_magma_refuses_past_snmax() {
        let mut state = CtrOmac::new(CtrOmacSuite::MAGMA, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0; 4]).unwrap();
        assert!(state.record_keys(0xFFFF_FFFF).is_ok());
        let refused = state.record_keys(0x1_0000_0000).unwrap_err();
        assert!(refused.contains("4.3.5"), "{}", refused);

        // Kuznyechik's IV is eight bytes and its ceiling is the counter's
        // own, so the same sequence number is fine there.
        let mut state = CtrOmac::new(CtrOmacSuite::KUZNYECHIK, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0; 8]).unwrap();
        assert!(state.record_keys(0x1_0000_0000).is_ok());
    }

    /// Each record starts a fresh keystream, unlike RC4 where it runs
    /// for the connection. Two records with the same plaintext at the
    /// same sequence number must be identical; at different sequence
    /// numbers they must differ, and by more than the MAC.
    #[test]
    fn test_the_keystream_is_per_record_not_per_connection() {
        let mut state = CtrOmac::new(CtrOmacSuite::MAGMA, &unhex(ENC_KEY),
                                     &unhex(MAC_KEY), &[0; 4]).unwrap();
        let first = encrypt(&mut state, SequenceNumber::at(5),
                            ContentType::ApplicationData, Version::TLS12,
                            b"repeated").unwrap();
        // The same record again through the *same* state: a connection
        // keystream would have advanced and given different bytes.
        let again = encrypt(&mut state, SequenceNumber::at(5),
                            ContentType::ApplicationData, Version::TLS12,
                            b"repeated").unwrap();
        assert_eq!(first, again);

        let later = encrypt(&mut state, SequenceNumber::at(6),
                            ContentType::ApplicationData, Version::TLS12,
                            b"repeated").unwrap();
        assert_ne!(first[..8], later[..8],
                   "a different sequence number must give a different keystream");
    }
}
