/*
RFC 9367's record protection: MGM under TLS 1.3, with external re-keying.

The four suites 0xC103..0xC106 use RFC 8446's record layer unchanged in
everything that shows on the wire - the header still lies about the
content type, the padding is still zeros scanned back from the end, the
additional data is still the five byte header - and change three things
that do not show at all.

## The key is not the traffic key

RFC 8446 derives one `sender_write_key` per epoch and varies only the
nonce. RFC 9367 section 4.1 derives a **fresh key for every record**:

    sender_record_write_key = TLSTREE(sender_write_key, seqnum)

which is three chained `KDF_GOSTR3411_2012_256` steps over the sequence
number masked three ways. The masks are the suite's - RFC 9367 section
4.1.2 - and they are nested, so the first two levels change rarely and
the third often. `kdf::gost::TlsTree` caches the first two for that
reason; here it is the plain function, because a record layer that
cached wrongly would be a bug found only at a boundary.

**Every mask is all ones at sequence number 0**, so a suite using
another suite's constants agrees on the first record of a connection and
diverges later. That is why `kdf::gost::document_tests` reads all six
sets back out of the two RFCs rather than trusting the transcription.

## The static IV is `n` bytes, not twelve

RFC 8446 section 7.3 expands `"iv"` to the AEAD's nonce length, and every
AEAD that document names takes twelve - so twelve became a constant.
RFC 9367 section 4.1.1 sets `IVlen = n`: sixteen bytes for Kuznyechik,
**eight** for Magma. The length is part of HKDF-Expand-Label's input, so
getting it wrong does not produce a length error at the first record -
it produces a different static IV, and a peer that disagrees about every
nonce.

The nonce itself is RFC 8446 section 5.3 unchanged: the sequence number,
big endian, left-padded to the IV's width, XORed with the IV.

## The nonce's top bit is cleared, and that is not cosmetic

    MGMnonce = STR_1(nonce[1] & 0x7f) | nonce[2..IVlen]

MGM's initial counter nonce is `n-1` bits. The missing bit is the domain
separator between its two counter chains: `0 || ICN` starts the
keystream's and `1 || ICN` starts the authentication's. So the masking
belongs here, one layer above MGM, and `block_ciphers::mgm` **refuses** a
nonce with that bit set rather than masking it quietly - because an
implementation that masked silently would turn two nonces differing only
there into one nonce, and a repeated nonce is the one thing RFC 9058
section 6 says destroys the mode entirely.

Here the two nonces cannot collide anyway: the bit being cleared is the
top bit of the *IV*, which is constant for the epoch, and the sequence
number does not reach it. The sequence number is eight bytes XORed into
the low end of the IV: for Kuznyechik's 16 byte IV it never touches
byte 0 at all, and for Magma's 8 byte IV it is the sequence number's own
bit 63, reached at 2^63 records - which the `_S` suites' SNMAX rules out
and the `_L` suites' 2^64-1 nominally allows, so for Magma the clearing
is a real masking at a count no connection reaches rather than a
no-op. Said out loud because the argument is about this layer, not about
MGM, and MGM must not rely on it.

## SNMAX

RFC 9367 section 4.1.3 caps how many records one traffic key may
protect, and the cap is per suite: 2^64-1 for the `_L` suites, but
**2^42-1 and 2^39-1** for the `_S` ones. A sender past it must re-key
rather than wrap, and this layer refuses rather than continuing - the
same decision `CtrOmac` makes at Magma's 2^32-1.
*/

use crate::kdf::gost::TlsTreeParams;

/// One RFC 9367 suite's record parameters, as one value.
///
/// Chosen individually, a suite ends up with the `_S` schedule under the
/// `_L` cipher - each choice separately plausible, the pair wrong and
/// silent until the first re-keying boundary. Same argument as
/// `CtrOmacSuite`, which this deliberately mirrors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MgmSuite {
    /// The AEAD name in `api::AEADS`, which carries the block cipher.
    pub aead: &'static str,
    /// The cipher's block, which is the tag length, the nonce length and
    /// the IV length all at once (RFC 9367 4.1.1: `S = n`, `IVlen = n`).
    pub block: usize,
    /// The three TLSTREE masks, RFC 9367 section 4.1.2.
    pub tree: TlsTreeParams,
    /// The largest sequence number this suite may protect a record with,
    /// RFC 9367 section 4.1.3.
    pub snmax: u64,
}

impl MgmSuite {
    /// `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L` (0xC103).
    pub const KUZNYECHIK_L: MgmSuite = MgmSuite {
        aead: "kuznyechik-mgm",
        block: 16,
        tree: TlsTreeParams::KUZNYECHIK_MGM_L,
        snmax: u64::MAX,
    };

    /// `TLS_GOSTR341112_256_WITH_MAGMA_MGM_L` (0xC104).
    pub const MAGMA_L: MgmSuite = MgmSuite {
        aead: "magma-mgm",
        block: 8,
        tree: TlsTreeParams::MAGMA_MGM_L,
        snmax: u64::MAX,
    };

    /// `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S` (0xC105).
    ///
    /// `2^42 - 1` records, where the `_L` suite allows `2^64 - 1`. The
    /// `_S` suites trade reach for a much shorter re-keying period.
    pub const KUZNYECHIK_S: MgmSuite = MgmSuite {
        aead: "kuznyechik-mgm",
        block: 16,
        tree: TlsTreeParams::KUZNYECHIK_MGM_S,
        snmax: (1u64 << 42) - 1,
    };

    /// `TLS_GOSTR341112_256_WITH_MAGMA_MGM_S` (0xC106).
    pub const MAGMA_S: MgmSuite = MgmSuite {
        aead: "magma-mgm",
        block: 8,
        tree: TlsTreeParams::MAGMA_MGM_S,
        snmax: (1u64 << 39) - 1,
    };

    /// The key for one record: `TLSTREE(sender_write_key, seqnum)`.
    pub fn record_key(&self, write_key: &[u8], sequence: u64) -> Vec<u8> {
        crate::kdf::gost::tlstree(write_key, sequence, self.tree)
    }

    /// The nonce MGM is given: RFC 8446's, with the top bit cleared.
    ///
    /// Takes the already-XORed nonce rather than the IV and the
    /// sequence number, so there is exactly one place that knows how a
    /// TLS 1.3 nonce is built and this is not a second one.
    pub fn mask_nonce(nonce: &mut [u8]) {
        if let Some(first) = nonce.first_mut() {
            *first &= 0x7f;
        }
    }

    /// Whether a record at this sequence number may still be sent.
    pub fn within_snmax(&self, sequence: u64) -> bool {
        sequence <= self.snmax
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four suites are four different things, in every field that
    /// can differ.
    ///
    /// A copied constant is the mistake here, and it is silent: two
    /// suites sharing a schedule interoperate with each other perfectly
    /// and with a real peer not at all.
    #[test]
    fn test_the_four_suites_are_distinct() {
        let all = [MgmSuite::KUZNYECHIK_L, MgmSuite::KUZNYECHIK_S,
                   MgmSuite::MAGMA_L, MgmSuite::MAGMA_S];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.tree, b.tree, "two suites share a schedule");
                assert_ne!(a, b);
            }
        }
        // The `_L` and `_S` forms of one cipher share everything but the
        // schedule and the cap, which is the pair most easily confused.
        assert_eq!(MgmSuite::KUZNYECHIK_L.aead, MgmSuite::KUZNYECHIK_S.aead);
        assert_eq!(MgmSuite::KUZNYECHIK_L.block, MgmSuite::KUZNYECHIK_S.block);
        assert_ne!(MgmSuite::KUZNYECHIK_L.snmax, MgmSuite::KUZNYECHIK_S.snmax);
    }

    /// The block is the tag, the nonce and the IV at once.
    #[test]
    fn test_the_block_is_the_aeads_own() {
        for suite in [MgmSuite::KUZNYECHIK_L, MgmSuite::KUZNYECHIK_S,
                      MgmSuite::MAGMA_L, MgmSuite::MAGMA_S] {
            let expected = if suite.aead.starts_with("magma") { 8 } else { 16 };
            assert_eq!(suite.block, expected, "{}", suite.aead);
            // And the AEAD agrees, asked rather than assumed.
            let tag = crate::api::aead_tag_len(suite.aead, &[0u8; 32]).unwrap();
            assert_eq!(tag, suite.block, "{}", suite.aead);
        }
    }

    /// The record key changes with the sequence number, and changes at
    /// the suite's own boundaries rather than at some other suite's.
    #[test]
    fn test_the_record_key_follows_this_suites_schedule() {
        let root = [0x5au8; 32];
        // The `_S` Magma suite re-keys on every record; the `_L`
        // Kuznyechik one does not re-key for 8192.
        let s = MgmSuite::MAGMA_S;
        assert_ne!(s.record_key(&root, 0), s.record_key(&root, 1));

        let l = MgmSuite::KUZNYECHIK_L;
        assert_eq!(l.record_key(&root, 0), l.record_key(&root, 1));
        assert_eq!(l.record_key(&root, 0), l.record_key(&root, 8191));
        assert_ne!(l.record_key(&root, 0), l.record_key(&root, 8192));

        // And a record key is not the root, which a cache initialised to
        // "already derived" would hand back.
        assert_ne!(l.record_key(&root, 0).as_slice(), &root[..]);
    }

    /// The caps are the document's, and the `_S` ones are reachable.
    #[test]
    fn test_snmax() {
        assert!(MgmSuite::KUZNYECHIK_L.within_snmax(u64::MAX));
        assert!(MgmSuite::MAGMA_L.within_snmax(u64::MAX));

        assert!(MgmSuite::KUZNYECHIK_S.within_snmax((1 << 42) - 1));
        assert!(!MgmSuite::KUZNYECHIK_S.within_snmax(1 << 42));
        assert!(MgmSuite::MAGMA_S.within_snmax((1 << 39) - 1));
        assert!(!MgmSuite::MAGMA_S.within_snmax(1 << 39));
    }

    /// The mask clears one bit and touches nothing else.
    #[test]
    fn test_the_nonce_mask() {
        let mut nonce = [0xffu8; 16];
        MgmSuite::mask_nonce(&mut nonce);
        assert_eq!(nonce[0], 0x7f);
        assert!(nonce[1..].iter().all(|&b| b == 0xff),
                "the mask reached past the first byte");

        // A nonce that already has the bit clear is unchanged.
        let mut clear = [0x69u8; 8];
        let before = clear;
        MgmSuite::mask_nonce(&mut clear);
        assert_eq!(clear, before);
    }
}
