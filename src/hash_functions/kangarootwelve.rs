//! KangarooTwelve, KT128 and KT256 (RFC 9861 section 3): a tree hash over
//! TurboSHAKE128 or TurboSHAKE256 (`keccak::Keccak::turboshake`), with a
//! customization string and any output length.
//!
//! ```text
//! S = M || C || length_encode(|C|)
//! |S| <= 8192:  KT = TurboSHAKE(S, 0x07, L)
//! otherwise:    S_0 = the first 8192 bytes, S_1 .. S_n-1 the rest in 8192s
//!               CV_i = TurboSHAKE(S_i, 0x0B, 32 or 64)        i >= 1
//!               KT = TurboSHAKE(S_0 || 03 00 00 00 00 00 00 00
//!                               || CV_1 || .. || CV_n-1
//!                               || length_encode(n - 1) || FF FF, 0x06, L)
//! ```
//!
//! `length_encode(x)` is `x` big endian with no leading zero bytes, then
//! the count of those bytes; `length_encode(0)` is the single byte `00`.
//! A chaining value is 32 bytes for KT128 and 64 for KT256.
//!
//! The message streams: the first 8192 bytes are held until the 8193rd
//! decides which of the two shapes this is, and after that each chunk
//! goes through a leaf sponge whose chaining value is absorbed into the
//! final node as soon as the chunk is complete. `digest` and `squeeze`
//! finish a copy, so `update` may follow them.

use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::HashFunction;

/// The chunk size `B`, 8192 bytes.
const CHUNK: usize = 8192;

/// RFC 9861 section 3.3's `length_encode`.
fn length_encode(x: u64) -> Vec<u8> {
    let bytes = x.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = bytes[skip..].to_vec();
    out.push(out.len() as u8);
    out
}

/// KT128 or KT256 under one customization string.
#[derive(Clone)]
pub struct KangarooTwelve {
    security_bits: usize,
    customization: Vec<u8>,
    digest_len: usize,
    /// The first chunk, until the input outgrows it.
    first: Vec<u8>,
    /// The final node, from the 8193rd byte on.
    final_node: Option<Keccak>,
    /// The leaf sponge of the chunk being read, and its bytes so far.
    leaf: Option<Keccak>,
    leaf_len: usize,
    /// Leaves whose chaining values the final node has absorbed.
    leaves: u64,
}

impl KangarooTwelve {
    /// KT128 (`security_bits` 128) or KT256 (256) with a customization
    /// string, `C` in RFC 9861, empty for the plain function, and a
    /// default output length; any length can be squeezed.
    pub fn new(security_bits: usize, customization: &[u8], digest_len: usize)
               -> Result<KangarooTwelve, String> {
        if security_bits != 128 && security_bits != 256 {
            return Err(format!(
                "KangarooTwelve comes as KT128 and KT256; {security_bits} is not one."));
        }
        if digest_len > Keccak::MAX_SQUEEZE {
            return Err(format!("A KangarooTwelve output is at most {} bytes here; asked for \
                                {digest_len}.", Keccak::MAX_SQUEEZE));
        }
        Ok(KangarooTwelve {
            security_bits, customization: customization.to_vec(), digest_len,
            first: Vec::with_capacity(CHUNK), final_node: None, leaf: None, leaf_len: 0,
            leaves: 0,
        })
    }

    /// A chaining value's length: 32 bytes for KT128, 64 for KT256.
    fn cv_len(&self) -> usize {
        self.security_bits / 4
    }

    fn turboshake(&self, domain: u8) -> Keccak {
        Keccak::turboshake(self.security_bits, domain, 0).expect("a valid TurboSHAKE")
    }

    /// The bytes of `S`, message or customization alike.
    fn absorb(&mut self, mut input: &[u8]) {
        if self.final_node.is_none() {
            let room = CHUNK - self.first.len();
            let take = room.min(input.len());
            self.first.extend_from_slice(&input[..take]);
            input = &input[take..];
            if input.is_empty() {
                return;
            }
            // An 8193rd byte: the tree shape, and S_0 is the final
            // node's first chunk.
            let mut node = self.turboshake(0x06);
            node.update(&self.first);
            node.update(&[0x03, 0, 0, 0, 0, 0, 0, 0]);
            self.final_node = Some(node);
        }
        while !input.is_empty() {
            if self.leaf.is_none() {
                self.leaf = Some(self.turboshake(0x0b));
                self.leaf_len = 0;
            }
            let take = (CHUNK - self.leaf_len).min(input.len());
            self.leaf.as_mut().unwrap().update(&input[..take]);
            self.leaf_len += take;
            input = &input[take..];
            if self.leaf_len == CHUNK {
                self.finish_leaf();
            }
        }
    }

    /// The current leaf's chaining value into the final node.
    fn finish_leaf(&mut self) {
        if let Some(leaf) = self.leaf.take() {
            let cv = leaf.squeeze(self.cv_len());
            self.final_node.as_mut().expect("a leaf after the first chunk").update(&cv);
            self.leaves += 1;
            self.leaf_len = 0;
        }
    }

    /// `length` bytes of output for the message so far. Repeatable, and
    /// `update` may follow it.
    pub fn squeeze(&self, length: usize) -> Result<Vec<u8>, String> {
        let mut tree = self.clone();
        let customization = core::mem::take(&mut tree.customization);
        tree.absorb(&customization);
        tree.absorb(&length_encode(customization.len() as u64));
        match tree.final_node.take() {
            None => {
                let mut single = tree.turboshake(0x07);
                single.update(&tree.first);
                single.try_squeeze(length)
            }
            Some(node) => {
                tree.final_node = Some(node);
                if tree.leaf_len > 0 {
                    tree.finish_leaf();
                }
                let mut node = tree.final_node.take().unwrap();
                node.update(&length_encode(tree.leaves));
                node.update(&[0xff, 0xff]);
                node.try_squeeze(length)
            }
        }
    }
}

impl HashFunction for KangarooTwelve {
    /// `kt128` or `kt256`, with the length in bits where it is not the
    /// default (32 or 64 bytes). A customization string has no name.
    fn name(&self) -> String {
        let default = self.security_bits / 4;
        if self.digest_len == default {
            format!("kt{}", self.security_bits)
        } else {
            format!("kt{}_{}", self.security_bits, self.digest_len * 8)
        }
    }

    fn digest_len(&self) -> usize { self.digest_len }

    /// TurboSHAKE's rate, 168 or 136 bytes, as for SHA-3 and SHAKE: the
    /// block HMAC would pad a key to. HMAC over KT is legal and not
    /// needed - KT given a key in its customization string or message is
    /// already a MAC (RFC 9861 section 4).
    fn block_size(&self) -> usize {
        if self.security_bits == 128 { 168 } else { 136 }
    }

    fn update(&mut self, input: &[u8]) {
        self.absorb(input);
    }

    fn digest(&mut self) -> Vec<u8> {
        self.squeeze(self.digest_len).expect("a digest length checked by new")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9861 section 3.3's examples of `length_encode`, read out of the
    /// text: `length_encode(N) = `HEX``, three of them.
    #[test]
    fn test_length_encode() {
        let text = include_str!("../../rfcs/rfc9861.txt");
        // The last occurrence: the table of contents has the same line.
        let section = &text[text.rfind("3.3.  length_encode( x )\n").expect("section 3.3")..];
        let section = &section[..section.find("3.4.  ").unwrap()];
        let mut found = 0;
        for piece in section.split("length_encode(").skip(1) {
            let Some((number, rest)) = piece.split_once(") = `") else { continue };
            let Ok(x) = number.parse::<u64>() else { continue };
            let hex = &rest[..rest.find('`').unwrap()];
            let bytes: Vec<u8> = hex.split_whitespace()
                .map(|b| u8::from_str_radix(b, 16).unwrap()).collect();
            assert_eq!(length_encode(x), bytes, "length_encode({x})");
            found += 1;
        }
        assert_eq!(found, 3);
    }

    /// Streaming in pieces of every awkward size gives the one-call answer,
    /// across the first chunk's end, the second's, and the customization's
    /// own crossing of a boundary.
    #[test]
    fn test_streaming_matches_one_call() {
        let message: Vec<u8> = (0..3 * CHUNK + 77).map(|i| (i * 7 + i / 251) as u8).collect();
        for security in [128, 256] {
            for (m, c) in [(CHUNK - 3, 5), (CHUNK, 0), (CHUNK + 1, 0), (2 * CHUNK, 9),
                           (message.len(), 300)] {
                let custom: Vec<u8> = (0..c).map(|i| i as u8).collect();
                let mut whole = KangarooTwelve::new(security, &custom, 40).unwrap();
                whole.update(&message[..m]);
                let expected = whole.digest();
                for piece in [1usize, 7, 168, 8191, 8193] {
                    let mut kt = KangarooTwelve::new(security, &custom, 40).unwrap();
                    for chunk in message[..m].chunks(piece) {
                        kt.update(chunk);
                    }
                    assert_eq!(kt.digest(), expected, "KT{security}, {m}, {c}, pieces of {piece}");
                    // And digesting twice, then going on, changes nothing.
                    assert_eq!(kt.digest(), expected);
                }
            }
        }
    }
}
