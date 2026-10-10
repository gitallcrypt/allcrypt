/*
ACPKM: internal re-keying, from RFC 8645 (and R 1323565.1.017-2018).

A block cipher in CTR mode is safe for a bounded number of blocks under
one key, and the bound is not large: the birthday bound on a 64 bit block
is 2^32 blocks, which is 32 GB for Magma. ACPKM raises the bound by
changing the key every `N` bytes, deterministically, with no extra
material from anybody:

    K_1 = K
    K_{i+1} = MSB_|K| ( E_{K_i}(D_1) || E_{K_i}(D_2) || ... )

where `D` is the fixed byte string 0x80, 0x81, ... 0x9f split into blocks.
It is a one-way step, so an attacker who recovers one section's key learns
nothing about the sections before it.

Three things to get right:

  * **The counter does not restart when the key changes.** It runs across
    the whole message. Restarting it per section would repeat a (key,
    nonce) pair only if a key repeated - but it also disagrees with every
    other implementation, which is the failure that actually happens.

  * **The section size is in bytes and must be a whole number of
    blocks.** A section boundary in the middle of a block would mean one
    block encrypted under two keys, which is not a thing.

  * **`D` is a constant, not a counter.** It is the same string for every
    re-key; what changes is the key it is encrypted under.

Nothing on this machine implements ACPKM, so `scripts/diff_check.py`
carries a second reading of RFC 8645. The constant `D` is the one in the
gost-engine project's `ACPKM_D_2018`, which cites the CFRG re-keying
draft it came from.
*/

use crate::api::AnyBlockCipher;
use crate::block_ciphers::BlockCipher;

/// Counter blocks handed to the cipher at a time.
const BATCH: usize = 16;

/// `D` from RFC 8645 section 4.1: 0x80 through 0x9f.
///
/// Thirty-two bytes, which is two Kuznyechik blocks or four Magma blocks -
/// exactly enough to fill a 256 bit key in either case, and the reason
/// the standard stops there.
const D: [u8; 32] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];

/// The next section key.
///
/// One way: the new key is the cipher's output, so recovering it says
/// nothing about the key that produced it. That is the whole point of
/// re-keying rather than, say, incrementing.
pub fn acpkm_next(cipher_name: &str, key: &[u8]) -> Result<Vec<u8>, String> {
    let mut cipher = AnyBlockCipher::new(cipher_name, key, None)?;
    let block_size = cipher.blocksize();
    if block_size == 0 || key.len() > D.len() {
        return Err(format!(
            "ACPKM's constant D is {} bytes, so it cannot fill a {} byte key.",
            D.len(), key.len()));
    }

    // RFC 8645 section 4.1: J = ceil(k / n) blocks of D, and the key is
    // the first k bytes of their encryptions - so a key that is not a
    // whole number of blocks (AES-192's 24 bytes) takes one block more
    // than it fills and keeps what it needs.
    //
    // Through `encrypt_blocks`, since the key that enciphers D is the
    // secret one and AES's one-block `block_encrypt` is its table path.
    let blocks = key.len().div_ceil(block_size);
    let mut next = D[..blocks * block_size].to_vec();
    cipher.encrypt_blocks(&mut next)?;
    next.truncate(key.len());
    Ok(next)
}

/// CTR-ACPKM (RFC 8645 section 4.2): CTR mode with the key re-derived
/// every `section` bytes.
///
/// `nonce` is half a block wide; the counter is the other half and starts
/// at zero. That split is why the nonce is not a whole block: the counter
/// has to have room to run without touching it.
pub struct CtrAcpkm {
    cipher_name: String,
    key: Vec<u8>,
    block_size: usize,
    /// How many bytes of message one key covers.
    section: usize,
    /// The counter block, as a whole-block big endian integer.
    counter: Vec<u8>,
    /// Bytes processed under the current key.
    in_section: usize,
    cipher: AnyBlockCipher,
    keystream: Vec<u8>,
    /// Keystream generated and not yet used.
    used: usize,
}

impl core::fmt::Debug for CtrAcpkm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CtrAcpkm {{ {}, section {}, keys redacted }}",
               self.cipher_name, self.section)
    }
}

impl CtrAcpkm {
    pub fn new(cipher_name: &str, key: &[u8], nonce: &[u8], section: usize)
               -> Result<CtrAcpkm, String> {
        let cipher = AnyBlockCipher::new(cipher_name, key, None)?;
        let block_size = cipher.blocksize();

        if nonce.len() * 2 != block_size {
            return Err(format!(
                "CTR-ACPKM's nonce is half a block: {} bytes for this cipher, \
                 not {}. The other half is the counter, and it needs the room.",
                block_size / 2, nonce.len()));
        }
        if section == 0 || !section.is_multiple_of(block_size) {
            return Err(format!(
                "The section size is {} bytes; it must be a non-zero multiple \
                 of the {} byte block, or a block would be split across two \
                 keys.", section, block_size));
        }

        let mut counter = vec![0u8; block_size];
        counter[..nonce.len()].copy_from_slice(nonce);

        Ok(CtrAcpkm {
            cipher_name: cipher_name.to_string(),
            key: key.to_vec(),
            block_size,
            section,
            counter,
            in_section: 0,
            cipher,
            keystream: Vec::with_capacity(BATCH * block_size),
            used: 0,
        })
    }

    fn bump(&mut self) {
        // Big endian increment over the whole block. The nonce occupies
        // the top half, so in practice only the bottom half ever moves -
        // but carrying into the nonce is what a message long enough to
        // exhaust the counter would do, and it is better to be arithmetic
        // than to silently wrap the low half.
        for byte in self.counter.iter_mut().rev() {
            let (next, carried) = byte.overflowing_add(1);
            *byte = next;
            if !carried {
                break;
            }
        }
    }

    /// Transform `input` in place. CTR is its own inverse, so this is
    /// both directions.
    pub fn apply(&mut self, mut data: &mut [u8]) -> Result<(), String> {
        let bs = self.block_size;
        // Keystream a previous call generated and did not use up. It
        // belongs to the current section: a batch never crosses a
        // section boundary, so neither can its remainder.
        if self.used < self.keystream.len() {
            let take = (self.keystream.len() - self.used).min(data.len());
            for (byte, mask) in data[..take].iter_mut().zip(&self.keystream[self.used..]) {
                *byte ^= mask;
            }
            self.used += take;
            self.in_section += take;
            data = &mut data[take..];
        }
        while !data.is_empty() {
            // A section boundary always falls on a block boundary, which
            // the constructor guarantees - so the key can only ever
            // change here, between batches.
            if self.in_section == self.section {
                self.key = acpkm_next(&self.cipher_name, &self.key)?;
                self.cipher = AnyBlockCipher::new(&self.cipher_name, &self.key, None)?;
                self.in_section = 0;
            }
            // As many counter blocks as the data needs, the section has
            // room for and a batch holds, enciphered together: the
            // blocks are independent, so this is what keeps AES on its
            // constant-time path.
            let blocks = data.len().div_ceil(bs)
                .min((self.section - self.in_section) / bs)
                .min(BATCH);
            self.keystream.clear();
            for _ in 0..blocks {
                self.keystream.extend_from_slice(&self.counter);
                self.bump();
            }
            self.cipher.encrypt_blocks(&mut self.keystream)?;
            let take = (blocks * bs).min(data.len());
            for (byte, mask) in data[..take].iter_mut().zip(&self.keystream) {
                *byte ^= mask;
            }
            self.used = take;
            self.in_section += take;
            data = &mut data[take..];
        }
        Ok(())
    }
}

/// One whole message under CTR-ACPKM.
pub fn ctr_acpkm(cipher_name: &str, key: &[u8], nonce: &[u8], section: usize,
                 data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = data.to_vec();
    CtrAcpkm::new(cipher_name, key, nonce, section)?.apply(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// The derivation is the cipher applied to a constant, so it is
    /// reproducible by hand - which is what this checks, against the
    /// cipher rather than against `acpkm_next`'s own loop.
    #[test]
    fn test_the_next_key_is_d_encrypted_under_the_current_one() {
        let key = vec![0x11u8; 32];
        let next = acpkm_next("kuznyechik", &key).unwrap();
        assert_eq!(next.len(), 32);

        let mut cipher = AnyBlockCipher::new("kuznyechik", &key, None).unwrap();
        let mut expected = Vec::new();
        cipher.block_encrypt(&D[..16], &mut expected);
        cipher.block_encrypt(&D[16..], &mut expected);
        assert_eq!(next, expected);

        // Magma's block is 8 bytes, so the same 32 byte key takes four
        // blocks of D rather than two.
        let magma = acpkm_next("magma", &key).unwrap();
        assert_eq!(magma.len(), 32);
        assert_ne!(magma, next);
    }

    /// Re-keying must actually move, and must not cycle.
    #[test]
    fn test_the_keys_keep_changing() {
        let mut key = vec![0x5au8; 32];
        let mut seen = vec![key.clone()];
        for _ in 0..8 {
            key = acpkm_next("kuznyechik", &key).unwrap();
            assert!(!seen.contains(&key), "the key schedule cycled");
            seen.push(key.clone());
        }
    }

    /// CTR is its own inverse, and the key changes have to line up on
    /// both sides.
    #[test]
    fn test_it_round_trips_across_several_sections() {
        for (name, block) in [("kuznyechik", 16usize), ("magma", 8)] {
            let key = vec![0x33u8; 32];
            let nonce = vec![0x9cu8; block / 2];
            let section = block * 2;

            // Four and a bit sections, so the last one is partial.
            let plaintext: Vec<u8> = (0..(section * 4 + 3) as u32)
                .map(|i| (i * 11 + 5) as u8).collect();

            let ciphertext = ctr_acpkm(name, &key, &nonce, section, &plaintext).unwrap();
            assert_ne!(ciphertext, plaintext);
            assert_eq!(ctr_acpkm(name, &key, &nonce, section, &ciphertext).unwrap(),
                       plaintext, "{}", name);
        }
    }

    /// The re-keying must make a difference. A section size longer than
    /// the message is plain CTR; a short one is not, and the two must
    /// diverge exactly at the first boundary.
    #[test]
    fn test_the_key_change_takes_effect_at_the_boundary_and_not_before() {
        let key = vec![0x44u8; 32];
        let nonce = vec![0x21u8; 8];
        let plaintext = vec![0u8; 16 * 6];

        let rekeyed = ctr_acpkm("kuznyechik", &key, &nonce, 32, &plaintext).unwrap();
        let plain_ctr = ctr_acpkm("kuznyechik", &key, &nonce, 16 * 100, &plaintext)
            .unwrap();

        assert_eq!(rekeyed[..32], plain_ctr[..32],
                   "the first section is under the original key");
        assert_ne!(rekeyed[32..], plain_ctr[32..],
                   "the second section must be under a new key");
    }

    /// The counter runs across sections rather than restarting. If it
    /// restarted, two sections whose keys happened to repeat would repeat
    /// their keystream - and, more to the point, it would disagree with
    /// every other implementation.
    #[test]
    fn test_the_counter_does_not_restart_with_the_key() {
        let key = vec![0x66u8; 32];
        let nonce = vec![0x07u8; 8];
        let section = 32usize;

        // Two sections of zeros. The second section's keystream is
        // produced under a new key *and* a counter that carried on, so
        // it must differ from what the new key alone would give starting
        // at zero.
        let whole = ctr_acpkm("kuznyechik", &key, &nonce, section, &[0u8; 64])
            .unwrap();

        let second_key = acpkm_next("kuznyechik", &key).unwrap();
        let restarted = ctr_acpkm("kuznyechik", &second_key, &nonce,
                                  section * 100, &[0u8; 32]).unwrap();
        assert_ne!(whole[32..], restarted[..],
                   "the counter restarted, which agrees with nobody");
    }

    /// Streaming in ragged pieces must equal one call, including across a
    /// section boundary - which is the only place this can go wrong.
    #[test]
    fn test_streaming_equals_one_call() {
        let key = vec![0x88u8; 32];
        let nonce = vec![0x13u8; 8];
        let section = 32usize;
        let plaintext: Vec<u8> = (0..200u32).map(|i| (i * 17 + 3) as u8).collect();

        let whole = ctr_acpkm("kuznyechik", &key, &nonce, section, &plaintext).unwrap();
        for chunk in [1usize, 5, 15, 16, 17, 31, 32, 33, 64] {
            let mut state = CtrAcpkm::new("kuznyechik", &key, &nonce, section).unwrap();
            let mut out = Vec::new();
            for piece in plaintext.chunks(chunk) {
                let mut buffer = piece.to_vec();
                state.apply(&mut buffer).unwrap();
                out.extend_from_slice(&buffer);
            }
            assert_eq!(out, whole, "in chunks of {}", chunk);
        }
    }

    #[test]
    fn test_the_parameters_are_checked() {
        let key = vec![0u8; 32];
        // The nonce is half a block, not a whole one.
        assert!(CtrAcpkm::new("kuznyechik", &key, &[0u8; 16], 32).is_err());
        assert!(CtrAcpkm::new("kuznyechik", &key, &[0u8; 8], 32).is_ok());
        // Magma's half-block is four bytes.
        assert!(CtrAcpkm::new("magma", &key, &[0u8; 8], 16).is_err());
        assert!(CtrAcpkm::new("magma", &key, &[0u8; 4], 16).is_ok());
        // The section must be a whole number of blocks, and non-zero.
        assert!(CtrAcpkm::new("kuznyechik", &key, &[0u8; 8], 0).is_err());
        assert!(CtrAcpkm::new("kuznyechik", &key, &[0u8; 8], 24).is_err());
    }

    /// `D` is only 32 bytes, so it cannot fill a longer key. A key that
    /// is not a whole number of blocks was refused, although RFC 8645
    /// section 4.1 derives `MSB_k` of `ceil(k/n)` blocks and AES-192 is
    /// such a key; the earlier form of this test pinned the refusal.
    /// Now the 24 byte key takes two blocks of D and keeps 24 bytes,
    /// which is the first 24 of what a 32 byte key gets.
    #[test]
    fn test_the_key_size_limits_are_checked() {
        assert!(acpkm_next("kuznyechik", &[0u8; 32]).is_ok());
        assert!(acpkm_next("aes", &[0u8; 16]).is_ok());
        assert!(acpkm_next("aes", &[0u8; 33]).is_err());
        let from_24 = acpkm_next("aes", &[0u8; 24]).unwrap();
        assert_eq!(from_24.len(), 24);
        let mut cipher = AnyBlockCipher::new("aes", &[0u8; 24], None).unwrap();
        let mut expected = Vec::new();
        cipher.block_encrypt(&D[..16], &mut expected);
        cipher.block_encrypt(&D[16..], &mut expected);
        assert_eq!(from_24, expected[..24]);
        assert_eq!(hex(&D[..4]), "80818283");
    }
}
