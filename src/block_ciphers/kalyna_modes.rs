/*!
DSTU 7624:2014's MAC and key wrap, over Kalyna. Its counter mode is
Kalyna's own `ctr` (see `kalyna`), and its CBC, CFB and OFB are the
generic ones.

## The MAC

A CBC-MAC with one masking key, close to CMAC: `δ = E(0)` when the
message ends on a whole block, `δ = E(01 00 ... 00)` when it does not,
in which case the last block is padded with `80 00 ... 00`. The last
block is XORed with `δ` before its encryption. The tag is the first `q`
bytes. The empty message is one zero block under `δ = E(0)`.

## The key wrap

The data, padded if it is not a whole number of blocks, followed by a
block of zeros, is split into half-blocks; `6·(n − 1)` steps, with `n`
the number of half-blocks, each encrypt the first half-block and the
next one, XOR the step number (from 1, as a 32-bit little-endian word)
into the second half of the result, and rotate the half-blocks one place.
Unwrapping runs the steps backwards and **refuses unless the zero block
comes back as zeros**.

Padding, for data that is not whole blocks: the data, its length **in
bits** as a little-endian half-block, then `80 00 ... 00` to a whole
block (or nothing, if the length already ends one). `unwrap` returns
whole blocks as they are; `unwrap_padded` requires that padding and
strips it. Two functions rather than a guess, because a whole-block key
can end in bytes that look like padding.

## Where the vectors come from

`vectors/kalyna_modes.vec`, written by
`scripts/make_kalyna_mode_vectors.py`: the standard's examples as
Bouncy Castle's tests carry them, and rows on which Bouncy Castle 1.77
and PrivatBank's cryptonite agree. Each implementation is alone where
the other stops: Bouncy Castle MACs and wraps whole blocks only, and
cryptonite's wrap counter is one byte, so it agrees for data of up to
20 blocks.
*/

use crate::block_ciphers::kalyna::Kalyna;
use crate::block_ciphers::BlockCipher;

fn encrypt(cipher: &mut Kalyna, block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(block.len());
    cipher.block_encrypt(block, &mut out);
    out
}

/// DSTU 7624's MAC, fed in pieces.
#[derive(Clone)]
pub struct KalynaMac {
    cipher: Kalyna,
    /// The chaining value.
    state: Vec<u8>,
    /// Up to one block not yet chained: a full block is held back until
    /// more data comes, since the last block is treated differently.
    pending: Vec<u8>,
    tag_len: usize,
}

impl KalynaMac {
    /// A MAC under `cipher` with a tag of `tag_len` bytes, 1 to the block
    /// size.
    ///
    /// # Errors
    /// A tag length out of that range.
    pub fn new(cipher: Kalyna, tag_len: usize) -> Result<KalynaMac, String> {
        let block = cipher.blocksize();
        if tag_len == 0 || tag_len > block {
            return Err(format!("A Kalyna MAC is 1 to {block} bytes, not {tag_len}."));
        }
        Ok(KalynaMac { cipher, state: vec![0; block], pending: Vec::with_capacity(block),
                       tag_len })
    }

    pub fn update(&mut self, mut data: &[u8]) {
        let block = self.state.len();
        while !data.is_empty() {
            if self.pending.len() == block {
                let mut x = std::mem::take(&mut self.pending);
                for (a, b) in x.iter_mut().zip(&self.state) {
                    *a ^= b;
                }
                self.state = encrypt(&mut self.cipher, &x);
                x.clear();
                self.pending = x;
            }
            let take = (block - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
    }

    /// The tag over everything so far; the MAC can go on being fed.
    pub fn tag(&mut self) -> Vec<u8> {
        let block = self.state.len();
        let mut delta_input = vec![0u8; block];
        let mut last = self.pending.clone();
        if last.len() < block && !last.is_empty() {
            last.push(0x80);
            delta_input[0] = 1;
        }
        last.resize(block, 0);
        let delta = encrypt(&mut self.cipher, &delta_input);
        for ((a, s), d) in last.iter_mut().zip(&self.state).zip(&delta) {
            *a ^= s ^ d;
        }
        let mut tag = encrypt(&mut self.cipher, &last);
        tag.truncate(self.tag_len);
        tag
    }

    /// Whether `tag` is the tag, compared in constant time.
    pub fn verify(&mut self, tag: &[u8]) -> bool {
        !crate::bignum::ct::bytes_differ(&self.tag(), tag)
    }
}

/// The data and its padding, for data that is not whole blocks.
fn pad(data: &[u8], block: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    if !data.len().is_multiple_of(block) {
        let half = block / 2;
        let bits = (data.len() as u128 * 8).to_le_bytes();
        out.extend_from_slice(&bits[..half.min(16)]);
        out.resize(data.len() + half, 0);
        if !out.len().is_multiple_of(block) {
            out.push(0x80);
            out.resize(out.len().next_multiple_of(block), 0);
        }
    }
    out
}

/// Wrap `data` (one byte or more) under `cipher`: padded if it is not a
/// whole number of blocks, then one block longer.
///
/// # Errors
/// Empty data, or so much that the step counter would pass 2^32.
pub fn wrap(cipher: &mut Kalyna, data: &[u8]) -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    if data.is_empty() {
        return Err("There is nothing to wrap.".to_string());
    }
    let mut buffer = pad(data, block);
    buffer.resize(buffer.len() + block, 0);
    wrap_blocks(cipher, &buffer)
}

/// The wrapping steps over data that already ends in its check block.
fn wrap_blocks(cipher: &mut Kalyna, buffer: &[u8]) -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    let half = block / 2;
    let n = buffer.len() / half;
    let steps = (n - 1) * 6;
    if steps > u32::MAX as usize {
        return Err("Too much data for the DSTU 7624 key wrap's step counter.".to_string());
    }
    let mut b = buffer[..half].to_vec();
    let mut rest: Vec<Vec<u8>> = buffer[half..].chunks(half).map(<[u8]>::to_vec).collect();
    let mut pair = Vec::with_capacity(block);
    for step in 1..=steps {
        pair.clear();
        pair.extend_from_slice(&b);
        pair.extend_from_slice(&rest[0]);
        let mut x = encrypt(cipher, &pair);
        for (byte, c) in x[half..half + 4].iter_mut().zip((step as u32).to_le_bytes()) {
            *byte ^= c;
        }
        b.copy_from_slice(&x[half..]);
        rest.rotate_left(1);
        let last = rest.len() - 1;
        rest[last].copy_from_slice(&x[..half]);
    }
    let mut out = b;
    for r in rest {
        out.extend_from_slice(&r);
    }
    Ok(out)
}

const WRONG_KEK: &str = "Wrong key-encryption key, or the wrapped data is damaged.";

/// Unwrap and check; the data comes back whole blocks, padding and all.
///
/// # Errors
/// A length that is not two blocks or more of whole blocks, or a check
/// block that is not zero, with the one message for every failure.
pub fn unwrap(cipher: &mut Kalyna, wrapped: &[u8]) -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    let half = block / 2;
    if wrapped.len() < 2 * block || !wrapped.len().is_multiple_of(block) {
        return Err(WRONG_KEK.to_string());
    }
    let n = wrapped.len() / half;
    let steps = (n - 1) * 6;
    let mut b = wrapped[..half].to_vec();
    let mut rest: Vec<Vec<u8>> = wrapped[half..].chunks(half).map(<[u8]>::to_vec).collect();
    let mut pair = Vec::with_capacity(block);
    for step in (1..=steps).rev() {
        let last = rest.len() - 1;
        pair.clear();
        pair.extend_from_slice(&rest[last]);
        pair.extend_from_slice(&b);
        for (byte, c) in pair[half..half + 4].iter_mut().zip((step as u32).to_le_bytes()) {
            *byte ^= c;
        }
        let mut x = Vec::with_capacity(block);
        cipher.block_decrypt(&pair, &mut x);
        b.copy_from_slice(&x[..half]);
        rest.rotate_right(1);
        rest[0].copy_from_slice(&x[half..]);
    }
    let mut out = b;
    for r in rest {
        out.extend_from_slice(&r);
    }
    let data_len = out.len() - block;
    if crate::bignum::ct::bytes_differ(&out[data_len..], &vec![0u8; block]) {
        return Err(WRONG_KEK.to_string());
    }
    out.truncate(data_len);
    Ok(out)
}

/// Unwrap data that was padded: check, then require the padding `wrap`
/// writes for data that is not whole blocks, and strip it.
///
/// # Errors
/// As `unwrap`, or no such padding.
pub fn unwrap_padded(cipher: &mut Kalyna, wrapped: &[u8]) -> Result<Vec<u8>, String> {
    let block = cipher.blocksize();
    let half = block / 2;
    let data = unwrap(cipher, wrapped)?;
    // The length field ends where the 80 starts, or at the end when
    // the length already filled the block. Both are tried, since the
    // field's own top byte can be 80; re-padding the candidate and
    // comparing is exact, and the length field makes two candidates
    // that both re-pad to this data impossible.
    let mut ends = vec![data.len()];
    if let Some(i) = data.iter().rposition(|&b| b != 0) {
        if data[i] == 0x80 {
            ends.push(i);
        }
    }
    for end in ends {
        if end < half {
            continue;
        }
        let mut field = [0u8; 16];
        let take = half.min(16);
        field[..take].copy_from_slice(&data[end - half..end - half + take]);
        let len = end - half;
        if u128::from_le_bytes(field) == len as u128 * 8 && !len.is_multiple_of(block)
            && pad(&data[..len], block) == data {
            return Ok(data[..len].to_vec());
        }
    }
    Err("The unwrapped data does not end in the DSTU 7624 key wrap's padding.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher(block: usize) -> Kalyna {
        Kalyna::new(block, &(0..block as u8).collect::<Vec<u8>>()).unwrap()
    }

    /// Every length from 1 to four blocks wraps, unwraps and, when it is
    /// not whole blocks, unwraps through its padding to itself.
    #[test]
    fn test_round_trips_at_every_length() {
        for block in [16, 32, 64] {
            for len in 1..=4 * block {
                let data: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
                let mut c = cipher(block);
                let wrapped = wrap(&mut c, &data).unwrap();
                assert!(wrapped.len().is_multiple_of(block));
                let back = unwrap(&mut c, &wrapped).unwrap();
                if len.is_multiple_of(block) {
                    assert_eq!(back, data, "{block} {len}");
                    assert!(unwrap_padded(&mut c, &wrapped).is_err(), "{block} {len}");
                } else {
                    assert_eq!(back, pad(&data, block));
                    assert_eq!(unwrap_padded(&mut c, &wrapped).unwrap(), data, "{block} {len}");
                }
            }
        }
    }

    /// A check block wrong in its last byte alone. Changing a wrapped
    /// byte scrambles the whole check block, so the test below could not
    /// tell an unwrap that checks every byte from one that checks one.
    #[test]
    fn test_every_byte_of_the_check_block_is_checked() {
        for block in [16, 32, 64] {
            let mut c = cipher(block);
            for at in [0, block / 2, block - 1] {
                let mut buffer = vec![9u8; block];
                buffer.resize(2 * block, 0);
                buffer[block + at] = 1;
                let wrapped = wrap_blocks(&mut c, &buffer).unwrap();
                assert!(unwrap(&mut c, &wrapped).is_err(), "{block} {at}");
            }
        }
    }

    #[test]
    fn test_a_changed_byte_is_refused() {
        let mut c = cipher(16);
        let wrapped = wrap(&mut c, &[7u8; 32]).unwrap();
        for at in 0..wrapped.len() {
            let mut bad = wrapped.clone();
            bad[at] ^= 1;
            assert!(unwrap(&mut c, &bad).is_err(), "byte {at}");
        }
        assert!(unwrap(&mut c, &wrapped[..wrapped.len() - 16]).is_err());
        assert!(wrap(&mut c, &[]).is_err());
    }

    /// The MAC in pieces equals the MAC in one call, at lengths around
    /// the block, where the held-back last block matters.
    #[test]
    fn test_mac_streams() {
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 48] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut one = KalynaMac::new(cipher(16), 16).unwrap();
            one.update(&data);
            let want = one.tag();
            let mut pieces = KalynaMac::new(cipher(16), 16).unwrap();
            for chunk in data.chunks(5) {
                pieces.update(chunk);
            }
            assert_eq!(pieces.tag(), want, "{len}");
            assert!(one.verify(&want));
        }
        assert!(KalynaMac::new(cipher(16), 0).is_err());
        assert!(KalynaMac::new(cipher(16), 17).is_err());
    }
}
