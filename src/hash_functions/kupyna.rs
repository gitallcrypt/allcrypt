/*!
Kupyna, DSTU 7564:2014: Ukraine's hash, the successor to GOST 34.311-95.

Any multiple of 8 bits from 8 to 512; the standard names 256, 384 and
512. Up to 256 bits the state is 512 bits (eight 64-bit columns) and the
permutations run 10 rounds; above, 1024 bits (sixteen columns) and 14.

## The construction

A wide-pipe Merkle-Damgard, the shape Grøstl has: two fixed
permutations `T⊕` and `T+` (the standard's names; `P` and `Q` in the
reference), and for each block `m`

```text
h' = T⊕(h ⊕ m) ⊕ T+(m) ⊕ h
```

then `T⊕(h) ⊕ h` at the end, of which the hash is the **last** bytes.
The initial state is zero but for its first byte, the state's size in
bytes (64 or 128).

The rounds are Kalyna's: its four S-boxes and its MDS matrix, used here
through `kalyna`'s own functions rather than a copy. What differs is the
round constants and ShiftBytes:

- `T⊕` XORs `(j << 4) ^ round` into the first byte of column `j`;
- `T+` **adds** `0x00F0F0F0F0F0F0F3 ^ (((columns - 1 - j) << 4) ^ round)
  << 56` to column `j` as a little-endian 64-bit word;
- ShiftBytes rotates row `i` by `i` columns, except the last row of the
  1024-bit state, which moves by 11, not 7.

## Padding

A `1` bit, zeros, then the message length **in bits** as 96 bits, little
endian, to a whole block. The length field is 96 bits wide, so the bit
count is kept in a `u128`.

## Where the vectors come from

`vectors/kupyna.vec`, written by `scripts/make_kupyna_vectors.py`: the
standard's examples as the reference implementation by the hash's
authors carries them, rows where that reference and Bouncy Castle 1.77
agree for 256, 384 and 512 bits, and the reference alone for the other
sizes, which Bouncy Castle does not offer.
*/

use crate::block_ciphers::kalyna::{mix_columns, sub_bytes, MUL, SBOX};
use crate::hash_functions::buffer::BlockBuffer;
use crate::hash_functions::HashFunction;

/// The state: sixteen columns of eight bytes, of which `columns` are used.
type State = [u8; 128];

#[derive(Clone)]
enum Buffer {
    Narrow(BlockBuffer<64>),
    Wide(BlockBuffer<128>),
}

#[derive(Clone)]
pub struct Kupyna {
    bits: usize,
    /// 8 or 16.
    columns: usize,
    rounds: usize,
    h: State,
    buffer: Buffer,
    /// Message bytes so far.
    length: u128,
}

/// Row `i` moves right by `i` columns; the last row of the wide state by
/// 11.
fn shift_bytes(s: &mut State, columns: usize) {
    let before = *s;
    for row in 0..8 {
        let shift = if row == 7 && columns == 16 { 11 } else { row };
        for col in 0..columns {
            s[row + 8 * ((col + shift) % columns)] = before[row + 8 * col];
        }
    }
}

/// `T⊕`.
fn t_xor(s: &mut State, columns: usize, rounds: usize) {
    for round in 0..rounds {
        for col in 0..columns {
            s[8 * col] ^= ((col << 4) ^ round) as u8;
        }
        permute(s, columns);
    }
}

/// `T+`.
fn t_plus(s: &mut State, columns: usize, rounds: usize) {
    for round in 0..rounds {
        for col in 0..columns {
            let constant = 0x00F0_F0F0_F0F0_F0F3u64
                ^ ((((columns - 1 - col) << 4) ^ round) as u64) << 56;
            let bytes = &mut s[8 * col..8 * col + 8];
            let word = u64::from_le_bytes((&*bytes).try_into().expect("eight bytes"));
            bytes.copy_from_slice(&word.wrapping_add(constant).to_le_bytes());
        }
        permute(s, columns);
    }
}

/// SubBytes, ShiftBytes, MixColumns: the part of the round both
/// permutations share.
fn permute(s: &mut State, columns: usize) {
    sub_bytes(&mut s[..8 * columns], &SBOX);
    shift_bytes(s, columns);
    mix_columns(&mut s[..8 * columns], &MUL);
}

fn compress(h: &mut State, block: &[u8], columns: usize, rounds: usize) {
    let n = 8 * columns;
    let mut x = [0u8; 128];
    let mut m = [0u8; 128];
    m[..n].copy_from_slice(&block[..n]);
    for i in 0..n {
        x[i] = h[i] ^ m[i];
    }
    t_xor(&mut x, columns, rounds);
    t_plus(&mut m, columns, rounds);
    for i in 0..n {
        h[i] ^= x[i] ^ m[i];
    }
}

impl Kupyna {
    /// Kupyna with a hash of `bits`: a multiple of 8 from 8 to 512.
    ///
    /// # Errors
    /// Any other size.
    pub fn new(bits: usize) -> Result<Kupyna, String> {
        if bits == 0 || bits > 512 || !bits.is_multiple_of(8) {
            return Err(format!("Kupyna's hash is a multiple of 8 bits from 8 to 512, \
                                not {bits}."));
        }
        let (columns, rounds, buffer) = if bits <= 256 {
            (8, 10, Buffer::Narrow(BlockBuffer::default()))
        } else {
            (16, 14, Buffer::Wide(BlockBuffer::default()))
        };
        let mut h = [0u8; 128];
        h[0] = (8 * columns) as u8;
        Ok(Kupyna { bits, columns, rounds, h, buffer, length: 0 })
    }
}

impl HashFunction for Kupyna {
    fn name(&self) -> String {
        format!("kupyna{}", self.bits)
    }

    fn digest_len(&self) -> usize {
        self.bits / 8
    }

    fn block_size(&self) -> usize {
        8 * self.columns
    }

    fn update(&mut self, input: &[u8]) {
        self.length += input.len() as u128;
        let (h, columns, rounds) = (&mut self.h, self.columns, self.rounds);
        match &mut self.buffer {
            Buffer::Narrow(b) => b.feed(input, |block| compress(h, block, columns, rounds)),
            Buffer::Wide(b) => b.feed(input, |block| compress(h, block, columns, rounds)),
        }
    }

    /// The hash of everything so far; the state is left as it was, so
    /// `update` can go on.
    fn digest(&mut self) -> Vec<u8> {
        let n = 8 * self.columns;
        let buffered = match &self.buffer {
            Buffer::Narrow(b) => b.buffered(),
            Buffer::Wide(b) => b.buffered(),
        };
        // The tail, a 1 bit, zeros, and the 96-bit length to a whole
        // number of blocks: one block, or two when the tail leaves fewer
        // than thirteen bytes.
        let mut tail = [0u8; 256];
        tail[..buffered.len()].copy_from_slice(buffered);
        tail[buffered.len()] = 0x80;
        let total = if buffered.len() + 13 <= n { n } else { 2 * n };
        tail[total - 12..total].copy_from_slice(&(self.length * 8).to_le_bytes()[..12]);

        let mut h = self.h;
        for block in tail[..total].chunks_exact(n) {
            compress(&mut h, block, self.columns, self.rounds);
        }
        let mut out = h;
        t_xor(&mut out, self.columns, self.rounds);
        for i in 0..n {
            h[i] ^= out[i];
        }
        h[n - self.bits / 8..n].to_vec()
    }
}

/// What follows `len` bytes of data to end them on a block of `block`
/// bytes: `80`, zeros, and the length in bits as 96 bits little endian -
/// a second block when the first has fewer than thirteen bytes left.
fn padding(len: u128, block: usize) -> Vec<u8> {
    let used = (len % block as u128) as usize;
    let total = if used + 13 <= block { block - used } else { 2 * block - used };
    let mut out = vec![0u8; total];
    out[0] = 0x80;
    out[total - 12..].copy_from_slice(&(len * 8).to_le_bytes()[..12]);
    out
}

/// DSTU 7564's MAC: Kupyna of `pad(K) || M || pad(M) || ~K`, where each
/// `pad` is the hash's own padding over that part alone - so the key
/// fills whole blocks and the message's padding starts on a boundary -
/// and the hash pads the whole once more. 256, 384 or 512 bits.
///
/// The standard's examples, and the reference implementation's MAC,
/// take a key as long as the MAC; Bouncy Castle and cryptonite take any,
/// and so does this. The key is held inverted until the end.
#[derive(Clone)]
pub struct KupynaMac {
    hash: Kupyna,
    inverted_key: Vec<u8>,
    message_len: u128,
}

impl KupynaMac {
    /// A MAC of `bits`, 256, 384 or 512, under `key`.
    ///
    /// # Errors
    /// Any other size.
    pub fn new(bits: usize, key: &[u8]) -> Result<KupynaMac, String> {
        if !matches!(bits, 256 | 384 | 512) {
            return Err(format!("Kupyna's MAC is 256, 384 or 512 bits, not {bits}."));
        }
        let mut hash = Kupyna::new(bits)?;
        let block = hash.block_size();
        hash.update(key);
        hash.update(&padding(key.len() as u128, block));
        Ok(KupynaMac { hash, inverted_key: key.iter().map(|b| !b).collect(), message_len: 0 })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
        self.message_len += data.len() as u128;
    }

    /// The MAC of everything so far; `update` can go on.
    pub fn mac(&self) -> Vec<u8> {
        let mut hash = self.hash.clone();
        hash.update(&padding(self.message_len, hash.block_size()));
        hash.update(&self.inverted_key);
        hash.digest()
    }

    /// Whether `tag` is the MAC, compared in constant time.
    pub fn verify(&self, tag: &[u8]) -> bool {
        !crate::bignum::ct::bytes_differ(&self.mac(), tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The padding is the hash's own: hashing `data || padding(data)`
    /// then nothing more is one compression per block of the two, and a
    /// part padded this way always ends on a block boundary.
    #[test]
    fn test_the_mac_padding_ends_on_a_block() {
        for block in [64usize, 128] {
            for len in 0..3 * block {
                let p = padding(len as u128, block);
                assert_eq!((len + p.len()) % block, 0, "{block} {len}");
                assert!(p.len() >= 13 && p.len() <= block + 12, "{block} {len}");
                assert_eq!(p[0], 0x80);
                assert_eq!(&p[p.len() - 12..p.len() - 4], &((len as u64) * 8).to_le_bytes());
                assert!(p[1..p.len() - 12].iter().all(|&b| b == 0));
            }
        }
    }

    #[test]
    fn test_the_mac_streams() {
        let mut one = KupynaMac::new(384, b"key").unwrap();
        one.update(&[7u8; 300]);
        let mut pieces = KupynaMac::new(384, b"key").unwrap();
        for chunk in [7u8; 300].chunks(13) {
            pieces.update(chunk);
        }
        assert_eq!(one.mac(), pieces.mac());
        assert!(one.verify(&pieces.mac()));
        // mac() leaves the state where it was.
        let first = one.mac();
        assert_eq!(one.mac(), first);
        one.update(b"more");
        assert_ne!(one.mac(), first);
        for bits in [0usize, 8, 128, 255, 257, 1024] {
            assert!(KupynaMac::new(bits, b"key").is_err(), "{bits}");
        }
    }

    #[test]
    fn test_sizes() {
        for bits in [8, 248, 256, 264, 512] {
            let mut k = Kupyna::new(bits).unwrap();
            assert_eq!(k.digest().len(), bits / 8);
            assert_eq!(k.block_size(), if bits <= 256 { 64 } else { 128 });
        }
        for bits in [0, 7, 520, 1024] {
            assert!(Kupyna::new(bits).is_err(), "{bits}");
        }
    }

    /// The padding's boundary: a tail of `n - 13` bytes fits the 1 bit
    /// and the length in one block, `n - 12` needs a second. Fed in one
    /// call or byte by byte, and with `digest` in the middle, the hash
    /// is the same.
    #[test]
    fn test_streaming_and_the_padding_boundary() {
        for bits in [256, 512] {
            let n = if bits == 256 { 64 } else { 128 };
            for len in [n - 13, n - 12, n - 1, n, n + 1, 2 * n - 13, 2 * n - 12] {
                let msg: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
                let mut one = Kupyna::new(bits).unwrap();
                one.update(&msg);
                let want = one.digest();
                let mut bytes = Kupyna::new(bits).unwrap();
                for (i, b) in msg.iter().enumerate() {
                    bytes.update(&[*b]);
                    if i == len / 2 {
                        let _ = bytes.digest();
                    }
                }
                assert_eq!(bytes.digest(), want, "kupyna-{bits} of {len}");
                assert_eq!(one.digest(), want, "digest twice");
            }
        }
    }
}
