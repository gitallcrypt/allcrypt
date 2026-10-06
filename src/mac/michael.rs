//! Michael, the message integrity code of TKIP (IEEE 802.11-2020
//! 12.5.2.3), designed by Niels Ferguson to be cheap enough for the
//! first-generation Wi-Fi hardware that WEP had been built for.
//!
//! A 64-bit key as two 32-bit little-endian words `(l, r)`; the message,
//! followed by the byte 0x5A and four to seven zero bytes so that it is
//! a whole number of 32-bit little-endian words, is absorbed one word at
//! a time: `l ^= word`, then the block function
//!
//! ```text
//! r ^= l <<< 17; l += r;
//! r ^= XSWAP(l); l += r;      XSWAP swaps the bytes of each 16-bit half
//! r ^= l <<< 3;  l += r;
//! r ^= l >>> 2;  l += r;
//! ```
//!
//! The tag is `l || r`, little endian.
//!
//! **Michael is weak by design**: it has about 20 bits of forgery
//! resistance, and 802.11 compensates with countermeasures (a minute of
//! silence after two failures within a minute) rather than with the
//! MIC. Known plaintext also gives the key outright: the block function
//! is invertible, so a tag and its message run backwards to `(l, r)`.
//! It is here because TKIP is, and TKIP is because networks still run
//! it.

fn block(mut l: u32, mut r: u32) -> (u32, u32) {
    r ^= l.rotate_left(17);
    l = l.wrapping_add(r);
    r ^= ((l & 0xff00_ff00) >> 8) | ((l & 0x00ff_00ff) << 8);
    l = l.wrapping_add(r);
    r ^= l.rotate_left(3);
    l = l.wrapping_add(r);
    r ^= l.rotate_right(2);
    l = l.wrapping_add(r);
    (l, r)
}

/// Michael over `data` under the 8-byte `key`.
pub fn michael(key: &[u8; 8], data: &[u8]) -> [u8; 8] {
    let mut l = u32::from_le_bytes(key[..4].try_into().unwrap());
    let mut r = u32::from_le_bytes(key[4..].try_into().unwrap());
    let mut padded = data.to_vec();
    padded.push(0x5a);
    padded.extend_from_slice(&[0; 4]);
    padded.resize(padded.len().next_multiple_of(4), 0);
    for word in padded.chunks(4) {
        l ^= u32::from_le_bytes(word.try_into().unwrap());
        (l, r) = block(l, r);
    }
    let mut tag = [0u8; 8];
    tag[..4].copy_from_slice(&l.to_le_bytes());
    tag[4..].copy_from_slice(&r.to_le_bytes());
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `vectors/michael.vec`: the Linux kernel's Michael test vectors
    /// (`crypto/testmgr.h`, from IEEE 802.11's annex), extracted by
    /// `scripts/make_michael_vectors.py`. Each key is the previous tag,
    /// so a wrong answer anywhere fails every later row.
    #[test]
    fn test_kernel_vectors() {
        let text = include_str!("../../vectors/michael.vec");
        let mut rows = 0;
        for record in text.split("\n\n").filter(|r| r.contains("key = ")) {
            let field = |name: &str| record.lines()
                .find_map(|l| l.strip_prefix(&format!("{name} = ")))
                .unwrap_or_else(|| panic!("no {name}"));
            let key: [u8; 8] = unhex(field("key")).try_into().unwrap();
            assert_eq!(michael(&key, &unhex(field("message"))).to_vec(), unhex(field("tag")),
                       "{record}");
            rows += 1;
        }
        assert_eq!(rows, 6);
    }

    /// The padding's zeros run to the next whole word after at least
    /// four: lengths 0 to 8 each add a different number.
    #[test]
    fn test_padding_lengths() {
        let key = [1, 2, 3, 4, 5, 6, 7, 8];
        let tags: Vec<[u8; 8]> = (0..9).map(|n| michael(&key, &vec![0u8; n])).collect();
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // One word by hand: "abc" + 0x5a, then a word of zeros.
        let (mut l, mut r) = (0x0403_0201u32, 0x0807_0605u32);
        l ^= u32::from_le_bytes([b'a', b'b', b'c', 0x5a]);
        (l, r) = block(l, r);
        (l, r) = block(l, r);
        let mut want = l.to_le_bytes().to_vec();
        want.extend(r.to_le_bytes());
        assert_eq!(michael(&key, b"abc").to_vec(), want);
    }
}
