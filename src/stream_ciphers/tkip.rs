//! TKIP's per-packet key (IEEE 802.11-2020 12.5.2), the encapsulation
//! WPA put on WEP's hardware: every frame gets its own RC4 key, mixed
//! from the 128-bit temporal key, the transmitter's address and the
//! frame's 48-bit sequence counter (TSC).
//!
//! - **Phase 1** mixes the key, the address and the TSC's upper 32 bits
//!   into an 80-bit TTAK - five 16-bit words, eight rounds through a
//!   16-bit S-box. It changes once every 65,536 frames.
//! - **Phase 2** mixes the TTAK with the key and the TSC's lower 16 bits
//!   into the 128-bit RC4 key. Its first three bytes are WEP's IV - the
//!   TSC's second byte, that byte with bit 5 set and bit 7 clear (which
//!   steers clear of RC4's weak-key classes), and the first byte - and
//!   the fourth is the last of the mixing.
//!
//! The 16-bit S-box is AES's: entry `i` is `2*S(i)` in the high byte and
//! `3*S(i)` in the low, multiplied in AES's field, and the substitution
//! of a 16-bit word XORs the low byte's entry with the high byte's
//! entry byte-swapped. It is computed here from the AES S-box's
//! definition rather than typed.
//!
//! The rest of the encapsulation - the Michael MIC over the whole MSDU,
//! RC4 over the MPDU and WEP's CRC-32 ICV - is in `encrypt_mpdu`,
//! `decrypt_mpdu` and `msdu_mic`. The 802.11 header handling is the
//! caller's.

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

/// AES's S-box at `x`: the inverse in GF(2^8) (zero to zero), then the
/// affine map.
const fn aes_sbox(x: u8) -> u8 {
    // x^254 is x's inverse.
    let mut inverse = 1u8;
    let mut power = x;
    let mut e = 254u32;
    while e != 0 {
        if e & 1 != 0 {
            inverse = gf_mul(inverse, power);
        }
        power = gf_mul(power, power);
        e >>= 1;
    }
    if x == 0 {
        inverse = 0;
    }
    inverse ^ inverse.rotate_left(1) ^ inverse.rotate_left(2) ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4) ^ 0x63
}

const SBOX: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let s = aes_sbox(i as u8);
        table[i] = ((gf_mul(s, 2) as u16) << 8) | gf_mul(s, 3) as u16;
        i += 1;
    }
    table
};

fn s(v: u16) -> u16 {
    SBOX[(v & 0xff) as usize] ^ SBOX[(v >> 8) as usize].swap_bytes()
}

fn tk16(tk: &[u8; 16], i: usize) -> u16 {
    u16::from_le_bytes([tk[2 * i], tk[2 * i + 1]])
}

/// Phase 1: the TTAK from the temporal key, the transmitter address and
/// the TSC's upper 32 bits.
pub fn phase1(tk: &[u8; 16], ta: &[u8; 6], iv32: u32) -> [u16; 5] {
    let mut p = [iv32 as u16, (iv32 >> 16) as u16, u16::from_le_bytes([ta[0], ta[1]]),
                 u16::from_le_bytes([ta[2], ta[3]]), u16::from_le_bytes([ta[4], ta[5]])];
    for i in 0..8u16 {
        let j = usize::from(i & 1);
        p[0] = p[0].wrapping_add(s(p[4] ^ tk16(tk, j)));
        p[1] = p[1].wrapping_add(s(p[0] ^ tk16(tk, 2 + j)));
        p[2] = p[2].wrapping_add(s(p[1] ^ tk16(tk, 4 + j)));
        p[3] = p[3].wrapping_add(s(p[2] ^ tk16(tk, 6 + j)));
        p[4] = p[4].wrapping_add(s(p[3] ^ tk16(tk, j))).wrapping_add(i);
    }
    p
}

/// Phase 2: the 16-byte RC4 key from the TTAK, the temporal key and the
/// TSC's lower 16 bits.
pub fn phase2(tk: &[u8; 16], ttak: &[u16; 5], iv16: u16) -> [u8; 16] {
    let mut p = [ttak[0], ttak[1], ttak[2], ttak[3], ttak[4], ttak[4].wrapping_add(iv16)];
    p[0] = p[0].wrapping_add(s(p[5] ^ tk16(tk, 0)));
    p[1] = p[1].wrapping_add(s(p[0] ^ tk16(tk, 1)));
    p[2] = p[2].wrapping_add(s(p[1] ^ tk16(tk, 2)));
    p[3] = p[3].wrapping_add(s(p[2] ^ tk16(tk, 3)));
    p[4] = p[4].wrapping_add(s(p[3] ^ tk16(tk, 4)));
    p[5] = p[5].wrapping_add(s(p[4] ^ tk16(tk, 5)));
    p[0] = p[0].wrapping_add((p[5] ^ tk16(tk, 6)).rotate_right(1));
    p[1] = p[1].wrapping_add((p[0] ^ tk16(tk, 7)).rotate_right(1));
    p[2] = p[2].wrapping_add(p[1].rotate_right(1));
    p[3] = p[3].wrapping_add(p[2].rotate_right(1));
    p[4] = p[4].wrapping_add(p[3].rotate_right(1));
    p[5] = p[5].wrapping_add(p[4].rotate_right(1));
    let [hi, lo] = iv16.to_be_bytes();
    let mut key = [0u8; 16];
    key[0] = hi;
    key[1] = (hi | 0x20) & 0x7f;
    key[2] = lo;
    key[3] = ((p[5] ^ tk16(tk, 0)) >> 1) as u8;
    for (i, word) in p.iter().enumerate() {
        key[4 + 2 * i..6 + 2 * i].copy_from_slice(&word.to_le_bytes());
    }
    key
}

/// The RC4 key for the frame with this 48-bit TSC.
pub fn rc4_key(tk: &[u8; 16], ta: &[u8; 6], tsc: u64) -> [u8; 16] {
    phase2(tk, &phase1(tk, ta, (tsc >> 16) as u32), tsc as u16)
}

/// RC4 under the frame's key over the plaintext and its CRC-32 ICV.
pub fn encrypt_mpdu(tk: &[u8; 16], ta: &[u8; 6], tsc: u64, plaintext: &[u8])
                    -> Result<Vec<u8>, String> {
    super::wep::seal(&rc4_key(tk, ta, tsc), plaintext)
}

/// The inverse of `encrypt_mpdu`, refusing a wrong ICV.
pub fn decrypt_mpdu(tk: &[u8; 16], ta: &[u8; 6], tsc: u64, ciphertext: &[u8])
                    -> Result<Vec<u8>, String> {
    super::wep::open(&rc4_key(tk, ta, tsc), ciphertext)
}

/// The MSDU's Michael MIC: over the destination and source addresses,
/// the priority and three zero bytes, then the data.
pub fn msdu_mic(mic_key: &[u8; 8], da: &[u8; 6], sa: &[u8; 6], priority: u8, data: &[u8])
                -> [u8; 8] {
    let mut input = Vec::with_capacity(16 + data.len());
    input.extend_from_slice(da);
    input.extend_from_slice(sa);
    input.extend_from_slice(&[priority, 0, 0, 0]);
    input.extend_from_slice(data);
    crate::mac::michael::michael(mic_key, &input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The S-box's first entry and its definition: S(0) = 0x63, and 2 *
    /// 0x63 = 0xc6, 3 * 0x63 = 0xa5. Every AES S-box value is distinct,
    /// and the table is a permutation in each byte.
    #[test]
    fn test_the_sbox() {
        assert_eq!(aes_sbox(0), 0x63);
        assert_eq!(aes_sbox(1), 0x7c);
        assert_eq!(aes_sbox(0x53), 0xed);
        assert_eq!(SBOX[0], 0xc6a5);
        let mut seen = [false; 256];
        for i in 0..256 {
            let s = aes_sbox(i as u8);
            assert!(!seen[s as usize]);
            seen[s as usize] = true;
        }
    }

    /// `vectors/tkip.vec`: RC4 keys from Linux's mac80211 TKIP mixing,
    /// written by `scripts/make_tkip_vectors.py` with the kernel's own
    /// S-box table, at TSCs that cross the phase-1 boundary.
    #[test]
    fn test_kernel_mixing() {
        fn unhex(text: &str) -> Vec<u8> {
            (0..text.len()).step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
        }
        let text = include_str!("../../vectors/tkip.vec");
        let mut rows = 0;
        for record in text.split("\n\n").filter(|r| r.contains("tk = ")) {
            let field = |name: &str| record.lines()
                .find_map(|l| l.strip_prefix(&format!("{name} = ")))
                .unwrap_or_else(|| panic!("no {name}"));
            let tk: [u8; 16] = unhex(field("tk")).try_into().unwrap();
            let ta: [u8; 6] = unhex(field("ta")).try_into().unwrap();
            let tsc = u64::from_str_radix(field("tsc"), 16).unwrap();
            assert_eq!(rc4_key(&tk, &ta, tsc).to_vec(), unhex(field("rc4_key")), "{record}");
            rows += 1;
        }
        assert!(rows >= 12, "{rows}");
    }

    #[test]
    fn test_mpdu_round_trip_and_icv() {
        let (tk, ta) = ([7u8; 16], [1, 2, 3, 4, 5, 6]);
        let sealed = encrypt_mpdu(&tk, &ta, 0x1_0002, b"payload").unwrap();
        assert_eq!(sealed.len(), 7 + 4);
        assert_eq!(decrypt_mpdu(&tk, &ta, 0x1_0002, &sealed).unwrap(), b"payload");
        assert!(decrypt_mpdu(&tk, &ta, 0x1_0003, &sealed).is_err());
        let mut bent = sealed.clone();
        bent[0] ^= 1;
        assert!(decrypt_mpdu(&tk, &ta, 0x1_0002, &bent).is_err());
    }

    #[test]
    fn test_the_iv_bytes() {
        let key = rc4_key(&[0; 16], &[0; 6], 0x1234);
        assert_eq!(key[..3], [0x12, 0x32, 0x34]);
        let key = rc4_key(&[0; 16], &[0; 6], 0xff00);
        assert_eq!(key[..3], [0xff, 0x7f, 0x00]);
    }
}
