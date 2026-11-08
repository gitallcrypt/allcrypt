//! Grain-128AEADv2 (Hell, Johansson, Meier, Sönnerup and Yoshida; the NIST
//! lightweight cryptography finalist, with the round 3 tweak): a 128 bit
//! key, a 96 bit nonce and a 64 bit tag. And Grain-128AEAD v1, the version
//! of the first two rounds, which differs only in its initialisation
//! ([`Version`]).
//!
//! ## The generator
//!
//! A 128 bit LFSR `s` and a 128 bit NFSR `b`, bit 0 of each the oldest;
//! every clock shifts both down one place and puts the feedback in bit
//! 127:
//!
//! ```text
//! s' = s0 + s7 + s38 + s70 + s81 + s96
//! b' = s0 + b0 + b26 + b56 + b91 + b96 + b3 b67 + b11 b13 + b17 b18 + b27 b59
//!      + b40 b48 + b61 b65 + b68 b84 + b22 b24 b25 + b70 b78 b82 + b88 b92 b93 b95
//! y  = b12 s8 + s13 s20 + b95 s42 + s60 s79 + b12 b95 s94 + s93
//!      + b2 + b15 + b36 + b45 + b64 + b73 + b89
//! ```
//!
//! No tap is above 96, so 32 clocks' outputs and feedbacks are computable
//! at once from the registers as they stand: bit `t` of `(r >> j) as u32`
//! is `r[j]` as it will be at clock `t`. This module works 32 clocks at a
//! time throughout.
//!
//! ## Initialisation
//!
//! `b` is the key and `s` the nonce, then 31 one bits and a zero, each byte
//! least significant bit first. 320 clocks feed the output `y` into both
//! feedbacks; 64 more do too, and add the key into them as well - its
//! first 64 bits into `b`'s, its last 64 into `s`'s - which is the round 3
//! tweak that made v2. Then 64 clocks without feeding `y` back fill the
//! accumulator `A`, and 64 more the shift register `R`, `y`'s first bit in
//! bit 0.
//!
//! v1 has 256 clocks of feeding `y` back where v2 has 320, no clocks that
//! add the key to both feedbacks, and adds the key into `s`'s feedback
//! alone - all 128 bits, one per clock - during the 128 clocks that fill
//! `A` and `R`. Everything from there on is the same, and the outputs of
//! the two are unrelated.
//!
//! ## Encryption and authentication
//!
//! From there the outputs alternate: even clocks give the keystream, odd
//! ones the authentication stream. For each message bit `m` in turn, the
//! keystream bit is added to it, `A` takes `A + R` if `m` is 1, and `R`
//! shifts down with the next authentication bit coming in at bit 63.
//! The associated data goes first, prefixed by its length in DER - one
//! byte below 128, otherwise `0x80 | n` and the length in `n` bytes, most
//! significant first - with its keystream bits discarded. The message is
//! then padded with a single one bit, which adds `R` into `A` once more,
//! and the tag is `A`, little endian. A message bit is authenticated as
//! plaintext, so decryption recovers each bit before authenticating it.
//!
//! Nothing branches on or indexes by the key, the nonce or the data; the
//! accumulation is by mask.

pub const KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 8;

/// Which Grain-128AEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// As submitted to the first two rounds of NIST's lightweight
    /// cryptography process; the designers' repository and its known
    /// answers.
    V1,
    /// With the round 3 tweak; the NIST finalist.
    V2,
}

impl Version {
    /// The name, as error messages give it.
    pub fn name(self) -> &'static str {
        match self {
            Version::V1 => "Grain-128AEADv1",
            Version::V2 => "Grain-128AEADv2",
        }
    }
}

#[derive(Clone)]
struct Grain {
    s: u128,
    b: u128,
    acc: u64,
    reg: u64,
    /// The second half of the last 32 clocks, unused: eight keystream and
    /// eight authentication bits.
    pending: Option<(u8, u8)>,
}

/// Bits `j` to `j + 31` of a register: its bit `j` over the next 32 clocks.
#[inline(always)]
fn at(r: u128, j: u32) -> u32 {
    (r >> j) as u32
}

impl Grain {
    /// The next 32 outputs, before the clocks that produce them.
    fn y(&self) -> u32 {
        let (s, b) = (|j| at(self.s, j), |j| at(self.b, j));
        (b(12) & s(8)) ^ (s(13) & s(20)) ^ (b(95) & s(42)) ^ (s(60) & s(79))
            ^ (b(12) & b(95) & s(94)) ^ s(93)
            ^ b(2) ^ b(15) ^ b(36) ^ b(45) ^ b(64) ^ b(73) ^ b(89)
    }

    /// 32 clocks, with `into_s` and `into_b` added to the two feedbacks.
    fn clock(&mut self, into_s: u32, into_b: u32) {
        let (s, b) = (|j| at(self.s, j), |j| at(self.b, j));
        let fs = s(0) ^ s(7) ^ s(38) ^ s(70) ^ s(81) ^ s(96);
        let fb = s(0) ^ b(0) ^ b(26) ^ b(56) ^ b(91) ^ b(96)
            ^ (b(3) & b(67)) ^ (b(11) & b(13)) ^ (b(17) & b(18)) ^ (b(27) & b(59))
            ^ (b(40) & b(48)) ^ (b(61) & b(65)) ^ (b(68) & b(84))
            ^ (b(22) & b(24) & b(25)) ^ (b(70) & b(78) & b(82))
            ^ (b(88) & b(92) & b(93) & b(95));
        self.s = (self.s >> 32) | (u128::from(fs ^ into_s) << 96);
        self.b = (self.b >> 32) | (u128::from(fb ^ into_b) << 96);
    }

    fn new(version: Version, key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> Grain {
        let k = u128::from_le_bytes(*key);
        let mut iv = [0u8; 16];
        iv[..NONCE_LEN].copy_from_slice(nonce);
        let s = u128::from_le_bytes(iv) | (0x7fff_ffffu128 << 96);
        let mut g = Grain { s, b: k, acc: 0, reg: 0, pending: None };
        let rounds = match version { Version::V1 => 8, Version::V2 => 10 };
        for _ in 0..rounds {
            let y = g.y();
            g.clock(y, y);
        }
        if version == Version::V2 {
            for half in 0..2 {
                let y = g.y();
                g.clock(y ^ at(k, 64 + 32 * half), y ^ at(k, 32 * half));
            }
        }
        let mut words = [0u32; 4];
        for (i, w) in (0u32..).zip(&mut words) {
            *w = g.y();
            match version {
                Version::V1 => g.clock(at(k, 32 * i), 0),
                Version::V2 => g.clock(0, 0),
            }
        }
        g.acc = u64::from(words[0]) | (u64::from(words[1]) << 32);
        g.reg = u64::from(words[2]) | (u64::from(words[3]) << 32);
        g
    }

    /// The next 16 clocks: eight keystream bits and eight authentication
    /// bits, each first bit in bit 0.
    fn next_pair(&mut self) -> (u8, u8) {
        if let Some(pair) = self.pending.take() {
            return pair;
        }
        let y = self.y();
        self.clock(0, 0);
        let (even, odd) = deinterleave(y);
        self.pending = Some(((even >> 8) as u8, (odd >> 8) as u8));
        (even as u8, odd as u8)
    }

    /// Authenticate one byte of plaintext or associated data with eight
    /// authentication bits.
    fn absorb(&mut self, byte: u8, auth: u8) {
        for j in 0..8 {
            let mask = 0u64.wrapping_sub(u64::from(byte >> j & 1));
            self.acc ^= self.reg & mask;
            self.reg = (self.reg >> 1) | (u64::from(auth >> j & 1) << 63);
        }
    }

    fn authenticate_ad(&mut self, ad: &[u8]) {
        for &byte in der_length(ad.len()).iter().chain(ad) {
            let (_, auth) = self.next_pair();
            self.absorb(byte, auth);
        }
    }

    fn tag(mut self) -> [u8; TAG_LEN] {
        self.acc ^= self.reg;
        self.acc.to_le_bytes()
    }
}

/// The even bits of a word and the odd bits, each packed into 16.
fn deinterleave(x: u32) -> (u16, u16) {
    let squeeze = |mut v: u32| {
        v &= 0x5555_5555;
        v = (v | (v >> 1)) & 0x3333_3333;
        v = (v | (v >> 2)) & 0x0f0f_0f0f;
        v = (v | (v >> 4)) & 0x00ff_00ff;
        v = (v | (v >> 8)) & 0x0000_ffff;
        v as u16
    };
    (squeeze(x), squeeze(x >> 1))
}

/// The DER length of `n` bytes: one byte below 128, otherwise `0x80 | k`
/// and `n` in `k` bytes, most significant first.
fn der_length(n: usize) -> Vec<u8> {
    if n < 128 {
        return vec![n as u8];
    }
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = vec![0x80 | (bytes.len() - skip) as u8];
    out.extend_from_slice(&bytes[skip..]);
    out
}

fn checked(version: Version, key: &[u8], nonce: &[u8]) -> Result<Grain, String> {
    let key: &[u8; KEY_LEN] = key.try_into().map_err(|_| {
        format!("A {} key is 16 bytes, not {}.", version.name(), key.len())
    })?;
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
        format!("A {} nonce is 12 bytes, not {}.", version.name(), nonce.len())
    })?;
    Ok(Grain::new(version, key, nonce))
}

/// Grain-128AEADv2: encrypt and authenticate, giving the ciphertext, as
/// long as the plaintext, and the 8 byte tag.
///
/// # Errors
/// A key that is not 16 bytes or a nonce that is not 12.
pub fn encrypt(key: &[u8], nonce: &[u8], ad: &[u8], plaintext: &[u8])
               -> Result<(Vec<u8>, [u8; TAG_LEN]), String> {
    encrypt_version(Version::V2, key, nonce, ad, plaintext)
}

/// Grain-128AEADv2: decrypt and verify. The plaintext, or an error and
/// nothing else.
///
/// # Errors
/// A wrong key, nonce or tag length, or a tag that does not match.
pub fn decrypt(key: &[u8], nonce: &[u8], ad: &[u8], ciphertext: &[u8], tag: &[u8])
               -> Result<Vec<u8>, String> {
    decrypt_version(Version::V2, key, nonce, ad, ciphertext, tag)
}

/// [`encrypt`] for either version.
///
/// # Errors
/// A key that is not 16 bytes or a nonce that is not 12.
pub fn encrypt_version(version: Version, key: &[u8], nonce: &[u8], ad: &[u8], plaintext: &[u8])
                       -> Result<(Vec<u8>, [u8; TAG_LEN]), String> {
    let mut g = checked(version, key, nonce)?;
    g.authenticate_ad(ad);
    let mut out = Vec::with_capacity(plaintext.len());
    for &m in plaintext {
        let (ks, auth) = g.next_pair();
        out.push(m ^ ks);
        g.absorb(m, auth);
    }
    Ok((out, g.tag()))
}

/// [`decrypt`] for either version.
///
/// # Errors
/// A wrong key, nonce or tag length, or a tag that does not match.
pub fn decrypt_version(version: Version, key: &[u8], nonce: &[u8], ad: &[u8], ciphertext: &[u8],
                       tag: &[u8]) -> Result<Vec<u8>, String> {
    if tag.len() != TAG_LEN {
        return Err(format!("A {} tag is 8 bytes, not {}.", version.name(), tag.len()));
    }
    let mut g = checked(version, key, nonce)?;
    g.authenticate_ad(ad);
    let mut out = Vec::with_capacity(ciphertext.len());
    for &c in ciphertext {
        let (ks, auth) = g.next_pair();
        let m = c ^ ks;
        out.push(m);
        g.absorb(m, auth);
    }
    if crate::bignum::ct::bytes_differ(&g.tag(), tag) {
        return Err(format!("{} authentication failed: the tag does not match. The data has \
                            been altered, or the key, nonce or associated data is not the one \
                            that protected it.", version.name()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 clocks at once are 32 clocks one at a time, bit by bit as the
    /// definitions above give them.
    #[test]
    fn test_the_wide_clock_is_the_narrow_one() {
        let bit = |r: u128, j: u32| (r >> j) as u32 & 1;
        let mut wide = Grain { s: 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
                               b: 0x0f1e_2d3c_4b5a_6978_8796_a5b4_c3d2_e1f0,
                               acc: 0, reg: 0, pending: None };
        let (mut s, mut b) = (wide.s, wide.b);
        for _ in 0..8 {
            let y32 = wide.y();
            wide.clock(0x5555_aaaa, 0x1234_5678);
            for t in 0..32 {
                let y = (bit(b, 12) & bit(s, 8)) ^ (bit(s, 13) & bit(s, 20))
                    ^ (bit(b, 95) & bit(s, 42)) ^ (bit(s, 60) & bit(s, 79))
                    ^ (bit(b, 12) & bit(b, 95) & bit(s, 94)) ^ bit(s, 93)
                    ^ [2, 15, 36, 45, 64, 73, 89].iter().fold(0, |a, &j| a ^ bit(b, j));
                assert_eq!(y, y32 >> t & 1);
                let fs = [0, 7, 38, 70, 81, 96].iter().fold(0, |a, &j| a ^ bit(s, j));
                let fb = bit(s, 0) ^ [0, 26, 56, 91, 96].iter().fold(0, |a, &j| a ^ bit(b, j))
                    ^ (bit(b, 3) & bit(b, 67)) ^ (bit(b, 11) & bit(b, 13))
                    ^ (bit(b, 17) & bit(b, 18)) ^ (bit(b, 27) & bit(b, 59))
                    ^ (bit(b, 40) & bit(b, 48)) ^ (bit(b, 61) & bit(b, 65))
                    ^ (bit(b, 68) & bit(b, 84)) ^ (bit(b, 22) & bit(b, 24) & bit(b, 25))
                    ^ (bit(b, 70) & bit(b, 78) & bit(b, 82))
                    ^ (bit(b, 88) & bit(b, 92) & bit(b, 93) & bit(b, 95));
                s = (s >> 1) | (u128::from(fs ^ (0x5555_aaaa >> t & 1)) << 127);
                b = (b >> 1) | (u128::from(fb ^ (0x1234_5678 >> t & 1)) << 127);
            }
            assert_eq!((wide.s, wide.b), (s, b));
        }
    }

    #[test]
    fn test_deinterleave_and_der() {
        assert_eq!(deinterleave(0x5555_5555), (0xffff, 0));
        assert_eq!(deinterleave(0xaaaa_aaaa), (0, 0xffff));
        assert_eq!(deinterleave(0x0000_0006), (0b10, 0b01));
        assert_eq!(der_length(127), [127]);
        assert_eq!(der_length(128), [0x81, 0x80]);
        assert_eq!(der_length(256), [0x82, 0x01, 0x00]);
        assert_eq!(der_length(65536), [0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_round_trip_and_forgery() {
        let (key, nonce) = ([3u8; 16], [5u8; 12]);
        for version in [Version::V1, Version::V2] {
            for len in [0, 1, 2, 3, 31, 32, 33] {
                let pt: Vec<u8> = (0..len as u8).collect();
                let (ct, tag) = encrypt_version(version, &key, &nonce, b"ad", &pt).unwrap();
                assert_eq!(decrypt_version(version, &key, &nonce, b"ad", &ct, &tag).unwrap(), pt);
                let mut bad = tag;
                bad[7] ^= 0x80;
                assert!(decrypt_version(version, &key, &nonce, b"ad", &ct, &bad).is_err());
                assert!(decrypt_version(version, &key, &nonce, b"ae", &ct, &tag).is_err());
            }
        }
        // The two versions share everything after initialisation, so
        // neither opens the other's.
        let (ct, tag) = encrypt_version(Version::V1, &key, &nonce, b"", b"x").unwrap();
        assert!(decrypt(&key, &nonce, b"", &ct, &tag).is_err());
        assert_eq!(encrypt_version(Version::V2, &key, &nonce, b"", b"x").unwrap(),
                   encrypt(&key, &nonce, b"", b"x").unwrap());
        assert!(encrypt(&[0; 15], &nonce, b"", b"").is_err());
        assert!(encrypt(&key, &[0; 16], b"", b"").is_err());
        assert!(decrypt(&key, &nonce, b"", b"", &[0; 16]).is_err());
    }
}
