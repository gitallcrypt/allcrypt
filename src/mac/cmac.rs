/*
CMAC (NIST SP 800-38B, RFC 4493), which GOST calls OMAC.

CBC-MAC with the one fix that makes it safe for variable-length messages:
the last block is XORed with a subkey derived from the cipher, and which
of two subkeys depends on whether the message needed padding.

Plain CBC-MAC over variable lengths is forgeable in one line. Given
`T = CBC-MAC(M)` for a one-block `M`, the two-block message
`M || (M xor T)` has the same tag, and no key is needed to work that out.
CMAC's two subkeys are what stop it: a padded message and an unpadded one
can never collide, because they were finished under different keys.

Three things to get right, and the first two are silent:

  * **Rb depends on the block size**, because it is the low coefficients
    of the irreducible polynomial for GF(2^b): 0x87 for a 128 bit block,
    0x1b for a 64 bit one. Using 0x87 everywhere gives a MAC that is
    perfectly consistent with itself over DES, 3DES, Blowfish and Magma,
    and agrees with nothing. SP 800-38B defines only those two; wider
    blocks - Rijndael's 160 to 256 bits, SHACAL-2's 256, Kalyna's and
    Threefish's 256 to 1024 - take the irreducible polynomial of fewest
    terms and smallest exponents, which is the rule the two standard ones
    follow and what Botan, Crypto++ and Bouncy Castle use. Above 128 bits
    Rb is more than one byte: 0x80043 for 1024.

  * **An empty message is padded**, so it uses K2 and not K1. The "is it
    a whole number of blocks" test is `len > 0 && len % b == 0`, and
    leaving the first half off makes the empty message's tag wrong and
    every other tag right.

  * **The subkey doubling is over GF(2^b), not a plain shift.** Shift
    left by one and, if the bit that fell off the top was set, XOR Rb in.

Checked against OpenSSL through `python-cryptography`, which has CMAC over
AES, Triple DES and Blowfish - so both Rb values are covered by a real
independent implementation, over a 128 bit block and a 64 bit one.
Kuznyechik and Magma then use the same construction with ciphers that are
themselves checked, which is as close to an independent check as an
algorithm nothing here implements can get. The wider blocks are checked
against Botan, Crypto++ and Bouncy Castle, in `vectors/cmac_eax_wide.vec`.
*/

use crate::api::AnyBlockCipher;
use crate::block_ciphers::BlockCipher;
use crate::Mac;

/// The low coefficients of the irreducible polynomial for the block size,
/// as a block: `x^b` is implicit, and the rest are bits of a big-endian
/// `b`-bit number.
///
/// Not a constant: a 64 bit block and a 128 bit block have different
/// fields, and the same value for both is a MAC that agrees with itself
/// and with nobody. The table is generated; see `cmac_polynomials.rs`.
pub(crate) fn rb(block_size: usize) -> Result<Vec<u8>, String> {
    let (_, exponents) = super::cmac_polynomials::POLYNOMIALS.iter()
        .find(|(size, _)| *size == block_size)
        .ok_or_else(|| format!(
            "CMAC is not defined for a {} bit block: the field's polynomial is \
             fixed for 64, 128, 160, 192, 224, 256, 512 and 1024 bits.",
            block_size * 8))?;
    let mut out = vec![0u8; block_size];
    for &exponent in exponents.iter() {
        let exponent = exponent as usize;
        out[block_size - 1 - exponent / 8] |= 1 << (exponent % 8);
    }
    Ok(out)
}

/// Multiply by x in GF(2^b): shift left one bit, and fold in `rb` if the
/// bit that fell off the top was set. `rb` is as long as `block`.
pub(crate) fn double(block: &mut [u8], rb: &[u8]) {
    let carry = block[0] >> 7;
    for index in 0..block.len() - 1 {
        block[index] = (block[index] << 1) | (block[index + 1] >> 7);
    }
    let last = block.len() - 1;
    block[last] <<= 1;
    // Branchless: `carry` is a bit of the cipher's output under the key,
    // and this is the one place in the construction where branching on it
    // would leak. `carry.wrapping_neg()` is 0x00 or 0xff, and every byte
    // of `rb` is masked whether it is zero or not.
    let mask = carry.wrapping_neg();
    for (byte, low) in block.iter_mut().zip(rb) {
        *byte ^= low & mask;
    }
}

/// CMAC over any block cipher this library has.
pub struct Cmac {
    cipher: AnyBlockCipher,
    block_size: usize,
    subkey_one: Vec<u8>,
    subkey_two: Vec<u8>,
    /// The running CBC chain.
    chain: Vec<u8>,
    /// Bytes not yet in a full block. Held back deliberately: the *last*
    /// block is treated differently, and a streaming MAC does not know
    /// which block is last until it is asked for the tag.
    pending: Vec<u8>,
    /// Scratch for one block, allocated once rather than per block.
    scratch: Vec<u8>,
}

impl core::fmt::Debug for Cmac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cmac {{ {}, keys redacted }}", self.cipher.name())
    }
}

impl Cmac {
    /// `cipher` must already be keyed.
    pub fn new(mut cipher: AnyBlockCipher) -> Result<Cmac, String> {
        let block_size = cipher.blocksize();
        let rb = rb(block_size)?;

        // L = E_K(0^b), then K1 = L.x and K2 = K1.x.
        let mut subkey_one = Vec::with_capacity(block_size);
        cipher.block_encrypt(&vec![0u8; block_size], &mut subkey_one);
        if subkey_one.len() != block_size {
            return Err(format!(
                "{} produced {} bytes for a {} byte block.",
                cipher.name(), subkey_one.len(), block_size));
        }
        double(&mut subkey_one, &rb);
        let mut subkey_two = subkey_one.clone();
        double(&mut subkey_two, &rb);

        Ok(Cmac {
            cipher,
            block_size,
            subkey_one,
            subkey_two,
            chain: vec![0u8; block_size],
            pending: Vec::with_capacity(block_size),
            scratch: Vec::with_capacity(block_size),
        })
    }

    /// Build one from a cipher name and a key.
    pub fn with_key(cipher_name: &str, key: &[u8]) -> Result<Cmac, String> {
        Cmac::new(AnyBlockCipher::new(cipher_name, key, None)?)
    }

    pub fn tag_len(&self) -> usize {
        self.block_size
    }

    /// The keyed cipher the MAC runs on, for a construction that uses
    /// the same key for a second purpose - EAX's CTR half - so that it
    /// holds one key schedule rather than two.
    pub fn cipher_mut(&mut self) -> &mut AnyBlockCipher {
        &mut self.cipher
    }

    /// Back to the start of a message, under the same key: the chain
    /// and the held-back bytes cleared, the subkeys kept. What a caller
    /// that MACs many messages under one key uses instead of a second
    /// key schedule per message.
    pub fn reset(&mut self) {
        self.chain.fill(0);
        self.pending.clear();
    }

    /// One CBC step over a whole block.
    fn absorb(&mut self, block: &[u8]) {
        for (chained, byte) in self.chain.iter_mut().zip(block.iter()) {
            *chained ^= byte;
        }
        self.scratch.clear();
        let chain = core::mem::take(&mut self.chain);
        self.cipher.block_encrypt(&chain, &mut self.scratch);
        self.chain = chain;
        self.chain.copy_from_slice(&self.scratch);
    }
}

impl Mac for Cmac {
    fn update(&mut self, input: &[u8]) {
        let mut rest = input;

        if !self.pending.is_empty() {
            let take = core::cmp::min(self.block_size - self.pending.len(), rest.len());
            self.pending.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            // Only absorb once there is *more* to come: a full `pending`
            // with nothing after it is the last block, and the last block
            // is finished differently.
            if self.pending.len() == self.block_size && !rest.is_empty() {
                let block = core::mem::take(&mut self.pending);
                self.absorb(&block);
                self.pending = block;
                self.pending.clear();
            }
        }

        while rest.len() > self.block_size {
            let (block, remaining) = rest.split_at(self.block_size);
            self.absorb(block);
            rest = remaining;
        }
        self.pending.extend_from_slice(rest);
    }

    /// The tag, without consuming the state - the same contract every
    /// other MAC here has.
    fn digest(&mut self) -> Vec<u8> {
        let mut last = self.pending.clone();
        // A whole number of non-zero blocks uses K1; anything else is
        // padded and uses K2. The empty message is *padded*, which is the
        // half of this condition an implementation leaves out.
        let complete = !last.is_empty() && last.len() == self.block_size;
        let subkey = if complete { &self.subkey_one } else { &self.subkey_two };
        if !complete {
            last.push(0x80);
            last.resize(self.block_size, 0);
        }
        for (byte, k) in last.iter_mut().zip(subkey.iter()) {
            *byte ^= k;
        }

        let saved_chain = self.chain.clone();
        let saved_pending = core::mem::take(&mut self.pending);
        self.absorb(&last);
        let tag = self.chain.clone();
        self.chain = saved_chain;
        self.pending = saved_pending;
        tag
    }
}

/// The tag over one message, for callers with all of it in hand.
pub fn cmac(cipher_name: &str, key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = Cmac::with_key(cipher_name, key)?;
    mac.update(message);
    Ok(mac.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 4493 section 4: AES-128 CMAC, all four published vectors.
    ///
    /// These cover the two cases that differ - a whole number of blocks
    /// and a partial one - and the empty message, which is the one an
    /// implementation gets wrong by testing `len % b == 0` alone.
    #[test]
    fn test_rfc_4493_aes128() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let message = unhex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710");

        for (length, want) in [
            (0usize, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ] {
            assert_eq!(hex(&cmac("aes", &key, &message[..length]).unwrap()), want,
                       "message of {} bytes", length);
        }
    }

    /// The subkeys from the same RFC, because a key schedule that is
    /// wrong still produces a MAC.
    #[test]
    fn test_rfc_4493_subkeys() {
        let mac = Cmac::with_key("aes", &unhex("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        assert_eq!(hex(&mac.subkey_one), "fbeed618357133667c85e08f7236a8de");
        assert_eq!(hex(&mac.subkey_two), "f7ddac306ae266ccf90bc11ee46d513b");
    }

    /// Rb is not a constant. A 64 bit block uses 0x1b, and using 0x87
    /// there gives a MAC that is self-consistent over every 64 bit cipher
    /// in this library.
    #[test]
    fn test_the_polynomial_depends_on_the_block_size() {
        assert_eq!(hex(&rb(16).unwrap()), "00000000000000000000000000000087");
        assert_eq!(hex(&rb(8).unwrap()), "000000000000001b");
        assert_eq!(hex(&rb(128).unwrap()[125..]), "080043");
        for size in [7, 12, 40, 48, 96, 256] {
            assert!(rb(size).is_err(), "{} bytes", size);
        }

        // A block whose top bit is set must fold; one without must not.
        let mut high = vec![0x80u8, 0, 0, 0, 0, 0, 0, 0];
        double(&mut high, &rb(8).unwrap());
        assert_eq!(hex(&high), "000000000000001b");

        let mut low = vec![0x01u8, 0, 0, 0, 0, 0, 0, 0];
        double(&mut low, &rb(8).unwrap());
        assert_eq!(hex(&low), "0200000000000000");

        let mut wide = vec![0x80u8; 16];
        double(&mut wide, &rb(16).unwrap());
        assert_eq!(hex(&wide), "010101010101010101010101010101" .to_string() + "87");

        // Above 128 bits Rb spans bytes: x^1024 + x^19 + x^6 + x + 1 folds
        // into the last three, and the carry out of a byte boundary still
        // shifts through.
        let mut top = vec![0u8; 128];
        top[0] = 0x80;
        top[127] = 0x80;
        double(&mut top, &rb(128).unwrap());
        assert_eq!(hex(&top[124..]), "00080143");
        assert!(top[..124].iter().all(|&b| b == 0));
    }

    /// Polynomials over GF(2) as bit vectors, little-endian in `u64`s, for
    /// checking the generated table. Tests only: nothing here is constant
    /// time, and nothing needs to be.
    mod gf2 {
        pub type Poly = Vec<u64>;

        pub fn degree(p: &[u64]) -> Option<usize> {
            (0..p.len()).rev().find(|&i| p[i] != 0)
                .map(|i| i * 64 + 63 - p[i].leading_zeros() as usize)
        }

        pub fn from_exponents(exponents: &[usize]) -> Poly {
            let mut p = vec![0u64; exponents.iter().max().unwrap() / 64 + 1];
            for &e in exponents {
                p[e / 64] ^= 1 << (e % 64);
            }
            p
        }

        /// `acc ^= src * x^shift`, growing `acc` as needed.
        fn xor_shifted(acc: &mut Poly, src: &[u64], shift: usize) {
            let (words, bits) = (shift / 64, shift % 64);
            if acc.len() < src.len() + words + 1 {
                acc.resize(src.len() + words + 1, 0);
            }
            for (i, &w) in src.iter().enumerate() {
                acc[i + words] ^= w << bits;
                if bits != 0 {
                    acc[i + words + 1] ^= w >> (64 - bits);
                }
            }
        }

        /// `p * x^-n`, dropping the bits below `x^n`.
        fn shift_down(p: &[u64], n: usize) -> Poly {
            let (words, bits) = (n / 64, n % 64);
            (words..p.len()).map(|i| {
                let high = if bits != 0 && i + 1 < p.len() { p[i + 1] << (64 - bits) } else { 0 };
                (p[i] >> bits) | high
            }).collect()
        }

        /// `p mod x^n`.
        fn truncate(p: &mut Poly, n: usize) {
            let (words, bits) = (n / 64, n % 64);
            for (i, w) in p.iter_mut().enumerate() {
                if i > words || (i == words && bits == 0) {
                    *w = 0;
                } else if i == words {
                    *w &= (1u64 << bits) - 1;
                }
            }
        }

        /// `a mod m`, a degree at a time from the top.
        pub fn reduce(mut a: Poly, m: &[u64]) -> Poly {
            let dm = degree(m).unwrap();
            while let Some(da) = degree(&a) {
                if da < dm {
                    break;
                }
                xor_shifted(&mut a, m, da - dm);
            }
            a
        }

        /// `p mod (x^n + sum of x^e for e in low)`: the part from `x^n` up
        /// folds back down as copies shifted by each `e`, until none is
        /// left.
        pub fn reduce_sparse(mut p: Poly, n: usize, low: &[usize]) -> Poly {
            while degree(&p).is_some_and(|d| d >= n) {
                let high = shift_down(&p, n);
                truncate(&mut p, n);
                for &e in low {
                    xor_shifted(&mut p, &high, e);
                }
            }
            // Below x^n now, so the words above it are zero; drop them, or
            // squaring doubles the length every time.
            p.truncate(n / 64 + 1);
            p
        }

        /// Each bit i moves to 2i.
        pub fn square(p: &[u64]) -> Poly {
            fn spread(x: u32) -> u64 {
                let mut x = x as u64;
                x = (x | (x << 16)) & 0x0000_ffff_0000_ffff;
                x = (x | (x << 8)) & 0x00ff_00ff_00ff_00ff;
                x = (x | (x << 4)) & 0x0f0f_0f0f_0f0f_0f0f;
                x = (x | (x << 2)) & 0x3333_3333_3333_3333;
                (x | (x << 1)) & 0x5555_5555_5555_5555
            }
            p.iter().flat_map(|&w| [spread(w as u32), spread((w >> 32) as u32)]).collect()
        }

        pub fn gcd(mut a: Poly, mut b: Poly) -> Poly {
            while degree(&b).is_some() {
                let r = reduce(a, &b);
                a = b;
                b = r;
            }
            a
        }

        /// Rabin's test for f = x^n + sum of x^e for e in low: irreducible
        /// exactly when x^(2^n) = x mod f and gcd(x^(2^(n/q)) - x, f) = 1
        /// for every prime q dividing n.
        pub fn irreducible(n: usize, low: &[usize]) -> bool {
            let mut all = low.to_vec();
            all.push(n);
            let f = from_exponents(&all);
            let x_to_2_to_minus_x = |k: usize| {
                let mut p = from_exponents(&[1]);
                for _ in 0..k {
                    p = reduce_sparse(square(&p), n, low);
                }
                p[0] ^= 2;
                p
            };
            if degree(&x_to_2_to_minus_x(n)).is_some() {
                return false;
            }
            let mut primes = Vec::new();
            let (mut m, mut d) = (n, 2);
            while m > 1 {
                if m % d == 0 {
                    primes.push(d);
                    while m % d == 0 {
                        m /= d;
                    }
                }
                d += 1;
            }
            primes.iter().all(|q| degree(&gcd(f.clone(), x_to_2_to_minus_x(n / q))) == Some(0))
        }
    }

    /// Every polynomial in the generated table is irreducible, checked
    /// here independently of the script that chose it. That it is also
    /// the one the rule picks is the script's check, against three
    /// libraries' tables.
    #[test]
    fn test_every_tabled_polynomial_is_irreducible() {
        for &(bytes, exponents) in super::super::cmac_polynomials::POLYNOMIALS {
            let n = bytes * 8;
            let low: Vec<usize> = exponents.iter().map(|&e| e as usize).collect();
            assert!(gf2::irreducible(n, &low), "{} bits", n);
            assert!(low.len() == 2 || low.len() == 4);
            assert_eq!(*low.last().unwrap(), 0);
            // A reducible polynomial of the same degree must fail, or the
            // test proves nothing: x + 1 divides one with an even number
            // of terms, and by Swan's theorem every trinomial of a degree
            // divisible by 8 is reducible.
            assert!(!gf2::irreducible(n, &[2, 1, 0]), "{} bits", n);
            assert!(!gf2::irreducible(n, &[1, 0]), "{} bits", n);
        }
    }

    /// The empty message is padded and uses K2. An implementation testing
    /// only `len % b == 0` gets every other length right and this one
    /// wrong.
    #[test]
    fn test_the_empty_message_is_padded() {
        let key = vec![0x11u8; 16];
        let empty = cmac("aes", &key, &[]).unwrap();

        // A single 0x80 byte is padded to the *same* block as the empty
        // message would be if the padding rule were skipped - so these
        // must differ.
        let one = cmac("aes", &key, &[0x80]).unwrap();
        assert_ne!(empty, one);

        // And a full block of zeros is not the same as the empty message
        // either: one uses K1, the other K2.
        let block = cmac("aes", &key, &[0u8; 16]).unwrap();
        assert_ne!(empty, block);
    }

    /// The length-extension forgery that plain CBC-MAC allows must not
    /// work. Given T over a one-block M, the message `M || (M xor T)` has
    /// the same CBC-MAC tag and a different CMAC tag.
    #[test]
    fn test_the_cbc_mac_forgery_does_not_work() {
        let key = vec![0x2au8; 16];
        let message = vec![0x42u8; 16];
        let tag = cmac("aes", &key, &message).unwrap();

        let mut forged = message.clone();
        forged.extend(message.iter().zip(tag.iter()).map(|(m, t)| m ^ t));
        assert_ne!(cmac("aes", &key, &forged).unwrap(), tag);
    }

    /// Streaming in ragged pieces must equal one call - and the last
    /// block is special, so a streaming implementation that absorbed
    /// every full block as it arrived would get the final one wrong.
    #[test]
    fn test_streaming_equals_one_call() {
        let key = vec![0x5cu8; 16];
        let message: Vec<u8> = (0..200u32).map(|i| (i * 13 + 7) as u8).collect();

        for length in 0..=100usize {
            let whole = cmac("aes", &key, &message[..length]).unwrap();
            for chunk in [1usize, 5, 15, 16, 17, 32] {
                let mut mac = Cmac::with_key("aes", &key).unwrap();
                for piece in message[..length].chunks(chunk) {
                    mac.update(piece);
                }
                assert_eq!(mac.digest(), whole,
                           "length {} in chunks of {}", length, chunk);
            }
        }
    }

    #[test]
    fn test_digest_does_not_consume_the_state() {
        let mut mac = Cmac::with_key("aes", &[0x33u8; 16]).unwrap();
        mac.update(b"abc");
        let first = mac.digest();
        assert_eq!(mac.digest(), first);
        mac.update(b"def");
        assert_eq!(mac.digest(), cmac("aes", &[0x33u8; 16], b"abcdef").unwrap());
    }

    /// Over the GOST ciphers, which is what this is for. The tags are
    /// whatever they are - the check that they are *right* is
    /// `scripts/diff_check.py` - but the shapes have to be right here.
    #[test]
    fn test_it_works_over_the_gost_ciphers() {
        let key = vec![0x77u8; 32];
        let kuznyechik = cmac("kuznyechik", &key, b"message").unwrap();
        let magma = cmac("magma", &key, b"message").unwrap();

        assert_eq!(kuznyechik.len(), 16, "Kuznyechik's block is 128 bits");
        assert_eq!(magma.len(), 8, "Magma's block is 64 bits");
        assert_ne!(kuznyechik[..8], magma[..]);
    }

    /// Blowfish and DES have 64 bit blocks, so they exercise the other
    /// Rb. 3DES too, which is what the differential corpus compares
    /// against OpenSSL.
    #[test]
    fn test_the_64_bit_block_ciphers_work() {
        for name in ["des", "3des", "blowfish", "magma"] {
            let key = match name {
                "des" => vec![0x01u8; 8],
                "3des" => vec![0x01u8; 24],
                "blowfish" => vec![0x01u8; 16],
                _ => vec![0x01u8; 32],
            };
            let tag = cmac(name, &key, b"sixty four bit block").unwrap();
            assert_eq!(tag.len(), 8, "{}", name);
        }
    }

    /// `reset` takes a CMAC back to the start of a message under the
    /// same key: after a message of any length, whole blocks or a
    /// ragged end, a reset CMAC tags the next message as a fresh one
    /// would. EAX relies on it for its three OMACs per message.
    #[test]
    fn test_reset_is_a_fresh_start() {
        let mut shared = Cmac::with_key("aes", &[0x42; 16]).unwrap();
        for length in [0usize, 5, 16, 17, 32, 40] {
            let first = vec![1u8; length];
            shared.update(&first);
            let _ = shared.digest();
            shared.reset();
            shared.update(b"the next message");
            let mut fresh = Cmac::with_key("aes", &[0x42; 16]).unwrap();
            fresh.update(b"the next message");
            assert_eq!(shared.digest(), fresh.digest(), "after {length} bytes");
            shared.reset();
        }
    }
}
