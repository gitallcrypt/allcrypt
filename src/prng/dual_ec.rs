/*
Dual_EC_DRBG (NIST SP 800-90A, January 2012, section 10.3.1; withdrawn in
revision 1, June 2015), and the back door in it.

## The generator

Two points on a NIST curve: `P`, the curve's generator, and `Q`, a
constant from SP 800-90A appendix A.1 given without any account of where
it came from. The state is a number `s` of `seedlen` bits (256, 384 or
521), and each block of output is

    s  = x(t * P)                      t is s, or s XOR the additional input
    r  = x(s * Q)
    output the rightmost outlen bits of r     (240, 368 or 504 bits)

and at the end of a request `s = x(s * P)` once more, which the 2007
revision added so that a captured state does not give away the output
already produced.

## The back door

`P` and `Q` are two generators of a group of prime order, so `P = e * Q`
for some `e`. Whoever knows `e` - whoever chose `Q` - can undo the
generator. An output block is `x(s * Q)` with 16 bits (17 for P-521)
cut off the top. Put those bits back, all 65,536 ways, and roughly half
of the guesses are the x coordinate of a point `R`; for the right one
`R = +-s * Q`, so

    x(e * R) = x(s * e * Q) = x(s * P)

which is the generator's next state. One block of output, and one more to
pick the right guess out of the thirty thousand, give the state, and
from the state every later output until fresh entropy arrives. Shumow
and Ferguson presented this at the CRYPTO 2007 rump session, months
after the standard was published. In 2013 documents from the Snowden
archive described a NIST standard the NSA had worked to control;
NIST reopened SP 800-90A for comment and withdrew Dual_EC_DRBG in 2015.
RSA's BSAFE library had used it as its default since 2004, and Juniper's
ScreenOS used it with a `Q` of Juniper's own - which somebody else
replaced in the source in 2012 (CVE-2015-7756).

What the standard lacked was any evidence that nobody holds `e` for the
published `Q`. A `Q` derived from a seed through a hash, as the other
curve constants of the period were, would have provided it.
`Parameters::with_q` takes another `Q`, as Juniper's code did; the
generator is otherwise unchanged by it.

## Details that are easy to get wrong

  * **The state is not reduced modulo the group order.** `s` is any
    `seedlen`-bit number, and `s * P` uses it as it stands (which is the
    same point as `s mod n` times `P`, but the multiplication must accept
    a scalar at or above `n`).
  * **P-521's seedlen is 521 bits, not a whole number of bytes.** Hash_df
    returns the leftmost 521 bits of its 66 bytes, so the state is those
    bytes shifted right by seven; going back into Hash_df (`pad8`) it is
    shifted left again. Keeping the 66 bytes as the state, unshifted,
    gives a generator that runs and matches nothing.
  * **The additional input is hashed to seedlen bits and XORed into `s`
    for the first block only.** Every later block of the same request
    runs on the state alone.
  * **Each block uses the rightmost bits of `r`**, not the leftmost: the
    leftmost are the ones dropped, which is exactly what the attack has
    to guess.
*/

use crate::bignum::ct::Secret;
use crate::bignum::BigUint;
use crate::ec::{curves, Curve, Point};
use crate::hash_functions::sha1::SHA1;
use crate::hash_functions::sha2::{SHA224, SHA256, SHA384, SHA512};
use crate::hash_functions::HashFunction;

/// SP 800-90A appendix A.1's `Q` for each curve, as big-endian hex. Copied
/// out of OpenSSL's FIPS module 2.0.5 source by
/// `scripts/make_dual_ec_vectors.py`, which also requires them to equal
/// Bouncy Castle's; `vectors/dual_ec.vec` repeats them, and a test
/// requires the three to agree. `P` is each curve's generator.
const Q_P256: (&str, &str) = (
    "c97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192",
    "b28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046",
);
const Q_P384: (&str, &str) = (
    "8e722de3125bddb05580164bfe20b8b432216a62926c57502ceede31c47816edd1e89769124179d0b695106428815065",
    "023b1660dd701d0839fd45eec36f9ee7b32e13b315dc02610aa1b636e346df671f790f84c5e09b05674dbb7e45c803dd",
);
const Q_P521: (&str, &str) = (
    "01b9fa3e518d683c6b65763694ac8efbaec6fab44f2276171a42726507dd08add4c3b3f4c1ebc5b1222ddba077f722943b24c3edfa0f85fe24d0c8c01591f0be6f63",
    "01f3bdba585295d9a1110d1df1f9430ef8442c5018976ff3437ef91b81dc0b8132c8d5c39c32d0e004a3092b7d327c0e7a4d26d2c7b69b58f9066652911e457779de",
);

/// Blocks between reseeds: SP 800-90A table 4's `reseed_interval`, 2^32.
const RESEED_INTERVAL: u64 = 1 << 32;

/// The three curves SP 800-90A defines points for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DualEcCurve {
    P256,
    P384,
    P521,
}

impl DualEcCurve {
    pub fn from_name(name: &str) -> Result<DualEcCurve, String> {
        match name.to_ascii_uppercase().replace('_', "-").as_str() {
            "P-256" | "P256" => Ok(DualEcCurve::P256),
            "P-384" | "P384" => Ok(DualEcCurve::P384),
            "P-521" | "P521" => Ok(DualEcCurve::P521),
            _ => Err(format!("Dual_EC_DRBG is defined on P-256, P-384 and P-521, not {name:?}.")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            DualEcCurve::P256 => "P-256",
            DualEcCurve::P384 => "P-384",
            DualEcCurve::P521 => "P-521",
        }
    }

    pub fn curve(self) -> Curve {
        match self {
            DualEcCurve::P256 => curves::p256(),
            DualEcCurve::P384 => curves::p384(),
            DualEcCurve::P521 => curves::p521(),
        }
    }

    /// The state's length in bits.
    pub fn seedlen(self) -> usize {
        match self {
            DualEcCurve::P256 => 256,
            DualEcCurve::P384 => 384,
            DualEcCurve::P521 => 521,
        }
    }

    /// Output bits per block: the x coordinate less 16 bits, rounded
    /// down to whole bytes (SP 800-90A table 4's max_outlen).
    pub fn outlen(self) -> usize {
        match self {
            DualEcCurve::P256 => 240,
            DualEcCurve::P384 => 368,
            DualEcCurve::P521 => 504,
        }
    }

    pub fn security_strength(self) -> usize {
        match self {
            DualEcCurve::P256 => 128,
            DualEcCurve::P384 => 192,
            DualEcCurve::P521 => 256,
        }
    }

    fn seed_bytes(self) -> usize {
        self.seedlen().div_ceil(8)
    }

    /// Bits of padding in the state's bytes: 7 for P-521, 0 otherwise.
    fn exbits(self) -> usize {
        8 * self.seed_bytes() - self.seedlen()
    }

    /// The standard's `Q`.
    pub fn standard_q(self) -> Point {
        let (x, y) = match self {
            DualEcCurve::P256 => Q_P256,
            DualEcCurve::P384 => Q_P384,
            DualEcCurve::P521 => Q_P521,
        };
        Point::new(BigUint::from_hex(x).expect("hex"), BigUint::from_hex(y).expect("hex"))
    }
}

/// The hashes Hash_df may use, with the security strength each supports
/// (SP 800-57 part 1, as SP 800-90A table 4 applies it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrbgHash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DrbgHash {
    pub fn from_name(name: &str) -> Result<DrbgHash, String> {
        match name.to_ascii_lowercase().replace('-', "").as_str() {
            "sha1" => Ok(DrbgHash::Sha1),
            "sha224" => Ok(DrbgHash::Sha224),
            "sha256" => Ok(DrbgHash::Sha256),
            "sha384" => Ok(DrbgHash::Sha384),
            "sha512" => Ok(DrbgHash::Sha512),
            _ => Err(format!("Dual_EC_DRBG's Hash_df takes SHA-1 or a SHA-2 hash, not {name:?}.")),
        }
    }

    fn strength(self) -> usize {
        match self {
            DrbgHash::Sha1 => 128,
            DrbgHash::Sha224 => 192,
            _ => 256,
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<H: HashFunction>(mut h: H, parts: &[&[u8]]) -> Vec<u8> {
            for part in parts {
                h.update(part);
            }
            h.digest()
        }
        match self {
            DrbgHash::Sha1 => run(SHA1::new(&[]), parts),
            DrbgHash::Sha224 => run(SHA224::new(&[]), parts),
            DrbgHash::Sha256 => run(SHA256::new(&[]), parts),
            DrbgHash::Sha384 => run(SHA384::new(&[]), parts),
            DrbgHash::Sha512 => run(SHA512::new(&[], 512), parts),
        }
    }
}

/// Hash_df (SP 800-90A 10.4.1): `bits` bits as `ceil(bits / 8)` bytes,
/// the leftmost `bits` of the concatenated hashes - so when `bits` is not
/// a multiple of eight, the last byte's low bits are zero.
pub fn hash_df(hash: DrbgHash, parts: &[&[u8]], bits: usize) -> Vec<u8> {
    let bytes = bits.div_ceil(8);
    let mut out = Vec::with_capacity(bytes + 64);
    let mut header = [0u8; 5];
    header[0] = 1;
    header[1..].copy_from_slice(&(bits as u32).to_be_bytes());
    while out.len() < bytes {
        let mut all: Vec<&[u8]> = vec![&header];
        all.extend_from_slice(parts);
        out.extend(hash.digest(&all));
        header[0] = header[0].wrapping_add(1);
    }
    out.truncate(bytes);
    if !bits.is_multiple_of(8) {
        out[bytes - 1] &= 0xffu8 << (8 - bits % 8);
    }
    out
}

/// `bytes` shifted right by `bits` (< 8), the same length.
fn shift_right(bytes: &[u8], bits: usize) -> Vec<u8> {
    if bits == 0 {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; bytes.len()];
    let mut carry = 0u8;
    for (o, b) in out.iter_mut().zip(bytes) {
        *o = (b >> bits) | carry;
        carry = b << (8 - bits);
    }
    out
}

/// `bytes` shifted left by `bits` (< 8), the same length: `pad8`.
fn shift_left(bytes: &[u8], bits: usize) -> Vec<u8> {
    if bits == 0 {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; bytes.len()];
    for i in 0..bytes.len() {
        let next = bytes.get(i + 1).copied().unwrap_or(0);
        out[i] = (bytes[i] << bits) | (next >> (8 - bits));
    }
    out
}

/// A curve, its `P` and `Q`, and the arithmetic the generator needs.
#[derive(Clone, Debug)]
pub struct Parameters {
    pub which: DualEcCurve,
    pub curve: Curve,
    pub q: Point,
}

impl Parameters {
    /// The standard's points.
    pub fn standard(which: DualEcCurve) -> Parameters {
        Parameters { which, curve: which.curve(), q: which.standard_q() }
    }

    /// Another `Q`, which must be a point of the curve other than the
    /// identity - Juniper's, say.
    pub fn with_q(which: DualEcCurve, q: Point) -> Result<Parameters, String> {
        let curve = which.curve();
        curve.validate(&q)?;
        if q.is_identity() {
            return Err("Q cannot be the point at infinity.".to_string());
        }
        Ok(Parameters { which, curve, q })
    }

    /// `x(k * point)` as `seed_bytes` big-endian bytes, for a scalar
    /// given the same way. Constant time in the scalar, which is the
    /// generator's state.
    fn x_of_multiple(&self, point: &Point, k: &[u8]) -> Result<Vec<u8>, String> {
        let width = self.curve.p.limbs().len().max(self.curve.n.limbs().len());
        let scalar = Secret::from_bytes_be(k, width)?;
        let product = self.curve.scalar_mul_secret_bytes(point, &scalar)?;
        let x = product.x().ok_or("The state is a multiple of the group order, so the \
                                   product is the point at infinity.")?;
        x.to_bytes_be_padded(self.which.seed_bytes())
    }

    /// One block from a state `s` that has already been through
    /// `x(t * P)`: the rightmost outlen bits of `x(s * Q)`.
    fn block(&self, s: &[u8]) -> Result<Vec<u8>, String> {
        let r = self.x_of_multiple(&self.q, s)?;
        Ok(r[r.len() - self.which.outlen() / 8..].to_vec())
    }

    fn step(&self, s: &[u8]) -> Result<Vec<u8>, String> {
        self.x_of_multiple(&self.curve.g, s)
    }
}

/// Dual_EC_DRBG with Hash_df, without prediction resistance unless the
/// caller asks for it by reseeding (SP 800-90A 9.3.1: prediction
/// resistance is a reseed before the request).
#[derive(Clone)]
pub struct DualEcDrbg {
    params: Parameters,
    hash: DrbgHash,
    /// `s`, as `seed_bytes` big-endian bytes holding a seedlen-bit number.
    s: Vec<u8>,
    reseed_counter: u64,
}

impl DualEcDrbg {
    /// Instantiate (SP 800-90A 10.3.1.2): `s = Hash_df(entropy || nonce ||
    /// personalization, seedlen)`.
    pub fn new(params: Parameters, hash: DrbgHash, entropy: &[u8], nonce: &[u8],
               personalization: &[u8]) -> Result<DualEcDrbg, String> {
        let which = params.which;
        if hash.strength() < which.security_strength() {
            return Err(format!("{} is not strong enough for Dual_EC_DRBG on {}, which \
                                needs {} bits.", hash_name(hash), which.name(),
                               which.security_strength()));
        }
        check_entropy(which, entropy)?;
        let seed = hash_df(hash, &[entropy, nonce, personalization], which.seedlen());
        Ok(DualEcDrbg { s: shift_right(&seed, which.exbits()), params, hash,
                        reseed_counter: 0 })
    }

    pub fn parameters(&self) -> &Parameters {
        &self.params
    }

    /// Reseed (10.3.1.3): `s = Hash_df(pad8(s) || entropy || additional_input)`.
    pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), String> {
        let which = self.params.which;
        check_entropy(which, entropy)?;
        let padded = shift_left(&self.s, which.exbits());
        let seed = hash_df(self.hash, &[&padded, entropy, additional_input], which.seedlen());
        self.s = shift_right(&seed, which.exbits());
        self.reseed_counter = 0;
        Ok(())
    }

    /// Generate (10.3.1.4) `n` bytes.
    pub fn generate(&mut self, n: usize, additional_input: &[u8]) -> Result<Vec<u8>, String> {
        let which = self.params.which;
        let block_bytes = which.outlen() / 8;
        let blocks = n.div_ceil(block_bytes) as u64;
        if self.reseed_counter + blocks > RESEED_INTERVAL {
            return Err("Dual_EC_DRBG needs a reseed: 2^32 blocks since the last one."
                       .to_string());
        }
        let mut t = self.s.clone();
        if !additional_input.is_empty() {
            let hashed = hash_df(self.hash, &[additional_input], which.seedlen());
            for (a, b) in t.iter_mut().zip(shift_right(&hashed, which.exbits())) {
                *a ^= b;
            }
        }
        let mut out = Vec::with_capacity(n + block_bytes);
        let mut s = t;
        while out.len() < n {
            s = self.params.step(&s)?;
            out.extend(self.params.block(&s)?);
            self.reseed_counter += 1;
        }
        out.truncate(n);
        self.s = self.params.step(&s)?;
        Ok(out)
    }
}

fn hash_name(hash: DrbgHash) -> &'static str {
    match hash {
        DrbgHash::Sha1 => "SHA-1",
        DrbgHash::Sha224 => "SHA-224",
        DrbgHash::Sha256 => "SHA-256",
        DrbgHash::Sha384 => "SHA-384",
        DrbgHash::Sha512 => "SHA-512",
    }
}

fn check_entropy(which: DualEcCurve, entropy: &[u8]) -> Result<(), String> {
    let need = which.security_strength() / 8;
    if entropy.len() < need {
        return Err(format!("Dual_EC_DRBG on {} needs at least {need} bytes of entropy; \
                            this is {}.", which.name(), entropy.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_standard_points_are_on_their_curves_and_p_is_the_generator() {
        for which in [DualEcCurve::P256, DualEcCurve::P384, DualEcCurve::P521] {
            let params = Parameters::standard(which);
            params.curve.validate(&params.q).unwrap();
            assert_ne!(params.q, params.curve.g);
        }
    }

    #[test]
    fn test_hash_df_keeps_the_leftmost_bits() {
        let full = hash_df(DrbgHash::Sha512, &[b"abc"], 528);
        let short = hash_df(DrbgHash::Sha512, &[b"abc"], 521);
        assert_eq!(short.len(), 66);
        // Not a truncation of the 528 bit output: the bit count is hashed.
        assert_ne!(short[..65], full[..65]);
        assert_eq!(short[65] & 0x7f, 0);
    }

    #[test]
    fn test_pad8_undoes_the_shift() {
        let bytes: Vec<u8> = (0..66u8).map(|i| i.wrapping_mul(37)).collect();
        let mut aligned = bytes.clone();
        aligned[65] &= 0x80;
        assert_eq!(shift_left(&shift_right(&aligned, 7), 7), aligned);
    }

    #[test]
    fn test_weak_hashes_and_short_entropy_are_refused() {
        let p521 = Parameters::standard(DualEcCurve::P521);
        assert!(DualEcDrbg::new(p521.clone(), DrbgHash::Sha224, &[0; 32], &[], &[]).is_err());
        assert!(DualEcDrbg::new(p521.clone(), DrbgHash::Sha256, &[0; 31], &[], &[]).is_err());
        assert!(DualEcDrbg::new(p521, DrbgHash::Sha256, &[0; 32], &[], &[]).is_ok());
    }

    /// Generating in two requests is not generating once: each request
    /// ends with an extra `x(s * P)`, so the second request does not
    /// continue the first's blocks.
    #[test]
    fn test_requests_are_not_a_stream() {
        let params = Parameters::standard(DualEcCurve::P256);
        let mut one = DualEcDrbg::new(params.clone(), DrbgHash::Sha256, &[1; 16], &[], &[])
            .unwrap();
        let mut two = one.clone();
        let whole = one.generate(60, &[]).unwrap();
        let mut parts = two.generate(30, &[]).unwrap();
        parts.extend(two.generate(30, &[]).unwrap());
        assert_eq!(whole[..30], parts[..30]);
        assert_ne!(whole[30..], parts[30..]);
    }
}
