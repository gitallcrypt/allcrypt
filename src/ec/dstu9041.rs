/*!
DSTU 9041:2020: Ukraine's public-key encryption, over twisted Edwards
curves.

A hybrid scheme, ECIES in shape: a one-time key `ε`, `R = ε·P` sent as
its `x`, and the `x` of `T = ε·Q` as the key of a Kalyna key wrap
around the formatted message. Messages are short - at most 200 bits on
E256/1 and 424 on E512/1 - as the scheme is for keys.

## The curves

`x^2 + a·y^2 = 1 + d·x^2·y^2` over `GF(p)`, `a = 2`, `p ≡ 5 (mod 8)`:
the twisted Edwards form with `x` and `y` exchanged, so the identity is
`(1, 0)` and `−(x, y) = (x, −y)`. Two curves, `dstu9041-e256-1` and
`dstu9041-e512-1`, the first of the standard's Tables В.1 and В.3 and
the ones its worked examples use; their parameters are in
`src/ec/dstu9041_params.rs`. The group has order `4n`, `n` prime.

Addition is the standard's projective formula (Annex Б.4), used for
doubling too. `a = 2` is not a square modulo such a `p`, so the formula
is not complete on the whole curve; its exceptions are pairs whose sum
or difference is a point at infinity, which has order 2 or 4, so two
points of odd order never meet one. Every point this module multiplies
is checked to have order `n` first, and a point that does not would
end at `Z = 0`, which is rejected.

## Encryption (clause 11)

- `M~` is the message left-padded with zero bits to `l_max(p)`, and
  `l_M` its length in bits as 16 bits, big endian.
- `M' = i_H || H || l_M || M~`, where `i_H = 01` names Kupyna-256 and
  `H` is the **last** `l_H` bits (32 or 64) of Kupyna-256 of
  `l_M || M~`. `M'` is exactly one field element long.
- `r = x(ε·P)` and `κ = x(ε·Q)`, both big endian at the field's width.
- `t` is Kalyna's key wrap (DSTU 7624, Kalyna-256/256 or -512/512 by
  the field) under `κ` of **`M'` followed by a block of zeros**: what
  both witnesses wrap, and what reproduces the standard's examples.
- The ciphertext is `r || t`, four field elements long.

## Decryption (clause 12)

`r` must be below `p` and not 0, 1 or `p − 1`, `r^2 ≠ a/d`, and
`v = (1 − r^2)/(a − d·r^2)` a nonzero square; then `R' = (r, √v)`,
which must have order `n` (beyond the clause, as both witnesses check:
the curve's points of order 2 and 4 would otherwise give away the
private key modulo 4). `κ = x(e·R')`, which does not depend on which
square root was taken. The unwrapped data must end in the zero block,
name Kupyna-256, give a length from 1 to `l_max(p)`, carry the right
hash, and be zero above the message's bits. Every one of these failures
is the same error.

## Constant time

The scalar multiplications are a fixed window of four bits over the
field's width, the sixteen-entry table read whole under masks, in
`bignum::fixed`'s Montgomery arithmetic; the private key and `ε` are
checked against the range by constant-time comparison, whose verdict is
the one branch. `scripts/ct_check.py`'s case `dstu9041_public_key`
checks that. The tests on `r` are on public data. The key wrap and the
hash in decryption are Kalyna and Kupyna, which are tables, as
everywhere here.

## Where the vectors come from

`vectors/dstu9041.vec`, written by `scripts/make_dstu9041_vectors.py`
from uacrypt's `hazmat::dstu9041` and li0ard's TypeScript `dstu9041`,
which must agree: the standard's examples Г.1 and Г.3, public keys,
ciphertexts at every message length, and ciphertexts both refuse.
*/

use crate::bignum::ct::Secret;
use crate::bignum::fixed::{is_zero, select, Arith, Mont};
use crate::bignum::BigUint;
use crate::block_ciphers::kalyna::Kalyna;
use crate::block_ciphers::kalyna_modes;
use crate::ec::dstu9041_params::{Params, CURVES};
use crate::hash_functions::kupyna::Kupyna;
use crate::hash_functions::HashFunction;

/// The curves by name, in the order of `CURVES`.
pub const NAMES: [&str; 2] = ["dstu9041-e256-1", "dstu9041-e512-1"];

/// `i_H` for Kupyna-256, the one hash the standard's examples use.
const KUPYNA_256: u8 = 1;

const INVALID: &str = "Invalid DSTU 9041 ciphertext, or the wrong private key.";

#[derive(Clone)]
pub struct Curve {
    name: &'static str,
    params: &'static Params,
    p: BigUint,
    d: BigUint,
    n: BigUint,
    gx: BigUint,
    gy: BigUint,
}

impl Curve {
    /// A curve by name: `dstu9041-e256-1` or `dstu9041-e512-1`, or the
    /// standard's own `E256/1` and `E512/1`, in any case.
    pub fn by_name(name: &str) -> Result<Curve, String> {
        let lower = name.to_ascii_lowercase();
        let index = match lower.as_str() {
            "dstu9041-e256-1" | "e256/1" => 0,
            "dstu9041-e512-1" | "e512/1" => 1,
            _ => return Err(format!("Unknown DSTU 9041 curve {name:?}. Known: {}.",
                                    NAMES.join(", "))),
        };
        let params = &CURVES[index];
        let hex = |s: &str| BigUint::from_hex(s);
        Ok(Curve { name: NAMES[index], params, p: hex(params.p)?, d: hex(params.d)?,
                   n: hex(params.n)?, gx: hex(params.gx)?, gy: hex(params.gy)? })
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The field's width in bytes, 32 or 64: the length of `x`, of a
    /// private key and of `M'`.
    pub fn field_bytes(&self) -> usize {
        self.params.bits / 8
    }

    /// The field's prime `p`.
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// The base point's order `n`.
    pub fn order(&self) -> &BigUint {
        &self.n
    }

    /// `l_max(p)`: the longest message, in bits.
    pub fn max_message_bits(&self) -> usize {
        self.params.l_max
    }

    /// The ciphertext's length: `r` and the wrap of two field elements.
    pub fn ciphertext_bytes(&self) -> usize {
        4 * self.field_bytes()
    }

    /// The public key `e·P` of the private key `e`, `x || y` big endian.
    ///
    /// # Errors
    /// A key outside `2 ..= n − 2`, the standard's range.
    pub fn public_key(&self, private: &[u8]) -> Result<Vec<u8>, String> {
        match self.field_bytes() {
            32 => Engine::<4>::new(self)?.public_key(private),
            _ => Engine::<8>::new(self)?.public_key(private),
        }
    }

    /// Check a public key, `x || y`: on the curve, not the identity, and
    /// of order `n`.
    pub fn check_public_key(&self, public: &[u8]) -> Result<(), String> {
        match self.field_bytes() {
            32 => Engine::<4>::new(self)?.point(public).map(|_| ()),
            _ => Engine::<8>::new(self)?.point(public).map(|_| ()),
        }
    }

    /// Encrypt `message`, of `bits` bits (`message` holds them right
    /// aligned in `⌈bits/8⌉` bytes, the bits above them zero), to
    /// `public`, with the one-time key `epsilon`.
    ///
    /// # Errors
    /// A message of no bits or more than `l_max(p)`, bytes that do not
    /// match `bits`, a public key `check_public_key` refuses, or
    /// `epsilon` outside `2 ..= n − 2`.
    pub fn encrypt(&self, public: &[u8], message: &[u8], bits: usize, epsilon: &[u8])
                   -> Result<Vec<u8>, String> {
        let m_prime = self.format(message, bits)?;
        match self.field_bytes() {
            32 => Engine::<4>::new(self)?.encrypt(public, &m_prime, epsilon),
            _ => Engine::<8>::new(self)?.encrypt(public, &m_prime, epsilon),
        }
    }

    /// Decrypt with the private key: the message, right aligned in
    /// `⌈bits/8⌉` bytes, and its length in bits.
    ///
    /// # Errors
    /// One error for every way a ciphertext can be wrong, and for a
    /// private key outside `2 ..= n − 2`.
    pub fn decrypt(&self, private: &[u8], ciphertext: &[u8]) -> Result<(Vec<u8>, usize), String> {
        let m_prime = match self.field_bytes() {
            32 => Engine::<4>::new(self)?.decrypt(private, ciphertext)?,
            _ => Engine::<8>::new(self)?.decrypt(private, ciphertext)?,
        };
        self.parse(&m_prime)
    }

    /// `l_M || M~`, what the hash covers.
    fn hashed(&self, bits: usize, m_tilde: &[u8]) -> Vec<u8> {
        let mut input = (bits as u16).to_be_bytes().to_vec();
        input.extend_from_slice(m_tilde);
        input
    }

    /// The last `l_H` bits of Kupyna-256.
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut kupyna = Kupyna::new(256).expect("Kupyna-256 exists");
        kupyna.update(data);
        let digest = kupyna.digest();
        digest[digest.len() - self.params.l_h / 8..].to_vec()
    }

    /// `M' = i_H || H || l_M || M~` (clause 11, steps 2 to 8).
    fn format(&self, message: &[u8], bits: usize) -> Result<Vec<u8>, String> {
        let l_max = self.params.l_max;
        if bits == 0 || bits > l_max {
            return Err(format!("A DSTU 9041 message on {} is 1 to {l_max} bits, not {bits}.",
                               self.name));
        }
        if message.len() != bits.div_ceil(8) {
            return Err(format!("{bits} bits are {} bytes, not {}.", bits.div_ceil(8),
                               message.len()));
        }
        if !bits.is_multiple_of(8) && message[0] >> (bits % 8) != 0 {
            return Err(format!("The bits of the first byte above the message's {bits} must \
                                be zero."));
        }
        let mut m_tilde = vec![0u8; l_max / 8];
        let start = m_tilde.len() - message.len();
        m_tilde[start..].copy_from_slice(message);
        let mut m_prime = vec![KUPYNA_256];
        m_prime.extend(self.hash(&self.hashed(bits, &m_tilde)));
        m_prime.extend_from_slice(&(bits as u16).to_be_bytes());
        m_prime.extend_from_slice(&m_tilde);
        debug_assert_eq!(m_prime.len(), self.field_bytes());
        Ok(m_prime)
    }

    /// Clause 12, steps 10 to 18, every check folded into one verdict.
    fn parse(&self, m_prime: &[u8]) -> Result<(Vec<u8>, usize), String> {
        let h = self.params.l_h / 8;
        let l_max = self.params.l_max;
        let bits = usize::from(u16::from_be_bytes([m_prime[1 + h], m_prime[2 + h]]));
        let m_tilde = &m_prime[3 + h..];
        let mut bad = u8::from(m_prime[0] != KUPYNA_256) | u8::from(bits == 0)
            | u8::from(bits > l_max);
        let length = bits.min(l_max);
        bad |= u8::from(crate::bignum::ct::bytes_differ(
            &self.hash(&self.hashed(bits, m_tilde)), &m_prime[1..1 + h]));
        // Every bit of `M~` above the message's must be zero: byte by
        // byte, each byte's allowed bits a mask of the length.
        for (i, &byte) in m_tilde.iter().enumerate() {
            let low_bit = 8 * (m_tilde.len() - 1 - i);
            let allowed = if length >= low_bit + 8 {
                0xff
            } else if length > low_bit {
                (1u8 << (length - low_bit)) - 1
            } else {
                0
            };
            bad |= u8::from(byte & !allowed != 0);
        }
        if bad != 0 {
            return Err(INVALID.to_string());
        }
        Ok((m_tilde[m_tilde.len() - bits.div_ceil(8)..].to_vec(), bits))
    }
}

/// A point `(X : Y : Z)`, `x = X/Z`, `y = Y/Z`, in the Montgomery domain.
#[derive(Clone, Copy)]
struct Proj<const N: usize> {
    x: [u64; N],
    y: [u64; N],
    z: [u64; N],
}

impl<const N: usize> Proj<N> {
    fn select(&self, other: &Self, choice: u64) -> Self {
        Proj { x: select(&self.x, &other.x, choice), y: select(&self.y, &other.y, choice),
               z: select(&self.z, &other.z, choice) }
    }
}

/// One curve's arithmetic at `N` limbs.
struct Engine<'a, const N: usize> {
    curve: &'a Curve,
    f: Mont<N>,
    /// `a = 2` and `d`, in the domain.
    a: [u64; N],
    d: [u64; N],
}

/// A public number as `N` limbs.
fn limbs<const N: usize>(value: &BigUint) -> [u64; N] {
    let mut out = [0u64; N];
    out[..value.limbs().len()].copy_from_slice(value.limbs());
    out
}

impl<'a, const N: usize> Engine<'a, N> {
    fn new(curve: &'a Curve) -> Result<Self, String> {
        let f = Mont::new(limbs(&curve.p))?;
        let a = f.enter(&limbs(&BigUint::from_u64(2)));
        let d = f.enter(&limbs(&curve.d));
        Ok(Engine { curve, f, a, d })
    }

    fn identity(&self) -> Proj<N> {
        Proj { x: self.f.one(), y: [0; N], z: self.f.one() }
    }

    fn base(&self) -> Proj<N> {
        Proj { x: self.f.enter(&limbs(&self.curve.gx)), y: self.f.enter(&limbs(&self.curve.gy)),
               z: self.f.one() }
    }

    /// Annex Б.4: `A = Z1·Z2`, `B = A^2`, `C = X1·X2`, `D = Y1·Y2`,
    /// `E = d·C·D`, `F = B − E`, `G = B + E`, and
    /// `X3 = A·G·(C − a·D)`, `Y3 = A·F·((X1 + Y1)(X2 + Y2) − C − D)`,
    /// `Z3 = F·G`.
    fn add(&self, p: &Proj<N>, q: &Proj<N>) -> Proj<N> {
        let f = &self.f;
        let a = f.mul(&p.z, &q.z);
        let b = f.square(&a);
        let c = f.mul(&p.x, &q.x);
        let d = f.mul(&p.y, &q.y);
        let e = f.mul(&self.d, &f.mul(&c, &d));
        let ff = f.sub(&b, &e);
        let g = f.add(&b, &e);
        let cross = f.mul(&f.add(&p.x, &p.y), &f.add(&q.x, &q.y));
        Proj {
            x: f.mul(&f.mul(&a, &g), &f.sub(&c, &f.mul(&self.a, &d))),
            y: f.mul(&f.mul(&a, &ff), &f.sub(&f.sub(&cross, &c), &d)),
            z: f.mul(&ff, &g),
        }
    }

    /// `k·p`, `k` below `2^(64N)`: a fixed window of four bits, the
    /// table of `0·p .. 15·p` read whole under masks.
    fn mul(&self, p: &Proj<N>, k: &[u64; N]) -> Proj<N> {
        let mut table = [self.identity(); 16];
        for i in 1..16 {
            table[i] = self.add(&table[i - 1], p);
        }
        let mut acc = self.identity();
        for i in (0..16 * N).rev() {
            for _ in 0..4 {
                acc = self.add(&acc, &acc);
            }
            let nibble = (k[i / 16] >> (4 * (i % 16))) & 15;
            let mut entry = table[0];
            for (j, candidate) in table.iter().enumerate().skip(1) {
                entry = entry.select(candidate, is_zero(&[j as u64 ^ nibble]));
            }
            acc = self.add(&acc, &entry);
        }
        acc
    }

    /// Whether `p` is the identity: `X = Z ≠ 0` and `Y = 0`. On public
    /// points.
    fn is_identity(&self, p: &Proj<N>) -> bool {
        is_zero(&p.z) == 0 && p.x == p.z && is_zero(&p.y) == 1
    }

    /// `(x, y)` out of the domain; `Z` is never zero for the points this
    /// is given, which have order `n`.
    fn affine(&self, p: &Proj<N>) -> ([u64; N], [u64; N]) {
        let inverse = self.f.invert(&p.z);
        (self.f.leave(&self.f.mul(&p.x, &inverse)), self.f.leave(&self.f.mul(&p.y, &inverse)))
    }

    fn bytes(&self, v: &[u64; N]) -> Vec<u8> {
        let width = self.curve.field_bytes();
        let mut out = Vec::with_capacity(width);
        for limb in v.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        out.split_off(out.len() - width)
    }

    /// A scalar in `2 ..= n − 2`, compared in constant time.
    fn scalar(&self, bytes: &[u8], what: &str) -> Result<[u64; N], String> {
        let s = Secret::from_bytes_be(bytes, N)
            .map_err(|_| format!("The {what} is wider than the curve's order."))?;
        let two = Secret::from_biguint(&BigUint::from_u64(2), N)?;
        let n_minus_1 = Secret::from_biguint(&self.curve.n.sub(&BigUint::one())?, N)?;
        let low = s.ct_lt(&two);
        let high = !s.ct_lt(&n_minus_1);
        if (low | high) != 0 {
            return Err(format!("The {what} must be from 2 to n - 2."));
        }
        let mut out = [0u64; N];
        out.copy_from_slice(s.limbs());
        Ok(out)
    }

    /// Whether `n·p` is the identity.
    fn has_order_n(&self, p: &Proj<N>) -> bool {
        self.is_identity(&self.mul(p, &limbs(&self.curve.n)))
    }

    fn on_curve(&self, x: &[u64; N], y: &[u64; N]) -> bool {
        let f = &self.f;
        let (x2, y2) = (f.square(x), f.square(y));
        let left = f.add(&x2, &f.mul(&self.a, &y2));
        let right = f.add(&f.one(), &f.mul(&self.d, &f.mul(&x2, &y2)));
        left == right
    }

    /// A public key, `x || y`, as a point of order `n`.
    fn point(&self, public: &[u8]) -> Result<Proj<N>, String> {
        let width = self.curve.field_bytes();
        if public.len() != 2 * width {
            return Err(format!("A DSTU 9041 public key on {} is {} bytes, x || y, not {}.",
                               self.curve.name, 2 * width, public.len()));
        }
        let x = BigUint::from_bytes_be(&public[..width]);
        let y = BigUint::from_bytes_be(&public[width..]);
        if x >= self.curve.p || y >= self.curve.p {
            return Err("A public key's coordinates must be below p.".to_string());
        }
        let (x, y) = (self.f.enter(&limbs(&x)), self.f.enter(&limbs(&y)));
        let point = Proj { x, y, z: self.f.one() };
        if !self.on_curve(&x, &y) || self.is_identity(&point) || !self.has_order_n(&point) {
            return Err("The public key is not a point of order n on the curve.".to_string());
        }
        Ok(point)
    }

    fn public_key(&self, private: &[u8]) -> Result<Vec<u8>, String> {
        let e = self.scalar(private, "private key")?;
        let (x, y) = self.affine(&self.mul(&self.base(), &e));
        let mut out = self.bytes(&x);
        out.extend(self.bytes(&y));
        Ok(out)
    }

    fn kalyna(&self, kappa: &[u8]) -> Result<Kalyna, String> {
        Kalyna::new(self.curve.field_bytes(), kappa)
    }

    fn encrypt(&self, public: &[u8], m_prime: &[u8], epsilon: &[u8]) -> Result<Vec<u8>, String> {
        let q = self.point(public)?;
        let eps = self.scalar(epsilon, "one-time key")?;
        let (r, _) = self.affine(&self.mul(&self.base(), &eps));
        let (kappa, _) = self.affine(&self.mul(&q, &eps));
        let mut data = m_prime.to_vec();
        data.resize(2 * m_prime.len(), 0);
        let t = kalyna_modes::wrap(&mut self.kalyna(&self.bytes(&kappa))?, &data)?;
        let mut out = self.bytes(&r);
        out.extend(t);
        Ok(out)
    }

    /// `y` with `y^2 = v` for a square `v`, in the domain (clause 6.7,
    /// for `p ≡ 5 mod 8`): `z = v^((p+3)/8)`, times `2^((p−1)/4)` when
    /// `v^((p−1)/4) = −1`. On public values.
    fn sqrt(&self, v: &[u64; N]) -> [u64; N] {
        let f = &self.f;
        let p = &self.curve.p;
        let quarter = limbs(&p.sub(&BigUint::one()).expect("p > 1").shr(2));
        let eighth = limbs(&p.add(&BigUint::from_u64(3)).shr(3));
        let z = f.pow_public(v, &eighth);
        let minus_one = f.sub(&[0; N], &f.one());
        if f.pow_public(v, &quarter) == minus_one {
            let two = f.add(&f.one(), &f.one());
            f.mul(&z, &f.pow_public(&two, &quarter))
        } else {
            z
        }
    }

    /// `R'` from `r` (clause 12, steps 2 to 6), of order `n`. On public
    /// values.
    fn recover(&self, r: &[u8]) -> Option<Proj<N>> {
        let f = &self.f;
        let p = &self.curve.p;
        let value = BigUint::from_bytes_be(r);
        if value >= *p || value.is_zero() || value.is_one()
            || value == p.sub(&BigUint::one()).ok()? {
            return None;
        }
        let x = f.enter(&limbs(&value));
        let x2 = f.square(&x);
        let denominator = f.sub(&self.a, &f.mul(&self.d, &x2));
        // r^2 = a/d is the denominator's zero.
        if is_zero(&denominator) == 1 {
            return None;
        }
        let v = f.mul(&f.sub(&f.one(), &x2), &f.invert(&denominator));
        let half = limbs(&p.sub(&BigUint::one()).ok()?.shr(1));
        if f.pow_public(&v, &half) != f.one() {
            return None;
        }
        let point = Proj { x, y: self.sqrt(&v), z: f.one() };
        if !self.has_order_n(&point) {
            return None;
        }
        Some(point)
    }

    /// Clause 12, steps 1 to 9: `M'`, unwrapped and with the zero block
    /// checked and removed.
    fn decrypt(&self, private: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let e = self.scalar(private, "private key")?;
        let width = self.curve.field_bytes();
        if ciphertext.len() != 4 * width {
            return Err(INVALID.to_string());
        }
        let r = self.recover(&ciphertext[..width]).ok_or_else(|| INVALID.to_string())?;
        let (kappa, _) = self.affine(&self.mul(&r, &e));
        let mut data = kalyna_modes::unwrap(&mut self.kalyna(&self.bytes(&kappa))?,
                                            &ciphertext[width..])
            .map_err(|_| INVALID.to_string())?;
        if data.len() != 2 * width
            || crate::bignum::ct::bytes_differ(&data[width..], &vec![0u8; width]) {
            return Err(INVALID.to_string());
        }
        data.truncate(width);
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_curves_are_what_they_say() {
        for name in NAMES {
            let curve = Curve::by_name(name).unwrap();
            assert_eq!(curve.p.limbs()[0] & 7, 5, "{name}: p is 5 mod 8");
            assert_eq!(curve.p.bit_len(), 8 * curve.field_bytes());
            let check = |engine_ok: bool| assert!(engine_ok, "{name}");
            match curve.field_bytes() {
                32 => {
                    let e = Engine::<4>::new(&curve).unwrap();
                    let g = e.base();
                    check(e.on_curve(&g.x, &g.y) && e.has_order_n(&g) && !e.is_identity(&g));
                }
                _ => {
                    let e = Engine::<8>::new(&curve).unwrap();
                    let g = e.base();
                    check(e.on_curve(&g.x, &g.y) && e.has_order_n(&g) && !e.is_identity(&g));
                }
            }
            // M' is one field element.
            assert_eq!(1 + curve.params.l_h / 8 + 2 + curve.params.l_max / 8,
                       curve.field_bytes());
        }
    }

    #[test]
    fn test_the_identity_is_one_zero() {
        let curve = Curve::by_name("dstu9041-e256-1").unwrap();
        let e = Engine::<4>::new(&curve).unwrap();
        let id = e.identity();
        assert!(e.on_curve(&id.x, &id.y));
        let g = e.base();
        let sum = e.add(&g, &id);
        assert_eq!(e.affine(&sum), e.affine(&g));
        // n - 1 times P is -P: the same x, the other y.
        let n_minus_1 = limbs(&curve.n.sub(&BigUint::one()).unwrap());
        let (x, y) = e.affine(&e.mul(&g, &n_minus_1));
        let (gx, gy) = e.affine(&g);
        assert_eq!(x, gx);
        assert_eq!(e.f.add(&e.f.enter(&y), &e.f.enter(&gy)), [0; 4]);
    }

    #[test]
    fn test_the_small_points_are_refused() {
        // r = p - 1 is the point of order 2, (p - 1, 0).
        for name in NAMES {
            let curve = Curve::by_name(name).unwrap();
            let width = curve.field_bytes();
            let p_minus_1 = curve.p.sub(&BigUint::one()).unwrap().to_bytes_be_padded(width)
                .unwrap();
            let mut ciphertext = p_minus_1.clone();
            ciphertext.resize(4 * width, 0);
            let mut key = vec![0u8; width];
            key[width - 1] = 5;
            assert_eq!(curve.decrypt(&key, &ciphertext).unwrap_err(), INVALID);
        }
    }

    #[test]
    fn test_scalars_are_range_checked() {
        let curve = Curve::by_name("dstu9041-e256-1").unwrap();
        assert!(curve.public_key(&[1]).is_err());
        assert!(curve.public_key(&[0]).is_err());
        assert!(curve.public_key(&[2]).is_ok());
        let n = curve.n.clone();
        let minus = |k: u64| n.sub(&BigUint::from_u64(k)).unwrap().to_bytes_be();
        assert!(curve.public_key(&minus(1)).is_err());
        assert!(curve.public_key(&minus(2)).is_ok());
        assert!(curve.public_key(&n.to_bytes_be()).is_err());
        assert!(curve.public_key(&[1; 33]).is_err());
    }

    /// A ciphertext of any data, wrapped as `encrypt` wraps `M'` and its
    /// zero block.
    fn seal(curve: &Curve, private: &[u8], data: &[u8]) -> Vec<u8> {
        let e = Engine::<4>::new(curve).unwrap();
        let public = e.public_key(private).unwrap();
        let q = e.point(&public).unwrap();
        let eps = e.scalar(&[0x17; 31], "").unwrap();
        let (r, _) = e.affine(&e.mul(&e.base(), &eps));
        let (kappa, _) = e.affine(&e.mul(&q, &eps));
        let mut out = e.bytes(&r);
        out.extend(kalyna_modes::wrap(&mut e.kalyna(&e.bytes(&kappa)).unwrap(), data).unwrap());
        out
    }

    /// Each check on the unwrapped data, on data that passes every other
    /// one: the zero block, `i_H`, the length, the hash and the bits
    /// above the message.
    #[test]
    fn test_each_check_on_m_prime() {
        let curve = Curve::by_name("dstu9041-e256-1").unwrap();
        let private = [0x0b; 32];
        let open = |m_prime: &[u8], tail: &[u8]| {
            curve.decrypt(&private, &seal(&curve, &private, &[m_prime, tail].concat()))
        };
        // M' with a given length field and the hash recomputed to match.
        let with_length = |message: &[u8], bits: usize, stated: u16| -> Vec<u8> {
            let mut m_prime = curve.format(message, bits).unwrap();
            m_prime[5..7].copy_from_slice(&stated.to_be_bytes());
            let hash = curve.hash(&curve.hashed(stated as usize, &m_prime[7..]));
            m_prime[1..5].copy_from_slice(&hash);
            m_prime
        };
        let zeros = [0u8; 32];
        let good = curve.format(&[0x30], 6).unwrap();
        assert_eq!(open(&good, &zeros).unwrap(), (vec![0x30], 6));
        // Something in the second block.
        let mut tail = zeros;
        tail[31] = 1;
        assert_eq!(open(&good, &tail).unwrap_err(), INVALID);
        // Another hash's identifier.
        let mut other = good.clone();
        other[0] = 2;
        assert_eq!(open(&other, &zeros).unwrap_err(), INVALID);
        // A wrong hash, in each of its bytes.
        for i in 1..5 {
            let mut wrong = good.clone();
            wrong[i] ^= 1;
            assert_eq!(open(&wrong, &zeros).unwrap_err(), INVALID, "hash byte {i}");
        }
        // The same bits said to be one fewer: bit 5 is then above them.
        assert_eq!(open(&with_length(&[0x30], 6, 5), &zeros).unwrap_err(), INVALID);
        // And one more, which is fine, and whole bytes.
        assert_eq!(open(&with_length(&[0x30], 6, 7), &zeros).unwrap(), (vec![0x30], 7));
        assert_eq!(open(&with_length(&[0x30, 0], 16, 9), &zeros).unwrap_err(), INVALID);
        // No bits, of a message of zeros, which nothing else refuses; and
        // more than l_max.
        assert_eq!(open(&with_length(&[0x00], 8, 0), &zeros).unwrap_err(), INVALID);
        assert_eq!(open(&with_length(&[0x01], 8, 0), &zeros).unwrap_err(), INVALID);
        assert_eq!(open(&with_length(&[0x01], 8, 201), &zeros).unwrap_err(), INVALID);
        assert_eq!(open(&with_length(&[0x01], 8, 200), &zeros).unwrap(),
                   ([vec![0u8; 24], vec![1]].concat(), 200));
    }

    #[test]
    fn test_coordinates_must_be_below_p() {
        let curve = Curve::by_name("dstu9041-e256-1").unwrap();
        // (p, 0) and (p + 1, 0), which reduce to (0, 0) and the identity.
        for x in [curve.p.clone(), curve.p.add(&BigUint::one())] {
            let mut public = x.to_bytes_be_padded(32).unwrap();
            public.resize(64, 0);
            assert!(curve.check_public_key(&public).unwrap_err().contains("below p"));
        }
    }

    /// The attack the order check on `R'` stops: `R'` the base point
    /// plus the point of order 2, and `t` wrapped under the key that
    /// point gives - which an attacker can try for both values of `e`
    /// modulo 2. Without the check this decrypts.
    #[test]
    fn test_r_outside_the_group_is_refused() {
        let curve = Curve::by_name("dstu9041-e256-1").unwrap();
        let e = Engine::<4>::new(&curve).unwrap();
        let private = [0x0b; 32];
        let order_two = Proj { x: e.f.sub(&[0; 4], &e.f.one()), y: [0; 4], z: e.f.one() };
        let outside = e.add(&e.base(), &order_two);
        assert!(!e.has_order_n(&outside));
        let (r, _) = e.affine(&outside);
        let (kappa, _) = e.affine(&e.mul(&outside, &e.scalar(&private, "").unwrap()));
        let mut data = curve.format(&[1], 8).unwrap();
        data.resize(64, 0);
        let mut ciphertext = e.bytes(&r);
        ciphertext.extend(kalyna_modes::wrap(&mut e.kalyna(&e.bytes(&kappa)).unwrap(), &data)
            .unwrap());
        assert_eq!(curve.decrypt(&private, &ciphertext).unwrap_err(), INVALID);
    }

    /// `Z = 0` is no point, and in particular not the identity.
    #[test]
    fn test_z_zero_is_not_the_identity() {
        let curve = Curve::by_name("dstu9041-e256-1").unwrap();
        let e = Engine::<4>::new(&curve).unwrap();
        assert!(e.is_identity(&e.identity()));
        assert!(!e.is_identity(&Proj { x: [0; 4], y: [0; 4], z: [0; 4] }));
    }

    #[test]
    fn test_messages_are_checked() {
        let curve = Curve::by_name("dstu9041-e256-1").unwrap();
        assert!(curve.format(&[], 0).is_err());
        assert!(curve.format(&[1], 9).is_err());
        assert!(curve.format(&[0x10], 4).is_err());
        assert!(curve.format(&[0x0f], 4).is_ok());
        assert!(curve.format(&[0; 25], 200).is_ok());
        assert!(curve.format(&[0; 26], 201).is_err());
    }
}
