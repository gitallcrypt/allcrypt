/*
EdDSA: Ed25519 and Ed448, RFC 8032.

Signatures on twisted Edwards curves. The conspicuous gap next to
`x25519` (key agreement on Montgomery form) and `ecdsa` (signatures on
Weierstrass form): Ed25519 is the signature everything modern uses -
SSH, Signal, TLS 1.3's `ed25519` scheme, Tor, Git - and Ed448 is its
larger sibling from the same RFC.

## Deterministic, and that is the point

ECDSA needs a fresh random nonce per signature and leaks the private key
outright if one is ever reused. RFC 6979 fixes that by deriving the
nonce from the message; EdDSA builds the same idea into the scheme:

    r = H(prefix || message)          -- prefix is half the key's hash
    R = r * B
    S = (r + H(R || A || message) * s) mod L

No randomness at any point. The same key and message always produce the
same signature, which also makes every test here reproducible.

## What is easy to get wrong

**The private key is not the scalar.** It is 32 (or 57) random bytes,
and the scalar comes from hashing them: the first half of the hash,
clamped, is `s`, and the second half is the `prefix` above. Signing with
the raw key bytes as the scalar produces valid-looking signatures that
no other implementation verifies.

**Clamping is not optional and differs between the curves.** Ed25519
clears the low three bits, clears the top bit and sets bit 254; Ed448
clears the low two bits, sets the top bit of byte 55 and clears byte 56
entirely. Skipping it gives signatures that verify against ourselves and
nobody else.

**The point encoding is the y coordinate with x's sign in the top bit**,
little endian - not the SEC1 encoding the Weierstrass curves here use.
Decoding has to recover x by square root and then pick the root whose
low bit matches that sign; picking the wrong root gives a point that is
still on the curve, so nothing downstream errors.

**Ed448 hashes with SHAKE256, not a fixed-length hash**, and prefixes
every hash with the domain string `"SigEd448"` plus two bytes. Ed25519
has no such prefix in its basic form. Using one scheme's hashing for the
other is the single easiest way to produce a self-consistent EdDSA that
interoperates with nothing.

**The two curves have different `a`.** Ed25519 is *twisted*, with
`a = -1`; Ed448 is untwisted, with `a = 1`. The addition formula below
takes `a` from the curve rather than baking in a sign, because a sign
baked in is a formula that is silently wrong on one of the two and
perfectly self-consistent on the other.

## What is here and what is not

Pure Ed25519 and pure Ed448. **Ed25519ctx, Ed25519ph and Ed448ph are
not implemented**, and their vectors in RFC 8032 section 7 are skipped
by name rather than ignored - `test_the_unimplemented_variants_are_named`
fails if one of them quietly becomes unrecognised, which is what would
happen if the vector parser broke.

## Arithmetic

Two copies of the group, deliberately.

**Signing, key derivation and verification run on `ec::edwards`**:
extended coordinates over the fixed-limb fields `field25519` and
`field448`, complete addition and doubling formulas, and a four-bit
fixed-window scalar multiplication whose table lookups read every entry.
The arithmetic modulo the group order `L` - reducing the 64 or 114 byte
hashes, and `S = r + k*s` - is `bignum::Montgomery` on fixed-width
`Secret`s. Nothing in signing branches on or indexes by the key, the
nonce or anything derived from them, which `scripts/ct_check.py`'s
`eddsa_sign` row measures.

**The `BigUint` copy below** - `Curve`, `Point`, `add`, `multiply`,
`decode`, `encode` - is the first implementation: projective
coordinates, the unified addition of Bernstein-Birkner-Joye-Lange-Peters,
and double-and-add. It branches on every bit of the scalar and is about
a hundred times slower. It stays, test-only, because the tests compare
`ec::edwards` against it - two implementations of one group, written
from different formulas, that have to agree on every point.
*/

use std::sync::OnceLock;

use crate::bignum::{BigUint, Montgomery, Secret};
use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::{sha2, HashFunction};

use super::edwards;

/// Which curve, and everything that differs between them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variant {
    /// Ed25519, RFC 8032 section 5.1. 32 byte keys and 64 byte
    /// signatures, hashed with SHA-512.
    Ed25519,
    /// Ed448, RFC 8032 section 5.2. 57 byte keys and 114 byte
    /// signatures, hashed with SHAKE256 and domain separated.
    Ed448,
}

impl Variant {
    pub fn name(self) -> &'static str {
        match self {
            Variant::Ed25519 => "ed25519",
            Variant::Ed448 => "ed448",
        }
    }

    /// Bytes in a private key, a public key and a point encoding.
    pub fn key_len(self) -> usize {
        match self {
            Variant::Ed25519 => 32,
            Variant::Ed448 => 57,
        }
    }

    /// The number of bits a scalar can occupy, which is a property of
    /// the variant and so **public**.
    ///
    /// `reference::multiply` iterates this many times rather than
    /// `scalar.bit_len()`. The latter is the value's own magnitude -
    /// `BigUint` is normalised, so its limb count measures it - and a
    /// loop that runs that many times announces it. Ed25519's clamp
    /// sets bit 254 and clears 255, and Ed448's sets bit 447, so these
    /// bounds cover every clamped scalar; the nonce `r` and the public
    /// scalars in verification are reduced mod L and are smaller still.
    pub fn scalar_bits(self) -> usize {
        match self {
            Variant::Ed25519 => 256,
            Variant::Ed448 => 456,
        }
    }

    /// Bytes in a signature: a point and a scalar.
    pub fn signature_len(self) -> usize {
        self.key_len() * 2
    }

    /// The hash output the key expansion needs: twice the key length.
    ///
    /// For Ed25519 this is SHA-512's natural 64 bytes. For Ed448 it is
    /// 114 bytes of SHAKE256, which is why the hash has to be an
    /// extendable output function rather than a digest - there is no
    /// fixed-length hash of that size.
    fn expanded_len(self) -> usize {
        self.key_len() * 2
    }

    /// Hash the two things the signature is built from: `r` and `k`.
    ///
    /// Ed25519 uses SHA-512 and no domain string. Ed448 uses SHAKE256
    /// and prefixes these two hashes with `dom4` - the string
    /// `"SigEd448"`, a one byte pre-hash flag and a one byte context
    /// length - so the two schemes' hashing is not interchangeable even
    /// before the algorithm differs.
    ///
    /// **`dom4` is not applied to the key expansion**, which is
    /// [`Variant::hash_private_key`]. RFC 8032 section 5.2.5 step 1 and
    /// section 5.2.6 step 1 both say plain `SHAKE256(x, 114)`, and only
    /// steps 2 and 4 carry `dom4`. Applying it everywhere gives a
    /// perfectly self-consistent Ed448 with the wrong public key for
    /// every private key - which is exactly what happened here, and
    /// what the RFC's vectors caught.
    fn hash(self, parts: &[&[u8]], context: &[u8], length: usize) -> Vec<u8> {
        match self {
            Variant::Ed25519 => self.hash_private_key(parts, length),
            Variant::Ed448 => {
                let mut sponge = match Keccak::shake(256, length) {
                    Ok(sponge) => sponge,
                    // 256 is a SHAKE security level, so this cannot
                    // happen; an empty hash rather than a panic keeps
                    // the promise that nothing here panics.
                    Err(_) => return Vec::new(),
                };
                sponge.update(b"SigEd448");
                // The pre-hash flag, always zero for pure Ed448, then
                // the context length and the context itself.
                sponge.update(&[0u8]);
                sponge.update(&[context.len() as u8]);
                sponge.update(context);
                for part in parts {
                    sponge.update(part);
                }
                sponge.squeeze(length)
            }
        }
    }

    /// The undomained hash, which is what expands a private key.
    fn hash_private_key(self, parts: &[&[u8]], length: usize) -> Vec<u8> {
        match self {
            Variant::Ed25519 => {
                let mut hash = sha2::SHA512::new(&[], 512);
                for part in parts {
                    hash.update(part);
                }
                let mut out = hash.digest();
                out.truncate(length);
                out
            }
            Variant::Ed448 => {
                let mut sponge = match Keccak::shake(256, length) {
                    Ok(sponge) => sponge,
                    Err(_) => return Vec::new(),
                };
                for part in parts {
                    sponge.update(part);
                }
                sponge.squeeze(length)
            }
        }
    }

    /// Clamp the expanded key's first half into a scalar.
    fn clamp(self, half: &mut [u8]) {
        match self {
            Variant::Ed25519 => {
                half[0] &= 0xf8; // clear the low three bits
                half[31] &= 0x7f; // clear the top bit
                half[31] |= 0x40; // set bit 254
            }
            Variant::Ed448 => {
                half[0] &= 0xfc; // clear the low two bits
                half[55] |= 0x80; // set the top bit of byte 55
                half[56] = 0; // and clear the last byte entirely
            }
        }
    }
}

// --------------------------------------------------------------- the API ---

/// Expand a private key into its clamped scalar, as little-endian
/// bytes, and the prefix. Both are secret; neither goes near `BigUint`.
fn expand(variant: Variant, private: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hash = variant.hash_private_key(&[private], variant.expanded_len());
    let key_len = variant.key_len();
    let mut scalar = hash[..key_len].to_vec();
    variant.clamp(&mut scalar);
    (scalar, hash[key_len..].to_vec())
}

/// The group order `L`, which is **not** the number of points on the
/// curve: the cofactor is 8 for Ed25519 and 4 for Ed448.
///
/// RFC 8032 sections 5.1 and 5.2 give both orders in decimal; these are
/// the same numbers in hex, and `test_the_base_point_has_the_stated_order`
/// is what checks them rather than a second reading.
pub(crate) fn group_order(variant: Variant) -> BigUint {
    let hex = match variant {
        Variant::Ed25519 => "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        Variant::Ed448 => "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                           7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
    };
    BigUint::from_hex(hex).unwrap_or_default()
}

/// Arithmetic modulo the group order `L`, constant time.
///
/// `L` is public, so building the `Montgomery` context (a division by
/// it) leaks nothing; it is built once per process. Everything after
/// that is on fixed-width `Secret`s.
pub(crate) struct Order {
    mont: Montgomery,
    /// `L` as a number, for verification's public "is S reduced" test.
    value: BigUint,
}

pub(crate) fn order(variant: Variant) -> Result<&'static Order, String> {
    static ED25519: OnceLock<Result<Order, String>> = OnceLock::new();
    static ED448: OnceLock<Result<Order, String>> = OnceLock::new();
    let cell = match variant {
        Variant::Ed25519 => &ED25519,
        Variant::Ed448 => &ED448,
    };
    cell.get_or_init(|| {
        let value = group_order(variant);
        Ok(Order { mont: Montgomery::new(&value)?, value })
    })
    .as_ref()
    .map_err(Clone::clone)
}

impl Order {
    /// A little-endian number of any length, reduced mod `L`.
    ///
    /// Horner's rule over chunks of `k` limbs, most significant first:
    /// each step puts the running value in the high half of a `2k` limb
    /// number and the next chunk in the low half, and reduces that with
    /// `reduce_wide`. The running value is below `L`, so the input to
    /// each reduction is below `L * R`, which is its precondition. The
    /// number of steps depends on the length alone.
    pub(crate) fn reduce(&self, bytes: &[u8]) -> Result<Secret, String> {
        let k = self.mont.limbs();
        let width = 8 * k;
        let mut acc = Secret::zero(k);
        for chunk in bytes.chunks(width).rev() {
            let mut wide = vec![0u64; 2 * k];
            for (i, &byte) in chunk.iter().enumerate() {
                wide[i / 8] |= u64::from(byte) << (8 * (i % 8));
            }
            wide[k..].copy_from_slice(acc.limbs());
            acc = self.mont.reduce_wide(&wide)?;
        }
        Ok(acc)
    }

    /// `a * b + c mod L`, for reduced operands.
    pub(crate) fn mul_add(&self, a: &Secret, b: &Secret, c: &Secret) -> Secret {
        self.mont.add_mod(&self.mont.mul_mod(a, b), c)
    }

    /// `-a mod L`, for a reduced `a`.
    pub(crate) fn negate(&self, a: &Secret) -> Secret {
        self.mont.sub_mod(&Secret::zero(self.mont.limbs()), a)
    }

    /// A reduced value as `length` little-endian bytes.
    pub(crate) fn encode(&self, value: &Secret, length: usize) -> Vec<u8> {
        let mut bytes = value.to_bytes_be();
        bytes.reverse();
        bytes.resize(length, 0);
        bytes
    }
}

/// `scalar * B`, encoded. Constant time in the scalar.
pub(crate) fn base_multiple(variant: Variant, scalar: &[u8]) -> Vec<u8> {
    fn on<F: edwards::Field>(curve: &edwards::Curve<F>, scalar: &[u8]) -> Vec<u8> {
        curve.encode(&curve.multiply_base(scalar))
    }
    match variant {
        Variant::Ed25519 => on(edwards::ed25519(), scalar),
        Variant::Ed448 => on(edwards::ed448(), scalar),
    }
}

/// Whether `S*B == R + k*A`, as `S*B + k*(-A) == R` with the doublings
/// shared. Every input is public. The errors name which encoding is
/// not a point, the public key's first.
fn verification_equation(variant: Variant, public: &[u8], big_r: &[u8], s: &[u8],
                         k: &[u8]) -> Result<bool, String> {
    fn on<F: edwards::Field>(curve: &edwards::Curve<F>, public: &[u8], big_r: &[u8],
                             s: &[u8], k: &[u8]) -> Result<bool, String> {
        let a = curve.decode(public)
            .ok_or_else(|| "The public key does not decode to a point.".to_string())?;
        let big_r = curve.decode(big_r)
            .ok_or_else(|| "The signature's R does not decode to a point.".to_string())?;
        let left = curve.multiply_two(s, &curve.base(), k, &curve.negate(&a));
        Ok(curve.equals(&left, &big_r))
    }
    match variant {
        Variant::Ed25519 => on(edwards::ed25519(), public, big_r, s, k),
        Variant::Ed448 => on(edwards::ed448(), public, big_r, s, k),
    }
}

/// A fresh key pair, as `(private, public)`.
///
/// The private key is **not** clamped on the way in, unlike X25519's:
/// clamping happens to the *hash* of these bytes, so storing a clamped
/// private key would change which key it is. Every byte of it is used.
///
/// # Errors
/// The system random source failing.
pub fn generate_key_pair(variant: Variant) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut private = vec![0u8; variant.key_len()];
    crate::random::fill(&mut private)?;
    let public = public_key(variant, &private)?;
    Ok((private, public))
}

/// Whether these bytes are a public key: the right length, a canonical
/// `y`, and a `y` that is on the curve.
///
/// Not every string of the right length is a point, so a caller that
/// stores keys wants this before it stores one.
pub fn is_public_key(variant: Variant, bytes: &[u8]) -> bool {
    match variant {
        Variant::Ed25519 => edwards::ed25519().decode(bytes).is_some(),
        Variant::Ed448 => edwards::ed448().decode(bytes).is_some(),
    }
}

/// The X25519 public key with the same discrete logarithm as an Ed25519
/// one: `u = (1 + y) / (1 - y)`, libsodium's
/// `crypto_sign_ed25519_pk_to_curve25519`.
///
/// Refused, as libsodium refuses them: bytes that are not a point, a
/// point of small order (whose `u` is shared by every key multiplied
/// into it), and a point outside the prime-order subgroup - a key with a
/// torsion component, which Ed25519 verification accepts and an
/// exchange would turn into a shared secret off by a known point.
///
/// # Errors
/// Any of those.
pub fn ed25519_public_to_x25519(public: &[u8]) -> Result<[u8; 32], String> {
    let curve = edwards::ed25519();
    let point = curve.decode(public)
        .ok_or("These bytes are not an Ed25519 public key.")?;
    if curve.is_identity(&curve.multiply(&[8], &point)) {
        return Err("This Ed25519 public key has small order; it has no X25519 \
                    counterpart worth having.".to_string());
    }
    let mut order = group_order(Variant::Ed25519).to_bytes_be();
    order.reverse();
    if !curve.is_identity(&curve.multiply(&order, &point)) {
        return Err("This Ed25519 public key is not in the prime-order subgroup.".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&curve.montgomery_u(&point)[..32]);
    Ok(out)
}

/// The X25519 private key for an Ed25519 one: the first half of
/// SHA-512 of the 32 byte seed, clamped - the scalar the Ed25519 key
/// signs with. libsodium's `crypto_sign_ed25519_sk_to_curve25519`, which
/// also returns it clamped.
///
/// # Errors
/// A private key that is not 32 bytes.
pub fn ed25519_private_to_x25519(private: &[u8]) -> Result<[u8; 32], String> {
    if private.len() != 32 {
        return Err(format!("An Ed25519 private key is 32 bytes; this one is {}.",
                           private.len()));
    }
    let digest = crate::hash_functions::sha2::SHA512::new(private, 512).digest();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    Ok(out)
}

/// The public key for a private key.
///
/// # Errors
/// A private key of the wrong length.
pub fn public_key(variant: Variant, private: &[u8]) -> Result<Vec<u8>, String> {
    if private.len() != variant.key_len() {
        return Err(format!(
            "An {} private key is {} bytes; this one is {}.",
            variant.name(),
            variant.key_len(),
            private.len()
        ));
    }
    let (scalar, _) = expand(variant, private);
    Ok(base_multiple(variant, &scalar))
}

/// Sign a message. Deterministic: no randomness anywhere.
///
/// `context` is Ed448's context string and must be empty for Ed25519,
/// which has no context in its basic form - Ed25519ctx is a different
/// scheme and is not implemented here.
///
/// # Errors
/// A private key of the wrong length, a context where none is allowed,
/// or a context longer than 255 bytes.
pub fn sign(
    variant: Variant,
    private: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, String> {
    if private.len() != variant.key_len() {
        return Err(format!(
            "An {} private key is {} bytes; this one is {}.",
            variant.name(),
            variant.key_len(),
            private.len()
        ));
    }
    if variant == Variant::Ed25519 && !context.is_empty() {
        return Err("Ed25519 has no context string. Ed25519ctx is a separate \
                    scheme and is not implemented here."
            .to_string());
    }
    if context.len() > 255 {
        return Err(format!(
            "An Ed448 context is at most 255 bytes; this one is {}.",
            context.len()
        ));
    }

    let order = order(variant)?;
    let key_len = variant.key_len();
    let (scalar, prefix) = expand(variant, private);
    let public = base_multiple(variant, &scalar);

    // r = H(prefix || message), reduced. This is where the randomness
    // would be in ECDSA, and its absence is the whole design.
    let r_bytes = variant.hash(&[&prefix, message], context, variant.expanded_len());
    let r = order.reduce(&r_bytes)?;
    let big_r = base_multiple(variant, &order.encode(&r, key_len));

    // S = (r + H(R || A || message) * s) mod L. The clamped scalar is
    // wider than L - the clamp sets a bit above it - so it is reduced
    // too before it is multiplied.
    let k_bytes =
        variant.hash(&[&big_r, &public, message], context, variant.expanded_len());
    let k = order.reduce(&k_bytes)?;
    let s = order.mul_add(&k, &order.reduce(&scalar)?, &r);

    let mut signature = big_r;
    signature.extend_from_slice(&order.encode(&s, key_len));
    Ok(signature)
}

/// Verify a signature.
///
/// Returns `Ok(())` only for a good one; every other outcome is an error
/// naming what was wrong, rather than a boolean a caller can forget to
/// check.
///
/// # Errors
/// Anything other than a valid signature, including a key or signature
/// of the wrong length, bytes that are not a point, and an unreduced
/// `S`.
pub fn verify(
    variant: Variant,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<(), String> {
    if public.len() != variant.key_len() {
        return Err(format!(
            "An {} public key is {} bytes; this one is {}.",
            variant.name(),
            variant.key_len(),
            public.len()
        ));
    }
    if signature.len() != variant.signature_len() {
        return Err(format!(
            "An {} signature is {} bytes; this one is {}.",
            variant.name(),
            variant.signature_len(),
            signature.len()
        ));
    }
    if variant == Variant::Ed25519 && !context.is_empty() {
        return Err("Ed25519 has no context string. Ed25519ctx is a separate \
                    scheme and is not implemented here."
            .to_string());
    }
    if context.len() > 255 {
        return Err(format!(
            "An Ed448 context is at most 255 bytes; this one is {}.",
            context.len()
        ));
    }

    let key_len = variant.key_len();
    let order = order(variant)?;
    let (big_r, s_bytes) = signature.split_at(key_len);

    let mut s_big_endian = s_bytes.to_vec();
    s_big_endian.reverse();
    // **S must be reduced.** An unreduced S gives a second valid
    // signature for the same message, which is how the "malleability"
    // problems in other implementations happen; RFC 8032 section 5.1.7
    // requires the check.
    let s_reduced = BigUint::from_bytes_be(&s_big_endian) < order.value;

    let k_bytes = variant.hash(&[big_r, public, message], context, variant.expanded_len());
    let k = order.encode(&order.reduce(&k_bytes)?, key_len);

    // Check S*B == R + k*A. The points are decoded inside, and a key or
    // R that is not a point is reported before an unreduced S.
    let holds = verification_equation(variant, public, big_r, s_bytes, &k)?;
    if !s_reduced {
        return Err("The signature's S is not reduced modulo the group order, \
                    which RFC 8032 requires."
            .to_string());
    }
    if holds {
        Ok(())
    } else {
        Err("The signature does not verify.".to_string())
    }
}

/// The first implementation of the group, on `BigUint`: the reference
/// `ec::edwards` is tested against. See the module comment.
#[cfg(test)]
pub(crate) mod reference {
    use super::*;

    // ------------------------------------------------------------- the curve ---

    /// A curve with its constants computed once.
    ///
    /// Everything below takes a `&Curve` rather than a `Variant`, because
    /// the constants are expensive: Ed25519's `d` costs a modular inversion
    /// to derive, and a scalar multiplication performs hundreds of
    /// additions.
    pub(crate) struct Curve {
        pub(crate) variant: Variant,
        /// The field prime.
        pub(crate) p: BigUint,
        /// The curve constant `d` of `a*x^2 + y^2 = 1 + d*x^2*y^2`.
        pub(crate) d: BigUint,
        /// `a`: `p - 1` (that is, `-1`) for Ed25519 and `1` for Ed448.
        pub(crate) a: BigUint,
        /// The group order `L`, which is **not** the number of points on
        /// the curve: the cofactor is 8 for Ed25519 and 4 for Ed448.
        pub(crate) order: BigUint,
    }

    impl Curve {
        pub(crate) fn new(variant: Variant) -> Curve {
            let one = BigUint::one();
            let p = match variant {
                // 2^255 - 19
                Variant::Ed25519 => sub(&one.shl(255), &BigUint::from_u64(19)),
                // 2^448 - 2^224 - 1
                Variant::Ed448 => sub(&sub(&one.shl(448), &one.shl(224)), &one),
            };

            let a = match variant {
                Variant::Ed25519 => sub(&p, &one),
                Variant::Ed448 => one.clone(),
            };

            let d = match variant {
                // -121665/121666 mod p
                Variant::Ed25519 => {
                    let numerator = sub(&p, &BigUint::from_u64(121665));
                    let denominator = BigUint::from_u64(121666);
                    mul_mod(&numerator, &invert(&denominator, &p), &p)
                }
                // -39081 mod p
                Variant::Ed448 => sub(&p, &BigUint::from_u64(39081)),
            };

            let order = group_order(variant);

        Curve { variant, p, d, a, order }
        }

        pub(crate) fn add_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
            let sum = x.add(y);
            if sum >= self.p {
                sub(&sum, &self.p)
            } else {
                sum
            }
        }

        pub(crate) fn sub_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
            if x >= y {
                sub(x, y)
            } else {
                sub(&x.add(&self.p), y)
            }
        }

        pub(crate) fn mul_mod(&self, x: &BigUint, y: &BigUint) -> BigUint {
            mul_mod(x, y, &self.p)
        }

        pub(crate) fn invert(&self, x: &BigUint) -> BigUint {
            invert(x, &self.p)
        }
    }

    /// `x - y`, where the caller has already established `x >= y`.
    ///
    /// `BigUint::sub` returns a `Result` because the type is unsigned.
    /// Every call here has established the ordering, so an error would be a
    /// bug in this file rather than bad input from a caller - and zero is
    /// the least harmful thing to carry on with, since any signature built
    /// on it fails to verify rather than being silently wrong.
    pub(crate) fn sub(x: &BigUint, y: &BigUint) -> BigUint {
        x.sub(y).unwrap_or_else(|_| BigUint::zero())
    }

    pub(crate) fn mul_mod(x: &BigUint, y: &BigUint, p: &BigUint) -> BigUint {
        x.mod_mul(y, p).unwrap_or_else(|_| BigUint::zero())
    }

    pub(crate) fn invert(x: &BigUint, p: &BigUint) -> BigUint {
        x.mod_inverse_prime(p).unwrap_or_else(|_| BigUint::zero())
    }

    // ------------------------------------------------------------- the points --

    /// A point in projective coordinates: `(x, y) = (X/Z, Y/Z)`.
    #[derive(Clone, Debug)]
    pub(crate) struct Point {
        pub(crate) x: BigUint,
        pub(crate) y: BigUint,
        pub(crate) z: BigUint,
    }

    impl Point {
        /// The identity, `(0, 1)`.
        ///
        /// Note that this is an ordinary point on an Edwards curve, not a
        /// point at infinity: there is no special encoding for it and no
        /// branch anywhere below that treats it differently.
        pub(crate) fn identity() -> Point {
            Point { x: BigUint::zero(), y: BigUint::one(), z: BigUint::one() }
        }

        pub(crate) fn affine(x: BigUint, y: BigUint) -> Point {
            Point { x, y, z: BigUint::one() }
        }

        /// `(X/Z, Y/Z)`: one modular inversion, paid once per encoding
        /// rather than once per addition.
        pub(crate) fn to_affine(&self, curve: &Curve) -> (BigUint, BigUint) {
            let inverse = curve.invert(&self.z);
            (curve.mul_mod(&self.x, &inverse), curve.mul_mod(&self.y, &inverse))
        }

        /// Projective equality: `X1*Z2 == X2*Z1` and `Y1*Z2 == Y2*Z1`.
        ///
        /// Comparing the coordinates directly would call two equal points
        /// different whenever they arrived by different routes, which is
        /// the normal case - so verification would reject every valid
        /// signature.
        pub(crate) fn equals(&self, other: &Point, curve: &Curve) -> bool {
            curve.mul_mod(&self.x, &other.z) == curve.mul_mod(&other.x, &self.z)
                && curve.mul_mod(&self.y, &other.z) == curve.mul_mod(&other.y, &self.z)
        }
    }

    /// Unified projective addition on a twisted Edwards curve.
    ///
    /// `add-2008-bbjlp` from the Explicit Formulas Database, which is the
    /// projective form of RFC 8032 section 5.1.4's affine addition:
    ///
    /// ```text
    /// A = Z1*Z2   B = A^2      C = X1*X2   D = Y1*Y2
    /// E = d*C*D   F = B-E      G = B+E
    /// X3 = A*F*((X1+Y1)*(X2+Y2) - C - D)
    /// Y3 = A*G*(D - a*C)
    /// Z3 = F*G
    /// ```
    ///
    /// Complete for both of our curves - `d` is a non-square on each - so it
    /// needs no branch for doubling, for the identity, or for `P + (-P)`.
    pub(crate) fn add(curve: &Curve, left: &Point, right: &Point) -> Point {
        let a = curve.mul_mod(&left.z, &right.z);
        let b = curve.mul_mod(&a, &a);
        let c = curve.mul_mod(&left.x, &right.x);
        let d = curve.mul_mod(&left.y, &right.y);
        let e = curve.mul_mod(&curve.d, &curve.mul_mod(&c, &d));
        let f = curve.sub_mod(&b, &e);
        let g = curve.add_mod(&b, &e);

        let cross = curve.mul_mod(
            &curve.add_mod(&left.x, &left.y),
            &curve.add_mod(&right.x, &right.y),
        );
        let inner = curve.sub_mod(&curve.sub_mod(&cross, &c), &d);

        Point {
            x: curve.mul_mod(&curve.mul_mod(&a, &f), &inner),
            y: curve.mul_mod(
                &curve.mul_mod(&a, &g),
                &curve.sub_mod(&d, &curve.mul_mod(&curve.a, &c)),
            ),
            z: curve.mul_mod(&f, &g),
        }
    }

    /// `scalar * point`, by double-and-add over the scalar's bits, on
    /// `BigUint`.
    ///
    /// **Not constant time**: it branches on each bit of the scalar, and the
    /// arithmetic underneath is variable time anyway. A test reference
    /// only; nothing outside the tests multiplies with it. The loop runs
    /// `variant.scalar_bits()` times rather than `scalar.bit_len()`, which
    /// would announce the scalar's magnitude.
    pub(crate) fn multiply(curve: &Curve, scalar: &BigUint, point: &Point) -> Point {
        let mut result = Point::identity();
        let mut addend = point.clone();
        for bit in 0..curve.variant.scalar_bits() {
            if scalar.bit(bit) {
                result = add(curve, &result, &addend);
            }
            addend = add(curve, &addend, &addend);
        }
        result
    }

    /// Recover `x` from `y` and the sign bit, RFC 8032 section 5.1.3.
    ///
    /// `x^2 = (y^2 - 1) / (d*y^2 - a)`. The square root is taken by
    /// exponentiation, and then **the root whose low bit matches `sign` is
    /// chosen** - picking the other one gives a point that is still on the
    /// curve, so nothing downstream errors and every signature is wrong.
    pub(crate) fn recover_x(curve: &Curve, y: &BigUint, sign: u8) -> Option<BigUint> {
        let p = &curve.p;
        let one = BigUint::one();

        let y2 = curve.mul_mod(y, y);
        let numerator = curve.sub_mod(&y2, &one);
        let denominator = curve.sub_mod(&curve.mul_mod(&curve.d, &y2), &curve.a);
        if denominator.is_zero() {
            return None;
        }
        let x2 = curve.mul_mod(&numerator, &curve.invert(&denominator));
        if x2.is_zero() {
            // x = 0 with the sign bit set is a non-canonical encoding of
            // (0, y), which RFC 8032 section 5.1.3 rejects.
            return if sign == 0 { Some(BigUint::zero()) } else { None };
        }

        let mut x = match curve.variant {
            // p = 5 mod 8, so the candidate root is x2^((p+3)/8) and may
            // need multiplying by sqrt(-1).
            Variant::Ed25519 => {
                let exponent = p.add(&BigUint::from_u64(3)).shr(3);
                let mut candidate = x2.mod_pow(&exponent, p).ok()?;
                if curve.mul_mod(&candidate, &candidate) != x2 {
                    // sqrt(-1) = 2^((p-1)/4)
                    let quarter = sub(p, &one).shr(2);
                    let i = BigUint::from_u64(2).mod_pow(&quarter, p).ok()?;
                    candidate = curve.mul_mod(&candidate, &i);
                }
                candidate
            }
            // p = 3 mod 4, so the root is simply x2^((p+1)/4).
            Variant::Ed448 => {
                let exponent = p.add(&one).shr(2);
                x2.mod_pow(&exponent, p).ok()?
            }
        };

        if curve.mul_mod(&x, &x) != x2 {
            return None; // y does not correspond to a point
        }
        // The sign bit selects which of the two roots.
        if u8::from(x.bit(0)) != sign {
            x = curve.sub_mod(p, &x);
        }
        Some(x)
    }

    /// Encode a point: `y` little endian, with `x`'s low bit in the top bit.
    pub(crate) fn encode(curve: &Curve, point: &Point) -> Vec<u8> {
        let length = curve.variant.key_len();
        let (x, y) = point.to_affine(curve);
        let mut out = y.to_bytes_be();
        out.reverse();
        out.resize(length, 0);
        if x.bit(0) {
            out[length - 1] |= 0x80;
        }
        out
    }

    /// Decode a point, or `None` if the bytes are not one.
    pub(crate) fn decode(curve: &Curve, bytes: &[u8]) -> Option<Point> {
        let length = curve.variant.key_len();
        if bytes.len() != length {
            return None;
        }
        let sign = bytes[length - 1] >> 7;
        let mut y_bytes = bytes.to_vec();
        y_bytes[length - 1] &= 0x7f;
        y_bytes.reverse();
        let y = BigUint::from_bytes_be(&y_bytes);
        if y >= curve.p {
            return None; // not a canonical encoding
        }
        let x = recover_x(curve, &y, sign)?;
        Some(Point::affine(x, y))
    }

    /// The base point `B`.
    pub(crate) fn base(curve: &Curve) -> Point {
        match curve.variant {
            Variant::Ed25519 => {
                // y = 4/5, and x is the even root. RFC 8032 section 5.1.
                let y =
                    curve.mul_mod(&BigUint::from_u64(4), &curve.invert(&BigUint::from_u64(5)));
                match recover_x(curve, &y, 0) {
                    Some(x) => Point::affine(x, y),
                    None => Point::identity(),
                }
            }
            Variant::Ed448 => {
                // RFC 8032 section 5.2 quotes these in decimal; they are
                // checked by `test_the_base_point_is_on_the_curve` and by
                // `test_the_base_point_has_the_stated_order` rather than by
                // a second reading of the document.
                let x = BigUint::from_hex(
                    "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324\
                     a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e",
                );
                let y = BigUint::from_hex(
                    "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e\
                     05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14",
                );
                match (x, y) {
                    (Ok(x), Ok(y)) => Point::affine(x, y),
                    _ => Point::identity(),
                }
            }
        }
    }

    /// A little endian hash reduced modulo the group order.
    pub(crate) fn reduce(bytes: &[u8], order: &BigUint) -> BigUint {
        let mut big_endian = bytes.to_vec();
        big_endian.reverse();
        BigUint::from_bytes_be(&big_endian)
            .rem(order)
            .unwrap_or_else(|_| BigUint::zero())
    }

    /// A scalar as `key_len` little endian bytes.
    pub(crate) fn encode_scalar(curve: &Curve, value: &BigUint) -> Vec<u8> {
        let mut bytes = value.to_bytes_be();
        bytes.reverse();
        bytes.resize(curve.variant.key_len(), 0);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::reference::*;
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    // ------------------------------------------ the RFC's own vectors ---

    /// RFC 8032 section 7, read out of the document rather than typed.
    ///
    /// Never type a vector - a rule earned twice over: one typed from
    /// memory parses, agrees with itself and is refused by everybody else.
    /// `rfcs/rfc8032.txt` is the unmodified RFC and this is its section 7,
    /// so the vectors below are the RFC's or the test fails to find any -
    /// which `test_the_vector_parser_found_them_all` turns into a failure
    /// rather than a silently empty loop.
    const RFC8032: &str = include_str!("../../rfcs/rfc8032.txt");

    #[derive(Debug)]
    struct Vector {
        name: String,
        algorithm: String,
        secret: Vec<u8>,
        public: Vec<u8>,
        message: Vec<u8>,
        context: Vec<u8>,
        signature: Vec<u8>,
    }

    /// A field header: an all-capitals name, optionally followed by
    /// `(length N bytes)`, then a colon.
    fn field_header(line: &str) -> Option<String> {
        let line = line.strip_suffix(':')?;
        let head = line.split('(').next()?.trim();
        if head.is_empty() {
            return None;
        }
        if !head.chars().all(|c| c.is_ascii_uppercase() || c == ' ') {
            return None;
        }
        Some(head.to_string())
    }

    fn parse_vectors() -> Vec<Vector> {
        let mut out: Vec<Vector> = Vec::new();
        let mut fields: Vec<(String, String)> = Vec::new();
        let mut name: Option<String> = None;
        let mut current: Option<String> = None;

        fn take(fields: &[(String, String)], key: &str) -> String {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        }

        fn flush(out: &mut Vec<Vector>, name: &Option<String>, fields: &[(String, String)]) {
            let Some(name) = name else { return };
            let algorithm = take(fields, "ALGORITHM");
            if algorithm.is_empty() {
                return;
            }
            out.push(Vector {
                name: name.clone(),
                algorithm,
                secret: unhex(&take(fields, "SECRET KEY")),
                public: unhex(&take(fields, "PUBLIC KEY")),
                message: unhex(&take(fields, "MESSAGE")),
                context: unhex(&take(fields, "CONTEXT")),
                signature: unhex(&take(fields, "SIGNATURE")),
            });
        }

        for raw in RFC8032.lines() {
            let raw = raw.replace('\u{c}', "");
            // The page headers and footers land in the middle of a
            // vector's hex, so they have to go before anything else.
            if raw.starts_with("RFC 8032") || raw.starts_with("Josefsson & Liusvaara") {
                continue;
            }
            if let Some(rest) = raw.strip_prefix("   -----") {
                flush(&mut out, &name, &fields);
                fields.clear();
                current = None;
                name = Some(rest.trim().to_string());
                continue;
            }
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(header) = field_header(line) {
                fields.push((header.clone(), String::new()));
                current = Some(header);
                continue;
            }
            let Some(key) = current.clone() else { continue };
            let accepted = if key == "ALGORITHM" {
                true
            } else {
                line.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            };
            if accepted {
                if let Some(slot) = fields.iter_mut().rev().find(|(k, _)| *k == key) {
                    slot.1.push_str(line);
                }
            } else {
                // Anything else - a section heading, prose - ends the
                // field. Without this a heading's letters would be
                // appended to a message.
                current = None;
            }
        }
        flush(&mut out, &name, &fields);
        out
    }

    fn vectors_for(algorithm: &str) -> Vec<Vector> {
        parse_vectors().into_iter().filter(|v| v.algorithm == algorithm).collect()
    }

    /// The parser found what the RFC contains.
    ///
    /// A parser that silently finds nothing turns every vector test
    /// below into an empty loop that passes. These counts come from
    /// reading section 7's headings, and they are the thing that makes
    /// the loops mean something.
    #[test]
    fn test_the_vector_parser_found_them_all() {
        let all = parse_vectors();
        assert_eq!(all.len(), 21, "section 7 has 21 vectors; the parser found {}", all.len());

        let mut counts: Vec<(String, usize)> = Vec::new();
        for vector in &all {
            match counts.iter_mut().find(|(name, _)| *name == vector.algorithm) {
                Some(entry) => entry.1 += 1,
                None => counts.push((vector.algorithm.clone(), 1)),
            }
        }
        counts.sort();
        assert_eq!(
            counts,
            vec![
                ("Ed25519".to_string(), 5),
                ("Ed25519ctx".to_string(), 4),
                ("Ed25519ph".to_string(), 1),
                ("Ed448".to_string(), 9),
                ("Ed448ph".to_string(), 2),
            ],
            "the mix of algorithms in section 7 changed"
        );

        // And the lengths are the ones the scheme demands, which
        // catches hex lost across a page break.
        for vector in &all {
            let key_len = if vector.algorithm.starts_with("Ed25519") { 32 } else { 57 };
            assert_eq!(vector.secret.len(), key_len, "{}: secret key", vector.name);
            assert_eq!(vector.public.len(), key_len, "{}: public key", vector.name);
            assert_eq!(
                vector.signature.len(),
                key_len * 2,
                "{}: signature",
                vector.name
            );
        }
    }

    /// The variants this module does not implement are named, not
    /// ignored.
    ///
    /// If the parser stopped recognising `Ed25519ctx` these would
    /// vanish from the skip list and nothing else would notice.
    #[test]
    fn test_the_unimplemented_variants_are_named() {
        for algorithm in ["Ed25519ctx", "Ed25519ph", "Ed448ph"] {
            assert!(
                !vectors_for(algorithm).is_empty(),
                "{} has no vectors, so the parser has stopped seeing it",
                algorithm
            );
        }
    }

    /// RFC 8032 section 7.1: every pure Ed25519 vector, including TEST
    /// 1024 whose message is 1023 bytes.
    ///
    /// The short ones all fit in a single SHA-512 block, so on their own
    /// they cannot tell a correct absorb from one that works only for
    /// short inputs.
    #[test]
    fn test_rfc8032_ed25519_vectors() {
        let vectors = vectors_for("Ed25519");
        assert_eq!(vectors.len(), 5);
        for vector in vectors {
            assert_eq!(
                hex(&public_key(Variant::Ed25519, &vector.secret).unwrap()),
                hex(&vector.public),
                "{}: public key",
                vector.name
            );

            let got = sign(Variant::Ed25519, &vector.secret, &vector.message, &[]).unwrap();
            assert_eq!(hex(&got), hex(&vector.signature), "{}: signature", vector.name);

            verify(Variant::Ed25519, &vector.public, &vector.message, &vector.signature, &[])
                .unwrap_or_else(|e| panic!("{}: the RFC's signature did not verify: {}", vector.name, e));
        }
    }

    /// RFC 8032 section 7.4: every pure Ed448 vector, including the one
    /// with a context and the 1023 byte message.
    #[test]
    fn test_rfc8032_ed448_vectors() {
        let vectors = vectors_for("Ed448");
        assert_eq!(vectors.len(), 9);
        for vector in vectors {
            assert_eq!(
                hex(&public_key(Variant::Ed448, &vector.secret).unwrap()),
                hex(&vector.public),
                "{}: public key",
                vector.name
            );

            let got =
                sign(Variant::Ed448, &vector.secret, &vector.message, &vector.context).unwrap();
            assert_eq!(hex(&got), hex(&vector.signature), "{}: signature", vector.name);

            verify(
                Variant::Ed448,
                &vector.public,
                &vector.message,
                &vector.signature,
                &vector.context,
            )
            .unwrap_or_else(|e| panic!("{}: the RFC's signature did not verify: {}", vector.name, e));
        }
    }

    /// At least one Ed448 vector carries a context, and it must not
    /// verify without it.
    ///
    /// A context that never reached the hash would pass the loop above
    /// for that vector only if the signature happened to match, so this
    /// is the check that the context is load bearing.
    #[test]
    fn test_the_ed448_context_vector_needs_its_context() {
        let with_context: Vec<Vector> =
            vectors_for("Ed448").into_iter().filter(|v| !v.context.is_empty()).collect();
        assert!(!with_context.is_empty(), "no Ed448 vector carries a context");
        for vector in with_context {
            assert!(
                verify(Variant::Ed448, &vector.public, &vector.message, &vector.signature, &[])
                    .is_err(),
                "{}: verified with the context dropped",
                vector.name
            );
            let without =
                sign(Variant::Ed448, &vector.secret, &vector.message, &[]).unwrap();
            assert_ne!(
                hex(&without),
                hex(&vector.signature),
                "{}: the context did not reach the hash",
                vector.name
            );
        }
    }

    // ------------------------------------------ properties and traps ---

    /// **The private key is not the scalar.**
    ///
    /// A signature made by treating the key bytes as the scalar directly
    /// is perfectly well formed and verifies against an implementation
    /// that makes the same mistake. This pins that the expansion
    /// happens.
    #[test]
    fn test_the_key_is_hashed_before_it_is_a_scalar() {
        let private = vectors_for("Ed25519")[0].secret.clone();
        let (scalar, prefix) = expand(Variant::Ed25519, &private);

        // Clamped, the key bytes would differ from themselves only in
        // the clamped bits; the hashed scalar differs almost everywhere.
        let mut clamped = private.clone();
        Variant::Ed25519.clamp(&mut clamped);
        assert_ne!(scalar, clamped,
                   "the scalar equals the key bytes, so no expansion happened");
        assert_eq!(prefix.len(), 32);
        assert_ne!(prefix, private, "the prefix equals the key");
    }

    /// The constant-time arithmetic mod L against `BigUint`: reductions
    /// of every length signing and verification use and some they do
    /// not, the all-ones value of each, and `a*b + c` and `-a`.
    #[test]
    fn test_the_order_arithmetic_agrees_with_the_bignum() {
        for variant in [Variant::Ed25519, Variant::Ed448] {
            let order = order(variant).unwrap();
            let l = &order.value;
            for length in [0, 1, 31, 32, 55, 56, 57, 64, 112, 113, 114, 200] {
                for round in 0..4 {
                    let mut bytes = vec![0xffu8; length];
                    if round > 0 {
                        crate::random::fill(&mut bytes).unwrap();
                    }
                    let ours = order.reduce(&bytes).unwrap();
                    assert_eq!(ours.declassify(), reduce(&bytes, l),
                               "{variant:?}, {length} bytes");
                }
            }
            let random = || {
                let mut bytes = vec![0u8; 64];
                crate::random::fill(&mut bytes).unwrap();
                order.reduce(&bytes).unwrap()
            };
            for _ in 0..20 {
                let (a, b, c) = (random(), random(), random());
                let expected = a.declassify().mod_mul(&b.declassify(), l).unwrap()
                    .mod_add(&c.declassify(), l).unwrap();
                assert_eq!(order.mul_add(&a, &b, &c).declassify(), expected);
                assert_eq!(order.negate(&a).declassify().mod_add(&a.declassify(), l).unwrap(),
                           BigUint::zero());
            }
            assert!(order.negate(&Secret::zero(order.mont.limbs())).declassify().is_zero());
        }
    }

    /// Clamping happens, and differs between the curves.
    #[test]
    fn test_clamping() {
        let mut half = vec![0xffu8; 32];
        Variant::Ed25519.clamp(&mut half);
        assert_eq!(half[0] & 0x07, 0, "the low three bits were not cleared");
        assert_eq!(half[31] & 0x80, 0, "the top bit was not cleared");
        assert_eq!(half[31] & 0x40, 0x40, "bit 254 was not set");

        let mut half = vec![0xffu8; 57];
        Variant::Ed448.clamp(&mut half);
        assert_eq!(half[0] & 0x03, 0, "the low two bits were not cleared");
        assert_eq!(half[55] & 0x80, 0x80, "the top bit of byte 55 was not set");
        assert_eq!(half[56], 0, "the last byte was not cleared");
    }

    /// A changed message, key or signature byte must not verify.
    ///
    /// Every byte position is touched, one bit each rather than all
    /// eight: a verification is two scalar multiplications, and the full
    /// 512 flips took minutes in a debug build for no more coverage.
    #[test]
    fn test_a_tampered_signature_is_refused() {
        let vectors = vectors_for("Ed25519");
        let private = vectors[0].secret.clone();
        let public = public_key(Variant::Ed25519, &private).unwrap();
        let message = b"the message that was signed";
        let signature = sign(Variant::Ed25519, &private, message, &[]).unwrap();
        verify(Variant::Ed25519, &public, message, &signature, &[]).unwrap();

        // A different message.
        assert!(verify(Variant::Ed25519, &public, b"a different message", &signature, &[])
            .is_err());

        // A different public key.
        let other = public_key(Variant::Ed25519, &vectors[1].secret).unwrap();
        assert!(verify(Variant::Ed25519, &other, message, &signature, &[]).is_err());

        // Every byte of the signature, one bit apiece, rotating which
        // bit so no position is always the low one.
        for index in 0..signature.len() {
            let mut broken = signature.clone();
            broken[index] ^= 1 << (index % 8);
            assert!(
                verify(Variant::Ed25519, &public, message, &broken, &[]).is_err(),
                "a signature with byte {} bit {} flipped verified",
                index,
                index % 8
            );
        }
    }

    /// **An unreduced S is refused**, RFC 8032 section 5.1.7.
    ///
    /// Adding the group order to a valid `S` gives a second signature
    /// that satisfies the verification equation. Accepting it means one
    /// message has two valid signatures, which has broken real systems
    /// that used a signature as an identifier.
    #[test]
    fn test_an_unreduced_s_is_refused() {
        let private = vectors_for("Ed25519")[0].secret.clone();
        let public = public_key(Variant::Ed25519, &private).unwrap();
        let message = b"malleability";
        let signature = sign(Variant::Ed25519, &private, message, &[]).unwrap();

        let curve = Curve::new(Variant::Ed25519);
        let mut s_bytes = signature[32..].to_vec();
        s_bytes.reverse();
        let s = BigUint::from_bytes_be(&s_bytes);
        let bumped = s.add(&curve.order);
        assert!(bumped.bit_len() <= 256, "the bumped S no longer fits in 32 bytes");

        let mut malleable = signature[..32].to_vec();
        malleable.extend_from_slice(&encode_scalar(&curve, &bumped));
        assert!(
            verify(Variant::Ed25519, &public, message, &malleable, &[]).is_err(),
            "an S larger than the group order was accepted"
        );

        // S = L exactly is the boundary: not reduced, and refused for
        // that reason rather than for failing the equation.
        let mut boundary = signature[..32].to_vec();
        boundary.extend_from_slice(&encode_scalar(&curve, &curve.order));
        let refused = verify(Variant::Ed25519, &public, message, &boundary, &[]).unwrap_err();
        assert!(refused.contains("not reduced"), "{refused}");
    }

    /// Signing is deterministic.
    #[test]
    fn test_signing_is_deterministic() {
        let private = vectors_for("Ed25519")[1].secret.clone();
        let first = sign(Variant::Ed25519, &private, b"same", &[]).unwrap();
        let second = sign(Variant::Ed25519, &private, b"same", &[]).unwrap();
        assert_eq!(hex(&first), hex(&second));
    }

    /// Encoding and decoding a point round-trips, and the sign bit
    /// selects the right root.
    #[test]
    fn test_point_encoding_round_trips() {
        for variant in [Variant::Ed25519, Variant::Ed448] {
            let curve = Curve::new(variant);
            let generator = base(&curve);
            let encoded = encode(&curve, &generator);
            assert_eq!(encoded.len(), variant.key_len());
            let decoded = decode(&curve, &encoded).expect("the base point must decode");
            assert!(
                decoded.equals(&generator, &curve),
                "{} base point did not round trip",
                variant.name()
            );

            // And the other sign gives the other root, not the same one.
            let mut flipped = encoded.clone();
            flipped[variant.key_len() - 1] ^= 0x80;
            let other = decode(&curve, &flipped).expect("the negation is a point");
            let (other_x, other_y) = other.to_affine(&curve);
            let (base_x, base_y) = generator.to_affine(&curve);
            assert_ne!(other_x, base_x, "{} sign bit did nothing", variant.name());
            assert_eq!(other_y, base_y, "{} sign bit changed y", variant.name());
        }
    }

    /// The base point has the order the curve claims.
    ///
    /// `L * B` must be the identity and `(L - 1) * B` must not be. A
    /// wrong group order passes every signature test made against
    /// ourselves, because both ends reduce by the same wrong number -
    /// this and the RFC's vectors are what rule it out.
    #[test]
    fn test_the_base_point_has_the_stated_order() {
        for variant in [Variant::Ed25519, Variant::Ed448] {
            let curve = Curve::new(variant);
            let generator = base(&curve);

            let times_order = multiply(&curve, &curve.order, &generator);
            assert!(
                times_order.equals(&Point::identity(), &curve),
                "{}: L*B is not the identity",
                variant.name()
            );

            let one_less = sub(&curve.order, &BigUint::one());
            let before = multiply(&curve, &one_less, &generator);
            assert!(
                !before.equals(&Point::identity(), &curve),
                "{}: (L-1)*B is already the identity, so L is not the order",
                variant.name()
            );
        }
    }

    /// The base point satisfies the curve equation.
    ///
    /// `a*x^2 + y^2 = 1 + d*x^2*y^2`. This is what pins `d` and `a`,
    /// which are otherwise only checked by the vectors.
    #[test]
    fn test_the_base_point_is_on_the_curve() {
        for variant in [Variant::Ed25519, Variant::Ed448] {
            let curve = Curve::new(variant);
            let (x, y) = base(&curve).to_affine(&curve);
            let x2 = curve.mul_mod(&x, &x);
            let y2 = curve.mul_mod(&y, &y);
            let left = curve.add_mod(&curve.mul_mod(&curve.a, &x2), &y2);
            let right = curve.add_mod(
                &BigUint::one(),
                &curve.mul_mod(&curve.d, &curve.mul_mod(&x2, &y2)),
            );
            assert_eq!(left, right, "{} base point is not on the curve", variant.name());
        }
    }

    /// The field prime is the one the exponentiation in `recover_x`
    /// assumes.
    ///
    /// Ed25519's square root is `x^((p+3)/8)`, which is a square root
    /// only when `p = 5 mod 8`; Ed448's is `x^((p+1)/4)`, only when
    /// `p = 3 mod 4`. Both produce *something* for any prime, so a wrong
    /// prime is caught here rather than by a decode that fails.
    #[test]
    fn test_the_primes_suit_their_square_roots() {
        let curve = Curve::new(Variant::Ed25519);
        let eight = BigUint::from_u64(8);
        assert_eq!(curve.p.rem(&eight).unwrap(), BigUint::from_u64(5));

        let curve = Curve::new(Variant::Ed448);
        let four = BigUint::from_u64(4);
        assert_eq!(curve.p.rem(&four).unwrap(), BigUint::from_u64(3));
    }

    /// The identity behaves like one, and addition is commutative and
    /// associative.
    ///
    /// The unified formula has no special case for any of these, so a
    /// failure here is the formula transcribed wrongly rather than a
    /// missing branch.
    /// `multiply` iterates a constant number of times now, so that
    /// constant must cover every scalar it can be handed - a bound one
    /// bit short silently drops the top bit and produces a signature
    /// that verifies against nothing.
    ///
    /// The RFC vectors catch that too, which is why this is a cheap
    /// assertion rather than the only guard; what it adds is naming the
    /// reason, since the bound looks arbitrary next to the clamp.
    #[test]
    fn test_the_scalar_bound_covers_every_clamped_scalar() {
        for variant in [Variant::Ed25519, Variant::Ed448] {
            let curve = Curve::new(variant);
            assert!(curve.order.bit_len() <= variant.scalar_bits());

            // The clamp sets a high bit on purpose - bit 254 for
            // Ed25519, 447 for Ed448 - so a clamped scalar is wider
            // than the group order and is the case that matters.
            let mut bytes = vec![0xffu8; variant.key_len()];
            variant.clamp(&mut bytes);
            let mut le = bytes.clone();
            le.reverse();
            let scalar = BigUint::from_bytes_be(&le);
            assert!(scalar.bit_len() <= variant.scalar_bits(),
                    "{variant:?}: a clamped scalar is {} bits and the bound is {}",
                    scalar.bit_len(), variant.scalar_bits());

            // And the bound is not wastefully large: within one limb of
            // what is needed, so nobody is tempted to "optimise" it back
            // to bit_len().
            assert!(variant.scalar_bits() - scalar.bit_len() < 64);
        }
    }

    #[test]
    fn test_the_group_law() {
        for variant in [Variant::Ed25519, Variant::Ed448] {
            let curve = Curve::new(variant);
            let g = base(&curve);
            let identity = Point::identity();

            assert!(add(&curve, &g, &identity).equals(&g, &curve), "P + 0 != P");
            assert!(add(&curve, &identity, &g).equals(&g, &curve), "0 + P != P");

            let two = add(&curve, &g, &g);
            let three_a = add(&curve, &two, &g);
            let three_b = add(&curve, &g, &two);
            assert!(three_a.equals(&three_b, &curve), "addition is not commutative");

            let four_a = add(&curve, &three_a, &g);
            let four_b = add(&curve, &two, &two);
            assert!(four_a.equals(&four_b, &curve), "addition is not associative");

            // And that scalar multiplication agrees with repeated
            // addition, which is the only independent check on the
            // double-and-add loop.
            let by_scalar = multiply(&curve, &BigUint::from_u64(4), &g);
            assert!(by_scalar.equals(&four_a, &curve), "4*G != G+G+G+G");
        }
    }

    /// Ed25519 refuses a context, on both the signing and the verifying
    /// side.
    ///
    /// Accepting one silently would make Ed25519ctx signatures look
    /// like Ed25519 ones.
    #[test]
    fn test_ed25519_refuses_a_context() {
        let private = vectors_for("Ed25519")[0].secret.clone();
        let public = public_key(Variant::Ed25519, &private).unwrap();
        let signature = sign(Variant::Ed25519, &private, b"x", &[]).unwrap();
        assert!(sign(Variant::Ed25519, &private, b"x", b"ctx").is_err());
        assert!(verify(Variant::Ed25519, &public, b"x", &signature, b"ctx").is_err());
    }

    #[test]
    fn test_wrong_lengths_are_errors() {
        assert!(public_key(Variant::Ed25519, &[0; 31]).is_err());
        assert!(public_key(Variant::Ed448, &[0; 56]).is_err());
        assert!(sign(Variant::Ed25519, &[0; 33], b"", &[]).is_err());
        assert!(verify(Variant::Ed25519, &[0; 31], b"", &[0; 64], &[]).is_err());
        assert!(verify(Variant::Ed25519, &[0; 32], b"", &[0; 63], &[]).is_err());
        assert!(sign(Variant::Ed448, &[0; 57], b"", &[0; 256]).is_err());
        assert!(verify(Variant::Ed448, &[0; 57], b"", &[0; 114], &[0; 256]).is_err());
    }

    /// **A point and its negation are not equal.**
    ///
    /// `Point::equals` cross-multiplies both coordinates. Comparing only
    /// `y` looks like it works — every test above passes, because two
    /// equal points do have equal `y` — and it makes `P` and `-P`
    /// indistinguishable, which is a verifier that accepts
    /// `S*B == -(R + k*A)`.
    ///
    /// Found by deliberate breakage: dropping the `x` half of the
    /// comparison failed nothing at all.
    #[test]
    fn test_a_point_and_its_negation_are_not_equal() {
        for variant in [Variant::Ed25519, Variant::Ed448] {
            let curve = Curve::new(variant);
            let g = base(&curve);
            let (x, y) = g.to_affine(&curve);
            let negated = Point::affine(curve.sub_mod(&curve.p, &x), y.clone());

            assert!(!negated.equals(&g, &curve),
                    "{}: a point and its negation compared equal", variant.name());
            // They do share a y, which is why comparing y alone passes
            // every other test in this file.
            let (_, negated_y) = negated.to_affine(&curve);
            assert_eq!(negated_y, y);
            // And P + (-P) is the identity, which is what makes it the
            // negation rather than some other point.
            assert!(add(&curve, &g, &negated).equals(&Point::identity(), &curve),
                    "{}: P + (-P) is not the identity", variant.name());
        }
    }

    /// **A `y` with no corresponding `x` is refused.**
    ///
    /// About half of all field elements are not the `y` of any point.
    /// `recover_x` exponentiates regardless — that always produces
    /// *something* — so the square has to be checked against `x^2`
    /// afterwards. Without that check the bytes decode to a value that
    /// is not on the curve at all, and every later operation is
    /// arithmetic on a point that does not exist.
    ///
    /// Found by deliberate breakage: removing the check failed nothing,
    /// because a signature made with such a key fails to verify anyway
    /// and the tests only ever asked whether it was refused, not why.
    #[test]
    fn test_a_y_with_no_point_is_refused() {
        for variant in [Variant::Ed25519, Variant::Ed448] {
            let curve = Curve::new(variant);
            let mut found = 0;
            for candidate in 2u64..200 {
                let y = BigUint::from_u64(candidate);
                if recover_x(&curve, &y, 0).is_some() {
                    continue;
                }
                found += 1;

                // The same y as an encoded point must not decode, under
                // either sign bit.
                let mut bytes = y.to_bytes_be();
                bytes.reverse();
                bytes.resize(variant.key_len(), 0);
                assert!(decode(&curve, &bytes).is_none(),
                        "{}: y = {} decoded and it is on no point",
                        variant.name(), candidate);
                assert!(!is_public_key(variant, &bytes));

                let mut flipped = bytes.clone();
                flipped[variant.key_len() - 1] |= 0x80;
                assert!(decode(&curve, &flipped).is_none(),
                        "{}: y = {} decoded with the sign bit set",
                        variant.name(), candidate);

                if found == 4 {
                    break;
                }
            }
            assert!(found > 0,
                    "{}: every y from 2 to 199 was on the curve, which cannot \
                     happen - recover_x is accepting non-residues",
                    variant.name());
        }
    }

    /// A `y` at or above the field prime is not a canonical encoding.
    #[test]
    fn test_a_non_canonical_y_is_refused() {
        let curve = Curve::new(Variant::Ed25519);
        // p itself, little endian, with the sign bit clear.
        let mut bytes = curve.p.to_bytes_be();
        bytes.reverse();
        bytes.resize(32, 0);
        assert!(decode(&curve, &bytes).is_none(), "y = p decoded");
        assert!(
            verify(Variant::Ed25519, &bytes, b"", &[0; 64], &[]).is_err(),
            "a public key of y = p was accepted"
        );
    }
}
