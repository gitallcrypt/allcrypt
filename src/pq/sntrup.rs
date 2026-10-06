/*
Streamlined NTRU Prime, sntrup761: the key encapsulation OpenSSH used for
its default post-quantum key exchange, `sntrup761x25519-sha512`, from
OpenSSH 9.0 until ML-KEM replaced it in 9.9.

Not a NIST standard - NTRU Prime was a round 3 alternate - and here for
that reason: every OpenSSH from 9.0 to 9.8 offers it first, and there
are a great many of those.

The definition followed is the Sage reference in
draft-josefsson-ntruprime-streamlined-00 (vendored in `rfcs/`), which is
the round 3 submission's; its test vectors are read out of the same
document. Parameters: p = 761, q = 4591, w = 286, in the ring
`Z[x]/(x^p - x - 1)`.

    public key   1158 bytes   h = g / (3f) in R/q, encoded
    secret key   1763 bytes   f, 1/g mod 3, the public key, rho, Hash4(pk)
    ciphertext   1039 bytes   Round(h r), encoded, and a 32 byte confirmation
    shared key     32 bytes

# Pitfalls

**The random source is called in the reference's pieces, and that is
part of the test vectors.** The vectors come from NIST's AES-256 CTR_DRBG,
which discards the rest of a block at the end of each call: four bytes
per `urandom32`, 191 bytes for `rho`. Drawing the same bytes in larger
calls gives a different stream and keys that match nothing - while the
scheme itself works perfectly. So `Fill` is called exactly as the
reference calls `randombytes`, and the test harness's DRBG reproduces
NIST's.

**Decapsulation never fails.** A ciphertext that does not re-encrypt to
itself yields `HashSession(0, rho, C)` - a key derived from a secret only
the holder has - instead of an error, so that a forged ciphertext tells
an attacker nothing. The choice between the two is a mask, not a branch.

**The weight check in decryption substitutes, it does not reject.** An
`r` of the wrong weight is replaced by a fixed one, again by a mask.

**Sorting decides the secret's shape.** `Short_fromlist` sorts p random
words with the low bits overwritten, which puts exactly w nonzero
coefficients in random places. A sort whose comparisons branch leaks
where they went; this one is a sorting network of masked min/max.

**Inversion is by a fixed number of division steps** (2p - 1, the
reference's loop), not Euclid's algorithm, whose running time depends
on the secret polynomial.
*/

use crate::hash_functions::{sha2::SHA512, HashFunction};

pub const P: usize = 761;
pub const Q: i32 = 4591;
pub const W: usize = 286;
const Q12: i32 = (Q - 1) / 2;

const SMALL_BYTES: usize = P.div_ceil(4);
pub const PUBLIC_KEY_BYTES: usize = 1158;
const ROUNDED_BYTES: usize = 1007;
const CONFIRM_BYTES: usize = 32;
const HASH_BYTES: usize = 32;
pub const SECRET_KEY_BYTES: usize = 2 * SMALL_BYTES + PUBLIC_KEY_BYTES + SMALL_BYTES + HASH_BYTES;
pub const CIPHERTEXT_BYTES: usize = ROUNDED_BYTES + CONFIRM_BYTES;
pub const SHARED_KEY_BYTES: usize = 32;

/// The random source, called as the reference calls `randombytes`.
pub type Fill<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

// ------------------------------------------------------------ arithmetic ---

/// x mod q, as the representative in [-q12, q12].
fn fq(x: i32) -> i16 {
    let r = x.rem_euclid(Q);
    (r - Q * i32::from(r > Q12)) as i16
}

/// x mod 3, as -1, 0 or 1.
fn f3(x: i32) -> i8 {
    let r = x.rem_euclid(3);
    (r - 3 * i32::from(r > 1)) as i8
}

/// All ones if `x` is nonzero.
fn nonzero_mask(x: i32) -> i32 {
    -(i32::from(x != 0))
}

/// All ones if `x` is negative.
fn negative_mask(x: i32) -> i32 {
    x >> 31
}

/// `a * b` in R/q, where b is small: the product mod x^p - x - 1.
fn rq_mult_small(a: &[i16], b: &[i8]) -> Vec<i16> {
    let mut product = vec![0i32; 2 * P - 1];
    for (i, ai) in a.iter().enumerate() {
        // At most p terms of q12 * 3 accumulate: 5.2 million, well inside
        // an i32.
        for (j, bj) in b.iter().enumerate() {
            product[i + j] += i32::from(*ai) * i32::from(*bj);
        }
    }
    // x^p = x + 1: fold the high half down, from the top.
    for i in (P..2 * P - 1).rev() {
        let high = i32::from(fq(product[i]));
        product[i - P] += high;
        product[i - P + 1] += high;
    }
    product[..P].iter().map(|v| fq(*v)).collect()
}

/// `a * b` in R/3.
fn r3_mult(a: &[i8], b: &[i8]) -> Vec<i8> {
    let mut product = vec![0i32; 2 * P - 1];
    for (i, ai) in a.iter().enumerate() {
        for (j, bj) in b.iter().enumerate() {
            product[i + j] += i32::from(*ai) * i32::from(*bj);
        }
    }
    for i in (P..2 * P - 1).rev() {
        let high = i32::from(f3(product[i]));
        product[i - P] += high;
        product[i - P + 1] += high;
    }
    product[..P].iter().map(|v| f3(*v)).collect()
}

/// 1/a in R/3, and whether a was invertible. Bernstein-Yang division
/// steps, a fixed 2p - 1 of them, as the reference's `R3_recip`.
fn r3_recip(a: &[i8]) -> (Vec<i8>, bool) {
    let mut f = vec![0i32; P + 1];
    let mut g = vec![0i32; P + 1];
    let mut v = vec![0i32; P + 1];
    let mut r = vec![0i32; P + 1];
    r[0] = 1;
    f[0] = 1;
    f[P - 1] = -1;
    f[P] = -1;
    for i in 0..P {
        g[P - 1 - i] = i32::from(a[i]);
    }
    let mut delta: i32 = 1;
    for _ in 0..2 * P - 1 {
        for i in (1..=P).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;
        let sign = -g[0] * f[0];
        let swap = negative_mask(-delta) & nonzero_mask(g[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for i in 0..=P {
            let t = swap & (f[i] ^ g[i]);
            f[i] ^= t;
            g[i] ^= t;
            let t = swap & (v[i] ^ r[i]);
            v[i] ^= t;
            r[i] ^= t;
        }
        for i in 0..=P {
            g[i] = i32::from(f3(g[i] + sign * f[i]));
            r[i] = i32::from(f3(r[i] + sign * v[i]));
        }
        for i in 0..P {
            g[i] = g[i + 1];
        }
        g[P] = 0;
    }
    let sign = f[0];
    let out = (0..P).map(|i| f3(sign * v[P - 1 - i])).collect();
    (out, delta == 0)
}

/// 1/(3a) in R/q, and whether it exists - the reference's `Rq_recip3`.
fn rq_recip3(a: &[i8]) -> (Vec<i16>, bool) {
    let mut f = vec![0i32; P + 1];
    let mut g = vec![0i32; P + 1];
    let mut v = vec![0i32; P + 1];
    let mut r = vec![0i32; P + 1];
    r[0] = i32::from(fq_recip(3));
    f[0] = 1;
    f[P - 1] = -1;
    f[P] = -1;
    for i in 0..P {
        g[P - 1 - i] = i32::from(a[i]);
    }
    let mut delta: i32 = 1;
    for _ in 0..2 * P - 1 {
        for i in (1..=P).rev() {
            v[i] = v[i - 1];
        }
        v[0] = 0;
        let swap = negative_mask(-delta) & nonzero_mask(g[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for i in 0..=P {
            let t = swap & (f[i] ^ g[i]);
            f[i] ^= t;
            g[i] ^= t;
            let t = swap & (v[i] ^ r[i]);
            v[i] ^= t;
            r[i] ^= t;
        }
        let (f0, g0) = (f[0], g[0]);
        for i in 0..=P {
            g[i] = i32::from(fq(f0 * g[i] - g0 * f[i]));
            r[i] = i32::from(fq(f0 * r[i] - g0 * v[i]));
        }
        for i in 0..P {
            g[i] = g[i + 1];
        }
        g[P] = 0;
    }
    let scale = i32::from(fq_recip(f[0] as i16));
    let out = (0..P).map(|i| fq(scale * v[P - 1 - i])).collect();
    (out, delta == 0)
}

/// 1/a mod q, by Fermat: a^(q-2).
fn fq_recip(a: i16) -> i16 {
    let mut result: i32 = 1;
    let mut base = i32::from(a);
    let mut exponent = Q - 2;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = i32::from(fq(result * base));
        }
        base = i32::from(fq(base * base));
        exponent >>= 1;
    }
    result as i16
}

/// The nearest multiple of 3 to each coefficient.
fn round(a: &[i16]) -> Vec<i16> {
    a.iter().map(|c| *c - i16::from(f3(i32::from(*c)))).collect()
}

// ------------------------------------------------------------- sorting ---

/// Sort with a fixed pattern of comparisons (djbsort's portable
/// network): which elements are compared depends only on the length.
fn sort_u32(x: &mut [u32]) {
    let n = x.len();
    if n < 2 {
        return;
    }
    let minmax = |x: &mut [u32], i: usize, j: usize| {
        let (a, b) = (x[i], x[j]);
        // All ones when b < a, computed without a branch.
        let swap = 0u32.wrapping_sub(((u64::from(b).wrapping_sub(u64::from(a))) >> 63) as u32);
        let t = swap & (a ^ b);
        x[i] = a ^ t;
        x[j] = b ^ t;
    };
    let mut top = 1;
    while top < n - top {
        top += top;
    }
    let mut p = top;
    while p >= 1 {
        let mut i = 0;
        while i < n - p {
            if i & p == 0 {
                minmax(x, i, i + p);
            }
            i += 1;
        }
        let mut i = 0;
        let mut q = top;
        while q > p {
            while i < n - q {
                if i & p == 0 {
                    let mut a = x[i + p];
                    let mut r = q;
                    while r > p {
                        let pair = [a, x[i + r]];
                        let mut scratch = pair;
                        minmax(&mut scratch, 0, 1);
                        a = scratch[0];
                        x[i + r] = scratch[1];
                        r >>= 1;
                    }
                    x[i + p] = a;
                }
                i += 1;
            }
            q >>= 1;
        }
        p >>= 1;
    }
}

// ---------------------------------------------------------- randomness ---

fn urandom32(fill: Fill<'_>) -> Result<u32, String> {
    let mut c = [0u8; 4];
    fill(&mut c)?;
    Ok(u32::from_le_bytes(c))
}

/// w coefficients of +-1, the rest 0, in random positions.
fn short_random(fill: Fill<'_>) -> Result<Vec<i8>, String> {
    let mut list = Vec::with_capacity(P);
    for _ in 0..P {
        list.push(urandom32(fill)?);
    }
    Ok(short_fromlist(&mut list))
}

fn short_fromlist(list: &mut [u32]) -> Vec<i8> {
    for (i, value) in list.iter_mut().enumerate() {
        *value = if i < W { *value & !1 } else { (*value & !3) | 1 };
    }
    sort_u32(list);
    list.iter().map(|value| (*value & 3) as i8 - 1).collect()
}

fn small_random(fill: Fill<'_>) -> Result<Vec<i8>, String> {
    let mut out = Vec::with_capacity(P);
    for _ in 0..P {
        let u = urandom32(fill)?;
        out.push((((u & 0x3fff_ffff) as u64 * 3) >> 30) as i8 - 1);
    }
    Ok(out)
}

// ------------------------------------------------------------ encoding ---

fn small_encode(r: &[i8]) -> Vec<u8> {
    let mut out = vec![0u8; SMALL_BYTES];
    for (i, coefficient) in r.iter().enumerate() {
        out[i / 4] |= ((*coefficient + 1) as u8) << (2 * (i % 4));
    }
    out
}

fn small_decode(s: &[u8]) -> Vec<i8> {
    (0..P).map(|i| ((s[i / 4] >> (2 * (i % 4))) & 3) as i8 - 1).collect()
}

const LIMIT: u64 = 16384;

/// The reference's mixed-radix encoder: `r[i] < m[i]`, packed into as few
/// bytes as the radices allow.
fn encode(r: &[u64], m: &[u64], out: &mut Vec<u8>) {
    if m.is_empty() {
        return;
    }
    if m.len() == 1 {
        let (mut r, mut m) = (r[0], m[0]);
        while m > 1 {
            out.push(r as u8);
            r >>= 8;
            m = m.div_ceil(256);
        }
        return;
    }
    let mut r2 = Vec::with_capacity(m.len().div_ceil(2));
    let mut m2 = Vec::with_capacity(m.len().div_ceil(2));
    for i in (0..m.len() - 1).step_by(2) {
        let (mut mm, mut rr) = (m[i] * m[i + 1], r[i] + m[i] * r[i + 1]);
        while mm >= LIMIT {
            out.push(rr as u8);
            rr >>= 8;
            mm = mm.div_ceil(256);
        }
        r2.push(rr);
        m2.push(mm);
    }
    if m.len() % 2 == 1 {
        r2.push(r[m.len() - 1]);
        m2.push(m[m.len() - 1]);
    }
    encode(&r2, &m2, out);
}

fn decode(s: &[u8], m: &[u64]) -> Vec<u64> {
    if m.is_empty() {
        return Vec::new();
    }
    if m.len() == 1 {
        let mut value: u64 = 0;
        for (i, byte) in s.iter().enumerate().take(8) {
            value |= u64::from(*byte) << (8 * i);
        }
        return vec![value % m[0]];
    }
    let mut k = 0;
    let mut bottom = Vec::with_capacity(m.len() / 2);
    let mut m2 = Vec::with_capacity(m.len().div_ceil(2));
    for i in (0..m.len() - 1).step_by(2) {
        let (mut mm, mut r, mut t) = (m[i] * m[i + 1], 0u64, 1u64);
        while mm >= LIMIT {
            r += u64::from(s[k]) * t;
            t *= 256;
            k += 1;
            mm = mm.div_ceil(256);
        }
        bottom.push((r, t));
        m2.push(mm);
    }
    if m.len() % 2 == 1 {
        m2.push(m[m.len() - 1]);
    }
    let r2 = decode(&s[k..], &m2);
    let mut out = Vec::with_capacity(m.len());
    for i in (0..m.len() - 1).step_by(2) {
        let (r, t) = bottom[i / 2];
        let r = r + t * r2[i / 2];
        out.push(r % m[i]);
        out.push((r / m[i]) % m[i + 1]);
    }
    if m.len() % 2 == 1 {
        out.push(r2[r2.len() - 1]);
    }
    out
}

fn rq_encode(h: &[i16]) -> Vec<u8> {
    let r: Vec<u64> = h.iter().map(|c| (i32::from(*c) + Q12) as u64).collect();
    let mut out = Vec::with_capacity(PUBLIC_KEY_BYTES);
    encode(&r, &[Q as u64; P], &mut out);
    out
}

fn rq_decode(s: &[u8]) -> Vec<i16> {
    decode(s, &[Q as u64; P]).iter().map(|r| (*r as i32 - Q12) as i16).collect()
}

fn rounded_encode(c: &[i16]) -> Vec<u8> {
    let r: Vec<u64> = c.iter().map(|c| ((i32::from(*c) + Q12) / 3) as u64).collect();
    let mut out = Vec::with_capacity(ROUNDED_BYTES);
    encode(&r, &[((Q as u64 - 1) / 3) + 1; P], &mut out);
    out
}

fn rounded_decode(s: &[u8]) -> Vec<i16> {
    decode(s, &[((Q as u64 - 1) / 3) + 1; P]).iter()
        .map(|r| (3 * (*r as i32) - Q12) as i16).collect()
}

// --------------------------------------------------------------- hashes ---

fn hash_prefix(prefix: u8, parts: &[&[u8]]) -> [u8; HASH_BYTES] {
    let mut sha = SHA512::new(&[prefix], 512);
    for part in parts {
        sha.update(part);
    }
    let digest = sha.digest();
    let mut out = [0u8; HASH_BYTES];
    out.copy_from_slice(&digest[..HASH_BYTES]);
    out
}

// ------------------------------------------------------------------ KEM ---

/// A key pair: `(public key, secret key)`.
pub fn keypair(fill: Fill<'_>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (g, v) = loop {
        let g = small_random(fill)?;
        let (v, invertible) = r3_recip(&g);
        if invertible {
            break (g, v);
        }
    };
    let f = short_random(fill)?;
    let (finv, _) = rq_recip3(&f);
    let h = rq_mult_small(&finv, &g);
    let pk = rq_encode(&h);
    let mut sk = Vec::with_capacity(SECRET_KEY_BYTES);
    sk.extend_from_slice(&small_encode(&f));
    sk.extend_from_slice(&small_encode(&v));
    sk.extend_from_slice(&pk);
    let mut rho = [0u8; SMALL_BYTES];
    fill(&mut rho)?;
    sk.extend_from_slice(&rho);
    sk.extend_from_slice(&hash_prefix(4, &[&pk]));
    Ok((pk, sk))
}

/// `Hide`: the ciphertext for `r` under `pk`, and `r`'s encoding.
fn hide(r: &[i8], pk: &[u8], cache: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let r_enc = small_encode(r);
    let h = rq_decode(pk);
    let mut c = rounded_encode(&round(&rq_mult_small(&h, r)));
    let gamma = hash_prefix(2, &[&hash_prefix(3, &[&r_enc]), cache]);
    c.extend_from_slice(&gamma);
    (c, r_enc)
}

/// Encapsulate to `pk`: `(ciphertext, shared key)`.
pub fn encapsulate(pk: &[u8], fill: Fill<'_>) -> Result<(Vec<u8>, Vec<u8>), String> {
    if pk.len() != PUBLIC_KEY_BYTES {
        return Err(format!("sntrup761: a public key is {} bytes and should be {}.",
                           pk.len(), PUBLIC_KEY_BYTES));
    }
    let r = short_random(fill)?;
    let cache = hash_prefix(4, &[pk]);
    let (c, r_enc) = hide(&r, pk, &cache);
    let k = hash_prefix(1, &[&hash_prefix(3, &[&r_enc]), &c]);
    Ok((c, k.to_vec()))
}

/// Decapsulate. A ciphertext of the right length always yields a key;
/// one that was not made for this key yields a different one.
pub fn decapsulate(c: &[u8], sk: &[u8]) -> Result<Vec<u8>, String> {
    if c.len() != CIPHERTEXT_BYTES || sk.len() != SECRET_KEY_BYTES {
        return Err(format!("sntrup761: a ciphertext is {} bytes and a secret key \
                            {}; these are {} and {}.", CIPHERTEXT_BYTES,
                           SECRET_KEY_BYTES, c.len(), sk.len()));
    }
    let f = small_decode(&sk[..SMALL_BYTES]);
    let v = small_decode(&sk[SMALL_BYTES..2 * SMALL_BYTES]);
    let pk = &sk[2 * SMALL_BYTES..2 * SMALL_BYTES + PUBLIC_KEY_BYTES];
    let rho = &sk[2 * SMALL_BYTES + PUBLIC_KEY_BYTES..3 * SMALL_BYTES + PUBLIC_KEY_BYTES];
    let cache = &sk[3 * SMALL_BYTES + PUBLIC_KEY_BYTES..];

    // ZDecrypt: e = 3fc mod q, lifted, mod 3; r = e/g.
    let rounded = rounded_decode(&c[..ROUNDED_BYTES]);
    let cf = rq_mult_small(&rounded, &f);
    let e: Vec<i8> = cf.iter().map(|x| f3(i32::from(fq(3 * i32::from(*x))))).collect();
    let mut r = r3_mult(&e, &v);
    // Weight w, or the fixed substitute - chosen by a mask.
    let weight = r.iter().filter(|x| **x != 0).count() as i32;
    let bad = nonzero_mask(weight - W as i32) as i8;
    for (i, coefficient) in r.iter_mut().enumerate() {
        let substitute = i8::from(i < W);
        *coefficient ^= bad & (*coefficient ^ substitute);
    }

    let (c_new, r_enc) = hide(&r, pk, cache);
    let differ = c_new.iter().zip(c).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    // 0xff when they differ.
    let mask = 0u8.wrapping_sub(u8::from(differ != 0));
    let chosen: Vec<u8> = r_enc.iter().zip(rho).map(|(a, b)| a ^ (mask & (a ^ b))).collect();
    let prefix = 1u8 & !mask;
    Ok(hash_prefix(prefix, &[&hash_prefix(3, &[&chosen]), c]).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_sizes() {
        assert_eq!(SMALL_BYTES, 191);
        assert_eq!(rq_encode(&[0; P]).len(), PUBLIC_KEY_BYTES);
        assert_eq!(rounded_encode(&[0; P]).len(), ROUNDED_BYTES);
        assert_eq!(SECRET_KEY_BYTES, 1763);
        assert_eq!(CIPHERTEXT_BYTES, 1039);
    }

    #[test]
    fn test_the_sorting_network_sorts() {
        let mut state = 0x9e37_79b9u32;
        for n in [0usize, 1, 2, 3, 17, 286, 761] {
            let mut values: Vec<u32> = (0..n).map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state
            }).collect();
            let mut expected = values.clone();
            expected.sort_unstable();
            sort_u32(&mut values);
            assert_eq!(values, expected, "{n}");
        }
    }

    #[test]
    fn test_the_inverses_are_inverses() {
        let mut fill = |buf: &mut [u8]| crate::random::fill(buf);
        let g = loop {
            let g = small_random(&mut fill).unwrap();
            if r3_recip(&g).1 {
                break g;
            }
        };
        let (v, _) = r3_recip(&g);
        let mut one = vec![0i8; P];
        one[0] = 1;
        assert_eq!(r3_mult(&g, &v), one);

        let f = short_random(&mut fill).unwrap();
        assert_eq!(f.iter().filter(|x| **x != 0).count(), W);
        let (finv, ok) = rq_recip3(&f);
        assert!(ok);
        let three_f: Vec<i8> = f.iter().map(|x| 3 * x).collect::<Vec<i8>>();
        let mut one_q = vec![0i16; P];
        one_q[0] = 1;
        // finv * 3f, with 3f's coefficients up to 3 - still small enough
        // for rq_mult_small's i8.
        assert_eq!(rq_mult_small(&finv, &three_f), one_q);
    }

    #[test]
    fn test_encodings_round_trip() {
        let mut fill = |buf: &mut [u8]| crate::random::fill(buf);
        let (pk, _) = keypair(&mut fill).unwrap();
        assert_eq!(rq_encode(&rq_decode(&pk)), pk);
        let r = short_random(&mut fill).unwrap();
        assert_eq!(small_decode(&small_encode(&r)), r);
    }

    #[test]
    fn test_a_round_trip_and_implicit_rejection() {
        let mut fill = |buf: &mut [u8]| crate::random::fill(buf);
        let (pk, sk) = keypair(&mut fill).unwrap();
        let (c, k) = encapsulate(&pk, &mut fill).unwrap();
        assert_eq!(decapsulate(&c, &sk).unwrap(), k);
        let mut altered = c.clone();
        altered[100] ^= 1;
        let other = decapsulate(&altered, &sk).unwrap();
        assert_ne!(other, k);
        assert_eq!(other.len(), 32);
    }
}

#[cfg(test)]
mod document_tests {
    /*
    The two test vectors in draft-josefsson-ntruprime-streamlined-00
    section 7, read out of the vendored draft. Each is a NIST KAT record:
    a 48 byte seed for AES-256 CTR_DRBG, and the public key, secret key,
    ciphertext and shared key that keypair-then-encapsulate draws from
    it. Reproducing them needs the DRBG exactly as NIST's `rng.c` has it,
    including the discarded tail of every call - which is the reason
    `Fill` is called in the reference's pieces.
    */

    use super::*;
    use crate::api::AnyBlockCipher;
    use crate::block_ciphers::BlockCipher;

    const DRAFT: &str = include_str!("../../rfcs/draft-josefsson-ntruprime-streamlined-00.txt");

    /// NIST's AES-256 CTR_DRBG, no derivation function, no reseeding.
    struct Drbg {
        key: [u8; 32],
        v: [u8; 16],
    }

    impl Drbg {
        fn new(seed: &[u8]) -> Drbg {
            let mut drbg = Drbg { key: [0; 32], v: [0; 16] };
            drbg.update(Some(seed));
            drbg
        }

        fn block(&mut self) -> Vec<u8> {
            for byte in self.v.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
            let mut out = Vec::with_capacity(16);
            AnyBlockCipher::new("aes", &self.key, None).unwrap().block_encrypt(&self.v, &mut out);
            out
        }

        fn update(&mut self, provided: Option<&[u8]>) {
            let mut temp = Vec::with_capacity(48);
            for _ in 0..3 {
                temp.extend_from_slice(&self.block());
            }
            if let Some(provided) = provided {
                for (t, p) in temp.iter_mut().zip(provided) {
                    *t ^= p;
                }
            }
            self.key.copy_from_slice(&temp[..32]);
            self.v.copy_from_slice(&temp[32..]);
        }

        fn fill(&mut self, out: &mut [u8]) {
            for chunk in out.chunks_mut(16) {
                let block = self.block();
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
            self.update(None);
        }
    }

    /// Section 7's records: each field's quoted hex rows, joined.
    fn records() -> Vec<Vec<(String, Vec<u8>)>> {
        let start = DRAFT.find("7.  Streamlined NTRU Prime: Test Vectors\n").unwrap();
        // After `start`: the table of contents has the same title.
        let end = start + DRAFT[start..].find("8.  Acknowledgements").unwrap();
        let mut records: Vec<Vec<(String, Vec<u8>)>> = Vec::new();
        let mut current: Option<(String, String)> = None;
        let flush = |records: &mut Vec<Vec<(String, Vec<u8>)>>,
                     current: &mut Option<(String, String)>| {
            if let Some((name, hex)) = current.take() {
                let bytes = (0..hex.len()).step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
                records.last_mut().unwrap().push((name, bytes));
            }
        };
        for line in DRAFT[start..end].lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("count =") {
                flush(&mut records, &mut current);
                records.push(Vec::new());
            } else if let Some((name, rest)) = trimmed.split_once('=')
                .filter(|(name, _)| ["seed", "pk", "sk", "ct", "ss"].contains(&name.trim())) {
                flush(&mut records, &mut current);
                current = Some((name.trim().to_string(), rest.trim().trim_matches('"').to_string()));
            } else if trimmed.starts_with('"') {
                if let Some((_, hex)) = current.as_mut() {
                    hex.push_str(trimmed.trim_matches('"'));
                }
            }
        }
        flush(&mut records, &mut current);
        records
    }

    #[test]
    fn test_the_drafts_vectors() {
        let all = records();
        assert_eq!(all.len(), 2, "two records in section 7");
        for record in all {
            let get = |name: &str| &record.iter().find(|(n, _)| n == name).unwrap().1;
            assert_eq!(get("seed").len(), 48);
            let mut drbg = Drbg::new(get("seed"));
            let mut fill = |buf: &mut [u8]| { drbg.fill(buf); Ok(()) };
            let (pk, sk) = keypair(&mut fill).unwrap();
            assert_eq!(&pk, get("pk"), "public key");
            assert_eq!(&sk, get("sk"), "secret key");
            let (ct, ss) = encapsulate(&pk, &mut fill).unwrap();
            assert_eq!(&ct, get("ct"), "ciphertext");
            assert_eq!(&ss, get("ss"), "shared key");
            assert_eq!(&decapsulate(&ct, &sk).unwrap(), get("ss"), "decapsulated");
        }
    }
}
