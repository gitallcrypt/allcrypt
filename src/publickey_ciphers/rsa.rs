/*
RSA: the primitives, PKCS#1 v1.5 encryption and signatures, OAEP and PSS.

Three things in here are load bearing and easy to leave out, so they are
listed first rather than buried:

  1. **The CRT result is checked before it is returned.** A single bit flipped
     during the CRT half of a private operation - by cosmic ray, by a
     deliberately induced fault, by bad RAM - lets an attacker factor the
     modulus from one bad signature and the message, by taking
     gcd(s^e - m, n). This is the Bellcore attack, it is about as cheap as an
     attack gets, and the defence is one public exponentiation: verify the
     result, and refuse to return it if it does not check out.

  2. **Private operations are blinded.** Blinding multiplies the input by
     r^e for a fresh random r, exponentiates that, then divides out r, so the
     value the arithmetic actually runs on is unpredictable to an attacker
     even when they chose the ciphertext. That is the input-dependent leak
     Brumley and Boneh used to extract a key over a network. The exponent
     is handled separately: the CRT halves run at fixed width, with
     `Montgomery::pow_ct` on `Secret`s, so its timing does not follow `d`.

  3. **PKCS#1 v1.5 decryption cannot report why it failed.** Distinguishing
     "the padding was wrong" from "the padding was right and the message was
     odd" is Bleichenbacher's 1998 attack, and it recovers the plaintext of a
     captured session in a few hundred thousand queries. The decryption here
     returns one error for every failure, and the caller must not add detail.
     See docs/pitfalls.md section 3.

What is deliberately *not* here yet: key generation from a strong prime
search beyond Miller-Rabin, and multi-prime RSA. PKCS#1 v1.5 came first
because it is what the legacy TLS suites use, which is the reason this
library exists.
*/

use crate::api::AnyHash;
use crate::bignum::{montgomery, BigUint, Montgomery, Secret};
use crate::hash_functions::HashFunction;
use crate::random;

// --------------------------------------------------------------- the keys ---

/// The public half: modulus and exponent. Everything here is public by
/// definition, so nothing in this half needs to be constant time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

impl RsaPublicKey {
    pub fn new(n: BigUint, e: BigUint) -> Result<RsaPublicKey, String> {
        if n.is_zero() || n.is_even() {
            return Err("RSA modulus must be odd and non-zero.".to_string());
        }
        if e.is_zero() || e.is_one() || e.is_even() {
            return Err("RSA public exponent must be odd and greater than 1.".to_string());
        }
        if e >= n {
            return Err("RSA public exponent must be smaller than the modulus.".to_string());
        }
        Ok(RsaPublicKey { n, e })
    }

    /// The modulus size in bytes, which is the size of every ciphertext and
    /// signature this key produces.
    pub fn size(&self) -> usize {
        self.n.bit_len().div_ceil(8)
    }

    pub fn bits(&self) -> usize {
        self.n.bit_len()
    }

    /// RSAEP / RSAVP1: `m^e mod n`. The same operation for encrypting with a
    /// public key and for recovering the padded block from a signature.
    pub fn raw(&self, m: &BigUint) -> Result<BigUint, String> {
        if *m >= self.n {
            return Err("Value is not smaller than the modulus.".to_string());
        }
        m.mod_pow(&self.e, &self.n)
    }
}

/// The private half. Carries the CRT parameters because that is where the
/// speedup is - a CRT private operation is about four times faster than the
/// straightforward one, since it exponentiates two half-size values.
#[derive(Clone, Debug)]
pub struct RsaPrivateKey {
    pub public: RsaPublicKey,
    d: BigUint,
    p: BigUint,
    q: BigUint,
    /// d mod (p-1)
    dp: BigUint,
    /// d mod (q-1)
    dq: BigUint,
    /// q^-1 mod p
    qinv: BigUint,
    /// Montgomery contexts for p, q and n, built once at construction.
    ///
    /// **Building one divides by its modulus**, and for `p` and `q` that is
    /// a division by a secret prime. Doing it per operation - which is what
    /// `Montgomery::new(&self.p)` inside `raw` amounted to - put back a
    /// bigger leak than the one the constant-time path removed, on every
    /// signature. Here it happens once, while the key is being made.
    mont_p: Montgomery,
    mont_q: Montgomery,
    mont_n: Montgomery,
}

impl RsaPrivateKey {
    /// Build a key from the primes. `e` is normally 65537.
    ///
    /// The CRT parameters are derived here rather than taken from the
    /// caller: a key file with inconsistent CRT parameters is a known way to
    /// make an implementation leak, and deriving them means there is nothing
    /// to be inconsistent with.
    pub fn from_primes(p: BigUint, q: BigUint, e: BigUint) -> Result<RsaPrivateKey, String> {
        if p == q {
            return Err("The two primes must be different.".to_string());
        }
        if p.is_even() || q.is_even() || p.is_one() || q.is_one() {
            return Err("Both primes must be odd and greater than 1.".to_string());
        }

        let one = BigUint::one();
        let n = p.mul(&q);
        let p1 = p.sub(&one)?;
        let q1 = q.sub(&one)?;

        // lambda(n) = lcm(p-1, q-1). Using lambda rather than phi gives the
        // smallest working d, which is what every modern spec asks for.
        let g = p1.gcd(&q1);
        let lambda = p1.mul(&q1).div(&g)?;

        if !e.gcd(&lambda).is_one() {
            return Err("Public exponent shares a factor with lambda(n); \
                        this key cannot be inverted.".to_string());
        }
        let d = e.mod_inverse(&lambda)?;

        // The CRT exponents use p-1 and q-1, not lambda.
        let dp = d.rem(&p1)?;
        let dq = d.rem(&q1)?;
        let qinv = q.mod_inverse(&p)?;

        let mont_p = Montgomery::new(&p)?;
        let mont_q = Montgomery::new(&q)?;
        let public = RsaPublicKey::new(n, e)?;
        let mont_n = Montgomery::new(&public.n)?;
        let key = RsaPrivateKey { public, d, p, q, dp, dq, qinv,
                                  mont_p, mont_q, mont_n };

        // A key that cannot round trip is not a key. This catches a
        // composite "prime" as well as any arithmetic slip above, and costs
        // one operation at construction rather than a wrong answer later.
        let probe = BigUint::from_u64(0xC0FFEE);
        if key.public.raw(&key.raw(&probe)?)? != probe {
            return Err("The key does not round trip; the primes are probably \
                        not both prime.".to_string());
        }
        Ok(key)
    }

    /// Generate a fresh key. `bits` is the modulus size; 2048 is the
    /// sensible minimum today and 1024 is only for talking to something old.
    ///
    /// Each prime is `bits/2` long with its top two bits set, which
    /// guarantees the product has exactly `bits` bits - otherwise a key
    /// labelled 2048 bit is sometimes 2047, and some peers reject that.
    pub fn generate(bits: usize) -> Result<RsaPrivateKey, String> {
        if bits < 512 || !bits.is_multiple_of(2) {
            return Err("Key size must be even and at least 512 bits.".to_string());
        }
        let e = BigUint::from_u64(65537);
        let half = bits / 2;

        for _ in 0..100 {
            let p = generate_prime(half, &e)?;
            let q = generate_prime(half, &e)?;
            if p == q {
                continue;
            }
            // The primes must not be close together: if |p - q| is small,
            // Fermat's method factors n by searching near sqrt(n). Requiring
            // them to differ in the top 100 bits is the usual guard.
            let difference = if p > q { p.sub(&q)? } else { q.sub(&p)? };
            if difference.bit_len() < half - 100 {
                continue;
            }
            match RsaPrivateKey::from_primes(p, q, e.clone()) {
                Ok(key) if key.public.bits() == bits => return Ok(key),
                _ => continue,
            }
        }
        Err("Key generation failed 100 times; the random source looks broken."
            .to_string())
    }

    pub fn size(&self) -> usize {
        self.public.size()
    }

    pub fn bits(&self) -> usize {
        self.public.bits()
    }

    pub fn public_key(&self) -> RsaPublicKey {
        self.public.clone()
    }

    /// A `BigUint`'s limbs, zero padded to exactly `k`. Errors rather than
    /// truncating: a silently narrowed operand here is a wrong plaintext.
    fn widen_to(value: &BigUint, k: usize) -> Result<Vec<u64>, String> {
        if value.limbs().len() > k {
            return Err(format!("Value needs {} limbs, width is {}.",
                               value.limbs().len(), k));
        }
        let mut out = vec![0u64; k];
        out[..value.limbs().len()].copy_from_slice(value.limbs());
        Ok(out)
    }

    /// RSADP / RSASP1: `c^d mod n`, by CRT, blinded, and checked.
    ///
    /// See the three numbered points at the top of this file - all of them
    /// live in this function.
    pub fn raw(&self, c: &BigUint) -> Result<BigUint, String> {
        let n = &self.public.n;
        if *c >= *n {
            return Err("Value is not smaller than the modulus.".to_string());
        }

        // Blinding. r is fresh per operation; the arithmetic then runs on
        // c * r^e, which the attacker cannot predict even having chosen c.
        let (blinded, unblind) = self.blinding_factors(c)?;

        // Everything from here to the unblinding is secret, and the divisors
        // are the primes themselves. `blinded.rem(&self.p)` was a Knuth
        // division whose add-back path depends on both operands - one of
        // which is `p`. The whole recombination is therefore done at fixed
        // width, with `reduce_wide` in place of every `rem`.
        let (mp, mq, mn) = (&self.mont_p, &self.mont_q, &self.mont_n);
        let (kp, kq, kn) = (mp.limbs(), mq.limbs(), mn.limbs());

        // `blinded` is below `n = p*q`, so it fits `2*kp` and `2*kq` limbs
        // and satisfies the `x < modulus * R` that `reduce_wide` needs.
        let blinded_p = mp.reduce_wide(&Self::widen_to(&blinded, 2 * kp)?)?;
        let blinded_q = mq.reduce_wide(&Self::widen_to(&blinded, 2 * kq)?)?;

        // CRT: two exponentiations modulo the primes rather than one modulo
        // n. The exponents are secret, so both use the ladder.
        let m1 = mp.pow_ct(&blinded_p, &Secret::from_biguint(&self.dp, kp)?, kp * 64);
        let m2 = mq.pow_ct(&blinded_q, &Secret::from_biguint(&self.dq, kq)?, kq * 64);

        // h = qinv * (m1 - m2) mod p, with the subtraction done in the ring
        // so it never goes negative. `m2` is below `q`, which may be above
        // or below `p`, so it has to come down modulo `p` first.
        let m2_mod_p = mp.reduce_wide(m2.resize(2 * kp)?.limbs())?;
        let difference = mp.sub_mod(&m1, &m2_mod_p);
        let h = mp.mul_mod(&Secret::from_biguint(&self.qinv, kp)?, &difference);

        // m = m2 + h*q. Both `h < p` and `m2 < q`, so the sum is below
        // `p*q + q <= 2n` and one conditional subtraction finishes it - no
        // division by `n` is needed, which matters because the dividend
        // would have been the plaintext.
        let product = h.resize(kn)?.mul_wide(&Secret::from_biguint(&self.q, kn)?);
        let mut recombined = Secret::from_limbs(product[..kn].to_vec());
        let high = product[kn..].iter().fold(0u64, |acc, &limb| acc | limb);
        debug_assert_eq!(high, 0, "h*q must fit the modulus width");
        let (sum, carry) = recombined.add(&m2.resize(kn)?);
        recombined = mn.reduce_once(sum, carry);

        // The unblinding is modulo `n`, which is public, but the value is
        // the plaintext - so it stays in the fixed-width path too.
        let m = mn.mul_mod(&recombined, &unblind);

        // The Bellcore check. If a fault corrupted either half of the CRT,
        // m^e will not be c, and returning m would hand over the
        // factorisation of n.
        //
        // Done at fixed width rather than through `self.public.raw(&m)`,
        // which would take the plaintext out to a normalised `BigUint` and
        // compare it with `!=`. A fault check has no business leaking the
        // value it is checking, and `c` is public so comparing against it
        // with a mask costs nothing.
        let recovered = mn.pow_public(&m, &self.public.e);
        let expected = Secret::from_biguint(c, kn)?;
        if !montgomery::unmask(recovered.ct_eq(&expected)) {
            return Err("RSA private operation failed its own verification; \
                        refusing to return a possibly faulty result.".to_string());
        }

        // The plaintext leaves as a `BigUint`, which normalises it. That is
        // the API boundary: the caller asked for the number. For a PKCS#1
        // block the top byte is always zero, so the length says nothing the
        // modulus size did not already.
        Ok(m.declassify())
    }

    /// `(c * r^e mod n, r^-1 mod n)` for a fresh random r.
    ///
    /// Fixed width throughout but for one step. The inverse is the
    /// Euclidean algorithm, which is variable time, so it is not taken of
    /// `r`: it is taken of `r * s` for a second random `s` - a value that
    /// says nothing about `r` - and `s` is multiplied back in afterwards,
    /// `s * (r s)^-1 = r^-1`. Two multiplications buy an inverse whose
    /// timing has nothing to measure.
    fn blinding_factors(&self, c: &BigUint) -> Result<(BigUint, Secret), String> {
        let n = &self.public.n;
        let mn = &self.mont_n;
        let kn = mn.limbs();
        for _ in 0..64 {
            let r = Secret::from_biguint(&random::below(n)?, kn)?;
            let s = Secret::from_biguint(&random::below(n)?, kn)?;
            // `r s` is invertible exactly when both are. For a genuine RSA
            // modulus a failure means one of them is a multiple of p or q,
            // which would also have factored n by accident.
            let inverse = match mn.mul_mod(&r, &s).declassify().mod_inverse(n) {
                Ok(inverse) => inverse,
                Err(_) => continue,
            };
            let r_inverse = mn.mul_mod(&Secret::from_biguint(&inverse, kn)?, &s);
            let blinded = mn.mul_mod(&Secret::from_biguint(c, kn)?,
                                     &mn.pow_public(&r, &self.public.e));
            return Ok((blinded.declassify(), r_inverse));
        }
        Err("Could not find a blinding factor; the random source looks broken."
            .to_string())
    }

    /// The private exponent, for serialisation. Nothing in this crate needs
    /// it - the CRT path does not use `d` - but a key file does.
    pub fn private_exponent(&self) -> &BigUint {
        &self.d
    }

    pub fn primes(&self) -> (&BigUint, &BigUint) {
        (&self.p, &self.q)
    }

    pub fn crt_parameters(&self) -> (&BigUint, &BigUint, &BigUint) {
        (&self.dp, &self.dq, &self.qinv)
    }
}

// ------------------------------------------------------------- primality ---

/// Primes below 256, for trial division. Rejecting a candidate by trial
/// division costs a few modular reductions; rejecting it by Miller-Rabin
/// costs a full exponentiation, and trial division alone removes about 80%
/// of odd candidates.
const SMALL_PRIMES: [u64; 54] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251,
];

/// Miller-Rabin with `rounds` random bases.
///
/// This is a probabilistic test: a composite survives one round with
/// probability at most 1/4, so 64 rounds leaves at most 4^-64. That is far
/// below the chance of the hardware getting the arithmetic wrong, which is
/// the honest way to think about the bound.
///
/// The bases are random rather than the first few primes on purpose. Fixed
/// bases are fine for a number that arrived by chance and not fine for one
/// an adversary chose, because composites that pass any fixed base set can
/// be constructed deliberately.
pub fn is_probably_prime(candidate: &BigUint, rounds: usize) -> Result<bool, String> {
    let one = BigUint::one();
    let two = BigUint::from_u64(2);

    if *candidate < two {
        return Ok(false);
    }
    for small in SMALL_PRIMES {
        let small = BigUint::from_u64(small);
        if *candidate == small {
            return Ok(true);
        }
        if candidate.rem(&small)?.is_zero() {
            return Ok(false);
        }
    }

    // n - 1 = 2^s * d with d odd.
    let n_minus_1 = candidate.sub(&one)?;
    let mut d = n_minus_1.clone();
    let mut s = 0usize;
    while d.is_even() {
        d = d.shr(1);
        s += 1;
    }

    'witness: for _ in 0..rounds {
        // A base in [2, n-2].
        let a = random::below(&n_minus_1)?;
        let a = if a < two { two.clone() } else { a };

        let mut x = a.mod_pow(&d, candidate)?;
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        for _ in 1..s {
            x = x.mod_mul(&x, candidate)?;
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return Ok(false);
    }
    Ok(true)
}

/// A random prime of exactly `bits` bits, coprime to `e`.
///
/// The top two bits are set so that the product of two such primes has
/// exactly `2*bits` bits, and the bottom bit is set because no even number
/// above 2 is prime.
fn generate_prime(bits: usize, e: &BigUint) -> Result<BigUint, String> {
    if bits < 256 {
        return Err("Primes below 256 bits are not worth generating.".to_string());
    }
    let one = BigUint::one();

    for _ in 0..(100 * bits) {
        let mut bytes = random::bytes(bits.div_ceil(8))?;
        // Clear anything above `bits`, then force the top two and bottom bit.
        let spare = bytes.len() * 8 - bits;
        if spare > 0 {
            bytes[0] &= 0xffu8 >> spare;
        }
        bytes[0] |= 0b1100_0000u8 >> spare;
        let last = bytes.len() - 1;
        bytes[last] |= 1;

        let candidate = BigUint::from_bytes_be(&bytes);
        if candidate.bit_len() != bits {
            continue;
        }
        // e must be invertible mod (candidate - 1), or the key cannot exist.
        if !e.gcd(&candidate.sub(&one)?).is_one() {
            continue;
        }
        if is_probably_prime(&candidate, 64)? {
            return Ok(candidate);
        }
    }
    Err(format!("Failed to find a {} bit prime; the random source looks broken.", bits))
}

// ------------------------------------------------------- PKCS#1 v1.5, enc ---

/// PKCS#1 v1.5 encryption (RFC 8017 section 7.2.1).
///
/// `EM = 0x00 || 0x02 || PS || 0x00 || M`, where PS is at least 8 nonzero
/// random bytes. The randomness is not optional: without it RSA is
/// deterministic, and a small message space can simply be enumerated.
pub fn encrypt_pkcs1v15(key: &RsaPublicKey, message: &[u8]) -> Result<Vec<u8>, String> {
    let size = key.size();
    if message.len() + 11 > size {
        return Err(format!("Message of {} bytes is too long for a {} byte key \
                            (limit {}).", message.len(), size, size - 11));
    }

    let padding_len = size - message.len() - 3;
    let mut padding = Vec::with_capacity(padding_len);
    // PS must contain no zero byte, since a zero is the separator. Drawing
    // fresh bytes and discarding zeros keeps it uniform over 1..=255.
    while padding.len() < padding_len {
        for byte in random::bytes(padding_len - padding.len() + 8)? {
            if byte != 0 {
                padding.push(byte);
                if padding.len() == padding_len {
                    break;
                }
            }
        }
    }

    let mut block = Vec::with_capacity(size);
    block.push(0x00);
    block.push(0x02);
    block.extend_from_slice(&padding);
    block.push(0x00);
    block.extend_from_slice(message);

    let ciphertext = key.raw(&BigUint::from_bytes_be(&block))?;
    ciphertext.to_bytes_be_padded(size)
}

/// PKCS#1 v1.5 decryption.
///
/// **Every failure returns the same error.** Padding wrong, separator
/// missing, length wrong - one message, no detail, and callers must not add
/// any. Telling an attacker which check failed, or taking a different amount
/// of time to fail, is Bleichenbacher's attack: it turns the server into an
/// oracle that decrypts a captured ciphertext in a few hundred thousand
/// queries.
///
/// The private operation underneath is fixed width, but this padding check
/// has no constant-time measurement of its own, so it reduces the oracle
/// rather than removing it. A protocol that needs to be safe against
/// Bleichenbacher must additionally do what TLS does: continue with a
/// random premaster secret on failure, so that failing to decrypt is
/// indistinguishable from decrypting to the wrong thing. That is the
/// protocol's job; the TLS server does it in
/// `ServerConnection::decrypt_premaster`.
pub fn decrypt_pkcs1v15(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    const FAILURE: &str = "RSA decryption failed.";
    let size = key.size();
    if ciphertext.len() != size {
        return Err(FAILURE.to_string());
    }

    let block = key.raw(&BigUint::from_bytes_be(ciphertext))
        .map_err(|_| FAILURE.to_string())?
        .to_bytes_be_padded(size)
        .map_err(|_| FAILURE.to_string())?;

    // Gather every condition before branching on any of them, so the shape
    // of the code does not itself describe which check failed.
    let mut good = (block[0] == 0x00) as u8 & (block[1] == 0x02) as u8;
    let mut separator = 0usize;
    let mut found = 0u8;
    for (index, &byte) in block.iter().enumerate().skip(2) {
        let is_zero = (byte == 0) as u8;
        let first = is_zero & (1 - found);
        separator |= index * first as usize;
        found |= is_zero;
    }
    good &= found;
    // PS must be at least 8 bytes, so the separator cannot be before index 10.
    good &= (separator >= 10) as u8;

    if good != 1 {
        return Err(FAILURE.to_string());
    }
    Ok(block[separator + 1..].to_vec())
}

// ------------------------------------------------------------------ OAEP ---

/// RSAES-OAEP encryption (RFC 8017 section 7.1.1), with a fresh random
/// seed.
///
/// `hash_name` hashes the label and sets the seed's length; `mgf_hash`
/// is MGF1's hash. RFC 8017 lets them differ and deployed parameter sets
/// do differ: JOSE's `RSA-OAEP` is SHA-1 for both, `RSA-OAEP-256` SHA-256
/// for both, and some Java configurations pair SHA-256 with MGF1-SHA-1.
pub fn encrypt_oaep(key: &RsaPublicKey, hash_name: &str, mgf_hash: &str, label: &[u8],
                    message: &[u8]) -> Result<Vec<u8>, String> {
    let seed = random::bytes(AnyHash::new(hash_name)?.digest_len())?;
    encrypt_oaep_with_seed(key, hash_name, mgf_hash, label, message, &seed)
}

/// RSAES-OAEP encryption with the seed given, which makes it
/// deterministic: for known-answer tests, and nothing else. A repeated
/// seed encrypts a repeated message to the same ciphertext.
pub fn encrypt_oaep_with_seed(key: &RsaPublicKey, hash_name: &str, mgf_hash: &str,
                              label: &[u8], message: &[u8], seed: &[u8])
                              -> Result<Vec<u8>, String> {
    let mut label_hash = AnyHash::new(hash_name)?;
    let hash_len = label_hash.digest_len();
    AnyHash::new(mgf_hash)?;
    if seed.len() != hash_len {
        return Err(format!("An OAEP seed under {hash_name} is {hash_len} bytes, not {}.",
                           seed.len()));
    }
    let k = key.size();
    if k < 2 * hash_len + 2 || message.len() > k - 2 * hash_len - 2 {
        return Err(format!(
            "Message of {} bytes is too long for OAEP with {} and a {} byte key \
             (limit {}).", message.len(), hash_name, k,
            k.saturating_sub(2 * hash_len + 2)));
    }

    // DB = lHash || PS || 0x01 || M, PS zeros to fill k - hLen - 1.
    label_hash.update(label);
    let db_len = k - hash_len - 1;
    let mut db = Vec::with_capacity(db_len);
    db.extend_from_slice(&label_hash.digest());
    db.resize(db_len - message.len() - 1, 0);
    db.push(0x01);
    db.extend_from_slice(message);

    // The DB is masked by the seed, then the seed by the masked DB.
    let db_mask = mgf1(mgf_hash, seed, db_len)?;
    for (byte, m) in db.iter_mut().zip(&db_mask) {
        *byte ^= m;
    }
    let seed_mask = mgf1(mgf_hash, &db, hash_len)?;
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.extend(seed.iter().zip(&seed_mask).map(|(s, m)| s ^ m));
    em.extend_from_slice(&db);

    let ciphertext = key.raw(&BigUint::from_bytes_be(&em))?;
    ciphertext.to_bytes_be_padded(k)
}

/// RSAES-OAEP decryption (RFC 8017 section 7.1.2): the private operation,
/// then `eme_oaep_decode`.
///
/// **Every failure of the ciphertext returns the same error.** Telling
/// an attacker whether the leading byte was zero is Manger's attack,
/// which decrypts a ciphertext in about a thousand queries - far fewer
/// than Bleichenbacher needs against PKCS#1 v1.5. The parameters -
/// hashes, key size - are public, and their errors say what is wrong.
pub fn decrypt_oaep(key: &RsaPrivateKey, hash_name: &str, mgf_hash: &str, label: &[u8],
                    ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let k = key.size();
    let hash_len = AnyHash::new(hash_name)?.digest_len();
    AnyHash::new(mgf_hash)?;
    if k < 2 * hash_len + 2 {
        return Err(format!("A {k} byte key is too small for OAEP with {hash_name}."));
    }
    if ciphertext.len() != k {
        return Err(OAEP_FAILURE.to_string());
    }
    let em = key.raw(&BigUint::from_bytes_be(ciphertext))
        .map_err(|_| OAEP_FAILURE.to_string())?
        .to_bytes_be_padded(k)
        .map_err(|_| OAEP_FAILURE.to_string())?;
    eme_oaep_decode(&em, hash_name, mgf_hash, label)
}

const OAEP_FAILURE: &str = "RSA decryption failed.";

/// EME-OAEP decoding (RFC 8017 section 7.1.2 step 3): the encoded
/// message `EM = Y || maskedSeed || maskedDB` back to the message.
///
/// Public so the padding can be tested apart from the private operation.
/// The conditions - `Y` zero, `lHash'` equal, a `0x01` after the zeros -
/// are folded into one mask before anything branches, and every one of
/// them fails with the same error as `decrypt_oaep`'s.
pub fn eme_oaep_decode(em: &[u8], hash_name: &str, mgf_hash: &str, label: &[u8])
                       -> Result<Vec<u8>, String> {
    let mut label_hash = AnyHash::new(hash_name)?;
    let hash_len = label_hash.digest_len();
    AnyHash::new(mgf_hash)?;
    if em.len() < 2 * hash_len + 2 {
        return Err(format!("{} bytes is too short an OAEP block for {hash_name}.", em.len()));
    }
    let (masked_seed, masked_db) = em[1..].split_at(hash_len);
    let seed_mask = mgf1(mgf_hash, masked_db, hash_len)?;
    let seed: Vec<u8> = masked_seed.iter().zip(&seed_mask).map(|(s, m)| s ^ m).collect();
    let db_mask = mgf1(mgf_hash, &seed, masked_db.len())?;
    let db: Vec<u8> = masked_db.iter().zip(&db_mask).map(|(d, m)| d ^ m).collect();
    label_hash.update(label);
    let expected = label_hash.digest();

    // Y must be zero and lHash' must match, compared without an early
    // exit; then PS is zeros up to the first nonzero byte, which must be
    // 0x01 - its position found by a scan of the whole block.
    let mut difference = em[0];
    for (a, b) in db[..hash_len].iter().zip(&expected) {
        difference |= a ^ b;
    }
    let mut good = (difference == 0) as u8;
    let mut looking = 1u8;
    let mut separator = 0usize;
    let mut bad_separator = 0u8;
    for (index, &byte) in db.iter().enumerate().skip(hash_len) {
        let nonzero = (byte != 0) as u8;
        let first = looking & nonzero;
        separator |= index * first as usize;
        bad_separator |= first & (byte != 0x01) as u8;
        looking &= 1 - nonzero;
    }
    good &= (1 - looking) & (1 - bad_separator);
    oaep_verdict(good, &db, separator)
}

/// Where the verdict and the message's length become public: the one
/// branch, and the slice at the separator. A function of its own, never
/// inlined, so that `scripts/ct_check.py` can name it - and so a branch
/// that appeared in `eme_oaep_decode` itself would be reported there
/// rather than hiding behind this one.
#[inline(never)]
fn oaep_verdict(good: u8, db: &[u8], separator: usize) -> Result<Vec<u8>, String> {
    if good != 1 {
        return Err(OAEP_FAILURE.to_string());
    }
    Ok(db[separator + 1..].to_vec())
}

// ------------------------------------------------------ PKCS#1 v1.5, sign ---

/// The DigestInfo DER prefix for each hash, from RFC 8017 section 9.2 note 1.
///
/// These are constants rather than something built by an ASN.1 encoder on
/// purpose. Signature verification must compare the *whole* encoded block
/// byte for byte; an implementation that parses the DigestInfo instead and
/// ignores trailing bytes is forgeable with a low public exponent, which is
/// the Bleichenbacher 2006 forgery that hit several libraries at once.
pub(crate) fn digest_info_prefix(hash_name: &str) -> Result<&'static [u8], String> {
    Ok(match hash_name.to_ascii_lowercase().as_str() {
        "md5" => &[0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86,
                   0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10],
        "sha1" => &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
                    0x1a, 0x05, 0x00, 0x04, 0x14],
        "sha224" => &[0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                      0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c],
        "sha256" => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
        "sha384" => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                      0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
        "sha512" => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                      0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        other => return Err(format!(
            "No PKCS#1 DigestInfo prefix for {:?}. Known: md5, sha1, sha224, \
             sha256, sha384, sha512.", other)),
    })
}

/// `EM = 0x00 || 0x01 || 0xFF... || 0x00 || DigestInfo`, RFC 8017 section 9.2.
fn emsa_pkcs1v15(hash_name: &str, digest: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let prefix = digest_info_prefix(hash_name)?;
    let encoded_len = prefix.len() + digest.len();
    if encoded_len + 11 > size {
        return Err(format!("A {} byte key is too small to sign a {} digest.",
                           size, hash_name));
    }

    let mut block = Vec::with_capacity(size);
    block.push(0x00);
    block.push(0x01);
    block.resize(size - encoded_len - 1, 0xff);
    block.push(0x00);
    block.extend_from_slice(prefix);
    block.extend_from_slice(digest);
    debug_assert_eq!(block.len(), size);
    Ok(block)
}

/// `EM = 0x00 || 0x01 || 0xFF... || 0x00 || digest`, with **no DigestInfo**.
///
/// Not a variant anyone would invent. TLS 1.0 and 1.1 sign the
/// ServerKeyExchange with exactly this: the digest is `MD5(input) ||
/// SHA1(input)`, 36 bytes, and RFC 4346 section 7.4.3 says it is signed
/// "using PKCS#1 block type 1" with the hash identifier omitted. There is
/// no DigestInfo because there is no algorithm to identify - the pair is
/// fixed by the protocol version.
///
/// TLS 1.2 replaced this with an ordinary PKCS#1 v1.5 signature over a
/// single named hash, which is why `emsa_pkcs1v15` above is the one every
/// other caller wants.
fn emsa_pkcs1v15_raw(digest: &[u8], size: usize) -> Result<Vec<u8>, String> {
    if digest.len() + 11 > size {
        return Err(format!("A {} byte key is too small for a {} byte digest.",
                           size, digest.len()));
    }
    let mut block = Vec::with_capacity(size);
    block.push(0x00);
    block.push(0x01);
    block.resize(size - digest.len() - 1, 0xff);
    block.push(0x00);
    block.extend_from_slice(digest);
    debug_assert_eq!(block.len(), size);
    Ok(block)
}

/// Verify a PKCS#1 v1.5 signature over a digest with no DigestInfo.
///
/// For TLS 1.0 and 1.1 ServerKeyExchange signatures; see
/// `emsa_pkcs1v15_raw`. Like `verify_pkcs1v15`, this compares against the
/// block we would have produced rather than parsing the one we received.
pub fn verify_pkcs1v15_raw(key: &RsaPublicKey, digest: &[u8], signature: &[u8])
                           -> Result<bool, String> {
    let size = key.size();
    if signature.len() != size {
        return Err(format!("Signature must be {} bytes, got {}.",
                           size, signature.len()));
    }
    let value = BigUint::from_bytes_be(signature);
    if value >= key.n {
        return Ok(false);
    }

    let recovered = key.raw(&value)?.to_bytes_be_padded(size)?;
    let expected = emsa_pkcs1v15_raw(digest, size)?;

    let mut difference = 0u8;
    for (a, b) in recovered.iter().zip(expected.iter()) {
        difference |= a ^ b;
    }
    Ok(difference == 0)
}

/// Sign an already computed digest with PKCS#1 v1.5.
///
/// `hash_name` must name the hash that produced the digest: it selects the
/// DigestInfo prefix, and a mismatch produces a signature that says one
/// thing and means another.
pub fn sign_pkcs1v15(key: &RsaPrivateKey, hash_name: &str, digest: &[u8])
                     -> Result<Vec<u8>, String> {
    let size = key.size();
    let block = emsa_pkcs1v15(hash_name, digest, size)?;
    let signature = key.raw(&BigUint::from_bytes_be(&block))?;
    signature.to_bytes_be_padded(size)
}

/// Sign a digest with PKCS#1 v1.5 and **no DigestInfo**.
///
/// The counterpart of `verify_pkcs1v15_raw`, for TLS 1.0 and 1.1, where
/// the digest is `MD5(input) || SHA1(input)` and the hash identifier is
/// omitted because the protocol version fixes the pair (RFC 4346 7.4.3).
///
/// Named `_raw` rather than taking a flag on `sign_pkcs1v15`, because a
/// flag is a thing a caller can pass wrongly: the two produce different
/// signatures over the same digest, and the wrong one verifies against
/// nothing while looking exactly like a wrong key.
pub fn sign_pkcs1v15_raw(key: &RsaPrivateKey, digest: &[u8])
                         -> Result<Vec<u8>, String> {
    let size = key.size();
    let block = emsa_pkcs1v15_raw(digest, size)?;
    let signature = key.raw(&BigUint::from_bytes_be(&block))?;
    signature.to_bytes_be_padded(size)
}

/// Verify a PKCS#1 v1.5 signature.
///
/// The check is a byte comparison against the block we would have produced,
/// not a parse of the block we received. That is the whole difference
/// between this and the forgeable version.
pub fn verify_pkcs1v15(key: &RsaPublicKey, hash_name: &str, digest: &[u8],
                       signature: &[u8]) -> Result<bool, String> {
    let size = key.size();
    if signature.len() != size {
        return Err(format!("Signature must be {} bytes, got {}.", size, signature.len()));
    }
    let value = BigUint::from_bytes_be(signature);
    if value >= key.n {
        return Ok(false);
    }

    let recovered = key.raw(&value)?.to_bytes_be_padded(size)?;
    let expected = emsa_pkcs1v15(hash_name, digest, size)?;

    // Fixed-time comparison. The values are public, so this is belt and
    // braces rather than load bearing - but a verifier that returns early is
    // a habit worth not having.
    let mut difference = 0u8;
    for (a, b) in recovered.iter().zip(expected.iter()) {
        difference |= a ^ b;
    }
    Ok(difference == 0)
}

/// Hash a message and sign it, for callers that have the message rather than
/// a digest.
pub fn sign_message<H: HashFunction>(key: &RsaPrivateKey, mut hash: H, message: &[u8])
                                     -> Result<Vec<u8>, String> {
    hash.update(message);
    let name = hash.name().to_lowercase();
    let digest = hash.digest();
    sign_pkcs1v15(key, &name, &digest)
}

// ------------------------------------------------------------ PKCS#1 PSS ---

/*
PSS (RFC 8017 section 8.1 and 9.1), which TLS 1.3 requires for every RSA
certificate - `rsa_pss_rsae_sha256` and its siblings are the only RSA
signature schemes TLS 1.3 allows, so a client without this cannot talk to
an RSA server at all.

PSS differs from PKCS#1 v1.5 in a way that changes how verification has to
be written. v1.5 is deterministic: build the block you expect and compare
bytes. PSS is randomised - the signature contains a salt the verifier does
not know in advance - so it cannot be re-derived. The block has to be
*decoded*, and decoding a structure an attacker controls is exactly where
signature forgeries have come from (see `verify_pkcs1v15`'s note).

So every check below is written to fail closed and to run to the end:
there is one boolean, ANDed at each step, and no early return between the
first parse and the final comparison. A verifier that returns as soon as
something looks wrong tells an attacker which step failed.
*/

/// MGF1 (RFC 8017 appendix B.2.1): a hash-based mask generator.
///
/// `hash(seed || counter)` concatenated, with the counter a four byte big
/// endian integer from zero. The counter's width matters: a one byte
/// counter would look identical for the first 255 blocks and diverge
/// afterwards, which is a bug that appears only for very large masks.
///
/// `pub(crate)` because FIPS 205 uses the same function: SLH-DSA's
/// `H_msg` is MGF1 over SHA-256 or SHA-512 in the SHA-2 parameter sets.
/// It is the same construction and not merely a similar one, so
/// `src/pq/slh_dsa.rs` calls this rather than carrying a second copy.
pub(crate) fn mgf1(hash_name: &str, seed: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(length + 64);
    let mut counter: u32 = 0;
    while out.len() < length {
        let mut hash = AnyHash::new(hash_name)?;
        hash.update(seed);
        hash.update(&counter.to_be_bytes());
        out.extend_from_slice(&hash.digest());
        counter = counter.checked_add(1).ok_or_else(|| {
            "MGF1 counter overflowed, which needs a mask of 2^32 blocks.".to_string()
        })?;
    }
    out.truncate(length);
    Ok(out)
}

/// The default salt length for a hash: its own output length, which is
/// what TLS 1.3 requires (RFC 8446 section 4.2.3) and what every library's
/// "PSS with the obvious parameters" means.
pub fn pss_salt_len(hash_name: &str) -> Result<usize, String> {
    Ok(AnyHash::new(hash_name)?.digest_len())
}

/// EMSA-PSS-ENCODE (RFC 8017 section 9.1.1), for signing.
///
/// `em_bits` is the modulus size in bits **minus one**, which is the
/// detail that makes the leading byte's masking necessary: the encoded
/// message must be numerically smaller than the modulus, so the top
/// `8*em_len - em_bits` bits are cleared.
fn emsa_pss_encode(hash_name: &str, digest: &[u8], salt: &[u8], em_bits: usize)
                   -> Result<Vec<u8>, String> {
    let hash_len = AnyHash::new(hash_name)?.digest_len();
    if digest.len() != hash_len {
        return Err(format!("PSS with {} needs a {} byte digest, got {}.",
                           hash_name, hash_len, digest.len()));
    }
    let em_len = em_bits.div_ceil(8);
    if em_len < hash_len + salt.len() + 2 {
        return Err(format!(
            "The key is too small for PSS with {} and a {} byte salt: {} bytes \
             of encoded message cannot hold {} + {} + 2.",
            hash_name, salt.len(), em_len, hash_len, salt.len()));
    }

    // M' = eight zero bytes || digest || salt. The eight zeros are not
    // padding: they stop a PSS signature from ever colliding with a
    // signature over a raw hash in some other scheme.
    let mut m_prime = Vec::with_capacity(8 + hash_len + salt.len());
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(salt);
    let mut hash = AnyHash::new(hash_name)?;
    hash.update(&m_prime);
    let h = hash.digest();

    // DB = PS || 0x01 || salt, masked with MGF1(H).
    let db_len = em_len - hash_len - 1;
    let mut db = vec![0u8; db_len];
    db[db_len - salt.len() - 1] = 0x01;
    db[db_len - salt.len()..].copy_from_slice(salt);

    let mask = mgf1(hash_name, &h, db_len)?;
    for (byte, m) in db.iter_mut().zip(&mask) {
        *byte ^= m;
    }
    // Clear the bits above em_bits, so EM < n.
    let spare = 8 * em_len - em_bits;
    if spare > 0 {
        db[0] &= 0xffu8 >> spare;
    }

    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    Ok(em)
}

/// Sign an already computed digest with PSS and a random salt.
pub fn sign_pss(key: &RsaPrivateKey, hash_name: &str, digest: &[u8],
                salt_len: usize) -> Result<Vec<u8>, String> {
    let size = key.size();
    let em_bits = key.public_key().n.bit_len() - 1;
    let salt = random::bytes(salt_len)?;
    let em = emsa_pss_encode(hash_name, digest, &salt, em_bits)?;
    let signature = key.raw(&BigUint::from_bytes_be(&em))?;
    signature.to_bytes_be_padded(size)
}

/// Verify a PSS signature (RFC 8017 section 9.1.2).
///
/// Unlike v1.5 this cannot be a byte comparison against a block we build:
/// the salt is chosen by the signer and arrives inside the signature, so
/// the encoded message has to be taken apart. Every step therefore folds
/// its result into one boolean rather than returning, so that a failure
/// says only "no".
///
/// `salt_len` is what the verifier requires. RFC 8017 allows a verifier to
/// recover the length from the block instead, and this one does not: TLS
/// 1.3 fixes the salt at the hash length (RFC 8446 section 4.2.3), and a
/// verifier that accepts any length accepts a salt of zero, which makes
/// PSS deterministic and throws away the property it exists for.
pub fn verify_pss(key: &RsaPublicKey, hash_name: &str, digest: &[u8],
                  signature: &[u8], salt_len: usize) -> Result<bool, String> {
    let size = key.size();
    if signature.len() != size {
        return Err(format!("Signature must be {} bytes, got {}.",
                           size, signature.len()));
    }
    let hash_len = AnyHash::new(hash_name)?.digest_len();
    if digest.len() != hash_len {
        return Err(format!("PSS with {} needs a {} byte digest, got {}.",
                           hash_name, hash_len, digest.len()));
    }

    let value = BigUint::from_bytes_be(signature);
    if value >= key.n {
        return Ok(false);
    }

    let em_bits = key.n.bit_len() - 1;
    let em_len = em_bits.div_ceil(8);
    if em_len < hash_len + salt_len + 2 {
        // The key cannot hold a signature of this shape at all.
        return Ok(false);
    }

    let recovered = key.raw(&value)?.to_bytes_be_padded(size)?;
    // For a modulus whose bit length is a multiple of eight, em_len is one
    // less than the key size and the leading byte must be zero.
    let em = &recovered[size - em_len..];
    let mut good = recovered[..size - em_len].iter().all(|b| *b == 0) as u8;

    good &= (em[em_len - 1] == 0xbc) as u8;

    let db_len = em_len - hash_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + hash_len];

    // The bits above em_bits must already be zero in what arrived.
    let spare = 8 * em_len - em_bits;
    if spare > 0 {
        good &= ((masked_db[0] >> (8 - spare)) == 0) as u8;
    }

    let mask = mgf1(hash_name, h, db_len)?;
    let mut db: Vec<u8> = masked_db.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
    if spare > 0 {
        db[0] &= 0xffu8 >> spare;
    }

    // DB must be zeros, then a single 0x01, then the salt.
    let zeros = db_len - salt_len - 1;
    for byte in &db[..zeros] {
        good &= (*byte == 0) as u8;
    }
    good &= (db[zeros] == 0x01) as u8;
    let salt = &db[zeros + 1..];

    let mut m_prime = Vec::with_capacity(8 + hash_len + salt_len);
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(salt);
    let mut hash = AnyHash::new(hash_name)?;
    hash.update(&m_prime);
    let expected = hash.digest();

    let mut difference = 0u8;
    for (a, b) in h.iter().zip(expected.iter()) {
        difference |= a ^ b;
    }
    good &= (difference == 0) as u8;

    Ok(good == 1)
}

#[cfg(test)]
mod tests {

    // --------------------------------------------------------------- PSS ---

    /// PSS round trips, at every hash and every key size.
    ///
    /// A round trip is the weakest possible PSS test - the signature is
    /// randomised, so it is also the only self-contained one - which is
    /// why the real check is against OpenSSL in pytests/test_rsa.py. What
    /// this adds is the shapes: the encoded message is one byte shorter
    /// than the key when the modulus is a multiple of eight bits, and the
    /// salt has to fit alongside the hash.
    #[test]
    fn test_pss_round_trips() {
        for bits in [1024usize, 2048] {
            let key = RsaPrivateKey::generate(bits).unwrap();
            let public = key.public_key();
            for hash_name in ["sha256", "sha384", "sha512"] {
                let mut hash = AnyHash::new(hash_name).unwrap();
                hash.update(b"a message to sign");
                let digest = hash.digest();
                let salt_len = pss_salt_len(hash_name).unwrap();

                // A 1024 bit key cannot do SHA-512 with a 64 byte salt:
                // 64 + 64 + 2 is 130 bytes of encoded message and the key
                // holds 128. That is refused rather than squeezed, and
                // checking it here is worth more than skipping quietly.
                if bits / 8 < digest.len() + salt_len + 2 {
                    assert!(sign_pss(&key, hash_name, &digest, salt_len).is_err(),
                            "{} at {} bits should not fit", hash_name, bits);
                    continue;
                }

                let signature = sign_pss(&key, hash_name, &digest, salt_len).unwrap();
                assert_eq!(signature.len(), public.size());
                assert!(verify_pss(&public, hash_name, &digest, &signature, salt_len)
                            .unwrap(), "{} at {} bits", hash_name, bits);

                // Randomised: two signatures over the same digest differ,
                // and both verify. A deterministic PSS means the salt is
                // not being used.
                let again = sign_pss(&key, hash_name, &digest, salt_len).unwrap();
                assert_ne!(signature, again, "PSS produced a constant signature");
                assert!(verify_pss(&public, hash_name, &digest, &again, salt_len)
                            .unwrap());
            }
        }
    }

    /// Every single-bit change must be rejected, and rejected as `false`
    /// rather than as an error: a verifier that errors on a malformed
    /// block and returns false on a wrong one has told the attacker which
    /// it was.
    #[test]
    fn test_pss_rejects_every_tampering() {
        let key = RsaPrivateKey::generate(1024).unwrap();
        let public = key.public_key();
        let mut hash = AnyHash::new("sha256").unwrap();
        hash.update(b"the message");
        let digest = hash.digest();
        let signature = sign_pss(&key, "sha256", &digest, 32).unwrap();

        for index in 0..signature.len() {
            for bit in [0x01u8, 0x80] {
                let mut broken = signature.clone();
                broken[index] ^= bit;
                assert!(!verify_pss(&public, "sha256", &digest, &broken, 32)
                            .unwrap_or(false),
                        "a signature with byte {} bit {:#x} flipped verified",
                        index, bit);
            }
        }

        // A different digest, the same signature.
        let mut other = AnyHash::new("sha256").unwrap();
        other.update(b"another message");
        assert!(!verify_pss(&public, "sha256", &other.digest(), &signature, 32)
                    .unwrap());
    }

    /// The salt length is required, not recovered.
    ///
    /// RFC 8017 lets a verifier take the length from the block. This one
    /// does not, because a verifier that accepts any length accepts zero -
    /// which makes PSS deterministic and throws away the randomisation it
    /// exists for. TLS 1.3 fixes the salt at the hash length, so this is
    /// also what interoperates.
    #[test]
    fn test_pss_salt_length_must_match() {
        let key = RsaPrivateKey::generate(1024).unwrap();
        let public = key.public_key();
        let mut hash = AnyHash::new("sha256").unwrap();
        hash.update(b"salted");
        let digest = hash.digest();

        let signature = sign_pss(&key, "sha256", &digest, 32).unwrap();
        assert!(verify_pss(&public, "sha256", &digest, &signature, 32).unwrap());
        for wrong in [0usize, 16, 31, 33, 48] {
            assert!(!verify_pss(&public, "sha256", &digest, &signature, wrong)
                        .unwrap_or(false),
                    "a {} byte salt verified a 32 byte one", wrong);
        }

        assert_eq!(pss_salt_len("sha256").unwrap(), 32);
        assert_eq!(pss_salt_len("sha384").unwrap(), 48);
    }

    /// A key too small for the hash and salt is an error at signing and a
    /// `false` at verification - never a silently truncated block.
    #[test]
    fn test_pss_refuses_a_key_that_cannot_hold_it() {
        let key = RsaPrivateKey::generate(512).unwrap();
        let public = key.public_key();
        let mut hash = AnyHash::new("sha512").unwrap();
        hash.update(b"too big");
        let digest = hash.digest();

        // 64 byte hash + 64 byte salt + 2 needs 130 bytes; a 512 bit key
        // has 64.
        assert!(sign_pss(&key, "sha512", &digest, 64).is_err());
        assert!(!verify_pss(&public, "sha512", &digest, &[0; 64], 64).unwrap());
    }

    /// MGF1's counter is four bytes, which only shows up past 255 blocks.
    #[test]
    fn test_mgf1_counter_is_four_bytes() {
        // A mask longer than 255 hash blocks: with a one byte counter the
        // 256th block would repeat the first.
        let mask = mgf1("sha256", b"seed", 32 * 300).unwrap();
        assert_eq!(mask.len(), 32 * 300);
        assert_ne!(&mask[..32], &mask[32 * 256..32 * 257],
                   "block 256 repeats block 0, so the counter wrapped");

        // And it is a prefix function: a shorter mask is the start of a
        // longer one.
        assert_eq!(mgf1("sha256", b"seed", 100).unwrap(), mask[..100]);
    }

    use super::*;
    use crate::hash_functions::sha2::SHA256;

    /// A 512 bit key, fixed, so the tests do not spend their time generating
    /// primes. Small on purpose: everything under test here is structural.
    fn test_key() -> RsaPrivateKey {
        let p = BigUint::from_hex(
            "e7a0f5f1d0e8b8b7b5c6f9c1d3e2a4b6c8d0e2f4a6b8cad3e5f7a9b1c3d5e7f9").unwrap();
        let q = BigUint::from_hex(
            "f3d1c5b9a7958371f5d3b1978d6b493f2d1b0997857361f3d1bf9d7b5931f70d").unwrap();
        // These two are not prime; find real ones nearby.
        let p = next_prime(&p);
        let q = next_prime(&q);
        RsaPrivateKey::from_primes(p, q, BigUint::from_u64(65537)).unwrap()
    }

    fn next_prime(from: &BigUint) -> BigUint {
        let two = BigUint::from_u64(2);
        let mut candidate = if from.is_even() { from.add(&BigUint::one()) } else { from.clone() };
        loop {
            if is_probably_prime(&candidate, 40).unwrap() {
                return candidate;
            }
            candidate = candidate.add(&two);
        }
    }

    #[test]
    fn test_primality_agrees_with_known_values() {
        for prime in [2u64, 3, 5, 7, 97, 65537, 2147483647] {
            assert!(is_probably_prime(&BigUint::from_u64(prime), 40).unwrap(),
                    "{} is prime", prime);
        }
        for composite in [0u64, 1, 4, 9, 91, 65536, 2147483649, 1_000_000_000] {
            assert!(!is_probably_prime(&BigUint::from_u64(composite), 40).unwrap(),
                    "{} is composite", composite);
        }

        // Carmichael numbers pass a Fermat test but not Miller-Rabin; 561 is
        // the smallest and the classic way to catch a Fermat test wearing a
        // Miller-Rabin label.
        for carmichael in [561u64, 1105, 1729, 2465, 2821, 6601, 8911] {
            assert!(!is_probably_prime(&BigUint::from_u64(carmichael), 40).unwrap(),
                    "{} is a Carmichael number, not a prime", carmichael);
        }

        // A large prime and the composite next to it.
        let prime = BigUint::from_hex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43").unwrap();
        assert!(is_probably_prime(&prime, 40).unwrap());
        assert!(!is_probably_prime(&prime.add(&BigUint::from_u64(2)), 40).unwrap());
    }

    #[test]
    fn test_raw_round_trip() {
        let key = test_key();
        for value in ["1", "2", "deadbeef", "c0ffee0123456789abcdef"] {
            let m = BigUint::from_hex(value).unwrap();
            let c = key.public.raw(&m).unwrap();
            assert_eq!(key.raw(&c).unwrap(), m, "round trip {}", value);
            // And the other direction, which is what signing does.
            assert_eq!(key.public.raw(&key.raw(&m).unwrap()).unwrap(), m);
        }
    }

    /// Blinding must not change the answer, only the timing. Running the
    /// same private operation repeatedly must give the same result every
    /// time even though the blinding factor is fresh each call.
    #[test]
    fn test_blinding_does_not_change_the_result() {
        let key = test_key();
        let c = key.public.raw(&BigUint::from_hex("abcdef").unwrap()).unwrap();
        let first = key.raw(&c).unwrap();
        for _ in 0..8 {
            assert_eq!(key.raw(&c).unwrap(), first);
        }
    }

    #[test]
    fn test_values_at_or_above_the_modulus_are_refused() {
        let key = test_key();
        assert!(key.public.raw(&key.public.n).is_err());
        assert!(key.raw(&key.public.n).is_err());
        assert!(key.public.raw(&key.public.n.add(&BigUint::one())).is_err());
    }

    #[test]
    fn test_pkcs1v15_encryption_round_trip() {
        let key = test_key();
        let size = key.size();
        for len in [0usize, 1, 16, 32] {
            let message: Vec<u8> = (0..len).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
            let ciphertext = encrypt_pkcs1v15(&key.public, &message).unwrap();
            assert_eq!(ciphertext.len(), size);
            assert_eq!(decrypt_pkcs1v15(&key, &ciphertext).unwrap(), message);
        }

        // The padding is random, so two encryptions of the same message must
        // differ. A deterministic result here means the randomness is not
        // reaching the padding.
        let a = encrypt_pkcs1v15(&key.public, b"same").unwrap();
        let b = encrypt_pkcs1v15(&key.public, b"same").unwrap();
        assert_ne!(a, b, "PKCS#1 v1.5 encryption must be randomised");
        assert_eq!(decrypt_pkcs1v15(&key, &a).unwrap(),
                   decrypt_pkcs1v15(&key, &b).unwrap());
    }

    #[test]
    fn test_a_message_containing_zero_bytes_survives() {
        // **The separator is the *first* zero after the padding, and a
        // message may contain zeros of its own.** A search that took the
        // last zero in the block would truncate any message with an
        // interior zero, and every other test here uses messages with
        // none - so replacing the first-zero search with a last-zero one
        // passed the whole suite. Found by a breakage sweep on the
        // ElGamal module, which has the same code and had the same gap.
        let key = test_key();
        for message in [vec![0u8],
                        vec![0u8, 0, 0],
                        b"a\0b\0c".to_vec(),
                        vec![0u8, 1, 2, 3],           // leading zero
                        vec![1u8, 2, 3, 0],           // trailing zero
                        // As long as the test key allows - zeros spread
                        // through a message that fills the block.
                        (0..(key.size() - 11) as u8).collect::<Vec<u8>>()] {
            let sealed = encrypt_pkcs1v15(&key.public, &message).unwrap();
            assert_eq!(decrypt_pkcs1v15(&key, &sealed).unwrap(), message,
                       "message {message:?}");
        }
    }

    #[test]
    fn test_encryption_rejects_oversized_messages() {
        let key = test_key();
        let limit = key.size() - 11;
        assert!(encrypt_pkcs1v15(&key.public, &vec![0u8; limit]).is_ok());
        assert!(encrypt_pkcs1v15(&key.public, &vec![0u8; limit + 1]).is_err());
    }

    /// Every way a ciphertext can be wrong must give the same error, with no
    /// detail about which check failed.
    #[test]
    fn test_decryption_failures_are_indistinguishable() {
        let key = test_key();
        let good = encrypt_pkcs1v15(&key.public, b"secret").unwrap();

        let mut messages = std::collections::HashSet::new();
        for bad in [
            vec![0u8; key.size()],                       // decrypts to zero
            vec![0xff; key.size()],                      // above the modulus
            good[..good.len() - 1].to_vec(),             // too short
            {   let mut c = good.clone(); c[5] ^= 0xff; c },  // corrupt
            {   let mut c = good.clone(); c[0] ^= 0x01; c },
        ] {
            let error = decrypt_pkcs1v15(&key, &bad).unwrap_err();
            messages.insert(error);
        }
        assert_eq!(messages.len(), 1,
                   "decryption errors must not distinguish failures: {:?}", messages);
    }

    // -------------------------------------------------------------- OAEP ---

    /// OAEP round trips at every length the 512-bit test key takes, under
    /// SHA-1 and SHA-224, MGF1 under its own hash and the other one, with
    /// and without a label - and the messages start with zeros and with
    /// 0x01, which is the separator's value: the decoder must take the
    /// *first* nonzero byte after the label hash and no other.
    #[test]
    fn test_oaep_round_trips() {
        let key = test_key();
        for (hash, mgf) in [("sha1", "sha1"), ("sha224", "sha224"), ("sha1", "sha224"),
                            ("sha224", "sha1")] {
            let hash_len = AnyHash::new(hash).unwrap().digest_len();
            let limit = key.size() - 2 * hash_len - 2;
            for len in 0..=limit {
                for first in [0u8, 1, 0xff] {
                    let mut message: Vec<u8> = (0..len).map(|i| (i * 37 + 1) as u8).collect();
                    if let Some(byte) = message.first_mut() {
                        *byte = first;
                    }
                    for label in [&b""[..], b"label"] {
                        let sealed = encrypt_oaep(&key.public, hash, mgf, label, &message)
                            .unwrap();
                        assert_eq!(sealed.len(), key.size());
                        assert_eq!(decrypt_oaep(&key, hash, mgf, label, &sealed).unwrap(),
                                   message, "{hash}/{mgf} {len} {first} {label:?}");
                    }
                }
            }
            assert!(encrypt_oaep(&key.public, hash, mgf, b"", &vec![0; limit + 1]).is_err());
        }
    }

    /// The seed is the randomness: fresh each time, and the only thing
    /// that varies - a given seed gives a given ciphertext.
    #[test]
    fn test_oaep_is_randomised_by_its_seed_alone() {
        let key = test_key();
        let a = encrypt_oaep(&key.public, "sha1", "sha1", b"", b"same").unwrap();
        let b = encrypt_oaep(&key.public, "sha1", "sha1", b"", b"same").unwrap();
        assert_ne!(a, b);
        let seed = [7u8; 20];
        assert_eq!(encrypt_oaep_with_seed(&key.public, "sha1", "sha1", b"", b"same", &seed),
                   encrypt_oaep_with_seed(&key.public, "sha1", "sha1", b"", b"same", &seed));
        assert!(encrypt_oaep_with_seed(&key.public, "sha1", "sha1", b"", b"x", &[7; 19])
            .is_err());
    }

    /// A key smaller than two hashes and two bytes cannot carry OAEP at
    /// all, and says so - in both directions, before touching the input.
    #[test]
    fn test_oaep_refuses_a_key_too_small_for_its_hash() {
        let key = test_key();
        assert_eq!(key.size(), 64);
        assert!(encrypt_oaep(&key.public, "sha256", "sha256", b"", b"").unwrap_err()
            .contains("too long"));
        assert!(decrypt_oaep(&key, "sha256", "sha256", b"", &[0; 64]).unwrap_err()
            .contains("too small"));
    }

    /// Every way the padding can be wrong gives one error: Manger's attack
    /// needs only to learn whether the leading byte was zero. Each block
    /// here is built by encoding a good one by hand and then breaking one
    /// thing, so each check is the only one refusing it.
    #[test]
    fn test_oaep_decoding_failures_are_indistinguishable() {
        let (hash, hash_len, k) = ("sha1", 20, 64);
        let label_hash = AnyHash::new(hash).unwrap().digest();
        let encode = |y: u8, l_hash: &[u8], ps_and_after: &[u8]| {
            let seed = [3u8; 20];
            let mut db = l_hash.to_vec();
            db.extend_from_slice(ps_and_after);
            assert_eq!(db.len(), k - hash_len - 1);
            let db_mask = mgf1(hash, &seed, db.len()).unwrap();
            let masked_db: Vec<u8> = db.iter().zip(&db_mask).map(|(a, b)| a ^ b).collect();
            let seed_mask = mgf1(hash, &masked_db, hash_len).unwrap();
            let mut em = vec![y];
            em.extend(seed.iter().zip(&seed_mask).map(|(a, b)| a ^ b));
            em.extend(masked_db);
            em
        };
        let body = |separator: u8| {
            let mut tail = vec![0u8; 5];
            tail.push(separator);
            tail.extend_from_slice(b"message");
            tail.resize(k - hash_len - 1 - hash_len, 0x55);
            tail
        };
        let good = encode(0, &label_hash, &body(1));
        assert_eq!(&eme_oaep_decode(&good, hash, hash, b"").unwrap()[..7], b"message");
        let mut wrong_hash = label_hash.clone();
        wrong_hash[19] ^= 1;
        let mut errors = std::collections::HashSet::new();
        for (what, em) in [("leading byte", encode(1, &label_hash, &body(1))),
                           ("label hash", encode(0, &wrong_hash, &body(1))),
                           ("separator", encode(0, &label_hash, &body(2))),
                           ("no separator", encode(0, &label_hash, &[0; 64 - 41]))] {
            errors.insert(eme_oaep_decode(&em, hash, hash, b"").expect_err(what));
        }
        errors.insert(eme_oaep_decode(&good, hash, hash, b"another label").unwrap_err());
        assert_eq!(errors.len(), 1, "{errors:?}");
    }

    #[test]
    fn test_signature_round_trip() {
        let key = test_key();
        let mut hash = SHA256::new(b"a message to sign");
        let digest = hash.digest();

        let signature = sign_pkcs1v15(&key, "sha256", &digest).unwrap();
        assert_eq!(signature.len(), key.size());
        assert!(verify_pkcs1v15(&key.public, "sha256", &digest, &signature).unwrap());

        // PKCS#1 v1.5 signatures are deterministic - no randomness anywhere
        // in the padding - so this must be byte identical.
        assert_eq!(sign_pkcs1v15(&key, "sha256", &digest).unwrap(), signature);

        // And through the message helper.
        assert_eq!(sign_message(&key, SHA256::new(&[]), b"a message to sign").unwrap(),
                   signature);
    }

    #[test]
    fn test_verification_rejects_tampering() {
        let key = test_key();
        let digest = SHA256::new(b"authentic").digest();
        let signature = sign_pkcs1v15(&key, "sha256", &digest).unwrap();

        // Wrong message.
        let other = SHA256::new(b"forged").digest();
        assert!(!verify_pkcs1v15(&key.public, "sha256", &other, &signature).unwrap());

        // Wrong hash name, which means a different DigestInfo prefix.
        assert!(!verify_pkcs1v15(&key.public, "sha512", &SHA256::new(b"authentic").digest(),
                                 &signature).unwrap_or(false));

        // Any flipped bit.
        for index in [0usize, 1, 17, 40] {
            let mut tampered = signature.clone();
            tampered[index] ^= 0x01;
            assert!(!verify_pkcs1v15(&key.public, "sha256", &digest, &tampered).unwrap(),
                    "byte {} flip accepted", index);
        }

        // Wrong length is an error, not a verdict.
        assert!(verify_pkcs1v15(&key.public, "sha256", &digest,
                                &signature[..signature.len() - 1]).is_err());

        // A signature from a different key.
        let mut other_key = test_key();
        other_key = RsaPrivateKey::from_primes(
            next_prime(&other_key.p.add(&BigUint::from_u64(1000))),
            other_key.q.clone(), BigUint::from_u64(65537)).unwrap();
        let elsewhere = sign_pkcs1v15(&other_key, "sha256", &digest).unwrap();
        assert!(!verify_pkcs1v15(&key.public, "sha256", &digest, &elsewhere)
                    .unwrap_or(false));
    }

    #[test]
    fn test_unknown_hash_is_refused() {
        let key = test_key();
        assert!(sign_pkcs1v15(&key, "md6", &[0u8; 32]).is_err());
        assert!(digest_info_prefix("sha3_256").is_err());
    }

    #[test]
    fn test_key_construction_validates() {
        let e = BigUint::from_u64(65537);
        let p = next_prime(&BigUint::from_hex("e7a0f5f1d0e8b8b7b5c6f9c1d3e2a4b7").unwrap());

        // Equal primes.
        assert!(RsaPrivateKey::from_primes(p.clone(), p.clone(), e.clone()).is_err());
        // A composite where a prime should be: caught by the round trip check.
        let composite = BigUint::from_u64(1_000_003 * 1_000_033);
        assert!(RsaPrivateKey::from_primes(p.clone(), composite, e.clone()).is_err());
        // An even "prime".
        assert!(RsaPrivateKey::from_primes(
            p.clone(), BigUint::from_u64(4), e.clone()).is_err());

        // Degenerate public keys.
        assert!(RsaPublicKey::new(BigUint::from_u64(15), BigUint::one()).is_err());
        assert!(RsaPublicKey::new(BigUint::from_u64(15), BigUint::from_u64(4)).is_err());
        assert!(RsaPublicKey::new(BigUint::from_u64(16), BigUint::from_u64(3)).is_err());
    }

    /// Generation is slow, so this runs at the smallest allowed size. The
    /// 2048 bit path is exercised by tools/src/bin/bench_rsa.rs.
    #[test]
    fn test_generate_512() {
        let key = RsaPrivateKey::generate(512).unwrap();
        assert_eq!(key.bits(), 512);
        assert_eq!(key.size(), 64);

        let (p, q) = key.primes();
        assert_ne!(p, q);
        assert!(is_probably_prime(p, 40).unwrap());
        assert!(is_probably_prime(q, 40).unwrap());
        assert_eq!(p.mul(q), key.public.n);

        let message = b"generated key";
        let ciphertext = encrypt_pkcs1v15(&key.public, message).unwrap();
        assert_eq!(decrypt_pkcs1v15(&key, &ciphertext).unwrap(), message);

        assert!(RsaPrivateKey::generate(511).is_err());
        assert!(RsaPrivateKey::generate(256).is_err());
    }
}
