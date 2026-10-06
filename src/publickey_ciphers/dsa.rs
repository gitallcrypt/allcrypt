/*
DSA, the Digital Signature Algorithm of FIPS 186-2 to 186-4.

FIPS 186-5 (2023) withdrew it for new signatures, and OpenSSH removed
`ssh-dss` entirely in 2024. It is here because a switch, a UPS card or a
storage controller from the 2000s often has a DSA host key and nothing
else, and certificates and TLS servers with DSA keys exist in the same
places. Verifying is what most callers need; signing is here too, with
deterministic nonces.

A key is a group `(p, q, g)` - `q` a prime dividing `p - 1`, `g` of order
`q` - and `y = g^x mod p`. A signature on a digest `z` is

    r = (g^k mod p) mod q
    s = k^-1 (z + x r) mod q

for a per-signature secret `k`.

# Pitfalls

**`k` is the private key, one signature removed.** Anyone who knows `k`
for one signature computes `x = (s k - z) / r mod q`; two signatures with
the same `k` give it away by subtraction (the PS3, 2010; Android's
SecureRandom, 2013). So `k` is derived, as RFC 6979 specifies, from the
private key and the digest with HMAC-DRBG - the same generator ECDSA
uses here - and never drawn from a random source that could repeat.

**The digest is truncated to `q`'s length, by bits, from the left.** A
SHA-256 digest with a 160 bit `q` keeps its first 160 bits. Reducing mod
`q` instead gives a different `z` and signatures nobody else verifies.

**The group is not to be taken on trust.** A `g` of the wrong order, a
`q` that does not divide `p - 1`, or a `y` outside the subgroup make
every check meaningless. `DsaParameters::new` checks the structure
(`q | p - 1`, `1 < g < p`, `g^q = 1`), `DsaPublicKey::new` checks
`1 < y < p` and `y^q = 1`; primality, which costs real time, is
`check_primes`, for callers that did not get the group from somewhere
they trust.

**`r` and `s` must be in `[1, q - 1]`.** Verifying without the range
check accepts `r = 0` forgeries in some formulations.

**SSH's `ssh-dss` fixes `q` at 160 bits and SHA-1**, and sends `r || s`
as exactly 40 bytes (RFC 4253 6.6) - not DER, and not the minimal
encodings of either.
*/

use crate::bignum::BigUint;
use crate::ec::ecdsa::NonceGenerator;
use crate::hash_functions::HashFunction;
use crate::publickey_ciphers::rsa::is_probably_prime;

/// A DSA group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaParameters {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
}

impl DsaParameters {
    /// A group, checked for structure: `q` divides `p - 1`, `g` is
    /// strictly between 1 and `p`, and `g` has order `q`. Primality is
    /// left to `check_primes`.
    pub fn new(p: BigUint, q: BigUint, g: BigUint) -> Result<DsaParameters, String> {
        let one = BigUint::one();
        if p.bit_len() < 512 || q.bit_len() < 160 || q.bit_len() >= p.bit_len() {
            return Err(format!("DSA: a {} bit p with a {} bit q is not a DSA group.",
                               p.bit_len(), q.bit_len()));
        }
        if !p.sub(&one)?.rem(&q)?.is_zero() {
            return Err("DSA: q does not divide p - 1.".to_string());
        }
        if g <= one || g >= p {
            return Err("DSA: g must be between 1 and p.".to_string());
        }
        if !g.mod_pow(&q, &p)?.is_one() {
            return Err("DSA: g does not have order q.".to_string());
        }
        Ok(DsaParameters { p, q, g })
    }

    /// Miller-Rabin on `p` and `q`.
    pub fn check_primes(&self, rounds: usize) -> Result<(), String> {
        if !is_probably_prime(&self.q, rounds)? {
            return Err("DSA: q is not prime.".to_string());
        }
        if !is_probably_prime(&self.p, rounds)? {
            return Err("DSA: p is not prime.".to_string());
        }
        Ok(())
    }

    /// A fresh group with an `l` bit `p` and an `n` bit `q`: a random
    /// prime `q`, then `p = k q + 1` for random `k` until prime, then
    /// `g = h^((p-1)/q)`. FIPS 186-4's sizes are (1024, 160), (2048, 224),
    /// (2048, 256) and (3072, 256); `ssh-dss` wants (1024, 160).
    pub fn generate(l: usize, n: usize) -> Result<DsaParameters, String> {
        if n < 160 || l < n + 64 {
            return Err(format!("DSA: ({l}, {n}) are not sizes to generate."));
        }
        let q = random_prime(n)?;
        let one = BigUint::one();
        let two_q = q.add(&q);
        for _ in 0..100_000 {
            // A random l bit number, rounded down to 1 mod 2q.
            let mut candidate = random_bits(l)?;
            let excess = candidate.rem(&two_q)?;
            candidate = candidate.sub(&excess)?.add(&one);
            if candidate.bit_len() != l {
                continue;
            }
            if is_probably_prime(&candidate, 40)? {
                let exponent = candidate.sub(&one)?.div(&q)?;
                let mut h = BigUint::from_u64(2);
                loop {
                    let g = h.mod_pow(&exponent, &candidate)?;
                    if !g.is_one() {
                        return DsaParameters::new(candidate, q, g);
                    }
                    h = h.add(&one);
                }
            }
        }
        Err("DSA: no prime p found; try again.".to_string())
    }
}

fn random_bits(bits: usize) -> Result<BigUint, String> {
    let mut bytes = vec![0u8; bits.div_ceil(8)];
    crate::random::fill(&mut bytes)?;
    let excess = bytes.len() * 8 - bits;
    bytes[0] &= 0xff >> excess;
    bytes[0] |= 0x80 >> excess;
    Ok(BigUint::from_bytes_be(&bytes))
}

fn random_prime(bits: usize) -> Result<BigUint, String> {
    loop {
        let candidate = random_bits(bits)?;
        let candidate = if candidate.is_even() { candidate.add(&BigUint::one()) } else { candidate };
        if candidate.bit_len() == bits && is_probably_prime(&candidate, 40)? {
            return Ok(candidate);
        }
    }
}

/// The leftmost min(N, outlen) bits of a digest, as an integer.
fn digest_to_int(digest: &[u8], q: &BigUint) -> BigUint {
    let n = q.bit_len();
    let z = BigUint::from_bytes_be(digest);
    let digest_bits = digest.len() * 8;
    if digest_bits > n { z.shr(digest_bits - n) } else { z }
}

/// The verifying half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaPublicKey {
    pub parameters: DsaParameters,
    pub y: BigUint,
}

impl DsaPublicKey {
    pub fn new(parameters: DsaParameters, y: BigUint) -> Result<DsaPublicKey, String> {
        if y <= BigUint::one() || y >= parameters.p {
            return Err("DSA: the public key must be between 1 and p.".to_string());
        }
        if !y.mod_pow(&parameters.q, &parameters.p)?.is_one() {
            return Err("DSA: the public key is not in the subgroup of order q.".to_string());
        }
        Ok(DsaPublicKey { parameters, y })
    }

    /// Whether `(r, s)` signs `digest`. `false` for anything out of range.
    pub fn verify(&self, digest: &[u8], r: &BigUint, s: &BigUint) -> Result<bool, String> {
        let DsaParameters { p, q, g } = &self.parameters;
        if r.is_zero() || s.is_zero() || r >= q || s >= q {
            return Ok(false);
        }
        let w = s.mod_inverse(q)?;
        let z = digest_to_int(digest, q).rem(q)?;
        let u1 = z.mod_mul(&w, q)?;
        let u2 = r.mod_mul(&w, q)?;
        let v = g.mod_pow(&u1, p)?.mod_mul(&self.y.mod_pow(&u2, p)?, p)?.rem(q)?;
        Ok(&v == r)
    }
}

/// A signing key.
#[derive(Clone)]
pub struct DsaPrivateKey {
    pub public: DsaPublicKey,
    x: BigUint,
}

impl DsaPrivateKey {
    /// A key from its private value, `1 <= x < q`.
    pub fn from_x(parameters: DsaParameters, x: BigUint) -> Result<DsaPrivateKey, String> {
        if x.is_zero() || x >= parameters.q {
            return Err("DSA: the private key must be between 1 and q - 1.".to_string());
        }
        let y = parameters.g.mod_pow_ct(&x, &parameters.p)?;
        Ok(DsaPrivateKey { public: DsaPublicKey { parameters, y }, x })
    }

    /// A fresh key in `parameters`.
    pub fn generate(parameters: DsaParameters) -> Result<DsaPrivateKey, String> {
        let limit = parameters.q.sub(&BigUint::one())?;
        let x = crate::random::below(&limit)?.add(&BigUint::one());
        DsaPrivateKey::from_x(parameters, x)
    }

    pub fn x(&self) -> &BigUint {
        &self.x
    }

    /// Sign a digest, with RFC 6979's deterministic `k`. `hash` is a
    /// fresh instance of the hash that made `digest`.
    pub fn sign<H: HashFunction + Clone>(&self, digest: &[u8], hash: H)
                                         -> Result<(BigUint, BigUint), String> {
        let DsaParameters { p, q, g } = &self.public.parameters;
        let z = digest_to_int(digest, q).rem(q)?;
        let mut nonces = NonceGenerator::new(hash, &self.x, digest, q)?;
        loop {
            let k = nonces.next();
            if k.is_zero() || &k >= q {
                continue;
            }
            let r = g.mod_pow_ct(&k, p)?.rem(q)?;
            if r.is_zero() {
                continue;
            }
            let k_inverse = k.mod_inverse_prime(q)?;
            let s = k_inverse.mod_mul(&z.mod_add(&self.x.mod_mul(&r, q)?, q)?, q)?;
            if s.is_zero() {
                continue;
            }
            return Ok((r, s));
        }
    }
}

/// RFC 6979 appendix A.2's vectors, read out of the vendored RFC - for
/// DSA here, and for ECDSA by `ec::ecdsa`'s tests.
#[cfg(test)]
pub(crate) mod rfc6979 {
    use crate::bignum::BigUint;

    const RFC: &str = include_str!("../../rfcs/rfc6979.txt");

    /// One signature: hash name as this library spells it, the message,
    /// and k, r, s.
    pub(crate) struct Signature {
        pub hash: String,
        pub message: String,
        pub k: BigUint,
        pub r: BigUint,
        pub s: BigUint,
    }

    /// The key fields (p, q, g, x, y, Ux, Uy, as the section has them)
    /// and the signatures of the section headed `heading`.
    pub(crate) fn section(heading: &str) -> (Vec<(String, BigUint)>, Vec<Signature>) {
        // As a line of its own: the table of contents has the same words.
        let line = format!("\n{heading}\n");
        let start = RFC.find(&line).unwrap_or_else(|| panic!("{heading}"));
        let rest = &RFC[start + line.len()..];
        let end = rest.find("\nA.").unwrap_or(rest.len());
        let mut fields: Vec<(String, String)> = Vec::new();
        let mut signatures = Vec::new();
        let mut current: Option<(String, String)> = None;
        let mut pending: Vec<(String, String)> = Vec::new();
        let finish_signature = |pending: &mut Vec<(String, String)>,
                                signatures: &mut Vec<Signature>,
                                header: &Option<(String, String)>| {
            if let (Some((hash, message)), 3) = (header, pending.len()) {
                let get = |n: &str| BigUint::from_hex(
                    &pending.iter().find(|(k, _)| k == n).unwrap().1).unwrap();
                signatures.push(Signature { hash: hash.clone(), message: message.clone(),
                                            k: get("k"), r: get("r"), s: get("s") });
            }
            pending.clear();
        };
        let mut header: Option<(String, String)> = None;
        for line in rest[..end].lines() {
            let trimmed = line.trim();
            if let Some(spec) = trimmed.strip_prefix("With SHA-") {
                if let Some(done) = current.take() { pending.push(done); }
                finish_signature(&mut pending, &mut signatures, &header);
                // `256, message = "sample":`
                let (bits, rest) = spec.split_once(',').unwrap();
                let message = rest.split('"').nth(1).unwrap();
                header = Some((format!("sha{bits}"), message.to_string()));
                continue;
            }
            let is_hex = !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_hexdigit());
            if is_hex && line.starts_with("     ") {
                if let Some((_, value)) = current.as_mut() {
                    value.push_str(trimmed);
                }
                continue;
            }
            if let Some((name, value)) = trimmed.split_once(" = ") {
                if value.chars().all(|c| c.is_ascii_hexdigit()) && !name.contains(' ') {
                    if let Some(done) = current.take() {
                        if header.is_some() { pending.push(done) } else { fields.push(done) }
                    }
                    current = Some((name.to_string(), value.to_string()));
                    continue;
                }
            }
            if let Some(done) = current.take() {
                if header.is_some() { pending.push(done) } else { fields.push(done) }
            }
        }
        if let Some(done) = current.take() { pending.push(done); }
        finish_signature(&mut pending, &mut signatures, &header);
        let fields = fields.into_iter()
            .map(|(name, hex)| (name, BigUint::from_hex(&hex).unwrap())).collect();
        (fields, signatures)
    }

    pub(crate) fn field(fields: &[(String, BigUint)], name: &str) -> BigUint {
        fields.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("{name}")).1.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AnyHash;

    fn digest(name: &str, message: &str) -> Vec<u8> {
        let mut hash = AnyHash::new(name).unwrap();
        hash.update(message.as_bytes());
        hash.digest()
    }

    /// Both of RFC 6979's DSA groups, every hash, both messages: the
    /// deterministic `k` gives exactly the document's `r` and `s`.
    #[test]
    fn test_the_rfc_6979_dsa_vectors() {
        for (heading, bits) in [("A.2.1.  DSA, 1024 Bits", 1024), ("A.2.2.  DSA, 2048 Bits", 2048)] {
            let (fields, signatures) = rfc6979::section(heading);
            let get = |name: &str| rfc6979::field(&fields, name);
            let parameters = DsaParameters::new(get("p"), get("q"), get("g")).unwrap();
            assert_eq!(parameters.p.bit_len(), bits);
            parameters.check_primes(16).unwrap();
            let key = DsaPrivateKey::from_x(parameters, get("x")).unwrap();
            assert_eq!(key.public.y, get("y"), "{heading}: y");
            assert_eq!(signatures.len(), 10, "{heading}");
            for signature in signatures {
                let hashed = digest(&signature.hash, &signature.message);
                let label = format!("{heading} {} {:?}", signature.hash, signature.message);
                // The document's k is the generator's first candidate below
                // q. Not always its first: with SHA-256 on the 160 bit
                // group the first one is out of range, which is the case
                // the retry path exists for.
                let q = &key.public.parameters.q;
                let mut nonces = NonceGenerator::new(AnyHash::new(&signature.hash).unwrap(),
                                                     key.x(), &hashed, q).unwrap();
                let k = std::iter::repeat_with(|| nonces.next())
                    .find(|k| !k.is_zero() && k < q).unwrap();
                assert_eq!(k, signature.k, "{label}: k");
                let (r, s) = key.sign(&hashed, AnyHash::new(&signature.hash).unwrap()).unwrap();
                assert_eq!((&r, &s), (&signature.r, &signature.s), "{label}");
                assert!(key.public.verify(&hashed, &r, &s).unwrap(), "{label}");
                assert!(!key.public.verify(&hashed, &s, &r).unwrap(), "{label}");
            }
        }
    }

    #[test]
    fn test_out_of_range_signatures_and_bad_groups_are_refused() {
        let (fields, _) = rfc6979::section("A.2.1.  DSA, 1024 Bits");
        let get = |name: &str| rfc6979::field(&fields, name);
        let parameters = DsaParameters::new(get("p"), get("q"), get("g")).unwrap();
        let public = DsaPublicKey::new(parameters.clone(), get("y")).unwrap();
        let q = get("q");
        assert!(!public.verify(&[1; 20], &BigUint::zero(), &BigUint::one()).unwrap());
        assert!(!public.verify(&[1; 20], &q, &BigUint::one()).unwrap());
        // g = p - 1 has order 2, not q; and a y outside the subgroup.
        assert!(DsaParameters::new(get("p"), get("q"),
                                   get("p").sub(&BigUint::one()).unwrap()).is_err());
        assert!(DsaPublicKey::new(parameters, get("p").sub(&BigUint::one()).unwrap()).is_err());
    }

    #[test]
    fn test_a_generated_group_signs() {
        let parameters = DsaParameters::generate(1024, 160).unwrap();
        parameters.check_primes(16).unwrap();
        let key = DsaPrivateKey::generate(parameters).unwrap();
        let hashed = digest("sha1", "anything");
        let (r, s) = key.sign(&hashed, AnyHash::new("sha1").unwrap()).unwrap();
        assert!(key.public.verify(&hashed, &r, &s).unwrap());
    }
}
