/*
ML-DSA (FIPS 204): the module-lattice signature scheme.

Signatures of 2.4 to 4.6 KB with keys of 1.3 to 2.6 KB, against
SLH-DSA's 8 to 50 KB signatures - the price is a security argument that
rests on lattice problems rather than on a hash function alone.

    ring.rs     Z_q[X]/(X^256+1) with q = 8380417, and the NTT
    round.rs    Power2Round, Decompose, the hints
    encode.rs   bit packing, and the hint encoding
    sample.rs   RejNTTPoly, RejBoundedPoly, SampleInBall, ExpandA/S/Mask
    mod.rs      key generation, signing, verification; the external
                interface with its pre-hash variant

# Pitfalls

**Signing is a rejection loop, and a signature that left it early is a
leak.** Each attempt draws a mask `y`, computes a candidate `z = y + c*s1`,
and throws it away unless `z` and the low bits of `w - c*s2` are small
enough that they say nothing about `s1` and `s2`. Skipping a check - or
checking against the wrong bound - produces signatures that verify and
that leak the key over enough of them. The verifier only checks `z`'s
bound, so **nothing a verifier does can catch a signer that skips the
`r0` or `ct0` checks**; NIST's deterministic signing vectors can, because
a skipped rejection changes which attempt is returned.

**The attempt counter `kappa` advances by `l`, not by 1.** `ExpandMask`
uses counters `kappa .. kappa + l` for one attempt's `l` polynomials, so
the next attempt must start at `kappa + l`. Advancing by one reuses
`l - 1` of the previous attempt's polynomials - and reusing a mask with a
different challenge is exactly how a lattice signature gives up its key.

**`mu` is `H(tr ‖ M', 64)` with `tr = H(pk, 64)`.** The public key is
bound into every signature through `tr`; the external interface's
domain separator and context are in `M'`. The `externalMu` variant
starts from a caller-supplied `mu` and is otherwise identical.

**Hedged signing mixes `rnd` into `rho''`, never into `mu`.** `rnd` is
32 random bytes, or 32 zero bytes for the deterministic variant.
*/

pub mod encode;
pub mod ring;
pub mod round;
pub mod sample;

pub use super::prehash::{PreHash, MAX_CONTEXT, PRE_HASHES};
use super::prehash::wrap;
use self::ring::{Poly, N, Q};
use self::round::{Gamma2, D};
use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::HashFunction;

/// One of FIPS 204's three parameter sets, table 1.
#[derive(Debug, PartialEq, Eq)]
pub struct Parameters {
    pub name: &'static str,
    /// Rows of `A`: the length of `s2`, `t` and `w`.
    pub k: usize,
    /// Columns of `A`: the length of `s1`, `y` and `z`.
    pub l: usize,
    pub eta: u32,
    /// Non-zero coefficients in the challenge.
    pub tau: usize,
    /// Collision strength; `c-tilde` is `lambda / 4` bytes.
    pub lambda: usize,
    pub gamma1: u32,
    pub gamma2: Gamma2,
    /// Most ones a hint may have.
    pub omega: usize,
}

pub const PARAMETER_SETS: [Parameters; 3] = [
    Parameters { name: "ML-DSA-44", k: 4, l: 4, eta: 2, tau: 39, lambda: 128,
                 gamma1: 1 << 17, gamma2: Gamma2::QMinusOneOver88, omega: 80 },
    Parameters { name: "ML-DSA-65", k: 6, l: 5, eta: 4, tau: 49, lambda: 192,
                 gamma1: 1 << 19, gamma2: Gamma2::QMinusOneOver32, omega: 55 },
    Parameters { name: "ML-DSA-87", k: 8, l: 7, eta: 2, tau: 60, lambda: 256,
                 gamma1: 1 << 19, gamma2: Gamma2::QMinusOneOver32, omega: 75 },
];

/// A parameter set by its FIPS 204 name, matched exactly.
pub fn parameters(name: &str) -> Result<&'static Parameters, String> {
    PARAMETER_SETS.iter().find(|set| set.name == name).ok_or_else(|| format!(
        "Unknown ML-DSA parameter set {:?}. FIPS 204 defines {}.", name,
        PARAMETER_SETS.iter().map(|set| set.name).collect::<Vec<_>>()
            .join(", ")))
}

impl Parameters {
    /// `beta = tau * eta`: the largest a coefficient of `c*s1` can be.
    pub fn beta(&self) -> u32 { self.tau as u32 * self.eta }

    /// Bytes of `c-tilde`.
    pub fn challenge_len(&self) -> usize { self.lambda / 4 }

    /// Width of a packed `s1` or `s2` coefficient.
    fn eta_width(&self) -> u32 { encode::bitlen(2 * self.eta) }

    /// Width of a packed `z` coefficient.
    fn z_width(&self) -> u32 { 1 + encode::bitlen(self.gamma1 - 1) }

    pub fn public_key_len(&self) -> usize { 32 + 320 * self.k }

    pub fn private_key_len(&self) -> usize {
        128 + 32 * ((self.k + self.l) * self.eta_width() as usize
                    + D as usize * self.k)
    }

    pub fn signature_len(&self) -> usize {
        self.challenge_len() + self.l * 32 * self.z_width() as usize
            + self.omega + self.k
    }
}

/// `H`: SHAKE256 to `length` bytes, over the concatenation of `parts`.
fn h(parts: &[&[u8]], length: usize) -> Result<Vec<u8>, String> {
    let mut sponge = Keccak::shake(256, length)?;
    for part in parts {
        sponge.update(part);
    }
    Ok(sponge.squeeze(length))
}

fn ntt_all(polys: &[Poly]) -> Vec<Poly> {
    polys.iter().map(|p| { let mut q = p.clone(); q.ntt(); q }).collect()
}

/// `A_hat * v_hat`, then out of the transformed domain.
fn matrix_times(a_hat: &[Vec<Poly>], v_hat: &[Poly]) -> Vec<Poly> {
    a_hat.iter().map(|row| {
        let mut sum = Poly::zero();
        for (a, v) in row.iter().zip(v_hat) {
            sum = sum.add(&a.multiply_ntt(v));
        }
        sum.inverse_ntt();
        sum
    }).collect()
}

/// `c_hat * v_hat[i]` for each `i`, out of the transformed domain.
fn scalar_times(c_hat: &Poly, v_hat: &[Poly]) -> Vec<Poly> {
    v_hat.iter().map(|v| {
        let mut product = c_hat.multiply_ntt(v);
        product.inverse_ntt();
        product
    }).collect()
}

/// The largest of some magnitudes, without a branch per value.
fn branchless_max(values: impl Iterator<Item = u32>) -> u32 {
    let mut largest = 0u32;
    for value in values {
        let bigger = round::greater(value, largest).wrapping_neg();
        largest ^= (largest ^ value) & bigger;
    }
    largest
}

/// The infinity norm of a vector: the largest `|w mod± q|`. Runs on
/// secrets while signing, so it is branchless.
fn infinity_norm(polys: &[Poly]) -> u32 {
    branchless_max(polys.iter().flat_map(|p| p.coefficients.iter())
                       .map(|v| round::magnitude(round::signed(*v))))
}

/// `w1Encode`: each high part at `bitlen(m - 1)` bits.
fn w1_encode(parameters: &Parameters, w1: &[Poly]) -> Vec<u8> {
    let top = parameters.gamma2.high_values() - 1;
    let mut out = Vec::with_capacity(w1.len() * 32
                                     * encode::bitlen(top) as usize);
    for poly in w1 {
        encode::simple_bit_pack(poly, top, &mut out);
    }
    out
}

/// FIPS 204 algorithm 6, `ML-DSA.KeyGen_internal`: `(pk, sk)` from the
/// 32 byte seed `xi`.
pub fn key_gen_internal(parameters: &'static Parameters, xi: &[u8])
        -> Result<(Vec<u8>, Vec<u8>), String> {
    if xi.len() != 32 {
        return Err(format!("ML-DSA.KeyGen: the seed is {} bytes and should \
                            be 32.", xi.len()));
    }
    let (k, l) = (parameters.k, parameters.l);
    let expanded = h(&[xi, &[k as u8, l as u8]], 128)?;
    let (rho, rho_prime, key) = (&expanded[..32], &expanded[32..96],
                                 &expanded[96..]);

    let (s1, s2) = sample::expand_s(rho_prime, parameters.eta, k, l)?;
    let (t1, t0) = split_t(parameters, rho, &s1, &s2)?;

    let pk = encode_public_key(parameters, rho, &t1);
    let tr = h(&[&pk], 64)?;
    let mut sk = Vec::with_capacity(parameters.private_key_len());
    sk.extend_from_slice(rho);
    sk.extend_from_slice(key);
    sk.extend_from_slice(&tr);
    for poly in s1.iter().chain(&s2) {
        encode::bit_pack(poly, parameters.eta, parameters.eta, &mut sk);
    }
    let half = 1u32 << (D - 1);
    for poly in &t0 {
        encode::bit_pack(poly, half - 1, half, &mut sk);
    }
    debug_assert_eq!(pk.len(), parameters.public_key_len());
    debug_assert_eq!(sk.len(), parameters.private_key_len());
    Ok((pk, sk))
}

/// `t = A*s1 + s2`, split by `Power2Round` into `(t1, t0)`.
fn split_t(parameters: &Parameters, rho: &[u8], s1: &[Poly], s2: &[Poly])
        -> Result<(Vec<Poly>, Vec<Poly>), String> {
    let a_hat = sample::expand_a(rho, parameters.k, parameters.l)?;
    let t: Vec<Poly> = matrix_times(&a_hat, &ntt_all(s1)).iter()
        .zip(s2).map(|(a, s)| a.add(s)).collect();
    let mut t1 = Vec::with_capacity(parameters.k);
    let mut t0 = Vec::with_capacity(parameters.k);
    for poly in &t {
        let (mut high, mut low) = (Poly::zero(), Poly::zero());
        for (at, value) in poly.coefficients.iter().enumerate() {
            let (r1, r0) = round::power2round(*value);
            high.coefficients[at] = r1;
            low.coefficients[at] = round::unsigned(r0);
        }
        t1.push(high);
        t0.push(low);
    }
    Ok((t1, t0))
}

/// The public key belonging to an expanded private key, recomputed - and
/// an error if the private key's parts do not belong together.
///
/// A private key carries `rho`, `s1`, `s2`, `t0` and `tr = H(pk)`, but not
/// `t1`. Everything `t1` comes from is there, so this recomputes
/// `t = A*s1 + s2`, takes `t1` from it, and checks two things against
/// what the key carries: that the recomputed `t0` is its `t0`, and that
/// the hash of the recomputed public key is its `tr`. It also refuses an
/// `s1` or `s2` coefficient outside `[-eta, eta]`, which only a malformed
/// encoding produces. All three are inputs FIPS 204 does not require
/// `skDecode` to check; checking them on import is what stops a key that
/// signs as one thing from claiming to be another.
///
/// Runs on secrets and branches on them; it is an import-time check, not
/// a signing-time one.
pub fn public_from_private(parameters: &'static Parameters, sk: &[u8])
        -> Result<Vec<u8>, String> {
    let private = decode_private_key(parameters, sk)?;
    let eta = parameters.eta;
    if private.s1.iter().chain(&private.s2)
            .flat_map(|p| p.coefficients.iter())
            .any(|v| round::signed(*v).unsigned_abs() > eta) {
        return Err(format!("{}: the private key's s1 or s2 has a coefficient \
                            outside [-{eta}, {eta}], so it is not an \
                            encoding of an ML-DSA key.", parameters.name));
    }
    let (t1, t0) = split_t(parameters, private.rho, &private.s1, &private.s2)?;
    if t0 != private.t0 {
        return Err(format!("{}: the private key's t0 is not the one its s1 \
                            and s2 give, so its parts do not belong \
                            together.", parameters.name));
    }
    let pk = encode_public_key(parameters, private.rho, &t1);
    if h(&[&pk], 64)? != sk[64..128] {
        return Err(format!("{}: the private key's tr is not the hash of the \
                            public key its parts give.", parameters.name));
    }
    Ok(pk)
}

/// FIPS 204 algorithm 22, `pkEncode`.
fn encode_public_key(parameters: &Parameters, rho: &[u8], t1: &[Poly])
        -> Vec<u8> {
    let mut pk = Vec::with_capacity(parameters.public_key_len());
    pk.extend_from_slice(rho);
    for poly in t1 {
        encode::simple_bit_pack(poly, (1 << 10) - 1, &mut pk);
    }
    pk
}

/// FIPS 204 algorithm 23, `pkDecode`: `(rho, t1)`.
fn decode_public_key<'a>(parameters: &Parameters, pk: &'a [u8])
        -> Result<(&'a [u8], Vec<Poly>), String> {
    if pk.len() != parameters.public_key_len() {
        return Err(format!("{}: a public key is {} bytes and should be {}.",
                           parameters.name, pk.len(),
                           parameters.public_key_len()));
    }
    let t1 = pk[32..].chunks(320)
        .map(|chunk| encode::simple_bit_unpack(chunk, (1 << 10) - 1))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((&pk[..32], t1))
}

/// What `skDecode` gives back.
struct PrivateKey<'a> {
    rho: &'a [u8],
    key: &'a [u8],
    s1: Vec<Poly>,
    s2: Vec<Poly>,
    t0: Vec<Poly>,
}

/// FIPS 204 algorithm 25, `skDecode`.
fn decode_private_key<'a>(parameters: &Parameters, sk: &'a [u8])
        -> Result<PrivateKey<'a>, String> {
    if sk.len() != parameters.private_key_len() {
        return Err(format!("{}: a private key is {} bytes and should be {}.",
                           parameters.name, sk.len(),
                           parameters.private_key_len()));
    }
    let (k, l, eta) = (parameters.k, parameters.l, parameters.eta);
    let eta_bytes = 32 * parameters.eta_width() as usize;
    let mut at = 128;
    let mut take = |count: usize, bytes: usize, a: u32, b: u32| {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(encode::bit_unpack(&sk[at..at + bytes], a, b)?);
            at += bytes;
        }
        Ok::<_, String>(out)
    };
    let s1 = take(l, eta_bytes, eta, eta)?;
    let s2 = take(k, eta_bytes, eta, eta)?;
    let half = 1u32 << (D - 1);
    let t0 = take(k, 32 * D as usize, half - 1, half)?;
    // `tr`, bytes 64..128, is read by `mu_from_private` - signing from a
    // caller-supplied `mu` does not need it.
    Ok(PrivateKey { rho: &sk[..32], key: &sk[32..64], s1, s2, t0 })
}

/// What decides whether one attempt of the signing loop is kept.
///
/// All four are measured on every attempt, so that the decision is one
/// function, [`accepted`], which can be tested at each of its bounds -
/// two of the four checks fire so rarely in practice that no vector set
/// reaches them (see `docs/pitfalls.md` section 7w).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Norms {
    /// `||z||∞`.
    pub z: u32,
    /// `||LowBits(w - c*s2)||∞`.
    pub r0: u32,
    /// `||c*t0||∞`.
    pub ct0: u32,
    /// Ones in the hint.
    pub ones: usize,
}

/// FIPS 204 algorithm 7's rejection test: whether an attempt with these
/// norms may be returned.
///
/// **Every bound is strict.** `||z||∞` must be *below* `gamma1 - beta`,
/// `r0` below `gamma2 - beta`, `c*t0` below `gamma2`, and there may be *at
/// most* `omega` ones. Each of the first three protects the private key;
/// the last keeps the hint encodable.
pub fn accepted(parameters: &Parameters, norms: &Norms) -> bool {
    let beta = parameters.beta();
    let gamma2 = parameters.gamma2.value();
    // `&`, not `&&`: short-circuiting would make *which* check failed a
    // timing signal, where FIPS 204 needs only *that* one did. The single
    // branch the caller takes on the result is the rejection itself,
    // which the number of attempts reveals anyway.
    (norms.z < parameters.gamma1 - beta)
        & (norms.r0 < gamma2 - beta)
        & (norms.ct0 < gamma2)
        & (norms.ones <= parameters.omega)
}

/// FIPS 204 algorithm 7, `ML-DSA.Sign_internal`, from `mu`.
///
/// `mu` is `H(tr ‖ M', 64)` - computed by [`sign_internal`], or supplied
/// by the caller for the `externalMu` variant. `rnd` is 32 bytes: random
/// for hedged signing, zero for deterministic.
pub fn sign_mu(parameters: &'static Parameters, sk: &[u8], mu: &[u8],
               rnd: &[u8]) -> Result<Vec<u8>, String> {
    sign_with(parameters, sk, mu, rnd, &accepted)
}

/// The signing loop, with the rejection test as a parameter.
///
/// [`sign_mu`] passes [`accepted`]. The tests pass something else, to
/// make signatures FIPS 204 forbids and check that verification refuses
/// them - the only way to reach the verifier's own bound on `z`, which an
/// honest signer never gives it anything to refuse.
pub(crate) fn sign_with(parameters: &'static Parameters, sk: &[u8], mu: &[u8],
                        rnd: &[u8], accept: &dyn Fn(&Parameters, &Norms) -> bool)
        -> Result<Vec<u8>, String> {
    if mu.len() != 64 || rnd.len() != 32 {
        return Err(format!("ML-DSA.Sign: mu is 64 bytes and rnd 32, not {} \
                            and {}.", mu.len(), rnd.len()));
    }
    let (k, l) = (parameters.k, parameters.l);
    let gamma2 = parameters.gamma2;
    let private = decode_private_key(parameters, sk)?;
    let s1_hat = ntt_all(&private.s1);
    let s2_hat = ntt_all(&private.s2);
    let t0_hat = ntt_all(&private.t0);
    let a_hat = sample::expand_a(private.rho, k, l)?;
    let rho_double_prime = h(&[private.key, rnd, mu], 64)?;

    let mut kappa = 0usize;
    loop {
        // FIPS 204 bounds the loop only by probability; a counter past
        // what two bytes can hold means something is badly wrong.
        if kappa > u16::MAX as usize - l {
            return Err("ML-DSA.Sign: the rejection loop did not terminate."
                       .to_string());
        }
        let y = sample::expand_mask(&rho_double_prime, kappa, parameters.gamma1,
                                    l)?;
        kappa += l;
        let w = matrix_times(&a_hat, &ntt_all(&y));
        let w1: Vec<Poly> = w.iter().map(|poly| {
            let mut high = Poly::zero();
            for (out, value) in high.coefficients.iter_mut()
                    .zip(poly.coefficients.iter()) {
                *out = round::high_bits(*value, gamma2);
            }
            high
        }).collect();

        let c_tilde = h(&[mu, &w1_encode(parameters, &w1)],
                        parameters.challenge_len())?;
        let mut c_hat = sample::sample_in_ball(&c_tilde, parameters.tau)?;
        c_hat.ntt();
        let cs1 = scalar_times(&c_hat, &s1_hat);
        let cs2 = scalar_times(&c_hat, &s2_hat);
        let ct0 = scalar_times(&c_hat, &t0_hat);

        let z: Vec<Poly> = y.iter().zip(&cs1).map(|(a, b)| a.add(b)).collect();
        let w_minus: Vec<Poly> = w.iter().zip(&cs2).map(|(a, b)| a.sub(b))
            .collect();

        let mut hints = vec![[false; N]; k];
        let mut ones = 0usize;
        for (hint, (ct0, w_minus)) in hints.iter_mut().zip(ct0.iter()
                                                           .zip(&w_minus)) {
            for (at, set) in hint.iter_mut().enumerate() {
                // MakeHint(-ct0, w - cs2 + ct0).
                let minus_ct0 = (Q - ct0.coefficients[at]) % Q;
                let r = (w_minus.coefficients[at] + ct0.coefficients[at]) % Q;
                // Stored and counted without a branch on the hint bit.
                let bit = round::make_hint(minus_ct0, r, gamma2);
                *set = bit;
                ones += usize::from(bit);
            }
        }
        let norms = Norms {
            z: infinity_norm(&z),
            r0: branchless_max(w_minus.iter().flat_map(|p| p.coefficients.iter())
                .map(|v| round::magnitude(round::low_bits(*v, gamma2)))),
            ct0: infinity_norm(&ct0),
            ones,
        };
        if !accept(parameters, &norms) {
            continue;
        }

        let mut signature = Vec::with_capacity(parameters.signature_len());
        signature.extend_from_slice(&c_tilde);
        for poly in &z {
            encode::bit_pack(poly, parameters.gamma1 - 1, parameters.gamma1,
                             &mut signature);
        }
        encode::hint_bit_pack(&hints, parameters.omega, &mut signature)?;
        debug_assert_eq!(signature.len(), parameters.signature_len());
        return Ok(signature);
    }
}

/// `mu = H(tr ‖ M', 64)`, with `tr` read from the private key.
fn mu_from_private(parameters: &Parameters, sk: &[u8], message: &[u8])
        -> Result<Vec<u8>, String> {
    if sk.len() != parameters.private_key_len() {
        return Err(format!("{}: a private key is {} bytes and should be {}.",
                           parameters.name, sk.len(),
                           parameters.private_key_len()));
    }
    h(&[&sk[64..128], message], 64)
}

/// FIPS 204 algorithm 7, `ML-DSA.Sign_internal`: sign `M'` as given.
pub fn sign_internal(parameters: &'static Parameters, sk: &[u8],
                     message: &[u8], rnd: &[u8]) -> Result<Vec<u8>, String> {
    let mu = mu_from_private(parameters, sk, message)?;
    sign_mu(parameters, sk, &mu, rnd)
}

/// FIPS 204 algorithm 8, `ML-DSA.Verify_internal`, from `mu`.
///
/// `Ok(false)` for a signature that does not verify - including one of
/// the wrong length or with a malformed hint; `Err` only for a public key
/// of the wrong length.
pub fn verify_mu(parameters: &'static Parameters, pk: &[u8], mu: &[u8],
                 signature: &[u8]) -> Result<bool, String> {
    let (rho, t1) = decode_public_key(parameters, pk)?;
    if mu.len() != 64 {
        return Err(format!("ML-DSA.Verify: mu is 64 bytes, not {}.", mu.len()));
    }
    if signature.len() != parameters.signature_len() {
        return Ok(false);
    }
    let (k, l) = (parameters.k, parameters.l);
    let lambda_bytes = parameters.challenge_len();
    let z_bytes = 32 * parameters.z_width() as usize;
    let c_tilde = &signature[..lambda_bytes];
    let z = signature[lambda_bytes..lambda_bytes + l * z_bytes].chunks(z_bytes)
        .map(|chunk| encode::bit_unpack(chunk, parameters.gamma1 - 1,
                                        parameters.gamma1))
        .collect::<Result<Vec<_>, _>>()?;
    let hints = match encode::hint_bit_unpack(
            &signature[lambda_bytes + l * z_bytes..], parameters.omega, k) {
        Some(hints) => hints,
        None => return Ok(false),
    };
    if infinity_norm(&z) >= parameters.gamma1 - parameters.beta() {
        return Ok(false);
    }

    let a_hat = sample::expand_a(rho, k, l)?;
    let mut c_hat = sample::sample_in_ball(c_tilde, parameters.tau)?;
    c_hat.ntt();
    let z_hat = ntt_all(&z);
    // t1 * 2^d, transformed.
    let t1_hat: Vec<Poly> = t1.iter().map(|poly| {
        let mut scaled = Poly::zero();
        for at in 0..N {
            scaled.coefficients[at] = ring::mul(poly.coefficients[at], 1 << D);
        }
        scaled.ntt();
        scaled
    }).collect();

    let mut w1 = Vec::with_capacity(k);
    for ((row, t1_hat), hint) in a_hat.iter().zip(&t1_hat).zip(&hints) {
        let mut sum = Poly::zero();
        for (a, z) in row.iter().zip(&z_hat) {
            sum = sum.add(&a.multiply_ntt(z));
        }
        let mut approx = sum.sub(&c_hat.multiply_ntt(t1_hat));
        approx.inverse_ntt();
        let mut high = Poly::zero();
        for (at, out) in high.coefficients.iter_mut().enumerate() {
            *out = round::use_hint(hint[at], approx.coefficients[at],
                                   parameters.gamma2);
        }
        w1.push(high);
    }
    let again = h(&[mu, &w1_encode(parameters, &w1)], lambda_bytes)?;
    Ok(again == c_tilde)
}

/// FIPS 204 algorithm 8, `ML-DSA.Verify_internal`: verify `M'` as given.
pub fn verify_internal(parameters: &'static Parameters, pk: &[u8],
                       message: &[u8], signature: &[u8])
        -> Result<bool, String> {
    if pk.len() != parameters.public_key_len() {
        return Err(format!("{}: a public key is {} bytes and should be {}.",
                           parameters.name, pk.len(),
                           parameters.public_key_len()));
    }
    let tr = h(&[pk], 64)?;
    let mu = h(&[&tr, message], 64)?;
    verify_mu(parameters, pk, &mu, signature)
}

/// FIPS 204 algorithms 2 and 4, `ML-DSA.Sign` and `HashML-DSA.Sign`: the
/// external interface, with the same domain separation as SLH-DSA's.
pub fn sign(parameters: &'static Parameters, sk: &[u8], message: &[u8],
            context: &[u8], pre_hash: Option<PreHash>, rnd: &[u8])
        -> Result<Vec<u8>, String> {
    let wrapped = wrap(message, context, pre_hash)?;
    sign_internal(parameters, sk, &wrapped, rnd)
}

/// FIPS 204 algorithms 3 and 5, `ML-DSA.Verify` and `HashML-DSA.Verify`.
pub fn verify(parameters: &'static Parameters, pk: &[u8], message: &[u8],
              context: &[u8], pre_hash: Option<PreHash>,
              signature: &[u8]) -> Result<bool, String> {
    let wrapped = wrap(message, context, pre_hash)?;
    verify_internal(parameters, pk, &wrapped, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte lengths FIPS 204 table 2 publishes - the one place the
    /// parameter table meets a number a reader can look up.
    #[test]
    fn test_the_sizes_are_what_fips_204_publishes() {
        let expected = [("ML-DSA-44", 1312, 2560, 2420),
                        ("ML-DSA-65", 1952, 4032, 3309),
                        ("ML-DSA-87", 2592, 4896, 4627)];
        for (name, pk, sk, sig) in expected {
            let set = parameters(name).unwrap();
            assert_eq!(set.public_key_len(), pk, "{name} pk");
            assert_eq!(set.private_key_len(), sk, "{name} sk");
            assert_eq!(set.signature_len(), sig, "{name} signature");
        }
        assert_eq!(parameters("ML-DSA-44").unwrap().beta(), 78);
        assert_eq!(parameters("ML-DSA-65").unwrap().beta(), 196);
        assert_eq!(parameters("ML-DSA-87").unwrap().beta(), 120);
        assert!(parameters("Dilithium2").is_err());
    }

    /// Each of the four bounds, at the bound and one below it.
    ///
    /// Two of the four - `c*t0` and the hint count - are reached by honest
    /// signing so rarely that no vector set exercises them: `||c*t0||∞`
    /// can only reach `gamma2` at ML-DSA-44, and then only when most of 39
    /// signs line up. So they are checked here, as a function, rather than
    /// trusted to the loop.
    #[test]
    fn test_every_rejection_bound_is_strict() {
        for set in &PARAMETER_SETS {
            let gamma2 = set.gamma2.value();
            let inside = Norms { z: set.gamma1 - set.beta() - 1,
                                 r0: gamma2 - set.beta() - 1,
                                 ct0: gamma2 - 1, ones: set.omega };
            assert!(accepted(set, &inside), "{}", set.name);
            let at_bound = [
                Norms { z: set.gamma1 - set.beta(), ..inside },
                Norms { r0: gamma2 - set.beta(), ..inside },
                Norms { ct0: gamma2, ..inside },
                Norms { ones: set.omega + 1, ..inside },
            ];
            for (which, norms) in at_bound.iter().enumerate() {
                assert!(!accepted(set, norms), "{} bound {which}", set.name);
            }
        }
    }

    /// A signature whose `z` is past the bound - which an honest signer
    /// never makes - is refused by the verifier.
    ///
    /// Made by running the signing loop with a rejection test that accepts
    /// *only* attempts whose `z` is in `[gamma1 - beta, gamma1)` and that
    /// are otherwise in bounds. Such a signature is internally consistent:
    /// the commitment matches, so the only thing standing between it and
    /// acceptance is the verifier's check on `z`.
    #[test]
    fn test_verification_refuses_z_past_its_bound() {
        let set = parameters("ML-DSA-44").unwrap();
        let (pk, sk) = key_gen_internal(set, &[7u8; 32]).unwrap();
        let mu = h(&[&h(&[&pk], 64).unwrap(), b"z".as_slice()], 64).unwrap();
        let too_large = |parameters: &Parameters, norms: &Norms| {
            let bound = parameters.gamma1 - parameters.beta();
            norms.z >= bound && norms.z < parameters.gamma1
                && accepted(parameters, &Norms { z: bound - 1, ..*norms })
        };
        let signature = sign_with(set, &sk, &mu, &[0u8; 32], &too_large)
            .unwrap();
        assert!(!verify_mu(set, &pk, &mu, &signature).unwrap(),
                "a signature with z past gamma1 - beta must be refused");
        // And an honest signature on the same mu is accepted, so the
        // refusal above is about z rather than about mu or the key.
        let honest = sign_mu(set, &sk, &mu, &[0u8; 32]).unwrap();
        assert!(verify_mu(set, &pk, &mu, &honest).unwrap());
    }

    /// The public key comes back out of the private key, and a private
    /// key whose parts were changed is refused for the part that changed.
    #[test]
    fn test_public_from_private_recomputes_and_checks() {
        for set in &PARAMETER_SETS {
            let (pk, sk) = key_gen_internal(set, &[3u8; 32]).unwrap();
            assert_eq!(public_from_private(set, &sk).unwrap(), pk, "{}", set.name);

            let mut bad_tr = sk.clone();
            bad_tr[64] ^= 1;
            assert!(public_from_private(set, &bad_tr).unwrap_err()
                        .contains("tr is not"), "{}", set.name);

            let mut bad_rho = sk.clone();
            bad_rho[0] ^= 1;                    // a different A
            assert!(public_from_private(set, &bad_rho).unwrap_err()
                        .contains("t0 is not"), "{}", set.name);

            let mut bad_t0 = sk.clone();
            let last = bad_t0.len() - 1;
            bad_t0[last] ^= 0x10;
            assert!(public_from_private(set, &bad_t0).unwrap_err()
                        .contains("t0 is not"), "{}", set.name);

            // An s1 coefficient of 7 - in three bits, b - w = 7 means
            // w = eta - 7, outside [-eta, eta] at eta = 2. At eta = 4 the
            // field is four bits and 15 does the same.
            let mut bad_s1 = sk.clone();
            bad_s1[128] |= if set.eta == 2 { 0x07 } else { 0x0f };
            assert!(public_from_private(set, &bad_s1).unwrap_err()
                        .contains("outside"), "{}", set.name);

            assert!(public_from_private(set, &sk[1..]).is_err());
        }
    }

    #[test]
    fn test_sign_and_verify_round_trip() {
        for set in &PARAMETER_SETS {
            let (pk, sk) = key_gen_internal(set, &[set.k as u8; 32]).unwrap();
            let signature = sign_internal(set, &sk, b"message", &[0u8; 32])
                .unwrap();
            assert_eq!(signature.len(), set.signature_len());
            assert!(verify_internal(set, &pk, b"message", &signature).unwrap());
            assert!(!verify_internal(set, &pk, b"massage", &signature).unwrap());
            let mut altered = signature.clone();
            altered[0] ^= 1;
            assert!(!verify_internal(set, &pk, b"message", &altered).unwrap());
            assert!(!verify_internal(set, &pk, b"message",
                                     &signature[..signature.len() - 1])
                        .unwrap());
        }
    }
}
