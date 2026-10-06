/*
ML-KEM (FIPS 203), the lattice key encapsulation mechanism.

Key generation, encapsulation and decapsulation, at the `_internal` level
FIPS 203 defines - the random inputs are arguments, which is what makes
them testable against vectors that state them. `ring` is
`Z_q[X]/(X^256 + 1)` with `q = 3329` and the NTT; `encode` and `sample`
are the byte encodings and the two samplers.

This is the one of the three post-quantum standards that is actually being
deployed - `X25519MLKEM768` is what a TLS 1.3 `key_share` carries in
Chrome and in OpenSSL 3.5 - so it is the one a library called "all crypt"
will be asked for first, whatever the order of implementation here.

## What is not decided yet, and should not be decided by accident

Two things about the eventual API are worth having written down before the
code that would fix them exists, because both are easy to get wrong in a
way that is hard to undo:

**Decapsulation must not report failure.** The FO transform re-encrypts
and compares, and on a mismatch FIPS 203 returns a *deterministic
pseudorandom* shared secret derived from the ciphertext and a stored
secret `z` - not an error. [`decapsulate_internal`] returns a `Result`,
and the distinction it draws is the important one: `Err` for inputs that
are malformed by *public* facts (lengths, and the key's own embedded
hash), decided before anything secret is touched; `Ok` for every
well-formed ciphertext, including the ones that fail re-encryption. The
shape is the same as `tls::server::ServerConnection::decrypt_premaster`
in this library, which cannot fail for the same reason.

**The parameter set is the type, not a number.** `ML-KEM-512`, `-768` and
`-1024` differ in `k`, in `eta_1` and `eta_2`, and in two compression
widths. A function taking those as arguments will eventually be called
with a mixed set, and the result is a scheme that runs and interoperates
with nothing.
*/

pub mod encode;
pub mod ring;
pub mod sample;

use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::HashFunction;
use ring::Poly;

/// One of the three approved parameter sets.
///
/// **The parameter set is the type, not a number**, which is the warning
/// above made concrete: `k`, `eta_1`, `eta_2`, `du` and `dv` all move
/// together, and a function taking them as five arguments will eventually
/// be called with a mixed set. Everything here takes a
/// `&'static Parameters` from [`parameters`].
#[derive(Debug)]
pub struct Parameters {
    /// The FIPS 203 name, e.g. `ML-KEM-768`.
    pub name: &'static str,
    /// Polynomials per vector, and the matrix is `k` by `k`.
    pub k: usize,
    /// The noise width for the secret and the key generation error.
    pub eta1: u32,
    /// The noise width for encryption's error terms.
    pub eta2: u32,
    /// Compression width for the ciphertext's `u` half.
    pub du: u32,
    /// Compression width for its `v` half.
    pub dv: u32,
}

/// The three approved sets.
///
/// `eta_2` is 2 in all three and `eta_1` is 3 only at ML-KEM-512, which is
/// the sort of near-uniformity that invites writing one number where two
/// belong.
pub const PARAMETER_SETS: [Parameters; 3] = [
    Parameters { name: "ML-KEM-512",  k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 },
    Parameters { name: "ML-KEM-768",  k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 },
    Parameters { name: "ML-KEM-1024", k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 },
];

/// Look a parameter set up by its FIPS 203 name, matched exactly.
pub fn parameters(name: &str) -> Result<&'static Parameters, String> {
    PARAMETER_SETS.iter().find(|set| set.name == name).ok_or_else(|| {
        format!("Unknown ML-KEM parameter set {:?}. FIPS 203 approves three: \
                 {}.", name,
                PARAMETER_SETS.iter().map(|s| s.name)
                    .collect::<Vec<_>>().join(", "))
    })
}

impl Parameters {
    /// `384k + 32`: the encoded `t_hat` and the 32 byte seed `rho`.
    pub fn encapsulation_key_len(&self) -> usize { 384 * self.k + 32 }

    /// `768k + 96`: `dk_PKE ‖ ek ‖ H(ek) ‖ z`.
    pub fn decapsulation_key_len(&self) -> usize { 768 * self.k + 96 }

    /// `32(du*k + dv)`: the two compressed halves of a ciphertext.
    pub fn ciphertext_len(&self) -> usize {
        32 * (self.du as usize * self.k + self.dv as usize)
    }
}

/// `H`: SHA3-256, FIPS 203's hash on byte strings.
fn h(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut hash = Keccak::sha3(32)?;
    hash.update(input);
    Ok(hash.digest())
}

/// `G`: SHA3-512, which produces the two 32 byte seeds at once.
///
/// Returned as a pair rather than 64 bytes, because the halves mean
/// different things - the first is public and the second is secret - and
/// an API handing back one buffer invites slicing it the wrong way round.
fn g(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut hash = Keccak::sha3(64)?;
    hash.update(input);
    let out = hash.digest();
    Ok((out[..32].to_vec(), out[32..].to_vec()))
}

/// `A_hat`, row by row, with `A_hat[i][j]` sampled from `XOF(rho, j, i)`.
///
/// **One function for both callers.** Key generation uses `A_hat`;
/// encryption uses its transpose. FIPS 203 orders the XOF's index bytes
/// so that the transpose could be generated by swapping them, but doing
/// that here would mean two samplers that must stay in step, and a
/// mismatch between them is the fault the module documentation calls the
/// nastiest in the scheme - every decapsulation returning the
/// implicit-rejection secret. So the matrix is sampled one way, always,
/// and encryption transposes it *by indexing* at the point of use: it
/// reads `a_hat[j][i]`.
fn sample_matrix(parameters: &'static Parameters, rho: &[u8])
        -> Result<Vec<Vec<Poly>>, String> {
    let k = parameters.k;
    let mut a_hat: Vec<Vec<Poly>> = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(k);
        for j in 0..k {
            row.push(sample::sample_ntt(rho, j as u8, i as u8)?);
        }
        a_hat.push(row);
    }
    Ok(a_hat)
}

/// FIPS 203 algorithm 13, `K-PKE.KeyGen`.
///
/// Returns `(ek_PKE, dk_PKE)`.
///
/// Three things here are the ones to watch, and all three are in the
/// pitfalls at the top of `sample.rs` as well:
///
/// * **`G` is fed `d ‖ k`**, the seed with the parameter set's `k`
///   appended as one byte. That domain separator was added in the final
///   FIPS 203 and is absent from the round-three Kyber submission, so an
///   implementation written from the older document produces different
///   keys from the same seed - and nothing says so.
/// * **`A_hat[i][j]` comes from `XOF(rho, j, i)`**, indices reversed.
/// * **`SampleNTT` returns a polynomial already in the NTT domain**, so
///   `A_hat` is not transformed again.
fn kpke_key_gen(parameters: &'static Parameters, d: &[u8])
        -> Result<(Vec<u8>, Vec<u8>), String> {
    if d.len() != 32 {
        return Err(format!("K-PKE.KeyGen: d is {} bytes and should be 32.",
                           d.len()));
    }
    let k = parameters.k;

    // G(d ‖ k) - the byte is the parameter set's k, not a counter.
    let mut seeded = Vec::with_capacity(33);
    seeded.extend_from_slice(d);
    seeded.push(k as u8);
    let (rho, sigma) = g(&seeded)?;

    let a_hat = sample_matrix(parameters, &rho)?;

    // s and e, with one PRF counter running across both.
    let mut counter = 0u8;
    let mut s = Vec::with_capacity(k);
    for _ in 0..k {
        s.push(sample::sample_poly_cbd(parameters.eta1, &sigma, counter)?);
        counter += 1;
    }
    let mut e = Vec::with_capacity(k);
    for _ in 0..k {
        e.push(sample::sample_poly_cbd(parameters.eta1, &sigma, counter)?);
        counter += 1;
    }

    for poly in s.iter_mut().chain(e.iter_mut()) {
        poly.ntt();
    }

    // t_hat = A_hat * s_hat + e_hat.
    let mut t_hat = Vec::with_capacity(k);
    for i in 0..k {
        let mut sum = e[i].clone();
        for j in 0..k {
            sum = sum.add(&a_hat[i][j].multiply_ntt(&s[j]));
        }
        t_hat.push(sum);
    }

    let mut ek = encode::byte_encode_vector_unchecked(&t_hat, 12)?;
    ek.extend_from_slice(&rho);
    let dk = encode::byte_encode_vector_unchecked(&s, 12)?;
    Ok((ek, dk))
}

/// FIPS 203 algorithm 16, `ML-KEM.KeyGen_internal`.
///
/// Returns `(ek, dk)`. The seeds are arguments rather than drawn here,
/// which is what makes this testable against vectors that state them;
/// `api::MlKemKey` is the wrapper that draws them.
///
/// `dk` is `dk_PKE ‖ ek ‖ H(ek) ‖ z` - the decapsulation key contains the
/// encapsulation key, the hash of it, and the implicit-rejection seed. All
/// four parts are needed by decapsulation, which is why the key is four
/// times the size a lattice secret would suggest.
pub fn key_gen_internal(parameters: &'static Parameters, d: &[u8], z: &[u8])
        -> Result<(Vec<u8>, Vec<u8>), String> {
    if z.len() != 32 {
        return Err(format!("ML-KEM.KeyGen: z is {} bytes and should be 32.",
                           z.len()));
    }
    let (ek, dk_pke) = kpke_key_gen(parameters, d)?;

    let mut dk = Vec::with_capacity(parameters.decapsulation_key_len());
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h(&ek)?);
    dk.extend_from_slice(z);

    if ek.len() != parameters.encapsulation_key_len()
            || dk.len() != parameters.decapsulation_key_len() {
        return Err(format!(
            "{}: produced a {} byte ek and a {} byte dk, expected {} and {}.",
            parameters.name, ek.len(), dk.len(),
            parameters.encapsulation_key_len(),
            parameters.decapsulation_key_len()));
    }
    Ok((ek, dk))
}

/// `J`: SHAKE-256 squeezed to 32 bytes, used only for the implicit
/// rejection secret.
fn j(z: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut sponge = Keccak::shake(256, 32)?;
    sponge.update(z);
    sponge.update(ciphertext);
    Ok(sponge.squeeze(32))
}

/// FIPS 203 algorithm 14, `K-PKE.Encrypt`.
///
/// `r` is the 32 byte seed for every random choice the encryption makes -
/// `y`, `e1` and `e2` - and it is **derived from the message** by the
/// caller, not drawn. That determinism is what makes the FO transform
/// work: decapsulation re-runs this function on the message it recovered
/// and compares ciphertexts, which only means anything if the same inputs
/// give the same output.
///
/// Uses the transpose of `A_hat` by indexing, as [`sample_matrix`]
/// explains: `u[i]` sums `a_hat[j][i] * y_hat[j]` over `j`.
fn kpke_encrypt(parameters: &'static Parameters, ek: &[u8], message: &[u8],
                r: &[u8]) -> Result<Vec<u8>, String> {
    let k = parameters.k;
    if message.len() != 32 || r.len() != 32 {
        return Err(format!(
            "K-PKE.Encrypt: the message and r are 32 bytes each, not {} and \
             {}.", message.len(), r.len()));
    }
    if ek.len() != parameters.encapsulation_key_len() {
        return Err(format!("{}: ek is {} bytes and should be {}.",
                           parameters.name, ek.len(),
                           parameters.encapsulation_key_len()));
    }
    let t_hat = encode::byte_decode_vector(&ek[..384 * k], 12, k)?;
    let rho = &ek[384 * k..];
    let a_hat = sample_matrix(parameters, rho)?;

    // y, e1 and e2, with one PRF counter running across all three - the
    // same discipline as key generation, and the same failure if it
    // restarts.
    let mut counter = 0u8;
    let mut y = Vec::with_capacity(k);
    for _ in 0..k {
        y.push(sample::sample_poly_cbd(parameters.eta1, r, counter)?);
        counter += 1;
    }
    let mut e1 = Vec::with_capacity(k);
    for _ in 0..k {
        e1.push(sample::sample_poly_cbd(parameters.eta2, r, counter)?);
        counter += 1;
    }
    let e2 = sample::sample_poly_cbd(parameters.eta2, r, counter)?;

    for poly in y.iter_mut() {
        poly.ntt();
    }

    // u = NTT^-1(A_hat^T * y_hat) + e1. The transpose is `a_hat[j][i]`.
    let mut u = Vec::with_capacity(k);
    for i in 0..k {
        let mut sum = Poly::zero();
        for (j, y_hat) in y.iter().enumerate() {
            sum = sum.add(&a_hat[j][i].multiply_ntt(y_hat));
        }
        sum.inverse_ntt();
        u.push(sum.add(&e1[i]));
    }

    // v = NTT^-1(t_hat^T * y_hat) + e2 + mu, where mu is the message with
    // each bit decompressed to 0 or round(q/2).
    let mut v = Poly::zero();
    for (t, y_hat) in t_hat.iter().zip(y.iter()) {
        v = v.add(&t.multiply_ntt(y_hat));
    }
    v.inverse_ntt();
    let mu = encode::byte_decode(message, 1)?.decompress_unchecked(1)?;
    let v = v.add(&e2).add(&mu);

    let mut ciphertext = Vec::with_capacity(parameters.ciphertext_len());
    for poly in &u {
        encode::byte_encode_unchecked(&poly.compress_unchecked(parameters.du)?,
                                      parameters.du, &mut ciphertext)?;
    }
    encode::byte_encode_unchecked(&v.compress_unchecked(parameters.dv)?,
                                  parameters.dv, &mut ciphertext)?;
    Ok(ciphertext)
}

/// FIPS 203 algorithm 15, `K-PKE.Decrypt`.
///
/// Recovers the 32 byte message. Never fails on a well-formed
/// ciphertext: a wrong or forged one decrypts to *some* message, and it is
/// the FO transform's re-encryption that notices - which is why this
/// returns bytes rather than a verdict.
fn kpke_decrypt(parameters: &'static Parameters, dk_pke: &[u8],
                ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let k = parameters.k;
    let (du, dv) = (parameters.du, parameters.dv);
    let split = 32 * du as usize * k;

    let mut u = encode::byte_decode_vector(&ciphertext[..split], du, k)?;
    for poly in u.iter_mut() {
        *poly = poly.decompress_unchecked(du)?;
        poly.ntt();
    }
    let v = encode::byte_decode(&ciphertext[split..], dv)?
        .decompress_unchecked(dv)?;
    let s_hat = encode::byte_decode_vector(dk_pke, 12, k)?;

    // w = v - NTT^-1(s_hat^T * NTT(u)).
    let mut inner = Poly::zero();
    for (s, u_hat) in s_hat.iter().zip(u.iter()) {
        inner = inner.add(&s.multiply_ntt(u_hat));
    }
    inner.inverse_ntt();
    let w = v.sub(&inner);

    let mut message = Vec::with_capacity(32);
    encode::byte_encode_unchecked(&w.compress_unchecked(1)?, 1, &mut message)?;
    Ok(message)
}

/// FIPS 203 algorithm 17, `ML-KEM.Encaps_internal`, with the input check
/// of section 7.2 in front of it.
///
/// Returns `(shared_secret, ciphertext)`. `m` is the 32 byte random input,
/// an argument here for the same reason the key generation seeds are:
/// it is what NIST's vectors state. `api::MlKemKey` is what draws it.
///
/// **The encapsulation key is checked before it is used** - its length,
/// and the modulus check that refuses a non-canonical encoding. That is
/// an `Err` rather than anything subtler because `ek` is public: refusing
/// it reveals nothing, and FIPS 203 requires the check.
pub fn encapsulate_internal(parameters: &'static Parameters, ek: &[u8],
                            m: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if m.len() != 32 {
        return Err(format!("ML-KEM.Encaps: m is {} bytes and should be 32.",
                           m.len()));
    }
    if !modulus_check(parameters, ek)? {
        return Err(format!(
            "{}: the encapsulation key fails FIPS 203's input check - it is \
             the wrong length, or a coefficient is encoded non-canonically. \
             Two different byte strings would then be the same key, which \
             the check exists to prevent.", parameters.name));
    }
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(m);
    seed.extend_from_slice(&h(ek)?);
    let (shared, r) = g(&seed)?;
    let ciphertext = kpke_encrypt(parameters, ek, m, &r)?;
    Ok((shared, ciphertext))
}

/// FIPS 203 algorithm 18, `ML-KEM.Decaps_internal`, with the input checks
/// of section 7.3 in front of it.
///
/// # This must not report a decryption failure, and it does not
///
/// The Fujisaki-Okamoto transform decrypts, re-encrypts what it got, and
/// compares the result with the ciphertext it was given. On a mismatch it
/// returns `J(z ‖ c)` - a pseudorandom secret derived from the ciphertext
/// and a secret seed `z` - rather than an error. A decapsulation that
/// returned `Err`, or behaved observably differently, on a mismatch would
/// be a decryption oracle: an attacker submits modified ciphertexts and
/// learns which ones decrypt to the same message.
///
/// So the comparison and the choice are **constant time**: the
/// ciphertexts are compared by folding every byte into one difference,
/// turned into a mask by `bignum::ct::mask_is_zero` (which is born opaque
/// to the optimiser), and the two candidate secrets are blended byte by
/// byte with `select`. Both candidates are always computed. There is no
/// branch on the result anywhere.
///
/// The `Result` is for the input checks only - a ciphertext or key of the
/// wrong length, or a decapsulation key whose embedded `H(ek)` does not
/// match its embedded `ek`. All of those are decided by public facts
/// before anything secret has been touched, and FIPS 203 requires them.
/// The cryptographic mismatch is `Ok`, always.
///
/// `scripts/ct_check.py` does not yet have a row for this. It should, and
/// `docs/pitfalls.md` lists it as owed.
pub fn decapsulate_internal(parameters: &'static Parameters, dk: &[u8],
                            ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use crate::bignum::ct::{mask_is_zero, select};

    let k = parameters.k;
    if ciphertext.len() != parameters.ciphertext_len() {
        return Err(format!("{}: the ciphertext is {} bytes and should be {}.",
                           parameters.name, ciphertext.len(),
                           parameters.ciphertext_len()));
    }
    if !hash_check(parameters, dk)? {
        return Err(format!(
            "{}: the decapsulation key fails FIPS 203's input check - it is \
             the wrong length, or the H(ek) it carries does not match the ek \
             it carries.", parameters.name));
    }
    let dk_pke = &dk[..384 * k];
    let ek = &dk[384 * k..768 * k + 32];
    let ek_hash = &dk[768 * k + 32..768 * k + 64];
    let z = &dk[768 * k + 64..768 * k + 96];

    let message = kpke_decrypt(parameters, dk_pke, ciphertext)?;
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(&message);
    seed.extend_from_slice(ek_hash);
    let (candidate, r) = g(&seed)?;
    let rejection = j(z, ciphertext)?;
    let again = kpke_encrypt(parameters, ek, &message, &r)?;

    // Fold every byte of the difference together, so the comparison takes
    // the same time wherever - or whether - the ciphertexts differ.
    let mut difference: u64 = 0;
    for (a, b) in ciphertext.iter().zip(again.iter()) {
        difference |= (a ^ b) as u64;
    }
    let equal = mask_is_zero(difference);

    let mut shared = Vec::with_capacity(32);
    for (good, fallback) in candidate.iter().zip(rejection.iter()) {
        shared.push(select(*good as u64, *fallback as u64, equal) as u8);
    }
    Ok(shared)
}

/// FIPS 203's **modulus check** on an encapsulation key.
///
/// `ByteDecode_12` then `ByteEncode_12` must give the bytes back. It can
/// only fail because a twelve bit field held a value at or above `q`,
/// which `ByteDecode_12` reduces - so this is a test for a non-canonical
/// encoding, and skipping it is a known malleability: two distinct byte
/// strings would be the same key.
///
/// See `encode.rs`'s note on why a decoder that did not reduce makes this
/// compare a value with itself and accept everything.
pub fn modulus_check(parameters: &'static Parameters, ek: &[u8])
        -> Result<bool, String> {
    if ek.len() != parameters.encapsulation_key_len() {
        // A wrong length is a failed check rather than an error: the
        // caller handed us something that is not a key for this parameter
        // set, and "no" is the answer to the question they asked.
        return Ok(false);
    }
    let packed = 384 * parameters.k;
    let decoded = encode::byte_decode_vector(&ek[..packed], 12, parameters.k)?;
    let again = encode::byte_encode_vector(&decoded, 12)?;
    Ok(again == ek[..packed])
}

/// FIPS 203's **hash check** on a decapsulation key.
///
/// `dk` carries `H(ek)` inside it, so a key whose embedded hash does not
/// match the embedded `ek` has been altered or assembled wrongly. This is
/// the other half of what ACVP's key-check groups test.
pub fn hash_check(parameters: &'static Parameters, dk: &[u8])
        -> Result<bool, String> {
    if dk.len() != parameters.decapsulation_key_len() {
        return Ok(false);
    }
    let k = parameters.k;
    let ek = &dk[384 * k..768 * k + 32];
    let embedded = &dk[768 * k + 32..768 * k + 64];
    Ok(h(ek)? == embedded)
}
