/*
SM2, the Chinese national public key algorithm. GB/T 32918.

Three things over one curve, and they share almost nothing with the
Western equivalents built on the same shape:

  * **Signature** (GB/T 32918.2), which is *not* ECDSA. Different
    equation, and the message digest is not a digest of the message -
    it is `SM3(Z_A || M)`, where `Z_A` binds the signer's identity and
    the whole curve into the hash before the message is seen.
  * **Public key encryption** (GB/T 32918.4), which is not ECIES: its
    own KDF, its own check value, and a ciphertext ordering that
    changed between the 2010 draft and the 2012 standard.
  * **Key exchange** (GB/T 32918.3), which is not ECDH.

All three are checked against OpenSSL 3.0, which implements SM2 - so
unlike the GOST work in this repository the reference here is somebody
else's code rather than a second reading of the standard.

## `Z_A` is the part that surprises people

    Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)
    e   = SM3(Z_A || M)

`ENTL_A` is the **bit** length of the identity as two big endian bytes,
not its byte length. `ID_A` is a user-chosen string; GB/T 32918.2 gives
`"1234567812345678"` as the default and that is what this module uses
when none is supplied.

Three consequences worth being clear about:

  * **A signature is over an identity as well as a message.** Verify
    with a different `ID_A` and a perfectly good signature fails, with
    no way to tell that from a forgery.
  * **The curve is inside the hash.** The same key and message over a
    different curve give a different `e`, which is a property ECDSA
    does not have.
  * **`e` is not a hash of the message**, so an API taking a
    pre-computed digest cannot express SM2. Everything here takes the
    message.

## OpenSSL's command line defaults to an *empty* identity

Measured, not assumed: `openssl pkeyutl -sign -rawin -digest sm3` with
no `-pkeyopt distid:` produces a signature that verifies only against an
empty `ID_A`, and fails against the standard's default. So a signature
made by the CLI and verified by a library that follows GB/T - or the
reverse - fails for a reason that looks like key mismatch.

This module follows the *standard*, because that is what a Chinese
device will do. `pytests/test_sm2.py` passes `distid:` explicitly in
both directions rather than relying on either default, and one test
asserts the two identities disagree so the trap stays documented.

## The nonce

SM2's signing equation leaks the private key from two signatures made
with the same `k`, exactly as ECDSA's does - `s = (1+d)^-1 (k - r d)`
with `k` known gives `d` in one step. `ecdsa.rs` says nothing here
generates nonces and this module keeps that: `sign` derives `k` through
RFC 6979 with SM3.

**That is an adaptation, not a standard.** GB/T 32918.2 says only that
`k` is a random number in `[1, n-1]`; RFC 6979 is not part of SM2, and a
signature from this module will not equal one from a Chinese
implementation given the same inputs. It does not have to: SM2
signatures are checked by verifying, and `sign_with_nonce` exists so the
standard's own worked example can be reproduced exactly.
*/

use super::{Curve, Point, Signature};
use crate::bignum::BigUint;
use crate::ec::ecdsa::NonceGenerator;
use crate::hash_functions::sm3::Sm3;
use crate::hash_functions::HashFunction;

/// GB/T 32918.2's default distinguishing identifier. Not OpenSSL's
/// command line default, which is empty - see the module comment.
pub const DEFAULT_ID: &[u8] = b"1234567812345678";

fn sm3_of(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = Sm3::new(&[]);
    for part in parts {
        hash.update(part);
    }
    hash.digest()
}

/// `Z_A`, GB/T 32918.2 section 5.5: the identity and the curve, hashed
/// before the message is involved at all.
///
/// Fails if the identity is longer than 8191 bytes, because `ENTL` is
/// its length **in bits** in two bytes and a longer one cannot be
/// represented. Truncating instead would make two identities sign
/// alike.
pub fn z_value(curve: &Curve, id: &[u8], public: &Point) -> Result<Vec<u8>, String> {
    let bits = id
        .len()
        .checked_mul(8)
        .filter(|bits| *bits <= u16::MAX as usize)
        .ok_or_else(|| {
            format!(
                "An SM2 identity is at most {} bytes, because ENTL is its \
                 length in bits in two bytes; this one is {}.",
                u16::MAX / 8,
                id.len()
            )
        })?;

    let width = curve.field_bytes();
    let (x, y) = match (public.x(), public.y()) {
        (Some(x), Some(y)) => (x, y),
        _ => return Err("The identity point has no Z value.".to_string()),
    };

    let entl = (bits as u16).to_be_bytes();
    let a = curve.a.to_bytes_be_padded(width)?;
    let b = curve.b.to_bytes_be_padded(width)?;
    let gx = curve.g.x().ok_or("The curve's generator is the identity.")?
        .to_bytes_be_padded(width)?;
    let gy = curve.g.y().ok_or("The curve's generator is the identity.")?
        .to_bytes_be_padded(width)?;
    let px = x.to_bytes_be_padded(width)?;
    let py = y.to_bytes_be_padded(width)?;

    Ok(sm3_of(&[&entl, id, &a, &b, &gx, &gy, &px, &py]))
}

/// `e = SM3(Z_A || M)`, the value the signature equation actually uses.
///
/// Exposed because it is the one intermediate the standard's examples
/// state, so a test can check it without a signature - and because a
/// caller streaming a large message wants to build it themselves.
pub fn message_digest(curve: &Curve, id: &[u8], public: &Point, message: &[u8])
                      -> Result<Vec<u8>, String> {
    let z = z_value(curve, id, public)?;
    Ok(sm3_of(&[&z, message]))
}

/// The private key is in `[1, n-2]`, not `[1, n-1]`.
///
/// `d = n-1` makes `(1 + d) = 0 mod n`, which has no inverse, so the
/// signing equation cannot be evaluated at all. It is a permanent
/// property of the key rather than of a nonce, which is why it is
/// checked here once rather than inside the retry loop: `sign` retries
/// on any error from `sign_with_nonce`, and a permanent error retried
/// 256 times is reported as a broken nonce generator.
fn check_private(curve: &Curve, private: &BigUint) -> Result<(), String> {
    if private.is_zero() || *private >= curve.n {
        return Err("The SM2 private key must be in [1, n-1].".to_string());
    }
    if private.add(&BigUint::one()) == curve.n {
        return Err("The SM2 private key must not be n-1: (1 + d) is not \
                    invertible modulo n, so no signature exists.".to_string());
    }
    Ok(())
}

/// Sign with an explicit `k`. The standard's worked examples fix `k`,
/// so this is how they are reproduced; it is also the only way to
/// produce a wrong signature on purpose.
///
/// **A caller that passes a `k` it did not choose uniformly, or passes
/// one twice, gives away the private key.** `sign` is the one to use.
pub fn sign_with_nonce(curve: &Curve, private: &BigUint, id: &[u8],
                       message: &[u8], k: &BigUint) -> Result<Signature, String> {
    check_private(curve, private)?;
    let one = BigUint::one();
    if k.is_zero() || *k >= curve.n {
        return Err("The SM2 nonce must be in [1, n-1].".to_string());
    }

    // **Not `generator_mul`, which is for public scalars.** `Z_A` needs
    // the public key, so signing derives it - and deriving it the
    // obvious way ran a variable-time multiplication on the private key
    // once per signature, when `generator_mul` was double-and-add. The ctgrind row caught this after
    // the nonce had already been moved to the ladder, which is the
    // usual shape: the fix to the loud problem leaves the quiet one.
    let public = curve.scalar_mul_secret(&curve.g, private)?;
    let e = BigUint::from_bytes_be(&message_digest(curve, id, &public, message)?);

    // **The constant-time path.** `k` is the nonce, and the signing
    // equation gives up `d` to anyone who learns it:
    // `s = (1+d)^-1 (k - r d)` solves for `d` in one step. `scalar_mul`
    // is for a public scalar; this is not one.
    // Same rule as `ecdsa::sign`, which this was written without.
    let point = curve.scalar_mul_secret(&curve.g, k)?;
    let x1 = point.x().ok_or("k*G is the identity.")?;

    // r = (e + x1) mod n
    let r = e.mod_add(x1, &curve.n)?;
    if r.is_zero() || r.add(k) == curve.n {
        return Err("This nonce is excluded by GB/T 32918.2 6.1 step 4; \
                    sign() retries, sign_with_nonce cannot.".to_string());
    }

    // s = ((1 + d)^-1 * (k - r*d)) mod n.
    //
    // **Not ECDSA's equation.** There is no inversion of a per-signature
    // value here - the inverse is of (1 + d), which is a property of the
    // key - and the subtraction is modular, so `k - r*d` is computed with
    // mod_sub rather than by hoping it stays positive.
    let inv = private.add(&one).rem(&curve.n)?.mod_inverse(&curve.n)?;
    let rd = r.mod_mul(private, &curve.n)?;
    let s = inv.mod_mul(&k.mod_sub(&rd, &curve.n)?, &curve.n)?;
    if s.is_zero() {
        return Err("This nonce gives s = 0 and is excluded by GB/T \
                    32918.2 6.1 step 5.".to_string());
    }

    Ok(Signature { r, s })
}

/// Sign a message. The nonce is derived from the key and the message
/// through RFC 6979 with SM3, so this never touches the random source
/// and the same inputs always give the same signature.
pub fn sign(curve: &Curve, private: &BigUint, id: &[u8], message: &[u8])
            -> Result<Signature, String> {
    check_private(curve, private)?;
    let public = curve.scalar_mul_secret(&curve.g, private)?;
    let e = message_digest(curve, id, &public, message)?;

    let mut nonces = NonceGenerator::new(Sm3::new(&[]), private, &e, &curve.n)?;
    // GB/T 32918.2 excludes two values of k per signature. Both are
    // vanishingly rare and both are reachable, so the loop is real
    // rather than decorative; the bound is the same shape as RFC 6979's
    // own rejection loop in `ecdsa.rs`.
    for _ in 0..256 {
        let k = nonces.next();
        if k.is_zero() || k >= curve.n {
            continue;
        }
        match sign_with_nonce(curve, private, id, message, &k) {
            Ok(signature) => return Ok(signature),
            Err(_) => continue,
        }
    }
    Err("RFC 6979 produced 256 nonces that SM2 excludes, which does not \
         happen; something is wrong with the generator.".to_string())
}

/// Verify a signature. `public` is the signer's key and `id` must be
/// the identity they signed under - a mismatch is indistinguishable
/// from a forgery, by design.
pub fn verify(curve: &Curve, public: &Point, id: &[u8], message: &[u8],
              signature: &Signature) -> Result<bool, String> {
    curve.validate(public)?;

    // r and s in [1, n-1]. A zero or out-of-range value is not a
    // signature; the same check ecdsa.rs makes, for the same reason.
    //
    // **What it actually stops is malleability, and only on one side.**
    // Offering `s + n` gives the same `t` and the same `s*G` - `n*G` is
    // the identity - so without this check a second, different byte
    // string verifies for a signature somebody else made. Offering
    // `r + n` does not, because `r` is compared against a value already
    // reduced mod n and simply fails. The breakage sweep found the
    // difference: removing this check left every test passing, because
    // every case offered until then failed for the other reason.
    // `test_a_signature_with_n_added_to_s_is_refused` covers it now.
    if signature.r.is_zero() || signature.r >= curve.n
        || signature.s.is_zero() || signature.s >= curve.n
    {
        return Ok(false);
    }

    let e = BigUint::from_bytes_be(&message_digest(curve, id, public, message)?);

    // t = (r + s) mod n, and t = 0 is refused: with t = 0 the check
    // reduces to `s*G` alone and the public key drops out of the
    // equation entirely.
    //
    // **A breakage sweep cannot isolate this one.** Removing it leaves
    // every test passing, because reaching *acceptance* through the
    // opened branch needs a message whose `e` takes a chosen value - an
    // SM3 preimage. So it is defence in depth rather than a hole, the
    // same standing as `ec::ct::Field::add`'s redundant P = -P arm, and
    // it is kept with this comment for the same reason: the sweep
    // cannot tell "untested" from "not reachable".
    let t = signature.r.mod_add(&signature.s, &curve.n)?;
    if t.is_zero() {
        return Ok(false);
    }

    let point = curve.add(&curve.scalar_mul(&curve.g, &signature.s),
                          &curve.scalar_mul(public, &t));
    let x1 = match point.x() {
        Some(x) => x,
        None => return Ok(false),
    };
    Ok(e.mod_add(x1, &curve.n)? == signature.r)
}

// ------------------------------------------------------------- encryption ---

/// The KDF of GB/T 32918.4 section 5.4.3: SM3 over the shared value and
/// a 32 bit big endian counter **starting at 1**, concatenated and cut
/// to length.
///
/// Starting the counter at 0 produces a keystream that is perfectly
/// usable and wrong, and it round-trips against itself - so nothing but
/// a foreign ciphertext can see it.
pub fn kdf(shared: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut counter: u32 = 1;
    while out.len() < length {
        out.extend_from_slice(&sm3_of(&[shared, &counter.to_be_bytes()]));
        counter += 1;
    }
    out.truncate(length);
    out
}

/// True when every byte is zero.
///
/// A named function rather than an inline `all`, because the branch
/// that uses it cannot be reached on purpose: finding a nonce whose KDF
/// output is all zeros is a 2^-8n event. Removing the check entirely
/// leaves every test passing, so the *decision* is tested here instead
/// of the branch - the same move `bignum::ct::bytes_differ` needs, and
/// for the same reason.
fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Encrypt with an explicit `k`, for reproducing the standard's worked
/// example. `encrypt` is the one to use.
pub fn encrypt_with_nonce(curve: &Curve, public: &Point, message: &[u8],
                          k: &BigUint) -> Result<Vec<u8>, String> {
    curve.validate(public)?;
    if message.is_empty() {
        return Err("SM2 encrypts at least one byte: an empty message makes \
                    the KDF output empty, which the all-zero check below \
                    cannot distinguish from failure.".to_string());
    }
    if k.is_zero() || *k >= curve.n {
        return Err("The SM2 nonce must be in [1, n-1].".to_string());
    }

    // Both multiplications are by the secret nonce, so both take the
    // ladder. Learning `k` here gives up the whole plaintext: the KDF
    // input is `k*P`, which anyone with `k` and `P` can recompute.
    let c1 = curve.scalar_mul_secret(&curve.g, k)?;
    let shared = curve.scalar_mul_secret(public, k)?;
    let (x2, y2) = match (shared.x(), shared.y()) {
        (Some(x), Some(y)) => (x, y),
        _ => return Err("k*P is the identity.".to_string()),
    };

    let width = curve.field_bytes();
    let mut material = x2.to_bytes_be_padded(width)?;
    material.extend_from_slice(&y2.to_bytes_be_padded(width)?);

    let t = kdf(&material, message.len());
    // GB/T 32918.4 6.1 step A5: an all-zero KDF output must be rejected,
    // because C2 would then be the plaintext.
    if all_zero(&t) {
        return Err("The KDF produced an all-zero key for this nonce; \
                    encrypt() retries, encrypt_with_nonce cannot.".to_string());
    }

    let c2: Vec<u8> = message.iter().zip(&t).map(|(m, k)| m ^ k).collect();
    // C3 = SM3(x2 || M || y2). The plaintext is in the *middle*: a
    // check value computed over x2 || y2 || M is self-consistent and
    // rejects every foreign ciphertext.
    let c3 = sm3_of(&[&x2.to_bytes_be_padded(width)?, message,
                      &y2.to_bytes_be_padded(width)?]);

    let mut out = curve.encode_point(&c1, false)?;
    out.extend_from_slice(&c3);
    out.extend_from_slice(&c2);
    Ok(out)
}

/// Encrypt. Returns `C1 || C3 || C2` - the **2012** ordering; see
/// `ciphertext_to_der` for the shape OpenSSL exchanges.
///
/// The nonce is derived from the key, the public key and the message
/// through RFC 6979 with SM3, so this never touches the random source.
/// The consequence is that encrypting the same message to the same key
/// twice gives the same ciphertext, which for a KEM-shaped scheme is a
/// property worth stating rather than hiding: it is deterministic
/// encryption, and two equal ciphertexts mean two equal plaintexts.
pub fn encrypt(curve: &Curve, public: &Point, message: &[u8]) -> Result<Vec<u8>, String> {
    curve.validate(public)?;
    let width = curve.field_bytes();
    let px = public.x().ok_or("The identity is not a public key.")?
        .to_bytes_be_padded(width)?;
    let seed = sm3_of(&[&px, message]);
    // The "private key" fed to RFC 6979 here is the recipient's public
    // x coordinate, which is public - so this is a deterministic
    // expansion rather than a secret-keyed one. That is the honest
    // description; see the note above about what determinism means here.
    let scalar = BigUint::from_bytes_be(&px).rem(&curve.n)?;

    let mut nonces = NonceGenerator::new(Sm3::new(&[]), &scalar, &seed, &curve.n)?;
    for _ in 0..256 {
        let k = nonces.next();
        if k.is_zero() || k >= curve.n {
            continue;
        }
        match encrypt_with_nonce(curve, public, message, &k) {
            Ok(ciphertext) => return Ok(ciphertext),
            Err(_) => continue,
        }
    }
    Err("256 nonces in a row were excluded, which does not happen.".to_string())
}

/// Decrypt `C1 || C3 || C2`.
pub fn decrypt(curve: &Curve, private: &BigUint, ciphertext: &[u8])
               -> Result<Vec<u8>, String> {
    if private.is_zero() || *private >= curve.n {
        return Err("The SM2 private key must be in [1, n-1].".to_string());
    }
    let width = curve.field_bytes();
    let point_len = 1 + 2 * width;
    if ciphertext.len() <= point_len + 32 {
        return Err(format!(
            "An SM2 ciphertext is a {} byte point, a 32 byte check value and \
             at least one byte of message; this one is {} bytes.",
            point_len,
            ciphertext.len()
        ));
    }

    // `decode_point` validates: on the curve, in range, not the
    // identity. A C1 that is not a point is the invalid-curve attack
    // and must not reach the multiplication below.
    let c1 = curve.decode_point(&ciphertext[..point_len])?;
    let c3 = &ciphertext[point_len..point_len + 32];
    let c2 = &ciphertext[point_len + 32..];

    let shared = curve.scalar_mul_secret(&c1, private)?;
    let (x2, y2) = match (shared.x(), shared.y()) {
        (Some(x), Some(y)) => (x, y),
        _ => return Err("d*C1 is the identity.".to_string()),
    };

    let mut material = x2.to_bytes_be_padded(width)?;
    material.extend_from_slice(&y2.to_bytes_be_padded(width)?);

    let t = kdf(&material, c2.len());
    if all_zero(&t) {
        return Err("The KDF produced an all-zero key, which GB/T 32918.4 \
                    7.1 requires be rejected.".to_string());
    }

    let message: Vec<u8> = c2.iter().zip(&t).map(|(c, k)| c ^ k).collect();
    let expected = sm3_of(&[&x2.to_bytes_be_padded(width)?, &message,
                            &y2.to_bytes_be_padded(width)?]);

    // Constant time, and over the whole value. This is the only thing
    // standing between a caller and a chosen-ciphertext oracle, and a
    // comparison that stops at the first differing byte is a timing
    // signal about a value the attacker is choosing.
    if crate::bignum::ct::bytes_differ(&expected, c3) {
        return Err("The SM2 check value C3 does not match; the ciphertext \
                    was altered or was not for this key.".to_string());
    }
    Ok(message)
}

// ------------------------------------------------------------ interchange ---

/// The DER form OpenSSL exchanges: `SEQUENCE { INTEGER r, INTEGER s }`.
pub fn signature_to_der(signature: &Signature) -> Vec<u8> {
    let mut writer = crate::asn1::Writer::new();
    writer.write_sequence(|seq| {
        seq.write_integer(&signature.r);
        seq.write_integer(&signature.s);
    });
    writer.finish()
}

pub fn signature_from_der(der: &[u8]) -> Result<Signature, String> {
    let mut reader = crate::asn1::Reader::new(der);
    let mut seq = reader.read_sequence()?;
    let r = seq.read_integer()?;
    let s = seq.read_integer()?;
    seq.finish()?;
    reader.finish()?;
    Ok(Signature { r, s })
}

/// `C1 || C3 || C2` to the DER OpenSSL uses:
/// `SEQUENCE { INTEGER x1, INTEGER y1, OCTET STRING C3, OCTET STRING C2 }`.
///
/// **The two orderings are the trap.** The 2010 draft put `C2` before
/// `C3` and a good deal of deployed Chinese software still does; the
/// 2012 standard and this module put `C3` first. The DER form is
/// unambiguous because the fields are named, which is why it is the one
/// to exchange with.
pub fn ciphertext_to_der(curve: &Curve, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let width = curve.field_bytes();
    let point_len = 1 + 2 * width;
    if ciphertext.len() <= point_len + 32 {
        return Err("Ciphertext too short to be SM2.".to_string());
    }
    let point = curve.decode_point(&ciphertext[..point_len])?;
    let x = point.x().ok_or("C1 is the identity.")?;
    let y = point.y().ok_or("C1 is the identity.")?;

    let mut writer = crate::asn1::Writer::new();
    writer.write_sequence(|seq| {
        seq.write_integer(x);
        seq.write_integer(y);
        seq.write_octet_string(&ciphertext[point_len..point_len + 32]);
        seq.write_octet_string(&ciphertext[point_len + 32..]);
    });
    Ok(writer.finish())
}

pub fn ciphertext_from_der(curve: &Curve, der: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = crate::asn1::Reader::new(der);
    let mut seq = reader.read_sequence()?;
    let x = seq.read_integer()?;
    let y = seq.read_integer()?;
    let c3 = seq.read_octet_string()?.to_vec();
    let c2 = seq.read_octet_string()?.to_vec();
    seq.finish()?;
    reader.finish()?;

    if c3.len() != 32 {
        return Err(format!("An SM2 check value is 32 bytes, not {}.", c3.len()));
    }
    let point = Point::new(x, y);
    curve.validate(&point)?;

    let mut out = curve.encode_point(&point, false)?;
    out.extend_from_slice(&c3);
    out.extend_from_slice(&c2);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves;

    /// The same vendored draft `sm3.rs` reads. Appendix B.1 and B.2 are
    /// GB/T 32918.2 A.2's `Z_A` and `e` - the two intermediates of a
    /// real SM2 signature, stated by the standard. Nothing is typed.
    const DRAFT: &str = include_str!("../../rfcs/draft-sca-cfrg-sm3-02.txt");

    fn heading(needle: &str) -> usize {
        let at = DRAFT.find(&format!("\n{needle}")).unwrap_or_else(|| panic!("no {needle}"));
        at + 1
    }

    fn unhex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    /// One `B.n` section's Input and Output blocks.
    fn example(section: &str) -> (Vec<u8>, Vec<u8>) {
        let start = heading(section);
        let body = &DRAFT[start..];
        let end = body[1..].find("\nB.").map(|at| at + 1).unwrap_or(body.len());
        let body = &body[..end];

        let mut input = String::new();
        let mut output = String::new();
        let mut collecting: Option<&str> = None;
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed == "Input:" {
                collecting = Some("input");
                continue;
            }
            if trimmed == "Output:" {
                collecting = Some("output");
                continue;
            }
            let is_hex = line.starts_with(' ')
                && !line.starts_with("   ")
                && !trimmed.is_empty()
                && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == ' ');
            if is_hex {
                match collecting {
                    Some("input") => input.push_str(trimmed),
                    Some("output") => output.push_str(trimmed),
                    _ => {}
                }
            } else if !trimmed.is_empty() && collecting == Some("output")
                && !output.is_empty()
            {
                break;
            }
        }
        assert!(!input.is_empty(), "{section} parsed with an empty input");
        assert!(!output.is_empty(), "{section} parsed with an empty output");
        (unhex(&input), unhex(&output))
    }

    /// GB/T 32918.2 A.2's `Z_A`, computed rather than looked up. The
    /// draft states the concatenated input and the result; this builds
    /// the same input out of the curve and the key and checks both.
    #[test]
    fn test_the_standards_own_z_value() {
        let (input, expected) = example("B.1.");
        assert_eq!(expected.len(), 32);

        // The input is ENTL || ID || a || b || xG || yG || xA || yA.
        // Everything after the identity is 32 bytes wide, so the
        // identity's length falls out of ENTL - which is the field this
        // test is really about.
        let entl = u16::from_be_bytes([input[0], input[1]]) as usize;
        assert_eq!(entl % 8, 0, "ENTL is a bit count and should be whole bytes here");
        let id = &input[2..2 + entl / 8];
        assert_eq!(id, b"ALICE123@YAHOO.COM");
        assert_eq!(input.len(), 2 + id.len() + 6 * 32);

        // The public key is the last 64 bytes of that input.
        let x = BigUint::from_bytes_be(&input[input.len() - 64..input.len() - 32]);
        let y = BigUint::from_bytes_be(&input[input.len() - 32..]);
        let public = Point::new(x, y);

        // **The example is over GB/T 32918.2 A.2's own curve, not
        // sm2p256v1.** The standard works two examples, one on each,
        // and taking the parameters from this input rather than from
        // `curves::sm2()` is what makes that visible.
        let curve = Curve {
            name: "GB/T 32918.2 A.2 example",
            p: BigUint::from_bytes_be(&input[2 + id.len()..2 + id.len() + 32])
                .add(&BigUint::from_u64(3)),
            a: BigUint::from_bytes_be(&input[2 + id.len()..2 + id.len() + 32]),
            b: BigUint::from_bytes_be(&input[2 + id.len() + 32..2 + id.len() + 64]),
            g: Point::new(
                BigUint::from_bytes_be(&input[2 + id.len() + 64..2 + id.len() + 96]),
                BigUint::from_bytes_be(&input[2 + id.len() + 96..2 + id.len() + 128]),
            ),
            n: BigUint::one(),
            h: BigUint::one(),
        };

        let z = z_value(&curve, id, &public).unwrap();
        assert_eq!(z, expected, "Z_A for GB/T 32918.2 A.2");

        // And B.2 is e = SM3(Z_A || "message digest") for the same
        // example, which pins the second hash as well as the first.
        let (e_input, e_expected) = example("B.2.");
        assert_eq!(&e_input[..32], &z[..], "B.2's input should begin with B.1's output");
        assert_eq!(&e_input[32..], b"message digest");
        // Through `message_digest` rather than by rebuilding the hash
        // here. Written the other way this test still passed with
        // `e = SM3(M || Z_A)`, because it never called the function
        // under test - the sweep caught that and no Rust test did.
        assert_eq!(message_digest(&curve, id, &public, b"message digest").unwrap(),
                   e_expected);
    }

    #[test]
    fn test_entl_is_a_bit_count_not_a_byte_count() {
        let curve = curves::sm2();
        let public = curve.generator_mul(&BigUint::from_u64(7));
        // A 16 byte identity must put 0x0080 in front, not 0x0010.
        let z = z_value(&curve, DEFAULT_ID, &public).unwrap();
        let mut hand = vec![0x00u8, 0x80];
        hand.extend_from_slice(DEFAULT_ID);
        let width = curve.field_bytes();
        for value in [&curve.a, &curve.b] {
            hand.extend_from_slice(&value.to_bytes_be_padded(width).unwrap());
        }
        for value in [curve.g.x().unwrap(), curve.g.y().unwrap(),
                      public.x().unwrap(), public.y().unwrap()] {
            hand.extend_from_slice(&value.to_bytes_be_padded(width).unwrap());
        }
        assert_eq!(z, sm3_of(&[&hand]));
    }

    #[test]
    fn test_an_identity_too_long_for_entl_is_refused() {
        let curve = curves::sm2();
        let public = curve.generator_mul(&BigUint::from_u64(3));
        let long = vec![b'a'; 8192];
        let error = z_value(&curve, &long, &public).unwrap_err();
        assert!(error.contains("ENTL"), "{error}");
        // One byte under the limit still works, so the boundary is where
        // it is claimed to be rather than somewhere nearby.
        assert!(z_value(&curve, &long[..8191], &public).is_ok());
    }

    #[test]
    fn test_sign_and_verify_round_trip() {
        let curve = curves::sm2();
        let d = BigUint::from_hex(
            "128b2fa8bd433c6c068c8d803dff79792a519a55171b1b650c23661d15897263").unwrap();
        let public = curve.generator_mul(&d);
        let message = b"message digest";

        let signature = sign(&curve, &d, DEFAULT_ID, message).unwrap();
        assert!(verify(&curve, &public, DEFAULT_ID, message, &signature).unwrap());
    }

    /// Deterministic, so the signature is its own vector - the same
    /// property `ecdsa.rs` relies on.
    #[test]
    fn test_signing_is_deterministic() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(0x1234_5678);
        let a = sign(&curve, &d, DEFAULT_ID, b"abc").unwrap();
        let b = sign(&curve, &d, DEFAULT_ID, b"abc").unwrap();
        assert_eq!(a.r, b.r);
        assert_eq!(a.s, b.s);
        assert_ne!(sign(&curve, &d, DEFAULT_ID, b"abd").unwrap().r, a.r);
    }

    /// The identity is inside the hash, so it is inside the signature.
    #[test]
    fn test_a_different_identity_does_not_verify() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(99);
        let public = curve.generator_mul(&d);
        let signature = sign(&curve, &d, DEFAULT_ID, b"hello").unwrap();
        assert!(verify(&curve, &public, DEFAULT_ID, b"hello", &signature).unwrap());
        assert!(!verify(&curve, &public, b"", b"hello", &signature).unwrap());
        assert!(!verify(&curve, &public, b"1234567812345679", b"hello", &signature).unwrap());
    }

    #[test]
    fn test_altering_anything_breaks_the_signature() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(0xfeed);
        let public = curve.generator_mul(&d);
        let signature = sign(&curve, &d, DEFAULT_ID, b"the message").unwrap();

        assert!(!verify(&curve, &public, DEFAULT_ID, b"the messagf", &signature).unwrap());

        let bumped = Signature { r: signature.r.add(&BigUint::one()), s: signature.s.clone() };
        assert!(!verify(&curve, &public, DEFAULT_ID, b"the message", &bumped).unwrap());
        let bumped = Signature { r: signature.r.clone(), s: signature.s.add(&BigUint::one()) };
        assert!(!verify(&curve, &public, DEFAULT_ID, b"the message", &bumped).unwrap());

        let other = curve.generator_mul(&BigUint::from_u64(0xbeef));
        assert!(!verify(&curve, &other, DEFAULT_ID, b"the message", &signature).unwrap());
    }

    /// Out-of-range `r` or `s` is refused rather than reduced. This is
    /// unreachable from any honest signature, so it needs its own test.
    #[test]
    fn test_out_of_range_components_are_refused() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(5);
        let public = curve.generator_mul(&d);
        let good = sign(&curve, &d, DEFAULT_ID, b"x").unwrap();

        for bad in [
            Signature { r: BigUint::zero(), s: good.s.clone() },
            Signature { r: good.r.clone(), s: BigUint::zero() },
            Signature { r: curve.n.clone(), s: good.s.clone() },
            Signature { r: good.r.clone(), s: curve.n.clone() },
            Signature { r: curve.n.add(&BigUint::one()), s: good.s.clone() },
        ] {
            assert!(!verify(&curve, &public, DEFAULT_ID, b"x", &bad).unwrap());
        }
    }

    /// `s + n` is the same scalar and a different byte string, so a
    /// signature is malleable unless `s < n` is enforced. This is the
    /// test the range check needed: the sweep removed that check and
    /// nothing failed, because every case offered until then failed for
    /// a second reason as well.
    ///
    /// `r + n` is asserted too, and it is refused by the final
    /// comparison rather than by the range check - which is exactly why
    /// it could not stand in for this.
    #[test]
    fn test_a_signature_with_n_added_to_s_is_refused() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(0x9f9f);
        let public = curve.generator_mul(&d);
        let message = b"malleable?";
        let good = sign(&curve, &d, DEFAULT_ID, message).unwrap();
        assert!(verify(&curve, &public, DEFAULT_ID, message, &good).unwrap());

        let slid = Signature { r: good.r.clone(), s: good.s.add(&curve.n) };
        assert_ne!(slid.s, good.s);
        assert_eq!(curve.scalar_mul(&curve.g, &slid.s),
                   curve.scalar_mul(&curve.g, &good.s),
                   "s + n must be the same scalar, or this tests nothing");
        assert!(!verify(&curve, &public, DEFAULT_ID, message, &slid).unwrap());

        let slid = Signature { r: good.r.add(&curve.n), s: good.s.clone() };
        assert!(!verify(&curve, &public, DEFAULT_ID, message, &slid).unwrap());
    }

    /// `t = (r + s) mod n == 0` is refused. **This test passes whether
    /// or not the check is there**, and says so rather than pretending
    /// otherwise: producing a signature the missing check would let
    /// through needs a message whose `e` takes a chosen value. The
    /// branch is defence in depth and the sweep cannot isolate it;
    /// deleting a check nothing can exercise is how a public key drops
    /// out of a verification.
    #[test]
    fn test_a_zero_t_is_refused() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(11);
        let public = curve.generator_mul(&d);
        let r = BigUint::from_u64(12345);
        let s = curve.n.sub(&r).unwrap();
        assert!(r.mod_add(&s, &curve.n).unwrap().is_zero());
        assert!(!verify(&curve, &public, DEFAULT_ID, b"anything",
                        &Signature { r, s }).unwrap());
    }

    #[test]
    fn test_a_private_key_of_n_minus_one_is_refused() {
        let curve = curves::sm2();
        let d = curve.n.sub(&BigUint::one()).unwrap();
        let error = sign(&curve, &d, DEFAULT_ID, b"x").unwrap_err();
        assert!(error.contains("invertible") || error.contains("n-1"), "{error}");
    }

    #[test]
    fn test_encrypt_and_decrypt_round_trip() {
        let curve = curves::sm2();
        let d = BigUint::from_hex(
            "1649ab77a00637bd5e2efe283fbf353534aa7f7cb89463f208ddbc2920bb0da0").unwrap();
        let public = curve.generator_mul(&d);
        for length in [1usize, 2, 15, 16, 31, 32, 33, 64, 100, 1000] {
            let message: Vec<u8> = (0..length).map(|i| (i * 7 + 1) as u8).collect();
            let ciphertext = encrypt(&curve, &public, &message).unwrap();
            assert_eq!(ciphertext.len(), 65 + 32 + length);
            assert_eq!(decrypt(&curve, &d, &ciphertext).unwrap(), message);
        }
    }

    #[test]
    fn test_altering_a_ciphertext_is_refused() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(0x5151);
        let public = curve.generator_mul(&d);
        let message = b"sixteen byte msg";
        let ciphertext = encrypt(&curve, &public, message).unwrap();

        let mut refused = 0;
        for index in 0..ciphertext.len() {
            let mut altered = ciphertext.clone();
            altered[index] ^= 0x01;
            if decrypt(&curve, &d, &altered).is_err() {
                refused += 1;
            }
        }
        assert_eq!(refused, ciphertext.len(),
                   "every single-bit change must be refused");
    }

    /// C3 covers `x2 || M || y2`, with the message in the middle. A
    /// check value over `x2 || y2 || M` is self-consistent, so only a
    /// foreign ciphertext or this test can see the difference.
    #[test]
    fn test_the_check_value_puts_the_message_between_the_coordinates() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(7);
        let public = curve.generator_mul(&d);
        let message = b"abc";
        let ciphertext = encrypt(&curve, &public, message).unwrap();

        let c1 = curve.decode_point(&ciphertext[..65]).unwrap();
        let shared = curve.scalar_mul(&c1, &d);
        let width = curve.field_bytes();
        let x2 = shared.x().unwrap().to_bytes_be_padded(width).unwrap();
        let y2 = shared.y().unwrap().to_bytes_be_padded(width).unwrap();

        assert_eq!(&ciphertext[65..97], &sm3_of(&[&x2, message, &y2])[..]);
        assert_ne!(&ciphertext[65..97], &sm3_of(&[&x2, &y2, message])[..]);
    }

    /// The KDF counter starts at 1. Starting it at 0 gives a different
    /// keystream that still round-trips, so this is asserted directly.
    #[test]
    fn test_the_kdf_counter_starts_at_one() {
        let shared = b"shared value";
        assert_eq!(&kdf(shared, 32), &sm3_of(&[shared, &1u32.to_be_bytes()]));
        assert_ne!(&kdf(shared, 32), &sm3_of(&[shared, &0u32.to_be_bytes()]));
        // And it carries across blocks rather than restarting.
        let long = kdf(shared, 64);
        assert_eq!(&long[32..], &sm3_of(&[shared, &2u32.to_be_bytes()])[..]);
        assert_eq!(&long[..32], &kdf(shared, 32)[..]);
        // A length that is not a multiple of 32 is cut, not padded.
        assert_eq!(kdf(shared, 40).len(), 40);
        assert_eq!(&kdf(shared, 40)[..32], &kdf(shared, 32)[..]);
    }

    #[test]
    fn test_a_ciphertext_whose_c1_is_not_on_the_curve_is_refused() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(3);
        let public = curve.generator_mul(&d);
        let mut ciphertext = encrypt(&curve, &public, b"hello").unwrap();
        // Move C1 off the curve without changing its length. This is the
        // invalid-curve attack; it must be refused before d is used.
        ciphertext[1] ^= 0xff;
        let error = decrypt(&curve, &d, &ciphertext).unwrap_err();
        assert!(!error.contains("check value"),
                "a point off the curve should be refused as a point, not \
                 reach the check value: {error}");
    }

    #[test]
    fn test_short_ciphertexts_are_refused_rather_than_panicking() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(3);
        let public = curve.generator_mul(&d);
        let ciphertext = encrypt(&curve, &public, b"hello").unwrap();
        for cut in 0..ciphertext.len() {
            assert!(decrypt(&curve, &d, &ciphertext[..cut]).is_err(),
                    "accepted a {cut} byte ciphertext");
        }
    }

    #[test]
    fn test_der_round_trips() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(0x2024);
        let public = curve.generator_mul(&d);

        let signature = sign(&curve, &d, DEFAULT_ID, b"der").unwrap();
        let der = signature_to_der(&signature);
        let back = signature_from_der(&der).unwrap();
        assert_eq!(back.r, signature.r);
        assert_eq!(back.s, signature.s);

        let ciphertext = encrypt(&curve, &public, b"der ciphertext").unwrap();
        let der = ciphertext_to_der(&curve, &ciphertext).unwrap();
        assert_eq!(ciphertext_from_der(&curve, &der).unwrap(), ciphertext);
    }

    #[test]
    fn test_trailing_bytes_after_der_are_refused() {
        let curve = curves::sm2();
        let d = BigUint::from_u64(17);
        let signature = sign(&curve, &d, DEFAULT_ID, b"x").unwrap();
        let mut der = signature_to_der(&signature);
        der.push(0x00);
        assert!(signature_from_der(&der).is_err());
    }


    /// The all-zero KDF check is unreachable by construction, so its
    /// decision is tested rather than its branch. An `all_zero` that
    /// looked at the first byte only, or that returned true for an
    /// empty slice in a context that mattered, would open a hole
    /// nothing else here can see.
    #[test]
    fn test_the_all_zero_decision() {
        assert!(all_zero(&[]));
        assert!(all_zero(&[0]));
        assert!(all_zero(&[0u8; 64]));
        for position in 0..64 {
            let mut bytes = vec![0u8; 64];
            bytes[position] = 1;
            assert!(!all_zero(&bytes), "missed a set byte at {position}");
        }
        // And the check is applied to the KDF output that is actually
        // used, at the length that is actually used.
        assert!(!all_zero(&kdf(b"anything", 32)));
    }

    #[test]
    fn test_an_empty_message_is_refused_by_encrypt() {
        let curve = curves::sm2();
        let public = curve.generator_mul(&BigUint::from_u64(3));
        assert!(encrypt(&curve, &public, b"").is_err());
    }
}
