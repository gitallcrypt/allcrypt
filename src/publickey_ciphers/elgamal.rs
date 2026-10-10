/*
ElGamal, Taher ElGamal 1985.

Diffie-Hellman turned into an encryption scheme, and separately into a
signature scheme. Both live in the same multiplicative group mod a prime
`p`, so this module is built on `DhGroup` - the validation a group and a
public value need is exactly the validation Diffie-Hellman needs, and
having it in one place is why `DhGroup` holds `p` and `g` together.

## Why it is here

**Old PGP keyrings.** OpenPGP algorithm 16 is ElGamal encryption, and it
was GnuPG's default encryption subkey for years - the `elg` half of the
`dsa/elg` keypairs that were the standard recommendation through the
2000s. Those keys are still in keyrings and those messages are still in
archives, and nothing decrypts them but this. GnuPG can still read them;
OpenSSL dropped ElGamal entirely and `cryptography` has never had it.

## Encryption and signing are two different schemes

They share `p`, `g`, `x` and `y` and nothing else:

- **Encryption** picks a random `k`, sends `c1 = g^k` and
  `c2 = m * y^k`, and the holder of `x` recovers `m = c2 / c1^x`. The
  ciphertext is twice the size of the modulus.
- **Signing** picks a random `k` *coprime to p-1*, sends `r = g^k` and
  `s = (H(m) - x*r) / k mod (p-1)`, and a verifier checks
  `y^r * r^s == g^H(m)`.

**GnuPG removed ElGamal signing in 2003** after Phong Nguyen showed that
its "sign+encrypt" keys were broken: to make signing fast it used a
short `k`, and a short `k` in the signature equation recovers `x`. That
was a flaw in one implementation's choice of `k`, not in the scheme, and
the scheme is here because old signatures still need verifying. `k` is
drawn full width, from the same place every other nonce in this library
comes from.

## Five ways to get it wrong, all of them silent

**`k` must never repeat, and must never be short.** Two signatures under
the same `k` give `x` by subtraction - the same arithmetic that broke
the PlayStation 3's ECDSA. A short `k` gives `x` to a lattice.

**`k` must be coprime to `p-1` for signing.** Otherwise `k` has no
inverse mod `p-1` and the signature cannot be made; an implementation
that reduced anyway would produce something that verifies for some
messages and not others.

**`m` must be less than `p` for encryption.** Larger and it is reduced,
so decryption returns something else - quietly. Checked.

**`c1` must be validated like a peer public value.** `c1 = 0`, `1` or
`p-1` are all accepted by naive decryption and reveal the plaintext or a
bit of `x`. `DhGroup::validate_peer` is the same check, for the same
reason.

**The verification equation must range-check `r`.** RFC-free folklore,
but Bleichenbacher showed in 1996 that a verifier accepting `r >= p`
lets an attacker forge signatures for a chosen message. The check is one
comparison and its absence is invisible against honest signatures.
*/

use crate::bignum::BigUint;
use crate::publickey_ciphers::dh::DhGroup;
use crate::publickey_ciphers::rsa;
use crate::random;

/// The public half: a group and `y = g^x mod p`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ElGamalPublicKey {
    group: DhGroup,
    y: BigUint,
}

/// The private half. Holds the public one rather than recomputing it,
/// because `g^x mod p` is an exponentiation and every operation here
/// needs the group.
#[derive(Clone)]
pub struct ElGamalPrivateKey {
    public: ElGamalPublicKey,
    x: BigUint,
}

impl ElGamalPublicKey {
    /// A public key from a group and `y`.
    ///
    /// `y` goes through the same validation a Diffie-Hellman peer value
    /// does, because it is the same claim: a number outside `[2, p-2]`
    /// generates a subgroup with one or two elements, and every
    /// ciphertext under it would be forgeable or constant.
    pub fn new(group: DhGroup, y: BigUint) -> Result<ElGamalPublicKey, String> {
        group.validate_peer(&y)?;
        Ok(ElGamalPublicKey { group, y })
    }

    pub fn group(&self) -> &DhGroup {
        &self.group
    }

    pub fn y(&self) -> &BigUint {
        &self.y
    }

    /// The size of one ciphertext component, which is the modulus width.
    /// A whole ElGamal ciphertext is twice this.
    pub fn size(&self) -> usize {
        self.group.modulus_bytes()
    }

    /// Encrypt an integer message, returning `(c1, c2)`.
    ///
    /// The raw scheme, with no padding - which is **malleable on
    /// purpose**: multiplying `c2` by any `t` multiplies the plaintext by
    /// `t`, with no key and no detection. That is a property of textbook
    /// ElGamal, and it is why OpenPGP wraps the message in PKCS#1 v1.5
    /// padding first. Use `encrypt_pkcs1v15` unless you are implementing
    /// something that specifies otherwise.
    pub fn encrypt(&self, message: &BigUint)
                   -> Result<(BigUint, BigUint), String> {
        let p = self.group.p();
        if message.is_zero() || message >= p {
            return Err(format!(
                "An ElGamal message must be in [1, p-1]; this one is {}. \
                 A larger value is reduced modulo p, so decryption would \
                 return a different message rather than failing.",
                if message.is_zero() { "zero".to_string() }
                else { format!("{} bits, and p is {}",
                               message.bit_len(), p.bit_len()) }));
        }

        // `k` is an ephemeral private key in the same group, so it is
        // drawn exactly the way a Diffie-Hellman private exponent is -
        // full width, from the system source. A short `k` is what broke
        // GnuPG's signing keys; there is no reason to reintroduce it on
        // the encryption side.
        let (k, c1) = self.group.generate_key_pair()?;
        let shared = self.y.mod_pow_ct(&k, p)?;
        let c2 = message.mod_mul(&shared, p)?;
        Ok((c1, c2))
    }

    /// Verify an ElGamal signature over `digest`.
    ///
    /// `y^r * r^s == g^m mod p`, with `m` the digest read as an integer.
    pub fn verify(&self, digest: &[u8], r: &BigUint, s: &BigUint)
                  -> Result<bool, String> {
        let p = self.group.p();
        let one = BigUint::one();
        let p_minus_1 = p.sub(&one)?;

        // **Bleichenbacher's 1996 forgery.** A verifier that skips these
        // accepts signatures an attacker can build for a chosen message
        // without the private key. `r` outside `[1, p-1]` is the whole
        // attack, and it is invisible against honest signatures because
        // an honest `r` is `g^k mod p` and so always in range.
        if *r < one || *r >= *p {
            return Ok(false);
        }
        if *s < one || *s >= p_minus_1 {
            return Ok(false);
        }

        let m = Self::digest_to_exponent(digest, &p_minus_1)?;
        let left = self.y.mod_pow(r, p)?
            .mod_mul(&r.mod_pow(s, p)?, p)?;
        let right = self.group.g().mod_pow(&m, p)?;
        Ok(left == right)
    }

    /// The digest as an integer, reduced into `[0, p-2]`.
    ///
    /// ElGamal signs `H(m)` as an exponent modulo `p-1`, so a digest
    /// wider than the group has to be reduced. Reading it big endian is
    /// the convention every implementation uses; GOST R 34.10 reads its
    /// digests little endian, which is recorded in `docs/pitfalls.md` as
    /// a thing that is silent when wrong.
    fn digest_to_exponent(digest: &[u8], p_minus_1: &BigUint)
                          -> Result<BigUint, String> {
        BigUint::from_bytes_be(digest).rem(p_minus_1)
    }
}

impl ElGamalPrivateKey {
    /// Generate a fresh key in an existing group.
    pub fn generate(group: DhGroup) -> Result<ElGamalPrivateKey, String> {
        let (x, y) = group.generate_key_pair()?;
        Ok(ElGamalPrivateKey {
            public: ElGamalPublicKey::new(group, y)?,
            x,
        })
    }

    /// A key from an existing private exponent, which is what reading a
    /// PGP secret key gives.
    pub fn from_private(group: DhGroup, x: BigUint)
                        -> Result<ElGamalPrivateKey, String> {
        let one = BigUint::one();
        let p_minus_2 = group.p().sub(&BigUint::from_u64(2))?;
        if x < one || x > p_minus_2 {
            return Err("An ElGamal private exponent must be in [1, p-2]."
                       .to_string());
        }
        let y = group.public_key(&x)?;
        Ok(ElGamalPrivateKey {
            public: ElGamalPublicKey::new(group, y)?,
            x,
        })
    }

    pub fn public(&self) -> &ElGamalPublicKey {
        &self.public
    }

    pub fn private_bytes(&self) -> Result<Vec<u8>, String> {
        self.x.to_bytes_be_padded(self.public.size())
    }

    /// Decrypt `(c1, c2)` back to the integer message.
    ///
    /// `m = c2 * (c1^x)^-1 mod p`. The inverse is computed as
    /// `c1^(p-1-x)`, which is Fermat's little theorem and avoids an
    /// extended-Euclid on a secret - the same reason
    /// `Montgomery::inverse_prime` exists.
    pub fn decrypt(&self, c1: &BigUint, c2: &BigUint)
                   -> Result<BigUint, String> {
        let p = self.public.group.p();

        // **The same check a Diffie-Hellman peer value gets**, and for
        // the same reason: `c1 = 1` makes `c1^x = 1`, so `m = c2` and the
        // plaintext is on the wire; `c1 = p-1` has order two, so whether
        // `m = c2` or `m = -c2` leaks the parity of `x`.
        self.public.group.validate_peer(c1)?;
        if c2.is_zero() || c2 >= p {
            return Err("An ElGamal ciphertext's second component must be \
                        in [1, p-1].".to_string());
        }

        let p_minus_1 = p.sub(&BigUint::one())?;
        let inverse_exponent = p_minus_1.sub(&self.x)?;
        let inverse = c1.mod_pow_ct(&inverse_exponent, p)?;
        c2.mod_mul(&inverse, p)
    }

    /// Sign `digest`, returning `(r, s)`.
    ///
    /// Read the module comment before using this: GnuPG withdrew ElGamal
    /// signing, and the reason was the choice of `k` rather than the
    /// equation. `k` here is full width and freshly drawn, and it is
    /// redrawn until it is coprime to `p-1`.
    pub fn sign(&self, digest: &[u8]) -> Result<(BigUint, BigUint), String> {
        let p = self.public.group.p();
        let g = self.public.group.g();
        let one = BigUint::one();
        let p_minus_1 = p.sub(&one)?;
        let m = ElGamalPublicKey::digest_to_exponent(digest, &p_minus_1)?;

        // Twenty attempts, which is astronomically more than needed: for
        // a safe prime `p-1 = 2q`, half of all `k` are coprime to it.
        // The loop exists because `k` must be invertible mod `p-1`, not
        // because failure is expected - and a loop that could run forever
        // on a broken random source would hang rather than report.
        for _ in 0..20 {
            let k = random::below(&p_minus_1)?.add(&one);
            if k.gcd(&p_minus_1) != one {
                continue;
            }
            let r = g.mod_pow_ct(&k, p)?;

            // s = (m - x*r) * k^-1 mod (p-1). The subtraction is modular:
            // `x*r` is reduced first, and `m - x*r` may be negative, so it
            // is computed as `m + (p-1) - (x*r mod (p-1))`.
            let xr = self.x.mod_mul(&r, &p_minus_1)?;
            let numerator = m.add(&p_minus_1).sub(&xr)?.rem(&p_minus_1)?;
            let k_inverse = k.mod_inverse(&p_minus_1)?;
            let s = numerator.mod_mul(&k_inverse, &p_minus_1)?;

            // `s = 0` is a degenerate signature: the verification
            // equation collapses to `y^r == g^m`, which no longer
            // depends on the nonce at all.
            //
            // **Unreachable in practice, and a breakage sweep cannot
            // see it.** `s` is zero only when `m == x*r mod (p-1)`,
            // which for a random `k` happens with probability about
            // `1/p`. Removing this `continue` fails no test, because no
            // test can make it happen - the nonce is drawn inside this
            // function on purpose. It is kept as defence in depth, with
            // this comment saying so, which is the convention this
            // repository uses for a branch that cannot be tested (see
            // `ec::ct::Field::add`).
            if s.is_zero() {
                continue;
            }
            return Ok((r, s));
        }
        Err("Failed to find a usable ElGamal nonce in twenty attempts; the \
             random source looks broken.".to_string())
    }
}

// --------------------------------------------------- PKCS#1 v1.5 framing ---

/// OpenPGP's ElGamal encryption (RFC 4880 section 13.1), which is
/// PKCS#1 v1.5 padding inside the raw scheme.
///
/// `EM = 0x00 || 0x02 || PS || 0x00 || M`, padded to the modulus width,
/// where PS is at least 8 nonzero random bytes. Without it, raw ElGamal
/// is malleable - multiply `c2` by `t` and the plaintext is multiplied
/// by `t`, with no key and no way to tell.
///
/// Returns `c1 || c2`, each left-padded to the modulus width, which is
/// how OpenPGP writes them apart from the MPI length prefixes.
pub fn encrypt_pkcs1v15(key: &ElGamalPublicKey, message: &[u8])
                        -> Result<Vec<u8>, String> {
    let size = key.size();
    if message.len() + 11 > size {
        return Err(format!("Message of {} bytes is too long for a {} byte \
                            modulus (limit {}).",
                           message.len(), size, size.saturating_sub(11)));
    }

    let padding_len = size - message.len() - 3;
    let mut padding = Vec::with_capacity(padding_len);
    // PS carries no zero byte, because a zero is the separator. Drawing
    // fresh bytes and discarding zeros keeps it uniform over 1..=255;
    // mapping a zero to something else would not.
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

    let (c1, c2) = key.encrypt(&BigUint::from_bytes_be(&block))?;
    let mut out = c1.to_bytes_be_padded(size)?;
    out.extend_from_slice(&c2.to_bytes_be_padded(size)?);
    Ok(out)
}

/// The counterpart of `encrypt_pkcs1v15`.
///
/// **Every failure returns the same error**, for the reason
/// `rsa::decrypt_pkcs1v15` gives at length: telling an attacker which
/// check failed turns this into a decryption oracle. ElGamal is as
/// exposed to that as RSA is - Bleichenbacher's attack is about the
/// padding check, not about the trapdoor underneath it.
///
/// This is not constant time, because the bignum underneath is not. It
/// reduces the oracle rather than removing it.
pub fn decrypt_pkcs1v15(key: &ElGamalPrivateKey, ciphertext: &[u8])
                        -> Result<Vec<u8>, String> {
    const FAILURE: &str = "ElGamal decryption failed.";
    let size = key.public().size();
    if ciphertext.len() != 2 * size {
        return Err(FAILURE.to_string());
    }

    let c1 = BigUint::from_bytes_be(&ciphertext[..size]);
    let c2 = BigUint::from_bytes_be(&ciphertext[size..]);
    let block = key.decrypt(&c1, &c2)
        .map_err(|_| FAILURE.to_string())?
        .to_bytes_be_padded(size)
        .map_err(|_| FAILURE.to_string())?;

    // The padding check is the RSA one: same block shape, same gathered
    // conditions, and a block too short to hold the header and the eight
    // bytes of PS is refused before it is indexed.
    rsa::pkcs1v15_unpad(&block)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| FAILURE.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_functions::HashFunction;
    use crate::publickey_ciphers::dh::modp_group;

    fn sha256(data: &[u8]) -> Vec<u8> {
        crate::hash_functions::sha2::SHA256::new(data).digest()
    }

    /// RFC 3526's 2048 bit MODP group, which the DH module already
    /// vendors. Using a standard group rather than generating one keeps
    /// these tests fast and means the parameters are somebody else's.
    fn group() -> DhGroup {
        modp_group(crate::publickey_ciphers::dh::MODP_2048).unwrap()
    }

    /// The smaller standard group, for the signing tests.
    ///
    /// ElGamal signing does several exponentiations per signature and
    /// the tests below make a dozen of them, so the 1024 bit group keeps
    /// `cargo test` quick. It is a standard group rather than a
    /// generated one, so the parameters are still somebody else's.
    fn small_group() -> DhGroup {
        modp_group(crate::publickey_ciphers::dh::MODP_1024).unwrap()
    }

    // ---------------------------------------------------- encryption ---

    #[test]
    fn test_encrypt_and_decrypt_round_trip() {
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let message = BigUint::from_bytes_be(b"a message as an integer");
        let (c1, c2) = key.public().encrypt(&message).unwrap();
        assert_eq!(key.decrypt(&c1, &c2).unwrap(), message);
    }

    #[test]
    fn test_encryption_is_randomised() {
        // ElGamal without a fresh `k` is deterministic, and a
        // deterministic public key encryption over a small message space
        // can simply be enumerated. Two encryptions of one message must
        // differ in both components.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let message = BigUint::from_u64(42);
        let (a1, a2) = key.public().encrypt(&message).unwrap();
        let (b1, b2) = key.public().encrypt(&message).unwrap();
        assert_ne!(a1, b1, "c1 repeated, so k repeated");
        assert_ne!(a2, b2);
        // And both still decrypt.
        assert_eq!(key.decrypt(&a1, &a2).unwrap(), message);
        assert_eq!(key.decrypt(&b1, &b2).unwrap(), message);
    }

    #[test]
    fn test_the_raw_scheme_is_malleable_and_that_is_why_padding_exists() {
        // Not a bug - a property, and the reason OpenPGP wraps the
        // message in PKCS#1 padding. Asserted so that anyone tempted to
        // use `encrypt` directly meets it here first.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let p = key.public().group().p();
        let message = BigUint::from_u64(1000);
        let (c1, c2) = key.public().encrypt(&message).unwrap();

        let doubled = c2.mod_mul(&BigUint::from_u64(2), p).unwrap();
        assert_eq!(key.decrypt(&c1, &doubled).unwrap(),
                   BigUint::from_u64(2000),
                   "multiplying c2 by t multiplies the plaintext by t");
    }

    #[test]
    fn test_a_message_that_is_not_smaller_than_p_is_refused() {
        // Larger messages are reduced mod p, so decryption returns a
        // *different* message rather than failing - which is the worst
        // shape a limit can have.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let p = key.public().group().p().clone();
        assert!(key.public().encrypt(&p).is_err());
        assert!(key.public().encrypt(&p.add(&BigUint::one())).is_err());
        assert!(key.public().encrypt(&BigUint::from_u64(0)).is_err());
        assert!(key.public().encrypt(&p.sub(&BigUint::one()).unwrap()).is_ok());
    }

    #[test]
    fn test_a_degenerate_first_component_is_refused() {
        // `c1 = 1` makes `c1^x = 1`, so `m = c2` and the plaintext is on
        // the wire. `c1 = p-1` has order two, so the answer depends on
        // the parity of `x` - one bit of the private key per decryption.
        // Both complete happily in a naive implementation.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let p = key.public().group().p();
        let c2 = BigUint::from_u64(12345);
        for bad in [BigUint::from_u64(0), BigUint::one(),
                    p.sub(&BigUint::one()).unwrap(), p.clone()] {
            assert!(key.decrypt(&bad, &c2).is_err(),
                    "c1 of {} bits was accepted", bad.bit_len());
        }
    }

    #[test]
    fn test_a_public_key_outside_the_group_is_refused() {
        let g = group();
        let p = g.p().clone();
        for bad in [BigUint::from_u64(0), BigUint::one(),
                    p.sub(&BigUint::one()).unwrap()] {
            assert!(ElGamalPublicKey::new(g.clone(), bad).is_err());
        }
    }

    #[test]
    fn test_a_private_exponent_can_be_loaded_back() {
        // What reading a PGP secret key does: the file carries `x`, and
        // `y` is recomputed rather than trusted.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let x = BigUint::from_bytes_be(&key.private_bytes().unwrap());
        let reloaded = ElGamalPrivateKey::from_private(
            key.public().group().clone(), x).unwrap();
        assert_eq!(reloaded.public(), key.public());

        let message = BigUint::from_u64(7777);
        let (c1, c2) = key.public().encrypt(&message).unwrap();
        assert_eq!(reloaded.decrypt(&c1, &c2).unwrap(), message);
    }

    // ------------------------------------------------ PKCS#1 framing ---

    #[test]
    fn test_pkcs1_round_trip_at_every_interesting_length() {
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let size = key.public().size();
        for len in [0usize, 1, 16, 32, size - 11] {
            let message: Vec<u8> = (0..len).map(|i| (i as u8) | 1).collect();
            let sealed = encrypt_pkcs1v15(key.public(), &message).unwrap();
            assert_eq!(sealed.len(), 2 * size,
                       "a ciphertext is two modulus widths");
            assert_eq!(decrypt_pkcs1v15(&key, &sealed).unwrap(), message,
                       "length {len}");
        }
    }

    #[test]
    fn test_a_message_containing_zero_bytes_survives() {
        // **The separator is the *first* zero after the padding, and a
        // message may contain zeros of its own.** A search that took the
        // last zero in the block, or the largest index, would truncate
        // any message with an interior zero - and the test above cannot
        // see it, because its messages are built with `| 1` and so have
        // none. A breakage sweep found exactly that gap.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        for message in [vec![0u8],
                        vec![0u8, 0, 0],
                        b"a\0b\0c".to_vec(),
                        vec![0u8, 1, 2, 3],           // leading zero
                        vec![1u8, 2, 3, 0],           // trailing zero
                        (0..64u8).collect::<Vec<u8>>()] {
            let sealed = encrypt_pkcs1v15(key.public(), &message).unwrap();
            assert_eq!(decrypt_pkcs1v15(&key, &sealed).unwrap(), message,
                       "message {message:?}");
        }
    }

    #[test]
    fn test_a_message_one_byte_too_long_is_refused() {
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let size = key.public().size();
        assert!(encrypt_pkcs1v15(key.public(), &vec![0u8; size - 11]).is_ok());
        assert!(encrypt_pkcs1v15(key.public(), &vec![0u8; size - 10]).is_err());
    }

    #[test]
    fn test_every_padding_failure_gives_the_same_message() {
        // Bleichenbacher's attack is about *which* check failed. One
        // message, no detail - and this asserts it rather than trusting
        // the constant to stay in one place.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let size = key.public().size();
        let sealed = encrypt_pkcs1v15(key.public(), b"secret").unwrap();

        let mut messages = std::collections::HashSet::new();
        // A truncated ciphertext, a corrupted one, and one that
        // decrypts to a block with no separator.
        messages.insert(decrypt_pkcs1v15(&key, &sealed[..2 * size - 1])
                        .unwrap_err());
        let mut corrupt = sealed.clone();
        corrupt[size + 5] ^= 1;
        messages.insert(decrypt_pkcs1v15(&key, &corrupt).unwrap_err());
        let mut zeroed = sealed.clone();
        zeroed[..size].copy_from_slice(&vec![0u8; size]);
        messages.insert(decrypt_pkcs1v15(&key, &zeroed).unwrap_err());

        assert_eq!(messages.len(), 1,
                   "the failures are distinguishable: {messages:?}");
    }

    /// Encrypt a crafted padding block directly, bypassing
    /// `encrypt_pkcs1v15`, so that `decrypt_pkcs1v15` can be offered a
    /// block it would never have produced.
    ///
    /// This is the only way to reach the padding checks: a correct
    /// encryptor cannot make a malformed block, so a test that only
    /// round-trips leaves every refusal in `decrypt_pkcs1v15` untested.
    /// The same point `docs/pitfalls.md` records about private-key
    /// parsers - the checks a parser needs are unreachable from a
    /// generated file.
    fn seal_raw_block(key: &ElGamalPrivateKey, block: &[u8]) -> Vec<u8> {
        let size = key.public().size();
        assert_eq!(block.len(), size);
        let (c1, c2) = key.public()
            .encrypt(&BigUint::from_bytes_be(block)).unwrap();
        let mut out = c1.to_bytes_be_padded(size).unwrap();
        out.extend_from_slice(&c2.to_bytes_be_padded(size).unwrap());
        out
    }

    #[test]
    fn test_a_padding_block_with_too_little_padding_is_refused() {
        // PKCS#1 v1.5 requires **at least eight** nonzero padding
        // bytes. A shorter PS narrows the search an attacker has to do
        // and is the first thing a padding oracle attack constructs, so
        // the bound is not cosmetic - and no honest encryptor can
        // produce one, which is why it needs a crafted block.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let size = key.public().size();

        for ps_len in 0..8usize {
            let mut block = vec![0x00, 0x02];
            block.extend(std::iter::repeat_n(0xaau8, ps_len));
            block.push(0x00);
            block.extend(std::iter::repeat_n(0x41u8, size - 3 - ps_len));
            assert_eq!(block.len(), size);
            let sealed = seal_raw_block(&key, &block);
            assert!(decrypt_pkcs1v15(&key, &sealed).is_err(),
                    "a PS of {ps_len} bytes was accepted");
        }

        // And eight is enough, so the bound is not simply refusing
        // everything.
        let mut block = vec![0x00, 0x02];
        block.extend(std::iter::repeat_n(0xaau8, 8));
        block.push(0x00);
        block.extend(std::iter::repeat_n(0x41u8, size - 11));
        let sealed = seal_raw_block(&key, &block);
        assert_eq!(decrypt_pkcs1v15(&key, &sealed).unwrap(),
                   vec![0x41u8; size - 11]);
    }

    #[test]
    fn test_a_padding_block_with_the_wrong_header_is_refused() {
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let size = key.public().size();
        let good = |first: u8, second: u8| {
            let mut block = vec![first, second];
            block.extend(std::iter::repeat_n(0xaau8, size - 3 - 5));
            block.push(0x00);
            block.extend_from_slice(b"hello");
            block
        };
        // 0x00 0x02 is the only accepted header. 0x00 0x01 is the
        // *signature* block type, and accepting it would let a
        // signature be replayed as a ciphertext.
        assert!(decrypt_pkcs1v15(&key, &seal_raw_block(&key, &good(0, 1)))
                .is_err());
        assert!(decrypt_pkcs1v15(&key, &seal_raw_block(&key, &good(0, 0)))
                .is_err());
        assert!(decrypt_pkcs1v15(&key, &seal_raw_block(&key, &good(1, 2)))
                .is_err());
        assert!(decrypt_pkcs1v15(&key, &seal_raw_block(&key, &good(0, 2)))
                .is_ok());
    }

    #[test]
    fn test_a_padding_block_with_no_separator_is_refused() {
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let size = key.public().size();
        let mut block = vec![0x00, 0x02];
        block.extend(std::iter::repeat_n(0xaau8, size - 2));
        assert_eq!(block.len(), size);
        assert!(decrypt_pkcs1v15(&key, &seal_raw_block(&key, &block)).is_err());
    }

    #[test]
    fn test_a_modulus_too_small_for_a_padding_block_is_refused_not_a_panic() {
        // `DhGroup::new` accepts any odd `p >= 5`, so an ElGamal key over
        // `p = 7` is a legal key whose decrypted block is one byte wide.
        // The padding check read `block[1]` before anything had checked
        // the width, so this ciphertext was an index-out-of-bounds panic
        // rather than the uniform failure - a `PanicException` through
        // the Python bindings and undefined behaviour through the C
        // ones. Every existing test used a standard MODP group, whose
        // block is 128 bytes or wider, so the width was never in doubt.
        //
        // `c1 = 2` and `c2 = 3` pass `validate_peer` and the range check
        // in `decrypt`, so the only thing that can refuse them is the
        // padding check itself.
        let group = DhGroup::new(BigUint::from_u64(7), BigUint::from_u64(2))
            .unwrap();
        let key = ElGamalPrivateKey::from_private(group, BigUint::one())
            .unwrap();
        assert_eq!(key.public().size(), 1);
        let error = decrypt_pkcs1v15(&key, &[0x02, 0x03]).unwrap_err();
        assert_eq!(error, "ElGamal decryption failed.");
    }

    #[test]
    fn test_the_padding_is_random() {
        // Two encryptions of one message differ, which is what the
        // padding and the fresh `k` are both for.
        let key = ElGamalPrivateKey::generate(group()).unwrap();
        let a = encrypt_pkcs1v15(key.public(), b"same").unwrap();
        let b = encrypt_pkcs1v15(key.public(), b"same").unwrap();
        assert_ne!(a, b);
        assert_eq!(decrypt_pkcs1v15(&key, &a).unwrap(), b"same");
        assert_eq!(decrypt_pkcs1v15(&key, &b).unwrap(), b"same");
    }

    // ------------------------------------------------------- signing ---

    #[test]
    fn test_sign_and_verify() {
        let key = ElGamalPrivateKey::generate(small_group()).unwrap();
        let digest = sha256(b"a message");
        let (r, s) = key.sign(&digest).unwrap();
        assert!(key.public().verify(&digest, &r, &s).unwrap());
    }

    #[test]
    fn test_a_signature_over_a_different_message_does_not_verify() {
        let key = ElGamalPrivateKey::generate(small_group()).unwrap();
        let digest = sha256(b"a message");
        let other = sha256(b"another");
        let (r, s) = key.sign(&digest).unwrap();
        assert!(!key.public().verify(&other, &r, &s).unwrap());
    }

    #[test]
    fn test_signatures_are_randomised() {
        // A repeated `k` gives `x` by subtraction - the same arithmetic
        // that broke the PlayStation 3's ECDSA. Two signatures over one
        // message must have different `r`.
        let key = ElGamalPrivateKey::generate(small_group()).unwrap();
        let digest = sha256(b"m");
        let (r1, s1) = key.sign(&digest).unwrap();
        let (r2, s2) = key.sign(&digest).unwrap();
        assert_ne!(r1, r2, "the nonce repeated");
        assert_ne!(s1, s2);
        assert!(key.public().verify(&digest, &r1, &s1).unwrap());
        assert!(key.public().verify(&digest, &r2, &s2).unwrap());
    }

    #[test]
    fn test_bleichenbachers_forgery_is_refused() {
        // **The 1996 forgery, built rather than described.**
        //
        // A verifier that does not require `r < p` can be handed a
        // signature for *any* message without the private key. The
        // construction is one application of the Chinese remainder
        // theorem, and it works because `r` appears twice in the
        // verification equation with two different moduli: as an
        // exponent, where it counts modulo `p-1`, and as a base, where
        // it counts modulo `p`. Those two moduli are coprime, so an
        // `r` larger than `p` can satisfy both independently.
        //
        // Take `s = 1` and ask for
        //     r == 0        (mod p-1)   so that y^r == 1
        //     r == g^m      (mod p)     so that r^s == g^m
        // and the equation `y^r * r^s == g^m` holds. CRT gives
        // `r = (p-1) * (p - g^m mod p)`, because the inverse of `p-1`
        // modulo `p` is `p-1` itself.
        //
        // **The first version of this test was worthless** and a
        // breakage sweep said so: it offered `r = 0`, `r = p` and
        // `r = p + r`, all of which the *arithmetic* rejects for
        // unrelated reasons, so removing the range check entirely
        // changed nothing. A test of a check has to offer a value the
        // check is the only thing refusing.
        let key = ElGamalPrivateKey::generate(small_group()).unwrap();
        let digest = sha256(b"a message nobody signed");
        let p = key.public().group().p();
        let g = key.public().group().g();
        let one = BigUint::one();
        let p_minus_1 = p.sub(&one).unwrap();

        let m = ElGamalPublicKey::digest_to_exponent(&digest, &p_minus_1)
            .unwrap();
        let target = g.mod_pow(&m, p).unwrap();
        let forged_r = p_minus_1.mul(&p.sub(&target).unwrap());

        // The forgery really does satisfy the equation - checked here
        // with the raw arithmetic, so the claim does not rest on our
        // own verifier.
        let left = key.public().y().mod_pow(&forged_r, p).unwrap()
            .mod_mul(&forged_r.mod_pow(&one, p).unwrap(), p).unwrap();
        assert_eq!(left, target,
                   "the forgery construction is wrong, so this test would \
                    pass for the wrong reason");
        assert!(forged_r > *p, "the forged r must be out of range");

        // And the range check is what refuses it.
        assert!(!key.public().verify(&digest, &forged_r, &one).unwrap());
    }

    #[test]
    fn test_a_signature_is_not_malleable_by_adding_p_minus_one_to_s() {
        // `s` is an exponent modulo `p-1` in the signing equation, so
        // `s` and `s + (p-1)` give the same `r^s mod p` and a verifier
        // without the upper bound accepts both. That is signature
        // malleability rather than forgery - but a system that
        // deduplicates or hashes signatures treats the two as different
        // objects with the same meaning, which is how transaction
        // malleability bugs happen.
        let key = ElGamalPrivateKey::generate(small_group()).unwrap();
        let digest = sha256(b"m");
        let (r, s) = key.sign(&digest).unwrap();
        let p_minus_1 = key.public().group().p().sub(&BigUint::one()).unwrap();

        assert!(key.public().verify(&digest, &r, &s).unwrap());
        let mutated = s.add(&p_minus_1);
        assert_ne!(mutated, s);
        assert!(!key.public().verify(&digest, &r, &mutated).unwrap(),
                "s + (p-1) must be refused, or the signature is malleable");
    }

    #[test]
    fn test_the_obviously_degenerate_signature_values_are_refused() {
        // These are refused by the arithmetic as well as by the range
        // check - `r = 0` makes the left side zero - so they prove less
        // than the two tests above. Kept because they are what a caller
        // is most likely to pass by accident.
        let key = ElGamalPrivateKey::generate(small_group()).unwrap();
        let digest = sha256(b"m");
        let (r, s) = key.sign(&digest).unwrap();
        let p = key.public().group().p();
        assert!(!key.public().verify(&digest, &BigUint::from_u64(0), &s)
                .unwrap());
        assert!(!key.public().verify(&digest, p, &s).unwrap());
        assert!(!key.public().verify(&digest, &r, &BigUint::from_u64(0))
                .unwrap());
    }

    #[test]
    fn test_the_nonce_is_coprime_to_p_minus_one() {
        // `k` must be invertible mod `p-1`, and the signing loop redraws
        // until it is. If it did not, `mod_inverse` would fail - so this
        // asserts the loop actually runs by signing repeatedly, which on
        // a safe prime rejects about half the draws.
        let key = ElGamalPrivateKey::generate(small_group()).unwrap();
        let digest = sha256(b"m");
        for _ in 0..8 {
            let (r, s) = key.sign(&digest).unwrap();
            assert!(key.public().verify(&digest, &r, &s).unwrap());
        }
    }

    #[test]
    fn test_a_tampered_signature_does_not_verify() {
        let key = ElGamalPrivateKey::generate(small_group()).unwrap();
        let digest = sha256(b"m");
        let (r, s) = key.sign(&digest).unwrap();
        let one = BigUint::one();
        assert!(!key.public().verify(&digest, &r.add(&one), &s).unwrap());
        assert!(!key.public().verify(&digest, &r, &s.add(&one)).unwrap());
    }
}
