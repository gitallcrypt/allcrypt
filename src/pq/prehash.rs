/*
The external interface's message wrapping, shared by ML-DSA (FIPS 204)
and SLH-DSA (FIPS 205).

Both standards sign `M'` rather than `M`, and both build `M'` the same
way - a domain separator byte, a one-byte context length, the context,
and then either the message or a pre-hash function's OID and digest -
from the same list of twelve approved hash functions. FIPS 204 section
5.4 and FIPS 205 section 10.2 agree byte for byte, and NIST's validation
files for the two spell the hash names identically. One copy, so the two
schemes cannot drift apart.
*/

use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::HashFunction;

/// A pre-hash function, for the variant of the external interface that
/// hashes the message before signing it.
///
/// Twelve of them, approved by FIPS 205 section 10.2 and FIPS 204
/// section 5.4 alike. The names are
/// the spelling NIST's own validation files use, because that is what a
/// caller reading those files will have in hand.
///
/// `Copy` because this is a one byte tag rather than data: passing it by
/// reference would cost more than copying it, and `Option<PreHash>` in a
/// signature is much clearer than `Option<&PreHash>`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PreHash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    /// SHA-512 truncated to 224 bits, which is **not** SHA-224: the two
    /// have different initial values and different outputs.
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    /// SHAKE128 squeezed to **32 bytes**, which is a choice FIPS 205
    /// makes rather than a property of SHAKE - it will produce any
    /// length.
    Shake128,
    /// SHAKE256 squeezed to **64 bytes**.
    Shake256,
}

/// Every pre-hash function, in the order FIPS 205's table lists them.
pub const PRE_HASHES: [PreHash; 12] = [
    PreHash::Sha224, PreHash::Sha256, PreHash::Sha384, PreHash::Sha512,
    PreHash::Sha512_224, PreHash::Sha512_256,
    PreHash::Sha3_224, PreHash::Sha3_256, PreHash::Sha3_384,
    PreHash::Sha3_512, PreHash::Shake128, PreHash::Shake256,
];

impl PreHash {
    /// The name NIST's validation files use, e.g. `SHA2-512/224`.
    pub fn name(&self) -> &'static str {
        match self {
            PreHash::Sha224 => "SHA2-224",
            PreHash::Sha256 => "SHA2-256",
            PreHash::Sha384 => "SHA2-384",
            PreHash::Sha512 => "SHA2-512",
            PreHash::Sha512_224 => "SHA2-512/224",
            PreHash::Sha512_256 => "SHA2-512/256",
            PreHash::Sha3_224 => "SHA3-224",
            PreHash::Sha3_256 => "SHA3-256",
            PreHash::Sha3_384 => "SHA3-384",
            PreHash::Sha3_512 => "SHA3-512",
            PreHash::Shake128 => "SHAKE-128",
            PreHash::Shake256 => "SHAKE-256",
        }
    }

    /// Look one up by the name above. Matched exactly, like
    /// [`parameters`].
    pub fn by_name(name: &str) -> Result<PreHash, String> {
        PRE_HASHES.iter().find(|which| which.name() == name).copied()
            .ok_or_else(|| format!(
                "Unknown pre-hash {:?}. FIPS 204 and FIPS 205 approve the \
                 same twelve: {}.",
                name,
                PRE_HASHES.iter().map(|which| which.name())
                    .collect::<Vec<_>>().join(", ")))
    }

    /// The OID's **contents**, without the tag and length.
    ///
    /// Taken from `x509::oids`, which builds them at compile time from
    /// their dotted forms, rather than written out here. A second copy of
    /// an OID is a second thing to be wrong, and the copy in `oids` is
    /// the one `scripts/diff_check.py` checks against OpenSSL's table.
    pub fn oid(&self) -> &'static [u8] {
        use crate::x509::oids;
        match self {
            PreHash::Sha224 => oids::SHA224,
            PreHash::Sha256 => oids::SHA256,
            PreHash::Sha384 => oids::SHA384,
            PreHash::Sha512 => oids::SHA512,
            PreHash::Sha512_224 => oids::SHA512_224,
            PreHash::Sha512_256 => oids::SHA512_256,
            PreHash::Sha3_224 => oids::SHA3_224,
            PreHash::Sha3_256 => oids::SHA3_256,
            PreHash::Sha3_384 => oids::SHA3_384,
            PreHash::Sha3_512 => oids::SHA3_512,
            PreHash::Shake128 => oids::SHAKE128,
            PreHash::Shake256 => oids::SHAKE256,
        }
    }

    /// How many bytes the digest is.
    ///
    /// The natural output length for the fixed-output hashes, and the
    /// length FIPS 205 chooses for the two SHAKEs.
    pub fn output_len(&self) -> usize {
        match self {
            PreHash::Sha224 | PreHash::Sha512_224 | PreHash::Sha3_224 => 28,
            PreHash::Sha256 | PreHash::Sha512_256 | PreHash::Sha3_256
                | PreHash::Shake128 => 32,
            PreHash::Sha384 | PreHash::Sha3_384 => 48,
            PreHash::Sha512 | PreHash::Sha3_512 | PreHash::Shake256 => 64,
        }
    }

    /// `PH(M)`.
    pub fn digest(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        use crate::hash_functions::sha2::{SHA224, SHA256, SHA384, SHA512};

        /// One SHA-3 or SHAKE digest of `message`.
        fn sponge(mut keccak: Keccak, message: &[u8], length: usize)
                -> Vec<u8> {
            keccak.update(message);
            keccak.squeeze(length)
        }

        let out = match self {
            PreHash::Sha224 => SHA224::new(message).digest(),
            PreHash::Sha256 => SHA256::new(message).digest(),
            PreHash::Sha384 => SHA384::new(message).digest(),
            PreHash::Sha512 => SHA512::new(message, 512).digest(),
            // Truncated SHA-512 is not SHA-512 cut short: the initial
            // value is derived from the output length, which is what
            // `SHA512::new`'s second argument selects.
            PreHash::Sha512_224 => SHA512::new(message, 224).digest(),
            PreHash::Sha512_256 => SHA512::new(message, 256).digest(),
            PreHash::Sha3_224 => sponge(Keccak::sha3(28)?, message, 28),
            PreHash::Sha3_256 => sponge(Keccak::sha3(32)?, message, 32),
            PreHash::Sha3_384 => sponge(Keccak::sha3(48)?, message, 48),
            PreHash::Sha3_512 => sponge(Keccak::sha3(64)?, message, 64),
            PreHash::Shake128 => sponge(Keccak::shake(128, 32)?, message, 32),
            PreHash::Shake256 => sponge(Keccak::shake(256, 64)?, message, 64),
        };
        if out.len() != self.output_len() {
            return Err(format!(
                "Pre-hash {}: produced {} bytes and should produce {}.",
                self.name(), out.len(), self.output_len()));
        }
        Ok(out)
    }
}

/// The longest context string FIPS 204 and FIPS 205 allow.
///
/// The length is written as **one byte** in front of the context, so 255
/// is not a policy choice here - a longer one cannot be encoded, and
/// silently truncating it would make two different contexts produce the
/// same signature.
pub const MAX_CONTEXT: usize = 255;

/// `M'`: the message the internal interface actually signs.
///
/// FIPS 205 section 10.2, and FIPS 204 algorithms 2 and 4:
///
/// ```text
/// pure:      M' = toByte(0, 1) ‖ toByte(|ctx|, 1) ‖ ctx ‖ M
/// pre-hash:  M' = toByte(1, 1) ‖ toByte(|ctx|, 1) ‖ ctx ‖ OID ‖ PH(M)
/// ```
///
/// **This is a domain separator and it is the whole point of the external
/// interface.** The leading byte keeps a pure signature from ever being a
/// valid pre-hash signature; the context length in front of the context
/// keeps `ctx = "ab", M = "c"` from colliding with `ctx = "a", M = "bc"`;
/// and the OID in the pre-hash form keeps a SHA-256 digest from being
/// accepted as a SHA3-256 one of the same length. Leave any of the three
/// out and signatures stay self-consistent while becoming transferable
/// between contexts they were never meant for.
///
/// The OID is written as DER - tag, length, contents - through
/// `asn1::Writer`, not assembled here.
pub(crate) fn wrap(message: &[u8], context: &[u8],
                   pre_hash: Option<PreHash>)
        -> Result<Vec<u8>, String> {
    if context.len() > MAX_CONTEXT {
        return Err(format!(
            "A context string is at most {} bytes and this one is \
             {}. Its length is written in a single byte, so a longer one \
             cannot be encoded.", MAX_CONTEXT, context.len()));
    }

    let mut out = Vec::with_capacity(2 + context.len() + message.len() + 16);
    out.push(u8::from(pre_hash.is_some()));
    out.push(context.len() as u8);
    out.extend_from_slice(context);

    match pre_hash {
        None => out.extend_from_slice(message),
        Some(which) => {
            let mut writer = crate::asn1::Writer::new();
            writer.write_oid(which.oid());
            out.extend_from_slice(&writer.finish());
            out.extend_from_slice(&which.digest(message)?);
        }
    }
    Ok(out)
}
