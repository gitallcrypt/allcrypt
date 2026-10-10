/*
Private keys, from PEM or DER.

Nothing else here reads a private key from a file. `EcKey::from_private`
takes a scalar and `RsaPrivateKey::from_primes` takes two primes, which is
right for a library and useless for anything that was handed a `.pem` -
which is how every server operator has their key, and why the `ssl` shim
could not offer a server side without this.

## Three encodings, and every one of them is in the wild

  * **PKCS#8** (RFC 5208), labelled `PRIVATE KEY`. An algorithm identifier
    and an OCTET STRING holding one of the two below. This is what
    `openssl genpkey` writes and what almost everything modern emits.
  * **SEC1** (RFC 5915), labelled `EC PRIVATE KEY`. An EC key on its own,
    with the curve as a tagged parameter inside it rather than in an
    algorithm identifier. `openssl ecparam -genkey` writes this.
  * **PKCS#1** (RFC 8017 A.1.2), labelled `RSA PRIVATE KEY`. An RSA key on
    its own. `openssl genrsa` wrote this for twenty years.

The label is **not** trusted to say which. A file whose header says
`PRIVATE KEY` and whose body is SEC1 is something `openssl` itself will
produce if asked the wrong way, and refusing it teaches nobody anything;
the structure decides and the label only narrows the search.

## Encrypted keys

Most private keys on a disk are encrypted, so `*_with_password` takes a
passphrase and `x509::encrypted_key` removes the outer
`EncryptedPrivateKeyInfo` before any of the three parsers above sees
anything. Whether a file is encrypted is decided by its structure, not by
its PEM label - a DER file has no label at all - and a key that *is*
encrypted with no passphrase given is refused by name, because "this
needs a password" and "this is not a private key" send the reader in
completely different directions.

## What is not here

**Key agreement between the two halves.** `parse` returns what the file
says. Whether the private key matches a certificate is a separate question
with a separate answer, and `api::TlsServer` is where the two meet.
*/

use crate::asn1::{tag, Reader, Tag};
use crate::bignum::BigUint;
use crate::x509::oids;

/// A parsed private key.
///
/// The two shapes this library can actually compute with. Anything else -
/// a GOST key, a curve we do not implement - is an error here rather than
/// a third variant, because unlike a *public* key in a certificate there
/// is no useful thing to do with a private key we cannot use. A
/// certificate on an unknown curve is still a link in a chain; a private
/// key on one is nothing at all.
pub enum PrivateKey {
    /// `(p, q, e)` - the two primes and the public exponent, which is
    /// what `RsaPrivateKey::from_primes` wants. The CRT parameters in the
    /// file are deliberately **not** kept: they are derivable from these
    /// three, and a file whose stored `dP` disagrees with `d mod (p-1)`
    /// is a file that would sign wrongly in a way nothing checks.
    Rsa { p: BigUint, q: BigUint, e: BigUint },
    /// The curve as this library spells it, and the scalar big endian.
    Ec { curve: &'static str, private: Vec<u8> },
    /// An EdDSA key, RFC 8410. `curve` is `ed25519` or `ed448` and
    /// `private` is the raw seed - 32 or 57 bytes.
    ///
    /// **Not a scalar**, unlike `Ec`. EdDSA's signing scalar is the
    /// *hash* of these bytes, clamped, so this is a seed and the name
    /// says so. Storing it clamped, or reducing it mod the group order,
    /// would change which key it is.
    Eddsa { curve: &'static str, private: Vec<u8> },
    /// An X25519 or X448 key, RFC 8410: `curve` is `x25519` or `x448` and
    /// `private` the 32 or 56 bytes RFC 7748 calls the scalar, as stored:
    /// unclamped, since clamping is the function's first step, not the
    /// key's.
    Xdh { curve: &'static str, private: Vec<u8> },
    /// An ML-DSA key, RFC 9881. `parameter_set` is FIPS 204's name;
    /// `expanded` is the expanded private key, always present (computed
    /// from the seed when the file carried only that); `seed` is the 32
    /// byte seed when the file carried it.
    ///
    /// Whichever form arrived, the key has been checked for consistency
    /// before it gets here - see `ml_dsa_private_key`.
    MlDsa { parameter_set: &'static str, seed: Option<Vec<u8>>, expanded: Vec<u8> },
    /// A DSA key: the group, checked for structure, and `x`. From PKCS#8
    /// (RFC 5208 with RFC 3279's Dss-Parms) or OpenSSL's traditional
    /// `DSA PRIVATE KEY`, whose stored `y` is checked against `g^x`.
    Dsa { p: BigUint, q: BigUint, g: BigUint, x: BigUint },
}

/// Names the algorithm and the curve or parameter set, and never the
/// secret: a key in an `unwrap_err` message, a `panic!("{:?}")` in a
/// test or a Python `repr` gives nothing away. A derived `Debug` printed
/// `p`, `q`, the EC scalar, the EdDSA seed and the ML-DSA expanded key,
/// and `ssh::private_key::PrivateKey` already prints its public half
/// only; the two should not differ.
impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PrivateKey::Rsa { p, q, .. } =>
                write!(f, "PrivateKey(RSA {} bits)", p.bit_len() + q.bit_len()),
            PrivateKey::Ec { curve, .. } => write!(f, "PrivateKey(EC {})", curve),
            PrivateKey::Eddsa { curve, .. } => write!(f, "PrivateKey(EdDSA {})", curve),
            PrivateKey::Xdh { curve, .. } => write!(f, "PrivateKey(XDH {})", curve),
            PrivateKey::MlDsa { parameter_set, .. } =>
                write!(f, "PrivateKey({})", parameter_set),
            PrivateKey::Dsa { p, .. } =>
                write!(f, "PrivateKey(DSA {} bits)", p.bit_len()),
        }
    }
}

impl PrivateKey {
    /// The name of the algorithm, for a message.
    pub fn algorithm(&self) -> &'static str {
        match self {
            PrivateKey::Rsa { .. } => "RSA",
            PrivateKey::Ec { .. } => "EC",
            PrivateKey::Eddsa { .. } => "EdDSA",
            PrivateKey::Xdh { curve: "x25519", .. } => "X25519",
            PrivateKey::Xdh { .. } => "X448",
            PrivateKey::MlDsa { parameter_set, .. } => parameter_set,
            PrivateKey::Dsa { .. } => "DSA",
        }
    }
}

/// Parse a private key from PEM text or from raw DER.
///
/// **The bytes decide, not the label.** A PEM block's header is a hint
/// about which structure to try first and nothing more; a `PRIVATE KEY`
/// header over a SEC1 body is a real thing `openssl` produces, and
/// refusing it would be refusing a valid key on the strength of a comment.
///
/// A file with several blocks - the usual "certificate and key in one
/// file" - is fine: the first block that is a private key is used, and
/// certificates are skipped rather than being an error.
pub fn parse(data: &[u8]) -> Result<PrivateKey, String> {
    parse_with_password(data, None)
}

/// The same, with a passphrase for an encrypted key.
///
/// `None` means "this file had better not be encrypted", and produces an
/// error naming the passphrase as the remedy rather than a parse failure.
/// A passphrase supplied for a key that is *not* encrypted is ignored
/// rather than refused: a caller that always passes one should not have
/// to know which of its files were encrypted.
pub fn parse_with_password(data: &[u8], password: Option<&[u8]>)
                           -> Result<PrivateKey, String> {
    // PEM is text; DER starts with a SEQUENCE tag. Checking for the tag
    // rather than for printable text, because a DER file can contain
    // anything and a PEM one always begins with the dashes after
    // whitespace.
    if let Ok(text) = core::str::from_utf8(data) {
        if text.contains("-----BEGIN") {
            return from_pem_with_password(text, password);
        }
    }
    from_der_with_password(data, password)
}

/// Every private-key block in some PEM text, first one wins.
pub fn from_pem(text: &str) -> Result<PrivateKey, String> {
    from_pem_with_password(text, None)
}

/// The same, with a passphrase for an encrypted key.
pub fn from_pem_with_password(text: &str, password: Option<&[u8]>)
                              -> Result<PrivateKey, String> {
    let blocks = crate::pem::parse(text)?;
    if blocks.is_empty() {
        return Err("No PEM blocks found.".to_string());
    }
    let mut refused = Vec::new();
    for block in &blocks {
        let label = block.label.as_str();
        if !label.contains("PRIVATE KEY") {
            continue;
        }
        // The *structure* decides whether a block is encrypted, here as
        // everywhere - but when there is a label and it says ENCRYPTED
        // and no passphrase was given, that is what to say. Otherwise a
        // key that is encrypted *and* damaged comes back as three parse
        // failures about PKCS#8, SEC1 and PKCS#1, and sends the reader
        // looking for a corrupt file rather than for their password.
        if label.contains("ENCRYPTED") && password.is_none() {
            return Err("This key is encrypted (its PEM block says ENCRYPTED \
                        PRIVATE KEY) and no passphrase was given.".to_string());
        }
        match from_der_with_password(&block.contents, password) {
            Ok(key) => return Ok(key),
            Err(reason) => refused.push(format!("{}: {}", label, reason)),
        }
    }
    if refused.is_empty() {
        return Err(format!(
            "No private key in this PEM: found {}.",
            blocks.iter().map(|b| b.label.clone()).collect::<Vec<_>>().join(", ")));
    }
    Err(refused.join("; "))
}

/// One DER structure, in any of the three encodings.
///
/// Tried in the order they are distinguishable rather than in the order
/// they are common: PKCS#8's second element is an OCTET STRING where
/// PKCS#1's is an INTEGER and SEC1's is an OCTET STRING too - so PKCS#8
/// and SEC1 are told apart by their *first* element, a version followed by
/// an AlgorithmIdentifier versus a version followed by the key itself.
pub fn from_der(data: &[u8]) -> Result<PrivateKey, String> {
    from_der_with_password(data, None)
}

/// The same, with a passphrase for an encrypted key.
///
/// The encrypted case is tested *first* and by structure rather than by
/// the PEM label, because a DER file has no label and because a caller
/// that concatenated the wrong thing deserves a better answer than
/// three parse failures in a row.
pub fn from_der_with_password(data: &[u8], password: Option<&[u8]>)
                              -> Result<PrivateKey, String> {
    if super::encrypted_key::looks_encrypted(data) {
        let Some(password) = password else {
            // Named rather than lumped in with "not a private key",
            // because the remedy is a passphrase and not a different
            // file, and a reader told only "unsupported" will go
            // looking for the wrong thing.
            return Err("This key is encrypted (PKCS#8 EncryptedPrivateKeyInfo) \
                        and no passphrase was given.".to_string());
        };
        let plain = super::encrypted_key::decrypt(data, password)?;
        // The decrypted bytes are a PrivateKeyInfo, never another
        // encrypted layer - so this recurses with no password and
        // cannot loop.
        return from_der_with_password(&plain, None);
    }

    let mut errors = Vec::new();
    match pkcs8(data) {
        Ok(key) => return Ok(key),
        Err(reason) => errors.push(format!("not PKCS#8 ({})", reason)),
    }
    match sec1(data) {
        Ok(key) => return Ok(key),
        Err(reason) => errors.push(format!("not SEC1 EC ({})", reason)),
    }
    match pkcs1(data) {
        Ok(key) => return Ok(key),
        Err(reason) => errors.push(format!("not PKCS#1 RSA ({})", reason)),
    }
    match dsa_traditional(data) {
        Ok(key) => return Ok(key),
        Err(reason) => errors.push(format!("not a traditional DSA key ({})", reason)),
    }
    Err(errors.join("; "))
}

/// PKCS#8 (RFC 5208 section 5):
///
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///   version                   INTEGER,
///   privateKeyAlgorithm       AlgorithmIdentifier,
///   privateKey                OCTET STRING,
///   attributes           [0]  IMPLICIT Attributes OPTIONAL }
/// ```
pub(crate) fn pkcs8(data: &[u8]) -> Result<PrivateKey, String> {
    let mut outer = Reader::new(data);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;

    let version = sequence.read_u32()?;
    if version != 0 {
        // Version 1 is asymmetric key packages (RFC 5958), which adds a
        // public key field. Refused by name rather than read as a 0,
        // since the difference is a trailing field we would ignore.
        return Err(format!("PKCS#8 version {} is not v1 (0).", version));
    }
    let mut algorithm = sequence.read_sequence()?;
    let oid = algorithm.read_oid()?;
    // The parameters are algorithm-specific and optional. For EC they
    // carry the curve, which is *the* thing that makes the key usable, so
    // they are read here and handed down rather than skipped.
    let parameters = if algorithm.is_empty() { None } else {
        Some(algorithm.read_raw()?)
    };
    algorithm.finish()?;

    let inner = sequence.read_octet_string()?;
    // Attributes and the RFC 5958 public key may follow; both are
    // optional and neither changes the private key. Read past rather
    // than refused: a key `openssl` wrote with attributes is still that
    // key, and refusing it would be strictness with no safety in it.
    while !sequence.is_empty() {
        sequence.read_any()?;
    }

    let bytes = oid.as_bytes();
    if bytes == oids::RSA_ENCRYPTION {
        pkcs1(inner)
    } else if bytes == oids::EC_PUBLIC_KEY {
        // **The curve comes from the algorithm parameters here**, and
        // SEC1's own optional parameters field inside is a duplicate
        // that RFC 5915 section 3 says to leave out. A parser that
        // preferred the inner one would take the curve from the part an
        // attacker controls if the two ever disagreed.
        let curve = match parameters {
            Some(parameters) => Some(named_curve(parameters)?),
            None => None,
        };
        sec1_body(inner, curve)
    } else if [oids::ID_ED25519, oids::ID_ED448, oids::ID_X25519, oids::ID_X448]
        .contains(&bytes) {
        // RFC 8410's four algorithms share the encoding; only the length
        // and what the bytes are differ.
        let (curve, length) = match bytes {
            b if b == oids::ID_ED25519 => ("ed25519", 32),
            b if b == oids::ID_ED448 => ("ed448", 57),
            b if b == oids::ID_X25519 => ("x25519", 32),
            _ => ("x448", 56),
        };
        // RFC 8410 section 3 again: absent, not NULL.
        if parameters.is_some() {
            return Err(format!(
                "An {} private key must have absent AlgorithmIdentifier \
                 parameters (RFC 8410 section 3).", curve));
        }
        // **The key is wrapped twice.** RFC 8410 section 7 defines
        // `CurvePrivateKey ::= OCTET STRING`, and PKCS#8 then puts
        // *that* inside the privateKey OCTET STRING. So the seed is an
        // OCTET STRING inside an OCTET STRING, and a parser that
        // unwraps once gets 34 bytes beginning `04 20` - which is the
        // right length for nothing and the wrong key for everything.
        let mut reader = Reader::new(inner);
        let seed = reader.read_octet_string()?;
        reader.finish()?;
        if seed.len() != length {
            return Err(format!("An {} private key is {} bytes; got {}.",
                               curve, length, seed.len()));
        }
        Ok(if curve.starts_with('x') {
            PrivateKey::Xdh { curve, private: seed.to_vec() }
        } else {
            PrivateKey::Eddsa { curve, private: seed.to_vec() }
        })
    } else if bytes == oids::ID_DSA {
        // The group is in the AlgorithmIdentifier, as in a certificate;
        // the privateKey OCTET STRING holds `x` as an INTEGER.
        let parameters = parameters.ok_or(
            "A DSA private key with no Dss-Parms has no group to use.")?;
        let mut reader = Reader::new(parameters);
        let mut sequence = reader.read_sequence()?;
        reader.finish()?;
        let (p, q, g) = (sequence.read_integer()?, sequence.read_integer()?,
                         sequence.read_integer()?);
        sequence.finish()?;
        let mut reader = Reader::new(inner);
        let x = reader.read_integer()?;
        reader.finish()?;
        dsa_key(p, q, g, x, None)
    } else if let Some(parameter_set) = crate::x509::ml_dsa_parameter_set(bytes) {
        if parameters.is_some() {
            return Err(format!(
                "An {} private key must have absent AlgorithmIdentifier \
                 parameters (RFC 9881 section 2).", parameter_set));
        }
        ml_dsa_private_key(parameter_set, inner)
    } else {
        Err(format!("PKCS#8 algorithm {} is not RSA, EC, EdDSA, X25519, X448, ML-DSA or \
                     DSA.", oid))
    }
}

/// OpenSSL's traditional DSA key, PEM label `DSA PRIVATE KEY`:
///
/// ```text
/// SEQUENCE { version INTEGER (0), p, q, g, y, x INTEGER }
/// ```
///
/// No standard defines it; `openssl dsa` and `ssh-keygen` before
/// `openssh-key-v1` wrote it for two decades.
fn dsa_traditional(data: &[u8]) -> Result<PrivateKey, String> {
    let mut outer = Reader::new(data);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;
    if sequence.read_u32()? != 0 {
        return Err("version is not 0".to_string());
    }
    let p = sequence.read_integer()?;
    let q = sequence.read_integer()?;
    let g = sequence.read_integer()?;
    let y = sequence.read_integer()?;
    let x = sequence.read_integer()?;
    sequence.finish()?;
    dsa_key(p, q, g, x, Some(y))
}

/// A DSA key, with the group's structure and `x`'s range checked, and a
/// stored `y` - where the format has one - required to be `g^x`. A file
/// whose `y` disagrees signs as one key and claims another.
fn dsa_key(p: BigUint, q: BigUint, g: BigUint, x: BigUint, y: Option<BigUint>)
           -> Result<PrivateKey, String> {
    use crate::publickey_ciphers::dsa::{DsaParameters, DsaPrivateKey};
    let parameters = DsaParameters::new(p, q, g)?;
    let key = DsaPrivateKey::from_x(parameters, x)?;
    if let Some(y) = y {
        if y != key.public.y {
            return Err("DSA: the stored public key is not g^x.".to_string());
        }
    }
    let DsaParameters { p, q, g } = key.public.parameters.clone();
    Ok(PrivateKey::Dsa { p, q, g, x: key.x().clone() })
}

/// RFC 9881 section 6's `ML-DSA-*-PrivateKey`, a CHOICE told apart by
/// its tag and never by its length (the section says so):
///
/// ```text
/// seed        [0] IMPLICIT OCTET STRING (SIZE (32))      -- 0x80
/// expandedKey OCTET STRING                               -- 0x04
/// both        SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
/// ```
///
/// **Every form is checked for consistency, because each can lie.**
/// `both` can carry a seed and an expanded key that do not belong
/// together, and section 8.2 says to regenerate and compare. An
/// expanded key alone can carry a `tr` that is not the hash of its
/// public key, or a `t0` that `s1` and `s2` do not produce; recomputing
/// the public key from it (`ml_dsa::public_from_private`) checks both.
/// Appendix C.4 has one example of each, and all three are refused.
fn ml_dsa_private_key(parameter_set: &'static str, inner: &[u8])
                      -> Result<PrivateKey, String> {
    use crate::pq::ml_dsa;
    let parameters = ml_dsa::parameters(parameter_set)?;
    let expanded_len = parameters.private_key_len();
    let mut reader = Reader::new(inner);
    let (seed, expanded) = match reader.peek_tag() {
        Some(t) if t == Tag::context(0, false) =>
            (Some(reader.read_tagged(Tag::context(0, false))?), None),
        Some(t) if t == Tag::universal(tag::OCTET_STRING) =>
            (None, Some(reader.read_octet_string()?)),
        Some(t) if t == Tag::sequence() => {
            let mut both = reader.read_sequence()?;
            let seed = both.read_octet_string()?;
            let expanded = both.read_octet_string()?;
            both.finish()?;
            (Some(seed), Some(expanded))
        }
        _ => return Err(format!(
            "An {} private key is a [0] seed, an OCTET STRING or a SEQUENCE \
             of both (RFC 9881 section 6).", parameter_set)),
    };
    reader.finish()?;

    if let Some(seed) = seed {
        if seed.len() != 32 {
            return Err(format!("An {} seed is 32 bytes; got {}.", parameter_set, seed.len()));
        }
    }
    if let Some(expanded) = expanded {
        if expanded.len() != expanded_len {
            return Err(format!("An {} expanded private key is {} bytes; got {}.",
                               parameter_set, expanded_len, expanded.len()));
        }
    }
    match (seed, expanded) {
        (Some(seed), expanded) => {
            let (_, derived) = ml_dsa::key_gen_internal(parameters, seed)?;
            if let Some(expanded) = expanded {
                if derived != expanded {
                    return Err(format!(
                        "This {} private key's seed and expanded key do not \
                         belong together (RFC 9881 section 8.2).", parameter_set));
                }
            }
            Ok(PrivateKey::MlDsa { parameter_set, seed: Some(seed.to_vec()), expanded: derived })
        }
        (None, Some(expanded)) => {
            ml_dsa::public_from_private(parameters, expanded).map_err(|reason| format!(
                "This {} expanded private key is inconsistent: {}", parameter_set, reason))?;
            Ok(PrivateKey::MlDsa { parameter_set, seed: None, expanded: expanded.to_vec() })
        }
        (None, None) => unreachable!("every arm above reads one or both"),
    }
}

/// SEC1 (RFC 5915 section 3):
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) },
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL }
/// ```
fn sec1(data: &[u8]) -> Result<PrivateKey, String> {
    sec1_body(data, None)
}

fn sec1_body(data: &[u8], outer_curve: Option<&'static str>)
             -> Result<PrivateKey, String> {
    let mut outer = Reader::new(data);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;

    let version = sequence.read_u32()?;
    if version != 1 {
        return Err(format!("SEC1 version {} is not ecPrivkeyVer1 (1).", version));
    }
    let scalar = sequence.read_octet_string()?.to_vec();

    let mut inner_curve = None;
    while !sequence.is_empty() {
        let tag = sequence.peek_tag()
            .ok_or_else(|| "truncated SEC1 key".to_string())?;
        if tag == Tag::context(0, true) {
            let mut parameters = sequence.read_constructed(Tag::context(0, true))?;
            inner_curve = Some(named_curve(parameters.read_raw()?)?);
            parameters.finish()?;
        } else {
            // [1] publicKey, or anything a future version adds. The
            // public half is derivable from the scalar, so keeping it
            // would be keeping a second copy that can disagree.
            sequence.read_any()?;
        }
    }

    // **Two curves that disagree is a refusal, not a preference.**
    // RFC 5915 section 3 says the inner parameters field MUST be omitted
    // when an ECPrivateKey is carried inside PKCS#8, precisely so that
    // there is one answer. A file with both and a disagreement between
    // them is malformed, and picking either one is guessing which half
    // the writer meant - so it is an error, and one that says what the
    // two answers were.
    let curve = match (outer_curve, inner_curve) {
        (Some(outer), Some(inner)) if outer != inner => return Err(format!(
            "This key names two different curves: {} in the PKCS#8 algorithm \
             identifier and {} inside the key. RFC 5915 section 3 says the \
             inner one must be omitted there, so this file is malformed and \
             there is no way to tell which was meant.", outer, inner)),
        (Some(outer), _) => outer,
        (None, Some(inner)) => inner,
        (None, None) => return Err(
            "EC private key with no curve. \"Implicit\" and \"specified\" \
             curve parameters both mean the curve arrives from somewhere \
             else, and there is nowhere else here.".to_string()),
    };

    // The scalar's length is fixed by the curve (RFC 5915 section 3: it
    // is ceil(log2(n)/8) octets), so a short one is left-padded rather
    // than refused - `openssl` has written short ones - and a long one is
    // an error, because it is not this curve's key.
    let handle = crate::ec::curves::by_name(curve)?;
    let width = handle.scalar_bytes();
    if scalar.len() > width {
        return Err(format!(
            "The private scalar is {} bytes; {} holds {}.",
            scalar.len(), curve, width));
    }
    let mut private = vec![0u8; width - scalar.len()];
    private.extend_from_slice(&scalar);

    let value = BigUint::from_bytes_be(&private);
    if value.is_zero() || value >= handle.n {
        return Err("The private scalar is not in [1, n).".to_string());
    }
    Ok(PrivateKey::Ec { curve, private })
}

/// PKCS#1 (RFC 8017 A.1.2):
///
/// ```text
/// RSAPrivateKey ::= SEQUENCE {
///   version, modulus, publicExponent, privateExponent,
///   prime1, prime2, exponent1, exponent2, coefficient }
/// ```
///
/// Only `publicExponent`, `prime1` and `prime2` are kept. Everything else
/// is derivable from them, and a file whose stored `d` or `dP` disagrees
/// with what they imply would otherwise produce signatures that fail in a
/// way nothing here would explain.
fn pkcs1(data: &[u8]) -> Result<PrivateKey, String> {
    let mut outer = Reader::new(data);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;

    let version = sequence.read_u32()?;
    if version != 0 {
        // Version 1 is a multi-prime key. Refused rather than read as
        // two-prime, because `prime1` and `prime2` of a three-prime key
        // are a perfectly well-formed pair that computes the wrong
        // thing.
        return Err(format!(
            "PKCS#1 version {} is a multi-prime key, which this library does \
             not implement.", version));
    }
    let modulus = sequence.read_integer()?;
    let e = sequence.read_integer()?;
    let _d = sequence.read_integer()?;
    let p = sequence.read_integer()?;
    let q = sequence.read_integer()?;
    // exponent1, exponent2, coefficient - read to check they are there
    // and well formed, then discarded for the reason in the doc comment.
    let _dp = sequence.read_integer()?;
    let _dq = sequence.read_integer()?;
    let _qinv = sequence.read_integer()?;
    // otherPrimeInfos, only present for version 1, which is refused above.
    sequence.finish()?;

    if p.is_zero() || q.is_zero() {
        return Err("An RSA prime is zero.".to_string());
    }
    // The modulus is not kept, but it is the one number in the file
    // that names *which* key this is - the certificate beside it
    // carries the same `n` - so the primes have to multiply back to
    // it, or the key signs as something the certificate does not name.
    // `ssh::private_key` makes the same check on its RSA section.
    if p.mul(&q) != modulus {
        return Err("The RSA primes in this file do not multiply to its \
                    modulus.".to_string());
    }
    Ok(PrivateKey::Rsa { p, q, e })
}

/// A named-curve OID, as this library spells the curve.
fn named_curve(parameters: &[u8]) -> Result<&'static str, String> {
    let mut reader = Reader::new(parameters);
    let oid = reader.read_oid()
        .map_err(|_| "EC parameters are not a named curve OID.".to_string())?;
    reader.finish()?;
    match oid.as_bytes() {
        b if b == oids::PRIME256V1 => Ok("P-256"),
        b if b == oids::SECP384R1 => Ok("P-384"),
        b if b == oids::SECP521R1 => Ok("P-521"),
        b if b == oids::SECP256K1 => Ok("secp256k1"),
        _ => Err(format!(
            "The curve {} is not one this library computes on.", oid)),
    }
}

/// The tag module is used for nothing else here; naming it keeps the
/// import honest rather than pulling in a wildcard.
const _: u32 = tag::SEQUENCE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_functions::HashFunction;

    /// `{:?}` on a private key names the algorithm and nothing else.
    ///
    /// What was wrong: `PrivateKey` derived `Debug`, so every
    /// `panic!("{:?}", key)` in these tests, every `unwrap_err` that
    /// carried one and any Python `repr` wrote the primes, the EC
    /// scalar or the EdDSA seed to the log. Nothing tested the format
    /// because nothing had a reason to read it. The hand-written impl
    /// is checked by formatting a key whose secret is a byte pattern
    /// that cannot appear in the output by accident.
    #[test]
    fn test_debug_names_the_algorithm_and_hides_the_secret() {
        let secret = vec![0xAB; 32];
        let key = PrivateKey::Ec { curve: "p256", private: secret.clone() };
        let text = format!("{:?}", key);
        assert_eq!(text, "PrivateKey(EC p256)");
        assert!(!text.contains("171"), "{}", text);       // 0xAB in decimal
        assert!(!text.to_lowercase().contains("ab"), "{}", text);

        let key = PrivateKey::Rsa {
            p: BigUint::from_u64(0xC5A3), q: BigUint::from_u64(0xD7B1),
            e: BigUint::from_u64(65537),
        };
        let text = format!("{:?}", key);
        assert_eq!(text, "PrivateKey(RSA 32 bits)");
        assert!(!text.contains("c5a3") && !text.contains("50595"), "{}", text);

        let key = PrivateKey::Eddsa { curve: "ed25519", private: secret.clone() };
        assert_eq!(format!("{:?}", key), "PrivateKey(EdDSA ed25519)");
        let key = PrivateKey::Xdh { curve: "x448", private: secret.clone() };
        assert_eq!(format!("{:?}", key), "PrivateKey(XDH x448)");
        let key = PrivateKey::MlDsa { parameter_set: "ML-DSA-44", seed: Some(secret.clone()),
                                      expanded: secret.clone() };
        assert_eq!(format!("{:?}", key), "PrivateKey(ML-DSA-44)");
        let key = PrivateKey::Dsa { p: BigUint::from_u64(0xC5A3), q: BigUint::from_u64(3),
                                    g: BigUint::from_u64(2), x: BigUint::from_u64(0xAB) };
        assert_eq!(format!("{:?}", key), "PrivateKey(DSA 16 bits)");
    }

    /// Written by `openssl genpkey -algorithm EC -pkeyopt
    /// ec_paramgen_curve:P-256`, then checked against the scalar
    /// `openssl ec -text` prints. Vectors rather than a round trip
    /// through our own encoder, because this library has no private-key
    /// *encoder* - so a round trip would check nothing at all.
    const P256_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+W/eH4hMK1tfGdl7
YYjE0Z70hh58zD5VZtXo7xOguU2hRANCAARxW1B1BLklWHhiqoXa2b5V7kcj3n9T
uUqf9i2EYI+MZoZn7jmDObE6grRz8qmpLGI/0DbIEczkW1ejYypl+Fvf
-----END PRIVATE KEY-----";

    const P256_SEC1: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPlv3h+ITCtbXxnZe2GIxNGe9IYefMw+VWbV6O8ToLlNoAoGCCqGSM49
AwEHoUQDQgAEcVtQdQS5JVh4YqqF2tm+Ve5HI95/U7lKn/YthGCPjGaGZ+45gzmx
OoK0c/KpqSxiP9A2yBHM5FtXo2MqZfhb3w==
-----END EC PRIVATE KEY-----";

    /// The same scalar, which is the point: two encodings, one key.
    ///
    /// **Both files came out of `openssl`, and so did this number.** The
    /// first version of this test used vectors typed from memory: they
    /// parsed, they agreed with each other, and `openssl pkey` refused
    /// both. A private-key parser that never looks at the public half
    /// will accept a well-shaped forgery, so the vectors have to be
    /// real - and `pytests/test_private_key.py` puts every one of them
    /// through python-cryptography as well.
    const P256_SCALAR: &str =
        "f96fde1f884c2b5b5f19d97b6188c4d19ef4861e7ccc3e5566d5e8ef13a0b94d";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_pkcs8_and_sec1_give_the_same_key() {
        // **The whole reason both are parsed.** An operator's key is in
        // whichever one the tool that made it writes, and the two are
        // different structures carrying the same scalar; a parser that
        // got one of them subtly wrong would still produce a key of the
        // right length on the right curve.
        for text in [P256_PKCS8, P256_SEC1] {
            match parse(text.as_bytes()).unwrap() {
                PrivateKey::Ec { curve, private } => {
                    assert_eq!(curve, "P-256");
                    assert_eq!(hex(&private), P256_SCALAR, "{}", text);
                }
                other => panic!("expected an EC key, got {:?}", other),
            }
        }
    }

    /// The label is a hint. `openssl` will put a SEC1 body under a
    /// `PRIVATE KEY` header if asked the wrong way, and a file that
    /// works everywhere else must work here.
    #[test]
    fn test_the_label_does_not_decide() {
        let der = crate::pem::parse(P256_SEC1).unwrap()[0].contents.clone();
        let relabelled = crate::pem::wrap("PRIVATE KEY", &der);
        match parse(relabelled.as_bytes()).unwrap() {
            PrivateKey::Ec { private, .. } => assert_eq!(hex(&private), P256_SCALAR),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn test_raw_der_works_without_a_wrapper() {
        let der = crate::pem::parse(P256_PKCS8).unwrap()[0].contents.clone();
        match parse(&der).unwrap() {
            PrivateKey::Ec { private, .. } => assert_eq!(hex(&private), P256_SCALAR),
            other => panic!("{:?}", other),
        }
    }

    /// An encrypted key is a different structure and a different
    /// remedy - a passphrase, not another file - so it is named rather
    /// than lumped in with "unsupported".
    ///
    /// The body here is a stub rather than a real encrypted key, which
    /// is the point: this is the *label* path. Recognition is otherwise
    /// structural, so a block that says ENCRYPTED and holds something
    /// damaged would fall through to three parse failures about PKCS#8,
    /// SEC1 and PKCS#1 - sending the reader after a corrupt file rather
    /// than after their password. Real encrypted keys, every scheme, are
    /// in `tests/test_encrypted_keys.rs`.
    #[test]
    fn test_an_encrypted_key_says_so() {
        let text = crate::pem::wrap("ENCRYPTED PRIVATE KEY", &[0x30, 0x00]);
        let failure = parse(text.as_bytes()).unwrap_err();
        assert!(failure.contains("encrypted"), "{}", failure);
        assert!(failure.contains("passphrase"), "{}", failure);
    }

    #[test]
    fn test_a_certificate_is_not_a_private_key() {
        let text = crate::pem::wrap("CERTIFICATE", &[0x30, 0x00]);
        let failure = parse(text.as_bytes()).unwrap_err();
        assert!(failure.contains("CERTIFICATE"), "{}", failure);
    }

    /// A key and its certificate in one file is the normal deployment
    /// shape, and the certificate must be skipped rather than tried.
    #[test]
    fn test_a_combined_file_finds_the_key() {
        let mut text = crate::pem::wrap("CERTIFICATE", &[0x30, 0x00]);
        text.push_str(P256_PKCS8);
        match parse(text.as_bytes()).unwrap() {
            PrivateKey::Ec { private, .. } => assert_eq!(hex(&private), P256_SCALAR),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn test_a_curve_we_cannot_compute_on_is_refused() {
        // secp224r1: 1.3.132.0.33. Real, and not implemented here. A
        // private key we cannot use is an error rather than a variant,
        // unlike a *public* key in a certificate, which is still a link
        // in a chain.
        let parameters = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21];
        let failure = named_curve(&parameters).unwrap_err();
        assert!(failure.contains("1.3.132.0.33"), "{}", failure);
    }

    #[test]
    fn test_a_scalar_outside_the_group_is_refused() {
        // Zero, which is not a private key on any curve and would make
        // every signature the same.
        let mut body = vec![0x02, 0x01, 0x01,           // version 1
                            0x04, 32];                  // an OCTET STRING of
        body.extend_from_slice(&[0u8; 32]);             // thirty-two zeros
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        let failure = sec1_body(&der, Some("P-256")).unwrap_err();
        assert!(failure.contains("[1, n)"), "{}", failure);
    }

    /// Generated with `openssl genrsa 1024`, kept small so the test is
    /// fast. The primes are checked by multiplying them back to the
    /// modulus the file also carries - which is the one cross-check a
    /// single key can give itself.
    const RSA_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC9v1M6baFrGpucInGytBP5hBRjSmZq+h8Q0x0p2WYxDq2MFbQj
VrbsL70WnkOmRg+XNpLZtb2Vi92HI3nCQHmVJ6TBLtmaLMTdRwZ2pEH4K4WPXWvx
qaUVomHaisqEWX7DUPPqJhsEBtdYxoCTPpZmjG8Q/d2T8o9E9zeq4HgT/wIDAQAB
AoGAMn/TBL/csAaa14kLPYZTspqGWo6Yh2weDHpDTrn/SpsfcSLtmGIhuOZTqstg
McZ/q7zohGysEjrxMGAurZY/RQ88WtnbRThW1ylLA5KWBaLwfVav7e/R2GzT/lN9
YLv7W71a2oB87owZUgYnzqhmzMQedrXpPXHSS7DTHT1sAyECQQDyIgr9TUkfhgjz
/DXcpVFC7aAi9O/Zsu1hngSSF73+AB5TBUa8Iay3eTBWncwj0QRSAKkfmlWrwGht
18r4z0+XAkEAyJ0/MAUYI6RYJzYYimn0ID9lvoqMR+QuUcjPI7T5HuBelus0umJT
oCc0ZFoe9ZZAsSbi25eWh6BfB6zAwILr2QJAVPBYRo9sDWDplx1sj6B2pzHQsTKX
SRkZaNsT42PsxEOqX5lEPQ7bFemvaVMln5LdHx8YNPvg/cUbXR0MGMgwtQJAfQIv
i7bA8gTIwbZd2HJpo2ad+fvPqkSv8FqXaQKuceUSTCzIsJPw1E1Zwma9//7e1QUM
PBXbwSvXy6qEefGbEQJBANkBQfPep3iliqJa2VvL4e3OUk8WNZj/aQV/x431gqpv
WPZgS6eMXByVI7jPpxcRsxIZ8jpzTeEeau2/n5worYk=
-----END RSA PRIVATE KEY-----";

    /// The same RSA key wrapped in PKCS#8, which is what `openssl
    /// genrsa` writes by default now.
    const RSA_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL2/UzptoWsam5wi
cbK0E/mEFGNKZmr6HxDTHSnZZjEOrYwVtCNWtuwvvRaeQ6ZGD5c2ktm1vZWL3Ycj
ecJAeZUnpMEu2ZosxN1HBnakQfgrhY9da/GppRWiYdqKyoRZfsNQ8+omGwQG11jG
gJM+lmaMbxD93ZPyj0T3N6rgeBP/AgMBAAECgYAyf9MEv9ywBprXiQs9hlOymoZa
jpiHbB4MekNOuf9Kmx9xIu2YYiG45lOqy2Axxn+rvOiEbKwSOvEwYC6tlj9FDzxa
2dtFOFbXKUsDkpYFovB9Vq/t79HYbNP+U31gu/tbvVragHzujBlSBifOqGbMxB52
tek9cdJLsNMdPWwDIQJBAPIiCv1NSR+GCPP8NdylUULtoCL079my7WGeBJIXvf4A
HlMFRrwhrLd5MFadzCPRBFIAqR+aVavAaG3XyvjPT5cCQQDInT8wBRgjpFgnNhiK
afQgP2W+ioxH5C5RyM8jtPke4F6W6zS6YlOgJzRkWh71lkCxJuLbl5aHoF8HrMDA
guvZAkBU8FhGj2wNYOmXHWyPoHanMdCxMpdJGRlo2xPjY+zEQ6pfmUQ9DtsV6a9p
UyWfkt0fHxg0++D9xRtdHQwYyDC1AkB9Ai+LtsDyBMjBtl3YcmmjZp35+8+qRK/w
WpdpAq5x5RJMLMiwk/DUTVnCZr3//t7VBQw8FdvBK9fLqoR58ZsRAkEA2QFB896n
eKWKolrZW8vh7c5STxY1mP9pBX/HjfWCqm9Y9mBLp4xcHJUjuM+nFxGzEhnyOnNN
4R5q7b+fnCitiQ==
-----END PRIVATE KEY-----";

    #[test]
    fn test_a_pkcs1_rsa_key_parses_and_its_primes_multiply_back() {
        // Both encodings of the same key, so a parser that got the
        // PKCS#8 unwrapping wrong cannot pass by reading the inner
        // structure of something else.
        let (a, b) = (parse(RSA_PKCS1.as_bytes()).unwrap(),
                      parse(RSA_PKCS8.as_bytes()).unwrap());
        match (&a, &b) {
            (PrivateKey::Rsa { p: p1, q: q1, .. },
             PrivateKey::Rsa { p: p2, q: q2, .. }) => {
                assert_eq!(p1, p2);
                assert_eq!(q1, q2);
            }
            _ => panic!("expected two RSA keys"),
        }
        match a {
            PrivateKey::Rsa { p, q, e } => {
                assert_eq!(e.to_u64(), Some(65537));
                // The modulus is in the file and is discarded, so this
                // is the check that the two primes are the file's own
                // rather than any two integers that happened to parse.
                let n = p.mul(&q);
                assert_eq!(n.bit_len(), 1024);
                // And the key really works: sign something and verify
                // it with the public half derived from these numbers.
                let key = crate::publickey_ciphers::rsa::RsaPrivateKey::from_primes(
                    p, q, e).unwrap();
                let mut hasher = crate::api::AnyHash::new("sha256").unwrap();
                hasher.update(b"a private key that parses but does not work \
                                is worse than one that does not parse");
                let digest = hasher.digest();
                let signature = crate::publickey_ciphers::rsa::sign_pkcs1v15(
                    &key, "sha256", &digest).unwrap();
                assert!(crate::publickey_ciphers::rsa::verify_pkcs1v15(
                    &key.public, "sha256", &digest, &signature).unwrap());
            }
            other => panic!("expected an RSA key, got {:?}", other),
        }
    }

    /// A file whose primes do not multiply to its modulus is refused.
    ///
    /// What was wrong: `pkcs1` read the modulus and dropped it, so a
    /// file whose `p` and `q` were not the factors of its `n` parsed
    /// to a key that signs as a different key from the one the matching
    /// certificate names - and nothing checked, since the CRT values
    /// are recomputed from the primes. The `openssh-key-v1` reader
    /// makes this check and the test above does it by hand; the
    /// parser now does it. Built by editing the real key: the trailing
    /// byte of `n` is changed, which cannot alter the INTEGER's
    /// encoding.
    #[test]
    fn test_a_pkcs1_modulus_that_is_not_p_times_q_is_refused() {
        let der = crate::pem::parse(RSA_PKCS1).unwrap()[0].contents.clone();
        let mut outer = Reader::new(&der);
        let mut sequence = outer.read_sequence().unwrap();
        let mut fields: Vec<Vec<u8>> = Vec::new();
        while !sequence.is_empty() {
            fields.push(sequence.read_integer_bytes().unwrap().to_vec());
        }
        assert_eq!(fields.len(), 9);
        *fields[1].last_mut().unwrap() ^= 0x01;   // the modulus's last byte

        let mut writer = crate::asn1::Writer::new();
        writer.write_sequence(|w| {
            for field in &fields {
                w.write_tlv(Tag::universal(tag::INTEGER), field);
            }
        });
        let edited = crate::pem::wrap("RSA PRIVATE KEY", &writer.finish());
        let error = parse(edited.as_bytes()).unwrap_err();
        assert!(error.contains("do not multiply"), "{}", error);
    }

    /// RFC 5915 section 3 fixes the OCTET STRING at the curve's width,
    /// but shorter ones exist in the wild and `PrivateKey::Ec` promises
    /// a padded scalar - a Rust caller gets these bytes directly rather
    /// than through `EcKey::from_private`, which would pad them again.
    ///
    /// **The Python tests cannot see this**, which is why it is here:
    /// `EcKey::private_bytes` pads to the field size on the way out, so
    /// a parser that returned a short scalar looks identical from there.
    /// The deliberate-breakage sweep found exactly that.
    #[test]
    fn test_a_short_scalar_comes_back_padded() {
        // A P-256 key whose scalar is one byte short: 0x01 repeated 31
        // times, which is a perfectly good private value.
        let mut body = vec![0x02, 0x01, 0x01,           // version 1
                            0x04, 31];                  // 31 octets
        body.extend_from_slice(&[0x01; 31]);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        match sec1_body(&der, Some("P-256")).unwrap() {
            PrivateKey::Ec { private, .. } => {
                assert_eq!(private.len(), 32, "not padded to the curve");
                assert_eq!(private[0], 0x00);
                assert_eq!(&private[1..], &[0x01; 31]);
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn test_a_truncated_key_is_an_error_not_a_panic() {
        let der = crate::pem::parse(P256_PKCS8).unwrap()[0].contents.clone();
        for cut in 1..der.len() {
            assert!(from_der(&der[..cut]).is_err(), "accepted {} bytes", cut);
        }
    }
}
