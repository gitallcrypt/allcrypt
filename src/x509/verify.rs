/*
Certificate verification: signatures, then chains, then names.

The split from parsing is deliberate. Parsing answers "what does this say";
this answers "should I believe it", and the second question has answers that
depend on time, on policy, and on who is asking.

The order things are checked in matters more than it looks. The rule
throughout is **cheap and decisive before expensive**: a name that does not
match, a validity window that has passed, a basicConstraints that says this
is not a CA - all of those are decided before any signature is verified,
because a signature check is milliseconds and an attacker controls how many
certificates they send.

The failure mode this code is most careful about is the one where a chain
*almost* verifies. Every check returns a reason, and a chain is only
accepted when every check passed for every link. There is no path through
this file where an error becomes a warning.

Name constraints are enforced, in `name_constraints.rs`, and they are the
one check that needs the whole path at once - so `verify_chain` runs them
after a trusted root has been chosen rather than per link.

Revocation is in `crl.rs` and `ocsp.rs` and reached through
`verify_chain_with_revocation`. It is a separate entry point because
nothing in this library fetches anything - the caller brings the
evidence, and `crl::distribution_points` and `ocsp::responder_urls` say
where to get it.

What is deliberately not here yet: policy constraints. Each is
noted where it belongs, and each is in docs/pitfalls.md rather than only
in a comment - a missing check that nobody wrote down is a missing check
nobody will add.
*/

use crate::bignum::BigUint;
use crate::ec::{curves, Point, Signature};
use crate::hash_functions::HashFunction;
use crate::hash_functions::streebog::Streebog;
use crate::publickey_ciphers::rsa;
use crate::x509::{crl, name_constraints, ocsp, oids, Certificate, GeneralName,
                  PublicKey, SignatureAlgorithm};

/// How a chain may be used. This is not decoration: a CA certificate that
/// happens to be in a chain must not be usable as a server certificate, and
/// a server certificate must not be able to sign another one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    ServerAuth,
    ClientAuth,
    /// Check the chain's structure and signatures but no usage bits. For
    /// inspecting a chain rather than trusting it.
    Any,
}

/// What a caller is willing to accept. Defaults are the modern answers;
/// every field exists because somebody has to talk to something old, which
/// is the whole reason this library exists.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Seconds since the Unix epoch. Passed in rather than read from a
    /// clock, so verification is a pure function and can be tested at any
    /// point in time.
    pub now: i64,
    /// Accept SHA-1 signatures. Off by default: SHA-1 collisions are
    /// practical, and a collision is a forged certificate.
    pub allow_sha1: bool,
    /// Accept MD5 signatures. Off by default, and the reason is Flame - a
    /// real forged Microsoft code-signing certificate, built on an MD5
    /// collision, in 2012.
    pub allow_md5: bool,
    /// Accept a certificate outside its validity window.
    ///
    /// Off by default. On, because it is the single most common reason a
    /// box that has sat in a rack since 2011 cannot be reached: its
    /// certificate expired years ago and there is nobody left to reissue
    /// it. Refusing is right for the public web and useless for that.
    ///
    /// This relaxes the dates and **nothing else**: the chain still has to
    /// reach a trusted root, the signatures still have to verify, and the
    /// name still has to match unless that is turned off separately. An
    /// expired certificate from the right CA is a different thing from an
    /// unverified one, and conflating them is how "just make it work"
    /// becomes "no authentication at all".
    pub allow_expired: bool,
    /// Smallest RSA modulus, in bits. 1024 is factorable by a
    /// well-resourced attacker; 2048 is the modern floor.
    pub min_rsa_bits: usize,
    /// How long a chain may be, counting the leaf and the root.
    pub max_chain_length: usize,
    /// Refuse a chain whose revocation status could not be established.
    ///
    /// Off by default, which is **soft fail**: a chain verifies when no
    /// CRL was supplied, or when the one supplied was stale or covered
    /// the wrong part of the space. On, it is hard fail.
    ///
    /// This is a deployment decision rather than a cryptographic one,
    /// which is why it is a flag and why it is not on by default.
    /// Nothing in this library fetches a CRL - no socket is opened
    /// anywhere in it - so with hard fail on, every chain fails until
    /// the caller has gone and got the CRL itself. That is right for a
    /// machine issuing money and wrong for one that has to reach a box
    /// in a rack whose distribution point stopped answering in 2014.
    ///
    /// A *revoked* certificate is refused either way. This flag only
    /// decides what an absence of evidence means.
    pub require_revocation: bool,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            now: 0,
            allow_sha1: false,
            allow_md5: false,
            allow_expired: false,
            min_rsa_bits: 2048,
            max_chain_length: 10,
            require_revocation: false,
        }
    }
}

impl Policy {
    /// A policy that accepts what an old server is likely to present.
    ///
    /// This exists because refusing to connect is not always an option -
    /// the server is not ours to upgrade. It is a separate constructor, and
    /// named, so that using it is a decision somebody made rather than a
    /// default somebody inherited.
    pub fn legacy(now: i64) -> Policy {
        Policy {
            now,
            allow_sha1: true,
            allow_md5: true,
            // The mildest of these relaxations, and the most often needed:
            // a box nobody has logged into since 2011 has a certificate
            // that ran out long ago. Milder than the MD5 and 512 bit RSA
            // this constructor already accepts.
            allow_expired: true,
            min_rsa_bits: 512,
            max_chain_length: 10,
            // Soft fail, like the default. A box this constructor
            // exists for is one whose CRL distribution point has been
            // unreachable for a decade.
            require_revocation: false,
        }
    }

    pub fn at(now: i64) -> Policy {
        Policy { now, ..Policy::default() }
    }

    /// The same gate as `accepts_hash`, for callers outside this module -
    /// the TLS handshake has its own signatures to check and must apply
    /// the same policy to them.
    pub fn accepts_hash_public(&self, hash: &str) -> Result<(), String> {
        self.accepts_hash(hash)
    }

    fn accepts_hash(&self, hash: &str) -> Result<(), String> {
        match hash {
            "md5" if !self.allow_md5 =>
                Err("Signed with MD5, which is collision-broken. Set \
                     allow_md5 if you must accept it.".to_string()),
            "sha1" if !self.allow_sha1 =>
                Err("Signed with SHA-1, which is collision-broken. Set \
                     allow_sha1 if you must accept it.".to_string()),
            _ => Ok(()),
        }
    }
}

// ------------------------------------------------------------- signatures ---

/// Verify that `certificate` was signed by `issuer`'s key.
///
/// This is the one operation everything else rests on, so it is deliberately
/// small enough to read in one go. It hashes the TBS bytes exactly as they
/// arrived - not a re-encoding - and hands them to the same verifiers the
/// rest of the library uses.
pub fn verify_signature(certificate: &Certificate<'_>, issuer: &Certificate<'_>,
                        policy: &Policy) -> Result<(), String> {
    verify_signed(certificate.tbs, certificate.signature_algorithm,
                  certificate.signature, &issuer.public_key, policy)
}

/// The same, over any signed DER body.
///
/// A CRL is signed exactly as a certificate is - the same algorithm
/// identifiers, the same encodings, the same key - so `crl.rs` calls
/// this rather than growing a second copy. A second copy is how the two
/// end up disagreeing about which hash a signature used, and the one
/// that is wrong is whichever gets less use.
///
/// `signed` is the exact bytes the signature covers, tag and length
/// included, as they arrived. Never a re-encoding.
pub fn verify_signed(signed: &[u8], algorithm: SignatureAlgorithm,
                     signature: &[u8], key: &PublicKey<'_>, policy: &Policy)
                     -> Result<(), String> {
    // GOST leaves first: its digest is Streebog, which `AnyHash` does
    // not name, and the signature is read little endian afterwards - so
    // there is no hash name to hand the shared path below.
    if let SignatureAlgorithm::Gost(bits) = algorithm {
        return verify_gost(signed, signature, key, bits, policy);
    }
    if algorithm == SignatureAlgorithm::Gost2001 {
        return verify_gost_2001(signed, signature, key, policy);
    }

    // EdDSA next, and for the same reason as GOST: there is no digest
    // to compute. RFC 8032 hashes the message inside the scheme, with a
    // prefix that depends on the variant, so a verifier that hashed
    // first and handed the digest over would be signing a hash of a
    // hash - self-consistent, and matching nobody.
    if let SignatureAlgorithm::Eddsa(variant) = algorithm {
        return verify_eddsa(signed, signature, key, variant, policy);
    }
    // ML-DSA likewise signs the message, not a digest of it.
    if let SignatureAlgorithm::MlDsa(parameter_set) = algorithm {
        return verify_ml_dsa(signed, signature, key, parameter_set);
    }

    let hash_name = match algorithm {
        SignatureAlgorithm::RsaPkcs1(hash) | SignatureAlgorithm::Ecdsa(hash)
            | SignatureAlgorithm::Dsa(hash) => hash,
        other => return Err(format!("Cannot verify a signature made with {}.",
                                    other.describe())),
    };
    policy.accepts_hash(hash_name)?;

    let digest = digest_of(hash_name, signed)?;

    match (key, algorithm) {
        (PublicKey::Rsa { n, e }, SignatureAlgorithm::RsaPkcs1(_)) => {
            if n.bit_len() < policy.min_rsa_bits {
                return Err(format!("Issuer's RSA key is {} bits; the policy \
                                    requires at least {}.",
                                   n.bit_len(), policy.min_rsa_bits));
            }
            let key = rsa::RsaPublicKey::new(n.clone(), e.clone())?;
            if rsa::verify_pkcs1v15(&key, hash_name, &digest, signature)? {
                Ok(())
            } else {
                Err("Signature does not verify against the issuer's RSA key."
                    .to_string())
            }
        }
        (PublicKey::Ec { curve, point }, SignatureAlgorithm::Ecdsa(_)) => {
            let curve = curves::by_name(curve)?;
            let public = curve.decode_point(point)?;
            // A certificate carries an ECDSA signature as a DER SEQUENCE of
            // two INTEGERs, not as the fixed-width r||s that TLS 1.3 uses.
            let signature = decode_ecdsa_der(signature)?;
            if curve.verify(&public, &digest, &signature)? {
                Ok(())
            } else {
                Err("Signature does not verify against the issuer's EC key."
                    .to_string())
            }
        }
        (PublicKey::Dsa { parameters, y }, SignatureAlgorithm::Dsa(_)) => {
            let key = dsa_public_key(parameters, y, policy)?;
            // Dss-Sig-Value is ECDSA's SEQUENCE { r, s } exactly.
            let signature = decode_ecdsa_der(signature)?;
            if key.verify(&digest, &signature.r, &signature.s)? {
                Ok(())
            } else {
                Err("Signature does not verify against the issuer's DSA key."
                    .to_string())
            }
        }
        (key, algorithm) => Err(format!(
            "Issuer's key ({}) cannot verify a signature made with {}.",
            describe_key(key), algorithm.describe())),
    }
}

/// A certificate's DSA key, checked for structure and size.
///
/// `p` is held to `min_rsa_bits`: both are finite-field problems of the
/// same kind, and a 1024 bit DSA group falls to the same effort as a
/// 1024 bit RSA modulus. An appliance with a 1024 bit key is reached by
/// lowering that one number, as for RSA.
pub(crate) fn dsa_public_key(parameters: &Option<(BigUint, BigUint, BigUint)>, y: &BigUint,
                             policy: &Policy)
                             -> Result<crate::publickey_ciphers::dsa::DsaPublicKey, String> {
    use crate::publickey_ciphers::dsa::{DsaParameters, DsaPublicKey};
    let (p, q, g) = parameters.as_ref().ok_or(
        "This DSA key inherits its group from its issuer (RFC 3279 section \
         2.3.2), which this verifier does not follow.")?;
    if p.bit_len() < policy.min_rsa_bits {
        return Err(format!("The DSA key's group is {} bits; the policy requires at \
                            least {} (min_rsa_bits, which applies to DSA's p too).",
                           p.bit_len(), policy.min_rsa_bits));
    }
    DsaPublicKey::new(DsaParameters::new(p.clone(), q.clone(), g.clone())?, y.clone())
}

/// An EdDSA signature on a certificate, RFC 8410 section 6.
///
/// The signature is the raw 64 (or 114) bytes **inside** the BIT
/// STRING, not a DER SEQUENCE of two INTEGERs the way ECDSA's is. Three
/// encodings of one idea sit next to each other in this file - ECDSA's
/// SEQUENCE, GOST's fixed-width `s || r`, and this - and each is the
/// obvious reading of the other two's neighbour.
fn verify_eddsa(signed: &[u8], signature: &[u8], key: &PublicKey<'_>,
                variant: &'static str, _policy: &Policy) -> Result<(), String> {
    let (curve, key_bytes) = match key {
        PublicKey::Eddsa { curve, key } => (*curve, *key),
        other => return Err(format!(
            "Issuer's key ({}) cannot verify an EdDSA signature.",
            describe_key(other))),
    };

    // **The OID names the algorithm twice and both must agree.** An
    // Ed448 key with an Ed25519 signature OID is a signature being
    // checked under a scheme nobody used; refusing it by name gives an
    // error that says so, where letting it through gives "does not
    // verify".
    if curve != variant {
        return Err(format!(
            "The signature says {} and the issuer's key is {}.", variant, curve));
    }

    // No `Policy::accepts_hash` call, deliberately. The hash is inside
    // the scheme and is not a choice: Ed25519 is SHA-512 and Ed448 is
    // SHAKE256, always. A policy that refused SHA-512 would be refusing
    // a curve rather than a digest, and `Policy` has no opinion on
    // curves - see the note in `verify_gost` about the key-size floor
    // that can never fire.
    // **No length check here.** `eddsa_verify` makes the same one, with
    // the same wording, so a copy of it was not defence in depth - it
    // was a second place for the message to drift from. The sweep found
    // it: removing this check failed no test even after a test was
    // written to pin the message, because the message came back
    // identical from one layer down.
    if crate::api::eddsa_verify(variant, key_bytes, signed, signature, &[])? {
        Ok(())
    } else {
        Err("Signature does not verify against the issuer's EdDSA key."
            .to_string())
    }
}

/// An ML-DSA signature on a certificate, RFC 9881 section 3: pure
/// ML-DSA (FIPS 204 algorithm 3) over the DER of the TBS, with an empty
/// context string, and the signature the raw bytes of the BIT STRING.
fn verify_ml_dsa(signed: &[u8], signature: &[u8], key: &PublicKey<'_>,
                 parameter_set: &'static str) -> Result<(), String> {
    let key_bytes = match key {
        PublicKey::MlDsa { parameter_set: ours, key } if *ours == parameter_set => *key,
        PublicKey::MlDsa { parameter_set: ours, .. } => return Err(format!(
            "The signature says {} and the issuer's key is {}.", parameter_set, ours)),
        other => return Err(format!(
            "Issuer's key ({}) cannot verify an {} signature.",
            describe_key(other), parameter_set)),
    };
    // No `Policy::accepts_hash`: the hash (SHAKE256) is inside the
    // scheme, as for EdDSA.
    let parameters = crate::pq::ml_dsa::parameters(parameter_set)?;
    if crate::pq::ml_dsa::verify(parameters, key_bytes, signed, &[], None, signature)? {
        Ok(())
    } else {
        Err(format!("Signature does not verify against the issuer's {} key.",
                    parameter_set))
    }
}

/// A GOST R 34.10-2012 signature on a certificate.
///
/// Three things differ from the ECDSA path, all silent when wrong:
///
///   * the digest is Streebog, and its size follows the *key* - a 256
///     bit key signs with Streebog-256 and a 512 bit key with
///     Streebog-512. The OID says which, and it must agree with the key
///     it is checked against or the signature is being verified under
///     an algorithm nobody used;
///   * the signature is `s || r` as a BIT STRING of fixed width bytes,
///     not a DER SEQUENCE of two INTEGERs and not `r || s`;
///   * `gost_verify` reads the digest little endian, which is inside
///     that function.
///
/// There is no key-size floor here, and deliberately not: `Policy` has
/// one for RSA and none for EC, because every named curve it accepts is
/// already large enough. The same is true of the five GOST curves - the
/// smallest is 256 bit - so a floor here would be a check that can
/// never fire, pretending to be one that can.
fn verify_gost(signed: &[u8], signature: &[u8], key: &PublicKey<'_>,
               bits: usize, _policy: &Policy) -> Result<(), String> {
    let (curve_name, x, y) = match key {
        PublicKey::Gost { curve, x, y, .. } => (*curve, x, y),
        key => return Err(format!(
            "Issuer's key ({}) cannot verify a GOST R 34.10-2012 signature.",
            describe_key(key))),
    };
    let curve = curves::by_name(curve_name)?;

    // The OID's size and the key's must agree. A 256 bit OID over a 512
    // bit key would hash with the wrong Streebog and read the wrong
    // number of signature bytes, and both would simply fail to verify -
    // which reads as a bad signature rather than as a malformed
    // certificate, and sends whoever debugs it in the wrong direction.
    let key_bits = curve.n.bit_len();
    let expected = if key_bits <= 256 { 256 } else { 512 };
    if bits != expected {
        return Err(format!(
            "The signature says GOST {} bit, but the issuer's key is on {}, \
             which is {} bit.", bits, curve_name, expected));
    }

    let public = Point::new(x.clone(), y.clone());
    // `s || r`, fixed width - not a DER SEQUENCE, and not `r || s`.
    let signature = curve.gost_signature_from_bytes(signature)?;

    let digest = if bits == 256 {
        Streebog::new_256(signed).digest()
    } else {
        Streebog::new(signed).digest()
    };

    if curve.gost_verify(&public, &digest, &signature)? {
        Ok(())
    } else {
        Err("Signature does not verify against the issuer's GOST key."
            .to_string())
    }
}

/// GOST R 34.10-2001 with GOST R 34.11-94, RFC 4357.
///
/// **The same arithmetic as the 2012 256 bit case with a different
/// digest**, which is the whole of the difference between the two
/// standards at this level: GOST R 34.10-2012 with a 256 bit key *is*
/// GOST R 34.10-2001 with Streebog in place of the old hash. So this
/// shares `gost_verify` and differs in four lines.
///
/// The parameter set is not checked against anything here because
/// there is nothing to check it against: a 2001 key names its curve in
/// the same field a 2012 key does, and `decode_public_key` has already
/// turned it into a curve or refused it.
fn verify_gost_2001(signed: &[u8], signature: &[u8], key: &PublicKey<'_>,
                    _policy: &Policy) -> Result<(), String> {
    let (curve_name, x, y) = match key {
        PublicKey::Gost { curve, x, y, .. } => (*curve, x, y),
        key => return Err(format!(
            "Issuer's key ({}) cannot verify a GOST R 34.10-2001 signature.",
            describe_key(key))),
    };
    let curve = curves::by_name(curve_name)?;
    // A 2001 key is always on a 256 bit curve; the 512 bit sets arrived
    // with the 2012 standard. A certificate claiming otherwise is
    // named rather than left to fail as a bad signature.
    if curve.n.bit_len() > 256 {
        return Err(format!(
            "The signature says GOST R 34.10-2001, whose keys are 256 bit, \
             but the issuer's key is on {}.", curve_name));
    }

    let public = Point::new(x.clone(), y.clone());
    let signature = curve.gost_signature_from_bytes(signature)?;
    let digest = crate::hash_functions::gost94::Gost94::new(signed).digest();

    if curve.gost_verify(&public, &digest, &signature)? {
        Ok(())
    } else {
        Err("Signature does not verify against the issuer's GOST R \
             34.10-2001 key.".to_string())
    }
}

pub(crate) fn describe_key(key: &PublicKey<'_>) -> String {
    match key {
        PublicKey::Rsa { n, .. } => format!("RSA {} bits", n.bit_len()),
        PublicKey::Ec { curve, .. } => format!("EC {}", curve),
        PublicKey::Eddsa { curve, .. } => format!("EdDSA {}", curve),
        PublicKey::MlDsa { parameter_set, .. } => parameter_set.to_string(),
        PublicKey::Dsa { parameters: Some((p, _, _)), .. } => format!("DSA {} bits", p.bit_len()),
        PublicKey::Dsa { parameters: None, .. } => "DSA with inherited parameters".to_string(),
        PublicKey::Gost { curve, legacy: true, .. } =>
            format!("GOST R 34.10-2001 {}", curve),
        PublicKey::Gost { curve, .. } => format!("GOST R 34.10-2012 {}", curve),
        PublicKey::UnsupportedCurve { oid, family } =>
            format!("a {} key on unsupported parameter set {}", family, oid),
        PublicKey::Unsupported { algorithm } =>
            format!("unsupported algorithm {}", oids::name_of(algorithm)
                    .unwrap_or("of unknown type")),
    }
}

fn digest_of(hash_name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut hash = crate::api::AnyHash::new(hash_name)?;
    hash.update(data);
    Ok(hash.digest())
}

/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`.
///
/// Strict, and `finish()` matters: trailing bytes after the SEQUENCE would
/// mean two signatures parse to the same value, which is signature
/// malleability - and that has broken things that assumed a signature was a
/// unique identifier for a transaction.
pub fn decode_ecdsa_der(der: &[u8]) -> Result<Signature, String> {
    let mut outer = crate::asn1::Reader::new(der);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;
    let r = sequence.read_integer()?;
    let s = sequence.read_integer()?;
    sequence.finish()?;
    Ok(Signature { r, s })
}

/// The inverse, for signing a certificate.
pub fn encode_ecdsa_der(signature: &Signature) -> Vec<u8> {
    let mut writer = crate::asn1::Writer::new();
    writer.write_sequence(|w| {
        w.write_integer(&signature.r);
        w.write_integer(&signature.s);
    });
    writer.finish()
}

// ----------------------------------------------------------------- chains ---

/// Check one certificate on its own: time, critical extensions, and the
/// usage bits for its position in the chain.
fn check_certificate(certificate: &Certificate<'_>, policy: &Policy,
                     purpose: Purpose, is_leaf: bool) -> Result<(), String> {
    if !certificate.extensions.unrecognised_critical.is_empty() {
        let names: Vec<String> = certificate.extensions.unrecognised_critical
            .iter().map(|o| o.to_string()).collect();
        // RFC 5280 §4.2: a relying party that does not recognise a critical
        // extension MUST reject. "Critical" is the issuer saying this
        // certificate means something you have not read.
        return Err(format!("Critical extension(s) not understood: {}.",
                           names.join(", ")));
    }

    if !policy.allow_expired {
        if policy.now < certificate.not_before {
            return Err(format!("Not valid until {}; it is {}. Set \
                                allow_expired to accept it anyway.",
                               certificate.not_before, policy.now));
        }
        if policy.now > certificate.not_after {
            return Err(format!("Expired at {}; it is {}. Set allow_expired \
                                to accept it anyway.",
                               certificate.not_after, policy.now));
        }
    }

    if is_leaf {
        if let Some(usages) = &certificate.extensions.extended_key_usage {
            let wanted: Option<&[u8]> = match purpose {
                Purpose::ServerAuth => Some(oids::EKU_SERVER_AUTH),
                Purpose::ClientAuth => Some(oids::EKU_CLIENT_AUTH),
                Purpose::Any => None,
            };
            if let Some(wanted) = wanted {
                let permitted = usages.iter().any(|oid| {
                    oid.as_bytes() == wanted || oid.as_bytes() == oids::EKU_ANY
                });
                if !permitted {
                    return Err("Certificate's extendedKeyUsage does not permit \
                                this purpose.".to_string());
                }
            }
        }
        if let Some(usage) = certificate.extensions.key_usage {
            // A leaf needs to be able to do *something* a handshake uses.
            // Nothing set at all means the key is not for this.
            if purpose != Purpose::Any
                && !(usage.digital_signature || usage.key_encipherment
                     || usage.key_agreement) {
                return Err("Certificate's keyUsage permits neither signing, \
                            key encipherment nor key agreement.".to_string());
            }
        }
    }
    Ok(())
}

/// Check a certificate that is acting as a CA in a chain.
///
/// The basicConstraints check here is the one whose absence was the 2002
/// "any certificate can sign any certificate" bug, and again in 2009, and
/// again in a mobile stack in 2011. A leaf certificate anybody can buy must
/// not be able to sign a certificate for a bank.
///
/// `is_trust_anchor` softens exactly one of those rules. RFC 5280 §6.1 makes
/// the trust anchor an *input* to path validation rather than a certificate
/// that gets validated: the decision to trust it was made out of band, by
/// whoever put it in the store. So a trust anchor that simply omits
/// basicConstraints is allowed to have issued the chain below it, which is
/// what a hand-rolled private CA usually looks like and what OpenSSL,
/// NSS and every other stack accept.
///
/// What is *not* softened is a certificate that says cA=FALSE, or a keyUsage
/// without keyCertSign. Those are not silence, they are the certificate
/// stating that it must not be used this way, and honouring that is the
/// whole of the 2002 bug. Trusting a certificate is not the same as
/// overruling it.
fn check_issuer(issuer: &Certificate<'_>, depth_below: usize,
                is_trust_anchor: bool) -> Result<(), String> {
    match issuer.extensions.basic_constraints {
        Some((true, path_len)) => {
            if let Some(limit) = path_len {
                // pathLenConstraint counts the non-self-issued intermediates
                // that may follow, not counting the leaf.
                if depth_below as u32 > limit {
                    return Err(format!(
                        "pathLenConstraint of {} exceeded: {} certificates below.",
                        limit, depth_below));
                }
            }
        }
        Some((false, _)) => {
            return Err(format!("{} is not a CA (basicConstraints says cA=FALSE) \
                                but is being used to sign.",
                               issuer.subject));
        }
        None => {
            // Version 1 certificates have no extensions at all, which is how
            // old roots look. Anything claiming version 3 must say so
            // explicitly - absence there is a leaf, not a CA. Unless it is
            // the trust anchor; see the note above.
            if issuer.version == 3 && !is_trust_anchor {
                return Err(format!("{} has no basicConstraints but claims \
                                    version 3; refusing to treat it as a CA.",
                                   issuer.subject));
            }
        }
    }

    if let Some(usage) = issuer.extensions.key_usage {
        if !usage.key_cert_sign {
            return Err(format!("{}'s keyUsage does not include keyCertSign.",
                               issuer.subject));
        }
    }
    Ok(())
}

/// Verify a chain, leaf first, against a set of trusted roots.
///
/// `chain` is what the peer sent: the leaf, then whatever intermediates it
/// chose to include. `roots` is what we already trust. The chain is only
/// accepted if it reaches one of those roots - a peer cannot supply its own
/// root, which is the entire point.
pub fn verify_chain(chain: &[Certificate<'_>], roots: &[Certificate<'_>],
                    policy: &Policy, purpose: Purpose) -> Result<(), String> {
    verify_chain_with_crls(chain, roots, policy, purpose, &[])
}

/// The same, with revocation lists to check against.
///
/// A convenience over `verify_chain_with_revocation` for the common
/// case of having CRLs and no OCSP responses.
pub fn verify_chain_with_crls(chain: &[Certificate<'_>],
                              roots: &[Certificate<'_>], policy: &Policy,
                              purpose: Purpose,
                              crls: &[crl::CertificateList<'_>])
                              -> Result<(), String> {
    verify_chain_with_revocation(chain, roots, policy, purpose,
                                 &Revocation { crls, ..Default::default() })
}

/// What a caller has been able to find out about revocation.
///
/// Gathered into one value because the two sources answer the same
/// question and a caller should not have to decide which to pass where.
/// Nothing in this library fetches any of it - no socket is opened
/// anywhere in it - so every field is something the caller went and
/// got. `crl::distribution_points` and `ocsp::responder_urls` say
/// where.
#[derive(Default)]
pub struct Revocation<'a> {
    pub crls: &'a [crl::CertificateList<'a>],
    /// OCSP responses, as DER. Each is tried against each certificate
    /// and the one whose CertID matches is the one that answers -
    /// which is why they need no labelling.
    pub ocsp: &'a [&'a [u8]],
    /// The nonce sent in the OCSP request, if one was sent. A response
    /// that does not carry it back is not an answer to that request.
    pub ocsp_nonce: Option<&'a [u8]>,
}

/// Verify a chain and check revocation against everything supplied.
///
/// Separate from `verify_chain` rather than another argument on it,
/// because almost every caller has no revocation material and the ones
/// that do had to go and fetch it.
///
/// Every certificate in the chain is checked, not only the leaf. A
/// revoked intermediate is the case revocation exists for: its key was
/// compromised, and everything below it is suspect.
///
/// **OCSP is consulted first**, because it answers about one
/// certificate and is normally fresher, and a CRL is the fallback when
/// no response settles the question. A `Revoked` from either is
/// decisive; an `Unknown` from both is what
/// `policy.require_revocation` decides about. A certificate that is
/// positively **revoked** is refused either way.
pub fn verify_chain_with_revocation(chain: &[Certificate<'_>],
                                    roots: &[Certificate<'_>], policy: &Policy,
                                    purpose: Purpose,
                                    revocation: &Revocation<'_>)
                                    -> Result<(), String> {
    let leaf = chain.first()
        .ok_or_else(|| "An empty chain verifies nothing.".to_string())?;
    if chain.len() > policy.max_chain_length {
        return Err(format!("Chain of {} is longer than the limit of {}.",
                           chain.len(), policy.max_chain_length));
    }

    check_certificate(leaf, policy, purpose, true)?;

    // **Trusted first.** The chain a server sends is a hint, not the path:
    // it may run past a certificate the store already trusts, to a
    // cross-signed copy of a current root issued by an older root the
    // store has since dropped. So the path is the shortest prefix of what
    // was sent whose top a trusted root issued, tried from the leaf
    // upwards, which is what OpenSSL has done by default since 1.1.0
    // (X509_V_FLAG_TRUSTED_FIRST).
    //
    // **Only where what is cut off continues the chain**: the first
    // certificate dropped must name itself as the issuer of the last one
    // kept. Without that, `[intermediate, leaf]` - a chain sent the wrong
    // way round - verified as a path of one, the intermediate, which a
    // root did issue. Order is still the sender's to get right; what
    // trusted-first forgives is going too far, not going sideways.
    //
    // Found by `check_live.py` against Google and Cloudflare: both send
    // `GTS Root R1` cross-signed by `GlobalSign Root CA`, the store has the
    // self-signed GTS Root R1 and not GlobalSign's, and walking to the end
    // of what was sent asked for the one root that was not there.
    //
    // On failure the error is the full chain's, unless a shorter prefix
    // reached a root that then refused it - that reason names the problem,
    // where "no trusted root issued" would only name the end of the line.
    let mut refusal = None;
    for end in 1..chain.len() {
        if !chain[end].is_issuer_of(&chain[end - 1])
                || !roots.iter().any(|root| root.is_issuer_of(&chain[end - 1])) {
            continue;
        }
        match verify_path(&chain[..end], roots, policy, purpose, revocation) {
            Ok(()) => return Ok(()),
            Err(reason) => if refusal.is_none()
                    && reason.starts_with("No trusted root accepted") {
                refusal = Some(reason);
            },
        }
    }
    match verify_path(chain, roots, policy, purpose, revocation) {
        Ok(()) => Ok(()),
        Err(reason) => Err(match refusal {
            Some(refused) if reason.starts_with("No trusted root issued") =>
                refused,
            _ => reason,
        }),
    }
}

/// One candidate path: `chain` exactly as given, ending at a certificate a
/// trusted root must have issued. The leaf has already been checked.
fn verify_path(chain: &[Certificate<'_>], roots: &[Certificate<'_>],
               policy: &Policy, purpose: Purpose,
               revocation: &Revocation<'_>) -> Result<(), String> {
    // Walk up the chain the peer sent. Each link must verify against the
    // next, and each issuer must be allowed to be one.
    for (index, certificate) in chain.iter().enumerate() {
        let issuer = match chain.get(index + 1) {
            Some(issuer) => issuer,
            None => break,
        };
        if !issuer.is_issuer_of(certificate) {
            return Err(format!("Chain is broken at position {}: {} was not \
                                issued by {}.", index,
                               certificate.subject,
                               issuer.subject));
        }
        check_certificate(issuer, policy, purpose, false)?;
        check_issuer(issuer, index, false)?;
        verify_signature(certificate, issuer, policy)
            .map_err(|e| format!("At position {} ({}): {}", index,
                                 certificate.subject, e))?;
    }

    // The top of what the peer sent must be signed by something we trust.
    //
    // A self-signed certificate at the top of the chain proves nothing on
    // its own - anybody can make one - so it is only accepted if the same
    // certificate is in the root set, which is checked by verifying its
    // signature against a root rather than against itself.
    let top = chain.last().unwrap();
    let mut reasons = Vec::new();
    for root in roots {
        if !root.is_issuer_of(top) {
            continue;
        }
        if let Err(reason) = check_certificate(root, policy, purpose, false) {
            reasons.push(format!("{}: {}", root.subject, reason));
            continue;
        }
        // A root that is the top of the chain (the peer sent the root too)
        // is checked against itself, which is what self-signed means.
        //
        // The reason from `verify_signature` is kept rather than replaced
        // with "the self-signature does not verify". That substitution was
        // here and it lied: a root refused for being 1024 bits reported a
        // bad signature, which sends whoever is debugging it in entirely
        // the wrong direction. The policy's reason is the useful one.
        if top.raw == root.raw {
            // No CA check at all on this branch. The trusted certificate is
            // not issuing anything here - it *is* the certificate presented,
            // vouched for by its presence in the store. Asking whether it is
            // allowed to be a CA is asking the wrong question, and asking it
            // is what made a pinned self-signed server certificate - the
            // single most common configuration on equipment too old to get
            // a public certificate - fail to verify against a store
            // containing that exact certificate.
            match verify_signature(top, root, policy) {
                Ok(()) => {
                    // The chain *is* this certificate, so the only
                    // constraints that could apply are ones it asserts
                    // about things below it - and there is nothing below
                    // it. Checked anyway rather than skipped, so the two
                    // branches cannot drift apart.
                    name_constraints::check_chain(chain, Some(root))?;
                    check_revocation(chain, root, revocation, policy)?;
                    return Ok(());
                }
                Err(reason) => {
                    reasons.push(format!("{}: {}", root.subject, reason));
                    continue;
                }
            }
        }
        // Below here the root really is issuing the chain, so it has to be
        // allowed to.
        if let Err(reason) = check_issuer(root, chain.len() - 1, true) {
            reasons.push(format!("{}: {}", root.subject, reason));
            continue;
        }
        match verify_signature(top, root, policy) {
            Ok(()) => {
                // Last, because it is the only check that needs the whole
                // path at once: a constraint on the root governs every
                // certificate below it, and until a root has been chosen
                // there is no "below it". Not optional and not behind a
                // policy flag - a CA that says what it may issue for is
                // making a promise the relying party is the only one who
                // can keep.
                name_constraints::check_chain(chain, Some(root))?;
                check_revocation(chain, root, revocation, policy)?;
                return Ok(());
            }
            Err(reason) => reasons.push(format!("{}: {}",
                                                root.subject, reason)),
        }
    }

    if reasons.is_empty() {
        Err(format!("No trusted root issued {}.", top.issuer))
    } else {
        Err(format!("No trusted root accepted this chain: {}", reasons.join("; ")))
    }
}

/// Every certificate in the chain against the CRLs supplied.
///
/// The issuer of `chain[i]` is `chain[i+1]`, and of the top one is the
/// trusted root - so the walk pairs them up rather than checking each
/// certificate against everything.
///
/// The root itself is not checked. A trust anchor is trusted because it
/// is in the store, and the only thing that could revoke it is itself;
/// removing it from the store is how a root is withdrawn.
fn check_revocation(chain: &[Certificate<'_>], root: &Certificate<'_>,
                    revocation: &Revocation<'_>, policy: &Policy)
                    -> Result<(), String> {
    if revocation.crls.is_empty() && revocation.ocsp.is_empty()
            && !policy.require_revocation {
        // Nothing to check against and nothing demanded. Said here
        // rather than reached through the checkers, so the common case
        // does no work at all.
        return Ok(());
    }
    for (index, certificate) in chain.iter().enumerate() {
        let issuer = chain.get(index + 1).unwrap_or(root);
        // A certificate the peer sent twice, or a root sent as part of
        // its own chain, is its own issuer and nothing can revoke it.
        if certificate.raw == issuer.raw {
            continue;
        }
        let status = status_of(certificate, issuer, revocation, policy);
        match status {
            crl::Status::NotRevoked => {}
            crl::Status::Revoked { .. } => return Err(format!(
                "{} has been revoked by {}. {}",
                certificate.subject, issuer.subject,
                status.describe().unwrap_or_default())),
            crl::Status::Unknown(why) if policy.require_revocation =>
                return Err(format!(
                    "The revocation status of {} could not be established, \
                     and the policy requires it: {}.",
                    certificate.subject, why)),
            crl::Status::Unknown(_) => {}
        }
    }
    Ok(())
}

/// One certificate's status, from whichever source can answer.
///
/// OCSP first: it answers about this certificate rather than about
/// every certificate the CA ever issued, and is normally fresher. A
/// CRL is the fallback.
///
/// A `Revoked` from anything ends it. An `Unknown` from everything
/// carries the reasons from both, because "no CRL was supplied" and
/// "the stapled response was for another certificate" send whoever is
/// debugging it in different directions.
fn status_of(certificate: &Certificate<'_>, issuer: &Certificate<'_>,
             revocation: &Revocation<'_>, policy: &Policy) -> crl::Status {
    let mut reasons: Vec<String> = Vec::new();

    for response in revocation.ocsp {
        let status = ocsp::check(certificate, issuer, response,
                                 revocation.ocsp_nonce, policy, policy.now);
        match status {
            crl::Status::Revoked { .. } | crl::Status::NotRevoked =>
                return status,
            crl::Status::Unknown(why) => reasons.push(format!("OCSP: {}", why)),
        }
    }

    let status = crl::check(certificate, issuer, revocation.crls, policy,
                            policy.now);
    match status {
        crl::Status::Revoked { .. } | crl::Status::NotRevoked => status,
        crl::Status::Unknown(why) => {
            reasons.push(format!("CRL: {}", why));
            crl::Status::Unknown(reasons.join("; "))
        }
    }
}

// ------------------------------------------------------------ name matching ---

/// Does this certificate cover `hostname`?
///
/// RFC 6125, with the rules that matter:
///
///   * If there is a subjectAltName, the common name is **not** looked at.
///     Falling back to CN when a SAN exists is how a certificate for one
///     name gets accepted for another.
///   * A wildcard matches exactly one label, only as the leftmost label,
///     and only one per name. `*.example.com` covers `a.example.com` and
///     not `a.b.example.com` and not `example.com`.
///   * A wildcard needs at least two labels after it, so `*.com` matches
///     nothing.
///   * Comparison is ASCII case-insensitive, and nothing else - no Unicode
///     folding, because two strings that fold together are two names that
///     would be accepted for one certificate.
pub fn matches_hostname(certificate: &Certificate<'_>, hostname: &str) -> bool {
    let hostname = hostname.trim_end_matches('.');
    if hostname.is_empty() || hostname.contains('\0') {
        return false;
    }

    // An IP address is matched against iPAddress entries only. A DNS name
    // entry that looks like an address does not count, which is why this is
    // decided first.
    if let Some(address) = parse_ip(hostname) {
        return certificate.extensions.subject_alt_names.iter().any(|name| {
            matches!(name, GeneralName::IpAddress(bytes) if *bytes == address.as_slice())
        });
    }

    let dns_names = certificate.extensions.dns_names();
    if !dns_names.is_empty() {
        return dns_names.iter().any(|pattern| matches_pattern(pattern, hostname));
    }

    // No SAN at all: fall back to the common name. This is deprecated and
    // browsers stopped doing it years ago, but certificates that predate
    // the SAN requirement are exactly what this library exists to talk to.
    match certificate.subject.common_name() {
        Some(common_name) => matches_pattern(&common_name, hostname),
        None => false,
    }
}

fn matches_pattern(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    if pattern.is_empty() || pattern.contains('\0') {
        return false;
    }
    if !pattern.contains('*') {
        return pattern.eq_ignore_ascii_case(hostname);
    }

    let mut labels = pattern.split('.');
    let first = match labels.next() {
        Some(first) => first,
        None => return false,
    };
    let rest: Vec<&str> = labels.collect();

    // Only the leftmost label may carry a wildcard, and only one of them.
    if rest.iter().any(|label| label.contains('*')) {
        return false;
    }
    if first.matches('*').count() != 1 {
        return false;
    }
    // `*.com` would cover an entire top level domain.
    if rest.len() < 2 {
        return false;
    }

    let mut host_labels = hostname.split('.');
    let host_first = match host_labels.next() {
        Some(label) => label,
        None => return false,
    };
    let host_rest: Vec<&str> = host_labels.collect();

    // The wildcard covers one label, so the rest must line up exactly.
    if host_rest.len() != rest.len() {
        return false;
    }
    if !host_rest.iter().zip(rest.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b)) {
        return false;
    }

    // Within the leftmost label, `*` matches any run of characters that
    // contains no dot - which it cannot, since we already split on dots.
    let (prefix, suffix) = first.split_once('*').unwrap();
    if host_first.len() < prefix.len() + suffix.len() {
        return false;
    }
    host_first[..prefix.len()].eq_ignore_ascii_case(prefix)
        && host_first[host_first.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Dotted IPv4 or an IPv6 literal, as the bytes a SAN would hold.
fn parse_ip(text: &str) -> Option<Vec<u8>> {
    if text.contains(':') {
        return parse_ipv6(text.trim_start_matches('[').trim_end_matches(']'));
    }
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = Vec::with_capacity(4);
    for part in parts {
        // No leading zeros: "010" is octal to some resolvers and decimal to
        // others, and a name that resolves differently in two places is a
        // name that can be pointed at two hosts.
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        out.push(part.parse::<u8>().ok()?);
    }
    Some(out)
}

fn parse_ipv6(text: &str) -> Option<Vec<u8>> {
    let (head, tail) = match text.split_once("::") {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    };

    let group = |part: &str| -> Option<[u8; 2]> {
        if part.is_empty() || part.len() > 4 {
            return None;
        }
        let value = u16::from_str_radix(part, 16).ok()?;
        Some(value.to_be_bytes())
    };

    let mut front = Vec::new();
    if !head.is_empty() {
        for part in head.split(':') {
            front.extend_from_slice(&group(part)?);
        }
    }
    let mut back = Vec::new();
    if let Some(tail) = tail {
        if !tail.is_empty() {
            for part in tail.split(':') {
                back.extend_from_slice(&group(part)?);
            }
        }
    }

    match tail {
        None => if front.len() == 16 { Some(front) } else { None },
        Some(_) => {
            if front.len() + back.len() >= 16 {
                return None;   // `::` must stand for at least one group
            }
            let mut out = front;
            out.resize(16 - back.len(), 0);
            out.extend_from_slice(&back);
            Some(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::tests_support;

    #[test]
    fn test_hostname_matching() {
        let exact = tests_support::leaf_with_sans(&["example.test", "www.example.test"]);
        let certificate = Certificate::parse(&exact).unwrap();

        assert!(matches_hostname(&certificate, "example.test"));
        assert!(matches_hostname(&certificate, "EXAMPLE.TEST"));
        assert!(matches_hostname(&certificate, "example.test."));   // trailing dot
        assert!(matches_hostname(&certificate, "www.example.test"));
        assert!(!matches_hostname(&certificate, "evil.test"));
        assert!(!matches_hostname(&certificate, "example.test.evil.test"));
        assert!(!matches_hostname(&certificate, "ample.test"));
        assert!(!matches_hostname(&certificate, ""));
    }

    #[test]
    fn test_wildcards() {
        let der = tests_support::leaf_with_sans(&["*.example.test"]);
        let certificate = Certificate::parse(&der).unwrap();

        assert!(matches_hostname(&certificate, "www.example.test"));
        assert!(matches_hostname(&certificate, "WWW.example.test"));
        // One label only, and not the bare domain.
        assert!(!matches_hostname(&certificate, "a.b.example.test"));
        assert!(!matches_hostname(&certificate, "example.test"));
        assert!(!matches_hostname(&certificate, "www.evil.test"));

        // A partial wildcard is legal but narrow.
        let der = tests_support::leaf_with_sans(&["www*.example.test"]);
        let certificate = Certificate::parse(&der).unwrap();
        assert!(matches_hostname(&certificate, "www1.example.test"));
        assert!(matches_hostname(&certificate, "www.example.test"));
        assert!(!matches_hostname(&certificate, "ww.example.test"));
        assert!(!matches_hostname(&certificate, "xwww.example.test"));

        // The dangerous shapes, all of which must match nothing.
        for pattern in ["*", "*.test", "*.*.example.test", "www.*.example.test",
                        "**.example.test"] {
            let der = tests_support::leaf_with_sans(&[pattern]);
            let certificate = Certificate::parse(&der).unwrap();
            for host in ["example.test", "www.example.test", "a.b.example.test",
                         "anything.test"] {
                assert!(!matches_hostname(&certificate, host),
                        "{} must not match {}", pattern, host);
            }
        }
    }

    /// When a SAN is present the common name is not consulted. A
    /// certificate whose CN says one thing and whose SAN says another is
    /// only good for what the SAN says.
    #[test]
    fn test_san_takes_precedence_over_common_name() {
        let der = tests_support::leaf(|b| {
            b.common_name = "evil.test".to_string();
            b.dns_names = vec!["good.test".to_string()];
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert!(matches_hostname(&certificate, "good.test"));
        assert!(!matches_hostname(&certificate, "evil.test"));

        // With no SAN at all, the CN is the fallback - certificates that
        // predate the SAN requirement are exactly what this library is for.
        let der = tests_support::leaf(|b| {
            b.common_name = "old.test".to_string();
            b.dns_names = vec![];
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert!(matches_hostname(&certificate, "old.test"));
    }

    #[test]
    fn test_ip_addresses() {
        let der = tests_support::leaf(|b| {
            b.dns_names = vec![];
            b.ip_addresses = vec![vec![192, 0, 2, 1]];
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert!(matches_hostname(&certificate, "192.0.2.1"));
        assert!(!matches_hostname(&certificate, "192.0.2.2"));
        // Leading zeros are ambiguous between octal and decimal.
        assert!(!matches_hostname(&certificate, "192.000.2.1"));

        // An address must not be matched against a DNS name entry.
        let der = tests_support::leaf(|b| {
            b.dns_names = vec!["192.0.2.1".to_string()];
            b.ip_addresses = vec![];
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert!(!matches_hostname(&certificate, "192.0.2.1"));
    }

    #[test]
    fn test_ipv6_parsing() {
        assert_eq!(parse_ip("::1").unwrap(), {
            let mut v = vec![0u8; 15]; v.push(1); v
        });
        assert_eq!(parse_ip("2001:db8::1").unwrap()[..4], [0x20, 0x01, 0x0d, 0xb8]);
        assert!(parse_ip("2001:db8::1:2:3:4:5:6:7:8").is_none());
        assert!(parse_ip("gggg::1").is_none());
        assert!(parse_ip("2001:db8").is_none());
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::x509::builder::key_usage;
    use crate::x509::tests_support::{self, Chain};

    fn policy() -> Policy {
        Policy::at(1_700_000_000)   // 2023-11-14
    }

    /// Parse a chain and verify it, which is the shape every test here has.
    fn check(chain: &Chain, policy: &Policy) -> Result<(), String> {
        let leaf = Certificate::parse(&chain.leaf)?;
        let intermediate = Certificate::parse(&chain.intermediate)?;
        let root = Certificate::parse(&chain.root)?;
        verify_chain(&[leaf, intermediate], &[root], policy, Purpose::ServerAuth)
    }

    #[test]
    fn test_a_good_chain_verifies() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        check(&chain, &policy()).unwrap();

        // And the leaf covers the name it says it does.
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        assert!(matches_hostname(&leaf, "leaf.test"));
        assert!(!matches_hostname(&leaf, "other.test"));
    }

    /// The Google and Cloudflare shape: the server sends its chain up to a
    /// **cross-signed** copy of the root - same name, same key, issued by
    /// an older root - and the store has the self-signed root and not the
    /// older one. The path ends at the trusted root; the rest of what was
    /// sent is a hint for clients that lack it.
    ///
    /// Walking to the end of the sent chain asked for the old root and
    /// failed with "No trusted root issued CN=Old Root", which is what
    /// `check_live.py --pq` reported for all three servers it tried.
    #[test]
    fn test_a_path_stops_at_a_trusted_root_the_chain_runs_past() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let old_root_key = tests_support::TestKey::new();
        // Test Root's name and key, certified by an older root.
        let cross = tests_support::Builder {
            common_name: "Test Root".to_string(),
            dns_names: vec![],
            is_ca: Some((true, None)),
            key_usage: Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN),
            ..tests_support::Builder::default()
        }.issue(&chain.root_key, &old_root_key, "Old Root", 9);

        let sent = [Certificate::parse(&chain.leaf).unwrap(),
                    Certificate::parse(&chain.intermediate).unwrap(),
                    Certificate::parse(&cross).unwrap()];
        let trusted = [Certificate::parse(&chain.root).unwrap()];
        verify_chain(&sent, &trusted, &policy(), Purpose::ServerAuth)
            .expect("the path ends at the trusted Test Root");

        // Only a tail that continues the chain is cut off. A certificate
        // after the path that is not its next link is a chain out of
        // order, and so is a chain sent the wrong way round - which a
        // prefix of one, the intermediate, would otherwise satisfy.
        let unrelated = tests_support::leaf(|_| {});
        let with_junk = [Certificate::parse(&chain.leaf).unwrap(),
                         Certificate::parse(&chain.intermediate).unwrap(),
                         Certificate::parse(&unrelated).unwrap()];
        assert!(verify_chain(&with_junk, &trusted, &policy(), Purpose::Any)
                    .is_err(), "a trailing certificate that is not the next link");
        let backwards = [Certificate::parse(&chain.intermediate).unwrap(),
                         Certificate::parse(&chain.leaf).unwrap()];
        assert!(verify_chain(&backwards, &trusted, &policy(), Purpose::Any)
                    .is_err(), "a chain the wrong way round");

        // But trusting only the *old* root still works through the cross
        // certificate, and trusting neither still fails, naming the end.
        let old_root = tests_support::Builder {
            common_name: "Old Root".to_string(),
            dns_names: vec![],
            is_ca: Some((true, None)),
            key_usage: Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN),
            ..tests_support::Builder::default()
        }.issue(&old_root_key, &old_root_key, "Old Root", 8);
        verify_chain(&sent, &[Certificate::parse(&old_root).unwrap()],
                     &policy(), Purpose::ServerAuth)
            .expect("the full sent path ends at the old root");
        let error = verify_chain(&sent, &[], &policy(), Purpose::ServerAuth)
            .unwrap_err();
        assert!(error.contains("No trusted root issued CN=Old Root"), "{error}");
    }

    /// A root found part-way up that then refuses the chain - here, for
    /// being expired - is the reason reported, rather than "nothing issued
    /// the top", which would point at the wrong certificate.
    #[test]
    fn test_a_refusing_root_part_way_up_is_the_reason_given() {
        let chain = tests_support::chain(
            |root| root.not_after = "20210101000000Z".to_string(), |_| {}, |_| {});
        let old_root_key = tests_support::TestKey::new();
        let cross = tests_support::Builder {
            common_name: "Test Root".to_string(),
            dns_names: vec![],
            is_ca: Some((true, None)),
            key_usage: Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN),
            ..tests_support::Builder::default()
        }.issue(&chain.root_key, &old_root_key, "Old Root", 9);
        let sent = [Certificate::parse(&chain.leaf).unwrap(),
                    Certificate::parse(&chain.intermediate).unwrap(),
                    Certificate::parse(&cross).unwrap()];
        let error = verify_chain(&sent, &[Certificate::parse(&chain.root).unwrap()],
                                 &policy(), Purpose::ServerAuth).unwrap_err();
        assert!(error.starts_with("No trusted root accepted"), "{error}");
        assert!(error.contains("Test Root"), "{error}");
    }

    /// The test that proves the signature check is real: flip one bit of the
    /// leaf's signature and the chain must fail.
    #[test]
    fn test_a_tampered_signature_fails() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let mut broken = chain.leaf.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0x01;

        let leaf = Certificate::parse(&broken).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        let root = Certificate::parse(&chain.root).unwrap();
        let error = verify_chain(&[leaf, intermediate], &[root], &policy(),
                                 Purpose::ServerAuth).unwrap_err();
        assert!(error.contains("does not verify"), "{}", error);
    }

    /// And that it covers the whole TBS, not just some of it: change a byte
    /// of the subject name and the signature must no longer match.
    #[test]
    fn test_tampering_with_the_body_fails() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let position = chain.leaf.windows(9)
            .position(|w| w == b"leaf.test")
            .expect("the name should be in there");

        let mut broken = chain.leaf.clone();
        broken[position] = b'x';

        let leaf = Certificate::parse(&broken).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        let root = Certificate::parse(&chain.root).unwrap();
        assert!(verify_chain(&[leaf, intermediate], &[root], &policy(),
                             Purpose::ServerAuth).is_err());
    }

    #[test]
    fn test_an_untrusted_root_is_refused() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let other = tests_support::chain(|b| b.common_name = "Other Root".to_string(),
                                         |_| {}, |_| {});

        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        let wrong_root = Certificate::parse(&other.root).unwrap();
        let error = verify_chain(&[leaf, intermediate], &[wrong_root], &policy(),
                                 Purpose::ServerAuth).unwrap_err();
        assert!(error.contains("No trusted root"), "{}", error);
    }

    /// An empty root set must never succeed, however good the chain is.
    #[test]
    fn test_no_roots_means_no_trust() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        assert!(verify_chain(&[leaf, intermediate], &[], &policy(),
                             Purpose::ServerAuth).is_err());
    }

    /// The one that was a real bug in more than one stack: a leaf
    /// certificate, which anybody can buy, must not be able to sign another
    /// certificate.
    #[test]
    fn test_a_leaf_cannot_act_as_a_ca() {
        let chain = tests_support::chain(
            |_| {},
            |b| b.is_ca = Some((false, None)),   // the intermediate says it is not a CA
            |_| {});
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("not a CA"), "{}", error);

        // Nor one with no basicConstraints at all, in a v3 certificate.
        let chain = tests_support::chain(|_| {}, |b| b.is_ca = None, |_| {});
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("basicConstraints"), "{}", error);
    }

    /// A trust anchor is an input to path validation, not a certificate that
    /// gets validated (RFC 5280 §6.1), so the CA rules that apply to an
    /// issuer do not all apply to it.
    ///
    /// This escaped the tests above because every one of them builds a
    /// well-formed three-certificate chain with a well-formed root. Nothing
    /// exercised the shape that actually turns up on old equipment: one
    /// self-signed server certificate, pinned directly. Found by the TLS
    /// seam tests, whose server is exactly that.
    #[test]
    fn test_a_pinned_self_signed_certificate_verifies() {
        // v3, no basicConstraints, not a CA by any reading - and trusted
        // anyway, because it is in the store and it is the certificate
        // being presented. It signs nothing but itself.
        let certificate = tests_support::leaf(|b| {
            b.common_name = "device.local".to_string();
            b.dns_names = vec!["device.local".to_string()];
        });
        let presented = Certificate::parse(&certificate).unwrap();
        let trusted = Certificate::parse(&certificate).unwrap();
        assert_eq!(presented.version, 3, "the interesting case is a v3 cert");
        assert!(presented.extensions.basic_constraints.is_none());
        verify_chain(&[presented], &[trusted], &policy(), Purpose::ServerAuth)
            .expect("a self-signed certificate that is itself trusted");
    }

    /// The softening above, for an anchor that really does issue the chain:
    /// silence about basicConstraints is forgiven, an explicit cA=FALSE is
    /// not. Trusting a certificate is not the same as overruling it.
    #[test]
    fn test_anchor_ca_rules_soften_for_silence_only() {
        let chain = tests_support::chain(|b| b.is_ca = None, |_| {}, |_| {});
        check(&chain, &policy())
            .expect("a private CA that omits basicConstraints on its root");

        let chain = tests_support::chain(|b| b.is_ca = Some((false, None)),
                                         |_| {}, |_| {});
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("not a CA"), "{}", error);

        // And keyUsage still binds: a root that says it cannot sign
        // certificates has said so, whoever trusts it.
        let chain = tests_support::chain(|b| b.key_usage = Some(key_usage::CRL_SIGN),
                                         |_| {}, |_| {});
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("keyCertSign"), "{}", error);
    }

    #[test]
    fn test_path_length_is_enforced() {
        // The default intermediate has pathLen 0, which permits a leaf
        // directly below it and nothing more.
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        check(&chain, &policy()).unwrap();

        // A root with pathLen 0 cannot have an intermediate below it.
        let chain = tests_support::chain(|b| b.is_ca = Some((true, Some(0))),
                                         |_| {}, |_| {});
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("pathLen"), "{}", error);
    }

    #[test]
    fn test_key_usage_on_the_issuer() {
        // An intermediate whose keyUsage omits keyCertSign must not sign.
        let chain = tests_support::chain(
            |_| {},
            |b| b.key_usage = Some(key_usage::DIGITAL_SIGNATURE),
            |_| {});
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("keyCertSign"), "{}", error);
    }

    #[test]
    fn test_validity_windows() {
        let chain = tests_support::chain(|_| {}, |_| {}, |b| {
            b.not_before = "20200101000000Z".to_string();
            b.not_after = "20210101000000Z".to_string();
        });
        // Expired.
        assert!(check(&chain, &Policy::at(1_700_000_000)).unwrap_err()
                    .contains("Expired"));
        // Not yet valid.
        assert!(check(&chain, &Policy::at(1_000_000_000)).unwrap_err()
                    .contains("Not valid until"));
        // Inside the window.
        check(&chain, &Policy::at(1_600_000_000)).unwrap();
    }

    /// An expired *root* must fail too. It is easy to check the leaf's dates
    /// and forget the ones above it.
    #[test]
    fn test_an_expired_issuer_fails() {
        let chain = tests_support::chain(|_| {}, |b| {
            b.not_before = "20200101000000Z".to_string();
            b.not_after = "20210101000000Z".to_string();
        }, |_| {});
        assert!(check(&chain, &policy()).unwrap_err().contains("Expired"));
    }

    #[test]
    fn test_extended_key_usage() {
        let chain = tests_support::chain(|_| {}, |_| {}, |b| {
            b.extended_key_usage = vec![crate::x509::oids::EKU_CLIENT_AUTH];
        });
        // Client auth only: no good for a server.
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("extendedKeyUsage"), "{}", error);

        // But it is fine for what it says it is for.
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        let root = Certificate::parse(&chain.root).unwrap();
        verify_chain(&[leaf, intermediate], &[root], &policy(),
                     Purpose::ClientAuth).unwrap();
    }

    /// Critical means "reject if you do not understand this".
    #[test]
    fn test_an_unknown_critical_extension_is_fatal() {
        let oid = crate::asn1::encode_oid("1.3.6.1.4.1.99999.7").unwrap();
        let chain = tests_support::chain(|_| {}, |_| {}, |b| {
            b.extra_extensions = vec![(oid.clone(), true, vec![0x05, 0x00])];
        });
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("Critical extension"), "{}", error);

        // The same extension, not critical, is ignored as it should be.
        let chain = tests_support::chain(|_| {}, |_| {}, |b| {
            b.extra_extensions = vec![(oid, false, vec![0x05, 0x00])];
        });
        check(&chain, &policy()).unwrap();
    }

    #[test]
    fn test_a_broken_chain_is_noticed() {
        let a = tests_support::chain(|_| {}, |_| {}, |_| {});
        let b = tests_support::chain(|b| b.common_name = "Other Root".to_string(),
                                     |b| b.common_name = "Other Intermediate".to_string(),
                                     |_| {});

        // A leaf from one chain under an intermediate from another.
        let leaf = Certificate::parse(&a.leaf).unwrap();
        let wrong = Certificate::parse(&b.intermediate).unwrap();
        let root = Certificate::parse(&b.root).unwrap();
        let error = verify_chain(&[leaf, wrong], &[root], &policy(),
                                 Purpose::ServerAuth).unwrap_err();
        assert!(error.contains("broken"), "{}", error);
    }

    #[test]
    fn test_chain_length_limit() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        let root = Certificate::parse(&chain.root).unwrap();

        let mut policy = policy();
        policy.max_chain_length = 1;
        assert!(verify_chain(&[leaf, intermediate], &[root], &policy,
                             Purpose::ServerAuth).is_err());
    }

    #[test]
    fn test_empty_chain() {
        assert!(verify_chain(&[], &[], &policy(), Purpose::ServerAuth).is_err());
    }

    /// A self-signed certificate offered as its own root is only trusted if
    /// that exact certificate is in the root set - not merely because it
    /// verifies against itself, which anything self-signed does.
    #[test]
    fn test_self_signed_needs_to_be_in_the_root_set() {
        let key = tests_support::TestKey::new();
        let builder = tests_support::Builder {
            common_name: "Self Signed".to_string(),
            dns_names: vec!["self.test".to_string()],
            is_ca: Some((true, None)),
            key_usage: Some(key_usage::KEY_CERT_SIGN | key_usage::DIGITAL_SIGNATURE),
            ..Default::default()
        };
        let der = builder.issue(&key, &key, "Self Signed", 1);
        let certificate = Certificate::parse(&der).unwrap();

        // Trusted, because it is the root we were given.
        let trusted = Certificate::parse(&der).unwrap();
        verify_chain(std::slice::from_ref(&certificate), &[trusted], &policy(),
                     Purpose::Any).unwrap();

        // Not trusted on its own merits.
        assert!(verify_chain(&[certificate], &[], &policy(), Purpose::Any).is_err());
    }

    /// SHA-1 is refused by default and available on request, which is the
    /// whole posture of this library in one test.
    ///
    /// Only SHA-1 goes through a chain here, because there is no such thing
    /// as ECDSA-with-MD5 - no OID was ever assigned - and these chains use
    /// EC keys so they are fast. MD5 is covered directly below, and through
    /// RSA in the differential example.
    #[test]
    fn test_sha1_needs_to_be_asked_for() {
        let chain = tests_support::chain(|_| {}, |_| {}, |b| {
            b.hash = "sha1".to_string();
        });
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("SHA-1"), "{}", error);

        // Legacy policy accepts it, deliberately and by name.
        check(&chain, &Policy::legacy(1_700_000_000)).unwrap();
    }

    #[test]
    fn test_the_policy_gate_on_weak_hashes() {
        let strict = policy();
        assert!(strict.accepts_hash("sha256").is_ok());
        assert!(strict.accepts_hash("sha1").unwrap_err().contains("SHA-1"));
        assert!(strict.accepts_hash("md5").unwrap_err().contains("MD5"));

        let legacy = Policy::legacy(1_700_000_000);
        assert!(legacy.accepts_hash("sha1").is_ok());
        assert!(legacy.accepts_hash("md5").is_ok());

        // Turning one on does not turn the other on.
        let mut only_sha1 = policy();
        only_sha1.allow_sha1 = true;
        assert!(only_sha1.accepts_hash("sha1").is_ok());
        assert!(only_sha1.accepts_hash("md5").is_err());
    }
    /// A GOST certificate signed by a GOST key, verified end to end.
    ///
    /// The path shares nothing with the ECDSA one: the key is parsed
    /// from an OCTET STRING inside the BIT STRING with little endian
    /// coordinates, the digest is Streebog at the curve's size, and the
    /// signature is `s || r` fixed width rather than a DER SEQUENCE.
    /// Every one of those differences is silent - a verifier that made
    /// any of them the ECDSA way simply reports a bad signature.
    #[test]
    fn test_a_gost_certificate_verifies() {
        for name in curves::gost_names() {
            let root_key = tests_support::GostTestKey::new(name);
            let root = root_key.issue(&root_key, "gost-root", "gost-root", 1);

            let parsed = Certificate::parse(&root).unwrap();
            match &parsed.public_key {
                PublicKey::Gost { curve, .. } => assert_eq!(*curve, name),
                other => panic!("{} parsed as {}", name, describe_key(other)),
            }
            let expected = if root_key.curve.n.bit_len() <= 256 { 256 } else { 512 };
            assert_eq!(parsed.signature_algorithm,
                       SignatureAlgorithm::Gost(expected));

            verify_signature(&parsed, &parsed, &policy()).unwrap();

            // A flipped bit anywhere in the signature must fail, or the
            // signature is not being checked at all.
            let mut altered = root.clone();
            let at = altered.len() - 1;
            altered[at] ^= 0x01;
            let parsed = Certificate::parse(&altered).unwrap();
            assert!(verify_signature(&parsed, &parsed, &policy()).is_err(),
                    "{}: a corrupted signature verified", name);
        }
    }

    /// A real two-certificate GOST chain, so the issuer's key rather
    /// than the subject's is what verifies.
    #[test]
    fn test_a_gost_chain_verifies() {
        let root_key = tests_support::GostTestKey::new("gost256-a");
        let leaf_key = tests_support::GostTestKey::new("gost256-a");
        let root = root_key.issue(&root_key, "gost-root", "gost-root", 1);
        let leaf = root_key.issue(&leaf_key, "leaf.test", "gost-root", 2);

        let root = Certificate::parse(&root).unwrap();
        let leaf = Certificate::parse(&leaf).unwrap();
        verify_signature(&leaf, &root, &policy()).unwrap();

        // The leaf's own key must not verify its own signature, which is
        // what a verifier that used the wrong certificate would do.
        assert!(verify_signature(&leaf, &leaf, &policy()).is_err());
    }

    /// The OID says which Streebog, and it must agree with the key.
    ///
    /// Mismatched, the verification reads the wrong number of signature
    /// bytes and hashes with the wrong digest - and both just fail, so
    /// it would report a bad signature on a perfectly good certificate
    /// and send whoever debugs it looking in the wrong place.
    #[test]
    fn test_a_gost_size_mismatch_is_named() {
        let small = tests_support::GostTestKey::new("gost256-a");
        let large = tests_support::GostTestKey::new("gost512-a");
        let certificate = small.issue(&small, "gost-root", "gost-root", 1);
        let certificate = Certificate::parse(&certificate).unwrap();
        let other = large.issue(&large, "other", "other", 2);
        let other = Certificate::parse(&other).unwrap();

        let error = verify_signature(&certificate, &other, &policy()).unwrap_err();
        assert!(error.contains("256") && error.contains("512"), "{}", error);
    }

    /// A GOST signature cannot be verified by an EC key, or the other
    /// way round - the mismatch is named rather than reported as a bad
    /// signature.
    #[test]
    fn test_gost_and_ecdsa_do_not_mix() {
        let gost = tests_support::GostTestKey::new("gost256-a");
        let gost_certificate = gost.issue(&gost, "gost-root", "gost-root", 1);
        let gost_certificate = Certificate::parse(&gost_certificate).unwrap();

        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let ec_root = Certificate::parse(&chain.root).unwrap();

        let error = verify_signature(&gost_certificate, &ec_root, &policy())
                    .unwrap_err();
        assert!(error.contains("GOST"), "{}", error);

        let ec_leaf = Certificate::parse(&chain.leaf).unwrap();
        let error = verify_signature(&ec_leaf, &gost_certificate, &policy())
                    .unwrap_err();
        assert!(error.contains("GOST"), "{}", error);
    }

    // ------------------------------------------------ name constraints ---

    /// Encode a nameConstraints extension: `(tag number, bytes)` pairs
    /// for the permitted and excluded lists.
    fn constraints(permitted: &[(u32, &[u8])], excluded: &[(u32, &[u8])])
                   -> (Vec<u8>, bool, Vec<u8>) {
        use crate::asn1::{Tag, Writer};
        fn subtrees(w: &mut Writer, number: u32, list: &[(u32, &[u8])]) {
            w.write_constructed(Tag::context(number, true), |w| {
                for (tag, bytes) in list {
                    w.write_sequence(|w| {
                        w.write_tlv(Tag::context(*tag, *tag == 4), bytes);
                    });
                }
            });
        }
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            if !permitted.is_empty() { subtrees(w, 0, permitted); }
            if !excluded.is_empty() { subtrees(w, 1, excluded); }
        });
        // Critical, as RFC 5280 requires of a conforming CA - and so the
        // test also proves the extension stopped being an unrecognised
        // critical one.
        (oids::NAME_CONSTRAINTS.to_vec(), true, writer.finish())
    }

    /// A DNS name inside the intermediate's permitted subtree verifies;
    /// one outside it does not.
    #[test]
    fn test_a_dns_constraint_on_the_intermediate_is_enforced() {
        let allowed = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])],
            |b| {
                b.common_name = "www.example.test".to_string();
                b.dns_names = vec!["www.example.test".to_string()];
            });
        check(&allowed, &policy()).unwrap();

        let refused = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])],
            |b| {
                b.common_name = "www.other.test".to_string();
                b.dns_names = vec!["www.other.test".to_string()];
            });
        let error = check(&refused, &policy()).unwrap_err();
        assert!(error.contains("no permitted subtree"), "{}", error);
    }

    /// The same, asserted by the **root**. This is the case that matters
    /// most in practice - a company root added to the store and confined
    /// to the company's own names - and it is the one a per-link check
    /// would miss, since the root is only chosen at the end.
    #[test]
    fn test_a_constraint_on_the_root_reaches_the_leaf() {
        let refused = tests_support::chain(
            |b| b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])],
            |_| {},
            |b| {
                b.common_name = "www.other.test".to_string();
                b.dns_names = vec!["www.other.test".to_string()];
            });
        let error = check(&refused, &policy()).unwrap_err();
        assert!(error.contains("no permitted subtree"), "{}", error);

        let allowed = tests_support::chain(
            |b| b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])],
            |_| {},
            |b| {
                b.common_name = "in.example.test".to_string();
                b.dns_names = vec!["in.example.test".to_string()];
            });
        check(&allowed, &policy()).unwrap();
    }

    /// "Any name matching a restriction in the excludedSubtrees field is
    /// invalid regardless of information appearing in the
    /// permittedSubtrees."
    #[test]
    fn test_excluded_beats_permitted() {
        let chain = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![
                constraints(&[(2, b"example.test")], &[(2, b"bad.example.test")])],
            |b| {
                b.common_name = "www.bad.example.test".to_string();
                b.dns_names = vec!["www.bad.example.test".to_string()];
            });
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("excluded subtree"), "{}", error);

        // And a sibling that is permitted and not excluded still passes,
        // so the exclusion is doing the work rather than the permission
        // failing for both.
        let fine = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![
                constraints(&[(2, b"example.test")], &[(2, b"bad.example.test")])],
            |b| {
                b.common_name = "www.good.example.test".to_string();
                b.dns_names = vec!["www.good.example.test".to_string()];
            });
        check(&fine, &policy()).unwrap();
    }

    /// **The constraint has to cover the common name when there is no
    /// SAN**, because `matches_hostname` falls back to it. Without that,
    /// a CA constrained to `example.test` could issue a certificate with
    /// no SAN and `CN=evil.test`, and this library would accept it for
    /// `evil.test` - the dNSName constraint having seen no DNS names at
    /// all and passed vacuously.
    ///
    /// RFC 5280 does not require this. It requires the constraint to
    /// cover the names the *RFC* honours; this covers the names *we*
    /// honour, which is a superset because of the fallback.
    #[test]
    fn test_a_constraint_covers_the_common_name_when_there_is_no_san() {
        let chain = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])],
            |b| {
                b.common_name = "evil.test".to_string();
                b.dns_names = vec![];          // no SAN at all
            });

        // The bypass this closes: without the check, the chain verifies
        // and then the hostname matches.
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        assert!(matches_hostname(&leaf, "evil.test"),
                "the fallback this test is about is not happening, so the \
                 test would pass for the wrong reason");

        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("no permitted subtree"), "{}", error);
    }

    /// A common name that is not host-shaped is not treated as a DNS
    /// name, so an ordinary organisational CN does not have to sit
    /// inside a DNS subtree.
    #[test]
    fn test_a_common_name_that_is_not_a_host_is_left_alone() {
        let chain = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])],
            |b| {
                b.common_name = "Some Person".to_string();
                b.dns_names = vec![];
            });
        check(&chain, &policy()).unwrap();
    }

    /// "Restrictions apply only when the specified name form is present."
    /// A constraint on one form says nothing about another.
    #[test]
    fn test_an_unconstrained_form_is_unconstrained() {
        use crate::x509::builder::SanEntry;
        let chain = tests_support::chain(
            |_| {},
            // Only rfc822Name is constrained.
            |b| b.extra_extensions = vec![constraints(&[(1, b"example.test")], &[])],
            |b| {
                // The DNS name is outside anything, and there is no
                // constraint on DNS names, so it is fine.
                b.common_name = "www.other.test".to_string();
                b.dns_names = vec!["www.other.test".to_string()];
                b.extra_sans = vec![SanEntry::Email("a@example.test".to_string())];
            });
        check(&chain, &policy()).unwrap();

        // And the mail address itself is constrained, so the form that
        // *is* mentioned is really being checked.
        let refused = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(1, b"example.test")], &[])],
            |b| {
                b.common_name = "www.other.test".to_string();
                b.dns_names = vec!["www.other.test".to_string()];
                b.extra_sans = vec![SanEntry::Email("a@other.test".to_string())];
            });
        let error = check(&refused, &policy()).unwrap_err();
        assert!(error.contains("mail address"), "{}", error);
    }

    /// One name outside the subtree invalidates the certificate even
    /// when another is inside it. The permitted list is not satisfied by
    /// any one name matching.
    #[test]
    fn test_every_name_of_a_constrained_form_must_be_inside() {
        let chain = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])],
            |b| {
                b.common_name = "in.example.test".to_string();
                b.dns_names = vec!["in.example.test".to_string(),
                                   "also.other.test".to_string()];
            });
        let error = check(&chain, &policy()).unwrap_err();
        assert!(error.contains("also.other.test"), "{}", error);
    }

    /// A constraint on the subject DN, which RFC 5280 says every
    /// conforming application must be able to process.
    #[test]
    fn test_a_directory_name_constraint_is_enforced() {
        use crate::asn1::Writer;
        fn dn(values: &[(&'static [u8], &str)]) -> Vec<u8> {
            let mut writer = Writer::new();
            writer.write_sequence(|w| {
                for (oid, value) in values {
                    w.write_set(|w| {
                        w.write_sequence(|w| {
                            w.write_oid(oid);
                            w.write_utf8_string(value);
                        });
                    });
                }
            });
            writer.finish()
        }
        let base = dn(&[(oids::ORGANIZATION, "Example Org")]);

        let inside = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(4, &base)], &[])],
            |b| {
                b.subject = Some(vec![
                    (oids::ORGANIZATION, "Example Org".to_string()),
                    (oids::COMMON_NAME, "leaf.test".to_string())]);
            });
        check(&inside, &policy()).unwrap();

        let outside = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(4, &base)], &[])],
            |b| {
                b.subject = Some(vec![
                    (oids::ORGANIZATION, "Other Org".to_string()),
                    (oids::COMMON_NAME, "leaf.test".to_string())]);
            });
        let error = check(&outside, &policy()).unwrap_err();
        assert!(error.contains("subject name"), "{}", error);
    }

    /// An iPAddress constraint, with its own eight byte encoding.
    #[test]
    fn test_an_ip_constraint_is_enforced() {
        let subnet: &[u8] = &[192, 0, 2, 0, 255, 255, 255, 0];
        let inside = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(7, subnet)], &[])],
            |b| {
                b.dns_names = vec![];
                b.common_name = "Host".to_string();
                b.ip_addresses = vec![vec![192, 0, 2, 7]];
            });
        check(&inside, &policy()).unwrap();

        let outside = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(7, subnet)], &[])],
            |b| {
                b.dns_names = vec![];
                b.common_name = "Host".to_string();
                b.ip_addresses = vec![vec![198, 51, 100, 7]];
            });
        let error = check(&outside, &policy()).unwrap_err();
        assert!(error.contains("IP address"), "{}", error);
    }

    /// The CA's own name is not constrained by its own extension: an
    /// intermediate confined to `.example.test` is still allowed to be
    /// called `Test Intermediate`.
    #[test]
    fn test_a_ca_does_not_constrain_itself() {
        let chain = tests_support::chain(
            |_| {},
            |b| {
                b.common_name = "Nothing Like A Host".to_string();
                b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])];
            },
            |b| {
                b.common_name = "in.example.test".to_string();
                b.dns_names = vec!["in.example.test".to_string()];
            });
        check(&chain, &policy()).unwrap();
    }

    /// Two constrained CAs both apply. The leaf must satisfy the root
    /// *and* the intermediate, which is the intersection - and a
    /// name inside one subtree but not the other is refused.
    #[test]
    fn test_constraints_from_two_levels_both_apply() {
        let configure = |permitted: &'static [u8]| {
            move |b: &mut tests_support::Builder| {
                b.extra_extensions = vec![constraints(&[(2, permitted)], &[])];
            }
        };
        let name = |host: &'static str| {
            move |b: &mut tests_support::Builder| {
                b.common_name = host.to_string();
                b.dns_names = vec![host.to_string()];
            }
        };

        // Root allows example.test, intermediate allows a.example.test.
        let inside_both = tests_support::chain(
            configure(b"example.test"), configure(b"a.example.test"),
            name("www.a.example.test"));
        check(&inside_both, &policy()).unwrap();

        // Inside the root's subtree and outside the intermediate's.
        let one_only = tests_support::chain(
            configure(b"example.test"), configure(b"a.example.test"),
            name("www.b.example.test"));
        assert!(check(&one_only, &policy()).is_err());

        // Inside the intermediate's and outside the root's. This is the
        // direction an implementation that kept only the narrowest list
        // would get wrong.
        let other_only = tests_support::chain(
            configure(b"a.example.test"), configure(b"other.test"),
            name("www.other.test"));
        assert!(check(&other_only, &policy()).is_err());
    }

    /// A critical nameConstraints extension used to fail as an
    /// unrecognised critical extension. Now it is recognised, so the
    /// reason a chain is refused is the constraint rather than the
    /// criticality - opposite remedies for whoever is reading the error.
    #[test]
    fn test_a_critical_constraint_is_no_longer_merely_unrecognised() {
        let chain = tests_support::chain(
            |_| {},
            |b| b.extra_extensions = vec![constraints(&[(2, b"example.test")], &[])],
            |b| {
                b.common_name = "in.example.test".to_string();
                b.dns_names = vec!["in.example.test".to_string()];
            });
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        assert!(intermediate.extensions.unrecognised_critical.is_empty());
        assert!(intermediate.extensions.name_constraints.is_some());
        check(&chain, &policy()).unwrap();
    }

    // ------------------------------------------------------- revocation ---

    use crate::x509::builder::{CrlBuilder, RevocationEntry};
    use crate::x509::crl::CertificateList;

    /// A chain whose intermediate may sign CRLs.
    ///
    /// `tests_support::chain`'s intermediate has keyCertSign and **not**
    /// cRLSign, which is a real configuration - RFC 5280 5.1.1.3
    /// describes a CA using separate keys for certificates and CRLs -
    /// and which `test_an_intermediate_without_crl_sign_cannot_revoke`
    /// relies on. So the revocation tests ask for the bit explicitly
    /// rather than the fixture quietly having it.
    fn revoking_chain() -> Chain {
        tests_support::chain(
            |_| {},
            |b| b.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN),
            |_| {})
    }

    /// A CRL signed by the chain's root, revoking whichever serials are
    /// given. The intermediate's serial is 2 and the leaf's is 3 - see
    /// `tests_support::chain`.
    fn crl_from_root(chain: &Chain, serials: &[&[u8]]) -> Vec<u8> {
        let mut builder = CrlBuilder::new("Test Root");
        builder.revoked = serials.iter().map(|s| RevocationEntry::new(s)).collect();
        builder.sign(&chain.root_key.signing()).unwrap()
    }

    fn crl_from_intermediate(chain: &Chain, serials: &[&[u8]]) -> Vec<u8> {
        let mut builder = CrlBuilder::new("Test Intermediate");
        builder.revoked = serials.iter().map(|s| RevocationEntry::new(s)).collect();
        builder.sign(&chain.intermediate_key.signing()).unwrap()
    }

    fn check_with(chain: &Chain, policy: &Policy, crl_ders: &[Vec<u8>])
                  -> Result<(), String> {
        let leaf = Certificate::parse(&chain.leaf)?;
        let intermediate = Certificate::parse(&chain.intermediate)?;
        let root = Certificate::parse(&chain.root)?;
        let crls: Vec<CertificateList<'_>> = crl_ders.iter()
            .map(|der| CertificateList::parse(der))
            .collect::<Result<_, _>>()?;
        verify_chain_with_crls(&[leaf, intermediate], &[root], policy,
                               Purpose::ServerAuth, &crls)
    }

    #[test]
    fn test_a_revoked_leaf_is_refused() {
        let chain = revoking_chain();
        let clean = crl_from_intermediate(&chain, &[]);
        check_with(&chain, &policy(), &[clean]).unwrap();

        let revoking = crl_from_intermediate(&chain, &[&[3]]);
        let error = check_with(&chain, &policy(), &[revoking]).unwrap_err();
        assert!(error.contains("revoked"), "{}", error);
    }

    /// **A revoked intermediate is the case revocation exists for.** Its
    /// key was compromised, and everything below it is suspect - so the
    /// check has to walk the whole chain rather than only the leaf.
    #[test]
    fn test_a_revoked_intermediate_is_refused() {
        let chain = revoking_chain();
        // Issued by the root, which is what revokes the intermediate.
        let revoking = crl_from_root(&chain, &[&[2]]);
        let error = check_with(&chain, &policy(), &[revoking]).unwrap_err();
        assert!(error.contains("revoked") && error.contains("Intermediate"),
                "{}", error);

        // And the same serial on the *intermediate's* CRL means nothing
        // about the intermediate: a CA does not revoke itself, and this
        // is the mix-up a check that ignored the issuer would make.
        let wrong_list = crl_from_intermediate(&chain, &[&[2]]);
        check_with(&chain, &policy(), &[wrong_list]).unwrap();
    }

    /// Soft fail by default: no CRL is not a failure. Hard fail on
    /// request, and then no CRL is.
    #[test]
    fn test_the_revocation_policy_decides_what_no_evidence_means() {
        let chain = revoking_chain();

        // The default.
        check_with(&chain, &policy(), &[]).unwrap();

        let strict = Policy { require_revocation: true, ..policy() };
        let error = check_with(&chain, &strict, &[]).unwrap_err();
        assert!(error.contains("could not be established"), "{}", error);

        // With a CRL covering both levels, hard fail is satisfied.
        let from_root = crl_from_root(&chain, &[]);
        let from_intermediate = crl_from_intermediate(&chain, &[]);
        check_with(&chain, &strict, &[from_root, from_intermediate]).unwrap();
    }

    /// Hard fail needs a CRL for **every** level, not just the leaf.
    /// One that covers only the leaf leaves the intermediate unknown,
    /// which is exactly the certificate whose revocation matters most.
    #[test]
    fn test_hard_fail_is_not_satisfied_by_the_leafs_crl_alone() {
        let chain = revoking_chain();
        let strict = Policy { require_revocation: true, ..policy() };
        let only_leaf = crl_from_intermediate(&chain, &[]);
        let error = check_with(&chain, &strict, &[only_leaf]).unwrap_err();
        assert!(error.contains("Intermediate"), "{}", error);
    }

    /// A revoked certificate is refused under soft fail too. The flag
    /// decides what *silence* means, never what a revocation means.
    #[test]
    fn test_soft_fail_still_refuses_a_revoked_certificate() {
        let chain = revoking_chain();
        let revoking = crl_from_intermediate(&chain, &[&[3]]);
        assert!(!policy().require_revocation);
        let error = check_with(&chain, &policy(), &[revoking]).unwrap_err();
        assert!(error.contains("revoked"), "{}", error);
    }

    /// A CRL for somebody else's chain neither clears nor revokes.
    #[test]
    fn test_another_cas_crl_is_not_evidence() {
        let chain = revoking_chain();
        let other = revoking_chain();
        // Same names, different keys - which is what an attacker who
        // can make certificates but not the CA's key has.
        let forged = crl_from_intermediate(&other, &[&[3]]);
        check_with(&chain, &policy(), std::slice::from_ref(&forged)).unwrap();

        let strict = Policy { require_revocation: true, ..policy() };
        assert!(check_with(&chain, &strict, &[forged]).is_err());
    }

    /// **An intermediate without the cRLSign bit cannot revoke.** RFC
    /// 5280 4.2.1.3: that bit is what says a key may sign a CRL, and a
    /// CA that uses separate keys for certificates and CRLs has one
    /// certificate with each. So a CRL signed by the certificate-signing
    /// key is not evidence, however convenient - and the default
    /// `tests_support::chain` intermediate is exactly that case, which
    /// is why the tests above ask for the bit.
    #[test]
    fn test_an_intermediate_without_crl_sign_cannot_revoke() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let revoking = crl_from_intermediate(&chain, &[&[3]]);
        // Not refused: the CRL is not evidence, so the chain is simply
        // unrevoked as far as anyone can tell.
        check_with(&chain, &policy(), std::slice::from_ref(&revoking)).unwrap();

        // And under hard fail it is a failure to establish, naming the
        // bit.
        let strict = Policy { require_revocation: true, ..policy() };
        let error = check_with(&chain, &strict, &[revoking]).unwrap_err();
        assert!(error.contains("cRLSign"), "{}", error);
    }

    /// The root is not checked against anything. A trust anchor is
    /// trusted because it is in the store, and the only thing that could
    /// revoke it is itself; taking it out of the store is how a root is
    /// withdrawn.
    #[test]
    fn test_the_root_is_not_subject_to_revocation() {
        let chain = revoking_chain();
        let strict = Policy { require_revocation: true, ..policy() };
        // Serial 1 is the root's. Nothing here is asked about it, so two
        // CRLs suffice even under hard fail.
        let from_root = crl_from_root(&chain, &[&[1]]);
        let from_intermediate = crl_from_intermediate(&chain, &[]);
        check_with(&chain, &strict, &[from_root, from_intermediate]).unwrap();
    }

    // ------------------------------------------------------------- OCSP ---

    use crate::x509::builder::{OcspResponseBuilder, OcspSingleResponse,
                               OcspStatus};

    /// A stapled response about the chain's leaf, signed by the
    /// intermediate that issued it.
    fn staple(chain: &Chain, status: OcspStatus) -> Vec<u8> {
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let issuer = Certificate::parse(&chain.intermediate).unwrap();
        let mut builder = OcspResponseBuilder::new("Test Intermediate");
        builder.responses = vec![
            OcspSingleResponse::about(&leaf, &issuer, "sha1", status).unwrap()];
        builder.sign(&chain.intermediate_key.signing()).unwrap()
    }

    fn check_stapled(chain: &Chain, policy: &Policy, responses: &[Vec<u8>],
                     crl_ders: &[Vec<u8>]) -> Result<(), String> {
        let leaf = Certificate::parse(&chain.leaf)?;
        let intermediate = Certificate::parse(&chain.intermediate)?;
        let root = Certificate::parse(&chain.root)?;
        let crls: Vec<CertificateList<'_>> = crl_ders.iter()
            .map(|der| CertificateList::parse(der))
            .collect::<Result<_, _>>()?;
        let ocsp: Vec<&[u8]> = responses.iter().map(|d| d.as_slice()).collect();
        verify_chain_with_revocation(
            &[leaf, intermediate], &[root], policy, Purpose::ServerAuth,
            &Revocation { crls: &crls, ocsp: &ocsp, ocsp_nonce: None })
    }

    #[test]
    fn test_a_stapled_revocation_refuses_the_chain() {
        let chain = revoking_chain();
        check_stapled(&chain, &policy(), &[staple(&chain, OcspStatus::Good)],
                      &[]).unwrap();

        let revoked = staple(&chain,
                             OcspStatus::Revoked("20230601000000Z", Some(1)));
        let error = check_stapled(&chain, &policy(), &[revoked], &[]).unwrap_err();
        assert!(error.contains("revoked"), "{}", error);
    }

    /// A stapled `good` satisfies hard fail for the leaf - and not for
    /// the intermediate, which needs its own evidence.
    #[test]
    fn test_a_staple_covers_only_the_certificate_it_is_about() {
        let chain = revoking_chain();
        let strict = Policy { require_revocation: true, ..policy() };
        let good = staple(&chain, OcspStatus::Good);

        let error = check_stapled(&chain, &strict, std::slice::from_ref(&good), &[])
                    .unwrap_err();
        assert!(error.contains("Intermediate"), "{}", error);

        // With the root's CRL covering the intermediate, hard fail is
        // satisfied.
        let from_root = crl_from_root(&chain, &[]);
        check_stapled(&chain, &strict, &[good], &[from_root]).unwrap();
    }

    /// **OCSP is consulted first and a CRL is the fallback.** A stapled
    /// `good` answers, and a stapled response about somebody else falls
    /// through to the list.
    #[test]
    fn test_ocsp_answers_first_and_a_crl_is_the_fallback() {
        let chain = revoking_chain();
        let other = revoking_chain();

        // A response about another chain's leaf: signed, valid, and not
        // about us. It must not answer, so the CRL decides - and the
        // CRL says revoked.
        let elsewhere = staple(&other, OcspStatus::Good);
        let revoking = crl_from_intermediate(&chain, &[&[3]]);
        let error = check_stapled(&chain, &policy(), std::slice::from_ref(&elsewhere),
                                  std::slice::from_ref(&revoking)).unwrap_err();
        assert!(error.contains("revoked"), "{}", error);

        // And a staple that *is* about us takes precedence over the
        // CRL, which is the point of consulting it first.
        let good = staple(&chain, OcspStatus::Good);
        check_stapled(&chain, &policy(), &[good], &[revoking]).unwrap();
    }

    /// When nothing can answer, the reasons from both sources come back
    /// together: "no CRL was supplied" and "the staple was for another
    /// certificate" send whoever is debugging in different directions.
    #[test]
    fn test_both_sources_reasons_are_reported() {
        let chain = revoking_chain();
        let other = revoking_chain();
        let strict = Policy { require_revocation: true, ..policy() };
        let elsewhere = staple(&other, OcspStatus::Good);

        let error = check_stapled(&chain, &strict, &[elsewhere], &[])
                    .unwrap_err();
        assert!(error.contains("OCSP:"), "{}", error);
        assert!(error.contains("CRL:"), "{}", error);
    }

    /// A staple from a key the CA never delegated to is not an answer,
    /// in either direction.
    #[test]
    fn test_a_forged_staple_is_not_an_answer() {
        let chain = revoking_chain();
        let stranger = tests_support::TestKey::new();
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let issuer = Certificate::parse(&chain.intermediate).unwrap();
        let mut builder = OcspResponseBuilder::new("Test Intermediate");
        builder.responses = vec![
            OcspSingleResponse::about(
                &leaf, &issuer, "sha1",
                OcspStatus::Revoked("20230601000000Z", Some(1))).unwrap()];
        let forged = builder.sign(&stranger.signing()).unwrap();

        // Not an answer, so soft fail lets it through.
        check_stapled(&chain, &policy(), std::slice::from_ref(&forged), &[]).unwrap();
        // And a genuine clean CRL still answers over the top of it.
        let clean = crl_from_intermediate(&chain, &[]);
        let from_root = crl_from_root(&chain, &[]);
        let strict = Policy { require_revocation: true, ..policy() };
        check_stapled(&chain, &strict, &[forged], &[clean, from_root]).unwrap();
    }

    // ---------------------------------------------------------- DSA ---

    /// RFC 6979's 2048 bit DSA key, read out of the vendored RFC.
    fn rfc6979_dsa() -> crate::publickey_ciphers::dsa::DsaPrivateKey {
        use crate::publickey_ciphers::dsa::{rfc6979, DsaParameters, DsaPrivateKey};
        let (fields, _) = rfc6979::section("A.2.2.  DSA, 2048 Bits");
        let get = |name| rfc6979::field(&fields, name);
        DsaPrivateKey::from_x(DsaParameters::new(get("p"), get("q"), get("g")).unwrap(),
                              get("x")).unwrap()
    }

    /// A DSA certificate from the builder, read back and verified: the
    /// Dss-Parms in the AlgorithmIdentifier, `y` as an INTEGER in the BIT
    /// STRING, and a Dss-Sig-Value. `diff_check.py x509` has OpenSSL verify
    /// the same shapes; this is the round trip that runs in the gate.
    #[test]
    fn test_a_dsa_certificate_round_trips() {
        use crate::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
        let key = rfc6979_dsa();
        for hash in ["sha1", "sha224", "sha256", "sha384", "sha512"] {
            let mut builder = CertificateBuilder::new("dsa.test", SubjectKey::Dsa(&key.public));
            builder.hash = hash;
            builder.serial = vec![1];
            let der = builder.sign(&SigningKey::Dsa(&key)).unwrap();
            let certificate = Certificate::parse(&der).unwrap();
            assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::Dsa(hash));
            assert!(matches!(&certificate.public_key,
                             PublicKey::Dsa { y, parameters: Some(_) } if *y == key.public.y));
            let policy = Policy { allow_sha1: true, ..Policy::default() };
            verify_signature(&certificate, &certificate, &policy)
                .unwrap_or_else(|e| panic!("{hash}: {e}"));
            let mut signature = certificate.signature.to_vec();
            let last = signature.len() - 1;
            signature[last] ^= 1;
            assert!(verify_signed(certificate.tbs, certificate.signature_algorithm,
                                  &signature, &certificate.public_key, &policy).is_err());
        }
    }

    /// RFC 3279 lets a DSA key leave its group out and use its issuer's.
    /// That is refused by name, rather than read as a parse failure or
    /// checked against nothing.
    #[test]
    fn test_inherited_dsa_parameters_are_named() {
        let key = rfc6979_dsa();
        let public = PublicKey::Dsa { parameters: None, y: key.public.y.clone() };
        let error = verify_signed(b"tbs", SignatureAlgorithm::Dsa("sha256"), &[0x30, 0],
                                  &public, &Policy::default()).unwrap_err();
        assert!(error.contains("inherits"), "{error}");
    }

    // -------------------------------------------------------- EdDSA ---
    //
    // Both tests below pin an *error message* rather than an outcome.
    // Removing either check left every test passing, because
    // `eddsa_verify` refuses the same inputs further down - so the
    // certificate is rejected either way, and only the message says
    // which check fired. That distinction is what a reader chasing a
    // failure needs, and `docs/pitfalls.md` records the general shape.

    /// **The OID names the algorithm twice and both must agree.** An
    /// Ed448 key with an Ed25519 signature OID is a signature being
    /// checked under a scheme nobody used.
    #[test]
    fn test_an_eddsa_variant_mismatch_is_named() {
        let key = PublicKey::Eddsa { curve: "ed448", key: &[0x11; 57] };
        let error = verify_eddsa(b"tbs", &[0u8; 64], &key, "ed25519", &policy())
            .unwrap_err();
        assert!(error.contains("says ed25519"), "{}", error);
        assert!(error.contains("key is ed448"), "{}", error);
    }

    /// The length check lives in `api::eddsa_verify` and **not** in
    /// `verify_eddsa`, which is what the sweep settled: a copy here
    /// produced the same message from one layer up, so removing it
    /// failed no test even with the message pinned. One check, one
    /// message, one place to change it.
    #[test]
    fn test_a_wrong_length_eddsa_signature_is_named() {
        let key = PublicKey::Eddsa { curve: "ed25519", key: &[0x11; 32] };
        for length in [0usize, 63, 65, 114] {
            let error = verify_eddsa(b"tbs", &vec![0u8; length], &key,
                                     "ed25519", &policy()).unwrap_err();
            assert!(error.contains("signature is 64 bytes"),
                    "length {length} gave {error:?}");
        }
        // A 64 byte signature gets past the length check and fails on
        // the arithmetic, which is a different message - so the check
        // above is not simply refusing everything.
        let error = verify_eddsa(b"tbs", &[0u8; 64], &key, "ed25519", &policy())
            .unwrap_err();
        assert!(error.contains("does not verify"), "{}", error);
    }

    /// A key of the wrong *kind* is refused by name too, rather than
    /// reaching EdDSA with an RSA modulus.
    #[test]
    fn test_a_non_eddsa_key_cannot_verify_an_eddsa_signature() {
        let key = PublicKey::Unsupported { algorithm: &[0x2a] };
        let error = verify_eddsa(b"tbs", &[0u8; 64], &key, "ed25519", &policy())
            .unwrap_err();
        assert!(error.contains("cannot verify an EdDSA signature"), "{}", error);
    }
}
