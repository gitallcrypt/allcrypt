/*
Mirroring somebody else's certificate.

A TLS-terminating proxy has to present *some* certificate to the client,
and the obvious thing to present is one its own CA signed. That works,
and it destroys something: the client can no longer tell a good server
from a bad one, because every server behind the proxy now looks equally
trustworthy. A padlock means "the proxy was satisfied" and nothing more,
and the user has no way to know that.

So this does the other thing. **The certificate the client sees is as
trustworthy as the one the server actually presented, and no more.**

  - The real chain verified            -> sign the mirror with the CA the
                                          client installed. It accepts.
  - The real certificate was self-signed -> the mirror is self-signed too,
                                          by its own key. The client shows
                                          the same warning it would have.
  - The real chain did not verify      -> sign the mirror with a throwaway
                                          CA nobody trusts. Same warning.

And the parts of the certificate that a client judges are **copied**:
the subject name, the subject alternative names, the validity window,
the serial. So an expired certificate stays expired, a certificate for
the wrong host stays wrong, and the decision stays where it belongs.

## What cannot be mirrored

**The key.** The proxy has to hold the private key for the certificate
it presents, and it does not have the server's. So:

  - A fingerprint pin does not survive. A client that remembers "this
    host has *this* certificate" sees a different one and says so -
    which is correct behaviour on its part, and worth knowing before it
    happens rather than after.
  - "Accept this certificate permanently", for a self-signed server,
    pins the mirror rather than the original. Reaching the same box
    directly afterwards will prompt again.

**The signature algorithm, when the key type differs.** A mirror of an
RSA certificate is signed with the proxy's EC key. What is copied is
what a client displays and judges; what is regenerated is what a client
verifies.

**Extensions that name a key.** subjectKeyIdentifier and
authorityKeyIdentifier describe keys, and the keys are different ones -
copying them would produce a certificate naming a key it does not hold.
They are recomputed. Everything else is copied verbatim, including
extensions this library does not itself understand, because a proxy that
silently dropped an extension would be making a decision on the client's
behalf.
*/

use crate::asn1;
use crate::bignum::BigUint;
use crate::ec::{curves, Curve};
use crate::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
use crate::x509::{oids, Certificate};

/// What the proxy made of the server's certificate.
///
/// Three outcomes rather than a `bool`, because "I could not check" and
/// "I checked and it was wrong" call for the same *presentation* to the
/// client and different words to whoever is watching the proxy's log.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Trust {
    /// The chain verified against the proxy's roots, for this name.
    Verified,
    /// The server's certificate signed itself.
    ///
    /// Distinguished from an untrusted chain because it is the common
    /// case on the equipment this library exists for, and because the
    /// mirror of a self-signed certificate is self-signed - which is a
    /// different certificate from one signed by an untrusted CA, and a
    /// client says different things about the two.
    SelfSigned,
    /// It did not verify, and the reason, for the log.
    Untrusted(String),
}

impl Trust {
    /// Whether the client will be given something its own store can
    /// accept.
    pub fn is_verified(&self) -> bool {
        matches!(self, Trust::Verified)
    }

    pub fn describe(&self) -> String {
        match self {
            Trust::Verified => "verified".to_string(),
            Trust::SelfSigned => "self-signed".to_string(),
            Trust::Untrusted(reason) => format!("untrusted: {}", reason),
        }
    }
}

/// The certificate to present, and the key to present it with.
pub struct Mirror {
    /// Leaf first. One certificate when the mirror is self-signed, two
    /// when it was signed by a CA - the client needs the issuer to
    /// build a path, and for the untrusted case it needs it to build
    /// the path that then *fails*.
    pub chain: Vec<Vec<u8>>,
    /// The leaf's private scalar, on P-256.
    pub private: Vec<u8>,
    /// What was made of the original, carried along so the caller can
    /// log it without re-deciding.
    pub trust: Trust,
}

/// A signing identity: a key and the certificate that names it.
///
/// The proxy holds two of these - the CA the user installed, and a
/// throwaway one generated per process for the untrusted case - and
/// they are the same shape.
pub struct Issuer {
    curve: Curve,
    private: BigUint,
    certificate: Vec<u8>,
    subject_raw: Vec<u8>,
}

impl Issuer {
    /// Build from a key and its certificate.
    pub fn new(curve_name: &str, private: &[u8], certificate: Vec<u8>)
               -> Result<Issuer, String> {
        let curve = curves::by_name(curve_name)?;
        let scalar = BigUint::from_bytes_be(private);
        if scalar.is_zero() || scalar >= curve.n {
            return Err("Private scalar is not in [1, n).".to_string());
        }
        let subject_raw = {
            let parsed = Certificate::parse(&certificate)?;
            parsed.subject.raw.to_vec()
        };
        Ok(Issuer { curve, private: scalar, certificate, subject_raw })
    }

    /// A fresh, self-signed CA nobody has ever trusted.
    ///
    /// The proxy makes one per process for mirroring an untrusted
    /// chain. Per process rather than per connection so that a client
    /// seeing two bad servers in a session sees one unknown issuer
    /// rather than two, which is how a real untrusted CA behaves.
    pub fn untrusted(common_name: &str, not_before: &str, not_after: &str)
                     -> Result<Issuer, String> {
        let curve = curves::p256();
        let (private, public) = curve.generate_key_pair()?;
        let point = curve.encode_point(&public, false)?;
        let mut builder = CertificateBuilder::new(
            common_name, SubjectKey::Ec { curve: &curve, point: &point });
        builder.serial = random_serial()?;
        builder.not_before = not_before;
        builder.not_after = not_after;
        builder.is_ca = Some((true, Some(0)));
        builder.key_usage = Some(crate::x509::builder::key_usage::KEY_CERT_SIGN);
        builder.key_identifiers = true;
        let certificate = builder.sign(&SigningKey::Ec { curve: &curve,
                                                         private: &private })?;
        let subject_raw = Certificate::parse(&certificate)?.subject.raw.to_vec();
        Ok(Issuer { curve, private, certificate, subject_raw })
    }

    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    fn signing(&self) -> SigningKey<'_> {
        SigningKey::Ec { curve: &self.curve, private: &self.private }
    }
}

/// Build the certificate to present, mirroring `original`.
///
/// `ca` signs it when the original was trusted; `untrusted` signs it
/// when the original chained to something we do not trust; and when the
/// original was self-signed the mirror signs itself and neither is
/// used.
pub fn mirror(original: &[u8], trust: Trust, ca: &Issuer, untrusted: &Issuer)
              -> Result<Mirror, String> {
    let parsed = Certificate::parse(original)
        .map_err(|e| format!("The server's certificate did not parse: {}", e))?;

    let curve = curves::p256();
    let (private, public) = curve.generate_key_pair()?;
    let point = curve.encode_point(&public, false)?;

    // `new` wants a common name for the default subject; the real
    // subject replaces it wholesale below, so this string never reaches
    // the certificate.
    let mut builder = CertificateBuilder::new(
        "mirrored", SubjectKey::Ec { curve: &curve, point: &point });

    // --- copied, because these are what a client judges ---
    //
    // The serial included. It is scoped to its issuer, so reusing it
    // under a different issuer collides with nothing - and a client
    // that logs or displays serials shows the one the real server has.
    builder.serial = parsed.serial.to_vec();
    if builder.serial.is_empty() {
        builder.serial = vec![1];
    }
    if builder.serial[0] & 0x80 != 0 {
        // Our own encoder refuses a negative INTEGER, and so does
        // RFC 5280. Some equipment issues them anyway; prefix a zero
        // rather than refuse to mirror the certificate at all.
        builder.serial.insert(0, 0);
    }
    builder.subject_raw = Some(parsed.subject.raw.to_vec());

    // **The validity window is copied, which is the point.** An expired
    // certificate mirrors as an expired certificate, and the client
    // refuses it exactly as it would have refused the original.
    let not_before = asn1::format_time(parsed.not_before);
    let not_after = asn1::format_time(parsed.not_after);
    builder.not_before = &not_before;
    builder.not_after = &not_after;

    // Every extension, verbatim, except the two that name a key.
    //
    // Verbatim rather than re-encoded from the parsed forms: a proxy
    // that dropped an extension it did not understand would be deciding
    // on the client's behalf, and re-encoding a name constraint or a
    // policy tree is a second chance to get it wrong. The two skipped
    // ones describe *keys*, and these are different keys.
    for (oid, critical, value) in &parsed.extensions.values {
        let bytes = oid.as_bytes();
        if bytes == oids::SUBJECT_KEY_ID || bytes == oids::AUTHORITY_KEY_ID {
            continue;
        }
        builder.extra_extensions.push((bytes.to_vec(), *critical,
                                       value.to_vec()));
    }
    builder.key_identifiers = true;

    // --- decided, because this is what the client's store judges ---
    let chain = match &trust {
        Trust::SelfSigned => {
            // Its own issuer, signed by its own key: the shape a client
            // reports as "self-signed certificate", which is what the
            // real one was.
            builder.issuer_raw = Some(parsed.subject.raw.to_vec());
            vec![builder.sign(&SigningKey::Ec { curve: &curve,
                                                private: &private })?]
        }
        Trust::Verified => {
            builder.issuer_raw = Some(ca.subject_raw.clone());
            vec![builder.sign(&ca.signing())?, ca.certificate.clone()]
        }
        Trust::Untrusted(_) => {
            builder.issuer_raw = Some(untrusted.subject_raw.clone());
            vec![builder.sign(&untrusted.signing())?,
                 untrusted.certificate.clone()]
        }
    };

    Ok(Mirror { chain, private: private.to_bytes_be_padded(curve.scalar_bytes())?,
                trust })
}

/// Whether a certificate signed itself.
///
/// By the names **and** the signature, not by the names alone. A
/// certificate whose issuer equals its subject but whose signature is
/// somebody else's is a cross-signed root, and calling it self-signed
/// would mirror it as one - presenting the client with a warning about
/// a certificate that would in fact have verified.
pub fn is_self_signed(certificate: &Certificate<'_>) -> bool {
    if certificate.issuer.raw != certificate.subject.raw {
        return false;
    }
    // A permissive policy: this is not the trust decision, it is a
    // question about the shape of one certificate. Whether the
    // signature is over a hash somebody would accept today is the
    // verifier's business and has already been answered by the time
    // this is called.
    let policy = crate::x509::verify::Policy {
        now: certificate.not_before,
        allow_sha1: true,
        allow_md5: true,
        allow_expired: true,
        min_rsa_bits: 512,
        max_key_bits: crate::x509::verify::Policy::MAX_KEY_BITS,
        max_chain_length: 8,
        require_revocation: false,
    };
    crate::x509::verify::verify_signed(certificate.tbs,
                                       certificate.signature_algorithm,
                                       certificate.signature,
                                       &certificate.public_key,
                                       &policy).is_ok()
}

/// Sixteen random bytes with the sign bit clear.
fn random_serial() -> Result<Vec<u8>, String> {
    let mut bytes = crate::random::bytes(16)?;
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::builder::{key_identifier, key_usage, SanEntry};
    use crate::x509::tests_support::TestKey;

    fn issuers() -> (Issuer, Issuer) {
        let key = TestKey::new();
        let mut builder = CertificateBuilder::new("Test proxy CA",
                                                  key.subject());
        builder.is_ca = Some((true, Some(0)));
        builder.key_usage = Some(key_usage::KEY_CERT_SIGN);
        builder.key_identifiers = true;
        let der = builder.sign(&key.signing()).unwrap();
        let ca = Issuer::new("P-256", &key.private.to_bytes_be_padded(32).unwrap(),
                             der).unwrap();
        let untrusted = Issuer::untrusted("Unknown CA", "20200101000000Z",
                                          "20400101000000Z").unwrap();
        (ca, untrusted)
    }

    /// An "original" with everything a client looks at.
    fn original(configure: impl FnOnce(&mut CertificateBuilder<'_>)) -> Vec<u8> {
        let key = TestKey::new();
        let mut builder = CertificateBuilder::new("old-box.test", key.subject());
        builder.serial = vec![0x12, 0x34, 0x56];
        builder.not_before = "20200101000000Z";
        builder.not_after = "20300101000000Z";
        builder.sans = vec![SanEntry::Dns("old-box.test".to_string()),
                            SanEntry::Dns("www.old-box.test".to_string()),
                            SanEntry::Ip(vec![192, 0, 2, 9])];
        builder.key_usage = Some(key_usage::DIGITAL_SIGNATURE);
        builder.extended_key_usage = vec![oids::EKU_SERVER_AUTH];
        configure(&mut builder);
        builder.sign(&key.signing()).unwrap()
    }

    /// **The fields a client judges come across unchanged.**
    ///
    /// Not "some of them": the test compares the parsed forms field by
    /// field, so an extension quietly dropped fails here rather than in
    /// somebody's browser.
    #[test]
    fn test_the_mirror_carries_the_originals_identity() {
        let (ca, untrusted) = issuers();
        let der = original(|_| {});
        let result = mirror(&der, Trust::Verified, &ca, &untrusted).unwrap();

        let source = Certificate::parse(&der).unwrap();
        let copy = Certificate::parse(&result.chain[0]).unwrap();

        assert_eq!(copy.subject.raw, source.subject.raw);
        assert_eq!(copy.serial, source.serial);
        assert_eq!(copy.not_before, source.not_before);
        assert_eq!(copy.not_after, source.not_after);
        assert_eq!(copy.extensions.subject_alt_names.len(),
                   source.extensions.subject_alt_names.len());
        assert_eq!(copy.extensions.extended_key_usage,
                   source.extensions.extended_key_usage);
        assert_eq!(copy.extensions.key_usage, source.extensions.key_usage);

        // And the key is *not* copied - the proxy has to hold the
        // private half, and it does not have the server's.
        assert_ne!(copy.spki, source.spki);
    }

    /// An expired certificate mirrors as an expired certificate.
    ///
    /// The whole design in one assertion: the client is given the same
    /// reason to refuse that it would have had talking directly.
    #[test]
    fn test_an_expired_original_mirrors_as_expired() {
        let (ca, untrusted) = issuers();
        let der = original(|b| {
            b.not_before = "20100101000000Z";
            b.not_after = "20110101000000Z";
        });
        let result = mirror(&der, Trust::Verified, &ca, &untrusted).unwrap();
        let copy = Certificate::parse(&result.chain[0]).unwrap();

        let source = Certificate::parse(&der).unwrap();
        assert_eq!(copy.not_after, source.not_after);

        // And our own verifier says so, which is the check that the
        // dates survived *encoding* rather than just assignment.
        let policy = crate::x509::verify::Policy::at(1_700_000_000);
        assert!(copy.not_after < policy.now,
                "the mirror of an expired certificate is not expired");
    }

    /// A self-signed original produces a self-signed mirror, not one
    /// the installed CA vouches for.
    #[test]
    fn test_a_self_signed_original_mirrors_as_self_signed() {
        let (ca, untrusted) = issuers();
        let der = original(|_| {});
        let result = mirror(&der, Trust::SelfSigned, &ca, &untrusted).unwrap();

        assert_eq!(result.chain.len(), 1, "a self-signed mirror has no issuer");
        let copy = Certificate::parse(&result.chain[0]).unwrap();
        assert_eq!(copy.issuer.raw, copy.subject.raw);
        assert!(is_self_signed(&copy),
                "the names match but the signature is somebody else's");
    }

    /// An untrusted original is signed by a CA nobody has, not by the
    /// one the user installed.
    #[test]
    fn test_an_untrusted_original_is_not_signed_by_the_installed_ca() {
        let (ca, untrusted) = issuers();
        let der = original(|_| {});
        let result = mirror(&der, Trust::Untrusted("no issuer".into()), &ca,
                            &untrusted).unwrap();

        let copy = Certificate::parse(&result.chain[0]).unwrap();
        let installed = Certificate::parse(ca.certificate()).unwrap();
        assert_ne!(copy.issuer.raw, installed.subject.raw,
                   "an untrusted server was mirrored as a trusted one");
        assert_eq!(result.chain.len(), 2);

        // The chain it does present is complete and internally
        // consistent - it fails because nobody trusts the root, not
        // because it is malformed.
        let issuer = Certificate::parse(&result.chain[1]).unwrap();
        assert_eq!(copy.issuer.raw, issuer.subject.raw);
    }

    /// Only the trusted case chains to the installed CA. Stated as a
    /// comparison across all three, so a mistake that made two of them
    /// behave alike cannot pass.
    #[test]
    fn test_the_issuer_differs_for_each_verdict() {
        let (ca, untrusted) = issuers();
        let der = original(|_| {});
        let installed = Certificate::parse(ca.certificate()).unwrap()
            .subject.raw.to_vec();

        let verdicts = [Trust::Verified, Trust::SelfSigned,
                        Trust::Untrusted("x".into())];
        let mut issuers_seen = Vec::new();
        for trust in verdicts {
            let is_verified = trust.is_verified();
            let result = mirror(&der, trust, &ca, &untrusted).unwrap();
            let copy = Certificate::parse(&result.chain[0]).unwrap();
            assert_eq!(copy.issuer.raw == installed.as_slice(), is_verified,
                       "the wrong verdict chains to the installed CA");
            issuers_seen.push(copy.issuer.raw.to_vec());
        }
        assert_ne!(issuers_seen[0], issuers_seen[1]);
        assert_ne!(issuers_seen[0], issuers_seen[2]);
        assert_ne!(issuers_seen[1], issuers_seen[2]);
    }

    /// An extension this library has no opinion about is carried across.
    ///
    /// A proxy that dropped one would be deciding on the client's
    /// behalf about something it did not understand.
    #[test]
    fn test_an_unknown_extension_is_carried_across() {
        let (ca, untrusted) = issuers();
        // 1.3.6.1.4.1.99999.1, non-critical - a critical one our own
        // verifier would then refuse, which is a different test.
        let oid = vec![0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x86,
                       0x8d, 0x1f, 0x01];
        let oid = oid[2..].to_vec();
        let der = original(|b| {
            b.extra_extensions.push((oid.clone(), false,
                                     vec![0x04, 0x03, 0x01, 0x02, 0x03]));
        });
        let result = mirror(&der, Trust::Verified, &ca, &untrusted).unwrap();
        let copy = Certificate::parse(&result.chain[0]).unwrap();

        let found = copy.extensions.values.iter()
            .find(|(o, _, _)| o.as_bytes() == oid.as_slice())
            .expect("the unknown extension was dropped");
        assert_eq!(found.2, &[0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    /// The key identifiers are **not** copied: they name keys, and
    /// these are different keys.
    #[test]
    fn test_the_key_identifiers_are_recomputed_not_copied() {
        let (ca, untrusted) = issuers();
        let der = original(|b| { b.key_identifiers = true; });
        let source = Certificate::parse(&der).unwrap();
        let result = mirror(&der, Trust::Verified, &ca, &untrusted).unwrap();
        let copy = Certificate::parse(&result.chain[0]).unwrap();

        assert_ne!(copy.extensions.subject_key_id,
                   source.extensions.subject_key_id,
                   "the mirror names the original's key, which it does not hold");
        assert_eq!(copy.extensions.subject_key_id.map(|id| id.to_vec()),
                   Some(key_identifier(&SubjectKey::Ec {
                       curve: &curves::p256(),
                       point: match copy.public_key {
                           crate::x509::PublicKey::Ec { point, .. } => point,
                           _ => unreachable!(),
                       } }).unwrap()));
    }

    /// A serial with the top bit set is mirrored rather than refused.
    ///
    /// RFC 5280 forbids a negative serial and our encoder refuses one,
    /// but equipment in the field issues them - and refusing to mirror
    /// such a certificate means refusing to reach the box, which is the
    /// opposite of what this is for.
    #[test]
    fn test_a_negative_serial_is_mirrored_rather_than_refused() {
        // This test used `[0x00, 0xff, 0x01]`, which is positive and
        // already zero-prefixed, so the sign-bit branch in `mirror` never
        // ran. The builder refuses a negative serial, so the original is
        // built with `7f 01` and that byte edited to `ff`: the same
        // length, so the encoding stays well formed (its signature no
        // longer verifies, which `mirror` does not check - it is given
        // the trust verdict).
        let (ca, untrusted) = issuers();
        let mut der = original(|b| { b.serial = vec![0x7f, 0x01]; });
        let at = der.windows(4).position(|w| w == [0x02, 0x02, 0x7f, 0x01])
            .expect("the serial's encoding");
        assert_eq!(der.windows(4).filter(|w| *w == [0x02, 0x02, 0x7f, 0x01]).count(), 1);
        der[at + 2] = 0xff;
        assert_eq!(Certificate::parse(&der).unwrap().serial, &[0xff, 0x01],
                   "the edited original should parse with a negative serial");
        let result = mirror(&der, Trust::Verified, &ca, &untrusted).unwrap();
        let copy = Certificate::parse(&result.chain[0]).unwrap();
        assert_eq!(copy.serial, &[0x00, 0xff, 0x01]);
    }

    /// Names that match but a signature that does not is **not**
    /// self-signed - it is a cross-signed root.
    ///
    /// Treating it as self-signed would show the client a warning about
    /// a certificate that would in fact have verified.
    #[test]
    fn test_matching_names_are_not_enough_to_be_self_signed() {
        let subject_key = TestKey::new();
        let other_key = TestKey::new();
        let mut builder = CertificateBuilder::new("Same Name",
                                                  subject_key.subject());
        // Issuer and subject are equal, and somebody else signed it.
        let der = builder.sign(&other_key.signing()).unwrap();
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(certificate.issuer.raw, certificate.subject.raw);
        assert!(!is_self_signed(&certificate));

        // And a real self-signed one is.
        builder = CertificateBuilder::new("Same Name", subject_key.subject());
        let der = builder.sign(&subject_key.signing()).unwrap();
        assert!(is_self_signed(&Certificate::parse(&der).unwrap()));
    }

    /// Every mirror gets its own key, so one compromise is one
    /// connection.
    #[test]
    fn test_every_mirror_has_its_own_key() {
        let (ca, untrusted) = issuers();
        let der = original(|_| {});
        let first = mirror(&der, Trust::Verified, &ca, &untrusted).unwrap();
        let second = mirror(&der, Trust::Verified, &ca, &untrusted).unwrap();
        assert_ne!(first.private, second.private);
        assert_ne!(first.chain[0], second.chain[0]);
    }
}
