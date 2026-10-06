/*
Certificate revocation lists: RFC 5280 section 5.

A CRL is a signed list of serial numbers its issuer has revoked. Checking
one is not "is the serial in the list" - that question has a right answer
and several wrong ones that all look like it, and every wrong one fails
in the same direction: **a certificate that is revoked appears not to
be.**

So this module's whole shape is built around refusing to answer rather
than answering wrongly. `Status` has three values, not two:

  * `Revoked` - an applicable CRL lists it;
  * `NotRevoked` - an applicable CRL that covers this certificate's whole
    scope does not list it;
  * `Unknown` - nothing applicable was supplied, or what was supplied
    covers only part of the scope, or was stale, or could not be trusted.

`Unknown` is not `NotRevoked`, and collapsing the two is the bug this
whole file exists to avoid. What to *do* about `Unknown` is the caller's
decision - hard fail or soft fail - and `Policy::require_revocation`
carries it, because it is a deployment question rather than a
cryptographic one. A machine that must reach an old server on a network
with no CRL distribution point in reach needs soft fail; a machine
issuing money does not.

## The ways of getting this wrong

**A delta CRL is not a CRL.** RFC 5280 5.2.4: a delta lists only what
*changed* since a base CRL. Read as a complete list, every certificate
revoked before the base and not changed since appears unrevoked - which
is most of them, and the revocations it hides are the old ones, which
are the ones that matter. A delta carries a critical deltaCRLIndicator
saying so, and this refuses to use one alone. `combine` applies RFC 5280
5.2.4's four conditions and merges a delta onto its base.

**removeFromCRL un-revokes.** Reason code 8 may only appear in a delta
and means the entry is gone - expired, or off hold. A merge that treated
it as a revocation reason like any other would revoke exactly the
certificates the delta was issued to release.

**A partitioned CRL does not cover everything.** An
issuingDistributionPoint may say the list holds only end-entity
certificates, only CA certificates, or only certain revocation reasons.
"Not on this list" then means nothing about the rest, and
`onlySomeReasons` in particular is easy to read past: the CRL is
complete, valid, correctly signed, and silent about key compromise. Here
that yields `Unknown`, with the reasons it does cover named.

**An indirect CRL attributes entries to other issuers.** The
certificateIssuer entry extension (5.3.3) names whose certificate an
entry is about, and - the part that catches people - **it carries
forward**: "On subsequent entries in an indirect CRL, if this extension
is not present, the certificate issuer for the entry is the same as that
for the preceding entry." So it is stateful during parsing, and an
implementation that reads each entry independently attributes every
unmarked entry after the first marked one to the CRL issuer, which is
wrong in both directions at once.

**Stale is not clean.** A CRL past its nextUpdate says what was true
then. Treating it as current is how a revocation published yesterday is
missed; treating it as absent is `Unknown`, which is what happens here.
A CRL with **no** nextUpdate at all is a conforming CRL issuer's mistake
(5.1.2: "This profile requires conforming CRL issuers to include the
nextUpdate field") and never expires, so it is accepted and marked.

**The wrong signer.** A CRL is only evidence if the certificate's own
issuer signed it, with the cRLSign bit set. A CRL checked against the
wrong key, or against the right key without checking the signature at
all, is a list an attacker writes. And the converse: a CRL from the
right issuer that does not verify must make the status `Unknown`, never
`NotRevoked`.

**Serial numbers are not integers here.** They are arbitrary length and
compared as the INTEGER's content octets. That is only safe because
`asn1::Reader` refuses a non-minimal INTEGER - two encodings of one
number would otherwise be two different serials, and a CRL entry written
with a redundant leading zero would miss its certificate. The parser's
strictness is load bearing at exactly this point.

## What is not here

**A CRL signed by a key other than the certificate issuer's.** RFC 5280
5.1.1.3 makes supporting the same-key case a MUST and the different-key
case a SHOULD, because the second needs a whole second certification
path built and validated for the CRL signer. A CRL whose issuer is not
the certificate's issuer is refused by name here rather than trusted.

**Fetching.** Nothing in this library opens a socket, and that is a
rule rather than an omission: the protocol code is sans-I/O, so it can
be tested against recorded bytes with no network. `distribution_points`
reports where a certificate says its CRL lives; getting it is the
caller's job.

## One deliberate divergence from OpenSSL

RFC 5280 section 6.3.3's algorithm consults a delta CRL only in
combination with a complete one, and `openssl verify` follows it: a
delta supplied on its own is ignored entirely, and reports "unable to
get certificate CRL" even when the delta lists the certificate as
revoked.

Here it revokes. A delta that does not fit a base cannot *clear*
anything - that much is agreed, and is the direction where being wrong
is dangerous - but it is still the CA, over its own signature, saying
this serial is revoked. Ignoring that discards a true statement about a
certificate the CA has withdrawn, and the only way to inject a false
one is to forge the CA's signature, which buys an attacker a denial of
service on a single certificate rather than a bypass of anything.

The same asymmetry runs through the rest of this file: a stale CRL
revokes and cannot clear; a reason-partitioned CRL revokes and can only
clear the reasons it carries. Being *on* a list is an answer; being off
it is a claim about coverage. OpenSSL agrees on both of those, so the
divergence is narrow, and `tools/src/bin/diff_crl.rs` says where it is.
*/

use crate::asn1::{self, Oid, Reader, Tag};
use crate::bignum::BigUint;
use crate::x509::verify::{verify_signed, Policy};
use crate::x509::{oids, read_general_name, Certificate, GeneralName, Name,
                  SignatureAlgorithm, ADDRESS_ONLY};

/// RFC 5280 5.3.1's `CRLReason`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    /// Temporary. The certificate may come off hold, and a delta CRL
    /// says so with `RemoveFromCrl`.
    CertificateHold,
    /// **Not a revocation.** Only legal in a delta CRL, where it means
    /// the entry is being withdrawn.
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
    /// A value the enumeration does not define. Kept rather than
    /// refused: a reason we cannot name is still a revocation.
    Other(u32),
}

impl Reason {
    /// The same, for `ocsp.rs`: a `RevokedInfo` carries a `CRLReason`,
    /// which RFC 6960 imports from RFC 5280 section 5.3.1 rather than
    /// defining again. One enumeration, one place that knows it.
    pub fn from_value_public(value: u32) -> Reason {
        Reason::from_value(value)
    }

    fn from_value(value: u32) -> Reason {
        match value {
            0 => Reason::Unspecified,
            1 => Reason::KeyCompromise,
            2 => Reason::CaCompromise,
            3 => Reason::AffiliationChanged,
            4 => Reason::Superseded,
            5 => Reason::CessationOfOperation,
            6 => Reason::CertificateHold,
            8 => Reason::RemoveFromCrl,
            9 => Reason::PrivilegeWithdrawn,
            10 => Reason::AaCompromise,
            other => Reason::Other(other),
        }
    }

    /// Its position in the `ReasonFlags` BIT STRING of an
    /// issuingDistributionPoint, which is **not** the enumerated value.
    ///
    /// RFC 5280 4.2.1.13 numbers the bits `unused(0)`,
    /// `keyCompromise(1)` ... so they line up for 1 to 6 and then
    /// diverge: the flags have `privilegeWithdrawn(7)` and
    /// `aACompromise(8)` where the enumeration has nothing at 7,
    /// `removeFromCRL(8)`, `privilegeWithdrawn(9)` and
    /// `aACompromise(10)`. Two numberings for one idea, agreeing over
    /// most of their range, which is the shape that gets copied wrong.
    fn flag_bit(self) -> Option<u8> {
        Some(match self {
            Reason::Unspecified => 0,
            Reason::KeyCompromise => 1,
            Reason::CaCompromise => 2,
            Reason::AffiliationChanged => 3,
            Reason::Superseded => 4,
            Reason::CessationOfOperation => 5,
            Reason::CertificateHold => 6,
            Reason::PrivilegeWithdrawn => 7,
            Reason::AaCompromise => 8,
            // Not a reason a distribution point can be scoped to.
            Reason::RemoveFromCrl | Reason::Other(_) => return None,
        })
    }

    pub fn name(self) -> String {
        match self {
            Reason::Unspecified => "unspecified".to_string(),
            Reason::KeyCompromise => "keyCompromise".to_string(),
            Reason::CaCompromise => "cACompromise".to_string(),
            Reason::AffiliationChanged => "affiliationChanged".to_string(),
            Reason::Superseded => "superseded".to_string(),
            Reason::CessationOfOperation => "cessationOfOperation".to_string(),
            Reason::CertificateHold => "certificateHold".to_string(),
            Reason::RemoveFromCrl => "removeFromCRL".to_string(),
            Reason::PrivilegeWithdrawn => "privilegeWithdrawn".to_string(),
            Reason::AaCompromise => "aACompromise".to_string(),
            Reason::Other(value) => format!("reason code {}", value),
        }
    }
}

/// One entry on the list.
#[derive(Clone, Debug)]
pub struct RevokedCertificate<'a> {
    /// The serial's content octets, exactly as `Certificate::serial`
    /// holds them, so the two compare directly.
    pub serial: &'a [u8],
    pub revoked_at: i64,
    pub reason: Option<Reason>,
    /// Whose certificate this entry is about, as DER.
    ///
    /// `None` means the CRL's own issuer. On an indirect CRL this comes
    /// from the certificateIssuer entry extension and **carries forward
    /// from the previous entry** when absent - which is why it is
    /// resolved during parsing rather than left to the caller.
    pub certificate_issuer: Option<&'a [u8]>,
}

/// RFC 5280 5.2.5. What part of the space this CRL claims to cover.
#[derive(Clone, Debug, Default)]
pub struct IssuingDistributionPoint<'a> {
    pub distribution_point: Option<&'a [u8]>,
    pub only_user_certs: bool,
    pub only_ca_certs: bool,
    pub only_attribute_certs: bool,
    /// The `ReasonFlags` bits, if the CRL is partitioned by reason.
    /// `None` means it covers all reasons, which is the common case and
    /// the only one under which absence from the list means anything.
    pub only_some_reasons: Option<u16>,
    pub indirect: bool,
}

impl IssuingDistributionPoint<'_> {
    /// Whether this CRL carries revocations for `reason`. A CRL with no
    /// `onlySomeReasons` carries all of them, which is the only case
    /// under which absence from it settles anything on its own.
    pub fn covers_reason(&self, reason: Reason) -> bool {
        match self.only_some_reasons {
            None => true,
            Some(flags) => flags_cover(flags, reason),
        }
    }
}

/// A parsed `CertificateList`.
#[derive(Clone, Debug)]
pub struct CertificateList<'a> {
    pub raw: &'a [u8],
    /// The TBSCertList, tag and length included: the bytes signed.
    pub tbs: &'a [u8],
    /// 1 or 2. The ASN.1 value is zero-based; this is not, and the field
    /// is absent on a v1 CRL.
    pub version: u32,
    pub signature_algorithm: SignatureAlgorithm,
    pub outer_algorithm: SignatureAlgorithm,
    pub issuer: Name<'a>,
    pub this_update: i64,
    pub next_update: Option<i64>,
    pub revoked: Vec<RevokedCertificate<'a>>,
    pub signature: &'a [u8],

    // ------------------------------------------------- CRL extensions ---
    pub crl_number: Option<BigUint>,
    /// The `BaseCRLNumber` from a deltaCRLIndicator. `Some` means **this
    /// is a delta CRL** and is not a complete list of anything.
    pub delta_from: Option<BigUint>,
    pub issuing_distribution_point: Option<IssuingDistributionPoint<'a>>,
    pub authority_key_id: Option<&'a [u8]>,
    /// Critical CRL extensions not recognised here. A CRL carrying one
    /// cannot be used, for the same reason a certificate cannot.
    pub unrecognised_critical: Vec<Oid<'a>>,
}

/// What a CRL check concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// An applicable CRL lists this certificate.
    Revoked { at: i64, reason: Option<Reason> },
    /// An applicable CRL, covering this certificate's whole scope, does
    /// not list it.
    NotRevoked,
    /// No conclusion. **Not the same as `NotRevoked`**, and the reason
    /// says which of the several ways this happened.
    Unknown(String),
}

impl Status {
    pub fn is_revoked(&self) -> bool {
        matches!(self, Status::Revoked { .. })
    }

    /// The message a caller should report, or `None` if the certificate
    /// is positively not revoked.
    pub fn describe(&self) -> Option<String> {
        match self {
            Status::NotRevoked => None,
            Status::Revoked { at, reason } => Some(match reason {
                Some(reason) => format!("Revoked at {} ({}).", at, reason.name()),
                None => format!("Revoked at {}, with no reason given.", at),
            }),
            Status::Unknown(why) => Some(format!("Revocation status unknown: {}", why)),
        }
    }
}

// -------------------------------------------------------------- parsing ---

impl<'a> CertificateList<'a> {
    pub fn parse(der: &'a [u8]) -> Result<CertificateList<'a>, String> {
        let mut outer = Reader::new(der);
        let mut list = outer.read_sequence()?;
        outer.finish()?;

        let tbs = list.clone().read_raw()?;
        let mut body = list.read_sequence()?;
        let outer_algorithm = crate::x509::read_algorithm(&mut list)?;
        let signature = list.read_bit_string()?;
        list.finish()?;

        // `version` is OPTIONAL and, when present, an INTEGER - which is
        // also what nothing else at this position is, so peeking at the
        // tag is how a v1 CRL is told from a v2 one.
        let version = if body.peek_tag() == Some(Tag::universal(asn1::tag::INTEGER)) {
            let value = body.read_u32()?;
            if value != 1 {
                return Err(format!(
                    "A CRL version field must be v2 (encoded as 1) if present; \
                     found {}.", value));
            }
            2
        } else {
            1
        };

        let signature_algorithm = crate::x509::read_algorithm(&mut body)?;
        // The two algorithm identifiers must agree, for the same reason
        // they must on a certificate: otherwise an attacker puts a weak
        // one where the verifier looks and a strong one where an
        // inspector looks.
        if signature_algorithm != outer_algorithm {
            return Err(format!(
                "The CRL names {} inside the signed body and {} outside it.",
                signature_algorithm.describe(), outer_algorithm.describe()));
        }

        let issuer = Name::parse(&mut body)?;
        let this_update = body.read_time()?;

        // `nextUpdate` is OPTIONAL and a Time, `revokedCertificates` is
        // a SEQUENCE, and `crlExtensions` is `[0]`. All three are
        // optional, so each is decided by its tag.
        let next_update = match body.peek_tag() {
            Some(tag) if tag == Tag::universal(asn1::tag::UTC_TIME)
                      || tag == Tag::universal(asn1::tag::GENERALIZED_TIME) =>
                Some(body.read_time()?),
            _ => None,
        };

        let mut revoked = Vec::new();
        if body.peek_tag() == Some(Tag::sequence()) {
            let mut entries = body.read_sequence()?;
            // The running attribution for an indirect CRL. RFC 5280
            // 5.3.3: absent on an entry means "the same as the previous
            // entry", and absent on the first means the CRL's issuer.
            let mut current_issuer: Option<&'a [u8]> = None;
            while !entries.is_empty() {
                let mut entry = entries.read_sequence()?;
                let serial = entry.read_integer_bytes()?;
                let revoked_at = entry.read_time()?;
                let mut reason = None;
                if !entry.is_empty() {
                    let (found_reason, found_issuer) =
                        parse_entry_extensions(&mut entry)?;
                    reason = found_reason;
                    if let Some(issuer) = found_issuer {
                        current_issuer = Some(issuer);
                    }
                }
                entry.finish()?;
                revoked.push(RevokedCertificate {
                    serial, revoked_at, reason,
                    certificate_issuer: current_issuer,
                });
            }
        }

        let mut crl = CertificateList {
            raw: der, tbs, version, signature_algorithm, outer_algorithm,
            issuer, this_update, next_update, revoked, signature,
            crl_number: None, delta_from: None,
            issuing_distribution_point: None, authority_key_id: None,
            unrecognised_critical: Vec::new(),
        };

        if body.peek_tag() == Some(Tag::context(0, true)) {
            let mut wrapper = body.read_constructed(Tag::context(0, true))?;
            parse_crl_extensions(&mut crl, &mut wrapper)?;
            wrapper.finish()?;
        }
        body.finish()?;

        if crl.version == 1 && (crl.crl_number.is_some()
                                || crl.issuing_distribution_point.is_some()
                                || crl.delta_from.is_some()) {
            return Err("A v1 CRL carries extensions, which only v2 may have."
                       .to_string());
        }
        Ok(crl)
    }

    /// Whether this is a delta CRL, which is not a complete list.
    pub fn is_delta(&self) -> bool {
        self.delta_from.is_some()
    }
}

/// `reasonCode` and `certificateIssuer` from one entry's extensions.
fn parse_entry_extensions<'a>(entry: &mut Reader<'a>)
                              -> Result<(Option<Reason>, Option<&'a [u8]>), String> {
    let mut list = entry.read_sequence()?;
    let mut reason = None;
    let mut certificate_issuer = None;
    let mut seen: Vec<&[u8]> = Vec::new();
    while !list.is_empty() {
        let mut extension = list.read_sequence()?;
        let oid = extension.read_oid()?;
        if seen.contains(&oid.as_bytes()) {
            return Err(format!("Duplicate CRL entry extension {}.", oid));
        }
        seen.push(oid.as_bytes());
        let critical = match extension.peek_tag() {
            Some(tag) if tag == Tag::universal(asn1::tag::BOOLEAN) =>
                extension.read_bool()?,
            _ => false,
        };
        let value = extension.read_octet_string()?;
        extension.finish()?;

        if oid.as_bytes() == oids::CRL_REASON_CODE {
            let mut reader = Reader::new(value);
            // An ENUMERATED, not an INTEGER. Same encoding, different
            // tag, and a reader that took either would accept a CRL
            // nobody else does.
            let bytes = reader.read_tagged(Tag::universal(asn1::tag::ENUMERATED))?;
            reader.finish()?;
            let mut number = 0u32;
            for byte in bytes {
                number = number.checked_mul(256)
                    .and_then(|n| n.checked_add(u32::from(*byte)))
                    .ok_or_else(|| "CRL reason code is absurdly large.".to_string())?;
            }
            reason = Some(Reason::from_value(number));
        } else if oid.as_bytes() == oids::CERTIFICATE_ISSUER {
            let mut reader = Reader::new(value);
            let mut names = reader.read_sequence()?;
            reader.finish()?;
            // GeneralNames, of which the directoryName is the one that
            // identifies an issuer. RFC 5280 5.3.3: "Conforming CRL
            // issuers MUST include in this extension the distinguished
            // name (DN) from the issuer field of the certificate".
            while !names.is_empty() {
                if let GeneralName::DirectoryName(raw) =
                        read_general_name(&mut names, &ADDRESS_ONLY)? {
                    certificate_issuer = Some(raw);
                    break;
                }
            }
            if certificate_issuer.is_none() {
                return Err("A certificateIssuer entry extension holds no \
                            directoryName, so the entry cannot be attributed \
                            to any certificate issuer.".to_string());
            }
        } else if critical {
            // A critical entry extension we cannot read means we cannot
            // say what the entry is about. Refusing the whole CRL is
            // the closed answer.
            return Err(format!(
                "A CRL entry carries a critical extension this does not \
                 recognise ({}), so what the entry means cannot be \
                 established.", oid));
        }
    }
    Ok((reason, certificate_issuer))
}

fn parse_crl_extensions<'a>(crl: &mut CertificateList<'a>,
                            wrapper: &mut Reader<'a>) -> Result<(), String> {
    let mut list = wrapper.read_sequence()?;
    let mut seen: Vec<&[u8]> = Vec::new();
    while !list.is_empty() {
        let mut extension = list.read_sequence()?;
        let oid = extension.read_oid()?;
        if seen.contains(&oid.as_bytes()) {
            return Err(format!("Duplicate CRL extension {}.", oid));
        }
        seen.push(oid.as_bytes());
        let critical = match extension.peek_tag() {
            Some(tag) if tag == Tag::universal(asn1::tag::BOOLEAN) =>
                extension.read_bool()?,
            _ => false,
        };
        let value = extension.read_octet_string()?;
        extension.finish()?;

        let bytes = oid.as_bytes();
        if bytes == oids::CRL_NUMBER {
            let mut reader = Reader::new(value);
            crl.crl_number = Some(reader.read_integer()?);
            reader.finish()?;
        } else if bytes == oids::DELTA_CRL_INDICATOR {
            let mut reader = Reader::new(value);
            crl.delta_from = Some(reader.read_integer()?);
            reader.finish()?;
        } else if bytes == oids::ISSUING_DISTRIBUTION_POINT {
            crl.issuing_distribution_point =
                Some(parse_issuing_distribution_point(value)?);
        } else if bytes == oids::AUTHORITY_KEY_ID {
            crl.authority_key_id = crate::x509::parse_authority_key_id(value)?;
        } else if critical {
            crl.unrecognised_critical.push(oid);
        }
    }
    Ok(())
}

fn parse_issuing_distribution_point(value: &[u8])
                                    -> Result<IssuingDistributionPoint<'_>, String> {
    let mut outer = Reader::new(value);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;

    let mut point = IssuingDistributionPoint::default();
    // Every field is optional and each has its own context tag, so the
    // loop is driven by the tags rather than by position. The booleans
    // are IMPLICIT BOOLEAN with DEFAULT FALSE, so a present one is
    // meaningful and an absent one is false.
    while !sequence.is_empty() {
        let (tag, content) = sequence.read_any()?;
        if tag.class != asn1::CLASS_CONTEXT {
            return Err("An issuingDistributionPoint field must use a context \
                        tag.".to_string());
        }
        let boolean = |content: &[u8]| -> Result<bool, String> {
            match content {
                [0x00] => Ok(false),
                [0xFF] => Ok(true),
                _ => Err("A BOOLEAN in an issuingDistributionPoint is not \
                          0x00 or 0xFF.".to_string()),
            }
        };
        match tag.number {
            0 => point.distribution_point = Some(content),
            1 => point.only_user_certs = boolean(content)?,
            2 => point.only_ca_certs = boolean(content)?,
            3 => {
                // A BIT STRING, implicitly tagged: the first content
                // octet is the number of unused bits.
                let (unused, bits) = content.split_first().ok_or_else(
                    || "onlySomeReasons is an empty BIT STRING.".to_string())?;
                if *unused > 7 {
                    return Err("onlySomeReasons claims more than seven unused \
                                bits.".to_string());
                }
                let mut flags = 0u16;
                for (index, byte) in bits.iter().take(2).enumerate() {
                    flags |= u16::from(*byte) << (8 - index * 8);
                }
                point.only_some_reasons = Some(flags);
            }
            4 => point.indirect = boolean(content)?,
            5 => point.only_attribute_certs = boolean(content)?,
            other => return Err(format!(
                "Unknown issuingDistributionPoint field [{}].", other)),
        }
    }
    Ok(point)
}

// ------------------------------------------------------------- checking ---

/// Is this CRL evidence about certificates issued by `issuer`?
///
/// Three questions, and all three have to be yes: the same issuer, the
/// right to sign a CRL, and a signature that verifies. Any one of them
/// missing makes the list somebody's opinion rather than the CA's.
fn is_trustworthy(crl: &CertificateList<'_>, issuer: &Certificate<'_>,
                  policy: &Policy) -> Result<(), String> {
    if !crl.unrecognised_critical.is_empty() {
        return Err(format!(
            "The CRL carries a critical extension this does not recognise \
             ({}), so its scope cannot be established - and a list whose \
             scope is unknown cannot show that anything is absent from it.",
            crl.unrecognised_critical[0]));
    }
    if !crl.issuer.matches(&issuer.subject) {
        return Err(format!(
            "The CRL was issued by {} and the certificate by {}. A CRL from \
             another issuer says nothing about this certificate, and this \
             does not build a second certification path for a separate CRL \
             signer (RFC 5280 5.1.1.3 makes that a SHOULD, not a MUST).",
            crl.issuer, issuer.subject));
    }
    // RFC 5280 4.2.1.3: the cRLSign bit is what says this key may sign a
    // CRL. A CA key without it is not a CRL signer, however convenient.
    if let Some(usage) = issuer.extensions.key_usage {
        if !usage.crl_sign {
            return Err(format!(
                "{} does not have the cRLSign key usage, so it may not sign \
                 a CRL.", issuer.subject));
        }
    }
    verify_signed(crl.tbs, crl.signature_algorithm, crl.signature,
                  &issuer.public_key, policy)
        .map_err(|e| format!("The CRL's signature does not check out: {}", e))
}

/// Does this CRL's declared scope include `certificate`?
///
/// Returns the reason it does not, which becomes part of an `Unknown` -
/// "this list is not about certificates like yours" and "this list does
/// not mention you" are different answers and only one of them is good
/// news.
fn scope_excludes(crl: &CertificateList<'_>, certificate: &Certificate<'_>)
                  -> Option<String> {
    let point = crl.issuing_distribution_point.as_ref()?;
    if point.only_attribute_certs {
        return Some("the CRL covers attribute certificates only".to_string());
    }
    let is_ca = certificate.extensions.is_ca();
    if point.only_user_certs && is_ca {
        return Some("the CRL covers end-entity certificates only, and this \
                     is a CA certificate".to_string());
    }
    if point.only_ca_certs && !is_ca {
        return Some("the CRL covers CA certificates only, and this is an \
                     end-entity certificate".to_string());
    }
    None
}

/// Check one certificate against the CRLs supplied for it.
///
/// `issuer` is the certificate that issued `certificate`, and is what
/// every CRL is checked against. `crls` may hold complete lists, delta
/// lists, and lists that turn out to be about something else entirely;
/// this sorts them out and says what can be concluded.
///
/// `now` is passed in rather than read from a clock, so a check is
/// reproducible and a test can sit at any moment.
pub fn check(certificate: &Certificate<'_>, issuer: &Certificate<'_>,
             crls: &[CertificateList<'_>], policy: &Policy, now: i64)
             -> Status {
    if crls.is_empty() {
        return Status::Unknown("no CRL was supplied".to_string());
    }

    // Sort into usable complete lists and usable deltas, keeping why
    // each rejected one was rejected - a count of unusable CRLs cannot
    // distinguish "the wrong file" from "we are too strict", which have
    // opposite remedies.
    let mut complete: Vec<&CertificateList<'_>> = Vec::new();
    let mut deltas: Vec<&CertificateList<'_>> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    // Stale lists, kept separately. **A stale CRL can still revoke; it
    // just cannot clear.** A revocation does not become untrue because
    // the list it is on is old, while an absence from an old list says
    // only that the certificate was fine then. Treating staleness as
    // total disqualification throws away real evidence of revocation,
    // and `openssl verify` reports exactly this pair - "CRL has
    // expired" *and* "certificate revoked" - on the same input.
    let mut stale: Vec<&CertificateList<'_>> = Vec::new();

    for crl in crls {
        if let Err(reason) = is_trustworthy(crl, issuer, policy) {
            rejected.push(reason);
            continue;
        }
        if let Some(reason) = scope_excludes(crl, certificate) {
            rejected.push(format!("a CRL was set aside because {}", reason));
            continue;
        }
        if let Some(reason) = freshness(crl, now) {
            rejected.push(reason);
            stale.push(crl);
            continue;
        }
        if crl.is_delta() { deltas.push(crl); } else { complete.push(crl); }
    }

    // The revocation pass, over everything that could be trusted at all
    // - fresh or not, complete or delta. A delta is a perfectly good
    // witness to the revocations it *does* list; what it cannot do is
    // show that anything is absent.
    //
    // Deliberately before the "can anything clear this" logic below, so
    // that no arrangement of stale or partial lists can turn a
    // revocation into silence.
    for crl in complete.iter().chain(&deltas).chain(&stale) {
        let entry = match entry_for(crl, certificate) {
            Some(entry) => entry,
            None => continue,
        };
        // `removeFromCRL` is a withdrawal rather than a revocation:
        // the entry is being taken off, because the certificate expired
        // or came off hold.
        //
        // RFC 5280 5.3.1 scopes it - "The removeFromCRL (8) reasonCode
        // value may only appear in delta CRLs" - so a complete CRL
        // carrying it is non-conforming, and there are two readings of
        // a non-conforming entry. The strict one is that an entry on a
        // revocation list revokes whatever odd reason it carries, which
        // is the safer direction and is what this did first. The other
        // is that the code means what it says wherever it appears,
        // which is what OpenSSL does, and `tools/src/bin/diff_crl.rs`
        // disagreed on exactly this row.
        //
        // OpenSSL's reading wins here, and the reason is what this
        // library is for. Our reading refuses a certificate that
        // everything else accepts, over a mistake in a CA's own signed
        // list that the user of this library cannot fix - and "the
        // server is not ours to upgrade" is the case this whole project
        // exists to handle. The other reading can only be reached by a
        // CA signing nonsense about its own certificate, which buys an
        // attacker nothing they could not get by simply not revoking
        // it.
        if entry.reason == Some(Reason::RemoveFromCrl) {
            continue;
        }
        // A base that revokes and a delta that withdraws: the delta
        // wins, and only over a base it is really an update to.
        if withdrawn(certificate, &deltas, crl) {
            continue;
        }
        return Status::Revoked { at: entry.revoked_at, reason: entry.reason };
    }

    if complete.is_empty() {
        let mut why = if deltas.is_empty() {
            "no supplied CRL could be used".to_string()
        } else {
            // The dangerous case, named explicitly. A delta lists only
            // what changed; read as a complete list it would report
            // every older revocation as clean.
            format!("{} delta CRL(s) were supplied and no complete CRL to \
                     apply them to. A delta lists only what changed since \
                     its base, so on its own it cannot show that anything \
                     is unrevoked", deltas.len())
        };
        if !rejected.is_empty() {
            why.push_str(&format!(" ({})", rejected.join("; ")));
        }
        return Status::Unknown(why);
    }

    // Walk every usable complete list, applying any delta that belongs
    // to it. An entry found anywhere is an answer; being absent from one
    // only rules out the reasons *that* list covers, so the covered
    // reasons are accumulated across every list that stayed silent.
    let mut covered: u16 = 0;

    // Nothing revoked it. Now: can anything here say so?
    for base in &complete {
        // Absent from this list. That rules out the reasons this list
        // covers and no others: a CRL partitioned by reason is
        // complete, valid, correctly signed and silent about the rest.
        //
        // Accumulated rather than decided here, because a CA may
        // partition its revocations across several CRLs - RFC 5280
        // 5.2.5 describes exactly that, keyCompromise in one
        // distribution point and the rest in another - and two
        // partitions that together cover everything *are* a complete
        // answer.
        covered |= match base.issuing_distribution_point.as_ref()
                             .and_then(|point| point.only_some_reasons) {
            None => ALL_REASONS,
            Some(flags) => flags & ALL_REASONS,
        };
    }

    if covered & ALL_REASONS == ALL_REASONS {
        return Status::NotRevoked;
    }
    Status::Unknown(format!(
        "the usable CRLs are partitioned by revocation reason and between \
         them cover only {}, so this certificate's absence from them says \
         nothing about {}",
        describe_reasons(covered), describe_reasons(!covered & ALL_REASONS)))
}

/// Every reason a distribution point can be scoped to, as `ReasonFlags`
/// bits: `unspecified(0)` through `aACompromise(8)`.
///
/// A CRL with no `onlySomeReasons` covers all of them, and a set of
/// partitioned CRLs covers their union.
const ALL_REASONS: u16 = 0xFF80;

/// The entry on `crl` about `certificate`, if there is one.
///
/// Two things have to match, not one. The serial is obvious; the
/// **issuer** is the part that is easy to leave out, because a serial
/// number is only unique per issuer. On an indirect CRL an entry names
/// whose certificate it is about, and an entry about somebody else's
/// certificate that happens to share a serial is not about this one -
/// which is an ordinary collision rather than an exotic one.
fn entry_for<'a>(crl: &'a CertificateList<'a>, certificate: &Certificate<'_>)
                 -> Option<&'a RevokedCertificate<'a>> {
    // The last match wins, so a CRL that lists a serial twice is read
    // the way a merge would read it.
    crl.revoked.iter().rev().find(|entry| {
        entry.serial == certificate.serial
            && match entry.certificate_issuer {
                Some(named) => named == certificate.issuer.raw,
                None => true,
            }
    })
}

/// Whether some delta withdraws the entry `source` carries.
///
/// `removeFromCRL` in a delta takes an entry off the list its base
/// holds - the certificate expired, or came off hold. A merge that read
/// reason 8 as a revocation reason like any other would revoke exactly
/// the certificates the delta was issued to release.
///
/// The delta only speaks for lists it is an update to, which is what
/// `combine` decides - so a delta from some other CRL number cannot
/// release anything here.
fn withdrawn(certificate: &Certificate<'_>, deltas: &[&CertificateList<'_>],
             source: &CertificateList<'_>) -> bool {
    if source.is_delta() {
        return false;
    }
    deltas.iter().any(|delta| {
        combine(source, delta).is_ok()
            && entry_for(delta, certificate)
                   .and_then(|entry| entry.reason)
               == Some(Reason::RemoveFromCrl)
    })
}

/// Whether a set of `ReasonFlags` bits includes this reason.
///
/// One place knows the bit order, because there are two numberings of a
/// revocation reason here - the ENUMERATED value and this bit position -
/// and they agree over most of their range.
fn flags_cover(flags: u16, reason: Reason) -> bool {
    match reason.flag_bit() {
        Some(bit) => flags & (1 << (15 - bit)) != 0,
        None => false,
    }
}

/// Why a CRL cannot be used at `now`, if it cannot.
fn freshness(crl: &CertificateList<'_>, now: i64) -> Option<String> {
    if now < crl.this_update {
        return Some(format!(
            "a CRL is not valid until {} and it is {}", crl.this_update, now));
    }
    match crl.next_update {
        Some(next) if now > next => Some(format!(
            "a CRL expired at {} and it is {}; what it said was true then, \
             and a revocation published since would not be on it",
            next, now)),
        // RFC 5280 5.1.2 requires conforming issuers to include
        // nextUpdate. One without it never expires, which is the issuer's
        // choice to have made and not ours to override.
        _ => None,
    }
}

/// RFC 5280 5.2.4's four conditions for combining a delta with a base.
fn combine(base: &CertificateList<'_>, delta: &CertificateList<'_>)
           -> Result<(), String> {
    // (a) the same issuer.
    if !base.issuer.matches(&delta.issuer) {
        return Err("a delta CRL and the complete CRL have different issuers"
                   .to_string());
    }
    // (b) the same scope, which means both omit the
    // issuingDistributionPoint or both carry identical ones.
    let scopes_agree = match (&base.issuing_distribution_point,
                              &delta.issuing_distribution_point) {
        (None, None) => true,
        (Some(a), Some(b)) =>
            a.distribution_point == b.distribution_point
            && a.only_user_certs == b.only_user_certs
            && a.only_ca_certs == b.only_ca_certs
            && a.only_attribute_certs == b.only_attribute_certs
            && a.only_some_reasons == b.only_some_reasons
            && a.indirect == b.indirect,
        _ => false,
    };
    if !scopes_agree {
        return Err("a delta CRL and the complete CRL have different scopes"
                   .to_string());
    }
    let (base_number, delta_number, base_of_delta) =
        match (&base.crl_number, &delta.crl_number, &delta.delta_from) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return Err("a delta CRL or its base is missing a CRL number, \
                             so they cannot be ordered".to_string()),
        };
    // (c) the complete CRL holds at least everything the delta's base
    // did, and (d) the delta comes after it.
    if base_number.cmp(base_of_delta) == core::cmp::Ordering::Less {
        return Err("a delta CRL is based on a newer CRL than the complete one \
                    supplied, so applying it would leave a gap".to_string());
    }
    if base_number.cmp(delta_number) != core::cmp::Ordering::Less {
        return Err("a delta CRL is not newer than the complete CRL".to_string());
    }
    Ok(())
}

fn describe_reasons(flags: u16) -> String {
    let names = [
        (Reason::Unspecified, "unspecified"),
        (Reason::KeyCompromise, "keyCompromise"),
        (Reason::CaCompromise, "cACompromise"),
        (Reason::AffiliationChanged, "affiliationChanged"),
        (Reason::Superseded, "superseded"),
        (Reason::CessationOfOperation, "cessationOfOperation"),
        (Reason::CertificateHold, "certificateHold"),
        (Reason::PrivilegeWithdrawn, "privilegeWithdrawn"),
        (Reason::AaCompromise, "aACompromise"),
    ];
    let listed: Vec<&str> = names.iter()
        .filter(|(reason, _)| flags_cover(flags, *reason))
        .map(|(_, name)| *name)
        .collect();
    if listed.is_empty() {
        "no reason at all".to_string()
    } else {
        listed.join(", ")
    }
}

// ---------------------------------------------------- distribution points ---

/// Where a certificate says its CRL can be found (RFC 5280 4.2.1.13).
///
/// Reported, not fetched: nothing in this library opens a socket. The
/// URIs are for a caller who has one.
pub fn distribution_points(certificate: &Certificate<'_>) -> Vec<String> {
    certificate.extensions.crl_distribution_points.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::builder::{key_usage, CrlBuilder, IssuingDistributionPointFields,
                               RevocationEntry};
    use crate::x509::tests_support::{self, TestKey};
    use crate::asn1::Writer;

    const NOW: i64 = 1_700_000_000;      // 2023-11-14

    fn policy() -> Policy {
        Policy::at(NOW)
    }

    /// The two numberings of a revocation reason. The enumerated value
    /// and the bit position in `ReasonFlags` agree from 1 to 6 and then
    /// diverge, which is exactly the shape that gets copied across.
    #[test]
    fn test_the_reason_enumeration_and_the_flag_bits_are_not_the_same() {
        for value in 1..=6u32 {
            assert_eq!(Reason::from_value(value).flag_bit(), Some(value as u8));
        }
        // 7 is unused in the enumeration and is privilegeWithdrawn in
        // the flags; 8 is removeFromCRL in the enumeration and
        // aACompromise in the flags.
        assert_eq!(Reason::PrivilegeWithdrawn.flag_bit(), Some(7));
        assert_eq!(Reason::from_value(9), Reason::PrivilegeWithdrawn);
        assert_eq!(Reason::AaCompromise.flag_bit(), Some(8));
        assert_eq!(Reason::from_value(10), Reason::AaCompromise);

        // removeFromCRL is not a scope a distribution point can have.
        assert_eq!(Reason::RemoveFromCrl.flag_bit(), None);
        assert_eq!(Reason::from_value(8), Reason::RemoveFromCrl);
    }

    /// `ReasonFlags` is a BIT STRING, so bit 1 is the *second most
    /// significant* bit of the first octet. Reading it as a little
    /// endian integer puts keyCompromise where aACompromise should be.
    #[test]
    fn test_reason_flags_are_read_as_a_bit_string() {
        // 0x40 is bit 1: keyCompromise.
        let point = IssuingDistributionPoint {
            only_some_reasons: Some(0x4000), ..Default::default()
        };
        assert!(point.covers_reason(Reason::KeyCompromise));
        assert!(!point.covers_reason(Reason::CaCompromise));
        assert!(!point.covers_reason(Reason::Superseded));

        // 0x80 is bit 0: unspecified.
        let point = IssuingDistributionPoint {
            only_some_reasons: Some(0x8000), ..Default::default()
        };
        assert!(point.covers_reason(Reason::Unspecified));
        assert!(!point.covers_reason(Reason::KeyCompromise));

        // Absent means every reason, which is the only case under which
        // absence from the list means anything.
        let point = IssuingDistributionPoint::default();
        for reason in [Reason::Unspecified, Reason::KeyCompromise,
                       Reason::AaCompromise] {
            assert!(point.covers_reason(reason));
        }
    }

    #[test]
    fn test_describe_reasons_names_the_bits_it_was_given() {
        assert_eq!(describe_reasons(0x4000), "keyCompromise");
        assert_eq!(describe_reasons(0x6000), "keyCompromise, cACompromise");
        assert_eq!(describe_reasons(0x0000), "no reason at all");
    }

    /// `Unknown` must never read as good news, and `describe` is where
    /// that could slip: returning `None` means "nothing to report".
    #[test]
    fn test_only_not_revoked_reports_nothing() {
        assert!(Status::NotRevoked.describe().is_none());
        assert!(Status::Unknown("whatever".to_string()).describe().is_some());
        assert!(Status::Revoked { at: 0, reason: None }.describe().is_some());
        assert!(!Status::Unknown("whatever".to_string()).is_revoked());
    }

    // ------------------------------------------------- end to end checks ---

    /// A CA, a leaf it issued, and a CRL it signed. Everything below
    /// varies one thing about this.
    struct Fixture {
        issuer_der: Vec<u8>,
        leaf_der: Vec<u8>,
        issuer_key: TestKey,
        other_key: TestKey,
    }

    impl Fixture {
        fn new() -> Fixture {
            Fixture::with(|_| {})
        }

        fn with(configure_leaf: impl FnOnce(&mut tests_support::Builder)) -> Fixture {
            let issuer_key = TestKey::new();
            let leaf_key = TestKey::new();
            let other_key = TestKey::new();

            let issuer_der = tests_support::Builder {
                common_name: "Test CA".to_string(),
                dns_names: vec![],
                is_ca: Some((true, None)),
                key_usage: Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN),
                ..Default::default()
            }.issue(&issuer_key, &issuer_key, "Test CA", 1);

            let mut leaf = tests_support::Builder::default();
            configure_leaf(&mut leaf);
            let leaf_der = leaf.issue(&leaf_key, &issuer_key, "Test CA", 0x2a);

            Fixture { issuer_der, leaf_der, issuer_key, other_key }
        }

        fn issuer(&self) -> Certificate<'_> {
            Certificate::parse(&self.issuer_der).unwrap()
        }

        fn leaf(&self) -> Certificate<'_> {
            Certificate::parse(&self.leaf_der).unwrap()
        }

        /// A CRL signed by the CA, with whatever the closure sets.
        fn crl(&self, configure: impl FnOnce(&mut CrlBuilder<'_>)) -> Vec<u8> {
            let mut builder = CrlBuilder::new("Test CA");
            configure(&mut builder);
            builder.sign(&self.issuer_key.signing()).unwrap()
        }

        fn check(&self, crl_ders: &[Vec<u8>]) -> Status {
            let parsed: Vec<CertificateList<'_>> = crl_ders.iter()
                .map(|der| CertificateList::parse(der).unwrap())
                .collect();
            check(&self.leaf(), &self.issuer(), &parsed, &policy(), NOW)
        }
    }

    /// The whole point, in one test: a serial on the list is revoked and
    /// one that is not is not.
    #[test]
    fn test_a_listed_serial_is_revoked_and_an_unlisted_one_is_not() {
        let fixture = Fixture::new();

        let empty = fixture.crl(|_| {});
        assert_eq!(fixture.check(&[empty]), Status::NotRevoked);

        let listed = fixture.crl(|b| {
            b.revoked = vec![RevocationEntry::new(&[0x2a])];
        });
        match fixture.check(&[listed]) {
            Status::Revoked { .. } => {}
            other => panic!("expected revoked, got {:?}", other),
        }

        // A different serial on the list leaves this one alone, so the
        // match is on the serial rather than on the list being non-empty.
        let elsewhere = fixture.crl(|b| {
            b.revoked = vec![RevocationEntry::new(&[0x2b]),
                             RevocationEntry::new(&[0x01])];
        });
        assert_eq!(fixture.check(&[elsewhere]), Status::NotRevoked);
    }

    #[test]
    fn test_the_reason_comes_back() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.reason = Some(1);              // keyCompromise
            b.revoked = vec![entry];
        });
        match fixture.check(&[der]) {
            Status::Revoked { reason, .. } =>
                assert_eq!(reason, Some(Reason::KeyCompromise)),
            other => panic!("{:?}", other),
        }
    }

    /// **No CRL is not a clean CRL.** The single most important
    /// distinction in this module.
    #[test]
    fn test_no_crl_is_unknown_and_not_clean() {
        let fixture = Fixture::new();
        match fixture.check(&[]) {
            Status::Unknown(why) => assert!(why.contains("no CRL"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// A CRL somebody else signed is a list somebody else wrote. It must
    /// not make a certificate look clean, and it must not make one look
    /// revoked either.
    #[test]
    fn test_a_crl_signed_by_the_wrong_key_concludes_nothing() {
        let fixture = Fixture::new();
        let mut builder = CrlBuilder::new("Test CA");
        builder.revoked = vec![RevocationEntry::new(&[0x2a])];
        // The right issuer name, the wrong key - which is what an
        // attacker has.
        let der = builder.sign(&fixture.other_key.signing()).unwrap();

        match fixture.check(&[der]) {
            Status::Unknown(why) =>
                assert!(why.contains("signature"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }

        // And the empty version does not make it clean either.
        let mut builder = CrlBuilder::new("Test CA");
        builder.revoked = vec![];
        let der = builder.sign(&fixture.other_key.signing()).unwrap();
        assert!(matches!(fixture.check(&[der]), Status::Unknown(_)));
    }

    #[test]
    fn test_a_crl_from_another_issuer_concludes_nothing() {
        let fixture = Fixture::new();
        let mut builder = CrlBuilder::new("Some Other CA");
        builder.revoked = vec![RevocationEntry::new(&[0x2a])];
        let der = builder.sign(&fixture.issuer_key.signing()).unwrap();
        match fixture.check(&[der]) {
            Status::Unknown(why) =>
                assert!(why.contains("another issuer"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// RFC 5280 4.2.1.3: the cRLSign bit is what permits signing a CRL.
    #[test]
    fn test_an_issuer_without_crl_sign_may_not_sign_one() {
        let issuer_key = TestKey::new();
        let leaf_key = TestKey::new();
        // keyCertSign but not cRLSign.
        let issuer_der = tests_support::Builder {
            common_name: "Test CA".to_string(),
            dns_names: vec![],
            is_ca: Some((true, None)),
            key_usage: Some(key_usage::KEY_CERT_SIGN),
            ..Default::default()
        }.issue(&issuer_key, &issuer_key, "Test CA", 1);
        let leaf_der = tests_support::Builder::default()
            .issue(&leaf_key, &issuer_key, "Test CA", 0x2a);

        let mut builder = CrlBuilder::new("Test CA");
        builder.revoked = vec![RevocationEntry::new(&[0x2a])];
        let crl_der = builder.sign(&issuer_key.signing()).unwrap();

        let issuer = Certificate::parse(&issuer_der).unwrap();
        let leaf = Certificate::parse(&leaf_der).unwrap();
        let crl = CertificateList::parse(&crl_der).unwrap();
        match check(&leaf, &issuer, &[crl], &policy(), NOW) {
            Status::Unknown(why) => assert!(why.contains("cRLSign"), "{}", why),
            other => panic!("{:?}", other),
        }
    }

    /// A CRL past its nextUpdate says what was true then. The revocation
    /// published since would not be on it, so absence proves nothing.
    #[test]
    fn test_a_stale_crl_concludes_nothing() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.this_update = "20200101000000Z";
            b.next_update = Some("20210101000000Z");
        });
        match fixture.check(&[der]) {
            Status::Unknown(why) => assert!(why.contains("expired"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }

        // A CRL that has not started yet is equally useless, and for the
        // opposite reason - so the comparison is not accidentally
        // one-sided.
        let der = fixture.crl(|b| {
            b.this_update = "20400101000000Z";
            b.next_update = Some("20410101000000Z");
        });
        assert!(matches!(fixture.check(&[der]), Status::Unknown(_)));
    }

    /// A CRL with no nextUpdate never expires. RFC 5280 tells conforming
    /// issuers to set one; a CRL without it is still usable, and that is
    /// the issuer's choice rather than ours to override.
    #[test]
    fn test_a_crl_with_no_next_update_does_not_expire() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.this_update = "20200101000000Z";
            b.next_update = None;
        });
        assert_eq!(fixture.check(&[der]), Status::NotRevoked);
    }

    // ------------------------------------------------------- delta CRLs ---

    /// **A delta CRL alone proves nothing.** It lists only what changed
    /// since its base, so every older revocation is absent from it - and
    /// reading it as a complete list reports all of those as clean.
    #[test]
    fn test_a_delta_crl_on_its_own_is_not_a_crl() {
        let fixture = Fixture::new();
        // Somebody else's serial, so the question is purely whether
        // *absence* from a delta means anything. It does not.
        let delta = fixture.crl(|b| {
            b.crl_number = Some(vec![5]);
            b.delta_from = Some(vec![3]);
            b.revoked = vec![RevocationEntry::new(&[0x99])];
        });
        match fixture.check(&[delta]) {
            Status::Unknown(why) => assert!(why.contains("delta"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// A delta applied to its base revokes what the delta adds.
    #[test]
    fn test_a_delta_adds_to_its_base() {
        let fixture = Fixture::new();
        let base = fixture.crl(|b| {
            b.crl_number = Some(vec![3]);
            b.revoked = vec![RevocationEntry::new(&[0x99])];
        });
        let delta = fixture.crl(|b| {
            b.crl_number = Some(vec![5]);
            b.delta_from = Some(vec![3]);
            b.revoked = vec![RevocationEntry::new(&[0x2a])];
        });

        // The base alone says nothing about us.
        assert_eq!(fixture.check(std::slice::from_ref(&base)), Status::NotRevoked);
        // With the delta, we are revoked.
        assert!(fixture.check(&[base, delta]).is_revoked());
    }

    /// **removeFromCRL un-revokes.** A delta carrying reason 8 withdraws
    /// the base's entry; treating it as a revocation reason like any
    /// other would revoke exactly the certificates the delta released.
    #[test]
    fn test_remove_from_crl_takes_an_entry_off() {
        let fixture = Fixture::new();
        let base = fixture.crl(|b| {
            b.crl_number = Some(vec![3]);
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.reason = Some(6);              // certificateHold
            b.revoked = vec![entry];
        });
        assert!(fixture.check(std::slice::from_ref(&base)).is_revoked());

        let delta = fixture.crl(|b| {
            b.crl_number = Some(vec![5]);
            b.delta_from = Some(vec![3]);
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.reason = Some(8);              // removeFromCRL
            b.revoked = vec![entry];
        });
        assert_eq!(fixture.check(&[base, delta]), Status::NotRevoked);
    }

    /// RFC 5280 5.2.4's conditions (c) and (d) govern whether a delta
    /// may be **merged** with a base - that is, whether the pair is a
    /// complete picture. They do not govern whether the delta's own
    /// entries are true.
    ///
    /// So a delta that does not fit still revokes what it lists (it is
    /// signed by the CA and says so), and still cannot *release*
    /// anything: a `removeFromCRL` in a delta from the wrong base must
    /// not take an entry off the base we actually have, because it is
    /// talking about a different list.
    ///
    /// The asymmetry is the point, and it is the safe direction of each
    /// question taken separately rather than one rule applied to both.
    #[test]
    fn test_a_mismatched_delta_may_revoke_but_may_not_release() {
        let fixture = Fixture::new();
        let base = fixture.crl(|b| b.crl_number = Some(vec![3]));

        // Based on CRL 7, which is newer than the complete CRL we have,
        // so the pair leaves a gap and must not be merged - and the
        // revocation in it is still the CA saying this certificate is
        // revoked.
        let ahead = fixture.crl(|b| {
            b.crl_number = Some(vec![9]);
            b.delta_from = Some(vec![7]);
            b.revoked = vec![RevocationEntry::new(&[0x2a])];
        });
        assert!(fixture.check(&[base.clone(), ahead]).is_revoked());

        // Now the release direction. A base that revokes us, and a
        // delta that withdraws the entry but is based on the wrong CRL
        // number: the withdrawal must not apply.
        let revoking_base = fixture.crl(|b| {
            b.crl_number = Some(vec![3]);
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.reason = Some(6);
            b.revoked = vec![entry];
        });
        let wrong_delta = fixture.crl(|b| {
            b.crl_number = Some(vec![9]);
            b.delta_from = Some(vec![7]);
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.reason = Some(8);              // removeFromCRL
            b.revoked = vec![entry];
        });
        assert!(fixture.check(&[revoking_base.clone(), wrong_delta]).is_revoked(),
                "a delta from another base released an entry it was not \
                 talking about");

        // And the matching delta does release it, so the test above is
        // not passing because withdrawal never works.
        let right_delta = fixture.crl(|b| {
            b.crl_number = Some(vec![5]);
            b.delta_from = Some(vec![3]);
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.reason = Some(8);
            b.revoked = vec![entry];
        });
        assert_eq!(fixture.check(&[revoking_base, right_delta]),
                   Status::NotRevoked);
    }

    /// **A stale CRL can still revoke.** A revocation does not become
    /// untrue because the list carrying it is old; an *absence* from an
    /// old list is what proves nothing. Treating staleness as total
    /// disqualification throws away real evidence, in the one direction
    /// where throwing evidence away is dangerous.
    ///
    /// `openssl verify` reports both errors on this input - "CRL has
    /// expired" and "certificate revoked" - and that disagreement is
    /// how this was found: `tools/src/bin/diff_crl.rs` had the row and the
    /// first implementation answered "unknown".
    #[test]
    fn test_a_stale_crl_still_revokes_what_it_lists() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.this_update = "20190101000000Z";
            b.next_update = Some("20210101000000Z");
            b.revoked = vec![RevocationEntry::new(&[0x2a])];
        });
        assert!(fixture.check(&[der]).is_revoked());
    }

    /// A delta alone cannot clear anything, and still revokes what it
    /// lists - the same asymmetry, from the other side. A delta is a
    /// perfectly good witness to the revocations it carries; what it
    /// cannot do is show that anything is absent.
    #[test]
    fn test_a_delta_alone_revokes_what_it_lists() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.crl_number = Some(vec![5]);
            b.delta_from = Some(vec![3]);
            b.revoked = vec![RevocationEntry::new(&[0x2a])];
        });
        assert!(fixture.check(&[der]).is_revoked());
    }

    // ------------------------------------------------ partitioned scopes ---

    /// A CRL partitioned by reason is complete, valid, correctly signed
    /// and silent about the reasons it does not carry. Absence from it
    /// is not news.
    #[test]
    fn test_a_crl_that_covers_only_some_reasons_cannot_clear_anything() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                only_some_reasons: Some(0x4000),     // keyCompromise only
                ..Default::default()
            });
        });
        match fixture.check(&[der]) {
            Status::Unknown(why) =>
                assert!(why.contains("keyCompromise"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// But it can still revoke: being *on* a partial list is an answer
    /// even when being off it is not.
    #[test]
    fn test_a_partitioned_crl_can_still_revoke() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                only_some_reasons: Some(0x4000),
                ..Default::default()
            });
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.reason = Some(1);
            b.revoked = vec![entry];
        });
        assert!(fixture.check(&[der]).is_revoked());
    }

    /// A CRL scoped to CA certificates is not about an end-entity one,
    /// and the answer is "not applicable" rather than "clean".
    #[test]
    fn test_a_crl_for_ca_certificates_says_nothing_about_a_leaf() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                only_ca_certs: true,
                ..Default::default()
            });
        });
        match fixture.check(&[der]) {
            Status::Unknown(why) => assert!(why.contains("CA certificates only"),
                                            "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }

        // The other way round, the same CRL scoped to end-entity
        // certificates does cover this leaf.
        let der = fixture.crl(|b| {
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                only_user_certs: true,
                ..Default::default()
            });
        });
        assert_eq!(fixture.check(&[der]), Status::NotRevoked);
    }

    /// **Two partitions that together cover everything are a complete
    /// answer.** RFC 5280 5.2.5 describes exactly this arrangement -
    /// the compromise reasons in one distribution point and the rest in
    /// another - so treating each partial CRL as inconclusive on its own
    /// would make a correctly partitioned CA permanently unknown.
    #[test]
    fn test_partitions_that_together_cover_everything_do_answer() {
        let fixture = Fixture::new();
        // keyCompromise, cACompromise and aACompromise in one; the rest
        // in the other. Between them: every bit of ALL_REASONS.
        let compromise = 0x4000 | 0x2000 | 0x0080;
        let rest = ALL_REASONS & !compromise;

        let one = fixture.crl(|b| {
            b.crl_number = Some(vec![1]);
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                only_some_reasons: Some(compromise), ..Default::default()
            });
        });
        let two = fixture.crl(|b| {
            b.crl_number = Some(vec![2]);
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                only_some_reasons: Some(rest), ..Default::default()
            });
        });

        // Either alone settles nothing...
        assert!(matches!(fixture.check(std::slice::from_ref(&one)), Status::Unknown(_)));
        assert!(matches!(fixture.check(std::slice::from_ref(&two)), Status::Unknown(_)));
        // ...and together they do.
        assert_eq!(fixture.check(&[one.clone(), two.clone()]), Status::NotRevoked);

        // And a pair with a gap does not. Dropping certificateHold from
        // the second leaves exactly one reason uncovered, which is the
        // off-by-one a union written with the wrong mask would miss.
        let gapped = fixture.crl(|b| {
            b.crl_number = Some(vec![3]);
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                only_some_reasons: Some(rest & !0x0200), ..Default::default()
            });
        });
        match fixture.check(&[one, gapped]) {
            Status::Unknown(why) =>
                assert!(why.contains("certificateHold"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// One usable complete CRL is enough, even alongside partial ones -
    /// so a partitioned CRL in the pile does not spoil a complete
    /// answer.
    #[test]
    fn test_a_complete_crl_beside_a_partial_one_still_answers() {
        let fixture = Fixture::new();
        let partial = fixture.crl(|b| {
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                only_some_reasons: Some(0x4000),
                ..Default::default()
            });
        });
        let complete = fixture.crl(|b| b.crl_number = Some(vec![2]));
        assert_eq!(fixture.check(&[partial, complete]), Status::NotRevoked);
    }

    // ----------------------------------------------------- indirect CRLs ---

    /// **The certificateIssuer entry extension carries forward.** RFC
    /// 5280 5.3.3: absent on a later entry means the same issuer as the
    /// previous one. So an entry that names nobody, sitting after one
    /// that names somebody else, is about that somebody else - and a
    /// parser reading entries independently attributes it to the CRL
    /// issuer instead.
    ///
    /// Here entry two shares our serial and names nothing, and entry one
    /// attributes the run to a different CA. Our certificate must not be
    /// revoked by it.
    #[test]
    fn test_certificate_issuer_carries_forward_to_later_entries() {
        let fixture = Fixture::new();

        let mut other_name = Writer::new();
        other_name.write_sequence(|w| {
            w.write_set(|w| {
                w.write_sequence(|w| {
                    w.write_oid(oids::COMMON_NAME);
                    w.write_utf8_string("Some Other CA");
                });
            });
        });
        let other_name = other_name.finish();

        let der = fixture.crl(|b| {
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                indirect: true, ..Default::default()
            });
            let mut first = RevocationEntry::new(&[0x01]);
            first.certificate_issuer = Some(other_name.clone());
            // No certificateIssuer of its own: it inherits the one above.
            let second = RevocationEntry::new(&[0x2a]);
            b.revoked = vec![first, second];
        });

        let parsed = CertificateList::parse(&der).unwrap();
        assert_eq!(parsed.revoked[0].certificate_issuer.map(<[u8]>::to_vec),
                   Some(other_name.clone()));
        assert_eq!(parsed.revoked[1].certificate_issuer.map(<[u8]>::to_vec),
                   Some(other_name),
                   "the attribution did not carry forward, so the entry is \
                    being read as the CRL issuer's");

        assert_eq!(fixture.check(&[der]), Status::NotRevoked,
                   "an entry attributed to another CA revoked our certificate");
    }

    /// And the same list, with the entry attributed to *our* issuer,
    /// does revoke - so the test above is not passing because the entry
    /// was ignored altogether.
    #[test]
    fn test_an_entry_attributed_to_our_own_issuer_does_revoke() {
        let fixture = Fixture::new();
        let ours = fixture.leaf().issuer.raw.to_vec();
        let der = fixture.crl(|b| {
            b.issuing_distribution_point = Some(IssuingDistributionPointFields {
                indirect: true, ..Default::default()
            });
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.certificate_issuer = Some(ours);
            b.revoked = vec![entry];
        });
        assert!(fixture.check(&[der]).is_revoked());
    }

    // ---------------------------------------------------------- parsing ---

    /// A critical CRL extension we do not recognise means the list's
    /// scope is unknown, and a list of unknown scope cannot show that
    /// anything is absent from it.
    #[test]
    fn test_an_unrecognised_critical_crl_extension_makes_it_unusable() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.extra_extensions = vec![
                (crate::asn1::encode_oid("1.3.6.1.4.1.99999.1").unwrap(),
                 true, vec![0x05, 0x00])];
        });
        match fixture.check(&[der]) {
            Status::Unknown(why) => assert!(why.contains("critical"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// The two algorithm identifiers must agree, exactly as on a
    /// certificate: otherwise a weak one can be put where the verifier
    /// looks and a strong one where an inspector looks.
    #[test]
    fn test_the_two_algorithm_identifiers_must_agree() {
        let fixture = Fixture::new();
        let der = fixture.crl(|_| {});

        // ecdsa-with-SHA256 is 1.2.840.10045.4.3.2, and a CRL holds it
        // exactly twice - once in the TBS, once outside. Found by
        // searching rather than by counting offsets, and the count is
        // asserted, so the test cannot start editing the wrong bytes if
        // the encoding shifts.
        let oid = crate::asn1::encode_oid("1.2.840.10045.4.3.2").unwrap();
        let mut found: Vec<usize> = Vec::new();
        for start in 0..der.len().saturating_sub(oid.len()) {
            if der[start..start + oid.len()] == oid[..] {
                found.push(start);
            }
        }
        assert_eq!(found.len(), 2,
                   "expected the algorithm OID inside the TBS and outside it");

        // Change the *outer* one's last arc: SHA-256 becomes SHA-384.
        let mut broken = der.clone();
        let last = found[1] + oid.len() - 1;
        assert_eq!(broken[last], 0x02);
        broken[last] = 0x03;

        let error = CertificateList::parse(&broken).unwrap_err();
        assert!(error.contains("sha256 inside the signed body")
                && error.contains("sha384 outside"), "{}", error);

        // And the untouched CRL parses, so the failure above is the
        // mismatch rather than anything about editing bytes.
        assert!(CertificateList::parse(&der).is_ok());
    }

    /// `parse` reads and does not judge, same as `Certificate::parse`:
    /// a stale CRL parses, and `check` is where it stops being useful.
    #[test]
    fn test_parsing_reads_and_does_not_judge() {
        let fixture = Fixture::new();
        let der = fixture.crl(|b| {
            b.this_update = "20200101000000Z";
            b.next_update = Some("20210101000000Z");
            b.revoked = vec![RevocationEntry::new(&[0x2a])];
        });
        let parsed = CertificateList::parse(&der).unwrap();
        assert_eq!(parsed.revoked.len(), 1);
        assert_eq!(parsed.version, 2);
        assert!(parsed.next_update.is_some());
    }

    /// A certificate's cRLDistributionPoints, which is where a caller
    /// with a socket would go looking.
    #[test]
    fn test_distribution_points_are_reported() {
        let mut value = Writer::new();
        value.write_sequence(|w| {
            w.write_sequence(|w| {
                w.write_constructed(Tag::context(0, true), |w| {
                    w.write_constructed(Tag::context(0, true), |w| {
                        w.write_tlv(Tag::context(6, false),
                                    b"http://crl.example.test/ca.crl");
                        w.write_tlv(Tag::context(6, false),
                                    b"ldap://ldap.example.test/cn=CA");
                    });
                });
            });
        });
        let der = tests_support::leaf(|b| {
            b.extra_extensions = vec![
                (oids::CRL_DISTRIBUTION.to_vec(), false, value.finish())];
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(distribution_points(&certificate),
                   vec!["http://crl.example.test/ca.crl".to_string(),
                        "ldap://ldap.example.test/cn=CA".to_string()]);
    }
}
