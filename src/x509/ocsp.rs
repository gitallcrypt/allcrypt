/*
OCSP: the Online Certificate Status Protocol, RFC 6960.

A CRL is a list; an OCSP response is an answer about one certificate.
That makes it smaller and makes almost every way of getting it wrong a
way of accepting an answer about *something else*.

The answer is the same three-valued thing a CRL check produces, and it
is deliberately the same type - `crl::Status`. A caller asking "is this
certificate revoked" should not have to hold two spellings of the same
three answers, and `Unknown` is the one that matters in both: an OCSP
response that could not be used must never read as `good`.

## The ways this goes wrong

**The response is about a different certificate.** A `SingleResponse`
carries a `CertID`, and a responder may return several. Taking the
first, or taking any without checking, means a `good` about some other
certificate answers for this one - and a responder that has never heard
of ours is exactly where an attacker's stapled response comes from.
`matches` rebuilds the CertID from the certificate and its issuer and
compares all four fields.

**issuerKeyHash is not over the SubjectPublicKeyInfo.** RFC 6960 4.1.1:
"the value (excluding tag and length) of the subject public key field in
the issuer's certificate" - so it is the BIT STRING's *contents*, and
not the SPKI SEQUENCE, and not the BIT STRING's tag and length either.
Three plausible readings, one right, and the wrong ones simply never
match anything - which reads as "the responder does not know this
certificate" rather than as a bug.

**The unsigned error statuses are not answers.** `responseStatus` sits
*outside* the signature, so `tryLater` and `unauthorized` are bytes
anybody can write. They carry no `responseBytes` at all. Treating one as
anything but "no answer" is the whole protocol undone; treating
`unauthorized` as `good` would be, too.

**`unknown` is not `good`.** It is a distinct `CertStatus` meaning the
responder cannot speak for this certificate, and a match statement that
groups it with `good` compiles.

**`good [0] IMPLICIT NULL` has no content octets.** Zero-length, and
`revoked [1] IMPLICIT RevokedInfo` is a constructed SEQUENCE. A reader
that switched on the tag number alone without caring about the content
would take an empty `revoked` for a revocation with no time.

**Who may sign.** RFC 6960 4.2.2.2 gives exactly three acceptable
signers, and the third is the one with a condition attached: a delegated
responder must carry `id-kp-OCSPSigning` in its extendedKeyUsage **and**
be issued by the CA that issued the certificate in question. A
responder certificate accepted from the `certs` field without both
checks is a complete bypass - anybody with any certificate could answer
for anything.

**Delegated responders are exempt from revocation checking** (4.2.2.2.1)
when they carry id-pkix-ocsp-nocheck, and that is deliberate rather than
an oversight: checking a responder's own status over OCSP needs a
responder, and so on.

**Time.** `thisUpdate` in the future and `nextUpdate` in the past both
make a response unreliable (4.2.2.1), and a response with no
`nextUpdate` means newer information is always available - which is not
a licence to cache it. As with a CRL, a stale response can still revoke
and cannot clear: a revocation does not become untrue because the answer
carrying it is old.

## What is not here

**Fetching, and the nonce's purpose.** Nothing in this library opens a
socket. `build_request` produces the DER to POST and `responder_urls`
says where; the round trip is the caller's. A nonce is generated and
checked when the caller supplies one, and it is the only defence against
a replayed response - without it a captured `good` is valid until its
nextUpdate, which is how a revoked certificate stays usable.

**Chain building for the responder.** A delegated responder's
certificate is checked against the issuer directly, which is what RFC
6960 4.2.2.2 requires ("issued directly by the CA that is identified in
the request"). No path is built beyond that.
*/

use crate::asn1::{self, Oid, Reader, Tag, Writer};
use crate::x509::crl::{Reason, Status};
use crate::x509::verify::{verify_signed, Policy};
use crate::x509::{oids, Certificate, Name, SignatureAlgorithm};

/// The outer, **unsigned** status byte.
///
/// Everything but `Successful` carries no response at all, and none of
/// it is authenticated - it is whatever was on the wire. So none of
/// these is ever news about a certificate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResponseStatus {
    Successful,
    MalformedRequest,
    InternalError,
    TryLater,
    SigRequired,
    Unauthorized,
    /// A value RFC 6960 does not define. Kept rather than refused, so a
    /// caller can report what arrived.
    Other(u32),
}

impl ResponseStatus {
    fn from_value(value: u32) -> ResponseStatus {
        match value {
            0 => ResponseStatus::Successful,
            1 => ResponseStatus::MalformedRequest,
            2 => ResponseStatus::InternalError,
            3 => ResponseStatus::TryLater,
            5 => ResponseStatus::SigRequired,
            6 => ResponseStatus::Unauthorized,
            other => ResponseStatus::Other(other),
        }
    }

    pub fn name(self) -> String {
        match self {
            ResponseStatus::Successful => "successful".to_string(),
            ResponseStatus::MalformedRequest => "malformedRequest".to_string(),
            ResponseStatus::InternalError => "internalError".to_string(),
            ResponseStatus::TryLater => "tryLater".to_string(),
            ResponseStatus::SigRequired => "sigRequired".to_string(),
            ResponseStatus::Unauthorized => "unauthorized".to_string(),
            ResponseStatus::Other(value) => format!("status {}", value),
        }
    }
}

/// What a responder said about one certificate.
///
/// `Unknown` is a status the responder gives, distinct from
/// `crl::Status::Unknown` which is what *we* conclude. They usually
/// coincide, and they are not the same thing: the first is a signed
/// statement and the second is an absence of one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CertStatus {
    Good,
    Revoked { at: i64, reason: Option<Reason> },
    Unknown,
}

/// `CertID`: which certificate a response is about.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertId<'a> {
    /// The hash this responder used. Its choice, not ours, so a check
    /// has to recompute with whatever it picked.
    pub hash: &'static str,
    pub issuer_name_hash: &'a [u8],
    pub issuer_key_hash: &'a [u8],
    pub serial: &'a [u8],
}

impl CertId<'_> {
    /// Whether this identifies `certificate`, issued by `issuer`.
    ///
    /// All four fields, recomputed. Comparing the serial alone is the
    /// mistake that matters: serials are unique per issuer, so a
    /// responder for another CA answering about *its* serial 3 would
    /// answer for ours.
    pub fn identifies(&self, certificate: &Certificate<'_>,
                      issuer: &Certificate<'_>) -> Result<bool, String> {
        if self.serial != certificate.serial {
            return Ok(false);
        }
        let name_hash = digest(self.hash, issuer.subject.raw)?;
        let key_hash = digest(self.hash, public_key_bits(issuer)?)?;
        Ok(self.issuer_name_hash == name_hash.as_slice()
           && self.issuer_key_hash == key_hash.as_slice())
    }
}

/// One `SingleResponse`.
#[derive(Clone, Debug)]
pub struct SingleResponse<'a> {
    pub cert_id: CertId<'a>,
    pub status: CertStatus,
    pub this_update: i64,
    pub next_update: Option<i64>,
}

/// How the responder named itself.
#[derive(Clone, Debug)]
pub enum ResponderId<'a> {
    ByName(Name<'a>),
    /// The SHA-1 of the responder's public key bits - the same value
    /// `CertID` hashes, and hashed the same way.
    ByKey(&'a [u8]),
}

/// A `BasicOCSPResponse`: the signed part.
#[derive(Clone, Debug)]
pub struct BasicResponse<'a> {
    /// The `ResponseData`, tag and length included: the bytes signed.
    pub tbs: &'a [u8],
    pub responder_id: ResponderId<'a>,
    pub produced_at: i64,
    pub responses: Vec<SingleResponse<'a>>,
    /// Certificates the responder supplied to check its own signature.
    /// Raw DER, unparsed: they are untrusted until one of them has been
    /// shown to be an authorised responder.
    pub certs: Vec<&'a [u8]>,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: &'a [u8],
    /// Extensions on the whole response, of which the nonce is the one
    /// that matters.
    pub nonce: Option<&'a [u8]>,
}

/// A whole `OCSPResponse`.
#[derive(Clone, Debug)]
pub struct Response<'a> {
    pub status: ResponseStatus,
    /// Present only when `status` is `Successful`. Everything else
    /// carries no response at all.
    pub basic: Option<BasicResponse<'a>>,
}

// -------------------------------------------------------------- parsing ---

/// The issuer's public key bits: the BIT STRING's contents, with the
/// unused-bits octet dropped.
///
/// **Not the SubjectPublicKeyInfo and not the BIT STRING's TLV.** RFC
/// 6960 4.1.1 says "the value (excluding tag and length) of the subject
/// public key field", and the three readings are all plausible. The
/// wrong ones never match anything, which reads as "the responder does
/// not know this certificate" rather than as a bug in here.
fn public_key_bits<'a>(issuer: &Certificate<'a>) -> Result<&'a [u8], String> {
    let mut reader = Reader::new(issuer.spki);
    let mut sequence = reader.read_sequence()?;
    reader.finish()?;
    sequence.read_any()?;                       // AlgorithmIdentifier
    let bits = sequence.read_bit_string()?;
    sequence.finish()?;
    Ok(bits)
}

/// The `KeyHash` a responder puts in `ResponderID ::= byKey`, and the
/// `issuerKeyHash` a `CertID` carries: the same value, over the same
/// bits, and RFC 6960 spells it out twice for that reason.
///
/// One function, because two would be two chances to pick a different
/// one of the three plausible readings of "the subject public key
/// field".
pub fn key_hash(certificate: &Certificate<'_>, hash: &str)
                -> Result<Vec<u8>, String> {
    digest(hash, public_key_bits(certificate)?)
}

/// The `issuerNameHash` a `CertID` carries: over the issuer's DN as it
/// is encoded in the certificate being checked.
pub fn name_hash(issuer: &Certificate<'_>, hash: &str)
                 -> Result<Vec<u8>, String> {
    digest(hash, issuer.subject.raw)
}

fn digest(hash: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    use crate::hash_functions::HashFunction;
    let mut hasher = crate::api::AnyHash::new(hash)?;
    hasher.update(data);
    Ok(hasher.digest())
}

/// The hash a `CertID`'s AlgorithmIdentifier names.
fn hash_name(oid: Oid<'_>) -> Result<&'static str, String> {
    let bytes = oid.as_bytes();
    if bytes == oids::SHA1 { Ok("sha1") }
    else if bytes == oids::SHA256 { Ok("sha256") }
    else if bytes == oids::SHA384 { Ok("sha384") }
    else if bytes == oids::SHA512 { Ok("sha512") }
    else {
        Err(format!("A CertID uses hash algorithm {}, which is not \
                     implemented here.", oid))
    }
}

fn hash_oid(hash: &str) -> Result<&'static [u8], String> {
    match hash {
        "sha1" => Ok(oids::SHA1),
        "sha256" => Ok(oids::SHA256),
        "sha384" => Ok(oids::SHA384),
        "sha512" => Ok(oids::SHA512),
        other => Err(format!("No OCSP CertID hash OID for {:?}.", other)),
    }
}

fn read_cert_id<'a>(reader: &mut Reader<'a>) -> Result<CertId<'a>, String> {
    let mut sequence = reader.read_sequence()?;
    let mut algorithm = sequence.read_sequence()?;
    let oid = algorithm.read_oid()?;
    // The parameters are an optional NULL; SHA-1 carries one in
    // practice and the SHA-2 family may not.
    while !algorithm.is_empty() {
        algorithm.read_any()?;
    }
    let hash = hash_name(oid)?;
    let issuer_name_hash = sequence.read_octet_string()?;
    let issuer_key_hash = sequence.read_octet_string()?;
    let serial = sequence.read_integer_bytes()?;
    sequence.finish()?;
    Ok(CertId { hash, issuer_name_hash, issuer_key_hash, serial })
}

impl<'a> Response<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Response<'a>, String> {
        let mut outer = Reader::new(der);
        let mut response = outer.read_sequence()?;
        outer.finish()?;

        let value = response.read_tagged(
            Tag::universal(asn1::tag::ENUMERATED))?;
        let mut status_value = 0u32;
        for byte in value {
            status_value = status_value.checked_mul(256)
                .and_then(|n| n.checked_add(u32::from(*byte)))
                .ok_or_else(|| "OCSP response status is absurdly large."
                            .to_string())?;
        }
        let status = ResponseStatus::from_value(status_value);

        // `responseBytes [0] EXPLICIT`, present only on success. RFC
        // 6960 4.2.1: "If the value of responseStatus is one of the
        // error conditions, the responseBytes field is not set."
        let mut basic = None;
        if response.peek_tag() == Some(Tag::context(0, true)) {
            if status != ResponseStatus::Successful {
                return Err(format!(
                    "An OCSP response with status {} carries responseBytes, \
                     which RFC 6960 4.2.1 says it must not.", status.name()));
            }
            let mut wrapper = response.read_constructed(Tag::context(0, true))?;
            let mut bytes = wrapper.read_sequence()?;
            wrapper.finish()?;
            let response_type = bytes.read_oid()?;
            if response_type.as_bytes() != oids::OCSP_BASIC {
                return Err(format!(
                    "The OCSP response is of type {}; only id-pkix-ocsp-basic \
                     is implemented.", response_type));
            }
            let inner = bytes.read_octet_string()?;
            bytes.finish()?;
            basic = Some(BasicResponse::parse(inner)?);
        } else if status == ResponseStatus::Successful {
            return Err("An OCSP response says successful and carries no \
                        response.".to_string());
        }
        response.finish()?;
        Ok(Response { status, basic })
    }
}

impl<'a> BasicResponse<'a> {
    pub fn parse(der: &'a [u8]) -> Result<BasicResponse<'a>, String> {
        let mut outer = Reader::new(der);
        let mut basic = outer.read_sequence()?;
        outer.finish()?;

        let tbs = basic.clone().read_raw()?;
        let mut data = basic.read_sequence()?;
        let signature_algorithm = crate::x509::read_algorithm(&mut basic)?;
        let signature = basic.read_bit_string()?;

        let mut certs = Vec::new();
        if basic.peek_tag() == Some(Tag::context(0, true)) {
            let mut wrapper = basic.read_constructed(Tag::context(0, true))?;
            let mut list = wrapper.read_sequence()?;
            wrapper.finish()?;
            while !list.is_empty() {
                certs.push(list.clone().read_raw()?);
                list.read_sequence()?;
            }
        }
        basic.finish()?;

        // `version [0] EXPLICIT Version DEFAULT v1` - so absent is v1,
        // and a present one must not be v1 under DER's DEFAULT rule.
        if data.peek_tag() == Some(Tag::context(0, true)) {
            let mut wrapper = data.read_constructed(Tag::context(0, true))?;
            let version = wrapper.read_u32()?;
            wrapper.finish()?;
            if version != 0 {
                return Err(format!("OCSP response version {} is not v1.",
                                   version + 1));
            }
            return Err("An OCSP response encodes version v1 explicitly, which \
                        DER's DEFAULT rule forbids.".to_string());
        }

        // `ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }`,
        // both EXPLICIT because Name is itself a CHOICE and the tagging
        // default in this module is explicit.
        let responder_id = match data.peek_tag() {
            Some(tag) if tag == Tag::context(1, true) => {
                let mut wrapper = data.read_constructed(Tag::context(1, true))?;
                let name = Name::parse(&mut wrapper)?;
                wrapper.finish()?;
                ResponderId::ByName(name)
            }
            Some(tag) if tag == Tag::context(2, true) => {
                let mut wrapper = data.read_constructed(Tag::context(2, true))?;
                let key = wrapper.read_octet_string()?;
                wrapper.finish()?;
                ResponderId::ByKey(key)
            }
            _ => return Err(
                "An OCSP ResponderID must be [1] byName or [2] byKey."
                .to_string()),
        };

        let produced_at = data.read_time()?;

        let mut responses = Vec::new();
        let mut list = data.read_sequence()?;
        while !list.is_empty() {
            responses.push(read_single_response(&mut list)?);
        }

        let mut nonce = None;
        if data.peek_tag() == Some(Tag::context(1, true)) {
            let mut wrapper = data.read_constructed(Tag::context(1, true))?;
            nonce = read_nonce(&mut wrapper)?;
            wrapper.finish()?;
        }
        data.finish()?;

        Ok(BasicResponse { tbs, responder_id, produced_at, responses, certs,
                           signature_algorithm, signature, nonce })
    }

    /// The response about `certificate`, if this holds one.
    ///
    /// A responder may answer about several certificates in one
    /// response. Taking the first is the mistake: a `good` about
    /// somebody else's certificate would answer for this one.
    pub fn response_for(&self, certificate: &Certificate<'_>,
                        issuer: &Certificate<'_>)
                        -> Result<Option<&SingleResponse<'a>>, String> {
        for single in &self.responses {
            if single.cert_id.identifies(certificate, issuer)? {
                return Ok(Some(single));
            }
        }
        Ok(None)
    }
}

fn read_single_response<'a>(reader: &mut Reader<'a>)
                            -> Result<SingleResponse<'a>, String> {
    let mut single = reader.read_sequence()?;
    let cert_id = read_cert_id(&mut single)?;

    // `CertStatus ::= CHOICE { good [0] IMPLICIT NULL,
    //                          revoked [1] IMPLICIT RevokedInfo,
    //                          unknown [2] IMPLICIT UnknownInfo }`
    //
    // All three IMPLICIT, so the tag replaces the type's own: `good` is
    // a primitive [0] with **no content octets**, `revoked` is a
    // constructed [1] holding a SEQUENCE's fields, `unknown` is a
    // primitive [2] with none (UnknownInfo is NULL).
    let (tag, content) = single.read_any()?;
    if tag.class != asn1::CLASS_CONTEXT {
        return Err("A CertStatus must use a context tag.".to_string());
    }
    let status = match tag.number {
        0 => {
            if !content.is_empty() {
                return Err("CertStatus good is NULL and has no content \
                            octets.".to_string());
            }
            CertStatus::Good
        }
        1 => {
            let mut info = Reader::new(content);
            let at = info.read_time()?;
            let mut reason = None;
            if info.peek_tag() == Some(Tag::context(0, true)) {
                let mut wrapper = info.read_constructed(Tag::context(0, true))?;
                let bytes = wrapper.read_tagged(
                    Tag::universal(asn1::tag::ENUMERATED))?;
                wrapper.finish()?;
                let mut value = 0u32;
                for byte in bytes {
                    value = value.checked_mul(256)
                        .and_then(|n| n.checked_add(u32::from(*byte)))
                        .ok_or_else(|| "OCSP revocation reason is absurdly \
                                        large.".to_string())?;
                }
                reason = Some(Reason::from_value_public(value));
            }
            info.finish()?;
            CertStatus::Revoked { at, reason }
        }
        2 => CertStatus::Unknown,
        other => return Err(format!("Unknown CertStatus [{}].", other)),
    };

    let this_update = single.read_time()?;
    let next_update = if single.peek_tag() == Some(Tag::context(0, true)) {
        let mut wrapper = single.read_constructed(Tag::context(0, true))?;
        let time = wrapper.read_time()?;
        wrapper.finish()?;
        Some(time)
    } else {
        None
    };
    // singleExtensions [1] EXPLICIT, read past: the ones defined here
    // (archive cutoff, CRL references) do not change the status.
    if single.peek_tag() == Some(Tag::context(1, true)) {
        single.read_any()?;
    }
    single.finish()?;

    Ok(SingleResponse { cert_id, status, this_update, next_update })
}

fn read_nonce<'a>(reader: &mut Reader<'a>) -> Result<Option<&'a [u8]>, String> {
    let mut list = reader.read_sequence()?;
    while !list.is_empty() {
        let mut extension = list.read_sequence()?;
        let oid = extension.read_oid()?;
        if extension.peek_tag() == Some(Tag::universal(asn1::tag::BOOLEAN)) {
            extension.read_bool()?;
        }
        let value = extension.read_octet_string()?;
        extension.finish()?;
        if oid.as_bytes() == oids::OCSP_NONCE {
            // The extension's value is itself an OCTET STRING holding
            // the nonce. Two layers, and a reader that peeled only one
            // compares the DER header along with the bytes - which
            // still round-trips against itself.
            let mut inner = Reader::new(value);
            let nonce = inner.read_octet_string()?;
            inner.finish()?;
            return Ok(Some(nonce));
        }
    }
    Ok(None)
}

// ------------------------------------------------------------- checking ---

/// Who signed a response, and whether they were allowed to.
///
/// RFC 6960 4.2.2.2 gives exactly three acceptable signers. Only two are
/// reachable without local configuration, and the second has a condition
/// attached that is the whole security of delegation.
fn verify_signer(basic: &BasicResponse<'_>, issuer: &Certificate<'_>,
                 policy: &Policy, now: i64) -> Result<(), String> {
    // 2. The issuer signed it itself.
    if let Ok(()) = verify_signed(basic.tbs, basic.signature_algorithm,
                                  basic.signature, &issuer.public_key, policy) {
        return Ok(());
    }

    // 3. A delegated responder, whose certificate the response carries.
    let mut reasons: Vec<String> = Vec::new();
    for der in &basic.certs {
        let responder = match Certificate::parse(der) {
            Ok(certificate) => certificate,
            Err(reason) => {
                reasons.push(format!("a supplied certificate did not parse: {}",
                                     reason));
                continue;
            }
        };
        // **Issued by the CA that issued the certificate in question.**
        // Without this, anybody with any certificate could answer for
        // anything.
        if !issuer.is_issuer_of(&responder) {
            reasons.push(format!(
                "{} was not issued by {}", responder.subject, issuer.subject));
            continue;
        }
        // **id-kp-OCSPSigning in the extendedKeyUsage.** This is what
        // designates the delegation; a certificate the CA issued for
        // anything else is not a responder.
        let delegated = responder.extensions.extended_key_usage.as_ref()
            .is_some_and(|usages| usages.iter()
                         .any(|oid| oid.as_bytes() == oids::EKU_OCSP_SIGNING));
        if !delegated {
            reasons.push(format!(
                "{} does not carry id-kp-OCSPSigning, so it is not a \
                 delegated responder", responder.subject));
            continue;
        }
        // Its own validity still applies. An expired responder is not
        // one, and this is the check `allow_expired` may relax like any
        // other.
        if !policy.allow_expired && (now < responder.not_before
                                     || now > responder.not_after) {
            reasons.push(format!("{} is outside its validity window",
                                 responder.subject));
            continue;
        }
        if let Err(reason) = crate::x509::verify::verify_signature(
                &responder, issuer, policy) {
            reasons.push(format!("{}'s own signature does not verify: {}",
                                 responder.subject, reason));
            continue;
        }
        if let Err(reason) = verify_signed(basic.tbs, basic.signature_algorithm,
                                           basic.signature,
                                           &responder.public_key, policy) {
            reasons.push(format!("the response does not verify under {}: {}",
                                 responder.subject, reason));
            continue;
        }
        return Ok(());
    }

    let mut message = format!(
        "no acceptable signer: the response does not verify under {}'s own \
         key, and no supplied certificate is an authorised responder for it \
         (RFC 6960 4.2.2.2)", issuer.subject);
    if !reasons.is_empty() {
        message.push_str(&format!(" - {}", reasons.join("; ")));
    }
    Err(message)
}

/// What an OCSP response says about one certificate.
///
/// `nonce` is what the caller put in its request, if it sent one. A
/// response whose nonce differs is about a different question, and one
/// with no nonce where a nonce was asked for could be a replay - both
/// are `Unknown` rather than an answer.
///
/// `now` is passed in rather than read from a clock, so the check is
/// reproducible.
pub fn check(certificate: &Certificate<'_>, issuer: &Certificate<'_>,
             response_der: &[u8], nonce: Option<&[u8]>, policy: &Policy,
             now: i64) -> Status {
    let response = match Response::parse(response_der) {
        Ok(response) => response,
        Err(reason) => return Status::Unknown(
            format!("the OCSP response did not parse: {}", reason)),
    };

    let basic = match (&response.status, &response.basic) {
        (ResponseStatus::Successful, Some(basic)) => basic,
        (status, _) => return Status::Unknown(format!(
            "the responder answered {}, which carries no signed statement \
             about anything - the status byte is outside the signature",
            status.name())),
    };

    if let Err(reason) = verify_signer(basic, issuer, policy, now) {
        return Status::Unknown(reason);
    }

    // The nonce, after the signature: an unsigned nonce proves nothing,
    // so checking it first would be checking bytes anybody can write.
    if let Some(sent) = nonce {
        match basic.nonce {
            Some(got) if got == sent => {}
            Some(_) => return Status::Unknown(
                "the response's nonce is not the one that was sent, so it \
                 answers a different question".to_string()),
            None => return Status::Unknown(
                "a nonce was sent and the response carries none, so it may \
                 be a replay of an older answer".to_string()),
        }
    }

    let single = match basic.response_for(certificate, issuer) {
        Ok(Some(single)) => single,
        Ok(None) => return Status::Unknown(format!(
            "the response is signed and says nothing about this certificate: \
             it carries {} answer(s), none of whose CertID matches",
            basic.responses.len())),
        Err(reason) => return Status::Unknown(
            format!("the response's CertID could not be checked: {}", reason)),
    };

    // A revocation stands whatever the clock says. The same asymmetry as
    // a stale CRL: being told "revoked" is an answer, being told "good"
    // by something out of date is not.
    if let CertStatus::Revoked { at, reason } = single.status {
        return Status::Revoked { at, reason };
    }

    if now < single.this_update {
        return Status::Unknown(format!(
            "the response is not valid until {} and it is {}",
            single.this_update, now));
    }
    if let Some(next) = single.next_update {
        if now > next {
            return Status::Unknown(format!(
                "the response expired at {} and it is {}; the certificate may \
                 have been revoked since", next, now));
        }
    }

    match single.status {
        CertStatus::Good => Status::NotRevoked,
        // **Not good.** The responder is saying it cannot speak for this
        // certificate - which is what a responder for a different CA
        // says about ours.
        CertStatus::Unknown => Status::Unknown(
            "the responder answered unknown, meaning it cannot speak for \
             this certificate".to_string()),
        CertStatus::Revoked { .. } => unreachable!("handled above"),
    }
}

// ------------------------------------------------------------- requests ---

/// Build an `OCSPRequest` for one certificate.
///
/// `hash` names the CertID digest; SHA-1 is what responders expect and
/// is not a security property here - the hashes identify a certificate
/// rather than authenticate anything, and the serial is compared
/// directly alongside them.
///
/// `nonce`, if given, goes in as id-pkix-ocsp-nonce and must be handed
/// back to `check`. It is the only defence against a replayed response.
pub fn build_request(certificate: &Certificate<'_>, issuer: &Certificate<'_>,
                     hash: &str, nonce: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let oid = hash_oid(hash)?;
    let name_hash = digest(hash, issuer.subject.raw)?;
    let key_hash = digest(hash, public_key_bits(issuer)?)?;

    let mut writer = Writer::new();
    writer.write_sequence(|request| {
        request.write_sequence(|tbs| {
            tbs.write_sequence(|list| {
                list.write_sequence(|entry| {
                    entry.write_sequence(|id| {
                        id.write_sequence(|algorithm| {
                            algorithm.write_oid(oid);
                            // SHA-1 carries an explicit NULL here in
                            // every responder's expectation.
                            algorithm.write_null();
                        });
                        id.write_octet_string(&name_hash);
                        id.write_octet_string(&key_hash);
                        id.write_tlv(Tag::universal(asn1::tag::INTEGER),
                                     certificate.serial);
                    });
                });
            });
            if let Some(nonce) = nonce {
                // requestExtensions [2] EXPLICIT Extensions
                tbs.write_constructed(Tag::context(2, true), |wrapper| {
                    wrapper.write_sequence(|list| {
                        list.write_sequence(|extension| {
                            extension.write_oid(oids::OCSP_NONCE);
                            let mut value = Writer::new();
                            value.write_octet_string(nonce);
                            extension.write_octet_string(&value.finish());
                        });
                    });
                });
            }
        });
    });
    Ok(writer.finish())
}

/// Where a certificate says its OCSP responder lives (RFC 5280
/// 4.2.2.1's authorityInfoAccess, `id-ad-ocsp`).
///
/// Reported, never fetched: nothing in this library opens a socket.
pub fn responder_urls(certificate: &Certificate<'_>) -> Vec<String> {
    certificate.extensions.ocsp_responders.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::builder::key_usage;
    use crate::x509::tests_support::{self, TestKey};

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn test_the_response_status_values_are_the_rfcs() {
        assert_eq!(ResponseStatus::from_value(0), ResponseStatus::Successful);
        assert_eq!(ResponseStatus::from_value(1),
                   ResponseStatus::MalformedRequest);
        assert_eq!(ResponseStatus::from_value(2), ResponseStatus::InternalError);
        assert_eq!(ResponseStatus::from_value(3), ResponseStatus::TryLater);
        // RFC 6960 4.2.1: "(4) is not used".
        assert_eq!(ResponseStatus::from_value(4), ResponseStatus::Other(4));
        assert_eq!(ResponseStatus::from_value(5), ResponseStatus::SigRequired);
        assert_eq!(ResponseStatus::from_value(6), ResponseStatus::Unauthorized);
    }

    /// **`issuerKeyHash` is over the BIT STRING's contents**, not the
    /// SubjectPublicKeyInfo and not the BIT STRING's TLV. All three
    /// readings are plausible and only one matches anybody.
    #[test]
    fn test_the_key_hash_is_over_the_bit_string_contents() {
        let key = TestKey::new();
        let der = tests_support::leaf(|_| {});
        let certificate = Certificate::parse(&der).unwrap();
        let _ = key;

        let bits = public_key_bits(&certificate).unwrap();

        // It is a slice of the SPKI, and strictly shorter than it.
        assert!(bits.len() < certificate.spki.len());
        // An uncompressed P-256 point: 0x04 and two 32 byte coordinates.
        assert_eq!(bits.len(), 65);
        assert_eq!(bits[0], 0x04);

        // And the two wrong readings give different hashes, so a test
        // of the right one is not vacuous.
        let right = digest("sha1", bits).unwrap();
        let whole_spki = digest("sha1", certificate.spki).unwrap();
        assert_ne!(right, whole_spki);
    }

    /// A CertID identifies a certificate by four fields, and the serial
    /// alone is not enough: serials are unique per issuer, so another
    /// CA's serial 42 is not ours.
    #[test]
    fn test_a_cert_id_needs_more_than_the_serial() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let other = tests_support::chain(|_| {}, |_| {}, |_| {});
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        let other_intermediate = Certificate::parse(&other.intermediate).unwrap();

        let request = build_request(&leaf, &intermediate, "sha1", None).unwrap();
        let id = cert_id_of(&request);

        assert!(id.identifies(&leaf, &intermediate).unwrap());
        // Same serial, different issuer: the name and key hashes differ.
        // `other`'s leaf also has serial 3.
        let other_leaf = Certificate::parse(&other.leaf).unwrap();
        assert_eq!(other_leaf.serial, leaf.serial);
        assert!(!id.identifies(&other_leaf, &other_intermediate).unwrap());
    }

    /// Pull the CertID back out of a request we built, which is also a
    /// round trip of the writer through the reader.
    fn cert_id_of(request: &[u8]) -> CertId<'_> {
        let mut outer = Reader::new(request);
        let mut sequence = outer.read_sequence().unwrap();
        let mut tbs = sequence.read_sequence().unwrap();
        let mut list = tbs.read_sequence().unwrap();
        let mut entry = list.read_sequence().unwrap();
        read_cert_id(&mut entry).unwrap()
    }

    #[test]
    fn test_a_request_round_trips_and_carries_its_nonce() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();

        let plain = build_request(&leaf, &intermediate, "sha1", None).unwrap();
        let with_nonce = build_request(&leaf, &intermediate, "sha1",
                                       Some(&[7u8; 16])).unwrap();
        assert!(with_nonce.len() > plain.len());

        // Every hash the CertID may use produces a different identifier,
        // and all of them parse back.
        let mut seen = Vec::new();
        for hash in ["sha1", "sha256", "sha384", "sha512"] {
            let request = build_request(&leaf, &intermediate, hash, None).unwrap();
            let id = cert_id_of(&request);
            assert_eq!(id.hash, hash);
            assert!(id.identifies(&leaf, &intermediate).unwrap());
            assert!(!seen.contains(&id.issuer_key_hash.to_vec()));
            seen.push(id.issuer_key_hash.to_vec());
        }
    }

    /// An unsigned error status is not an answer about anything. It
    /// carries no signed bytes at all - the status byte is outside the
    /// signature, so anybody on the wire can write it.
    #[test]
    fn test_an_error_status_is_never_an_answer() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let intermediate = Certificate::parse(&chain.intermediate).unwrap();
        let policy = Policy::at(NOW);

        for value in [1u8, 2, 3, 5, 6] {
            let mut writer = Writer::new();
            writer.write_sequence(|w| {
                w.write_tlv(Tag::universal(asn1::tag::ENUMERATED), &[value]);
            });
            let der = writer.finish();
            match check(&leaf, &intermediate, &der, None, &policy, NOW) {
                Status::Unknown(why) =>
                    assert!(why.contains("no signed statement"), "{}", why),
                other => panic!("status {} gave {:?}", value, other),
            }
        }
    }

    /// An error status carrying a response is malformed: RFC 6960 4.2.1
    /// says responseBytes is not set for one.
    #[test]
    fn test_an_error_status_may_not_carry_a_response() {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_tlv(Tag::universal(asn1::tag::ENUMERATED), &[6]);
            w.write_constructed(Tag::context(0, true), |w| {
                w.write_sequence(|w| {
                    w.write_oid(oids::OCSP_BASIC);
                    w.write_octet_string(&[]);
                });
            });
        });
        let error = Response::parse(&writer.finish()).unwrap_err();
        assert!(error.contains("must not"), "{}", error);
    }

    /// And success with nothing in it is equally malformed.
    #[test]
    fn test_success_must_carry_a_response() {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_tlv(Tag::universal(asn1::tag::ENUMERATED), &[0]);
        });
        let error = Response::parse(&writer.finish()).unwrap_err();
        assert!(error.contains("carries no response"), "{}", error);
    }

    #[test]
    fn test_responder_urls_come_from_the_certificate() {
        let mut value = Writer::new();
        value.write_sequence(|w| {
            w.write_sequence(|w| {
                w.write_oid(oids::AD_OCSP);
                w.write_tlv(Tag::context(6, false),
                            b"http://ocsp.example.test/");
            });
            // A second access method, which must not be reported as a
            // responder: caIssuers points at the issuer's certificate.
            w.write_sequence(|w| {
                w.write_oid(oids::AD_CA_ISSUERS);
                w.write_tlv(Tag::context(6, false),
                            b"http://certs.example.test/ca.cer");
            });
        });
        let der = tests_support::leaf(|b| {
            b.extra_extensions = vec![
                (oids::AUTHORITY_INFO_ACCESS.to_vec(), false, value.finish())];
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(responder_urls(&certificate),
                   vec!["http://ocsp.example.test/".to_string()]);
    }

    /// A certificate with a CA-signing key usage but no OCSP extension
    /// reports nothing rather than raising.
    #[test]
    fn test_no_aia_means_no_responders() {
        let der = tests_support::leaf(|b| {
            b.key_usage = Some(key_usage::DIGITAL_SIGNATURE);
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert!(responder_urls(&certificate).is_empty());
    }

    // ------------------------------------------------ signed responses ---

    use crate::x509::builder::{OcspResponseBuilder, OcspSingleResponse,
                               OcspStatus};

    /// A chain, and a responder that answers about its leaf.
    struct Responder {
        chain: tests_support::Chain,
        /// A key the CA never delegated to.
        stranger: TestKey,
    }

    impl Responder {
        fn new() -> Responder {
            Responder {
                chain: tests_support::chain(|_| {}, |_| {}, |_| {}),
                stranger: TestKey::new(),
            }
        }

        fn leaf(&self) -> Certificate<'_> {
            Certificate::parse(&self.chain.leaf).unwrap()
        }

        fn issuer(&self) -> Certificate<'_> {
            Certificate::parse(&self.chain.intermediate).unwrap()
        }

        /// A response about our leaf, signed by the issuer itself -
        /// RFC 6960 4.2.2.2's second acceptable signer.
        fn response(&self, status: OcspStatus,
                    configure: impl FnOnce(&mut OcspResponseBuilder<'_>))
                    -> Vec<u8> {
            let leaf = self.leaf();
            let issuer = self.issuer();
            let mut builder = OcspResponseBuilder::new("Test Intermediate");
            builder.responses = vec![
                OcspSingleResponse::about(&leaf, &issuer, "sha1", status)
                    .unwrap()];
            configure(&mut builder);
            builder.sign(&self.chain.intermediate_key.signing()).unwrap()
        }

        fn check(&self, der: &[u8], nonce: Option<&[u8]>) -> Status {
            check(&self.leaf(), &self.issuer(), der, nonce,
                  &Policy::at(NOW), NOW)
        }
    }

    #[test]
    fn test_good_revoked_and_unknown_are_three_different_answers() {
        let responder = Responder::new();

        assert_eq!(responder.check(&responder.response(OcspStatus::Good, |_| {}),
                                   None),
                   Status::NotRevoked);

        let revoked = responder.response(
            OcspStatus::Revoked("20230601000000Z", Some(1)), |_| {});
        match responder.check(&revoked, None) {
            Status::Revoked { reason, .. } =>
                assert_eq!(reason, Some(Reason::KeyCompromise)),
            other => panic!("{:?}", other),
        }

        // **`unknown` is not `good`.** The responder is saying it
        // cannot speak for this certificate, which is what a responder
        // for a different CA says about ours.
        match responder.check(&responder.response(OcspStatus::Unknown, |_| {}),
                              None) {
            Status::Unknown(why) => assert!(why.contains("unknown"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// A revocation with no reason is still a revocation.
    #[test]
    fn test_a_revocation_without_a_reason_still_revokes() {
        let responder = Responder::new();
        let der = responder.response(
            OcspStatus::Revoked("20230601000000Z", None), |_| {});
        match responder.check(&der, None) {
            Status::Revoked { reason, at } => {
                assert_eq!(reason, None);
                assert!(at > 0);
            }
            other => panic!("{:?}", other),
        }
    }

    /// **The signature is checked.** A response signed by a key the CA
    /// never delegated to is not an answer, whatever it says - in
    /// either direction.
    #[test]
    fn test_a_response_from_a_stranger_is_not_an_answer() {
        let responder = Responder::new();
        let leaf = responder.leaf();
        let issuer = responder.issuer();

        for status in [OcspStatus::Good,
                       OcspStatus::Revoked("20230601000000Z", Some(1))] {
            let mut builder = OcspResponseBuilder::new("Test Intermediate");
            builder.responses = vec![
                OcspSingleResponse::about(&leaf, &issuer, "sha1", status)
                    .unwrap()];
            let der = builder.sign(&responder.stranger.signing()).unwrap();
            match responder.check(&der, None) {
                Status::Unknown(why) =>
                    assert!(why.contains("no acceptable signer"), "{}", why),
                other => panic!("expected unknown, got {:?}", other),
            }
        }
    }

    /// **A response about a different certificate answers for nothing.**
    /// The responder is real, the signature is good, and the CertID is
    /// somebody else's - which is exactly the shape of a stapled
    /// response harvested from another connection.
    #[test]
    fn test_a_response_about_another_certificate_is_not_an_answer() {
        let responder = Responder::new();
        let other = tests_support::chain(|_| {}, |_| {}, |_| {});
        let other_leaf = Certificate::parse(&other.leaf).unwrap();
        let other_issuer = Certificate::parse(&other.intermediate).unwrap();

        // Signed by *our* issuer, so the signature checks out, and
        // about somebody else's certificate. Both leaves have serial 3,
        // so only the issuer hashes tell them apart.
        let mut builder = OcspResponseBuilder::new("Test Intermediate");
        builder.responses = vec![
            OcspSingleResponse::about(&other_leaf, &other_issuer, "sha1",
                                      OcspStatus::Good).unwrap()];
        let der = builder.sign(&responder.chain.intermediate_key.signing())
                         .unwrap();

        assert_eq!(other_leaf.serial, responder.leaf().serial,
                   "the two leaves must share a serial or this test is \
                    about nothing");
        match responder.check(&der, None) {
            Status::Unknown(why) =>
                assert!(why.contains("says nothing about this certificate"),
                        "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// A responder answering about several certificates: ours has to be
    /// picked out, not the first one taken.
    #[test]
    fn test_the_right_single_response_is_picked_from_several() {
        let responder = Responder::new();
        let leaf = responder.leaf();
        let issuer = responder.issuer();
        let other = tests_support::chain(|_| {}, |_| {}, |_| {});
        let other_leaf = Certificate::parse(&other.leaf).unwrap();
        let other_issuer = Certificate::parse(&other.intermediate).unwrap();

        let mut builder = OcspResponseBuilder::new("Test Intermediate");
        builder.responses = vec![
            // Somebody else's, first, and good.
            OcspSingleResponse::about(&other_leaf, &other_issuer, "sha1",
                                      OcspStatus::Good).unwrap(),
            // Ours, second, and revoked.
            OcspSingleResponse::about(
                &leaf, &issuer, "sha1",
                OcspStatus::Revoked("20230601000000Z", Some(4))).unwrap(),
        ];
        let der = builder.sign(&responder.chain.intermediate_key.signing())
                         .unwrap();
        assert!(responder.check(&der, None).is_revoked(),
                "the first answer was taken rather than ours");
    }

    /// Every CertID hash a responder may choose has to work, because
    /// the choice is the responder's.
    #[test]
    fn test_any_cert_id_hash_the_responder_chooses_is_understood() {
        let responder = Responder::new();
        let leaf = responder.leaf();
        let issuer = responder.issuer();
        for hash in ["sha1", "sha256", "sha384", "sha512"] {
            let mut builder = OcspResponseBuilder::new("Test Intermediate");
            builder.responses = vec![
                OcspSingleResponse::about(&leaf, &issuer, hash,
                                          OcspStatus::Good).unwrap()];
            let der = builder.sign(&responder.chain.intermediate_key.signing())
                             .unwrap();
            assert_eq!(responder.check(&der, None), Status::NotRevoked,
                       "CertID hash {}", hash);
        }
    }

    // --------------------------------------------- delegated responders ---

    /// A delegated responder: a certificate the CA issued, carrying
    /// id-kp-OCSPSigning, supplied in the response's `certs`.
    fn delegated(chain: &tests_support::Chain, key: &TestKey,
                 eku: Vec<&'static [u8]>, issued_by_the_ca: bool) -> Vec<u8> {
        let builder = tests_support::Builder {
            common_name: "Test Responder".to_string(),
            dns_names: vec![],
            key_usage: Some(key_usage::DIGITAL_SIGNATURE),
            extended_key_usage: eku,
            ..Default::default()
        };
        if issued_by_the_ca {
            builder.issue(key, &chain.intermediate_key, "Test Intermediate", 9)
        } else {
            // Signed by the root instead, which is *a* CA and not the
            // one that issued the certificate in question.
            builder.issue(key, &chain.root_key, "Test Root", 9)
        }
    }

    fn delegated_response(responder: &Responder, responder_key: &TestKey,
                          certificate: Vec<u8>, status: OcspStatus) -> Vec<u8> {
        let leaf = responder.leaf();
        let issuer = responder.issuer();
        let mut builder = OcspResponseBuilder::new("Test Responder");
        builder.responses = vec![
            OcspSingleResponse::about(&leaf, &issuer, "sha1", status).unwrap()];
        builder.certs = vec![certificate];
        builder.sign(&responder_key.signing()).unwrap()
    }

    #[test]
    fn test_a_properly_delegated_responder_is_accepted() {
        let responder = Responder::new();
        let key = TestKey::new();
        let certificate = delegated(&responder.chain, &key,
                                    vec![oids::EKU_OCSP_SIGNING], true);
        let der = delegated_response(&responder, &key, certificate,
                                     OcspStatus::Good);
        assert_eq!(responder.check(&der, None), Status::NotRevoked);
    }

    /// **Without id-kp-OCSPSigning it is not a responder.** This is the
    /// check that stops anybody holding a certificate from that CA -
    /// every one of its customers - from answering for every other
    /// certificate it issued.
    #[test]
    fn test_a_certificate_without_ocsp_signing_may_not_answer() {
        let responder = Responder::new();
        let key = TestKey::new();
        let certificate = delegated(&responder.chain, &key,
                                    vec![oids::EKU_SERVER_AUTH], true);
        let der = delegated_response(&responder, &key, certificate,
                                     OcspStatus::Good);
        match responder.check(&der, None) {
            Status::Unknown(why) =>
                assert!(why.contains("id-kp-OCSPSigning"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// **And it must be issued by the CA in question.** A responder
    /// certificate from some *other* CA, even one in the same chain,
    /// is not a delegation from this one.
    #[test]
    fn test_a_responder_issued_by_another_ca_may_not_answer() {
        let responder = Responder::new();
        let key = TestKey::new();
        let certificate = delegated(&responder.chain, &key,
                                    vec![oids::EKU_OCSP_SIGNING], false);
        let der = delegated_response(&responder, &key, certificate,
                                     OcspStatus::Good);
        match responder.check(&der, None) {
            Status::Unknown(why) =>
                assert!(why.contains("not issued by"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// The certificate in `certs` has to actually verify against the
    /// CA. One that merely claims the right issuer name is not one.
    #[test]
    fn test_a_forged_responder_certificate_may_not_answer() {
        let responder = Responder::new();
        let key = TestKey::new();
        let certificate = delegated(&responder.chain, &key,
                                    vec![oids::EKU_OCSP_SIGNING], true);
        // Flip a bit of the signature.
        let mut broken = certificate.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0x01;
        let der = delegated_response(&responder, &key, broken,
                                     OcspStatus::Good);
        match responder.check(&der, None) {
            Status::Unknown(why) =>
                assert!(why.contains("does not verify"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    // ---------------------------------------------------------- the nonce ---

    /// A nonce is the only defence against a replayed response: without
    /// one a captured `good` is valid until its nextUpdate.
    #[test]
    fn test_the_nonce_must_come_back() {
        let responder = Responder::new();
        let sent = [0x5au8; 16];

        let matching = responder.response(OcspStatus::Good, |b| {
            b.nonce = Some(sent.to_vec());
        });
        assert_eq!(responder.check(&matching, Some(&sent)), Status::NotRevoked);

        // A different nonce answers a different question.
        let different = responder.response(OcspStatus::Good, |b| {
            b.nonce = Some(vec![0xa5; 16]);
        });
        match responder.check(&different, Some(&sent)) {
            Status::Unknown(why) => assert!(why.contains("not the one"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }

        // And none at all may be a replay.
        let absent = responder.response(OcspStatus::Good, |_| {});
        match responder.check(&absent, Some(&sent)) {
            Status::Unknown(why) => assert!(why.contains("replay"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }

        // A caller that sent no nonce does not mind a response carrying
        // one, since it cannot be checked either way.
        assert_eq!(responder.check(&matching, None), Status::NotRevoked);
    }

    /// The nonce is checked **after** the signature. An unsigned nonce
    /// proves nothing, and a check that ran first would be comparing
    /// bytes anybody on the wire can write - reporting a nonce mismatch
    /// where the real problem is a forged response.
    #[test]
    fn test_the_signature_is_checked_before_the_nonce() {
        let responder = Responder::new();
        let leaf = responder.leaf();
        let issuer = responder.issuer();
        let mut builder = OcspResponseBuilder::new("Test Intermediate");
        builder.responses = vec![
            OcspSingleResponse::about(&leaf, &issuer, "sha1", OcspStatus::Good)
                .unwrap()];
        builder.nonce = Some(vec![0x11; 16]);
        let der = builder.sign(&responder.stranger.signing()).unwrap();

        match responder.check(&der, Some(&[0x22u8; 16])) {
            Status::Unknown(why) => assert!(
                why.contains("no acceptable signer"),
                "reported the nonce where the real problem is the \
                 signature: {}", why),
            other => panic!("{:?}", other),
        }
    }

    // ------------------------------------------------------------- time ---

    /// **A stale response revokes and cannot clear**, the same
    /// asymmetry as a stale CRL: a revocation does not become untrue
    /// because the answer carrying it is old.
    #[test]
    fn test_a_stale_response_revokes_but_cannot_clear() {
        let responder = Responder::new();

        let stale_good = responder.response(OcspStatus::Good, |b| {
            b.responses[0].this_update = "20190101000000Z";
            b.responses[0].next_update = Some("20210101000000Z");
        });
        match responder.check(&stale_good, None) {
            Status::Unknown(why) => assert!(why.contains("expired"), "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }

        let stale_revoked = responder.response(
            OcspStatus::Revoked("20200101000000Z", Some(1)), |b| {
                b.responses[0].this_update = "20190101000000Z";
                b.responses[0].next_update = Some("20210101000000Z");
            });
        assert!(responder.check(&stale_revoked, None).is_revoked());
    }

    #[test]
    fn test_a_response_from_the_future_cannot_clear() {
        let responder = Responder::new();
        let der = responder.response(OcspStatus::Good, |b| {
            b.responses[0].this_update = "20380101000000Z";
            b.responses[0].next_update = Some("20390101000000Z");
        });
        match responder.check(&der, None) {
            Status::Unknown(why) => assert!(why.contains("not valid until"),
                                            "{}", why),
            other => panic!("expected unknown, got {:?}", other),
        }
    }

    /// No nextUpdate means newer information is always available (RFC
    /// 6960 4.2.2.1). The response is usable at the moment it is read.
    #[test]
    fn test_a_response_with_no_next_update_is_usable() {
        let responder = Responder::new();
        let der = responder.response(OcspStatus::Good, |b| {
            b.responses[0].this_update = "20230101000000Z";
            b.responses[0].next_update = None;
        });
        assert_eq!(responder.check(&der, None), Status::NotRevoked);
    }

    /// An unsigned error status, built the way a responder builds one -
    /// no responseBytes at all.
    #[test]
    fn test_a_built_error_status_carries_nothing() {
        let responder = Responder::new();
        let der = responder.response(OcspStatus::Good, |b| {
            b.response_status = 3;               // tryLater
        });
        let parsed = Response::parse(&der).unwrap();
        assert_eq!(parsed.status, ResponseStatus::TryLater);
        assert!(parsed.basic.is_none());
        match responder.check(&der, None) {
            Status::Unknown(why) => assert!(why.contains("tryLater"), "{}", why),
            other => panic!("{:?}", other),
        }
    }

    /// `ResponderID ::= byKey` is the other form, and it is the SHA-1
    /// of the same bits a CertID hashes. We do not check the responder
    /// id against anything - the signature decides who signed - but it
    /// has to parse or the whole response is unreadable.
    #[test]
    fn test_a_response_naming_its_responder_by_key_parses() {
        let responder = Responder::new();
        let der = responder.response(OcspStatus::Good, |b| {
            b.responder_key_hash = Some(vec![0x42; 20]);
        });
        let parsed = Response::parse(&der).unwrap();
        let basic = parsed.basic.unwrap();
        match basic.responder_id {
            ResponderId::ByKey(key) => assert_eq!(key, &[0x42u8; 20]),
            other => panic!("{:?}", other),
        }
        assert_eq!(responder.check(&der, None), Status::NotRevoked);
    }
}
