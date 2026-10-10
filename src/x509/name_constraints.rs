/*
Name constraints: RFC 5280 section 4.2.1.10.

A CA certificate may carry a nameConstraints extension saying what names
the certificates below it are allowed to have. A CA constrained to
`.example.test` may issue for `www.example.test` and may not issue for
`www.example.com` - and *we* are the ones who have to enforce that,
because the CA cannot stop itself.

This is the extension that makes a private CA safe to trust. Without it,
adding a company's internal root to the store means that root can issue
for `google.com`; with it, the root can be confined to the company's own
names. Until this module existed, `docs/pitfalls.md` recorded the gap as
open: a constrained CA was accepted here for any name, and a *critical*
nameConstraints extension was refused only because it was a critical
extension we did not recognise.

    NameConstraints ::= SEQUENCE {
         permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
         excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

    GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

    GeneralSubtree ::= SEQUENCE {
         base                    GeneralName,
         minimum         [0]     BaseDistance DEFAULT 0,
         maximum         [1]     BaseDistance OPTIONAL }

## The rules, and where each one is easy to get wrong

**Excluded beats permitted.** A name matching any excluded subtree is
invalid "regardless of information appearing in the permittedSubtrees".
So the excluded check runs first and is not overridable.

**Only the forms that are constrained are constrained.** "Restrictions
apply only when the specified name form is present. If no name of the
type is in the certificate, the certificate is acceptable." So a
constraint on dNSName says nothing about an rfc822Name, and a
certificate with no dNSName at all satisfies any dNSName constraint.
The trap is the other direction: a permitted list that mentions a form
constrains **every** name of that form, so one DNS name outside the
subtree invalidates the certificate even if another is inside it.

**A leading period means different things to different forms**, and
this is the single most confusable part of the section:

  * **dNSName**: the base is a host name, and any number of labels may
    be added on the left. `host.example.com` matches itself *and*
    `www.host.example.com`. There is no leading period in the RFC's
    syntax for this form at all.
  * **URI and rfc822Name**: a base *with* a leading period matches
    subdomains and **not** the domain itself - `.example.com` is
    satisfied by `host.example.com` and not by `example.com`. A base
    *without* one specifies a single host exactly.

So the same string means "this host and everything under it" as a
dNSName and "this host only" as a URI constraint. Writing one matcher
for both is wrong in one direction or the other, and wrong in a way
that only shows up on the names that matter.

**rfc822Name reaches into the subject DN.** "When constraints are
imposed on the rfc822Name name form, but the certificate does not
include a subject alternative name, the rfc822Name constraint MUST be
applied to the attribute of type emailAddress in the subject
distinguished name." Legacy certificates put the address there, and a
constraint that ignored it would be bypassed by leaving the SAN out.

**A URI whose host is not a fully qualified domain name must be
rejected**, not ignored, when a URI constraint applies. The RFC says
so explicitly: no authority component, or an authority holding an IP
address, and "the application MUST reject the certificate". Ignoring
it is the natural implementation and is a bypass.

**iPAddress in a constraint is twice as long.** The field is an address
*and a mask*: eight octets for IPv4 and thirty-two for IPv6, where
everywhere else in X.509 it is four and sixteen. A parser that accepts
either length in both places reads a bare address as a constraint with
no mask. `read_general_name` takes the permitted lengths for that
reason.

**minimum and maximum are not usable.** The profile says minimum MUST
be zero and maximum MUST be absent, and that an application meeting
other values "MUST either process these fields or reject the
certificate". We reject: they express a distance in RDNs that nothing
here implements, and silently ignoring them would widen the subtree.

**Self-issued certificates are exempt** unless they are the leaf, so a
CA can roll its key over without tripping its own constraints.

## Intersecting subtrees, and why this does not

RFC 5280 section 6.1 describes path validation as carrying a
`permitted_subtrees` state that starts as "all names" and is
*intersected* with each CA's permitted set. Intersecting subtrees as
sets is fiddly - the intersection of `.a.example.com` and
`.example.com` is `.a.example.com`, and for directoryNames it is a
prefix comparison - and getting it wrong widens the set, which is the
dangerous direction.

So this keeps every constrained CA's list separately and requires a
name to satisfy **all** of them. For the only question anybody asks -
"is this name allowed" - that is exactly the intersection, computed
per-name instead of per-subtree, and it cannot accidentally widen
because nothing is ever merged.
*/

use crate::x509::{Certificate, GeneralName, oids, read_general_name, verify};
#[cfg(test)]
use crate::asn1;
use crate::asn1::{Reader, Tag};

/// The lengths an `iPAddress` may have inside a name constraint: an
/// address followed by a mask of the same width.
const ADDRESS_AND_MASK: [usize; 2] = [8, 32];

/// One CA's nameConstraints extension.
#[derive(Clone, Debug, Default)]
pub struct NameConstraints<'a> {
    pub permitted: Vec<GeneralName<'a>>,
    pub excluded: Vec<GeneralName<'a>>,
}

impl<'a> NameConstraints<'a> {
    pub fn parse(value: &'a [u8]) -> Result<NameConstraints<'a>, String> {
        let mut outer = Reader::new(value);
        let mut sequence = outer.read_sequence()?;
        outer.finish()?;

        let mut constraints = NameConstraints::default();
        // Both fields are OPTIONAL and IMPLICIT, so `[0]` and `[1]`
        // replace the `SEQUENCE OF` tag rather than wrapping it.
        if sequence.peek_tag() == Some(Tag::context(0, true)) {
            constraints.permitted = read_subtrees(&mut sequence, 0)?;
        }
        if sequence.peek_tag() == Some(Tag::context(1, true)) {
            constraints.excluded = read_subtrees(&mut sequence, 1)?;
        }
        sequence.finish()?;

        // "Conforming CAs MUST NOT issue certificates where name
        // constraints is an empty sequence." An empty one constrains
        // nothing, so accepting it would be accepting a certificate that
        // claims to be constrained and is not.
        if constraints.permitted.is_empty() && constraints.excluded.is_empty() {
            return Err("nameConstraints with neither permitted nor excluded \
                        subtrees constrains nothing (RFC 5280 4.2.1.10)."
                       .to_string());
        }
        Ok(constraints)
    }
}

fn read_subtrees<'a>(reader: &mut Reader<'a>, number: u32)
                     -> Result<Vec<GeneralName<'a>>, String> {
    let mut list = reader.read_constructed(Tag::context(number, true))?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let mut subtree = list.read_sequence()?;
        let base = read_general_name(&mut subtree, &ADDRESS_AND_MASK)?;

        // `minimum [0]` collides with GeneralName's `[0] otherName`, but
        // the order is fixed: the base is always first, so anything left
        // is a distance.
        if subtree.peek_tag() == Some(Tag::context(0, false)) {
            let bytes = subtree.read_tagged(Tag::context(0, false))?;
            // DEFAULT 0 means a zero must not be encoded at all, so any
            // value here is a non-zero distance - and so is a present
            // encoding of zero, which is a DER violation either way.
            return Err(format!(
                "nameConstraints sets a minimum BaseDistance ({} bytes of \
                 it). RFC 5280 4.2.1.10 requires it to be zero and absent, \
                 and an application that meets another value must process \
                 it or reject the certificate; this one rejects.",
                bytes.len()));
        }
        if subtree.peek_tag() == Some(Tag::context(1, false)) {
            return Err("nameConstraints sets a maximum BaseDistance. RFC \
                        5280 4.2.1.10 requires it to be absent, and an \
                        application that meets one must process it or \
                        reject the certificate; this one rejects."
                       .to_string());
        }
        subtree.finish()?;
        out.push(base);
    }
    // SIZE (1..MAX): a present-but-empty list is not a thing.
    if out.is_empty() {
        return Err("nameConstraints has an empty subtree list.".to_string());
    }
    Ok(out)
}

// ------------------------------------------------------------- the forms ---

/// Which name form a `GeneralName` is, so a constraint is only compared
/// against names of its own kind.
fn form(name: &GeneralName<'_>) -> u32 {
    match name {
        GeneralName::Other(number, _) | GeneralName::Malformed(number, _) => *number,
        GeneralName::Email(_) => 1,
        GeneralName::Dns(_) => 2,
        GeneralName::DirectoryName(_) => 4,
        GeneralName::Uri(_) => 6,
        GeneralName::IpAddress(_) => 7,
    }
}

/// Strip one trailing dot, which is the root label and means nothing here.
fn host(text: &str) -> &str {
    text.strip_suffix('.').unwrap_or(text)
}

/// A dNSName constraint: the base is a host, and labels may be added on
/// the left. RFC 5280: `host.example.com` is satisfied by
/// `www.host.example.com` and not by `host1.example.com`.
fn dns_matches(base: &str, name: &str) -> bool {
    let (base, name) = (host(base), host(name));
    // An empty base constrains nothing away; it is the "any DNS name"
    // subtree. Real certificates do not carry it, but a permitted list
    // holding it must not reject everything.
    if base.is_empty() {
        return true;
    }
    // A base written with a leading period is not in the RFC's syntax for
    // this form, and CAs emit it anyway. Read as "strictly below", which
    // is the narrower of the two readings - a constraint read too widely
    // admits names it should not.
    if let Some(suffix) = base.strip_prefix('.') {
        return ends_with_label(name, suffix);
    }
    if name.len() == base.len() {
        return name.eq_ignore_ascii_case(base);
    }
    // The label boundary is what stops `evilexample.com` satisfying a
    // constraint of `example.com`.
    ends_with_label(name, base)
}

/// Does `name` end in `.suffix`, ASCII case-insensitively?
///
/// Compared as bytes. Both strings come from certificates - the suffix
/// from the CA's constraint, the name from the leaf's SAN - and either
/// may hold a multi-byte character, since `read_general_name` accepts
/// any UTF-8. Slicing a `&str` at a byte offset taken from the *other*
/// string panics when that offset falls inside a character; a byte
/// slice cannot. ASCII folding on bytes is the same comparison as on
/// text for ASCII and an exact one for everything else.
fn ends_with_label(name: &str, suffix: &str) -> bool {
    let (name, suffix) = (name.as_bytes(), suffix.as_bytes());
    name.len() > suffix.len()
        && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        && name[name.len() - suffix.len() - 1] == b'.'
}

/// A host against a URI or rfc822Name base, where a leading period means
/// "strictly below" and its absence means "this host exactly".
fn host_matches(base: &str, candidate: &str) -> bool {
    let (base, candidate) = (host(base), host(candidate));
    if let Some(suffix) = base.strip_prefix('.') {
        // "Strictly below" is a label boundary, not a string suffix:
        // `.example.com` covers `host.example.com` and not
        // `evilexample.com`.
        return ends_with_label(candidate, suffix);
    }
    candidate.eq_ignore_ascii_case(base)
}

/// Split a mailbox at its last `@`.
fn mailbox(text: &str) -> Option<(&str, &str)> {
    let at = text.rfind('@')?;
    Some((&text[..at], &text[at + 1..]))
}

/// An rfc822Name constraint. Three shapes, per RFC 5280 4.2.1.10:
/// a whole mailbox, a bare host, or a leading-period domain.
fn email_matches(base: &str, name: &str) -> Result<bool, String> {
    let (local, name_host) = mailbox(name).ok_or_else(|| format!(
        "An rfc822Name of {:?} has no '@', so it is not a mail address and \
         cannot be checked against a constraint.", name))?;

    match mailbox(base) {
        // "root@example.com": a particular mailbox. The domain is
        // case-insensitive and the local part is not - the local part
        // belongs to the receiving host, which is free to distinguish
        // case, so folding it here would admit a mailbox the CA did not
        // name.
        Some((base_local, base_host)) =>
            Ok(local == base_local && name_host.eq_ignore_ascii_case(base_host)),
        None => Ok(host_matches(base, name_host)),
    }
}

/// The host of a URI, if it has one that is a domain name.
///
/// `Err` when a URI constraint applies and the URI has no such host: RFC
/// 5280 says the certificate MUST be rejected rather than the name
/// ignored.
fn uri_host(uri: &str) -> Result<&str, String> {
    let rest = uri.split_once("://").map(|(_, rest)| rest).ok_or_else(|| format!(
        "A uniformResourceIdentifier of {:?} has no authority component, and \
         a URI name constraint applies (RFC 5280 4.2.1.10).", uri))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Drop userinfo, which may itself contain an '@'.
    let authority = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    if authority.starts_with('[') {
        return Err(format!(
            "The URI {:?} has a literal IPv6 address for a host, not a fully \
             qualified domain name, and a URI name constraint applies.", uri));
    }
    // Strip a port. The host itself never contains a colon here, the IPv6
    // literal form having been refused above.
    let authority = authority.split(':').next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("The URI {:?} has an empty host.", uri));
    }
    // An IP address literal is not a fully qualified domain name, and the
    // RFC names that case specifically.
    if authority.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!(
            "The URI {:?} has an IP address for a host, not a fully \
             qualified domain name, and a URI name constraint applies.", uri));
    }
    Ok(authority)
}

/// An iPAddress constraint: address and mask, both of the address's width.
fn ip_matches(constraint: &[u8], address: &[u8]) -> bool {
    if constraint.len() != address.len() * 2 {
        // A v4 address against a v6 subtree, or the reverse. Different
        // families are different name spaces, not a mismatch to report.
        return false;
    }
    let (base, mask) = constraint.split_at(address.len());
    base.iter().zip(mask).zip(address)
        .all(|((b, m), a)| (b & m) == (a & m))
}

/// A directoryName constraint: the base's RDN sequence must be a prefix
/// of the name's.
///
/// Compared as DER, which is what RFC 5280 asks for: "name restrictions
/// MUST be stated identically to the encoding used in the subject field".
/// The alternative is the full ISO name comparison, and the RFC tells CAs
/// not to rely on it - every place two implementations normalise
/// differently is a place a constraint can be made to miss.
fn directory_matches(base: &[u8], name_rdns: &[&[u8]]) -> Result<bool, String> {
    // The constraint's bytes are the content of the explicit `[4]`, which
    // is a whole `Name` - a SEQUENCE OF RelativeDistinguishedName.
    let mut reader = Reader::new(base);
    let mut sequence = reader.read_sequence()?;
    reader.finish()?;
    let mut base_rdns: Vec<&[u8]> = Vec::new();
    while !sequence.is_empty() {
        let raw = sequence.clone().read_raw()?;
        sequence.read_set()?;
        base_rdns.push(raw);
    }
    if base_rdns.len() > name_rdns.len() {
        return Ok(false);
    }
    Ok(base_rdns.iter().zip(name_rdns).all(|(b, n)| b == n))
}

/// Does `name` fall inside the subtree `base`?
///
/// Only called with a base and a name of the same form.
fn inside(base: &GeneralName<'_>, name: &GeneralName<'_>,
          subject_rdns: &[&[u8]]) -> Result<bool, String> {
    let _ = subject_rdns;
    Ok(match (base, name) {
        (GeneralName::Dns(base), GeneralName::Dns(name)) =>
            dns_matches(base, name),
        (GeneralName::Email(base), GeneralName::Email(name)) =>
            email_matches(base, name)?,
        (GeneralName::Uri(base), GeneralName::Uri(name)) =>
            host_matches(base, uri_host(name)?),
        (GeneralName::IpAddress(base), GeneralName::IpAddress(name)) =>
            ip_matches(base, name),
        (GeneralName::DirectoryName(base), GeneralName::DirectoryName(name)) => {
            let mut reader = Reader::new(name);
            let mut sequence = reader.read_sequence()?;
            reader.finish()?;
            let mut rdns: Vec<&[u8]> = Vec::new();
            while !sequence.is_empty() {
                let raw = sequence.clone().read_raw()?;
                sequence.read_set()?;
                rdns.push(raw);
            }
            directory_matches(base, &rdns)?
        }
        // A form whose semantics RFC 5280 does not define. Treated as
        // matching only an identical encoding, which is the narrowest
        // reading available and so cannot admit anything.
        (GeneralName::Other(_, base), GeneralName::Other(_, name)) => base == name,
        _ => false,
    })
}

// ------------------------------------------------------------ enforcement ---

/// The names one certificate presents, for constraint purposes.
///
/// Not the same list as `subject_alt_names`: the subject DN is included
/// as a directoryName, and two legacy fallbacks are folded in because
/// otherwise leaving the SAN out is a way round the constraint.
fn names_of<'a>(certificate: &'a Certificate<'a>,
                constrained_forms: &[u32]) -> Result<Vec<GeneralName<'a>>, String> {
    let mut names: Vec<GeneralName<'a>> = Vec::new();

    // "Restrictions of the form directoryName MUST be applied to the
    // subject field in the certificate (when the certificate includes a
    // non-empty subject field)."
    if !certificate.subject.attributes.is_empty() {
        names.push(GeneralName::DirectoryName(certificate.subject.raw));
    }
    names.extend(certificate.extensions.subject_alt_names.iter().cloned());

    if certificate.extensions.subject_alt_names.is_empty() {
        // RFC 5280 4.2.1.10: with no SAN, an rfc822Name constraint applies
        // to the emailAddress attribute of the subject DN.
        if constrained_forms.contains(&1) {
            for attribute in &certificate.subject.attributes {
                if attribute.oid.as_bytes() == oids::EMAIL_ADDRESS {
                    let text = core::str::from_utf8(attribute.value)
                        .map_err(|_| "emailAddress attribute is not UTF-8."
                                 .to_string())?;
                    names.push(GeneralName::Email(text));
                }
            }
        }
    }

    // Not in RFC 5280, and necessary here: `matches_hostname` falls back
    // to the common name when the SAN names no host (no dNSName, no
    // URI), so a CA constrained to a DNS subtree could otherwise issue a
    // certificate with a CN of `evil.test` and either no SAN or a SAN
    // holding only an rfc822Name or iPAddress, and this library would
    // accept it for `evil.test` while the dNSName constraint saw no DNS
    // names at all. The constraint has to cover every name the verifier
    // will honour, not every name the RFC lists - so the condition is
    // the verifier's own predicate, not a reading of it.
    if constrained_forms.contains(&2) && verify::common_name_is_honoured(certificate) {
        if let Some(index) = certificate.subject.attributes.iter()
            .position(|a| a.oid.as_bytes() == oids::COMMON_NAME) {
            let attribute = &certificate.subject.attributes[index];
            if let Ok(text) = core::str::from_utf8(attribute.value) {
                if looks_like_a_host(text) {
                    names.push(GeneralName::Dns(text));
                }
            }
        }
    }
    Ok(names)
}

/// Whether a common name is the sort of string `matches_hostname` would
/// compare against a host name. "Acme Inc CA" is not; "leaf.test" is.
///
/// Deliberately loose: a string this says yes to gets *checked* against
/// the constraint, and the cost of a false positive is a certificate
/// refused for a CN that could never have matched a host anyway.
fn looks_like_a_host(text: &str) -> bool {
    !text.is_empty()
        && text.contains('.')
        && text.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*'
        })
}

/// Check one certificate against one CA's constraints.
fn check_one(certificate: &Certificate<'_>, constraints: &NameConstraints<'_>)
             -> Result<(), String> {
    let mut constrained: Vec<u32> = constraints.permitted.iter()
        .chain(&constraints.excluded)
        .map(form)
        .collect();
    constrained.sort_unstable();
    constrained.dedup();

    let names = names_of(certificate, &constrained)?;
    let subject_rdns = certificate.subject.rdns()?;

    for name in &names {
        let this_form = form(name);

        // A malformed name of a constrained form cannot be checked: it is
        // not inside a permitted subtree, and nobody can say it is not
        // inside an excluded one. Refused, since passing it would make
        // an unreadable name the way round an excluded subtree.
        if let GeneralName::Malformed(number, _) = name {
            if constrained.contains(number) {
                return Err(format!("{} cannot be checked against the issuer's \
                                    name constraints.", describe(name)));
            }
            continue;
        }

        // Excluded first and unconditionally: "Any name matching a
        // restriction in the excludedSubtrees field is invalid regardless
        // of information appearing in the permittedSubtrees."
        for base in &constraints.excluded {
            if form(base) == this_form && inside(base, name, &subject_rdns)? {
                return Err(format!("{} is inside an excluded subtree {}.",
                                   describe(name), describe(base)));
            }
        }

        // Permitted applies only to forms the permitted list mentions.
        // "Restrictions apply only when the specified name form is
        // present. If no name of the type is in the certificate, the
        // certificate is acceptable" - and the mirror of that is that a
        // form the permitted list does not mention is unconstrained.
        let mut bases = constraints.permitted.iter()
            .filter(|base| form(base) == this_form)
            .peekable();
        if bases.peek().is_none() {
            continue;
        }
        let mut allowed = false;
        for base in bases {
            if inside(base, name, &subject_rdns)? {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(format!("{} is in no permitted subtree.", describe(name)));
        }
    }
    Ok(())
}

fn describe(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::Dns(text) => format!("the DNS name {:?}", text),
        GeneralName::Email(text) => format!("the mail address {:?}", text),
        GeneralName::Uri(text) => format!("the URI {:?}", text),
        GeneralName::IpAddress(bytes) => format!("an IP address of {} bytes",
                                                 bytes.len()),
        GeneralName::DirectoryName(_) => "the subject name".to_string(),
        GeneralName::Other(number, _) => format!("a name of form [{}]", number),
        GeneralName::Malformed(number, _) => format!("a malformed name of form [{}]", number),
    }
}

/// Enforce every constraint in the chain.
///
/// `chain` is leaf first, as `verify_chain` takes it, and `root` is the
/// trusted certificate that issued the top of it - which may carry
/// constraints of its own and is the case that matters most, since a
/// privately added root is exactly what gets constrained.
///
/// A CA's constraints apply to every certificate *below* it, never to
/// itself: an intermediate constrained to `.example.test` is allowed to
/// be called `Example Test CA`.
pub fn check_chain(chain: &[Certificate<'_>], root: Option<&Certificate<'_>>)
                   -> Result<(), String> {
    // Issuers, from the one directly above the leaf upwards. The root
    // goes last so its constraints reach the whole chain.
    let issuers = chain.iter().skip(1).chain(root);

    for (height, issuer) in issuers.enumerate() {
        let value = match &issuer.extensions.name_constraints {
            Some(constraints) => constraints,
            None => continue,
        };
        // Everything strictly below this issuer. `height` counts from
        // zero at the certificate directly above the leaf, so that one
        // governs chain[..1] and the root governs the whole chain.
        let below = &chain[..height + 1];
        for (index, certificate) in below.iter().enumerate() {
            // "Name constraints are not applied to self-issued
            // certificates (unless the certificate is the final
            // certificate in the path)", so a CA can roll its key over
            // without tripping its own rules. Index 0 is the leaf, which
            // is the final certificate and is never exempt.
            if index > 0 && certificate.subject.matches(&certificate.issuer) {
                continue;
            }
            check_one(certificate, value).map_err(|reason| format!(
                "{} constrains the names below it, and {}: {}",
                issuer.subject, certificate.subject, reason))?;
        }
    }
    Ok(())
}

/// Whether this extension OID is one this module handles, so the parser
/// need not record it as an unrecognised critical extension.
pub fn is_name_constraints(oid: &[u8]) -> bool {
    oid == oids::NAME_CONSTRAINTS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::Writer;

    // ------------------------------------------------------ the matchers ---

    /// RFC 5280's own worked example, both halves. The negative half is
    /// the one that matters: `host1.example.com` shares a suffix with
    /// `host.example.com` and is not below it, which is exactly the
    /// mistake a `ends_with` with no label check makes.
    #[test]
    fn test_the_rfcs_dns_example() {
        assert!(dns_matches("host.example.com", "host.example.com"));
        assert!(dns_matches("host.example.com", "www.host.example.com"));
        assert!(!dns_matches("host.example.com", "host1.example.com"));

        // And the suffix attack in its bare form.
        assert!(!dns_matches("example.com", "evilexample.com"));
        assert!(dns_matches("example.com", "evil.example.com"));
    }

    /// A dNSName base matches itself; a URI base with the same spelling
    /// matches itself; a URI base with a leading period does **not**.
    /// The three readings differ and this pins which is which.
    #[test]
    fn test_a_leading_period_means_different_things_per_form() {
        // dNSName: no period, and subdomains are included anyway.
        assert!(dns_matches("example.com", "example.com"));
        assert!(dns_matches("example.com", "a.example.com"));

        // URI and email: no period means this host and nothing under it.
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("example.com", "a.example.com"));

        // With a period, the domain itself is excluded. RFC 5280:
        // "the constraint '.example.com' is not satisfied by
        // 'example.com'".
        assert!(!host_matches(".example.com", "example.com"));
        assert!(host_matches(".example.com", "host.example.com"));
        assert!(host_matches(".example.com", "my.host.example.com"));
    }

    /// A leading-period URI or rfc822Name base is a domain, so the name
    /// below it has to sit at a label boundary.
    ///
    /// What was wrong: `host_matches` checked only that the candidate
    /// ended with the base's text, so a CA constrained to
    /// `permitted rfc822Name .example.com` admitted any mailbox at
    /// `evilexample.com` - the suffix attack `dns_matches` already
    /// refuses, on the other two forms. The existing tests offered
    /// hosts that were either exactly the domain or properly below it,
    /// never one that merely ended in its spelling.
    #[test]
    fn test_a_leading_period_host_base_stops_at_a_label_boundary() {
        assert!(!host_matches(".example.com", "evilexample.com"));
        assert!(!email_matches(".example.com", "a@evilexample.com").unwrap());
        // And the shapes that must still pass.
        assert!(host_matches(".example.com", "evil.example.com"));
        assert!(email_matches(".example.com", "a@evil.example.com").unwrap());
    }

    /// A name holding a multi-byte character is compared, not panicked
    /// on.
    ///
    /// What was wrong: `dns_matches` and `host_matches` sliced one
    /// `&str` at a byte offset computed from the other's length, and a
    /// slice that lands inside a character panics. `read_general_name`
    /// accepts any UTF-8, so a leaf SAN of `éxample.com` under a CA
    /// constrained to `example.com` - a peer-supplied input that reaches
    /// this code once the signatures verify - panicked in `verify_chain`
    /// instead of being refused. Every name in the existing tests was
    /// ASCII, where byte and character offsets coincide. The comparisons
    /// are now over bytes.
    #[test]
    fn test_non_ascii_names_are_compared_not_panicked_on() {
        // 12 bytes against an 11 byte base: the old slice began one
        // byte into the two-byte `é`.
        assert!(!dns_matches("example.com", "éxample.com"));
        assert!(!dns_matches(".example.com", "éxample.com"));
        assert!(!host_matches(".example.com", "éxample.com"));
        // The constraint side can be the odd one too.
        assert!(!dns_matches("éxample.com", "example.com"));
        // A non-ASCII name inside a non-ASCII subtree still matches
        // exactly, since only ASCII folds.
        assert!(dns_matches("éxample.com", "a.éxample.com"));
        assert!(!dns_matches("éxample.com", "a.Éxample.com"));
    }

    #[test]
    fn test_dns_matching_is_case_insensitive_and_ignores_the_root_label() {
        assert!(dns_matches("Example.COM", "a.EXAMPLE.com"));
        assert!(dns_matches("example.com", "a.example.com."));
        assert!(dns_matches("example.com.", "a.example.com"));
    }

    /// The RFC's three mail shapes.
    #[test]
    fn test_the_rfcs_email_examples() {
        // A particular mailbox.
        assert!(email_matches("root@example.com", "root@example.com").unwrap());
        assert!(!email_matches("root@example.com", "other@example.com").unwrap());
        assert!(!email_matches("root@example.com", "root@sub.example.com").unwrap());

        // All mail at a host.
        assert!(email_matches("example.com", "anybody@example.com").unwrap());
        assert!(!email_matches("example.com", "anybody@host.example.com").unwrap());

        // All mail in a domain, but not on the domain's own host.
        assert!(email_matches(".example.com", "a@host.example.com").unwrap());
        assert!(!email_matches(".example.com", "a@example.com").unwrap());
    }

    /// The domain is case-insensitive; the local part is not. A
    /// constraint naming `root@` must not admit `ROOT@`, because the
    /// receiving host is free to treat those as two mailboxes.
    #[test]
    fn test_only_the_domain_half_of_a_mailbox_folds_case() {
        assert!(email_matches("root@example.com", "root@EXAMPLE.COM").unwrap());
        assert!(!email_matches("root@example.com", "ROOT@example.com").unwrap());
    }

    /// An rfc822Name with no `@` is not a mail address, and a name that
    /// cannot be checked must not pass.
    #[test]
    fn test_a_mail_name_with_no_at_sign_is_an_error() {
        assert!(email_matches("example.com", "example.com").is_err());
    }

    #[test]
    fn test_uri_hosts_are_extracted_around_userinfo_and_ports() {
        assert_eq!(uri_host("https://host.example.com/a/b").unwrap(),
                   "host.example.com");
        assert_eq!(uri_host("https://host.example.com").unwrap(),
                   "host.example.com");
        assert_eq!(uri_host("https://host.example.com:8443/x").unwrap(),
                   "host.example.com");
        // Userinfo may hold an '@', so the *last* one starts the host.
        assert_eq!(uri_host("https://user@evil.test@host.example.com/").unwrap(),
                   "host.example.com");
        assert_eq!(uri_host("ldap://host.example.com/?query").unwrap(),
                   "host.example.com");
        assert_eq!(uri_host("https://host.example.com#frag").unwrap(),
                   "host.example.com");
    }

    /// "If the URI either does not include an authority component or
    /// includes an authority component in which the host name is
    /// specified as an IP address, then the application MUST reject the
    /// certificate." Not ignore the name - reject.
    #[test]
    fn test_a_uri_without_a_domain_host_is_rejected_not_ignored() {
        assert!(uri_host("urn:example:thing").is_err());
        assert!(uri_host("https://192.0.2.1/x").is_err());
        assert!(uri_host("https://[2001:db8::1]:443/x").is_err());
        assert!(uri_host("https:///path").is_err());
    }

    /// The RFC's own CIDR example: 192.0.2.0/24 as
    /// `C0 00 02 00 FF FF FF 00`.
    #[test]
    fn test_the_rfcs_ip_example() {
        let constraint = [0xC0, 0x00, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0x00];
        assert!(ip_matches(&constraint, &[192, 0, 2, 1]));
        assert!(ip_matches(&constraint, &[192, 0, 2, 255]));
        assert!(!ip_matches(&constraint, &[192, 0, 3, 1]));

        // A v6 address is not in a v4 subtree, and the lengths say so
        // rather than the bytes.
        assert!(!ip_matches(&constraint, &[0u8; 16]));
    }

    /// A mask of all zeros is "every address", and a mask of all ones is
    /// a single host. Both are degenerate and both must work, because a
    /// wrong loop bound gives the right answer on one of them.
    #[test]
    fn test_the_degenerate_masks() {
        assert!(ip_matches(&[0, 0, 0, 0, 0, 0, 0, 0], &[203, 0, 113, 7]));
        let single = [203, 0, 113, 7, 255, 255, 255, 255];
        assert!(ip_matches(&single, &[203, 0, 113, 7]));
        assert!(!ip_matches(&single, &[203, 0, 113, 8]));
    }

    // --------------------------------------------------------- the parser ---

    /// Encode a nameConstraints extension value.
    fn encode(permitted: &[(u32, &[u8])], excluded: &[(u32, &[u8])]) -> Vec<u8> {
        fn subtrees(w: &mut Writer, number: u32, list: &[(u32, &[u8])]) {
            w.write_constructed(Tag::context(number, true), |w| {
                for (tag, bytes) in list {
                    w.write_sequence(|w| {
                        // [4] directoryName is the one constructed form:
                        // Name is a CHOICE, so its tag is explicit.
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
        writer.finish()
    }

    #[test]
    fn test_both_subtree_lists_parse() {
        let der = encode(&[(2, b"example.test")], &[(2, b"bad.example.test")]);
        let parsed = NameConstraints::parse(&der).unwrap();
        assert_eq!(parsed.permitted.len(), 1);
        assert_eq!(parsed.excluded.len(), 1);
        assert!(matches!(parsed.permitted[0], GeneralName::Dns("example.test")));
        assert!(matches!(parsed.excluded[0],
                         GeneralName::Dns("bad.example.test")));
    }

    #[test]
    fn test_either_list_alone_parses() {
        let permitted_only = encode(&[(2, b"example.test")], &[]);
        let parsed = NameConstraints::parse(&permitted_only).unwrap();
        assert_eq!(parsed.permitted.len(), 1);
        assert!(parsed.excluded.is_empty());

        let excluded_only = encode(&[], &[(2, b"example.test")]);
        let parsed = NameConstraints::parse(&excluded_only).unwrap();
        assert!(parsed.permitted.is_empty());
        assert_eq!(parsed.excluded.len(), 1);
    }

    /// "Conforming CAs MUST NOT issue certificates where name constraints
    /// is an empty sequence." Accepting one would accept a certificate
    /// that says it is constrained and is not.
    #[test]
    fn test_an_empty_constraint_is_refused() {
        let mut writer = Writer::new();
        writer.write_sequence(|_| {});
        assert!(NameConstraints::parse(&writer.finish()).is_err());
    }

    /// **An iPAddress subtree is eight bytes, not four.** Everywhere else
    /// in X.509 it is four, and a parser that took either here would read
    /// a bare address as a constraint with no mask - which `ip_matches`
    /// would then decline to match against anything, silently widening
    /// the subtree to "unconstrained".
    #[test]
    fn test_an_address_without_a_mask_is_refused_in_a_constraint() {
        let bare = encode(&[(7, &[192, 0, 2, 0])], &[]);
        let error = NameConstraints::parse(&bare).unwrap_err();
        assert!(error.contains("8 or 32"), "{}", error);

        let with_mask = encode(
            &[(7, &[192, 0, 2, 0, 255, 255, 255, 0])], &[]);
        assert!(NameConstraints::parse(&with_mask).is_ok());
    }

    /// And the reverse: a subjectAltName iPAddress is four or sixteen,
    /// so a constraint-shaped one there is refused too.
    #[test]
    fn test_a_masked_address_is_refused_in_a_subject_alt_name() {
        let mut inner = Writer::new();
        inner.write_sequence(|w| {
            w.write_tlv(Tag::context(7, false), &[192, 0, 2, 0, 255, 255, 255, 0]);
        });
        let der = inner.finish();
        let mut reader = Reader::new(&der);
        let mut sequence = reader.read_sequence().unwrap();
        assert!(read_general_name(&mut sequence, &crate::x509::ADDRESS_ONLY)
                .is_err());
    }

    /// minimum and maximum express a distance in RDNs that nothing here
    /// implements. RFC 5280 says an application meeting them must
    /// process them or reject; ignoring them widens the subtree.
    #[test]
    fn test_a_base_distance_is_refused() {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_constructed(Tag::context(0, true), |w| {
                w.write_sequence(|w| {
                    w.write_tlv(Tag::context(2, false), b"example.test");
                    w.write_tlv(Tag::context(0, false), &[1]);
                });
            });
        });
        let error = NameConstraints::parse(&writer.finish()).unwrap_err();
        assert!(error.contains("minimum"), "{}", error);

        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_constructed(Tag::context(0, true), |w| {
                w.write_sequence(|w| {
                    w.write_tlv(Tag::context(2, false), b"example.test");
                    w.write_tlv(Tag::context(1, false), &[4]);
                });
            });
        });
        let error = NameConstraints::parse(&writer.finish()).unwrap_err();
        assert!(error.contains("maximum"), "{}", error);
    }

    #[test]
    fn test_an_empty_subtree_list_is_refused() {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_constructed(Tag::context(0, true), |_| {});
        });
        assert!(NameConstraints::parse(&writer.finish()).is_err());
    }

    /// The two lists must appear in order and nothing may follow them.
    #[test]
    fn test_trailing_bytes_are_refused() {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_constructed(Tag::context(0, true), |w| {
                w.write_sequence(|w| {
                    w.write_tlv(Tag::context(2, false), b"example.test");
                });
            });
            w.write_tlv(Tag::context(9, false), b"junk");
        });
        assert!(NameConstraints::parse(&writer.finish()).is_err());
    }

    // ---------------------------------------------------- directory names ---

    fn name_der(attributes: &[(&[u8], &str)]) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            for (oid, value) in attributes {
                w.write_set(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(oid);
                        w.write_tlv(Tag::universal(asn1::tag::UTF8_STRING),
                                    value.as_bytes());
                    });
                });
            }
        });
        writer.finish()
    }

    fn rdns_of(der: &[u8]) -> Vec<&[u8]> {
        let mut reader = Reader::new(der);
        let mut sequence = reader.read_sequence().unwrap();
        let mut out = Vec::new();
        while !sequence.is_empty() {
            let raw = sequence.clone().read_raw().unwrap();
            sequence.read_set().unwrap();
            out.push(raw);
        }
        out
    }

    /// A directoryName constraint selects a subtree, so it matches names
    /// that *extend* it and not names that merely share attributes.
    #[test]
    fn test_a_directory_name_constraint_is_a_prefix() {
        let base = name_der(&[(oids::COUNTRY, "US"),
                              (oids::ORGANIZATION, "Example")]);
        let under = name_der(&[(oids::COUNTRY, "US"),
                               (oids::ORGANIZATION, "Example"),
                               (oids::COMMON_NAME, "leaf.test")]);
        let equal = name_der(&[(oids::COUNTRY, "US"),
                               (oids::ORGANIZATION, "Example")]);
        let other = name_der(&[(oids::COUNTRY, "US"),
                               (oids::ORGANIZATION, "Other")]);
        // A prefix *of the base*, which is shorter and so not below it.
        let shorter = name_der(&[(oids::COUNTRY, "US")]);

        assert!(directory_matches(&base, &rdns_of(&under)).unwrap());
        assert!(directory_matches(&base, &rdns_of(&equal)).unwrap());
        assert!(!directory_matches(&base, &rdns_of(&other)).unwrap());
        assert!(!directory_matches(&base, &rdns_of(&shorter)).unwrap());
    }

    /// The prefix is in RDNs, not attributes. `CN=a+O=b` is one RDN
    /// holding two attributes, and a flattened comparison would let a
    /// constraint on `O=b` alone match it.
    #[test]
    fn test_the_prefix_is_counted_in_rdns_not_attributes() {
        // One RDN with two attributes in it.
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_set(|w| {
                w.write_sequence(|w| {
                    w.write_oid(oids::COUNTRY);
                    w.write_tlv(Tag::universal(asn1::tag::UTF8_STRING), b"US");
                });
                w.write_sequence(|w| {
                    w.write_oid(oids::ORGANIZATION);
                    w.write_tlv(Tag::universal(asn1::tag::UTF8_STRING), b"Example");
                });
            });
        });
        let multi = writer.finish();
        assert_eq!(rdns_of(&multi).len(), 1);

        // The same two attributes as two separate RDNs is a different
        // name and must not match the combined one.
        let separate = name_der(&[(oids::COUNTRY, "US"),
                                  (oids::ORGANIZATION, "Example")]);
        assert_eq!(rdns_of(&separate).len(), 2);
        assert!(!directory_matches(&separate, &rdns_of(&multi)).unwrap());
        assert!(!directory_matches(&multi, &rdns_of(&separate)).unwrap());
    }

    #[test]
    fn test_looks_like_a_host_says_no_to_a_company_name() {
        assert!(looks_like_a_host("leaf.test"));
        assert!(looks_like_a_host("*.example.test"));
        assert!(!looks_like_a_host("Example Inc CA"));
        assert!(!looks_like_a_host("Root"));
        assert!(!looks_like_a_host(""));
    }
}
