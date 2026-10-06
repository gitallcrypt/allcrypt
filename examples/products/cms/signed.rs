//! SignedData (RFC 5652 section 5), with RSA PKCS#1 v1.5 and PSS
//! (RFC 4056), ECDSA (RFC 5753), DSA (RFC 3370) and EdDSA (RFC 8419).
//!
//! With signed attributes the signature covers the DER of the
//! attributes - re-tagged from `[0] IMPLICIT` to `SET OF` - and the
//! attributes carry the content's type and digest, both of which are
//! checked; without them it covers the content itself.

use allcrypt::asn1::{tag, Reader, Tag, Writer};
use allcrypt::publickey_ciphers::rsa::{self, RsaPublicKey};
use allcrypt::x509::verify::{self, Policy};
use allcrypt::x509::{Certificate, PublicKey, SignatureAlgorithm};

use crate::asn::{self, AlgId, CertId, IssuerSerial};
use crate::keys::Key;

pub struct SignerInfo {
    pub version: u32,
    pub sid: CertId,
    pub digest_alg: AlgId,
    /// The content octets of `signedAttrs [0]`, as they arrived.
    pub signed_attrs: Option<Vec<u8>>,
    pub sig_alg: AlgId,
    pub signature: Vec<u8>,
}

pub struct SignedData {
    pub version: u32,
    pub digest_algs: Vec<AlgId>,
    pub content_type: Vec<u8>,
    pub content: Option<Vec<u8>>,
    pub certificates: Vec<Vec<u8>>,
    pub crl_count: usize,
    pub signers: Vec<SignerInfo>,
}

/// The `EncapsulatedContentInfo`: its type and, unless detached, its
/// content octets.
pub fn read_encapsulated(r: &mut Reader) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    let mut seq = r.read_sequence()?;
    let content_type = seq.read_oid()?.as_bytes().to_vec();
    let content = match seq.read_optional_context(0, true)? {
        None => None,
        Some(explicit) => {
            let mut inner = Reader::new(explicit);
            let octets = inner.read_octet_string()
                .map_err(|_| "eContent is not an OCTET STRING.".to_string())?;
            inner.finish()?;
            Some(octets.to_vec())
        }
    };
    seq.finish()?;
    Ok((content_type, content))
}

pub fn write_encapsulated(w: &mut Writer, content_type: &str, content: Option<&[u8]>) {
    w.write_sequence(|w| {
        w.write_oid(&asn::oid(content_type));
        if let Some(content) = content {
            w.write_constructed(Tag::context(0, true), |w| w.write_octet_string(content));
        }
    });
}

pub fn read_cert_id(r: &mut Reader) -> Result<CertId, String> {
    match r.peek_tag() {
        Some(t) if t == Tag::sequence() => Ok(CertId::IssuerSerial(IssuerSerial::read(r)?)),
        Some(t) if t == Tag::context(0, false) =>
            Ok(CertId::KeyId(r.read_tagged(Tag::context(0, false))?.to_vec())),
        _ => Err("A signer or recipient identified by something other than issuer and \
                  serial or a key identifier.".to_string()),
    }
}

pub fn write_cert_id(w: &mut Writer, id: &CertId) {
    match id {
        CertId::IssuerSerial(is) => is.write(w),
        CertId::KeyId(key) => w.write_tlv(Tag::context(0, false), key),
    }
}

/// The certificates of a `CertificateSet`, skipping the attribute
/// certificates and other kinds it may also hold.
pub fn read_certificate_set(content: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut r = Reader::new(content);
    let mut out = Vec::new();
    while !r.is_empty() {
        let is_cert = r.peek_tag() == Some(Tag::sequence());
        let raw = r.read_raw()?;
        if is_cert {
            out.push(raw.to_vec());
        }
    }
    Ok(out)
}

pub fn parse(der: &[u8]) -> Result<SignedData, String> {
    let mut r = Reader::new(der);
    let mut seq = r.read_sequence()?;
    r.finish()?;
    let version = seq.read_u32()?;
    let mut algs = seq.read_set()?;
    let mut digest_algs = Vec::new();
    while !algs.is_empty() {
        digest_algs.push(AlgId::read(&mut algs)?);
    }
    let (content_type, content) = read_encapsulated(&mut seq)?;
    let certificates = match seq.read_optional_context(0, true)? {
        Some(set) => read_certificate_set(set)?,
        None => Vec::new(),
    };
    let crl_count = match seq.read_optional_context(1, true)? {
        Some(set) => {
            let mut r = Reader::new(set);
            let mut n = 0;
            while !r.is_empty() {
                r.read_raw()?;
                n += 1;
            }
            n
        }
        None => 0,
    };
    let mut infos = seq.read_set()?;
    seq.finish()?;
    let mut signers = Vec::new();
    while !infos.is_empty() {
        let mut si = infos.read_sequence()?;
        let version = si.read_u32()?;
        let sid = read_cert_id(&mut si)?;
        let digest_alg = AlgId::read(&mut si)?;
        let signed_attrs = si.read_optional_context(0, true)?.map(<[u8]>::to_vec);
        let sig_alg = AlgId::read(&mut si)?;
        let signature = si.read_octet_string()?.to_vec();
        si.read_optional_context(1, true)?;
        si.finish()?;
        signers.push(SignerInfo { version, sid, digest_alg, signed_attrs, sig_alg, signature });
    }
    Ok(SignedData { version, digest_algs, content_type, content, certificates, crl_count,
                    signers })
}

/// What verifying one signer found.
pub struct SignerReport {
    pub id: String,
    pub subject: Option<String>,
    pub algorithm: String,
    pub signing_time: Option<i64>,
    pub result: Result<(), String>,
    /// The signer's certificate, when it was found.
    pub certificate: Option<Vec<u8>>,
}

/// The content and each signer's verdict. `detached` is the content for
/// a SignedData that does not carry it; `extra` are certificates to look
/// in besides the ones the message carries.
pub fn verify_all(sd: &SignedData, detached: Option<&[u8]>, extra: &[Vec<u8>], policy: &Policy)
                  -> Result<(Vec<u8>, Vec<SignerReport>), String> {
    let content = match (&sd.content, detached) {
        (Some(_), Some(_)) => return Err("The message carries its content; there is none \
                                          to give it.".to_string()),
        (Some(c), None) => c.clone(),
        (None, Some(c)) => c.to_vec(),
        (None, None) => return Err("The content is detached: give it with --content."
                                   .to_string()),
    };
    if sd.signers.is_empty() {
        return Err("The message has no signers (a certificates-only message?).".to_string());
    }
    let pool: Vec<&[u8]> = sd.certificates.iter().chain(extra).map(Vec::as_slice).collect();
    let parsed: Vec<Certificate> = pool.iter().filter_map(|der| Certificate::parse(der).ok())
        .collect();
    let mut reports = Vec::new();
    for signer in &sd.signers {
        let cert = parsed.iter().find(|c| signer.sid.matches(c));
        let mut report = SignerReport {
            id: signer.sid.describe(),
            subject: cert.map(|c| c.subject.to_string()),
            algorithm: describe_algorithm(signer),
            signing_time: None,
            result: Ok(()),
            certificate: cert.map(|c| c.raw.to_vec()),
        };
        report.result = match cert {
            None => Err("The signer's certificate is not in the message; give it with \
                         --certfile.".to_string()),
            Some(cert) => verify_one(sd, signer, &content, cert, &parsed, policy,
                                     &mut report.signing_time),
        };
        reports.push(report);
    }
    Ok((content, reports))
}

fn describe_algorithm(signer: &SignerInfo) -> String {
    let digest = asn::digest_name(&signer.digest_alg).unwrap_or("?");
    let names = [(asn::RSA_ENCRYPTION, "RSA"), (asn::RSASSA_PSS, "RSA-PSS"),
                 (asn::ED25519, "Ed25519"), (asn::ED448, "Ed448"), (asn::ID_DSA, "DSA"),
                 (asn::EC_PUBLIC_KEY, "ECDSA")];
    let name = names.iter().find(|(o, _)| signer.sig_alg.is(o)).map(|(_, n)| *n)
        .unwrap_or_else(|| {
            let ecdsa = [asn::ECDSA_WITH_SHA1, asn::ECDSA_WITH_SHA224, asn::ECDSA_WITH_SHA256,
                         asn::ECDSA_WITH_SHA384, asn::ECDSA_WITH_SHA512];
            let dsa = [asn::DSA_WITH_SHA1, asn::DSA_WITH_SHA224, asn::DSA_WITH_SHA256,
                       asn::DSA_WITH_SHA384, asn::DSA_WITH_SHA512];
            if ecdsa.iter().any(|o| signer.sig_alg.is(o)) { "ECDSA" }
            else if dsa.iter().any(|o| signer.sig_alg.is(o)) { "DSA" }
            else { "RSA" }
        });
    format!("{name} {digest}")
}

fn verify_one(sd: &SignedData, signer: &SignerInfo, content: &[u8], cert: &Certificate,
              pool: &[Certificate], policy: &Policy, signing_time: &mut Option<i64>)
              -> Result<(), String> {
    let digest_name = asn::digest_name(&signer.digest_alg)?;
    let signed: Vec<u8> = match &signer.signed_attrs {
        None => {
            if !asn::is(&sd.content_type, asn::DATA) {
                return Err("Content other than data must be signed with attributes \
                            (RFC 5652 5.3).".to_string());
            }
            content.to_vec()
        }
        Some(attrs) => {
            let attributes = asn::read_attributes(attrs)?;
            let content_type = asn::single(&attributes, asn::CONTENT_TYPE)?
                .ok_or("The signed attributes have no content type.")?;
            if Reader::new(content_type).read_oid()?.as_bytes() != sd.content_type.as_slice() {
                return Err("The signed content type is not the content's type.".to_string());
            }
            let digest = asn::single(&attributes, asn::MESSAGE_DIGEST)?
                .ok_or("The signed attributes have no message digest.")?;
            let mut d = Reader::new(digest);
            if d.read_octet_string()? != asn::digest(digest_name, content)?.as_slice() {
                return Err("The content's digest is not the one that was signed: the content \
                            has changed.".to_string());
            }
            if let Some(time) = asn::single(&attributes, asn::SIGNING_TIME)? {
                *signing_time = Some(Reader::new(time).read_time()?);
            }
            // The signature is over the attributes' DER with the SET OF
            // tag (RFC 5652 5.4), not the [0] they travel under.
            let mut w = Writer::new();
            w.write_tlv(Tag::set(), attrs);
            w.finish()
        }
    };
    check_signature(cert, pool, digest_name, &signer.sig_alg, &signed, &signer.signature, policy)
}

/// RSASSA-PSS-params (RFC 4055 3.1): the hash, MGF1's hash and the salt
/// length, defaults applied.
fn pss_params(alg: &AlgId) -> Result<(&'static str, &'static str, usize), String> {
    let mut hash = "sha1";
    let mut mgf = "sha1";
    let mut salt = 20usize;
    if let Some(params) = &alg.params {
        let mut r = Reader::new(params);
        let mut seq = r.read_sequence()?;
        if let Some(h) = seq.read_optional_context(0, true)? {
            hash = asn::digest_name(&AlgId::read(&mut Reader::new(h))?)?;
        }
        if let Some(m) = seq.read_optional_context(1, true)? {
            let mgf_alg = AlgId::read(&mut Reader::new(m))?;
            if !mgf_alg.is(asn::MGF1) {
                return Err("RSA-PSS with a mask generation function other than MGF1."
                           .to_string());
            }
            mgf = asn::digest_name(&AlgId::read(&mut mgf_alg.params_reader()?)?)?;
        }
        if let Some(s) = seq.read_optional_context(2, true)? {
            salt = Reader::new(s).read_u32()? as usize;
        }
        if let Some(t) = seq.read_optional_context(3, true)? {
            if Reader::new(t).read_u32()? != 1 {
                return Err("RSA-PSS with a trailer field other than 1.".to_string());
            }
        }
        seq.finish()?;
    }
    Ok((hash, mgf, salt))
}

pub fn pss_alg(hash: &str) -> Result<AlgId, String> {
    let hash_alg = asn::digest_alg(hash)?;
    let salt = asn::digest(hash, b"")?.len() as u32;
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_constructed(Tag::context(0, true), |w| hash_alg.write(w));
        w.write_constructed(Tag::context(1, true), |w| {
            AlgId::with_params(asn::MGF1, hash_alg.to_der()).write(w);
        });
        w.write_constructed(Tag::context(2, true), |w| w.write_u32(salt));
    });
    Ok(AlgId::with_params(asn::RSASSA_PSS, w.finish()))
}

fn check_signature(cert: &Certificate, pool: &[Certificate], digest_name: &'static str,
                   sig_alg: &AlgId, signed: &[u8], signature: &[u8], policy: &Policy)
                   -> Result<(), String> {
    if sig_alg.is(asn::RSASSA_PSS) {
        let (hash, mgf, salt) = pss_params(sig_alg)?;
        if hash != digest_name || mgf != hash {
            return Err(format!("RSA-PSS over {hash} with MGF1-{mgf}, in a signer that \
                                digests with {digest_name}: only one hash throughout is \
                                supported."));
        }
        policy.accepts_hash_public(hash)?;
        let PublicKey::Rsa { n, e } = &cert.public_key else {
            return Err("An RSA-PSS signature from a certificate without an RSA key."
                       .to_string());
        };
        let key = RsaPublicKey::new(n.clone(), e.clone())?;
        let digest = asn::digest(hash, signed)?;
        return if rsa::verify_pss(&key, hash, &digest, signature, salt)? {
            Ok(())
        } else {
            Err("The signature does not verify.".to_string())
        };
    }
    let rsa = [(asn::RSA_ENCRYPTION, None), (asn::MD5_WITH_RSA, Some("md5")),
               (asn::SHA1_WITH_RSA, Some("sha1")), (asn::SHA224_WITH_RSA, Some("sha224")),
               (asn::SHA256_WITH_RSA, Some("sha256")), (asn::SHA384_WITH_RSA, Some("sha384")),
               (asn::SHA512_WITH_RSA, Some("sha512"))];
    let ecdsa = [(asn::EC_PUBLIC_KEY, None), (asn::ECDSA_WITH_SHA1, Some("sha1")),
                 (asn::ECDSA_WITH_SHA224, Some("sha224")), (asn::ECDSA_WITH_SHA256, Some("sha256")),
                 (asn::ECDSA_WITH_SHA384, Some("sha384")), (asn::ECDSA_WITH_SHA512, Some("sha512"))];
    let dsa = [(asn::ID_DSA, None), (asn::DSA_WITH_SHA1, Some("sha1")),
               (asn::DSA_WITH_SHA224, Some("sha224")), (asn::DSA_WITH_SHA256, Some("sha256")),
               (asn::DSA_WITH_SHA384, Some("sha384")), (asn::DSA_WITH_SHA512, Some("sha512"))];
    fn named(table: &[(&str, Option<&'static str>)], alg: &AlgId) -> Option<Option<&'static str>> {
        table.iter().find(|(o, _)| alg.is(o)).map(|(_, h)| *h)
    }
    let named = |table: &[(&str, Option<&'static str>)]| named(table, sig_alg);
    let (algorithm, hash) = if let Some(hash) = named(&rsa) {
        (SignatureAlgorithm::RsaPkcs1(digest_name), hash)
    } else if let Some(hash) = named(&ecdsa) {
        (SignatureAlgorithm::Ecdsa(digest_name), hash)
    } else if let Some(hash) = named(&dsa) {
        (SignatureAlgorithm::Dsa(digest_name), hash)
    } else if sig_alg.is(asn::ED25519) {
        (SignatureAlgorithm::Eddsa("ed25519"), None)
    } else if sig_alg.is(asn::ED448) {
        (SignatureAlgorithm::Eddsa("ed448"), None)
    } else {
        return Err(format!("Signature algorithm {} is not one this verifies.",
                           asn::dotted(&sig_alg.oid)));
    };
    if hash.is_some_and(|h| h != digest_name) {
        return Err(format!("The signature algorithm names {} and the signer digests with \
                            {digest_name}.", hash.unwrap_or("?")));
    }
    let key = inherit_dsa_parameters(cert, pool)?;
    verify::verify_signed(signed, algorithm, signature, &key, policy)
        .map_err(|e| format!("The signature does not verify: {e}"))
}

/// A DSA certificate may leave its group out and use its issuer's
/// (RFC 3279 2.3.2), as RFC 4134's Diane does.
fn inherit_dsa_parameters<'a>(cert: &Certificate<'a>, pool: &[Certificate<'a>])
                              -> Result<PublicKey<'a>, String> {
    if let PublicKey::Dsa { parameters: None, y } = &cert.public_key {
        let issuer = pool.iter().find(|c| c.is_issuer_of(cert))
            .ok_or("A DSA key that inherits its group, from an issuer not in the message.")?;
        let PublicKey::Dsa { parameters: Some(p), .. } = &issuer.public_key else {
            return Err("A DSA key whose issuer has no DSA group to inherit.".to_string());
        };
        return Ok(PublicKey::Dsa { parameters: Some(p.clone()), y: y.clone() });
    }
    Ok(clone_key(&cert.public_key))
}

fn clone_key<'a>(key: &PublicKey<'a>) -> PublicKey<'a> {
    match key {
        PublicKey::Rsa { n, e } => PublicKey::Rsa { n: n.clone(), e: e.clone() },
        PublicKey::Ec { curve, point } => PublicKey::Ec { curve, point },
        PublicKey::Eddsa { curve, key } => PublicKey::Eddsa { curve, key },
        PublicKey::Dsa { parameters, y } =>
            PublicKey::Dsa { parameters: parameters.clone(), y: y.clone() },
        PublicKey::MlDsa { parameter_set, key } => PublicKey::MlDsa { parameter_set, key },
        PublicKey::UnsupportedCurve { oid, family } =>
            PublicKey::UnsupportedCurve { oid: *oid, family },
        PublicKey::Unsupported { algorithm } => PublicKey::Unsupported { algorithm },
        PublicKey::Gost { curve, x, y, param_set, algorithm_id, legacy } => PublicKey::Gost {
            curve, x: x.clone(), y: y.clone(), param_set: *param_set, algorithm_id,
            legacy: *legacy },
    }
}

// ------------------------------------------------------------------ signing --

pub struct SignOptions {
    pub hash: String,
    pub attributes: bool,
    pub detached: bool,
    pub key_id: bool,
    pub pss: bool,
    pub now: i64,
}

pub struct Signer<'a> {
    pub certificate: &'a [u8],
    pub key: &'a Key,
}

/// UTCTime from 1950 to 2049, GeneralizedTime otherwise (RFC 5652 11.3).
pub fn write_time(w: &mut Writer, seconds: i64) {
    let full = allcrypt::asn1::format_time(seconds);
    let year: i64 = full[..4].parse().unwrap_or(0);
    if (1950..2050).contains(&year) {
        w.write_tlv(Tag::universal(tag::UTC_TIME), &full.as_bytes()[2..]);
    } else {
        w.write_tlv(Tag::universal(tag::GENERALIZED_TIME), full.as_bytes());
    }
}

/// A SignedData ContentInfo over `content`.
pub fn sign(content: &[u8], signers: &[Signer], extra_certs: &[Vec<u8>], options: &SignOptions)
            -> Result<Vec<u8>, String> {
    let mut digest_algs = Vec::new();
    let mut infos = Vec::new();
    let mut any_key_id = false;
    for signer in signers {
        let cert = Certificate::parse(signer.certificate)?;
        let hash = match signer.key {
            Key::Eddsa { name, .. } if *name == "ed25519" => "sha512".to_string(),
            Key::Eddsa { .. } => if options.attributes { "shake256-512" }
                                 else { "shake256" }.to_string(),
            _ => options.hash.clone(),
        };
        let digest_alg = if hash == "shake256" { AlgId::new(asn::SHAKE256) }
                         else { asn::digest_alg(&hash)? };
        let (sig_alg, pss) = match signer.key {
            Key::Rsa(_) if options.pss => (pss_alg(&hash)?, true),
            Key::Rsa(_) => (AlgId::with_null(asn::RSA_ENCRYPTION), false),
            Key::Ec { .. } => (AlgId::new(match hash.as_str() {
                "sha1" => asn::ECDSA_WITH_SHA1, "sha224" => asn::ECDSA_WITH_SHA224,
                "sha256" => asn::ECDSA_WITH_SHA256, "sha384" => asn::ECDSA_WITH_SHA384,
                "sha512" => asn::ECDSA_WITH_SHA512,
                other => return Err(format!("ECDSA with {other} has no identifier here.")),
            }), false),
            Key::Dsa(_) => (AlgId::new(match hash.as_str() {
                "sha1" => asn::DSA_WITH_SHA1, "sha224" => asn::DSA_WITH_SHA224,
                "sha256" => asn::DSA_WITH_SHA256, "sha384" => asn::DSA_WITH_SHA384,
                "sha512" => asn::DSA_WITH_SHA512,
                other => return Err(format!("DSA with {other} has no identifier here.")),
            }), false),
            Key::Eddsa { name, .. } =>
                (AlgId::new(if *name == "ed25519" { asn::ED25519 } else { asn::ED448 }), false),
        };
        let sid = if options.key_id {
            any_key_id = true;
            CertId::KeyId(cert.extensions.subject_key_id
                .ok_or("--keyid needs certificates with a subject key identifier.")?.to_vec())
        } else {
            CertId::IssuerSerial(IssuerSerial::of(&cert))
        };
        let (signed_attrs, to_sign) = if options.attributes {
            let mut ct = Writer::new();
            ct.write_oid(&asn::oid(asn::DATA));
            let mut time = Writer::new();
            write_time(&mut time, options.now);
            let mut md = Writer::new();
            md.write_octet_string(&asn::digest(&hash, content)?);
            let set = asn::der_set_of(vec![
                asn::attribute(asn::CONTENT_TYPE, ct.finish()),
                asn::attribute(asn::SIGNING_TIME, time.finish()),
                asn::attribute(asn::MESSAGE_DIGEST, md.finish()),
            ], 0x31);
            let mut r = Reader::new(&set);
            let inner = r.read_tagged(Tag::set())?.to_vec();
            (Some(inner), set)
        } else {
            (None, content.to_vec())
        };
        let signature = if pss {
            let Key::Rsa(key) = signer.key else { unreachable!() };
            let digest = asn::digest(&hash, &to_sign)?;
            rsa::sign_pss(key, &hash, &digest, digest.len())?
        } else {
            match signer.key {
                Key::Eddsa { .. } => signer.key.signing().sign_signed_data(&hash, &to_sign)?,
                _ => signer.key.signing().sign(&hash, &to_sign)?,
            }
        };
        let version = if matches!(sid, CertId::KeyId(_)) { 3 } else { 1 };
        let mut w = Writer::new();
        w.write_sequence(|w| {
            w.write_u32(version);
            write_cert_id(w, &sid);
            digest_alg.write(w);
            if let Some(attrs) = &signed_attrs {
                w.write_tlv(Tag::context(0, true), attrs);
            }
            sig_alg.write(w);
            w.write_octet_string(&signature);
        });
        infos.push(w.finish());
        let alg_der = digest_alg.to_der();
        if !digest_algs.contains(&alg_der) {
            digest_algs.push(alg_der);
        }
    }
    let mut certs: Vec<Vec<u8>> = signers.iter().map(|s| s.certificate.to_vec())
        .chain(extra_certs.iter().cloned()).collect();
    certs.dedup();
    let version = if any_key_id { 3 } else { 1 };
    let mut body = Writer::new();
    body.write_sequence(|w| {
        w.write_u32(version);
        w.write_raw(&asn::der_set_of(digest_algs, 0x31));
        write_encapsulated(w, asn::DATA, (!options.detached).then_some(content));
        w.write_raw(&asn::der_set_of(certs, 0xa0));
        w.write_raw(&asn::der_set_of(infos, 0x31));
    });
    Ok(content_info(asn::SIGNED_DATA, &body.finish()))
}

/// ContentInfo: the type and `[0] EXPLICIT` content.
pub fn content_info(content_type: &str, content: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_oid(&asn::oid(content_type));
        w.write_constructed(Tag::context(0, true), |w| w.write_raw(content));
    });
    w.finish()
}
