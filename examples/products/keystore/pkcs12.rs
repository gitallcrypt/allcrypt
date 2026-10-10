//! PKCS#12 (RFC 7292): the `.p12` / `.pfx` file every browser, OpenSSL
//! and Java exchange keys in.
//!
//! A PFX holds an "authenticated safe": a list of ContentInfos, each a
//! list of bags either in the clear (`data`) or encrypted as a whole
//! (`encryptedData`). Bags hold a private key - plain, or "shrouded" in
//! a PKCS#8 EncryptedPrivateKeyInfo - a certificate, a CRL or a secret,
//! with a friendly name and a local key ID tying a key to its
//! certificate. A MAC over the authenticated safe, from the same
//! password, guards it.
//!
//! The ciphers are the PKCS#12 PBE family - SHA-1 with 3DES or RC2, the
//! notorious 40-bit RC2 that Windows and OpenSSL wrote for certificates
//! for twenty years - and PBES2, which modern OpenSSL and Java write
//! (PBKDF2 with AES-256-CBC). The MAC is HMAC under a key from the
//! PKCS#12 KDF, or PBMAC1 (RFC 9579): HMAC under a key from PBKDF2.
//!
//! Reading and encrypting both go through the library's
//! `x509::encrypted_key`, which knows every scheme.
//!
//! The PKCS#12 schemes hash the password as a BMPString - UTF-16, big
//! endian, with a terminating NUL - and PBES2 and PBMAC1 hash its UTF-8.
//! An empty password is ambiguous: OpenSSL hashes no bytes at all where
//! others hash the NUL alone, so reading tries both.

use allcrypt::asn1::{self, tag, Reader, Tag, Writer};
use allcrypt::hash_functions::HashFunction;
use allcrypt::kdf::password::{pkcs12_bmp_password, pkcs12_kdf, Pkcs12Purpose};
use allcrypt::x509::encrypted_key;

// Object identifiers. The PKCS#12 ones are checked against
// rfcs/rfc7292.txt by a test; the PKCS#7 and PKCS#9 ones come from
// RFC 2315 and RFC 2985, which every witness reads.
pub const DATA: &str = "1.2.840.113549.1.7.1";
pub const ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";
pub const KEY_BAG: &str = "1.2.840.113549.1.12.10.1.1";
pub const SHROUDED_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
pub const CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
pub const CRL_BAG: &str = "1.2.840.113549.1.12.10.1.4";
pub const SECRET_BAG: &str = "1.2.840.113549.1.12.10.1.5";
pub const SAFE_CONTENTS_BAG: &str = "1.2.840.113549.1.12.10.1.6";
pub const PBE_SHA1_3DES: &str = "1.2.840.113549.1.12.1.3";
pub const PBE_SHA1_RC2_40: &str = "1.2.840.113549.1.12.1.6";
pub const X509_CERTIFICATE: &str = "1.2.840.113549.1.9.22.1";
pub const X509_CRL: &str = "1.2.840.113549.1.9.23.1";
pub const FRIENDLY_NAME: &str = "1.2.840.113549.1.9.20";
pub const LOCAL_KEY_ID: &str = "1.2.840.113549.1.9.21";
pub const PBES2: &str = "1.2.840.113549.1.5.13";
pub const PBKDF2: &str = "1.2.840.113549.1.5.12";
pub const PBMAC1: &str = "1.2.840.113549.1.5.14";
pub const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";

/// The hashes a MAC or a PRF may name, by OID: (dotted digest OID,
/// dotted HMAC OID, the library's name).
const HASHES: [(&str, &str, &str); 6] = [
    ("1.3.14.3.2.26", "1.2.840.113549.2.7", "sha1"),
    ("2.16.840.1.101.3.4.2.4", "1.2.840.113549.2.8", "sha224"),
    ("2.16.840.1.101.3.4.2.1", "1.2.840.113549.2.9", "sha256"),
    ("2.16.840.1.101.3.4.2.2", "1.2.840.113549.2.10", "sha384"),
    ("2.16.840.1.101.3.4.2.3", "1.2.840.113549.2.11", "sha512"),
    ("1.2.840.113549.2.5", "", "md5"),
];

pub fn oid(dotted: &str) -> Vec<u8> {
    asn1::encode_oid(dotted).expect("a well-formed OID")
}

fn dotted(der: &[u8]) -> String {
    asn1::Oid::new(der).map(|o| o.to_string()).unwrap_or_else(|_| "?".to_string())
}

fn is(found: &asn1::Oid, dotted: &str) -> bool {
    found.as_bytes() == oid(dotted).as_slice()
}

fn integer(reader: &mut Reader) -> Result<u64, String> {
    let bytes = reader.read_integer_bytes()?;
    if bytes.len() > 8 {
        return Err("An integer too large for this field.".to_string());
    }
    Ok(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

/// The bytes of an OCTET STRING, or of a `[0] IMPLICIT` one, which BER
/// writers may have built from pieces.
fn octets(content: &[u8], constructed: bool) -> Result<Vec<u8>, String> {
    if !constructed {
        return Ok(content.to_vec());
    }
    let mut pieces = Reader::new(content);
    let mut out = Vec::new();
    while !pieces.is_empty() {
        out.extend_from_slice(pieces.read_octet_string()?);
    }
    Ok(out)
}

// ---------------------------------------------------------------- model --

#[derive(Clone, PartialEq)]
pub enum Kind {
    /// A PKCS#8 PrivateKeyInfo, decrypted if it was shrouded.
    Key { pkcs8: Vec<u8>, shrouded: bool },
    Certificate(Vec<u8>),
    Crl(Vec<u8>),
    /// A secret bag: its type OID, and the value - decrypted, when the
    /// type says it is a shrouded key bag, as Java writes secret keys.
    Secret { kind: String, value: Vec<u8> },
}

impl std::fmt::Debug for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::hidden::HiddenBytes;
        match self {
            Kind::Key { pkcs8, shrouded } => f.debug_struct("Key")
                .field("pkcs8", &HiddenBytes(pkcs8)).field("shrouded", shrouded).finish(),
            Kind::Certificate(der) => f.debug_tuple("Certificate").field(der).finish(),
            Kind::Crl(der) => f.debug_tuple("Crl").field(der).finish(),
            Kind::Secret { kind, value } => f.debug_struct("Secret")
                .field("kind", kind).field("value", &HiddenBytes(value)).finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bag {
    pub kind: Kind,
    pub friendly_name: Option<String>,
    pub local_key_id: Option<Vec<u8>>,
    /// Other attributes, by dotted OID: Java's trusted-certificate
    /// marker, say.
    pub other_attributes: Vec<String>,
}

/// What opening a file found besides the bags.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// The MAC and what it was, if there was one.
    pub mac: Option<String>,
    /// How each encrypted part was protected, in order.
    pub schemes: Vec<String>,
}

// -------------------------------------------------------------- reading --

/// The password forms to try: as given, and for the empty password,
/// also no bytes at all - RFC 7292's BMPString of it is the two-byte
/// terminator, but OpenSSL's API given a NULL password hashes nothing,
/// and its own reader tries that first.
fn bmp_candidates(password: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text = std::str::from_utf8(password).map_err(|_| "The password is not UTF-8.")?;
    let mut out = vec![pkcs12_bmp_password(text)];
    if text.is_empty() {
        out.push(Vec::new());
    }
    Ok(out)
}

fn hash_by_oid(found: &[u8], hmac: bool) -> Result<&'static str, String> {
    HASHES.iter().find(|(digest, mac, _)| {
        let wanted = if hmac { *mac } else { *digest };
        !wanted.is_empty() && found == oid(wanted).as_slice()
    }).map(|h| h.2).ok_or_else(|| format!("Hash {} is not supported.", dotted(found)))
}

/// PBKDF2's parameters.
struct Pbkdf2 {
    salt: Vec<u8>,
    iterations: u32,
    key_length: Option<usize>,
    prf: &'static str,
}

fn pbkdf2_parameters(parameters: &[u8]) -> Result<Pbkdf2, String> {
    let mut p = Reader::new(parameters).read_sequence()?;
    let salt = p.read_octet_string()?.to_vec();
    let iterations = u32::try_from(integer(&mut p)?)
        .map_err(|_| "A PBKDF2 iteration count over 2^32.".to_string())?;
    let mut key_length = None;
    if p.peek_tag() == Some(Tag::universal(tag::INTEGER)) {
        key_length = Some(integer(&mut p)? as usize);
    }
    let prf = if p.is_empty() { "sha1" } else {
        let mut algorithm = p.read_sequence()?;
        hash_by_oid(algorithm.read_oid()?.as_bytes(), true)?
    };
    Ok(Pbkdf2 { salt, iterations, key_length, prf })
}

/// Check the MAC, returning a description of it.
fn check_mac(mac_data: &[u8], content: &[u8], password: &[u8]) -> Result<String, String> {
    let mut m = Reader::new(mac_data);
    let mut digest_info = m.read_sequence()?;
    let mut algorithm = digest_info.read_sequence()?;
    let algorithm_oid = algorithm.read_oid()?;
    let expected = digest_info.read_octet_string()?.to_vec();
    let salt = m.read_octet_string()?.to_vec();
    let iterations = if m.is_empty() { 1 } else {
        u32::try_from(integer(&mut m)?).map_err(|_| "A MAC iteration count over 2^32.")?
    };
    if is(&algorithm_oid, PBMAC1) {
        // RFC 9579: the parameters name PBKDF2 and an HMAC; MacData's own
        // salt and count are not used.
        let mut params = algorithm.read_sequence()?;
        let mut kdf = params.read_sequence()?;
        if !is(&kdf.read_oid()?, PBKDF2) {
            return Err("PBMAC1 with a key derivation other than PBKDF2.".to_string());
        }
        let Pbkdf2 { salt: kdf_salt, iterations: kdf_iterations, key_length, prf } =
            pbkdf2_parameters(kdf.remaining())?;
        let mut scheme = params.read_sequence()?;
        let hmac = hash_by_oid(scheme.read_oid()?.as_bytes(), true)?;
        let key_length = key_length.ok_or("PBMAC1 needs a key length.")?;
        let key = allcrypt::api::pbkdf2(prf, password, &kdf_salt, kdf_iterations, key_length)?;
        if allcrypt::api::hmac(hmac, &key, content)? != expected {
            return Err("Wrong password, or the file was changed: the MAC does not match."
                .to_string());
        }
        return Ok(format!("PBMAC1, HMAC-{} under PBKDF2-HMAC-{} x {kdf_iterations}",
                          hmac.to_uppercase(), prf.to_uppercase()));
    }
    let hash = hash_by_oid(algorithm_oid.as_bytes(), false)?;
    for bmp in bmp_candidates(password)? {
        let key = pkcs12_kdf(allcrypt::api::AnyHash::new(hash)?, &bmp, &salt,
                             Pkcs12Purpose::Mac, iterations, expected.len())?;
        if allcrypt::api::hmac(hash, &key, content)? == expected {
            return Ok(format!("HMAC-{} x {iterations}", hash.to_uppercase()));
        }
    }
    Err("Wrong password, or the file was changed: the MAC does not match.".to_string())
}

/// Decrypt through the library: an EncryptedPrivateKeyInfo is an
/// algorithm and an OCTET STRING, which is exactly what an encrypted
/// safe carries too. The library tries the empty password both ways.
fn decrypt(algorithm: &[u8], ciphertext: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_raw(algorithm);
        w.write_octet_string(ciphertext);
    });
    encrypted_key::decrypt(&w.finish(), password)
}

/// A description of an encryption AlgorithmIdentifier.
fn describe(algorithm: &[u8]) -> String {
    let mut r = Reader::new(algorithm);
    let Ok(mut a) = r.read_sequence() else { return "?".to_string() };
    let Ok(scheme) = a.read_oid() else { return "?".to_string() };
    let scheme = scheme.to_string();
    let name = match scheme.as_str() {
        PBE_SHA1_3DES => "PBE-SHA1-3DES".to_string(),
        PBE_SHA1_RC2_40 => "PBE-SHA1-RC2-40".to_string(),
        "1.2.840.113549.1.12.1.1" => "PBE-SHA1-RC4-128".to_string(),
        "1.2.840.113549.1.12.1.2" => "PBE-SHA1-RC4-40".to_string(),
        "1.2.840.113549.1.12.1.4" => "PBE-SHA1-2DES".to_string(),
        "1.2.840.113549.1.12.1.5" => "PBE-SHA1-RC2-128".to_string(),
        PBES2 => "PBES2".to_string(),
        other => other.to_string(),
    };
    let mut params = Reader::new(a.remaining());
    match params.read_sequence() {
        Ok(mut p) if scheme == PBES2 => {
            let detail = (|| -> Result<String, String> {
                let mut kdf = p.read_sequence()?;
                kdf.read_oid()?;
                let Pbkdf2 { iterations, prf, .. } = pbkdf2_parameters(kdf.remaining())?;
                let mut cipher = p.read_sequence()?;
                let cipher = cipher.read_oid()?.to_string();
                let cipher = if cipher == AES256_CBC { "AES-256-CBC".to_string() } else { cipher };
                Ok(format!("{name}, PBKDF2-HMAC-{} x {iterations}, {cipher}",
                           prf.to_uppercase()))
            })();
            detail.unwrap_or(name)
        }
        Ok(mut p) => {
            let _ = p.read_octet_string();
            match integer(&mut p) {
                Ok(iterations) => format!("{name} x {iterations}"),
                Err(_) => name,
            }
        }
        Err(_) => name,
    }
}

fn attributes(set: Option<&[u8]>, bag: &mut Bag) -> Result<(), String> {
    let Some(set) = set else { return Ok(()) };
    let mut set = Reader::new(set);
    while !set.is_empty() {
        let mut attribute = set.read_sequence()?;
        let kind = attribute.read_oid()?;
        let mut values = attribute.read_set()?;
        if is(&kind, FRIENDLY_NAME) {
            let (_, text) = values.read_string()?;
            let units: Vec<u16> = text.chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            bag.friendly_name = Some(String::from_utf16_lossy(&units));
        } else if is(&kind, LOCAL_KEY_ID) {
            bag.local_key_id = Some(values.read_octet_string()?.to_vec());
        } else {
            bag.other_attributes.push(kind.to_string());
        }
    }
    Ok(())
}

fn safe_contents(der: &[u8], password: &[u8], report: &mut Report, out: &mut Vec<Bag>,
                 depth: usize) -> Result<(), String> {
    if depth > 8 {
        return Err("Safe contents nested more than 8 deep.".to_string());
    }
    // Each layer is an OCTET STRING's content, which the outer pass
    // leaves alone, so each may be BER again.
    let der = crate::ber::to_der(der)?;
    let mut outer = Reader::new(&der);
    let mut bags = outer.read_sequence()?;
    while !bags.is_empty() {
        let mut bag = bags.read_sequence()?;
        let kind = bag.read_oid()?;
        let value = bag.read_tagged(Tag::context(0, true))?;
        let attribute_set = if bag.is_empty() { None } else { Some(bag.read_tagged(Tag::set())?) };
        let mut value = Reader::new(value);
        let kind = if is(&kind, KEY_BAG) {
            Kind::Key { pkcs8: value.read_raw()?.to_vec(), shrouded: false }
        } else if is(&kind, SHROUDED_KEY_BAG) {
            let mut epki = value.read_sequence()?;
            let algorithm = epki.read_raw()?;
            let ciphertext = epki.read_octet_string()?;
            report.schemes.push(format!("key: {}", describe(algorithm)));
            let pkcs8 = key_info(&decrypt(algorithm, ciphertext, password)?)?;
            Kind::Key { pkcs8, shrouded: true }
        } else if is(&kind, CERT_BAG) || is(&kind, CRL_BAG) {
            let mut inner = value.read_sequence()?;
            let kind_oid = inner.read_oid()?;
            let mut content = Reader::new(inner.read_tagged(Tag::context(0, true))?);
            let der = content.read_octet_string()?.to_vec();
            if is(&kind_oid, X509_CERTIFICATE) {
                Kind::Certificate(der)
            } else if is(&kind_oid, X509_CRL) {
                Kind::Crl(der)
            } else {
                return Err(format!("A certificate or CRL of type {}.", kind_oid));
            }
        } else if is(&kind, SECRET_BAG) {
            let mut inner = value.read_sequence()?;
            let kind_oid = inner.read_oid()?;
            let mut content = Reader::new(inner.read_tagged(Tag::context(0, true))?);
            let raw = content.read_raw()?;
            let value = if is(&kind_oid, SHROUDED_KEY_BAG) {
                // Java's secret keys: a PrivateKeyInfo-shaped structure
                // around the key, shrouded like a private key, the whole
                // in an OCTET STRING.
                let inner = Reader::new(raw).read_octet_string()?;
                let mut epki = Reader::new(inner).read_sequence()?;
                let algorithm = epki.read_raw()?;
                let ciphertext = epki.read_octet_string()?;
                report.schemes.push(format!("secret: {}", describe(algorithm)));
                key_info(&decrypt(algorithm, ciphertext, password)?)?
            } else {
                raw.to_vec()
            };
            Kind::Secret { kind: kind_oid.to_string(), value }
        } else if is(&kind, SAFE_CONTENTS_BAG) {
            safe_contents(value.read_raw()?, password, report, out, depth + 1)?;
            continue;
        } else {
            return Err(format!("A bag of unknown type {kind}."));
        };
        let mut bag = Bag { kind, friendly_name: None, local_key_id: None,
                            other_attributes: Vec::new() };
        attributes(attribute_set, &mut bag)?;
        out.push(bag);
    }
    Ok(())
}

/// A decrypted key as DER, refused if it is not a PrivateKeyInfo. Without a MAC,
/// CBC padding is all that checks the password, and a wrong one passes
/// it about one time in 256; what comes out is then noise in the place
/// of a key. OpenSSL and Java both find that out by parsing it. Java's
/// secret keys are in the same shape and get the same check.
pub fn key_info(plain: &[u8]) -> Result<Vec<u8>, String> {
    let wrong = |_| "Wrong password: the decrypted key is not a PrivateKeyInfo.".to_string();
    // `to_der` refuses anything after the one element.
    let der = crate::ber::to_der(plain).map_err(wrong)?;
    let mut info = Reader::new(&der).read_sequence().map_err(wrong)?;
    info.read_integer_bytes().map_err(wrong)?;
    info.read_sequence().map_err(wrong)?;
    info.read_octet_string().map_err(wrong)?;
    Ok(der)
}

/// Open a PFX: check the MAC, decrypt everything, and list the bags in
/// the order they were stored.
pub fn open(data: &[u8], password: &[u8]) -> Result<(Vec<Bag>, Report), String> {
    let der = crate::ber::to_der(data)?;
    let mut outer = Reader::new(&der);
    let mut pfx = outer.read_sequence()?;
    outer.finish()?;
    if integer(&mut pfx)? != 3 {
        return Err("A PFX that is not version 3.".to_string());
    }
    let mut auth_safe = pfx.read_sequence()?;
    if !is(&auth_safe.read_oid()?, DATA) {
        return Err("A PFX signed with a public key (authSafe of type signedData) is not \
                    supported; only password integrity is.".to_string());
    }
    let mut wrapper = Reader::new(auth_safe.read_tagged(Tag::context(0, true))?);
    let content = wrapper.read_octet_string()?;
    let mut report = Report::default();
    if !pfx.is_empty() {
        report.mac = Some(check_mac(pfx.read_tagged(Tag::sequence())?, content, password)?);
    }
    let mut bags = Vec::new();
    // The MAC is over the content as written; the parse is over its DER.
    let content = crate::ber::to_der(content)?;
    let mut infos = Reader::new(&content).read_sequence()?;
    while !infos.is_empty() {
        let mut info = infos.read_sequence()?;
        let kind = info.read_oid()?;
        let mut body = Reader::new(info.read_tagged(Tag::context(0, true))?);
        if is(&kind, DATA) {
            safe_contents(body.read_octet_string()?, password, &mut report, &mut bags, 0)?;
        } else if is(&kind, ENCRYPTED_DATA) {
            let mut encrypted = body.read_sequence()?;
            integer(&mut encrypted)?;
            let mut content_info = encrypted.read_sequence()?;
            content_info.read_oid()?;
            let algorithm = content_info.read_raw()?;
            let (tag, ciphertext) = content_info.read_any()?;
            if tag.class != asn1::CLASS_CONTEXT || tag.number != 0 {
                return Err("EncryptedContentInfo without its [0] content.".to_string());
            }
            let ciphertext = octets(ciphertext, tag.constructed)?;
            report.schemes.push(format!("safe: {}", describe(algorithm)));
            let plain = decrypt(algorithm, &ciphertext, password)?;
            safe_contents(&plain, password, &mut report, &mut bags, 0)?;
        } else {
            return Err(format!("A safe of type {kind} (public-key privacy) is not supported."));
        }
    }
    Ok((bags, report))
}

// ------------------------------------------------------------ encrypting --

/// Encrypt under the PKCS#12 PBE: 3DES or 40-bit RC2 under SHA-1,
/// PKCS#7 padding. `bmp` is the password's BMPString. (The library
/// decrypts these; it has no encrypting side.)
/// A new encryption AlgorithmIdentifier for `scheme`, with fresh salt
/// (and IV), and the data encrypted under it: the library's
/// `encrypted_key::encrypt`, whose EncryptedPrivateKeyInfo is the
/// AlgorithmIdentifier and the ciphertext that a shrouded key bag and an
/// EncryptedData both carry.
pub fn seal(scheme: &str, iterations: u32, password: &[u8], data: &[u8])
            -> Result<(Vec<u8>, Vec<u8>), String> {
    let (name, prf, salt_len, iv_len) = match scheme {
        "3des" => ("pbe-sha1-3des", None, 8, 0),
        "rc2-40" => ("pbe-sha1-rc2-40", None, 8, 0),
        "aes-256" => ("aes-256-cbc", Some("sha256"), 16, 16),
        other => return Err(format!("Unknown scheme {other}: aes-256, 3des, rc2-40 or none.")),
    };
    let salt = allcrypt::api::random_bytes(salt_len)?;
    let iv = allcrypt::api::random_bytes(iv_len)?;
    let sealed = encrypted_key::encrypt(data, password, name, prf, iterations, &salt, &iv)?;
    let mut outer = Reader::new(&sealed);
    let mut info = outer.read_sequence()?;
    let algorithm = info.read_raw()?.to_vec();
    let ciphertext = info.read_octet_string()?.to_vec();
    Ok((algorithm, ciphertext))
}

pub struct Options {
    /// For shrouded keys: aes-256, 3des, rc2-40, or none for plain key bags.
    pub key_scheme: String,
    /// For the certificates' safe: the same, none leaving it in the clear.
    pub cert_scheme: String,
    /// sha1, sha256 (the PKCS#12 KDF), pbmac1 (PBKDF2 and HMAC-SHA-256),
    /// or none.
    pub mac: String,
    pub iterations: u32,
}

/// Java's mark on a trusted certificate: this attribute, holding the
/// "any" extended key usage. keytool lists a certificate bag without it
/// as nothing at all.
pub const ORACLE_TRUSTED_KEY_USAGE: &str = "2.16.840.1.113894.746875.1.1";

/// The secret-key algorithms Java names in a PKCS#12 secret bag, by the
/// name a `SecretKeySpec` carries and the OID `AlgorithmId.get` gives
/// it - transcribed from the JDK's `sun.security.util.KnownOIDs`, whose
/// lookup ignores case. Reading back, Java turns DES's and RC2's OIDs
/// into their bare names, so the names here are what it reads back.
pub const JAVA_SECRET_ALGORITHMS: &[(&str, &str)] = &[
    ("AES", "2.16.840.1.101.3.4.1"),
    ("DES", "1.3.14.3.2.7"),
    ("DESede", "1.3.14.3.2.17"),
    ("RC2", "1.2.840.113549.3.2"),
    ("ARCFOUR", "1.2.840.113549.3.4"),
    ("Blowfish", "1.3.6.1.4.1.3029.1.1.2"),
    ("HmacSHA1", "1.2.840.113549.2.7"),
    ("HmacSHA224", "1.2.840.113549.2.8"),
    ("HmacSHA256", "1.2.840.113549.2.9"),
    ("HmacSHA384", "1.2.840.113549.2.10"),
    ("HmacSHA512", "1.2.840.113549.2.11"),
    ("HmacSHA512/224", "1.2.840.113549.2.12"),
    ("HmacSHA512/256", "1.2.840.113549.2.13"),
    ("HmacSHA3-224", "2.16.840.1.101.3.4.2.13"),
    ("HmacSHA3-256", "2.16.840.1.101.3.4.2.14"),
    ("HmacSHA3-384", "2.16.840.1.101.3.4.2.15"),
    ("HmacSHA3-512", "2.16.840.1.101.3.4.2.16"),
];

/// Java's secret key as it goes into a secret bag before shrouding: a
/// PrivateKeyInfo-shaped `SEQUENCE { 0, AlgorithmIdentifier, OCTET
/// STRING key }`, the identifier with no parameters.
pub fn secret_key_info(algorithm: &str, key: &[u8]) -> Result<Vec<u8>, String> {
    let (_, dotted) = JAVA_SECRET_ALGORITHMS.iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(algorithm))
        .ok_or_else(|| format!("Java has no PKCS#12 identifier for a {algorithm} key."))?;
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_u32(0);
        w.write_sequence(|w| w.write_oid(&oid(dotted)));
        w.write_octet_string(key);
    });
    Ok(w.finish())
}

/// The other way: the algorithm's Java name and the key.
pub fn read_secret_key_info(info: &[u8]) -> Result<(String, Vec<u8>), String> {
    let mut outer = Reader::new(info);
    let mut seq = outer.read_sequence()?;
    outer.finish()?;
    if integer(&mut seq)? != 0 {
        return Err("A secret key of a version other than 0.".to_string());
    }
    let mut algorithm = seq.read_sequence()?;
    let dotted = algorithm.read_oid()?.to_string();
    let key = seq.read_octet_string()?.to_vec();
    seq.finish()?;
    let (name, _) = JAVA_SECRET_ALGORITHMS.iter().find(|(_, o)| *o == dotted)
        .ok_or_else(|| format!("A secret key of algorithm {dotted}, which Java does not name."))?;
    Ok((name.to_string(), key))
}
const ANY_EXTENDED_KEY_USAGE: &str = "2.5.29.37.0";

fn write_attributes(w: &mut Writer, bag: &Bag) {
    let trusted = bag.other_attributes.iter().any(|a| a == ORACLE_TRUSTED_KEY_USAGE);
    if bag.friendly_name.is_none() && bag.local_key_id.is_none() && !trusted {
        return;
    }
    w.write_set(|w| {
        if trusted {
            w.write_sequence(|w| {
                w.write_oid(&oid(ORACLE_TRUSTED_KEY_USAGE));
                w.write_set(|w| w.write_oid(&oid(ANY_EXTENDED_KEY_USAGE)));
            });
        }
        if let Some(name) = &bag.friendly_name {
            w.write_sequence(|w| {
                w.write_oid(&oid(FRIENDLY_NAME));
                w.write_set(|w| {
                    let bmp: Vec<u8> = name.encode_utf16().flat_map(u16::to_be_bytes).collect();
                    w.write_tlv(Tag::universal(tag::BMP_STRING), &bmp);
                });
            });
        }
        if let Some(id) = &bag.local_key_id {
            w.write_sequence(|w| {
                w.write_oid(&oid(LOCAL_KEY_ID));
                w.write_set(|w| w.write_octet_string(id));
            });
        }
    });
}

fn data_info(w: &mut Writer, content: &[u8]) {
    w.write_sequence(|w| {
        w.write_oid(&oid(DATA));
        w.write_constructed(Tag::context(0, true), |w| w.write_octet_string(content));
    });
}

/// Write a PFX holding `bags`: the keys in one clear safe of shrouded
/// (or plain) key bags, everything else in a second safe, encrypted as
/// a whole unless the scheme is none - the layout OpenSSL writes.
pub fn write(bags: &[Bag], password: &[u8], options: &Options) -> Result<Vec<u8>, String> {
    let mut keys = Writer::new();
    let mut others = Writer::new();
    let mut failure = None;
    keys.write_sequence(|w| {
        for bag in bags {
            // Java's secret keys, in the keys' safe as Java puts them:
            // shrouded like a key, the EncryptedPrivateKeyInfo in an
            // OCTET STRING inside the secret bag.
            if let Kind::Secret { kind, value } = &bag.kind {
                let shrouded = if kind != SHROUDED_KEY_BAG {
                    Ok(None)
                } else if options.key_scheme == "none" {
                    Err("A Java secret key is always shrouded; give a key scheme.".to_string())
                } else {
                    seal(&options.key_scheme, options.iterations, password, value).map(Some)
                };
                match shrouded {
                    Err(e) => failure = Some(e),
                    Ok(sealed) => w.write_sequence(|w| {
                        w.write_oid(&oid(SECRET_BAG));
                        w.write_constructed(Tag::context(0, true), |w| w.write_sequence(|w| {
                            w.write_oid(&oid(kind));
                            w.write_constructed(Tag::context(0, true), |w| match &sealed {
                                None => w.write_raw(value),
                                Some((algorithm, sealed)) => {
                                    let mut epki = Writer::new();
                                    epki.write_sequence(|w| {
                                        w.write_raw(algorithm);
                                        w.write_octet_string(sealed);
                                    });
                                    w.write_octet_string(&epki.finish());
                                }
                            });
                        }));
                        write_attributes(w, bag);
                    }),
                }
                continue;
            }
            if let Kind::Key { pkcs8, .. } = &bag.kind {
                w.write_sequence(|w| {
                    if options.key_scheme == "none" {
                        w.write_oid(&oid(KEY_BAG));
                        w.write_constructed(Tag::context(0, true), |w| w.write_raw(pkcs8));
                    } else {
                        match seal(&options.key_scheme, options.iterations, password, pkcs8) {
                            Ok((algorithm, sealed)) => {
                                w.write_oid(&oid(SHROUDED_KEY_BAG));
                                w.write_constructed(Tag::context(0, true), |w| {
                                    w.write_sequence(|w| {
                                        w.write_raw(&algorithm);
                                        w.write_octet_string(&sealed);
                                    });
                                });
                            }
                            Err(e) => failure = Some(e),
                        }
                    }
                    write_attributes(w, bag);
                });
            }
        }
    });
    others.write_sequence(|w| {
        for bag in bags {
            let (bag_type, inner_type, der) = match &bag.kind {
                Kind::Certificate(der) => (CERT_BAG, X509_CERTIFICATE, der),
                Kind::Crl(der) => (CRL_BAG, X509_CRL, der),
                Kind::Key { .. } | Kind::Secret { .. } => continue,
            };
            w.write_sequence(|w| {
                w.write_oid(&oid(bag_type));
                w.write_constructed(Tag::context(0, true), |w| {
                    w.write_sequence(|w| {
                        w.write_oid(&oid(inner_type));
                        w.write_constructed(Tag::context(0, true), |w| w.write_octet_string(der));
                    });
                });
                write_attributes(w, bag);
            });
        }
    });
    if let Some(e) = failure {
        return Err(e);
    }
    let (keys, others) = (keys.finish(), others.finish());
    let mut safe = Writer::new();
    let mut sealed_others = None;
    if options.cert_scheme != "none" {
        sealed_others = Some(seal(&options.cert_scheme, options.iterations, password, &others)?);
    }
    safe.write_sequence(|w| {
        data_info(w, &keys);
        match &sealed_others {
            None => data_info(w, &others),
            Some((algorithm, sealed)) => w.write_sequence(|w| {
                w.write_oid(&oid(ENCRYPTED_DATA));
                w.write_constructed(Tag::context(0, true), |w| {
                    w.write_sequence(|w| {
                        w.write_u32(0);
                        w.write_sequence(|w| {
                            w.write_oid(&oid(DATA));
                            w.write_raw(algorithm);
                            w.write_tlv(Tag::context(0, false), sealed);
                        });
                    });
                });
            }),
        }
    });
    let content = safe.finish();
    let mac = match options.mac.as_str() {
        "none" => None,
        "sha1" | "sha256" => {
            let hash = options.mac.as_str();
            let salt = allcrypt::api::random_bytes(8)?;
            let text = std::str::from_utf8(password).map_err(|_| "The password is not UTF-8.")?;
            let length = allcrypt::api::AnyHash::new(hash)?.digest_len();
            let key = pkcs12_kdf(allcrypt::api::AnyHash::new(hash)?, &pkcs12_bmp_password(text),
                                 &salt, Pkcs12Purpose::Mac, options.iterations, length)?;
            let value = allcrypt::api::hmac(hash, &key, &content)?;
            let digest_oid = HASHES.iter().find(|h| h.2 == hash).expect("listed").0;
            let mut w = Writer::new();
            w.write_sequence(|w| {
                w.write_sequence(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(&oid(digest_oid));
                        w.write_null();
                    });
                    w.write_octet_string(&value);
                });
                w.write_octet_string(&salt);
                w.write_u32(options.iterations);
            });
            Some(w.finish())
        }
        "pbmac1" => {
            let salt = allcrypt::api::random_bytes(16)?;
            let key = allcrypt::api::pbkdf2("sha256", password, &salt, options.iterations, 32)?;
            let value = allcrypt::api::hmac("sha256", &key, &content)?;
            let mut w = Writer::new();
            w.write_sequence(|w| {
                w.write_sequence(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(&oid(PBMAC1));
                        w.write_sequence(|w| {
                            w.write_sequence(|w| {
                                w.write_oid(&oid(PBKDF2));
                                w.write_sequence(|w| {
                                    w.write_octet_string(&salt);
                                    w.write_u32(options.iterations);
                                    w.write_u32(32);
                                    w.write_sequence(|w| {
                                        w.write_oid(&oid(HASHES[2].1));
                                        w.write_null();
                                    });
                                });
                            });
                            w.write_sequence(|w| {
                                w.write_oid(&oid(HASHES[2].1));
                                w.write_null();
                            });
                        });
                    });
                    w.write_octet_string(&value);
                });
                // RFC 9579: MacData's salt and count are set and ignored.
                w.write_octet_string(&salt);
                w.write_u32(options.iterations);
            });
            Some(w.finish())
        }
        other => return Err(format!("Unknown MAC {other}: sha1, sha256, pbmac1 or none.")),
    };
    let mut out = Writer::new();
    out.write_sequence(|w| {
        w.write_u32(3);
        data_info(w, &content);
        if let Some(mac) = &mac {
            w.write_raw(mac);
        }
    });
    Ok(out.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Every `name OBJECT IDENTIFIER ::= {...}` and `name BAG-TYPE ::=
    /// {Type IDENTIFIED BY {...}}` in an RFC's ASN.1, resolved to dotted
    /// form. A component is `name(n)`, a bare number, or - first only -
    /// a name defined elsewhere in the document. Page furniture is
    /// dropped first, since a definition can straddle a page break.
    fn rfc_oids(text: &str) -> HashMap<String, String> {
        let body: String = text.lines()
            .filter(|l| !l.contains("[Page ") && !l.starts_with("RFC "))
            .collect::<Vec<_>>().join(" ").replace('{', " { ").replace('}', " } ");
        let tokens: Vec<&str> = body.split_whitespace().collect();
        let mut definitions: Vec<(String, Vec<String>)> = Vec::new();
        for i in 0..tokens.len() {
            let start = if tokens[i..].starts_with(&["OBJECT", "IDENTIFIER", "::=", "{"]) {
                i + 4
            } else if tokens[i..].starts_with(&["BAG-TYPE", "::=", "{"])
                && tokens.get(i + 4..i + 7) == Some(&["IDENTIFIED", "BY", "{"][..]) {
                i + 7
            } else {
                continue;
            };
            let Some(length) = tokens[start..].iter().position(|t| *t == "}") else { continue };
            if i == 0 {
                continue;
            }
            definitions.push((tokens[i - 1].to_string(),
                              tokens[start..start + length].iter().map(|t| t.to_string())
                                  .collect()));
        }
        let mut resolved: HashMap<String, String> = HashMap::new();
        loop {
            let before = resolved.len();
            for (name, components) in &definitions {
                let mut arcs: Vec<String> = Vec::new();
                for (k, c) in components.iter().enumerate() {
                    let number = c.split_once('(').map(|(_, n)| n.trim_end_matches(')'))
                        .unwrap_or(c);
                    if number.bytes().all(|b| b.is_ascii_digit()) && !number.is_empty() {
                        arcs.push(number.to_string());
                    } else if k == 0 && resolved.contains_key(c.as_str()) {
                        arcs.push(resolved[c.as_str()].clone());
                    } else {
                        arcs.clear();
                        break;
                    }
                }
                if arcs.is_empty() {
                    continue;
                }
                let value = arcs.join(".");
                if let Some(old) = resolved.get(name) {
                    assert_eq!(old, &value, "{name} is defined twice, differently");
                }
                resolved.insert(name.clone(), value);
            }
            if resolved.len() == before {
                return resolved;
            }
        }
    }

    /// The PKCS#12 identifiers are RFC 7292's, and the PKCS#5 ones and
    /// the HMACs RFC 8018's, read out of the vendored documents rather
    /// than compared with a second typing.
    #[test]
    fn test_the_object_identifiers_are_the_rfcs() {
        let rfc7292 = rfc_oids(include_str!("../../../rfcs/rfc7292.txt"));
        let rfc8018 = rfc_oids(include_str!("../../../rfcs/rfc8018.txt"));
        // A parser that found nothing would pass every lookup below by
        // panicking on none of them - so count first.
        assert!(rfc7292.len() >= 16, "{rfc7292:?}");
        assert!(rfc8018.len() >= 20, "{rfc8018:?}");
        for (ours, name) in [(KEY_BAG, "keyBag"), (SHROUDED_KEY_BAG, "pkcs8ShroudedKeyBag"),
                             (CERT_BAG, "certBag"), (CRL_BAG, "crlBag"),
                             (SECRET_BAG, "secretBag"), (SAFE_CONTENTS_BAG, "safeContentsBag"),
                             (PBE_SHA1_3DES, "pbeWithSHAAnd3-KeyTripleDES-CBC"),
                             (PBE_SHA1_RC2_40, "pbewithSHAAnd40BitRC2-CBC")] {
            assert_eq!(rfc7292.get(name).map(String::as_str), Some(ours), "{name}");
        }
        for (ours, name) in [(PBES2, "id-PBES2"), (PBKDF2, "id-PBKDF2"), (PBMAC1, "id-PBMAC1"),
                             (AES256_CBC, "aes256-CBC-PAD")] {
            assert_eq!(rfc8018.get(name).map(String::as_str), Some(ours), "{name}");
        }
        for ((_, hmac, hash), name) in HASHES.iter().zip(["id-hmacWithSHA1", "id-hmacWithSHA224",
                                                          "id-hmacWithSHA256", "id-hmacWithSHA384",
                                                          "id-hmacWithSHA512"]) {
            assert_eq!(rfc8018.get(name).map(String::as_str), Some(*hmac), "{hash}");
        }
        // Java's secret-key names, where RFC 8018 names the same thing.
        let java: HashMap<&str, &str> = JAVA_SECRET_ALGORITHMS.iter().copied().collect();
        for (java_name, name) in [("AES", "aes"), ("DES", "desCBC"), ("RC2", "rc2CBC"),
                                  ("HmacSHA1", "id-hmacWithSHA1"),
                                  ("HmacSHA256", "id-hmacWithSHA256"),
                                  ("HmacSHA512/224", "id-hmacWithSHA512-224"),
                                  ("HmacSHA512/256", "id-hmacWithSHA512-256")] {
            assert_eq!(rfc8018.get(name).map(String::as_str), Some(java[java_name]), "{name}");
        }
        assert_eq!(java.len(), JAVA_SECRET_ALGORITHMS.len(), "a name twice");
        let mut oids: Vec<&str> = JAVA_SECRET_ALGORITHMS.iter().map(|(_, o)| *o).collect();
        oids.sort();
        oids.dedup();
        assert_eq!(oids.len(), JAVA_SECRET_ALGORITHMS.len(), "an OID twice");
    }

    /// With no MAC, a wrong password that happens to leave valid CBC
    /// padding is refused by the key not parsing - which is the only
    /// thing refusing it, so the test looks for such a password first.
    #[test]
    fn test_a_wrong_password_with_good_padding_is_refused() {
        let pkcs8 = {
            let mut w = Writer::new();
            w.write_sequence(|w| {
                w.write_u32(0);
                w.write_sequence(|w| w.write_oid(&oid("1.3.101.112")));
                w.write_octet_string(&[0x04, 0x20, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                                       7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]);
            });
            w.finish()
        };
        let bags = [Bag { kind: Kind::Key { pkcs8: pkcs8.clone(), shrouded: true },
                          friendly_name: None, local_key_id: None,
                          other_attributes: Vec::new() }];
        for scheme in ["aes-256", "3des", "rc2-40"] {
            let options = Options { key_scheme: scheme.to_string(), cert_scheme: "none".into(),
                                    mac: "none".into(), iterations: 1 };
            let file = write(&bags, b"right", &options).unwrap();
            assert_eq!(open(&file, b"right").unwrap().0[0].kind,
                       Kind::Key { pkcs8: pkcs8.clone(), shrouded: true });
            let mut caught = 0;
            for n in 0..4000 {
                match open(&file, format!("wrong {n}").as_bytes()) {
                    Ok(_) => panic!("{scheme}: wrong {n} was accepted"),
                    Err(e) if e.contains("not a PrivateKeyInfo") => caught += 1,
                    Err(_) => {}
                }
            }
            assert!(caught > 0, "{scheme}: no wrong password passed the padding");
        }
    }

    /// One key and one "certificate" - the reader keeps a certificate's
    /// bytes without parsing them, so any bytes will do, and these are
    /// easy to find in the file.
    fn sample_bags() -> Vec<Bag> {
        let pkcs8 = {
            let mut w = Writer::new();
            w.write_sequence(|w| {
                w.write_u32(0);
                w.write_sequence(|w| w.write_oid(&oid("1.3.101.112")));
                w.write_octet_string(&[0x04, 0x02, 9, 9]);
            });
            w.finish()
        };
        vec![Bag { kind: Kind::Key { pkcs8, shrouded: true }, friendly_name: Some("k".into()),
                   local_key_id: Some(vec![1]), other_attributes: Vec::new() },
             Bag { kind: Kind::Certificate(b"certificate bytes".to_vec()),
                   friendly_name: Some("k".into()), local_key_id: Some(vec![1]),
                   other_attributes: Vec::new() }]
    }

    fn options(key: &str, cert: &str, mac: &str) -> Options {
        Options { key_scheme: key.into(), cert_scheme: cert.into(), mac: mac.into(),
                  iterations: 2 }
    }

    /// A PFX's three parts: version, authSafe, and macData if present.
    fn parts(pfx: &[u8]) -> (Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
        let mut outer = Reader::new(pfx).read_sequence().unwrap();
        let version = outer.read_raw().unwrap().to_vec();
        let auth_safe = outer.read_raw().unwrap().to_vec();
        let mac = (!outer.is_empty()).then(|| outer.read_raw().unwrap().to_vec());
        (version, auth_safe, mac)
    }

    /// A changed byte under the MAC is refused - by each MAC, PBMAC1's
    /// included. The certificate safe is left unencrypted, so the change
    /// reaches the parser intact and the MAC is the only thing to object:
    /// without one the changed certificate is read back as it now is.
    #[test]
    fn test_a_changed_file_is_refused_by_its_mac() {
        for mac in ["sha256", "sha1", "pbmac1", "none"] {
            let mut file = write(&sample_bags(), b"pw", &options("aes-256", "none", mac)).unwrap();
            let at = file.windows(17).position(|w| w == b"certificate bytes").unwrap();
            file[at] ^= 1;
            match open(&file, b"pw") {
                Err(e) => {
                    assert_ne!(mac, "none", "{e}");
                    assert!(e.contains("the MAC does not match"), "{mac}: {e}");
                }
                Ok((bags, _)) => {
                    assert_eq!(mac, "none", "a changed file passed its {mac} MAC");
                    assert_eq!(bags[1].kind, Kind::Certificate(b"bertificate bytes".to_vec()));
                }
            }
        }
    }

    /// RFC 9579: under PBMAC1 the MacData's own salt and iteration count
    /// are not used - PBKDF2's parameters are. Changing them leaves a
    /// PBMAC1 file valid and breaks a classic one.
    #[test]
    fn test_pbmac1_ignores_the_mac_data_salt_and_count() {
        for mac in ["pbmac1", "sha256"] {
            let file = write(&sample_bags(), b"pw", &options("aes-256", "aes-256", mac)).unwrap();
            let (version, auth_safe, mac_data) = parts(&file);
            let mut m = Reader::new(mac_data.as_ref().unwrap()).read_sequence().unwrap();
            let digest_info = m.read_raw().unwrap().to_vec();
            let salt: Vec<u8> = m.read_octet_string().unwrap().iter().map(|b| !b).collect();
            let mut w = Writer::new();
            w.write_sequence(|w| {
                w.write_raw(&version);
                w.write_raw(&auth_safe);
                w.write_sequence(|w| {
                    w.write_raw(&digest_info);
                    w.write_octet_string(&salt);
                    w.write_u32(7);
                });
            });
            let changed = w.finish();
            assert_eq!(open(&changed, b"pw").is_ok(), mac == "pbmac1", "{mac}");
        }
    }

    /// BER with indefinite lengths everywhere, recursively: what Windows
    /// and older Java write.
    fn indefinite(der: &[u8]) -> Vec<u8> {
        let mut r = Reader::new(der);
        let mut out = Vec::new();
        while !r.is_empty() {
            let raw = r.read_raw().unwrap();
            let (tag, content) = Reader::new(raw).read_any().unwrap();
            let header = raw.len() - content.len();
            let identifier_length = if raw[0] & 0x1f == 0x1f {
                1 + raw[1..].iter().position(|b| b & 0x80 == 0).unwrap() + 1
            } else {
                1
            };
            assert!(header > identifier_length);
            if tag.constructed {
                out.extend_from_slice(&raw[..identifier_length]);
                out.push(0x80);
                out.extend(indefinite(content));
                out.extend([0, 0]);
            } else {
                out.extend_from_slice(raw);
            }
        }
        out
    }

    /// The safes inside a PFX are OCTET STRINGs whose content is a
    /// document of its own, so the PFX's own BER-to-DER pass leaves them
    /// as they were - each is converted where it is opened. NSS's safes
    /// are DER; Windows' are not, and none was to hand, so this writes
    /// them.
    #[test]
    fn test_ber_inside_the_safes_is_read() {
        let bags = sample_bags();
        let file = write(&bags, b"pw", &options("aes-256", "none", "none")).unwrap();
        let (version, auth_safe, _) = parts(&file);
        let mut a = Reader::new(&auth_safe).read_sequence().unwrap();
        a.read_oid().unwrap();
        let content = Reader::new(a.read_tagged(Tag::context(0, true)).unwrap())
            .read_octet_string().unwrap().to_vec();
        let mut infos = Reader::new(&content).read_sequence().unwrap();
        let mut rewritten = Writer::new();
        rewritten.write_sequence(|w| {
            while !infos.is_empty() {
                let mut info = infos.read_sequence().unwrap();
                info.read_oid().unwrap();
                let safe = Reader::new(info.read_tagged(Tag::context(0, true)).unwrap())
                    .read_octet_string().unwrap();
                data_info(w, &indefinite(safe));
            }
        });
        let mut pfx = Writer::new();
        pfx.write_sequence(|w| {
            w.write_raw(&version);
            data_info(w, &indefinite(&rewritten.finish()));
        });
        let ber = indefinite(&pfx.finish());
        assert!(ber.windows(2).filter(|w| *w == [0x30, 0x80]).count() > 6);
        let (read, _) = open(&ber, b"pw").unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[1], bags[1]);
        let Kind::Key { pkcs8: wanted, .. } = &bags[0].kind else { unreachable!() };
        assert!(matches!(&read[0].kind, Kind::Key { pkcs8, .. } if pkcs8 == wanted));
    }

    /// What `key_info` takes for a key: the outline of a PrivateKeyInfo,
    /// all of it, and nothing after it.
    #[test]
    fn test_key_info_wants_a_whole_private_key_info() {
        let build = |body: &dyn Fn(&mut Writer)| {
            let mut w = Writer::new();
            w.write_sequence(|w| body(w));
            w.finish()
        };
        let whole = build(&|w| {
            w.write_u32(0);
            w.write_sequence(|w| w.write_oid(&oid("1.3.101.112")));
            w.write_octet_string(&[4, 0]);
        });
        assert_eq!(key_info(&whole).unwrap(), whole);
        let mut trailing = whole.clone();
        trailing.push(0);
        assert!(key_info(&trailing).is_err());
        assert!(key_info(&build(&|w| w.write_u32(0))).is_err());
        assert!(key_info(&build(&|w| {
            w.write_u32(0);
            w.write_sequence(|w| w.write_oid(&oid("1.3.101.112")));
        })).is_err());
        assert!(key_info(&build(&|w| {
            w.write_u32(0);
            w.write_octet_string(&[4, 0]);
        })).is_err());
    }

    /// keytool's PKCS#12 secret bag, decrypted, is exactly what
    /// `secret_key_info` writes for the key inside it - Java has to read
    /// ours, and the structure is Java's own, in no standard.
    #[test]
    fn test_the_secret_key_info_is_javas() {
        let data = std::fs::read(crate::fixtures::dir().join("keystore")
                                 .join("keytool-pkcs12.pkcs12")).unwrap();
        let (bags, _) = open(&data, b"store password").unwrap();
        let values: Vec<&Vec<u8>> = bags.iter().filter_map(|b| match &b.kind {
            Kind::Secret { kind, value } if kind == SHROUDED_KEY_BAG => Some(value),
            _ => None,
        }).collect();
        assert_eq!(values.len(), 1);
        let (algorithm, key) = read_secret_key_info(values[0]).unwrap();
        assert_eq!((algorithm.as_str(), key.len()), ("AES", 32));
        assert_eq!(&secret_key_info(&algorithm, &key).unwrap(), values[0]);
        // Java looks the name up ignoring case.
        assert_eq!(&secret_key_info("aes", &key).unwrap(), values[0]);
        assert!(secret_key_info("Serpent", &key).is_err());
    }
}
