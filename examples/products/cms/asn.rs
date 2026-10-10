//! The object identifiers CMS uses, and the ASN.1 pieces every part of
//! it shares: AlgorithmIdentifier, attributes, issuer-and-serial.
//!
//! The OIDs are dotted strings encoded at use. `scripts/check_cms.py`
//! asks OpenSSL to name every one of them, so a mistyped arc is a
//! failure there rather than an identifier nobody else recognises.

use allcrypt::asn1::{self, tag, Reader, Tag, Writer};
use allcrypt::x509::Certificate;

pub use crate::cli::hex;

// Content types, RFC 5652 and RFC 5083.
pub const DATA: &str = "1.2.840.113549.1.7.1";
pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
pub const DIGESTED_DATA: &str = "1.2.840.113549.1.7.5";
pub const ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";
pub const AUTH_ENVELOPED_DATA: &str = "1.2.840.113549.1.9.16.1.23";
pub const COMPRESSED_DATA: &str = "1.2.840.113549.1.9.16.1.9";
pub const ZLIB: &str = "1.2.840.113549.1.9.16.3.8";

// Attributes, RFC 5652 section 11 and RFC 8551.
pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";

// Digests.
pub const MD5: &str = "1.2.840.113549.2.5";
pub const SHA1: &str = "1.3.14.3.2.26";
pub const SHA224: &str = "2.16.840.1.101.3.4.2.4";
pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const SHA3_256: &str = "2.16.840.1.101.3.4.2.8";
pub const SHA3_384: &str = "2.16.840.1.101.3.4.2.9";
pub const SHA3_512: &str = "2.16.840.1.101.3.4.2.10";
pub const SHAKE256: &str = "2.16.840.1.101.3.4.2.12";
pub const SHAKE256_LEN: &str = "2.16.840.1.101.3.4.2.18";

// Signatures.
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const MD5_WITH_RSA: &str = "1.2.840.113549.1.1.4";
pub const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
pub const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
pub const SHA224_WITH_RSA: &str = "1.2.840.113549.1.1.14";
pub const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
pub const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";
pub const MGF1: &str = "1.2.840.113549.1.1.8";
pub const P_SPECIFIED: &str = "1.2.840.113549.1.1.9";
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const ECDSA_WITH_SHA1: &str = "1.2.840.10045.4.1";
pub const ECDSA_WITH_SHA224: &str = "1.2.840.10045.4.3.1";
pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
pub const ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";
pub const ID_DSA: &str = "1.2.840.10040.4.1";
pub const DSA_WITH_SHA1: &str = "1.2.840.10040.4.3";
pub const DSA_WITH_SHA224: &str = "2.16.840.1.101.3.4.3.1";
pub const DSA_WITH_SHA256: &str = "2.16.840.1.101.3.4.3.2";
pub const DSA_WITH_SHA384: &str = "2.16.840.1.101.3.4.3.3";
pub const DSA_WITH_SHA512: &str = "2.16.840.1.101.3.4.3.4";
pub const ED25519: &str = "1.3.101.112";
pub const ED448: &str = "1.3.101.113";

// Content encryption.
pub const DES_CBC: &str = "1.3.14.3.2.7";
pub const DES_EDE3_CBC: &str = "1.2.840.113549.3.7";
pub const RC2_CBC: &str = "1.2.840.113549.3.2";
pub const AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
pub const AES192_CBC: &str = "2.16.840.1.101.3.4.1.22";
pub const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";
pub const AES128_GCM: &str = "2.16.840.1.101.3.4.1.6";
pub const AES192_GCM: &str = "2.16.840.1.101.3.4.1.26";
pub const AES256_GCM: &str = "2.16.840.1.101.3.4.1.46";

// Key wrapping and agreement, RFC 3565, RFC 3211 and RFC 5753.
pub const AES128_WRAP: &str = "2.16.840.1.101.3.4.1.5";
pub const AES192_WRAP: &str = "2.16.840.1.101.3.4.1.25";
pub const AES256_WRAP: &str = "2.16.840.1.101.3.4.1.45";
pub const PWRI_KEK: &str = "1.2.840.113549.1.9.16.3.9";
pub const DES3_WRAP: &str = "1.2.840.113549.1.9.16.3.6";
pub const PBKDF2: &str = "1.2.840.113549.1.5.12";
pub const HMAC_SHA1: &str = "1.2.840.113549.2.7";
pub const HMAC_SHA224: &str = "1.2.840.113549.2.8";
pub const HMAC_SHA256: &str = "1.2.840.113549.2.9";
pub const HMAC_SHA384: &str = "1.2.840.113549.2.10";
pub const HMAC_SHA512: &str = "1.2.840.113549.2.11";
pub const STD_DH_SHA1KDF: &str = "1.3.133.16.840.63.0.2";
pub const STD_DH_SHA224KDF: &str = "1.3.132.1.11.0";
pub const STD_DH_SHA256KDF: &str = "1.3.132.1.11.1";
pub const STD_DH_SHA384KDF: &str = "1.3.132.1.11.2";
pub const STD_DH_SHA512KDF: &str = "1.3.132.1.11.3";
pub const COFACTOR_DH_SHA1KDF: &str = "1.3.133.16.840.63.0.3";
pub const COFACTOR_DH_SHA224KDF: &str = "1.3.132.1.14.0";
pub const COFACTOR_DH_SHA256KDF: &str = "1.3.132.1.14.1";
pub const COFACTOR_DH_SHA384KDF: &str = "1.3.132.1.14.2";
pub const COFACTOR_DH_SHA512KDF: &str = "1.3.132.1.14.3";

// Named curves, for an ephemeral key's parameters.
pub const PRIME256V1: &str = "1.2.840.10045.3.1.7";
pub const SECP384R1: &str = "1.3.132.0.34";
pub const SECP521R1: &str = "1.3.132.0.35";
pub const SECP256K1: &str = "1.3.132.0.10";

/// Every constant above with its name, for `scripts/check_cms.py`, which
/// prints this table through `cms oids` and compares it with OpenSSL's
/// own names.
pub const ALL: &[(&str, &str)] = &[
    ("pkcs7-data", DATA), ("pkcs7-signedData", SIGNED_DATA),
    ("pkcs7-envelopedData", ENVELOPED_DATA), ("pkcs7-digestData", DIGESTED_DATA),
    ("pkcs7-encryptedData", ENCRYPTED_DATA),
    ("id-smime-ct-authEnvelopedData", AUTH_ENVELOPED_DATA),
    ("id-smime-ct-compressedData", COMPRESSED_DATA), ("zlib compression", ZLIB),
    ("contentType", CONTENT_TYPE), ("messageDigest", MESSAGE_DIGEST),
    ("signingTime", SIGNING_TIME),
    ("md5", MD5), ("sha1", SHA1), ("sha224", SHA224), ("sha256", SHA256), ("sha384", SHA384),
    ("sha512", SHA512), ("sha3-256", SHA3_256), ("sha3-384", SHA3_384), ("sha3-512", SHA3_512),
    ("shake256", SHAKE256),
    ("rsaEncryption", RSA_ENCRYPTION), ("md5WithRSAEncryption", MD5_WITH_RSA),
    ("sha1WithRSAEncryption", SHA1_WITH_RSA), ("sha256WithRSAEncryption", SHA256_WITH_RSA),
    ("sha384WithRSAEncryption", SHA384_WITH_RSA), ("sha512WithRSAEncryption", SHA512_WITH_RSA),
    ("sha224WithRSAEncryption", SHA224_WITH_RSA), ("rsassaPss", RSASSA_PSS),
    ("rsaesOaep", RSAES_OAEP), ("mgf1", MGF1), ("pSpecified", P_SPECIFIED),
    ("id-ecPublicKey", EC_PUBLIC_KEY), ("ecdsa-with-SHA1", ECDSA_WITH_SHA1),
    ("ecdsa-with-SHA224", ECDSA_WITH_SHA224), ("ecdsa-with-SHA256", ECDSA_WITH_SHA256),
    ("ecdsa-with-SHA384", ECDSA_WITH_SHA384), ("ecdsa-with-SHA512", ECDSA_WITH_SHA512),
    ("dsaEncryption", ID_DSA), ("dsaWithSHA1", DSA_WITH_SHA1),
    ("dsa_with_SHA224", DSA_WITH_SHA224), ("dsa_with_SHA256", DSA_WITH_SHA256),
    ("dsa_with_SHA384", DSA_WITH_SHA384), ("dsa_with_SHA512", DSA_WITH_SHA512),
    ("ED25519", ED25519), ("ED448", ED448),
    ("des-cbc", DES_CBC), ("des-ede3-cbc", DES_EDE3_CBC), ("rc2-cbc", RC2_CBC),
    ("aes-128-cbc", AES128_CBC), ("aes-192-cbc", AES192_CBC), ("aes-256-cbc", AES256_CBC),
    ("aes-128-gcm", AES128_GCM), ("aes-192-gcm", AES192_GCM), ("aes-256-gcm", AES256_GCM),
    ("id-aes128-wrap", AES128_WRAP), ("id-aes192-wrap", AES192_WRAP),
    ("id-aes256-wrap", AES256_WRAP), ("id-alg-PWRI-KEK", PWRI_KEK),
    ("id-smime-alg-CMS3DESwrap", DES3_WRAP), ("PBKDF2", PBKDF2),
    ("hmacWithSHA1", HMAC_SHA1), ("hmacWithSHA224", HMAC_SHA224),
    ("hmacWithSHA256", HMAC_SHA256), ("hmacWithSHA384", HMAC_SHA384),
    ("hmacWithSHA512", HMAC_SHA512),
    ("dhSinglePass-stdDH-sha1kdf-scheme", STD_DH_SHA1KDF),
    ("dhSinglePass-stdDH-sha224kdf-scheme", STD_DH_SHA224KDF),
    ("dhSinglePass-stdDH-sha256kdf-scheme", STD_DH_SHA256KDF),
    ("dhSinglePass-stdDH-sha384kdf-scheme", STD_DH_SHA384KDF),
    ("dhSinglePass-stdDH-sha512kdf-scheme", STD_DH_SHA512KDF),
    ("dhSinglePass-cofactorDH-sha1kdf-scheme", COFACTOR_DH_SHA1KDF),
    ("dhSinglePass-cofactorDH-sha224kdf-scheme", COFACTOR_DH_SHA224KDF),
    ("dhSinglePass-cofactorDH-sha256kdf-scheme", COFACTOR_DH_SHA256KDF),
    ("dhSinglePass-cofactorDH-sha384kdf-scheme", COFACTOR_DH_SHA384KDF),
    ("dhSinglePass-cofactorDH-sha512kdf-scheme", COFACTOR_DH_SHA512KDF),
    ("prime256v1", PRIME256V1), ("secp384r1", SECP384R1), ("secp521r1", SECP521R1),
    ("secp256k1", SECP256K1),
];

pub fn oid(dotted: &str) -> Vec<u8> {
    asn1::encode_oid(dotted).expect("a well-formed OID")
}

pub fn is(found: &[u8], dotted: &str) -> bool {
    found == oid(dotted).as_slice()
}

/// The dotted form of an OID's bytes, for a message.
pub fn dotted(bytes: &[u8]) -> String {
    asn1::Oid::new(bytes).map(|o| o.to_string()).unwrap_or_else(|_| "?".to_string())
}

/// An AlgorithmIdentifier: the OID's bytes and the parameters' whole
/// TLV, if there are any.
#[derive(Clone, Debug, PartialEq)]
pub struct AlgId {
    pub oid: Vec<u8>,
    pub params: Option<Vec<u8>>,
}

impl AlgId {
    pub fn new(dotted: &str) -> AlgId {
        AlgId { oid: oid(dotted), params: None }
    }

    pub fn with_params(dotted: &str, params: Vec<u8>) -> AlgId {
        AlgId { oid: oid(dotted), params: Some(params) }
    }

    /// An explicit NULL, which RSA's identifiers carry.
    pub fn with_null(dotted: &str) -> AlgId {
        AlgId::with_params(dotted, vec![0x05, 0x00])
    }

    pub fn read(r: &mut Reader) -> Result<AlgId, String> {
        let mut seq = r.read_sequence()?;
        let oid = seq.read_oid()?.as_bytes().to_vec();
        let params = if seq.is_empty() { None } else { Some(seq.read_raw()?.to_vec()) };
        seq.finish()?;
        Ok(AlgId { oid, params })
    }

    pub fn is(&self, dotted: &str) -> bool {
        is(&self.oid, dotted)
    }

    /// Parameters that are absent or NULL, which the specifications
    /// write both ways for the same meaning.
    pub fn params_empty(&self) -> bool {
        self.params.as_deref().is_none_or(|p| p == [0x05, 0x00])
    }

    pub fn params_reader(&self) -> Result<Reader<'_>, String> {
        Ok(Reader::new(self.params.as_deref()
            .ok_or_else(|| format!("{} needs parameters.", dotted(&self.oid)))?))
    }

    pub fn write(&self, w: &mut Writer) {
        w.write_sequence(|w| {
            w.write_oid(&self.oid);
            if let Some(params) = &self.params {
                w.write_raw(params);
            }
        });
    }

    pub fn to_der(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.finish()
    }
}

/// The hash a digest identifier names, as `AnyHash` spells it, and
/// whether the parameters are acceptable for it.
pub fn digest_name(alg: &AlgId) -> Result<&'static str, String> {
    let table = [(MD5, "md5"), (SHA1, "sha1"), (SHA224, "sha224"), (SHA256, "sha256"),
                 (SHA384, "sha384"), (SHA512, "sha512"), (SHA3_256, "sha3_256"),
                 (SHA3_384, "sha3_384"), (SHA3_512, "sha3_512"),
                 // Plain id-shake256 is RFC 8419's identifier for Ed448
                 // without signed attributes, where no digest is taken;
                 // OpenSSL 3.5 also writes it with them, and digests to
                 // 64 bytes, as id-shake256-len with 512 would.
                 (SHAKE256, "shake256-512")];
    if alg.is(SHAKE256_LEN) {
        // RFC 8419: only with 512 bits of output.
        let mut p = alg.params_reader()?;
        if p.read_u32()? != 512 {
            return Err("id-shake256-len is used here with 512 bits only.".to_string());
        }
        return Ok("shake256-512");
    }
    let name = table.iter().find(|(d, _)| alg.is(d)).map(|(_, n)| *n)
        .ok_or_else(|| format!("Digest {} is not one this reads.", dotted(&alg.oid)))?;
    if !alg.params_empty() {
        return Err(format!("{name} with parameters."));
    }
    Ok(name)
}

pub fn digest_alg(name: &str) -> Result<AlgId, String> {
    Ok(match name {
        "md5" => AlgId::new(MD5),
        "sha1" => AlgId::new(SHA1),
        "sha224" => AlgId::new(SHA224),
        "sha256" => AlgId::new(SHA256),
        "sha384" => AlgId::new(SHA384),
        "sha512" => AlgId::new(SHA512),
        "sha3_256" => AlgId::new(SHA3_256),
        "sha3_384" => AlgId::new(SHA3_384),
        "sha3_512" => AlgId::new(SHA3_512),
        "shake256-512" => {
            let mut w = Writer::new();
            w.write_u32(512);
            AlgId::with_params(SHAKE256_LEN, w.finish())
        }
        other => return Err(format!("No digest named {other}.")),
    })
}

/// A digest by the names above, SHAKE256 at 512 bits included.
pub fn digest(name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    if name == "shake256-512" {
        return allcrypt::api::shake("shake256", data, 64);
    }
    use allcrypt::hash_functions::HashFunction;
    let mut hash = allcrypt::api::AnyHash::new(name)?;
    hash.update(data);
    Ok(hash.digest())
}

/// IssuerAndSerialNumber: the issuer Name's DER and the serial
/// INTEGER's content bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct IssuerSerial {
    pub issuer: Vec<u8>,
    pub serial: Vec<u8>,
}

impl IssuerSerial {
    pub fn of(cert: &Certificate) -> IssuerSerial {
        IssuerSerial { issuer: cert.issuer.raw.to_vec(), serial: cert.serial.to_vec() }
    }

    pub fn read(r: &mut Reader) -> Result<IssuerSerial, String> {
        let mut seq = r.read_sequence()?;
        let issuer = seq.read_raw()?.to_vec();
        let serial = seq.read_integer_bytes()?.to_vec();
        seq.finish()?;
        Ok(IssuerSerial { issuer, serial })
    }

    pub fn write(&self, w: &mut Writer) {
        w.write_sequence(|w| {
            w.write_raw(&self.issuer);
            w.write_tlv(Tag::universal(tag::INTEGER), &self.serial);
        });
    }

    pub fn matches(&self, cert: &Certificate) -> bool {
        self.issuer == cert.issuer.raw && self.serial == cert.serial
    }
}

/// How a signer or a recipient names its certificate.
#[derive(Clone, Debug, PartialEq)]
pub enum CertId {
    IssuerSerial(IssuerSerial),
    KeyId(Vec<u8>),
}

impl CertId {
    pub fn matches(&self, cert: &Certificate) -> bool {
        match self {
            CertId::IssuerSerial(is) => is.matches(cert),
            CertId::KeyId(id) => cert.extensions.subject_key_id == Some(id.as_slice()),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            CertId::IssuerSerial(is) => format!("serial {}", hex(&is.serial)),
            CertId::KeyId(id) => format!("key id {}", hex(id)),
        }
    }
}

/// One attribute: its type and its values' DER, in order.
#[derive(Clone, Debug)]
pub struct Attribute {
    pub oid: Vec<u8>,
    pub values: Vec<Vec<u8>>,
}

/// A SET OF Attribute's content.
pub fn read_attributes(content: &[u8]) -> Result<Vec<Attribute>, String> {
    let mut r = Reader::new(content);
    let mut out = Vec::new();
    while !r.is_empty() {
        let mut a = r.read_sequence()?;
        let oid = a.read_oid()?.as_bytes().to_vec();
        let mut set = a.read_set()?;
        let mut values = Vec::new();
        while !set.is_empty() {
            values.push(set.read_raw()?.to_vec());
        }
        a.finish()?;
        out.push(Attribute { oid, values });
    }
    Ok(out)
}

/// The one value of a single-valued attribute, refusing it twice over
/// or with several values (RFC 5652 11.1, 11.2).
pub fn single<'a>(attributes: &'a [Attribute], dotted: &str) -> Result<Option<&'a [u8]>, String> {
    let mut found = attributes.iter().filter(|a| is(&a.oid, dotted));
    let Some(first) = found.next() else { return Ok(None) };
    if found.next().is_some() || first.values.len() != 1 {
        return Err(format!("Attribute {dotted} must appear once with one value."));
    }
    Ok(Some(&first.values[0]))
}

/// DER of `SET OF`: each element's encoding, sorted (X.690 11.6).
pub fn der_set_of(mut elements: Vec<Vec<u8>>, tag: u8) -> Vec<u8> {
    elements.sort();
    let content: Vec<u8> = elements.concat();
    let mut w = Writer::new();
    let tag = if tag == 0x31 { Tag::set() } else { Tag::context(u32::from(tag & 0x1f), true) };
    w.write_tlv(tag, &content);
    w.finish()
}

pub fn attribute(dotted: &str, value: Vec<u8>) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_oid(&oid(dotted));
        w.write_set(|w| w.write_raw(&value));
    });
    w.finish()
}

/// The content octets of an OCTET STRING that may arrive primitive or,
/// from a BER writer under an implicit tag, constructed from pieces.
pub fn string_pieces(tag_byte: u8, content: &[u8]) -> Result<Vec<u8>, String> {
    if tag_byte & 0x20 == 0 {
        return Ok(content.to_vec());
    }
    let mut r = Reader::new(content);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.extend_from_slice(r.read_octet_string()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DER sorts a SET OF by encoding, whatever order it is given in.
    #[test]
    fn test_set_of_is_sorted() {
        let set = der_set_of(vec![vec![0x04, 0x01, 0x02], vec![0x02, 0x01, 0x05],
                                  vec![0x04, 0x01, 0x01]], 0x31);
        assert_eq!(set, [0x31, 0x09, 0x02, 0x01, 0x05, 0x04, 0x01, 0x01, 0x04, 0x01, 0x02]);
    }

    /// A single-valued attribute twice, or with two values, is refused.
    #[test]
    fn test_single_valued_attributes() {
        let one = Attribute { oid: oid(MESSAGE_DIGEST), values: vec![vec![1]] };
        let two_values = Attribute { oid: oid(MESSAGE_DIGEST), values: vec![vec![1], vec![2]] };
        assert_eq!(single(std::slice::from_ref(&one), MESSAGE_DIGEST).unwrap(), Some(&[1u8][..]));
        assert!(single(&[one.clone(), one.clone()], MESSAGE_DIGEST).is_err());
        assert!(single(&[two_values], MESSAGE_DIGEST).is_err());
        assert_eq!(single(&[one], CONTENT_TYPE).unwrap(), None);
    }

    /// A digest identifier's parameters are absent or NULL, nothing else.
    #[test]
    fn test_digest_parameters() {
        assert_eq!(digest_name(&AlgId::new(SHA256)).unwrap(), "sha256");
        assert_eq!(digest_name(&AlgId::with_null(SHA256)).unwrap(), "sha256");
        assert!(digest_name(&AlgId::with_params(SHA256, vec![0x02, 0x01, 0x01])).is_err());
        assert!(digest_name(&AlgId::new(SHAKE256_LEN)).is_err());
    }

    /// Issuer and serial both: the same serial from another issuer is
    /// another certificate.
    #[test]
    fn test_issuer_and_serial_both_count() {
        let pem = std::fs::read(crate::fixtures::dir().join("cms").join("rsa.crt")).unwrap();
        let der = crate::keys::certificates(&pem).unwrap().remove(0);
        let cert = Certificate::parse(&der).unwrap();
        let id = IssuerSerial::of(&cert);
        assert!(id.matches(&cert));
        let other_issuer = IssuerSerial { issuer: cert.subject.raw.to_vec(), ..id.clone() };
        assert!(!other_issuer.matches(&cert));
        let other_serial = IssuerSerial { serial: vec![0x01], ..id };
        assert!(!other_serial.matches(&cert));
    }
}
