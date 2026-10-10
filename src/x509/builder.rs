/*
Building and signing certificates.

Mostly this exists so the verifier can be tested against chains that are
real rather than hand-assembled: a chain whose signatures were made by this
library and checked by OpenSSL, and one whose signatures were made by
OpenSSL and checked by this library, are two different tests and both are
worth having.

It is also genuinely useful. A TLS client needs to present a client
certificate sometimes, a test harness needs a private CA, and generating
those with an external tool means the test depends on that tool.

This is not a CA. There is no serial number policy, no revocation, no
profile enforcement beyond what the encoder needs. What it does do is refuse
to build something structurally invalid - a v3 certificate with no
extensions is fine, a pathLenConstraint on a leaf is not.
*/

use crate::asn1::{self, Tag, Writer};
use crate::bignum::BigUint;
use crate::ec::Curve;
use crate::hash_functions::HashFunction;
use crate::publickey_ciphers::rsa::{self, RsaPrivateKey};
use crate::x509::{ocsp, oids, verify};

/// The key a certificate is signed with, and the one it carries.
pub enum SigningKey<'a> {
    Rsa(&'a RsaPrivateKey),
    Ec { curve: &'a Curve, private: &'a BigUint },
    /// GOST R 34.10-2012. The hash is not a free choice here the way it
    /// is for RSA and ECDSA - it is Streebog, at the curve's size - so
    /// the builder's `hash` field is ignored for this variant and a
    /// mismatch is refused rather than silently overridden.
    Gost { curve: &'a Curve, private: &'a BigUint },
    /// GOST R 34.10-2001, RFC 4357: the same arithmetic on the same
    /// curves, hashed with GOST R 34.11-94 instead of Streebog and
    /// named by an OID from a different arc.
    ///
    /// A variant rather than a flag on `Gost`, because every place
    /// that matches on the key has to choose an OID, and a boolean
    /// that changes which OID is written is a boolean somebody will
    /// forget to pass.
    Gost2001 { curve: &'a Curve, private: &'a BigUint },
    /// EdDSA, RFC 8410. Like GOST, the builder's `hash` field is
    /// ignored - but for a different reason: GOST's hash follows the
    /// curve, and EdDSA has no separable hash at all. The message is
    /// signed whole.
    Eddsa { name: &'static str, seed: &'a [u8] },
    /// ML-DSA, RFC 9881: pure ML-DSA over the message with an empty
    /// context, hedged. The builder's `hash` field is ignored, as for
    /// EdDSA.
    MlDsa(&'a crate::api::MlDsaKey),
    /// DSA, RFC 3279: hash, then sign with RFC 6979 nonces, and the
    /// signature a DER `Dss-Sig-Value`.
    Dsa(&'a crate::publickey_ciphers::dsa::DsaPrivateKey),
    /// A key this library cannot read: on a smart card, in an HSM, in
    /// another process. `public` is its public half, which decides the
    /// signature algorithm and the authority key identifier, and `sign`
    /// is called with the hash's name and the bytes to sign - the DER of
    /// the TBSCertificate, TBSCertList or ResponseData - and returns the
    /// signature value as the algorithm writes it: PKCS#1 v1.5 for RSA,
    /// a DER `Ecdsa-Sig-Value` for ECDSA, the raw signature for EdDSA.
    ///
    /// Nothing checks the signature here; a signer that returns garbage
    /// makes a certificate that verifies nowhere. A caller that can check
    /// it - with the public key it already has - should.
    External {
        public: SubjectKey<'a>,
        sign: &'a ExternalSigner<'a>,
    },
}

/// What `SigningKey::External` calls: the hash's name and the bytes to
/// sign in, the signature value out.
pub type ExternalSigner<'a> = dyn Fn(&str, &[u8]) -> Result<Vec<u8>, String> + 'a;

/// A public key to put in a certificate.
#[derive(Clone, Copy)]
pub enum SubjectKey<'a> {
    Rsa { n: &'a BigUint, e: &'a BigUint },
    /// The curve and a SEC1 encoded point.
    Ec { curve: &'a Curve, point: &'a [u8] },
    /// A GOST key, which is encoded quite differently: little endian
    /// coordinates in an OCTET STRING inside the BIT STRING, and a
    /// parameter set OID rather than a curve OID.
    Gost { curve: &'a Curve, point: &'a crate::ec::Point },
    /// A GOST R 34.10-2001 key. The same bytes as `Gost` under a
    /// different algorithm OID - see `tls::gost_kex::encode_public_key`.
    Gost2001 { curve: &'a Curve, point: &'a crate::ec::Point },
    /// An EdDSA key: the variant's name and the raw encoded point.
    /// **The BIT STRING is the key** - no wrapper of any kind.
    Eddsa { name: &'static str, key: &'a [u8] },
    /// An ML-DSA key: FIPS 204's parameter set name and the raw public
    /// key, which is the BIT STRING as it is for EdDSA.
    MlDsa { parameter_set: &'static str, key: &'a [u8] },
    /// A DSA key: the group goes in the AlgorithmIdentifier as Dss-Parms
    /// and `y` in the BIT STRING as an INTEGER.
    Dsa(&'a crate::publickey_ciphers::dsa::DsaPublicKey),
}


/// `private * G` for a signing key's scalar, after checking it is in
/// `[1, n)`.
fn public_point(curve: &crate::ec::Curve, private: &BigUint)
                -> Result<crate::ec::Point, String> {
    if private.is_zero() || *private >= curve.n {
        return Err("The signing key's private scalar is not in [1, n).".to_string());
    }
    curve.scalar_mul_secret(&curve.g, private)
}

impl<'a> SigningKey<'a> {
    /// The signature algorithm OID for this key and hash.
    fn algorithm_oid(&self, hash: &str) -> Result<&'static [u8], String> {
        Ok(match (self, hash) {
            (SigningKey::Rsa(_), "sha256") => oids::SHA256_WITH_RSA,
            (SigningKey::Rsa(_), "sha384") => oids::SHA384_WITH_RSA,
            (SigningKey::Rsa(_), "sha512") => oids::SHA512_WITH_RSA,
            (SigningKey::Rsa(_), "sha1") => oids::SHA1_WITH_RSA,
            (SigningKey::Rsa(_), "md5") => oids::MD5_WITH_RSA,
            (SigningKey::Ec { .. }, "sha256") => oids::ECDSA_WITH_SHA256,
            (SigningKey::Ec { .. }, "sha384") => oids::ECDSA_WITH_SHA384,
            (SigningKey::Ec { .. }, "sha512") => oids::ECDSA_WITH_SHA512,
            (SigningKey::Ec { .. }, "sha1") => oids::ECDSA_WITH_SHA1,
            (SigningKey::Dsa(_), "sha1") => oids::DSA_WITH_SHA1,
            (SigningKey::Dsa(_), "sha224") => oids::DSA_WITH_SHA224,
            (SigningKey::Dsa(_), "sha256") => oids::DSA_WITH_SHA256,
            (SigningKey::Dsa(_), "sha384") => oids::DSA_WITH_SHA384,
            (SigningKey::Dsa(_), "sha512") => oids::DSA_WITH_SHA512,
            // GOST's OID names the key size and the digest together, so
            // it comes from the curve rather than from `hash`.
            (SigningKey::Gost { curve, .. }, _) => {
                if curve.n.bit_len() <= 256 {
                    oids::GOST3410_12_256_WITH_DIGEST
                } else {
                    oids::GOST3410_12_512_WITH_DIGEST
                }
            }
            // One OID, because GOST R 34.10-2001 has one key size and
            // one hash.
            (SigningKey::Gost2001 { .. }, _) =>
                oids::GOST3411_94_WITH_GOST3410_2001,
            // One OID for the key and the signature both, and no hash
            // in it - so `hash` is not consulted rather than being
            // matched and rejected.
            (SigningKey::Eddsa { name, .. }, _) => match *name {
                "ed25519" => oids::ID_ED25519,
                "ed448" => oids::ID_ED448,
                other => return Err(format!("No OID for EdDSA variant {}.", other)),
            },
            (SigningKey::MlDsa(key), _) => crate::x509::ml_dsa_oid(key.parameter_set())?,
            // An external key signs as its public half's algorithm does.
            (SigningKey::External { public, .. }, hash) => match public {
                SubjectKey::Rsa { .. } | SubjectKey::Ec { .. } => {
                    let stand_in = match public {
                        SubjectKey::Rsa { .. } => "rsa",
                        _ => "ec",
                    };
                    return external_oid(stand_in, hash);
                }
                SubjectKey::Eddsa { name: "ed25519", .. } => oids::ID_ED25519,
                SubjectKey::Eddsa { name: "ed448", .. } => oids::ID_ED448,
                _ => return Err("An external signer holds an RSA, ECDSA or EdDSA key \
                                 here.".to_string()),
            },
            (_, other) => return Err(format!("No signature algorithm OID for {}.", other)),
        })
    }

    /// The AlgorithmIdentifier: RSA carries an explicit NULL parameter,
    /// ECDSA carries nothing. Both spellings are required by their specs and
    /// getting them the wrong way round makes a certificate that some
    /// parsers accept and others do not.
    fn write_algorithm(&self, writer: &mut Writer, hash: &str) -> Result<(), String> {
        let oid = self.algorithm_oid(hash)?;
        // RSA carries an explicit NULL; ECDSA, GOST and EdDSA carry
        // nothing. For EdDSA that is RFC 8410 section 3 and is a MUST,
        // not a convention - our own parser refuses a NULL there.
        let needs_null = matches!(self, SigningKey::Rsa(_)
                                  | SigningKey::External { public: SubjectKey::Rsa { .. }, .. });
        writer.write_sequence(|w| {
            w.write_oid(oid);
            if needs_null {
                w.write_null();
            }
        });
        Ok(())
    }

    /// The key identifier of this key's **public** half, for the
    /// `authorityKeyIdentifier` of a certificate it signs.
    ///
    /// A signing key is the private one, so the public half has to be
    /// derived - a scalar multiplication for the EC and GOST variants.
    /// Worth the cost once per issuance, because the alternative is for
    /// the caller to carry the issuer's public key alongside its
    /// private one and keep the pair straight.
    pub fn key_identifier(&self) -> Result<Vec<u8>, String> {
        match self {
            SigningKey::Rsa(key) => {
                let public = key.public_key();
                key_identifier(&SubjectKey::Rsa { n: &public.n, e: &public.e })
            }
            // The scalar is the caller's, unchecked until `sign`, which
            // runs after this; so it is range-checked here, and the
            // ladder's error is returned rather than its panic.
            SigningKey::Ec { curve, private } => {
                let point = curve.encode_point(&public_point(curve, private)?, false)?;
                key_identifier(&SubjectKey::Ec { curve, point: &point })
            }
            SigningKey::Gost { curve, private } => {
                let point = public_point(curve, private)?;
                key_identifier(&SubjectKey::Gost { curve, point: &point })
            }
            SigningKey::Gost2001 { curve, private } => {
                let point = public_point(curve, private)?;
                key_identifier(&SubjectKey::Gost2001 { curve, point: &point })
            }
            SigningKey::Eddsa { name, seed } => {
                let public = crate::api::eddsa_public_key(name, seed)?;
                key_identifier(&SubjectKey::Eddsa { name, key: &public })
            }
            SigningKey::MlDsa(key) => key_identifier(&SubjectKey::MlDsa {
                parameter_set: key.parameter_set(), key: key.public_bytes() }),
            SigningKey::Dsa(key) => key_identifier(&SubjectKey::Dsa(&key.public)),
            SigningKey::External { public, .. } => key_identifier(public),
        }
    }

    /// Sign the DER of a TBSCertificate, TBSCertList or ResponseData:
    /// whatever the key, the signature value for the BIT STRING that
    /// follows the AlgorithmIdentifier.
    ///
    /// One dispatch for the three structures, because GOST, EdDSA and
    /// ML-DSA each skip the digest that `sign` computes, and three copies
    /// of that choice are three places to forget a new key type.
    pub fn sign_signed_data(&self, hash: &str, tbs: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            SigningKey::Gost { curve, private } => SigningKey::sign_gost(curve, private, tbs),
            SigningKey::Gost2001 { curve, private } =>
                SigningKey::sign_gost_2001(curve, private, tbs),
            SigningKey::Eddsa { name, seed } => SigningKey::sign_eddsa(name, seed, tbs),
            // RFC 9881 section 3: the empty context string.
            SigningKey::MlDsa(key) => key.sign(tbs, &[], None),
            SigningKey::External { sign, .. } => sign(hash, tbs),
            other => other.sign(hash, tbs),
        }
    }

    /// Sign a message with this key.
    ///
    /// `pub` because `tls::server` signs a ServerKeyExchange with the
    /// same key it presents a certificate for, and the alternative was
    /// a second copy of "which signature algorithm goes with which key
    /// and hash" living in the TLS code.
    ///
    /// For the hash-then-sign keys only; `sign_signed_data` is the one
    /// that takes every variant.
    pub fn sign(&self, hash: &str, message: &[u8]) -> Result<Vec<u8>, String> {
        if let SigningKey::External { sign, .. } = self {
            return sign(hash, message);
        }
        let mut hasher = crate::api::AnyHash::new(hash)?;
        hasher.update(message);
        let digest = hasher.digest();

        match self {
            SigningKey::Rsa(key) => rsa::sign_pkcs1v15(key, hash, &digest),
            SigningKey::Ec { curve, private } => {
                let signature = curve.sign(private, &digest,
                                           crate::api::AnyHash::new(hash)?)?;
                Ok(verify::encode_ecdsa_der(&signature))
            }
            SigningKey::Dsa(key) => {
                let (r, s) = key.sign(&digest, crate::api::AnyHash::new(hash)?)?;
                Ok(verify::encode_ecdsa_der(&crate::ec::Signature { r, s }))
            }
            SigningKey::Gost { .. } | SigningKey::Gost2001 { .. } =>
                unreachable!("handled in sign_gost"),
            SigningKey::Eddsa { .. } => unreachable!("handled in sign_eddsa"),
            SigningKey::MlDsa(_) => unreachable!("handled in sign_signed_data"),
            SigningKey::External { .. } => unreachable!("handled above"),
        }
    }

    /// EdDSA signing, which does not hash first.
    ///
    /// A separate function for the same reason `sign_gost` is one: the
    /// arm above computes a digest before it dispatches, and handing
    /// EdDSA a digest would sign the hash of the message rather than
    /// the message - self-consistent, and verifying nowhere.
    fn sign_eddsa(name: &'static str, seed: &[u8], message: &[u8])
                  -> Result<Vec<u8>, String> {
        crate::api::eddsa_sign(name, seed, message, &[])
    }

    /// GOST signing, which shares nothing with the branch above.
    ///
    /// The digest is Streebog at the curve's size - not the builder's
    /// `hash`, which is why this is a separate function rather than
    /// another arm - and the signature is `s || r` fixed width rather
    /// than a DER SEQUENCE.
    /// GOST R 34.10-2001: the same signature over a GOST R 34.11-94
    /// digest, and the same hash again as the nonce generator.
    fn sign_gost_2001(curve: &Curve, private: &BigUint, message: &[u8])
                      -> Result<Vec<u8>, String> {
        use crate::hash_functions::gost94::Gost94;
        let digest = Gost94::new(message).digest();
        let signature = curve.gost_sign(private, &digest, Gost94::new(&[]))?;
        curve.gost_signature_bytes(&signature)
    }

    fn sign_gost(curve: &Curve, private: &BigUint, message: &[u8])
                 -> Result<Vec<u8>, String> {
        use crate::hash_functions::streebog::Streebog;
        if curve.n.bit_len() <= 256 {
            let digest = Streebog::new_256(message).digest();
            let signature = curve.gost_sign(private, &digest,
                                            Streebog::new_256(&[]))?;
            curve.gost_signature_bytes(&signature)
        } else {
            let digest = Streebog::new(message).digest();
            let signature = curve.gost_sign(private, &digest,
                                            Streebog::new(&[]))?;
            curve.gost_signature_bytes(&signature)
        }
    }
}

/// The RSA or ECDSA signature OID for a hash, for an external signer.
fn external_oid(kind: &str, hash: &str) -> Result<&'static [u8], String> {
    Ok(match (kind, hash) {
        ("rsa", "sha256") => oids::SHA256_WITH_RSA,
        ("rsa", "sha384") => oids::SHA384_WITH_RSA,
        ("rsa", "sha512") => oids::SHA512_WITH_RSA,
        ("rsa", "sha1") => oids::SHA1_WITH_RSA,
        ("ec", "sha256") => oids::ECDSA_WITH_SHA256,
        ("ec", "sha384") => oids::ECDSA_WITH_SHA384,
        ("ec", "sha512") => oids::ECDSA_WITH_SHA512,
        ("ec", "sha1") => oids::ECDSA_WITH_SHA1,
        (_, other) => return Err(format!("No signature algorithm OID for {}.", other)),
    })
}

/// One entry for a subjectAltName.
#[derive(Clone, Debug)]
pub enum SanEntry {
    Dns(String),
    Email(String),
    Uri(String),
    Ip(Vec<u8>),
}

/// A certificate to be built.
pub struct CertificateBuilder<'a> {
    pub serial: Vec<u8>,
    pub issuer: Vec<(&'static [u8], String)>,
    pub subject: Vec<(&'static [u8], String)>,
    /// A subject DN to write **verbatim**, in place of `subject`.
    ///
    /// The attribute list above cannot express every name: a
    /// multi-valued RDN, an attribute encoded as PrintableString rather
    /// than UTF8String, an OID nothing here has a constant for. A proxy
    /// mirroring somebody else's certificate has to reproduce the name
    /// exactly - a browser that pinned the original compares the bytes
    /// - so it hands over the DER it parsed.
    pub subject_raw: Option<Vec<u8>>,
    /// The same for the issuer.
    pub issuer_raw: Option<Vec<u8>>,
    pub not_before: &'a str,
    pub not_after: &'a str,
    pub subject_key: SubjectKey<'a>,
    pub is_ca: Option<(bool, Option<u32>)>,
    pub key_usage: Option<u16>,
    pub extended_key_usage: Vec<&'static [u8]>,
    pub sans: Vec<SanEntry>,
    /// Extensions we do not build ourselves: OID, critical, DER value.
    pub extra_extensions: Vec<(Vec<u8>, bool, Vec<u8>)>,
    /// Emit `subjectKeyIdentifier` and `authorityKeyIdentifier`
    /// (RFC 5280 4.2.1.1 and 4.2.1.2), both computed by method 1.
    ///
    /// **A CA certificate MUST carry a subjectKeyIdentifier** and every
    /// certificate but a self-signed root MUST carry an
    /// authorityKeyIdentifier - so anything a browser will be asked to
    /// trust needs this on. python-cryptography's path verifier refuses
    /// a chain without the authority one before it looks at anything
    /// else, which is how strict a real relying party can be.
    ///
    /// Off by default all the same: turning it on changes the bytes of
    /// every certificate this builder makes, and the tests that pin
    /// those bytes are pinning them for reasons of their own.
    pub key_identifiers: bool,
    /// The X.509 version to write: 1, 2 or 3. Only version 3 may carry
    /// extensions, so `sign` refuses any other version once anything
    /// above would produce one. Here for the verifier's tests, which
    /// need a version 1 certificate in the middle of a path to prove it
    /// is not treated as a CA.
    pub version: u32,
    pub hash: &'a str,
}

impl<'a> CertificateBuilder<'a> {
    /// A builder with the fields every certificate needs, and nothing else.
    pub fn new(subject_common_name: &str, subject_key: SubjectKey<'a>)
               -> CertificateBuilder<'a> {
        CertificateBuilder {
            serial: vec![0x01],
            issuer: vec![(oids::COMMON_NAME, subject_common_name.to_string())],
            subject: vec![(oids::COMMON_NAME, subject_common_name.to_string())],
            subject_raw: None,
            issuer_raw: None,
            not_before: "20200101000000Z",
            not_after: "20400101000000Z",
            subject_key,
            is_ca: None,
            key_usage: None,
            extended_key_usage: vec![],
            sans: vec![],
            extra_extensions: vec![],
            key_identifiers: false,
            version: 3,
            hash: "sha256",
        }
    }

    /// Build and sign. `issuer_name` is the signer's subject, which becomes
    /// this certificate's issuer - passed separately because a self-signed
    /// certificate is its own issuer and a signed one is not.
    pub fn sign(&self, key: &SigningKey<'_>) -> Result<Vec<u8>, String> {
        if self.serial.is_empty() {
            return Err("A certificate needs a serial number.".to_string());
        }
        if self.serial[0] & 0x80 != 0 {
            // A serial with the top bit set is a negative INTEGER, which
            // RFC 5280 forbids and our own parser refuses.
            return Err("Serial number must be positive; prefix a zero byte."
                       .to_string());
        }
        if let Some((false, Some(_))) = self.is_ca {
            return Err("pathLenConstraint on something that is not a CA."
                       .to_string());
        }
        if !(1..=3).contains(&self.version) {
            return Err(format!("There is no X.509 version {}.", self.version));
        }

        let tbs = self.write_tbs(key)?;
        let signature = key.sign_signed_data(self.hash, &tbs)?;

        let mut writer = Writer::new();
        writer.write_sequence(|c| {
            c.write_raw(&tbs);
            // The outer algorithm must equal the inner one - our parser
            // checks that, and so does everyone else's.
            key.write_algorithm(c, self.hash).expect("algorithm already validated");
            c.write_bit_string(&signature);
        });
        Ok(writer.finish())
    }

    fn write_tbs(&self, key: &SigningKey<'_>) -> Result<Vec<u8>, String> {
        let mut algorithm = Writer::new();
        key.write_algorithm(&mut algorithm, self.hash)?;
        let algorithm = algorithm.finish();

        let extensions = self.write_extensions(key)?;
        if self.version != 3 && !extensions.is_empty() {
            // RFC 5280 4.1.2.9: extensions appear only in a version 3
            // certificate, and the parser refuses anything else.
            return Err(format!(
                "A version {} certificate cannot carry extensions.", self.version));
        }

        // Built before the closure, because `write_sequence` takes one
        // that cannot fail and an unnamed curve is now an error rather
        // than a wrong OID.
        let mut spki = Writer::new();
        self.write_spki(&mut spki)?;
        let spki = spki.finish();

        let mut writer = Writer::new();
        writer.write_sequence(|t| {
            // version [0] EXPLICIT INTEGER DEFAULT v1: 2 means v3, and
            // DER omits a value equal to the default.
            if self.version != 1 {
                let value = self.version - 1;
                t.write_constructed(Tag::context(0, true), |w| w.write_u32(value));
            }
            t.write_tlv(Tag::universal(asn1::tag::INTEGER), &self.serial);
            t.write_raw(&algorithm);
            match &self.issuer_raw {
                Some(der) => t.write_raw(der),
                None => write_name(t, &self.issuer),
            }
            t.write_sequence(|w| {
                write_time(w, self.not_before);
                write_time(w, self.not_after);
            });
            match &self.subject_raw {
                Some(der) => t.write_raw(der),
                None => write_name(t, &self.subject),
            }
            t.write_raw(&spki);
            if !extensions.is_empty() {
                t.write_constructed(Tag::context(3, true), |w| w.write_raw(&extensions));
            }
        });
        Ok(writer.finish())
    }

    fn write_spki(&self, writer: &mut Writer) -> Result<(), String> {
        write_spki(writer, &self.subject_key)
    }
}

/// The SubjectPublicKeyInfo for a key.
///
/// Out of the impl block because `key_identifier` needs it for a key
/// that has no builder around it - the *signer's* own, when writing an
/// authorityKeyIdentifier.
fn write_spki(writer: &mut Writer, subject_key: &SubjectKey<'_>)
              -> Result<(), String> {
    {
        match subject_key {
            SubjectKey::Rsa { n, e } => {
                writer.write_sequence(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(oids::RSA_ENCRYPTION);
                        w.write_null();
                    });
                    let mut key = Writer::new();
                    key.write_sequence(|w| {
                        w.write_integer(n);
                        w.write_integer(e);
                    });
                    w.write_bit_string(&key.finish());
                });
            }
            SubjectKey::Dsa(key) => {
                let crate::publickey_ciphers::dsa::DsaParameters { p, q, g } = &key.parameters;
                writer.write_sequence(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(oids::ID_DSA);
                        w.write_sequence(|w| {
                            w.write_integer(p);
                            w.write_integer(q);
                            w.write_integer(g);
                        });
                    });
                    let mut y = Writer::new();
                    y.write_integer(&key.y);
                    w.write_bit_string(&y.finish());
                });
            }
            SubjectKey::MlDsa { parameter_set, key } => {
                let oid = crate::x509::ml_dsa_oid(parameter_set)?;
                // RFC 9881 sections 2 and 4: absent parameters, and the
                // BIT STRING is FIPS 204's encoding of the key.
                writer.write_sequence(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(oid);
                    });
                    w.write_bit_string(key);
                });
            }
            SubjectKey::Eddsa { name, key } => {
                let oid = match *name {
                    "ed25519" => oids::ID_ED25519,
                    "ed448" => oids::ID_ED448,
                    other => return Err(format!("No OID for EdDSA variant {}.", other)),
                };
                writer.write_sequence(|w| {
                    // **No parameters at all** - RFC 8410 section 3.
                    // Not a NULL, which is what the RSA arm above
                    // writes and what an encoder copied from it emits.
                    w.write_sequence(|w| {
                        w.write_oid(oid);
                    });
                    // And the BIT STRING is the key, with nothing
                    // around it: no SEQUENCE, no OCTET STRING, no SEC1
                    // format byte.
                    w.write_bit_string(key);
                });
            }
            SubjectKey::Ec { curve, point } => {
                // Named explicitly, and an unnamed curve is an error.
                // It used to fall back to prime256v1, which produced a
                // certificate that parsed, verified against nothing,
                // and said P-256 about a key that was not on P-256.
                // Keeps a computed encoding alive for the match below.
                let registered;
                let curve_oid: &[u8] = match curve.name {
                    "P-256" => oids::PRIME256V1,
                    "P-384" => oids::SECP384R1,
                    "P-521" => oids::SECP521R1,
                    "secp256k1" => oids::SECP256K1,
                    // **And a curve the caller registered**, which
                    // otherwise could be read from a certificate and not
                    // written into one. That asymmetry is worth closing
                    // rather than documenting: a caller who registers a
                    // curve to talk to a box usually has to issue a
                    // certificate on it too, and the alternative is
                    // editing this match and rebuilding - the thing the
                    // registry exists to avoid.
                    other => {
                        let oids = crate::registry::oids_for_curve(other);
                        match oids.len() {
                            1 => {
                                registered = crate::asn1::encode_oid(&oids[0])?;
                                &registered
                            }
                            0 => return Err(format!(
                                "No curve OID for {}, so a certificate \
                                 carrying this key would name a different \
                                 curve. Register the curve's OID with \
                                 register_oid if the box you are talking to \
                                 uses one.", other)),
                            // Refused rather than resolved by picking the
                            // first: a certificate names one curve, and
                            // choosing which would be choosing for the
                            // caller. Reading is unaffected - each of
                            // these OIDs resolves to this curve.
                            _ => return Err(format!(
                                "{} is registered under {} OIDs ({}), and a \
                                 certificate names one. Forget the ones this \
                                 certificate should not claim.",
                                other, oids.len(), oids.join(", "))),
                        }
                    }
                };
                writer.write_sequence(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(oids::EC_PUBLIC_KEY);
                        w.write_oid(curve_oid);
                    });
                    w.write_bit_string(point);
                });
            }
            SubjectKey::Gost { curve, point } => {
                // RFC 9215 section 4.3, the same encoding
                // `tls::gost_kex` writes for an ephemeral key.
                writer.write_raw(
                    &crate::tls::gost_kex::encode_public_key(curve, point)?);
            }
            SubjectKey::Gost2001 { curve, point } => {
                writer.write_raw(
                    &crate::tls::gost_kex::encode_public_key_2001(curve, point)?);
            }
        }
        Ok(())
    }
}

/// The key identifier for a public key: **RFC 5280 4.2.1.2 method 1**,
/// the SHA-1 of the `subjectPublicKey` BIT STRING's *contents* - not of
/// the SubjectPublicKeyInfo, and not of the BIT STRING's TLV.
///
/// The three readings are all plausible and only one interoperates.
/// The wrong ones produce an identifier that matches nothing, which
/// looks like a chain whose links do not belong together rather than
/// like a bug in here.
///
/// SHA-1 is not a choice: the identifier is a name, not a signature,
/// and every verifier that looks one up computes it this way.
pub fn key_identifier(subject_key: &SubjectKey<'_>) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    write_spki(&mut writer, subject_key)?;
    let spki = writer.finish();

    // Read the bits back out of what was just written, rather than
    // building them a second way. The two would agree today and drift
    // the first time a key type is added.
    let mut reader = crate::asn1::Reader::new(&spki);
    let mut sequence = reader.read_sequence()?;
    reader.finish()?;
    sequence.read_any()?;                       // AlgorithmIdentifier
    let bits = sequence.read_bit_string()?;
    sequence.finish()?;
    Ok(crate::hash_functions::sha1::SHA1::new(bits).digest())
}

impl<'a> CertificateBuilder<'a> {
    fn write_extensions(&self, signer: &SigningKey<'_>)
                        -> Result<Vec<u8>, String> {
        let mut entries: Vec<(Vec<u8>, bool, Vec<u8>)> = Vec::new();

        if let Some((is_ca, path_len)) = self.is_ca {
            let mut value = Writer::new();
            value.write_sequence(|w| {
                if is_ca { w.write_bool(true); }
                if let Some(limit) = path_len { w.write_u32(limit); }
            });
            // basicConstraints is critical on a CA, per RFC 5280.
            entries.push((oids::BASIC_CONSTRAINTS.to_vec(), is_ca, value.finish()));
        }

        if let Some(bits) = self.key_usage {
            // The BIT STRING holds the bits most-significant first, with the
            // trailing zero bits declared as unused - which is what makes
            // this a DER encoding rather than one of several.
            let mut bytes = vec![(bits >> 8) as u8, bits as u8];
            let mut unused = 0u8;
            while bytes.len() > 1 && *bytes.last().unwrap() == 0 {
                bytes.pop();
            }
            if let Some(&last) = bytes.last() {
                if last != 0 {
                    unused = last.trailing_zeros() as u8;
                }
            }
            let mut body = vec![unused];
            body.extend_from_slice(&bytes);
            let mut value = Writer::new();
            value.write_tlv(Tag::universal(asn1::tag::BIT_STRING), &body);
            entries.push((oids::KEY_USAGE.to_vec(), true, value.finish()));
        }

        if !self.extended_key_usage.is_empty() {
            let mut value = Writer::new();
            value.write_sequence(|w| {
                for oid in &self.extended_key_usage {
                    w.write_oid(oid);
                }
            });
            entries.push((oids::EXT_KEY_USAGE.to_vec(), false, value.finish()));
        }

        if !self.sans.is_empty() {
            let mut value = Writer::new();
            value.write_sequence(|w| {
                for entry in &self.sans {
                    match entry {
                        SanEntry::Email(text) =>
                            w.write_tlv(Tag::context(1, false), text.as_bytes()),
                        SanEntry::Dns(text) =>
                            w.write_tlv(Tag::context(2, false), text.as_bytes()),
                        SanEntry::Uri(text) =>
                            w.write_tlv(Tag::context(6, false), text.as_bytes()),
                        SanEntry::Ip(bytes) =>
                            w.write_tlv(Tag::context(7, false), bytes),
                    }
                }
            });
            entries.push((oids::SUBJECT_ALT_NAME.to_vec(), false, value.finish()));
        }

        if self.key_identifiers {
            let mut value = Writer::new();
            value.write_octet_string(&key_identifier(&self.subject_key)?);
            entries.push((oids::SUBJECT_KEY_ID.to_vec(), false, value.finish()));

            // AuthorityKeyIdentifier ::= SEQUENCE {
            //   keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
            //
            // The [0] is IMPLICIT, so the identifier's bytes go in
            // directly with a context tag - not wrapped in an OCTET
            // STRING inside it. An extra layer here parses as a
            // different, longer identifier that matches nothing.
            let mut value = Writer::new();
            let id = signer.key_identifier()?;
            value.write_sequence(|w| {
                w.write_tlv(Tag::context(0, false), &id);
            });
            entries.push((oids::AUTHORITY_KEY_ID.to_vec(), false,
                          value.finish()));
        }

        entries.extend(self.extra_extensions.iter().cloned());

        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            for (oid, critical, value) in &entries {
                w.write_sequence(|w| {
                    w.write_oid(oid);
                    // DEFAULT FALSE, so the flag is only written when true.
                    if *critical { w.write_bool(true); }
                    w.write_octet_string(value);
                });
            }
        });
        Ok(writer.finish())
    }
}

/// A validity date, in the encoding RFC 5280 4.1.2.5 requires for its
/// year.
///
/// **Through 2049 it must be UTCTime and from 2050 it must be
/// GeneralizedTime.** Not a choice: "CAs conforming to this profile MUST
/// always encode certificate validity dates through the year 2049 as
/// UTCTime; certificate validity dates in 2050 or later MUST be encoded
/// as GeneralizedTime."
///
/// This wrote GeneralizedTime for everything, and every certificate it
/// built was refused by a strict verifier - python-cryptography's path
/// verifier says "validity dates between 1950 and 2049 must be UtcTime"
/// and stops there. Nothing here caught it because our own parser
/// accepts both forms, as the same paragraph requires of a *relying
/// party*, so every test that built a certificate and read it back
/// agreed with itself. `tools/src/bin/diff_name_constraints.rs` found it on
/// its first run, by handing the certificates to somebody else.
///
/// The input is always the 14 digit `YYYYMMDDHHMMSSZ` form; UTCTime is
/// the same string with the century dropped.
fn write_time(w: &mut Writer, text: &str) {
    let year = if text.len() == 15 && text.ends_with('Z') {
        text[..4].parse::<u32>().ok()
    } else {
        // Not a shape this understands; pass it through unchanged rather
        // than mangle it. The caller is inside this crate and the tests
        // pin the shape.
        None
    };
    match year {
        Some(year) if (1950..=2049).contains(&year) =>
            w.write_tlv(Tag::universal(asn1::tag::UTC_TIME),
                        &text.as_bytes()[2..]),
        _ => w.write_tlv(Tag::universal(asn1::tag::GENERALIZED_TIME),
                         text.as_bytes()),
    }
}

fn write_name(writer: &mut Writer, attributes: &[(&'static [u8], String)]) {
    writer.write_sequence(|w| {
        for (oid, value) in attributes {
            w.write_set(|w| {
                w.write_sequence(|w| {
                    w.write_oid(oid);
                    w.write_utf8_string(value);
                });
            });
        }
    });
}

// --------------------------------------------------------------------- CRLs ---

/// One entry for a `CrlBuilder`.
pub struct RevocationEntry {
    /// The serial's content octets, as `Certificate::serial` holds them.
    pub serial: Vec<u8>,
    pub revoked_at: &'static str,
    pub reason: Option<u32>,
    /// A `certificateIssuer` entry extension, for an indirect CRL. The
    /// DER of a `Name`.
    ///
    /// Its whole difficulty is that it **carries forward** to later
    /// entries, so a builder that could only set it on every entry
    /// could not produce the case that catches people.
    pub certificate_issuer: Option<Vec<u8>>,
}

impl RevocationEntry {
    pub fn new(serial: &[u8]) -> RevocationEntry {
        RevocationEntry {
            serial: serial.to_vec(),
            revoked_at: "20230101000000Z",
            reason: None,
            certificate_issuer: None,
        }
    }
}

/// A `CertificateList` to be built.
///
/// Here rather than only in the tests because a CRL is something a
/// private CA has to publish, and because the verifier's tests need
/// lists that are really signed - a CRL whose signature does not check
/// out cannot tell a verifier that checks signatures from one that does
/// not.
pub struct CrlBuilder<'a> {
    pub issuer: Vec<(&'static [u8], String)>,
    pub this_update: &'a str,
    /// RFC 5280 5.1.2 requires a conforming issuer to set this. `None`
    /// makes a CRL that never expires, which exists in the wild.
    pub next_update: Option<&'a str>,
    pub revoked: Vec<RevocationEntry>,
    pub crl_number: Option<Vec<u8>>,
    /// The `BaseCRLNumber` of a deltaCRLIndicator, which makes this a
    /// **delta** CRL and not a complete list of anything.
    pub delta_from: Option<Vec<u8>>,
    /// `(distribution_point, only_user, only_ca, only_some_reasons,
    /// indirect)` for an issuingDistributionPoint.
    pub issuing_distribution_point: Option<IssuingDistributionPointFields>,
    pub extra_extensions: Vec<(Vec<u8>, bool, Vec<u8>)>,
    pub hash: &'a str,
}

#[derive(Clone, Default)]
pub struct IssuingDistributionPointFields {
    /// The `distributionPoint` field, as the URIs of a `fullName`. Empty
    /// means the field is omitted and the CRL covers every point.
    pub distribution_point_uris: Vec<String>,
    pub only_user_certs: bool,
    pub only_ca_certs: bool,
    /// The `ReasonFlags` bits, most significant first, as a BIT STRING
    /// carries them: bit 1 (keyCompromise) is 0x4000.
    pub only_some_reasons: Option<u16>,
    pub indirect: bool,
}

impl<'a> CrlBuilder<'a> {
    pub fn new(issuer_common_name: &str) -> CrlBuilder<'a> {
        CrlBuilder {
            issuer: vec![(oids::COMMON_NAME, issuer_common_name.to_string())],
            this_update: "20230101000000Z",
            next_update: Some("20330101000000Z"),
            revoked: Vec::new(),
            crl_number: Some(vec![1]),
            delta_from: None,
            issuing_distribution_point: None,
            extra_extensions: Vec::new(),
            hash: "sha256",
        }
    }

    pub fn sign(&self, key: &SigningKey<'_>) -> Result<Vec<u8>, String> {
        let tbs = self.write_tbs(key)?;
        let signature = key.sign_signed_data(self.hash, &tbs)?;
        let mut writer = Writer::new();
        writer.write_sequence(|c| {
            c.write_raw(&tbs);
            key.write_algorithm(c, self.hash).expect("algorithm already validated");
            c.write_bit_string(&signature);
        });
        Ok(writer.finish())
    }

    fn write_tbs(&self, key: &SigningKey<'_>) -> Result<Vec<u8>, String> {
        let mut algorithm = Writer::new();
        key.write_algorithm(&mut algorithm, self.hash)?;
        let algorithm = algorithm.finish();

        let extensions = self.write_extensions();

        let mut writer = Writer::new();
        writer.write_sequence(|t| {
            // `version` is OPTIONAL and v2 is encoded as 1. Written
            // whenever there are extensions, because extensions on a v1
            // CRL are not legal.
            if !extensions.is_empty() {
                t.write_u32(1);
            }
            t.write_raw(&algorithm);
            write_name(t, &self.issuer);
            write_time(t, self.this_update);
            if let Some(next) = self.next_update {
                write_time(t, next);
            }
            if !self.revoked.is_empty() {
                t.write_sequence(|w| {
                    for entry in &self.revoked {
                        w.write_sequence(|w| {
                            w.write_tlv(Tag::universal(asn1::tag::INTEGER),
                                        &entry.serial);
                            write_time(w, entry.revoked_at);
                            let has_extensions = entry.reason.is_some()
                                || entry.certificate_issuer.is_some();
                            if has_extensions {
                                w.write_sequence(|w| {
                                    if let Some(reason) = entry.reason {
                                        w.write_sequence(|w| {
                                            w.write_oid(oids::CRL_REASON_CODE);
                                            let mut value = Writer::new();
                                            value.write_tlv(
                                                Tag::universal(asn1::tag::ENUMERATED),
                                                &[reason as u8]);
                                            w.write_octet_string(&value.finish());
                                        });
                                    }
                                    if let Some(name) = &entry.certificate_issuer {
                                        w.write_sequence(|w| {
                                            w.write_oid(oids::CERTIFICATE_ISSUER);
                                            // Critical, as RFC 5280 5.3.3
                                            // requires: an implementation
                                            // ignoring it cannot attribute
                                            // entries to certificates.
                                            w.write_bool(true);
                                            let mut value = Writer::new();
                                            value.write_sequence(|w| {
                                                // [4] directoryName, explicit.
                                                w.write_tlv(Tag::context(4, true), name);
                                            });
                                            w.write_octet_string(&value.finish());
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
            if !extensions.is_empty() {
                t.write_constructed(Tag::context(0, true), |w| w.write_raw(&extensions));
            }
        });
        Ok(writer.finish())
    }

    fn write_extensions(&self) -> Vec<u8> {
        let mut entries: Vec<(Vec<u8>, bool, Vec<u8>)> = Vec::new();

        if let Some(number) = &self.crl_number {
            let mut value = Writer::new();
            value.write_tlv(Tag::universal(asn1::tag::INTEGER), number);
            entries.push((oids::CRL_NUMBER.to_vec(), false, value.finish()));
        }
        if let Some(base) = &self.delta_from {
            let mut value = Writer::new();
            value.write_tlv(Tag::universal(asn1::tag::INTEGER), base);
            // Critical, and that is the point: a reader that ignored it
            // would take a delta for a complete list.
            entries.push((oids::DELTA_CRL_INDICATOR.to_vec(), true, value.finish()));
        }
        if let Some(point) = &self.issuing_distribution_point {
            let mut value = Writer::new();
            value.write_sequence(|w| {
                if !point.distribution_point_uris.is_empty() {
                    // distributionPoint [0] DistributionPointName, whose
                    // fullName [0] is a GeneralNames.
                    w.write_constructed(Tag::context(0, true), |w| {
                        w.write_constructed(Tag::context(0, true), |w| {
                            for uri in &point.distribution_point_uris {
                                w.write_tlv(Tag::context(6, false), uri.as_bytes());
                            }
                        });
                    });
                }
                if point.only_user_certs {
                    w.write_tlv(Tag::context(1, false), &[0xFF]);
                }
                if point.only_ca_certs {
                    w.write_tlv(Tag::context(2, false), &[0xFF]);
                }
                if let Some(flags) = point.only_some_reasons {
                    // A BIT STRING: the leading octet is the number of
                    // unused bits in the last one.
                    let bytes = flags.to_be_bytes();
                    let (content, unused) = if bytes[1] == 0 {
                        (vec![bytes[0]], bytes[0].trailing_zeros().min(7) as u8)
                    } else {
                        (vec![bytes[0], bytes[1]],
                         bytes[1].trailing_zeros().min(7) as u8)
                    };
                    let mut encoded = vec![unused];
                    encoded.extend_from_slice(&content);
                    w.write_tlv(Tag::context(3, false), &encoded);
                }
                if point.indirect {
                    w.write_tlv(Tag::context(4, false), &[0xFF]);
                }
            });
            entries.push((oids::ISSUING_DISTRIBUTION_POINT.to_vec(), true,
                          value.finish()));
        }
        entries.extend(self.extra_extensions.iter().cloned());

        if entries.is_empty() {
            return Vec::new();
        }
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            for (oid, critical, value) in &entries {
                w.write_sequence(|w| {
                    w.write_oid(oid);
                    if *critical { w.write_bool(true); }
                    w.write_octet_string(value);
                });
            }
        });
        writer.finish()
    }
}

// -------------------------------------------------------------- OCSP ---

/// What a responder says about one certificate.
pub enum OcspStatus {
    Good,
    /// `(revocation time, optional CRLReason value)`.
    Revoked(&'static str, Option<u32>),
    Unknown,
}

/// A `BasicOCSPResponse` to be built and signed.
///
/// Here rather than only in the tests because running a responder is a
/// thing a private CA does, and because the checker's tests need
/// responses that are really signed - a response whose signature does
/// not check out cannot tell a verifier that checks signatures from one
/// that does not.
pub struct OcspResponseBuilder<'a> {
    /// The outer, unsigned status. Anything but zero means the response
    /// carries nothing at all.
    pub response_status: u8,
    /// The responder's own name, for `ResponderID ::= byName`.
    pub responder_name: Vec<(&'static [u8], String)>,
    /// Or its key hash, for `byKey`. Takes precedence when set.
    pub responder_key_hash: Option<Vec<u8>>,
    pub produced_at: &'a str,
    /// One entry per certificate answered about: the CertID's four
    /// fields, the status, and the two times.
    pub responses: Vec<OcspSingleResponse>,
    /// Certificates to help the client check the signature - a
    /// delegated responder's own certificate goes here.
    pub certs: Vec<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub hash: &'a str,
}

pub struct OcspSingleResponse {
    /// The hash naming `issuer_name_hash` and `issuer_key_hash`.
    pub cert_id_hash: &'static str,
    pub issuer_name_hash: Vec<u8>,
    pub issuer_key_hash: Vec<u8>,
    pub serial: Vec<u8>,
    pub status: OcspStatus,
    pub this_update: &'static str,
    pub next_update: Option<&'static str>,
    /// `singleExtensions`: OID, critical, DER value. Empty means the
    /// field is omitted.
    pub extensions: Vec<(Vec<u8>, bool, Vec<u8>)>,
}

impl OcspSingleResponse {
    /// The four CertID fields for a certificate, computed the way RFC
    /// 6960 4.1.1 says - which is the part a test must not compute a
    /// second way, or it would agree with whatever the checker got
    /// wrong.
    pub fn about(certificate: &crate::x509::Certificate<'_>,
                 issuer: &crate::x509::Certificate<'_>, hash: &'static str,
                 status: OcspStatus) -> Result<OcspSingleResponse, String> {
        use crate::hash_functions::HashFunction;
        // `AnyHash::new` accepts every hash this library has, and a
        // CertID can name only the four with an OID in `ocsp::hash_oid`;
        // refused here, by the same function the response writer uses.
        ocsp::hash_oid(hash)?;
        let digest = |data: &[u8]| -> Result<Vec<u8>, String> {
            let mut hasher = crate::api::AnyHash::new(hash)?;
            hasher.update(data);
            Ok(hasher.digest())
        };
        // The BIT STRING's contents, which is what the RFC means by
        // "the value (excluding tag and length) of the subject public
        // key field".
        let bits = {
            let mut reader = asn1::Reader::new(issuer.spki);
            let mut sequence = reader.read_sequence()?;
            reader.finish()?;
            sequence.read_any()?;
            let bits = sequence.read_bit_string()?;
            sequence.finish()?;
            bits
        };
        Ok(OcspSingleResponse {
            cert_id_hash: hash,
            issuer_name_hash: digest(issuer.subject.raw)?,
            issuer_key_hash: digest(bits)?,
            serial: certificate.serial.to_vec(),
            status,
            this_update: "20230101000000Z",
            next_update: Some("20330101000000Z"),
            extensions: Vec::new(),
        })
    }
}

impl<'a> OcspResponseBuilder<'a> {
    pub fn new(responder_common_name: &str) -> OcspResponseBuilder<'a> {
        OcspResponseBuilder {
            response_status: 0,
            responder_name: vec![(oids::COMMON_NAME,
                                  responder_common_name.to_string())],
            responder_key_hash: None,
            produced_at: "20230101000000Z",
            responses: Vec::new(),
            certs: Vec::new(),
            nonce: None,
            hash: "sha256",
        }
    }

    pub fn sign(&self, key: &SigningKey<'_>) -> Result<Vec<u8>, String> {
        let mut writer = Writer::new();
        if self.response_status != 0 {
            // An error status carries no responseBytes at all, which is
            // the shape a test of "an unsigned error is not an answer"
            // needs.
            writer.write_sequence(|w| {
                w.write_tlv(Tag::universal(asn1::tag::ENUMERATED),
                            &[self.response_status]);
            });
            return Ok(writer.finish());
        }

        let basic = self.sign_basic(key)?;
        writer.write_sequence(|w| {
            w.write_tlv(Tag::universal(asn1::tag::ENUMERATED), &[0]);
            w.write_constructed(Tag::context(0, true), |w| {
                w.write_sequence(|w| {
                    w.write_oid(oids::OCSP_BASIC);
                    w.write_octet_string(&basic);
                });
            });
        });
        Ok(writer.finish())
    }

    /// The `BasicOCSPResponse` alone, which is what gets stapled.
    pub fn sign_basic(&self, key: &SigningKey<'_>) -> Result<Vec<u8>, String> {
        // `cert_id_hash` is a public field, so `about`'s check can be
        // bypassed; the names are checked again here, where there is a
        // `Result` to return, rather than inside `write_response_data`'s
        // closures, where there is not.
        for single in &self.responses {
            ocsp::hash_oid(single.cert_id_hash)?;
        }
        let tbs = self.write_response_data();
        let signature = key.sign_signed_data(self.hash, &tbs)?;
        // The algorithm identifier is built first, because
        // `write_sequence` takes a closure that cannot fail and
        // `write_algorithm` can.
        let mut algorithm = Writer::new();
        key.write_algorithm(&mut algorithm, self.hash)?;
        let algorithm = algorithm.finish();

        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_raw(&tbs);
            w.write_raw(&algorithm);
            w.write_bit_string(&signature);
            if !self.certs.is_empty() {
                w.write_constructed(Tag::context(0, true), |w| {
                    w.write_sequence(|w| {
                        for der in &self.certs {
                            w.write_raw(der);
                        }
                    });
                });
            }
        });
        Ok(writer.finish())
    }

    fn write_response_data(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_sequence(|data| {
            // version [0] EXPLICIT DEFAULT v1: omitted, because DER
            // forbids encoding a DEFAULT at its default value.
            match &self.responder_key_hash {
                Some(hash) => data.write_constructed(Tag::context(2, true),
                                                     |w| w.write_octet_string(hash)),
                None => data.write_constructed(Tag::context(1, true),
                                               |w| write_name(w, &self.responder_name)),
            }
            write_time_generalized(data, self.produced_at);
            data.write_sequence(|list| {
                for single in &self.responses {
                    list.write_sequence(|w| {
                        w.write_sequence(|id| {
                            id.write_sequence(|algorithm| {
                                // Validated in `sign_basic` before this
                                // closure, which cannot fail, is entered.
                                algorithm.write_oid(
                                    ocsp::hash_oid(single.cert_id_hash)
                                        .expect("hash name validated by sign_basic"));
                                algorithm.write_null();
                            });
                            id.write_octet_string(&single.issuer_name_hash);
                            id.write_octet_string(&single.issuer_key_hash);
                            id.write_tlv(Tag::universal(asn1::tag::INTEGER),
                                         &single.serial);
                        });
                        match &single.status {
                            // good [0] IMPLICIT NULL: no content octets.
                            OcspStatus::Good =>
                                w.write_tlv(Tag::context(0, false), &[]),
                            OcspStatus::Revoked(at, reason) => {
                                let mut info = Writer::new();
                                write_time_generalized(&mut info, at);
                                if let Some(reason) = reason {
                                    info.write_constructed(
                                        Tag::context(0, true), |w| {
                                        w.write_tlv(
                                            Tag::universal(asn1::tag::ENUMERATED),
                                            &[*reason as u8]);
                                    });
                                }
                                // revoked [1] IMPLICIT RevokedInfo: the
                                // SEQUENCE's tag is replaced, so the
                                // content is its fields directly.
                                w.write_tlv(Tag::context(1, true), &info.finish());
                            }
                            OcspStatus::Unknown =>
                                w.write_tlv(Tag::context(2, false), &[]),
                        }
                        write_time_generalized(w, single.this_update);
                        if let Some(next) = single.next_update {
                            w.write_constructed(Tag::context(0, true), |w| {
                                write_time_generalized(w, next);
                            });
                        }
                        if !single.extensions.is_empty() {
                            w.write_constructed(Tag::context(1, true), |w| {
                                w.write_sequence(|list| {
                                    for (oid, critical, value) in &single.extensions {
                                        list.write_sequence(|w| {
                                            w.write_oid(oid);
                                            if *critical { w.write_bool(true); }
                                            w.write_octet_string(value);
                                        });
                                    }
                                });
                            });
                        }
                    });
                }
            });
            if let Some(nonce) = &self.nonce {
                data.write_constructed(Tag::context(1, true), |w| {
                    w.write_sequence(|list| {
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
        writer.finish()
    }
}

/// OCSP's times are **always** GeneralizedTime, whatever the year - RFC
/// 6960's ASN.1 says so directly, where a certificate's Validity is a
/// `Time` CHOICE and switches at 2050.
fn write_time_generalized(w: &mut Writer, text: &str) {
    w.write_tlv(Tag::universal(asn1::tag::GENERALIZED_TIME), text.as_bytes());
}

/// Key usage bits, for `CertificateBuilder::key_usage`.
pub mod key_usage {
    pub const DIGITAL_SIGNATURE: u16 = 0x8000;
    pub const NON_REPUDIATION: u16 = 0x4000;
    pub const KEY_ENCIPHERMENT: u16 = 0x2000;
    pub const DATA_ENCIPHERMENT: u16 = 0x1000;
    pub const KEY_AGREEMENT: u16 = 0x0800;
    pub const KEY_CERT_SIGN: u16 = 0x0400;
    pub const CRL_SIGN: u16 = 0x0200;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::{tests_support, Certificate};

    /// A CertID hash this library can compute but has no OID for is an
    /// error from `about` and from `sign`, not a panic.
    ///
    /// What was wrong: `about` validated the name only through
    /// `AnyHash::new`, which accepts `"md5"` or `"sha3-256"`, and the
    /// builder's own copy of `hash_oid` then panicked inside a
    /// `write_sequence` closure in `sign`. The existing OCSP tests all
    /// used `"sha1"` or `"sha256"`. There is now one `hash_oid`, in
    /// `ocsp`, returning `Result`; `about` calls it, and `sign_basic`
    /// calls it again for every response because `cert_id_hash` is a
    /// public field.
    #[test]
    fn test_an_ocsp_cert_id_hash_without_an_oid_is_an_error_not_a_panic() {
        let chain = tests_support::chain(|_| {}, |_| {}, |_| {});
        let leaf = Certificate::parse(&chain.leaf).unwrap();
        let issuer = Certificate::parse(&chain.intermediate).unwrap();

        match OcspSingleResponse::about(&leaf, &issuer, "md5", OcspStatus::Good) {
            Err(error) => assert!(error.contains("No OCSP CertID hash OID"), "{}", error),
            Ok(_) => panic!("md5 has no CertID OID and must be refused"),
        }

        // Set directly, past `about`.
        let mut single = OcspSingleResponse::about(&leaf, &issuer, "sha256",
                                                   OcspStatus::Good).unwrap();
        single.cert_id_hash = "sha3-256";
        let mut builder = OcspResponseBuilder::new("Test Intermediate");
        builder.responses = vec![single];
        let error = builder.sign(&chain.intermediate_key.signing()).unwrap_err();
        assert!(error.contains("No OCSP CertID hash OID"), "{}", error);
    }

    /// A certificate signed through `SigningKey::External` by a signer
    /// that is the library's own key is **byte for byte** the one the key
    /// signs directly - RSA PKCS#1 v1.5, RFC 6979 ECDSA and Ed25519 are
    /// all deterministic - so the external route writes the same
    /// algorithm identifier, parameters, key identifiers and signature
    /// encoding. And it verifies.
    #[test]
    fn test_an_external_signer_makes_the_same_certificate() {
        let rsa = crate::publickey_ciphers::rsa::RsaPrivateKey::generate(1024).unwrap();
        let ec = tests_support::TestKey::new();
        let seed = [7u8; 32];
        let ed_public = crate::api::eddsa_public_key("ed25519", &seed).unwrap();
        let cases: [(SigningKey, SubjectKey, &str); 4] = [
            (SigningKey::Rsa(&rsa), SubjectKey::Rsa { n: &rsa.public.n, e: &rsa.public.e },
             "sha256"),
            (SigningKey::Rsa(&rsa), SubjectKey::Rsa { n: &rsa.public.n, e: &rsa.public.e },
             "sha384"),
            (ec.signing(), ec.subject(), "sha256"),
            (SigningKey::Eddsa { name: "ed25519", seed: &seed },
             SubjectKey::Eddsa { name: "ed25519", key: &ed_public }, "sha512"),
        ];
        for (inner, public, hash) in cases {
            let mut builder = CertificateBuilder::new("external", public);
            builder.hash = hash;
            builder.key_identifiers = true;
            let direct = builder.sign(&inner).unwrap();
            let calls = std::cell::Cell::new(0);
            // `SigningKey::sign` is the prehash route; EdDSA signs the
            // message whole, through its own key.
            let sign = |hash: &str, tbs: &[u8]| {
                calls.set(calls.get() + 1);
                match inner {
                    SigningKey::Eddsa { name, seed } =>
                        crate::api::EddsaKey::from_private(name, seed)?.sign(tbs, &[]),
                    _ => inner.sign(hash, tbs),
                }
            };
            let external = builder.sign(&SigningKey::External { public, sign: &sign }).unwrap();
            assert_eq!(external, direct, "{hash}");
            assert_eq!(calls.get(), 1);
            let certificate = Certificate::parse(&external).unwrap();
            let policy = crate::x509::verify::Policy { min_rsa_bits: 1024,
                                                       ..Default::default() };
            crate::x509::verify::verify_signature(&certificate, &certificate, &policy).unwrap();
        }
    }

    /// Nothing checks what the signer returns: a wrong signature makes a
    /// certificate that verifies nowhere, and a failing signer is an
    /// error. An external key of a kind with no signature algorithm here
    /// is refused before the signer is called.
    #[test]
    fn test_an_external_signer_is_trusted_and_its_errors_pass_through() {
        let ec = tests_support::TestKey::new();
        let builder = CertificateBuilder::new("external", ec.subject());
        let garbage = |_: &str, _: &[u8]| Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        let der = builder.sign(&SigningKey::External { public: ec.subject(), sign: &garbage })
            .unwrap();
        let certificate = Certificate::parse(&der).unwrap();
        assert!(crate::x509::verify::verify_signature(&certificate, &certificate,
                                                      &Default::default()).is_err());

        let failing = |_: &str, _: &[u8]| Err("the card is gone".to_string());
        let error = builder.sign(&SigningKey::External { public: ec.subject(), sign: &failing })
            .unwrap_err();
        assert!(error.contains("the card is gone"), "{error}");

        // `SigningKey::sign` hands the signer the hash name and the
        // message itself, not a digest of it.
        let echo = |hash: &str, message: &[u8]| Ok([hash.as_bytes(), message].concat());
        let external = SigningKey::External { public: ec.subject(), sign: &echo };
        assert_eq!(external.sign("sha256", b"tbs").unwrap(), b"sha256tbs");
        assert!(SigningKey::External { public: ec.subject(), sign: &failing }
            .sign("sha256", b"tbs").unwrap_err().contains("the card is gone"));

        let mut sha3 = CertificateBuilder::new("external", ec.subject());
        sha3.hash = "sha3-256";
        let never = |_: &str, _: &[u8]| -> Result<Vec<u8>, String> { panic!("signed anyway") };
        assert!(sha3.sign(&SigningKey::External { public: ec.subject(), sign: &never }).is_err());
    }

    /// The two key identifiers are computed from the two keys, and the
    /// child's authority identifier equals the parent's subject one.
    ///
    /// That equality is the whole job: an identifier is a name a
    /// verifier looks a certificate up by, so the only mistake that
    /// matters is the two ends of one link disagreeing. The test
    /// therefore checks a *chain*, not a certificate - a single
    /// certificate's identifiers agree with themselves under any of the
    /// three plausible readings of "the subject public key field".
    #[test]
    fn test_the_key_identifiers_link_a_chain() {
        let root_key = tests_support::TestKey::new();
        let leaf_key = tests_support::TestKey::new();

        let mut root = CertificateBuilder::new("Test Root", root_key.subject());
        root.is_ca = Some((true, None));
        root.key_identifiers = true;
        let root_der = root.sign(&root_key.signing()).unwrap();

        let mut leaf = CertificateBuilder::new("leaf.test", leaf_key.subject());
        leaf.serial = vec![2];
        leaf.issuer = vec![(oids::COMMON_NAME, "Test Root".to_string())];
        leaf.key_identifiers = true;
        let leaf_der = leaf.sign(&root_key.signing()).unwrap();

        let root_cert = Certificate::parse(&root_der).unwrap();
        let leaf_cert = Certificate::parse(&leaf_der).unwrap();

        let root_ski = root_cert.extensions.subject_key_id
            .expect("the root has no subjectKeyIdentifier");
        let leaf_aki = leaf_cert.extensions.authority_key_id
            .expect("the leaf has no authorityKeyIdentifier");

        assert_eq!(root_ski, leaf_aki,
                   "the leaf names an issuer key that is not the root's");
        assert_eq!(root_ski.len(), 20, "not a SHA-1");

        // A self-signed root names itself, which is what makes it a
        // root rather than a certificate whose issuer is missing.
        assert_eq!(root_cert.extensions.authority_key_id, Some(root_ski));

        // And the leaf's own identifier is its own key's, not the
        // root's - the obvious way to get this wrong is to compute one
        // identifier and write it into both fields.
        let leaf_ski = leaf_cert.extensions.subject_key_id
            .expect("the leaf has no subjectKeyIdentifier");
        assert_ne!(leaf_ski, leaf_aki,
                   "the leaf's subject and authority identifiers are the \
                    same, so one of them is the wrong key's");
        assert_eq!(leaf_ski,
                   key_identifier(&leaf_key.subject()).unwrap().as_slice());
    }

    /// The signing scalar is checked before the identifier is computed,
    /// because the identifier is computed before `sign` checks it. A
    /// scalar wider than the field used to panic in the ladder here.
    #[test]
    fn test_a_key_identifier_refuses_a_scalar_outside_the_group() {
        let curve = crate::ec::curves::p256();
        let wide = BigUint::one().shl(64 * 10);
        for private in [BigUint::zero(), curve.n.clone(), wide] {
            let key = SigningKey::Ec { curve: &curve, private: &private };
            let reason = key.key_identifier().unwrap_err();
            assert!(reason.contains("[1, n)"), "{}", reason);
        }
    }

    /// Off by default, so the bytes of every existing certificate are
    /// unchanged.
    #[test]
    fn test_the_key_identifiers_are_not_written_unless_asked() {
        let key = tests_support::TestKey::new();
        let builder = CertificateBuilder::new("leaf.test", key.subject());
        let der = builder.sign(&key.signing()).unwrap();
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(certificate.extensions.subject_key_id, None);
        assert_eq!(certificate.extensions.authority_key_id, None);
    }

    /// **RFC 5280 4.1.2.5: a validity date through 2049 must be UTCTime
    /// and one from 2050 must be GeneralizedTime.**
    ///
    /// This wrote GeneralizedTime for both, and every certificate it
    /// built was refused outright by a strict verifier. Nothing here
    /// noticed because our own parser accepts either form - which the
    /// same paragraph requires of a relying party - so the encoder and
    /// the parser agreed with each other and with nobody else. It was
    /// found by `tools/src/bin/diff_name_constraints.rs` on its first run,
    /// the moment a certificate was handed to somebody else's verifier.
    ///
    /// The test reads the tag out of the DER rather than round-tripping
    /// through our parser, because a round trip is exactly what missed
    /// it.
    #[test]
    fn test_validity_dates_use_the_encoding_their_year_requires() {
        fn validity_tags(der: &[u8]) -> (u32, u32) {
            let mut reader = crate::asn1::Reader::new(der);
            let mut certificate = reader.read_sequence().unwrap();
            let mut tbs = certificate.read_sequence().unwrap();
            tbs.read_any().unwrap();                 // version [0]
            tbs.read_any().unwrap();                 // serial
            tbs.read_any().unwrap();                 // signature algorithm
            tbs.read_any().unwrap();                 // issuer
            let mut validity = tbs.read_sequence().unwrap();
            let (before, _) = validity.read_any().unwrap();
            let (after, _) = validity.read_any().unwrap();
            (before.number, after.number)
        }

        let key = tests_support::TestKey::new();

        let der = tests_support::Builder {
            not_before: "20200101000000Z".to_string(),
            not_after: "20400101000000Z".to_string(),
            ..Default::default()
        }.issue(&key, &key, "leaf.test", 1);
        assert_eq!(validity_tags(&der),
                   (asn1::tag::UTC_TIME, asn1::tag::UTC_TIME),
                   "a date before 2050 must be UTCTime");

        // 2049 and 2050 are the two sides of the boundary, and an
        // off-by-one in the comparison puts one of them on the wrong
        // side while leaving every ordinary certificate right.
        let der = tests_support::Builder {
            not_before: "20491231235959Z".to_string(),
            not_after: "20500101000000Z".to_string(),
            ..Default::default()
        }.issue(&key, &key, "leaf.test", 1);
        assert_eq!(validity_tags(&der),
                   (asn1::tag::UTC_TIME, asn1::tag::GENERALIZED_TIME),
                   "2049 is UTCTime and 2050 is GeneralizedTime");

        // And whichever form it took, our own parser reads the same
        // instant back - which is what let the bug hide. The two are one
        // second apart, so a UTCTime whose century was guessed wrong
        // would show up as a fifty or a hundred and fifty year gap
        // rather than as a parse failure.
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(certificate.not_before, 2_524_607_999);
        assert_eq!(certificate.not_after, 2_524_608_000);
    }
}
