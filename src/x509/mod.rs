/*
X.509 certificates: parsing, then verification.

A certificate arrives from whoever we are talking to, before anything about
them has been established. So this module's job is to turn untrusted bytes
into a structure, carefully, and then to answer one question honestly: does
this chain say what it claims to say.

Parsing and deciding are kept apart on purpose. `Certificate::parse` reads
and does not judge - it will happily parse an expired certificate, or one
signed with MD5, because refusing at parse time hides the reason from the
caller and makes it impossible to build tools that inspect bad certificates.
`verify.rs` is where policy lives.

Four things that are parsing decisions rather than policy, because getting
them wrong cannot be fixed later:

  * **The TBS bytes are kept, not re-encoded.** A signature covers the exact
    bytes that arrived. Verifying a re-encoding verifies our understanding
    of the certificate instead of the certificate, and the two differ
    precisely when an attacker wants them to.

  * **Text with an embedded NUL is refused - after decoding, not
    before.** `www.good.com\0.evil.com` is a valid ASN.1 string, and a C
    library that hands it to strcmp sees only the first part. Moxie
    Marlinspike, 2009. We are not C, but the name leaves here and goes
    somewhere, so it does not leave here.

    The check is in `Attribute::text` and refuses that one attribute; it
    is not a parse error, and it is not applied to the encoded bytes. It
    used to be both, and a live GOST server found what that cost: a
    `BMPString` is UTF-16, so every ASCII character in one is `00 xx`,
    and checking the encoded bytes refused every certificate carrying a
    `BMPString` anywhere in a name.

  * **A duplicate extension is an error.** RFC 5280 forbids it, and where
    duplicates are tolerated the question becomes which one is enforced -
    an attacker adds a second basicConstraints and hopes the checker reads
    the first while the parser read the second.

  * **An unrecognised critical extension is recorded.** Critical means "if
    you do not understand this, do not use this certificate". That refusal
    happens in verification, but the parser has to notice.

See docs/pitfalls.md section 6.
*/

pub mod builder;
pub mod crl;
pub mod encrypted_key;
pub mod name_constraints;
pub mod ocsp;
pub mod oids;
pub mod private_key;
pub mod verify;

#[cfg(test)]
pub mod tests_support;
#[cfg(test)]
mod rfc9881_tests;

use crate::asn1::{self, Oid, Reader, Tag};
use crate::bignum::BigUint;

// ------------------------------------------------------------- algorithms ---

/// A signature algorithm, as a pair of what to verify with and what to hash
/// with. Anything not recognised is kept rather than rejected, so a caller
/// can report "signed with something I do not know" rather than "malformed".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignatureAlgorithm {
    RsaPkcs1(&'static str),
    Ecdsa(&'static str),
    /// DSA (RFC 3279, RFC 5758) with the named hash. The signature is a
    /// DER `Dss-Sig-Value`, the same shape as ECDSA's.
    Dsa(&'static str),
    /// GOST R 34.10-2012 with Streebog, RFC 9215. The hash size follows
    /// the key size and the OID names both at once, so there is one
    /// variant carrying the digest rather than a hash name: 256 and 512
    /// are not interchangeable here the way SHA-256 and SHA-384 are
    /// under ECDSA.
    Gost(usize),
    /// GOST R 34.10-2001 with GOST R 34.11-94, RFC 4357. The signature
    /// on a certificate for the 0x0081 cipher suite.
    ///
    /// A variant of its own rather than `Gost(256)` with a different
    /// hash, because the *digest* is what differs and `Gost`'s number
    /// is the digest: Streebog-256 and GOST R 34.11-94 are both 256
    /// bits and are different functions. One carrying both would be a
    /// number that means two things.
    Gost2001,
    /// EdDSA, RFC 8410. The name is `ed25519` or `ed448`.
    ///
    /// **It carries no hash name and cannot.** Every other variant here
    /// names a digest that the caller computes and then verifies
    /// against; EdDSA hashes internally, twice, with a prefix that
    /// depends on the variant, so there is no digest to compute in
    /// advance and `hash_name()` returns `None`. A verifier that hashed
    /// first and passed the digest in would be signing the hash of the
    /// hash - which is self-consistent and matches nobody.
    Eddsa(&'static str),
    /// ML-DSA, RFC 9881. The name is FIPS 204's: `ML-DSA-44`, `ML-DSA-65`
    /// or `ML-DSA-87`.
    ///
    /// Like EdDSA it carries no hash name: the pure form of ML-DSA signs
    /// the message itself, with an empty context string (RFC 9881
    /// section 3). HashML-DSA has OIDs of its own, and RFC 9881 section
    /// 8.3 keeps them out of certificates.
    MlDsa(&'static str),
    /// Recognised as a signature algorithm, not implemented here. PSS is the
    /// one that matters, and certificate verification does not handle it yet.
    Unsupported(&'static str),
    Unknown,
}

impl SignatureAlgorithm {
    fn from_oid(oid: Oid<'_>) -> SignatureAlgorithm {
        let bytes = oid.as_bytes();
        // MD2, MD5 and SHA-1 signatures are here because old certificates
        // exist and this library does not pretend otherwise. Whether to
        // accept one is a policy question, and `verify` answers it.
        if bytes == oids::SHA256_WITH_RSA { SignatureAlgorithm::RsaPkcs1("sha256") }
        else if bytes == oids::SHA384_WITH_RSA { SignatureAlgorithm::RsaPkcs1("sha384") }
        else if bytes == oids::SHA512_WITH_RSA { SignatureAlgorithm::RsaPkcs1("sha512") }
        else if bytes == oids::SHA224_WITH_RSA { SignatureAlgorithm::RsaPkcs1("sha224") }
        else if bytes == oids::SHA1_WITH_RSA { SignatureAlgorithm::RsaPkcs1("sha1") }
        else if bytes == oids::MD5_WITH_RSA { SignatureAlgorithm::RsaPkcs1("md5") }
        else if bytes == oids::ECDSA_WITH_SHA256 { SignatureAlgorithm::Ecdsa("sha256") }
        else if bytes == oids::ECDSA_WITH_SHA384 { SignatureAlgorithm::Ecdsa("sha384") }
        else if bytes == oids::ECDSA_WITH_SHA512 { SignatureAlgorithm::Ecdsa("sha512") }
        else if bytes == oids::ECDSA_WITH_SHA224 { SignatureAlgorithm::Ecdsa("sha224") }
        else if bytes == oids::ECDSA_WITH_SHA1 { SignatureAlgorithm::Ecdsa("sha1") }
        else if bytes == oids::DSA_WITH_SHA1 { SignatureAlgorithm::Dsa("sha1") }
        else if bytes == oids::DSA_WITH_SHA224 { SignatureAlgorithm::Dsa("sha224") }
        else if bytes == oids::DSA_WITH_SHA256 { SignatureAlgorithm::Dsa("sha256") }
        else if bytes == oids::DSA_WITH_SHA384 { SignatureAlgorithm::Dsa("sha384") }
        else if bytes == oids::DSA_WITH_SHA512 { SignatureAlgorithm::Dsa("sha512") }
        else if bytes == oids::GOST3410_12_256_WITH_DIGEST { SignatureAlgorithm::Gost(256) }
        else if bytes == oids::GOST3410_12_512_WITH_DIGEST { SignatureAlgorithm::Gost(512) }
        else if bytes == oids::GOST3411_94_WITH_GOST3410_2001 { SignatureAlgorithm::Gost2001 }
        // GOST R 34.10-94 is a discrete log scheme over a prime field
        // rather than a curve, and nothing here does that arithmetic.
        // Named so a certificate using it says which algorithm is
        // missing instead of reading as an unknown OID.
        else if bytes == oids::GOST3411_94_WITH_GOST3410_94 {
            SignatureAlgorithm::Unsupported("GOST R 34.10-94") }
        // **The same OID is the key algorithm and the signature
        // algorithm.** RFC 8410 section 3: there is no
        // "Ed25519 with SHA-512" arc, because the hash is not a
        // parameter of the scheme.
        else if bytes == oids::ID_ED25519 { SignatureAlgorithm::Eddsa("ed25519") }
        else if bytes == oids::ID_ED448 { SignatureAlgorithm::Eddsa("ed448") }
        // The same shape as EdDSA: one OID per parameter set, serving
        // as key and signature algorithm both.
        else if let Some(name) = ml_dsa_parameter_set(bytes) { SignatureAlgorithm::MlDsa(name) }
        else if bytes == oids::RSASSA_PSS { SignatureAlgorithm::Unsupported("RSASSA-PSS") }
        else if bytes == oids::MD2_WITH_RSA { SignatureAlgorithm::Unsupported("MD2-with-RSA") }
        else { SignatureAlgorithm::Unknown }
    }

    pub fn hash_name(&self) -> Option<&'static str> {
        match self {
            SignatureAlgorithm::RsaPkcs1(h) | SignatureAlgorithm::Ecdsa(h)
                | SignatureAlgorithm::Dsa(h) => Some(h),
            // Streebog is not in `AnyHash`'s naming the way the SHA
            // family is, and the GOST digest is read little endian
            // afterwards - so the hash is not separable from the
            // algorithm here and the caller must go through the GOST
            // path rather than hashing generically.
            SignatureAlgorithm::Gost(_) | SignatureAlgorithm::Gost2001 => None,
            // EdDSA and ML-DSA hash the message themselves. See the
            // variants' notes.
            SignatureAlgorithm::Eddsa(_) | SignatureAlgorithm::MlDsa(_) => None,
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            SignatureAlgorithm::RsaPkcs1(h) => format!("RSA PKCS#1 v1.5 with {}", h),
            SignatureAlgorithm::Ecdsa(h) => format!("ECDSA with {}", h),
            SignatureAlgorithm::Dsa(h) => format!("DSA with {}", h),
            SignatureAlgorithm::Gost(bits) =>
                format!("GOST R 34.10-2012 ({} bit) with Streebog-{}", bits, bits),
            SignatureAlgorithm::Gost2001 =>
                "GOST R 34.10-2001 with GOST R 34.11-94".to_string(),
            SignatureAlgorithm::Eddsa(name) => format!("EdDSA ({})", name),
            SignatureAlgorithm::MlDsa(name) => name.to_string(),
            SignatureAlgorithm::Unsupported(name) => format!("{} (not implemented)", name),
            SignatureAlgorithm::Unknown => "an unrecognised algorithm".to_string(),
        }
    }
}

/// A subject public key, as the certificate carries it.
#[derive(Clone, Debug)]
pub enum PublicKey<'a> {
    Rsa { n: BigUint, e: BigUint },
    /// The curve name as this library spells it, plus the SEC1 point.
    Ec { curve: &'static str, point: &'a [u8] },
    /// An EC key on a curve this library does not implement.
    ///
    /// Separate from `Unsupported` because the algorithm *is* supported and
    /// the curve is the part we cannot do arithmetic on, which is what the
    /// error message has to say. Carried rather than refused for the same
    /// reason as `Unsupported`: see the note on `Certificate::parse`.
    ///
    /// `family` says **which** kind of key it was, because the OID
    /// alone does not: `id-ecPublicKey` and `id-GostR3410-2001` both
    /// name their curve in the algorithm parameters, and both end up
    /// here. A live server reported
    /// *"an EC key on unsupported curve 1.2.643.2.2.36.0"* for a curve
    /// this library has had all along under a GOST name - and the
    /// message sent whoever read it to the wrong table. Same lesson as
    /// `TrustStore::skipped`: a value with its reason discarded cannot
    /// tell two opposite remedies apart.
    UnsupportedCurve { oid: Oid<'a>, family: &'static str },
    /// A GOST R 34.10-2012 key: the curve its parameter set names, and
    /// the raw 64 or 128 bytes from inside the OCTET STRING.
    ///
    /// Separate from `Ec` rather than another curve under it, because
    /// the encoding is different at every level - the coordinates are
    /// little endian and wrapped twice, there is no SEC1 point format
    /// byte, and the curve comes from a parameter set OID rather than a
    /// curve OID. Folding it into `Ec` would mean `point` meant two
    /// things depending on which curve it was.
    Gost {
        curve: &'static str,
        x: BigUint,
        y: BigUint,
        /// **The parameter set OID exactly as the certificate wrote
        /// it**, which is not recoverable from `curve`.
        ///
        /// `oids::gost_curve_for` is many-to-one: twelve OIDs name
        /// seven curves, because RFC 4357's CryptoPro sets, TC 26's
        /// 2012 renumbering (shifted by one) and RFC 4357's two
        /// *exchange* sets are three namings of overlapping curves.
        /// `XchA` is CryptoPro-A to the digit and TC 26's `paramSetB`
        /// is CryptoPro-A as well.
        ///
        /// So the inverse is a **choice**, and a client that made it
        /// echoed a different OID in its ClientKeyExchange from the one
        /// the server had sent. The curves were identical and the bytes
        /// were not, and CryptoPro answers `decode_error`. Reported from
        /// a real server on `XchA`; see `docs/pitfalls.md` 7o.
        ///
        /// Kept as the bytes that arrived, because the only correct
        /// thing to echo is what was sent.
        param_set: Oid<'a>,
        /// **The whole `AlgorithmIdentifier` as the certificate wrote
        /// it**, OID and parameters together.
        ///
        /// This is what a ClientKeyExchange's ephemeral key carries, and
        /// it carries it *verbatim*. All five suites' handshakes in
        /// `tests/transcripts/gost_handshakes.txt` show OpenSSL's
        /// ephemeral key repeating the server certificate's
        /// AlgorithmIdentifier byte for byte - the algorithm OID, the
        /// parameter set and the `digestParamSet` - and changing only
        /// the point.
        ///
        /// Copying it settles three things that were separate decisions
        /// before, each of which could be made wrongly: which of the
        /// several OIDs naming this curve to use, whether the algorithm
        /// is the 2001 one or a 2012 one, and whether to include the
        /// `digestParamSet` that RFC 9215 4.2 deprecates and RFC 9189's
        /// own example carries. The answer to all three is "whatever the
        /// server said".
        algorithm_id: &'a [u8],
        /// Which standard's algorithm OID the certificate used:
        /// `id-GostR3410-2001` rather than one of the 2012 pair.
        ///
        /// **The key bytes are identical either way**, which is why
        /// this is here: a 2012 certificate and a 2001 one can carry
        /// the same point on the same curve, and the only thing that
        /// says which cipher suite may use it is this OID. Without it
        /// a client would accept either for either, and complete a
        /// handshake it had not authenticated the way the suite
        /// specifies.
        legacy: bool,
    },
    /// An EdDSA key, RFC 8410. `curve` is `ed25519` or `ed448` and
    /// `key` is the raw encoded point - 32 or 57 bytes.
    ///
    /// **There is nothing inside the BIT STRING.** Every other key here
    /// wraps something: RSA a SEQUENCE, EC a SEC1 point with a format
    /// byte, GOST an OCTET STRING holding little endian coordinates.
    /// RFC 8410 section 4 says the subjectPublicKey *is* the key, and a
    /// parser written from the neighbouring branches will try to read a
    /// structure that is not there.
    Eddsa { curve: &'static str, key: &'a [u8] },
    /// An ML-DSA key, RFC 9881. `parameter_set` is FIPS 204's name and
    /// `key` the raw public key - 1312, 1952 or 2592 bytes.
    ///
    /// The BIT STRING is the key, as for EdDSA: RFC 9881 section 4
    /// puts FIPS 204's own encoding there with no ASN.1 around it.
    MlDsa { parameter_set: &'static str, key: &'a [u8] },
    /// A DSA key, RFC 3279 section 2.3.2: the group from the
    /// AlgorithmIdentifier's Dss-Parms and `y` from the BIT STRING.
    ///
    /// `parameters` is `None` when the certificate leaves them out, which
    /// RFC 3279 allows: the key then uses its issuer's group. Carried
    /// rather than refused, so the rest of the certificate can still be
    /// read and the verifier can say what it cannot do.
    Dsa { parameters: Option<(BigUint, BigUint, BigUint)>, y: BigUint },
    /// A key we can carry but not use. Keeping it means a caller can still
    /// read the rest of the certificate and report why it is unusable.
    Unsupported { algorithm: &'a [u8] },
}

// ------------------------------------------------------------------- names ---

/// One attribute-value pair inside a distinguished name.
#[derive(Clone, Debug)]
pub struct Attribute<'a> {
    pub oid: Oid<'a>,
    /// The ASN.1 string tag, which name comparison sometimes cares about.
    pub value_tag: u32,
    pub value: &'a [u8],
}

impl<'a> Attribute<'a> {
    /// The short label used in a printed DN, or the dotted OID.
    pub fn label(&self) -> String {
        let bytes = self.oid.as_bytes();
        if bytes == oids::COMMON_NAME { "CN".to_string() }
        else if bytes == oids::COUNTRY { "C".to_string() }
        else if bytes == oids::ORGANIZATION { "O".to_string() }
        else if bytes == oids::ORGANIZATIONAL_UNIT { "OU".to_string() }
        else if bytes == oids::LOCALITY { "L".to_string() }
        else if bytes == oids::STATE_OR_PROVINCE { "ST".to_string() }
        else if bytes == oids::EMAIL_ADDRESS { "emailAddress".to_string() }
        else if bytes == oids::DOMAIN_COMPONENT { "DC".to_string() }
        else if bytes == oids::SERIAL_NUMBER { "serialNumber".to_string() }
        else { self.oid.to_string() }
    }

    /// The value as text. `BMPString` is UTF-16, which is why this is not
    /// just a `from_utf8`.
    ///
    /// **The embedded-NUL check is here, on the decoded text, and it
    /// used to be in `Name::parse` on the encoded bytes.** That was
    /// wrong twice over and a live GOST server found both halves:
    ///
    ///   * A `BMPString` is UTF-16, so every ASCII character in one is
    ///     `00 xx`. Checking the encoded bytes therefore refused
    ///     **every** certificate with a `BMPString` anywhere in a name,
    ///     which is a common encoding for Cyrillic - so it refused
    ///     exactly the certificates this library exists to read, and
    ///     the decoder five lines below was already right.
    ///   * And it was a *parse* error, where the rule here is that
    ///     `Certificate::parse` reads and `verify` judges. A NUL in an
    ///     organisation name is not a reason to make the whole
    ///     certificate unreadable; it is a reason not to trust that one
    ///     string. `Name::get` returns `None` for an attribute whose
    ///     text is refused, so a CN carrying one cannot match a
    ///     hostname - which is the only place the attack lives.
    ///
    /// The attack is still refused. `www.good.com\0.evil.com` is a valid
    /// ASN.1 string, and a C library that hands it to `strcmp` sees only
    /// the first part (Moxie Marlinspike, 2009). We are not C, but the
    /// name leaves here and goes somewhere, so it does not leave here.
    pub fn text(&self) -> Result<String, String> {
        let decoded = self.decode()?;
        if decoded.contains('\0') {
            return Err("Name attribute contains an embedded NUL.".to_string());
        }
        Ok(decoded)
    }

    /// The decoding alone, without judging what came out.
    fn decode(&self) -> Result<String, String> {
        if self.value_tag == asn1::tag::BMP_STRING {
            if !self.value.len().is_multiple_of(2) {
                return Err("BMPString with an odd number of bytes.".to_string());
            }
            let units: Vec<u16> = self.value.chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]])).collect();
            return String::from_utf16(&units)
                .map_err(|_| "BMPString is not valid UTF-16.".to_string());
        }
        // TeletexString is officially T.61 and is in practice Latin-1 or
        // UTF-8 depending on who wrote it. Treating it as UTF-8 and falling
        // back to Latin-1 is what every other implementation does.
        match core::str::from_utf8(self.value) {
            Ok(text) => Ok(text.to_string()),
            Err(_) if self.value_tag == asn1::tag::T61_STRING =>
                Ok(self.value.iter().map(|&b| b as char).collect()),
            Err(_) => Err("String is not valid UTF-8.".to_string()),
        }
    }
}

/// A distinguished name: a sequence of sets of attributes.
#[derive(Clone, Debug)]
pub struct Name<'a> {
    /// The exact DER, which is what issuer/subject matching compares.
    ///
    /// Comparing the encoded bytes rather than the parsed attributes is the
    /// conservative choice. RFC 5280 defines a normalising comparison, and
    /// every place two implementations normalise differently is a place a
    /// chain can be made to link where it should not.
    pub raw: &'a [u8],
    pub attributes: Vec<Attribute<'a>>,
}

impl<'a> Name<'a> {
    pub(crate) fn parse(reader: &mut Reader<'a>) -> Result<Name<'a>, String> {
        let raw = reader.clone().read_raw()?;
        let mut sequence = reader.read_sequence()?;
        let mut attributes = Vec::new();
        while !sequence.is_empty() {
            let mut set = sequence.read_set()?;
            while !set.is_empty() {
                let mut pair = set.read_sequence()?;
                let oid = pair.read_oid()?;
                let (value_tag, value) = match pair.clone().read_string() {
                    Ok(parsed) => { pair.read_string()?; parsed }
                    Err(_) => {
                        // Some attributes are not strings at all - a
                        // serialNumber can be an INTEGER in the wild. Keep
                        // the bytes rather than failing the whole name.
                        let (tag, content) = pair.read_any()?;
                        (tag.number, content)
                    }
                };
                // **No NUL check here.** It lives in `Attribute::text`,
                // on the decoded string - see the note there, and the
                // live certificate that found it.
                pair.finish()?;
                attributes.push(Attribute { oid, value_tag, value });
            }
        }
        Ok(Name { raw, attributes })
    }

    /// The first value for an attribute type, as text.
    pub fn get(&self, oid: &[u8]) -> Option<String> {
        self.attributes.iter()
            .find(|a| a.oid.as_bytes() == oid)
            .and_then(|a| a.text().ok())
    }

    pub fn common_name(&self) -> Option<String> {
        self.get(oids::COMMON_NAME)
    }

    /// Byte-exact comparison, which is what chain building uses.
    pub fn matches(&self, other: &Name<'_>) -> bool {
        self.raw == other.raw
    }

    /// The relative distinguished names, each as its raw DER `SET`.
    ///
    /// `attributes` flattens the RDNs away, which is right for looking a
    /// value up and wrong for anything positional. A directoryName name
    /// constraint is a *prefix* of the sequence (RFC 5280 4.2.1.10), and a
    /// prefix of a flattened list is not the same thing: `CN=a+O=b` is one
    /// RDN holding two attributes, and reading it as two RDNs makes a
    /// constraint on `CN=a` alone appear to match.
    pub fn rdns(&self) -> Result<Vec<&'a [u8]>, String> {
        let mut reader = Reader::new(self.raw);
        let mut sequence = reader.read_sequence()?;
        reader.finish()?;
        let mut out = Vec::new();
        while !sequence.is_empty() {
            let raw = sequence.clone().read_raw()?;
            sequence.read_set()?;
            out.push(raw);
        }
        Ok(out)
    }
}

/// RFC 4514 order, which prints the most specific attribute first.
///
/// A `Display` impl rather than an inherent `to_string`, so that
/// `format!("{}", name)` and `name.to_string()` cannot disagree - an
/// inherent method of that name shadows the blanket `ToString` for
/// direct calls but not for formatting.
///
/// This is for humans. `matches` is what decides whether two names are
/// the same, and it compares the DER; two distinct names can print
/// identically.
impl core::fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (index, attribute) in self.attributes.iter().rev().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            write!(f, "{}={}", attribute.label(),
                   attribute.text().unwrap_or_else(|_| "<unprintable>".to_string()))?;
        }
        Ok(())
    }
}

// -------------------------------------------------------------- extensions ---

/// One entry of a subjectAltName or issuerAltName.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneralName<'a> {
    Dns(&'a str),
    Email(&'a str),
    Uri(&'a str),
    /// 4 bytes for IPv4, 16 for IPv6.
    IpAddress(&'a [u8]),
    DirectoryName(&'a [u8]),
    /// Anything else, kept by its context tag number.
    Other(u32, &'a [u8]),
    /// A subjectAltName entry of a form this library reads that is not
    /// well formed - a name with an embedded NUL or that is not UTF-8, an
    /// address of the wrong length - kept by its tag number with its raw
    /// contents.
    ///
    /// **Kept rather than refused**, because reading is not judging: one
    /// odd entry used to make the whole certificate unparseable, so it
    /// could not even be looked at. The judging is in `verify`: a
    /// malformed entry matches no host, a malformed dNSName or URI still
    /// stops the fallback to the common name as a well-formed one would,
    /// and a constrained CA's certificate holding one of a constrained
    /// form is refused, since it cannot be checked against the subtree.
    Malformed(u32, &'a [u8]),
}

/// What a certificate's key may be used for, as the bits of RFC 5280 §4.2.1.3.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

impl KeyUsage {
    fn from_bits(bits: &[u8], unused: u8) -> KeyUsage {
        let bit = |index: usize| -> bool {
            let byte = index / 8;
            if byte >= bits.len() {
                return false;
            }
            // A bit beyond the last significant one is absent, not false by
            // accident: the unused-bit count says where the value stops.
            if byte == bits.len() - 1 && (index % 8) >= (8 - unused as usize) {
                return false;
            }
            bits[byte] & (0x80 >> (index % 8)) != 0
        };
        KeyUsage {
            digital_signature: bit(0),
            non_repudiation: bit(1),
            key_encipherment: bit(2),
            data_encipherment: bit(3),
            key_agreement: bit(4),
            key_cert_sign: bit(5),
            crl_sign: bit(6),
            encipher_only: bit(7),
            decipher_only: bit(8),
        }
    }
}

/// The extensions this library understands, plus a note of the ones it does
/// not.
#[derive(Clone, Debug, Default)]
pub struct Extensions<'a> {
    /// `(is_ca, path_len_constraint)`.
    pub basic_constraints: Option<(bool, Option<u32>)>,
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usage: Option<Vec<Oid<'a>>>,
    pub subject_alt_names: Vec<GeneralName<'a>>,
    pub subject_key_id: Option<&'a [u8]>,
    pub authority_key_id: Option<&'a [u8]>,
    /// RFC 5280 4.2.1.10, enforced by `name_constraints::check_chain`.
    /// Only meaningful on a CA certificate; a leaf carrying one
    /// constrains nothing, since nothing is issued below it.
    pub name_constraints: Option<name_constraints::NameConstraints<'a>>,
    /// Where the issuer says its CRL can be fetched (RFC 5280 4.2.1.13),
    /// as the URIs only. Reported, never fetched: nothing in this
    /// library opens a socket.
    pub crl_distribution_points: Vec<String>,
    /// Where the issuer says its OCSP responder lives, from the
    /// authorityInfoAccess extension's `id-ad-ocsp` entries only. The
    /// other access method in that extension points at the issuer's
    /// *certificate*, and sending an OCSP request there would reach a
    /// file server.
    pub ocsp_responders: Vec<String>,
    /// Critical extensions whose OID we did not recognise. RFC 5280: a
    /// relying party that does not understand a critical extension **must**
    /// reject the certificate. `verify` enforces that; the parser records it.
    pub unrecognised_critical: Vec<Oid<'a>>,
    /// Every extension OID in order, so a caller can see what is there.
    pub present: Vec<(Oid<'a>, bool)>,
    /// The same, with each extension's **value bytes** - the contents of
    /// its OCTET STRING, unparsed.
    ///
    /// Here for one caller: a proxy that mirrors somebody else's
    /// certificate has to reproduce extensions it does not itself
    /// understand, and it can only do that by copying the bytes. Every
    /// other consumer wants the parsed fields above.
    pub values: Vec<(Oid<'a>, bool, &'a [u8])>,
}

impl<'a> Extensions<'a> {
    fn parse(content: &'a [u8]) -> Result<Extensions<'a>, String> {
        let mut outer = Reader::new(content);
        let mut list = outer.read_sequence()?;
        outer.finish()?;

        let mut extensions = Extensions::default();
        let mut seen: Vec<&[u8]> = Vec::new();

        while !list.is_empty() {
            let mut entry = list.read_sequence()?;
            let oid = entry.read_oid()?;

            // RFC 5280: at most one instance of each extension. Where a
            // duplicate is tolerated, the question becomes which copy is
            // enforced - and an attacker will supply a second
            // basicConstraints hoping the answer is "not the one you read".
            if seen.contains(&oid.as_bytes()) {
                return Err(format!("Duplicate extension {}.", oid));
            }
            seen.push(oid.as_bytes());

            // DEFAULT FALSE, so a critical flag that is present and false is
            // a non-minimal encoding; the BOOLEAN reader already refuses
            // anything but 0x00 and 0xFF.
            let critical = match entry.peek_tag() {
                Some(tag) if tag == Tag::universal(asn1::tag::BOOLEAN) => entry.read_bool()?,
                _ => false,
            };
            let value = entry.read_octet_string()?;
            entry.finish()?;
            extensions.present.push((oid, critical));
            extensions.values.push((oid, critical, value));

            let bytes = oid.as_bytes();
            if bytes == oids::BASIC_CONSTRAINTS {
                extensions.basic_constraints = Some(parse_basic_constraints(value)?);
            } else if bytes == oids::KEY_USAGE {
                let mut reader = Reader::new(value);
                let (bits, unused) = reader.read_bit_string_with_unused()?;
                reader.finish()?;
                extensions.key_usage = Some(KeyUsage::from_bits(bits, unused));
            } else if bytes == oids::EXT_KEY_USAGE {
                extensions.extended_key_usage = Some(parse_ext_key_usage(value)?);
            } else if bytes == oids::SUBJECT_ALT_NAME {
                extensions.subject_alt_names = parse_general_names(value)?;
            } else if bytes == oids::SUBJECT_KEY_ID {
                let mut reader = Reader::new(value);
                extensions.subject_key_id = Some(reader.read_octet_string()?);
                reader.finish()?;
            } else if bytes == oids::AUTHORITY_KEY_ID {
                extensions.authority_key_id = parse_authority_key_id(value)?;
            } else if bytes == oids::NAME_CONSTRAINTS {
                extensions.name_constraints =
                    Some(name_constraints::NameConstraints::parse(value)?);
            } else if bytes == oids::CRL_DISTRIBUTION {
                extensions.crl_distribution_points =
                    parse_crl_distribution_points(value)?;
            } else if bytes == oids::AUTHORITY_INFO_ACCESS {
                extensions.ocsp_responders = parse_ocsp_responders(value)?;
            } else if critical {
                extensions.unrecognised_critical.push(oid);
            }
        }
        Ok(extensions)
    }

    pub fn is_ca(&self) -> bool {
        matches!(self.basic_constraints, Some((true, _)))
    }

    pub fn path_len(&self) -> Option<u32> {
        match self.basic_constraints {
            Some((true, limit)) => limit,
            _ => None,
        }
    }

    pub fn dns_names(&self) -> Vec<&'a str> {
        self.subject_alt_names.iter()
            .filter_map(|name| match name {
                GeneralName::Dns(text) => Some(*text),
                _ => None,
            })
            .collect()
    }
}

fn parse_basic_constraints(value: &[u8]) -> Result<(bool, Option<u32>), String> {
    let mut outer = Reader::new(value);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;

    // Both fields are OPTIONAL, and cA is DEFAULT FALSE - so an empty
    // SEQUENCE means "not a CA", which is a real encoding seen in the wild.
    let is_ca = match sequence.peek_tag() {
        Some(tag) if tag == Tag::universal(asn1::tag::BOOLEAN) => sequence.read_bool()?,
        _ => false,
    };
    let path_len = match sequence.peek_tag() {
        Some(tag) if tag == Tag::universal(asn1::tag::INTEGER) => Some(sequence.read_u32()?),
        _ => None,
    };
    sequence.finish()?;

    // A pathLenConstraint on something that is not a CA is a CA's
    // mistake - RFC 5280 4.2.1.9 says CAs MUST NOT write one - and it
    // is recorded rather than refused: parsing reads and `verify`
    // judges, and a certificate with cA=FALSE cannot issue anything
    // whatever its pathLen says, so the field constrains nothing and
    // refusing the certificate for it would refuse a leaf for an
    // extension that cannot be used against anyone. `path_len()`
    // reports it only for a CA.
    Ok((is_ca, path_len))
}

fn parse_ext_key_usage(value: &[u8]) -> Result<Vec<Oid<'_>>, String> {
    let mut outer = Reader::new(value);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;

    let mut usages = Vec::new();
    while !sequence.is_empty() {
        usages.push(sequence.read_oid()?);
    }
    if usages.is_empty() {
        return Err("extendedKeyUsage must list at least one purpose.".to_string());
    }
    Ok(usages)
}

pub(crate) fn parse_authority_key_id(value: &[u8])
                                     -> Result<Option<&[u8]>, String> {
    let mut outer = Reader::new(value);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;
    // keyIdentifier is [0] IMPLICIT, so it is a primitive context tag.
    let identifier = sequence.read_optional_context(0, false)?;
    // The other two fields are the issuer name and serial; we do not use
    // them for chain building, and reading them would mean trusting a hint
    // from the certificate about which issuer to pick.
    Ok(identifier)
}

/// One GeneralName from a reader positioned at it.
///
/// `address_lengths` says whether an `iPAddress` must be an address (4 or
/// 16 bytes) or may be an address **and mask** (8 or 32). It is the second
/// inside a nameConstraints extension and the first everywhere else - RFC
/// 5280 4.2.1.10 redefines the field there, and a parser that accepts both
/// lengths everywhere would read a bare address as a constraint whose mask
/// is missing, or a constraint as an address nobody has.
pub(crate) fn read_general_name<'a>(reader: &mut Reader<'a>,
                                    address_lengths: &[usize])
                                    -> Result<GeneralName<'a>, String> {
    let (tag, content) = reader.read_any()?;
    if tag.class != asn1::CLASS_CONTEXT {
        return Err("GeneralName must use a context tag.".to_string());
    }
    general_name_from(tag.number, content, address_lengths)
}

/// A subjectAltName entry: as `read_general_name`, except that an entry
/// whose contents are ill-formed is kept as `GeneralName::Malformed`
/// rather than refusing the certificate. Only the contents: a tag of the
/// wrong class is still a structure that does not parse.
fn read_subject_alt_name<'a>(reader: &mut Reader<'a>) -> Result<GeneralName<'a>, String> {
    let (tag, content) = reader.read_any()?;
    if tag.class != asn1::CLASS_CONTEXT {
        return Err("GeneralName must use a context tag.".to_string());
    }
    Ok(general_name_from(tag.number, content, &ADDRESS_ONLY)
        .unwrap_or(GeneralName::Malformed(tag.number, content)))
}

fn general_name_from<'a>(number: u32, content: &'a [u8], address_lengths: &[usize])
                         -> Result<GeneralName<'a>, String> {
    // An embedded NUL in a name is the null-prefix attack, so such a name
    // never becomes a `Dns`, `Email` or `Uri` that something might hand to
    // code that stops at NUL: it is refused where a name is required, and
    // kept as `Malformed` - compared with nothing - in a subjectAltName.
    if content.contains(&0) && matches!(number, 1 | 2 | 6) {
        return Err("GeneralName contains an embedded NUL.".to_string());
    }
    fn as_text(bytes: &[u8]) -> Result<&str, String> {
        core::str::from_utf8(bytes)
            .map_err(|_| "GeneralName is not valid UTF-8.".to_string())
    }

    Ok(match number {
        1 => GeneralName::Email(as_text(content)?),
        2 => GeneralName::Dns(as_text(content)?),
        6 => GeneralName::Uri(as_text(content)?),
        7 => {
            if !address_lengths.contains(&content.len()) {
                return Err(format!("iPAddress must be {} bytes, got {}.",
                                   address_lengths.iter().map(|n| n.to_string())
                                       .collect::<Vec<_>>().join(" or "),
                                   content.len()));
            }
            GeneralName::IpAddress(content)
        }
        4 => GeneralName::DirectoryName(content),
        other => GeneralName::Other(other, content),
    })
}

/// The lengths an `iPAddress` may have outside a name constraint.
pub(crate) const ADDRESS_ONLY: [usize; 2] = [4, 16];

/// The URIs from a cRLDistributionPoints extension (RFC 5280 4.2.1.13).
///
/// ```text
/// DistributionPoint ::= SEQUENCE {
///      distributionPoint       [0]     DistributionPointName OPTIONAL,
///      reasons                 [1]     ReasonFlags OPTIONAL,
///      cRLIssuer               [2]     GeneralNames OPTIONAL }
///
/// DistributionPointName ::= CHOICE {
///      fullName                [0]     GeneralNames,
///      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
/// ```
///
/// Only the URIs come back, and only from `fullName`. The other forms
/// name a directory entry rather than something fetchable, and
/// `nameRelativeToCRLIssuer` is a DN fragment that has to be appended to
/// the CRL issuer's name - which RFC 5280 tells CAs not to use.
///
/// Nothing is refused here for being unreachable. A certificate is still
/// a certificate when its CRL lives somewhere we cannot go, and parsing
/// judges nothing.
fn parse_crl_distribution_points(value: &[u8]) -> Result<Vec<String>, String> {
    let mut outer = Reader::new(value);
    let mut points = outer.read_sequence()?;
    outer.finish()?;

    let mut uris = Vec::new();
    while !points.is_empty() {
        let mut point = points.read_sequence()?;
        while !point.is_empty() {
            let (tag, content) = point.read_any()?;
            if tag.class != asn1::CLASS_CONTEXT {
                return Err("A DistributionPoint field must use a context tag."
                           .to_string());
            }
            if tag.number != 0 {
                // reasons and cRLIssuer: read past. They matter to a
                // caller choosing *which* CRL to fetch, and this
                // function only answers "from where".
                continue;
            }
            let mut name = Reader::new(content);
            if name.peek_tag() != Some(Tag::context(0, true)) {
                continue;               // nameRelativeToCRLIssuer
            }
            let mut names = name.read_constructed(Tag::context(0, true))?;
            while !names.is_empty() {
                if let GeneralName::Uri(text) =
                        read_general_name(&mut names, &ADDRESS_ONLY)? {
                    uris.push(text.to_string());
                }
            }
        }
    }
    Ok(uris)
}

/// The OCSP responder URLs from an authorityInfoAccess extension.
///
/// ```text
/// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
///
/// AccessDescription ::= SEQUENCE {
///      accessMethod          OBJECT IDENTIFIER,
///      accessLocation        GeneralName }
/// ```
///
/// Only `id-ad-ocsp` entries, and only their URIs. The other method
/// defined for a certificate is `id-ad-caIssuers`, which points at the
/// issuer's *certificate* - sending an OCSP request there would reach a
/// file server, and returning both from one function is how that
/// happens.
fn parse_ocsp_responders(value: &[u8]) -> Result<Vec<String>, String> {
    let mut outer = Reader::new(value);
    let mut descriptions = outer.read_sequence()?;
    outer.finish()?;

    let mut urls = Vec::new();
    while !descriptions.is_empty() {
        let mut description = descriptions.read_sequence()?;
        let method = description.read_oid()?;
        let location = read_general_name(&mut description, &ADDRESS_ONLY)?;
        description.finish()?;
        if method.as_bytes() == oids::AD_OCSP {
            if let GeneralName::Uri(text) = location {
                urls.push(text.to_string());
            }
        }
    }
    Ok(urls)
}

fn parse_general_names(value: &[u8]) -> Result<Vec<GeneralName<'_>>, String> {
    let mut outer = Reader::new(value);
    let mut sequence = outer.read_sequence()?;
    outer.finish()?;

    let mut names = Vec::new();
    while !sequence.is_empty() {
        names.push(read_subject_alt_name(&mut sequence)?);
    }
    Ok(names)
}

// ------------------------------------------------------------ certificate ---

/// A parsed certificate. Borrows the DER it came from throughout.
#[derive(Clone, Debug)]
pub struct Certificate<'a> {
    /// The whole certificate, as it arrived.
    pub raw: &'a [u8],
    /// The TBSCertificate, tag and length included: exactly the bytes the
    /// signature covers.
    pub tbs: &'a [u8],
    /// 1, 2 or 3. The ASN.1 value is zero-based; this is not.
    pub version: u32,
    /// The serial number's content octets, unsigned. Kept as bytes because
    /// serials are compared and printed, never arithmetic.
    pub serial: &'a [u8],
    /// The algorithm named inside the TBS.
    pub signature_algorithm: SignatureAlgorithm,
    /// The algorithm named outside it. These must agree - see `parse`.
    pub outer_algorithm: SignatureAlgorithm,
    pub issuer: Name<'a>,
    pub subject: Name<'a>,
    pub not_before: i64,
    pub not_after: i64,
    pub public_key: PublicKey<'a>,
    /// The SubjectPublicKeyInfo as DER, for fingerprinting and for handing
    /// to something else unchanged.
    pub spki: &'a [u8],
    pub extensions: Extensions<'a>,
    pub signature: &'a [u8],
}

impl<'a> Certificate<'a> {
    /// Parse a DER certificate.
    ///
    /// This reads; it does not judge. An expired certificate, one signed
    /// with MD5, one whose key is 512 bits - all parse. `verify` decides.
    pub fn parse(der: &'a [u8]) -> Result<Certificate<'a>, String> {
        let mut outer = Reader::new(der);
        let mut certificate = outer.read_sequence()?;
        outer.finish()?;

        let tbs = certificate.clone().read_raw()?;
        let mut body = certificate.read_sequence()?;

        // version [0] EXPLICIT INTEGER DEFAULT v1
        let version = match body.read_optional_context(0, true)? {
            Some(content) => {
                let mut reader = Reader::new(content);
                let value = reader.read_u32()?;
                reader.finish()?;
                if value > 2 {
                    return Err(format!("Unknown certificate version {}.", value + 1));
                }
                value + 1
            }
            None => 1,
        };

        // The serial is kept as raw content octets rather than a number.
        //
        // RFC 5280 says it must be a positive integer, and real roots break
        // that: Go Daddy's G2 root, both Starfield G2 roots and the Hellenic
        // academic roots all carry serial 0. Rejecting them would mean not
        // being able to verify a large slice of the public web, which is the
        // opposite of what this library is for. Serials are compared and
        // printed, never used in arithmetic, so there is nothing to gain by
        // insisting.
        let serial = body.read_integer_bytes()?;
        let inner_algorithm_raw = body.clone().read_raw()?;
        let signature_algorithm = read_algorithm(&mut body)?;
        let issuer = Name::parse(&mut body)?;

        let mut validity = body.read_sequence()?;
        let not_before = validity.read_time()?;
        let not_after = validity.read_time()?;
        validity.finish()?;

        let subject = Name::parse(&mut body)?;

        let spki = body.clone().read_raw()?;
        let public_key = read_public_key(&mut body)?;

        // issuerUniqueID [1] and subjectUniqueID [2] are v2 relics. Skip
        // them rather than failing, since certificates carrying them exist.
        body.read_optional_context(1, false)?;
        body.read_optional_context(2, false)?;

        let extensions = match body.read_optional_context(3, true)? {
            Some(content) => {
                if version != 3 {
                    return Err(format!("Extensions in a version {} certificate.",
                                       version));
                }
                Extensions::parse(content)?
            }
            None => Extensions::default(),
        };
        body.finish()?;

        let outer_algorithm_raw = certificate.clone().read_raw()?;
        let outer_algorithm = read_algorithm(&mut certificate)?;
        let signature = certificate.read_bit_string()?;
        certificate.finish()?;

        // RFC 5280 §4.1.1.2: the two algorithm identifiers must be the same.
        // If they can differ, an attacker picks a weak one on the outside
        // for the verifier and leaves a strong one inside for anyone
        // inspecting the certificate. Compared as the bytes that arrived,
        // not as the parsed enum: two different unrecognised OIDs both
        // parse to `Unknown`, and two PSS identifiers with different
        // parameter blocks both parse to `Unsupported`, and neither pair
        // is "the same".
        if inner_algorithm_raw != outer_algorithm_raw {
            return Err(format!(
                "Signature algorithm mismatch: {} inside the TBS, {} outside.",
                signature_algorithm.describe(), outer_algorithm.describe()));
        }

        Ok(Certificate {
            raw: der, tbs, version, serial, signature_algorithm, outer_algorithm,
            issuer, subject, not_before, not_after, public_key, spki, extensions,
            signature,
        })
    }

    /// Whether this certificate could have issued `child`, by name alone.
    /// The signature is a separate question, and a much more expensive one.
    pub fn is_issuer_of(&self, child: &Certificate<'_>) -> bool {
        self.subject.matches(&child.issuer)
    }

    pub fn is_self_issued(&self) -> bool {
        self.subject.matches(&self.issuer)
    }

    /// The serial as hex, which is how everyone writes it.
    pub fn serial_hex(&self) -> String {
        self.serial.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

pub(crate) fn read_algorithm(reader: &mut Reader<'_>)
                             -> Result<SignatureAlgorithm, String> {
    let mut sequence = reader.read_sequence()?;
    let oid = sequence.read_oid()?;
    // The parameters differ by algorithm: RSA requires NULL, ECDSA requires
    // absent. Both are read without being interpreted - and neither is
    // enforced, because certificates in the wild get this wrong in both
    // directions and rejecting them would break the thing this library is
    // for. Nothing downstream depends on it.
    while !sequence.is_empty() {
        sequence.read_any()?;
    }
    Ok(SignatureAlgorithm::from_oid(oid))
}

fn read_public_key<'a>(reader: &mut Reader<'a>) -> Result<PublicKey<'a>, String> {
    let mut spki = reader.read_sequence()?;

    // **The AlgorithmIdentifier's own bytes, kept before it is taken
    // apart.** `read_sequence` hands back a reader over the *contents*,
    // so the enclosing TLV is gone by the time the OIDs are known - and
    // a GOST ClientKeyExchange has to put that whole structure back on
    // the wire verbatim. See `PublicKey::Gost::algorithm_id`.
    let before_algorithm = spki.remaining();

    let mut algorithm = spki.read_sequence()?;
    let oid = algorithm.read_oid()?;
    let parameters = if algorithm.is_empty() { None } else { Some(algorithm.read_raw()?) };
    algorithm.finish()?;

    let algorithm_id =
        &before_algorithm[..before_algorithm.len() - spki.remaining().len()];

    let key_bits = spki.read_bit_string()?;
    spki.finish()?;

    let bytes = oid.as_bytes();
    if bytes == oids::RSA_ENCRYPTION {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let mut key = Reader::new(key_bits);
        let mut sequence = key.read_sequence()?;
        key.finish()?;
        let n = sequence.read_integer()?;
        let e = sequence.read_integer()?;
        sequence.finish()?;
        Ok(PublicKey::Rsa { n, e })
    } else if bytes == oids::EC_PUBLIC_KEY {
        // The curve is in the algorithm parameters, not the key, so a key
        // with no named curve cannot be used - "implicit curve" and
        // "specified curve" both mean the parameters arrive from somewhere
        // else, and accepting arbitrary curve parameters from a certificate
        // is the invalid-curve attack with extra steps.
        let parameters = parameters
            .ok_or_else(|| "EC public key with no curve parameters.".to_string())?;
        let mut reader = Reader::new(parameters);
        let curve_oid = reader.read_oid()
            .map_err(|_| "EC curve parameters are not a named curve OID.".to_string())?;
        reader.finish()?;

        let curve = match curve_oid.as_bytes() {
            b if b == oids::PRIME256V1 => "P-256",
            b if b == oids::SECP384R1 => "P-384",
            b if b == oids::SECP521R1 => "P-521",
            b if b == oids::SECP256K1 => "secp256k1",
            // Not an error. A curve we cannot compute on is a judgement,
            // and this function reads rather than judges - the same rule
            // that keeps `Unsupported` around for an unknown algorithm.
            //
            // It used to be an error, and the cost was out of all
            // proportion: one root on an unimplemented curve made the
            // whole certificate unparseable, so `TrustStore` dropped it
            // and reported a bare count. A live run came back "120 roots
            // loaded, 1 skipped as unparseable" with nothing to say which
            // root or why. A server presenting such a certificate got
            // "cannot parse" instead of the curve's name, which sends
            // whoever reads it looking for a malformed certificate that
            // is not malformed at all.
            // **And then whatever a caller has registered**, which is
            // how a curve this file does not carry becomes readable
            // without a rebuild. The registry is consulted after the
            // three above for the reason in `src/registry.rs`: nothing a
            // caller registers can change what `prime256v1` means.
            //
            // `interned_name` rather than a fresh leak: the name already
            // has a `&'static str` from when the curve was registered,
            // and this branch runs once per certificate parsed.
            other => match crate::registry::curve_for_der(other)
                .and_then(|name| crate::ec::curves::interned_name(&name)) {
                Some(registered) => registered,
                // Not an error. A curve we cannot compute on is a
                // judgement, and this function reads rather than judges.
                None => return Ok(PublicKey::UnsupportedCurve {
                    oid: curve_oid, family: "EC" }),
            },
        };
        Ok(PublicKey::Ec { curve, point: key_bits })
    } else if bytes == oids::GOST3410_12_256 || bytes == oids::GOST3410_12_512
              || bytes == oids::GOST3410_2001 {
        // **The 2001 keys read exactly the same way**, which is why
        // this branch takes them too. RFC 4357's
        // `GostR3410-2001-PublicKeyParameters` has the same three
        // fields as RFC 9215's 2012 structure - a parameter set OID, a
        // digest parameter set OID, and optionally an encryption one -
        // and the key is the same 64 bytes of little endian
        // coordinates inside an OCTET STRING inside the BIT STRING.
        // The only thing that changes is the algorithm OID and which
        // hash signs it.
        //
        // GostR3410-2012-PublicKeyParameters ::= SEQUENCE {
        //     publicKeyParamSet OBJECT IDENTIFIER,
        //     digestParamSet    OBJECT IDENTIFIER OPTIONAL }
        //
        // The digest OID is deprecated by RFC 9215 and present in plenty
        // of real certificates, so it is read past rather than refused.
        let parameters = parameters.ok_or_else(||
            "GOST public key with no parameters.".to_string())?;
        let mut reader = Reader::new(parameters);
        let mut params = reader.read_sequence()?;
        reader.finish()?;
        let param_set = params.read_oid()?;

        let curve = match oids::gost_curve_for(param_set.as_bytes()) {
            Some(name) => name,
            // Judging, not reading - the same rule as the EC branch.
            None => return Ok(PublicKey::UnsupportedCurve {
                oid: param_set,
                family: if bytes == oids::GOST3410_2001 {
                    "GOST R 34.10-2001"
                } else {
                    "GOST R 34.10-2012"
                } }),
        };

        // The key is an OCTET STRING *inside* the BIT STRING, and its
        // coordinates are little endian. Both are RFC 9215 section 4.3
        // and both are places a reader that assumed the EC conventions
        // would get a plausible wrong answer rather than an error.
        let mut inner = Reader::new(key_bits);
        let raw = inner.read_octet_string()?;
        inner.finish()?;

        let width = crate::ec::curves::by_name(curve)?.field_bytes();
        if raw.len() != 2 * width {
            return Err(format!(
                "A {} public key is {} bytes, x then y; got {}.",
                curve, 2 * width, raw.len()));
        }
        let mut x = raw[..width].to_vec();
        x.reverse();
        let mut y = raw[width..].to_vec();
        y.reverse();
        Ok(PublicKey::Gost { curve,
                             x: BigUint::from_bytes_be(&x),
                             y: BigUint::from_bytes_be(&y),
                             param_set,
                             algorithm_id,
                             legacy: bytes == oids::GOST3410_2001 })
    } else if bytes == oids::ID_ED25519 || bytes == oids::ID_ED448 {
        let (curve, length) = if bytes == oids::ID_ED25519 {
            ("ed25519", 32)
        } else {
            ("ed448", 57)
        };

        // **RFC 8410 section 3: the parameters field MUST be absent.**
        // Not NULL, which is what RSA uses and what an encoder written
        // from the RSA branch emits. Refused rather than tolerated,
        // because these keys are new enough that there is no corpus of
        // old certificates getting it wrong to be kind to - and being
        // kind here would mean accepting two encodings of one key,
        // which is what `Certificate::fingerprint` cannot survive.
        if parameters.is_some() {
            return Err(format!(
                "An {} key must have absent AlgorithmIdentifier parameters \
                 (RFC 8410 section 3); this one has them present.", curve));
        }

        // The BIT STRING *is* the key. No SEQUENCE, no OCTET STRING, no
        // SEC1 format byte.
        if key_bits.len() != length {
            return Err(format!("An {} public key is {} bytes; got {}.",
                               curve, length, key_bits.len()));
        }
        Ok(PublicKey::Eddsa { curve, key: key_bits })
    } else if bytes == oids::ID_DSA {
        // Dss-Parms ::= SEQUENCE { p INTEGER, q INTEGER, g INTEGER }, or
        // absent for a key that inherits its issuer's.
        let parameters = match parameters {
            None => None,
            Some(der) => {
                let mut reader = Reader::new(der);
                let mut sequence = reader.read_sequence()?;
                reader.finish()?;
                let p = sequence.read_integer()?;
                let q = sequence.read_integer()?;
                let g = sequence.read_integer()?;
                sequence.finish()?;
                Some((p, q, g))
            }
        };
        // DSAPublicKey ::= INTEGER, inside the BIT STRING.
        let mut inner = Reader::new(key_bits);
        let y = inner.read_integer()?;
        inner.finish()?;
        Ok(PublicKey::Dsa { parameters, y })
    } else if let Some(parameter_set) = ml_dsa_parameter_set(bytes) {
        // RFC 9881 section 2: "The contents of the parameters component
        // for each algorithm MUST be absent." Refused for the reason
        // given for EdDSA above, which applies with more force: there is
        // no installed base of these certificates to be lenient to.
        if parameters.is_some() {
            return Err(format!(
                "An {} key must have absent AlgorithmIdentifier parameters \
                 (RFC 9881 section 2); this one has them present.", parameter_set));
        }
        let expected = crate::pq::ml_dsa::parameters(parameter_set)?.public_key_len();
        if key_bits.len() != expected {
            return Err(format!("An {} public key is {} bytes; got {}.",
                               parameter_set, expected, key_bits.len()));
        }
        Ok(PublicKey::MlDsa { parameter_set, key: key_bits })
    } else {
        Ok(PublicKey::Unsupported { algorithm: bytes })
    }
}

/// FIPS 204's name for an RFC 9881 OID, or `None` for any other OID.
pub(crate) fn ml_dsa_parameter_set(oid: &[u8]) -> Option<&'static str> {
    if oid == oids::ID_ML_DSA_44 { Some("ML-DSA-44") }
    else if oid == oids::ID_ML_DSA_65 { Some("ML-DSA-65") }
    else if oid == oids::ID_ML_DSA_87 { Some("ML-DSA-87") }
    else { None }
}

/// The RFC 9881 OID for a FIPS 204 parameter set name.
pub(crate) fn ml_dsa_oid(parameter_set: &str) -> Result<&'static [u8], String> {
    match parameter_set {
        "ML-DSA-44" => Ok(oids::ID_ML_DSA_44),
        "ML-DSA-65" => Ok(oids::ID_ML_DSA_65),
        "ML-DSA-87" => Ok(oids::ID_ML_DSA_87),
        other => Err(format!("No RFC 9881 OID for {:?}.", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::Writer;

    /// Build a minimal but structurally valid certificate, so the parser can
    /// be tested without a real one. The real ones come from OpenSSL in
    /// tools/src/bin/diff_x509.rs.
    fn build(mutate: impl FnOnce(&mut CertificateParts)) -> Vec<u8> {
        let mut parts = CertificateParts::default();
        mutate(&mut parts);
        parts.build()
    }

    struct CertificateParts {
        version: Option<u32>,
        serial: Vec<u8>,
        inner_algorithm: Vec<u8>,
        outer_algorithm: Vec<u8>,
        not_before: Vec<u8>,
        not_after: Vec<u8>,
        common_name: Vec<u8>,
        /// The string tag the common name is written with.
        ///
        /// A knob rather than a constant because the encoding is part of
        /// what a parser has to get right: `BMPString` is UTF-16, and a
        /// check that ran on the encoded bytes refused every one of
        /// them. See `test_a_bmpstring_name_is_not_a_nul_attack`.
        common_name_tag: u32,
        extensions: Vec<(Vec<u8>, bool, Vec<u8>)>,
    }

    impl Default for CertificateParts {
        fn default() -> Self {
            CertificateParts {
                version: Some(2),
                serial: vec![0x01, 0x02, 0x03],
                inner_algorithm: oids::SHA256_WITH_RSA.to_vec(),
                outer_algorithm: oids::SHA256_WITH_RSA.to_vec(),
                not_before: b"200101000000Z".to_vec(),
                not_after: b"300101000000Z".to_vec(),
                common_name: b"example.test".to_vec(),
                common_name_tag: asn1::tag::UTF8_STRING,
                extensions: vec![],
            }
        }
    }

    impl CertificateParts {
        fn name(writer: &mut Writer, common_name: &[u8]) {
            Self::name_tagged(writer, common_name, asn1::tag::UTF8_STRING);
        }

        fn name_tagged(writer: &mut Writer, common_name: &[u8], tag: u32) {
            writer.write_sequence(|w| {
                w.write_set(|w| {
                    w.write_sequence(|w| {
                        w.write_oid(oids::COMMON_NAME);
                        w.write_tlv(Tag::universal(tag), common_name);
                    });
                });
            });
        }

        fn build(&self) -> Vec<u8> {
            let mut writer = Writer::new();
            writer.write_sequence(|c| {
                c.write_sequence(|t| {
                    if let Some(version) = self.version {
                        t.write_constructed(Tag::context(0, true), |w| w.write_u32(version));
                    }
                    t.write_tlv(Tag::universal(asn1::tag::INTEGER), &self.serial);
                    t.write_sequence(|w| { w.write_oid(&self.inner_algorithm); w.write_null(); });
                    Self::name(t, b"Test CA");
                    t.write_sequence(|w| {
                        w.write_tlv(Tag::universal(asn1::tag::UTC_TIME), &self.not_before);
                        w.write_tlv(Tag::universal(asn1::tag::UTC_TIME), &self.not_after);
                    });
                    Self::name_tagged(t, &self.common_name, self.common_name_tag);
                    // A tiny but well formed RSA SubjectPublicKeyInfo.
                    t.write_sequence(|w| {
                        w.write_sequence(|w| { w.write_oid(oids::RSA_ENCRYPTION); w.write_null(); });
                        let mut key = Writer::new();
                        key.write_sequence(|w| {
                            w.write_integer(&BigUint::from_hex("c0ffeeed").unwrap());
                            w.write_integer(&BigUint::from_u64(65537));
                        });
                        w.write_bit_string(&key.finish());
                    });
                    if !self.extensions.is_empty() {
                        t.write_constructed(Tag::context(3, true), |w| {
                            w.write_sequence(|w| {
                                for (oid, critical, value) in &self.extensions {
                                    w.write_sequence(|w| {
                                        w.write_oid(oid);
                                        if *critical { w.write_bool(true); }
                                        w.write_octet_string(value);
                                    });
                                }
                            });
                        });
                    }
                });
                c.write_sequence(|w| { w.write_oid(&self.outer_algorithm); w.write_null(); });
                c.write_bit_string(&[0xde, 0xad, 0xbe, 0xef]);
            });
            writer.finish()
        }
    }

    fn basic_constraints(is_ca: bool, path_len: Option<u32>) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            if is_ca { w.write_bool(true); }
            if let Some(limit) = path_len { w.write_u32(limit); }
        });
        writer.finish()
    }

    fn san(names: &[(u32, &[u8])]) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            for (tag, value) in names {
                w.write_tlv(Tag::context(*tag, false), value);
            }
        });
        writer.finish()
    }

    #[test]
    fn test_parses_a_minimal_certificate() {
        let der = build(|_| {});
        let certificate = Certificate::parse(&der).unwrap();

        assert_eq!(certificate.version, 3);
        assert_eq!(certificate.serial_hex(), "010203");
        assert_eq!(certificate.signature_algorithm,
                   SignatureAlgorithm::RsaPkcs1("sha256"));
        assert_eq!(certificate.subject.common_name().unwrap(), "example.test");
        assert_eq!(certificate.issuer.common_name().unwrap(), "Test CA");
        assert_eq!(certificate.subject.to_string(), "CN=example.test");
        assert_eq!(certificate.not_before, 1_577_836_800);   // 2020-01-01
        assert!(certificate.not_after > certificate.not_before);
        assert!(!certificate.is_self_issued());

        match certificate.public_key {
            PublicKey::Rsa { ref e, .. } => assert_eq!(e.to_u64(), Some(65537)),
            ref other => panic!("expected an RSA key, got {:?}", other),
        }

        // The TBS must be a slice of the original, starting with a SEQUENCE
        // tag - this is the thing the signature covers.
        assert_eq!(certificate.tbs[0], 0x30);
        assert!(der.windows(certificate.tbs.len()).any(|w| w == certificate.tbs));
    }

    /// The algorithm inside the TBS and the one outside it must agree. If
    /// they may differ, the verifier and anyone reading the certificate can
    /// be shown different things.
    #[test]
    fn test_algorithm_mismatch_is_rejected() {
        let der = build(|p| p.outer_algorithm = oids::SHA1_WITH_RSA.to_vec());
        let error = Certificate::parse(&der).unwrap_err();
        assert!(error.contains("mismatch"), "{}", error);
    }

    /// Two *different* unrecognised algorithms are a mismatch too.
    ///
    /// What was wrong: the two identifiers were compared as the parsed
    /// `SignatureAlgorithm`, and every OID the table does not know maps
    /// to the one `Unknown` variant, so any two unknown OIDs compared
    /// equal - as did two PSS identifiers with different parameters.
    /// The test above used two known algorithms, which the enum does
    /// tell apart. The comparison is now over the bytes that arrived,
    /// as RFC 5280 4.1.1.2 asks.
    #[test]
    fn test_two_different_unknown_algorithms_are_a_mismatch() {
        let inner = asn1::encode_oid("1.3.6.1.4.1.99999.1").unwrap();
        let outer = asn1::encode_oid("1.3.6.1.4.1.99999.2").unwrap();
        let der = build(|p| {
            p.inner_algorithm = inner.clone();
            p.outer_algorithm = outer.clone();
        });
        let error = Certificate::parse(&der).unwrap_err();
        assert!(error.contains("mismatch"), "{}", error);

        // The same unknown OID on both sides still parses: unknown is
        // recorded, not refused, so the verifier can say what it was.
        let der = build(|p| {
            p.inner_algorithm = inner.clone();
            p.outer_algorithm = inner.clone();
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(certificate.signature_algorithm, SignatureAlgorithm::Unknown);
    }

    #[test]
    fn test_version_rules() {
        // v1 with no extensions is fine.
        let der = build(|p| p.version = None);
        assert_eq!(Certificate::parse(&der).unwrap().version, 1);

        // Extensions require v3.
        let der = build(|p| {
            p.version = None;
            p.extensions = vec![(oids::BASIC_CONSTRAINTS.to_vec(), true,
                                 basic_constraints(true, None))];
        });
        assert!(Certificate::parse(&der).unwrap_err().contains("version 1"));

        // An unknown version number is refused rather than assumed.
        let der = build(|p| p.version = Some(7));
        assert!(Certificate::parse(&der).is_err());
    }

    #[test]
    fn test_basic_constraints() {
        for (is_ca, path_len) in [(false, None), (true, None), (true, Some(0)),
                                  (true, Some(3))] {
            let der = build(|p| {
                p.extensions = vec![(oids::BASIC_CONSTRAINTS.to_vec(), true,
                                     basic_constraints(is_ca, path_len))];
            });
            let certificate = Certificate::parse(&der).unwrap();
            assert_eq!(certificate.extensions.is_ca(), is_ca);
            assert_eq!(certificate.extensions.path_len(), path_len);
        }

        // A path length on something that is not a CA is a CA's mistake
        // (RFC 5280 4.2.1.9) and is recorded, not refused: the parser
        // reads and the verifier judges, and `check_issuer` refuses a
        // cA=FALSE issuer whatever the field says. This used to be a
        // parse error, which made a leaf unreadable for an extension
        // that could not be used against anyone.
        let mut writer = Writer::new();
        writer.write_sequence(|w| w.write_u32(2));
        let odd = writer.finish();
        let der = build(|p| {
            p.extensions = vec![(oids::BASIC_CONSTRAINTS.to_vec(), true, odd)];
        });
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(certificate.extensions.basic_constraints, Some((false, Some(2))));
        assert!(!certificate.extensions.is_ca());
        assert_eq!(certificate.extensions.path_len(), None);
    }

    #[test]
    fn test_duplicate_extensions_are_rejected() {
        let der = build(|p| {
            p.extensions = vec![
                (oids::BASIC_CONSTRAINTS.to_vec(), true, basic_constraints(false, None)),
                (oids::BASIC_CONSTRAINTS.to_vec(), true, basic_constraints(true, None)),
            ];
        });
        let error = Certificate::parse(&der).unwrap_err();
        assert!(error.contains("Duplicate"), "{}", error);
    }

    #[test]
    fn test_unrecognised_critical_extension_is_recorded() {
        let der = build(|p| {
            p.extensions = vec![
                (asn1::encode_oid("1.3.6.1.4.1.99999.1").unwrap(), true, vec![0x05, 0x00]),
                (asn1::encode_oid("1.3.6.1.4.1.99999.2").unwrap(), false, vec![0x05, 0x00]),
            ];
        });
        let certificate = Certificate::parse(&der).unwrap();
        // Critical and unknown is recorded; non-critical and unknown is not.
        assert_eq!(certificate.extensions.unrecognised_critical.len(), 1);
        assert_eq!(certificate.extensions.present.len(), 2);
    }

    #[test]
    fn test_subject_alt_names() {
        let der = build(|p| {
            p.extensions = vec![(oids::SUBJECT_ALT_NAME.to_vec(), false,
                                 san(&[(2, b"example.test"), (2, b"*.example.test"),
                                       (1, b"someone@example.test"),
                                       (7, &[192, 0, 2, 1]),
                                       (6, b"https://example.test/")]))];
        });
        let certificate = Certificate::parse(&der).unwrap();
        let names = &certificate.extensions.subject_alt_names;
        assert_eq!(names.len(), 5);
        assert_eq!(certificate.extensions.dns_names(),
                   vec!["example.test", "*.example.test"]);
        assert!(names.contains(&GeneralName::IpAddress(&[192, 0, 2, 1])));
        assert!(names.contains(&GeneralName::Email("someone@example.test")));
    }

    /// The null prefix attack: `evil.test\0.good.test` is one ASN.1 string,
    /// and anything that stops at a NUL sees only the first half.
    ///
    /// **What is refused changed, and the protection did not.** A NUL in
    /// a *name attribute* no longer fails the parse - it fails that
    /// attribute's text, so the CN is not available to match a hostname
    /// against, which is the only place the attack lives. See
    /// `Attribute::text` for why, and
    /// `test_a_bmpstring_name_is_not_a_nul_attack` for what the old
    /// check cost.
    #[test]
    fn test_embedded_nul_is_rejected() {
        let der = build(|p| {
            p.extensions = vec![(oids::SUBJECT_ALT_NAME.to_vec(), false,
                                 san(&[(2, b"evil.test\0.good.test")]))];
        });
        // In a subjectAltName it is kept as malformed, not refused, and
        // matches neither half.
        let leaf = Certificate::parse(&der).expect("one odd SAN entry made it unreadable");
        assert_eq!(leaf.extensions.subject_alt_names,
                   [GeneralName::Malformed(2, b"evil.test\0.good.test")]);
        assert!(leaf.extensions.dns_names().is_empty());
        assert!(!crate::x509::verify::matches_hostname(&leaf, "evil.test"));
        assert!(!crate::x509::verify::matches_hostname(&leaf, "good.test"));

        // And in the common name, which is where the original attack
        // was. The certificate parses now - and the name does not come
        // out, so nothing downstream can match against it.
        let der = build(|p| p.common_name = b"evil.test\0.good.test".to_vec());
        let leaf = Certificate::parse(&der)
            .expect("a NUL in a name is no longer a parse error");
        assert_eq!(leaf.subject.get(oids::COMMON_NAME), None,
                   "the common name came out despite its NUL");
        // Which is what makes the attack fail: neither half matches.
        assert!(!crate::x509::verify::matches_hostname(&leaf, "evil.test"));
        assert!(!crate::x509::verify::matches_hostname(&leaf, "good.test"));
        assert!(!crate::x509::verify::matches_hostname(&leaf, "evil.test\0.good.test"));
    }

    /// **The bug a live server found.**
    ///
    /// A `BMPString` is UTF-16, so every ASCII character in one is
    /// `00 xx`. The embedded-NUL check used to run on the *encoded*
    /// bytes in `Name::parse`, which meant every certificate carrying a
    /// `BMPString` anywhere in a name was refused as a null-prefix
    /// attack - and `BMPString` is a common encoding for Cyrillic, so
    /// it refused exactly the certificates this library exists to read.
    ///
    /// It reached us as `check_live.py --gost` reporting
    /// *"certificate verify failed: bad_certificate: Name attribute
    /// contains an embedded NUL"* from two CryptoPro GOST TLS servers.
    /// Nothing offline could have found it: every certificate the test
    /// suite judges is one this library generated, and the builder
    /// writes `UTF8String`.
    #[test]
    fn test_a_bmpstring_name_is_not_a_nul_attack() {
        // "ok.test" as UTF-16BE, which is what a BMPString holds.
        let mut utf16 = Vec::new();
        for unit in "ok.test".encode_utf16() {
            utf16.extend_from_slice(&unit.to_be_bytes());
        }
        assert!(utf16.contains(&0), "a BMPString of ASCII must contain NULs, \
                                     or this test is not about anything");

        let der = build(|p| {
            p.common_name = utf16;
            p.common_name_tag = asn1::tag::BMP_STRING;
        });
        let leaf = Certificate::parse(&der)
            .expect("a BMPString name was refused as a NUL attack");
        assert_eq!(leaf.subject.get(oids::COMMON_NAME),
                   Some("ok.test".to_string()));
        assert!(crate::x509::verify::matches_hostname(&leaf, "ok.test"));

        // And the attack still fails in a BMPString: a *real* NUL is
        // `00 00` there, and it survives the decoding.
        let mut attack = Vec::new();
        for unit in "evil.test\0.good.test".encode_utf16() {
            attack.extend_from_slice(&unit.to_be_bytes());
        }
        let der = build(|p| {
            p.common_name = attack;
            p.common_name_tag = asn1::tag::BMP_STRING;
        });
        let leaf = Certificate::parse(&der).unwrap();
        assert_eq!(leaf.subject.get(oids::COMMON_NAME), None,
                   "a NUL inside a BMPString got through");
        assert!(!crate::x509::verify::matches_hostname(&leaf, "evil.test"));
    }

    /// An address of the wrong length is kept as malformed rather than
    /// refusing the certificate, and is never an address: not three bytes
    /// of one, and not padded into one.
    #[test]
    fn test_a_bad_ip_address_length_is_kept_as_malformed() {
        let der = build(|p| {
            p.extensions = vec![(oids::SUBJECT_ALT_NAME.to_vec(), false,
                                 san(&[(7, &[192, 0, 2])]))];
        });
        let leaf = Certificate::parse(&der).unwrap();
        assert_eq!(leaf.extensions.subject_alt_names,
                   [GeneralName::Malformed(7, &[192, 0, 2])]);
        assert!(!crate::x509::verify::matches_hostname(&leaf, "192.0.2.0"));
    }

    #[test]
    fn test_key_usage_bits() {
        // digitalSignature and keyCertSign: bits 0 and 5, so 0b10000100 with
        // two bits of the byte unused.
        let mut writer = Writer::new();
        writer.write_tlv(Tag::universal(asn1::tag::BIT_STRING), &[0x02, 0b1000_0100]);
        let value = writer.finish();

        let der = build(|p| {
            p.extensions = vec![(oids::KEY_USAGE.to_vec(), true, value.clone())];
        });
        let usage = Certificate::parse(&der).unwrap().extensions.key_usage.unwrap();
        assert!(usage.digital_signature);
        assert!(usage.key_cert_sign);
        assert!(!usage.key_encipherment);
        assert!(!usage.crl_sign);
        assert!(!usage.decipher_only);
    }

    #[test]
    fn test_truncation_at_every_offset_is_an_error_not_a_panic() {
        let der = build(|p| {
            p.extensions = vec![
                (oids::BASIC_CONSTRAINTS.to_vec(), true, basic_constraints(true, Some(1))),
                (oids::SUBJECT_ALT_NAME.to_vec(), false, san(&[(2, b"example.test")])),
            ];
        });
        for cut in 0..der.len() {
            let _ = Certificate::parse(&der[..cut]);
        }
        // And a byte flipped at every offset.
        for index in 0..der.len() {
            let mut corrupt = der.clone();
            corrupt[index] ^= 0xff;
            let _ = Certificate::parse(&corrupt);
        }
    }

    #[test]
    fn test_trailing_data_after_the_certificate_is_rejected() {
        let mut der = build(|_| {});
        der.push(0x00);
        assert!(Certificate::parse(&der).is_err());
    }

    #[test]
    fn test_signature_algorithms_are_recognised() {
        for (oid, expected) in [
            (oids::SHA256_WITH_RSA, SignatureAlgorithm::RsaPkcs1("sha256")),
            (oids::SHA1_WITH_RSA, SignatureAlgorithm::RsaPkcs1("sha1")),
            (oids::MD5_WITH_RSA, SignatureAlgorithm::RsaPkcs1("md5")),
            (oids::ECDSA_WITH_SHA256, SignatureAlgorithm::Ecdsa("sha256")),
            (oids::ECDSA_WITH_SHA384, SignatureAlgorithm::Ecdsa("sha384")),
            (oids::RSASSA_PSS, SignatureAlgorithm::Unsupported("RSASSA-PSS")),
        ] {
            let der = build(|p| {
                p.inner_algorithm = oid.to_vec();
                p.outer_algorithm = oid.to_vec();
            });
            assert_eq!(Certificate::parse(&der).unwrap().signature_algorithm, expected);
        }
    }
}

#[cfg(test)]
mod real_world_tests {
    use super::*;

    /// Real roots violate RFC 5280's "the serial number MUST be a positive
    /// integer": Go Daddy's G2 root, both Starfield G2 roots and the
    /// Hellenic academic roots all use serial 0. Refusing them would mean
    /// refusing a large slice of the public web.
    ///
    /// `tools/src/bin/diff_roots.rs` parses every root on the machine and
    /// compares each field with OpenSSL; this pins the specific case so a
    /// future tightening of the INTEGER rules fails here with an
    /// explanation rather than in a corpus.
    #[test]
    fn test_a_zero_serial_is_accepted() {
        use crate::asn1::{Tag, Writer};

        let mut writer = Writer::new();
        writer.write_sequence(|c| {
            c.write_sequence(|t| {
                t.write_constructed(Tag::context(0, true), |w| w.write_u32(2));
                t.write_tlv(Tag::universal(asn1::tag::INTEGER), &[0x00]);
                t.write_sequence(|w| { w.write_oid(oids::SHA256_WITH_RSA); w.write_null(); });
                t.write_sequence(|w| {
                    w.write_set(|w| w.write_sequence(|w| {
                        w.write_oid(oids::COMMON_NAME);
                        w.write_utf8_string("Zero Serial Root");
                    }));
                });
                t.write_sequence(|w| {
                    w.write_tlv(Tag::universal(asn1::tag::UTC_TIME), b"200101000000Z");
                    w.write_tlv(Tag::universal(asn1::tag::UTC_TIME), b"300101000000Z");
                });
                t.write_sequence(|w| {
                    w.write_set(|w| w.write_sequence(|w| {
                        w.write_oid(oids::COMMON_NAME);
                        w.write_utf8_string("Zero Serial Root");
                    }));
                });
                t.write_sequence(|w| {
                    w.write_sequence(|w| { w.write_oid(oids::RSA_ENCRYPTION); w.write_null(); });
                    let mut key = Writer::new();
                    key.write_sequence(|w| {
                        w.write_integer(&BigUint::from_hex("c0ffeeed").unwrap());
                        w.write_integer(&BigUint::from_u64(65537));
                    });
                    w.write_bit_string(&key.finish());
                });
            });
            c.write_sequence(|w| { w.write_oid(oids::SHA256_WITH_RSA); w.write_null(); });
            c.write_bit_string(&[0xde, 0xad]);
        });

        let der = writer.finish();
        let certificate = Certificate::parse(&der).unwrap();
        assert_eq!(certificate.serial_hex(), "00");
        assert!(certificate.is_self_issued());
    }

    /// An EC SPKI on any curve - for the tests below, a brainpool curve,
    /// which this library does not implement yet.
    fn ec_spki(curve: &[u8]) -> Vec<u8> {
        use crate::asn1::Writer;
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_sequence(|w| {
                w.write_oid(oids::EC_PUBLIC_KEY);
                w.write_oid(curve);
            });
            // An uncompressed point, contents irrelevant: nothing here
            // does arithmetic on it.
            w.write_bit_string(&[0x04; 133]);
        });
        writer.finish()
    }

    /// A curve we cannot compute on must still parse.
    ///
    /// This used to be `Err("Unsupported curve ...")`, and the cost was out
    /// of all proportion to the cause. `TrustStore` parses each root as it
    /// loads it, so one root on an unimplemented curve was dropped from the
    /// store entirely and reported only as a number - a live run said "120
    /// roots loaded, 1 skipped as unparseable" and there was no way to tell
    /// which root or what was wrong with it. Worse, a *server* presenting
    /// such a certificate got "cannot parse", which reads as a malformed
    /// certificate rather than as a gap in this library.
    ///
    /// The existing tests missed it because every certificate they build
    /// carries an RSA key, and the real-certificate corpus in
    /// `tools/src/bin/diff_x509.rs` only has curves OpenSSL and this library
    /// both implement - so the failing branch was never taken.
    #[test]
    fn test_an_unimplemented_curve_parses_and_is_named() {
        // brainpoolP256r1, 1.3.36.3.3.2.8.1.1.7. This was secp521r1 until
        // P-521 arrived.
        let brainpool = [0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
        let der = ec_spki(&brainpool);
        let mut reader = Reader::new(&der);
        match read_public_key(&mut reader).unwrap() {
            PublicKey::UnsupportedCurve { oid, .. } => {
                assert_eq!(oid.to_string(), "1.3.36.3.3.2.8.1.1.7");
            }
            other => panic!("expected an unsupported curve, got {:?}", other),
        }

        // And the curves we do implement are still recognised, so this is
        // not a change that swallows everything.
        for (oid, name) in [(oids::SECP384R1, "P-384"), (oids::SECP521R1, "P-521")] {
            let der = ec_spki(oid);
            let mut reader = Reader::new(&der);
            match read_public_key(&mut reader).unwrap() {
                PublicKey::Ec { curve, .. } => assert_eq!(curve, name),
                other => panic!("expected {name}, got {:?}", other),
            }
        }
    }

    /// An RFC 8410 SPKI, for the tests below. Written here rather than
    /// taken from the builder, so the two encoders are separate.
    fn eddsa_spki(oid: &[u8], key: &[u8], null_parameter: bool) -> Vec<u8> {
        use crate::asn1::Writer;
        let mut writer = Writer::new();
        writer.write_sequence(|w| {
            w.write_sequence(|w| {
                w.write_oid(oid);
                if null_parameter {
                    w.write_null();
                }
            });
            w.write_bit_string(key);
        });
        writer.finish()
    }

    #[test]
    fn test_an_ed25519_key_parses_as_raw_bytes() {
        let der = eddsa_spki(oids::ID_ED25519, &[0x11; 32], false);
        let mut reader = Reader::new(&der);
        match read_public_key(&mut reader).unwrap() {
            PublicKey::Eddsa { curve, key } => {
                assert_eq!(curve, "ed25519");
                assert_eq!(key, &[0x11; 32]);
            }
            other => panic!("expected ed25519, got {:?}", other),
        }

        let der = eddsa_spki(oids::ID_ED448, &[0x22; 57], false);
        let mut reader = Reader::new(&der);
        match read_public_key(&mut reader).unwrap() {
            PublicKey::Eddsa { curve, key } => {
                assert_eq!(curve, "ed448");
                assert_eq!(key.len(), 57);
            }
            other => panic!("expected ed448, got {:?}", other),
        }
    }

    /// RFC 8410 section 3: the parameters field MUST be absent.
    ///
    /// An explicit NULL is what an encoder copied from the RSA branch
    /// writes, and it parses in plenty of software - so nothing but a
    /// direct check sees it.
    #[test]
    fn test_a_null_parameter_is_refused() {
        let der = eddsa_spki(oids::ID_ED25519, &[0x11; 32], true);
        let mut reader = Reader::new(&der);
        let error = read_public_key(&mut reader).unwrap_err();
        assert!(error.contains("absent"), "{}", error);
        assert!(error.contains("8410"), "{}", error);
    }

    /// **A check that another check covers is invisible to a breakage
    /// sweep.** Removing this length test left every test passing,
    /// because `eddsa_verify` refuses a wrong-length key further down -
    /// so the certificate still fails, with an error about the
    /// signature rather than about the key. That is defence in depth
    /// rather than a hole, and the way to hold it is to pin the
    /// message, which is what tells a reader which of the two fired.
    #[test]
    fn test_a_wrong_length_ed25519_key_says_so_at_the_parser() {
        for length in [0usize, 31, 33, 57, 64] {
            let der = eddsa_spki(oids::ID_ED25519, &vec![0x11; length], false);
            let mut reader = Reader::new(&der);
            let error = read_public_key(&mut reader).unwrap_err();
            assert!(error.contains("public key is 32 bytes"),
                    "length {length} gave {error:?}");
        }
        // And 57 bytes is right for Ed448, so the check is per-variant
        // rather than a single constant.
        let der = eddsa_spki(oids::ID_ED448, &[0x11; 57], false);
        let mut reader = Reader::new(&der);
        assert!(read_public_key(&mut reader).is_ok());
    }

    /// Parsing it is not using it: a signature made with a key on a curve
    /// we cannot compute on must still fail, and say why.
    #[test]
    fn test_an_unimplemented_curve_cannot_verify_a_signature() {
        let brainpool = [0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
        let der = ec_spki(&brainpool);
        let mut reader = Reader::new(&der);
        let key = read_public_key(&mut reader).unwrap();
        let described = crate::x509::verify::describe_key(&key);
        assert!(described.contains("1.3.36.3.3.2.8.1.1.7"), "{}", described);
        assert!(described.contains("unsupported parameter set"), "{}", described);
        // **And which family it was**, which the message used to leave
        // out: `id-ecPublicKey` and the GOST algorithms all name their
        // curve in the algorithm parameters and all arrive here, so a
        // message saying only "EC" sent whoever read it to the wrong
        // table. A live server reported a GOST parameter set that way.
        assert!(described.contains("EC "), "{}", described);
    }
}
