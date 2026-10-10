/*
The object identifiers certificates use.

These are `&[u8]` constants rather than something parsed at run time
because OID comparison is how a certificate decides what an extension
means, and comparing byte slices cannot go subtly wrong the way comparing
decoded arc lists can.

**The bytes are computed at compile time from the dotted form**, by
`encode_const` below. They used to be written out by hand next to each
name, and a typo in one is close to the worst bug available here: an OID
that never matches means an extension is silently unrecognised - and an
unrecognised *critical* extension must cause rejection, while an
unrecognised basicConstraints means not noticing that a leaf certificate
claims to be a CA. Now there is nothing to mistype: every hand-typed
byte array became one encoder, and the table has grown to well over a
hundred entries since without another byte being typed.

That moves the risk rather than removing it, so the encoder is checked
three ways, none of them by itself enough:

  1. `tests` below compares every constant against `asn1::encode_oid`,
     the run-time encoder. Two encoders written separately agreeing is
     worth more than either agreeing with itself - but they are both
     ours.
  2. `scripts/diff_check.py` re-encodes each dotted form with an encoder
     written from X.690 in Python, which is not ours.
  3. The same script looks each constant's *name* up in
     python-cryptography's tables, which are OpenSSL's, and compares the
     number. That is the check nothing had before: the dotted string and
     the bytes were both typed from one glance at one document, so they
     could agree with each other and disagree with the world.

Most have a counterpart over there. The ones that do not are named in
that script (`_OID_EQUIVALENTS`, mapped to `None`) with what covers them
instead, or that nothing does - and a constant missing from that map
entirely fails the script, so the list cannot drift silently.
*/

/// The longest OID here, with room to spare. A dotted form that needs
/// more than this fails to compile rather than truncating.
const MAX_ENCODED: usize = 32;

/// Encode an OID from its dotted form at compile time, X.690 section 8.19.
///
/// The first two arcs are packed into one byte as `40 * a + b`, which is
/// why `2.5.4.3` starts 0x55. Every arc after that is base 128, most
/// significant group first, with the top bit set on every group but the
/// last.
///
/// Written as a `const fn` and therefore without iterators, `?` or
/// `String` - which is why it is a loop over bytes with an index. It
/// returns the buffer and the used length because a `const fn` cannot
/// return a slice whose length it computed.
const fn encode_const(dotted: &str) -> ([u8; MAX_ENCODED], usize) {
    let bytes = dotted.as_bytes();
    let mut out = [0u8; MAX_ENCODED];
    let mut len = 0usize;

    let mut index = 0usize;
    let mut arc: u64 = 0;
    let mut arc_index = 0usize;
    let mut first: u64 = 0;

    loop {
        let at_end = index == bytes.len();
        if at_end || bytes[index] == b'.' {
            if arc_index == 0 {
                // Held back: the first arc is not encoded on its own.
                first = arc;
            } else {
                let value = if arc_index == 1 { 40 * first + arc } else { arc };
                let mut groups = [0u8; 10];
                let mut count = 0usize;
                let mut rest = value;
                loop {
                    groups[count] = (rest & 0x7f) as u8;
                    count += 1;
                    rest >>= 7;
                    if rest == 0 {
                        break;
                    }
                }
                let mut group = count;
                while group > 0 {
                    group -= 1;
                    // Every group but the last carries a continuation bit.
                    out[len] = groups[group] | if group > 0 { 0x80 } else { 0 };
                    len += 1;
                }
            }
            arc_index += 1;
            arc = 0;
            if at_end {
                break;
            }
        } else {
            arc = arc * 10 + (bytes[index] - b'0') as u64;
        }
        index += 1;
    }
    (out, len)
}

macro_rules! oids {
    ($($name:ident = $dotted:literal;)*) => {
        $(
            pub const $name: &[u8] = {
                const ENCODED: ([u8; MAX_ENCODED], usize) = encode_const($dotted);
                ENCODED.0.split_at(ENCODED.1).0
            };
        )*

        /// Every constant with its dotted form, for the tests below and
        /// for rendering an unknown OID in an error message.
        pub const ALL: &[(&str, &[u8])] = &[$(($dotted, $name),)*];

        /// The same, with the constant's own identifier.
        ///
        /// The identifier is what `scripts/diff_check.py` matches against
        /// another library's table: an encoder agreeing with itself says
        /// nothing about whether the dotted string is the number the
        /// world assigns to *this name*.
        pub const ALL_NAMED: &[(&str, &str, &[u8])] =
            &[$((stringify!($name), $dotted, $name),)*];
    };
}

oids! {
    // Password based encryption, PKCS#5 (1.2.840.113549.1.5.x) and its
    // key derivations. The six PBES1 schemes are listed in full even
    // though two of them need MD2, which this library does not have
    // yet: a reader that recognises the scheme can say "no MD2", and
    // one that does not can only say "unknown OID".
    PBE_MD2_DES           = "1.2.840.113549.1.5.1";
    PBE_MD5_DES           = "1.2.840.113549.1.5.3";
    PBE_MD2_RC2           = "1.2.840.113549.1.5.4";
    PBE_MD5_RC2           = "1.2.840.113549.1.5.6";
    PBE_SHA1_DES          = "1.2.840.113549.1.5.10";
    PBE_SHA1_RC2          = "1.2.840.113549.1.5.11";
    PBKDF2                = "1.2.840.113549.1.5.12";
    PBES2                 = "1.2.840.113549.1.5.13";

    // PBKDF2's PRFs (1.2.840.113549.2.x). Absent in a file means
    // hmacWithSHA1 by DEFAULT, which is why older files carry no PRF at
    // all rather than naming SHA-1.
    HMAC_WITH_SHA1        = "1.2.840.113549.2.7";
    HMAC_WITH_SHA224      = "1.2.840.113549.2.8";
    HMAC_WITH_SHA256      = "1.2.840.113549.2.9";
    HMAC_WITH_SHA384      = "1.2.840.113549.2.10";
    HMAC_WITH_SHA512      = "1.2.840.113549.2.11";
    HMAC_WITH_SHA512_224  = "1.2.840.113549.2.12";
    HMAC_WITH_SHA512_256  = "1.2.840.113549.2.13";

    // The PKCS#12 password schemes (1.2.840.113549.1.12.1.x). Not
    // PBES1 and not PBES2: a third key derivation, and the one OpenSSL
    // still writes for `-v1`.
    PBE_SHA1_128_RC4      = "1.2.840.113549.1.12.1.1";
    PBE_SHA1_RC4_40       = "1.2.840.113549.1.12.1.2";
    PBE_SHA1_3DES         = "1.2.840.113549.1.12.1.3";
    PBE_SHA1_2DES         = "1.2.840.113549.1.12.1.4";
    PBE_SHA1_RC2_128      = "1.2.840.113549.1.12.1.5";
    PBE_SHA1_RC2_40       = "1.2.840.113549.1.12.1.6";

    // Java's two private key protectors, from Sun's arc and in no RFC:
    // JKS's SHA-1 keystream, and JCEKS's PBEWithMD5AndTripleDES.
    JKS_KEY_PROTECTOR     = "1.3.6.1.4.1.42.2.17.1.1";
    JCE_KEY_PROTECTOR     = "1.3.6.1.4.1.42.2.19.1";

    // Symmetric ciphers, as PBES2 names them.
    DES_CBC               = "1.3.14.3.2.7";
    DES_EDE3_CBC          = "1.2.840.113549.3.7";
    RC2_CBC               = "1.2.840.113549.3.2";
    AES128_CBC            = "2.16.840.1.101.3.4.1.2";
    AES192_CBC            = "2.16.840.1.101.3.4.1.22";
    AES256_CBC            = "2.16.840.1.101.3.4.1.42";

    // Signature algorithms, PKCS#1 (1.2.840.113549.1.1.x)
    RSA_ENCRYPTION        = "1.2.840.113549.1.1.1";
    SHA1_WITH_RSA         = "1.2.840.113549.1.1.5";
    SHA224_WITH_RSA       = "1.2.840.113549.1.1.14";
    SHA256_WITH_RSA       = "1.2.840.113549.1.1.11";
    SHA384_WITH_RSA       = "1.2.840.113549.1.1.12";
    SHA512_WITH_RSA       = "1.2.840.113549.1.1.13";
    RSASSA_PSS            = "1.2.840.113549.1.1.10";
    MD5_WITH_RSA          = "1.2.840.113549.1.1.4";
    MD2_WITH_RSA          = "1.2.840.113549.1.1.2";

    // Elliptic curve (1.2.840.10045.x)
    EC_PUBLIC_KEY         = "1.2.840.10045.2.1";
    ECDSA_WITH_SHA1       = "1.2.840.10045.4.1";
    ECDSA_WITH_SHA224     = "1.2.840.10045.4.3.1";
    ECDSA_WITH_SHA256     = "1.2.840.10045.4.3.2";
    ECDSA_WITH_SHA384     = "1.2.840.10045.4.3.3";
    ECDSA_WITH_SHA512     = "1.2.840.10045.4.3.4";

    // DSA: RFC 3279 for the key and SHA-1, RFC 5758 for SHA-224 and
    // SHA-256, NIST's sigAlgs arc for SHA-384 and SHA-512. The key's
    // parameters are a Dss-Parms SEQUENCE; the signatures' are absent.
    ID_DSA                = "1.2.840.10040.4.1";
    DSA_WITH_SHA1         = "1.2.840.10040.4.3";
    DSA_WITH_SHA224       = "2.16.840.1.101.3.4.3.1";
    DSA_WITH_SHA256       = "2.16.840.1.101.3.4.3.2";
    DSA_WITH_SHA384       = "2.16.840.1.101.3.4.3.3";
    DSA_WITH_SHA512       = "2.16.840.1.101.3.4.3.4";

    // RFC 8410's arc, 1.3.101.x. **One OID serves as both the key
    // algorithm and the signature algorithm** - there is no
    // "Ed25519 with SHA-512" the way there is "ECDSA with SHA-256",
    // because the hash is inside EdDSA and is not negotiable. The
    // AlgorithmIdentifier's parameters field must be *absent*, not
    // NULL, which is the one thing about this encoding that a parser
    // written from the EC one gets wrong.
    ID_ED25519            = "1.3.101.112";
    ID_ED448              = "1.3.101.113";
    ID_X25519             = "1.3.101.110";
    ID_X448               = "1.3.101.111";

    // RFC 9881, ML-DSA (FIPS 204) under NIST's sigAlgs arc. Like
    // EdDSA's, **each OID is both the key algorithm and the signature
    // algorithm**, the parameters are absent, and the BIT STRING is the
    // raw key. HashML-DSA has OIDs of its own and RFC 9881 section 8.3
    // keeps them out of certificates.
    ID_ML_DSA_44          = "2.16.840.1.101.3.4.3.17";
    ID_ML_DSA_65          = "2.16.840.1.101.3.4.3.18";
    ID_ML_DSA_87          = "2.16.840.1.101.3.4.3.19";

    // Named curves
    PRIME256V1            = "1.2.840.10045.3.1.7";
    SECP384R1             = "1.3.132.0.34";
    SECP521R1             = "1.3.132.0.35";
    SECP256K1             = "1.3.132.0.10";

    // Hashes, for the DigestInfo in a PSS parameter block and for
    // SLH-DSA's pre-hash message formatting, which carries the DER of
    // one of these in front of the digest (FIPS 205 section 10.2).
    //
    // All twelve of NIST's hash arc are here rather than only the four
    // that were needed first, because FIPS 205 approves all twelve as
    // pre-hash functions and a partial table would mean a second place
    // to look. The dotted forms are checked against OpenSSL's object
    // table by `scripts/diff_check.py` - an encoder agreeing with itself
    // says nothing about whether these are the numbers the world assigns
    // to these names.
    SHA1                  = "1.3.14.3.2.26";
    SHA224                = "2.16.840.1.101.3.4.2.4";
    SHA256                = "2.16.840.1.101.3.4.2.1";
    SHA384                = "2.16.840.1.101.3.4.2.2";
    SHA512                = "2.16.840.1.101.3.4.2.3";
    SHA512_224            = "2.16.840.1.101.3.4.2.5";
    SHA512_256            = "2.16.840.1.101.3.4.2.6";
    SHA3_224              = "2.16.840.1.101.3.4.2.7";
    SHA3_256              = "2.16.840.1.101.3.4.2.8";
    SHA3_384              = "2.16.840.1.101.3.4.2.9";
    SHA3_512              = "2.16.840.1.101.3.4.2.10";
    SHAKE128              = "2.16.840.1.101.3.4.2.11";
    SHAKE256              = "2.16.840.1.101.3.4.2.12";

    // Distinguished name attributes (2.5.4.x)
    COMMON_NAME           = "2.5.4.3";
    SURNAME               = "2.5.4.4";
    SERIAL_NUMBER         = "2.5.4.5";
    COUNTRY               = "2.5.4.6";
    LOCALITY              = "2.5.4.7";
    STATE_OR_PROVINCE     = "2.5.4.8";
    STREET_ADDRESS        = "2.5.4.9";
    ORGANIZATION          = "2.5.4.10";
    ORGANIZATIONAL_UNIT   = "2.5.4.11";
    TITLE                 = "2.5.4.12";
    GIVEN_NAME            = "2.5.4.42";
    EMAIL_ADDRESS         = "1.2.840.113549.1.9.1";
    DOMAIN_COMPONENT      = "0.9.2342.19200300.100.1.25";
    USER_ID               = "0.9.2342.19200300.100.1.1";

    // Certificate extensions (2.5.29.x)
    SUBJECT_KEY_ID        = "2.5.29.14";
    KEY_USAGE             = "2.5.29.15";
    SUBJECT_ALT_NAME      = "2.5.29.17";
    ISSUER_ALT_NAME       = "2.5.29.18";
    BASIC_CONSTRAINTS     = "2.5.29.19";
    CRL_NUMBER            = "2.5.29.20";
    CRL_REASON_CODE       = "2.5.29.21";
    INVALIDITY_DATE       = "2.5.29.24";
    DELTA_CRL_INDICATOR   = "2.5.29.27";
    ISSUING_DISTRIBUTION_POINT = "2.5.29.28";
    CERTIFICATE_ISSUER    = "2.5.29.29";
    NAME_CONSTRAINTS      = "2.5.29.30";
    CRL_DISTRIBUTION      = "2.5.29.31";
    FRESHEST_CRL          = "2.5.29.46";
    CERTIFICATE_POLICIES  = "2.5.29.32";
    AUTHORITY_KEY_ID      = "2.5.29.35";
    EXT_KEY_USAGE         = "2.5.29.37";

    // Extended key usages (1.3.6.1.5.5.7.3.x)
    EKU_SERVER_AUTH       = "1.3.6.1.5.5.7.3.1";
    EKU_CLIENT_AUTH       = "1.3.6.1.5.5.7.3.2";
    EKU_CODE_SIGNING      = "1.3.6.1.5.5.7.3.3";
    EKU_EMAIL             = "1.3.6.1.5.5.7.3.4";
    EKU_TIME_STAMPING     = "1.3.6.1.5.5.7.3.8";
    EKU_OCSP_SIGNING      = "1.3.6.1.5.5.7.3.9";
    EKU_ANY               = "2.5.29.37.0";

    // Authority information access, which OCSP lives under
    AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";
    // Its two access methods. `AD_OCSP` is where a responder lives;
    // `AD_CA_ISSUERS` is where the issuer's *certificate* lives, and
    // reporting the second as a responder would send an OCSP request
    // to a file server.
    AD_OCSP               = "1.3.6.1.5.5.7.48.1";
    AD_CA_ISSUERS         = "1.3.6.1.5.5.7.48.2";
    // OCSP itself (RFC 6960). `id-pkix-ocsp` and `id-ad-ocsp` are the
    // same arc, which is why `AD_OCSP` above is also the root of these.
    OCSP_BASIC            = "1.3.6.1.5.5.7.48.1.1";
    OCSP_NONCE            = "1.3.6.1.5.5.7.48.1.2";
    OCSP_NOCHECK          = "1.3.6.1.5.5.7.48.1.5";
    OCSP_ARCHIVE_CUTOFF   = "1.3.6.1.5.5.7.48.1.6";

    // GOST R 34.10-2012 keys and signatures (RFC 9215 appendix A), on
    // the TC 26 arc 1.2.643.7.1. Note the *two* families of signature
    // OID: `GOST3410_12_256` identifies a public key's algorithm, and
    // `GOST3410_12_256_WITH_DIGEST` identifies a signature - they differ
    // in one arc and both read as "GOST 256".
    GOST3410_12_256       = "1.2.643.7.1.1.1.1";
    GOST3410_12_512       = "1.2.643.7.1.1.1.2";
    GOST3411_12_256       = "1.2.643.7.1.1.2.2";
    GOST3411_12_512       = "1.2.643.7.1.1.2.3";
    GOST3410_12_256_WITH_DIGEST = "1.2.643.7.1.1.3.2";
    GOST3410_12_512_WITH_DIGEST = "1.2.643.7.1.1.3.3";

    // GOST R 34.10-2001 and GOST R 34.11-94 (RFC 4357 appendix A), on
    // the older CryptoPro arc 1.2.643.2.2. These are what a certificate
    // for the 0x0081 cipher suite carries, and what a box installed
    // before 2012 has.
    //
    // **The same split as above, and shorter arcs to confuse it
    // with**: `GOST3410_2001` identifies a public key's algorithm and
    // `GOST3411_94_WITH_GOST3410_2001` identifies a signature, and
    // neither contains the other's number.
    GOST3410_2001         = "1.2.643.2.2.19";
    // GOST R 34.10-94, the pre-elliptic-curve signature. Carried so a
    // certificate using it reads as "an algorithm this library does
    // not implement" rather than as an unknown OID: it is a discrete
    // log scheme over a prime field, not a curve, and nothing here
    // does that arithmetic.
    GOST3410_94           = "1.2.643.2.2.20";
    GOST3411_94           = "1.2.643.2.2.9";
    GOST3411_94_WITH_GOST3410_2001 = "1.2.643.2.2.3";
    GOST3411_94_WITH_GOST3410_94   = "1.2.643.2.2.4";
    // The hash parameter set every certificate on this arc names, and
    // the only one this library implements for it. RFC 4357 section
    // 11.2 has its S-box.
    GOST3411_94_CRYPTOPRO_PARAMSET = "1.2.643.2.2.30.1";
    GOST3411_94_TEST_PARAMSET      = "1.2.643.2.2.30.0";
    // The 28147-89 S-box the 0x0081 suite encrypts with, named in the
    // key transport message's `encryptionParamSet`.
    GOST_28147_CRYPTOPRO_A = "1.2.643.2.2.31.1";

    // Curve parameter sets. The 256 bit curves have two names each: the
    // CryptoPro ones from RFC 4357, which is what certificates in the
    // wild carry, and the TC 26 ones from RFC 7836, which are the same
    // curves renamed - and renamed with a *shift*, so CryptoPro-A is
    // paramSetB and there is a separate paramSetA that is a different
    // curve, stated by RFC 7836 in both twisted Edwards and short
    // Weierstrass form. This library has it in the second form, as
    // `gost256-tc26-a`.
    GOST_2001_CRYPTOPRO_A = "1.2.643.2.2.35.1";
    GOST_2001_CRYPTOPRO_B = "1.2.643.2.2.35.2";
    GOST_2001_CRYPTOPRO_C = "1.2.643.2.2.35.3";
    GOST_2001_CRYPTOPRO_XCHA = "1.2.643.2.2.36.0";
    GOST_2001_CRYPTOPRO_XCHB = "1.2.643.2.2.36.1";
    GOST_2012_256_PARAMSET_A = "1.2.643.7.1.2.1.1.1";
    GOST_2012_256_PARAMSET_B = "1.2.643.7.1.2.1.1.2";
    GOST_2012_256_PARAMSET_C = "1.2.643.7.1.2.1.1.3";
    GOST_2012_256_PARAMSET_D = "1.2.643.7.1.2.1.1.4";
    GOST_2012_512_PARAMSET_TEST = "1.2.643.7.1.2.1.2.0";
    GOST_2012_512_PARAMSET_A = "1.2.643.7.1.2.1.2.1";
    GOST_2012_512_PARAMSET_B = "1.2.643.7.1.2.1.2.2";
    GOST_2012_512_PARAMSET_C = "1.2.643.7.1.2.1.2.3";

    // The GOST 28147-89 S-box RFC 9189's CNT_IMIT suite requires.
    GOST_28147_PARAM_Z    = "1.2.643.7.1.2.5.1.1";
}

/// The curve a GOST parameter set OID names, as `ec::curves::by_name`
/// knows it - or `None` for a parameter set this library does not
/// implement.
///
/// `None` is deliberately distinct from "not a GOST OID at all": the
/// 512 bit *test* set and the CryptoPro exchange sets are real
/// parameter sets that we cannot do arithmetic on, and a certificate
/// carrying one should say so rather than reading as unrecognised.
pub fn gost_curve_for(oid: &[u8]) -> Option<&'static str> {
    // The CryptoPro names and the TC 26 names are the *same curves*, and
    // the TC 26 numbering is shifted by one: paramSetB is CryptoPro-A.
    // Written as one table so the shift is visible in one place instead
    // of being rediscovered at each call site.
    // The exchange sets are a third naming of two of the same curves.
    // RFC 4357 section 11.4 prints their parameters, and XchA's are
    // CryptoPro-A's to the digit while XchB's are CryptoPro-C's -
    // which is checked against the document in
    // `ec::curves::tests`. A certificate carrying one used to be
    // refused for a curve this library has had all along.
    if oid == GOST_2001_CRYPTOPRO_A || oid == GOST_2012_256_PARAMSET_B
        || oid == GOST_2001_CRYPTOPRO_XCHA {
        Some("gost256-a")
    } else if oid == GOST_2001_CRYPTOPRO_B || oid == GOST_2012_256_PARAMSET_C {
        Some("gost256-b")
    } else if oid == GOST_2001_CRYPTOPRO_C || oid == GOST_2012_256_PARAMSET_D
        || oid == GOST_2001_CRYPTOPRO_XCHB {
        Some("gost256-c")
    } else if oid == GOST_2012_256_PARAMSET_A {
        // No CryptoPro name: this set arrived with TC 26 in 2012. It
        // is the twisted Edwards curve of RFC 7836, and this library
        // uses the short Weierstrass form the same document gives.
        Some("gost256-tc26-a")
    } else if oid == GOST_2012_512_PARAMSET_A {
        Some("gost512-a")
    } else if oid == GOST_2012_512_PARAMSET_B {
        Some("gost512-b")
    } else if oid == GOST_2012_512_PARAMSET_C {
        Some("gost512-c")
    } else {
        // **And then whatever a caller has registered.** A parameter
        // set from an arc this library has never seen is the ordinary
        // way to meet a curve it does have, since the same curve is
        // named three times over already - see `src/registry.rs`.
        //
        // The leak is deliberate and bounded: `curves::by_name`
        // returns a `&'static str`, and the registry only ever holds
        // one of those names, so this turns a registered name back
        // into the static one rather than leaking a fresh string on
        // each call.
        let registered = crate::registry::curve_for_der(oid)?;
        // A registration naming a built-in curve resolves to that name's
        // `&'static str`, which is what this signature promises and what
        // keeps it from leaking a string per call.
        if let Some(builtin) = crate::ec::curves::NAMES.iter()
            .find(|name| **name == registered) {
            return Some(builtin);
        }
        // **And a registration that supplied its own parameters.** Its
        // name is not in `NAMES` - it is not a curve this file carries -
        // but `curves::from_parameters` interned it when it was
        // registered, so there is a `&'static str` for it already and
        // this hands back that one rather than making another.
        //
        // Without this arm a caller could register a curve, see it in
        // `registered_oids()`, use it through `curves::by_name`, and
        // still have a certificate carrying that very OID come back as
        // `UnsupportedCurve` - which is the one thing the registration
        // was for.
        crate::ec::curves::interned_name(&registered)
    }
}

/// The dotted form of a known OID, for error messages.
pub fn name_of(bytes: &[u8]) -> Option<&'static str> {
    ALL.iter().find(|(_, oid)| *oid == bytes).map(|(dotted, _)| *dotted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::encode_oid;

    /// Every constant must be exactly what the *run time* encoder makes
    /// of its dotted form.
    ///
    /// The bytes are produced by `encode_const` at compile time and this
    /// checks them against `asn1::encode_oid`, which was written
    /// separately. Two encoders agreeing is worth more than either
    /// agreeing with itself - and they are still both ours, which is why
    /// `scripts/diff_check.py` re-encodes the same dotted forms with a
    /// third written from X.690 in Python.
    #[test]
    fn test_every_constant_matches_its_dotted_form() {
        for (dotted, bytes) in ALL {
            assert_eq!(encode_oid(dotted).unwrap(), *bytes,
                       "constant for {} does not match its encoding", dotted);
        }
    }

    /// The compile-time encoder's edge cases, written out rather than
    /// only exercised through the table - the table happens not to
    /// contain an arc that needs three base-128 groups, and an encoder
    /// that broke on one would pass everything above.
    #[test]
    fn test_the_compile_time_encoder() {
        fn encoded(dotted: &str) -> Vec<u8> {
            let (buffer, length) = encode_const(dotted);
            buffer[..length].to_vec()
        }

        // The two-arc packing.
        assert_eq!(encoded("2.5.4.3"), vec![0x55, 0x04, 0x03]);
        assert_eq!(encoded("1.2"), vec![0x2a]);
        assert_eq!(encoded("0.0"), vec![0x00]);
        // A single arc needing two groups, and one needing three.
        assert_eq!(encoded("1.2.840"), vec![0x2a, 0x86, 0x48]);
        assert_eq!(encoded("0.9.2342.19200300.100.1.25"),
                   vec![0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19]);
        // And an arc of exactly 128, where the continuation bit starts.
        assert_eq!(encoded("1.2.127"), vec![0x2a, 0x7f]);
        assert_eq!(encoded("1.2.128"), vec![0x2a, 0x81, 0x00]);

        // Every one of those agrees with the run-time encoder too.
        for dotted in ["2.5.4.3", "1.2", "0.0", "1.2.840",
                       "0.9.2342.19200300.100.1.25", "1.2.127", "1.2.128"] {
            assert_eq!(encoded(dotted), encode_oid(dotted).unwrap(), "{}", dotted);
        }
    }

    /// And no two of them are the same, which a copy-paste slip would make.
    #[test]
    fn test_no_duplicate_constants() {
        for (index, (dotted, bytes)) in ALL.iter().enumerate() {
            for (other_dotted, other_bytes) in &ALL[index + 1..] {
                assert_ne!(bytes, other_bytes,
                           "{} and {} encode to the same bytes",
                           dotted, other_dotted);
            }
        }
    }

    /// The four bare hash OIDs have no counterpart in any table
    /// `scripts/diff_check.py` can reach, so they are tied here to the
    /// PKCS#1 DigestInfo prefixes in `rsa.rs` instead - which *are*
    /// checked against OpenSSL, byte for byte, by
    /// `pytests/test_rsa.py::test_signatures_match_openssl_byte_for_byte`.
    /// A v1.5 signature is deterministic, so identical bytes mean the OID
    /// inside the prefix is the one OpenSSL uses.
    ///
    /// That makes this an indirect check with a real independent
    /// implementation at the end of it, rather than the nothing it would
    /// otherwise be.
    #[test]
    fn test_the_bare_hash_oids_match_the_digest_info_prefixes() {
        for (name, oid) in [("sha1", SHA1), ("sha256", SHA256),
                            ("sha384", SHA384), ("sha512", SHA512)] {
            let prefix = crate::publickey_ciphers::rsa::digest_info_prefix(name)
                .unwrap();
            assert!(prefix.windows(oid.len()).any(|window| window == oid),
                    "the DigestInfo prefix for {} does not contain our OID for \
                     it; one of the two is wrong and the other is checked \
                     against OpenSSL", name);
        }
    }

    #[test]
    fn test_name_lookup() {
        assert_eq!(name_of(SHA256_WITH_RSA), Some("1.2.840.113549.1.1.11"));
        assert_eq!(name_of(&[0x2a, 0x03]), None);
    }

    /// Every GOST parameter set OID either names a curve this library
    /// has, or is one of the four it deliberately does not.
    ///
    /// Nothing outside this repository can check this mapping -
    /// python-cryptography has no name for these curves at all, so
    /// `diff_check.py` carries `None` for each of them. What makes the
    /// mapping checkable here is that the two namings are the *same
    /// curves*: CryptoPro-A and TC 26 paramSetB must resolve to one
    /// curve, and the renaming is shifted by one, so a table that
    /// matched them up positionally would be wrong by exactly one
    /// everywhere and still look like a table.
    #[test]
    fn test_the_parameter_sets_name_our_curves() {
        use crate::ec::curves;

        for (oid, expected) in [
            (GOST_2001_CRYPTOPRO_A, "gost256-a"),
            (GOST_2001_CRYPTOPRO_B, "gost256-b"),
            (GOST_2001_CRYPTOPRO_C, "gost256-c"),
            (GOST_2012_256_PARAMSET_B, "gost256-a"),
            (GOST_2012_256_PARAMSET_C, "gost256-b"),
            (GOST_2012_256_PARAMSET_D, "gost256-c"),
            (GOST_2012_256_PARAMSET_A, "gost256-tc26-a"),
            (GOST_2001_CRYPTOPRO_XCHA, "gost256-a"),
            (GOST_2001_CRYPTOPRO_XCHB, "gost256-c"),
            (GOST_2012_512_PARAMSET_A, "gost512-a"),
            (GOST_2012_512_PARAMSET_B, "gost512-b"),
            (GOST_2012_512_PARAMSET_C, "gost512-c"),
        ] {
            assert_eq!(gost_curve_for(oid), Some(expected));
            // And the name must be one `curves` actually answers to,
            // rather than a string that only this table believes in.
            assert!(curves::by_name(expected).is_ok(), "{}", expected);
        }

        // The shift is the point: the two namings are off by one, so
        // paramSetA is *not* CryptoPro-A. It is a different curve, and
        // one this library used to refuse - see `gost256_tc26_a` for
        // what that cost.
        assert_ne!(gost_curve_for(GOST_2012_256_PARAMSET_A),
                   gost_curve_for(GOST_2001_CRYPTOPRO_A));
        // The 512 bit *test* set is the one parameter set still left
        // out, and it is left out on purpose: it is a demonstration
        // curve from the standard rather than something a certificate
        // in the field carries.
        assert_eq!(gost_curve_for(GOST_2012_512_PARAMSET_TEST), None,
                   "the test parameter set resolved to a curve");

        // Nothing that is not a parameter set resolves to one.
        assert_eq!(gost_curve_for(GOST3410_12_256), None);
        assert_eq!(gost_curve_for(PRIME256V1), None);

        // Two different parameter sets must not name one curve except
        // where the RFCs say they do, which is the eight rows above.
        let mut seen: Vec<(&str, &[u8])> = Vec::new();
        for (_, _, oid) in ALL_NAMED.iter().filter(|(name, _, _)| {
            name.starts_with("GOST_2001_") || name.starts_with("GOST_2012_")
        }) {
            if let Some(curve) = gost_curve_for(oid) {
                seen.push((curve, oid));
            }
        }
        assert_eq!(seen.len(), 12, "the parameter set table changed size");
    }
}
