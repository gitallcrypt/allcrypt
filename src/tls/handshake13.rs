/*
The TLS 1.3 handshake: the extensions that carry the negotiation, and the
messages whose shape changed.

TLS 1.3 kept the ClientHello and ServerHello envelopes and moved the whole
negotiation inside them, which is why so much of this file is extensions.
The envelope is a lie told to middleboxes: a 1.3 ClientHello says 1.2 in
its version field, a 1.3 ServerHello says 1.2, and the real version is in
`supported_versions`. `ServerHello::negotiated_version` in `handshake.rs`
exists for exactly that reason.

The trap this module exists to contain: **the same extension type has a
different body depending on which message it is in.** Not a different
meaning - a different wire format, with no marker to say which one you are
looking at except the message around it.

    supported_versions   ClientHello:  uint8 length, then 2-byte versions
                         ServerHello:  bare 2 bytes, no length at all

    key_share            ClientHello:  uint16 length, then a list of entries
                         ServerHello:  exactly one entry, no list length
                         HelloRetry:   a bare uint16 group, nothing else

Parsing a ServerHello's `supported_versions` with the ClientHello's rule
reads the version's high byte as a length and then runs out of data - which
at least fails loudly. The other direction does not: a ClientHello share
list read as a single entry finds a plausible group code in the list's own
length field, and reports a group the client never offered.

So there is one function per (extension, message) pair and none of them
take a flag. A function that decided which format to use from a parameter
is a function whose caller can get it wrong.

The other pieces here:

  * **HelloRetryRequest is not a message type.** It is a ServerHello whose
    random is a fixed constant, which is SHA-256("HelloRetryRequest").
    Treating it as an ordinary ServerHello means deriving a handshake
    secret from a key share that was never sent.

  * **CertificateVerify signs a constructed string**, not the transcript
    on its own: 64 spaces, a context string that differs by side, a zero
    byte, then the transcript hash. The 64 spaces are there so that a
    signature made by a TLS 1.3 client or server cannot be replayed as a
    signature over something else - and the context string is what stops a
    client's signature being replayed as a server's.

  * **The Certificate message gained a context and per-entry extensions.**
    A 1.2 chain is a list of `opaque<1..2^24-1>`; a 1.3 one is a request
    context, then a list of (certificate, extensions) pairs. Parsing one
    with the other's rule reads the first certificate's length as part of
    the context.
*/

use crate::tls::codec::{CodecError, Reader, Result, Writer};
use crate::tls::handshake::{extension, find_extension, read_extensions,
                            write_extensions_required, Extension,
                            Random};
use crate::tls::Version;
use crate::tls::suites::{BulkCipher, CipherSuite, MacAlgorithm};

/// The random every HelloRetryRequest carries (RFC 8446 section 4.1.3).
///
/// It is not arbitrary: it is `SHA-256("HelloRetryRequest")`. Written out
/// as bytes because that is what goes on the wire and what has to be
/// compared, with a test that derives it from the string so a
/// transcription error cannot survive.
pub const HELLO_RETRY_REQUEST_RANDOM: Random = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The last eight bytes of a ServerHello random from a server that
/// supports TLS 1.3 and negotiated TLS 1.2 (RFC 8446 section 4.1.3):
/// `DOWNGRD` and a one.
///
/// A client that offered 1.3 and sees this has been steered down by
/// something that removed `supported_versions` from its hello, and the
/// 1.2 handshake that follows authenticates the steered hello rather
/// than detecting it: the ServerKeyExchange signature covers the
/// randoms, and these eight bytes are inside them.
pub const DOWNGRADE_TO_TLS12: [u8; 8] = *b"DOWNGRD\x01";

/// The same marker from a server that supports TLS 1.2 or later and
/// negotiated TLS 1.1 or below: `DOWNGRD` and a zero.
pub const DOWNGRADE_TO_TLS11: [u8; 8] = *b"DOWNGRD\x00";

/// Which marker, if any, a server whose ceiling is `ceiling` writes
/// into its random when it negotiates `chosen`. One function decides
/// for both ends, so the writer and the reader cannot disagree about
/// which byte means what.
pub fn downgrade_marker(ceiling: Version, chosen: Version) -> Option<[u8; 8]> {
    if ceiling >= Version::TLS13 && chosen == Version::TLS12 {
        Some(DOWNGRADE_TO_TLS12)
    } else if ceiling >= Version::TLS12 && chosen < Version::TLS12 {
        Some(DOWNGRADE_TO_TLS11)
    } else {
        None
    }
}

// ---------------------------------------------------- supported_versions ---

/// The ClientHello form: `ProtocolVersion versions<2..254>`, a **one byte**
/// length followed by that many bytes of two-byte versions.
pub fn encode_client_supported_versions(versions: &[Version]) -> Result<Vec<u8>> {
    if versions.is_empty() {
        return Err(CodecError::illegal(
            "supported_versions must offer at least one version."));
    }
    let mut writer = Writer::new();
    writer.nested8(|inner| {
        for version in versions {
            inner.raw(&version.to_bytes());
        }
        Ok(())
    })?;
    Ok(writer.finish())
}

pub fn parse_client_supported_versions(body: &[u8]) -> Result<Vec<Version>> {
    let mut reader = Reader::new(body);
    let mut list = reader.sub8()?;
    reader.expect_empty("supported_versions")?;
    if list.left() % 2 != 0 || list.is_empty() {
        return Err(CodecError::decode(format!(
            "supported_versions holds {} bytes, which is not a non-empty list \
             of two-byte versions.", list.left())));
    }
    let mut versions = Vec::with_capacity(list.left() / 2);
    while !list.is_empty() {
        versions.push(Version::from_bytes([list.u8()?, list.u8()?]));
    }
    Ok(versions)
}

/// The ServerHello form: **two bytes, and nothing else**. No length
/// prefix, because the server chose one version and a list of one would
/// be a list.
pub fn encode_server_supported_version(version: Version) -> Vec<u8> {
    version.to_bytes().to_vec()
}

pub fn parse_server_supported_version(body: &[u8]) -> Result<Version> {
    if body.len() != 2 {
        return Err(CodecError::decode(format!(
            "A ServerHello's supported_versions is exactly two bytes with no \
             length prefix; this one is {}. (The ClientHello form is a \
             length-prefixed list, and they are not interchangeable.)",
            body.len())));
    }
    Ok(Version::from_bytes([body[0], body[1]]))
}

// ------------------------------------------------------------- key_share ---

/// One offered or selected group and its public key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyShareEntry {
    pub group: u16,
    /// The group's own encoding: a SEC1 point for the EC curves, 32 bytes
    /// little-endian for X25519, the padded integer for a finite field
    /// group. This layer does not interpret it.
    pub key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    fn read(reader: &mut Reader<'_>) -> Result<KeyShareEntry> {
        let group = reader.u16()?;
        let key_exchange = reader.vector16()?.to_vec();
        // `opaque key_exchange<1..2^16-1>`: an empty share is not a share,
        // and accepting one means deriving a secret from nothing.
        if key_exchange.is_empty() {
            return Err(CodecError::illegal(format!(
                "key_share offers group {} with an empty key.", group)));
        }
        Ok(KeyShareEntry { group, key_exchange })
    }

    fn write(&self, writer: &mut Writer) -> Result<()> {
        writer.u16(self.group);
        writer.vector16(&self.key_exchange)
    }
}

/// The ClientHello form: `KeyShareEntry client_shares<0..2^16-1>`, a
/// **uint16 length** and then the entries.
pub fn encode_client_key_share(shares: &[KeyShareEntry]) -> Result<Vec<u8>> {
    let mut writer = Writer::new();
    writer.nested16(|inner| {
        for share in shares {
            share.write(inner)?;
        }
        Ok(())
    })?;
    Ok(writer.finish())
}

pub fn parse_client_key_share(body: &[u8]) -> Result<Vec<KeyShareEntry>> {
    let mut reader = Reader::new(body);
    let mut list = reader.sub16()?;
    reader.expect_empty("key_share")?;

    let mut shares = Vec::new();
    while !list.is_empty() {
        let entry = KeyShareEntry::read(&mut list)?;
        // A client that offers the same group twice is asking which one
        // the server picks, which is the duplicate-extension problem one
        // level down.
        if shares.iter().any(|other: &KeyShareEntry| other.group == entry.group) {
            return Err(CodecError::illegal(format!(
                "key_share offers group {} twice.", entry.group)));
        }
        shares.push(entry);
    }
    Ok(shares)
}

/// The ServerHello form: **exactly one entry**, with no list length in
/// front of it.
pub fn encode_server_key_share(share: &KeyShareEntry) -> Result<Vec<u8>> {
    let mut writer = Writer::new();
    share.write(&mut writer)?;
    Ok(writer.finish())
}

pub fn parse_server_key_share(body: &[u8]) -> Result<KeyShareEntry> {
    let mut reader = Reader::new(body);
    let entry = KeyShareEntry::read(&mut reader)?;
    reader.expect_empty("key_share")?;
    Ok(entry)
}

/// The HelloRetryRequest form: a bare `uint16 selected_group` and nothing
/// else. The server is naming a group it wants and has no key to send,
/// because it has not seen one yet.
pub fn encode_retry_key_share(group: u16) -> Vec<u8> {
    group.to_be_bytes().to_vec()
}

pub fn parse_retry_key_share(body: &[u8]) -> Result<u16> {
    if body.len() != 2 {
        return Err(CodecError::decode(format!(
            "A HelloRetryRequest's key_share is a bare two byte group; this \
             one is {} bytes. (A ServerHello's carries a key as well.)",
            body.len())));
    }
    Ok(u16::from_be_bytes([body[0], body[1]]))
}

// -------------------------------------------------- EncryptedExtensions ---

/// Everything the server would have put in its ServerHello, now that the
/// ServerHello itself is readable by anyone watching.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>,
}

impl EncryptedExtensions {
    pub fn parse(body: &[u8]) -> Result<EncryptedExtensions> {
        let mut reader = Reader::new(body);
        let extensions = read_extensions(&mut reader)?;
        reader.expect_empty("EncryptedExtensions")?;
        Ok(EncryptedExtensions { extensions })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        // Mandatory: an empty EncryptedExtensions is a two-byte zero, not
        // nothing. See `write_extensions_required`.
        write_extensions_required(&mut writer, &self.extensions)?;
        Ok(writer.finish())
    }
}

// --------------------------------------------------- Certificate (1.3) ---

/// One certificate and the extensions that travel with it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificateEntry {
    pub certificate: Vec<u8>,
    /// Per-certificate extensions - OCSP staples and SCTs, which in TLS
    /// 1.2 hung off the hello instead.
    pub extensions: Vec<Extension>,
}

/// The TLS 1.3 Certificate message.
///
/// A TLS 1.2 chain is `opaque certificate_list<0..2^24-1>` of
/// `opaque<1..2^24-1>`. This one puts a request context in front and
/// wraps each certificate in a structure. Parsing one with the other's
/// rule reads the first certificate's length bytes as the context.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Certificate13 {
    /// Echoed from a CertificateRequest. Empty in a server's certificate,
    /// which is the only case a client meets first.
    pub request_context: Vec<u8>,
    pub entries: Vec<CertificateEntry>,
}

impl Certificate13 {
    pub fn parse(body: &[u8]) -> Result<Certificate13> {
        let mut reader = Reader::new(body);
        let request_context = reader.vector8()?.to_vec();
        let mut list = reader.sub24()?;
        reader.expect_empty("Certificate")?;

        let mut entries = Vec::new();
        while !list.is_empty() {
            let certificate = list.vector24()?.to_vec();
            if certificate.is_empty() {
                return Err(CodecError::illegal(
                    "Certificate entry carries no certificate."));
            }
            let extensions = read_extensions(&mut list)?;
            entries.push(CertificateEntry { certificate, extensions });
        }
        Ok(Certificate13 { request_context, entries })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.vector8(&self.request_context)?;
        writer.nested24(|inner| {
            for entry in &self.entries {
                inner.vector24(&entry.certificate)?;
                // Mandatory here too, and for the same reason.
                write_extensions_required(inner, &entry.extensions)?;
            }
            Ok(())
        })?;
        Ok(writer.finish())
    }

    /// The chain as bare DER, leaf first - the shape the rest of this
    /// library already verifies.
    pub fn chain(&self) -> Vec<Vec<u8>> {
        self.entries.iter().map(|entry| entry.certificate.clone()).collect()
    }
}

/// The TLS 1.3 CertificateRequest.
///
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     Extension extensions<2..2^16-1>;
/// } CertificateRequest;
/// ```
///
/// Nothing like the 1.2 message, which carried certificate types and CA
/// names as bare fields. Here everything is an extension, and
/// `signature_algorithms` is **required** - RFC 8446 4.3.2 says a
/// CertificateRequest without it must be refused, because a client that
/// guessed a scheme would sign something the server cannot check.
///
/// The context is echoed back in the client's Certificate. It is empty in a
/// handshake CertificateRequest and non-empty only for post-handshake
/// authentication, which is not implemented - so a non-empty one here means
/// the two ends disagree about which message this is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificateRequest13 {
    pub context: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl CertificateRequest13 {
    pub fn parse(body: &[u8]) -> Result<CertificateRequest13> {
        let mut reader = Reader::new(body);
        let context = reader.vector8()?.to_vec();
        let extensions = read_extensions(&mut reader)?;
        reader.expect_empty("CertificateRequest")?;
        if find_extension(&extensions, extension::SIGNATURE_ALGORITHMS).is_none() {
            return Err(CodecError::illegal(
                "A TLS 1.3 CertificateRequest must carry signature_algorithms; \
                 without it a client would have to guess what the server can \
                 verify."));
        }
        Ok(CertificateRequest13 { context, extensions })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.vector8(&self.context)?;
        // Mandatory, like every other 1.3 extensions field.
        write_extensions_required(&mut writer, &self.extensions)?;
        Ok(writer.finish())
    }

    /// The schemes the server will accept, which is the only part a client
    /// has to act on.
    pub fn schemes(&self) -> Result<Vec<u16>> {
        match find_extension(&self.extensions, extension::SIGNATURE_ALGORITHMS) {
            Some(extension) => parse_signature_algorithms(&extension.body),
            // `parse` refuses one without it, so this is unreachable for a
            // parsed message and possible for a hand-built one.
            None => Err(CodecError::illegal("No signature_algorithms.")),
        }
    }
}

// -------------------------------------------------- CertificateVerify ---

/// Which side made a signature, which is part of what it covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side13 {
    Client,
    Server,
}

impl Side13 {
    /// RFC 8446 section 4.4.3. The two strings differ, which is what stops
    /// a client's CertificateVerify being replayed as a server's - the two
    /// cover the same transcript at the same point in some flows.
    pub fn context_string(self) -> &'static [u8] {
        match self {
            Side13::Client => b"TLS 1.3, client CertificateVerify",
            Side13::Server => b"TLS 1.3, server CertificateVerify",
        }
    }
}

/// The bytes a CertificateVerify signs (RFC 8446 section 4.4.3):
///
/// ```text
/// 64 bytes of 0x20
/// || context string
/// || 0x00
/// || Transcript-Hash(Handshake Context, Certificate)
/// ```
///
/// The 64 spaces are not padding. A TLS 1.2 signature is over data that
/// starts with the randoms, and 64 leading spaces make it impossible for
/// a signature produced here to also be a valid signature over one of
/// those - the cross-protocol replay that this construction exists to
/// prevent. The single zero byte terminates the context string so a
/// longer one cannot be confused with a shorter one plus transcript.
pub fn certificate_verify_content(side: Side13, transcript_hash: &[u8]) -> Vec<u8> {
    let context = side.context_string();
    let mut out = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    out.resize(64, 0x20);
    out.extend_from_slice(context);
    out.push(0x00);
    out.extend_from_slice(transcript_hash);
    out
}

/// A CertificateVerify message: the scheme, then the signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificateVerify {
    pub scheme: u16,
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn parse(body: &[u8]) -> Result<CertificateVerify> {
        let mut reader = Reader::new(body);
        let scheme = reader.u16()?;
        let signature = reader.vector16()?.to_vec();
        reader.expect_empty("CertificateVerify")?;
        if signature.is_empty() {
            return Err(CodecError::illegal(
                "CertificateVerify carries an empty signature."));
        }
        Ok(CertificateVerify { scheme, signature })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.u16(self.scheme);
        writer.vector16(&self.signature)?;
        Ok(writer.finish())
    }
}

// -------------------------------------------------------- signature schemes ---

/// The TLS 1.3 signature scheme codepoints.
///
/// These are **opaque sixteen bit values**, not the TLS 1.2 `(hash,
/// signature)` pair. `rsa_pss_rsae_sha256` is 0x0804, which under the old
/// split reads as hash 8 and signature 4 - both meaningless. The old
/// `SignatureScheme` struct still carries them as a transport, but its
/// `hash` and `signature` fields must not be read for these.
pub mod scheme {
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
    /// PSS with an rsaEncryption key - what an ordinary RSA certificate
    /// gets used for in TLS 1.3.
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    pub const ED25519: u16 = 0x0807;
    pub const ED448: u16 = 0x0808;
    /// PSS with an RSASSA-PSS key, which carries its parameters in the
    /// certificate. Rare, and a different thing from the above.
    pub const RSA_PSS_PSS_SHA256: u16 = 0x0809;
    pub const RSA_PSS_PSS_SHA384: u16 = 0x080a;
    pub const RSA_PSS_PSS_SHA512: u16 = 0x080b;

    // draft-ietf-tls-mldsa: pure ML-DSA with an empty FIPS 204 context,
    // over the same content any 1.3 CertificateVerify signs. TLS 1.3
    // only; the draft forbids them at 1.2.
    pub const MLDSA44: u16 = 0x0904;
    pub const MLDSA65: u16 = 0x0905;
    pub const MLDSA87: u16 = 0x0906;

    /// The FIPS 204 parameter set an ML-DSA scheme names.
    pub fn ml_dsa_parameter_set(scheme: u16) -> Option<&'static str> {
        match scheme {
            MLDSA44 => Some("ML-DSA-44"),
            MLDSA65 => Some("ML-DSA-65"),
            MLDSA87 => Some("ML-DSA-87"),
            _ => None,
        }
    }

    /// The inverse, for a server choosing the scheme its key signs with.
    pub fn ml_dsa_for_parameter_set(parameter_set: &str) -> Option<u16> {
        [MLDSA44, MLDSA65, MLDSA87].into_iter()
            .find(|scheme| ml_dsa_parameter_set(*scheme) == Some(parameter_set))
    }

    // RFC 9367 section 5. Seven schemes, each pinning GOST R 34.10-2012
    // to **one** curve - the same binding TLS 1.3 applies to ECDSA, and
    // for the same reason: otherwise a peer picks a hash that does not
    // match the curve's strength.
    //
    // **The numbering is not the parameter sets' own**, and the naming
    // is shifted on top of that: `256a` is the TC 26 set, while `256b`,
    // `256c` and `256d` are CryptoPro A, B and C. A table written from
    // the letters alone is wrong in three places out of four - the same
    // trap `handshake::groups` already carries a note about.
    pub const GOSTR34102012_256A: u16 = 0x0709;
    pub const GOSTR34102012_256B: u16 = 0x070a;
    pub const GOSTR34102012_256C: u16 = 0x070b;
    pub const GOSTR34102012_256D: u16 = 0x070c;
    pub const GOSTR34102012_512A: u16 = 0x070d;
    pub const GOSTR34102012_512B: u16 = 0x070e;
    pub const GOSTR34102012_512C: u16 = 0x070f;

    /// The seven RFC 9367 schemes, in the document's order.
    pub const GOST_13: &[u16] = &[
        GOSTR34102012_256A, GOSTR34102012_256B, GOSTR34102012_256C,
        GOSTR34102012_256D, GOSTR34102012_512A, GOSTR34102012_512B,
        GOSTR34102012_512C,
    ];

    pub fn is_gost_13(scheme: u16) -> bool {
        GOST_13.contains(&scheme)
    }

    /// The hash a scheme uses, by this library's name for it.
    pub fn hash_name(scheme: u16) -> Option<&'static str> {
        match scheme {
            RSA_PKCS1_SHA256 | ECDSA_SECP256R1_SHA256
                | RSA_PSS_RSAE_SHA256 | RSA_PSS_PSS_SHA256 => Some("sha256"),
            RSA_PKCS1_SHA384 | ECDSA_SECP384R1_SHA384
                | RSA_PSS_RSAE_SHA384 | RSA_PSS_PSS_SHA384 => Some("sha384"),
            RSA_PKCS1_SHA512 | ECDSA_SECP521R1_SHA512
                | RSA_PSS_RSAE_SHA512 | RSA_PSS_PSS_SHA512 => Some("sha512"),
            // GOST R 34.10-2012's digest follows the **key** size, not
            // the curve's name: 32 byte keys take Streebog-256 and 64
            // byte ones Streebog-512 (RFC 7091). The handshake hash is
            // Streebog-256 for all four suites either way (RFC 9367
            // section 4.2), so these two are different questions that
            // happen to share an answer four times out of seven.
            GOSTR34102012_256A | GOSTR34102012_256B | GOSTR34102012_256C
                | GOSTR34102012_256D => Some("streebog256"),
            GOSTR34102012_512A | GOSTR34102012_512B
                | GOSTR34102012_512C => Some("streebog512"),
            _ => None,
        }
    }

    /// The curve an ECDSA scheme is bound to.
    ///
    /// TLS 1.2 let a signature name a hash and leave the curve to the
    /// certificate. TLS 1.3 binds them, so a P-256 key may only sign with
    /// `ecdsa_secp256r1_sha256` - which closes the gap where a peer picks
    /// a hash that does not match the curve's strength.
    pub fn curve_name(scheme: u16) -> Option<&'static str> {
        match scheme {
            ECDSA_SECP256R1_SHA256 => Some("P-256"),
            ECDSA_SECP384R1_SHA384 => Some("P-384"),
            ECDSA_SECP521R1_SHA512 => Some("P-521"),
            // RFC 9367 section 5.2's table, which is the one place the
            // letters mean what they say and the one place they do not:
            // `256a` is `id-tc26-gost-3410-2012-256-paramSetA` and the
            // other three are CryptoPro A, B and C, shifted by one.
            GOSTR34102012_256A => Some("gost256-tc26-a"),
            GOSTR34102012_256B => Some("gost256-a"),
            GOSTR34102012_256C => Some("gost256-b"),
            GOSTR34102012_256D => Some("gost256-c"),
            GOSTR34102012_512A => Some("gost512-a"),
            GOSTR34102012_512B => Some("gost512-b"),
            GOSTR34102012_512C => Some("gost512-c"),
            _ => None,
        }
    }

    /// The RFC 9367 scheme a GOST curve must sign with, the inverse of
    /// `curve_name`.
    ///
    /// One scheme per curve, because 1.3 binds them - so this is a
    /// function and not a preference list. Written as the inverse rather
    /// than as a second table: `tests::test_the_gost_scheme_map_is_a_bijection`
    /// walks `GOST_13` through both and back, which is what stops the two
    /// drifting apart. Three of the seven curves are named by a letter
    /// that does not match the parameter set's, so a second hand-written
    /// table is exactly where that would go wrong.
    pub fn gost_13_for_curve(curve: &str) -> Option<u16> {
        GOST_13.iter().copied()
            .find(|scheme| curve_name(*scheme) == Some(curve))
    }

    pub fn is_pss(scheme: u16) -> bool {
        matches!(scheme, RSA_PSS_RSAE_SHA256 | RSA_PSS_RSAE_SHA384
                       | RSA_PSS_RSAE_SHA512 | RSA_PSS_PSS_SHA256
                       | RSA_PSS_PSS_SHA384 | RSA_PSS_PSS_SHA512)
    }

    pub fn name(scheme: u16) -> String {
        match scheme {
            RSA_PKCS1_SHA256 => "rsa_pkcs1_sha256".to_string(),
            RSA_PKCS1_SHA384 => "rsa_pkcs1_sha384".to_string(),
            RSA_PKCS1_SHA512 => "rsa_pkcs1_sha512".to_string(),
            ECDSA_SECP256R1_SHA256 => "ecdsa_secp256r1_sha256".to_string(),
            ECDSA_SECP384R1_SHA384 => "ecdsa_secp384r1_sha384".to_string(),
            ECDSA_SECP521R1_SHA512 => "ecdsa_secp521r1_sha512".to_string(),
            RSA_PSS_RSAE_SHA256 => "rsa_pss_rsae_sha256".to_string(),
            RSA_PSS_RSAE_SHA384 => "rsa_pss_rsae_sha384".to_string(),
            RSA_PSS_RSAE_SHA512 => "rsa_pss_rsae_sha512".to_string(),
            ED25519 => "ed25519".to_string(),
            ED448 => "ed448".to_string(),
            RSA_PSS_PSS_SHA256 => "rsa_pss_pss_sha256".to_string(),
            RSA_PSS_PSS_SHA384 => "rsa_pss_pss_sha384".to_string(),
            RSA_PSS_PSS_SHA512 => "rsa_pss_pss_sha512".to_string(),
            MLDSA44 => "mldsa44".to_string(),
            MLDSA65 => "mldsa65".to_string(),
            MLDSA87 => "mldsa87".to_string(),
            GOSTR34102012_256A => "gostr34102012_256a".to_string(),
            GOSTR34102012_256B => "gostr34102012_256b".to_string(),
            GOSTR34102012_256C => "gostr34102012_256c".to_string(),
            GOSTR34102012_256D => "gostr34102012_256d".to_string(),
            GOSTR34102012_512A => "gostr34102012_512a".to_string(),
            GOSTR34102012_512B => "gostr34102012_512b".to_string(),
            GOSTR34102012_512C => "gostr34102012_512c".to_string(),
            other => format!("signature scheme {:#06x}", other),
        }
    }

    /// What this library can actually verify, in the order it prefers.
    ///
    /// PSS first: RFC 8446 requires a TLS 1.3 peer to support
    /// `rsa_pss_rsae_sha256`, and the PKCS#1 v1.5 schemes are legal only
    /// in certificates, never in a CertificateVerify. They are offered
    /// anyway because a certificate in the chain may be signed with one,
    /// and `signature_algorithms` covers both uses unless
    /// `signature_algorithms_cert` splits them.
    pub const OFFERED: &[u16] = &[
        RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512,
        ECDSA_SECP256R1_SHA256, ECDSA_SECP384R1_SHA384, ECDSA_SECP521R1_SHA512,
        // Offered after the ECDSA schemes rather than before them, because
        // a server that can do either should pick the one this library
        // has had longest. Offering them at all is what lets an EdDSA
        // server be reached, at 1.3 and at 1.2 (RFC 8422 5.1.3).
        ED25519, ED448,
        // After every classical scheme, for the same reason Ed25519 is
        // after ECDSA, and because an ML-DSA CertificateVerify is 2.4 to
        // 4.6 KB where an ECDSA one is about 70 bytes. A server whose only
        // certificate is ML-DSA picks one of these whatever the order.
        MLDSA44, MLDSA65, MLDSA87,
        RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
    ];

    /// Whether a CertificateVerify may use this scheme.
    ///
    /// RFC 8446 section 4.4.3: "RSA signatures MUST use an RSASSA-PSS
    /// algorithm... the rsa_pkcs1_* values refer solely to signatures
    /// which appear in certificates". Accepting a v1.5 signature here
    /// would undo that, and it is the sort of thing a downgrade tries.
    pub fn allowed_in_certificate_verify(scheme: u16) -> bool {
        matches!(scheme, RSA_PSS_RSAE_SHA256 | RSA_PSS_RSAE_SHA384
                       | RSA_PSS_RSAE_SHA512 | RSA_PSS_PSS_SHA256
                       | RSA_PSS_PSS_SHA384 | RSA_PSS_PSS_SHA512
                       | ECDSA_SECP256R1_SHA256 | ECDSA_SECP384R1_SHA384
                       | ECDSA_SECP521R1_SHA512 | ED25519 | ED448
                       | MLDSA44 | MLDSA65 | MLDSA87)
            // RFC 9367 section 5: the TLS13_GOST schemes are defined
            // for exactly this message and nothing else. There is no
            // certificate-only form of them to exclude, which is why
            // they are a separate arm rather than another pattern.
            || is_gost_13(scheme)
    }
}

/// `SignatureSchemeList supported_signature_algorithms<2..2^16-2>`.
pub fn encode_signature_algorithms(schemes: &[u16]) -> Result<Vec<u8>> {
    if schemes.is_empty() {
        return Err(CodecError::illegal(
            "signature_algorithms must offer at least one scheme."));
    }
    let mut writer = Writer::new();
    writer.u16_list(schemes)?;
    Ok(writer.finish())
}

pub fn parse_signature_algorithms(body: &[u8]) -> Result<Vec<u16>> {
    let mut reader = Reader::new(body);
    let schemes = reader.u16_list()?;
    reader.expect_empty("signature_algorithms")?;
    Ok(schemes)
}

// ---------------------------------------------------------- KeyUpdate ---

/// `KeyUpdate.request_update`, RFC 8446 section 4.6.3.
///
/// One byte, and the two values mean quite different things: one is
/// "I have changed my sending key", the other is that *and* "change
/// yours and tell me". Treating them alike either leaves the peer
/// waiting or sends a message it did not ask for, and RFC 8446 says a
/// KeyUpdate sent in reply MUST carry `update_not_requested` - a pair
/// of implementations that both replied with `update_requested` would
/// update each other forever.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyUpdateRequest {
    NotRequested,
    Requested,
}

impl KeyUpdateRequest {
    pub fn parse(body: &[u8]) -> Result<KeyUpdateRequest> {
        // Exactly one byte: a KeyUpdate with anything else in it is not
        // a KeyUpdate, and RFC 8446 section 4.6.3 says to treat an
        // unknown value as a fatal `illegal_parameter` rather than
        // ignoring it.
        match body {
            [0] => Ok(KeyUpdateRequest::NotRequested),
            [1] => Ok(KeyUpdateRequest::Requested),
            [other] => Err(CodecError::illegal(format!(
                "KeyUpdate.request_update is {}, which is not one of the two \
                 values RFC 8446 section 4.6.3 defines.", other))),
            _ => Err(CodecError::decode(format!(
                "A KeyUpdate body is one byte; this one is {}.", body.len()))),
        }
    }

    pub fn encode(self) -> Vec<u8> {
        match self {
            KeyUpdateRequest::NotRequested => vec![0],
            KeyUpdateRequest::Requested => vec![1],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::handshake::groups;

    /// The three ML-DSA codepoints, read out of draft-ietf-tls-mldsa's
    /// IANA table rather than trusted from the constants. The table is
    /// matched by its rows - `| 0x0904 | mldsa44 |` - because the same
    /// numbers also appear in section 3's table with the names written
    /// differently.
    #[test]
    fn test_the_ml_dsa_codepoints_are_the_drafts() {
        const DRAFT: &str = include_str!("../../rfcs/draft-ietf-tls-mldsa-06.txt");
        let mut found = Vec::new();
        for line in DRAFT.lines() {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            if cells.len() >= 3 && cells[1].starts_with("0x09") {
                let value = u16::from_str_radix(&cells[1][2..], 16).unwrap();
                found.push((value, cells[2].to_string()));
            }
        }
        assert_eq!(found.len(), 3, "{found:?}");
        for (value, name) in found {
            assert_eq!(scheme::name(value), name);
            let set = scheme::ml_dsa_parameter_set(value).unwrap();
            assert_eq!(set.replace('-', "").to_ascii_lowercase(), name);
            assert_eq!(scheme::ml_dsa_for_parameter_set(set), Some(value));
            assert!(scheme::allowed_in_certificate_verify(value));
            assert!(scheme::OFFERED.contains(&value));
        }
    }

    /// The constant is SHA-256("HelloRetryRequest"), derived here so a
    /// mistyped byte cannot survive. A wrong constant means every
    /// HelloRetryRequest is treated as an ordinary ServerHello, and the
    /// handshake secret gets derived from a key share the server never
    /// sent.
    #[test]
    fn test_the_retry_random_is_the_hash_of_its_name() {
        use crate::hash_functions::{sha2::SHA256, HashFunction};
        let mut hash = SHA256::new(&[]);
        hash.update(b"HelloRetryRequest");
        assert_eq!(hash.digest(), HELLO_RETRY_REQUEST_RANDOM.to_vec());
    }

    /// supported_versions has two formats and no marker to tell them
    /// apart. Each must refuse the other's.
    #[test]
    fn test_the_two_supported_versions_formats_do_not_interchange() {
        let client = encode_client_supported_versions(
            &[Version::TLS13, Version::TLS12]).unwrap();
        assert_eq!(client, vec![0x04, 0x03, 0x04, 0x03, 0x03]);
        assert_eq!(parse_client_supported_versions(&client).unwrap(),
                   vec![Version::TLS13, Version::TLS12]);

        let server = encode_server_supported_version(Version::TLS13);
        assert_eq!(server, vec![0x03, 0x04]);
        assert_eq!(parse_server_supported_version(&server).unwrap(), Version::TLS13);

        // The server form read as a client list: 0x03 is taken as a
        // length of three, and three is not a whole number of versions.
        assert!(parse_client_supported_versions(&server).is_err());
        // And the client form read as a server one is the wrong length.
        assert!(parse_server_supported_version(&client).is_err());
    }

    #[test]
    fn test_an_empty_supported_versions_is_refused() {
        assert!(encode_client_supported_versions(&[]).is_err());
        assert!(parse_client_supported_versions(&[0x00]).is_err());
        // An odd number of bytes is not a list of two-byte versions.
        assert!(parse_client_supported_versions(&[0x03, 0x03, 0x04, 0x03]).is_err());
    }

    fn a_share(group: u16, len: usize) -> KeyShareEntry {
        KeyShareEntry { group, key_exchange: vec![0xab; len] }
    }

    /// key_share has three formats. This is the pair that fails silently:
    /// a client's list read as a server's single entry takes the list
    /// length as a group code and reports a group nobody offered.
    #[test]
    fn test_the_three_key_share_formats_do_not_interchange() {
        let shares = vec![a_share(groups::X25519, 32),
                          a_share(groups::SECP256R1, 65)];
        let client = encode_client_key_share(&shares).unwrap();
        assert_eq!(parse_client_key_share(&client).unwrap(), shares);

        let server = encode_server_key_share(&shares[0]).unwrap();
        assert_eq!(parse_server_key_share(&server).unwrap(), shares[0]);

        let retry = encode_retry_key_share(groups::SECP384R1);
        assert_eq!(retry, vec![0x00, 0x18]);
        assert_eq!(parse_retry_key_share(&retry).unwrap(), groups::SECP384R1);

        // The client's list, read as one entry. The outer length is
        // 0x0069, so this would claim group 105 and then find the trailing
        // bytes unaccounted for - which is why `expect_empty` is there.
        assert!(parse_server_key_share(&client).is_err());
        // A server's entry read as a list: the group code becomes the
        // list length and the rest does not line up.
        assert!(parse_client_key_share(&server).is_err());
        // And the retry form has no key at all.
        assert!(parse_server_key_share(&retry).is_err());
        assert!(parse_retry_key_share(&server).is_err());
    }

    /// An empty key is not a key, and a secret derived from one is a
    /// secret an observer can derive too.
    #[test]
    fn test_an_empty_key_share_is_refused() {
        let empty = vec![0x00, 0x1d, 0x00, 0x00];
        assert!(parse_server_key_share(&empty).is_err());

        let mut list = vec![0x00, 0x04];
        list.extend_from_slice(&empty);
        assert!(parse_client_key_share(&list).is_err());
    }

    /// Offering a group twice asks the server to choose, which is the
    /// duplicate-extension problem one level down.
    #[test]
    fn test_a_repeated_group_in_a_key_share_is_refused() {
        let shares = vec![a_share(groups::X25519, 32), a_share(groups::X25519, 32)];
        let encoded = encode_client_key_share(&shares).unwrap();
        assert!(parse_client_key_share(&encoded).is_err());
    }

    #[test]
    fn test_an_empty_client_key_share_is_legal() {
        // A client that offers no shares at all is asking for a
        // HelloRetryRequest, which is legal and is what a client does
        // when it has no idea what the server supports.
        let encoded = encode_client_key_share(&[]).unwrap();
        assert_eq!(encoded, vec![0x00, 0x00]);
        assert!(parse_client_key_share(&encoded).unwrap().is_empty());
    }

    #[test]
    fn test_certificate_message_round_trips_with_its_extensions() {
        let message = Certificate13 {
            request_context: vec![],
            entries: vec![
                CertificateEntry {
                    certificate: vec![0x30, 0x82, 0x01, 0x00],
                    extensions: vec![Extension { kind: 5, body: vec![1, 2, 3] }],
                },
                CertificateEntry {
                    certificate: vec![0x30, 0x03, 0x01, 0x02],
                    extensions: vec![],
                },
            ],
        };
        let encoded = message.encode().unwrap();
        assert_eq!(Certificate13::parse(&encoded).unwrap(), message);
        assert_eq!(message.chain().len(), 2);

        // The 1.2 shape has no request context, so parsing one as 1.3
        // takes the first length byte as a context length. It must not
        // silently produce a chain.
        let legacy = crate::tls::handshake::CertificateChain {
            certificates: vec![vec![0x30, 0x82, 0x01, 0x00]],
        }.encode().unwrap();
        assert!(Certificate13::parse(&legacy).is_err());
    }

    #[test]
    fn test_an_entry_with_no_certificate_is_refused() {
        // context, list length 3, cert length 0, no extensions.
        let body = vec![0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(Certificate13::parse(&body).is_err());
    }

    /// The signed content is 64 spaces, the context, a zero, then the
    /// hash - and the two sides' contexts differ, which is what stops one
    /// side's signature being replayed as the other's.
    #[test]
    fn test_the_certificate_verify_content_is_built_as_the_rfc_says() {
        let hash = [0x5au8; 32];
        let server = certificate_verify_content(Side13::Server, &hash);

        assert_eq!(&server[..64], &[0x20u8; 64]);
        assert_eq!(&server[64..64 + 33], b"TLS 1.3, server CertificateVerify");
        assert_eq!(server[64 + 33], 0x00);
        assert_eq!(&server[64 + 34..], &hash);
        assert_eq!(server.len(), 64 + 33 + 1 + 32);

        let client = certificate_verify_content(Side13::Client, &hash);
        assert_ne!(server, client);
        // Same length, different only in one word - so a comparison that
        // stopped at the length would pass.
        assert_eq!(server.len(), client.len());
    }

    #[test]
    fn test_certificate_verify_round_trips_and_refuses_an_empty_signature() {
        let message = CertificateVerify {
            scheme: scheme::RSA_PSS_RSAE_SHA256,
            signature: vec![0x11; 256],
        };
        let encoded = message.encode().unwrap();
        assert_eq!(CertificateVerify::parse(&encoded).unwrap(), message);

        assert!(CertificateVerify::parse(&[0x08, 0x04, 0x00, 0x00]).is_err());
    }

    /// RFC 8446 section 4.4.3: a CertificateVerify's RSA signature must be
    /// PSS. The PKCS#1 v1.5 codepoints exist only for signatures inside
    /// certificates, and accepting one here would undo that.
    #[test]
    fn test_pkcs1_is_not_allowed_in_a_certificate_verify() {
        for pkcs1 in [scheme::RSA_PKCS1_SHA256, scheme::RSA_PKCS1_SHA384,
                      scheme::RSA_PKCS1_SHA512] {
            assert!(!scheme::allowed_in_certificate_verify(pkcs1),
                    "{}", scheme::name(pkcs1));
            // ...but they are still offered, because a certificate in the
            // chain may be signed with one.
            assert!(scheme::OFFERED.contains(&pkcs1));
        }
        assert!(scheme::allowed_in_certificate_verify(scheme::RSA_PSS_RSAE_SHA256));
        assert!(scheme::allowed_in_certificate_verify(scheme::ECDSA_SECP256R1_SHA256));
    }

    /// The TLS 1.3 codepoints are opaque, and reading them as a TLS 1.2
    /// (hash, signature) pair gives nonsense - hash 8 does not exist.
    #[test]
    fn test_a_pss_codepoint_is_not_a_hash_signature_pair() {
        use crate::tls::handshake::SignatureScheme;
        let pair = SignatureScheme::from_u16(scheme::RSA_PSS_RSAE_SHA256);
        assert_eq!(pair.hash, 8);
        assert_eq!(pair.signature, 4);
        assert_eq!(pair.hash_name(), None, "hash 8 is not a TLS 1.2 hash");

        // The TLS 1.3 table knows what it is.
        assert_eq!(scheme::hash_name(scheme::RSA_PSS_RSAE_SHA256), Some("sha256"));
        assert!(scheme::is_pss(scheme::RSA_PSS_RSAE_SHA256));
    }

    /// TLS 1.3 binds the curve to the scheme, which TLS 1.2 did not.
    #[test]
    fn test_an_ecdsa_scheme_names_its_curve() {
        assert_eq!(scheme::curve_name(scheme::ECDSA_SECP256R1_SHA256), Some("P-256"));
        assert_eq!(scheme::curve_name(scheme::ECDSA_SECP384R1_SHA384), Some("P-384"));
        assert_eq!(scheme::curve_name(scheme::RSA_PSS_RSAE_SHA256), None);
    }

    #[test]
    fn test_signature_algorithms_round_trips() {
        let encoded = encode_signature_algorithms(scheme::OFFERED).unwrap();
        assert_eq!(parse_signature_algorithms(&encoded).unwrap(),
                   scheme::OFFERED.to_vec());
        assert!(encode_signature_algorithms(&[]).is_err());
    }

    #[test]
    fn test_encrypted_extensions_round_trips() {
        let message = EncryptedExtensions {
            extensions: vec![Extension { kind: 0, body: vec![] },
                             Extension { kind: 16, body: vec![0, 3, 2, b'h', b'2'] }],
        };
        let encoded = message.encode().unwrap();
        assert_eq!(EncryptedExtensions::parse(&encoded).unwrap(), message);

        // An empty one is the ordinary case and must not be an error.
        let empty = EncryptedExtensions::default();
        let encoded = empty.encode().unwrap();
        assert_eq!(EncryptedExtensions::parse(&encoded).unwrap(), empty);
    }

    /// A KeyUpdate is one byte and only two values are legal. RFC 8446
    /// section 4.6.3 makes an unknown one a fatal `illegal_parameter`
    /// rather than something to ignore, because ignoring it means
    /// failing to decrypt everything after it with an error that points
    /// somewhere else.
    #[test]
    fn test_key_update_takes_one_byte_of_two_values() {
        assert_eq!(KeyUpdateRequest::parse(&[0]).unwrap(),
                   KeyUpdateRequest::NotRequested);
        assert_eq!(KeyUpdateRequest::parse(&[1]).unwrap(),
                   KeyUpdateRequest::Requested);
        for body in [&[][..], &[2], &[255], &[0, 0], &[1, 0]] {
            assert!(KeyUpdateRequest::parse(body).is_err(), "{:?}", body);
        }
        for request in [KeyUpdateRequest::NotRequested, KeyUpdateRequest::Requested] {
            assert_eq!(KeyUpdateRequest::parse(&request.encode()).unwrap(),
                       request);
        }
    }
}

// ------------------------------------------------------- resumption ---

/// `NewSessionTicket`, RFC 8446 section 4.6.1.
///
/// ```text
/// struct {
///     uint32 ticket_lifetime;
///     uint32 ticket_age_add;
///     opaque ticket_nonce<0..255>;
///     opaque ticket<1..2^16-1>;
///     Extension extensions<0..2^16-2>;
/// } NewSessionTicket;
/// ```
///
/// **This is not the TLS 1.2 NewSessionTicket**, which is a lifetime
/// and a blob. The four extra fields are all load bearing: the nonce
/// makes each ticket's PSK different, the age_add obscures how old the
/// ticket is from anyone watching, and the extensions say whether 0-RTT
/// is allowed and how much. A parser that took the 1.2 shape would read
/// the lifetime and then a length that is really the age_add.
#[derive(Clone, Debug)]
pub struct NewSessionTicket13 {
    /// Seconds from issuance. RFC 8446: a server must not exceed
    /// 604800 (seven days), a client must not cache longer than that
    /// whatever the server said, and **zero means discard at once**.
    pub lifetime: u32,
    /// Added to the ticket's age, modulo 2^32, to make the
    /// `obfuscated_ticket_age` the client sends back. Without it, two
    /// connections offering the same ticket are linkable by the age.
    pub age_add: u32,
    pub nonce: Vec<u8>,
    /// The opaque identity to send back.
    pub ticket: Vec<u8>,
    /// `max_early_data_size` from the early_data extension, if the
    /// server offered 0-RTT with this ticket. `None` means no 0-RTT.
    pub max_early_data: Option<u32>,
}

impl NewSessionTicket13 {
    pub fn parse(body: &[u8]) -> Result<NewSessionTicket13> {
        let mut reader = Reader::new(body);
        let lifetime = reader.u32()?;
        let age_add = reader.u32()?;
        let nonce = reader.vector8()?.to_vec();
        let ticket = reader.vector16()?.to_vec();
        if ticket.is_empty() {
            return Err(CodecError::decode(
                "A NewSessionTicket carries an empty ticket, which is \
                 `opaque ticket<1..2^16-1>` - there would be nothing to \
                 send back."));
        }

        let mut max_early_data = None;
        let mut extensions = reader.sub16()?;
        let mut seen = crate::tls::handshake::ExtensionSet::new();
        while !extensions.is_empty() {
            let kind = extensions.u16()?;
            let value = extensions.vector16()?;
            if !seen.insert(kind) {
                return Err(CodecError::illegal(format!(
                    "A NewSessionTicket repeats the {} extension.",
                    extension::name(kind))));
            }
            if kind == extension::EARLY_DATA {
                // In *this* message the early_data extension carries a
                // `uint32 max_early_data_size`; in a ClientHello and an
                // EncryptedExtensions it is empty. One extension code,
                // three wire formats, which is why there is a function
                // per message rather than one with a flag.
                let mut value = Reader::new(value);
                max_early_data = Some(value.u32()?);
                value.expect_empty("early_data in a NewSessionTicket")?;
            }
        }
        reader.expect_empty("NewSessionTicket")?;
        Ok(NewSessionTicket13 { lifetime, age_add, nonce, ticket,
                                max_early_data })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.u32(self.lifetime);
        writer.u32(self.age_add);
        writer.vector8(&self.nonce)?;
        writer.vector16(&self.ticket)?;
        writer.nested16(|w| {
            if let Some(max) = self.max_early_data {
                w.u16(extension::EARLY_DATA);
                w.nested16(|w| { w.u32(max); Ok(()) })?;
            }
            Ok(())
        })?;
        Ok(writer.finish())
    }
}

/// One offered PSK: `struct { opaque identity<1..2^16-1>; uint32
/// obfuscated_ticket_age; } PskIdentity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

/// The `pre_shared_key` extension's body in a **ClientHello**.
///
/// ```text
/// struct {
///     PskIdentity identities<7..2^16-1>;
///     PskBinderEntry binders<33..2^16-1>;
/// } OfferedPsks;
/// ```
#[derive(Clone, Debug)]
pub struct OfferedPsks {
    pub identities: Vec<PskIdentity>,
    pub binders: Vec<Vec<u8>>,
}

impl OfferedPsks {
    /// The extension body with the binders written as the right number
    /// of zero bytes.
    ///
    /// **This is what the binders are computed over**, not a shorter
    /// encoding. RFC 8446 4.2.11.2: "The length fields for the message
    /// (including the overall length, the length of the extensions
    /// block, and the length of the pre_shared_key extension) are all
    /// set as if binders of the correct lengths were present." So the
    /// truncated hello is the *whole* hello minus exactly the binder
    /// bytes, with every length still counting them - an implementation
    /// that recomputed the lengths without the binders produces a
    /// binder that no server accepts and that verifies against itself.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.nested16(|w| {
            for identity in &self.identities {
                w.vector16(&identity.identity)?;
                w.u32(identity.obfuscated_ticket_age);
            }
            Ok(())
        })?;
        writer.nested16(|w| {
            for binder in &self.binders {
                w.vector8(binder)?;
            }
            Ok(())
        })?;
        Ok(writer.finish())
    }

    /// How many bytes at the end of the encoding the binders occupy,
    /// including the list's own two length bytes and each entry's
    /// one-byte length.
    ///
    /// The truncated transcript is the hello with exactly this many
    /// bytes removed from the end.
    pub fn binders_length(&self) -> usize {
        2 + self.binders.iter().map(|binder| 1 + binder.len()).sum::<usize>()
    }

    pub fn parse(body: &[u8]) -> Result<OfferedPsks> {
        let mut reader = Reader::new(body);
        let mut identities = Vec::new();
        let mut list = reader.sub16()?;
        while !list.is_empty() {
            let identity = list.vector16()?.to_vec();
            if identity.is_empty() {
                return Err(CodecError::decode(
                    "A PskIdentity has an empty identity."));
            }
            identities.push(PskIdentity {
                identity,
                obfuscated_ticket_age: list.u32()?,
            });
        }
        let mut binders = Vec::new();
        let mut list = reader.sub16()?;
        while !list.is_empty() {
            let binder = list.vector8()?;
            // `opaque PskBinderEntry<32..255>`: a binder is a whole
            // HMAC output, and a short one is either a truncation
            // attack or a broken peer.
            if binder.len() < 32 {
                return Err(CodecError::illegal(format!(
                    "A PskBinderEntry is {} bytes; the minimum is 32.",
                    binder.len())));
            }
            binders.push(binder.to_vec());
        }
        reader.expect_empty("pre_shared_key")?;
        if identities.len() != binders.len() {
            return Err(CodecError::illegal(format!(
                "A pre_shared_key extension offers {} identities and {} \
                 binders; RFC 8446 4.2.11 requires one binder per identity, \
                 in the same order.", identities.len(), binders.len())));
        }
        if identities.is_empty() {
            return Err(CodecError::illegal(
                "A pre_shared_key extension offers no identities."));
        }
        Ok(OfferedPsks { identities, binders })
    }
}

/// The `pre_shared_key` extension's body in a **ServerHello**: a bare
/// `uint16 selected_identity`.
///
/// The same extension code as the ClientHello form above and a
/// completely different shape, which is why this is its own function
/// and takes no flag - a caller can pass the wrong flag.
pub fn encode_server_pre_shared_key(selected: u16) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.u16(selected);
    writer.finish()
}

pub fn parse_server_pre_shared_key(body: &[u8]) -> Result<u16> {
    let mut reader = Reader::new(body);
    let selected = reader.u16()?;
    reader.expect_empty("pre_shared_key in a ServerHello")?;
    Ok(selected)
}

/// `psk_key_exchange_modes`, RFC 8446 4.2.9.
pub mod psk_mode {
    /// PSK alone: no (EC)DHE, so no forward secrecy at all. Offered by
    /// nobody here and named so a server's choice can be reported.
    pub const KE: u8 = 0;
    /// PSK with (EC)DHE, which is what resumption means in practice and
    /// the only mode this client offers.
    pub const DHE_KE: u8 = 1;
}

pub fn encode_psk_key_exchange_modes(modes: &[u8]) -> Result<Vec<u8>> {
    let mut writer = Writer::new();
    writer.vector8(modes)?;
    Ok(writer.finish())
}

pub fn parse_psk_key_exchange_modes(body: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Reader::new(body);
    let modes = reader.vector8()?.to_vec();
    reader.expect_empty("psk_key_exchange_modes")?;
    if modes.is_empty() {
        return Err(CodecError::illegal(
            "A psk_key_exchange_modes extension lists no modes."));
    }
    Ok(modes)
}

// ------------------------------------------------- suite interpretation ---

/// The AEAD a TLS 1.3 suite uses, with its key and tag lengths.
///
/// Shared by both ends. It lived in `client.rs` until the server needed the
/// same answer, and a second copy would have been a second implementation
/// free to disagree - which for a table mapping suite codes to key sizes
/// means a handshake that fails at the first protected record with nothing
/// to say about why.
pub fn tls13_aead(suite: &CipherSuite)
                  -> core::result::Result<Tls13Aead, String> {
    let name = match suite.cipher {
        BulkCipher::Aes128Gcm | BulkCipher::Aes256Gcm => "aes-gcm",
        BulkCipher::Aes128Ccm | BulkCipher::Aes256Ccm => "aes-ccm",
        BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8 => "aes-ccm-8",
        BulkCipher::ChaCha20Poly1305 => "chacha20-poly1305",
        BulkCipher::KuznyechikMgmL | BulkCipher::KuznyechikMgmS
        | BulkCipher::MagmaMgmL | BulkCipher::MagmaMgmS => {
            // The name carries the block cipher, and `mgm()` below
            // carries everything else. Taken from the same place rather
            // than written twice.
            suite.cipher.mgm().expect("an MGM suite has MGM parameters").aead
        }
        other => return Err(format!("{} is not a TLS 1.3 AEAD.", other.name())),
    };
    Ok(Tls13Aead {
        name,
        key_len: suite.cipher.key_len(),
        iv_len: suite.cipher.iv_len_13(),
        tag_len: suite.cipher.tag_len(),
        mgm: suite.cipher.mgm(),
    })
}

/// Everything the record layer needs to know about a TLS 1.3 suite.
///
/// Returned as one value rather than a tuple because the set grew: it
/// was `(name, key_len, tag_len)` while every AEAD RFC 8446 names had a
/// twelve byte nonce and used its traffic key directly for a whole
/// epoch. RFC 9367's suites agree with neither, and picking the fields
/// separately is how a connection ends up with a sixteen byte IV and a
/// twelve byte nonce - each plausible, the pair silent until the first
/// protected record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tls13Aead {
    /// The AEAD's name in `api::AEADS`.
    pub name: &'static str,
    pub key_len: usize,
    /// The static IV's length, which is **an input to the expansion**
    /// rather than a truncation of it: RFC 8446 section 7.3 puts the
    /// requested length into what it hashes.
    pub iv_len: usize,
    pub tag_len: usize,
    /// RFC 9367's per-record re-keying and sequence cap, for the four
    /// suites that have them.
    pub mgm: Option<crate::tls::record_mgm::MgmSuite>,
}

/// The hash a TLS 1.3 suite's schedule runs on, as a `&'static str` because
/// the record layer carries it forward into every key update.
pub fn tls13_hash(suite: &CipherSuite) -> core::result::Result<&'static str, String> {
    tls13_hash_name(suite.prf).map_err(|e| format!("{}: {}", suite.name, e))
}

/// The hash a TLS 1.3 PRF names.
///
/// **Streebog-256 is one of them.** RFC 9367 section 4.2 requires it for
/// the four GOST suites - for the key schedule, the Finished MACs, the
/// transcript hash, the PSK binders and TLSTREE - so "TLS 1.3 means
/// SHA-2" stopped being true. One function rather than the two copies
/// this used to have, since the pair disagreeing would mean a schedule
/// that derives keys under one hash and checks Finished under another.
pub fn tls13_hash_name(prf: MacAlgorithm)
                       -> core::result::Result<&'static str, String> {
    match prf {
        MacAlgorithm::Sha256 => Ok("sha256"),
        MacAlgorithm::Sha384 => Ok("sha384"),
        MacAlgorithm::Streebog256 => Ok("streebog256"),
        other => Err(format!(
            "TLS 1.3 needs a SHA-256, SHA-384 or Streebog-256 suite; this \
             one says {}.", other.name())),
    }
}
