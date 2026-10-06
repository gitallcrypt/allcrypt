/*
Handshake messages.

A handshake message is a one byte type, a three byte length, and a body. The
awkward part is that messages and records do not line up: one record can
hold several messages, and one message can span several records. An
implementation that assumes one message per record works against most peers
and then fails against one that coalesces - and the failure looks like a
protocol error rather than a framing bug.

So `HandshakeReader` reassembles. Records go in, whole messages come out,
and nothing is returned until its declared length has arrived.

The other thing this file is careful about is **the transcript**. Every
handshake message's bytes, exactly as they appeared, go into a running hash
that the Finished message covers. If the transcript is computed over
anything other than what was actually exchanged - a re-encoding, a message
we reassembled differently - the handshake either fails or, worse, succeeds
while the two sides disagree about what they agreed. So the reader hands
back the raw bytes alongside the parsed message, and the hash is fed from
those.
*/

use crate::tls::codec::{CodecError, Reader, Result, Writer};
use crate::tls::{AlertDescription, ContentType, Version};

/// The largest handshake message we will reassemble.
///
/// The length field is 24 bits, so a peer can ask for 16MB before anything
/// has been authenticated. Real messages are a few kilobytes; a certificate
/// chain is the largest and rarely passes 16KB. 64KB is generous and still
/// bounded.
pub const MAX_HANDSHAKE_MESSAGE: usize = 65536;

// ------------------------------------------------------------------- types ---

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    /// TLS 1.2 only, and only for a stapled OCSP response (RFC 6066
    /// §8). At 1.3 the staple is an extension on the certificate entry
    /// instead, which is why there is no shared code between the two.
    CertificateStatus,
    Finished,
    KeyUpdate,
    MessageHash,
    Unknown(u8),
}

impl HandshakeType {
    pub fn from_byte(byte: u8) -> HandshakeType {
        match byte {
            0 => HandshakeType::HelloRequest,
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            4 => HandshakeType::NewSessionTicket,
            5 => HandshakeType::EndOfEarlyData,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            12 => HandshakeType::ServerKeyExchange,
            13 => HandshakeType::CertificateRequest,
            14 => HandshakeType::ServerHelloDone,
            15 => HandshakeType::CertificateVerify,
            16 => HandshakeType::ClientKeyExchange,
            22 => HandshakeType::CertificateStatus,
            20 => HandshakeType::Finished,
            24 => HandshakeType::KeyUpdate,
            254 => HandshakeType::MessageHash,
            other => HandshakeType::Unknown(other),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            HandshakeType::HelloRequest => 0,
            HandshakeType::ClientHello => 1,
            HandshakeType::ServerHello => 2,
            HandshakeType::NewSessionTicket => 4,
            HandshakeType::EndOfEarlyData => 5,
            HandshakeType::EncryptedExtensions => 8,
            HandshakeType::Certificate => 11,
            HandshakeType::ServerKeyExchange => 12,
            HandshakeType::CertificateRequest => 13,
            HandshakeType::ServerHelloDone => 14,
            HandshakeType::CertificateVerify => 15,
            HandshakeType::ClientKeyExchange => 16,
            HandshakeType::CertificateStatus => 22,
            HandshakeType::Finished => 20,
            HandshakeType::KeyUpdate => 24,
            HandshakeType::MessageHash => 254,
            HandshakeType::Unknown(byte) => byte,
        }
    }

    pub fn name(self) -> String {
        match self {
            HandshakeType::HelloRequest => "hello_request".to_string(),
            HandshakeType::ClientHello => "client_hello".to_string(),
            HandshakeType::ServerHello => "server_hello".to_string(),
            HandshakeType::NewSessionTicket => "new_session_ticket".to_string(),
            HandshakeType::EndOfEarlyData => "end_of_early_data".to_string(),
            HandshakeType::EncryptedExtensions => "encrypted_extensions".to_string(),
            HandshakeType::Certificate => "certificate".to_string(),
            HandshakeType::ServerKeyExchange => "server_key_exchange".to_string(),
            HandshakeType::CertificateRequest => "certificate_request".to_string(),
            HandshakeType::ServerHelloDone => "server_hello_done".to_string(),
            HandshakeType::CertificateVerify => "certificate_verify".to_string(),
            HandshakeType::ClientKeyExchange => "client_key_exchange".to_string(),
            HandshakeType::CertificateStatus => "certificate_status".to_string(),
            HandshakeType::Finished => "finished".to_string(),
            HandshakeType::KeyUpdate => "key_update".to_string(),
            HandshakeType::MessageHash => "message_hash".to_string(),
            HandshakeType::Unknown(byte) => format!("unknown handshake type {}", byte),
        }
    }
}

/// One handshake message, with the bytes it arrived as.
///
/// `raw` includes the four byte header and is what goes into the transcript
/// hash. Keeping it rather than re-encoding is not an optimisation: a
/// re-encoding that differs anywhere makes the Finished check fail, or -
/// far worse - lets two sides agree on a transcript that differs from what
/// crossed the wire.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HandshakeMessage {
    pub message_type: HandshakeType,
    pub body: Vec<u8>,
    pub raw: Vec<u8>,
}

impl HandshakeMessage {
    /// Build a message, computing its header.
    pub fn new(message_type: HandshakeType, body: Vec<u8>) -> Result<HandshakeMessage> {
        if body.len() > 0xff_ffff {
            return Err(CodecError::decode("Handshake message body is too long."));
        }
        let mut raw = Vec::with_capacity(body.len() + 4);
        raw.push(message_type.to_byte());
        raw.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        raw.extend_from_slice(&body);
        Ok(HandshakeMessage { message_type, body, raw })
    }

    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.body)
    }
}

// ----------------------------------------------------------- reassembling ---

/// Turns record payloads into whole handshake messages.
///
/// Messages and records do not line up. Feed every handshake record's
/// payload in and take whole messages out.
#[derive(Default)]
pub struct HandshakeReader {
    buffer: Vec<u8>,
}

impl HandshakeReader {
    pub fn new() -> HandshakeReader {
        HandshakeReader::default()
    }

    pub fn push(&mut self, payload: &[u8]) {
        self.buffer.extend_from_slice(payload);
    }

    /// Bytes held that are not yet a whole message.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// True if a partial message is being held.
    ///
    /// This matters at a flight boundary: a ChangeCipherSpec arriving while
    /// a handshake message is half-delivered is a peer interleaving things
    /// it should not, and has been a real attack.
    pub fn has_partial_message(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// The next whole message, if there is one.
    ///
    /// Not `next`, and not an `Iterator`: this returns
    /// `Result<Option<..>>`, where `None` means "not yet, push more
    /// bytes" and `Err` means the peer sent something malformed. An
    /// `Iterator` flattens those into one `None`, and a caller that
    /// stops on the first `None` would treat a protocol violation as a
    /// quiet end of flight.
    pub fn next_message(&mut self) -> Result<Option<HandshakeMessage>> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let message_type = HandshakeType::from_byte(self.buffer[0]);
        let length = u32::from_be_bytes([0, self.buffer[1], self.buffer[2],
                                         self.buffer[3]]) as usize;

        // Checked before the body is waited for, so a peer cannot make us
        // hold 16MB of buffer by claiming a length it never sends.
        if length > MAX_HANDSHAKE_MESSAGE {
            return Err(CodecError {
                alert: AlertDescription::RECORD_OVERFLOW,
                detail: format!("{} message claims {} bytes; the limit is {}.",
                                message_type.name(), length, MAX_HANDSHAKE_MESSAGE),
            });
        }

        if self.buffer.len() < 4 + length {
            return Ok(None);
        }

        let raw = self.buffer[..4 + length].to_vec();
        let body = self.buffer[4..4 + length].to_vec();
        self.buffer.drain(..4 + length);
        Ok(Some(HandshakeMessage { message_type, body, raw }))
    }
}

// ------------------------------------------------------------- extensions ---

/// An extension, kept as its code and body.
///
/// Unknown extensions are kept rather than dropped, because a client has to
/// be able to notice that a server answered with an extension the client
/// never offered - which RFC 5246 forbids and which is worth refusing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Extension {
    pub kind: u16,
    pub body: Vec<u8>,
}

/// The extension type codes, from the IANA registry.
pub mod extension {
    pub const SERVER_NAME: u16 = 0;
    pub const MAX_FRAGMENT_LENGTH: u16 = 1;
    pub const STATUS_REQUEST: u16 = 5;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const EC_POINT_FORMATS: u16 = 11;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const USE_SRTP: u16 = 14;
    pub const HEARTBEAT: u16 = 15;
    pub const ALPN: u16 = 16;
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;
    pub const PADDING: u16 = 21;
    pub const ENCRYPT_THEN_MAC: u16 = 22;
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    pub const SESSION_TICKET: u16 = 35;
    pub const PRE_SHARED_KEY: u16 = 41;
    pub const EARLY_DATA: u16 = 42;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const COOKIE: u16 = 44;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const CERTIFICATE_AUTHORITIES: u16 = 47;
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = 50;
    pub const KEY_SHARE: u16 = 51;
    /// RFC 5746. Its absence is what made the 2009 renegotiation attack
    /// work, so it is not an optional nicety.
    pub const RENEGOTIATION_INFO: u16 = 0xff01;

    pub fn name(kind: u16) -> String {
        match kind {
            SERVER_NAME => "server_name".to_string(),
            MAX_FRAGMENT_LENGTH => "max_fragment_length".to_string(),
            STATUS_REQUEST => "status_request".to_string(),
            SUPPORTED_GROUPS => "supported_groups".to_string(),
            EC_POINT_FORMATS => "ec_point_formats".to_string(),
            SIGNATURE_ALGORITHMS => "signature_algorithms".to_string(),
            USE_SRTP => "use_srtp".to_string(),
            HEARTBEAT => "heartbeat".to_string(),
            ALPN => "application_layer_protocol_negotiation".to_string(),
            SIGNED_CERTIFICATE_TIMESTAMP => "signed_certificate_timestamp".to_string(),
            PADDING => "padding".to_string(),
            ENCRYPT_THEN_MAC => "encrypt_then_mac".to_string(),
            EXTENDED_MASTER_SECRET => "extended_master_secret".to_string(),
            SESSION_TICKET => "session_ticket".to_string(),
            PRE_SHARED_KEY => "pre_shared_key".to_string(),
            EARLY_DATA => "early_data".to_string(),
            SUPPORTED_VERSIONS => "supported_versions".to_string(),
            COOKIE => "cookie".to_string(),
            PSK_KEY_EXCHANGE_MODES => "psk_key_exchange_modes".to_string(),
            CERTIFICATE_AUTHORITIES => "certificate_authorities".to_string(),
            SIGNATURE_ALGORITHMS_CERT => "signature_algorithms_cert".to_string(),
            KEY_SHARE => "key_share".to_string(),
            RENEGOTIATION_INFO => "renegotiation_info".to_string(),
            other => format!("extension {}", other),
        }
    }
}

/// Read an extension block: `Extension extensions<0..2^16-1>`.
///
/// A repeated extension type is an error. RFC 5246 says each may appear at
/// most once, and where a duplicate is tolerated the question becomes which
/// one is honoured - the same shape of problem as duplicate certificate
/// extensions.
pub fn read_extensions(reader: &mut Reader<'_>) -> Result<Vec<Extension>> {
    if reader.is_empty() {
        // Extensions are optional in TLS 1.2 and their absence is not an
        // empty block - a hello with no extension block at all is legal.
        return Ok(Vec::new());
    }
    let mut block = reader.sub16()?;
    let mut extensions: Vec<Extension> = Vec::new();

    while !block.is_empty() {
        let kind = block.u16()?;
        let body = block.vector16()?.to_vec();
        if extensions.iter().any(|existing| existing.kind == kind) {
            return Err(CodecError::illegal(format!(
                "Extension {} appears more than once.", extension::name(kind))));
        }
        extensions.push(Extension { kind, body });
    }
    Ok(extensions)
}

/// The **optional** form: an empty list writes nothing at all.
///
/// Right for a ClientHello or a ServerHello, where TLS 1.0 to 1.2 allow
/// the extension block to be absent entirely and a two-byte zero would be
/// a different message. Wrong everywhere in TLS 1.3 that declares an
/// `Extension extensions<0..2^16-1>` field, which is mandatory and whose
/// empty value is a two-byte zero - see `write_extensions_required`.
pub fn write_extensions(writer: &mut Writer, extensions: &[Extension]) -> Result<()> {
    if extensions.is_empty() {
        return Ok(());
    }
    writer.nested16(|block| {
        for extension in extensions {
            block.u16(extension.kind);
            block.vector16(&extension.body)?;
        }
        Ok(())
    })
}

/// The **mandatory** form: an empty list writes a two-byte zero.
///
/// TLS 1.3's EncryptedExtensions and the per-certificate extensions in its
/// Certificate message both declare the field as present, so omitting it
/// makes the message two bytes short. OpenSSL answers `length mismatch`
/// and says nothing more useful.
///
/// Our own parser accepts both forms - `read_extensions` treats an empty
/// reader as an empty list, as a relying party must - so an encoder using
/// the wrong one agrees with our own decoder perfectly. Our client and our
/// server completed a whole 1.3 handshake over a malformed
/// EncryptedExtensions before a real peer saw it.
pub fn write_extensions_required(writer: &mut Writer, extensions: &[Extension])
                                 -> Result<()> {
    writer.nested16(|block| {
        for extension in extensions {
            block.u16(extension.kind);
            block.vector16(&extension.body)?;
        }
        Ok(())
    })
}

/// Find one extension by type.
pub fn find_extension(extensions: &[Extension], kind: u16) -> Option<&Extension> {
    extensions.iter().find(|extension| extension.kind == kind)
}

// ----------------------------------------------------------------- hellos ---

/// The 32 byte random every hello carries.
///
/// In TLS 1.2 the first four bytes were nominally a timestamp. They are
/// not, any more: sending the real time leaks the client's clock and helps
/// fingerprint it, and every modern implementation fills all 32 bytes with
/// random. We do the same.
pub type Random = [u8; 32];

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientHello {
    /// The *legacy* version: what the client claims here is capped at TLS
    /// 1.2 even when it wants 1.3, because middleboxes drop anything
    /// higher. The real preference is in `supported_versions`.
    pub legacy_version: Version,
    pub random: Random,
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn parse(body: &[u8]) -> Result<ClientHello> {
        let mut reader = Reader::new(body);
        let legacy_version = Version::from_bytes([reader.u8()?, reader.u8()?]);

        let random_bytes = reader.take(32)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(random_bytes);

        let session_id = reader.vector8()?.to_vec();
        if session_id.len() > 32 {
            return Err(CodecError::illegal(format!(
                "Session id is {} bytes; the limit is 32.", session_id.len())));
        }

        let cipher_suites = reader.u16_list()?;
        if cipher_suites.is_empty() {
            return Err(CodecError::illegal("ClientHello offers no cipher suites."));
        }

        let compression_methods = reader.vector8()?.to_vec();
        if compression_methods.is_empty() {
            return Err(CodecError::illegal(
                "ClientHello offers no compression methods."));
        }

        let extensions = read_extensions(&mut reader)?;
        reader.expect_empty("ClientHello")?;

        Ok(ClientHello { legacy_version, random, session_id, cipher_suites,
                         compression_methods, extensions })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.raw(&self.legacy_version.to_bytes());
        writer.raw(&self.random);
        writer.vector8(&self.session_id)?;
        writer.u16_list(&self.cipher_suites)?;
        writer.vector8(&self.compression_methods)?;
        write_extensions(&mut writer, &self.extensions)?;
        Ok(writer.finish())
    }

    /// The server name this hello asks for, if it carries SNI.
    pub fn server_name(&self) -> Option<String> {
        let extension = find_extension(&self.extensions, extension::SERVER_NAME)?;
        let mut reader = Reader::new(&extension.body);
        let mut list = reader.sub16().ok()?;
        while !list.is_empty() {
            let name_type = list.u8().ok()?;
            let name = list.vector16().ok()?;
            // Type 0 is host_name, and it is the only one ever defined.
            if name_type == 0 {
                return core::str::from_utf8(name).ok().map(|s| s.to_string());
            }
        }
        None
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServerHello {
    pub legacy_version: Version,
    pub random: Random,
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn parse(body: &[u8]) -> Result<ServerHello> {
        let mut reader = Reader::new(body);
        let legacy_version = Version::from_bytes([reader.u8()?, reader.u8()?]);

        let random_bytes = reader.take(32)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(random_bytes);

        let session_id = reader.vector8()?.to_vec();
        if session_id.len() > 32 {
            return Err(CodecError::illegal(format!(
                "Session id is {} bytes; the limit is 32.", session_id.len())));
        }

        let cipher_suite = reader.u16()?;
        let compression_method = reader.u8()?;
        let extensions = read_extensions(&mut reader)?;
        reader.expect_empty("ServerHello")?;

        Ok(ServerHello { legacy_version, random, session_id, cipher_suite,
                         compression_method, extensions })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.raw(&self.legacy_version.to_bytes());
        writer.raw(&self.random);
        writer.vector8(&self.session_id)?;
        writer.u16(self.cipher_suite);
        writer.u8(self.compression_method);
        write_extensions(&mut writer, &self.extensions)?;
        Ok(writer.finish())
    }

    /// The version TLS 1.3 hides in `supported_versions`, or the legacy one.
    ///
    /// A TLS 1.3 ServerHello still says 1.2 in the version field, to get
    /// past middleboxes; the real answer is in the extension. Reading only
    /// the legacy field means silently treating a 1.3 connection as 1.2.
    pub fn negotiated_version(&self) -> Version {
        if let Some(extension) = find_extension(&self.extensions,
                                                extension::SUPPORTED_VERSIONS) {
            if extension.body.len() == 2 {
                return Version::from_bytes([extension.body[0], extension.body[1]]);
            }
        }
        self.legacy_version
    }
}

// ----------------------------------------------------------- other messages ---

/// The server's certificate chain: leaf first, then whatever it chose to
/// include.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CertificateChain {
    pub certificates: Vec<Vec<u8>>,
}

impl CertificateChain {
    pub fn parse(body: &[u8]) -> Result<CertificateChain> {
        let mut reader = Reader::new(body);
        let mut list = reader.sub24()?;
        reader.expect_empty("Certificate")?;

        let mut certificates = Vec::new();
        while !list.is_empty() {
            certificates.push(list.vector24()?.to_vec());
        }
        // An empty chain is legal from a *client* that has no certificate,
        // and is a protocol error from a server. Which one this is depends
        // on who sent it, so that check belongs in the state machine.
        Ok(CertificateChain { certificates })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.nested24(|list| {
            for certificate in &self.certificates {
                list.vector24(certificate)?;
            }
            Ok(())
        })?;
        Ok(writer.finish())
    }
}

/// The Finished message's verify_data: 12 bytes in TLS, 36 in SSLv3.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn parse(body: &[u8]) -> Result<Finished> {
        // The length is fixed by the version, so a Finished of the wrong
        // size is a protocol error. The state machine knows which version
        // is in play; this keeps the bytes.
        if body.is_empty() {
            return Err(CodecError::decode("Finished has no verify_data."));
        }
        Ok(Finished { verify_data: body.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.verify_data.clone()
    }
}

/// `ServerKeyExchange` and `ClientKeyExchange` bodies are
/// ciphersuite-specific, so they are kept as bytes here and interpreted by
/// whichever key exchange is in play.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyExchange {
    pub body: Vec<u8>,
}

/// The `signature_algorithms` extension and the signature on a
/// ServerKeyExchange both use this pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignatureScheme {
    pub hash: u8,
    pub signature: u8,
}

impl SignatureScheme {
    pub const RSA_PKCS1_SHA256: SignatureScheme = SignatureScheme { hash: 4, signature: 1 };
    pub const RSA_PKCS1_SHA384: SignatureScheme = SignatureScheme { hash: 5, signature: 1 };
    pub const RSA_PKCS1_SHA512: SignatureScheme = SignatureScheme { hash: 6, signature: 1 };
    pub const RSA_PKCS1_SHA1: SignatureScheme = SignatureScheme { hash: 2, signature: 1 };
    pub const ECDSA_SHA256: SignatureScheme = SignatureScheme { hash: 4, signature: 3 };
    pub const ECDSA_SHA384: SignatureScheme = SignatureScheme { hash: 5, signature: 3 };
    pub const ECDSA_SHA512: SignatureScheme = SignatureScheme { hash: 6, signature: 3 };
    pub const ECDSA_SHA1: SignatureScheme = SignatureScheme { hash: 2, signature: 3 };
    // DSA, signature 2 (RFC 5246 7.4.1.4.1). TLS 1.2 only; RFC 8446
    // removed DSA.
    pub const DSA_SHA1: SignatureScheme = SignatureScheme { hash: 2, signature: 2 };
    pub const DSA_SHA224: SignatureScheme = SignatureScheme { hash: 3, signature: 2 };
    pub const DSA_SHA256: SignatureScheme = SignatureScheme { hash: 4, signature: 2 };
    pub const DSA_SHA384: SignatureScheme = SignatureScheme { hash: 5, signature: 2 };
    pub const DSA_SHA512: SignatureScheme = SignatureScheme { hash: 6, signature: 2 };
    /// RFC 9189 section 5. The hash byte is 8, "Intrinsic" (RFC 8422) -
    /// **not** a hash identifier: GOST R 34.10-2012 names its digest
    /// itself, so the pair is (8, 64) and (8, 65) rather than a hash
    /// crossed with a signature the way every other pair here is.
    ///
    /// The same byte 8 is the first octet of TLS 1.3's PSS and EdDSA
    /// codepoints, which is why `hash_name` must not answer for it -
    /// 0x0804 is `rsa_pss_rsae_sha256`, not hash 8 signature 4.
    pub const GOST_256: SignatureScheme = SignatureScheme { hash: 8, signature: 64 };
    pub const GOST_512: SignatureScheme = SignatureScheme { hash: 8, signature: 65 };

    /// The same two algorithms as a GOST implementation older than RFC
    /// 9189 names them, and the 2001 one that has no modern spelling
    /// at all.
    ///
    /// Before the codepoints above were assigned, both halves of the
    /// pair carried the same private-use byte: 0xEDED, 0xEEEE, 0xEFEF.
    /// RFC 9189 section 10 describes the 2012 pair as "the old value
    /// 0xEE instead of the values 64, 8, and 67" - one byte standing
    /// for the signature algorithm, the hash and the certificate type
    /// at once - and OpenSSL spells the two halves out as
    /// `TLSEXT_hash_gostr34112012_256` and
    /// `TLSEXT_signature_gostr34102012_256`, both 238.
    ///
    /// `GOST_2001` is not a legacy spelling of anything: GOST R
    /// 34.10-2001 with GOST R 34.11-94 was never given an IANA
    /// codepoint, so 0xEDED is its only name. It is what the
    /// TLS_GOSTR341001_WITH_28147_CNT_IMIT suite signs with.
    pub const GOST_256_LEGACY: SignatureScheme =
        SignatureScheme { hash: 238, signature: 238 };
    pub const GOST_512_LEGACY: SignatureScheme =
        SignatureScheme { hash: 239, signature: 239 };
    pub const GOST_2001: SignatureScheme =
        SignatureScheme { hash: 237, signature: 237 };

    pub fn from_u16(value: u16) -> SignatureScheme {
        SignatureScheme { hash: (value >> 8) as u8, signature: value as u8 }
    }

    pub fn to_u16(self) -> u16 {
        ((self.hash as u16) << 8) | self.signature as u16
    }

    /// The hash this library's name for it, if we implement it.
    pub fn hash_name(self) -> Option<&'static str> {
        match self.hash {
            1 => Some("md5"),
            2 => Some("sha1"),
            3 => Some("sha224"),
            4 => Some("sha256"),
            5 => Some("sha384"),
            6 => Some("sha512"),
            _ => None,
        }
    }

    pub fn signature_name(self) -> &'static str {
        match self.signature {
            0 => "anonymous",
            1 => "rsa",
            2 => "dsa",
            3 => "ecdsa",
            64 => "gostr34102012_256",
            65 => "gostr34102012_512",
            237 => "gostr34102001",
            238 => "gostr34102012_256",
            239 => "gostr34102012_512",
            _ => "unknown",
        }
    }

    pub fn name(self) -> String {
        // GOST names its own digest, so there is no hash half to print
        // and appending one would invent a distinction the codepoint
        // does not have.
        if self == SignatureScheme::GOST_256 || self == SignatureScheme::GOST_512
            || self.hash >= 237 {
            return self.signature_name().to_string();
        }
        format!("{}_{}", self.signature_name(),
                self.hash_name().unwrap_or("unknown-hash"))
    }
}

/// The named curve codes from the IANA "TLS Supported Groups" registry.
///
/// These are the numbers on the wire; `curve_name` maps them to what this
/// library calls its curves. A group we do not implement is kept rather
/// than rejected, so a server choosing one produces a clear message instead
/// of a parse failure.
pub mod groups {
    pub const SECP256K1: u16 = 22;
    pub const SECP256R1: u16 = 23;      // P-256
    pub const SECP384R1: u16 = 24;      // P-384
    pub const SECP521R1: u16 = 25;      // P-521
    pub const X25519: u16 = 29;
    pub const X448: u16 = 30;
    pub const FFDHE2048: u16 = 256;
    pub const FFDHE3072: u16 = 257;

    /// The hybrid post-quantum groups of RFC 10024: ML-KEM combined with
    /// a classical exchange, so that the connection is secure if either
    /// half is. **TLS 1.3 only** - the RFC defines no TLS 1.2 use, and a
    /// 1.2 ServerKeyExchange naming one is refused.
    pub const SECP256R1_MLKEM768: u16 = 0x11EB;
    pub const X25519_MLKEM768: u16 = 0x11EC;
    pub const SECP384R1_MLKEM1024: u16 = 0x11ED;

    /// The hybrid groups, strongest first.
    pub const HYBRID: &[u16] = &[SECP384R1_MLKEM1024, X25519_MLKEM768,
                                 SECP256R1_MLKEM768];

    /// For a hybrid group: `(ML-KEM parameter set, classical group,
    /// whether ML-KEM comes first)`.
    ///
    /// **The order is not the same for all three**, and it is the whole
    /// of the difference between a working hybrid and one that
    /// interoperates with nothing. RFC 10024 puts ML-KEM first for
    /// X25519MLKEM768 - in both key shares and in the shared secret - and
    /// the ECDHE part first for the two NIST-curve hybrids, which follow
    /// the older draft's "classical then post-quantum" rule. A single
    /// "KEM first" or "classical first" for all three would get one of
    /// the two kinds wrong while round-tripping against itself.
    pub fn hybrid(code: u16) -> Option<(&'static str, u16, bool)> {
        match code {
            X25519_MLKEM768 => Some(("ML-KEM-768", X25519, true)),
            SECP256R1_MLKEM768 => Some(("ML-KEM-768", SECP256R1, false)),
            SECP384R1_MLKEM1024 => Some(("ML-KEM-1024", SECP384R1, false)),
            _ => None,
        }
    }

    /// The GOST curves, RFC 9189 section 6 and table 2.
    ///
    /// **The numbering is not the parameter sets' own.** GC256B is
    /// CryptoPro-A, GC256C is CryptoPro-B and GC256D is CryptoPro-C,
    /// while GC256A is the TC 26 set that has no CryptoPro name at
    /// all - so the letters line up with nothing and a table written
    /// from the letters alone is wrong by one in three places. The
    /// document's table is reproduced in `curve_name` below.
    pub const GC256A: u16 = 34;
    pub const GC256B: u16 = 35;
    pub const GC256C: u16 = 36;
    pub const GC256D: u16 = 37;
    pub const GC512A: u16 = 38;
    pub const GC512B: u16 = 39;
    pub const GC512C: u16 = 40;

    /// The GOST groups, in the order a ClientHello offers them.
    pub const GOST: &[u16] = &[GC256A, GC256B, GC256C, GC256D,
                               GC512A, GC512B, GC512C];

    /// This library's name for a group, if it implements it.
    pub fn curve_name(code: u16) -> Option<&'static str> {
        match code {
            SECP256R1 => Some("P-256"),
            SECP384R1 => Some("P-384"),
            SECP521R1 => Some("P-521"),
            SECP256K1 => Some("secp256k1"),
            // RFC 9189 table 2, in the document's order rather than
            // ours.
            GC256A => Some("gost256-tc26-a"),
            GC256B => Some("gost256-a"),
            GC256C => Some("gost256-b"),
            GC256D => Some("gost256-c"),
            GC512A => Some("gost512-a"),
            GC512B => Some("gost512-b"),
            GC512C => Some("gost512-c"),
            _ => None,
        }
    }

    pub fn name(code: u16) -> String {
        match code {
            SECP256K1 => "secp256k1".to_string(),
            SECP256R1 => "secp256r1".to_string(),
            SECP384R1 => "secp384r1".to_string(),
            SECP521R1 => "secp521r1".to_string(),
            X25519 => "x25519".to_string(),
            X448 => "x448".to_string(),
            FFDHE2048 => "ffdhe2048".to_string(),
            FFDHE3072 => "ffdhe3072".to_string(),
            X25519_MLKEM768 => "X25519MLKEM768".to_string(),
            SECP256R1_MLKEM768 => "SecP256r1MLKEM768".to_string(),
            SECP384R1_MLKEM1024 => "SecP384r1MLKEM1024".to_string(),
            GC256A => "GC256A".to_string(),
            GC256B => "GC256B".to_string(),
            GC256C => "GC256C".to_string(),
            GC256D => "GC256D".to_string(),
            GC512A => "GC512A".to_string(),
            GC512B => "GC512B".to_string(),
            GC512C => "GC512C".to_string(),
            other => format!("group {}", other),
        }
    }
}

/// A parsed ECDHE ServerKeyExchange (RFC 4492 section 5.4).
///
/// The signature covers `client_random || server_random || params`, where
/// `params` is the curve and point exactly as they appeared. Verifying it
/// over a re-encoding would verify our understanding rather than the
/// message - and the whole purpose of the signature is to bind the
/// ephemeral key to the certificate, so a re-encoding that differs
/// anywhere breaks the binding.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServerEcdhParams {
    pub group: u16,
    /// The server's ephemeral public point, SEC1 encoded.
    pub point: Vec<u8>,
    /// The curve and point as they arrived, for the signature input.
    pub raw_params: Vec<u8>,
    /// The signature algorithm, present from TLS 1.2 on.
    pub scheme: Option<SignatureScheme>,
    pub signature: Vec<u8>,
}

impl ServerEcdhParams {
    /// `version` decides whether a SignatureAndHashAlgorithm precedes the
    /// signature: TLS 1.2 added it, and reading it when it is not there
    /// silently consumes two bytes of the signature.
    pub fn parse(body: &[u8], version: Version) -> Result<ServerEcdhParams> {
        let mut reader = Reader::new(body);

        // ECParameters: curve_type must be named_curve (3). The other two -
        // explicit_prime and explicit_char2 - let a server send arbitrary
        // curve parameters, which is the invalid-curve attack with the
        // curve supplied by the attacker. RFC 8422 deprecates them and we
        // refuse them.
        let curve_type = reader.u8()?;
        if curve_type != 3 {
            return Err(CodecError::illegal(format!(
                "ServerKeyExchange uses curve type {}; only named curves (3) \
                 are accepted, because explicit parameters let the server \
                 choose the group.", curve_type)));
        }
        let group = reader.u16()?;
        let point = reader.vector8()?.to_vec();
        if point.is_empty() {
            return Err(CodecError::illegal("ServerKeyExchange has an empty point."));
        }

        // Everything read so far is what the signature covers.
        let params_len = body.len() - reader.left();
        let raw_params = body[..params_len].to_vec();

        let scheme = if version >= Version::TLS12 {
            Some(SignatureScheme::from_u16(reader.u16()?))
        } else {
            None
        };
        let signature = reader.vector16()?.to_vec();
        reader.expect_empty("ServerKeyExchange")?;

        Ok(ServerEcdhParams { group, point, raw_params, scheme, signature })
    }

    /// The bytes the signature is over: both randoms then the parameters.
    pub fn signed_bytes(&self, client_random: &Random,
                        server_random: &Random) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.raw_params.len());
        out.extend_from_slice(client_random);
        out.extend_from_slice(server_random);
        out.extend_from_slice(&self.raw_params);
        out
    }
}

/// A parsed finite-field DHE ServerKeyExchange (RFC 5246 section 7.4.3).
///
/// `ServerDHParams` is three opaque vectors - the prime, the generator and
/// the server's public value - and then the same signature tail as the
/// elliptic curve version. The numbers are kept as bytes rather than
/// parsed into `BigUint` here for the same reason `ServerEcdhParams` keeps
/// the raw point: the signature covers the bytes that arrived, and
/// verifying it over a re-encoding would verify our understanding of the
/// message instead of the message.
///
/// Note what is *not* in this structure and not in the protocol: any
/// indication that `p` is prime, that it is large, or that it is a group
/// the client would have chosen. In TLS 1.2 DHE the server picks the group
/// unilaterally and the client's only options are to accept it or hang up.
/// That asymmetry is Logjam's foothold, and it is why the client checks
/// the size itself.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServerDhParams {
    /// The prime modulus, big-endian, as it arrived.
    pub p: Vec<u8>,
    /// The generator, big-endian, as it arrived.
    pub g: Vec<u8>,
    /// The server's ephemeral public value, big-endian, as it arrived.
    pub public: Vec<u8>,
    /// The three vectors together, for the signature input.
    pub raw_params: Vec<u8>,
    /// The signature algorithm, present from TLS 1.2 on.
    pub scheme: Option<SignatureScheme>,
    pub signature: Vec<u8>,
}

impl ServerDhParams {
    pub fn parse(body: &[u8], version: Version) -> Result<ServerDhParams> {
        let mut reader = Reader::new(body);

        let p = reader.vector16()?.to_vec();
        let g = reader.vector16()?.to_vec();
        let public = reader.vector16()?.to_vec();
        for (label, value) in [("prime", &p), ("generator", &g),
                               ("public value", &public)] {
            if value.is_empty() {
                return Err(CodecError::illegal(format!(
                    "The ServerKeyExchange has an empty Diffie-Hellman {}.",
                    label)));
            }
        }

        let params_len = body.len() - reader.left();
        let raw_params = body[..params_len].to_vec();

        let scheme = if version >= Version::TLS12 {
            Some(SignatureScheme::from_u16(reader.u16()?))
        } else {
            None
        };
        let signature = reader.vector16()?.to_vec();
        reader.expect_empty("ServerKeyExchange")?;

        Ok(ServerDhParams { p, g, public, raw_params, scheme, signature })
    }

    /// The bytes the signature is over: both randoms then the parameters.
    pub fn signed_bytes(&self, client_random: &Random,
                        server_random: &Random) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.raw_params.len());
        out.extend_from_slice(client_random);
        out.extend_from_slice(server_random);
        out.extend_from_slice(&self.raw_params);
        out
    }
}

/// A parsed export-grade RSA ServerKeyExchange (RFC 2246 section 7.4.3).
///
/// The message every non-export RSA suite does **not** have, and the one
/// FREAK is about.
///
/// In an export RSA suite the server's certificate key is too large for
/// the export rules, so it signs a *temporary* RSA key - historically 512
/// bits - and the client encrypts the premaster under that instead. The
/// temporary key is the thing an attacker factors: 512 bits is hours of
/// cloud time, and the same temporary key is typically reused for a
/// server's whole lifetime.
///
/// FREAK was not a flaw in this message. It was clients accepting it for
/// a suite that has no ServerKeyExchange at all - a plain
/// `TLS_RSA_WITH_AES_128_CBC_SHA` - and downgrading themselves to a 512
/// bit key the server had never agreed to use. The defence is to decide
/// whether this message is expected from the **negotiated suite**, which
/// is what `ClientConnection` does.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServerRsaParams {
    /// The temporary modulus, big-endian, as it arrived.
    pub modulus: Vec<u8>,
    /// The temporary public exponent, big-endian, as it arrived.
    pub exponent: Vec<u8>,
    /// Both vectors together, for the signature input.
    pub raw_params: Vec<u8>,
    pub scheme: Option<SignatureScheme>,
    pub signature: Vec<u8>,
}

impl ServerRsaParams {
    pub fn parse(body: &[u8], version: Version) -> Result<ServerRsaParams> {
        let mut reader = Reader::new(body);

        let modulus = reader.vector16()?.to_vec();
        let exponent = reader.vector16()?.to_vec();
        if modulus.is_empty() || exponent.is_empty() {
            return Err(CodecError::illegal(
                "The ServerKeyExchange has an empty temporary RSA key."));
        }

        let params_len = body.len() - reader.left();
        let raw_params = body[..params_len].to_vec();

        let scheme = if version >= Version::TLS12 {
            Some(SignatureScheme::from_u16(reader.u16()?))
        } else {
            None
        };
        let signature = reader.vector16()?.to_vec();
        reader.expect_empty("ServerKeyExchange")?;

        Ok(ServerRsaParams { modulus, exponent, raw_params, scheme, signature })
    }

    pub fn signed_bytes(&self, client_random: &Random,
                        server_random: &Random) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.raw_params.len());
        out.extend_from_slice(client_random);
        out.extend_from_slice(server_random);
        out.extend_from_slice(&self.raw_params);
        out
    }
}

/// A record payload's content type paired with its bytes, for the state
/// machine to dispatch on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Incoming {
    Handshake(HandshakeMessage),
    ChangeCipherSpec,
    Alert(crate::tls::Alert),
    ApplicationData(Vec<u8>),
}

impl Incoming {
    pub fn describe(&self) -> String {
        match self {
            Incoming::Handshake(message) => message.message_type.name(),
            Incoming::ChangeCipherSpec => "change_cipher_spec".to_string(),
            Incoming::Alert(alert) => alert.name(),
            Incoming::ApplicationData(data) =>
                format!("{} bytes of application data", data.len()),
        }
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            Incoming::Handshake(_) => ContentType::Handshake,
            Incoming::ChangeCipherSpec => ContentType::ChangeCipherSpec,
            Incoming::Alert(_) => ContentType::Alert,
            Incoming::ApplicationData(_) => ContentType::ApplicationData,
        }
    }
}

// ------------------------------------------ the TLS 1.2 CertificateRequest ---

/// What kinds of key a TLS 1.2 server will accept (RFC 5246 7.4.4).
///
/// These are **key algorithms, not signature schemes**, and they are a
/// different list from `supported_signature_algorithms` in the same
/// message. A client has to satisfy both: the type says what kind of key
/// the certificate may hold, the schemes say how it may sign.
pub mod client_certificate_type {
    pub const RSA_SIGN: u8 = 1;
    pub const DSS_SIGN: u8 = 2;
    pub const RSA_FIXED_DH: u8 = 3;
    pub const DSS_FIXED_DH: u8 = 4;
    pub const ECDSA_SIGN: u8 = 64;
    pub const RSA_FIXED_ECDH: u8 = 65;
    pub const ECDSA_FIXED_ECDH: u8 = 66;
    /// RFC 9189 section 7.
    pub const GOST_SIGN256: u8 = 67;
    pub const GOST_SIGN512: u8 = 68;
    /// The values a GOST implementation older than RFC 9189 uses for
    /// the two above, from the private-use range - section 10 of the
    /// same document. One byte stood for the signature algorithm, the
    /// hash and the certificate type at once, which is why 0xEE turns
    /// up in three different registries' worth of fields.
    pub const GOST_SIGN256_LEGACY: u8 = 0xee;
    pub const GOST_SIGN512_LEGACY: u8 = 0xef;

    pub fn name(value: u8) -> String {
        match value {
            RSA_SIGN => "rsa_sign".to_string(),
            DSS_SIGN => "dss_sign".to_string(),
            RSA_FIXED_DH => "rsa_fixed_dh".to_string(),
            DSS_FIXED_DH => "dss_fixed_dh".to_string(),
            ECDSA_SIGN => "ecdsa_sign".to_string(),
            RSA_FIXED_ECDH => "rsa_fixed_ecdh".to_string(),
            ECDSA_FIXED_ECDH => "ecdsa_fixed_ecdh".to_string(),
            GOST_SIGN256 => "gost_sign256".to_string(),
            GOST_SIGN512 => "gost_sign512".to_string(),
            GOST_SIGN256_LEGACY => "gost_sign256 (the old 0xee)".to_string(),
            GOST_SIGN512_LEGACY => "gost_sign512 (the old 0xef)".to_string(),
            other => format!("unknown({})", other),
        }
    }
}

/// The TLS 1.2 CertificateRequest.
///
/// ```text
/// struct {
///     ClientCertificateType certificate_types<1..2^8-1>;
///     SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;
///     DistinguishedName certificate_authorities<0..2^16-1>;
/// } CertificateRequest;
/// ```
///
/// **Nothing like the 1.3 message**, which has no fields at all and puts
/// everything in extensions. The certificate types are the part with no
/// 1.3 equivalent: a client whose key is not of a listed type is being
/// told not to send that certificate, and a client that ignored the list
/// would sign with a key the server has already said it will not take.
///
/// `certificate_authorities` is advisory in both directions - a hint
/// about which issuers the server will recognise. It is parsed and
/// reported rather than enforced, because a client with one certificate
/// has nothing to choose between and a server that meant it will refuse
/// the chain anyway.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificateRequest12 {
    pub certificate_types: Vec<u8>,
    pub schemes: Vec<u16>,
    /// Each entry is one DER-encoded `DistinguishedName`.
    pub authorities: Vec<Vec<u8>>,
}

impl CertificateRequest12 {
    pub fn parse(body: &[u8]) -> Result<CertificateRequest12> {
        let mut reader = Reader::new(body);
        let certificate_types = reader.vector8()?.to_vec();
        if certificate_types.is_empty() {
            return Err(CodecError::decode(
                "A CertificateRequest with no certificate types accepts no \
                 certificate at all, which is not a request."));
        }
        let mut schemes = Vec::new();
        let mut list = reader.sub16()?;
        if list.is_empty() {
            // TLS 1.2 made the field mandatory (RFC 5246 7.4.4): a client
            // that guessed a scheme would sign something the server
            // cannot check. Empty is the 1.1 message with a 1.2 version
            // number on it.
            return Err(CodecError::decode(
                "A TLS 1.2 CertificateRequest with an empty \
                 supported_signature_algorithms."));
        }
        while !list.is_empty() {
            schemes.push(list.u16()?);
        }
        let mut authorities = Vec::new();
        let mut names = reader.sub16()?;
        while !names.is_empty() {
            authorities.push(names.vector16()?.to_vec());
        }
        reader.expect_empty("CertificateRequest")?;
        Ok(CertificateRequest12 { certificate_types, schemes, authorities })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.vector8(&self.certificate_types)?;
        let mut schemes = Writer::new();
        for scheme in &self.schemes {
            schemes.u16(*scheme);
        }
        writer.vector16(&schemes.finish())?;
        let mut names = Writer::new();
        for authority in &self.authorities {
            names.vector16(authority)?;
        }
        writer.vector16(&names.finish())?;
        Ok(writer.finish())
    }
}

/// The TLS 1.0 and 1.1 CertificateRequest.
///
/// ```text
/// struct {
///     ClientCertificateType certificate_types<1..2^8-1>;
///     DistinguishedName certificate_authorities<0..2^16-1>;
/// } CertificateRequest;
/// ```
///
/// **The 1.2 message with the middle field taken out.** TLS 1.2 added
/// `supported_signature_algorithms` (RFC 5246 7.4.4), and before it
/// there was nothing to negotiate: the construction is fixed by the
/// protocol version. A parser that read the 1.2 shape here takes the
/// first two bytes of the CA list for a signature-algorithm length, and
/// the failure is a decode error two fields later.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificateRequest10 {
    pub certificate_types: Vec<u8>,
    pub authorities: Vec<Vec<u8>>,
}

impl CertificateRequest10 {
    pub fn parse(body: &[u8]) -> Result<CertificateRequest10> {
        let mut reader = Reader::new(body);
        let certificate_types = reader.vector8()?.to_vec();
        if certificate_types.is_empty() {
            return Err(CodecError::decode(
                "A CertificateRequest with no certificate types accepts no \
                 certificate at all, which is not a request."));
        }
        let mut authorities = Vec::new();
        let mut names = reader.sub16()?;
        while !names.is_empty() {
            authorities.push(names.vector16()?.to_vec());
        }
        reader.expect_empty("CertificateRequest")?;
        Ok(CertificateRequest10 { certificate_types, authorities })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.vector8(&self.certificate_types)?;
        let mut names = Writer::new();
        for authority in &self.authorities {
            names.vector16(authority)?;
        }
        writer.vector16(&names.finish())?;
        Ok(writer.finish())
    }
}

/// The TLS 1.0 and 1.1 CertificateVerify body: **a bare signature**.
///
/// No algorithm field, because there is no algorithm to name: the
/// construction is fixed by the protocol version and by the key's type.
/// An RSA signature is over `MD5(handshake_messages) ||
/// SHA1(handshake_messages)` - 36 bytes - with **no DigestInfo** (RFC
/// 4346 7.4.3, which sends you to 7.4.8). A DSA or ECDSA one is over the
/// SHA-1 half alone.
///
/// A parser that read the 1.2 shape here takes the first two bytes of
/// the signature for a scheme, and then a length two bytes into it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificateVerify10 {
    pub signature: Vec<u8>,
}

impl CertificateVerify10 {
    pub fn parse(body: &[u8]) -> Result<CertificateVerify10> {
        let mut reader = Reader::new(body);
        let signature = reader.vector16()?.to_vec();
        reader.expect_empty("CertificateVerify")?;
        if signature.is_empty() {
            return Err(CodecError::decode(
                "CertificateVerify carries an empty signature."));
        }
        Ok(CertificateVerify10 { signature })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.vector16(&self.signature)?;
        Ok(writer.finish())
    }
}

/// The TLS 1.2 CertificateVerify body: a scheme and a signature.
///
/// **The signature is over `Hash(handshake_messages)`** - the raw
/// concatenation of everything sent and received so far, hashed with the
/// scheme's own hash (RFC 5246 7.4.8). TLS 1.3 signs a context string
/// and a transcript hash instead, and a signature made the 1.3 way
/// verifies against nothing while looking exactly like a wrong key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificateVerify12 {
    pub scheme: SignatureScheme,
    pub signature: Vec<u8>,
}

impl CertificateVerify12 {
    pub fn parse(body: &[u8]) -> Result<CertificateVerify12> {
        let mut reader = Reader::new(body);
        let scheme = SignatureScheme::from_u16(reader.u16()?);
        let signature = reader.vector16()?.to_vec();
        reader.expect_empty("CertificateVerify")?;
        if signature.is_empty() {
            return Err(CodecError::decode(
                "CertificateVerify carries an empty signature."));
        }
        Ok(CertificateVerify12 { scheme, signature })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        writer.u16(self.scheme.to_u16());
        writer.vector16(&self.signature)?;
        Ok(writer.finish())
    }
}

// --------------------------------------------------------- OCSP stapling ---
//
// Two wire shapes for one thing, and they are in different messages.
//
// The `status_request` extension is *three* different bodies depending on
// where it appears (RFC 6066 §8, RFC 8446 §4.4.2.1), which is the same
// trap `supported_versions` and `key_share` set and is handled the same
// way: one function per (extension, message) pair, and none takes a flag.
//
//   * in a ClientHello, a `CertificateStatusRequest`: a status type, a
//     list of responder IDs and a list of request extensions;
//   * in a TLS 1.2 ServerHello, **empty** - an acknowledgement, with the
//     response arriving later in its own `CertificateStatus` message;
//   * in a TLS 1.3 certificate entry, a whole `CertificateStatus` body,
//     because 1.3 has no separate message and the staple belongs to the
//     certificate it is about rather than to the connection.

/// The only status type RFC 6066 defines.
pub const OCSP_STATUS_TYPE: u8 = 1;

/// The client's `status_request`, asking for a stapled OCSP response.
///
/// Both lists are empty, which is what every client sends: a responder
/// ID list names responders the client already trusts, and request
/// extensions would carry a nonce - but a *stapled* response is cached
/// and shared between connections, so a nonce would defeat the point of
/// stapling rather than add freshness.
pub fn encode_status_request() -> Vec<u8> {
    let mut writer = crate::tls::codec::Writer::new();
    writer.u8(OCSP_STATUS_TYPE);
    writer.u16(0);                 // responder_id_list, empty
    writer.u16(0);                 // request_extensions, empty
    writer.finish()
}

/// A `CertificateStatus` body: the status type and the DER response.
///
/// This is the whole TLS 1.2 message and also the *body* of the 1.3
/// certificate entry's extension - the one place where the two versions
/// share bytes, which is why it is one function.
pub fn encode_certificate_status(response: &[u8]) -> Result<Vec<u8>> {
    let mut writer = crate::tls::codec::Writer::new();
    writer.u8(OCSP_STATUS_TYPE);
    writer.vector24(response)?;
    Ok(writer.finish())
}

/// Read a `CertificateStatus` body, returning the DER response.
///
/// A status type other than 1 is an error rather than something to
/// ignore: the field says how to read the rest, and there is no other
/// value defined. Reading past it would be guessing.
pub fn parse_certificate_status(body: &[u8]) -> core::result::Result<Vec<u8>, String> {
    let mut reader = crate::tls::codec::Reader::new(body);
    let kind = reader.u8().map_err(|e| e.to_string())?;
    if kind != OCSP_STATUS_TYPE {
        return Err(format!(
            "CertificateStatus has status type {}, and RFC 6066 defines only \
             1 (ocsp).", kind));
    }
    let response = reader.vector24().map_err(|e| e.to_string())?.to_vec();
    if response.is_empty() {
        // An empty response is not "no answer" - the server chose to send
        // this message, so an empty body is a malformed one. A server with
        // nothing to staple simply does not send it.
        return Err("CertificateStatus carries an empty OCSP response."
                   .to_string());
    }
    reader.expect_empty("CertificateStatus").map_err(|e| e.to_string())?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    /// The three wire shapes of `status_request` are three different
    /// bodies, and the trap is the same one `supported_versions` sets:
    /// a parser that read the ClientHello form where the server's
    /// belongs takes a status type for a length. These pin the two this
    /// file writes.
    #[test]
    fn test_the_status_request_shapes_are_distinct() {
        // In a ClientHello: type, then two empty lists.
        assert_eq!(encode_status_request(), vec![1, 0, 0, 0, 0]);

        // A CertificateStatus body: type, then a 24-bit length.
        let body = encode_certificate_status(&[0xaa, 0xbb]).unwrap();
        assert_eq!(body, vec![1, 0, 0, 2, 0xaa, 0xbb]);
        assert_eq!(parse_certificate_status(&body).unwrap(), vec![0xaa, 0xbb]);
    }

    /// The status type says how to read the rest and has exactly one
    /// defined value, so anything else is a guess rather than something
    /// to skip.
    #[test]
    fn test_an_unknown_status_type_is_refused() {
        let body = vec![2, 0, 0, 1, 0xaa];
        assert!(parse_certificate_status(&body).unwrap_err().contains("status type"));
    }

    /// A server with nothing to staple does not send the message, so an
    /// empty body is a malformed message rather than "no answer".
    #[test]
    fn test_an_empty_stapled_response_is_refused() {
        let body = vec![1, 0, 0, 0];
        assert!(parse_certificate_status(&body).unwrap_err().contains("empty"));
    }

    #[test]
    fn test_trailing_bytes_after_a_stapled_response_are_refused() {
        let mut body = encode_certificate_status(&[0xaa]).unwrap();
        body.push(0x00);
        assert!(parse_certificate_status(&body).is_err());
    }

    use super::*;

    fn sample_client_hello() -> ClientHello {
        ClientHello {
            legacy_version: Version::TLS12,
            random: [7u8; 32],
            session_id: vec![1, 2, 3, 4],
            cipher_suites: vec![0xc02f, 0x002f, 0x0005],
            compression_methods: vec![0],
            extensions: vec![
                Extension { kind: extension::SERVER_NAME,
                            body: server_name_extension("example.test") },
                Extension { kind: extension::SUPPORTED_GROUPS,
                            body: vec![0, 4, 0, 23, 0, 24] },
            ],
        }
    }

    fn server_name_extension(name: &str) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.nested16(|list| {
            list.u8(0);                       // host_name
            list.vector16(name.as_bytes())
        }).unwrap();
        writer.finish()
    }

    #[test]
    fn test_client_hello_round_trip() {
        let hello = sample_client_hello();
        let encoded = hello.encode().unwrap();
        assert_eq!(ClientHello::parse(&encoded).unwrap(), hello);
        assert_eq!(hello.server_name().unwrap(), "example.test");
    }

    #[test]
    fn test_server_hello_round_trip() {
        let hello = ServerHello {
            legacy_version: Version::TLS12,
            random: [9u8; 32],
            session_id: vec![],
            cipher_suite: 0xc02f,
            compression_method: 0,
            extensions: vec![Extension { kind: extension::RENEGOTIATION_INFO,
                                         body: vec![0] }],
        };
        let encoded = hello.encode().unwrap();
        assert_eq!(ServerHello::parse(&encoded).unwrap(), hello);
        assert_eq!(hello.negotiated_version(), Version::TLS12);
    }

    /// A TLS 1.3 ServerHello says 1.2 in the version field and puts the real
    /// answer in an extension. Reading only the legacy field means silently
    /// treating a 1.3 connection as 1.2.
    #[test]
    fn test_tls13_hides_its_version_in_an_extension() {
        let hello = ServerHello {
            legacy_version: Version::TLS12,
            random: [0u8; 32],
            session_id: vec![],
            cipher_suite: 0x1302,
            compression_method: 0,
            extensions: vec![Extension { kind: extension::SUPPORTED_VERSIONS,
                                         body: vec![3, 4] }],
        };
        assert_eq!(hello.legacy_version, Version::TLS12);
        assert_eq!(hello.negotiated_version(), Version::TLS13);
    }

    #[test]
    fn test_hellos_reject_nonsense() {
        // No cipher suites at all.
        let mut hello = sample_client_hello();
        hello.cipher_suites = vec![];
        let encoded = hello.encode().unwrap();
        assert!(ClientHello::parse(&encoded).is_err());

        // No compression methods.
        let mut hello = sample_client_hello();
        hello.compression_methods = vec![];
        let encoded = hello.encode().unwrap();
        assert!(ClientHello::parse(&encoded).is_err());

        // A session id longer than 32 bytes, written by hand since encode
        // would not produce one.
        let mut writer = Writer::new();
        writer.raw(&Version::TLS12.to_bytes());
        writer.raw(&[0u8; 32]);
        writer.vector8(&[0u8; 64]).unwrap();
        writer.u16_list(&[0x002f]).unwrap();
        writer.vector8(&[0]).unwrap();
        assert!(ClientHello::parse(&writer.finish()).is_err());

        // Trailing bytes after the extensions.
        let mut encoded = sample_client_hello().encode().unwrap();
        encoded.push(0);
        assert!(ClientHello::parse(&encoded).is_err());
    }

    /// A repeated extension raises the question of which one is honoured,
    /// which is exactly the kind of ambiguity an attacker looks for.
    #[test]
    fn test_duplicate_extensions_are_refused() {
        let mut writer = Writer::new();
        writer.raw(&Version::TLS12.to_bytes());
        writer.raw(&[0u8; 32]);
        writer.vector8(&[]).unwrap();
        writer.u16_list(&[0x002f]).unwrap();
        writer.vector8(&[0]).unwrap();
        writer.nested16(|block| {
            block.u16(extension::SERVER_NAME);
            block.vector16(&server_name_extension("one.test"))?;
            block.u16(extension::SERVER_NAME);
            block.vector16(&server_name_extension("two.test"))
        }).unwrap();

        let error = ClientHello::parse(&writer.finish()).unwrap_err();
        assert!(error.detail.contains("more than once"), "{}", error.detail);
    }

    #[test]
    fn test_certificate_chain_round_trip() {
        let chain = CertificateChain {
            certificates: vec![vec![1u8; 100], vec![2u8; 500], vec![3u8; 1]],
        };
        let encoded = chain.encode().unwrap();
        assert_eq!(CertificateChain::parse(&encoded).unwrap(), chain);

        // An empty chain encodes and parses; whether it is legal depends on
        // who sent it, which is the state machine's question.
        let empty = CertificateChain::default();
        assert_eq!(CertificateChain::parse(&empty.encode().unwrap()).unwrap(), empty);
    }

    // ----------------------------------------------------- reassembly ---

    /// One record can hold several messages, and one message can span
    /// several records. An implementation that assumes one message per
    /// record works against most peers and then fails against one that
    /// coalesces.
    #[test]
    fn test_messages_and_records_do_not_line_up() {
        let one = HandshakeMessage::new(HandshakeType::ServerHello,
                                        vec![1u8; 50]).unwrap();
        let two = HandshakeMessage::new(HandshakeType::Certificate,
                                        vec![2u8; 3000]).unwrap();
        let three = HandshakeMessage::new(HandshakeType::ServerHelloDone,
                                          vec![]).unwrap();

        let mut stream = Vec::new();
        stream.extend_from_slice(&one.raw);
        stream.extend_from_slice(&two.raw);
        stream.extend_from_slice(&three.raw);

        // Delivered in every awkward split, the same three messages must
        // come out.
        for chunk_size in [1usize, 2, 3, 4, 5, 16, 100, 1000, stream.len()] {
            let mut reader = HandshakeReader::new();
            let mut messages = Vec::new();
            for chunk in stream.chunks(chunk_size) {
                reader.push(chunk);
                while let Some(message) = reader.next_message().unwrap() {
                    messages.push(message);
                }
            }
            assert_eq!(messages, vec![one.clone(), two.clone(), three.clone()],
                       "chunk size {}", chunk_size);
            assert!(!reader.has_partial_message());
        }
    }

    /// The raw bytes must be exactly what arrived, because the transcript
    /// hash is computed over them and the Finished message covers it.
    #[test]
    fn test_raw_bytes_are_preserved() {
        let body = vec![0xabu8; 20];
        let message = HandshakeMessage::new(HandshakeType::Finished,
                                            body.clone()).unwrap();
        assert_eq!(message.raw[0], 20);                    // finished
        assert_eq!(&message.raw[1..4], &[0, 0, 20]);       // 24 bit length
        assert_eq!(&message.raw[4..], &body[..]);

        let mut reader = HandshakeReader::new();
        reader.push(&message.raw);
        let read = reader.next_message().unwrap().unwrap();
        assert_eq!(read.raw, message.raw);
        assert_eq!(read.body, body);
    }

    /// The length is 24 bits, so a peer can claim 16MB before anything has
    /// been authenticated. The check must happen before the body is waited
    /// for.
    #[test]
    fn test_an_absurd_length_is_refused_immediately() {
        let mut reader = HandshakeReader::new();
        reader.push(&[11, 0xff, 0xff, 0xff]);      // certificate, 16MB
        let error = reader.next_message().unwrap_err();
        assert_eq!(error.alert, AlertDescription::RECORD_OVERFLOW);
        // And it did not start buffering for it.
        assert_eq!(reader.buffered(), 4);
    }

    #[test]
    fn test_a_partial_message_is_visible() {
        let message = HandshakeMessage::new(HandshakeType::ClientHello,
                                            vec![0u8; 100]).unwrap();
        let mut reader = HandshakeReader::new();
        reader.push(&message.raw[..50]);
        assert!(reader.next_message().unwrap().is_none());
        // A ChangeCipherSpec arriving now would be a peer interleaving
        // things it should not, and the state machine needs to see that.
        assert!(reader.has_partial_message());

        reader.push(&message.raw[50..]);
        assert!(reader.next_message().unwrap().is_some());
        assert!(!reader.has_partial_message());
    }

    #[test]
    fn test_handshake_types_round_trip() {
        for byte in 0u8..=255 {
            assert_eq!(HandshakeType::from_byte(byte).to_byte(), byte);
        }
        assert_eq!(HandshakeType::from_byte(1), HandshakeType::ClientHello);
        assert_eq!(HandshakeType::from_byte(200), HandshakeType::Unknown(200));
    }

    #[test]
    fn test_signature_schemes() {
        for (scheme, name) in [
            (SignatureScheme::RSA_PKCS1_SHA256, "rsa_sha256"),
            (SignatureScheme::ECDSA_SHA384, "ecdsa_sha384"),
            (SignatureScheme::RSA_PKCS1_SHA1, "rsa_sha1"),
        ] {
            assert_eq!(scheme.name(), name);
            assert_eq!(SignatureScheme::from_u16(scheme.to_u16()), scheme);
        }
        assert_eq!(SignatureScheme::RSA_PKCS1_SHA256.to_u16(), 0x0401);
        assert_eq!(SignatureScheme::ECDSA_SHA256.to_u16(), 0x0403);
        assert!(SignatureScheme::from_u16(0x0801).hash_name().is_none());
    }

    /// Truncating a message at every offset must be an error, never a panic
    /// and never a message that was not there.
    #[test]
    fn test_no_truncation_panics() {
        let encoded = sample_client_hello().encode().unwrap();
        for cut in 0..encoded.len() {
            let _ = ClientHello::parse(&encoded[..cut]);
        }
        for index in 0..encoded.len() {
            let mut corrupt = encoded.clone();
            corrupt[index] ^= 0xff;
            let _ = ClientHello::parse(&corrupt);
        }
    }

    // ------------------------------------------------- ServerKeyExchange ---

    /// A named-curve ECDHE ServerKeyExchange: curve_type=3, secp256r1, an
    /// uncompressed point, rsa_sha256, and a signature.
    fn sample_server_key_exchange() -> Vec<u8> {
        let mut body = vec![3, 0x00, 0x17];         // named_curve, secp256r1
        let point: Vec<u8> = core::iter::once(0x04)
            .chain((0u8..64).map(|i| i.wrapping_mul(7).wrapping_add(1)))
            .collect();
        body.push(point.len() as u8);
        body.extend_from_slice(&point);
        body.extend_from_slice(&[0x04, 0x01]);      // rsa_pkcs1_sha256
        body.extend_from_slice(&[0x00, 0x04]);
        body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        body
    }

    #[test]
    fn test_server_key_exchange_round_trip() {
        let body = sample_server_key_exchange();
        let params = ServerEcdhParams::parse(&body, Version::TLS12).unwrap();
        assert_eq!(params.group, groups::SECP256R1);
        assert_eq!(params.point.len(), 65);
        assert_eq!(params.point[0], 0x04);
        assert_eq!(params.scheme, Some(SignatureScheme::RSA_PKCS1_SHA256));
        assert_eq!(params.signature, vec![0xde, 0xad, 0xbe, 0xef]);

        // The signature input is the curve and point as they arrived, and
        // stops before the algorithm. Getting this boundary wrong makes
        // every ECDHE signature fail to verify, with nothing to say why.
        assert_eq!(params.raw_params, body[..3 + 1 + 65]);

        let signed = params.signed_bytes(&[0xaa; 32], &[0xbb; 32]);
        assert_eq!(&signed[..32], &[0xaa; 32]);
        assert_eq!(&signed[32..64], &[0xbb; 32]);
        assert_eq!(&signed[64..], &params.raw_params[..]);
    }

    /// Explicit curve parameters let the server pick the group the shared
    /// secret lives in, which is the invalid-curve attack handed over
    /// voluntarily. RFC 8422 deprecates them; we refuse them.
    #[test]
    fn test_explicit_curve_parameters_are_refused() {
        for curve_type in [0u8, 1, 2, 4, 255] {
            let mut body = sample_server_key_exchange();
            body[0] = curve_type;
            let error = ServerEcdhParams::parse(&body, Version::TLS12)
                .expect_err("curve type must be named_curve");
            assert!(format!("{:?}", error).contains("named curves"),
                    "curve_type {}: {:?}", curve_type, error);
        }
    }

    /// Before TLS 1.2 there is no SignatureAndHashAlgorithm. Reading one
    /// anyway eats the first two bytes of the signature length, which turns
    /// into a length error rather than anything that says what happened -
    /// so the version has to be threaded through the parse.
    #[test]
    fn test_the_algorithm_field_is_tls12_only() {
        let mut body = vec![3, 0x00, 0x17, 4, 0x04, 1, 2, 3];
        body.extend_from_slice(&[0x00, 0x02, 0x11, 0x22]);   // signature
        let params = ServerEcdhParams::parse(&body, Version::TLS11).unwrap();
        assert_eq!(params.scheme, None);
        assert_eq!(params.signature, vec![0x11, 0x22]);

        // The same bytes read as TLS 1.2 consume two of them as the
        // algorithm and then find a signature that does not fit.
        assert!(ServerEcdhParams::parse(&body, Version::TLS12).is_err());
    }

    #[test]
    fn test_an_empty_point_is_refused() {
        let body = vec![3, 0x00, 0x17, 0, 0x04, 0x01, 0x00, 0x01, 0xff];
        assert!(ServerEcdhParams::parse(&body, Version::TLS12).is_err());
    }

    /// Trailing bytes are refused rather than ignored: a parser that stops
    /// early lets a peer append whatever it likes to a signed message.
    #[test]
    fn test_trailing_bytes_are_refused() {
        let mut body = sample_server_key_exchange();
        body.push(0x00);
        assert!(ServerEcdhParams::parse(&body, Version::TLS12).is_err());
    }

    /// A finite-field DHE ServerKeyExchange: three vectors, then the
    /// signature tail.
    fn sample_dh_key_exchange() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x00, 0x08]);      // p
        body.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb]);
        body.extend_from_slice(&[0x00, 0x01, 0x02]); // g
        body.extend_from_slice(&[0x00, 0x08]);      // Ys
        body.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        body.extend_from_slice(&[0x04, 0x01]);      // rsa_pkcs1_sha256
        body.extend_from_slice(&[0x00, 0x04]);
        body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        body
    }

    #[test]
    fn test_dh_key_exchange_round_trip() {
        let body = sample_dh_key_exchange();
        let params = ServerDhParams::parse(&body, Version::TLS12).unwrap();
        assert_eq!(params.p.len(), 8);
        assert_eq!(params.g, vec![0x02]);
        assert_eq!(params.public.len(), 8);
        assert_eq!(params.scheme, Some(SignatureScheme::RSA_PKCS1_SHA256));
        assert_eq!(params.signature, vec![0xde, 0xad, 0xbe, 0xef]);

        // The signature covers all three vectors *including* their length
        // prefixes, and stops before the algorithm. Same boundary trap as
        // the elliptic curve version.
        assert_eq!(params.raw_params, body[..2 + 8 + 2 + 1 + 2 + 8]);

        let signed = params.signed_bytes(&[0xaa; 32], &[0xbb; 32]);
        assert_eq!(&signed[..32], &[0xaa; 32]);
        assert_eq!(&signed[32..64], &[0xbb; 32]);
        assert_eq!(&signed[64..], &params.raw_params[..]);
    }

    /// The same pre-TLS-1.2 trap as the curve version: there is no
    /// SignatureAndHashAlgorithm before 1.2, and reading one eats the
    /// signature's length.
    #[test]
    fn test_the_dh_algorithm_field_is_tls12_only() {
        let mut body = sample_dh_key_exchange();
        body.drain((body.len() - 8)..(body.len() - 6));   // drop the algorithm
        let params = ServerDhParams::parse(&body, Version::TLS10).unwrap();
        assert_eq!(params.scheme, None);
        assert_eq!(params.signature, vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(ServerDhParams::parse(&body, Version::TLS12).is_err());
    }

    #[test]
    fn test_an_empty_dh_value_is_refused() {
        // Each of the three vectors, emptied in turn. An empty prime or
        // generator is a group with nothing in it; an empty public value
        // is zero, which is the degenerate case the DH module refuses
        // later - but it should not get that far.
        for empty in 0..3 {
            let mut body = Vec::new();
            for which in 0..3 {
                if which == empty {
                    body.extend_from_slice(&[0x00, 0x00]);
                } else {
                    body.extend_from_slice(&[0x00, 0x02, 0x01, 0x03]);
                }
            }
            body.extend_from_slice(&[0x04, 0x01, 0x00, 0x01, 0xff]);
            assert!(ServerDhParams::parse(&body, Version::TLS12).is_err(),
                    "empty vector {} was accepted", empty);
        }
    }

    #[test]
    fn test_dh_key_exchange_never_panics() {
        let body = sample_dh_key_exchange();
        for cut in 0..body.len() {
            let _ = ServerDhParams::parse(&body[..cut], Version::TLS12);
            let _ = ServerDhParams::parse(&body[..cut], Version::TLS10);
        }
        for index in 0..body.len() {
            let mut corrupt = body.clone();
            corrupt[index] ^= 0xff;
            let _ = ServerDhParams::parse(&corrupt, Version::TLS12);
        }
    }

    #[test]
    fn test_server_key_exchange_never_panics() {
        let body = sample_server_key_exchange();
        for cut in 0..body.len() {
            let _ = ServerEcdhParams::parse(&body[..cut], Version::TLS12);
            let _ = ServerEcdhParams::parse(&body[..cut], Version::TLS11);
        }
        for index in 0..body.len() {
            let mut corrupt = body.clone();
            corrupt[index] ^= 0xff;
            let _ = ServerEcdhParams::parse(&corrupt, Version::TLS12);
        }
    }

    #[test]
    fn test_group_names() {
        assert_eq!(groups::curve_name(groups::SECP256R1), Some("P-256"));
        assert_eq!(groups::curve_name(groups::SECP384R1), Some("P-384"));
        // Offered by everyone, implemented by us as a curve we do not have:
        // it must report absence rather than a wrong curve.
        assert_eq!(groups::curve_name(groups::X25519), None);
        assert_eq!(groups::curve_name(0xffff), None);
    }
}
