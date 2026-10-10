/*
The TLS client: the state machine, and a complete handshake.

Sans-I/O, like everything else here. Bytes in through `push_incoming`,
bytes out through `take_outgoing`, and whoever owns the connection does the
reading and writing. Nothing in this file knows what a socket is.

**The state machine rejects by default.** Each state names what it will
accept and everything else is `unexpected_message`. That is not tidiness:
accepting a handshake message in the wrong state is exactly how FREAK,
SMACK and Logjam worked - a ServerKeyExchange arriving where none was
expected, a message skipped, a state entered twice. A machine that asks
"is this allowed here?" and defaults to no cannot have those bugs; one that
asks "do I know what to do with this?" can.

The order the checks happen in matters too. The certificate is verified
before its key is used for anything. The server's Finished is checked
before the connection is considered established. There is no path here
where a failure becomes a warning.

What is implemented: SSLv3 through TLS 1.3, every key exchange this
library has, and the whole ciphersuite registry down to the export-grade
ones. The default ceiling is 1.3 and the default floor is 1.2; reaching
below that is `ClientConfig::legacy`, and reaching SSLv3 means naming it.

**There are two state machines in here, and they do not share states.**
TLS 1.3 renegotiated almost everything: the keys change at the
ServerHello rather than at a ChangeCipherSpec, the server's flight
arrives encrypted, the certificate has a different shape, and there is a
CertificateVerify every time rather than only when there is a key
exchange to sign. Giving the two a shared state would give it a state
that accepts messages from both, which is the exact thing this machine is
built not to do. So `State` has `WaitCertificate` and
`WaitCertificate13`, and the dispatch table names each pair once.

TLS 1.3 resumption is here: a `NewSessionTicket` becomes a `Ticket` the
caller keeps, and `ClientConfig::tickets` offers them back. The binder
is the part to be careful with - see `resumption.rs`, and note that
**the client's own Finished goes into the transcript** because the
resumption master secret is over a transcript one message longer than
the application keys'.

Not done in 1.3: 0-RTT and post-handshake authentication. Each of those
is an explicit error naming itself rather than a message quietly
ignored.
*/

use crate::api::AnyHash;
use crate::ec::curves;
use crate::hash_functions::HashFunction;
use crate::bignum::BigUint;
use crate::publickey_ciphers::{dh, rsa};
use crate::tls::codec::{CodecError, Writer};
use crate::tls::handshake::{extension, find_extension, groups, CertificateChain,
                            ClientHello, Extension, Finished, HandshakeMessage,
                            HandshakeReader, HandshakeType, ServerDhParams,
                            ServerEcdhParams, ServerHello, ServerRsaParams,
                            SignatureScheme};
use crate::tls::handshake13::{self as hs13, scheme, Certificate13, CertificateVerify,
                              EncryptedExtensions, KeyShareEntry, Side13};
use crate::tls::keys::{self, Side, Transcript};
use crate::tls::keys13::{self, Schedule};
use crate::tls::record::{Protection, RecordError, RecordReader, RecordWriter};
use crate::tls::kex::EphemeralKey;
use crate::tls::record13::Aead13;
use crate::tls::resumption::{self, Offer, Ticket};
use crate::tls::suites::{self, CipherSuite, KeyExchange, Selection};
use crate::tls::{Alert, AlertDescription, AlertLevel, ContentType, Version};
use crate::trust::TrustStore;
use crate::x509::verify::{Policy, Purpose};
use crate::x509::{Certificate, PublicKey};

// ------------------------------------------------------------------ errors ---

/// A failure, with the alert the peer should be told about.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Error {
    pub alert: Option<AlertDescription>,
    pub detail: String,
}

impl Error {
    pub(crate) fn new(alert: AlertDescription, detail: impl Into<String>) -> Error {
        Error { alert: Some(alert), detail: detail.into() }
    }

    /// A failure that is ours, not the peer's - nothing to send.
    pub(crate) fn local(detail: impl Into<String>) -> Error {
        Error { alert: None, detail: detail.into() }
    }

    fn unexpected(state: &str, what: &str) -> Error {
        Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                   format!("Received {} while {}.", what, state))
    }

    pub fn describe(&self) -> String {
        match self.alert {
            Some(alert) => format!("{}: {}", alert.name(), self.detail),
            None => self.detail.clone(),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.describe())
    }
}

impl From<Error> for String {
    fn from(error: Error) -> String {
        error.describe()
    }
}

impl From<RecordError> for Error {
    fn from(error: RecordError) -> Error {
        Error { alert: Some(error.alert), detail: error.detail }
    }
}

impl From<CodecError> for Error {
    fn from(error: CodecError) -> Error {
        Error { alert: Some(error.alert), detail: error.detail }
    }
}

// ------------------------------------------------------------------ config ---

/// What the client will do.
/// A certificate and key this client will authenticate with, when a server
/// asks.
///
/// Holding the key here rather than taking a callback is deliberate: a
/// callback would be invoked in the middle of a handshake, and whatever it
/// touched would be running at a moment the caller cannot reason about.
pub struct ClientIdentity {
    /// Leaf first, DER, the same shape a server's chain has.
    pub chain: Vec<Vec<u8>>,
    pub key: ClientKey,
}

/// The private half of a [`ClientIdentity`].
///
/// The same shape as the server's `ServerKey` and separate from it, because
/// a client key signs and never decrypts - there is no RSA key transport in
/// this direction at any version.
pub enum ClientKey {
    Rsa(Box<crate::publickey_ciphers::rsa::RsaPrivateKey>),
    Ec { curve: &'static str, private: BigUint },
    /// A GOST R 34.10-2012 key, for a TLS **1.3** client certificate.
    ///
    /// 1.3 only, and not for lack of a codepoint: RFC 9189 defines
    /// `gostr34102012_256` and `_512` for 1.2's `signature_algorithms`,
    /// but a 1.2 CertificateVerify signs
    /// `Hash(handshake_messages)` under a hash the *message* names, and
    /// the GOST pair carries no hash byte - it is `(8, 64)`, "Intrinsic",
    /// because the algorithm names its own digest. That is a third
    /// construction rather than a variant of the 1.2 one, so it is left
    /// unbuilt and refused rather than guessed at.
    Gost { curve: &'static str, private: BigUint },
    /// An ML-DSA key, for a TLS **1.3** client certificate:
    /// draft-ietf-tls-mldsa forbids its schemes at 1.2.
    MlDsa(std::sync::Arc<crate::api::MlDsaKey>),
    /// An Ed25519 or Ed448 key, for TLS 1.2 and 1.3. `seed` is the RFC
    /// 8032 private key, 32 or 57 bytes. Not before 1.2: the 1.0 and 1.1
    /// CertificateVerify is a signature over `MD5 || SHA1`, which RFC 8422
    /// does not define for EdDSA.
    Eddsa { name: &'static str, seed: Vec<u8> },
}

impl ClientIdentity {
    /// The schemes this key can sign a TLS 1.3 CertificateVerify with, in
    /// preference order.
    ///
    /// RSA is PSS only - RFC 8446 4.4.3 forbids the `rsa_pkcs1_*`
    /// codepoints here - and an EC key can only use the scheme that names
    /// its own curve.
    pub fn schemes(&self) -> Vec<u16> {
        match &self.key {
            ClientKey::Rsa(_) => vec![scheme::RSA_PSS_RSAE_SHA256,
                                      scheme::RSA_PSS_RSAE_SHA384,
                                      scheme::RSA_PSS_RSAE_SHA512],
            ClientKey::Ec { curve, .. } => match *curve {
                "P-256" => vec![scheme::ECDSA_SECP256R1_SHA256],
                "P-384" => vec![scheme::ECDSA_SECP384R1_SHA384],
                "P-521" => vec![scheme::ECDSA_SECP521R1_SHA512],
                _ => Vec::new(),
            },
            // One scheme, bound to the curve by RFC 9367 section 5.2. A
            // curve that section does not cover gets an empty list, and
            // the caller declines to send a certificate rather than
            // signing with something the server cannot check.
            ClientKey::Gost { curve, .. } => match scheme::gost_13_for_curve(curve) {
                Some(scheme) => vec![scheme],
                None => Vec::new(),
            },
            ClientKey::MlDsa(key) => scheme::ml_dsa_for_parameter_set(key.parameter_set())
                .into_iter().collect(),
            ClientKey::Eddsa { name, .. } => eddsa_scheme(name).into_iter().collect(),
        }
    }

    /// Sign the CertificateVerify content with the chosen scheme.
    pub fn sign(&self, chosen: u16, content: &[u8]) -> Result<Vec<u8>, String> {
        // ML-DSA signs `content` itself, with FIPS 204's empty context;
        // there is no digest to take first.
        if let ClientKey::MlDsa(key) = &self.key {
            if scheme::ml_dsa_parameter_set(chosen) != Some(key.parameter_set()) {
                return Err(format!("Asked to sign with {} using an {} key.",
                                   scheme::name(chosen), key.parameter_set()));
            }
            return key.sign(content, &[], None);
        }
        // EdDSA likewise signs `content` itself; Ed448's context is empty
        // (RFC 8446 4.4.3 and RFC 8422 5.10 give it none). The same call
        // serves 1.2, where `content` is the handshake concatenation.
        if let ClientKey::Eddsa { name, seed } = &self.key {
            if eddsa_scheme(name) != Some(chosen) {
                return Err(format!("Asked to sign with {} using an {} key.",
                                   scheme::name(chosen), name));
            }
            return crate::api::eddsa_sign(name, seed, content, &[]);
        }
        let hash_name = scheme::hash_name(chosen)
            .ok_or_else(|| format!("No hash for {}.", scheme::name(chosen)))?;
        let mut hasher = AnyHash::new(hash_name)?;
        hasher.update(content);
        let digest = hasher.digest();

        match &self.key {
            ClientKey::Rsa(key) => {
                let salt = rsa::pss_salt_len(hash_name)?;
                rsa::sign_pss(key, hash_name, &digest, salt)
            }
            ClientKey::Ec { curve, private } => {
                let handle = curves::by_name(curve)?;
                let signature = handle.sign(private, &digest, AnyHash::new(hash_name)?)?;
                Ok(crate::x509::verify::encode_ecdsa_der(&signature))
            }
            // `hash_name` already answered `streebog256` or `streebog512`
            // by the scheme, and `gost_signature_bytes_13` writes RFC
            // 9367 section 5.3's `str_l(r) | str_l(s)` - the components
            // in the opposite order from a certificate's and each
            // reversed. Both are pinned to the document's worked example
            // in `tests/test_rfc9367_flight.rs`.
            ClientKey::Gost { curve, private } => {
                let handle = curves::by_name(curve)?;
                let signature = handle.gost_sign(private, &digest,
                                                 AnyHash::new(hash_name)?)?;
                handle.gost_signature_bytes_13(&signature)
            }
            ClientKey::MlDsa(_) | ClientKey::Eddsa { .. } =>
                unreachable!("ML-DSA and EdDSA return before the digest"),
        }
    }

    /// Sign a **TLS 1.0 or 1.1** CertificateVerify.
    ///
    /// `digest` is the transcript hash at those versions, which is
    /// already `MD5(handshake_messages) || SHA1(handshake_messages)`.
    ///
    /// A third routine rather than a third flag, because a third thing
    /// differs: an RSA signature here has **no DigestInfo** - there is no
    /// algorithm to identify, since the version fixes the pair - and an
    /// ECDSA one covers the **SHA-1 half alone**. Signing the whole 36
    /// bytes with ECDSA truncates them to the group's width and produces
    /// a signature over something nobody will check.
    pub fn sign_certificate_verify_10(&self, digest: &[u8])
                                      -> Result<Vec<u8>, String> {
        if digest.len() != 36 {
            return Err(format!(
                "A pre-1.2 CertificateVerify covers 36 bytes of MD5 and \
                 SHA-1; got {}.", digest.len()));
        }
        match &self.key {
            ClientKey::Rsa(key) => rsa::sign_pkcs1v15_raw(key, digest),
            // No GOST client certificate before 1.2: the digest here is
            // `MD5 || SHA1`, which GOST R 34.10 has nothing to do with,
            // and the 2001 suite's own construction is a fourth thing
            // again. Refused rather than signed over 36 bytes that mean
            // nothing to it.
            ClientKey::MlDsa(_) => Err(
                "An ML-DSA client certificate is TLS 1.3 only.".to_string()),
            ClientKey::Eddsa { .. } => Err(
                "An EdDSA client certificate needs TLS 1.2 or later.".to_string()),
            ClientKey::Gost { .. } => Err(
                "A GOST client certificate is built for TLS 1.3 only. At 1.0 \
                 and 1.1 the CertificateVerify is over MD5 || SHA1, which \
                 GOST R 34.10 does not sign.".to_string()),
            ClientKey::Ec { curve, private } => {
                let handle = curves::by_name(curve)?;
                let signature = handle.sign(private, &digest[16..],
                                            AnyHash::new("sha1")?)?;
                Ok(crate::x509::verify::encode_ecdsa_der(&signature))
            }
        }
    }

    /// Sign an already computed digest for a **TLS 1.2**
    /// CertificateVerify.
    ///
    /// A separate routine rather than a flag on `sign`, because two
    /// things differ and both are silent when wrong. The RSA padding is
    /// **PKCS#1 v1.5**, not PSS: RFC 8446 4.4.3 forbids the
    /// `rsa_pkcs1_*` codepoints at 1.3 and 1.2 expects nothing else. And
    /// the caller hands over a digest rather than the content, because
    /// at 1.2 the content is the whole handshake concatenation and the
    /// caller already has to hash it to know how long it is.
    pub fn sign_digest_12(&self, scheme: u16, hash_name: &str, digest: &[u8])
                          -> Result<Vec<u8>, String> {
        let _ = scheme;
        match &self.key {
            ClientKey::Rsa(key) => rsa::sign_pkcs1v15(key, hash_name, digest),
            // **Not built, and not for lack of a codepoint.** RFC 9189
            // assigns `gostr34102012_256` and `_512` for 1.2, and section
            // 7 assigns client certificate types 67 and 68 - but the pair
            // carries no hash byte (it is `(8, 64)`, "Intrinsic", because
            // the algorithm names its own digest), so `hash_name` has
            // nothing to answer and the 1.2 construction is a third one
            // rather than a variant. Left for whoever meets a box that
            // asks, with the codepoints already here for them.
            ClientKey::MlDsa(_) => Err(
                "An ML-DSA client certificate is TLS 1.3 only \
                 (draft-ietf-tls-mldsa section 3.2).".to_string()),
            // EdDSA signs the handshake messages, not a digest of them;
            // the caller sends it through `sign` instead.
            ClientKey::Eddsa { .. } => Err(
                "An EdDSA CertificateVerify signs the messages, not a \
                 digest; use `sign`.".to_string()),
            ClientKey::Gost { .. } => Err(
                "A GOST client certificate is built for TLS 1.3 only; the \
                 1.2 CertificateVerify construction for RFC 9189's schemes \
                 is not implemented.".to_string()),
            ClientKey::Ec { curve, private } => {
                let handle = curves::by_name(curve)?;
                let signature = handle.sign(private, digest,
                                            AnyHash::new(hash_name)?)?;
                Ok(crate::x509::verify::encode_ecdsa_der(&signature))
            }
        }
    }
}

/// The one scheme an EdDSA key signs with.
fn eddsa_scheme(name: &str) -> Option<u16> {
    match name {
        "ed25519" => Some(scheme::ED25519),
        "ed448" => Some(scheme::ED448),
        _ => None,
    }
}

pub struct ClientConfig {
    /// What to present when a server asks for a client certificate.
    ///
    /// `None` answers an ask with an **empty** Certificate, which is legal
    /// (RFC 8446 4.4.2.1) and lets the server decide. Silence is not an
    /// option: the server would wait for a message that never comes.
    pub client_certificate: Option<ClientIdentity>,
    /// Data to send as TLS 1.3 early data (0-RTT), before the handshake
    /// completes. Empty - the default - offers none.
    ///
    /// It goes only when a ticket in `tickets` was issued by this host
    /// *and* carries a `max_early_data` big enough, and only if the
    /// server then accepts. So a caller sets this and afterwards asks
    /// `early_data_accepted`; when that is false the same bytes have to
    /// be written again once the connection is up. **They are not
    /// resent automatically**, because whether sending them twice is
    /// acceptable is the caller's decision and always was.
    ///
    /// Two things are true of these bytes and of nothing else on the
    /// connection. They are **not forward secret**: they are encrypted
    /// under a key derived from a PSK that has been sitting in storage,
    /// so whoever later obtains that reads them. And they are
    /// **replayable**: they are sent before the server has said a word,
    /// so a captured copy of the flight is as valid the second time.
    /// Put in them only what may happen twice.
    pub early_data: Vec<u8>,
    /// The application protocols to offer (RFC 7301), in the client's
    /// order of preference. Empty - the default - sends no extension.
    ///
    /// The *server* chooses, and it may choose against this order; the
    /// order is a preference, not an instruction. What the client does
    /// enforce is that the answer is one of these, because a protocol
    /// nobody offered is a server answering a question that was not
    /// asked.
    pub alpn: Vec<String>,
    /// Ask the server to staple an OCSP response (RFC 6066 §8). On by
    /// default: it costs one extension and the server either has one or
    /// does not.
    ///
    /// A stapled response that says **revoked** fails the handshake
    /// whatever else is configured, because that is an answer. One that
    /// settles nothing - absent, unreadable, about another certificate -
    /// is reported through `stapled_ocsp` and costs nothing unless
    /// `require_stapled_ocsp` says otherwise.
    pub request_stapled_ocsp: bool,
    /// Refuse a connection whose revocation status a staple did not
    /// settle.
    ///
    /// **Separate from `policy.require_revocation`, which is about
    /// CRLs.** They are two different questions with two different
    /// answers: nothing here fetches a CRL, so
    /// `policy.require_revocation` fails every chain unless the caller
    /// supplies one, while this one is satisfied by a response the
    /// server stapled. Folding them together would mean turning on
    /// stapling enforcement refused every connection for want of a CRL,
    /// which is what happened the first time this was written.
    ///
    /// Off by default: most servers staple nothing, and hard-failing
    /// would refuse most of the web.
    pub require_stapled_ocsp: bool,
    /// Which cipher suites to offer. The default offers nothing broken.
    pub suites: Selection,
    /// The roots to verify against. There is no default: a client with no
    /// roots verifies nothing, and that must be a decision rather than an
    /// oversight.
    pub roots: TrustStore,
    /// Certificate policy - validity window, weak hash acceptance, minimum
    /// RSA size.
    pub policy: Policy,
    /// The highest version to offer.
    pub max_version: Version,
    /// The lowest version to accept.
    pub min_version: Version,
    /// Check the server's certificate at all.
    ///
    /// Turning this off is sometimes the only way to talk to something, and
    /// this library will not pretend otherwise - but it is a named field
    /// that defaults to true, and the connection reports it afterwards, so
    /// it cannot be on by accident.
    ///
    /// Off means off: no chain, no name, no dates. When something narrower
    /// will do, use it - `verify_hostname` below, `Policy::allow_expired`,
    /// or putting the server's own certificate in the trust store, which
    /// authenticates it properly rather than not at all.
    pub verify_certificate: bool,
    /// Check that the certificate covers the hostname.
    ///
    /// Separate from `verify_certificate`, because "this is a certificate I
    /// trust, for a name I am not going to check" is a real and much
    /// narrower request than "do not check anything". It is what you want
    /// when connecting to a box by IP address, or to one whose certificate
    /// was issued for a name it no longer answers to.
    ///
    /// The chain is still verified. Turning this off does not turn that
    /// off, and the two used to be welded together: there was no way to ask
    /// for one without the other, and the Python shim's `check_hostname`
    /// was silently ignored because of it.
    pub verify_hostname: bool,
    /// The smallest finite-field Diffie-Hellman group to accept, in bits.
    ///
    /// A TLS 1.2 DHE server chooses the group unilaterally, so this is the
    /// client's only say in it. 2048 by default. Logjam broke 512 bit
    /// export groups in real time and put a precomputation attack on the
    /// common 1024 bit groups within reach of a state, so the floor is a
    /// real defence rather than a formality - and lowering it is how you
    /// reach a server that has only ever been configured once, in 2003.
    ///
    /// Deliberately not part of `policy`: that is the certificate policy,
    /// and the DH group is a negotiation parameter with nothing to do with
    /// the certificate. Sharing `min_rsa_bits` between them would tie two
    /// unrelated decisions to one number.
    pub min_dh_bits: usize,
    /// Test the server's Diffie-Hellman modulus for primality.
    ///
    /// Off by default because it costs several full-width exponentiations
    /// on every handshake - more than the key exchange itself. On, it is
    /// the only thing standing between you and a server that sends a
    /// composite modulus, which makes the shared secret computable by
    /// whoever chose it while every other check passes.
    pub check_dh_prime: bool,
    /// Ask for encrypt-then-MAC. On by default: it is the proper fix for
    /// the CBC padding oracle, and modern servers agree to it.
    pub request_encrypt_then_mac: bool,
    /// Ask for the extended master secret. On by default; it is what stops
    /// two connections sharing a master secret.
    pub request_extended_master_secret: bool,
    /// TLS 1.3 session tickets to offer, from a previous connection to
    /// the same host.
    ///
    /// Empty by default, and it has to be: there is no cache in this
    /// library and no clock in it either, so the caller keeps the
    /// tickets and decides which to offer. `Connection::tickets` hands
    /// out the ones that arrived.
    ///
    /// **A ticket holds key material** - anybody with one can resume
    /// the connection it came from - and **a ticket is offered once**.
    /// Offering one twice lets a passive observer link the two
    /// connections, which is what `ticket_age_add` exists to prevent
    /// (RFC 8446 appendix C.4).
    ///
    /// Tickets whose hash does not match an offered 1.3 suite, or whose
    /// lifetime has run out at `policy.now`, are dropped rather than
    /// sent.
    pub tickets: Vec<Ticket>,
}

impl ClientConfig {
    /// A configuration with the given roots and the modern defaults.
    pub fn new(roots: TrustStore, now: i64) -> ClientConfig {
        ClientConfig {
            suites: Selection::modern(),
            roots,
            policy: Policy::at(now),
            // The ceiling is the highest we implement; the floor is the
            // lowest that is not broken. TLS 1.0 and 1.1 are reachable
            // through `legacy`, and SSLv3 only by asking for it by name -
            // its CBC padding is unspecified, which is POODLE.
            max_version: Version::TLS13,
            min_version: Version::TLS12,
            verify_certificate: true,
            verify_hostname: true,
            min_dh_bits: 2048,
            check_dh_prime: false,
            request_encrypt_then_mac: true,
            request_extended_master_secret: true,
            tickets: Vec::new(),
            early_data: Vec::new(),
            alpn: Vec::new(),
            request_stapled_ocsp: true,
            require_stapled_ocsp: false,
            // No certificate by default. A client that has one and does
            // not want it sent to every server it meets is the normal
            // case, so this is set per connection rather than assumed.
            client_certificate: None,
        }
    }

    /// The configuration for talking to something old: the legacy suite
    /// set and the legacy certificate policy.
    ///
    /// A named constructor rather than a pile of flags, so that using it is
    /// a decision somebody made.
    pub fn legacy(roots: TrustStore, now: i64) -> ClientConfig {
        ClientConfig {
            suites: Selection::legacy(),
            policy: Policy::legacy(now),
            min_version: Version::TLS10,
            // 512 rather than 0: an export-grade group is a real thing an
            // old server offers and this selection exists to reach it.
            //
            // It is a default, not a floor on the floor - a caller who has
            // to reach a 480 bit group sets 480, and there is a real one
            // at dh480.badssl.com. What this value says is that going
            // below export grade should be a separate decision rather than
            // something the legacy configuration does for you.
            min_dh_bits: 512,
            ..ClientConfig::new(roots, now)
        }
    }
}

// ------------------------------------------------------------------ states ---

/// Where the handshake has got to.
///
/// Every transition is explicit and every state names what it will accept.
/// A message that does not belong is `unexpected_message`, not a warning
/// and not a guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// The ClientHello has been written and we are waiting for an answer.
    WaitServerHello,
    WaitCertificate,
    /// After the certificate: a ServerKeyExchange for the key exchanges
    /// that have one, a CertificateRequest, or ServerHelloDone.
    WaitServerFlight,

    // TLS 1.3 has its own states rather than reusing the ones above.
    // The two machines accept different messages in the same-sounding
    // place - a 1.3 Certificate arrives *after* the keys have changed and
    // has a different shape - and a shared state would be a state that
    // accepts both, which is the whole thing this machine is built not to
    // do.
    /// The keys have changed; the server's first protected message is next.
    WaitEncryptedExtensions,
    WaitCertificate13,
    WaitCertificateVerify,
    WaitServerFinished13,

    /// Our second flight is out; the server's ChangeCipherSpec is next.
    WaitChangeCipherSpec,
    WaitFinished,
    Established,
    Closed,
    Failed,
}

impl State {
    fn describe(self) -> &'static str {
        match self {
            State::WaitServerHello => "waiting for the ServerHello",
            State::WaitCertificate => "waiting for the server's Certificate",
            State::WaitServerFlight => "waiting for the rest of the server's flight",
            State::WaitEncryptedExtensions =>
                "waiting for the server's EncryptedExtensions",
            State::WaitCertificate13 =>
                "waiting for the server's Certificate (TLS 1.3)",
            State::WaitCertificateVerify =>
                "waiting for the server's CertificateVerify",
            State::WaitServerFinished13 =>
                "waiting for the server's Finished (TLS 1.3)",
            State::WaitChangeCipherSpec => "waiting for the server's ChangeCipherSpec",
            State::WaitFinished => "waiting for the server's Finished",
            State::Established => "the handshake is finished",
            State::Closed => "the connection is closed",
            State::Failed => "the connection has failed",
        }
    }
}

// -------------------------------------------------------------- connection ---

/// One TLS client connection.
pub struct ClientConnection {
    config: ClientConfig,
    hostname: String,
    state: State,

    /// The two Finished messages' `verify_data`, for `tls-unique`
    /// channel binding (RFC 5929).
    ///
    /// **Which one is the binding depends on whether the session was
    /// resumed**, and for a client the rule is "our own, unless
    /// resumed, and then the peer's" - which is what OpenSSL does and
    /// therefore what every peer expects. On a full handshake at TLS
    /// 1.2 the client's Finished is also the first one sent, so the two
    /// readings agree; on an abbreviated handshake, and at TLS 1.3
    /// where the server goes first, they do not. A client that always
    /// used its own agrees with itself on every handshake and with the
    /// server on some of them, and SCRAM then fails looking like a bad
    /// password.
    own_finished: Option<Vec<u8>>,
    peer_finished: Option<Vec<u8>>,

    reader: RecordReader,
    writer: RecordWriter,
    handshake: HandshakeReader,
    transcript: Option<Transcript>,

    /// Bytes to send.
    outgoing: Vec<u8>,
    /// Application data received and not yet taken.
    incoming: Vec<u8>,

    client_random: [u8; 32],
    server_random: [u8; 32],
    /// The version in the ClientHello's `legacy_version` field - which is
    /// what goes in the RSA premaster, not the negotiated one and not the
    /// highest version offered.
    ///
    /// Those three stopped being the same thing when TLS 1.3 moved the
    /// real offer into `supported_versions` and pinned the field at
    /// 0x0303. Putting 0x0304 in the premaster makes a TLS 1.2 server
    /// reject the Finished with `bad_record_mac` - RFC 5246 section
    /// 7.4.7.1 has it compare the premaster's first two bytes against the
    /// *field*, as a rollback countermeasure, and the comparison is done
    /// in a way that deliberately does not say what went wrong.
    offered_version: Version,
    negotiated_version: Option<Version>,
    suite: Option<&'static CipherSuite>,
    master: Option<Vec<u8>>,

    certificates: Vec<Vec<u8>>,
    /// The server's ephemeral key, for the key exchanges that have one.
    server_ecdh: Option<ServerEcdhParams>,
    /// The server's temporary RSA key, for the export RSA suites. The
    /// only kind of RSA key exchange that has a ServerKeyExchange at all.
    server_rsa: Option<ServerRsaParams>,
    /// The same, for finite-field DHE. Two fields rather than one enum
    /// because the two carry different things and only one can ever be
    /// set: the suite decides which, before either is parsed.
    server_dh: Option<ServerDhParams>,
    encrypt_then_mac: bool,
    extended_master_secret: bool,
    /// The alert received or sent, if any.
    alert: Option<Alert>,
    /// Whether the certificate was actually verified, so a caller can ask
    /// afterwards rather than having to remember what it configured.
    certificate_verified: bool,
    /// The signature scheme the peer authenticated with, once one
    /// has been checked. See the accessor for which message that is.
    peer_signature_scheme: Option<u16>,

    /// The ClientHello exactly as it was written.
    ///
    /// Kept rather than rebuilt. Rebuilding was safe while the hello was a
    /// pure function of the configuration; a TLS 1.3 hello carries a
    /// freshly generated key share, so a rebuild would have to reproduce a
    /// random value - and a transcript that silently differs from what was
    /// sent fails the Finished check with nothing to point at.
    client_hello_bytes: Vec<u8>,
    /// What the TLS 1.3 transcript starts with.
    ///
    /// Normally the ClientHello's own bytes. After a HelloRetryRequest
    /// it is the synthetic `message_hash` message, the retry, and the
    /// second hello - RFC 8446 section 4.4.1 replaces the first hello
    /// with a hash of itself rather than keeping it, so a transcript
    /// built by concatenating what crossed the wire is wrong.
    transcript_prefix: Vec<u8>,
    /// The group the TLS 1.3 key exchange actually used.
    ///
    /// Recorded rather than read back off `key_shares`, because after a
    /// HelloRetryRequest that list has been replaced and would name the
    /// group the *server asked for* whether or not it was then used.
    negotiated_group: Option<u16>,
    /// A HelloRetryRequest has been answered. A second one is fatal
    /// (RFC 8446 section 4.1.4), and without this a server could loop a
    /// client indefinitely.
    saw_retry_request: bool,
    /// What the HelloRetryRequest chose - its suite code and the group it
    /// asked for - kept so that the real ServerHello can be held to it.
    /// RFC 8446 4.1.4: a client "MUST abort the handshake with an
    /// illegal_parameter alert" if that ServerHello selects a different
    /// suite, a version other than 1.3, or a key share from another group.
    retry_choice: Option<(u16, u16)>,
    /// Whether the server's TLS 1.3 compatibility ChangeCipherSpec has
    /// arrived. RFC 8446 appendix D.4 has each side send exactly one,
    /// so a second is a peer - or a middlebox - injecting records.
    saw_compat_ccs: bool,
    /// The cookie a HelloRetryRequest asked to have echoed.
    retry_cookie: Option<Vec<u8>>,
    /// The ephemeral keys offered in the 1.3 key_share, kept so the
    /// server's answer can be completed against the right one.
    key_shares: Vec<EphemeralKey>,
    tls13: Option<Tls13>,
    /// The PSK offer in flight, kept from writing the hello until the
    /// server answers - the binder keys are in it, and so is the
    /// mapping from `selected_identity` back to a ticket.
    psk_offer: Option<(Offer, Vec<Ticket>)>,
    /// Whether the server accepted a PSK. A resumed connection has no
    /// Certificate and no CertificateVerify, so this decides which
    /// messages the state machine expects next.
    resumed: bool,
    /// NewSessionTickets that arrived, ready for the caller to keep.
    tickets: Vec<Ticket>,
    /// A CertificateRequest the server sent, kept until our second flight -
    /// it arrives before the server's Certificate and is answered after
    /// its Finished.
    certificate_request: Option<hs13::CertificateRequest13>,
    /// The early-data keys, from the moment the hello was written until
    /// EndOfEarlyData goes out or the server declines.
    ///
    /// `Some` means early data was *offered*, and the writer is on those
    /// keys; whether the server accepted is `early_data_accepted`.
    early_keys: Option<keys13::TrafficKeys>,
    /// The client's handshake keys, **held back** while early data is in
    /// flight, because the writer stays on the early keys until
    /// EndOfEarlyData has been written under them.
    held_handshake_keys: Option<keys13::TrafficKeys>,
    early_data_accepted: bool,
    offered_early_data: bool,
    negotiated_alpn: Option<String>,
    /// The TLS 1.2 CertificateRequest, kept until the second flight.
    /// Separate from `certificate_request` - the 1.3 one - because the
    /// two are different messages answered in different orders, and one
    /// field would be read in a state it means nothing in.
    certificate_request_12: Option<crate::tls::handshake::CertificateRequest12>,
    /// The OCSP response the server stapled, as DER, if it stapled one.
    stapled_ocsp: Option<Vec<u8>>,
    /// Whether the server said, in its ServerHello, that a
    /// CertificateStatus was coming. TLS 1.2 only, and the reason it is
    /// tracked at all is that the message is *optional even after the
    /// acknowledgement* - so a client cannot wait for it, and must
    /// refuse one that arrives unannounced.
    expect_certificate_status: bool,
}

// ------------------------------------------------------------ TLS 1.3 state ---

/// What a TLS 1.3 handshake carries that a 1.2 one does not.
///
/// A struct rather than loose fields, so a 1.2 handshake cannot reach any
/// of it and a 1.3 one cannot forget to set it.
struct Tls13 {
    schedule: Schedule,
    hash: &'static str,
    /// The AEAD's name, its key, IV and tag lengths, and RFC 9367's
    /// re-keying if the suite has it - as one value, because picking
    /// them separately is how a connection ends up with a sixteen byte
    /// IV and a twelve byte nonce.
    aead: crate::tls::handshake13::Tls13Aead,
    /// Kept out of the record layer's protection because the client's is
    /// needed *after* the writer has moved on to the application keys.
    client_finished_key: Vec<u8>,
    server_finished_key: Vec<u8>,
    /// The resumption master secret, computed once when the handshake
    /// ends and kept.
    ///
    /// **Not derived when a ticket arrives.** RFC 8446 7.1 puts it over
    /// the transcript "ClientHello ... client Finished", and a
    /// NewSessionTicket comes after that - but `handle_handshake` feeds
    /// every incoming message to the transcript *before* dispatching
    /// it, so by the time a ticket's handler runs the transcript
    /// already includes the ticket. Deriving it there gave a PSK the
    /// server had never heard of, and the failure showed up one
    /// connection later as a binder OpenSSL rejected. The second ticket
    /// of a pair would have included the first, too.
    resumption_master: Option<Vec<u8>>,

    /// The exporter master secret, for `tls-exporter` channel binding
    /// (RFC 9266) and anything else that needs keying material from
    /// this connection.
    ///
    /// Taken at the same moment as the application keys - over the
    /// transcript through the *server's* Finished, one message earlier
    /// than `resumption_master` above. Storing it rather than deriving
    /// it on demand is not an optimisation: by the time a caller asks,
    /// the transcript has moved on past the point the secret is defined
    /// at, and a later derivation would silently produce a different
    /// one.
    exporter_master: Option<Vec<u8>>,
}

impl ClientConnection {
    /// Start a connection and produce the ClientHello.
    pub fn new(config: ClientConfig, hostname: &str) -> Result<ClientConnection, Error> {
        // **An empty hostname means "send no SNI", and is only allowed
        // when nothing is going to check a name.**
        //
        // There are two real cases for it and neither is exotic:
        // connecting to a literal IP address, where RFC 6066 3 forbids
        // putting the address in SNI so every real client omits the
        // extension; and connecting to something whose certificate is
        // not going to be trusted anyway, which is what
        // `check_hostname = False` with `CERT_NONE` means in Python's
        // `ssl`. Refusing both was this library being stricter than the
        // standard library for no benefit - there is nothing to check
        // the name against, so requiring one only forces the caller to
        // invent it.
        //
        // With `verify_hostname` on it stays an error, because the
        // alternative is a connection that silently checks nothing.
        if hostname.is_empty() && config.verify_hostname {
            return Err(Error::local(
                "A hostname is required while verify_hostname is on: it goes \
                 in SNI and is what the certificate is checked against. To \
                 connect without one - to an IP address, or to something \
                 whose certificate you are not judging - turn verify_hostname \
                 off, and no server_name extension is sent."));
        }
        if config.verify_certificate && config.roots.is_empty() {
            return Err(Error::local(
                "Certificate verification is on but there are no trusted roots. \
                 Load a trust store, or set verify_certificate to false and \
                 understand what that means."));
        }

        let mut random = [0u8; 32];
        crate::random::fill(&mut random).map_err(Error::local)?;

        // The ephemeral keys for the 1.3 key_share, generated before the
        // hello is written because the hello carries their public halves.
        //
        // Two groups rather than one. A server that wants a group we did
        // not offer a share for answers with a HelloRetryRequest and the
        // handshake costs an extra round trip; X25519 and P-256 between
        // them cover essentially everything, which is why every browser
        // sends exactly this pair.
        let mut key_shares = Vec::new();
        if config.max_version >= Version::TLS13 {
            // The hybrid share first: key_share is in preference order.
            for group in TLS13_HYBRID_SHARES.iter().chain(TLS13_KEY_SHARE_GROUPS) {
                key_shares.push(EphemeralKey::generate(*group).map_err(Error::local)?);
            }
        }

        // Not `config.max_version`: see the field's comment. This is the
        // hello's `legacy_version` field, which is never above 1.2.
        let offered_version = core::cmp::min(config.max_version, Version::TLS12);
        let mut connection = ClientConnection {
            hostname: hostname.to_string(),
            state: State::WaitServerHello,
            own_finished: None,
            peer_finished: None,
            reader: RecordReader::new(),
            // The record version of a ClientHello is deliberately
            // conservative - TLS 1.0 - because middleboxes drop anything
            // higher. The real offer is in the hello body.
            //
            // Unless we are not offering TLS 1.0 at all: a server that
            // speaks only SSLv3 has never seen a 0x0301 record and may
            // refuse one, and claiming a version above our own ceiling
            // would be a lie in the one direction that matters.
            writer: RecordWriter::new(if config.max_version < Version::TLS10 {
                config.max_version
            } else {
                Version::TLS10
            }),
            handshake: HandshakeReader::new(),
            transcript: None,
            outgoing: Vec::new(),
            incoming: Vec::new(),
            client_random: random,
            server_random: [0u8; 32],
            offered_version,
            negotiated_version: None,
            suite: None,
            master: None,
            certificates: Vec::new(),
            server_ecdh: None,
            server_dh: None,
            server_rsa: None,
            encrypt_then_mac: false,
            extended_master_secret: false,
            alert: None,
            certificate_verified: false,
            peer_signature_scheme: None,
            client_hello_bytes: Vec::new(),
            transcript_prefix: Vec::new(),
            negotiated_group: None,
            saw_retry_request: false,
            retry_choice: None,
            saw_compat_ccs: false,
            retry_cookie: None,
            key_shares,
            tls13: None,
            psk_offer: None,
            resumed: false,
            tickets: Vec::new(),
            certificate_request: None,
            early_keys: None,
            held_handshake_keys: None,
            early_data_accepted: false,
            offered_early_data: false,
            negotiated_alpn: None,
            certificate_request_12: None,
            stapled_ocsp: None,
            expect_certificate_status: false,
            config,
        };

        connection.send_client_hello()?;
        Ok(connection)
    }

    // ---------------------------------------------------------- the seam ---

    pub fn push_incoming(&mut self, bytes: &[u8]) {
        self.reader.push_incoming(bytes);
    }

    /// Take everything waiting to be sent.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    pub fn wants_write(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Take the application data received so far.
    pub fn take_incoming(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.incoming)
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Established | State::Closed | State::Failed)
    }

    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    pub fn negotiated_version(&self) -> Option<Version> {
        self.negotiated_version
    }

    pub fn negotiated_suite(&self) -> Option<&'static CipherSuite> {
        self.suite
    }

    /// The chain the server sent, leaf first, as DER.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }

    /// Whether the certificate chain was actually verified.
    ///
    /// A caller should not have to remember what it configured to know
    /// whether the peer was authenticated.
    pub fn certificate_verified(&self) -> bool {
        self.certificate_verified
    }

    /// The signature scheme the server authenticated itself with, or
    /// `None` if it has not yet or the suite has no server signature.
    ///
    /// Two messages carry one, and which it was follows from the version:
    /// a TLS 1.3 CertificateVerify, or a 1.2 ServerKeyExchange. The suites
    /// that authenticate by key transport - RSA, and RFC 9189's GOST -
    /// sign nothing, so `None` there is the right answer rather than a gap.
    ///
    /// Here because the RFC 9367 schemes are each bound to one curve, and
    /// "the handshake completed" does not say the server picked the bound
    /// one: a client that accepted any GOST scheme with any GOST
    /// certificate would complete every handshake in
    /// `tests/test_gost_13_signature.rs` too.
    pub fn peer_signature_scheme(&self) -> Option<u16> {
        self.peer_signature_scheme
    }

    pub fn uses_encrypt_then_mac(&self) -> bool {
        self.encrypt_then_mac
    }

    /// The session tickets this connection was given, for a later one.
    ///
    /// Empty until the handshake is finished, and usually until a
    /// little after: a TLS 1.3 server sends them under the application
    /// keys, so they arrive with or after the first data. A caller that
    /// reads the list immediately after the handshake will often find
    /// it empty and should look again after the first `receive`.
    ///
    /// **These hold key material.** Each one is enough to resume this
    /// connection, so storing them is storing keys.
    pub fn tickets(&self) -> &[Ticket] {
        &self.tickets
    }

    /// Channel binding material for this connection, RFC 5929 and RFC
    /// 9266.
    ///
    /// `kind` is `"tls-unique"` or `"tls-exporter"`. Both are what a
    /// SASL mechanism - SCRAM, mostly, as used by LDAP, PostgreSQL and
    /// IMAP - mixes into its exchange so that an authentication cannot
    /// be relayed onto a different TLS connection.
    ///
    /// **They belong to different versions and neither is a fallback
    /// for the other.** `tls-unique` is the first Finished message's
    /// verify_data and is defined for TLS 1.2 and below; TLS 1.3
    /// changed the key schedule so that value is no longer unique to
    /// the connection, and RFC 9266 defines `tls-exporter` in its
    /// place. Asking for the wrong one for the negotiated version
    /// returns `Ok(None)` rather than something plausible, because a
    /// binding that is merely *a* value would authenticate the wrong
    /// connection and nothing would report it.
    ///
    /// `None` also means the handshake has not reached the point where
    /// the material exists.
    ///
    /// # Errors
    /// A binding type this library does not implement.
    pub fn channel_binding(&self, kind: &str) -> Result<Option<Vec<u8>>, String> {
        match kind {
            "tls-unique" => {
                // OpenSSL's rule, and therefore everybody's: for a
                // client it is our own Finished unless the session was
                // resumed, in which case it is the peer's. CPython
                // spells the same thing `SSL_session_reused(ssl) ^
                // !server_side`.
                //
                // **This is returned at TLS 1.3 as well, and that is a
                // decision rather than an oversight.** RFC 9266 does not
                // define `tls-unique` for 1.3 and offers `tls-exporter`
                // in its place, so the sound thing would be to return
                // nothing here - but OpenSSL returns the Finished, every
                // peer that asks for `tls-unique` at 1.3 gets it, and a
                // client that alone returned `None` would fail every
                // SCRAM exchange against them while being no safer:
                // the value is exactly as (un)sound at both ends.
                // `tls-exporter` is the one to ask for, and
                // `docs/pitfalls.md` records why.
                Ok(if self.resumed {
                    self.peer_finished.clone()
                } else {
                    self.own_finished.clone()
                })
            }
            "tls-exporter" => {
                let Some(state) = self.tls13.as_ref() else { return Ok(None) };
                let Some(master) = state.exporter_master.as_ref() else {
                    return Ok(None);
                };
                // RFC 9266 section 3: the label is exactly this, the
                // context is empty and the length is 32.
                Schedule::export_keying_material(
                    state.hash, master, b"EXPORTER-Channel-Binding", &[], 32)
                    .map(Some)
            }
            other => Err(format!(
                "{:?} is not a channel binding this library implements. \
                 tls-unique (RFC 5929, TLS 1.2 and below) and tls-exporter \
                 (RFC 9266, TLS 1.3) are.", other)),
        }
    }

    /// Take the tickets, leaving none behind.
    ///
    /// The shape a caller actually wants: a ticket is offered **once**,
    /// so reading them without removing them invites offering the same
    /// one twice, which lets a passive observer link the two
    /// connections (RFC 8446 appendix C.4).
    pub fn take_tickets(&mut self) -> Vec<Ticket> {
        core::mem::take(&mut self.tickets)
    }

    /// Whether this handshake resumed a previous session.
    ///
    /// A resumed TLS 1.3 connection has **no certificate**: the PSK is
    /// what authenticates the server, and it does so because only the
    /// peer that ran the original handshake could derive the same key.
    /// So `peer_certificates` is empty on one and
    /// `certificate_verified` is false, and neither means anything went
    /// wrong - a caller that treats an empty chain as a failure needs
    /// to ask this first.
    pub fn resumed(&self) -> bool {
        self.resumed
    }

    /// The group an ephemeral key exchange used, or `None` for a static
    /// RSA key exchange, which has no group.
    ///
    /// Worth exposing rather than leaving inferable from the suite name: a
    /// suite says ECDHE but not *which* curve, and the curve is the part
    /// that decides the strength. A server that picked secp256r1 when we
    /// would rather have had secp384r1 is a thing a caller may want to
    /// refuse, and it cannot refuse what it cannot see.
    ///
    /// The name is the IANA one (`secp256r1`), not this library's curve
    /// name (`P-256`), because it is the protocol's answer to what was
    /// negotiated and the two vocabularies should not be mixed. A
    /// finite-field DHE group has no IANA name to report before TLS 1.3,
    /// since the server sends the numbers themselves, so it is reported
    /// by its size (`dh2048`), which is the property anybody asking this
    /// question about a DHE connection actually wants.
    pub fn named_group(&self) -> Option<String> {
        // TLS 1.3 first: it has no ServerKeyExchange, so neither of the
        // fields below is ever set on a 1.3 connection and this used to
        // return None for every one of them.
        if let Some(group) = self.negotiated_group {
            return Some(groups::name(group));
        }
        if let Some(params) = self.server_dh.as_ref() {
            let bits = BigUint::from_bytes_be(&params.p).bit_len();
            return Some(format!("dh{}", bits));
        }
        self.server_ecdh.as_ref().map(|params| groups::name(params.group))
    }

    pub fn uses_extended_master_secret(&self) -> bool {
        self.extended_master_secret
    }

    /// This session's line in the NSS key log format, which is what
    /// Wireshark reads to decrypt a capture:
    ///
    /// ```text
    /// CLIENT_RANDOM <client_random, hex> <master_secret, hex>
    /// ```
    ///
    /// `None` until the master secret exists, which is from the client's
    /// second flight onwards.
    ///
    /// # This hands out the session keys
    ///
    /// Anyone holding this line can decrypt every record of this
    /// connection, from a capture taken at any time, for as long as the
    /// capture exists. It is a debugging tool and nothing else. It is not
    /// written anywhere unless a caller asks for it, there is no
    /// environment variable read down here, and a log file holding these
    /// deserves the same care as a private key - more, since a private key
    /// is usually encrypted at rest and this is not.
    ///
    /// The format is deliberately the one everything else uses (NSS,
    /// OpenSSL's `SSLKEYLOGFILE`, Python's `SSLContext.keylog_filename`),
    /// because a debugging format nobody else reads is not a debugging
    /// format. For TLS 1.2 the `CLIENT_RANDOM` label is the whole of it;
    /// TLS 1.3 uses several labels for its separate traffic secrets, and
    /// will need more here when it lands.
    pub fn key_log_line(&self) -> Option<String> {
        let master = self.master.as_ref()?;
        Some(format!("CLIENT_RANDOM {} {}",
                     crate::to_hex(&self.client_random).to_lowercase(),
                     crate::to_hex(master).to_lowercase()))
    }

    pub fn alert(&self) -> Option<Alert> {
        self.alert
    }

    /// Send application data. Only once the handshake is done.
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Established {
            return Err(Error::local(format!(
                "Cannot write application data: {}.", self.state.describe())));
        }
        let bytes = self.writer.write(ContentType::ApplicationData, data)?;
        self.outgoing.extend_from_slice(&bytes);
        Ok(())
    }

    /// Send close_notify and stop.
    pub fn close(&mut self) -> Result<(), Error> {
        if matches!(self.state, State::Closed | State::Failed) {
            return Ok(());
        }
        self.send_alert(Alert::close_notify())?;
        self.state = State::Closed;
        Ok(())
    }

    /// Advance as far as the bytes allow.
    ///
    /// Returns when there is nothing more to do with what has arrived.
    /// Every failure leaves the connection in `Failed` and queues the alert
    /// the peer should be sent, because a connection that failed and then
    /// carried on is the bug this whole file is about.
    pub fn process(&mut self) -> Result<(), Error> {
        match self.process_inner() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.state = State::Failed;
                if let Some(description) = error.alert {
                    let alert = Alert::fatal(description);
                    self.alert = Some(alert);
                    // Best effort: if even this fails there is nothing to
                    // be done about it, and the original error is what
                    // matters.
                    let _ = self.send_alert(alert);
                }
                Err(error)
            }
        }
    }

    fn process_inner(&mut self) -> Result<(), Error> {
        loop {
            if matches!(self.state, State::Closed | State::Failed) {
                return Ok(());
            }
            let record = match self.reader.read()? {
                Some(record) => record,
                None => return Ok(()),
            };

            match record.content_type {
                ContentType::Alert => {
                    let alert = Alert::parse(&record.payload)
                        .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
                    self.alert = Some(alert);
                    if alert.description == AlertDescription::CLOSE_NOTIFY {
                        self.state = State::Closed;
                        return Ok(());
                    }
                    if alert.level == AlertLevel::Fatal {
                        self.state = State::Failed;
                        return Err(Error { alert: None,
                                           detail: format!("The peer sent a {}.",
                                                           alert.name()) });
                    }
                    // A warning that is not close_notify is noted and
                    // ignored, which is what the spec allows.
                }

                ContentType::ChangeCipherSpec => {
                    self.handle_change_cipher_spec(&record.payload)?;
                }

                ContentType::Handshake => {
                    self.handshake.push(&record.payload);
                    while let Some(message) = self.handshake.next_message()? {
                        self.handle_handshake(message)?;
                    }
                }

                ContentType::ApplicationData => {
                    if self.state != State::Established {
                        // Application data before the handshake finishes is
                        // not early data in TLS 1.2; it is a peer skipping
                        // the authentication.
                        return Err(Error::unexpected(self.state.describe(),
                                                     "application data"));
                    }
                    self.incoming.extend_from_slice(&record.payload);
                }

                ContentType::Unknown(byte) => {
                    return Err(Error::unexpected(self.state.describe(),
                                                 &format!("a record of type {}", byte)));
                }
            }
        }
    }

    // ------------------------------------------------------- the messages ---

    fn send_client_hello(&mut self) -> Result<(), Error> {
        let extensions = self.hello_extensions()?;

        let hello = ClientHello {
            legacy_version: self.legacy_hello_version(),
            random: self.client_random,
            session_id: Vec::new(),
            // to_hello appends the renegotiation SCSV, which is not
            // optional - without it or the extension a server cannot tell a
            // renegotiation from a fresh handshake.
            cipher_suites: self.config.suites
                .for_version(self.config.max_version).to_hello(),
            compression_methods: vec![0],
            extensions,
        };

        let mut message = HandshakeMessage::new(HandshakeType::ClientHello,
                                                hello.encode()?)?;
        // The prefix and the hello are the same thing until a
        // HelloRetryRequest makes them differ.
        let mut prefix = message.raw.clone();
        // The binders are computed over the hello that has just been
        // written and then put back into it, in place. Nothing is
        // re-encoded: every length in the message already counts the
        // binder bytes, which is exactly what the binder covers.
        self.seal_binders(&mut message.raw, &mut prefix)?;
        // Kept, not rebuilt: a 1.3 hello carries a freshly generated key
        // share, so there is no way to reproduce it later.
        self.client_hello_bytes = message.raw.clone();
        self.transcript_prefix = prefix;
        self.emit_handshake(&message)?;
        self.send_early_data()
    }

    /// The early data (0-RTT), written straight after the ClientHello.
    ///
    /// **Everything it needs comes from the ticket, not from the
    /// negotiation**, because there has not been one: the suite, the
    /// hash, the AEAD and the PSK are all the *previous* connection's,
    /// and the transcript is this ClientHello alone. That is the whole
    /// shape of 0-RTT and the whole reason it is replayable - nothing
    /// the server has said is in these keys, so nothing about them is
    /// fresh.
    fn send_early_data(&mut self) -> Result<(), Error> {
        if !self.offered_early_data {
            return Ok(());
        }
        let ticket = self.psk_offer.as_ref()
            .and_then(|(_, tickets)| tickets.first())
            .ok_or_else(|| Error::local("Early data with no ticket."))?;
        let suite = suites::by_code(ticket.suite).ok_or_else(||
            Error::local("The ticket names a suite this build does not have."))?;
        let parameters = tls13_aead(suite)?;
        let (aead, key_len, tag_len) = (parameters.name, parameters.key_len,
                                        parameters.tag_len);
        let hash = tls13_hash(suite)?;
        let psk = ticket.psk.clone();

        // The transcript is the ClientHello and nothing else - the
        // binders are already spliced in, so `transcript_prefix` is the
        // message exactly as it went out.
        let mut hasher = crate::api::AnyHash::new(hash).map_err(Error::local)?;
        hasher.update(&self.transcript_prefix);
        let hello_hash = hasher.digest();

        let keys = Schedule::early(suite.prf, Some(&psk)).map_err(Error::local)?
            .client_early_traffic(&hello_hash, key_len, parameters.iv_len)
            .map_err(Error::local)?;

        // **The compatibility ChangeCipherSpec moves earlier.** It is
        // sent in the clear, and from the next line the writer is not
        // writing in the clear any more - so a client that left it where
        // the ordinary path puts it (after the ServerHello) would send a
        // plaintext record after encrypted ones, which is exactly what
        // the middlebox it exists for is watching out for.
        //
        // The version is pinned *first*: a 1.3 peer requires every record
        // from here on to claim 0x0303, and this one is still going out
        // at the hello's version otherwise. On the ordinary path that
        // happens in `handle_server_hello_13` before the same record is
        // written; sending it early moves the record but not the rule.
        self.writer.set_version(crate::tls::record13::LEGACY_RECORD_VERSION);
        let ccs = self.writer.write(ContentType::ChangeCipherSpec, &[1])?;
        self.outgoing.extend_from_slice(&ccs);
        self.writer.change_cipher_spec(Protection::Aead13(
            Aead13::with_rekeying(aead, hash, keys.clone(), tag_len,
                                  parameters.mgm).map_err(Error::local)?));
        self.early_keys = Some(keys);

        let data = self.config.early_data.clone();
        let bytes = self.writer.write(ContentType::ApplicationData, &data)?;
        self.outgoing.extend_from_slice(&bytes);
        Ok(())
    }

    /// What goes in the hello's `legacy_version` field.
    ///
    /// **Never above 1.2.** RFC 8446 section 4.1.2 fixes it at 0x0303 for
    /// a TLS 1.3 hello, and the reason is not aesthetic: middleboxes
    /// written before 2015 drop a record or a hello claiming anything
    /// higher, and the connection fails in a way that looks like a network
    /// problem. The real offer is in `supported_versions`.
    fn legacy_hello_version(&self) -> Version {
        core::cmp::min(self.config.max_version, Version::TLS12)
    }

    fn handle_handshake(&mut self, message: HandshakeMessage) -> Result<(), Error> {
        // The transcript covers every handshake message except
        // HelloRequest, and it must be fed the bytes that arrived rather
        // than a re-encoding.
        //
        // Finished is the exception to *when*: the verify_data inside it is
        // computed over the transcript up to but not including itself, so
        // it is dispatched first and added afterwards. Every other message
        // is added before dispatch, so no path through the match can
        // forget one.
        // Two messages cover the transcript *before* themselves:
        // Finished in every version, and TLS 1.3's CertificateVerify,
        // whose signature is over the transcript through the Certificate.
        // Both are dispatched first and added afterwards.
        //
        // TLS 1.3's Finished handler adds it itself, because the
        // application secrets are derived from the transcript that
        // includes it - so the deferred update must not happen twice.
        let defer = matches!(message.message_type,
                             HandshakeType::Finished | HandshakeType::CertificateVerify);
        let adds_its_own = message.message_type == HandshakeType::Finished
            && self.negotiated_version == Some(Version::TLS13);
        if message.message_type != HandshakeType::HelloRequest && !defer {
            if let Some(transcript) = &mut self.transcript {
                transcript.update(&message.raw);
            }
        }

        let outcome = self.dispatch_handshake(&message);

        if defer && !adds_its_own && outcome.is_ok() {
            if let Some(transcript) = &mut self.transcript {
                transcript.update(&message.raw);
            }
        }
        outcome
    }

    fn dispatch_handshake(&mut self, message: &HandshakeMessage) -> Result<(), Error> {
        match (self.state, message.message_type) {
            (State::WaitServerHello, HandshakeType::ServerHello) =>
                self.handle_server_hello(message),

            (State::WaitCertificate, HandshakeType::Certificate) =>
                self.handle_certificate(message),

            (State::WaitServerFlight, HandshakeType::CertificateStatus) =>
                self.handle_certificate_status(message),

            (State::WaitServerFlight, HandshakeType::ServerKeyExchange) =>
                self.handle_server_key_exchange(message),

            (State::WaitServerFlight, HandshakeType::CertificateRequest) =>
                self.handle_certificate_request_12(message),

            (State::WaitServerFlight, HandshakeType::ServerHelloDone) =>
                self.handle_server_hello_done(message),

            (State::WaitFinished, HandshakeType::NewSessionTicket) => {
                // Real servers send this before their ChangeCipherSpec, in
                // the clear. Noticed by the captured transcripts before any
                // live connection, which is what they are for.
                Ok(())
            }
            (State::WaitChangeCipherSpec, HandshakeType::NewSessionTicket) => Ok(()),

            (State::WaitFinished, HandshakeType::Finished) =>
                self.handle_finished(message),

            // TLS 1.3's flight. Each state names exactly one message, so
            // a server that skips the CertificateVerify - which is what
            // an unauthenticated handshake would look like - is refused
            // rather than accepted with `certificate_verified` unset.
            (State::WaitEncryptedExtensions, HandshakeType::EncryptedExtensions) =>
                self.handle_encrypted_extensions(message),

            (State::WaitCertificate13, HandshakeType::Certificate) =>
                self.handle_certificate_13(message),

            (State::WaitCertificate13, HandshakeType::CertificateRequest) =>
                self.handle_certificate_request_13(message),

            (State::WaitCertificateVerify, HandshakeType::CertificateVerify) =>
                self.handle_certificate_verify(message),

            (State::WaitServerFinished13, HandshakeType::Finished) =>
                self.handle_finished_13(message),

            // Session tickets arrive after the handshake in 1.3, under
            // the application keys.
            (State::Established, HandshakeType::NewSessionTicket) =>
                self.handle_new_session_ticket(message),

            (State::Established, HandshakeType::KeyUpdate) =>
                self.handle_key_update(message),

            (_, HandshakeType::HelloRequest) => self.handle_hello_request(),

            (state, message_type) =>
                Err(Error::unexpected(state.describe(), &message_type.name())),
        }
    }

    /// A HelloRequest: the server asking for a renegotiation.
    ///
    /// Three answers, by version and state. TLS 1.3 has no such message:
    /// renegotiation was removed, and the type is not in its registry of
    /// legal post-handshake messages, so one arriving there is
    /// `unexpected_message` like any other message out of place. At 1.2
    /// and below on an established connection, this client does not
    /// renegotiate and says so with a `no_renegotiation` warning (RFC
    /// 5246 7.4.1.1), which is a refusal rather than a failure. And in
    /// the middle of a handshake the same section says the client
    /// ignores it: a server that asks to start over while a handshake is
    /// running gets no answer, and the handshake continues.
    fn handle_hello_request(&mut self) -> Result<(), Error> {
        if self.negotiated_version == Some(Version::TLS13) || self.saw_retry_request {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                "A HelloRequest arrived on a TLS 1.3 connection, which has no \
                 renegotiation and no such message."));
        }
        if self.state == State::Established {
            return self.send_alert(Alert::warning(AlertDescription::NO_RENEGOTIATION));
        }
        Ok(())
    }

    /// A TLS 1.3 KeyUpdate (RFC 8446 section 4.6.3).
    ///
    /// The two halves of a connection change keys independently, and
    /// this message says only that the *sender* has changed its own. So
    /// receiving one steps the **reader** and nothing else - stepping
    /// the writer too would encrypt under a key the peer has not
    /// derived, and the failure would look like a MAC error on a record
    /// we sent rather than like a missing feature.
    ///
    /// `update_requested` additionally asks us to change ours, which
    /// means sending our own KeyUpdate and then stepping the writer -
    /// in that order, because the KeyUpdate itself goes out under the
    /// *old* key. RFC 8446 requires the reply to carry
    /// `update_not_requested`: two implementations that both asked
    /// would update each other forever.
    ///
    /// The sequence number restarts at zero on each side's change,
    /// which `Aead13::update` does as part of the same step - a counter
    /// that kept running would produce nonces nobody computes.
    fn handle_key_update(&mut self, message: &HandshakeMessage) -> Result<(), Error> {
        let request = hs13::KeyUpdateRequest::parse(&message.body)?;

        match self.reader.protection_mut() {
            Protection::Aead13(state) => state.update().map_err(Error::local)?,
            other => return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                format!("A KeyUpdate arrived on a {} connection, which has no \
                         key epochs.", other.name()))),
        }

        if request == hs13::KeyUpdateRequest::Requested {
            let reply = HandshakeMessage::new(
                HandshakeType::KeyUpdate,
                hs13::KeyUpdateRequest::NotRequested.encode())?;
            // Out under the old key, then step - the peer has not
            // changed its reading key until it sees this.
            self.emit_handshake(&reply)?;
            match self.writer.protection_mut() {
                Protection::Aead13(state) => state.update().map_err(Error::local)?,
                other => return Err(Error::local(format!(
                    "The writer is {} in a 1.3 connection.", other.name()))),
            }
        }

        // A KeyUpdate is not part of the handshake transcript: RFC 8446
        // section 4.4.1 ends it at the client's Finished, and post
        // handshake messages do not extend it. Adding one would change
        // every later `resumption_master_secret`.
        Ok(())
    }

    /// A HelloRetryRequest: send the hello again with the key share the
    /// server asked for (RFC 8446 section 4.1.4).
    ///
    /// It is a ServerHello with a fixed random rather than a message
    /// type of its own, which is why it is recognised in
    /// `handle_server_hello` before anything reads the rest.
    ///
    /// ## The transcript is not what crossed the wire
    ///
    /// RFC 8446 section 4.4.1 **replaces the first ClientHello with a
    /// hash of itself**:
    ///
    /// ```text
    /// Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
    ///     Hash(message_hash    ||      /* 254 */
    ///          00 00 Hash.length  ||   /* a three byte length */
    ///          Hash(ClientHello1) ||
    ///          HelloRetryRequest  || ... || Mn)
    /// ```
    ///
    /// So a transcript built by concatenating the messages that
    /// actually arrived is wrong, and wrong in a way that shows up only
    /// at the Finished check - with no indication that a retry was the
    /// cause. The synthetic message is a real handshake message with
    /// type 254 and the first hello's hash as its body, and it is built
    /// here.
    ///
    /// ## What may and may not change in the second hello
    ///
    /// Everything but the key share and the cookie must be identical,
    /// including the random - a client that generated a fresh one would
    /// be starting a different handshake. So the hello is rebuilt from
    /// the same fields with `key_shares` replaced by the single group
    /// the server named.
    ///
    /// ## Two refusals
    ///
    /// A **second** HelloRetryRequest is fatal: without that a server
    /// could loop a client indefinitely, and the RFC says one is the
    /// limit. And a retry asking for a group we already offered is
    /// fatal too - it cannot make progress, so it is either a mistake
    /// or an attempt to make us do work, and RFC 8446 section 4.1.4
    /// names it `illegal_parameter`.
    fn handle_retry_request(&mut self, hello: &ServerHello,
                            message: &HandshakeMessage) -> Result<(), Error> {
        if self.saw_retry_request {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                "The server sent a second HelloRetryRequest. RFC 8446 section \
                 4.1.4 allows one, and a client that answered every one could \
                 be kept in a loop."));
        }
        if hello.negotiated_version() != Version::TLS13 {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "A HelloRetryRequest arrived claiming {}, but it exists only \
                 in TLS 1.3.", hello.negotiated_version().name())));
        }
        // **Early data is over, and the writer goes back to plaintext.**
        // The second ClientHello is sent in the clear, and by now the
        // writer is on the early keys - so a client that did not put it
        // back would encrypt a hello the server reads as a record it
        // cannot decrypt. The server has already rejected the early data
        // by sending this at all (RFC 8446 4.2.10), and the records are
        // spent: they were derived over the *first* hello, which the
        // transcript is about to replace with a hash of itself.
        if self.early_keys.take().is_some() {
            self.writer.change_cipher_spec(Protection::Null);
            self.held_handshake_keys = None;
            self.offered_early_data = false;
            self.early_data_accepted = false;
        }
        let suite = suites::by_code(hello.cipher_suite).ok_or_else(|| Error::new(
            AlertDescription::ILLEGAL_PARAMETER, format!(
                "The HelloRetryRequest chose suite {:#06x}, which is not in the \
                 registry.", hello.cipher_suite)))?;
        if !self.config.suites.for_version(Version::TLS13)
                .was_offered(hello.cipher_suite) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The HelloRetryRequest chose {}, which this client did not \
                 offer.", suite.name)));
        }

        let wanted = find_extension(&hello.extensions, extension::KEY_SHARE)
            .ok_or_else(|| Error::new(AlertDescription::MISSING_EXTENSION,
                "The HelloRetryRequest carries no key_share, so it asks for \
                 nothing this client can act on."))
            .and_then(|e| hs13::parse_retry_key_share(&e.body)
                              .map_err(Error::from))?;

        if self.key_shares.iter().any(|share| share.group() == wanted) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The HelloRetryRequest asks for {}, which this client already \
                 sent a key share for. Answering would send the same hello \
                 again.", groups::name(wanted))));
        }
        if !OFFERED_GROUPS.contains(&wanted) && !groups::HYBRID.contains(&wanted) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The HelloRetryRequest asks for {}, which this client did not \
                 offer in supported_groups.", groups::name(wanted))));
        }

        // The cookie, if any, has to be echoed back verbatim - it is the
        // server's own state and it is not ours to interpret.
        self.retry_cookie = find_extension(&hello.extensions, extension::COOKIE)
            .map(|e| e.body.clone());

        // The synthetic first message, built before the hello is
        // replaced: it hashes the hello that actually went out.
        let hash_name = tls13_hash(suite)?;
        let mut hasher = crate::api::AnyHash::new(hash_name).map_err(Error::local)?;
        hasher.update(&self.client_hello_bytes);
        let synthetic = HandshakeMessage::new(HandshakeType::MessageHash,
                                              hasher.digest())?;

        // One share, for the group the server named.
        self.key_shares = vec![EphemeralKey::generate(wanted)
                               .map_err(Error::local)?];
        self.saw_retry_request = true;
        self.retry_choice = Some((hello.cipher_suite, wanted));

        let extensions = self.hello_extensions()?;
        let second = ClientHello {
            legacy_version: self.legacy_hello_version(),
            // The **same** random: a fresh one would be a different
            // handshake, and the server has already hashed this one.
            random: self.client_random,
            session_id: Vec::new(),
            cipher_suites: self.config.suites
                .for_version(self.config.max_version).to_hello(),
            compression_methods: vec![0],
            extensions,
        };
        let mut second = HandshakeMessage::new(HandshakeType::ClientHello,
                                               second.encode()?)?;

        let mut prefix = synthetic.raw;
        prefix.extend_from_slice(&message.raw);
        prefix.extend_from_slice(&second.raw);
        // **After a HelloRetryRequest the binder covers all three**:
        // RFC 8446 4.2.11.2, `Transcript-Hash(ClientHello1,
        // HelloRetryRequest, Truncate(ClientHello2))`. Binding only the
        // second hello would leave the retry unauthenticated, so the
        // whole prefix is what gets truncated and hashed - which is why
        // `seal_binders` takes it rather than the hello alone.
        self.seal_binders(&mut second.raw, &mut prefix)?;
        self.transcript_prefix = prefix;
        self.client_hello_bytes = second.raw.clone();

        self.emit_handshake(&second)?;
        // Still waiting for a ServerHello, and now for a real one.
        self.state = State::WaitServerHello;
        Ok(())
    }

    fn handle_server_hello(&mut self, message: &HandshakeMessage) -> Result<(), Error> {
        let hello = ServerHello::parse(&message.body)?;
        let version = hello.negotiated_version();

        // A HelloRetryRequest is a ServerHello with a fixed random, not a
        // message type of its own. Recognised here so it cannot be
        // mistaken for an ordinary one - which would mean deriving a
        // handshake secret from a key share the server never sent.
        if hello.random == hs13::HELLO_RETRY_REQUEST_RANDOM {
            return self.handle_retry_request(&hello, message);
        }
        // **After a retry, the real ServerHello is held to it.** The
        // retry already committed both ends to a suite - the second
        // hello's transcript hash is under that suite's hash - and to
        // TLS 1.3, which is the only version a HelloRetryRequest exists
        // in. A ServerHello choosing anything else would be a 1.2
        // handshake over a 1.3 transcript prefix, failing later and far
        // from the cause, or a downgrade. RFC 8446 4.1.4 names
        // illegal_parameter for all of it. The group is checked where
        // the share is read, in `handle_server_hello_13`.
        if let Some((suite, _)) = self.retry_choice {
            if version != Version::TLS13 {
                return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                    "After a HelloRetryRequest the ServerHello chose {}; the \
                     retry committed the handshake to TLS 1.3.", version.name())));
            }
            if hello.cipher_suite != suite {
                return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                    "After a HelloRetryRequest naming {} the ServerHello chose \
                     {}; the suite is settled by the retry.",
                    suites::describe_code(suite),
                    suites::describe_code(hello.cipher_suite))));
            }
        }

        if version < self.config.min_version || version > self.config.max_version {
            return Err(Error::new(AlertDescription::PROTOCOL_VERSION, format!(
                "The server chose {}, outside the {}..={} this client offered.",
                version.name(), self.config.min_version.name(),
                self.config.max_version.name())));
        }

        // **A server that supports more than it chose says so in its
        // random** (RFC 8446 4.1.3), and the marker is checked against
        // what this client offered: a hello that reached the server
        // with `supported_versions` stripped arrives as a 1.2 hello,
        // and the 1.2 handshake that follows signs the randoms rather
        // than the hello's extensions, so nothing later can notice.
        // A client offering 1.3 refuses either marker (a MUST for the
        // one matching the version chosen, a SHOULD for the other); a
        // client offering 1.2 refuses the 1.1 marker, which is the
        // RFC's SHOULD for it.
        {
            use crate::tls::handshake13::{DOWNGRADE_TO_TLS11, DOWNGRADE_TO_TLS12};
            let tail = &hello.random[24..];
            let ceiling = self.config.max_version;
            let refused = (ceiling >= Version::TLS13 && version <= Version::TLS12
                           && (tail == DOWNGRADE_TO_TLS12 || tail == DOWNGRADE_TO_TLS11))
                || (ceiling == Version::TLS12 && version < Version::TLS12
                    && tail == DOWNGRADE_TO_TLS11);
            if refused {
                return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                    "The server chose {} and its random says it supports more, \
                     which is what a hello cut down on the way looks like \
                     (RFC 8446 4.1.3).", version.name())));
            }
        }

        // A suite we did not offer is either a broken server or a
        // downgrade; accepting it is how one happens silently.
        //
        // **The message names the rule and says what we offered**,
        // because the two readings of this are opposite and the old
        // wording chose neither. A live GOST server answered a hello
        // offering exactly `TLS_GOSTR341001_WITH_28147_CNT_IMIT` with
        // suite `0x0031` - a suite nobody offered, nobody implements
        // here, and which is `TLS_DH_RSA_WITH_AES_128_CBC_SHA` to
        // IANA - and then sent its ordinary GOST **2012** certificate,
        // byte for byte the one it serves for 0xC102. It has no 2001
        // certificate, so it could not satisfy the request; instead of
        // `handshake_failure` it produced a ServerHello with a
        // nonsense suite. That is its refusal path rather than a fault
        // here, which took some establishing.
        let offered = self.config.suites.for_version(version);
        if !offered.was_offered(hello.cipher_suite) {
            // Naming them is only useful while there are few, which is
            // exactly the case that is being diagnosed: a probe
            // offering one suite and getting another.
            let ours = offered.names();
            // **The empty case is a different finding, not a shorter
            // list.** `ours.len() <= 4` is true of an empty list too, so
            // this used to print "it offered ." - a reader told the
            // client offered something, shown nothing, and left worse
            // off than with no list at all. It came from a real run:
            // `check_live.py --gost` offers one suite per connection, and
            // four of its rows offer only the RFC 9367 MGM suites, which
            // are TLS 1.3 only. CryptoPro answers TLS 1.2, every offered
            // suite is filtered out by version, and the list is empty.
            //
            // Which is the whole diagnosis, so it is what gets said:
            // every suite in the hello needs a newer version than the
            // server chose. That is a different conversation from "we
            // offered these three and it picked a fourth", and the reader
            // cannot act on either without being told which.
            let listed = if ours.is_empty() {
                let all = self.config.suites.names();
                let floor = self.config.suites.codes().iter()
                    .filter_map(|code| suites::by_code(*code))
                    .map(|suite| suite.min_version)
                    .min();
                match floor {
                    Some(floor) => format!(
                        "offered {} suite(s) - {} - and every one of them needs {} or \
                         later, so none was available at the {} the \
                         server chose",
                        all.len(), all.join(", "), floor.name(), version.name()),
                    // No suites at all, which `ClientConnection::new`
                    // should have refused long before a ServerHello - said
                    // plainly rather than printed as an empty list.
                    None => "offered no suites at all, which is a configuration \
                             error here rather than a server fault".to_string(),
                }
            } else if ours.len() <= 4 {
                format!("offered {}", ours.join(", "))
            } else {
                format!("offered {} suites, none of them this", ours.len())
            };
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server chose {}, which this client did not offer - it \
                 {}. RFC 5246 7.4.1.3 requires the selected suite to be one \
                 from the ClientHello, so this is the server breaking that, \
                 not a suite this library is missing.",
                suites::describe_code(hello.cipher_suite), listed)));
        }
        let suite = suites::by_code(hello.cipher_suite).ok_or_else(|| Error::new(
            AlertDescription::ILLEGAL_PARAMETER,
            format!("The server chose {}, which this library does not know.",
                    suites::describe_code(hello.cipher_suite))))?;
        if !suite.is_implemented() {
            return Err(Error::new(AlertDescription::HANDSHAKE_FAILURE, format!(
                "The server chose {}, which is in the registry but not \
                 implemented yet.", suite.name)));
        }
        // There used to be a second list of the key exchanges we can do,
        // right here, duplicating the one inside `is_implemented`. Two
        // lists of the same fact drift: adding DHE to the registry's list
        // left this one refusing the suite the client had just offered,
        // with a message saying it was not implemented while it was.
        // `is_implemented` is the single answer.
        if hello.compression_method != 0 {
            // Compression is CRIME. There is one legal value.
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                                  "The server selected compression."));
        }

        if version >= Version::TLS13 {
            return self.handle_server_hello_13(&hello, message, suite);
        }

        // A server must not answer with an extension the client did not
        // offer. RFC 5246 forbids it and it is a sign of something strange.
        let offered = [extension::SERVER_NAME, extension::SIGNATURE_ALGORITHMS,
                       extension::ENCRYPT_THEN_MAC, extension::EXTENDED_MASTER_SECRET,
                       extension::RENEGOTIATION_INFO, extension::SESSION_TICKET,
                       extension::SUPPORTED_VERSIONS, extension::EC_POINT_FORMATS,
                       extension::ALPN, extension::STATUS_REQUEST];
        for answer in &hello.extensions {
            if !offered.contains(&answer.kind) {
                return Err(Error::new(AlertDescription::UNSUPPORTED_EXTENSION, format!(
                    "The server answered with {}, which this client did not offer.",
                    extension::name(answer.kind))));
            }
        }

        // **ALPN answers in the ServerHello at 1.2 and in
        // EncryptedExtensions at 1.3.** Reading it in one place would
        // mean accepting it in the wrong one, and at 1.3 that is an
        // answer sent in the clear.
        self.negotiated_alpn = self.read_alpn_answer(&hello.extensions)?;
        // **Empty here, and it only says one is coming.** RFC 6066 §8
        // makes the ServerHello's `status_request` an acknowledgement
        // with no body; the response arrives in its own message, and
        // even then it is optional. So this is permission to accept one
        // rather than a promise of one.
        if let Some(answer) = find_extension(&hello.extensions,
                                             extension::STATUS_REQUEST) {
            if !answer.body.is_empty() {
                return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                    "The ServerHello's status_request has a body. RFC 6066 \
                     section 8 makes it an empty acknowledgement; the \
                     response goes in a CertificateStatus message."));
            }
            self.expect_certificate_status = true;
        }

        self.encrypt_then_mac = self.config.request_encrypt_then_mac
            && find_extension(&hello.extensions, extension::ENCRYPT_THEN_MAC).is_some();
        // **Not for a GOST suite**, whatever the server answered. RFC
        // 9189 section 4.2.1 says the ServerHello MUST NOT carry
        // encrypt_then_mac with these suites, and it is easy to see
        // why: their record protection is CTR_OMAC or CNT_IMIT, which
        // have no CBC padding for RFC 7366 to move the MAC around.
        //
        // A server that sends it anyway is answered by ignoring it
        // rather than by hanging up. Nothing downstream reads the flag
        // for these suites - it is only consulted inside `CbcHmac` -
        // so refusing the connection would cost a reachable box for a
        // field that changes nothing. What it must not do is leave
        // `uses_encrypt_then_mac` saying yes about a connection that
        // has no such thing.
        if suite.key_exchange == crate::tls::suites::KeyExchange::GostVko {
            self.encrypt_then_mac = false;
        }
        self.extended_master_secret = self.config.request_extended_master_secret
            && find_extension(&hello.extensions,
                              extension::EXTENDED_MASTER_SECRET).is_some();

        self.server_random = hello.random;
        self.negotiated_version = Some(version);
        self.suite = Some(suite);

        // Both sides pin the version now, so a later record claiming
        // something else is refused before it is decrypted.
        self.reader.expect_version(version);
        self.writer.set_version(version);

        // The transcript starts with the ClientHello, which was written
        // before the hash algorithm was known - so it is built here and the
        // ClientHello is replayed into it.
        let mut transcript = Transcript::new(version, suite.prf).map_err(Error::local)?;
        if self.config.client_certificate.is_some() {
            // **Before the first update.** A TLS 1.2 CertificateVerify
            // signs the raw concatenation under a hash the message
            // itself names, so it cannot come from the running hashes -
            // and a buffer started late covers the wrong bytes, which
            // fails at the server's verification rather than here.
            //
            // Only when there is an identity to send: otherwise this is
            // a few kilobytes per connection bought for nothing.
            transcript.keep_messages();
        }
        transcript.update(&self.client_hello_raw()?);
        transcript.update(&message.raw);
        self.transcript = Some(transcript);

        self.state = State::WaitCertificate;
        Ok(())
    }

    // ------------------------------------------------------- TLS 1.3 ---

    /// The ServerHello of a TLS 1.3 handshake.
    ///
    /// Everything happens here. By the end of this function the key
    /// exchange is done, the schedule is at its handshake stage, and both
    /// directions are encrypted - which is why the rest of the server's
    /// flight arrives protected and why a 1.3 handshake reveals nothing
    /// after this point.
    fn handle_server_hello_13(&mut self, hello: &ServerHello,
                              message: &HandshakeMessage,
                              suite: &'static CipherSuite) -> Result<(), Error> {
        if suite.min_version < Version::TLS13 {
            // A 1.2 suite code in a 1.3 ServerHello. The two registries
            // overlap in numbering and not in meaning, and a suite from
            // the wrong one would name a key exchange that 1.3 does not
            // have.
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server chose {} for a TLS 1.3 connection; that is a \
                 TLS 1.2 suite.", suite.name)));
        }

        // A 1.3 ServerHello may only answer with these. Anything else -
        // encrypt_then_mac, extended_master_secret, a session ticket -
        // belongs to a version that is not being spoken.
        for answer in &hello.extensions {
            if !matches!(answer.kind,
                         extension::SUPPORTED_VERSIONS | extension::KEY_SHARE
                             | extension::PRE_SHARED_KEY) {
                return Err(Error::new(AlertDescription::UNSUPPORTED_EXTENSION, format!(
                    "A TLS 1.3 ServerHello answered with {}, which belongs in \
                     EncryptedExtensions or in an earlier version.",
                    extension::name(answer.kind))));
            }
        }
        // A selected PSK, if we offered any. Resolved before the key
        // share, because the suite's hash has to match the ticket's and
        // that is a reason to refuse the whole hello.
        let psk = self.selected_psk(hello, suite)?;

        let share = find_extension(&hello.extensions, extension::KEY_SHARE)
            .ok_or_else(|| Error::new(AlertDescription::MISSING_EXTENSION,
                "A TLS 1.3 ServerHello must carry a key_share; without one there \
                 is no key exchange and nothing authenticates the connection."))?;
        let answer = hs13::parse_server_key_share(&share.body)?;
        if let Some((_, group)) = self.retry_choice {
            if answer.group != group {
                return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                    "The HelloRetryRequest asked for {} and the ServerHello \
                     answered with a {} key share.",
                    groups::name(group), groups::name(answer.group))));
            }
        }

        // The share must answer one we sent. A server naming a group we
        // only listed in supported_groups has no key of ours to combine
        // with, and accepting it would mean completing against the wrong
        // private key or none.
        let ours = self.key_shares.iter().find(|s| s.group() == answer.group)
            .ok_or_else(|| Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server answered with a {} key share; this client sent \
                 shares for {}. A server wanting another group must send a \
                 HelloRetryRequest.",
                groups::name(answer.group),
                self.key_shares.iter().map(|s| groups::name(s.group()))
                    .collect::<Vec<_>>().join(", "))))?;
        self.negotiated_group = Some(answer.group);
        // A peer's key that will not complete is a parameter we cannot
        // use, which is `illegal_parameter` rather than an internal
        // fault - the alert says whose fault it is.
        let shared = ours.complete(&answer.key_exchange)
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;

        self.server_random = hello.random;
        self.negotiated_version = Some(Version::TLS13);
        self.suite = Some(suite);

        // The record header's version is fixed at 0x0303 in 1.3, so the
        // reader must expect that rather than the negotiated version.
        // `Protection::Aead13` makes it check exactly that, and setting
        // `expect_version(TLS13)` here would refuse every record.
        self.writer.set_version(crate::tls::record13::LEGACY_RECORD_VERSION);

        let mut transcript = Transcript::new(Version::TLS13, suite.prf)
            .map_err(Error::local)?;
        transcript.update(&self.client_hello_raw()?);
        transcript.update(&message.raw);
        let hello_hash = transcript.hash();
        self.transcript = Some(transcript);

        let aead = tls13_aead(suite)?;
        let hash = tls13_hash(suite)?;

        // The PSK is the Early Secret's input keying material. With
        // none, RFC 8446 7.1 says to use `Hash.length` zero bytes -
        // which `Schedule::early` does for `None`, so the resumed and
        // fresh paths differ in exactly this argument and nowhere else.
        let schedule = Schedule::early(suite.prf, psk.as_deref())
            .map_err(Error::local)?
            .handshake(&shared).map_err(Error::local)?;
        let (client, server) = schedule
            .handshake_traffic(&hello_hash, aead.key_len, aead.iv_len)
            .map_err(Error::local)?;

        self.tls13 = Some(Tls13 {
            hash, aead,
            client_finished_key: client.finished_key.clone(),
            server_finished_key: server.finished_key.clone(),
            schedule,
            resumption_master: None,
            exporter_master: None,
        });

        // The middlebox compatibility ChangeCipherSpec, sent in the clear
        // and before the writer changes keys (RFC 8446 appendix D.4). It
        // is not part of the handshake and never goes into the transcript;
        // it exists so that a network appliance watching for one sees it
        // and lets the connection through.
        //
        // A 0-RTT client has already sent it, right after the hello,
        // because from that point its writer was encrypting.
        if self.early_keys.is_none() {
            let bytes = self.writer.write(ContentType::ChangeCipherSpec, &[1])?;
            self.outgoing.extend_from_slice(&bytes);
        }

        self.reader.change_cipher_spec(Protection::Aead13(
            Aead13::with_rekeying(aead.name, hash, server, aead.tag_len,
                                  aead.mgm).map_err(Error::local)?));
        if self.early_keys.is_some() {
            // **The writer stays on the early keys** until EndOfEarlyData
            // has gone out under them. Switching here would encrypt that
            // message with the handshake key, and the server - which is
            // still reading with the early key, because it is waiting for
            // exactly that message - would see a record that does not
            // authenticate.
            //
            // Held rather than re-derived: re-deriving needs the
            // transcript hash through the ServerHello, which has moved on
            // by the time the server's Finished arrives.
            self.held_handshake_keys = Some(client);
        } else {
            self.writer.change_cipher_spec(Protection::Aead13(
                Aead13::with_rekeying(aead.name, hash, client, aead.tag_len,
                                      aead.mgm).map_err(Error::local)?));
        }

        self.state = State::WaitEncryptedExtensions;
        Ok(())
    }

    /// The PSK the server chose, if it chose one.
    ///
    /// Four checks, and RFC 8446 4.2.11 makes every one of them a MUST
    /// for the client:
    ///
    ///   * we offered a `pre_shared_key` at all. A server selecting one
    ///     we did not offer is answering a question nobody asked;
    ///   * `selected_identity` is within the range we sent. An index
    ///     past the end would otherwise be a panic or, worse, a wrap
    ///     into somebody else's ticket;
    ///   * the suite's KDF hash is the ticket's. RFC 8446 4.6.1 binds a
    ///     ticket to a hash, and a mismatch means the binder the server
    ///     just verified was computed under a different schedule from
    ///     the one about to be used;
    ///   * a `key_share` is present, because the only mode offered is
    ///     `psk_dhe_ke`. Without one the connection would have no
    ///     (EC)DHE in it and no forward secrecy, which is the thing
    ///     `psk_ke` was left out to avoid.
    fn selected_psk(&mut self, hello: &ServerHello, suite: &'static CipherSuite)
                    -> Result<Option<Vec<u8>>, Error> {
        let answer = match find_extension(&hello.extensions,
                                          extension::PRE_SHARED_KEY) {
            Some(answer) => answer,
            None => return Ok(None),
        };
        let (_, tickets) = self.psk_offer.as_ref().ok_or_else(|| Error::new(
            AlertDescription::UNSUPPORTED_EXTENSION,
            "The server selected a pre-shared key, which this client did not \
             offer."))?;

        let selected = hs13::parse_server_pre_shared_key(&answer.body)?;
        let ticket = tickets.get(usize::from(selected)).ok_or_else(|| Error::new(
            AlertDescription::ILLEGAL_PARAMETER, format!(
            "The server selected pre-shared key {}, and this client offered \
             {}.", selected, tickets.len())))?;

        let hash = tls13_hash(suite)?;
        if !ticket.matches_hash(hash) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server resumed with {}, whose KDF hash is {}, against a \
                 ticket issued under {}. RFC 8446 4.6.1 requires them to \
                 match.", suite.name, hash, ticket.hash)));
        }
        if find_extension(&hello.extensions, extension::KEY_SHARE).is_none() {
            return Err(Error::new(AlertDescription::MISSING_EXTENSION,
                "The server resumed without a key_share. This client offers \
                 only psk_dhe_ke, so a resumption with no (EC)DHE in it has \
                 no forward secrecy and is not what was asked for."));
        }
        self.resumed = true;
        Ok(Some(ticket.psk.clone()))
    }

    /// A `NewSessionTicket`, kept for a later connection.
    ///
    /// The ticket is stored with a PSK derived from *this* connection's
    /// resumption master secret and the ticket's own nonce - so the key
    /// never crosses the wire and two tickets from one connection are
    /// two different keys.
    ///
    /// Two kinds of bad ticket, treated differently on purpose.
    ///
    /// A **malformed** one fails the connection. It is a post-handshake
    /// message under the application keys, so it is authenticated: a
    /// peer sending one that does not parse is broken or something odd
    /// is going on, and RFC 8446 aborts on a message it cannot decode
    /// like any other.
    ///
    /// A **well formed but unusable** one is dropped. A zero lifetime
    /// means "discard immediately" and is the server's business; a
    /// working connection must not be torn down over an offer nobody
    /// has to accept.
    fn handle_new_session_ticket(&mut self, message: &HandshakeMessage)
                                 -> Result<(), Error> {
        if self.negotiated_version != Some(Version::TLS13) {
            // The TLS 1.2 message of the same name is a different
            // structure entirely, and this client does not resume 1.2.
            return Ok(());
        }
        let ticket = hs13::NewSessionTicket13::parse(&message.body)?;
        let state = match &self.tls13 {
            Some(state) => state,
            None => return Ok(()),
        };
        let suite = match self.suite {
            Some(suite) => suite,
            None => return Ok(()),
        };
        // Taken from when the handshake ended, not derived now: the
        // transcript has moved on, and this message is already in it.
        let resumption_master = match &state.resumption_master {
            Some(secret) => secret.clone(),
            None => return Ok(()),
        };

        if let Ok(ticket) = Ticket::from_message(
                &ticket, &resumption_master, state.hash, suite.code,
                &self.hostname, self.config.policy.now) {
            self.tickets.push(ticket);
        }
        // An unusable ticket is dropped here. See the note above for
        // why that is not the same as a malformed one, which
        // `NewSessionTicket13::parse` has already refused.
        Ok(())
    }

    fn handle_encrypted_extensions(&mut self, message: &HandshakeMessage)
                                   -> Result<(), Error> {
        let encrypted = EncryptedExtensions::parse(&message.body)?;
        // Everything the server tells us about the connection that is not
        // needed to derive keys arrives here, now that it is encrypted.
        // A key_share or a supported_versions in here is the server
        // putting a ServerHello extension somewhere it cannot be checked.
        for answer in &encrypted.extensions {
            if matches!(answer.kind, extension::KEY_SHARE
                                   | extension::SUPPORTED_VERSIONS
                                   | extension::SIGNATURE_ALGORITHMS) {
                return Err(Error::new(AlertDescription::UNSUPPORTED_EXTENSION, format!(
                    "EncryptedExtensions carried {}, which belongs in the \
                     ServerHello.", extension::name(answer.kind))));
            }
        }
        // **A resumed handshake has no Certificate and no
        // CertificateVerify.** The PSK is what authenticates the
        // server, and it authenticates it because only the peer that
        // ran the original handshake could have derived the same key.
        // So the next message is the server's Finished, and a
        // Certificate arriving here is a server trying to re-do an
        // authentication that has already happened by other means -
        // which the state machine refuses by not having a transition
        // for it.
        // **`early_data` here means accepted, and it must be empty.**
        // The extension carries a `max_early_data_size` in a
        // NewSessionTicket and in no other message; one with a body here
        // is a server that has confused the two forms, and taking it as
        // an acceptance would leave us writing EndOfEarlyData to a peer
        // that is not expecting one.
        let accepted = match find_extension(&encrypted.extensions,
                                            extension::EARLY_DATA) {
            Some(answer) => {
                if !answer.body.is_empty() {
                    return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                        "The early_data extension is empty everywhere but a \
                         NewSessionTicket; this EncryptedExtensions gave \
                         it a body."));
                }
                true
            }
            None => false,
        };
        if accepted && !self.offered_early_data {
            // A server cannot accept what was not offered, and a client
            // that shrugged would then send an EndOfEarlyData nobody
            // asked for.
            return Err(Error::new(AlertDescription::UNSUPPORTED_EXTENSION,
                "The server accepted early data that was never offered."));
        }
        self.early_data_accepted = accepted;
        if self.offered_early_data && !accepted {
            // **Declined.** The records are already sent and the server
            // is discarding them. Switch the writer to the handshake keys
            // now: there is no EndOfEarlyData in this case - RFC 8446
            // 4.2.10 - because the server never moved to the early keys
            // and would not be able to read it.
            self.finish_early_data(false)?;
        }

        self.negotiated_alpn = self.read_alpn_answer(&encrypted.extensions)?;

        self.state = if self.resumed {
            State::WaitServerFinished13
        } else {
            State::WaitCertificate13
        };
        Ok(())
    }

    /// Stop writing under the early keys.
    ///
    /// `send_end_of_early_data` is true when the server accepted, in
    /// which case the message goes out **under the early keys** and
    /// **into the transcript** (RFC 8446 4.5): the client's Finished has
    /// to cover the fact that early data happened, or stripping a 0-RTT
    /// flight would go unnoticed.
    ///
    /// When it declined there is no such message. The server never
    /// derived the early keys, so a record written under them is one it
    /// cannot read - which is why this is a parameter rather than
    /// something inferred from "we offered".
    fn finish_early_data(&mut self, send_end_of_early_data: bool)
                         -> Result<(), Error> {
        if self.early_keys.is_none() {
            return Ok(());
        }
        if send_end_of_early_data {
            let message = HandshakeMessage::new(HandshakeType::EndOfEarlyData,
                                                Vec::new())?;
            self.emit_handshake(&message)?;
            if let Some(transcript) = self.transcript.as_mut() {
                transcript.update(&message.raw);
            }
        }
        let keys = self.held_handshake_keys.take().ok_or_else(||
            Error::local("No held-back client handshake keys."))?;
        let (aead, hash, tag_len) = {
            let state = self.tls13.as_ref()
                .ok_or_else(|| Error::local("No TLS 1.3 state."))?;
            (state.aead, state.hash, state.aead.tag_len)
        };
        self.writer.change_cipher_spec(Protection::Aead13(
            Aead13::with_rekeying(aead.name, hash, keys, tag_len, aead.mgm)
                .map_err(Error::local)?));
        self.early_keys = None;
        Ok(())
    }

    /// The protocol the server chose, or `None` if it chose none.
    ///
    /// `None` covers "we offered none", "the server has none in common"
    /// and "the server does not do ALPN" - all the same on the wire, and
    /// all meaning the application decides the protocol some other way.
    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }

    /// The server's answer to `application_layer_protocol_negotiation`.
    ///
    /// **Exactly one protocol, and one we offered.** RFC 7301 4.2 makes
    /// the answer a list of length one; a longer one is a server that has
    /// not chosen, and a protocol we did not offer is a server answering
    /// a question nobody asked - which, if shrugged at, is an
    /// application talking a protocol it never agreed to.
    fn read_alpn_answer(&self, extensions: &[Extension])
                        -> Result<Option<String>, Error> {
        let answer = match find_extension(extensions, extension::ALPN) {
            Some(answer) => answer,
            None => return Ok(None),
        };
        if self.config.alpn.is_empty() {
            return Err(Error::new(AlertDescription::UNSUPPORTED_EXTENSION,
                "The server selected an application protocol, which this \
                 client did not ask for."));
        }
        let mut reader = crate::tls::codec::Reader::new(&answer.body);
        let mut list = reader.sub16()?;
        let chosen = list.vector8()?.to_vec();
        if !list.is_empty() {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                "The server's ALPN answer names more than one protocol. \
                 RFC 7301 4.2 says it selects exactly one."));
        }
        reader.expect_empty("the ALPN answer")?;
        let chosen = String::from_utf8(chosen).map_err(|_| Error::new(
            AlertDescription::ILLEGAL_PARAMETER,
            "The server's ALPN answer is not valid UTF-8."))?;
        if !self.config.alpn.contains(&chosen) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server chose the application protocol {:?}, which this \
                 client did not offer.", chosen)));
        }
        Ok(Some(chosen))
    }

    /// Whether the server accepted the early data that was offered.
    ///
    /// False after offering is the ordinary rejection and not an error -
    /// but the bytes did not arrive, and **they are not resent
    /// automatically**. Whether sending them again is acceptable is the
    /// caller's decision, the same decision that made them early data.
    pub fn early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    /// The server asking the client to authenticate.
    ///
    /// It arrives between EncryptedExtensions and the server's own
    /// Certificate, and it does not advance the state: the very next
    /// message is still the server's Certificate. All this does is
    /// remember that an answer is owed, because the answer is sent much
    /// later - after the server's Finished, in the client's own flight.
    ///
    /// **The context must be empty here.** A non-empty one belongs to
    /// post-handshake authentication (RFC 8446 4.6.2), which this client
    /// does not implement; accepting it and echoing it would answer a
    /// question we did not understand.
    fn handle_certificate_request_13(&mut self, message: &HandshakeMessage)
                                     -> Result<(), Error> {
        if self.certificate_request.is_some() {
            // The state allows any number of messages before the
            // Certificate, so the count is checked here rather than by
            // the state machine. Two requests are two different questions
            // and only one can be answered.
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                                  "A second CertificateRequest."));
        }
        let request = hs13::CertificateRequest13::parse(&message.body)?;
        if !request.context.is_empty() {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                                  "The CertificateRequest carries a context, \
                                   which is post-handshake authentication. \
                                   This client does not implement it."));
        }
        self.certificate_request = Some(request);
        Ok(())
    }

    fn handle_certificate_13(&mut self, message: &HandshakeMessage)
                             -> Result<(), Error> {
        let chain = Certificate13::parse(&message.body)?;
        if chain.entries.is_empty() {
            return Err(Error::new(AlertDescription::DECODE_ERROR,
                                  "The server sent an empty certificate chain."));
        }
        if !chain.request_context.is_empty() {
            // The context is echoed from a CertificateRequest, and a
            // server's own certificate answers no request.
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                                  "The server's Certificate carries a request \
                                   context, which only a client's answer has."));
        }
        // **The staple hangs off the leaf's entry**, not off the
        // connection: TLS 1.3 has no CertificateStatus message, and RFC
        // 8446 4.4.2.1 puts a `status_request` extension on each entry.
        // Read before the chain is verified, because verification is
        // where it gets checked and the issuer is in this same chain.
        //
        // Only the leaf's is taken. A response about an intermediate is
        // an answer to a different question, and treating one as the
        // leaf's would be reading "good" about the wrong certificate.
        if let Some(answer) = chain.entries.first()
            .and_then(|entry| find_extension(&entry.extensions,
                                             extension::STATUS_REQUEST)) {
            if !self.config.request_stapled_ocsp {
                return Err(Error::new(AlertDescription::UNSUPPORTED_EXTENSION,
                    "The server stapled an OCSP response that was never \
                     requested."));
            }
            let response = crate::tls::handshake::parse_certificate_status(
                &answer.body)
                .map_err(|reason| Error::new(AlertDescription::DECODE_ERROR,
                                             reason))?;
            self.stapled_ocsp = Some(response);
        }

        self.certificates = chain.chain();
        if self.config.verify_certificate {
            self.verify_peer()?;
            self.certificate_verified = true;
        }
        self.state = State::WaitCertificateVerify;
        Ok(())
    }

    /// The signature that makes the certificate mean anything.
    ///
    /// In TLS 1.2 the certificate's key signs the *key exchange*, so a
    /// signature is only present when there is one to sign. In 1.3 it
    /// signs the transcript, every time - which is why an unauthenticated
    /// 1.3 handshake is not a shape the protocol has.
    fn handle_certificate_verify(&mut self, message: &HandshakeMessage)
                                 -> Result<(), Error> {
        let verify = CertificateVerify::parse(&message.body)?;

        // RFC 8446 section 4.4.3: an RSA signature here must be PSS. The
        // rsa_pkcs1_* codepoints are offered in signature_algorithms
        // because a *certificate* may be signed with one, and a server
        // using one here is either broken or downgrading.
        if !scheme::allowed_in_certificate_verify(verify.scheme) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server signed its CertificateVerify with {}. RFC 8446 \
                 4.4.3 allows those codepoints only for signatures inside \
                 certificates.", scheme::name(verify.scheme))));
        }
        // RFC 9367's seven are in the hello only when a 1.3 GOST suite
        // is offered, so they are checked the same way rather than
        // being added to `OFFERED` - a scheme offered with no suite
        // that can use it is a row nothing checks.
        let offered = scheme::OFFERED.contains(&verify.scheme)
            || (scheme::is_gost_13(verify.scheme)
                && self.config.suites.offers_gost_13());
        if !offered {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server signed with {}, which this client did not offer.",
                scheme::name(verify.scheme))));
        }

        // The transcript at this point covers everything up to and
        // including the Certificate - `handle_handshake` has already added
        // this message, so the hash has to be taken before it. That is why
        // CertificateVerify is one of the two messages whose transcript
        // update is deferred.
        let transcript = self.transcript.as_ref()
            .ok_or_else(|| Error::local("No transcript."))?;
        let content = hs13::certificate_verify_content(Side13::Server,
                                                       &transcript.hash());

        let leaf = Certificate::parse(&self.certificates[0])
            .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
        // **EdDSA first, because there is no digest to compute.** Every
        // other scheme here hashes `content` and hands the digest to a
        // verifier; EdDSA signs the message itself, hashing internally
        // with a prefix of its own. Handing it a digest would check a
        // signature over the hash of the transcript hash - which is
        // self-consistent and matches no peer. `scheme::hash_name`
        // returns `None` for these two, so the line below would refuse
        // them outright before the key was ever looked at.
        if matches!(verify.scheme, scheme::ED25519 | scheme::ED448) {
            verify_eddsa(&leaf.public_key, verify.scheme, &content, &verify.signature)?;
            // **The state transition, which the early return above
            // would otherwise skip.** It cost a handshake that failed
            // with "Received finished while waiting for the server's
            // CertificateVerify" - a message about the *next* step,
            // which reads as the peer having sent the wrong thing.
            // Every early return out of a state handler has to carry
            // the transition with it - and the record of which scheme
            // was used, which this one once did not.
            self.peer_signature_scheme = Some(verify.scheme);
            self.state = State::WaitServerFinished13;
            return Ok(());
        }

        // ML-DSA likewise signs `content` itself (draft-ietf-tls-mldsa
        // section 3.2), with FIPS 204's empty context - which is not the
        // context *string* already inside `content`.
        if let Some(named) = scheme::ml_dsa_parameter_set(verify.scheme) {
            verify_ml_dsa_13(&leaf.public_key, verify.scheme, named, &content,
                             &verify.signature)?;
            self.peer_signature_scheme = Some(verify.scheme);
            self.state = State::WaitServerFinished13;
            return Ok(());
        }

        let hash_name = scheme::hash_name(verify.scheme).ok_or_else(|| Error::new(
            AlertDescription::ILLEGAL_PARAMETER,
            format!("{} names no hash this library knows.",
                    scheme::name(verify.scheme))))?;

        let mut hash = AnyHash::new(hash_name).map_err(Error::local)?;
        hash.update(&content);
        let digest = hash.digest();

        let valid = match &leaf.public_key {
            PublicKey::Rsa { n, e } if scheme::is_pss(verify.scheme) => {
                key_ceiling(&self.config.policy, "The server's RSA key", n.bit_len())?;
                let key = rsa::RsaPublicKey::new(n.clone(), e.clone())
                    .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
                if key.bits() < self.config.policy.min_rsa_bits {
                    return Err(Error::new(AlertDescription::INSUFFICIENT_SECURITY,
                        format!("The server's RSA key is {} bits; the policy \
                                 requires {}.", key.bits(),
                                self.config.policy.min_rsa_bits)));
                }
                // The salt length is not recoverable from the signature,
                // and RFC 8446 fixes it at the hash's own length.
                let salt_len = rsa::pss_salt_len(hash_name).map_err(Error::local)?;
                rsa::verify_pss(&key, hash_name, &digest, &verify.signature, salt_len)
                    .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
            }
            PublicKey::Ec { curve, point } => {
                // TLS 1.3 binds the curve to the scheme, which TLS 1.2 did
                // not: a P-256 key may only sign with
                // ecdsa_secp256r1_sha256. Checking it closes the gap where
                // a peer picks a hash that does not match the curve.
                match scheme::curve_name(verify.scheme) {
                    Some(named) if named == *curve => {}
                    Some(named) => return Err(Error::new(
                        AlertDescription::ILLEGAL_PARAMETER, format!(
                            "The server signed with {}, which is bound to {}, \
                             but its certificate carries a {} key.",
                            scheme::name(verify.scheme), named, curve))),
                    None => return Err(Error::new(
                        AlertDescription::ILLEGAL_PARAMETER, format!(
                            "The server signed with {} using an EC key.",
                            scheme::name(verify.scheme)))),
                }
                let handle = curves::by_name(curve).map_err(Error::local)?;
                let public = handle.decode_point(point).map_err(|e| Error::new(
                    AlertDescription::BAD_CERTIFICATE, e))?;
                let signature = crate::x509::verify::decode_ecdsa_der(&verify.signature)
                    .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
                handle.verify(&public, &digest, &signature)
                    .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
            }
            PublicKey::Gost { curve, x, y, .. }
                    if scheme::is_gost_13(verify.scheme) => {
                // RFC 9367 section 5.2 binds each scheme to one curve,
                // the way TLS 1.3 binds ECDSA's - and here the binding
                // is doing more work, because the seven schemes cover
                // curves of two different sizes and the digest follows
                // the key rather than the curve's name.
                match scheme::curve_name(verify.scheme) {
                    Some(named) if named == *curve => {}
                    Some(named) => return Err(Error::new(
                        AlertDescription::ILLEGAL_PARAMETER, format!(
                            "The server signed with {}, which RFC 9367 binds \
                             to {}, but its certificate is on {}.",
                            scheme::name(verify.scheme), named, curve))),
                    None => return Err(Error::new(
                        AlertDescription::ILLEGAL_PARAMETER, format!(
                            "The server signed with {} using a GOST key.",
                            scheme::name(verify.scheme)))),
                }
                let handle = curves::by_name(curve).map_err(Error::local)?;
                let public = crate::ec::Point::new(x.clone(), y.clone());
                // **Not the certificate's encoding.** RFC 9215 writes a
                // signature as `s || r` big endian and RFC 9367 section
                // 5.3 writes this one as `str_l(r) | str_l(s)` - the
                // components the other way round *and* each reversed.
                // Either change alone gives a signature of exactly the
                // right length that verifies against nothing, so the
                // two encodings cannot be told apart by shape.
                let signature = handle.gost_signature_from_bytes_13(&verify.signature)
                    .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
                handle.gost_verify(&public, &digest, &signature)
                    .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
            }
            other => return Err(Error::new(AlertDescription::UNSUPPORTED_CERTIFICATE,
                format!("The server signed with {} but its certificate carries {}.",
                        scheme::name(verify.scheme),
                        crate::x509::verify::describe_key(other)))),
        };

        if !valid {
            return Err(Error::new(AlertDescription::DECRYPT_ERROR,
                "The server's CertificateVerify does not verify against its \
                 certificate. The transcript is not the one it signed, which is \
                 what a man in the middle looks like."));
        }

        self.peer_signature_scheme = Some(verify.scheme);
        self.state = State::WaitServerFinished13;
        Ok(())
    }

    /// The server's Finished, and then everything that follows from it.
    ///
    /// Three things happen at this one point, and the order matters. The
    /// Finished is checked against the transcript *before* it; the
    /// application secrets are derived from the transcript *including* it;
    /// and our own Finished is computed over that same transcript under
    /// the *handshake* key, which is why the handshake key has to outlive
    /// the writer's switch to the application key.
    fn handle_finished_13(&mut self, message: &HandshakeMessage) -> Result<(), Error> {
        let finished = Finished::parse(&message.body)?;

        let hash = {
            let state = self.tls13.as_ref()
                .ok_or_else(|| Error::local("No TLS 1.3 state."))?;
            state.hash
        };
        let transcript = self.transcript.as_ref()
            .ok_or_else(|| Error::local("No transcript."))?;

        let expected = {
            let state = self.tls13.as_ref().unwrap();
            keys13::finished(hash, &state.server_finished_key, &transcript.hash())
                .map_err(Error::local)?
        };
        if !keys::verify_data_matches(&expected, &finished.verify_data) {
            return Err(Error::new(AlertDescription::DECRYPT_ERROR,
                "The server's Finished does not match the handshake we saw. The \
                 handshake was tampered with, or the keys disagree."));
        }

        // The peer's Finished, for `tls-unique` on a resumed connection.
        // See `own_finished`/`peer_finished`.
        self.peer_finished = Some(finished.verify_data.clone());

        // The transcript for everything below includes this Finished, so
        // it is added now rather than by `handle_handshake` - which
        // defers it and would add it after this returns.
        let transcript_hash = {
            let transcript = self.transcript.as_mut().unwrap();
            transcript.update(&message.raw);
            transcript.hash()
        };

        let state = self.tls13.as_mut().unwrap();
        let master = state.schedule.master().map_err(Error::local)?;
        let (client_app, server_app) =
            master.application_traffic(&transcript_hash, state.aead.key_len,
                                       state.aead.iv_len)
                .map_err(Error::local)?;

        // **The exporter master secret is taken here**, over the same
        // transcript as the application keys - through the server's
        // Finished, one message *earlier* than the resumption master
        // secret below. Taking it later, where it would be more
        // convenient, gives a different secret with no error anywhere:
        // every value is the right length and only the peer disagrees.
        let exporter_master = master.exporter_master(&transcript_hash)
            .map_err(Error::local)?;

        state.schedule = master;
        state.exporter_master = Some(exporter_master);

        let (aead, tag_len) = (state.aead, state.aead.tag_len);
        let client_finished_key = state.client_finished_key.clone();

        // **Client authentication goes here**, between the server's
        // Finished and ours: RFC 8446 4.4.2 puts the client's Certificate
        // and CertificateVerify at the head of its second flight. Each
        // goes into the transcript as it is written, so our Finished
        // below covers them.
        // **EndOfEarlyData comes first**, before the Certificate and the
        // Finished, and it is the last thing written under the early
        // keys. After this the writer is on the handshake keys, which is
        // what the Finished below needs.
        self.finish_early_data(self.early_data_accepted)?;
        let transcript_hash = match self.transcript.as_ref() {
            Some(transcript) => transcript.hash(),
            None => transcript_hash,
        };

        let finished_over = self.send_client_certificate(transcript_hash)?;

        // Our Finished, under the *handshake* key and over the transcript
        // that now ends with the server's Finished - or with our own
        // CertificateVerify, if we authenticated.
        let verify = keys13::finished(hash, &client_finished_key, &finished_over)
            .map_err(Error::local)?;
        self.own_finished = Some(verify.clone());
        let reply = HandshakeMessage::new(HandshakeType::Finished,
                                          Finished { verify_data: verify }.encode())?;
        self.emit_handshake(&reply)?;

        // **Our own Finished goes into the transcript too**, and this is
        // the only message we send that has to.
        //
        // `emit_handshake` writes a record and nothing else - the
        // transcript is fed by `handle_handshake` on the way *in*, so
        // nothing had ever added an outgoing message to it. That was
        // fine while the last thing derived from the transcript was the
        // application keys, which are over the transcript through the
        // *server's* Finished. The resumption master secret is one
        // message later (RFC 8446 7.1: over "ClientHello ... client
        // Finished"), so without this every ticket's PSK is computed
        // over a transcript the server does not share, and the failure
        // appears on the *next* connection as a binder the server
        // rejects.
        if let Some(transcript) = self.transcript.as_mut() {
            transcript.update(&reply.raw);
        }

        // And the resumption master secret is taken **here**, while the
        // transcript is exactly "ClientHello ... client Finished".
        // Everything after this - a NewSessionTicket, a KeyUpdate - is
        // fed to the transcript by `handle_handshake` before its own
        // handler runs, so a later derivation would be over a longer
        // transcript than the server used.
        let resumption_master = {
            let transcript = self.transcript.as_ref().unwrap().hash();
            let state = self.tls13.as_ref().unwrap();
            state.schedule.resumption_master(&transcript).map_err(Error::local)?
        };
        self.tls13.as_mut().unwrap().resumption_master = Some(resumption_master);

        self.reader.change_cipher_spec(Protection::Aead13(
            Aead13::with_rekeying(aead.name, hash, server_app, tag_len, aead.mgm)
                .map_err(Error::local)?));
        self.writer.change_cipher_spec(Protection::Aead13(
            Aead13::with_rekeying(aead.name, hash, client_app, tag_len, aead.mgm)
                .map_err(Error::local)?));

        self.state = State::Established;
        Ok(())
    }

    /// The TLS 1.2 CertificateStatus: a stapled OCSP response.
    ///
    /// **Only if we asked and the server acknowledged.** RFC 6066 §8
    /// makes this message conditional on the ServerHello's
    /// `status_request`, and a message arriving without one is a server
    /// sending something the client never agreed to parse. The check is
    /// worth having on its own account: an unannounced message here is
    /// a peer injecting an extra handshake message into the flight,
    /// which the transcript will catch at the Finished - but only after
    /// this code has parsed whatever it holds.
    ///
    /// **Nothing is judged here.** The chain has not been verified yet
    /// at this point - the issuer is in it - so the response is kept and
    /// checked in `verify_peer`, where there is an issuer to check it
    /// against.
    fn handle_certificate_status(&mut self, message: &HandshakeMessage)
                                 -> Result<(), Error> {
        if !self.expect_certificate_status {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                "A CertificateStatus arrived without a status_request in the \
                 ServerHello. RFC 6066 section 8 makes this message an answer \
                 to that acknowledgement and to nothing else."));
        }
        if self.stapled_ocsp.is_some() {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                                  "A second CertificateStatus."));
        }
        let response = crate::tls::handshake::parse_certificate_status(&message.body)
            .map_err(|reason| Error::new(AlertDescription::DECODE_ERROR, reason))?;
        self.stapled_ocsp = Some(response);
        Ok(())
    }

    /// The OCSP response the server stapled, as DER, or `None`.
    ///
    /// `None` is the ordinary case and not a failure: most servers do
    /// not staple. What it *means* about the certificate is nothing at
    /// all - see `ClientConfig::request_stapled_ocsp`.
    pub fn stapled_ocsp(&self) -> Option<&[u8]> {
        self.stapled_ocsp.as_deref()
    }

    fn handle_certificate(&mut self, message: &HandshakeMessage) -> Result<(), Error> {
        let chain = CertificateChain::parse(&message.body)?;
        if chain.certificates.is_empty() {
            return Err(Error::new(AlertDescription::HANDSHAKE_FAILURE,
                                  "The server sent an empty certificate chain."));
        }
        self.certificates = chain.certificates;

        if self.config.verify_certificate {
            self.verify_peer()?;
            self.certificate_verified = true;
        }

        self.state = State::WaitServerFlight;
        Ok(())
    }

    fn verify_peer(&mut self) -> Result<(), Error> {
        let parsed: Vec<Certificate<'_>> = self.certificates.iter()
            .map(|der| Certificate::parse(der))
            .collect::<Result<_, _>>()
            .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE,
                                    format!("A certificate did not parse: {}", e)))?;

        // The name is checked first: it is the cheapest check and the one
        // most likely to fail, and there is no point verifying signatures
        // on a chain for somebody else's name.
        if self.config.verify_hostname
            && !crate::x509::verify::matches_hostname(&parsed[0], &self.hostname) {
            return Err(Error::new(AlertDescription::BAD_CERTIFICATE, format!(
                "The certificate does not cover {:?}. Set verify_hostname to \
                 false to accept it anyway; the chain is still checked.",
                self.hostname)));
        }

        let roots: Vec<Certificate<'_>> = self.config.roots.roots().iter()
            .map(|der| Certificate::parse(der))
            .collect::<Result<_, _>>()
            .map_err(|e| Error::local(format!("A trusted root did not parse: {}", e)))?;

        crate::x509::verify::verify_chain(&parsed, &roots, &self.config.policy,
                                          Purpose::ServerAuth)
            .map_err(|e| Error::new(AlertDescription::UNKNOWN_CA, e))?;

        self.check_staple(&parsed)
    }

    /// Judge the stapled OCSP response, if one arrived.
    ///
    /// **The asymmetry is the whole of revocation**: being on a list is
    /// an answer, being off one is a claim about coverage. So:
    ///
    ///   * `Revoked` fails the handshake **whatever the policy says**.
    ///     That is an answer, signed by somebody the certificate's own
    ///     issuer delegated to, and a client that shrugged at it would
    ///     be treating a revocation as advice.
    ///   * `Unknown` - no staple, one that does not parse, one about
    ///     another certificate, one signed by nobody we trust - fails
    ///     only under `policy.require_revocation`. It is the default
    ///     that a missing staple is not a failure, because most servers
    ///     staple nothing and hard-failing would refuse most of the web.
    ///
    /// A **nonce is deliberately not sent** and so not checked: a
    /// stapled response is cached by the server and shared between
    /// connections, so demanding a fresh nonce defeats stapling rather
    /// than adding freshness. What bounds a replayed staple is its own
    /// `nextUpdate`, which `ocsp::check` enforces.
    fn check_staple(&self, chain: &[Certificate<'_>]) -> Result<(), Error> {
        use crate::x509::crl::Status;
        let required = self.config.require_stapled_ocsp;
        let response = match &self.stapled_ocsp {
            Some(response) => response,
            None => {
                if required {
                    return Err(Error::new(AlertDescription::CERTIFICATE_UNKNOWN,
                        "No stapled OCSP response, and this connection \
                         requires one. Nothing here fetches from a \
                         responder, so the server has to staple it."));
                }
                return Ok(());
            }
        };
        // **The issuer may not be in the chain.** A server whose CA is a
        // well-known root often sends the leaf alone, and RFC 8446
        // 4.4.2 lets it omit anything the client already has. So the
        // chain is looked at first and then the trust store - and
        // without the second, stapling would silently do nothing for
        // exactly the servers most likely to staple.
        //
        // The chain has already been verified at this point, so a
        // certificate found here is one this client trusts.
        let roots: Vec<Certificate<'_>> = self.config.roots.roots().iter()
            .filter_map(|der| Certificate::parse(der).ok())
            .collect();
        let issuer = match chain.get(1) {
            Some(issuer) => issuer,
            None => match roots.iter().find(|root| root.is_issuer_of(&chain[0])) {
                Some(root) => root,
                None => {
                    if required {
                        return Err(Error::new(
                            AlertDescription::CERTIFICATE_UNKNOWN,
                            "A stapled OCSP response arrived and this \
                             certificate's issuer is neither in the chain nor \
                             in the trust store, so there is nothing to check \
                             the response's signer against."));
                    }
                    return Ok(());
                }
            },
        };
        let status = crate::x509::ocsp::check(&chain[0], issuer, response, None,
                                              &self.config.policy,
                                              self.config.policy.now);
        match status {
            Status::Revoked { at, reason } => Err(Error::new(
                AlertDescription::CERTIFICATE_REVOKED, format!(
                    "The stapled OCSP response says this certificate was \
                     revoked at {}{}.", at,
                    match reason {
                        Some(reason) => format!(" ({})", reason.name()),
                        None => String::new(),
                    }))),
            Status::Unknown(reason) if required => Err(Error::new(
                AlertDescription::CERTIFICATE_UNKNOWN, format!(
                    "The stapled OCSP response settles nothing and this \
                     connection requires one that does: {}",
                    reason))),
            _ => Ok(()),
        }
    }

    /// Answer a CertificateRequest, if one arrived.
    ///
    /// Returns the transcript hash the client's Finished must cover: the
    /// one passed in when nothing was sent, and the one through our own
    /// CertificateVerify when something was.
    ///
    /// **An empty Certificate is a legal answer** (RFC 8446 4.4.2.1) and is
    /// what a client with no suitable key sends - not silence, which the
    /// server would wait for. The server then decides whether that ends the
    /// connection; that decision is not ours to pre-empt by refusing to
    /// answer.
    fn send_client_certificate(&mut self, transcript_hash: Vec<u8>)
                               -> Result<Vec<u8>, Error> {
        let request = match self.certificate_request.take() {
            Some(request) => request,
            None => return Ok(transcript_hash),
        };
        // Read the offered schemes before the context is moved into the
        // message; `parse` has already refused a request without them.
        let offered = request.schemes()?;

        // The chain, or nothing. `request` carries the context to echo -
        // empty in a handshake request, and echoing whatever arrived is
        // what RFC 8446 asks for rather than assuming it was empty.
        let entries = match &self.config.client_certificate {
            Some(identity) => identity.chain.iter().map(|der| hs13::CertificateEntry {
                certificate: der.clone(),
                extensions: Vec::new(),
            }).collect(),
            None => Vec::new(),
        };
        let sent_something = !entries.is_empty();
        let body = hs13::Certificate13 { request_context: request.context, entries }
            .encode()?;
        let message = HandshakeMessage::new(HandshakeType::Certificate, body)?;
        self.emit_handshake(&message)?;
        if let Some(transcript) = self.transcript.as_mut() {
            transcript.update(&message.raw);
        }
        if !sent_something {
            // No certificate, so nothing to prove possession of.
            let transcript = self.transcript.as_ref()
                .ok_or_else(|| Error::local("No transcript."))?;
            return Ok(transcript.hash());
        }

        // The scheme has to satisfy three things at once: the server
        // offered it, our key can make it, and it is legal in a
        // CertificateVerify. The last is not a formality - `rsa_pkcs1_*`
        // appears in `signature_algorithms` for certificates and is
        // forbidden here.
        let identity = self.config.client_certificate.as_ref()
            .ok_or_else(|| Error::local("No client identity."))?;
        let chosen = identity.schemes().into_iter()
            .find(|s| offered.contains(s) && scheme::allowed_in_certificate_verify(*s))
            .ok_or_else(|| Error::new(AlertDescription::HANDSHAKE_FAILURE, format!(
                "No signature scheme in common for the client certificate. The \
                 server offered {:?}.",
                offered.iter().map(|s| scheme::name(*s)).collect::<Vec<_>>())))?;

        // **`Side13::Client`.** The context strings differ by one word and
        // signing with the server's produces something that verifies
        // against nothing and looks exactly like a wrong key.
        let transcript = self.transcript.as_ref()
            .ok_or_else(|| Error::local("No transcript."))?
            .hash();
        let content = hs13::certificate_verify_content(Side13::Client, &transcript);
        let signature = identity.sign(chosen, &content).map_err(Error::local)?;
        let body = hs13::CertificateVerify { scheme: chosen, signature }.encode()?;
        let message = HandshakeMessage::new(HandshakeType::CertificateVerify, body)?;
        self.emit_handshake(&message)?;
        if let Some(transcript) = self.transcript.as_mut() {
            transcript.update(&message.raw);
        }
        let transcript = self.transcript.as_ref()
            .ok_or_else(|| Error::local("No transcript."))?;
        Ok(transcript.hash())
    }

    /// The server's ephemeral key, and the signature that binds it to the
    /// certificate.
    ///
    /// That signature is the entire security of an ephemeral key exchange.
    /// Without checking it, the "server" could be anybody - the ephemeral
    /// key is unauthenticated by construction, and the certificate is what
    /// makes it mean something. An implementation that parses this message
    /// and forgets to verify it has a handshake that completes perfectly
    /// with a man in the middle.
    fn handle_server_key_exchange(&mut self, message: &HandshakeMessage)
                                  -> Result<(), Error> {
        // Once. `WaitServerFlight` stays where it is after this message,
        // so without this a second ServerKeyExchange replaced the
        // parameters of the first - both signed, so not exploitable, but
        // a server padding its flight with a message RFC 5246 7.4.3
        // sends exactly once, and the CertificateRequest and
        // CertificateStatus handlers already refuse a second copy.
        if self.server_ecdh.is_some() || self.server_dh.is_some()
            || self.server_rsa.is_some() {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                                  "A second ServerKeyExchange."));
        }
        let suite = self.suite.ok_or_else(|| Error::local("No suite."))?;
        let version = self.negotiated_version
            .ok_or_else(|| Error::local("No version."))?;

        if suite.key_exchange == KeyExchange::Rsa {
            // A plain RSA key exchange has no ServerKeyExchange: the
            // premaster goes under the certificate's key. An *export* RSA
            // suite does have one, carrying a temporary key small enough
            // for the 1990s export rules.
            //
            // That difference is FREAK. The attack was clients accepting
            // this message for a suite that has no such message, and
            // downgrading themselves to a 512 bit key the server never
            // agreed to use. The decision is made from the **negotiated
            // suite** - the only thing that says which case this is - and
            // never from the message having arrived.
            if !suite.cipher.is_exportable() {
                return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE, format!(
                    "The server sent a ServerKeyExchange, which {} does not \
                     have. That is FREAK: accepting it would mean encrypting \
                     the premaster under a temporary key this suite never \
                     agreed to.", suite.name)));
            }
            return self.handle_export_rsa_key_exchange(&message.body, version, suite);
        }
        if suite.key_exchange == KeyExchange::GostVko {
            // RFC 9189 section 4.2: a ServerKeyExchange MUST NOT be sent,
            // because the server's certificate already carries everything
            // the client needs. Refused for the same reason as the FREAK
            // check above - the decision is the negotiated suite's, and a
            // message that suite has no place for is not an optional
            // extra. Accepting one would mean agreeing a key with
            // whoever sent it rather than with the certificate's owner,
            // and there is no signature here to tell them apart.
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE, format!(
                "The server sent a ServerKeyExchange, which {} does not have \
                 (RFC 9189 section 4.2). The key comes from the certificate, \
                 so this message could only move it somewhere else.",
                suite.name)));
        }
        if self.certificates.is_empty() {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                                  "ServerKeyExchange arrived before the certificate."));
        }

        if suite.key_exchange.is_finite_field_dh() {
            return self.handle_dh_key_exchange(&message.body, version, suite);
        }

        let params = ServerEcdhParams::parse(&message.body, version)?;

        // The group has to be one we offered. A server picking something
        // else is choosing the group for us, which is the shape of the
        // invalid-curve attack even when the curve is a real one. Asked
        // before "do we implement it", so that a group we do implement but
        // did not offer is still refused.
        if groups::HYBRID.contains(&params.group) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server chose {} for a TLS 1.2 key exchange. The hybrid \
                 post-quantum groups are defined for TLS 1.3 only (RFC 10024), \
                 and a ServerKeyExchange has no way to carry an ML-KEM \
                 ciphertext.", groups::name(params.group))));
        }
        if !OFFERED_GROUPS.contains(&params.group) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server chose {} for the key exchange, which this client \
                 did not offer for one.",
                groups::name(params.group))));
        }
        // The Montgomery groups, whose width is the whole of their
        // structural validity. **Taken from a table rather than written
        // as a literal at each use**: 32 and 56 in separate `if` arms is
        // how one of them ends up checking the other's length, and a
        // 56 byte value truncated to 32 is still a perfectly valid u
        // coordinate, so nothing downstream would object.
        let montgomery_width = match params.group {
            groups::X25519 => Some(32),
            groups::X448 => Some(56),
            _ => None,
        };
        let curve_name = groups::curve_name(params.group);
        if curve_name.is_none() && montgomery_width.is_none() {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server chose {}, which this library does not implement.",
                groups::name(params.group))));
        }

        // Their only structural requirement is the length: every string
        // of the right width is a valid u coordinate, which is the point
        // of these curves. Checked here, before the signature, because it
        // is a property of the message rather than a computation on its
        // contents - unlike the on-curve check below, which is arithmetic
        // on data that is not yet authenticated and therefore waits.
        if let Some(width) = montgomery_width {
            if params.point.len() != width {
                return Err(Error::new(
                    AlertDescription::ILLEGAL_PARAMETER, format!(
                        "A {} public key is {} bytes; the server sent {}.",
                        groups::name(params.group), width,
                        params.point.len())));
            }
        }

        self.verify_key_exchange_signature(
            &params.signed_bytes(&self.client_random, &self.server_random),
            params.scheme, &params.signature, suite)?;

        if montgomery_width.is_none() {
            // For the Weierstrass curves the point is validated when it is
            // decoded, by `decode_point`, which refuses anything off the
            // curve. A degenerate Montgomery point needs no equivalent: it
            // is caught by the all-zero check in `x25519::exchange` and
            // `x448::exchange`, which RFC 7748 section 6 requires.
            let curve = curves::by_name(curve_name.expect("checked above"))
                .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;
            curve.decode_point(&params.point).map_err(|e| Error::new(
                AlertDescription::ILLEGAL_PARAMETER,
                format!("The server's ephemeral point is not usable: {}", e)))?;
        }

        // `None` before TLS 1.2: those versions' ServerKeyExchange
        // carries no algorithm field, so there is no scheme to report
        // and the certificate's key type decides what was signed.
        self.peer_signature_scheme = params.scheme.map(|s| s.to_u16());
        self.server_ecdh = Some(params);
        Ok(())
    }

    /// The export RSA half: a temporary key, signed by the certificate.
    ///
    /// Two policy questions here have deliberately different answers from
    /// everywhere else in this file:
    ///
    ///   * the temporary key is **not** held to `min_rsa_bits`. It is 512
    ///     bits by design - that is what "export" meant - so applying the
    ///     modern floor would refuse every export suite while looking like
    ///     a policy. The certificate's key, which signs it, is still held
    ///     to the floor by `verify_key_exchange_signature`.
    ///   * a temporary key *larger* than 1024 bits is refused. An export
    ///     suite whose temporary key is not small is not an export suite;
    ///     it is a server trying to use this message for something else.
    ///
    /// None of which makes the suite safe. A 512 bit modulus is hours of
    /// arithmetic, and servers reused one for years. It is implemented
    /// because equipment that offers nothing else exists.
    fn handle_export_rsa_key_exchange(&mut self, body: &[u8], version: Version,
                                      suite: &CipherSuite) -> Result<(), Error> {
        let params = ServerRsaParams::parse(body, version)?;

        // The size is a property of the message rather than a computation
        // on its contents, so it is checked before the signature - which
        // also means a server using this message for something other than
        // an export key is told that, rather than being told its
        // signature failed.
        let modulus = BigUint::from_bytes_be(&params.modulus);
        if modulus.bit_len() > 1024 {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The server's temporary RSA key is {} bits. An export suite's \
                 temporary key is small by definition; a large one means this \
                 message is being used for something else.", modulus.bit_len())));
        }

        self.verify_key_exchange_signature(
            &params.signed_bytes(&self.client_random, &self.server_random),
            params.scheme, &params.signature, suite)?;

        self.server_rsa = Some(params);
        Ok(())
    }

    /// The finite-field half of the same message.
    ///
    /// The order of the checks here is not cosmetic. The signature is
    /// verified *before* the group is examined, because until it verifies
    /// the parameters are an anonymous stranger's and there is no point
    /// having an opinion about their size. After it verifies they are the
    /// server's - which is not the same as their being any good, and the
    /// rest of the function is about that difference.
    fn handle_dh_key_exchange(&mut self, body: &[u8], version: Version,
                              suite: &CipherSuite) -> Result<(), Error> {
        let params = ServerDhParams::parse(body, version)?;

        self.verify_key_exchange_signature(
            &params.signed_bytes(&self.client_random, &self.server_random),
            params.scheme, &params.signature, suite)?;

        // `DhGroup::new` refuses a group that is structurally impossible;
        // `check_size` refuses one that is merely too small, which is the
        // policy question and so is asked separately.
        let group = dh::DhGroup::from_bytes(&params.p, &params.g)
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;
        group.check_size(self.config.min_dh_bits)
            .map_err(|e| Error::new(AlertDescription::INSUFFICIENT_SECURITY, e))?;
        // And one that is too large to compute with, before the primality
        // test or the exchange exponentiates over it.
        self.config.policy.check_key_ceiling("The server's Diffie-Hellman group",
                                             group.bits())
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;
        if self.config.check_dh_prime {
            group.check_prime(24)
                .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;
        }

        // The public value is validated here as well as in
        // `shared_secret`, so that a degenerate one is an
        // illegal_parameter alert at the message that carried it rather
        // than a local error three steps later.
        group.validate_peer(&BigUint::from_bytes_be(&params.public))
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;

        self.server_dh = Some(params);
        Ok(())
    }

    /// Check the signature over the ephemeral parameters.
    /// No `version` parameter: the hash is named by the message in TLS 1.2
    /// and fixed by the key type before it, and `params.scheme` already
    /// carries that distinction from the parse. Taking the version here
    /// too would be a second source of truth for the same fact.
    ///
    /// Takes the signed bytes rather than a parameter structure, because
    /// the elliptic curve and finite-field messages carry different
    /// parameters and an identical signature tail. Two copies of this
    /// function would be two places for the pre-1.2 rules to be got
    /// right, and the pre-1.2 rules have already been got wrong once.
    fn verify_key_exchange_signature(&self, signed: &[u8],
                                     scheme: Option<SignatureScheme>,
                                     signature: &[u8], suite: &CipherSuite)
                                     -> Result<(), Error> {
        // `scheme` is present only from TLS 1.2, where the message names
        // its own hash. Its absence *is* the fact that this is a TLS 1.0
        // or 1.1 ServerKeyExchange, which signs an entirely different
        // thing - so it is the discriminator rather than the version,
        // which would be a second source of truth for the same fact.
        let legacy_format = scheme.is_none();
        let scheme = scheme.unwrap_or(match suite.key_exchange {
            KeyExchange::EcdheEcdsa => SignatureScheme::ECDSA_SHA1,
            // Before 1.2 a DSA signature is over SHA-1 alone, like
            // ECDSA's (RFC 4346 7.4.3).
            KeyExchange::DheDss => SignatureScheme::DSA_SHA1,
            _ => SignatureScheme::RSA_PKCS1_SHA1,
        });
        // The TLS 1.3 codepoints are legal in a TLS 1.2 ServerKeyExchange
        // too (RFC 8446 section 4.2.3), and a server offered them will use
        // one - so this has to understand both numbering schemes. They
        // cannot be told apart by structure: `rsa_pss_rsae_sha256` is
        // 0x0804, which as a TLS 1.2 (hash, signature) pair reads as hash
        // 8 and signature 4, both of which are unassigned.
        //
        // Found by a real TLS 1.2 handshake, the moment this client
        // started offering the PSS schemes for 1.3: the server picked one
        // and we refused it with "the server signed with hash 8".
        let code = scheme.to_u16();
        // **EdDSA signs the randoms and the params themselves** (RFC 8422
        // 5.4): the hash byte is 8, "Intrinsic", and there is no digest to
        // take - so it is decided before the hash lookup below, which has
        // no answer for it and would refuse the scheme as unimplemented.
        // That is exactly what happened: this client offered `ed25519` in
        // every hello, a TLS 1.2 server with an Ed25519 certificate chose
        // it, and the client refused its own offer. EdDSA has no TLS 1.0
        // or 1.1 form here, so a legacy-format message never gets this far
        // with an EdDSA key - it is refused below as a key mismatch.
        if !legacy_format && matches!(code, scheme::ED25519 | scheme::ED448) {
            let leaf = Certificate::parse(&self.certificates[0])
                .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
            return verify_eddsa(&leaf.public_key, code, signed, signature);
        }
        let is_pss = scheme::is_pss(code);
        let hash_name = match scheme::hash_name(code).or_else(|| scheme.hash_name()) {
            Some(name) => name,
            None => return Err(Error::new(
                AlertDescription::ILLEGAL_PARAMETER,
                format!("The server signed with {}, which is not implemented.",
                        scheme::name(code)))),
        };

        // The weak-hash policy applies only where the peer *chose* the
        // hash. Before TLS 1.2 there is no choice: the construction is
        // fixed by the protocol version, so refusing it is not a policy
        // about weak hashes but a refusal to speak TLS 1.0 and 1.1 with
        // any ephemeral key exchange at all - which is most of what the
        // servers this library exists for actually offer.
        //
        // A real TLS 1.0 server found this. Every local test used a static
        // RSA key exchange, which has no ServerKeyExchange and so never
        // reached this line.
        if !legacy_format {
            self.config.policy.accepts_hash_public(hash_name)
                .map_err(|e| Error::new(AlertDescription::INSUFFICIENT_SECURITY, e))?;
        }

        // Before TLS 1.2 an RSA signature is over MD5(input) || SHA1(input)
        // - 36 bytes, both hashes, concatenated (RFC 4346 section 7.4.3).
        // An ECDSA one is SHA-1 alone. That asymmetry is why this is not
        // simply "the hash named by the scheme", and why ECDSA at TLS 1.0
        // worked while RSA did not.
        let digest = if legacy_format && !is_pss && scheme.signature == 1 {
            let mut md5 = AnyHash::new("md5").map_err(Error::local)?;
            md5.update(signed);
            let mut sha1 = AnyHash::new("sha1").map_err(Error::local)?;
            sha1.update(signed);
            let mut both = md5.digest();
            both.extend_from_slice(&sha1.digest());
            both
        } else {
            let mut hasher = AnyHash::new(hash_name).map_err(Error::local)?;
            hasher.update(signed);
            hasher.digest()
        };

        let leaf = Certificate::parse(&self.certificates[0])
            .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;

        let valid = match (&leaf.public_key, if is_pss { 1 } else { scheme.signature }) {
            (PublicKey::Rsa { n, e }, 1) => {
                if n.bit_len() < self.config.policy.min_rsa_bits {
                    return Err(Error::new(AlertDescription::INSUFFICIENT_SECURITY,
                        format!("The server's RSA key is {} bits; the policy \
                                 requires {}.", n.bit_len(),
                                self.config.policy.min_rsa_bits)));
                }
                key_ceiling(&self.config.policy, "The server's RSA key", n.bit_len())?;
                let key = rsa::RsaPublicKey::new(n.clone(), e.clone())
                    .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
                // And the encoding differs too: before TLS 1.2 the 36 byte
                // digest is signed with no DigestInfo prefix, because there
                // is no algorithm to identify. Building a SHA-1 DigestInfo
                // over it, as the TLS 1.2 path does, produces a block that
                // never matches - which is what a real server rejected.
                if is_pss {
                    // The salt length is not recoverable from a PSS
                    // signature, and both RFC 8446 and what OpenSSL sends
                    // fix it at the hash's own length.
                    let salt_len = rsa::pss_salt_len(hash_name).map_err(Error::local)?;
                    rsa::verify_pss(&key, hash_name, &digest, signature, salt_len)
                        .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
                } else if legacy_format {
                    rsa::verify_pkcs1v15_raw(&key, &digest, signature)
                        .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
                } else {
                    rsa::verify_pkcs1v15(&key, hash_name, &digest, signature)
                        .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
                }
            }
            (PublicKey::Dsa { parameters, y }, 2) => {
                // The group's size is held to `min_rsa_bits`, as in a
                // certificate: see `x509::verify::dsa_public_key`.
                let key = crate::x509::verify::dsa_public_key(parameters, y,
                                                              &self.config.policy)
                    .map_err(|e| Error::new(AlertDescription::INSUFFICIENT_SECURITY, e))?;
                // Dss-Sig-Value, the same DER as ECDSA's.
                let signature = crate::x509::verify::decode_ecdsa_der(signature)
                    .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
                key.verify(&digest, &signature.r, &signature.s)
                    .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
            }
            (PublicKey::Ec { curve, point }, 3) => {
                let curve = curves::by_name(curve)
                    .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
                let public = curve.decode_point(point)
                    .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
                let signature = crate::x509::verify::decode_ecdsa_der(signature)
                    .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
                curve.verify(&public, &digest, &signature)
                    .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
            }
            (key, signature_type) => return Err(Error::new(
                AlertDescription::ILLEGAL_PARAMETER, format!(
                    "The server signed with {} but its certificate carries {}.",
                    scheme::name(code),
                    match key {
                        PublicKey::Rsa { .. } => "an RSA key",
                        PublicKey::Ec { .. } => "an EC key",
                        PublicKey::Dsa { .. } => "a DSA key",
                        _ => "an unsupported key",
                    }))).map(|_: ()| unreachable!("{}", signature_type)),
        };

        if !valid {
            // This is the check that makes an ephemeral key exchange mean
            // anything at all.
            return Err(Error::new(AlertDescription::DECRYPT_ERROR,
                "The signature over the server's ephemeral key does not verify \
                 against its certificate. The ephemeral key is unauthenticated, \
                 which is what a man in the middle looks like."));
        }
        Ok(())
    }

    fn handle_server_hello_done(&mut self, _message: &HandshakeMessage)
                                -> Result<(), Error> {
        if self.certificates.is_empty() {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                                  "ServerHelloDone arrived with no certificate."));
        }
        self.send_client_second_flight()
    }

    /// The TLS 1.2 CertificateRequest.
    ///
    /// It arrives in the server's first flight, before ServerHelloDone,
    /// and the answer goes out in the client's second flight - so all
    /// this does is remember what was asked.
    ///
    /// **Nothing like the 1.3 message.** The certificate types are a
    /// list of key algorithms with no 1.3 equivalent, and a client whose
    /// key is not of a listed type has been told not to send that
    /// certificate.
    fn handle_certificate_request_12(&mut self, message: &HandshakeMessage)
                                     -> Result<(), Error> {
        use crate::tls::handshake::{CertificateRequest10, CertificateRequest12};
        if self.certificate_request_12.is_some() {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                                  "A second CertificateRequest."));
        }
        let version = self.negotiated_version
            .ok_or_else(|| Error::local("No version negotiated."))?;
        // **Two different messages.** TLS 1.2 added
        // `supported_signature_algorithms` in the middle; before it
        // there was nothing to negotiate. Reading the 1.2 shape from a
        // 1.0 server takes the CA list's length for a signature list.
        let request = if version >= Version::TLS12 {
            CertificateRequest12::parse(&message.body)?
        } else {
            let old = CertificateRequest10::parse(&message.body)?;
            CertificateRequest12 {
                certificate_types: old.certificate_types,
                // **Not a real offer.** Before 1.2 the construction is
                // fixed by the version and by the key's type, so this
                // stands in for "whatever your key can do" - and
                // `choose_client_scheme_12` is not consulted on this
                // path, `sign_certificate_verify_10` is.
                schemes: Vec::new(),
                authorities: old.authorities,
            }
        };
        self.certificate_request_12 = Some(request);
        Ok(())
    }

    /// The certificate and scheme to answer a TLS 1.2 request with.
    ///
    /// `None` means send an empty Certificate, which is a legal answer
    /// (RFC 5246 7.4.6) and the right one whenever the identity does not
    /// fit: no identity configured, a key of a type the server did not
    /// list, or no scheme in common. Signing anyway with something the
    /// server said it would not take fails at the signature, which is
    /// far from the decision that caused it.
    fn choose_client_scheme_12(&self) -> Option<u16> {
        use crate::tls::handshake::client_certificate_type as kind;
        let request = self.certificate_request_12.as_ref()?;
        let identity = self.config.client_certificate.as_ref()?;
        let wanted = match &identity.key {
            ClientKey::Rsa(_) => kind::RSA_SIGN,
            // RFC 8422 section 3: `ecdsa_sign` covers an EdDSA key too.
            ClientKey::Ec { .. } | ClientKey::Eddsa { .. } => kind::ECDSA_SIGN,
            // `kind::GOST_SIGN256` and `GOST_SIGN512` exist and a server
            // may well ask for them, but `sign_digest_12` cannot produce
            // the signature - so declining here is the honest answer and
            // keeps the refusal at the decision rather than at the
            // signature.
            ClientKey::Gost { .. } => return None,
            // TLS 1.3 only, so a 1.2 server gets an empty Certificate.
            ClientKey::MlDsa(_) => return None,
        };
        if !request.certificate_types.contains(&wanted) {
            return None;
        }
        // **PKCS#1 v1.5 for RSA here, not PSS.** `ClientKey::schemes`
        // answers for TLS 1.3, where RFC 8446 4.4.3 forbids the
        // `rsa_pkcs1_*` codepoints in a CertificateVerify; at 1.2 they
        // are the only thing a peer expects. One list per version, for
        // the same reason there is one signature routine per version.
        let ours: &[u16] = match &identity.key {
            ClientKey::Rsa(_) => &[0x0401, 0x0501, 0x0601],
            ClientKey::Ec { curve, .. } => match *curve {
                "P-256" => &[0x0403, 0x0503, 0x0603],
                "P-384" => &[0x0503, 0x0403, 0x0603],
                "P-521" => &[0x0603, 0x0503, 0x0403],
                _ => &[0x0403],
            },
            ClientKey::Eddsa { name: "ed448", .. } => &[scheme::ED448],
            ClientKey::Eddsa { .. } => &[scheme::ED25519],
            // Unreachable: the match above already returned for this key.
            // Spelled out rather than wildcarded, so that building the 1.2
            // path fails here and says what it needs.
            ClientKey::Gost { .. } | ClientKey::MlDsa(_) => return None,
        };
        ours.iter().copied().find(|scheme| request.schemes.contains(scheme))
    }

    /// Whether our key is of a type the server's CertificateRequest
    /// listed. The whole of the decision before TLS 1.2, where there is
    /// no scheme to agree on.
    fn key_type_is_listed(&self) -> bool {
        use crate::tls::handshake::client_certificate_type as kind;
        let request = match self.certificate_request_12.as_ref() {
            Some(request) => request,
            None => return false,
        };
        let identity = match self.config.client_certificate.as_ref() {
            Some(identity) => identity,
            None => return false,
        };
        let wanted = match &identity.key {
            ClientKey::Rsa(_) => kind::RSA_SIGN,
            ClientKey::Ec { .. } => kind::ECDSA_SIGN,
            // Before 1.2 there is no scheme to agree on, and this key
            // cannot sign that CertificateVerify either - see
            // `sign_certificate_verify_10`.
            ClientKey::Gost { .. } | ClientKey::MlDsa(_)
                | ClientKey::Eddsa { .. } => return false,
        };
        request.certificate_types.contains(&wanted)
    }

    /// ClientKeyExchange, ChangeCipherSpec, Finished - and, when the
    /// server asked, a Certificate before it and a CertificateVerify
    /// after it.
    fn send_client_second_flight(&mut self) -> Result<(), Error> {
        let suite = self.suite.ok_or_else(|| Error::local("No suite negotiated."))?;
        let version = self.negotiated_version
            .ok_or_else(|| Error::local("No version negotiated."))?;

        // --- the Certificate, if one was asked for ---
        //
        // **Before the ClientKeyExchange** (RFC 5246 7.4), which is the
        // opposite order from 1.3's flight and matters because the
        // CertificateVerify signs the concatenation of everything
        // before it.
        let legacy = version < Version::TLS12;
        let scheme = if legacy { None } else { self.choose_client_scheme_12() };
        // Before 1.2 there is no scheme to choose: the key type decides
        // everything, so "can we answer" is only "is our key of a type
        // the server listed".
        let can_answer_10 = legacy && self.key_type_is_listed();
        let answering = self.certificate_request_12.is_some();
        if answering {
            let chain = match (scheme.is_some() || can_answer_10,
                               &self.config.client_certificate) {
                (true, Some(identity)) => identity.chain.clone(),
                // An **empty** chain, not silence: the server is waiting
                // for the message either way, and it decides what an
                // empty answer costs.
                _ => Vec::new(),
            };
            let body = CertificateChain { certificates: chain }.encode()?;
            let message = HandshakeMessage::new(HandshakeType::Certificate, body)?;
            self.emit_handshake(&message)?;
            if let Some(transcript) = &mut self.transcript {
                transcript.update(&message.raw);
            }
        }

        // --- the premaster, and the ClientKeyExchange that carries it ---
        let (premaster, body) = match suite.key_exchange {
            KeyExchange::Rsa => self.rsa_key_exchange()?,
            KeyExchange::EcdheRsa | KeyExchange::EcdheEcdsa =>
                self.ecdhe_key_exchange()?,
            KeyExchange::DheRsa | KeyExchange::DheDss =>
                self.dhe_key_exchange()?,
            KeyExchange::GostVko | KeyExchange::GostVko2001 =>
                self.gost_key_exchange()?,
            other => return Err(Error::new(AlertDescription::HANDSHAKE_FAILURE,
                format!("{} is not implemented.", other.name()))),
        };

        let message = HandshakeMessage::new(HandshakeType::ClientKeyExchange, body)?;
        self.emit_handshake(&message)?;
        if let Some(transcript) = &mut self.transcript {
            transcript.update(&message.raw);
        }

        // **The session hash is taken here**, before the
        // CertificateVerify goes out. RFC 7627 defines it as the
        // transcript through the ClientKeyExchange, and the
        // CertificateVerify comes *after* that message - so a client
        // that derived the master secret further down, after writing
        // it, computes a different one from every server. The symptom
        // is `bad_record_mac` at the Finished, which reads as a broken
        // cipher rather than as a hash taken one message too late.
        let session_hash = self.transcript.as_ref()
            .ok_or_else(|| Error::local("No transcript."))?
            .session_hash();

        // --- the CertificateVerify ---
        //
        // **After the ClientKeyExchange**, because it signs the
        // concatenation of every handshake message so far and that one
        // is part of it. Taken before the message is written, for the
        // obvious reason.
        if answering && legacy && can_answer_10 {
            if let Some(identity) = self.config.client_certificate.as_ref() {
                // The transcript hash before this message, which at these
                // versions is already MD5 and SHA-1 concatenated - exactly
                // what an RSA signature covers. No message buffer needed.
                let digest = self.transcript.as_ref()
                    .ok_or_else(|| Error::local("No transcript."))?
                    .hash();
                let signature = identity.sign_certificate_verify_10(&digest)
                    .map_err(Error::local)?;
                let body = crate::tls::handshake::CertificateVerify10 { signature }
                    .encode()?;
                let message = HandshakeMessage::new(
                    HandshakeType::CertificateVerify, body)?;
                self.emit_handshake(&message)?;
                if let Some(transcript) = &mut self.transcript {
                    transcript.update(&message.raw);
                }
            }
        } else if answering {
            if let (Some(scheme), Some(identity)) =
                (scheme, self.config.client_certificate.as_ref()) {
                let signed = self.transcript.as_ref()
                    .ok_or_else(|| Error::local("No transcript."))?
                    .messages().to_vec();
                if signed.is_empty() {
                    return Err(Error::local(
                        "The transcript was not keeping messages, so there is \
                         nothing to sign. `keep_messages` has to be called \
                         before the first update."));
                }
                // EdDSA signs the concatenation itself (RFC 8422 5.10);
                // every other 1.2 scheme signs its hash under the scheme's
                // hash byte.
                let signature = if matches!(scheme, scheme::ED25519 | scheme::ED448) {
                    identity.sign(scheme, &signed).map_err(Error::local)?
                } else {
                    let hash_name = SignatureScheme::from_u16(scheme).hash_name()
                        .ok_or_else(|| Error::local("No hash for the chosen scheme."))?;
                    let mut hasher = crate::api::AnyHash::new(hash_name)
                        .map_err(Error::local)?;
                    hasher.update(&signed);
                    let digest = hasher.digest();
                    identity.sign_digest_12(scheme, hash_name, &digest)
                        .map_err(Error::local)?
                };
                let body = crate::tls::handshake::CertificateVerify12 {
                    scheme: SignatureScheme::from_u16(scheme), signature,
                }.encode()?;
                let message = HandshakeMessage::new(
                    HandshakeType::CertificateVerify, body)?;
                self.emit_handshake(&message)?;
                if let Some(transcript) = &mut self.transcript {
                    transcript.update(&message.raw);
                }
            }
        }

        // --- the master secret ---
        //
        // `session_hash` was taken above, through the ClientKeyExchange
        // and before any CertificateVerify, which is what RFC 7627
        // defines it as.
        let master = if self.extended_master_secret {
            keys::extended_master_secret(version, suite.prf, &premaster,
                                         &session_hash)
        } else {
            keys::master_secret(version, suite.prf, &premaster,
                                &self.client_random, &self.server_random)
        }.map_err(Error::local)?;

        let block = keys::key_block(version, suite, &master, &self.client_random,
                                    &self.server_random).map_err(Error::local)?;
        self.master = Some(master);

        // --- ChangeCipherSpec, then everything after it is protected ---
        let bytes = self.writer.write(ContentType::ChangeCipherSpec, &[1])?;
        self.outgoing.extend_from_slice(&bytes);

        let write_keys = self.protection(suite, version, &block.client)?;
        self.writer.change_cipher_spec(write_keys);

        // --- Finished, over the transcript so far ---
        //
        // SSLv3's Finished is 36 bytes built from the transcript's running
        // state rather than 12 bytes from a PRF over its digest, so it
        // takes a different call rather than a different argument.
        let transcript = self.transcript.as_ref().unwrap();
        let master = self.master.as_ref().unwrap();
        let verify = if version == Version::SSL30 {
            transcript.ssl3_finished(master, Side::Client).map_err(Error::local)?
        } else {
            keys::verify_data(version, suite, master, Side::Client,
                              &transcript.hash()).map_err(Error::local)?
        };
        self.own_finished = Some(verify.clone());
        let message = HandshakeMessage::new(HandshakeType::Finished, verify)?;
        self.emit_handshake(&message)?;
        if let Some(transcript) = &mut self.transcript {
            transcript.update(&message.raw);
        }

        self.state = State::WaitChangeCipherSpec;
        Ok(())
    }

    /// RSA: the premaster is ours, encrypted under the server's key.
    ///
    /// No forward secrecy: anyone who later obtains the server's private
    /// key can decrypt every session they recorded. That is a property of
    /// the key exchange, not of this code, and it is why ECDHE exists.
    fn rsa_key_exchange(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // The version in the premaster is the one we *offered*, not the
        // one negotiated. That is the anti-rollback check from RFC 5246
        // 7.4.7.1: a server that negotiated a lower version sees the
        // client's real preference and knows the handshake was tampered
        // with. Using the negotiated version makes the check useless.
        let premaster = keys::rsa_premaster(self.offered_version)
            .map_err(Error::local)?;

        // And the reverse of the FREAK check: an export suite that sent no
        // ServerKeyExchange must not quietly fall back to the certificate
        // key. Both directions are the same mistake - using a key the
        // negotiated suite did not call for.
        if let Some(suite) = self.suite {
            if suite.cipher.is_exportable() && self.server_rsa.is_none() {
                return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE, format!(
                    "{} is an export suite and the server sent no \
                     ServerKeyExchange, so there is no temporary key to \
                     encrypt under.", suite.name)));
            }
        }

        // An export suite encrypts under the *temporary* key from the
        // ServerKeyExchange, not the certificate's. The temporary key was
        // already checked there - its signature against the certificate,
        // and its size against the ceiling an export key has - and it is
        // deliberately not held to `min_rsa_bits`, which would refuse
        // every export suite while looking like a policy decision.
        let key = if let Some(params) = &self.server_rsa {
            rsa::RsaPublicKey::new(BigUint::from_bytes_be(&params.modulus),
                                   BigUint::from_bytes_be(&params.exponent))
                .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?
        } else {
            let leaf = Certificate::parse(&self.certificates[0])
                .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
            let (n, e) = match &leaf.public_key {
                PublicKey::Rsa { n, e } => (n.clone(), e.clone()),
                other => return Err(Error::new(AlertDescription::UNSUPPORTED_CERTIFICATE,
                    format!("The RSA key exchange needs an RSA certificate; this one \
                             carries {}.",
                            match other {
                                PublicKey::Ec { curve, .. } => format!("an EC {} key", curve),
                                _ => "an unsupported key".to_string(),
                            }))),
            };
            key_ceiling(&self.config.policy, "The server's RSA key", n.bit_len())?;
            let key = rsa::RsaPublicKey::new(n, e)
                .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
            if key.bits() < self.config.policy.min_rsa_bits {
                return Err(Error::new(AlertDescription::INSUFFICIENT_SECURITY, format!(
                    "The server's RSA key is {} bits; the policy requires {}.",
                    key.bits(), self.config.policy.min_rsa_bits)));
            }
            key
        };
        let encrypted = rsa::encrypt_pkcs1v15(&key, &premaster)
            .map_err(|e| Error::new(AlertDescription::INTERNAL_ERROR, e))?;

        let mut body = Writer::new();
        body.vector16(&encrypted)?;
        Ok((premaster, body.finish()))
    }

    /// RFC 9189's key exchange: wrap a fresh preliminary secret under
    /// keys agreed against the server's certificate key.
    ///
    /// Closer to RSA key transport than to ECDHE despite the ephemeral
    /// key: the client chooses the secret, the server's only role is to
    /// unwrap it, and that unwrapping is what authenticates the server.
    /// It is **not** forward secret - the ephemeral key is the client's
    /// and the server's is long-lived, so anyone who later obtains the
    /// certificate's private key can recover the premaster from a
    /// recorded handshake, exactly as with RSA. The ephemeral half buys
    /// a fresh export key per connection, not forward secrecy.
    fn gost_key_exchange(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let suite = self.suite.ok_or_else(|| Error::local("No suite."))?;
        if self.certificates.is_empty() {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                "The GOST key exchange needs the server's certificate, and \
                 none arrived."));
        }
        let leaf = Certificate::parse(&self.certificates[0])
            .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;

        let generation = if suite.key_exchange
                            == crate::tls::suites::KeyExchange::GostVko2001 {
            "GOST R 34.10-2001"
        } else {
            "GOST R 34.10-2012"
        };
        // **The certificate's own algorithm has to match the suite's.**
        // A 2001 key and a 2012 key are the same point on the same
        // curve under different OIDs, so a client that looked only at
        // the shape would use either for either - and would then be
        // agreeing a key with an algorithm the server never said it
        // would use. The OID is the only thing that distinguishes them.
        let wants_2001 = suite.key_exchange
                         == crate::tls::suites::KeyExchange::GostVko2001;
        let (curve_name, x, y, algorithm_id) = match &leaf.public_key {
            PublicKey::Gost { legacy, .. } if *legacy != wants_2001 =>
                return Err(Error::new(
                    AlertDescription::UNSUPPORTED_CERTIFICATE, format!(
                    "{} needs a {} certificate; this one carries {}.",
                    suite.name, generation,
                    crate::x509::verify::describe_key(&leaf.public_key)))),
            // **The AlgorithmIdentifier travels with the point.** The
            // ephemeral key in the ClientKeyExchange has to wear the
            // server's, verbatim: the curve alone does not determine the
            // OID, because several OIDs name the same curve and the
            // server picked one. See `gost_kex::encode_public_key_like`.
            PublicKey::Gost { curve, x, y, algorithm_id, .. } =>
                (*curve, x.clone(), y.clone(), *algorithm_id),
            other => return Err(Error::new(
                AlertDescription::UNSUPPORTED_CERTIFICATE, format!(
                "{} needs a {} certificate; this one carries {}.",
                suite.name, generation,
                crate::x509::verify::describe_key(other)))),
        };
        let curve = crate::ec::curves::by_name(curve_name)
            .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
        let public = crate::ec::Point::new(x, y);

        // Validated here rather than trusted from the certificate: an
        // invalid-curve point would move the agreement into a group the
        // certificate's issuer chose, and `Certificate::parse` reads
        // rather than judges.
        curve.validate(&public)
            .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;

        // The two families wrap the secret quite differently - KEG and
        // KExp15 against KEG_28147 and KExp28147, and a different DER
        // structure - so which one is decided by the *suite*, here,
        // rather than by anything in the certificate.
        let (body, premaster) = match (suite.key_exchange, suite.cipher.ctr_omac()) {
            // The 2001 suite first, because it shares a cipher with
            // RFC 9189's CNT_IMIT and differs in everything around it:
            // GOST R 34.11-94 over the randoms, VKO GOST R
            // 34.10-2001, and CryptoPro-A wherever a table is needed.
            (crate::tls::suites::KeyExchange::GostVko2001, _) =>
                crate::tls::gost_kex_28147::client_key_exchange_2001(
                    &curve, algorithm_id, &public,
                    &self.client_random, &self.server_random),
            (_, Some(gost)) => crate::tls::gost_kex::client_key_exchange(
                gost, &curve, algorithm_id, &public,
                &self.client_random, &self.server_random),
            (_, None) => crate::tls::gost_kex_28147::client_key_exchange(
                &curve, algorithm_id, &public,
                &self.client_random, &self.server_random),
        }.map_err(|e| Error::new(AlertDescription::INTERNAL_ERROR, e))?;
        Ok((premaster, body))
    }

    /// ECDHE: a fresh key pair, and the premaster is the shared secret.
    ///
    /// Forward secret: the ephemeral private key is generated here, used
    /// once, and never written down, so a later compromise of the server's
    /// certificate key does not open a recorded session.
    ///
    /// The server's point was already validated and its signature checked
    /// in `handle_server_key_exchange` - by the time this runs, the
    /// ephemeral key is known to belong to the certificate.
    fn ecdhe_key_exchange(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let params = self.server_ecdh.as_ref().ok_or_else(|| Error::new(
            AlertDescription::UNEXPECTED_MESSAGE,
            "An ECDHE suite was negotiated but the server sent no \
             ServerKeyExchange."))?;

        if params.group == groups::X25519 || params.group == groups::X448 {
            return self.montgomery_key_exchange(params.group, &params.point);
        }

        let curve_name = groups::curve_name(params.group)
            .ok_or_else(|| Error::local("Unsupported group."))?;
        let curve = curves::by_name(curve_name).map_err(Error::local)?;

        let peer = curve.decode_point(&params.point).map_err(|e| Error::new(
            AlertDescription::ILLEGAL_PARAMETER, e))?;
        let (private, public) = curve.generate_key_pair().map_err(Error::local)?;

        // The shared secret is the X coordinate, and `ecdh` validates the
        // peer point again before touching it with our scalar.
        //
        // Its leading zeros stay: RFC 4492 5.10 forbids truncating
        // them, where RFC 5246 8.1.2 requires it for finite-field DH.
        // `keys::premaster_from_shared` is the one place that knows.
        let shared = curve.ecdh(&private, &peer)
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;
        let premaster = keys::premaster_from_shared(KeyExchange::EcdheRsa, shared);

        let encoded = curve.encode_point(&public, false).map_err(Error::local)?;
        let mut body = Writer::new();
        body.vector8(&encoded)?;
        Ok((premaster, body.finish()))
    }

    /// X25519, which is the same idea with none of the encoding.
    ///
    /// The peer's key needs no validation: every 32 byte string is a valid
    /// u coordinate, and the curve was chosen so that a value on the twist
    /// is not an attack. What replaces the on-curve check is the all-zero
    /// test inside `exchange`, which catches a peer sending one of the
    /// low-order points to force a shared secret everybody knows.
    /// X25519 or X448 at TLS 1.2, through the same `EphemeralKey` the 1.3
    /// path uses.
    ///
    /// **One function for both curves, and not because they are similar.**
    /// They are not: different clamp, different base point, different
    /// `a24`, and no spare high bit on Curve448. What is shared is the
    /// *shape* - generate, exchange, write the raw public value with a
    /// one-byte length - and the arithmetic that differs lives in
    /// `ec::x25519` and `ec::x448` behind `EphemeralKey`. A second copy of
    /// this function for X448 would be a second place for the length check
    /// to be written with the wrong number in it.
    ///
    /// The premaster keeps its leading zeros. RFC 8422 section 5.11 is
    /// explicit that the X25519 and X448 output is used as it comes, where
    /// RFC 5246 section 8.1.2 strips them for finite-field DH - the
    /// distinction `keys::premaster_from_shared` exists for.
    fn montgomery_key_exchange(&self, group: u16, peer: &[u8])
                               -> Result<(Vec<u8>, Vec<u8>), Error> {
        let key = EphemeralKey::generate(group).map_err(Error::local)?;
        // The length check is inside `complete`, and it names the curve
        // and the width it wanted - which is the message a caller needs
        // when a 32 byte X25519 key arrives for an X448 group.
        let premaster = key.complete(peer)
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;

        let mut body = Writer::new();
        body.vector8(key.public())?;
        Ok((premaster, body.finish()))
    }

    /// Finite-field DHE: the same shape as above in a different group.
    ///
    /// The one thing here that is not arithmetic is the last line. TLS
    /// 1.0-1.2 strip the leading zero bytes from the shared secret before
    /// using it as the premaster (RFC 5246 section 8.1.2), and TLS 1.3 and
    /// RFC 7919 do not. It matters about one handshake in 256 - which
    /// means an implementation with the wrong rule works for days and then
    /// fails one connection that nobody can reproduce.
    fn dhe_key_exchange(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let params = self.server_dh.as_ref().ok_or_else(|| Error::new(
            AlertDescription::UNEXPECTED_MESSAGE,
            "A DHE suite was negotiated but the server sent no \
             ServerKeyExchange."))?;

        // Rebuilt rather than stored: the group was already validated in
        // `handle_dh_key_exchange`, and carrying the parsed form would
        // mean two representations of the same numbers that have to agree.
        let group = dh::DhGroup::from_bytes(&params.p, &params.g)
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;
        let peer = BigUint::from_bytes_be(&params.public);

        let (private, public) = group.generate_key_pair().map_err(Error::local)?;
        let shared = group.shared_secret(&private, &peer)
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;
        // The stripping rule lives in one place for both sides and
        // both families - see `keys::strips_leading_zeros`, where the
        // opposite EC rule is written down beside it.
        let premaster = keys::premaster_from_shared(KeyExchange::DheRsa, shared);

        let mut body = Writer::new();
        body.vector16(&group.encode(&public).map_err(Error::local)?)?;
        Ok((premaster, body.finish()))
    }

    fn handle_change_cipher_spec(&mut self, payload: &[u8]) -> Result<(), Error> {
        // In TLS 1.3 this is a relic with no meaning. The keys changed at
        // the ServerHello and a record layer that acted on this one would
        // change them again. RFC 8446 appendix D.4: accept it, drop it,
        // carry on - it exists so that middleboxes watching for the shape
        // of a TLS 1.2 handshake let the connection through.
        //
        // `saw_retry_request` counts as knowing the version: a
        // HelloRetryRequest exists only in 1.3 and this client refuses
        // one that does not say so, so by the time we have answered
        // one the connection is 1.3 - but `negotiated_version` is not
        // set until a *real* ServerHello arrives, and the server sends
        // its compatibility ChangeCipherSpec in between. Without this
        // the retry path fails with "a ChangeCipherSpec while waiting
        // for the ServerHello", which is true and unhelpful.
        //
        // Dropped, not ignored: RFC 8446 5 allows it only after the first
        // ClientHello and **before the peer's Finished**, and one
        // received after that "MUST be treated as an unexpected record
        // type". Without the state check an on-path attacker could inject
        // plaintext records into an established connection forever and
        // have every one swallowed. Appendix D.4 has each side send
        // exactly one - after the HelloRetryRequest when there is one,
        // else after the ServerHello - which is what `saw_compat_ccs`
        // holds the server to.
        if self.negotiated_version == Some(Version::TLS13) || self.saw_retry_request {
            if payload != [1] {
                return Err(Error::new(AlertDescription::DECODE_ERROR,
                    "A ChangeCipherSpec is a single byte with value 1."));
            }
            // `WaitServerHello` is only the retry path: the record arrives
            // between the HelloRetryRequest and the real ServerHello.
            let before_finished = match self.state {
                State::WaitServerHello => self.saw_retry_request,
                State::WaitEncryptedExtensions
                | State::WaitCertificate13
                | State::WaitCertificateVerify
                | State::WaitServerFinished13 => true,
                _ => false,
            };
            if !before_finished || self.saw_compat_ccs {
                return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                    format!("A ChangeCipherSpec arrived while {}; at TLS 1.3 one \
                             is allowed, before the server's Finished.",
                            self.state.describe())));
            }
            self.saw_compat_ccs = true;
            return Ok(());
        }
        if self.state != State::WaitChangeCipherSpec {
            return Err(Error::unexpected(self.state.describe(), "a ChangeCipherSpec"));
        }
        if payload != [1] {
            return Err(Error::new(AlertDescription::DECODE_ERROR,
                                  "A ChangeCipherSpec is a single byte with value 1."));
        }
        // A half-delivered handshake message when the cipher changes is a
        // peer interleaving things it should not - and has been a real
        // attack, because the two halves are then authenticated under
        // different keys.
        if self.handshake.has_partial_message() {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                                  "ChangeCipherSpec arrived with a handshake message \
                                   only half delivered."));
        }

        let suite = self.suite.ok_or_else(|| Error::local("No suite."))?;
        let version = self.negotiated_version.ok_or_else(|| Error::local("No version."))?;
        let master = self.master.as_ref().ok_or_else(|| Error::local("No master."))?;
        let block = keys::key_block(version, suite, master, &self.client_random,
                                    &self.server_random).map_err(Error::local)?;

        let read_keys = self.protection(suite, version, &block.server)?;
        self.reader.change_cipher_spec(read_keys);

        self.state = State::WaitFinished;
        Ok(())
    }

    fn handle_finished(&mut self, message: &HandshakeMessage) -> Result<(), Error> {
        let finished = Finished::parse(&message.body)?;
        let suite = self.suite.ok_or_else(|| Error::local("No suite."))?;
        let version = self.negotiated_version.ok_or_else(|| Error::local("No version."))?;
        let master = self.master.as_ref().ok_or_else(|| Error::local("No master."))?;

        // The transcript here covers everything up to but not including
        // this Finished - `handle_handshake` defers the update for exactly
        // this reason.
        let transcript = self.transcript.as_ref()
            .ok_or_else(|| Error::local("No transcript."))?;
        let expected = if version == Version::SSL30 {
            transcript.ssl3_finished(master, Side::Server).map_err(Error::local)?
        } else {
            keys::verify_data(version, suite, master, Side::Server,
                              &transcript.hash()).map_err(Error::local)?
        };

        if !keys::verify_data_matches(&expected, &finished.verify_data) {
            // This is the check that makes everything above mean anything:
            // it proves the server saw the same handshake we did, with the
            // same keys. A failure here is a tampered handshake.
            return Err(Error::new(AlertDescription::DECRYPT_ERROR,
                                  "The server's Finished does not match the \
                                   handshake we saw. The handshake was tampered \
                                   with, or the keys disagree."));
        }

        self.peer_finished = Some(finished.verify_data.clone());

        self.state = State::Established;
        Ok(())
    }

    fn protection(&self, suite: &CipherSuite, version: Version,
                  direction: &keys::DirectionKeys) -> Result<Protection, Error> {
        crate::tls::record::protection_for(suite, version, direction,
                                           self.encrypt_then_mac)
            .map_err(Error::local)
    }

    // ----------------------------------------------------------- plumbing ---

    fn emit_handshake(&mut self, message: &HandshakeMessage) -> Result<(), Error> {
        let bytes = self.writer.write(ContentType::Handshake, &message.raw)?;
        self.outgoing.extend_from_slice(&bytes);
        Ok(())
    }

    fn send_alert(&mut self, alert: Alert) -> Result<(), Error> {
        let bytes = self.writer.write(ContentType::Alert, &alert.to_bytes())?;
        self.outgoing.extend_from_slice(&bytes);
        Ok(())
    }

    /// The extensions this client offers. One place, so the hello we send
    /// and the hello we hash cannot drift apart.
    ///
    /// **None at all for SSLv3.** Extensions were added by RFC 3546, two
    /// years after SSLv3, and a server old enough to speak nothing else is
    /// old enough to choke on a ClientHello that carries them - some close
    /// the connection, some fail the handshake, and the failure looks like
    /// a network problem rather than a protocol one. Sending none is not a
    /// limitation here, it is the version.
    ///
    /// The cost is real and worth stating: no SNI, so a name-based virtual
    /// host will answer with its default certificate; no encrypt-then-MAC,
    /// so the CBC suites are MAC-then-encrypt; and no extended master
    /// secret. All three are things SSLv3 genuinely does not have.
    fn hello_extensions(&mut self) -> Result<Vec<Extension>, Error> {
        if self.config.max_version == Version::SSL30 {
            return Ok(Vec::new());
        }
        let mut extensions = Vec::new();

        // **An empty `server_name` extension is not "no name".** RFC 6066
        // 3 defines the body as a non-empty list of names and forbids a
        // literal address in one, so a client with nothing to say omits
        // the extension rather than sending an empty list - which is
        // what a browser does when you type an IP address. Sending the
        // empty form instead makes some servers answer with an alert and
        // others with their default certificate, which is the worst
        // shape of bug: it works until it does not.
        if !self.hostname.is_empty() {
            extensions.push(Extension {
                kind: extension::SERVER_NAME,
                body: server_name_extension(&self.hostname)?,
            });
        }

        extensions.extend(vec![
            Extension { kind: extension::SIGNATURE_ALGORITHMS,
                        body: signature_algorithms_extension(
                            self.config.suites.offers_gost(),
                            self.config.suites.offers_dss())? },
            // The curves we can do, and the only point format anyone uses.
            // Without these a server will not choose an ECDHE suite, which
            // is most of what modern servers offer.
            Extension { kind: extension::SUPPORTED_GROUPS,
                        body: supported_groups_extension(
                            self.config.suites.offers_gost()
                                || self.config.suites.offers_gost_13(),
                            self.config.max_version >= Version::TLS13)? },
            Extension { kind: extension::EC_POINT_FORMATS,
                        body: vec![1, 0] },      // one format: uncompressed
        ]);
        if self.config.request_encrypt_then_mac {
            extensions.push(Extension { kind: extension::ENCRYPT_THEN_MAC,
                                        body: Vec::new() });
        }
        if self.config.request_extended_master_secret {
            extensions.push(Extension { kind: extension::EXTENDED_MASTER_SECRET,
                                        body: Vec::new() });
        }
        if !self.config.alpn.is_empty() {
            extensions.push(Extension { kind: extension::ALPN,
                                        body: encode_alpn_list(&self.config.alpn)? });
        }
        if self.config.request_stapled_ocsp {
            extensions.push(Extension {
                kind: extension::STATUS_REQUEST,
                body: crate::tls::handshake::encode_status_request(),
            });
        }

        if self.config.max_version >= Version::TLS13 {
            // The real version offer. The hello's own version field says
            // 1.2 forever, because a middlebox that has not been updated
            // since 2015 drops anything higher - so this extension is
            // where the negotiation actually happens.
            //
            // **Every version down to the floor, not just 1.2 and 1.3.**
            // RFC 8446 4.2.1 requires a client sending this extension to
            // list "all versions of TLS which they are prepared to
            // negotiate", and 4.1.2 requires a server that sees it to
            // *ignore* `legacy_version` entirely. So a list stopping at
            // 1.2 is a client saying it cannot speak TLS 1.0 - and a
            // modern server answers `protocol_version` rather than
            // coming down.
            //
            // That failure is the worst shape there is: an old OpenSSL
            // ignores the extension and negotiates from the version
            // field, so the connection works; a current one honours it
            // and refuses. "Works against some servers", with the ones
            // it fails against being exactly the modern boxes pinned to
            // an old version on purpose.
            let mut versions = Vec::new();
            let mut version = self.config.max_version;
            loop {
                versions.push(version);
                if version <= self.config.min_version || version.minor == 0 {
                    break;
                }
                version = Version::new(version.major, version.minor - 1);
            }
            extensions.push(Extension {
                kind: extension::SUPPORTED_VERSIONS,
                body: hs13::encode_client_supported_versions(&versions)?,
            });

            // signature_algorithms is rewritten rather than added to: a
            // 1.3 server must be offered the PSS schemes, and the TLS
            // 1.2 list has none of them. The v1.5 ones stay in it
            // because a certificate in the chain may be signed with one.
            //
            // The GOST pairs stay too, and that is not a detail. RFC
            // 9189 is a TLS 1.2 profile and its suites are in the same
            // hello; a client that offered 1.3 and thereby dropped (8,64)
            // and (8,65) would be offering a GOST suite it had just
            // declared it cannot authenticate. RFC 9189 section 4.2.1
            // lets a server proceed as if they were sent, so the failure
            // would be a server that works and a server that does not,
            // with nothing in the handshake to say why.
            if let Some(slot) = extensions.iter_mut()
                .find(|e| e.kind == extension::SIGNATURE_ALGORITHMS) {
                let mut schemes = scheme::OFFERED.to_vec();
                // **The GOST pairs come from the one list**, rather
                // than being named again here. They used to be: two of
                // them were pushed by hand, and when the legacy
                // spellings and the 2001 codepoint were added to
                // `signature_algorithms_extension` this branch went on
                // sending the old five. The effect was that offering
                // TLS 1.3 quietly dropped them - so a box that speaks
                // only the private-use values was reachable with
                // `--max-version TLSv1.2` and not otherwise, with
                // nothing in the handshake to say why.
                schemes.extend(gost_signature_schemes(
                    self.config.suites.offers_gost()));
                // The same for DSA, which a 1.2 DHE_DSS server picks
                // from this list even when the hello also offers 1.3.
                schemes.extend(dsa_signature_schemes(self.config.suites.offers_dss()));
                // **And RFC 9367's seven, which are a different set
                // again.** The five above are RFC 9189's TLS 1.2
                // codepoints; 0x0709..0x070F are the 1.3 ones, and a
                // 1.3 GOST server will not use a 1.2 codepoint. They go
                // in only when a GOST 1.3 suite is actually offered,
                // because a scheme offered with no suite that can use
                // it is a row nothing checks.
                if self.config.suites.offers_gost_13() {
                    schemes.extend_from_slice(scheme::GOST_13);
                }
                slot.body = hs13::encode_signature_algorithms(&schemes)?;
            }

            // A cookie from a HelloRetryRequest goes back **verbatim**.
            // It is the server's own state - it exists so the server
            // can stay stateless across the retry - and interpreting or
            // regenerating any of it would make the two halves
            // disagree about a value only the server understands.
            if let Some(cookie) = &self.retry_cookie {
                extensions.push(Extension { kind: extension::COOKIE,
                                            body: cookie.clone() });
            }

            let entries: Vec<KeyShareEntry> =
                self.key_shares.iter().map(|share| share.entry()).collect();
            extensions.push(Extension {
                kind: extension::KEY_SHARE,
                body: hs13::encode_client_key_share(&entries)?,
            });

            // ------------------------------------------- resumption ---
            //
            // Two extensions and an order that is not negotiable.
            // `psk_key_exchange_modes` says which kinds of PSK handshake
            // we will do; **only `psk_dhe_ke`**, because `psk_ke` alone
            // has no (EC)DHE in it and therefore no forward secrecy, and
            // a server that picked it would hand anyone who later
            // learns the PSK every byte of the connection.
            //
            // `pre_shared_key` **must be the last extension in the
            // ClientHello** (RFC 8446 4.2.11), and a server must refuse
            // one that is not. That is not style: the binders are an
            // HMAC over the hello with exactly the binder bytes cut off
            // the end, and the truncation is only well defined if they
            // are the last bytes of the message.
            if let Some(offer) = self.build_psk_offer()? {
                extensions.push(Extension {
                    kind: extension::PSK_KEY_EXCHANGE_MODES,
                    body: hs13::encode_psk_key_exchange_modes(
                        &[hs13::psk_mode::DHE_KE])?,
                });
                // **`early_data` goes before `pre_shared_key`**, because
                // that one has to be last. It is empty here: the
                // `max_early_data_size` body belongs to a
                // NewSessionTicket and nowhere else.
                //
                // Only on a first hello. After a HelloRetryRequest the
                // server has already spoken, the early keys were derived
                // over the first hello, and RFC 8446 4.2.10 says the
                // client must not offer early data in the second.
                if self.wants_early_data() && self.retry_cookie.is_none()
                    && !self.saw_retry_request {
                    extensions.push(Extension { kind: extension::EARLY_DATA,
                                                body: Vec::new() });
                    self.offered_early_data = true;
                }
                extensions.push(Extension {
                    kind: extension::PRE_SHARED_KEY,
                    body: offer.placeholder().map_err(Error::local)?
                          .encode()?,
                });
            }
        }
        Ok(extensions)
    }

    /// Whether to offer early data with this hello.
    ///
    /// **The first ticket decides**, because RFC 8446 4.2.10 binds early
    /// data to `identities[0]` - the keys come from that PSK, and the
    /// client has to derive them before hearing anything back. So a bag
    /// of tickets where the first permits no early data offers none,
    /// even if a later one would have.
    ///
    /// The limit is checked here rather than discovered at the server:
    /// sending more than the ticket allows is refused outright by RFC
    /// 8446 4.2.10, so a client that guessed would lose the whole
    /// connection rather than just the 0-RTT.
    fn wants_early_data(&self) -> bool {
        if self.config.early_data.is_empty() {
            return false;
        }
        match self.psk_offer.as_ref().and_then(|(_, tickets)| tickets.first()) {
            Some(ticket) => match ticket.max_early_data {
                Some(max) => self.config.early_data.len() as u64 <= max as u64,
                None => false,
            },
            None => false,
        }
    }

    /// The tickets worth offering, turned into an `Offer` and stashed.
    ///
    /// Returns the offer so the caller can write its placeholder, and
    /// keeps a copy with the binder keys and the tickets, so that the
    /// server's `selected_identity` can be turned back into a PSK.
    ///
    /// Filtering happens here rather than at the caller because every
    /// rule is a reason a ticket cannot be *used*, not a reason it is
    /// bad: a ticket for another host, one past its lifetime, one from
    /// a suite whose hash no offered 1.3 suite uses. Each is dropped
    /// silently, because a caller handing back a bag of stored tickets
    /// expects the unusable ones to be skipped rather than to fail the
    /// connection.
    fn build_psk_offer(&mut self) -> Result<Option<Offer>, Error> {
        self.psk_offer = None;
        if self.config.tickets.is_empty() {
            return Ok(None);
        }
        // Which KDF hashes the 1.3 suites we are about to offer use. A
        // ticket is bound to a hash (RFC 8446 4.6.1), and one that
        // matches nothing on offer would produce a binder of a length
        // the server cannot parse.
        let offered: Vec<&'static str> = self.config.suites
            .for_version(Version::TLS13).codes().iter()
            .filter_map(|code| suites::by_code(*code))
            .filter(|suite| suite.min_version >= Version::TLS13)
            .filter_map(|suite| tls13_hash(suite).ok())
            .collect();

        let now = self.config.policy.now;
        let usable: Vec<Ticket> = self.config.tickets.iter()
            .filter(|ticket| ticket.hostname == self.hostname)
            .filter(|ticket| ticket.is_usable_at(now))
            .filter(|ticket| offered.contains(&ticket.hash))
            .cloned()
            .collect();
        if usable.is_empty() {
            return Ok(None);
        }

        // One hash per offer: the binders are that hash's length and
        // the truncated hello is hashed once. The first usable
        // ticket's hash wins, and the rest are left for another
        // connection.
        let hash = usable[0].hash;
        let usable: Vec<Ticket> = usable.into_iter()
            .filter(|ticket| ticket.hash == hash)
            .collect();

        let borrowed: Vec<&Ticket> = usable.iter().collect();
        let offer = Offer::new(&borrowed, now).map_err(Error::local)?;
        let copy = Offer::new(&borrowed, now).map_err(Error::local)?;
        self.psk_offer = Some((copy, usable));
        Ok(Some(offer))
    }

    /// Compute the binders over a hello that has just been written, and
    /// put them where the placeholders are.
    ///
    /// `prefix` is the transcript through this hello: the hello itself
    /// on a first flight, and
    /// `message_hash || HelloRetryRequest || ClientHello2` after a
    /// retry. Either way the binder covers it **minus the binder
    /// bytes**, which is why this slices the prefix rather than
    /// re-encoding anything.
    fn seal_binders(&mut self, hello: &mut [u8], prefix: &mut [u8])
                    -> Result<(), Error> {
        let offer = match &self.psk_offer {
            Some((offer, _)) => offer,
            None => return Ok(()),
        };
        let placeholder = offer.placeholder().map_err(Error::local)?;
        let length = placeholder.binders_length();
        if prefix.len() < length || hello.len() < length {
            return Err(Error::local("The ClientHello is shorter than the \
                                     binders it was written with."));
        }
        let truncated = &prefix[..prefix.len() - length];
        let binders = offer.seal(truncated).map_err(Error::local)?;

        resumption::splice_binders(hello, &binders).map_err(Error::local)?;
        let at = prefix.len() - length;
        prefix[at..].copy_from_slice(&hello[hello.len() - length..]);
        Ok(())
    }

    /// The ClientHello's raw bytes, exactly as they were written.
    fn client_hello_raw(&self) -> Result<Vec<u8>, Error> {
        if self.transcript_prefix.is_empty() {
            return Err(Error::local("The ClientHello has not been written yet."));
        }
        Ok(self.transcript_prefix.clone())
    }
}

/// The client's ALPN offer: a list of length-prefixed names inside a
/// two-byte length. The same wire shape as the server's answer, which is
/// simply a list with one entry in it.
fn encode_alpn_list(protocols: &[String]) -> Result<Vec<u8>, Error> {
    let mut list = crate::tls::codec::Writer::new();
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > 255 {
            return Err(Error::local(format!(
                "An ALPN protocol name is 1..=255 bytes; {:?} is {}.",
                protocol, protocol.len())));
        }
        list.vector8(protocol.as_bytes())?;
    }
    let mut writer = crate::tls::codec::Writer::new();
    writer.vector16(&list.finish())?;
    Ok(writer.finish())
}

/// A TLS 1.3 suite's AEAD, as (name, key length, tag length).
///
/// Separate from the TLS 1.2 lookup in `protection` because the two ask
/// different questions: 1.2 also needs an explicit nonce length, and 1.3
/// has none. The tag length comes from the suite rather than being 16,
/// because TLS_AES_128_CCM_8_SHA256 exists to make it 8.
fn tls13_aead(suite: &CipherSuite)
              -> Result<crate::tls::handshake13::Tls13Aead, Error> {
    crate::tls::handshake13::tls13_aead(suite).map_err(Error::local)
}

/// The hash a TLS 1.3 suite's schedule runs on, as a `&'static str`
/// because the record layer carries it forward into every key update.
fn tls13_hash(suite: &CipherSuite) -> Result<&'static str, Error> {
    crate::tls::handshake13::tls13_hash(suite).map_err(Error::local)
}

/// The groups this client offers, strongest first.
///
/// A server that picks something else is choosing the group for us, which
/// `handle_server_key_exchange` refuses.
///
/// X25519 is offered first among the 128-bit-security groups because it is
/// the one whose implementation has the fewest ways to be wrong: no point
/// encoding, no on-curve check, and a twist chosen so that landing on it
/// is not an attack. P-384 stays ahead of it on strength alone.
///
/// X448 leads on the same reasoning that puts P-384 ahead of X25519 - it
/// is the strongest group here, about 224 bits against P-384's 192 - and
/// it costs nothing to name: two bytes in the hello, and no key generation
/// unless a server asks for it, because it is deliberately not in
/// `TLS13_KEY_SHARE_GROUPS` below.
///
/// **P-521 last, out of strength order.** It is here for the server that
/// has nothing else - some appliances were configured for "the strongest
/// curve" once and never again - and not for one with a choice: a 1.2
/// server that honours the client's order would otherwise pick it over
/// P-384, and a P-521 exchange costs several times as much for a margin
/// nobody needs.
const OFFERED_GROUPS: &[u16] =
    &[groups::X448, groups::SECP384R1, groups::X25519, groups::SECP256R1,
      groups::SECP521R1];

/// The groups a TLS 1.3 ClientHello sends an actual key share for.
///
/// A subset of `OFFERED_GROUPS`, because a share costs a key generation
/// and a few hundred bytes in the hello while `supported_groups` costs two
/// bytes. A server wanting one of the others answers with a
/// HelloRetryRequest, which is a round trip rather than a failure.
///
/// P-384 is deliberately not here: no server prefers it strongly enough to
/// be worth generating a key for on every connection, and it stays in
/// `supported_groups` so one that does can ask.
///
/// **X448 is not here either, and that is a measurement rather than a
/// guess.** An X448 key pair costs 2.3 times an X25519 one on this
/// library's bignum (2.3 ms against 1.0 ms), paid on every connection
/// whether or not any server wants it - and none prefers it. A server that
/// does asks with a HelloRetryRequest, which is one round trip.
const TLS13_KEY_SHARE_GROUPS: &[u16] = &[groups::X25519, groups::SECP256R1];

/// The hybrid post-quantum groups a TLS 1.3 ClientHello sends a share for,
/// ahead of the classical ones.
///
/// **X25519MLKEM768 only**, which is what browsers send: it is what
/// servers that support post-quantum key exchange prefer, so a share for
/// it saves the round trip, and it costs about 1.2 KB in the hello and
/// an ML-KEM key generation - a fraction of an X25519 one on this
/// library. The other two hybrids are in `supported_groups`, and a server
/// that wants one asks with a HelloRetryRequest.
///
/// Sent only when TLS 1.3 is on offer. A client capped at 1.2 sends no
/// hybrid share and names no hybrid group, so a 1.2-only ClientHello is
/// exactly what it was before these existed - which matters for the old
/// servers this library is for, some of which mishandle a large hello.
const TLS13_HYBRID_SHARES: &[u16] = &[groups::X25519_MLKEM768];

/// The supported_groups body, with the GOST curves appended when a GOST
/// suite is on offer.
///
/// **Only then.** The seven GOST groups are meaningless to a server
/// that speaks none of those suites, and a ClientHello that names
/// curves it cannot use is a ClientHello that lies about itself. When
/// a GOST suite *is* offered they matter: a box with both a 256 bit
/// and a 512 bit certificate chooses between them by this list, and a
/// client that sends nothing gets whichever the server likes - which
/// may be a curve it cannot do.
fn supported_groups_extension(with_gost: bool, with_hybrid: bool)
        -> Result<Vec<u8>, CodecError> {
    // The hybrids first: supported_groups is in preference order, and a
    // client offering post-quantum protection prefers it.
    let mut codes = if with_hybrid { groups::HYBRID.to_vec() } else { Vec::new() };
    codes.extend_from_slice(OFFERED_GROUPS);
    if with_gost {
        codes.extend_from_slice(groups::GOST);
    }
    let mut writer = Writer::new();
    writer.u16_list(&codes)?;
    Ok(writer.finish())
}

fn server_name_extension(hostname: &str) -> Result<Vec<u8>, CodecError> {
    let mut writer = Writer::new();
    writer.nested16(|list| {
        list.u8(0);                                  // host_name
        list.vector16(hostname.as_bytes())
    })?;
    Ok(writer.finish())
}

/// An EdDSA signature (RFC 8032) over `message` itself - there is no
/// digest - checked against the peer's certificate key.
///
/// One routine for the four places it is needed: a TLS 1.3
/// CertificateVerify in either direction, a TLS 1.2 ServerKeyExchange
/// (RFC 8422 5.4, over the randoms and the params) and a TLS 1.2
/// CertificateVerify (RFC 8422 5.8, over the raw handshake messages).
/// What is signed differs; how it is checked does not. Ed448's context is
/// empty in all of them (RFC 8422 5.10, RFC 8446 4.2.3).
///
/// The scheme names the variant and so does the key; a mismatch is
/// refused by name, as an ECDSA scheme bound to the wrong curve is.
pub(crate) fn verify_eddsa(key: &PublicKey<'_>, scheme: u16, message: &[u8],
                           signature: &[u8]) -> Result<(), Error> {
    let named = match scheme {
        scheme::ED25519 => "ed25519",
        scheme::ED448 => "ed448",
        other => return Err(Error::local(format!("{} is not EdDSA.", scheme::name(other)))),
    };
    let key = match key {
        PublicKey::Eddsa { curve, key } if *curve == named => *key,
        PublicKey::Eddsa { curve, .. } => return Err(Error::new(
            AlertDescription::ILLEGAL_PARAMETER, format!(
                "The peer signed with {} but its certificate carries a {} key.",
                scheme::name(scheme), curve))),
        other => return Err(Error::new(AlertDescription::UNSUPPORTED_CERTIFICATE, format!(
            "The peer signed with {} but its certificate carries {}.",
            scheme::name(scheme), crate::x509::verify::describe_key(other)))),
    };
    let valid = crate::api::eddsa_verify(named, key, message, signature, &[])
        .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?;
    if valid {
        Ok(())
    } else {
        Err(Error::new(AlertDescription::DECRYPT_ERROR, format!(
            "The peer's signature does not verify against its certificate's {} \
             key.", named)))
    }
}

/// A TLS 1.3 CertificateVerify made with ML-DSA, checked against the
/// peer's certificate key. Shared by both directions: the server checks a
/// client's with the same rule.
///
/// The scheme names a parameter set and so does the certificate; a
/// mismatch is refused by name, as an ECDSA scheme bound to the wrong
/// curve is, rather than reported as a bad signature.
pub(crate) fn verify_ml_dsa_13(key: &PublicKey<'_>, scheme: u16, named: &'static str,
                               content: &[u8], signature: &[u8]) -> Result<(), Error> {
    let key = match key {
        PublicKey::MlDsa { parameter_set, key } if *parameter_set == named => *key,
        other => return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
            "The peer signed with {} but its certificate carries {}.",
            scheme::name(scheme), crate::x509::verify::describe_key(other)))),
    };
    let parameters = crate::pq::ml_dsa::parameters(named).map_err(Error::local)?;
    let valid = crate::pq::ml_dsa::verify(parameters, key, content, &[], None, signature)
        .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?;
    if valid {
        Ok(())
    } else {
        Err(Error::new(AlertDescription::DECRYPT_ERROR, format!(
            "The peer's CertificateVerify does not verify against its \
             certificate's {} key.", named)))
    }
}

/// The GOST signature algorithm codepoints, in one place.
///
/// Five of them, and every one is needed by something:
///
///   * (8, 64) and (8, 65) are RFC 9189 section 5, which section 4.2.1
///     *requires* a ClientHello to carry for its suites - and says a
///     server may proceed as if they had been sent, so omitting them
///     works against some servers and not others.
///   * 0xEEEE and 0xEFEF are the same two algorithms as a box older
///     than RFC 9189 names them (section 10 of the same document):
///     before IANA assigned the pairs, implementations used single
///     private-use bytes for the signature, the hash and the
///     certificate type at once.
///   * 0xEDED is GOST R 34.10-2001 with GOST R 34.11-94, which never
///     got an IANA codepoint at all and is what the 0x0081 suite
///     signs with.
fn gost_signature_schemes(offered: bool) -> Vec<u16> {
    if !offered {
        return Vec::new();
    }
    [SignatureScheme::GOST_256, SignatureScheme::GOST_512,
     SignatureScheme::GOST_256_LEGACY, SignatureScheme::GOST_512_LEGACY,
     SignatureScheme::GOST_2001]
        .iter().map(|scheme| scheme.to_u16()).collect()
}

/// The DSA pairs, when a DHE_DSS suite is offered. TLS 1.2 only: RFC 8446
/// removed DSA, so they go in alongside the 1.3 schemes rather than in
/// place of anything.
fn dsa_signature_schemes(offered: bool) -> Vec<u16> {
    if !offered {
        return Vec::new();
    }
    [SignatureScheme::DSA_SHA256, SignatureScheme::DSA_SHA384,
     SignatureScheme::DSA_SHA512, SignatureScheme::DSA_SHA224,
     SignatureScheme::DSA_SHA1]
        .iter().map(|scheme| scheme.to_u16()).collect()
}

fn signature_algorithms_extension(with_gost: bool, with_dss: bool)
                                  -> Result<Vec<u8>, CodecError> {
    let mut schemes: Vec<u16> = [
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_SHA256,
        SignatureScheme::ECDSA_SHA384,
        SignatureScheme::ECDSA_SHA512,
    ].iter().map(|scheme| scheme.to_u16()).collect();
    // RFC 8422 section 5.1.3: EdDSA at 1.2, as (8, 7) and (8, 8). Without
    // them a 1.2-only hello leaves an EdDSA server nothing to sign with.
    schemes.extend([scheme::ED25519, scheme::ED448]);
    schemes.extend(gost_signature_schemes(with_gost));
    schemes.extend(dsa_signature_schemes(with_dss));
    // SHA-1 last, and offered at all only because some old servers have
    // nothing else. A server that picks it is telling us something.
    schemes.push(SignatureScheme::RSA_PKCS1_SHA1.to_u16());
    let mut writer = Writer::new();
    writer.u16_list(&schemes)?;
    Ok(writer.finish())
}

/// `Policy::check_key_ceiling` as an alert, for a key taken from a peer's
/// certificate. Shared by both ends: the server's key here, a client's in
/// `server13`. A key that size is not weak but unusable, so the alert is
/// `unsupported_certificate` rather than `insufficient_security`.
pub(crate) fn key_ceiling(policy: &Policy, what: &str, bits: usize) -> Result<(), Error> {
    policy.check_key_ceiling(what, bits)
        .map_err(|e| Error::new(AlertDescription::UNSUPPORTED_CERTIFICATE, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ClientConfig {
        let mut store = TrustStore::new();
        // A store with something in it, so the "no roots" check does not
        // fire; the contents do not matter for the tests that never get as
        // far as verifying.
        store.add_der(&sample_root()).ok();
        ClientConfig::new(store, 1_700_000_000)
    }

    fn sample_root() -> Vec<u8> {
        use crate::ec::curves;
        use crate::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
        let curve = curves::p256();
        let (private, public) = curve.generate_key_pair().unwrap();
        let point = curve.encode_point(&public, false).unwrap();
        let mut builder = CertificateBuilder::new("Test Root",
                                                  SubjectKey::Ec { curve: &curve,
                                                                   point: &point });
        builder.is_ca = Some((true, None));
        builder.sign(&SigningKey::Ec { curve: &curve, private: &private }).unwrap()
    }

    /// Our own server, and a client whose hello carries **no** key share,
    /// so the server has to send a HelloRetryRequest.
    ///
    /// RFC 8446 4.2.8 allows an empty share list, and nothing else forces
    /// a retry between these two ends: the pair of shares every browser
    /// sends covers whatever this library's server prefers, so a handshake
    /// between them never retries on its own - which is why
    /// `server::tests::test_tls13_hello_retry_request` completes in the
    /// ordinary two round trips and exercises no retry at all. The hello
    /// written at construction is discarded and a second one written over
    /// an emptied share list.
    fn retrying_pair() -> (ClientConnection, crate::tls::server::ServerConnection) {
        use crate::tls::server::{ServerConfig, ServerConnection, ServerKey};
        use crate::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};

        let curve = crate::ec::curves::p256();
        let (private, public) = curve.generate_key_pair().unwrap();
        let point = curve.encode_point(&public, false).unwrap();
        let leaf = CertificateBuilder::new(
            "retry.test", SubjectKey::Ec { curve: &curve, point: &point })
            .sign(&SigningKey::Ec { curve: &curve, private: &private }).unwrap();
        let server = ServerConnection::new(ServerConfig::new(
            vec![leaf], ServerKey::Ec { curve: "P-256", private })).unwrap();

        let mut config = config();
        config.verify_certificate = false;
        let mut client = ClientConnection::new(config, "retry.test").unwrap();
        client.take_outgoing();
        client.key_shares = Vec::new();
        client.send_client_hello().unwrap();
        (client, server)
    }

    /// Pump the two ends until neither has anything to say, collecting
    /// every byte the server wrote.
    fn pump_collecting_server_output(
        client: &mut ClientConnection,
        server: &mut crate::tls::server::ServerConnection) -> Vec<u8> {
        let mut from_server = Vec::new();
        for _ in 0..6 {
            let to_server = client.take_outgoing();
            server.push_incoming(&to_server);
            server.process().expect("the server refused the client");
            let flight = server.take_outgoing();
            if to_server.is_empty() && flight.is_empty() {
                break;
            }
            from_server.extend_from_slice(&flight);
            client.push_incoming(&flight);
            client.process().expect("the client refused the server");
        }
        from_server
    }

    /// A HelloRetryRequest from this library's own server completes.
    ///
    /// What was wrong: the server fed the second ClientHello into the
    /// transcript twice - once in `handle_handshake`, which updates the
    /// transcript whenever one exists and after a retry one does, and
    /// once more in `handle_client_hello_13`, which added the hello it
    /// had just been handed. The handshake keys were then derived over a
    /// transcript no client computes, and the client's first encrypted
    /// record failed to authenticate. No test saw it because the only
    /// retry the suite drove was OpenSSL retrying *this client*, and the
    /// server's own retry test never produced a retry (see
    /// `retrying_pair`).
    #[test]
    fn test_a_hello_retry_request_from_our_own_server_completes() {
        let (mut client, mut server) = retrying_pair();
        pump_collecting_server_output(&mut client, &mut server);
        assert!(client.saw_retry_request, "no HelloRetryRequest arrived");
        assert!(client.is_established(), "client: {:?}", client.state());
        assert!(server.is_established(), "server: {}", server.state());

        // And the application keys agree, which the Finished alone does
        // not show.
        client.write(b"after the retry").unwrap();
        server.push_incoming(&client.take_outgoing());
        server.process().unwrap();
        assert_eq!(server.take_incoming(), b"after the retry");
        server.write(b"and back").unwrap();
        client.push_incoming(&server.take_outgoing());
        client.process().unwrap();
        assert_eq!(client.take_incoming(), b"and back");
    }

    /// After a HelloRetryRequest the server sends its compatibility
    /// ChangeCipherSpec once - after the retry, as RFC 8446 appendix D.4
    /// places it, and not again after the real ServerHello.
    ///
    /// Pinned on the bytes because this client refuses a second
    /// ChangeCipherSpec, so a server that still sent two would fail only
    /// its own client, after a retry, over a record it sent itself.
    #[test]
    fn test_the_retry_path_sends_one_change_cipher_spec() {
        let (mut client, mut server) = retrying_pair();
        let from_server = pump_collecting_server_output(&mut client, &mut server);
        assert!(client.saw_retry_request, "no HelloRetryRequest arrived");
        assert!(client.is_established(), "client: {:?}", client.state());

        let mut ccs = 0;
        let mut at = 0;
        while at + 5 <= from_server.len() {
            let length = u16::from_be_bytes([from_server[at + 3],
                                             from_server[at + 4]]) as usize;
            if from_server[at] == ContentType::ChangeCipherSpec.to_byte() {
                ccs += 1;
            }
            at += 5 + length;
        }
        assert_eq!(ccs, 1, "the server sent {} ChangeCipherSpec records", ccs);
    }

    /// A HelloRetryRequest is answered with a second hello carrying the
    /// group the server asked for - and the transcript is rebuilt, not
    /// appended to.
    ///
    /// RFC 8446 section 4.4.1 replaces the first ClientHello with a
    /// **hash of itself** inside a synthetic `message_hash` message. A
    /// transcript built from the bytes that actually crossed the wire
    /// is wrong, and wrong in a way that appears only at the Finished
    /// check with nothing to say a retry caused it - so the check here
    /// is on the transcript's shape rather than on the handshake
    /// completing.
    #[test]
    fn test_a_hello_retry_request_is_answered() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        let first_hello = connection.client_hello_bytes.clone();
        connection.take_outgoing();

        // The client offers shares for x25519 and P-256, so a retry has
        // to ask for something else it did offer in supported_groups.
        assert!(!connection.key_shares.iter().any(|s| s.group() == groups::SECP384R1));
        let retry = retry_request(0x1301, groups::SECP384R1, Some(b"opaque state"));
        connection.dispatch_handshake(&retry).unwrap();

        // A second hello went out, with one share, for the named group.
        let out = connection.take_outgoing();
        assert!(!out.is_empty(), "the retry was not answered");
        assert_eq!(connection.key_shares.len(), 1);
        assert_eq!(connection.key_shares[0].group(), groups::SECP384R1);
        assert_eq!(connection.state, State::WaitServerHello);

        let mut reader = crate::tls::handshake::HandshakeReader::new();
        reader.push(&out[5..]);
        let second = reader.next_message().unwrap().expect("no second hello");
        assert_eq!(second.message_type, HandshakeType::ClientHello);
        let parsed = ClientHello::parse(&second.body).unwrap();

        // The random is the **same**: a fresh one is a different
        // handshake, and the server has already hashed this one.
        assert_eq!(parsed.random, connection.client_random);

        // The cookie comes back verbatim.
        let cookie = find_extension(&parsed.extensions, extension::COOKIE)
            .expect("the cookie was not echoed");
        assert_eq!(cookie.body, b"opaque state");

        // And the transcript prefix is the synthetic message, the
        // retry, and the second hello - not the first hello at all.
        let mut hasher = crate::api::AnyHash::new("sha256").unwrap();
        hasher.update(&first_hello);
        let synthetic = HandshakeMessage::new(HandshakeType::MessageHash,
                                              hasher.digest()).unwrap();
        let mut expected = synthetic.raw.clone();
        expected.extend_from_slice(&retry.raw);
        expected.extend_from_slice(&second.raw);
        assert_eq!(connection.client_hello_raw().unwrap(), expected);
        assert!(!connection.client_hello_raw().unwrap()
                    .windows(first_hello.len()).any(|w| w == first_hello),
                "the first hello is still in the transcript, which RFC 8446 \
                 section 4.4.1 replaces with a hash of it");
        // The synthetic message is type 254 with a three byte length,
        // which is what makes it a handshake message rather than a bare
        // hash.
        assert_eq!(synthetic.raw[0], 254);
        assert_eq!(&synthetic.raw[1..4], &[0, 0, 32]);
    }

    /// After a HelloRetryRequest, the real ServerHello must keep the
    /// retry's suite, stay at TLS 1.3 and answer with the requested
    /// group.
    ///
    /// What was wrong: nothing after `saw_retry_request` compared the
    /// ServerHello with the retry. A 1.2 ServerHello took the 1.2 path
    /// over a transcript prefix holding a synthetic `message_hash` and
    /// failed later with nothing to say a retry caused it; a different
    /// suite went into the key schedule under a hash the retry had not
    /// committed to. RFC 8446 4.1.4 requires `illegal_parameter` for
    /// each. No test saw it because the only retries driven were honest
    /// ones, OpenSSL's and this library's server's, and each of them
    /// answers with exactly what it asked for.
    #[test]
    fn test_a_server_hello_after_a_retry_must_match_the_retry() {
        use crate::tls::handshake13::encode_server_supported_version;
        let group = groups::SECP384R1;
        let fresh = || {
            let mut connection = ClientConnection::new(config(), "example.test")
                .unwrap();
            connection.take_outgoing();
            connection.dispatch_handshake(&retry_request(0x1301, group, None))
                .unwrap();
            assert_eq!(connection.retry_choice, Some((0x1301, group)));
            connection
        };
        let share = |group: u16| {
            let key = EphemeralKey::generate(group).unwrap();
            Extension { kind: extension::KEY_SHARE,
                        body: hs13::encode_server_key_share(&key.entry()).unwrap() }
        };
        let supported = Extension { kind: extension::SUPPORTED_VERSIONS,
                                    body: encode_server_supported_version(Version::TLS13) };
        let hello = |suite: u16, extensions: Vec<Extension>| {
            let hello = ServerHello {
                legacy_version: Version::TLS12,
                random: [7u8; 32],
                session_id: Vec::new(),
                cipher_suite: suite,
                compression_method: 0,
                extensions,
            };
            HandshakeMessage::new(HandshakeType::ServerHello, hello.encode().unwrap())
                .unwrap()
        };

        // A different suite from the one the retry named.
        let error = fresh().dispatch_handshake(
            &hello(0x1302, vec![supported.clone(), share(group)])).unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("settled by the retry"), "{}", error.detail);

        // TLS 1.2: no supported_versions, so the legacy field decides.
        let error = fresh().dispatch_handshake(
            &hello(0x1301, vec![share(group)])).unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("TLS 1.3"), "{}", error.detail);

        // A share for a group other than the one asked for.
        let error = fresh().dispatch_handshake(
            &hello(0x1301, vec![supported.clone(), share(groups::SECP256R1)]))
            .unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("asked for"), "{}", error.detail);

        // And the matching answer gets past all three checks: it fails
        // only further on, at the key schedule's certificate, which is
        // the next state and not a retry complaint.
        let mut connection = fresh();
        connection.dispatch_handshake(&hello(0x1301, vec![supported, share(group)]))
            .unwrap();
        assert_eq!(connection.state, State::WaitEncryptedExtensions);
    }

    /// The retries that must be refused.
    #[test]
    fn test_a_hello_retry_request_that_cannot_help_is_refused() {
        // A group we already sent a share for: answering would send the
        // same hello again, so the server is either mistaken or making
        // us work.
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        let already = connection.key_shares[0].group();
        let error = connection.dispatch_handshake(
            &retry_request(0x1301, already, None)).unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("already"), "{}", error.detail);

        // A group we never offered at all.
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        let error = connection.dispatch_handshake(
            &retry_request(0x1301, 0xfefe, None)).unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));

        // A suite we never offered.
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        let error = connection.dispatch_handshake(
            &retry_request(0x00ff, groups::SECP384R1, None)).unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));

        // And a second retry, which could otherwise loop forever.
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        connection.dispatch_handshake(
            &retry_request(0x1301, groups::SECP384R1, None)).unwrap();
        connection.take_outgoing();
        let error = connection.dispatch_handshake(
            &retry_request(0x1301, groups::SECP521R1, None)).unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE));
        assert!(error.detail.contains("second"), "{}", error.detail);
    }

    /// A HelloRetryRequest, as a server would send it: a ServerHello
    /// whose random is the fixed value from RFC 8446 section 4.1.3.
    fn retry_request(suite: u16, group: u16, cookie: Option<&[u8]>)
                     -> HandshakeMessage {
        let mut extensions = vec![
            Extension { kind: extension::SUPPORTED_VERSIONS,
                        body: Version::TLS13.to_bytes().to_vec() },
            Extension { kind: extension::KEY_SHARE,
                        body: group.to_be_bytes().to_vec() },
        ];
        if let Some(cookie) = cookie {
            extensions.push(Extension { kind: extension::COOKIE,
                                        body: cookie.to_vec() });
        }
        let hello = ServerHello {
            legacy_version: Version::TLS12,
            random: hs13::HELLO_RETRY_REQUEST_RANDOM,
            session_id: Vec::new(),
            cipher_suite: suite,
            compression_method: 0,
            extensions,
        };
        HandshakeMessage::new(HandshakeType::ServerHello, hello.encode().unwrap())
            .unwrap()
    }

    /// A HelloRequest is refused at TLS 1.3, declined with a warning on
    /// an established 1.2 connection, and ignored mid-handshake.
    ///
    /// What was wrong: every HelloRequest, at any version and in any
    /// state, was answered with a `no_renegotiation` warning. At 1.3 the
    /// message does not exist and belongs with every other message out
    /// of place; mid-handshake RFC 5246 7.4.1.1 says to ignore it. No
    /// server in the tests sends one, so the messages are dispatched by
    /// hand.
    #[test]
    fn test_a_hello_request_is_answered_by_version_and_state() {
        let request = HandshakeMessage::new(HandshakeType::HelloRequest, vec![])
            .unwrap();

        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        connection.state = State::Established;
        connection.negotiated_version = Some(Version::TLS13);
        let error = connection.dispatch_handshake(&request).unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE));

        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        connection.state = State::Established;
        connection.negotiated_version = Some(Version::TLS12);
        connection.dispatch_handshake(&request).unwrap();
        let out = connection.take_outgoing();
        assert_eq!(out.first(), Some(&ContentType::Alert.to_byte()));
        let alert = Alert::parse(&out[5..]).unwrap();
        assert_eq!(alert, Alert::warning(AlertDescription::NO_RENEGOTIATION));
        assert!(connection.is_established());

        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        assert_eq!(connection.state, State::WaitServerHello);
        connection.dispatch_handshake(&request).unwrap();
        assert!(connection.take_outgoing().is_empty(),
                "a HelloRequest mid-handshake was answered");
        assert_eq!(connection.state, State::WaitServerHello);
    }

    /// A TLS 1.3 KeyUpdate steps the reading epoch, and only that.
    ///
    /// The two directions change keys independently: a KeyUpdate says
    /// the *sender* has changed its own, so stepping ours as well would
    /// encrypt under a key the peer has not derived - and the failure
    /// would look like a MAC error on a record we sent rather than like
    /// a missing feature.
    ///
    /// Driven through the dispatch table with a real record layer,
    /// because the Python harness cannot make OpenSSL send one (Python
    /// exposes no `SSL_key_update`). An earlier version of this test
    /// drove it on a connection with no 1.3 protection at all, so it
    /// passed on the "this is not a 1.3 connection" branch and never
    /// reached the epoch logic - which is why the assertions below are
    /// about records decrypting rather than about an error message.
    #[test]
    fn test_a_key_update_steps_the_reading_epoch_only() {
        use crate::tls::keys13::TrafficKeys;
        use crate::tls::record13::Aead13;

        let keys = |secret: &[u8]| TrafficKeys::derive("sha256", secret, 16, 12).unwrap();
        let client_secret = [0x11u8; 32];
        let server_secret = [0x22u8; 32];

        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        // The ClientHello is already queued from construction; drop it,
        // or the first "did we answer?" check sees it.
        connection.take_outgoing();
        connection.state = State::Established;
        connection.negotiated_version = Some(Version::TLS13);
        connection.reader.change_cipher_spec(Protection::Aead13(
            Aead13::new("aes-gcm", "sha256", keys(&server_secret), 16).unwrap()));
        connection.writer.change_cipher_spec(Protection::Aead13(
            Aead13::new("aes-gcm", "sha256", keys(&client_secret), 16).unwrap()));

        // The peer's side of both directions, kept in step by hand.
        let mut peer_writes = Aead13::new("aes-gcm", "sha256",
                                          keys(&server_secret), 16).unwrap();
        let mut peer_reads = Aead13::new("aes-gcm", "sha256",
                                         keys(&client_secret), 16).unwrap();

        // --- update_not_requested: our reader moves, our writer does not ---
        let message = HandshakeMessage::new(HandshakeType::KeyUpdate,
                                            vec![0]).unwrap();
        connection.dispatch_handshake(&message).unwrap();
        assert!(connection.take_outgoing().is_empty(),
                "an unrequested KeyUpdate must not be answered");

        peer_writes.update().unwrap();
        let record = peer_writes.encrypt(ContentType::ApplicationData,
                                         b"after one update", 0).unwrap();
        match connection.reader.protection_mut() {
            Protection::Aead13(state) => {
                let (kind, payload) = state.decrypt(&record).unwrap();
                assert_eq!(kind, ContentType::ApplicationData);
                assert_eq!(payload, b"after one update");
            }
            other => panic!("the reader is {}", other.name()),
        }

        // Our writer is untouched, so the peer still reads it at the
        // old epoch - and its sequence number has not restarted.
        connection.write(b"still the old key").unwrap();
        connection.process().unwrap();
        let ours = connection.take_outgoing();
        let (kind, payload) = peer_reads.decrypt(&ours[5..]).unwrap();
        assert_eq!(kind, ContentType::ApplicationData);
        assert_eq!(payload, b"still the old key");

        // --- update_requested: we answer, then move our writer ---
        let message = HandshakeMessage::new(HandshakeType::KeyUpdate,
                                            vec![1]).unwrap();
        connection.dispatch_handshake(&message).unwrap();
        connection.process().unwrap();
        let reply = connection.take_outgoing();
        assert!(!reply.is_empty(), "a requested KeyUpdate must be answered");

        // The reply goes out under the **old** key: the peer has not
        // changed its reading epoch until it has seen this message.
        let (kind, payload) = peer_reads.decrypt(&reply[5..]).unwrap();
        assert_eq!(kind, ContentType::Handshake);
        let answer = HandshakeMessage::new(HandshakeType::KeyUpdate,
                                           vec![0]).unwrap();
        assert_eq!(payload, answer.raw,
                   "the reply must carry update_not_requested, or two \
                    implementations would update each other forever");
        peer_reads.update().unwrap();

        // Now both of our epochs have moved once more.
        peer_writes.update().unwrap();
        let record = peer_writes.encrypt(ContentType::ApplicationData,
                                         b"after two", 0).unwrap();
        match connection.reader.protection_mut() {
            Protection::Aead13(state) =>
                assert_eq!(state.decrypt(&record).unwrap().1, b"after two"),
            other => panic!("the reader is {}", other.name()),
        }

        connection.write(b"new key").unwrap();
        connection.process().unwrap();
        let ours = connection.take_outgoing();
        assert_eq!(peer_reads.decrypt(&ours[5..]).unwrap().1, b"new key");
    }

    /// An unknown `request_update` is fatal, and a KeyUpdate on a
    /// connection with no key epochs is refused by name.
    #[test]
    fn test_a_malformed_key_update_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.state = State::Established;
        connection.negotiated_version = Some(Version::TLS13);

        // No 1.3 protection: there is no epoch to step.
        let message = HandshakeMessage::new(HandshakeType::KeyUpdate,
                                            vec![0]).unwrap();
        let error = connection.dispatch_handshake(&message).unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE));
        assert!(error.detail.contains("key epochs"), "{}", error.detail);

        for body in [vec![], vec![2], vec![0, 0]] {
            let message = HandshakeMessage::new(HandshakeType::KeyUpdate,
                                                body.clone()).unwrap();
            assert!(connection.dispatch_handshake(&message).is_err(), "{:?}", body);
        }

        // **A malformed NewSessionTicket at the same point is refused.**
        // It arrives under the application keys, so it is
        // authenticated: a peer sending one that does not parse is
        // broken, and a message that cannot be decoded aborts like any
        // other. Sixteen zero bytes says the ticket itself is empty,
        // which `opaque ticket<1..2^16-1>` forbids.
        let ticket = HandshakeMessage::new(HandshakeType::NewSessionTicket,
                                           vec![0; 16]).unwrap();
        assert!(connection.dispatch_handshake(&ticket).is_err());

        // A **well formed** one that cannot be used is dropped instead,
        // which is the other half of the rule: a zero lifetime means
        // discard it, and a working connection is not torn down over an
        // offer nobody has to accept.
        let body = hs13::NewSessionTicket13 {
            lifetime: 0, age_add: 1, nonce: vec![0],
            ticket: vec![1, 2, 3, 4], max_early_data: None,
        }.encode().unwrap();
        let ticket = HandshakeMessage::new(HandshakeType::NewSessionTicket,
                                           body).unwrap();
        assert!(connection.dispatch_handshake(&ticket).is_ok());
        assert!(connection.tickets().is_empty());
    }

    /// The states of the two handshakes must not accept each other's
    /// messages. That is the whole design of this machine, and TLS 1.3
    /// added four states to it.
    #[test]
    fn test_the_two_state_machines_do_not_accept_each_others_messages() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();

        for (state, message_type) in [
            // A 1.2 Certificate where a 1.3 one belongs, and the reverse.
            (State::WaitCertificate13, HandshakeType::ServerKeyExchange),
            (State::WaitCertificate13, HandshakeType::ServerHelloDone),
            (State::WaitServerFlight, HandshakeType::EncryptedExtensions),
            (State::WaitServerFlight, HandshakeType::CertificateVerify),
            // And the 1.3 flight in the wrong order: a server skipping the
            // CertificateVerify is an unauthenticated handshake.
            (State::WaitCertificateVerify, HandshakeType::Finished),
            (State::WaitEncryptedExtensions, HandshakeType::Certificate),
        ] {
            connection.state = state;
            let message = HandshakeMessage::new(message_type, vec![0; 8]).unwrap();
            let error = connection.dispatch_handshake(&message).unwrap_err();
            assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE),
                       "{:?} accepted {} ", state, message_type.name());
        }
    }

    /// A TLS 1.3 hello says 1.2 in its version field, and offers 1.3 in
    /// `supported_versions`. Getting that backwards means middleboxes drop
    /// the connection, which looks like a network problem.
    #[test]
    fn test_a_tls13_hello_claims_12_and_offers_13_in_the_extension() {
        let mut config = config();
        config.max_version = Version::TLS13;
        let mut connection = ClientConnection::new(config, "example.test").unwrap();

        let bytes = connection.take_outgoing();
        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes);
        let record = reader.read().unwrap().unwrap();
        let mut handshake = HandshakeReader::new();
        handshake.push(&record.payload);
        let message = handshake.next_message().unwrap().unwrap();
        let hello = ClientHello::parse(&message.body).unwrap();

        assert_eq!(hello.legacy_version, Version::TLS12,
                   "the hello's own version field must never say 1.3");

        let offered = find_extension(&hello.extensions, extension::SUPPORTED_VERSIONS)
            .expect("a TLS 1.3 hello carries supported_versions");
        let versions = hs13::parse_client_supported_versions(&offered.body).unwrap();
        assert_eq!(versions, vec![Version::TLS13, Version::TLS12]);

        // And a key share for each group we generated one for.
        let shares = find_extension(&hello.extensions, extension::KEY_SHARE)
            .expect("a TLS 1.3 hello carries key_share");
        let entries = hs13::parse_client_key_share(&shares.body).unwrap();
        assert_eq!(entries.iter().map(|e| e.group).collect::<Vec<_>>(),
                   [TLS13_HYBRID_SHARES, TLS13_KEY_SHARE_GROUPS].concat());
        // X25519MLKEM768's share is the ML-KEM-768 key then X25519's.
        assert_eq!(entries[0].group, groups::X25519_MLKEM768);
        assert_eq!(entries[0].key_exchange.len(), 1184 + 32);

        // And the hybrids lead supported_groups.
        let supported = find_extension(&hello.extensions,
                                       extension::SUPPORTED_GROUPS).unwrap();
        let mut reader = crate::tls::codec::Reader::new(&supported.body);
        let listed = reader.u16_list().unwrap();
        assert_eq!(&listed[..3], groups::HYBRID);

        // The signature_algorithms list is the 1.3 one, with PSS in it.
        let signatures = find_extension(&hello.extensions,
                                        extension::SIGNATURE_ALGORITHMS).unwrap();
        let schemes = hs13::parse_signature_algorithms(&signatures.body).unwrap();
        assert!(schemes.contains(&scheme::RSA_PSS_RSAE_SHA256),
                "a TLS 1.3 server requires rsa_pss_rsae_sha256 to be offered");
    }

    /// The RSA premaster's version bytes are the ClientHello's
    /// `legacy_version` field, not the highest version offered.
    ///
    /// Those were the same thing until TLS 1.3 pinned the field at 0x0303
    /// and moved the real offer into `supported_versions`. Raising the
    /// default ceiling to 1.3 put 0x0304 in the premaster, and every RSA
    /// key exchange against a TLS 1.2 server failed with the server
    /// sending `bad_record_mac` - RFC 5246 section 7.4.7.1 compares the
    /// premaster's first two bytes against the field as a rollback
    /// countermeasure, and deliberately does not say that is what failed.
    ///
    /// Sixteen end-to-end tests caught it and not one unit test did,
    /// because every unit test built a connection whose ceiling was 1.2.
    #[test]
    fn test_the_premaster_version_is_the_hello_field_not_the_ceiling() {
        for ceiling in [Version::SSL30, Version::TLS10, Version::TLS11,
                        Version::TLS12, Version::TLS13] {
            let mut config = config();
            config.min_version = core::cmp::min(config.min_version, ceiling);
            config.max_version = ceiling;
            let connection = ClientConnection::new(config, "example.test").unwrap();

            assert!(connection.offered_version <= Version::TLS12,
                    "ceiling {} put {} in the premaster",
                    ceiling.name(), connection.offered_version.name());
            assert_eq!(connection.offered_version,
                       connection.legacy_hello_version(),
                       "the premaster must carry the hello's own version field");
        }
    }

    /// A TLS 1.2 hello must not carry any of that.
    #[test]
    fn test_a_tls12_hello_carries_no_13_extensions() {
        let mut config = config();
        config.max_version = Version::TLS12;
        let mut connection = ClientConnection::new(config, "example.test").unwrap();

        let bytes = connection.take_outgoing();
        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes);
        let record = reader.read().unwrap().unwrap();
        let mut handshake = HandshakeReader::new();
        handshake.push(&record.payload);
        let message = handshake.next_message().unwrap().unwrap();
        let hello = ClientHello::parse(&message.body).unwrap();

        assert!(find_extension(&hello.extensions, extension::SUPPORTED_VERSIONS)
                .is_none());
        assert!(find_extension(&hello.extensions, extension::KEY_SHARE).is_none());

        // Nor any hybrid group: they are 1.3 only, and a 1.2 hello naming
        // them would be naming groups it cannot use.
        let supported = find_extension(&hello.extensions,
                                       extension::SUPPORTED_GROUPS).unwrap();
        let mut reader = crate::tls::codec::Reader::new(&supported.body);
        let listed = reader.u16_list().unwrap();
        assert!(!listed.iter().any(|g| groups::HYBRID.contains(g)), "{listed:?}");
        assert_eq!(&listed[..OFFERED_GROUPS.len()], OFFERED_GROUPS,
                   "the classical groups lead when there are no hybrids");
    }

    #[test]
    fn test_a_new_connection_writes_a_client_hello() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        assert_eq!(connection.state(), State::WaitServerHello);
        assert!(connection.is_handshaking());
        assert!(connection.wants_write());

        let bytes = connection.take_outgoing();
        assert!(!connection.wants_write());

        // One handshake record holding a ClientHello.
        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes);
        let record = reader.read().unwrap().unwrap();
        assert_eq!(record.content_type, ContentType::Handshake);
        // The record version is conservative even though we offer 1.2.
        assert_eq!(record.version, Version::TLS10);

        let mut handshake = HandshakeReader::new();
        handshake.push(&record.payload);
        let message = handshake.next_message().unwrap().unwrap();
        assert_eq!(message.message_type, HandshakeType::ClientHello);

        let hello = ClientHello::parse(&message.body).unwrap();
        assert_eq!(hello.legacy_version, Version::TLS12);
        assert_eq!(hello.server_name().as_deref(), Some("example.test"));
        assert!(hello.cipher_suites.contains(&suites::RENEGOTIATION_SCSV));
        assert!(find_extension(&hello.extensions,
                               extension::ENCRYPT_THEN_MAC).is_some());
        assert!(find_extension(&hello.extensions,
                               extension::EXTENDED_MASTER_SECRET).is_some());
    }

    #[test]
    fn test_a_connection_needs_roots_or_a_decision() {
        let empty = ClientConfig::new(TrustStore::new(), 1_700_000_000);
        let error = match ClientConnection::new(empty, "example.test") {
            Err(error) => error,
            Ok(_) => panic!("a connection with no roots was allowed"),
        };
        assert!(error.detail.contains("no trusted roots"), "{}", error.detail);

        // Turning verification off is allowed, and is a decision.
        let mut without = ClientConfig::new(TrustStore::new(), 1_700_000_000);
        without.verify_certificate = false;
        let connection = ClientConnection::new(without, "example.test").unwrap();
        assert!(!connection.certificate_verified());
    }

    #[test]
    fn test_a_hostname_is_required_while_the_name_is_checked() {
        assert!(ClientConnection::new(config(), "").is_err());
    }

    /// **With `verify_hostname` off, no hostname is allowed and no SNI
    /// is sent.**
    ///
    /// Two real cases: a literal IP address, which RFC 6066 3 forbids
    /// putting in SNI, and a peer whose certificate is not being judged
    /// at all - which is `check_hostname = False` with `CERT_NONE` in
    /// Python's `ssl`, and worked there while failing here. Requiring a
    /// name when nothing checks it only forces the caller to invent one.
    ///
    /// The extension must be **absent**, not present and empty: RFC 6066
    /// defines the body as a non-empty list, and the empty form gets an
    /// alert from some servers and the default certificate from others.
    #[test]
    fn test_no_hostname_sends_no_server_name_extension() {
        let mut settings = config();
        settings.verify_hostname = false;
        let mut connection = ClientConnection::new(settings, "")
            .expect("a nameless connection is allowed when nothing checks the name");

        let hello = connection.take_outgoing();
        assert!(!hello.is_empty());

        // Find the ClientHello's extensions by parsing the record and
        // handshake headers, rather than scanning for bytes: a code that
        // happens to appear inside a random or a key share would make a
        // byte scan lie in either direction.
        let parsed = parse_client_hello(&hello);
        assert!(parsed.iter().all(|(kind, _)| *kind != extension::SERVER_NAME),
                "a server_name extension was sent with no hostname");
        // And the rest of the hello is intact - this is not "no
        // extensions at all".
        assert!(parsed.iter().any(|(kind, _)| *kind == extension::SIGNATURE_ALGORITHMS),
                "the other extensions went missing too");

        // With a name it comes back, carrying that name.
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        let hello = connection.take_outgoing();
        let parsed = parse_client_hello(&hello);
        let body = parsed.iter()
            .find(|(kind, _)| *kind == extension::SERVER_NAME)
            .map(|(_, body)| body.clone())
            .expect("a named connection must send server_name");
        assert!(body.windows(12).any(|w| w == b"example.test"),
                "the server_name extension does not carry the name");
    }

    /// The extensions of a ClientHello sitting in one handshake record,
    /// as `(kind, body)`.
    #[cfg(test)]
    fn parse_client_hello(record: &[u8]) -> Vec<(u16, Vec<u8>)> {
        // record: type(1) version(2) length(2) | handshake: type(1) length(3)
        let body = &record[5..];
        assert_eq!(body[0], 1, "not a ClientHello");
        let mut at = 4usize;                    // past the handshake header
        at += 2;                                // legacy_version
        at += 32;                               // random
        at += 1 + body[at] as usize;            // legacy_session_id
        let suites = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        at += 2 + suites;
        at += 1 + body[at] as usize;            // compression methods
        let total = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        at += 2;
        let end = at + total;

        let mut out = Vec::new();
        while at + 4 <= end {
            let kind = u16::from_be_bytes([body[at], body[at + 1]]);
            let length = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            out.push((kind, body[at + 4..at + 4 + length].to_vec()));
            at += 4 + length;
        }
        out
    }

    /// The state machine must reject by default. Every message that does
    /// not belong in the current state is unexpected_message, and the
    /// connection fails rather than carrying on.
    #[test]
    fn test_messages_out_of_order_are_refused() {
        for message_type in [HandshakeType::Certificate,
                             HandshakeType::ServerHelloDone,
                             HandshakeType::Finished,
                             HandshakeType::ServerKeyExchange,
                             HandshakeType::ClientHello] {
            let mut connection = ClientConnection::new(config(), "example.test").unwrap();
            connection.take_outgoing();

            let message = HandshakeMessage::new(message_type, vec![0u8; 8]).unwrap();
            let mut writer = RecordWriter::new(Version::TLS12);
            let bytes = writer.write(ContentType::Handshake, &message.raw).unwrap();

            connection.push_incoming(&bytes);
            let error = connection.process().unwrap_err();
            assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE),
                       "{} was not refused", message_type.name());
            assert_eq!(connection.state(), State::Failed);
        }
    }

    /// And a ChangeCipherSpec before the handshake reaches that point.
    #[test]
    fn test_an_early_change_cipher_spec_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();

        let mut writer = RecordWriter::new(Version::TLS12);
        let bytes = writer.write(ContentType::ChangeCipherSpec, &[1]).unwrap();
        connection.push_incoming(&bytes);

        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE));
    }

    /// Application data before the handshake finishes is a peer skipping
    /// the authentication.
    #[test]
    fn test_early_application_data_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();

        let mut writer = RecordWriter::new(Version::TLS12);
        let bytes = writer.write(ContentType::ApplicationData, b"surprise").unwrap();
        connection.push_incoming(&bytes);

        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE));
    }

    fn server_hello_bytes(suite: u16, version: Version,
                          extensions: Vec<Extension>) -> Vec<u8> {
        let hello = ServerHello {
            legacy_version: version,
            random: [3u8; 32],
            session_id: vec![],
            cipher_suite: suite,
            compression_method: 0,
            extensions,
        };
        let message = HandshakeMessage::new(HandshakeType::ServerHello,
                                            hello.encode().unwrap()).unwrap();
        let mut writer = RecordWriter::new(version);
        writer.write(ContentType::Handshake, &message.raw).unwrap()
    }

    /// The same as `up_to_server_key_exchange`, for a chosen suite, so a
    /// test can put a ServerKeyExchange in front of a suite that should
    /// not have one.
    fn up_to_certificate(suite: u16) -> ClientConnection {
        let mut config = config();
        config.verify_certificate = false;
        config.suites = Selection::legacy();
        config.min_version = Version::TLS10;
        let mut connection = ClientConnection::new(config, "example.test").unwrap();
        connection.take_outgoing();
        connection.push_incoming(&server_hello_bytes(suite, Version::TLS12, vec![]));
        connection.process().unwrap();

        let leaf = crate::x509::tests_support::leaf(|b| {
            b.common_name = "example.test".to_string();
            b.dns_names = vec!["example.test".to_string()];
        });
        let mut body = Writer::new();
        let mut list = Writer::new();
        list.vector24(&leaf).unwrap();
        body.vector24(&list.finish()).unwrap();
        let message = HandshakeMessage::new(HandshakeType::Certificate,
                                            body.finish()).unwrap();
        let mut writer = RecordWriter::new(Version::TLS12);
        let bytes = writer.write(ContentType::Handshake, &message.raw).unwrap();
        connection.push_incoming(&bytes);
        connection.process().expect("the certificate step");
        connection
    }

    fn export_rsa_key_exchange_bytes() -> Vec<u8> {
        export_rsa_key_exchange_with_modulus_bits(512)
    }

    /// An export RSA ServerKeyExchange with a temporary modulus of the
    /// given size. The signature is nonsense, which is fine for every test
    /// that uses it: each one is about a check that happens before or
    /// instead of the signature, and the ones about the signature itself
    /// live with the other key exchanges.
    fn export_rsa_key_exchange_with_modulus_bits(bits: usize) -> Vec<u8> {
        let modulus: Vec<u8> = (0..bits / 8).map(|i| (i as u8) | 0x80).collect();
        let mut body = Writer::new();
        body.vector16(&modulus).unwrap();
        body.vector16(&[0x01, 0x00, 0x01]).unwrap();
        body.u16(0x0401);                                  // rsa_pkcs1_sha256
        body.vector16(&[0xff; 64]).unwrap();
        let message = HandshakeMessage::new(HandshakeType::ServerKeyExchange,
                                            body.finish()).unwrap();
        let mut writer = RecordWriter::new(Version::TLS12);
        writer.write(ContentType::Handshake, &message.raw).unwrap()
    }

    // ----------------------------------------------------------- export ---

    /// A plain RSA suite has no ServerKeyExchange, and accepting one is
    /// FREAK.
    ///
    /// The attack is not subtle once stated: a man in the middle rewrites
    /// the ClientHello to ask for an export suite, the server answers with
    /// a 512 bit temporary key, and a client that accepts that message for
    /// the suite it *thinks* it negotiated encrypts the premaster under a
    /// key the attacker can factor. Nothing in the message says it is
    /// wrong - it is a perfectly well-formed message for a different
    /// suite.
    ///
    /// So the decision comes from the negotiated suite and never from the
    /// message having arrived.
    #[test]
    fn test_a_server_key_exchange_for_a_plain_rsa_suite_is_refused() {
        let mut connection = up_to_certificate(0x002f);   // RSA_WITH_AES_128_CBC_SHA
        connection.push_incoming(&export_rsa_key_exchange_bytes());
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE));
        assert!(error.detail.contains("FREAK"), "{}", error.detail);
    }

    /// And the same message for an *export* suite is expected, so it is
    /// the negotiated suite doing the work rather than a blanket refusal
    /// of a message type.
    ///
    /// The test certificate carries an EC key, so this one cannot reach a
    /// verifying signature - and that is the right place for it to stop:
    /// past the "this suite has no such message" refusal, into the
    /// signature check that every ephemeral key exchange shares. The
    /// distinction being tested is exactly which of those two it hits.
    #[test]
    fn test_an_export_suite_expects_its_temporary_key() {
        let mut connection = up_to_certificate(0x0003);   // RSA_EXPORT_WITH_RC4_40_MD5
        connection.push_incoming(&export_rsa_key_exchange_bytes());
        let error = connection.process().unwrap_err();

        assert_ne!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE),
                   "an export suite refused its own ServerKeyExchange");
        assert!(!error.detail.contains("FREAK"), "{}", error.detail);
        assert!(error.detail.contains("certificate carries an EC key"),
                "the message got past the suite check but stopped somewhere \
                 unexpected: {}", error.detail);
    }

    /// A temporary key that is not small is not an export key.
    #[test]
    fn test_an_oversized_temporary_key_is_refused() {
        let mut connection = up_to_certificate(0x0003);
        connection.push_incoming(&export_rsa_key_exchange_with_modulus_bits(2048));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("bits"), "{}", error.detail);
    }

    /// The export key expansion, which no key block produces directly.
    ///
    /// Five bytes of key material become sixteen, and the IVs come from a
    /// separate PRF pass with an **empty secret** rather than from the key
    /// block at all. Both are things that would work perfectly if both
    /// ends got them wrong the same way, which is why they are pinned here
    /// and in `tools/src/bin/diff_ssl3_keys.rs` against the RFC.
    #[test]
    fn test_the_export_key_expansion() {
        let master = vec![0x0bu8; 48];
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];

        for (name, expanded, iv_len) in [
            ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", 16usize, 0usize),
            ("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 16, 8),
            ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 8, 8),
        ] {
            let suite = suites::by_name(name).unwrap();
            assert!(suite.cipher.is_exportable(), "{} is not marked exportable", name);
            assert_eq!(suite.cipher.key_len(), 5, "{}: key material is 5 bytes", name);
            assert_eq!(suite.cipher.expanded_key_len(), expanded, "{}", name);

            let block = keys::key_block(Version::TLS10, suite, &master,
                                        &client_random, &server_random).unwrap();
            assert_eq!(block.client.key.len(), expanded,
                       "{}: the key was not expanded", name);
            assert_eq!(block.client.iv.len(), iv_len, "{}", name);
            assert_ne!(block.client.key, block.server.key,
                       "{}: both directions got the same key", name);

            // The expansion is not the identity: the five bytes that went
            // in are not a prefix of the sixteen that came out.
            let unexpanded = keys::key_block(Version::TLS10,
                suites::by_name("TLS_RSA_WITH_AES_128_CBC_SHA").unwrap(),
                &master, &client_random, &server_random).unwrap();
            assert_ne!(block.client.key[..5], unexpanded.client.key[..5],
                       "{}: the expansion looks like a copy", name);
        }
    }

    /// SSLv3's export expansion is a different construction from TLS's,
    /// and swaps the two randoms for the server direction.
    #[test]
    fn test_the_ssl3_export_expansion_differs() {
        let suite = suites::by_name("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5").unwrap();
        let master = vec![0x0bu8; 48];
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];

        let ssl3 = keys::key_block(Version::SSL30, suite, &master,
                                   &client_random, &server_random).unwrap();
        let tls10 = keys::key_block(Version::TLS10, suite, &master,
                                    &client_random, &server_random).unwrap();
        assert_eq!(ssl3.client.key.len(), 16);
        assert_ne!(ssl3.client.key, tls10.client.key);

        // The randoms are swapped for the server side in SSLv3 but not in
        // TLS, so the two directions differ in both - and differently.
        assert_ne!(ssl3.client.key, ssl3.server.key);
        assert_ne!(ssl3.client.iv, ssl3.server.iv);
    }

    /// RC2_CBC_40 is a 16 byte key with 40 effective bits. Keying RC2 with
    /// those 16 bytes unweakened is a different cipher that round-trips
    /// perfectly against itself.
    #[test]
    fn test_rc2_carries_its_effective_key_length() {
        let suite = suites::by_name("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5").unwrap();
        assert_eq!(suite.cipher.rc2_effective_bits(), Some(40));
        assert_eq!(suites::by_name("TLS_RSA_WITH_AES_128_CBC_SHA").unwrap()
                       .cipher.rc2_effective_bits(), None);

        let key = vec![0x5au8; 16];
        let weakened = crate::api::AnyBlockCipher::new("rc2", &key, Some("40")).unwrap();
        let full = crate::api::AnyBlockCipher::new("rc2", &key, None).unwrap();
        let mut weakened = weakened;
        let mut full = full;
        let mut a = Vec::new();
        let mut b = Vec::new();
        use crate::block_ciphers::BlockCipher;
        weakened.block_encrypt(&[0u8; 8], &mut a);
        full.block_encrypt(&[0u8; 8], &mut b);
        assert_ne!(a, b, "the effective key length was ignored");
    }

    // ------------------------------------------------------------ SSLv3 ---
    //
    // No end-to-end test exists for these, and the reason is worth stating
    // rather than leaving to be discovered: this machine's OpenSSL is
    // built without SSLv3 (`ssl.HAS_SSLv3` is False), so there is no
    // server anywhere here to hand a ClientHello to. What *is* pinned
    // externally is every construction SSLv3 does differently - the key
    // expansion, the record MAC and Finished - by
    // `tools/src/bin/diff_ssl3_keys.rs` and `tools/src/bin/diff_tls_record.rs`
    // against references written from RFC 6101 in Python. These tests
    // cover the decisions the client makes around them.

    fn ssl3_config() -> ClientConfig {
        let mut config = config();
        config.verify_certificate = false;
        config.suites = Selection::legacy();
        config.min_version = Version::SSL30;
        config.max_version = Version::SSL30;
        config
    }

    /// An SSLv3 ClientHello carries no extensions at all.
    ///
    /// Extensions arrived with RFC 3546, two years after SSLv3, and a
    /// server old enough to speak nothing else is old enough to drop a
    /// hello that has them - which looks like a network failure rather
    /// than a protocol one. This is the single most likely reason an
    /// SSLv3 client fails to connect while looking correct.
    #[test]
    fn test_an_ssl3_hello_has_no_extensions() {
        let mut connection = ClientConnection::new(ssl3_config(), "example.test")
            .unwrap();
        let bytes = connection.take_outgoing();

        // Dig the ClientHello back out of the record and parse it.
        let body = &bytes[5 + 4..];
        let hello = ClientHello::parse(body).unwrap();
        assert!(hello.extensions.is_empty(),
                "an SSLv3 hello carried {} extensions", hello.extensions.len());
        assert_eq!(hello.legacy_version, Version::SSL30);

        // And the contrast: at TLS 1.2 the same client sends several.
        let mut modern = ClientConnection::new(config(), "example.test").unwrap();
        let bytes = modern.take_outgoing();
        let hello = ClientHello::parse(&bytes[5 + 4..]).unwrap();
        assert!(hello.extensions.len() >= 4,
                "the TLS hello should still carry its extensions");
    }

    /// SSLv3's Finished is 36 bytes - an MD5 and a SHA-1 - not the 12 a
    /// PRF produces. A client that sent 12 would be refused by every
    /// server, and one that accepted 12 would accept a forgery.
    #[test]
    fn test_the_ssl3_finished_is_thirty_six_bytes() {
        let mut transcript =
            Transcript::new(Version::SSL30, suites::MacAlgorithm::Sha256).unwrap();
        transcript.update(b"some handshake messages");
        let master = vec![0x0bu8; 48];

        let client = transcript.ssl3_finished(&master, Side::Client).unwrap();
        let server = transcript.ssl3_finished(&master, Side::Server).unwrap();
        assert_eq!(client.len(), 36);
        assert_eq!(server.len(), 36);

        // The sender constant has to reach the hash. If it did not, each
        // side would still verify the other's - which is exactly the kind
        // of agreement that proves nothing.
        assert_ne!(client, server);

        // And it depends on the transcript, which is the whole point.
        let mut other =
            Transcript::new(Version::SSL30, suites::MacAlgorithm::Sha256).unwrap();
        other.update(b"different handshake messages");
        assert_ne!(other.ssl3_finished(&master, Side::Client).unwrap(), client);
    }

    /// The default must not reach SSLv3, and asking for it must work.
    ///
    /// POODLE is not a weakness in a suite, it is a weakness in the
    /// version: SSLv3's CBC padding bytes are unspecified, so a receiver
    /// may not check them, so an attacker learns a byte at a time. The
    /// only fix is not to speak it - which is a decision the caller makes
    /// here, not one this library makes for them by deleting the code.
    #[test]
    fn test_ssl3_is_not_reachable_by_default() {
        let default = config();
        assert!(default.min_version > Version::SSL30,
                "the default floor reaches SSLv3");

        let legacy = ClientConfig::legacy(TrustStore::new(), 1_700_000_000);
        assert!(legacy.min_version > Version::SSL30,
                "even the legacy configuration must not reach SSLv3 by \
                 default; POODLE is a property of the version");

        // And asking for it explicitly works.
        let mut connection = ClientConnection::new(ssl3_config(), "example.test")
            .unwrap();
        assert!(!connection.take_outgoing().is_empty());
    }

    /// A server that answers an SSLv3 hello with a TLS version is picking
    /// something we did not offer.
    #[test]
    fn test_an_ssl3_client_refuses_a_higher_version() {
        let mut connection = ClientConnection::new(ssl3_config(), "example.test")
            .unwrap();
        connection.take_outgoing();
        connection.push_incoming(&server_hello_bytes(0x002f, Version::TLS12, vec![]));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::PROTOCOL_VERSION));
    }

    /// A server that picks a suite is answered with the SSLv3 key
    /// schedule, not the TLS 1.0 one. The two produce different bytes
    /// from the same inputs, and nothing later would say which was used.
    #[test]
    fn test_the_ssl3_key_schedule_differs_from_tls10() {
        let suite = suites::by_name("TLS_RSA_WITH_AES_128_CBC_SHA").unwrap();
        let premaster = vec![0x03u8; 48];
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];

        let ssl3 = keys::master_secret(Version::SSL30, suite.prf, &premaster,
                                       &client_random, &server_random).unwrap();
        let tls10 = keys::master_secret(Version::TLS10, suite.prf, &premaster,
                                        &client_random, &server_random).unwrap();
        assert_eq!(ssl3.len(), 48);
        assert_ne!(ssl3, tls10, "SSLv3 and TLS 1.0 derived the same master \
                                 secret, so one of them is using the other's \
                                 construction");

        let ssl3_block = keys::key_block(Version::SSL30, suite, &ssl3,
                                         &client_random, &server_random).unwrap();
        let tls10_block = keys::key_block(Version::TLS10, suite, &ssl3,
                                          &client_random, &server_random).unwrap();
        assert_ne!(ssl3_block.client.key, tls10_block.client.key);
        // The shapes still match: SSLv3 chains its IV like TLS 1.0 does.
        assert_eq!(ssl3_block.client.iv.len(), 16);
        assert_eq!(ssl3_block.client.mac_key.len(), 20);
    }

    /// A server that picks a suite the client did not offer is either
    /// broken or attacking. Accepting it is how a downgrade happens
    /// silently.
    #[test]
    fn test_a_suite_we_did_not_offer_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();

        // RC4-SHA, which the modern selection does not offer.
        connection.push_incoming(&server_hello_bytes(0x0005, Version::TLS12, vec![]));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("did not offer"), "{}", error.detail);
        // **And that it is the server's rule being broken.** A live
        // GOST server answers a one-suite hello with a suite nobody
        // offered, and the old message left a reader to guess whether
        // this library was missing something. It is not.
        assert!(error.detail.contains("7.4.1.3"), "{}", error.detail);
    }

    /// The shape a live server actually produced: **one suite offered,
    /// a completely different one chosen.**
    ///
    /// `tlsgost-256.cryptopro.ru` answers a hello offering only
    /// `TLS_GOSTR341001_WITH_28147_CNT_IMIT` with suite `0x0031`, then
    /// sends its GOST **2012** certificate - byte for byte the one it
    /// serves for 0xC102, so it has no 2001 certificate and cannot
    /// satisfy the request. Instead of `handshake_failure` it invents a
    /// suite.
    ///
    /// The refusal is right and stays. What this pins is that the
    /// message **names the suites that were offered**, because with one
    /// suite in the hello that is the entire diagnosis, and without it
    /// the reader has no way to tell a broken server from a gap here.
    #[test]
    fn test_the_message_names_what_was_offered() {
        let mut config = config();
        config.suites = crate::tls::suites::Selection::named(
            &["TLS_GOSTR341001_WITH_28147_CNT_IMIT"]).unwrap();
        let mut connection = ClientConnection::new(config, "example.test").unwrap();
        connection.take_outgoing();

        // At 1.2 rather than the 1.0 the live probe used: this
        // config's floor is 1.2, and the version check runs first - so
        // a 1.0 hello here would be refused for its version and the
        // suite would never be looked at. The suite rule is the same
        // at every version.
        connection.push_incoming(&server_hello_bytes(0x0031, Version::TLS12, vec![]));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("TLS_GOSTR341001_WITH_28147_CNT_IMIT"),
                "the offered suite is not named: {}", error.detail);
        assert!(error.detail.contains("0x0031"), "{}", error.detail);
    }

    /// The same server, answering a hello that offered **only TLS 1.3
    /// suites**, with a TLS 1.2 ServerHello.
    ///
    /// This is the case the message got wrong, and it came back from a
    /// real run: `check_live.py --gost` sends one suite per connection
    /// now, so four of its rows offer nothing but the RFC 9367 MGM
    /// suites - which are TLS 1.3 only. CryptoPro answers TLS 1.2 with
    /// `0x0031`, and the diagnosis printed
    ///
    ///     which this client did not offer - it offered .
    ///
    /// because `for_version(TLS12)` filters every offered suite out and
    /// `ours.len() <= 4` is true of an empty list, so `join` produced
    /// nothing. A reader is told the client offered *something*, shown
    /// an empty list, and left worse off than with no list at all.
    ///
    /// **And the empty list is the diagnosis.** It is not a formatting
    /// slip to paper over: every suite this hello offered needs a newer
    /// version than the server chose, which is a different conversation
    /// from "we offered these three and it picked a fourth". The message
    /// has to say which.
    #[test]
    fn test_the_message_when_every_offered_suite_needs_a_newer_version() {
        let mut config = config();
        config.suites = crate::tls::suites::Selection::named(
            &["TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
              "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"]).unwrap();
        config.min_version = Version::TLS12;
        config.max_version = Version::TLS13;
        let mut connection = ClientConnection::new(config, "example.test").unwrap();
        connection.take_outgoing();

        connection.push_incoming(&server_hello_bytes(0x0031, Version::TLS12, vec![]));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));

        // Never the empty list that started this.
        assert!(!error.detail.contains("it offered ."),
                "the empty list is back: {}", error.detail);
        // It says the suites needed a newer version, and names one so the
        // reader can see which family it was.
        assert!(error.detail.contains("TLSv1.3"),
                "the version requirement is not named: {}", error.detail);
        assert!(error.detail.contains("MGM_L"),
                "no offered suite is named: {}", error.detail);
        assert!(error.detail.contains("0x0031"), "{}", error.detail);

        // **No run of spaces, which is how this message was wrong the
        // first time it was fixed.** A Rust string literal split across
        // lines keeps the newline *and* the indentation unless each line
        // ends with a backslash, so a long message assembled without them
        // reaches the user with twenty-five spaces in the middle of a
        // sentence. Nothing else would have noticed: every assertion
        // above is a `contains`, and the substrings they look for do not
        // straddle the join.
        assert!(!error.detail.contains("  "),
                "a run of spaces in the message: {:?}", error.detail);
        assert!(!error.detail.contains('\n'),
                "a newline in the message: {:?}", error.detail);
    }

    /// Feed a connection a ServerHello for an ECDHE suite and a
    /// certificate, so that the next message it expects is a
    /// ServerKeyExchange.
    ///
    /// Verification is off in the config these use: the point is the group
    /// check, and a connection that dies on an untrusted certificate never
    /// reaches it.
    fn up_to_server_key_exchange() -> ClientConnection {
        let mut config = config();
        config.verify_certificate = false;
        let mut connection = ClientConnection::new(config, "example.test").unwrap();
        connection.take_outgoing();
        connection.push_incoming(&server_hello_bytes(0xc013, Version::TLS12,
                                                     vec![]));
        connection.process().unwrap();

        let leaf = crate::x509::tests_support::leaf(|b| {
            b.common_name = "example.test".to_string();
            b.dns_names = vec!["example.test".to_string()];
        });
        let mut body = Writer::new();
        let mut list = Writer::new();
        list.vector24(&leaf).unwrap();
        body.vector24(&list.finish()).unwrap();
        let message = HandshakeMessage::new(HandshakeType::Certificate,
                                            body.finish()).unwrap();
        let mut writer = RecordWriter::new(Version::TLS12);
        let bytes = writer.write(ContentType::Handshake, &message.raw).unwrap();
        connection.push_incoming(&bytes);
        connection.process().expect("the certificate step");
        assert_eq!(connection.state, State::WaitServerFlight);
        connection
    }

    fn server_key_exchange_bytes(group: u16) -> Vec<u8> {
        let mut body = vec![3];
        body.extend_from_slice(&group.to_be_bytes());
        body.push(65);
        body.push(0x04);
        body.extend_from_slice(&[0x11; 64]);
        body.extend_from_slice(&[0x04, 0x01]);      // rsa_pkcs1_sha256
        body.extend_from_slice(&[0x00, 0x02, 0xff, 0xff]);
        let message = HandshakeMessage::new(HandshakeType::ServerKeyExchange,
                                            body).unwrap();
        let mut writer = RecordWriter::new(Version::TLS12);
        writer.write(ContentType::Handshake, &message.raw).unwrap()
    }

    /// A second ServerKeyExchange in one flight is refused.
    ///
    /// What was wrong: the state did not move after a ServerKeyExchange,
    /// so a second one was parsed and its parameters replaced the
    /// first's. The sibling messages (CertificateRequest,
    /// CertificateStatus) each refuse a second copy and this one did
    /// not. No real server sends two, so the first is stood in for by
    /// the parameters it would have left behind, and the second is a
    /// message that would otherwise be refused for its *group* - the
    /// alert tells the two refusals apart.
    #[test]
    fn test_a_second_server_key_exchange_is_refused() {
        let mut connection = up_to_server_key_exchange();
        connection.server_ecdh = Some(crate::tls::handshake::ServerEcdhParams {
            group: groups::SECP256R1,
            point: vec![4; 65],
            raw_params: Vec::new(),
            scheme: None,
            signature: Vec::new(),
        });
        connection.push_incoming(&server_key_exchange_bytes(groups::SECP256K1));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::UNEXPECTED_MESSAGE),
                   "{}", error.detail);
        assert!(error.detail.contains("second ServerKeyExchange"), "{}", error.detail);
    }

    /// A server that picks a curve the client did not offer is choosing the
    /// group the shared secret lives in. That it is a real, named curve
    /// makes no difference - secp256k1 here is a perfectly good curve, and
    /// still not one this client said it would use.
    ///
    /// This is checked before the signature, because reaching the signature
    /// means having already decided to do arithmetic in the server's group.
    #[test]
    fn test_a_curve_we_did_not_offer_is_refused() {
        let mut connection = up_to_server_key_exchange();
        connection.push_incoming(&server_key_exchange_bytes(groups::SECP256K1));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("did not offer"), "{}", error.detail);
    }

    /// And a group we have no implementation for at all is refused by
    /// name rather than by falling through to something we do have.
    ///
    /// The reason given is "did not offer" rather than "not implemented",
    /// and that is the accurate one: we only ever offer groups we
    /// implement, so a group we cannot do is necessarily one we did not
    /// ask for. The two checks used to be the other way round, and this
    /// test used X25519 as its example of something unimplemented - which
    /// stopped being true the day it was implemented.
    #[test]
    fn test_an_unimplemented_group_is_refused() {
        let mut connection = up_to_server_key_exchange();
        connection.push_incoming(&server_key_exchange_bytes(groups::X448));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("x448"), "{}", error.detail);
    }

    /// A hybrid post-quantum group in a TLS 1.2 ServerKeyExchange is
    /// refused for what it is - RFC 10024 defines them for 1.3 only - even
    /// though the same client names them in a 1.3-capable hello.
    #[test]
    fn test_a_hybrid_group_at_tls12_is_refused() {
        for group in groups::HYBRID {
            let mut connection = up_to_server_key_exchange();
            connection.push_incoming(&server_key_exchange_bytes(*group));
            let error = connection.process().unwrap_err();
            assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
            assert!(error.detail.contains("TLS 1.3 only"), "{}", error.detail);
        }
    }

    /// X25519 goes down the same path as the other curves up to the point
    /// where it does not: the offer check and the signature are shared,
    /// and only the point handling differs. A server sending an X25519
    /// key of the wrong length must be refused there rather than in the
    /// arithmetic.
    #[test]
    fn test_an_x25519_point_of_the_wrong_length_is_refused() {
        let mut connection = up_to_server_key_exchange();
        // The helper sends a 65 byte SEC1 point, which is right for the
        // Weierstrass curves and wrong for this one.
        connection.push_incoming(&server_key_exchange_bytes(groups::X25519));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("32 bytes"), "{}", error.detail);
    }

    #[test]
    fn test_a_version_we_did_not_offer_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        connection.push_incoming(&server_hello_bytes(0x002f, Version::TLS10, vec![]));
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::PROTOCOL_VERSION));
    }

    /// A server answering with an extension the client never offered is
    /// forbidden by RFC 5246 and is a sign of something strange.
    #[test]
    fn test_an_unoffered_extension_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        connection.push_incoming(&server_hello_bytes(
            0x002f, Version::TLS12,
            vec![Extension { kind: extension::ALPN, body: vec![] }]));

        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::UNSUPPORTED_EXTENSION));
    }

    /// Compression is CRIME. There is one legal value.
    #[test]
    fn test_compression_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();

        let hello = ServerHello {
            legacy_version: Version::TLS12,
            random: [3u8; 32],
            session_id: vec![],
            cipher_suite: 0x002f,
            compression_method: 1,
            extensions: vec![],
        };
        let message = HandshakeMessage::new(HandshakeType::ServerHello,
                                            hello.encode().unwrap()).unwrap();
        let mut writer = RecordWriter::new(Version::TLS12);
        let bytes = writer.write(ContentType::Handshake, &message.raw).unwrap();

        connection.push_incoming(&bytes);
        let error = connection.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER));
        assert!(error.detail.contains("compression"), "{}", error.detail);
    }

    /// A fatal alert from the peer ends the connection, and is reported
    /// rather than swallowed.
    #[test]
    fn test_a_fatal_alert_ends_the_connection() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();

        let mut writer = RecordWriter::new(Version::TLS12);
        let alert = Alert::fatal(AlertDescription::HANDSHAKE_FAILURE);
        let bytes = writer.write(ContentType::Alert, &alert.to_bytes()).unwrap();

        connection.push_incoming(&bytes);
        let error = connection.process().unwrap_err();
        assert!(error.detail.contains("handshake_failure"), "{}", error.detail);
        assert_eq!(connection.state(), State::Failed);
        assert_eq!(connection.alert(), Some(alert));
    }

    /// An unannounced CertificateStatus is refused.
    ///
    /// **No real server sends one**, so this needs a hand-built message:
    /// the deliberate-breakage sweep found that removing the check
    /// failed nothing at all. RFC 6066 section 8 makes the message an
    /// answer to the ServerHello's acknowledgement and to nothing else,
    /// and a client that parsed one anyway is parsing bytes it never
    /// agreed to receive, in a message the transcript will only catch
    /// at the Finished.
    #[test]
    fn test_an_unannounced_certificate_status_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        connection.state = State::WaitServerFlight;
        assert!(!connection.expect_certificate_status);

        let body = crate::tls::handshake::encode_certificate_status(
            &[0x30, 0x03, 0x0a, 0x01, 0x00]).unwrap();
        let message = HandshakeMessage::new(HandshakeType::CertificateStatus,
                                            body).unwrap();
        let error = connection.dispatch_handshake(&message).unwrap_err();
        assert!(error.detail.contains("status_request"), "{}", error.detail);

        // And accepted once the ServerHello has said one is coming,
        // which is what stops the check above from being "this message
        // is never allowed".
        connection.expect_certificate_status = true;
        connection.dispatch_handshake(&message).unwrap();
        assert!(connection.stapled_ocsp().is_some());

        // Once. A second is a peer padding the flight.
        assert!(connection.dispatch_handshake(&message).is_err());
    }

    /// The certificate types are a list the client has to satisfy, and
    /// a real server lists both `rsa_sign` and `ecdsa_sign` - so the
    /// check is unreachable from any handshake test, and the
    /// deliberate-breakage sweep found that removing it failed nothing.
    ///
    /// It matters because a client that ignored the list would sign
    /// with a key the server has already said it will not take, and the
    /// failure lands at the signature rather than at the decision.
    #[test]
    fn test_a_key_of_an_unlisted_type_is_not_offered() {
        use crate::tls::handshake::client_certificate_type as kind;
        use crate::tls::handshake::CertificateRequest12;

        let mut config = config();
        let curve = crate::ec::curves::p256();
        let (private, _) = curve.generate_key_pair().unwrap();
        config.client_certificate = Some(ClientIdentity {
            chain: vec![vec![0x30, 0x00]],
            key: ClientKey::Ec { curve: "P-256", private },
        });
        let mut connection = ClientConnection::new(config, "example.test").unwrap();

        // A server that takes EC keys: our scheme is chosen.
        connection.certificate_request_12 = Some(CertificateRequest12 {
            certificate_types: vec![kind::ECDSA_SIGN],
            schemes: vec![0x0403],
            authorities: Vec::new(),
        });
        assert_eq!(connection.choose_client_scheme_12(), Some(0x0403));

        // The same server, taking RSA keys only. Nothing is offered -
        // which means an *empty* Certificate goes out, not a signature
        // with a key that was refused in advance.
        connection.certificate_request_12 = Some(CertificateRequest12 {
            certificate_types: vec![kind::RSA_SIGN],
            schemes: vec![0x0403],
            authorities: Vec::new(),
        });
        assert_eq!(connection.choose_client_scheme_12(), None);

        // And a server that takes the key type but no scheme we can
        // make - the other half of "both lists have to be satisfied".
        connection.certificate_request_12 = Some(CertificateRequest12 {
            certificate_types: vec![kind::ECDSA_SIGN],
            schemes: vec![0x0401],          // rsa_pkcs1_sha256
            authorities: Vec::new(),
        });
        assert_eq!(connection.choose_client_scheme_12(), None);
    }

    /// RFC 8422 section 3: an EdDSA client certificate answers a request
    /// for `ecdsa_sign`. Every real server lists `rsa_sign` beside it, so
    /// only a request built here shows which type the key claims.
    #[test]
    fn test_an_eddsa_key_answers_ecdsa_sign() {
        use crate::tls::handshake::client_certificate_type as kind;
        use crate::tls::handshake::CertificateRequest12;

        for (name, code) in [("ed25519", scheme::ED25519), ("ed448", scheme::ED448)] {
            let mut config = config();
            config.client_certificate = Some(ClientIdentity {
                chain: vec![vec![0x30, 0x00]],
                key: ClientKey::Eddsa { name, seed: vec![7; if name == "ed448" { 57 } else { 32 }] },
            });
            let mut connection = ClientConnection::new(config, "example.test").unwrap();
            connection.certificate_request_12 = Some(CertificateRequest12 {
                certificate_types: vec![kind::ECDSA_SIGN],
                schemes: vec![scheme::ED25519, scheme::ED448],
                authorities: Vec::new(),
            });
            assert_eq!(connection.choose_client_scheme_12(), Some(code), "{name}");
            connection.certificate_request_12 = Some(CertificateRequest12 {
                certificate_types: vec![kind::RSA_SIGN],
                schemes: vec![scheme::ED25519, scheme::ED448],
                authorities: Vec::new(),
            });
            assert_eq!(connection.choose_client_scheme_12(), None, "{name}");
        }
    }

    #[test]
    fn test_close_notify_closes_cleanly() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();

        let mut writer = RecordWriter::new(Version::TLS12);
        let bytes = writer.write(ContentType::Alert,
                                 &Alert::close_notify().to_bytes()).unwrap();
        connection.push_incoming(&bytes);
        connection.process().unwrap();

        assert_eq!(connection.state(), State::Closed);
        assert!(!connection.is_handshaking());
        assert!(!connection.is_established());
    }

    #[test]
    fn test_writing_before_the_handshake_finishes_is_refused() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        assert!(connection.write(b"too early").is_err());
    }

    /// A failure must be sticky. A connection that failed and then carried
    /// on is the bug this whole file is about.
    #[test]
    fn test_failure_is_sticky() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        connection.push_incoming(&server_hello_bytes(0x0005, Version::TLS12, vec![]));
        assert!(connection.process().is_err());
        assert_eq!(connection.state(), State::Failed);

        // More bytes change nothing, and no further error is invented.
        connection.push_incoming(&server_hello_bytes(0x002f, Version::TLS12, vec![]));
        connection.process().unwrap();
        assert_eq!(connection.state(), State::Failed);
        assert!(connection.write(b"anything").is_err());
    }

    /// The alert to send is queued when the connection fails, so the peer
    /// is told rather than left waiting.
    #[test]
    fn test_a_failure_queues_an_alert_for_the_peer() {
        let mut connection = ClientConnection::new(config(), "example.test").unwrap();
        connection.take_outgoing();
        connection.push_incoming(&server_hello_bytes(0x0005, Version::TLS12, vec![]));
        assert!(connection.process().is_err());

        let bytes = connection.take_outgoing();
        assert!(!bytes.is_empty(), "no alert was queued");

        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes);
        let record = reader.read().unwrap().unwrap();
        assert_eq!(record.content_type, ContentType::Alert);
        let alert = Alert::parse(&record.payload).unwrap();
        assert_eq!(alert.level, AlertLevel::Fatal);
        assert_eq!(alert.description, AlertDescription::ILLEGAL_PARAMETER);
    }

    #[test]
    fn test_garbage_never_panics() {
        for seed in 0..200u32 {
            let mut connection = ClientConnection::new(config(), "example.test").unwrap();
            connection.take_outgoing();
            let bytes: Vec<u8> = (0..200u32)
                .map(|i| ((i * 37 + seed * 11) & 0xff) as u8).collect();
            connection.push_incoming(&bytes);
            let _ = connection.process();
        }
    }
}
