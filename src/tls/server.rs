/*
The TLS 1.2 server.

The mirror of `client.rs`, and written against it rather than beside it:
every piece the two share - the record layer, the key block, the
transcript, `protection_for`, `EphemeralKey` - is one copy that both
call. Two copies would agree about AES and disagree about something
small, and the disagreement would show as a handshake that fails against
one peer in twenty.

Sans-I/O, like the client: bytes in, bytes out, no socket.

## Why there is a server here at all

This library exists to reach servers nobody will upgrade. A browser
cannot be made to speak to one of those - Chromium compiles BoringSSL
in, so nothing can be interposed, and Firefox's NSS is a different world
- so the way a browser reaches an old box is a local proxy that
terminates TLS on one side and speaks whatever the box speaks on the
other. That needs a server, and this is it.

That use set the first shape: one certificate per connection, issued
fresh per host from the proxy's own CA and thrown away. Client
certificates, ALPN, OCSP stapling and TLS 1.3 resumption came later,
for callers that are not the proxy.

## What is different from writing a client

**The server chooses.** A client offers and checks what came back; a
server picks the version and the suite out of what was offered, and
every choice is a place to pick something weaker than necessary. The
selection is the caller's `Selection`, in the caller's order, and the
first one the client also offered wins - so a caller that wants the
client's preference honoured passes a different order rather than
setting a flag.

**The server signs.** A TLS 1.2 ECDHE ServerKeyExchange is a signature
over `client_random || server_random || ServerECDHParams`, and the two
randoms are *not* in the transcript at that point - they are in the
hellos, which are, but the signature covers them directly and in that
order. Signing the params alone produces something a client rejects with
no explanation.

**The RSA key transport path is a Bleichenbacher oracle if you let it
be.** RFC 5246 7.4.7.1 is explicit: on *any* failure decrypting or
checking the premaster - bad padding, wrong length, wrong version - the
server must continue with a **random** premaster and fail later at the
Finished, and must not report which. `decrypt_premaster` does that and
has no error path out of it at all, which is the only shape that cannot
leak: a function that returns `Result` invites a caller to branch on it.

## What is not here

Session resumption at TLS 1.2 - a 1.2 client offering a session ID or a
ticket gets a full handshake - and renegotiation. Each is absent rather
than half-done.

TLS 1.3 **is** here, in `server13.rs` — a separate module rather than a
version flag in this one, because the two handshakes share no step. This
file owns the connection (the transcript, the record layers, the output
buffer) and hands the 1.3 flight to that module; `handle_client_hello`
branches to `handle_client_hello_13` as soon as `choose_version` says
1.3, and nothing below that line is reachable from the 1.3 path.
*/

use std::sync::{Arc, Mutex};

use crate::publickey_ciphers::rsa::{self, RsaPrivateKey};
use crate::random;
use crate::tls::client::Error;
use crate::tls::codec::Writer;
use crate::tls::handshake::{extension, find_extension, groups, CertificateChain,
                            ClientHello, Extension, Finished, HandshakeMessage,
                            HandshakeReader, HandshakeType, ServerHello,
                            SignatureScheme};
use crate::tls::kex::EphemeralKey;
use crate::tls::keys::{self, Side, Transcript};
use crate::tls::keys13;
use crate::tls::server13;
use crate::tls::record::{protection_for, Protection, RecordReader, RecordWriter};
use crate::tls::suites::{self, CipherSuite, KeyExchange, Selection};
use crate::tls::{Alert, AlertDescription, AlertLevel, ContentType, Version};

/// How many bytes of *rejected* early data to skip before treating the
/// connection as broken.
///
/// A rejected 0-RTT client keeps writing under keys the server does not
/// have until it has heard the ServerHello, so those records cannot be
/// decrypted and must not be fatal (RFC 8446 4.2.10). But "skip whatever
/// arrives" is a peer that can make a server discard bytes forever, so it
/// is bounded - generously, because the client is behaving correctly and
/// the only cost of the bound being hit is a handshake that fails where
/// it could have succeeded.
///
/// Sixteen kilobytes plus a record's overhead is one full record's worth
/// more than the largest early data any ticket here allows.
const EARLY_DATA_SKIP_BUDGET: usize = 3 * 16_384;
use crate::x509::builder::SigningKey;
use crate::ec::curves;
use crate::bignum::BigUint;

/// The "hash" of a scheme whose algorithm hashes internally - EdDSA's
/// hash byte 8 (RFC 8422 5.10). A name rather than an `Option`, so that
/// the one place choosing a ServerKeyExchange's signature can treat it as
/// one more answer.
const INTRINSIC: &str = "intrinsic";

/// The private key a server signs and decrypts with.
///
/// Owned rather than borrowed, because a connection outlives the call
/// that made it. The EC variant carries the curve by name so the
/// certificate and the key cannot be given different ones by accident.
/// The RSA half is boxed because an `RsaPrivateKey` is an order of magnitude
/// larger than the EC one - it carries `n`, `d`, both primes, both CRT
/// exponents, the coefficient and three Montgomery contexts, which is most
/// of half a kilobyte. Every move of a `ServerKey` would carry that. One
/// allocation per server configuration is the better trade.
#[derive(Clone)]
pub enum ServerKey {
    Rsa(Box<RsaPrivateKey>),
    Ec { curve: &'static str, private: BigUint },
    /// An EdDSA key: the variant's name and the **seed**, not a scalar.
    ///
    /// TLS 1.3, and TLS 1.2 under the ECDHE_ECDSA suites: RFC 8422 2
    /// defines that family as "ephemeral ECDH with ECDSA or EdDSA
    /// signatures", and 5.4 signs its ServerKeyExchange with EdDSA over the
    /// randoms and params themselves. Not before 1.2: those versions carry
    /// no signature algorithm, so nothing in the message could say the
    /// signature is EdDSA, and OpenSSL refuses an EdDSA certificate there.
    Eddsa { name: &'static str, seed: Vec<u8> },
    /// A GOST R 34.10-2012 key: a curve and the private scalar.
    ///
    /// **TLS 1.3 only, and for the same reason as EdDSA but a different
    /// one.** RFC 9189's 1.2 suites do not sign at all - they are key
    /// transport, so there is no ServerKeyExchange for this key to put a
    /// signature in - and this library's 1.2 *server* does not implement
    /// those suites either. `authenticates` says false for every 1.2
    /// exchange so that a suite is never chosen whose flight this key
    /// cannot produce.
    ///
    /// The scalar rather than a parsed key structure because nothing here
    /// reads a GOST private key out of PKCS#8 yet; a caller has the
    /// number, which is what signing needs.
    Gost { curve: &'static str, private: BigUint },
    /// An ML-DSA key (FIPS 204, RFC 9881 certificates). TLS 1.3 only:
    /// draft-ietf-tls-mldsa forbids its schemes at 1.2, so
    /// `authenticates` refuses every 1.2 exchange.
    ///
    /// In an `Arc` because the expanded key is 2.5 to 4.9 KB and a
    /// server configuration is cloned per connection.
    MlDsa(std::sync::Arc<crate::api::MlDsaKey>),
}

impl core::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServerKey::Rsa(key) => write!(f, "ServerKey::Rsa({} bits, redacted)",
                                          key.public.n.bit_len()),
            ServerKey::Ec { curve, .. } =>
                write!(f, "ServerKey::Ec({}, redacted)", curve),
            ServerKey::Eddsa { name, .. } =>
                write!(f, "ServerKey::Eddsa({}, redacted)", name),
            ServerKey::Gost { curve, .. } =>
                write!(f, "ServerKey::Gost({}, redacted)", curve),
            ServerKey::MlDsa(key) =>
                write!(f, "ServerKey::MlDsa({}, redacted)", key.parameter_set()),
        }
    }
}

impl ServerKey {
    /// Which key exchanges this key can authenticate, at a version.
    fn authenticates(&self, exchange: KeyExchange, version: Version) -> bool {
        match self {
            ServerKey::Rsa(_) => matches!(exchange, KeyExchange::Rsa
                                                  | KeyExchange::EcdheRsa
                                                  | KeyExchange::DheRsa),
            // An EC key cannot do RSA key transport at all: there is
            // nothing for the client to encrypt to.
            ServerKey::Ec { .. } => matches!(exchange, KeyExchange::EcdheEcdsa),
            // **ECDHE_ECDSA, from TLS 1.2.** RFC 8422 2 names the family
            // "ephemeral ECDH with ECDSA or EdDSA signatures". This used to
            // answer false for every 1.2 exchange, on the reading that
            // `ecdhe_ecdsa` meant ECDSA only - which the RFC's own table
            // contradicts - so an Ed25519 server refused every 1.2 client.
            // Before 1.2 there is no algorithm field to name EdDSA in.
            ServerKey::Eddsa { .. } => exchange == KeyExchange::EcdheEcdsa
                && version >= Version::TLS12,
            // **Also no TLS 1.2 suite, for two reasons at once.** RFC
            // 9189's GOST suites are key transport: the client wraps the
            // premaster to this key and there is no ServerKeyExchange to
            // sign, so "authenticates" has nothing to mean. And this
            // library's 1.2 server does not implement those suites -
            // `server_key_exchange` refuses their `KeyExchange` - so
            // answering true would choose a suite whose flight cannot be
            // built. Both would surface far from the decision.
            ServerKey::Gost { .. } => false,
            // draft-ietf-tls-mldsa section 3.2: "MUST NOT be used in TLS
            // 1.2".
            ServerKey::MlDsa(_) => false,
        }
    }

    /// The signature scheme to use with this key and hash.
    fn scheme(&self, hash: &str) -> Option<SignatureScheme> {
        Some(match (self, hash) {
            (ServerKey::Rsa(_), "sha256") => SignatureScheme::RSA_PKCS1_SHA256,
            (ServerKey::Rsa(_), "sha384") => SignatureScheme::RSA_PKCS1_SHA384,
            (ServerKey::Rsa(_), "sha512") => SignatureScheme::RSA_PKCS1_SHA512,
            (ServerKey::Rsa(_), "sha1") => SignatureScheme::RSA_PKCS1_SHA1,
            (ServerKey::Ec { .. }, "sha256") => SignatureScheme::ECDSA_SHA256,
            (ServerKey::Ec { .. }, "sha384") => SignatureScheme::ECDSA_SHA384,
            (ServerKey::Ec { .. }, "sha512") => SignatureScheme::ECDSA_SHA512,
            (ServerKey::Ec { .. }, "sha1") => SignatureScheme::ECDSA_SHA1,
            // EdDSA hashes inside the scheme: the hash byte is 8,
            // "Intrinsic" (RFC 8422 5.10), and the pairs are the TLS 1.3
            // codepoints 0x0807 and 0x0808 read as two bytes.
            (ServerKey::Eddsa { name: "ed25519", .. }, INTRINSIC) =>
                SignatureScheme { hash: 8, signature: 7 },
            (ServerKey::Eddsa { name: "ed448", .. }, INTRINSIC) =>
                SignatureScheme { hash: 8, signature: 8 },
            // No 1.2 scheme for a GOST key here: `authenticates` refuses
            // every 1.2 exchange, so nothing reaches this asking.
            _ => return None,
        })
    }

    fn sign(&self, hash: &str, message: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            ServerKey::Rsa(key) => SigningKey::Rsa(key).sign(hash, message),
            ServerKey::Ec { curve, private } => {
                let handle = curves::by_name(curve)?;
                SigningKey::Ec { curve: &handle, private }.sign(hash, message)
            }
            // **The message itself, not a digest** (RFC 8422 5.4): the
            // randoms and the params go to EdDSA whole, with Ed448's
            // context empty. Any hash but "intrinsic" here means the
            // scheme was chosen for some other key.
            ServerKey::Eddsa { name, seed } => {
                if hash != INTRINSIC {
                    return Err(format!("An {} key signs with no separate hash; \
                                        asked for {}.", name, hash));
                }
                crate::api::eddsa_sign(name, seed, message, &[])
            }
            // Unreachable for the same reason, and spelled out rather
            // than folded into a wildcard so that building the 1.2 GOST
            // server side fails here with what it needs.
            ServerKey::Gost { .. } => Err(
                "RFC 9189's GOST suites are key transport and send no \
                 ServerKeyExchange, so there is nothing here for a GOST key \
                 to sign.".to_string()),
            ServerKey::MlDsa(_) => Err(
                "ML-DSA's TLS signature schemes are TLS 1.3 only, so there is \
                 no ServerKeyExchange for an ML-DSA key to sign.".to_string()),
        }
    }
}

/// What a server offers and how it identifies itself.
pub struct ServerConfig {
    /// The suites this server will accept, **in its own order of
    /// preference**. The first one the client also offered wins.
    ///
    /// A caller that wants the client's preference honoured reorders
    /// this rather than setting a flag: "whose order decides" is a
    /// property of the list, and a boolean beside it would be a second
    /// place to look.
    pub suites: Selection,
    /// The chain to present, leaf first, as DER.
    pub certificate_chain: Vec<Vec<u8>>,
    pub key: ServerKey,
    pub max_version: Version,
    pub min_version: Version,
    /// Ask the client for a certificate, at TLS 1.2 or 1.3.
    ///
    /// **Asking is not requiring.** RFC 8446 4.4.2.1 lets a client answer
    /// with an empty Certificate, and this server accepts that unless
    /// `require_client_certificate` is set - which is the difference
    /// between "show me if you have one" and "no certificate, no
    /// connection", and is a decision rather than a default.
    pub request_client_certificate: bool,
    /// Refuse a client that answered the request with no certificate.
    ///
    /// Only meaningful with `request_client_certificate`. On its own it
    /// does nothing, because a client that was never asked cannot be
    /// faulted for not answering.
    pub require_client_certificate: bool,
    /// How strictly to judge a client chain - key sizes, hash algorithms,
    /// validity dates. The same type the client uses on a server's chain.
    ///
    /// **It carries its own clock, and `ServerConfig::now` does not set
    /// it.** `Policy::default()` verifies as at the epoch, so a caller who
    /// sets `now` here and leaves this alone refuses every client
    /// certificate with "not valid until ...", one field away from the
    /// answer. `Policy::at(now)` is the usual thing to assign, which is
    /// what `api::tls_server` does.
    ///
    /// Two fields rather than one because the policy is a whole object a
    /// caller may want to hold - a different key floor for clients than
    /// for servers is a reasonable thing to want - and folding the clock
    /// out of it would make that impossible. Said here because it is not
    /// guessable from the field's name.
    pub client_policy: crate::x509::verify::Policy,
    /// Roots to judge a client certificate against.
    ///
    /// Empty means the chain is parsed, its signature over the transcript
    /// is checked, and **nothing else** - the connection is authenticated
    /// as "whoever holds that key", which is what a system keyed on public
    /// keys wants and is not what "verified" usually means. Say so at the
    /// call site if that is the intent.
    pub client_roots: Option<crate::trust::TrustStore>,
    /// The key session tickets are sealed under.
    ///
    /// `None` makes each connection generate its own, which seals tickets
    /// nothing else can open - useful for a single connection and useless
    /// for resumption, which is between *two* of them. A server that wants
    /// clients to resume shares one key across every connection it serves,
    /// and `TicketKey::from_bytes` is how a deployment configures one that
    /// also survives a restart.
    pub ticket_key: Option<Arc<crate::tls::tickets::TicketKey>>,
    /// The current time, seconds since the epoch.
    ///
    /// Supplied rather than read, the same way `ClientConfig` takes it:
    /// nothing below `main.rs` calls `SystemTime::now`, so a handshake is
    /// reproducible in a test and a clock is never a hidden input.
    ///
    /// A server only needs it for session tickets - to stamp them, and to
    /// refuse them when they expire. **Which is why `session_tickets`
    /// defaults to zero**: a server that does not know the time cannot
    /// expire a ticket, and one that issues tickets it will honour forever
    /// is worse than one that issues none. `ServerConfig::with_clock` sets
    /// both together.
    pub now: i64,
    /// How many TLS 1.3 session tickets to send after a handshake.
    ///
    /// Two is what most servers send, and the reason is not redundancy: a
    /// client that opens several connections at once would otherwise reuse
    /// one ticket, and a PSK offered twice is linkable across those
    /// connections. Zero turns resumption off - every connection is then a
    /// full handshake, which is slower and no less safe.
    pub session_tickets: u8,
    /// How long a ticket is offered for, in seconds. RFC 8446 4.6.1 caps
    /// this at seven days.
    pub ticket_lifetime: u32,
    /// How much early data (0-RTT) a ticket allows, in bytes. **Zero is
    /// off, and is the default.**
    ///
    /// Off by default because early data is not like the rest of the
    /// connection in two ways that the rest of this configuration cannot
    /// express. It is **not forward secret** - it is encrypted under a key
    /// derived from a PSK the client has been holding, so someone who
    /// later obtains that ticket's PSK reads it, which is not true of
    /// anything sent after the handshake. And it is **replayable**: it is
    /// sent before the server has said a word, so a captured flight can
    /// be sent again and is as valid the second time.
    ///
    /// So this is a statement about the *application*, not about the
    /// transport: turn it on only where the first thing a client sends is
    /// something that may happen twice. `replay_guard` bounds how often a
    /// replay works and does not make it impossible; see `ReplayGuard`.
    pub max_early_data: u32,
    /// The strike register that refuses a 0-RTT flight already seen.
    ///
    /// Shared across connections - a register per connection has seen
    /// nothing - so it is an `Arc<Mutex<..>>` the way `ticket_key` is an
    /// `Arc`. `None` with `max_early_data` set means early data is
    /// accepted with no replay check at all, which is a decision the
    /// caller has to make rather than a default: it is right behind a
    /// front end that already de-duplicates, and wrong everywhere else.
    pub replay_guard: Option<Arc<Mutex<crate::tls::tickets::ReplayGuard>>>,
    /// The application protocols this server speaks, **in its own order
    /// of preference** (RFC 7301). Empty - the default - negotiates
    /// nothing and the client falls back to whatever it would do
    /// without ALPN, which for HTTP is 1.1.
    ///
    /// The server's order rather than the client's, and no flag to
    /// change it, for the same reason `suites` works that way: whose
    /// preference decides is a property of the list, and a boolean
    /// beside it would be a second place to look.
    ///
    /// **Nothing is promised that is not in this list.** A proxy must
    /// not answer `h2` on behalf of something that speaks HTTP/1.1, so
    /// the list is what the thing *behind* the server can do, not what
    /// this code can parse.
    /// A cached OCSP response to staple to the certificate (RFC 6066
    /// §8), as DER. `None` - the default - staples nothing.
    ///
    /// **Nothing here fetches it.** A server that went to the responder
    /// during a handshake would add the responder's latency and the
    /// responder's availability to every connection, which is the
    /// problem stapling exists to solve rather than a way to solve it.
    /// The operator fetches it out of band, on a schedule, and hands it
    /// over; `x509::ocsp::build_request` and `responder_urls` are what
    /// that job needs.
    ///
    /// It is not checked here either. A server cannot usefully judge a
    /// statement about its own certificate - it would be checking its
    /// own homework - and a response this server thought was bad is one
    /// the *client* still has to judge for itself. What is stapled is
    /// what was supplied.
    pub ocsp_response: Option<Vec<u8>>,
    pub alpn: Vec<String>,
    /// Fail the handshake when the client offered ALPN and none of its
    /// protocols is in `alpn`.
    ///
    /// Off by default, which is RFC 7301's own advice read the careful
    /// way: a server with nothing in common may either fail with
    /// `no_application_protocol` or carry on without the extension, and
    /// carrying on is right when the protocol is decided some other way
    /// (a URL scheme, a port). It is wrong when the application has no
    /// other way to tell, and then this makes the disagreement loud
    /// instead of leaving two ends speaking past each other.
    ///
    /// Ignored when `alpn` is empty: a server that offers no protocols
    /// has not disagreed with anybody.
    pub require_alpn: bool,
    /// Agree to encrypt-then-MAC when the client asks (RFC 7366). On by
    /// default: it is the proper fix for the CBC padding oracle.
    pub allow_encrypt_then_mac: bool,
    /// Agree to the extended master secret when the client asks. On by
    /// default; it is what stops two connections sharing one.
    pub allow_extended_master_secret: bool,
}

impl ServerConfig {
    pub fn new(certificate_chain: Vec<Vec<u8>>, key: ServerKey) -> ServerConfig {
        ServerConfig {
            suites: Selection::modern(),
            certificate_chain,
            key,
            max_version: Version::TLS13,
            min_version: Version::TLS12,
            request_client_certificate: false,
            require_client_certificate: false,
            client_roots: None,
            client_policy: crate::x509::verify::Policy::default(),
            ticket_key: None,
            now: 0,
            session_tickets: 0,
            ticket_lifetime: crate::tls::tickets::DEFAULT_LIFETIME,
            max_early_data: 0,
            replay_guard: None,
            ocsp_response: None,
            alpn: Vec::new(),
            require_alpn: false,
            allow_encrypt_then_mac: true,
            allow_extended_master_secret: true,
        }
    }

    /// The same, with a clock, and session tickets on.
    ///
    /// The two go together: tickets are the only thing a server needs the
    /// time for, and a ticket whose expiry is never checked is a session
    /// key with no end date.
    pub fn with_clock(certificate_chain: Vec<Vec<u8>>, key: ServerKey, now: i64)
                      -> ServerConfig {
        ServerConfig {
            now,
            session_tickets: 2,
            ..ServerConfig::new(certificate_chain, key)
        }
    }

    /// A server that will also talk to something old: the legacy suite
    /// set and a floor of TLS 1.0.
    ///
    /// A named constructor rather than flags, so that using it is a
    /// decision somebody made.
    pub fn legacy(certificate_chain: Vec<Vec<u8>>, key: ServerKey) -> ServerConfig {
        ServerConfig {
            suites: Selection::legacy(),
            min_version: Version::TLS10,
            ..ServerConfig::new(certificate_chain, key)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    WaitClientHello,
    WaitClientKeyExchange,
    /// TLS 1.3 only. No state is shared with the 1.2 machine.
    ///
    /// A client that was asked for a certificate sends one - possibly
    /// empty - and then a CertificateVerify only if it was not empty, so
    /// the Finished is reachable from all three.
    /// Early data (0-RTT) is arriving, under the client's early traffic
    /// keys, until an EndOfEarlyData says it has stopped. Only reachable
    /// when the server accepted it.
    WaitEndOfEarlyData13,
    /// TLS 1.2 only, and only after this server asked: the client's
    /// CertificateVerify, which comes **after** its ClientKeyExchange
    /// because it signs the concatenation that message is part of.
    WaitClientCertificateVerify12,
    WaitClientCertificate13,
    WaitClientCertificateVerify13,
    WaitClientFinished13,
    WaitChangeCipherSpec,
    WaitFinished,
    Established,
    Closed,
    Failed,
}

impl State {
    fn describe(self) -> &'static str {
        match self {
            State::WaitClientHello => "waiting for the ClientHello",
            State::WaitClientCertificateVerify12 =>
                "waiting for the client's CertificateVerify (TLS 1.2)",
            State::WaitEndOfEarlyData13 =>
                "reading early data (TLS 1.3 0-RTT)",
            State::WaitClientCertificate13 =>
                "waiting for the client's Certificate (TLS 1.3)",
            State::WaitClientCertificateVerify13 =>
                "waiting for the client's CertificateVerify (TLS 1.3)",
            State::WaitClientFinished13 =>
                "waiting for the client's Finished (TLS 1.3)",
            State::WaitClientKeyExchange =>
                "waiting for the client's ClientKeyExchange",
            State::WaitChangeCipherSpec =>
                "waiting for the client's ChangeCipherSpec",
            State::WaitFinished => "waiting for the client's Finished",
            State::Established => "the handshake is finished",
            State::Closed => "the connection is closed",
            State::Failed => "the connection has failed",
        }
    }
}

/// One server-side connection.
pub struct ServerConnection {
    config: ServerConfig,
    state: State,
    reader: RecordReader,
    writer: RecordWriter,
    messages: HandshakeReader,
    outgoing: Vec<u8>,
    incoming: Vec<u8>,

    version: Option<Version>,
    suite: Option<&'static CipherSuite>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    /// The name the client asked for, from SNI. Reported, so a proxy can
    /// tell which host this connection is for.
    server_name: Option<String>,
    /// The protocol chosen from what the client offered, if any.
    negotiated_alpn: Option<String>,
    /// Whether a TLS 1.2 CertificateRequest went out. (The 1.3 answer
    /// lives on `Tls13`, because the two flights are different shapes
    /// and a shared field would be read in a state it means nothing in.)
    requested_client_certificate: bool,
    /// Whether a CertificateVerify is owed: the client sent a
    /// non-empty certificate. **Not the same as having asked** - a
    /// client that answered with an empty chain owes nothing, and one
    /// that sent a CertificateVerify anyway is signing for a
    /// certificate nobody saw.
    expect_certificate_verify: bool,
    /// The concatenation of every handshake message before the client's
    /// CertificateVerify, which is what that signature covers.
    ///
    /// The raw bytes rather than a hash, because the scheme in the
    /// message chooses the hash and the message has not arrived yet.
    /// Taken on the way in for the same reason `before_client_finished`
    /// is: it cannot be reconstructed afterwards.
    before_certificate_verify: Vec<u8>,
    /// The **transcript hash** before the client's CertificateVerify,
    /// for TLS 1.0 and 1.1 - where it is already MD5 and SHA-1
    /// concatenated, which is exactly what the signature covers. A
    /// separate field from the raw bytes above because the two versions
    /// want different things and one field would be right for one of
    /// them.
    before_certificate_verify_10: Vec<u8>,
    /// Whether a stapled OCSP response is going out: the client asked
    /// and this server has one. Both halves, because a server that
    /// stapled unasked would be sending an extension the client must
    /// refuse.
    stapling: bool,
    /// The ALPN protocols the client offered, reported for the same
    /// reason, and because a protocol that was *not* chosen is still
    /// worth reporting.
    offered_alpn: Vec<String>,

    transcript: Option<Transcript>,
    /// The transcript hash as it stood *before* the client's Finished,
    /// which is what that message's verify_data covers. Taken when the
    /// message arrives, because a hash cannot be rewound.
    before_client_finished: Vec<u8>,
    before_client_certificate_verify: Vec<u8>,
    ephemeral: Option<EphemeralKey>,
    master: Vec<u8>,
    encrypt_then_mac: bool,
    extended_master_secret: bool,
    /// The session hash for the extended master secret: the transcript
    /// through the ClientKeyExchange.
    session_hash: Vec<u8>,
    /// The `legacy_version` field of the ClientHello, for the RSA
    /// rollback check. See `decrypt_premaster`.
    offered_version: Version,

    /// TLS 1.3 state, present only once 1.3 has been negotiated. All of
    /// it lives in `server13.rs`; none of it is reachable from the 1.2
    /// path, which is the point of the split.
    tls13: Option<crate::tls::server13::Tls13>,
    /// The first ClientHello, kept only so that a HelloRetryRequest can
    /// replace it in the transcript with the synthetic `message_hash`
    /// message RFC 8446 4.4.1 requires.
    first_hello: Vec<u8>,
    /// One retry and no more. A second lets a peer loop us.
    sent_retry_request: bool,
    /// The key this server seals its session tickets under, generated once
    /// per connection object. A server that wants tickets to survive a
    /// restart, or to work across a fleet, passes the same key in - see
    /// `ServerConnection::with_ticket_key`.
    ticket_key: Arc<crate::tls::tickets::TicketKey>,
    /// The chain the client presented, leaf first. Empty when none was
    /// asked for, or when the client answered the request with nothing.
    client_certificates: Vec<Vec<u8>>,
    client_certificate_verified: bool,
    /// Whether this ClientHello carried `early_data`, whatever we did
    /// about it. Kept because the *rejected* case still has records
    /// arriving that have to be skipped rather than failed on.
    offered_early_data: bool,
    /// How many more bytes of undecryptable record to skip before giving
    /// up. `Some` only after early data was offered and declined.
    skipping_early_data: Option<usize>,
    /// The early data that was accepted, kept separate from `incoming`
    /// until the handshake finishes.
    ///
    /// **Separate because it is not the same kind of data.** It is not
    /// forward secret and it can be a replay, and a caller that reads it
    /// out of the same buffer as everything else has no way to tell which
    /// bytes those were.
    early_data: Vec<u8>,
    /// What the 1.3 transcript starts with before the ClientHello: empty
    /// normally, `message_hash || HelloRetryRequest` after a retry. A PSK
    /// binder covers all of it, so it has to be kept rather than recomputed.
    transcript_prefix: Vec<u8>,
}

impl ServerConnection {
    pub fn new(config: ServerConfig) -> Result<ServerConnection, Error> {
        if config.certificate_chain.is_empty() {
            return Err(Error::local("A server needs a certificate chain; \
                                     without one it has nothing to present."));
        }
        // The EC key names its curve as a string, so a typo is a failure
        // somewhere. Make it here, where the caller is still holding the
        // config, rather than in the middle of a handshake where it
        // arrives as an internal_error the peer cannot act on.
        if let ServerKey::Ec { curve, .. } = &config.key {
            curves::by_name(curve).map_err(Error::local)?;
        }
        // Resolved before `config` is moved into the connection.
        let ticket_key = match &config.ticket_key {
            Some(key) => Arc::clone(key),
            None => Arc::new(crate::tls::tickets::TicketKey::generate()
                .map_err(Error::local)?),
        };
        let mut server_random = [0u8; 32];
        let bytes = random::bytes(32).map_err(Error::local)?;
        server_random.copy_from_slice(&bytes);

        Ok(ServerConnection {
            config,
            state: State::WaitClientHello,
            reader: RecordReader::new(),
            // Until a version is negotiated the writer uses 1.0, which
            // is what RFC 5246 appendix E says to put in the record
            // header of a first flight - a client that only speaks 1.0
            // drops a record claiming anything higher.
            writer: RecordWriter::new(Version::TLS10),
            messages: HandshakeReader::new(),
            outgoing: Vec::new(),
            incoming: Vec::new(),
            version: None,
            suite: None,
            client_random: [0u8; 32],
            server_random,
            server_name: None,
            offered_alpn: Vec::new(),
            negotiated_alpn: None,
            requested_client_certificate: false,
            expect_certificate_verify: false,
            before_certificate_verify: Vec::new(),
            before_certificate_verify_10: Vec::new(),
            stapling: false,
            transcript: None,
            before_client_finished: Vec::new(),
            before_client_certificate_verify: Vec::new(),
            ephemeral: None,
            master: Vec::new(),
            encrypt_then_mac: false,
            extended_master_secret: false,
            session_hash: Vec::new(),
            offered_version: Version::TLS12,
            tls13: None,
            first_hello: Vec::new(),
            sent_retry_request: false,
            ticket_key,
            transcript_prefix: Vec::new(),
            client_certificates: Vec::new(),
            client_certificate_verified: false,
            offered_early_data: false,
            skipping_early_data: None,
            early_data: Vec::new(),
        })
    }

    // ------------------------------------------------------- the surface ---

    pub fn push_incoming(&mut self, bytes: &[u8]) {
        self.reader.push_incoming(bytes);
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }

    pub fn take_incoming(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.incoming)
    }

    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    pub fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Established | State::Closed | State::Failed)
    }

    pub fn state(&self) -> &'static str {
        self.state.describe()
    }

    /// The version negotiated, once there is one.
    pub fn version(&self) -> Option<Version> {
        self.version
    }

    /// The suite chosen, once there is one.
    ///
    /// The whole suite rather than a name, because there are two names,
    /// the IANA one and OpenSSL's, and an accessor returning one of them
    /// makes the caller guess which. The client side does the same.
    pub fn negotiated_suite(&self) -> Option<&'static CipherSuite> {
        self.suite
    }

    /// The name the client asked for in SNI.
    ///
    /// **This is what a proxy needs**: it is the only thing in a TLS
    /// handshake that says which host the client thinks it is reaching,
    /// and it arrives before anything has to be decided. A client that
    /// sends none gives `None`, and then a proxy has only the address.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Whether encrypt-then-MAC was agreed (RFC 7366).
    ///
    /// Reported rather than assumed from the config: the server offers
    /// it and the *client* has to have asked, so the config says what
    /// we would accept and this says what happened.
    pub fn uses_encrypt_then_mac(&self) -> bool {
        self.encrypt_then_mac
    }

    /// Whether the extended master secret was agreed (RFC 7627).
    pub fn uses_extended_master_secret(&self) -> bool {
        self.extended_master_secret
    }

    /// The protocol chosen from `ServerConfig::alpn`, or `None`.
    ///
    /// `None` means either that this server offers no protocols, or
    /// that the client offered none, or that nothing was in common and
    /// `require_alpn` was off. The three are the same on the wire - no
    /// extension comes back - and a caller that has to tell them apart
    /// reads `offered_alpn` as well.
    pub fn negotiated_alpn(&self) -> Option<&str> {
        self.negotiated_alpn.as_deref()
    }

    /// Every ALPN protocol the client offered, chosen or not.
    pub fn offered_alpn(&self) -> &[String] {
        &self.offered_alpn
    }

    /// The client's certificate chain, leaf first, or empty.
    ///
    /// Empty means one of three different things - we did not ask, we
    /// asked and the client had nothing, or the handshake has not got
    /// that far - and the caller can tell them apart from its own
    /// configuration and `is_established`. It is deliberately not an
    /// `Option`: a chain that is present says nothing on its own about
    /// whether it was *verified*, and `client_certificate_verified`
    /// is the separate question.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.client_certificates
    }

    /// Discard a record that failed to deprotect, if it can only be
    /// early data the client sent before it learned we declined.
    ///
    /// **This is the one place a decryption failure is not fatal**, and it
    /// is narrow on purpose: only after the client offered early data and
    /// we did not accept it, only before the handshake has finished, only
    /// for a bad MAC, and only for a bounded number of bytes. Outside
    /// that, a record that does not authenticate is an attacker or a
    /// broken peer and the connection ends.
    ///
    /// RFC 8446 4.2.10 requires it: the client wrote those records before
    /// it had heard the ServerHello, so it could not have known. Failing
    /// on the first one means 0-RTT can never be *declined*, only
    /// forbidden.
    fn skip_rejected_early_data(&mut self,
                                error: &crate::tls::record::RecordError) -> bool {
        if error.alert != AlertDescription::BAD_RECORD_MAC {
            return false;
        }
        let budget = match self.skipping_early_data {
            Some(budget) => budget,
            None => return false,
        };
        // A record we could not read has a length we did see, and that is
        // what is charged against the budget. Using the plaintext length
        // is not an option - there is no plaintext.
        let spent = self.reader.last_record_length();
        if spent >= budget {
            self.skipping_early_data = None;
            return false;
        }
        self.skipping_early_data = Some(budget - spent);
        true
    }

    /// Take the early data (0-RTT) this connection accepted.
    ///
    /// **Kept out of `take_incoming` on purpose.** These bytes are not
    /// like the rest of the connection in two ways: they are not forward
    /// secret, having been encrypted under a key derived from a PSK the
    /// client was holding, and they may be a **replay** of a flight that
    /// already happened. Mixing them into the ordinary stream would leave
    /// a caller no way to tell which bytes those were, and the whole
    /// decision about whether 0-RTT is safe is a decision about what the
    /// application does with exactly these bytes.
    ///
    /// Taken rather than read, so the same bytes are not processed twice
    /// by a caller that polls.
    pub fn take_early_data(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.early_data)
    }

    /// Whether this connection accepted early data.
    ///
    /// False with the client having offered it is the ordinary rejection,
    /// and it is not an error: the client resends the same bytes after
    /// the handshake.
    pub fn accepted_early_data(&self) -> bool {
        self.tls13.as_ref().and_then(|state| state.early_data).is_some()
    }

    /// Whether the client's chain was checked against `client_roots`.
    ///
    /// False with a non-empty `peer_certificates` is the legitimate
    /// shape where the caller configured no roots and judges the key
    /// itself. The client's *signature* is checked either way - that
    /// is what proves it holds the key - so this is only about the
    /// chain.
    pub fn client_certificate_verified(&self) -> bool {
        self.client_certificate_verified
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Established {
            return Err(Error::local(format!(
                "Cannot write application data: {}.", self.state.describe())));
        }
        let bytes = self.writer.write(ContentType::ApplicationData, data)?;
        self.outgoing.extend_from_slice(&bytes);
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if matches!(self.state, State::Closed | State::Failed) {
            return Ok(());
        }
        self.send_alert(Alert::warning(AlertDescription::CLOSE_NOTIFY))?;
        self.state = State::Closed;
        Ok(())
    }

    /// Advance as far as the bytes allow.
    pub fn process(&mut self) -> Result<(), Error> {
        loop {
            if matches!(self.state, State::Closed | State::Failed) {
                return Ok(());
            }
            let record = match self.reader.read() {
                Ok(Some(record)) => record,
                Ok(None) => return Ok(()),
                Err(error) if self.skip_rejected_early_data(&error) => continue,
                Err(error) => {
                    self.state = State::Failed;
                    let error = Error::from(error);
                    if let Some(alert) = error.alert {
                        let _ = self.send_alert(Alert::fatal(alert));
                    }
                    return Err(error);
                }
            };
            if let Err(error) = self.handle_record(record) {
                self.state = State::Failed;
                if let Some(alert) = error.alert {
                    let _ = self.send_alert(Alert::fatal(alert));
                }
                return Err(error);
            }
        }
    }

    // -------------------------------------------------------- the machine ---

    fn handle_record(&mut self, record: crate::tls::record::Record)
                     -> Result<(), Error> {
        match record.content_type {
            ContentType::Handshake => {
                self.messages.push(&record.payload);
                while let Some(message) = self.messages.next_message()? {
                    self.handle_handshake(message)?;
                }
                Ok(())
            }
            ContentType::ChangeCipherSpec => {
                // **At TLS 1.3 a ChangeCipherSpec means nothing and is
                // dropped.** RFC 8446 5 keeps it only so that a
                // middlebox watching for a 1.2-shaped handshake sees
                // one; acting on it would install keys in the middle of
                // a handshake that does not have any at that point. It
                // is only legal in the clear, which is enforced by
                // `Aead13::decrypt` refusing the type inside a
                // protected record rather than by a check here.
                if self.version == Some(Version::TLS13) || self.sent_retry_request {
                    if record.payload != [1] {
                        return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                            "A ChangeCipherSpec must be exactly one byte, 0x01."));
                    }
                    return Ok(());
                }
                if self.state != State::WaitChangeCipherSpec {
                    return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                        format!("A ChangeCipherSpec arrived while {}.",
                                self.state.describe())));
                }
                if record.payload != [1] {
                    return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                        "A ChangeCipherSpec must be exactly one byte, 0x01."));
                }
                // **A partial handshake message held across a
                // ChangeCipherSpec is a peer interleaving things it
                // should not**, and has been a real attack: the
                // fragment before the key change and the fragment after
                // it get joined into one message that neither key
                // authenticated on its own.
                if self.messages.has_partial_message() {
                    return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                        "A ChangeCipherSpec arrived with a handshake message \
                         half delivered."));
                }
                let keys = self.key_block()?;
                let protection = self.protection(&keys.client)?;
                self.reader.change_cipher_spec(protection);
                self.state = State::WaitFinished;
                Ok(())
            }
            ContentType::ApplicationData => {
                if self.state == State::WaitEndOfEarlyData13 {
                    return self.accept_early_record(&record.payload);
                }
                if self.state != State::Established {
                    return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                        format!("Application data arrived while {}.",
                                self.state.describe())));
                }
                self.incoming.extend_from_slice(&record.payload);
                Ok(())
            }
            ContentType::Alert => {
                let alert = Alert::parse(&record.payload)
                    .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
                if alert.description == AlertDescription::CLOSE_NOTIFY {
                    self.state = State::Closed;
                    return Ok(());
                }
                if alert.level == AlertLevel::Fatal {
                    self.state = State::Failed;
                    // Nothing to send back: the peer has already given up.
                    return Err(Error::local(
                        format!("The peer sent a {}.", alert.name())));
                }
                Ok(())
            }
            other => Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                format!("A {:?} record arrived, which this server does not \
                         expect at any point.", other))),
        }
    }

    fn handle_handshake(&mut self, message: HandshakeMessage) -> Result<(), Error> {
        // The client's Finished covers the transcript *before* itself,
        // so the hash is taken here rather than rewound afterwards - a
        // hash cannot be rewound, and a server that tried would be
        // checking something else.
        if message.message_type == HandshakeType::Finished {
            if let Some(transcript) = &self.transcript {
                self.before_client_finished = transcript.hash();
            }
        }
        // And the client's CertificateVerify covers the transcript
        // before *itself* too - through its Certificate. Same reason,
        // and the same trap: the hash has to be taken on the way in,
        // because by the time the handler runs the message is already
        // in it.
        if message.message_type == HandshakeType::CertificateVerify {
            if let Some(transcript) = &self.transcript {
                self.before_client_certificate_verify = transcript.hash();
                // **And the raw bytes, for TLS 1.2.** That version's
                // CertificateVerify signs `Hash(handshake_messages)`
                // with a hash the message itself names, so the hash
                // cannot be taken until the message has been read - and
                // by then the bytes are gone. 1.3 needs the hash and
                // 1.2 needs the bytes; both are taken here because
                // neither can be recovered afterwards.
                self.before_certificate_verify = transcript.messages().to_vec();
                // And the transcript *hash*, which before TLS 1.2 is
                // the 36 bytes an RSA CertificateVerify covers directly.
                self.before_certificate_verify_10 = transcript.hash();
            }
        }
        if let Some(transcript) = &mut self.transcript {
            transcript.update(&message.raw);
        }
        // The session hash for the extended master secret is the
        // transcript through the ClientKeyExchange, which is the
        // message just added.
        if message.message_type == HandshakeType::ClientKeyExchange {
            if let Some(transcript) = &self.transcript {
                self.session_hash = transcript.session_hash();
            }
        }

        match (self.state, message.message_type) {
            (State::WaitClientHello, HandshakeType::ClientHello) =>
                self.handle_client_hello(&message),
            (State::WaitClientKeyExchange, HandshakeType::Certificate) =>
                self.handle_client_certificate_12(&message),
            (State::WaitClientCertificateVerify12,
             HandshakeType::CertificateVerify) =>
                self.handle_client_certificate_verify_12(&message),
            (State::WaitClientKeyExchange, HandshakeType::ClientKeyExchange) =>
                self.handle_client_key_exchange(&message),
            (State::WaitFinished, HandshakeType::Finished) =>
                self.handle_finished(&message),
            (State::WaitEndOfEarlyData13, HandshakeType::EndOfEarlyData) =>
                self.handle_end_of_early_data(&message),
            (State::WaitClientCertificate13, HandshakeType::Certificate) =>
                self.handle_client_certificate_13(&message),
            (State::WaitClientCertificateVerify13, HandshakeType::CertificateVerify) =>
                self.handle_client_certificate_verify_13(&message),
            (State::WaitClientFinished13, HandshakeType::Finished) =>
                self.handle_finished_13(&message),
            (state, kind) => Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                format!("A {} arrived while {}.", kind.name(), state.describe()))),
        }
    }

    fn handle_client_hello(&mut self, message: &HandshakeMessage)
                           -> Result<(), Error> {
        let hello = ClientHello::parse(&message.body)?;
        self.client_random = hello.random;
        // Kept for the RSA rollback check, which compares it with the
        // first two bytes of the premaster. It is the version the
        // client *offered*, not the one negotiated - using the
        // negotiated one makes the check useless, because a man in the
        // middle who forced the version down would have forced both
        // sides of the comparison down together.
        self.offered_version = hello.legacy_version;

        let version = self.choose_version(&hello)?;
        if version >= Version::TLS13 {
            return self.handle_client_hello_13(&hello, message);
        }
        let suite = self.choose_suite(&hello, version)?;
        self.version = Some(version);
        self.suite = Some(suite);
        self.writer.set_version(version);

        // The transcript begins now, with the hello that has just
        // arrived - it cannot begin earlier, because the PRF hash comes
        // from the suite that the hello decides.
        let mut transcript = Transcript::new(version, suite.prf)
            .map_err(Error::local)?;
        if self.config.request_client_certificate {
            // **Before the first update**, or the buffer starts in the
            // middle of the handshake and the client's CertificateVerify
            // is checked against the wrong bytes - which fails at the
            // signature, a long way from the cause. Only on handshakes
            // that will need it: a 1.2 CertificateVerify signs the raw
            // concatenation under a hash the message itself names, so
            // there is no way to have it from the running hashes.
            transcript.keep_messages();
        }
        transcript.update(&message.raw);
        self.transcript = Some(transcript);

        self.encrypt_then_mac = self.config.allow_encrypt_then_mac
            && suite.cipher.is_cbc()
            && find_extension(&hello.extensions, extension::ENCRYPT_THEN_MAC)
               .is_some();
        self.extended_master_secret = self.config.allow_extended_master_secret
            && find_extension(&hello.extensions,
                              extension::EXTENDED_MASTER_SECRET).is_some();
        self.server_name = read_server_name(&hello);
        self.offered_alpn = read_alpn(&hello);

        let mut extensions = Vec::new();
        // RFC 5746: answering with an empty renegotiation_info is how a
        // server says it understands the extension. Without it a client
        // cannot tell a fresh handshake from a renegotiation, which is
        // the 2009 attack.
        extensions.push(Extension { kind: extension::RENEGOTIATION_INFO,
                                    body: vec![0] });
        if self.encrypt_then_mac {
            extensions.push(Extension { kind: extension::ENCRYPT_THEN_MAC,
                                        body: Vec::new() });
        }
        if self.extended_master_secret {
            extensions.push(Extension { kind: extension::EXTENDED_MASTER_SECRET,
                                        body: Vec::new() });
        }
        if self.server_name.is_some() {
            // An empty server_name is the acknowledgement; the name
            // itself is not echoed.
            extensions.push(Extension { kind: extension::SERVER_NAME,
                                        body: Vec::new() });
        }
        // **ALPN goes in the ServerHello at 1.2 and in
        // EncryptedExtensions at 1.3**, which is why it is written in
        // two places rather than one: at 1.3 it must not be in the
        // ServerHello, where it would be in the clear.
        self.negotiated_alpn = choose_alpn(&self.config, &self.offered_alpn)?;
        self.stapling = self.config.ocsp_response.is_some()
            && find_extension(&hello.extensions, extension::STATUS_REQUEST)
               .is_some();
        if let Some(protocol) = &self.negotiated_alpn {
            extensions.push(Extension {
                kind: extension::ALPN,
                body: server13::encode_alpn(protocol)?,
            });
        }
        if self.stapling {
            // **Empty here.** RFC 6066 §8: the ServerHello's
            // `status_request` is an acknowledgement and nothing more -
            // the response itself comes in its own CertificateStatus
            // message. Putting the response here is the 1.3 shape in
            // the 1.2 message, and a client reads the length fields
            // wrong rather than reading a response.
            extensions.push(Extension { kind: extension::STATUS_REQUEST,
                                        body: Vec::new() });
        }

        let server_hello = ServerHello {
            legacy_version: version,
            random: self.server_random,
            session_id: Vec::new(),
            cipher_suite: suite.code,
            compression_method: 0,
            extensions,
        };

        let mut flight: Vec<(HandshakeType, Vec<u8>)> = vec![
            (HandshakeType::ServerHello, server_hello.encode()?),
            (HandshakeType::Certificate,
             CertificateChain {
                 certificates: self.config.certificate_chain.clone(),
             }.encode()?),
        ];
        if self.stapling {
            // **Immediately after the Certificate**, which is what makes
            // it a statement about that chain's leaf: RFC 6066 §8 puts it
            // there and gives it no CertID of its own on the wire. A
            // client matches it against the certificate it just read.
            let response = self.config.ocsp_response.as_ref()
                .ok_or_else(|| Error::local("Stapling with nothing to staple."))?;
            flight.push((HandshakeType::CertificateStatus,
                         crate::tls::handshake::encode_certificate_status(response)?));
        }
        if let Some(body) = self.server_key_exchange(&hello, suite, version)? {
            flight.push((HandshakeType::ServerKeyExchange, body));
        }
        // **After the ServerKeyExchange and before the
        // ServerHelloDone** (RFC 5246 7.4). The order is not decoration:
        // the client's CertificateVerify signs the concatenation of
        // every handshake message so far, so the two ends have to agree
        // about what was in it and in what order.
        if self.config.request_client_certificate {
            self.requested_client_certificate = true;
            // **Two different messages.** TLS 1.2 added
            // `supported_signature_algorithms` in the middle; before it
            // there was nothing to negotiate, because the construction
            // is fixed by the version. Sending the 1.2 shape to a 1.0
            // client has it read the CA list's length as a signature
            // list, and the failure is a decode error two fields later.
            let body = if version >= Version::TLS12 {
                self.certificate_request_12()?
            } else {
                self.certificate_request_10()?
            };
            flight.push((HandshakeType::CertificateRequest, body));
        }
        flight.push((HandshakeType::ServerHelloDone, Vec::new()));

        let mut bytes = Vec::new();
        for (kind, body) in flight {
            let message = HandshakeMessage::new(kind, body)?;
            if let Some(transcript) = &mut self.transcript {
                transcript.update(&message.raw);
            }
            bytes.extend_from_slice(&message.raw);
        }
        let records = self.writer.write(ContentType::Handshake, &bytes)?;
        self.outgoing.extend_from_slice(&records);

        self.state = State::WaitClientKeyExchange;
        Ok(())
    }

    /// The highest version both sides speak.
    ///
    /// From `supported_versions` when the client sent one, and from
    /// `legacy_version` otherwise. A client offering nothing in range
    /// gets `protocol_version`, which is the alert that says so.
    fn choose_version(&self, hello: &ClientHello) -> Result<Version, Error> {
        let ceiling = self.config.max_version;
        let floor = self.config.min_version;

        let offered: Vec<Version> = match find_extension(
                &hello.extensions, extension::SUPPORTED_VERSIONS) {
            Some(extension) =>
                crate::tls::handshake13::parse_client_supported_versions(
                    &extension.body)?,
            // No extension: the legacy field is the highest offered, and
            // everything down to the floor is implied.
            None => vec![hello.legacy_version],
        };

        let mut best: Option<Version> = None;
        for version in offered {
            if version > ceiling || version < floor {
                continue;
            }
            if best.is_none_or(|current| version > current) {
                best = Some(version);
            }
        }
        // A client whose legacy field is above our ceiling still gets
        // the ceiling, which is the ordinary downgrade a 1.2 server does
        // for a 1.3 client that sent no extension.
        if best.is_none() && hello.legacy_version >= ceiling {
            best = Some(ceiling);
        }
        best.ok_or_else(|| Error::new(AlertDescription::PROTOCOL_VERSION, format!(
            "The client offered nothing between {} and {}.",
            floor.name(), ceiling.name())))
    }

    /// The first suite *this server* prefers that the client also
    /// offered, and that this server's key can authenticate.
    fn choose_suite(&self, hello: &ClientHello, version: Version)
                    -> Result<&'static CipherSuite, Error> {
        let mut refused: Vec<&'static str> = Vec::new();
        for code in self.config.suites.for_version(version).codes() {
            let suite = match suites::by_code(*code) {
                Some(suite) => suite,
                None => continue,
            };
            if !hello.cipher_suites.contains(code) {
                continue;
            }
            if version < suite.min_version {
                continue;
            }
            // A suite whose key exchange this server's key cannot
            // authenticate is not a choice: an EC key cannot decrypt an
            // RSA premaster, and an RSA key cannot make an ECDSA
            // signature.
            if !self.config.key.authenticates(suite.key_exchange, version) {
                refused.push(suite.name);
                continue;
            }
            if !suite.is_implemented() {
                continue;
            }
            return Ok(suite);
        }
        let detail = if refused.is_empty() {
            String::new()
        } else {
            format!(" ({} would have matched, and this server's {:?} key \
                     cannot authenticate them)", refused.join(", "),
                    self.config.key)
        };
        Err(Error::new(AlertDescription::HANDSHAKE_FAILURE, format!(
            "No cipher suite in common at {}.{}", version.name(), detail)))
    }

    /// The ServerKeyExchange, for the exchanges that have one.
    ///
    /// **Plain RSA key transport has none**, and that distinction is
    /// FREAK: a client must decide whether to expect one from the suite
    /// rather than from a message having arrived. The server's side of
    /// that is simply never to send one for those suites.
    fn server_key_exchange(&mut self, hello: &ClientHello,
                           suite: &'static CipherSuite, version: Version)
                           -> Result<Option<Vec<u8>>, Error> {
        match suite.key_exchange {
            KeyExchange::Rsa => Ok(None),
            KeyExchange::EcdheRsa | KeyExchange::EcdheEcdsa => {
                let group = self.choose_group(hello)?;
                let key = EphemeralKey::generate(group).map_err(Error::local)?;

                // `ServerECDHParams`: curve_type(3) || named_curve ||
                // one byte length || point.
                let mut params = Writer::new();
                params.u8(3);
                params.u16(group);
                params.vector8(&key.public_bytes())?;
                let params = params.finish();

                // **The signature covers both randoms and then the
                // params.** They are in the hellos, which are in the
                // transcript, but this signature does not use the
                // transcript - it names them directly and in that
                // order. Signing the params alone makes a client refuse
                // with nothing to say.
                let mut signed = Vec::with_capacity(64 + params.len());
                signed.extend_from_slice(&self.client_random);
                signed.extend_from_slice(&self.server_random);
                signed.extend_from_slice(&params);

                let hash = self.choose_signature_hash(hello, version)?;
                let scheme = self.config.key.scheme(hash).ok_or_else(
                    || Error::local(format!(
                        "No signature scheme for this key with {}.", hash)))?;
                let signature = self.config.key.sign(hash, &signed)
                    .map_err(Error::local)?;

                let mut body = Writer::new();
                body.raw(&params);
                // **The SignatureAndHashAlgorithm is TLS 1.2 and later
                // only.** Writing it at 1.0 or 1.1 puts two bytes where
                // the signature's length belongs, and the client reads
                // a length from the middle of a hash identifier.
                if version >= Version::TLS12 {
                    body.u16(scheme.to_u16());
                }
                body.vector16(&signature)?;

                self.ephemeral = Some(key);
                Ok(Some(body.finish()))
            }
            other => Err(Error::new(AlertDescription::HANDSHAKE_FAILURE, format!(
                "{:?} is not implemented on this side.", other))),
        }
    }

    /// A group both sides do, from `supported_groups`.
    fn choose_group(&self, hello: &ClientHello) -> Result<u16, Error> {
        // X448 last, not on strength but on cost: it is the slowest of
        // these on this library's bignum, and a *server* pays for the
        // group the client asked for. It is here at all because a client
        // that offers only X448 should get a handshake rather than a
        // refusal.
        const OURS: [u16; 5] = [groups::X25519, groups::SECP256R1,
                                groups::SECP384R1, groups::SECP521R1,
                                groups::X448];
        let offered = match find_extension(&hello.extensions,
                                           extension::SUPPORTED_GROUPS) {
            Some(extension) => {
                let mut reader = crate::tls::codec::Reader::new(&extension.body);
                let mut list = reader.sub16()?;
                let mut groups = Vec::new();
                while !list.is_empty() {
                    groups.push(list.u16()?);
                }
                groups
            }
            // RFC 4492 section 4: a client that sends no
            // supported_groups is taken to support the common ones.
            // P-256 is the one every such client has.
            None => vec![groups::SECP256R1],
        };
        for group in OURS {
            if offered.contains(&group) {
                return Ok(group);
            }
        }
        Err(Error::new(AlertDescription::HANDSHAKE_FAILURE,
            "The client offered no elliptic curve group this server does."))
    }

    /// The hash to sign the ServerKeyExchange with.
    ///
    /// From `signature_algorithms` when the client sent one. Before
    /// TLS 1.2 there was no such extension and no choice: the signature
    /// is MD5+SHA-1 for RSA and SHA-1 for ECDSA, which is not a scheme
    /// this side implements - so those versions get SHA-1 through the
    /// ordinary path and a caller that needs the true legacy
    /// construction does not have it.
    fn choose_signature_hash(&self, hello: &ClientHello, version: Version)
                             -> Result<&'static str, Error> {
        if version < Version::TLS12 {
            return Ok("sha1");
        }
        let extension = find_extension(&hello.extensions,
                                       extension::SIGNATURE_ALGORITHMS)
            .ok_or_else(|| Error::new(AlertDescription::MISSING_EXTENSION,
                "A TLS 1.2 client must send signature_algorithms."))?;
        let offered = crate::tls::handshake13::parse_signature_algorithms(
            &extension.body)?;

        // This server's order, not the client's: the client's list is
        // what it accepts, and choosing the strongest of those is the
        // server's business. "Intrinsic" is the EdDSA keys' only answer
        // and no other key's, so where it sits in the order changes
        // nothing.
        for hash in [INTRINSIC, "sha256", "sha384", "sha512", "sha1"] {
            if let Some(scheme) = self.config.key.scheme(hash) {
                if offered.contains(&scheme.to_u16()) {
                    return Ok(hash);
                }
            }
        }
        Err(Error::new(AlertDescription::HANDSHAKE_FAILURE,
            "The client accepts no signature scheme this server's key can \
             produce."))
    }

    /// The TLS 1.2 CertificateRequest this server sends.
    ///
    /// **The certificate types and the signature schemes are two
    /// different lists and both are the server's answer.** The types say
    /// what kind of key the certificate may hold; the schemes say how it
    /// may sign. A client has to satisfy both, and a server that sent
    /// only one of them would be asking a question with half the answer
    /// in it.
    ///
    /// `certificate_authorities` is left empty. It is a hint about which
    /// issuers the server will recognise, and this server does not
    /// enforce it - `client_roots` does the enforcing, at the chain,
    /// where a refusal can say why. Sending the list would also leak
    /// which CAs a private service trusts to anybody who connects.
    fn certificate_request_12(&self) -> Result<Vec<u8>, Error> {
        use crate::tls::handshake::client_certificate_type as kind;
        Ok(crate::tls::handshake::CertificateRequest12 {
            certificate_types: vec![kind::RSA_SIGN, kind::ECDSA_SIGN],
            // What this server can *verify*, deliberately a different
            // list from what it can sign with - a server with an EC key
            // still verifies an RSA client certificate perfectly well.
            //
            // The TLS 1.3 PSS codepoints are legal here too (RFC 8446
            // 4.2.3 allows them in a 1.2 handshake), but they are left
            // out: at 1.2 the signature is over a raw concatenation and
            // an RSA client will use PKCS#1 v1.5, which is what every
            // 1.2 peer expects.
            schemes: server13::VERIFIABLE_12.to_vec(),
            authorities: Vec::new(),
        }.encode()?)
    }

    /// The TLS 1.0 and 1.1 CertificateRequest: the same message with the
    /// signature-algorithm list taken out, because there is nothing to
    /// negotiate before 1.2.
    fn certificate_request_10(&self) -> Result<Vec<u8>, Error> {
        use crate::tls::handshake::client_certificate_type as kind;
        Ok(crate::tls::handshake::CertificateRequest10 {
            certificate_types: vec![kind::RSA_SIGN, kind::ECDSA_SIGN],
            authorities: Vec::new(),
        }.encode()?)
    }

    /// The client's TLS 1.2 Certificate: a plain chain, possibly empty.
    ///
    /// **An empty chain is a legal answer** (RFC 5246 7.4.6) and is what
    /// a client with nothing suitable sends - not silence, which the
    /// server would wait for. Whether that ends the connection is
    /// `require_client_certificate`, and the two are separate for the
    /// same reason they are at 1.3.
    fn handle_client_certificate_12(&mut self, message: &HandshakeMessage)
                                    -> Result<(), Error> {
        let chain = CertificateChain::parse(&message.body)?;
        self.client_certificates = chain.certificates;
        if self.client_certificates.is_empty() {
            if self.config.require_client_certificate {
                return Err(Error::new(AlertDescription::HANDSHAKE_FAILURE,
                    "The client sent an empty certificate chain and this \
                     server requires one."));
            }
            // Nothing to prove possession of, so no CertificateVerify
            // follows - and one arriving would be a client signing for a
            // certificate it did not send.
            self.expect_certificate_verify = false;
        } else {
            self.expect_certificate_verify = true;
        }
        self.state = State::WaitClientKeyExchange;
        Ok(())
    }

    /// The client's TLS 1.2 CertificateVerify.
    ///
    /// **It signs `Hash(handshake_messages)`** - the raw concatenation
    /// of everything up to but not including this message, hashed with
    /// the scheme's own hash (RFC 5246 7.4.8). Not a context string and
    /// not a transcript hash fed through a KDF, which is what 1.3 does:
    /// the two produce different bytes, and a signature made the other
    /// way verifies against nothing and looks exactly like a wrong key.
    ///
    /// It arrives **after** the ClientKeyExchange, which is why the
    /// concatenation includes that message and the 1.3 one does not
    /// exist.
    fn handle_client_certificate_verify_12(&mut self, message: &HandshakeMessage)
                                           -> Result<(), Error> {
        // **Unreachable through the state machine, and kept anyway.**
        // `handle_client_key_exchange` only enters this state when a
        // non-empty certificate arrived, so removing this check fails no
        // test - the deliberate-breakage sweep says so. It stays for the
        // same reason `ec::ct::Field::add` keeps its redundant P = -P
        // arm: a sweep cannot tell "untested" from "not needed", and the
        // thing being guarded is a client signing for a certificate
        // nobody saw. The check below for a leaf to verify against is a
        // third copy of the same invariant.
        if !self.expect_certificate_verify {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                "A CertificateVerify arrived from a client that sent no \
                 certificate, so there is nothing it could be proving \
                 possession of."));
        }
        let version = self.version.ok_or_else(|| Error::local("No version."))?;
        if version < Version::TLS12 {
            return self.verify_client_signature_10(&message.body);
        }
        let verify = crate::tls::handshake::CertificateVerify12::parse(
            &message.body)?;
        if !server13::VERIFIABLE_12.contains(&verify.scheme.to_u16()) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The client signed with {:#06x}, which this server did not \
                 offer.", verify.scheme.to_u16())));
        }
        // The concatenation **before** this message: `handle_handshake`
        // took it on the way in, because a running hash cannot be
        // rewound and the raw bytes are not kept anywhere else.
        let signed = core::mem::take(&mut self.before_certificate_verify);
        let leaf = self.client_certificates.first()
            .ok_or_else(|| Error::local("No client certificate to verify."))?;
        crate::tls::server13::verify_signature_12(leaf, verify.scheme, &signed,
                                                  &verify.signature)?;

        // Only now is the chain worth judging: a chain that verifies
        // against a root but did not sign this handshake is somebody
        // else's certificate, replayed.
        if let Some(roots) = &self.config.client_roots {
            crate::tls::server13::verify_client_chain(
                roots, &self.client_certificates, &self.config.client_policy)?;
            self.client_certificate_verified = true;
        }
        self.state = State::WaitChangeCipherSpec;
        Ok(())
    }

    /// The TLS 1.0 and 1.1 CertificateVerify: a bare signature.
    ///
    /// **Three things differ from 1.2 and none of them is a flag.**
    /// There is no algorithm field, so what was signed is decided by the
    /// certificate's key type. An RSA signature is over
    /// `MD5(handshake_messages) || SHA1(handshake_messages)` - which is
    /// exactly what `Transcript::hash` returns at these versions, and
    /// why this path needs no message buffer at all - with **no
    /// DigestInfo**, because there is no algorithm to identify. An
    /// ECDSA one is over the SHA-1 half alone.
    fn verify_client_signature_10(&mut self, body: &[u8]) -> Result<(), Error> {
        use crate::x509::{Certificate, PublicKey};
        let verify = crate::tls::handshake::CertificateVerify10::parse(body)?;
        // Taken on the way in, before this message joined the
        // transcript: at these versions it is already the 36 bytes an
        // RSA signature covers.
        let digest = core::mem::take(&mut self.before_certificate_verify_10);
        if digest.len() != 36 {
            return Err(Error::local(format!(
                "The pre-1.2 transcript hash is {} bytes; it must be MD5 and \
                 SHA-1 concatenated.", digest.len())));
        }
        let leaf = self.client_certificates.first()
            .ok_or_else(|| Error::local("No client certificate to verify."))?;
        let certificate = Certificate::parse(leaf)
            .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;

        let ok = match &certificate.public_key {
            PublicKey::Rsa { n, e } => {
                let key = rsa::RsaPublicKey::new(n.clone(), e.clone())
                    .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
                rsa::verify_pkcs1v15_raw(&key, &digest, &verify.signature)
                    .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
            }
            PublicKey::Ec { curve, point } => {
                // **The SHA-1 half alone**, which is the second twenty
                // bytes. Handing the whole 36 to an ECDSA verifier
                // truncates it to the group's width and checks
                // something nobody signed.
                let handle = crate::ec::curves::by_name(curve)
                    .map_err(Error::local)?;
                let public = handle.decode_point(point).map_err(|e| Error::new(
                    AlertDescription::BAD_CERTIFICATE, e))?;
                let decoded = crate::x509::verify::decode_ecdsa_der(&verify.signature)
                    .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
                handle.verify(&public, &digest[16..], &decoded)
                    .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
            }
            other => return Err(Error::new(AlertDescription::UNSUPPORTED_CERTIFICATE,
                format!("Cannot verify a pre-1.2 CertificateVerify against a \
                         {:?} key.", other))),
        };
        if !ok {
            return Err(Error::new(AlertDescription::DECRYPT_ERROR,
                "The CertificateVerify signature did not check out."));
        }
        if let Some(roots) = &self.config.client_roots {
            crate::tls::server13::verify_client_chain(
                roots, &self.client_certificates, &self.config.client_policy)?;
            self.client_certificate_verified = true;
        }
        self.state = State::WaitChangeCipherSpec;
        Ok(())
    }

    fn handle_client_key_exchange(&mut self, message: &HandshakeMessage)
                                  -> Result<(), Error> {
        let suite = self.suite.ok_or_else(|| Error::local("No suite."))?;
        let version = self.version.ok_or_else(|| Error::local("No version."))?;

        let shared = match suite.key_exchange {
            KeyExchange::Rsa => {
                let mut reader = crate::tls::codec::Reader::new(&message.body);
                // TLS 1.0 sent the encrypted premaster with no length
                // prefix; every version since has one. SSLv3 is the only
                // one this would get wrong and it is below the floor.
                let encrypted = reader.vector16()?.to_vec();
                reader.expect_empty("ClientKeyExchange")?;
                // Drawn here, where a failure can end the handshake: it
                // happens before the ciphertext is examined, so it says
                // nothing about it.
                let fallback = random::bytes(48).map_err(Error::local)?;
                self.decrypt_premaster(&encrypted, fallback)
            }
            KeyExchange::EcdheRsa | KeyExchange::EcdheEcdsa => {
                let mut reader = crate::tls::codec::Reader::new(&message.body);
                let point = reader.vector8()?;
                reader.expect_empty("ClientKeyExchange")?;
                let key = self.ephemeral.as_ref()
                    .ok_or_else(|| Error::local("No ephemeral key."))?;
                let shared = key.complete(point).map_err(|e| Error::new(
                    AlertDescription::ILLEGAL_PARAMETER, e))?;
                // **Not stripped.** RFC 4492 5.10 is explicit that
                // the x coordinate's leading zeros MUST NOT be
                // truncated, which is the opposite of the finite-field
                // rule in RFC 5246 8.1.2. `keys::premaster_from_shared`
                // is the one place that knows the difference.
                shared
            }
            other => return Err(Error::new(AlertDescription::HANDSHAKE_FAILURE,
                format!("{:?} is not implemented on this side.", other))),
        };
        let premaster = keys::premaster_from_shared(suite.key_exchange, shared);

        self.master = if self.extended_master_secret {
            keys::extended_master_secret(version, suite.prf, &premaster,
                                         &self.session_hash)
        } else {
            keys::master_secret(version, suite.prf, &premaster,
                                &self.client_random, &self.server_random)
        }.map_err(Error::local)?;

        self.state = if self.expect_certificate_verify {
            // **The CertificateVerify comes after the
            // ClientKeyExchange** at 1.2, because it signs the
            // concatenation and that message is part of it. At 1.3 the
            // order is the other way round, which is one of several
            // reasons the two paths share no state.
            State::WaitClientCertificateVerify12
        } else {
            State::WaitChangeCipherSpec
        };
        Ok(())
    }

    /// The premaster secret from an RSA ClientKeyExchange.
    ///
    /// **This function cannot fail, and that is the point.**
    ///
    /// RFC 5246 7.4.7.1: on any failure - bad PKCS#1 padding, the wrong
    /// length, the wrong version in the first two bytes - the server
    /// must continue with a *random* premaster and let the handshake
    /// die at the Finished instead, and must not report which happened.
    /// Every distinguishable outcome here is a Bleichenbacher oracle,
    /// and the attack needs only that the two cases be told apart, by
    /// message or by timing.
    ///
    /// So there is no `Result` to branch on. A caller that got one
    /// would write `?` and put the oracle back.
    ///
    /// The random fallback is drawn by the caller **unconditionally**,
    /// before anything is examined, so the failing path does no work the
    /// succeeding path does not - and so that the random source failing
    /// ends the handshake there, rather than leaving a fixed fallback.
    /// A fixed fallback would be worse than none: the same wrong
    /// premaster gives the same Finished, so two connections tell the
    /// cases apart.
    fn decrypt_premaster(&self, encrypted: &[u8], fallback: Vec<u8>) -> Vec<u8> {

        let key = match &self.config.key {
            ServerKey::Rsa(key) => key,
            // An EC key cannot have been chosen for an RSA suite, so
            // this is unreachable through `choose_suite` - and it still
            // must not distinguish itself.
            _ => return fallback,
        };

        let decrypted = rsa::decrypt_pkcs1v15(key, encrypted).unwrap_or_default();

        // Everything from here is folded into one byte and selected on
        // at the end, rather than returned from early. Three separate
        // `return fallback` statements are three different amounts of
        // work, and the difference is the oracle.
        //
        // `good` is 0xff while nothing has gone wrong and 0x00 after
        // anything has.
        let mut candidate = [0u8; 48];
        let mut good = ct_eq_usize(decrypted.len(), 48);
        // Copy whatever there is, up to 48 bytes. A short decryption
        // leaves zeros behind it and `good` is already 0.
        let take = core::cmp::min(decrypted.len(), 48);
        candidate[..take].copy_from_slice(&decrypted[..take]);

        // **The first two bytes are the ClientHello's `legacy_version`
        // field, not the negotiated version.** They were the same thing
        // until TLS 1.3 pinned the field at 0x0303. A client that was
        // forced down to an older version by a man in the middle puts
        // its *real* preference here, so the mismatch is how the server
        // finds out - which is the whole point of those two bytes.
        //
        // RFC 5246 7.4.7.1 deliberately does not report the failure:
        // reporting it is Bleichenbacher's oracle. So it folds into
        // `good` like every other failure and comes out as the same
        // random premaster.
        let offered = self.offered_version.to_bytes();
        good &= ct_eq_u8(candidate[0], offered[0]);
        good &= ct_eq_u8(candidate[1], offered[1]);

        // Select without branching: `good` is a mask, not a bool.
        let mut premaster = vec![0u8; 48];
        for index in 0..48 {
            premaster[index] = (candidate[index] & good)
                             | (fallback[index] & !good);
        }
        premaster
    }

    // ------------------------------------------------------- TLS 1.3 ---

    /// The 1.3 ClientHello: negotiate, then either retry or send the whole
    /// flight.
    ///
    /// Everything this does lives in `server13.rs`; what stays here is the
    /// state that belongs to the connection - the transcript, the record
    /// layers and the output buffer.
    fn handle_client_hello_13(&mut self, hello: &ClientHello,
                              message: &HandshakeMessage) -> Result<(), Error> {
        self.version = Some(Version::TLS13);
        // The record header says 1.2 for the rest of the connection. The
        // reader is deliberately *not* pinned with `expect_version`: the
        // 1.3 record layer checks the header itself, as part of the AEAD's
        // additional data, where a wrong one is a decryption failure rather
        // than a version complaint.
        self.writer.set_version(crate::tls::record13::LEGACY_RECORD_VERSION);

        // The binder covers `transcript_prefix || this hello`, so both have
        // to go in. After a HelloRetryRequest the prefix is the synthetic
        // `message_hash` and the retry itself.
        let resumption = server13::Resumption {
            key: &self.ticket_key,
            prefix: &self.transcript_prefix,
            hello_bytes: &message.raw,
            now: self.config.now,
        };
        let offer = if self.config.session_tickets > 0 {
            Some(&resumption)
        } else {
            // No clock and no tickets, so nothing we issued can be offered
            // back. Not looking at the extension at all is the honest
            // version of refusing every ticket in it.
            None
        };
        let negotiated = match server13::prepare(&self.config, hello, offer)? {
            Some(negotiated) => negotiated,
            None => return self.send_retry_request(hello, message),
        };
        self.suite = Some(negotiated.suite);
        let hash = server13::hash_of(negotiated.suite)?;

        // The transcript starts either with this hello, or - if this is the
        // second one after a retry - with what was already accumulated:
        // `message_hash` and the HelloRetryRequest. The first ClientHello
        // is not in it and must not be.
        let mut transcript = match self.transcript.take() {
            Some(transcript) => transcript,
            None => Transcript::new(Version::TLS13, negotiated.suite.prf)
                .map_err(Error::local)?,
        };
        transcript.update(&message.raw);
        self.first_hello = message.raw.clone();
        // Taken here, before anything of ours goes in: the client's early
        // traffic secret is over the ClientHello alone, because that is
        // all the client had when it wrote those records.
        let hello_only_hash = transcript.hash();
        let _ = hash;

        self.server_name = read_server_name(hello);
        self.offered_alpn = read_alpn(hello);
        self.offered_early_data =
            find_extension(&hello.extensions, extension::EARLY_DATA).is_some();
        self.negotiated_alpn = choose_alpn(&self.config, &self.offered_alpn)?;
        // **The client has to have asked.** A server that stapled
        // unasked sends a certificate-entry extension RFC 8446 4.2
        // requires the client to refuse, and the handshake fails for a
        // reason that looks like a broken certificate.
        self.stapling = self.config.ocsp_response.is_some()
            && find_extension(&hello.extensions, extension::STATUS_REQUEST)
               .is_some();

        let mut outgoing = core::mem::take(&mut self.outgoing);
        let state = server13::send_flight(&self.config, &negotiated,
                                          self.server_random, &mut transcript,
                                          &mut self.reader, &mut self.writer,
                                          &mut outgoing,
                                          self.negotiated_alpn.as_deref(),
                                          &hello_only_hash,
                                          self.stapling);
        self.outgoing = outgoing;
        self.transcript = Some(transcript);
        let state = state?;
        self.state = if state.early_data.is_some() {
            // Early data first, whatever else was asked for: the client
            // wrote those records before it had heard a word from us, so
            // they are already on their way.
            State::WaitEndOfEarlyData13
        } else if state.requested_client_certificate {
            State::WaitClientCertificate13
        } else {
            State::WaitClientFinished13
        };
        if state.early_data.is_none() && self.offered_early_data {
            // Offered and declined. The client is sending those records
            // anyway, under keys we do not have, and RFC 8446 4.2.10 says
            // to skip them rather than fail - it cannot know yet.
            self.skipping_early_data = Some(EARLY_DATA_SKIP_BUDGET);
        }
        self.tls13 = Some(state);
        Ok(())
    }

    /// A HelloRetryRequest, and the transcript surgery it requires.
    ///
    /// **The first ClientHello leaves the transcript.** RFC 8446 4.4.1
    /// replaces it with a synthetic `message_hash` message carrying its
    /// hash, so the transcript the second hello continues is
    /// `message_hash || HelloRetryRequest || ClientHello2`. A server that
    /// simply kept appending agrees with itself and with no client.
    fn send_retry_request(&mut self, hello: &ClientHello,
                          message: &HandshakeMessage) -> Result<(), Error> {
        if self.sent_retry_request {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE,
                "A second ClientHello still had no usable key share. One \
                 HelloRetryRequest is all RFC 8446 allows, and a second \
                 would let a peer loop us."));
        }
        let suite = server13::retry_suite(&self.config, hello)?;
        let group = server13::retry_group(hello)?;
        let hash = server13::hash_of(suite)?;

        let synthetic = server13::synthetic_message_hash(hash, &message.raw)?;
        let mut transcript = Transcript::new(Version::TLS13, suite.prf)
            .map_err(Error::local)?;
        transcript.update(&synthetic.raw);
        // The second hello's binder covers `message_hash || HelloRetryRequest`
        // in front of itself, so the prefix has to be kept rather than
        // recomputed - by then the transcript is a hash and cannot be read
        // back. The HelloRetryRequest is appended just below, inside
        // `send_retry_request`, so it is added to the prefix there too.
        self.transcript_prefix = synthetic.raw.clone();

        let mut outgoing = core::mem::take(&mut self.outgoing);
        let mut prefix = core::mem::take(&mut self.transcript_prefix);
        let result = server13::send_retry_request(suite, group, &hello.session_id,
                                                  &mut transcript, &mut self.writer,
                                                  &mut outgoing, &mut prefix);
        self.transcript_prefix = prefix;
        self.outgoing = outgoing;
        result?;

        self.suite = Some(suite);
        self.transcript = Some(transcript);
        self.sent_retry_request = true;
        // Back to the same state: the next message is another ClientHello.
        self.state = State::WaitClientHello;
        Ok(())
    }

    /// The client's Certificate, which may be empty.
    ///
    /// **An empty one is a legitimate answer** (RFC 8446 4.4.2.1): the
    /// client was asked and has nothing to show. Whether that ends the
    /// connection is `require_client_certificate`, and the two are
    /// deliberately separate - "show me if you have one" is a real and
    /// common configuration.
    fn handle_client_certificate_13(&mut self, message: &HandshakeMessage)
                                    -> Result<(), Error> {
        let chain = crate::tls::handshake13::Certificate13::parse(&message.body)?;
        // The context echoes the one we sent, which was empty. A non-empty
        // one is a reply to a post-handshake request we never made.
        if !chain.request_context.is_empty() {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                "The client's Certificate echoed a request context we never \
                 sent."));
        }
        self.client_certificates = chain.chain();

        if self.client_certificates.is_empty() {
            if self.config.require_client_certificate {
                return Err(Error::new(AlertDescription::CERTIFICATE_REQUIRED,
                    "This server requires a client certificate and the client \
                     sent none."));
            }
            // No certificate, so no CertificateVerify: there is nothing to
            // prove possession of. Straight to the Finished.
            self.state = State::WaitClientFinished13;
            return Ok(());
        }
        self.state = State::WaitClientCertificateVerify13;
        Ok(())
    }

    /// The client's CertificateVerify.
    ///
    /// **`Side13::Client`, not `Side13::Server`.** The two differ only in a
    /// context string, and verifying with the wrong one rejects every
    /// honest client - or, in a server that also signs with the wrong one,
    /// accepts a signature made over something else entirely.
    fn handle_client_certificate_verify_13(&mut self, message: &HandshakeMessage)
                                           -> Result<(), Error> {
        use crate::tls::handshake13::{self as hs13, scheme, Side13};

        let verify = hs13::CertificateVerify::parse(&message.body)?;
        if !scheme::allowed_in_certificate_verify(verify.scheme) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "{} is not legal in a TLS 1.3 CertificateVerify.",
                scheme::name(verify.scheme))));
        }
        // **The list this server actually sent**, which depends on the
        // suite: `verifiable_for` adds RFC 9367's schemes under an RFC
        // 9367 suite and not otherwise. Checking against the static
        // `VERIFIABLE` instead refused a GOST client certificate the
        // server had itself asked for, one message after asking - which
        // `tests/test_gost_13_signature.rs` found, and which is the
        // ordinary cost of the same rule being written in two places.
        // It is one function called twice now, not two lists.
        let suite = self.suite.ok_or_else(|| Error::local(
            "A CertificateVerify before a suite was chosen."))?;
        if !crate::tls::server13::verifiable_for(suite).contains(&verify.scheme) {
            return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
                "The client signed with {}, which this server did not offer.",
                scheme::name(verify.scheme))));
        }

        // The transcript **through the client's Certificate**, taken in
        // `handle_handshake` before this message went in. Reading it
        // here instead signs over the CertificateVerify's own bytes,
        // which is a hash nobody else computes.
        let content = hs13::certificate_verify_content(
            Side13::Client, &self.before_client_certificate_verify);

        let leaf = self.client_certificates.first()
            .ok_or_else(|| Error::local("No client certificate to verify against."))?;
        crate::tls::server13::verify_signature(leaf, verify.scheme,
                                               &content, &verify.signature)?;

        // Only now is the chain worth judging: a chain that verifies against
        // a root but did not sign this transcript is somebody else's
        // certificate, replayed.
        if let Some(roots) = &self.config.client_roots {
            crate::tls::server13::verify_client_chain(
                roots, &self.client_certificates, &self.config.client_policy)?;
            self.client_certificate_verified = true;
        }

        self.state = State::WaitClientFinished13;
        Ok(())
    }

    /// One record of accepted early data.
    ///
    /// Counted against the limit the ticket and the configuration agreed
    /// on, and **refused rather than truncated** when it is exceeded: the
    /// limit is the server's promise about how much it will process, and
    /// quietly dropping the rest is a request that half happened. RFC 8446
    /// 4.2.10 names `unexpected_message` for it.
    fn accept_early_record(&mut self, payload: &[u8]) -> Result<(), Error> {
        let state = self.tls13.as_mut().ok_or_else(||
            Error::local("No TLS 1.3 state while reading early data."))?;
        let limit = state.early_data.ok_or_else(||
            Error::local("Early data arrived with no limit agreed."))?;
        let total = state.early_bytes as u64 + payload.len() as u64;
        if total > limit as u64 {
            return Err(Error::new(AlertDescription::UNEXPECTED_MESSAGE, format!(
                "The client sent more than the {} bytes of early data \
                 this ticket allows.", limit)));
        }
        state.early_bytes = total as u32;
        self.early_data.extend_from_slice(payload);
        Ok(())
    }

    /// EndOfEarlyData: the client has stopped writing under its early
    /// keys, and everything after this is under its handshake keys.
    ///
    /// **It is in the transcript** (RFC 8446 4.5), which is why it is a
    /// handshake message at all rather than a record type: the client's
    /// Finished has to cover the fact that early data happened, or a
    /// stripped 0-RTT flight would go unnoticed.
    fn handle_end_of_early_data(&mut self, message: &HandshakeMessage)
                                -> Result<(), Error> {
        if !message.body.is_empty() {
            return Err(Error::new(AlertDescription::DECODE_ERROR,
                                  "EndOfEarlyData has no body."));
        }
        let state = self.tls13.as_mut().ok_or_else(||
            Error::local("No TLS 1.3 state at EndOfEarlyData."))?;
        let keys = state.client_handshake.take().ok_or_else(||
            Error::local("No held-back client handshake keys."))?;
        let protection = Protection::Aead13(
            crate::tls::record13::Aead13::with_rekeying(
                state.aead.name, state.hash, keys, state.aead.tag_len,
                state.aead.mgm).map_err(Error::local)?);
        self.reader.change_cipher_spec(protection);
        // A resumed handshake never asks for a certificate, so this can
        // only go one way - but the check is written out rather than
        // assumed, because "resumption implies no CertificateRequest" is
        // enforced somewhere else and a second copy of a rule is how the
        // two drift apart.
        self.state = if state.requested_client_certificate {
            State::WaitClientCertificate13
        } else {
            State::WaitClientFinished13
        };
        Ok(())
    }

    /// The client's Finished, which is the whole of its second flight.
    fn handle_finished_13(&mut self, message: &HandshakeMessage)
                          -> Result<(), Error> {
        let finished = Finished::parse(&message.body)?;
        let state = self.tls13.as_mut().ok_or_else(||
            Error::local("No TLS 1.3 state at the client Finished."))?;

        // `before_client_finished` is the hash taken in `handle_handshake`
        // before this message was added - which is what the client signed.
        let expected = keys13::finished(state.hash, &state.client_finished_key,
                                        &self.before_client_finished)
            .map_err(Error::local)?;
        if !keys::verify_data_matches(&expected, &finished.verify_data) {
            return Err(Error::new(AlertDescription::DECRYPT_ERROR,
                "The client's Finished did not verify.".to_string()));
        }

        // Only now can the reader move to the application keys: this
        // message was protected under the handshake ones.
        let keys = state.client_application.take().ok_or_else(||
            Error::local("The client's application keys were already taken."))?;
        let protection = Protection::Aead13(
            crate::tls::record13::Aead13::with_rekeying(
                state.aead.name, state.hash, keys, state.aead.tag_len,
                state.aead.mgm).map_err(Error::local)?);
        self.reader.change_cipher_spec(protection);
        self.state = State::Established;

        // **The resumption secret is over a transcript one message longer
        // than the application keys'** - "ClientHello ... client Finished"
        // (RFC 8446 7.1). `handle_handshake` has already added the client's
        // Finished, so the transcript is at exactly the right point *now*
        // and will not be again: the next thing written into it would be the
        // ticket itself.
        self.issue_session_tickets()?;
        Ok(())
    }

    /// Send the NewSessionTickets, if this server issues any.
    ///
    /// Each carries a PSK derived with its own nonce, so two tickets from
    /// one handshake do not give each other up. They go out under the
    /// application keys, which are already installed on the writer.
    fn issue_session_tickets(&mut self) -> Result<(), Error> {
        let count = self.config.session_tickets;
        if count == 0 {
            return Ok(());
        }
        let (hash, prf, suite) = {
            let state = self.tls13.as_ref().ok_or_else(||
                Error::local("No TLS 1.3 state when issuing tickets."))?;
            (state.hash, state.prf, state.suite)
        };
        let transcript = self.transcript.as_ref()
            .ok_or_else(|| Error::local("No transcript when issuing tickets."))?
            .hash();
        let master = {
            let state = self.tls13.as_ref().ok_or_else(||
                Error::local("No TLS 1.3 state when issuing tickets."))?;
            state.schedule.resumption_master(&transcript).map_err(Error::local)?
        };
        let _ = hash;

        for _ in 0..count {
            let ticket = crate::tls::tickets::issue(
                &self.ticket_key, prf, suite, &master,
                self.config.now, self.config.ticket_lifetime,
                self.config.max_early_data,
                // The name this connection was for, sealed into the
                // ticket, because early data arrives before anything is
                // negotiated and only the previous connection can say
                // what it was meant for.
                self.server_name.as_deref().unwrap_or("").as_bytes())
                .map_err(Error::local)?;
            let message = HandshakeMessage::new(
                HandshakeType::NewSessionTicket, ticket.encode()?)?;
            // **Not into the transcript.** A NewSessionTicket is a
            // post-handshake message; adding it would move the transcript
            // past the point every later ticket's PSK is derived from, and
            // the second ticket would be computed over a transcript the
            // client does not share. The client's own code has the mirror
            // image of this note.
            let bytes = self.writer.write(ContentType::Handshake, &message.raw)?;
            self.outgoing.extend_from_slice(&bytes);
        }
        Ok(())
    }

    fn handle_finished(&mut self, message: &HandshakeMessage) -> Result<(), Error> {
        let suite = self.suite.ok_or_else(|| Error::local("No suite."))?;
        let version = self.version.ok_or_else(|| Error::local("No version."))?;

        let expected = keys::verify_data(version, suite, &self.master,
                                         Side::Client,
                                         &self.before_client_finished)
            .map_err(Error::local)?;
        let finished = Finished::parse(&message.body)?;
        if !keys::verify_data_matches(&expected, &finished.verify_data) {
            return Err(Error::new(AlertDescription::DECRYPT_ERROR,
                "The client's Finished does not match the handshake we saw. \
                 The handshake was tampered with, or the keys disagree - and \
                 in the RSA case, the premaster did not decrypt."));
        }

        let bytes = self.writer.write(ContentType::ChangeCipherSpec, &[1])?;
        self.outgoing.extend_from_slice(&bytes);
        let keys = self.key_block()?;
        let protection = self.protection(&keys.server)?;
        self.writer.change_cipher_spec(protection);

        // The server's verify_data covers the transcript **including**
        // the client's Finished, which `handle_handshake` has already
        // added.
        let transcript_hash = self.transcript.as_ref()
            .ok_or_else(|| Error::local("No transcript."))?.hash();
        let verify = keys::verify_data(version, suite, &self.master,
                                       Side::Server, &transcript_hash)
            .map_err(Error::local)?;
        let reply = HandshakeMessage::new(HandshakeType::Finished,
                                          Finished { verify_data: verify }
                                              .encode())?;
        let bytes = self.writer.write(ContentType::Handshake, &reply.raw)?;
        self.outgoing.extend_from_slice(&bytes);

        self.state = State::Established;
        Ok(())
    }

    // ---------------------------------------------------------- plumbing ---

    fn key_block(&self) -> Result<keys::KeyBlock, Error> {
        let suite = self.suite.ok_or_else(|| Error::local("No suite."))?;
        let version = self.version.ok_or_else(|| Error::local("No version."))?;
        keys::key_block(version, suite, &self.master, &self.client_random,
                        &self.server_random).map_err(Error::local)
    }

    fn protection(&self, direction: &keys::DirectionKeys)
                  -> Result<Protection, Error> {
        let suite = self.suite.ok_or_else(|| Error::local("No suite."))?;
        let version = self.version.ok_or_else(|| Error::local("No version."))?;
        protection_for(suite, version, direction, self.encrypt_then_mac)
            .map_err(Error::local)
    }

    fn send_alert(&mut self, alert: Alert) -> Result<(), Error> {
        let bytes = self.writer.write(ContentType::Alert, &alert.to_bytes())?;
        self.outgoing.extend_from_slice(&bytes);
        Ok(())
    }
}

/// `0xff` if the two bytes are equal, `0x00` otherwise, without a branch.
///
/// A mask rather than a `bool`, because the caller needs to combine
/// several of these and then select with them. Returning `bool` would
/// invite an `if`, which is the thing being avoided.
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let difference = a ^ b;
    // difference == 0  ->  0xff;  anything else  ->  0x00.
    // (x | -x) has its top bit set for every non-zero x.
    let folded = difference | difference.wrapping_neg();
    (folded >> 7).wrapping_sub(1)
}

/// The same for two lengths.
///
/// A length is not attacker-chosen the way a plaintext byte is - it
/// comes from our own decryption - but it takes the same path to the
/// same answer, and a shape where one input is compared carefully and
/// another casually is a shape somebody edits into a leak.
fn ct_eq_usize(a: usize, b: usize) -> u8 {
    let difference = (a ^ b) as u64;
    let folded = difference | difference.wrapping_neg();
    ((folded >> 63) as u8).wrapping_sub(1)
}

impl EphemeralKey {
    /// The public half as a ServerKeyExchange carries it: a bare SEC1
    /// point, or 32 bytes for X25519.
    fn public_bytes(&self) -> Vec<u8> {
        self.entry().key_exchange
    }
}

/// The host name from SNI, if the client sent one.
pub(crate) fn read_server_name(hello: &ClientHello) -> Option<String> {
    let extension = find_extension(&hello.extensions, extension::SERVER_NAME)?;
    let mut reader = crate::tls::codec::Reader::new(&extension.body);
    let mut list = reader.sub16().ok()?;
    while !list.is_empty() {
        let kind = list.u8().ok()?;
        let name = list.vector16().ok()?;
        // Type 0 is host_name, and it is the only one ever defined.
        if kind == 0 {
            return core::str::from_utf8(name).ok().map(str::to_string);
        }
    }
    None
}

/// The protocol to answer with: the first of **ours** the client also
/// offered.
///
/// `Ok(None)` is "say nothing", which is what a server with no list, a
/// client with no list, and a disagreement that `require_alpn` is
/// willing to shrug at all look like on the wire.
fn choose_alpn(config: &ServerConfig, offered: &[String])
               -> Result<Option<String>, Error> {
    if config.alpn.is_empty() || offered.is_empty() {
        return Ok(None);
    }
    if let Some(chosen) = config.alpn.iter().find(|ours| offered.contains(ours)) {
        return Ok(Some(chosen.clone()));
    }
    if config.require_alpn {
        return Err(Error::new(AlertDescription::NO_APPLICATION_PROTOCOL, format!(
            "No application protocol in common. The client offered {:?} and \
             this server speaks {:?}.", offered, config.alpn)));
    }
    Ok(None)
}

/// The ALPN protocols the client offered.
fn read_alpn(hello: &ClientHello) -> Vec<String> {
    let extension = match find_extension(&hello.extensions, extension::ALPN) {
        Some(extension) => extension,
        None => return Vec::new(),
    };
    let mut reader = crate::tls::codec::Reader::new(&extension.body);
    let mut list = match reader.sub16() {
        Ok(list) => list,
        Err(_) => return Vec::new(),
    };
    let mut names = Vec::new();
    while !list.is_empty() {
        match list.vector8() {
            Ok(name) => match core::str::from_utf8(name) {
                Ok(text) => names.push(text.to_string()),
                Err(_) => return names,
            },
            Err(_) => return names,
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves;
    use crate::trust::TrustStore;
    use crate::tls::client::{ClientConfig, ClientConnection};
    use crate::x509::builder::{key_usage, CertificateBuilder, SanEntry,
                               SigningKey, SubjectKey};
    use crate::x509::oids;

    /// A root, and a leaf for `leaf.test` signed by it, on P-256.
    ///
    /// EC rather than RSA because an RSA key generation is a prime
    /// search and these run on every `cargo test`. The RSA key
    /// transport path gets its own key, once, in the test that needs it.
    struct Pki {
        root_der: Vec<u8>,
        leaf_der: Vec<u8>,
        leaf_private: BigUint,
    }

    fn pki() -> Pki {
        let curve = curves::p256();
        let (root_private, root_public) = curve.generate_key_pair().unwrap();
        let root_point = curve.encode_point(&root_public, false).unwrap();
        let (leaf_private, leaf_public) = curve.generate_key_pair().unwrap();
        let leaf_point = curve.encode_point(&leaf_public, false).unwrap();

        let mut root = CertificateBuilder::new(
            "Test Root", SubjectKey::Ec { curve: &curve, point: &root_point });
        root.is_ca = Some((true, None));
        root.key_usage = Some(key_usage::KEY_CERT_SIGN);
        let root_der = root.sign(&SigningKey::Ec { curve: &curve,
                                                   private: &root_private })
            .unwrap();

        let mut leaf = CertificateBuilder::new(
            "leaf.test", SubjectKey::Ec { curve: &curve, point: &leaf_point });
        leaf.serial = vec![2];
        leaf.issuer = vec![(oids::COMMON_NAME, "Test Root".to_string())];
        leaf.key_usage = Some(key_usage::DIGITAL_SIGNATURE);
        leaf.extended_key_usage = vec![oids::EKU_SERVER_AUTH];
        leaf.sans = vec![SanEntry::Dns("leaf.test".to_string())];
        let leaf_der = leaf.sign(&SigningKey::Ec { curve: &curve,
                                                   private: &root_private })
            .unwrap();

        Pki { root_der, leaf_der, leaf_private }
    }

    fn server_config(pki: &Pki) -> ServerConfig {
        ServerConfig::new(vec![pki.leaf_der.clone()],
                          ServerKey::Ec { curve: "P-256",
                                          private: pki.leaf_private.clone() })
    }

    fn client_config(pki: &Pki) -> ClientConfig {
        let mut store = TrustStore::new();
        store.add_der(&pki.root_der).unwrap();
        let mut config = ClientConfig::new(store, 1_700_000_000);
        // This server speaks 1.2 only, and a client that offers 1.3 has
        // to be willing to come down.
        config.max_version = Version::TLS12;
        config
    }

    /// Pump bytes between the two until neither has anything to say.
    ///
    /// Returns the number of round trips, so a test can assert the
    /// handshake did not silently stall in a state that reports
    /// neither established nor failed.
    fn pump(client: &mut ClientConnection, server: &mut ServerConnection)
            -> usize {
        for trip in 1..=12 {
            let to_server = client.take_outgoing();
            if !to_server.is_empty() {
                server.push_incoming(&to_server);
                server.process().expect("the server rejected the client");
            }
            let to_client = server.take_outgoing();
            if to_client.is_empty() && to_server.is_empty() {
                return trip;
            }
            if !to_client.is_empty() {
                client.push_incoming(&to_client);
                client.process().expect("the client rejected the server");
            }
        }
        panic!("the handshake did not settle in twelve round trips");
    }

    /// Each of RFC 9367's four suites completes a TLS 1.3 handshake.
    ///
    /// **What this settles is the wiring, and only that.** Both ends are
    /// ours, so a record layer that got MGM's counters or TLSTREE's
    /// masks wrong would pass here perfectly - the bytes are settled by
    /// `tests/test_rfc9367_flight.rs`, which replays the document's own
    /// records. What it does settle is the part no document can: that
    /// the suite reaches a real key schedule with Streebog-256 under
    /// it, that the IV comes out the cipher's block rather than twelve
    /// bytes, that `Aead13` is built with the suite's re-keying rather
    /// than without it, and that application data flows afterwards.
    ///
    /// All four, because the `_L` and `_S` forms differ only in
    /// constants this code passes around - the sort of thing that is
    /// right for the one suite anybody tested and wrong for its
    /// neighbour.
    #[test]
    fn test_the_rfc_9367_suites_complete_a_handshake() {
        use crate::tls::suites::Selection;

        for name in ["TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
                     "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
                     "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
                     "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"] {
            let pki = pki();
            let only = Selection::named(&[name]).unwrap();

            let mut config = server_config(&pki);
            config.suites = only.clone();
            let mut server = ServerConnection::new(config).unwrap();

            let mut config = client_config(&pki);
            config.max_version = Version::TLS13;
            config.min_version = Version::TLS13;
            config.suites = only;
            let mut client = ClientConnection::new(config, "leaf.test").unwrap();
            pump(&mut client, &mut server);

            assert!(client.is_established(), "{name}: client {:?}",
                    client.state());
            assert!(server.is_established(), "{name}: server {}",
                    server.state());
            assert_eq!(server.version(), Some(Version::TLS13), "{name}");
            assert_eq!(client.negotiated_suite().map(|s| s.name), Some(name),
                       "{name}");

            // And data flows, which is the only thing that says the
            // *application* keys were derived the same way at both ends
            // - the handshake completes on the handshake keys alone.
            server.write(b"from the server").unwrap();
            client.push_incoming(&server.take_outgoing());
            client.process().unwrap();
            assert_eq!(client.take_incoming(), b"from the server", "{name}");

            client.write(b"from the client").unwrap();
            server.push_incoming(&client.take_outgoing());
            server.process().unwrap();
            assert_eq!(server.take_incoming(), b"from the client", "{name}");
        }
    }

    /// Our client and our server complete a **TLS 1.3** handshake.
    ///
    /// Same caveat as the 1.2 version below: both ends are ours, so this
    /// settles the wiring and nothing about the bytes. The four transcript
    /// hashes in `server13::send_flight` could all be wrong in the same way
    /// and this would pass. `pytests/test_tls13_server.py` drives a real
    /// OpenSSL client, which is the only thing that can say otherwise.
    #[test]
    fn test_tls13_handshake_with_our_own_client() {
        let pki = pki();
        let mut server = ServerConnection::new(server_config(&pki)).unwrap();
        let mut config = client_config(&pki);
        config.max_version = Version::TLS13;
        config.min_version = Version::TLS12;
        let mut client = ClientConnection::new(config, "leaf.test").unwrap();
        pump(&mut client, &mut server);

        assert!(client.is_established(), "client: {:?}", client.state());
        assert!(server.is_established(), "server: {}", server.state());
        assert_eq!(server.version(), Some(Version::TLS13));

        server.write(b"from the server").unwrap();
        client.push_incoming(&server.take_outgoing());
        client.process().unwrap();
        assert_eq!(client.take_incoming(), b"from the server");

        client.write(b"from the client").unwrap();
        server.push_incoming(&client.take_outgoing());
        server.process().unwrap();
        assert_eq!(server.take_incoming(), b"from the client");
    }

    /// A server that issues tickets, with a shared key and a clock.
    fn resuming_config(pki: &Pki, now: i64) -> ServerConfig {
        let mut config = server_config(pki);
        config.now = now;
        config.session_tickets = 2;
        config.ticket_key = Some(Arc::new(
            crate::tls::tickets::TicketKey::from_bytes(
                &(0..crate::tls::tickets::TicketKey::byte_length() as u8)
                    .collect::<Vec<u8>>()).unwrap()));
        config
    }

    fn resuming_client(pki: &Pki, now: i64) -> ClientConfig {
        let mut config = client_config(pki);
        config.max_version = Version::TLS13;
        config.min_version = Version::TLS13;
        config.policy.now = now;
        config
    }

    /// One connection that collects tickets, then one that offers them
    /// back with early data.
    ///
    /// **Both ends are ours, so this settles the wiring and nothing
    /// else** - the early traffic secret could be derived over the wrong
    /// transcript at both ends and they would agree perfectly.
    /// `pytests/test_tls13_early_data.py` drives the real `openssl`
    /// binary, which is the only thing that can say otherwise. What this
    /// covers is the part a real peer cannot reach easily: the writer
    /// changing keys three times in the right order, and the server's
    /// held-back handshake keys.
    #[test]
    fn test_early_data_between_our_own_ends() {
        let now = 1_700_000_000;
        let pki = pki();
        let mut server = ServerConnection::new(resuming_config(&pki, now)).unwrap();
        let mut client = ClientConnection::new(resuming_client(&pki, now),
                                               "leaf.test").unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_established());
        // The tickets arrive under the application keys, which means
        // after the handshake, which means a read.
        let tickets = client.take_tickets();
        assert!(!tickets.is_empty(), "no tickets were issued");
        assert_eq!(tickets[0].max_early_data, None,
                   "a server with max_early_data unset must offer none");

        // Now with early data switched on at both ends.
        let mut config = resuming_config(&pki, now);
        config.max_early_data = 16_384;
        let mut server = ServerConnection::new(config).unwrap();
        let mut client = ClientConnection::new(resuming_client(&pki, now),
                                               "leaf.test").unwrap();
        pump(&mut client, &mut server);
        let tickets = client.take_tickets();
        assert_eq!(tickets[0].max_early_data, Some(16_384));

        let mut config = resuming_config(&pki, now);
        config.max_early_data = 16_384;
        let mut server = ServerConnection::new(config).unwrap();
        let mut resuming = resuming_client(&pki, now);
        resuming.tickets = tickets;
        resuming.early_data = b"GET /early".to_vec();
        let mut client = ClientConnection::new(resuming, "leaf.test").unwrap();
        pump(&mut client, &mut server);

        assert!(client.is_established(), "client: {:?}", client.state());
        assert!(server.is_established(), "server: {}", server.state());
        assert!(client.early_data_accepted(), "the server declined");
        assert!(server.accepted_early_data());
        assert_eq!(server.take_early_data(), b"GET /early");
        // And it is *not* in the ordinary stream, which is the whole
        // reason it has its own accessor.
        assert!(server.take_incoming().is_empty());

        // The connection still works afterwards, which is what says the
        // writer's three key changes landed in the right order.
        client.write(b"and the rest").unwrap();
        server.push_incoming(&client.take_outgoing());
        server.process().unwrap();
        assert_eq!(server.take_incoming(), b"and the rest");
    }

    /// A server that does not offer early data still completes the
    /// handshake with a client that tried.
    ///
    /// **This is the case that needs the skip.** The client has already
    /// written those records under keys the server never derived, so the
    /// server has to discard them rather than fail (RFC 8446 4.2.10) -
    /// and, less obviously, a discarded record must not advance the
    /// reader's sequence number, or the client's real Finished decrypts
    /// under the wrong nonce.
    #[test]
    fn test_rejected_early_data_still_connects() {
        let now = 1_700_000_000;
        let pki = pki();
        let mut config = resuming_config(&pki, now);
        config.max_early_data = 16_384;
        let mut server = ServerConnection::new(config).unwrap();
        let mut client = ClientConnection::new(resuming_client(&pki, now),
                                               "leaf.test").unwrap();
        pump(&mut client, &mut server);
        let tickets = client.take_tickets();

        // The second server does not take early data at all, which is
        // what a restart with a changed configuration looks like.
        let mut server = ServerConnection::new(resuming_config(&pki, now)).unwrap();
        let mut resuming = resuming_client(&pki, now);
        resuming.tickets = tickets;
        resuming.early_data = b"GET /early".to_vec();
        let mut client = ClientConnection::new(resuming, "leaf.test").unwrap();
        pump(&mut client, &mut server);

        assert!(client.is_established(), "client: {:?}", client.state());
        assert!(server.is_established(), "server: {}", server.state());
        assert!(!client.early_data_accepted());
        assert!(!server.accepted_early_data());
        assert!(server.take_early_data().is_empty());

        // And the bytes are *not* resent for us. The caller decides.
        client.write(b"GET /early").unwrap();
        server.push_incoming(&client.take_outgoing());
        server.process().unwrap();
        assert_eq!(server.take_incoming(), b"GET /early");
    }

    /// The same flight twice is accepted once.
    ///
    /// Bytes for bytes: the second connection is fed the *recorded*
    /// output of the first, which is what a replay is. A fresh client
    /// offering the same ticket honestly has a different binder and is
    /// not affected.
    #[test]
    fn test_the_replay_guard_refuses_a_repeated_flight() {
        let now = 1_700_000_000;
        let pki = pki();
        let guard = Arc::new(Mutex::new(
            crate::tls::tickets::ReplayGuard::with_capacity(16)));
        let early_config = |pki: &Pki| {
            let mut config = resuming_config(pki, now);
            config.max_early_data = 16_384;
            config.replay_guard = Some(Arc::clone(&guard));
            config
        };

        let mut server = ServerConnection::new(early_config(&pki)).unwrap();
        let mut client = ClientConnection::new(resuming_client(&pki, now),
                                               "leaf.test").unwrap();
        pump(&mut client, &mut server);
        let tickets = client.take_tickets();

        // The 0-RTT flight, recorded as it goes out.
        let mut resuming = resuming_client(&pki, now);
        resuming.tickets = tickets;
        resuming.early_data = b"POST /pay".to_vec();
        let mut client = ClientConnection::new(resuming, "leaf.test").unwrap();
        let flight = client.take_outgoing();

        let mut first = ServerConnection::new(early_config(&pki)).unwrap();
        first.push_incoming(&flight);
        first.process().unwrap();
        assert!(first.accepted_early_data());
        assert_eq!(first.take_early_data(), b"POST /pay");

        // The identical bytes again, to a second connection sharing the
        // register. The handshake is still answered - a full one is
        // always a correct answer to a 0-RTT attempt, and refusing
        // loudly would tell an attacker the replay reached a machine
        // that remembers.
        let mut second = ServerConnection::new(early_config(&pki)).unwrap();
        second.push_incoming(&flight);
        second.process().unwrap();
        assert!(!second.accepted_early_data(), "the replay was accepted");
        assert!(second.take_early_data().is_empty());
    }

    /// A client whose only key share is in a group the server does not
    /// prefer gets one HelloRetryRequest and then succeeds.
    ///
    /// The transcript surgery RFC 8446 4.4.1 requires - the first hello
    /// replaced by a synthetic `message_hash` - is what this exercises, and
    /// getting it wrong shows up only at the Finished.
    #[test]
    fn test_tls13_hello_retry_request() {
        let pki = pki();
        let mut config = server_config(&pki);
        config.max_version = Version::TLS13;
        let mut server = ServerConnection::new(config).unwrap();
        let mut client_config = client_config(&pki);
        client_config.max_version = Version::TLS13;
        let mut client = ClientConnection::new(client_config, "leaf.test").unwrap();
        let trips = pump(&mut client, &mut server);

        assert!(client.is_established(), "client: {:?}", client.state());
        assert!(server.is_established(), "server: {}", server.state());
        assert_eq!(server.version(), Some(Version::TLS13));
        assert!(trips >= 2, "a retry takes an extra round trip, got {}", trips);
    }

    /// Our client and our server complete a handshake and exchange data.
    ///
    /// This settles the *wiring* - directions, ordering, which key comes
    /// from where - and nothing else. Both ends are ours, so a byte
    /// order that is wrong in the same way twice agrees with itself
    /// perfectly. Only OpenSSL can say whether the bytes are right,
    /// which is what `pytests/test_tls_server.py` is for.
    #[test]
    fn test_our_client_and_our_server_agree() {
        let pki = pki();
        let mut server = ServerConnection::new(server_config(&pki)).unwrap();
        let mut client = ClientConnection::new(client_config(&pki),
                                               "leaf.test").unwrap();
        pump(&mut client, &mut server);

        assert!(client.is_established(), "client: {:?}", client.state());
        assert!(server.is_established(), "server: {}", server.state());
        assert_eq!(server.version(), Some(Version::TLS12));
        assert_eq!(server.server_name(), Some("leaf.test"));

        // Application data in both directions, on keys derived
        // independently at each end.
        server.write(b"from the server").unwrap();
        client.push_incoming(&server.take_outgoing());
        client.process().unwrap();
        assert_eq!(client.take_incoming(), b"from the server");

        client.write(b"from the client").unwrap();
        server.push_incoming(&client.take_outgoing());
        server.process().unwrap();
        assert_eq!(server.take_incoming(), b"from the client");
    }

    /// The suite comes from the *server's* list, in the server's order.
    #[test]
    fn test_the_server_order_decides() {
        let pki = pki();
        let mut config = server_config(&pki);
        config.suites = Selection::named(&["ECDHE-ECDSA-AES128-GCM-SHA256"])
            .unwrap();
        let mut server = ServerConnection::new(config).unwrap();
        let mut client = ClientConnection::new(client_config(&pki),
                                               "leaf.test").unwrap();
        pump(&mut client, &mut server);
        assert!(server.is_established(), "server: {}", server.state());
        assert_eq!(server.negotiated_suite().map(|s| s.openssl_name),
                   Some("ECDHE-ECDSA-AES128-GCM-SHA256"));
        assert_eq!(client.negotiated_suite().map(|s| s.openssl_name),
                   Some("ECDHE-ECDSA-AES128-GCM-SHA256"));
    }

    /// A client with nothing in common is refused with a handshake
    /// failure rather than a panic or a silent downgrade.
    #[test]
    fn test_no_suite_in_common_is_a_handshake_failure() {
        let pki = pki();
        let mut config = server_config(&pki);
        config.suites = Selection::named(&["ECDHE-ECDSA-AES128-GCM-SHA256"])
            .unwrap();
        let mut server = ServerConnection::new(config).unwrap();

        let mut client_config = client_config(&pki);
        client_config.suites =
            Selection::named(&["ECDHE-ECDSA-AES256-GCM-SHA384"]).unwrap();
        let mut client = ClientConnection::new(client_config,
                                               "leaf.test").unwrap();

        server.push_incoming(&client.take_outgoing());
        let error = server.process().unwrap_err();
        assert_eq!(error.alert, Some(AlertDescription::HANDSHAKE_FAILURE));
        // And the alert actually went out, so the client is not left
        // waiting on a server that has given up.
        assert!(!server.take_outgoing().is_empty(),
                "the server failed without telling the client");
    }

    /// A server with an EC key must not choose an RSA suite, whatever
    /// the client offered: there is no key for it.
    #[test]
    fn test_a_key_that_cannot_authenticate_a_suite_is_not_chosen() {
        let pki = pki();
        let mut config = server_config(&pki);
        config.suites = Selection::all();
        let mut server = ServerConnection::new(config).unwrap();
        let mut client = ClientConnection::new(client_config(&pki),
                                               "leaf.test").unwrap();
        pump(&mut client, &mut server);
        let suite = server.negotiated_suite().expect("no suite was chosen");
        assert_eq!(suite.key_exchange, KeyExchange::EcdheEcdsa,
                   "an EC key authenticated {:?}", suite.key_exchange);
    }

    /// A server with no certificate is refused at construction, not at
    /// the first handshake.
    #[test]
    fn test_a_server_without_a_certificate_is_refused() {
        let pki = pki();
        let config = ServerConfig::new(
            vec![], ServerKey::Ec { curve: "P-256",
                                    private: pki.leaf_private.clone() });
        assert!(ServerConnection::new(config).is_err());
    }

    /// The masks are masks: 0xff or 0x00 and nothing between.
    ///
    /// A helper that returned 1 instead of 0xff would make the select
    /// below keep one bit of each byte and zero the other seven, which
    /// produces a premaster that is wrong in a way no test of the
    /// happy path can see - the happy path never takes the fallback.
    #[test]
    fn test_the_constant_time_masks_are_all_or_nothing() {
        assert_eq!(ct_eq_u8(0, 0), 0xff);
        assert_eq!(ct_eq_u8(0x03, 0x03), 0xff);
        assert_eq!(ct_eq_u8(0xff, 0xff), 0xff);
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let expected = if a == b { 0xff } else { 0x00 };
                assert_eq!(ct_eq_u8(a, b), expected, "ct_eq_u8({}, {})", a, b);
            }
        }
        assert_eq!(ct_eq_usize(48, 48), 0xff);
        assert_eq!(ct_eq_usize(0, 48), 0x00);
        assert_eq!(ct_eq_usize(47, 48), 0x00);
        assert_eq!(ct_eq_usize(49, 48), 0x00);
        assert_eq!(ct_eq_usize(usize::MAX, 48), 0x00);
        assert_eq!(ct_eq_usize(0, 0), 0xff);
    }

    /// A premaster with the wrong version in it is replaced, silently.
    ///
    /// RFC 5246 7.4.7.1. The two bytes are the version the client
    /// **offered**, and a mismatch means somebody forced the version
    /// down between the hello and here. The server must not say so -
    /// saying so is Bleichenbacher's oracle - so the evidence is that
    /// the premaster it continues with is not the one that arrived.
    #[test]
    fn test_a_premaster_with_the_wrong_version_is_replaced() {
        let key = rsa::RsaPrivateKey::generate(1024).unwrap();
        let public = key.public_key();
        let mut config = ServerConfig::new(vec![vec![0x30, 0x00]],
                                           ServerKey::Rsa(Box::new(key)));
        config.suites = Selection::all();
        let mut server = ServerConnection::new(config).unwrap();
        server.offered_version = Version::TLS12;

        // The right version: the premaster comes back untouched.
        let mut good = vec![0x03, 0x03];
        good.extend_from_slice(&[0x41u8; 46]);
        let encrypted = rsa::encrypt_pkcs1v15(&public, &good).unwrap();
        assert_eq!(server.decrypt_premaster(&encrypted, random::bytes(48).unwrap()), good);

        // One byte of the version wrong: something else comes back.
        let mut rolled_back = vec![0x03, 0x01];
        rolled_back.extend_from_slice(&[0x41u8; 46]);
        let encrypted = rsa::encrypt_pkcs1v15(&public, &rolled_back).unwrap();
        let answer = server.decrypt_premaster(&encrypted, random::bytes(48).unwrap());
        assert_eq!(answer.len(), 48);
        assert_ne!(answer, rolled_back,
                   "a rolled-back version was accepted");
    }

    /// Every failure produces 48 bytes, and two failures produce
    /// *different* 48 bytes.
    ///
    /// A fixed fallback would be worse than none: the attacker learns
    /// nothing from one connection but everything from two, because
    /// the same wrong premaster gives the same Finished.
    #[test]
    fn test_every_failing_premaster_is_forty_eight_fresh_bytes() {
        let key = rsa::RsaPrivateKey::generate(1024).unwrap();
        let public = key.public_key();
        let config = ServerConfig::new(vec![vec![0x30, 0x00]],
                                       ServerKey::Rsa(Box::new(key)));
        let server = ServerConnection::new(config).unwrap();

        let cases: Vec<Vec<u8>> = vec![
            // Not a valid ciphertext at all.
            vec![0x00; 128],
            // Valid PKCS#1, wrong length inside.
            rsa::encrypt_pkcs1v15(&public, &[0x41u8; 16]).unwrap(),
            rsa::encrypt_pkcs1v15(&public, &[0x41u8; 47]).unwrap(),
            // Valid PKCS#1, right length, wrong version.
            rsa::encrypt_pkcs1v15(&public, &[0x41u8; 48]).unwrap(),
        ];
        let mut seen = Vec::new();
        for ciphertext in &cases {
            // A failure returns exactly the fallback it was handed, which
            // the caller draws fresh for every ClientKeyExchange.
            let fallback = random::bytes(48).unwrap();
            let first = server.decrypt_premaster(ciphertext, fallback.clone());
            assert_eq!(first, fallback);
            let second = server.decrypt_premaster(ciphertext, random::bytes(48).unwrap());
            assert_eq!(first.len(), 48);
            assert_ne!(first, second,
                       "the fallback premaster repeats, so two failed \
                        handshakes give the same Finished");
            seen.push(first);
        }
        // And no two of them collide either.
        for (i, a) in seen.iter().enumerate() {
            for b in seen.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    /// Garbage never panics, whatever it is.
    #[test]
    fn test_garbage_never_panics() {
        let pki = pki();
        for seed in 0..200u32 {
            let mut server =
                ServerConnection::new(server_config(&pki)).unwrap();
            let bytes: Vec<u8> = (0..200u32)
                .map(|i| ((i * 37 + seed * 11) & 0xff) as u8).collect();
            server.push_incoming(&bytes);
            let _ = server.process();
        }
    }
}
