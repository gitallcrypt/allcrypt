/*
The TLS 1.3 half of the server.

Separate from `server.rs` for the same reason `keys13.rs` is separate from
`keys.rs`: the two handshakes share no step. There is no ServerKeyExchange,
no ChangeCipherSpec that means anything, no master secret derived from a
premaster, and the server's signature covers a transcript hash rather than
the two randoms. A version flag inside the 1.2 code would be a machine that
accepts messages from both, which is what this file exists not to be.

The flight is written in one go, which is the shape of 1.3: everything from
the ServerHello to the server's Finished goes out before the client has said
anything more, and only the Finished comes back. So `send_flight` below is
almost the whole handshake, and the state machine afterwards has one state
in it.

**Three things here are easy to get wrong and silent when wrong.**

  * The transcript hash is taken at four different points and they are all
    different: through the ServerHello for the handshake keys, through the
    Certificate for the CertificateVerify signature, through the
    CertificateVerify for the server's Finished, and through the server's
    Finished for the application keys. Any two of those swapped gives a
    schedule that agrees with itself and with nobody else.
  * The keys go on the *opposite* sides from the client. The client's
    traffic keys protect our reader; ours protect our writer.
  * The suite no longer names a key exchange or an authentication method.
    `KeyExchange::EcdheRsa` in the 1.3 rows of the suite table is a
    placeholder to satisfy the type, and consulting it - as `choose_suite`
    does at 1.2, quite correctly - would refuse every 1.3 handshake made
    with an EC key. What authenticates is the signature scheme, chosen from
    `signature_algorithms`.
*/

use crate::hash_functions::HashFunction;
use crate::tls::client::Error;
use crate::tls::handshake::{extension, find_extension, ClientHello, Extension,
                            Finished, HandshakeMessage, HandshakeType, ServerHello,
                            SignatureScheme};
use crate::tls::handshake13::{self as hs13, scheme, Certificate13, CertificateEntry,
                              CertificateVerify, EncryptedExtensions, KeyShareEntry,
                              Side13};
use crate::tls::kex::EphemeralKey;
use crate::tls::keys::Transcript;
use crate::tls::keys13::{self, Schedule, TrafficKeys};
use crate::tls::record::{Protection, RecordReader, RecordWriter};
use crate::tls::record13::Aead13;
use crate::tls::suites::CipherSuite;
use crate::tls::{AlertDescription, ContentType, Version};

use super::server::{ServerConfig, ServerKey};

/// The signature schemes this server will **verify** in a client
/// CertificateVerify.
///
/// Not the same list as what it can sign with: a server holding an EC key
/// verifies an RSA client certificate perfectly well, and the two lists
/// being the same is a mistake that only shows up with a mismatched pair.
pub const VERIFIABLE: &[u16] = &[
    scheme::ECDSA_SECP256R1_SHA256,
    scheme::ECDSA_SECP384R1_SHA384,
    scheme::ECDSA_SECP521R1_SHA512,
    scheme::RSA_PSS_RSAE_SHA256,
    scheme::RSA_PSS_RSAE_SHA384,
    scheme::RSA_PSS_RSAE_SHA512,
    // Both EdDSA schemes. OpenSSL issues and signs with Ed448
    // certificates; an earlier comment here said nothing did.
    scheme::ED25519,
    scheme::ED448,
    scheme::MLDSA44,
    scheme::MLDSA65,
    scheme::MLDSA87,
];

/// The schemes to ask a client for, which depends on the suite.
///
/// **RFC 9367's schemes are added only under an RFC 9367 suite**, mirroring
/// the client's rule that a GOST scheme is offered only when a GOST suite
/// is - `suites::Selection::offers_gost_13`. The verification itself does
/// not care: a Streebog digest and a GOST curve work whatever the record
/// layer is. The reason is that a scheme asked for with no suite that pairs
/// with it is a row nothing checks, and a client that took the invitation
/// would be authenticating with an algorithm the rest of the handshake
/// never uses.
///
/// Found by `tests/test_gost_13_signature.rs`: a GOST client certificate
/// could not be used at all, because this list had no GOST scheme in it and
/// the client correctly declined to sign with something the server had not
/// asked for. The server verified nothing and said nothing - the refusal
/// came from the other end.
pub fn verifiable_for(suite: &CipherSuite) -> Vec<u16> {
    let mut schemes = VERIFIABLE.to_vec();
    // The four RFC 9367 suites are exactly the 1.3 suites whose PRF is
    // Streebog, which is what identifies them without a second list to
    // keep in step.
    if suite.prf == crate::tls::suites::MacAlgorithm::Streebog256
        && suite.min_version == Version::TLS13 {
        schemes.extend_from_slice(scheme::GOST_13);
    }
    schemes
}

/// The groups this server will use a key share from, in its own order of
/// preference. A client that sent a share for none of them gets a
/// HelloRetryRequest naming the first one it said it supported.
pub const OURS: &[u16] = &[
    // The hybrid post-quantum groups first: a client that offers one has
    // said it wants protection against a future quantum adversary, and a
    // share for it is already in hand - no extra round trip. X25519MLKEM768
    // leads them because it is the one clients send a share for.
    crate::tls::handshake::groups::X25519_MLKEM768,
    crate::tls::handshake::groups::SECP384R1_MLKEM1024,
    crate::tls::handshake::groups::SECP256R1_MLKEM768,
    crate::tls::handshake::groups::X25519,
    crate::tls::handshake::groups::SECP256R1,
    crate::tls::handshake::groups::SECP384R1,
    crate::tls::handshake::groups::SECP521R1,
    // Last for cost rather than strength - see `server::choose_group`.
    // Accepted so that a client offering only X448 is answered.
    crate::tls::handshake::groups::X448,
];

/// Everything that only exists once 1.3 has been negotiated.
pub struct Tls13 {
    pub schedule: Schedule,
    pub hash: &'static str,
    /// The AEAD's name, its key, IV and tag lengths, and RFC 9367's
    /// re-keying if the suite has it, as one value.
    pub aead: hs13::Tls13Aead,
    /// The key the *client* will use for its Finished, kept so it can be
    /// checked when that message arrives.
    pub client_finished_key: Vec<u8>,
    /// The client's application traffic keys, derived at the same moment as
    /// ours but installed later - the client's Finished is still protected
    /// under the handshake keys, so the reader cannot move until it has
    /// arrived and been checked.
    pub client_application: Option<TrafficKeys>,
    /// The negotiated suite's code, for the tickets issued afterwards: a
    /// ticket belongs to a suite and must be refused against another.
    pub suite: u16,
    /// The suite's PRF, likewise.
    pub prf: crate::tls::suites::MacAlgorithm,
    /// Whether this handshake resumed. A resumed one sends no Certificate
    /// and no CertificateVerify, which is most of what makes it cheap.
    pub resumed: bool,
    /// Whether a CertificateRequest went out, and so whether a Certificate
    /// is expected back before the client's Finished.
    pub requested_client_certificate: bool,
    /// How much early data this handshake accepted, if it accepted any.
    pub early_data: Option<u32>,
    /// The client's handshake traffic keys, **held back** while early data
    /// is being read and installed at EndOfEarlyData.
    ///
    /// `None` is the ordinary handshake, where they went on the reader
    /// immediately. Holding them here rather than re-deriving later is
    /// deliberate: re-deriving needs the transcript hash through the
    /// ServerHello, which has long since moved on.
    pub client_handshake: Option<crate::tls::keys13::TrafficKeys>,
    /// How much early data has arrived, against the accepted limit. A
    /// client that sends more is refused rather than truncated: the limit
    /// is the server's promise about how much it will process, and
    /// silently dropping the rest is a connection that half happened.
    pub early_bytes: u32,
}

/// What `prepare` worked out from the ClientHello, before anything is sent.
pub struct Negotiated {
    pub suite: &'static CipherSuite,
    pub group: u16,
    pub shared: Vec<u8>,
    pub ours: KeyShareEntry,
    pub session_id: Vec<u8>,
    pub scheme: u16,
    /// The accepted pre-shared key, if the client offered one that worked:
    /// the index to echo in the ServerHello, and the PSK itself.
    ///
    /// `None` is a full handshake, which is also what every *failed* offer
    /// becomes - a rejected ticket is never reported as an error, because
    /// "that one was almost right" is information.
    pub psk: Option<(u16, Vec<u8>)>,
    /// How many bytes of early data this handshake will accept, if it
    /// accepted any.
    ///
    /// `None` covers both "the client offered none" and "it offered some
    /// and we declined", which are the same thing on the wire: the server
    /// simply does not echo `early_data`, and the client resends. There
    /// is no way to decline with a reason and there should not be - every
    /// reason is something about the ticket.
    pub early_data: Option<u32>,
}

/// The certificate entries for a TLS 1.3 Certificate message.
///
/// **The staple hangs off the leaf, not off the connection.** At TLS 1.2
/// it is a message of its own, which implicitly means "the certificate
/// you are about to see"; at 1.3 it is an extension on a certificate
/// entry (RFC 8446 4.4.2.1), and there is one entry per certificate.
/// Only the leaf gets one, because a response about an intermediate
/// answers a different question and this server was not given an answer
/// to it.
///
/// A function of its own so that "only the leaf" can be checked by a
/// test: from the wire, a client reads the leaf's and a staple on every
/// entry looks exactly the same.
fn certificate_entries(chain: &[Vec<u8>], staple: Option<&[u8]>)
                       -> Result<Vec<CertificateEntry>, Error> {
    let body = match staple {
        Some(response) =>
            Some(crate::tls::handshake::encode_certificate_status(response)?),
        None => None,
    };
    Ok(chain.iter().enumerate().map(|(index, der)| CertificateEntry {
        certificate: der.clone(),
        extensions: match (index, &body) {
            (0, Some(body)) => vec![Extension {
                kind: extension::STATUS_REQUEST,
                body: body.clone(),
            }],
            _ => Vec::new(),
        },
    }).collect())
}

/// The AEAD's name, lengths and re-keying, from a 1.3 suite.
pub fn aead_of(suite: &CipherSuite) -> Result<hs13::Tls13Aead, Error> {
    hs13::tls13_aead(suite).map_err(Error::local)
}

/// The handshake hash for a 1.3 suite, which is also its PRF.
pub fn hash_of(suite: &CipherSuite) -> Result<&'static str, Error> {
    hs13::tls13_hash(suite).map_err(Error::local)
}

/// Pick the suite, the group and the signature scheme, and do the key
/// exchange. Nothing is written here, so a caller can still decide to send
/// a HelloRetryRequest instead.
///
/// `Err` with `HANDSHAKE_FAILURE` means no suite or no scheme in common;
/// `Ok(None)` means the client supports a group we like but did not send a
/// share for it, which is a retry rather than a failure.
pub fn prepare(config: &ServerConfig, hello: &ClientHello,
               resumption: Option<&Resumption<'_>>)
               -> Result<Option<Negotiated>, Error> {
    let suite = choose_suite(config, hello)?;
    // A resumed handshake authenticates with the PSK and sends no
    // certificate, so it needs no signature scheme. Demanding one would
    // refuse a client that offered only schemes this key cannot make - and
    // a resumption does not need it to.
    let accepted = match resumption {
        Some(resumption) => accept_psk(hello, suite, resumption)?,
        None => None,
    };
    let early_data = match (&accepted, resumption) {
        (Some(accepted), Some(resumption)) =>
            decide_early_data(config, hello, accepted, resumption),
        _ => None,
    };
    let psk = accepted.map(|accepted| (accepted.index, accepted.psk));
    let scheme = match psk {
        Some(_) => 0,
        None => choose_scheme(config, hello)?,
    };

    // The client's shares, in *our* order of preference rather than theirs:
    // which group is used is the server's choice, and a client that offers
    // several has said it is content with any of them.
    let shares = match find_extension(&hello.extensions, extension::KEY_SHARE) {
        Some(extension) => hs13::parse_client_key_share(&extension.body)?,
        None => return Err(Error::new(AlertDescription::MISSING_EXTENSION,
                                      "A TLS 1.3 ClientHello must carry key_share.")),
    };
    for group in OURS {
        let theirs = match shares.iter().find(|entry| entry.group == *group) {
            Some(entry) => entry,
            None => continue,
        };
        // A share whose point is not on the curve, or is the identity - or,
        // for a hybrid group, whose ML-KEM key fails FIPS 203's modulus
        // check or whose length is wrong - fails here, which is the only
        // place it can, so the error is an alert about the peer's
        // parameter rather than a local one.
        let (ours, shared) = EphemeralKey::respond(*group, &theirs.key_exchange)
            .map_err(|e| Error::new(AlertDescription::ILLEGAL_PARAMETER, e))?;
        return Ok(Some(Negotiated {
            suite,
            group: *group,
            shared,
            ours,
            session_id: hello.session_id.clone(),
            scheme,
            psk,
            early_data,
        }));
    }
    Ok(None)
}

/// What `prepare` needs to consider a client's PSK offer.
pub struct Resumption<'a> {
    pub key: &'a crate::tls::tickets::TicketKey,
    /// What the 1.3 transcript starts with before this ClientHello: empty
    /// normally, and `message_hash || HelloRetryRequest` after a retry. The
    /// binder covers all of it.
    pub prefix: &'a [u8],
    /// This ClientHello exactly as it arrived, binders included.
    pub hello_bytes: &'a [u8],
    pub now: i64,
}

/// Resolve the client's `pre_shared_key`, if it sent one.
///
/// Every failure is `Ok(None)` - a full handshake - rather than an error.
/// A client whose ticket has expired, or which was issued by another server,
/// or whose binder does not check out, gets a handshake rather than an
/// alert, and learns nothing about which of those it was.
pub struct AcceptedPsk {
    pub index: u16,
    pub psk: Vec<u8>,
    /// The binder that proved it, kept because that is what the replay
    /// register keys on: the same ticket used honestly twice has two
    /// binders, and only a byte-for-byte replay of a hello repeats one.
    pub binder: Vec<u8>,
    pub session: crate::tls::tickets::Session,
    /// The `obfuscated_ticket_age` the client sent with this identity,
    /// for the early-data age check: the age it reports, with
    /// `age_add` still in it.
    pub obfuscated_ticket_age: u32,
}

/// How far the client's reported ticket age may differ from the ticket's
/// actual age before early data is refused, in milliseconds.
///
/// RFC 8446 4.2.10 and 8.3: the reported age is checked against the
/// server's own record so that a captured 0-RTT flight can only be
/// replayed within this window rather than within the ticket's whole
/// lifetime (up to seven days). The window has to absorb the round trip
/// the ticket took to reach the client, the client's clock drifting from
/// the server's, and the time the flight spent in transit; ten seconds
/// is the usual allowance and far below what makes a replay useful.
pub const EARLY_DATA_AGE_TOLERANCE_MS: u64 = 10_000;

fn accept_psk(hello: &ClientHello, suite: &'static CipherSuite,
              resumption: &Resumption<'_>) -> Result<Option<AcceptedPsk>, Error> {
    let offer = match find_extension(&hello.extensions, extension::PRE_SHARED_KEY) {
        Some(extension) => hs13::OfferedPsks::parse(&extension.body)?,
        None => return Ok(None),
    };
    // **`pre_shared_key` must be the last extension** (RFC 8446 4.2.11),
    // because the binder covers the hello up to itself. If it is not last,
    // the truncation below would cut the wrong bytes - so refuse rather
    // than compute a binder over something else.
    if hello.extensions.last().map(|e| e.kind) != Some(extension::PRE_SHARED_KEY) {
        return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
            "pre_shared_key must be the last extension in a ClientHello: the \
             binder covers everything before it."));
    }
    // The client must be willing to do a key exchange as well. We never
    // offer PSK-only resumption, because it has no forward secrecy.
    let modes = match find_extension(&hello.extensions,
                                     extension::PSK_KEY_EXCHANGE_MODES) {
        Some(extension) => hs13::parse_psk_key_exchange_modes(&extension.body)?,
        None => return Ok(None),
    };
    if !modes.contains(&hs13::psk_mode::DHE_KE) {
        return Ok(None);
    }

    let hash = hash_of(suite)?;
    let truncated = crate::tls::tickets::truncated_hash(
        hash, resumption.prefix, resumption.hello_bytes, offer.binders_length())
        .map_err(Error::local)?;
    Ok(crate::tls::tickets::accept(resumption.key, &offer, suite.code, suite.prf,
                                   &truncated, resumption.now)
        .map(|accepted| AcceptedPsk {
            binder: offer.binders[accepted.index as usize].clone(),
            obfuscated_ticket_age:
                offer.identities[accepted.index as usize].obfuscated_ticket_age,
            index: accepted.index,
            psk: accepted.session.psk.clone(),
            session: accepted.session,
        }))
}

/// Whether to accept early data, and how much.
///
/// Seven conditions, and every one of them is a way for early data to be
/// accepted into the wrong context. They are listed here rather than
/// spread over the handshake because each one on its own looks like a
/// formality.
fn decide_early_data(config: &ServerConfig, hello: &ClientHello,
                     accepted: &AcceptedPsk, resumption: &Resumption<'_>)
                     -> Option<u32> {
    // 1. This server offers it at all.
    if config.max_early_data == 0 {
        return None;
    }
    // 2. The client asked. In a ClientHello the extension is empty - the
    //    `max_early_data_size` form belongs to a NewSessionTicket only.
    let asked = find_extension(&hello.extensions, extension::EARLY_DATA)?;
    if !asked.body.is_empty() {
        return None;
    }
    // 3. **The first identity, and only the first.** RFC 8446 4.2.10
    //    binds early data to `identities[0]`, because the keys come from
    //    that PSK and the client derived them before hearing anything
    //    back. Accepting it for a later identity decrypts the flight with
    //    a key the client did not use, which fails - but a server that
    //    tried the right key for the wrong identity would succeed, and be
    //    accepting data the client meant for a different session.
    if accepted.index != 0 {
        return None;
    }
    // 4. The ticket allows it. The number the client was told is not the
    //    check: the sealed copy is, because the client's copy is a number
    //    we handed out and can no longer see.
    if accepted.session.max_early_data == 0 {
        return None;
    }
    // 5. **The same server name.** Early data is sent before anything is
    //    negotiated, so the only thing that can say what it was for is
    //    what the previous connection settled. Without this, a ticket for
    //    one virtual host replays its early data into another.
    let now_name = crate::tls::server::read_server_name(hello).unwrap_or_default();
    if now_name.as_bytes() != accepted.session.server_name.as_slice() {
        return None;
    }
    // 6. **No HelloRetryRequest.** A non-empty prefix means the transcript
    //    starts with a synthetic `message_hash`, which means we have
    //    already sent a message - and RFC 8446 4.2.10 says a server that
    //    sends one must reject early data. The client's early keys were
    //    derived over the *first* hello and it has stopped sending under
    //    them.
    if !resumption.prefix.is_empty() {
        return None;
    }
    // 7. **The ticket is as old as the client says it is.** The client
    //    reports the ticket's age in milliseconds plus `age_add`; the
    //    sealed copy says when it was issued. A flight whose reported age
    //    is far from the real one is a replay from another time, or a
    //    clock nobody should trust early data to - and without this the
    //    replay window is the ticket's whole lifetime. The PSK is still
    //    accepted for the ordinary handshake: the age says nothing about
    //    who holds it, only about when this flight was made.
    if !reported_age_is_fresh(accepted, resumption.now) {
        return None;
    }
    // 8. This exact flight has not been accepted before. A repeat gets a
    //    normal 1-RTT handshake, which is always a correct answer to a
    //    0-RTT attempt - not an alert, because refusing loudly tells an
    //    attacker their replay arrived at a machine that remembers.
    if let Some(guard) = &config.replay_guard {
        match guard.lock() {
            Ok(mut guard) => if !guard.accept(&accepted.binder) { return None; },
            // A poisoned lock means another thread panicked holding it, so
            // the register's contents are not to be trusted. Refusing early
            // data is the safe reading of "I do not know whether I have
            // seen this".
            Err(_) => return None,
        }
    }
    Some(config.max_early_data.min(accepted.session.max_early_data))
}

/// Whether the client's `obfuscated_ticket_age` agrees with the sealed
/// ticket's actual age to within `EARLY_DATA_AGE_TOLERANCE_MS`.
///
/// The reported age is `(actual milliseconds + age_add) mod 2^32`, so
/// `age_add` is subtracted with wrapping, as the client added it. The
/// actual age is by the server's clock; a ticket from the future is as
/// wrong as a stale one.
fn reported_age_is_fresh(accepted: &AcceptedPsk, now: i64) -> bool {
    let reported = u64::from(
        accepted.obfuscated_ticket_age.wrapping_sub(accepted.session.age_add));
    let actual = (now - accepted.session.issued_at).max(0) as u64;
    let actual = actual.saturating_mul(1000);
    reported.abs_diff(actual) <= EARLY_DATA_AGE_TOLERANCE_MS
}

/// The group to ask for in a HelloRetryRequest: the first of ours that the
/// client said it supports at all.
pub fn retry_group(hello: &ClientHello) -> Result<u16, Error> {
    let offered = match find_extension(&hello.extensions, extension::SUPPORTED_GROUPS) {
        Some(extension) => parse_supported_groups(&extension.body)?,
        None => return Err(Error::new(AlertDescription::MISSING_EXTENSION,
                                      "A TLS 1.3 ClientHello must carry \
                                       supported_groups.")),
    };
    OURS.iter().find(|group| offered.contains(group)).copied().ok_or_else(|| {
        Error::new(AlertDescription::HANDSHAKE_FAILURE,
                   "No key exchange group in common.".to_string())
    })
}

fn parse_supported_groups(body: &[u8]) -> Result<Vec<u16>, Error> {
    let mut reader = crate::tls::codec::Reader::new(body);
    Ok(reader.u16_list()?)
}

/// The suite to name in a HelloRetryRequest.
///
/// It has to be one the client offered, because the second ClientHello's
/// transcript already contains this message and the schedule's hash comes
/// from the suite - naming one the client will not accept makes the retry
/// unanswerable.
pub fn retry_suite(config: &ServerConfig, hello: &ClientHello)
                   -> Result<&'static CipherSuite, Error> {
    choose_suite(config, hello)
}

/// The first 1.3 suite this server prefers that the client also offered.
///
/// **`ServerKey::authenticates` is deliberately not consulted.** At 1.2 a
/// suite names its key exchange and its authentication, so an RSA key
/// cannot serve `ECDHE_ECDSA`. At 1.3 a suite names neither - it is an AEAD
/// and a hash, nothing more - and the `KeyExchange` in those rows of the
/// table is a placeholder. Asking it here would refuse every 1.3 handshake
/// made with an EC key, because the placeholder says `EcdheRsa`.
fn choose_suite(config: &ServerConfig, hello: &ClientHello)
                -> Result<&'static CipherSuite, Error> {
    for code in config.suites.for_version(Version::TLS13).codes() {
        let suite = match crate::tls::suites::by_code(*code) {
            Some(suite) => suite,
            None => continue,
        };
        if suite.min_version < Version::TLS13 || !suite.is_implemented() {
            continue;
        }
        if hello.cipher_suites.contains(code) {
            return Ok(suite);
        }
    }
    Err(Error::new(AlertDescription::HANDSHAKE_FAILURE,
                   "No TLS 1.3 cipher suite in common.".to_string()))
}

/// The signature scheme for the CertificateVerify.
///
/// This is where authentication is decided at 1.3, and it has to satisfy
/// three things at once: the client offered it, this server's key can
/// produce it, and it is legal in a CertificateVerify. The last one is not
/// a formality - RFC 8446 4.4.3 forbids the `rsa_pkcs1_*` codepoints there,
/// so a server that picks one because it appears in `signature_algorithms`
/// (where they *are* legal, for certificates) gets refused by any correct
/// client.
fn choose_scheme(config: &ServerConfig, hello: &ClientHello) -> Result<u16, Error> {
    let offered = match find_extension(&hello.extensions,
                                       extension::SIGNATURE_ALGORITHMS) {
        Some(extension) => hs13::parse_signature_algorithms(&extension.body)?,
        None => return Err(Error::new(AlertDescription::MISSING_EXTENSION,
                                      "A TLS 1.3 ClientHello must carry \
                                       signature_algorithms.")),
    };
    for candidate in ours_for(&config.key) {
        if offered.contains(&candidate) && scheme::allowed_in_certificate_verify(candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::new(AlertDescription::HANDSHAKE_FAILURE, format!(
        "No signature scheme in common for a {} key at TLS 1.3. The client \
         offered {:?}.",
        match &config.key {
            ServerKey::Rsa(_) => "RSA",
            ServerKey::Ec { .. } => "EC",
            ServerKey::Eddsa { name, .. } => name,
            ServerKey::Gost { curve, .. } => curve,
            ServerKey::MlDsa(key) => key.parameter_set(),
        },
        offered.iter().map(|s| scheme::name(*s)).collect::<Vec<_>>())))
}

/// What this key can sign with at 1.3, in preference order.
///
/// RSA is PSS only. An EC key can only sign with the scheme that names its
/// own curve: `ecdsa_secp256r1_sha256` is P-256 **and** SHA-256, and a
/// signature made on the wrong curve is refused however good it is.
fn ours_for(key: &ServerKey) -> Vec<u16> {
    match key {
        ServerKey::Rsa(_) => vec![scheme::RSA_PSS_RSAE_SHA256,
                                  scheme::RSA_PSS_RSAE_SHA384,
                                  scheme::RSA_PSS_RSAE_SHA512],
        ServerKey::Ec { curve, .. } => match *curve {
            "P-256" => vec![scheme::ECDSA_SECP256R1_SHA256],
            "P-384" => vec![scheme::ECDSA_SECP384R1_SHA384],
            "P-521" => vec![scheme::ECDSA_SECP521R1_SHA512],
            _ => Vec::new(),
        },
        // One scheme each, and the key names it. There is no hash to
        // choose - EdDSA's is fixed by the variant.
        ServerKey::Eddsa { name, .. } => match *name {
            "ed25519" => vec![scheme::ED25519],
            "ed448" => vec![scheme::ED448],
            _ => Vec::new(),
        },
        // **One scheme, and the curve decides which.** RFC 9367 section
        // 5.2 binds each of its seven schemes to one curve, so there is
        // nothing to prefer - and a curve with no scheme (a GOST key on a
        // curve RFC 9367 does not cover, or a registered one) gets an
        // empty list and a clear refusal from `choose_scheme` rather than
        // a signature nobody can check.
        ServerKey::Gost { curve, .. } => match scheme::gost_13_for_curve(curve) {
            Some(scheme) => vec![scheme],
            None => Vec::new(),
        },
        // One scheme per parameter set, as for EdDSA.
        ServerKey::MlDsa(key) => scheme::ml_dsa_for_parameter_set(key.parameter_set())
            .into_iter().collect(),
    }
}

/// Everything the server sends, from the ServerHello to its own Finished.
///
/// The caller owns the transcript, the record layers and the output buffer;
/// this function drives all three because the order between them is the
/// whole difficulty. It returns the 1.3 state to be stored on the
/// connection.
#[allow(clippy::too_many_arguments)]
pub fn send_flight(config: &ServerConfig,
                   negotiated: &Negotiated,
                   server_random: [u8; 32],
                   transcript: &mut Transcript,
                   reader: &mut RecordReader,
                   writer: &mut RecordWriter,
                   outgoing: &mut Vec<u8>,
                   alpn: Option<&str>,
                   // The transcript hash **through the ClientHello and
                   // nothing else**, which is what the client's early
                   // traffic secret is derived over. Taken from the caller
                   // because by the time this function has written the
                   // ServerHello the transcript has moved on, and a hash
                   // cannot be rewound.
                   hello_only_hash: &[u8],
                   // Whether the client asked for a stapled OCSP
                   // response. A server that stapled unasked would send
                   // an extension the client has to refuse (RFC 8446
                   // 4.2: a server may not answer what was not offered).
                   stapling: bool,
                   // Whether a HelloRetryRequest went out before this
                   // hello. The compatibility ChangeCipherSpec was sent
                   // after it in that case and is not sent again.
                   retried: bool)
                   -> Result<Tls13, Error> {
    let suite = negotiated.suite;
    let hash = hash_of(suite)?;
    let aead = aead_of(suite)?;
    let (key_len, tag_len) = (aead.key_len, aead.tag_len);

    // ---- ServerHello ------------------------------------------------
    //
    // `legacy_version` is pinned at 1.2 and the real answer is in
    // supported_versions; `session_id` echoes whatever the client sent,
    // including an empty one, because a middlebox that sees it change
    // decides the handshake is not a resumption it recognises.
    let mut extensions = vec![
        Extension {
            kind: extension::SUPPORTED_VERSIONS,
            body: hs13::encode_server_supported_version(Version::TLS13),
        },
        Extension {
            kind: extension::KEY_SHARE,
            body: hs13::encode_server_key_share(&negotiated.ours)?,
        },
    ];
    if let Some((index, _)) = &negotiated.psk {
        // Which of the client's identities was chosen. The key share stays:
        // we only ever resume with a fresh exchange, so the session gets
        // forward secrecy that a PSK-only resumption would not have.
        extensions.push(Extension {
            kind: extension::PRE_SHARED_KEY,
            body: hs13::encode_server_pre_shared_key(*index),
        });
    }
    let hello = ServerHello {
        legacy_version: Version::TLS12,
        random: server_random,
        session_id: negotiated.session_id.clone(),
        cipher_suite: suite.code,
        compression_method: 0,
        extensions,
    };
    let message = HandshakeMessage::new(HandshakeType::ServerHello, hello.encode()?)?;
    transcript.update(&message.raw);
    let bytes = writer.write(ContentType::Handshake, &message.raw)?;
    outgoing.extend_from_slice(&bytes);

    // The transcript hash *through the ServerHello* - the first of four,
    // and the one the handshake keys come from.
    let hello_hash = transcript.hash();

    // ---- the compatibility ChangeCipherSpec --------------------------
    //
    // Written before the writer changes keys, so it goes out in the clear.
    // It means nothing in 1.3 and exists only so that a middlebox watching
    // for a 1.2-shaped handshake sees one.
    //
    // **Once per connection.** RFC 8446 appendix D.4 has the server send
    // it "immediately after its first handshake message", which after a
    // retry was the HelloRetryRequest - `send_retry_request` wrote it
    // there. A second one here was harmless to a peer that drops every
    // such record, and is refused by one that holds the sender to the
    // appendix, which this library's client now does.
    if !retried {
        let ccs = writer.write(ContentType::ChangeCipherSpec, &[1])?;
        outgoing.extend_from_slice(&ccs);
    }

    // ---- handshake keys ----------------------------------------------
    //
    // The PSK if one was accepted, else `None`. The client's keys go on the
    // reader and ours on the writer - the opposite of the client's own code,
    // and the kind of thing that produces a decryption failure three
    // messages later if it is reversed.
    let psk = negotiated.psk.as_ref().map(|(_, secret)| secret.as_slice());
    let schedule = Schedule::early(suite.prf, psk).map_err(Error::local)?
        .handshake(&negotiated.shared).map_err(Error::local)?;
    let (client_keys, server_keys) = schedule
        .handshake_traffic(&hello_hash, key_len, aead.iv_len)
        .map_err(Error::local)?;
    let client_finished_key = client_keys.finished_key.clone();
    let server_finished_key = server_keys.finished_key.clone();

    writer.change_cipher_spec(Protection::Aead13(
        Aead13::with_rekeying(aead.name, hash, server_keys, tag_len, aead.mgm)
            .map_err(Error::local)?));

    // **The reader's keys depend on whether early data was accepted, and
    // the handshake keys are held back when it was.** Accepted early data
    // arrives under a secret derived from the PSK over the ClientHello
    // alone - the client had heard nothing when it wrote those records -
    // and the client does not switch to its handshake keys until it has
    // sent EndOfEarlyData. Installing the handshake keys here would make
    // every early record fail to decrypt, which is what rejecting looks
    // like, so the mistake reads as a policy decision.
    let client_handshake = if negotiated.early_data.is_some() {
        let early = Schedule::early(
            suite.prf, negotiated.psk.as_ref().map(|(_, s)| s.as_slice()))
            .map_err(Error::local)?;
        let early_keys = early
            .client_early_traffic(hello_only_hash, key_len, aead.iv_len)
            .map_err(Error::local)?;
        reader.change_cipher_spec(Protection::Aead13(
            Aead13::with_rekeying(aead.name, hash, early_keys, tag_len, aead.mgm)
                .map_err(Error::local)?));
        Some(client_keys)
    } else {
        reader.change_cipher_spec(Protection::Aead13(
            Aead13::with_rekeying(aead.name, hash, client_keys, tag_len, aead.mgm)
                .map_err(Error::local)?));
        None
    };

    // ---- EncryptedExtensions -----------------------------------------
    //
    // Everything that is not needed to establish the keys moves here, where
    // it is encrypted. The SNI acknowledgement is an empty extension: it
    // says "I used the name you sent" and carries nothing.
    let mut encrypted = Vec::new();
    if let Some(protocol) = alpn {
        encrypted.push(Extension {
            kind: extension::ALPN,
            body: encode_alpn(protocol)?,
        });
    }
    if negotiated.early_data.is_some() {
        // **Empty here, and empty in the ClientHello.** The extension has
        // a `max_early_data_size` body in a NewSessionTicket and nowhere
        // else; writing the limit here is a message the client reads as
        // malformed. Its mere presence is the acceptance.
        encrypted.push(Extension { kind: extension::EARLY_DATA, body: Vec::new() });
    }
    let body = EncryptedExtensions { extensions: encrypted }.encode()?;
    emit(HandshakeType::EncryptedExtensions, body, transcript, writer, outgoing)?;

    // ---- CertificateRequest ---------------------------------------------
    //
    // Only on a full handshake: a resumed one has already authenticated the
    // client with the PSK, and RFC 8446 4.3.2 forbids asking again there.
    //
    // The context is empty. A non-empty one belongs to post-handshake
    // authentication, which is not implemented, so writing one would be a
    // message the peer reads as something else.
    let requesting = config.request_client_certificate && negotiated.psk.is_none();
    if requesting {
        let request = hs13::CertificateRequest13 {
            context: Vec::new(),
            extensions: vec![Extension {
                kind: extension::SIGNATURE_ALGORITHMS,
                // What we can *verify*, which is not the same list as what
                // we can sign with: a server with an EC key still verifies
                // an RSA client certificate perfectly well.
                body: hs13::encode_signature_algorithms(
                    &verifiable_for(negotiated.suite))?,
            }],
        };
        emit(HandshakeType::CertificateRequest, request.encode()?,
             transcript, writer, outgoing)?;
    }

    // ---- Certificate and CertificateVerify ------------------------------
    //
    // **Skipped entirely when the handshake resumed.** The PSK is the
    // authentication: the client proved it holds a secret only a server
    // that ran the earlier handshake could have issued, and a certificate
    // on top would be a second, redundant proof - RFC 8446 2.2. Sending one
    // anyway is not merely wasteful; the client is not expecting it and
    // will fail on an unexpected message.
    //
    // This is also most of what makes resumption cheap: it takes out the
    // chain, the signature, and the client's verification of both.
    let resumed = negotiated.psk.is_some();
    if !resumed {
        // `request_context` is empty in a server Certificate and must be: a
        // non-empty one belongs to a reply to a CertificateRequest.
        // **The staple hangs off the *leaf*, not off the connection.**
        // At TLS 1.2 it is a message of its own, which implicitly means
        // "the certificate you are about to see"; at 1.3 it is an
        // extension on the certificate entry, and RFC 8446 4.4.2.1
        // allows one per entry. Only the leaf gets one, because a
        // response about an intermediate is a different question this
        // server was not given an answer to.
        let staple = match (&config.ocsp_response, stapling) {
            (Some(response), true) => Some(response.as_slice()),
            _ => None,
        };
        let entries = certificate_entries(&config.certificate_chain, staple)?;
        let body = Certificate13 { request_context: Vec::new(), entries }.encode()?;
        emit(HandshakeType::Certificate, body, transcript, writer, outgoing)?;

        // The second transcript hash: through the Certificate, not including
        // this message. `Side13::Server` picks the context string; signing
        // with `Side13::Client` produces a signature that verifies against
        // nothing and looks exactly like a wrong key.
        let content = hs13::certificate_verify_content(Side13::Server,
                                                       &transcript.hash());
        let signature = sign(&config.key, negotiated.scheme, &content)?;
        let body = CertificateVerify { scheme: negotiated.scheme, signature }.encode()?;
        emit(HandshakeType::CertificateVerify, body, transcript, writer, outgoing)?;
    }

    // ---- Finished ------------------------------------------------------
    //
    // The third hash: through the CertificateVerify. The key is the one
    // derived with the *handshake* traffic secret, not the application one.
    let verify = keys13::finished(hash, &server_finished_key, &transcript.hash())
        .map_err(Error::local)?;
    let body = Finished { verify_data: verify }.encode();
    emit(HandshakeType::Finished, body, transcript, writer, outgoing)?;

    // ---- application keys -----------------------------------------------
    //
    // The fourth hash: through our own Finished. Both directions come from
    // it, but only ours is installed now - the client's Finished is still
    // protected under the handshake keys, so the reader has to wait.
    //
    // **Getting this one wrong still completes the handshake.** The other
    // three show up as a failed Finished or a failed signature, which is
    // loud; this one is not used until the first application record, so
    // every handshake test passes and only the ones that send data fail.
    // Of the seven deliberate breaks in the sweep, six failed ten tests of
    // thirteen and this one failed two. A 1.3 server tested only on
    // handshakes would ship it.
    let master = schedule.master().map_err(Error::local)?;
    let (client_application, server_application) = master
        .application_traffic(&transcript.hash(), key_len, aead.iv_len)
        .map_err(Error::local)?;
    writer.change_cipher_spec(Protection::Aead13(
        Aead13::with_rekeying(aead.name, hash, server_application, tag_len,
                              aead.mgm).map_err(Error::local)?));

    Ok(Tls13 {
        schedule: master,
        hash,
        aead,
        client_finished_key,
        client_application: Some(client_application),
        suite: suite.code,
        prf: suite.prf,
        resumed,
        requested_client_certificate: requesting,
        early_data: negotiated.early_data,
        client_handshake,
        early_bytes: 0,
    })
}

/// A HelloRetryRequest: a ServerHello with a fixed random, asking for a
/// share in a group the client did not send one for.
///
/// RFC 8446 4.4.1 replaces the first ClientHello in the transcript with a
/// synthetic `message_hash` message holding its hash. The caller has to do
/// that *before* calling this, because after it the original hello is gone
/// from the transcript for good.
pub fn send_retry_request(suite: &'static CipherSuite,
                          group: u16,
                          session_id: &[u8],
                          transcript: &mut Transcript,
                          writer: &mut RecordWriter,
                          outgoing: &mut Vec<u8>,
                          prefix: &mut Vec<u8>)
                          -> Result<(), Error> {
    let hello = ServerHello {
        legacy_version: Version::TLS12,
        random: hs13::HELLO_RETRY_REQUEST_RANDOM,
        session_id: session_id.to_vec(),
        cipher_suite: suite.code,
        compression_method: 0,
        extensions: vec![
            Extension {
                kind: extension::SUPPORTED_VERSIONS,
                body: hs13::encode_server_supported_version(Version::TLS13),
            },
            Extension {
                kind: extension::KEY_SHARE,
                body: hs13::encode_retry_key_share(group),
            },
        ],
    };
    let message = HandshakeMessage::new(HandshakeType::ServerHello, hello.encode()?)?;
    transcript.update(&message.raw);
    // And into the prefix: a PSK binder in the *second* ClientHello covers
    // `message_hash || HelloRetryRequest` before it, and by then the
    // transcript is a hash and cannot be read back.
    prefix.extend_from_slice(&message.raw);
    let bytes = writer.write(ContentType::Handshake, &message.raw)?;
    outgoing.extend_from_slice(&bytes);

    // The compatibility CCS goes out after the retry too, and in the clear:
    // no keys exist yet on this path.
    let ccs = writer.write(ContentType::ChangeCipherSpec, &[1])?;
    outgoing.extend_from_slice(&ccs);
    Ok(())
}

/// The second ClientHello after a HelloRetryRequest, checked against the
/// first (RFC 8446 4.1.2).
///
/// A client answering a retry "MUST send the same ClientHello without
/// modification", except that it replaces `key_share` with one entry for
/// the group the retry named, removes `early_data`, echoes a `cookie`,
/// recomputes `pre_shared_key`, and may resize `padding`. The server
/// "MUST abort the handshake with an illegal_parameter alert" otherwise.
/// Everything else - the random, the session id, the suites, every other
/// extension in its original order - has to match, or the server would
/// be negotiating from a hello it never retried: a client switching
/// suites, SNI, ALPN or signature schemes between the two hellos is
/// either broken or steering the server somewhere the first hello did
/// not go. The transcript covers both, so an honest mismatch fails at
/// the Finished; this refuses it before anything is decided on it.
///
/// The key share is checked here too: the retry asked for exactly one
/// group, and a second hello without a share for it cannot make
/// progress and would be answered with a second retry, which a server
/// is not allowed to send.
pub fn check_second_hello(first: &ClientHello, second: &ClientHello,
                          requested_group: u16) -> Result<(), Error> {
    let changed = |what: &str| Error::new(
        AlertDescription::ILLEGAL_PARAMETER,
        format!("The second ClientHello after a HelloRetryRequest changed \
                 its {}, which RFC 8446 4.1.2 does not allow.", what));
    if first.legacy_version != second.legacy_version {
        return Err(changed("legacy_version"));
    }
    if first.random != second.random {
        return Err(changed("random"));
    }
    if first.session_id != second.session_id {
        return Err(changed("session_id"));
    }
    if first.cipher_suites != second.cipher_suites {
        return Err(changed("cipher suites"));
    }
    if first.compression_methods != second.compression_methods {
        return Err(changed("compression methods"));
    }
    // The extensions the retry entitles the client to change, taken out
    // of both lists; what is left has to match in order and in content.
    let may_change = |kind: u16| matches!(
        kind, extension::KEY_SHARE | extension::EARLY_DATA | extension::COOKIE
            | extension::PRE_SHARED_KEY | extension::PADDING);
    let kept = |hello: &ClientHello| -> Vec<Extension> {
        hello.extensions.iter().filter(|e| !may_change(e.kind)).cloned().collect()
    };
    let (before, after) = (kept(first), kept(second));
    if before.len() != after.len() {
        return Err(changed("set of extensions"));
    }
    for (a, b) in before.iter().zip(&after) {
        if a.kind != b.kind {
            return Err(changed("order of extensions"));
        }
        if a.body != b.body {
            return Err(changed(&format!("{} extension", extension::name(a.kind))));
        }
    }
    let shares = match find_extension(&second.extensions, extension::KEY_SHARE) {
        Some(extension) => hs13::parse_client_key_share(&extension.body)?,
        None => return Err(Error::new(AlertDescription::MISSING_EXTENSION,
                                      "A TLS 1.3 ClientHello must carry key_share.")),
    };
    if !shares.iter().any(|entry| entry.group == requested_group) {
        return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER, format!(
            "The HelloRetryRequest asked for a {} key share and the second \
             ClientHello carries none.",
            crate::tls::handshake::groups::name(requested_group))));
    }
    Ok(())
}

/// The synthetic `message_hash` that replaces the first ClientHello.
pub fn synthetic_message_hash(hash_name: &str, first_hello: &[u8])
                              -> Result<HandshakeMessage, Error> {
    let mut hasher = crate::api::AnyHash::new(hash_name).map_err(Error::local)?;
    hasher.update(first_hello);
    HandshakeMessage::new(HandshakeType::MessageHash, hasher.digest())
        .map_err(Error::from)
}

/// Write one handshake message: into the transcript, then into a record,
/// then into the output buffer. Always in that order.
fn emit(kind: HandshakeType, body: Vec<u8>, transcript: &mut Transcript,
        writer: &mut RecordWriter, outgoing: &mut Vec<u8>) -> Result<(), Error> {
    let message = HandshakeMessage::new(kind, body)?;
    transcript.update(&message.raw);
    let bytes = writer.write(ContentType::Handshake, &message.raw)?;
    outgoing.extend_from_slice(&bytes);
    Ok(())
}

/// Sign the CertificateVerify content with the scheme that was negotiated.
///
/// The scheme decides the hash **and**, for RSA, that the padding is PSS
/// with a salt the length of the digest. `SigningKey::sign` does PKCS#1
/// v1.5, which is not allowed here, so the RSA branch goes to `sign_pss`
/// directly rather than through it.
fn sign(key: &ServerKey, chosen: u16, content: &[u8]) -> Result<Vec<u8>, Error> {
    // **EdDSA signs `content`, not a digest of it.** The rest of this
    // function hashes first, which is right for everything else here
    // and wrong for these two - a digest handed to EdDSA is signed as
    // if it were the message, and the result verifies nowhere.
    if let ServerKey::Eddsa { name, seed } = key {
        let expected = if *name == "ed25519" { scheme::ED25519 } else { scheme::ED448 };
        if chosen != expected {
            return Err(Error::local(format!(
                "Asked to sign with {} using an {} key.",
                scheme::name(chosen), name)));
        }
        return crate::api::eddsa_sign(name, seed, content, &[]).map_err(Error::local);
    }
    // ML-DSA too signs `content` itself, hedged, with FIPS 204's empty
    // context (draft-ietf-tls-mldsa section 3.2).
    if let ServerKey::MlDsa(key) = key {
        if scheme::ml_dsa_parameter_set(chosen) != Some(key.parameter_set()) {
            return Err(Error::local(format!(
                "Asked to sign with {} using an {} key.",
                scheme::name(chosen), key.parameter_set())));
        }
        return key.sign(content, &[], None).map_err(Error::local);
    }

    let hash_name = scheme::hash_name(chosen).ok_or_else(|| Error::local(format!(
        "No hash for signature scheme {}.", scheme::name(chosen))))?;
    let mut hasher = crate::api::AnyHash::new(hash_name).map_err(Error::local)?;
    hasher.update(content);
    let digest = hasher.digest();

    match key {
        ServerKey::Rsa(private) => {
            let salt = crate::publickey_ciphers::rsa::pss_salt_len(hash_name)
                .map_err(Error::local)?;
            crate::publickey_ciphers::rsa::sign_pss(private, hash_name, &digest, salt)
                .map_err(Error::local)
        }
        ServerKey::Ec { curve, private } => {
            let handle = crate::ec::curves::by_name(curve).map_err(Error::local)?;
            let hash = crate::api::AnyHash::new(hash_name).map_err(Error::local)?;
            let signature = handle.sign(private, &digest, hash).map_err(Error::local)?;
            // DER, as every TLS signature is - the fixed-width r||s form is
            // for JWS and the NIST vectors, not for the wire here.
            Ok(crate::x509::verify::encode_ecdsa_der(&signature))
        }
        // **GOST R 34.10-2012.** The digest is already the right one:
        // `scheme::hash_name` answers `streebog256` or `streebog512` by
        // the scheme, which RFC 9367 section 5.2 pairs with the key size
        // rather than with the curve's name.
        //
        // The signature's encoding is the trap, and it is not this
        // function's invention: RFC 9367 section 5.3 writes
        // `str_l(r) | str_l(s)`, which is the components in the opposite
        // order from RFC 9215's certificates *and* each one reversed.
        // `gost_signature_bytes_13` does that and is pinned to the
        // document's own worked example in `tests/test_rfc9367_flight.rs`,
        // so this side and the verifying side cannot agree on a wrong
        // encoding between themselves.
        ServerKey::Gost { curve, private } => {
            let handle = crate::ec::curves::by_name(curve).map_err(Error::local)?;
            let hash = crate::api::AnyHash::new(hash_name).map_err(Error::local)?;
            let signature = handle.gost_sign(private, &digest, hash)
                .map_err(Error::local)?;
            handle.gost_signature_bytes_13(&signature).map_err(Error::local)
        }
        // Handled above, before anything was hashed.
        ServerKey::Eddsa { .. } => unreachable!("EdDSA returns before the digest"),
        ServerKey::MlDsa(_) => unreachable!("ML-DSA returns before the digest"),
    }
}

/// Verify a CertificateVerify signature against a certificate's public key.
///
/// Shared between the two directions of client authentication, because the
/// arithmetic is the same and only the context string differs - which the
/// caller has already folded into `content`.
pub fn verify_signature(certificate_der: &[u8], chosen: u16,
                        content: &[u8], signature: &[u8]) -> Result<(), Error> {
    use crate::x509::{verify, Certificate, PublicKey};

    let certificate = Certificate::parse(certificate_der)
        .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;

    // EdDSA before the digest, for the reason `sign` gives above: there
    // is no digest. `client::verify_eddsa` is the one check, shared.
    if matches!(chosen, scheme::ED25519 | scheme::ED448) {
        return crate::tls::client::verify_eddsa(&certificate.public_key, chosen, content,
                                                signature);
    }

    if let Some(named) = scheme::ml_dsa_parameter_set(chosen) {
        return crate::tls::client::verify_ml_dsa_13(&certificate.public_key, chosen, named,
                                                    content, signature);
    }

    let hash_name = scheme::hash_name(chosen).ok_or_else(|| Error::local(
        format!("No hash for {}.", scheme::name(chosen))))?;
    let mut hasher = crate::api::AnyHash::new(hash_name).map_err(Error::local)?;
    hasher.update(content);
    let digest = hasher.digest();

    let ok = match &certificate.public_key {
        PublicKey::Rsa { n, e } => {
            if !scheme::is_pss(chosen) {
                return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                    "An RSA CertificateVerify must use PSS at TLS 1.3."));
            }
            let key = crate::publickey_ciphers::rsa::RsaPublicKey::new(
                n.clone(), e.clone())
                .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
            let salt = crate::publickey_ciphers::rsa::pss_salt_len(hash_name)
                .map_err(Error::local)?;
            crate::publickey_ciphers::rsa::verify_pss(&key, hash_name, &digest,
                                                      signature, salt)
                .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
        }
        PublicKey::Ec { curve, point } => {
            // **The scheme names the curve**, and a signature made on a
            // different one is refused however good it is: RFC 8446 4.4.3
            // binds `ecdsa_secp256r1_sha256` to P-256 exactly.
            match scheme::curve_name(chosen) {
                Some(named) if named == *curve => {}
                Some(named) => return Err(Error::new(
                    AlertDescription::ILLEGAL_PARAMETER, format!(
                        "The client signed with {}, which is bound to {}, but \
                         its certificate carries a {} key.",
                        scheme::name(chosen), named, curve))),
                None => return Err(Error::new(
                    AlertDescription::ILLEGAL_PARAMETER, format!(
                        "The client signed with {} using an EC key.",
                        scheme::name(chosen)))),
            }
            let handle = crate::ec::curves::by_name(curve).map_err(Error::local)?;
            let public = handle.decode_point(point).map_err(|e| Error::new(
                AlertDescription::BAD_CERTIFICATE, e))?;
            let decoded = verify::decode_ecdsa_der(signature)
                .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
            handle.verify(&public, &digest, &decoded)
                .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
        }
        // **GOST R 34.10-2012**, the mirror of the client's own arm in
        // `client.rs`. Two things differ from the EC one above and both
        // are RFC 9367's rather than a choice here:
        //
        //   * the scheme-to-curve binding covers curves of two sizes, and
        //     three of the seven schemes are named by a letter that does
        //     not match their parameter set's - so `scheme::curve_name` is
        //     the only place that mapping is written;
        //   * the signature is `str_l(r) | str_l(s)` (section 5.3), the
        //     components in the opposite order from a certificate's and
        //     each reversed. Reading it with the certificate's decoder
        //     gives two numbers of the right length that verify against
        //     nothing.
        PublicKey::Gost { curve, x, y, .. }
                if scheme::is_gost_13(chosen) => {
            match scheme::curve_name(chosen) {
                Some(named) if named == *curve => {}
                Some(named) => return Err(Error::new(
                    AlertDescription::ILLEGAL_PARAMETER, format!(
                        "The client signed with {}, which RFC 9367 binds to \
                         {}, but its certificate is on {}.",
                        scheme::name(chosen), named, curve))),
                None => return Err(Error::new(
                    AlertDescription::ILLEGAL_PARAMETER, format!(
                        "The client signed with {} using a GOST key.",
                        scheme::name(chosen)))),
            }
            let handle = crate::ec::curves::by_name(curve).map_err(Error::local)?;
            let public = crate::ec::Point::new(x.clone(), y.clone());
            let decoded = handle.gost_signature_from_bytes_13(signature)
                .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
            handle.gost_verify(&public, &digest, &decoded)
                .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
        }
        other => {
            return Err(Error::new(AlertDescription::UNSUPPORTED_CERTIFICATE,
                format!("Cannot verify a CertificateVerify against a {:?} key.",
                        other)));
        }
    };
    if !ok {
        return Err(Error::new(AlertDescription::DECRYPT_ERROR,
            "The CertificateVerify signature did not check out."));
    }
    Ok(())
}

/// The signature schemes this server will verify a **TLS 1.2** client
/// certificate with.
///
/// PKCS#1 v1.5 for RSA, not PSS: at 1.2 the signature is over a raw
/// concatenation and every 1.2 peer signs it the old way. The PSS
/// codepoints are legal in a 1.2 handshake (RFC 8446 4.2.3) but nothing
/// sends them for a client certificate, and offering a scheme nobody
/// uses is an invitation to test a path nobody exercises.
///
/// Deliberately a **different list** from what this server signs with,
/// for the same reason `VERIFIABLE` is at 1.3: a server with an EC key
/// verifies an RSA client certificate perfectly well.
pub const VERIFIABLE_12: &[u16] = &[
    0x0403,   // ecdsa_secp256r1_sha256
    0x0503,   // ecdsa_secp384r1_sha384
    0x0603,   // ecdsa_secp521r1_sha512
    0x0401,   // rsa_pkcs1_sha256
    0x0501,   // rsa_pkcs1_sha384
    0x0601,   // rsa_pkcs1_sha512
    0x0807,   // ed25519, RFC 8422 section 5.1.3
    0x0808,   // ed448
];

/// Verify a **TLS 1.2** CertificateVerify.
///
/// Separate from `verify_signature` rather than a flag on it, because
/// every part differs: the RSA padding is PKCS#1 v1.5 rather than PSS,
/// the hash comes from the scheme's own hash byte rather than from a 1.3
/// codepoint table, and an EC scheme at 1.2 is **not** bound to a curve -
/// `ecdsa_sha256` is a hash and an algorithm, and RFC 5246 says nothing
/// about which curve the key is on. Binding it here would refuse a
/// P-384 key signing with SHA-256, which is a legal 1.2 signature.
///
/// `signed` is `Hash(handshake_messages)`'s *input* - the raw
/// concatenation - because the hash is chosen by the message.
///
/// EdDSA (hash byte 8, "Intrinsic") signs `signed` itself, with no
/// digest taken first and an empty Ed448 context, which is RFC 8422
/// section 5.10's rule for both 1.2 signatures. It is checked before the
/// hash is looked up, because there is none to look up.
pub fn verify_signature_12(certificate_der: &[u8], scheme: SignatureScheme,
                           signed: &[u8], signature: &[u8])
                           -> Result<(), Error> {
    use crate::x509::{verify, Certificate, PublicKey};

    let certificate = Certificate::parse(certificate_der)
        .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
    let code = scheme.to_u16();
    if matches!(code, scheme::ED25519 | scheme::ED448) {
        return crate::tls::client::verify_eddsa(&certificate.public_key, code,
                                                signed, signature);
    }
    let hash_name = scheme.hash_name().ok_or_else(|| Error::new(
        AlertDescription::ILLEGAL_PARAMETER,
        format!("Unknown hash {} in a CertificateVerify.", scheme.hash)))?;
    let mut hasher = crate::api::AnyHash::new(hash_name).map_err(Error::local)?;
    hasher.update(signed);
    let digest = hasher.digest();

    let ok = match &certificate.public_key {
        PublicKey::Rsa { n, e } => {
            if scheme.signature != 1 {
                return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                    format!("The client's certificate holds an RSA key and it \
                             signed with {}.", scheme.signature_name())));
            }
            let key = crate::publickey_ciphers::rsa::RsaPublicKey::new(
                n.clone(), e.clone())
                .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
            crate::publickey_ciphers::rsa::verify_pkcs1v15(&key, hash_name,
                                                           &digest, signature)
                .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
        }
        PublicKey::Ec { curve, point } => {
            if scheme.signature != 3 {
                return Err(Error::new(AlertDescription::ILLEGAL_PARAMETER,
                    format!("The client's certificate holds an EC key and it \
                             signed with {}.", scheme.signature_name())));
            }
            let handle = crate::ec::curves::by_name(curve).map_err(Error::local)?;
            let public = handle.decode_point(point).map_err(|e| Error::new(
                AlertDescription::BAD_CERTIFICATE, e))?;
            let decoded = verify::decode_ecdsa_der(signature)
                .map_err(|e| Error::new(AlertDescription::DECODE_ERROR, e))?;
            handle.verify(&public, &digest, &decoded)
                .map_err(|e| Error::new(AlertDescription::DECRYPT_ERROR, e))?
        }
        other => {
            return Err(Error::new(AlertDescription::UNSUPPORTED_CERTIFICATE,
                format!("Cannot verify a TLS 1.2 CertificateVerify against a \
                         {:?} key.", other)));
        }
    };
    if !ok {
        return Err(Error::new(AlertDescription::DECRYPT_ERROR,
            "The CertificateVerify signature did not check out."));
    }
    Ok(())
}

/// Judge a client chain against a set of roots.
///
/// **Separate from the signature check, and after it.** A chain that
/// verifies against a root but did not sign this transcript is somebody
/// else's certificate, replayed - so possession is proved first and
/// provenance second. There is no hostname to check: a client certificate
/// names a person or a machine, not a server, so `verify_chain` is called
/// without one.
pub fn verify_client_chain(roots: &crate::trust::TrustStore,
                           chain: &[Vec<u8>],
                           policy: &crate::x509::verify::Policy)
                           -> Result<(), Error> {
    use crate::x509::{verify::Purpose, Certificate};

    let parsed: Vec<Certificate<'_>> = chain.iter()
        .map(|der| Certificate::parse(der))
        .collect::<Result<_, _>>()
        .map_err(|e| Error::new(AlertDescription::BAD_CERTIFICATE, e))?;
    let anchors: Vec<Certificate<'_>> = roots.roots().iter()
        .map(|der| Certificate::parse(der))
        .collect::<Result<_, _>>()
        .map_err(|e| Error::local(format!("A trusted root did not parse: {}", e)))?;

    // **`Purpose::ClientAuth`, not `ServerAuth`.** The extended key usage
    // bits differ, and a certificate issued for a server would otherwise be
    // accepted as a client - which is a real way to turn a public web
    // certificate into an identity.
    crate::x509::verify::verify_chain(&parsed, &anchors, policy,
                                      Purpose::ClientAuth)
        .map_err(|e| Error::new(AlertDescription::UNKNOWN_CA, e))
}

pub(crate) fn encode_alpn(protocol: &str) -> Result<Vec<u8>, Error> {
    let mut writer = crate::tls::codec::Writer::new();
    let mut list = crate::tls::codec::Writer::new();
    list.vector8(protocol.as_bytes())?;
    writer.vector16(&list.finish())?;
    Ok(writer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The second ClientHello after a retry may change only what the
    /// retry entitles it to change.
    ///
    /// What was wrong: the server kept the first hello and never
    /// compared it with the second, so a client could switch suites,
    /// SNI, ALPN, signature schemes or its PSK offers between the two
    /// hellos, and could answer a retry asking for one group with a
    /// share for another, which no retry can fix. RFC 8446 4.1.2
    /// requires `illegal_parameter` for a changed hello. No handshake
    /// test could reach it because every client that retries here -
    /// OpenSSL's and this library's - resends the same hello, so the
    /// hellos are built by hand.
    #[test]
    fn test_the_second_hello_may_change_only_what_the_retry_allows() {
        use crate::tls::handshake::groups;
        let share = |group: u16| {
            let key = EphemeralKey::generate(group).unwrap();
            Extension { kind: extension::KEY_SHARE,
                        body: hs13::encode_client_key_share(&[key.entry()]).unwrap() }
        };
        let plain = |kind: u16, body: &[u8]| Extension { kind, body: body.to_vec() };
        let first = ClientHello {
            legacy_version: Version::TLS12,
            random: [0x5A; 32],
            session_id: vec![1, 2, 3],
            cipher_suites: vec![0x1301, 0x1302],
            compression_methods: vec![0],
            extensions: vec![
                plain(extension::SERVER_NAME, b"\x00\x0b\x00\x00\x08one.test"),
                plain(extension::SUPPORTED_GROUPS, b"\x00\x04\x00\x1d\x00\x18"),
                plain(extension::EARLY_DATA, b""),
                share(groups::X25519),
                plain(extension::ALPN, b"\x00\x03\x02h2"),
                plain(extension::PADDING, b"\x00\x00\x00"),
            ],
        };
        let wanted = groups::SECP384R1;

        // The honest answer: a share for the requested group, early_data
        // gone, a cookie echoed, padding resized, everything else as it was.
        let mut second = first.clone();
        second.extensions = vec![
            plain(extension::SERVER_NAME, b"\x00\x0b\x00\x00\x08one.test"),
            plain(extension::SUPPORTED_GROUPS, b"\x00\x04\x00\x1d\x00\x18"),
            share(wanted),
            plain(extension::COOKIE, b"\x00\x02ok"),
            plain(extension::ALPN, b"\x00\x03\x02h2"),
            plain(extension::PADDING, b"\x00"),
        ];
        check_second_hello(&first, &second, wanted).expect("the honest answer");

        let refused = |second: &ClientHello, what: &str| {
            let error = check_second_hello(&first, second, wanted)
                .err().unwrap_or_else(|| panic!("{} was accepted", what));
            assert_eq!(error.alert, Some(AlertDescription::ILLEGAL_PARAMETER),
                       "{}: {}", what, error.detail);
            error.detail
        };
        let mut changed = second.clone();
        changed.random[0] ^= 1;
        assert!(refused(&changed, "a new random").contains("random"));

        let mut changed = second.clone();
        changed.cipher_suites = vec![0x1302];
        assert!(refused(&changed, "a shorter suite list").contains("cipher suites"));

        let mut changed = second.clone();
        changed.extensions[0] = plain(extension::SERVER_NAME,
                                      b"\x00\x0b\x00\x00\x08two.test");
        assert!(refused(&changed, "a new server name").contains("server_name"));

        let mut changed = second.clone();
        changed.extensions.remove(4);
        assert!(refused(&changed, "a dropped ALPN").contains("set of extensions"));

        let mut changed = second.clone();
        changed.extensions.swap(0, 1);
        assert!(refused(&changed, "reordered extensions").contains("order"));

        // A share for the wrong group: the one change the retry exists
        // to make, made wrongly.
        let mut changed = second.clone();
        changed.extensions[2] = share(groups::X25519);
        assert!(refused(&changed, "a share for the wrong group")
                    .contains("asked for"));
    }

    /// The staple goes on the **leaf's** entry and no other.
    ///
    /// Invisible from the wire: a client reads the leaf's entry, so a
    /// staple on every entry looks identical to a correct one. The
    /// deliberate-breakage sweep found exactly that, which is why the
    /// entries are built by a function with a test rather than inline.
    ///
    /// It matters because a response is about *one* certificate. Copying
    /// the leaf's answer onto an intermediate's entry is telling the
    /// client something about the intermediate that nobody said.
    #[test]
    fn test_only_the_leaf_carries_the_staple() {
        let chain = vec![vec![0x01], vec![0x02], vec![0x03]];
        let entries = certificate_entries(&chain, Some(&[0xaa, 0xbb])).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].extensions.len(), 1);
        assert_eq!(entries[0].extensions[0].kind, extension::STATUS_REQUEST);
        // The body is a CertificateStatus, not the bare response: type
        // byte, 24-bit length, then the DER.
        assert_eq!(entries[0].extensions[0].body,
                   vec![1, 0, 0, 2, 0xaa, 0xbb]);
        assert!(entries[1].extensions.is_empty());
        assert!(entries[2].extensions.is_empty());
    }

    /// And nothing at all when there is nothing to staple, since an
    /// empty extension is a different statement from no extension.
    #[test]
    fn test_no_staple_means_no_extension() {
        let chain = vec![vec![0x01], vec![0x02]];
        let entries = certificate_entries(&chain, None).unwrap();
        assert!(entries.iter().all(|entry| entry.extensions.is_empty()));
    }
}
