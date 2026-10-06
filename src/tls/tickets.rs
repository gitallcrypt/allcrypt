/*
Session tickets, server side.

A TLS 1.3 server that wants resumption has two ways to remember a session:
keep a table of them, or hand the client the state back, sealed under a key
only the server has. This is the second - "stateless" tickets - because a
table is state that has to survive a restart and be shared between machines,
and because the sealed form is what every large deployment ends up using.

`resumption.rs` is the client's half: it stores tickets and offers them.
Nothing in it is reusable for sealing, but two things in it are exactly what
a server needs and are used from here - `resumption::binder`, which computes
a binder from a binder key and a transcript hash and is side-agnostic, and
the truncation rule that `OfferedPsks::binders_length` encodes.

**What is sealed and why.** The ticket carries the resumption PSK itself,
the suite it belongs to, and when it was issued. Not the master secret: a
ticket is handed to a client and may be handed on, and a PSK derived for one
ticket compromises only that one. The suite is in there because the PSK's
length and the whole schedule depend on the hash, and a ticket offered
against a different suite has to be refused rather than reinterpreted.

**Three things a ticket must not be.**

  * **Readable.** It holds a key. Sealed with AES-256-GCM under a key the
    server generates and never sends.
  * **Forgeable.** The same AEAD authenticates it. A ticket that does not
    open is not an error to report in detail - it is a full handshake, and
    the client is told nothing, because "that ticket was almost right" is
    information.
  * **Eternal.** `lifetime` is what the client is told and `issued_at` is
    what the server checks. RFC 8446 4.6.1 caps a ticket at seven days, and
    a server that only tells the client is trusting the client.
*/

use crate::api::AnyHash;
use crate::hash_functions::HashFunction;
use crate::random;
use crate::tls::codec::{Reader, Writer};
use crate::tls::handshake13::NewSessionTicket13;
use crate::tls::keys13;
use crate::tls::suites::MacAlgorithm;

/// How long a ticket is offered for, in seconds. RFC 8446 4.6.1 forbids
/// more than seven days; this is a day, which is the usual deployment
/// choice and keeps the window for a stolen ticket short.
pub const DEFAULT_LIFETIME: u32 = 86_400;

/// The AEAD tickets are sealed with, and its sizes.
const SEAL_AEAD: &str = "aes-gcm";
const SEAL_KEY_LEN: usize = 32;
const SEAL_NONCE_LEN: usize = 12;
const SEAL_TAG_LEN: usize = 16;
/// A key name, so a server holding several can tell at a glance which one a
/// ticket was sealed under without trying to open it with each.
const KEY_NAME_LEN: usize = 8;

/// The key a server seals its tickets under.
///
/// Generated at startup and held in memory. Losing it on a restart costs
/// resumption and nothing else: every outstanding ticket simply fails to
/// open and those clients do a full handshake.
///
/// No `Debug` and no `Clone`: it is a key.
pub struct TicketKey {
    name: [u8; KEY_NAME_LEN],
    key: Vec<u8>,
}

impl Drop for TicketKey {
    fn drop(&mut self) {
        for byte in &mut self.key {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
}

impl TicketKey {
    pub fn generate() -> Result<TicketKey, String> {
        let mut name = [0u8; KEY_NAME_LEN];
        name.copy_from_slice(&random::bytes(KEY_NAME_LEN)?);
        Ok(TicketKey { name, key: random::bytes(SEAL_KEY_LEN)? })
    }

    /// A key from configured bytes: eight of name, then thirty-two of key.
    ///
    /// **This is how a ticket survives a restart, or works across a fleet.**
    /// A key generated per process means every ticket it issued becomes
    /// useless the moment that process goes away, and a client talking to
    /// the second machine behind a load balancer never resumes. A
    /// deployment that wants either generates forty bytes out of band and
    /// configures them on every instance.
    ///
    /// It is a key: whatever holds it has to protect it the way it would a
    /// private key, and rotating it is the only way to end the sessions it
    /// has sealed.
    pub fn from_bytes(bytes: &[u8]) -> Result<TicketKey, String> {
        if bytes.len() != KEY_NAME_LEN + SEAL_KEY_LEN {
            return Err(format!("A ticket key is {} bytes, got {}.",
                               KEY_NAME_LEN + SEAL_KEY_LEN, bytes.len()));
        }
        let mut name = [0u8; KEY_NAME_LEN];
        name.copy_from_slice(&bytes[..KEY_NAME_LEN]);
        Ok(TicketKey { name, key: bytes[KEY_NAME_LEN..].to_vec() })
    }

    /// How many bytes `from_bytes` wants.
    pub const fn byte_length() -> usize {
        KEY_NAME_LEN + SEAL_KEY_LEN
    }

    /// The eight bytes that prefix every ticket this key seals.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Seal a session into an opaque ticket.
    ///
    /// The key name and the nonce are in the clear and authenticated as
    /// additional data, so a ticket whose name was edited to point at
    /// another key fails to open rather than being tried under it.
    pub fn seal(&self, session: &Session) -> Result<Vec<u8>, String> {
        let nonce = random::bytes(SEAL_NONCE_LEN)?;
        let plaintext = session.encode()?;
        let mut aad = Vec::with_capacity(KEY_NAME_LEN + SEAL_NONCE_LEN);
        aad.extend_from_slice(&self.name);
        aad.extend_from_slice(&nonce);

        let (ciphertext, tag) =
            crate::api::aead_encrypt(SEAL_AEAD, &self.key, &nonce, &aad, &plaintext)?;

        let mut out = Vec::with_capacity(aad.len() + ciphertext.len() + tag.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// The inverse, with **one** error for every failure.
    ///
    /// A ticket that is the wrong length, sealed under another key, altered,
    /// or simply expired all come back the same way, and the caller's only
    /// response is a full handshake. Distinguishing them would tell a client
    /// which of its guesses was closest.
    pub fn open(&self, ticket: &[u8], now: i64) -> Option<Session> {
        if ticket.len() < KEY_NAME_LEN + SEAL_NONCE_LEN + SEAL_TAG_LEN {
            return None;
        }
        let (aad, rest) = ticket.split_at(KEY_NAME_LEN + SEAL_NONCE_LEN);
        if aad[..KEY_NAME_LEN] != self.name {
            return None;
        }
        let nonce = &aad[KEY_NAME_LEN..];
        let (ciphertext, tag) = rest.split_at(rest.len() - SEAL_TAG_LEN);

        let plaintext =
            crate::api::aead_decrypt(SEAL_AEAD, &self.key, nonce, aad, ciphertext, tag)
                .ok()?;
        let session = Session::decode(&plaintext).ok()?;
        // The lifetime the client was told is not a check. This is.
        if now < session.issued_at || now - session.issued_at > session.lifetime as i64 {
            return None;
        }
        Some(session)
    }
}

/// What a ticket carries, once opened.
///
/// No `Debug`: `psk` is key material.
#[derive(Clone)]
pub struct Session {
    /// The resumption PSK for this ticket, already derived with its nonce.
    pub psk: Vec<u8>,
    /// The suite code the session used. A ticket offered against a
    /// different one is refused, not reinterpreted: the hash decides the
    /// PSK's length and the whole key schedule.
    pub suite: u16,
    /// Seconds since the epoch, by the server's clock.
    pub issued_at: i64,
    /// What the client was told, and what `open` enforces.
    pub lifetime: u32,
    /// The obfuscation offset the client adds to the age it reports.
    pub age_add: u32,
    /// How much early data this ticket allows, in bytes. Zero is off, and
    /// is what every ticket said before 0-RTT existed.
    pub max_early_data: u32,
    /// The server name the original handshake was for, as the client sent
    /// it in SNI, or empty if it sent none.
    ///
    /// **Early data is sent before anything is negotiated**, so the only
    /// thing that can say what it was meant for is what the *previous*
    /// connection settled. RFC 8446 4.2.11 requires the client to offer
    /// the same parameters and the server to check them; a server that
    /// does not is one where a ticket for one virtual host replays its
    /// early data into another.
    pub server_name: Vec<u8>,
}

impl Session {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut writer = Writer::new();
        // Format version 2 added the two early-data fields. A version 1
        // ticket is not read: it is sealed under a key this process may
        // still hold, and the fields it lacks are exactly the ones that
        // decide whether early data is allowed. Refusing it costs one
        // full handshake per outstanding ticket after an upgrade.
        writer.u8(2);
        writer.u16(self.suite);
        writer.raw(&(self.issued_at as u64).to_be_bytes());
        writer.u32(self.lifetime);
        writer.u32(self.age_add);
        writer.u32(self.max_early_data);
        writer.vector8(&self.server_name).map_err(|e| e.to_string())?;
        writer.vector8(&self.psk).map_err(|e| e.to_string())?;
        Ok(writer.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Session, String> {
        let mut reader = Reader::new(bytes);
        let to_string = |e: crate::tls::codec::CodecError| e.to_string();
        let version = reader.u8().map_err(to_string)?;
        if version != 2 {
            return Err(format!("Unknown ticket format {}.", version));
        }
        let suite = reader.u16().map_err(to_string)?;
        let stamp: [u8; 8] = reader.take(8).map_err(to_string)?
            .try_into().map_err(|_| "short timestamp".to_string())?;
        let issued_at = u64::from_be_bytes(stamp) as i64;
        let lifetime = reader.u32().map_err(to_string)?;
        let age_add = reader.u32().map_err(to_string)?;
        let max_early_data = reader.u32().map_err(to_string)?;
        let server_name = reader.vector8().map_err(to_string)?.to_vec();
        let psk = reader.vector8().map_err(to_string)?.to_vec();
        Ok(Session { psk, suite, issued_at, lifetime, age_add,
                     max_early_data, server_name })
    }
}

/// Build one NewSessionTicket for a finished handshake.
///
/// `resumption_master` is the secret taken over the transcript **including
/// the client's Finished** - one message longer than the application keys'.
/// The nonce is fresh per ticket, so two tickets from one handshake carry
/// different PSKs and one being stolen does not give up the other.
#[allow(clippy::too_many_arguments)]
pub fn issue(key: &TicketKey, prf: MacAlgorithm, suite: u16,
             resumption_master: &[u8], now: i64, lifetime: u32,
             max_early_data: u32, server_name: &[u8])
             -> Result<NewSessionTicket13, String> {
    let hash = prf.hash_name().ok_or("No hash for this suite.")?;
    let nonce = random::bytes(8)?;
    let psk = keys13::resumption_psk(hash, resumption_master, &nonce)?;
    let age_add = u32::from_be_bytes(random::bytes(4)?.try_into()
        .map_err(|_| "random::bytes gave the wrong length")?);

    let session = Session { psk, suite, issued_at: now, lifetime, age_add,
                            max_early_data, server_name: server_name.to_vec() };
    Ok(NewSessionTicket13 {
        lifetime,
        age_add,
        nonce,
        ticket: key.seal(&session)?,
        // **Absent, not zero, when early data is off.** The extension not
        // being there is what tells the client not to send any; a zero
        // would be a server that offers the feature and allows nothing,
        // which some clients read as "offer it and find out".
        max_early_data: if max_early_data == 0 { None }
                        else { Some(max_early_data) },
    })
}

/// Which offered identity the server accepted, and what it decided.
pub struct Accepted {
    /// The index into the client's list, which goes back in the ServerHello.
    pub index: u16,
    pub session: Session,
}

/// Check a client's PSK offer, and return the one that works.
///
/// **The binder is the whole check.** The ticket opening proves the server
/// issued it; the binder proves the client holds the PSK inside it, over
/// *this* ClientHello. Skipping it turns a captured ticket into a session.
///
/// `truncated_transcript` is the hash of everything up to and including this
/// ClientHello **minus exactly the binder bytes**, with every length field
/// still counting them. The caller computes it, because only the caller
/// knows whether a HelloRetryRequest put a synthetic `message_hash` in front.
///
/// Returns `None` for every failure, with nothing said about which: a
/// rejected offer is a full handshake and the client learns nothing else.
pub fn accept(key: &TicketKey, offer: &crate::tls::handshake13::OfferedPsks,
              suite: u16, prf: MacAlgorithm,
              truncated_transcript: &[u8], now: i64) -> Option<Accepted> {
    let hash = prf.hash_name()?;
    if offer.identities.len() != offer.binders.len() {
        return None;
    }
    for (index, identity) in offer.identities.iter().enumerate() {
        let session = match key.open(&identity.identity, now) {
            Some(session) => session,
            None => continue,
        };
        // A ticket from another suite has a PSK of another length under
        // another hash. Refuse rather than reinterpret.
        if session.suite != suite {
            continue;
        }
        let schedule = match keys13::Schedule::early(prf, Some(&session.psk)) {
            Ok(schedule) => schedule,
            Err(_) => continue,
        };
        // `false` is "res binder" - a ticket we issued, not an external PSK.
        let binder_key = match schedule.binder_key(false) {
            Ok(key) => key,
            Err(_) => continue,
        };
        let expected = match crate::tls::resumption::binder(
            hash, &binder_key, truncated_transcript) {
            Ok(value) => value,
            Err(_) => continue,
        };
        // Constant time, because a binder comparison that returns early is
        // an oracle for guessing one byte at a time.
        if !crate::tls::keys::verify_data_matches(&expected, &offer.binders[index]) {
            continue;
        }
        return Some(Accepted { index: index as u16, session });
    }
    None
}

/// A bounded record of the binders early data has already been accepted
/// for, so the same 0-RTT flight is not run twice.
///
/// **0-RTT is replayable by construction and this does not change that.**
/// Early data is sent before the server has said anything, so there is no
/// freshness from the server in it; anyone who captured the flight can
/// send the identical bytes again, and the second copy is as valid as the
/// first. Nothing a single server can do makes that false. What a strike
/// register does is bound how *often* it works: a repeat that reaches the
/// same process within the window is refused, so a replay has to find a
/// machine that has not seen it or wait for the entry to age out.
///
/// RFC 8446 8.2 describes exactly this and says exactly this: a
/// single-machine register does not stop an attacker who can reach
/// another machine in the cluster. The guarantee to build on is not "this
/// cannot be replayed" but "the application only puts things in early
/// data that it is willing to have happen twice".
///
/// The binder is the key rather than the ticket, because the binder
/// covers *this* ClientHello: the same ticket used honestly in two
/// connections has two different binders, and only a byte-for-byte
/// replay of one hello repeats one.
///
/// **Bounded, and it forgets the oldest first.** An unbounded register is
/// memory an attacker chooses the size of. Forgetting is a hole by
/// construction, which is why the window is also bounded by the ticket
/// age check in `open`: an entry that has aged out belongs to a ticket
/// whose own lifetime is the remaining limit.
pub struct ReplayGuard {
    seen: std::collections::VecDeque<Vec<u8>>,
    capacity: usize,
}

impl ReplayGuard {
    /// A register holding at most `capacity` binders.
    ///
    /// Size it for the 0-RTT connections expected within a ticket
    /// lifetime, not for comfort: the cost of it being too small is that
    /// a replay outside the window succeeds, which is the thing it is
    /// for.
    pub fn with_capacity(capacity: usize) -> ReplayGuard {
        ReplayGuard { seen: std::collections::VecDeque::new(),
                      capacity: capacity.max(1) }
    }

    /// Record a binder, and say whether it is new.
    ///
    /// `false` means this exact flight has been accepted before and its
    /// early data must be refused - the handshake itself still proceeds,
    /// because the client may simply be retrying and a full 1-RTT
    /// handshake is always a correct answer to a 0-RTT attempt.
    pub fn accept(&mut self, binder: &[u8]) -> bool {
        // Constant time is not the criterion here: the binder is a value
        // the peer just sent us, so learning whether we have seen it is
        // learning what it already knows. What matters is that a match
        // is exact.
        if self.seen.iter().any(|seen| seen.as_slice() == binder) {
            return false;
        }
        if self.seen.len() >= self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(binder.to_vec());
        true
    }

    pub fn len(&self) -> usize { self.seen.len() }
    pub fn is_empty(&self) -> bool { self.seen.is_empty() }
}

impl Default for ReplayGuard {
    /// Enough for a few thousand 0-RTT connections inside one ticket
    /// lifetime, which is a small server's day.
    fn default() -> ReplayGuard { ReplayGuard::with_capacity(4096) }
}

/// The hash of a ClientHello with its binders removed, which is what a
/// binder covers.
///
/// **The truncation is by byte count, not by re-encoding.** The hello was
/// written with the binders in it and every length field counts them; an
/// encoder asked to leave them out produces three smaller lengths and a
/// different message. `resumption::splice_binders` is the client's side of
/// the same rule.
pub fn truncated_hash(hash_name: &str, prefix: &[u8], hello: &[u8],
                      binders_length: usize) -> Result<Vec<u8>, String> {
    if hello.len() < binders_length {
        return Err("The ClientHello is shorter than its own binders.".to_string());
    }
    let mut hasher = AnyHash::new(hash_name)?;
    hasher.update(prefix);
    hasher.update(&hello[..hello.len() - binders_length]);
    Ok(hasher.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(now: i64) -> Session {
        Session {
            psk: vec![0xab; 32],
            suite: 0x1301,
            issued_at: now,
            lifetime: DEFAULT_LIFETIME,
            age_add: 0x1234_5678,
            max_early_data: 0,
            server_name: b"localhost".to_vec(),
        }
    }

    /// A configured key must open what an identically configured one
    /// sealed - which is the whole point of `from_bytes`, and the only way
    /// resumption survives a restart or reaches a second machine.
    #[test]
    fn test_two_keys_from_the_same_bytes_agree() {
        let bytes: Vec<u8> = (0..TicketKey::byte_length() as u8).collect();
        let first = TicketKey::from_bytes(&bytes).unwrap();
        let second = TicketKey::from_bytes(&bytes).unwrap();
        let sealed = first.seal(&session(1_700_000_000)).unwrap();
        assert!(second.open(&sealed, 1_700_000_000).is_some());
        assert!(TicketKey::from_bytes(&bytes[..10]).is_err());
    }

    #[test]
    fn test_a_ticket_round_trips() {
        let key = TicketKey::generate().unwrap();
        let now = 1_700_000_000;
        let sealed = key.seal(&session(now)).unwrap();
        let opened = key.open(&sealed, now).expect("our own ticket must open");
        assert_eq!(opened.psk, vec![0xab; 32]);
        assert_eq!(opened.suite, 0x1301);
        assert_eq!(opened.issued_at, now);
        assert_eq!(opened.age_add, 0x1234_5678);
    }

    #[test]
    fn test_the_psk_is_not_in_the_clear() {
        let key = TicketKey::generate().unwrap();
        let sealed = key.seal(&session(1_700_000_000)).unwrap();
        // The whole point. A ticket that carried the PSK readably would
        // round trip perfectly and hand the session to anyone who saw it.
        assert!(!sealed.windows(32).any(|w| w == [0xab; 32]),
                "the PSK is in the ticket in the clear");
    }

    #[test]
    fn test_another_key_cannot_open_it() {
        let mine = TicketKey::generate().unwrap();
        let theirs = TicketKey::generate().unwrap();
        let sealed = mine.seal(&session(1_700_000_000)).unwrap();
        assert!(theirs.open(&sealed, 1_700_000_000).is_none());
    }

    /// Every byte of a ticket is authenticated, including the key name and
    /// the nonce - which are in the clear and so are the ones somebody would
    /// try first.
    #[test]
    fn test_no_single_byte_can_be_changed() {
        let key = TicketKey::generate().unwrap();
        let now = 1_700_000_000;
        let sealed = key.seal(&session(now)).unwrap();
        for index in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[index] ^= 1;
            assert!(key.open(&altered, now).is_none(),
                    "byte {} could be flipped and the ticket still opened", index);
        }
    }

    #[test]
    fn test_an_expired_ticket_does_not_open() {
        let key = TicketKey::generate().unwrap();
        let now = 1_700_000_000;
        let sealed = key.seal(&session(now)).unwrap();
        assert!(key.open(&sealed, now + DEFAULT_LIFETIME as i64 - 1).is_some());
        assert!(key.open(&sealed, now + DEFAULT_LIFETIME as i64 + 1).is_none(),
                "the lifetime the client was told is not the check");
        // A clock that went backwards is not a licence either.
        assert!(key.open(&sealed, now - 1).is_none());
    }

    #[test]
    fn test_a_truncated_or_empty_ticket_is_refused() {
        let key = TicketKey::generate().unwrap();
        let sealed = key.seal(&session(1_700_000_000)).unwrap();
        assert!(key.open(&[], 1_700_000_000).is_none());
        assert!(key.open(&sealed[..sealed.len() - 1], 1_700_000_000).is_none());
        assert!(key.open(&sealed[1..], 1_700_000_000).is_none());
    }

    /// Two tickets from one handshake must carry different PSKs, so that one
    /// being stolen does not give up the other.
    #[test]
    fn test_two_tickets_differ() {
        let key = TicketKey::generate().unwrap();
        let master = vec![0x11; 32];
        let first = issue(&key, MacAlgorithm::Sha256, 0x1301, &master,
                          1_700_000_000, DEFAULT_LIFETIME, 0, b"localhost").unwrap();
        let second = issue(&key, MacAlgorithm::Sha256, 0x1301, &master,
                           1_700_000_000, DEFAULT_LIFETIME, 0, b"localhost").unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ticket, second.ticket);
        let one = key.open(&first.ticket, 1_700_000_000).unwrap();
        let two = key.open(&second.ticket, 1_700_000_000).unwrap();
        assert_ne!(one.psk, two.psk, "a shared PSK makes one theft into two");
    }

    /// Build a genuine offer for a ticket, with a correct binder.
    fn offer_for(key: &TicketKey, ticket: &[u8], psk: &[u8], prf: MacAlgorithm,
                 transcript: &[u8])
                 -> crate::tls::handshake13::OfferedPsks {
        let _ = key;
        let hash = prf.hash_name().unwrap();
        let schedule = keys13::Schedule::early(prf, Some(psk)).unwrap();
        let binder_key = schedule.binder_key(false).unwrap();
        let value = crate::tls::resumption::binder(hash, &binder_key, transcript)
            .unwrap();
        crate::tls::handshake13::OfferedPsks {
            identities: vec![crate::tls::handshake13::PskIdentity {
                identity: ticket.to_vec(),
                obfuscated_ticket_age: 0,
            }],
            binders: vec![value],
        }
    }

    /// **The binder is the whole security property of resumption**, and no
    /// handshake test can check it: an honest client always sends a correct
    /// one, so deleting the check leaves every OpenSSL resumption test
    /// passing. It did, in the sweep for this commit - seven of seven.
    ///
    /// What the check stops is somebody replaying a ticket they captured.
    /// The ticket proves the *server* issued it; only the binder proves the
    /// client holds the PSK sealed inside it, over this ClientHello.
    #[test]
    fn test_a_wrong_binder_is_refused() {
        let key = TicketKey::generate().unwrap();
        let now = 1_700_000_000;
        let prf = MacAlgorithm::Sha256;
        let suite = 0x1301;
        let issued = issue(&key, prf, suite, &[0x11; 32], now,
                           DEFAULT_LIFETIME, 0, b"localhost").unwrap();
        let psk = key.open(&issued.ticket, now).unwrap().psk;
        let transcript = vec![0x77; 32];

        let good = offer_for(&key, &issued.ticket, &psk, prf, &transcript);
        assert!(accept(&key, &good, suite, prf, &transcript, now).is_some(),
                "the honest case must work, or the rest proves nothing");

        // Every single bit of the binder is load bearing.
        for index in 0..good.binders[0].len() {
            let mut altered = good.binders[0].clone();
            altered[index] ^= 1;
            let offer = crate::tls::handshake13::OfferedPsks {
                identities: good.identities.clone(),
                binders: vec![altered],
            };
            assert!(accept(&key, &offer, suite, prf, &transcript, now).is_none(),
                    "binder byte {} could be flipped and the offer accepted",
                    index);
        }

        // A binder that is correct for *another* ClientHello. This is the
        // replay: the ticket is genuine and the binder is genuine, and they
        // do not belong to this handshake.
        let elsewhere = vec![0x88; 32];
        assert!(accept(&key, &good, suite, prf, &elsewhere, now).is_none(),
                "a binder from another transcript was accepted");

        // An empty binder, which is what a client that computed nothing
        // would send.
        let empty = crate::tls::handshake13::OfferedPsks {
            identities: good.identities.clone(),
            binders: vec![Vec::new()],
        };
        assert!(accept(&key, &empty, suite, prf, &transcript, now).is_none());
    }

    /// A ticket issued for one suite must not be usable under another: the
    /// PSK's length and the whole schedule come from the hash.
    #[test]
    fn test_a_ticket_from_another_suite_is_refused() {
        let key = TicketKey::generate().unwrap();
        let now = 1_700_000_000;
        let issued = issue(&key, MacAlgorithm::Sha256, 0x1301, &[0x11; 32], now,
                           DEFAULT_LIFETIME, 0, b"localhost").unwrap();
        let psk = key.open(&issued.ticket, now).unwrap().psk;
        let transcript = vec![0x77; 32];
        let offer = offer_for(&key, &issued.ticket, &psk, MacAlgorithm::Sha256,
                              &transcript);
        assert!(accept(&key, &offer, 0x1301, MacAlgorithm::Sha256,
                       &transcript, now).is_some());
        assert!(accept(&key, &offer, 0x1302, MacAlgorithm::Sha384,
                       &transcript, now).is_none(),
                "a ticket was reinterpreted under another suite");
    }

    /// A mismatched number of identities and binders is a malformed offer,
    /// not something to index into.
    #[test]
    fn test_a_lopsided_offer_is_refused() {
        let key = TicketKey::generate().unwrap();
        let now = 1_700_000_000;
        let issued = issue(&key, MacAlgorithm::Sha256, 0x1301, &[0x11; 32], now,
                           DEFAULT_LIFETIME, 0, b"localhost").unwrap();
        let offer = crate::tls::handshake13::OfferedPsks {
            identities: vec![crate::tls::handshake13::PskIdentity {
                identity: issued.ticket.clone(),
                obfuscated_ticket_age: 0,
            }],
            binders: Vec::new(),
        };
        assert!(accept(&key, &offer, 0x1301, MacAlgorithm::Sha256,
                       &[0x77; 32], now).is_none());
    }

    #[test]
    fn test_no_early_data_is_offered() {
        let key = TicketKey::generate().unwrap();
        let ticket = issue(&key, MacAlgorithm::Sha256, 0x1301, &[0x11; 32],
                           1_700_000_000, DEFAULT_LIFETIME, 0, b"localhost").unwrap();
        // Absent, not zero: the extension's absence is what says "no early
        // data", and a zero would offer the feature and allow nothing.
        assert!(ticket.max_early_data.is_none());
    }

    #[test]
    fn test_early_data_is_offered_when_configured() {
        let key = TicketKey::generate().unwrap();
        let ticket = issue(&key, MacAlgorithm::Sha256, 0x1301, &[0x11; 32],
                           1_700_000_000, DEFAULT_LIFETIME, 16_384,
                           b"example.test").unwrap();
        assert_eq!(ticket.max_early_data, Some(16_384));
        let session = key.open(&ticket.ticket, 1_700_000_000).unwrap();
        // And the limit is *in the ticket* as well as in the extension.
        // The extension is what the client was told; the sealed copy is
        // what the server enforces, and a server that trusted the client's
        // copy would be trusting a number it handed out and can no longer
        // see.
        assert_eq!(session.max_early_data, 16_384);
        assert_eq!(session.server_name, b"example.test");
    }

    /// The name is sealed because early data arrives before anything is
    /// negotiated, so nothing in the new connection can say what it was
    /// meant for. Without it a ticket from one virtual host replays its
    /// early data into another.
    #[test]
    fn test_the_server_name_survives_the_round_trip() {
        let key = TicketKey::generate().unwrap();
        let mut original = session(1_700_000_000);
        original.server_name = b"one.example".to_vec();
        original.max_early_data = 99;
        let opened = key.open(&key.seal(&original).unwrap(), 1_700_000_000)
            .unwrap();
        assert_eq!(opened.server_name, b"one.example");
        assert_eq!(opened.max_early_data, 99);
    }

    /// A register that does not forget is memory an attacker sizes, and
    /// one that forgets is a hole. Both halves are asserted, so a change
    /// to either is a failure rather than a surprise.
    #[test]
    fn test_the_replay_guard_refuses_a_repeat_and_forgets_the_oldest() {
        let mut guard = ReplayGuard::with_capacity(2);
        assert!(guard.accept(b"first"));
        assert!(!guard.accept(b"first"), "a repeat must be refused");
        assert!(guard.accept(b"second"));
        assert!(guard.accept(b"third"));         // evicts "first"
        assert_eq!(guard.len(), 2);
        assert!(guard.accept(b"first"),
                "the oldest is forgotten, which is the bounded part");
        assert!(!guard.accept(b"third"));
    }
}
