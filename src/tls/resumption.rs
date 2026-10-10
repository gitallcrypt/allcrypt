/*
TLS 1.3 session resumption: tickets, pre-shared keys and binders.

RFC 8446 section 2.2. A server that has finished a handshake may hand
out a `NewSessionTicket`; a client that kept one may offer it in a later
ClientHello and skip the certificate, the signature and a round trip.

What is stored is not the ticket. It is the ticket **and** a key derived
from the connection that issued it, and the two travel separately: the
ticket goes on the wire as an identity and the key never does. That is
the whole construction, and it is why `Ticket` holds a `psk` that must
be treated like any other key.

## The pieces, and how each one fails

**The PSK is derived per ticket.**

    PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
                            ticket_nonce, Hash.length)

An `Expand-Label` with the nonce as the *context*, not a
`Derive-Secret`. The two differ only in whether the context is hashed
first, so writing one for the other compiles and produces a PSK the
server has never heard of.

**The binder is an HMAC over a truncated ClientHello.** RFC 8446
4.2.11.2: over "a partial ClientHello up to and including the
PreSharedKeyExtension.identities field", with "the length fields for the
message (including the overall length, the length of the extensions
block, and the length of the pre_shared_key extension) ... all set as if
binders of the correct lengths were present".

So the transcript is the *whole* hello with exactly the binder bytes
removed from the end, and every length in it still counts them. An
implementation that re-encoded the hello without the binders gets three
length fields smaller and produces a binder that is perfectly
self-consistent and that no server accepts. That is why
`truncated_transcript` slices rather than rebuilding, and why
`OfferedPsks::binders_length` exists.

**The binder key is derived with an empty context.**
`Derive-Secret(Early, "res binder", "")` - the empty *string*, so
`Hash("")`, not the hello. The hello goes into the HMAC.

**The pre_shared_key extension must be last in the ClientHello**, and a
server must reject one that is not. That is not decoration: the
truncation above is only well defined if the binders are the last bytes
of the message.

**A ticket is bound to a hash, not to a suite.** RFC 8446 4.6.1: "Any
ticket MUST only be resumed with a cipher suite that has the same KDF
hash algorithm as that used to establish the original connection." So a
ticket from a SHA-384 suite cannot be offered to a SHA-256 one, and
offering it anyway produces a binder of the wrong length that the server
cannot even parse.

**The age is obfuscated, and in milliseconds.** The ticket's age in
milliseconds plus `ticket_age_add` modulo 2^32. The lifetime in the
message is in *seconds* and the age on the wire is in milliseconds; a
thousandfold error here makes every ticket look either brand new or
expired, and a server that checks the age against its own record rejects
it with no explanation.

## What a caller has to do

Keep the tickets somewhere, and hand them back. Nothing here is a cache:
there is no clock in this library and no storage in it either, so
`Connection::tickets()` hands out what arrived and
`ClientConfig::tickets` takes back what to offer. A caller that stores
them on disk is storing key material and should know it.

**Do not offer one ticket twice.** RFC 8446 appendix C.4: reusing a
ticket lets a passive observer link the two connections, which is
exactly what `ticket_age_add` exists to prevent. Servers usually refuse
a reuse anyway, so the cost of getting this wrong is a failed
resumption and a privacy leak rather than a broken connection - which is
the kind of bug that survives.
*/

use crate::api::AnyHash;
use crate::hash_functions::HashFunction;
use crate::mac::hmac::Hmac;
use crate::tls::codec::{Reader, Writer};
use crate::tls::handshake13::{NewSessionTicket13, OfferedPsks, PskIdentity};
use crate::tls::keys13::{resumption_psk, Schedule};
use crate::tls::suites::MacAlgorithm;
use crate::Mac;

/// The longest a client may keep a ticket, whatever the server said.
///
/// RFC 8446 4.6.1: "Clients MUST NOT cache tickets for longer than 7
/// days, regardless of the ticket_lifetime". A server that asks for
/// longer is capped rather than refused.
pub const MAX_TICKET_LIFETIME: u32 = 604_800;

/// What a stored ticket starts with, so one from another version - or
/// from something else entirely - is refused rather than misread.
const TICKET_MAGIC: &[u8] = b"allcrypt-ticket-1";

/// Everything needed to offer one PSK, and the key itself.
///
/// **This holds key material.** A `Ticket` is as sensitive as a session
/// key: anybody with one can resume the connection it came from. The
/// `Debug` impl prints no secrets for that reason.
#[derive(Clone)]
pub struct Ticket {
    /// The opaque identity to send back - the server's own state.
    pub identity: Vec<u8>,
    /// The PSK derived from the issuing connection. Never sent.
    pub psk: Vec<u8>,
    /// The KDF hash of the suite that issued it. A ticket may only be
    /// resumed with a suite whose hash is this one.
    pub hash: &'static str,
    /// The suite it was issued under, for reporting.
    pub suite: u16,
    /// Seconds from issuance, already capped at seven days.
    pub lifetime: u32,
    /// Added to the age, modulo 2^32, to obfuscate it.
    pub age_add: u32,
    /// When it arrived, in seconds since the epoch, from the caller's
    /// own clock - there is none in this library.
    pub issued_at: i64,
    /// How much 0-RTT data the server will accept under it, if any.
    /// `None` means the server did not offer early data.
    pub max_early_data: Option<u32>,
    /// The host it was issued by. RFC 8446 4.6.1 tells clients to store
    /// it and only resume against the same name.
    pub hostname: String,
}

impl core::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ticket {{ {} bytes for {:?}, {}, lifetime {}s, psk redacted }}",
               self.identity.len(), self.hostname, self.hash, self.lifetime)
    }
}

impl Ticket {
    /// Build one from a `NewSessionTicket` and the connection that
    /// issued it.
    ///
    /// `now` is the caller's clock in seconds. `resumption_master` is
    /// the connection's resumption master secret, over the transcript
    /// through the *client's* Finished.
    pub fn from_message(message: &NewSessionTicket13, resumption_master: &[u8],
                        hash: &'static str, suite: u16, hostname: &str,
                        now: i64) -> Result<Ticket, String> {
        // A zero lifetime means "discard immediately", so there is
        // nothing to build. Refused rather than stored with a lifetime
        // of zero, because a stored one is a thing a caller can offer.
        if message.lifetime == 0 {
            return Err("The ticket's lifetime is zero, which RFC 8446 4.6.1 \
                        says means discard it immediately.".to_string());
        }
        let psk = resumption_psk(hash, resumption_master, &message.nonce)?;
        Ok(Ticket {
            identity: message.ticket.clone(),
            psk,
            hash,
            suite,
            lifetime: message.lifetime.min(MAX_TICKET_LIFETIME),
            age_add: message.age_add,
            issued_at: now,
            max_early_data: message.max_early_data,
            hostname: hostname.to_string(),
        })
    }

    /// Whether this ticket is still within its lifetime at `now`.
    ///
    /// A ticket from the future - which is what a clock that went
    /// backwards looks like - is not usable either, because its age
    /// would go on the wire as an enormous number and the server would
    /// refuse it.
    pub fn is_usable_at(&self, now: i64) -> bool {
        now >= self.issued_at
            && now - self.issued_at <= i64::from(self.lifetime)
    }

    /// The `obfuscated_ticket_age` for this moment.
    ///
    /// **Milliseconds**, plus `age_add`, modulo 2^32. The lifetime
    /// above is in seconds and this is not; the two units live one
    /// field apart in the same message.
    pub fn obfuscated_age(&self, now: i64) -> u32 {
        let seconds = (now - self.issued_at).max(0);
        // Saturating rather than wrapping: a caller with a wild clock
        // gets a large age and a refused resumption, not a small one
        // that looks fresh.
        let milliseconds = (seconds as u64).saturating_mul(1000);
        (milliseconds as u32).wrapping_add(self.age_add)
    }

    /// The ticket as one opaque blob, for a caller that has to store
    /// it.
    ///
    /// **This is key material in a byte string.** It is not encrypted
    /// and not authenticated: anybody who can read it can resume the
    /// connection it came from, and anybody who can write it chooses
    /// the PSK for a connection that will then appear to have resumed.
    /// Somewhere only the owner can read.
    ///
    /// Self-describing and versioned, so a stored ticket from an older
    /// build is refused rather than misread - a PSK read at the wrong
    /// offset produces a binder that fails, which looks like a server
    /// problem.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut writer = Writer::new();
        writer.raw(TICKET_MAGIC);
        writer.vector8(self.hash.as_bytes()).map_err(|e| e.describe())?;
        writer.u16(self.suite);
        writer.u32(self.lifetime);
        writer.u32(self.age_add);
        writer.raw(&self.issued_at.to_be_bytes());
        match self.max_early_data {
            Some(max) => { writer.u8(1); writer.u32(max); }
            None => writer.u8(0),
        }
        writer.vector16(&self.identity).map_err(|e| e.describe())?;
        writer.vector8(&self.psk).map_err(|e| e.describe())?;
        writer.vector16(self.hostname.as_bytes()).map_err(|e| e.describe())?;
        Ok(writer.finish())
    }

    /// The inverse. Refuses anything it does not recognise rather than
    /// guessing.
    pub fn decode(bytes: &[u8]) -> Result<Ticket, String> {
        let mut reader = Reader::new(bytes);
        let magic = reader.take(TICKET_MAGIC.len()).map_err(|e| e.describe())?;
        if magic != TICKET_MAGIC {
            return Err("This is not a stored session ticket from this \
                        library, or it is from a version that stored them \
                        differently.".to_string());
        }
        let hash = reader.vector8().map_err(|e| e.describe())?;
        // Interned, because `Ticket::hash` is `&'static str` - the key
        // schedule takes names by reference and the set is closed. The
        // set is **the one `tls13_hash_name` produces**, reached through
        // its inverse, so this decoder accepts exactly what `encode`
        // can write: a list kept here named SHA-256 and SHA-384 only,
        // and a ticket from an RFC 9367 (Streebog-256) connection was
        // written, stored, and refused on reload as "not one TLS 1.3
        // uses".
        let hash = core::str::from_utf8(hash).map_err(|_| format!(
            "A stored ticket's hash name is not UTF-8: {:?}.", hash))?;
        let hash = MacAlgorithm::for_tls13_hash(hash)
            .and_then(crate::tls::handshake13::tls13_hash_name)
            .map_err(|e| format!("A stored ticket names hash {:?}: {}", hash, e))?;
        let suite = reader.u16().map_err(|e| e.describe())?;
        let lifetime = reader.u32().map_err(|e| e.describe())?;
        let age_add = reader.u32().map_err(|e| e.describe())?;
        let issued = reader.take(8).map_err(|e| e.describe())?;
        let issued_at = i64::from_be_bytes(issued.try_into()
            .map_err(|_| "A stored ticket's timestamp is malformed."
                     .to_string())?);
        let max_early_data = match reader.u8().map_err(|e| e.describe())? {
            0 => None,
            1 => Some(reader.u32().map_err(|e| e.describe())?),
            other => return Err(format!(
                "A stored ticket's early-data flag is {}, not 0 or 1.", other)),
        };
        let identity = reader.vector16().map_err(|e| e.describe())?.to_vec();
        let psk = reader.vector8().map_err(|e| e.describe())?.to_vec();
        let hostname = reader.vector16().map_err(|e| e.describe())?;
        let hostname = core::str::from_utf8(hostname)
            .map_err(|_| "A stored ticket's hostname is not UTF-8.".to_string())?
            .to_string();
        reader.expect_empty("stored ticket").map_err(|e| e.describe())?;

        if psk.is_empty() || identity.is_empty() {
            return Err("A stored ticket has an empty key or identity."
                       .to_string());
        }
        Ok(Ticket { identity, psk, hash, suite, lifetime, age_add, issued_at,
                    max_early_data, hostname })
    }

    /// Whether this ticket may be offered to a suite using `hash`.
    ///
    /// RFC 8446 4.6.1 ties a ticket to the KDF hash of the connection
    /// that issued it, and the binder's length follows from that - so
    /// offering it to a suite with a different hash sends a binder the
    /// server cannot parse.
    pub fn matches_hash(&self, hash: &str) -> bool {
        self.hash == hash
    }
}

/// A PSK offer under construction: the identities and the binder keys
/// they will be bound with.
///
/// Two steps, because the binder covers a hello that cannot be written
/// until the identities are in it. `identities` goes into the hello with
/// placeholder binders of the right length; then the hello's own bytes
/// are the transcript for `seal`.
pub struct Offer {
    /// The hash every offered ticket shares. A single offer cannot mix
    /// hashes: the binders would be different lengths and the
    /// transcript is one hash.
    pub hash: &'static str,
    pub identities: Vec<PskIdentity>,
    /// One binder key per identity, in the same order.
    binder_keys: Vec<Vec<u8>>,
}

impl Offer {
    /// Prepare an offer from tickets already filtered to one hash.
    pub fn new(tickets: &[&Ticket], now: i64) -> Result<Offer, String> {
        let first = tickets.first()
            .ok_or_else(|| "An offer with no tickets is not an offer."
                        .to_string())?;
        let hash = first.hash;
        if tickets.iter().any(|ticket| ticket.hash != hash) {
            return Err("All the tickets in one pre_shared_key extension must \
                        share a hash: the binders are that hash's length and \
                        the transcript is hashed with it once.".to_string());
        }
        let prf = MacAlgorithm::for_tls13_hash(hash)?;

        let mut identities = Vec::new();
        let mut binder_keys = Vec::new();
        for ticket in tickets {
            identities.push(PskIdentity {
                identity: ticket.identity.clone(),
                obfuscated_ticket_age: ticket.obfuscated_age(now),
            });
            let early = Schedule::early(prf, Some(&ticket.psk))?;
            binder_keys.push(early.binder_key(false)?);
        }
        Ok(Offer { hash, identities, binder_keys })
    }

    /// The extension body with binders of the right length, all zero.
    ///
    /// What goes into the hello before the binders are known. The
    /// lengths are final: the real binders replace these bytes in place
    /// and nothing else moves.
    pub fn placeholder(&self) -> Result<OfferedPsks, String> {
        let length = crate::tls::keys13::empty_hash(self.hash)?.len();
        Ok(OfferedPsks {
            identities: self.identities.clone(),
            binders: vec![vec![0u8; length]; self.identities.len()],
        })
    }

    /// The binders, over a ClientHello whose binder bytes have been cut
    /// off the end.
    ///
    /// `truncated` is the transcript **through** the identities: for a
    /// first flight that is the hello minus its binders, and after a
    /// HelloRetryRequest it is
    /// `message_hash || HelloRetryRequest || Truncate(ClientHello2)` -
    /// the same slicing applied to the whole prefix.
    pub fn seal(&self, truncated: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let mut hasher = AnyHash::new(self.hash)?;
        hasher.update(truncated);
        let transcript = hasher.digest();

        self.binder_keys.iter()
            .map(|key| binder(self.hash, key, &transcript))
            .collect()
    }
}

/// One binder value.
///
/// "computed in the same way as the Finished message but with the
/// BaseKey being the binder_key" - so `HMAC(HKDF-Expand-Label(binder_key,
/// "finished", "", Hash.length), transcript_hash)`. The intermediate
/// `finished` key is not optional and is the step most easily skipped:
/// HMACing under the binder key directly gives a value of the right
/// length.
pub fn binder(hash_name: &str, binder_key: &[u8], transcript_hash: &[u8])
              -> Result<Vec<u8>, String> {
    let length = crate::tls::keys13::empty_hash(hash_name)?.len();
    let finished_key = crate::tls::keys13::expand_label(
        hash_name, binder_key, b"finished", b"", length)?;
    let mut mac = Hmac::new(AnyHash::new(hash_name)?, &finished_key);
    mac.update(transcript_hash);
    Ok(mac.digest())
}

/// Replace the binder bytes at the end of an encoded ClientHello.
///
/// The hello was written with placeholders of exactly these lengths, so
/// this overwrites in place and moves nothing. Taking the hello's own
/// bytes rather than re-encoding is the point: re-encoding is how the
/// three length fields end up disagreeing with what the binder covered.
pub fn splice_binders(hello: &mut [u8], binders: &[Vec<u8>])
                      -> Result<(), String> {
    let total: usize = 2 + binders.iter().map(|b| 1 + b.len()).sum::<usize>();
    if hello.len() < total {
        return Err(format!("A ClientHello of {} bytes cannot end in {} bytes \\
                            of binders.", hello.len(), total));
    }
    let mut at = hello.len() - total;
    // The list's own two length bytes, then each entry's one.
    let listed = (total - 2) as u16;
    if hello[at..at + 2] != listed.to_be_bytes() {
        return Err("The placeholder binder list in the ClientHello is not \
                    where it was expected; splicing would corrupt the \
                    message.".to_string());
    }
    at += 2;
    for value in binders {
        if usize::from(hello[at]) != value.len() {
            return Err("A placeholder binder is a different length from the \
                        one computed for it.".to_string());
        }
        at += 1;
        hello[at..at + value.len()].copy_from_slice(value);
        at += value.len();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(hash: &'static str, issued_at: i64, lifetime: u32) -> Ticket {
        Ticket {
            identity: vec![1, 2, 3, 4],
            psk: vec![0x42; 32],
            hash,
            suite: 0x1301,
            lifetime,
            age_add: 0x1000_0000,
            issued_at,
            max_early_data: None,
            hostname: "example.test".to_string(),
        }
    }

    /// **The age is in milliseconds and the lifetime is in seconds.**
    /// The two fields live next to each other in one message, and a
    /// thousandfold error makes every ticket look brand new or ancient.
    #[test]
    fn test_the_age_is_in_milliseconds_and_obfuscated() {
        let ticket = ticket("sha256", 1_000_000, 3600);
        // Ten seconds later: ten thousand milliseconds, plus the add.
        assert_eq!(ticket.obfuscated_age(1_000_010),
                   10_000u32.wrapping_add(0x1000_0000));
        // At the instant of issue the age is zero and only the add
        // shows - which is what makes two offers of one ticket
        // linkable, and why a ticket is offered once.
        assert_eq!(ticket.obfuscated_age(1_000_000), 0x1000_0000);
    }

    /// The addition wraps at 2^32 rather than saturating, because that
    /// is what the server undoes.
    #[test]
    fn test_the_age_wraps_rather_than_saturating() {
        let mut ticket = ticket("sha256", 0, 604_800);
        ticket.age_add = 0xFFFF_FFFF;
        // One second is a thousand milliseconds, so the sum is 999.
        assert_eq!(ticket.obfuscated_age(1), 999);
    }

    /// A clock that went backwards must not produce a *small* age,
    /// which would look fresh.
    #[test]
    fn test_a_backwards_clock_does_not_look_fresh() {
        let ticket = ticket("sha256", 1_000_000, 3600);
        assert_eq!(ticket.obfuscated_age(999_000), 0x1000_0000);
        assert!(!ticket.is_usable_at(999_000));
    }

    #[test]
    fn test_a_ticket_expires() {
        let ticket = ticket("sha256", 1_000, 60);
        assert!(ticket.is_usable_at(1_000));
        assert!(ticket.is_usable_at(1_060));
        assert!(!ticket.is_usable_at(1_061));
    }

    /// Seven days, whatever the server asked for.
    #[test]
    fn test_the_lifetime_is_capped_at_a_week() {
        let message = NewSessionTicket13 {
            lifetime: 30 * 24 * 3600,
            age_add: 7,
            nonce: vec![0],
            ticket: vec![9, 9],
            max_early_data: None,
        };
        let built = Ticket::from_message(&message, &[0x11; 32], "sha256",
                                         0x1301, "example.test", 0).unwrap();
        assert_eq!(built.lifetime, MAX_TICKET_LIFETIME);
    }

    /// A zero lifetime means discard at once, so there is nothing to
    /// store - and a stored one is a thing a caller can offer.
    #[test]
    fn test_a_zero_lifetime_ticket_is_refused() {
        let message = NewSessionTicket13 {
            lifetime: 0,
            age_add: 7,
            nonce: vec![0],
            ticket: vec![9, 9],
            max_early_data: None,
        };
        assert!(Ticket::from_message(&message, &[0x11; 32], "sha256", 0x1301,
                                     "example.test", 0).is_err());
    }

    /// **The nonce makes each ticket's PSK different.** Two tickets from
    /// one connection with the same nonce would be the same key, which
    /// is the whole reason the field exists.
    #[test]
    fn test_the_nonce_changes_the_psk() {
        let master = [0x33u8; 32];
        let make = |nonce: Vec<u8>| {
            let message = NewSessionTicket13 {
                lifetime: 3600, age_add: 0, nonce, ticket: vec![1],
                max_early_data: None,
            };
            Ticket::from_message(&message, &master, "sha256", 0x1301,
                                 "example.test", 0).unwrap().psk
        };
        assert_ne!(make(vec![0]), make(vec![1]));
        assert_ne!(make(vec![]), make(vec![0]));
        assert_eq!(make(vec![7]), make(vec![7]));

        // And it is an Expand-Label with the nonce as context, not a
        // Derive-Secret - which would hash the nonce first. The two
        // differ only in that, so this pins which.
        let hashed = {
            let mut hasher = AnyHash::new("sha256").unwrap();
            hasher.update(&[7u8]);
            crate::tls::keys13::expand_label("sha256", &master, b"resumption",
                                             &hasher.digest(), 32).unwrap()
        };
        assert_ne!(make(vec![7]), hashed);
    }

    /// A binder under the binder key directly is the mistake: the
    /// intermediate `finished` key is a whole extra Expand-Label and
    /// leaving it out gives a value of exactly the right length.
    #[test]
    fn test_the_binder_goes_through_a_finished_key() {
        let key = [0x55u8; 32];
        let transcript = [0x66u8; 32];
        let proper = binder("sha256", &key, &transcript).unwrap();

        let shortcut = {
            let mut mac = Hmac::new(AnyHash::new("sha256").unwrap(), &key);
            mac.update(&transcript);
            mac.digest()
        };
        assert_eq!(proper.len(), shortcut.len());
        assert_ne!(proper, shortcut);
    }

    /// The two binder labels are for two different kinds of PSK, and
    /// they differ only in a string - so using one for the other fails
    /// silently at the far end.
    #[test]
    fn test_the_two_binder_labels_give_different_keys() {
        let early = Schedule::early(MacAlgorithm::Sha256, Some(&[0x77; 32]))
                    .unwrap();
        assert_ne!(early.binder_key(false).unwrap(),
                   early.binder_key(true).unwrap());
    }

    /// An offer cannot mix hashes: the binders would be different
    /// lengths and the transcript is hashed once.
    #[test]
    fn test_an_offer_cannot_mix_hashes() {
        let one = ticket("sha256", 0, 3600);
        let two = ticket("sha384", 0, 3600);
        assert!(Offer::new(&[&one, &two], 0).is_err());
        assert!(Offer::new(&[&one], 0).is_ok());
        assert!(Offer::new(&[], 0).is_err());
    }

    /// The placeholder binders are the hash's length, which is what
    /// makes the splice a replacement rather than a rewrite.
    #[test]
    fn test_the_placeholder_is_the_right_shape() {
        for (hash, length) in [("sha256", 32usize), ("sha384", 48)] {
            let offer = Offer::new(&[&ticket(hash, 0, 3600)], 0).unwrap();
            let placeholder = offer.placeholder().unwrap();
            assert_eq!(placeholder.binders.len(), 1);
            assert_eq!(placeholder.binders[0].len(), length);
            assert_eq!(placeholder.binders_length(), 2 + 1 + length);

            let sealed = offer.seal(b"a truncated hello").unwrap();
            assert_eq!(sealed.len(), 1);
            assert_eq!(sealed[0].len(), length);
            assert_ne!(sealed[0], placeholder.binders[0]);
        }
    }

    /// Splicing replaces exactly the binder bytes and moves nothing.
    #[test]
    fn test_splicing_replaces_in_place() {
        let offer = Offer::new(&[&ticket("sha256", 0, 3600)], 0).unwrap();
        let placeholder = offer.placeholder().unwrap();
        let body = placeholder.encode().unwrap();

        // A pretend hello: some bytes, then the extension body.
        let mut hello = vec![0xAA; 20];
        hello.extend_from_slice(&body);
        let before = hello.clone();

        let binders = offer.seal(b"whatever").unwrap();
        splice_binders(&mut hello, &binders).unwrap();

        let cut = hello.len() - placeholder.binders_length();
        assert_eq!(hello[..cut], before[..cut],
                   "splicing changed bytes before the binders");
        assert_eq!(&hello[hello.len() - 32..], &binders[0][..]);
    }

    /// And a hello whose tail is not a binder list is refused rather
    /// than corrupted.
    #[test]
    fn test_splicing_refuses_a_hello_that_does_not_end_in_binders() {
        let offer = Offer::new(&[&ticket("sha256", 0, 3600)], 0).unwrap();
        let binders = offer.seal(b"whatever").unwrap();

        let mut nonsense = vec![0xAA; 100];
        assert!(splice_binders(&mut nonsense, &binders).is_err());

        let mut tiny = vec![0xAA; 4];
        assert!(splice_binders(&mut tiny, &binders).is_err());
    }

    /// Two tickets in one offer get two binders, in the identities'
    /// order - and different ones, since the keys differ.
    #[test]
    fn test_two_tickets_get_two_binders_in_order() {
        let mut one = ticket("sha256", 0, 3600);
        one.identity = vec![1];
        let mut two = ticket("sha256", 0, 3600);
        two.identity = vec![2];
        two.psk = vec![0x99; 32];

        let offer = Offer::new(&[&one, &two], 0).unwrap();
        assert_eq!(offer.identities[0].identity, vec![1]);
        assert_eq!(offer.identities[1].identity, vec![2]);

        let binders = offer.seal(b"hello").unwrap();
        assert_eq!(binders.len(), 2);
        assert_ne!(binders[0], binders[1]);
    }

    /// Debug must not print the PSK. A `Ticket` in a log is a session
    /// key in a log.
    #[test]
    fn test_debug_prints_no_key_material() {
        let ticket = ticket("sha256", 0, 3600);
        let printed = format!("{:?}", ticket);
        assert!(printed.contains("redacted"), "{}", printed);
        assert!(!printed.contains("66"), "{}", printed);   // 0x42 in decimal
        assert!(!printed.contains("0x42"), "{}", printed);
    }

    /// A stored ticket round trips, and one that has been touched is
    /// refused rather than misread - a PSK read at the wrong offset
    /// gives a binder that fails, which looks like a server problem.
    #[test]
    fn test_a_ticket_round_trips_through_its_stored_form() {
        let mut original = ticket("sha384", 1_234_567, 7_200);
        original.max_early_data = Some(16384);
        original.identity = vec![9; 300];        // past a one byte length
        original.psk = vec![0xAB; 48];

        let stored = original.encode().unwrap();
        let back = Ticket::decode(&stored).unwrap();
        assert_eq!(back.identity, original.identity);
        assert_eq!(back.psk, original.psk);
        assert_eq!(back.hash, "sha384");
        assert_eq!(back.suite, original.suite);
        assert_eq!(back.lifetime, original.lifetime);
        assert_eq!(back.age_add, original.age_add);
        assert_eq!(back.issued_at, original.issued_at);
        assert_eq!(back.max_early_data, Some(16384));
        assert_eq!(back.hostname, original.hostname);

        // A negative timestamp - which is a clock before 1970, and a
        // thing that happens on embedded hardware - survives, rather
        // than becoming an enormous positive one.
        let mut ancient = ticket("sha256", -86_400, 3_600);
        ancient.max_early_data = None;
        let back = Ticket::decode(&ancient.encode().unwrap()).unwrap();
        assert_eq!(back.issued_at, -86_400);
        assert_eq!(back.max_early_data, None);
    }

    /// A stored ticket round trips under **every** hash a TLS 1.3 suite
    /// here can have, not only the two SHA-2 ones.
    ///
    /// What was wrong: `encode` wrote whatever `Ticket::hash` held and
    /// `decode` interned only `sha256` and `sha384`, so a ticket issued
    /// on an RFC 9367 suite - whose hash is Streebog-256 - was written
    /// and then refused on reload as naming a hash TLS 1.3 does not use.
    /// The round-trip test above used SHA-384, and the GOST 1.3 tests
    /// resume nothing, so the two ends of the storage format were never
    /// compared on the third name. The list of names is taken from the
    /// suite table rather than written here, so a fourth hash joins the
    /// loop by itself.
    #[test]
    fn test_a_stored_ticket_round_trips_under_every_tls13_hash() {
        use crate::tls::handshake13::tls13_hash_name;
        let mut names: Vec<&'static str> = crate::tls::suites::Selection::all()
            .codes().iter()
            .filter_map(|code| crate::tls::suites::by_code(*code))
            .filter(|suite| suite.min_version == crate::tls::Version::TLS13)
            .filter_map(|suite| tls13_hash_name(suite.prf).ok())
            .collect();
        names.sort();
        names.dedup();
        assert!(names.contains(&"streebog256"),
                "the suite table has no Streebog-256 suite: {:?}", names);
        assert!(names.len() >= 3, "{:?}", names);
        for name in names {
            let stored = ticket(name, 1_234_567, 7_200).encode().unwrap();
            let back = Ticket::decode(&stored)
                .unwrap_or_else(|e| panic!("{}: {}", name, e));
            assert_eq!(back.hash, name);
        }
        // And a name no suite produces is still refused.
        let mut ticket = ticket("sha256", 0, 3600);
        ticket.hash = "sha1";
        assert!(Ticket::decode(&ticket.encode().unwrap()).is_err());
    }

    #[test]
    fn test_a_damaged_stored_ticket_is_refused() {
        let stored = ticket("sha256", 0, 3600).encode().unwrap();
        assert!(Ticket::decode(&stored).is_ok());

        // Wrong magic.
        let mut wrong = stored.clone();
        wrong[0] ^= 0x01;
        assert!(Ticket::decode(&wrong).is_err());

        // Truncated at every length: none of them may panic, and none
        // may succeed.
        for cut in 0..stored.len() {
            assert!(Ticket::decode(&stored[..cut]).is_err(), "cut at {}", cut);
        }
        // And trailing bytes are refused too, because they would mean
        // the reader and the writer disagree about the shape.
        let mut longer = stored.clone();
        longer.push(0);
        assert!(Ticket::decode(&longer).is_err());
    }
}
