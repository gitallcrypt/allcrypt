//! WireGuard's cryptography (the whitepaper's section 5.4, as wireguard-go
//! and the Linux module implement it): Noise_IKpsk2 over Curve25519,
//! ChaCha20-Poly1305 and BLAKE2s; the MAC1 and MAC2 fields and the cookie
//! reply under XChaCha20-Poly1305; and transport data messages.

use allcrypt::api::{self, aead_decrypt, aead_encrypt};
use allcrypt::hash_functions::blake2::Blake2s;
use allcrypt::hash_functions::HashFunction;

pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";

pub const INITIATION: u8 = 1;
pub const RESPONSE: u8 = 2;
pub const COOKIE_REPLY: u8 = 3;
pub const TRANSPORT: u8 = 4;

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;

pub type Key = [u8; 32];

// ---------------------------------------------------------------- primitives --

pub fn hash(parts: &[&[u8]]) -> Key {
    let mut h = Blake2s::with_length(32).expect("32 bytes");
    for p in parts {
        h.update(p);
    }
    h.digest().try_into().expect("32 bytes")
}

/// Keyed BLAKE2s with a 16-byte output: MAC1, MAC2 and the cookie.
pub fn mac(key: &[u8], input: &[u8]) -> [u8; 16] {
    let mut h = Blake2s::keyed(key, 16).expect("a key of at most 32 bytes");
    h.update(input);
    h.digest().try_into().expect("16 bytes")
}

fn hmac(key: &[u8], input: &[u8]) -> Key {
    api::hmac("blake2s", key, input).expect("BLAKE2s").try_into().expect("32 bytes")
}

/// The HKDF-like chain of the whitepaper: `T0 = HMAC(key, input)`,
/// `T1 = HMAC(T0, 0x1)`, `Ti = HMAC(T0, T(i-1) || i)`.
pub fn kdf<const N: usize>(key: &[u8], input: &[u8]) -> [Key; N] {
    let t0 = hmac(key, input);
    let mut out = [[0u8; 32]; N];
    let mut previous: Vec<u8> = Vec::new();
    for (i, slot) in out.iter_mut().enumerate() {
        previous.push(i as u8 + 1);
        *slot = hmac(&t0, &previous);
        previous = slot.to_vec();
    }
    out
}

/// ChaCha20-Poly1305 with the counter as the nonce's last eight bytes,
/// little endian, after four zero bytes.
pub fn aead_seal(key: &Key, counter: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (mut ct, tag) = aead_encrypt("chacha20-poly1305", key, &nonce(counter), aad, plaintext)
        .expect("a 32 byte key and a 12 byte nonce");
    ct.extend(tag);
    ct
}

pub fn aead_open(key: &Key, counter: u64, sealed: &[u8], aad: &[u8])
                 -> Result<Vec<u8>, String> {
    if sealed.len() < 16 {
        return Err("A sealed field shorter than its tag.".to_string());
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    aead_decrypt("chacha20-poly1305", key, &nonce(counter), aad, ct, tag)
        .map_err(|_| "The tag did not verify.".to_string())
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

pub fn dh(private: &Key, public: &Key) -> Result<Key, String> {
    api::x25519_exchange(private, public)
        .map_err(|e| format!("Curve25519: {e}"))?
        .try_into().map_err(|_| "Curve25519 gave the wrong length.".to_string())
}

pub fn public_key(private: &Key) -> Key {
    api::x25519_public_key(private).expect("32 bytes").try_into().expect("32 bytes")
}

/// A fresh private key, clamped as `wg genkey` writes one.
pub fn generate_private() -> Result<Key, String> {
    let mut key: Key = api::random_bytes(32)?.try_into().expect("32 bytes");
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
    Ok(key)
}

/// TAI64N: seconds since 1970 plus 2^62, big endian, then nanoseconds,
/// big endian - 12 bytes that compare as the time does.
pub fn tai64n(unix_seconds: u64, nanoseconds: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(unix_seconds + (1 << 62)).to_be_bytes());
    out[8..].copy_from_slice(&nanoseconds.to_be_bytes());
    out
}

pub fn now_tai64n() -> [u8; 12] {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    tai64n(now.as_secs(), now.subsec_nanos())
}

// ----------------------------------------------------------------- MAC1, MAC2 --

/// MAC1 over everything before it, keyed by the receiver's public key;
/// MAC2 over everything before it including MAC1, keyed by a cookie, or
/// zeros without one. Returns the MAC1 written, which a cookie reply
/// will be sealed against.
pub fn add_macs(message: &mut [u8], receiver_public: &Key, cookie: Option<&[u8; 16]>)
                -> [u8; 16] {
    let n = message.len();
    let mac1 = mac(&hash(&[LABEL_MAC1, receiver_public]), &message[..n - 32]);
    message[n - 32..n - 16].copy_from_slice(&mac1);
    let mac2 = match cookie {
        Some(cookie) => mac(cookie, &message[..n - 16]),
        None => [0u8; 16],
    };
    message[n - 16..].copy_from_slice(&mac2);
    mac1
}

pub fn check_mac1(message: &[u8], our_public: &Key) -> bool {
    let n = message.len();
    let expected = mac(&hash(&[LABEL_MAC1, our_public]), &message[..n - 32]);
    !allcrypt::bignum::ct::bytes_differ(&expected, &message[n - 32..n - 16])
}

/// The cookie a responder under load hands out for a source address:
/// MAC(secret, address), the secret changing every two minutes.
pub fn cookie(secret: &[u8; 32], source: &[u8]) -> [u8; 16] {
    mac(secret, source)
}

pub fn check_mac2(message: &[u8], secret: &[u8; 32], source: &[u8]) -> bool {
    let n = message.len();
    let expected = mac(&cookie(secret, source), &message[..n - 16]);
    !allcrypt::bignum::ct::bytes_differ(&expected, &message[n - 16..])
}

/// A cookie reply (type 3): the cookie sealed with XChaCha20-Poly1305
/// under HASH(LABEL_COOKIE || our public key), a random 24-byte nonce, and
/// the MAC1 of the message being answered as associated data.
pub fn cookie_reply(message: &[u8], our_public: &Key, secret: &[u8; 32], source: &[u8],
                    nonce: &[u8; 24]) -> Vec<u8> {
    let n = message.len();
    let sender = &message[4..8];
    let key = hash(&[LABEL_COOKIE, our_public]);
    let (mut sealed, tag) = aead_encrypt("xchacha20-poly1305", &key, nonce,
                                         &message[n - 32..n - 16], &cookie(secret, source))
        .expect("a 32 byte key and a 24 byte nonce");
    sealed.extend(tag);
    let mut out = vec![COOKIE_REPLY, 0, 0, 0];
    out.extend_from_slice(sender);
    out.extend_from_slice(nonce);
    out.extend(sealed);
    out
}

/// The cookie out of a reply, checked against the MAC1 we last sent.
pub fn open_cookie_reply(reply: &[u8], peer_public: &Key, last_mac1: &[u8; 16])
                         -> Result<[u8; 16], String> {
    if reply.len() != COOKIE_REPLY_LEN || reply[0] != COOKIE_REPLY || reply[1..4] != [0; 3] {
        return Err("Not a cookie reply.".to_string());
    }
    let key = hash(&[LABEL_COOKIE, peer_public]);
    let (sealed, tag) = reply[32..].split_at(16);
    let cookie = aead_decrypt("xchacha20-poly1305", &key, &reply[8..32], last_mac1, sealed, tag)
        .map_err(|_| "The cookie reply does not open: not for our last message, or not \
                      from this peer.".to_string())?;
    Ok(cookie.try_into().expect("16 bytes"))
}

// ------------------------------------------------------------------ handshake --

/// The initiator's state between its initiation and the response.
#[derive(Clone, PartialEq)]
pub struct Pending {
    pub chaining_key: Key,
    pub hash: Key,
    pub ephemeral_private: Key,
    pub sender: u32,
}

/// The transcript hash is public; the chaining key and the ephemeral
/// private key are not.
impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::hidden::HiddenBytes;
        f.debug_struct("Pending").field("chaining_key", &HiddenBytes(&self.chaining_key))
            .field("hash", &self.hash)
            .field("ephemeral_private", &HiddenBytes(&self.ephemeral_private))
            .field("sender", &self.sender).finish()
    }
}

/// Transport keys, and the indices each side names the session by.
#[derive(Clone, PartialEq)]
pub struct Session {
    pub send: Key,
    pub receive: Key,
    pub local_index: u32,
    pub remote_index: u32,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::hidden::HiddenBytes;
        f.debug_struct("Session").field("send", &HiddenBytes(&self.send))
            .field("receive", &HiddenBytes(&self.receive))
            .field("local_index", &self.local_index)
            .field("remote_index", &self.remote_index).finish()
    }
}

/// What the responder learns from an initiation.
pub struct Initiation {
    pub peer_public: Key,
    pub timestamp: [u8; 12],
    pub chaining_key: Key,
    pub hash: Key,
    pub ephemeral: Key,
    pub sender: u32,
}

fn initial(responder_public: &Key) -> (Key, Key) {
    let chaining_key = hash(&[CONSTRUCTION]);
    let h = hash(&[&chaining_key, IDENTIFIER]);
    (chaining_key, hash(&[&h, responder_public]))
}

/// Message 1. Returns it without its MACs, which `add_macs` writes.
pub fn create_initiation(static_private: &Key, responder_public: &Key, ephemeral_private: &Key,
                         timestamp: &[u8; 12], sender: u32)
                         -> Result<(Vec<u8>, Pending), String> {
    let (mut ck, mut h) = initial(responder_public);
    let ephemeral = public_key(ephemeral_private);
    [ck] = kdf::<1>(&ck, &ephemeral);
    h = hash(&[&h, &ephemeral]);
    let [c, key] = kdf::<2>(&ck, &dh(ephemeral_private, responder_public)?);
    ck = c;
    let static_sealed = aead_seal(&key, 0, &public_key(static_private), &h);
    h = hash(&[&h, &static_sealed]);
    let [c, key] = kdf::<2>(&ck, &dh(static_private, responder_public)?);
    ck = c;
    let time_sealed = aead_seal(&key, 0, timestamp, &h);
    h = hash(&[&h, &time_sealed]);

    let mut msg = vec![INITIATION, 0, 0, 0];
    msg.extend_from_slice(&sender.to_le_bytes());
    msg.extend_from_slice(&ephemeral);
    msg.extend(static_sealed);
    msg.extend(time_sealed);
    msg.extend([0u8; 32]);
    debug_assert_eq!(msg.len(), INITIATION_LEN);
    Ok((msg, Pending { chaining_key: ck, hash: h, ephemeral_private: *ephemeral_private,
                       sender }))
}

/// Read message 1 with our static key: the initiator's static key and
/// timestamp, and the handshake state to answer it from. MAC1 is the
/// caller's to check first; that is what makes a forged message cheap
/// to refuse.
pub fn consume_initiation(msg: &[u8], static_private: &Key) -> Result<Initiation, String> {
    if msg.len() != INITIATION_LEN || msg[0] != INITIATION || msg[1..4] != [0; 3] {
        return Err(format!("Not a handshake initiation ({} bytes).", msg.len()));
    }
    let our_public = public_key(static_private);
    let (ck, h) = initial(&our_public);
    let ephemeral: Key = msg[8..40].try_into().expect("32 bytes");
    let [ck] = kdf::<1>(&ck, &ephemeral);
    let h = hash(&[&h, &ephemeral]);
    let [ck, key] = kdf::<2>(&ck, &dh(static_private, &ephemeral)?);
    let static_sealed = &msg[40..88];
    let peer: Key = aead_open(&key, 0, static_sealed, &h)
        .map_err(|_| "The initiation's static key does not decrypt: it was not made for \
                      this key.".to_string())?
        .try_into().expect("32 bytes");
    let h = hash(&[&h, static_sealed]);
    let [ck, key] = kdf::<2>(&ck, &dh(static_private, &peer)?);
    let time_sealed = &msg[88..116];
    let timestamp: [u8; 12] = aead_open(&key, 0, time_sealed, &h)
        .map_err(|_| "The initiation's timestamp does not decrypt.".to_string())?
        .try_into().expect("12 bytes");
    let h = hash(&[&h, time_sealed]);
    Ok(Initiation { peer_public: peer, timestamp, chaining_key: ck, hash: h, ephemeral,
                    sender: u32::from_le_bytes(msg[4..8].try_into().expect("four")) })
}

/// Message 2, without its MACs, and the responder's session. The
/// preshared key is mixed in here, which is what the "psk2" means.
pub fn create_response(init: &Initiation, psk: &Key, ephemeral_private: &Key, sender: u32)
                       -> Result<(Vec<u8>, Session), String> {
    let ephemeral = public_key(ephemeral_private);
    let [ck] = kdf::<1>(&init.chaining_key, &ephemeral);
    let h = hash(&[&init.hash, &ephemeral]);
    let [ck] = kdf::<1>(&ck, &dh(ephemeral_private, &init.ephemeral)?);
    let [ck] = kdf::<1>(&ck, &dh(ephemeral_private, &init.peer_public)?);
    let [ck, tau, key] = kdf::<3>(&ck, psk);
    let h = hash(&[&h, &tau]);
    let empty = aead_seal(&key, 0, &[], &h);

    let mut msg = vec![RESPONSE, 0, 0, 0];
    msg.extend_from_slice(&sender.to_le_bytes());
    msg.extend_from_slice(&init.sender.to_le_bytes());
    msg.extend_from_slice(&ephemeral);
    msg.extend(empty);
    msg.extend([0u8; 32]);
    debug_assert_eq!(msg.len(), RESPONSE_LEN);
    // The responder receives with the first key and sends with the second.
    let [receive, send] = kdf::<2>(&ck, &[]);
    Ok((msg, Session { send, receive, local_index: sender, remote_index: init.sender }))
}

/// Read message 2 with the pending state; the initiator's session.
pub fn consume_response(msg: &[u8], pending: &Pending, static_private: &Key, psk: &Key)
                        -> Result<Session, String> {
    if msg.len() != RESPONSE_LEN || msg[0] != RESPONSE || msg[1..4] != [0; 3] {
        return Err(format!("Not a handshake response ({} bytes).", msg.len()));
    }
    let receiver = u32::from_le_bytes(msg[8..12].try_into().expect("four"));
    if receiver != pending.sender {
        return Err(format!("The response is for index {receiver}, and ours is {}.",
                           pending.sender));
    }
    let ephemeral: Key = msg[12..44].try_into().expect("32 bytes");
    let [ck] = kdf::<1>(&pending.chaining_key, &ephemeral);
    let h = hash(&[&pending.hash, &ephemeral]);
    let [ck] = kdf::<1>(&ck, &dh(&pending.ephemeral_private, &ephemeral)?);
    let [ck] = kdf::<1>(&ck, &dh(static_private, &ephemeral)?);
    let [ck, tau, key] = kdf::<3>(&ck, psk);
    let h = hash(&[&h, &tau]);
    aead_open(&key, 0, &msg[44..60], &h)
        .map_err(|_| "The response does not authenticate: a different preshared key, or \
                      not an answer to our initiation.".to_string())?;
    let [send, receive] = kdf::<2>(&ck, &[]);
    Ok(Session { send, receive, local_index: pending.sender,
                 remote_index: u32::from_le_bytes(msg[4..8].try_into().expect("four")) })
}

// ------------------------------------------------------------------ transport --

/// Pad as WireGuard pads an IP packet: the last MTU-sized unit of it up to
/// a multiple of 16, but not past the MTU. A packet longer than the MTU
/// is padded by its remainder, as the Linux module's
/// `calculate_skb_padding` and wireguard-go's `calculatePaddingSize` do.
pub fn pad(plaintext: &[u8], mtu: usize) -> Vec<u8> {
    let mut last_unit = plaintext.len();
    if last_unit > mtu {
        last_unit %= mtu;
    }
    let padded = (last_unit.div_ceil(16) * 16).min(mtu);
    let mut out = plaintext.to_vec();
    out.resize(plaintext.len() + padded - last_unit, 0);
    out
}

/// A transport data message (type 4).
pub fn seal_transport(session: &Session, counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut msg = vec![TRANSPORT, 0, 0, 0];
    msg.extend_from_slice(&session.remote_index.to_le_bytes());
    msg.extend_from_slice(&counter.to_le_bytes());
    msg.extend(aead_seal(&session.send, counter, plaintext, &[]));
    msg
}

/// The counter and plaintext of a transport message. Replay is the
/// window's business (`ReplayWindow`).
pub fn open_transport(session: &Session, msg: &[u8]) -> Result<(u64, Vec<u8>), String> {
    if msg.len() < 32 || msg[0] != TRANSPORT || msg[1..4] != [0; 3] {
        return Err("Not a transport data message.".to_string());
    }
    let receiver = u32::from_le_bytes(msg[4..8].try_into().expect("four"));
    if receiver != session.local_index {
        return Err(format!("The message is for index {receiver}, and this session is {}.",
                           session.local_index));
    }
    let counter = u64::from_le_bytes(msg[8..16].try_into().expect("eight"));
    Ok((counter, aead_open(&session.receive, counter, &msg[16..], &[])?))
}

/// RFC 6479's sliding window, as WireGuard keeps it: the highest counter
/// seen, and a bitmap of the 2,048 below it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReplayWindow {
    pub highest: Option<u64>,
    pub seen: Vec<u64>,
}

pub const WINDOW: u64 = 2048;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

impl ReplayWindow {
    /// Accept a counter once, and only within the window.
    pub fn accept(&mut self, counter: u64) -> Result<(), String> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err("A counter past the session's limit.".to_string());
        }
        if let Some(highest) = self.highest {
            if counter + WINDOW <= highest {
                return Err(format!("Counter {counter} is older than the window."));
            }
            if self.seen.contains(&counter) {
                return Err(format!("Counter {counter} was seen already: a replay."));
            }
        }
        self.highest = Some(self.highest.map_or(counter, |h| h.max(counter)));
        self.seen.push(counter);
        let highest = self.highest.expect("set above");
        self.seen.retain(|&c| c + WINDOW > highest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TAI64N's epoch is 2^62 at 1970 (with no leap-second offset, as
    /// WireGuard writes it).
    #[test]
    fn test_tai64n() {
        assert_eq!(tai64n(0, 0), [0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(tai64n(1, 0) > tai64n(0, 999_999_999));
    }

    #[test]
    fn test_padding() {
        assert_eq!(pad(&[], 1420).len(), 0);
        assert_eq!(pad(&[1], 1420).len(), 16);
        assert_eq!(pad(&[1; 16], 1420).len(), 16);
        assert_eq!(pad(&[1; 1419], 1420).len(), 1420);
        assert_eq!(pad(&[1; 1420], 1420).len(), 1420);
        // Past the MTU, the remainder is padded: 1500 is 80 over.
        assert_eq!(pad(&[1; 1500], 1420).len(), 1500);
        assert_eq!(pad(&[1; 1430], 1420).len(), 1436);
    }

    #[test]
    fn test_the_replay_window() {
        let mut w = ReplayWindow::default();
        w.accept(5).unwrap();
        assert!(w.accept(5).is_err());
        w.accept(3).unwrap();
        w.accept(5000).unwrap();
        assert!(w.accept(3).is_err());
        assert!(w.accept(5000 - 2048).is_err());
        w.accept(5000 - 2047).unwrap();
        assert!(w.accept(REJECT_AFTER_MESSAGES).is_err());
    }

    #[test]
    fn test_a_handshake_between_two_of_ours() {
        let (a, b) = (generate_private().unwrap(), generate_private().unwrap());
        let (ea, eb) = (generate_private().unwrap(), generate_private().unwrap());
        let psk = [7u8; 32];
        let (mut init, pending) = create_initiation(&a, &public_key(&b), &ea,
                                                    &tai64n(1, 2), 11).unwrap();
        let mac1 = add_macs(&mut init, &public_key(&b), None);
        assert!(check_mac1(&init, &public_key(&b)));
        assert!(!check_mac1(&init, &public_key(&a)));
        let seen = consume_initiation(&init, &b).unwrap();
        assert_eq!(seen.peer_public, public_key(&a));
        assert_eq!(seen.timestamp, tai64n(1, 2));
        let (mut resp, responder) = create_response(&seen, &psk, &eb, 22).unwrap();
        add_macs(&mut resp, &public_key(&a), None);
        let initiator = consume_response(&resp, &pending, &a, &psk).unwrap();
        assert_eq!(initiator.send, responder.receive);
        assert_eq!(initiator.receive, responder.send);
        assert_ne!(initiator.send, initiator.receive);
        assert!(consume_response(&resp, &pending, &a, &[8u8; 32]).is_err());

        let msg = seal_transport(&initiator, 0, &pad(b"ping", 1420));
        assert_eq!(open_transport(&responder, &msg).unwrap().1, pad(b"ping", 1420));

        // A cookie reply under load, and MAC2 with the cookie.
        let secret = [3u8; 32];
        let source = [192, 0, 2, 1, 0x1f, 0x90];
        let reply = cookie_reply(&init, &public_key(&b), &secret, &source, &[5; 24]);
        let cookie = open_cookie_reply(&reply, &public_key(&b), &mac1).unwrap();
        let (mut again, _) = create_initiation(&a, &public_key(&b), &ea, &tai64n(1, 3), 12)
            .unwrap();
        add_macs(&mut again, &public_key(&b), Some(&cookie));
        assert!(check_mac2(&again, &secret, &source));
        assert!(!check_mac2(&again, &secret, &[192, 0, 2, 2, 0x1f, 0x90]));
        assert!(open_cookie_reply(&reply, &public_key(&b), &[0; 16]).is_err());
    }
}
