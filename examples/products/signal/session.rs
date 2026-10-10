//! Pairwise sessions: X3DH to start one, the Double Ratchet to run it.
//!
//! Follows libsignal-protocol-c 2.3.3 step for step, including the
//! order in which it draws randomness, so that given the same random
//! stream the two produce the same bytes (`rng.rs`).
//!
//! ## X3DH
//!
//! Alice has Bob's bundle: identity key `IKb`, signed prekey `SPKb` with
//! its XEdDSA signature, and optionally a one-time prekey `OPKb`. She
//! draws a base key `EKa` and computes
//!
//! ```text
//! secret = FF*32 || DH(IKa, SPKb) || DH(EKa, IKb) || DH(EKa, SPKb) [|| DH(EKa, OPKb)]
//! root || chain = HKDF-SHA256(salt = 0*32, secret, "WhisperText", 64)
//! ```
//!
//! The 32 bytes of `FF` are the "discontinuity bytes": an X25519 output
//! can never be them, which separates this hash input from any made of
//! DH outputs alone. Bob computes the same from his private halves.
//!
//! ## The ratchet
//!
//! A root step mixes a new DH output into the root key:
//! `root' || chain = HKDF(salt = root, DH, "WhisperRatchet", 64)`.
//! A chain step is two HMACs of the chain key: with `01` it gives a
//! message's seed, with `02` the next chain key. The seed expands with
//! `HKDF(salt = 0*32, seed, "WhisperMessageKeys", 80)` into an AES-256
//! key, an HMAC key and a CBC IV - there is no nonce in the message,
//! because every message has its own key.
//!
//! **The initial state is lopsided**, and copying either side to the
//! other gives a session that works one way. Bob's sending chain is the
//! X3DH chain with `SPKb` as its ratchet key, and he cannot send until he
//! has received. Alice draws a ratchet key at once, takes a root step
//! with it against `SPKb`, and sends on the result; she also files the
//! X3DH chain as a receiving chain under `SPKb`.

use std::collections::HashMap;

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::kdf::hkdf as rfc5869;
use allcrypt::mac::hmac::Hmac;

use crate::rng::Random;
use crate::wire::{self, Error, KeyPair, PreKeySignalMessage, PublicKey, SignalMessage};

/// Messages a receiving chain may be ahead of the last one decrypted.
pub const MAX_SKIP: u32 = 2000;
/// Message keys kept per receiving chain for late messages.
const MAX_MESSAGE_KEYS: usize = 2000;
/// Receiving chains kept per session.
const MAX_RECEIVER_CHAINS: usize = 5;
/// Superseded sessions kept per peer.
const MAX_ARCHIVED_STATES: usize = 40;
/// A one-time prekey id with this value is never deleted after use.
const PRE_KEY_MEDIUM_MAX_VALUE: u32 = 0xff_ffff;

// ----------------------------------------------------------- primitives --

pub fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    Hmac::mac(SHA256::new(&[]), key, data)
}

pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    rfc5869(SHA256::new(&[]), salt, ikm, info, length).unwrap_or_default()
}

/// AES-256-CBC with PKCS#7 padding.
pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut cipher = AesCrypto::new(key).map_err(|_| Error::UNKNOWN)?;
    let padded = allcrypt::api::pad_pkcs7(plaintext, 16).map_err(|_| Error::UNKNOWN)?;
    let mut out = Vec::with_capacity(padded.len());
    cipher.cbc_encrypt(&padded, &mut out, iv).map_err(|_| Error::UNKNOWN)?;
    Ok(out)
}

/// The inverse. A length that is not whole blocks or padding that is
/// not PKCS#7 is the generic failure, as libsignal's provider reports it.
pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(Error::UNKNOWN);
    }
    let mut cipher = AesCrypto::new(key).map_err(|_| Error::UNKNOWN)?;
    let mut out = Vec::with_capacity(ciphertext.len());
    cipher.cbc_decrypt(ciphertext, &mut out, iv).map_err(|_| Error::UNKNOWN)?;
    allcrypt::api::unpad_pkcs7(&out, 16).map_err(|_| Error::UNKNOWN)
}

fn split32(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&bytes[..32]);
    second.copy_from_slice(&bytes[32..64]);
    (first, second)
}

// --------------------------------------------------------------- chains --

#[derive(Clone)]
pub struct ChainKey {
    key: [u8; 32],
    index: u32,
}

#[derive(Clone)]
pub struct MessageKeys {
    cipher: [u8; 32],
    mac: [u8; 32],
    iv: [u8; 16],
    counter: u32,
}

impl ChainKey {
    fn message_keys(&self) -> MessageKeys {
        let seed = hmac(&self.key, &[0x01]);
        let material = hkdf(&[0u8; 32], &seed, b"WhisperMessageKeys", 80);
        let mut keys = MessageKeys { cipher: [0; 32], mac: [0; 32], iv: [0; 16],
                                     counter: self.index };
        keys.cipher.copy_from_slice(&material[..32]);
        keys.mac.copy_from_slice(&material[32..64]);
        keys.iv.copy_from_slice(&material[64..80]);
        keys
    }

    fn next(&self) -> ChainKey {
        let mut key = [0u8; 32];
        key.copy_from_slice(&hmac(&self.key, &[0x02]));
        ChainKey { key, index: self.index + 1 }
    }
}

/// A root step: `HKDF(salt = root, DH(ours, theirs), "WhisperRatchet")`.
fn root_step(root: &[u8; 32], theirs: &PublicKey, ours: &KeyPair) -> ([u8; 32], ChainKey) {
    let material = hkdf(root, &ours.agree(theirs), b"WhisperRatchet", 64);
    let (root, chain) = split32(&material);
    (root, ChainKey { key: chain, index: 0 })
}

#[derive(Clone)]
struct ReceiverChain {
    ratchet_key: PublicKey,
    chain: ChainKey,
    /// Keys of messages skipped on this chain, oldest first.
    skipped: Vec<MessageKeys>,
}

/// What a session's first messages carry until the peer answers.
#[derive(Clone)]
struct Pending {
    pre_key_id: Option<u32>,
    signed_pre_key_id: u32,
    base_key: PublicKey,
}

#[derive(Clone)]
pub struct SessionState {
    version: u8,
    local_identity: PublicKey,
    remote_identity: PublicKey,
    root: [u8; 32],
    sender: (KeyPair, ChainKey),
    /// Oldest first; the sixth pushes the first out.
    receivers: Vec<ReceiverChain>,
    previous_counter: u32,
    pending: Option<Pending>,
    local_registration_id: u32,
    remote_registration_id: u32,
    alice_base_key: PublicKey,
}

/// One peer's sessions: the current one and up to forty it replaced,
/// most recent first. A message is tried against all of them, because a
/// peer may still be sending on a session this side has moved on from -
/// both sides starting a session at once is the usual way.
#[derive(Clone, Default)]
pub struct SessionRecord {
    current: Option<SessionState>,
    previous: Vec<SessionState>,
}

impl SessionRecord {
    /// Make room for a new current session: the old one goes to the
    /// front of the archive.
    fn archive_current(&mut self) {
        if let Some(state) = self.current.take() {
            self.previous.insert(0, state);
            self.previous.truncate(MAX_ARCHIVED_STATES);
        }
    }

    fn has_state(&self, version: u8, base_key: &PublicKey) -> bool {
        self.current.iter().chain(self.previous.iter())
            .any(|state| state.version == version && state.alice_base_key == *base_key)
    }
}

/// X3DH's shared secret into the first root and chain keys.
fn derive_initial(agreements: &[[u8; 32]]) -> ([u8; 32], ChainKey) {
    let mut secret = vec![0xffu8; 32];
    for agreement in agreements {
        secret.extend_from_slice(agreement);
    }
    let (root, chain) = split32(&hkdf(&[0u8; 32], &secret, b"WhisperText", 64));
    (root, ChainKey { key: chain, index: 0 })
}

// ----------------------------------------------------- encrypt, decrypt --

impl SessionState {
    fn receiver(&mut self, ratchet_key: &PublicKey) -> Option<&mut ReceiverChain> {
        self.receivers.iter_mut().find(|chain| chain.ratchet_key == *ratchet_key)
    }

    fn add_receiver(&mut self, ratchet_key: PublicKey, chain: ChainKey) {
        self.receivers.push(ReceiverChain { ratchet_key, chain, skipped: Vec::new() });
        if self.receivers.len() > MAX_RECEIVER_CHAINS {
            self.receivers.remove(0);
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
        let (ratchet, chain) = &self.sender;
        let keys = chain.message_keys();
        let ciphertext = encrypt(&keys.cipher, &keys.iv, plaintext)?;
        let message = SignalMessage::new(&keys.mac, ratchet.public, chain.index,
                                         self.previous_counter, ciphertext,
                                         &self.local_identity, &self.remote_identity);
        let out = match &self.pending {
            Some(pending) => (wire::PREKEY_TYPE, PreKeySignalMessage::new(
                self.local_registration_id, pending.pre_key_id, pending.signed_pre_key_id,
                pending.base_key, self.local_identity, message).serialized),
            None => (wire::SIGNAL_TYPE, message.serialized),
        };
        self.sender.1 = chain.next();
        Ok(out)
    }

    /// The receiving chain for `their_key`, taking a DH ratchet step
    /// if it is new: a root step to the receiving chain, a fresh ratchet
    /// key of our own, and a second root step to a new sending chain.
    fn chain_for(&mut self, random: &mut Random, their_key: &PublicKey)
                 -> Result<ChainKey, Error> {
        if let Some(chain) = self.receiver(their_key) {
            return Ok(chain.chain.clone());
        }
        let (root, receiving) = root_step(&self.root, their_key, &self.sender.0);
        let ours = KeyPair::generate(random)?;
        let (root, sending) = root_step(&root, their_key, &ours);
        self.root = root;
        self.add_receiver(*their_key, receiving.clone());
        // The counter of the last message sent on the chain being
        // retired - one less than its index, but zero rather than minus
        // one when nothing was sent, so "sent one" and "sent none" look
        // the same. libsignal does exactly this.
        self.previous_counter = self.sender.1.index.saturating_sub(1);
        self.sender = (ours, sending);
        Ok(receiving)
    }

    fn message_keys(&mut self, their_key: &PublicKey, chain: ChainKey, counter: u32)
                    -> Result<MessageKeys, Error> {
        let receiver = self.receiver(their_key).ok_or(Error::UNKNOWN)?;
        if chain.index > counter {
            let at = receiver.skipped.iter().position(|keys| keys.counter == counter)
                .ok_or(Error::DUPLICATE_MESSAGE)?;
            return Ok(receiver.skipped.remove(at));
        }
        if counter - chain.index > MAX_SKIP {
            return Err(Error::INVALID_MESSAGE);
        }
        let mut current = chain;
        while current.index < counter {
            receiver.skipped.push(current.message_keys());
            if receiver.skipped.len() > MAX_MESSAGE_KEYS {
                receiver.skipped.remove(0);
            }
            current = current.next();
        }
        receiver.chain = current.next();
        Ok(current.message_keys())
    }

    /// Decrypt on this state, which the caller has copied: every change
    /// here - a ratchet step, skipped keys stored - is kept only if the
    /// MAC checks, and the copy is discarded otherwise.
    fn decrypt(&mut self, random: &mut Random, message: &SignalMessage)
               -> Result<Vec<u8>, Error> {
        if message.version != self.version {
            return Err(Error::INVALID_MESSAGE);
        }
        let chain = self.chain_for(random, &message.ratchet_key)?;
        let keys = self.message_keys(&message.ratchet_key, chain, message.counter)?;
        if !message.verify_mac(&self.remote_identity, &self.local_identity, &keys.mac) {
            return Err(Error::INVALID_MESSAGE);
        }
        let plaintext = decrypt(&keys.cipher, &keys.iv, &message.ciphertext)?;
        self.pending = None;
        Ok(plaintext)
    }
}

/// Try the current session, then each archived one, newest first. An
/// archived session that decrypts becomes current. Any failure other
/// than "not this session" stops the search: a duplicate, for one, is
/// a definite answer about the session it was found in.
fn decrypt_from_record(record: &mut SessionRecord, random: &mut Random,
                       message: &SignalMessage) -> Result<Vec<u8>, Error> {
    if let Some(current) = &record.current {
        let mut copy = current.clone();
        match copy.decrypt(random, message) {
            Ok(plaintext) => {
                record.current = Some(copy);
                return Ok(plaintext);
            }
            Err(error) if error != Error::INVALID_MESSAGE => return Err(error),
            Err(_) => {}
        }
    }
    for at in 0..record.previous.len() {
        let mut copy = record.previous[at].clone();
        match copy.decrypt(random, message) {
            Ok(plaintext) => {
                record.previous.remove(at);
                record.archive_current();
                record.current = Some(copy);
                return Ok(plaintext);
            }
            Err(error) if error != Error::INVALID_MESSAGE => return Err(error),
            Err(_) => {}
        }
    }
    Err(Error::INVALID_MESSAGE)
}

// -------------------------------------------------------------- a party --

/// What a peer publishes so that others can start sessions with it.
#[derive(Clone, Debug)]
pub struct Bundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub pre_key: Option<(u32, PublicKey)>,
    pub signed_pre_key_id: u32,
    pub signed_pre_key: PublicKey,
    pub signature: Vec<u8>,
    pub identity: PublicKey,
}

/// One user's device: its keys and its sessions, in memory.
pub struct Party {
    pub random: Random,
    pub identity: KeyPair,
    pub registration_id: u32,
    pre_keys: HashMap<u32, KeyPair>,
    signed_pre_keys: HashMap<u32, KeyPair>,
    sessions: HashMap<String, SessionRecord>,
    /// The identity each peer was first seen with. A different one is
    /// refused until the user decides otherwise - Signal's "safety
    /// number changed".
    trusted: HashMap<String, PublicKey>,
    pub groups: crate::group::SenderKeys,
}

impl Party {
    /// The identity key is the first draw from `random`.
    pub fn new(mut random: Random, registration_id: u32) -> Result<Party, Error> {
        let identity = KeyPair::generate(&mut random)?;
        Ok(Party { random, identity, registration_id, pre_keys: HashMap::new(),
                   signed_pre_keys: HashMap::new(), sessions: HashMap::new(),
                   trusted: HashMap::new(), groups: Default::default() })
    }

    fn is_trusted(&self, peer: &str, identity: &PublicKey) -> bool {
        self.trusted.get(peer).is_none_or(|known| known == identity)
    }

    /// A one-time prekey and a signed prekey, stored, and the bundle
    /// that publishes them. Drawn in libsignal's order: the one-time key,
    /// then the signed key, then the signature's random bytes.
    pub fn publish(&mut self, pre_key_id: u32, signed_pre_key_id: u32) -> Result<Bundle, Error> {
        let pre_key = KeyPair::generate(&mut self.random)?;
        let signed = KeyPair::generate(&mut self.random)?;
        let signature = self.identity.sign(&mut self.random, &signed.public.serialize())?;
        let bundle = Bundle {
            registration_id: self.registration_id,
            device_id: 1,
            pre_key: Some((pre_key_id, pre_key.public)),
            signed_pre_key_id,
            signed_pre_key: signed.public,
            signature: signature.to_vec(),
            identity: self.identity.public,
        };
        self.pre_keys.insert(pre_key_id, pre_key);
        self.signed_pre_keys.insert(signed_pre_key_id, signed);
        Ok(bundle)
    }

    /// Alice's side of X3DH: a session with `peer` from its bundle.
    pub fn process_bundle(&mut self, peer: &str, bundle: &Bundle) -> Result<(), Error> {
        if !self.is_trusted(peer, &bundle.identity) {
            return Err(Error::UNTRUSTED_IDENTITY);
        }
        if bundle.signature.len() != wire::SIGNATURE_LEN {
            return Err(Error::INVALID_ARGUMENT);
        }
        if !wire::verify(&bundle.identity, &bundle.signed_pre_key.serialize(), &bundle.signature) {
            return Err(Error::INVALID_KEY);
        }
        let fresh = !self.sessions.contains_key(peer);
        let mut record = self.sessions.get(peer).cloned().unwrap_or_default();

        let base = KeyPair::generate(&mut self.random)?;
        let sending = KeyPair::generate(&mut self.random)?;
        let mut agreements = vec![
            self.identity.agree(&bundle.signed_pre_key),
            base.agree(&bundle.identity),
            base.agree(&bundle.signed_pre_key),
        ];
        if let Some((_, one_time)) = &bundle.pre_key {
            agreements.push(base.agree(one_time));
        }
        let (root, chain) = derive_initial(&agreements);
        let (root, sending_chain) = root_step(&root, &bundle.signed_pre_key, &sending);
        let mut state = SessionState {
            version: wire::VERSION,
            local_identity: self.identity.public,
            remote_identity: bundle.identity,
            root,
            sender: (sending, sending_chain),
            receivers: Vec::new(),
            previous_counter: 0,
            pending: Some(Pending {
                pre_key_id: bundle.pre_key.map(|(id, _)| id),
                signed_pre_key_id: bundle.signed_pre_key_id,
                base_key: base.public,
            }),
            local_registration_id: self.registration_id,
            remote_registration_id: bundle.registration_id,
            alice_base_key: base.public,
        };
        state.add_receiver(bundle.signed_pre_key, chain);

        if !fresh {
            record.archive_current();
        }
        record.current = Some(state);
        self.sessions.insert(peer.to_string(), record);
        self.trusted.insert(peer.to_string(), bundle.identity);
        Ok(())
    }

    /// The registration id the peer's session was built with, which an
    /// application compares with the one its server lists to notice a
    /// reinstalled device.
    pub fn remote_registration_id(&self, peer: &str) -> Option<u32> {
        self.sessions.get(peer)?.current.as_ref().map(|state| state.remote_registration_id)
    }

    pub fn encrypt(&mut self, peer: &str, plaintext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
        let state = self.sessions.get_mut(peer).and_then(|record| record.current.as_mut())
            .ok_or(Error::UNKNOWN)?;
        state.encrypt(plaintext)
    }

    /// Bob's side of X3DH, from the first message: a new session, unless
    /// one with this base key exists already - every message before Bob
    /// answers is a prekey message, and only the first builds anything.
    /// Returns the one-time prekey to delete once the message decrypts.
    fn process_prekey_message(&mut self, peer: &str, record: &mut SessionRecord, fresh: bool,
                              message: &PreKeySignalMessage) -> Result<Option<u32>, Error> {
        if !self.is_trusted(peer, &message.identity_key) {
            return Err(Error::UNTRUSTED_IDENTITY);
        }
        if record.has_state(message.message.version, &message.base_key) {
            self.trusted.insert(peer.to_string(), message.identity_key);
            return Ok(None);
        }
        let signed = self.signed_pre_keys.get(&message.signed_pre_key_id)
            .ok_or(Error::INVALID_KEY_ID)?.clone();
        let one_time = match message.pre_key_id {
            Some(id) => Some(self.pre_keys.get(&id).ok_or(Error::INVALID_KEY_ID)?.clone()),
            None => None,
        };
        let mut agreements = vec![
            signed.agree(&message.identity_key),
            self.identity.agree(&message.base_key),
            signed.agree(&message.base_key),
        ];
        if let Some(one_time) = &one_time {
            agreements.push(one_time.agree(&message.base_key));
        }
        let (root, chain) = derive_initial(&agreements);
        if !fresh {
            record.archive_current();
        }
        record.current = Some(SessionState {
            version: wire::VERSION,
            local_identity: self.identity.public,
            remote_identity: message.identity_key,
            root,
            sender: (signed, chain),
            receivers: Vec::new(),
            previous_counter: 0,
            pending: None,
            local_registration_id: self.registration_id,
            remote_registration_id: message.registration_id,
            alice_base_key: message.base_key,
        });
        self.trusted.insert(peer.to_string(), message.identity_key);
        Ok(message.pre_key_id.filter(|id| *id != PRE_KEY_MEDIUM_MAX_VALUE))
    }

    /// Decrypt a message of either pairwise type. Nothing is kept unless
    /// it decrypts - except that a prekey message's identity is
    /// remembered as soon as its session is built, as libsignal does.
    pub fn decrypt(&mut self, peer: &str, kind: u32, data: &[u8]) -> Result<Vec<u8>, Error> {
        if kind == wire::PREKEY_TYPE {
            let message = PreKeySignalMessage::parse(data)?;
            let fresh = !self.sessions.contains_key(peer);
            let mut record = self.sessions.get(peer).cloned().unwrap_or_default();
            let used = self.process_prekey_message(peer, &mut record, fresh, &message)?;
            let plaintext = decrypt_from_record(&mut record, &mut self.random, &message.message)?;
            self.sessions.insert(peer.to_string(), record);
            if let Some(id) = used {
                self.pre_keys.remove(&id);
            }
            Ok(plaintext)
        } else {
            let message = SignalMessage::parse(data)?;
            let mut record = self.sessions.get(peer).cloned().ok_or(Error::NO_SESSION)?;
            let plaintext = decrypt_from_record(&mut record, &mut self.random, &message)?;
            self.sessions.insert(peer.to_string(), record);
            Ok(plaintext)
        }
    }
}
