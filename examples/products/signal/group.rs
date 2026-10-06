//! Sender keys: Signal's group messages.
//!
//! A group message is encrypted once, not once per member. Each member
//! has a *sender key* per group - a chain key and a signing key pair -
//! and sends every other member a distribution message holding the
//! chain key at its current iteration and the public signing key, over
//! the pairwise sessions. After that its group messages go to everyone
//! as one ciphertext.
//!
//! The chain steps as the pairwise one does - `HMAC(ck, 01)` for a
//! message seed, `HMAC(ck, 02)` for the next key - but has no DH ratchet,
//! so there is no forward secrecy against a member, only against
//! outsiders. The seed expands with `HKDF(salt = 0*32, seed,
//! "WhisperGroup", 48)` into an IV (the *first* 16 bytes) and an
//! AES-256 key (the next 32): the opposite order from the pairwise
//! derivation's key-then-IV, and swapping them is invisible between two
//! copies of the same code.
//!
//! The message is **signed**, not MACed: every member holds the chain
//! key, so a MAC would let any of them forge as any other.

use std::collections::HashMap;

use crate::rng::Random;
use crate::session::{decrypt, encrypt, hkdf, hmac};
use crate::wire::{Error, KeyPair, PublicKey, SenderKeyDistributionMessage, SenderKeyMessage};

/// Iterations a group message may be ahead of the chain.
const MAX_SKIP: u32 = 2000;
/// Message keys kept per sender key for late messages.
const MAX_MESSAGE_KEYS: usize = 2000;
/// Sender keys kept per (group, sender): a sender that rotates its key
/// leaves the old one usable for messages still in flight.
const MAX_STATES: usize = 5;

#[derive(Clone)]
struct ChainKey {
    iteration: u32,
    seed: Vec<u8>,
}

#[derive(Clone)]
struct MessageKey {
    iteration: u32,
    iv: [u8; 16],
    cipher: [u8; 32],
}

impl ChainKey {
    fn message_key(&self) -> MessageKey {
        let material = hkdf(&[0u8; 32], &hmac(&self.seed, &[0x01]), b"WhisperGroup", 48);
        let mut key = MessageKey { iteration: self.iteration, iv: [0; 16], cipher: [0; 32] };
        key.iv.copy_from_slice(&material[..16]);
        key.cipher.copy_from_slice(&material[16..48]);
        key
    }

    fn next(&self) -> ChainKey {
        ChainKey { iteration: self.iteration + 1, seed: hmac(&self.seed, &[0x02]) }
    }
}

#[derive(Clone)]
struct SenderKeyState {
    key_id: u32,
    chain: ChainKey,
    signing_public: PublicKey,
    /// Only for our own sender key.
    signing_private: Option<KeyPair>,
    skipped: Vec<MessageKey>,
}

/// Every sender key this party holds, by (group, sender), newest first.
#[derive(Default)]
pub struct SenderKeys {
    records: HashMap<(String, String), Vec<SenderKeyState>>,
}

fn name(group: &str, sender: &str) -> (String, String) {
    (group.to_string(), sender.to_string())
}

impl SenderKeys {
    /// Our sender key for `group`, created on first use - an id (31
    /// random bits), a chain key (32 random bytes) and a signing key, in
    /// that order - and the distribution message that announces it at
    /// its current iteration.
    pub fn distribution(&mut self, random: &mut Random, group: &str, us: &str)
                        -> Result<Vec<u8>, Error> {
        let states = self.records.entry(name(group, us)).or_default();
        if states.is_empty() {
            let key_id = random.sequence().map_err(|_| Error::UNKNOWN)?;
            let mut seed = vec![0u8; 32];
            random.fill(&mut seed).map_err(|_| Error::UNKNOWN)?;
            let signing = KeyPair::generate(random)?;
            states.push(SenderKeyState {
                key_id,
                chain: ChainKey { iteration: 0, seed },
                signing_public: signing.public,
                signing_private: Some(signing),
                skipped: Vec::new(),
            });
        }
        let state = &states[0];
        Ok(SenderKeyDistributionMessage::new(state.key_id, state.chain.iteration,
                                             &state.chain.seed, state.signing_public)
            .serialized)
    }

    /// Take a member's distribution message. A second one for the same
    /// sender is added in front rather than replacing, so messages under
    /// the older key still decrypt.
    pub fn process(&mut self, group: &str, sender: &str, data: &[u8]) -> Result<(), Error> {
        let message = SenderKeyDistributionMessage::parse(data)?;
        let states = self.records.entry(name(group, sender)).or_default();
        states.insert(0, SenderKeyState {
            key_id: message.key_id,
            chain: ChainKey { iteration: message.iteration, seed: message.chain_key },
            signing_public: message.signing_key,
            signing_private: None,
            skipped: Vec::new(),
        });
        states.truncate(MAX_STATES);
        Ok(())
    }

    pub fn encrypt(&mut self, random: &mut Random, group: &str, us: &str, plaintext: &[u8])
                   -> Result<Vec<u8>, Error> {
        // No sender key yet: libsignal finds no state (an invalid key
        // id) and reports it as having no session.
        let state = self.records.get_mut(&name(group, us)).and_then(|states| states.first_mut())
            .ok_or(Error::NO_SESSION)?;
        let signing = state.signing_private.as_ref().ok_or(Error::INVALID_KEY)?;
        let key = state.chain.message_key();
        let ciphertext = encrypt(&key.cipher, &key.iv, plaintext)?;
        let message = SenderKeyMessage::new(random, state.key_id, key.iteration, ciphertext,
                                             signing)?;
        state.chain = state.chain.next();
        Ok(message.serialized)
    }

    pub fn decrypt(&mut self, group: &str, sender: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
        let message = SenderKeyMessage::parse(data)?;
        let states = self.records.get(&name(group, sender)).filter(|states| !states.is_empty())
            .ok_or(Error::NO_SESSION)?;
        let at = states.iter().position(|state| state.key_id == message.key_id)
            // libsignal reports a key id it does not have as an invalid
            // message, not as the missing-key error it is internally.
            .ok_or(Error::INVALID_MESSAGE)?;
        let mut state = states[at].clone();
        if !message.verify(&state.signing_public) {
            return Err(Error::INVALID_MESSAGE);
        }
        let key = state.message_key(message.iteration)?;
        let plaintext = decrypt(&key.cipher, &key.iv, &message.ciphertext)?;
        if let Some(states) = self.records.get_mut(&name(group, sender)) {
            states[at] = state;
        }
        Ok(plaintext)
    }
}

impl SenderKeyState {
    fn message_key(&mut self, iteration: u32) -> Result<MessageKey, Error> {
        if self.chain.iteration > iteration {
            let at = self.skipped.iter().position(|key| key.iteration == iteration)
                .ok_or(Error::DUPLICATE_MESSAGE)?;
            return Ok(self.skipped.remove(at));
        }
        if iteration - self.chain.iteration > MAX_SKIP {
            return Err(Error::INVALID_MESSAGE);
        }
        let mut chain = self.chain.clone();
        while chain.iteration < iteration {
            self.skipped.push(chain.message_key());
            if self.skipped.len() > MAX_MESSAGE_KEYS {
                self.skipped.remove(0);
            }
            chain = chain.next();
        }
        self.chain = chain.next();
        Ok(chain.message_key())
    }
}
