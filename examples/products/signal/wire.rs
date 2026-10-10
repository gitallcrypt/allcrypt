//! Keys, errors and the four message formats, version 3.
//!
//! Every message starts with one byte: the message's version in the
//! high nibble and the current version, 3, in the low one - `0x33`.
//! The rest is a protobuf, followed by a truncated MAC (a signal
//! message), a signature (a group message), or nothing.

use allcrypt::ec::{x25519, xeddsa};
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::mac::hmac::Hmac;

use crate::proto::{self, Writer};
use crate::rng::Random;

pub const VERSION: u8 = 3;
pub const SIGNAL_TYPE: u32 = 2;
pub const PREKEY_TYPE: u32 = 3;
pub const SENDERKEY_TYPE: u32 = 4;
pub const MAC_LEN: usize = 8;
pub const SIGNATURE_LEN: usize = 64;
/// The type byte in front of every serialised Curve25519 public key.
const DJB_TYPE: u8 = 5;

/// A failure, as libsignal-protocol-c's error code, so that the check
/// against it can compare refusals as well as successes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub i32);

impl Error {
    pub const INVALID_ARGUMENT: Error = Error(-22);
    pub const UNKNOWN: Error = Error(-1000);
    pub const DUPLICATE_MESSAGE: Error = Error(-1001);
    pub const INVALID_KEY: Error = Error(-1002);
    pub const INVALID_KEY_ID: Error = Error(-1003);
    pub const INVALID_MESSAGE: Error = Error(-1005);
    pub const INVALID_VERSION: Error = Error(-1006);
    pub const LEGACY_MESSAGE: Error = Error(-1007);
    pub const NO_SESSION: Error = Error(-1008);
    pub const UNTRUSTED_IDENTITY: Error = Error(-1010);
    pub const INVALID_PROTOBUF: Error = Error(-1100);

    pub fn describe(self) -> &'static str {
        match self.0 {
            -22 => "an argument is malformed",
            -1000 => "the operation failed",
            -1001 => "this message was already decrypted",
            -1002 => "a key is not a valid Curve25519 public key, or a signature over one is wrong",
            -1003 => "no prekey or sender key has that id",
            -1005 => "the message does not decrypt or does not authenticate",
            -1006 => "the message is from a later version of the protocol",
            -1007 => "the message is from a version before 3, which is not supported",
            -1008 => "there is no session with this peer",
            -1010 => "the peer's identity key has changed",
            -1100 => "the message is not a well-formed protobuf",
            _ => "unrecognised error",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.describe(), self.0)
    }
}

// ------------------------------------------------------------------ keys --

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// `0x05 || u`.
    pub fn serialize(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = DJB_TYPE;
        out[1..].copy_from_slice(&self.0);
        out
    }

    /// libsignal's `curve_decode_point`: the type byte, then exactly 32
    /// bytes. Any `u` is accepted - X25519 has no invalid points, only
    /// low-order ones, and libsignal does not look for those.
    pub fn decode(bytes: &[u8]) -> Result<PublicKey, Error> {
        if bytes.len() != 33 || bytes[0] != DJB_TYPE {
            return Err(Error::INVALID_KEY);
        }
        let mut u = [0u8; 32];
        u.copy_from_slice(&bytes[1..]);
        Ok(PublicKey(u))
    }
}

#[derive(Clone)]
pub struct KeyPair {
    pub private: [u8; 32],
    pub public: PublicKey,
}

impl KeyPair {
    /// 32 random bytes, clamped and stored clamped, as
    /// `curve_generate_private_key` does.
    pub fn generate(random: &mut Random) -> Result<KeyPair, Error> {
        let mut private = [0u8; 32];
        random.fill(&mut private).map_err(|_| Error::UNKNOWN)?;
        KeyPair::from_private(x25519::clamp(&private))
    }

    pub fn from_private(private: [u8; 32]) -> Result<KeyPair, Error> {
        let public = x25519::public_key(&private).map_err(|_| Error::UNKNOWN)?;
        Ok(KeyPair { private, public: PublicKey(public) })
    }

    /// The raw X25519 function, with **no** check for an all-zero
    /// result. libsignal makes none - `curve25519_donna` cannot fail -
    /// and refusing here would refuse sessions libsignal completes.
    pub fn agree(&self, peer: &PublicKey) -> [u8; 32] {
        x25519::x25519(&self.private, &peer.0).unwrap_or([0; 32])
    }

    /// An XEdDSA signature in libsignal's form, over 64 fresh random
    /// bytes drawn here, as `curve_calculate_signature` draws them.
    pub fn sign(&self, random: &mut Random, message: &[u8]) -> Result<[u8; 64], Error> {
        let mut z = [0u8; 64];
        random.fill(&mut z).map_err(|_| Error::UNKNOWN)?;
        xeddsa::sign(xeddsa::Form::Signal, &self.private, message, &z)
            .map_err(|_| Error::UNKNOWN)
    }
}

pub fn verify(key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    match <&[u8; 64]>::try_from(signature) {
        Ok(signature) => {
            xeddsa::verify(xeddsa::Form::Signal, &key.0, message, signature).is_ok()
        }
        Err(_) => false,
    }
}

/// A field this message defines, present with the wrong wire type, is
/// a protobuf error - protobuf-c fails the whole unpack on it - and
/// that is decided for *every* field before any missing one is an
/// invalid message, which is the order libsignal reports them in.
fn well_formed<T>(value: Result<Option<T>, ()>) -> Result<Option<T>, Error> {
    value.map_err(|()| Error::INVALID_PROTOBUF)
}

fn required<T>(value: Option<T>) -> Result<T, Error> {
    value.ok_or(Error::INVALID_MESSAGE)
}

// -------------------------------------------------------- SignalMessage --

/// `version || SignalMessage || MAC[..8]`, the MAC an HMAC-SHA256 over
/// `sender identity || receiver identity || version || SignalMessage`.
///
/// **The identities are in the MAC from version 3 on, and their order is
/// sender then receiver.** The receiver therefore checks with the order
/// reversed from its own point of view - remote, then local - and
/// getting that backwards fails every message in one direction only.
#[derive(Clone, Debug)]
pub struct SignalMessage {
    pub version: u8,
    pub ratchet_key: PublicKey,
    pub counter: u32,
    /// The last counter on the sender's previous chain. Carried, and
    /// ignored on receipt, as libsignal ignores it: keys skipped on an
    /// old chain are derived when a message on it arrives, from that
    /// message's own counter, so nothing needs the total in advance.
    #[allow(dead_code)]
    pub previous_counter: u32,
    pub ciphertext: Vec<u8>,
    pub serialized: Vec<u8>,
}

fn message_mac(version: u8, mac_key: &[u8], sender: &PublicKey, receiver: &PublicKey,
               body: &[u8]) -> [u8; MAC_LEN] {
    let mut input = Vec::with_capacity(66 + body.len());
    if version >= 3 {
        input.extend_from_slice(&sender.serialize());
        input.extend_from_slice(&receiver.serialize());
    }
    input.extend_from_slice(body);
    let full = Hmac::mac(SHA256::new(&[]), mac_key, &input);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

impl SignalMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(mac_key: &[u8], ratchet_key: PublicKey, counter: u32, previous_counter: u32,
               ciphertext: Vec<u8>, sender: &PublicKey, receiver: &PublicKey) -> SignalMessage {
        let mut serialized = vec![(VERSION << 4) | VERSION];
        serialized.extend_from_slice(
            &Writer::new()
                .bytes(1, &ratchet_key.serialize())
                .varint(2, u64::from(counter))
                .varint(3, u64::from(previous_counter))
                .bytes(4, &ciphertext)
                .finish(),
        );
        let mac = message_mac(VERSION, mac_key, sender, receiver, &serialized);
        serialized.extend_from_slice(&mac);
        SignalMessage { version: VERSION, ratchet_key, counter, previous_counter, ciphertext,
                        serialized }
    }

    /// `signal_message_deserialize`. A version-2 message parses - its
    /// MAC and cipher differ, and the session refuses it later by
    /// version - while 0 and 1 are legacy and above 3 is unknown.
    pub fn parse(data: &[u8]) -> Result<SignalMessage, Error> {
        if data.len() <= 1 + MAC_LEN {
            return Err(Error::INVALID_ARGUMENT);
        }
        let version = data[0] >> 4;
        if version <= 1 {
            return Err(Error::LEGACY_MESSAGE);
        }
        if version > VERSION {
            return Err(Error::INVALID_MESSAGE);
        }
        let fields = proto::parse(&data[1..data.len() - MAC_LEN])
            .ok_or(Error::INVALID_PROTOBUF)?;
        let ratchet_key = well_formed(fields.bytes(1))?;
        let counter = well_formed(fields.uint32(2))?;
        let previous_counter = well_formed(fields.uint32(3))?.unwrap_or(0);
        let ciphertext = well_formed(fields.bytes(4))?;
        let (ciphertext, counter, ratchet_key) =
            (required(ciphertext)?, required(counter)?, required(ratchet_key)?);
        Ok(SignalMessage {
            version,
            ratchet_key: PublicKey::decode(ratchet_key)?,
            counter,
            previous_counter,
            ciphertext: ciphertext.to_vec(),
            serialized: data.to_vec(),
        })
    }

    pub fn verify_mac(&self, sender: &PublicKey, receiver: &PublicKey, mac_key: &[u8]) -> bool {
        let split = self.serialized.len() - MAC_LEN;
        let expected = message_mac(self.version, mac_key, sender, receiver,
                                   &self.serialized[..split]);
        constant_time_eq(&expected, &self.serialized[split..])
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// -------------------------------------------------- PreKeySignalMessage --

/// The first messages of a session, until the peer answers: a signal
/// message wrapped with what the recipient needs to build the session -
/// the sender's identity and base key, and which of the recipient's
/// prekeys were used.
#[derive(Clone, Debug)]
pub struct PreKeySignalMessage {
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key: PublicKey,
    pub identity_key: PublicKey,
    pub message: SignalMessage,
    pub serialized: Vec<u8>,
}

impl PreKeySignalMessage {
    pub fn new(registration_id: u32, pre_key_id: Option<u32>, signed_pre_key_id: u32,
               base_key: PublicKey, identity_key: PublicKey, message: SignalMessage)
               -> PreKeySignalMessage {
        let mut writer = Writer::new();
        if let Some(id) = pre_key_id {
            writer.varint(1, u64::from(id));
        }
        writer
            .bytes(2, &base_key.serialize())
            .bytes(3, &identity_key.serialize())
            .bytes(4, &message.serialized)
            .varint(5, u64::from(registration_id))
            .varint(6, u64::from(signed_pre_key_id));
        let mut serialized = vec![(VERSION << 4) | VERSION];
        serialized.extend_from_slice(&writer.finish());
        PreKeySignalMessage { registration_id, pre_key_id, signed_pre_key_id, base_key,
                              identity_key, message, serialized }
    }

    /// `pre_key_signal_message_deserialize`. Stricter about versions
    /// than a signal message - below 3 is legacy, above 3 is an
    /// *invalid version* rather than an invalid message - and the inner
    /// message must carry the same version as the wrapper.
    pub fn parse(data: &[u8]) -> Result<PreKeySignalMessage, Error> {
        if data.len() <= 1 {
            return Err(Error::INVALID_ARGUMENT);
        }
        let version = data[0] >> 4;
        if version < VERSION {
            return Err(Error::LEGACY_MESSAGE);
        }
        if version > VERSION {
            return Err(Error::INVALID_VERSION);
        }
        let fields = proto::parse(&data[1..]).ok_or(Error::INVALID_PROTOBUF)?;
        let pre_key_id = well_formed(fields.uint32(1))?;
        let base_key = well_formed(fields.bytes(2))?;
        let identity_key = well_formed(fields.bytes(3))?;
        let message = well_formed(fields.bytes(4))?;
        let registration_id = well_formed(fields.uint32(5))?.unwrap_or(0);
        let signed_pre_key_id = well_formed(fields.uint32(6))?;
        let (signed_pre_key_id, base_key, identity_key, message) = (
            required(signed_pre_key_id)?, required(base_key)?, required(identity_key)?,
            required(message)?);
        let base_key = PublicKey::decode(base_key)?;
        let identity_key = PublicKey::decode(identity_key)?;
        let message = SignalMessage::parse(message)?;
        if message.version != version {
            return Err(Error::INVALID_VERSION);
        }
        Ok(PreKeySignalMessage { registration_id, pre_key_id, signed_pre_key_id, base_key,
                                 identity_key, message, serialized: data.to_vec() })
    }
}

// ---------------------------------------------------- SenderKeyMessage --

/// A group message: `version || SenderKeyMessage || signature`, signed
/// by the sender's per-group signing key rather than MACed, because
/// every member holds the symmetric key and a MAC would let any of them
/// forge as any other.
#[derive(Clone, Debug)]
pub struct SenderKeyMessage {
    pub key_id: u32,
    pub iteration: u32,
    pub ciphertext: Vec<u8>,
    pub serialized: Vec<u8>,
}

impl SenderKeyMessage {
    pub fn new(random: &mut Random, key_id: u32, iteration: u32, ciphertext: Vec<u8>,
               signing_key: &KeyPair) -> Result<SenderKeyMessage, Error> {
        let mut serialized = vec![(VERSION << 4) | VERSION];
        serialized.extend_from_slice(
            &Writer::new()
                .varint(1, u64::from(key_id))
                .varint(2, u64::from(iteration))
                .bytes(3, &ciphertext)
                .finish(),
        );
        let signature = signing_key.sign(random, &serialized)?;
        serialized.extend_from_slice(&signature);
        Ok(SenderKeyMessage { key_id, iteration, ciphertext, serialized })
    }

    pub fn parse(data: &[u8]) -> Result<SenderKeyMessage, Error> {
        if data.len() <= 1 + SIGNATURE_LEN {
            return Err(Error::INVALID_ARGUMENT);
        }
        let version = data[0] >> 4;
        if version < VERSION {
            return Err(Error::LEGACY_MESSAGE);
        }
        if version > VERSION {
            return Err(Error::INVALID_VERSION);
        }
        let fields = proto::parse(&data[1..data.len() - SIGNATURE_LEN])
            .ok_or(Error::INVALID_PROTOBUF)?;
        let key_id = well_formed(fields.uint32(1))?;
        let iteration = well_formed(fields.uint32(2))?;
        let ciphertext = well_formed(fields.bytes(3))?;
        let (key_id, iteration, ciphertext) =
            (required(key_id)?, required(iteration)?, required(ciphertext)?);
        Ok(SenderKeyMessage { key_id, iteration, ciphertext: ciphertext.to_vec(),
                              serialized: data.to_vec() })
    }

    pub fn verify(&self, signing_key: &PublicKey) -> bool {
        let split = self.serialized.len() - SIGNATURE_LEN;
        verify(signing_key, &self.serialized[..split], &self.serialized[split..])
    }
}

// --------------------------------------- SenderKeyDistributionMessage --

/// What a group member sends each other member, over their pairwise
/// sessions, before its first group message: the chain key at an
/// iteration and the public half of the signing key.
#[derive(Clone, Debug)]
pub struct SenderKeyDistributionMessage {
    pub key_id: u32,
    pub iteration: u32,
    pub chain_key: Vec<u8>,
    pub signing_key: PublicKey,
    pub serialized: Vec<u8>,
}

impl SenderKeyDistributionMessage {
    pub fn new(key_id: u32, iteration: u32, chain_key: &[u8], signing_key: PublicKey)
               -> SenderKeyDistributionMessage {
        let mut serialized = vec![(VERSION << 4) | VERSION];
        serialized.extend_from_slice(
            &Writer::new()
                .varint(1, u64::from(key_id))
                .varint(2, u64::from(iteration))
                .bytes(3, chain_key)
                .bytes(4, &signing_key.serialize())
                .finish(),
        );
        SenderKeyDistributionMessage { key_id, iteration, chain_key: chain_key.to_vec(),
                                       signing_key, serialized }
    }

    pub fn parse(data: &[u8]) -> Result<SenderKeyDistributionMessage, Error> {
        if data.len() <= 1 {
            return Err(Error::INVALID_ARGUMENT);
        }
        let version = data[0] >> 4;
        if version < VERSION {
            return Err(Error::LEGACY_MESSAGE);
        }
        if version > VERSION {
            return Err(Error::INVALID_VERSION);
        }
        let fields = proto::parse(&data[1..]).ok_or(Error::INVALID_PROTOBUF)?;
        let key_id = well_formed(fields.uint32(1))?;
        let iteration = well_formed(fields.uint32(2))?;
        let chain_key = well_formed(fields.bytes(3))?;
        let signing_key = well_formed(fields.bytes(4))?;
        let (key_id, iteration, chain_key, signing_key) = (
            required(key_id)?, required(iteration)?, required(chain_key)?,
            required(signing_key)?);
        let signing_key = PublicKey::decode(signing_key)?;
        Ok(SenderKeyDistributionMessage { key_id, iteration, chain_key: chain_key.to_vec(),
                                          signing_key, serialized: data.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    #[test]
    fn test_a_public_key_is_the_type_byte_and_32_bytes() {
        assert_eq!(PublicKey::decode(&key(7).serialize()), Ok(key(7)));
        assert_eq!(PublicKey::decode(&[5; 32]), Err(Error::INVALID_KEY));
        let mut wrong_type = key(7).serialize();
        wrong_type[0] = 6;
        assert_eq!(PublicKey::decode(&wrong_type), Err(Error::INVALID_KEY));
    }

    /// The MAC covers both identities, sender first. Swapping them is
    /// the mistake a round trip between two copies of this code cannot
    /// see when both copies swap; checking with the order reversed must
    /// fail.
    #[test]
    fn test_the_mac_binds_both_identities_in_order() {
        let message = SignalMessage::new(&[1; 32], key(2), 5, 4, vec![9; 16], &key(3), &key(4));
        let parsed = SignalMessage::parse(&message.serialized).unwrap();
        assert!(parsed.verify_mac(&key(3), &key(4), &[1; 32]));
        assert!(!parsed.verify_mac(&key(4), &key(3), &[1; 32]));
        assert!(!parsed.verify_mac(&key(3), &key(4), &[2; 32]));
        assert_eq!((parsed.counter, parsed.previous_counter), (5, 4));
    }

    #[test]
    fn test_versions_are_refused_with_libsignals_codes() {
        let message = SignalMessage::new(&[1; 32], key(2), 0, 0, vec![9; 16], &key(3), &key(4));
        let with_version = |byte: u8| {
            let mut data = message.serialized.clone();
            data[0] = byte;
            data
        };
        assert_eq!(SignalMessage::parse(&with_version(0x13)).unwrap_err(), Error::LEGACY_MESSAGE);
        assert_eq!(SignalMessage::parse(&with_version(0x43)).unwrap_err(), Error::INVALID_MESSAGE);
        assert_eq!(SignalMessage::parse(&with_version(0x23)).unwrap().version, 2);

        let wrapped = PreKeySignalMessage::new(1, None, 2, key(5), key(6), message.clone());
        let mut data = wrapped.serialized.clone();
        data[0] = 0x23;
        assert_eq!(PreKeySignalMessage::parse(&data).unwrap_err(), Error::LEGACY_MESSAGE);
        data[0] = 0x43;
        assert_eq!(PreKeySignalMessage::parse(&data).unwrap_err(), Error::INVALID_VERSION);
    }

    #[test]
    fn test_a_missing_required_field_is_an_invalid_message() {
        // A SignalMessage with no counter.
        let mut data = vec![0x33];
        data.extend_from_slice(&Writer::new().bytes(1, &key(1).serialize()).bytes(4, &[0; 16])
            .finish());
        data.extend_from_slice(&[0; MAC_LEN]);
        assert_eq!(SignalMessage::parse(&data).unwrap_err(), Error::INVALID_MESSAGE);
        // And a field of the wrong wire type is a protobuf error.
        let mut data = vec![0x33];
        data.extend_from_slice(&Writer::new().bytes(2, &[1]).finish());
        data.extend_from_slice(&[0; MAC_LEN]);
        assert_eq!(SignalMessage::parse(&data).unwrap_err(), Error::INVALID_PROTOBUF);
    }

    #[test]
    fn test_the_prekey_id_is_optional_and_written_only_when_present() {
        let inner = SignalMessage::new(&[1; 32], key(2), 0, 0, vec![9; 16], &key(3), &key(4));
        let without = PreKeySignalMessage::new(7, None, 2, key(5), key(6), inner.clone());
        let with = PreKeySignalMessage::new(7, Some(9), 2, key(5), key(6), inner);
        assert_eq!(with.serialized.len(), without.serialized.len() + 2);
        assert_eq!(PreKeySignalMessage::parse(&without.serialized).unwrap().pre_key_id, None);
        assert_eq!(PreKeySignalMessage::parse(&with.serialized).unwrap().pre_key_id, Some(9));
    }
}
