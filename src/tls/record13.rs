/*
The TLS 1.3 record layer (RFC 8446 section 5).

Kept apart from `record.rs` for the same reason `keys13.rs` is kept apart
from `keys.rs`: this is not the old record layer with a different version
number. Four things change at once, and three of them are invisible if you
get them wrong while talking to yourself.

  * **The header lies, deliberately.** Every protected record says
    `application_data` and `0x0303`, whatever it actually carries, because
    a middlebox that inspects the type would otherwise break the
    connection. The real content type is the last non-zero byte of the
    *decrypted* plaintext.

  * **Padding is zeros after that byte**, and is removed by scanning back
    from the end. An all-zero plaintext therefore has no content type and
    is an error - `unexpected_message` - rather than something to guess at.

  * **The nonce is the static IV XOR the sequence number**, left-padded to
    twelve bytes. There is no explicit nonce on the wire any more, so
    nothing travels with the record that says which one was used: get the
    padding side wrong and every record fails to authenticate.

  * **The additional data is the five byte record header**, exactly as
    sent. Not the sequence number, not the plaintext length - the header,
    including the length of the *ciphertext plus tag*. TLS 1.2's AAD was
    `seq || type || version || plaintext_len`, and none of those fields
    survive.

And one that is not about bytes at all:

  * **The sequence number restarts at zero on every key change.** It
    belongs to the keys, not to the connection. Handshake keys start at
    zero, application keys start at zero again, and each KeyUpdate starts
    at zero. Carrying the count across a key change produces a nonce that
    nothing else will use.

A ChangeCipherSpec record arriving mid-handshake is a middlebox
compatibility relic and carries no protection at all. It must be dropped
without being decrypted - trying would fail its tag and tear down a
connection that is perfectly healthy.
*/

use crate::tls::keys13::TrafficKeys;
use crate::tls::record::{RecordError, SequenceNumber};
use crate::tls::{AlertDescription, ContentType, Version};

/// RFC 8446 section 5.2: the protected record may be up to 256 bytes
/// longer than the plaintext, not the 2048 that TLS 1.2 allowed for an
/// explicit nonce, a MAC and a block of padding.
pub const MAX_CIPHERTEXT_13: usize = crate::tls::record::MAX_PLAINTEXT + 256;

/// The version every TLS 1.3 record claims in its header, and the one the
/// reader must not check against the negotiated version.
pub const LEGACY_RECORD_VERSION: Version = Version::TLS12;

/// One direction's protection for TLS 1.3.
///
/// Holds the traffic keys and the sequence number *together*, because they
/// belong together: a key change replaces both, and a structure that let
/// one be replaced without the other is the bug this arrangement exists to
/// prevent.
pub struct Aead13 {
    aead_name: String,
    keys: TrafficKeys,
    sequence: SequenceNumber,
    tag_len: usize,
    /// The hash the schedule runs on, needed to derive the next epoch.
    hash_name: &'static str,
    /// RFC 9367's per-record re-keying, for the four GOST suites, and
    /// `None` for RFC 8446's own AEADs.
    ///
    /// Not a boolean and not a separate type: the whole point is that a
    /// record layer either uses its traffic key directly or derives one
    /// per record from a *named* schedule, and the schedule, the block
    /// size and the sequence cap travel together or not at all.
    mgm: Option<crate::tls::record_mgm::MgmSuite>,
}

impl core::fmt::Debug for Aead13 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Aead13 {{ {}, seq {}, keys redacted }}",
               self.aead_name, self.sequence.value())
    }
}

impl Aead13 {
    /// RFC 8446's record layer: the traffic key protects the whole
    /// epoch and only the nonce varies.
    pub fn new(aead_name: &str, hash_name: &'static str, keys: TrafficKeys,
               tag_len: usize) -> Result<Aead13, String> {
        Aead13::with_rekeying(aead_name, hash_name, keys, tag_len, None)
    }

    /// The same, with RFC 9367's external re-keying when the suite asks
    /// for it.
    ///
    /// `mgm` being `Some` changes three things at once, which is why it
    /// is one argument: the key for each record becomes
    /// `TLSTREE(write_key, seqnum)`, the nonce's top bit is cleared
    /// before the AEAD sees it, and the sequence number is capped at the
    /// suite's SNMAX. `src/tls/record_mgm.rs` has why each of them is
    /// not optional.
    pub fn with_rekeying(aead_name: &str, hash_name: &'static str,
                         keys: TrafficKeys, tag_len: usize,
                         mgm: Option<crate::tls::record_mgm::MgmSuite>)
                         -> Result<Aead13, String> {
        // Build one now to check the key length here rather than at the
        // first record, where the error would arrive with no context.
        // The nonce here is a placeholder of the right width; MGM cares
        // about its top bit, so it is built clear.
        let probe = vec![0u8; keys.iv.len()];
        crate::api::AeadStream::new(aead_name, &keys.key, &probe, &[], false)?;
        // **The IV's length is the AEAD's nonce length, and it is not
        // twelve for everything.** It used to be checked against a
        // constant, which was right for every AEAD RFC 8446 names and
        // wrong for all four of RFC 9367's.
        let expected = match &mgm {
            Some(suite) => suite.block,
            None => crate::tls::keys13::NONCE_LEN,
        };
        if keys.iv.len() != expected {
            return Err(format!(
                "This suite's record nonce is {} bytes; the IV derived for \
                 it is {}.", expected, keys.iv.len()));
        }
        if let Some(suite) = &mgm {
            if suite.aead != aead_name {
                return Err(format!(
                    "The MGM parameters are for {}, and the AEAD is {}.",
                    suite.aead, aead_name));
            }
            if tag_len != suite.block {
                return Err(format!(
                    "An MGM tag is one block, {} bytes here; the suite says \
                     {}.", suite.block, tag_len));
            }
        }
        Ok(Aead13 {
            aead_name: aead_name.to_string(),
            keys,
            sequence: SequenceNumber::zero(),
            tag_len,
            hash_name,
            mgm,
        })
    }

    /// The same, starting at a given sequence number.
    ///
    /// Nothing in a handshake needs this - every epoch starts at zero, and
    /// that is the point of the design. It exists so one record can be
    /// reproduced outside the connection that produced it, which is what
    /// `tools/src/bin/diff_tls13_record.rs` does to check the nonce against a
    /// reference written from the RFC. The nonce for a high sequence
    /// number is exactly the case a wrongly padded XOR gets wrong, and it
    /// is unreachable by encrypting records one at a time.
    ///
    /// Same reason `SequenceNumber::at` exists.
    pub fn starting_at(aead_name: &str, hash_name: &'static str, keys: TrafficKeys,
                       tag_len: usize, sequence: SequenceNumber)
                       -> Result<Aead13, String> {
        Aead13::starting_at_with_rekeying(aead_name, hash_name, keys, tag_len,
                                          sequence, None)
    }

    /// The same for an RFC 9367 suite, which is what makes the TLSTREE
    /// schedule reachable from a test: the interesting sequence numbers
    /// are the re-keying boundaries, and reaching 8192 by sending 8192
    /// records is not a test anyone runs.
    pub fn starting_at_with_rekeying(
        aead_name: &str, hash_name: &'static str, keys: TrafficKeys,
        tag_len: usize, sequence: SequenceNumber,
        mgm: Option<crate::tls::record_mgm::MgmSuite>)
        -> Result<Aead13, String> {
        let mut state = Aead13::with_rekeying(aead_name, hash_name, keys,
                                              tag_len, mgm)?;
        state.sequence = sequence;
        Ok(state)
    }

    pub fn name(&self) -> String {
        format!("{}-{}", self.aead_name, self.keys.key.len() * 8)
    }

    pub fn finished_key(&self) -> &[u8] {
        &self.keys.finished_key
    }

    pub fn sequence(&self) -> SequenceNumber {
        self.sequence
    }

    /// Move to the next epoch after a KeyUpdate (RFC 8446 section 7.2).
    ///
    /// The sequence number restarts at zero, which is the whole reason
    /// this replaces the structure rather than mutating the keys inside
    /// it: an update that left the counter running would produce nonces
    /// no peer computes.
    pub fn update(&mut self) -> Result<(), String> {
        self.keys = self.keys.update(self.hash_name)?;
        self.sequence = SequenceNumber::zero();
        Ok(())
    }

    /// The per-record nonce: the static IV XOR the sequence number,
    /// left-padded to the IV's length (RFC 8446 section 5.3).
    ///
    /// Left-padded. The counter goes in the *last* eight bytes, and the
    /// first four are the IV untouched. Padding on the other side is a
    /// mistake that is consistent with itself and with nothing else.
    fn nonce(&self, sequence: SequenceNumber) -> Vec<u8> {
        let mut nonce = self.keys.iv.clone();
        let counter = sequence.to_bytes();
        let offset = nonce.len() - counter.len();
        for (byte, value) in nonce[offset..].iter_mut().zip(counter.iter()) {
            *byte ^= value;
        }
        if self.mgm.is_some() {
            // RFC 9367 4.1.1 step 1. The bit is MGM's domain separator
            // rather than part of the nonce, and `block_ciphers::mgm`
            // refuses a nonce carrying it - deliberately, so that this
            // masking has to be somebody's decision rather than a
            // silent fixup inside the mode.
            crate::tls::record_mgm::MgmSuite::mask_nonce(&mut nonce);
        }
        nonce
    }

    /// The key protecting one record.
    ///
    /// RFC 8446 uses the traffic key for the whole epoch; RFC 9367
    /// derives `TLSTREE(sender_write_key, seqnum)` for each record.
    /// Returned by value because the second case has to compute one.
    fn record_key(&self, sequence: SequenceNumber) -> Vec<u8> {
        match &self.mgm {
            None => self.keys.key.clone(),
            Some(suite) => suite.record_key(&self.keys.key, sequence.value()),
        }
    }

    /// The additional data: the record header as it appears on the wire.
    ///
    /// `opaque_type || legacy_record_version || length`, where the length
    /// is the protected fragment's - ciphertext plus tag - and not the
    /// plaintext's. The sequence number is *not* in here; it is in the
    /// nonce, and putting it in both is TLS 1.2's habit.
    fn additional_data(length: usize) -> [u8; 5] {
        let length = (length as u16).to_be_bytes();
        [ContentType::ApplicationData.to_byte(),
         LEGACY_RECORD_VERSION.major, LEGACY_RECORD_VERSION.minor,
         length[0], length[1]]
    }

    /// Protect one record.
    ///
    /// `padding` is how many zero bytes to add after the content type, for
    /// hiding the length of what is inside. Zero is legal and is what
    /// everything does by default.
    pub fn encrypt(&mut self, content_type: ContentType, plaintext: &[u8],
                   padding: usize) -> Result<Vec<u8>, RecordError> {
        let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);
        let sequence = self.sequence.next()?;

        // TLSInnerPlaintext: the content, then the *real* type, then the
        // padding. The type goes before the padding, not after - it is
        // found by scanning back past the zeros.
        let mut inner = Vec::with_capacity(plaintext.len() + 1 + padding);
        inner.extend_from_slice(plaintext);
        inner.push(content_type.to_byte());
        inner.resize(inner.len() + padding, 0);

        // RFC 9367 4.1.3 caps how many records one traffic key may
        // protect, and the cap is as low as 2^39-1. Past it a sender
        // must re-key rather than wrap, so this refuses rather than
        // continuing - the same decision `CtrOmac` makes at Magma's
        // 2^32-1.
        if let Some(suite) = &self.mgm {
            if !suite.within_snmax(sequence.value()) {
                return Err(internal(format!(
                    "This suite may protect at most {} records under one \
                     traffic key (RFC 9367 section 4.1.3); the connection \
                     has to re-key.", suite.snmax)));
            }
        }

        let aad = Self::additional_data(inner.len() + self.tag_len);
        let nonce = self.nonce(sequence);
        let key = self.record_key(sequence);
        let (ciphertext, tag) = crate::api::aead_encrypt(
            &self.aead_name, &key, &nonce, &aad, &inner)
            .map_err(internal)?;

        let mut out = Vec::with_capacity(ciphertext.len() + tag.len());
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Unprotect one record, returning the real content type and the
    /// plaintext with its padding and type byte removed.
    ///
    /// Every failure is `bad_record_mac` with one message, except the
    /// all-padding case, which is a structural error rather than an
    /// authentication one - the record authenticated, and then turned out
    /// to say nothing.
    pub fn decrypt(&mut self, fragment: &[u8])
                   -> Result<(ContentType, Vec<u8>), RecordError> {
        let bad = || RecordError::new(
            AlertDescription::BAD_RECORD_MAC,
            "The record did not authenticate. It was altered in transit, or \
             the keys do not match.".to_string());

        if fragment.len() < self.tag_len {
            return Err(bad());
        }
        // **Peeked, and committed only if the record authenticates.** A
        // failed deprotection is fatal on an ordinary connection, so
        // advancing the counter would cost nothing there - but a server
        // that *rejected* early data is required to attempt and discard
        // the records the client already sent under its early keys (RFC
        // 8446 4.2.10), and a counter advanced by each of those leaves
        // the client's real Finished decrypting under the wrong nonce.
        // The symptom is a handshake that fails only when 0-RTT was
        // offered and declined, which is the one case no ordinary test
        // covers.
        let sequence = *self.sequence.peek();
        let (ciphertext, tag) = fragment.split_at(fragment.len() - self.tag_len);

        // The AAD is the header of the record as it arrived, and its
        // length field covers the whole fragment - so it is reconstructed
        // from `fragment.len()`, not from the plaintext we are about to
        // get.
        let aad = Self::additional_data(fragment.len());
        let nonce = self.nonce(sequence);
        let key = self.record_key(sequence);
        let mut inner = crate::api::aead_decrypt(
            &self.aead_name, &key, &nonce, &aad, ciphertext, tag)
            .map_err(|_| bad())?;
        self.sequence.next()?;

        // Strip the zero padding from the end. The first non-zero byte
        // going backwards is the content type.
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let content_type = match inner.pop() {
            Some(byte) => ContentType::from_byte(byte),
            None => return Err(RecordError::new(
                AlertDescription::UNEXPECTED_MESSAGE,
                "A TLS 1.3 record decrypted to nothing but padding, so it \
                 carries no content type. RFC 8446 section 5.4 says this is \
                 unexpected_message rather than something to guess at."
                    .to_string())),
        };

        // RFC 8446 section 5: change_cipher_spec is never encrypted, so
        // one arriving *inside* a protected record is a peer doing
        // something the protocol does not allow. Refusing it here keeps
        // the state machine from having to think about it.
        if content_type == ContentType::ChangeCipherSpec {
            return Err(RecordError::new(
                AlertDescription::UNEXPECTED_MESSAGE,
                "A change_cipher_spec arrived inside a protected record. \
                 TLS 1.3 never encrypts one.".to_string()));
        }

        Ok((content_type, inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::keys13::{Schedule, TrafficKeys};
    use crate::tls::suites::MacAlgorithm;

    fn pair() -> (Aead13, Aead13) {
        let schedule = Schedule::early(MacAlgorithm::Sha256, None).unwrap()
            .handshake(&[0x5c; 32]).unwrap();
        let (client, server) = schedule.handshake_traffic(&[0x2b; 32], 16, 12).unwrap();
        (Aead13::new("aes-gcm", "sha256", client, 16).unwrap(),
         Aead13::new("aes-gcm", "sha256", server, 16).unwrap())
    }

    /// One `Aead13` for each end of the *same* direction, so what one
    /// writes the other reads. Two independently derived ones would be
    /// two different directions and would never agree.
    fn same_direction() -> (Aead13, Aead13) {
        let schedule = Schedule::early(MacAlgorithm::Sha256, None).unwrap()
            .handshake(&[0x5c; 32]).unwrap();
        let (client, _) = schedule.handshake_traffic(&[0x2b; 32], 16, 12).unwrap();
        (Aead13::new("aes-gcm", "sha256", client.clone(), 16).unwrap(),
         Aead13::new("aes-gcm", "sha256", client, 16).unwrap())
    }

    #[test]
    fn test_a_record_round_trips_with_its_real_content_type() {
        let (mut writer, mut reader) = same_direction();
        for content_type in [ContentType::Handshake, ContentType::ApplicationData,
                             ContentType::Alert] {
            let payload = b"the quick brown fox".to_vec();
            let fragment = writer.encrypt(content_type, &payload, 0).unwrap();
            let (got_type, got) = reader.decrypt(&fragment).unwrap();
            assert_eq!(got_type, content_type);
            assert_eq!(got, payload);
        }
    }

    /// The type byte is inside the ciphertext, so the header cannot say
    /// what a record carries. That is the point of the construction.
    #[test]
    fn test_the_type_is_not_visible_in_the_fragment() {
        let (mut writer, _) = same_direction();
        let handshake = writer.encrypt(ContentType::Handshake, b"x", 0).unwrap();
        // Length is the only thing that leaks, and padding is what hides
        // that. One byte of content plus one type byte plus the tag.
        assert_eq!(handshake.len(), 1 + 1 + 16);
    }

    /// Padding is stripped by scanning back, and must not eat content.
    #[test]
    fn test_padding_is_stripped_without_touching_trailing_zeros_of_content() {
        let (mut writer, mut reader) = same_direction();
        // Content that itself ends in zeros - the case where a padding
        // stripper that scanned too eagerly would silently truncate.
        let payload = vec![0x01, 0x00, 0x00, 0x00];
        for padding in [0usize, 1, 7, 255] {
            let fragment = writer.encrypt(ContentType::ApplicationData,
                                          &payload, padding).unwrap();
            let (got_type, got) = reader.decrypt(&fragment).unwrap();
            assert_eq!(got_type, ContentType::ApplicationData);
            assert_eq!(got, payload, "padding {}", padding);
        }
    }

    /// An empty record is legal: no content, just the type byte.
    #[test]
    fn test_an_empty_record_carries_only_its_type() {
        let (mut writer, mut reader) = same_direction();
        let fragment = writer.encrypt(ContentType::ApplicationData, &[], 0).unwrap();
        let (got_type, got) = reader.decrypt(&fragment).unwrap();
        assert_eq!(got_type, ContentType::ApplicationData);
        assert!(got.is_empty());
    }

    /// All padding and no type byte. RFC 8446 section 5.4 names this
    /// `unexpected_message`, and it is worth distinguishing from a MAC
    /// failure: the record *did* authenticate, so the peer sent it on
    /// purpose.
    #[test]
    fn test_a_record_of_nothing_but_padding_is_unexpected_message() {
        let (mut writer, mut reader) = same_direction();

        // Encrypt an inner plaintext that is all zeros, by hand - the
        // normal path cannot produce one, which is the point.
        let sequence = writer.sequence.next().unwrap();
        let inner = vec![0u8; 8];
        let aad = Aead13::additional_data(inner.len() + 16);
        let nonce = writer.nonce(sequence);
        let (ciphertext, tag) = crate::api::aead_encrypt(
            "aes-gcm", &writer.keys.key, &nonce, &aad, &inner).unwrap();
        let mut fragment = ciphertext;
        fragment.extend_from_slice(&tag);

        let error = reader.decrypt(&fragment).unwrap_err();
        assert_eq!(error.alert, AlertDescription::UNEXPECTED_MESSAGE,
                   "{}", error.describe());
    }

    /// The sequence number is in the nonce and nowhere else, so two
    /// records with the same content must still differ - and must be read
    /// back in order.
    #[test]
    fn test_the_sequence_number_advances_and_order_matters() {
        let (mut writer, mut reader) = same_direction();
        let first = writer.encrypt(ContentType::ApplicationData, b"same", 0).unwrap();
        let second = writer.encrypt(ContentType::ApplicationData, b"same", 0).unwrap();
        assert_ne!(first, second, "the nonce must advance");

        // Reading them the wrong way round fails, because the reader's
        // own counter says which nonce it expects.
        assert!(reader.decrypt(&second).is_err());
    }

    /// Every bit of the fragment is covered by the tag.
    #[test]
    fn test_any_single_bit_flip_is_refused() {
        let (mut writer, _) = same_direction();
        let fragment = writer.encrypt(ContentType::Handshake, b"authenticated", 0)
            .unwrap();
        for index in 0..fragment.len() {
            for bit in [0x01u8, 0x80] {
                let (_, mut reader) = same_direction();
                let mut damaged = fragment.clone();
                damaged[index] ^= bit;
                let error = reader.decrypt(&damaged).unwrap_err();
                assert_eq!(error.alert, AlertDescription::BAD_RECORD_MAC,
                           "byte {} bit {:#x}", index, bit);
            }
        }
    }

    /// The two directions must not read each other. This is the check
    /// that the client and server keys really are different all the way
    /// through the record layer, not only in the schedule.
    #[test]
    fn test_the_two_directions_cannot_read_each_other() {
        let (mut client, mut server) = pair();
        let fragment = client.encrypt(ContentType::Handshake, b"mine", 0).unwrap();
        assert!(server.decrypt(&fragment).is_err());
    }

    /// The AAD carries the fragment's length, so a record whose length
    /// field was tampered with fails even if the ciphertext is untouched.
    /// There is no separate test for that here because the AAD is built
    /// from `fragment.len()` on both sides - what this checks is the
    /// consequence: a truncated fragment is refused rather than decoded
    /// short.
    #[test]
    fn test_a_truncated_fragment_is_refused() {
        let (mut writer, _) = same_direction();
        let fragment = writer.encrypt(ContentType::ApplicationData,
                                      b"a reasonable amount of data", 0).unwrap();
        for keep in 0..fragment.len() {
            let (_, mut reader) = same_direction();
            assert!(reader.decrypt(&fragment[..keep]).is_err(), "kept {}", keep);
        }
    }

    /// A change_cipher_spec is never encrypted in TLS 1.3, so one inside a
    /// protected record is a peer doing something the protocol forbids.
    #[test]
    fn test_an_encrypted_change_cipher_spec_is_refused() {
        let (mut writer, mut reader) = same_direction();
        let fragment = writer.encrypt(ContentType::ChangeCipherSpec, &[1], 0).unwrap();
        let error = reader.decrypt(&fragment).unwrap_err();
        assert_eq!(error.alert, AlertDescription::UNEXPECTED_MESSAGE);
    }

    /// A key update replaces the keys *and* restarts the counter. Leaving
    /// the counter running would produce nonces nobody else computes, and
    /// nothing on this side would notice.
    #[test]
    fn test_a_key_update_restarts_the_sequence_number() {
        let (mut writer, mut reader) = same_direction();
        for _ in 0..5 {
            let fragment = writer.encrypt(ContentType::ApplicationData, b"x", 0).unwrap();
            reader.decrypt(&fragment).unwrap();
        }
        assert_eq!(writer.sequence().value(), 5);

        writer.update().unwrap();
        reader.update().unwrap();
        assert_eq!(writer.sequence().value(), 0);
        assert_eq!(reader.sequence().value(), 0);

        let fragment = writer.encrypt(ContentType::ApplicationData, b"after", 0).unwrap();
        let (_, got) = reader.decrypt(&fragment).unwrap();
        assert_eq!(got, b"after");
    }

    /// The old keys must not read the new epoch's records, which is what
    /// makes a key update worth doing.
    #[test]
    fn test_the_old_keys_cannot_read_the_new_epoch() {
        let (mut writer, mut stale) = same_direction();
        writer.update().unwrap();
        let fragment = writer.encrypt(ContentType::ApplicationData, b"new", 0).unwrap();
        assert!(stale.decrypt(&fragment).is_err());
    }

    /// CCM_8's tag is eight bytes, and a record layer that assumed sixteen
    /// would read the last eight bytes of every ciphertext as tag.
    #[test]
    fn test_a_short_tag_suite_is_handled() {
        let schedule = Schedule::early(MacAlgorithm::Sha256, None).unwrap()
            .handshake(&[0x11; 32]).unwrap();
        let (secret, _) = schedule.handshake_traffic(&[0x77; 32], 16, 12).unwrap();
        let mut writer = Aead13::new("aes-ccm-8", "sha256",
                                     secret.clone(), 8).unwrap();
        let mut reader = Aead13::new("aes-ccm-8", "sha256", secret, 8).unwrap();

        let fragment = writer.encrypt(ContentType::Handshake, b"eight", 0).unwrap();
        assert_eq!(fragment.len(), 5 + 1 + 8);
        let (got_type, got) = reader.decrypt(&fragment).unwrap();
        assert_eq!(got_type, ContentType::Handshake);
        assert_eq!(got, b"eight");
    }

    /// An IV that is not twelve bytes is refused when the keys are built,
    /// not at the first record.
    #[test]
    fn test_a_wrong_length_iv_is_refused_up_front() {
        let mut keys = TrafficKeys {
            secret: vec![0; 32], key: vec![0; 16], iv: vec![0; 16],
            finished_key: vec![0; 32],
        };
        assert!(Aead13::new("aes-gcm", "sha256", keys.clone(), 16).is_err());
        keys.iv = vec![0; 12];
        assert!(Aead13::new("aes-gcm", "sha256", keys, 16).is_ok());
    }

    /// The nonce is the IV XOR the sequence number in the *last* eight
    /// bytes. Written out here rather than only round-tripped, because
    /// padding on the wrong side is self-consistent.
    #[test]
    fn test_the_nonce_is_the_iv_xor_the_counter_left_padded() {
        let keys = TrafficKeys {
            secret: vec![0; 32], key: vec![0; 16],
            iv: vec![0xff; 12], finished_key: vec![0; 32],
        };
        let state = Aead13::new("aes-gcm", "sha256", keys, 16).unwrap();

        assert_eq!(state.nonce(SequenceNumber::zero()), vec![0xff; 12]);
        // Sequence 1 touches only the last byte.
        let mut expected = vec![0xffu8; 12];
        expected[11] = 0xfe;
        assert_eq!(state.nonce(SequenceNumber::at(1)), expected);
        // And a counter big enough to reach the ninth byte from the end
        // must leave the first four alone.
        let nonce = state.nonce(SequenceNumber::at(u64::MAX));
        assert_eq!(&nonce[..4], &[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(&nonce[4..], &[0u8; 8]);
    }

    /// The AAD is the wire header, whose length field covers ciphertext
    /// plus tag - not the plaintext.
    #[test]
    fn test_the_additional_data_is_the_wire_header() {
        assert_eq!(Aead13::additional_data(0x1234),
                   [0x17, 0x03, 0x03, 0x12, 0x34]);
    }

    // --- through the record framing, where the header is written ---

    use crate::tls::record::{Protection, RecordReader, RecordWriter};

    fn framed() -> (RecordWriter, RecordReader) {
        let (send, receive) = same_direction();
        let mut writer = RecordWriter::new(Version::TLS12);
        writer.change_cipher_spec(Protection::Aead13(send));
        let mut reader = RecordReader::new();
        reader.change_cipher_spec(Protection::Aead13(receive));
        (writer, reader)
    }

    /// Every protected record's header says application_data and 0x0303,
    /// whatever it carries - and the reader gets the real type back out.
    #[test]
    fn test_the_framed_header_says_application_data_whatever_it_carries() {
        let (mut writer, mut reader) = framed();
        for content_type in [ContentType::Handshake, ContentType::Alert,
                             ContentType::ApplicationData] {
            let bytes = writer.write(content_type, b"inside").unwrap();
            assert_eq!(bytes[0], ContentType::ApplicationData.to_byte(),
                       "header type for {:?}", content_type);
            assert_eq!(&bytes[1..3], &[0x03, 0x03]);

            reader.push_incoming(&bytes);
            let record = reader.read().unwrap().unwrap();
            assert_eq!(record.content_type, content_type);
            assert_eq!(record.payload, b"inside");
        }
    }

    /// A ChangeCipherSpec arriving after the keys are in place is the
    /// middlebox compatibility relic, sent in the clear. Decrypting it
    /// would fail its tag and tear down a healthy connection.
    #[test]
    fn test_a_plaintext_change_cipher_spec_passes_through() {
        let (_, mut reader) = framed();
        reader.push_incoming(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        let record = reader.read().unwrap().unwrap();
        assert_eq!(record.content_type, ContentType::ChangeCipherSpec);
        assert_eq!(record.payload, vec![0x01]);

        // ...and it must not have advanced the record counter, or every
        // record after it would use the wrong nonce.
        let (mut writer, _) = framed();
        let bytes = writer.write(ContentType::ApplicationData, b"next").unwrap();
        reader.push_incoming(&bytes);
        let record = reader.read().unwrap().unwrap();
        assert_eq!(record.payload, b"next");
    }

    /// Anything else in the clear after the keys are in place is a peer
    /// bypassing encryption, which is not a thing to accept quietly.
    #[test]
    fn test_an_unprotected_handshake_record_is_refused() {
        let (_, mut reader) = framed();
        reader.push_incoming(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x00]);
        let error = reader.read().unwrap_err();
        assert_eq!(error.alert, AlertDescription::UNEXPECTED_MESSAGE);
    }

    /// The header's version is a decoy and is fixed at 0x0303. A record
    /// that says 0x0304 is not a TLS 1.3 record however much it looks
    /// like one.
    #[test]
    fn test_a_record_claiming_the_real_version_is_refused() {
        let (_, mut reader) = framed();
        reader.push_incoming(&[0x17, 0x03, 0x04, 0x00, 0x01, 0x00]);
        let error = reader.read().unwrap_err();
        assert_eq!(error.alert, AlertDescription::PROTOCOL_VERSION);
    }

    /// TLS 1.3 allows 256 bytes of expansion, not 2048. A peer claiming
    /// more is refused before anything is allocated.
    #[test]
    fn test_the_expansion_allowance_is_the_smaller_one() {
        let (_, mut reader) = framed();
        let too_long = crate::tls::record::MAX_PLAINTEXT + 257;
        let mut header = vec![0x17, 0x03, 0x03];
        header.extend_from_slice(&(too_long as u16).to_be_bytes());
        reader.push_incoming(&header);
        let error = reader.read().unwrap_err();
        assert_eq!(error.alert, AlertDescription::RECORD_OVERFLOW);
    }
}
