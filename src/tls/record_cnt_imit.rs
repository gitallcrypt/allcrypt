/*
The CNT_IMIT record protection from RFC 9189 section 4.1.2.

`TLS_GOSTR341112_256_WITH_28147_CNT_IMIT` is the oldest of RFC 9189's
three suites and shares nothing with the other two below the key
exchange. GOST 28147-89 in CNT mode (RFC 5830 section 6) with CryptoPro
key meshing does the encryption, and `gostIMIT28147` with a four byte
tag does the authentication.

It is authenticate-then-encrypt over a stream cipher, like CTR_OMAC -
and there the similarity stops, because **this construction is
cumulative in both halves**:

    MACValue_n = MAC(K_MAC, STR_8(0) | header_0 | fragment_0 | ...
                            | STR_8(n) | header_n | fragment_n)

    ENC_0 | ... | ENC_n = ENC(K_ENC, IV,
                              fragment_0 | MAC_0 | ... | fragment_n | MAC_n)

Every record's MAC covers **every record so far**, and the keystream is
one stream for the whole connection. The RFC says so outright and adds
that neither needs reprocessing the earlier records - it is enough to
keep the MAC's chaining state and the cipher's counter, which is what
`CntImit` holds.

That is the opposite of CTR_OMAC, where each record has its own keys and
its own fresh stream, and it makes several habits wrong here:

  * **the state may not be rebuilt per record.** Doing so restarts the
    keystream, which repeats the gamma for every record - the single
    worst thing a stream cipher can do - and it round trips perfectly
    against an implementation making the same mistake;
  * **a record that fails to authenticate has still consumed keystream
    and MAC state.** The position is a function of how many bytes
    arrived, not of how many verified. Rewinding on failure would let
    anyone injecting a record desynchronise the two ends;
  * the MAC's input includes the record's own `MACValue`? No - it does
    not. The MAC covers the *fragments*, and the cipher covers the
    fragments *and* the MAC values. The two cover different byte
    streams, which is why they mesh on separate counts.

## The meshing

Both halves mesh under RFC 4357 (see `block_ciphers::meshing`), every
1024 octets, each on its own count. The counts differ: the MAC's input
carries eight bytes of sequence number and five of header per record on
top of the fragment, and the cipher's carries four bytes of tag. A
single shared counter would be wrong for both.

## Four bytes of tag

`gostIMIT28147` produces 32 bits. A blind forgery therefore succeeds
once in 2^32 attempts rather than once in 2^128, which is a real
difference and not a rounding one - it is why this suite is the one of
the three a modern deployment should not choose. It is implemented
because equipment that speaks only this exists and is not ours to
upgrade.
*/

use crate::block_ciphers::gost::GostCrypto;
use crate::block_ciphers::meshing;
use crate::block_ciphers::BlockCipher;
use crate::tls::record::{RecordError, SequenceNumber};
use crate::tls::{AlertDescription, ContentType, Version};
use crate::Mac;

/// The S-box RFC 9189 section 4.3.1 requires for this suite.
/// The S-box RFC 9189's CNT_IMIT suite encrypts and MACs with.
pub const SBOX: &str = "id-tc26-gost-28147-param-Z";

/// The S-box the *2001* suite uses - `TLS_GOSTR341001_WITH_28147_CNT_IMIT`,
/// draft-chudov-cryptopro-cptls section 3.1.
///
/// **The record layer is otherwise identical**: CNT with CryptoPro
/// meshing, a cumulative keystream and a cumulative four byte MAC, the
/// same 32/32/8 key material. Only the table changes, and a table is
/// the whole of a GOST cipher - so the two suites' record layers
/// produce entirely different bytes from the same keys, and nothing
/// but this constant says which is which.
pub const SBOX_2001: &str = "id-Gost28147-89-CryptoPro-A-ParamSet";

/// `gostIMIT28147`'s output length, RFC 9189 section 4.3.2.
pub const TAG_LEN: usize = 4;

/// The block, and so the IV's width.
const BLOCK: usize = 8;

/// CNT's IV is a **whole** block, unlike CTR-ACPKM's half - RFC 5830
/// section 6 encrypts it to make the starting counter rather than
/// splitting it with one. The key block derives this many bytes per
/// direction.
pub const IV_LEN: usize = BLOCK;

/// `gost28147IMIT(IV, K, M)`, RFC 9189 section 8.4.
///
/// The IV is XORed into the *first* block and the message is padded
/// with zeros to a whole number of blocks; the tag is the first four
/// bytes of the chaining state, which is `N1` read little endian.
///
/// This is one-shot, for `KExp28147`. The record layer needs the state
/// to persist across records and uses `CntImit` below.
pub fn gost28147imit(iv: &[u8], key: &[u8], message: &[u8], sbox: &str)
                     -> Result<Vec<u8>, String> {
    if iv.len() != BLOCK {
        return Err(format!("gostIMIT28147's IV is {} bytes; got {}.",
                           BLOCK, iv.len()));
    }
    let mut mac = GostCrypto::new(key, sbox)?;
    mac.set_mac_iv(iv);
    mac.update(message);
    let mut tag = mac.digest();
    tag.truncate(TAG_LEN);
    Ok(tag)
}

/// The cipher half: CNT with meshing, one stream for the connection.
struct Stream {
    /// Which parameter set. Carried rather than taken from a constant
    /// because two suites share this code and differ only in it.
    sbox: String,
    key: Vec<u8>,
    cipher: GostCrypto,
    /// The counter block, `(N1, N2)` little endian, as it stands before
    /// the next gamma block is made from it.
    ///
    /// Fixed arrays, not `Vec`s: a stream advances one block per eight
    /// bytes, and a `clone` of a `Vec` there is an allocation per block
    /// - the thing the mode code is written to avoid.
    counter: [u8; BLOCK],
    /// The counter value that produced the *last* gamma block - one
    /// step behind `counter`. Meshing needs this one, not the next:
    /// see the note in `apply`.
    previous: [u8; BLOCK],
    /// Gamma produced and not yet used, and how much of it is spent.
    /// Cleared and refilled in place; `block_encrypt` appends to a `Vec`,
    /// and the capacity stays with it after the first block.
    gamma: Vec<u8>,
    used: usize,
    /// Octets since the last meshing. RFC 4357 counts *data*, so this
    /// counts the bytes handed to `apply`, not the gamma generated.
    since_mesh: usize,
}

impl Stream {
    fn new(key: &[u8], iv: &[u8], sbox: &str) -> Result<Stream, String> {
        if iv.len() != BLOCK {
            return Err(format!("CNT's IV is {} bytes; got {}.", BLOCK, iv.len()));
        }
        let mut cipher = GostCrypto::new(key, sbox)?;
        // RFC 5830 section 6: the IV is encrypted once to make the
        // starting counter, and the counter is stepped before the first
        // gamma block. `ctr_init` on the cipher does both.
        let mut initial = Vec::new();
        cipher.ctr_init(iv, &mut initial)?;
        let counter: [u8; BLOCK] = initial.as_slice().try_into().map_err(|_| format!(
            "GOST's starting counter is {} bytes, not {}.", initial.len(), BLOCK))?;
        Ok(Stream { sbox: sbox.to_string(), key: key.to_vec(), cipher, counter,
                    previous: counter, gamma: Vec::with_capacity(BLOCK), used: 0,
                    since_mesh: 0 })
    }

    fn apply(&mut self, data: &mut [u8]) -> Result<(), String> {
        for byte in data.iter_mut() {
            if self.since_mesh == meshing::SECTION {
                // Two things here are off by one step, and RFC 9189
                // Appendix A.2.1's second record is what settles both -
                // it is 2048 bytes precisely so that it crosses this
                // boundary.
                //
                // **The evolved IV is the counter that produced the
                // last gamma block, not the next one.** The RFC calls
                // it "the value of the initialization vector after
                // processing", and after processing a block that is the
                // block's own counter - the next one has not been used
                // for anything yet.
                //
                // **And the meshed IV is stepped before it is used.**
                // `IV0[i+1] = encryptECB(K[i+1], IVn[i])` takes the
                // place of the *stored* counter, which in this mode is
                // always one step behind the next gamma. Using it
                // directly skips a step; running it through the
                // start-of-stream path encrypts it twice.
                //
                // Both mistakes give a stream that is right for the
                // first 1024 bytes and wrong afterwards.
                let (key, iv) = meshing::mesh(&self.sbox, &self.key,
                                              &self.previous)?;
                self.key = key;
                self.cipher = GostCrypto::new(&self.key,
                                              &self.sbox)?;
                self.counter = iv.as_slice().try_into().map_err(|_| format!(
                    "The meshed IV is {} bytes, not {}.", iv.len(), BLOCK))?;
                self.cipher.ctr_next(&mut self.counter);
                self.gamma.clear();
                self.used = 0;
                self.since_mesh = 0;
            }
            if self.used == self.gamma.len() {
                self.gamma.clear();
                self.previous = self.counter;
                self.cipher.block_encrypt(&self.previous, &mut self.gamma);
                if self.gamma.len() != BLOCK {
                    return Err(format!("GOST produced {} bytes for an {} byte \
                                        block.", self.gamma.len(), BLOCK));
                }
                self.cipher.ctr_next(&mut self.counter);
                self.used = 0;
            }
            *byte ^= self.gamma[self.used];
            self.used += 1;
            self.since_mesh += 1;
        }
        Ok(())
    }
}

/// The MAC half: `gostIMIT28147` over every record so far, with meshing.
struct Chain {
    sbox: String,
    key: Vec<u8>,
    mac: GostCrypto,
    since_mesh: usize,
}

impl Chain {
    fn new(key: &[u8], sbox: &str) -> Result<Chain, String> {
        let mut mac = GostCrypto::new(key, sbox)?;
        // RFC 9189 section 4.3.2: IV = IV0, a string of zeros. It is
        // XORed into the first block only, which is what `set_mac_iv`
        // means - and after that the chaining state *is* the IV, so
        // there is nothing to re-apply per record.
        mac.set_mac_iv(&[0u8; BLOCK]);
        Ok(Chain { sbox: sbox.to_string(), key: key.to_vec(), mac,
                   since_mesh: 0 })
    }

    /// Absorb one record's MAC input and return the running tag.
    ///
    /// `digest` does not consume the state: `GostCrypto`'s MAC keeps
    /// chaining, which is exactly what this construction wants. The
    /// input is always a whole number of blocks here only by accident,
    /// so the partial-block handling matters - and a record whose
    /// fragment is not a multiple of eight leaves bytes buffered that
    /// the *next* record's input continues, which is what "the MAC
    /// covers the concatenation" means.
    fn absorb(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let mut rest = input;
        while !rest.is_empty() {
            if self.since_mesh == meshing::SECTION {
                // **Only the key changes here.** The chaining state is
                // left exactly as it is - `cryptopro_key_meshing` takes
                // the IV as an argument and the MAC passes nothing,
                // because CryptoPro does not treat a MAC's internal
                // state as an IV for this purpose. Re-deriving it, the
                // way the cipher half does, gives a MAC that is right
                // for the first 1024 octets and wrong afterwards.
                //
                // The buffered partial block survives the re-key for
                // the same reason: the MAC covers one continuous byte
                // stream, and a section boundary is not a message
                // boundary.
                self.key = meshing::next_key(&self.sbox, &self.key)?;
                let state = self.mac.mac_state().to_vec();
                let buffered = self.mac.mac_buffered().to_vec();
                let done = self.mac.mac_blocks_done();
                self.mac = GostCrypto::new(&self.key,
                                           &self.sbox)?;
                self.mac.set_mac_iv(&state);
                self.mac.restore_buffered(&buffered, done);
                self.since_mesh = 0;
            }
            let take = core::cmp::min(rest.len(), meshing::SECTION - self.since_mesh);
            self.mac.update(&rest[..take]);
            self.since_mesh += take;
            rest = &rest[take..];
        }
        let mut tag = self.mac.digest();
        tag.truncate(TAG_LEN);
        Ok(tag)
    }
}

/// One direction's CNT_IMIT state.
///
/// Both halves live here because both are cumulative: rebuilding either
/// per record repeats a keystream or forgets a chain, and both round
/// trip perfectly against an implementation making the same mistake.
pub struct CntImit {
    stream: Stream,
    chain: Chain,
    sbox: &'static str,
}

impl core::fmt::Debug for CntImit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CntImit {{ keys redacted }}")
    }
}

impl CntImit {
    /// RFC 9189's CNT_IMIT, on `id-tc26-gost-28147-param-Z`.
    pub fn new(key: &[u8], mac_key: &[u8], iv: &[u8]) -> Result<CntImit, String> {
        CntImit::with_sbox(key, mac_key, iv, SBOX)
    }

    /// The 2001 suite's, on `id-Gost28147-89-CryptoPro-A-ParamSet`.
    pub fn new_2001(key: &[u8], mac_key: &[u8], iv: &[u8])
                    -> Result<CntImit, String> {
        CntImit::with_sbox(key, mac_key, iv, SBOX_2001)
    }

    pub fn with_sbox(key: &[u8], mac_key: &[u8], iv: &[u8], sbox: &'static str)
                     -> Result<CntImit, String> {
        if key.len() != 32 || mac_key.len() != 32 {
            return Err(format!(
                "CNT_IMIT takes 32 byte keys; got {} for encryption and {} \
                 for the MAC.", key.len(), mac_key.len()));
        }
        Ok(CntImit { stream: Stream::new(key, iv, sbox)?,
                     chain: Chain::new(mac_key, sbox)?,
                     sbox })
    }

    /// The parameter set this state was built with, for the record
    /// layer's description.
    pub fn sbox(&self) -> &'static str {
        self.sbox
    }

    pub fn name(&self) -> String {
        if self.sbox == SBOX_2001 {
            "gost28147-cnt-imit (CryptoPro-A)".to_string()
        } else {
            "gost28147-cnt-imit".to_string()
        }
    }

    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The RFC 5246 section 6.2.3.1 MAC input for one record, which is
    /// what gets appended to the running chain.
    fn mac_input(sequence: SequenceNumber, content_type: ContentType,
                 version: Version, fragment: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(fragment.len() + 13);
        input.extend_from_slice(&sequence.to_bytes());
        input.push(content_type.to_byte());
        input.extend_from_slice(&version.to_bytes());
        input.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        input.extend_from_slice(fragment);
        input
    }
}

/// Protect one record: append it to the MAC chain, then encrypt
/// `fragment || tag` with the connection's running keystream.
pub fn encrypt(state: &mut CntImit, sequence: SequenceNumber,
               content_type: ContentType, version: Version, plaintext: &[u8])
               -> Result<Vec<u8>, RecordError> {
    let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);

    let input = CntImit::mac_input(sequence, content_type, version, plaintext);
    let tag = state.chain.absorb(&input).map_err(internal)?;

    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    out.extend_from_slice(&tag);
    state.stream.apply(&mut out).map_err(internal)?;
    Ok(out)
}

/// Unprotect one record.
///
/// A record that fails still consumed keystream and MAC state, and
/// deliberately so: both positions are a function of how many bytes
/// arrived, not of how many authenticated. Rewinding on failure would
/// let anyone injecting a record desynchronise the two ends.
pub fn decrypt(state: &mut CntImit, sequence: SequenceNumber,
               content_type: ContentType, version: Version, fragment: &[u8])
               -> Result<Vec<u8>, RecordError> {
    let bad = || RecordError::new(
        AlertDescription::BAD_RECORD_MAC,
        "The record did not authenticate. It was altered in transit, or the \
         keys do not match.".to_string());
    let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);

    if fragment.len() < TAG_LEN {
        return Err(bad());
    }
    let mut plain = fragment.to_vec();
    state.stream.apply(&mut plain).map_err(internal)?;

    let received = plain.split_off(plain.len() - TAG_LEN);
    let input = CntImit::mac_input(sequence, content_type, version, &plain);
    let expected = state.chain.absorb(&input).map_err(internal)?;

    // Constant time over the whole tag, as everywhere else here.
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(received.iter()) {
        difference |= a ^ b;
    }
    if difference != 0 || expected.len() != received.len() {
        return Err(bad());
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 9189 Appendix A.2.1, the first record.
    ///
    /// Short enough to be printed whole, so it pins the MAC input's
    /// framing, the four byte tag, the S-box and the order of MAC and
    /// encryption all at once.
    #[test]
    fn test_rfc_9189_cnt_imit_first_record() {
        let mut state = CntImit::new(&[0u8; 32], &[0xffu8; 32], &[0u8; 8]).unwrap();
        let out = encrypt(&mut state, SequenceNumber::at(0),
                          ContentType::ApplicationData, Version::TLS12,
                          &[0u8; 7]).unwrap();
        assert_eq!(hex(&out), "8671cdbf3c1aae0f624b04");
        assert_eq!(out.len(), 7 + TAG_LEN);
    }

    /// The second record of the same example: 2048 bytes, which crosses
    /// the 1024 octet meshing boundary in both halves, and follows the
    /// first - so it also pins that neither half restarts.
    ///
    /// The RFC elides the middle, so the printed head and tail are
    /// checked. That is enough for what the elision could hide: a
    /// keystream that restarted would be wrong from the first byte, and
    /// a meshing that did not happen would be wrong from byte 1024,
    /// which is inside the tail.
    #[test]
    fn test_rfc_9189_cnt_imit_across_the_meshing_boundary() {
        let mut state = CntImit::new(&[0u8; 32], &[0xffu8; 32], &[0u8; 8]).unwrap();
        encrypt(&mut state, SequenceNumber::at(0), ContentType::ApplicationData,
                Version::TLS12, &[0u8; 7]).unwrap();

        let out = encrypt(&mut state, SequenceNumber::at(1),
                          ContentType::ApplicationData, Version::TLS12,
                          &[0u8; 0x800]).unwrap();
        assert_eq!(out.len(), 0x800 + TAG_LEN);

        // The RFC prints TLSCiphertext including its five byte header,
        // so its offsets are five ahead of the fragment's: its first two
        // rows are 32 bytes, of which 27 are fragment.
        assert_eq!(hex(&out[..0x1b]),
                   "cfaa0cb42fa5a47a133d73b9f2c0b04f8ca25552f856bcbe6a58fa");
        assert_eq!(hex(&out[0x7eb..]),
                   "3ee2c76fa230a044be21dc8e1a96f9a8881fad83459696844 7"
                   .replace(' ', ""));
    }

    /// A round trip, over lengths that cross the meshing boundary in
    /// both halves and in neither.
    ///
    /// This proves much less than the vectors above - two ends of the
    /// same implementation agree however wrong they are - so it is here
    /// for the lengths and the ordering.
    #[test]
    fn test_a_round_trip_across_the_boundary() {
        let (key, mac_key, iv) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 8]);
        let mut out = CntImit::new(&key, &mac_key, &iv).unwrap();
        let mut back = CntImit::new(&key, &mac_key, &iv).unwrap();

        for (sequence, len) in [(0u64, 0usize), (1, 1), (2, 7), (3, 8), (4, 9),
                                (5, 1015), (6, 1016), (7, 1017), (8, 2048),
                                (9, 5), (10, 4096)] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let wire = encrypt(&mut out, SequenceNumber::at(sequence),
                               ContentType::ApplicationData, Version::TLS12,
                               &plaintext).unwrap();
            assert_eq!(wire.len(), len + TAG_LEN);
            let got = decrypt(&mut back, SequenceNumber::at(sequence),
                              ContentType::ApplicationData, Version::TLS12,
                              &wire).unwrap();
            assert_eq!(got, plaintext, "sequence {} length {}", sequence, len);
        }
    }

    /// **The keystream runs for the connection, not the record.**
    ///
    /// Rebuilding the state per record repeats the gamma, which is the
    /// worst thing a stream cipher can do and which round trips
    /// perfectly against an implementation doing the same. So: the same
    /// plaintext in two successive records must give different bytes,
    /// and rebuilding must give the same bytes twice.
    #[test]
    fn test_the_keystream_runs_for_the_connection() {
        let (key, mac_key, iv) = ([0x44u8; 32], [0x55u8; 32], [0x66u8; 8]);
        let mut state = CntImit::new(&key, &mac_key, &iv).unwrap();
        let first = encrypt(&mut state, SequenceNumber::at(0),
                            ContentType::ApplicationData, Version::TLS12,
                            b"repeated").unwrap();
        let second = encrypt(&mut state, SequenceNumber::at(1),
                             ContentType::ApplicationData, Version::TLS12,
                             b"repeated").unwrap();
        assert_ne!(first, second);

        // A fresh state gives the first record again, which is what a
        // per-record rebuild would do every time.
        let mut fresh = CntImit::new(&key, &mac_key, &iv).unwrap();
        assert_eq!(encrypt(&mut fresh, SequenceNumber::at(0),
                           ContentType::ApplicationData, Version::TLS12,
                           b"repeated").unwrap(),
                   first);
    }

    /// The MAC is cumulative: a record's tag depends on every record
    /// before it, so the same record at the same sequence number after
    /// a different history has a different tag.
    #[test]
    fn test_the_mac_covers_every_record_so_far() {
        let (key, mac_key, iv) = ([0x77u8; 32], [0x88u8; 32], [0x99u8; 8]);

        // Two histories that differ only in an earlier record must give
        // a different tag for the same later one.
        let run = |history: &[&[u8]]| {
            let mut state = CntImit::new(&key, &mac_key, &iv).unwrap();
            let mut out = Vec::new();
            for (n, record) in history.iter().enumerate() {
                out = encrypt(&mut state, SequenceNumber::at(n as u64),
                              ContentType::ApplicationData, Version::TLS12,
                              record).unwrap();
            }
            out
        };
        assert_ne!(run(&[b"one", b"same"]), run(&[b"two", b"same"]));
    }

    /// Every field the MAC covers is checked, and every bit of the
    /// record is covered.
    ///
    /// Each attempt needs a state that has seen the same history, since
    /// both halves are cumulative - which is itself the point: a record
    /// cannot be replayed into a different position.
    #[test]
    fn test_every_field_is_covered() {
        let (key, mac_key, iv) = ([0x0au8; 32], [0x0bu8; 32], [0x0cu8; 8]);
        let mut sender = CntImit::new(&key, &mac_key, &iv).unwrap();
        let wire = encrypt(&mut sender, SequenceNumber::at(0),
                           ContentType::ApplicationData, Version::TLS12,
                           b"hello").unwrap();

        let fresh = || CntImit::new(&key, &mac_key, &iv).unwrap();
        assert_eq!(decrypt(&mut fresh(), SequenceNumber::at(0),
                           ContentType::ApplicationData, Version::TLS12,
                           &wire).unwrap(), b"hello");

        assert!(decrypt(&mut fresh(), SequenceNumber::at(1),
                        ContentType::ApplicationData, Version::TLS12,
                        &wire).is_err(), "a replayed record was accepted");
        assert!(decrypt(&mut fresh(), SequenceNumber::at(0),
                        ContentType::Handshake, Version::TLS12,
                        &wire).is_err(), "a retyped record was accepted");
        assert!(decrypt(&mut fresh(), SequenceNumber::at(0),
                        ContentType::ApplicationData, Version::TLS11,
                        &wire).is_err(), "a re-versioned record was accepted");

        for bit in 0..wire.len() * 8 {
            let mut altered = wire.clone();
            altered[bit / 8] ^= 1 << (bit % 8);
            assert!(decrypt(&mut fresh(), SequenceNumber::at(0),
                            ContentType::ApplicationData, Version::TLS12,
                            &altered).is_err(),
                    "bit {} could be flipped undetected", bit);
        }
    }

    /// The one-shot `gostIMIT28147`, which `KExp28147` uses, must agree
    /// with the chain over the same bytes from a fresh state.
    #[test]
    fn test_the_one_shot_agrees_with_the_chain() {
        let key = [0x5au8; 32];
        for message in [&b""[..], b"a", b"12345678", b"123456789",
                        &[0u8; 1023][..], &[0u8; 1024][..]] {
            let mut chain = Chain::new(&key, SBOX).unwrap();
            // The chain meshes past 1024 octets and the one-shot does
            // not, so they agree only below the boundary - which is all
            // KExp28147 ever needs, its input being 32 bytes.
            if message.len() < meshing::SECTION {
                assert_eq!(gost28147imit(&[0u8; 8], &key, message, SBOX).unwrap(),
                           chain.absorb(message).unwrap(),
                           "message of {} bytes", message.len());
            }
        }
    }

    /// The IV is XORed into the first block only, so a non-zero IV
    /// changes the tag - and a zero one is not a no-op to assume.
    #[test]
    fn test_the_imit_iv_is_used() {
        let key = [0x3cu8; 32];
        let zero = gost28147imit(&[0u8; 8], &key, b"message", SBOX).unwrap();
        let other = gost28147imit(&[1u8; 8], &key, b"message", SBOX).unwrap();
        assert_ne!(zero, other);
        assert_eq!(zero.len(), TAG_LEN);

        // XORing the IV into the first block is not the same as
        // prepending it as a block of its own.
        let mut prepended = vec![1u8; 8];
        prepended.extend_from_slice(b"message");
        assert_ne!(other, gost28147imit(&[0u8; 8], &key, &prepended, SBOX).unwrap());
    }
}
