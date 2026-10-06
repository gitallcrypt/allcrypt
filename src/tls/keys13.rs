/*
The TLS 1.3 key schedule (RFC 8446 section 7.1).

Nothing here is shared with `keys.rs`. TLS 1.3 threw the old PRF away and
built a new schedule on HKDF, and the two have no step in common - not the
inputs, not the labels, not the shape. Trying to reuse `key_block` for it
would mean a function with two unrelated halves and a version flag, which
is how the SSLv3 differences got hidden last time.

The schedule is three HKDF-Extract steps with a chain of derivations
hanging off each:

             0
             |
             v
   PSK ->  HKDF-Extract  =  Early Secret
             |
             +--> Derive-Secret(., "c e traffic", ClientHello)
             |
       Derive-Secret(., "derived", "")
             |
             v
 (EC)DHE ->  HKDF-Extract  =  Handshake Secret
             |
             +--> Derive-Secret(., "c hs traffic", ClientHello..ServerHello)
             +--> Derive-Secret(., "s hs traffic", ClientHello..ServerHello)
             |
       Derive-Secret(., "derived", "")
             |
             v
      0 ->  HKDF-Extract  =  Master Secret
             |
             +--> Derive-Secret(., "c ap traffic", ..server Finished)
             +--> Derive-Secret(., "s ap traffic", ..server Finished)
             +--> Derive-Secret(., "exp master",   ..server Finished)
             +--> Derive-Secret(., "res master",   ..client Finished)

Six ways to get this wrong, every one of them producing a schedule that is
perfectly self-consistent and agrees with nobody:

  1. **The label prefix is `"tls13 "`, with the trailing space**, and the
     length byte in front of it counts the prefix too. A schedule built
     with `"tls13"` or with the length of the bare label is internally
     consistent and interoperates with nothing.

  2. **"Empty" context in Derive-Secret means `Hash("")`, not a
     zero-length string.** The two "derived" steps take an empty message
     list, and an empty message list still gets hashed. Passing a
     zero-length context instead is the single easiest mistake here.

  3. **The Extract salt is the *derived* secret, not the secret above
     it.** The Handshake Secret is `Extract(Derive-Secret(Early,
     "derived", ""), ECDHE)`, and feeding it the Early Secret directly
     skips a step that exists precisely so the stages cannot be confused.

  4. **With no PSK, the input keying material is `Hash.length` zero
     bytes, not an empty string.** HKDF-Extract treats an *empty salt* as
     zeros, so the salt side forgives this and the IKM side does not.

  5. **`key` and `iv` are derived from a traffic secret, not from the
     stage secret.** Each direction has its own, and a key derived from
     the Handshake Secret rather than from `s hs traffic` still decrypts
     nothing.

  6. **Every key change resets the record sequence number to zero.** It
     is not a counter over the connection; it is a counter per key. See
     `record13.rs`.

None of these are caught by talking to ourselves. They are caught by the
differential corpus in `tools/src/bin/diff_tls13_keys.rs`, checked against a
reference written from the RFC text in `scripts/diff_check.py`, and by the
transcript in `tests/test_tls13_keys.rs`.
*/

use crate::api::AnyHash;
use crate::hash_functions::HashFunction;
use crate::kdf;
use crate::tls::suites::MacAlgorithm;

/// The AEAD nonce is always 12 bytes in TLS 1.3, for every suite. TLS 1.2
/// had a 4 byte fixed part and an 8 byte explicit part; 1.3 has neither.
/// The static IV's length for every AEAD RFC 8446 itself names.
///
/// **Not a property of TLS 1.3**, which is how it came to be a constant
/// here: RFC 8446 section 7.3 expands `"iv"` to the AEAD's nonce length,
/// and AES-GCM, AES-CCM and ChaCha20-Poly1305 all take twelve bytes.
/// RFC 9367's suites take `n` - sixteen or **eight** - so the length is
/// now an argument to `TrafficKeys::derive` and this is its default.
/// `BulkCipher::iv_len_13` is what a caller should ask.
pub const NONCE_LEN: usize = 12;

/// The label prefix, RFC 8446 section 7.1. The trailing space is part of
/// it: `HkdfLabel.label` is `"tls13 " + Label`.
const PREFIX: &[u8] = b"tls13 ";

/// HKDF-Expand-Label (RFC 8446 section 7.1).
///
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
///
/// Both the label and the context are length-prefixed with a single byte,
/// and the 16 bit length at the front is the *output* length rather than
/// the structure's.
pub fn expand_label(hash_name: &str, secret: &[u8], label: &[u8],
                    context: &[u8], length: usize) -> Result<Vec<u8>, String> {
    if label.is_empty() {
        return Err("HKDF-Expand-Label needs a label.".to_string());
    }
    // The wire field is `opaque label<7..255>`, and the 7 is the prefix's
    // own length - so the bound is on the prefixed label, not on ours.
    if PREFIX.len() + label.len() > 255 {
        return Err(format!("HKDF-Expand-Label label is {} bytes with the \
                            prefix; the limit is 255.",
                           PREFIX.len() + label.len()));
    }
    if context.len() > 255 {
        return Err(format!("HKDF-Expand-Label context is {} bytes; the \
                            limit is 255.", context.len()));
    }
    if length > u16::MAX as usize {
        return Err(format!("HKDF-Expand-Label output is {} bytes; the \
                            length field is 16 bits.", length));
    }

    let mut info = Vec::with_capacity(2 + 1 + PREFIX.len() + label.len()
                                      + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((PREFIX.len() + label.len()) as u8);
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    kdf::hkdf_expand(AnyHash::new(hash_name)?, secret, &info, length)
}

/// Derive-Secret (RFC 8446 section 7.1).
///
/// ```text
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages),
///                       Hash.length)
/// ```
///
/// `transcript_hash` is the hash of the messages, already taken - which
/// matters for the "derived" steps, where the message list is empty and
/// the context is therefore `Hash("")` rather than nothing. `empty_hash`
/// exists so that is hard to get wrong.
pub fn derive_secret(hash_name: &str, secret: &[u8], label: &[u8],
                     transcript_hash: &[u8]) -> Result<Vec<u8>, String> {
    let length = AnyHash::new(hash_name)?.digest_len();
    expand_label(hash_name, secret, label, transcript_hash, length)
}

/// `Hash("")`, which is what Derive-Secret uses for an empty message list.
///
/// Spelled out as a function because the alternative - passing `&[]` and
/// hoping - is mistake 2 in the list above, and it produces a schedule
/// that works perfectly against itself.
pub fn empty_hash(hash_name: &str) -> Result<Vec<u8>, String> {
    Ok(AnyHash::new(hash_name)?.digest())
}

/// The keys one direction uses for one epoch.
#[derive(Clone, PartialEq, Eq)]
pub struct TrafficKeys {
    /// The traffic secret these came from, kept so a key update can derive
    /// the next epoch from it.
    pub secret: Vec<u8>,
    pub key: Vec<u8>,
    /// The *static* IV. The per-record nonce is this XOR the sequence
    /// number, which is `record13.rs`'s job, not this one's.
    pub iv: Vec<u8>,
    /// The key for the Finished HMAC of whichever side owns this secret.
    pub finished_key: Vec<u8>,
}

impl core::fmt::Debug for TrafficKeys {
    /// Deliberately says nothing. These are the live keys, and a `{:?}` in
    /// a log is how key material escapes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TrafficKeys {{ {} byte key, redacted }}", self.key.len())
    }
}

impl TrafficKeys {
    /// Derive the key, IV and Finished key from a traffic secret
    /// (RFC 8446 sections 7.1 and 7.3).
    /// `iv_len` is the AEAD's nonce length, which is twelve for
    /// everything RFC 8446 names and `n` for RFC 9367's suites.
    ///
    /// **It is an input to the expansion, not a truncation of it.**
    /// HKDF-Expand-Label puts the requested length into the label
    /// structure it hashes, so asking for sixteen bytes and asking for
    /// twelve give two IVs that share no prefix. A wrong length here is
    /// therefore not a length error at the first record - it is a
    /// different static IV and a peer that disagrees about every nonce.
    pub fn derive(hash_name: &str, secret: &[u8], key_len: usize,
                  iv_len: usize) -> Result<TrafficKeys, String> {
        Ok(TrafficKeys {
            key: expand_label(hash_name, secret, b"key", &[], key_len)?,
            iv: expand_label(hash_name, secret, b"iv", &[], iv_len)?,
            finished_key: derive_secret_no_context(hash_name, secret, b"finished")?,
            secret: secret.to_vec(),
        })
    }

    /// The next epoch's keys, after a KeyUpdate (RFC 8446 section 7.2):
    ///
    /// ```text
    /// application_traffic_secret_N+1 =
    ///     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd",
    ///                       "", Hash.length)
    /// ```
    ///
    /// The context is empty here in the literal sense - `""` rather than
    /// `Hash("")` - because this is Expand-Label directly and not
    /// Derive-Secret. The two look alike and are not.
    pub fn update(&self, hash_name: &str) -> Result<TrafficKeys, String> {
        let next = derive_secret_no_context(hash_name, &self.secret, b"traffic upd")?;
        // The IV keeps its length across a key update, which is the
        // one place it could silently revert to twelve.
        TrafficKeys::derive(hash_name, &next, self.key.len(), self.iv.len())
    }
}

/// `HKDF-Expand-Label(secret, label, "", Hash.length)` - an empty context
/// in the literal sense, which is what "finished" and "traffic upd" take.
fn derive_secret_no_context(hash_name: &str, secret: &[u8], label: &[u8])
                            -> Result<Vec<u8>, String> {
    let length = AnyHash::new(hash_name)?.digest_len();
    expand_label(hash_name, secret, label, &[], length)
}

/// Which stage of the schedule a `Schedule` is currently holding.
///
/// Tracked rather than assumed, because the whole point of the three
/// Extract steps is that a secret from one stage must not be used as if it
/// came from another. An out-of-order call is an error here rather than a
/// silently wrong secret.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    Early,
    Handshake,
    Master,
}

/// The running key schedule.
///
/// Built stage by stage: `early` then `handshake` then `master`, each
/// consuming the one before. The traffic secrets come off whichever stage
/// is current.
#[derive(Clone)]
pub struct Schedule {
    hash_name: &'static str,
    hash_len: usize,
    stage: Stage,
    secret: Vec<u8>,
}

impl core::fmt::Debug for Schedule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Schedule {{ {} at {:?}, secret redacted }}",
               self.hash_name, self.stage)
    }
}

impl Schedule {
    /// The Early Secret: `HKDF-Extract(0, PSK)`.
    ///
    /// With no PSK the input keying material is `Hash.length` zero bytes.
    /// That is not the same as an empty input - HKDF-Extract forgives an
    /// empty *salt* by substituting zeros, and does no such thing for the
    /// IKM.
    pub fn early(prf: MacAlgorithm, psk: Option<&[u8]>) -> Result<Schedule, String> {
        let hash_name = crate::tls::handshake13::tls13_hash_name(prf)?;
        let hash_len = AnyHash::new(hash_name)?.digest_len();
        let zeros = vec![0u8; hash_len];
        let psk = psk.unwrap_or(&zeros);
        let secret = kdf::hkdf_extract(AnyHash::new(hash_name)?, &zeros, psk);
        Ok(Schedule { hash_name, hash_len, stage: Stage::Early, secret })
    }

    pub fn hash_name(&self) -> &'static str {
        self.hash_name
    }

    pub fn hash_len(&self) -> usize {
        self.hash_len
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// The current stage's secret. Exposed for the differential corpus and
    /// for a key log; nothing in the handshake should need it.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// `Derive-Secret(current, "derived", "")`, the step between stages.
    fn derived(&self) -> Result<Vec<u8>, String> {
        derive_secret(self.hash_name, &self.secret, b"derived",
                      &empty_hash(self.hash_name)?)
    }

    /// The Handshake Secret: `HKDF-Extract(Derive-Secret(Early, "derived",
    /// ""), (EC)DHE)`.
    pub fn handshake(&self, shared_secret: &[u8]) -> Result<Schedule, String> {
        if self.stage != Stage::Early {
            return Err(format!("The handshake secret comes from the early \
                                secret; this schedule is at {:?}.", self.stage));
        }
        if shared_secret.is_empty() {
            // An all-zero or absent shared secret would produce a schedule
            // that both sides can compute without the key exchange, which
            // is the key exchange not having happened.
            return Err("The (EC)DHE shared secret is empty.".to_string());
        }
        let salt = self.derived()?;
        let secret = kdf::hkdf_extract(AnyHash::new(self.hash_name)?,
                                       &salt, shared_secret);
        Ok(Schedule { stage: Stage::Handshake, secret, ..self.clone() })
    }

    /// The Master Secret: `HKDF-Extract(Derive-Secret(Handshake,
    /// "derived", ""), 0)`, where the 0 is `Hash.length` zero bytes.
    pub fn master(&self) -> Result<Schedule, String> {
        if self.stage != Stage::Handshake {
            return Err(format!("The master secret comes from the handshake \
                                secret; this schedule is at {:?}.", self.stage));
        }
        let salt = self.derived()?;
        let zeros = vec![0u8; self.hash_len];
        let secret = kdf::hkdf_extract(AnyHash::new(self.hash_name)?, &salt, &zeros);
        Ok(Schedule { stage: Stage::Master, secret, ..self.clone() })
    }

    /// One traffic secret off the current stage.
    pub fn traffic_secret(&self, label: &[u8], transcript_hash: &[u8])
                          -> Result<Vec<u8>, String> {
        derive_secret(self.hash_name, &self.secret, label, transcript_hash)
    }

    /// The client's and server's handshake traffic secrets, from the
    /// transcript through ServerHello.
    pub fn handshake_traffic(&self, transcript_hash: &[u8], key_len: usize,
                             iv_len: usize)
                             -> Result<(TrafficKeys, TrafficKeys), String> {
        if self.stage != Stage::Handshake {
            return Err(format!("Handshake traffic keys come from the \
                                handshake secret; this schedule is at {:?}.",
                               self.stage));
        }
        self.pair(b"c hs traffic", b"s hs traffic", transcript_hash, key_len,
                  iv_len)
    }

    /// The client's and server's application traffic secrets, from the
    /// transcript through the *server's* Finished.
    ///
    /// Both of them, including the client's, even though the client's
    /// Finished has not been sent yet. That is not an oversight in the
    /// RFC: fixing the transcript at the server's Finished is what lets
    /// the server send application data immediately.
    pub fn application_traffic(&self, transcript_hash: &[u8], key_len: usize,
                               iv_len: usize)
                               -> Result<(TrafficKeys, TrafficKeys), String> {
        if self.stage != Stage::Master {
            return Err(format!("Application traffic keys come from the \
                                master secret; this schedule is at {:?}.",
                               self.stage));
        }
        self.pair(b"c ap traffic", b"s ap traffic", transcript_hash, key_len,
                  iv_len)
    }

    fn pair(&self, client_label: &[u8], server_label: &[u8],
            transcript_hash: &[u8], key_len: usize, iv_len: usize)
            -> Result<(TrafficKeys, TrafficKeys), String> {
        let client = self.traffic_secret(client_label, transcript_hash)?;
        let server = self.traffic_secret(server_label, transcript_hash)?;
        Ok((TrafficKeys::derive(self.hash_name, &client, key_len, iv_len)?,
            TrafficKeys::derive(self.hash_name, &server, key_len, iv_len)?))
    }

    /// The exporter master secret, for anything that needs keying material
    /// derived from this connection (RFC 8446 section 7.5).
    pub fn exporter_master(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, String> {
        if self.stage != Stage::Master {
            return Err("The exporter master secret comes from the master \
                        secret.".to_string());
        }
        self.traffic_secret(b"exp master", transcript_hash)
    }

    /// Keying material exported from this connection, RFC 8446 section
    /// 7.5.
    ///
    /// **Two derivations, not one**, and collapsing them is the mistake
    /// to avoid:
    ///
    /// ```text
    /// Derive-Secret(exporter_master, label, "")
    /// HKDF-Expand-Label(that, "exporter", Hash(context), length)
    /// ```
    ///
    /// The first takes `Hash("")` for its context - the label alone
    /// identifies the consumer - and only the second carries the
    /// caller's context, hashed. Feeding the context into the first
    /// step, or handing the second the raw context instead of its hash,
    /// gives an exporter that agrees with itself and with nothing else;
    /// there is no error anywhere, because every value involved is the
    /// right length.
    ///
    /// `exporter_master` is the secret from [`Schedule::exporter_master`],
    /// taken over the transcript through the server's Finished.
    ///
    /// # Errors
    /// An unusable hash name, or a length the expansion cannot produce.
    pub fn export_keying_material(hash_name: &str, exporter_master: &[u8],
                                  label: &[u8], context: &[u8], length: usize)
                                  -> Result<Vec<u8>, String> {
        let empty = empty_hash(hash_name)?;
        let secret = derive_secret(hash_name, exporter_master, label, &empty)?;
        let mut hash = AnyHash::new(hash_name)?;
        hash.update(context);
        expand_label(hash_name, &secret, b"exporter", &hash.digest(), length)
    }

    /// The resumption master secret, over the transcript through the
    /// *client's* Finished - one message later than everything else above.
    pub fn resumption_master(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, String> {
        if self.stage != Stage::Master {
            return Err("The resumption master secret comes from the master \
                        secret.".to_string());
        }
        self.traffic_secret(b"res master", transcript_hash)
    }

    /// The binder key: `Derive-Secret(Early, "res binder", "")`.
    ///
    /// **The context is the empty *string*, so the transcript hash is
    /// `Hash("")`** - not the hash of the hello the binder will cover.
    /// The hello goes into the HMAC, not into this derivation, and an
    /// implementation that passed the hello here produces a binder that
    /// is self-consistent and that no server accepts.
    ///
    /// There are two labels. `"res binder"` is for a PSK that came from
    /// a NewSessionTicket, `"ext binder"` for one established out of
    /// band. They are separate so that a PSK provisioned externally
    /// cannot be made to authenticate a resumption, or the reverse -
    /// and since they only differ in a string, using one for the other
    /// is a silent failure at the far end.
    pub fn binder_key(&self, external: bool) -> Result<Vec<u8>, String> {
        if self.stage != Stage::Early {
            return Err(format!("The binder key comes from the early secret; \
                                this schedule is at {:?}.", self.stage));
        }
        let label: &[u8] = if external { b"ext binder" } else { b"res binder" };
        let empty = empty_hash(self.hash_name)?;
        derive_secret(self.hash_name, &self.secret, label, &empty)
    }

    /// The client's early traffic secret:
    /// `Derive-Secret(Early, "c e traffic", ClientHello)`.
    ///
    /// The transcript is the ClientHello **and nothing else** - the
    /// server has not spoken yet, which is the whole point of 0-RTT.
    /// The full ClientHello including its binders, not the truncated
    /// one the binder was computed over.
    pub fn client_early_traffic(&self, transcript_hash: &[u8], key_len: usize,
                                iv_len: usize)
                                -> Result<TrafficKeys, String> {
        if self.stage != Stage::Early {
            return Err(format!("Early traffic keys come from the early \
                                secret; this schedule is at {:?}.", self.stage));
        }
        let secret = self.traffic_secret(b"c e traffic", transcript_hash)?;
        TrafficKeys::derive(self.hash_name, &secret, key_len, iv_len)
    }

    /// The early exporter master secret, for anything a caller wants
    /// keyed to the 0-RTT flight.
    pub fn early_exporter_master(&self, transcript_hash: &[u8])
                                 -> Result<Vec<u8>, String> {
        if self.stage != Stage::Early {
            return Err("The early exporter master secret comes from the \
                        early secret.".to_string());
        }
        self.traffic_secret(b"e exp master", transcript_hash)
    }
}

/// The PSK a NewSessionTicket names:
///
/// ```text
/// HKDF-Expand-Label(resumption_master_secret, "resumption",
///                   ticket_nonce, Hash.length)
/// ```
///
/// An `Expand-Label` with the nonce as the **context**, not a
/// `Derive-Secret` - so the nonce goes in as itself and is not hashed
/// first. `Derive-Secret` is `Expand-Label` with a *hash* as the
/// context, and the two differ only in that, so writing one for the
/// other compiles, runs, and produces a PSK the server has never heard
/// of.
///
/// The nonce is what makes several tickets from one connection give
/// several different PSKs. A server sending two tickets with the same
/// nonce would be issuing the same key twice, and nothing here can
/// detect that.
pub fn resumption_psk(hash_name: &str, resumption_master: &[u8],
                      nonce: &[u8]) -> Result<Vec<u8>, String> {
    // The PSK is a whole hash output wide, so its length follows the
    // suite's hash rather than being a parameter.
    let length = empty_hash(hash_name)?.len();
    expand_label(hash_name, resumption_master, b"resumption", nonce, length)
}

/// The Finished message's verify_data (RFC 8446 section 4.4.4):
///
/// ```text
/// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context,
///                                                  Certificate*,
///                                                  CertificateVerify*))
/// ```
///
/// Nothing like TLS 1.2's, which ran the master secret through the PRF
/// over a label and the transcript. Here it is a plain HMAC under a key
/// that is itself derived from the traffic secret, and the output is the
/// full hash length rather than 12 bytes.
pub fn finished(hash_name: &str, finished_key: &[u8], transcript_hash: &[u8])
                -> Result<Vec<u8>, String> {
    Ok(crate::mac::hmac::Hmac::mac(AnyHash::new(hash_name)?,
                                   finished_key, transcript_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The one constant in the schedule that does not depend on anything:
    /// with no PSK the Early Secret is `HKDF-Extract(0^32, 0^32)`, the same
    /// value in every TLS 1.3 connection that does not resume. It is
    /// printed in RFC 8448 and quoted in most implementations' tests, so a
    /// wrong Extract shows up here before anything else is built on it.
    #[test]
    fn test_the_early_secret_with_no_psk_is_the_known_constant() {
        let schedule = Schedule::early(MacAlgorithm::Sha256, None).unwrap();
        assert_eq!(hex(schedule.secret()),
                   "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    }

    /// The label encoding, byte for byte, because everything else in the
    /// schedule is built on it and a wrong prefix is invisible from inside.
    #[test]
    fn test_the_hkdf_label_is_encoded_as_the_rfc_spells_it() {
        // Reproduce the info string the way the RFC writes the structure,
        // independently of `expand_label`'s own assembly.
        let secret = [0x0bu8; 32];
        let context = [0xaa, 0xbb, 0xcc];
        let ours = expand_label("sha256", &secret, b"key", &context, 16).unwrap();

        let mut info = Vec::new();
        info.extend_from_slice(&16u16.to_be_bytes());
        info.push(b"tls13 key".len() as u8);      // 9, the *prefixed* label
        info.extend_from_slice(b"tls13 key");
        info.push(context.len() as u8);
        info.extend_from_slice(&context);
        let theirs = kdf::hkdf_expand(AnyHash::new("sha256").unwrap(),
                                      &secret, &info, 16).unwrap();
        assert_eq!(ours, theirs);

        // And the mistakes it is easy to make instead, each of which is
        // self-consistent: no space, no prefix, bare label length.
        for wrong in [&b"tls13key"[..], &b"key"[..]] {
            let mut info = Vec::new();
            info.extend_from_slice(&16u16.to_be_bytes());
            info.push(wrong.len() as u8);
            info.extend_from_slice(wrong);
            info.push(context.len() as u8);
            info.extend_from_slice(&context);
            let other = kdf::hkdf_expand(AnyHash::new("sha256").unwrap(),
                                         &secret, &info, 16).unwrap();
            assert_ne!(ours, other, "label {:?} must not produce our output", wrong);
        }
    }

    /// Derive-Secret with an empty message list hashes the empty string.
    /// Passing a zero-length context instead is the mistake that produces
    /// a working-against-itself schedule.
    #[test]
    fn test_an_empty_message_list_still_gets_hashed() {
        let secret = [0x2cu8; 32];
        let with_empty_hash = derive_secret("sha256", &secret, b"derived",
                                            &empty_hash("sha256").unwrap()).unwrap();
        let with_no_context = expand_label("sha256", &secret, b"derived", &[], 32).unwrap();
        assert_ne!(with_empty_hash, with_no_context);

        // Hash("") for SHA-256, so the helper is pinned to a known value
        // rather than to whatever our own hash happens to produce.
        assert_eq!(hex(&empty_hash("sha256").unwrap()),
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&empty_hash("sha384").unwrap()),
                   "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                    274edebfe76f65fbd51ad2f14898b95b");
    }

    /// The stages must be taken in order. A secret from the wrong stage is
    /// still 32 bytes of pseudorandom data, so nothing downstream would
    /// notice.
    #[test]
    fn test_the_stages_cannot_be_taken_out_of_order() {
        let early = Schedule::early(MacAlgorithm::Sha256, None).unwrap();
        assert!(early.master().is_err(), "master must not follow early directly");

        let handshake = early.handshake(&[0x42; 32]).unwrap();
        assert!(handshake.handshake(&[0x42; 32]).is_err(),
                "the handshake secret is derived once");

        let master = handshake.master().unwrap();
        assert!(master.master().is_err());

        let empty_hash = empty_hash("sha256").unwrap();
        assert!(handshake.application_traffic(&empty_hash, 16, 12).is_err(),
                "application keys must not come off the handshake secret");
        assert!(master.handshake_traffic(&empty_hash, 16, 12).is_err(),
                "handshake keys must not come off the master secret");
    }

    /// An empty shared secret means the key exchange did not happen, and
    /// the schedule that results is one an observer could compute.
    #[test]
    fn test_an_empty_shared_secret_is_refused() {
        let early = Schedule::early(MacAlgorithm::Sha256, None).unwrap();
        assert!(early.handshake(&[]).is_err());
    }

    /// TLS 1.3 has no suites on anything but SHA-256 and SHA-384, and a
    /// schedule on SHA-1 would be a schedule for a suite that does not
    /// exist.
    #[test]
    fn test_only_the_two_real_prf_hashes_are_accepted() {
        assert!(Schedule::early(MacAlgorithm::Sha256, None).is_ok());
        assert!(Schedule::early(MacAlgorithm::Sha384, None).is_ok());
        for wrong in [MacAlgorithm::Sha1, MacAlgorithm::Md5, MacAlgorithm::Aead] {
            assert!(Schedule::early(wrong, None).is_err(), "{:?}", wrong);
        }
    }

    /// The two directions must differ everywhere. A `pair` that returned
    /// the same keys twice would let each side decrypt its own records and
    /// nobody else's.
    #[test]
    fn test_the_two_directions_get_different_keys() {
        let schedule = Schedule::early(MacAlgorithm::Sha256, None).unwrap()
            .handshake(&[0x99; 32]).unwrap();
        let transcript = [0x11u8; 32];
        let (client, server) = schedule.handshake_traffic(&transcript, 16, 12).unwrap();

        assert_ne!(client.secret, server.secret);
        assert_ne!(client.key, server.key);
        assert_ne!(client.iv, server.iv);
        assert_ne!(client.finished_key, server.finished_key);
        assert_eq!(client.key.len(), 16);
        assert_eq!(client.iv.len(), NONCE_LEN);
        assert_eq!(client.finished_key.len(), 32);
    }

    /// A key update must change the key, and must be derivable only
    /// forwards - the point of it is that a compromised epoch does not
    /// hand over the previous one.
    #[test]
    fn test_a_key_update_moves_forward() {
        let schedule = Schedule::early(MacAlgorithm::Sha384, None).unwrap()
            .handshake(&[0x07; 48]).unwrap().master().unwrap();
        let (client, _) = schedule.application_traffic(&[0x33; 48], 32, 12).unwrap();

        let next = client.update("sha384").unwrap();
        assert_ne!(client.secret, next.secret);
        assert_ne!(client.key, next.key);
        assert_ne!(client.iv, next.iv);
        assert_eq!(next.key.len(), 32);

        // Twice is not the same as once, which catches an update that
        // derives from the original secret every time.
        let third = next.update("sha384").unwrap();
        assert_ne!(next.secret, third.secret);
        assert_ne!(client.secret, third.secret);
    }

    /// SHA-384 is not SHA-256 with a different length: it is a different
    /// schedule from the first Extract onwards.
    #[test]
    fn test_sha384_is_a_different_schedule_and_not_a_truncation() {
        let short = Schedule::early(MacAlgorithm::Sha256, None).unwrap();
        let long = Schedule::early(MacAlgorithm::Sha384, None).unwrap();
        assert_eq!(short.secret().len(), 32);
        assert_eq!(long.secret().len(), 48);
        assert_ne!(short.secret(), &long.secret()[..32]);
    }

    /// Finished is an HMAC, not the TLS 1.2 PRF, and it is the full hash
    /// length rather than 12 bytes.
    #[test]
    fn test_finished_is_an_hmac_of_the_full_length() {
        let key = unhex("5b4c5b4c5b4c5b4c5b4c5b4c5b4c5b4c\
                         5b4c5b4c5b4c5b4c5b4c5b4c5b4c5b4c");
        let transcript = [0x5a; 32];
        let ours = finished("sha256", &key, &transcript).unwrap();
        assert_eq!(ours.len(), 32);
        assert_eq!(ours, crate::mac::hmac::Hmac::mac(
            AnyHash::new("sha256").unwrap(), &key, &transcript));
    }

    /// The label bounds are on the wire field, and the prefix counts.
    #[test]
    fn test_the_label_and_context_limits_are_checked() {
        let secret = [0u8; 32];
        assert!(expand_label("sha256", &secret, b"", &[], 16).is_err());
        assert!(expand_label("sha256", &secret, &[b'x'; 249], &[], 16).is_ok());
        assert!(expand_label("sha256", &secret, &[b'x'; 250], &[], 16).is_err(),
                "250 + 6 bytes of prefix is over the 255 limit");
        assert!(expand_label("sha256", &secret, b"key", &[0u8; 255], 16).is_ok());
        assert!(expand_label("sha256", &secret, b"key", &[0u8; 256], 16).is_err());
    }
}
