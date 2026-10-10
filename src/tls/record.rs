/*
The TLS record layer.

Records are the frame every other TLS message travels inside:

    struct {
        ContentType type;          // 1 byte
        ProtocolVersion version;   // 2 bytes
        uint16 length;             // 2 bytes
        opaque fragment[length];
    } TLSPlaintext;

Five bytes of header and then the payload. The whole of this file is about
two things: turning a stream of bytes into those records without trusting
any of the lengths, and protecting or unprotecting the payload without
leaking through how long it takes.

**Sans-I/O.** `push_incoming` takes whatever bytes arrived, however they
were split; `read` produces whole records when there are any. No socket, no
reader, no timeouts. Every test in here is a byte sequence.

**Encrypt-then-MAC (RFC 7366) is supported and preferred**, and it is not a
nicety. With it the MAC covers the ciphertext and is checked *before*
anything is decrypted, so a record that fails authentication is never
decrypted at all and its padding is never looked at. That removes the
padding oracle completely rather than making it hard to measure. Every
modern OpenSSL negotiates it for CBC suites by default - which this
library found out the way you would hope, by failing to decrypt a captured
session until it was implemented.

**Lucky 13 is the reason the MAC-then-encrypt path looks the way it does.**
Without encrypt-then-MAC the record is MAC-then-encrypt, so the MAC can only
be checked after decrypting, and the padding can only be checked after that.
An implementation that stops early when the padding is wrong takes
measurably less time than one that goes on to check the MAC, and that
difference recovers the plaintext. So that decrypt path:

  - runs the same number of hash compression calls whatever the padding
    said: the MAC over the content the padding left behind, then dummy
    compressions up to the count the longest possible content would have
    taken (the countermeasure in the Lucky 13 paper, section 6),
  - never returns early between the padding check and the MAC check,
  - reports one error for every failure, and

it is still not constant time, because the primitives underneath are not.
What it removes is the large, easily measured difference. That is an
improvement, not a proof, and it is written down in docs/pitfalls.md as
such.
*/

use crate::api::{AnyBlockCipher, AnyHash, AnyStreamCipher, CipherStream, Mode};
use crate::block_ciphers::BlockCipher;
use crate::hash_functions::HashFunction;
use crate::mac::Hmac;
use crate::tls::keys::DirectionKeys;
use crate::tls::suites::{BulkCipher, CipherSuite, KeyExchange};
use crate::tls::{Alert, AlertDescription, ContentType, Version};
use crate::Mac;

/// The largest plaintext fragment a record may carry: 2^14.
pub const MAX_PLAINTEXT: usize = 16384;

/// The largest ciphertext fragment TLS 1.2 permits: 2^14 + 2048.
///
/// The slack is for the MAC, the padding and the explicit IV. A record
/// larger than this is `record_overflow` - and the check matters, because
/// the length field is two bytes and an attacker will happily claim 65535
/// to make us allocate.
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 2048;

/// The five byte header.
pub const HEADER_LEN: usize = 5;

/// A record, after framing and after any decryption.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    pub content_type: ContentType,
    pub version: Version,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn new(content_type: ContentType, version: Version, payload: Vec<u8>) -> Record {
        Record { content_type, version, payload }
    }

    pub fn alert(version: Version, alert: Alert) -> Record {
        Record::new(ContentType::Alert, version, alert.to_bytes().to_vec())
    }
}

/// What went wrong, as the alert the peer should be sent.
///
/// Returning the alert rather than a string means the caller cannot forget
/// which one to send, and cannot invent a more informative one - which for
/// a decryption failure is the entire point.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecordError {
    pub alert: AlertDescription,
    pub detail: String,
}

impl RecordError {
    pub(crate) fn new(alert: AlertDescription, detail: impl Into<String>) -> RecordError {
        RecordError { alert, detail: detail.into() }
    }

    pub fn describe(&self) -> String {
        format!("{}: {}", self.alert.name(), self.detail)
    }
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.describe())
    }
}

/// Everything else in this library returns `Result<_, String>`, so a
/// `RecordError` has to be able to flow into one. The alert is preserved in
/// the text; a caller that needs the code itself keeps the `RecordError`.
impl From<RecordError> for String {
    fn from(error: RecordError) -> String {
        error.describe()
    }
}

// ----------------------------------------------------------- sequence number ---

/// The per-direction record counter that goes into every MAC.
///
/// 64 bits, and it **must not wrap**. If it did, two records would be
/// authenticated with the same sequence number, and a MAC that has been
/// used twice over different data is not a MAC any more. At one record per
/// nanosecond this takes 584 years to reach, so the failure is
/// theoretical - but the code that handles it costs nothing and the code
/// that ignores it is a silent break.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SequenceNumber(u64);

impl SequenceNumber {
    pub fn zero() -> SequenceNumber {
        SequenceNumber(0)
    }

    /// A sequence number at a given value, so a caller outside the record
    /// layer can reproduce one record's MAC. Used by `api::ssl3_record_mac`,
    /// which exists so the construction can be checked from Python against
    /// a reference written from the RFC.
    pub fn at(value: u64) -> SequenceNumber {
        SequenceNumber(value)
    }

    pub fn value(self) -> u64 {
        self.0
    }

    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// The number the *next* record will use, without consuming it.
    ///
    /// For the one caller that has to know whether a record authenticated
    /// before it decides the counter moved: see `Aead13::decrypt`.
    pub(crate) fn peek(&self) -> &SequenceNumber {
        self
    }

    pub(crate) fn next(&mut self) -> Result<SequenceNumber, RecordError> {
        let current = *self;
        self.0 = self.0.checked_add(1).ok_or_else(|| RecordError::new(
            AlertDescription::INTERNAL_ERROR,
            "The record sequence number would wrap, which would reuse a MAC \
             key with a repeated counter. The connection must be torn down."))?;
        Ok(current)
    }
}

// --------------------------------------------------------------- protection ---

/// How a record's payload is protected.
///
/// `Null` is the state before the first ChangeCipherSpec, when records go
/// out in the clear. It is a variant rather than an `Option` so that the
/// transition is a state change rather than a special case at every use.
pub enum Protection {
    Null,
    CbcHmac(CbcHmac),
    Aead(AeadKeys),
    StreamHmac(StreamHmac),
    /// RFC 9189's CTR_OMAC suites. Authenticate-then-encrypt over a
    /// counter mode, like `StreamHmac` - but every record has its own
    /// keys, derived from the sequence number by TLSTREE, so the state
    /// is a pair of key trees rather than a keystream. See
    /// `record_gost.rs`.
    CtrOmac(crate::tls::record_gost::CtrOmac),
    /// RFC 9189's CNT_IMIT suite. Also authenticate-then-encrypt over
    /// a counter mode, and cumulative in both halves: one keystream and
    /// one running MAC for the whole connection. See
    /// `record_cnt_imit.rs`.
    CntImit(crate::tls::record_cnt_imit::CntImit),
    /// TLS 1.3, which is a different construction rather than another
    /// AEAD suite: the header's content type is a decoy, the real one is
    /// inside the ciphertext, and the sequence number lives with the keys
    /// because a key change restarts it. See `record13.rs`.
    Aead13(crate::tls::record13::Aead13),
}

impl Protection {
    pub fn is_null(&self) -> bool {
        matches!(self, Protection::Null)
    }

    pub fn name(&self) -> String {
        match self {
            Protection::Null => "null".to_string(),
            Protection::CbcHmac(state) => state.name(),
            Protection::Aead(state) => state.name(),
            Protection::StreamHmac(state) => state.name(),
            Protection::CtrOmac(state) => state.name(),
            Protection::CntImit(state) => state.name(),
            Protection::Aead13(state) => state.name(),
        }
    }

    /// Whether this is the TLS 1.3 construction, which the framing code
    /// has to know because the header it writes is not the header the
    /// record describes.
    pub fn is_tls13(&self) -> bool {
        matches!(self, Protection::Aead13(_))
    }
}

/// A stream cipher suite's keys for one direction: RC4, and the NULL
/// ciphers that encrypt nothing at all.
///
/// The simplest construction in TLS and the one with the fewest places to
/// go wrong - `plaintext || MAC`, encrypted, with no padding and no IV.
/// There is nothing here for a padding oracle to be about.
///
/// # The keystream runs for the whole connection
///
/// This is the detail that separates a stream suite from every other one
/// here, and the only real trap in the file. RC4's state is **not** reset
/// per record: record 2 continues exactly where record 1 stopped. So the
/// cipher lives in this struct rather than being built per record the way
/// `CbcHmac` builds one from its key each time.
///
/// Reset it per record and every record would be encrypted under the same
/// keystream prefix, which is the single worst thing a stream cipher can
/// do and which round-trips perfectly against an implementation making the
/// same mistake. `tools/src/bin/diff_tls_record.rs` is what settles it, because
/// the reference on the other side is written from the RFC.
///
/// # RC4 is broken and that is not why it is here
///
/// The biases in RC4's keystream are practical against TLS (RFC 7465
/// prohibits it outright), and this library implements it anyway, marked
/// `Broken`, offered by nothing but an explicit request. Equipment that
/// speaks only RC4 exists and is not ours to upgrade.
pub struct StreamHmac {
    cipher_name: String,
    hash_name: String,
    hash_len: usize,
    mac_key: Vec<u8>,
    /// `None` for the NULL ciphers, which authenticate and encrypt nothing.
    cipher: Option<AnyStreamCipher>,
    /// SSLv3's MAC is not HMAC and does not cover the record version. See
    /// `ssl3_mac`.
    ssl3: bool,
}

impl StreamHmac {
    /// `cipher_name` is `"rc4"`, or `"null"` for an authentication-only
    /// suite. `key` is ignored for NULL, which has none.
    pub fn new(cipher_name: &str, hash_name: &str, key: &[u8], mac_key: &[u8],
               version: Version) -> Result<StreamHmac, String> {
        let cipher = match cipher_name.to_ascii_lowercase().as_str() {
            "null" => None,
            other => Some(AnyStreamCipher::new(other, key, &[])?),
        };
        Ok(StreamHmac {
            cipher_name: cipher_name.to_ascii_lowercase(),
            hash_name: hash_name.to_string(),
            hash_len: AnyHash::new(hash_name)?.digest_len(),
            mac_key: mac_key.to_vec(),
            cipher,
            ssl3: version == Version::SSL30,
        })
    }

    pub fn name(&self) -> String {
        format!("{}-{}", self.cipher_name, self.hash_name)
    }

    /// The same MAC input as the CBC suites: RFC 5246 section 6.2.3.1, or
    /// `ssl3_mac` for SSLv3.
    fn mac(&self, sequence: SequenceNumber, content_type: ContentType,
           version: Version, fragment: &[u8]) -> Result<Vec<u8>, String> {
        if self.ssl3 {
            return ssl3_mac(&self.hash_name, &self.mac_key, sequence,
                            content_type, fragment);
        }
        let mut mac = Hmac::new(AnyHash::new(&self.hash_name)?, &self.mac_key);
        mac.update(&sequence.to_bytes());
        mac.update(&[content_type.to_byte()]);
        mac.update(&version.to_bytes());
        mac.update(&(fragment.len() as u16).to_be_bytes());
        mac.update(fragment);
        Ok(mac.digest())
    }

    /// Apply the keystream in place, continuing from wherever the last
    /// record left it. A NULL cipher leaves the bytes alone.
    fn apply(&mut self, buf: &mut [u8]) -> Result<(), String> {
        match &mut self.cipher {
            None => Ok(()),
            Some(cipher) => cipher.apply(buf),
        }
    }
}

/// An AEAD ciphersuite's keys for one direction (RFC 5246 §6.2.3.3).
///
/// The construction is much simpler than the CBC one, and that is the
/// point: there is no padding, so there is no padding oracle; the tag
/// covers everything and is checked before any plaintext exists; and a
/// failure has exactly one shape. Everything that makes `CbcHmac`'s
/// decrypt path delicate is absent here by construction rather than
/// mitigated.
///
/// ## The nonce, which is built two different ways
///
/// **AES-GCM (RFC 5288)** splits it. Four bytes come from the key block and
/// never change; eight travel in the clear at the front of each record. The
/// explicit half here is the sequence number, which is what OpenSSL sends
/// and what the RFC suggests.
///
/// **ChaCha20-Poly1305 (RFC 7905)** does not. The whole 12 byte nonce is
/// the key block's IV XORed with the sequence number, zero-padded on the
/// left, and nothing travels with the record - which saves eight bytes per
/// record and removes the peer's ability to choose any of the nonce at all.
/// That is the later and better design; GCM's split is a holdover.
///
/// Either way the sequence number is what makes each record's nonce
/// different, and that part is load-bearing. **A repeated nonce gives away
/// the authentication key** in both constructions - GHASH's H, or
/// Poly1305's r - and not just for the two records involved. So "the nonce
/// is unique" has to be a structural property rather than a hope. It is
/// tied to the same counter the record layer already refuses to let wrap,
/// so there is one thing to be right about instead of two.
pub struct AeadKeys {
    aead_name: String,
    key: Vec<u8>,
    /// The nonce's fixed half, from the key block.
    salt: Vec<u8>,
    /// How many bytes of nonce travel with each record.
    explicit_len: usize,
    tag_len: usize,
}

impl AeadKeys {
    /// `key` and `salt` come from the key block; `salt` is the "IV" slot,
    /// which for an AEAD holds the fixed half of the nonce rather than a
    /// CBC initialisation vector.
    pub fn new(aead_name: &str, key: &[u8], salt: &[u8], explicit_len: usize,
               tag_len: usize) -> Result<AeadKeys, String> {
        // Build one to validate the key length here, rather than at the
        // first record, where the error would arrive with no context.
        crate::api::AeadStream::new(aead_name, key, &[0u8; 12], &[], false)?;
        if salt.len() + explicit_len != 12 {
            return Err(format!(
                "An AEAD nonce is 12 bytes; {} of salt and {} explicit make {}.",
                salt.len(), explicit_len, salt.len() + explicit_len));
        }
        Ok(AeadKeys {
            aead_name: aead_name.to_string(),
            key: key.to_vec(),
            salt: salt.to_vec(),
            explicit_len,
            tag_len,
        })
    }

    pub fn name(&self) -> String {
        format!("{}-{}", self.aead_name, self.key.len() * 8)
    }

    /// Build the record nonce. See the note above for why there are two
    /// ways: `explicit_len > 0` is the RFC 5288 split, and zero is the
    /// RFC 7905 XOR construction.
    fn nonce(&self, sequence: SequenceNumber, explicit: &[u8]) -> Vec<u8> {
        if self.explicit_len > 0 {
            let mut nonce = Vec::with_capacity(12);
            nonce.extend_from_slice(&self.salt);
            nonce.extend_from_slice(explicit);
            return nonce;
        }

        // RFC 7905: the 64 bit sequence number, left-padded to the IV's
        // length, XORed with the IV.
        let mut nonce = self.salt.clone();
        let counter = sequence.to_bytes();
        let offset = nonce.len() - counter.len();
        for (byte, value) in nonce[offset..].iter_mut().zip(counter.iter()) {
            *byte ^= value;
        }
        nonce
    }

    /// The additional data an AEAD record authenticates:
    ///
    /// ```text
    /// seq_num || type || version || length
    /// ```
    ///
    /// `length` is the **plaintext** length, not the length in the record
    /// header, which also counts the explicit nonce and the tag. Using the
    /// header's would be self-consistent and would not interoperate with
    /// anything.
    fn additional_data(sequence: SequenceNumber, content_type: ContentType,
                       version: Version, plaintext_len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(13);
        data.extend_from_slice(&sequence.to_bytes());
        data.push(content_type.to_byte());
        data.extend_from_slice(&version.to_bytes());
        data.extend_from_slice(&(plaintext_len as u16).to_be_bytes());
        data
    }
}

/// A CBC ciphersuite's keys for one direction.
///
/// MAC-then-encrypt, which is what TLS up to 1.2 does and what makes the
/// decrypt path delicate. The alternative constructions (encrypt-then-MAC
/// from RFC 7366, and the AEAD suites) come later; this is the one the
/// legacy suites need.
pub struct CbcHmac {
    cipher_name: String,
    hash_name: String,
    key: Vec<u8>,
    mac_key: Vec<u8>,
    /// TLS 1.0 and SSLv3 chain the IV between records. TLS 1.1 added a
    /// fresh explicit IV per record, precisely because the chained one is
    /// what BEAST exploits. `None` means the version carries an explicit
    /// IV; `Some` is the carried-over block.
    chained_iv: Option<Vec<u8>>,
    /// RFC 7366. When the peer agreed to it, the MAC covers the ciphertext
    /// and is checked before anything is decrypted - so a forged record is
    /// rejected without its padding ever being examined, and the padding
    /// oracle is gone rather than merely hard to time.
    encrypt_then_mac: bool,
    block_size: usize,
    mac_len: usize,
    /// SSLv3 differs from every TLS version in two ways that live here:
    /// its MAC is not HMAC, and its padding bytes are unspecified. Kept as
    /// a flag rather than the whole `Version`, because those two facts are
    /// the only thing about the version this struct cares about.
    ssl3: bool,
    /// The cipher's one configuration parameter, for the cipher that has
    /// one: RC2's effective key length in bits, which is part of its key
    /// schedule rather than a length check. `None` for everything else.
    cipher_param: Option<String>,
}

impl CbcHmac {
    /// `key`, `mac_key` and the initial IV come from the key block the PRF
    /// produced. The IV is only used by the versions that chain it.
    pub fn new(cipher_name: &str, hash_name: &str, key: &[u8], mac_key: &[u8],
               iv: &[u8], version: Version) -> Result<CbcHmac, String> {
        let probe = AnyBlockCipher::new(cipher_name, key, None)?;
        let block_size = probe.blocksize();
        let mac_len = AnyHash::new(hash_name)?.digest_len();

        let chained_iv = if version.has_explicit_iv() {
            None
        } else {
            if iv.len() != block_size {
                return Err(format!(
                    "{} needs a {} byte IV for {}, got {}.",
                    version.name(), block_size, cipher_name, iv.len()));
            }
            Some(iv.to_vec())
        };

        Ok(CbcHmac {
            cipher_name: cipher_name.to_string(),
            hash_name: hash_name.to_string(),
            key: key.to_vec(),
            mac_key: mac_key.to_vec(),
            chained_iv,
            encrypt_then_mac: false,
            block_size,
            mac_len,
            ssl3: version == Version::SSL30,
            cipher_param: None,
        })
    }

    /// Set the cipher's parameter - RC2's effective key length in bits.
    ///
    /// A builder step rather than a constructor argument, because exactly
    /// one cipher has one and threading `Option<&str>` through every call
    /// site would put it in front of everybody who does not.
    pub fn with_cipher_param(mut self, param: &str) -> CbcHmac {
        self.cipher_param = Some(param.to_string());
        self
    }

    /// Turn on RFC 7366, once the handshake has agreed to it.
    ///
    /// Both sides must agree, which is what the extension is for. Turning
    /// it on unilaterally produces records the peer cannot read.
    pub fn with_encrypt_then_mac(mut self) -> CbcHmac {
        self.encrypt_then_mac = true;
        self
    }

    pub fn uses_encrypt_then_mac(&self) -> bool {
        self.encrypt_then_mac
    }

    pub fn name(&self) -> String {
        format!("{}-cbc-{}{}", self.cipher_name, self.hash_name,
                if self.encrypt_then_mac { "-etm" } else { "" })
    }

    /// The MAC input, from RFC 5246 section 6.2.3.1:
    ///
    /// ```text
    /// seq_num || type || version || length || fragment
    /// ```
    ///
    /// The sequence number is the part that matters: without it, records
    /// could be reordered or replayed with their MACs still valid.
    ///
    /// SSLv3 goes through `ssl3_mac` instead, and the difference is not
    /// only the construction: **the version is not in the input**. A
    /// straight port of this function with HMAC swapped out would still
    /// be wrong, and wrong in a way two implementations making the same
    /// assumption would agree on.
    fn mac(&self, sequence: SequenceNumber, content_type: ContentType,
           version: Version, fragment: &[u8]) -> Result<Vec<u8>, String> {
        if self.ssl3 {
            return ssl3_mac(&self.hash_name, &self.mac_key, sequence,
                            content_type, fragment);
        }
        let mut mac = Hmac::new(AnyHash::new(&self.hash_name)?, &self.mac_key);
        mac.update(&sequence.to_bytes());
        mac.update(&[content_type.to_byte()]);
        mac.update(&version.to_bytes());
        mac.update(&(fragment.len() as u16).to_be_bytes());
        mac.update(fragment);
        Ok(mac.digest())
    }
}

/// SSLv3's record MAC (RFC 6101 section 5.2.3.1).
///
/// ```text
/// hash(MAC_write_secret + pad_2 +
///      hash(MAC_write_secret + pad_1 + seq_num + type + length + fragment))
/// ```
///
/// Three things separate this from the HMAC that replaced it:
///
///   * the pads are **concatenated**, not XORed into the key, and they are
///     48 bytes for MD5 and 40 for SHA-1 rather than one block each;
///   * there is no key padding or shortening, so a MAC key longer than a
///     block is used as it is;
///   * the record's **version is not covered**, because SSLv3 had only one.
///
/// The construction is weaker than HMAC and is not a drop-in for it. It is
/// here because a server that speaks only SSLv3 is not ours to upgrade.
pub fn ssl3_mac(hash_name: &str, mac_key: &[u8], sequence: SequenceNumber,
            content_type: ContentType, fragment: &[u8]) -> Result<Vec<u8>, String> {
    let pad_len = match hash_name {
        "md5" => 48,
        "sha1" => 40,
        other => return Err(format!(
            "SSLv3's MAC is defined for MD5 and SHA-1 only; {} has no pad \
             length in the specification and inventing one would produce a \
             MAC that agrees with nobody.", other)),
    };

    let mut inner = AnyHash::new(hash_name)?;
    inner.update(mac_key);
    inner.update(&vec![0x36u8; pad_len]);
    inner.update(&sequence.to_bytes());
    inner.update(&[content_type.to_byte()]);
    inner.update(&(fragment.len() as u16).to_be_bytes());
    inner.update(fragment);
    let digest = inner.digest();

    let mut outer = AnyHash::new(hash_name)?;
    outer.update(mac_key);
    outer.update(&vec![0x5cu8; pad_len]);
    outer.update(&digest);
    Ok(outer.digest())
}

// ------------------------------------------------------------------ writing ---

/// Turns records into bytes, protecting them with whatever is current.
pub struct RecordWriter {
    protection: Protection,
    sequence: SequenceNumber,
    version: Version,
}

impl RecordWriter {
    pub fn new(version: Version) -> RecordWriter {
        RecordWriter {
            protection: Protection::Null,
            sequence: SequenceNumber::zero(),
            version,
        }
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    pub fn protection(&self) -> &Protection {
        &self.protection
    }

    /// The protection, mutably, for a TLS 1.3 KeyUpdate.
    ///
    /// Narrow on purpose: the only thing that may change a protection
    /// in place is an epoch change (`Aead13::update`), and every other
    /// transition goes through `change_cipher_spec`, which replaces the
    /// protection and resets the counter together.
    pub fn protection_mut(&mut self) -> &mut Protection {
        &mut self.protection
    }

    /// Switch to a new protection, as ChangeCipherSpec does.
    ///
    /// The sequence number restarts at zero, which is what the spec says
    /// and what every implementation has to get right: the new keys start
    /// counting fresh.
    pub fn change_cipher_spec(&mut self, protection: Protection) {
        self.protection = protection;
        self.sequence = SequenceNumber::zero();
    }

    /// Frame and protect one payload, fragmenting if it is too large.
    ///
    /// Returns the bytes to send. A payload longer than `MAX_PLAINTEXT`
    /// becomes several records, because that is the limit and silently
    /// truncating would lose data.
    pub fn write(&mut self, content_type: ContentType, payload: &[u8])
                 -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::with_capacity(payload.len() + HEADER_LEN);

        // An empty payload still produces one record: a zero-length
        // application data record is legal and is how some implementations
        // mitigate BEAST.
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![&[]]
        } else {
            payload.chunks(MAX_PLAINTEXT).collect()
        };

        for chunk in chunks {
            // TLS 1.3 keeps its own counter, inside the keys, because a
            // key change restarts it. Taking one from here as well would
            // advance a number nothing reads.
            let (header_type, header_version, fragment) = match &mut self.protection {
                Protection::Aead13(state) => {
                    // The header is a decoy: application_data and 0x0303
                    // whatever this record carries, so a middlebox that
                    // inspects the type sees nothing worth acting on.
                    let fragment = state.encrypt(content_type, chunk, 0)?;
                    (ContentType::ApplicationData,
                     crate::tls::record13::LEGACY_RECORD_VERSION, fragment)
                }
                other => {
                    let sequence = self.sequence.next()?;
                    let fragment = match other {
                        Protection::Null => chunk.to_vec(),
                        Protection::CbcHmac(state) => {
                            encrypt_cbc(state, sequence, content_type, self.version, chunk)?
                        }
                        Protection::Aead(state) => {
                            encrypt_aead(state, sequence, content_type, self.version, chunk)?
                        }
                        Protection::StreamHmac(state) => {
                            encrypt_stream(state, sequence, content_type, self.version, chunk)?
                        }
                        Protection::CtrOmac(state) => {
                            crate::tls::record_gost::encrypt(
                                state, sequence, content_type, self.version, chunk)?
                        }
                        Protection::CntImit(state) => {
                            crate::tls::record_cnt_imit::encrypt(
                                state, sequence, content_type, self.version, chunk)?
                        }
                        Protection::Aead13(_) => unreachable!("handled above"),
                    };
                    (content_type, self.version, fragment)
                }
            };

            let limit = if self.protection.is_tls13() {
                crate::tls::record13::MAX_CIPHERTEXT_13
            } else {
                MAX_CIPHERTEXT
            };
            if fragment.len() > limit {
                return Err(RecordError::new(
                    AlertDescription::RECORD_OVERFLOW,
                    format!("Protected fragment of {} bytes exceeds the {} byte limit.",
                            fragment.len(), limit)));
            }

            out.push(header_type.to_byte());
            out.extend_from_slice(&header_version.to_bytes());
            out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
            out.extend_from_slice(&fragment);
        }
        Ok(out)
    }
}

/// Protect one record with an AEAD.
///
/// `explicit_nonce || ciphertext || tag`, where the explicit nonce is the
/// sequence number. No padding, so nothing to get wrong about padding.
fn encrypt_aead(state: &mut AeadKeys, sequence: SequenceNumber,
                content_type: ContentType, version: Version, plaintext: &[u8])
                -> Result<Vec<u8>, RecordError> {
    let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);

    let explicit = &sequence.to_bytes()[8 - state.explicit_len..];
    let nonce = state.nonce(sequence, explicit);
    let aad = AeadKeys::additional_data(sequence, content_type, version,
                                        plaintext.len());

    let (ciphertext, tag) = crate::api::aead_encrypt(
        &state.aead_name, &state.key, &nonce, &aad, plaintext).map_err(internal)?;

    let mut out = Vec::with_capacity(state.explicit_len + ciphertext.len()
                                     + state.tag_len);
    out.extend_from_slice(explicit);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Unprotect one AEAD record.
///
/// Every failure is `bad_record_mac` with one message. There is nothing
/// here to distinguish - unlike the CBC path, there is no padding to check
/// separately and no order of checks to get right, because the tag covers
/// the whole record and is checked before any plaintext is handed back.
///
/// The explicit nonce that arrives with the record is used as sent rather
/// than compared against the sequence number. It is inside the tag's input
/// by way of being the nonce, so a peer that sends the wrong one gets a
/// tag failure - and peers are allowed to choose their own explicit nonces,
/// so requiring ours would refuse records that are perfectly valid.
fn decrypt_aead(state: &mut AeadKeys, sequence: SequenceNumber,
                content_type: ContentType, version: Version, fragment: &[u8])
                -> Result<Vec<u8>, RecordError> {
    let bad = || RecordError::new(
        AlertDescription::BAD_RECORD_MAC,
        "The record did not authenticate. It was altered in transit, or the \
         keys do not match.".to_string());

    let overhead = state.explicit_len + state.tag_len;
    if fragment.len() < overhead {
        // Too short to hold what every record must hold. Reported as a MAC
        // failure like everything else, since a length is something an
        // attacker chooses and a distinct error would be one bit of oracle.
        return Err(bad());
    }

    let explicit = &fragment[..state.explicit_len];
    let body = &fragment[state.explicit_len..fragment.len() - state.tag_len];
    let tag = &fragment[fragment.len() - state.tag_len..];

    let nonce = state.nonce(sequence, explicit);
    let aad = AeadKeys::additional_data(sequence, content_type, version,
                                        body.len());

    crate::api::aead_decrypt(&state.aead_name, &state.key, &nonce, &aad, body, tag)
        .map_err(|_| bad())
}

/// Protect one record with a stream cipher: `E(plaintext || MAC)`.
fn encrypt_stream(state: &mut StreamHmac, sequence: SequenceNumber,
                  content_type: ContentType, version: Version, plaintext: &[u8])
                  -> Result<Vec<u8>, RecordError> {
    let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);

    let mac = state.mac(sequence, content_type, version, plaintext)
        .map_err(internal)?;
    let mut fragment = Vec::with_capacity(plaintext.len() + mac.len());
    fragment.extend_from_slice(plaintext);
    fragment.extend_from_slice(&mac);
    state.apply(&mut fragment).map_err(internal)?;
    Ok(fragment)
}

/// Unprotect one stream-cipher record.
///
/// No padding, so none of `decrypt_cbc`'s care about the order of checks
/// applies - there is one check, and it is the MAC. What does still apply
/// is that a record too short to hold a MAC must fail the same way a bad
/// MAC does, and that the comparison is constant time.
///
/// A failed record still consumed keystream, and deliberately so: the
/// keystream position is a function of how many bytes have arrived, not of
/// how many authenticated. Rewinding it on failure would let a peer - or
/// anyone injecting a record - desynchronise the two ends by sending
/// something that does not verify.
fn decrypt_stream(state: &mut StreamHmac, sequence: SequenceNumber,
                  content_type: ContentType, version: Version, fragment: &[u8])
                  -> Result<Vec<u8>, RecordError> {
    let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);
    let bad = || RecordError::new(
        AlertDescription::BAD_RECORD_MAC,
        "The record did not authenticate. It was altered in transit, or the \
         keys do not match.".to_string());

    let mut plain = fragment.to_vec();
    state.apply(&mut plain).map_err(internal)?;

    if plain.len() < state.hash_len {
        return Err(bad());
    }
    let split = plain.len() - state.hash_len;
    let (content, received) = plain.split_at(split);

    let expected = state.mac(sequence, content_type, version, content)
        .map_err(internal)?;

    // Constant time over the whole MAC, as everywhere else here.
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(received.iter()) {
        difference |= a ^ b;
    }
    if difference != 0 || expected.len() != received.len() {
        return Err(bad());
    }
    Ok(content.to_vec())
}

fn encrypt_cbc(state: &mut CbcHmac, sequence: SequenceNumber,
               content_type: ContentType, version: Version, plaintext: &[u8])
               -> Result<Vec<u8>, RecordError> {
    let internal = |e: String| RecordError::new(AlertDescription::INTERNAL_ERROR, e);

    // Encrypt-then-MAC computes the MAC last, over the ciphertext, so the
    // two constructions diverge right at the start.
    let mac = if state.encrypt_then_mac {
        Vec::new()
    } else {
        state.mac(sequence, content_type, version, plaintext).map_err(internal)?
    };

    // plaintext || MAC || padding, where padding is N+1 bytes of value N.
    // Note it is N+1: the length byte is itself part of the padding, which
    // is the detail that differs from PKCS#7 and that implementations get
    // backwards.
    let unpadded = plaintext.len() + mac.len();
    let padding_len = state.block_size - (unpadded % state.block_size);
    let mut block = Vec::with_capacity(unpadded + padding_len);
    block.extend_from_slice(plaintext);
    block.extend_from_slice(&mac);
    block.resize(unpadded + padding_len, (padding_len - 1) as u8);

    // The IV: explicit and fresh from TLS 1.1 on, chained before that.
    let iv = match &state.chained_iv {
        Some(carried) => carried.clone(),
        None => crate::random::bytes(state.block_size).map_err(internal)?,
    };

    let cipher = AnyBlockCipher::new(&state.cipher_name, &state.key,
                                     state.cipher_param.as_deref())
        .map_err(internal)?;
    let mut stream = CipherStream::new(cipher, Mode::Cbc, &iv, false)
        .map_err(internal)?;
    let mut ciphertext = stream.update(&block).map_err(internal)?;
    ciphertext.extend_from_slice(&stream.finish().map_err(internal)?);

    // Assemble the fragment: the explicit IV, if this version has one,
    // then the ciphertext.
    let mut fragment = match &mut state.chained_iv {
        Some(carried) => {
            // The next record chains from this one's last block.
            *carried = ciphertext[ciphertext.len() - state.block_size..].to_vec();
            ciphertext
        }
        None => {
            let mut out = iv;
            out.extend_from_slice(&ciphertext);
            out
        }
    };

    if state.encrypt_then_mac {
        // RFC 7366: the MAC covers the explicit IV and the ciphertext, and
        // the length in the MAC input is the length of both - not of the
        // plaintext, which is the MAC-then-encrypt rule and the easy
        // mistake here.
        let mac = state.mac(sequence, content_type, version, &fragment)
            .map_err(internal)?;
        fragment.extend_from_slice(&mac);
    }
    Ok(fragment)
}

// ------------------------------------------------------------------ reading ---

/// Turns a byte stream into records.
///
/// Bytes arrive in whatever pieces the transport gives them: half a header,
/// three records at once, one byte at a time. `push_incoming` takes any of
/// those and `read` returns whole records when there are any.
pub struct RecordReader {
    buffer: Vec<u8>,
    protection: Protection,
    sequence: SequenceNumber,
    /// What version the records must claim. `None` before it is negotiated,
    /// when anything plausible is allowed.
    expected_version: Option<Version>,
    /// The wire length of the record most recently taken off the buffer,
    /// header included.
    ///
    /// For the one caller that has to charge a record it could not read
    /// against a budget: a TLS 1.3 server discarding early data it
    /// declined has no plaintext to measure.
    last_record_length: usize,
}

impl RecordReader {
    pub fn new() -> RecordReader {
        RecordReader {
            buffer: Vec::new(),
            protection: Protection::Null,
            sequence: SequenceNumber::zero(),
            expected_version: None,
            last_record_length: 0,
        }
    }

    /// The wire length of the record most recently taken off the buffer.
    pub fn last_record_length(&self) -> usize {
        self.last_record_length
    }

    pub fn protection(&self) -> &Protection {
        &self.protection
    }

    /// The protection, mutably, for a TLS 1.3 KeyUpdate.
    ///
    /// Narrow on purpose: the only thing that may change a protection
    /// in place is an epoch change (`Aead13::update`), and every other
    /// transition goes through `change_cipher_spec`, which replaces the
    /// protection and resets the counter together.
    pub fn protection_mut(&mut self) -> &mut Protection {
        &mut self.protection
    }

    pub fn change_cipher_spec(&mut self, protection: Protection) {
        self.protection = protection;
        self.sequence = SequenceNumber::zero();
    }

    /// Pin the version every subsequent record must claim.
    ///
    /// Before this is set, a record may claim anything; after it, a record
    /// claiming a different version is `protocol_version`. A peer that
    /// changes version mid-connection is either broken or trying something.
    pub fn expect_version(&mut self, version: Version) {
        self.expected_version = Some(version);
    }

    pub fn push_incoming(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// How many bytes are buffered and not yet a whole record.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// The next complete record, if there is one.
    ///
    /// `Ok(None)` means "not enough bytes yet", which is different from an
    /// error and different from end of stream. The caller reads more and
    /// asks again.
    pub fn read(&mut self) -> Result<Option<Record>, RecordError> {
        if self.buffer.len() < HEADER_LEN {
            return Ok(None);
        }

        let content_type = ContentType::from_byte(self.buffer[0]);
        let version = Version::from_bytes([self.buffer[1], self.buffer[2]]);
        let length = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;

        // The length check happens before anything is allocated or copied.
        // The field is two bytes, so a peer can claim 65535 for free.
        //
        // TLS 1.3 narrowed the allowance from 2048 to 256: there is no
        // explicit nonce and no padding block any more, only a tag and
        // whatever padding the sender chose.
        let limit = if self.protection.is_null() {
            MAX_PLAINTEXT
        } else if self.protection.is_tls13() {
            crate::tls::record13::MAX_CIPHERTEXT_13
        } else {
            MAX_CIPHERTEXT
        };
        if length > limit {
            return Err(RecordError::new(
                AlertDescription::RECORD_OVERFLOW,
                format!("Record claims {} bytes; the limit is {}.", length, limit)));
        }

        if self.buffer.len() < HEADER_LEN + length {
            return Ok(None);
        }

        // A record with a version we did not negotiate is refused before it
        // is decrypted, because it is cheap and decisive.
        //
        // Except under TLS 1.3, where the header's version is a decoy and
        // says 0x0303 forever. Checking it against the negotiated version
        // would refuse every record of a working connection.
        if self.protection.is_tls13() {
            if version != crate::tls::record13::LEGACY_RECORD_VERSION {
                return Err(RecordError::new(
                    AlertDescription::PROTOCOL_VERSION,
                    format!("A TLS 1.3 record must carry the legacy version {}; \
                             this one says {}.",
                            crate::tls::record13::LEGACY_RECORD_VERSION.name(),
                            version.name())));
            }
        } else if let Some(expected) = self.expected_version {
            if version != expected {
                return Err(RecordError::new(
                    AlertDescription::PROTOCOL_VERSION,
                    format!("Record claims {} but {} was negotiated.",
                            version.name(), expected.name())));
            }
        } else if version.major != 3 {
            return Err(RecordError::new(
                AlertDescription::PROTOCOL_VERSION,
                format!("Record claims {}, which is not a TLS version.",
                        version.name())));
        }

        let fragment = self.buffer[HEADER_LEN..HEADER_LEN + length].to_vec();
        self.buffer.drain(..HEADER_LEN + length);
        self.last_record_length = HEADER_LEN + length;

        let (content_type, payload) = match &mut self.protection {
            Protection::Aead13(state) => {
                // RFC 8446 section 5: a ChangeCipherSpec arriving mid
                // handshake is a middlebox compatibility relic sent in the
                // clear. Decrypting it would fail its tag and tear down a
                // connection that is perfectly healthy, so it goes
                // straight through and the state machine drops it.
                if content_type == ContentType::ChangeCipherSpec {
                    (content_type, fragment)
                } else if content_type != ContentType::ApplicationData {
                    // Anything else unprotected after the keys are in
                    // place is a peer bypassing encryption.
                    return Err(RecordError::new(
                        AlertDescription::UNEXPECTED_MESSAGE,
                        format!("A TLS 1.3 record claims {:?} rather than \
                                 application_data. Every protected record \
                                 says application_data; the real type is \
                                 inside.", content_type)));
                } else {
                    // The type that comes back is the real one, from
                    // inside the ciphertext - the header's was a decoy.
                    state.decrypt(&fragment)?
                }
            }
            other => {
                let sequence = self.sequence.next()?;
                let payload = match other {
                    Protection::Null => fragment,
                    Protection::CbcHmac(state) => {
                        decrypt_cbc(state, sequence, content_type, version, &fragment)?
                    }
                    Protection::Aead(state) => {
                        decrypt_aead(state, sequence, content_type, version, &fragment)?
                    }
                    Protection::StreamHmac(state) => {
                        decrypt_stream(state, sequence, content_type, version, &fragment)?
                    }
                    Protection::CtrOmac(state) => {
                        crate::tls::record_gost::decrypt(
                            state, sequence, content_type, version, &fragment)?
                    }
                    Protection::CntImit(state) => {
                        crate::tls::record_cnt_imit::decrypt(
                            state, sequence, content_type, version, &fragment)?
                    }
                    Protection::Aead13(_) => unreachable!("handled above"),
                };
                (content_type, payload)
            }
        };

        if payload.len() > MAX_PLAINTEXT {
            return Err(RecordError::new(
                AlertDescription::RECORD_OVERFLOW,
                format!("Record decrypted to {} bytes; the limit is {}.",
                        payload.len(), MAX_PLAINTEXT)));
        }

        Ok(Some(Record { content_type, version, payload }))
    }
}

impl Default for RecordReader {
    fn default() -> RecordReader {
        RecordReader::new()
    }
}

/// Decrypt and authenticate one CBC record.
///
/// The Lucky 13 shape, described at the top of this file: one error for
/// every failure, no early return once decryption has happened, and the MAC
/// computed over a fixed length regardless of what the padding claimed.
fn decrypt_cbc(state: &mut CbcHmac, sequence: SequenceNumber,
               content_type: ContentType, version: Version, fragment: &[u8])
               -> Result<Vec<u8>, RecordError> {
    // One error for everything below. Distinguishing "bad padding" from
    // "bad MAC" is the attack; so is distinguishing either from "wrong
    // length", once an attacker can choose the length.
    let failure = || RecordError::new(
        AlertDescription::BAD_RECORD_MAC,
        "Record failed to decrypt or authenticate.");

    let block_size = state.block_size;

    // --- encrypt-then-MAC: authenticate first, and only then decrypt ---
    //
    // This is the whole point of RFC 7366. A forged record is rejected
    // here, before anything is decrypted and before its padding is looked
    // at, so there is no padding oracle to time. The rest of this function
    // - the careful, fixed-length, no-early-return dance - exists only for
    // the peers that will not do this.
    let fragment = if state.encrypt_then_mac {
        if fragment.len() < state.mac_len {
            return Err(failure());
        }
        let split = fragment.len() - state.mac_len;
        let (body, received_mac) = fragment.split_at(split);

        let expected_mac = state.mac(sequence, content_type, version, body)
            .map_err(|_| failure())?;
        let mut difference = 0u8;
        for (a, b) in received_mac.iter().zip(expected_mac.iter()) {
            difference |= a ^ b;
        }
        if difference != 0 {
            return Err(failure());
        }
        body
    } else {
        fragment
    };

    // Split off the explicit IV, for the versions that carry one.
    let (iv, ciphertext) = match &state.chained_iv {
        Some(carried) => (carried.clone(), fragment),
        None => {
            if fragment.len() < block_size {
                return Err(failure());
            }
            (fragment[..block_size].to_vec(), &fragment[block_size..])
        }
    };

    // The ciphertext must be a whole number of blocks, and must hold at
    // least a MAC and one byte of padding.
    // With encrypt-then-MAC the MAC is already gone, so the block holds
    // only plaintext and padding.
    let minimum = if state.encrypt_then_mac { 1 } else { state.mac_len + 1 };
    if ciphertext.is_empty()
        || ciphertext.len() % block_size != 0
        || ciphertext.len() < minimum {
        return Err(failure());
    }

    // Chain forward before anything can fail, so a rejected record does not
    // leave the IV in the wrong state for the next one.
    if let Some(carried) = &mut state.chained_iv {
        *carried = ciphertext[ciphertext.len() - block_size..].to_vec();
    }

    let cipher = AnyBlockCipher::new(&state.cipher_name, &state.key,
                                     state.cipher_param.as_deref())
        .map_err(|_| failure())?;
    let mut stream = CipherStream::new(cipher, Mode::Cbc, &iv, true)
        .map_err(|_| failure())?;
    let mut block = stream.update(ciphertext).map_err(|_| failure())?;
    block.extend_from_slice(&stream.finish().map_err(|_| failure())?);

    // --- padding, checked without branching out early ---
    //
    // The last byte claims how many padding bytes precede it. TLS padding
    // is N+1 bytes all of value N, and *every one of them* must be right -
    // checking only the last byte is what made the original padding oracle
    // attacks work.
    let last = block[block.len() - 1] as usize;
    let padding_len = last + 1;

    // A claimed padding longer than the record cannot be right, but saying
    // so here would be a branch an attacker can time. Instead the length
    // used for the MAC is clamped, and the mismatch is folded into `good`.
    let inner_mac_len = if state.encrypt_then_mac { 0 } else { state.mac_len };
    let padding_fits = padding_len <= block.len() - inner_mac_len;
    let effective_padding = if padding_fits { padding_len } else { 1 };

    let mut good = padding_fits as u8;
    // SSLv3 leaves the padding bytes' *contents* unspecified: only the
    // final length byte means anything, and a receiver may not reject a
    // record because the bytes before it are arbitrary.
    //
    // That is POODLE. With MAC-then-encrypt and unchecked padding, an
    // attacker who can replay a record with its last block swapped learns
    // one byte of plaintext per 256 attempts, and the only fix is to stop
    // speaking SSLv3 - which is why this library refuses it unless the
    // caller asks for it by name. Checking the bytes anyway would not fix
    // it either: it would just make us unable to talk to the servers this
    // is for, since their padding is genuinely arbitrary.
    let check_contents = !state.ssl3;
    // Check the padding bytes that are actually there. The loop runs over a
    // fixed window - the largest padding TLS allows - so its length does
    // not depend on what the record claimed.
    for offset in 0..256usize {
        let within = offset < padding_len;
        let index = block.len().wrapping_sub(1).wrapping_sub(offset);
        let byte = if within && index < block.len() { block[index] } else { last as u8 };
        let matches = (byte == last as u8) as u8;
        good &= matches | !(within as u8) | !(check_contents as u8);
    }

    if state.encrypt_then_mac {
        // The MAC was already checked and is not inside the block; only
        // the padding is left to strip, and a wrong padding here means a
        // peer that authenticated a malformed record - which is an error
        // but not an oracle, since the attacker cannot produce a valid MAC.
        if good != 1 || padding_len > block.len() {
            return Err(failure());
        }
        return Ok(block[..block.len() - padding_len].to_vec());
    }

    // --- MAC-then-encrypt: MAC over the length the padding left behind ---
    let content_len = block.len() - state.mac_len - effective_padding;
    let plaintext = &block[..content_len];
    let received_mac = &block[content_len..content_len + state.mac_len];

    let expected_mac = state.mac(sequence, content_type, version, plaintext)
        .map_err(|_| failure())?;

    // **The HMAC above ran a number of compressions that depends on
    // `content_len`, and so on the padding byte** - which is the whole
    // of what Lucky 13 measures. Top it up to the count the longest
    // content this record could hold would have taken, so the total
    // does not depend on the padding. SSLv3's MAC is a different
    // construction and is left alone: SSLv3 has POODLE, which no
    // timing countermeasure addresses.
    if !state.ssl3 {
        let longest = block.len() - state.mac_len - 1;
        let mut dummy = AnyHash::new(&state.hash_name).map_err(|_| failure())?;
        let block_size = dummy.block_size();
        let extra = lucky13_extra_compressions(block_size, longest, content_len);
        let zeros = [0u8; 128];
        for _ in 0..extra {
            dummy.update(&zeros[..block_size]);
        }
        // Nothing reads `dummy`, so without this the optimiser may
        // remove the loop as dead code and the countermeasure with it -
        // the same way it turned `Montgomery::conditional_subtract`'s
        // select back into a branch.
        core::hint::black_box(&mut dummy);
    }

    let mut difference = 0u8;
    for (a, b) in received_mac.iter().zip(expected_mac.iter()) {
        difference |= a ^ b;
    }
    good &= (difference == 0) as u8;

    if good != 1 {
        return Err(failure());
    }
    Ok(plaintext.to_vec())
}

/// How many compression calls HMAC's inner hash runs over a record MAC
/// input whose content is `content_len` bytes: the key block, the
/// thirteen bytes of sequence number, type, version and length, the
/// content, and the hash's own padding (one `0x80` byte and a length
/// field of an eighth of the block).
fn hmac_inner_compressions(block_size: usize, content_len: usize) -> usize {
    let length_field = block_size / 8;
    (block_size + 13 + content_len + 1 + length_field).div_ceil(block_size)
}

/// The dummy compressions that bring a MAC over `content_len` bytes up
/// to the count a MAC over `longest` bytes takes, so that MAC-then-
/// encrypt does the same hashing work whatever the padding claimed.
/// `content_len` is never more than `longest`, since the padding is at
/// least one byte.
fn lucky13_extra_compressions(block_size: usize, longest: usize,
                              content_len: usize) -> usize {
    hmac_inner_compressions(block_size, longest)
        - hmac_inner_compressions(block_size, content_len)
}

/// The record protection one direction of one connection uses.
///
/// A free function because **both sides need exactly this**, and two
/// copies of it would drift: the client had the only one, and a server
/// written beside it would have grown a second that agreed about AES
/// and disagreed about, say, whether CCM_8's tag is eight bytes. The
/// one thing that differs between the two is which half of the key
/// block goes in, which is the caller's to choose.
pub fn protection_for(suite: &CipherSuite, version: Version,
                      direction: &DirectionKeys, encrypt_then_mac: bool)
                      -> Result<Protection, String> {
        // The NULL ciphers have no algorithm to look up, by definition, so
        // they are decided before anything asks for one. They encrypt
        // nothing and authenticate everything, which is a diagnostic tool
        // rather than a ciphersuite - `Selection` will only ever produce
        // one if somebody named it.
        if suite.cipher == BulkCipher::Null {
            let hash = suite.mac.hash_name().ok_or_else(
                || format!("{}'s MAC is not implemented.", suite.name))?;
            let state = StreamHmac::new("null", hash, &direction.key,
                                        &direction.mac_key, version)
                ?;
            return Ok(Protection::StreamHmac(state));
        }

        // CTR_OMAC before the algorithm lookup, because it needs the
        // whole parameter set rather than a cipher name - and because
        // its MAC is OMAC, which has no hash name for the lookup below
        // to find.
        if suite.cipher == BulkCipher::Gost28147Cnt {
            // Both halves are cumulative, so this value is built once
            // per direction and kept - rebuilding it per record would
            // repeat the keystream.
            //
            // **Which S-box is decided by the suite, not by the
            // cipher.** Two suites share this record layer and differ
            // only in their parameter set: RFC 9189's CNT_IMIT uses
            // `id-tc26-gost-28147-param-Z` and the 2001 one uses
            // `id-Gost28147-89-CryptoPro-A-ParamSet`. Both encrypt,
            // both MAC, and the wrong one produces a record the peer
            // reads as a MAC failure.
            let state = if suite.key_exchange == KeyExchange::GostVko2001 {
                crate::tls::record_cnt_imit::CntImit::new_2001(
                    &direction.key, &direction.mac_key, &direction.iv)?
            } else {
                crate::tls::record_cnt_imit::CntImit::new(
                    &direction.key, &direction.mac_key, &direction.iv)?
            };
            return Ok(Protection::CntImit(state));
        }
        if let Some(gost) = suite.cipher.ctr_omac() {
            let state = crate::tls::record_gost::CtrOmac::new(
                gost, &direction.key, &direction.mac_key, &direction.iv)
                ?;
            return Ok(Protection::CtrOmac(state));
        }

        let cipher = suite.cipher.algorithm().ok_or_else(
            || format!("{}'s cipher is not implemented.", suite.name))?;

        // An AEAD carries its own authentication, so there is no separate
        // MAC to look up - and asking for one would fail, since an AEAD
        // suite's `mac` is the `Aead` marker rather than a hash.
        if suite.cipher.is_aead() {
            let aead = match suite.cipher {
                BulkCipher::Aes128Gcm | BulkCipher::Aes256Gcm =>
                    "aes-gcm",
                BulkCipher::Aes128Ccm | BulkCipher::Aes256Ccm =>
                    "aes-ccm",
                BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8 =>
                    "aes-ccm-8",
                BulkCipher::ChaCha20Poly1305 => "chacha20-poly1305",
                other => return Err(format!(
                    "{} is not implemented as a record layer AEAD.", other.name())),
            };
            // The tag length comes from the suite rather than being a
            // constant: the CCM_8 suites exist to make it eight, and a
            // record layer that assumed sixteen would read the last eight
            // bytes of the ciphertext as part of the tag.
            let state = AeadKeys::new(aead, &direction.key, &direction.iv,
                                      suite.cipher.explicit_iv_len(),
                                      suite.cipher.tag_len())
                ?;
            return Ok(Protection::Aead(state));
        }

        let hash = suite.mac.hash_name().ok_or_else(
            || format!("{}'s MAC is not implemented.", suite.name))?;

        // A stream cipher, or no cipher at all. Neither has a block size,
        // padding or an IV, so neither goes through CbcHmac - and RC4's
        // keystream runs for the whole connection, which is why the state
        // has to be built once here and kept.
        if !suite.cipher.is_cbc() {
            let state = StreamHmac::new(cipher, hash, &direction.key,
                                        &direction.mac_key, version)
                ?;
            return Ok(Protection::StreamHmac(state));
        }

        let state = CbcHmac::new(cipher, hash, &direction.key, &direction.mac_key,
                                 &direction.iv, version)?;
        // RC2 is the one cipher with a parameter, and it is not optional:
        // RC2_CBC_40 means a 16 byte key with 40 effective bits, which is
        // a different cipher from the same 16 bytes unweakened.
        let state = match suite.cipher.rc2_effective_bits() {
            Some(bits) => state.with_cipher_param(&bits.to_string()),
            None => state,
        };
        Ok(Protection::CbcHmac(if encrypt_then_mac {
            state.with_encrypt_then_mac()
        } else {
            state
        }))
    }

#[cfg(test)]
mod tests {
    use super::*;

    /// The dummy hashing that evens out MAC-then-encrypt's work is
    /// defined for every record a CBC suite can deliver: it never
    /// underflows (the content is never longer than the longest the
    /// padding allows) and it never needs more than a few blocks.
    ///
    /// Whether the total work is then *independent of the padding* is a
    /// timing property, and a functional test cannot see it - the MAC
    /// computed is the same either way, which is how the path spent its
    /// life computing a padding-dependent amount of it while the module
    /// comment said otherwise. `scripts/ct_check.py` and
    /// `tools/src/bin/dudect` are what measure that; this pins the
    /// arithmetic they rely on.
    #[test]
    fn test_the_lucky13_dummy_work_is_defined_for_every_record() {
        for name in ["md5", "sha1", "sha256", "sha384"] {
            let block_size = AnyHash::new(name).unwrap().block_size();
            for mac_len in [16usize, 20, 32, 48] {
                for record in mac_len + 1..=mac_len + 1 + 600 {
                    let longest = record - mac_len - 1;
                    for padding in 1..=256usize.min(record - mac_len) {
                        let content = record - mac_len - padding;
                        let extra = lucky13_extra_compressions(block_size, longest,
                                                               content);
                        assert!(extra * block_size <= 256 + 2 * block_size,
                                "{name}, record {record}, padding {padding}");
                    }
                }
            }
        }
    }


    fn keys(version: Version) -> (CbcHmac, CbcHmac) {
        let key: Vec<u8> = (0..16u8).collect();
        let mac_key: Vec<u8> = (100..120u8).collect();
        let iv: Vec<u8> = (200..216u8).collect();
        (CbcHmac::new("aes", "sha1", &key, &mac_key, &iv, version).unwrap(),
         CbcHmac::new("aes", "sha1", &key, &mac_key, &iv, version).unwrap())
    }

    /// A writer and a reader wired together, which is what every test here
    /// needs: protect, then unprotect, and see the same bytes.
    fn pair(version: Version) -> (RecordWriter, RecordReader) {
        let mut writer = RecordWriter::new(version);
        let mut reader = RecordReader::new();
        let (send, receive) = keys(version);
        writer.change_cipher_spec(Protection::CbcHmac(send));
        reader.change_cipher_spec(Protection::CbcHmac(receive));
        reader.expect_version(version);
        (writer, reader)
    }

    /// A CBC pair over any cipher and block size, for the suites whose
    /// block is not 16 bytes.
    fn cbc_pair(cipher: &str, key_len: usize, block: usize, version: Version)
                -> (RecordWriter, RecordReader) {
        let key: Vec<u8> = (0..key_len as u8).collect();
        let mac_key: Vec<u8> = (100..120u8).collect();
        let iv: Vec<u8> = (0..block as u8).collect();
        let mut writer = RecordWriter::new(version);
        let mut reader = RecordReader::new();
        writer.change_cipher_spec(Protection::CbcHmac(
            CbcHmac::new(cipher, "sha1", &key, &mac_key, &iv, version).unwrap()));
        reader.change_cipher_spec(Protection::CbcHmac(
            CbcHmac::new(cipher, "sha1", &key, &mac_key, &iv, version).unwrap()));
        reader.expect_version(version);
        (writer, reader)
    }

    /// SSLv3 records, through both constructions.
    ///
    /// Nothing here can be checked against OpenSSL - this build has SSLv3
    /// compiled out - so what this test says is that our own writer and
    /// reader agree, and `tools/src/bin/diff_tls_record.rs` says the bytes are
    /// the ones RFC 6101 describes. Neither claim is worth much without
    /// the other.
    #[test]
    fn test_ssl3_records_round_trip() {
        for (cipher, key_len, block) in [("aes", 16usize, 16usize),
                                         ("3des", 24, 8), ("des", 8, 8)] {
            let (mut writer, mut reader) =
                cbc_pair(cipher, key_len, block, Version::SSL30);
            for length in [0usize, 1, 15, 16, 17, 100, 1000] {
                let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
                let record = writer.write(ContentType::ApplicationData, &payload)
                    .unwrap();
                reader.push_incoming(&record);
                let incoming = reader.read().unwrap().unwrap();
                assert_eq!(incoming.payload, payload,
                           "{} at {} bytes", cipher, length);
            }
        }

        // And the stream path, which SSLv3 shares with TLS apart from the
        // MAC. MD5 and SHA-1 only: SSLv3's MAC has no pad length defined
        // for anything else.
        for hash in ["md5", "sha1"] {
            let (mut writer, mut reader) =
                stream_pair_at("rc4", hash, Version::SSL30);
            for length in [0usize, 1, 100] {
                let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
                let record = writer.write(ContentType::ApplicationData, &payload)
                    .unwrap();
                reader.push_incoming(&record);
                assert_eq!(reader.read().unwrap().unwrap().payload, payload);
            }
        }
    }

    /// SSLv3 refuses a MAC hash it has no pad length for, rather than
    /// inventing one.
    ///
    /// The pads are 48 bytes for MD5 and 40 for SHA-1, chosen so that
    /// `key + pad` fills whole blocks of each. SHA-256 has a different
    /// block size and no value in the specification at all, so any choice
    /// would be ours - and an implementation that guessed would produce
    /// MACs that agree with nobody.
    #[test]
    fn test_ssl3_refuses_a_hash_it_has_no_pad_length_for() {
        let key: Vec<u8> = (0..16u8).collect();
        let mac_key: Vec<u8> = (100..132u8).collect();
        let iv: Vec<u8> = (0..16u8).collect();
        let state = CbcHmac::new("aes", "sha256", &key, &mac_key, &iv,
                                 Version::SSL30).unwrap();
        // The construction succeeds - the suite exists - and using it
        // fails, with a message that says why rather than a wrong MAC.
        let mut writer = RecordWriter::new(Version::SSL30);
        writer.change_cipher_spec(Protection::CbcHmac(state));
        let error = writer.write(ContentType::ApplicationData, b"x").unwrap_err();
        assert!(format!("{:?}", error).contains("MD5 and SHA-1"),
                "{:?}", error);
    }

    /// SSLv3's padding bytes are unspecified, and a receiver must not
    /// reject a record because of them. This is POODLE.
    ///
    /// The attack is exactly this property plus MAC-then-encrypt: an
    /// attacker who can replay a record with its last block swapped in
    /// learns one byte of plaintext per 256 attempts, because a wrong
    /// guess fails the MAC and a right one passes. Checking the padding
    /// bytes would not fix it - the padding is genuinely arbitrary, so we
    /// would simply be unable to talk to the servers this exists for.
    ///
    /// The fix is not to speak SSLv3, which is why the default floor is
    /// above it and even `ClientConfig::legacy` does not reach it.
    #[test]
    fn test_ssl3_accepts_arbitrary_padding_bytes_and_tls_does_not() {
        for (version, ssl3) in [(Version::SSL30, true), (Version::TLS10, false)] {
            let key: Vec<u8> = (0..16u8).collect();
            let mac_key: Vec<u8> = (100..120u8).collect();
            let iv: Vec<u8> = (200..216u8).collect();

            // Build the record by hand so the padding can be filled with
            // something other than the length byte.
            let sender =
                CbcHmac::new("aes", "sha1", &key, &mac_key, &iv, version).unwrap();
            let payload = b"a message".to_vec();
            let mac = sender.mac(SequenceNumber::zero(), ContentType::ApplicationData,
                                 version, &payload).unwrap();
            let unpadded = payload.len() + mac.len();
            let padding_len = 16 - (unpadded % 16);
            let mut block = payload.clone();
            block.extend_from_slice(&mac);
            // Arbitrary bytes, then the correct length byte last. TLS
            // requires every one of them to equal the length; SSLv3 says
            // nothing about them at all.
            block.resize(unpadded + padding_len - 1, 0xa5);
            block.push((padding_len - 1) as u8);

            let cipher = AnyBlockCipher::new("aes", &key, None).unwrap();
            let mut stream = CipherStream::new(cipher, Mode::Cbc, &iv, false).unwrap();
            let mut ciphertext = stream.update(&block).unwrap();
            ciphertext.extend_from_slice(&stream.finish().unwrap());

            let mut record = vec![ContentType::ApplicationData.to_byte()];
            record.extend_from_slice(&version.to_bytes());
            record.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
            record.extend_from_slice(&ciphertext);

            let receiver =
                CbcHmac::new("aes", "sha1", &key, &mac_key, &iv, version).unwrap();
            let mut reader = RecordReader::new();
            reader.change_cipher_spec(Protection::CbcHmac(receiver));
            reader.expect_version(version);
            reader.push_incoming(&record);

            let got = reader.read();
            if ssl3 {
                assert_eq!(got.unwrap().unwrap().payload, payload,
                           "SSLv3 must accept arbitrary padding bytes");
            } else {
                assert!(got.is_err(),
                        "TLS must reject padding bytes that are not the length");
            }
        }
    }

    /// 3DES and single DES through the record layer, at every version.
    ///
    /// These cannot be tested against OpenSSL as a peer: it has removed
    /// both from TLS entirely - this build offers 158 suites and not one
    /// uses either - which is the reason this library exists. The record
    /// *construction* is checked against OpenSSL's primitive in
    /// `scripts/diff_check.py`; what this adds is that our own two ends
    /// agree across versions and lengths.
    ///
    /// The 8 byte block is the thing to watch. Padding and the explicit IV
    /// are both block-sized, so every length lands differently than it
    /// does for AES - a record layer that assumed 16 bytes anywhere works
    /// perfectly for AES and fails here.
    #[test]
    fn test_des_records_round_trip_at_every_version() {
        for version in [Version::TLS10, Version::TLS11, Version::TLS12] {
            for (cipher, key_len) in [("3des", 24usize), ("des", 8)] {
                let (mut writer, mut reader) =
                    cbc_pair(cipher, key_len, 8, version);

                for length in [0usize, 1, 7, 8, 9, 15, 16, 17, 100, 1000] {
                    let payload: Vec<u8> =
                        (0..length).map(|i| (i * 13) as u8).collect();
                    let bytes = writer.write(ContentType::ApplicationData,
                                             &payload).unwrap();

                    // The fragment is a whole number of 8 byte blocks,
                    // plus an explicit IV where the version has one.
                    let fragment = bytes.len() - 5;
                    assert_eq!(fragment % 8, 0,
                               "{} {} at {}: fragment of {} is not whole blocks",
                               version.name(), cipher, length, fragment);

                    reader.push_incoming(&bytes);
                    let record = reader.read().unwrap().unwrap();
                    assert_eq!(record.payload, payload,
                               "{} {} at length {}", version.name(), cipher, length);
                }
            }
        }
    }

    /// A tampered 3DES record must fail, at every byte.
    #[test]
    fn test_a_tampered_des_record_is_refused() {
        let (mut writer, _) = cbc_pair("3des", 24, 8, Version::TLS12);
        let bytes = writer.write(ContentType::ApplicationData, b"protected")
            .unwrap();

        for index in 5..bytes.len() {
            let (_, mut reader) = cbc_pair("3des", 24, 8, Version::TLS12);
            let mut altered = bytes.clone();
            altered[index] ^= 0x01;
            reader.push_incoming(&altered);
            assert_eq!(reader.read().unwrap_err().alert,
                       AlertDescription::BAD_RECORD_MAC, "byte {}", index);
        }
    }

    /// A stream-cipher writer and reader wired together.
    fn stream_pair(cipher: &str, hash: &str) -> (RecordWriter, RecordReader) {
        stream_pair_at(cipher, hash, Version::TLS12)
    }

    fn stream_pair_at(cipher: &str, hash: &str, version: Version)
                      -> (RecordWriter, RecordReader) {
        let key: Vec<u8> = (0..16u8).collect();
        let mac_key: Vec<u8> = (100..132u8).collect();
        let mut writer = RecordWriter::new(version);
        let mut reader = RecordReader::new();
        writer.change_cipher_spec(Protection::StreamHmac(
            StreamHmac::new(cipher, hash, &key, &mac_key, version).unwrap()));
        reader.change_cipher_spec(Protection::StreamHmac(
            StreamHmac::new(cipher, hash, &key, &mac_key, version).unwrap()));
        reader.expect_version(version);
        (writer, reader)
    }

    #[test]
    fn test_stream_round_trip() {
        for cipher in ["rc4", "null"] {
            let (mut writer, mut reader) = stream_pair(cipher, "sha1");
            for length in [0usize, 1, 15, 16, 17, 100, 1000] {
                let payload: Vec<u8> = (0..length).map(|i| (i * 7) as u8).collect();
                let bytes = writer.write(ContentType::ApplicationData, &payload)
                    .unwrap();
                reader.push_incoming(&bytes);
                let record = reader.read().unwrap().unwrap();
                assert_eq!(record.payload, payload, "{} at {}", cipher, length);
            }
        }
    }

    /// The one that matters for RC4: the keystream runs for the whole
    /// connection, not per record.
    ///
    /// A record layer that restarts the cipher each time round-trips
    /// against itself perfectly and interoperates with nothing, so a
    /// round-trip test cannot catch it. This one can: encrypting the same
    /// bytes twice must give *different* ciphertext, because the second
    /// record uses keystream the first one did not.
    #[test]
    fn test_the_rc4_keystream_does_not_restart_per_record() {
        let (mut writer, _reader) = stream_pair("rc4", "sha1");
        let payload = b"the same sixteen";

        let first = writer.write(ContentType::ApplicationData, payload).unwrap();
        let second = writer.write(ContentType::ApplicationData, payload).unwrap();

        assert_ne!(first, second,
                   "two records of identical plaintext produced identical \
                    ciphertext, so the keystream restarted");

        // And a NULL cipher is the opposite: it encrypts nothing, so the
        // only thing that differs is the MAC, which covers the sequence
        // number.
        let (mut writer, _reader) = stream_pair("null", "sha1");
        let first = writer.write(ContentType::ApplicationData, payload).unwrap();
        let second = writer.write(ContentType::ApplicationData, payload).unwrap();
        assert_ne!(first, second, "the sequence number is not in the MAC");
        assert_eq!(&first[5..5 + payload.len()], payload,
                   "a NULL cipher should leave the plaintext visible");
    }

    #[test]
    fn test_a_tampered_stream_record_is_refused() {
        for cipher in ["rc4", "null"] {
            let (mut writer, _) = stream_pair(cipher, "sha1");
            let bytes = writer.write(ContentType::ApplicationData, b"protected")
                .unwrap();

            for index in 5..bytes.len() {
                let (_, mut reader) = stream_pair(cipher, "sha1");
                let mut altered = bytes.clone();
                altered[index] ^= 0x01;
                reader.push_incoming(&altered);
                let error = reader.read().unwrap_err();
                assert_eq!(error.alert, AlertDescription::BAD_RECORD_MAC,
                           "{} byte {}", cipher, index);
            }
        }
    }

    /// A record too short to hold a MAC must fail the same way a bad MAC
    /// does. A distinct error for it would be one bit of an oracle, and
    /// the length is something an attacker picks.
    #[test]
    fn test_a_stream_record_shorter_than_its_mac() {
        for length in [0usize, 1, 10, 19] {
            let (_, mut reader) = stream_pair("rc4", "sha1");
            let mut bytes = vec![23u8, 3, 3];
            bytes.extend_from_slice(&(length as u16).to_be_bytes());
            bytes.extend(std::iter::repeat_n(0u8, length));
            reader.push_incoming(&bytes);
            let error = reader.read().unwrap_err();
            assert_eq!(error.alert, AlertDescription::BAD_RECORD_MAC,
                       "a {} byte record", length);
        }
    }

    /// Records must arrive in order: the sequence number is in the MAC.
    #[test]
    fn test_stream_records_must_arrive_in_order() {
        let (mut writer, mut reader) = stream_pair("rc4", "sha1");
        let first = writer.write(ContentType::ApplicationData, b"one").unwrap();
        let second = writer.write(ContentType::ApplicationData, b"two").unwrap();

        // The second record, delivered first, is both the wrong sequence
        // number and the wrong keystream position.
        reader.push_incoming(&second);
        assert_eq!(reader.read().unwrap_err().alert,
                   AlertDescription::BAD_RECORD_MAC);
        let _ = first;
    }

    #[test]
    fn test_plaintext_round_trip() {
        let mut writer = RecordWriter::new(Version::TLS12);
        let mut reader = RecordReader::new();

        let bytes = writer.write(ContentType::Handshake, b"hello").unwrap();
        assert_eq!(bytes[0], 22);
        assert_eq!(&bytes[1..3], &[3, 3]);
        assert_eq!(u16::from_be_bytes([bytes[3], bytes[4]]), 5);

        reader.push_incoming(&bytes);
        let record = reader.read().unwrap().unwrap();
        assert_eq!(record.content_type, ContentType::Handshake);
        assert_eq!(record.version, Version::TLS12);
        assert_eq!(record.payload, b"hello");
        assert!(reader.read().unwrap().is_none());
    }

    /// The transport splits bytes wherever it likes. A record must appear
    /// exactly once the last byte of it has arrived, and not before.
    #[test]
    fn test_bytes_arriving_in_any_split() {
        let mut writer = RecordWriter::new(Version::TLS12);
        let payload: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        let bytes = writer.write(ContentType::ApplicationData, &payload).unwrap();

        for chunk_size in [1usize, 2, 3, 5, 7, 64, 128, 505] {
            let mut reader = RecordReader::new();
            let mut records = Vec::new();
            for chunk in bytes.chunks(chunk_size) {
                reader.push_incoming(chunk);
                while let Some(record) = reader.read().unwrap() {
                    records.push(record);
                }
            }
            assert_eq!(records.len(), 1, "chunk size {}", chunk_size);
            assert_eq!(records[0].payload, payload, "chunk size {}", chunk_size);
            assert_eq!(reader.buffered(), 0);
        }
    }

    #[test]
    fn test_several_records_in_one_read() {
        let mut writer = RecordWriter::new(Version::TLS12);
        let mut bytes = writer.write(ContentType::Handshake, b"one").unwrap();
        bytes.extend(writer.write(ContentType::Handshake, b"two").unwrap());
        bytes.extend(writer.write(ContentType::Alert, &[1, 0]).unwrap());

        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes);
        assert_eq!(reader.read().unwrap().unwrap().payload, b"one");
        assert_eq!(reader.read().unwrap().unwrap().payload, b"two");
        assert_eq!(reader.read().unwrap().unwrap().content_type, ContentType::Alert);
        assert!(reader.read().unwrap().is_none());
    }

    /// A payload larger than 2^14 must become several records, not one
    /// oversized one and not a truncated one.
    #[test]
    fn test_fragmentation() {
        let mut writer = RecordWriter::new(Version::TLS12);
        let payload: Vec<u8> = (0..40000u32).map(|i| (i % 251) as u8).collect();
        let bytes = writer.write(ContentType::ApplicationData, &payload).unwrap();

        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes);

        let mut rebuilt = Vec::new();
        let mut count = 0;
        while let Some(record) = reader.read().unwrap() {
            assert!(record.payload.len() <= MAX_PLAINTEXT);
            rebuilt.extend_from_slice(&record.payload);
            count += 1;
        }
        assert_eq!(count, 3);           // 16384 + 16384 + 7232
        assert_eq!(rebuilt, payload);
    }

    /// An empty payload is a real record, not nothing. A zero-length
    /// application data record is legal and is one of the BEAST
    /// workarounds.
    #[test]
    fn test_empty_payload_is_a_record() {
        let mut writer = RecordWriter::new(Version::TLS12);
        let bytes = writer.write(ContentType::ApplicationData, b"").unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);

        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes);
        let record = reader.read().unwrap().unwrap();
        assert!(record.payload.is_empty());
    }

    /// The length field is two bytes, so a peer can claim 65535 for free.
    /// The check must happen before anything is allocated.
    #[test]
    fn test_oversized_length_is_refused_before_the_body_arrives() {
        let mut reader = RecordReader::new();
        reader.push_incoming(&[23, 3, 3, 0xff, 0xff]);
        let error = reader.read().unwrap_err();
        assert_eq!(error.alert, AlertDescription::RECORD_OVERFLOW);
        // Nothing was buffered beyond the header we gave it.
        assert_eq!(reader.buffered(), HEADER_LEN);
    }

    #[test]
    fn test_version_is_pinned_once_negotiated() {
        let mut writer = RecordWriter::new(Version::TLS12);
        let bytes = writer.write(ContentType::Handshake, b"x").unwrap();

        let mut reader = RecordReader::new();
        reader.expect_version(Version::TLS10);
        reader.push_incoming(&bytes);
        let error = reader.read().unwrap_err();
        assert_eq!(error.alert, AlertDescription::PROTOCOL_VERSION);

        // And before negotiation, anything in the 3.x family is allowed.
        let mut reader = RecordReader::new();
        reader.push_incoming(&bytes);
        assert!(reader.read().unwrap().is_some());

        // But not something outside it.
        let mut reader = RecordReader::new();
        reader.push_incoming(&[22, 2, 0, 0, 1, 0]);
        assert_eq!(reader.read().unwrap_err().alert, AlertDescription::PROTOCOL_VERSION);
    }

    // ------------------------------------------------------------ CBC ---

    #[test]
    fn test_cbc_round_trip() {
        for version in [Version::TLS10, Version::TLS11, Version::TLS12] {
            let (mut writer, mut reader) = pair(version);

            for payload in [b"".as_slice(), b"x", b"a longer message", &[0u8; 1000]] {
                let bytes = writer.write(ContentType::ApplicationData, payload).unwrap();
                reader.push_incoming(&bytes);
                let record = reader.read().unwrap().unwrap();
                assert_eq!(record.payload, payload,
                           "{} payload of {} bytes", version.name(), payload.len());
            }
        }
    }

    /// TLS 1.1 and later put a fresh IV in every record; 1.0 chains it.
    /// Encrypting the same payload twice must therefore differ from 1.1 on,
    /// and the chained versions must still round trip in order.
    #[test]
    fn test_explicit_versus_chained_iv() {
        let (mut writer, _) = pair(Version::TLS12);
        let first = writer.write(ContentType::ApplicationData, b"same").unwrap();
        let second = writer.write(ContentType::ApplicationData, b"same").unwrap();
        assert_ne!(first, second, "TLS 1.2 records must carry a fresh IV");

        // TLS 1.0 chains, so several records in a row must still decrypt -
        // which only works if both sides advance the chain identically.
        let (mut writer, mut reader) = pair(Version::TLS10);
        for index in 0..5u8 {
            let payload = vec![index; 20];
            let bytes = writer.write(ContentType::ApplicationData, &payload).unwrap();
            reader.push_incoming(&bytes);
            assert_eq!(reader.read().unwrap().unwrap().payload, payload,
                       "record {}", index);
        }
    }

    /// The sequence number is in the MAC, so records that arrive out of
    /// order must fail - otherwise they could be reordered or replayed with
    /// their MACs still valid.
    #[test]
    fn test_records_must_arrive_in_order() {
        let (mut writer, mut reader) = pair(Version::TLS12);
        let first = writer.write(ContentType::ApplicationData, b"first").unwrap();
        let second = writer.write(ContentType::ApplicationData, b"second").unwrap();

        // Second first: the sequence number in the MAC will not match.
        reader.push_incoming(&second);
        assert_eq!(reader.read().unwrap_err().alert, AlertDescription::BAD_RECORD_MAC);

        // And a replay of a record already accepted.
        let (mut writer, mut reader) = pair(Version::TLS12);
        let bytes = writer.write(ContentType::ApplicationData, b"once").unwrap();
        reader.push_incoming(&bytes);
        assert!(reader.read().unwrap().is_some());
        reader.push_incoming(&bytes);
        assert_eq!(reader.read().unwrap_err().alert, AlertDescription::BAD_RECORD_MAC);

        let _ = first;
    }

    /// Every way of corrupting a record must produce the same alert, with
    /// no clue about which check failed. That indistinguishability is the
    /// whole Lucky 13 mitigation.
    #[test]
    fn test_every_corruption_gives_the_same_alert() {
        let (mut writer, _) = pair(Version::TLS12);
        let good = writer.write(ContentType::ApplicationData, b"authentic data").unwrap();

        let mut errors = std::collections::HashSet::new();
        // A flip in the IV, in the ciphertext, and in the last block, plus
        // a truncated record and one that is not a whole number of blocks.
        let mut corruptions: Vec<Vec<u8>> = Vec::new();
        for index in [5usize, 10, 20, good.len() - 1] {
            let mut corrupt = good.clone();
            corrupt[index] ^= 0x01;
            corruptions.push(corrupt);
        }
        {
            // Truncated by one block, with the length fixed up so framing
            // still accepts it.
            let mut corrupt = good.clone();
            corrupt.truncate(corrupt.len() - 16);
            let length = (corrupt.len() - HEADER_LEN) as u16;
            corrupt[3..5].copy_from_slice(&length.to_be_bytes());
            corruptions.push(corrupt);
        }
        {
            // Not a whole number of blocks.
            let mut corrupt = good.clone();
            corrupt.truncate(corrupt.len() - 3);
            let length = (corrupt.len() - HEADER_LEN) as u16;
            corrupt[3..5].copy_from_slice(&length.to_be_bytes());
            corruptions.push(corrupt);
        }

        for corrupt in corruptions {
            let (_, mut reader) = pair(Version::TLS12);
            reader.push_incoming(&corrupt);
            let error = reader.read().unwrap_err();
            errors.insert(error.describe());
        }

        assert_eq!(errors.len(), 1,
                   "decrypt failures must be indistinguishable, got {:?}", errors);
    }

    /// Changing the content type byte must break the MAC, because the type
    /// is part of the MAC input. Otherwise an attacker could turn a
    /// handshake record into an application data one.
    #[test]
    fn test_content_type_is_authenticated() {
        let (mut writer, mut reader) = pair(Version::TLS12);
        let mut bytes = writer.write(ContentType::Handshake, b"payload").unwrap();
        bytes[0] = ContentType::ApplicationData.to_byte();
        reader.push_incoming(&bytes);
        assert_eq!(reader.read().unwrap_err().alert, AlertDescription::BAD_RECORD_MAC);
    }

    /// And so must the version, for the same reason.
    #[test]
    fn test_version_is_authenticated() {
        let (mut writer, mut reader) = pair(Version::TLS12);
        let mut bytes = writer.write(ContentType::ApplicationData, b"payload").unwrap();
        bytes[1..3].copy_from_slice(&Version::TLS11.to_bytes());
        reader.push_incoming(&bytes);
        // The version pin catches it first, which is cheaper; without the
        // pin the MAC would catch it.
        let error = reader.read().unwrap_err();
        assert_eq!(error.alert, AlertDescription::PROTOCOL_VERSION);

        let (mut writer, mut reader) = pair(Version::TLS12);
        let mut bytes = writer.write(ContentType::ApplicationData, b"payload").unwrap();
        bytes[1..3].copy_from_slice(&Version::TLS11.to_bytes());
        // Without the pin, the MAC is what rejects it.
        reader.expected_version = None;
        reader.push_incoming(&bytes);
        assert_eq!(reader.read().unwrap_err().alert, AlertDescription::BAD_RECORD_MAC);
    }

    /// Changing the keys restarts the sequence number, which is what
    /// ChangeCipherSpec does and what both sides must agree on.
    #[test]
    fn test_change_cipher_spec_restarts_the_sequence() {
        let mut writer = RecordWriter::new(Version::TLS12);
        let mut reader = RecordReader::new();

        // A few plaintext records first, so the sequence is not zero.
        for _ in 0..3 {
            let bytes = writer.write(ContentType::Handshake, b"hello").unwrap();
            reader.push_incoming(&bytes);
            reader.read().unwrap().unwrap();
        }

        let (send, receive) = keys(Version::TLS12);
        writer.change_cipher_spec(Protection::CbcHmac(send));
        reader.change_cipher_spec(Protection::CbcHmac(receive));

        // If either side failed to restart at zero, the MAC would not match.
        let bytes = writer.write(ContentType::ApplicationData, b"after ccs").unwrap();
        reader.push_incoming(&bytes);
        assert_eq!(reader.read().unwrap().unwrap().payload, b"after ccs");
    }

    /// Encrypt-then-MAC round trips, and produces different bytes from
    /// MAC-then-encrypt - the two constructions are not interchangeable
    /// and a peer that agreed to one cannot read the other.
    #[test]
    fn test_encrypt_then_mac_round_trip() {
        for version in [Version::TLS10, Version::TLS11, Version::TLS12] {
            let (send, receive) = keys(version);
            let mut writer = RecordWriter::new(version);
            let mut reader = RecordReader::new();
            writer.change_cipher_spec(Protection::CbcHmac(send.with_encrypt_then_mac()));
            reader.change_cipher_spec(
                Protection::CbcHmac(receive.with_encrypt_then_mac()));
            reader.expect_version(version);

            for payload in [b"".as_slice(), b"x", b"a longer message", &[0u8; 1000]] {
                let bytes = writer.write(ContentType::ApplicationData, payload).unwrap();
                reader.push_incoming(&bytes);
                assert_eq!(reader.read().unwrap().unwrap().payload, payload,
                           "{} with {} bytes", version.name(), payload.len());
            }
        }
    }

    /// A peer that agreed to encrypt-then-MAC cannot read MAC-then-encrypt
    /// records, and the reverse. Both sides must agree, which is what the
    /// extension is for.
    #[test]
    fn test_the_two_constructions_are_not_interchangeable() {
        let (send, receive) = keys(Version::TLS12);
        let mut writer = RecordWriter::new(Version::TLS12);
        let mut reader = RecordReader::new();
        writer.change_cipher_spec(Protection::CbcHmac(send.with_encrypt_then_mac()));
        reader.change_cipher_spec(Protection::CbcHmac(receive));   // not EtM
        reader.expect_version(Version::TLS12);

        let bytes = writer.write(ContentType::ApplicationData, b"payload").unwrap();
        reader.push_incoming(&bytes);
        assert_eq!(reader.read().unwrap_err().alert, AlertDescription::BAD_RECORD_MAC);
    }

    /// With encrypt-then-MAC a forged record is rejected before it is
    /// decrypted at all, so its padding is never examined - which is what
    /// removes the padding oracle rather than making it hard to time.
    #[test]
    fn test_encrypt_then_mac_rejects_without_decrypting() {
        let (send, _) = keys(Version::TLS12);
        let mut writer = RecordWriter::new(Version::TLS12);
        writer.change_cipher_spec(Protection::CbcHmac(send.with_encrypt_then_mac()));
        let good = writer.write(ContentType::ApplicationData, b"authentic").unwrap();

        let mut errors = std::collections::HashSet::new();
        for index in [5usize, 20, good.len() - 1] {
            let mut corrupt = good.clone();
            corrupt[index] ^= 0x01;

            let (_, receive) = keys(Version::TLS12);
            let mut reader = RecordReader::new();
            reader.change_cipher_spec(
                Protection::CbcHmac(receive.with_encrypt_then_mac()));
            reader.expect_version(Version::TLS12);
            reader.push_incoming(&corrupt);
            errors.insert(reader.read().unwrap_err().describe());
        }
        assert_eq!(errors.len(), 1, "failures must be indistinguishable: {:?}", errors);
    }

    /// The MAC covers the explicit IV too, so moving it must fail. An
    /// implementation that MACs only the ciphertext leaves the IV
    /// malleable, and the first plaintext block with it.
    #[test]
    fn test_encrypt_then_mac_covers_the_explicit_iv() {
        let (send, receive) = keys(Version::TLS12);
        let mut writer = RecordWriter::new(Version::TLS12);
        writer.change_cipher_spec(Protection::CbcHmac(send.with_encrypt_then_mac()));
        let mut bytes = writer.write(ContentType::ApplicationData,
                                     b"sixteen bytes!!!").unwrap();
        // Flip a bit in the explicit IV, which is the first block after the
        // five byte header.
        bytes[HEADER_LEN] ^= 0x01;

        let mut reader = RecordReader::new();
        reader.change_cipher_spec(Protection::CbcHmac(receive.with_encrypt_then_mac()));
        reader.expect_version(Version::TLS12);
        reader.push_incoming(&bytes);
        assert_eq!(reader.read().unwrap_err().alert, AlertDescription::BAD_RECORD_MAC);
    }

    #[test]
    fn test_sequence_number_refuses_to_wrap() {
        let mut sequence = SequenceNumber(u64::MAX);
        let error = sequence.next().unwrap_err();
        assert_eq!(error.alert, AlertDescription::INTERNAL_ERROR);
        assert!(error.detail.contains("wrap"));
    }

    #[test]
    fn test_padding_that_claims_too_much_is_refused() {
        // Build a record by hand whose last byte claims 255 bytes of
        // padding in a record that does not have them. The check must not
        // read out of bounds and must not accept it.
        let (mut writer, mut reader) = pair(Version::TLS12);
        let bytes = writer.write(ContentType::ApplicationData, b"short").unwrap();

        let mut corrupt = bytes.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        reader.push_incoming(&corrupt);
        assert_eq!(reader.read().unwrap_err().alert, AlertDescription::BAD_RECORD_MAC);
    }

    /// Truncation at every offset, and a flipped byte at every offset, must
    /// be an error rather than a panic.
    #[test]
    fn test_no_input_causes_a_panic() {
        let (mut writer, _) = pair(Version::TLS12);
        let good = writer.write(ContentType::ApplicationData, &[7u8; 100]).unwrap();

        for cut in 0..good.len() {
            let (_, mut reader) = pair(Version::TLS12);
            reader.push_incoming(&good[..cut]);
            let _ = reader.read();
        }
        for index in 0..good.len() {
            let mut corrupt = good.clone();
            corrupt[index] ^= 0xff;
            let (_, mut reader) = pair(Version::TLS12);
            reader.push_incoming(&corrupt);
            let _ = reader.read();
        }
    }
}
