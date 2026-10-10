/*
The key schedule: from a premaster secret to the keys the record layer uses.

    premaster secret
        |  PRF(premaster, "master secret", client_random + server_random)
        v
    master secret (48 bytes, always, whatever the suite)
        |  PRF(master, "key expansion", server_random + client_random)
        v
    key block -> MAC keys, encryption keys, IVs

Two details in there are the ones implementations get wrong, and both are
silent when you do:

  1. **The randoms are in the opposite order in the two steps.** Client then
     server for the master secret; server then client for the key block.
     Getting it the same way round in both produces a key block that is
     perfectly deterministic, matches on neither side, and fails at the
     Finished check with no clue why.

  2. **The key block is split in a fixed order** - both MAC keys, then both
     encryption keys, then both IVs - and the client's comes first in each
     pair. Swapping a pair gives two sides that each encrypt correctly and
     cannot read each other.

Neither is caught by a round trip against yourself, because a consistent
mistake is still consistent. They are caught by decrypting something a real
implementation encrypted, which is what `tests/test_tls_keys.rs` does with a
captured session's master secret.

**Extended master secret** (RFC 7627) is here too. Without it, a master
secret is a function of the premaster and the two randoms only, and two
different connections can be made to share one - which is the triple
handshake attack. With it the master secret also covers the handshake
transcript, so it cannot be shared. Real servers offer it; we ask for it.
*/

use crate::api::AnyHash;
use crate::hash_functions::HashFunction;
use crate::kdf;
use crate::tls::suites::{CipherSuite, KeyExchange, MacAlgorithm};
use crate::tls::Version;

/// The master secret is 48 bytes in every version and every suite.
pub const MASTER_SECRET_LEN: usize = 48;

/// Finished carries 12 bytes in TLS. SSLv3 is different and is not this.
pub const VERIFY_DATA_LEN: usize = 12;

/// The running hash of every handshake message, which Finished covers.
///
/// Fed with the *raw* bytes of each message, header included, exactly as
/// they crossed the wire. A re-encoding that differs anywhere makes the
/// Finished check fail - or, if both sides re-encode the same way, lets
/// them agree on a transcript that is not what was exchanged, which is
/// worse.
#[derive(Clone)]
pub struct Transcript {
    /// TLS 1.2 hashes with the suite's PRF hash. Before 1.2 the transcript
    /// is MD5 and SHA-1 together, which is why both are kept.
    md5: AnyHash,
    sha1: AnyHash,
    suite_hash: AnyHash,
    version: Version,
    /// The raw messages, kept only when somebody has asked for them.
    ///
    /// **A TLS 1.2 CertificateVerify signs `Hash(handshake_messages)`
    /// with a hash the message itself names** (RFC 5246 7.4.8), so the
    /// digest cannot be taken until that message has arrived - and by
    /// then a running hash has already eaten the bytes. There is no way
    /// to have both cheaply, so the bytes are kept only on the
    /// handshakes that need them: a server that asked for a client
    /// certificate, or a client that might send one.
    ///
    /// `None` on every other handshake, which is nearly all of them.
    /// Keeping them always would be a few kilobytes per connection
    /// bought for nothing.
    messages: Option<Vec<u8>>,
}

impl Transcript {
    pub fn new(version: Version, prf: MacAlgorithm) -> Result<Transcript, String> {
        // **An error, not a default.** `hash_name` is `None` for `Aead`
        // and `Gost`, which are MACs and not hashes; a suite row whose
        // `prf` were ever set to one of those would get a SHA-256
        // transcript and a Finished nobody else computes, with nothing
        // said anywhere. Every row's `prf` is a hash today, which is
        // exactly why the fallback would not be noticed when it stopped
        // being true.
        let name = prf.hash_name().ok_or_else(|| format!(
            "{} is a MAC, not a hash, so it cannot be a transcript hash.",
            prf.name()))?;
        Ok(Transcript {
            md5: AnyHash::new("md5")?,
            sha1: AnyHash::new("sha1")?,
            suite_hash: AnyHash::new(name)?,
            version,
            messages: None,
        })
    }

    /// Start keeping the raw messages as well as the running hashes.
    ///
    /// Call it before the first `update`, or the buffer starts in the
    /// middle of the handshake and the signature covers the wrong
    /// bytes - which is a failure at the CertificateVerify and nowhere
    /// nearer the cause.
    pub fn keep_messages(&mut self) {
        if self.messages.is_none() {
            self.messages = Some(Vec::new());
        }
    }

    /// The raw concatenation, or empty if it was never kept.
    pub fn messages(&self) -> &[u8] {
        self.messages.as_deref().unwrap_or(&[])
    }

    /// Add one handshake message's raw bytes.
    pub fn update(&mut self, raw: &[u8]) {
        self.md5.update(raw);
        self.sha1.update(raw);
        self.suite_hash.update(raw);
        if let Some(messages) = &mut self.messages {
            messages.extend_from_slice(raw);
        }
    }

    /// The transcript hash as the current version wants it.
    ///
    /// TLS 1.2 uses the suite's PRF hash. TLS 1.0 and 1.1 concatenate an
    /// MD5 and a SHA-1 over the same bytes - not a hash of a hash, and not
    /// one after the other.
    pub fn hash(&self) -> Vec<u8> {
        let mut clone = self.clone();
        if self.version >= Version::TLS12 {
            clone.suite_hash.digest()
        } else {
            let mut out = clone.md5.digest();
            out.extend_from_slice(&clone.sha1.digest());
            out
        }
    }

    /// The hash for the extended master secret, which RFC 7627 calls the
    /// session hash: the transcript up to and including ClientKeyExchange.
    pub fn session_hash(&self) -> Vec<u8> {
        self.hash()
    }

    /// SSLv3's Finished (RFC 6101 section 5.6.9), 36 bytes:
    ///
    /// ```text
    /// MD5(master + pad2 + MD5(handshake_messages + Sender + master + pad1)) +
    /// SHA(master + pad2 + SHA(handshake_messages + Sender + master + pad1))
    /// ```
    ///
    /// This needs the transcript's *running state* rather than its digest,
    /// because the sender constant, the master secret and the padding are
    /// appended to the handshake messages before the hash is taken - so it
    /// lives here, where the state is, instead of in `verify_data`.
    ///
    /// The pad lengths differ per hash: 48 bytes for MD5 and 40 for SHA-1,
    /// chosen so that `master + pad` fills whole blocks. Using one length
    /// for both is a mistake that produces a Finished which agrees with
    /// nobody, and that no round-trip test would catch.
    pub fn ssl3_finished(&self, master: &[u8], side: Side)
                         -> Result<Vec<u8>, String> {
        let sender = side.ssl3_sender();
        let mut out = Vec::with_capacity(36);
        for (name, mut hash, pad_len) in [("md5", self.md5.clone(), 48usize),
                                          ("sha1", self.sha1.clone(), 40usize)] {
            hash.update(&sender);
            hash.update(master);
            hash.update(&vec![0x36u8; pad_len]);
            let inner = hash.digest();

            let mut outer = AnyHash::new(name)?;
            outer.update(master);
            outer.update(&vec![0x5cu8; pad_len]);
            outer.update(&inner);
            out.extend_from_slice(&outer.digest());
        }
        Ok(out)
    }
}

/// SSLv3's key derivation (RFC 6101 section 6.2.2).
///
/// Not a PRF with a label: an ad-hoc expansion that predates the idea.
///
/// ```text
/// MD5(secret + SHA('A'   + secret + seed)) +
/// MD5(secret + SHA('BB'  + secret + seed)) +
/// MD5(secret + SHA('CCC' + secret + seed)) + ...
/// ```
///
/// The salt grows by one letter each round - `A`, `BB`, `CCC`, `DDDD` -
/// and each round yields sixteen bytes, so the output is taken in 16 byte
/// steps and truncated at the end.
///
/// Two things here are easy to get wrong and impossible to notice without
/// a reference, because both sides of a handshake would make the same
/// mistake: the secret appears **twice** in each round, inside the SHA-1
/// and again in front of the MD5; and the salt is the letter repeated, not
/// the letter followed by a counter.
///
/// TLS 1.0 replaced all of this with the MD5/SHA-1 xor construction, so
/// nothing after SSLv3 uses it. It is here because a server that speaks
/// only SSLv3 is not ours to upgrade.
fn ssl3_expand(secret: &[u8], seed: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(length + 16);
    let mut letter = b'A';
    while out.len() < length {
        let rounds = (letter - b'A') as usize + 1;

        let mut sha = AnyHash::new("sha1")?;
        for _ in 0..rounds {
            sha.update(&[letter]);
        }
        sha.update(secret);
        sha.update(seed);
        let inner = sha.digest();

        let mut md5 = AnyHash::new("md5")?;
        md5.update(secret);
        md5.update(&inner);
        out.extend_from_slice(&md5.digest());

        if letter == b'Z' {
            return Err("SSLv3's key expansion runs out of salt letters after \
                        416 bytes; nothing needs that much.".to_string());
        }
        letter += 1;
    }
    out.truncate(length);
    Ok(out)
}

/// The PRF for a version and suite.
///
/// TLS 1.2 made the PRF hash part of the ciphersuite; before that it was
/// fixed by the version at MD5 xor SHA-1 over split halves of the secret.
/// Both are here because both are needed.
///
/// SSLv3 does not come through here at all: it has no label, so a function
/// taking one could only ignore it, and an ignored argument is a lie the
/// next reader has to discover. Its callers branch instead.
fn prf(version: Version, prf_hash: MacAlgorithm, secret: &[u8], label: &[u8],
       seed: &[u8], length: usize) -> Result<Vec<u8>, String> {
    if version >= Version::TLS12 {
        let name = prf_hash.hash_name()
            .ok_or_else(|| "This suite's PRF hash is not implemented.".to_string())?;
        Ok(kdf::tls12_prf(AnyHash::new(name)?, secret, label, seed, length))
    } else {
        Ok(kdf::tls10_prf(secret, label, seed, length))
    }
}

/// `PRF(premaster, "master secret", client_random + server_random)`.
///
/// Note the order: **client random first**. The key block below reverses
/// it, and getting them the same way round in both places is a silent
/// failure that only shows up at the Finished check.
pub fn master_secret(version: Version, prf_hash: MacAlgorithm, premaster: &[u8],
                     client_random: &[u8; 32], server_random: &[u8; 32])
                     -> Result<Vec<u8>, String> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    if version == Version::SSL30 {
        return ssl3_expand(premaster, &seed, MASTER_SECRET_LEN);
    }
    prf(version, prf_hash, premaster, b"master secret", &seed, MASTER_SECRET_LEN)
}

/// The extended master secret of RFC 7627.
///
/// `PRF(premaster, "extended master secret", session_hash)`. Without this,
/// a master secret depends only on the premaster and the two randoms, and
/// an attacker who can make two connections share a premaster can make them
/// share a master secret - the triple handshake attack. Binding the
/// transcript in makes that impossible.
pub fn extended_master_secret(version: Version, prf_hash: MacAlgorithm,
                              premaster: &[u8], session_hash: &[u8])
                              -> Result<Vec<u8>, String> {
    prf(version, prf_hash, premaster, b"extended master secret", session_hash,
        MASTER_SECRET_LEN)
}

/// The key material one direction needs.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectionKeys {
    pub mac_key: Vec<u8>,
    pub key: Vec<u8>,
    /// Only the versions with an implicit IV carry one here; TLS 1.1 and
    /// later put a fresh IV in every record instead.
    pub iv: Vec<u8>,
}

impl core::fmt::Debug for DirectionKeys {
    /// Deliberately says nothing but the lengths. These are the live
    /// record keys of a connection, and a `{:?}` in a log line, an error
    /// path or a failing `assert_eq!` is how key material escapes - the
    /// same rule every other secret-carrying type in this module family
    /// follows (`TrafficKeys`, `Aead13`, `Ticket`, `ServerKey`).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DirectionKeys {{ {} byte mac_key, {} byte key, {} byte iv, \
                   redacted }}", self.mac_key.len(), self.key.len(), self.iv.len())
    }
}

/// The key block, split.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyBlock {
    pub client: DirectionKeys,
    pub server: DirectionKeys,
}

impl core::fmt::Debug for KeyBlock {
    /// Redacted through `DirectionKeys`' own `Debug`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyBlock {{ client: {:?}, server: {:?} }}", self.client, self.server)
    }
}

/// Derive and split the key block.
///
/// `PRF(master, "key expansion", server_random + client_random)` - **server
/// random first**, the opposite of the master secret above.
///
/// The split order is fixed by RFC 5246 section 6.3 and is not obvious:
/// both MAC keys, then both encryption keys, then both IVs, client first in
/// each pair. A swapped pair gives two sides that each encrypt correctly
/// and cannot read one another.
/// RFC 9189 section 4.3.2: the OMAC key is 32 bytes for both CTR_OMAC
/// suites, regardless of the block size.
const GOST_MAC_KEY_LEN: usize = 32;

pub fn key_block(version: Version, suite: &CipherSuite, master: &[u8],
                 client_random: &[u8; 32], server_random: &[u8; 32])
                 -> Result<KeyBlock, String> {
    let mac_len = if suite.mac == MacAlgorithm::Aead {
        0
    } else if suite.mac == MacAlgorithm::Gost {
        // OMAC is not a hash, so its key length does not come from a
        // digest size. RFC 9189 section 4.3.2 fixes it at 32 bytes for
        // both suites - note that is the *key*, while the tag is a whole
        // block and so differs between them.
        GOST_MAC_KEY_LEN
    } else {
        let name = suite.mac.hash_name()
            .ok_or_else(|| format!("{}'s MAC is not implemented.", suite.name))?;
        AnyHash::new(name)?.digest_len()
    };
    let key_len = suite.cipher.key_len();
    // Two different things live in this slot, which is why the condition
    // is not a single test.
    //
    // For CBC it is a chained IV, and only for the versions that chain it:
    // from TLS 1.1 the IV is explicit and random per record, so deriving
    // one here would be dead material and a source of confusion about
    // which IV is in use.
    //
    // For an AEAD it is the nonce's fixed half - the salt - which every
    // version needs, since the nonce is built from it once per record.
    let iv_len = if suite.cipher == crate::tls::suites::BulkCipher::Gost28147Cnt {
        // CNT's IV is a whole block, not half of one: RFC 5830 section
        // 6 encrypts it to make the starting counter rather than
        // splitting it with a counter, which is what CTR-ACPKM does.
        crate::tls::record_cnt_imit::IV_LEN
    } else if let Some(gost) = suite.cipher.ctr_omac() {
        // CTR_OMAC's IV is half a block, and the other half is the
        // counter (RFC 9189 4.1.1). It is not a chained CBC IV and not
        // an AEAD salt, so it needs its own branch - and it is four
        // bytes for Magma against eight for Kuznyechik, which is why it
        // comes from the suite rather than a constant.
        gost.iv_len()
    } else if suite.cipher.is_aead() {
        suite.cipher.fixed_iv_len()
    } else if suite.cipher.is_exportable() {
        // An export suite takes no IV from the key block at all: its IVs
        // come from a separate PRF pass with an empty secret, in
        // `export_expansion` below. Taking them from here as well would
        // consume bytes the peer did not consume and shift every key
        // after them.
        0
    } else if version.has_explicit_iv() || !suite.cipher.is_cbc() {
        0
    } else {
        suite.cipher.block_size()
    };

    let needed = 2 * (mac_len + key_len + iv_len);
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let block = if version == Version::SSL30 {
        ssl3_expand(master, &seed, needed)?
    } else {
        prf(version, suite.prf, master, b"key expansion", &seed, needed)?
    };

    let mut at = 0;
    let mut take = |n: usize| -> Vec<u8> {
        let piece = block[at..at + n].to_vec();
        at += n;
        piece
    };

    let client_mac = take(mac_len);
    let server_mac = take(mac_len);
    let client_key = take(key_len);
    let server_key = take(key_len);
    let client_iv = take(iv_len);
    let server_iv = take(iv_len);

    let block = KeyBlock {
        client: DirectionKeys { mac_key: client_mac, key: client_key, iv: client_iv },
        server: DirectionKeys { mac_key: server_mac, key: server_key, iv: server_iv },
    };

    if suite.cipher.is_exportable() {
        return export_expansion(version, suite, block, client_random, server_random);
    }
    Ok(block)
}

/// The second expansion the export suites need (RFC 2246 section 6.3.1,
/// RFC 6101 section 6.2.2 for SSLv3).
///
/// An export suite does not simply use a five byte key. The key block
/// yields five bytes per direction, and those five bytes are then run
/// through the PRF *again* to produce a key of the cipher's real length -
/// sixteen bytes for RC4_40 and RC2_CBC_40, eight for DES40_CBC. The
/// result has forty bits of entropy spread over the full key, which was
/// the whole design: the export paperwork said forty and the wire format
/// did not have to change.
///
/// Two details here are easy to miss and impossible to notice without a
/// reference, because both ends of a handshake would miss them together:
///
///   * **the IVs do not come from the key block at all.** They come from
///     a separate PRF pass with an *empty secret* - `PRF("", "IV block",
///     ...)` - which is not a secret in any sense. An export suite's IV
///     is public, and saying so is the honest description of it.
///   * **SSLv3's version swaps the randoms for the server side**, and
///     uses a bare MD5 rather than a PRF. Applying the TLS rule to an
///     SSLv3 connection produces keys that agree with nobody.
fn export_expansion(version: Version, suite: &CipherSuite, block: KeyBlock,
                    client_random: &[u8; 32], server_random: &[u8; 32])
                    -> Result<KeyBlock, String> {
    let expanded = suite.cipher.expanded_key_len();
    let iv_len = if suite.cipher.is_cbc() { suite.cipher.block_size() } else { 0 };

    let mut forward = Vec::with_capacity(64);
    forward.extend_from_slice(client_random);
    forward.extend_from_slice(server_random);
    let mut backward = Vec::with_capacity(64);
    backward.extend_from_slice(server_random);
    backward.extend_from_slice(client_random);

    let (client_key, server_key, client_iv, server_iv) =
        if version == Version::SSL30 {
            // SSLv3: a bare MD5, with the randoms the other way round for
            // the server. No label, no PRF.
            let hash = |parts: &[&[u8]]| -> Result<Vec<u8>, String> {
                let mut h = AnyHash::new("md5")?;
                for part in parts {
                    h.update(part);
                }
                Ok(h.digest())
            };
            let client_key = hash(&[&block.client.key, &forward])?;
            let server_key = hash(&[&block.server.key, &backward])?;
            let client_iv = hash(&[&forward])?;
            let server_iv = hash(&[&backward])?;
            (client_key, server_key, client_iv, server_iv)
        } else {
            let client_key = prf(version, suite.prf, &block.client.key,
                                 b"client write key", &forward, expanded)?;
            let server_key = prf(version, suite.prf, &block.server.key,
                                 b"server write key", &forward, expanded)?;
            // The empty secret is not a mistake in the transcription.
            let iv_block = prf(version, suite.prf, &[], b"IV block", &forward,
                               2 * iv_len)?;
            let (client_iv, server_iv) = iv_block.split_at(iv_len);
            (client_key, server_key, client_iv.to_vec(), server_iv.to_vec())
        };

    Ok(KeyBlock {
        client: DirectionKeys {
            mac_key: block.client.mac_key,
            key: client_key[..expanded].to_vec(),
            iv: client_iv[..iv_len].to_vec(),
        },
        server: DirectionKeys {
            mac_key: block.server.mac_key,
            key: server_key[..expanded].to_vec(),
            iv: server_iv[..iv_len].to_vec(),
        },
    })
}

/// Which side a Finished message came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    pub fn finished_label(self) -> &'static [u8] {
        match self {
            Side::Client => b"client finished",
            Side::Server => b"server finished",
        }
    }

    pub fn other(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

/// The two constants that stand in for a label in SSLv3's Finished
/// (RFC 6101 section 5.6.9). They are ASCII - "CLNT" and "SRVR" - but are
/// specified as numbers, and writing them as numbers is what keeps them
/// from being "improved" into a string with a different length.
impl Side {
    pub fn ssl3_sender(self) -> [u8; 4] {
        match self {
            Side::Client => [0x43, 0x4c, 0x4e, 0x54],
            Side::Server => [0x53, 0x52, 0x56, 0x52],
        }
    }
}

/// `PRF(master, label, transcript_hash)[0..verify_data_len]`.
///
/// **The length is the suite's**, not a constant. RFC 5246 7.4.9 makes
/// twelve a default that a cipher suite may override, and RFC 9189
/// 4.2.6 overrides it to 32 for the CTR_OMAC suites. See
/// `BulkCipher::verify_data_len`; a wrong length here is a handshake
/// that works against another copy of itself and gets `bad digest
/// length` from anything else.
pub fn verify_data(version: Version, suite: &crate::tls::suites::CipherSuite,
                   master: &[u8], side: Side, transcript_hash: &[u8])
                   -> Result<Vec<u8>, String> {
    prf(version, suite.prf, master, side.finished_label(), transcript_hash,
        suite.cipher.verify_data_len())
}

/// Compare two verify_data values without returning early.
///
/// The values are not secret - both sides know them - so this is belt and
/// braces. But a verifier that returns on the first differing byte is a
/// habit worth not having, and this one is free.
pub fn verify_data_matches(expected: &[u8], received: &[u8]) -> bool {
    if expected.len() != received.len() || expected.is_empty() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(received.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Whether a key exchange's raw shared value has its leading zero bytes
/// stripped before it becomes the premaster secret.
///
/// **The two families have opposite rules, and both are explicit.**
///
/// Finite-field Diffie-Hellman strips: RFC 5246 section 8.1.2 says the
/// premaster is "the negotiated key Z, with leading zero bytes
/// stripped", and OpenSSL pads Z to the width of the modulus before
/// that happens, so the stripping is real work.
///
/// Elliptic-curve Diffie-Hellman does not: RFC 4492 section 5.10 says
/// of the x coordinate that "leading zeros found in this octet string
/// MUST NOT be truncated". RFC 8422 keeps the sentence and X25519's
/// output is a fixed 32 bytes for the same reason.
///
/// So one line decides it, and it is this one. The server had the DH
/// rule applied to ECDHE, which agrees with itself, agrees with our own
/// client 255 times out of 256, and fails the 256th connection with
/// `bad_record_mac` and nothing to say why. The deliberate-breakage
/// sweep did not catch it either: removing the stripping made the
/// server *correct*, and every test still passed.
pub fn strips_leading_zeros(exchange: KeyExchange) -> bool {
    match exchange {
        KeyExchange::DheRsa | KeyExchange::DheDss
        | KeyExchange::DhRsa | KeyExchange::DhDss
        | KeyExchange::AnonDh => true,
        KeyExchange::EcdheRsa | KeyExchange::EcdheEcdsa
        | KeyExchange::EcdhRsa | KeyExchange::EcdhEcdsa
        | KeyExchange::AnonEcdh => false,
        // These do not have a shared value of this shape at all: the
        // RSA premaster is built rather than agreed, PSK's is assembled
        // from the identity, and GOST's is a wrapped key. Listed rather
        // than swept into a wildcard, so adding an exchange is a
        // compile error here instead of a silent `false`.
        KeyExchange::Rsa | KeyExchange::Psk | KeyExchange::GostVko
        | KeyExchange::GostVko2001 => false,
    }
}

/// The premaster secret from a key exchange's raw shared value.
///
/// One function for both sides, because the rule above is a convention
/// rather than arithmetic: two copies would agree with each other and a
/// third of the world.
pub fn premaster_from_shared(exchange: KeyExchange, shared: Vec<u8>) -> Vec<u8> {
    if strips_leading_zeros(exchange) {
        let start = shared.iter().position(|byte| *byte != 0)
            .unwrap_or(shared.len());
        shared[start..].to_vec()
    } else {
        shared
    }
}

/// Build an RSA premaster secret.
///
/// 48 bytes: the two version bytes the client put in its **ClientHello**,
/// then 46 random. The version is the anti-rollback check from RFC 5246
/// section 7.4.7.1 - a server that negotiated a lower version than the
/// client offered will see the client's real preference here and know the
/// handshake was tampered with.
///
/// The subtlety: it is the *offered* version, not the negotiated one. Using
/// the negotiated version makes the check useless, and some servers notice.
pub fn rsa_premaster(offered_version: Version) -> Result<Vec<u8>, String> {
    let mut premaster = Vec::with_capacity(48);
    premaster.extend_from_slice(&offered_version.to_bytes());
    premaster.extend_from_slice(&crate::random::bytes(46)?);
    Ok(premaster)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::suites;

    /// The two families strip in opposite directions, and the test
    /// shows it by being about the *difference*.
    ///
    /// A test that only asserted "DHE strips" would still pass if ECDHE
    /// stripped too - which is the bug this was written for. So it
    /// takes one shared value with a leading zero and requires the two
    /// rules to disagree about it.
    #[test]
    fn test_only_the_finite_field_exchanges_strip_leading_zeros() {
        let shared = vec![0x00, 0x00, 0x7f, 0x11, 0x22];

        let dhe = premaster_from_shared(KeyExchange::DheRsa, shared.clone());
        let ecdhe = premaster_from_shared(KeyExchange::EcdheRsa, shared.clone());

        assert_eq!(dhe, vec![0x7f, 0x11, 0x22], "RFC 5246 8.1.2");
        assert_eq!(ecdhe, shared, "RFC 4492 5.10: MUST NOT be truncated");
        assert_ne!(dhe, ecdhe,
                   "the two rules agree, so one of them is not being applied");

        // Both families, every variant, so adding a suite cannot quietly
        // pick up the wrong rule.
        for exchange in [KeyExchange::DheRsa, KeyExchange::DheDss,
                         KeyExchange::DhRsa, KeyExchange::DhDss,
                         KeyExchange::AnonDh] {
            assert!(strips_leading_zeros(exchange), "{:?}", exchange);
        }
        for exchange in [KeyExchange::EcdheRsa, KeyExchange::EcdheEcdsa,
                         KeyExchange::EcdhRsa, KeyExchange::EcdhEcdsa,
                         KeyExchange::AnonEcdh] {
            assert!(!strips_leading_zeros(exchange), "{:?}", exchange);
        }

        // A value with no leading zero is untouched by either rule,
        // which is why the mistake survives 255 handshakes in 256.
        let ordinary = vec![0x7f, 0x11, 0x22];
        assert_eq!(premaster_from_shared(KeyExchange::DheRsa, ordinary.clone()),
                   premaster_from_shared(KeyExchange::EcdheRsa, ordinary.clone()));

        // All zeros strips to nothing rather than panicking.
        assert!(premaster_from_shared(KeyExchange::DheRsa,
                                      vec![0, 0, 0]).is_empty());
    }

    fn suite() -> &'static CipherSuite {
        suites::by_code(0x002f).unwrap()     // RSA_WITH_AES_128_CBC_SHA
    }

    fn randoms() -> ([u8; 32], [u8; 32]) {
        let mut client = [0u8; 32];
        let mut server = [0u8; 32];
        for i in 0..32 {
            client[i] = (i * 7 + 1) as u8;
            server[i] = (i * 11 + 3) as u8;
        }
        (client, server)
    }

    /// The two derivations must use the randoms in opposite orders. If they
    /// did not, swapping them would change nothing - so this test works by
    /// showing that it does.
    #[test]
    fn test_the_randoms_are_in_opposite_orders() {
        let (client, server) = randoms();
        let premaster = vec![3u8; 48];

        let master = master_secret(Version::TLS12, MacAlgorithm::Sha256,
                                   &premaster, &client, &server).unwrap();
        let swapped = master_secret(Version::TLS12, MacAlgorithm::Sha256,
                                    &premaster, &server, &client).unwrap();
        assert_ne!(master, swapped);

        let block = key_block(Version::TLS12, suite(), &master, &client, &server).unwrap();
        let block_swapped = key_block(Version::TLS12, suite(), &master,
                                      &server, &client).unwrap();
        assert_ne!(block, block_swapped);
    }

    /// A PRF that is not a hash is refused rather than quietly replaced
    /// by SHA-256.
    ///
    /// What was wrong: `Transcript::new` did `hash_name().unwrap_or
    /// ("sha256")`, so a suite whose `prf` slot held `Aead` or `Gost` -
    /// a one-token slip in a sixty-row table - got a SHA-256 transcript
    /// and a Finished nobody else computes, with no error anywhere. No
    /// test could reach it because every row's `prf` is a hash, which is
    /// also why the slip would go unnoticed. The function already
    /// returned `Result`; it now uses it.
    #[test]
    fn test_a_prf_without_a_hash_is_refused_as_a_transcript() {
        for prf in [MacAlgorithm::Aead, MacAlgorithm::Gost] {
            assert!(prf.hash_name().is_none(), "{:?}", prf);
            let error = Transcript::new(Version::TLS12, prf)
                .err().unwrap_or_else(|| panic!("{:?} was accepted", prf));
            assert!(error.contains("not a hash"), "{}", error);
        }
        // And every suite in the table still gets a transcript, which is
        // what says no row was broken by the refusal.
        for code in suites::Selection::all().codes() {
            let suite = suites::by_code(*code).unwrap();
            Transcript::new(suite.min_version, suite.prf)
                .unwrap_or_else(|e| panic!("{}: {}", suite.name, e));
        }
    }

    /// `{:?}` on a key block prints lengths and nothing else.
    ///
    /// What was wrong: `DirectionKeys` and `KeyBlock` derived `Debug`,
    /// while every other secret-carrying type here hand-writes a
    /// redacting one. Any `{:?}` on an error path, a log line or a
    /// failing `assert_eq!` that touched a key block printed the MAC key,
    /// the encryption key and the IV of a live connection. Nothing
    /// caught it because no test formats a key block, and the derived
    /// output is well formed. The bytes are distinctive so that a
    /// derived `Debug` cannot pass by printing them in some other base.
    #[test]
    fn test_a_key_block_prints_no_key_material() {
        let suite = suites::by_name("ECDHE-RSA-AES128-SHA").unwrap();
        let master = vec![0xA7; 48];
        let block = key_block(Version::TLS12, suite, &master, &[0x5C; 32],
                              &[0x36; 32]).unwrap();
        let printed = format!("{:?}", block);
        assert!(printed.contains("redacted"), "{}", printed);
        for keys in [&block.client, &block.server] {
            for secret in [&keys.mac_key, &keys.key, &keys.iv] {
                if secret.is_empty() {
                    continue;
                }
                let hex: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
                let decimal = format!("{:?}", secret);
                assert!(!printed.contains(&hex[..8]), "{}", printed);
                assert!(!printed.contains(&decimal[1..12]), "{}", printed);
            }
        }
        // The lengths are still there, which is what a log line needs.
        assert!(printed.contains("20 byte mac_key"), "{}", printed);
        assert!(printed.contains("16 byte key"), "{}", printed);
    }

    #[test]
    fn test_key_block_sizes() {
        let (client, server) = randoms();
        let master = vec![5u8; 48];

        // AES-128 with SHA-1: 20 byte MAC keys, 16 byte keys.
        let block = key_block(Version::TLS12, suite(), &master, &client, &server).unwrap();
        assert_eq!(block.client.mac_key.len(), 20);
        assert_eq!(block.server.mac_key.len(), 20);
        assert_eq!(block.client.key.len(), 16);
        assert_eq!(block.server.key.len(), 16);
        // TLS 1.2 has an explicit IV per record, so none is derived here.
        assert!(block.client.iv.is_empty());

        // TLS 1.0 chains the IV, so it comes from the key block.
        let block = key_block(Version::TLS10, suite(), &master, &client, &server).unwrap();
        assert_eq!(block.client.iv.len(), 16);
        assert_eq!(block.server.iv.len(), 16);

        // The two directions must differ. A key block split wrongly can
        // easily give both sides the same material.
        assert_ne!(block.client.key, block.server.key);
        assert_ne!(block.client.mac_key, block.server.mac_key);
        assert_ne!(block.client.iv, block.server.iv);
    }

    /// The key block is one PRF output split in a fixed order. This checks
    /// the split against the raw PRF, so a reordering is caught.
    #[test]
    fn test_the_key_block_split_order() {
        let (client, server) = randoms();
        let master = vec![9u8; 48];
        let block = key_block(Version::TLS10, suite(), &master, &client, &server).unwrap();

        let mut seed = Vec::new();
        seed.extend_from_slice(&server);      // server first, deliberately
        seed.extend_from_slice(&client);
        // TLS 1.0's PRF, because that is the version this block is for -
        // the PRF is fixed by the version before 1.2, not by the suite.
        // `tls12_prf` here is the plausible wrong answer, and the test
        // below is what refuses it.
        let raw = kdf::tls10_prf(&master, b"key expansion", &seed,
                                 2 * (20 + 16 + 16));

        // RFC 5246 6.3: both MACs, both keys, both IVs, client first.
        assert_eq!(block.client.mac_key, raw[0..20]);
        assert_eq!(block.server.mac_key, raw[20..40]);
        assert_eq!(block.client.key, raw[40..56]);
        assert_eq!(block.server.key, raw[56..72]);
        assert_eq!(block.client.iv, raw[72..88]);
        assert_eq!(block.server.iv, raw[88..104]);
    }

    #[test]
    fn test_verify_data() {
        use crate::tls::suites;
        let master = vec![1u8; 48];
        let transcript = vec![2u8; 32];
        let suite = suites::by_name("TLS_RSA_WITH_AES_128_CBC_SHA256").unwrap();

        let client = verify_data(Version::TLS12, suite, &master,
                                 Side::Client, &transcript).unwrap();
        let server = verify_data(Version::TLS12, suite, &master,
                                 Side::Server, &transcript).unwrap();

        assert_eq!(client.len(), VERIFY_DATA_LEN);
        // The labels differ, so the two must differ - otherwise a Finished
        // could be reflected back at its sender.
        assert_ne!(client, server);

        assert!(verify_data_matches(&client, &client));
        assert!(!verify_data_matches(&client, &server));
        assert!(!verify_data_matches(&client, &client[..11]));
        assert!(!verify_data_matches(&[], &[]));
    }

    /// **RFC 9189 section 4.2.6: 32 for CTR_OMAC, 12 for CNT_IMIT.**
    ///
    /// Twelve was a constant here, because RFC 5246 7.4.9 makes it the
    /// default and nothing this library had implemented overrode it.
    /// The CTR_OMAC suites do.
    ///
    /// Nothing offline could see it: both ends of a handshake between
    /// two copies of this library truncate to the same length and agree
    /// perfectly, which is what `tests/test_gost_handshake.rs` was
    /// doing. A real GOST server answers `bad digest length` and
    /// nothing else, and it took building OpenSSL's GOST engine and
    /// running `s_server` on loopback to hear it.
    #[test]
    fn test_the_gost_suites_verify_data_lengths() {
        use crate::tls::suites;
        let master = vec![3u8; 48];
        let transcript = vec![4u8; 32];

        for (name, expected) in [
            ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", 32),
            ("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", 32),
            ("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", 12),
            ("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT_LEGACY", 12),
            ("TLS_GOSTR341001_WITH_28147_CNT_IMIT", 12),
            // And the ordinary suites are untouched.
            ("TLS_RSA_WITH_AES_128_CBC_SHA256", 12),
        ] {
            let suite = suites::by_name(name).unwrap();
            assert_eq!(suite.cipher.verify_data_len(), expected, "{name}");
            let produced = verify_data(Version::TLS12, suite, &master,
                                       Side::Client, &transcript).unwrap();
            assert_eq!(produced.len(), expected, "{name}");
        }

        // The two lengths are not a truncation of one another in the
        // sense that matters: the longer one must *start* with the
        // shorter, since both are the same PRF stream - so a peer
        // comparing 12 bytes of a 32 byte value would agree. That is
        // why the length has to be right rather than merely checked.
        let long = suites::by_name(
            "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC").unwrap();
        let short = suites::by_name(
            "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT").unwrap();
        let a = verify_data(Version::TLS12, long, &master, Side::Client,
                            &transcript).unwrap();
        let b = verify_data(Version::TLS12, short, &master, Side::Client,
                            &transcript).unwrap();
        assert_eq!(&a[..12], &b[..], "the PRF stream differs, not the length");
    }

    #[test]
    fn test_transcript_hashing() {
        let mut transcript = Transcript::new(Version::TLS12, MacAlgorithm::Sha256).unwrap();
        transcript.update(b"first message");
        let after_one = transcript.hash();
        transcript.update(b"second message");
        let after_two = transcript.hash();

        assert_eq!(after_one.len(), 32);
        assert_ne!(after_one, after_two);

        // hash() must not consume: asking twice gives the same answer.
        assert_eq!(transcript.hash(), after_two);

        // It is a hash of the concatenation, which is what both sides
        // compute independently.
        let mut direct = AnyHash::new("sha256").unwrap();
        direct.update(b"first messagesecond message");
        assert_eq!(after_two, direct.digest());

        // Before TLS 1.2 it is MD5 and SHA-1 over the same bytes,
        // concatenated - 36 bytes, not a hash of a hash.
        let mut old = Transcript::new(Version::TLS10, MacAlgorithm::Sha256).unwrap();
        old.update(b"first message");
        assert_eq!(old.hash().len(), 16 + 20);
    }

    #[test]
    fn test_extended_master_secret_differs() {
        let (client, server) = randoms();
        let premaster = vec![4u8; 48];
        let session_hash = vec![6u8; 32];

        let ordinary = master_secret(Version::TLS12, MacAlgorithm::Sha256,
                                     &premaster, &client, &server).unwrap();
        let extended = extended_master_secret(Version::TLS12, MacAlgorithm::Sha256,
                                              &premaster, &session_hash).unwrap();
        assert_eq!(extended.len(), MASTER_SECRET_LEN);
        assert_ne!(ordinary, extended);

        // And it depends on the transcript, which is the whole point: two
        // connections sharing a premaster cannot share a master secret.
        let other = extended_master_secret(Version::TLS12, MacAlgorithm::Sha256,
                                           &premaster, &[7u8; 32]).unwrap();
        assert_ne!(extended, other);
    }

    /// The premaster carries the version the client *offered*, not the one
    /// that was negotiated. Using the negotiated version makes the
    /// anti-rollback check useless, and some servers notice.
    #[test]
    fn test_rsa_premaster_shape() {
        let premaster = rsa_premaster(Version::TLS12).unwrap();
        assert_eq!(premaster.len(), 48);
        assert_eq!(&premaster[..2], &[3, 3]);

        // The other 46 bytes are random, so two are different.
        let other = rsa_premaster(Version::TLS12).unwrap();
        assert_ne!(premaster[2..], other[2..]);

        // An old server negotiating TLS 1.0 still sees what we offered.
        let offered_high = rsa_premaster(Version::TLS12).unwrap();
        assert_eq!(&offered_high[..2], &Version::TLS12.to_bytes());
    }
    /// RFC 9189 Appendix A.1.3.1's master secret and key block.
    ///
    /// The lengths in this block cannot be checked any other way. The
    /// OMAC key is 32 bytes because RFC 9189 section 4.3.2 says so and
    /// not because any digest is that long, and the IV is four bytes
    /// for Magma against eight for Kuznyechik - so the block is 136
    /// bytes here and 144 there. Get any of them wrong and every later
    /// field is shifted, which shows up as a Finished that does not
    /// match and says nothing about why.
    ///
    /// The example uses the extended master secret (RFC 7627), which is
    /// why the transcript hash rather than the two randoms feeds the
    /// PRF.
    #[test]
    fn test_rfc_9189_magma_key_block() {
        fn unhex(text: &str) -> Vec<u8> {
            let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            (0..text.len()).step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        }
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }

        let suite = crate::tls::suites::by_code(0xc101).unwrap();
        assert_eq!(suite.name, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC");

        let premaster = unhex("A5576CE7924A24F58113808DBD9EF856\
                               F5BDC3B183CE5DADCA36A53AA077651D");
        let session_hash = unhex("7E1F59D3649DB60900EA4F8A585A657A\
                                  9277B30450584CF54351198CDEA30C49");

        let master = extended_master_secret(Version::TLS12, suite.prf,
                                            &premaster, &session_hash).unwrap();
        assert_eq!(hex(&master), "fdd27cb404ad4e4449684f7c5590e9e7\
                                  02ef4101933b5277a4a96df500b07cc3\
                                  324fd8a6d907cbb03df3fb331f1c4d0c");

        let client_random: [u8; 32] = unhex(
            "933EA21EC3802A561550EC78D6ED51AC2439D7E749C31BC3A3456165889684CA")
            .try_into().unwrap();
        let server_random: [u8; 32] = unhex(
            "933EA21E49C31BC3A3456165889684CAA5576CE7924A24F58113808DBD9EF856")
            .try_into().unwrap();

        let keys = key_block(Version::TLS12, suite, &master,
                             &client_random, &server_random).unwrap();

        // The RFC prints the block as one string in the client's order:
        // K_write_MAC | K_read_MAC | K_write_ENC | K_read_ENC |
        // IV_write | IV_read - which is client-then-server for each, the
        // same order `key_block` takes them in.
        let whole = unhex("DD4E1017E3091FFD867565 8A780090093BBE69ECA693315C\
                           A85BE0A6143DC9F81D64D0 23465F8BEA17F812F8C2D8BFC0\
                           D9BBABA7B4DFD3A17CE0E1 3B2D6365F3FC8B3459CF54FE44\
                           9A0407645373080075103 2559D07B6C4EAC675 4871BC978A\
                           B90E2AEE987714BBD8F757 AEF784FF2447B3942EB43E2635\
                           731C4C2822D02D792B6A81 3F93EDA6FA");
        assert_eq!(whole.len(), 2 * (32 + 32 + 4),
                   "the key block is two MAC keys, two 32 byte keys and two \
                    four byte IVs");

        assert_eq!(hex(&keys.client.mac_key), hex(&whole[..32]));
        assert_eq!(hex(&keys.server.mac_key), hex(&whole[32..64]));
        assert_eq!(hex(&keys.client.key), hex(&whole[64..96]));
        assert_eq!(hex(&keys.server.key), hex(&whole[96..128]));
        assert_eq!(hex(&keys.client.iv), hex(&whole[128..132]));
        assert_eq!(hex(&keys.server.iv), hex(&whole[132..136]));

        // Kuznyechik takes the same lengths except for the IV, which is
        // eight bytes - so its block is 144 and every field after the
        // keys sits somewhere else.
        let kuznyechik = crate::tls::suites::by_code(0xc100).unwrap();
        let other = key_block(Version::TLS12, kuznyechik, &master,
                              &client_random, &server_random).unwrap();
        assert_eq!(other.client.iv.len(), 8);
        assert_eq!(other.client.mac_key.len(), 32);
        assert_eq!(other.client.key.len(), 32);
    }
}
