/*
The CNT_IMIT key exchange from RFC 9189 section 4.2.4.2.

The same shape as the CTR_OMAC one - an ephemeral key agreed against the
server's certificate key, used to wrap a 32 byte preliminary secret -
and a different algorithm at every step:

    H     = HASH(r_c | r_s)
    UKM   = H[1..8]
    R     = VKO_256(d_eph, Q_s, int(UKM))
    K_EXP = CPDivers(UKM, R)                       RFC 4357 section 6.5
    PSExp = KExp28147(PS, K_EXP, H[1..8])          RFC 9189 section 8.2.2

and the message is RFC 4490's `TLSGostKeyTransportBlob` rather than the
much simpler `GostKeyTransport`.

That is the RFC's pairing, a 2012 suite on a 2012 key. A server may also
put these suites on a GOST R 34.10-2001 key, and then the hash stays the
suite's while the VKO and the S-box become the key's; `Transport` below
carries the two separately.

## Which tables

Two tables run underneath: the GOST 28147-89 S-box of CPDivers and the
key wrap, and - for a 2001 key - the GOST R 34.11-94 parameter set VKO
hashes its point under. **The message names the first** (its
`encryptionParamSet`, RFC 4490 section 4.2: "used for all encryption
operations"), so a server unwraps under whatever the message says.

What a *client* puts there is a choice. RFC 4357 and gost-engine take
both tables from the key's generation alone - CryptoPro-A or `param-Z`,
and CryptoPro's hash parameters - and gost-engine's certificates carry
the CryptoPro `digestParamSet` and no `encryptionParamSet`. Deployed
servers exist that take both from the certificate instead: the
`encryptionParamSet` and `digestParamSet` after the curve in
`GostR3410-2001-PublicKeyParameters`, often an organisation's own sets
registered with `registry::register`. `Tables::for_key` takes each from
the certificate when it is there and keeps the generation's default when
it is not, which gives gost-engine's certificates exactly the defaults.

Four things here are the *opposite* of the CTR_OMAC path, and each is
silent when confused with it:

  * **`int(UKM)` is little endian.** RFC 9189 section 3 defines `int`
    (little) and `INT` (big) and uses both; `KEG` takes `INT(H[1..16])`
    and `KEG_28147` takes `int(H[1..8])`. So this one agrees with VKO's
    own wire convention and the other does not.
  * **The UKM is eight bytes, not sixteen**, and it is also the IV.
  * **VKO_256 whatever the curve.** RFC 9189 section 8.3.2 has no 512
    branch: a 512 bit key still hashes its shared point with
    Streebog-256 here, which is why the RFC's own example uses a 512 bit
    curve - to make the point that the digest does not follow the key.
  * **There is no KDF.** `KEG` runs the tree KDF for 256 bit keys;
    `KEG_28147` runs CryptoPro's diversification instead, which is a
    different construction entirely.

## CPDivers

RFC 4357 section 6.5, eight rounds of:

    S = (sum of the key's words where this UKM byte's bit is set)
      | (sum of the words where it is clear)
    K = CFB-Encrypt(key = K, iv = S, plaintext = K)

The words are read **little endian**, each sum is modulo 2^32, and the
two halves of `S` are written little endian in that order. It is
deterministic under any reading, and the RFC has no test vector - RFC
9189 Appendix A.2.2 prints `K_EXP`, which is what pins it here.

## The message

    TLSGostKeyTransportBlob ::= SEQUENCE { keyBlob GostR3410-KeyTransport }
    GostR3410-KeyTransport ::= SEQUENCE {
        sessionEncryptedKey  Gost28147-89-EncryptedKey,
        transportParameters  [0] IMPLICIT GostR3410-TransportParameters OPTIONAL }
    Gost28147-89-EncryptedKey ::= SEQUENCE {
        encryptedKey  Gost28147-89-Key,
        maskKey       [0] IMPLICIT Gost28147-89-Key OPTIONAL,
        macKey        Gost28147-89-MAC }
    GostR3410-TransportParameters ::= SEQUENCE {
        encryptionParamSet  OBJECT IDENTIFIER,
        ephemeralPublicKey  [0] IMPLICIT SubjectPublicKeyInfo OPTIONAL,
        ukm                 OCTET STRING }

The tagging is **implicit** throughout, so `[0]` replaces the tag of
what it wraps rather than nesting a second one - `A0` holding a
SubjectPublicKeyInfo's *fields*, not holding a SEQUENCE holding them.
Explicit tagging would produce a message of a different length that
parses cleanly as something else.

`maskKey` is absent and the server ignores it; `ukm` here is the same
eight bytes as the IV, and unlike `GostKeyTransport`'s `ukm` field it is
**not** ignorable - `KImp28147` checks the IV it carries against the one
it derived.
*/

use crate::asn1::{tag, Reader, Tag, Writer};
use crate::bignum::BigUint;
use crate::block_ciphers::gost::GostCrypto;
use crate::block_ciphers::modes::CfbState;
use crate::block_ciphers::BlockCipher;
use crate::ec::{Curve, Point};
use crate::tls::gost_kex::{self, PRELIMINARY_SECRET_LEN};
use crate::tls::record_cnt_imit::{gost28147imit, SBOX, SBOX_2001, TAG_LEN};
use crate::x509::oids;
use crate::hash_functions::gost94::{CRYPTOPRO_PARAM_SET, TEST_PARAM_SET};

/// `UKM = H[1..8]`, and the same bytes are `KExp28147`'s IV.
pub const UKM_LEN: usize = 8;

/// `IV | CEK_ENC | CEK_MAC`: 8 + 32 + 4.
pub const WRAPPED_LEN: usize = UKM_LEN + 32 + TAG_LEN;

// ----------------------------------------------------------- CPDivers ---

/// The CryptoPro KEK diversification algorithm, RFC 4357 section 6.5.
pub fn cp_divers(ukm: &[u8], key: &[u8], sbox: &str) -> Result<Vec<u8>, String> {
    if ukm.len() != UKM_LEN {
        return Err(format!("CPDivers takes an {} byte UKM; got {}.",
                           UKM_LEN, ukm.len()));
    }
    if key.len() != 32 {
        return Err(format!("CPDivers takes a 32 byte key; got {}.", key.len()));
    }

    let mut current = key.to_vec();
    for byte in ukm {
        // The key is eight 32 bit words, read little endian. Each word
        // joins one of two sums depending on the corresponding bit of
        // this UKM byte - bit 0 selects word 0, so the mask walks up
        // from 1 rather than down from 0x80.
        let (mut set, mut clear) = (0u32, 0u32);
        for (index, word) in current.chunks(4).enumerate() {
            let value = u32::from_le_bytes(word.try_into().unwrap());
            if byte & (1 << index) != 0 {
                set = set.wrapping_add(value);
            } else {
                clear = clear.wrapping_add(value);
            }
        }
        let mut s = set.to_le_bytes().to_vec();
        s.extend_from_slice(&clear.to_le_bytes());

        // The key encrypts itself, under itself, in CFB with S as the
        // IV. All three being the same value is not a simplification -
        // it is what the RFC says.
        let mut cipher = GostCrypto::new(&current, sbox)?;
        let mut state = CfbState::new(&mut cipher, &s, false)?;
        let mut next = current.clone();
        state.apply(&mut cipher, &mut next)?;
        current = next;
    }
    Ok(current)
}

/// `KEG_28147(d, Q, H)`, RFC 9189 section 8.3.2.
pub fn keg_28147(curve: &Curve, private: &BigUint, peer: &Point, h: &[u8])
                 -> Result<Vec<u8>, String> {
    if h.len() != 32 {
        return Err(format!(
            "KEG_28147's H is the 32 byte Streebog-256 of the two randoms; \
             got {}.", h.len()));
    }
    keg_2012(curve, private, peer, &h[..UKM_LEN])
}

/// `KEG_28147` from its UKM rather than the digest it is cut from, so
/// that a suite whose UKM comes from another hash can reach it.
fn keg_2012(curve: &Curve, private: &BigUint, peer: &Point, ukm: &[u8])
            -> Result<Vec<u8>, String> {
    keg_2012_with(curve, private, peer, ukm, SBOX)
}

/// `keg_2012` with CPDivers under another S-box.
fn keg_2012_with(curve: &Curve, private: &BigUint, peer: &Point, ukm: &[u8], sbox: &str)
                 -> Result<Vec<u8>, String> {
    if ukm.len() != UKM_LEN {
        return Err(format!("The UKM is {} bytes; got {}.", UKM_LEN, ukm.len()));
    }
    // `int` - **little endian**, which is also VKO's own wire
    // convention, so the byte string goes in as it stands. `KEG` above
    // takes `INT`, big endian, from a longer prefix.
    //
    // And VKO_**256** whatever the curve: section 8.3.2 has no 512
    // branch, so a 512 bit key still hashes with Streebog-256 here.
    // `AsSpecified`, for the reason in `gost_kex::keg`: RFC 7836's
    // `m/q` term is in gost-engine's answer too, which was established
    // by measuring the engine rather than by reading its source. On a
    // cofactor four curve the two readings are different points, so
    // this is the difference between a shared key and a private one.
    let shared = curve.vko_using(private, peer, ukm, 256,
                                 crate::ec::vko::Cofactor::AsSpecified)?;
    cp_divers(ukm, &shared, sbox)
}

/// The 2001 suite's key derivation: VKO GOST R 34.10-2001 and the same
/// CryptoPro diversification over it.
///
/// draft-chudov-cryptopro-cptls section 3.6 does not name a
/// construction - it says "VKO GOST R 34.10-2001 to produce KEK, then
/// CryptoPro Key Wrap" - and RFC 4357 section 6.3 step 2 is the
/// diversification. So this is `KEG_28147`'s shape with three things
/// changed: the hash over the randoms, the VKO, and the S-box
/// everything underneath uses.
pub fn keg_2001(curve: &Curve, private: &BigUint, peer: &Point, ukm: &[u8])
                -> Result<Vec<u8>, String> {
    keg_2001_with(curve, private, peer, ukm, SBOX_2001, CRYPTOPRO_PARAM_SET)
}

/// `keg_2001` with CPDivers under another S-box and VKO's point hashed
/// under another GOST R 34.11-94 parameter set.
pub fn keg_2001_with(curve: &Curve, private: &BigUint, peer: &Point, ukm: &[u8],
                     sbox: &str, digest_param_set: &str) -> Result<Vec<u8>, String> {
    if ukm.len() != UKM_LEN {
        return Err(format!(
            "The 2001 suite's UKM is {} bytes, the first half of a GOST R \
             34.11-94 digest; got {}.", UKM_LEN, ukm.len()));
    }
    let shared = curve.vko_2001_with(private, peer, ukm, digest_param_set)?;
    cp_divers(ukm, &shared, sbox)
}

/// `shared_ukm`, draft-chudov-cryptopro-cptls section 3.6: the first
/// eight bytes of the GOST R 34.11-94 digest of the two randoms.
///
/// **A different hash from RFC 9189's**, which takes Streebog-256 of
/// the same two values. Both are 32 bytes and both are truncated to
/// eight, so the wrong one is a UKM of the right shape that derives a
/// different key - and the failure is a MAC check inside the key
/// transport blob, which reads as a corrupt message rather than as a
/// wrong hash.
pub fn shared_ukm_2001(client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
    use crate::hash_functions::HashFunction;
    let mut input = client_random.to_vec();
    input.extend_from_slice(server_random);
    let digest = crate::hash_functions::gost94::Gost94::new(&input).digest();
    digest[..UKM_LEN].to_vec()
}

// ------------------------------------------------- KExp28147/KImp28147 ---

/// `KExp28147(S, K, IV)`, RFC 9189 section 8.2.2.
///
/// Note the order against `KExp15`: here the secret is encrypted in
/// **ECB** and the MAC is computed over the *plaintext*, so the two are
/// independent rather than chained. `KExp15` MACs `IV | S` and then
/// encrypts `S | MAC` together.
pub fn kexp28147(secret: &[u8], key: &[u8], iv: &[u8], sbox: &str)
                 -> Result<Vec<u8>, String> {
    if secret.len() != PRELIMINARY_SECRET_LEN {
        return Err(format!("KExp28147 exports a {} byte secret; got {}.",
                           PRELIMINARY_SECRET_LEN, secret.len()));
    }
    if iv.len() != UKM_LEN {
        return Err(format!("KExp28147's IV is {} bytes; got {}.",
                           UKM_LEN, iv.len()));
    }
    let mac = gost28147imit(iv, key, secret, sbox)?;

    let mut cipher = GostCrypto::new(key, sbox)?;
    let mut encrypted = Vec::with_capacity(secret.len());
    for block in secret.chunks(8) {
        cipher.block_encrypt(block, &mut encrypted);
    }

    let mut out = Vec::with_capacity(WRAPPED_LEN);
    out.extend_from_slice(iv);
    out.extend_from_slice(&encrypted);
    out.extend_from_slice(&mac);
    Ok(out)
}

/// `KImp28147(SExp, K, IV)`, RFC 9189 section 8.2.2.
pub fn kimp28147(wrapped: &[u8], key: &[u8], iv: &[u8], sbox: &str)
                 -> Result<Vec<u8>, String> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(format!("A wrapped 28147 secret is {} bytes; got {}.",
                           WRAPPED_LEN, wrapped.len()));
    }
    // Step 2 of the RFC: the IV carried with the wrapping must be the
    // one derived from the handshake. Unlike `GostKeyTransport`'s `ukm`
    // field, this one is not ignorable - it is inside the MAC.
    if wrapped[..UKM_LEN] != *iv {
        return Err("The wrapped secret carries a different IV from the one \
                    the handshake derived.".to_string());
    }

    let mut cipher = GostCrypto::new(key, sbox)?;
    let mut secret = Vec::with_capacity(32);
    for block in wrapped[UKM_LEN..UKM_LEN + 32].chunks(8) {
        cipher.block_decrypt(block, &mut secret);
    }

    let expected = gost28147imit(iv, key, &secret, sbox)?;
    let received = &wrapped[UKM_LEN + 32..];
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(received.iter()) {
        difference |= a ^ b;
    }
    if difference != 0 || expected.len() != received.len() {
        return Err("The wrapped secret did not authenticate.".to_string());
    }
    Ok(secret)
}

// --------------------------------------------- TLSGostKeyTransportBlob ---

/// The ClientKeyExchange body for CNT_IMIT.
pub struct KeyTransportBlob {
    pub encrypted: Vec<u8>,
    pub mac: Vec<u8>,
    /// The S-box parameter set, `id-tc26-gost-28147-param-Z` for this
    /// suite (RFC 9189 section 4.3.1).
    pub encryption_param_set: Vec<u8>,
    /// The ephemeral public key's `SubjectPublicKeyInfo`, whole - the
    /// `[0]` wrapper is implicit, so only its *fields* go on the wire
    /// and `encode` strips the outer SEQUENCE.
    pub ephemeral: Vec<u8>,
    pub ukm: Vec<u8>,
}

/// Strip a DER SEQUENCE's header, leaving its fields.
///
/// Needed because `[0] IMPLICIT SubjectPublicKeyInfo` replaces the
/// SEQUENCE's tag rather than nesting inside it. Writing the SEQUENCE
/// whole under an `A0` is explicit tagging, which is a different
/// message that parses cleanly as something else.
fn sequence_contents(der: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(der);
    let inner = reader.read_tagged(Tag::sequence())?;
    reader.finish()?;
    Ok(inner.to_vec())
}

impl KeyTransportBlob {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let fields = sequence_contents(&self.ephemeral)?;
        let mut writer = Writer::new();
        writer.write_sequence(|blob| {
            blob.write_sequence(|transport| {
                transport.write_sequence(|key| {
                    key.write_octet_string(&self.encrypted);
                    // `maskKey` is optional and absent.
                    key.write_octet_string(&self.mac);
                });
                transport.write_constructed(Tag::context(0, true), |params| {
                    params.write_oid(&self.encryption_param_set);
                    params.write_constructed(Tag::context(0, true),
                                             |spki| spki.write_raw(&fields));
                    params.write_octet_string(&self.ukm);
                });
            });
        });
        Ok(writer.finish())
    }

    pub fn parse(der: &[u8]) -> Result<KeyTransportBlob, String> {
        let mut outer = Reader::new(der);
        let mut blob = outer.read_sequence()?;
        outer.finish()?;
        let mut transport = blob.read_sequence()?;
        blob.finish()?;

        let mut key = transport.read_sequence()?;
        let encrypted = key.read_tagged(Tag::universal(tag::OCTET_STRING))?.to_vec();
        let mut mac = key.read_tagged(Tag::universal(tag::OCTET_STRING))?.to_vec();
        if !key.is_empty() {
            // Two OCTET STRINGs and another: the first was `maskKey`,
            // which is `[0] IMPLICIT` - so it would have arrived tagged
            // A0 and not as an OCTET STRING at all. Anything left here
            // is a field we do not understand.
            return Err("Unexpected field in Gost28147-89-EncryptedKey.".to_string());
        }
        if mac.len() != TAG_LEN {
            return Err(format!("The wrapping's MAC is {} bytes, not {}.",
                               mac.len(), TAG_LEN));
        }
        mac.truncate(TAG_LEN);

        let mut params = transport.read_constructed(Tag::context(0, true))?;
        transport.finish()?;
        let encryption_param_set =
            params.read_tagged(Tag::universal(tag::OID))?.to_vec();
        let fields = params.read_constructed(Tag::context(0, true))?
                           .remaining().to_vec();
        let ukm = params.read_tagged(Tag::universal(tag::OCTET_STRING))?.to_vec();
        params.finish()?;

        // Put the SEQUENCE header back, so the result is a whole
        // SubjectPublicKeyInfo that `gost_kex::decode_public_key` can
        // read - the implicit tag is a wire detail and not something to
        // propagate into every caller.
        let mut writer = Writer::new();
        writer.write_constructed(Tag::sequence(), |w| w.write_raw(&fields));

        Ok(KeyTransportBlob { encrypted, mac, encryption_param_set,
                              ephemeral: writer.finish(), ukm })
    }
}

// ------------------------------------------- which algorithm from where ---

/// Which hash of `r_c | r_s` gives the UKM. **The suite decides it.**
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UkmHash {
    /// GOST R 34.11-94, for `TLS_GOSTR341001_WITH_28147_CNT_IMIT`.
    Gost94,
    /// Streebog-256, for the two GOST R 34.10-2012 CNT_IMIT suites.
    Streebog256,
}

/// Which GOST R 34.10 the server's certificate key is. **The key
/// decides** the VKO and the S-box everything underneath runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyGeneration {
    /// GOST R 34.10-2001: VKO GOST R 34.10-2001 and CryptoPro-A.
    Gost2001,
    /// GOST R 34.10-2012, either size: VKO_256 and `param-Z`.
    Gost2012,
}

/// How one CNT_IMIT ClientKeyExchange is built: the UKM's hash from the
/// suite, and the VKO and the S-box from the server's key.
///
/// **Two inputs rather than one**, because a server can pair the suites
/// and the keys across generations. OpenSSL offers
/// `GOST2012-GOST8912-GOST8912` and `LEGACY-GOST2012-GOST8912-GOST8912`
/// on a GOST R 34.10-2001 certificate - their authentication is
/// `aGOST12|aGOST01` - and then its client hashes the randoms with
/// Streebog-256 because of the suite and runs gost-engine's VKO GOST R
/// 34.10-2001 over CryptoPro-A because of the key. A client that took
/// all three from the suite derived a key the server could not, and one
/// that took all three from the key sent a UKM that was not the hash the
/// suite names. `tests/test_gost_transcript.rs` holds both pairings as
/// the engine's own handshakes and unwraps them under the server's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transport {
    pub ukm_hash: UkmHash,
    pub key: KeyGeneration,
}

impl Transport {
    /// The 0xC102 and 0xFF85 suites on a GOST R 34.10-2012 key: RFC 9189
    /// section 8.3.2's `KEG_28147` exactly.
    pub const RFC_9189: Transport = Transport { ukm_hash: UkmHash::Streebog256,
                                                key: KeyGeneration::Gost2012 };
    /// The 0x0081 suite on its own key generation.
    pub const GOST_2001: Transport = Transport { ukm_hash: UkmHash::Gost94,
                                                 key: KeyGeneration::Gost2001 };

    /// The transport for a CNT_IMIT suite and the server's key.
    ///
    /// `Err` for the pairing no implementation makes: the 2001 suite on a
    /// GOST R 34.10-2012 key. OpenSSL's server will not choose it - the
    /// suite authenticates with `aGOST01` alone - and its client refuses
    /// it with "wrong certificate type", so there is no reference for
    /// which VKO such a server would expect.
    pub fn for_suite(suite_is_2001: bool, key: KeyGeneration)
                     -> Result<Transport, String> {
        match (suite_is_2001, key) {
            (true, KeyGeneration::Gost2001) => Ok(Transport::GOST_2001),
            (true, KeyGeneration::Gost2012) => Err(
                "TLS_GOSTR341001_WITH_28147_CNT_IMIT needs a GOST R 34.10-2001 \
                 key; neither OpenSSL nor gost-engine pairs it with a 2012 one, \
                 so there is nothing to say which VKO it would take."
                    .to_string()),
            (false, key) => Ok(Transport { ukm_hash: UkmHash::Streebog256, key }),
        }
    }

    /// The UKM: the first eight bytes of the suite's hash of the randoms.
    pub fn ukm(&self, client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
        match self.ukm_hash {
            UkmHash::Gost94 => shared_ukm_2001(client_random, server_random),
            UkmHash::Streebog256 =>
                gost_kex::keg_hash(client_random, server_random)[..UKM_LEN].to_vec(),
        }
    }

    /// The default S-box: CryptoPro-A for a 2001 key, `param-Z` for a
    /// 2012 one - `Tables::defaults`, which a key can override.
    pub fn sbox(&self) -> &'static str {
        match self.key {
            KeyGeneration::Gost2001 => SBOX_2001,
            KeyGeneration::Gost2012 => SBOX,
        }
    }

    /// The default S-box's OID, which the blob names when the key does
    /// not name another.
    pub fn encryption_param_set(&self) -> &'static [u8] {
        match self.key {
            KeyGeneration::Gost2001 => oids::GOST_28147_CRYPTOPRO_A,
            KeyGeneration::Gost2012 => oids::GOST_28147_PARAM_Z,
        }
    }

    /// The key encryption key: the key's VKO under this UKM, then
    /// CryptoPro's diversification under the key's S-box.
    pub fn kek(&self, curve: &Curve, private: &BigUint, peer: &Point, ukm: &[u8])
               -> Result<Vec<u8>, String> {
        self.kek_with(&Tables::defaults(self.key), curve, private, peer, ukm)
    }

    /// `kek` under the given tables.
    pub fn kek_with(&self, tables: &Tables, curve: &Curve, private: &BigUint, peer: &Point,
                    ukm: &[u8]) -> Result<Vec<u8>, String> {
        match self.key {
            KeyGeneration::Gost2001 =>
                keg_2001_with(curve, private, peer, ukm, &tables.sbox, &tables.vko_digest),
            KeyGeneration::Gost2012 => keg_2012_with(curve, private, peer, ukm, &tables.sbox),
        }
    }
}

// ------------------------------------------------------ the tables ---

/// The tables one CNT_IMIT exchange runs on. See "Which tables" at the
/// top of this file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tables {
    /// The GOST 28147-89 S-box of CPDivers and the key wrap, as
    /// `GostCrypto::sbox_named` knows it: a built-in name, or the dotted
    /// OID of a registered parameter set.
    pub sbox: String,
    /// That parameter set's OID, which the message's
    /// `encryptionParamSet` carries.
    pub sbox_oid: Vec<u8>,
    /// The GOST R 34.11-94 parameter set VKO GOST R 34.10-2001 hashes its
    /// point under, as `Gost94::with_param_set` takes it. A 2012 key's
    /// VKO hashes with Streebog-256 and does not read it.
    pub vko_digest: String,
}

impl Tables {
    /// The key generation's own: CryptoPro-A and CryptoPro's hash
    /// parameters for a 2001 key, `param-Z` for a 2012 one - RFC 4357,
    /// RFC 9189, and what gost-engine always uses.
    pub fn defaults(key: KeyGeneration) -> Tables {
        let (sbox, sbox_oid) = match key {
            KeyGeneration::Gost2001 => (SBOX_2001, oids::GOST_28147_CRYPTOPRO_A),
            KeyGeneration::Gost2012 => (SBOX, oids::GOST_28147_PARAM_Z),
        };
        Tables { sbox: sbox.to_string(), sbox_oid: sbox_oid.to_vec(),
                 vko_digest: CRYPTOPRO_PARAM_SET.to_string() }
    }

    /// The tables the server's key names, each one it names replacing
    /// the generation's default: `algorithm_id` is the certificate's
    /// `AlgorithmIdentifier`, as `PublicKey::Gost::algorithm_id` keeps it.
    ///
    /// # Errors
    /// Parameters that are not a GOST key's, or a parameter set that is
    /// neither built in nor registered - refused rather than replaced by
    /// a default, which would give a key the server cannot derive and
    /// nothing to say why.
    pub fn for_key(key: KeyGeneration, algorithm_id: &[u8]) -> Result<Tables, String> {
        let KeyParameterSets { digest, encryption } = key_parameter_sets(algorithm_id)?;
        let mut tables = Tables::defaults(key);
        if let Some(oid) = encryption {
            tables.sbox = encryption_sbox(&oid)?;
            tables.sbox_oid = oid;
        }
        // A 2012 key's `digestParamSet` names Streebog, which its VKO
        // uses whatever the field says.
        if let (KeyGeneration::Gost2001, Some(oid)) = (key, digest) {
            tables.vko_digest = digest_param_set(&oid)?;
        }
        Ok(tables)
    }
}

/// The parameter sets after the curve in a GOST key's parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyParameterSets {
    /// The `digestParamSet` OID.
    pub digest: Option<Vec<u8>>,
    /// The `encryptionParamSet` OID.
    pub encryption: Option<Vec<u8>>,
}

/// The `digestParamSet` and `encryptionParamSet` of a GOST key's
/// `AlgorithmIdentifier`, each if present.
///
/// ```text
/// GostR3410-2001-PublicKeyParameters ::= SEQUENCE {
///     publicKeyParamSet   OBJECT IDENTIFIER,
///     digestParamSet      OBJECT IDENTIFIER,
///     encryptionParamSet  OBJECT IDENTIFIER OPTIONAL }    RFC 4357
/// ```
///
/// RFC 9215 makes `digestParamSet` optional for a 2012 key and has no
/// `encryptionParamSet`. The fields are read by position, as the ASN.1
/// defines them: an encryption set is the third OID, never the second.
pub fn key_parameter_sets(algorithm_id: &[u8]) -> Result<KeyParameterSets, String> {
    let mut outer = Reader::new(algorithm_id);
    let mut algid = outer.read_sequence()?;
    outer.finish()?;
    let algorithm = algid.read_tagged(Tag::universal(tag::OID))?;
    if algorithm != oids::GOST3410_2001 && algorithm != oids::GOST3410_12_256
        && algorithm != oids::GOST3410_12_512 {
        return Err("The key's algorithm is not a GOST R 34.10 one.".to_string());
    }
    let mut params = algid.read_sequence()?;
    algid.finish()?;
    params.read_tagged(Tag::universal(tag::OID))?;
    let mut sets = Vec::new();
    while !params.is_empty() {
        sets.push(params.read_tagged(Tag::universal(tag::OID))?.to_vec());
    }
    if sets.len() > 2 {
        return Err(format!(
            "A GOST key's parameters are a curve, a digest and an encryption \
             parameter set; these have {} OIDs.", sets.len() + 1));
    }
    let mut sets = sets.into_iter();
    Ok(KeyParameterSets { digest: sets.next(), encryption: sets.next() })
}

/// The S-box an `encryptionParamSet` names, as `GostCrypto::sbox_named`
/// knows it: RFC 4357's five and `param-Z` by name, any other by the
/// dotted OID it was registered under.
///
/// # Errors
/// An OID that is neither.
pub fn encryption_sbox(oid: &[u8]) -> Result<String, String> {
    let built_in = [
        (oids::GOST_28147_TEST, "id-Gost28147-89-TestParamSet"),
        (oids::GOST_28147_CRYPTOPRO_A, "id-Gost28147-89-CryptoPro-A-ParamSet"),
        (oids::GOST_28147_CRYPTOPRO_B, "id-Gost28147-89-CryptoPro-B-ParamSet"),
        (oids::GOST_28147_CRYPTOPRO_C, "id-Gost28147-89-CryptoPro-C-ParamSet"),
        (oids::GOST_28147_CRYPTOPRO_D, "id-Gost28147-89-CryptoPro-D-ParamSet"),
        (oids::GOST_28147_PARAM_Z, SBOX),
    ];
    if let Some((_, name)) = built_in.iter().find(|(known, _)| *known == oid) {
        return Ok(name.to_string());
    }
    let dotted = crate::asn1::Oid::new(oid)?.to_string();
    match crate::registry::lookup(&dotted) {
        Some(crate::registry::Meaning::GostParamSet(_)) => Ok(dotted),
        _ => Err(format!(
            "The encryption parameter set {dotted} is not one this library \
             carries; give it with allcrypt.register_oid(oid, gost_sbox=...).")),
    }
}

/// The GOST R 34.11-94 parameter set a 2001 key's `digestParamSet`
/// names, as `Gost94::with_param_set` takes it.
///
/// # Errors
/// An OID that is neither RFC 4357's two nor registered.
pub fn digest_param_set(oid: &[u8]) -> Result<String, String> {
    if oid == oids::GOST3411_94_CRYPTOPRO_PARAMSET {
        return Ok(CRYPTOPRO_PARAM_SET.to_string());
    }
    if oid == oids::GOST3411_94_TEST_PARAMSET {
        return Ok(TEST_PARAM_SET.to_string());
    }
    let dotted = crate::asn1::Oid::new(oid)?.to_string();
    match crate::registry::lookup(&dotted) {
        Some(crate::registry::Meaning::GostParamSet(_)) => Ok(dotted),
        _ => Err(format!(
            "The digest parameter set {dotted} is not one this library \
             carries; give it with allcrypt.register_oid(oid, gost_sbox=...).")),
    }
}

// ------------------------------------------------- the two halves ---

/// The client's side, with the ephemeral key and the secret supplied,
/// under the key generation's default tables.
#[allow(clippy::too_many_arguments)]
pub fn wrap_secret_with(transport: Transport, curve: &Curve,
                        server_algorithm_id: &[u8],
                        ephemeral_private: &BigUint, ephemeral_public: &Point,
                        server_public: &Point, client_random: &[u8],
                        server_random: &[u8], secret: &[u8])
                        -> Result<Vec<u8>, String> {
    wrap_secret_with_tables(transport, &Tables::defaults(transport.key), curve,
                            server_algorithm_id, ephemeral_private, ephemeral_public,
                            server_public, client_random, server_random, secret)
}

/// The client's side under the given tables: CPDivers and the wrap under
/// `tables.sbox`, which the message names, and a 2001 key's VKO under
/// `tables.vko_digest`.
#[allow(clippy::too_many_arguments)]
pub fn wrap_secret_with_tables(transport: Transport, tables: &Tables, curve: &Curve,
                               server_algorithm_id: &[u8],
                               ephemeral_private: &BigUint, ephemeral_public: &Point,
                               server_public: &Point, client_random: &[u8],
                               server_random: &[u8], secret: &[u8])
                               -> Result<Vec<u8>, String> {
    if secret.len() != PRELIMINARY_SECRET_LEN {
        return Err(format!(
            "The preliminary secret is {} bytes; got {}.",
            PRELIMINARY_SECRET_LEN, secret.len()));
    }
    let ukm = transport.ukm(client_random, server_random);
    let key = transport.kek_with(tables, curve, ephemeral_private, server_public, &ukm)?;
    let wrapped = kexp28147(secret, &key, &ukm, &tables.sbox)?;

    KeyTransportBlob {
        encrypted: wrapped[UKM_LEN..UKM_LEN + 32].to_vec(),
        mac: wrapped[UKM_LEN + 32..].to_vec(),
        // The S-box's own OID, which is the one field that tells a server
        // which table the blob was built with. gost-engine's server reads
        // it rather than inferring it.
        encryption_param_set: tables.sbox_oid.clone(),
        // The server's AlgorithmIdentifier, copied rather than rebuilt
        // from the curve - see `gost_kex::encode_public_key_like`. For a
        // 2001 key that is also what keeps `XchA` from coming back as
        // CryptoPro-A.
        ephemeral: gost_kex::encode_public_key_like(server_algorithm_id, curve,
                                                   ephemeral_public)?,
        ukm,
    }.encode()
}

/// Pick the ephemeral key and the secret, and produce the message, under
/// the key generation's default tables.
pub fn client_key_exchange_with(transport: Transport, curve: &Curve,
                                server_algorithm_id: &[u8], server_public: &Point,
                                client_random: &[u8], server_random: &[u8])
                                -> Result<(Vec<u8>, Vec<u8>), String> {
    client_key_exchange_with_tables(transport, &Tables::defaults(transport.key), curve,
                                    server_algorithm_id, server_public, client_random,
                                    server_random)
}

/// `client_key_exchange_with` under the given tables - the TLS client's
/// call, with `Tables::for_key` over the server's certificate.
pub fn client_key_exchange_with_tables(transport: Transport, tables: &Tables, curve: &Curve,
                                       server_algorithm_id: &[u8], server_public: &Point,
                                       client_random: &[u8], server_random: &[u8])
                                       -> Result<(Vec<u8>, Vec<u8>), String> {
    let secret = crate::random::bytes(PRELIMINARY_SECRET_LEN)?;
    let (private, public) = curve.generate_key_pair()?;
    let body = wrap_secret_with_tables(transport, tables, curve, server_algorithm_id,
                                       &private, &public, server_public, client_random,
                                       server_random, &secret)?;
    Ok((body, secret))
}

/// The server's side, with a 2001 key's VKO under CryptoPro's hash
/// parameters. The S-box is the one the message names.
pub fn unwrap_secret_with(transport: Transport, curve: &Curve, private: &BigUint,
                          client_random: &[u8], server_random: &[u8],
                          body: &[u8]) -> Result<Vec<u8>, String> {
    unwrap_secret_with_tables(transport, &Tables::defaults(transport.key), curve, private,
                              client_random, server_random, body)
}

/// The server's side with a 2001 key's VKO under `tables.vko_digest` -
/// from `Tables::for_key` over the server's own certificate.
///
/// **The S-box is the message's**, not `tables.sbox`: RFC 4490 section
/// 4.2 has its `encryptionParamSet` "used for all encryption
/// operations", and gost-engine's server reads it. One this library
/// does not carry is refused.
pub fn unwrap_secret_with_tables(transport: Transport, tables: &Tables, curve: &Curve,
                                 private: &BigUint, client_random: &[u8],
                                 server_random: &[u8], body: &[u8])
                                 -> Result<Vec<u8>, String> {
    let blob = KeyTransportBlob::parse(body)?;
    let sbox = encryption_sbox(&blob.encryption_param_set)?;
    let (their_curve, ephemeral) = gost_kex::decode_public_key(&blob.ephemeral)?;
    if their_curve.name != curve.name {
        return Err(format!(
            "The ephemeral key is on {}, and the server's key is on {}.",
            their_curve.name, curve.name));
    }
    if ephemeral.is_identity() {
        return Err("The ephemeral public key is the identity.".to_string());
    }

    let ukm = transport.ukm(client_random, server_random);
    // draft-chudov-cryptopro-cptls section 3.6: the server MUST check
    // the UKM in the message against the one it derived, before
    // decrypting. `kimp28147` checks it again as part of the wrapping,
    // but this is the check the document asks for and it is about a
    // different field - the blob's own `ukm`, which a client could
    // have filled in with anything.
    if blob.ukm != ukm {
        return Err("The key transport blob's UKM is not the suite's hash of \
                    the two randoms.".to_string());
    }
    let message_tables = Tables { sbox: sbox.clone(),
                                  sbox_oid: blob.encryption_param_set.clone(),
                                  vko_digest: tables.vko_digest.clone() };
    let key = transport.kek_with(&message_tables, curve, private, &ephemeral, &ukm)?;

    let mut wrapped = blob.ukm.clone();
    wrapped.extend_from_slice(&blob.encrypted);
    wrapped.extend_from_slice(&blob.mac);
    kimp28147(&wrapped, &key, &ukm, &sbox)
}

/// `wrap_secret_with` for RFC 9189's own pairing: a 2012 suite on a 2012
/// key.
#[allow(clippy::too_many_arguments)]
pub fn wrap_secret(curve: &Curve, server_algorithm_id: &[u8],
                   ephemeral_private: &BigUint,
                   ephemeral_public: &Point, server_public: &Point,
                   client_random: &[u8], server_random: &[u8], secret: &[u8])
                   -> Result<Vec<u8>, String> {
    wrap_secret_with(Transport::RFC_9189, curve, server_algorithm_id,
                     ephemeral_private, ephemeral_public, server_public,
                     client_random, server_random, secret)
}

/// `client_key_exchange_with` for a 2012 suite on a 2012 key.
pub fn client_key_exchange(curve: &Curve, server_algorithm_id: &[u8],
                           server_public: &Point,
                           client_random: &[u8], server_random: &[u8])
                           -> Result<(Vec<u8>, Vec<u8>), String> {
    client_key_exchange_with(Transport::RFC_9189, curve, server_algorithm_id,
                             server_public, client_random, server_random)
}

/// `unwrap_secret_with` for a 2012 suite on a 2012 key.
pub fn unwrap_secret(curve: &Curve, private: &BigUint, client_random: &[u8],
                     server_random: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    unwrap_secret_with(Transport::RFC_9189, curve, private, client_random,
                       server_random, body)
}

// --------------------------------------------- the 2001 suite's halves ---

/// The client's side of `TLS_GOSTR341001_WITH_28147_CNT_IMIT`.
///
/// Every step has the same shape as `wrap_secret` above and a
/// different algorithm inside it: GOST R 34.11-94 over the randoms,
/// VKO GOST R 34.10-2001, and CryptoPro-A everywhere a table is
/// needed. The message is the same `TLSGostKeyTransportBlob`.
#[allow(clippy::too_many_arguments)]
pub fn wrap_secret_2001(curve: &Curve, server_algorithm_id: &[u8],
                        ephemeral_private: &BigUint,
                        ephemeral_public: &Point, server_public: &Point,
                        client_random: &[u8], server_random: &[u8],
                        secret: &[u8]) -> Result<Vec<u8>, String> {
    wrap_secret_with(Transport::GOST_2001, curve, server_algorithm_id,
                     ephemeral_private, ephemeral_public, server_public,
                     client_random, server_random, secret)
}

pub fn client_key_exchange_2001(curve: &Curve, server_algorithm_id: &[u8],
                                server_public: &Point,
                                client_random: &[u8], server_random: &[u8])
                                -> Result<(Vec<u8>, Vec<u8>), String> {
    client_key_exchange_with(Transport::GOST_2001, curve, server_algorithm_id,
                             server_public, client_random, server_random)
}

pub fn unwrap_secret_2001(curve: &Curve, private: &BigUint,
                          client_random: &[u8], server_random: &[u8],
                          body: &[u8]) -> Result<Vec<u8>, String> {
    unwrap_secret_with(Transport::GOST_2001, curve, private, client_random,
                       server_random, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9189 Appendix A.2.2's key exchange, every printed value.
    ///
    /// This is the only thing that settles CPDivers: RFC 4357 gives it
    /// no vector, and it is deterministic under every wrong reading of
    /// the word order, the bit order and the two sums. The example uses
    /// a **512 bit** curve, which also settles that `KEG_28147` hashes
    /// with Streebog-256 regardless - section 8.3.2 has no 512 branch,
    /// unlike `KEG`.
    #[test]
    fn test_rfc_9189_cnt_imit_key_exchange() {
        let curve = curves::by_name("gost512-a").unwrap();

        let ephemeral_private = BigUint::from_bytes_be(&unhex(
            "C96486B1A3732389A162F5AD0145D53743C9AC27D42ACF1091CE7EF67E6C3CCA\
             0F6C879B2DA3C1607648BAEB96471BD2078DF5CAAA4FA83ECC0FFD6D3C8E5D56"));
        let ephemeral_public = Point::new(
            BigUint::from_bytes_be(&unhex(
                "4B9CB381BCC737E493E43B2D7FD95BFE2AEF6BE8F6224882E5E559ADA08170DC\
                 49A815B3A1B3B323D2B50195153CFC60DD6139C3770C5762A6A7719FABF84BFB")),
            BigUint::from_bytes_be(&unhex(
                "95CEF28392C846A5EEFCB51C84E4960A77B77D0D85EBD22061BFDA0013C5AB6C\
                 42DDD04973F65D2AEB8A5427A53D6872CF2D68F5F722C4640D7AAF2E0194FBD0")));
        assert_eq!(curve.scalar_mul(&curve.g, &ephemeral_private), ephemeral_public,
                   "the example's ephemeral key pair does not match itself");

        let h = unhex("FBF39D10E800AF70E7AA22C110DA94A9\
                       9A5898D84527C7CBDEC11E5339906A1A");
        let ukm = &h[..UKM_LEN];
        assert_eq!(hex(ukm), "fbf39d10e800af70");

        // The server's key is not printed, so the shared point cannot be
        // recomputed from both sides - but `K_EXP` is, and CPDivers is
        // what stands between the two.
        let shared = curve.vko(&ephemeral_private, &ephemeral_public, ukm, 256)
                          .unwrap();
        assert_eq!(shared.len(), 32, "VKO_256 regardless of the curve's size");

        // **The RFC's `K_EXP` is the VKO output, not the export key.**
        // Both of its examples label the value before the last
        // derivation step that way - in A.1.3.1 the tree KDF's output
        // is separately labelled "Export keys K_Exp_MAC | K_Exp_ENC",
        // and here there is no second label at all, so `K_EXP` reads
        // like the thing `KExp28147` is keyed with and is not. Using it
        // directly gives a wrapping of exactly the right length that
        // nobody can unwrap.
        //
        // That also makes this example the only check CPDivers has:
        // RFC 4357 gives it no vector, and it is deterministic under
        // every wrong reading of the word order, the bit order and the
        // two sums.
        let vko_output = unhex("3FD999D1684A15CC9BDD5A35067AF698\
                                17150022E09554AC791A60F161F55349");
        let k_exp = cp_divers(ukm, &vko_output, SBOX).unwrap();
        assert_ne!(k_exp, vko_output, "CPDivers is not the identity");
        let pms = unhex("CE0DD6B67042121 52BE4695A7E89F64C\
                         8929A40DBF0A5A55C2CE002B06BAB62F".replace(' ', "").as_str());
        let wrapped = kexp28147(&pms, &k_exp, ukm, SBOX).unwrap();

        assert_eq!(hex(&wrapped[UKM_LEN..UKM_LEN + 32]),
                   "d622d167a5642e29525a295cb9f28f96\
                    f28b0efaa7d3a2bee149b01178c2dfd5");
        assert_eq!(hex(&wrapped[UKM_LEN + 32..]), "4c933657");
        assert_eq!(hex(&wrapped),
                   "fbf39d10e800af70\
                    d622d167a5642e29525a295cb9f28f96\
                    f28b0efaa7d3a2bee149b01178c2dfd5\
                    4c933657");

        // And it comes back.
        assert_eq!(kimp28147(&wrapped, &k_exp, ukm, SBOX).unwrap(), pms);

        // The whole ClientKeyExchange body, byte for byte.
        let body = KeyTransportBlob {
            encrypted: wrapped[UKM_LEN..UKM_LEN + 32].to_vec(),
            mac: wrapped[UKM_LEN + 32..].to_vec(),
            encryption_param_set: oids::GOST_28147_PARAM_Z.to_vec(),
            ephemeral: gost_kex::encode_public_key(&curve, &ephemeral_public)
                       .unwrap(),
            ukm: ukm.to_vec(),
        }.encode().unwrap();
        assert_eq!(hex(&body), hex(&unhex(
            "3081F23081EF30280420D622D167A5642E29525A295CB9F28F96F28B0EFAA7D3\
             A2BEE149B01178C2DFD504044C933657A081C206092A85030701020501 01A081\
             AA302106082A85030701010102301506092A850307010201020106082A850307\
             010102030381840004818 0FB4BF8AB9F71A7A662570C77C33961DD60FC3C1595\
             01B5D223B3B3A1B315A849DC7081A0AD59E5E5824822F6E86BEF2AFE5BD97F2D\
             3BE493E437C7BC81B39C4BD0FB94012EAF7A0D64C422F7F5682DCF72683DA527\
             548AEB2A5DF67349D0DD426CABC51300DABF6120D2EB850D7DB7770A96E4841C\
             B5FCEEA546C89283F2CE950408FBF39D10E800AF70")));

        // And it round trips through the parser.
        let back = KeyTransportBlob::parse(&body).unwrap();
        assert_eq!(hex(&back.encrypted), hex(&wrapped[UKM_LEN..UKM_LEN + 32]));
        assert_eq!(hex(&back.mac), "4c933657");
        assert_eq!(hex(&back.ukm), hex(ukm));
        assert_eq!(back.encryption_param_set, oids::GOST_28147_PARAM_Z);
        let (back_curve, back_point) =
            gost_kex::decode_public_key(&back.ephemeral).unwrap();
        assert_eq!(back_curve.name, "gost512-a");
        assert_eq!(back_point, ephemeral_public);
    }

    /// CPDivers is not the identity, depends on every UKM byte, and is
    /// deterministic.
    #[test]
    fn test_cp_divers_uses_the_whole_ukm() {
        let key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(31).wrapping_add(7))
                                    .collect();
        let ukm = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let base = cp_divers(&ukm, &key, SBOX).unwrap();
        assert_eq!(base.len(), 32);
        assert_ne!(base, key);
        assert_eq!(base, cp_divers(&ukm, &key, SBOX).unwrap());

        for index in 0..UKM_LEN {
            let mut altered = ukm;
            altered[index] ^= 0x01;
            assert_ne!(cp_divers(&altered, &key, SBOX).unwrap(), base,
                       "UKM byte {} does not affect the result", index);
        }

        // The bit order within a byte matters too: bit 0 selects word 0.
        // Reversing a byte's bits must give a different key.
        let mut reversed = ukm;
        reversed[0] = ukm[0].reverse_bits();
        assert_ne!(cp_divers(&reversed, &key, SBOX).unwrap(), base);
    }

    #[test]
    fn test_cp_divers_refuses_wrong_lengths() {
        assert!(cp_divers(&[0u8; 7], &[0u8; 32], SBOX).is_err());
        assert!(cp_divers(&[0u8; 8], &[0u8; 31], SBOX).is_err());
    }

    /// The wrapping is authenticated, and the IV it carries is checked.
    #[test]
    fn test_the_wrapping_is_authenticated() {
        let key = [0x5au8; 32];
        let iv = [0x0fu8; 8];
        let secret = [0x77u8; 32];
        let wrapped = kexp28147(&secret, &key, &iv, SBOX).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        assert_eq!(kimp28147(&wrapped, &key, &iv, SBOX).unwrap(), secret);

        // The IV the message carries must be the one derived.
        let mut other = iv;
        other[0] ^= 1;
        assert!(kimp28147(&wrapped, &key, &other, SBOX).is_err());

        for bit in 0..wrapped.len() * 8 {
            let mut altered = wrapped.clone();
            altered[bit / 8] ^= 1 << (bit % 8);
            assert!(kimp28147(&altered, &key, &iv, SBOX).is_err(),
                    "bit {} could be flipped undetected", bit);
        }
    }

    /// The `[0]` tags are **implicit**, so the SubjectPublicKeyInfo's
    /// SEQUENCE header does not appear on the wire.
    ///
    /// Explicit tagging produces a message two bytes longer that parses
    /// cleanly as something else, which is why this is checked directly
    /// rather than left to the round trip.
    #[test]
    fn test_the_tagging_is_implicit() {
        let curve = curves::by_name("gost256-a").unwrap();
        let point = curve.scalar_mul(&curve.g, &BigUint::from_u64(12345));
        let spki = gost_kex::encode_public_key(&curve, &point).unwrap();

        let body = KeyTransportBlob {
            encrypted: vec![0u8; 32],
            mac: vec![1, 2, 3, 4],
            encryption_param_set: oids::GOST_28147_PARAM_Z.to_vec(),
            ephemeral: spki.clone(),
            ukm: vec![9u8; 8],
        }.encode().unwrap();

        // The SPKI's own SEQUENCE header must not be in the message;
        // its contents must be.
        let contents = sequence_contents(&spki).unwrap();
        assert!(body.windows(contents.len()).any(|w| w == contents));
        assert!(!body.windows(spki.len()).any(|w| w == &spki[..]),
                "the SubjectPublicKeyInfo's SEQUENCE header is on the wire, \
                 which means the [0] tag was written explicitly");

        assert_eq!(KeyTransportBlob::parse(&body).unwrap().ephemeral, spki);
    }

    const KEYWRAP: &str = include_str!("../../vectors/gost_keywrap.vec");

    /// The parameter set a `gost_keywrap.vec` row names, as the OID a
    /// message's `encryptionParamSet` would carry.
    fn set_oid(name: &str) -> &'static [u8] {
        match name {
            "test" => oids::GOST_28147_TEST,
            "a" => oids::GOST_28147_CRYPTOPRO_A,
            "b" => oids::GOST_28147_CRYPTOPRO_B,
            "c" => oids::GOST_28147_CRYPTOPRO_C,
            "d" => oids::GOST_28147_CRYPTOPRO_D,
            "z" => oids::GOST_28147_PARAM_Z,
            other => panic!("no parameter set {other}"),
        }
    }

    /// CPDivers and the key wrap under every parameter set a message can
    /// name, against gost-engine's own `keyDiversifyCryptoPro` and
    /// `keyWrapCryptoPro` (`vectors/gost_keywrap.vec`), each set reached
    /// through its OID as a message names it. RFC 9189's example pins
    /// `param-Z` alone.
    #[test]
    fn test_the_wrap_under_every_parameter_set_is_gost_engine_s() {
        let mut seen = std::collections::BTreeMap::new();
        for line in KEYWRAP.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let mut fields = line.split(' ');
            let kind = fields.next().unwrap();
            let f: std::collections::HashMap<&str, &str> =
                fields.map(|w| w.split_once('=').unwrap()).collect();
            let sbox = encryption_sbox(set_oid(f["set"])).unwrap();
            let (kek, ukm) = (unhex(f["kek"]), unhex(f["ukm"]));
            let key = cp_divers(&ukm, &kek, &sbox).unwrap();
            match kind {
                "diversify" => assert_eq!(key, unhex(f["key"]), "{line}"),
                "wrap" => {
                    let (cek, wrapped) = (unhex(f["cek"]), unhex(f["wrapped"]));
                    assert_eq!(kexp28147(&cek, &key, &ukm, &sbox).unwrap(), wrapped, "{line}");
                    assert_eq!(kimp28147(&wrapped, &key, &ukm, &sbox).unwrap(), cek, "{line}");
                }
                other => panic!("a {other} row"),
            }
            *seen.entry(f["set"].to_string()).or_insert(0) += 1;
        }
        // A parser that found nothing would pass every assertion above.
        assert_eq!(seen.len(), 6, "{seen:?}");
        assert!(seen.values().all(|&n| n >= 6), "{seen:?}");
    }

    /// The derivations hand CPDivers the S-box they are given, and a 2001
    /// key's VKO the digest set: the composition, under every set.
    #[test]
    fn test_the_derivations_use_the_tables_they_are_given() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (a, _) = curve.generate_key_pair().unwrap();
        let (_, b) = curve.generate_key_pair().unwrap();
        let ukm = [1u8, 2, 3, 4, 5, 6, 7, 8];
        for set in ["test", "a", "b", "c", "d", "z"] {
            let sbox = encryption_sbox(set_oid(set)).unwrap();
            let shared = curve.vko_2001_with(&a, &b, &ukm, TEST_PARAM_SET).unwrap();
            assert_eq!(keg_2001_with(&curve, &a, &b, &ukm, &sbox, TEST_PARAM_SET).unwrap(),
                       cp_divers(&ukm, &shared, &sbox).unwrap(), "{set}");
            let shared = curve.vko_using(&a, &b, &ukm, 256,
                                         crate::ec::vko::Cofactor::AsSpecified).unwrap();
            assert_eq!(keg_2012_with(&curve, &a, &b, &ukm, &sbox).unwrap(),
                       cp_divers(&ukm, &shared, &sbox).unwrap(), "{set}");
        }
    }

    /// A 2001 key's `AlgorithmIdentifier` on CryptoPro-A, with the given
    /// parameter sets after the curve.
    fn algorithm_id_2001(sets: &[&[u8]]) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_sequence(|algid| {
            algid.write_oid(oids::GOST3410_2001);
            algid.write_sequence(|params| {
                params.write_oid(oids::GOST_2001_CRYPTOPRO_A);
                for set in sets {
                    params.write_oid(set);
                }
            });
        });
        w.finish()
    }

    /// Registers an S-box under `oid` for the test's lifetime: CryptoPro-A
    /// with its first row reversed, a table nothing else carries.
    struct Registered(&'static str);
    impl Registered {
        fn new(oid: &'static str) -> Registered {
            let mut rows = GostCrypto::sbox_named(SBOX_2001).unwrap();
            rows[0].reverse();
            crate::registry::register(oid, crate::registry::Meaning::gost_param_set(rows))
                .unwrap();
            Registered(oid)
        }
        fn der(&self) -> Vec<u8> {
            crate::asn1::encode_oid(self.0).unwrap()
        }
    }
    impl Drop for Registered {
        fn drop(&mut self) {
            crate::registry::forget(self.0);
        }
    }

    /// gost-engine's own key parameters - CryptoPro's digest set and no
    /// encryption set - and none at all after the curve, give the
    /// defaults; so does a 2012 key's Streebog `digestParamSet`.
    #[test]
    fn test_keys_that_name_no_tables_get_the_defaults() {
        for sets in [&[][..], &[oids::GOST3411_94_CRYPTOPRO_PARAMSET][..]] {
            assert_eq!(Tables::for_key(KeyGeneration::Gost2001, &algorithm_id_2001(sets)),
                       Ok(Tables::defaults(KeyGeneration::Gost2001)));
        }
        for name in ["gost256-a", "gost512-a"] {
            let curve = curves::by_name(name).unwrap();
            let algorithm_id = gost_kex::algorithm_id_for(&curve).unwrap();
            assert!(key_parameter_sets(&algorithm_id).unwrap().digest.is_some(),
                    "{name}: the 2012 identifier carries a Streebog digestParamSet");
            assert_eq!(Tables::for_key(KeyGeneration::Gost2012, &algorithm_id),
                       Ok(Tables::defaults(KeyGeneration::Gost2012)), "{name}");
        }
    }

    /// The sets are read by position: the second OID is the digest set
    /// and the third the encryption set.
    #[test]
    fn test_the_key_s_tables_are_read_by_position() {
        let algorithm_id = algorithm_id_2001(&[oids::GOST3411_94_TEST_PARAMSET,
                                               oids::GOST_28147_CRYPTOPRO_B]);
        assert_eq!(key_parameter_sets(&algorithm_id),
                   Ok(KeyParameterSets {
                       digest: Some(oids::GOST3411_94_TEST_PARAMSET.to_vec()),
                       encryption: Some(oids::GOST_28147_CRYPTOPRO_B.to_vec()) }));
        let tables = Tables::for_key(KeyGeneration::Gost2001, &algorithm_id).unwrap();
        assert_eq!(tables.sbox, "id-Gost28147-89-CryptoPro-B-ParamSet");
        assert_eq!(tables.sbox_oid, oids::GOST_28147_CRYPTOPRO_B);
        assert_eq!(tables.vko_digest, TEST_PARAM_SET);

        // An encryption set in the digest's place is a digest set this
        // library does not know, not an encryption set.
        let swapped = algorithm_id_2001(&[oids::GOST_28147_CRYPTOPRO_B]);
        assert!(Tables::for_key(KeyGeneration::Gost2001, &swapped).unwrap_err()
                    .contains("digest parameter set"));
        let four = algorithm_id_2001(&[oids::GOST3411_94_CRYPTOPRO_PARAMSET,
                                       oids::GOST_28147_CRYPTOPRO_B,
                                       oids::GOST_28147_CRYPTOPRO_C]);
        assert!(key_parameter_sets(&four).is_err());
    }

    /// A set neither built in nor registered is refused, not replaced by
    /// a default.
    #[test]
    fn test_an_unknown_table_is_refused() {
        let unknown = crate::asn1::encode_oid("1.3.6.1.4.1.99999.7.1").unwrap();
        let as_digest = algorithm_id_2001(&[&unknown]);
        let as_encryption = algorithm_id_2001(&[oids::GOST3411_94_CRYPTOPRO_PARAMSET, &unknown]);
        for algorithm_id in [as_digest, as_encryption] {
            let err = Tables::for_key(KeyGeneration::Gost2001, &algorithm_id).unwrap_err();
            assert!(err.contains("1.3.6.1.4.1.99999.7.1") && err.contains("register_oid"),
                    "{err}");
        }
    }

    /// A key naming other tables: the client wraps under them and names
    /// the S-box, the server unwraps under the S-box the message names
    /// and its own key's digest set - and each table is load bearing.
    #[test]
    fn test_a_key_s_own_tables_carry_the_exchange() {
        let encryption = Registered::new("1.3.6.1.4.1.99999.7.2");
        let digest = Registered::new("1.3.6.1.4.1.99999.7.3");
        let curve = curves::by_name("gost256-a").unwrap();
        let (server_private, server_public) = curve.generate_key_pair().unwrap();
        let (private, public) = curve.generate_key_pair().unwrap();
        let secret = [0x42u8; PRELIMINARY_SECRET_LEN];
        let transport = Transport::GOST_2001;
        let (random_c, random_s) = ([1u8; 32], [2u8; 32]);

        for sets in [vec![oids::GOST3411_94_TEST_PARAMSET.to_vec(),
                          oids::GOST_28147_CRYPTOPRO_B.to_vec()],
                     vec![digest.der(), encryption.der()]] {
            let refs: Vec<&[u8]> = sets.iter().map(|s| s.as_slice()).collect();
            let algorithm_id = algorithm_id_2001(&refs);
            let tables = Tables::for_key(KeyGeneration::Gost2001, &algorithm_id).unwrap();
            assert_ne!(tables.sbox, SBOX_2001);
            assert_ne!(tables.vko_digest, CRYPTOPRO_PARAM_SET);
            let body = wrap_secret_with_tables(transport, &tables, &curve, &algorithm_id,
                                               &private, &public, &server_public,
                                               &random_c, &random_s, &secret).unwrap();
            assert_eq!(KeyTransportBlob::parse(&body).unwrap().encryption_param_set,
                       sets[1], "the message names the S-box it was wrapped under");
            assert_eq!(unwrap_secret_with_tables(transport, &tables, &curve, &server_private,
                                                 &random_c, &random_s, &body),
                       Ok(secret.to_vec()));
            // The server's own key decides the VKO's digest set: the
            // defaults' CryptoPro set derives another key.
            assert!(unwrap_secret_with(transport, &curve, &server_private, &random_c,
                                       &random_s, &body).is_err());
            // And the defaults' wrap does not unwrap as these tables.
            let default_body = wrap_secret_with(transport, &curve, &algorithm_id, &private,
                                                &public, &server_public, &random_c,
                                                &random_s, &secret).unwrap();
            assert_ne!(default_body, body);
        }
    }

    /// The server unwraps under the S-box the message names, whatever its
    /// own defaults: a client that wrapped under CryptoPro-B is read.
    #[test]
    fn test_the_server_unwraps_under_the_message_s_s_box() {
        let curve = curves::by_name("gost256-a").unwrap();
        let (server_private, server_public) = curve.generate_key_pair().unwrap();
        let (private, public) = curve.generate_key_pair().unwrap();
        let secret = [0x5au8; PRELIMINARY_SECRET_LEN];
        let algorithm_id = algorithm_id_2001(&[oids::GOST3411_94_CRYPTOPRO_PARAMSET,
                                               oids::GOST_28147_CRYPTOPRO_B]);
        let tables = Tables::for_key(KeyGeneration::Gost2001, &algorithm_id).unwrap();
        assert_eq!(tables.vko_digest, CRYPTOPRO_PARAM_SET);
        let body = wrap_secret_with_tables(Transport::GOST_2001, &tables, &curve, &algorithm_id,
                                           &private, &public, &server_public,
                                           &[1u8; 32], &[2u8; 32], &secret).unwrap();
        assert_eq!(unwrap_secret_2001(&curve, &server_private, &[1u8; 32], &[2u8; 32], &body),
                   Ok(secret.to_vec()));

        // A message naming a table nobody registered is refused.
        let mut blob = KeyTransportBlob::parse(&body).unwrap();
        blob.encryption_param_set = crate::asn1::encode_oid("1.3.6.1.4.1.99999.7.4").unwrap();
        let err = unwrap_secret_2001(&curve, &server_private, &[1u8; 32], &[2u8; 32],
                                     &blob.encode().unwrap()).unwrap_err();
        assert!(err.contains("register_oid"), "{err}");
    }

    /// The whole exchange, both halves, on every GOST curve.
    #[test]
    fn test_the_exchange_round_trips() {
        for name in curves::gost_names() {
            let curve = curves::by_name(name).unwrap();
            let (server_private, server_public) = curve.generate_key_pair().unwrap();
            let (private, public) = curve.generate_key_pair().unwrap();
            let secret = [0x42u8; PRELIMINARY_SECRET_LEN];

            let body = wrap_secret(&curve, &gost_kex::algorithm_id_for(&curve).unwrap(), &private, &public, &server_public,
                                   &[1u8; 32], &[2u8; 32], &secret).unwrap();
            assert_eq!(unwrap_secret(&curve, &server_private, &[1u8; 32],
                                     &[2u8; 32], &body).unwrap(),
                       secret, "{}", name);
            assert!(!body.windows(secret.len()).any(|w| w == secret),
                    "{}: the secret appears in the message", name);

            // A different hello gives different export keys, so the
            // message does not unwrap.
            assert!(unwrap_secret(&curve, &server_private, &[1u8; 32],
                                  &[3u8; 32], &body).is_err(), "{}", name);
        }
    }

    /// `KEG_28147` reads its UKM **little endian**, unlike `KEG`.
    #[test]
    fn test_the_ukm_is_read_little_endian() {
        let curve = curves::by_name("gost256-a").unwrap();
        let private = BigUint::from_u64(0x1234_5678);
        let peer = curve.scalar_mul(&curve.g, &BigUint::from_u64(0x9abc_def0));
        let h: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(17).wrapping_add(3))
                                  .collect();

        let ours = keg_28147(&curve, &private, &peer, &h).unwrap();

        let mut reversed = h[..UKM_LEN].to_vec();
        reversed.reverse();
        let other = curve.vko(&private, &peer, &reversed, 256).unwrap();
        assert_ne!(ours, cp_divers(&h[..UKM_LEN], &other, SBOX).unwrap());
    }

    /// The generated form, and the only test that touches randomness.
    #[test]
    fn test_the_generated_exchange_works() {
        let curve = curves::by_name("gost256-b").unwrap();
        let (private, public) = curve.generate_key_pair().unwrap();
        let (body, secret) = client_key_exchange(&curve, &gost_kex::algorithm_id_for(&curve).unwrap(), &public,
                                                 &[7u8; 32], &[8u8; 32]).unwrap();
        assert_eq!(secret.len(), PRELIMINARY_SECRET_LEN);
        assert_eq!(unwrap_secret(&curve, &private, &[7u8; 32], &[8u8; 32], &body)
                       .unwrap(),
                   secret);

        let (_, again) = client_key_exchange(&curve, &gost_kex::algorithm_id_for(&curve).unwrap(), &public,
                                             &[7u8; 32], &[8u8; 32]).unwrap();
        assert_ne!(secret, again);
    }
}
