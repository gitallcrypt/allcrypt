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
        let mut cipher = GostCrypto::new(current.clone(), sbox.to_string())?;
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
    let ukm = &h[..UKM_LEN];
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
    cp_divers(ukm, &shared, SBOX)
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
    if ukm.len() != UKM_LEN {
        return Err(format!(
            "The 2001 suite's UKM is {} bytes, the first half of a GOST R \
             34.11-94 digest; got {}.", UKM_LEN, ukm.len()));
    }
    let shared = curve.vko_2001(private, peer, ukm)?;
    cp_divers(ukm, &shared, SBOX_2001)
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

    let mut cipher = GostCrypto::new(key.to_vec(), sbox.to_string())?;
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

    let mut cipher = GostCrypto::new(key.to_vec(), sbox.to_string())?;
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

// ------------------------------------------------- the two halves ---

/// The client's side, with the ephemeral key and the secret supplied.
#[allow(clippy::too_many_arguments)]
pub fn wrap_secret(curve: &Curve, server_algorithm_id: &[u8],
                   ephemeral_private: &BigUint,
                   ephemeral_public: &Point, server_public: &Point,
                   client_random: &[u8], server_random: &[u8], secret: &[u8])
                   -> Result<Vec<u8>, String> {
    if secret.len() != PRELIMINARY_SECRET_LEN {
        return Err(format!(
            "The preliminary secret is {} bytes; got {}.",
            PRELIMINARY_SECRET_LEN, secret.len()));
    }
    let h = gost_kex::keg_hash(client_random, server_random);
    let ukm = h[..UKM_LEN].to_vec();
    let key = keg_28147(curve, ephemeral_private, server_public, &h)?;
    let wrapped = kexp28147(secret, &key, &ukm, SBOX)?;

    KeyTransportBlob {
        encrypted: wrapped[UKM_LEN..UKM_LEN + 32].to_vec(),
        mac: wrapped[UKM_LEN + 32..].to_vec(),
        encryption_param_set: oids::GOST_28147_PARAM_Z.to_vec(),
        // The server's AlgorithmIdentifier, copied rather than rebuilt
        // from the curve - see `gost_kex::encode_public_key_like`.
        ephemeral: gost_kex::encode_public_key_like(server_algorithm_id, curve,
                                                   ephemeral_public)?,
        ukm,
    }.encode()
}

/// Pick the ephemeral key and the secret, and produce the message.
pub fn client_key_exchange(curve: &Curve, server_algorithm_id: &[u8],
                           server_public: &Point,
                           client_random: &[u8], server_random: &[u8])
                           -> Result<(Vec<u8>, Vec<u8>), String> {
    let secret = crate::random::bytes(PRELIMINARY_SECRET_LEN)?;
    let (private, public) = curve.generate_key_pair()?;
    let body = wrap_secret(curve, server_algorithm_id, &private, &public,
                           server_public, client_random, server_random, &secret)?;
    Ok((body, secret))
}

/// The server's side.
pub fn unwrap_secret(curve: &Curve, private: &BigUint, client_random: &[u8],
                     server_random: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    let blob = KeyTransportBlob::parse(body)?;
    let (their_curve, ephemeral) = gost_kex::decode_public_key(&blob.ephemeral)?;
    if their_curve.name != curve.name {
        return Err(format!(
            "The ephemeral key is on {}, and the server's key is on {}.",
            their_curve.name, curve.name));
    }
    if ephemeral.is_identity() {
        return Err("The ephemeral public key is the identity.".to_string());
    }

    let h = gost_kex::keg_hash(client_random, server_random);
    let ukm = h[..UKM_LEN].to_vec();
    let key = keg_28147(curve, private, &ephemeral, &h)?;

    let mut wrapped = blob.ukm.clone();
    wrapped.extend_from_slice(&blob.encrypted);
    wrapped.extend_from_slice(&blob.mac);
    kimp28147(&wrapped, &key, &ukm, SBOX)
}

// --------------------------------------------- the 2001 suite's halves ---

/// The client's side of `TLS_GOSTR341001_WITH_28147_CNT_IMIT`.
///
/// Every step has the same shape as `wrap_secret` above and a
/// different algorithm inside it: GOST R 34.11-94 over the randoms,
/// VKO GOST R 34.10-2001, and CryptoPro-A everywhere a table is
/// needed. The message is the same `TLSGostKeyTransportBlob`, and the
/// `encryptionParamSet` it carries names the S-box - which is the one
/// field that tells a server which of the two suites' conventions the
/// blob was built with.
#[allow(clippy::too_many_arguments)]
pub fn wrap_secret_2001(curve: &Curve, server_algorithm_id: &[u8],
                        ephemeral_private: &BigUint,
                        ephemeral_public: &Point, server_public: &Point,
                        client_random: &[u8], server_random: &[u8],
                        secret: &[u8]) -> Result<Vec<u8>, String> {
    if secret.len() != PRELIMINARY_SECRET_LEN {
        return Err(format!(
            "The premaster secret is {} bytes; got {}.",
            PRELIMINARY_SECRET_LEN, secret.len()));
    }
    let ukm = shared_ukm_2001(client_random, server_random);
    let key = keg_2001(curve, ephemeral_private, server_public, &ukm)?;
    let wrapped = kexp28147(secret, &key, &ukm, SBOX_2001)?;

    KeyTransportBlob {
        encrypted: wrapped[UKM_LEN..UKM_LEN + 32].to_vec(),
        mac: wrapped[UKM_LEN + 32..].to_vec(),
        encryption_param_set: oids::GOST_28147_CRYPTOPRO_A.to_vec(),
        // Copied, like the 2012 path. `encode_public_key_2001` picks a
        // CryptoPro OID from the curve's name, which is right when *we*
        // choose the curve - writing a certificate - and wrong when the
        // server already named it, because `XchA` and CryptoPro-A are the
        // same curve under two OIDs.
        ephemeral: gost_kex::encode_public_key_like(server_algorithm_id, curve,
                                                   ephemeral_public)?,
        ukm,
    }.encode()
}

pub fn client_key_exchange_2001(curve: &Curve, server_algorithm_id: &[u8],
                                server_public: &Point,
                                client_random: &[u8], server_random: &[u8])
                                -> Result<(Vec<u8>, Vec<u8>), String> {
    let secret = crate::random::bytes(PRELIMINARY_SECRET_LEN)?;
    let (private, public) = curve.generate_key_pair()?;
    let body = wrap_secret_2001(curve, server_algorithm_id, &private, &public,
                                server_public, client_random, server_random,
                                &secret)?;
    Ok((body, secret))
}

pub fn unwrap_secret_2001(curve: &Curve, private: &BigUint,
                          client_random: &[u8], server_random: &[u8],
                          body: &[u8]) -> Result<Vec<u8>, String> {
    let blob = KeyTransportBlob::parse(body)?;
    let (their_curve, ephemeral) = gost_kex::decode_public_key(&blob.ephemeral)?;
    if their_curve.name != curve.name {
        return Err(format!(
            "The ephemeral key is on {}, and the server's key is on {}.",
            their_curve.name, curve.name));
    }
    if ephemeral.is_identity() {
        return Err("The ephemeral public key is the identity.".to_string());
    }

    let ukm = shared_ukm_2001(client_random, server_random);
    // draft-chudov-cryptopro-cptls section 3.6: the server MUST check
    // the UKM in the message against the one it derived, before
    // decrypting. `kimp28147` checks it again as part of the wrapping,
    // but this is the check the document asks for and it is about a
    // different field - the blob's own `ukm`, which a client could
    // have filled in with anything.
    if blob.ukm != ukm {
        return Err("The key transport blob's UKM is not the hash of the two \
                    randoms.".to_string());
    }
    let key = keg_2001(curve, private, &ephemeral, &ukm)?;

    let mut wrapped = blob.ukm.clone();
    wrapped.extend_from_slice(&blob.encrypted);
    wrapped.extend_from_slice(&blob.mac);
    kimp28147(&wrapped, &key, &ukm, SBOX_2001)
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
