/*
HPKE, Hybrid Public Key Encryption: RFC 9180, with the post-quantum KEMs
of draft-ietf-hpke-pq-05 and the one-stage KDFs that draft and
draft-ietf-hpke-hpke define.

A sender encrypts to a recipient's public key in two steps. A **KEM**
(key encapsulation mechanism) produces a fresh shared secret and an
encapsulation `enc` only the recipient can turn back into it; a **key
schedule** turns the shared secret, an application's `info` and
optionally a pre-shared key into an AEAD key, a base nonce and an
exporter secret. The sender's context then seals any number of messages,
each with the base nonce XORed with a sequence number; the recipient's
context, built from `enc`, opens them in the same order. A context can
also *export* secrets for the application, labelled by a context string.

    KEMs                                  id      Npk   Nenc  Nsk  Nsecret
    DHKEM(P-256, HKDF-SHA256)           0x0010    65    65   32    32
    DHKEM(P-384, HKDF-SHA384)           0x0011    97    97   48    48
    DHKEM(P-521, HKDF-SHA512)           0x0012   133   133   66    64
    DHKEM(X25519, HKDF-SHA256)          0x0020    32    32   32    32
    DHKEM(X448, HKDF-SHA512)            0x0021    56    56   56    64
    ML-KEM-512                          0x0040   800   768   64    32
    ML-KEM-768                          0x0041  1184  1088   64    32
    ML-KEM-1024                         0x0042  1568  1568   64    32
    MLKEM768-P256                       0x0050  1249  1153   32    32
    MLKEM1024-P384                      0x0051  1665  1665   32    32
    MLKEM768-X25519 (X-Wing)            0x647a  1216  1120   32    32

    KDFs                id               AEADs                 id
    HKDF-SHA256       0x0001             AES-128-GCM         0x0001
    HKDF-SHA384       0x0002             AES-256-GCM         0x0002
    HKDF-SHA512       0x0003             ChaCha20Poly1305    0x0003
    SHAKE128          0x0010             export only         0xffff
    SHAKE256          0x0011

## Modes

`base` (0), `psk` (1) - a pre-shared key and its identifier, both or
neither - and with a DHKEM `auth` (2) and `auth_psk` (3), in which the
sender's own static key enters the KEM so the recipient learns who sent
it. The mode is not a parameter here: it follows from what is given, a
PSK and a sender key, so a caller cannot ask for one mode and supply the
inputs of another. draft-ietf-hpke-hpke drops the auth modes; with a
one-stage KDF they are refused, since nothing defines them.

## Two kinds of KDF

The HKDFs are *two-stage*: `LabeledExtract` then `LabeledExpand`, with
the key, nonce and exporter secret each expanded separately from one
extracted secret. The SHAKEs are *one-stage*: a single `LabeledDerive`
call over length-prefixed inputs produces all three at once. Both kinds
prefix every input with `"HPKE-v1"` and a suite identifier - `"KEM"` and
the KEM's id inside a KEM, `"HPKE"` and all three ids outside it - so no
two uses of the KDF can collide.

A DHKEM always uses its own HKDF, whatever KDF the suite names; the
ML-KEM and hybrid KEMs derive their keys with SHAKE256's
`LabeledDerive`, also whatever the suite names.

## Determinism

Every function that needs randomness takes it as bytes: a key pair is
derived from input keying material (`derive_key_pair`), and an
encapsulation from `randomness` - for a DHKEM the ephemeral key pair's
`ikm`, for ML-KEM the 32 byte message `m`, for a hybrid `m` followed by
candidates for the ephemeral curve key (`Kem::encap_randomness_len`).
That is what the published vectors state, and it is what makes them
testable here; `generate_key_pair`, `setup_sender` and `seal` draw the
bytes from the OS generator.
*/

use crate::bignum::BigUint;
use crate::ec::{curves, x25519, x448, Curve};
use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::sha2::{SHA256, SHA384, SHA512};
use crate::hash_functions::HashFunction;
use crate::kdf::{hkdf_expand, hkdf_extract};
use crate::pq::ml_kem;

/// A key encapsulation mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kem {
    P256,
    P384,
    P521,
    X25519,
    X448,
    MlKem512,
    MlKem768,
    MlKem1024,
    MlKem768P256,
    MlKem1024P384,
    MlKem768X25519,
}

/// A key derivation function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
    Shake128,
    Shake256,
    TurboShake128,
    TurboShake256,
}

/// An AEAD, or none: an export-only context seals nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    ExportOnly,
}

/// The four modes, by the byte the key schedule takes.
pub const MODE_BASE: u8 = 0;
pub const MODE_PSK: u8 = 1;
pub const MODE_AUTH: u8 = 2;
pub const MODE_AUTH_PSK: u8 = 3;

const HPKE_V1: &[u8] = b"HPKE-v1";

fn length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let length = u16::try_from(bytes.len()).map_err(|_| format!(
        "HPKE: a one-stage KDF takes inputs of at most 65535 bytes; this one is {}.",
        bytes.len()))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A name as the documents print it, or a short spelling: lower case,
/// with spaces, parentheses, commas and hyphens dropped.
fn squash(name: &str) -> String {
    name.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
}

impl Kdf {
    pub const ALL: [Kdf; 7] = [Kdf::HkdfSha256, Kdf::HkdfSha384, Kdf::HkdfSha512, Kdf::Shake128,
                               Kdf::Shake256, Kdf::TurboShake128, Kdf::TurboShake256];

    /// `"HKDF-SHA256"`, `"hkdf-sha256"`, `"SHAKE256"`; or the id in hex,
    /// `"0x0001"`.
    pub fn from_name(name: &str) -> Result<Kdf, String> {
        if let Some(id) = parse_id(name) {
            return Kdf::from_id(id);
        }
        let wanted = squash(name);
        Kdf::ALL.into_iter().find(|k| squash(k.name()) == wanted)
            .ok_or_else(|| format!("HPKE: no KDF is called {name:?}; the KDFs are {}.",
                                   Kdf::ALL.map(|k| k.name()).join(", ")))
    }

    pub fn from_id(id: u16) -> Result<Kdf, String> {
        Ok(match id {
            0x0001 => Kdf::HkdfSha256,
            0x0002 => Kdf::HkdfSha384,
            0x0003 => Kdf::HkdfSha512,
            0x0010 => Kdf::Shake128,
            0x0011 => Kdf::Shake256,
            0x0012 => Kdf::TurboShake128,
            0x0013 => Kdf::TurboShake256,
            other => return Err(format!("HPKE: no KDF has the id {other:#06x}.")),
        })
    }

    pub fn id(self) -> u16 {
        match self {
            Kdf::HkdfSha256 => 0x0001,
            Kdf::HkdfSha384 => 0x0002,
            Kdf::HkdfSha512 => 0x0003,
            Kdf::Shake128 => 0x0010,
            Kdf::Shake256 => 0x0011,
            Kdf::TurboShake128 => 0x0012,
            Kdf::TurboShake256 => 0x0013,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kdf::HkdfSha256 => "HKDF-SHA256",
            Kdf::HkdfSha384 => "HKDF-SHA384",
            Kdf::HkdfSha512 => "HKDF-SHA512",
            Kdf::Shake128 => "SHAKE128",
            Kdf::Shake256 => "SHAKE256",
            Kdf::TurboShake128 => "TurboSHAKE128",
            Kdf::TurboShake256 => "TurboSHAKE256",
        }
    }

    /// `Nh`: the hash's output length, or the size a one-stage KDF
    /// declares for its exporter secret.
    pub fn hash_len(self) -> usize {
        match self {
            Kdf::HkdfSha256 | Kdf::Shake128 | Kdf::TurboShake128 => 32,
            Kdf::HkdfSha384 => 48,
            Kdf::HkdfSha512 | Kdf::Shake256 | Kdf::TurboShake256 => 64,
        }
    }

    pub fn one_stage(self) -> bool {
        matches!(self, Kdf::Shake128 | Kdf::Shake256 | Kdf::TurboShake128 | Kdf::TurboShake256)
    }

    fn extract(self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, String> {
        Ok(match self {
            Kdf::HkdfSha256 => hkdf_extract(SHA256::new(&[]), salt, ikm),
            Kdf::HkdfSha384 => hkdf_extract(SHA384::new(&[]), salt, ikm),
            Kdf::HkdfSha512 => hkdf_extract(SHA512::new(&[], 512), salt, ikm),
            other => return Err(format!("HPKE: {} is one-stage and has no Extract.",
                                        other.name())),
        })
    }

    fn expand(self, prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, String> {
        match self {
            Kdf::HkdfSha256 => hkdf_expand(SHA256::new(&[]), prk, info, length),
            Kdf::HkdfSha384 => hkdf_expand(SHA384::new(&[]), prk, info, length),
            Kdf::HkdfSha512 => hkdf_expand(SHA512::new(&[], 512), prk, info, length),
            other => Err(format!("HPKE: {} is one-stage and has no Expand.", other.name())),
        }
    }

    /// `LabeledExtract(salt, label, ikm)`.
    fn labeled_extract(self, suite_id: &[u8], salt: &[u8], label: &str, ikm: &[u8])
                       -> Result<Vec<u8>, String> {
        let mut labeled = HPKE_V1.to_vec();
        labeled.extend_from_slice(suite_id);
        labeled.extend_from_slice(label.as_bytes());
        labeled.extend_from_slice(ikm);
        self.extract(salt, &labeled)
    }

    /// `LabeledExpand(prk, label, info, L)`.
    fn labeled_expand(self, suite_id: &[u8], prk: &[u8], label: &str, info: &[u8],
                      length: usize) -> Result<Vec<u8>, String> {
        let l = u16::try_from(length).map_err(|_| format!(
            "HPKE: {length} bytes is more than a labeled expansion encodes."))?;
        let mut labeled = l.to_be_bytes().to_vec();
        labeled.extend_from_slice(HPKE_V1);
        labeled.extend_from_slice(suite_id);
        labeled.extend_from_slice(label.as_bytes());
        labeled.extend_from_slice(info);
        self.expand(prk, &labeled, length)
    }

    /// `LabeledDerive(ikm, label, context, L)`, the one-stage KDFs' only
    /// function: the KDF of `ikm || "HPKE-v1" || suite_id ||
    /// lengthPrefixed(label) || I2OSP(L, 2) || context`. TurboSHAKE's
    /// `Derive` is `TurboSHAKE(M = ikm, D = 0x1F, L)` (draft-ietf-hpke-pq).
    fn labeled_derive(self, suite_id: &[u8], ikm: &[u8], label: &str, context: &[u8],
                      length: usize) -> Result<Vec<u8>, String> {
        let l = u16::try_from(length).map_err(|_| format!(
            "HPKE: {length} bytes is more than a labeled derivation encodes."))?;
        let mut sponge = match self {
            Kdf::Shake128 => Keccak::shake(128, length)?,
            Kdf::Shake256 => Keccak::shake(256, length)?,
            Kdf::TurboShake128 => Keccak::turboshake(128, 0x1f, length)?,
            Kdf::TurboShake256 => Keccak::turboshake(256, 0x1f, length)?,
            other => return Err(format!("HPKE: {} is two-stage and has no Derive.",
                                        other.name())),
        };
        sponge.update(ikm);
        sponge.update(HPKE_V1);
        sponge.update(suite_id);
        let mut label_field = Vec::new();
        length_prefixed(&mut label_field, label.as_bytes())?;
        sponge.update(&label_field);
        sponge.update(&l.to_be_bytes());
        sponge.update(context);
        Ok(sponge.squeeze(length))
    }
}

impl Aead {
    pub const ALL: [Aead; 4] = [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305,
                                Aead::ExportOnly];

    /// `"AES-128-GCM"`, `"chacha20-poly1305"`, `"export-only"`; or the
    /// id in hex.
    pub fn from_name(name: &str) -> Result<Aead, String> {
        if let Some(id) = parse_id(name) {
            return Aead::from_id(id);
        }
        let wanted = squash(name);
        Aead::ALL.into_iter().find(|a| squash(a.name()) == wanted)
            .ok_or_else(|| format!("HPKE: no AEAD is called {name:?}; the AEADs are {}.",
                                   Aead::ALL.map(|a| a.name()).join(", ")))
    }

    pub fn from_id(id: u16) -> Result<Aead, String> {
        Ok(match id {
            0x0001 => Aead::Aes128Gcm,
            0x0002 => Aead::Aes256Gcm,
            0x0003 => Aead::ChaCha20Poly1305,
            0xffff => Aead::ExportOnly,
            other => return Err(format!("HPKE: no AEAD has the id {other:#06x}.")),
        })
    }

    pub fn id(self) -> u16 {
        match self {
            Aead::Aes128Gcm => 0x0001,
            Aead::Aes256Gcm => 0x0002,
            Aead::ChaCha20Poly1305 => 0x0003,
            Aead::ExportOnly => 0xffff,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Aead::Aes128Gcm => "AES-128-GCM",
            Aead::Aes256Gcm => "AES-256-GCM",
            Aead::ChaCha20Poly1305 => "ChaCha20Poly1305",
            Aead::ExportOnly => "export only",
        }
    }

    /// `Nk`.
    pub fn key_len(self) -> usize {
        match self {
            Aead::Aes128Gcm => 16,
            Aead::Aes256Gcm | Aead::ChaCha20Poly1305 => 32,
            Aead::ExportOnly => 0,
        }
    }

    /// `Nn`.
    pub fn nonce_len(self) -> usize {
        if self == Aead::ExportOnly { 0 } else { 12 }
    }

    /// `Nt`.
    pub fn tag_len(self) -> usize {
        if self == Aead::ExportOnly { 0 } else { 16 }
    }

    fn library_name(self) -> Result<&'static str, String> {
        match self {
            Aead::Aes128Gcm | Aead::Aes256Gcm => Ok("aes-gcm"),
            Aead::ChaCha20Poly1305 => Ok("chacha20-poly1305"),
            Aead::ExportOnly => Err("HPKE: an export-only context seals and opens nothing."
                .to_string()),
        }
    }
}

/// The curve, or Montgomery function, under a KEM's classical part.
enum Group {
    Nist(Curve, u8),
    X25519,
    X448,
}

impl Group {
    fn public_len(&self) -> usize {
        match self {
            Group::Nist(curve, _) => 1 + 2 * curve.field_bytes(),
            Group::X25519 => 32,
            Group::X448 => 56,
        }
    }

    fn private_len(&self) -> usize {
        match self {
            Group::Nist(curve, _) => curve.scalar_bytes(),
            Group::X25519 => 32,
            Group::X448 => 56,
        }
    }

    /// A NIST curve's private key as a scalar in `[1, n)`, or `None`.
    fn scalar(curve: &Curve, bytes: &[u8]) -> Option<BigUint> {
        let scalar = BigUint::from_bytes_be(bytes);
        (!scalar.is_zero() && scalar < curve.n).then_some(scalar)
    }

    /// `pk(sk)`, serialized.
    fn public_key(&self, private: &[u8]) -> Result<Vec<u8>, String> {
        if private.len() != self.private_len() {
            return Err(format!("HPKE: a private key here is {} bytes, not {}.",
                               self.private_len(), private.len()));
        }
        match self {
            Group::Nist(curve, _) => {
                let scalar = Group::scalar(curve, private)
                    .ok_or("HPKE: the private key is not in [1, n).")?;
                curve.encode_point(&curve.generator_mul(&scalar), false)
            }
            Group::X25519 => Ok(x25519::public_key(&array(private)?)?.to_vec()),
            Group::X448 => Ok(x448::public_key(&array(private)?)?.to_vec()),
        }
    }

    /// `DH(sk, pk)`: a NIST curve's shared x coordinate, or the X25519
    /// or X448 output, the all-zero output refused.
    fn dh(&self, private: &[u8], public: &[u8]) -> Result<Vec<u8>, String> {
        if public.len() != self.public_len() {
            return Err(format!("HPKE: a public key here is {} bytes, not {}.",
                               self.public_len(), public.len()));
        }
        match self {
            Group::Nist(curve, _) => {
                let scalar = Group::scalar(curve, private)
                    .ok_or("HPKE: the private key is not in [1, n).")?;
                curve.ecdh(&scalar, &curve.decode_point(public)?)
            }
            Group::X25519 => Ok(x25519::exchange(&array(private)?, &array(public)?)?.to_vec()),
            Group::X448 => Ok(x448::exchange(&array(private)?, &array(public)?)?.to_vec()),
        }
    }

    /// The first of `candidates` (each `private_len` bytes) that is a
    /// private key: any of them for X25519 and X448, a scalar in
    /// `[1, n)` for a NIST curve - the rejection sampling the hybrid
    /// KEMs use, with no mask.
    fn first_valid<'a>(&self, candidates: &'a [u8]) -> Result<&'a [u8], String> {
        let size = self.private_len();
        for candidate in candidates.chunks_exact(size) {
            match self {
                Group::Nist(curve, _) if Group::scalar(curve, candidate).is_none() => continue,
                _ => return Ok(candidate),
            }
        }
        Err("HPKE: none of the candidates is a private key on the curve; more randomness \
             is needed.".to_string())
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| format!("HPKE: expected {N} bytes, found {}.", bytes.len()))
}

/// `"0x0010"`: an id, in hex with its prefix.
fn parse_id(name: &str) -> Option<u16> {
    name.strip_prefix("0x").and_then(|hex| u16::from_str_radix(hex, 16).ok())
}

impl Kem {
    pub const ALL: [Kem; 11] = [Kem::P256, Kem::P384, Kem::P521, Kem::X25519, Kem::X448,
                                Kem::MlKem512, Kem::MlKem768, Kem::MlKem1024, Kem::MlKem768P256,
                                Kem::MlKem1024P384, Kem::MlKem768X25519];

    /// The document's name (`"DHKEM(X25519, HKDF-SHA256)"`,
    /// `"MLKEM768-P256"`), the group or parameter set alone (`"X25519"`,
    /// `"P-256"`, `"ML-KEM-768"`), `"X-Wing"`, or the id in hex.
    pub fn from_name(name: &str) -> Result<Kem, String> {
        if let Some(id) = parse_id(name) {
            return Kem::from_id(id);
        }
        let wanted = squash(name);
        if wanted == "xwing" {
            return Ok(Kem::MlKem768X25519);
        }
        Kem::ALL.into_iter().find(|k| {
            let full = squash(k.name());
            let short = full.strip_prefix("dhkem").map(|rest| rest.split("hkdf").next()
                .unwrap_or(rest).to_string());
            full == wanted || short.as_deref() == Some(wanted.as_str())
        }).ok_or_else(|| format!("HPKE: no KEM is called {name:?}; the KEMs are {}.",
                                 Kem::ALL.map(|k| k.name()).join(", ")))
    }

    pub fn from_id(id: u16) -> Result<Kem, String> {
        Ok(match id {
            0x0010 => Kem::P256,
            0x0011 => Kem::P384,
            0x0012 => Kem::P521,
            0x0020 => Kem::X25519,
            0x0021 => Kem::X448,
            0x0040 => Kem::MlKem512,
            0x0041 => Kem::MlKem768,
            0x0042 => Kem::MlKem1024,
            0x0050 => Kem::MlKem768P256,
            0x0051 => Kem::MlKem1024P384,
            0x647a => Kem::MlKem768X25519,
            other => return Err(format!("HPKE: no KEM has the id {other:#06x}.")),
        })
    }

    pub fn id(self) -> u16 {
        match self {
            Kem::P256 => 0x0010,
            Kem::P384 => 0x0011,
            Kem::P521 => 0x0012,
            Kem::X25519 => 0x0020,
            Kem::X448 => 0x0021,
            Kem::MlKem512 => 0x0040,
            Kem::MlKem768 => 0x0041,
            Kem::MlKem1024 => 0x0042,
            Kem::MlKem768P256 => 0x0050,
            Kem::MlKem1024P384 => 0x0051,
            Kem::MlKem768X25519 => 0x647a,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kem::P256 => "DHKEM(P-256, HKDF-SHA256)",
            Kem::P384 => "DHKEM(P-384, HKDF-SHA384)",
            Kem::P521 => "DHKEM(P-521, HKDF-SHA512)",
            Kem::X25519 => "DHKEM(X25519, HKDF-SHA256)",
            Kem::X448 => "DHKEM(X448, HKDF-SHA512)",
            Kem::MlKem512 => "ML-KEM-512",
            Kem::MlKem768 => "ML-KEM-768",
            Kem::MlKem1024 => "ML-KEM-1024",
            Kem::MlKem768P256 => "MLKEM768-P256",
            Kem::MlKem1024P384 => "MLKEM1024-P384",
            Kem::MlKem768X25519 => "MLKEM768-X25519",
        }
    }

    fn suite_id(self) -> Vec<u8> {
        let mut id = b"KEM".to_vec();
        id.extend_from_slice(&self.id().to_be_bytes());
        id
    }

    /// A DHKEM's HKDF and group.
    fn dhkem(self) -> Option<(Kdf, Group)> {
        Some(match self {
            Kem::P256 => (Kdf::HkdfSha256, Group::Nist(curves::p256(), 0xff)),
            Kem::P384 => (Kdf::HkdfSha384, Group::Nist(curves::p384(), 0xff)),
            Kem::P521 => (Kdf::HkdfSha512, Group::Nist(curves::p521(), 0x01)),
            Kem::X25519 => (Kdf::HkdfSha256, Group::X25519),
            Kem::X448 => (Kdf::HkdfSha512, Group::X448),
            _ => return None,
        })
    }

    /// The ML-KEM parameter set, alone or in a hybrid.
    fn ml_kem(self) -> Option<&'static ml_kem::Parameters> {
        let name = match self {
            Kem::MlKem512 => "ML-KEM-512",
            Kem::MlKem768 | Kem::MlKem768P256 | Kem::MlKem768X25519 => "ML-KEM-768",
            Kem::MlKem1024 | Kem::MlKem1024P384 => "ML-KEM-1024",
            _ => return None,
        };
        ml_kem::parameters(name).ok()
    }

    /// A hybrid's classical group and the label its combiner hashes in.
    fn hybrid(self) -> Option<(Group, &'static [u8])> {
        Some(match self {
            Kem::MlKem768P256 => (Group::Nist(curves::p256(), 0xff), b"MLKEM768-P256"),
            Kem::MlKem1024P384 => (Group::Nist(curves::p384(), 0xff), b"MLKEM1024-P384"),
            Kem::MlKem768X25519 => (Group::X25519, b"\\.//^\\"),
            _ => return None,
        })
    }

    /// Whether the KEM authenticates a sender (the DHKEMs).
    pub fn supports_auth(self) -> bool {
        self.dhkem().is_some()
    }

    /// `Npk`.
    pub fn public_len(self) -> usize {
        if let Some((_, group)) = self.dhkem() {
            return group.public_len();
        }
        let ek = self.ml_kem().map(|p| p.encapsulation_key_len()).unwrap_or(0);
        ek + self.hybrid().map(|(g, _)| g.public_len()).unwrap_or(0)
    }

    /// `Nenc`.
    pub fn enc_len(self) -> usize {
        if let Some((_, group)) = self.dhkem() {
            return group.public_len();
        }
        let ct = self.ml_kem().map(|p| p.ciphertext_len()).unwrap_or(0);
        ct + self.hybrid().map(|(g, _)| g.public_len()).unwrap_or(0)
    }

    /// `Nsk`: a DHKEM's scalar, ML-KEM's 64 byte seed, a hybrid's 32
    /// byte seed.
    pub fn private_len(self) -> usize {
        match (self.dhkem(), self.hybrid()) {
            (Some((_, group)), _) => group.private_len(),
            (None, Some(_)) => 32,
            (None, None) => 64,
        }
    }

    /// `Nsecret`.
    pub fn secret_len(self) -> usize {
        match self.dhkem() {
            Some((kdf, _)) => kdf.hash_len(),
            None => 32,
        }
    }

    /// How many bytes of randomness `encap` takes: a DHKEM's `ikm` for
    /// the ephemeral key (`Nsk` bytes), ML-KEM's `m`, a hybrid's `m` and
    /// then the curve's candidates - two, of which the second is needed
    /// with probability about 2^-32 for P-256 and 2^-190 for P-384.
    pub fn encap_randomness_len(self) -> usize {
        match (self.dhkem(), self.hybrid()) {
            (Some((_, group)), _) => group.private_len(),
            (None, Some((Group::X25519, _))) => 64,
            (None, Some((group, _))) => 32 + 2 * group.private_len(),
            (None, None) => 32,
        }
    }

    /// `DeriveKeyPair(ikm)`: `(private, public)`, both serialized. A
    /// DHKEM hashes `ikm` with its HKDF into a scalar - rejection sampled
    /// on a NIST curve - or into X25519's or X448's key; ML-KEM derives
    /// its 64 byte seed and a hybrid its 32 byte seed with SHAKE256.
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let suite_id = self.suite_id();
        if let Some((kdf, group)) = self.dhkem() {
            let prk = kdf.labeled_extract(&suite_id, b"", "dkp_prk", ikm)?;
            let private = match &group {
                Group::Nist(curve, mask) => {
                    let mut found = None;
                    for counter in 0..=255u8 {
                        let mut bytes = kdf.labeled_expand(&suite_id, &prk, "candidate",
                                                           &[counter], group.private_len())?;
                        bytes[0] &= mask;
                        if Group::scalar(curve, &bytes).is_some() {
                            found = Some(bytes);
                            break;
                        }
                    }
                    found.ok_or("HPKE: DeriveKeyPair found no scalar in 256 tries.")?
                }
                _ => kdf.labeled_expand(&suite_id, &prk, "sk", b"", group.private_len())?,
            };
            let public = group.public_key(&private)?;
            return Ok((private, public));
        }
        let seed = Kdf::Shake256.labeled_derive(&suite_id, ikm, "DeriveKeyPair", b"",
                                                self.private_len())?;
        let public = self.public_key(&seed)?;
        Ok((seed, public))
    }

    /// `GenerateKeyPair()`: `derive_key_pair` of `Nsk` random bytes.
    pub fn generate_key_pair(self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut ikm = vec![0u8; self.private_len()];
        crate::random::fill(&mut ikm)?;
        self.derive_key_pair(&ikm)
    }

    /// An ML-KEM seed expanded: `(ek, dk)`.
    fn ml_kem_keys(parameters: &'static ml_kem::Parameters, seed: &[u8])
                   -> Result<(Vec<u8>, Vec<u8>), String> {
        if seed.len() != 64 {
            return Err(format!("HPKE: an ML-KEM private key is a 64 byte seed, not {} bytes.",
                               seed.len()));
        }
        ml_kem::key_gen_internal(parameters, &seed[..32], &seed[32..])
    }

    /// A hybrid's 32 byte seed expanded by SHAKE256: ML-KEM's 64 byte
    /// seed, then the classical key - X25519's next 32 bytes, or the
    /// first of the next candidates that is a scalar in `[1, n)`.
    fn hybrid_keys(self, seed: &[u8]) -> Result<HybridKeys, String> {
        let (group, _) = self.hybrid().ok_or("hybrid")?;
        let parameters = self.ml_kem().ok_or("ml_kem")?;
        if seed.len() != 32 {
            return Err(format!("HPKE: a {} private key is a 32 byte seed, not {} bytes.",
                               self.name(), seed.len()));
        }
        // Enough for 64 candidates; the chance that P-256 needs more is
        // 2^-2048.
        let mut sponge = Keccak::shake(256, 64 + 64 * group.private_len())?;
        sponge.update(seed);
        let stream = sponge.digest();
        let (ek, dk) = Kem::ml_kem_keys(parameters, &stream[..64])?;
        let private = group.first_valid(&stream[64..])?.to_vec();
        let public = group.public_key(&private)?;
        Ok(HybridKeys { ek, dk, private, public })
    }

    /// `pk(sk)`.
    pub fn public_key(self, private: &[u8]) -> Result<Vec<u8>, String> {
        if let Some((_, group)) = self.dhkem() {
            return group.public_key(private);
        }
        if self.hybrid().is_some() {
            let HybridKeys { mut ek, public, .. } = self.hybrid_keys(private)?;
            ek.extend_from_slice(&public);
            return Ok(ek);
        }
        Ok(Kem::ml_kem_keys(self.ml_kem().ok_or("ml_kem")?, private)?.0)
    }

    fn check_randomness(self, randomness: &[u8], least: usize) -> Result<(), String> {
        if randomness.len() < least {
            return Err(format!("HPKE: {} encapsulation takes {} bytes of randomness; {} \
                                given.", self.name(), least, randomness.len()));
        }
        Ok(())
    }

    /// `Encap(pkR)` (or with `sender`, the DHKEM's `AuthEncap(pkR, skS)`),
    /// derandomized: `(shared secret, enc)`.
    pub fn encap(self, public: &[u8], sender: Option<&[u8]>, randomness: &[u8])
                 -> Result<(Vec<u8>, Vec<u8>), String> {
        if public.len() != self.public_len() {
            return Err(format!("HPKE: a {} public key is {} bytes, not {}.", self.name(),
                               self.public_len(), public.len()));
        }
        if let Some((kdf, group)) = self.dhkem() {
            self.check_randomness(randomness, group.private_len())?;
            let (ephemeral, enc) = self.derive_key_pair(randomness)?;
            let mut dh = group.dh(&ephemeral, public)?;
            let mut context = enc.clone();
            context.extend_from_slice(public);
            if let Some(sender) = sender {
                dh.extend_from_slice(&group.dh(sender, public)?);
                context.extend_from_slice(&group.public_key(sender)?);
            }
            return Ok((self.extract_and_expand(kdf, &dh, &context)?, enc));
        }
        if sender.is_some() {
            return Err(format!("HPKE: {} does not authenticate a sender; the auth modes \
                                need a DHKEM.", self.name()));
        }
        let parameters = self.ml_kem().ok_or("ml_kem")?;
        let ek_len = parameters.encapsulation_key_len();
        let (ek, rest) = public.split_at(ek_len);
        self.check_randomness(randomness, 32)?;
        let (ss_pq, mut enc) = ml_kem::encapsulate_internal(parameters, ek, &randomness[..32])
            .map_err(|e| format!("HPKE: {e}"))?;
        let Some((group, label)) = self.hybrid() else {
            return Ok((ss_pq, enc));
        };
        let candidates = randomness.get(32..).unwrap_or(&[]);
        self.check_randomness(randomness, 32 + group.private_len())?;
        let ephemeral = group.first_valid(candidates)?;
        let ct_t = group.public_key(ephemeral)?;
        let ss_t = group.dh(ephemeral, rest)?;
        enc.extend_from_slice(&ct_t);
        Ok((Kem::combine(&ss_pq, &ss_t, &ct_t, rest, label), enc))
    }

    /// `Encap(pkR)` with randomness from the OS generator.
    pub fn encap_random(self, public: &[u8], sender: Option<&[u8]>)
                        -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut randomness = vec![0u8; self.encap_randomness_len()];
        crate::random::fill(&mut randomness)?;
        self.encap(public, sender, &randomness)
    }

    /// `Decap(enc, skR)` (or with `sender`, `AuthDecap(enc, skR, pkS)`).
    pub fn decap(self, enc: &[u8], private: &[u8], sender: Option<&[u8]>)
                 -> Result<Vec<u8>, String> {
        if enc.len() != self.enc_len() {
            return Err(format!("HPKE: a {} encapsulation is {} bytes, not {}.", self.name(),
                               self.enc_len(), enc.len()));
        }
        if let Some((kdf, group)) = self.dhkem() {
            let mut dh = group.dh(private, enc)?;
            let mut context = enc.to_vec();
            context.extend_from_slice(&group.public_key(private)?);
            if let Some(sender) = sender {
                dh.extend_from_slice(&group.dh(private, sender)?);
                context.extend_from_slice(sender);
            }
            return self.extract_and_expand(kdf, &dh, &context);
        }
        if sender.is_some() {
            return Err(format!("HPKE: {} does not authenticate a sender; the auth modes \
                                need a DHKEM.", self.name()));
        }
        let parameters = self.ml_kem().ok_or("ml_kem")?;
        let ct_len = parameters.ciphertext_len();
        let Some((group, label)) = self.hybrid() else {
            let (_, dk) = Kem::ml_kem_keys(parameters, private)?;
            return ml_kem::decapsulate_internal(parameters, &dk, enc)
                .map_err(|e| format!("HPKE: {e}"));
        };
        let keys = self.hybrid_keys(private)?;
        let (ct_pq, ct_t) = enc.split_at(ct_len);
        let ss_pq = ml_kem::decapsulate_internal(parameters, &keys.dk, ct_pq)
            .map_err(|e| format!("HPKE: {e}"))?;
        let ss_t = group.dh(&keys.private, ct_t)?;
        Ok(Kem::combine(&ss_pq, &ss_t, ct_t, &keys.public, label))
    }

    /// The hybrids' combiner: SHA3-256 of both shared secrets, the
    /// classical ciphertext and public key, and the KEM's label.
    fn combine(ss_pq: &[u8], ss_t: &[u8], ct_t: &[u8], pk_t: &[u8], label: &[u8]) -> Vec<u8> {
        let mut h = Keccak::sha3(32).expect("SHA3-256");
        for part in [ss_pq, ss_t, ct_t, pk_t, label] {
            h.update(part);
        }
        h.digest()
    }

    /// A DHKEM's `ExtractAndExpand(dh, kem_context)`.
    fn extract_and_expand(self, kdf: Kdf, dh: &[u8], context: &[u8])
                          -> Result<Vec<u8>, String> {
        let suite_id = self.suite_id();
        let prk = kdf.labeled_extract(&suite_id, b"", "eae_prk", dh)?;
        kdf.labeled_expand(&suite_id, &prk, "shared_secret", context, self.secret_len())
    }
}

/// A hybrid KEM's keys, expanded from its seed: ML-KEM's encapsulation
/// and decapsulation keys, and the classical private and public keys.
struct HybridKeys {
    ek: Vec<u8>,
    dk: Vec<u8>,
    private: Vec<u8>,
    public: Vec<u8>,
}

/// A ciphersuite: one KEM, KDF and AEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suite {
    pub kem: Kem,
    pub kdf: Kdf,
    pub aead: Aead,
}

/// What a setup may take beyond the keys: the pre-shared key and its
/// identifier (`psk` mode), and the sender's key - its private key to
/// seal, its public key to open (`auth` mode).
#[derive(Clone, Copy, Default)]
pub struct Options<'a> {
    pub psk: Option<(&'a [u8], &'a [u8])>,
    pub sender: Option<&'a [u8]>,
}

impl Suite {
    pub fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Suite {
        Suite { kem, kdf, aead }
    }

    pub fn from_ids(kem: u16, kdf: u16, aead: u16) -> Result<Suite, String> {
        Ok(Suite { kem: Kem::from_id(kem)?, kdf: Kdf::from_id(kdf)?, aead: Aead::from_id(aead)? })
    }

    fn suite_id(&self) -> Vec<u8> {
        let mut id = b"HPKE".to_vec();
        id.extend_from_slice(&self.kem.id().to_be_bytes());
        id.extend_from_slice(&self.kdf.id().to_be_bytes());
        id.extend_from_slice(&self.aead.id().to_be_bytes());
        id
    }

    /// The mode the options make, after `VerifyPSKInputs`: a PSK and its
    /// identifier both or neither, and neither of them empty.
    fn mode(&self, options: &Options) -> Result<u8, String> {
        if let Some((psk, psk_id)) = options.psk {
            if psk.is_empty() || psk_id.is_empty() {
                return Err("HPKE: a pre-shared key and its identifier come together, and \
                            neither may be empty.".to_string());
            }
        }
        if options.sender.is_some() {
            if !self.kem.supports_auth() {
                return Err(format!("HPKE: {} does not authenticate a sender; the auth modes \
                                    need a DHKEM.", self.kem.name()));
            }
            if self.kdf.one_stage() {
                return Err(format!("HPKE: the auth modes are not defined with {}, a \
                                    one-stage KDF.", self.kdf.name()));
            }
        }
        Ok(match (options.psk.is_some(), options.sender.is_some()) {
            (false, false) => MODE_BASE,
            (true, false) => MODE_PSK,
            (false, true) => MODE_AUTH,
            (true, true) => MODE_AUTH_PSK,
        })
    }

    /// `KeySchedule`: the AEAD key, base nonce and exporter secret.
    fn key_schedule(&self, mode: u8, shared_secret: &[u8], info: &[u8], options: &Options)
                    -> Result<Context, String> {
        let (psk, psk_id) = options.psk.unwrap_or((b"", b""));
        let suite_id = self.suite_id();
        let (nk, nn, nh) = (self.aead.key_len(), self.aead.nonce_len(), self.kdf.hash_len());
        let (key, base_nonce, exporter_secret) = if self.kdf.one_stage() {
            let mut secrets = Vec::new();
            length_prefixed(&mut secrets, psk)?;
            length_prefixed(&mut secrets, shared_secret)?;
            let mut context = vec![mode];
            length_prefixed(&mut context, psk_id)?;
            length_prefixed(&mut context, info)?;
            let secret = self.kdf.labeled_derive(&suite_id, &secrets, "secret", &context,
                                                 nk + nn + nh)?;
            (secret[..nk].to_vec(), secret[nk..nk + nn].to_vec(), secret[nk + nn..].to_vec())
        } else {
            let psk_id_hash = self.kdf.labeled_extract(&suite_id, b"", "psk_id_hash", psk_id)?;
            let info_hash = self.kdf.labeled_extract(&suite_id, b"", "info_hash", info)?;
            let mut context = vec![mode];
            context.extend_from_slice(&psk_id_hash);
            context.extend_from_slice(&info_hash);
            let secret = self.kdf.labeled_extract(&suite_id, shared_secret, "secret", psk)?;
            (self.kdf.labeled_expand(&suite_id, &secret, "key", &context, nk)?,
             self.kdf.labeled_expand(&suite_id, &secret, "base_nonce", &context, nn)?,
             self.kdf.labeled_expand(&suite_id, &secret, "exp", &context, nh)?)
        };
        Ok(Context { suite: *self, key, base_nonce, exporter_secret, sequence: 0 })
    }

    /// `SetupS`, derandomized: `(enc, context)`. `randomness` is
    /// `Kem::encap_randomness_len` bytes or more.
    pub fn setup_sender_with(&self, public: &[u8], info: &[u8], options: &Options,
                             randomness: &[u8]) -> Result<(Vec<u8>, Context), String> {
        let mode = self.mode(options)?;
        let (shared_secret, enc) = self.kem.encap(public, options.sender, randomness)?;
        Ok((enc, self.key_schedule(mode, &shared_secret, info, options)?))
    }

    /// `SetupS`, with randomness from the OS generator.
    pub fn setup_sender(&self, public: &[u8], info: &[u8], options: &Options)
                        -> Result<(Vec<u8>, Context), String> {
        let mut randomness = vec![0u8; self.kem.encap_randomness_len()];
        crate::random::fill(&mut randomness)?;
        self.setup_sender_with(public, info, options, &randomness)
    }

    /// `SetupR`.
    pub fn setup_receiver(&self, enc: &[u8], private: &[u8], info: &[u8], options: &Options)
                          -> Result<Context, String> {
        let mode = self.mode(options)?;
        let shared_secret = self.kem.decap(enc, private, options.sender)?;
        self.key_schedule(mode, &shared_secret, info, options)
    }

    /// Single-shot `Seal`: `(enc, ciphertext)`.
    pub fn seal(&self, public: &[u8], info: &[u8], aad: &[u8], plaintext: &[u8],
                options: &Options) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (enc, mut context) = self.setup_sender(public, info, options)?;
        Ok((enc, context.seal(aad, plaintext)?))
    }

    /// Single-shot `Open`.
    pub fn open(&self, enc: &[u8], private: &[u8], info: &[u8], aad: &[u8], ciphertext: &[u8],
                options: &Options) -> Result<Vec<u8>, String> {
        self.setup_receiver(enc, private, info, options)?.open(aad, ciphertext)
    }
}

/// A sender's or recipient's context.
pub struct Context {
    suite: Suite,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    sequence: u64,
}

impl Context {
    /// The AEAD key, for tests that check the key schedule.
    pub fn key(&self) -> &[u8] { &self.key }
    pub fn base_nonce(&self) -> &[u8] { &self.base_nonce }
    pub fn exporter_secret(&self) -> &[u8] { &self.exporter_secret }
    /// The sequence number of the next message.
    pub fn sequence(&self) -> u64 { self.sequence }

    /// The next message's nonce: the base nonce XORed with the sequence
    /// number, right-aligned.
    fn nonce(&self) -> Vec<u8> {
        let mut nonce = self.base_nonce.clone();
        let sequence = self.sequence.to_be_bytes();
        let n = nonce.len();
        for (i, byte) in sequence.iter().enumerate() {
            if n + i >= 8 {
                nonce[n + i - 8] ^= byte;
            }
        }
        nonce
    }

    /// RFC 9180 stops a context before its sequence number wraps:
    /// reusing a nonce would be the one thing an AEAD cannot survive.
    /// The limit here is 2^64 - 1 messages rather than the nonce's
    /// 2^96 - 1; a message at the last number is sealed or opened, then
    /// refused, its result discarded.
    fn advance(&mut self) -> Result<(), String> {
        self.sequence = self.sequence.checked_add(1)
            .ok_or("HPKE: the context's sequence number is exhausted.")?;
        Ok(())
    }

    /// `Seal(aad, pt)`: ciphertext and tag.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let name = self.suite.aead.library_name()?;
        let (mut ciphertext, tag) = crate::api::aead_encrypt(name, &self.key, &self.nonce(),
                                                             aad, plaintext)?;
        ciphertext.extend_from_slice(&tag);
        self.advance()?;
        Ok(ciphertext)
    }

    /// `Open(aad, ct)`. A failure leaves the sequence number where it
    /// was, as RFC 9180 says: the next message is still the one expected.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let name = self.suite.aead.library_name()?;
        let tag_len = self.suite.aead.tag_len();
        if ciphertext.len() < tag_len {
            return Err("HPKE: the ciphertext is shorter than its tag.".to_string());
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - tag_len);
        let plaintext = crate::api::aead_decrypt(name, &self.key, &self.nonce(), aad, body, tag)
            .map_err(|_| "HPKE: the ciphertext does not open: a wrong key, a wrong aad, or a \
                          message out of order.".to_string())?;
        self.advance()?;
        Ok(plaintext)
    }

    /// `Export(exporter_context, L)`.
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, String> {
        let suite_id = self.suite.suite_id();
        let kdf = self.suite.kdf;
        if kdf.one_stage() {
            kdf.labeled_derive(&suite_id, &self.exporter_secret, "sec", exporter_context, length)
        } else {
            if length > 255 * kdf.hash_len() {
                return Err(format!("HPKE: {} exports at most {} bytes.", kdf.name(),
                                   255 * kdf.hash_len()));
            }
            kdf.labeled_expand(&suite_id, &self.exporter_secret, "sec", exporter_context, length)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn unhex(text: &str) -> Vec<u8> {
        if text == "-" {
            return Vec::new();
        }
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `(seq, aad, pt, ct)`.
    type Encryption = (u64, Vec<u8>, Vec<u8>, Vec<u8>);

    /// One vector: its setup fields, then its encryptions and
    /// `(context, L, value)`.
    struct Vector {
        fields: HashMap<String, String>,
        encryptions: Vec<Encryption>,
        exports: Vec<(Vec<u8>, usize, Vec<u8>)>,
    }

    impl Vector {
        fn get(&self, name: &str) -> Vec<u8> {
            unhex(self.fields.get(name).unwrap_or_else(|| panic!("no {name}")))
        }
        fn has(&self, name: &str) -> bool {
            self.fields.get(name).is_some_and(|v| v != "-" && !v.is_empty())
        }
        fn number(&self, name: &str) -> u16 {
            self.fields[name].parse().unwrap()
        }
        fn label(&self) -> String {
            format!("mode {} kem {:#06x} kdf {:#06x} aead {:#06x}", self.fields["mode"],
                    self.number("kem_id"), self.number("kdf_id"), self.number("aead_id"))
        }
    }

    /// RFC 9180's appendix A, read from the vendored text: page headers
    /// and footers and blank lines dropped, each `name: hex` field joined
    /// with the hex lines that continue it, a vector begun at each "Setup
    /// Information" heading.
    fn rfc_vectors() -> Vec<Vector> {
        let text = include_str!("../../rfcs/rfc9180.txt");
        let start = text.find("\nA.1.  DHKEM(X25519").unwrap();
        let end = text[start..].find("\nAcknowledgements").map(|e| start + e)
            .unwrap_or(text.len());
        let is_hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
        let mut tokens: Vec<(String, String)> = Vec::new();
        for raw in text[start..end].lines() {
            let line = raw.trim_end_matches('\u{c}').trim();
            if line.is_empty() || line.starts_with("RFC 9180") || line.ends_with(']')
                && line.contains("[Page") {
                continue;
            }
            if line.starts_with("A.") {
                tokens.push(("#heading".to_string(), line.to_string()));
            } else if let Some((name, value)) = line.split_once(':')
                .filter(|(name, _)| name.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_'
                                                     || b == b' ')) {
                tokens.push((name.trim().to_string(), value.trim().to_string()));
            } else if is_hex(line) {
                tokens.last_mut().unwrap().1.push_str(line);
            } else {
                panic!("RFC 9180 appendix A: {line:?}");
            }
        }
        let mut vectors: Vec<Vector> = Vec::new();
        let mut section = "";
        let mut pending: HashMap<String, String> = HashMap::new();
        let flush = |pending: &mut HashMap<String, String>, vectors: &mut Vec<Vector>,
                     section: &str| {
            if pending.is_empty() {
                return;
            }
            let vector = vectors.last_mut().unwrap();
            match section {
                "encryptions" => vector.encryptions.push((
                    pending["sequence number"].parse().unwrap(), unhex(&pending["aad"]),
                    unhex(&pending["pt"]), unhex(&pending["ct"]))),
                "exports" => vector.exports.push((
                    unhex(&pending["exporter_context"]), pending["L"].parse().unwrap(),
                    unhex(&pending["exported_value"]))),
                _ => vector.fields.extend(pending.drain()),
            }
            pending.clear();
        };
        for (name, value) in tokens {
            if name == "#heading" {
                flush(&mut pending, &mut vectors, section);
                if value.ends_with("Setup Information") {
                    vectors.push(Vector { fields: HashMap::new(), encryptions: Vec::new(),
                                          exports: Vec::new() });
                    section = "setup";
                } else if value.ends_with("Encryptions") {
                    section = "encryptions";
                } else if value.ends_with("Exported Values") {
                    section = "exports";
                } else {
                    section = "";
                }
                continue;
            }
            let starts = matches!(name.as_str(), "sequence number" | "exporter_context");
            if starts {
                flush(&mut pending, &mut vectors, section);
            }
            pending.insert(name, value);
        }
        flush(&mut pending, &mut vectors, section);
        vectors
    }

    /// `vectors/hpke.vec`, from the CFRG's and the PQ draft's files.
    fn file_vectors() -> Vec<Vector> {
        let text = include_str!("../../vectors/hpke.vec");
        text.lines().filter(|l| !l.starts_with('#')).map(|line| {
            let mut fields: HashMap<String, String> = line.split(' ')
                .map(|f| { let (k, v) = f.split_once('=').unwrap(); (k.to_string(), v.to_string()) })
                .collect();
            let encryptions = fields.remove("encryptions").unwrap();
            let exports = fields.remove("exports").unwrap();
            let split = |text: &str| -> Vec<Vec<String>> {
                if text == "-" { return Vec::new(); }
                text.split(',').map(|e| e.split(':').map(str::to_string).collect()).collect()
            };
            Vector {
                fields,
                encryptions: split(&encryptions).into_iter().map(|e| (
                    e[0].parse().unwrap(), unhex(&e[1]), unhex(&e[2]), unhex(&e[3]))).collect(),
                exports: split(&exports).into_iter().map(|e| (
                    unhex(&e[0]), e[1].parse().unwrap(), unhex(&e[2]))).collect(),
            }
        }).collect()
    }

    /// Everything a vector states: the derived key pairs, the sender's
    /// setup from `ikmE` (enc, shared secret, key schedule), the
    /// recipient's from `enc`, each encryption sealed and opened at its
    /// sequence number, and each export from both sides.
    fn check(vector: &Vector) {
        let label = vector.label();
        let suite = Suite::from_ids(vector.number("kem_id"), vector.number("kdf_id"),
                                    vector.number("aead_id")).unwrap();
        let (sk_r, pk_r) = suite.kem.derive_key_pair(&vector.get("ikmR")).unwrap();
        assert_eq!(pk_r, vector.get("pkRm"), "{label}: pkR");
        assert_eq!(sk_r, vector.get("skRm"), "{label}: skR");
        let sender = vector.has("ikmS").then(|| {
            let (sk_s, pk_s) = suite.kem.derive_key_pair(&vector.get("ikmS")).unwrap();
            assert_eq!(pk_s, vector.get("pkSm"), "{label}: pkS");
            (sk_s, pk_s)
        });
        let optional = |name: &str| if vector.has(name) { vector.get(name) } else { Vec::new() };
        let (psk, psk_id) = (optional("psk"), optional("psk_id"));
        let psk = (!psk.is_empty()).then_some((&psk[..], &psk_id[..]));
        let info = optional("info");
        let sending = Options { psk, sender: sender.as_ref().map(|(sk, _)| &sk[..]) };
        let receiving = Options { psk, sender: sender.as_ref().map(|(_, pk)| &pk[..]) };
        let mode = suite.mode(&sending).unwrap();
        assert_eq!(mode.to_string(), vector.fields["mode"], "{label}: mode");

        let (enc, mut sealer) = suite.setup_sender_with(&pk_r, &info, &sending,
                                                        &vector.get("ikmE")).unwrap();
        assert_eq!(enc, vector.get("enc"), "{label}: enc");
        let shared = suite.kem.decap(&enc, &sk_r, receiving.sender).unwrap();
        assert_eq!(shared, vector.get("shared_secret"), "{label}: shared secret");
        let mut opener = suite.setup_receiver(&enc, &sk_r, &info, &receiving).unwrap();
        for context in [&sealer, &opener] {
            assert_eq!(context.key(), vector.get("key"), "{label}: key");
            assert_eq!(context.base_nonce(), vector.get("base_nonce"), "{label}: base nonce");
            assert_eq!(context.exporter_secret(), vector.get("exporter_secret"),
                       "{label}: exporter secret");
        }
        for (seq, aad, pt, ct) in &vector.encryptions {
            sealer.sequence = *seq;
            assert_eq!(&sealer.seal(aad, pt).unwrap(), ct, "{label}: seal {seq}");
            opener.sequence = *seq;
            assert_eq!(&opener.open(aad, ct).unwrap(), pt, "{label}: open {seq}");
        }
        if suite.aead == Aead::ExportOnly {
            assert!(sealer.seal(b"", b"x").is_err());
        }
        for (context, length, value) in &vector.exports {
            assert_eq!(&sealer.export(context, *length).unwrap(), value, "{label}: export");
            assert_eq!(&opener.export(context, *length).unwrap(), value, "{label}: export");
        }
    }

    #[test]
    fn test_rfc_9180_appendix_a() {
        let vectors = rfc_vectors();
        assert_eq!(vectors.len(), 28);
        let encryptions: usize = vectors.iter().map(|v| v.encryptions.len()).sum();
        let exports: usize = vectors.iter().map(|v| v.exports.len()).sum();
        assert_eq!((encryptions, exports), (24 * 6, 28 * 3));
        for vector in &vectors {
            check(vector);
        }
    }

    #[test]
    fn test_cfrg_and_pq_draft_vectors() {
        let vectors = file_vectors();
        assert_eq!(vectors.len(), 141);
        for kem in [0x10, 0x11, 0x12, 0x20, 0x21, 0x40, 0x41, 0x42, 0x50, 0x51, 0x647a] {
            assert!(vectors.iter().any(|v| v.number("kem_id") == kem), "{kem:#x}");
        }
        for vector in &vectors {
            check(vector);
        }
    }

    /// `vectors/hpke_witness.vec`: what pyhpke and filippo.io/hpke sealed
    /// and exported, opened here; and what this sealed from fixed
    /// randomness - which pyhpke sealed identically and Go opened - made
    /// again byte for byte. Every DHKEM in all four modes, every PQ KEM
    /// and both SHAKE KDFs.
    #[test]
    fn test_what_pyhpke_and_go_sealed() {
        let text = include_str!("../../vectors/hpke_witness.vec");
        let rows: Vec<HashMap<&str, &str>> = text.lines().filter(|l| !l.starts_with('#'))
            .map(|l| l.split(' ').map(|f| f.split_once('=').unwrap()).collect()).collect();
        assert_eq!(rows.len(), 38);
        let mut kems = std::collections::HashSet::new();
        for row in &rows {
            let label = format!("{} {} {} {} {}", row["witness"], row["kem"], row["kdf"],
                                row["aead"], row["mode"]);
            let id = |k: &str| u16::from_str_radix(row[k], 16).unwrap();
            let get = |k: &str| row.get(k).map(|v| unhex(v)).unwrap_or_default();
            let suite = Suite::from_ids(id("kem"), id("kdf"), id("aead")).unwrap();
            kems.insert(suite.kem.id());
            let (sk_r, pk_r) = suite.kem.derive_key_pair(&get("ikmR")).unwrap();
            let sender = (!get("ikmS").is_empty())
                .then(|| suite.kem.derive_key_pair(&get("ikmS")).unwrap());
            let (psk, psk_id) = (get("psk"), get("psk_id"));
            let psk = (!psk.is_empty()).then_some((&psk[..], &psk_id[..]));
            let sending = Options { psk, sender: sender.as_ref().map(|(sk, _)| &sk[..]) };
            let receiving = Options { psk, sender: sender.as_ref().map(|(_, pk)| &pk[..]) };
            assert_eq!(suite.mode(&sending).unwrap(),
                       ["base", "psk", "auth", "auth_psk"].iter()
                           .position(|m| *m == row["mode"]).unwrap() as u8, "{label}");
            let (info, aad, pt) = (get("info"), get("aad"), get("pt"));
            let (enc, mut sealer) = suite.setup_sender_with(&pk_r, &info, &sending,
                                                            &get("randomness")).unwrap();
            let sealed = if suite.aead == Aead::ExportOnly { Vec::new() }
                         else { sealer.seal(&aad, &pt).unwrap() };
            let (ours_enc, ours_ct) = if row["witness"] == "pyhpke" { ("enc", "ct") }
                                      else { ("ours_enc", "ours_ct") };
            assert_eq!((enc, sealed), (get(ours_enc), get(ours_ct)), "{label}: ours again");
            let mut opener = suite.setup_receiver(&get("enc"), &sk_r, &info, &receiving)
                .unwrap();
            assert_eq!(opener.export(b"exporter context",
                                     if row["witness"] == "go" { 37 } else { 41 }).unwrap(),
                       get("export"), "{label}: export");
            if suite.aead != Aead::ExportOnly {
                assert_eq!(opener.open(&aad, &get("ct")).unwrap(), pt, "{label}: open");
            }
        }
        assert_eq!(kems.len(), 10, "every KEM but ML-KEM-512, which neither witness has");
    }

    /// What a setup refuses: a PSK without its identifier or the other way
    /// round, a sender key where the KEM or KDF has no auth mode, keys
    /// and encapsulations of the wrong size or off the curve, a low-order
    /// X25519 point, an ML-KEM key that fails FIPS 203's modulus check.
    #[test]
    fn test_inputs_are_checked() {
        let x25519 = Suite::new(Kem::X25519, Kdf::HkdfSha256, Aead::ChaCha20Poly1305);
        let (sk, pk) = x25519.kem.derive_key_pair(&[1; 32]).unwrap();
        let none = Options::default();
        for psk in [(&b""[..], &b"id"[..]), (&b"key"[..], &b""[..])] {
            let options = Options { psk: Some(psk), sender: None };
            assert!(x25519.setup_sender(&pk, b"", &options).is_err(), "{psk:?}");
        }
        let auth = Options { psk: None, sender: Some(&sk) };
        assert!(x25519.setup_sender(&pk, b"", &auth).is_ok());
        let shake = Suite::new(Kem::X25519, Kdf::Shake256, Aead::ChaCha20Poly1305);
        assert!(shake.setup_sender(&pk, b"", &auth).err().unwrap().contains("one-stage"));
        let ml_kem = Suite::new(Kem::MlKem768, Kdf::HkdfSha256, Aead::Aes128Gcm);
        let (ml_sk, ml_pk) = ml_kem.kem.derive_key_pair(&[2; 32]).unwrap();
        let ml_auth = Options { psk: None, sender: Some(&ml_sk) };
        assert!(ml_kem.setup_sender(&ml_pk, b"", &ml_auth).err().unwrap().contains("DHKEM"));
        assert!(x25519.setup_sender(&pk[..31], b"", &none).is_err());
        assert!(x25519.setup_receiver(&[0; 32], &sk, b"", &none).err().unwrap()
            .contains("all zero"));
        assert!(x25519.setup_receiver(&[9; 33], &sk, b"", &none).is_err());
        let p256 = Suite::new(Kem::P256, Kdf::HkdfSha256, Aead::Aes128Gcm);
        let (p_sk, mut p_pk) = p256.kem.derive_key_pair(&[3; 32]).unwrap();
        assert!(p256.setup_receiver(&p_pk, &p_sk, b"", &none).is_ok());
        p_pk[64] ^= 1;
        assert!(p256.setup_receiver(&p_pk, &p_sk, b"", &none).is_err(), "off the curve");
        assert!(p256.setup_sender(&p_pk, b"", &none).is_err(), "off the curve");
        assert!(p256.kem.public_key(&[0; 32]).is_err(), "zero scalar");
        assert!(p256.kem.public_key(&[0xff; 32]).is_err(), "scalar above n");
        let mut bad_ek = ml_pk.clone();
        bad_ek[0] = 0xff;
        bad_ek[1] |= 0x0f;
        assert!(ml_kem.setup_sender(&bad_ek, b"", &none).err().unwrap().contains("FIPS 203"));
        assert!(ml_kem.kem.encap(&ml_pk, None, &[0; 31]).is_err(), "short randomness");
    }

    /// A hybrid's ephemeral P-256 key is the first candidate that is a
    /// scalar below the order: one that is not is skipped, as the
    /// CONCRETE draft's rejection sampling skips it; with none left the
    /// encapsulation is refused rather than made with a bad key.
    #[test]
    fn test_hybrid_candidates_are_rejection_sampled() {
        let kem = Kem::MlKem768P256;
        let (_, pk) = kem.derive_key_pair(&[4; 32]).unwrap();
        let m = [5u8; 32];
        let good = [6u8; 32];
        let direct = kem.encap(&pk, None, &[&m[..], &good[..]].concat()).unwrap();
        let skipped = kem.encap(&pk, None, &[&m[..], &[0xff; 32][..], &good[..]].concat())
            .unwrap();
        assert_eq!(direct, skipped);
        let zero_then_good = kem.encap(&pk, None, &[&m[..], &[0; 32][..], &good[..]].concat())
            .unwrap();
        assert_eq!(direct, zero_then_good);
        assert!(kem.encap(&pk, None, &[&m[..], &[0xff; 64][..]].concat()).is_err());
        assert_eq!(kem.encap_randomness_len(), 96);
        assert_eq!(Kem::MlKem768X25519.encap_randomness_len(), 64);
    }

    /// A failed open leaves the sequence number where it was, so the
    /// right message still opens; a context stops before its sequence
    /// number wraps; an export longer than HKDF can make is refused.
    #[test]
    fn test_context_sequence_and_limits() {
        let suite = Suite::new(Kem::X25519, Kdf::HkdfSha256, Aead::Aes128Gcm);
        let (sk, pk) = suite.kem.derive_key_pair(&[7; 32]).unwrap();
        let none = Options::default();
        let (enc, mut sealer) = suite.setup_sender(&pk, b"info", &none).unwrap();
        let mut opener = suite.setup_receiver(&enc, &sk, b"info", &none).unwrap();
        let first = sealer.seal(b"a", b"one").unwrap();
        let second = sealer.seal(b"a", b"two").unwrap();
        assert!(opener.open(b"a", &second).is_err(), "out of order");
        assert!(opener.open(b"b", &first).is_err(), "wrong aad");
        assert!(opener.open(b"a", &first[..10]).is_err(), "shorter than the tag");
        assert_eq!(opener.sequence(), 0);
        assert_eq!(opener.open(b"a", &first).unwrap(), b"one");
        assert_eq!(opener.open(b"a", &second).unwrap(), b"two");
        sealer.sequence = u64::MAX - 1;
        assert!(sealer.seal(b"", b"last").is_ok());
        assert!(sealer.seal(b"", b"one too many").is_err());
        assert!(sealer.export(b"", 255 * 32).is_ok());
        assert!(sealer.export(b"", 255 * 32 + 1).is_err());
        let shake = Suite::new(Kem::X25519, Kdf::Shake128, Aead::ExportOnly);
        let (_, context) = shake.setup_sender(&pk, b"", &none).unwrap();
        assert_eq!(context.export(b"", 65535).unwrap().len(), 65535);
        assert!(context.export(b"", 65536).is_err());
    }
}
