//! PIV, NIST SP 800-73-4: the card application that holds X.509 keys
//! and certificates, as YubiKeys implement it - the Windows smart card
//! logon, SSH and code signing keys a YubiKey carries live here.
//!
//! The card has key **slots** (9A authentication, 9C signature, 9D key
//! management, 9E card authentication, 82-95 retired key management) and
//! **data objects**, of which the ones that matter are the certificate
//! beside each slot. Three secrets guard it:
//!
//! * the **PIN** (6-8 characters, padded with `FF` to eight bytes), for
//!   using a private key;
//! * the **PUK**, for unblocking the PIN;
//! * the **management key**, a 3DES or AES key, for changing anything:
//!   generating or importing a key, writing a certificate. It is not
//!   sent: the host proves it holds it by a challenge-response, and the
//!   card proves the same back (SP 800-73-4 part 2, appendix A.1, the
//!   "mutual authentication" form of GENERAL AUTHENTICATE).
//!
//! The card's own extensions beyond the standard - metadata, serial,
//! attestation, Ed25519 and X25519 slots, AES management keys - are
//! YubiKey's, from Yubico's PIV documentation, and CanoKey implements
//! the same instructions.
//!
//! **The card computes the private key operation and nothing else.** An
//! RSA signature is the raw RSA of whatever block the host sends, so the
//! host builds the PKCS#1 v1.5 block itself; an ECDSA signature is over
//! whatever digest the host sends; ECDH returns the shared x coordinate.
//! Everything around the key - hashing, padding, certificates, checking
//! the answers - is this library.

use allcrypt::api;
use allcrypt::block_ciphers::BlockCipher;

use super::card::Card;
use super::tlv;

pub const AID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];

/// The management key every YubiKey and CanoKey leaves the factory with,
/// and which ought to be changed: anybody holding it can replace every
/// key and certificate on the card.
pub const DEFAULT_MANAGEMENT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2C;
const INS_GENERATE: u8 = 0x47;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_GET_DATA: u8 = 0xCB;
const INS_PUT_DATA: u8 = 0xDB;
const INS_GET_METADATA: u8 = 0xF7;
const INS_GET_SERIAL: u8 = 0xF8;
const INS_ATTEST: u8 = 0xF9;
const INS_RESET: u8 = 0xFB;
const INS_GET_VERSION: u8 = 0xFD;
const INS_IMPORT_KEY: u8 = 0xFE;
const INS_SET_MANAGEMENT_KEY: u8 = 0xFF;

const PIN: u8 = 0x80;
const PUK: u8 = 0x81;
const MANAGEMENT_SLOT: u8 = 0x9B;

/// The algorithms a slot can hold, by PIV's and YubiKey's numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    P256,
    P384,
    Ed25519,
    X25519,
}

impl KeyType {
    pub const ALL: [KeyType; 8] = [KeyType::Rsa1024, KeyType::Rsa2048, KeyType::Rsa3072,
                                   KeyType::Rsa4096, KeyType::P256, KeyType::P384,
                                   KeyType::Ed25519, KeyType::X25519];

    pub fn code(self) -> u8 {
        match self {
            KeyType::Rsa1024 => 0x06,
            KeyType::Rsa2048 => 0x07,
            KeyType::Rsa3072 => 0x05,
            KeyType::Rsa4096 => 0x16,
            KeyType::P256 => 0x11,
            KeyType::P384 => 0x14,
            KeyType::Ed25519 => 0xE0,
            KeyType::X25519 => 0xE1,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            KeyType::Rsa1024 => "rsa1024",
            KeyType::Rsa2048 => "rsa2048",
            KeyType::Rsa3072 => "rsa3072",
            KeyType::Rsa4096 => "rsa4096",
            KeyType::P256 => "p256",
            KeyType::P384 => "p384",
            KeyType::Ed25519 => "ed25519",
            KeyType::X25519 => "x25519",
        }
    }

    pub fn from_code(code: u8) -> Option<KeyType> {
        KeyType::ALL.into_iter().find(|t| t.code() == code)
    }

    pub fn from_name(name: &str) -> Result<KeyType, String> {
        KeyType::ALL.into_iter().find(|t| t.name() == name.to_ascii_lowercase()).ok_or_else(|| {
            let names: Vec<_> = KeyType::ALL.iter().map(|t| t.name()).collect();
            format!("{name} is not a PIV key type; the types are {}.", names.join(", "))
        })
    }

    /// The RSA modulus in bytes, or `None` for the curves.
    pub fn rsa_bytes(self) -> Option<usize> {
        match self {
            KeyType::Rsa1024 => Some(128),
            KeyType::Rsa2048 => Some(256),
            KeyType::Rsa3072 => Some(384),
            KeyType::Rsa4096 => Some(512),
            _ => None,
        }
    }
}

/// A slot, by the one-byte reference the card uses.
pub fn parse_slot(text: &str) -> Result<u8, String> {
    let named = match text.to_ascii_lowercase().as_str() {
        "authentication" => Some(0x9A),
        "signature" => Some(0x9C),
        "key-management" => Some(0x9D),
        "card-authentication" => Some(0x9E),
        "attestation" => Some(0xF9),
        _ => None,
    };
    let slot = match named {
        Some(slot) => slot,
        None => u8::from_str_radix(text.trim_start_matches("0x"), 16)
            .map_err(|_| format!("{text} is not a slot: 9a, 9c, 9d, 9e, 82 to 95 or f9."))?,
    };
    if object_for_slot(slot).is_none() {
        return Err(format!("{slot:02x} is not a PIV slot: 9a, 9c, 9d, 9e, 82 to 95 or f9."));
    }
    Ok(slot)
}

/// The data object that holds a slot's certificate (SP 800-73-4 part 1,
/// table 3, and YubiKey's F9 for the attestation certificate).
pub fn object_for_slot(slot: u8) -> Option<u32> {
    match slot {
        0x9A => Some(0x5FC105),
        0x9C => Some(0x5FC10A),
        0x9D => Some(0x5FC10B),
        0x9E => Some(0x5FC101),
        0x82..=0x95 => Some(0x5FC10D + u32::from(slot - 0x82)),
        0xF9 => Some(0x5FFF01),
        _ => None,
    }
}

/// The management key's algorithm, which fixes its length and the
/// challenge size of the mutual authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementKeyType {
    Tdes,
    Aes128,
    Aes192,
    Aes256,
}

impl ManagementKeyType {
    pub fn code(self) -> u8 {
        match self {
            ManagementKeyType::Tdes => 0x03,
            ManagementKeyType::Aes128 => 0x08,
            ManagementKeyType::Aes192 => 0x0A,
            ManagementKeyType::Aes256 => 0x0C,
        }
    }

    pub fn from_code(code: u8) -> Option<ManagementKeyType> {
        [ManagementKeyType::Tdes, ManagementKeyType::Aes128, ManagementKeyType::Aes192,
         ManagementKeyType::Aes256].into_iter().find(|t| t.code() == code)
    }

    pub fn from_name(name: &str) -> Result<ManagementKeyType, String> {
        match name.to_ascii_lowercase().as_str() {
            "tdes" | "3des" => Ok(ManagementKeyType::Tdes),
            "aes128" => Ok(ManagementKeyType::Aes128),
            "aes192" => Ok(ManagementKeyType::Aes192),
            "aes256" => Ok(ManagementKeyType::Aes256),
            _ => Err(format!("{name} is not a management key type: tdes, aes128, aes192 \
                              or aes256.")),
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            ManagementKeyType::Tdes | ManagementKeyType::Aes192 => 24,
            ManagementKeyType::Aes128 => 16,
            ManagementKeyType::Aes256 => 32,
        }
    }

    /// The witness and challenge are one cipher block.
    fn block_len(self) -> usize {
        match self {
            ManagementKeyType::Tdes => 8,
            _ => 16,
        }
    }

    fn cipher(self, key: &[u8]) -> Result<api::AnyBlockCipher, String> {
        if key.len() != self.key_len() {
            return Err(format!("A {:?} management key is {} bytes, not {}.", self,
                               self.key_len(), key.len()));
        }
        let name = if self == ManagementKeyType::Tdes { "3des" } else { "aes" };
        api::AnyBlockCipher::new(name, key, None)
    }
}

/// A public key as the card returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// The curve's name as this library spells it, and the uncompressed
    /// point.
    Ec { curve: &'static str, point: Vec<u8> },
    Ed25519(Vec<u8>),
    X25519(Vec<u8>),
}

impl PublicKey {
    /// From the contents of a `7F49` template: `81` modulus and `82`
    /// exponent for RSA, `86` the point or the raw key for the others.
    pub fn parse(key_type: KeyType, template: &[u8]) -> Result<PublicKey, String> {
        Ok(match key_type {
            KeyType::P256 | KeyType::P384 => PublicKey::Ec {
                curve: if key_type == KeyType::P256 { "P-256" } else { "P-384" },
                point: tlv::find(template, 0x86)?.to_vec(),
            },
            KeyType::Ed25519 => PublicKey::Ed25519(tlv::find(template, 0x86)?.to_vec()),
            KeyType::X25519 => PublicKey::X25519(tlv::find(template, 0x86)?.to_vec()),
            // Without leading zeros, so that the same key compares equal
            // however the card or a certificate padded it.
            _ => PublicKey::Rsa {
                n: strip_zeros(tlv::find(template, 0x81)?),
                e: strip_zeros(tlv::find(template, 0x82)?),
            },
        })
    }

    pub fn describe(&self) -> String {
        match self {
            PublicKey::Rsa { n, e } => {
                let exponent = e.iter().try_fold(0u64, |acc, &b| acc.checked_mul(256)
                    .map(|acc| acc + u64::from(b)));
                match exponent {
                    Some(value) => format!("RSA-{} e={value}", bits(n)),
                    None => format!("RSA-{} e={}", bits(n), super::hex(e)),
                }
            }
            PublicKey::Ec { curve, point } => format!("{curve} {}", super::hex(point)),
            PublicKey::Ed25519(key) => format!("Ed25519 {}", super::hex(key)),
            PublicKey::X25519(key) => format!("X25519 {}", super::hex(key)),
        }
    }
}

fn bits(number: &[u8]) -> usize {
    let skip = number.iter().take_while(|&&b| b == 0).count();
    match number.get(skip) {
        Some(&top) => (number.len() - skip) * 8 - top.leading_zeros() as usize,
        None => 0,
    }
}

/// What GET METADATA says about a slot (YubiKey 5.3 and later).
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    pub algorithm: Option<u8>,
    /// PIN policy and touch policy.
    pub policy: Option<(u8, u8)>,
    /// 1 generated on the card, 2 imported.
    pub origin: Option<u8>,
    pub public_key: Option<Vec<u8>>,
    /// For the PIN, PUK and management key: still the factory value.
    pub is_default: Option<bool>,
    /// For the PIN and PUK: total and remaining tries.
    pub retries: Option<(u8, u8)>,
}

/// A PIN as the card wants it: six to eight bytes, padded with `FF`.
fn pin_bytes(pin: &str) -> Result<[u8; 8], String> {
    let bytes = pin.as_bytes();
    if bytes.len() < 6 || bytes.len() > 8 {
        return Err("A PIV PIN or PUK is 6 to 8 characters.".to_string());
    }
    let mut out = [0xFF; 8];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

fn pin_error(sw: u16, which: &str) -> String {
    match sw {
        0x63C0..=0x63CF => format!("Wrong {which}: {} left.", super::card::tries(sw & 0x0F)),
        0x6983 => format!("The {which} is blocked."),
        other => format!("Verifying the {which}: the card answered {other:04X} ({}).",
                         super::card::describe(other)),
    }
}

/// The PIV application on a card.
pub struct Piv<'a> {
    pub card: &'a mut Card,
}

impl<'a> Piv<'a> {
    pub fn select(card: &'a mut Card) -> Result<Piv<'a>, String> {
        card.get_response = 0xC0;
        card.select(&AID, "PIV")?;
        Ok(Piv { card })
    }

    /// The firmware version, three bytes (a YubiKey extension).
    pub fn version(&mut self) -> Result<[u8; 3], String> {
        let data = self.card.get(0, INS_GET_VERSION, 0, 0, "Reading the version")?;
        data.get(..3).and_then(|v| v.try_into().ok())
            .ok_or_else(|| "The version is not three bytes.".to_string())
    }

    /// The serial number, or `None` where the card has none to give.
    pub fn serial(&mut self) -> Result<Option<u32>, String> {
        let response = self.card.read(0, INS_GET_SERIAL, 0, 0)?;
        if !response.ok() || response.data.len() != 4 {
            return Ok(None);
        }
        Ok(Some(u32::from_be_bytes(response.data[..4].try_into().expect("four bytes"))))
    }

    /// GET METADATA for a slot, or for `80` the PIN, `81` the PUK and
    /// `9B` the management key. `None` on a card without the instruction.
    pub fn metadata(&mut self, slot: u8) -> Result<Option<Metadata>, String> {
        let response = self.card.read(0, INS_GET_METADATA, 0, slot)?;
        match response.sw {
            0x9000 => {}
            0x6D00 | 0x6A81 | 0x6E00 => return Ok(None),
            0x6A88 | 0x6A82 => return Ok(Some(Metadata::default())),
            _ => return Err(format!("Reading the metadata of {slot:02x}: the card answered \
                                     {:04X} ({}).", response.sw,
                                    super::card::describe(response.sw))),
        }
        let mut metadata = Metadata::default();
        for item in tlv::parse(&response.data)? {
            let value = item.value;
            match item.tag {
                0x01 => metadata.algorithm = value.first().copied(),
                0x02 if value.len() >= 2 => metadata.policy = Some((value[0], value[1])),
                0x03 => metadata.origin = value.first().copied(),
                0x04 => metadata.public_key = Some(value.to_vec()),
                0x05 => metadata.is_default = value.first().map(|&b| b != 0),
                0x06 if value.len() >= 2 => metadata.retries = Some((value[0], value[1])),
                _ => {}
            }
        }
        Ok(Some(metadata))
    }

    /// The management key's type, from its metadata; a card too old to
    /// say has 3DES, the only kind it supports.
    pub fn management_key_type(&mut self) -> Result<ManagementKeyType, String> {
        match self.metadata(MANAGEMENT_SLOT)?.and_then(|m| m.algorithm) {
            Some(code) => ManagementKeyType::from_code(code)
                .ok_or_else(|| format!("The management key has algorithm {code:02x}, which \
                                        this example does not know.")),
            None => Ok(ManagementKeyType::Tdes),
        }
    }

    /// Prove we hold the management key, and check the card holds it too.
    ///
    /// Two GENERAL AUTHENTICATE commands. The card sends a **witness**,
    /// a random block encrypted under the key; we return it decrypted,
    /// together with a **challenge** of our own; the card answers with
    /// the challenge encrypted. The first half authenticates us, the
    /// second the card - without it a card that accepted any key would
    /// look exactly like one that accepted ours.
    pub fn authenticate(&mut self, key: &[u8]) -> Result<(), String> {
        let key_type = self.management_key_type()?;
        let mut cipher = key_type.cipher(key)?;
        let block = key_type.block_len();

        let request = tlv::encode(0x7C, &tlv::encode(0x80, &[]));
        let answer = self.card.call(0, INS_AUTHENTICATE, key_type.code(), MANAGEMENT_SLOT,
                                    &request, "Starting management key authentication")?;
        let witness = tlv::path(&answer, &[0x7C, 0x80])?;
        if witness.len() != block {
            return Err(format!("The card's witness is {} bytes; a {:?} block is {block}.",
                               witness.len(), key_type));
        }
        let mut decrypted = Vec::new();
        cipher.ecb_decrypt(witness, &mut decrypted)?;
        let challenge = self.card.random(block)?;

        let mut inner = tlv::encode(0x80, &decrypted);
        inner.extend_from_slice(&tlv::encode(0x81, &challenge));
        let response = self.card.send(0, INS_AUTHENTICATE, key_type.code(), MANAGEMENT_SLOT,
                                      &tlv::encode(0x7C, &inner))?;
        if response.sw == 0x6982 || response.sw == 0x6A80 {
            return Err("The management key is wrong.".to_string());
        }
        let answer = response.check("Finishing management key authentication")?;
        let encrypted = tlv::path(&answer, &[0x7C, 0x82])?;
        let mut expected = Vec::new();
        cipher.ecb_encrypt(&challenge, &mut expected)?;
        if !api_equal(&expected, encrypted) {
            return Err("The card accepted the management key but could not prove it holds \
                        it: its answer to our challenge is wrong.".to_string());
        }
        Ok(())
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<(), String> {
        let response = self.card.send(0, INS_VERIFY, 0, PIN, &pin_bytes(pin)?)?;
        if response.ok() { Ok(()) } else { Err(pin_error(response.sw, "PIN")) }
    }

    /// Tries left on the PIN, by an empty VERIFY - or `None` when the PIN
    /// is already verified in this session and the card will not say.
    pub fn pin_tries(&mut self) -> Result<Option<u8>, String> {
        let response = self.card.send(0, INS_VERIFY, 0, PIN, &[])?;
        match response.sw {
            0x9000 => Ok(None),
            0x63C0..=0x63CF => Ok(Some((response.sw & 0x0F) as u8)),
            0x6983 => Ok(Some(0)),
            sw => Err(pin_error(sw, "PIN")),
        }
    }

    /// Change the PIN (`puk` false) or the PUK (`puk` true).
    pub fn change(&mut self, puk: bool, old: &str, new: &str) -> Result<(), String> {
        let mut data = pin_bytes(old)?.to_vec();
        data.extend_from_slice(&pin_bytes(new)?);
        let (reference, which) = if puk { (PUK, "PUK") } else { (PIN, "PIN") };
        let response = self.card.send(0, INS_CHANGE_REFERENCE, 0, reference, &data)?;
        if response.ok() { Ok(()) } else { Err(pin_error(response.sw, which)) }
    }

    /// Set a new PIN with the PUK, which also unblocks it.
    pub fn unblock_pin(&mut self, puk: &str, new_pin: &str) -> Result<(), String> {
        let mut data = pin_bytes(puk)?.to_vec();
        data.extend_from_slice(&pin_bytes(new_pin)?);
        let response = self.card.send(0, INS_RESET_RETRY, 0, PIN, &data)?;
        if response.ok() { Ok(()) } else { Err(pin_error(response.sw, "PUK")) }
    }

    /// Replace the management key. Requires `authenticate` first.
    pub fn set_management_key(&mut self, key_type: ManagementKeyType, key: &[u8],
                              require_touch: bool) -> Result<(), String> {
        key_type.cipher(key)?;
        let mut data = vec![key_type.code()];
        data.extend_from_slice(&tlv::encode(u32::from(MANAGEMENT_SLOT), key));
        let p2 = if require_touch { 0xFE } else { 0xFF };
        self.card.call(0, INS_SET_MANAGEMENT_KEY, 0xFF, p2, &data, "Setting the management key")?;
        Ok(())
    }

    /// Generate a key pair in a slot; the private half never leaves the
    /// card. Requires `authenticate` first.
    pub fn generate(&mut self, slot: u8, key_type: KeyType, pin_policy: u8, touch_policy: u8)
                    -> Result<PublicKey, String> {
        let mut template = tlv::encode(0x80, &[key_type.code()]);
        if pin_policy != 0 {
            template.extend_from_slice(&tlv::encode(0xAA, &[pin_policy]));
        }
        if touch_policy != 0 {
            template.extend_from_slice(&tlv::encode(0xAB, &[touch_policy]));
        }
        let answer = self.card.call(0, INS_GENERATE, 0, slot, &tlv::encode(0xAC, &template),
                                    &format!("Generating a {} key in {slot:02x}",
                                             key_type.name()))?;
        PublicKey::parse(key_type, tlv::find(&answer, 0x7F49)?)
    }

    /// Put a private key into a slot. Requires `authenticate` first.
    ///
    /// RSA goes in as its CRT form - `p`, `q`, `dP`, `dQ` and `qInv`,
    /// each padded to half the modulus - because that is what the card
    /// computes with; an EC key as its scalar padded to the field;
    /// Ed25519 and X25519 as their 32-byte seeds.
    pub fn import(&mut self, slot: u8, key: &api::PrivateKeyParts, pin_policy: u8,
                  touch_policy: u8) -> Result<KeyType, String> {
        let (key_type, mut data) = match key {
            api::PrivateKeyParts::Rsa { p, q, e } => {
                let rsa = api::RsaKey::from_primes(p, q, e)?;
                let key_type = match rsa.bits() {
                    1024 => KeyType::Rsa1024,
                    2048 => KeyType::Rsa2048,
                    3072 => KeyType::Rsa3072,
                    4096 => KeyType::Rsa4096,
                    bits => return Err(format!("PIV holds RSA keys of 1024, 2048, 3072 or \
                                                4096 bits; this one is {bits}.")),
                };
                let numbers: std::collections::HashMap<_, _> = rsa.numbers().into_iter().collect();
                let half = rsa.size() / 2;
                let mut data = Vec::new();
                for (tag, name) in [(0x01, "p"), (0x02, "q"), (0x03, "dp"), (0x04, "dq"),
                                    (0x05, "qinv")] {
                    data.extend_from_slice(&tlv::encode(tag, &left_pad(&numbers[name], half)?));
                }
                (key_type, data)
            }
            api::PrivateKeyParts::Ec { curve, private } => {
                let (key_type, width) = match curve.as_str() {
                    "P-256" => (KeyType::P256, 32),
                    "P-384" => (KeyType::P384, 48),
                    other => return Err(format!("PIV holds P-256 and P-384 keys, not {other}.")),
                };
                (key_type, tlv::encode(0x06, &left_pad(private, width)?))
            }
            api::PrivateKeyParts::Eddsa { curve, private } if curve == "ed25519" =>
                (KeyType::Ed25519, tlv::encode(0x07, private)),
            api::PrivateKeyParts::Xdh { curve, private } if curve == "x25519" =>
                (KeyType::X25519, tlv::encode(0x08, private)),
            _ => return Err("PIV holds RSA, P-256, P-384, Ed25519 and X25519 keys; this file \
                             has another kind.".to_string()),
        };
        if pin_policy != 0 {
            data.extend_from_slice(&tlv::encode(0xAA, &[pin_policy]));
        }
        if touch_policy != 0 {
            data.extend_from_slice(&tlv::encode(0xAB, &[touch_policy]));
        }
        self.card.call(0, INS_IMPORT_KEY, key_type.code(), slot, &data,
                       &format!("Importing a {} key into {slot:02x}", key_type.name()))?;
        Ok(key_type)
    }

    /// The private key operation: GENERAL AUTHENTICATE with the input in
    /// `81` (a signature or an RSA decryption) or `85` (ECDH's peer
    /// point), the answer in `82`. Requires the PIN, per the slot's
    /// policy.
    fn use_key(&mut self, slot: u8, key_type: KeyType, input: &[u8], exchange: bool)
               -> Result<Vec<u8>, String> {
        let mut inner = tlv::encode(0x82, &[]);
        inner.extend_from_slice(&tlv::encode(if exchange { 0x85 } else { 0x81 }, input));
        let response = self.card.send(0, INS_AUTHENTICATE, key_type.code(), slot,
                                      &tlv::encode(0x7C, &inner))?;
        if response.sw == 0x6982 {
            return Err(format!("Slot {slot:02x} needs the PIN first (or a touch)."));
        }
        let answer = response.check(&format!("Using the key in slot {slot:02x}"))?;
        Ok(tlv::path(&answer, &[0x7C, 0x82])?.to_vec())
    }

    /// Sign. `input` is what the card's key operation takes: the
    /// PKCS#1 v1.5 block for RSA (see `pkcs1_block`), the digest for
    /// ECDSA, the message itself for Ed25519.
    pub fn sign(&mut self, slot: u8, key_type: KeyType, input: &[u8]) -> Result<Vec<u8>, String> {
        self.use_key(slot, key_type, input, false)
    }

    /// The raw RSA private operation on a ciphertext; the caller removes
    /// the padding.
    pub fn decrypt(&mut self, slot: u8, key_type: KeyType, ciphertext: &[u8])
                   -> Result<Vec<u8>, String> {
        self.use_key(slot, key_type, ciphertext, false)
    }

    /// ECDH or X25519 with the key in `slot` and the peer's public key
    /// (an uncompressed point, or 32 bytes for X25519).
    pub fn exchange(&mut self, slot: u8, key_type: KeyType, peer: &[u8]) -> Result<Vec<u8>, String> {
        self.use_key(slot, key_type, peer, true)
    }

    /// A data object's contents (inside its `53`), or `None` when the
    /// card has nothing stored there.
    pub fn get_object(&mut self, object: u32) -> Result<Option<Vec<u8>>, String> {
        let id = object.to_be_bytes();
        let response = self.card.send(0, INS_GET_DATA, 0x3F, 0xFF, &tlv::encode(0x5C, &id[1..]))?;
        if response.sw == 0x6A82 {
            return Ok(None);
        }
        let answer = response.check(&format!("Reading object {object:06x}"))?;
        Ok(Some(tlv::find(&answer, 0x53)?.to_vec()))
    }

    /// Write a data object. Requires `authenticate` first.
    pub fn put_object(&mut self, object: u32, contents: &[u8]) -> Result<(), String> {
        let id = object.to_be_bytes();
        let mut data = tlv::encode(0x5C, &id[1..]);
        data.extend_from_slice(&tlv::encode(0x53, contents));
        self.card.call(0, INS_PUT_DATA, 0x3F, 0xFF, &data,
                       &format!("Writing object {object:06x}"))?;
        Ok(())
    }

    /// The certificate beside a slot, DER. A compressed one (CertInfo
    /// `01`, gzip, which YubiKey's tools write for certificates too big
    /// for the object) is inflated.
    pub fn read_certificate(&mut self, slot: u8) -> Result<Option<Vec<u8>>, String> {
        let object = object_for_slot(slot).ok_or("Not a slot with a certificate.")?;
        let Some(contents) = self.get_object(object)? else { return Ok(None) };
        let certificate = tlv::find(&contents, 0x70)?;
        match tlv::find_optional(&contents, 0x71)?.and_then(|info| info.first().copied()) {
            None | Some(0) => Ok(Some(certificate.to_vec())),
            Some(1) => Ok(Some(super::gunzip(certificate)?)),
            Some(other) => Err(format!("The certificate's CertInfo is {other:02x}, which \
                                        this example does not know.")),
        }
    }

    /// Store a certificate beside a slot, uncompressed. Requires
    /// `authenticate` first.
    pub fn write_certificate(&mut self, slot: u8, der: &[u8]) -> Result<(), String> {
        let object = object_for_slot(slot).ok_or("Not a slot with a certificate.")?;
        let mut contents = tlv::encode(0x70, der);
        contents.extend_from_slice(&tlv::encode(0x71, &[0]));
        contents.extend_from_slice(&tlv::encode(0xFE, &[]));
        self.put_object(object, &contents)
    }

    /// The card's attestation that the key in `slot` was generated on
    /// it: a certificate for that key, signed by the key in F9.
    pub fn attest(&mut self, slot: u8) -> Result<Vec<u8>, String> {
        self.card.get(0, INS_ATTEST, slot, 0, &format!("Attesting slot {slot:02x}"))
    }

    /// Return the application to its factory state. The card refuses
    /// until both the PIN and the PUK are blocked.
    /// Reset the application to its factory state. The card refuses
    /// until the PIN and the PUK are both blocked, so both are blocked
    /// first, as ykman does: with wrong attempts, each an empty value
    /// padded with FF, which no PIN or PUK of six to eight characters is.
    pub fn reset(&mut self) -> Result<(), String> {
        let wrong = [0xFF; 8];
        let mut twice = wrong.to_vec();
        twice.extend_from_slice(&wrong);
        for (ins, reference, data, which) in [(INS_VERIFY, PIN, &wrong[..], "PIN"),
                                              (INS_CHANGE_REFERENCE, PUK, &twice[..], "PUK")] {
            let mut blocked = false;
            for _ in 0..16 {
                let sw = self.card.send(0, ins, 0, reference, data)?.sw;
                match sw {
                    0x6983 => {
                        blocked = true;
                        break;
                    }
                    0x63C0..=0x63CF => {}
                    other => return Err(pin_error(other, which)),
                }
            }
            if !blocked {
                return Err(format!("The {which} did not block after sixteen wrong attempts."));
            }
        }
        self.card.call(0, INS_RESET, 0, 0, &[], "Resetting PIV")?;
        Ok(())
    }
}

fn strip_zeros(number: &[u8]) -> Vec<u8> {
    let skip = number.iter().take_while(|&&b| b == 0).count();
    number[skip..].to_vec()
}

fn left_pad(number: &[u8], width: usize) -> Result<Vec<u8>, String> {
    let skip = number.iter().take_while(|&&b| b == 0).count();
    let significant = &number[skip..];
    if significant.len() > width {
        return Err(format!("A key component is {} bytes, wider than {width}.",
                           significant.len()));
    }
    let mut out = vec![0u8; width - significant.len()];
    out.extend_from_slice(significant);
    Ok(out)
}

fn api_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The DER DigestInfo prefix for each hash (RFC 8017 9.2 note 1).
fn digest_info_prefix(hash: &str) -> Result<&'static [u8], String> {
    Ok(match hash {
        "sha1" => &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
                    0x04, 0x14],
        "sha256" => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                      0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
        "sha384" => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                      0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
        "sha512" => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                      0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        other => return Err(format!("{other} is not a hash this example signs with: sha1, \
                                     sha256, sha384 or sha512.")),
    })
}

/// The DigestInfo for a digest, which is what an RSA signature and an
/// OpenPGP card's RSA signing command both sign.
pub fn digest_info(hash: &str, digest: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = digest_info_prefix(hash)?.to_vec();
    out.extend_from_slice(digest);
    Ok(out)
}

/// EMSA-PKCS1-v1_5 (RFC 8017 9.2): `00 01 FF..FF 00 DigestInfo`, the
/// width of the modulus. PIV's RSA is the raw private operation, so
/// this block is what the host hands it.
pub fn pkcs1_block(hash: &str, digest: &[u8], width: usize) -> Result<Vec<u8>, String> {
    let info = digest_info(hash, digest)?;
    if info.len() + 11 > width {
        return Err("The digest does not fit the key.".to_string());
    }
    let mut block = vec![0x00, 0x01];
    block.resize(width - info.len() - 1, 0xFF);
    block.push(0x00);
    block.extend_from_slice(&info);
    Ok(block)
}

/// Remove PKCS#1 v1.5 encryption padding (`00 02 nonzero.. 00 message`)
/// from the card's raw decryption.
pub fn unpad_pkcs1_encryption(block: &[u8]) -> Result<Vec<u8>, String> {
    if block.len() < 11 || block[0] != 0 || block[1] != 2 {
        return Err("The decryption is not PKCS#1 v1.5 padded.".to_string());
    }
    let separator = block[2..].iter().position(|&b| b == 0)
        .ok_or("The decryption's padding has no end.")? + 2;
    if separator < 10 {
        return Err("The decryption's padding is shorter than eight bytes.".to_string());
    }
    Ok(block[separator + 1..].to_vec())
}
