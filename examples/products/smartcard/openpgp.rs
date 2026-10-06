//! The OpenPGP card application, version 3.4 of the specification
//! (Pietig, "Functional Specification of the OpenPGP application on ISO
//! Smart Card Operating Systems"): what GnuPG's `scdaemon` talks to, and
//! what a YubiKey, a Nitrokey or a CanoKey presents for OpenPGP.
//!
//! Three keys - signature, decryption, authentication - each with its
//! algorithm chosen by a writable "algorithm attributes" object, and
//! three secrets: PW1, the user PIN (default `123456`), verified in one
//! of two modes - `81` for signing, `82` for everything else - and PW3,
//! the admin PIN (default `12345678`), for changing anything.
//!
//! **The card stores keys, not OpenPGP keys.** It has no idea what an
//! OpenPGP key packet or fingerprint is; the host writes the fingerprint
//! and creation time into data objects so that GnuPG can recognise the
//! key later, and the fingerprint is only right if the host built the
//! same key packet GnuPG will. So this module also writes the few OpenPGP
//! packets a card key needs to be usable - the public key, a user ID, the
//! self-signature the card makes, and detached signatures - which is
//! where most of the ways to get this wrong are:
//!
//! * the fingerprint covers the **creation time**, so the time written
//!   to the card and the one in the exported key must be the same number;
//! * Ed25519 and Curve25519 points are prefixed with `40` in OpenPGP
//!   and are bare on the card, and an X25519 private key goes to the card
//!   **byte-reversed** (OpenPGP's Curve25519 secret is big-endian);
//! * ECDH keys carry KDF parameters, part of the fingerprint, which must
//!   be the ones GnuPG writes for that curve.

use allcrypt::api;
use allcrypt::hash_functions::HashFunction;

use super::card::Card;
use super::tlv;

pub const AID: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2C;
const INS_PSO: u8 = 0x2A;
const INS_ACTIVATE: u8 = 0x44;
const INS_GENERATE: u8 = 0x47;
const INS_GET_DATA: u8 = 0xCA;
const INS_PUT_DATA: u8 = 0xDA;
const INS_PUT_DATA_ODD: u8 = 0xDB;
const INS_TERMINATE: u8 = 0xE6;

/// One of the card's three keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Signature,
    Decryption,
    Authentication,
}

impl Slot {
    pub fn from_name(name: &str) -> Result<Slot, String> {
        match name.to_ascii_lowercase().as_str() {
            "sig" | "signature" => Ok(Slot::Signature),
            "dec" | "decryption" | "encryption" => Ok(Slot::Decryption),
            "aut" | "authentication" => Ok(Slot::Authentication),
            _ => Err(format!("{name} is not an OpenPGP card key: sig, dec or aut.")),
        }
    }

    /// The control reference template naming the key.
    fn crt(self) -> u8 {
        match self {
            Slot::Signature => 0xB6,
            Slot::Decryption => 0xB8,
            Slot::Authentication => 0xA4,
        }
    }

    fn attributes_object(self) -> u16 {
        0xC1 + self.index() as u16
    }

    fn fingerprint_object(self) -> u16 {
        0xC7 + self.index() as u16
    }

    fn time_object(self) -> u16 {
        0xCE + self.index() as u16
    }

    pub fn index(self) -> usize {
        match self {
            Slot::Signature => 0,
            Slot::Decryption => 1,
            Slot::Authentication => 2,
        }
    }
}

/// An algorithm the card's key can have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Rsa(u16),
    /// ECDSA, or ECDH for the decryption key, on a named curve.
    Ec(&'static Curve),
    Ed25519,
    X25519,
}

/// A curve as both the card and OpenPGP name it.
#[derive(Debug, PartialEq, Eq)]
pub struct Curve {
    pub name: &'static str,
    /// This library's name, for checking the card's answers.
    pub library: &'static str,
    /// The OID's DER contents, which is how both the card's attributes
    /// and OpenPGP's key packets write it.
    pub oid: &'static [u8],
    /// The ECDH KDF parameters GnuPG writes for this curve: hash, cipher.
    pub kdf: (u8, u8),
}

pub const CURVES: [Curve; 4] = [
    Curve { name: "p256", library: "P-256",
            oid: &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], kdf: (8, 7) },
    Curve { name: "p384", library: "P-384", oid: &[0x2B, 0x81, 0x04, 0x00, 0x22], kdf: (9, 9) },
    Curve { name: "p521", library: "P-521", oid: &[0x2B, 0x81, 0x04, 0x00, 0x23], kdf: (10, 9) },
    Curve { name: "secp256k1", library: "secp256k1", oid: &[0x2B, 0x81, 0x04, 0x00, 0x0A],
            kdf: (8, 7) },
];

/// Ed25519's OID as OpenPGP (RFC 4880bis, "legacy EdDSA") and the card
/// write it.
const ED25519_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
/// Curve25519 for ECDH, likewise.
const X25519_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

impl Algorithm {
    pub fn from_name(name: &str) -> Result<Algorithm, String> {
        let lower = name.to_ascii_lowercase();
        if let Some(bits) = lower.strip_prefix("rsa") {
            let bits: u16 = bits.parse().map_err(|_| format!("{name}: rsa2048, rsa3072 or \
                                                              rsa4096."))?;
            return Ok(Algorithm::Rsa(bits));
        }
        match lower.as_str() {
            "ed25519" => return Ok(Algorithm::Ed25519),
            "x25519" | "cv25519" => return Ok(Algorithm::X25519),
            _ => {}
        }
        CURVES.iter().find(|c| c.name == lower).map(Algorithm::Ec).ok_or_else(|| {
            format!("{name} is not an algorithm this example puts on an OpenPGP card: \
                     rsa2048, rsa3072, rsa4096, p256, p384, p521, secp256k1, ed25519, x25519.")
        })
    }

    /// The algorithm attributes object (spec 4.4.3.9).
    fn attributes(self, slot: Slot) -> Vec<u8> {
        match self {
            // RSA, the modulus bits, 17 bits of public exponent, and the
            // standard import format (e, p, q).
            Algorithm::Rsa(bits) => {
                let mut out = vec![0x01];
                out.extend_from_slice(&bits.to_be_bytes());
                out.extend_from_slice(&[0x00, 0x11, 0x00]);
                out
            }
            Algorithm::Ec(curve) => {
                let mut out = vec![if slot == Slot::Decryption { 0x12 } else { 0x13 }];
                out.extend_from_slice(curve.oid);
                out
            }
            Algorithm::Ed25519 => [&[0x16], ED25519_OID].concat(),
            Algorithm::X25519 => [&[0x12], X25519_OID].concat(),
        }
    }

    fn from_attributes(data: &[u8]) -> Result<Algorithm, String> {
        let (&id, rest) = data.split_first().ok_or("Empty algorithm attributes.")?;
        // A trailing FF says the import format carries the public key.
        let oid = rest.strip_suffix(&[0xFF]).unwrap_or(rest);
        match id {
            0x01 if rest.len() >= 2 => Ok(Algorithm::Rsa(u16::from_be_bytes([rest[0], rest[1]]))),
            0x16 if oid == ED25519_OID => Ok(Algorithm::Ed25519),
            0x12 if oid == X25519_OID => Ok(Algorithm::X25519),
            0x12 | 0x13 => CURVES.iter().find(|c| c.oid == oid).map(Algorithm::Ec)
                .ok_or_else(|| format!("The card's key is on curve {}, which this example \
                                        does not know.", super::hex(oid))),
            _ => Err(format!("The card's key has algorithm {id:02x}, which this example \
                              does not know.")),
        }
    }

    /// OpenPGP's public-key algorithm number for this key in this slot.
    fn openpgp_id(self, slot: Slot) -> u8 {
        match self {
            Algorithm::Rsa(_) => 1,
            Algorithm::Ec(_) if slot == Slot::Decryption => 18,
            Algorithm::Ec(_) => 19,
            Algorithm::Ed25519 => 22,
            Algorithm::X25519 => 18,
        }
    }

    pub fn describe(self) -> String {
        match self {
            Algorithm::Rsa(bits) => format!("RSA-{bits}"),
            Algorithm::Ec(curve) => curve.name.to_string(),
            Algorithm::Ed25519 => "Ed25519".to_string(),
            Algorithm::X25519 => "X25519".to_string(),
        }
    }
}

/// A key's public half, as the card gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// The point as the card writes it: uncompressed for the NIST and
    /// Koblitz curves, the bare 32 bytes for Ed25519 and X25519.
    Point(Vec<u8>),
}

impl PublicKey {
    fn parse(template: &[u8]) -> Result<PublicKey, String> {
        if let Some(point) = tlv::find_optional(template, 0x86)? {
            return Ok(PublicKey::Point(point.to_vec()));
        }
        Ok(PublicKey::Rsa { n: tlv::find(template, 0x81)?.to_vec(),
                            e: tlv::find(template, 0x82)?.to_vec() })
    }
}

/// A multiprecision integer (RFC 4880 3.2): bit count, then the bytes
/// without leading zeros.
fn mpi(value: &[u8]) -> Vec<u8> {
    let skip = value.iter().take_while(|&&b| b == 0).count();
    let value = &value[skip..];
    let bits = match value.first() {
        Some(&top) => value.len() * 8 - top.leading_zeros() as usize,
        None => 0,
    };
    let mut out = (bits as u16).to_be_bytes().to_vec();
    out.extend_from_slice(value);
    out
}

/// The body of a version 4 public key packet (RFC 4880 5.5.2) for a card
/// key: the format the fingerprint is computed over.
pub fn key_packet_body(algorithm: Algorithm, slot: Slot, key: &PublicKey, created: u32)
                       -> Result<Vec<u8>, String> {
    let mut body = vec![4];
    body.extend_from_slice(&created.to_be_bytes());
    body.push(algorithm.openpgp_id(slot));
    match (algorithm, key) {
        (Algorithm::Rsa(_), PublicKey::Rsa { n, e }) => {
            body.extend_from_slice(&mpi(n));
            body.extend_from_slice(&mpi(e));
        }
        (Algorithm::Ec(curve), PublicKey::Point(point)) => {
            body.push(curve.oid.len() as u8);
            body.extend_from_slice(curve.oid);
            body.extend_from_slice(&mpi(point));
            if slot == Slot::Decryption {
                // KDF parameters: length 3, version 1, hash, cipher.
                body.extend_from_slice(&[3, 1, curve.kdf.0, curve.kdf.1]);
            }
        }
        (Algorithm::Ed25519, PublicKey::Point(point)) => {
            body.push(ED25519_OID.len() as u8);
            body.extend_from_slice(ED25519_OID);
            body.extend_from_slice(&mpi(&[&[0x40], point.as_slice()].concat()));
        }
        (Algorithm::X25519, PublicKey::Point(point)) => {
            body.push(X25519_OID.len() as u8);
            body.extend_from_slice(X25519_OID);
            body.extend_from_slice(&mpi(&[&[0x40], point.as_slice()].concat()));
            // SHA-256 and AES-128, as GnuPG writes for Curve25519.
            body.extend_from_slice(&[3, 1, 8, 7]);
        }
        _ => return Err("The card's public key does not match its algorithm.".to_string()),
    }
    Ok(body)
}

fn sha(name: &str, parts: &[&[u8]]) -> Result<Vec<u8>, String> {
    let mut hash = api::AnyHash::new(name)?;
    for part in parts {
        hash.update(part);
    }
    Ok(hash.digest())
}

/// The version 4 fingerprint: SHA-1 of `99`, the body's length and the
/// body.
pub fn fingerprint(body: &[u8]) -> Result<Vec<u8>, String> {
    sha("sha1", &[&[0x99], &(body.len() as u16).to_be_bytes(), body])
}

/// An OpenPGP packet with a new-format header (RFC 4880 4.2.2).
pub fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xC0 | tag];
    let n = body.len();
    if n < 192 {
        out.push(n as u8);
    } else if n < 8384 {
        let m = n - 192;
        out.extend_from_slice(&[((m >> 8) + 192) as u8, m as u8]);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

/// Card status, from the application related data and friends.
#[derive(Debug, Clone)]
pub struct Status {
    /// The full AID: version, manufacturer and serial are inside it.
    pub aid: Vec<u8>,
    pub algorithms: [Option<Algorithm>; 3],
    pub fingerprints: [Vec<u8>; 3],
    pub times: [u32; 3],
    /// PW1, reset code and PW3 tries left.
    pub tries: [u8; 3],
    pub signatures: Option<u32>,
}

impl Status {
    pub fn version(&self) -> String {
        match self.aid.get(6..8) {
            Some(v) => format!("{}.{}", v[0], v[1]),
            None => "?".to_string(),
        }
    }

    pub fn serial(&self) -> String {
        match self.aid.get(8..14) {
            Some(s) => format!("{:02X}{:02X} {}", s[0], s[1], super::hex(&s[2..]).to_uppercase()),
            None => "?".to_string(),
        }
    }
}

/// Find a tag at any depth of a constructed object: cards differ on
/// whether the discretionary data objects sit inside `73` or directly in
/// `6E`.
fn deep_find(data: &[u8], tag: u32) -> Option<&[u8]> {
    for item in tlv::parse(data).ok()? {
        if item.tag == tag {
            return Some(item.value);
        }
        // Constructed: bit 0x20 of the first tag byte.
        let first = if item.tag > 0xFFFF { item.tag >> 16 } else if item.tag > 0xFF {
            item.tag >> 8 } else { item.tag };
        if first & 0x20 != 0 {
            if let Some(found) = deep_find(item.value, tag) {
                return Some(found);
            }
        }
    }
    None
}

pub struct OpenPgp<'a> {
    pub card: &'a mut Card,
}

fn pin_error(sw: u16, which: &str) -> String {
    match sw {
        0x63C0..=0x63CF => format!("Wrong {which}: {} left.", super::card::tries(sw & 0x0F)),
        0x6982 => format!("Wrong {which}."),
        0x6983 => format!("The {which} is blocked."),
        other => format!("Verifying the {which}: the card answered {other:04X} ({}).",
                         super::card::describe(other)),
    }
}

impl<'a> OpenPgp<'a> {
    pub fn select(card: &'a mut Card) -> Result<OpenPgp<'a>, String> {
        card.get_response = 0xC0;
        card.select(&AID, "OpenPGP")?;
        Ok(OpenPgp { card })
    }

    fn get_data(&mut self, object: u16) -> Result<Vec<u8>, String> {
        let [p1, p2] = object.to_be_bytes();
        self.card.get(0, INS_GET_DATA, p1, p2, &format!("Reading object {object:04X}"))
    }

    fn put_data(&mut self, object: u16, value: &[u8]) -> Result<(), String> {
        let [p1, p2] = object.to_be_bytes();
        self.card.call(0, INS_PUT_DATA, p1, p2, value, &format!("Writing object {object:04X}"))?;
        Ok(())
    }

    pub fn status(&mut self) -> Result<Status, String> {
        let related = self.get_data(0x6E)?;
        let aid = deep_find(&related, 0x4F).ok_or("The card did not give its AID.")?.to_vec();
        let mut algorithms = [None, None, None];
        for (i, slot) in [Slot::Signature, Slot::Decryption, Slot::Authentication]
                .into_iter().enumerate() {
            if let Some(attributes) = deep_find(&related, u32::from(slot.attributes_object())) {
                algorithms[i] = Algorithm::from_attributes(attributes).ok();
            }
        }
        let prints = deep_find(&related, 0xC5).unwrap_or(&[]);
        let fingerprints = [0, 1, 2].map(|i| prints.get(20 * i..20 * i + 20)
                                                  .map(<[u8]>::to_vec).unwrap_or_default());
        let stamps = deep_find(&related, 0xCD).unwrap_or(&[]);
        let times = [0, 1, 2].map(|i| stamps.get(4 * i..4 * i + 4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("four bytes"))).unwrap_or(0));
        let pw = deep_find(&related, 0xC4).ok_or("The card did not give its PIN status.")?;
        let tries = [pw.get(4), pw.get(5), pw.get(6)].map(|b| b.copied().unwrap_or(0));
        let signatures = self.card.read(0, INS_GET_DATA, 0x00, 0x7A)?;
        let signatures = if signatures.ok() {
            tlv::find_optional(&signatures.data, 0x93)?.filter(|c| c.len() == 3)
                .map(|c| u32::from_be_bytes([0, c[0], c[1], c[2]]))
        } else {
            None
        };
        Ok(Status { aid, algorithms, fingerprints, times, tries, signatures })
    }

    /// Verify a PIN: `81` PW1 for signing, `82` PW1 for decryption and
    /// authentication, `83` PW3 the admin PIN.
    pub fn verify(&mut self, reference: u8, pin: &str) -> Result<(), String> {
        let which = if reference == 0x83 { "admin PIN" } else { "PIN" };
        let response = self.card.send(0, INS_VERIFY, 0, reference, pin.as_bytes())?;
        if response.ok() { Ok(()) } else { Err(pin_error(response.sw, which)) }
    }

    pub fn change_pin(&mut self, admin: bool, old: &str, new: &str) -> Result<(), String> {
        let (reference, which, minimum) = if admin { (0x83, "admin PIN", 8) }
                                          else { (0x81, "PIN", 6) };
        if new.len() < minimum {
            return Err(format!("The {which} is at least {minimum} characters."));
        }
        let data = [old.as_bytes(), new.as_bytes()].concat();
        let response = self.card.send(0, INS_CHANGE_REFERENCE, 0, reference, &data)?;
        if response.ok() { Ok(()) } else { Err(pin_error(response.sw, which)) }
    }

    /// Set a new user PIN with the admin PIN verified first.
    pub fn reset_pin(&mut self, new: &str) -> Result<(), String> {
        let response = self.card.send(0, INS_RESET_RETRY, 0x02, 0x81, new.as_bytes())?;
        if response.ok() { Ok(()) } else { Err(pin_error(response.sw, "admin PIN")) }
    }

    pub fn algorithm(&mut self, slot: Slot) -> Result<Algorithm, String> {
        let related = self.get_data(0x6E)?;
        let attributes = deep_find(&related, u32::from(slot.attributes_object()))
            .ok_or("The card did not give the key's algorithm.")?;
        Algorithm::from_attributes(attributes)
    }

    pub fn set_algorithm(&mut self, slot: Slot, algorithm: Algorithm) -> Result<(), String> {
        self.put_data(slot.attributes_object(), &algorithm.attributes(slot))
    }

    /// Generate a key on the card (admin PIN first), then write its
    /// fingerprint and creation time, so that the card describes the
    /// same OpenPGP key `export` will write.
    pub fn generate(&mut self, slot: Slot, algorithm: Algorithm, created: u32)
                    -> Result<PublicKey, String> {
        self.set_algorithm(slot, algorithm)?;
        let answer = self.card.call(0, INS_GENERATE, 0x80, 0x00, &[slot.crt(), 0x00],
                                    &format!("Generating the {slot:?} key"))?;
        let key = PublicKey::parse(tlv::find(&answer, 0x7F49)?)?;
        self.register(slot, algorithm, &key, created)?;
        Ok(key)
    }

    /// Write the fingerprint and creation time for a key now on the card.
    pub fn register(&mut self, slot: Slot, algorithm: Algorithm, key: &PublicKey, created: u32)
                    -> Result<Vec<u8>, String> {
        let body = key_packet_body(algorithm, slot, key, created)?;
        let print = fingerprint(&body)?;
        self.put_data(slot.fingerprint_object(), &print)?;
        self.put_data(slot.time_object(), &created.to_be_bytes())?;
        Ok(print)
    }

    /// The public key in a slot, read back (READ PUBLIC KEY, `47 81`).
    pub fn public_key(&mut self, slot: Slot) -> Result<PublicKey, String> {
        let answer = self.card.call(0, INS_GENERATE, 0x81, 0x00, &[slot.crt(), 0x00],
                                    &format!("Reading the {slot:?} key"))?;
        PublicKey::parse(tlv::find(&answer, 0x7F49)?)
    }

    /// Import a private key (admin PIN first): the extended header list
    /// of spec 4.4.3.12, whose `7F48` lists each component's tag and
    /// length and whose `5F48` holds the values, in the same order.
    pub fn import(&mut self, slot: Slot, key: &api::PrivateKeyParts, created: u32)
                  -> Result<(Algorithm, PublicKey), String> {
        let (algorithm, components, public): (Algorithm, Vec<(u32, Vec<u8>)>, PublicKey) =
            match key {
                api::PrivateKeyParts::Rsa { p, q, e } => {
                    let rsa = api::RsaKey::from_primes(p, q, e)?;
                    let public = rsa.public_key();
                    (Algorithm::Rsa(rsa.bits() as u16),
                     vec![(0x91, e.clone()), (0x92, p.clone()), (0x93, q.clone())],
                     PublicKey::Rsa { n: public.modulus(), e: public.exponent() })
                }
                api::PrivateKeyParts::Ec { curve, private } => {
                    let found = CURVES.iter().find(|c| c.library == curve.as_str())
                        .ok_or_else(|| format!("This example puts P-256, P-384, P-521 and \
                                                secp256k1 keys on a card, not {curve}."))?;
                    let point = api::EcKey::from_private(curve, private)?.public_bytes(false)?;
                    (Algorithm::Ec(found), vec![(0x92, private.clone())], PublicKey::Point(point))
                }
                api::PrivateKeyParts::Eddsa { curve, private } if curve == "ed25519" => {
                    let point = api::eddsa_public_key("ed25519", private)?;
                    (Algorithm::Ed25519, vec![(0x92, private.clone())], PublicKey::Point(point))
                }
                // The card takes an X25519 scalar in the reverse of RFC
                // 7748's byte order, as OpenPGP writes Curve25519 secrets.
                api::PrivateKeyParts::Xdh { curve, private } if curve == "x25519" => {
                    if slot != Slot::Decryption {
                        return Err("An X25519 key decrypts: it goes in the dec slot."
                            .to_string());
                    }
                    let point = api::x25519_public_key(private)?;
                    let mut reversed = private.clone();
                    reversed.reverse();
                    (Algorithm::X25519, vec![(0x92, reversed)], PublicKey::Point(point))
                }
                _ => return Err("This example puts RSA, NIST, secp256k1, Ed25519 and X25519 \
                                 keys on an OpenPGP card.".to_string()),
            };
        self.import_components(slot, algorithm, &components)?;
        self.register(slot, algorithm, &public, created)?;
        Ok((algorithm, public))
    }

    fn import_components(&mut self, slot: Slot, algorithm: Algorithm,
                         components: &[(u32, Vec<u8>)]) -> Result<(), String> {
        self.set_algorithm(slot, algorithm)?;
        let mut headers = Vec::new();
        let mut values = Vec::new();
        for (tag, value) in components {
            let encoded = tlv::encode(*tag, value);
            headers.extend_from_slice(&encoded[..encoded.len() - value.len()]);
            values.extend_from_slice(value);
        }
        let mut list = vec![slot.crt(), 0x00];
        list.extend_from_slice(&tlv::encode(0x7F48, &headers));
        list.extend_from_slice(&tlv::encode(0x5F48, &values));
        self.card.call(0, INS_PUT_DATA_ODD, 0x3F, 0xFF, &tlv::encode(0x4D, &list),
                       &format!("Importing the {slot:?} key"))?;
        Ok(())
    }

    /// PSO: COMPUTE DIGITAL SIGNATURE (PW1 in mode 81 first). `input` is
    /// the DigestInfo for RSA and the digest itself for ECDSA and EdDSA.
    pub fn sign(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let response = self.card.send(0, INS_PSO, 0x9E, 0x9A, input)?;
        if response.sw == 0x6982 {
            return Err("Signing needs the PIN first (mode 81).".to_string());
        }
        response.check("Signing")
    }

    /// Return the application to its factory state: block both PINs with
    /// wrong tries, then TERMINATE and ACTIVATE (spec 7.2.16-17).
    pub fn reset(&mut self) -> Result<(), String> {
        let status = self.status()?;
        for (reference, tries) in [(0x81, status.tries[0]), (0x83, status.tries[2])] {
            for _ in 0..tries {
                self.card.send(0, INS_VERIFY, 0, reference, &[0x00; 8])?;
            }
        }
        self.card.call(0, INS_TERMINATE, 0, 0, &[], "Terminating OpenPGP")?;
        self.card.call(0, INS_ACTIVATE, 0, 0, &[], "Activating OpenPGP")?;
        Ok(())
    }
}

/// Signature packets: what a card key signs to be usable from GnuPG.
pub mod signature {
    use super::*;

    /// The hash a signature by this key uses, by OpenPGP's number and
    /// this library's name: as wide as the curve, which GnuPG expects of
    /// ECDSA, and SHA-256 otherwise.
    pub fn hash_for(algorithm: Algorithm) -> (u8, &'static str) {
        match algorithm {
            Algorithm::Ec(curve) => match curve.kdf.0 {
                9 => (9, "sha384"),
                10 => (10, "sha512"),
                _ => (8, "sha256"),
            },
            _ => (8, "sha256"),
        }
    }

    /// What the card is asked to sign for `digest`, by algorithm: the
    /// DigestInfo for RSA, the digest for the others.
    pub fn card_input(algorithm: Algorithm, digest: &[u8]) -> Result<Vec<u8>, String> {
        match algorithm {
            Algorithm::Rsa(_) => super::super::piv::digest_info(hash_for(algorithm).1, digest),
            _ => Ok(digest.to_vec()),
        }
    }

    /// Turns a digest into the card's signature.
    pub type DigestSigner<'a> = dyn FnMut(&[u8]) -> Result<Vec<u8>, String> + 'a;

    /// Build a version 4 signature packet. `signed` is everything the
    /// signature covers before its own trailer; `sign` turns the digest
    /// into the card's signature.
    pub fn build(kind: u8, algorithm: Algorithm, issuer: &[u8], created: u32,
                 extra_hashed: &[u8], signed: &[u8],
                 sign: &mut DigestSigner<'_>)
                 -> Result<Vec<u8>, String> {
        let mut hashed = Vec::new();
        // Signature creation time, then the issuer's fingerprint.
        hashed.extend_from_slice(&[5, 2]);
        hashed.extend_from_slice(&created.to_be_bytes());
        hashed.extend_from_slice(&[22, 33, 4]);
        hashed.extend_from_slice(issuer);
        hashed.extend_from_slice(extra_hashed);

        let (hash_id, hash_name) = hash_for(algorithm);
        let mut header = vec![4, kind, algorithm.openpgp_id(Slot::Signature), hash_id];
        header.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
        header.extend_from_slice(&hashed);
        let mut trailer = vec![4, 0xFF];
        trailer.extend_from_slice(&(header.len() as u32).to_be_bytes());
        let digest = sha(hash_name, &[signed, &header, &trailer])?;

        let raw = sign(&card_input(algorithm, &digest)?)?;
        let mut body = header;
        // Unhashed: the issuer key ID, the fingerprint's low eight bytes.
        body.extend_from_slice(&10u16.to_be_bytes());
        body.extend_from_slice(&[9, 16]);
        body.extend_from_slice(&issuer[12..20]);
        body.extend_from_slice(&digest[..2]);
        match algorithm {
            Algorithm::Rsa(_) => body.extend_from_slice(&mpi(&raw)),
            _ => {
                let half = raw.len() / 2;
                body.extend_from_slice(&mpi(&raw[..half]));
                body.extend_from_slice(&mpi(&raw[half..]));
            }
        }
        Ok(packet(2, &body))
    }

    /// The bytes a key signature covers for a key packet body: `99`,
    /// length, body.
    pub fn key_prefix(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x99];
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// And for a user ID: `B4`, four-byte length, the ID.
    pub fn user_id_prefix(user_id: &str) -> Vec<u8> {
        let mut out = vec![0xB4];
        out.extend_from_slice(&(user_id.len() as u32).to_be_bytes());
        out.extend_from_slice(user_id.as_bytes());
        out
    }
}
