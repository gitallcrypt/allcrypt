//! Smart cards and YubiKeys, through PC/SC: PIV keys and certificates,
//! OpenPGP card keys usable from GnuPG, OATH one-time passwords, and the
//! YubiKey OTP application's HMAC-SHA1 challenge-response. The card holds
//! the private keys and secrets; everything around them - hashing,
//! padding, certificates, OpenPGP packets, and checking every answer the
//! card gives - is this library.
//!
//!     cargo run --release --example smartcard -- readers
//!     cargo run --release --example smartcard -- [CARD] info
//!     cargo run --release --example smartcard -- [CARD] piv COMMAND ...
//!     cargo run --release --example smartcard -- [CARD] openpgp COMMAND ...
//!     cargo run --release --example smartcard -- [CARD] oath COMMAND ...
//!     cargo run --release --example smartcard -- [CARD] otp COMMAND ...
//!
//! CARD is `--reader NAME` (any reader whose name contains NAME; the
//! first reader with a card otherwise) or `--card tcp:HOST:PORT`, a card
//! simulator speaking canokey-core's `apdu-replay` protocol, which is
//! what `scripts/witness/cardsim.py` serves.
//!
//! PIV:
//!
//!     piv info
//!     piv generate SLOT TYPE [--management-key HEX] [--pin-policy P]
//!             [--touch-policy P] [--self-sign COMMON-NAME --pin PIN]
//!             [--time UNIX] [--days N]
//!     piv import SLOT KEYFILE [--management-key HEX]
//!     piv sign SLOT FILE --pin PIN [--hash sha256] [--out FILE]
//!     piv decrypt SLOT FILE --pin PIN [--out FILE]
//!     piv ecdh SLOT PEER-HEX --pin PIN [--out FILE]
//!     piv read-cert SLOT [--out FILE]
//!     piv write-cert SLOT CERTFILE [--management-key HEX]
//!     piv attest SLOT [--out FILE]
//!     piv change-pin --pin OLD --new NEW
//!     piv change-puk --puk OLD --new NEW
//!     piv unblock-pin --puk PUK --new NEW
//!     piv set-management-key --new HEX [--type aes192] [--touch]
//!             [--management-key HEX]
//!     piv reset
//!
//! OpenPGP card:
//!
//!     openpgp status
//!     openpgp generate SLOT ALGORITHM --admin-pin PIN [--time UNIX]
//!     openpgp import SLOT KEYFILE --admin-pin PIN [--time UNIX]
//!     openpgp export --user-id ID --pin PIN [--time UNIX] [--out FILE]
//!     openpgp sign FILE --pin PIN [--time UNIX] [--out FILE]
//!     openpgp change-pin --pin OLD --new NEW
//!     openpgp change-admin-pin --admin-pin OLD --new NEW
//!     openpgp reset-pin --admin-pin PIN --new NEW
//!     openpgp reset
//!
//! OATH:
//!
//!     oath list [--password PW]
//!     oath add NAME BASE32-SECRET [--hotp] [--digits N] [--hash sha256]
//!             [--issuer NAME] [--period S] [--touch] [--counter N]
//!             [--password PW]
//!     oath code [NAME] [--time UNIX] [--password PW]
//!     oath delete NAME [--password PW]
//!     oath set-password --new PW [--password PW]
//!     oath remove-password --password PW
//!     oath reset
//!
//! YubiKey OTP:
//!
//!     otp status
//!     otp challenge SLOT CHALLENGE-HEX
//!     otp program SLOT KEY-HEX [--touch]
//!
//! SLOT for PIV is 9a, 9c, 9d, 9e or 82-95 (f9 to read the attestation
//! certificate); TYPE is rsa1024 to rsa4096, p256, p384, ed25519 or
//! x25519. SLOT for OpenPGP is sig, dec or aut; ALGORITHM is rsa2048 to
//! rsa4096, p256, p384, p521, secp256k1, ed25519 or x25519. A PIN, PUK,
//! password or management key given as `-` is read from standard input,
//! one line each in the order the options are listed above, so that it
//! is not on the command line. Without `--management-key` the factory
//! default is used, and says so. `--time` fixes what is otherwise the
//! clock: an OpenPGP key's creation time, a signature's, a TOTP code's.
//!
//! What has checked it is in `examples/products/README.md`.

mod card;
mod oath;
mod openpgp;
mod otp;
mod pcsc;
mod piv;
mod tlv;

#[path = "../shared/base64.rs"]
mod base64;
#[path = "../shared/inflate.rs"]
mod inflate;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[cfg(test)]
#[path = "../shared/fixtures.rs"]
mod fixtures;
#[cfg(test)]
mod tests;

use std::cell::RefCell;

/// A line of output, gathered rather than printed so that the tests can
/// compare it.
macro_rules! say {
    ($out:expr, $($text:tt)*) => {{
        $out.push_str(&format!($($text)*));
        $out.push('\n');
    }};
}

use allcrypt::api;
use card::Card;

// ------------------------------------------------------------- helpers --

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let text: String = text.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if !text.len().is_multiple_of(2) || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{text}: not hex."));
    }
    Ok((0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect())
}

/// A gzip member's contents (RFC 1952): the header skipped and the
/// DEFLATE data inflated. The trailer's CRC is not checked: what is
/// inside is a certificate, parsed and signature-checked afterwards.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 18 || data[0] != 0x1F || data[1] != 0x8B || data[2] != 8 {
        return Err("A compressed certificate is not gzip.".to_string());
    }
    let flags = data[3];
    let mut at = 10;
    if flags & 0x04 != 0 {
        let extra = data.get(at..at + 2).ok_or("A gzip header runs past the end.")?;
        at += 2 + usize::from(u16::from_le_bytes([extra[0], extra[1]]));
    }
    for bit in [0x08, 0x10] {
        if flags & bit != 0 {
            let rest = data.get(at..).ok_or("A gzip header runs past the end.")?;
            at += rest.iter().position(|&b| b == 0).ok_or("A gzip name has no end.")? + 1;
        }
    }
    if flags & 0x02 != 0 {
        at += 2;
    }
    Ok(inflate::inflate(data.get(at..).ok_or("A gzip header runs past the end.")?,
                        1 << 20)?.0)
}

pub fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::encode(der);
    let lines: Vec<&str> = body.as_bytes().chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII")).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// A certificate as DER, from a DER or PEM file.
fn read_certificate_file(path: &str) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if data.starts_with(b"-----") {
        let text = String::from_utf8_lossy(&data);
        let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        return base64::decode(&body).ok_or_else(|| format!("{path}: bad PEM."));
    }
    Ok(data)
}

/// OpenPGP ASCII armor (RFC 4880 6.2), with its CRC-24.
pub fn armor(label: &str, data: &[u8]) -> String {
    let mut crc: u32 = 0xB7_04CE;
    for &byte in data {
        crc ^= u32::from(byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    let body = base64::encode(data);
    let lines: Vec<&str> = body.as_bytes().chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII")).collect();
    format!("-----BEGIN PGP {label}-----\n\n{}\n={}\n-----END PGP {label}-----\n",
            lines.join("\n"), base64::encode(&(crc & 0xFF_FFFF).to_be_bytes()[1..]))
}

/// A DER `Ecdsa-Sig-Value` - the form PIV and X.509 use - as the
/// fixed-width `r || s` this library's verifier takes.
pub fn ecdsa_der_to_raw(der: &[u8], width: usize) -> Result<Vec<u8>, String> {
    let sequence = tlv::find(der, 0x30)?;
    let parts = tlv::parse(sequence)?;
    if parts.len() != 2 || parts.iter().any(|p| p.tag != 0x02) {
        return Err("An ECDSA signature is not two INTEGERs.".to_string());
    }
    let mut out = Vec::with_capacity(2 * width);
    for part in parts {
        let skip = part.value.iter().take_while(|&&b| b == 0).count();
        let value = &part.value[skip..];
        if value.len() > width {
            return Err("An ECDSA signature component is wider than the curve.".to_string());
        }
        out.extend(std::iter::repeat_n(0u8, width - value.len()));
        out.extend_from_slice(value);
    }
    Ok(out)
}

fn hash_bytes(name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    use allcrypt::hash_functions::HashFunction;
    let mut hash = api::AnyHash::new(name)?;
    hash.update(data);
    Ok(hash.digest())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

// ----------------------------------------------------------- arguments --

pub struct Args {
    words: Vec<String>,
}

/// Options that take no value.
const SWITCHES: &[&str] = &["--hotp", "--touch"];

/// Options that take one. Anything else beginning `--` is refused, so a
/// misspelt `--pin-policy` is an error rather than a key generated
/// under the default policy.
const OPTIONS: &[&str] = &[
    "--admin-pin", "--card", "--counter", "--days", "--digits", "--hash", "--issuer",
    "--management-key", "--new", "--out", "--password", "--period", "--pin", "--pin-policy",
    "--puk", "--random-seed", "--reader", "--record", "--self-sign", "--time",
    "--touch-policy", "--type", "--user-id",
];

impl Args {
    pub fn new(words: Vec<String>) -> Result<Args, String> {
        let mut i = 0;
        while i < words.len() {
            let word = words[i].as_str();
            if OPTIONS.contains(&word) {
                if i + 1 == words.len() {
                    return Err(format!("{word} needs a value."));
                }
                i += 1;
            } else if word.starts_with("--") && !SWITCHES.contains(&word) {
                return Err(format!("There is no option {word}."));
            }
            i += 1;
        }
        Ok(Args { words })
    }

    fn flag(&self, name: &str) -> bool {
        self.words.iter().any(|w| w == name)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.words.iter().position(|w| w == name)
            .and_then(|i| self.words.get(i + 1)).map(String::as_str)
    }

    /// A secret option: its value, or a line of standard input for `-`.
    fn secret(&self, name: &str) -> Result<Option<String>, String> {
        match self.value(name) {
            Some("-") => {
                let line = passphrase::read_line(&format!("{}: ", &name[2..]))?;
                Ok(Some(String::from_utf8(line).map_err(|_| format!("{name} is not UTF-8."))?))
            }
            other => Ok(other.map(str::to_string)),
        }
    }

    fn required_secret(&self, name: &str) -> Result<String, String> {
        self.secret(name)?.ok_or_else(|| format!("{name} is required."))
    }

    fn number(&self, name: &str) -> Result<Option<u64>, String> {
        self.value(name).map(|v| v.parse().map_err(|_| format!("{name}: {v} is not a number.")))
            .transpose()
    }

    /// The words that are not options or their values.
    fn positional(&self) -> Vec<&str> {
        let mut out = Vec::new();
        let mut skip = false;
        for word in &self.words {
            if skip {
                skip = false;
            } else if word.starts_with("--") {
                skip = !SWITCHES.contains(&word.as_str());
            } else {
                out.push(word.as_str());
            }
        }
        out
    }
}

// ----------------------------------------------------------------- PIV --

fn management_key(args: &Args, piv: &mut piv::Piv) -> Result<(), String> {
    let key = match args.secret("--management-key")? {
        Some(text) => unhex(&text)?,
        None => {
            eprintln!("Using the factory management key.");
            piv::DEFAULT_MANAGEMENT_KEY.to_vec()
        }
    };
    piv.authenticate(&key)
}

/// A PIN or touch policy by name: PIV's numbers (YubiKey's extension).
fn policy(text: Option<&str>, touch: bool) -> Result<u8, String> {
    Ok(match (text, touch) {
        (None, _) => 0,
        (Some("never"), _) => 1,
        (Some("once"), false) | (Some("always"), true) => 2,
        (Some("always"), false) | (Some("cached"), true) => 3,
        (Some(other), _) => return Err(format!("{other} is not a {} policy.",
                                               if touch { "touch" } else { "PIN" })),
    })
}

/// The type and public key of a slot, from GET METADATA.
/// A slot's key type and public key. The metadata instruction (YubiKey
/// 5.3 and later, CanoKey) says both; a card without it, or one that
/// refuses it for a slot, still has the certificate stored beside the
/// key, whose public half says the same.
fn slot_key(piv: &mut piv::Piv, slot: u8) -> Result<(piv::KeyType, piv::PublicKey), String> {
    let why_not = match piv.metadata(slot) {
        Ok(Some(metadata)) => return match (metadata.algorithm, &metadata.public_key) {
            (Some(code), Some(template)) => {
                let key_type = piv::KeyType::from_code(code)
                    .ok_or_else(|| format!("Slot {slot:02x} holds algorithm {code:02x}, which \
                                            this example does not know."))?;
                Ok((key_type, piv::PublicKey::parse(key_type, template)?))
            }
            _ => Err(format!("Slot {slot:02x} holds no key.")),
        },
        Ok(None) => "the card does not report key metadata".to_string(),
        Err(error) => error,
    };
    let der = piv.read_certificate(slot)?.ok_or_else(|| {
        format!("Slot {slot:02x}'s key type is unknown: {}, and the slot has no certificate \
                 to read it from.", why_not.trim_end_matches('.'))
    })?;
    key_from_certificate(&der)
}

/// The PIV key type and public key a certificate carries.
fn key_from_certificate(der: &[u8]) -> Result<(piv::KeyType, piv::PublicKey), String> {
    use allcrypt::x509::PublicKey as Spki;
    let certificate = allcrypt::x509::Certificate::parse(der)?;
    Ok(match &certificate.public_key {
        Spki::Rsa { n, e } => {
            let key_type = piv::KeyType::from_name(&format!("rsa{}", n.bit_len()))?;
            (key_type, piv::PublicKey::Rsa { n: n.to_bytes_be(), e: e.to_bytes_be() })
        }
        Spki::Ec { curve: curve @ ("P-256" | "P-384"), point } => {
            let key_type = if *curve == "P-256" { piv::KeyType::P256 } else { piv::KeyType::P384 };
            (key_type, piv::PublicKey::Ec { curve, point: point.to_vec() })
        }
        Spki::Eddsa { curve: "ed25519", key } =>
            (piv::KeyType::Ed25519, piv::PublicKey::Ed25519(key.to_vec())),
        _ => return Err("The slot's certificate holds a key PIV has no type for.".to_string()),
    })
}

/// Check a signature the card made against the slot's public key. A card
/// signing with another key, or a host padding wrongly, is caught here
/// rather than by whoever relies on the signature.
fn verify_piv_signature(key: &piv::PublicKey, hash: &str, digest: &[u8], message: &[u8],
                        signature: &[u8]) -> Result<(), String> {
    let good = match key {
        piv::PublicKey::Rsa { n, e } => api::RsaPublicKey::new(n, e)?
            .verify(hash, digest, signature)?,
        piv::PublicKey::Ec { curve, point } => {
            let public = api::EcPublicKey::from_bytes(curve, point)?;
            let width = public.key_size().div_ceil(8);
            public.verify(digest, &ecdsa_der_to_raw(signature, width)?)?
        }
        piv::PublicKey::Ed25519(public) =>
            api::eddsa_verify("ed25519", public, message, signature, &[]).is_ok(),
        piv::PublicKey::X25519(_) => return Err("An X25519 key does not sign.".to_string()),
    };
    if good { Ok(()) } else { Err("The card's signature does not verify.".to_string()) }
}

/// Sign `message` with the key in `slot`: hashed and padded here, the
/// private operation on the card, the answer verified here. The result
/// is in X.509's form: PKCS#1 v1.5, a DER ECDSA signature, or raw
/// Ed25519.
pub fn piv_sign(piv: &mut piv::Piv, slot: u8, key_type: piv::KeyType, key: &piv::PublicKey,
                hash: &str, message: &[u8]) -> Result<Vec<u8>, String> {
    let digest = hash_bytes(hash, message)?;
    let input = match key_type.rsa_bytes() {
        Some(width) => piv::pkcs1_block(hash, &digest, width)?,
        None if key_type == piv::KeyType::Ed25519 => message.to_vec(),
        // ECDSA signs the digest's leftmost bits as wide as the group
        // (SEC 1 4.1.3), and the card takes exactly that many bytes: a
        // longer digest is cut, a shorter one widened with leading zeros,
        // which leaves its value alone.
        None => {
            let width = if key_type == piv::KeyType::P256 { 32 } else { 48 };
            if digest.len() >= width {
                digest[..width].to_vec()
            } else {
                let mut padded = vec![0; width - digest.len()];
                padded.extend_from_slice(&digest);
                padded
            }
        }
    };
    let signature = piv.sign(slot, key_type, &input)?;
    verify_piv_signature(key, hash, &digest, message, &signature)?;
    Ok(signature)
}

/// A self-signed certificate for the key in `slot`, signed by the card:
/// the library builds and encodes it, and the card signs the
/// TBSCertificate through `SigningKey::External`.
pub fn self_signed(piv: &mut piv::Piv, slot: u8, key_type: piv::KeyType, key: &piv::PublicKey,
                   name: &str, serial: Vec<u8>, validity: (i64, i64))
                   -> Result<Vec<u8>, String> {
    use allcrypt::bignum::BigUint;
    use allcrypt::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
    let (n, e);
    let curve;
    let subject = match key {
        piv::PublicKey::Rsa { n: modulus, e: exponent } => {
            n = BigUint::from_bytes_be(modulus);
            e = BigUint::from_bytes_be(exponent);
            SubjectKey::Rsa { n: &n, e: &e }
        }
        piv::PublicKey::Ec { curve: curve_name, point } => {
            curve = allcrypt::ec::curves::by_name(curve_name)?;
            SubjectKey::Ec { curve: &curve, point }
        }
        piv::PublicKey::Ed25519(point) => SubjectKey::Eddsa { name: "ed25519", key: point },
        piv::PublicKey::X25519(_) =>
            return Err("An X25519 key cannot sign a certificate.".to_string()),
    };
    let signer = RefCell::new(piv);
    let sign = |hash: &str, tbs: &[u8]| {
        piv_sign(&mut signer.borrow_mut(), slot, key_type, key, hash, tbs)
    };
    let mut builder = CertificateBuilder::new(name, subject);
    builder.serial = serial;
    let (not_before, not_after) = (allcrypt::asn1::format_time(validity.0),
                                   allcrypt::asn1::format_time(validity.1));
    builder.not_before = &not_before;
    builder.not_after = &not_after;
    builder.sign(&SigningKey::External { public: subject, sign: &sign })
}

fn piv_command(card: &mut Card, args: &Args, out: &mut String) -> Result<(), String> {
    let words = args.positional();
    let command = *words.get(1).ok_or("piv needs a command.")?;
    let slot_at = |i: usize| -> Result<u8, String> {
        piv::parse_slot(words.get(i).ok_or("A slot is needed.")?)
    };
    let mut piv = piv::Piv::select(card)?;
    match command {
        "info" => {
            let version = piv.version()?;
            say!(out, "PIV version {}.{}.{}", version[0], version[1], version[2]);
            if let Some(serial) = piv.serial()? {
                say!(out, "serial {serial}");
            }
            say!(out, "management key {:?}", piv.management_key_type()?);
            for (reference, name) in [(0x80, "PIN"), (0x81, "PUK")] {
                if let Some((total, left)) = piv.metadata(reference)?.and_then(|m| m.retries) {
                    say!(out, "{name}: {left} of {total} tries left");
                }
            }
            for slot in [0x9A, 0x9C, 0x9D, 0x9E] {
                let key = slot_key(&mut piv, slot).map(|(_, key)| key.describe()).ok();
                let certificate = piv.read_certificate(slot)?
                    .and_then(|der| api::Certificate::parse(&der).ok())
                    .and_then(|c| c.subject_string().ok());
                if key.is_some() || certificate.is_some() {
                    say!(out, "slot {slot:02x}: {}; certificate {}",
                             key.unwrap_or_else(|| "key unknown".to_string()),
                             certificate.unwrap_or_else(|| "none".to_string()));
                }
            }
        }
        "generate" => {
            let slot = slot_at(2)?;
            let key_type = piv::KeyType::from_name(words.get(3).ok_or("A key type is needed.")?)?;
            management_key(args, &mut piv)?;
            let key = piv.generate(slot, key_type, policy(args.value("--pin-policy"), false)?,
                                   policy(args.value("--touch-policy"), true)?)?;
            say!(out, "{}", key.describe());
            if let Some(name) = args.value("--self-sign") {
                piv.verify_pin(&args.required_secret("--pin")?)?;
                let mut serial = piv.card.random(16)?;
                serial[0] = (serial[0] & 0x7F) | 0x01;
                let start = args.number("--time")?.unwrap_or_else(now) as i64;
                let days = args.number("--days")?.unwrap_or(365) as i64;
                let der = self_signed(&mut piv, slot, key_type, &key, name, serial,
                                      (start, start + days * 86400))?;
                piv.write_certificate(slot, &der)?;
                out.push_str(&pem("CERTIFICATE", &der));
            }
        }
        "import" => {
            let slot = slot_at(2)?;
            let parts = api::parse_private_key(&read_file(words.get(3)
                .ok_or("A key file is needed.")?)?)?;
            management_key(args, &mut piv)?;
            let key_type = piv.import(slot, &parts, policy(args.value("--pin-policy"), false)?,
                                      policy(args.value("--touch-policy"), true)?)?;
            say!(out, "imported a {} key into {slot:02x}", key_type.name());
        }
        "sign" => {
            let slot = slot_at(2)?;
            let message = read_file(words.get(3).ok_or("A file to sign is needed.")?)?;
            let hash = args.value("--hash").unwrap_or("sha256");
            let (key_type, key) = slot_key(&mut piv, slot)?;
            piv.verify_pin(&args.required_secret("--pin")?)?;
            let signature = piv_sign(&mut piv, slot, key_type, &key, hash, &message)?;
            write_or_hex(args, &signature, out)?;
        }
        "decrypt" => {
            let slot = slot_at(2)?;
            let ciphertext = read_file(words.get(3).ok_or("A ciphertext file is needed.")?)?;
            let (key_type, _) = slot_key(&mut piv, slot)?;
            piv.verify_pin(&args.required_secret("--pin")?)?;
            let block = piv.decrypt(slot, key_type, &ciphertext)?;
            write_or_hex(args, &piv::unpad_pkcs1_encryption(&block)?, out)?;
        }
        "ecdh" => {
            let slot = slot_at(2)?;
            let peer = unhex(words.get(3).ok_or("The peer's public key is needed.")?)?;
            let (key_type, _) = slot_key(&mut piv, slot)?;
            piv.verify_pin(&args.required_secret("--pin")?)?;
            write_or_hex(args, &piv.exchange(slot, key_type, &peer)?, out)?;
        }
        "read-cert" => {
            let slot = slot_at(2)?;
            let der = piv.read_certificate(slot)?
                .ok_or_else(|| format!("Slot {slot:02x} has no certificate."))?;
            write_or_print(args, &pem("CERTIFICATE", &der), out)?;
        }
        "write-cert" => {
            let slot = slot_at(2)?;
            let der = read_certificate_file(words.get(3).ok_or("A certificate is needed.")?)?;
            // A certificate for another key in the slot would make every
            // signature from it fail to verify against the certificate
            // the slot advertises. Where the card says which key the slot
            // holds, the two must agree.
            api::Certificate::parse(&der)?;
            let certified = key_from_certificate(&der).map(|(_, key)| key);
            if let Ok(Some(metadata)) = piv.metadata(slot) {
                if let (Some(code), Some(template)) = (metadata.algorithm, &metadata.public_key) {
                    let held = piv::KeyType::from_code(code)
                        .map(|key_type| piv::PublicKey::parse(key_type, template));
                    if let (Ok(certified), Some(Ok(held))) = (&certified, held) {
                        if *certified != held {
                            return Err(format!("The certificate is for another key than the \
                                                one in slot {slot:02x}."));
                        }
                    }
                }
            }
            management_key(args, &mut piv)?;
            piv.write_certificate(slot, &der)?;
        }
        "attest" => {
            let slot = slot_at(2)?;
            let attestation = piv.attest(slot)?;
            let signer = piv.read_certificate(0xF9)?
                .ok_or("The card has no attestation certificate in F9.")?;
            check_attestation(&attestation, &signer, &slot_key(&mut piv, slot)?.1)?;
            write_or_print(args, &pem("CERTIFICATE", &attestation), out)?;
        }
        "change-pin" => piv.change(false, &args.required_secret("--pin")?,
                                   &args.required_secret("--new")?)?,
        "change-puk" => piv.change(true, &args.required_secret("--puk")?,
                                   &args.required_secret("--new")?)?,
        "unblock-pin" => piv.unblock_pin(&args.required_secret("--puk")?,
                                         &args.required_secret("--new")?)?,
        "set-management-key" => {
            let new = unhex(&args.required_secret("--new")?)?;
            let key_type = match args.value("--type") {
                Some(name) => piv::ManagementKeyType::from_name(name)?,
                None => piv.management_key_type()?,
            };
            management_key(args, &mut piv)?;
            piv.set_management_key(key_type, &new, args.flag("--touch"))?;
        }
        "reset" => piv.reset()?,
        other => return Err(format!("piv has no command {other}.")),
    }
    Ok(())
}

/// An attestation is a certificate for the slot's key signed by the key
/// in F9. Check both halves: the signature, with the library's chain
/// verifier treating F9's certificate as the anchor, and that the key it
/// certifies is the key the card says is in the slot.
pub fn check_attestation(attestation: &[u8], signer: &[u8], key: &piv::PublicKey)
                         -> Result<(), String> {
    // An attestation proves where a key was made, not that anything is
    // current: YubiKey's attestation certificates are not renewed, and
    // their purpose is none of TLS's.
    let options = api::VerifyOptions { allow_expired: true, purpose: "any".to_string(),
                                       now: now() as i64, ..api::VerifyOptions::default() };
    api::verify_chain(&[attestation], &[signer], &options)
        .map_err(|e| format!("The attestation does not verify against F9: {e}"))?;
    let certified = api::Certificate::parse(attestation)?.info()?;
    let matches = match key {
        piv::PublicKey::Rsa { n, .. } => certified.public_key_bits == n.len() * 8,
        _ => true,
    };
    if !matches {
        return Err("The attestation certifies a different key from the slot's.".to_string());
    }
    eprintln!("The attestation verifies against the card's F9 certificate, {}.",
              api::Certificate::parse(signer)?.subject_string()?);
    Ok(())
}

/// Bytes to `--out`, or as hex on standard output.
fn write_or_hex(args: &Args, bytes: &[u8], out: &mut String) -> Result<(), String> {
    match args.value("--out") {
        Some(path) => std::fs::write(path, bytes).map_err(|e| format!("{path}: {e}")),
        None => {
            say!(out, "{}", hex(bytes));
            Ok(())
        }
    }
}

fn write_or_print(args: &Args, text: &str, out: &mut String) -> Result<(), String> {
    match args.value("--out") {
        Some(path) => std::fs::write(path, text).map_err(|e| format!("{path}: {e}")),
        None => {
            out.push_str(text);
            Ok(())
        }
    }
}

// ------------------------------------------------------------- OpenPGP --

/// A signature by the card's signature key over `signed`, as an OpenPGP
/// signature packet, with the user PIN verified first.
fn openpgp_signature(pgp: &mut openpgp::OpenPgp, kind: u8, signed: &[u8], extra_hashed: &[u8],
                     created: u32) -> Result<Vec<u8>, String> {
    let status = pgp.status()?;
    let algorithm = status.algorithms[0].ok_or("The card's signature key is not set up.")?;
    let issuer = status.fingerprints[0].clone();
    if issuer.iter().all(|&b| b == 0) || issuer.len() != 20 {
        return Err("The card's signature key has no fingerprint: generate or import it with \
                    this example, or set it with GnuPG.".to_string());
    }
    let mut sign = |input: &[u8]| pgp.sign(input);
    openpgp::signature::build(kind, algorithm, &issuer, created, extra_hashed, signed, &mut sign)
}

fn openpgp_command(card: &mut Card, args: &Args, out: &mut String) -> Result<(), String> {
    let words = args.positional();
    let command = *words.get(1).ok_or("openpgp needs a command.")?;
    let time = args.number("--time")?.unwrap_or_else(now) as u32;
    let mut pgp = openpgp::OpenPgp::select(card)?;
    match command {
        "status" => {
            let status = pgp.status()?;
            say!(out, "OpenPGP card version {}, serial {}", status.version(), status.serial());
            say!(out, "PIN tries left: user {}, reset code {}, admin {}",
                     status.tries[0], status.tries[1], status.tries[2]);
            if let Some(count) = status.signatures {
                say!(out, "signatures made: {count}");
            }
            for (i, name) in ["signature", "decryption", "authentication"].iter().enumerate() {
                let print = &status.fingerprints[i];
                let set = !print.is_empty() && print.iter().any(|&b| b != 0);
                say!(out, "{name}: {}, {}", status.algorithms[i].map(|a| a.describe())
                             .unwrap_or_else(|| "?".to_string()),
                         if set { format!("fingerprint {}, created {}", hex(print).to_uppercase(),
                                          status.times[i]) }
                         else { "no key".to_string() });
            }
        }
        "generate" => {
            let slot = openpgp::Slot::from_name(words.get(2).ok_or("A key slot is needed.")?)?;
            let algorithm = openpgp::Algorithm::from_name(words.get(3)
                .ok_or("An algorithm is needed.")?)?;
            pgp.verify(0x83, &args.required_secret("--admin-pin")?)?;
            let key = pgp.generate(slot, algorithm, time)?;
            let body = openpgp::key_packet_body(algorithm, slot, &key, time)?;
            say!(out, "fingerprint {}", hex(&openpgp::fingerprint(&body)?).to_uppercase());
        }
        "import" => {
            let slot = openpgp::Slot::from_name(words.get(2).ok_or("A key slot is needed.")?)?;
            let parts = api::parse_private_key(&read_file(words.get(3)
                .ok_or("A key file is needed.")?)?)?;
            pgp.verify(0x83, &args.required_secret("--admin-pin")?)?;
            let (algorithm, key) = pgp.import(slot, &parts, time)?;
            let body = openpgp::key_packet_body(algorithm, slot, &key, time)?;
            say!(out, "fingerprint {}", hex(&openpgp::fingerprint(&body)?).to_uppercase());
        }
        "export" => {
            let user_id = args.value("--user-id").ok_or("--user-id is required.")?;
            let pin = args.required_secret("--pin")?;
            let exported = export_openpgp(&mut pgp, user_id, &pin, time)?;
            write_or_print(args, &armor("PUBLIC KEY BLOCK", &exported), out)?;
        }
        "sign" => {
            let data = read_file(words.get(2).ok_or("A file to sign is needed.")?)?;
            pgp.verify(0x81, &args.required_secret("--pin")?)?;
            let signature = openpgp_signature(&mut pgp, 0x00, &data, &[], time)?;
            write_or_print(args, &armor("SIGNATURE", &signature), out)?;
        }
        "change-pin" => pgp.change_pin(false, &args.required_secret("--pin")?,
                                       &args.required_secret("--new")?)?,
        "change-admin-pin" => pgp.change_pin(true, &args.required_secret("--admin-pin")?,
                                             &args.required_secret("--new")?)?,
        "reset-pin" => {
            pgp.verify(0x83, &args.required_secret("--admin-pin")?)?;
            pgp.reset_pin(&args.required_secret("--new")?)?;
        }
        "reset" => pgp.reset()?,
        other => return Err(format!("openpgp has no command {other}.")),
    }
    Ok(())
}

/// The card's keys as an OpenPGP certificate GnuPG can import: the
/// signature key as the primary key with the user ID, certified by the
/// card, and the decryption and authentication keys as subkeys bound by
/// the card's signatures. Each key's packet uses the creation time the
/// card stores, so the fingerprints match what the card says.
pub fn export_openpgp(pgp: &mut openpgp::OpenPgp, user_id: &str, pin: &str, created: u32)
                      -> Result<Vec<u8>, String> {
    use openpgp::signature::{key_prefix, user_id_prefix};
    let status = pgp.status()?;
    let slots = [openpgp::Slot::Signature, openpgp::Slot::Decryption,
                 openpgp::Slot::Authentication];
    let mut bodies = Vec::new();
    for (i, slot) in slots.into_iter().enumerate() {
        let print = &status.fingerprints[i];
        if print.len() != 20 || print.iter().all(|&b| b == 0) {
            bodies.push(None);
            continue;
        }
        let algorithm = status.algorithms[i].ok_or("A key's algorithm is unknown.")?;
        let key = pgp.public_key(slot)?;
        let body = openpgp::key_packet_body(algorithm, slot, &key, status.times[i])?;
        if openpgp::fingerprint(&body)? != *print {
            return Err(format!("The card's {slot:?} key does not match the fingerprint it \
                                stores; it was not set up by this example or by GnuPG."));
        }
        bodies.push(Some(body));
    }
    let primary = bodies[0].clone().ok_or("The card has no signature key.")?;
    pgp.verify(0x81, pin)?;

    let mut out = openpgp::packet(6, &primary);
    out.extend_from_slice(&openpgp::packet(13, user_id.as_bytes()));
    // Key flags: certify and sign.
    let certification = openpgp_signature(
        pgp, 0x13, &[key_prefix(&primary), user_id_prefix(user_id)].concat(), &[2, 27, 0x03],
        created)?;
    out.extend_from_slice(&certification);
    for (i, flags) in [(1usize, 0x0Cu8), (2, 0x20)] {
        let Some(body) = &bodies[i] else { continue };
        // PIN mode 81 lasts for one signature on many cards.
        pgp.verify(0x81, pin)?;
        out.extend_from_slice(&openpgp::packet(14, body));
        let binding = openpgp_signature(pgp, 0x18, &[key_prefix(&primary), key_prefix(body)]
                                        .concat(), &[2, 27, flags], created)?;
        out.extend_from_slice(&binding);
    }
    Ok(out)
}

// ---------------------------------------------------------------- OATH --

fn oath_command(card: &mut Card, args: &Args, out: &mut String) -> Result<(), String> {
    let words = args.positional();
    let command = *words.get(1).ok_or("oath needs a command.")?;
    let mut oath = oath::Oath::select(card)?;
    if oath.locked() && command != "reset" {
        let password = args.secret("--password")?
            .ok_or("The OATH application has a password: --password.")?;
        let key = oath::derive_key(&password, &oath.selected.salt)?;
        oath.validate(&key)?;
    }
    match command {
        "list" => {
            for credential in oath.list()? {
                say!(out, "{}  {} {}", credential.name, if credential.kind.totp { "TOTP" }
                         else { "HOTP" }, credential.kind.hash);
            }
        }
        "add" => {
            let account = words.get(2).ok_or("A name is needed.")?;
            let secret = oath::base32_decode(words.get(3).ok_or("A base32 secret is needed.")?)?;
            let totp = !args.flag("--hotp");
            let hash = match args.value("--hash").unwrap_or("sha1") {
                "sha1" => "sha1",
                "sha256" => "sha256",
                "sha512" => "sha512",
                other => return Err(format!("OATH's hashes are sha1, sha256 and sha512, \
                                             not {other}.")),
            };
            let period = args.number("--period")?.unwrap_or(30);
            let name = oath::credential_name(args.value("--issuer"), account, totp, period);
            let digits = args.number("--digits")?.unwrap_or(6) as u8;
            let touch = args.flag("--touch");
            oath.put(&name, oath::Kind { totp, hash }, &secret, digits, touch,
                     args.number("--counter")?.unwrap_or(0) as u32)?;
            // A TOTP code costs the card nothing, so the stored secret is
            // checked by asking for one and computing the same here. An
            // HOTP code would advance the counter, and a touch credential
            // would wait for a finger.
            if totp && !touch {
                let credential = oath.list()?.into_iter().find(|c| c.name == name)
                    .ok_or_else(|| format!("{name} is not in the card's list after storing it."))?;
                let time = args.number("--time")?.unwrap_or_else(now);
                let ours = oath::compute_code(&secret, hash, time / credential.period(),
                                              usize::from(digits))?;
                let theirs = oath.calculate(&credential, time)?;
                if ours != theirs {
                    return Err(format!("The card computes {theirs} for {name} where the secret \
                                        gives {ours}."));
                }
            }
            say!(out, "stored {name}");
        }
        "code" => {
            let time = args.number("--time")?.unwrap_or_else(now);
            match words.get(2) {
                Some(name) => {
                    let credential = oath.list()?.into_iter().find(|c| c.name == *name)
                        .ok_or_else(|| format!("No credential named {name}."))?;
                    say!(out, "{}", oath.calculate(&credential, time)?);
                }
                None => {
                    for (name, code) in oath.calculate_all(time)? {
                        say!(out, "{name}  {}", code.unwrap_or_else(|| "(on request)".to_string()));
                    }
                }
            }
        }
        "delete" => oath.delete(words.get(2).ok_or("A name is needed.")?)?,
        "set-password" => {
            let new = args.required_secret("--new")?;
            let key = oath::derive_key(&new, &oath.selected.salt)?;
            oath.set_key(Some(&key))?;
        }
        "remove-password" => oath.set_key(None)?,
        "reset" => oath.reset()?,
        other => return Err(format!("oath has no command {other}.")),
    }
    Ok(())
}

// ----------------------------------------------------------------- OTP --

fn otp_command(card: &mut Card, args: &Args, out: &mut String) -> Result<(), String> {
    let words = args.positional();
    let command = *words.get(1).ok_or("otp needs a command.")?;
    let slot = |i: usize| -> Result<u8, String> {
        words.get(i).ok_or("A slot, 1 or 2, is needed.")?.parse()
            .map_err(|_| "The slot is 1 or 2.".to_string())
    };
    let mut otp = otp::Otp::select(card)?;
    match command {
        "status" => {
            let v = otp.status.version;
            say!(out, "YubiKey OTP version {}.{}.{}, programming sequence {}", v[0], v[1], v[2],
                     otp.status.sequence);
            if let Ok(serial) = otp.serial() {
                say!(out, "serial {serial}");
            }
        }
        "challenge" => {
            let challenge = unhex(words.get(3).ok_or("A challenge in hex is needed.")?)?;
            say!(out, "{}", hex(&otp.challenge_response(slot(2)?, &challenge)?));
        }
        "program" => {
            let key = unhex(words.get(3).ok_or("A key in hex is needed.")?)?;
            otp.program_hmac(slot(2)?, &key, args.flag("--touch"))?;
            say!(out, "slot {} programmed for HMAC-SHA1 challenge-response", slot(2)?);
        }
        other => return Err(format!("otp has no command {other}.")),
    }
    Ok(())
}

// ---------------------------------------------------------------- main --

/// Open the card the options name.
fn open_transport(args: &Args) -> Result<Box<dyn card::Transport>, String> {
    if let Some(address) = args.value("--card") {
        let address = address.strip_prefix("tcp:")
            .ok_or("--card takes tcp:HOST:PORT.")?;
        return Ok(Box::new(card::Tcp::connect(address)?));
    }
    let service = pcsc::Pcsc::establish()?;
    let readers = service.readers()?;
    if readers.is_empty() {
        return Err("No smart card reader is connected.".to_string());
    }
    let wanted = args.value("--reader");
    let mut last_error = None;
    for reader in readers.iter().filter(|r| wanted.is_none_or(|w| r.contains(w))) {
        match service.connect(reader) {
            Ok(connection) => return Ok(Box::new(connection)),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| format!("No reader's name contains {:?}; the readers \
                                             are: {}.", wanted.unwrap_or(""),
                                            readers.join(", "))))
}

/// Which applications answer, and their versions.
fn info(card: &mut Card, out: &mut String) -> Result<(), String> {
    // Each application is reported on its own line, and one that is
    // missing or refuses says why rather than being left out.
    let piv = piv::Piv::select(card).map(|mut piv| match piv.version() {
        Ok(v) => format!("PIV {}.{}.{}", v[0], v[1], v[2]),
        Err(_) => "PIV".to_string(),
    });
    say!(out, "{}", piv.unwrap_or_else(|e| e));
    let pgp = openpgp::OpenPgp::select(card).and_then(|mut pgp| pgp.status())
        .map(|status| format!("OpenPGP {} serial {}", status.version(), status.serial()));
    say!(out, "{}", pgp.unwrap_or_else(|e| e));
    let oath = oath::Oath::select(card).map(|oath| {
        let v = &oath.selected.version;
        format!("OATH {}{}", v.iter().map(u8::to_string).collect::<Vec<_>>().join("."),
                if oath.locked() { " (password set)" } else { "" })
    });
    say!(out, "{}", oath.unwrap_or_else(|e| e));
    let otp = otp::Otp::select(card).map(|otp| {
        let v = otp.status.version;
        format!("YubiKey OTP {}.{}.{}", v[0], v[1], v[2])
    });
    say!(out, "{}", otp.unwrap_or_else(|e| e));
    Ok(())
}

/// Run one command line against `card` - or, when `card` is `None`, the
/// card the options name - returning what it prints.
pub fn run(words: Vec<String>, card: Option<Card>) -> Result<String, String> {
    let args = Args::new(words)?;
    let mut out = String::new();
    let positional = args.positional();
    let command = *positional.first().ok_or("A command is needed; see the top of \
                                             examples/products/smartcard/main.rs.")?;
    if command == "readers" {
        for reader in pcsc::Pcsc::establish()?.readers()? {
            say!(out, "{reader}");
        }
        return Ok(out);
    }
    // `--record FILE` keeps every exchange, and `--random-seed N` makes
    // the host's challenges reproducible: together they are how the
    // offline tests' conversations were captured.
    let recording = std::rc::Rc::new(RefCell::new(Vec::new()));
    let mut card = match card {
        Some(card) => card,
        None => {
            let mut transport = open_transport(&args)?;
            if args.value("--record").is_some() {
                transport = Box::new(card::Recorder { inner: transport,
                                                      exchanges: recording.clone() });
            }
            Card::new(transport)
        }
    };
    if let Some(seed) = args.number("--random-seed")? {
        card.random = card::seeded_random(seed);
    }
    let result = dispatch(command, &mut card, &args, &mut out);
    if let Some(path) = args.value("--record") {
        std::fs::write(path, card::encode_recording(&recording.borrow()) + "\n")
            .map_err(|e| format!("{path}: {e}"))?;
    }
    result?;
    Ok(out)
}

fn dispatch(command: &str, card: &mut Card, args: &Args, out: &mut String)
            -> Result<(), String> {
    match command {
        "info" => info(card, out),
        "piv" => piv_command(card, args, out),
        "openpgp" => openpgp_command(card, args, out),
        "oath" => oath_command(card, args, out),
        "otp" => otp_command(card, args, out),
        other => Err(format!("{other} is not a command: readers, info, piv, openpgp, oath, \
                              otp.")),
    }
}

fn main() {
    match run(std::env::args().skip(1).collect(), None) {
        Ok(output) => print!("{output}"),
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}
