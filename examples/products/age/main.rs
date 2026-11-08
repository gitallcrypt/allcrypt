//! age, the file encryption format (C2SP age.md, age-encryption.org/v1),
//! built from this library's primitives.
//!
//!     cargo run --release --example age -- keygen [--pq] [--seed N]
//!     cargo run --release --example age -- encrypt IN OUT (-r RECIPIENT | -R FILE)... [--armor]
//!     cargo run --release --example age -- encrypt IN OUT --passphrase PW [--work-factor N] [--armor]
//!     cargo run --release --example age -- decrypt IN OUT (-i IDENTITY | --identity-file FILE)...
//!             [--key-passphrase PW]
//!     cargo run --release --example age -- decrypt IN OUT --passphrase PW
//!     cargo run --release --example age -- encrypt IN OUT -j PLUGIN | -r age1NAME1...
//!             [--plugin-recipients]
//!     cargo run --release --example age -- decrypt IN OUT -i AGE-PLUGIN-NAME-1... | -j PLUGIN
//!
//! `--passphrase-stdin` in place of `--passphrase PW` reads it from
//! standard input instead of the command line.
//!
//! Plugins: a recipient `age1NAME1...` of a type the example does not
//! know, an identity `AGE-PLUGIN-NAME-1...`, and `-j NAME` (a plugin
//! identity with no data, also as a recipient) go to the program
//! `age-plugin-NAME` on the `PATH`, over age's plugin protocol (C2SP
//! age-plugin.md): `recipient-v1` to wrap a file key, `identity-v1` to
//! unwrap one. `--plugin-recipients` sends every `age1NAME1...`
//! recipient to its plugin, even one of a type the example knows.
//!
//! Seven recipient types: X25519 (`age1...`), the post-quantum hybrid
//! MLKEM768-X25519 (`age1pq1...`, X-Wing through HPKE), a passphrase
//! through scrypt, SSH keys - `ssh-ed25519` and `ssh-rsa` public key
//! lines as recipients, OpenSSH private key files as identities
//! (`--key-passphrase` opens an encrypted one) - and the tagged types
//! `p256tag` (`age1tag1...`) and `mlkem768p256tag` (`age1tagpq1...`),
//! the public side of keys held in hardware: HPKE to P-256 or to
//! MLKEM768-P256, with a four byte tag that lets the hardware skip
//! stanzas that are not its own. Files are encrypted to the tagged
//! types; their identities live behind age's plugins, so here only the
//! tests make one, from a seed as age's own tests do. The SSH types are age's
//! `agessh` package, which no specification covers: `ssh-rsa` is RSA-OAEP
//! with SHA-256 and the label `age-encryption.org/v1/ssh-rsa`;
//! `ssh-ed25519` is X25519 to the key's Montgomery form, the shared
//! secret multiplied again by a tweak HKDF derives from the SSH key, then
//! wrapped like X25519. Both carry a tag, the first four bytes of the SHA-256
//! of the SSH key's wire form, so they are not anonymous. An age file is a textual header that
//! wraps a 16 byte file key once per recipient and ends with an
//! HMAC-SHA-256 under a key derived from the file key, then the payload:
//! a nonce and 64 KiB chunks of ChaCha20-Poly1305 whose nonces count the
//! chunks and mark the last.
//!
//! What has checked it is in `examples/products/README.md`.

use std::io::{BufRead, Write};

use allcrypt::api::AnyHash;
use allcrypt::ec::x25519;
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::hash_functions::HashFunction;
use allcrypt::kdf::{hkdf, hkdf_extract};
use allcrypt::mac::hmac::Hmac;
use allcrypt::publickey_ciphers::hpke::{Aead, Kdf, Kem, Options, Suite};
use allcrypt::publickey_ciphers::rsa::{self, RsaPrivateKey, RsaPublicKey};
use allcrypt::ssh;
use allcrypt::stream_ciphers::chacha20poly1305;

#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/inflate.rs"]
#[cfg(test)]
mod inflate;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

const VERSION_LINE: &str = "age-encryption.org/v1";
const CHUNK: usize = 64 * 1024;
const ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_END: &str = "-----END AGE ENCRYPTED FILE-----";
/// The largest scrypt work factor accepted: 2^22 is a gigabyte of
/// memory, age's own ceiling.
const MAX_WORK_FACTOR: u32 = 22;

type Random<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

/// How decryption failed, in the age test suite's categories.
#[derive(Debug, PartialEq)]
enum Failure {
    Armor(String),
    Header(String),
    NoMatch,
    Hmac,
    Payload(String),
    /// A plugin failed, or reported an error: not the file's fault.
    Plugin(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Armor(why) => write!(f, "the ASCII armor is not valid: {why}"),
            Failure::Header(why) => write!(f, "the header is not valid: {why}"),
            Failure::NoMatch => write!(f, "no identity matches any of the recipients"),
            Failure::Hmac => write!(f, "the header's MAC does not match"),
            Failure::Payload(why) => write!(f, "the payload does not decrypt: {why}"),
            Failure::Plugin(why) => write!(f, "{why}"),
        }
    }
}

fn header_error<T>(why: &str) -> Result<T, Failure> {
    Err(Failure::Header(why.to_string()))
}

// ------------------------------------------------------- encodings ---

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 without padding, as the header writes it.
fn b64_encode(data: &[u8]) -> String {
    allcrypt::pem::encode(data).trim_end_matches('=').to_string()
}

/// Base64 without padding, refusing anything that would not encode back
/// to the same text: padding, a stray character, or unused bits set in
/// the last character.
fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 6 || acc != 0 {
        return None;
    }
    Some(out)
}

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|b| b & 31));
    out
}

fn regroup(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    let max = (1 << to) - 1;
    for &v in data {
        acc = (acc << from) | u32::from(v);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || (acc << (to - bits)) & max != 0 {
        return None;
    }
    Some(out)
}

/// BIP 173 Bech32, without its 90 character limit: an `age1pq`
/// recipient is nearly two thousand.
fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let values = regroup(data, 8, 5, true).unwrap_or_default();
    let mut check_input = hrp_expand(hrp);
    check_input.extend(&values);
    check_input.extend([0u8; 6]);
    let polymod = bech32_polymod(&check_input) ^ 1;
    let mut out = format!("{hrp}1");
    for v in values.iter().copied().chain((0..6).map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8)) {
        out.push(BECH32[v as usize] as char);
    }
    out
}

/// Bech32 back to its human readable part (lower case) and data. One
/// case throughout, as BIP 173 requires.
fn bech32_decode(text: &str) -> Result<(String, Vec<u8>), String> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) && text.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err("Bech32 in mixed case.".to_string());
    }
    let lower = text.to_ascii_lowercase();
    let split = lower.rfind('1').ok_or("Bech32 without a separator.")?;
    let (hrp, rest) = (&lower[..split], &lower[split + 1..]);
    if hrp.is_empty() || rest.len() < 6 {
        return Err("Bech32 too short.".to_string());
    }
    let values: Vec<u8> = rest.bytes().map(|b| BECH32.iter().position(|&c| c == b).map(|v| v as u8))
        .collect::<Option<_>>().ok_or("Bech32 with a character outside its alphabet.")?;
    let mut check_input = hrp_expand(hrp);
    check_input.extend(&values);
    if bech32_polymod(&check_input) != 1 {
        return Err("Bech32 checksum does not match.".to_string());
    }
    let data = regroup(&values[..values.len() - 6], 5, 8, false)
        .ok_or("Bech32 with leftover bits.")?;
    Ok((hrp.to_string(), data))
}

// ------------------------------------------------------- primitives ---

fn sha256_hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    hkdf(SHA256::new(&[]), salt, ikm, info, length).unwrap_or_default()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    Hmac::mac(SHA256::new(&[]), key, data)
}

fn aead_seal(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let (mut ciphertext, tag) = chacha20poly1305::seal(key, nonce, &[], plaintext)
        .expect("a 32 byte key and a 12 byte nonce");
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

fn aead_open(key: &[u8], nonce: &[u8; 12], sealed: &[u8]) -> Option<Vec<u8>> {
    let (ciphertext, tag) = sealed.split_at(sealed.len().checked_sub(16)?);
    chacha20poly1305::open(key, nonce, &[], ciphertext, tag).ok()
}

fn x25519_checked(scalar: &[u8; 32], point: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = x25519::exchange(scalar, point).ok()?;
    if shared == [0u8; 32] { None } else { Some(shared) }
}

// ------------------------------------------------------------- HPKE ---

/// The HPKE suites age wraps file keys with: a KEM, HKDF-SHA256 and
/// ChaCha20Poly1305, the AEAD's associated data empty and the label as
/// HPKE's `info`. The library's `publickey_ciphers::hpke` does the rest.
fn hpke_suite(kem: Kem) -> Suite {
    Suite::new(kem, Kdf::HkdfSha256, Aead::ChaCha20Poly1305)
}

/// A file key sealed to an HPKE recipient: `(enc, body)`.
fn hpke_wrap(kem: Kem, public: &[u8], info: &[u8], file_key: &[u8], random: Random<'_>)
             -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut randomness = vec![0u8; kem.encap_randomness_len()];
    random(&mut randomness)?;
    let (enc, mut context) = hpke_suite(kem).setup_sender_with(public, info, &Options::default(),
                                                              &randomness)?;
    Ok((enc, context.seal(b"", file_key)?))
}

/// The file key, `Ok(None)` if the body does not open, `Err` if `enc`
/// does not decapsulate.
fn hpke_unwrap(kem: Kem, private: &[u8], info: &[u8], enc: &[u8], body: &[u8])
               -> Result<Option<Vec<u8>>, Failure> {
    let mut context = hpke_suite(kem).setup_receiver(enc, private, info, &Options::default())
        .map_err(|_| Failure::Header("the encapsulated key does not decapsulate".into()))?;
    Ok(context.open(b"", body).ok())
}

const P256TAG_LABEL: &[u8] = b"age-encryption.org/p256tag";
const MLKEM768P256TAG_LABEL: &[u8] = b"age-encryption.org/mlkem768p256tag";

/// A tagged stanza's tag: HKDF-Extract with the label as the salt, over
/// `enc` and the first four bytes of the SHA-256 of the recipient's
/// P-256 key - compressed for `p256tag`, uncompressed (as the hybrid
/// public key carries it) for `mlkem768p256tag` - cut to four bytes.
fn tag_of(label: &[u8], enc: &[u8], p256_key: &[u8]) -> Vec<u8> {
    let mut ikm = enc.to_vec();
    ikm.extend_from_slice(&SHA256::new(p256_key).digest()[..4]);
    hkdf_extract(SHA256::new(&[]), label, &ikm)[..4].to_vec()
}

/// What a tagged type is, for one recipient: its KEM, stanza type and
/// label, and the P-256 key its tag covers.
struct TagType {
    kem: Kem,
    kind: &'static str,
    label: &'static [u8],
    p256_key: Vec<u8>,
}

/// The tagged type of an HPKE public key.
fn tag_parts(pq: bool, public: &[u8]) -> Result<TagType, String> {
    if pq {
        return Ok(TagType { kem: Kem::MlKem768P256, kind: "mlkem768p256tag",
                            label: MLKEM768P256TAG_LABEL,
                            p256_key: public.get(1184..).ok_or("a short mlkem768p256tag key")?
                                .to_vec() });
    }
    let curve = allcrypt::ec::curves::p256();
    let point = curve.decode_point(public)?;
    Ok(TagType { kem: Kem::P256, kind: "p256tag", label: P256TAG_LABEL,
                 p256_key: curve.encode_point(&point, true)? })
}

const HYBRID_INFO: &[u8] = b"age-encryption.org/mlkem768x25519";
/// MLKEM768-X25519's encapsulation, in bytes.
const HYBRID_ENC_LEN: usize = 1120;

// ---------------------------------------------------- identities ---

enum Identity {
    X25519([u8; 32]),
    /// MLKEM768-X25519's 32 byte seed.
    Hybrid([u8; 32]),
    Passphrase(Vec<u8>),
    /// The SSH key's wire form, its X25519 scalar, and that scalar's
    /// public key.
    SshEd25519 { blob: Vec<u8>, secret: [u8; 32], public: [u8; 32] },
    SshRsa { blob: Vec<u8>, key: Box<RsaPrivateKey> },
    /// The private side of a `p256tag` or `mlkem768p256tag` recipient:
    /// its HPKE private key and public key. age has no encoding for
    /// these - the keys live in hardware, behind a plugin - so only
    /// the tests make one, from a seed, as age's own tests do
    /// (`Identity::tag_from_seed`).
    Tag { pq: bool, private: Vec<u8>, public: Vec<u8> },
    /// `AGE-PLUGIN-NAME-1...`: an identity `age-plugin-NAME` holds, the
    /// whole string handed to it.
    Plugin { name: String, encoding: String },
}

impl Identity {
    /// age's test identities for the tagged types (its
    /// `tag/internal/tagtest`): HPKE's `DeriveKeyPair` of the seed's
    /// bytes, over P-256 or MLKEM768-P256.
    #[cfg_attr(not(test), allow(dead_code))]
    fn tag_from_seed(seed: &[u8], pq: bool) -> Result<Identity, String> {
        let kem = if pq { Kem::MlKem768P256 } else { Kem::P256 };
        let (private, public) = kem.derive_key_pair(seed)?;
        Ok(Identity::Tag { pq, private, public })
    }

    /// The recipient a tag identity answers to.
    #[cfg_attr(not(test), allow(dead_code))]
    fn tag_recipient(&self) -> Option<Recipient> {
        match self {
            Identity::Tag { pq: true, public, .. } => Some(Recipient::TagPq(public.clone())),
            Identity::Tag { pq: false, public, .. } => {
                let curve = allcrypt::ec::curves::p256();
                Some(Recipient::Tag(curve.encode_point(&curve.decode_point(public).ok()?, true)
                    .ok()?))
            }
            _ => None,
        }
    }
}

enum Recipient {
    X25519([u8; 32]),
    Hybrid(Vec<u8>),
    Passphrase { passphrase: Vec<u8>, work_factor: u32 },
    /// The SSH key's wire form and its Montgomery form.
    SshEd25519 { blob: Vec<u8>, public: [u8; 32] },
    SshRsa { blob: Vec<u8>, key: RsaPublicKey },
    /// `age1tag1...`: a compressed P-256 point, the public side of a key
    /// held in hardware.
    Tag(Vec<u8>),
    /// `age1tagpq1...`: an MLKEM768-P256 public key, ML-KEM-768's 1184
    /// bytes and an uncompressed P-256 point.
    TagPq(Vec<u8>),
    /// `age1NAME1...`, wrapped by `age-plugin-NAME`; or with `identity`,
    /// a plugin identity whose recipient the plugin works out itself
    /// (`-j NAME`).
    Plugin { name: String, encoding: String, identity: bool },
}

const SSH_ED25519_LABEL: &[u8] = b"age-encryption.org/v1/ssh-ed25519";
const SSH_RSA_LABEL: &[u8] = b"age-encryption.org/v1/ssh-rsa";

/// An SSH stanza's tag: the first four bytes of the SHA-256 of the key's
/// wire form, unpadded base64.
fn ssh_tag(blob: &[u8]) -> String {
    b64_encode(&SHA256::new(blob).digest()[..4])
}

/// The tweak `ssh-ed25519` multiplies the shared secret by: HKDF-SHA-256
/// with no input key, the SSH key's wire form as the salt.
fn ssh_ed25519_tweak(blob: &[u8]) -> [u8; 32] {
    sha256_hkdf(blob, b"", SSH_ED25519_LABEL, 32).try_into().expect("32 bytes")
}

fn ssh_recipient(key: &ssh::keys::PublicKey) -> Result<Recipient, String> {
    let blob = key.to_blob();
    match key {
        ssh::keys::PublicKey::Ed25519(public) => Ok(Recipient::SshEd25519 {
            public: allcrypt::ec::eddsa::ed25519_public_to_x25519(public)?, blob }),
        ssh::keys::PublicKey::Rsa(public) => Ok(Recipient::SshRsa { key: public.clone(), blob }),
        other => Err(format!("{} keys are not age recipients; only ssh-ed25519 and ssh-rsa \
                              are.", other.algorithm())),
    }
}

/// An OpenSSH private key file as an identity.
fn ssh_identity(text: &str, passphrase: Option<&[u8]>) -> Result<Identity, String> {
    let (key, _) = ssh::private_key::read(text, passphrase)?;
    let blob = key.public().to_blob();
    match key {
        ssh::private_key::PrivateKey::Ed25519 { seed, .. } => {
            let secret = allcrypt::ec::eddsa::ed25519_private_to_x25519(&seed)?;
            Ok(Identity::SshEd25519 { public: x25519::public_key(&secret)?, secret, blob })
        }
        ssh::private_key::PrivateKey::Rsa(key) => Ok(Identity::SshRsa { key, blob }),
        other => Err(format!("{} keys are not age identities; only ssh-ed25519 and ssh-rsa \
                              are.", other.public().algorithm())),
    }
}

/// A plugin's name, as age allows it: alphanumerics and `+-._`.
fn plugin_name(name: &str) -> Option<&str> {
    (!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-._".contains(&b)))
        .then_some(name)
}

/// `-j NAME`: a plugin identity with no data, `AGE-PLUGIN-NAME-1` and a
/// checksum.
fn plugin_identity_without_data(name: &str) -> Result<String, String> {
    let name = plugin_name(&name.to_ascii_lowercase()).ok_or("not a plugin name")?.to_string();
    Ok(bech32_encode(&format!("age-plugin-{name}-"), &[]).to_ascii_uppercase())
}

fn parse_identity(text: &str) -> Result<Identity, String> {
    let (hrp, data) = bech32_decode(text.trim())?;
    if let Some(name) = hrp.strip_prefix("age-plugin-").and_then(|r| r.strip_suffix('-'))
        .and_then(plugin_name) {
        return Ok(Identity::Plugin { name: name.to_string(), encoding: text.trim().to_string() });
    }
    match hrp.as_str() {
        "age-secret-key-" => Ok(Identity::X25519(data.try_into()
            .map_err(|_| "an X25519 identity is 32 bytes")?)),
        "age-secret-key-pq-" => Ok(Identity::Hybrid(
            data.try_into().map_err(|_| "a hybrid identity is 32 bytes")?)),
        other => Err(format!("{other:?} is not an age identity.")),
    }
}

#[cfg(test)]
fn parse_recipient(text: &str) -> Result<Recipient, String> {
    parse_recipient_with(text, false)
}

/// `via_plugin`: an `age1NAME1...` recipient goes to `age-plugin-NAME`
/// even when it is a type this example knows - which is how the plugin
/// protocol is checked against plugins for types age knows too.
fn parse_recipient_with(text: &str, via_plugin: bool) -> Result<Recipient, String> {
    if text.trim_start().starts_with("ssh-") || text.trim_start().starts_with("ecdsa-") {
        return ssh_recipient(&ssh::keys::parse_line(text.trim())?.key);
    }
    let (hrp, data) = bech32_decode(text.trim())?;
    let plugin = || hrp.strip_prefix("age1").and_then(plugin_name).map(|name| Recipient::Plugin {
        name: name.to_string(), encoding: text.trim().to_string(), identity: false });
    if via_plugin {
        if let Some(recipient) = plugin() {
            return Ok(recipient);
        }
    }
    match hrp.as_str() {
        "age" => Ok(Recipient::X25519(data.try_into()
            .map_err(|_| "an X25519 recipient is 32 bytes")?)),
        "age1pq" if data.len() == Kem::MlKem768X25519.public_len() => Ok(Recipient::Hybrid(data)),
        "age1tag" => {
            let curve = allcrypt::ec::curves::p256();
            if data.len() != 33 {
                return Err("a p256tag recipient is a 33 byte compressed P-256 point".to_string());
            }
            curve.decode_point(&data)?;
            Ok(Recipient::Tag(data))
        }
        "age1tagpq" if data.len() == Kem::MlKem768P256.public_len() => {
            let curve = allcrypt::ec::curves::p256();
            curve.decode_point(&data[1184..])?;
            Ok(Recipient::TagPq(data))
        }
        _ if plugin().is_some() && !matches!(hrp.as_str(), "age1pq" | "age1tag" | "age1tagpq") =>
            plugin().ok_or_else(|| "plugin".to_string()),
        other => Err(format!("{other:?} is not an age recipient.")),
    }
}

// ----------------------------------------------------------- header ---

#[derive(Debug)]
struct Stanza {
    args: Vec<String>,
    body: Vec<u8>,
}

struct Header {
    stanzas: Vec<Stanza>,
    mac: Vec<u8>,
    /// Everything the MAC covers: up to and including `---`.
    covered_len: usize,
    /// Where the payload starts.
    len: usize,
}

fn line(data: &[u8], at: usize) -> Result<&str, Failure> {
    let end = data[at..].iter().position(|&b| b == b'\n')
        .ok_or(Failure::Header("a line without its line feed".into()))?;
    std::str::from_utf8(&data[at..at + end]).map_err(|_| Failure::Header("not ASCII".into()))
}

fn parse_header(data: &[u8]) -> Result<Header, Failure> {
    let mut at = 0;
    let version = line(data, at)?;
    if version != VERSION_LINE {
        return header_error("not an age v1 file");
    }
    at += version.len() + 1;
    let mut stanzas = Vec::new();
    loop {
        let text = line(data, at)?;
        if let Some(rest) = text.strip_prefix("---") {
            let covered_len = at + 3;
            let encoded = rest.strip_prefix(' ').ok_or(Failure::Header("--- without its MAC".into()))?;
            let mac = b64_decode(encoded).filter(|m| m.len() == 32)
                .ok_or(Failure::Header("the MAC is not 32 bytes of canonical base64".into()))?;
            if stanzas.is_empty() {
                return header_error("no recipient stanzas");
            }
            return Ok(Header { stanzas, mac, covered_len, len: at + text.len() + 1 });
        }
        let args_text = text.strip_prefix("-> ").ok_or(Failure::Header("a line that is not a stanza".into()))?;
        let args: Vec<String> = args_text.split(' ').map(str::to_string).collect();
        if args.iter().any(|a| a.is_empty() || !a.bytes().all(|b| (0x21..=0x7e).contains(&b))) {
            return header_error("an empty or non-printable stanza argument");
        }
        at += text.len() + 1;
        let mut body_text = String::new();
        loop {
            let body_line = line(data, at)?;
            if body_line.len() > 64 {
                return header_error("a stanza body line longer than 64 columns");
            }
            body_text.push_str(body_line);
            at += body_line.len() + 1;
            if body_line.len() < 64 {
                break;
            }
        }
        let body = b64_decode(&body_text).ok_or(Failure::Header("a stanza body that is not canonical base64".into()))?;
        stanzas.push(Stanza { args, body });
    }
}

fn write_header(stanzas: &[Stanza], hmac_key: &[u8]) -> Vec<u8> {
    let mut out = format!("{VERSION_LINE}\n");
    for stanza in stanzas {
        out.push_str(&format!("-> {}\n", stanza.args.join(" ")));
        let body = b64_encode(&stanza.body);
        let mut rest = body.as_str();
        while rest.len() >= 64 {
            out.push_str(&rest[..64]);
            out.push('\n');
            rest = &rest[64..];
        }
        out.push_str(rest);
        out.push('\n');
    }
    out.push_str("---");
    let mac = hmac_sha256(hmac_key, out.as_bytes());
    out.push_str(&format!(" {}\n", b64_encode(&mac)));
    out.into_bytes()
}

// ---------------------------------------------------- wrapping keys ---

const ZERO_NONCE: [u8; 12] = [0; 12];

/// `Ok(Some(file key))`, `Ok(None)` for a stanza that is not this
/// identity's, `Err` for one that is malformed.
fn unwrap(identity: &Identity, stanza: &Stanza) -> Result<Option<Vec<u8>>, Failure> {
    let kind = stanza.args[0].as_str();
    match (identity, kind) {
        (Identity::X25519(secret), "X25519") => {
            if stanza.args.len() != 2 {
                return header_error("an X25519 stanza has one argument");
            }
            let share: [u8; 32] = b64_decode(&stanza.args[1]).and_then(|s| s.try_into().ok())
                .ok_or(Failure::Header("an X25519 share is 32 bytes".into()))?;
            if stanza.body.len() != 32 {
                return header_error("an X25519 stanza body is 32 bytes");
            }
            let Some(shared) = x25519_checked(secret, &share) else {
                return header_error("a low-order X25519 share");
            };
            let recipient = x25519::public_key(secret).map_err(Failure::Header)?;
            let mut salt = share.to_vec();
            salt.extend_from_slice(&recipient);
            let key = sha256_hkdf(&salt, &shared, b"age-encryption.org/v1/X25519", 32);
            Ok(aead_open(&key, &ZERO_NONCE, &stanza.body))
        }
        (Identity::Hybrid(secret), "mlkem768x25519") => {
            if stanza.args.len() != 2 {
                return header_error("an mlkem768x25519 stanza has one argument");
            }
            let enc = b64_decode(&stanza.args[1]).filter(|e| e.len() == HYBRID_ENC_LEN)
                .ok_or(Failure::Header("an mlkem768x25519 enc is 1120 bytes".into()))?;
            if stanza.body.len() != 32 {
                return header_error("an mlkem768x25519 stanza body is 32 bytes");
            }
            hpke_unwrap(Kem::MlKem768X25519, secret, HYBRID_INFO, &enc, &stanza.body)
        }
        // A tag that is not this key's is a stanza for somebody else, and
        // so is one whose body does not open: the tag is four bytes, and
        // another key's can collide with it, as age's own reader allows.
        (Identity::Tag { pq, private, public }, kind @ ("p256tag" | "mlkem768p256tag"))
                if kind == if *pq { "mlkem768p256tag" } else { "p256tag" } => {
            if stanza.args.len() != 3 {
                return header_error("a tagged stanza has two arguments");
            }
            let TagType { kem, label, p256_key, .. } = tag_parts(*pq, public)
                .map_err(Failure::Header)?;
            let tag = b64_decode(&stanza.args[1]).filter(|t| t.len() == 4)
                .ok_or(Failure::Header("a tag is 4 bytes".into()))?;
            let enc = b64_decode(&stanza.args[2]).filter(|e| e.len() == kem.enc_len())
                .ok_or(Failure::Header(format!("a {kind} enc is {} bytes", kem.enc_len())))?;
            if stanza.body.len() != 32 {
                return header_error("a tagged stanza body is 32 bytes");
            }
            if tag != tag_of(label, &enc, &p256_key) {
                return Ok(None);
            }
            hpke_unwrap(kem, private, label, &enc, &stanza.body)
        }
        // A tagged stanza that names this key and does not open is an
        // error, as age has it, not a stanza for somebody else.
        (Identity::SshEd25519 { blob, secret, public }, "ssh-ed25519") => {
            if stanza.args.len() != 3 {
                return header_error("an ssh-ed25519 stanza has two arguments");
            }
            let share: [u8; 32] = b64_decode(&stanza.args[2]).and_then(|s| s.try_into().ok())
                .ok_or(Failure::Header("an ssh-ed25519 share is 32 bytes".into()))?;
            if stanza.args[1] != ssh_tag(blob) {
                return Ok(None);
            }
            let Some(shared) = x25519_checked(secret, &share) else {
                return header_error("a low-order ssh-ed25519 share");
            };
            let shared = x25519::x25519(&ssh_ed25519_tweak(blob), &shared)
                .map_err(Failure::Header)?;
            let mut salt = share.to_vec();
            salt.extend_from_slice(public);
            let key = sha256_hkdf(&salt, &shared, SSH_ED25519_LABEL, 32);
            aead_open(&key, &ZERO_NONCE, &stanza.body).map(Some)
                .ok_or(Failure::Header("an ssh-ed25519 stanza for this key does not open".into()))
        }
        (Identity::SshRsa { blob, key }, "ssh-rsa") => {
            if stanza.args.len() != 2 {
                return header_error("an ssh-rsa stanza has one argument");
            }
            if stanza.args[1] != ssh_tag(blob) {
                return Ok(None);
            }
            rsa::decrypt_oaep(key, "sha256", "sha256", SSH_RSA_LABEL, &stanza.body).map(Some)
                .map_err(|_| Failure::Header("an ssh-rsa stanza for this key does not open".into()))
        }
        (Identity::Passphrase(passphrase), "scrypt") => {
            if stanza.args.len() != 3 {
                return header_error("an scrypt stanza has two arguments");
            }
            let salt = b64_decode(&stanza.args[1]).filter(|s| s.len() == 16)
                .ok_or(Failure::Header("an scrypt salt is 16 bytes".into()))?;
            let factor = &stanza.args[2];
            if !factor.starts_with(|c: char| ('1'..='9').contains(&c))
                || !factor.bytes().all(|b| b.is_ascii_digit()) {
                return header_error("an scrypt work factor is a decimal without leading zeros");
            }
            let factor: u32 = factor.parse().map_err(|_| Failure::Header("work factor".into()))?;
            if factor > MAX_WORK_FACTOR {
                return header_error("an scrypt work factor over the limit");
            }
            if stanza.body.len() != 32 {
                return header_error("an scrypt stanza body is 32 bytes");
            }
            let mut full_salt = b"age-encryption.org/v1/scrypt".to_vec();
            full_salt.extend_from_slice(&salt);
            let key = allcrypt::kdf::scrypt::scrypt(passphrase, &full_salt, 1 << factor, 8, 1, 32)
                .map_err(Failure::Header)?;
            Ok(aead_open(&key, &ZERO_NONCE, &stanza.body))
        }
        _ => Ok(None),
    }
}

fn wrap(recipient: &Recipient, file_key: &[u8], random: Random<'_>) -> Result<Stanza, String> {
    match recipient {
        Recipient::X25519(public) => {
            let mut ephemeral = [0u8; 32];
            random(&mut ephemeral)?;
            let share = x25519::public_key(&ephemeral)?;
            let shared = x25519_checked(&ephemeral, public).ok_or("a low-order recipient")?;
            let mut salt = share.to_vec();
            salt.extend_from_slice(public);
            let key = sha256_hkdf(&salt, &shared, b"age-encryption.org/v1/X25519", 32);
            Ok(Stanza { args: vec!["X25519".into(), b64_encode(&share)],
                        body: aead_seal(&key, &ZERO_NONCE, file_key) })
        }
        Recipient::Hybrid(public) => {
            let (enc, body) = hpke_wrap(Kem::MlKem768X25519, public, HYBRID_INFO, file_key,
                                        random)?;
            Ok(Stanza { args: vec!["mlkem768x25519".into(), b64_encode(&enc)], body })
        }
        Recipient::Tag(compressed) => {
            let curve = allcrypt::ec::curves::p256();
            let public = curve.encode_point(&curve.decode_point(compressed)?, false)?;
            tag_wrap(false, &public, file_key, random)
        }
        Recipient::TagPq(public) => tag_wrap(true, public, file_key, random),
        Recipient::Plugin { name, .. } => Err(format!("age-plugin-{name} wraps its own \
                                                      recipients")),
        Recipient::SshEd25519 { blob, public } => {
            let mut ephemeral = [0u8; 32];
            random(&mut ephemeral)?;
            let share = x25519::public_key(&ephemeral)?;
            let shared = x25519_checked(&ephemeral, public).ok_or("a low-order recipient")?;
            let shared = x25519::x25519(&ssh_ed25519_tweak(blob), &shared)?;
            let mut salt = share.to_vec();
            salt.extend_from_slice(public);
            let key = sha256_hkdf(&salt, &shared, SSH_ED25519_LABEL, 32);
            Ok(Stanza { args: vec!["ssh-ed25519".into(), ssh_tag(blob), b64_encode(&share)],
                        body: aead_seal(&key, &ZERO_NONCE, file_key) })
        }
        Recipient::SshRsa { blob, key } => {
            let mut seed = vec![0u8; 32];
            random(&mut seed)?;
            let body = rsa::encrypt_oaep_with_seed(key, "sha256", "sha256", SSH_RSA_LABEL,
                                                   file_key, &seed)?;
            Ok(Stanza { args: vec!["ssh-rsa".into(), ssh_tag(blob)], body })
        }
        Recipient::Passphrase { passphrase, work_factor } => {
            let mut salt = [0u8; 16];
            random(&mut salt)?;
            let mut full_salt = b"age-encryption.org/v1/scrypt".to_vec();
            full_salt.extend_from_slice(&salt);
            let key = allcrypt::kdf::scrypt::scrypt(passphrase, &full_salt, 1 << work_factor, 8, 1,
                                                    32)?;
            Ok(Stanza { args: vec!["scrypt".into(), b64_encode(&salt), work_factor.to_string()],
                        body: aead_seal(&key, &ZERO_NONCE, file_key) })
        }
    }
}

/// A `p256tag` or `mlkem768p256tag` stanza: `-> TYPE TAG ENC`, the file
/// key sealed by HPKE with the type's label as `info`.
fn tag_wrap(pq: bool, public: &[u8], file_key: &[u8], random: Random<'_>)
            -> Result<Stanza, String> {
    let TagType { kem, kind, label, p256_key } = tag_parts(pq, public)?;
    let (enc, body) = hpke_wrap(kem, public, label, file_key, random)?;
    Ok(Stanza { args: vec![kind.into(), b64_encode(&tag_of(label, &enc, &p256_key)),
                           b64_encode(&enc)], body })
}

// ---------------------------------------------------------- plugins ---

/// A conversation with a plugin: what it says, and where to answer. A
/// child process `age-plugin-NAME --age-plugin=PROTOCOL` in use; in the
/// tests, a recorded conversation played back.
struct PluginSession {
    from_plugin: Box<dyn BufRead>,
    to_plugin: Box<dyn Write>,
    child: Option<std::process::Child>,
}

impl PluginSession {
    fn spawn(name: &str, protocol: &str) -> Result<PluginSession, String> {
        use std::process::{Command, Stdio};
        let program = format!("age-plugin-{name}");
        let mut child = Command::new(&program).arg(format!("--age-plugin={protocol}"))
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        let to_plugin = Box::new(child.stdin.take().ok_or("stdin")?);
        let from_plugin = Box::new(std::io::BufReader::new(child.stdout.take().ok_or("stdout")?));
        Ok(PluginSession { from_plugin, to_plugin, child: Some(child) })
    }

    /// `-> TYPE ARGS...`, then the body in base64 lines of 64 columns,
    /// the last shorter - an empty line when the body is empty.
    fn send(&mut self, args: &[&str], body: &[u8]) -> Result<(), String> {
        let mut text = format!("-> {}\n", args.join(" "));
        let encoded = b64_encode(body);
        let mut rest = encoded.as_str();
        while rest.len() >= 64 {
            text.push_str(&rest[..64]);
            text.push('\n');
            rest = &rest[64..];
        }
        text.push_str(rest);
        text.push('\n');
        self.to_plugin.write_all(text.as_bytes()).and_then(|_| self.to_plugin.flush())
            .map_err(|e| format!("writing to the plugin: {e}"))
    }

    fn line(&mut self) -> Result<String, String> {
        let mut line = String::new();
        let n = self.from_plugin.read_line(&mut line).map_err(|e| format!("the plugin: {e}"))?;
        if n == 0 || !line.ends_with('\n') {
            return Err("the plugin stopped in the middle of the conversation".to_string());
        }
        line.pop();
        Ok(line)
    }

    /// The plugin's next stanza: its arguments and body.
    fn receive(&mut self) -> Result<(Vec<String>, Vec<u8>), String> {
        let first = self.line()?;
        let args: Vec<String> = first.strip_prefix("-> ")
            .ok_or_else(|| format!("the plugin sent {first:?}, not a stanza"))?
            .split(' ').map(str::to_string).collect();
        if args.iter().any(|a| a.is_empty()) {
            return Err("the plugin sent an empty stanza argument".to_string());
        }
        let mut body = String::new();
        loop {
            let line = self.line()?;
            if line.len() > 64 {
                return Err("the plugin sent a body line longer than 64 columns".to_string());
            }
            body.push_str(&line);
            if line.len() < 64 {
                break;
            }
        }
        let body = b64_decode(&body).ok_or("the plugin sent a body that is not canonical base64")?;
        Ok((args, body))
    }

    /// The plugin's requests of the client that both state machines
    /// share: a message to show, a value to ask for. `false` for any
    /// other stanza.
    fn answer_common(&mut self, name: &str, args: &[String], body: &[u8]) -> Result<bool, String> {
        match args[0].as_str() {
            "msg" => {
                eprintln!("age-plugin-{name}: {}", String::from_utf8_lossy(body));
                self.send(&["ok"], b"")?;
            }
            "request-secret" | "request-public" => {
                let prompt = format!("age-plugin-{name}: {} ", String::from_utf8_lossy(body));
                match passphrase::read_line(&prompt) {
                    Ok(value) => self.send(&["ok"], &value)?,
                    Err(_) => self.send(&["fail"], b"")?,
                }
            }
            // A yes or no this example cannot put to anyone.
            "confirm" => self.send(&["fail"], b"")?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(mut self) {
        drop(self.to_plugin);
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

/// How a plugin is reached: `PluginSession::spawn`, or a recording.
type Launcher<'a> = &'a mut dyn FnMut(&str, &str) -> Result<PluginSession, String>;

fn spawn_plugin(name: &str, protocol: &str) -> Result<PluginSession, String> {
    PluginSession::spawn(name, protocol)
}

/// recipient-v1: the plugin wraps the file key for one recipient, or for
/// a plugin identity's own recipient, in stanzas of its making.
fn plugin_wrap(name: &str, encoding: &str, identity: bool, file_key: &[u8],
               launch: Launcher<'_>) -> Result<Vec<Stanza>, String> {
    let mut session = launch(name, "recipient-v1")?;
    let add = if identity { "add-identity" } else { "add-recipient" };
    session.send(&[add, encoding], b"")?;
    session.send(&["wrap-file-key"], file_key)?;
    session.send(&["extension-labels"], b"")?;
    session.send(&["done"], b"")?;
    let mut stanzas = Vec::new();
    let result = loop {
        let (args, body) = session.receive()?;
        match args[0].as_str() {
            "recipient-stanza" => {
                if args.len() < 3 || args[1] != "0" {
                    break Err(format!("age-plugin-{name} sent a recipient stanza for a file \
                                       other than this one"));
                }
                stanzas.push(Stanza { args: args[2..].to_vec(), body });
                session.send(&["ok"], b"")?;
            }
            // age refuses to mix a post-quantum recipient with others by
            // these; this example does not, for any recipient.
            "labels" => session.send(&["ok"], b"")?,
            "error" => {
                session.send(&["ok"], b"")?;
                break Err(format!("age-plugin-{name}: {}", String::from_utf8_lossy(&body)));
            }
            "done" => break Ok(()),
            _ => {
                if !session.answer_common(name, &args, &body)? {
                    session.send(&["unsupported"], b"")?;
                }
            }
        }
    };
    session.finish();
    result?;
    if stanzas.is_empty() {
        return Err(format!("age-plugin-{name} wrapped the file key in no stanza"));
    }
    Ok(stanzas)
}

/// identity-v1: the plugin is shown every stanza and answers with the
/// file key, or with nothing if none is its identity's.
fn plugin_unwrap(name: &str, encoding: &str, stanzas: &[Stanza], launch: Launcher<'_>)
                 -> Result<Option<Vec<u8>>, String> {
    let mut session = launch(name, "identity-v1")?;
    session.send(&["add-identity", encoding], b"")?;
    for stanza in stanzas {
        let mut args = vec!["recipient-stanza", "0"];
        args.extend(stanza.args.iter().map(String::as_str));
        session.send(&args, &stanza.body)?;
    }
    session.send(&["done"], b"")?;
    let mut file_key = None;
    let result = loop {
        let (args, body) = session.receive()?;
        match args[0].as_str() {
            "file-key" => {
                if args.len() != 2 || args[1] != "0" || file_key.is_some() {
                    break Err(format!("age-plugin-{name} sent a malformed or second file key"));
                }
                file_key = Some(body);
                session.send(&["ok"], b"")?;
            }
            "error" => {
                session.send(&["ok"], b"")?;
                break Err(format!("age-plugin-{name}: {}", String::from_utf8_lossy(&body)));
            }
            "done" => break Ok(()),
            _ => {
                if !session.answer_common(name, &args, &body)? {
                    session.send(&["unsupported"], b"")?;
                }
            }
        }
    };
    session.finish();
    result.map(|()| file_key)
}

// ---------------------------------------------------------- payload ---

fn chunk_nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

/// The payload decrypted chunk by chunk, as age's reference reader
/// does. On failure, what was released before it - each chunk only once
/// its tag has verified.
///
/// A short chunk is the last, and must authenticate as the final chunk.
/// A full one is tried as an ordinary chunk and then as the final one;
/// if final, nothing may follow it. An empty final chunk is allowed only
/// as the whole payload.
fn decrypt_payload(file_key: &[u8], nonce: &[u8], mut rest: &[u8]) -> (Vec<u8>, Option<Failure>) {
    let key = sha256_hkdf(nonce, file_key, b"payload", 32);
    let mut out = Vec::new();
    let mut counter = 0u64;
    loop {
        if rest.is_empty() && counter > 0 {
            return (out, Some(Failure::Payload("the file ends without a final chunk".into())));
        }
        let take = rest.len().min(CHUNK + 16);
        let sealed = &rest[..take];
        rest = &rest[take..];
        let (plain, last) = if take < CHUNK + 16 {
            (aead_open(&key, &chunk_nonce(counter, true), sealed), true)
        } else {
            match aead_open(&key, &chunk_nonce(counter, false), sealed) {
                Some(plain) => (Some(plain), false),
                None => (aead_open(&key, &chunk_nonce(counter, true), sealed), true),
            }
        };
        let Some(plain) = plain else {
            return (out, Some(Failure::Payload(format!("chunk {counter} does not authenticate"))));
        };
        if last && plain.is_empty() && counter > 0 {
            return (out, Some(Failure::Payload("an empty final chunk after others".into())));
        }
        out.extend_from_slice(&plain);
        if last {
            if !rest.is_empty() {
                return (out, Some(Failure::Payload("data after the final chunk".into())));
            }
            return (out, None);
        }
        counter += 1;
    }
}

fn encrypt_payload(file_key: &[u8], plaintext: &[u8], random: Random<'_>)
                   -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; 16];
    random(&mut nonce)?;
    let key = sha256_hkdf(&nonce, file_key, b"payload", 32);
    let mut out = nonce.to_vec();
    let chunks: Vec<&[u8]> = if plaintext.is_empty() { vec![&[]] }
                             else { plaintext.chunks(CHUNK).collect() };
    for (i, chunk) in chunks.iter().enumerate() {
        out.extend(aead_seal(&key, &chunk_nonce(i as u64, i + 1 == chunks.len()), chunk));
    }
    Ok(out)
}

// ------------------------------------------------------------ armor ---

/// RFC 7468's strict encoding, with whitespace around the block and
/// CRLF line ends tolerated.
fn dearmor(data: &[u8]) -> Result<Vec<u8>, Failure> {
    let text = std::str::from_utf8(data).map_err(|_| Failure::Armor("not text".into()))?;
    let text = text.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n');
    let normalized = text.replace("\r\n", "\n");
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    if lines.first() != Some(&ARMOR_BEGIN) || lines.last() != Some(&ARMOR_END) {
        return Err(Failure::Armor("not between the BEGIN and END lines".into()));
    }
    lines.remove(0);
    lines.pop();
    if lines.is_empty() {
        // Nothing inside: an empty file, for the header to refuse.
        return Ok(Vec::new());
    }
    let last = lines.len() - 1;
    let mut encoded = String::new();
    for (i, l) in lines.iter().enumerate() {
        if (i < last && l.len() != 64) || (i == last && (l.is_empty() || l.len() > 64)) {
            return Err(Failure::Armor("a line of the wrong length".into()));
        }
        encoded.push_str(l);
    }
    if !encoded.len().is_multiple_of(4) {
        return Err(Failure::Armor("base64 without its padding".into()));
    }
    let unpadded = encoded.trim_end_matches('=');
    if encoded.len() - unpadded.len() > 2 {
        return Err(Failure::Armor("too much padding".into()));
    }
    b64_decode(unpadded).ok_or(Failure::Armor("base64 that is not canonical".into()))
}

fn armor(data: &[u8]) -> Vec<u8> {
    let encoded = allcrypt::pem::encode(data);
    let mut out = format!("{ARMOR_BEGIN}\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out.push('\n');
    out.into_bytes()
}

// ------------------------------------------------- whole files ---

/// Decrypt an age file. `armored` says whether it is ASCII armored;
/// `None` decides by whether it starts, after any whitespace, with the
/// armor's first line.
fn decrypt(file: &[u8], identities: &[Identity], armored: Option<bool>)
           -> (Vec<u8>, Option<Failure>) {
    decrypt_with(file, identities, armored, &mut spawn_plugin)
}

fn decrypt_with(file: &[u8], identities: &[Identity], armored: Option<bool>, launch: Launcher<'_>)
                -> (Vec<u8>, Option<Failure>) {
    let armored = armored.unwrap_or_else(|| file.trim_ascii_start()
        .starts_with(ARMOR_BEGIN.as_bytes()));
    let dearmored;
    let data = if armored {
        match dearmor(file) {
            Ok(d) => {
                dearmored = d;
                &dearmored[..]
            }
            Err(failure) => return (Vec::new(), Some(failure)),
        }
    } else {
        file
    };
    let header = match parse_header(data) {
        Ok(h) => h,
        Err(failure) => return (Vec::new(), Some(failure)),
    };
    let scrypt = header.stanzas.iter().any(|s| s.args[0] == "scrypt");
    if scrypt && header.stanzas.len() > 1 {
        return (Vec::new(), Some(Failure::Header("an scrypt stanza with others".into())));
    }
    let mut file_key = None;
    'search: for identity in identities {
        if let Identity::Plugin { name, encoding } = identity {
            match plugin_unwrap(name, encoding, &header.stanzas, launch) {
                Ok(Some(key)) => {
                    file_key = Some(key);
                    break 'search;
                }
                Ok(None) => continue,
                Err(why) => return (Vec::new(), Some(Failure::Plugin(why))),
            }
        }
        for stanza in &header.stanzas {
            match unwrap(identity, stanza) {
                Ok(Some(key)) => {
                    file_key = Some(key);
                    break 'search;
                }
                Ok(None) => {}
                Err(failure) => return (Vec::new(), Some(failure)),
            }
        }
    }
    let Some(file_key) = file_key else {
        return (Vec::new(), Some(Failure::NoMatch));
    };
    if file_key.len() != 16 {
        return (Vec::new(), Some(Failure::Header("a file key that is not 16 bytes".into())));
    }
    let hmac_key = sha256_hkdf(b"", &file_key, b"header", 32);
    if hmac_sha256(&hmac_key, &data[..header.covered_len]) != header.mac {
        return (Vec::new(), Some(Failure::Hmac));
    }
    // The nonce is read with the header: a file too short for it is a
    // malformed header, not a payload that fails.
    let Some(nonce) = data.get(header.len..header.len + 16) else {
        return (Vec::new(), Some(Failure::Header("no payload nonce".into())));
    };
    decrypt_payload(&file_key, nonce, &data[header.len + 16..])
}

fn encrypt(plaintext: &[u8], recipients: &[Recipient], random: Random<'_>)
           -> Result<Vec<u8>, String> {
    encrypt_with(plaintext, recipients, random, &mut spawn_plugin)
}

fn encrypt_with(plaintext: &[u8], recipients: &[Recipient], random: Random<'_>,
                launch: Launcher<'_>) -> Result<Vec<u8>, String> {
    if recipients.is_empty() {
        return Err("at least one recipient".to_string());
    }
    let mut file_key = [0u8; 16];
    random(&mut file_key)?;
    let mut stanzas = Vec::new();
    for recipient in recipients {
        match recipient {
            Recipient::Plugin { name, encoding, identity } =>
                stanzas.extend(plugin_wrap(name, encoding, *identity, &file_key, launch)?),
            _ => stanzas.push(wrap(recipient, &file_key, random)?),
        }
    }
    let mut out = write_header(&stanzas, &sha256_hkdf(b"", &file_key, b"header", 32));
    out.extend(encrypt_payload(&file_key, plaintext, random)?);
    Ok(out)
}

// -------------------------------------------------------------- CLI ---

fn counter_stream(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), String> {
    let mut counter = 0u64;
    let mut pool: Vec<u8> = Vec::new();
    move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            if pool.is_empty() {
                let mut h = AnyHash::new("sha256")?;
                h.update(&seed.to_be_bytes());
                h.update(&counter.to_be_bytes());
                pool = h.digest();
                counter += 1;
                pool.reverse();
            }
            *byte = pool.pop().unwrap_or(0);
        }
        Ok(())
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: age keygen [--pq] | encrypt IN OUT (-r R | -R FILE | -j PLUGIN)... \
                 [--plugin-recipients] | --passphrase P | decrypt IN OUT (-i IDENTITY | \
                 --identity-file F | -j PLUGIN)... | --passphrase P; --passphrase-stdin in \
                 place of --passphrase P";
    let command = args.first().ok_or(usage)?;
    let mut values: Vec<(String, String)> = Vec::new();
    let mut flags = Vec::new();
    let mut positional = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--pq" || a == "--armor" || a == "--passphrase-stdin"
                || a == "--plugin-recipients" {
            flags.push(a.clone());
            i += 1;
        } else if a.starts_with('-') {
            values.push((a.trim_start_matches('-').to_string(),
                         args.get(i + 1).ok_or(format!("{a} needs a value"))?.clone()));
            i += 2;
        } else {
            positional.push(a.clone());
            i += 1;
        }
    }
    let get = |name: &str| values.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str())
        .collect::<Vec<_>>();
    let mut passphrases: Vec<Vec<u8>> = get("passphrase").iter()
        .map(|p| p.as_bytes().to_vec()).collect();
    if flags.iter().any(|f| f == "--passphrase-stdin") {
        passphrases.push(passphrase::read_line("Passphrase: ")?);
    }
    let seed = get("seed").first().map(|s| s.parse::<u64>().map_err(|e| e.to_string())).transpose()?;
    let mut os_random = |b: &mut [u8]| allcrypt::random::fill(b);
    let mut seeded = seed.map(counter_stream);
    let random: Random<'_> = match seeded.as_mut() {
        Some(s) => s,
        None => &mut os_random,
    };
    match command.as_str() {
        "keygen" => {
            let mut secret = [0u8; 32];
            random(&mut secret)?;
            if flags.iter().any(|f| f == "--pq") {
                let public = Kem::MlKem768X25519.public_key(&secret)?;
                println!("# public key: {}", bech32_encode("age1pq", &public));
                println!("{}", bech32_encode("age-secret-key-pq-", &secret).to_ascii_uppercase());
            } else {
                println!("# public key: {}", bech32_encode("age", &x25519::public_key(&secret)?));
                println!("{}", bech32_encode("age-secret-key-", &secret).to_ascii_uppercase());
            }
            Ok(())
        }
        "encrypt" => {
            let [input, output] = &positional[..] else { return Err(usage.to_string()) };
            let plaintext = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
            let via_plugin = flags.iter().any(|f| f == "--plugin-recipients");
            let mut recipients = get("r").iter().map(|r| parse_recipient_with(r, via_plugin))
                .collect::<Result<Vec<_>, _>>()?;
            for path in get("R") {
                let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                for l in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                    recipients.push(parse_recipient_with(l, via_plugin)?);
                }
            }
            for name in get("j") {
                recipients.push(Recipient::Plugin { name: name.to_ascii_lowercase(),
                    encoding: plugin_identity_without_data(name)?, identity: true });
            }
            if let Some(p) = passphrases.first() {
                let work_factor = get("work-factor").first().map(|w| w.parse::<u32>())
                    .transpose().map_err(|e| e.to_string())?.unwrap_or(18);
                recipients.push(Recipient::Passphrase { passphrase: p.clone(), work_factor });
            }
            let mut out = encrypt(&plaintext, &recipients, random)?;
            if flags.iter().any(|f| f == "--armor") {
                out = armor(&out);
            }
            std::fs::write(output, out).map_err(|e| format!("{output}: {e}"))
        }
        "decrypt" => {
            let [input, output] = &positional[..] else { return Err(usage.to_string()) };
            let file = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
            let mut identities = get("i").iter().map(|i| parse_identity(i))
                .collect::<Result<Vec<_>, _>>()?;
            for name in get("j") {
                identities.push(Identity::Plugin { name: name.to_ascii_lowercase(),
                                                   encoding: plugin_identity_without_data(name)? });
            }
            let key_passphrase = get("key-passphrase").first().map(|p| p.as_bytes().to_vec());
            for path in get("identity-file") {
                let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
                    identities.push(ssh_identity(&text, key_passphrase.as_deref())
                        .map_err(|e| format!("{path}: {e}"))?);
                    continue;
                }
                for l in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                    identities.push(parse_identity(l)?);
                }
            }
            for p in passphrases {
                identities.push(Identity::Passphrase(p));
            }
            let (plaintext, failure) = decrypt(&file, &identities, None);
            if let Some(failure) = failure {
                return Err(failure.to_string());
            }
            std::fs::write(output, plaintext).map_err(|e| format!("{output}: {e}"))
        }
        _ => Err(usage.to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("age: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = AnyHash::new("sha256").unwrap();
        h.update(data);
        fixtures::hex(&h.digest())
    }

    /// The age test suite (C2SP CCTV, `fixtures/age/testkit/`, 0BSD):
    /// every vector's file decrypted with its identities or passphrases,
    /// the outcome its `expect` line names, and the plaintext released -
    /// all of it, failure or not - hashing to its `payload` line.
    #[test]
    fn test_age_testkit() {
        let dir = fixtures::dir().join("age").join("testkit");
        let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        let mut checked = 0;
        let mut failed = Vec::new();
        for name in &names {
            let raw = std::fs::read(dir.join(name)).unwrap();
            let split = raw.windows(2).position(|w| w == b"\n\n").unwrap();
            let fields: Vec<(String, String)> = std::str::from_utf8(&raw[..split]).unwrap().lines()
                .filter_map(|l| l.split_once(": ").map(|(k, v)| (k.to_string(), v.to_string())))
                .collect();
            let field = |k: &str| fields.iter().filter(|(key, _)| key == k).map(|(_, v)| v.as_str())
                .collect::<Vec<_>>();
            let mut body = raw[split + 2..].to_vec();
            if field("compressed").first() == Some(&"zlib") {
                body = inflate::zlib_decompress(&body, 64 << 20).unwrap();
            }
            let mut identities: Vec<Identity> = field("identity").iter()
                .map(|i| parse_identity(i).unwrap()).collect();
            identities.extend(field("passphrase").iter()
                .map(|p| Identity::Passphrase(p.as_bytes().to_vec())));
            let armored = field("armored").first() == Some(&"yes");
            let (released, failure) = decrypt(&body, &identities, Some(armored));
            let got = match &failure {
                None => "success",
                Some(Failure::Armor(_)) => "armor failure",
                Some(Failure::Header(_)) => "header failure",
                Some(Failure::NoMatch) => "no match",
                Some(Failure::Hmac) => "HMAC failure",
                Some(Failure::Payload(_)) => "payload failure",
                Some(Failure::Plugin(why)) => panic!("{name}: no plugin is involved: {why}"),
            };
            let expected = field("expect")[0];
            let mut ok = got == expected;
            if let Some(hash) = field("payload").first() {
                ok &= sha256_hex(&released) == *hash;
            } else if expected != "success" && expected != "payload failure" {
                ok &= released.is_empty();
            }
            if !ok {
                failed.push(format!("{name}: expected {expected}, got {got} \
                                     ({:?})", failure.map(|f| f.to_string())));
            }
            checked += 1;
        }
        assert!(failed.is_empty(), "{} of {checked} failed:\n{}", failed.len(), failed.join("\n"));
        assert!(checked >= 140, "{checked}");
    }

    /// The spec's own examples of each encoding.
    #[test]
    fn test_spec_keys() {
        let identity = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX";
        let Identity::X25519(secret) = parse_identity(identity).unwrap() else { panic!() };
        assert_eq!(bech32_encode("age", &x25519::public_key(&secret).unwrap()),
                   "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj");
        assert_eq!(bech32_encode("age-secret-key-", &secret).to_ascii_uppercase(), identity);
        assert!(parse_identity(&identity.replace('G', "g")).is_err());
    }

    #[test]
    fn test_round_trips() {
        let mut random = counter_stream(5);
        let plaintext: Vec<u8> = (0..(2 * CHUNK + 100) as u32).map(|i| i as u8).collect();
        let mut x_secret = [0u8; 32];
        random(&mut x_secret).unwrap();
        let mut pq_seed = [0u8; 32];
        random(&mut pq_seed).unwrap();
        let pq = Kem::MlKem768X25519.public_key(&pq_seed).unwrap();
        let recipients = [Recipient::X25519(x25519::public_key(&x_secret).unwrap()),
                          Recipient::Hybrid(pq)];
        for (len, armored) in [(0, false), (CHUNK, false), (plaintext.len(), true)] {
            let mut file = encrypt(&plaintext[..len], &recipients, &mut random).unwrap();
            if armored {
                file = armor(&file);
            }
            for identity in [Identity::X25519(x_secret), Identity::Hybrid(pq_seed)] {
                let (out, failure) = decrypt(&file, &[identity], None);
                assert!(failure.is_none(), "{len}: {failure:?}");
                assert_eq!(out, &plaintext[..len]);
            }
        }
        let file = encrypt(b"pw", &[Recipient::Passphrase { passphrase: b"hunter2".to_vec(),
                                                             work_factor: 4 }], &mut random).unwrap();
        assert_eq!(decrypt(&file, &[Identity::Passphrase(b"hunter2".to_vec())], None).0, b"pw");
        assert_eq!(decrypt(&file, &[Identity::Passphrase(b"hunter3".to_vec())], None).1,
                   Some(Failure::NoMatch));
    }

    // ------------------------------------------------------- SSH keys --

    fn ssh_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixtures::dir().join("age").join("ssh").join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn ssh_key_identity(name: &str) -> Identity {
        let text = String::from_utf8(ssh_fixture(name)).unwrap();
        let passphrase = name.ends_with("-encrypted").then_some(&b"key passphrase"[..]);
        ssh_identity(&text, passphrase).unwrap()
    }

    fn ssh_key_recipient(name: &str) -> Recipient {
        parse_recipient(&String::from_utf8(ssh_fixture(&format!("{name}.pub"))).unwrap())
            .unwrap()
    }

    /// Files age 1.1.1 and rage 0.11.1 encrypted to SSH keys - Ed25519,
    /// RSA, and an encrypted Ed25519 key - singly and all three at once,
    /// binary and armored, open here to the plaintext with each key they
    /// were made for, and with another key find nothing.
    #[test]
    fn test_age_and_rage_files_to_ssh_keys() {
        let records = fixtures::records("age/ssh/ssh.vec", "theirs");
        assert_eq!(records.len(), 24);
        let mut makers = std::collections::BTreeSet::new();
        for record in &records {
            let name = fixtures::field(record, "name");
            let identity = fixtures::field(record, "identity");
            let file = ssh_fixture(name);
            let (out, failure) = decrypt(&file, &[ssh_key_identity(identity)], None);
            assert!(failure.is_none(), "{name} with {identity}: {failure:?}");
            assert!(out == ssh_fixture(fixtures::field(record, "plain")), "{name}");
            makers.insert(fixtures::field(record, "made_by").split(' ').next().unwrap()
                .to_string());
            if !name.contains("-all-") {
                let other = if identity == "rsa" { "ed25519" } else { "rsa" };
                assert_eq!(decrypt(&file, &[ssh_key_identity(other)], None).1,
                           Some(Failure::NoMatch), "{name} with {other}");
            }
        }
        assert_eq!(makers.into_iter().collect::<Vec<_>>(), ["age", "rage"]);
    }

    /// The example's own files to SSH keys, which age and rage decrypted
    /// when they were written, made again byte for byte from their seed -
    /// so the stanzas, the tag and the RSA-OAEP seed all come out as they
    /// were checked.
    #[test]
    fn test_our_files_to_ssh_keys_are_made_again() {
        let records = fixtures::records("age/ssh/ssh.vec", "ours");
        assert_eq!(records.len(), 7);
        for record in &records {
            let name = fixtures::field(record, "name");
            let to = fixtures::field(record, "to");
            let names: Vec<&str> = if to == "all" { vec!["ed25519", "rsa", "ed25519-encrypted"] }
                                   else { vec![to] };
            let recipients: Vec<Recipient> = names.iter().map(|n| ssh_key_recipient(n))
                .collect();
            let mut random = counter_stream(fixtures::field(record, "seed").parse().unwrap());
            let again = encrypt(&ssh_fixture(fixtures::field(record, "plain")), &recipients,
                                &mut random).unwrap();
            assert!(again == ssh_fixture(name), "{name}");
        }
    }

    /// What an SSH stanza must be. A tag naming another key is somebody
    /// else's stanza; a stanza whose tag names this key and does not open
    /// is an error, as age has it, since the tag says it was meant for
    /// this key. The wrong number of arguments is malformed. ECDSA keys
    /// are neither recipients nor identities, and an encrypted key needs
    /// its passphrase.
    #[test]
    fn test_ssh_stanzas_and_keys_are_checked() {
        let mut random = counter_stream(77);
        for key in ["ed25519", "rsa"] {
            let file = encrypt(b"tagged", &[ssh_key_recipient(key)], &mut random).unwrap();
            let header = parse_header(&file).unwrap();
            let stanza = &header.stanzas[0];
            let identity = ssh_key_identity(key);
            assert_eq!(unwrap(&identity, stanza).unwrap().unwrap().len(), 16);
            // Another tag: not ours.
            let mut other = Stanza { args: stanza.args.clone(), body: stanza.body.clone() };
            other.args[1] = "AAAAAA".to_string();
            assert_eq!(unwrap(&identity, &other).unwrap(), None);
            // Our tag, a changed body: an error.
            let mut damaged = Stanza { args: stanza.args.clone(), body: stanza.body.clone() };
            damaged.body[0] ^= 1;
            assert!(matches!(unwrap(&identity, &damaged), Err(Failure::Header(_))), "{key}");
            // An argument too many.
            let mut long = Stanza { args: stanza.args.clone(), body: stanza.body.clone() };
            long.args.push("AAAA".to_string());
            assert!(matches!(unwrap(&identity, &long), Err(Failure::Header(_))), "{key}");
        }
        // The two tags differ, and each is four bytes of the key's hash.
        let (ed, rsa) = (ssh_key_recipient("ed25519"), ssh_key_recipient("rsa"));
        let (Recipient::SshEd25519 { blob: ed, .. }, Recipient::SshRsa { blob: rsa, .. }) = (ed, rsa)
        else { panic!() };
        assert_ne!(ssh_tag(&ed), ssh_tag(&rsa));
        assert_eq!(b64_decode(&ssh_tag(&ed)).unwrap().len(), 4);

        let ecdsa = ssh::private_key::PrivateKey::generate("ecdsa-sha2-nistp256", None).unwrap();
        assert!(ssh_recipient(&ecdsa.public()).err().unwrap().contains("not age recipients"));
        let text = ssh::private_key::write(&ecdsa, "", None).unwrap();
        assert!(ssh_identity(&text, None).err().unwrap().contains("not age identities"));
        let encrypted = String::from_utf8(ssh_fixture("ed25519-encrypted")).unwrap();
        assert!(ssh_identity(&encrypted, None).is_err());
        assert!(ssh_identity(&encrypted, Some(b"wrong")).is_err());
    }

    // ------------------------------------------------------ tagged types --

    fn tag_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixtures::dir().join("age/tag").join(name)).unwrap()
    }

    /// The recipient strings `age-tag-witness` printed for each seed, by
    /// seed.
    fn tag_recipients() -> std::collections::HashMap<String, (String, String)> {
        fixtures::records("age/tag/tag.vec", "recipients").iter().map(|r| (
            fixtures::field(r, "name").to_string(),
            (fixtures::field(r, "type").to_string(), fixtures::field(r, "recipient").to_string())))
            .collect()
    }

    /// age's test identities are HPKE's DeriveKeyPair of a seed, and the
    /// recipients they answer to must encode as age's do - bech32 of the
    /// compressed point for `age1tag`, of the whole hybrid key for
    /// `age1tagpq` - and parse back.
    #[test]
    fn test_tag_recipients_are_ages() {
        let recipients = tag_recipients();
        assert_eq!(recipients.len(), 4);
        for (seed, (kind, text)) in &recipients {
            let identity = Identity::tag_from_seed(seed.as_bytes(), kind == "pq").unwrap();
            let ours = match identity.tag_recipient().unwrap() {
                Recipient::Tag(point) => bech32_encode("age1tag", &point),
                Recipient::TagPq(key) => bech32_encode("age1tagpq", &key),
                _ => unreachable!(),
            };
            assert_eq!(&ours, text, "{seed}");
            assert!(matches!((parse_recipient(text).unwrap(), kind.as_str()),
                             (Recipient::Tag(_), "classic") | (Recipient::TagPq(_), "pq")));
        }
        // Not a point; the hybrid key's P-256 part not a point either.
        let (_, (_, classic)) = recipients.iter().find(|(_, (k, _))| k == "classic").unwrap();
        let (_, mut point) = bech32_decode(classic).unwrap();
        point[0] = 0x04;
        assert!(parse_recipient(&bech32_encode("age1tag", &point)).is_err());
        let (_, (_, pq)) = recipients.iter().find(|(_, (k, _))| k == "pq").unwrap();
        let (_, mut key) = bech32_decode(pq).unwrap();
        key[1184 + 64] ^= 1;
        assert!(parse_recipient(&bech32_encode("age1tagpq", &key)).is_err());
    }

    /// Files age 1.3.2 encrypted to the tagged types, to one recipient or
    /// two, binary and armored, open here with the identity made from the
    /// same seed; and with the other type's identity find nothing.
    #[test]
    fn test_age_files_to_tag_recipients() {
        let records = fixtures::records("age/tag/tag.vec", "theirs");
        assert_eq!(records.len(), 16);
        for record in &records {
            let name = fixtures::field(record, "name");
            let pq = fixtures::field(record, "type") == "pq";
            let seed = fixtures::field(record, "seed");
            let file = tag_fixture(name);
            let identity = Identity::tag_from_seed(seed.as_bytes(), pq).unwrap();
            let (out, failure) = decrypt(&file, &[identity], None);
            assert!(failure.is_none(), "{name} with {seed}: {failure:?}");
            assert!(out == tag_fixture(fixtures::field(record, "plain")), "{name}");
            let other = Identity::tag_from_seed(seed.as_bytes(), !pq).unwrap();
            assert_eq!(decrypt(&file, &[other], None).1, Some(Failure::NoMatch), "{name}");
        }
    }

    /// The example's own files to the tagged types, which age's test
    /// identities decrypted when they were written, made again byte for
    /// byte from their seed.
    #[test]
    fn test_our_files_to_tag_recipients_are_made_again() {
        let records = fixtures::records("age/tag/tag.vec", "ours");
        assert_eq!(records.len(), 5);
        let recipients = tag_recipients();
        for record in &records {
            let name = fixtures::field(record, "name");
            let targets: Vec<Recipient> = fixtures::field(record, "seed").split(" + ")
                .map(|seed| parse_recipient(&recipients[seed].1).unwrap()).collect();
            let mut random = counter_stream(fixtures::field(record, "seed_number").parse()
                .unwrap());
            let again = encrypt(&tag_fixture(fixtures::field(record, "plain")), &targets,
                                &mut random).unwrap();
            assert!(again == tag_fixture(name), "{name}");
        }
    }

    /// A tagged stanza: one whose tag is another key's is somebody else's,
    /// and so is one whose tag matches and whose body does not open - the
    /// tag is four bytes and can collide, as age's reader allows; one with
    /// an enc of the wrong size or the wrong number of arguments is
    /// malformed.
    #[test]
    fn test_tag_stanzas_are_checked() {
        let mut random = counter_stream(91);
        for pq in [false, true] {
            let identity = Identity::tag_from_seed(b"stanza check", pq).unwrap();
            let file = encrypt(b"tagged", &[identity.tag_recipient().unwrap()], &mut random)
                .unwrap();
            let header = parse_header(&file).unwrap();
            let stanza = &header.stanzas[0];
            assert_eq!(stanza.args[0], if pq { "mlkem768p256tag" } else { "p256tag" });
            assert_eq!(unwrap(&identity, stanza).unwrap().unwrap().len(), 16);
            let changed = |f: &dyn Fn(&mut Stanza)| {
                let mut s = Stanza { args: stanza.args.clone(), body: stanza.body.clone() };
                f(&mut s);
                unwrap(&identity, &s)
            };
            assert!(changed(&|s| s.args[1] = b64_encode(b"\0\0\0\0")).unwrap().is_none());
            assert!(changed(&|s| s.body[0] ^= 1).unwrap().is_none());
            assert!(changed(&|s| s.args.push("x".into())).is_err());
            assert!(changed(&|s| s.args[2] = b64_encode(&[4; 65 + 1])).is_err());
            assert!(changed(&|s| s.body.push(0)).is_err());
            let other = Identity::tag_from_seed(b"someone else", pq).unwrap();
            assert!(unwrap(&other, stanza).unwrap().is_none());
        }
    }

    // ------------------------------------------------------------ plugins --

    fn plugin_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixtures::dir().join("age/plugin").join(name)).unwrap()
    }

    /// Bytes written to a plugin, kept where the test can read them.
    #[derive(Clone, Default)]
    struct Captured(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }

    /// A launcher that plays back `answers` for a plugin of `name` and
    /// `protocol`, keeping what the example writes.
    fn replay(name: &'static str, protocol: &'static str, answers: Vec<u8>)
              -> (impl FnMut(&str, &str) -> Result<PluginSession, String>, Captured) {
        let captured = Captured::default();
        let writer = captured.clone();
        let mut answers = Some(answers);
        let launch = move |plugin: &str, wanted: &str| {
            assert_eq!((plugin, wanted), (name, protocol));
            let from = answers.take().ok_or("one conversation only")?;
            Ok(PluginSession { from_plugin: Box::new(std::io::Cursor::new(from)),
                               to_plugin: Box::new(writer.clone()), child: None })
        };
        (launch, captured)
    }

    fn leak(text: &str) -> &'static str {
        Box::leak(text.to_string().into_boxed_str())
    }

    /// Every conversation with age 1.3.2's plugins, played back: the
    /// example must write to the plugin exactly what it wrote then - the
    /// same file key, from the same seed, and the same answers to the
    /// plugin's grease and labels - and make the same file, or open age's
    /// file to the plaintext.
    #[test]
    fn test_conversations_with_ages_plugins() {
        let keys = &fixtures::records("age/plugin/plugin.vec", "keys")[0];
        let records = fixtures::records("age/plugin/plugin.vec", "sessions");
        assert_eq!(records.len(), 6);
        let plain = plugin_fixture("plain");
        let mut protocols = std::collections::BTreeSet::new();
        for record in &records {
            let name = fixtures::field(record, "name");
            let session = fixtures::field(record, "session");
            let plugin = leak(fixtures::field(record, "plugin"));
            let protocol = leak(fixtures::field(record, "protocol"));
            protocols.insert((plugin, protocol));
            let args = fixtures::field(record, "args")
                .replace("PQ_RECIPIENT", fixtures::field(keys, "recipient"))
                .replace("PQ_PLUGIN_IDENTITY", fixtures::field(keys, "plugin_identity"));
            let args: Vec<&str> = args.split(' ').collect();
            let (mut launch, captured) = replay(plugin, protocol,
                                                plugin_fixture(&format!("{session}.from")));
            if protocol == "recipient-v1" {
                let recipient = match args[..] {
                    ["-r", text, "--plugin-recipients"] => parse_recipient_with(text, true).unwrap(),
                    ["-j", name] => Recipient::Plugin {
                        name: name.to_string(), identity: true,
                        encoding: plugin_identity_without_data(name).unwrap() },
                    _ => panic!("{args:?}"),
                };
                let mut random = counter_stream(fixtures::field(record, "seed_number").parse()
                    .unwrap());
                let file = encrypt_with(&plain, &[recipient], &mut random, &mut launch)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert!(file == plugin_fixture(name), "{name}: not the same file");
            } else {
                let identity = match args[..] {
                    ["-i", text] => parse_identity(text).unwrap(),
                    ["-j", name] => Identity::Plugin {
                        name: name.to_string(), encoding: plugin_identity_without_data(name).unwrap() },
                    _ => panic!("{args:?}"),
                };
                let (out, failure) = decrypt_with(&plugin_fixture(name), &[identity], None,
                                                  &mut launch);
                assert!(failure.is_none(), "{name}: {failure:?}");
                assert!(out == plain, "{name}");
            }
            assert!(*captured.0.borrow() == plugin_fixture(&format!("{session}.to")),
                    "{name}: not what was written to the plugin");
        }
        assert_eq!(protocols.len(), 6);
        // The files through age-plugin-pq are ordinary age1pq files.
        let native = parse_identity(fixtures::field(keys, "identity")).unwrap();
        for name in ["ours-pq.age", "age-pq.age"] {
            assert!(decrypt(&plugin_fixture(name), std::slice::from_ref(&native), None).0 == plain,
                    "{name}");
        }
        assert_eq!(plugin_identity_without_data("batchpass").unwrap(), "AGE-PLUGIN-BATCHPASS-1JCS0Q9");
    }

    /// What a plugin may say and what it may not: an error ends the
    /// conversation with that error; a stanza for another file, a second
    /// file key, a conversation cut short or no stanza at all are
    /// refused; a request this example cannot answer gets "unsupported"
    /// and the conversation goes on.
    #[test]
    fn test_what_a_plugin_may_say() {
        // A stanza as a plugin would send it, written by the same code
        // that writes the example's own.
        let stanza = |args: &str, body: &[u8]| {
            let captured = Captured::default();
            let mut session = PluginSession { from_plugin: Box::new(std::io::empty()),
                                              to_plugin: Box::new(captured.clone()), child: None };
            session.send(&args.split(' ').collect::<Vec<_>>(), body).unwrap();
            let bytes = captured.0.borrow().clone();
            bytes
        };
        let wrap = |answers: Vec<u8>| {
            let (mut launch, captured) = replay("x", "recipient-v1", answers);
            let result = plugin_wrap("x", "age1x1qqqqqqqq", false, &[7; 16], &mut launch);
            (result, captured)
        };
        let ok = [stanza("recipient-stanza 0 X25519 abc", &[1; 32]), stanza("done", b"")].concat();
        let (stanzas, captured) = wrap(ok);
        assert_eq!(stanzas.unwrap()[0].args, ["X25519", "abc"]);
        assert!(String::from_utf8(captured.0.borrow().clone()).unwrap()
                    .ends_with("-> done\n\n-> ok\n\n"));
        let error = [stanza("error internal", b"no such key"), stanza("done", b"")].concat();
        let (result, captured) = wrap(error);
        assert!(result.unwrap_err().contains("no such key"));
        // The error is acknowledged before the conversation ends.
        assert!(String::from_utf8(captured.0.borrow().clone()).unwrap()
                    .ends_with("-> done\n\n-> ok\n\n"));
        let other_file = [stanza("recipient-stanza 1 X25519 abc", &[1; 32]), stanza("done", b"")]
            .concat();
        assert!(wrap(other_file).0.is_err());
        assert!(wrap(stanza("done", b"")).0.unwrap_err().contains("no stanza"));
        assert!(wrap(stanza("recipient-stanza 0 X25519 abc", &[1; 32])).0.unwrap_err()
                    .contains("stopped"));
        let unknown = [stanza("something-new", b""), stanza("recipient-stanza 0 Y", &[2; 3]),
                       stanza("done", b"")].concat();
        let (stanzas, captured) = wrap(unknown);
        assert_eq!(stanzas.unwrap().len(), 1);
        assert!(String::from_utf8(captured.0.borrow().clone()).unwrap()
                    .contains("-> unsupported\n\n-> ok\n\n"));
        let unwrap_with = |answers: Vec<u8>| {
            let (mut launch, _) = replay("x", "identity-v1", answers);
            plugin_unwrap("x", "AGE-PLUGIN-X-1", &[], &mut launch)
        };
        assert_eq!(unwrap_with(stanza("done", b"")).unwrap(), None);
        let key = [stanza("file-key 0", &[9; 16]), stanza("done", b"")].concat();
        assert_eq!(unwrap_with(key).unwrap(), Some(vec![9; 16]));
        let twice = [stanza("file-key 0", &[9; 16]), stanza("file-key 0", &[9; 16]),
                     stanza("done", b"")].concat();
        assert!(unwrap_with(twice).is_err());
        assert!(unwrap_with(b"not a stanza\n".to_vec()).is_err());
        // A body of 48 bytes is one full line of 64 columns and an empty
        // one after it; 49 bytes, a full line and a short one.
        for (length, lines) in [(48, vec![4, 64, 0]), (49, vec![4, 64, 2])] {
            let body: Vec<u8> = (0..length as u8).collect();
            let text = String::from_utf8(stanza("x", &body)).unwrap();
            assert_eq!(text.split('\n').map(str::len).collect::<Vec<_>>()[..lines.len()], lines);
            let mut back = PluginSession { from_plugin: Box::new(std::io::Cursor::new(text)),
                                           to_plugin: Box::new(std::io::sink()), child: None };
            assert_eq!(back.receive().unwrap(), (vec!["x".to_string()], body));
        }
        // A plugin's name is alphanumerics and `+-._`: nothing that could
        // name a path.
        assert!(parse_identity(&bech32_encode("age-plugin-bad/name-", &[1]).to_ascii_uppercase())
                    .is_err());
        assert!(parse_recipient_with(&bech32_encode("age1bad/name", &[1, 2]), true).is_err());
        assert!(plugin_identity_without_data("bad/name").is_err());
        assert!(matches!(parse_identity(&bech32_encode("age-plugin-good.name-", &[1])
                                             .to_ascii_uppercase()),
                         Ok(Identity::Plugin { name, .. }) if name == "good.name"));
    }
}
