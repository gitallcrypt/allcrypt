/*
OpenSSH's own private key format, `openssh-key-v1` (OpenSSH's
PROTOCOL.key), plain and encrypted.

    -----BEGIN OPENSSH PRIVATE KEY-----
    base64 of:
        "openssh-key-v1" 0x00
        string  cipher name          ("none", "aes256-ctr", ...)
        string  KDF name             ("none" or "bcrypt")
        string  KDF options          (bcrypt: string salt, uint32 rounds)
        uint32  number of keys       (OpenSSH writes and reads only 1)
        string  public key blob
        string  private section, encrypted   [then the AEAD tag, if any]

    the private section, decrypted:
        uint32  check, uint32 check  (equal: the passphrase was right)
        string  key type, then the type's private fields
        string  comment
        1, 2, 3, ... padding to the cipher's block size

This is the default format of `ssh-keygen` since OpenSSH 7.8. Keys made
before that, and RSA and ECDSA keys made with `-m PEM` since, are
PKCS#1 / SEC1 / PKCS#8 in PEM, which `x509::private_key` already reads.

# Pitfalls

**An AEAD cipher's tag sits after the private section's string, not
inside it.** The string's length counts the ciphertext only, and the
16 byte tag follows with no length of its own - so a reader that takes
the string and then expects the end of the data refuses every
`aes256-gcm@openssh.com` and `chacha20-poly1305@openssh.com` key.

**A wrong passphrase is the check words, not an error from the
cipher.** CTR and CBC decrypt garbage without complaint; only the two
equal `uint32`s at the front say whether it worked. For the AEAD
ciphers the tag fails first, and that is the same answer.

**The private fields carry the public key again**, and nothing in the
format says the two copies agree. A file whose public blob is one key
and whose private section is another is a file that signs as a key
other than the one it claims to be - so every key read here is checked:
the public key is recomputed from the private one and must equal the
blob in the header.

**A stream cipher's "IV" is still eight bytes of the derivation.**
OpenSSH asks bcrypt_pbkdf for the key and `cipher_ivlen` bytes, and
`cipher_ivlen` is the block size - 8 - for a cipher with no IV at all,
which is to say RC4. Eight unused bytes would not matter, except that
bcrypt_pbkdf interleaves: the key that comes out of a 40 byte derivation
is not the first 32 bytes of a 32 byte one. `arcfour` and `arcfour128`
(24 bytes either way) worked without this and `arcfour256` did not,
which is how it was found.

**RSA's private fields are `n, e, d, iqmp, p, q`** - not PKCS#1's order,
and with `iqmp` (q^-1 mod p) but no `d mod (p-1)` or `d mod (q-1)`.
This library rebuilds the key from `p`, `q` and `e` and requires the
`n` it gets to be the file's; `d` and `iqmp` are not trusted, for the
reason `RsaPrivateKey::from_primes` gives.
*/

use crate::bignum::BigUint;
use crate::ec::eddsa;
use crate::kdf::bcrypt_pbkdf::bcrypt_pbkdf;
use crate::pem;
use crate::publickey_ciphers::dsa::{DsaParameters, DsaPrivateKey};
use crate::publickey_ciphers::rsa::RsaPrivateKey;
use crate::random;

use super::cipher::{self, Cipher};
use super::keys::{NistCurve, PublicKey};
use super::wire::{Reader, Writer};

const MAGIC: &[u8] = b"openssh-key-v1\0";
const LABEL: &str = "OPENSSH PRIVATE KEY";

/// A private key SSH can sign with.
#[derive(Clone)]
pub enum PrivateKey {
    /// The 32 byte seed RFC 8032 calls the private key, and the public
    /// key it makes.
    Ed25519 { seed: [u8; 32], public: [u8; 32] },
    Ecdsa { curve: NistCurve, scalar: BigUint, point: Vec<u8> },
    /// Boxed: an RSA key with its CRT values and Montgomery contexts is
    /// several times the size of the other two.
    Rsa(Box<RsaPrivateKey>),
    Dsa(Box<DsaPrivateKey>),
}

/// Names the key by its public half and never prints the secret, so a
/// key in an `unwrap_err` message or a log line gives nothing away.
impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let public = self.public();
        write!(f, "PrivateKey({} {})", public.algorithm(), public.fingerprint_sha256())
    }
}

impl PrivateKey {
    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519 { public, .. } => PublicKey::Ed25519(*public),
            PrivateKey::Ecdsa { curve, point, .. } =>
                PublicKey::Ecdsa { curve: *curve, point: point.clone() },
            PrivateKey::Rsa(key) => PublicKey::Rsa(key.public.clone()),
            PrivateKey::Dsa(key) => PublicKey::Dsa(key.public.clone()),
        }
    }

    /// An Ed25519 key from its 32 byte seed.
    pub fn ed25519(seed: [u8; 32]) -> Result<PrivateKey, String> {
        let public = eddsa::public_key(eddsa::Variant::Ed25519, &seed)?;
        let public: [u8; 32] = public.try_into()
            .map_err(|_| "Ed25519 public key length".to_string())?;
        Ok(PrivateKey::Ed25519 { seed, public })
    }

    /// A fresh key, named the way `ssh-keygen -t` names them (`ed25519`,
    /// `ecdsa`, `rsa`) or by key type (`ssh-ed25519`,
    /// `ecdsa-sha2-nistp384`, `ssh-rsa`). `bits` is the curve for
    /// `ecdsa` (256, 384 or 521; 256 if absent) and the modulus for RSA
    /// (3072 if absent, as `ssh-keygen` has it).
    pub fn generate(kind: &str, bits: Option<usize>) -> Result<PrivateKey, String> {
        match kind {
            "ed25519" | "ssh-ed25519" => {
                let mut seed = [0u8; 32];
                random::fill(&mut seed)?;
                PrivateKey::ed25519(seed)
            }
            // 1024 and 160 are the only sizes ssh-dss has: the signature
            // format is two 20 byte numbers and the hash is SHA-1.
            "dsa" | "ssh-dss" => Ok(PrivateKey::Dsa(Box::new(DsaPrivateKey::generate(
                DsaParameters::generate(1024, 160)?)?))),
            "rsa" | "ssh-rsa" => Ok(PrivateKey::Rsa(
                Box::new(RsaPrivateKey::generate(bits.unwrap_or(3072))?))),
            other => {
                let curve = match (other, bits) {
                    ("ecdsa", None | Some(256)) | ("ecdsa-sha2-nistp256", _) => NistCurve::P256,
                    ("ecdsa", Some(384)) | ("ecdsa-sha2-nistp384", _) => NistCurve::P384,
                    ("ecdsa", Some(521)) | ("ecdsa-sha2-nistp521", _) => NistCurve::P521,
                    ("ecdsa", Some(other)) => return Err(format!(
                        "SSH: ECDSA keys are 256, 384 or 521 bits, not {other}.")),
                    _ => return Err(format!(
                        "SSH: unknown key type {kind:?}. Known: ed25519, ecdsa, \
                         rsa, or a key type name.")),
                };
                let scalar = random::below(&curve.curve().n.sub(&BigUint::one())?)?.add(&BigUint::one());
                PrivateKey::ecdsa(curve, scalar)
            }
        }
    }

    /// An ECDSA key from its scalar.
    pub fn ecdsa(curve: NistCurve, scalar: BigUint) -> Result<PrivateKey, String> {
        let ec = curve.curve();
        if scalar.is_zero() || scalar >= ec.n {
            return Err(format!("SSH: an {} private key must be between 1 and \
                                n - 1.", curve.algorithm()));
        }
        // The ladder, not `generator_mul`: the scalar is the private key.
        let point = ec.encode_point(&ec.scalar_mul_ct(&ec.g, &scalar), false)?;
        Ok(PrivateKey::Ecdsa { curve, scalar, point })
    }
}

/// How to encrypt a key file: a cipher by SSH name, the passphrase, and
/// bcrypt_pbkdf's round count (OpenSSH's default is 16).
pub struct Encryption<'a> {
    pub cipher: &'a str,
    pub passphrase: &'a [u8],
    pub rounds: u32,
}

/// Read an `openssh-key-v1` file. `passphrase` is needed only for an
/// encrypted one; giving one for an unencrypted file is not an error.
///
/// Returns the key and its comment.
pub fn read(text: &str, passphrase: Option<&[u8]>) -> Result<(PrivateKey, String), String> {
    let blocks = pem::parse(text)?;
    let block = blocks.iter().find(|block| block.label == LABEL)
        .ok_or_else(|| format!("SSH: no {LABEL} block in this text."))?;
    let data = &block.contents;
    let body = data.strip_prefix(MAGIC)
        .ok_or_else(|| "SSH: this is not an openssh-key-v1 key.".to_string())?;
    let mut reader = Reader::new(body);
    let cipher_name = reader.text()?;
    let kdf_name = reader.text()?;
    let kdf_options = reader.string()?;
    let count = reader.uint32()?;
    if count != 1 {
        return Err(format!("SSH: this key file holds {count} keys; OpenSSH \
                            writes and reads exactly one."));
    }
    let public = PublicKey::from_blob(reader.string()?)?;
    let encrypted = reader.string()?;
    let spec = cipher::lookup(cipher_name)?;
    let tag = reader.rest();
    if tag.len() != spec.tag_len {
        return Err(format!("SSH: {} bytes follow the private section, and {} \
                            leaves {}.", tag.len(), cipher_name, spec.tag_len));
    }

    let (key, iv) = match (kdf_name, cipher_name) {
        ("none", "none") => (Vec::new(), Vec::new()),
        ("none", _) | (_, "none") => return Err(format!(
            "SSH: cipher {cipher_name:?} with KDF {kdf_name:?}: either both \
             are \"none\" or neither is.")),
        ("bcrypt", _) => {
            let mut options = Reader::new(kdf_options);
            let salt = options.string()?;
            let rounds = options.uint32()?;
            options.finish("bcrypt's KDF options")?;
            let passphrase = passphrase.ok_or_else(|| {
                "SSH: this key is encrypted and needs a passphrase.".to_string()
            })?;
            let mut material = bcrypt_pbkdf(passphrase, salt, rounds,
                                            spec.key_len + spec.kdf_iv_len())?;
            let mut iv = material.split_off(spec.key_len);
            iv.truncate(spec.iv_len);
            (material, iv)
        }
        (other, _) => return Err(format!("SSH: unknown key derivation {other:?}.")),
    };

    let mut sealed = Vec::with_capacity(encrypted.len() + tag.len());
    sealed.extend_from_slice(encrypted);
    sealed.extend_from_slice(tag);
    let section = Cipher::new(cipher_name, &key, &iv, false)?
        .crypt(0, &sealed, 0)
        .map_err(|_| "SSH: wrong passphrase, or the key file is damaged."
                 .to_string())?;

    let mut reader = Reader::new(&section);
    if reader.uint32()? != reader.uint32()? {
        return Err("SSH: wrong passphrase, or the key file is damaged.".to_string());
    }
    let private = read_private_fields(&mut reader)?;
    let comment = reader.text()?.to_string();
    for (expected, padding) in (1u8..).zip(reader.rest()) {
        if *padding != expected {
            return Err("SSH: the private section's padding is not 1, 2, 3, \
                        ...".to_string());
        }
    }
    if private.public() != public {
        return Err("SSH: the private key in this file is not the one its \
                    public key says.".to_string());
    }
    Ok((private, comment))
}

fn read_private_fields(reader: &mut Reader<'_>) -> Result<PrivateKey, String> {
    let name = reader.text()?;
    match name {
        "ssh-ed25519" => {
            let public = reader.string()?;
            let both = reader.string()?;
            if both.len() != 64 || public.len() != 32 || &both[32..] != public {
                return Err("SSH: an ssh-ed25519 private key is a 32 byte \
                            public key, then the seed and that public key \
                            again.".to_string());
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&both[..32]);
            let key = PrivateKey::ed25519(seed)?;
            match &key {
                PrivateKey::Ed25519 { public: derived, .. } if derived[..] == *public =>
                    Ok(key),
                _ => Err("SSH: the ssh-ed25519 seed does not make the public key \
                          stored beside it.".to_string()),
            }
        }
        "ssh-dss" => {
            let p = BigUint::from_bytes_be(reader.mpint()?);
            let q = BigUint::from_bytes_be(reader.mpint()?);
            let g = BigUint::from_bytes_be(reader.mpint()?);
            let y = BigUint::from_bytes_be(reader.mpint()?);
            let x = BigUint::from_bytes_be(reader.mpint()?);
            let key = DsaPrivateKey::from_x(DsaParameters::new(p, q, g)?, x)
                .map_err(|reason| format!("SSH: ssh-dss private key: {reason}"))?;
            if key.public.y != y {
                return Err("SSH: the ssh-dss private key does not make the public \
                            key stored beside it.".to_string());
            }
            Ok(PrivateKey::Dsa(Box::new(key)))
        }
        "ssh-rsa" => {
            let n = BigUint::from_bytes_be(reader.mpint()?);
            let e = BigUint::from_bytes_be(reader.mpint()?);
            let _d = reader.mpint()?;
            let _iqmp = reader.mpint()?;
            let p = BigUint::from_bytes_be(reader.mpint()?);
            let q = BigUint::from_bytes_be(reader.mpint()?);
            let key = RsaPrivateKey::from_primes(p, q, e)
                .map_err(|reason| format!("SSH: ssh-rsa private key: {reason}"))?;
            if key.public.n != n {
                return Err("SSH: the ssh-rsa primes do not multiply to the \
                            modulus.".to_string());
            }
            Ok(PrivateKey::Rsa(Box::new(key)))
        }
        other => {
            let curve = super::keys::KEY_TYPES.iter()
                .find(|known| **known == other)
                .and_then(|_| ["P-256", "P-384", "P-521"].into_iter()
                          .filter_map(NistCurve::from_name)
                          .find(|curve| curve.algorithm() == other))
                .ok_or_else(|| format!("SSH: unknown private key type {other:?}."))?;
            let identifier = reader.string()?;
            if identifier != curve.identifier().as_bytes() {
                return Err(format!("SSH: a {other} private key names its curve \
                                    {:?}.", String::from_utf8_lossy(identifier)));
            }
            let point = reader.string()?;
            let scalar = BigUint::from_bytes_be(reader.mpint()?);
            let key = PrivateKey::ecdsa(curve, scalar)?;
            match &key {
                PrivateKey::Ecdsa { point: derived, .. } if derived[..] == *point => Ok(key),
                _ => Err(format!("SSH: the {other} scalar does not make the \
                                  point stored beside it.")),
            }
        }
    }
}

fn write_private_fields(key: &PrivateKey, writer: &mut Writer) {
    match key {
        PrivateKey::Ed25519 { seed, public } => {
            writer.string(b"ssh-ed25519").string(public);
            let mut both = Vec::with_capacity(64);
            both.extend_from_slice(seed);
            both.extend_from_slice(public);
            writer.string(&both);
        }
        PrivateKey::Ecdsa { curve, scalar, point } => {
            writer.string(curve.algorithm().as_bytes())
                .string(curve.identifier().as_bytes())
                .string(point)
                .mpint(&scalar.to_bytes_be());
        }
        PrivateKey::Dsa(key) => {
            let DsaParameters { p, q, g } = &key.public.parameters;
            writer.string(b"ssh-dss")
                .mpint(&p.to_bytes_be()).mpint(&q.to_bytes_be()).mpint(&g.to_bytes_be())
                .mpint(&key.public.y.to_bytes_be()).mpint(&key.x().to_bytes_be());
        }
        PrivateKey::Rsa(key) => {
            let (p, q) = key.primes();
            let (_, _, qinv) = key.crt_parameters();
            writer.string(b"ssh-rsa")
                .mpint(&key.public.n.to_bytes_be())
                .mpint(&key.public.e.to_bytes_be())
                .mpint(&key.private_exponent().to_bytes_be())
                .mpint(&qinv.to_bytes_be())
                .mpint(&p.to_bytes_be())
                .mpint(&q.to_bytes_be());
        }
    }
}

/// Write an `openssh-key-v1` file, as `ssh-keygen` does: 70 columns of
/// base64 and a 16 byte salt.
pub fn write(key: &PrivateKey, comment: &str, encryption: Option<&Encryption<'_>>)
             -> Result<String, String> {
    let (cipher_name, kdf_name) = match encryption {
        None => ("none", "none"),
        Some(encryption) => (encryption.cipher, "bcrypt"),
    };
    let spec = cipher::lookup(cipher_name)?;
    if encryption.is_some() && cipher_name == "none" {
        return Err("SSH: encrypting with the \"none\" cipher is not \
                    encrypting.".to_string());
    }

    let mut check = [0u8; 4];
    random::fill(&mut check)?;
    let check = u32::from_be_bytes(check);
    let mut section = Writer::new();
    section.uint32(check).uint32(check);
    write_private_fields(key, &mut section);
    section.string(comment.as_bytes());
    let mut padding = 1u8;
    while !section.len().is_multiple_of(spec.block_size) {
        section.byte(padding);
        padding += 1;
    }
    let section = section.finish();

    let mut kdf_options = Writer::new();
    let (cipher_key, iv) = match encryption {
        None => (Vec::new(), Vec::new()),
        Some(encryption) => {
            let salt = random::bytes(16)?;
            kdf_options.string(&salt).uint32(encryption.rounds);
            let mut material = bcrypt_pbkdf(encryption.passphrase, &salt,
                                            encryption.rounds,
                                            spec.key_len + spec.kdf_iv_len())?;
            let mut iv = material.split_off(spec.key_len);
            iv.truncate(spec.iv_len);
            (material, iv)
        }
    };
    let mut sealed = Cipher::new(cipher_name, &cipher_key, &iv, true)?
        .crypt(0, &section, 0)?;
    let tag = sealed.split_off(section.len());

    let mut out = Writer::new();
    out.raw(MAGIC)
        .string(cipher_name.as_bytes())
        .string(kdf_name.as_bytes())
        .string(&kdf_options.finish())
        .uint32(1)
        .string(&key.public().to_blob())
        .string(&sealed)
        .raw(&tag);
    let encoded = pem::encode(&out.finish());
    let mut text = format!("-----BEGIN {LABEL}-----\n");
    for line in encoded.as_bytes().chunks(70) {
        text.push_str(core::str::from_utf8(line).map_err(|_| "base64".to_string())?);
        text.push('\n');
    }
    text.push_str(&format!("-----END {LABEL}-----\n"));
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_key() -> PrivateKey {
        PrivateKey::ed25519([42; 32]).unwrap()
    }

    #[test]
    fn test_a_written_key_reads_back_plain_and_encrypted() {
        let key = a_key();
        let plain = write(&key, "me@here", None).unwrap();
        let (read_back, comment) = read(&plain, None).unwrap();
        assert_eq!(comment, "me@here");
        assert_eq!(read_back.public(), key.public());

        for name in ["aes256-ctr", "aes256-gcm@openssh.com",
                     "chacha20-poly1305@openssh.com", "3des-cbc"] {
            let encryption = Encryption { cipher: name, passphrase: b"pw", rounds: 1 };
            let text = write(&key, "", Some(&encryption)).unwrap();
            let (read_back, _) = read(&text, Some(b"pw")).unwrap();
            assert_eq!(read_back.public(), key.public(), "{name}");
            assert!(read(&text, Some(b"wrong")).unwrap_err()
                    .contains("wrong passphrase"), "{name}");
            assert!(read(&text, None).unwrap_err().contains("needs a passphrase"));
        }
    }

    /// A file whose private section is a different key from its header.
    #[test]
    fn test_a_private_key_that_is_not_the_public_one_is_refused() {
        let text = write(&a_key(), "", None).unwrap();
        let other = PrivateKey::ed25519([7; 32]).unwrap().public().to_blob();
        let block = &pem::parse(&text).unwrap()[0].contents;
        let ours = a_key().public().to_blob();
        let at = block.windows(ours.len()).position(|w| w == ours.as_slice()).unwrap();
        let mut swapped = block.clone();
        swapped[at..at + ours.len()].copy_from_slice(&other);
        let error = read(&pem::wrap(LABEL, &swapped), None).unwrap_err();
        assert!(error.contains("not the one its public key says"), "{error}");
    }
}
