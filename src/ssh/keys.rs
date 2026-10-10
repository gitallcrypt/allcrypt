/*
SSH public keys: the wire blob, the `authorized_keys` / `.pub` line, and
fingerprints.

RFC 4253 section 6.6 defines the blob for `ssh-rsa` (and `ssh-dss`),
RFC 5656 section 3.1 for `ecdsa-sha2-*`, and RFC 8709 section 4 for
`ssh-ed25519`. Each is a `string` naming the key type followed by the
key's numbers in SSH wire encoding (`ssh::wire`). The blob is what goes
on the wire in a key exchange or a `publickey` authentication request,
what is hashed into a fingerprint, and - base64 encoded - the middle
field of a line in `authorized_keys` or `id_ed25519.pub`.

# Pitfalls

**`ssh-rsa` puts `e` before `n`.** Every other format in this library
(PKCS#1, X.509, JWK) leads with the modulus. A blob written the other
way round parses: both are mpints, and `e = n` is not obviously
nonsense until something tries to use it.

**An ECDSA blob names its curve twice**, once in the key type
(`ecdsa-sha2-nistp256`) and once as a separate string (`nistp256`).
RFC 5656 does not say what to do when they disagree; this library
refuses, because a key whose two names disagree has no single meaning.

**The type name on an `authorized_keys` line is a claim.** The blob
inside the base64 names its own type, and that is the one that counts;
OpenSSH refuses a line whose two names differ, and so does this.

**A fingerprint is of the blob, not of the line**, and the SHA-256 form
is unpadded base64 while the MD5 form is colon-separated lowercase hex.
Both are what `ssh-keygen -l` prints and both are checked against it.
*/

use crate::bignum::BigUint;
use crate::ec::{curves, Curve};
use crate::ec::eddsa;
use crate::hash_functions::{md5::MD5, sha2::SHA256, HashFunction};
use crate::pem;
use crate::publickey_ciphers::dsa::{DsaParameters, DsaPublicKey};
use crate::publickey_ciphers::rsa::RsaPublicKey;

use super::wire::{Reader, Writer};

/// The NIST curves SSH names, RFC 5656 section 10.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NistCurve {
    P256,
    P384,
    P521,
}

impl NistCurve {
    /// The curve identifier RFC 5656 puts inside the blob.
    pub fn identifier(self) -> &'static str {
        match self {
            NistCurve::P256 => "nistp256",
            NistCurve::P384 => "nistp384",
            NistCurve::P521 => "nistp521",
        }
    }

    /// The key type, which is also the signature algorithm's name.
    pub fn algorithm(self) -> &'static str {
        match self {
            NistCurve::P256 => "ecdsa-sha2-nistp256",
            NistCurve::P384 => "ecdsa-sha2-nistp384",
            NistCurve::P521 => "ecdsa-sha2-nistp521",
        }
    }

    pub fn curve(self) -> Curve {
        match self {
            NistCurve::P256 => curves::p256(),
            NistCurve::P384 => curves::p384(),
            NistCurve::P521 => curves::p521(),
        }
    }

    /// The hash RFC 5656 section 6.2.1 pairs with the curve - by size,
    /// so SHA-512 for P-521 rather than a 521 bit hash.
    pub fn hash_name(self) -> &'static str {
        match self {
            NistCurve::P256 => "sha256",
            NistCurve::P384 => "sha384",
            NistCurve::P521 => "sha512",
        }
    }

    pub fn bits(self) -> usize {
        match self {
            NistCurve::P256 => 256,
            NistCurve::P384 => 384,
            NistCurve::P521 => 521,
        }
    }

    fn from_identifier(identifier: &[u8]) -> Option<NistCurve> {
        [NistCurve::P256, NistCurve::P384, NistCurve::P521].into_iter()
            .find(|curve| curve.identifier().as_bytes() == identifier)
    }

    fn from_algorithm(name: &str) -> Option<NistCurve> {
        [NistCurve::P256, NistCurve::P384, NistCurve::P521].into_iter()
            .find(|curve| curve.algorithm() == name)
    }

    /// This library's name for the curve, as `ec::curves` spells it.
    pub fn name(self) -> &'static str {
        match self {
            NistCurve::P256 => "P-256",
            NistCurve::P384 => "P-384",
            NistCurve::P521 => "P-521",
        }
    }

    /// From this library's curve name.
    pub fn from_name(name: &str) -> Option<NistCurve> {
        [NistCurve::P256, NistCurve::P384, NistCurve::P521].into_iter()
            .find(|curve| curve.name() == name)
    }
}

/// An SSH public key, validated: an RSA modulus and exponent that
/// `RsaPublicKey::new` accepts, an EC point on its curve, an Ed25519
/// point that decodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    /// `point` is SEC1 uncompressed, as RFC 5656 requires on the wire.
    Ecdsa { curve: NistCurve, point: Vec<u8> },
    Ed25519([u8; 32]),
    /// `ssh-dss` (RFC 4253 6.6): DSA with a 160 bit `q` and SHA-1.
    /// Removed from OpenSSH in 10.0 and still what old devices have.
    Dsa(DsaPublicKey),
}

/// The key types this module reads, in the order `ssh-keygen` lists them.
pub const KEY_TYPES: &[&str] = &[
    "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521", "ssh-rsa", "ssh-dss",
];

impl PublicKey {
    /// The key type: the first string in the blob.
    pub fn algorithm(&self) -> &'static str {
        match self {
            PublicKey::Rsa(_) => "ssh-rsa",
            PublicKey::Ecdsa { curve, .. } => curve.algorithm(),
            PublicKey::Ed25519(_) => "ssh-ed25519",
            PublicKey::Dsa(_) => "ssh-dss",
        }
    }

    /// The size `ssh-keygen -l` reports: the modulus for RSA, the
    /// curve for ECDSA, 256 for Ed25519.
    pub fn bits(&self) -> usize {
        match self {
            PublicKey::Rsa(key) => key.bits(),
            PublicKey::Ecdsa { curve, .. } => curve.bits(),
            PublicKey::Ed25519(_) => 256,
            PublicKey::Dsa(key) => key.parameters.p.bit_len(),
        }
    }

    /// The largest RSA modulus or DSA `p` a blob may carry: 16384 bits,
    /// OpenSSH's own `SSH_RSA_MAXIMUM_MODULUS_SIZE`.
    ///
    /// A host key arrives before anything is authenticated, and a user
    /// key arrives from anyone who can open a connection; the signature
    /// check that follows is a modular exponentiation with the peer's
    /// own `e` and `n`, so a multi-million-bit modulus is a CPU denial
    /// of service unless its size is refused first.
    pub const MAX_KEY_BITS: usize = 16384;

    /// Read a blob. The whole of it: trailing bytes are an error.
    pub fn from_blob(blob: &[u8]) -> Result<PublicKey, String> {
        let mut reader = Reader::new(blob);
        let name = reader.text()?;
        let key = match name {
            "ssh-rsa" => {
                // e first, then n - RFC 4253 6.6.
                let e = BigUint::from_bytes_be(reader.mpint()?);
                let n = BigUint::from_bytes_be(reader.mpint()?);
                if n.bit_len() > PublicKey::MAX_KEY_BITS {
                    return Err(format!("SSH: an ssh-rsa key of {} bits is larger \
                                        than the {} bit limit.",
                                       n.bit_len(), PublicKey::MAX_KEY_BITS));
                }
                PublicKey::Rsa(RsaPublicKey::new(n, e)
                    .map_err(|reason| format!("SSH: ssh-rsa key: {reason}"))?)
            }
            "ssh-dss" => {
                let p = BigUint::from_bytes_be(reader.mpint()?);
                let q = BigUint::from_bytes_be(reader.mpint()?);
                let g = BigUint::from_bytes_be(reader.mpint()?);
                let y = BigUint::from_bytes_be(reader.mpint()?);
                // Before `DsaParameters::new`, which exponentiates over p.
                if p.bit_len() > PublicKey::MAX_KEY_BITS {
                    return Err(format!("SSH: an ssh-dss key's p of {} bits is \
                                        larger than the {} bit limit.",
                                       p.bit_len(), PublicKey::MAX_KEY_BITS));
                }
                if q.bit_len() > 160 {
                    return Err(format!("SSH: an ssh-dss key's q is {} bits; the \
                                        format has room for 160.", q.bit_len()));
                }
                let parameters = DsaParameters::new(p, q, g)
                    .map_err(|reason| format!("SSH: ssh-dss key: {reason}"))?;
                PublicKey::Dsa(DsaPublicKey::new(parameters, y)
                    .map_err(|reason| format!("SSH: ssh-dss key: {reason}"))?)
            }
            "ssh-ed25519" => {
                let bytes = reader.string()?;
                let key: [u8; 32] = bytes.try_into().map_err(|_| format!(
                    "SSH: an ssh-ed25519 key is {} bytes and should be 32.",
                    bytes.len()))?;
                if !eddsa::is_public_key(eddsa::Variant::Ed25519, &key) {
                    return Err("SSH: the ssh-ed25519 key is not a point on \
                                the curve.".to_string());
                }
                PublicKey::Ed25519(key)
            }
            other => match NistCurve::from_algorithm(other) {
                Some(curve) => {
                    let identifier = reader.string()?;
                    if NistCurve::from_identifier(identifier) != Some(curve) {
                        return Err(format!(
                            "SSH: a {other} key names its curve {:?}.",
                            String::from_utf8_lossy(identifier)));
                    }
                    let point = reader.string()?;
                    let ec = curve.curve();
                    if point.first() != Some(&4) {
                        return Err(format!("SSH: a {other} key must be an \
                                            uncompressed point."));
                    }
                    let decoded = ec.decode_point(point)
                        .map_err(|reason| format!("SSH: {other} key: {reason}"))?;
                    ec.validate(&decoded)
                        .map_err(|reason| format!("SSH: {other} key: {reason}"))?;
                    PublicKey::Ecdsa { curve, point: point.to_vec() }
                }
                None => return Err(format!(
                    "SSH: unknown key type {other:?}. Known: {}.",
                    KEY_TYPES.join(", "))),
            },
        };
        reader.finish("an SSH public key")?;
        Ok(key)
    }

    /// The blob, as it goes on the wire and into a fingerprint.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.string(self.algorithm().as_bytes());
        match self {
            PublicKey::Rsa(key) => {
                writer.mpint(&key.e.to_bytes_be());
                writer.mpint(&key.n.to_bytes_be());
            }
            PublicKey::Ecdsa { curve, point } => {
                writer.string(curve.identifier().as_bytes());
                writer.string(point);
            }
            PublicKey::Ed25519(key) => {
                writer.string(key);
            }
            PublicKey::Dsa(key) => {
                let DsaParameters { p, q, g } = &key.parameters;
                writer.mpint(&p.to_bytes_be()).mpint(&q.to_bytes_be())
                    .mpint(&g.to_bytes_be()).mpint(&key.y.to_bytes_be());
            }
        }
        writer.finish()
    }

    /// `SHA256:` and unpadded base64, which is what `ssh-keygen -l` has
    /// printed by default since OpenSSH 6.8.
    pub fn fingerprint_sha256(&self) -> String {
        let digest = SHA256::new(&self.to_blob()).digest();
        format!("SHA256:{}", pem::encode(&digest).trim_end_matches('='))
    }

    /// `MD5:` and colon-separated hex, what `ssh-keygen -l -E md5` prints
    /// and what every SSH client printed before 6.8 - so what an old
    /// device's documentation, or a known_hosts note written years ago,
    /// will have.
    pub fn fingerprint_md5(&self) -> String {
        let digest = MD5::new(&self.to_blob()).digest();
        let pairs: Vec<String> = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!("MD5:{}", pairs.join(":"))
    }

    /// The `type base64 comment` line of a `.pub` file or `authorized_keys`.
    pub fn to_openssh(&self, comment: &str) -> String {
        let mut line = format!("{} {}", self.algorithm(), pem::encode(&self.to_blob()));
        if !comment.is_empty() {
            line.push(' ');
            line.push_str(comment);
        }
        line
    }
}

/// One line of an `authorized_keys` or `.pub` file, read.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyLine<'a> {
    /// The options field of an `authorized_keys` line (`from="..."`,
    /// `no-pty`, ...), as written, or empty. Not interpreted: they are
    /// policy for whoever holds the file.
    pub options: &'a str,
    pub key: PublicKey,
    pub comment: &'a str,
}

/// Read one line. Leading options are recognised the way OpenSSH
/// recognises them: if the line does not start with a key type, the
/// options field runs to the first space outside double quotes.
pub fn parse_line(line: &str) -> Result<KeyLine<'_>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err("SSH: an empty line or a comment carries no key.".to_string());
    }
    let (options, rest) = if KEY_TYPES.iter().any(|name| starts_with_word(line, name)) {
        ("", line)
    } else {
        let end = options_end(line)?;
        (&line[..end], line[end..].trim_start())
    };
    let mut fields = rest.splitn(3, [' ', '\t']);
    let name = fields.next().unwrap_or("");
    let encoded = fields.next()
        .ok_or_else(|| "SSH: a key line needs a type and a base64 blob."
                    .to_string())?;
    let comment = fields.next().unwrap_or("").trim();
    let blob = pem::decode(encoded)
        .map_err(|_| "SSH: the key's base64 does not decode.".to_string())?;
    let key = PublicKey::from_blob(&blob)?;
    if key.algorithm() != name {
        return Err(format!("SSH: the line says {name:?} and the key inside \
                            it is {:?}.", key.algorithm()));
    }
    Ok(KeyLine { options, key, comment })
}

fn starts_with_word(line: &str, word: &str) -> bool {
    line.strip_prefix(word)
        .is_some_and(|rest| rest.starts_with([' ', '\t']))
}

/// Where an options field ends: the first unquoted space or tab.
fn options_end(line: &str) -> Result<usize, String> {
    let mut quoted = false;
    let mut escaped = false;
    for (at, character) in line.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => return Ok(at),
            _ => {}
        }
    }
    Err("SSH: a key line with options needs a key after them.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_blob_round_trips_and_trailing_bytes_are_refused() {
        let key = PublicKey::Ed25519(eddsa::public_key(
            eddsa::Variant::Ed25519, &[7; 32]).unwrap().try_into().unwrap());
        let blob = key.to_blob();
        assert_eq!(PublicKey::from_blob(&blob).unwrap(), key);
        let mut longer = blob.clone();
        longer.push(0);
        assert!(PublicKey::from_blob(&longer).is_err());
        assert!(PublicKey::from_blob(&blob[..blob.len() - 1]).is_err());
    }

    /// A blob carrying a modulus above `PublicKey::MAX_KEY_BITS` is
    /// refused before the key is built.
    ///
    /// What was wrong: `from_blob` handed `n` and `e` straight to
    /// `RsaPublicKey::new`, which checks parity and `e < n` and nothing
    /// about size, and the host-key or user-key signature check that
    /// followed was a modular exponentiation with the peer's own
    /// numbers - a CPU denial of service from anyone who can open a
    /// connection, before authentication. The recorded sessions carry
    /// real OpenSSH keys, so none of them could reach the case.
    #[test]
    fn test_an_oversized_modulus_is_refused() {
        let modulus = |bits: usize| {
            let mut bytes = vec![0u8; bits.div_ceil(8)];
            bytes[0] = 1 << ((bits - 1) % 8);
            *bytes.last_mut().unwrap() |= 1;
            bytes
        };
        let blob = |bits: usize| {
            let mut writer = Writer::new();
            writer.string(b"ssh-rsa").mpint(&[1, 0, 1]).mpint(&modulus(bits));
            writer.finish()
        };
        let error = PublicKey::from_blob(&blob(PublicKey::MAX_KEY_BITS + 1)).unwrap_err();
        assert!(error.contains("limit"), "{}", error);
        // Exactly the limit is a key.
        assert_eq!(PublicKey::from_blob(&blob(PublicKey::MAX_KEY_BITS)).unwrap().bits(),
                   PublicKey::MAX_KEY_BITS);

        // ssh-dss: p is capped before `DsaParameters::new` exponentiates
        // over it, so the refusal names the limit and not the group.
        let mut writer = Writer::new();
        writer.string(b"ssh-dss").mpint(&modulus(PublicKey::MAX_KEY_BITS + 1))
            .mpint(&[3]).mpint(&[2]).mpint(&[2]);
        let error = PublicKey::from_blob(&writer.finish()).unwrap_err();
        assert!(error.contains("limit"), "{}", error);
    }

    /// `e` before `n`: a blob written the other way round must not
    /// read as the same key.
    #[test]
    fn test_ssh_rsa_puts_the_exponent_first() {
        let n = BigUint::from_hex("c5a3").unwrap();
        let key = PublicKey::Rsa(RsaPublicKey::new(n, BigUint::from_u64(3)).unwrap());
        let blob = key.to_blob();
        // string "ssh-rsa", then mpint 3, then mpint 0x00c5a3.
        assert_eq!(&blob[11..20], [0, 0, 0, 1, 3, 0, 0, 0, 3]);
        assert_eq!(&blob[20..], [0, 0xc5, 0xa3]);
    }

    #[test]
    fn test_an_ecdsa_key_whose_two_curve_names_differ_is_refused() {
        let curve = NistCurve::P256.curve();
        let point = curve.encode_point(&curve.g, false).unwrap();
        let mut writer = Writer::new();
        writer.string(b"ecdsa-sha2-nistp256").string(b"nistp384").string(&point);
        let error = PublicKey::from_blob(&writer.finish()).unwrap_err();
        assert!(error.contains("nistp384"), "{error}");

        // And a point that is not on the curve.
        let mut bad = point.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let mut writer = Writer::new();
        writer.string(b"ecdsa-sha2-nistp256").string(b"nistp256").string(&bad);
        assert!(PublicKey::from_blob(&writer.finish()).is_err());
    }

    #[test]
    fn test_line_options_and_a_mismatched_type_name() {
        let key = PublicKey::Ed25519(eddsa::public_key(
            eddsa::Variant::Ed25519, &[9; 32]).unwrap().try_into().unwrap());
        let line = key.to_openssh("someone@somewhere");
        let read = parse_line(&line).unwrap();
        assert_eq!((read.options, read.comment), ("", "someone@somewhere"));
        assert_eq!(read.key, key);

        let with_options = format!(r#"from="10.0.0.1, 10.0.0.2",command="echo \"hi there\"",no-pty {line}"#);
        let read = parse_line(&with_options).unwrap();
        assert_eq!(read.options,
                   r#"from="10.0.0.1, 10.0.0.2",command="echo \"hi there\"",no-pty"#);
        assert_eq!(read.key, key);

        let lying = line.replacen("ssh-ed25519", "ssh-rsa", 1);
        assert!(parse_line(&lying).unwrap_err().contains("ssh-ed25519"));
    }
}
