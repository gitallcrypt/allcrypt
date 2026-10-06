/*
SSH signatures: the signature blob every SSH signature travels in, and
SSHSIG, the detached file signature `ssh-keygen -Y sign` makes.

A signature blob is `string algorithm, string signature-bytes`
(RFC 4253 section 6.6), and what the bytes are depends on the algorithm:

| algorithm | hash | bytes |
|---|---|---|
| `ssh-ed25519` (RFC 8709) | none, Ed25519 hashes itself | the 64 byte signature |
| `ecdsa-sha2-nistp256/384/521` (RFC 5656 3.1.2) | SHA-256/384/512 | `mpint r, mpint s` |
| `ssh-rsa` (RFC 4253) | SHA-1 | PKCS#1 v1.5, the modulus's length |
| `rsa-sha2-256`, `rsa-sha2-512` (RFC 8332) | SHA-256, SHA-512 | the same, with that hash |
| `ssh-dss` (RFC 4253) | SHA-1 | `r` and `s`, 20 bytes each |

# Pitfalls

**The RSA algorithm name is not the key type.** An `ssh-rsa` key signs
as `ssh-rsa` (SHA-1), `rsa-sha2-256` or `rsa-sha2-512`, and the key's
blob says `ssh-rsa` in every case. OpenSSH 8.8 stopped accepting the
SHA-1 one by default; old servers know nothing else. Both are here, and
the caller picks - the name inside the signature is what is verified
against, and it must be one the key's type allows.

**An RSA signature may arrive short.** PKCS#1 says the signature is the
modulus's length; some old implementations strip leading zero bytes,
and OpenSSH pads them back before verifying. So does this.

**ECDSA's `r` and `s` are mpints inside a string**, not the fixed-width
`r || s` of TLS 1.3 or JWS, and not DER.

**SSHSIG signs a hash of the message wrapped in a namespace**, not the
message: `"SSHSIG" || string namespace || string reserved || string
hash-name || string H(message)`. The namespace (`"file"`, `"git"`,
`"email"`) is what stops a signature made for one purpose from being
presented for another, and a verifier that does not insist on the one
it expects has thrown that away.
*/

use crate::api::AnyHash;
use crate::bignum::BigUint;
use crate::ec::ecdsa::Signature as EcdsaSignature;
use crate::ec::eddsa;
use crate::hash_functions::HashFunction;
use crate::pem;
use crate::publickey_ciphers::rsa;

use super::keys::{NistCurve, PublicKey};
use super::private_key::PrivateKey;
use super::wire::{Reader, Writer};

fn digest(hash_name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut hash = AnyHash::new(hash_name)?;
    hash.update(data);
    Ok(hash.digest())
}

/// The RSA signature algorithms and their hashes, RFC 8332 section 3.
const RSA_ALGORITHMS: [(&str, &str); 3] =
    [("rsa-sha2-512", "sha512"), ("rsa-sha2-256", "sha256"), ("ssh-rsa", "sha1")];

/// The algorithm names a key can sign under.
pub fn algorithms_for(key: &PublicKey) -> Vec<&'static str> {
    match key {
        PublicKey::Rsa(_) => RSA_ALGORITHMS.iter().map(|(name, _)| *name).collect(),
        other => vec![other.algorithm()],
    }
}

/// Sign `data` and return the signature blob. `algorithm` matters only
/// for RSA, where it picks the hash; `None` there means `rsa-sha2-512`.
pub fn sign(key: &PrivateKey, data: &[u8], algorithm: Option<&str>)
            -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    match key {
        PrivateKey::Ed25519 { seed, .. } => {
            check_algorithm(algorithm, "ssh-ed25519")?;
            let signature = eddsa::sign(eddsa::Variant::Ed25519, seed, data, &[])?;
            writer.string(b"ssh-ed25519").string(&signature);
        }
        PrivateKey::Ecdsa { curve, scalar, .. } => {
            check_algorithm(algorithm, curve.algorithm())?;
            let ec = curve.curve();
            let hashed = digest(curve.hash_name(), data)?;
            let signature = ec.sign(scalar, &hashed, AnyHash::new(curve.hash_name())?)?;
            let mut inner = Writer::new();
            inner.mpint(&signature.r.to_bytes_be()).mpint(&signature.s.to_bytes_be());
            writer.string(curve.algorithm().as_bytes()).string(&inner.finish());
        }
        PrivateKey::Dsa(dsa_key) => {
            check_algorithm(algorithm, "ssh-dss")?;
            let (r, s) = dsa_key.sign(&digest("sha1", data)?, AnyHash::new("sha1")?)?;
            // RFC 4253 6.6: r and s as 20 bytes each, not mpints.
            let mut bytes = r.to_bytes_be_padded(20)?;
            bytes.extend_from_slice(&s.to_bytes_be_padded(20)?);
            writer.string(b"ssh-dss").string(&bytes);
        }
        PrivateKey::Rsa(rsa_key) => {
            let name = algorithm.unwrap_or("rsa-sha2-512");
            let hash_name = rsa_hash(name)?;
            let signature = rsa::sign_pkcs1v15(rsa_key, hash_name,
                                               &digest(hash_name, data)?)?;
            writer.string(name.as_bytes()).string(&signature);
        }
    }
    Ok(writer.finish())
}

fn check_algorithm(asked: Option<&str>, only: &str) -> Result<(), String> {
    match asked {
        Some(name) if name != only => Err(format!(
            "SSH: this key signs as {only}, not {name}.")),
        _ => Ok(()),
    }
}

fn rsa_hash(name: &str) -> Result<&'static str, String> {
    RSA_ALGORITHMS.iter().find(|(known, _)| *known == name)
        .map(|(_, hash)| *hash)
        .ok_or_else(|| format!("SSH: an ssh-rsa key cannot sign as {name:?}."))
}

/// Verify a signature blob over `data` with `key`. `Ok(false)` is a
/// signature that does not verify; `Err` is one that cannot be read, or
/// names an algorithm this key does not sign with.
///
/// Returns the algorithm name it verified under, for a caller that has a
/// policy about SHA-1.
pub fn verify(key: &PublicKey, data: &[u8], blob: &[u8])
              -> Result<Option<&'static str>, String> {
    let mut reader = Reader::new(blob);
    let name = reader.text()?;
    let bytes = reader.string()?;
    reader.finish("an SSH signature")?;
    let algorithm = algorithms_for(key).into_iter().find(|known| *known == name)
        .ok_or_else(|| format!("SSH: a {} key does not sign as {name:?}.",
                               key.algorithm()))?;
    let good = match key {
        PublicKey::Ed25519(public) =>
            eddsa::verify(eddsa::Variant::Ed25519, public, data, bytes, &[]).is_ok(),
        PublicKey::Ecdsa { curve, point } => verify_ecdsa(*curve, point, data, bytes)?,
        PublicKey::Dsa(public) => {
            if bytes.len() != 40 {
                return Err(format!("SSH: an ssh-dss signature is 40 bytes, not {}.",
                                   bytes.len()));
            }
            let r = BigUint::from_bytes_be(&bytes[..20]);
            let s = BigUint::from_bytes_be(&bytes[20..]);
            public.verify(&digest("sha1", data)?, &r, &s)?
        }
        PublicKey::Rsa(public) => {
            let hash_name = rsa_hash(algorithm)?;
            let size = public.size();
            if bytes.len() > size {
                return Ok(None);
            }
            let mut padded = vec![0u8; size - bytes.len()];
            padded.extend_from_slice(bytes);
            rsa::verify_pkcs1v15(public, hash_name, &digest(hash_name, data)?, &padded)?
        }
    };
    Ok(good.then_some(algorithm))
}

fn verify_ecdsa(curve: NistCurve, point: &[u8], data: &[u8], bytes: &[u8])
                -> Result<bool, String> {
    let mut inner = Reader::new(bytes);
    let r = BigUint::from_bytes_be(inner.mpint()?);
    let s = BigUint::from_bytes_be(inner.mpint()?);
    inner.finish("an ECDSA signature's r and s")?;
    let ec = curve.curve();
    let public = ec.decode_point(point)?;
    ec.verify(&public, &digest(curve.hash_name(), data)?, &EcdsaSignature { r, s })
}

// ------------------------------------------------------------------ SSHSIG ---

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const SSHSIG_LABEL: &str = "SSH SIGNATURE";

/// What SSHSIG actually signs.
fn sshsig_signed_data(namespace: &str, hash_name: &str, message: &[u8])
                      -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    writer.raw(SSHSIG_MAGIC)
        .string(namespace.as_bytes())
        .string(b"")
        .string(hash_name.as_bytes())
        .string(&digest(hash_name, message)?);
    Ok(writer.finish())
}

/// `ssh-keygen -Y sign`: an armoured SSHSIG over `message`. `hash_name` is
/// `"sha512"` (the default) or `"sha256"`.
pub fn sshsig_sign(key: &PrivateKey, namespace: &str, message: &[u8],
                   hash_name: &str) -> Result<String, String> {
    if hash_name != "sha512" && hash_name != "sha256" {
        return Err(format!("SSHSIG hashes with sha256 or sha512, not {hash_name:?}."));
    }
    if namespace.is_empty() {
        return Err("SSHSIG needs a namespace; an empty one is refused by \
                    every verifier.".to_string());
    }
    let signed = sshsig_signed_data(namespace, hash_name, message)?;
    // An RSA key signs with the RSA algorithm of the same hash - which is
    // what ssh-keygen does, and what the byte-for-byte test against its
    // output found: the first version used rsa-sha2-512 throughout and
    // matched OpenSSH on every sha512 row and no sha256 one.
    let algorithm = match key {
        PrivateKey::Rsa(_) if hash_name == "sha256" => Some("rsa-sha2-256"),
        _ => None,
    };
    let signature = sign(key, &signed, algorithm)?;
    let mut writer = Writer::new();
    writer.raw(SSHSIG_MAGIC)
        .uint32(1)
        .string(&key.public().to_blob())
        .string(namespace.as_bytes())
        .string(b"")
        .string(hash_name.as_bytes())
        .string(&signature);
    let encoded = pem::encode(&writer.finish());
    let mut text = format!("-----BEGIN {SSHSIG_LABEL}-----\n");
    for line in encoded.as_bytes().chunks(70) {
        text.push_str(core::str::from_utf8(line).map_err(|_| "base64".to_string())?);
        text.push('\n');
    }
    text.push_str(&format!("-----END {SSHSIG_LABEL}-----\n"));
    Ok(text)
}

/// The key an SSHSIG names, without checking the signature: what
/// `ssh-keygen -Y find-principals` looks up in an allowed signers file
/// before anything is verified.
pub fn sshsig_public_key(armoured: &str) -> Result<PublicKey, String> {
    let blocks = pem::parse(armoured)?;
    let block = blocks.iter().find(|block| block.label == SSHSIG_LABEL)
        .ok_or_else(|| format!("SSHSIG: no {SSHSIG_LABEL} block."))?;
    let body = block.contents.strip_prefix(SSHSIG_MAGIC)
        .ok_or_else(|| "SSHSIG: not an SSHSIG signature.".to_string())?;
    let mut reader = Reader::new(body);
    let version = reader.uint32()?;
    if version != 1 {
        return Err(format!("SSHSIG: version {version}, and only 1 exists."));
    }
    PublicKey::from_blob(reader.string()?)
}

/// `ssh-keygen -Y verify`, short of the allowed-signers file: checks the
/// signature over `message` under `namespace`, and returns the key that
/// made it - which the caller must then decide whether to trust.
pub fn sshsig_verify(armoured: &str, namespace: &str, message: &[u8])
                     -> Result<PublicKey, String> {
    let blocks = pem::parse(armoured)?;
    let block = blocks.iter().find(|block| block.label == SSHSIG_LABEL)
        .ok_or_else(|| format!("SSHSIG: no {SSHSIG_LABEL} block."))?;
    let body = block.contents.strip_prefix(SSHSIG_MAGIC)
        .ok_or_else(|| "SSHSIG: not an SSHSIG signature.".to_string())?;
    let mut reader = Reader::new(body);
    let version = reader.uint32()?;
    if version != 1 {
        return Err(format!("SSHSIG: version {version}, and only 1 exists."));
    }
    let key = PublicKey::from_blob(reader.string()?)?;
    let signed_namespace = reader.text()?;
    let _reserved = reader.string()?;
    let hash_name = reader.text()?;
    let signature = reader.string()?;
    reader.finish("an SSHSIG signature")?;
    if signed_namespace != namespace {
        return Err(format!("SSHSIG: signed for namespace {signed_namespace:?}, \
                            not {namespace:?}."));
    }
    if hash_name != "sha512" && hash_name != "sha256" {
        return Err(format!("SSHSIG: unknown hash {hash_name:?}."));
    }
    let signed = sshsig_signed_data(namespace, hash_name, message)?;
    match verify(&key, &signed, signature)? {
        Some(_) => Ok(key),
        None => Err("SSHSIG: the signature does not verify.".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_every_kind_and_rsa_name() {
        let keys = [
            PrivateKey::ed25519([3; 32]).unwrap(),
            PrivateKey::ecdsa(NistCurve::P256, BigUint::from_u64(12345)).unwrap(),
            PrivateKey::ecdsa(NistCurve::P521, BigUint::from_u64(678)).unwrap(),
        ];
        for key in &keys {
            let blob = sign(key, b"data", None).unwrap();
            assert!(verify(&key.public(), b"data", &blob).unwrap().is_some());
            assert!(verify(&key.public(), b"other", &blob).unwrap().is_none());
        }
        // A key cannot be made to claim another algorithm.
        assert!(sign(&keys[0], b"data", Some("ssh-rsa")).is_err());
    }

    #[test]
    fn test_sshsig_namespace_is_enforced() {
        let key = PrivateKey::ed25519([5; 32]).unwrap();
        let armoured = sshsig_sign(&key, "file", b"message", "sha512").unwrap();
        assert_eq!(sshsig_verify(&armoured, "file", b"message").unwrap(), key.public());
        assert!(sshsig_verify(&armoured, "git", b"message").unwrap_err()
                .contains("namespace"));
        assert!(sshsig_verify(&armoured, "file", b"massage").is_err());
    }
}
