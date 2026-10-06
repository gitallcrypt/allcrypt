//! Java's own key stores, JKS and JCEKS, from the JDK's source
//! (`sun.security.provider.JavaKeyStore` and `KeyProtector`,
//! `com.sun.crypto.provider.JceKeyStore`, `KeyProtector` and
//! `PBES1Core`).
//!
//! Both are a magic number, a version and a list of entries - a private
//! key with its certificate chain, a trusted certificate, and in JCEKS a
//! secret key - closed by a SHA-1 over the password, the words "Mighty
//! Aphrodite" and everything before it. That digest is the store's only
//! integrity, keyed by nothing but the password.
//!
//! A private key is a PKCS#8 EncryptedPrivateKeyInfo under one of two
//! proprietary schemes:
//!
//! - **JKS**: a 20-byte salt, and a keystream of SHA-1 over the password
//!   and the previous block (the salt first), XORed in; then the SHA-1
//!   of the password and the plaintext as a check. One SHA-1 per 20
//!   bytes of key: a password guess costs two hashes.
//! - **JCEKS**: PBEWithMD5AndTripleDES - each half of an 8-byte salt
//!   hashed with the password by MD5, iterated (200,000 times by
//!   default), giving 3DES's key and IV. Its password is ASCII only.
//!
//! JCEKS secret keys are Java-serialized `SealedObject`s around a
//! serialized `SecretKeySpec`, sealed with the same PBE (`javaser.rs`).
//!
//! Passwords are UTF-16 big endian for the store digest and for JKS,
//! and seven-bit ASCII for JCEKS's PBE.

use allcrypt::asn1::{Reader, Writer};
use allcrypt::hash_functions::HashFunction;
use allcrypt::x509::encrypted_key;

use crate::javaser;
use crate::pkcs12::oid;

pub const JKS_MAGIC: u32 = 0xfeed_feed;
pub const JCEKS_MAGIC: u32 = 0xcece_cece;
/// JKS's key protector and JCEKS's, as `KnownOIDs` names them.
pub const JKS_KEY_PROTECTOR: &str = "1.3.6.1.4.1.42.2.17.1.1";
pub const JCE_KEY_PROTECTOR: &str = "1.3.6.1.4.1.42.2.19.1";
const PBE_MD5_3DES: &str = "PBEWithMD5AndTripleDES";

fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = allcrypt::api::AnyHash::new("sha1").expect("built in");
    for part in parts {
        h.update(part);
    }
    h.digest()
}

/// `JavaKeyStore.convertToBytes`: each UTF-16 unit, high byte first.
pub fn utf16be(password: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(password).map_err(|_| "The password is not UTF-8.")?;
    Ok(text.encode_utf16().flat_map(u16::to_be_bytes).collect())
}

#[derive(Clone, Debug, PartialEq)]
pub enum Entry {
    PrivateKey { pkcs8: Vec<u8>, chain: Vec<Vec<u8>> },
    Certificate(Vec<u8>),
    Secret { algorithm: String, key: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Named {
    pub alias: String,
    /// Milliseconds since 1970, as Java writes it.
    pub date: u64,
    pub entry: Entry,
}

// ---------------------------------------------------- the key protectors --
//
// Both protectors are the library's (`allcrypt::x509::encrypted_key`):
// JKS's SHA-1 keystream and JCEKS's PBEWithMD5AndTripleDES.

fn md5_3des(password: &[u8], salt: &[u8], iterations: u32, data: &[u8], encrypting: bool)
            -> Result<Vec<u8>, String> {
    if encrypting {
        encrypted_key::jdk_pbe_md5_3des_encrypt(password, salt, iterations, data)
    } else {
        encrypted_key::jdk_pbe_md5_3des_decrypt(password, salt, iterations, data)
    }
}

/// The DER `PBEParameter`: salt and iteration count.
fn pbe_parameters(der: &[u8]) -> Result<(Vec<u8>, u32), String> {
    let mut p = Reader::new(der).read_sequence()?;
    let salt = p.read_octet_string()?.to_vec();
    let iterations = p.read_u32()?;
    Ok((salt, iterations))
}

fn write_pbe_parameters(salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_octet_string(salt);
        w.write_u32(iterations);
    });
    w.finish()
}

/// Unprotect an EncryptedPrivateKeyInfo under either Java scheme.
pub fn unprotect(epki: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let mut outer = Reader::new(epki).read_sequence()?;
    let mut algorithm = outer.read_sequence()?;
    let scheme = algorithm.read_oid()?.to_string();
    match scheme.as_str() {
        JKS_KEY_PROTECTOR => encrypted_key::decrypt(epki, password),
        // Nothing but the CBC padding checks the password, which a wrong
        // one passes about one time in 256; Java then fails to parse the
        // key, and so does this.
        JCE_KEY_PROTECTOR => crate::pkcs12::key_info(&encrypted_key::decrypt(epki, password)?),
        other => Err(format!("A key protected by {other}, which is not Java's.")),
    }
}

fn epki(scheme: &str, parameters: Option<&[u8]>, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_sequence(|w| {
            w.write_oid(&oid(scheme));
            match parameters {
                Some(p) => w.write_raw(p),
                None => w.write_null(),
            }
        });
        w.write_octet_string(data);
    });
    w.finish()
}

// -------------------------------------------------------- the container --

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let out = self.data.get(self.at..self.at + n).ok_or("The key store is truncated.")?;
        self.at += n;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four")))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("eight")))
    }

    fn utf(&mut self) -> Result<String, String> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().expect("two")) as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.u32()? as usize;
        if n > self.data.len() {
            return Err("A length past the end of the key store.".to_string());
        }
        Ok(self.take(n)?.to_vec())
    }

    fn certificate(&mut self, version: u32) -> Result<Vec<u8>, String> {
        if version == 2 {
            let kind = self.utf()?;
            if kind != "X.509" {
                return Err(format!("A certificate of type {kind}."));
            }
        }
        self.bytes()
    }
}

/// The store digest: SHA-1 of the password, "Mighty Aphrodite" and the
/// store.
fn store_digest(password: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    Ok(sha1(&[&utf16be(password)?, b"Mighty Aphrodite", body]))
}

/// Read a JKS or JCEKS store, checking its digest with the store
/// password and decrypting every key with the key password.
pub fn open(data: &[u8], store_password: &[u8], key_password: &[u8])
            -> Result<(u32, Vec<Named>), String> {
    open_keeping(data, store_password, key_password, &mut Vec::new())
}

/// `open`, keeping each sealed secret key's serialised object and its
/// serialised plaintext in `sealed`: the bytes Java wrote, for a test
/// to hold the writer to.
fn open_keeping(data: &[u8], store_password: &[u8], key_password: &[u8],
                sealed: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<(u32, Vec<Named>), String> {
    if data.len() < 32 {
        return Err("Too short for a Java key store.".to_string());
    }
    let (body, digest) = data.split_at(data.len() - 20);
    if store_digest(store_password, body)? != digest {
        return Err("Wrong store password, or the store was changed: its digest does not \
                    match.".to_string());
    }
    let mut c = Cursor { data: body, at: 0 };
    let magic = c.u32()?;
    if magic != JKS_MAGIC && magic != JCEKS_MAGIC {
        return Err(format!("Magic {magic:#010x} is neither JKS nor JCEKS."));
    }
    let version = c.u32()?;
    if version != 1 && version != 2 {
        return Err(format!("Key store version {version}."));
    }
    let count = c.u32()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let tag = c.u32()?;
        let alias = c.utf()?;
        let date = c.u64()?;
        let entry = match tag {
            1 => {
                let protected = c.bytes()?;
                let n = c.u32()?;
                let mut chain = Vec::new();
                for _ in 0..n {
                    chain.push(c.certificate(version)?);
                }
                Entry::PrivateKey { pkcs8: unprotect(&protected, key_password)
                    .map_err(|e| format!("{alias}: {e}"))?, chain }
            }
            2 => Entry::Certificate(c.certificate(version)?),
            3 if magic == JCEKS_MAGIC => {
                let (value, used) = javaser::read(&body[c.at..])?;
                let object = body[c.at..c.at + used].to_vec();
                c.at += used;
                let (params, encrypted, _) = javaser::unseal_parts(&value)?;
                let (salt, iterations) = pbe_parameters(&params)?;
                let plain = md5_3des(key_password, &salt, iterations, &encrypted, false)
                    .map_err(|e| format!("{alias}: {e}"))?;
                let (spec, _) = javaser::read(&plain)?;
                sealed.push((object, plain.clone()));
                let algorithm = match spec.field("algorithm") {
                    Some(javaser::Value::String(s)) => s.clone(),
                    _ => return Err(format!("{alias}: a sealed key with no algorithm.")),
                };
                let key = match spec.field("key") {
                    Some(javaser::Value::Bytes(b)) => b.clone(),
                    _ => return Err(format!("{alias}: a sealed key with no key.")),
                };
                Entry::Secret { algorithm, key }
            }
            other => return Err(format!("Entry type {other}.")),
        };
        out.push(Named { alias, date, entry });
    }
    if c.at != body.len() {
        return Err("Bytes after the last entry.".to_string());
    }
    Ok((magic, out))
}

/// Write a JKS (`magic` = JKS_MAGIC) or JCEKS store.
pub fn write(magic: u32, entries: &[Named], store_password: &[u8], key_password: &[u8],
             iterations: u32) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend(magic.to_be_bytes());
    out.extend(2u32.to_be_bytes());
    out.extend((entries.len() as u32).to_be_bytes());
    let utf = |out: &mut Vec<u8>, s: &str| {
        out.extend((s.len() as u16).to_be_bytes());
        out.extend(s.as_bytes());
    };
    let certificate = |out: &mut Vec<u8>, der: &[u8]| {
        out.extend(5u16.to_be_bytes());
        out.extend(b"X.509");
        out.extend((der.len() as u32).to_be_bytes());
        out.extend(der);
    };
    for named in entries {
        let tag: u32 = match named.entry {
            Entry::PrivateKey { .. } => 1,
            Entry::Certificate(_) => 2,
            Entry::Secret { .. } => 3,
        };
        out.extend(tag.to_be_bytes());
        utf(&mut out, &named.alias);
        out.extend(named.date.to_be_bytes());
        match &named.entry {
            Entry::PrivateKey { pkcs8, chain } => {
                let protected = if magic == JKS_MAGIC {
                    let salt = allcrypt::api::random_bytes(20)?;
                    epki(JKS_KEY_PROTECTOR, None,
                         &encrypted_key::jks_protect(pkcs8, key_password, &salt)?)
                } else {
                    let salt = allcrypt::api::random_bytes(8)?;
                    let sealed = md5_3des(key_password, &salt, iterations, pkcs8, true)?;
                    epki(JCE_KEY_PROTECTOR, Some(&write_pbe_parameters(&salt, iterations)), &sealed)
                };
                out.extend((protected.len() as u32).to_be_bytes());
                out.extend(&protected);
                out.extend((chain.len() as u32).to_be_bytes());
                for der in chain {
                    certificate(&mut out, der);
                }
            }
            Entry::Certificate(der) => certificate(&mut out, der),
            Entry::Secret { algorithm, key } => {
                if magic != JCEKS_MAGIC {
                    return Err("JKS cannot hold a secret key; JCEKS can.".to_string());
                }
                let salt = allcrypt::api::random_bytes(8)?;
                let sealed = md5_3des(key_password, &salt, iterations,
                                      &javaser::secret_key_spec(algorithm, key), true)?;
                out.extend(javaser::sealed_object(&write_pbe_parameters(&salt, iterations),
                                                  &sealed, PBE_MD5_3DES, PBE_MD5_3DES));
            }
        }
    }
    let digest = store_digest(store_password, &out)?;
    out.extend(digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JCEKS's key protector has no check of its own: a wrong password
    /// that leaves valid padding is refused because the key does not
    /// parse, as Java refuses it.
    #[test]
    fn test_a_jceks_wrong_password_with_good_padding_is_refused() {
        let mut pkcs8 = vec![0x30, 0x0e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
                             0x70, 0x04, 0x02, 0x04, 0x00];
        pkcs8[1] = (pkcs8.len() - 2) as u8;
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let sealed = epki(JCE_KEY_PROTECTOR, Some(&write_pbe_parameters(&salt, 1)),
                          &md5_3des(b"right", &salt, 1, &pkcs8, true).unwrap());
        assert_eq!(unprotect(&sealed, b"right").unwrap(), pkcs8);
        let mut caught = 0;
        for n in 0..4000 {
            match unprotect(&sealed, format!("wrong {n}").as_bytes()) {
                Ok(_) => panic!("wrong {n} was accepted"),
                Err(e) if e.contains("not a PrivateKeyInfo") => caught += 1,
                Err(_) => {}
            }
        }
        assert!(caught > 0, "no wrong password passed the padding");
    }

    /// The store digest is SHA-1 over the password and then the store,
    /// a secret prefix, so anyone can extend it: append bytes and carry
    /// the hash on, without the password. What makes that useless is
    /// that the entry count comes first and nothing may follow the last
    /// entry - so the test appends under a correct digest, the most an
    /// extension could produce, and expects the store refused.
    #[test]
    fn test_bytes_after_the_last_entry_are_refused() {
        let data = std::fs::read(crate::fixtures::dir().join("keystore")
                                 .join("keytool-jks.jks")).unwrap();
        let password = b"store password";
        assert!(open(&data, password, password).is_ok());
        let mut body = data[..data.len() - 20].to_vec();
        body.extend([0x80, 0, 0, 0, 1]);
        let digest = store_digest(password, &body).unwrap();
        body.extend(digest);
        let error = open(&body, password, password).unwrap_err();
        assert!(error.contains("after the last entry"), "{error}");
    }

    /// keytool's JCEKS secret key, both layers of Java serialisation -
    /// the sealed object as stored and the `SecretKeySpec` inside it -
    /// is byte for byte what `javaser` writes for the same parts. The
    /// class names, the serial version UIDs, the field order and the
    /// handle numbering all have to be Java's for that, and a reader
    /// that is lenient about any of them would not notice.
    #[test]
    fn test_the_serialised_secret_key_is_javas() {
        let data = std::fs::read(crate::fixtures::dir().join("keystore")
                                 .join("keytool-jceks.jceks")).unwrap();
        let mut sealed = Vec::new();
        let (_, entries) = open_keeping(&data, b"store password", b"store password",
                                        &mut sealed).unwrap();
        assert_eq!(sealed.len(), 1);
        let (object, plain) = &sealed[0];
        let (algorithm, key) = entries.iter().find_map(|n| match &n.entry {
            Entry::Secret { algorithm, key } => Some((algorithm, key)),
            _ => None,
        }).unwrap();
        assert_eq!((algorithm.as_str(), key.len()), ("AES", 32));
        assert_eq!(&javaser::secret_key_spec(algorithm, key), plain);
        let (value, _) = javaser::read(object).unwrap();
        let (params, encrypted, seal) = javaser::unseal_parts(&value).unwrap();
        assert_eq!(&javaser::sealed_object(&params, &encrypted, PBE_MD5_3DES, &seal), object);
    }
}
