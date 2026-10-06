//! JSON Web Encryption (RFC 7516) with RFC 7518's key management and
//! content encryption, and ECDH-ES over X25519 and X448 (RFC 8037).

use crate::json::{self, Json};
use crate::jwk::{b64, unb64, Jwk, Key};
use allcrypt::api::{EcKey, RsaPublicKey};

/// The most a `"zip": "DEF"` plaintext may inflate to. A JWE is small,
/// and a compressed one is a way to make a reader allocate far more
/// than it was sent.
pub const INFLATE_LIMIT: usize = 64 << 20;

pub struct Recipient {
    pub header: Option<Json>,
    pub encrypted_key: Vec<u8>,
}

pub struct Jwe {
    /// The protected header as the base64url text carried: it is the
    /// additional authenticated data, not a re-encoding of it.
    pub protected: String,
    pub unprotected: Option<Json>,
    pub recipients: Vec<Recipient>,
    pub aad: Option<String>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

// ------------------------------------------------------ content encryption --

/// The content key length for an `enc`.
pub fn cek_length(enc: &str) -> Result<usize, String> {
    match enc {
        "A128CBC-HS256" => Ok(32),
        "A192CBC-HS384" => Ok(48),
        "A256CBC-HS512" => Ok(64),
        "A128GCM" => Ok(16),
        "A192GCM" => Ok(24),
        "A256GCM" => Ok(32),
        other => Err(format!("No content encryption {other:?}.")),
    }
}

/// The library's AEAD name for a CBC content encryption (RFC 7518 5.2).
fn cbc_hmac_name(enc: &str) -> &'static str {
    match enc {
        "A128CBC-HS256" => "aes-128-cbc-hmac-sha256",
        "A192CBC-HS384" => "aes-192-cbc-hmac-sha384",
        _ => "aes-256-cbc-hmac-sha512",
    }
}

/// What content encryption produces.
pub struct Sealed {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Encrypt under `enc`, with a fresh IV unless one is given.
pub fn seal(enc: &str, cek: &[u8], aad: &[u8], plaintext: &[u8], iv: Option<&[u8]>)
            -> Result<Sealed, String> {
    if cek.len() != cek_length(enc)? {
        return Err(format!("{enc} takes a {} byte key, not {}.", cek_length(enc)?, cek.len()));
    }
    if enc.contains("CBC") {
        let iv = match iv {
            Some(iv) => iv.to_vec(),
            None => allcrypt::api::random_bytes(16)?,
        };
        let (ciphertext, tag) = allcrypt::api::aead_encrypt(cbc_hmac_name(enc), cek, &iv, aad,
                                                            plaintext)?;
        Ok(Sealed { iv, ciphertext, tag })
    } else {
        let iv = match iv {
            Some(iv) => iv.to_vec(),
            None => allcrypt::api::random_bytes(12)?,
        };
        let (ciphertext, tag) = allcrypt::api::aead_encrypt("aes-gcm", cek, &iv, aad, plaintext)?;
        Ok(Sealed { iv, ciphertext, tag })
    }
}

/// Decrypt under `enc`. One error for every failure.
pub fn open(enc: &str, cek: &[u8], aad: &[u8], iv: &[u8], ciphertext: &[u8], tag: &[u8])
            -> Result<Vec<u8>, String> {
    const FAILURE: &str = "The JWE does not decrypt: wrong key, or the message was changed.";
    if cek.len() != cek_length(enc)? {
        return Err(FAILURE.to_string());
    }
    if enc.contains("CBC") {
        // The tag is checked before anything is decrypted, so the padding
        // cannot be an oracle (the library's `cbc_hmac`).
        allcrypt::api::aead_decrypt(cbc_hmac_name(enc), cek, iv, aad, ciphertext, tag)
            .map_err(|_| FAILURE.to_string())
    } else {
        if iv.len() != 12 || tag.len() != 16 {
            return Err(FAILURE.to_string());
        }
        allcrypt::api::aead_decrypt("aes-gcm", cek, iv, aad, ciphertext, tag)
            .map_err(|_| FAILURE.to_string())
    }
}

// ----------------------------------------------------------- key management --

/// NIST SP 800-56A's single-step KDF with SHA-256, as RFC 7518 4.6.2
/// fixes its OtherInfo: the algorithm, apu, apv, each length-prefixed,
/// then the key length in bits.
pub fn concat_kdf(z: &[u8], algorithm: &str, apu: &[u8], apv: &[u8], length: usize)
                  -> Vec<u8> {
    let mut other = Vec::new();
    for part in [algorithm.as_bytes(), apu, apv] {
        other.extend_from_slice(&(part.len() as u32).to_be_bytes());
        other.extend_from_slice(part);
    }
    other.extend_from_slice(&(length as u32 * 8).to_be_bytes());
    allcrypt::kdf::nist::concat_kdf("sha256", z, &other, length).expect("SHA-256 is built in")
}

fn kw_length(alg: &str) -> Result<usize, String> {
    if alg.contains("128") {
        Ok(16)
    } else if alg.contains("192") {
        Ok(24)
    } else if alg.contains("256") {
        Ok(32)
    } else {
        Err(format!("No key wrapping length in {alg:?}."))
    }
}

/// What decrypts: a key, or for PBES2 a password.
pub enum Secret<'a> {
    Key(&'a Jwk),
    Password(&'a [u8]),
}

/// The ECDH shared secret between a private key and a peer's public
/// JWK on the same curve.
pub fn agree(private: &Jwk, peer: &Jwk) -> Result<Vec<u8>, String> {
    match (&private.key, &peer.key) {
        (Key::Ec { crv, private: Some(d), .. }, Key::Ec { crv: peer_crv, point, .. })
            if crv == peer_crv => {
            EcKey::from_private(Jwk::ec_library_curve(crv)?, d)?.exchange(point)
        }
        (Key::Okp { crv: "X25519", d: Some(d), .. }, Key::Okp { crv: "X25519", x, .. }) => {
            allcrypt::api::x25519_exchange(d, x)
        }
        (Key::Okp { crv: "X448", d: Some(d), .. }, Key::Okp { crv: "X448", x, .. }) => {
            allcrypt::api::x448_exchange(d, x)
        }
        _ => Err(format!("ECDH between a {} key and a {} key on another curve, or without \
                          the private half.", private.kty(), peer.kty())),
    }
}

/// An ephemeral key on the recipient's curve.
fn ephemeral(recipient: &Jwk) -> Result<Jwk, String> {
    match &recipient.key {
        Key::Ec { crv, .. } => Jwk::generate("EC", crv),
        Key::Okp { crv: crv @ ("X25519" | "X448"), .. } => Jwk::generate("OKP", crv),
        _ => Err(format!("ECDH-ES to a {} key.", recipient.kty())),
    }
}

/// Header members ECDH-ES's KDF reads: the party information.
fn party(header: &Json, name: &str) -> Result<Vec<u8>, String> {
    header.str(name).map(unb64).transpose().map(Option::unwrap_or_default)
}

/// Wrap (or agree) a content key for one recipient. Returns the
/// encrypted key, the header members the algorithm adds, and - for the
/// direct modes - the content key itself, which they choose.
pub struct Wrapped {
    pub encrypted_key: Vec<u8>,
    pub header: Json,
    pub cek: Option<Vec<u8>>,
}

pub fn wrap(alg: &str, enc: &str, secret: &Secret, cek: &[u8], header: &Json,
            p2c: u32) -> Result<Wrapped, String> {
    let mut added = Json::object();
    let encrypted_key = match (alg, secret) {
        ("RSA1_5" | "RSA-OAEP" | "RSA-OAEP-256", Secret::Key(Jwk { key: Key::Rsa { public, .. },
                                                                  .. })) => {
            rsa_encrypt(alg, public, cek)?
        }
        ("A128KW" | "A192KW" | "A256KW", Secret::Key(Jwk { key: Key::Oct(kek), .. })) => {
            if kek.len() != kw_length(alg)? {
                return Err(format!("{alg} takes a {} byte key.", kw_length(alg)?));
            }
            allcrypt::api::key_wrap("aes", kek, cek)?
        }
        ("A128GCMKW" | "A192GCMKW" | "A256GCMKW", Secret::Key(Jwk { key: Key::Oct(kek), .. })) => {
            if kek.len() != kw_length(alg)? {
                return Err(format!("{alg} takes a {} byte key.", kw_length(alg)?));
            }
            let iv = allcrypt::api::random_bytes(12)?;
            let (wrapped, tag) = allcrypt::api::aead_encrypt("aes-gcm", kek, &iv, &[], cek)?;
            added.set("iv", Json::string(&b64(&iv)));
            added.set("tag", Json::string(&b64(&tag)));
            wrapped
        }
        ("PBES2-HS256+A128KW" | "PBES2-HS384+A192KW" | "PBES2-HS512+A256KW",
         Secret::Password(password)) => {
            let p2s = allcrypt::api::random_bytes(16)?;
            let kek = pbes2_key(alg, password, &p2s, p2c)?;
            added.set("p2s", Json::string(&b64(&p2s)));
            added.set("p2c", Json::Number(p2c.to_string()));
            allcrypt::api::key_wrap("aes", &kek, cek)?
        }
        ("dir", Secret::Key(Jwk { key: Key::Oct(key), .. })) => {
            if key.len() != cek_length(enc)? {
                return Err(format!("dir with {enc} takes a {} byte key.", cek_length(enc)?));
            }
            return Ok(Wrapped { encrypted_key: Vec::new(), header: added,
                                cek: Some(key.clone()) });
        }
        ("ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW", Secret::Key(peer)) => {
            let epk = ephemeral(peer)?;
            let z = agree(&epk, peer)?;
            added.set("epk", epk.to_json(false));
            let (apu, apv) = (party(header, "apu")?, party(header, "apv")?);
            if alg == "ECDH-ES" {
                let key = concat_kdf(&z, enc, &apu, &apv, cek_length(enc)?);
                return Ok(Wrapped { encrypted_key: Vec::new(), header: added, cek: Some(key) });
            }
            let kek = concat_kdf(&z, alg, &apu, &apv, kw_length(alg)?);
            allcrypt::api::key_wrap("aes", &kek, cek)?
        }
        _ => return Err(format!("{alg} cannot be used with this key.")),
    };
    Ok(Wrapped { encrypted_key, header: added, cek: None })
}

fn rsa_encrypt(alg: &str, public: &RsaPublicKey, cek: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        "RSA1_5" => public.encrypt(cek),
        "RSA-OAEP" => public.encrypt_oaep("sha1", Some("sha1"), &[], cek),
        _ => public.encrypt_oaep("sha256", Some("sha256"), &[], cek),
    }
}

/// RFC 7518 4.8.1.1: the salt is the algorithm's name, a zero byte, and
/// `p2s`; the key is PBKDF2 under the algorithm's HMAC.
fn pbes2_key(alg: &str, password: &[u8], p2s: &[u8], p2c: u32) -> Result<Vec<u8>, String> {
    if p2s.len() < 8 {
        return Err("PBES2's p2s must be at least 8 bytes.".to_string());
    }
    if p2c == 0 {
        return Err("PBES2's p2c must be at least 1.".to_string());
    }
    let prf = match &alg[6..11] {
        "HS256" => "sha256",
        "HS384" => "sha384",
        _ => "sha512",
    };
    let mut salt = alg.as_bytes().to_vec();
    salt.push(0);
    salt.extend_from_slice(p2s);
    allcrypt::api::pbkdf2(prf, password, &salt, p2c, kw_length(alg)?)
}

/// The content key from one recipient's encrypted key. `None` when the
/// key or password does not fit this recipient's algorithm - try the
/// next. RSA1_5's failure is not an error here: RFC 7516 11.5 has the
/// decryptor go on with a random key so that a padding failure and a
/// wrong key fail at the same place, the tag.
pub fn unwrap(header: &Json, secret: &Secret, enc: &str, encrypted_key: &[u8],
              max_p2c: u32) -> Result<Option<Vec<u8>>, String> {
    let alg = header.str("alg").ok_or("A JWE recipient with no \"alg\".")?;
    let length = cek_length(enc)?;
    let cek = match (alg, secret) {
        ("RSA1_5", Secret::Key(Jwk { key: Key::Rsa { private: Some(private), .. }, .. })) => {
            let fallback = allcrypt::api::random_bytes(length)?;
            match private.decrypt(encrypted_key) {
                Ok(cek) if cek.len() == length => cek,
                _ => fallback,
            }
        }
        ("RSA-OAEP", Secret::Key(Jwk { key: Key::Rsa { private: Some(private), .. }, .. })) => {
            private.decrypt_oaep("sha1", Some("sha1"), &[], encrypted_key)?
        }
        ("RSA-OAEP-256", Secret::Key(Jwk { key: Key::Rsa { private: Some(private), .. }, .. })) => {
            private.decrypt_oaep("sha256", Some("sha256"), &[], encrypted_key)?
        }
        ("A128KW" | "A192KW" | "A256KW", Secret::Key(Jwk { key: Key::Oct(kek), .. })) => {
            if kek.len() != kw_length(alg)? {
                return Ok(None);
            }
            allcrypt::api::key_unwrap("aes", kek, encrypted_key)?
        }
        ("A128GCMKW" | "A192GCMKW" | "A256GCMKW", Secret::Key(Jwk { key: Key::Oct(kek), .. })) => {
            if kek.len() != kw_length(alg)? {
                return Ok(None);
            }
            let iv = unb64(header.str("iv").ok_or("A GCMKW header with no \"iv\".")?)?;
            let tag = unb64(header.str("tag").ok_or("A GCMKW header with no \"tag\".")?)?;
            if iv.len() != 12 || tag.len() != 16 {
                return Err("A GCMKW iv is 12 bytes and its tag 16.".to_string());
            }
            allcrypt::api::aead_decrypt("aes-gcm", kek, &iv, &[], encrypted_key, &tag)?
        }
        ("PBES2-HS256+A128KW" | "PBES2-HS384+A192KW" | "PBES2-HS512+A256KW",
         Secret::Password(password)) => {
            let p2s = unb64(header.str("p2s").ok_or("A PBES2 header with no \"p2s\".")?)?;
            let p2c = header.get("p2c").and_then(Json::as_u64)
                .ok_or("A PBES2 header with no whole-number \"p2c\".")?;
            // The sender chooses the iteration count and the reader pays
            // for it, so it is capped.
            if p2c > u64::from(max_p2c) {
                return Err(format!("PBES2 asks for {p2c} iterations, more than the {max_p2c} \
                                    allowed."));
            }
            let kek = pbes2_key(alg, password, &p2s, p2c as u32)?;
            allcrypt::api::key_unwrap("aes", &kek, encrypted_key)?
        }
        ("dir", Secret::Key(Jwk { key: Key::Oct(key), .. })) => {
            if !encrypted_key.is_empty() {
                return Err("dir with an encrypted key.".to_string());
            }
            key.clone()
        }
        ("ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW", Secret::Key(own)) => {
            let epk = Jwk::parse(header.get("epk").ok_or("ECDH-ES with no \"epk\".")?)?;
            if epk.is_private() {
                return Err("An \"epk\" with a private key in it.".to_string());
            }
            let z = agree(own, &epk)?;
            let (apu, apv) = (party(header, "apu")?, party(header, "apv")?);
            if alg == "ECDH-ES" {
                if !encrypted_key.is_empty() {
                    return Err("ECDH-ES with an encrypted key.".to_string());
                }
                concat_kdf(&z, enc, &apu, &apv, length)
            } else {
                let kek = concat_kdf(&z, alg, &apu, &apv, kw_length(alg)?);
                allcrypt::api::key_unwrap("aes", &kek, encrypted_key)?
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(cek))
}

// -------------------------------------------------------------- the message --

/// One recipient to encrypt to.
pub struct To<'a> {
    pub alg: &'a str,
    pub secret: Secret<'a>,
    /// Members of this recipient's header beyond what the algorithm adds:
    /// `kid`, `apu`, `apv`.
    pub header: Json,
}

pub struct Options<'a> {
    pub enc: &'a str,
    pub zip: bool,
    /// Extra protected members.
    pub protected: Json,
    pub unprotected: Option<Json>,
    pub aad: Option<&'a [u8]>,
    pub p2c: u32,
}

/// RFC 1951's stored blocks: valid DEFLATE that compresses nothing,
/// which is all `"zip": "DEF"` requires of a writer.
fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / 65535 + 1));
    let mut chunks = data.chunks(65535).peekable();
    if chunks.peek().is_none() {
        return vec![1, 0, 0, 0xff, 0xff];
    }
    while let Some(chunk) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        let n = chunk.len() as u16;
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(!n).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// Encrypt to every recipient. One recipient's algorithm members go in
/// the protected header, as the compact serialization needs; with
/// several, each recipient's go in its own header.
pub fn encrypt(plaintext: &[u8], to: &[To], options: &Options) -> Result<Jwe, String> {
    if to.is_empty() {
        return Err("No recipient.".to_string());
    }
    let direct = |alg: &str| alg == "dir" || alg == "ECDH-ES";
    if to.len() > 1 && to.iter().any(|t| direct(t.alg)) {
        return Err("dir and ECDH-ES choose the content key, so they have one recipient."
            .to_string());
    }
    let single = to.len() == 1;
    let mut cek = allcrypt::api::random_bytes(cek_length(options.enc)?)?;
    let mut recipients = Vec::new();
    let mut protected = Json::object();
    for recipient in to {
        let mut header = recipient.header.clone();
        header.set("alg", Json::string(recipient.alg));
        let wrapped = wrap(recipient.alg, options.enc, &recipient.secret, &cek, &header,
                           options.p2c)?;
        if let Some(chosen) = wrapped.cek {
            cek = chosen;
        }
        for (name, value) in wrapped.header.members() {
            header.set(name, value.clone());
        }
        if single {
            protected = header;
            recipients.push(Recipient { header: None, encrypted_key: wrapped.encrypted_key });
        } else {
            recipients.push(Recipient { header: Some(header),
                                        encrypted_key: wrapped.encrypted_key });
        }
    }
    protected.set("enc", Json::string(options.enc));
    if options.zip {
        protected.set("zip", Json::string("DEF"));
    }
    for (name, value) in options.protected.members() {
        protected.set(name, value.clone());
    }
    let protected = b64(protected.to_text().as_bytes());
    let aad_text = options.aad.map(b64);
    let plaintext = if options.zip { deflate_stored(plaintext) } else { plaintext.to_vec() };
    let Sealed { iv, ciphertext, tag } =
        seal(options.enc, &cek, &additional_data(&protected, aad_text.as_deref()), &plaintext,
             None)?;
    Ok(Jwe { protected, unprotected: options.unprotected.clone(), recipients, aad: aad_text,
             iv, ciphertext, tag })
}

/// RFC 7516 5.1 step 14: the protected header's text, then a '.' and
/// the base64url AAD when there is one.
fn additional_data(protected: &str, aad: Option<&str>) -> Vec<u8> {
    let mut out = protected.as_bytes().to_vec();
    if let Some(aad) = aad {
        out.push(b'.');
        out.extend_from_slice(aad.as_bytes());
    }
    out
}

/// The protected header, unprotected header and one recipient's header,
/// joined; their member names must be disjoint (RFC 7516 7.2.1).
fn joined(jwe: &Jwe, recipient: &Recipient) -> Result<(Json, Json), String> {
    let protected = if jwe.protected.is_empty() {
        Json::object()
    } else {
        let bytes = unb64(&jwe.protected)?;
        json::parse(std::str::from_utf8(&bytes).map_err(|_| "A protected header that is not \
                                                               UTF-8.")?)?
    };
    if !matches!(protected, Json::Object(_)) {
        return Err("A protected header that is not an object.".to_string());
    }
    let mut all = protected.clone();
    for header in [jwe.unprotected.as_ref(), recipient.header.as_ref()].into_iter().flatten() {
        if !matches!(header, Json::Object(_)) {
            return Err("A JWE header that is not an object.".to_string());
        }
        for (name, value) in header.members() {
            if all.get(name).is_some() {
                return Err(format!("{name:?} is in two JWE headers."));
            }
            all.set(name, value.clone());
        }
    }
    if let Some(crit) = protected.get("crit") {
        return Err(format!("\"crit\" names {}, none of which is understood here.",
                           crit.to_text()));
    }
    if all.get("zip").is_some() && protected.get("zip").is_none() {
        return Err("\"zip\" must be in the protected header.".to_string());
    }
    Ok((protected, all))
}

/// Decrypt with a key or a password. Every recipient the secret fits is
/// tried; the first that authenticates gives the plaintext.
pub fn decrypt(jwe: &Jwe, secret: &Secret, max_p2c: u32) -> Result<Vec<u8>, String> {
    let aad = additional_data(&jwe.protected, jwe.aad.as_deref());
    let mut last_error = "No recipient's algorithm fits this key.".to_string();
    for recipient in &jwe.recipients {
        let (_, header) = joined(jwe, recipient)?;
        let enc = header.str("enc").ok_or("A JWE with no \"enc\".")?;
        if let (Secret::Key(key), Some(want)) = (secret, header.str("kid")) {
            if key.kid.as_deref().is_some_and(|have| have != want) {
                continue;
            }
        }
        let cek = match unwrap(&header, secret, enc, &recipient.encrypted_key, max_p2c) {
            Ok(Some(cek)) => cek,
            Ok(None) => continue,
            Err(e) => {
                last_error = e;
                continue;
            }
        };
        match open(enc, &cek, &aad, &jwe.iv, &jwe.ciphertext, &jwe.tag) {
            Ok(plaintext) => {
                return match header.str("zip") {
                    None => Ok(plaintext),
                    Some("DEF") => {
                        let (out, used) = crate::inflate::inflate(&plaintext, INFLATE_LIMIT)?;
                        if used != plaintext.len() {
                            return Err("Bytes after the compressed plaintext.".to_string());
                        }
                        Ok(out)
                    }
                    Some(other) => Err(format!("\"zip\": {other:?} is not DEF.")),
                };
            }
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

impl Jwe {
    pub fn compact(&self) -> Result<String, String> {
        let [recipient] = &self.recipients[..] else {
            return Err("A compact JWE has exactly one recipient.".to_string());
        };
        if self.unprotected.is_some() || recipient.header.is_some() || self.aad.is_some() {
            return Err("A compact JWE has only a protected header, and no AAD.".to_string());
        }
        Ok(format!("{}.{}.{}.{}.{}", self.protected, b64(&recipient.encrypted_key),
                   b64(&self.iv), b64(&self.ciphertext), b64(&self.tag)))
    }

    pub fn json(&self, flattened: bool) -> Result<String, String> {
        let mut out = Json::object();
        if !self.protected.is_empty() {
            out.set("protected", Json::string(&self.protected));
        }
        if let Some(unprotected) = &self.unprotected {
            out.set("unprotected", unprotected.clone());
        }
        let entry = |r: &Recipient| {
            let mut json = Json::object();
            if let Some(header) = &r.header {
                json.set("header", header.clone());
            }
            if !r.encrypted_key.is_empty() {
                json.set("encrypted_key", Json::string(&b64(&r.encrypted_key)));
            }
            json
        };
        if flattened {
            let [recipient] = &self.recipients[..] else {
                return Err("A flattened JWE has exactly one recipient.".to_string());
            };
            for (name, value) in entry(recipient).members() {
                out.set(name, value.clone());
            }
        } else {
            out.set("recipients", Json::Array(self.recipients.iter().map(entry).collect()));
        }
        if let Some(aad) = &self.aad {
            out.set("aad", Json::string(aad));
        }
        out.set("iv", Json::string(&b64(&self.iv)));
        out.set("ciphertext", Json::string(&b64(&self.ciphertext)));
        out.set("tag", Json::string(&b64(&self.tag)));
        Ok(out.to_text())
    }

    pub fn parse(text: &str) -> Result<Jwe, String> {
        let text = text.trim();
        if !text.starts_with('{') {
            let parts: Vec<&str> = text.split('.').collect();
            let [protected, encrypted_key, iv, ciphertext, tag] = parts[..] else {
                return Err("A compact JWE is five parts.".to_string());
            };
            return Ok(Jwe { protected: protected.to_string(), unprotected: None,
                            recipients: vec![Recipient { header: None,
                                                         encrypted_key: unb64(encrypted_key)? }],
                            aad: None, iv: unb64(iv)?, ciphertext: unb64(ciphertext)?,
                            tag: unb64(tag)? });
        }
        let json = json::parse(text)?;
        let field = |name: &str| -> Result<Vec<u8>, String> {
            json.str(name).map(unb64).transpose().map(Option::unwrap_or_default)
        };
        let read = |entry: &Json| -> Result<Recipient, String> {
            Ok(Recipient { header: entry.get("header").cloned(),
                           encrypted_key: entry.str("encrypted_key").map(unb64).transpose()?
                               .unwrap_or_default() })
        };
        let recipients = match json.get("recipients") {
            Some(Json::Array(entries)) => {
                if json.get("header").is_some() || json.get("encrypted_key").is_some() {
                    return Err("A JWE that is both general and flattened.".to_string());
                }
                if entries.is_empty() {
                    return Err("A JWE with an empty recipient list.".to_string());
                }
                entries.iter().map(read).collect::<Result<_, _>>()?
            }
            Some(_) => return Err("\"recipients\" is a list.".to_string()),
            None => vec![read(&json)?],
        };
        if let Some(aad) = json.str("aad") {
            unb64(aad)?;
        }
        Ok(Jwe { protected: json.str("protected").unwrap_or("").to_string(),
                 unprotected: json.get("unprotected").cloned(), recipients,
                 aad: json.str("aad").map(str::to_string), iv: field("iv")?,
                 ciphertext: field("ciphertext")?, tag: field("tag")? })
    }
}
