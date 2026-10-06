//! JSON Web Signature (RFC 7515), the algorithms of RFC 7518 section 3,
//! EdDSA (RFC 8037), ES256K (RFC 8812), the fully-specified `Ed25519` and
//! `Ed448` (RFC 9864), and the unencoded payload of RFC 7797.

use crate::json::{self, Json};
use crate::jwk::{b64, unb64, Jwk, Key};
use allcrypt::api::{EcKey, EcPublicKey};

/// One signature: its protected header as the base64url text it was
/// carried as - the signing input is that text, not a re-encoding - its
/// unprotected header, and the signature.
pub struct Signature {
    pub protected: String,
    pub header: Option<Json>,
    pub signature: Vec<u8>,
}

pub struct Jws {
    /// The payload as it appears in the serialization: base64url, or the
    /// bytes themselves when `b64` is false.
    pub payload_text: Vec<u8>,
    pub signatures: Vec<Signature>,
}

/// The hash a JWS algorithm uses, by its bit length.
fn bits(alg: &str) -> Result<usize, String> {
    match &alg[alg.len().saturating_sub(3)..] {
        "256" | "56K" => Ok(256),
        "384" => Ok(384),
        "512" => Ok(512),
        _ => Err(format!("No JWS algorithm {alg:?}.")),
    }
}

fn hash_name(bits: usize) -> &'static str {
    match bits {
        256 => "sha256",
        384 => "sha384",
        _ => "sha512",
    }
}

/// The curve each ECDSA algorithm is defined on. RFC 7518 3.4 ties them:
/// ES512 is P-521, not P-512.
fn ec_curve(alg: &str) -> Option<&'static str> {
    match alg {
        "ES256" => Some("P-256"),
        "ES384" => Some("P-384"),
        "ES512" => Some("P-521"),
        "ES256K" => Some("secp256k1"),
        _ => None,
    }
}

fn eddsa_curve(alg: &str, key_crv: &str) -> Result<String, String> {
    match (alg, key_crv) {
        ("EdDSA", "Ed25519" | "Ed448") | ("Ed25519", "Ed25519") | ("Ed448", "Ed448") => {
            Ok(key_crv.to_lowercase())
        }
        _ => Err(format!("{alg} with an {key_crv} key.")),
    }
}

/// Sign `input` under `alg` with `key`.
pub fn sign_input(alg: &str, key: &Jwk, input: &[u8]) -> Result<Vec<u8>, String> {
    match (alg, &key.key) {
        ("none", _) => Ok(Vec::new()),
        ("HS256" | "HS384" | "HS512", Key::Oct(k)) => {
            let bits = bits(alg)?;
            // RFC 7518 3.2: a key at least as long as the hash's output.
            if k.len() * 8 < bits {
                return Err(format!("{alg} needs a key of at least {} bytes.", bits / 8));
            }
            allcrypt::api::hmac(hash_name(bits), k, input)
        }
        ("RS256" | "RS384" | "RS512", Key::Rsa { private: Some(private), .. }) => {
            let hash = hash_name(bits(alg)?);
            private.sign(hash, &crate::hash(hash, input))
        }
        ("PS256" | "PS384" | "PS512", Key::Rsa { private: Some(private), .. }) => {
            // Salt as long as the hash, MGF1 under the same hash.
            let hash = hash_name(bits(alg)?);
            private.sign_pss(hash, &crate::hash(hash, input), None)
        }
        (_, Key::Ec { crv, private: Some(d), .. }) if ec_curve(alg) == Some(crv) => {
            let hash = hash_name(bits(alg)?);
            // r || s, each the width of the group order: RFC 7518 3.4,
            // not the DER sequence of X.509.
            EcKey::from_private(Jwk::ec_library_curve(crv)?, d)?
                .sign(&crate::hash(hash, input), hash)
        }
        ("EdDSA" | "Ed25519" | "Ed448", Key::Okp { crv, d: Some(d), .. }) => {
            allcrypt::api::eddsa_sign(&eddsa_curve(alg, crv)?, d, input, &[])
        }
        _ => Err(format!("A {} key{} cannot sign {alg}.", key.kty(),
                         if key.is_private() { "" } else { " without its private half" })),
    }
}

/// Verify `signature` over `input`. `Ok(false)` for a signature that is
/// well formed and wrong.
pub fn verify_input(alg: &str, key: &Jwk, input: &[u8], signature: &[u8])
                    -> Result<bool, String> {
    match (alg, &key.key) {
        ("HS256" | "HS384" | "HS512", Key::Oct(k)) => {
            let bits = bits(alg)?;
            if k.len() * 8 < bits {
                return Err(format!("{alg} needs a key of at least {} bytes.", bits / 8));
            }
            let expected = allcrypt::api::hmac(hash_name(bits), k, input)?;
            Ok(crate::equal(&expected, signature))
        }
        ("RS256" | "RS384" | "RS512", Key::Rsa { public, .. }) => {
            let hash = hash_name(bits(alg)?);
            if signature.len() != public.size() {
                return Ok(false);
            }
            public.verify(hash, &crate::hash(hash, input), signature)
        }
        ("PS256" | "PS384" | "PS512", Key::Rsa { public, .. }) => {
            let hash = hash_name(bits(alg)?);
            if signature.len() != public.size() {
                return Ok(false);
            }
            public.verify_pss(hash, &crate::hash(hash, input), signature, None)
        }
        (_, Key::Ec { crv, point, .. }) if ec_curve(alg) == Some(crv) => {
            let hash = hash_name(bits(alg)?);
            let public = EcPublicKey::from_bytes(Jwk::ec_library_curve(crv)?, point)?;
            if signature.len() != point.len() - 1 {
                return Ok(false);
            }
            public.verify(&crate::hash(hash, input), signature)
        }
        ("EdDSA" | "Ed25519" | "Ed448", Key::Okp { crv, x, .. }) => {
            let curve = eddsa_curve(alg, crv)?;
            let length = if curve == "ed25519" { 64 } else { 114 };
            if signature.len() != length {
                return Ok(false);
            }
            allcrypt::api::eddsa_verify(&curve, x, input, signature, &[])
        }
        _ => Err(format!("A {} key cannot verify {alg}.", key.kty())),
    }
}

/// The header members this implementation understands in `crit`.
const UNDERSTOOD: [&str; 1] = ["b64"];

/// A signature's two headers, checked as RFC 7515 4 and 7797 3 require,
/// and joined: the algorithm, and whether the payload is encoded.
pub struct Headers {
    pub joined: Json,
    pub alg: String,
    pub b64: bool,
}

pub fn headers(signature: &Signature) -> Result<Headers, String> {
    let protected = if signature.protected.is_empty() {
        Json::object()
    } else {
        let bytes = unb64(&signature.protected)?;
        json::parse(std::str::from_utf8(&bytes).map_err(|_| "A protected header that is \
                                                               not UTF-8.")?)?
    };
    if !matches!(protected, Json::Object(_)) {
        return Err("A protected header that is not an object.".to_string());
    }
    let mut joined = protected.clone();
    if let Some(header) = &signature.header {
        if !matches!(header, Json::Object(_)) {
            return Err("An unprotected header that is not an object.".to_string());
        }
        for (name, value) in header.members() {
            if protected.get(name).is_some() {
                return Err(format!("{name:?} is in both headers."));
            }
            joined.set(name, value.clone());
        }
    }
    // RFC 7515 4.1.11: crit is protected, lists what must be understood,
    // and each name it lists must be present.
    if let Some(crit) = joined.get("crit") {
        if protected.get("crit").is_none() {
            return Err("\"crit\" must be in the protected header.".to_string());
        }
        let Json::Array(names) = crit else { return Err("\"crit\" is a list.".to_string()) };
        if names.is_empty() {
            return Err("\"crit\" is an empty list.".to_string());
        }
        for name in names {
            let name = name.as_str().ok_or("\"crit\" lists strings.")?;
            if !UNDERSTOOD.contains(&name) {
                return Err(format!("\"crit\" names {name:?}, which is not understood."));
            }
            if protected.get(name).is_none() {
                return Err(format!("\"crit\" names {name:?}, which is not in the protected \
                                    header."));
            }
        }
    }
    // RFC 7797 3: b64 is protected and critical, or absent.
    let b64 = match protected.get("b64") {
        None => {
            if signature.header.as_ref().is_some_and(|h| h.get("b64").is_some()) {
                return Err("\"b64\" must be in the protected header.".to_string());
            }
            true
        }
        Some(Json::Bool(value)) => {
            let critical = matches!(protected.get("crit"), Some(Json::Array(names))
                                    if names.iter().any(|n| n.as_str() == Some("b64")));
            if !critical {
                return Err("\"b64\" must be listed in \"crit\".".to_string());
            }
            *value
        }
        Some(_) => return Err("\"b64\" is true or false.".to_string()),
    };
    let alg = joined.str("alg").ok_or("A JWS header with no \"alg\".")?.to_string();
    Ok(Headers { joined, alg, b64 })
}

fn signing_input(protected: &str, payload_text: &[u8]) -> Vec<u8> {
    let mut input = protected.as_bytes().to_vec();
    input.push(b'.');
    input.extend_from_slice(payload_text);
    input
}

/// What to sign with: a key, its algorithm, extra protected members and
/// an unprotected header.
pub struct Signer<'a> {
    pub key: &'a Jwk,
    pub alg: &'a str,
    pub protected: Json,
    pub header: Option<Json>,
}

/// Sign `payload` once per signer. `encode` false is RFC 7797's
/// unencoded payload, marked critical in every protected header.
pub fn sign(payload: &[u8], signers: &[Signer], encode: bool) -> Result<Jws, String> {
    let payload_text = if encode { b64(payload).into_bytes() } else { payload.to_vec() };
    let mut signatures = Vec::new();
    for signer in signers {
        let mut protected = Json::object();
        protected.set("alg", Json::string(signer.alg));
        if let Some(kid) = &signer.key.kid {
            protected.set("kid", Json::string(kid));
        }
        for (name, value) in signer.protected.members() {
            protected.set(name, value.clone());
        }
        if !encode {
            protected.set("b64", Json::Bool(false));
            protected.set("crit", Json::Array(vec![Json::string("b64")]));
        }
        let protected_text = b64(protected.to_text().as_bytes());
        let signature = sign_input(signer.alg, signer.key,
                                   &signing_input(&protected_text, &payload_text))?;
        signatures.push(Signature { protected: protected_text, header: signer.header.clone(),
                                    signature });
    }
    Ok(Jws { payload_text, signatures })
}

/// Verify, with `key`, any one signature whose algorithm it can check;
/// return the payload. `none` is refused unless `allow_none`, and then
/// only with no key at all. `detached` is the payload of a JWS that
/// carries none, as the serialization would have carried it.
pub fn verify(jws: &Jws, key: Option<&Jwk>, allow_none: bool, detached: Option<&[u8]>)
              -> Result<Vec<u8>, String> {
    let payload_text = match detached {
        Some(payload) if jws.payload_text.is_empty() => payload,
        Some(_) => return Err("A detached payload for a JWS that carries one.".to_string()),
        None => &jws.payload_text[..],
    };
    // Every signature's headers are checked, and RFC 7797 3 has them all
    // read the payload the same way, before any is verified: a JWS is
    // not valid because one of its signatures is, if another makes it
    // malformed.
    let all: Vec<Headers> = jws.signatures.iter().map(headers).collect::<Result<_, _>>()?;
    if all.iter().any(|h| h.b64 != all[0].b64) {
        return Err("Signatures disagree on \"b64\".".to_string());
    }
    let mut last_error = "No signature to verify.".to_string();
    for (signature, headers) in jws.signatures.iter().zip(all) {
        let input = signing_input(&signature.protected, payload_text);
        let verified = match (headers.alg.as_str(), key) {
            ("none", None) if allow_none => signature.signature.is_empty(),
            ("none", _) => {
                last_error = "An unsecured JWS (\"alg\": \"none\"); pass --allow-none, and no \
                              key, to accept one.".to_string();
                continue;
            }
            (_, None) => {
                last_error = format!("{} needs a key.", headers.alg);
                continue;
            }
            (alg, Some(key)) => {
                if let (Some(want), Some(have)) = (headers.joined.str("kid"), &key.kid) {
                    if want != have {
                        last_error = format!("The signature is by kid {want:?}, the key is \
                                              {have:?}.");
                        continue;
                    }
                }
                match verify_input(alg, key, &input, &signature.signature) {
                    Ok(v) => v,
                    Err(e) => {
                        last_error = e;
                        continue;
                    }
                }
            }
        };
        if verified {
            return if headers.b64 { unb64(std::str::from_utf8(payload_text)
                                          .map_err(|_| "A payload that is not base64url.")?) }
                   else { Ok(payload_text.to_vec()) };
        }
        last_error = "The signature does not verify.".to_string();
    }
    Err(last_error)
}

impl Jws {
    /// Compact: `protected.payload.signature`, one signature, no
    /// unprotected header.
    pub fn compact(&self) -> Result<String, String> {
        let [signature] = &self.signatures[..] else {
            return Err("A compact JWS has exactly one signature.".to_string());
        };
        if signature.header.is_some() {
            return Err("A compact JWS has no unprotected header.".to_string());
        }
        let payload = std::str::from_utf8(&self.payload_text)
            .map_err(|_| "An unencoded payload that is not text cannot be compact.")?;
        if payload.contains('.') {
            return Err("An unencoded payload with a '.' cannot be compact.".to_string());
        }
        Ok(format!("{}.{}.{}", signature.protected, payload, b64(&signature.signature)))
    }

    /// The general JSON serialization, or the flattened one.
    pub fn json(&self, flattened: bool) -> Result<String, String> {
        let payload = match std::str::from_utf8(&self.payload_text) {
            Ok(text) => text.to_string(),
            Err(_) => return Err("An unencoded payload that is not UTF-8 cannot be JSON."
                .to_string()),
        };
        let entry = |s: &Signature| {
            let mut json = Json::object();
            if !s.protected.is_empty() {
                json.set("protected", Json::string(&s.protected));
            }
            if let Some(header) = &s.header {
                json.set("header", header.clone());
            }
            json.set("signature", Json::string(&b64(&s.signature)));
            json
        };
        let mut out = Json::object();
        out.set("payload", Json::String(payload));
        if flattened {
            let [signature] = &self.signatures[..] else {
                return Err("A flattened JWS has exactly one signature.".to_string());
            };
            for (name, value) in entry(signature).members() {
                out.set(name, value.clone());
            }
        } else {
            out.set("signatures", Json::Array(self.signatures.iter().map(entry).collect()));
        }
        Ok(out.to_text())
    }

    /// Either serialization. A compact JWS with an empty payload part
    /// has a detached payload.
    pub fn parse(text: &str) -> Result<Jws, String> {
        let text = text.trim();
        if !text.starts_with('{') {
            let parts: Vec<&str> = text.split('.').collect();
            let [protected, payload, signature] = parts[..] else {
                return Err("A compact JWS is three parts.".to_string());
            };
            if protected.is_empty() {
                return Err("A compact JWS needs its protected header.".to_string());
            }
            return Ok(Jws { payload_text: payload.as_bytes().to_vec(),
                            signatures: vec![Signature { protected: protected.to_string(),
                                                         header: None,
                                                         signature: unb64(signature)? }] });
        }
        let json = json::parse(text)?;
        let payload = json.get("payload").map(|p| p.as_str().ok_or("\"payload\" is a string."))
            .transpose()?.unwrap_or("");
        let read = |entry: &Json| -> Result<Signature, String> {
            Ok(Signature {
                protected: entry.str("protected").unwrap_or("").to_string(),
                header: entry.get("header").cloned(),
                signature: unb64(entry.str("signature").ok_or("A signature entry with no \
                                                               \"signature\".")?)?,
            })
        };
        let signatures = match json.get("signatures") {
            Some(Json::Array(entries)) => {
                if json.get("signature").is_some() || json.get("protected").is_some() {
                    return Err("A JWS that is both general and flattened.".to_string());
                }
                entries.iter().map(read).collect::<Result<_, _>>()?
            }
            Some(_) => return Err("\"signatures\" is a list.".to_string()),
            None => vec![read(&json)?],
        };
        Ok(Jws { payload_text: payload.as_bytes().to_vec(), signatures })
    }
}
