//! JSON Web Keys (RFC 7517), with RFC 7518 section 6's key types, RFC
//! 8037's OKP keys and RFC 7638's thumbprint.

use crate::json::Json;
use allcrypt::api::{EcKey, EcPublicKey, RsaKey, RsaPublicKey};

// ---------------------------------------------------------------- base64url --

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding (RFC 7515 section 2).
pub fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// The other way, strictly: no padding, no whitespace, nothing outside
/// the URL-safe alphabet, and no bits set past the last byte - a value
/// with two spellings is a value two parsers can disagree about.
pub fn unb64(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 4 == 1 {
        return Err(format!("{text:?} is not base64url: a length of 4n+1."));
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut bits = 0u32;
    let mut count = 0;
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c)
            .ok_or_else(|| format!("{:?} in base64url {text:?}.", c as char))?;
        bits = bits << 6 | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if bits != 0 {
        return Err(format!("base64url {text:?} has bits set past its last byte."));
    }
    Ok(out)
}

// --------------------------------------------------------------------- keys --

/// The JOSE curve name and the library's, and the field width.
const EC_CURVES: [(&str, &str, usize); 4] = [("P-256", "P-256", 32), ("P-384", "P-384", 48),
                                             ("P-521", "P-521", 66),
                                             ("secp256k1", "secp256k1", 32)];

/// RFC 8037's curves, with their key lengths.
const OKP_CURVES: [(&str, usize); 4] = [("Ed25519", 32), ("Ed448", 57), ("X25519", 32),
                                        ("X448", 56)];

pub enum Key {
    Oct(Vec<u8>),
    Rsa { public: RsaPublicKey, private: Option<Box<RsaKey>> },
    /// `point` is SEC1's uncompressed `04 || x || y`.
    Ec { crv: &'static str, point: Vec<u8>, private: Option<Vec<u8>> },
    Okp { crv: &'static str, x: Vec<u8>, d: Option<Vec<u8>> },
}

/// A key and the members that travel with it.
pub struct Jwk {
    pub key: Key,
    pub kid: Option<String>,
    pub alg: Option<String>,
}

fn member(json: &Json, name: &str) -> Result<Vec<u8>, String> {
    unb64(json.str(name).ok_or_else(|| format!("The JWK has no {name:?}."))?)
}

fn optional(json: &Json, name: &str) -> Result<Option<Vec<u8>>, String> {
    json.str(name).map(unb64).transpose()
}

/// A big-endian integer as RFC 7518 writes it: no leading zero bytes,
/// except that zero itself is one byte.
fn unsigned(bytes: &[u8]) -> &[u8] {
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(bytes.len().saturating_sub(1));
    &bytes[skip..]
}

impl Jwk {
    pub fn parse(json: &Json) -> Result<Jwk, String> {
        let kty = json.str("kty").ok_or("The JWK has no \"kty\".")?;
        let key = match kty {
            "oct" => Key::Oct(member(json, "k")?),
            "RSA" => {
                let (n, e) = (member(json, "n")?, member(json, "e")?);
                let public = RsaPublicKey::new(&n, &e)?;
                let private = match optional(json, "d")? {
                    None => None,
                    Some(d) => {
                        let (p, q) = match (optional(json, "p")?, optional(json, "q")?) {
                            (Some(p), Some(q)) => (p, q),
                            _ => return Err("An RSA private JWK without its primes; this \
                                             library builds keys from p and q.".to_string()),
                        };
                        let key = RsaKey::from_primes(&p, &q, &e)?;
                        let numbers = key.numbers();
                        let get = |name| numbers.iter().find(|(k, _)| *k == name)
                            .map(|(_, v)| v.clone()).unwrap_or_default();
                        // d is one of many exponents that work - modulo
                        // lcm(p-1, q-1) or (p-1)(q-1), as the writer chose -
                        // so it is checked by what it does to each prime.
                        use allcrypt::bignum::BigUint;
                        let big = |bytes: &[u8]| BigUint::from_bytes_be(bytes);
                        let reduced = |prime: &[u8]| -> Result<Vec<u8>, String> {
                            let less_one = big(prime).sub(&BigUint::one())?;
                            Ok(big(&d).rem(&less_one)?.to_bytes_be())
                        };
                        if get("n") != unsigned(&n) || reduced(&p)? != unsigned(&get("dp"))
                            || reduced(&q)? != unsigned(&get("dq")) {
                            return Err("The RSA JWK's n or d does not follow from its \
                                        primes.".to_string());
                        }
                        Some(Box::new(key))
                    }
                };
                Key::Rsa { public, private }
            }
            "EC" => {
                let name = json.str("crv").ok_or("An EC JWK has no \"crv\".")?;
                let (crv, library, width) = EC_CURVES.iter().find(|c| c.0 == name).copied()
                    .ok_or_else(|| format!("An EC JWK on {name:?}, which is not implemented."))?;
                let (x, y) = (member(json, "x")?, member(json, "y")?);
                // RFC 7518 6.2.1.2: the full width of the field, always.
                if x.len() != width || y.len() != width {
                    return Err(format!("An {crv} JWK's x and y are {width} bytes each."));
                }
                let mut point = vec![4];
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                EcPublicKey::from_bytes(library, &point)?;
                let private = optional(json, "d")?;
                if let Some(d) = &private {
                    if d.len() != width {
                        return Err(format!("An {crv} JWK's d is {width} bytes."));
                    }
                    let key = EcKey::from_private(library, d)?;
                    if key.public_bytes(false)? != point {
                        return Err("The EC JWK's d is not the private key of x and y."
                            .to_string());
                    }
                }
                Key::Ec { crv, point, private }
            }
            "OKP" => {
                let name = json.str("crv").ok_or("An OKP JWK has no \"crv\".")?;
                let (crv, length) = OKP_CURVES.iter().find(|c| c.0 == name).copied()
                    .ok_or_else(|| format!("An OKP JWK on {name:?}, which is not \
                                            implemented."))?;
                let x = member(json, "x")?;
                let d = optional(json, "d")?;
                if x.len() != length || d.as_ref().is_some_and(|d| d.len() != length) {
                    return Err(format!("An {crv} key is {length} bytes."));
                }
                if let Some(d) = &d {
                    if okp_public(crv, d)? != x {
                        return Err("The OKP JWK's d is not the private key of x.".to_string());
                    }
                }
                Key::Okp { crv, x, d }
            }
            other => return Err(format!("A JWK of type {other:?}.")),
        };
        Ok(Jwk { key, kid: json.str("kid").map(str::to_string),
                 alg: json.str("alg").map(str::to_string) })
    }

    #[cfg(test)]
    pub fn from_text(text: &str) -> Result<Jwk, String> {
        Jwk::parse(&crate::json::parse(text)?)
    }

    pub fn is_private(&self) -> bool {
        match &self.key {
            Key::Oct(_) => true,
            Key::Rsa { private, .. } => private.is_some(),
            Key::Ec { private, .. } => private.is_some(),
            Key::Okp { d, .. } => d.is_some(),
        }
    }

    pub fn kty(&self) -> &'static str {
        match self.key {
            Key::Oct(_) => "oct",
            Key::Rsa { .. } => "RSA",
            Key::Ec { .. } => "EC",
            Key::Okp { .. } => "OKP",
        }
    }

    /// The key's required members, as RFC 7638 orders them: the
    /// thumbprint's input, and the start of any JWK this writes.
    fn required(&self) -> Json {
        let mut json = Json::object();
        match &self.key {
            Key::Oct(k) => {
                json.set("k", Json::string(&b64(k)));
                json.set("kty", Json::string("oct"));
            }
            Key::Rsa { public, .. } => {
                json.set("e", Json::string(&b64(&public.exponent())));
                json.set("kty", Json::string("RSA"));
                json.set("n", Json::string(&b64(&public.modulus())));
            }
            Key::Ec { crv, point, .. } => {
                let width = (point.len() - 1) / 2;
                json.set("crv", Json::string(crv));
                json.set("kty", Json::string("EC"));
                json.set("x", Json::string(&b64(&point[1..1 + width])));
                json.set("y", Json::string(&b64(&point[1 + width..])));
            }
            Key::Okp { crv, x, .. } => {
                json.set("crv", Json::string(crv));
                json.set("kty", Json::string("OKP"));
                json.set("x", Json::string(&b64(x)));
            }
        }
        json
    }

    /// RFC 7638: SHA-256 over the required members, sorted, no
    /// whitespace.
    pub fn thumbprint(&self) -> String {
        b64(&crate::sha(256, self.required().to_text().as_bytes()))
    }

    /// The JWK as JSON, with the private members when asked for and
    /// held.
    pub fn to_json(&self, private: bool) -> Json {
        let mut json = self.required();
        if private {
            match &self.key {
                Key::Rsa { private: Some(key), .. } => {
                    let numbers = key.numbers();
                    for (ours, theirs) in [("d", "d"), ("p", "p"), ("q", "q"), ("dp", "dp"),
                                           ("dq", "dq"), ("qinv", "qi")] {
                        if let Some((_, value)) = numbers.iter().find(|(k, _)| *k == ours) {
                            json.set(theirs, Json::string(&b64(value)));
                        }
                    }
                }
                Key::Ec { private: Some(d), .. } => json.set("d", Json::string(&b64(d))),
                Key::Okp { d: Some(d), .. } => json.set("d", Json::string(&b64(d))),
                _ => {}
            }
        } else if let Key::Oct(_) = self.key {
            // A symmetric key has no public half to show.
            return Json::object();
        }
        if let Some(kid) = &self.kid {
            json.set("kid", Json::string(kid));
        }
        if let Some(alg) = &self.alg {
            json.set("alg", Json::string(alg));
        }
        json
    }

    /// A new key: `RSA` with a size in bits, `EC` or `OKP` with a curve,
    /// `oct` with a size in bytes.
    pub fn generate(kty: &str, parameter: &str) -> Result<Jwk, String> {
        let key = match kty {
            "oct" => {
                let bytes: usize = parameter.parse().map_err(|_| "An oct key's size is bytes.")?;
                Key::Oct(allcrypt::api::random_bytes(bytes)?)
            }
            "RSA" => {
                let bits: usize = parameter.parse().map_err(|_| "An RSA key's size is bits.")?;
                let private = RsaKey::generate(bits)?;
                Key::Rsa { public: private.public_key(), private: Some(Box::new(private)) }
            }
            "EC" => {
                let (crv, library, _) = EC_CURVES.iter().find(|c| c.0 == parameter).copied()
                    .ok_or_else(|| format!("No EC curve {parameter:?}."))?;
                let key = EcKey::generate(library)?;
                Key::Ec { crv, point: key.public_bytes(false)?,
                          private: Some(key.private_bytes()?) }
            }
            "OKP" => {
                let (crv, length) = OKP_CURVES.iter().find(|c| c.0 == parameter).copied()
                    .ok_or_else(|| format!("No OKP curve {parameter:?}."))?;
                let d = allcrypt::api::random_bytes(length)?;
                Key::Okp { crv, x: okp_public(crv, &d)?, d: Some(d) }
            }
            other => return Err(format!("No key type {other:?}: RSA, EC, OKP or oct.")),
        };
        Ok(Jwk { key, kid: None, alg: None })
    }

    /// The library's name for an EC key's curve.
    pub fn ec_library_curve(crv: &str) -> Result<&'static str, String> {
        EC_CURVES.iter().find(|c| c.0 == crv).map(|c| c.1)
            .ok_or_else(|| format!("No EC curve {crv:?}."))
    }
}

/// An OKP key's public half from its private one.
pub fn okp_public(crv: &str, d: &[u8]) -> Result<Vec<u8>, String> {
    match crv {
        "Ed25519" | "Ed448" => allcrypt::api::eddsa_public_key(&crv.to_lowercase(), d),
        "X25519" => allcrypt::api::x25519_public_key(d),
        "X448" => allcrypt::api::x448_public_key(d),
        other => Err(format!("No OKP curve {other:?}.")),
    }
}

/// A JWK, or the one in a JWK Set that matches `kid` - the only one if
/// the set has one and no `kid` is asked for.
pub fn select(text: &str, kid: Option<&str>) -> Result<Jwk, String> {
    let json = crate::json::parse(text)?;
    let Some(Json::Array(keys)) = json.get("keys") else { return Jwk::parse(&json) };
    let keys: Vec<Jwk> = keys.iter().map(Jwk::parse).collect::<Result<_, _>>()?;
    let mut matching: Vec<Jwk> = keys.into_iter()
        .filter(|k| kid.is_none() || k.kid.as_deref() == kid).collect();
    match matching.len() {
        1 => Ok(matching.remove(0)),
        0 => Err(format!("No key in the set has kid {kid:?}.")),
        _ => Err("Several keys in the set match; name one by its kid.".to_string()),
    }
}
