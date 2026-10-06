//! Keys (RFC 9580 section 5.5): public and secret key packets of
//! versions 3, 4, 5 (LibrePGP) and 6, their fingerprints, the protection
//! of their secret parts, and transferable keys - a primary key with its
//! user IDs, subkeys and signatures.

use crate::algo::{self, Cipher};
use crate::packet::{self, Packet, Reader};
use crate::s2k::S2k;
use allcrypt::bignum::BigUint;

pub const RSA: u8 = 1;
pub const RSA_ENCRYPT: u8 = 2;
pub const RSA_SIGN: u8 = 3;
pub const ELGAMAL: u8 = 16;
pub const DSA: u8 = 17;
pub const ECDH: u8 = 18;
pub const ECDSA: u8 = 19;
/// ElGamal that may also sign: GnuPG 1.x made these, and signatures
/// with them are broken (Nguyen 2004). Read for decryption only.
pub const ELGAMAL_SIGN: u8 = 20;
pub const EDDSA_LEGACY: u8 = 22;
pub const X25519: u8 = 25;
pub const X448: u8 = 26;
pub const ED25519: u8 = 27;
pub const ED448: u8 = 28;

pub fn algorithm_name(id: u8) -> &'static str {
    match id {
        RSA => "RSA",
        RSA_ENCRYPT => "RSA (encrypt only)",
        RSA_SIGN => "RSA (sign only)",
        ELGAMAL => "ElGamal",
        DSA => "DSA",
        ECDH => "ECDH",
        ECDSA => "ECDSA",
        ELGAMAL_SIGN => "ElGamal (encrypt or sign)",
        EDDSA_LEGACY => "EdDSA (legacy)",
        X25519 => "X25519",
        X448 => "X448",
        ED25519 => "Ed25519",
        ED448 => "Ed448",
        _ => "unknown",
    }
}

pub fn can_sign(id: u8) -> bool {
    matches!(id, RSA | RSA_SIGN | DSA | ECDSA | ELGAMAL_SIGN | EDDSA_LEGACY | ED25519 | ED448)
}

pub fn can_encrypt(id: u8) -> bool {
    matches!(id, RSA | RSA_ENCRYPT | ELGAMAL | ELGAMAL_SIGN | ECDH | X25519 | X448)
}

/// An elliptic curve as OpenPGP names it: by OID (RFC 9580 table 19,
/// and secp256k1, which GnuPG also has).
#[derive(Debug, PartialEq)]
pub struct Curve {
    pub name: &'static str,
    pub dotted: &'static str,
    /// The library's name for the curve, for the ones with Weierstrass
    /// arithmetic there.
    pub library: Option<&'static str>,
    /// Field size in bytes.
    pub field: usize,
}

pub const CURVES: &[Curve] = &[
    Curve { name: "NIST P-256", dotted: "1.2.840.10045.3.1.7", library: Some("P-256"), field: 32 },
    Curve { name: "NIST P-384", dotted: "1.3.132.0.34", library: Some("P-384"), field: 48 },
    Curve { name: "NIST P-521", dotted: "1.3.132.0.35", library: Some("P-521"), field: 66 },
    // The library does not carry the Brainpool curves; they are
    // registered from RFC 5639's text the first time one is used
    // (`register_brainpool`).
    Curve { name: "brainpoolP256r1", dotted: "1.3.36.3.3.2.8.1.1.7",
            library: Some("brainpoolP256r1"), field: 32 },
    Curve { name: "brainpoolP384r1", dotted: "1.3.36.3.3.2.8.1.1.11",
            library: Some("brainpoolP384r1"), field: 48 },
    Curve { name: "brainpoolP512r1", dotted: "1.3.36.3.3.2.8.1.1.13",
            library: Some("brainpoolP512r1"), field: 64 },
    Curve { name: "Ed25519Legacy", dotted: "1.3.6.1.4.1.11591.15.1", library: None, field: 32 },
    Curve { name: "Curve25519Legacy", dotted: "1.3.6.1.4.1.3029.1.5.1", library: None,
            field: 32 },
    Curve { name: "secp256k1", dotted: "1.3.132.0.10", library: Some("secp256k1"), field: 32 },
    // LibrePGP's (GnuPG's) version 5 keys: EdDSA and ECDH over Ed448 and
    // X448, and RFC 8410's OIDs for the 25519 pair. The points are
    // native octet strings without RFC 9580's 0x40 prefix.
    Curve { name: "Ed448", dotted: "1.3.101.113", library: None, field: 57 },
    Curve { name: "X448", dotted: "1.3.101.111", library: None, field: 56 },
    Curve { name: "Ed25519", dotted: "1.3.101.112", library: None, field: 32 },
    Curve { name: "X25519", dotted: "1.3.101.110", library: None, field: 32 },
];

/// A native point from its stored form: RFC 9580's `0x40 || native`,
/// or LibrePGP's bare native string, whose leading zero bytes the MPI
/// encoding may have dropped.
pub fn native_point(point: &[u8], field: usize) -> Result<Vec<u8>, String> {
    if point.len() == field + 1 && point[0] == 0x40 {
        return Ok(point[1..].to_vec());
    }
    if point.len() > field {
        return Err("a point longer than its curve's field".to_string());
    }
    let mut out = vec![0u8; field - point.len()];
    out.extend_from_slice(point);
    Ok(out)
}

const RFC5639: &str = include_str!("../../../rfcs/rfc5639.txt");

/// A Brainpool curve's domain parameters, read out of RFC 5639 section 3
/// (`p`, `A`, `B`, `x`, `y`, `q`, `h` after its `Curve-ID` line; a value
/// may start on its label's line or the next, and run over two).
pub fn brainpool_parameters(name: &str)
                            -> Result<allcrypt::ec::curves::CurveParameters, String> {
    use allcrypt::bignum::BigUint;
    let start = RFC5639.find(&format!("Curve-ID: {name}\n"))
        .ok_or_else(|| format!("{name} is not in RFC 5639"))?;
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in RFC5639[start..].lines().skip(1) {
        if line.starts_with("Lochter & Merkle") || line.starts_with("RFC 5639") {
            continue;
        }
        let t = line.trim();
        if t.starts_with("Curve-ID:") || t.starts_with('#') || t.starts_with("3.") {
            break;
        }
        if let Some((label, rest)) = t.split_once(" =") {
            fields.push((label.to_string(), rest.trim().to_string()));
        } else if !t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            fields.last_mut().ok_or("hex before any label")?.1.push_str(t);
        }
    }
    let get = |label: &str| -> Result<BigUint, String> {
        let text = &fields.iter().find(|(l, _)| l == label)
            .ok_or_else(|| format!("{name}: no {label} in RFC 5639"))?.1;
        BigUint::from_hex(text)
    };
    Ok(allcrypt::ec::curves::CurveParameters {
        name: name.to_string(), p: get("p")?, a: get("A")?, b: get("B")?, gx: get("x")?,
        gy: get("y")?, n: get("q")?, h: get("h")?,
    })
}

/// Register the three Brainpool curves with the library, once.
pub fn register_brainpool() -> Result<(), String> {
    static DONE: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    DONE.get_or_init(|| {
        for curve in CURVES.iter().filter(|c| c.name.starts_with("brainpool")) {
            let parameters = brainpool_parameters(curve.name)?;
            allcrypt::registry::register(
                curve.dotted, allcrypt::registry::Meaning::curve_parameters(parameters))?;
        }
        Ok(())
    }).clone()
}

pub const CURVE25519_LEGACY: &str = "Curve25519Legacy";

/// The DER body of a dotted OID (without tag and length), which is how
/// OpenPGP writes a curve.
pub fn oid_bytes(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut out = Vec::new();
    for (i, &arc) in arcs.iter().enumerate().skip(1) {
        let value = if i == 1 { arcs[0] * 40 + arc } else { arc };
        let mut groups = vec![(value & 0x7f) as u8];
        let mut rest = value >> 7;
        while rest > 0 {
            groups.push((rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        out.extend(groups.iter().rev());
    }
    out
}

pub fn curve_by_oid(oid: &[u8]) -> Option<&'static Curve> {
    CURVES.iter().find(|c| oid_bytes(c.dotted) == oid)
}

/// The public part of a key, by algorithm.
#[derive(Clone, Debug, PartialEq)]
pub enum Material {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Dsa { p: Vec<u8>, q: Vec<u8>, g: Vec<u8>, y: Vec<u8> },
    ElGamal { p: Vec<u8>, g: Vec<u8>, y: Vec<u8> },
    /// ECDSA and EdDSA (legacy): the curve's OID and the point as stored
    /// (SEC1 for Weierstrass curves, `0x40 || native` for Ed25519).
    Ec { oid: Vec<u8>, point: Vec<u8> },
    /// ECDH adds the KDF's hash and the key wrap's cipher.
    Ecdh { oid: Vec<u8>, point: Vec<u8>, hash: u8, cipher: u8 },
    /// X25519, X448, Ed25519, Ed448: the native public key.
    Native(Vec<u8>),
    Unknown(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    pub version: u8,
    pub created: u32,
    /// Version 3 only: days of validity, 0 for none.
    pub expiry_days: u16,
    pub algorithm: u8,
    pub material: Material,
    /// The packet body up to the end of the public material: what the
    /// fingerprint hashes and what a signature over the key covers.
    pub body: Vec<u8>,
}

/// A multiprecision integer's value bytes as stored.
fn mpi<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], String> {
    let bits = u16::from_be_bytes(r.bytes(2)?.try_into().unwrap()) as usize;
    r.bytes(bits.div_ceil(8))
}

/// An MPI holding `value`, leading zero bytes removed.
pub fn write_mpi(value: &[u8], out: &mut Vec<u8>) {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let value = &value[start..];
    let bits = if value.is_empty() { 0 } else {
        (value.len() - 1) * 8 + (8 - value[0].leading_zeros() as usize)
    };
    out.extend_from_slice(&(bits as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// A fixed-length octet string as GnuPG writes one into an MPI field
/// (its "SOS"): a leading zero byte is kept, with the bit count of the
/// whole string, where an MPI would drop it. GnuPG's Ed448 and X448
/// values must keep their full length.
pub fn write_sos(value: &[u8], out: &mut Vec<u8>) {
    if value.first() == Some(&0) {
        out.extend_from_slice(&((value.len() * 8) as u16).to_be_bytes());
        out.extend_from_slice(value);
    } else {
        write_mpi(value, out);
    }
}

fn oid(r: &mut Reader<'_>) -> Result<Vec<u8>, String> {
    let len = r.u8()? as usize;
    if len == 0 || len == 0xff {
        return Err("a curve OID length of 0 or 255 is reserved".to_string());
    }
    Ok(r.bytes(len)?.to_vec())
}

fn read_material(algorithm: u8, r: &mut Reader<'_>, length: Option<usize>)
                 -> Result<Material, String> {
    let start = r.at;
    let material = match algorithm {
        RSA | RSA_ENCRYPT | RSA_SIGN =>
            Material::Rsa { n: mpi(r)?.to_vec(), e: mpi(r)?.to_vec() },
        DSA => Material::Dsa { p: mpi(r)?.to_vec(), q: mpi(r)?.to_vec(), g: mpi(r)?.to_vec(),
                               y: mpi(r)?.to_vec() },
        ELGAMAL | ELGAMAL_SIGN =>
            Material::ElGamal { p: mpi(r)?.to_vec(), g: mpi(r)?.to_vec(), y: mpi(r)?.to_vec() },
        ECDSA | EDDSA_LEGACY => Material::Ec { oid: oid(r)?, point: mpi(r)?.to_vec() },
        ECDH => {
            let oid = oid(r)?;
            let point = mpi(r)?.to_vec();
            let kdf_len = r.u8()?;
            if kdf_len != 3 || r.u8()? != 1 {
                return Err("ECDH KDF parameters other than version 1".to_string());
            }
            Material::Ecdh { oid, point, hash: r.u8()?, cipher: r.u8()? }
        }
        X25519 => Material::Native(r.bytes(32)?.to_vec()),
        X448 => Material::Native(r.bytes(56)?.to_vec()),
        ED25519 => Material::Native(r.bytes(32)?.to_vec()),
        ED448 => Material::Native(r.bytes(57)?.to_vec()),
        _ => match length {
            Some(n) => Material::Unknown(r.bytes(n)?.to_vec()),
            None => return Err(format!("public key algorithm {algorithm} is not one this \
                                        program has")),
        },
    };
    if let Some(n) = length {
        if r.at - start != n {
            return Err("a key's material is not the length its count says".to_string());
        }
    }
    Ok(material)
}

impl PublicKey {
    /// Read the public part from the start of a key packet's body.
    /// Returns it and how many bytes it took.
    pub fn read(body: &[u8]) -> Result<(PublicKey, usize), String> {
        let mut r = Reader::new(body);
        let version = r.u8()?;
        let created = r.u32()?;
        let mut expiry_days = 0;
        let algorithm;
        let material = match version {
            2 | 3 => {
                expiry_days = u16::from_be_bytes(r.bytes(2)?.try_into().unwrap());
                algorithm = r.u8()?;
                if !matches!(algorithm, RSA | RSA_ENCRYPT | RSA_SIGN) {
                    return Err("a version 3 key that is not RSA".to_string());
                }
                read_material(algorithm, &mut r, None)?
            }
            4 => {
                algorithm = r.u8()?;
                read_material(algorithm, &mut r, None)?
            }
            5 | 6 => {
                algorithm = r.u8()?;
                let count = r.u32()? as usize;
                read_material(algorithm, &mut r, Some(count))?
            }
            v => return Err(format!("key version {v} is not one this program reads")),
        };
        let used = r.at;
        Ok((PublicKey { version, created, expiry_days, algorithm, material,
                        body: body[..used].to_vec() }, used))
    }

    pub fn fingerprint(&self) -> Vec<u8> {
        match self.version {
            2 | 3 => {
                let Material::Rsa { n, e } = &self.material else { unreachable!() };
                algo::digest(algo::hash(1).unwrap(), &[n, e])
            }
            4 => {
                let len = (self.body.len() as u16).to_be_bytes();
                algo::digest(algo::hash(2).unwrap(), &[&[0x99], &len, &self.body])
            }
            v => {
                let len = (self.body.len() as u32).to_be_bytes();
                let prefix = if v == 5 { 0x9A } else { 0x9B };
                algo::digest(algo::hash(8).unwrap(), &[&[prefix], &len, &self.body])
            }
        }
    }

    pub fn key_id(&self) -> [u8; 8] {
        match self.version {
            2 | 3 => {
                let Material::Rsa { n, .. } = &self.material else { unreachable!() };
                let mut id = [0u8; 8];
                let take = n.len().min(8);
                id[8 - take..].copy_from_slice(&n[n.len() - take..]);
                id
            }
            4 => self.fingerprint()[12..].try_into().unwrap(),
            _ => self.fingerprint()[..8].try_into().unwrap(),
        }
    }

    pub fn curve(&self) -> Option<&'static Curve> {
        match &self.material {
            Material::Ec { oid, .. } | Material::Ecdh { oid, .. } => curve_by_oid(oid),
            _ => None,
        }
    }

    /// "RSA 3072", "ECDH NIST P-256", "Ed25519" - for listing.
    pub fn describe(&self) -> String {
        match &self.material {
            Material::Rsa { n, .. } => format!("RSA {}", bit_len(n)),
            Material::Dsa { p, q, .. } => format!("DSA {}/{}", bit_len(p), bit_len(q)),
            Material::ElGamal { p, .. } => format!("ElGamal {}", bit_len(p)),
            Material::Ec { oid, .. } | Material::Ecdh { oid, .. } => format!(
                "{} {}", algorithm_name(self.algorithm),
                curve_by_oid(oid).map_or_else(|| format!("curve {}", hex_upper(oid)),
                                              |c| c.name.to_string())),
            _ => algorithm_name(self.algorithm).to_string(),
        }
    }
}

fn bit_len(n: &[u8]) -> usize {
    let start = n.iter().position(|&b| b != 0).unwrap_or(n.len());
    if start == n.len() { 0 } else { (n.len() - start) * 8 - n[start].leading_zeros() as usize }
}

pub fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// The secret part of a key, by algorithm, as numbers or native bytes.
#[derive(Clone, Debug)]
pub enum Secret {
    /// d and u are read and checked for form, and recomputed when needed.
    Rsa { p: Vec<u8>, q: Vec<u8> },
    /// DSA's and ElGamal's x, and an ECDSA or ECDH scalar (big endian;
    /// for Curve25519Legacy, the X25519 scalar reversed, as stored).
    Scalar(Vec<u8>),
    /// EdDSA legacy's 32 byte seed, and the native secrets of X25519,
    /// X448, Ed25519 and Ed448.
    Native(Vec<u8>),
}

/// How a secret key packet protects its secret part.
#[derive(Clone, Debug)]
pub enum Protection {
    None,
    /// 254: CFB with a SHA-1 inside; 255 and legacy cipher numbers: CFB
    /// with a two byte checksum.
    Cfb { usage: u8, cipher: Cipher, s2k: S2k, iv: Vec<u8> },
    /// 253: AEAD under an HKDF of the S2K output.
    Aead { cipher: Cipher, aead: algo::Aead, s2k: S2k, iv: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct SecretKey {
    pub public: PublicKey,
    /// The packet tag (5 or 7), which AEAD protection authenticates.
    pub tag: u8,
    pub protection: Protection,
    /// The secret part as stored: encrypted unless `Protection::None`.
    pub stored: Vec<u8>,
}

fn read_secret_material(public: &PublicKey, data: &[u8]) -> Result<Secret, String> {
    let mut r = Reader::new(data);
    let secret = match public.algorithm {
        RSA | RSA_ENCRYPT | RSA_SIGN => {
            mpi(&mut r)?;
            let (p, q) = (mpi(&mut r)?.to_vec(), mpi(&mut r)?.to_vec());
            mpi(&mut r)?;
            Secret::Rsa { p, q }
        }
        DSA | ELGAMAL | ELGAMAL_SIGN | ECDSA | ECDH => Secret::Scalar(mpi(&mut r)?.to_vec()),
        EDDSA_LEGACY => {
            let field = public.curve().map_or(32, |c| c.field);
            let value = mpi(&mut r)?;
            if value.len() > field {
                return Err("an EdDSA secret longer than its curve's".to_string());
            }
            let mut seed = vec![0u8; field - value.len()];
            seed.extend_from_slice(value);
            Secret::Native(seed)
        }
        X25519 | ED25519 => Secret::Native(r.bytes(32)?.to_vec()),
        X448 => Secret::Native(r.bytes(56)?.to_vec()),
        ED448 => Secret::Native(r.bytes(57)?.to_vec()),
        other => return Err(format!("no secret key format for algorithm {other}")),
    };
    if r.at != data.len() {
        return Err("the secret key material is not the length its fields say".to_string());
    }
    Ok(secret)
}

fn write_secret_material(public: &PublicKey, secret: &Secret, out: &mut Vec<u8>) {
    match secret {
        Secret::Rsa { p, q } => {
            // d and u from p and q (and e): d = e^-1 mod lcm... OpenPGP
            // takes d mod (p-1)(q-1), which every reader accepts.
            let Material::Rsa { e, .. } = &public.material else { unreachable!() };
            let (bp, bq) = (BigUint::from_bytes_be(p), BigUint::from_bytes_be(q));
            let one = BigUint::one();
            let phi = bp.sub(&one).unwrap().mul(&bq.sub(&one).unwrap());
            let d = BigUint::from_bytes_be(e).mod_inverse(&phi).expect("e is invertible");
            let u = bp.mod_inverse(&bq).expect("p is invertible mod q");
            for value in [d.to_bytes_be(), p.clone(), q.clone(), u.to_bytes_be()] {
                write_mpi(&value, out);
            }
        }
        Secret::Scalar(x) => write_mpi(x, out),
        Secret::Native(bytes) if public.algorithm == EDDSA_LEGACY => {
            if public.curve().is_some_and(|c| c.name == "Ed448") {
                write_sos(bytes, out);
            } else {
                write_mpi(bytes, out);
            }
        }
        Secret::Native(bytes) => out.extend_from_slice(bytes),
    }
}

impl SecretKey {
    /// A secret key packet body for `public` and `secret`, protected
    /// with `passphrase` unless it is empty: CFB with the SHA-1 inside
    /// (usage 254), which every reader takes, unless the S2K is Argon2
    /// or the key is version 6 - then AEAD (usage 253, OCB), as RFC 9580
    /// requires of both.
    pub fn write(public: &PublicKey, secret: &Secret, tag: u8, passphrase: &[u8], s2k: S2k,
                 random: crate::message::Random<'_>) -> Result<Vec<u8>, String> {
        let mut plain = Vec::new();
        write_secret_material(public, secret, &mut plain);
        let mut body = public.body.clone();
        let v6 = public.version == 6;
        if passphrase.is_empty() {
            body.push(0);
            body.extend_from_slice(&plain);
            if !v6 {
                body.extend_from_slice(&algo_checksum(&plain));
            }
            return Ok(body);
        }
        let cipher = algo::cipher(9)?;
        let mut s2k_bytes = Vec::new();
        s2k.write(&mut s2k_bytes);
        let derived = s2k.derive(passphrase, cipher.key_len)?;
        if v6 || matches!(s2k, S2k::Argon2 { .. }) {
            let aead = algo::aead(2)?;
            let mut iv = vec![0u8; aead.nonce_len];
            random(&mut iv)?;
            let mut params = vec![cipher.id, aead.id];
            if v6 {
                params.push(s2k_bytes.len() as u8);
            }
            params.extend_from_slice(&s2k_bytes);
            params.extend_from_slice(&iv);
            body.push(253);
            if v6 {
                body.push(params.len() as u8);
            }
            body.extend_from_slice(&params);
            let key = SecretKey { public: public.clone(), tag, protection: Protection::None,
                                  stored: Vec::new() };
            let (kek, aad) = key.aead_parameters(&derived, cipher, aead);
            body.extend(algo::seal(cipher, aead, &kek, &iv, &aad, &plain)?);
        } else {
            let mut iv = vec![0u8; cipher.block_len];
            random(&mut iv)?;
            body.extend_from_slice(&[254, cipher.id]);
            body.extend_from_slice(&s2k_bytes);
            body.extend_from_slice(&iv);
            let sha1 = algo::digest(algo::hash(2)?, &[&plain]);
            plain.extend_from_slice(&sha1);
            body.extend(algo::cfb(cipher, &derived, &iv, &plain, false)?);
        }
        Ok(body)
    }

    pub fn read(packet: &Packet) -> Result<SecretKey, String> {
        let (public, used) = PublicKey::read(&packet.body)?;
        let mut r = Reader::new(&packet.body);
        r.at = used;
        let version = public.version;
        let usage = r.u8()?;
        // Version 6 counts the parameter fields when there are any;
        // LibrePGP's version 5 always does.
        if version == 5 || (version == 6 && usage != 0) {
            r.u8()?;
        }
        let protection = match usage {
            0 => Protection::None,
            253 => {
                let cipher = algo::cipher(r.u8()?)?;
                let aead = algo::aead(r.u8()?)?;
                if version == 6 {
                    r.u8()?;
                }
                let s2k = S2k::read(&mut r)?;
                // LibrePGP's version 5 stores a block-sized IV whose
                // leading bytes are the nonce.
                let iv_len = if version == 5 { cipher.block_len } else { aead.nonce_len };
                let mut iv = r.bytes(iv_len)?.to_vec();
                iv.truncate(aead.nonce_len);
                Protection::Aead { cipher, aead, s2k, iv }
            }
            254 | 255 => {
                let cipher = algo::cipher(r.u8()?)?;
                if version == 6 && usage == 254 {
                    r.u8()?;
                }
                let s2k = S2k::read(&mut r)?;
                if matches!(s2k, S2k::Argon2 { .. }) {
                    return Err("Argon2 outside AEAD protection is malformed".to_string());
                }
                // GnuPG's stub for a key with no secret part has no IV.
                let iv = if matches!(s2k, S2k::Gnu { .. }) { Vec::new() }
                         else { r.bytes(cipher.block_len)?.to_vec() };
                Protection::Cfb { usage, cipher, s2k, iv }
            }
            legacy => {
                // A cipher number, with the passphrase hashed by MD5.
                let cipher = algo::cipher(legacy)?;
                let iv = r.bytes(cipher.block_len)?.to_vec();
                Protection::Cfb { usage, cipher, s2k: S2k::Simple { hash: algo::hash(1)? }, iv }
            }
        };
        if version == 5 {
            let count = r.u32()? as usize;
            let tail = if matches!(protection, Protection::None)
                || matches!(protection, Protection::Cfb { usage: 255, .. }) { 2 } else { 0 };
            if r.data.len() - r.at != count + tail {
                return Err("a version 5 secret key's count does not match its data".to_string());
            }
        }
        if version <= 3 && !matches!(protection, Protection::None) {
            return Err("an encrypted version 3 secret key (PGP 2's per-MPI CFB) is not \
                        read here".to_string());
        }
        Ok(SecretKey { public, tag: packet.tag, protection, stored: r.rest().to_vec() })
    }

    pub fn is_protected(&self) -> bool {
        !matches!(self.protection, Protection::None)
    }

    pub fn is_stub(&self) -> bool {
        matches!(self.protection, Protection::Cfb { s2k: S2k::Gnu { .. }, .. })
    }

    /// The secret part, with `passphrase` if the key is protected.
    pub fn unlock(&self, passphrase: &[u8]) -> Result<Secret, String> {
        let derived = match &self.protection {
            Protection::None => Vec::new(),
            Protection::Cfb { cipher, s2k, .. } | Protection::Aead { cipher, s2k, .. } =>
                s2k.derive(passphrase, cipher.key_len)?,
        };
        self.unlock_derived(&derived)
    }

    /// The secret part, given what the S2K made of the passphrase.
    pub fn unlock_derived(&self, derived: &[u8]) -> Result<Secret, String> {
        let wrong = || "the passphrase does not unlock the secret key".to_string();
        let plain = match &self.protection {
            Protection::None => {
                if self.public.version == 6 {
                    self.stored.clone()
                } else {
                    let (data, sum) = self.stored.split_at(self.stored.len().checked_sub(2)
                        .ok_or("a secret key shorter than its checksum")?);
                    if algo_checksum(data) != sum {
                        return Err("the secret key's checksum does not match".to_string());
                    }
                    data.to_vec()
                }
            }
            Protection::Cfb { usage, cipher, iv, .. } => {
                let plain = algo::cfb(*cipher, derived, iv, &self.stored, true)?;
                if *usage == 254 {
                    let (data, sha1) = plain.split_at(plain.len().checked_sub(20)
                        .ok_or_else(wrong)?);
                    if algo::digest(algo::hash(2)?, &[data]) != sha1 {
                        return Err(wrong());
                    }
                    data.to_vec()
                } else {
                    let (data, sum) = plain.split_at(plain.len().checked_sub(2)
                        .ok_or_else(wrong)?);
                    if algo_checksum(data) != sum {
                        return Err(wrong());
                    }
                    data.to_vec()
                }
            }
            Protection::Aead { cipher, aead, iv, .. } => {
                // RFC 9580 and LibrePGP define usage 253 differently:
                // RFC 9580 with an HKDF and the packet tag and public key
                // as associated data, LibrePGP with the S2K output as the
                // key and the cipher and mode in the associated data too.
                // A version 4 key may be either; both are authenticated,
                // so trying both is safe.
                let (kek, aad) = self.aead_parameters(derived, *cipher, *aead);
                let rfc9580 = || algo::open(*cipher, *aead, &kek, iv, &aad, &self.stored);
                let librepgp = || {
                    let mut aad = vec![0xC0 | self.tag, cipher.id, aead.id];
                    aad.extend_from_slice(&self.public.body);
                    algo::open(*cipher, *aead, derived, iv, &aad, &self.stored)
                };
                match self.public.version {
                    6 => rfc9580(),
                    5 => librepgp(),
                    _ => rfc9580().or_else(|_| librepgp()),
                }.map_err(|_| wrong())?
            }
        };
        let secret = read_secret_material(&self.public, &plain)
            .map_err(|_| wrong())?;
        crate::pubkey::check_pair(&self.public, &secret)?;
        Ok(secret)
    }

    /// The KEK and associated data of AEAD protection.
    pub fn aead_parameters(&self, derived: &[u8], cipher: Cipher, aead: algo::Aead)
                           -> (Vec<u8>, Vec<u8>) {
        let tag = 0xC0 | self.tag;
        let info = [tag, self.public.version, cipher.id, aead.id];
        let kek = algo::hkdf_sha256(&[], derived, &info, cipher.key_len);
        let mut aad = vec![tag];
        aad.extend_from_slice(&self.public.body);
        (kek, aad)
    }
}

fn algo_checksum(data: &[u8]) -> [u8; 2] {
    (data.iter().map(|&b| u32::from(b)).sum::<u32>() as u16).to_be_bytes()
}

// ------------------------------------------------- transferable keys ---

/// A key packet in a transferable key: its public part, and its secret
/// part when the file holds one.
#[derive(Clone, Debug)]
pub struct KeyPacket {
    pub public: PublicKey,
    pub secret: Option<SecretKey>,
}

#[derive(Clone, Debug)]
pub struct UserId {
    pub packet: Packet,
    pub signatures: Vec<Packet>,
}

#[derive(Clone, Debug)]
pub struct Subkey {
    pub key: KeyPacket,
    pub signatures: Vec<Packet>,
}

/// A transferable public or secret key (RFC 9580 section 10.1).
#[derive(Clone, Debug)]
pub struct Cert {
    pub primary: KeyPacket,
    pub direct: Vec<Packet>,
    pub user_ids: Vec<UserId>,
    pub subkeys: Vec<Subkey>,
}

fn key_packet(p: &Packet) -> Result<KeyPacket, String> {
    if matches!(p.tag, packet::SECRET_KEY | packet::SECRET_SUBKEY) {
        let secret = SecretKey::read(p)?;
        Ok(KeyPacket { public: secret.public.clone(), secret: Some(secret) })
    } else {
        Ok(KeyPacket { public: PublicKey::read(&p.body)?.0, secret: None })
    }
}

impl Cert {
    /// Every transferable key in a packet sequence (a keyring, or one
    /// exported key).
    pub fn read_all(packets: &[Packet]) -> Result<Vec<Cert>, String> {
        let mut certs: Vec<Cert> = Vec::new();
        for p in packets {
            match p.tag {
                packet::PUBLIC_KEY | packet::SECRET_KEY => certs.push(Cert {
                    primary: key_packet(p)?, direct: Vec::new(), user_ids: Vec::new(),
                    subkeys: Vec::new() }),
                packet::TRUST | packet::MARKER | packet::PADDING => {}
                tag => {
                    let cert = certs.last_mut().ok_or_else(|| format!(
                        "a {} packet before any key", packet::tag_name(tag)))?;
                    match tag {
                        packet::USER_ID | packet::USER_ATTRIBUTE => cert.user_ids.push(
                            UserId { packet: p.clone(), signatures: Vec::new() }),
                        packet::PUBLIC_SUBKEY | packet::SECRET_SUBKEY => cert.subkeys.push(
                            Subkey { key: key_packet(p)?, signatures: Vec::new() }),
                        packet::SIGNATURE => {
                            if let Some(subkey) = cert.subkeys.last_mut() {
                                subkey.signatures.push(p.clone());
                            } else if let Some(uid) = cert.user_ids.last_mut() {
                                uid.signatures.push(p.clone());
                            } else {
                                cert.direct.push(p.clone());
                            }
                        }
                        other => return Err(format!("a {} packet in a key",
                                                    packet::tag_name(other))),
                    }
                }
            }
        }
        Ok(certs)
    }

    /// The primary key and the subkeys, in order.
    pub fn keys(&self) -> impl Iterator<Item = &KeyPacket> {
        std::iter::once(&self.primary).chain(self.subkeys.iter().map(|s| &s.key))
    }
}
