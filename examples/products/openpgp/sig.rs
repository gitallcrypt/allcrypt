//! Signatures (RFC 9580 section 5.2, and LibrePGP's version 5): the
//! packet, its subpackets, what each signature type hashes, and the
//! public key operations that make and check one.

use crate::algo::{self, Hash};
use crate::keys::{self, Material, PublicKey, Secret};
use crate::message::Random;
use crate::packet::{self, Packet, Reader};
use allcrypt::api::{self, AnyHash, EcKey, EcPublicKey, RsaKey, RsaPublicKey};
use allcrypt::bignum::BigUint;
use allcrypt::hash_functions::HashFunction;
use allcrypt::publickey_ciphers::dh::DhGroup;
use allcrypt::publickey_ciphers::dsa::{DsaParameters, DsaPrivateKey, DsaPublicKey};
use allcrypt::publickey_ciphers::elgamal::{ElGamalPrivateKey, ElGamalPublicKey};

pub const BINARY: u8 = 0x00;
pub const TEXT: u8 = 0x01;
pub const SUBKEY_BINDING: u8 = 0x18;
pub const PRIMARY_KEY_BINDING: u8 = 0x19;
pub const DIRECT_KEY: u8 = 0x1F;
pub const KEY_REVOCATION: u8 = 0x20;
pub const SUBKEY_REVOCATION: u8 = 0x28;
pub const CERTIFICATION_REVOCATION: u8 = 0x30;

pub const CREATION_TIME: u8 = 2;
pub const SIGNATURE_EXPIRATION: u8 = 3;
pub const KEY_EXPIRATION: u8 = 9;
pub const ISSUER: u8 = 16;
pub const PRIMARY_USER_ID: u8 = 25;
pub const KEY_FLAGS: u8 = 27;
pub const EMBEDDED_SIGNATURE: u8 = 32;
pub const ISSUER_FINGERPRINT: u8 = 33;

/// The subpacket types this program acts on, or whose whole meaning
/// is a preference or a note that ignoring satisfies. A signer marks a
/// subpacket critical to say "do not accept this signature unless you
/// understand this" (RFC 9580 section 5.2.3.7), so a critical one of
/// any other type - a signature target, a revocation key, a notation,
/// a type not yet defined - makes the signature bad here.
const UNDERSTOOD: [u8; 18] = [
    CREATION_TIME, SIGNATURE_EXPIRATION, KEY_EXPIRATION, ISSUER, PRIMARY_USER_ID, KEY_FLAGS,
    EMBEDDED_SIGNATURE, ISSUER_FINGERPRINT,
    // Preferred symmetric, hash, compression and AEAD algorithms, key
    // server preferences and URL, policy URI, signer's user ID, reason
    // for revocation, features.
    11, 21, 22, 39, 23, 24, 26, 28, 29, 30,
];

pub const FLAG_SIGN: u8 = 0x02;
pub const FLAG_ENCRYPT: u8 = 0x0C;

pub fn type_name(t: u8) -> &'static str {
    match t {
        0x00 => "binary document",
        0x01 => "text document",
        0x02 => "standalone",
        0x10..=0x13 => "certification",
        0x18 => "subkey binding",
        0x19 => "primary key binding",
        0x1F => "direct key",
        0x20 => "key revocation",
        0x28 => "subkey revocation",
        0x30 => "certification revocation",
        0x40 => "timestamp",
        0x50 => "third-party confirmation",
        _ => "unknown",
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Subpacket {
    pub kind: u8,
    pub critical: bool,
    pub data: Vec<u8>,
}

impl Subpacket {
    pub fn new(kind: u8, data: &[u8]) -> Subpacket {
        Subpacket { kind, critical: false, data: data.to_vec() }
    }

    fn write(&self, out: &mut Vec<u8>) {
        packet::encode_length(self.data.len() + 1, out);
        out.push(self.kind | if self.critical { 0x80 } else { 0 });
        out.extend_from_slice(&self.data);
    }
}

fn read_subpackets(mut area: &[u8]) -> Result<Vec<Subpacket>, String> {
    let mut out = Vec::new();
    while !area.is_empty() {
        let mut r = Reader::new(area);
        let first = r.u8()? as usize;
        let len = match first {
            0..=191 => first,
            192..=254 => ((first - 192) << 8) + r.u8()? as usize + 192,
            _ => r.u32()? as usize,
        };
        if len == 0 {
            return Err("an empty signature subpacket".to_string());
        }
        let body = r.bytes(len)?;
        out.push(Subpacket { kind: body[0] & 0x7f, critical: body[0] & 0x80 != 0,
                             data: body[1..].to_vec() });
        area = &area[r.at..];
    }
    Ok(out)
}

/// The salt length a version 6 signature uses with each hash (RFC 9580
/// table 23); none for the hashes it does not allow.
pub fn salt_len(hash: Hash) -> Option<usize> {
    match hash.id {
        8 | 11 | 12 => Some(16),
        9 => Some(24),
        10 | 14 => Some(32),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub version: u8,
    pub sig_type: u8,
    pub algorithm: u8,
    pub hash: Hash,
    pub hashed: Vec<Subpacket>,
    pub unhashed: Vec<Subpacket>,
    pub left16: [u8; 2],
    pub salt: Vec<u8>,
    /// The algorithm-specific fields as stored.
    pub fields: Vec<u8>,
    /// Version 3's creation time and issuer, which later versions carry
    /// in subpackets.
    pub v3_created: u32,
    pub v3_issuer: [u8; 8],
    /// What is hashed after the data: built when the packet is read.
    trailer: Vec<u8>,
}

impl Signature {
    pub fn parse(body: &[u8]) -> Result<Signature, String> {
        let mut r = Reader::new(body);
        let version = r.u8()?;
        let mut sig = Signature {
            version, sig_type: 0, algorithm: 0, hash: algo::hash(2)?, hashed: Vec::new(),
            unhashed: Vec::new(), left16: [0; 2], salt: Vec::new(), fields: Vec::new(),
            v3_created: 0, v3_issuer: [0; 8], trailer: Vec::new(),
        };
        match version {
            2 | 3 => {
                if r.u8()? != 5 {
                    return Err("a version 3 signature's hashed length is not 5".to_string());
                }
                sig.sig_type = r.u8()?;
                sig.v3_created = r.u32()?;
                sig.v3_issuer = r.bytes(8)?.try_into().unwrap();
                sig.algorithm = r.u8()?;
                sig.hash = algo::hash(r.u8()?)?;
                sig.trailer = body[2..7].to_vec();
            }
            4..=6 => {
                sig.sig_type = r.u8()?;
                sig.algorithm = r.u8()?;
                sig.hash = algo::hash(r.u8()?)?;
                let wide = version == 6;
                let hashed_len = if wide { r.u32()? as usize } else {
                    u16::from_be_bytes(r.bytes(2)?.try_into().unwrap()) as usize };
                sig.hashed = read_subpackets(r.bytes(hashed_len)?)?;
                let hashed_end = r.at;
                let unhashed_len = if wide { r.u32()? as usize } else {
                    u16::from_be_bytes(r.bytes(2)?.try_into().unwrap()) as usize };
                sig.unhashed = read_subpackets(r.bytes(unhashed_len)?)?;
                sig.trailer = body[..hashed_end].to_vec();
            }
            v => return Err(format!("signature version {v} is not one this program reads")),
        }
        sig.left16 = r.bytes(2)?.try_into().unwrap();
        if version == 6 {
            let n = r.u8()? as usize;
            sig.salt = r.bytes(n)?.to_vec();
            if Some(n) != salt_len(sig.hash) {
                return Err(format!("a version 6 signature's salt is {n} bytes; {} takes {:?}",
                                   sig.hash.display, salt_len(sig.hash)));
            }
        }
        sig.fields = r.rest().to_vec();
        Ok(sig)
    }

    pub fn subpacket(&self, kind: u8) -> Option<&[u8]> {
        self.hashed.iter().rev().find(|s| s.kind == kind).map(|s| s.data.as_slice())
    }

    /// Issuer key IDs and fingerprints, hashed or not (the issuer is
    /// commonly unhashed: it is a hint, the signature itself decides).
    pub fn issuer_fingerprints(&self) -> Vec<Vec<u8>> {
        self.hashed.iter().chain(&self.unhashed).filter(|s| s.kind == ISSUER_FINGERPRINT
                                                        && s.data.len() > 1)
            .map(|s| s.data[1..].to_vec()).collect()
    }

    pub fn issuer_key_ids(&self) -> Vec<[u8; 8]> {
        let mut ids: Vec<[u8; 8]> = self.hashed.iter().chain(&self.unhashed)
            .filter(|s| s.kind == ISSUER && s.data.len() == 8)
            .map(|s| s.data[..].try_into().unwrap()).collect();
        if self.version <= 3 {
            ids.push(self.v3_issuer);
        }
        ids
    }

    /// Whether `key` may be this signature's issuer, by what it names.
    /// A signature naming nothing could be anybody's.
    pub fn may_be_by(&self, key: &PublicKey) -> bool {
        let fingerprints = self.issuer_fingerprints();
        let ids = self.issuer_key_ids();
        if fingerprints.is_empty() && ids.is_empty() {
            return true;
        }
        fingerprints.contains(&key.fingerprint()) || ids.contains(&key.key_id())
    }

    pub fn created(&self) -> Option<u32> {
        if self.version <= 3 {
            return Some(self.v3_created);
        }
        self.subpacket(CREATION_TIME).and_then(|d| d.try_into().ok()).map(u32::from_be_bytes)
    }

    pub fn key_flags(&self) -> Option<u8> {
        self.subpacket(KEY_FLAGS).and_then(|d| d.first().copied())
    }

    /// Seconds after the key's creation that it expires, if it does.
    pub fn key_expiration(&self) -> Option<u32> {
        self.subpacket(KEY_EXPIRATION).and_then(|d| d.try_into().ok()).map(u32::from_be_bytes)
            .filter(|&e| e != 0)
    }

    pub fn signature_expiration(&self) -> Option<u32> {
        self.subpacket(SIGNATURE_EXPIRATION).and_then(|d| d.try_into().ok())
            .map(u32::from_be_bytes).filter(|&e| e != 0)
    }

    pub fn embedded(&self) -> Vec<Signature> {
        self.hashed.iter().chain(&self.unhashed).filter(|s| s.kind == EMBEDDED_SIGNATURE)
            .filter_map(|s| Signature::parse(&s.data).ok()).collect()
    }

    /// A hash context with the salt (version 6) already in it.
    pub fn hasher(&self) -> AnyHash {
        let mut h = algo::new_hash(self.hash);
        h.update(&self.salt);
        h
    }

    /// The digest: `h`, which has had the signed data, and the trailer.
    /// `literal` is the literal data packet's format, file name and date,
    /// which LibrePGP's version 5 document signatures also hash.
    pub fn finish(&self, mut h: AnyHash, literal: Option<&[u8]>) -> Vec<u8> {
        h.update(&self.trailer);
        match self.version {
            2 | 3 => {}
            5 => {
                if matches!(self.sig_type, BINARY | TEXT) {
                    h.update(literal.unwrap_or(&[0; 6]));
                }
                h.update(&[5, 0xFF]);
                h.update(&(self.trailer.len() as u64).to_be_bytes());
            }
            v => {
                h.update(&[v, 0xFF]);
                h.update(&(self.trailer.len() as u32).to_be_bytes());
            }
        }
        h.digest()
    }

    /// Check the signature over `digest` with `key`.
    pub fn verify_digest(&self, key: &PublicKey, digest: &[u8]) -> Result<(), String> {
        // Only the hashed area is the signer's statement.
        if let Some(s) = self.hashed.iter().find(|s| s.critical && !UNDERSTOOD.contains(&s.kind)) {
            return Err(format!("the signature carries a critical subpacket of type {} that this \
                                program does not understand", s.kind));
        }
        if digest[..2] != self.left16 {
            return Err("the digest's first two bytes are not the signature's".to_string());
        }
        if self.algorithm != key.algorithm {
            return Err("the signature's algorithm is not the key's".to_string());
        }
        let bad = || "the signature does not verify".to_string();
        let mut r = Reader::new(&self.fields);
        let ok = match (&key.material, key.algorithm) {
            (Material::Rsa { n, e }, keys::RSA | keys::RSA_SIGN) => {
                let public = RsaPublicKey::new(n, e)?;
                let s = pad_left(read_mpi(&mut r)?, public.size())?;
                public.verify(self.hash.name, digest, &s)?
            }
            (Material::Dsa { p, q, g, y }, keys::DSA) => {
                let parameters = DsaParameters::new(BigUint::from_bytes_be(p),
                                                    BigUint::from_bytes_be(q),
                                                    BigUint::from_bytes_be(g))?;
                let public = DsaPublicKey::new(parameters, BigUint::from_bytes_be(y))?;
                let (rr, s) = (read_mpi(&mut r)?, read_mpi(&mut r)?);
                public.verify(digest, &BigUint::from_bytes_be(rr), &BigUint::from_bytes_be(s))?
            }
            (Material::ElGamal { p, g, y }, keys::ELGAMAL_SIGN) => {
                let public = ElGamalPublicKey::new(DhGroup::from_bytes(p, g)?,
                                                   BigUint::from_bytes_be(y))?;
                let (rr, s) = (read_mpi(&mut r)?, read_mpi(&mut r)?);
                public.verify(digest, &BigUint::from_bytes_be(rr), &BigUint::from_bytes_be(s))?
            }
            (Material::Ec { point, .. }, keys::ECDSA) => {
                let curve = key.curve().ok_or("an ECDSA curve this program does not have")?;
                let name = weierstrass(curve)?;
                // r and s are below the group order, which on every curve
                // here is as wide as the field.
                let mut rs = pad_left(read_mpi(&mut r)?, curve.field)?;
                rs.extend(pad_left(read_mpi(&mut r)?, curve.field)?);
                EcPublicKey::from_bytes(name, point)?.verify(digest, &rs)?
            }
            (Material::Ec { point, .. }, keys::EDDSA_LEGACY) => {
                let curve = key.curve().ok_or("an EdDSA curve this program does not have")?;
                let (name, half) = if curve.name == "Ed448" { ("ed448", 57) } else { ("ed25519", 32) };
                let (rr, s) = (read_mpi(&mut r)?, read_mpi(&mut r)?);
                let mut signature = pad_left(rr, half)?;
                signature.extend(pad_left(s, half)?);
                api::eddsa_verify(name, &keys::native_point(point, curve.field)?, digest,
                                  &signature, &[])?
            }
            (Material::Native(public), keys::ED25519) =>
                api::eddsa_verify("ed25519", public, digest, r.bytes(64)?, &[])?,
            (Material::Native(public), keys::ED448) =>
                api::eddsa_verify("ed448", public, digest, r.bytes(114)?, &[])?,
            _ => return Err(format!("{} cannot verify a {} signature",
                                    keys::algorithm_name(key.algorithm),
                                    keys::algorithm_name(self.algorithm))),
        };
        // The fields are the signature's values and nothing else: bytes
        // after them are not part of any value that was checked.
        if r.at != self.fields.len() {
            return Err(format!("{} bytes follow the signature's values", self.fields.len() - r.at));
        }
        if ok { Ok(()) } else { Err(bad()) }
    }
}

fn pad_left(value: &[u8], width: usize) -> Result<Vec<u8>, String> {
    if value.len() > width {
        return Err("a signature value wider than its key".to_string());
    }
    let mut out = vec![0u8; width - value.len()];
    out.extend_from_slice(value);
    Ok(out)
}

fn read_mpi<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], String> {
    let bits = u16::from_be_bytes(r.bytes(2)?.try_into().unwrap()) as usize;
    r.bytes(bits.div_ceil(8))
}

fn weierstrass(curve: &keys::Curve) -> Result<&'static str, String> {
    if curve.name.starts_with("brainpool") {
        keys::register_brainpool()?;
    }
    curve.library.ok_or_else(|| format!("{} has no ECDSA here", curve.name))
}

// ---------------------------------------------------- what is hashed ---

/// A key as signatures over keys hash it.
pub fn hash_key(h: &mut AnyHash, key: &PublicKey) {
    match key.version {
        2..=4 => {
            h.update(&[0x99]);
            h.update(&(key.body.len() as u16).to_be_bytes());
        }
        v => {
            h.update(&[if v == 5 { 0x9A } else { 0x9B }]);
            h.update(&(key.body.len() as u32).to_be_bytes());
        }
    }
    h.update(&key.body);
}

/// A user ID or user attribute as a certification hashes it.
pub fn hash_user_id(h: &mut AnyHash, uid: &Packet, version: u8) {
    if version >= 4 {
        h.update(&[if uid.tag == packet::USER_ATTRIBUTE { 0xD1 } else { 0xB4 }]);
        h.update(&(uid.body.len() as u32).to_be_bytes());
    }
    h.update(&uid.body);
}

/// Text canonicalised for a text signature: every line ending CR LF.
pub fn canonical_text(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 32);
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\r' if data.get(i + 1) == Some(&b'\n') => {
                out.extend_from_slice(b"\r\n");
                i += 2;
                continue;
            }
            b'\n' => out.extend_from_slice(b"\r\n"),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

// ------------------------------------------------------------ making ---

/// Make a signature with `key` (`secret` being its secret half) over
/// whatever `feed` hashes. The version follows the key's (4 for version
/// 4 keys, 6 for version 6, LibrePGP's 5 for version 5); `hashed`
/// should hold the creation time and the issuer fingerprint, which
/// `standard_subpackets` gives.
#[allow(clippy::too_many_arguments)]
pub fn make(key: &PublicKey, secret: &Secret, sig_type: u8, hash: Hash, hashed: Vec<Subpacket>,
            unhashed: Vec<Subpacket>, literal: Option<&[u8]>, feed: &dyn Fn(&mut AnyHash),
            random: Random<'_>) -> Result<Vec<u8>, String> {
    let version = match key.version { 6 => 6, 5 => 5, _ => 4 };
    let mut salt = Vec::new();
    if version == 6 {
        salt = vec![0u8; salt_len(hash).ok_or_else(|| format!(
            "{} is not allowed in a version 6 signature", hash.display))?];
        random(&mut salt)?;
    }
    let mut body = vec![version, sig_type, key.algorithm, hash.id];
    let mut area = Vec::new();
    for s in &hashed {
        s.write(&mut area);
    }
    if version == 6 {
        body.extend_from_slice(&(area.len() as u32).to_be_bytes());
    } else {
        body.extend_from_slice(&(area.len() as u16).to_be_bytes());
    }
    body.extend_from_slice(&area);
    let trailer_end = body.len();
    let mut unhashed_area = Vec::new();
    for s in &unhashed {
        s.write(&mut unhashed_area);
    }
    if version == 6 {
        body.extend_from_slice(&(unhashed_area.len() as u32).to_be_bytes());
    } else {
        body.extend_from_slice(&(unhashed_area.len() as u16).to_be_bytes());
    }
    body.extend_from_slice(&unhashed_area);

    let partial = Signature {
        version, sig_type, algorithm: key.algorithm, hash, hashed, unhashed,
        left16: [0; 2], salt: salt.clone(), fields: Vec::new(), v3_created: 0,
        v3_issuer: [0; 8], trailer: body[..trailer_end].to_vec(),
    };
    let mut h = partial.hasher();
    feed(&mut h);
    let digest = partial.finish(h, literal);
    body.extend_from_slice(&digest[..2]);
    if version == 6 {
        body.push(salt.len() as u8);
        body.extend_from_slice(&salt);
    }
    sign_digest(key, secret, hash, &digest, &mut body)?;
    Ok(body)
}

fn sign_digest(key: &PublicKey, secret: &Secret, hash: Hash, digest: &[u8], out: &mut Vec<u8>)
               -> Result<(), String> {
    match (&key.material, secret, key.algorithm) {
        (Material::Rsa { e, .. }, Secret::Rsa { p, q }, keys::RSA | keys::RSA_SIGN) => {
            let s = RsaKey::from_primes(p, q, e)?.sign(hash.name, digest)?;
            keys::write_mpi(&s, out);
        }
        (Material::Dsa { p, q, g, .. }, Secret::Scalar(x), keys::DSA) => {
            let parameters = DsaParameters::new(BigUint::from_bytes_be(p),
                                                BigUint::from_bytes_be(q),
                                                BigUint::from_bytes_be(g))?;
            let private = DsaPrivateKey::from_x(parameters, BigUint::from_bytes_be(x))?;
            let (r, s) = private.sign(digest, algo::new_hash(hash))?;
            keys::write_mpi(&r.to_bytes_be(), out);
            keys::write_mpi(&s.to_bytes_be(), out);
        }
        (Material::ElGamal { p, g, .. }, Secret::Scalar(x), keys::ELGAMAL_SIGN) => {
            let private = ElGamalPrivateKey::from_private(DhGroup::from_bytes(p, g)?,
                                                          BigUint::from_bytes_be(x))?;
            let (r, s) = private.sign(digest)?;
            keys::write_mpi(&r.to_bytes_be(), out);
            keys::write_mpi(&s.to_bytes_be(), out);
        }
        (Material::Ec { .. }, Secret::Scalar(d), keys::ECDSA) => {
            let curve = key.curve().ok_or("an ECDSA curve this program does not have")?;
            let rs = EcKey::from_private(weierstrass(curve)?, d)?.sign(digest, hash.name)?;
            let (r, s) = rs.split_at(rs.len() / 2);
            keys::write_mpi(r, out);
            keys::write_mpi(s, out);
        }
        (Material::Ec { .. }, Secret::Native(seed), keys::EDDSA_LEGACY) => {
            let ed448 = key.curve().is_some_and(|c| c.name == "Ed448");
            let rs = api::eddsa_sign(if ed448 { "ed448" } else { "ed25519" }, seed, digest, &[])?;
            let (r, s) = rs.split_at(rs.len() / 2);
            // RFC 9580 strips Ed25519Legacy's leading zeros like an MPI's;
            // GnuPG's Ed448 keeps all 57 bytes.
            let write = if ed448 { keys::write_sos } else { keys::write_mpi };
            write(r, out);
            write(s, out);
        }
        (Material::Native(_), Secret::Native(seed), keys::ED25519) =>
            out.extend(api::eddsa_sign("ed25519", seed, digest, &[])?),
        (Material::Native(_), Secret::Native(seed), keys::ED448) =>
            out.extend(api::eddsa_sign("ed448", seed, digest, &[])?),
        _ => return Err(format!("{} cannot sign", keys::algorithm_name(key.algorithm))),
    }
    Ok(())
}

/// Creation time and issuer fingerprint (and, before version 6, the
/// issuer key ID, which older readers look for).
pub fn standard_subpackets(key: &PublicKey, created: u32) -> (Vec<Subpacket>, Vec<Subpacket>) {
    let mut fingerprint = vec![key.version];
    fingerprint.extend(key.fingerprint());
    let hashed = vec![Subpacket::new(CREATION_TIME, &created.to_be_bytes()),
                      Subpacket::new(ISSUER_FINGERPRINT, &fingerprint)];
    let unhashed = if key.version >= 6 { Vec::new() }
                   else { vec![Subpacket::new(ISSUER, &key.key_id())] };
    (hashed, unhashed)
}

/// A one-pass signature packet body announcing a signature by `key`.
pub fn one_pass(sig_type: u8, hash: Hash, key: &PublicKey, salt: &[u8], last: bool) -> Vec<u8> {
    if key.version >= 6 {
        let mut body = vec![6, sig_type, hash.id, key.algorithm, salt.len() as u8];
        body.extend_from_slice(salt);
        body.extend(key.fingerprint());
        body.push(u8::from(last));
        body
    } else {
        let mut body = vec![3, sig_type, hash.id, key.algorithm];
        body.extend(key.key_id());
        body.push(u8::from(last));
        body
    }
}
