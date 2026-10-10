/*
SSH key exchange: the methods, the exchange hash, and the keys derived
from it (RFC 4253 sections 7 and 8, RFC 4419, RFC 5656, RFC 8731,
RFC 8268, and OpenSSH's `mlkem768x25519-sha256`).

Every method ends the same way. Each side contributes a public value;
the two make a shared secret `K`; and the exchange hash

    H = HASH(string V_C, string V_S, string I_C, string I_S, string K_S,
             [group-exchange parameters,] client value, server value, K)

binds that secret to both version strings, both KEXINIT payloads and the
server's host key, which then signs `H`. The first `H` of a connection
is its session identifier, and stays so through every re-exchange.
Keys are `HASH(K || H || letter || session_id)`, extended by
`HASH(K || H || everything so far)` until long enough (RFC 4253 7.2).

# Pitfalls

**`K` is an mpint, except where it is a string.** Diffie-Hellman, ECDH
and Curve25519 put `K` into the hash as an mpint - so a secret whose
first byte is zero loses it, and one whose top bit is set gains a zero
byte. The post-quantum hybrids put `K` in as a *string*: it is already
a hash, and OpenSSH encodes it with `sshbuf_put_string`. Each convention
applied to the other method fails the exchange, the first one time in
256 and the second always - and the same encoding goes into the key
derivation, not only the exchange hash.

**Curve25519's `K` is the X25519 output read as a big-endian number**
(RFC 8731 section 3.1), not the little-endian integer X25519 itself
uses. The bytes go into the mpint as they are.

**ECDH's `K` is the x-coordinate alone**, as an mpint (RFC 5656 4).

**`sntrup761x25519-sha512` has the same shape with SHA-512**: the client
sends the NTRU Prime public key then its X25519 key (1190 bytes), the
server the ciphertext then its X25519 key (1071), and `K` is the
SHA-512 of the two secrets, NTRU Prime's first - a 64 byte string.

**The hybrid's values are concatenations, in a fixed order**: the client
sends ML-KEM-768's encapsulation key then its X25519 key (1216 bytes),
the server its ML-KEM ciphertext then its X25519 key (1120 bytes), and
`K = SHA-256(ML-KEM secret || X25519 secret)` - post-quantum part first
in all three, as X25519MLKEM768 does in TLS.

**A Diffie-Hellman exponent need not be as long as the modulus.** The
groups are safe primes, where a 2t bit exponent gives t bits of
security; OpenSSH uses twice the hash's output size, capped by the
group. An 8192 bit exponent would cost a second or more here for
nothing.
*/

use crate::api::{AnyHash, MlKemKey};
use crate::bignum::BigUint;
use crate::ec::x25519;
use crate::hash_functions::HashFunction;
use crate::pq::{ml_kem, sntrup};
use crate::publickey_ciphers::dh::{self, DhGroup};

use super::keys::NistCurve;
use super::wire::Writer;

/// What a method is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `mlkem768x25519-sha256`: ML-KEM-768 and X25519, hybrid.
    MlKem768X25519,
    /// `sntrup761x25519-sha512`: Streamlined NTRU Prime and X25519,
    /// OpenSSH's default from 9.0 to 9.8.
    Sntrup761X25519,
    /// `curve25519-sha256` and its older name `curve25519-sha256@libssh.org`.
    Curve25519,
    /// `ecdh-sha2-nistp256`, `-nistp384`, `-nistp521`.
    Ecdh(NistCurve),
    /// A fixed MODP group with a hash.
    DhGroup { bits: usize, hash: &'static str },
    /// RFC 4419: the server chooses the group.
    DhGroupExchange { hash: &'static str },
}

/// A method by SSH name.
#[derive(Debug)]
pub struct MethodSpec {
    pub name: &'static str,
    pub method: Method,
    /// Refused unless asked for by name: SHA-1 or a group below 2048 bits.
    pub legacy: bool,
}

const fn method(name: &'static str, method: Method, legacy: bool) -> MethodSpec {
    MethodSpec { name, method, legacy }
}

/// Every method, in the order a client offers them.
pub const METHODS: &[MethodSpec] = &[
    method("mlkem768x25519-sha256", Method::MlKem768X25519, false),
    method("sntrup761x25519-sha512", Method::Sntrup761X25519, false),
    method("sntrup761x25519-sha512@openssh.com", Method::Sntrup761X25519, false),
    method("curve25519-sha256", Method::Curve25519, false),
    method("curve25519-sha256@libssh.org", Method::Curve25519, false),
    method("ecdh-sha2-nistp256", Method::Ecdh(NistCurve::P256), false),
    method("ecdh-sha2-nistp384", Method::Ecdh(NistCurve::P384), false),
    method("ecdh-sha2-nistp521", Method::Ecdh(NistCurve::P521), false),
    method("diffie-hellman-group-exchange-sha256",
           Method::DhGroupExchange { hash: "sha256" }, false),
    method("diffie-hellman-group16-sha512", Method::DhGroup { bits: 4096, hash: "sha512" }, false),
    method("diffie-hellman-group18-sha512", Method::DhGroup { bits: 8192, hash: "sha512" }, false),
    method("diffie-hellman-group14-sha256", Method::DhGroup { bits: 2048, hash: "sha256" }, false),
    method("diffie-hellman-group14-sha1", Method::DhGroup { bits: 2048, hash: "sha1" }, true),
    method("diffie-hellman-group-exchange-sha1",
           Method::DhGroupExchange { hash: "sha1" }, true),
    method("diffie-hellman-group1-sha1", Method::DhGroup { bits: 1024, hash: "sha1" }, true),
];

pub fn lookup(name: &str) -> Result<&'static MethodSpec, String> {
    METHODS.iter().find(|spec| spec.name == name).ok_or_else(|| {
        let known: Vec<&str> = METHODS.iter().map(|spec| spec.name).collect();
        format!("SSH: unknown key exchange {name:?}. Known: {}.", known.join(", "))
    })
}

impl Method {
    /// The hash for the exchange hash and the key derivation.
    pub fn hash_name(self) -> &'static str {
        match self {
            Method::MlKem768X25519 | Method::Curve25519 => "sha256",
            Method::Sntrup761X25519 => "sha512",
            Method::Ecdh(curve) => curve.hash_name(),
            Method::DhGroup { hash, .. } | Method::DhGroupExchange { hash } => hash,
        }
    }

    /// Whether the public values travel as mpints (Diffie-Hellman's `e`
    /// and `f`) or as strings (everything else).
    pub fn values_are_mpints(self) -> bool {
        matches!(self, Method::DhGroup { .. } | Method::DhGroupExchange { .. })
    }

    /// Append a public value - either side's - as its message field.
    pub fn write_value(self, writer: &mut Writer, value: &[u8]) {
        if self.values_are_mpints() {
            writer.mpint(value);
        } else {
            writer.string(value);
        }
    }
}

fn hash(name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut hash = AnyHash::new(name)?;
    hash.update(data);
    Ok(hash.digest())
}

/// The sizes `modp` has, which are what a group exchange can offer.
pub const MODP_SIZES: [usize; 7] = [1024, 1536, 2048, 3072, 4096, 6144, 8192];

/// The fixed group for a size, from `publickey_ciphers::dh`: RFC 2409
/// and RFC 3526's MODP groups.
pub fn modp(bits: usize) -> Result<DhGroup, String> {
    dh::modp_group(match bits {
        1024 => dh::MODP_1024,
        1536 => dh::MODP_1536,
        2048 => dh::MODP_2048,
        3072 => dh::MODP_3072,
        4096 => dh::MODP_4096,
        6144 => dh::MODP_6144,
        8192 => dh::MODP_8192,
        other => return Err(format!("SSH: no fixed group of {other} bits.")),
    })
}

/// The shared secret, already encoded the way it goes into the exchange
/// hash and the key derivation: an mpint or a string, by method.
pub struct SharedSecret {
    encoded: Vec<u8>,
}

impl SharedSecret {
    fn mpint(magnitude: &[u8]) -> SharedSecret {
        let mut writer = Writer::new();
        writer.mpint(magnitude);
        SharedSecret { encoded: writer.finish() }
    }

    fn string(bytes: &[u8]) -> SharedSecret {
        let mut writer = Writer::new();
        writer.string(bytes);
        SharedSecret { encoded: writer.finish() }
    }

    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    #[cfg(test)]
    pub(crate) fn for_test(bytes: &[u8]) -> SharedSecret {
        SharedSecret::mpint(bytes)
    }
}

/// The parts of the exchange hash that are not the key exchange's own.
pub struct Transcript<'a> {
    pub client_version: &'a [u8],
    pub server_version: &'a [u8],
    pub client_kexinit: &'a [u8],
    pub server_kexinit: &'a [u8],
    pub host_key: &'a [u8],
}

/// A group exchange's negotiated parameters, which RFC 4419 puts in the
/// hash: the client's `min, n, max` and the server's `p, g`.
///
/// `old` marks the pre-RFC `KEX_DH_GEX_REQUEST_OLD` form (message 30),
/// which carries `n` alone; the hash then holds only `n` (RFC 4419
/// section 3, "if the 'old' form was used"). The `min` and `max` of
/// such an exchange are the server's defaults and are not hashed.
pub struct GroupExchange {
    pub min: u32,
    pub preferred: u32,
    pub max: u32,
    pub group: DhGroup,
    pub old: bool,
}

enum Secret {
    X25519([u8; 32]),
    Ecdh { curve: NistCurve, scalar: BigUint },
    Dh { group: DhGroup, exponent: BigUint },
    Hybrid { kem: MlKemKey, x25519: [u8; 32] },
    Sntrup { secret: Vec<u8>, x25519: [u8; 32] },
}

/// One side's half of a key exchange in progress.
pub struct Ephemeral {
    method: Method,
    secret: Secret,
    /// The value sent: a string's contents, or an mpint's magnitude.
    public: Vec<u8>,
    exchange: Option<GroupExchange>,
}

/// Fill a buffer with random bytes. The OS source normally; a test can
/// pass its own, which is what makes a recorded session replayable.
pub type Fill<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

fn random_below(limit: &BigUint, fill: Fill<'_>) -> Result<BigUint, String> {
    let mut bytes = vec![0u8; limit.bit_len().div_ceil(8) + 8];
    fill(&mut bytes)?;
    // Eight extra bytes make the bias of the reduction 2^-64.
    let value = BigUint::from_bytes_be(&bytes).rem(&limit.sub(&BigUint::one())?)?;
    Ok(value.add(&BigUint::one()))
}

impl Ephemeral {
    /// The client's half. `exchange` is required for a group exchange and
    /// ignored otherwise.
    pub fn client(method: Method, exchange: Option<GroupExchange>, fill: Fill<'_>)
                  -> Result<Ephemeral, String> {
        let (secret, public) = match method {
            Method::Curve25519 => {
                let mut private = [0u8; 32];
                fill(&mut private)?;
                let public = x25519::public_key(&private)?;
                (Secret::X25519(private), public.to_vec())
            }
            Method::Ecdh(curve) => {
                let ec = curve.curve();
                let scalar = random_below(&ec.n, fill)?;
                let point = ec.encode_point(&ec.scalar_mul_ct(&ec.g, &scalar), false)?;
                (Secret::Ecdh { curve, scalar }, point)
            }
            Method::DhGroup { bits, hash } => {
                let group = modp(bits)?;
                let (exponent, public) = dh_pair(&group, hash, fill)?;
                (Secret::Dh { group, exponent }, public)
            }
            Method::DhGroupExchange { hash } => {
                let group = exchange.as_ref()
                    .ok_or_else(|| "SSH: a group exchange needs the server's group."
                                .to_string())?.group.clone();
                let (exponent, public) = dh_pair(&group, hash, fill)?;
                (Secret::Dh { group, exponent }, public)
            }
            Method::MlKem768X25519 => {
                let mut seed = [0u8; 64];
                fill(&mut seed)?;
                let kem = MlKemKey::from_seed("ML-KEM-768", &seed)?;
                let mut private = [0u8; 32];
                fill(&mut private)?;
                let mut public = kem.public_bytes().to_vec();
                public.extend_from_slice(&x25519::public_key(&private)?);
                (Secret::Hybrid { kem, x25519: private }, public)
            }
            Method::Sntrup761X25519 => {
                let (mut public, secret) = sntrup::keypair(fill)?;
                let mut private = [0u8; 32];
                fill(&mut private)?;
                public.extend_from_slice(&x25519::public_key(&private)?);
                (Secret::Sntrup { secret, x25519: private }, public)
            }
        };
        Ok(Ephemeral { method, secret, public, exchange })
    }

    /// The value to send - as a string's contents or an mpint's
    /// magnitude, which `write_public` encodes correctly.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Append the public value as its message field.
    pub fn write_public(&self, writer: &mut Writer) {
        self.method.write_value(writer, &self.public);
    }

    /// Finish with the server's value, and compute `K` and `H`.
    pub fn finish(self, transcript: &Transcript<'_>, server_public: &[u8])
                  -> Result<(SharedSecret, Vec<u8>), String> {
        let shared = match &self.secret {
            Secret::Hybrid { kem, x25519: private } => {
                if server_public.len() != 1088 + 32 {
                    return Err(format!("SSH: the mlkem768x25519 reply is {} bytes \
                                        and should be 1120.", server_public.len()));
                }
                let (ciphertext, peer) = server_public.split_at(1088);
                let mut both = kem.decapsulate(ciphertext)?;
                let peer: [u8; 32] = peer.try_into().map_err(|_| "length".to_string())?;
                both.extend_from_slice(&x25519::exchange(private, &peer)?);
                SharedSecret::string(&hash("sha256", &both)?)
            }
            Secret::Sntrup { secret, x25519: private } => {
                if server_public.len() != sntrup::CIPHERTEXT_BYTES + 32 {
                    return Err(format!("SSH: the sntrup761x25519 reply is {} bytes \
                                        and should be {}.", server_public.len(),
                                       sntrup::CIPHERTEXT_BYTES + 32));
                }
                let (ciphertext, peer) = server_public.split_at(sntrup::CIPHERTEXT_BYTES);
                let mut both = sntrup::decapsulate(ciphertext, secret)?;
                let peer: [u8; 32] = peer.try_into().map_err(|_| "length".to_string())?;
                both.extend_from_slice(&x25519::exchange(private, &peer)?);
                SharedSecret::string(&hash("sha512", &both)?)
            }
            _ => self.classical_secret(server_public)?,
        };
        let h = self.exchange_hash(transcript, &self.public, server_public, &shared)?;
        Ok((shared, h))
    }

    fn exchange_hash(&self, transcript: &Transcript<'_>, client: &[u8], server: &[u8],
                     shared: &SharedSecret) -> Result<Vec<u8>, String> {
        let mut writer = Writer::new();
        writer.string(transcript.client_version)
            .string(transcript.server_version)
            .string(transcript.client_kexinit)
            .string(transcript.server_kexinit)
            .string(transcript.host_key);
        if let Some(exchange) = &self.exchange {
            if exchange.old {
                writer.uint32(exchange.preferred);
            } else {
                writer.uint32(exchange.min).uint32(exchange.preferred).uint32(exchange.max);
            }
            writer.mpint(&exchange.group.p().to_bytes_be())
                .mpint(&exchange.group.g().to_bytes_be());
        }
        if self.method.values_are_mpints() {
            writer.mpint(client).mpint(server);
        } else {
            writer.string(client).string(server);
        }
        writer.raw(shared.encoded());
        hash(self.method.hash_name(), &writer.finish())
    }
}

/// A Diffie-Hellman exponent of twice the hash's size in bits (at least
/// 256, as OpenSSH's `dh_estimate` floors it), and its public value.
fn dh_pair(group: &DhGroup, hash_name: &str, fill: Fill<'_>)
           -> Result<(BigUint, Vec<u8>), String> {
    let hash_bits = 8 * AnyHash::new(hash_name)?.digest_len();
    let bits = (2 * hash_bits).max(256).min(group.bits() - 1);
    let mut bytes = vec![0u8; bits.div_ceil(8)];
    fill(&mut bytes)?;
    let mut exponent = BigUint::from_bytes_be(&bytes).shr(bytes.len() * 8 - bits);
    if exponent.bit_len() < 2 {
        exponent = BigUint::from_u64(2);
    }
    let public = group.public_key(&exponent)?.to_bytes_be();
    Ok((exponent, public))
}

/// RFC 4253 7.2: one key, `HASH(K || H || letter || session_id)`,
/// extended with `HASH(K || H || key so far)` until `length` bytes.
pub fn derive(hash_name: &str, shared: &SharedSecret, h: &[u8], letter: u8,
              session_id: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let mut input = Vec::with_capacity(shared.encoded.len() + h.len() + 1 + session_id.len());
    input.extend_from_slice(&shared.encoded);
    input.extend_from_slice(h);
    input.push(letter);
    input.extend_from_slice(session_id);
    let mut key = hash(hash_name, &input)?;
    while key.len() < length {
        let mut more = Vec::with_capacity(shared.encoded.len() + h.len() + key.len());
        more.extend_from_slice(&shared.encoded);
        more.extend_from_slice(h);
        more.extend_from_slice(&key);
        key.extend_from_slice(&hash(hash_name, &more)?);
    }
    key.truncate(length);
    Ok(key)
}

/// The server's half: the reply value, `K` and `H`. Every random byte
/// comes from `fill` - the ML-KEM encapsulation's `m` included - so a
/// seeded server's side of a session is reproducible, as a seeded
/// client's is.
pub fn server_respond(method: Method, exchange: Option<GroupExchange>,
                      transcript: &Transcript<'_>, client_public: &[u8], fill: Fill<'_>)
                      -> Result<(Vec<u8>, SharedSecret, Vec<u8>), String> {
    match method {
        Method::MlKem768X25519 => {
            if client_public.len() != 1184 + 32 {
                return Err(format!("SSH: the mlkem768x25519 client value is {} \
                                    bytes and should be 1216.", client_public.len()));
            }
            let (ek, peer) = client_public.split_at(1184);
            let mut m = [0u8; 32];
            fill(&mut m)?;
            let (mut both, ciphertext) =
                ml_kem::encapsulate_internal(ml_kem::parameters("ML-KEM-768")?, ek, &m)?;
            let mut private = [0u8; 32];
            fill(&mut private)?;
            let peer: [u8; 32] = peer.try_into().map_err(|_| "length".to_string())?;
            both.extend_from_slice(&x25519::exchange(&private, &peer)?);
            let shared = SharedSecret::string(&hash("sha256", &both)?);
            let mut reply = ciphertext;
            reply.extend_from_slice(&x25519::public_key(&private)?);
            let ours = Ephemeral { method, secret: Secret::X25519(private),
                                   public: Vec::new(), exchange };
            let h = ours.exchange_hash(transcript, client_public, &reply, &shared)?;
            Ok((reply, shared, h))
        }
        Method::Sntrup761X25519 => {
            let length = sntrup::PUBLIC_KEY_BYTES + 32;
            if client_public.len() != length {
                return Err(format!("SSH: the sntrup761x25519 client value is {} \
                                    bytes and should be {length}.", client_public.len()));
            }
            let (pk, peer) = client_public.split_at(sntrup::PUBLIC_KEY_BYTES);
            let (ciphertext, mut both) = sntrup::encapsulate(pk, fill)?;
            let mut private = [0u8; 32];
            fill(&mut private)?;
            let peer: [u8; 32] = peer.try_into().map_err(|_| "length".to_string())?;
            both.extend_from_slice(&x25519::exchange(&private, &peer)?);
            let shared = SharedSecret::string(&hash("sha512", &both)?);
            let mut reply = ciphertext;
            reply.extend_from_slice(&x25519::public_key(&private)?);
            let ours = Ephemeral { method, secret: Secret::X25519(private),
                                   public: Vec::new(), exchange };
            let h = ours.exchange_hash(transcript, client_public, &reply, &shared)?;
            Ok((reply, shared, h))
        }
        _ => {
            // For every other method the server's half is made the same
            // way as the client's; only the order in the hash differs.
            let ours = Ephemeral::client(method, exchange, fill)?;
            let shared = ours.classical_secret(client_public)?;
            let h = ours.exchange_hash(transcript, client_public, &ours.public, &shared)?;
            Ok((ours.public, shared, h))
        }
    }
}

impl Ephemeral {
    /// `K` for the methods that are a Diffie-Hellman of some kind, from
    /// the other side's public value. Each as an mpint.
    fn classical_secret(&self, peer_public: &[u8]) -> Result<SharedSecret, String> {
        match &self.secret {
            Secret::X25519(private) => {
                let peer: [u8; 32] = peer_public.try_into().map_err(|_| format!(
                    "SSH: a Curve25519 public value is {} bytes and should be 32.",
                    peer_public.len()))?;
                // `exchange` refuses the all-zero output, as OpenSSH does.
                Ok(SharedSecret::mpint(&x25519::exchange(private, &peer)?))
            }
            Secret::Ecdh { curve, scalar } => {
                let ec = curve.curve();
                Ok(SharedSecret::mpint(&ec.ecdh(scalar, &ec.decode_point(peer_public)?)?))
            }
            Secret::Dh { group, exponent } => {
                let peer = BigUint::from_bytes_be(peer_public);
                group.validate_peer(&peer)?;
                Ok(SharedSecret::mpint(dh::strip_leading_zeros(
                    &group.shared_secret(exponent, &peer)?)))
            }
            Secret::Hybrid { .. } | Secret::Sntrup { .. } => Err(
                "SSH: the hybrids are KEMs, not Diffie-Hellman.".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript() -> Transcript<'static> {
        Transcript { client_version: b"SSH-2.0-a", server_version: b"SSH-2.0-b",
                     client_kexinit: b"\x14ci", server_kexinit: b"\x14si",
                     host_key: b"key" }
    }

    /// Both halves agree on K and H, for every method, the legacy ones
    /// included - except group 18, whose four 8192 bit exponentiations
    /// take most of a minute in a debug build and run the same code as
    /// group 16 with a longer constant (which `dh::rfc_modp_tests`
    /// checks).
    #[test]
    fn test_client_and_server_halves_agree() {
        let mut fill = |buf: &mut [u8]| crate::random::fill(buf);
        for spec in METHODS.iter().filter(|spec| spec.name != "diffie-hellman-group18-sha512") {
            let exchange = || match spec.method {
                Method::DhGroupExchange { .. } => Some(GroupExchange {
                    min: 1024, preferred: 2048, max: 8192, group: modp(2048).unwrap(),
                    old: false }),
                _ => None,
            };
            let client = Ephemeral::client(spec.method, exchange(), &mut fill).unwrap();
            let (reply, server_k, server_h) = server_respond(
                spec.method, exchange(), &transcript(), client.public(), &mut fill).unwrap();
            let (client_k, client_h) = client.finish(&transcript(), &reply).unwrap();
            assert_eq!(client_k.encoded(), server_k.encoded(), "{}", spec.name);
            assert_eq!(client_h, server_h, "{}", spec.name);
        }
    }

    /// The old request form hashes `n` alone, so the two forms of the
    /// same exchange have different hashes - a server that hashed
    /// `min, n, max` for an old request would derive keys its client
    /// does not share.
    #[test]
    fn test_the_old_group_exchange_request_hashes_n_alone() {
        let method = Method::DhGroupExchange { hash: "sha256" };
        let hash_for = |old: bool| {
            let mut fill = |buf: &mut [u8]| { buf.fill(7); Ok(()) };
            let exchange = GroupExchange {
                min: 1024, preferred: 2048, max: 8192, group: modp(2048).unwrap(), old };
            let client = Ephemeral::client(method, Some(exchange), &mut fill).unwrap();
            let exchange = GroupExchange {
                min: 1024, preferred: 2048, max: 8192, group: modp(2048).unwrap(), old };
            let (reply, _, server_h) = server_respond(
                method, Some(exchange), &transcript(), client.public(), &mut fill).unwrap();
            let (_, client_h) = client.finish(&transcript(), &reply).unwrap();
            assert_eq!(client_h, server_h);
            client_h
        };
        assert_ne!(hash_for(true), hash_for(false));
    }

    /// The hybrid's K is a string; everything else's an mpint.
    #[test]
    fn test_the_secret_is_a_string_only_for_the_hybrid() {
        let mut fill = |buf: &mut [u8]| crate::random::fill(buf);
        for (method, string) in [(Method::MlKem768X25519, true), (Method::Curve25519, false)] {
            let client = Ephemeral::client(method, None, &mut fill).unwrap();
            let (reply, _, _) = server_respond(method, None, &transcript(), client.public(),
                                               &mut fill).unwrap();
            let (k, _) = client.finish(&transcript(), &reply).unwrap();
            let length = u32::from_be_bytes(k.encoded()[..4].try_into().unwrap()) as usize;
            if string {
                assert_eq!(length, 32);
            } else {
                // An mpint of a 32 byte value: 31 to 33 bytes.
                assert!((31..=33).contains(&length), "{length}");
            }
        }
    }

    /// RFC 4253 7.2's extension: a key longer than the hash continues
    /// with HASH(K || H || key so far), and its prefix is the short key.
    #[test]
    fn test_derivation_extends_by_rehashing() {
        let shared = SharedSecret::mpint(&[7; 32]);
        let short = derive("sha256", &shared, &[1; 32], b'C', &[2; 32], 32).unwrap();
        let long = derive("sha256", &shared, &[1; 32], b'C', &[2; 32], 64).unwrap();
        assert_eq!(&long[..32], short.as_slice());
        let mut more = shared.encoded().to_vec();
        more.extend_from_slice(&[1; 32]);
        more.extend_from_slice(&short);
        assert_eq!(&long[32..], hash("sha256", &more).unwrap().as_slice());
    }
}
