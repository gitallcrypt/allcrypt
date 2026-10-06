/*
The CTR_OMAC key exchange from RFC 9189 section 4.2.

It is not a Diffie-Hellman exchange whose result becomes the premaster,
and it is not RSA key transport either. The client picks a 32 byte
preliminary secret at random, wraps it under keys derived from an
*ephemeral* GOST key agreement against the server's certificate key, and
sends the wrapped form. The server unwraps it with its certificate's
private key. So:

  * **there is no ServerKeyExchange.** The server's certificate carries
    everything the client needs, and RFC 9189 says one MUST NOT be sent.
    That is the same distinction `suites.rs` already has to make for the
    plain RSA suites, and for the same reason: whether a message is
    expected is decided by the negotiated suite, never by the message
    having arrived;

  * the server is authenticated by being able to *unwrap*, exactly as in
    RSA key transport - not by a signature;

  * the preliminary secret is the TLS premaster secret, and the master
    secret is then derived from it in the ordinary TLS 1.2 way with
    Streebog-256 as the PRF hash.

The three pieces, in the order they are used:

## KEG (section 8.3.1) - the export keys

    H = HASH(r_c | r_s)                      Streebog-256 of the randoms
    UKM = INT(H[1..16]), or 1 if that is 0
    K_EXP = VKO_256(d, Q, UKM)
    K_EXP_MAC | K_EXP_ENC = KDFTREE_256(K_EXP, "kdf tree", H[17..24], 1)

**`INT` is big endian** (RFC 9189 section 3), and VKO's own UKM
convention is little endian - the two are opposite, in one expression.
`Curve::vko_with_ukm` takes the integer so that neither caller inherits
the other's reading.

The 512 bit case is shorter and not a variation on the same theme: it is
`VKO_512(d, Q, UKM)` with **no KDF at all**, because VKO-512 already
produces the 64 bytes the pair of export keys needs. Feeding it through
the tree KDF anyway would be an obvious thing to do and would be wrong.

## KExp15 / KImp15 (section 8.2.1) - wrapping the secret

    IV = H[25..24 + n/2]
    CEK_MAC = OMAC(K_EXP_MAC, IV | S)
    SExp    = CTR(K_EXP_ENC, IV, S | CEK_MAC)

Authenticate-then-encrypt again, and the MAC covers the IV as well as
the secret. The CTR here is the plain one from GOST R 34.13-2015 with no
ACPKM: the message is 48 or 80 bytes, far inside one section, so the two
would agree anyway - which is exactly why using the wrong one is silent.
It is written as the plain mode because that is what the standard says,
not because the difference cannot be reached.

## GostKeyTransport - the ClientKeyExchange body

    GostKeyTransport ::= SEQUENCE {
        keyExp               OCTET STRING,
        ephemeralPublicKey   SubjectPublicKeyInfo,
        ukm                  OCTET STRING OPTIONAL
    }

DER, and the `ukm` field "MUST be ignored by the server" - it is a
vestige of the CNT_IMIT structure this one replaced. It is written
because implementations exist that expect it and reading it costs
nothing; it is ignored on the way in.

The ephemeral public key goes in a SubjectPublicKeyInfo, so its
encoding is the certificate one from RFC 9215 section 4.3: an OCTET
STRING inside the BIT STRING, holding **x then y, each little endian**,
padded to the field width. Three chances to be wrong, all silent against
another implementation making the same choice, and none of them visible
in a round trip against ourselves.
*/

use crate::asn1::{tag, Reader, Tag, Writer};
use crate::bignum::BigUint;
use crate::ec::vko::Cofactor;
use crate::ec::{Curve, Point};
use crate::hash_functions::streebog::Streebog;
use crate::hash_functions::HashFunction;
use crate::kdf::gost::kdf_tree_gostr3411_2012_256;
use crate::mac::cmac::Cmac;
use crate::tls::record_gost::CtrOmacSuite;
use crate::x509::oids;
use crate::Mac;

/// The preliminary secret's size, RFC 9189 section 4.2: `PS in B_32`.
pub const PRELIMINARY_SECRET_LEN: usize = 32;

// ------------------------------------------------------------- KEG ---

/// `H = HASH(r_c | r_s)`, the 32 bytes every later step slices up.
///
/// The order is client random then server random, and it is *not* the
/// order the TLS 1.2 PRF uses for the master secret (`r_c | r_s` here,
/// but `r_c | r_s` there too - which is the point: they agree, so
/// getting this backwards is not caught by the handshake failing at a
/// different step).
pub fn keg_hash(client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(client_random.len() + server_random.len());
    input.extend_from_slice(client_random);
    input.extend_from_slice(server_random);
    Streebog::new_256(&input).digest()
}

/// `KEG(d, Q, H)`, RFC 9189 section 8.3.1: 64 bytes of export key
/// material, which the caller splits into MAC and ENC halves.
pub fn keg(curve: &Curve, private: &BigUint, peer: &Point, h: &[u8])
           -> Result<Vec<u8>, String> {
    if h.len() != 32 {
        return Err(format!(
            "KEG's H is the 32 byte Streebog-256 of the two randoms; got {}.",
            h.len()));
    }

    // UKM = INT(H[1..16]) - **big endian**, RFC 9189 section 3. VKO's own
    // wire convention is little endian; these are opposite and both
    // appear in this one function, which is why the integer form of
    // `vko` exists.
    let mut ukm = BigUint::from_bytes_be(&h[..16]);
    if ukm.is_zero() {
        // The RFC says so explicitly rather than failing: a zero UKM
        // makes the shared point the identity, so it is replaced.
        ukm = BigUint::from_u64(1);
    }

    // The branch is on the *order*, not the curve's name or the key
    // length, because that is what RFC 9189 8.3.1 branches on.
    let bits = curve.n.bit_len();
    if bits > 254 && bits <= 256 {
        // **`AsSpecified`**: RFC 7836's `m/q` term included.
        //
        // This used to be `AsDeployed`, on the argument that a
        // handshake against a real box has to match the box and the box
        // runs gost-engine. The argument was right and the premise was
        // wrong: gost-engine applies the cofactor too, inside its point
        // multiplication rather than in `VKO_compute_key`, where
        // reading the source suggested otherwise. The `vko-tca-256` and
        // `vko-c-512` rows of `vectors/gost_engine.vec` are what
        // settled it - eighteen derivations the engine actually
        // produced, and all eighteen are the document's reading.
        //
        // The two readings agree on every curve with cofactor one, so
        // this changes nothing on seven of the nine and was invisible
        // in every handshake test. It changes the derived key on
        // `gost256-tc26-a` and `gost512-c`, where it would have derived
        // a key no peer shares. See `ec::vko`.
        let k_exp = curve.vko_with_ukm_using(private, peer, &ukm, 256,
                                             Cofactor::AsSpecified)?;
        // seed = H[17..24], eight bytes. L = 512, so the tree KDF emits
        // two blocks and both export keys come out of one call.
        kdf_tree_gostr3411_2012_256(&k_exp, b"kdf tree", &h[16..24], 1, 512)
    } else if bits > 508 && bits <= 512 {
        // No KDF: VKO-512 already produces 64 bytes, and running it
        // through the tree KDF as well would be the obvious mistake.
        curve.vko_with_ukm_using(private, peer, &ukm, 512,
                                 Cofactor::AsSpecified)
    } else {
        Err(format!(
            "KEG is defined for group orders in (2^254, 2^256) and \
             (2^508, 2^512); {} has a {} bit order.", curve.name, bits))
    }
}

/// KEG's output split the way RFC 9189 section 4.2.4.1 splits it.
///
/// Returned as a pair rather than 64 bytes because the halves are used
/// by different algorithms and swapping them produces a wrapped secret
/// that unwraps against an implementation making the same swap.
pub fn export_keys(curve: &Curve, private: &BigUint, peer: &Point, h: &[u8])
                   -> Result<(Vec<u8>, Vec<u8>), String> {
    let material = keg(curve, private, peer, h)?;
    if material.len() != 64 {
        return Err(format!("KEG produced {} bytes, not 64.", material.len()));
    }
    let (mac, enc) = material.split_at(32);
    Ok((mac.to_vec(), enc.to_vec()))
}

/// `IV = H[25..24 + n/2]`, RFC 9189 section 4.2.4.1.
///
/// One-indexed in the RFC, so it is bytes 24.. here, and its length is
/// half the *block*, which differs between the two suites.
pub fn export_iv(h: &[u8], suite: CtrOmacSuite) -> Result<Vec<u8>, String> {
    let width = suite.iv_len();
    if h.len() < 24 + width {
        return Err(format!(
            "The export IV is H[25..{}], which needs {} bytes of H; got {}.",
            24 + width, 24 + width, h.len()));
    }
    Ok(h[24..24 + width].to_vec())
}

// ------------------------------------------------- KExp15 / KImp15 ---

/// The plain CTR of GOST R 34.13-2015, as KExp15 uses it.
///
/// The counter block is `IV || 0^{n/2}` incremented as a big endian
/// integer, which is what the generic mode here already does once given
/// that starting block - so this is the generic CTR with the nonce
/// placed in the top half, and **not** CTR-ACPKM. The messages are 48 or
/// 80 bytes, well inside one ACPKM section, so the two agree on
/// everything this function is ever asked; using the wrong one would be
/// silent, which is why it is spelled out.
fn kexp_ctr(suite: CtrOmacSuite, key: &[u8], iv: &[u8], data: &[u8])
            -> Result<Vec<u8>, String> {
    if iv.len() * 2 != suite.block {
        return Err(format!(
            "KExp15's IV is half a block: {} bytes for {}, not {}.",
            suite.block / 2, suite.cipher, iv.len()));
    }
    let mut counter = vec![0u8; suite.block];
    counter[..iv.len()].copy_from_slice(iv);

    let mut stream = crate::api::CipherStream::new(
        crate::api::AnyBlockCipher::new(suite.cipher, key, None)?,
        crate::api::Mode::Ctr, &counter, false)?;
    let mut out = stream.update(data)?;
    out.extend_from_slice(&stream.finish()?);
    Ok(out)
}

/// `KExp15(S, K_MAC, K_ENC, IV)`, RFC 9189 section 8.2.1.
pub fn kexp15(suite: CtrOmacSuite, secret: &[u8], mac_key: &[u8],
              enc_key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    // CEK_MAC = OMAC(K_MAC, IV | S). The IV is inside the MAC as well as
    // being the counter's nonce, so a peer cannot move a wrapped secret
    // to a different IV.
    let mut mac = Cmac::with_key(suite.cipher, mac_key)?;
    mac.update(iv);
    mac.update(secret);
    let tag = mac.digest();

    let mut body = Vec::with_capacity(secret.len() + tag.len());
    body.extend_from_slice(secret);
    body.extend_from_slice(&tag);
    kexp_ctr(suite, enc_key, iv, &body)
}

/// `KImp15(SExp, K_MAC, K_ENC, IV)`, RFC 9189 section 8.2.1.
pub fn kimp15(suite: CtrOmacSuite, wrapped: &[u8], mac_key: &[u8],
              enc_key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if wrapped.len() <= suite.block {
        return Err(format!(
            "A wrapped secret is at least one block longer than the secret; \
             {} bytes cannot hold a {} byte MAC and anything else.",
            wrapped.len(), suite.block));
    }
    let mut plain = kexp_ctr(suite, enc_key, iv, wrapped)?;
    let tag = plain.split_off(plain.len() - suite.block);

    let mut mac = Cmac::with_key(suite.cipher, mac_key)?;
    mac.update(iv);
    mac.update(&plain);
    let want = mac.digest();

    let mut difference = 0u8;
    for (a, b) in tag.iter().zip(want.iter()) {
        difference |= a ^ b;
    }
    if difference != 0 || tag.len() != want.len() {
        return Err("The wrapped secret did not authenticate.".to_string());
    }
    Ok(plain)
}

// --------------------------------------------- GostKeyTransport ---

/// A GOST public key as a `SubjectPublicKeyInfo`, RFC 9215 section 4.3.
///
/// `BIT STRING { OCTET STRING { x_le || y_le } }` - the double wrapping
/// is real and not a mistake, and the coordinates are little endian and
/// padded to the field's width.
pub fn encode_public_key(curve: &Curve, point: &Point) -> Result<Vec<u8>, String> {
    encode_public_key_like(&algorithm_id_for(curve)?, curve, point)
}

/// The canonical 2012 `AlgorithmIdentifier` for a curve.
///
/// **Only for keys we are choosing the curve for** - writing a
/// certificate, or our own server's key. When the *peer* named the
/// curve, its OID is the one to use and this is the wrong function:
/// several OIDs name each of these curves and picking one discards which
/// the peer said. `encode_public_key_like` is the other one.
pub fn algorithm_id_for(curve: &Curve) -> Result<Vec<u8>, String> {
    let (algorithm, param_set, digest) = spki_oids(curve)?;
    let mut writer = Writer::new();
    writer.write_sequence(|algid| {
        algid.write_oid(algorithm);
            // GostR3410-2012-PublicKeyParameters, which is the parameter
            // set and an optional `digestParamSet`.
            //
        // RFC 9215 section 4.2 says a sender SHOULD NOT include the
        // digest OID, and RFC 9189's own handshake example does include
        // it. That is not a contradiction to resolve by preference here:
        // a server that predates the deprecation may expect it, one that
        // follows RFC 9215 must accept it anyway, and reproducing the
        // RFC's example byte for byte is a check this code would
        // otherwise not have. So it is written, and ignored on the way
        // in. **When answering a peer, the question does not arise** -
        // `encode_public_key_like` copies whichever the peer chose.
        algid.write_sequence(|params| {
            params.write_oid(param_set);
            params.write_oid(digest);
        });
    });
    Ok(writer.finish())
}

/// An ephemeral public key wearing **the server's own**
/// `AlgorithmIdentifier`.
///
/// This is what a ClientKeyExchange must carry, and the reason is a bug
/// a real server found. `oids::gost_curve_for` is many-to-one: twelve
/// parameter set OIDs name seven curves, because RFC 4357's CryptoPro
/// sets, TC 26's 2012 renumbering (shifted by one, so `paramSetB` is
/// CryptoPro-A) and RFC 4357's two *exchange* sets are three namings of
/// overlapping curves. `XchA` is CryptoPro-A to the digit.
///
/// `encode_public_key` below inverts that map, and **the inverse of a
/// many-to-one map is a choice.** It chose the CryptoPro spelling, so a
/// server whose certificate said `XchA` - or `paramSetB`, or `paramSetC`,
/// or `paramSetD` - got a different OID back than it had sent. The curve
/// was identical and the bytes were not, and CryptoPro answers
/// `decode_error`. Reported from a real server on `XchA`.
///
/// So the OIDs are not chosen here at all: the server's
/// `AlgorithmIdentifier` is copied whole. All seven handshakes in
/// `tests/transcripts/gost_handshakes.txt` show OpenSSL doing exactly
/// that, which is also what settles the `digestParamSet` question -
/// RFC 9215 4.2 says SHOULD NOT include it and RFC 9189's own example
/// includes it, and copying means agreeing with whichever the peer is.
///
/// **The curve is still checked.** Copying an AlgorithmIdentifier that
/// names a different curve from the point being written would produce a
/// key that is internally inconsistent, so the parameter set inside it
/// has to resolve to the curve the point is on. That check is the reason
/// this takes a `curve` it could otherwise infer.
pub fn encode_public_key_like(algorithm_id: &[u8], curve: &Curve,
                              point: &Point) -> Result<Vec<u8>, String> {
    // Parsed back rather than trusted: these bytes came off the wire in
    // a certificate, and writing them into our own message without
    // reading them would make this a byte-forwarding path for anything
    // an issuer chose to put there.
    let mut outer = Reader::new(algorithm_id);
    let mut algid = outer.read_sequence()?;
    outer.finish()?;
    let algorithm = algid.read_oid()?;
    let mut params = algid.read_sequence()?;
    algid.finish()?;
    let param_set = params.read_oid()?;

    let named = oids::gost_curve_for(param_set.as_bytes()).ok_or_else(|| format!(
        "The peer's parameter set {param_set} is not a GOST curve this \
         library has."))?;
    if named != curve.name {
        return Err(format!(
            "The peer's parameter set {param_set} is {named}, and the \
             ephemeral key is on {}.", curve.name));
    }
    let expected_algorithm = if curve.n.bit_len() > 256 {
        oids::GOST3410_12_512
    } else {
        // A 256 bit curve takes either the 2012 or the 2001 algorithm
        // OID, and which one is the server's business rather than ours.
        if algorithm.as_bytes() == oids::GOST3410_2001 {
            oids::GOST3410_2001
        } else {
            oids::GOST3410_12_256
        }
    };
    if algorithm.as_bytes() != expected_algorithm {
        return Err(format!(
            "The peer's key algorithm {algorithm} does not go with a \
             {} key.", curve.name));
    }

    let width = curve.field_bytes();
    let x = point.x().ok_or("the identity has no x coordinate")?;
    let y = point.y().ok_or("the identity has no y coordinate")?;
    let mut raw = x.to_bytes_be_padded(width)?;
    raw.reverse();
    let mut y_bytes = y.to_bytes_be_padded(width)?;
    y_bytes.reverse();
    raw.extend_from_slice(&y_bytes);

    let mut writer = Writer::new();
    writer.write_sequence(|spki| {
        // Verbatim, including whatever `digestParamSet` the server did
        // or did not include.
        spki.write_raw(algorithm_id);
        let mut inner = Writer::new();
        inner.write_octet_string(&raw);
        spki.write_bit_string(&inner.finish());
    });
    Ok(writer.finish())
}

/// A GOST R 34.10-2001 public key as a `SubjectPublicKeyInfo`, RFC 4357.
///
/// **The same bytes in the same wrappers, under a different algorithm
/// OID**: `GostR3410-2001-PublicKeyParameters` has the same shape as
/// the 2012 structure, so the only things that change are the
/// algorithm and the digest parameter set. Written as its own function
/// rather than a flag on the one above, because the flag would be a
/// boolean that decides which standard a key claims to be.
pub fn encode_public_key_2001(curve: &Curve, point: &Point)
                              -> Result<Vec<u8>, String> {
    encode_public_key_like(&algorithm_id_for_2001(curve)?, curve, point)
}

/// The canonical 2001 `AlgorithmIdentifier` for a curve.
///
/// Same caveat as `algorithm_id_for`: this picks one of the several OIDs
/// that name the curve, which is right when we are choosing the curve and
/// wrong when the peer already named it.
pub fn algorithm_id_for_2001(curve: &Curve) -> Result<Vec<u8>, String> {
    if curve.n.bit_len() > 256 {
        return Err(format!(
            "GOST R 34.10-2001 keys are 256 bit; {} is not.", curve.name));
    }
    let param_set = match curve.name {
        "gost256-a" => oids::GOST_2001_CRYPTOPRO_A,
        "gost256-b" => oids::GOST_2001_CRYPTOPRO_B,
        "gost256-c" => oids::GOST_2001_CRYPTOPRO_C,
        // The TC 26 sets arrived with the 2012 standard, so a 2001 key
        // on one of them is not a thing that exists.
        other => return Err(format!(
            "{} has no GOST R 34.10-2001 parameter set OID.", other)),
    };
    let mut writer = Writer::new();
    writer.write_sequence(|algid| {
        algid.write_oid(oids::GOST3410_2001);
        algid.write_sequence(|params| {
            params.write_oid(param_set);
            params.write_oid(oids::GOST3411_94_CRYPTOPRO_PARAMSET);
        });
    });
    Ok(writer.finish())
}

/// Read a GOST `SubjectPublicKeyInfo` back.
///
/// Returns the curve its parameters name along with the point, because
/// the point's meaning depends on the curve and carrying them
/// separately is how a point ends up validated against the wrong one.
pub fn decode_public_key(der: &[u8]) -> Result<(Curve, Point), String> {
    let mut outer = Reader::new(der);
    let mut spki = outer.read_sequence()?;
    outer.finish()?;

    let mut algid = spki.read_sequence()?;
    let algorithm = algid.read_tagged(Tag::universal(tag::OID))?;
    // The 2001 algorithm OID is accepted here too: the ephemeral key
    // in a 2001 key transport blob is encoded exactly like a 2012 one
    // and differs only in this field, so refusing it would refuse the
    // 0x0081 suite's ClientKeyExchange for a difference that is not in
    // the bytes that follow.
    if algorithm != oids::GOST3410_12_256 && algorithm != oids::GOST3410_12_512
        && algorithm != oids::GOST3410_2001 {
        return Err(format!(
            "The key's algorithm is {}, which is not a GOST R 34.10 one.",
            oids::name_of(algorithm).unwrap_or("an unknown OID")));
    }
    let mut params = algid.read_sequence()?;
    let param_set = params.read_tagged(Tag::universal(tag::OID))?;
    // `digestParamSet` may follow and is obsolete; anything else here is
    // not a parameters block we understand.

    let name = oids::gost_curve_for(param_set).ok_or_else(|| format!(
        "The parameter set {} is not a curve this library implements.",
        oids::name_of(param_set).unwrap_or("with an unknown OID")))?;
    let curve = crate::ec::curves::by_name(name)?;

    let bits = spki.read_tagged(Tag::universal(tag::BIT_STRING))?;
    spki.finish()?;
    if bits.first() != Some(&0) {
        return Err("The public key BIT STRING has unused bits.".to_string());
    }
    let mut inner = Reader::new(&bits[1..]);
    let raw = inner.read_tagged(Tag::universal(tag::OCTET_STRING))?;
    inner.finish()?;

    let width = curve.field_bytes();
    if raw.len() != 2 * width {
        return Err(format!(
            "A {} public key is {} bytes, x then y; got {}.",
            curve.name, 2 * width, raw.len()));
    }

    // Little endian, both halves.
    let mut x = raw[..width].to_vec();
    x.reverse();
    let mut y = raw[width..].to_vec();
    y.reverse();
    let point = Point::new(BigUint::from_bytes_be(&x), BigUint::from_bytes_be(&y));

    // Validated here rather than by the caller: a point that is not on
    // the curve moves the whole exchange into a group the peer chose.
    curve.validate(&point)?;
    Ok((curve, point))
}

/// Which OIDs a curve's `SubjectPublicKeyInfo` carries: the algorithm,
/// the parameter set, and the digest.
///
/// The algorithm and digest OIDs follow the key *size*, and the
/// parameter set is the curve. The CryptoPro names are used for the 256 bit curves
/// because that is what certificates in the wild carry; the TC 26 names
/// for the same curves are accepted on the way in.
#[allow(clippy::type_complexity)]
fn spki_oids(curve: &Curve)
             -> Result<(&'static [u8], &'static [u8], &'static [u8]), String> {
    Ok(match curve.name {
        "gost256-a" => (oids::GOST3410_12_256, oids::GOST_2001_CRYPTOPRO_A,
                        oids::GOST3411_12_256),
        "gost256-b" => (oids::GOST3410_12_256, oids::GOST_2001_CRYPTOPRO_B,
                        oids::GOST3411_12_256),
        "gost256-c" => (oids::GOST3410_12_256, oids::GOST_2001_CRYPTOPRO_C,
                        oids::GOST3411_12_256),
        // The one 256 bit set with no CryptoPro name, so the TC 26 one
        // is what a certificate carries.
        "gost256-tc26-a" => (oids::GOST3410_12_256, oids::GOST_2012_256_PARAMSET_A,
                        oids::GOST3411_12_256),
        "gost512-a" => (oids::GOST3410_12_512, oids::GOST_2012_512_PARAMSET_A,
                        oids::GOST3411_12_512),
        "gost512-b" => (oids::GOST3410_12_512, oids::GOST_2012_512_PARAMSET_B,
                        oids::GOST3411_12_512),
        "gost512-c" => (oids::GOST3410_12_512, oids::GOST_2012_512_PARAMSET_C,
                        oids::GOST3411_12_512),
        other => return Err(format!(
            "{} is not a GOST curve, so it has no GOST parameter set OID.",
            other)),
    })
}

/// The `GostKeyTransport` body of a ClientKeyExchange.
pub struct KeyTransport {
    pub wrapped: Vec<u8>,
    pub ephemeral: Vec<u8>,
    /// Present in the structure and **ignored by the server** (RFC 9189
    /// section 4.2.4.1). Kept so a peer that sends one round trips.
    pub ukm: Option<Vec<u8>>,
}

impl KeyTransport {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_sequence(|body| {
            body.write_octet_string(&self.wrapped);
            body.write_raw(&self.ephemeral);
            if let Some(ukm) = &self.ukm {
                body.write_octet_string(ukm);
            }
        });
        writer.finish()
    }

    pub fn parse(der: &[u8]) -> Result<KeyTransport, String> {
        let mut outer = Reader::new(der);
        let mut body = outer.read_sequence()?;
        outer.finish()?;

        let wrapped = body.read_tagged(Tag::universal(tag::OCTET_STRING))?
                          .to_vec();
        let ephemeral = body.read_raw()?.to_vec();
        let ukm = if body.is_empty() {
            None
        } else {
            Some(body.read_tagged(Tag::universal(tag::OCTET_STRING))?.to_vec())
        };
        body.finish()?;
        Ok(KeyTransport { wrapped, ephemeral, ukm })
    }
}

// ------------------------------------------------- the two halves ---

/// The client's side: pick an ephemeral key and a preliminary secret,
/// and produce the ClientKeyExchange body.
///
/// Returns the secret as well, because it is the premaster and the
/// caller needs it - it is generated here rather than passed in so that
/// there is one place the length and the source of randomness are
/// decided.
pub fn client_key_exchange(suite: CtrOmacSuite, curve: &Curve,
                           server_algorithm_id: &[u8],
                           server_public: &Point, client_random: &[u8],
                           server_random: &[u8])
                           -> Result<(Vec<u8>, Vec<u8>), String> {
    let secret = crate::random::bytes(PRELIMINARY_SECRET_LEN)?;
    let (ephemeral_private, ephemeral_public) = curve.generate_key_pair()?;
    let body = wrap_secret(suite, curve, server_algorithm_id,
                           &ephemeral_private, &ephemeral_public,
                           server_public, client_random, server_random, &secret)?;
    Ok((body, secret))
}

/// The wrapping, with the ephemeral key and the secret supplied.
///
/// Split out from `client_key_exchange` so the tests and the corpus can
/// drive it deterministically: everything random is an argument.
#[allow(clippy::too_many_arguments)]
pub fn wrap_secret(suite: CtrOmacSuite, curve: &Curve,
                   server_algorithm_id: &[u8],
                   ephemeral_private: &BigUint, ephemeral_public: &Point,
                   server_public: &Point, client_random: &[u8],
                   server_random: &[u8], secret: &[u8])
                   -> Result<Vec<u8>, String> {
    if secret.len() != PRELIMINARY_SECRET_LEN {
        return Err(format!(
            "The preliminary secret is {} bytes (RFC 9189 section 4.2); got {}.",
            PRELIMINARY_SECRET_LEN, secret.len()));
    }
    let h = keg_hash(client_random, server_random);
    let (mac_key, enc_key) = export_keys(curve, ephemeral_private,
                                         server_public, &h)?;
    let iv = export_iv(&h, suite)?;
    let wrapped = kexp15(suite, secret, &mac_key, &enc_key, &iv)?;

    Ok(KeyTransport {
        wrapped,
        // **The server's AlgorithmIdentifier, copied.** Not the
        // canonical OID for this curve - see `encode_public_key_like`.
        ephemeral: encode_public_key_like(server_algorithm_id, curve,
                                         ephemeral_public)?,
        ukm: None,
    }.encode())
}

/// The server's side: recover the preliminary secret from a
/// ClientKeyExchange body.
///
/// Here for the differential corpus and for symmetry - this library has
/// no server - and because writing both halves is what makes the wrap
/// testable at all.
pub fn unwrap_secret(suite: CtrOmacSuite, curve: &Curve, private: &BigUint,
                     client_random: &[u8], server_random: &[u8], body: &[u8])
                     -> Result<Vec<u8>, String> {
    let transport = KeyTransport::parse(body)?;
    let (their_curve, ephemeral) = decode_public_key(&transport.ephemeral)?;
    if their_curve.name != curve.name {
        return Err(format!(
            "The ephemeral key is on {}, and the server's key is on {}. \
             RFC 9189 section 4.2.4.1 requires the same curve.",
            their_curve.name, curve.name));
    }
    // `decode_public_key` validated the point, which covers "on the
    // curve" and "not the identity"; `n * Q = O` follows from the point
    // being on a curve of prime order, which every GOST curve here is.
    if ephemeral.is_identity() {
        return Err("The ephemeral public key is the identity.".to_string());
    }

    let h = keg_hash(client_random, server_random);
    let (mac_key, enc_key) = export_keys(curve, private, &ephemeral, &h)?;
    let iv = export_iv(&h, suite)?;
    kimp15(suite, &transport.wrapped, &mac_key, &enc_key, &iv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..text.len()).step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn scalar(curve: &Curve, seed: u8) -> BigUint {
        let mut bytes = vec![0u8; curve.field_bytes()];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = ((i as u32 * 97 + seed as u32 * 31 + 7) & 0xff) as u8;
        }
        bytes[0] &= 0x3f;
        BigUint::from_bytes_be(&bytes)
    }

    /// RFC 9189 Appendix A.1.3.1, the Magma handshake example.
    ///
    /// This is the only thing that settles the byte orders. Every one of
    /// them - `INT(H[1..16])` big endian while VKO's own UKM is little
    /// endian, the coordinates little endian in the
    /// SubjectPublicKeyInfo, which eight bytes of H are the seed and
    /// which four are the IV - produces an exchange that works
    /// perfectly against another implementation making the same
    /// choice. The round trip test below cannot see any of it.
    ///
    /// The example prints every intermediate value, so each step is
    /// checked rather than only the answer.
    #[test]
    fn test_rfc_9189_magma_handshake() {
        let curve = curves::by_name("gost256-a").unwrap();
        let suite = CtrOmacSuite::MAGMA;

        let client_random = unhex(
            "933EA21EC3802A561550EC78D6ED51AC2439D7E749C31BC3A3456165889684CA");
        let server_random = unhex(
            "933EA21E49C31BC3A3456165889684CAA5576CE7924A24F58113808DBD9EF856");

        let server_public = Point::new(
            BigUint::from_bytes_be(&unhex(
                "6531D4A72E655BFC9DFB94293B26070282FABF10D5C49B7366148C60E0BF8167")),
            BigUint::from_bytes_be(&unhex(
                "37F8CC71DC5D917FC4A66F7826E727508270B4FFC266C26CD4363E77B553A5B8")));
        let server_private = BigUint::from_bytes_be(&unhex(
            "5F308355DFD6A8ACAEE0837B100A3B1F6D63FB29B78EF27D3967757F0527144C"));
        // The private key must actually be the public one's, or the
        // example is being checked against half of itself.
        assert_eq!(curve.scalar_mul(&curve.g, &server_private), server_public);

        let ephemeral_private = BigUint::from_bytes_be(&unhex(
            "A5C77C7482373DE16CE4A6F73CCE7F78471493FF2C0709B8B706C9E8A25E6C1E"));
        let ephemeral_public = Point::new(
            BigUint::from_bytes_be(&unhex(
                "A8F36D63D262A203978F1B3B6795CDBBF1AE7FB8EF7F47F1F18871C198E00793")),
            BigUint::from_bytes_be(&unhex(
                "34CA5D6B4485640EA195435993BEB1F8B016ED610496B5CC175AC2EA1F14F887")));
        assert_eq!(curve.scalar_mul(&curve.g, &ephemeral_private),
                   ephemeral_public);

        // H = Streebog-256(r_c | r_s), and the order matters.
        let h = keg_hash(&client_random, &server_random);
        assert_eq!(hex(&h), "c3ef0428d4b7a1f4c5025f2e65dd2b2e\
                             a583aeefdb67c7f4214a6a298e99e325");

        // UKM = INT(H[1..16]), big endian, and the seed is the next
        // eight bytes - not the four after those, which are the IV.
        assert_eq!(hex(&h[..16]), "c3ef0428d4b7a1f4c5025f2e65dd2b2e");
        assert_eq!(hex(&h[16..24]), "a583aeefdb67c7f4");
        assert_eq!(hex(&export_iv(&h, suite).unwrap()), "214a6a29");

        // K_EXP, the VKO output before the tree KDF.
        let ukm = BigUint::from_bytes_be(&h[..16]);
        assert_eq!(hex(&curve.vko_with_ukm(&ephemeral_private, &server_public,
                                           &ukm, 256).unwrap()),
                   "1e585490e865ffd18f18d7c0a04d0ee8\
                    4f1a5d797cefada01b1e3b7fdb90e029");

        // And the 64 bytes of export key material the KDF makes of it.
        let (mac_key, enc_key) = export_keys(&curve, &ephemeral_private,
                                             &server_public, &h).unwrap();
        assert_eq!(hex(&mac_key), "2d8ba8c84cb232ff41f10c3ad9241342\
                                   23254f71e5696d3d29c3e4c9daa6b293");
        assert_eq!(hex(&enc_key), "849eb6340bffae6928a3c3e4ff92eccb\
                                   1e8f0cf7a188368e6b748e52ea378b0c");

        // The server reaches the same material from the other side.
        assert_eq!(export_keys(&curve, &server_private, &ephemeral_public, &h)
                       .unwrap(),
                   (mac_key.clone(), enc_key.clone()));

        // PMS and its wrapped form.
        let pms = unhex("A5576CE7924A24F58113808DBD9EF856\
                         F5BDC3B183CE5DADCA36A53AA077651D");
        let wrapped = kexp15(suite, &pms, &mac_key, &enc_key,
                             &export_iv(&h, suite).unwrap()).unwrap();
        assert_eq!(hex(&wrapped),
                   "d7f0f042236786 7b25fa4233a954f58b\
                    de92e9c9bbfb8816c99f15e6398722a0\
                    b2b7bfe8493e9a5c".replace(' ', ""));

        // The whole ClientKeyExchange body, byte for byte.
        let body = wrap_secret(suite, &curve, &algorithm_id_for(&curve).unwrap(), &ephemeral_private,
                               &ephemeral_public, &server_public,
                               &client_random, &server_random, &pms).unwrap();
        // `unhex` drops whitespace, so the message is written in the
        // RFC's own grouping: the wrapped secret, then the SPKI - which
        // carries the algorithm OID, the parameter set, the
        // `digestParamSet` the RFC's example includes, and the 64 raw
        // coordinate bytes.
        assert_eq!(hex(&body), hex(&unhex(
            "308192 0428 D7F0F042 2367867B 25FA4233 A954F58B\
                          DE92E9C9 BBFB8816 C99F15E6 398722A0\
                          B2B7BFE8 493E9A5C\
             3066 301F 06082A85030701010101\
                       3013 06072A8503020223 01\
                            06082A8503070101 0202\
                  034300 0440\
                    9307E098C17188F1F1477FEFB87FAEF1\
                    BBCD95673B1B8F9703A262D2636DF3A8\
                    87F8141FEAC25A17CCB5960461ED16B0\
                    F8B1BE93594395A10E6485446B5DCA34")));

        // And the server recovers the PMS from it.
        assert_eq!(unwrap_secret(suite, &curve, &server_private,
                                 &client_random, &server_random, &body).unwrap(),
                   pms);
    }

    /// The whole exchange, both halves, on every GOST curve and both
    /// suites.
    ///
    /// This proves less than it looks - the two halves are ours, and a
    /// shared misreading round trips - so what it actually covers is
    /// the plumbing: the DER, the curve check, the lengths. The byte
    /// orders are the differential corpus's job.
    #[test]
    fn test_the_exchange_round_trips() {
        for name in curves::gost_names() {
            let curve = curves::by_name(name).unwrap();
            let server_private = scalar(&curve, 1);
            let server_public = curve.scalar_mul(&curve.g, &server_private);

            for suite in [CtrOmacSuite::MAGMA, CtrOmacSuite::KUZNYECHIK] {
                let ephemeral_private = scalar(&curve, 2);
                let ephemeral_public = curve.scalar_mul(&curve.g,
                                                        &ephemeral_private);
                let secret = [0x5au8; PRELIMINARY_SECRET_LEN];
                let body = wrap_secret(suite, &curve, &algorithm_id_for(&curve).unwrap(), &ephemeral_private,
                                       &ephemeral_public, &server_public,
                                       &[1u8; 32], &[2u8; 32], &secret).unwrap();

                let got = unwrap_secret(suite, &curve, &server_private,
                                        &[1u8; 32], &[2u8; 32], &body).unwrap();
                assert_eq!(got, secret, "{} {}", name, suite.cipher);

                // The wrapped secret is not the secret in the clear.
                assert!(!body.windows(secret.len()).any(|w| w == secret),
                        "{}: the secret appears in the message", name);
            }
        }
    }

    /// The randoms are in the export keys, so a different hello gives a
    /// different wrap and the wrong one fails to unwrap rather than
    /// producing a different secret quietly.
    #[test]
    fn test_the_randoms_are_bound_in() {
        let curve = curves::by_name("gost256-a").unwrap();
        let server_private = scalar(&curve, 1);
        let server_public = curve.scalar_mul(&curve.g, &server_private);
        let ephemeral_private = scalar(&curve, 2);
        let ephemeral_public = curve.scalar_mul(&curve.g, &ephemeral_private);
        let secret = [0x11u8; PRELIMINARY_SECRET_LEN];

        let body = wrap_secret(CtrOmacSuite::MAGMA, &curve, &algorithm_id_for(&curve).unwrap(), &ephemeral_private,
                               &ephemeral_public, &server_public,
                               &[1u8; 32], &[2u8; 32], &secret).unwrap();

        assert!(unwrap_secret(CtrOmacSuite::MAGMA, &curve, &server_private,
                              &[1u8; 32], &[3u8; 32], &body).is_err(),
                "a different server random still unwrapped");
        assert!(unwrap_secret(CtrOmacSuite::MAGMA, &curve, &server_private,
                              &[9u8; 32], &[2u8; 32], &body).is_err(),
                "a different client random still unwrapped");
        // And swapping them is a different H, because the concatenation
        // is ordered.
        assert!(unwrap_secret(CtrOmacSuite::MAGMA, &curve, &server_private,
                              &[2u8; 32], &[1u8; 32], &body).is_err());
    }

    /// The two export keys are not interchangeable. Swapping them
    /// produces a wrap that a peer making the same swap would accept,
    /// so only an explicit check can see it.
    #[test]
    fn test_the_export_keys_are_not_interchangeable() {
        let suite = CtrOmacSuite::KUZNYECHIK;
        let secret = [0x77u8; 32];
        let mac_key = [0x01u8; 32];
        let enc_key = [0x02u8; 32];
        let iv = [0x03u8; 8];

        let right = kexp15(suite, &secret, &mac_key, &enc_key, &iv).unwrap();
        let swapped = kexp15(suite, &secret, &enc_key, &mac_key, &iv).unwrap();
        assert_ne!(right, swapped);
        assert!(kimp15(suite, &swapped, &mac_key, &enc_key, &iv).is_err());
        assert_eq!(kimp15(suite, &right, &mac_key, &enc_key, &iv).unwrap(),
                   secret);
    }

    /// KExp15's MAC covers the IV, so a wrapped secret cannot be moved
    /// to another IV - and every bit of it is covered.
    #[test]
    fn test_the_wrap_is_authenticated() {
        let suite = CtrOmacSuite::MAGMA;
        let secret = [0x42u8; 32];
        let (mac_key, enc_key, iv) = ([0x0au8; 32], [0x0bu8; 32], [0x0cu8; 4]);
        let wrapped = kexp15(suite, &secret, &mac_key, &enc_key, &iv).unwrap();
        assert_eq!(wrapped.len(), 32 + suite.block);

        let mut other_iv = iv;
        other_iv[0] ^= 1;
        assert!(kimp15(suite, &wrapped, &mac_key, &enc_key, &other_iv).is_err(),
                "the wrap was accepted under a different IV");

        for bit in 0..wrapped.len() * 8 {
            let mut altered = wrapped.clone();
            altered[bit / 8] ^= 1 << (bit % 8);
            assert!(kimp15(suite, &altered, &mac_key, &enc_key, &iv).is_err(),
                    "bit {} could be flipped undetected", bit);
        }
    }

    /// KEG's 512 bit branch has **no KDF**: VKO-512 already produces 64
    /// bytes. Running it through the tree KDF as well is the obvious
    /// thing to do and is wrong, so it is asserted against.
    #[test]
    fn test_the_512_branch_does_not_use_the_kdf() {
        let curve = curves::by_name("gost512-a").unwrap();
        let private = scalar(&curve, 3);
        let peer = curve.scalar_mul(&curve.g, &scalar(&curve, 4));
        let h: Vec<u8> = (0..32u8).collect();

        let material = keg(&curve, &private, &peer, &h).unwrap();
        assert_eq!(material.len(), 64);

        let mut ukm = BigUint::from_bytes_be(&h[..16]);
        if ukm.is_zero() {
            ukm = BigUint::from_u64(1);
        }
        let vko = curve.vko_with_ukm(&private, &peer, &ukm, 512).unwrap();
        assert_eq!(material, vko, "the 512 bit branch is VKO-512 unchanged");

        let through_kdf = kdf_tree_gostr3411_2012_256(&vko, b"kdf tree",
                                                      &h[16..24], 1, 512)
                          .unwrap();
        assert_ne!(material, through_kdf,
                   "the 512 bit branch must not also run the tree KDF");
    }

    /// The 256 bit branch does use it, and the seed is H[17..24] - eight
    /// bytes starting at offset 16, not at 24 where the IV starts.
    #[test]
    fn test_the_256_branch_uses_the_kdf_with_the_right_slice() {
        let curve = curves::by_name("gost256-a").unwrap();
        let private = scalar(&curve, 5);
        let peer = curve.scalar_mul(&curve.g, &scalar(&curve, 6));
        let h: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(9)).collect();

        let material = keg(&curve, &private, &peer, &h).unwrap();
        let ukm = BigUint::from_bytes_be(&h[..16]);
        let k_exp = curve.vko_with_ukm(&private, &peer, &ukm, 256).unwrap();

        assert_eq!(material,
                   kdf_tree_gostr3411_2012_256(&k_exp, b"kdf tree", &h[16..24],
                                               1, 512).unwrap());
        // The neighbouring slices must give something else, or the
        // offset is not being checked by this test at all.
        for wrong in [&h[24..32], &h[8..16], &h[17..25]] {
            assert_ne!(material,
                       kdf_tree_gostr3411_2012_256(&k_exp, b"kdf tree", wrong,
                                                   1, 512).unwrap());
        }
    }

    /// A zero UKM is replaced by one rather than failing, which is what
    /// the RFC says - and the two are different keys, so the rule is
    /// reachable rather than decorative.
    #[test]
    fn test_a_zero_ukm_becomes_one() {
        let curve = curves::by_name("gost256-a").unwrap();
        let private = scalar(&curve, 7);
        let peer = curve.scalar_mul(&curve.g, &scalar(&curve, 8));

        let mut zero_h = vec![0u8; 32];
        zero_h[24..].copy_from_slice(&[0xaa; 8]);   // the IV half, not the UKM
        let with_zero = keg(&curve, &private, &peer, &zero_h).unwrap();

        let mut one_h = zero_h.clone();
        one_h[15] = 1;      // INT is big endian, so the last byte is the low one
        assert_eq!(with_zero, keg(&curve, &private, &peer, &one_h).unwrap());

        // And a UKM of 2 is a different key, so the substitution is not
        // simply "any small UKM gives the same answer".
        let mut two_h = zero_h.clone();
        two_h[15] = 2;
        assert_ne!(with_zero, keg(&curve, &private, &peer, &two_h).unwrap());
    }

    /// `INT` is big endian. The reversed reading of H[1..16] must give a
    /// different UKM and therefore different export keys.
    #[test]
    fn test_the_ukm_is_read_big_endian() {
        let curve = curves::by_name("gost256-a").unwrap();
        let private = scalar(&curve, 9);
        let peer = curve.scalar_mul(&curve.g, &scalar(&curve, 10));
        let h: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(13).wrapping_add(1))
                                  .collect();

        let ours = keg(&curve, &private, &peer, &h).unwrap();

        let mut reversed = h[..16].to_vec();
        reversed.reverse();
        let other_ukm = BigUint::from_bytes_be(&reversed);
        let k_exp = curve.vko_with_ukm(&private, &peer, &other_ukm, 256).unwrap();
        let backwards = kdf_tree_gostr3411_2012_256(&k_exp, b"kdf tree",
                                                    &h[16..24], 1, 512).unwrap();
        assert_ne!(ours, backwards);
    }

    /// The SubjectPublicKeyInfo round trips, and its coordinates are
    /// little endian inside an OCTET STRING inside the BIT STRING.
    #[test]
    fn test_the_public_key_encoding() {
        let curve = curves::by_name("gost256-a").unwrap();
        let point = curve.scalar_mul(&curve.g, &scalar(&curve, 11));
        let der = encode_public_key(&curve, &point).unwrap();

        let (back_curve, back) = decode_public_key(&der).unwrap();
        assert_eq!(back_curve.name, curve.name);
        assert_eq!(back, point);

        // The raw coordinates, little endian, must appear in the DER.
        let width = curve.field_bytes();
        let mut x = point.x().unwrap().to_bytes_be_padded(width).unwrap();
        assert!(!der.windows(width).any(|w| w == x),
                "the x coordinate is big endian in the encoding");
        x.reverse();
        assert!(der.windows(width).any(|w| w == x),
                "the x coordinate is not little endian in the encoding");

        // The double wrapping is real: the BIT STRING's content is an
        // OCTET STRING, not the coordinates directly. Read it rather
        // than scanning for a tag byte - 0x03 also occurs inside the
        // parameter set OID, which is what a scan finds first.
        let mut outer = Reader::new(&der);
        let mut spki = outer.read_sequence().unwrap();
        spki.read_sequence().unwrap();      // the AlgorithmIdentifier
        let bits = spki.read_tagged(Tag::universal(tag::BIT_STRING)).unwrap();
        assert_eq!(bits[0], 0, "the BIT STRING must have no unused bits");
        assert_eq!(bits[1], 0x04,
                   "the BIT STRING does not contain an OCTET STRING");
        assert_eq!(usize::from(bits[2]), 2 * width,
                   "the OCTET STRING is not both coordinates");
    }

    /// A key on a curve we do not implement is refused by name rather
    /// than being mistaken for one we do.
    #[test]
    fn test_an_unknown_parameter_set_is_refused() {
        let curve = curves::by_name("gost256-a").unwrap();
        let point = curve.scalar_mul(&curve.g, &scalar(&curve, 12));
        let der = encode_public_key(&curve, &point).unwrap();

        // Rebuild the same key under the twisted Edwards paramSetA,
        // which is a real parameter set and not one this library has.
        // Built rather than patched: the two OIDs are different lengths,
        // so a byte substitution would corrupt the DER and the refusal
        // would be about the encoding instead of the curve.
        let mut outer = Reader::new(&der);
        let mut spki = outer.read_sequence().unwrap();
        spki.read_sequence().unwrap();
        let bits = spki.read_tagged(Tag::universal(tag::BIT_STRING)).unwrap();

        let mut writer = Writer::new();
        writer.write_sequence(|out| {
            out.write_sequence(|algid| {
                algid.write_oid(oids::GOST3410_12_256);
                // The 512 bit *test* set: a real parameter set, and
                // the one this library still has no arithmetic for.
                // It was `GOST_2012_256_PARAMSET_A` until that curve
                // was implemented, at which point this test started
                // refusing for the wrong reason - the point is not on
                // that curve - rather than for the unknown set.
                algid.write_sequence(|p| p.write_oid(oids::GOST_2012_512_PARAMSET_TEST));
            });
            out.write_bit_string(&bits[1..]);
        });
        let altered = writer.finish();

        let refused = decode_public_key(&altered).unwrap_err();
        assert!(refused.contains("1.2.643.7.1.2.1.2.0"), "{}", refused);

        // And the same rebuild with the *right* parameter set must
        // succeed, or this test would pass on a broken rebuild.
        let mut writer = Writer::new();
        writer.write_sequence(|out| {
            out.write_sequence(|algid| {
                algid.write_oid(oids::GOST3410_12_256);
                algid.write_sequence(|p| p.write_oid(oids::GOST_2001_CRYPTOPRO_A));
            });
            out.write_bit_string(&bits[1..]);
        });
        assert_eq!(decode_public_key(&writer.finish()).unwrap().1, point);
    }

    /// A point that is not on the curve is refused at parse time. An
    /// invalid-curve point moves the exchange into a group the peer
    /// chose, and the wrap would otherwise happily proceed.
    #[test]
    fn test_a_point_off_the_curve_is_refused() {
        let curve = curves::by_name("gost256-a").unwrap();
        let point = curve.scalar_mul(&curve.g, &scalar(&curve, 13));
        let mut der = encode_public_key(&curve, &point).unwrap();
        let last = der.len() - 1;
        der[last] ^= 0x01;
        assert!(decode_public_key(&der).is_err(),
                "a point off the curve was accepted");
    }

    /// The ephemeral key must be on the same curve as the server's.
    #[test]
    fn test_a_mismatched_curve_is_refused() {
        let curve = curves::by_name("gost256-a").unwrap();
        let other = curves::by_name("gost256-b").unwrap();
        let server_private = scalar(&curve, 1);
        let server_public = curve.scalar_mul(&curve.g, &server_private);

        // A well formed message, but built on the other curve.
        let ephemeral_private = scalar(&other, 2);
        let ephemeral_public = other.scalar_mul(&other.g, &ephemeral_private);
        let body = wrap_secret(CtrOmacSuite::MAGMA, &other, &algorithm_id_for(&other).unwrap(), &ephemeral_private,
                               &ephemeral_public,
                               &other.scalar_mul(&other.g, &scalar(&other, 3)),
                               &[0u8; 32], &[0u8; 32], &[0u8; 32]).unwrap();

        let refused = unwrap_secret(CtrOmacSuite::MAGMA, &curve, &server_private,
                                    &[0u8; 32], &[0u8; 32], &body).unwrap_err();
        assert!(refused.contains("same curve"), "{}", refused);

        // The same message built on the server's own curve is accepted,
        // so the refusal above is about the curve and not about the
        // message being malformed some other way.
        let ephemeral_private = scalar(&curve, 2);
        let ephemeral_public = curve.scalar_mul(&curve.g, &ephemeral_private);
        let body = wrap_secret(CtrOmacSuite::MAGMA, &curve, &algorithm_id_for(&curve).unwrap(), &ephemeral_private,
                               &ephemeral_public, &server_public,
                               &[0u8; 32], &[0u8; 32], &[0u8; 32]).unwrap();
        assert_eq!(unwrap_secret(CtrOmacSuite::MAGMA, &curve, &server_private,
                                 &[0u8; 32], &[0u8; 32], &body).unwrap(),
                   [0u8; 32]);
    }

    /// The `ukm` field is optional and ignored, so a message with one
    /// and a message without both parse.
    #[test]
    fn test_the_ukm_field_is_optional_and_ignored() {
        let without = KeyTransport { wrapped: vec![1, 2, 3],
                                     ephemeral: vec![0x05, 0x00],
                                     ukm: None };
        let with = KeyTransport { wrapped: vec![1, 2, 3],
                                  ephemeral: vec![0x05, 0x00],
                                  ukm: Some(vec![9, 9, 9, 9, 9, 9, 9, 9]) };
        for message in [&without, &with] {
            let back = KeyTransport::parse(&message.encode()).unwrap();
            assert_eq!(back.wrapped, message.wrapped);
            assert_eq!(back.ephemeral, message.ephemeral);
            assert_eq!(back.ukm, message.ukm);
        }
        assert_ne!(without.encode(), with.encode());
    }

    /// The generated form produces a 32 byte secret and a message that
    /// the other half recovers it from - the only test that touches the
    /// random source.
    #[test]
    fn test_the_generated_exchange_works() {
        let curve = curves::by_name("gost256-c").unwrap();
        let (private, public) = curve.generate_key_pair().unwrap();
        let (body, secret) = client_key_exchange(
            CtrOmacSuite::KUZNYECHIK, &curve, &algorithm_id_for(&curve).unwrap(),
            &public, &[4u8; 32], &[5u8; 32])
            .unwrap();
        assert_eq!(secret.len(), PRELIMINARY_SECRET_LEN);
        assert_eq!(unwrap_secret(CtrOmacSuite::KUZNYECHIK, &curve, &private,
                                 &[4u8; 32], &[5u8; 32], &body).unwrap(),
                   secret);

        // Two calls must not produce the same secret, which would mean
        // the random source is not being used.
        let (_, again) = client_key_exchange(
            CtrOmacSuite::KUZNYECHIK, &curve, &algorithm_id_for(&curve).unwrap(),
            &public, &[4u8; 32], &[5u8; 32])
            .unwrap();
        assert_ne!(hex(&secret), hex(&again));
    }
}
