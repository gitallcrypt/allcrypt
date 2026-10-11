/*!
Ukrainian private keys: DSTU 4145-2002 keys as the IIT software and the
accredited key centres write them, and IIT's `Key-6.dat` container.

## The private key

A PKCS#8 `PrivateKeyInfo` in shape, with two departures:

```text
PrivateKeyInfo ::= SEQUENCE {
  version              INTEGER (0),
  privateKeyAlgorithm  AlgorithmIdentifier,   -- dstu4145le or dstu4145be
  privateKey           OCTET STRING,          -- d itself, no wrapping
  attributes           [0] IMPLICIT SET OF Attribute OPTIONAL }
```

`privateKey` is `d`'s bytes, little endian under `dstu4145le` and
sometimes longer than the order with zeros on the high end. The
attributes are where a second key goes: the IIT software issues a key
for signing and one for key agreement and stores the second in four
attributes on IIT's arc - its identifier (`.2.5`), its `d` as a BIT
STRING whose bits run from the least significant (`.2.3`), and its curve
(`.2.2`), **big endian** whatever the first key's order, followed by two
DKEs. `.2.1` is the first key's identifier: GOST 34.311 over the DER
OCTET STRING of its compressed public key, little endian, as a
certificate's subject key identifier is. Where the identifiers are
present they are checked, which is what catches a key read in the wrong
byte order.

The algorithm's parameters are DSTU 4145's:

```text
DSTU4145Params ::= SEQUENCE {
  definition  CHOICE { ecbinary ECBinary, namedCurve OBJECT IDENTIFIER },
  dke         OCTET STRING (SIZE (64)) OPTIONAL }
ECBinary ::= SEQUENCE {
  version     [0] EXPLICIT INTEGER DEFAULT 0,
  f           SEQUENCE { m INTEGER, CHOICE { trinomial INTEGER,
                pentanomial SEQUENCE { k INTEGER, j INTEGER, l INTEGER } } },
  a           INTEGER (0..1),
  b           OCTET STRING,
  n           INTEGER,
  bp          OCTET STRING }   -- the base point, compressed
```

`b` and `bp` are reversed under `dstu4145le`. The pentanomial's three
exponents are written in either order in the wild and are sorted here; a
field without a polynomial is the optimal normal basis, which is not
supported.

## `Key-6.dat`

```text
SEQUENCE {
  SEQUENCE { OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.1.2,
             SEQUENCE { mac OCTET STRING (SIZE (4)), pad OCTET STRING } },
  OCTET STRING }   -- the key, encrypted
```

The key is GOST 34.311 applied ten thousand times, the first time to the
password and then to its own output. The private key DER is zero-padded
to whole blocks and encrypted with GOST 28147 in simple replacement
(ECB) under the DSTU S-box; the encrypted DER's length is the body and
the rest of the last block is `pad`. `mac` is the GOST 28147 MAC
(imitovstavka) of the plaintext under the same key, four bytes - which
dstu-engine's keylib and the dstucrypt tools both ignore, and which is
checked here, so a wrong password is refused by name rather than by the
garbage failing to parse.
*/

use crate::asn1::{tag, Reader, Tag, Writer};
use crate::bignum::BigUint;
use crate::block_ciphers::gost::{GostCrypto, DSTU4145_DEFAULT_DKE};
use crate::block_ciphers::BlockCipher;
use crate::ec::dstu4145::{Curve, Point};
use crate::x509::oids;

/// A DSTU 4145 private key read from, or to be written into, a container.
#[derive(Clone, Debug)]
pub struct UaKey {
    pub curve: Curve,
    pub d: BigUint,
    /// The 64-byte DKE from the key's parameters: the S-box its
    /// signatures hash with. `None` when the parameters carry none.
    pub dke: Option<Vec<u8>>,
}

impl UaKey {
    /// The public key, `−d·G`.
    pub fn public_key(&self) -> Result<Point, String> {
        self.curve.public_key(&self.d)
    }

    /// The key identifier: GOST 34.311 of the DER OCTET STRING of the
    /// compressed public key, little endian.
    pub fn key_id(&self) -> Result<Vec<u8>, String> {
        key_id(&self.curve, &self.public_key()?)
    }
}

/// GOST 34.311 (zero start, DSTU S-box) of the DER OCTET STRING holding
/// the compressed point little endian.
pub fn key_id(curve: &Curve, q: &Point) -> Result<Vec<u8>, String> {
    let mut packed = curve.compress(q)?;
    packed.reverse();
    let mut w = Writer::new();
    w.write_octet_string(&packed);
    gost34311(&w.finish())
}

fn gost34311(data: &[u8]) -> Result<Vec<u8>, String> {
    use crate::hash_functions::HashFunction;
    let mut h = crate::api::AnyHash::new("gost34311")?;
    h.update(data);
    Ok(h.digest())
}

fn reversed(bytes: &[u8], little_endian: bool) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if little_endian {
        out.reverse();
    }
    out
}

// ------------------------------------------------------------ parameters ---

/// Read `DSTU4145Params`: the curve and the DKE.
pub fn read_parameters(der: &[u8], little_endian: bool)
                       -> Result<(Curve, Option<Vec<u8>>), String> {
    let mut outer = Reader::new(der);
    let mut params = outer.read_sequence()?;
    outer.finish()?;
    let curve = if params.peek_tag() == Some(Tag::universal(tag::OID)) {
        named_curve(params.read_oid()?.as_bytes())?
    } else {
        read_ecbinary(&mut params, little_endian)?
    };
    let dke = read_dke(&mut params)?;
    params.finish()?;
    Ok((curve, dke))
}

fn read_dke(reader: &mut Reader<'_>) -> Result<Option<Vec<u8>>, String> {
    if reader.is_empty() {
        return Ok(None);
    }
    let dke = reader.read_octet_string()?;
    if dke.len() != 64 {
        return Err(format!("A DKE is 64 bytes, not {}.", dke.len()));
    }
    Ok(Some(dke.to_vec()))
}

fn named_curve(oid: &[u8]) -> Result<Curve, String> {
    let arc = oids::DSTU4145_NAMED_CURVES;
    match oid.strip_prefix(arc) {
        Some([number]) if *number < 10 => Curve::named(usize::from(*number)),
        _ => Err("The key names a curve that is not one of DSTU 4145's ten.".to_string()),
    }
}

fn read_ecbinary(reader: &mut Reader<'_>, little_endian: bool) -> Result<Curve, String> {
    let mut ecb = reader.read_sequence()?;
    if let Some(version) = ecb.read_optional_context(0, true)? {
        let mut v = Reader::new(version);
        if v.read_u32()? != 0 {
            return Err("ECBinary's version is 0.".to_string());
        }
        v.finish()?;
    }
    let mut field = ecb.read_sequence()?;
    let m = field.read_u32()? as usize;
    if field.is_empty() {
        return Err("The curve is over an optimal normal basis, which is not supported; \
                    only polynomial bases are.".to_string());
    }
    let mut terms = if field.peek_tag() == Some(Tag::universal(tag::INTEGER)) {
        vec![field.read_u32()? as usize]
    } else {
        let mut p = field.read_sequence()?;
        let k = vec![p.read_u32()? as usize, p.read_u32()? as usize, p.read_u32()? as usize];
        p.finish()?;
        k
    };
    field.finish()?;
    // The field puts the exponents in order, whichever order they came.
    terms.push(0);
    // The curve refuses anything but 0 and 1; this keeps 256 from
    // passing as 0.
    let a = u8::try_from(ecb.read_u32()?)
        .map_err(|_| "A DSTU 4145 curve's a is 0 or 1.".to_string())?;
    let b = reversed(ecb.read_octet_string()?, little_endian);
    let n = ecb.read_integer()?;
    let bp = reversed(ecb.read_octet_string()?, little_endian);
    ecb.finish()?;
    // The base point comes compressed, so the curve is first built
    // without one and the point decompressed on it, which checks its
    // order too.
    let probe = Curve::without_base_point(m, &terms, a, &b, &n)?;
    let g = probe.decompress(&bp)?;
    let Point::Affine(gx, gy) = g else {
        return Err("The base point is the identity.".to_string());
    };
    let f = probe.field();
    Curve::custom(m, &terms, a, &b, &n, &f.to_bytes(&gx), &f.to_bytes(&gy))
}

/// Write `DSTU4145Params` with the curve given whole and the DKE.
fn write_parameters(w: &mut Writer, curve: &Curve, dke: &[u8], little_endian: bool)
                    -> Result<(), String> {
    let f = curve.field();
    let bp = reversed(&curve.compress(curve.generator())?, little_endian);
    let b = reversed(&f.to_bytes(curve.b()), little_endian);
    let ks: Vec<usize> = f.terms().iter().copied().filter(|&t| t != 0).collect();
    w.write_sequence(|w| {
        w.write_sequence(|w| {
            w.write_sequence(|w| {
                w.write_u32(f.degree() as u32);
                if let [k] = ks[..] {
                    w.write_u32(k as u32);
                } else {
                    w.write_sequence(|w| {
                        for k in ks.iter().rev() {
                            w.write_u32(*k as u32);
                        }
                    });
                }
            });
            w.write_u32(u32::from(curve.a()));
            w.write_octet_string(&b);
            w.write_integer(curve.order());
            w.write_octet_string(&bp);
        });
        w.write_octet_string(dke);
    });
    Ok(())
}

// ----------------------------------------------------------- private key ---

/// Read a Ukrainian `PrivateKeyInfo`: the key, and the second key its
/// attributes carry when there is one.
///
/// # Errors
/// Anything that is not such a key, a `d` that is zero modulo `n`, or a
/// key whose identifier attribute does not match it.
pub fn read_private_key(der: &[u8]) -> Result<Vec<UaKey>, String> {
    let mut outer = Reader::new(der);
    let mut info = outer.read_sequence()?;
    outer.finish()?;
    if info.read_u32()? != 0 {
        return Err("A private key's version is 0.".to_string());
    }
    let mut algorithm = info.read_sequence()?;
    let oid = algorithm.read_oid()?;
    let little_endian = match oid.as_bytes() {
        o if o == oids::DSTU4145_LE => true,
        o if o == oids::DSTU4145_BE => false,
        _ => return Err("Not a DSTU 4145 private key.".to_string()),
    };
    let (curve, dke) = read_parameters(algorithm.remaining(), little_endian)?;
    let d_bytes = reversed(info.read_octet_string()?, little_endian);
    // Reduced modulo n: a d past the order is the same key as its
    // remainder - every use of it is a multiplication of a point of
    // order n - and such files exist (jkurwa's tests carry one).
    let d = BigUint::from_bytes_be(&d_bytes).rem(curve.order())?;
    let mut keys = vec![checked(UaKey { curve, d, dke })?];

    let mut ids: Vec<(usize, Vec<u8>)> = Vec::new();
    let (mut second_d, mut second_curve) = (None, None);
    if let Some(attributes) = info.read_optional_context(0, true)? {
        let mut attributes = Reader::new(attributes);
        while !attributes.is_empty() {
            let mut attribute = attributes.read_sequence()?;
            let oid = attribute.read_oid()?.as_bytes().to_vec();
            let mut values = attribute.read_set()?;
            attribute.finish()?;
            match oid.as_slice() {
                o if o == oids::IIT_KEY_ID => ids.push((0, values.read_octet_string()?.to_vec())),
                o if o == oids::IIT_SECOND_KEY_ID =>
                    ids.push((1, values.read_octet_string()?.to_vec())),
                o if o == oids::IIT_SECOND_KEY => {
                    let (bits, _) = values.read_bit_string_with_unused()?;
                    // Bit i of the string is bit i of d: each byte's bits
                    // reversed, and the bytes reversed.
                    let be: Vec<u8> = bits.iter().rev().map(|b| b.reverse_bits()).collect();
                    second_d = Some(BigUint::from_bytes_be(&be));
                }
                o if o == oids::IIT_SECOND_CURVE => {
                    let mut spec = values.read_sequence()?;
                    let curve = read_ecbinary(&mut spec, false)?;
                    let dke = read_dke(&mut spec)?;
                    second_curve = Some((curve, dke));
                }
                // The software writes others whose meaning is not
                // published; they are passed over.
                _ => {}
            }
        }
    }
    info.finish()?;
    match (second_d, second_curve) {
        (Some(d), Some((curve, dke))) => {
            let d = d.rem(curve.order())?;
            keys.push(checked(UaKey { curve, d, dke })?);
        }
        (None, None) => {}
        _ => return Err("The second key's attributes are incomplete: it needs both its \
                         bits and its curve.".to_string()),
    }
    for (index, id) in ids {
        let key = keys.get(index).ok_or("A second key's identifier with no second key.")?;
        if key.key_id()? != id {
            return Err(format!("Key {} does not match its own identifier attribute: the \
                                key was read wrongly or the file is damaged.", index + 1));
        }
    }
    Ok(keys)
}

fn checked(key: UaKey) -> Result<UaKey, String> {
    if key.d.is_zero() || key.d >= *key.curve.order() {
        return Err("A DSTU 4145 private key is in [1, n).".to_string());
    }
    Ok(key)
}

/// Write a Ukrainian `PrivateKeyInfo` as the IIT software does: little
/// endian, the curve given whole with the default DKE, the identifier
/// attribute, and a second key in the four attributes when given.
pub fn write_private_key(key: &UaKey, second: Option<&UaKey>) -> Result<Vec<u8>, String> {
    let key = checked(key.clone())?;
    let width = key.curve.order().bit_len().div_ceil(8);
    let d = reversed(&key.d.to_bytes_be_padded(width)?, true);
    let dke = key.dke.clone().unwrap_or_else(|| DSTU4145_DEFAULT_DKE.to_vec());
    let mut params = Writer::new();
    write_parameters(&mut params, &key.curve, &dke, true)?;
    let params = params.finish();

    let mut attributes: Vec<Vec<u8>> = vec![attribute(oids::IIT_KEY_ID, |w| {
        w.write_octet_string(&key.key_id().expect("a checked key has a public key"));
    })];
    if let Some(second) = second {
        let second = checked(second.clone())?;
        let width = second.curve.order().bit_len().div_ceil(8);
        let bits: Vec<u8> = second.d.to_bytes_be_padded(width)?.iter().rev()
            .map(|b| b.reverse_bits()).collect();
        let mut spec = Writer::new();
        write_parameters(&mut spec, &second.curve, &[0; 64], false)?;
        // `write_parameters` wrote SEQUENCE { ECBinary, dke }; the
        // attribute wants SEQUENCE { ECBinary, dke, dke }.
        let spec = spec.finish();
        let mut inner = Reader::new(&spec);
        let mut seq = inner.read_sequence()?;
        let ecbinary = seq.read_raw()?.to_vec();
        let dke2 = second.dke.clone().unwrap_or_else(|| DSTU4145_DEFAULT_DKE.to_vec());
        attributes.push(attribute(oids::IIT_SECOND_KEY_ID, |w| {
            w.write_octet_string(&second.key_id().expect("a checked key has a public key"));
        }));
        attributes.push(attribute(oids::IIT_SECOND_KEY, |w| w.write_bit_string(&bits)));
        attributes.push(attribute(oids::IIT_SECOND_CURVE, |w| {
            w.write_sequence(|w| {
                w.write_raw(&ecbinary);
                w.write_octet_string(&dke2);
                w.write_octet_string(&dke2);
            });
        }));
    }
    // DER's SET OF is in the order of the encodings.
    attributes.sort();

    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_u32(0);
        w.write_sequence(|w| {
            w.write_oid(oids::DSTU4145_LE);
            w.write_raw(&params);
        });
        w.write_octet_string(&d);
        w.write_constructed(Tag::context(0, true), |w| {
            for a in &attributes {
                w.write_raw(a);
            }
        });
    });
    Ok(w.finish())
}

fn attribute(oid: &[u8], value: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_oid(oid);
        w.write_set(value);
    });
    w.finish()
}

// --------------------------------------------------------------- Key-6 ---

/// The `Key-6.dat` key: GOST 34.311 ten thousand times over.
fn key6_key(password: &[u8]) -> Result<Vec<u8>, String> {
    let mut key = gost34311(password)?;
    for _ in 1..10_000 {
        key = gost34311(&key)?;
    }
    Ok(key)
}

fn key6_mac(key: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    let sbox = GostCrypto::sbox_from_dke(&DSTU4145_DEFAULT_DKE)?;
    crate::block_ciphers::gost::imitovstavka(key, &sbox, &[0; 8], plain, 4)
}

/// Whether these bytes are shaped like a `Key-6.dat`.
pub fn looks_like_key6(data: &[u8]) -> bool {
    let mut outer = Reader::new(data);
    let Ok(mut store) = outer.read_sequence() else { return false };
    let Ok(mut header) = store.read_sequence() else { return false };
    matches!(header.read_oid(), Ok(oid) if oid.as_bytes() == oids::IIT_KEY_STORE)
}

/// Open a `Key-6.dat`: the private key DER inside it.
///
/// # Errors
/// Not a `Key-6.dat`, or a MAC that does not match - a wrong password.
pub fn key6_open(data: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let mut outer = Reader::new(data);
    let mut store = outer.read_sequence()?;
    outer.finish()?;
    let mut header = store.read_sequence()?;
    if header.read_oid()?.as_bytes() != oids::IIT_KEY_STORE {
        return Err("Not an IIT key store (Key-6.dat).".to_string());
    }
    let mut params = header.read_sequence()?;
    header.finish()?;
    let mac = params.read_octet_string()?;
    let pad = if params.is_empty() { &[][..] } else { params.read_octet_string()? };
    params.finish()?;
    let body = store.read_octet_string()?;
    store.finish()?;
    if mac.len() != 4 {
        return Err(format!("A Key-6.dat MAC is 4 bytes, not {}.", mac.len()));
    }
    if !(body.len() + pad.len()).is_multiple_of(8) || pad.len() >= 8 {
        return Err("A Key-6.dat's body and padding make whole 8-byte blocks, the \
                    padding less than one.".to_string());
    }
    let key = key6_key(password)?;
    let mut cipher = GostCrypto::new_with_sbox(&key, &GostCrypto::sbox_from_dke(
        &DSTU4145_DEFAULT_DKE)?)?;
    let mut sealed = body.to_vec();
    sealed.extend_from_slice(pad);
    let mut plain = Vec::with_capacity(sealed.len());
    cipher.ecb_decrypt(&sealed, &mut plain)?;
    plain.truncate(body.len());
    if crate::bignum::ct::bytes_differ(&key6_mac(&key, &plain)?, mac) {
        return Err("Wrong password: the Key-6.dat MAC does not match.".to_string());
    }
    Ok(plain)
}

/// Seal a private key DER into a `Key-6.dat`.
pub fn key6_seal(plain: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    if plain.is_empty() {
        return Err("Nothing to seal.".to_string());
    }
    let key = key6_key(password)?;
    let mut cipher = GostCrypto::new_with_sbox(&key, &GostCrypto::sbox_from_dke(
        &DSTU4145_DEFAULT_DKE)?)?;
    let mut padded = plain.to_vec();
    padded.resize(plain.len().div_ceil(8) * 8, 0);
    let mut sealed = Vec::with_capacity(padded.len());
    cipher.ecb_encrypt(&padded, &mut sealed)?;
    let mac = key6_mac(&key, plain)?;
    let mut w = Writer::new();
    w.write_sequence(|w| {
        w.write_sequence(|w| {
            w.write_oid(oids::IIT_KEY_STORE);
            w.write_sequence(|w| {
                w.write_octet_string(&mac);
                w.write_octet_string(&sealed[plain.len()..]);
            });
        });
        w.write_octet_string(&sealed[..plain.len()]);
    });
    Ok(w.finish())
}

/// The keys in a container: a `Key-6.dat`, an encrypted PKCS#8 (the
/// Ukrainian software writes PBES2 with GOST 28147 CFB), or a plain
/// private key, as DER or PEM.
///
/// # Errors
/// None of those, a wrong password, or a key this module cannot read.
pub fn open(data: &[u8], password: &[u8]) -> Result<Vec<UaKey>, String> {
    // PEM when it is text with a block in it; the first block.
    let der = match core::str::from_utf8(data).ok().and_then(|t| crate::pem::parse(t).ok()) {
        Some(blocks) if !blocks.is_empty() => blocks[0].contents.clone(),
        _ => data.to_vec(),
    };
    if looks_like_key6(&der) {
        return read_private_key(&key6_open(&der, password)?);
    }
    if crate::x509::encrypted_key::looks_encrypted(&der) {
        return read_private_key(&crate::x509::encrypted_key::decrypt(&der, password)?);
    }
    read_private_key(&der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(number: usize, d: u64) -> UaKey {
        UaKey { curve: Curve::named(number).unwrap(), d: BigUint::from_u64(d), dke: None }
    }

    /// A key and a second key through the writer and the reader, and
    /// through Key-6.dat; the curve given whole comes back as the named
    /// curve it is.
    #[test]
    fn test_a_round_trip() {
        let (first, second) = (key(6, 0x1234_5678_9abc), key(9, 0x0fed_cba9_8765));
        let der = write_private_key(&first, Some(&second)).unwrap();
        let back = read_private_key(&der).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].d, first.d);
        assert_eq!(back[1].d, second.d);
        assert_eq!(back[0].curve.matching_named(), Some(6));
        assert_eq!(back[1].curve.matching_named(), Some(9));
        assert_eq!(back[0].dke.as_deref(), Some(&DSTU4145_DEFAULT_DKE[..]));
        let sealed = key6_seal(&der, b"tect4").unwrap();
        assert_eq!(key6_open(&sealed, b"tect4").unwrap(), der);
        assert!(key6_open(&sealed, b"tect5").unwrap_err().contains("Wrong password"));
        assert_eq!(open(&sealed, b"tect4").unwrap()[1].d, second.d);
    }

    /// An identifier attribute that does not match its key is refused:
    /// it is what tells a key read in the wrong byte order from a key.
    #[test]
    fn test_an_identifier_that_does_not_match_is_refused() {
        let (first, second) = (key(3, 0x5555), key(9, 0x7777));
        let der = write_private_key(&first, Some(&second)).unwrap();
        for (index, id) in [first.key_id().unwrap(), second.key_id().unwrap()].iter()
            .enumerate() {
            let at = der.windows(id.len()).position(|w| w == &id[..]).unwrap();
            let mut damaged = der.clone();
            damaged[at] ^= 1;
            let error = read_private_key(&damaged).unwrap_err();
            assert!(error.contains(&format!("Key {}", index + 1)), "{error}");
        }
    }

    /// A curve given whole with `a` other than 0 or 1 is refused,
    /// including 256, which a byte would read as 0.
    #[test]
    fn test_a_is_zero_or_one() {
        let curve = Curve::named(6).unwrap();
        let f = curve.field();
        let with_a = |a: u32| {
            let ks: Vec<usize> = f.terms().iter().copied().filter(|&t| t != 0).collect();
            let mut w = Writer::new();
            w.write_sequence(|w| w.write_sequence(|w| {
                w.write_sequence(|w| {
                    w.write_u32(f.degree() as u32);
                    w.write_u32(ks[0] as u32);
                });
                w.write_u32(a);
                w.write_octet_string(&f.to_bytes(curve.b()));
                w.write_integer(curve.order());
                w.write_octet_string(&curve.compress(curve.generator()).unwrap());
            }));
            w.finish()
        };
        assert_eq!(f.terms().len(), 2, "a trinomial");
        let (read, _) = read_parameters(&with_a(u32::from(curve.a())), false).unwrap();
        assert_eq!(read.matching_named(), Some(6));
        for a in [2, 256, 257] {
            assert!(read_parameters(&with_a(a), false).is_err(), "{a}");
        }
    }

    /// d is taken modulo n, for both keys; zero modulo n is no key.
    #[test]
    fn test_d_is_reduced_and_never_zero() {
        let curve = Curve::named(6).unwrap();
        let n = curve.order().clone();
        let small = key(6, 3);
        let mut big = small.clone();
        big.d = small.d.add(&n);
        assert!(write_private_key(&big, None).is_err());
        assert!(write_private_key(&UaKey { d: BigUint::zero(), ..small.clone() }, None).is_err());

        // Written with d + n in place of d, as such files have it: the
        // first key's octets and the second key's bits.
        let der = write_private_key(&small, Some(&small)).unwrap();
        let width = n.bit_len().div_ceil(8);
        let mut little = small.d.to_bytes_be_padded(width).unwrap();
        little.reverse();
        let mut big_little = big.d.to_bytes_be_padded(width).unwrap();
        big_little.reverse();
        let bits: Vec<u8> = little.iter().map(|b| b.reverse_bits()).collect();
        let big_bits: Vec<u8> = big_little.iter().map(|b| b.reverse_bits()).collect();
        let replace = |data: &[u8], from: &[u8], to: &[u8]| {
            let at = data.windows(from.len()).position(|w| w == from).unwrap();
            [&data[..at], to, &data[at + from.len()..]].concat()
        };
        let damaged = replace(&replace(&der, &little, &big_little), &bits, &big_bits);
        assert_ne!(damaged, der);
        let keys = read_private_key(&damaged).unwrap();
        assert_eq!((&keys[0].d, &keys[1].d), (&small.d, &small.d));

        let zero = vec![0u8; width];
        let mut n_little = n.to_bytes_be_padded(width).unwrap();
        n_little.reverse();
        let single = write_private_key(&small, None).unwrap();
        assert!(read_private_key(&replace(&single, &little, &n_little)).is_err());
        assert!(read_private_key(&replace(&single, &little, &zero)).is_err());
    }
}
