//! DSTU 4145-2002 certificates against `vectors/dstu4145_x509.vec`,
//! written by `scripts/make_dstu4145_x509_vectors.py`: three root
//! certificates of Ukraine's central certifying authority and sixteen
//! of ours, in `tests/keys/ua-x509/`, whose signatures dstu-engine, li0ard or
//! both verify, and whose subject keys dstu-engine reads. Offline.

use std::collections::{BTreeMap, HashMap};

use allcrypt::bignum::BigUint;
use allcrypt::ec::dstu4145::{Curve, Point};
use allcrypt::hash_functions::HashFunction;
use allcrypt::x509::builder::{key_identifier, CertificateBuilder, SigningKey, SubjectKey};
use allcrypt::x509::verify::{verify_chain, verify_signature, verify_signed, Policy, Purpose};
use allcrypt::x509::{Certificate, PublicKey, SignatureAlgorithm};

const VECTORS: &str = include_str!("../vectors/dstu4145_x509.vec");

fn rows() -> Vec<HashMap<&'static str, &'static str>> {
    VECTORS.lines()
        .filter(|line| line.starts_with("cert "))
        .map(|line| line.split(' ').skip(1).map(|w| w.split_once('=').unwrap()).collect())
        .collect()
}

fn read(file: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/keys/ua-x509/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn int(hex: &str) -> BigUint {
    let hex = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_string() };
    BigUint::from_bytes_be(&(0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect::<Vec<_>>())
}

fn dstu_key<'a>(c: &'a Certificate<'_>) -> (&'a Curve, &'a Point, Option<&'a [u8]>, bool) {
    match &c.public_key {
        PublicKey::Dstu4145 { curve, point, dke, little_endian } =>
            (curve, point, dke.as_deref(), *little_endian),
        other => panic!("not a DSTU 4145 key: {other:?}"),
    }
}

fn changed(der: &[u8], at: usize) -> Vec<u8> {
    let mut out = der.to_vec();
    out[at] ^= 0x01;
    out
}

#[test]
fn test_every_certificate_verifies_and_its_key_reads_as_dstu_engine_reads_it() {
    let rows = rows();
    let mut sources = BTreeMap::new();
    for r in &rows {
        *sources.entry(r["source"]).or_insert(0) += 1;
    }
    assert_eq!(sources, BTreeMap::from([("both", 6), ("dstu-engine", 7), ("li0ard", 6)]));
    for r in rows {
        let (der, issuer_der) = (read(r["file"]), read(r["issuer"]));
        let (cert, issuer) = (Certificate::parse(&der).unwrap(),
                              Certificate::parse(&issuer_der).unwrap());
        assert_eq!(cert.signature_algorithm, SignatureAlgorithm::Dstu4145(
            Box::leak(r["hash"].to_string().into_boxed_str())), "{}", r["file"]);
        assert_eq!(dstu_key(&issuer).3, r["order"] == "le");
        verify_signature(&cert, &issuer, &Policy::default())
            .unwrap_or_else(|e| panic!("{}: {e}", r["file"]));

        let (curve, point, _, little_endian) = dstu_key(&cert);
        // Our leaves are in their CA's byte order, as the centre's roots
        // are self-signed.
        assert_eq!(little_endian, r["order"] == "le");
        let f = curve.field();
        assert_eq!(f.degree().to_string(), r["m"]);
        let mut poly = BigUint::from_u64(1).shl(f.degree());
        for &t in f.terms() {
            poly = poly.add(&BigUint::from_u64(1).shl(t));
        }
        assert_eq!(poly, int(r["poly"]), "{}", r["file"]);
        assert_eq!(BigUint::from_u64(u64::from(curve.a())), int(r["a"]));
        assert_eq!(BigUint::from_bytes_be(&curve.element_to_bytes(curve.b())), int(r["b"]));
        assert_eq!(*curve.order(), int(r["n"]));
        let coordinates = |p: &Point| match p {
            Point::Affine(x, y) => (BigUint::from_bytes_be(&curve.element_to_bytes(x)),
                                    BigUint::from_bytes_be(&curve.element_to_bytes(y))),
            Point::Infinity => panic!("the identity"),
        };
        assert_eq!(coordinates(curve.generator()), (int(r["gx"]), int(r["gy"])));
        assert_eq!(coordinates(point), (int(r["qx"]), int(r["qy"])), "{}", r["file"]);
    }
}

#[test]
fn test_a_changed_signature_or_tbs_is_refused() {
    for r in rows() {
        let (der, issuer_der) = (read(r["file"]), read(r["issuer"]));
        let issuer = Certificate::parse(&issuer_der).unwrap();
        let cert = Certificate::parse(&der).unwrap();
        let signature_at = der.len() - cert.signature.len();
        let serial_at = cert.serial.as_ptr() as usize - der.as_ptr() as usize + cert.serial.len() - 1;
        // The signature's OCTET STRING header is two bytes: its first
        // value byte, its last, and the serial's last byte.
        for at in [signature_at + 2, der.len() - 1, serial_at] {
            let copy = changed(&der, at);
            let copy = Certificate::parse(&copy).unwrap();
            // A self-signed certificate's key does not move with its serial.
            let issuer = if r["file"] == r["issuer"] { &copy } else { &issuer };
            assert!(verify_signature(&copy, issuer, &Policy::default()).is_err(),
                    "{} changed at {at}", r["file"]);
        }
    }
}

/// The other key the certificate's issuer could have been read as: the
/// same, with the byte order or the DKE changed.
fn variant<'a>(key: &PublicKey<'a>, flip_order: bool, dke: Option<Option<Vec<u8>>>)
               -> PublicKey<'a> {
    let PublicKey::Dstu4145 { curve, point, dke: own, little_endian } = key.clone() else {
        panic!("not a DSTU 4145 key")
    };
    PublicKey::Dstu4145 { curve, point, dke: dke.unwrap_or(own),
                          little_endian: little_endian ^ flip_order }
}

#[test]
fn test_the_signature_is_read_in_the_issuer_keys_byte_order() {
    for r in rows() {
        let (der, issuer_der) = (read(r["file"]), read(r["issuer"]));
        let (cert, issuer) = (Certificate::parse(&der).unwrap(),
                              Certificate::parse(&issuer_der).unwrap());
        let key = variant(&issuer.public_key, true, None);
        assert!(verify_signed(cert.tbs, cert.signature_algorithm, cert.signature, &key,
                              &Policy::default()).is_err(), "{}", r["file"]);
    }
}

#[test]
fn test_gost_34311_runs_under_the_issuers_dke() {
    // czo-1.cer's DKE is none of the ten named tables, and its signature
    // needs it.
    let der = read("czo-1.cer");
    let cert = Certificate::parse(&der).unwrap();
    let dke = dstu_key(&cert).2.expect("czo-1.cer carries a DKE").to_vec();
    assert!(!allcrypt::block_ciphers::gost::DSTU4145_DEFAULT_DKE.iter().eq(dke.iter()));
    let default = variant(&cert.public_key, false, Some(None));
    assert!(verify_signed(cert.tbs, cert.signature_algorithm, cert.signature, &default,
                          &Policy::default()).is_err());

    // czo-root-2017.cer writes the default DKE out, which is the same as
    // writing none.
    let der = read("czo-root-2017.cer");
    let cert = Certificate::parse(&der).unwrap();
    assert!(dstu_key(&cert).2.unwrap().iter()
            .eq(allcrypt::block_ciphers::gost::DSTU4145_DEFAULT_DKE.iter()));
    let none = variant(&cert.public_key, false, Some(None));
    verify_signed(cert.tbs, cert.signature_algorithm, cert.signature, &none,
                  &Policy::default()).unwrap();

    // Our leaf carries the default DKE and its CA another: the CA's is
    // the one, and the leaf's is not.
    let (leaf_der, ca_der) = (read("ours-x509-leaf-le-dke.cer"), read("ours-x509-ca-le-dke.cer"));
    let (leaf, ca) = (Certificate::parse(&leaf_der).unwrap(), Certificate::parse(&ca_der).unwrap());
    assert!(dstu_key(&leaf).2.is_some() && dstu_key(&ca).2 != dstu_key(&leaf).2);
    verify_signature(&leaf, &ca, &Policy::default()).unwrap();
    let leafs = variant(&ca.public_key, false, Some(dstu_key(&leaf).2.map(<[u8]>::to_vec)));
    assert!(verify_signed(leaf.tbs, leaf.signature_algorithm, leaf.signature, &leafs,
                          &Policy::default()).is_err());
}

#[test]
fn test_the_hash_is_the_one_the_oid_names() {
    for r in rows() {
        let (der, issuer_der) = (read(r["file"]), read(r["issuer"]));
        let (cert, issuer) = (Certificate::parse(&der).unwrap(),
                              Certificate::parse(&issuer_der).unwrap());
        for other in ["gost34311", "kupyna256", "kupyna384", "kupyna512"] {
            let result = verify_signed(cert.tbs, SignatureAlgorithm::Dstu4145(other),
                                       cert.signature, &issuer.public_key, &Policy::default());
            assert_eq!(result.is_ok(), other == r["hash"], "{} under {other}", r["file"]);
        }
    }
}

#[test]
fn test_key_identifiers() {
    // The centre names a key by GOST 34.311-95 of the subjectPublicKey's
    // contents under the key's DKE - czo-1.cer's own - as the builder
    // does; the Kupyna-era root by Kupyna-256 of the same bytes.
    for file in ["czo-root-2017.cer", "czo-1.cer"] {
        let der = read(file);
        let cert = Certificate::parse(&der).unwrap();
        let (curve, point, dke, little_endian) = dstu_key(&cert);
        let id = key_identifier(&SubjectKey::Dstu4145 { curve, point, dke, little_endian })
            .unwrap();
        assert_eq!(Some(&id[..]), cert.extensions.subject_key_id, "{file}");
    }
    let der = read("cao-2026.cer");
    let cert = Certificate::parse(&der).unwrap();
    let (curve, point, _, _) = dstu_key(&cert);
    let mut packed = curve.compress(point).unwrap();
    packed.reverse();
    let contents = [vec![0x04, packed.len() as u8], packed].concat();
    let mut kupyna = allcrypt::api::AnyHash::new("kupyna256").unwrap();
    kupyna.update(&contents);
    assert_eq!(Some(&kupyna.digest()[..]), cert.extensions.subject_key_id);

    // Ours, and each leaf's authority identifier is its CA's.
    for r in rows().iter().filter(|r| r["file"].starts_with("ours-")) {
        let (der, issuer_der) = (read(r["file"]), read(r["issuer"]));
        let (cert, issuer) = (Certificate::parse(&der).unwrap(),
                              Certificate::parse(&issuer_der).unwrap());
        let (curve, point, dke, little_endian) = dstu_key(&cert);
        let id = key_identifier(&SubjectKey::Dstu4145 { curve, point, dke, little_endian })
            .unwrap();
        assert_eq!(Some(&id[..]), cert.extensions.subject_key_id);
        assert_eq!(cert.extensions.authority_key_id, issuer.extensions.subject_key_id);
    }
}

#[test]
fn test_our_chains_verify_as_chains() {
    let policy = Policy { now: 1_800_000_000, ..Policy::default() };
    for tag in ["le-dke", "be", "le-kupyna256"] {
        let (leaf, ca) = (read(&format!("ours-x509-leaf-{tag}.cer")),
                          read(&format!("ours-x509-ca-{tag}.cer")));
        let (leaf, ca) = (Certificate::parse(&leaf).unwrap(), Certificate::parse(&ca).unwrap());
        verify_chain(std::slice::from_ref(&leaf), std::slice::from_ref(&ca), &policy,
                     Purpose::Any).unwrap_or_else(|e| panic!("{tag}: {e}"));
        // And a leaf is no root for itself.
        assert!(verify_chain(std::slice::from_ref(&leaf), std::slice::from_ref(&leaf), &policy,
                             Purpose::Any).is_err());
    }
}

#[test]
fn test_jkurwas_certificates_are_refused_for_their_authority_key_identifier() {
    // jkurwa writes the authority key identifier as a bare OCTET STRING
    // rather than the SEQUENCE RFC 5280 defines, and OpenSSL marks such
    // a certificate invalid; dstu-engine's X509_verify, which reads no
    // extension, accepts their signatures.
    for file in ["SELF_SIGNED1.cer", "SELF_SIGNED_ENC_40A0.cer", "SELF_SIGNED_ENC_6929.cer",
                 "SELF_SIGNED_ENC_E54B.cer"] {
        let der = std::fs::read(format!("{}/tests/keys/ua/{file}", env!("CARGO_MANIFEST_DIR")))
            .unwrap();
        assert!(Certificate::parse(&der).is_err(), "{file}");
    }
}

#[test]
fn test_the_builder_refuses_what_a_certificate_cannot_carry() {
    let curve = Curve::by_name("dstu4145-m257").unwrap();
    let (d, q) = curve.generate().unwrap();
    let key = SigningKey::Dstu4145 { curve: &curve, private: &d, dke: None, little_endian: true };
    let mut b = CertificateBuilder::new("x", SubjectKey::Dstu4145 {
        curve: &curve, point: &q, dke: None, little_endian: true });
    b.hash = "sha256";
    assert!(b.sign(&key).unwrap_err().contains("gost34311"));

    // A normal basis has no ECBinary to be written in.
    let onb = Curve::by_name("dstu4145-m233-onb").unwrap();
    let (d, q) = onb.generate().unwrap();
    let mut b = CertificateBuilder::new("x", SubjectKey::Dstu4145 {
        curve: &onb, point: &q, dke: None, little_endian: true });
    b.hash = "gost34311";
    let key = SigningKey::Dstu4145 { curve: &onb, private: &d, dke: None, little_endian: true };
    assert!(b.sign(&key).unwrap_err().contains("normal basis"));
}

/// What the builder writes, verified here: the verifier is pinned by the
/// real certificates and by the witnesses' verdicts on our recorded
/// ones, so a fresh round trip checks the builder as it is now. Small
/// curves, every byte order and hash, and a chain whose CA has a DKE of
/// its own.
#[test]
fn test_freshly_issued_certificates_verify() {
    use allcrypt::x509::oids;
    let custom: Vec<u8> = allcrypt::block_ciphers::gost::DSTU4145_DEFAULT_DKE.chunks(8).rev()
        .flatten().copied().collect();
    for (curve, little_endian, hash) in [("dstu4145-m163", true, "gost34311"),
                                         ("dstu4145-m167", false, "gost34311"),
                                         ("dstu4145-m173", true, "kupyna384"),
                                         ("dstu4145-m179", false, "kupyna512")] {
        let curve = Curve::by_name(curve).unwrap();
        let (ca_d, ca_q) = curve.generate().unwrap();
        let (_, leaf_q) = curve.generate().unwrap();
        let ca_key = SubjectKey::Dstu4145 { curve: &curve, point: &ca_q, dke: Some(&custom),
                                            little_endian };
        let ca_signing = SigningKey::Dstu4145 { curve: &curve, private: &ca_d, dke: Some(&custom),
                                                little_endian };
        let mut b = CertificateBuilder::new("CA", ca_key);
        b.hash = hash;
        b.is_ca = Some((true, None));
        let ca_der = b.sign(&ca_signing).unwrap();
        let mut b = CertificateBuilder::new("leaf", SubjectKey::Dstu4145 {
            curve: &curve, point: &leaf_q, dke: None, little_endian });
        b.hash = hash;
        b.issuer = vec![(oids::COMMON_NAME, "CA".to_string())];
        let leaf_der = b.sign(&ca_signing).unwrap();
        let (ca, leaf) = (Certificate::parse(&ca_der).unwrap(), Certificate::parse(&leaf_der).unwrap());

        for cert in [&ca, &leaf] {
            assert_eq!(cert.signature_algorithm, SignatureAlgorithm::Dstu4145(hash));
            verify_signature(cert, &ca, &Policy::default()).unwrap();
            assert!(verify_signature(cert, &leaf, &Policy::default()).is_err());
        }
        assert_eq!(dstu_key(&ca).2, Some(&custom[..]));
        assert_eq!(dstu_key(&leaf).2.map(<[u8]>::to_vec),
                   Some(allcrypt::block_ciphers::gost::DSTU4145_DEFAULT_DKE.to_vec()));
        assert_eq!(dstu_key(&leaf).3, little_endian);
        assert_eq!(dstu_key(&leaf).1, &leaf_q);

        // Over GOST 34.311-95 the signature algorithm is the key's own
        // OID, inside and outside the TBSCertificate - dstu-engine refuses
        // a certificate whose signature names the other byte order's.
        let oid = match (hash, little_endian) {
            ("gost34311", true) => oids::DSTU4145_LE,
            ("gost34311", false) => oids::DSTU4145_BE,
            ("kupyna384", _) => oids::DSTU4145_KUPYNA384,
            _ => oids::DSTU4145_KUPYNA512,
        };
        let algorithm = [vec![0x30, oid.len() as u8 + 2, 0x06, oid.len() as u8], oid.to_vec()]
            .concat();
        assert_eq!(leaf_der.windows(algorithm.len()).filter(|w| *w == algorithm).count(), 2);
    }
}

#[test]
fn test_a_signature_of_the_wrong_length_is_refused_by_name() {
    let der = read("ours-x509-m163-le-gost34311.cer");
    let cert = Certificate::parse(&der).unwrap();
    // The OCTET STRING's two-byte header, then the value with two more
    // bytes: equal halves, each one byte too long.
    let mut value = cert.signature[2..].to_vec();
    value.extend([0, 0]);
    let signature = [vec![0x04, value.len() as u8], value].concat();
    let error = verify_signed(cert.tbs, cert.signature_algorithm, &signature, &cert.public_key,
                              &Policy::default()).unwrap_err();
    assert!(error.contains("bytes, s and r; got 44"), "{error}");
}
