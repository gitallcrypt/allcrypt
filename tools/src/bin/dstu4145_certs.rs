// DSTU 4145-2002 certificates issued by this library, for
// scripts/make_dstu4145_x509_vectors.py to hand to dstu-engine and
// li0ard, which must verify every one.
//
//     cargo run -p allcrypt-tools --bin dstu4145_certs DIR
//
// Writes the certificates into DIR and prints a line per certificate,
// `cert FILE ISSUER_FILE`, a self-signed one naming itself. One
// self-signed certificate on each of the ten named curves - the
// even-numbered little endian, over GOST 34.311-95 or one of the three
// Kupynas; the odd-numbered big endian, over GOST 34.311-95, since
// neither witness signs with Kupyna under a big-endian key - and three
// chains of two, one of them with a CA whose DKE is not the default
// while its leaf's is, so the DKE a signature hashes under is the
// issuer's.
use allcrypt::bignum::BigUint;
use allcrypt::ec::dstu4145::{Curve, Point};
use allcrypt::x509::builder::{CertificateBuilder, SigningKey, SubjectKey};
use allcrypt::x509::oids;

struct Key {
    curve: Curve,
    d: BigUint,
    q: Point,
    dke: Option<Vec<u8>>,
    little_endian: bool,
}

impl Key {
    fn new(curve: &str, dke: Option<Vec<u8>>, little_endian: bool) -> Key {
        let curve = Curve::by_name(curve).expect("a named curve");
        let (d, q) = curve.generate().expect("a key");
        Key { curve, d, q, dke, little_endian }
    }

    fn subject(&self) -> SubjectKey<'_> {
        SubjectKey::Dstu4145 { curve: &self.curve, point: &self.q, dke: self.dke.as_deref(),
                               little_endian: self.little_endian }
    }

    fn signing(&self) -> SigningKey<'_> {
        SigningKey::Dstu4145 { curve: &self.curve, private: &self.d, dke: self.dke.as_deref(),
                               little_endian: self.little_endian }
    }
}

fn issue(name: &str, subject: &Key, issuer: Option<(&str, &Key)>, hash: &str) -> Vec<u8> {
    let mut b = CertificateBuilder::new(name, subject.subject());
    b.hash = hash;
    b.key_identifiers = true;
    b.is_ca = Some((issuer.is_none(), None));
    if let Some((issuer_name, _)) = issuer {
        b.issuer = vec![(oids::COMMON_NAME, issuer_name.to_string())];
    }
    let signer = issuer.map_or(subject, |(_, key)| key);
    b.sign(&signer.signing()).expect("the certificate signs")
}

/// The default DKE with its eight rows in the opposite order: an S-box
/// that is valid and is none of the ten named tables.
fn reversed_rows_dke() -> Vec<u8> {
    allcrypt::block_ciphers::gost::DSTU4145_DEFAULT_DKE.chunks(8).rev().flatten().copied()
        .collect()
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: dstu4145_certs DIR");
    let write = |file: &str, issuer: &str, der: &[u8]| {
        std::fs::write(format!("{dir}/{file}"), der).expect("the directory is writable");
        println!("cert {file} {issuer}");
    };

    let le_hashes = ["gost34311", "kupyna256", "gost34311", "kupyna384", "kupyna512"];
    for (i, curve) in allcrypt::ec::dstu4145::NAMES[..10].iter().enumerate() {
        let little_endian = i % 2 == 0;
        let hash = if little_endian { le_hashes[i / 2] } else { "gost34311" };
        let key = Key::new(curve, None, little_endian);
        let file = format!("ours-x509-{}-{}-{}.cer", &curve["dstu4145-".len()..],
                           if little_endian { "le" } else { "be" }, hash);
        write(&file, &file, &issue(curve, &key, None, hash));
    }

    for (ca_curve, leaf_curve, little_endian, dke, hash, tag) in [
        ("dstu4145-m257", "dstu4145-m173", true, Some(reversed_rows_dke()), "gost34311", "le-dke"),
        ("dstu4145-m367", "dstu4145-m191", false, None, "gost34311", "be"),
        ("dstu4145-m431", "dstu4145-m233", true, None, "kupyna256", "le-kupyna256"),
    ] {
        let ca = Key::new(ca_curve, dke, little_endian);
        let leaf = Key::new(leaf_curve, None, little_endian);
        let ca_file = format!("ours-x509-ca-{tag}.cer");
        let leaf_file = format!("ours-x509-leaf-{tag}.cer");
        write(&ca_file, &ca_file, &issue("CA", &ca, None, hash));
        write(&leaf_file, &ca_file, &issue("leaf", &leaf, Some(("CA", &ca)), hash));
    }
}
