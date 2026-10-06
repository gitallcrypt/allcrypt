// Certificates built and parsed by this library, dumped for comparison
// against OpenSSL through python-cryptography. Verified by
// scripts/diff_check.py.
//
// Each certificate goes out twice over: once as DER, and once as the fields
// *our own parser* read back out of it. The checker parses the same DER with
// OpenSSL and compares field by field. So one corpus tests three things -
// that our encoder produces a certificate OpenSSL accepts, that our parser
// reads it the same way OpenSSL does, and that the two of ours agree.
//
// The other direction, where OpenSSL builds and we parse, needs the Python
// bindings and lives in pytests/test_x509.py.
use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, Curve};
use allcrypt::publickey_ciphers::rsa::RsaPrivateKey;
use allcrypt::x509::builder::{key_usage, CertificateBuilder, SanEntry, SigningKey, SubjectKey};
use allcrypt::x509::{oids, Certificate, GeneralName, PublicKey, SignatureAlgorithm};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Print a certificate and everything our parser makes of it.
///
/// `signer` names the certificate holding the key that signed this one, so
/// the checker can have OpenSSL verify the signature rather than guess at
/// which key to use. A self-signed certificate names itself.
fn emit(label: &str, signer: &str, der: &[u8]) {
    // Parsing our own output is not a formality: an encoder and a parser
    // written together can agree on something wrong, which is exactly what
    // the comparison with OpenSSL is for.
    let certificate = Certificate::parse(der)
        .unwrap_or_else(|e| panic!("our own certificate {} did not parse: {}", label, e));

    println!("cert {} {}", label, hex(der));
    println!("field {} signer {}", label, signer);
    println!("field {} version {}", label, certificate.version);
    println!("field {} serial {}", label, certificate.serial_hex());
    println!("field {} not_before {}", label, certificate.not_before);
    println!("field {} not_after {}", label, certificate.not_after);
    println!("field {} subject_cn {}",
             label, certificate.subject.common_name().unwrap_or_default());
    println!("field {} issuer_cn {}",
             label, certificate.issuer.common_name().unwrap_or_default());
    println!("field {} sig_alg {}", label, match certificate.signature_algorithm {
        SignatureAlgorithm::RsaPkcs1(hash) => format!("rsa-{}", hash),
        SignatureAlgorithm::Ecdsa(hash) => format!("ecdsa-{}", hash),
        SignatureAlgorithm::Dsa(hash) => format!("dsa-{}", hash),
        other => format!("other-{:?}", other),
    });
    println!("field {} public_key {}", label, match &certificate.public_key {
        PublicKey::Rsa { n, .. } => format!("rsa-{}", n.bit_len()),
        PublicKey::Ec { curve, .. } => format!("ec-{}", curve),
        PublicKey::Eddsa { curve, .. } => format!("eddsa-{}", curve),
        // python-cryptography here cannot read one, so no corpus row has
        // one; the RFC 9881 examples and OpenSSL 3.5's certificates are
        // the checks (`x509::tests`, `tests/test_ml_dsa_openssl.rs`).
        PublicKey::MlDsa { parameter_set, .. } => parameter_set.to_ascii_lowercase(),
        PublicKey::Dsa { parameters, .. } => format!("dsa-{}",
            parameters.as_ref().map_or(0, |(p, _, _)| p.bit_len())),
        // Nothing here can issue one: OpenSSL is built without the GOST
        // engine, so the other side of the comparison cannot describe
        // such a certificate. `x509::verify`'s own tests cover it, with
        // certificates this library signs.
        PublicKey::Gost { curve, .. } => format!("gost-{}", curve),
        // A curve we do not implement. The corpus cannot contain one, since
        // the comparison needs both sides to describe the same key - which
        // is exactly why a gap in curve support is invisible here and had to
        // be found by a unit test instead.
        PublicKey::UnsupportedCurve { oid, .. } => format!("ec-unsupported-{}", oid),
        PublicKey::Unsupported { .. } => "unsupported".to_string(),
    });
    println!("field {} is_ca {}", label, certificate.extensions.is_ca());
    println!("field {} path_len {}", label,
             certificate.extensions.path_len()
                 .map(|n| n.to_string()).unwrap_or_else(|| "-".to_string()));
    println!("field {} tbs_sha256 {}", label, {
        use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
        hex(&SHA256::new(certificate.tbs).digest())
    });

    let names: Vec<String> = certificate.extensions.subject_alt_names.iter()
        .filter_map(|name| match name {
            GeneralName::Dns(text) => Some(format!("dns:{}", text)),
            GeneralName::IpAddress(bytes) => Some(format!("ip:{}", hex(bytes))),
            GeneralName::Email(text) => Some(format!("email:{}", text)),
            GeneralName::Uri(text) => Some(format!("uri:{}", text)),
            _ => None,
        })
        .collect();
    println!("field {} sans {}", label,
             if names.is_empty() { "-".to_string() } else { names.join(",") });
}

struct EcKeyPair {
    curve: Curve,
    private: BigUint,
    point: Vec<u8>,
}

fn ec_key(name: &str) -> EcKeyPair {
    let curve = curves::by_name(name).unwrap();
    let (private, public) = curve.generate_key_pair().unwrap();
    let point = curve.encode_point(&public, false).unwrap();
    EcKeyPair { curve, private, point }
}

fn main() {
    // One RSA key, generated once: this is the slow part.
    let rsa_key = RsaPrivateKey::generate(2048).unwrap();
    let rsa_public = rsa_key.public_key();

    let p256 = ec_key("P-256");
    let p384 = ec_key("P-384");

    // --- RSA signed, RSA key, every hash we support for it ---
    for hash in ["sha256", "sha384", "sha512", "sha1"] {
        // Self-signed, with a name unique to this case: that lets the
        // checker find the issuing key and have OpenSSL verify the
        // signature, rather than only comparing parsed fields.
        let name = format!("rsa-{}.example.test", hash);
        let mut builder = CertificateBuilder::new(
            &name,
            SubjectKey::Rsa { n: &rsa_public.n, e: &rsa_public.e });
        builder.hash = hash;
        builder.serial = vec![0x11, 0x22, 0x33];
        builder.sans = vec![SanEntry::Dns(name.clone()),
                            SanEntry::Dns(format!("*.{}", name)),
                            SanEntry::Ip(vec![192, 0, 2, 1]),
                            SanEntry::Email("someone@example.test".to_string())];
        builder.key_usage = Some(key_usage::DIGITAL_SIGNATURE | key_usage::KEY_ENCIPHERMENT);
        builder.extended_key_usage = vec![oids::EKU_SERVER_AUTH];
        let der = builder.sign(&SigningKey::Rsa(&rsa_key)).unwrap();
        emit(&format!("rsa-{}", hash), &format!("rsa-{}", hash), &der);
    }

    // --- ECDSA signed, EC keys, on both curves ---
    for (label, key) in [("p256", &p256), ("p384", &p384)] {
        for hash in ["sha256", "sha384", "sha512"] {
            let name = format!("ec-{}-{}.example.test", label, hash);
            let mut builder = CertificateBuilder::new(
                &name,
                SubjectKey::Ec { curve: &key.curve, point: &key.point });
            builder.hash = hash;
            builder.serial = vec![0x7f, 0xff];
            builder.sans = vec![SanEntry::Dns(name.clone())];
            let der = builder.sign(&SigningKey::Ec {
                curve: &key.curve, private: &key.private }).unwrap();
            emit(&format!("ec-{}-{}", label, hash), &format!("ec-{}-{}", label, hash), &der);
        }
    }

    // --- DSA signed, DSA key, every hash RFC 3279, RFC 5758 and NIST's
    //     arc give an OID for ---
    let dsa_key = allcrypt::publickey_ciphers::dsa::DsaPrivateKey::generate(
        allcrypt::publickey_ciphers::dsa::DsaParameters::generate(2048, 256).unwrap()).unwrap();
    for hash in ["sha256", "sha224", "sha384", "sha512", "sha1"] {
        let name = format!("dsa-{}.example.test", hash);
        let mut builder = CertificateBuilder::new(&name, SubjectKey::Dsa(&dsa_key.public));
        builder.hash = hash;
        builder.serial = vec![0x0d, 0x5a];
        builder.sans = vec![SanEntry::Dns(name.clone())];
        let der = builder.sign(&SigningKey::Dsa(&dsa_key)).unwrap();
        emit(&format!("dsa-{}", hash), &format!("dsa-{}", hash), &der);
    }

    // --- A CA, with basicConstraints and a path length ---
    for (label, path_len) in [("ca-nolimit", None), ("ca-0", Some(0)), ("ca-3", Some(3))] {
        let mut builder = CertificateBuilder::new(
            &format!("Test Root {}", label),
            SubjectKey::Ec { curve: &p256.curve, point: &p256.point });
        builder.is_ca = Some((true, path_len));
        builder.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
        builder.serial = vec![0x01];
        let der = builder.sign(&SigningKey::Ec {
            curve: &p256.curve, private: &p256.private }).unwrap();
        emit(label, label, &der);
    }

    // --- A mixed chain: RSA root signing an EC leaf, and the reverse ---
    // The signers are the self-signed certificates emitted above: an RSA
    // CA signing an EC leaf and an EC CA signing an RSA leaf, which is the
    // combination a real chain hits during a migration and the one where
    // an implementation is most likely to pick the wrong key type.
    let mut builder = CertificateBuilder::new(
        "mixed-ec-leaf.test",
        SubjectKey::Ec { curve: &p256.curve, point: &p256.point });
    builder.issuer = vec![(oids::COMMON_NAME, "rsa-sha256.example.test".to_string())];
    builder.serial = vec![0x42];
    builder.sans = vec![SanEntry::Dns("mixed-ec-leaf.test".to_string())];
    let der = builder.sign(&SigningKey::Rsa(&rsa_key)).unwrap();
    emit("mixed-rsa-signs-ec", "rsa-sha256", &der);

    let mut builder = CertificateBuilder::new(
        "mixed-rsa-leaf.test",
        SubjectKey::Rsa { n: &rsa_public.n, e: &rsa_public.e });
    builder.issuer = vec![(oids::COMMON_NAME, "ec-p256-sha256.example.test".to_string())];
    builder.serial = vec![0x43];
    builder.sans = vec![SanEntry::Dns("mixed-rsa-leaf.test".to_string())];
    let der = builder.sign(&SigningKey::Ec {
        curve: &p256.curve, private: &p256.private }).unwrap();
    emit("mixed-ec-signs-rsa", "ec-p256-sha256", &der);

    let mut builder = CertificateBuilder::new(
        "mixed-dsa-signs-ec.test",
        SubjectKey::Ec { curve: &p256.curve, point: &p256.point });
    builder.issuer = vec![(oids::COMMON_NAME, "dsa-sha256.example.test".to_string())];
    builder.serial = vec![0x44];
    builder.sans = vec![SanEntry::Dns("mixed-dsa-signs-ec.test".to_string())];
    let der = builder.sign(&SigningKey::Dsa(&dsa_key)).unwrap();
    emit("mixed-dsa-signs-ec", "dsa-sha256", &der);

    // --- A multi-attribute name, which exercises the RDN parsing ---
    let mut builder = CertificateBuilder::new(
        "full-name.test",
        SubjectKey::Ec { curve: &p256.curve, point: &p256.point });
    builder.subject = vec![
        (oids::COUNTRY, "SE".to_string()),
        (oids::STATE_OR_PROVINCE, "Stockholm".to_string()),
        (oids::LOCALITY, "Stockholm".to_string()),
        (oids::ORGANIZATION, "Example AB".to_string()),
        (oids::ORGANIZATIONAL_UNIT, "Engineering".to_string()),
        (oids::COMMON_NAME, "full-name.test".to_string()),
    ];
    builder.issuer = builder.subject.clone();
    builder.serial = vec![0x44];
    let der = builder.sign(&SigningKey::Ec {
        curve: &p256.curve, private: &p256.private }).unwrap();
    emit("full-name", "full-name", &der);

    // --- A name with non-ASCII in it, since UTF8String is where encoders
    //     tend to go wrong ---
    let mut builder = CertificateBuilder::new(
        "Räksmörgås AB",
        SubjectKey::Ec { curve: &p256.curve, point: &p256.point });
    builder.serial = vec![0x45];
    builder.sans = vec![SanEntry::Dns("xn--rksmrgs-5wao1o.test".to_string())];
    let der = builder.sign(&SigningKey::Ec {
        curve: &p256.curve, private: &p256.private }).unwrap();
    emit("utf8-name", "utf8-name", &der);

    // --- Long serial numbers, which are common and easy to mishandle ---
    for (label, serial) in [
        ("serial-1", vec![0x01]),
        ("serial-zero-prefixed", vec![0x00, 0xff]),
        ("serial-20-bytes", (0..20u8).map(|i| i.wrapping_mul(7).wrapping_add(1)).collect()),
    ] {
        let mut builder = CertificateBuilder::new(
            &format!("{}.test", label),
            SubjectKey::Ec { curve: &p256.curve, point: &p256.point });
        builder.serial = serial;
        let der = builder.sign(&SigningKey::Ec {
            curve: &p256.curve, private: &p256.private }).unwrap();
        emit(label, label, &der);
    }

    // --- The key identifiers, which nothing else can judge ---
    //
    // **RFC 5280 4.2.1.2 method 1 has three plausible readings** - the
    // SHA-1 of the SubjectPublicKeyInfo, of the BIT STRING's TLV, or of
    // the BIT STRING's *contents* - and only the last one is right.
    // Every one of them is self-consistent: a chain built entirely with
    // the wrong reading has an authority identifier that matches its
    // issuer's subject identifier perfectly, so our own tests agree with
    // themselves whichever we picked. python-cryptography computes the
    // same identifier from the same key and is the only thing here that
    // can say which reading it is.
    //
    // Emitted as (SPKI, identifier) pairs rather than as certificates:
    // the checker needs the key on its own to compute the reference,
    // and an identifier inside a certificate is only ever compared with
    // another of ours.
    for (label, subject) in [
        ("keyid-rsa", SubjectKey::Rsa { n: &rsa_public.n, e: &rsa_public.e }),
        ("keyid-p256", SubjectKey::Ec { curve: &p256.curve, point: &p256.point }),
        ("keyid-p384", SubjectKey::Ec { curve: &p384.curve, point: &p384.point }),
    ] {
        // The SPKI comes out of a certificate we build for the purpose,
        // so there is one encoder rather than two.
        let mut builder = CertificateBuilder::new("keyid.test", subject);
        builder.serial = vec![0x46];
        let der = builder.sign(&SigningKey::Ec {
            curve: &p256.curve, private: &p256.private }).unwrap();
        let certificate = Certificate::parse(&der).unwrap();
        let identifier = allcrypt::x509::builder::key_identifier(
            &builder.subject_key).unwrap();
        println!("keyid {} {} {}", label, hex(certificate.spki), hex(&identifier));
    }

    eprintln!("every certificate parsed back correctly by our own parser");
}
