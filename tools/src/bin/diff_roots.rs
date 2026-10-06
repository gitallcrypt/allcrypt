// Every certificate in the machine's own trust store, parsed by us and
// dumped for comparison against OpenSSL. Verified by scripts/diff_check.py.
//
// This is the corpus the other X.509 tests cannot be: a few hundred real
// certificates, issued by real CAs over twenty-five years, carrying every
// encoding quirk that actually survives in production. Certificates we
// generate ourselves all look the way we think certificates look.
//
// It is also the check on strictness. A parser that refuses real roots is
// not strict, it is broken - so any failure here is ours until proven
// otherwise, and the count of parsed-versus-present is part of the output.
use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
use allcrypt::{pem, x509::{Certificate, GeneralName, PublicKey, SignatureAlgorithm}};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let candidates = ["/etc/ssl/certs/ca-certificates.crt",
                      "/etc/pki/tls/certs/ca-bundle.crt",
                      "/etc/ssl/cert.pem",
                      "/root/.ccr/ca-bundle.crt"];

    let mut found = false;
    for path in candidates {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let blocks = match pem::certificates(&text) {
            Ok(blocks) => blocks,
            Err(reason) => {
                eprintln!("{}: PEM error: {}", path, reason);
                continue;
            }
        };
        found = true;
        println!("bundle {} {}", path, blocks.len());

        let mut parsed = 0usize;
        for (index, der) in blocks.iter().enumerate() {
            let label = format!("{}#{}", path, index);
            let certificate = match Certificate::parse(der) {
                Ok(certificate) => certificate,
                Err(reason) => {
                    // Reported rather than skipped silently: the checker
                    // turns this into a failure, because a real root that
                    // we cannot parse is a bug in us.
                    println!("unparsed {} {} {}", label, hex(der), reason);
                    continue;
                }
            };
            parsed += 1;

            println!("cert {} {}", label, hex(der));
            println!("field {} subject_cn {}", label,
                     certificate.subject.common_name().unwrap_or_default());
            println!("field {} issuer_cn {}", label,
                     certificate.issuer.common_name().unwrap_or_default());
            println!("field {} not_before {}", label, certificate.not_before);
            println!("field {} not_after {}", label, certificate.not_after);
            println!("field {} serial {}", label, certificate.serial_hex());
            println!("field {} version {}", label, certificate.version);
            println!("field {} is_ca {}", label, certificate.extensions.is_ca());
            println!("field {} tbs_sha256 {}", label,
                     hex(&SHA256::new(certificate.tbs).digest()));
            println!("field {} sig_alg {}", label, match certificate.signature_algorithm {
                SignatureAlgorithm::RsaPkcs1(hash) => format!("rsa-{}", hash),
                SignatureAlgorithm::Ecdsa(hash) => format!("ecdsa-{}", hash),
                SignatureAlgorithm::Gost(bits) => format!("gost-{}", bits),
                SignatureAlgorithm::Gost2001 => "gost-2001".to_string(),
                SignatureAlgorithm::Eddsa(name) => format!("eddsa-{}", name),
                SignatureAlgorithm::MlDsa(name) => name.to_ascii_lowercase(),
                SignatureAlgorithm::Dsa(hash) => format!("dsa-{}", hash),
                SignatureAlgorithm::Unsupported(name) => format!("unsupported-{}", name),
                SignatureAlgorithm::Unknown => "unknown".to_string(),
            });
            println!("field {} public_key {}", label, match &certificate.public_key {
                PublicKey::Rsa { n, .. } => format!("rsa-{}", n.bit_len()),
                PublicKey::Ec { curve, .. } => format!("ec-{}", curve),
                PublicKey::Eddsa { curve, .. } => format!("eddsa-{}", curve),
                PublicKey::MlDsa { parameter_set, .. } => parameter_set.to_ascii_lowercase(),
                PublicKey::Dsa { parameters, .. } => format!("dsa-{}",
                    parameters.as_ref().map_or(0, |(p, _, _)| p.bit_len())),
                PublicKey::Gost { curve, .. } => format!("gost-{}", curve),
                // Such a root now parses rather than being dropped, which
                // is the point - it used to disappear from the store and
                // from this corpus at the same time, leaving a bare count.
                PublicKey::UnsupportedCurve { oid, .. } =>
                    format!("ec-unsupported-{}", oid),
                PublicKey::Unsupported { .. } => "unsupported".to_string(),
            });

            let names: Vec<String> = certificate.extensions.subject_alt_names.iter()
                .filter_map(|name| match name {
                    GeneralName::Dns(text) => Some(format!("dns:{}", text)),
                    GeneralName::Email(text) => Some(format!("email:{}", text)),
                    GeneralName::Uri(text) => Some(format!("uri:{}", text)),
                    GeneralName::IpAddress(bytes) => Some(format!("ip:{}", hex(bytes))),
                    _ => None,
                }).collect();
            println!("field {} sans {}", label,
                     if names.is_empty() { "-".to_string() } else { names.join(",") });

            // A root is self-signed, so we can check its own signature
            // without needing anything else - which makes this a real
            // verification corpus, not only a parsing one.
            let self_issued = certificate.is_self_issued();
            println!("field {} self_issued {}", label, self_issued);
            if self_issued {
                use allcrypt::x509::verify::{verify_signature, Policy};
                // `..Policy::legacy` rather than every field by name, so
                // a new field does not silently get whatever the literal
                // happened to omit - and does not break this example
                // either, which is what just happened.
                let policy = Policy { now: certificate.not_before + 1,
                                      ..Policy::legacy(0) };
                println!("field {} self_signature {}", label,
                         match verify_signature(&certificate, &certificate, &policy) {
                             Ok(()) => "ok".to_string(),
                             Err(reason) => format!("failed: {}", reason),
                         });
            }
        }
        eprintln!("{}: parsed {} of {}", path, parsed, blocks.len());
    }

    if !found {
        eprintln!("no system CA bundle on this machine; nothing to compare");
    }
}
