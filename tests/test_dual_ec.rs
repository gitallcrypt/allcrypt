//! Dual_EC_DRBG against `vectors/dual_ec.vec`: OpenSSL FIPS module 2.0.5's
//! answers, which Bouncy Castle 1.78.1 agrees with (one row is Bouncy
//! Castle's own). `scripts/make_dual_ec_vectors.py` writes the file; this
//! reads it offline. Rows with `q=` run under another `Q`, set in OpenSSL's
//! code the way ScreenOS set its own; they are read twice, through the
//! module and through the facade's `DualEcDrbg`, which is what Python
//! calls.

use std::collections::HashMap;

use allcrypt::prng::dual_ec::{DrbgHash, DualEcCurve, DualEcDrbg, Parameters};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_dual_ec_vectors() {
    let text = include_str!("../vectors/dual_ec.vec");
    let mut count = 0;
    let mut from_bouncycastle = 0;
    let mut with_q = 0;
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut fields = HashMap::new();
        let mut words = line.split(' ');
        assert_eq!(words.next(), Some("vector"));
        for word in words {
            let (k, v) = word.split_once('=').unwrap();
            fields.insert(k, v);
        }
        let get = |k: &str| *fields.get(k).unwrap_or_else(|| panic!("no {k}"));

        let curve = DualEcCurve::from_name(get("curve")).unwrap();
        let hash = DrbgHash::from_name(get("hash")).unwrap();
        let params = match fields.get("q") {
            None => Parameters::standard(curve),
            Some(q) => Parameters::with_q(curve, curve.curve().decode_point(&unhex(q)).unwrap())
                .unwrap(),
        };
        let mut drbg = DualEcDrbg::new(params, hash, &unhex(get("entropy")),
                                       &unhex(get("nonce")), &unhex(get("pers"))).unwrap();

        let out1 = unhex(get("out1"));
        assert_eq!(drbg.generate(out1.len(), &unhex(get("adin1"))).unwrap(), out1,
                   "{line}");

        if fields.get("reseed_entropy").is_some_and(|&v| v != "-") {
            drbg.reseed(&unhex(get("reseed_entropy")), &unhex(get("reseed_adin"))).unwrap();
        }
        let out2 = unhex(get("out2"));
        assert_eq!(drbg.generate(out2.len(), &unhex(get("adin2"))).unwrap(), out2,
                   "{line}");

        if let Some(q) = fields.get("q") {
            let mut facade = allcrypt::api::DualEcDrbg::new(
                get("curve"), get("hash"), &unhex(get("entropy")), &unhex(get("nonce")),
                &unhex(get("pers")), Some(&unhex(q))).unwrap();
            assert_eq!(facade.q().unwrap(), unhex(q));
            assert_eq!(facade.generate(out1.len(), b"").unwrap(), out1, "{line}");
            facade.reseed(&unhex(get("reseed_entropy")), b"").unwrap();
            assert_eq!(facade.generate(out2.len(), b"").unwrap(), out2, "{line}");
            with_q += 1;
        }

        count += 1;
        if fields.get("source") == Some(&"bouncycastle") {
            from_bouncycastle += 1;
        }
    }
    // A parser that finds nothing passes every assertion above.
    assert!(count >= 40, "only {count} rows");
    assert_eq!(from_bouncycastle, 1, "the independent anchor row is missing");
    assert_eq!(with_q, 6, "two rows per curve under another Q");
}
