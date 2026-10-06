// The RFC 9189 CTR_OMAC key exchange, dumped for comparison against a
// reading of the RFC. Verified by scripts/diff_check.py.
//
// The unit tests reproduce RFC 9189 Appendix A.1.3.1 byte for byte,
// which is one exchange on one curve with one suite. This corpus is the
// rest of the space, and it exists because of how many byte orders are
// stacked in one message:
//
//   * `UKM = INT(H[1..16])` is **big endian**, while VKO's own wire UKM
//     is little endian - opposite conventions, one expression apart;
//   * the shared point's coordinates are hashed **little endian**;
//   * the ephemeral public key's coordinates are written **little
//     endian** again, inside an OCTET STRING inside a BIT STRING;
//   * `seed = H[17..24]` and `IV = H[25..24+n/2]` are adjacent slices of
//     the same hash, and swapping them is invisible in a round trip.
//
// Every one of these produces an exchange that works perfectly between
// two implementations making the same choice. Only a second reading can
// see them, and the checker asserts that each wrong reading gives a
// *different* message.
//
// The 512 bit curves are the other half of the reason: KEG's 512 branch
// is VKO-512 with **no KDF**, which is not what the 256 branch does.
//
// Everything random is fixed here, so the corpus is reproducible: the
// ephemeral key and the preliminary secret are arguments rather than
// generated.
//
//   kex <curve> <suite> <d_eph> <d_s> <r_c> <r_s> <pms>  <h> <mac> <enc> <body>
use allcrypt::bignum::BigUint;
use allcrypt::ec::curves;
use allcrypt::tls::gost_kex::{export_iv, export_keys, keg_hash, wrap_secret,
                              unwrap_secret};
use allcrypt::tls::record_gost::CtrOmacSuite;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn scalar(width: usize, seed: u8) -> BigUint {
    let mut bytes: Vec<u8> = (0..width)
        .map(|i| ((i as u32 * 149 + seed as u32 * 53 + 31) & 0xff) as u8)
        .collect();
    bytes[0] &= 0x3f;
    BigUint::from_bytes_be(&bytes)
}

/// RFC 4357's *exchange* parameter set for a curve, where it has one.
///
/// `XchA` is CryptoPro-A's parameters to the digit and `XchB` is
/// CryptoPro-C's, so a certificate can name either curve two ways. Built
/// here by hand because there is deliberately no map from a curve to
/// "the OIDs that name it" - that direction is the one that caused the
/// bug.
fn exchange_algorithm_id(curve_name: &str) -> Option<Vec<u8>> {
    let param_set: &[u8] = match curve_name {
        "gost256-a" => &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00],
        "gost256-c" => &[0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x01],
        _ => return None,
    };
    let mut writer = allcrypt::asn1::Writer::new();
    writer.write_sequence(|algid| {
        // id-tc26-gost3410-12-256, the algorithm these suites use.
        algid.write_oid(&[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01]);
        algid.write_sequence(|params| {
            params.write_oid(param_set);
            // id-tc26-gost3411-12-256.
            params.write_oid(&[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02]);
        });
    });
    Some(writer.finish())
}

fn main() {
    let mut cases = 0usize;

    for name in curves::gost_names() {
        let curve = curves::by_name(name).unwrap();
        let width = curve.field_bytes();

        for pair in 0..3u8 {
            let server_private = scalar(width, pair + 1);
            let server_public = curve.scalar_mul(&curve.g, &server_private);
            let ephemeral_private = scalar(width, pair + 60);
            let ephemeral_public = curve.scalar_mul(&curve.g, &ephemeral_private);

            for randoms in 0..3u8 {
                // The randoms are 32 bytes each in TLS, and H is their
                // hash - so a pattern that makes the first sixteen
                // bytes of H zero is not reachable on purpose. What is
                // varied here is enough to move every slice of H.
                let client_random: Vec<u8> =
                    (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(randoms))
                             .collect();
                let server_random: Vec<u8> =
                    (0..32u8).map(|i| i.wrapping_mul(11).wrapping_add(randoms * 3))
                             .collect();

                for (suite_name, suite) in [("magma", CtrOmacSuite::MAGMA),
                                            ("kuznyechik", CtrOmacSuite::KUZNYECHIK)] {
                    let pms: Vec<u8> = (0..32u8)
                        .map(|i| i.wrapping_mul(29).wrapping_add(pair))
                        .collect();

                    let h = keg_hash(&client_random, &server_random);
                    let (mac_key, enc_key) =
                        export_keys(&curve, &ephemeral_private, &server_public,
                                    &h).unwrap();

                    // The server must reach the same keys from the other
                    // side, or the row describes an exchange that cannot
                    // happen.
                    assert_eq!(export_keys(&curve, &server_private,
                                           &ephemeral_public, &h).unwrap(),
                               (mac_key.clone(), enc_key.clone()),
                               "{} disagreed with itself", name);
                    assert_ne!(mac_key, enc_key,
                               "{}: the two export keys are equal", name);

                    // **Two spellings of the same curve**, so the rows
                    // cover the thing a real server found: the ephemeral
                    // key must wear the *server's* parameter set OID, and
                    // several OIDs name each of these curves. The
                    // canonical one for every curve, plus the exchange
                    // spelling where RFC 4357 gives one - `XchA` is
                    // CryptoPro-A to the digit and `XchB` is CryptoPro-C,
                    // so a client that rebuilt the OID from the curve
                    // would answer a server on either with the other.
                    let canonical = allcrypt::tls::gost_kex::algorithm_id_for(
                        &curve).unwrap();
                    let mut algorithm_ids = vec![canonical];
                    if let Some(exchange) = exchange_algorithm_id(name) {
                        algorithm_ids.push(exchange);
                    }
                    for algorithm_id in &algorithm_ids {
                    let body = wrap_secret(suite, &curve, algorithm_id,
                                           &ephemeral_private,
                                           &ephemeral_public, &server_public,
                                           &client_random, &server_random, &pms)
                               .unwrap();
                    // The AlgorithmIdentifier must come back out
                    // unchanged. A client that canonicalised it would
                    // pass every other assertion here.
                    assert!(body.windows(algorithm_id.len())
                                .any(|w| w == algorithm_id.as_slice()),
                            "{}: the ephemeral key does not carry the \
                             AlgorithmIdentifier it was given", name);
                    // Never emit a message the other half cannot read.
                    assert_eq!(unwrap_secret(suite, &curve, &server_private,
                                             &client_random, &server_random,
                                             &body).unwrap(),
                               pms, "{} {}", name, suite_name);
                    // And never one with the secret in the clear.
                    assert!(!body.windows(pms.len()).any(|w| w == pms),
                            "{}: the secret appears in the message", name);
                    // The IV must be inside H rather than derived some
                    // other way, which the checker also recomputes.
                    assert_eq!(export_iv(&h, suite).unwrap(),
                               h[24..24 + suite.iv_len()]);

                    // **The AlgorithmIdentifier goes into the row.** The
                    // checker rebuilds the message, and without it the
                    // two sides would have to agree on which OID names
                    // the curve - which is the choice this bug was.
                    println!("kex {} {} {} {} {} {} {} {} {} {} {} {}",
                             name, suite_name,
                             hex(&ephemeral_private.to_bytes_be_padded(width).unwrap()),
                             hex(&server_private.to_bytes_be_padded(width).unwrap()),
                             hex(&client_random), hex(&server_random), hex(&pms),
                             hex(&h), hex(&mac_key), hex(&enc_key),
                             hex(algorithm_id), hex(&body));
                    cases += 1;
                    }
                }
            }
        }
    }

    eprintln!("[diff_gost_kex] {} cases", cases);
}
