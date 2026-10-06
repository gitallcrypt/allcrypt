// GOST R 34.10-2012 signatures, dumped for comparison against a reference
// written from the standard. Verified by scripts/diff_check.py.
//
// The check that matters here is **verification by somebody else**, not a
// round trip. A signature scheme that signs and verifies against itself
// proves only that the two halves agree; what has to be true is that the
// equation is the standard's and the byte conventions are everyone's.
//
// So the checker recomputes the verification from GOST R 34.10-2012 in
// Python and accepts or rejects each signature. The two conventions that
// can only be caught that way:
//
//   * the digest is read *little endian*, which combines with Streebog's
//     array-order output to give the standard's number;
//   * the signing equation is `s = r*d + k*e` with no inversion, so
//     verification needs `e^-1` where ECDSA needs `s^-1`.
//
// Nothing on this machine implements GOST R 34.10, so the reference is a
// second reading of the standard - the same claim and the same caveat as
// the rest of the GOST work.
//
// Every row carries the public key, so the checker never has to trust our
// key derivation either: it recomputes d*G itself and compares.
//
//   sign <curve> <private> <publicX> <publicY> <digest>  <signature s||r>
use allcrypt::ec::curves;
use allcrypt::bignum::BigUint;
use allcrypt::hash_functions::streebog::Streebog;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let mut cases = 0usize;

    for name in curves::gost_names() {
        let curve = curves::by_name(name).unwrap();
        let width = curve.gost_component_bytes();

        for seed in 0..5u8 {
            // A private scalar well inside [1, n).
            let mut bytes = vec![0u8; width];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = ((index as u32 * 89 + seed as u32 * 41 + 7) & 0xff) as u8;
            }
            bytes[0] &= 0x3f;
            let private = BigUint::from_bytes_be(&bytes);
            let public = curve.scalar_mul(&curve.g, &private);

            // Both digest sizes against both curve sizes. RFC 9189 pairs
            // 256 bit curves with Streebog-256, but the standard permits
            // either and a digest wider than the order exercises the
            // reduction.
            for bits in [256usize, 512] {
                for message in [&b""[..], b"m", b"a slightly longer message",
                                &[0xffu8; 200][..]] {
                    let (digest, fresh) = if bits == 256 {
                        (Streebog::new_256(message), Streebog::new_256(&[]))
                    } else {
                        (Streebog::new(message), Streebog::new(&[]))
                    };
                    use allcrypt::hash_functions::HashFunction;
                    let digest = { let mut h = digest; h.digest() };

                    let signature = curve.gost_sign(&private, &digest, fresh).unwrap();
                    assert!(curve.gost_verify(&public, &digest, &signature).unwrap(),
                            "{} does not verify its own signature", name);

                    let encoded = curve.gost_signature_bytes(&signature).unwrap();
                    println!("sign {} {} {} {} {} {}",
                             name,
                             hex(&private.to_bytes_be_padded(width).unwrap()),
                             hex(&public.x().unwrap().to_bytes_be_padded(width).unwrap()),
                             hex(&public.y().unwrap().to_bytes_be_padded(width).unwrap()),
                             hex(&digest), hex(&encoded));
                    cases += 1;
                }
            }
        }
    }

    eprintln!("[diff_gost3410] {} cases", cases);
}
