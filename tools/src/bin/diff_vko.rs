// VKO key agreement, dumped for comparison against a reading of
// RFC 7836. Verified by scripts/diff_check.py.
//
// This corpus matters more than most, for a reason worth stating.
//
// **VKO is symmetric, so two wrong implementations agree perfectly.**
// Both sides compute `ukm * da * db * G`, and the order of the
// multiplications does not matter - so a round trip between our own two
// ends produces a matching key whichever way round the UKM is read and
// whichever way round the coordinates are serialised. Every one of those
// mistakes is invisible from inside, and produces a key a real peer will
// not have.
//
// The three conventions the checker exists to pin:
//
//   * the UKM is read as a *little endian* integer;
//   * both coordinates are written *little endian* before hashing, x then
//     y, each padded to the field's width;
//   * the digest follows the key size, not the curve.
//
// Every row carries both private keys and both public points, so the
// checker recomputes the whole exchange rather than taking any of our
// arithmetic on trust - and checks that *both* directions give the key
// in the row, which is what makes a one-sided mistake visible.
//
// **Two row kinds, because there are two readings of the scalar.**
// RFC 7836 writes `K = (m/q * UKM * x mod q) * (y*P)`, where `m/q` is
// the cofactor, and the other reading leaves it out. On every curve
// with `h = 1` the two scalars are the same number and the rows are
// duplicates - which is why the assertion below requires them to
// *differ* on the two curves where `h = 4`, so neither kind can
// quietly become the other.
//
// The second kind matches no implementation known here. It was once
// believed to be gost-engine's, on a misreading of its source;
// `vectors/gost_engine.vec` settled that the engine follows the
// document. It stays because the *distinction* is what these rows
// exist to keep honest - a `vko_using` that ignored its last argument
// would otherwise pass on seven of the nine curves.
//
//   vko           <curve> <da> <db> <ukm> <bits>  <key>  RFC 7836
//   vkonocofactor <curve> <da> <db> <ukm> <bits>  <key>  without m/q
use allcrypt::bignum::BigUint;
use allcrypt::ec::curves;
use allcrypt::ec::vko::Cofactor;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn scalar(width: usize, seed: u8) -> BigUint {
    let mut bytes: Vec<u8> = (0..width)
        .map(|i| ((i as u32 * 113 + seed as u32 * 37 + 19) & 0xff) as u8)
        .collect();
    bytes[0] &= 0x3f;
    BigUint::from_bytes_be(&bytes)
}

fn main() {
    let mut cases = 0usize;

    for name in curves::gost_names() {
        let curve = curves::by_name(name).unwrap();
        let width = curve.field_bytes();

        for pair in 0..4u8 {
            let da = scalar(width, pair + 1);
            let db = scalar(width, pair + 40);
            let qa = curve.scalar_mul(&curve.g, &da);
            let qb = curve.scalar_mul(&curve.g, &db);

            // UKM lengths around and past the field width, because it is
            // reduced modulo the order and a long one exercises that.
            for ukm in [&b"\x01"[..], b"ukm", b"0123456789abcdef",
                        &[0xffu8; 40][..]] {
                for bits in [256usize, 512] {
                    let ours = curve.vko(&da, &qb, ukm, bits).unwrap();
                    // Never emit a key the other side does not reach.
                    assert_eq!(curve.vko(&db, &qa, ukm, bits).unwrap(), ours,
                               "{} disagreed with itself", name);

                    let without = curve
                        .vko_using(&da, &qb, ukm, bits,
                                   Cofactor::WithoutCofactor)
                        .unwrap();
                    assert_eq!(curve.vko_using(&db, &qa, ukm, bits,
                                               Cofactor::WithoutCofactor)
                               .unwrap(),
                               without,
                               "{} disagreed with itself", name);

                    // The two readings are the same scalar when h = 1 and
                    // must not be when it is not - otherwise one of the
                    // two row kinds is testing the other's arithmetic.
                    if curve.h.is_one() {
                        assert_eq!(without, ours,
                                   "{}: h = 1 and the readings differ", name);
                    } else {
                        assert_ne!(without, ours,
                                   "{}: h = {} and the cofactor changed \
                                    nothing", name, curve.h);
                    }

                    let da_hex = hex(&da.to_bytes_be_padded(width).unwrap());
                    let db_hex = hex(&db.to_bytes_be_padded(width).unwrap());
                    println!("vko {} {} {} {} {} {}", name,
                             da_hex, db_hex, hex(ukm), bits, hex(&ours));
                    println!("vkonocofactor {} {} {} {} {} {}", name,
                             da_hex, db_hex, hex(ukm), bits, hex(&without));
                    cases += 2;
                }
            }
        }
    }

    eprintln!("[diff_vko] {} cases", cases);
}
