// Scalar multiplication, point encoding and ECDH, dumped for comparison
// against OpenSSL through python-cryptography.
use allcrypt::bignum::BigUint;
use allcrypt::ec::curves;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn scalar(&mut self, n: &BigUint) -> BigUint {
        let bytes: Vec<u8> = (0..n.bit_len().div_ceil(8)).map(|_| (self.next() >> 24) as u8).collect();
        let mut v = BigUint::from_bytes_be(&bytes);
        while v >= *n || v.is_zero() { v = v.shr(1).add(&BigUint::one()); }
        v
    }
}

fn main() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for curve in curves::all() {
        let name = curve.name;

        // k*G across small, structured and random scalars.
        let mut scalars: Vec<BigUint> = (1u64..=20).map(BigUint::from_u64).collect();
        scalars.push(BigUint::from_u64(65537));
        scalars.push(BigUint::from_u64(u64::MAX));
        scalars.push(curve.n.sub(&BigUint::one()).unwrap());
        scalars.push(curve.n.shr(1));
        for _ in 0..25 { scalars.push(rng.scalar(&curve.n)); }

        for k in &scalars {
            let point = curve.generator_mul(k);
            // The ladder must agree, every time.
            assert_eq!(point, curve.scalar_mul_ct(&curve.g, k), "{} ladder mismatch", name);
            let enc = curve.encode_point(&point, false).unwrap();
            let comp = curve.encode_point(&point, true).unwrap();
            println!("mulg {} {} {}", name, k.to_hex(),
                     enc.iter().map(|b| format!("{:02x}", b)).collect::<String>());
            println!("comp {} {} {}", name, k.to_hex(),
                     comp.iter().map(|b| format!("{:02x}", b)).collect::<String>());
            // Compressed decoding must recover the same point.
            // A curve whose p is 1 mod 4 cannot decompress with the
            // square root we have. Not a skip: it must *fail*, rather
            // than decoding to some other point.
            if curve.supports_compression() {
                assert_eq!(curve.decode_point(&comp).unwrap(), point,
                           "{} compressed roundtrip", name);
            } else {
                assert!(curve.decode_point(&comp).is_err(),
                        "{} decompressed a point it has no square root for", name);
            }
        }

        // ECDH over random pairs: this exercises k*P for a P that is not G.
        for _ in 0..10 {
            let da = rng.scalar(&curve.n);
            let db = rng.scalar(&curve.n);
            let qa = curve.generator_mul(&da);
            let qb = curve.generator_mul(&db);
            let sa = curve.ecdh(&da, &qb).unwrap();
            let sb = curve.ecdh(&db, &qa).unwrap();
            assert_eq!(sa, sb, "{} ECDH disagreed with itself", name);
            println!("ecdh {} {} {} {}", name, da.to_hex(), db.to_hex(),
                     sa.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        }

        // **A shared secret whose first byte is zero**, found by search
        // rather than waited for.
        //
        // This is the row that matters for the TLS premaster: RFC 4492
        // 5.10 says these leading zeros MUST NOT be truncated, and the
        // finite-field rule in RFC 5246 8.1.2 says the opposite. One
        // random pair in 256 has one, so a corpus of ten rows per curve
        // covers it about four times in ten runs - which is the same as
        // not covering it. `tools/src/bin/diff_dh.rs` uses small groups to
        // make its equivalent case routine; there is no small curve, so
        // this searches.
        //
        // The scalar is emitted like any other ECDH row, so the checker
        // needs no special case - it only counts how many it saw.
        let db = rng.scalar(&curve.n);
        let qb = curve.generator_mul(&db);
        let mut found = 0;
        let mut da = rng.scalar(&curve.n);
        for _ in 0..4000 {
            da = da.add(&BigUint::one());
            if da >= curve.n { da = BigUint::from_u64(2); }
            let shared = curve.ecdh(&da, &qb).unwrap();
            if shared[0] != 0 {
                continue;
            }
            println!("ecdh {} {} {} {}", name, da.to_hex(), db.to_hex(),
                     shared.iter().map(|b| format!("{:02x}", b))
                         .collect::<String>());
            found += 1;
            if found == 2 { break; }
        }
        assert!(found > 0,
                "{}: no shared secret with a leading zero byte in 4000 \
                 tries, which is impossible by chance - the search or \
                 the padding is broken", name);
    }
    eprintln!("ladder and ECDH self-consistency held throughout");
}
