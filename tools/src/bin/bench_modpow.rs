// How much did Montgomery buy, and is the ladder's price acceptable?
use allcrypt::bignum::BigUint;
use std::time::Instant;

fn main() {
    // A 2048 bit odd modulus and a matching exponent, RSA scale.
    let m = BigUint::from_hex(&"c7".to_string().repeat(256)).unwrap();
    let base = BigUint::from_hex(&"9a".to_string().repeat(255)).unwrap();
    let e_public = BigUint::from_u64(65537);
    let e_private = BigUint::from_hex(&"b3".to_string().repeat(256)).unwrap();

    for (label, exp, iters) in [("public e=65537", &e_public, 20u32),
                                ("private 2048 bit", &e_private, 3)] {
        let t = Instant::now();
        for _ in 0..iters { base.mod_pow(exp, &m).unwrap(); }
        let mont = t.elapsed() / iters;

        let t = Instant::now();
        for _ in 0..iters { base.mod_pow_ct(exp, &m).unwrap(); }
        let ladder = t.elapsed() / iters;

        let t = Instant::now();
        for _ in 0..iters.min(2) { base.mod_pow_schoolbook(exp, &m).unwrap(); }
        let school = t.elapsed() / iters.min(2);

        println!("{:18}  montgomery {:>10.2?}   ladder {:>10.2?}   schoolbook {:>10.2?}   speedup {:.0}x",
                 label, mont, ladder, school, school.as_secs_f64() / mont.as_secs_f64());
    }

    // 256 bit, the elliptic curve field size.
    let p = BigUint::from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff").unwrap();
    let a = BigUint::from_hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978").unwrap();
    let t = Instant::now();
    for _ in 0..200 { a.mod_pow(&p, &p).unwrap(); }
    println!("{:18}  montgomery {:>10.2?}", "P-256 field", t.elapsed() / 200);
}
