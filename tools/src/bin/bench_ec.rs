use allcrypt::bignum::BigUint;
use allcrypt::ec::curves;
use std::time::Instant;

fn main() {
    for curve in curves::all() {
        let k = curve.n.shr(1).add(&BigUint::from_u64(12345));
        let iters = 20;
        let t = Instant::now();
        for _ in 0..iters { curve.generator_mul(&k); }
        let var = t.elapsed() / iters;
        let t = Instant::now();
        for _ in 0..iters { curve.scalar_mul_ct(&curve.g, &k); }
        let ct = t.elapsed() / iters;
        println!("{:11}  scalar_mul {:>9.2?}   scalar_mul_ct {:>9.2?}", curve.name, var, ct);
    }
}
