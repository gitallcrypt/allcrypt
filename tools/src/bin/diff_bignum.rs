// Emits `op a b result` lines in hex for a large pseudorandom matrix, so
// Python's exact integers can be used as the oracle.
use allcrypt::bignum::BigUint;

/// xorshift64*, so the corpus is reproducible on both sides.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn number(&mut self, max_bits: usize) -> BigUint {
        let bits = (self.next() as usize % max_bits) + 1;
        let bytes = bits.div_ceil(8);
        let v: Vec<u8> = (0..bytes).map(|_| (self.next() >> 24) as u8).collect();
        let mut n = BigUint::from_bytes_be(&v);
        // trim to exactly `bits` so small values appear too
        if n.bit_len() > bits { n = n.shr(n.bit_len() - bits); }
        n
    }
}

fn main() {
    let mut rng = Rng(0x2545F4914F6CDD1D);
    // A spread of sizes: single limb, limb boundaries, and RSA/EC scale.
    for &max_bits in &[1usize, 8, 63, 64, 65, 127, 128, 129, 256, 521, 1024, 2048] {
        for _ in 0..60 {
            let a = rng.number(max_bits);
            let b = rng.number(max_bits);
            println!("add {} {} {}", a.to_hex(), b.to_hex(), a.add(&b).to_hex());
            println!("mul {} {} {}", a.to_hex(), b.to_hex(), a.mul(&b).to_hex());
            println!("cmp {} {} {}", a.to_hex(), b.to_hex(),
                     match a.cmp(&b) { std::cmp::Ordering::Less => "lt",
                                       std::cmp::Ordering::Equal => "eq",
                                       std::cmp::Ordering::Greater => "gt" });
            if a >= b {
                println!("sub {} {} {}", a.to_hex(), b.to_hex(), a.sub(&b).unwrap().to_hex());
            }
            if !b.is_zero() {
                let (q, r) = a.divrem(&b).unwrap();
                println!("div {} {} {}", a.to_hex(), b.to_hex(), q.to_hex());
                println!("rem {} {} {}", a.to_hex(), b.to_hex(), r.to_hex());
                println!("gcd {} {} {}", a.to_hex(), b.to_hex(), a.gcd(&b).to_hex());
                match a.mod_inverse(&b) {
                    Ok(inv) => println!("inv {} {} {}", a.to_hex(), b.to_hex(), inv.to_hex()),
                    Err(_)  => println!("inv {} {} none", a.to_hex(), b.to_hex()),
                }
            }
            for &sh in &[0usize, 1, 7, 63, 64, 65, 200] {
                println!("shl {} {} {}", a.to_hex(), sh, a.shl(sh).to_hex());
                println!("shr {} {} {}", a.to_hex(), sh, a.shr(sh).to_hex());
            }
            println!("bitlen {} - {}", a.to_hex(), a.bit_len());
            println!("bytes {} - {}", a.to_hex(),
                     a.to_bytes_be().iter().map(|b| format!("{:02x}", b)).collect::<String>());
        }
    }

    // modpow separately: expensive, so fewer but at realistic sizes
    for &bits in &[8usize, 64, 128, 256, 512] {
        for _ in 0..8 {
            let base = rng.number(bits);
            let exp = rng.number(bits.min(64));
            let m = rng.number(bits);
            if m.is_zero() { continue; }
            let got = base.mod_pow(&exp, &m).unwrap();
            println!("modpow3 {} {} {} {}", base.to_hex(), exp.to_hex(), m.to_hex(), got.to_hex());

            // Every path must agree with every other, whatever the modulus.
            assert_eq!(got, base.mod_pow_schoolbook(&exp, &m).unwrap(),
                       "montgomery vs schoolbook for {} ^ {} mod {}",
                       base.to_hex(), exp.to_hex(), m.to_hex());
            if !m.is_even() {
                assert_eq!(got, base.mod_pow_ct(&exp, &m).unwrap(),
                           "ladder vs fast path for {} ^ {} mod {}",
                           base.to_hex(), exp.to_hex(), m.to_hex());
            }
        }
    }

    // Montgomery-specific: odd moduli only, across the awkward sizes, with
    // exponents chosen to stress the ladder's branch pattern.
    for &bits in &[64usize, 65, 127, 128, 129, 256, 512, 1024] {
        for _ in 0..6 {
            let mut m = rng.number(bits);
            if m.is_even() { m = m.add(&BigUint::one()); }
            if m.is_zero() || m.is_one() { continue; }
            let base = rng.number(bits);
            for exp in [BigUint::one(), rng.number(bits.min(200)),
                        m.sub(&BigUint::one()).unwrap()] {
                let fast = base.mod_pow(&exp, &m).unwrap();
                assert_eq!(fast, base.mod_pow_ct(&exp, &m).unwrap(), "ladder mismatch");
                assert_eq!(fast, base.mod_pow_schoolbook(&exp, &m).unwrap(), "schoolbook mismatch");
                println!("modpow3 {} {} {} {}", base.to_hex(), exp.to_hex(), m.to_hex(),
                         fast.to_hex());
            }
        }
    }
    eprintln!("all montgomery / ladder / schoolbook paths agreed");
}

// Appended: Montgomery must agree with the schoolbook path and with Python.
