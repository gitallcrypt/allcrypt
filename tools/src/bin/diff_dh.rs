// Finite-field Diffie-Hellman, dumped for comparison against Python's own
// integers and against OpenSSL through python-cryptography.
//
// Two references rather than one, and deliberately: `pow(g, x, p)` is a
// completely independent implementation of the arithmetic, which is what
// catches a bignum bug, while python-cryptography's DH exchange is what
// catches a *convention* bug - the padding of the shared secret, which is
// arithmetically invisible and interoperably fatal.
use allcrypt::bignum::BigUint;
use allcrypt::publickey_ciphers::dh::{modp_group, DhGroup, MODP_1024, MODP_2048};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    /// An exponent of roughly `bytes` bytes. Short ones on purpose for most
    /// of the corpus: the arithmetic is the same and 40,000 full-width
    /// exponentiations would take long enough that nobody would run this.
    fn exponent(&mut self, bytes: usize) -> BigUint {
        let raw: Vec<u8> = (0..bytes).map(|_| (self.next() >> 24) as u8).collect();
        let value = BigUint::from_bytes_be(&raw);
        if value < BigUint::from_u64(2) { BigUint::from_u64(2) } else { value }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn dump(label: &str, group: &DhGroup, rng: &mut Rng, pairs: usize, exp_bytes: usize) {
    let p_hex = group.p().to_hex();
    let g_hex = group.g().to_hex();
    for _ in 0..pairs {
        let a = rng.exponent(exp_bytes);
        let b = rng.exponent(exp_bytes);
        let ya = group.public_key(&a).unwrap();
        let yb = group.public_key(&b).unwrap();
        let ya_bytes = group.encode(&ya).unwrap();

        let sa = group.shared_secret(&a, &yb).unwrap();
        let sb = group.shared_secret(&b, &ya).unwrap();
        // If the two sides disagree nothing downstream is worth checking.
        assert_eq!(sa, sb, "{}: the two sides derived different secrets", label);
        assert_eq!(sa.len(), group.modulus_bytes(), "{}: unpadded secret", label);

        println!("pub {} {} {} {} {}", label, p_hex, g_hex, a.to_hex(), hex(&ya_bytes));
        println!("dh {} {} {} {} {} {}", label, p_hex, g_hex,
                 a.to_hex(), b.to_hex(), hex(&sa));
    }
}

fn main() {
    let mut rng = Rng(0x243F6A8885A308D3);

    // The two standard groups, with short exponents for volume and a few
    // full-width ones because that is what the TLS client actually draws.
    let modp1024 = modp_group(MODP_1024).unwrap();
    let modp2048 = modp_group(MODP_2048).unwrap();
    dump("modp1024", &modp1024, &mut rng, 60, 20);
    dump("modp2048", &modp2048, &mut rng, 30, 32);
    dump("modp1024full", &modp1024, &mut rng, 4, 128);

    // Small groups, where the shared secret is short and so the padding
    // rule is exercised constantly rather than one time in 256. This is
    // the half of the corpus that catches a convention bug.
    //
    // 2^256 - 189 and 2^192 - 237 are prime; 2 generates a large subgroup
    // of each. They are too small to use and exactly right to test.
    for (label, hex_p) in [
        ("p256", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43"),
        ("p192", "ffffffffffffffffffffffffffffffffffffffffffffff13"),
    ] {
        let p = BigUint::from_hex(hex_p).unwrap();
        let group = DhGroup::new(p, BigUint::from_u64(2)).unwrap();
        dump(label, &group, &mut rng, 200, 8);
    }

    // And the boundary values, which is where an off-by-one in the range
    // check lives. These must all be refused.
    for group in [&modp1024, &modp2048] {
        let p = group.p();
        for bad in [BigUint::zero(), BigUint::one(),
                    p.sub(&BigUint::one()).unwrap(), p.clone(),
                    p.add(&BigUint::one())] {
            assert!(group.validate_peer(&bad).is_err(),
                    "a degenerate peer value was accepted");
        }
        assert!(group.validate_peer(&BigUint::from_u64(2)).is_ok());
        assert!(group.validate_peer(&p.sub(&BigUint::from_u64(2)).unwrap()).is_ok());
    }

    eprintln!("diff_dh: both sides agreed on every secret, and every \
               degenerate peer value was refused");
}
