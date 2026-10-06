// ElGamal, dumped for comparison against Python's own integers.
//
// **There is no second implementation to compare against.** OpenSSL
// dropped ElGamal entirely and python-cryptography never had it, so
// unlike Diffie-Hellman next door there is no library here that can do a
// key exchange with us and tell us we agree on the convention. What is
// left is the arithmetic, and Python's `pow(g, x, p)` is a genuinely
// independent implementation of that - the same reference
// `tools/src/bin/diff_dh.rs` uses for its own first half.
//
// So the rows here are chosen to make the *conventions* checkable from
// the arithmetic alone:
//
//   * `enc` gives `(p, g, y, m, k)` and both ciphertext components, so
//     the checker recomputes `c1 = g^k` and `c2 = m * y^k` itself. Our
//     `encrypt` draws `k` internally, so the corpus cannot use it - it
//     dumps the pieces of a *chosen*-`k` encryption instead, and a
//     separate row proves the real one round-trips.
//   * `dec` gives a ciphertext and the plaintext we recovered, which
//     checks the inversion - the one step where `c1^(p-1-x)` and
//     `c1^x` inverted the other way could disagree.
//   * `sig` gives a whole signature and the digest, so the checker
//     verifies `y^r * r^s == g^m` with Python integers.
//
// Small primes are in the corpus on purpose: a 192 bit modulus makes
// short values - the ones whose padding is wrong if `to_bytes_be_padded`
// is - a routine occurrence rather than a one-in-256 surprise.

use allcrypt::bignum::BigUint;
use allcrypt::publickey_ciphers::dh::{modp_group, DhGroup, MODP_1024};
use allcrypt::publickey_ciphers::elgamal::{ElGamalPrivateKey, ElGamalPublicKey};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn value(&mut self, bytes: usize) -> BigUint {
        let raw: Vec<u8> = (0..bytes).map(|_| (self.next() >> 24) as u8).collect();
        let value = BigUint::from_bytes_be(&raw);
        if value < BigUint::from_u64(2) { BigUint::from_u64(2) } else { value }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn big(value: &BigUint) -> String {
    let text = hex(&value.to_bytes_be());
    let trimmed = text.trim_start_matches('0');
    if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
}

/// A small prime, so that short values - and therefore the padding - are
/// common rather than a one-in-256 surprise.
///
/// **`2^192 - 237`, which is the modulus `tools/src/bin/diff_dh.rs` already
/// uses**, and it is taken from there rather than invented. The first
/// draft of this file made one up; `DhGroup::new` accepts any odd
/// number, so it was built without complaint and the round-trip
/// assertion below failed with a wrong plaintext. That is the "never
/// type a value you have not checked" rule from docs/extending.md,
/// applied to a prime.
///
/// `check_prime` is called here for the same reason: a corpus built on
/// a composite modulus would compare our wrong answers with Python's
/// wrong answers and agree.
fn small_group() -> DhGroup {
    let p = BigUint::from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffff13")
        .expect("the small modulus parses");
    let group = DhGroup::new(p, BigUint::from_u64(2))
        .expect("the small group is structurally valid");
    group.check_prime(24).expect("the small modulus is prime");
    group
}

fn main() {
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let groups = [("small", small_group()),
                  ("modp1024", modp_group(MODP_1024).expect("MODP-1024"))];

    for (label, group) in &groups {
        for round in 0..12u32 {
            let width = group.modulus_bytes();
            let x = rng.value(if *label == "small" { 20 } else { 24 });
            let key = ElGamalPrivateKey::from_private(group.clone(), x.clone())
                .expect("a private exponent in range");
            let y = key.public().y().clone();

            // The pieces of one encryption with a chosen `k`, so the
            // checker can recompute both components.
            let k = rng.value(if *label == "small" { 20 } else { 24 });
            let m = rng.value(if *label == "small" { 16 } else { 40 });
            let c1 = group.g().mod_pow(&k, group.p()).expect("c1");
            let shared = y.mod_pow(&k, group.p()).expect("y^k");
            let c2 = m.mod_mul(&shared, group.p()).expect("c2");
            println!("enc {}/{} {} {} {} {} {} {} {}",
                     label, round,
                     big(group.p()), big(group.g()), big(&y),
                     big(&m), big(&k), big(&c1), big(&c2));

            // And that our decryption recovers it, which checks the
            // inversion rather than the exponentiation.
            let recovered = key.decrypt(&c1, &c2).expect("decrypt");
            assert_eq!(recovered, m, "{label} round {round} did not round-trip");
            println!("dec {}/{} {} {} {} {} {} {}",
                     label, round,
                     big(group.p()), big(group.g()), big(&x),
                     big(&c1), big(&c2), big(&recovered));

            // A real encryption, with `k` drawn internally, decrypted
            // back. The checker cannot predict the ciphertext, so what
            // it checks is that the two components are consistent with
            // *some* `k`: `c1` must be in the group and `c2 / m` must be
            // `c1^x`.
            let (r1, r2) = key.public().encrypt(&m).expect("encrypt");
            println!("live {}/{} {} {} {} {} {} {}",
                     label, round,
                     big(group.p()), big(group.g()), big(&x),
                     big(&m), big(&r1), big(&r2));

            // The padded wire forms, which is where a short value would
            // show up as a buffer of the wrong length.
            let sealed = allcrypt::publickey_ciphers::elgamal::encrypt_pkcs1v15(
                key.public(), b"pkcs#1 framed").expect("pkcs1 encrypt");
            assert_eq!(sealed.len(), 2 * width,
                       "{label} round {round}: ciphertext is not two widths");
            let opened = allcrypt::publickey_ciphers::elgamal::decrypt_pkcs1v15(
                &key, &sealed).expect("pkcs1 decrypt");
            assert_eq!(opened, b"pkcs#1 framed");

            // A signature, verified by the checker with Python integers.
            let digest: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7)
                                                 .wrapping_add(round as u8))
                .collect();
            let (r, s) = key.sign(&digest).expect("sign");
            assert!(key.public().verify(&digest, &r, &s).expect("verify"),
                    "{label} round {round}: our own signature did not verify");
            println!("sig {}/{} {} {} {} {} {} {}",
                     label, round,
                     big(group.p()), big(group.g()), big(&y),
                     hex(&digest), big(&r), big(&s));
        }
    }

    // A public key that must be refused, so the checker can confirm the
    // validation exists rather than taking it on trust.
    for (label, group) in &groups {
        for bad in [BigUint::from_u64(0), BigUint::one(),
                    group.p().sub(&BigUint::one()).expect("p-1")] {
            assert!(ElGamalPublicKey::new(group.clone(), bad.clone()).is_err(),
                    "{label}: a degenerate public value was accepted");
        }
    }
    eprintln!("[diff_elgamal] 2 groups x 12 rounds, and the three degenerate \
               public values refused in each");
}
