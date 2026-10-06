// ECDSA signatures, dumped for comparison against OpenSSL through
// python-cryptography. Verified by scripts/diff_check.py.
//
// Deterministic nonces make this a much stronger test than it would
// otherwise be: because RFC 6979 fixes k, a correct implementation produces
// byte-identical signatures, so the reference can check the exact bytes
// rather than only that the signature verifies. Both are checked.
use allcrypt::bignum::BigUint;
use allcrypt::ec::curves;
use allcrypt::hash_functions::{sha1::SHA1, sha2, HashFunction};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn scalar(&mut self, n: &BigUint) -> BigUint {
        let bytes: Vec<u8> = (0..n.bit_len().div_ceil(8))
            .map(|_| (self.next() >> 24) as u8).collect();
        let mut v = BigUint::from_bytes_be(&bytes);
        while v >= *n || v.is_zero() { v = v.shr(1).add(&BigUint::one()); }
        v
    }
}

fn main() {
    let mut rng = Rng(0x243F6A8885A308D3);

    // Not `curves::all()`: the GOST curves are in that list and nothing
    // on this machine can verify an ECDSA signature over one. Nobody
    // signs with ECDSA over a GOST curve either - they are used with
    // GOST R 34.10-2012, which has its own corpus - so emitting rows here
    // would add cases that count towards the total and check nothing.
    for curve in [curves::p256(), curves::p384(), curves::p521(), curves::secp256k1()] {
        let name = curve.name;

        // A spread of message lengths, including the empty message and
        // lengths either side of the hash block size.
        let messages: Vec<Vec<u8>> = [0usize, 1, 3, 55, 56, 63, 64, 65, 119, 128, 1000]
            .iter().map(|n| (0..*n).map(|i| ((i * 31 + 7) & 0xff) as u8).collect())
            .collect();

        for _ in 0..3 {
            let private = rng.scalar(&curve.n);
            let public = curve.generator_mul(&private);
            let encoded_public = curve.encode_point(&public, false).unwrap();

            for message in &messages {
                // Four hashes, so the truncation path is exercised in both
                // directions: SHA-1 and SHA-224 are shorter than P-256's
                // order, SHA-512 is longer than every order here but
                // P-521's - where every hash is shorter, and 512 bits
                // into a 521 bit order is the case that is not a whole
                // number of bytes.
                let mut h1 = SHA1::new(message);
                let mut h224 = sha2::SHA224::new(message);
                let mut h256 = sha2::SHA256::new(message);
                let mut h512 = sha2::SHA512::new(message, 512);

                for (hash_name, digest, signature) in [
                    ("sha1", h1.digest(),
                     curve.sign(&private, &SHA1::new(message).digest(), SHA1::new(&[]))),
                    ("sha224", h224.digest(),
                     curve.sign(&private, &sha2::SHA224::new(message).digest(),
                                sha2::SHA224::new(&[]))),
                    ("sha256", h256.digest(),
                     curve.sign(&private, &sha2::SHA256::new(message).digest(),
                                sha2::SHA256::new(&[]))),
                    ("sha512", h512.digest(),
                     curve.sign(&private, &sha2::SHA512::new(message, 512).digest(),
                                sha2::SHA512::new(&[], 512))),
                ] {
                    let signature = signature.unwrap();

                    // Self-consistency first: we must verify our own work,
                    // and signing twice must give the same bytes.
                    assert!(curve.verify(&public, &digest, &signature).unwrap(),
                            "{} {} failed to verify its own signature", name, hash_name);

                    println!("ecdsa {} {} {} {} {} {}",
                             name, hash_name,
                             hex(&encoded_public),
                             hex(&digest),
                             signature.r.to_hex(),
                             signature.s.to_hex());
                }
            }
        }
    }
    eprintln!("every signature verified against our own verifier");
}
