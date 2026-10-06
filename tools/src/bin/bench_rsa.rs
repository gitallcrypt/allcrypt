// Timings for the RSA operations, so the cost of a handshake is a number
// rather than a guess.
use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
use allcrypt::publickey_ciphers::rsa::{self, RsaPrivateKey};
use std::time::Instant;

fn time<F: FnMut()>(label: &str, iterations: u32, mut body: F) {
    let start = Instant::now();
    for _ in 0..iterations {
        body();
    }
    let each = start.elapsed() / iterations;
    println!("{:<34} {:>10.3?}", label, each);
}

fn main() {
    for bits in [1024usize, 2048, 4096] {
        let start = Instant::now();
        let key = RsaPrivateKey::generate(bits).unwrap();
        println!("\n--- {} bit ---", bits);
        println!("{:<34} {:>10.3?}  (varies widely: it is a prime search)",
                 "key generation", start.elapsed());

        let digest = SHA256::new(b"a message").digest();
        let signature = rsa::sign_pkcs1v15(&key, "sha256", &digest).unwrap();
        let ciphertext = rsa::encrypt_pkcs1v15(&key.public, b"a short message").unwrap();

        time("sign (private, CRT, blinded)", 20, || {
            rsa::sign_pkcs1v15(&key, "sha256", &digest).unwrap();
        });
        time("verify (public)", 200, || {
            rsa::verify_pkcs1v15(&key.public, "sha256", &digest, &signature).unwrap();
        });
        time("encrypt (public)", 200, || {
            rsa::encrypt_pkcs1v15(&key.public, b"a short message").unwrap();
        });
        time("decrypt (private, CRT, blinded)", 20, || {
            rsa::decrypt_pkcs1v15(&key, &ciphertext).unwrap();
        });
    }
}
