// RSA keys and operations, dumped for comparison against OpenSSL through
// python-cryptography. Verified by scripts/diff_check.py.
//
// There is no ASN.1 in the library yet, so keys go out as their raw
// components and the checker reassembles them on the other side. That is
// enough to check the parts that matter: that our generated keys are real
// RSA keys, that OpenSSL accepts our signatures and ciphertexts, and that we
// accept its.
use allcrypt::bignum::BigUint;
use allcrypt::hash_functions::{md5::MD5, sha1::SHA1, sha2, HashFunction};
use allcrypt::publickey_ciphers::rsa::{self, RsaPrivateKey};

/// Hex, with "-" for empty: an empty field would otherwise vanish when the
/// checker splits the line on whitespace, and an empty message is exactly
/// the case worth testing.
fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    // Three sizes: the smallest allowed, the smallest still seen in the
    // wild, and the one anybody should be using. Generation is the slow
    // part of this example, and three keys is about four seconds.
    let keys: Vec<RsaPrivateKey> = [512usize, 1024, 2048]
        .iter()
        .map(|bits| {
            let key = RsaPrivateKey::generate(*bits)
                .unwrap_or_else(|e| panic!("generating {} bits: {}", bits, e));
            assert_eq!(key.bits(), *bits, "generated key is the wrong size");
            key
        })
        .collect();

    for (index, key) in keys.iter().enumerate() {
        let (p, q) = key.primes();
        let (dp, dq, qinv) = key.crt_parameters();
        println!("key {} {} {} {} {} {} {} {} {}", index,
                 key.public.n.to_hex(), key.public.e.to_hex(),
                 key.private_exponent().to_hex(),
                 p.to_hex(), q.to_hex(), dp.to_hex(), dq.to_hex(), qinv.to_hex());
    }

    let messages: Vec<Vec<u8>> = [0usize, 1, 7, 16, 32, 53]
        .iter().map(|n| (0..*n).map(|i| ((i * 31 + 7) & 0xff) as u8).collect())
        .collect();

    for (index, key) in keys.iter().enumerate() {
        for message in &messages {
            // Signatures over four hashes. A 512 bit key cannot hold a
            // SHA-512 DigestInfo, which the size check catches - so skip
            // rather than assert, and let the ones that fit be checked.
            for (name, digest) in [
                ("md5", MD5::new(message).digest()),
                ("sha1", SHA1::new(message).digest()),
                ("sha256", sha2::SHA256::new(message).digest()),
                ("sha512", sha2::SHA512::new(message, 512).digest()),
            ] {
                if let Ok(signature) = rsa::sign_pkcs1v15(key, name, &digest) {
                    // We must accept our own before anyone else is asked to.
                    assert!(rsa::verify_pkcs1v15(&key.public, name, &digest, &signature)
                                .unwrap(),
                            "key {} {} failed its own verification", index, name);
                    println!("sign {} {} {} {}", index, name, hex(&digest), hex(&signature));
                }
            }

            // Encryption is randomised, so the checker cannot compare bytes;
            // it decrypts with OpenSSL and compares the plaintext.
            if message.len() + 11 <= key.size() {
                let ciphertext = rsa::encrypt_pkcs1v15(&key.public, message).unwrap();
                assert_eq!(rsa::decrypt_pkcs1v15(key, &ciphertext).unwrap(), *message,
                           "key {} failed its own round trip", index);
                println!("enc {} {} {}", index, hex(message), hex(&ciphertext));
            }
        }

        // OAEP under every hash pairing a key holds, with and without a
        // label, at the empty message, one byte, and the longest the key
        // takes. The seed is printed: the checker re-encodes from it and
        // compares bytes, and OpenSSL decrypts. The seeds come from a
        // counter so the corpus is the same every run.
        let mut seed_counter = 0u8;
        for hash in ["sha1", "sha224", "sha256", "sha384", "sha512"] {
            for mgf in ["sha1", "sha256", hash] {
                let hash_len = allcrypt::api::AnyHash::new(hash).unwrap().digest_len();
                if key.size() < 2 * hash_len + 2 {
                    continue;
                }
                let longest = key.size() - 2 * hash_len - 2;
                for (length, label) in [(0usize, &b""[..]), (1, b"L"),
                                        (longest, b"a longer label, 33 bytes long...")] {
                    let message: Vec<u8> = (0..length).map(|i| (i * 13 + 5) as u8).collect();
                    seed_counter = seed_counter.wrapping_add(1);
                    let seed: Vec<u8> = (0..hash_len)
                        .map(|i| (i as u8).wrapping_mul(31) ^ seed_counter).collect();
                    let ciphertext = rsa::encrypt_oaep_with_seed(&key.public, hash, mgf, label,
                                                                 &message, &seed).unwrap();
                    assert_eq!(rsa::decrypt_oaep(key, hash, mgf, label, &ciphertext).unwrap(),
                               message, "key {} OAEP {}/{} failed its own round trip",
                               index, hash, mgf);
                    println!("oaep {} {} {} {} {} {} {}", index, hash, mgf, hex(label),
                             hex(&seed), hex(&message), hex(&ciphertext));
                }
            }
        }

        // A raw round trip too, which isolates the primitive from the
        // padding: m^e^d == m for a value the checker picks apart itself.
        let m = BigUint::from_hex("c0ffee0123456789abcdef").unwrap();
        println!("raw {} {} {}", index, m.to_hex(), key.public.raw(&m).unwrap().to_hex());
    }

    eprintln!("every key round tripped and verified against itself");
}
