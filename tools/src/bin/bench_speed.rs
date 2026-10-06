// Throughput of the hashes, ciphers, AEADs and KDFs, and the rate of the
// public-key operations, printed one per line as `name<TAB>value<TAB>unit`
// so `scripts/bench_compare.py` can set them against `openssl speed`.
//
// Bulk operations run over 16 KiB buffers, the size `openssl speed -bytes
// 16384` uses, for at least `SECONDS` each.
//
//     cargo run --release -p allcrypt-tools --bin bench_speed [filter]
use allcrypt::api::{self, AnyBlockCipher, AnyHash, AnyStreamCipher, CipherStream, Mode};
use allcrypt::bignum::BigUint;
use allcrypt::block_ciphers::gcm::Gcm;
use allcrypt::block_ciphers::{xts, BlockCipher};
use allcrypt::ec::curves;
use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
use allcrypt::publickey_ciphers::rsa::{self, RsaPrivateKey};
use std::hint::black_box;
use std::time::{Duration, Instant};

const CHUNK: usize = 16 * 1024;
const SECONDS: f64 = 0.6;

/// Calls `body` until `SECONDS` have passed; returns calls per second.
fn rate<F: FnMut()>(mut body: F) -> f64 {
    body();
    let start = Instant::now();
    let mut calls = 0u64;
    let limit = Duration::from_secs_f64(SECONDS);
    while start.elapsed() < limit {
        body();
        calls += 1;
    }
    calls as f64 / start.elapsed().as_secs_f64()
}

fn bulk<F: FnMut(&mut [u8])>(filter: &str, name: &str, mut body: F) {
    if !name.contains(filter) {
        return;
    }
    let mut buf = vec![0x5au8; CHUNK];
    let per_second = rate(|| body(black_box(&mut buf)));
    println!("{name}\t{:.1}\tMB/s", per_second * CHUNK as f64 / 1e6);
}

fn ops<F: FnMut()>(filter: &str, name: &str, body: F) {
    if !name.contains(filter) {
        return;
    }
    println!("{name}\t{:.1}\tops/s", rate(body));
}

fn main() {
    let filter = std::env::args().nth(1).unwrap_or_default();
    let f = filter.as_str();

    for hash in ["md4", "md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b", "blake2s",
                 "ripemd160", "whirlpool", "sm3", "streebog256", "gost94", "md2"] {
        bulk(f, &format!("hash/{hash}"), |buf| {
            let mut h = AnyHash::new(hash).unwrap();
            h.update(buf);
            black_box(h.digest());
        });
    }

    // Block ciphers: (name, key length, mode, decrypt).
    let modes: &[(&str, usize, &str, bool)] = &[
        ("aes", 16, "ecb", false), ("aes", 16, "ctr", false), ("aes", 32, "ctr", false),
        ("aes", 16, "cbc", false), ("aes", 16, "cbc", true),
        ("des", 8, "cbc", false), ("3des", 24, "cbc", false),
        ("blowfish", 16, "cbc", false), ("cast5", 16, "cbc", false),
        ("idea", 16, "cbc", false), ("rc2", 16, "cbc", false), ("seed", 16, "cbc", false),
        ("camellia", 16, "cbc", false), ("aria", 16, "cbc", false), ("sm4", 16, "cbc", false),
        ("twofish", 16, "cbc", false), ("serpent", 16, "cbc", false),
        ("kuznyechik", 32, "cbc", false), ("magma", 32, "cbc", false),
        ("gost", 32, "cbc", false), ("tea", 16, "cbc", false), ("rc5", 16, "cbc", false),
    ];
    for &(cipher, key_len, mode, decrypting) in modes {
        let name = format!("cipher/{cipher}-{}-{mode}{}", key_len * 8,
                           if decrypting { "-dec" } else { "" });
        let key = vec![7u8; key_len];
        let mode_value = Mode::from_name(mode).unwrap();
        let probe = AnyBlockCipher::new(cipher, &key, None).unwrap();
        let iv = if mode == "ecb" { vec![] } else { vec![1u8; probe.blocksize()] };
        let mut stream = CipherStream::new(probe, mode_value, &iv, decrypting).unwrap();
        bulk(f, &name, |buf| { black_box(stream.update(buf).unwrap()); });
    }

    // Keyed once, as `openssl speed` keys once: a disk encrypts sector
    // after sector under the same two keys.
    let xts_key: Vec<u8> = (0..64).collect();
    let mut data_cipher = AnyBlockCipher::new("aes", &xts_key[..32], None).unwrap();
    let mut tweak_cipher = AnyBlockCipher::new("aes", &xts_key[32..], None).unwrap();
    bulk(f, "cipher/aes-256-xts", |buf| {
        black_box(xts::encrypt(&mut data_cipher, &mut tweak_cipher, &xts::sector_tweak(9), buf)
            .unwrap());
    });

    for (cipher, key_len, nonce_len) in [("chacha20", 32, 12), ("salsa20", 32, 8), ("rc4", 16, 0)] {
        let mut s = AnyStreamCipher::new(cipher, &vec![9u8; key_len], &vec![0u8; nonce_len])
            .unwrap();
        bulk(f, &format!("stream/{cipher}"), |buf| s.apply(buf).unwrap());
    }

    // GCM keyed once with a fresh nonce per message, as `openssl speed`
    // runs it; the one-call API below also builds the key schedule.
    for key_len in [16, 32] {
        let mut cipher = AnyBlockCipher::new("aes", &vec![4u8; key_len], None).unwrap();
        bulk(f, &format!("aead/aes-gcm-{}", key_len * 8), |buf| {
            let mut gcm = Gcm::encryptor(&mut cipher, &[2u8; 12], b"").unwrap();
            gcm.apply(buf).unwrap();
            black_box(gcm.tag().unwrap());
        });
    }
    for (aead, key_len) in [("chacha20-poly1305", 32), ("aes-ccm", 16)] {
        let key = vec![4u8; key_len];
        let nonce = [2u8; 12];
        let label = if aead == "chacha20-poly1305" { aead.to_string() }
                    else { format!("{aead}-{}", key_len * 8) };
        bulk(f, &format!("aead/{label}"), |buf| {
            black_box(api::aead_encrypt(aead, &key, &nonce, b"", buf).unwrap());
        });
    }

    bulk(f, "mac/hmac-sha256", |buf| {
        black_box(api::hmac("sha256", b"key", buf).unwrap());
    });

    // KDFs: calls per second at a fixed cost.
    ops(f, "kdf/pbkdf2-sha256-10000", || {
        black_box(api::pbkdf2("sha256", b"password", b"salt", 10_000, 32).unwrap());
    });
    ops(f, "kdf/pbkdf2-sha1-4096", || {
        black_box(api::pbkdf2("sha1", b"password", b"salt", 4096, 32).unwrap());
    });
    ops(f, "kdf/scrypt-16384-8-1", || {
        black_box(api::scrypt(b"password", b"salt", 16384, 8, 1, 32).unwrap());
    });
    ops(f, "kdf/argon2id-65536-3-1", || {
        black_box(api::argon2("argon2id", b"password", b"saltsalt", 65536, 3, 1, b"", b"", 32)
            .unwrap());
    });

    // Public key.
    // RSA key generation takes seconds, so only when an RSA row is wanted.
    if ["pk/rsa2048-sign", "pk/rsa2048-verify"].iter().any(|name| name.contains(f)) {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let digest = SHA256::new(b"a message").digest();
        let signature = rsa::sign_pkcs1v15(&key, "sha256", &digest).unwrap();
        ops(f, "pk/rsa2048-sign", || {
            black_box(rsa::sign_pkcs1v15(&key, "sha256", &digest).unwrap());
        });
        ops(f, "pk/rsa2048-verify", || {
            black_box(rsa::verify_pkcs1v15(&key.public, "sha256", &digest, &signature).unwrap());
        });
    }

    let p256 = curves::p256();
    let d = p256.n.shr(1).add(&BigUint::from_u64(12345));
    let q = p256.generator_mul(&d);
    let digest = SHA256::new(b"a message").digest();
    let signature = p256.sign(&d, &digest, SHA256::new(&[])).unwrap();
    ops(f, "pk/ecdsa-p256-sign", || {
        black_box(p256.sign(&d, &digest, SHA256::new(&[])).unwrap());
    });
    ops(f, "pk/ecdsa-p256-verify", || {
        black_box(p256.verify(&q, &digest, &signature).unwrap());
    });

    for curve in ["ed25519", "ed448"] {
        let (private, public) = api::eddsa_generate(curve).unwrap();
        let signature = api::eddsa_sign(curve, &private, b"a message", b"").unwrap();
        ops(f, &format!("pk/{curve}-sign"), || {
            black_box(api::eddsa_sign(curve, &private, b"a message", b"").unwrap());
        });
        ops(f, &format!("pk/{curve}-verify"), || {
            black_box(api::eddsa_verify(curve, &public, b"a message", &signature, b"").unwrap());
        });
    }

    let (a, _) = api::x25519_generate().unwrap();
    let (_, b) = api::x25519_generate().unwrap();
    ops(f, "pk/x25519", || {
        black_box(api::x25519_exchange(&a, &b).unwrap());
    });
    let (a, _) = api::x448_generate().unwrap();
    let (_, b) = api::x448_generate().unwrap();
    ops(f, "pk/x448", || {
        black_box(api::x448_exchange(&a, &b).unwrap());
    });
}
