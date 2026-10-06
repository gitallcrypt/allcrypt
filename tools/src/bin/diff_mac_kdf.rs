// Dumps HMAC / HKDF / TLS-PRF output for a deterministic matrix, so an
// independent implementation can be compared against it.
use allcrypt::hash_functions::{md5::MD5, sha1::SHA1, sha2};
use allcrypt::kdf::argon2::{Argon2, Variant};
use allcrypt::kdf::luks_af::{af_merge, af_split};
use allcrypt::kdf::password::{keepass_aes_kdf, openpgp_s2k, pbkdf2, sevenzip_aes_key};
use allcrypt::kdf::scrypt::scrypt;
use allcrypt::kdf::nist::{concat_kdf, kbkdf_counter, kbkdf_feedback, x963_kdf, Prf};
use allcrypt::kdf::{hkdf, hkdf_extract, tls10_prf, tls12_prf};
use allcrypt::api::AnyBlockCipher;
use allcrypt::mac::cbc_mac::{cbc_mac, cbc_mac_zero_padded};
use allcrypt::mac::Hmac;
use allcrypt::to_hex;

/// `(password, salt, iterations, length) -> derived key`, so each row
/// below names its hash once instead of spelling the signature out.
type Pbkdf2 = fn(&[u8], &[u8], u32, usize) -> Vec<u8>;

fn data(n: usize) -> Vec<u8> { (0..n).map(|i| ((i*167+13) & 0xff) as u8).collect() }
fn key(n: usize) -> Vec<u8> { (0..n).map(|i| ((i*89+7) & 0xff) as u8).collect() }

fn main() {
    let mut lens: Vec<usize> = (0..=140).collect();
    lens.extend_from_slice(&[255, 256, 257, 1000]);
    // key lengths either side of both block sizes (64 and 128)
    let keylens = [0usize, 1, 16, 32, 63, 64, 65, 100, 127, 128, 129, 200];

    for kl in keylens {
        for n in &lens {
            let (k, d) = (key(kl), data(*n));
            println!("hmac/md5/{}/{} {}", kl, n, to_hex(&Hmac::mac(MD5::new(&[]), &k, &d)).to_lowercase());
            println!("hmac/sha1/{}/{} {}", kl, n, to_hex(&Hmac::mac(SHA1::new(&[]), &k, &d)).to_lowercase());
            println!("hmac/sha224/{}/{} {}", kl, n, to_hex(&Hmac::mac(sha2::SHA224::new(&[]), &k, &d)).to_lowercase());
            println!("hmac/sha256/{}/{} {}", kl, n, to_hex(&Hmac::mac(sha2::SHA256::new(&[]), &k, &d)).to_lowercase());
            println!("hmac/sha384/{}/{} {}", kl, n, to_hex(&Hmac::mac(sha2::SHA384::new(&[]), &k, &d)).to_lowercase());
            println!("hmac/sha512/{}/{} {}", kl, n, to_hex(&Hmac::mac(sha2::SHA512::new(&[], 512), &k, &d)).to_lowercase());
        }
    }

    // HKDF across output lengths that straddle the hash-output boundary.
    for out_len in [1usize, 16, 31, 32, 33, 64, 65, 100, 255, 1000, 8160] {
        let ikm = data(22);
        let salt = key(13);
        let info = data(10);
        println!("hkdf/sha256/{} {}", out_len,
                 to_hex(&hkdf(sha2::SHA256::new(&[]), &salt, &ikm, &info, out_len).unwrap()).to_lowercase());
        if out_len <= 255 * 20 {
            println!("hkdf/sha1/{} {}", out_len,
                     to_hex(&hkdf(SHA1::new(&[]), &salt, &ikm, &info, out_len).unwrap()).to_lowercase());
        }
        println!("hkdf/sha512/{} {}", out_len,
                 to_hex(&hkdf(sha2::SHA512::new(&[], 512), &salt, &ikm, &info, out_len).unwrap()).to_lowercase());
        // empty salt takes the "zeros" path
        println!("hkdfnosalt/sha256/{} {}", out_len,
                 to_hex(&hkdf(sha2::SHA256::new(&[]), &[], &ikm, &info, out_len).unwrap()).to_lowercase());
    }
    println!("hkdfextract/sha256 {}",
             to_hex(&hkdf_extract(sha2::SHA256::new(&[]), &key(13), &data(22))).to_lowercase());

    // TLS PRFs: master-secret and key-expansion sized outputs, plus boundaries.
    for out_len in [1usize, 12, 31, 32, 33, 48, 64, 104, 200] {
        let secret = key(48);
        let seed = data(64);
        println!("prf12sha256/{} {}", out_len,
                 to_hex(&tls12_prf(sha2::SHA256::new(&[]), &secret, b"master secret", &seed, out_len)).to_lowercase());
        println!("prf12sha384/{} {}", out_len,
                 to_hex(&tls12_prf(sha2::SHA384::new(&[]), &secret, b"key expansion", &seed, out_len)).to_lowercase());
        println!("prf10/{} {}", out_len,
                 to_hex(&tls10_prf(&secret, b"master secret", &seed, out_len)).to_lowercase());
        // odd length secret, where the 1.0 halves share a byte
        println!("prf10odd/{} {}", out_len,
                 to_hex(&tls10_prf(&key(47), b"master secret", &seed, out_len)).to_lowercase());
    }

    // PBKDF2 (RFC 8018). Four focused sweeps rather than one cross
    // product: the full matrix would be millions of HMACs for no extra
    // coverage, since each parameter fails independently. Each sweep
    // holds everything but one input still.
    //
    // `hashlib.pbkdf2_hmac` is the reference, which is OpenSSL's, and it
    // is the one piece of this file that does not need a `continue` for
    // a missing algorithm - every hash here has been in hashlib since
    // Python 2.5.
    let pbkdf2_hashes: [(&str, Pbkdf2); 5] = [
        ("sha1",   |p, s, c, l| pbkdf2(SHA1::new(&[]), p, s, c, l).unwrap()),
        ("sha224", |p, s, c, l| pbkdf2(sha2::SHA224::new(&[]), p, s, c, l).unwrap()),
        ("sha256", |p, s, c, l| pbkdf2(sha2::SHA256::new(&[]), p, s, c, l).unwrap()),
        ("sha384", |p, s, c, l| pbkdf2(sha2::SHA384::new(&[]), p, s, c, l).unwrap()),
        ("sha512", |p, s, c, l| pbkdf2(sha2::SHA512::new(&[], 512), p, s, c, l).unwrap()),
    ];

    // Output length, every value through two block boundaries. This is
    // the sweep that catches a wrong block counter, a wrong truncation
    // and an off-by-one in the final partial block.
    for (name, derive) in pbkdf2_hashes {
        for dklen in (1usize..=140).chain([200, 255, 256, 257, 1000]) {
            println!("pbkdf2/{}/16/13/3/{} {}", name, dklen,
                     to_hex(&derive(&key(16), &data(13), 3, dklen)).to_lowercase());
        }
    }

    // Password length, either side of both HMAC block sizes (64 and
    // 128), which is where the key is hashed rather than padded.
    for (name, derive) in pbkdf2_hashes {
        for pwlen in [0usize, 1, 16, 32, 63, 64, 65, 100, 127, 128, 129, 200] {
            println!("pbkdf2/{}/{}/13/2/32 {}", name, pwlen,
                     to_hex(&derive(&key(pwlen), &data(13), 2, 32)).to_lowercase());
        }
    }

    // Salt length, including empty - which is legal here and is not the
    // all-zero salt HKDF substitutes.
    for (name, derive) in pbkdf2_hashes {
        for saltlen in [0usize, 1, 8, 15, 16, 31, 32, 63, 64, 65, 100, 200] {
            println!("pbkdf2/{}/16/{}/2/32 {}", name, saltlen,
                     to_hex(&derive(&key(16), &data(saltlen), 2, 32)).to_lowercase());
        }
    }

    // Iteration count, every value up to 64 plus a few larger. Small
    // counts are where an off-by-one in the XOR loop shows: c=1 must be
    // one PRF call and no XOR at all, and c=2 must differ from it.
    for (name, derive) in pbkdf2_hashes {
        for c in (1u32..=64).chain([100, 1000, 4096]) {
            println!("pbkdf2/{}/16/13/{}/32 {}", name, c,
                     to_hex(&derive(&key(16), &data(13), c, 32)).to_lowercase());
        }
    }

    // scrypt (RFC 7914), against hashlib's - which is OpenSSL's.
    // Deliberately small parameters: N only controls how many times the
    // same two loops run, so a large N costs minutes and covers nothing
    // the small ones do not. What does need sweeping is `r`, because
    // BlockMix's interleave is the identity at r=1 and only shows up
    // above it.
    for (n, r, p) in [(16u64, 1u32, 1u32), (16, 2, 1), (16, 3, 1), (16, 8, 1),
                      (32, 1, 2), (64, 2, 2), (128, 4, 1), (256, 1, 1),
                      (512, 2, 3), (1024, 8, 1)] {
        for dklen in [1usize, 16, 31, 32, 33, 64, 100] {
            println!("scrypt/{}/{}/{}/{} {}", n, r, p, dklen,
                     to_hex(&scrypt(&key(13), &data(17), n, r, p, dklen).unwrap())
                         .to_lowercase());
        }
    }

    // Argon2id (RFC 9106), against python-cryptography's. Only the `id`
    // variant: nothing on this machine implements `d` or `i`, so those
    // two are pinned to the RFC's own published tags in
    // `src/kdf/argon2.rs` instead - which is the weaker form of
    // evidence and the only one available.
    for (memory, passes, lanes) in [(32u32, 1u32, 1u32), (32, 3, 4), (64, 2, 2),
                                    (128, 1, 4), (256, 3, 2), (512, 2, 1)] {
        for dklen in [4usize, 16, 32, 64, 100] {
            let argon = Argon2 {
                variant: Variant::Id, memory_kib: memory, passes, lanes,
                secret: Vec::new(), associated_data: Vec::new(),
            };
            println!("argon2id/{}/{}/{}/{} {}", memory, passes, lanes, dklen,
                     to_hex(&argon.derive(&key(13), &data(16), dklen).unwrap())
                         .to_lowercase());
        }
    }

    // CBC-MAC over DES, 3DES and AES, zero IV and a random-looking one,
    // at whole-block lengths, and with ISO 9797-1 padding method 1 at
    // every length. Checked against OpenSSL's CBC: the tag is its last
    // block, which is the definition.
    for (name, keylen, bs) in [("des", 8usize, 8usize), ("3des", 24, 8), ("aes", 16, 16),
                               ("aes", 32, 16)] {
        for zero_iv in [true, false] {
            let iv = if zero_iv { vec![0u8; bs] } else { data(bs + 3)[3..].to_vec() };
            let label = if zero_iv { "zero" } else { "iv" };
            for n in (1..=10).map(|b| b * bs) {
                let mut c = AnyBlockCipher::new(name, &key(keylen), None).unwrap();
                println!("cbcmac/{}/{}/{}/{} {}", name, keylen, label, n,
                         to_hex(&cbc_mac(&mut c, &iv, &data(n)).unwrap()).to_lowercase());
            }
            for n in 0..=40usize {
                let mut c = AnyBlockCipher::new(name, &key(keylen), None).unwrap();
                println!("cbcmaczero/{}/{}/{}/{} {}", name, keylen, label, n,
                         to_hex(&cbc_mac_zero_padded(&mut c, &iv, &data(n)).unwrap())
                             .to_lowercase());
            }
        }
    }

    // SP 800-108, both modes, over HMAC and CMAC: counter mode against
    // python-cryptography's KBKDF, feedback mode against OpenSSL's
    // (python-cryptography has counter mode only). Lengths cross the
    // PRF's output size; label and context lengths vary.
    let prfs = ["hmac-sha1", "hmac-sha256", "hmac-sha512", "cmac-aes"];
    for prf in prfs {
        for (kl, ll, cl) in [(16usize, 0usize, 0usize), (32, 5, 0), (16, 0, 7), (32, 12, 33)] {
            for len in [1usize, 16, 20, 31, 32, 33, 64, 65, 100] {
                let p = Prf::named(prf).unwrap();
                println!("kbkdfctr/{}/{}/{}/{}/{} {}", prf, kl, ll, cl, len,
                         to_hex(&kbkdf_counter(p, &key(kl), &data(ll), &data(cl + 50)[50..],
                                               len).unwrap()).to_lowercase());
                // The IV is empty or one PRF output long; OpenSSL refuses
                // any other length.
                let out_len = match prf { "hmac-sha1" => 20, "hmac-sha256" => 32,
                                          "hmac-sha512" => 64, _ => 16 };
                for iv_len in [0usize, out_len] {
                    println!("kbkdffb/{}/{}/{}/{}/{}/{} {}", prf, kl, ll, cl, iv_len, len,
                             to_hex(&kbkdf_feedback(p, &key(kl), &data(iv_len), &data(ll),
                                                    &data(cl + 50)[50..], len).unwrap())
                                 .to_lowercase());
                }
            }
        }
    }
    // SP 800-56C's one-step hash KDF and X9.63, against
    // python-cryptography's ConcatKDFHash and X963KDF.
    for hash in ["sha1", "sha256", "sha384", "sha512"] {
        for (zl, il) in [(16usize, 0usize), (32, 10), (66, 40)] {
            for len in [1usize, 20, 32, 33, 64, 65, 129] {
                println!("concat/{}/{}/{}/{} {}", hash, zl, il, len,
                         to_hex(&concat_kdf(hash, &key(zl), &data(il), len).unwrap())
                             .to_lowercase());
                println!("x963/{}/{}/{}/{} {}", hash, zl, il, len,
                         to_hex(&x963_kdf(hash, &key(zl), &data(il), len).unwrap())
                             .to_lowercase());
            }
        }
    }
    // OpenPGP's S2K: counts below one copy, around the 64 KiB buffer of
    // repetitions, and not a multiple of the unit; keys needing two and
    // three hash contexts.
    for hash in ["md5", "sha1", "sha256", "sha512"] {
        for (pl, sl) in [(0usize, 0usize), (8, 0), (8, 8), (37, 8)] {
            for count in [0usize, 1, 15, 16, 1024, 65535, 65536, 65537, 65536 + 45, 200_003] {
                for len in [16usize, 24, 32, 64, 100] {
                    let h = allcrypt::api::AnyHash::new(hash).unwrap();
                    println!("s2k/{}/{}/{}/{}/{} {}", hash, pl, sl, count, len,
                             to_hex(&openpgp_s2k(h, &key(pl), &data(sl), count, len))
                                 .to_lowercase());
                }
            }
        }
    }
    // 7-Zip's AES key, including its raw "0x3f" form, and KeePass's
    // AES-KDF.
    for (pl, sl) in [(0usize, 0usize), (2, 0), (16, 0), (10, 16), (40, 8)] {
        for cycles in [0u8, 1, 5, 10, 11, 12, 19, 0x3f] {
            println!("7zkey/{}/{}/{} {}", pl, sl, cycles,
                     to_hex(&sevenzip_aes_key(&key(pl), &data(sl), cycles).unwrap())
                         .to_lowercase());
        }
    }
    for rounds in [0u64, 1, 2, 3, 1000, 60_000] {
        println!("keepass/{} {}", rounds,
                 to_hex(&keepass_aes_kdf(&key(32), &data(32), rounds).unwrap()).to_lowercase());
    }
    // LUKS's AF splitter: merging arbitrary stripes, and the last stripe
    // of a split whose random stripes are `data`.
    for hash in ["sha1", "sha256", "sha512"] {
        for (kl, stripes) in [(16usize, 1usize), (16, 2), (32, 3), (33, 7), (64, 4000), (65, 50)] {
            let material = data(kl * stripes + 5);
            println!("afmerge/{}/{}/{} {}", hash, kl, stripes,
                     to_hex(&af_merge(&material, kl, stripes, hash).unwrap()).to_lowercase());
            let random = data(kl * (stripes - 1));
            let mut feed = |buf: &mut [u8]| { buf.copy_from_slice(&random); Ok(()) };
            let split = af_split(&key(kl), stripes, hash, &mut feed).unwrap();
            println!("afsplit/{}/{}/{} {}", hash, kl, stripes,
                     to_hex(&split[kl * (stripes - 1)..]).to_lowercase());
        }
    }
}
