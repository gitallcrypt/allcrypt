//! The dynamic facade in `api` must agree exactly with the statically typed
//! API it wraps. The Python bindings are a thin layer over this, so anything
//! verified here is verified for Python too.

use allcrypt::api::{AnyBlockCipher, AnyHash, AnyStreamCipher, CipherStream, Mode,
                    BLOCK_CIPHERS, HASHES, MODES, STREAM_CIPHERS};
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::gost::GostCrypto;
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::hash_functions::{sha2, HashFunction};
use allcrypt::stream_ciphers::{chacha::Chacha, StreamCipher};

fn data(n: usize) -> Vec<u8> { (0..n).map(|i| ((i*167+13) & 0xff) as u8).collect() }
fn key(n: usize) -> Vec<u8> { (0..n).map(|i| ((i*89+7) & 0xff) as u8).collect() }
fn iv(n: usize) -> Vec<u8> { (0..n).map(|i| ((i*211+5) & 0xff) as u8).collect() }

/// One-shot through the facade must equal one-shot through the trait.
#[test]
fn test_facade_matches_static_api() {
    for (name, keylen, bs) in [("aes", 16usize, 16usize), ("aes", 32, 16),
                               ("blowfish", 16, 8), ("gost", 32, 8)] {
        for mode_name in MODES {
            let mode = Mode::from_name(mode_name).unwrap();
            // ECB and CBC need whole blocks.
            let lens: Vec<usize> = if mode.is_stream_like() {
                vec![0, 1, 7, bs - 1, bs, bs + 1, 100, 257]
            } else if mode.cts_variant().is_some() {
                // Any length of at least one block.
                vec![bs, bs + 1, 2 * bs - 1, 2 * bs, 2 * bs + 1, 3 * bs + 5, bs * 16]
            } else {
                vec![0, bs, bs * 2, bs * 16]
            };

            for n in lens {
                let pt = data(n);
                let v = if mode.needs_iv() { iv(bs) } else { vec![] };

                let mut s = CipherStream::new(
                    AnyBlockCipher::new(name, &key(keylen), None).unwrap(),
                    mode, &v, false).unwrap();
                let mut got = s.update(&pt).unwrap();
                got.extend_from_slice(&s.finish().unwrap());

                let mut want = vec![];
                let mut c = AnyBlockCipher::new(name, &key(keylen), None).unwrap();
                match mode {
                    Mode::Ecb => c.ecb_encrypt(&pt, &mut want).unwrap(),
                    Mode::Cbc => c.cbc_encrypt(&pt, &mut want, v.clone()).unwrap(),
                    Mode::Pcbc => c.pcbc_encrypt(&pt, &mut want, v.clone()).unwrap(),
                    Mode::Cfb => c.cfb_encrypt(&pt, &mut want, v.clone()).unwrap(),
                    Mode::Ofb => c.ofb_encrypt(&pt, &mut want, v.clone()).unwrap(),
                    Mode::Ctr => c.ctr_encrypt(&pt, &mut want, &v).unwrap(),
                    Mode::CtrLe => c.ctr_le_encrypt(&pt, &mut want, &v).unwrap(),
                    Mode::CbcCs1 | Mode::CbcCs2 | Mode::CbcCs3 => c.cbc_cs_encrypt(
                        &pt, &mut want, &v, mode.cts_variant().unwrap()).unwrap(),
                }
                assert_eq!(got, want, "{} {} len {}", name, mode_name, n);

                // and back again
                let mut s = CipherStream::new(
                    AnyBlockCipher::new(name, &key(keylen), None).unwrap(),
                    mode, &v, true).unwrap();
                let mut back = s.update(&got).unwrap();
                back.extend_from_slice(&s.finish().unwrap());
                assert_eq!(back, pt, "{} {} roundtrip len {}", name, mode_name, n);
            }
        }
    }
}

/// GOST has its own counter. The facade forwards `ctr_init`/`ctr_next`, so it
/// must reproduce the published GOST CTR vector, not the generic counter.
#[test]
fn test_facade_preserves_gost_counter() {
    let k: Vec<u8> = vec![0xBE, 0x5E, 0xC2, 0x00, 0x6C, 0xFF, 0x9D, 0xCF,
                          0x52, 0x35, 0x49, 0x59, 0xF1, 0xFF, 0x0C, 0xBF,
                          0xE9, 0x50, 0x61, 0xB5, 0xA6, 0x48, 0xC1, 0x03,
                          0x87, 0x06, 0x9C, 0x25, 0x99, 0x7C, 0x06, 0x72];
    let expected = vec![0x3b, 0x23, 0x45, 0x15, 0xad, 0x4f, 0xa0, 0x40,
                        0x5d, 0x2f, 0x3c, 0xf1, 0x67, 0x76, 0x97];
    let mut s = CipherStream::new(
        AnyBlockCipher::new("gost", &k, None).unwrap(),
        Mode::Ctr, &[1, 2, 3, 4, 5, 6, 7, 8], false).unwrap();
    assert_eq!(s.update(&[0u8; 15]).unwrap(), expected);

    // Sanity: the generic counter would give something else entirely.
    let mut generic = vec![];
    GostCrypto::new(k, GostCrypto::DEFAULT_PARAM_SET.to_string()).unwrap()
        .ctr_encrypt(&[0u8; 15], &mut generic, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    assert_eq!(generic, expected);
}

/// Streaming through the facade in awkward pieces must equal one call.
#[test]
fn test_facade_streaming() {
    let pt = data(640);
    for mode_name in MODES {
        let mode = Mode::from_name(mode_name).unwrap();
        let v = if mode.needs_iv() { iv(16) } else { vec![] };

        let mut s = CipherStream::new(
            AnyBlockCipher::new("aes", &key(16), None).unwrap(), mode, &v, false).unwrap();
        let mut one = s.update(&pt).unwrap();
        one.extend_from_slice(&s.finish().unwrap());

        for first in [1usize, 3, 7, 15, 16, 17, 33, 64, 100] {
            let mut s = CipherStream::new(
                AnyBlockCipher::new("aes", &key(16), None).unwrap(), mode, &v, false).unwrap();
            let mut streamed = vec![];
            let (mut i, mut step) = (0usize, first);
            while i < pt.len() {
                let e = std::cmp::min(pt.len(), i + step);
                streamed.extend_from_slice(&s.update(&pt[i..e]).unwrap());
                i = e;
                step = step * 2 + 1;
            }
            streamed.extend_from_slice(&s.finish().unwrap());
            assert_eq!(streamed, one, "{} streaming from {}", mode_name, first);
        }
    }
}

/// In-place update must agree with the appending one, and be refused by the
/// modes that cannot do it.
#[test]
fn test_facade_update_into() {
    let pt = data(300);
    let v = iv(16);

    for mode_name in ["cfb", "ofb", "ctr"] {
        let mode = Mode::from_name(mode_name).unwrap();
        let mut s = CipherStream::new(
            AnyBlockCipher::new("aes", &key(16), None).unwrap(), mode, &v, false).unwrap();
        let appended = s.update(&pt).unwrap();

        let mut s = CipherStream::new(
            AnyBlockCipher::new("aes", &key(16), None).unwrap(), mode, &v, false).unwrap();
        let mut buf = pt.clone();
        s.update_into(&mut buf).unwrap();
        assert_eq!(buf, appended, "{} in place", mode_name);
    }

    for mode_name in ["ecb", "cbc"] {
        let mode = Mode::from_name(mode_name).unwrap();
        let v = if mode.needs_iv() { iv(16) } else { vec![] };
        let mut s = CipherStream::new(
            AnyBlockCipher::new("aes", &key(16), None).unwrap(), mode, &v, false).unwrap();
        let mut buf = pt.clone();
        assert!(s.update_into(&mut buf).is_err(), "{} should refuse in place", mode_name);
    }
}

/// The nonce each stream cipher takes, since they do not agree.
///
/// RC4 has none, Salsa20 wants exactly 8 bytes and ChaCha 12. Written
/// as a function rather than as `if name == "rc4"` so that adding a
/// cipher with a different nonce fails here loudly rather than being
/// silently given the wrong length.
fn stream_nonce(name: &str) -> Vec<u8> {
    match name {
        "rc4" | "zipcrypto" => vec![],
        "salsa20" | "salsa12" | "salsa8" => iv(8),
        "xchacha20" | "xsalsa20" => iv(24),
        _ => iv(12),
    }
}

#[test]
fn test_facade_rejects_bad_input() {
    // Unknown names.
    assert!(AnyBlockCipher::new("rot13", &key(16), None).is_err());
    assert!(AnyStreamCipher::new("rot13stream", &key(32), &iv(8)).is_err());
    assert!(AnyHash::new("md6").is_err());
    assert!(Mode::from_name("gcm").is_err());

    // Blowfish used to divide by zero on an empty key.
    assert!(AnyBlockCipher::new("blowfish", &[], None).is_err());
    assert!(AnyBlockCipher::new("blowfish", &[0u8; 57], None).is_err());

    // IV presence is checked against the mode.
    let c = || AnyBlockCipher::new("aes", &key(16), None).unwrap();
    assert!(CipherStream::new(c(), Mode::Ecb, &iv(16), false).is_err(), "ECB takes no IV");
    assert!(CipherStream::new(c(), Mode::Cbc, &[], false).is_err(), "CBC needs an IV");
    assert!(CipherStream::new(c(), Mode::Cbc, &iv(8), false).is_err(), "wrong IV length");

    // A ragged tail is reported at finish, not silently dropped.
    let mut s = CipherStream::new(c(), Mode::Cbc, &iv(16), false).unwrap();
    let out = s.update(&data(20)).unwrap();
    assert_eq!(out.len(), 16);
    assert!(s.finish().is_err());

    // Using a stream after finishing is an error, not undefined behaviour.
    let mut s = CipherStream::new(c(), Mode::Ctr, &iv(16), false).unwrap();
    s.update(&data(10)).unwrap();
    s.finish().unwrap();
    assert!(s.update(&data(10)).is_err());
    assert!(s.finish().is_err());
}

#[test]
fn test_hash_facade() {
    for name in HASHES {
        let mut h = AnyHash::new(name).unwrap();
        let mut direct = AnyHash::new(name).unwrap();

        // Streaming equals one shot.
        h.update(&data(100));
        h.update(&data(57));
        let mut combined = data(100);
        combined.extend_from_slice(&data(57));
        direct.update(&combined);
        assert_eq!(h.digest(), direct.digest(), "{} streaming", name);

        // A digest leaves the hash as it was: a second one is the same,
        // and an update afterwards continues the message, as hashlib's
        // `digest()` does. GOST R 34.11-94 finalised its state in place,
        // so both were wrong for it alone. Every test here digested once;
        // the C interface's test, which digests and then carries on, was
        // the first to do otherwise.
        let first = h.digest();
        assert_eq!(h.digest(), first, "{} digest twice", name);
        h.update(&data(9));
        combined.extend_from_slice(&data(9));
        let mut longer = AnyHash::new(name).unwrap();
        longer.update(&combined);
        assert_eq!(h.digest(), longer.digest(), "{} update after digest", name);

        assert_eq!(h.digest().len(), h.digest_len(), "{} digest_len", name);
        // Most Merkle-Damgard hashes have a 64 or 128 byte compression
        // block; a sponge has no such thing and reports its *rate*,
        // which is 200 minus the capacity; and **MD2's block is
        // sixteen bytes**, which is what moved this from a floor of 64
        // to the property that floor was standing in for.
        //
        // What HMAC actually needs is `B >= L` - a key longer than the
        // block is replaced by its own digest, and that digest then has
        // to fit in a block. Asserting the number HMAC needs says why
        // it is here; asserting 64 said only that nothing small had
        // been added yet. The ceiling is MD6's, whose leaves are
        // 512-byte blocks; it was 200, a sponge's widest rate, until a
        // hash with a larger block arrived.
        assert!(h.block_size() >= h.digest_len() && h.block_size() <= 512,
                "{} reports a block size of {} for a digest of {}",
                name, h.block_size(), h.digest_len());

        // Uppercase and dashes resolve to the same thing.
        assert!(AnyHash::new(&name.to_uppercase()).is_ok());
    }

    // copy() forks the state: the clone must not see later updates.
    let mut h = AnyHash::new("sha256").unwrap();
    h.update(b"hello ");
    let mut forked = h.clone();
    h.update(b"world");
    forked.update(b"there");

    let mut a = AnyHash::new("sha256").unwrap();
    a.update(b"hello world");
    let mut b = AnyHash::new("sha256").unwrap();
    b.update(b"hello there");
    assert_eq!(h.digest(), a.digest());
    assert_eq!(forked.digest(), b.digest());

    // The facade must agree with the concrete type, truncation included.
    let mut viaapi = AnyHash::new("sha512_256").unwrap();
    viaapi.update(&data(200));
    let mut direct = sha2::SHA512::new(&data(200), 256);
    assert_eq!(viaapi.digest(), direct.digest());
}

#[test]
fn test_stream_cipher_facade() {
    for name in STREAM_CIPHERS {
        let nonce = stream_nonce(name);
        let mut c = AnyStreamCipher::new(name, &key(32), &nonce).unwrap();
        let pt = data(500);

        // Streamed in pieces equals one call.
        let mut streamed = vec![];
        let (mut i, mut step) = (0usize, 1usize);
        while i < pt.len() {
            let e = std::cmp::min(pt.len(), i + step);
            streamed.extend_from_slice(&c.encrypt(&pt[i..e]));
            i = e;
            step = step * 2 + 1;
        }
        let mut c2 = AnyStreamCipher::new(name, &key(32), &nonce).unwrap();
        assert_eq!(streamed, c2.encrypt(&pt), "{} streaming", name);

        // Round trip.
        let mut c3 = AnyStreamCipher::new(name, &key(32), &nonce).unwrap();
        assert_eq!(c3.decrypt(&streamed), pt, "{} roundtrip", name);

        // `update` is the keystream, for the ciphers that have one, and
        // refused for the one that does not.
        let mut c4 = AnyStreamCipher::new(name, &key(32), &nonce).unwrap();
        if c4.is_keystream() {
            assert_eq!(c4.update(&pt).unwrap(), streamed, "{} update", name);
        } else {
            assert!(c4.update(&pt).unwrap_err().contains("encrypt or decrypt"), "{}", name);
        }
    }
    let keystreamless: Vec<&&str> = STREAM_CIPHERS.iter()
        .filter(|n| !AnyStreamCipher::new(n, &key(32), &stream_nonce(n)).unwrap().is_keystream())
        .collect();
    assert_eq!(keystreamless, [&"zipcrypto"]);

    // Matches the concrete type.
    let mut viaapi = AnyStreamCipher::new("chacha12", &key(32), &iv(12)).unwrap();
    let mut direct = Chacha::new(key(32), iv(12), 12).unwrap();
    let mut want = vec![];
    direct.crypt(&data(300), &mut want);
    assert_eq!(viaapi.update(&data(300)).unwrap(), want);
    let mut viaapi = AnyStreamCipher::new("zipcrypto", b"pw", &[]).unwrap();
    let mut direct = allcrypt::stream_ciphers::zipcrypto::ZipCrypto::new(b"pw");
    let mut want = vec![];
    direct.encrypt(&data(300), &mut want);
    assert_eq!(viaapi.encrypt(&data(300)), want);
    // Any password, the empty one included, and no nonce.
    assert!(AnyStreamCipher::new("zipcrypto", b"", &[]).is_ok());
    assert!(AnyStreamCipher::new("zipcrypto", b"pw", &iv(12)).is_err());
}

/// The catalogue constants must actually resolve, so Python can list them.
#[test]
fn test_catalogue_is_accurate() {
    // **Every key length, and at least one must work.** This was a
    // table of which cipher takes which key size, and it was wrong
    // three times: when DES arrived, when IDEA, SEED, SM4 and CAST5
    // did, and when TEA and XTEA did. A table beside the catalogue is a
    // second copy of the catalogue and will disagree with it - the same
    // reasoning as the AEAD loop in `pytests/test_name_enums.py`.
    //
    // It is not only a maintenance point. The table always handed GOST
    // the one length that works, so `GostCrypto::new` **panicking** on
    // every other length went unnoticed until this loop replaced it.
    for name in BLOCK_CIPHERS {
        let usable: Vec<usize> = [5usize, 8, 16, 24, 32, 56].into_iter()
            .filter(|&n| AnyBlockCipher::new(name, &key(n), None).is_ok())
            .collect();
        assert!(!usable.is_empty(), "{} constructs at no key length", name);
    }

    // And a wrong length is an `Err`, never a panic. A panic unwinds
    // through a function that returns `Result` and reaches the Python
    // bindings as a `PanicException`, which `except ValueError` does
    // not catch - so it is a crash where the caller asked a question.
    for name in BLOCK_CIPHERS {
        for length in [0usize, 1, 5, 7, 9, 15, 17, 23, 31, 33, 100] {
            let attempt = std::panic::catch_unwind(|| {
                AnyBlockCipher::new(name, &key(length), None).is_ok()
            });
            assert!(attempt.is_ok(),
                    "{} panicked on a {} byte key instead of returning an \
                     error", name, length);
        }
    }

    for name in HASHES {
        assert!(AnyHash::new(name).is_ok(), "{} should construct", name);
    }
    for name in STREAM_CIPHERS {
        let nonce = stream_nonce(name);
        assert!(AnyStreamCipher::new(name, &key(32), &nonce).is_ok(), "{} should construct", name);
    }
    for name in MODES {
        assert!(Mode::from_name(name).is_ok(), "{} should resolve", name);
    }
    // And the AES facade really is AES.
    let mut want = vec![];
    AesCrypto::new(key(16)).unwrap().ecb_encrypt(&data(32), &mut want).unwrap();
    let mut s = CipherStream::new(AnyBlockCipher::new("aes", &key(16), None).unwrap(),
                                  Mode::Ecb, &[], false).unwrap();
    assert_eq!(s.update(&data(32)).unwrap(), want);
}

/// The free padding functions must agree with the in-place trait methods.
#[test]
fn test_padding_helpers_match_trait() {
    use allcrypt::api::{pad_pkcs7, unpad_pkcs7};
    for bs in [8usize, 16] {
        for n in 0..(3*bs) {
            let original = data(n);
            let got = pad_pkcs7(&original, bs).unwrap();

            let mut viatrait = original.clone();
            let mut c = AnyBlockCipher::new(if bs == 16 { "aes" } else { "blowfish" },
                                            &key(16), None).unwrap();
            c.pad_pkcs7(&mut viatrait);
            assert_eq!(got, viatrait, "pad block size {} len {}", bs, n);

            assert_eq!(unpad_pkcs7(&got, bs).unwrap(), original, "unpad {} {}", bs, n);
        }
    }
    assert!(unpad_pkcs7(&[], 16).is_err());
    assert!(unpad_pkcs7(&[0u8; 16], 16).is_err());
    assert!(unpad_pkcs7(&[17u8; 16], 16).is_err());
    assert!(pad_pkcs7(&[1, 2, 3], 0).is_err());
    assert!(pad_pkcs7(&[1, 2, 3], 256).is_err());
}

/// The EC facade must produce the same key material as the typed API, and
/// two facade keys must agree on a shared secret. The curve arithmetic
/// itself is checked against OpenSSL in `tools/src/bin/diff_ec.rs`; this is only
/// about the facade not scrambling anything on the way through.
#[test]
fn test_ec_facade() {
    use allcrypt::api::{EcKey, CURVES};
    use allcrypt::ec::curves;
    use allcrypt::bignum::BigUint;

    for name in CURVES {
        let curve = curves::by_name(name).unwrap();

        // A known scalar through the facade must match the typed API.
        let d = BigUint::from_hex("c0ffee1234567890abcdef").unwrap();
        let scalar = d.to_bytes_be_padded(curve.field_bytes()).unwrap();
        let key = EcKey::from_private(name, &scalar).unwrap();
        assert_eq!(key.curve_name(), *name);
        assert_eq!(key.key_size(), curve.p.bit_len());
        assert_eq!(key.private_bytes().unwrap(), scalar);

        let want = curve.scalar_mul(&curve.g, &d);
        assert_eq!(key.public_bytes(false).unwrap(),
                   curve.encode_point(&want, false).unwrap());
        assert_eq!(key.public_bytes(true).unwrap(),
                   curve.encode_point(&want, true).unwrap());

        // Two generated keys must agree, in both compression forms -
        // except on a curve whose p is 1 mod 4, where a compressed point
        // cannot be decompressed with the square root we have. That is a
        // property of the curve rather than of the caller, so it is asked
        // rather than assumed.
        let a = EcKey::generate(name).unwrap();
        let b = EcKey::generate(name).unwrap();
        let ab = a.exchange(&b.public_bytes(false).unwrap()).unwrap();
        let other = a.public_bytes(curve.supports_compression()).unwrap();
        let ba = b.exchange(&other).unwrap();
        assert_eq!(ab, ba, "{} ECDH disagreed", name);
        assert_eq!(ab.len(), curve.field_bytes());
        assert_ne!(a.private_bytes().unwrap(), b.private_bytes().unwrap());

        // Scalars outside [1, n) are not keys.
        assert!(EcKey::from_private(name, &[]).is_err(), "zero scalar accepted");
        assert!(EcKey::from_private(name, &curve.n.to_bytes_be_padded(
                    curve.field_bytes()).unwrap()).is_err(), "n accepted as scalar");

        // A point that is not on the curve must be refused rather than used.
        let mut bad = a.public_bytes(false).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(b.exchange(&bad).is_err(), "{} accepted an off-curve peer", name);
    }

    // P-521 was the unknown curve here until it arrived.
    assert!(EcKey::generate("brainpoolP256r1").is_err(), "unknown curve accepted");
}

/// The AEAD facade, which is the surface the Python bindings translate.
///
/// `python.rs` holds no cryptographic logic, so everything it exposes has
/// to be reachable and covered from here.
#[test]
fn test_aead_through_the_api() {
    use allcrypt::api::{aead_decrypt, aead_encrypt, AeadStream, AEADS};

    // **A deliberate pin, and a second copy of the catalogue on
    // purpose.** It exists to make a silent *removal* impossible -
    // dropping an AEAD from the list is otherwise invisible, and the
    // whole premise of this library is that nothing gets deprecated.
    // The cost is that adding one means editing this line, which is the
    // intended cost; the combinations below must gain a row in the same
    // commit, and `test_every_aead_in_the_catalogue_is_exercised_here`
    // fails if they do not.
    assert_eq!(AEADS, &["aes-gcm", "aes-ccm", "aes-ccm-8", "chacha20-poly1305",
                        "xchacha20-poly1305", "aes-eax", "twofish-eax", "serpent-eax", "camellia-eax",
                        "sm4-eax", "des-eax", "3des-eax", "blowfish-eax",
                        "tea-eax", "xtea-eax", "rc5-eax", "aria-eax",
                        "kuznyechik-mgm", "magma-mgm", "aes-mgm",
                        "twofish-mgm", "serpent-mgm", "camellia-mgm",
                        "sm4-mgm", "aria-mgm", "des-mgm", "3des-mgm",
                        "blowfish-mgm", "tea-mgm", "xtea-mgm", "rc5-mgm",
                        "aes-ocb", "camellia-ocb", "twofish-ocb", "serpent-ocb",
                        "aria-ocb", "sm4-ocb", "seed-ocb", "kuznyechik-ocb",
                        "aes-128-cbc-hmac-sha256", "aes-192-cbc-hmac-sha384",
                        "aes-256-cbc-hmac-sha512"]);

    // Every AEAD, over every key length it takes. ChaCha20-Poly1305 has
    // exactly one; AES has three.
    let combinations: Vec<(&str, usize)> = vec![
        ("aes-gcm", 16), ("aes-gcm", 24), ("aes-gcm", 32),
        ("aes-ccm", 16), ("aes-ccm", 24), ("aes-ccm", 32),
        ("aes-ccm-8", 16), ("aes-ccm-8", 32),
        ("chacha20-poly1305", 32), ("xchacha20-poly1305", 32),
        // EAX, over a cipher of each block size the catalogue offers -
        // 128 bit and 64 bit - because EAX's OMAC tweak is a whole
        // block and a 64 bit one is where an implementation that
        // hard-coded 16 falls over.
        ("aes-eax", 16), ("aes-eax", 32),
        ("twofish-eax", 32), ("serpent-eax", 32),
        ("camellia-eax", 16), ("sm4-eax", 16),
        ("des-eax", 8), ("3des-eax", 24), ("blowfish-eax", 16),
        ("tea-eax", 16), ("xtea-eax", 16), ("rc5-eax", 16),
        ("aria-eax", 16), ("aria-eax", 32),
        // MGM, the same way: the standard's own two ciphers first, then
        // one of each block size from the rest. MGM's field polynomial
        // differs between a 64 and a 128 bit block, so the two sizes
        // are two different modes sharing a name.
        ("kuznyechik-mgm", 32), ("magma-mgm", 32),
        ("aes-mgm", 16), ("aes-mgm", 32),
        ("twofish-mgm", 32), ("serpent-mgm", 32),
        ("camellia-mgm", 16), ("sm4-mgm", 16), ("aria-mgm", 32),
        ("des-mgm", 8), ("3des-mgm", 24), ("blowfish-mgm", 16),
        ("tea-mgm", 16), ("xtea-mgm", 16), ("rc5-mgm", 16),
        // OCB, 128 bit blocks only.
        ("aes-ocb", 16), ("aes-ocb", 24), ("aes-ocb", 32),
        ("camellia-ocb", 16), ("twofish-ocb", 32), ("serpent-ocb", 32),
        ("aria-ocb", 16), ("sm4-ocb", 16), ("seed-ocb", 16),
        ("kuznyechik-ocb", 32),
        // AES-CBC with HMAC: one key size each, the MAC key and the AES
        // key together.
        ("aes-128-cbc-hmac-sha256", 32), ("aes-192-cbc-hmac-sha384", 48),
        ("aes-256-cbc-hmac-sha512", 64),
    ];

    // The list above must cover the catalogue. Without this, adding an
    // AEAD and updating only the equality assertion leaves it untested
    // while every test still passes.
    let covered: Vec<&str> = combinations.iter().map(|(name, _)| *name).collect();
    for name in AEADS {
        assert!(covered.contains(name),
                "{} is in the catalogue but not exercised below", name);
    }

    for (aead, key_len) in combinations {
        let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(7)).collect();
        // **The nonce is not one size.** GCM, CCM and ChaCha20-Poly1305
        // take twelve bytes; EAX takes any length; MGM's is exactly one
        // block, with the top bit clear, because that bit separates its
        // two counter chains. Built here rather than listed, so a new
        // AEAD with its own rule is a compile-time decision.
        let nonce: Vec<u8> = if let Some(cipher) = aead.strip_suffix("-mgm") {
            use allcrypt::api::AnyBlockCipher;
            let block = AnyBlockCipher::new(cipher, &key, None).unwrap().blocksize();
            let mut value = vec![0x2bu8; block];
            value[0] &= 0x7f;
            value
        } else if aead.starts_with("xchacha") {
            vec![0x2bu8; 24]
        } else if aead.contains("-cbc-hmac-") {
            vec![0x2bu8; 16]
        } else {
            vec![0x2bu8; 12]
        };
        let other_nonce: Vec<u8> = {
            let mut value = nonce.clone();
            let last = value.len() - 1;
            value[last] ^= 1;
            value
        };
        let aad = b"associated";
        let message = b"the payload, of an awkward length";

        let (ciphertext, tag) =
            aead_encrypt(aead, &key, &nonce, aad, message).unwrap();
        // CBC-HMAC pads to whole blocks; everything else is as long as
        // the message.
        let expected_len = if aead.contains("-cbc-hmac-") {
            (message.len() / 16 + 1) * 16
        } else {
            message.len()
        };
        assert_eq!(ciphertext.len(), expected_len, "{}", aead);
        // 16 everywhere except the CCM_8 suites, whose whole reason for
        // existing is the shorter tag - and **EAX over a 64 bit block
        // cipher, whose tag is one block and so is 8**. That is not a
        // truncation: EAX's tag is the block size, so DES-EAX and
        // 3DES-EAX have half the forgery resistance of the rest, which
        // is a property of the cipher rather than a choice.
        // Asked of the cipher rather than listed by name, because the
        // list would be a second place to record which ciphers are 64
        // bit - and it would be wrong the first time one was added.
        let expected_tag = if aead.ends_with("-8") {
            8
        } else if let Some(cipher) = aead.strip_suffix("-eax")
                                        .or_else(|| aead.strip_suffix("-mgm")) {
            use allcrypt::api::AnyBlockCipher;
            AnyBlockCipher::new(cipher, &key, None).unwrap().blocksize()
        } else if aead.contains("-cbc-hmac-") {
            // Half the key: the MAC key's length.
            key_len / 2
        } else {
            16
        };
        assert_eq!(tag.len(), expected_tag, "{}", aead);

        let back = aead_decrypt(aead, &key, &nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(back, message, "{}", aead);

        // Every input is authenticated, so changing any of them fails.
        let mut altered = ciphertext.clone();
        altered[0] ^= 1;
        assert!(aead_decrypt(aead, &key, &nonce, aad, &altered, &tag).is_err());

        let mut wrong_tag = tag.clone();
        wrong_tag[expected_tag - 1] ^= 1;
        assert!(aead_decrypt(aead, &key, &nonce, aad, &ciphertext, &wrong_tag).is_err());
        assert!(aead_decrypt(aead, &key, &nonce, b"other", &ciphertext, &tag).is_err());
        assert!(aead_decrypt(aead, &key, &other_nonce, aad, &ciphertext, &tag).is_err());

        // Feeding it in pieces must equal the one-shot, in both
        // directions. `finish` and `open` rather than `tag` and `verify`,
        // because CCM cannot produce anything until it has everything -
        // its MAC begins with the message's length - and the two
        // interfaces have to cope with both shapes.
        let mut stream = AeadStream::new(aead, &key, &nonce, aad, false).unwrap();
        let mut streamed = Vec::new();
        for piece in message.chunks(7) {
            stream.update(piece, &mut streamed).unwrap();
        }
        let buffers = stream.buffers_everything();
        // CCM buffers because it *cannot* stream - its MAC begins with
        // the message's length. EAX buffers because this implementation
        // is one-shot, though the mode is online in both passes; that
        // is a property of the code rather than of the mode, and
        // `buffers_everything` is what says so honestly either way.
        let expected_to_buffer = aead.starts_with("aes-ccm")
            || aead.ends_with("-eax") || aead.ends_with("-mgm") || aead.ends_with("-ocb")
            || aead.contains("-cbc-hmac-");
        assert_eq!(buffers, expected_to_buffer,
                   "{} disagrees about whether it buffers", aead);
        if buffers {
            assert!(streamed.is_empty(),
                    "{} produced output before it had the whole message", aead);
        } else {
            assert_eq!(streamed, ciphertext, "{} streamed", aead);
        }
        assert_eq!(stream.finish(&mut streamed).unwrap(), tag);
        assert_eq!(streamed, ciphertext, "{} finished", aead);

        let mut stream = AeadStream::new(aead, &key, &nonce, aad, true).unwrap();
        let mut opened = Vec::new();
        for piece in ciphertext.chunks(5) {
            stream.update(piece, &mut opened).unwrap();
        }
        stream.open(&tag, &mut opened).unwrap();
        assert_eq!(opened, message, "{} streamed back", aead);

        // And a bad tag releases nothing at all.
        let mut stream = AeadStream::new(aead, &key, &nonce, aad, true).unwrap();
        let mut nothing = Vec::new();
        stream.update(&ciphertext, &mut nothing).unwrap();
        assert!(stream.open(&wrong_tag, &mut nothing).is_err());
        if buffers {
            assert!(nothing.is_empty(),
                    "{} released plaintext with a bad tag", aead);
        }
    }

    // The two must not be the same function. If the dispatch ever
    // collapsed onto one implementation, every assertion above would
    // still pass.
    let (gcm, _) = aead_encrypt("aes-gcm", &[9u8; 32], &[1u8; 12], b"a", b"m").unwrap();
    let (ccm, _) = aead_encrypt("aes-ccm", &[9u8; 32], &[1u8; 12], b"a", b"m").unwrap();
    let (chacha, _) =
        aead_encrypt("chacha20-poly1305", &[9u8; 32], &[1u8; 12], b"a", b"m").unwrap();
    assert_ne!(gcm, chacha);
    assert_ne!(gcm, ccm);
    assert_ne!(ccm, chacha);

    // And each takes only the key sizes it has.
    assert!(AeadStream::new("chacha20-poly1305", &[0; 16], &[0; 12], &[], false)
                .is_err(), "ChaCha20-Poly1305 accepted a 128 bit key");
    assert!(AeadStream::new("chacha20-poly1305", &[0; 32], &[0; 8], &[], false)
                .is_err(), "ChaCha20-Poly1305 accepted an 8 byte nonce");

    // The two halves are not interchangeable: an encryption has no tag to
    // verify against, and a decryption has no tag to hand out.
    let mut encrypting = AeadStream::new("aes-gcm", &[0; 16], &[0; 12], &[], false).unwrap();
    assert!(encrypting.verify(&[0; 16]).is_err());
    let mut decrypting = AeadStream::new("aes-gcm", &[0; 16], &[0; 12], &[], true).unwrap();
    assert!(decrypting.tag().is_err());

    // **The stand-in for "not an AEAD" must be one that cannot become
    // one.** This assertion has now been wrong twice: it named
    // `aes-ccm`, which stopped being true the day CCM landed, and then
    // `aes-eax`, which stopped being true the day EAX did - and the
    // second time the comment above it was already a warning about the
    // first. So it is a name that is not an algorithm at all, plus a
    // plausible-looking one built on a cipher that does not exist.
    assert!(AeadStream::new("not-an-aead", &[0; 16], &[0; 12], &[], false).is_err());
    assert!(AeadStream::new("nonesuch-eax", &[0; 16], &[0; 12], &[], false).is_err());
    // And the error names the catalogue, so a caller who guessed can see
    // what there is.
    let error = match AeadStream::new("not-an-aead", &[0; 16], &[0; 12], &[], false) {
        Err(reason) => reason,
        Ok(_) => panic!("not-an-aead was accepted"),
    };
    assert!(error.contains("aes-gcm"), "{}", error);
    // And the two halves of CCM's interface refuse the other's call,
    // rather than quietly losing the ciphertext or releasing it unchecked.
    let mut ccm = AeadStream::new("aes-ccm", &[0; 16], &[0; 12], &[], false).unwrap();
    assert!(ccm.tag().is_err(), "CCM handed out a tag without its ciphertext");
    let mut ccm = AeadStream::new("aes-ccm", &[0; 16], &[0; 12], &[], true).unwrap();
    assert!(ccm.verify(&[0; 16]).is_err(),
            "CCM verified without handing back the plaintext it was verifying");
    assert!(AeadStream::new("aes-gcm", &[0; 17], &[0; 12], &[], false).is_err(),
            "a key length AES does not have was accepted");
}

// ------------------------------------------------------- suite listings ---

/// `tls_suite_names` must report what a client with the same string
/// would actually offer.
///
/// The two used to be separate matches on the same strings, and two
/// copies of a match drift - invisibly, because the report would then
/// be right about a selection nobody used. They are one function now,
/// and this pins the strings it answers to.
#[test]
fn test_the_selection_names_are_the_ones_a_client_takes() {
    for selection in ["modern", "default", "legacy", "all", "everything",
                      "MODERN", "Legacy"] {
        let names = allcrypt::api::tls_suite_names(selection)
            .unwrap_or_else(|e| panic!("{}: {}", selection, e));
        assert!(!names.is_empty(), "{} offers nothing", selection);
    }

    // The aliases are aliases, not near misses.
    assert_eq!(allcrypt::api::tls_suite_names("modern").unwrap(),
               allcrypt::api::tls_suite_names("default").unwrap());
    assert_eq!(allcrypt::api::tls_suite_names("all").unwrap(),
               allcrypt::api::tls_suite_names("everything").unwrap());

    // And the sets nest the way the documentation says.
    let modern = allcrypt::api::tls_suite_names("modern").unwrap();
    let legacy = allcrypt::api::tls_suite_names("legacy").unwrap();
    let all = allcrypt::api::tls_suite_names("all").unwrap();
    assert!(modern.len() < legacy.len());
    assert!(legacy.len() < all.len());
    for name in &modern {
        assert!(legacy.contains(name), "{} is in modern but not legacy", name);
    }
    for name in &legacy {
        assert!(all.contains(name), "{} is in legacy but not all", name);
    }
}

/// A named list gives exactly those suites in that order, and an
/// unknown name is an error rather than an empty list.
#[test]
fn test_a_named_suite_list_is_exact() {
    let names = allcrypt::api::tls_suite_names("AES128-SHA, RC4-SHA").unwrap();
    assert_eq!(names, vec!["TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
                           "TLS_RSA_WITH_RC4_128_SHA".to_string()]);

    // Empty would read as "this selection offers nothing", and a typo
    // would read as neither.
    assert!(allcrypt::api::tls_suite_names("NOT-A-SUITE").is_err());
    assert!(allcrypt::api::tls_suite_names("AES128-SHA,NOT-A-SUITE").is_err());
}

/// Every name a selection reports must be in the registry, and the
/// registry must be strictly wider - it is the catalogue of what TLS
/// has, not of what this library has.
#[test]
fn test_every_offered_suite_is_in_the_registry() {
    let known = allcrypt::api::tls_suites_known();
    let all = allcrypt::api::tls_suite_names("all").unwrap();
    for name in &all {
        assert!(known.contains(name), "{} is offered but not in the registry",
                name);
    }
    assert!(known.len() > all.len(),
            "the registry must hold suites no selection offers");
}

// ------------------------------------------------- the certificate authority ---

/// A CA issues a leaf that verifies against it, for the name asked for.
///
/// The chain is checked by `verify_chain`, not by reading the fields
/// back: an issuer that writes its own name into a leaf and an issuer
/// that actually signed it look identical field by field.
#[test]
fn test_an_issued_leaf_verifies_against_its_own_ca() {
    let ca = allcrypt::api::CertificateAuthority::generate(
        "allcrypt test CA", "20240101000000Z", "20340101000000Z").unwrap();
    let (leaf, _key) = ca.issue("old-box.test", "20240101000000Z",
                                "20250101000000Z").unwrap();

    let roots = vec![ca.certificate().to_vec()];
    let options = allcrypt::api::VerifyOptions {
        now: 1_720_000_000,
        hostname: Some("old-box.test".to_string()),
        ..Default::default()
    };
    let verdict = allcrypt::api::verify_chain(std::slice::from_ref(&leaf), &roots, &options);
    assert!(verdict.is_ok(), "{:?}", verdict);

    // And the name is actually checked, so the success above is about
    // this leaf rather than about verification being off.
    let wrong = allcrypt::api::verify_chain(&[leaf], &roots,
        &allcrypt::api::VerifyOptions {
            now: 1_720_000_000,
            hostname: Some("other.test".to_string()),
            ..Default::default()
        });
    assert!(wrong.is_err(), "any hostname was accepted");
}

/// A leaf issued by one CA does not verify against another.
///
/// The obvious way to get `issue` wrong is to self-sign the leaf: it
/// then has the right names, the right extensions and a valid
/// signature, and verifies against nothing.
#[test]
fn test_a_leaf_does_not_verify_against_a_different_ca() {
    let ca = allcrypt::api::CertificateAuthority::generate(
        "CA one", "20240101000000Z", "20340101000000Z").unwrap();
    let other = allcrypt::api::CertificateAuthority::generate(
        "CA two", "20240101000000Z", "20340101000000Z").unwrap();
    let (leaf, _key) = ca.issue("host.test", "20240101000000Z",
                                "20250101000000Z").unwrap();

    let roots = vec![other.certificate().to_vec()];
    let options = allcrypt::api::VerifyOptions {
        now: 1_720_000_000,
        hostname: Some("host.test".to_string()),
        ..Default::default() };
    assert!(allcrypt::api::verify_chain(&[leaf], &roots, &options).is_err());
}

/// An IP address goes into an iPAddress SAN, not a dNSName.
///
/// The two are not interchangeable: a verifier asked about an address
/// looks only at the address entries, so an address written as a name
/// produces a certificate that matches nothing and explains nothing.
#[test]
fn test_an_address_is_issued_as_an_address() {
    let ca = allcrypt::api::CertificateAuthority::generate(
        "allcrypt test CA", "20240101000000Z", "20340101000000Z").unwrap();
    let roots = vec![ca.certificate().to_vec()];

    for host in ["192.0.2.1", "2001:db8::1"] {
        let (leaf, _key) = ca.issue(host, "20240101000000Z",
                                    "20250101000000Z").unwrap();
        let options = allcrypt::api::VerifyOptions {
            now: 1_720_000_000,
            hostname: Some(host.to_string()),
            ..Default::default() };
        let verdict = allcrypt::api::verify_chain(&[leaf], &roots, &options);
        assert!(verdict.is_ok(), "{}: {:?}", host, verdict);
    }
}

/// Two issuances never share a serial or a key.
///
/// A repeated serial from one issuer is what a browser caches and then
/// refuses, and a shared key means one compromise is every site the
/// proxy ever served.
#[test]
fn test_every_issuance_is_fresh() {
    let ca = allcrypt::api::CertificateAuthority::generate(
        "allcrypt test CA", "20240101000000Z", "20340101000000Z").unwrap();
    let mut serials = std::collections::HashSet::new();
    let mut keys = std::collections::HashSet::new();
    for _ in 0..20 {
        let (der, key) = ca.issue("same.test", "20240101000000Z",
                                  "20250101000000Z").unwrap();
        let parsed = allcrypt::x509::Certificate::parse(&der).unwrap();
        assert!(serials.insert(parsed.serial.to_vec()), "a serial repeated");
        assert!(keys.insert(key), "a key repeated");
        assert!(parsed.serial[0] & 0x80 == 0, "a negative serial");
    }
}

/// A CA rebuilt from its parts is the same CA, and one rebuilt from
/// mismatched parts is refused.
#[test]
fn test_a_ca_rebuilt_from_its_parts_is_the_same_ca() {
    let ca = allcrypt::api::CertificateAuthority::generate(
        "allcrypt test CA", "20240101000000Z", "20340101000000Z").unwrap();
    let key = ca.private_bytes().unwrap();
    let certificate = ca.certificate().to_vec();

    let again = allcrypt::api::CertificateAuthority::from_parts(
        &key, certificate.clone()).unwrap();
    assert_eq!(again.common_name(), "allcrypt test CA");
    assert_eq!(again.key_identifier().unwrap(),
               ca.key_identifier().unwrap());

    // A leaf issued by the rebuilt CA still chains to the original
    // certificate, which is the only thing that matters.
    let (leaf, _key) = again.issue("host.test", "20240101000000Z",
                                   "20250101000000Z").unwrap();
    let roots = vec![certificate.clone()];
    let options = allcrypt::api::VerifyOptions {
        now: 1_720_000_000,
        hostname: Some("host.test".to_string()),
        ..Default::default() };
    assert!(allcrypt::api::verify_chain(&[leaf], &roots, &options).is_ok());

    // Somebody else's key with this certificate is refused, rather than
    // producing a CA that signs chains verifying against nothing.
    let other = allcrypt::api::CertificateAuthority::generate(
        "other", "20240101000000Z", "20340101000000Z").unwrap();
    assert!(allcrypt::api::CertificateAuthority::from_parts(
        &other.private_bytes().unwrap(), certificate).is_err());
}

/// The EdDSA facade, which is the only route Python has to it.
///
/// The curve arithmetic is covered in `src/ec/eddsa.rs` against RFC
/// 8032's own vectors and in `pytests/test_eddsa.py` against OpenSSL.
/// What is checked here is the translation layer: names in, bytes out,
/// and the split between "this signature is wrong" (`false`) and "this
/// is not a signature" (`Err`).
#[test]
fn test_eddsa_facade() {
    for name in allcrypt::api::eddsa_curves() {
        let (private, public) = allcrypt::api::eddsa_generate(name).unwrap();
        assert_eq!(allcrypt::api::eddsa_public_key(name, &private).unwrap(), public);

        let message = b"through the facade";
        let signature = allcrypt::api::eddsa_sign(name, &private, message, &[]).unwrap();
        assert!(allcrypt::api::eddsa_verify(name, &public, message, &signature, &[])
                .unwrap());

        // Wrong but well formed is `false`, not an error.
        assert!(!allcrypt::api::eddsa_verify(name, &public, b"other", &signature, &[])
                .unwrap());

        // Wrong lengths are errors, because they are not signatures.
        assert!(allcrypt::api::eddsa_verify(name, &public, message,
                                            &signature[..signature.len() - 1], &[])
                .is_err());
        assert!(allcrypt::api::eddsa_verify(name, &public[..public.len() - 1], message,
                                            &signature, &[]).is_err());
    }
}

/// The variants this library does not implement are refused **by name**,
/// with an error that says why rather than "unknown curve".
///
/// Ed25519ctx, Ed25519ph and Ed448ph are different schemes over the same
/// two curves. Quietly aliasing one to the pure variant would produce
/// signatures that verify here and nowhere else, which is the failure
/// this whole module is written to avoid.
#[test]
fn test_the_eddsa_variants_that_are_not_implemented_say_so() {
    for name in ["ed25519ctx", "ed25519ph", "ed448ph"] {
        let error = allcrypt::api::eddsa_generate(name).unwrap_err();
        assert!(error.contains("different scheme"), "{}: {}", name, error);
    }
    assert!(allcrypt::api::eddsa_generate("ed12345").is_err());

    // And the two that are implemented are the two that are listed.
    for name in allcrypt::api::eddsa_curves() {
        assert!(allcrypt::api::eddsa_variant(name).is_ok(), "{} is listed but unknown", name);
    }
}

/// An Ed448 context is Ed448's alone.
#[test]
fn test_the_eddsa_context_belongs_to_ed448() {
    let (private, public) = allcrypt::api::eddsa_generate("ed25519").unwrap();
    assert!(allcrypt::api::eddsa_sign("ed25519", &private, b"x", b"ctx").is_err());
    let signature = allcrypt::api::eddsa_sign("ed25519", &private, b"x", &[]).unwrap();
    assert!(allcrypt::api::eddsa_verify("ed25519", &public, b"x", &signature, b"ctx")
            .is_err());

    let (private, public) = allcrypt::api::eddsa_generate("ed448").unwrap();
    let with = allcrypt::api::eddsa_sign("ed448", &private, b"x", b"ctx").unwrap();
    let without = allcrypt::api::eddsa_sign("ed448", &private, b"x", &[]).unwrap();
    assert_ne!(with, without);
    assert!(allcrypt::api::eddsa_verify("ed448", &public, b"x", &with, b"ctx").unwrap());
    assert!(!allcrypt::api::eddsa_verify("ed448", &public, b"x", &with, &[]).unwrap());
    assert!(allcrypt::api::eddsa_sign("ed448", &private, b"x", &[0; 256]).is_err());
}

/// The key wrap facade: names in, bytes out, and the two forms kept
/// apart.
#[test]
fn test_key_wrap_facade() {
    let kek = [0x42u8; 32];
    let data = [0x17u8; 24];

    let wrapped = allcrypt::api::key_wrap("aes", &kek, &data).unwrap();
    assert_eq!(wrapped.len(), data.len() + 8);
    assert_eq!(allcrypt::api::key_unwrap("aes", &kek, &wrapped).unwrap(), data);

    // The padded form is a *different* algorithm, so its output must not
    // be the unpadded one's even where both apply.
    let padded = allcrypt::api::key_wrap_with_padding("aes", &kek, &data).unwrap();
    assert_ne!(padded, wrapped);
    assert_eq!(allcrypt::api::key_unwrap_with_padding("aes", &kek, &padded).unwrap(),
               data);

    // And neither unwraps the other's output.
    assert!(allcrypt::api::key_unwrap("aes", &kek, &padded).is_err());

    // A length only the padded form can carry.
    let odd = [1u8, 2, 3, 4, 5];
    assert!(allcrypt::api::key_wrap("aes", &kek, &odd).is_err());
    let padded = allcrypt::api::key_wrap_with_padding("aes", &kek, &odd).unwrap();
    assert_eq!(allcrypt::api::key_unwrap_with_padding("aes", &kek, &padded).unwrap(),
               odd);
}

/// A 64 bit block cipher is named, not unknown, and the error says which
/// it is.
///
/// `des` and `magma` are both in `block_ciphers_available`; neither can
/// do either of these modes, and "unknown cipher" would send the caller
/// looking for a typo.
#[test]
fn test_the_wide_block_modes_refuse_a_narrow_cipher() {
    let error = allcrypt::api::key_wrap("des", &[1u8; 8], &[0u8; 16]).unwrap_err();
    assert!(error.contains("128 bit"), "{}", error);
    assert!(error.contains("des"), "{}", error);

    // The halves must differ, or the key check fires first and this
    // would assert on the wrong error.
    let magma_key: Vec<u8> = (0..64u8).collect();
    let error = allcrypt::api::xts_encrypt("magma", &magma_key, 0, &[0u8; 32])
        .unwrap_err();
    assert!(error.contains("128 bit"), "{}", error);
    assert!(error.contains("magma"), "{}", error);

    // And an actually unknown one still says so.
    assert!(allcrypt::api::key_wrap("nosuchcipher", &[0u8; 16], &[0u8; 16]).is_err());
}

/// The XTS facade, including the key rules that only live there.
#[test]
fn test_xts_facade() {
    let key: Vec<u8> = (0..32u8).collect();
    for length in [16usize, 17, 31, 32, 33, 64] {
        let plaintext: Vec<u8> = (0..length).map(|i| (i * 9 + 1) as u8).collect();
        let ciphertext = allcrypt::api::xts_encrypt("aes", &key, 7, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len(), "length {}", length);
        assert_eq!(allcrypt::api::xts_decrypt("aes", &key, 7, &ciphertext).unwrap(),
                   plaintext, "length {}", length);
        // Another sector does not decrypt it.
        assert_ne!(allcrypt::api::xts_decrypt("aes", &key, 8, &ciphertext).unwrap(),
                   plaintext);
    }

    // The mode is generic over any 128 bit block cipher, which is the
    // whole reason it is a mode and not part of AES.
    let key: Vec<u8> = (0..64u8).collect();
    for cipher in ["camellia", "kuznyechik"] {
        let plaintext = [0x5cu8; 48];
        let ciphertext =
            allcrypt::api::xts_encrypt(cipher, &key, 1, &plaintext).unwrap();
        assert_eq!(allcrypt::api::xts_decrypt(cipher, &key, 1, &ciphertext).unwrap(),
                   plaintext.to_vec());
    }
}

/// **An XTS key with two equal halves is refused.**
///
/// It collapses the tweak cipher into the data cipher. OpenSSL refuses
/// such a key outright, and this is the one place the library is strict
/// about *reading* as well as writing, because no disk was ever written
/// with one.
#[test]
fn test_xts_refuses_a_key_whose_halves_match() {
    let duplicated = [[0x33u8; 16], [0x33u8; 16]].concat();
    let error = allcrypt::api::xts_encrypt("aes", &duplicated, 0, &[0u8; 32])
        .unwrap_err();
    assert!(error.contains("identical"), "{}", error);
    assert!(allcrypt::api::xts_decrypt("aes", &duplicated, 0, &[0u8; 32]).is_err());

    // An odd length is not two keys at all.
    assert!(allcrypt::api::xts_encrypt("aes", &[0u8; 31], 0, &[0u8; 32]).is_err());
    // And a short data unit cannot steal from anything.
    let key: Vec<u8> = (0..32u8).collect();
    assert!(allcrypt::api::xts_encrypt("aes", &key, 0, &[0u8; 15]).is_err());
}

/// `hardware_aes` says what this build does: false without the `aes-ni`
/// feature, and with it whatever the processor offers.
#[test]
fn test_hardware_aes_reports_the_build() {
    #[cfg(not(all(feature = "aes-ni", target_arch = "x86_64")))]
    assert!(!allcrypt::api::hardware_aes());
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    assert_eq!(allcrypt::api::hardware_aes(),
               std::is_x86_feature_detected!("aes")
                   && std::is_x86_feature_detected!("pclmulqdq")
                   && std::is_x86_feature_detected!("sse2"));
}

/// `AnyBlockCipher` forwards the one-block in-place calls to AES's own,
/// rather than taking the trait's default through `block_encrypt`. The
/// answer is the same either way, so what tells them apart is the
/// scratch buffer: the default fills it, AES's leaves it alone. A
/// wrapper that stopped forwarding would cost CBC its fast path with
/// nothing else noticing.
#[test]
fn test_the_wrapper_forwards_the_one_block_path() {
    let key = [0x2Bu8; 16];
    let mut wrapped = AnyBlockCipher::new("aes", &key, None).unwrap();
    let mut direct = AesCrypto::new(key.to_vec()).unwrap();
    let mut scratch = Vec::new();
    let mut block = *b"sixteen bytes!!!";
    wrapped.encrypt_block_in_place(&mut block, &mut scratch).unwrap();
    assert!(scratch.is_empty(), "the default path ran");
    let mut expected = Vec::new();
    direct.block_encrypt(b"sixteen bytes!!!", &mut expected);
    assert_eq!(block.to_vec(), expected);
    wrapped.decrypt_block_in_place(&mut block, &mut scratch).unwrap();
    assert!(scratch.is_empty(), "the default path ran");
    assert_eq!(&block, b"sixteen bytes!!!");

    // A cipher with no override takes the default, through the scratch.
    let mut des = AnyBlockCipher::new("des", &[1u8; 8], None).unwrap();
    let mut eight = *b"8 bytes!";
    des.encrypt_block_in_place(&mut eight, &mut scratch).unwrap();
    assert_eq!(scratch.len(), 8);
    des.decrypt_block_in_place(&mut eight, &mut scratch).unwrap();
    assert_eq!(&eight, b"8 bytes!");
}
