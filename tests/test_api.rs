//! The dynamic facade in `api` must agree exactly with the statically typed
//! API it wraps. The Python bindings are a thin layer over this, so anything
//! verified here is verified for Python too.

use allcrypt::api::{self, AnyBlockCipher, AnyHash, AnyStreamCipher, CipherStream, Mode,
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
                    Mode::Cbc => c.cbc_encrypt(&pt, &mut want, &v).unwrap(),
                    Mode::Pcbc => c.pcbc_encrypt(&pt, &mut want, &v).unwrap(),
                    Mode::Cfb => c.cfb_encrypt(&pt, &mut want, &v).unwrap(),
                    Mode::Ofb => c.ofb_encrypt(&pt, &mut want, &v).unwrap(),
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
    GostCrypto::new(&k, GostCrypto::DEFAULT_PARAM_SET).unwrap()
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
        "strumok" => iv(32),
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

    // Blowfish's constructor refuses an empty key, which its schedule
    // would read as zeros, and one past the 72 bytes the P-array takes.
    assert!(AnyBlockCipher::new("blowfish", &[], None).is_err());
    assert!(AnyBlockCipher::new("blowfish", &[0u8; 73], None).is_err());
    assert!(AnyBlockCipher::new("blowfish", &[0u8; 72], None).is_ok());

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
            streamed.extend_from_slice(&c.encrypt(&pt[i..e]).unwrap());
            i = e;
            step = step * 2 + 1;
        }
        let mut c2 = AnyStreamCipher::new(name, &key(32), &nonce).unwrap();
        assert_eq!(streamed, c2.encrypt(&pt).unwrap(), "{} streaming", name);

        // Round trip.
        let mut c3 = AnyStreamCipher::new(name, &key(32), &nonce).unwrap();
        assert_eq!(c3.decrypt(&streamed).unwrap(), pt, "{} roundtrip", name);

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
    let mut direct = Chacha::new(&key(32), &iv(12), 12).unwrap();
    let mut want = vec![];
    direct.crypt(&data(300), &mut want);
    assert_eq!(viaapi.update(&data(300)).unwrap(), want);
    let mut viaapi = AnyStreamCipher::new("zipcrypto", b"pw", &[]).unwrap();
    let mut direct = allcrypt::stream_ciphers::zipcrypto::ZipCrypto::new(b"pw");
    let mut want = vec![];
    direct.encrypt(&data(300), &mut want);
    assert_eq!(viaapi.encrypt(&data(300)).unwrap(), want);
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
        let usable: Vec<usize> = [5usize, 8, 10, 12, 16, 24, 32, 56, 64, 128].into_iter()
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
    AesCrypto::new(&key(16)).unwrap().ecb_encrypt(&data(32), &mut want).unwrap();
    let mut s = CipherStream::new(AnyBlockCipher::new("aes", &key(16), None).unwrap(),
                                  Mode::Ecb, &[], false).unwrap();
    assert_eq!(s.update(&data(32)).unwrap(), want);
}

/// `block_cipher_name` is the constructor's own list of spellings: every
/// catalogue name is its own canonical form and builds a cipher that
/// reports it, every alias builds the same cipher as the name it stands
/// for, and a name it refuses the constructor refuses too.
#[test]
fn test_cipher_names_have_one_list_of_aliases() {
    for name in BLOCK_CIPHERS {
        assert_eq!(api::block_cipher_name(name), Some(*name));
        assert_eq!(api::block_cipher_name(&name.to_ascii_uppercase()), Some(*name));
        let n = [5usize, 8, 10, 12, 16, 24, 32, 56, 64, 128].into_iter()
            .find(|&n| AnyBlockCipher::new(name, &key(n), None).is_ok()).unwrap();
        assert_eq!(AnyBlockCipher::new(name, &key(n), None).unwrap().name(), *name);
    }
    let aliases = [("blowfish_le", "blowfish-le", 16), ("cast6", "cast256", 16),
                   ("cast128", "cast5", 16), ("kuznechik", "kuznyechik", 32),
                   ("Grasshopper", "kuznyechik", 32), ("des3", "3des", 24),
                   ("des-ede", "3des", 24), ("DES-EDE3", "3des", 24),
                   ("tripledes", "3des", 24), ("3way", "threeway", 12),
                   ("3-Way", "threeway", 12), ("Threefish-256", "threefish256", 48),
                   ("threefish-512", "threefish512", 64),
                   ("THREEFISH-1024", "threefish1024", 128)];
    for (alias, canonical, n) in aliases {
        assert_eq!(api::block_cipher_name(alias), Some(canonical));
        let encrypt = |name: &str| {
            let c = AnyBlockCipher::new(name, &key(n), None).unwrap();
            let mut s = CipherStream::new(c, Mode::Ecb, &[], false).unwrap();
            s.update(&data(128)).unwrap()
        };
        assert!(!encrypt(alias).is_empty(), "{alias}");
        assert_eq!(encrypt(alias), encrypt(canonical), "{alias}");
    }
    for unknown in ["", "nosuch", "aes-128", "kalyna-64", "rijndael-512", "3-des"] {
        assert_eq!(api::block_cipher_name(unknown), None, "{unknown}");
        let err = AnyBlockCipher::new(unknown, &key(16), None).err().unwrap();
        assert!(err.starts_with("Unknown block cipher"), "{err}");
    }
}

/// `curve_parameters_from_hex` reads what `curve_parameters` writes, and
/// the hex a specification prints; a missing, unknown or non-hex field is
/// refused by name. It is what `register_oid(curve_parameters=)` goes
/// through, so the bindings hold none of this.
#[test]
fn test_curve_parameters_from_hex() {
    let written = api::curve_parameters("P-256").unwrap();
    let pairs: Vec<(&str, &str)> = written.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let read = api::curve_parameters_from_hex(&pairs).unwrap();
    assert_eq!(read.name, "P-256");
    assert_eq!(read.p.to_hex(), written[1].1.trim_start_matches('0'));
    assert_eq!(read.h.to_hex(), "1");

    // Spaced, prefixed and odd-length hex, as a document prints it.
    let p = format!("0x{}", written[1].1.as_bytes().chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" "));
    let mut loose = pairs.clone();
    loose[1].1 = &p;
    loose[7].1 = "1";
    let again = api::curve_parameters_from_hex(&loose).unwrap();
    assert_eq!(again.p, read.p);
    assert_eq!(again.h, read.h);

    let without: Vec<_> = pairs.iter().copied().filter(|(k, _)| *k != "cofactor").collect();
    assert!(api::curve_parameters_from_hex(&without).unwrap_err().contains("\"cofactor\""));
    let mut misspelt = without.clone();
    misspelt.push(("cofator", "1"));
    assert!(api::curve_parameters_from_hex(&misspelt).unwrap_err().contains("\"cofator\""));
    let mut bad = pairs.clone();
    bad[3].1 = "12g4";
    assert!(api::curve_parameters_from_hex(&bad).unwrap_err().contains("not hex"));
    bad[3].1 = "0x";
    assert!(api::curve_parameters_from_hex(&bad).unwrap_err().contains("not hex"));
}

/// A hash's name is the name it was made from, whatever case or alias
/// that was, and any name it reports makes the same function again -
/// including the lengths the catalogue does not list.
#[test]
fn test_a_hash_names_itself_as_new_reads_it() {
    for name in HASHES {
        assert_eq!(AnyHash::new(name).unwrap().name(), *name);
        assert_eq!(AnyHash::new(&name.to_ascii_uppercase()).unwrap().name(), *name);
    }
    assert_eq!(AnyHash::new("streebog").unwrap().name(), "streebog256");
    assert_eq!(AnyHash::new("RMD160").unwrap().name(), "ripemd160");
    assert_eq!(AnyHash::new("whirlpool1").unwrap().name(), "whirlpool_t");
    assert_eq!(AnyHash::new("keccak").unwrap().name(), "keccak_256");
    for odd in ["blake2b_256", "blake2s_128", "md6_200", "kupyna128", "sha512_128",
                "keccak_160", "shake_128_512", "shake_256_80"] {
        let mut first = AnyHash::new(odd).unwrap();
        assert_eq!(first.name(), odd);
        let mut again = AnyHash::new(&first.name()).unwrap();
        first.update(b"abc");
        again.update(b"abc");
        assert_eq!(first.digest(), again.digest(), "{odd}");
    }
    assert!(AnyHash::new("kupyna100").is_err());
    assert!(AnyHash::new("sha512_384").is_err());
    assert!(AnyHash::new("keccak_7").is_err());
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
    assert_eq!(AEADS, &["aes-gcm", "aes-ccm", "aes-ccm-8", "aria-gcm", "camellia-gcm", "sm4-gcm",
                        "aria-ccm", "camellia-ccm", "sm4-ccm", "chacha20-poly1305",
                        "xchacha20-poly1305", "aes-eax", "twofish-eax", "serpent-eax", "camellia-eax",
                        "sm4-eax", "des-eax", "3des-eax", "blowfish-eax",
                        "tea-eax", "xtea-eax", "rc5-eax", "aria-eax", "rc6-eax",
                        "cast256-eax", "mars-eax", "khazad-eax", "anubis-eax", "noekeon-eax",
                        "noekeon-indirect-eax", "skipjack-eax", "skipjack-reversed-eax",
                        "safer-k64-eax", "safer-k128-eax", "safer-sk64-eax", "safer-sk128-eax",
                        "square-eax", "kasumi-eax", "misty1-eax", "saferplus-eax",
                        "saferplus-reversed-words-eax", "loki97-eax", "loki97-mcrypt-eax", "lea-eax",
                        "hight-eax", "speck64-eax", "speck128-eax", "simon64-eax",
                        "simon128-eax", "present-eax", "feal-eax", "feal-nx-eax",
                        "kuznyechik-mgm", "magma-mgm", "aes-mgm",
                        "twofish-mgm", "serpent-mgm", "camellia-mgm",
                        "sm4-mgm", "aria-mgm", "des-mgm", "3des-mgm",
                        "blowfish-mgm", "tea-mgm", "xtea-mgm", "rc5-mgm", "rc6-mgm",
                        "cast256-mgm", "mars-mgm", "khazad-mgm", "anubis-mgm", "noekeon-mgm",
                        "noekeon-indirect-mgm", "skipjack-mgm", "skipjack-reversed-mgm",
                        "safer-k64-mgm", "safer-k128-mgm", "safer-sk64-mgm", "safer-sk128-mgm",
                        "square-mgm", "kasumi-mgm", "misty1-mgm", "saferplus-mgm",
                        "saferplus-reversed-words-mgm", "loki97-mgm", "loki97-mcrypt-mgm", "lea-mgm",
                        "hight-mgm", "speck64-mgm", "speck128-mgm", "simon64-mgm",
                        "simon128-mgm", "present-mgm", "feal-mgm", "feal-nx-mgm",
                        "aes-ocb", "camellia-ocb", "twofish-ocb", "serpent-ocb",
                        "aria-ocb", "sm4-ocb", "seed-ocb", "kuznyechik-ocb", "rc6-ocb",
                        "cast256-ocb", "mars-ocb", "anubis-ocb", "noekeon-ocb",
                        "noekeon-indirect-ocb", "square-ocb", "saferplus-ocb",
                        "saferplus-reversed-words-ocb", "loki97-ocb", "loki97-mcrypt-ocb", "lea-ocb",
                        "speck128-ocb", "simon128-ocb",
                        "aes-128-cbc-hmac-sha256",
                        "aes-192-cbc-hmac-sha384",
                        "aes-256-cbc-hmac-sha512", "kalyna-128-gcm", "kalyna-256-gcm",
                        "kalyna-512-gcm", "kalyna-128-ccm", "kalyna-256-ccm", "kalyna-512-ccm"]);

    // Every AEAD, over every key length it takes. ChaCha20-Poly1305 has
    // exactly one; AES has three.
    let combinations: Vec<(&str, usize)> = vec![
        ("aes-gcm", 16), ("aes-gcm", 24), ("aes-gcm", 32),
        ("aes-ccm", 16), ("aes-ccm", 24), ("aes-ccm", 32),
        ("aes-ccm-8", 16), ("aes-ccm-8", 32),
        ("aria-gcm", 16), ("aria-gcm", 32), ("camellia-gcm", 24), ("sm4-gcm", 16),
        ("aria-ccm", 24), ("camellia-ccm", 16), ("camellia-ccm", 32), ("sm4-ccm", 16),
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
        ("aria-eax", 16), ("aria-eax", 32), ("rc6-eax", 16), ("rc6-eax", 32),
        ("cast256-eax", 20), ("mars-eax", 40), ("khazad-eax", 16), ("anubis-eax", 40),
        ("noekeon-eax", 16), ("noekeon-indirect-eax", 16),
        ("skipjack-eax", 10), ("skipjack-reversed-eax", 10),
        ("safer-k64-eax", 8), ("safer-k128-eax", 16), ("safer-sk64-eax", 8),
        ("safer-sk128-eax", 16), ("square-eax", 16), ("kasumi-eax", 16),
        ("misty1-eax", 16), ("saferplus-eax", 24), ("saferplus-reversed-words-eax", 32),
        ("loki97-eax", 16), ("loki97-mcrypt-eax", 24), ("lea-eax", 32),
        ("hight-eax", 16), ("speck64-eax", 12), ("speck128-eax", 32), ("simon64-eax", 16),
        ("simon128-eax", 24), ("present-eax", 10), ("feal-eax", 8), ("feal-nx-eax", 16),
        // MGM, the same way: the standard's own two ciphers first, then
        // one of each block size from the rest. MGM's field polynomial
        // differs between a 64 and a 128 bit block, so the two sizes
        // are two different modes sharing a name.
        ("kuznyechik-mgm", 32), ("magma-mgm", 32),
        ("aes-mgm", 16), ("aes-mgm", 32),
        ("twofish-mgm", 32), ("serpent-mgm", 32),
        ("camellia-mgm", 16), ("sm4-mgm", 16), ("aria-mgm", 32),
        ("des-mgm", 8), ("3des-mgm", 24), ("blowfish-mgm", 16),
        ("tea-mgm", 16), ("xtea-mgm", 16), ("rc5-mgm", 16), ("rc6-mgm", 24), ("cast256-mgm", 32),
        ("mars-mgm", 56), ("khazad-mgm", 16), ("anubis-mgm", 20),
        ("noekeon-mgm", 16), ("noekeon-indirect-mgm", 16),
        ("skipjack-mgm", 10), ("skipjack-reversed-mgm", 10),
        ("safer-k64-mgm", 8), ("safer-k128-mgm", 16), ("safer-sk64-mgm", 8),
        ("safer-sk128-mgm", 16), ("square-mgm", 16), ("kasumi-mgm", 16),
        ("misty1-mgm", 16), ("saferplus-mgm", 32), ("saferplus-reversed-words-mgm", 16),
        ("loki97-mgm", 24), ("loki97-mcrypt-mgm", 32), ("lea-mgm", 16),
        ("hight-mgm", 16), ("speck64-mgm", 16), ("speck128-mgm", 24), ("simon64-mgm", 12),
        ("simon128-mgm", 16), ("present-mgm", 16), ("feal-mgm", 8), ("feal-nx-mgm", 16),
        // OCB, 128 bit blocks only.
        ("aes-ocb", 16), ("aes-ocb", 24), ("aes-ocb", 32),
        ("camellia-ocb", 16), ("twofish-ocb", 32), ("serpent-ocb", 32),
        ("aria-ocb", 16), ("sm4-ocb", 16), ("seed-ocb", 16),
        ("kuznyechik-ocb", 32), ("rc6-ocb", 16), ("cast256-ocb", 28),
        ("mars-ocb", 20), ("anubis-ocb", 32), ("noekeon-ocb", 16),
        ("noekeon-indirect-ocb", 16), ("square-ocb", 16), ("saferplus-ocb", 16),
        ("saferplus-reversed-words-ocb", 24), ("loki97-ocb", 32), ("loki97-mcrypt-ocb", 16),
        ("lea-ocb", 24), ("speck128-ocb", 16), ("simon128-ocb", 32),
        // AES-CBC with HMAC: one key size each, the MAC key and the AES
        // key together.
        ("aes-128-cbc-hmac-sha256", 32), ("aes-192-cbc-hmac-sha384", 48),
        ("aes-256-cbc-hmac-sha512", 64),
        // DSTU 7624's own GCM and CCM at each Kalyna block size, and
        // both key lengths where the block has two.
        ("kalyna-128-gcm", 16), ("kalyna-256-gcm", 64), ("kalyna-512-gcm", 64),
        ("kalyna-128-ccm", 32), ("kalyna-256-ccm", 32), ("kalyna-512-ccm", 64),
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
        let nonce: Vec<u8> = if aead.starts_with("kalyna-") {
            // DSTU 7624's GCM and CCM take a whole block.
            vec![0x2bu8; aead["kalyna-".len()..aead.len() - 4].parse::<usize>().unwrap() / 8]
        } else if let Some(cipher) = aead.strip_suffix("-mgm") {
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
                                        .or_else(|| aead.strip_suffix("-mgm"))
                                        .or_else(|| aead.strip_prefix("kalyna-")
                                                         .map(|_| &aead[..aead.len() - 4])) {
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
        if aead.starts_with("kalyna-") && aead.ends_with("-gcm") {
            // **Except DSTU 7624's GCM, whose tag does not cover the
            // IV**: it is E(B xor lengths), and the IV reaches only the
            // keystream. Another IV opens with the same tag and returns
            // a different plaintext. Both witnesses and the standard's
            // examples agree; docs/pitfalls.md, 7zzp.
            let other = aead_decrypt(aead, &key, &other_nonce, aad, &ciphertext, &tag).unwrap();
            assert_ne!(other, message, "{}", aead);
        } else {
            assert!(aead_decrypt(aead, &key, &other_nonce, aad, &ciphertext, &tag).is_err());
        }

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
        let expected_to_buffer = aead.ends_with("-ccm") || aead.ends_with("-ccm-8")
            || aead.ends_with("-eax") || aead.ends_with("-mgm") || aead.ends_with("-ocb")
            || aead.contains("-cbc-hmac-")
            // Kalyna's GCM is one-shot here, as EAX is.
            || aead.starts_with("kalyna-");
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
    let mut direct = AesCrypto::new(&key).unwrap();
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

#[test]
fn test_lcg_outputs_and_custom_parameters() {
    use allcrypt::api;
    let names = api::lcg_names();
    assert!(names.contains(&"minstd_rand0") && names.contains(&"randu"));
    // skip discards outputs: the 10,000th minstd_rand0 value from seed 1
    // is the 10,000th of the full run.
    let run = api::lcg_outputs("minstd_rand0", 1, 0, 10_000).unwrap();
    assert_eq!(api::lcg_outputs("minstd_rand0", 1, 9_999, 1).unwrap(), vec![run[9_999]]);
    assert!(api::lcg_outputs("rand", 1, 0, 1).unwrap_err().contains("msvc"));
    let mut custom = api::lcg_custom(16807, 0, (1 << 31) - 1, 1, u128::MAX).unwrap();
    assert_eq!(custom.next_output(), run[0]);
    assert!(api::lcg_custom(1, 0, 1, 0, 1).is_err());
    assert!(api::lcg_custom(1, 0, 7, 0, 0).is_err());
}

/// Every `AeadStream` refuses `update`, `finish` and `open` once it has
/// finished. The buffered arms (CCM, EAX, MGM, OCB, CBC-HMAC) had no
/// finished state: `update` after `finish` appended to the old buffer
/// and a second `finish` sealed `a || b` under the same key and nonce,
/// which is the repeated nonce the type's documentation forbids. GCM and
/// ChaCha20-Poly1305 already refused inside their own states, and the
/// existing tests only ever finished a stream once, so nothing noticed.
/// A tag length after GCM, CCM, EAX, MGM or OCB is a parameter of the
/// mode, and each mode's own set of lengths decides. Once named, a tag
/// of exactly that length is the only one opened: for GCM a shorter one
/// is a prefix a forger can guess more cheaply, and for CCM it is a tag
/// of a different CCM.
#[test]
fn test_aead_tag_lengths_by_name() {
    use allcrypt::api::{aead_decrypt, aead_encrypt, aead_tag_len, AeadStream};
    let key = [0x42u8; 16];
    let message = b"twenty-three bytes long";
    let cases: &[(&str, &[usize], &[usize], usize)] = &[
        // (AEAD, lengths it takes, lengths it refuses, nonce length)
        ("aes-gcm", &[4, 8, 12, 13, 14, 15, 16], &[0, 1, 5, 9, 11, 17], 12),
        ("camellia-gcm", &[4, 8, 16], &[6, 17], 12),
        ("aes-ccm", &[4, 6, 8, 10, 12, 14, 16], &[0, 2, 3, 5, 15, 18], 12),
        ("sm4-ccm", &[4, 16], &[7], 12),
        ("aes-eax", &[1, 8, 16], &[0, 17], 12),
        ("des-eax", &[1, 8], &[9], 12),
        ("aes-ocb", &[1, 8, 12, 16], &[0, 17], 12),
        ("aes-mgm", &[4, 8, 16], &[3, 17], 16),
        ("magma-mgm", &[4, 8], &[3, 9], 8),
    ];
    let mut opened = 0;
    for &(aead, takes, refuses, nonce_len) in cases {
        let key: Vec<u8> = if aead.starts_with("des") { key[..8].to_vec() }
                           else if aead.starts_with("magma") { [key, key].concat() }
                           else { key.to_vec() };
        let nonce = vec![0x1du8; nonce_len];
        let (_, full) = aead_encrypt(aead, &key, &nonce, b"aad", message).unwrap();
        for &n in takes {
            let name = format!("{aead}-{n}");
            assert_eq!(aead_tag_len(&name, &key).unwrap(), n, "{name}");
            let (ciphertext, tag) = aead_encrypt(&name, &key, &nonce, b"aad", message).unwrap();
            assert_eq!(tag.len(), n, "{name}");
            assert_eq!(aead_decrypt(&name, &key, &nonce, b"aad", &ciphertext, &tag).unwrap(),
                       message, "{name}");
            let mut altered = tag.clone();
            altered[n - 1] ^= 1;
            assert!(aead_decrypt(&name, &key, &nonce, b"aad", &ciphertext, &altered).is_err());
            // The full-length tag, and any other length, is not this one.
            for &other in takes.iter().filter(|&&other| other != n) {
                let (_, other_tag) = aead_encrypt(&format!("{aead}-{other}"), &key, &nonce,
                                                  b"aad", message).unwrap();
                let mut stream = AeadStream::new(&name, &key, &nonce, b"aad", true).unwrap();
                let mut nothing = Vec::new();
                stream.update(&ciphertext, &mut nothing).unwrap();
                let refused = if stream.buffers_everything() {
                    stream.open(&other_tag, &mut nothing).is_err()
                } else {
                    stream.verify(&other_tag).is_err()
                };
                assert!(refused, "{name} opened a {other} byte tag");
            }
            // The default length, named, is the default.
            if n == full.len() {
                assert_eq!(tag, full, "{name}");
            }
            opened += 1;
        }
        for &n in refuses {
            let name = format!("{aead}-{n}");
            assert!(AeadStream::new(&name, &key, &nonce, b"", false).is_err(), "{name}");
        }
    }
    assert_eq!(opened, 33);

    // The bare names and the suffix spelling agree, and the suffix is
    // read only after a mode that has one.
    let (_, eight) = aead_encrypt("ccm-8", &key, &[1; 12], b"", b"m").unwrap();
    assert_eq!(aead_encrypt("aes-ccm-8", &key, &[1; 12], b"", b"m").unwrap().1, eight);
    assert_eq!(aead_encrypt("gcm-12", &key, &[1; 12], b"", b"m").unwrap().1.len(), 12);
    assert!(aead_encrypt("chacha20-poly1305-8", &[0; 32], &[1; 12], b"", b"m").is_err());
    assert!(aead_encrypt("aes-gcm-99999999999999999999999", &key, &[1; 12], b"", b"m")
                .is_err());

    // Without a named length, GCM still opens 12 to 16 byte prefixes and
    // nothing shorter: there the length arrives with the message.
    let (ciphertext, tag) = aead_encrypt("aes-gcm", &key, &[1; 12], b"", message).unwrap();
    for n in 12..=16 {
        aead_decrypt("aes-gcm", &key, &[1; 12], b"", &ciphertext, &tag[..n]).unwrap();
    }
    for n in [4, 8, 11] {
        assert!(aead_decrypt("aes-gcm", &key, &[1; 12], b"", &ciphertext, &tag[..n]).is_err());
    }

    // GCM and CCM need a 128 bit block. Kalyna's are DSTU 7624's own
    // (tests/test_kalyna_aead.rs), whose nonce is a whole block, so the
    // twelve bytes NIST's modes take are refused rather than read.
    assert!(AeadStream::new("des-gcm", &[0; 8], &[1; 12], b"", false).is_err());
    assert!(AeadStream::new("blowfish-ccm", &[0; 16], &[1; 12], b"", false).is_err());
    for name in ["kalyna-128-gcm", "kalyna-128-ccm", "kalyna-128-gcm-16"] {
        let refusal = aead_encrypt(name, &[0; 16], &[1; 12], b"", b"m").err().unwrap();
        assert!(refusal.contains("one block"), "{name}: {refusal}");
    }
}

#[test]
fn test_aead_stream_refuses_use_after_finish() {
    use allcrypt::api::AeadStream;
    for (aead, key_len, nonce) in [
        ("aes-gcm", 16usize, vec![3u8; 12]),
        ("chacha20-poly1305", 32, vec![3u8; 12]),
        ("aes-ccm", 16, vec![3u8; 12]),
        ("aes-eax", 16, vec![3u8; 12]),
        ("kuznyechik-mgm", 32, vec![0x3bu8; 16]),
        ("aes-ocb", 16, vec![3u8; 12]),
        ("aes-128-cbc-hmac-sha256", 32, vec![3u8; 16]),
    ] {
        let key = key(key_len);
        let mut sealing = AeadStream::new(aead, &key, &nonce, b"ad", false).unwrap();
        let mut ciphertext = Vec::new();
        sealing.update(b"first message", &mut ciphertext).unwrap();
        let tag = sealing.finish(&mut ciphertext).unwrap();
        let mut more = Vec::new();
        assert!(sealing.update(b"second", &mut more).is_err(),
                "{aead}: update after finish was accepted");
        assert!(sealing.finish(&mut more).is_err(),
                "{aead}: a second finish sealed again under the same nonce");
        assert!(more.is_empty(), "{aead}: output after finish");

        let mut opening = AeadStream::new(aead, &key, &nonce, b"ad", true).unwrap();
        let mut plaintext = Vec::new();
        opening.update(&ciphertext, &mut plaintext).unwrap();
        opening.open(&tag, &mut plaintext).unwrap();
        assert_eq!(plaintext, b"first message", "{aead}");
        assert!(opening.update(&ciphertext, &mut more).is_err(),
                "{aead}: update after open was accepted");
        assert!(opening.open(&tag, &mut more).is_err(),
                "{aead}: a second open was accepted");
        assert!(more.is_empty(), "{aead}: output after open");
    }
}

/// A ChaCha or Salsa20 stream whose counter runs out is an `Err` from
/// `update`, `encrypt` and `decrypt`. They called `StreamCipher::crypt`,
/// whose signature has no error, so an exhausted stream returned fewer
/// bytes than it was given, with `Ok` - a short ciphertext the caller
/// had no way to tell from a whole one. The counter is 256 GiB away for
/// a 12-byte ChaCha nonce, so no test had reached it; `set_counter` and
/// `seek_block` put it one block from the end here.
#[test]
fn test_an_exhausted_stream_cipher_is_an_error() {
    use allcrypt::stream_ciphers::salsa20::Salsa20;
    let near_the_end = || {
        let mut chacha = Chacha::new(&key(32), &iv(12), 20).unwrap();
        chacha.set_counter(u32::MAX).unwrap();
        AnyStreamCipher::Chacha(chacha)
    };
    let salsa_near_the_end = || {
        let mut salsa = Salsa20::new(&key(32), &iv(8)).unwrap();
        salsa.seek_block(u64::MAX);
        AnyStreamCipher::Salsa20(salsa)
    };
    for make in [&near_the_end as &dyn Fn() -> AnyStreamCipher, &salsa_near_the_end] {
        // One block is still there.
        assert_eq!(make().update(&[0u8; 64]).unwrap().len(), 64);
        assert!(make().update(&[0u8; 128]).is_err(), "update returned a short result");
        assert!(make().encrypt(&[0u8; 128]).is_err(), "encrypt returned a short result");
        assert!(make().decrypt(&[0u8; 128]).is_err(), "decrypt returned a short result");
        let mut buf = [0u8; 128];
        assert!(make().apply(&mut buf).is_err());
    }
}

/// `api::tls10_prf` returned `Vec` and called `kdf::tls10_prf`, which
/// panics above `kdf::MAX_OUTPUT_BYTES` - a `PanicException` from Python
/// where `tls12_prf` beside it raised `ValueError`. `api::shake` went
/// through `Keccak::squeeze`, which panics the same way (the cap is also
/// checked earlier, so that one was not reachable). The existing tests
/// only asked for lengths below the cap.
#[test]
fn test_prf_output_caps_are_errors() {
    use allcrypt::api;
    let over = allcrypt::kdf::MAX_OUTPUT_BYTES + 1;
    assert!(api::tls10_prf(b"secret", b"label", b"seed", over).is_err());
    assert!(api::shake("shake_128", b"data", over).is_err());
    let short = api::tls10_prf(b"secret", b"label", b"seed", 100).unwrap();
    assert_eq!(api::tls10_prf(b"secret", b"label", b"seed", 40).unwrap(), short[..40]);
}

/// The calls the Python bindings make for CMAC, the GOST S-box and curve
/// read-outs, the encryption scheme list and SSH went straight into the
/// crate (`mac::cmac`, `ec::curves`, `ssh::*`), so this file - which is
/// what stands behind "verified here is verified for Python" - covered
/// none of them. They now go through `api`, and these are the calls.
#[test]
fn test_binding_surfaces_go_through_the_api() {
    use allcrypt::api;

    // CMAC: one block of tag, keyed and message-dependent, and an
    // unknown cipher refused.
    let tag = api::cmac("aes", &key(16), &data(40)).unwrap();
    assert_eq!(tag.len(), 16);
    assert_ne!(tag, api::cmac("aes", &key(16), &data(41)).unwrap());
    assert!(api::cmac("no-such-cipher", &key(16), &data(40)).is_err());

    // The GOST S-box: eight rows, each a permutation of 0..16.
    let sbox = api::gost_sbox("id-Gost28147-89-TestParamSet").unwrap();
    assert_eq!(sbox.len(), 8);
    for row in &sbox {
        let mut sorted = row.clone();
        sorted.sort();
        assert_eq!(sorted, (0..16).collect::<Vec<u8>>());
    }
    assert!(api::gost_sbox("no-such-set").is_err());

    // Curve parameters: the fields in `register_oid`'s order, every
    // number a whole number of bytes, and the base point on the curve.
    let fields = api::curve_parameters("P-256").unwrap();
    let names: Vec<&str> = fields.iter().map(|(field, _)| *field).collect();
    assert_eq!(names, ["name", "p", "a", "b", "gx", "gy", "n", "cofactor"]);
    for (field, value) in &fields[1..] {
        assert_eq!(value.len() % 2, 0, "{field} is not whole bytes: {value}");
    }
    assert_eq!(fields[7].1, "01");
    assert!(api::curve_parameters("no-such-curve").is_err());

    // Every scheme listed is one `encrypt_private_key` takes.
    let schemes = api::encryption_schemes();
    assert!(!schemes.is_empty());
}

#[test]
fn test_ssh_through_the_api() {
    use allcrypt::api;

    let key = api::ssh_generate_key("ed25519", None).unwrap();
    let public = key.public();

    // Raw signatures, both ways, and a changed message refused.
    let signature = api::ssh_sign(&key, b"message", None).unwrap();
    assert!(api::ssh_verify(&public, b"message", &signature).unwrap());
    assert!(!api::ssh_verify(&public, b"messagf", &signature).unwrap());

    // The key file, plain and encrypted, comes back as the same key.
    for passphrase in [None, Some(&b"correct horse"[..])] {
        let text = api::ssh_write_private_key(&key, "a comment", passphrase,
                                              "aes256-ctr", 2).unwrap();
        let (read, comment) = api::ssh_read_private_key(&text, passphrase).unwrap();
        assert_eq!(comment, "a comment");
        assert!(read.public() == public);
    }

    // A public key line and its blob.
    let line = format!("from=\"10.0.0.1\" {}", public.to_openssh("someone"));
    let (parsed, comment, options) = api::ssh_parse_public_line(&line).unwrap();
    assert!(parsed == public);
    assert_eq!(comment, "someone");
    assert_eq!(options, "from=\"10.0.0.1\"");
    assert!(api::ssh_public_key_from_blob(&public.to_blob()).unwrap() == public);

    // SSHSIG names its signer, and a different namespace is refused.
    let armoured = api::ssh_sshsig_sign(&key, "file", b"payload", "sha512").unwrap();
    assert!(api::ssh_sshsig_verify(&armoured, "file", b"payload").unwrap() == public);
    assert!(api::ssh_sshsig_verify(&armoured, "email", b"payload").is_err());

    // The algorithm names the Python lists are resolved against: every
    // default of both ends and every key type, each once. This replaced
    // a hand-typed list in python.rs that could drift from the tables.
    let names = api::ssh_algorithm_names();
    let client = api::SshClientConfig::new("user", api::SshHostKeyCheck::AcceptAny);
    for name in client.kex.iter().chain(&client.ciphers).chain(&client.macs)
                      .chain(&client.host_key_algorithms)
                      .chain(allcrypt::ssh::keys::KEY_TYPES) {
        assert!(names.contains(name), "{name} is missing");
    }
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), names.len());
}

/// `AeadStream` had no name accessor, so the Python `AeadEncryptor`
/// printed a hard-coded `aes-gcm` for every stream, ChaCha20-Poly1305
/// included; nothing compared the repr with the AEAD asked for.
#[test]
fn test_aead_stream_knows_its_name() {
    use allcrypt::api::AeadStream;
    let stream = AeadStream::new("ChaCha20-Poly1305", &key(32), &iv(12), &[], false).unwrap();
    assert_eq!(stream.name(), "chacha20-poly1305");
    let stream = AeadStream::new("aes-eax", &key(16), &iv(12), &[], true).unwrap();
    assert_eq!(stream.name(), "aes-eax");
}

/// No private key type here is `Clone`. `DsaKey` derived it while
/// `EcKey`, `RsaKey`, `EddsaKey`, `SlhDsaKey`, `MlKemKey` and `MlDsaKey`
/// deliberately do not; nothing checked the set as a whole. The check
/// is the inherent-constant trick: `IsClone::<T>::VALUE` resolves to the
/// inherent constant only when `T: Clone`, and to the trait's otherwise.
#[test]
fn test_private_keys_are_not_clone() {
    use allcrypt::api::{DsaKey, EcKey, EddsaKey, MlDsaKey, MlKemKey, RsaKey, SlhDsaKey};
    use std::marker::PhantomData;
    trait NotClone { const VALUE: bool = false; }
    struct IsClone<T>(PhantomData<T>);
    impl<T> NotClone for IsClone<T> {}
    #[allow(dead_code)]
    impl<T: Clone> IsClone<T> { const VALUE: bool = true; }
    const { assert!(IsClone::<Vec<u8>>::VALUE, "the check itself does not work") };
    const { assert!(!IsClone::<DsaKey>::VALUE, "DsaKey is Clone") };
    const { assert!(!IsClone::<EcKey>::VALUE) };
    const { assert!(!IsClone::<RsaKey>::VALUE) };
    const { assert!(!IsClone::<EddsaKey>::VALUE) };
    const { assert!(!IsClone::<SlhDsaKey>::VALUE) };
    const { assert!(!IsClone::<MlKemKey>::VALUE) };
    const { assert!(!IsClone::<MlDsaKey>::VALUE) };
}

/// `kerberos_nfold`'s length is the caller's, and `nfold` computed
/// `len * length / gcd` unchecked: a length near `usize::MAX / len`
/// overflowed, a `PanicException` from Python in a debug build and an
/// allocation abort in release. Every test folded to a key size.
#[test]
fn test_kerberos_nfold_lengths_are_bounded() {
    use allcrypt::api;
    assert!(api::kerberos_nfold(b"012345", usize::MAX / 3).is_err());
    assert!(api::kerberos_nfold(b"0123456", 1 << 30).is_err());
    assert!(api::kerberos_nfold(b"", usize::MAX).is_err());
    // The ordinary sizes still fold (their values are pinned by the
    // RFC 3961 vectors in pytests/test_kdf_nist.py).
    assert_eq!(api::kerberos_nfold(b"012345", 8).unwrap().len(), 8);
    assert_eq!(api::kerberos_nfold(b"", 16).unwrap(), vec![0u8; 16]);
}

/// `api::wipe` is what the private key types' drops call. A plain
/// `fill(0)` before a free is a dead store the optimiser may delete, and
/// the key types (`EddsaKey`, `SlhDsaKey`, `MlKemKey`, `MlDsaKey`, the
/// Python `Cipher` and `Aead`) had no drop at all, while the C buffer
/// that copies the same bytes out was wiped. Reading freed memory to
/// check the drops themselves is undefined behaviour, so this pins the
/// helper; the drops are one line each.
#[test]
fn test_wipe_zeroes_the_buffer() {
    let mut secret = key(64);
    assert!(secret.iter().any(|b| *b != 0));
    allcrypt::api::wipe(&mut secret);
    assert_eq!(secret, vec![0u8; 64]);
}

/// `seek` lands on the same keystream byte a straight run reaches, at
/// offsets on and either side of block boundaries, forwards and back,
/// for every cipher with a counter; and the 32 bit counter of a 12 byte
/// ChaCha nonce ends where RFC 8439 says rather than wrapping.
#[test]
fn test_stream_cipher_seek() {
    let key = [0x5au8; 32];
    let cases: &[(&str, usize)] = &[("chacha20", 8), ("chacha20", 12), ("chacha12", 12),
                                    ("chacha8", 8), ("xchacha20", 24), ("salsa20", 8),
                                    ("salsa12", 8), ("salsa8", 8), ("xsalsa20", 24)];
    for &(name, nonce_len) in cases {
        let nonce: Vec<u8> = (0..nonce_len as u8).collect();
        let long = AnyStreamCipher::new(name, &key, &nonce).unwrap().update(&[0; 1000]).unwrap();
        let mut reused = AnyStreamCipher::new(name, &key, &nonce).unwrap();
        reused.update(&[0; 300]).unwrap();
        for offset in [999usize, 0, 1, 63, 64, 65, 127, 128, 200, 640, 1000] {
            let mut fresh = AnyStreamCipher::new(name, &key, &nonce).unwrap();
            fresh.seek(offset as u64).unwrap();
            assert_eq!(fresh.update(&vec![0; 1000 - offset]).unwrap(), long[offset..],
                       "{name}/{nonce_len} at {offset}");
            // The same stream, moved about.
            reused.seek(offset as u64).unwrap();
            assert_eq!(reused.update(&vec![0; 1000 - offset]).unwrap(), long[offset..],
                       "{name}/{nonce_len} reused at {offset}");
        }
    }

    // A 12 byte nonce: the last block is 2^32 - 1, and it is usable.
    let mut chacha = AnyStreamCipher::new("chacha20", &key, &[1; 12]).unwrap();
    assert!(chacha.seek(64 << 32).is_err());
    chacha.seek((64 << 32) - 64).unwrap();
    assert_eq!(chacha.update(&[0; 64]).unwrap().len(), 64);
    assert!(chacha.update(&[0; 1]).is_err());
    chacha.seek(0).unwrap();
    assert_eq!(chacha.update(&[0; 64]).unwrap(),
               AnyStreamCipher::new("chacha20", &key, &[1; 12]).unwrap().update(&[0; 64])
                   .unwrap());
    // A 64 bit counter: block 2^32 reached by running across the carry
    // is block 2^32 reached by seeking, and is not block 0.
    for name in ["chacha20", "salsa20", "xsalsa20"] {
        let nonce = if name == "xsalsa20" { vec![1; 24] } else { vec![1; 8] };
        let mut wide = AnyStreamCipher::new(name, &key, &nonce).unwrap();
        wide.seek_block(u32::MAX as u64).unwrap();
        let across = wide.update(&[0; 128]).unwrap();
        wide.seek_block(1 << 32).unwrap();
        let past_32_bits = wide.update(&[0; 64]).unwrap();
        assert_eq!(past_32_bits, across[64..], "{name}");
        wide.seek(0).unwrap();
        assert_ne!(wide.update(&[0; 64]).unwrap(), past_32_bits, "{name}");
    }

    for name in ["rc4", "zipcrypto"] {
        assert!(AnyStreamCipher::new(name, &key, &[]).unwrap().seek(0).is_err(), "{name}");
    }
    assert!(AnyStreamCipher::new("strumok", &key, &[0; 32]).unwrap().seek(0).is_err());
}

/// The raw primitives, each composed back into the construction it comes
/// from: GHASH and an AES block are GMAC, GMAC is GCM's tag, Poly1305 under
/// ChaCha20's block zero is ChaCha20-Poly1305's tag, and HChaCha20 and
/// ChaCha20 are XChaCha20.
#[test]
fn test_raw_primitives_compose_into_their_constructions() {
    let key = [0x24u8; 16];
    let nonce = [0x36u8; 12];
    let aad: Vec<u8> = (0..37u8).collect();

    let mut aes = AnyBlockCipher::new("aes", &key, None).unwrap();
    let mut h = Vec::new();
    aes.block_encrypt(&[0; 16], &mut h);
    let mut j0 = nonce.to_vec();
    j0.extend_from_slice(&[0, 0, 0, 1]);
    let mut mask = Vec::new();
    aes.block_encrypt(&j0, &mut mask);
    let mut blocks = aad.clone();
    blocks.resize(48, 0);
    blocks.extend_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    blocks.extend_from_slice(&0u64.to_be_bytes());
    let s = api::ghash(&h, &blocks).unwrap();
    let tag: Vec<u8> = s.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
    assert_eq!(api::gmac("aes", &key, &nonce, &aad, None).unwrap(), tag);
    assert_eq!(api::aead_encrypt("aes-gcm", &key, &nonce, &aad, b"").unwrap().1, tag);
    assert_eq!(api::gmac("aes", &key, &nonce, &aad, Some(8)).unwrap(), tag[..8]);
    assert!(api::ghash(&h, &blocks[..47]).is_err());
    assert!(api::ghash(&h[..15], &blocks).is_err());
    assert_eq!(api::ghash(&h, &[]).unwrap(), [0; 16]);
    assert!(api::gmac("des", &[0; 8], &nonce, &aad, None).is_err());

    // ChaCha20-Poly1305 (RFC 8439 2.8): the one-time key is block zero's
    // first 32 bytes, and the payload starts at block one.
    let key = [0x71u8; 32];
    let message = b"twenty-seven bytes of text.";
    let (ciphertext, tag) =
        api::aead_encrypt("chacha20-poly1305", &key, &nonce, &aad, message).unwrap();
    let mut chacha = AnyStreamCipher::new("chacha20", &key, &nonce).unwrap();
    let one_time = chacha.update(&[0; 32]).unwrap();
    chacha.seek(64).unwrap();
    assert_eq!(chacha.update(message).unwrap(), ciphertext);
    let mut mac_data = aad.clone();
    mac_data.resize(48, 0);
    mac_data.extend_from_slice(&ciphertext);
    mac_data.resize(48 + 32, 0);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    assert_eq!(api::poly1305(&one_time, &mac_data).unwrap(), tag);
    assert!(api::poly1305_verify(&one_time, &mac_data, &tag).unwrap());
    let mut altered = tag.clone();
    altered[15] ^= 1;
    assert!(!api::poly1305_verify(&one_time, &mac_data, &altered).unwrap());
    assert!(!api::poly1305_verify(&one_time, &mac_data, &tag[..15]).unwrap());
    assert!(api::poly1305(&one_time[..31], b"").is_err());

    // XChaCha20 (draft-irtf-cfrg-xchacha 2.3): ChaCha20 under
    // HChaCha20(key, nonce[..16]) with four zero bytes and nonce[16..].
    let long_nonce: Vec<u8> = (100..124u8).collect();
    let subkey = api::hchacha20(&key, &long_nonce[..16]).unwrap();
    let mut inner_nonce = vec![0u8; 4];
    inner_nonce.extend_from_slice(&long_nonce[16..]);
    assert_eq!(AnyStreamCipher::new("xchacha20", &key, &long_nonce).unwrap()
                   .update(&[0; 200]).unwrap(),
               AnyStreamCipher::new("chacha20", &subkey, &inner_nonce).unwrap()
                   .update(&[0; 200]).unwrap());
    assert!(api::hchacha20(&key[..16], &long_nonce[..16]).is_err());
    assert!(api::hchacha20(&key, &long_nonce[..15]).is_err());

    // The Salsa20 core: zero is its fixed point, and the round count
    // must be even.
    assert_eq!(api::salsa20_core(&[0; 64], 20).unwrap(), [0; 64]);
    assert_ne!(api::salsa20_core(&[1; 64], 20).unwrap(),
               api::salsa20_core(&[1; 64], 8).unwrap());
    assert!(api::salsa20_core(&[1; 64], 7).is_err());
    assert!(api::salsa20_core(&[1; 63], 8).is_err());
}

/// The GOST pieces through the facade, each tied to the thing it is a
/// piece of. The engine's answers for the MAC, CTR-ACPKM, KExp15 and
/// TLSTREE are in `tests/test_gost_engine_vectors.rs` and, through
/// Python, in `pytests/test_gost_primitives.py`.
#[test]
fn test_gost_primitives_through_the_api() {
    let key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(29).wrapping_add(3)).collect();
    let block = [0x5cu8, 0x11, 0x92, 0x07, 0xe4, 0x3a, 0x60, 0xbd];

    // S-boxes given directly are the named ones.
    let encrypt = |mut cipher: AnyBlockCipher| {
        let mut out = Vec::new();
        cipher.block_encrypt(&block, &mut out);
        out
    };
    for name in ["id-tc26-gost-28147-param-Z", "id-Gost28147-89-CryptoPro-B-ParamSet",
                 "dstu4145-default-dke"] {
        let rows = api::gost_sbox(name).unwrap();
        assert_eq!(encrypt(AnyBlockCipher::gost_with_sbox(&key, &rows).unwrap()),
                   encrypt(AnyBlockCipher::new("gost", &key, Some(name)).unwrap()), "{name}");
    }
    let dke = allcrypt::block_ciphers::gost::DSTU4145_DEFAULT_DKE;
    assert_eq!(encrypt(AnyBlockCipher::gost_with_dke(&key, &dke).unwrap()),
               encrypt(AnyBlockCipher::new("gost", &key, Some("dstu4145-default-dke")).unwrap()));
    let mut not_a_permutation = api::gost_sbox("id-tc26-gost-28147-param-Z").unwrap();
    not_a_permutation[3][5] = not_a_permutation[3][6];
    assert!(AnyBlockCipher::gost_with_sbox(&key, &not_a_permutation).is_err());
    assert!(AnyBlockCipher::gost_with_dke(&key, &dke[..63]).is_err());

    // The MAC: four bytes is RFC 9189's gost28147IMIT, and a longer tag
    // carries on into the rest of the state.
    let message = b"seventeen bytes!!";
    let iv = [0x0fu8; 8];
    let four = api::gost28147_mac(&key, message, Some("id-tc26-gost-28147-param-Z"), Some(&iv), 4)
        .unwrap();
    assert_eq!(four, allcrypt::tls::record_cnt_imit::gost28147imit(
        &iv, &key, message, "id-tc26-gost-28147-param-Z").unwrap());
    let eight = api::gost28147_mac(&key, message, Some("id-tc26-gost-28147-param-Z"), Some(&iv), 8)
        .unwrap();
    assert_eq!(eight.len(), 8);
    assert_eq!(eight[..4], four);
    // The defaults are CryptoPro-A and a zero IV, gost-engine's `gost-mac`.
    assert_eq!(api::gost28147_mac(&key, message, None, None, 4).unwrap(),
               api::gost28147_mac(&key, message, Some("id-Gost28147-89-CryptoPro-A-ParamSet"),
                                  Some(&[0; 8]), 4).unwrap());
    assert_ne!(api::gost28147_mac(&key, message, None, None, 4).unwrap(), four);
    for bad in [0usize, 9] {
        assert!(api::gost28147_mac(&key, message, None, None, bad).is_err());
    }
    assert!(api::gost28147_mac(&key, message, None, Some(&[0; 7]), 4).is_err());

    // Meshing, and that the new key is not the old one's encryption.
    let (meshed, meshed_iv) = api::cryptopro_key_mesh(&key, &iv, None).unwrap();
    assert_eq!((meshed.clone(), meshed_iv.clone()),
               allcrypt::block_ciphers::meshing::mesh(
                   "id-Gost28147-89-CryptoPro-A-ParamSet", &key, &iv).unwrap());
    assert_eq!(meshed.len(), 32);
    assert!(api::cryptopro_key_mesh(&key, &iv[..7], None).is_err());

    // CTR-ACPKM: within the first section it is plain CTR from
    // `nonce || 0`, and it is its own inverse.
    let nonce = [0x12u8, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0];
    let data: Vec<u8> = (0..200u8).collect();
    let k_key = [0x88u8; 32];
    let sealed = api::ctr_acpkm("kuznyechik", &k_key, &nonce, 4096, &data).unwrap();
    let mut counter = nonce.to_vec();
    counter.resize(16, 0);
    let mut plain_ctr = CipherStream::new(AnyBlockCipher::new("kuznyechik", &k_key, None).unwrap(),
                                          Mode::Ctr, &counter, false).unwrap();
    assert_eq!(plain_ctr.update(&data).unwrap(), sealed);
    assert_eq!(api::ctr_acpkm("kuznyechik", &k_key, &nonce, 4096, &sealed).unwrap(), data);
    // A section boundary inside the data changes what follows it only.
    let short_sections = api::ctr_acpkm("kuznyechik", &k_key, &nonce, 32, &data).unwrap();
    assert_eq!(short_sections[..32], sealed[..32]);
    assert_ne!(short_sections[32..64], sealed[32..64]);
    assert_eq!(api::acpkm_next("kuznyechik", &k_key).unwrap().len(), 32);
    assert!(api::ctr_acpkm("kuznyechik", &k_key, &nonce, 24, &data).is_err());

    // RFC 7836 4.5: KDF_256 is KDF_TREE with R = 1 and L = 256.
    assert_eq!(api::kdf_gostr3411_2012_256(&key, b"label", b"seed"),
               api::kdf_tree_gostr3411_2012_256(&key, b"label", b"seed", 32, 1).unwrap());
    let long = api::kdf_tree_gostr3411_2012_256(&key, b"label", b"seed", 64, 1).unwrap();
    assert_eq!(long.len(), 64);
    assert!(api::kdf_tree_gostr3411_2012_256(&key, b"label", b"seed", 64, 5).is_err());
    assert!(api::kdf_tree_gostr3411_2012_256(&key, b"label", b"seed", 0, 1).is_err());

    // TLSTREE: at sequence 0 every mask is zero, so every suite agrees
    // there; past the lowest level boundary of any of them they part.
    let at_zero: Vec<Vec<u8>> = api::TLSTREE_SUITES.iter()
        .map(|suite| api::tlstree(suite, &key, 0).unwrap()).collect();
    assert!(at_zero.windows(2).all(|pair| pair[0] == pair[1]));
    let later: std::collections::HashSet<Vec<u8>> = api::TLSTREE_SUITES.iter()
        .map(|suite| api::tlstree(suite, &key, 1 << 40 | 0xfff_ffff).unwrap()).collect();
    assert!(later.len() > 1);
    // Each name is its own suite's constants, which `kdf::gost`'s
    // document tests read out of RFC 9189 and RFC 9367; past the top
    // level boundary of all six, a name on the wrong set differs.
    use allcrypt::kdf::gost::{tlstree, TlsTreeParams};
    for (name, params) in [("kuznyechik-ctr-omac", TlsTreeParams::KUZNYECHIK),
                           ("magma-ctr-omac", TlsTreeParams::MAGMA),
                           ("kuznyechik-mgm-l", TlsTreeParams::KUZNYECHIK_MGM_L),
                           ("magma-mgm-l", TlsTreeParams::MAGMA_MGM_L),
                           ("kuznyechik-mgm-s", TlsTreeParams::KUZNYECHIK_MGM_S),
                           ("magma-mgm-s", TlsTreeParams::MAGMA_MGM_S)] {
        for sequence in [1u64 << 40 | 0xfff_ffff, u64::MAX, 0x0123_4567_89ab_cdef] {
            assert_eq!(api::tlstree(name, &key, sequence).unwrap(),
                       tlstree(&key, sequence, params), "{name}");
        }
    }
    assert!(api::tlstree("aes", &key, 0).is_err());
    assert!(api::tlstree("magma-ctr-omac", &key[..31], 0).is_err());

    // KExp15 and KImp15.
    let (mac_key, enc_key) = ([0x31u8; 32], [0x47u8; 32]);
    for (cipher, half_block) in [("kuznyechik", 8usize), ("magma", 4)] {
        let iv = vec![0x5au8; half_block];
        let wrapped = api::kexp15(cipher, &key, &mac_key, &enc_key, &iv).unwrap();
        assert_eq!(wrapped.len(), 32 + 2 * half_block);
        assert_eq!(api::kimp15(cipher, &wrapped, &mac_key, &enc_key, &iv).unwrap(), key);
        let mut altered = wrapped.clone();
        altered[5] ^= 1;
        assert!(api::kimp15(cipher, &altered, &mac_key, &enc_key, &iv).is_err());
        assert!(api::kimp15(cipher, &wrapped, &enc_key, &mac_key, &iv).is_err());
    }
    assert!(api::kexp15("aes", &key, &mac_key, &enc_key, &[0; 8]).is_err());
}

/// The derivations and 802.11 pieces through the facade, each tied to
/// the construction it is part of; their outside witnesses are in
/// `pytests/test_kdf_pieces.py` and `tests/test_pkcs12_kdf_vectors.rs`.
#[test]
fn test_kdf_and_wifi_pieces_through_the_api() {
    use allcrypt::api::AnyHash;

    // BLAKE2's parameter block: the defaults are the plain hash, and each
    // of key, salt and personalisation changes the answer.
    let digest = |mut h: AnyHash| { h.update(b"abc"); h.digest() };
    assert_eq!(digest(AnyHash::blake2("blake2b", 64, b"", b"", b"").unwrap()),
               digest(AnyHash::new("blake2b").unwrap()));
    assert_eq!(digest(AnyHash::blake2("blake2s", 16, b"", b"", b"").unwrap()),
               digest(AnyHash::new("blake2s_128").unwrap()));
    let plain = digest(AnyHash::blake2("blake2s", 32, b"", b"", b"").unwrap());
    for (key, salt, personal) in [(&b"k"[..], &b""[..], &b""[..]), (b"", b"saltsalt", b""),
                                  (b"", b"", b"personal")] {
        assert_ne!(digest(AnyHash::blake2("blake2s", 32, key, salt, personal).unwrap()), plain);
    }
    // Each argument reaches its own field of the module's parameter block.
    use allcrypt::hash_functions::blake2::{Blake2s, Params};
    let direct = Blake2s::with_params(&Params { digest_len: 20, key: b"key".to_vec(),
                                                salt: b"salt".to_vec(),
                                                personal: b"person".to_vec() }).unwrap();
    assert_eq!(digest(AnyHash::blake2("blake2s", 20, b"key", b"salt", b"person").unwrap()),
               digest(AnyHash::Blake2s(direct)));
    assert!(AnyHash::blake2("blake2s", 32, b"", b"nine byte", b"").is_err());
    assert!(AnyHash::blake2("blake2b", 65, b"", b"", b"").is_err());
    assert!(AnyHash::blake2("blake2b", 32, &[0; 65], b"", b"").is_err());
    assert!(AnyHash::blake2("blake3", 32, b"", b"", b"").is_err());

    // HKDF's halves are HKDF.
    let prk = api::hkdf_extract("sha256", b"salt", b"ikm").unwrap();
    assert_eq!(prk.len(), 32);
    assert_eq!(api::hkdf_expand("sha256", &prk, b"info", 100).unwrap(),
               api::hkdf("sha256", b"salt", b"ikm", b"info", 100).unwrap());
    assert!(api::hkdf_expand("sha256", &prk, b"", 255 * 32 + 1).is_err());

    // PBKDF1 is the hash iterated: once is one hash of password || salt.
    assert_eq!(api::pbkdf1("sha1", b"pw", b"saltsalt", 1, 20).unwrap(),
               digest_of("sha1", b"pwsaltsalt"));
    assert_eq!(api::pbkdf1("md5", b"pw", b"saltsalt", 2, 16).unwrap(),
               digest_of("md5", &digest_of("md5", b"pwsaltsalt")));
    assert!(api::pbkdf1("md5", b"pw", b"saltsalt", 1, 17).is_err());
    assert!(api::pbkdf1("md5", b"pw", b"saltsalt", 0, 16).is_err());

    assert!(api::pkcs12_kdf("sha1", b"", b"salt", 4, 1, 20).is_err());
    assert!(api::pkcs12_kdf("sha1", b"", b"salt", 0, 1, 20).is_err());

    let (key, iv) = api::jdk_pbe_md5_3des(b"password", b"8 bytes!", 20).unwrap();
    assert_eq!((key.len(), iv.len()), (24, 8));
    assert!(api::jdk_pbe_md5_3des(b"password", b"7 bytes", 20).is_err());

    for octets in [0usize, 1024, 1025, 65536, 65_011_712] {
        let coded = api::openpgp_s2k_coded_count(octets);
        assert!(api::openpgp_s2k_count(coded) >= octets, "{octets}");
        assert!(coded == 0 || api::openpgp_s2k_count(coded - 1) < octets, "{octets}");
    }
    assert_eq!(api::openpgp_s2k_coded_count(usize::MAX), 255);

    assert_eq!(api::bcrypt_pbkdf(b"pw", b"salt", 4, 48).unwrap().len(), 48);
    assert!(api::bcrypt_pbkdf(b"pw", b"salt", 0, 48).is_err());

    // BitLocker's password key is the stretch after two SHA-256s of the
    // UTF-16LE password.
    let salt = [0x2au8; 16];
    let utf16: Vec<u8> = "pass word".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let initial = digest_of("sha256", &digest_of("sha256", &utf16));
    assert_eq!(api::bitlocker_stretch(&initial, &salt).unwrap(),
               api::bitlocker_password_key("pass word", &salt).unwrap());
    assert!(api::bitlocker_stretch(&initial[..31], &salt).is_err());
    assert!(api::bitlocker_stretch(&initial, &salt[..15]).is_err());

    // The PTK is PRF-384 over the sorted addresses and nonces.
    let pmk = [0x55u8; 32];
    let (aa, spa) = ([0x02u8; 6], [0x01u8; 6]);
    let (anonce, snonce) = ([0x10u8; 32], [0x20u8; 32]);
    let mut data = Vec::new();
    data.extend_from_slice(&spa);
    data.extend_from_slice(&aa);
    data.extend_from_slice(&anonce);
    data.extend_from_slice(&snonce);
    assert_eq!(api::ieee80211_prf(&pmk, b"Pairwise key expansion", &data, 384).unwrap(),
               api::wpa_ptk("sha1", &pmk, &aa, &spa, &anonce, &snonce, 384).unwrap());
    assert_eq!(api::ieee80211_kdf_sha256(&pmk, b"Pairwise key expansion", &data, 384).unwrap(),
               api::wpa_ptk("sha256", &pmk, &aa, &spa, &anonce, &snonce, 384).unwrap());

    // A TKIP payload is RC4 under the frame's key over the plaintext and
    // its CRC-32, little endian.
    let (tk, ta) = ([0x77u8; 16], [0x08u8, 0, 0x27, 0x11, 0x22, 0x33]);
    let tsc = 0x0001_0000_fffe;
    let plaintext = b"an MPDU's payload";
    let sealed = api::tkip_encrypt(&tk, &ta, tsc, plaintext).unwrap();
    let mut with_icv = plaintext.to_vec();
    with_icv.extend_from_slice(&crc32(plaintext).to_le_bytes());
    let rc4_key = api::tkip_rc4_key(&tk, &ta, tsc).unwrap();
    assert_eq!(sealed, AnyStreamCipher::new("rc4", &rc4_key, &[]).unwrap().update(&with_icv)
                           .unwrap());
    assert_eq!(api::tkip_decrypt(&tk, &ta, tsc, &sealed).unwrap(), plaintext);
    let mut altered = sealed.clone();
    altered[3] ^= 1;
    assert!(api::tkip_decrypt(&tk, &ta, tsc, &altered).is_err());
    assert!(api::tkip_encrypt(&tk, &ta, 1 << 48, plaintext).is_err());
    assert!(api::tkip_rc4_key(&tk, &ta, 1 << 48).is_err());

    // The MSDU MIC is Michael over DA, SA, the priority and three zeros.
    let (da, sa) = ([1u8; 6], [2u8; 6]);
    let mut mic_input = [da, sa].concat();
    mic_input.extend_from_slice(&[5, 0, 0, 0]);
    mic_input.extend_from_slice(b"data");
    assert_eq!(api::tkip_msdu_mic(&[9; 8], &da, &sa, 5, b"data").unwrap(),
               api::michael(&[9; 8], &mic_input).unwrap());
    assert!(api::tkip_msdu_mic(&[9; 7], &da, &sa, 5, b"data").is_err());
    assert!(api::tkip_msdu_mic(&[9; 8], &da[..5], &sa, 5, b"data").is_err());
}

fn digest_of(name: &str, data: &[u8]) -> Vec<u8> {
    let mut hash = AnyHash::new(name).unwrap();
    hash.update(data);
    hash.digest()
}

/// CRC-32 (IEEE 802.3), bit by bit, for the TKIP ICV.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// RFC 9189's key agreements and the 28147 export through the facade:
/// both ends of each agreement derive the same keys, the 28147 KEG is
/// VKO-256 under `H[1..8]` diversified under TC26-Z, and the export
/// round-trips and refuses a wrong IV or MAC. The RFC's own worked
/// handshakes are `pytests/test_gost_key_export.py` and
/// `tests/test_gost_rfc9189_flight.rs`.
#[test]
fn test_gost_key_agreement_and_28147_export_through_the_api() {
    use allcrypt::api::EcKey;
    let h: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(13).wrapping_add(1)).collect();
    for curve in ["gost256-a", "gost512-a", "gost256-tc26-a", "gost512-c"] {
        let size = if curve.starts_with("gost256") { 32 } else { 64 };
        let a = EcKey::from_private(curve, &vec![0x11; size]).unwrap();
        let b = EcKey::from_private(curve, &vec![0x07; size]).unwrap();
        let (pa, pb) = (a.public_key().to_bytes(false).unwrap(),
                        b.public_key().to_bytes(false).unwrap());
        let keys = a.gost_keg(&pb, &h).unwrap();
        assert_eq!(keys.len(), 64, "{curve}");
        assert_eq!(keys, b.gost_keg(&pa, &h).unwrap(), "{curve}");
        let k28147 = a.gost_keg_28147(&pb, &h).unwrap();
        assert_eq!(k28147, b.gost_keg_28147(&pa, &h).unwrap(), "{curve}");
        let vko = a.vko(&pb, &h[..8], 256).unwrap();
        assert_eq!(k28147, api::cryptopro_kek_diversify(&h[..8], &vko,
                                                        Some("id-tc26-gost-28147-param-Z"))
                               .unwrap(), "{curve}");
        assert!(a.gost_keg(&pb, &h[..31]).is_err());
        assert!(a.gost_keg_28147(&pb, &h[..31]).is_err());
    }
    let a = EcKey::from_private("gost256-a", &[0x23; 32]).unwrap();
    let b = EcKey::from_private("gost256-a", &[0x45; 32]).unwrap();
    let ukm = [0x5au8; 8];
    let (pa, pb) = (a.public_key().to_bytes(false).unwrap(),
                    b.public_key().to_bytes(false).unwrap());
    assert_eq!(a.gost_keg_2001(&pb, &ukm).unwrap(),
               b.gost_keg_2001(&pa, &ukm).unwrap());
    assert!(a.gost_keg_2001(&pb, &ukm[..7]).is_err());

    let key = [0x3cu8; 32];
    let secret: Vec<u8> = (0..32u8).collect();
    let iv = [0x9eu8; 8];
    let wrapped = api::kexp28147(&secret, &key, &iv, None).unwrap();
    assert_eq!(wrapped.len(), 44);
    assert_eq!(wrapped[..8], iv);
    assert_eq!(wrapped[40..], api::gost28147_mac(&key, &secret, None, Some(&iv), 4).unwrap());
    assert_eq!(api::kimp28147(&wrapped, &key, &iv, None).unwrap(), secret);
    assert_ne!(api::kexp28147(&secret, &key, &iv, Some("id-tc26-gost-28147-param-Z")).unwrap(),
               wrapped);
    let mut altered = wrapped.clone();
    altered[43] ^= 1;
    assert!(api::kimp28147(&altered, &key, &iv, None).is_err());
    assert!(api::kimp28147(&wrapped, &key, &[0; 8], None).is_err());
    assert!(api::kexp28147(&secret[..31], &key, &iv, None).is_err());
    assert_ne!(api::cryptopro_kek_diversify(&iv, &key, None).unwrap(),
               api::cryptopro_kek_diversify(&iv, &key, Some("id-tc26-gost-28147-param-Z"))
                   .unwrap());
    assert!(api::cryptopro_kek_diversify(&iv[..7], &key, None).is_err());
}
