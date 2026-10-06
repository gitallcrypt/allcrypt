// Dumps ciphertext for a deterministic set of cases so an independent
// implementation (OpenSSL via python-cryptography) can be compared against it.
// Output format: one "label hex" line per case.

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::camellia::Camellia;
use allcrypt::block_ciphers::cast5::Cast5;
use allcrypt::block_ciphers::idea::Idea;
use allcrypt::block_ciphers::seed::Seed;
use allcrypt::block_ciphers::sm4::Sm4;
use allcrypt::block_ciphers::blowfish::Blowfish;
use allcrypt::block_ciphers::des::{Des, TripleDes};
use allcrypt::block_ciphers::rc2::RC2;
use allcrypt::block_ciphers::aria::Aria;
use allcrypt::block_ciphers::rc5::Rc5;
use allcrypt::block_ciphers::tea::{Tea, Xtea};
use allcrypt::block_ciphers::{BlockCipher, Cbc, Cfb, Ctr, CtsVariant, Ofb};
use allcrypt::to_hex;

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 167 + 13) & 0xff) as u8).collect()
}
fn key(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 89 + 7) & 0xff) as u8).collect()
}
fn iv(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 211 + 5) & 0xff) as u8).collect()
}

fn lengths(bs: usize, aligned_only: bool) -> Vec<usize> {
    let mut v: Vec<usize> = (0..=136).collect();
    v.extend_from_slice(&[255, 256, 257, 511, 512, 513, 1023, 1024]);
    if aligned_only {
        v.retain(|n| n % bs == 0);
    }
    v
}

fn emit(label: &str, bytes: &[u8]) {
    println!("{} {}", label, to_hex(bytes).to_lowercase());
}

/// Run every mode for one cipher instance factory.
fn run<F>(name: &str, bs: usize, keylen: usize, mut make: F)
where F: FnMut() -> Box<dyn BlockCipher> {
    let k = key(keylen);
    let v = iv(bs);
    let _ = k;

    for n in lengths(bs, true) {
        let p = data(n);
        let mut c = make();
        let mut out = vec![];
        c.ecb_encrypt(&p, &mut out).unwrap();
        emit(&format!("{}/{}/ecb/{}", name, keylen, n), &out);

        let mut back = vec![];
        let mut c = make();
        c.ecb_decrypt(&out, &mut back).unwrap();
        assert_eq!(back, p, "{} ecb roundtrip {}", name, n);

        let mut out = vec![];
        let mut c = make();
        c.cbc_encrypt(&p, &mut out, v.clone()).unwrap();
        emit(&format!("{}/{}/cbc/{}", name, keylen, n), &out);
        let mut back = vec![];
        let mut c = make();
        c.cbc_decrypt(&out, &mut back, v.clone()).unwrap();
        assert_eq!(back, p, "{} cbc roundtrip {}", name, n);
    }

    for n in lengths(bs, false) {
        let p = data(n);

        for mode in ["cfb", "ofb", "ctr"] {
            let mut out = vec![];
            let mut c = make();
            match mode {
                "cfb" => c.cfb_encrypt(&p, &mut out, v.clone()).unwrap(),
                "ofb" => c.ofb_encrypt(&p, &mut out, v.clone()).unwrap(),
                _     => c.ctr_encrypt(&p, &mut out, &v).unwrap(),
            }
            emit(&format!("{}/{}/{}/{}", name, keylen, mode, n), &out);

            let mut back = vec![];
            let mut c = make();
            match mode {
                "cfb" => c.cfb_decrypt(&out, &mut back, v.clone()).unwrap(),
                "ofb" => c.ofb_decrypt(&out, &mut back, v.clone()).unwrap(),
                _     => c.ctr_decrypt(&out, &mut back, &v).unwrap(),
            }
            assert_eq!(back, p, "{} {} roundtrip {}", name, mode, n);
        }
    }

    // CBC with ciphertext stealing, both directions, at every length of
    // at least a block; and CTR with a little-endian counter. OpenSSL has
    // CTS for AES and Camellia only (`AES-128-CBC-CTS` and friends, CS1
    // to CS3), so the rows are for those two.
    if name == "aes" || name == "camellia" {
        let variants = [("cbc-cs1", CtsVariant::Cs1), ("cbc-cs2", CtsVariant::Cs2),
                        ("cbc-cs3", CtsVariant::Cs3)];
        for n in lengths(bs, false).into_iter().filter(|&n| n >= bs) {
            let p = data(n);
            for (label, variant) in variants {
                let mut out = vec![];
                make().cbc_cs_encrypt(&p, &mut out, &v, variant).unwrap();
                emit(&format!("{}/{}/{}/{}", name, keylen, label, n), &out);
                let mut back = vec![];
                make().cbc_cs_decrypt(&out, &mut back, &v, variant).unwrap();
                assert_eq!(back, p, "{} {} roundtrip {}", name, label, n);
                // Decrypting bytes nobody encrypted: the corpus data
                // itself, taken as ciphertext.
                let mut plain = vec![];
                make().cbc_cs_decrypt(&p, &mut plain, &v, variant).unwrap();
                emit(&format!("{}/{}/{}-dec/{}", name, keylen, label, n), &plain);
            }
        }
    }
    if name == "aes" {
        for n in lengths(bs, false) {
            let p = data(n);
            let mut out = vec![];
            make().ctr_le_encrypt(&p, &mut out, &v).unwrap();
            emit(&format!("{}/{}/ctr-le/{}", name, keylen, n), &out);
        }
    }

    // Streaming must agree with one-shot, for every awkward split.
    let splits: &[usize] = &[1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100];
    let p = data(640); // divisible by both 8 and 16
    for &s in splits {
        let chunks: Vec<&[u8]> = {
            let mut v2 = vec![];
            let mut i = 0;
            let mut step = s;
            while i < p.len() {
                let e = std::cmp::min(p.len(), i + step);
                v2.push(&p[i..e]);
                i = e;
                step = step * 2 + 1; // keep the chunk sizes irregular
            }
            v2
        };

        let mut one = vec![];
        let mut c = make();
        c.ctr_encrypt(&p, &mut one, &v).unwrap();
        let mut c = make();
        let mut streamed = vec![];
        {
            let mut m = Ctr::new(&mut *c, &v).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
        }
        assert_eq!(one, streamed, "{} ctr streaming split {}", name, s);

        let mut one = vec![];
        let mut c = make();
        c.cfb_encrypt(&p, &mut one, v.clone()).unwrap();
        let mut c = make();
        let mut streamed = vec![];
        {
            let mut m = Cfb::encryptor(&mut *c, &v).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
        }
        assert_eq!(one, streamed, "{} cfb streaming split {}", name, s);

        let mut one = vec![];
        let mut c = make();
        c.cfb_decrypt(&p, &mut one, v.clone()).unwrap();
        let mut c = make();
        let mut streamed = vec![];
        {
            let mut m = Cfb::decryptor(&mut *c, &v).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
        }
        assert_eq!(one, streamed, "{} cfb-dec streaming split {}", name, s);

        let mut one = vec![];
        let mut c = make();
        c.ofb_encrypt(&p, &mut one, v.clone()).unwrap();
        let mut c = make();
        let mut streamed = vec![];
        {
            let mut m = Ofb::new(&mut *c, &v).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
        }
        assert_eq!(one, streamed, "{} ofb streaming split {}", name, s);

        // CBC buffers partial blocks across calls.
        let mut one = vec![];
        let mut c = make();
        c.cbc_encrypt(&p, &mut one, v.clone()).unwrap();
        let mut c = make();
        let mut streamed = vec![];
        {
            let mut m = Cbc::encryptor(&mut *c, &v).unwrap();
            for ch in &chunks { m.update(ch, &mut streamed).unwrap(); }
            m.finish().unwrap();
        }
        assert_eq!(one, streamed, "{} cbc streaming split {}", name, s);

        let mut back = vec![];
        let mut c = make();
        {
            let mut m = Cbc::decryptor(&mut *c, &v).unwrap();
            for ch in one.chunks(s.max(1)) { m.update(ch, &mut back).unwrap(); }
            m.finish().unwrap();
        }
        assert_eq!(back, p, "{} cbc-dec streaming split {}", name, s);
    }
    eprintln!("{} keylen {}: streaming and roundtrip checks passed", name, keylen);
}

fn main() {
    for kl in [16usize, 24, 32] {
        run("aes", 16, kl, move || Box::new(AesCrypto::new(key(kl)).unwrap()));
    }
    for kl in [4usize, 8, 16, 32, 56] {
        run("blowfish", 8, kl, move || Box::new(Blowfish::new(key(kl))));
    }
    // DES and Triple DES. OpenSSL still has 3DES - deprecated, in the
    // "decrepit" module, but present - so unlike RC4 these can be checked
    // against it properly rather than against a reference written here.
    // Single DES goes through the same comparison by giving 3DES a
    // repeated key, which is exactly what EDE mode is for.
    run("des", 8, 8, || Box::new(Des::new(key(8)).unwrap()));
    for kl in [8usize, 16, 24] {
        run("3des", 8, kl, move || Box::new(TripleDes::new(key(kl)).unwrap()));
    }
    // RC2, at the one key length OpenSSL's binding will accept - 128 bits,
    // which is also the length TLS's export suites expand to. The other
    // key lengths are covered by the RFC 2268 vectors in the unit tests,
    // and the effective-key-length parameter by `diff_rc2.rs`, which needs
    // a reference written from the specification because no library
    // interface exposes it.
    run("rc2", 8, 16, || Box::new(RC2::new(&key(16)).unwrap()));

    // The set python-cryptography has moved, or is moving, to
    // `hazmat.decrepit`. Every one of them still has a working
    // reference on this machine *today*, which is the whole reason
    // they are here now rather than later - see docs/pitfalls.md.
    run("idea", 8, 16, || Box::new(Idea::new(key(16)).unwrap()));
    run("seed", 16, 16, || Box::new(Seed::new(key(16)).unwrap()));
    run("sm4", 16, 16, || Box::new(Sm4::new(key(16)).unwrap()));
    for kl in [16usize, 24, 32] {
        run("camellia", 16, kl, move || Box::new(Camellia::new(key(kl)).unwrap()));
    }
    // CAST5 across the 80 bit boundary, where the round count changes
    // from twelve to sixteen - so these are two ciphers, not one with
    // two key lengths.
    for kl in [5usize, 8, 10, 11, 16] {
        run("cast5", 8, kl, move || Box::new(Cast5::new(&key(kl)).unwrap()));
    }

    // TEA and XTEA. Neither is in python-cryptography or in OpenSSL, so
    // the reference is written in `scripts/diff_check.py` from the
    // papers - the same position the GOST ciphers are in. The published
    // vectors in `src/block_ciphers/tea.rs` settle the primitive; what
    // these rows are for is the *modes* over a 64 bit block at every
    // awkward length, which no vector file covers.
    run("tea", 8, 16, || Box::new(Tea::new(&key(16)).unwrap()));
    run("xtea", 8, 16, || Box::new(Xtea::new(&key(16)).unwrap()));

    // RC5, at the nominal twelve rounds and at two key lengths that
    // bracket the word boundary - five bytes is two `L` words with the
    // second zero-padded, sixteen is four full ones. Same reference
    // situation as TEA: nothing else on this machine has RC5.
    for kl in [5usize, 16] {
        run("rc5", 8, kl, move || Box::new(Rc5::new(&key(kl)).unwrap()));
    }

    // ARIA, at all three key sizes - and unlike TEA and RC5 this one
    // has a real third party: OpenSSL implements it, and
    // `scripts/diff_check.py` pins its own reference to OpenSSL before
    // using it for the sweep.
    for kl in [16usize, 24, 32] {
        run("aria", 16, kl, move || Box::new(Aria::new(&key(kl)).unwrap()));
    }
}
