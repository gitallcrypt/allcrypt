use allcrypt::hash_functions::{blake2, keccak, md2, md4, md5, ripemd160, sha1,
                               sha2, sm3, whirlpool, HashFunction};
use allcrypt::stream_ciphers::{chacha, rc4, salsa20, zipcrypto, StreamCipher};
use allcrypt::to_hex;

fn data(n: usize) -> Vec<u8> { (0..n).map(|i| ((i*167+13)&0xff) as u8).collect() }
fn key(n: usize) -> Vec<u8> { (0..n).map(|i| ((i*89+7)&0xff) as u8).collect() }

fn main() {
    let mut lens: Vec<usize> = (0..=300).collect();
    lens.extend_from_slice(&[1000, 4096, 100000]);

    for n in &lens {
        let d = data(*n);
        let mut h = md2::Md2::new(&d);    println!("md2/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = md4::Md4::new(&d);    println!("md4/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = md5::MD5::new(&d);    println!("md5/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = sha1::SHA1::new(&d);  println!("sha1/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = sha2::SHA224::new(&d); println!("sha224/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = sha2::SHA256::new(&d); println!("sha256/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = sha2::SHA384::new(&d); println!("sha384/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = sha2::SHA512::new(&d, 512); println!("sha512/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = sha2::SHA512::new(&d, 224); println!("sha512_224/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = sha2::SHA512::new(&d, 256); println!("sha512_256/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = blake2::Blake2b::new(&d); println!("blake2b/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = blake2::Blake2s::new(&d); println!("blake2s/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = ripemd160::Ripemd160::new(&d); println!("ripemd160/{} {}", n, to_hex(&h.digest()).to_lowercase());
        let mut h = sm3::Sm3::new(&d); println!("sm3/{} {}", n, to_hex(&h.digest()).to_lowercase());
        // Whirlpool. `hashlib` has no such thing, but OpenSSL keeps it
        // in the legacy provider - so these rows are checked against a
        // real implementation rather than against a second reading of
        // the specification, for as long as that provider exists.
        let mut h = whirlpool::Whirlpool::new(&d); println!("whirlpool/{} {}", n, to_hex(&h.digest()).to_lowercase());
        for bits in [224usize, 256, 384, 512] {
            let mut h = keccak::Keccak::sha3(bits / 8).unwrap();
            h.update(&d);
            println!("sha3_{}/{} {}", bits, n, to_hex(&h.digest()).to_lowercase());
        }
        // The pre-standard padding. hashlib has no such thing, so these
        // rows are checked against a Keccak written independently in
        // `scripts/diff_check.py` - and pinned to Ethereum's published
        // function selectors in the unit tests, which is the one number
        // in this repository that nothing here could have influenced.
        for bits in [256usize, 512] {
            let mut h = keccak::Keccak::keccak(bits / 8).unwrap();
            h.update(&d);
            println!("keccak_{}/{} {}", bits, n, to_hex(&h.digest()).to_lowercase());
        }
    }

    // BLAKE2's parameter block: every output length, and the keyed,
    // salted and personalised forms. The length is part of the function
    // rather than a truncation, so each one is a separate row - an
    // implementation that hashed at full width and truncated would pass
    // the rows above and fail every one of these.
    for out_len in 1..=64usize {
        let mut h = blake2::Blake2b::with_length(out_len).unwrap();
        h.update(&data(100));
        println!("blake2blen/{} {}", out_len, to_hex(&h.digest()).to_lowercase());
        if out_len <= 32 {
            let mut h = blake2::Blake2s::with_length(out_len).unwrap();
            h.update(&data(100));
            println!("blake2slen/{} {}", out_len, to_hex(&h.digest()).to_lowercase());
        }
    }
    for key_len in [0usize, 1, 16, 32, 63, 64] {
        let mut h = blake2::Blake2b::keyed(&key(key_len), 64).unwrap();
        h.update(&data(100));
        println!("blake2bkey/{} {}", key_len, to_hex(&h.digest()).to_lowercase());
    }
    for key_len in [0usize, 1, 16, 31, 32] {
        let mut h = blake2::Blake2s::keyed(&key(key_len), 32).unwrap();
        h.update(&data(100));
        println!("blake2skey/{} {}", key_len, to_hex(&h.digest()).to_lowercase());
    }
    {
        let mut h = blake2::Blake2b::with_params(&blake2::Params {
            digest_len: 64, key: key(16), salt: data(16), personal: key(16),
        }).unwrap();
        h.update(&data(100));
        println!("blake2bfull {}", to_hex(&h.digest()).to_lowercase());
        let mut h = blake2::Blake2s::with_params(&blake2::Params {
            digest_len: 32, key: key(16), salt: data(8), personal: key(8),
        }).unwrap();
        h.update(&data(100));
        println!("blake2sfull {}", to_hex(&h.digest()).to_lowercase());
    }

    // ChaCha20, RFC 8439 layout: 12 byte nonce, counter starts at 0.
    let key: Vec<u8> = (0..32).map(|i| ((i*89+7)&0xff) as u8).collect();
    let nonce: Vec<u8> = (0..12).map(|i| ((i*211+5)&0xff) as u8).collect();
    for n in &lens {
        let d = data(*n);
        let mut c = chacha::Chacha::new(&key, &nonce, 20).unwrap();
        let mut out = vec![];
        c.crypt(&d, &mut out);
        println!("chacha20/{} {}", n, to_hex(&out).to_lowercase());
    }
    // Streaming: irregular splits must equal one-shot.
    for split in [1usize,2,3,7,15,16,17,31,32,33,63,64,65,100,127,128,129] {
        let d = data(1000);
        let mut c = chacha::Chacha::new(&key, &nonce, 20).unwrap();
        let mut out = vec![];
        let mut i = 0; let mut step = split;
        while i < d.len() {
            let e = std::cmp::min(d.len(), i+step);
            c.crypt(&d[i..e], &mut out);
            i = e; step = step*2+1;
        }
        println!("chacha20stream/{} {}", split, to_hex(&out).to_lowercase());
    }
    for kl in [1usize,2,5,16,32,64] {
        let k: Vec<u8> = (0..kl).map(|i| ((i*89+7)&0xff) as u8).collect();
        for n in [0usize,1,16,63,64,65,256,300,1024] {
            let mut c = rc4::RC4::new(&k).unwrap();
            let mut out = vec![];
            c.crypt(&data(n), &mut out);
            println!("rc4/{}/{} {}", kl, n, to_hex(&out).to_lowercase());
        }
    }

    // ZipCrypto, both directions: its keys absorb the plaintext, so
    // decrypting is not encrypting again and each needs its own rows.
    // CPython's `zipfile` has the only other implementation here.
    for pl in [0usize, 1, 2, 5, 16, 64, 200] {
        let pw: Vec<u8> = (0..pl).map(|i| ((i*89+7)&0xff) as u8).collect();
        for n in [0usize, 1, 2, 12, 13, 100, 255, 256, 1000] {
            let mut out = vec![];
            zipcrypto::ZipCrypto::new(&pw).encrypt(&data(n), &mut out);
            println!("zipcrypto-enc/{}/{} {}", pl, n, to_hex(&out).to_lowercase());
            let mut out = vec![];
            zipcrypto::ZipCrypto::new(&pw).decrypt(&data(n), &mut out);
            println!("zipcrypto-dec/{}/{} {}", pl, n, to_hex(&out).to_lowercase());
        }
    }

    // Salsa20. No reference library on this machine implements it, so
    // these rows are checked against a Salsa20 written independently in
    // `scripts/diff_check.py` from Bernstein's specification - the same
    // arrangement as the GOST and SSLv3 rows, and for the same reason.
    let salsa_key: Vec<u8> = (0..32).map(|i| ((i*89+7)&0xff) as u8).collect();
    let salsa_nonce: Vec<u8> = (0..8).map(|i| ((i*211+5)&0xff) as u8).collect();
    for n in &lens {
        let d = data(*n);
        for rounds in [20usize, 12, 8] {
            let mut c = salsa20::Salsa20::with_rounds(
                &salsa_key, &salsa_nonce, rounds).unwrap();
            let mut out = vec![];
            c.crypt(&d, &mut out);
            println!("salsa{}/{} {}", rounds, n, to_hex(&out).to_lowercase());
        }
    }
    // A 128 bit key takes the TAU constants rather than SIGMA, so it is
    // a different cipher and not a doubled key.
    for n in &[0usize, 1, 63, 64, 65, 200] {
        let mut c = salsa20::Salsa20::new(
            &salsa_key[..16], &salsa_nonce).unwrap();
        let mut out = vec![];
        c.crypt(&data(*n), &mut out);
        println!("salsa20short/{} {}", n, to_hex(&out).to_lowercase());
    }

    // SHAKE, across output lengths that straddle both rates (168 and
    // 136) - the boundary where the sponge has to permute again.
    for out_len in [1usize, 16, 32, 100, 135, 136, 137, 167, 168, 169, 400, 1000] {
        for bits in [128usize, 256] {
            let mut h = keccak::Keccak::shake(bits, out_len).unwrap();
            h.update(&data(100));
            println!("shake_{}/{} {}", bits, out_len,
                     to_hex(&h.squeeze(out_len)).to_lowercase());
        }
    }
}
