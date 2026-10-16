# allcrypt

Implementations of common and uncommon cryptographic algorithms in pure
Rust. It is meant for people who have to, or just want to, work with old
crypto: opening an encrypted volume or archive from years ago, talking to
a device that only speaks TLS 1.0 and RC4, verifying a signature made
with MD5, or studying how an algorithm actually works.

Nothing is deprecated or removed for being weak. If an algorithm is
historically interesting or still turns up in the wild, it belongs here.
The point is to have it available and correct, not to gatekeep which
ciphers you are allowed to use and look at. The broken ones are never
chosen for you, though: RC4, 3DES, export ciphers and SSLv3 have to be
asked for by name, and the defaults are modern. For new designs, use
them.

The code is written to be as robust as it can be. Anything
unimplemented returns an error rather than silently doing nothing, and
everything is checked against a second implementation wherever one
exists. Correctness and coverage come first; speed comes second.

This is an early public beta and has not been independently audited.
Missing algorithms, modes and file formats are welcome in
[the repository](https://github.com/gitallcrypt/allcrypt); please
include a description and test vectors.

This page covers the Rust library and the proxy built with it. The
Python module, the C interface, the OpenSSL shim, the test suite and the
full documentation are in the repository.

## What is in it

- **Block ciphers**, about fifty, from AES, Camellia, Serpent and Twofish
  to DES, IDEA, RC2, Skipjack, FEAL, GOST 28147-89, Kuznyechik, Kalyna,
  SM4, Simon, Speck and Threefish, in every mode their block size allows:
  ECB, CBC, CFB, OFB, CTR, ciphertext stealing, XTS, GCM, CCM, EAX, OCB,
  MGM, key wrap and more.
- **Stream ciphers**: ChaCha20, Salsa20, their X variants, RC4, Strumok.
- **Hashes**: MD2 to SHA-3, BLAKE to BLAKE3, the SHA-3 finalists,
  RIPEMD, Whirlpool, Tiger, HAVAL, Snefru, Streebog, GOST R 34.11-94,
  Kupyna, SM3, LSH, ssdeep, xxHash, MurmurHash3 and the common checksums.
- **MACs and KDFs**: HMAC, CMAC, Poly1305, UMAC, SipHash, PBKDF2, scrypt,
  Argon2, HKDF, and the KDFs particular formats define.
- **Public key**: RSA, DSA, Diffie-Hellman, ElGamal, ECDSA and ECDH,
  X25519, X448, Ed25519, Ed448, GOST R 34.10, SM2, DSTU 4145, and the
  post-quantum ML-KEM, ML-DSA, SLH-DSA and NTRU Prime.
- **Certificates and protocols**: X.509 parsing, verification and
  issuing, CRLs and OCSP, PKCS#8 and PEM keys; TLS 1.0 to 1.3 and SSH,
  client and server.

[status.md](https://github.com/gitallcrypt/allcrypt/blob/HEAD/docs/status.md)
lists every algorithm and what checked it.

## Using it

```sh
cargo add allcrypt
```

Each algorithm has its own type, and every family also has one entry
point that takes a name:

```rust
use allcrypt::api::{self, AnyHash};
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::{BlockCipher, Ctr};
use allcrypt::hash_functions::{sha2, HashFunction};

fn main() -> Result<(), String> {
    // A hash by type, and the same hash by name.
    let mut hash = sha2::SHA256::new(b"abc");
    let mut by_name = AnyHash::new("sha256")?;
    by_name.update(b"abc");
    assert_eq!(hash.digest(), by_name.digest());

    // AES in CTR mode, streamed in as many pieces as you like.
    let mut cipher = AesCrypto::new(&[0u8; 16])?;
    let mut stream = Ctr::new(&mut cipher, &[0u8; 16])?;
    let mut out = Vec::new();
    stream.update(b"first piece ", &mut out)?;
    stream.update(b"second piece", &mut out)?;

    // An AEAD in one call each way.
    let (ciphertext, tag) = api::aead_encrypt(
        "chacha20-poly1305", &[7u8; 32], &[0u8; 12], b"header", b"message")?;
    let plaintext = api::aead_decrypt(
        "chacha20-poly1305", &[7u8; 32], &[0u8; 12], b"header", &ciphertext, &tag)?;
    assert_eq!(plaintext, b"message");
    Ok(())
}
```

Everything that can fail returns `Result<_, String>`, and nothing panics
on bad input.
[rust.md](https://github.com/gitallcrypt/allcrypt/blob/HEAD/docs/rust.md)
is the guide, family by family.

## Features

| feature | what it adds |
| --- | --- |
| `aes-ni` | AES and GHASH on the x86-64 instructions, chosen at run time |
| `sha-ni` | SHA-1 and SHA-256 on the x86-64 SHA extensions, chosen at run time |
| `simd` | ChaCha20 on SSE2 and AVX2 |
| `c-api` | the C interface; the header is `include/allcrypt.h` |
| `python` | the Python module's bindings, which the repository's build script turns into a module |

All are off by default; the first three because they need `unsafe` to
reach the instructions.

## The proxy

The crate also installs `allcrypt-proxy`, a local HTTPS proxy for
browsers, which link their TLS library statically so nothing can be put
underneath them. It terminates TLS on one side and speaks whatever the
old box speaks on the other:

```sh
cargo install allcrypt
allcrypt-proxy --legacy --port 8080
```

Point the browser's HTTPS proxy at 127.0.0.1:8080 and import the
`ca.pem` it writes into `~/.allcrypt-proxy`. The proxy **mirrors** the
real certificate - subject, names, validity and serial - and signs with
its CA only when the real chain verified, so the browser warns exactly
when it would have warned without it. **Installing that CA means
anything holding its key can impersonate any site to that browser**;
[proxy.md](https://github.com/gitallcrypt/allcrypt/blob/HEAD/docs/proxy.md)
says what you are agreeing to.

## Everything else is in the repository

The crate carries the library and nothing to test it with. These need a
checkout of [github.com/gitallcrypt/allcrypt](https://github.com/gitallcrypt/allcrypt):

- the **test suite**, the recorded vectors and the scripts that check the
  library against OpenSSL, OpenSSH, GnuPG and the other implementations
  it is compared with ([building.md](https://github.com/gitallcrypt/allcrypt/blob/HEAD/docs/building.md));
- the **Python module** and its drop-in `ssl` replacement ([python.md](https://github.com/gitallcrypt/allcrypt/blob/HEAD/docs/python.md));
- the **C interface**'s documentation and test program ([c.md](https://github.com/gitallcrypt/allcrypt/blob/HEAD/docs/c.md));
- the **OpenSSL shim**, a `libssl.so` that lets `curl`, `wget` and `git` reach servers OpenSSL refuses ([shim.md](https://github.com/gitallcrypt/allcrypt/blob/HEAD/docs/shim.md));
- the **products**: LUKS, VeraCrypt, age, OpenPGP, KeePass, ZIP, PDF, Office and more, built from the library;
- [pitfalls.md](https://github.com/gitallcrypt/allcrypt/blob/HEAD/docs/pitfalls.md), the list of side channels, correctness traps and protocol hazards, each marked mitigated, accepted or open.

## License

0BSD.
