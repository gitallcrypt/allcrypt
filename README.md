# Allcrypt

Implementations of common and uncommon cryptographic algorithms in pure
Rust, with Python and C bindings. It is meant for people who have to, or
just want to, work with old crypto: opening an encrypted volume or
archive from years ago, talking to a device that only speaks TLS 1.0 and
RC4, verifying a signature made with MD5, or studying how an algorithm
actually works.

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
Missing algorithms, modes and file formats are welcome; please include a
description and test vectors.

## What is in it

- **Block ciphers** - AES, ARIA, Blowfish, Camellia, CAST5, DES and 3DES,
  GOST 28147-89, IDEA, Kuznyechik, Magma, RC2, RC5, SEED, Serpent, SM4,
  TEA, Twofish, XTEA - in the modes each one's block size allows: ECB,
  CBC, PCBC, CFB, OFB, CTR, ciphertext stealing, XTS, LRW, GCM, CCM,
  EAX, OCB, MGM and key wrap.
- **Stream ciphers** - ChaCha20 and XChaCha20, Salsa20, RC4, ZipCrypto,
  and WEP and TKIP's constructions on top of them.
- **Hashes** - MD2, MD4, MD5, SHA-0 to SHA-3, SHAKE, Keccak, BLAKE2,
  RIPEMD-128 to -320, HAS-160, SM3, Whirlpool and its two earlier
  versions, Streebog and GOST R 34.11-94.
- **MACs and key derivation** - HMAC, CMAC, CBC-MAC, Poly1305, UMAC;
  PBKDF1 and 2, scrypt, Argon2, HKDF, SP 800-108, Windows's NT and LM
  hashes, and the KDFs that particular formats and protocols define.
- **Public key** - RSA (PKCS#1 v1.5, OAEP, PSS), DSA, Diffie-Hellman,
  ElGamal, ECDSA and ECDH on the NIST, secp256k1, SM2 and GOST curves,
  X25519 and X448, Ed25519 and Ed448, GOST R 34.10, SM2. RSA, finite-
  field Diffie-Hellman, ECDSA, EdDSA, X25519, X448, ML-KEM and ML-DSA keep
  their secrets in fixed-width arithmetic, checked for constant time
  under valgrind; the leaks that remain elsewhere are named in
  [pitfalls.md](docs/pitfalls.md).
- **Post-quantum** - ML-KEM, ML-DSA, SLH-DSA, Streamlined NTRU Prime, and
  the hybrid key exchanges TLS and SSH use.
- **Certificates and keys** - X.509 parsing, chain verification and
  building, CRLs, OCSP, name constraints, PEM and PKCS#8 keys, encrypted
  keys, and Java's key stores.
- **Protocols** - TLS 1.0 to 1.3, client and server, with RC4 and
  RFC 9367's GOST suites on both, and on the client also SSLv3, the
  export suites and RFC 9189's GOST suites; SSH, client and server,
  including the algorithms OpenSSH has since dropped.
- **Products** - formats other software writes, built from the library
  and checked against that software's own tools: LUKS, VeraCrypt, age,
  OpenPGP, Signal, KeePass, ZIP and 7z, PDF, Office, PKCS#12 and Java key
  stores, JOSE, CMS, Kerberos, DNSSEC, WireGuard, BitLocker, Wi-Fi, smart
  cards and more. See the [product examples](examples/products/README.md).

[docs/status.md](docs/status.md) lists every algorithm and what checked
it.

## Quick start

Rust:

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::{BlockCipher, Ctr};
use allcrypt::hash_functions::{sha2, HashFunction};

// hashing
let mut hash = sha2::SHA256::new(b"abc");
println!("{}", allcrypt::to_hex(&hash.digest()));

// encryption, streamed in as many pieces as you like
let mut cipher = AesCrypto::new(vec![0u8; 16])?;
let mut stream = Ctr::new(&mut cipher, &[0u8; 16])?;
let mut out = vec![];
stream.update(b"first piece ", &mut out)?;
stream.update(b"second piece", &mut out)?;

// or in place, with no copying at all
let mut buffer = b"transformed in place".to_vec();
let mut cipher = AesCrypto::new(vec![0u8; 16])?;
Ctr::new(&mut cipher, &[0u8; 16])?.apply(&mut buffer)?;
```

Python, after `python3 scripts/build_python.py --install`:

```python
import allcrypt

allcrypt.sha256(b"abc").hexdigest()

allcrypt.aeads_available
allcrypt.algorithms_available
allcrypt.modes_available

key = bytes(16)
c = allcrypt.Cipher("aes", key)
iv = b'1234567890abcdef'
enc = c.encryptor(allcrypt.Mode.CTR, iv)
ciphertext = enc.update(b"first ") + enc.update(b"second") + enc.finalize()
```

C, after `cargo build --release --features c-api`, compiled with
`cc -I include program.c -L target/release -Wl,-rpath,target/release -lallcrypt`:

```c
#include <allcrypt.h>
#include <stdio.h>

int main(void) {
    allcrypt_buffer digest = {0};
    if (allcrypt_hash("sha256", (const uint8_t *)"abc", 3, &digest) != ALLCRYPT_OK) {
        fprintf(stderr, "%s\n", allcrypt_last_error());
        return 1;
    }
    for (size_t i = 0; i < digest.len; i++) {
        printf("%02x", digest.data[i]);
    }
    printf("\n");
    allcrypt_buffer_free(&digest);
    return 0;
}
```

## Reaching old servers

Two tools put the library in front of programs that cannot be changed.

**The shim** builds a `libssl.so` that replaces OpenSSL's TLS underneath
`curl`, `wget` and `git`, which reach it through the dynamic linker:

    cargo build --release
    LD_PRELOAD=target/release/libssl.so curl https://old-box/

It is permissive by default - it was preloaded because OpenSSL already
said no - while the certificate decision stays with the program: the
shim checks, reports through `SSL_get_verify_result`, and `curl -k`
means what it always meant. Unix only; see [shim.md](docs/shim.md).

**`allcrypt-proxy`** is for browsers, which link their TLS library
statically so nothing can be interposed. It terminates TLS on one side
and speaks whatever the old box speaks on the other:

    cargo build --release
    ./target/release/allcrypt-proxy --legacy --port 8080

Point the browser's HTTPS proxy at 127.0.0.1:8080 and import the
`ca.pem` it writes. The proxy **mirrors** the real certificate - subject,
names, validity and serial - and signs with its CA only when the real
chain verified, so the browser warns exactly when it would have warned
without it. **Installing that CA means anything holding its key can
impersonate any site to that browser**; [proxy.md](docs/proxy.md) says
what you are agreeing to.

In Python, `allcrypt_ssl` is a drop-in for the standard `ssl` module, so
`http.client`, `urllib3` and `requests` reach the same servers.

## How it is tested

Known-answer tests are necessary and never enough: this library has had
bugs that passed every published vector. So algorithms are also
compared with an independent implementation - OpenSSL through
python-cryptography, `hashlib`, or a reference built from source - over
hundreds of input lengths, and streaming in irregular pieces is checked
against a single call; [status.md](docs/status.md) says what checked
each one, including those with no second implementation available.
Where possible, test vectors are read out of the specifications' own
text rather than typed. The constant-time code is run under valgrind
with its secrets marked, and the check fails if a branch or a memory
address depends on them anywhere a leak is not named and accepted. Protocols are tested against real peers - OpenSSL, OpenSSH, GnuPG
and the rest - and recorded sessions replay offline byte for byte.

No test needs the network. [building.md](docs/building.md) has the
commands; [pitfalls.md](docs/pitfalls.md) is the list of side channels,
correctness traps and protocol hazards, each marked mitigated, accepted
or open.

## Documentation

- [Status](docs/status.md) - every algorithm, mode and protocol, and what checked it
- [Building and testing](docs/building.md) - cargo, the Python module, the C library, offline builds, the test suites, and [building for speed](docs/building.md#building-for-speed)
- [Using allcrypt from Rust](docs/rust.md)
- [Using allcrypt from Python](docs/python.md) - the hashlib- and cryptography-shaped API, and the `ssl` drop-in
- [Using allcrypt from C and C++](docs/c.md) - `include/allcrypt.h` and the `c-api` feature
- [Adding an algorithm](docs/extending.md) - what to implement, where to register it, what to test
- [Pitfalls](docs/pitfalls.md) - side channels, correctness traps, and what is mitigated and what is not
- [Post-quantum](docs/post-quantum.md) - ML-KEM, ML-DSA, SLH-DSA and how each is checked
- [The OpenSSL shim](docs/shim.md) and [the proxy](docs/proxy.md)
- [Windows](docs/windows.md) - what runs there, and what to use instead of `LD_PRELOAD`
- [Product examples](examples/products/README.md)

## License

[0BSD](LICENSE): do anything with it, no attribution required, and no
warranty of any kind. The specifications in `rfcs/` and the test data
other programs wrote keep their own terms.
