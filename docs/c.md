# Using allcrypt from C and C++

The library has a C interface: `include/allcrypt.h`, and the functions it
declares, which are compiled in by the `c-api` feature. It covers the
common ground - hashes, HMAC, the password and key derivation functions,
block ciphers in every mode, the AEADs, the stream ciphers, X25519, ECDSA
and ECDH, EdDSA, and RSA - and reaches every algorithm in those families
by name. TLS, X.509, SSH and the file formats are not in it; they are
reachable from Rust and Python.

## Building

```
cargo build --release --features c-api
```

makes `target/release/liballcrypt.so` (`liballcrypt.dylib` on macOS,
`allcrypt.dll` with its import library `allcrypt.dll.lib` on Windows).
For a static library:

```
cargo rustc --release --lib --features c-api --crate-type staticlib
```

makes `target/release/liballcrypt.a` (`allcrypt.lib` on Windows). A static
link also needs the system libraries Rust's standard library uses; add
`-- --print native-static-libs` to the command above and it prints them
(on Linux, `-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc`).

Then:

```
cc -I path/to/allcrypt/include program.c -L path/to/allcrypt/target/release -lallcrypt
```

The header is plain C99 and has `extern "C"` guards, so C++ includes it
as it is.

The `python` and `c-api` features can be on together; the Python module
is then also a C library, which is harmless and occasionally useful.

## Conventions

The header's opening comment states them; in short:

- **Only 0 is success.** A function that can fail returns `ALLCRYPT_OK`
  (0) or `ALLCRYPT_ERROR`, and `allcrypt_last_error()` says why, per
  thread. The verifiers return `ALLCRYPT_INVALID` for a well-formed
  signature that does not verify and `ALLCRYPT_ERROR` for a malformed
  one. Test them with `== ALLCRYPT_OK`: neither "invalid" nor "error" is
  zero, so `if (allcrypt_ec_verify(...))` reads the wrong way round and
  the header says so.
- **Bytes in are a pointer and a length**, and the pointer may be NULL
  when the length is 0. Names are NUL-terminated and case-insensitive -
  `"sha256"`, `"aes"`, `"cbc"`, `"P-256"`. `allcrypt_names("hashes")`
  and its siblings list them.
- **Output whose length you choose** (random bytes, a derived key) is
  written to your memory. **Output whose length the library decides**
  comes back in an `allcrypt_buffer`, which you release with
  `allcrypt_buffer_free`. That zeroes the bytes first, so a key or a
  plaintext does not stay in freed memory.
- **Objects are opaque pointers**, made by `_new`, `_generate`, `_from_`
  and `_load` and released by the matching `_free`, which accepts NULL.
  An object is used by one thread at a time; separate objects are
  independent.
- **A panic does not reach C.** Each function catches one and returns
  `ALLCRYPT_ERROR` with a message saying it is a bug in allcrypt.

## An example

Hash a message, sign the digest with a fresh P-256 key, and verify it:

```c
#include <allcrypt.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *text = "attack at dawn";
    allcrypt_buffer digest = {0}, signature = {0}, public_key = {0};
    allcrypt_ec_key *key = NULL;

    if (allcrypt_hash("sha256", (const uint8_t *)text, strlen(text), &digest) != ALLCRYPT_OK
        || allcrypt_ec_generate("P-256", &key) != ALLCRYPT_OK
        || allcrypt_ec_sign(key, "sha256", digest.data, digest.len, &signature) != ALLCRYPT_OK
        || allcrypt_ec_public_bytes(key, 0, &public_key) != ALLCRYPT_OK) {
        fprintf(stderr, "allcrypt: %s\n", allcrypt_last_error());
        return 1;
    }

    int verdict = allcrypt_ec_verify("P-256", public_key.data, public_key.len,
                                     digest.data, digest.len,
                                     signature.data, signature.len);
    printf("%s\n", verdict == ALLCRYPT_OK ? "valid" : "not valid");

    allcrypt_ec_key_free(key);
    allcrypt_buffer_free(&digest);
    allcrypt_buffer_free(&signature);
    allcrypt_buffer_free(&public_key);
    return verdict == ALLCRYPT_OK ? 0 : 1;
}
```

Encrypt with AES-256-GCM and open it again, refusing a forgery:

```c
#include <allcrypt.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t key[32], nonce[12];
    const char *text = "a secret";
    allcrypt_buffer ciphertext = {0}, tag = {0}, plaintext = {0};

    if (allcrypt_random(key, sizeof key) != ALLCRYPT_OK
        || allcrypt_random(nonce, sizeof nonce) != ALLCRYPT_OK
        || allcrypt_aead_encrypt("aes-gcm", key, sizeof key, nonce, sizeof nonce, NULL, 0,
                                 (const uint8_t *)text, strlen(text),
                                 &ciphertext, &tag) != ALLCRYPT_OK) {
        fprintf(stderr, "allcrypt: %s\n", allcrypt_last_error());
        return 1;
    }

    tag.data[0] ^= 1;
    if (allcrypt_aead_decrypt("aes-gcm", key, sizeof key, nonce, sizeof nonce, NULL, 0,
                              ciphertext.data, ciphertext.len, tag.data, tag.len,
                              &plaintext) == ALLCRYPT_OK) {
        return 1;
    }
    printf("forgery refused: %s\n", allcrypt_last_error());

    tag.data[0] ^= 1;
    if (allcrypt_aead_decrypt("aes-gcm", key, sizeof key, nonce, sizeof nonce, NULL, 0,
                              ciphertext.data, ciphertext.len, tag.data, tag.len,
                              &plaintext) != ALLCRYPT_OK) {
        return 1;
    }
    printf("%.*s\n", (int)plaintext.len, (const char *)plaintext.data);

    allcrypt_buffer_free(&ciphertext);
    allcrypt_buffer_free(&tag);
    allcrypt_buffer_free(&plaintext);
    return 0;
}
```

`scripts/check_c_api.py` compiles and runs both of these, so they stay
correct as the interface changes.

## What checks it

`python3 scripts/check_c_api.py`, which needs a C compiler, the `openssl`
command and python-cryptography, and nothing from the network:

1. compares every exported function with its prototype in the header -
   names, parameter names and types, return type - and the constants. A
   compiler cannot see a header that disagrees with the library; it
   compiles, links and passes the wrong thing;
2. builds the library, compiles `tests/c/test_capi.c` against the header
   with every warning an error, and runs it. The program calls every
   function in the header, checks the round trips and refusals itself,
   and prints the rest for the script to compare with hashlib and
   python-cryptography;
3. compiles and runs the examples above.

`--static` repeats the second step against the static library.

## Adding a function

1. Write it in `src/capi.rs`: `#[no_mangle] pub unsafe extern "C"`, its
   body inside `guard`, and nothing in it but translation - the work goes
   through `src/api.rs`, as the Python bindings' does.
2. Declare it in `include/allcrypt.h` with the same parameter names.
3. Call it from `tests/c/test_capi.c`, and compare what it prints in
   `scripts/check_c_api.py` if anything else can compute it.

The script fails on a function missing from any of the three.
