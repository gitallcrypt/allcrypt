# The OpenSSL shim

    cargo build --release
    LD_PRELOAD=target/release/libssl.so curl https://old-box.example/

Replaces OpenSSL's TLS with this library's, underneath a program that
knows nothing about it. Same `curl`, same server:

```
$ curl https://old-box/
curl: (35) OpenSSL/3.0.13: error:0A00042E:SSL routines::tlsv1 alert protocol version

$ LD_PRELOAD=libssl.so curl https://old-box/
allcrypt: TLS is being handled by the allcrypt shim, not OpenSSL.
allcrypt: old-box TLSv1 TLS_RSA_WITH_AES_128_CBC_SHA [verified]
<the page>
```

---

## Why this works where the browsers do not

The proxy exists because a browser cannot be got at from underneath.
A command line tool can:

| | |
|---|---|
| **wget** | calls `SSL_connect` and 31 other libssl functions through the PLT |
| **curl** | the same, but from `libcurl.so.4` — 56 functions |
| **git** | uses libcurl for HTTPS, so it comes along |
| **Chromium** | links BoringSSL statically; zero TLS imports, nothing to interpose |
| **Firefox** | NSS is a shared library, but ~500 entry points plus NSPR, PKCS#11 and a certificate database |

The union for curl and wget is 63 functions. That is a small enough
surface to implement properly rather than approximately.

### Two mechanics, both checked rather than assumed

**An unversioned definition satisfies a versioned reference.** `wget`
refers to `SSL_connect@OPENSSL_3.0.0`; the shim exports a plain
`SSL_connect`, and the dynamic linker binds it. This was verified with
a three-line C program before anything else was written, because the
whole approach depends on it.

**The real `libssl.so.3` is still loaded**, because it is in the
program's `DT_NEEDED`. It simply goes unused — and that is the hazard.
Any function the shim fails to define resolves *there*, and is then
handed one of our structs to read as one of OpenSSL's. So the rule for
`shim/src/lib.rs` is to implement the whole set a shimmed program
references, not the set that looked necessary.

## What it leaves alone

`libcrypto` is untouched, and the objects handed back are **real
OpenSSL ones**. `wget` takes the `X509 *` from
`SSL_get1_peer_certificate` and calls `X509_get_subject_name`,
`X509_get_ext_d2i`, `X509_NAME_get_text_by_NID` and a dozen more on it,
none of which the shim intercepts. A pointer to something of our own
would be read as an OpenSSL struct by every one of them.

So `shim/src/objects.rs` converts: our DER in, `d2i_X509` out. **No
cryptography happens there** — nothing in that file verifies a
signature, derives a key or decides what to trust. It is the only file
in the shim that calls OpenSSL, kept that way so that replacing it with
our own object model later is a contained change rather than a rewrite.

There is one place this matters in the other direction. **`libcurl`
never calls a libssl function to load `--cacert`**: it takes the
context's `X509_STORE` and uses `X509_STORE_add_cert` and
`X509_STORE_load_file` on it directly, neither of which the shim sees.
So the store is read back with `X509_STORE_get1_all_certs` at handshake
time. Without that, every curl connection verified against nothing —
which it did, until the first test caught it.

### Found at run time, not linked against

Those eighteen functions are resolved with `dlsym`, and `libssl.so` has
**no `DT_NEEDED` on libcrypto at all** — `readelf -d` on it lists
`libc`, `libgcc_s` and the loader, and nothing else. Two reasons, and
the second is the one that bites:

- `#[link(name = "crypto")]` makes OpenSSL's *development* package a
  build dependency of the whole workspace. `-lcrypto` resolves through
  the unversioned `libcrypto.so` symlink, which only `libssl-dev`
  installs — so on an ordinary machine that merely *runs* OpenSSL,
  `cargo test` fails to link, and `cargo test` has nothing to do with
  the shim.

- Linking writes a `DT_NEEDED` for whichever soname was installed on
  the *build* machine. Preload that into a program linked against a
  different libcrypto and the process now holds two of them. We build
  an `X509` with one; the program calls `X509_get_subject_name` on it
  from the other. Same symbol name, different struct layout, different
  allocator. Build on a box with OpenSSL 3 and preload into a program
  using 1.1 and that is exactly what happens.

The lookup is therefore done in the **global** symbol scope:
`dlopen(NULL, RTLD_LAZY)` is a handle onto the running program and
everything it has already loaded, which under `LD_PRELOAD` is precisely
the libcrypto the program itself is using — the one whose objects it is
about to call accessors on. Opening a copy by soname
(`libcrypto.so.3`, `.so.1.1`, `.so.1.0.0`, …) is only the fallback, for
a host program that brought none.

Seventeen of the eighteen resolve or none does. A libcrypto missing one
of them is not one we can use, and finding that out halfway through a
handshake is worse than finding it out at the first call. That sets a
floor of **OpenSSL 1.1.0** — where the generic `OPENSSL_sk_*` replaced
the per-type macros, `X509_up_ref` and `BIO_test_flags` became real
functions and `CRYPTO_free` grew its file and line arguments.

The eighteenth, `X509_STORE_get1_all_certs`, is optional, because it is
OpenSSL 3.0 and later and 1.1.1 is exactly the sort of host this
library exists for. Requiring it would mean that on such a host
*nothing* resolved and every certificate object was lost, to save a
feature only `libcurl --cacert` uses. Where it is absent, a store
cannot be read back and `--cacert` does not reach us.

When none is found the shim says so once on stderr and carries on: the
handshake still works, because all of that is ours, but
`SSL_get1_peer_certificate` starts answering null and a program that
reads the certificate for its own reasons will behave as though the
peer sent none.

Which of those happened is written to `ALLCRYPT_LOG` as
`libcrypto: global scope`, or the soname, or `none`, or the soname
followed by `(pre-3.0: a store cannot be read back)`. That line is
there for the same reason `shim active` is: none of it is observable
from outside. A second libcrypto of the same version behaves
identically to the program's own until the day the versions differ, so
`test_libcrypto_is_the_programs_own_and_not_a_second_copy` asserts on
the log rather than on the page that came back.

## Defaults: permissive

This is the opposite of every other entry point into the library, and
deliberate.

`ClientConfig::new` offers modern suites and a TLS 1.2 floor because a
program written against this library chose to use it and can say
otherwise. A shimmed program said nothing — it asked for OpenSSL and got
us, because somebody typed `LD_PRELOAD=` in front of a command that had
already failed. A shim that then refuses for the same reason is an
elaborate way to print the same error.

So the default is the widest thing that still finishes a handshake:

| | |
|---|---|
| suites | every implemented one, insecure included |
| versions | TLS 1.0 to TLS 1.3 |
| chain signatures | SHA-1 and MD5 accepted |
| RSA | 1024 bits |
| Diffie-Hellman | 512 bits |

Three things are **not** loosened, because they belong to the program:

- **Whether the certificate is checked at all.** The shim always checks
  and puts the answer where `SSL_get_verify_result` finds it. Whether a
  bad answer ends the connection comes from the program's
  `SSL_CTX_set_verify` — which is exactly what `curl -k` and
  `wget --no-check-certificate` set.
- **Which roots to trust.** From `--cacert` and the system store.
- **SSLv3.** Its CBC padding is unspecified, which is POODLE. The floor
  is TLS 1.0, and below it has to be asked for by name.

### Environment

There is no other channel — the command line belongs to the program.

| | |
|---|---|
| `ALLCRYPT_CIPHERS` | `all` (default), `modern`, `legacy`, or a comma separated list |
| `ALLCRYPT_MIN_VERSION` | `SSLv3`, `TLSv1` (default), `TLSv1.1`, `TLSv1.2`, `TLSv1.3` |
| `ALLCRYPT_MAX_VERSION` | default `TLSv1.3` |
| `ALLCRYPT_MIN_RSA_BITS` | default 1024 |
| `ALLCRYPT_MIN_DH_BITS` | default 512 |
| `ALLCRYPT_NO_SHA1`, `ALLCRYPT_NO_MD5` | tighten the chain policy |
| `ALLCRYPT_VERBOSE` | one line per connection |
| `ALLCRYPT_QUIET` | say nothing on stderr |
| `ALLCRYPT_LOG` | append the same lines to a file |

An OpenSSL cipher string passed by the program is **not** translated.
`SSL_CTX_set_cipher_list("HIGH:!aNULL:!RC4")` succeeds and is ignored,
with a note under `ALLCRYPT_VERBOSE`; the suites offered come from
`ALLCRYPT_CIPHERS`. Failing the call instead would make curl and wget
abort outright, which means no connection rather than one whose suite
list came from somewhere else.

## What it refuses rather than ignores

A shim that silently skips something the program asked for is worse than
one that fails: the program reports success and the person believes a
check happened. So:

- **A client certificate** (`curl --cert`, `wget --certificate`) is
  refused. Against a server that requests but does not require one,
  connecting without it would look like success.
- **A revocation list** (`wget --crl-file`) is refused. That call reaches
  `X509_load_crl_file`, which the shim intercepts purely to say no —
  letting the real function load a CRL into a store nobody reads would
  mean wget reporting a revocation check that never happened. The
  library *can* check a CRL; wiring the store back out has not been
  done.
- **SRP** is refused.
- **A per-certificate verify callback** is refused. OpenSSL calls it
  once per link and lets the program override the verdict; calling it
  with a fabricated `X509_STORE_CTX` would be worse than not calling it.

## What is simply absent

- **Session resumption.** `SSL_get_session` returns null, which every
  program handles — it is the normal case for a first connection.
- **ALPN.** `SSL_get0_alpn_selected` reports nothing agreed, so libcurl
  falls back to HTTP/1.1, which works everywhere.
- **The server side.** `SSL_CTX_new(TLS_server_method())` returns null
  with a message pointing at `allcrypt-proxy`.
- **Key logging** for Wireshark. The library supports it; the callback
  is not wired up.

## How it is tested

`pytests/test_shim.py` runs the real `curl` and `wget` binaries against
real OpenSSL origin servers on loopback.

**The trap the file is written against**: a shim that fails to load
leaves the program working perfectly — against the real OpenSSL. Every
assertion about the connection still passes and the test proves nothing.
So every test also asserts that *we* were in the path, by reading the
`ALLCRYPT_LOG` file. Without that check the whole file is decoration.

The second thing: the point is not that curl still works, it is that
curl works against origins it otherwise refuses. Each legacy row in the
table says whether an unaided curl can reach that server, **and the test
checks the claim**. That expectation has already been wrong once —
`AES256-SHA` over TLS 1.2 was written as a refused row on the assumption
that a modern OpenSSL declines SHA-1 CBC, and this distribution's does
not. A row that drifts between the two categories now fails loudly
instead of quietly becoming decoration, and a separate test fails if no
row needs the shim at all any more.

Seven deliberate breaks of the shim; six caught. The seventh — accepting
a client certificate and not presenting it — is masked because two
independent things refuse it, which is defence in depth working rather
than a hole. It is noted at the code.

## Limitations worth knowing before you hit them

- **Unix only.** The crate is `#![cfg(unix)]` and compiles to an empty
  library everywhere else, so `cargo test` on the workspace builds and
  passes on Windows — it just does not produce a usable shim there.
  `LD_PRELOAD` is the dynamic linker's; Windows resolves imports
  through an import address table written at load time and has no
  equivalent switch. [windows.md](windows.md) weighs what it does have
  and why the proxy is the supported answer instead.
- **Non-blocking sockets** are handled, including partial writes: the
  remainder is kept and resent, because `take_outgoing` has already
  handed the bytes over and dropping them puts a hole in the middle of
  a TLS stream.
- **`SSL_CTX_set1_param`** is accepted and ignored. It carries the
  hostname a program wants checked, and reading an `X509_VERIFY_PARAM`
  needs accessors the shim does not have. The name comes from SNI
  instead, which every program also sets.
- **Threads.** An `SSL` object is not shared between threads by any
  program here, which is OpenSSL's own contract for it. The shim holds
  each connection behind its own lock and does not try to do better.
- **`SSL_CTX_set_options`** is accepted and returns what it was given.
  Those options are almost all "do not do this old thing", and doing old
  things when asked is the entire purpose. Version limits arrive through
  `SSL_CTX_ctrl` instead and *are* honoured.
