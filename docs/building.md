# Building and testing

## The Rust library

No setup beyond a Rust toolchain. The crate has exactly one runtime
dependency (`lazy_static`) and pulls nothing else in by default.

```
cargo build
cargo test
```

`cargo test` runs everything: the unit tests inside `src/`, and the
integration suites in `tests/`. A green run is currently 944 tests.

**No OpenSSL is needed to build.** Not the library, not the headers,
not `libssl-dev`. The shim talks to libcrypto, but it looks its
functions up with `dlsym` at run time rather than linking them, so
nothing in the workspace asks the linker for `-lcrypto` — which it
used to, and which broke `cargo test` on any machine that had OpenSSL
installed but not its development package. See
[shim.md](shim.md#found-at-run-time-not-linked-against).

For a release build, `cargo build --release`. The library is built as both an
`rlib` (for other Rust code) and a `cdylib` (which is what the Python module
is loaded from).

This is a two-package workspace. The root package is the library, the
`allcrypt-proxy` binary and the Python module; `shim/` is the OpenSSL
`LD_PRELOAD` shim, which has to be its own package because a package
produces one library and the shim's must be called `libssl.so`.
`default-members` lists both, so a plain `cargo build` produces
everything. On Windows the shim crate is `#![cfg(unix)]` and compiles
to an empty library, so the workspace still builds and `cargo test`
still passes there — see [windows.md](windows.md) for what that means
and what to use instead of the shim.

See [proxy.md](proxy.md) and [shim.md](shim.md). Both are built by any
`cargo build` and by `scripts/build_python.py`, which is why
`pytests/test_proxy.py` and `pytests/test_shim.py` can run the real
things rather than re-implementations. Those tests **fail** rather than
skip when the artefact is missing: a test that quietly vanishes because
somebody forgot to build is a hole that looks like a pass.

One way to be caught out: `cargo clippy` does not rebuild the release
profile, so editing the shim, running clippy and then running pytest
tests the *previous* `libssl.so`. The documented gate above does not
have this problem, because `build_python.py` builds release.

## The Python bindings

The bindings live behind the `python` feature, which is **off by default**.
That is deliberate: a plain `cargo build` or `cargo test` never compiles
`pyo3` and never needs a Python interpreter.

```
python3 scripts/build_python.py
python3 -m pytest
```

That is all of it. **No extra build tool is needed** — the crate is
`crate-type = ["cdylib"]`, so cargo already produces a module Python can
load. The script is `cargo build --features python` followed by a rename,
because Python imports by file name and cargo's name is not the one it
looks for:

| | cargo writes | Python wants |
|---|---|---|
| Linux | `target/release/liballcrypt.so` | `allcrypt.so` |
| macOS | `target/release/liballcrypt.dylib` | `allcrypt.so` |
| Windows | `target/release/allcrypt.dll` | `allcrypt.pyd` |

The Windows row is the one to notice: it is not only a different name but
a different extension, and Python will not import a `.dll` under any name.

The module lands in `python/`, which is where the scripts in `scripts/`
already look, so they work with no further setup. To import it from
anywhere else, either put that directory on the path:

```console
$ export PYTHONPATH=$PWD/python          # Linux, macOS
> set PYTHONPATH=%CD%\python             # Windows, cmd
> $env:PYTHONPATH = "$PWD\python"        # Windows, PowerShell
```

or install it:

```
python3 scripts/build_python.py --install
```

which copies the module, the type stubs and `allcrypt_ssl.py` into
site-packages. Use a virtualenv or `--user` if that needs permission.

`--debug` builds faster and runs much slower; the bignum and key
generation paths are several times off the pace, so RSA key generation in
particular goes from a third of a second to several seconds.

### If the Windows build fails to link

PyO3 needs to find your interpreter to link against. If cargo reports
unresolved Python symbols, point it at one:

```
set PYO3_PYTHON=C:\path\to\python.exe
```

### maturin

[maturin](https://www.maturin.rs/) is the usual way to build a PyO3
extension and is a good tool — it produces wheels, handles metadata and
can publish to PyPI, which is what `pyproject.toml` here is set up for:

```
pip install maturin
maturin build -F python --release    # wheel lands in target/wheels/
```

None of that is needed to import the module locally, which is why the
script above exists. One fewer tool to install is one fewer reason for
somebody not to run the tests.

## The C library

```
cargo build --release --features c-api
cargo rustc --release --lib --features c-api --crate-type staticlib
```

The first makes the shared library, the second the static one, both in
`target/release/`; `include/allcrypt.h` declares what they export. No
dependency is added - the feature only compiles `src/capi.rs` in.
`docs/c.md` has the conventions, the link lines and examples, and

```
python3 scripts/check_c_api.py [--static]
```

checks it: the header against `src/capi.rs` function by function (no
compiler needed for that part), then a C program through the header
against the built library, with its answers compared with hashlib and
python-cryptography. That part needs a C compiler and the `openssl`
command, and builds into `target/c-api` so it does not disturb the
other builds.

## Building without network access

If the machine cannot reach crates.io, vendor the dependencies from one that
can, then point cargo at them. On the networked machine, in the repo:

```
cargo vendor --versioned-dirs vendor-offline
```

Copy `vendor-offline/` to the offline machine and add `.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor-offline"
```

Then `cargo build --offline --features python` works with no network at all.
`vendor-offline/` and `.cargo/config.toml` are gitignored, since the vendor
path is machine specific.

The full dependency set for the `python` feature is about 21 crates and 5 MB:
`pyo3` and its macro crates, plus `syn`/`quote`/`proc-macro2` and a handful of
small support crates.

## Test layout

| Path | What it covers |
|---|---|
| `src/**` (`#[test]`) | Unit tests next to the code: padding, mode plumbing |
| `tests/test_aes.rs`, `test_blowfish.rs`, `test_gost.rs`, … | Per algorithm known answer tests |
| `tests/test_modes.rs` | NIST SP 800-38A vectors, streaming equivalence, counter carry |
| `tests/test_api.rs` | The dynamic facade must match the statically typed API |
| `tests/test_tls_transcripts.rs` | Framing and messages, against three real captured handshakes |
| `tests/test_tls_keys.rs` | The key schedule, by decrypting a real captured session |
| `pytests/test_allcrypt.py` | The Python binding layer, differential against `hashlib` |
| `pytests/test_tls_handshake.py` | Our client against a real OpenSSL server |
| `pytests/test_tls_server.py` | Our TLS 1.2 server against a real OpenSSL client |
| `pytests/test_tls13_server.py` | Our TLS 1.3 server against the same, sharing that file's harness |
| `pytests/test_proxy.py` | The real `allcrypt-proxy` binary, as a subprocess |
| `pytests/test_shim.py` | The real `curl` and `wget`, with `libssl.so` preloaded |
| `shim/src/objects.rs` (`#[test]`) | Finding libcrypto — the branch the preloaded tests cannot reach |
| `tools/src/bin/diff_*.rs` | Bulk corpus generators for differential testing |
| `scripts/diff_check.py` | Checks those corpora against OpenSSL, `hashlib` and Python ints |
| `scripts/rfc_oids.py` | Reads OIDs back out of the RFC texts vendored in `rfcs/` |
| `tools/src/bin/ct_bignum.rs` | Runs each operation with its secrets marked, for ctgrind |
| `scripts/ct_check.py` | Checks those under valgrind: what is constant time, and what is not |
| `tools/src/bin/dudect.rs` | Times the constant-time targets on the machine itself, with controls |
| `tests/test_nacl.rs`, `pytests/test_nacl.py` | NaCl's boxes against `vectors/nacl.vec`, from NaCl, libsodium and Go |
| `tests/test_gost_handshake.rs` | A whole RFC 9189 handshake, against a server written there |
| `examples/doc_examples.rs` | Generated; see below |
| `scripts/check_messages.py` | Error messages with Rust's line-continuation rule forgotten |

## Differential testing

Known answer tests catch known cases. What catches the rest is comparing
against a different implementation over a lot of inputs. The
`tools/src/bin/diff_*.rs` programs print a deterministic corpus each, and
`scripts/diff_check.py` runs every one of them against an independent
implementation:

```
python3 scripts/diff_check.py            # all of it, ~89,500 cases
python3 scripts/diff_check.py ec ecdsa   # just those
```

The generators, the ctgrind harness and the benchmarks are a package of
their own, `tools/`, a member of the workspace: every file in
`tools/src/bin/` is a program Cargo finds by itself, and `cargo test`
and clippy compile them with everything else, so a generator that stops
compiling fails the gate rather than the next differential run. One
corpus on its own is `cargo run --release -p allcrypt-tools --bin
diff_gcm`.

The references are `hashlib` for the hashes, Python's `hmac` for HMAC,
OpenSSL through `python-cryptography` for the ciphers, HKDF and the curves,
and Python's own arbitrary precision `int` for `bignum`. None of them are
ours, which is the point.

| Corpus | What it covers | Cases |
|---|---|---|
| `block` | AES, Blowfish, CAST5, IDEA, SEED, Camellia, SM4 and the rest × key size × mode × length | 11,304 |
| `hash` | Every hash and stream cipher, lengths 0..300 plus large, BLAKE2's whole parameter block, RIPEMD-160, SHA-3, SHAKE, pre-standard Keccak, Salsa20 at three round counts | 6,577 |
| `mackdf` | HMAC over six hashes × key length × message length, HKDF, PBKDF2, scrypt, Argon2id | 11,763 |
| `bignum` | Every arithmetic operation, 1 to 2048 bits | 16,237 |
| `ec` | `k*G`, both SEC1 encodings, ECDH | 864 |
| `ecdsa` | Signatures OpenSSL must verify, four hashes | 396 |
| `dh` | Finite-field DH, including the short-secret case TLS strips | 988 |
| `x25519` | RFC 7748, including the low-order points | 420 |
| `rsa` | Generated keys OpenSSL must accept, signatures, encryption | 90 |
| `x509` | Certificates we build, every field and signature checked by OpenSSL | 20 |
| `roots` | **Every root in the machine's real CA bundle**, parsed and self-verified | ~306 |
| `oids` | Every OID: re-encoded, named in OpenSSL's tables, **and read out of the RFCs** | 74 |
| `gcm`, `ccm`, `chachapoly` | The AEADs, including a flipped tag OpenSSL must reject | 15,948 |
| `tlsrecord`, `tlsstream` | TLS records against RFC 5246 §6.2.3.2 and RFC 7366, written independently | 1,766 |
| `ssl3keys` | SSLv3's key expansion, from RFC 6101 — nothing here implements it | 115 |
| `exportkeys` | The export suites' second expansion, from RFC 2246 | 96 |
| `tls13keys`, `tls13record` | The TLS 1.3 schedule and record layer, from RFC 8446 | 3,394 |
| `suites` | Cipher suite codes against OpenSSL's own registry | 45 |
| `gost`, `cmac`, `acpkm` | Kuznyechik, Magma, Streebog, OMAC, CTR-ACPKM | 1,231 |
| `gost3410`, `vko` | GOST signatures and key agreement, from RFC 7836 — both readings of VKO's cofactor | 728 |
| `tlstree`, `gostkex`, `ctromac` | RFC 9189's CTR_OMAC KDF, key exchange and record protection | 758 |
| `cntimit` | RFC 9189's CNT_IMIT suite: the MAC, CPDivers, and whole connections across the meshing boundary | 134 |
| `mgm` | MGM (RFC 9058) on four ciphers of both block sizes, across every length boundary and at both counters' wrap | 3,840 |
| `ocb` | AES-OCB (RFC 7253) against OpenSSL, every length either side of the block boundaries, all four nonce lengths OpenSSL takes and all 64 nonce bottoms | 6,924 |

The GOST rows and `ssl3keys`, `exportkeys` and `tls13*` say *written
independently* rather than naming a library, and that is the honest
difference: nothing on a normal machine implements them, so the
reference is a second reading of the specification rather than somebody
else's code. Each is additionally pinned to its own standard's published
vectors — for RFC 9189 that is Appendix A reproduced byte for byte — and
the checkers assert that the *wrong* reading gives a different answer, so
a row cannot pass vacuously.

**For the GOST rows there is now a second opinion as well**, and it is
in `cargo test` rather than here: `vectors/gost_engine.vec` holds
OpenSSL gost-engine's own answers and
`tests/test_gost_engine_vectors.rs` reads them offline. It has found two
bugs this corpus could not see, both for the same reason — both sides of
it were the same reading of the same document. The GOST MAC's two-block
minimum, and VKO's cofactor, where the TLS key exchange was pointed at a
reading nothing implements. See below for how to regenerate the file,
and `docs/pitfalls.md` §7o for the second one, which is the clearest
illustration in this repository of what a differential corpus cannot
do.

Where OpenSSL will not do something — Blowfish in CTR, say — the checker
builds the expected keystream from OpenSSL's ECB instead, since CTR and OFB
are *defined* in terms of the block function. That keeps it an independent
implementation rather than quietly falling back to ours.

This is how the SHA-1/224/256 padding bug and the ChaCha keystream bug were
found — both produced correct output for the lengths the unit tests happened
to use.

## Regenerating the GOST transcripts

`tests/transcripts/gost_handshakes.txt` holds seven real GOST TLS 1.2
handshakes with OpenSSL plus gost-engine at **both** ends, recorded by a
relay that sat between them, together with the master secret from
`s_server -keylogfile`. Five are the five suites; the last two repeat one
suite on two other spellings of the same curve — RFC 4357's `XchA` and
TC 26's `paramSetB` are both CryptoPro-A's parameters — because the
ephemeral key must echo the server's parameter set OID and the five
canonical captures cannot tell echoing from rebuilding. `tests/test_gost_transcript.rs` derives the key
block from that secret and decrypts records the engine encrypted, which
is the only thing that can settle the byte orders in these suites — our
own client and server agree with each other whichever way round any of
them is.

With the engine built as below:

```
$ python3 scripts/capture_gost_transcripts.py --engines ../gost-engine/build/bin
$ cargo test --test test_gost_transcript
```

It needs the engine, the `openssl` binary and loopback sockets. The test
needs none of those. Nothing here is deterministic — fresh keys, fresh
randoms and a fresh certificate every time — so a diff against the
previous capture is noise; what matters is which suites are listed.

## Regenerating the GOST vectors

`vectors/gost_engine.vec` holds OpenSSL gost-engine's answers for the
GOST ciphers, modes, digests and MACs. The tests that read it need
nothing but the file; **this section is only for regenerating it**, and
like `check_live.py` the tool is deliberately not part of the gate.

You need the engine built. It is not a dependency of this library and
nothing here links it:

```
$ git clone https://github.com/gost-engine/engine gost-engine
$ cd gost-engine
$ git checkout v3.0.3          # master needs OpenSSL 3.4; 3.0 needs this
$ git submodule update --init --recursive --depth 1
$ cmake -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/usr
$ cmake --build build -j"$(nproc)"
```

Then, from this repository:

```
$ python3 scripts/make_gost_vectors.py --engines ../gost-engine/build/bin
$ cargo test --test test_gost_engine_vectors
```

The generator compiles `scripts/gost_engine_probe.c` with `cc` on the
way through — that is what reaches MGM, OMAC and KExp15, which the
`openssl` command line either cannot express or answers wrongly. It
checks three things about the engine before writing anything, and
refuses rather than producing a file it cannot vouch for: that the
three digests are three different functions, that CTR-ACPKM re-keys
where the file says it does, and that `openssl enc` still
zero-extends a short `-iv` (which is why every IV in the file is
exactly the length the engine reports).

Re-running it should change nothing: every key, IV and input comes from
a counter, so a diff shows exactly the rows where the engine's answer
moved. If the file changes, the OpenSSL and gost-engine versions in its
header should say why, and that belongs in the commit message.

`docs/pitfalls.md` §7b has the four ways the command line misreports
these algorithms, each of which would have produced a plausible-looking
file.

## Our TLS client against gost-engine's server, every suite

`scripts/check_gost_engine_suites.py` puts **our client** in front of
gost-engine's own `s_server`, one GOST suite at a time, over loopback:

```console
$ export OPENSSL_ENGINES=../gost-engine/build/bin
$ python3 scripts/check_gost_engine_suites.py
$ python3 scripts/check_gost_engine_suites.py --suite magma --keep
```

It needs a built engine, so it is a hand-run tool and not part of the
gate, like everything else in this section. What it adds that nothing
else here has:

| what already existed | what it cannot say |
| --- | --- |
| `pytests/`, `cargo test` | our client against **our** server: one reading of RFC 9189 on both ends, agreeing on its own mistakes |
| `tests/test_gost_transcript.rs` | replays **recorded** handshakes; our client is not in them and answers nothing |
| `check_live.py --gost` | the strongest check there is, and it reaches **one** suite |

This one runs a full handshake, in both directions, with 1.4 kB of data
each way so the record layer crosses a re-keying boundary, against an
implementation that is not ours — on all five GOST suites that OpenSSL
plus gost-engine can serve, plus the 512-bit key.

**And it verifies the chain.** `check_live.py --gost` turns verification
off on purpose, because no trust store here carries a Russian test CA, so
until this existed our verifier had never followed a GOST signature on a
certificate somebody else issued. Here the CA is one the engine made and
we trust it explicitly, which includes a GOST R 34.11-94 signed chain for
the 2001 row — the reason that row alone needs `@SECLEVEL=0`, since
OpenSSL refuses to *load* such a certificate at its default level.

The server keys are deliberately generated on **CryptoPro-XchA**, not the
canonical `A`. Generating them canonically would make every row pass on a
client that rebuilds the ephemeral key's parameter-set OID from the curve
instead of echoing the peer's — the bug real CryptoPro servers refuse
with `decode_error`. Reverting that fix and re-running turns five of the
six rows red, and gost-engine names the cause itself:

```
error:08000065:elliptic curve routines:EC_POINT_get_affine_coordinates:
    incompatible objects
error:4000006B:lib(128)::error point mul:gost_ec_keyx.c:81
```

which is the reference implementation building its group from *its*
OID and finding our point tagged with another. The four RFC 9367 MGM
suites cannot appear at all: they are TLS 1.3 suites and neither OpenSSL
3.0 nor gost-engine 3.0.3 has a TLS 1.3 GOST suite to negotiate against,
so the script lists them as unreachable rather than counting "6 of 6" as
full coverage. They are checked against the engine as primitives
instead, through `vectors/gost_engine.vec`.

## The hybrid post-quantum groups against OpenSSL 3.5

`pytests/test_hybrid_kex.py` connects our client to our server for the
three RFC 10024 groups, because the system OpenSSL is 3.0 and does not
know them. `scripts/check_pq_witness.py` puts each end in front of
OpenSSL 3.5 instead, over loopback, one group at a time:

```console
$ git clone --depth 1 --branch openssl-3.5.4 https://github.com/openssl/openssl.git
$ cd openssl
$ ./Configure --prefix=/opt/openssl35 --libdir=lib no-docs no-tests
$ make -j"$(nproc)" && make install_sw
$ cd -
$ python3 scripts/check_pq_witness.py --openssl /opt/openssl35/bin/openssl
```

Building into its own prefix keeps it away from the OpenSSL the Python
`ssl` module and the gate use; the script sets `LD_LIBRARY_PATH` from
the binary's location. Like the gost-engine tools it is run by hand and
is not part of the gate. Each row is a full TLS 1.3 handshake plus data
both ways; a failure names the side and the group.

## ML-DSA certificates and signatures against OpenSSL 3.5

The same OpenSSL 3.5 build is the witness for ML-DSA in X.509 and TLS
1.3, which neither the system OpenSSL nor python-cryptography has:

```console
$ python3 scripts/check_mldsa_witness.py --openssl /opt/openssl35/bin/openssl
$ python3 scripts/capture_mldsa.py --openssl /opt/openssl35/bin/openssl
```

The first is live: for each parameter set, our client against
`s_server` with OpenSSL's certificate, `openssl verify` on a chain our
CA issued, and `s_client -verify_return_error` against our server. The
second records what can be checked offline - OpenSSL's keys in all three
private key forms, its certificates and signatures
(`vectors/ml_dsa_openssl.vec`), and three TLS 1.3 handshakes with their
key log (`tests/transcripts/mldsa_handshakes.txt`) - which
`tests/test_ml_dsa_openssl.rs` reads without OpenSSL. Every row changes
on a re-capture; the counts do not.

A prefix build of OpenSSL has no `openssl.cnf`, and `openssl req` will
not run without one. Both scripts write a minimal one into their
temporary directory and point `OPENSSL_CONF` at it.

## SSH against OpenSSH

OpenSSH is the witness for everything in `src/ssh/`. It is built into
its own prefix, apart from the system's:

```console
$ git clone --depth 1 --branch V_10_0_P2 https://github.com/openssh/openssh-portable.git
$ cd openssh-portable          # the release tag carries its configure
$ ./configure --prefix=/opt/openssh --with-privsep-path=/opt/openssh/empty \
      --with-privsep-user=nobody --without-pam --without-selinux
$ make -j"$(nproc)" && make install-nokeys
$ cd -
```

Two tools use it, both run by hand:

```console
$ python3 scripts/make_ssh_vectors.py --openssh /opt/openssh/bin
$ cargo test --test test_ssh_vectors
$ python3 scripts/check_ssh_witness.py --openssh /opt/openssh/bin
```

`make_ssh_vectors.py` records what `ssh-keygen` says - keys, fingerprints,
private key files under every cipher, SSHSIG signatures - into
`vectors/ssh_keys.vec`, which the gate reads with no OpenSSH present. It
rewrites every row on each run (fresh keys and salts), so diff the counts.
`check_ssh_witness.py` is the other direction: it has
`examples/ssh_write_keys.rs` write keys, encrypted files and signatures
with this library, and asks `ssh-keygen` to read and verify each one.

The client is checked against `sshd` itself:

```console
$ sudo python3 scripts/check_ssh_client.py --openssh /opt/openssh
$ sudo python3 scripts/check_ssh_client.py --record tests/transcripts/ssh_sessions.txt
$ cargo test --test test_ssh_sessions
```

The first starts an `sshd` on 127.0.0.1 with every algorithm it has
switched on, legacy ones included, and runs a complete SSH session per key
exchange, cipher, MAC, host key algorithm and user key type through
`examples/ssh_exec.rs`. sshd's privilege separation wants root. The
second also records a set of sessions with the client's randomness
drawn from a counter, which `tests/test_ssh_sessions.rs` replays offline:
the client must send sshd's recording exactly the bytes it sent sshd.

**After re-recording, check the secret encodings are still covered.**
For a 32 byte shared secret an mpint and a string are the same bytes
unless the top bit is set, so a recording can by chance contain no
session that tells them apart. Swap `SharedSecret::mpint` for
`SharedSecret::string` in the Curve25519 branch of `ssh::kex` (and the
reverse in each of the two hybrids') and the replay test must fail; if
it does not, record again.

The server is checked against OpenSSH's client, `ssh`, which needs no
root:

```console
$ python3 scripts/check_ssh_server.py --openssh /opt/openssh --legacy-openssh /opt/openssh74
$ python3 scripts/check_ssh_server.py --legacy-openssh /opt/openssh74 \
      --record tests/transcripts/ssh_server_sessions.txt
$ cargo test --test test_ssh_server_sessions
$ cargo test --release --test test_ssh_server -- --include-ignored
```

The first runs `examples/ssh_serve.rs` on 127.0.0.1 offering every
algorithm, and connects with `ssh` once per key exchange, cipher, MAC,
host key algorithm and user key type, plus passwords, 5 MB each way with
the client re-keying, and `ssh -tt`. The second also records sessions
with the server's randomness drawn from a counter; the replay test feeds
`ssh`'s side to a server seeded the same way and requires the server's
bytes back exactly. The same check of the secret encodings applies after
re-recording. The last command runs the in-memory tests of the 4096 and
8192 bit groups, which are skipped in a debug build for their time.

## The product examples

`examples/products/` holds formats other software writes, each an
example with its own tests that `cargo test` runs offline from
fixtures. Their witnesses are the products' own tools, built into their
own prefixes like the others; see `examples/products/README.md` for
what checked each.

**cryptsetup** (LUKS), built from source without root and without
touching the system's libraries. Its dependencies go into the same
prefix first: json-c (cmake), popt (`./configure --prefix`) and
libdevmapper (lvm2's `./configure --prefix` and `make device-mapper`).
Then cryptsetup, with the OpenSSL backend and its internal Argon2:

```console
$ git clone --depth 1 --branch v2.8.8 https://github.com/mbroz/cryptsetup.git   # or the tarball
$ meson setup build --prefix=/opt/cryptsetup -Dcrypto-backend=openssl -Dargon-implementation=internal
$ ninja -C build install
$ python3 scripts/check_luks.py --cryptsetup /opt/cryptsetup/run.sh \
      --cryptsetup-tests ~/src/cryptsetup/tests
$ python3 scripts/check_luks.py --record     # rewrites examples/products/fixtures/luks*
$ cargo test --example luks
```

The same cryptsetup and test tree check the TrueCrypt and VeraCrypt
example:

```console
$ python3 scripts/check_veracrypt.py --cryptsetup-tests ~/src/cryptsetup/tests
$ python3 scripts/check_veracrypt.py --record   # rewrites examples/products/fixtures/veracrypt*
$ cargo test --release --example veracrypt -- --include-ignored
```

VeraCrypt's key derivations run hundreds of thousands of iterations; the
tests that use them are skipped in a debug build and run in a release
one, as the last line does.

**age**: the system's 1.1.1, and a current one with post-quantum
recipients built from source into `/opt/age-main`. Its module wants Go
1.25 and dependencies from vanity hosts; with Go 1.24 and no module
proxy, clone each dependency's GitHub mirror at the version `go.mod`
names (edwards25519, hpke, nistec, golang/crypto, sys, term), point
`replace` lines at them, lower the `go` lines to 1.24, and build with
`GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod GOSUMDB=off go build
./cmd/age ./cmd/age-keygen`. Then:

```console
$ python3 scripts/check_age.py              # both ages, both directions
$ cargo test --example age                  # the format's 147 test vectors
```

**OpenPGP**: the system's GnuPG 2.4, and ProtonMail's go-crypto for
what GnuPG 2.4 does not have (RFC 9580's version 6 packets, SEIPD v2,
Argon2). `scripts/witness/pgpwitness/main.go` is a small program on
go-crypto's `openpgp/v2`; build it the way age is built - clone
`ProtonMail/go-crypto`, `cloudflare/circl` at the tag go-crypto's
`go.mod` names (v1.6.3, which still builds with Go 1.24),
`golang/crypto` and `golang/sys`, write a `go.mod` with `replace` lines
pointing at them, and `go build -o /opt/pgpwitness/pgpwitness` with the
same environment. Then:

```console
$ python3 scripts/check_openpgp.py          # gpg and go-crypto, both directions
$ python3 scripts/check_openpgp.py --record # rewrites examples/products/fixtures/openpgp*
$ cargo test --release --example openpgp -- --include-ignored
```

RFC 9580's Argon2 samples take two gigabytes of memory each and its AEAD
samples hash 65 MB for their S2K, so those tests run in a release build
only, as do RSA and DSA key generation; the debug tests take the derived
keys the appendix prints. The check script gives each GnuPG home a
`gpg-agent.conf` with `s2k-count 65536`: the agent protects exported
secret keys with its own count, the maximum by default, which would make
every recorded key take seconds to unlock.

**Signal**: libsignal-protocol-c 2.3.3, the C implementation of the
protocol, driven by `scripts/witness/signalwitness/main.c`. Build the
library with its own CMake (`-DCMAKE_POSITION_INDEPENDENT_CODE=ON`), then
compile the witness against it together with the library's own
`tests/test_common.c` (its in-memory stores) and
`tests/test_common_openssl.c` (its OpenSSL crypto provider).
`test_common.c` includes `<check.h>` for one assertion macro, so a
two-line stand-in does instead of the `check` framework, and the
witness supplies its own random generator, so the OpenSSL file's is
renamed out of the way:

```console
$ S=~/src/libsignal-protocol-c W=scripts/witness/signalwitness
$ printf '#include <assert.h>\n#define ck_assert_int_eq(a, b) assert((a) == (b))\n' > check.h
$ cc -O1 -w -I. -I$S/src -I$S/tests -c $S/tests/test_common.c
$ cc -O1 -w -I. -I$S/src -I$S/tests -Dtest_random_generator=openssl_random_generator \
      -c $S/tests/test_common_openssl.c
$ cc -O1 -I. -I$S/src -I$S/tests -c $W/main.c
$ cc -o /opt/signalwitness/signalwitness main.o test_common.o test_common_openssl.o \
      $S/build/src/libsignal-protocol-c.a -lcrypto -lm
$ python3 scripts/make_xeddsa_vectors.py    # rewrites vectors/xeddsa.vec
```

The witness's randomness is a SHA-256 counter stream from a seed on its
command line, so a run is reproducible and `make_xeddsa_vectors.py`
writes the same file every time.

The Signal example runs against it:

```console
$ cargo build --release --example signal
$ python3 scripts/check_signal.py           # twelve conversations, four pairings
$ python3 scripts/check_signal.py --record  # rewrites examples/products/fixtures/signal.vec
$ cargo test --example signal
```

**KeePass**: gokeepasslib (`tobischo/gokeepasslib`), with
`scripts/witness/kdbxwitness/main.go` on top. Its `go.mod` asks for Go
1.26 and carries a `vendor/` directory; with Go 1.24, copy the vendored
`tobischo/argon2` out beside it with a one-line `go.mod`, delete
`vendor/`, lower both `go` lines to 1.24, drop the test-only
requirements, and point `replace` lines in the witness's `go.mod` at
the copy and at the `golang.org/x/crypto` and `sys` clones age uses.
Build into `/opt/kdbxwitness/kdbxwitness` with the same environment as
age. pykeepass's `tests/` holds more databases other applications wrote; it is only
read, so a clone is enough.

```console
$ cargo build --release --example keepass
$ python3 scripts/check_keepass.py --gokeepasslib-tests ~/src/gokeepasslib/tests \
      --pykeepass-tests ~/src/pykeepass/tests
$ python3 scripts/check_keepass.py --gokeepasslib-tests ~/src/gokeepasslib/tests --record
$ cargo test --example keepass
```

**ZIP**: the system's Info-ZIP `zip` 3.0 and `unzip` 6.0, and two
built from source. libarchive 3.8.1 with OpenSSL for its crypto,
everything optional off: `cmake .. -DCMAKE_INSTALL_PREFIX=/opt/libarchive
-DENABLE_TEST=OFF -DENABLE_OPENSSL=ON -DENABLE_LZMA=OFF -DENABLE_ZSTD=OFF
-DENABLE_LZ4=OFF -DENABLE_LIBXML2=OFF -DENABLE_EXPAT=OFF`, then `make
bsdtar` and `make install`; the check script sets `LD_LIBRARY_PATH` for
it. And 7-Zip (`ip7z/7zip`): `make -f makefile.gcc` in
`CPP/7zip/Bundles/Alone2`, and copy `_o/7zz` to `/opt/7zip/`.

```console
$ cargo build --release --example zip
$ python3 scripts/check_zip.py              # all three writers, four readers
$ python3 scripts/check_zip.py --record     # rewrites examples/products/fixtures/zip*
$ cargo test --example zip
```

**7z**: the same 7-Zip and libarchive builds as for ZIP, and the
system's XZ Utils 5.4.5 (`xz`), whose `--format=raw` output is bare
LZMA2 that the script wraps in a 7z container itself. Only the small
set is recorded; the large one adds an 8 MB file that makes LZMA2
switch between stored and LZMA chunks.

```console
$ cargo build --release --example sevenzip
$ python3 scripts/check_sevenzip.py
$ python3 scripts/check_sevenzip.py --record    # rewrites examples/products/fixtures/sevenzip*
$ cargo test --example sevenzip
```

7-Zip derives every key it writes with 2^19 rounds of SHA-256 and has
no switch to lower it, which is about two seconds in a debug build.
The offline tests take it twice - once for the right password and once
for a wrong one - because derived keys are cached, as 7-Zip caches
them.

**CMS and S/MIME**: OpenSSL 3.0 (the system's, with `-provider legacy`
for DES and RC2) and 3.5 (`/opt/openssl35`), the system's
python-cryptography and NSS's `cmsutil`, `certutil` and `pk12util`. The
script makes its own CA and keys with OpenSSL and an NSS database from
them, and records both alongside the messages.

```console
$ cargo build --release --example cms
$ python3 scripts/check_cms.py
$ python3 scripts/check_cms.py --record    # rewrites examples/products/fixtures/cms*
$ cargo test --example cms
```

**Kerberos**: MIT Kerberos 1.21.3 and 1.17.2, built from the release
tarballs into their own prefixes - `./configure --prefix=/opt/krb5`
(and `/opt/krb5-117`) in `src/`, then `make` and `make install`. 1.17
is there for single DES, which 1.18 removed. The witness is
`scripts/witness/krb5witness/main.c`, built once against each:

```console
$ gcc -O2 main.c -I/opt/krb5/include -L/opt/krb5/lib \
      -Wl,--disable-new-dtags,-rpath,/opt/krb5/lib -lkrb5 -lk5crypto -lcom_err \
      -o /opt/krb5witness/krb5witness-121
$ gcc -O2 main.c -I/opt/krb5-117/include -L/opt/krb5-117/lib \
      -Wl,--disable-new-dtags,-rpath,/opt/krb5-117/lib -lkrb5 -lk5crypto -lcom_err \
      -o /opt/krb5witness/krb5witness-117
$ cargo build --release --example kerberos
$ python3 scripts/check_kerberos.py
$ python3 scripts/check_kerberos.py --record    # rewrites examples/products/fixtures/kerberos*
$ cargo test --example kerberos
```

`--disable-new-dtags` makes the path an `RPATH`, which libkrb5's own
dependencies are found through too; a `RUNPATH` applies to the program
only, and libkrb5 then cannot find libcom_err. The witness sets
`k5_allow_weak_pbkdf2iter`, as MIT's own tests do, or libk5crypto
refuses PBKDF2 counts below the type's default. The script runs a KDC
per encryption type on a loopback port and needs nothing else.

**Wallets**: python-mnemonic (`trezor/python-mnemonic`, the BIP-39
reference) and pycoin (`richardkiss/pycoin`), both pure Python and used
from git checkouts in `/opt/walletwitness/` rather than installed, and
OpenSSL 3.5 (`/opt/openssl35`) for Keccak-256, which 3.0 does not have.
The script needs python-cryptography and hashlib's scrypt and nothing
else.

```console
$ git clone https://github.com/trezor/python-mnemonic /opt/walletwitness/python-mnemonic
$ git clone https://github.com/richardkiss/pycoin /opt/walletwitness/pycoin
$ cargo build --release --example wallet
$ python3 scripts/check_wallet.py
$ python3 scripts/check_wallet.py --record    # rewrites examples/products/fixtures/wallet/wallet.vec
$ cargo test --example wallet
$ cargo test --release --example wallet -- --ignored    # every BIP-38 vector, the heavy keystores
```

The wallet's normalization tables come from the Unicode Character
Database: UnicodeData.txt, DerivedNormalizationProps.txt and
NormalizationTest.txt of one version. unicode.org was not reachable
from the development container, and unicode-org/unicodetools on GitHub
carries the same files. The script writes
`examples/products/wallet/unicode_tables.rs` and the compressed test
file, and refuses files of two versions.

```console
$ V=16.0.0; B=https://raw.githubusercontent.com/unicode-org/unicodetools/main/unicodetools/data/ucd/$V
$ mkdir -p /tmp/ucd && for f in UnicodeData.txt DerivedNormalizationProps.txt NormalizationTest.txt; do
      curl -sSo /tmp/ucd/$f $B/$f; done
$ python3 scripts/make_unicode_tables.py --ucd /tmp/ucd
$ cargo test --example wallet unicode
```

**XChaCha20**: golang.org/x/crypto at v0.37.0 (the tag wireguard-go
pins; its main branch needs Go 1.26) and x/sys at v0.32.0, cloned from
their GitHub mirrors and used through `replace` lines, so the Go module
proxy is not needed.

```console
$ git clone https://github.com/golang/crypto /opt/wgwitness/crypto && git -C /opt/wgwitness/crypto checkout v0.37.0
$ git clone https://github.com/golang/sys /opt/wgwitness/sys && git -C /opt/wgwitness/sys checkout v0.32.0
$ (cd scripts/witness/xchachawitness && GOFLAGS=-mod=mod GOPROXY=off go build -o /opt/wgwitness/xchachawitness .)
$ python3 scripts/make_xchacha_vectors.py    # rewrites vectors/xchacha.vec
```

**NaCl**: the system's libsodium 1.0.18 (`libsodium23`, reached through
`ctypes`, no headers), and golang.org/x/crypto's `nacl/*` packages from
the same checkouts as XChaCha20 above. The script fetches NaCl's own
examples from libsodium's `test/default` at tag 1.0.18 and requires
libsodium to reproduce them; `--ours` has libsodium and Go open boxes
and sealed boxes made by the built Python module.

```console
$ (cd scripts/witness/naclwitness && GOFLAGS=-mod=mod GOPROXY=off go build -o /opt/wgwitness/naclwitness .)
$ python3 scripts/build_python.py
$ python3 scripts/make_nacl_vectors.py --ours    # rewrites vectors/nacl.vec
```

**Dual_EC_DRBG**: OpenSSL FIPS module 2.0.5's `fips_drbg_ec.c`, fetched
unchanged and built against OpenSSL 1.0.2 (`/opt/openssl102`) through the
stand-in headers in `scripts/witness/dualecwitness/shim`. The script
requires it to reproduce Bouncy Castle 1.78.1's published vectors (an
implementation independent of OpenSSL) before writing the corpus.

```console
$ scripts/witness/dualecwitness/build.sh         # builds /opt/dualecwitness/dualec
$ python3 scripts/make_dual_ec_vectors.py        # rewrites vectors/dual_ec.vec
```

**Unix crypt(3)**: the system's `libcrypt` (libxcrypt 4.4.36) through
`ctypes`, and its `test/ka-table.inc` of known answers, whose header
says Passlib generated them. The script fetches the table, keeps the
methods implemented here, and requires `libcrypt` to reproduce each row.

```console
$ python3 scripts/make_unix_crypt_vectors.py     # rewrites vectors/unix_crypt.vec
```

**Linear congruential generators**: the rand() of musl 1.2.5 and newlib
4.4.0, and of MSVC as Wine 9.0's msvcrt reimplements it, compiled from
their own sources (newlib's and Wine's per-thread state reached through
the stand-ins in `scripts/witness/lcgwitness/shim`); PCG's 64 bit step for
Knuth's MMIX constants; libstdc++'s `minstd` engines; the JDK's
`java.util.Random`; and the system glibc through `ctypes` for TYPE_0
`random()` and the `drand48` family. The build fetches each source at a
pinned tag and checks its SHA-256.

```console
$ scripts/witness/lcgwitness/build.sh           # builds /opt/lcgwitness
$ python3 scripts/make_lcg_vectors.py           # rewrites vectors/lcg.vec
```

**WireGuard**: wireguard-go (`WireGuard/wireguard-go`, its main branch)
with the x/ modules at the versions its `go.mod` pins, all from GitHub,
and `replace` lines for them and three empty stand-ins for modules the
Linux build does not compile (wintun, gvisor, btree). The witness is a
test file copied into wireguard-go's `device` package, because the
handshake functions it drives are unexported, and built as a test
binary.

```console
$ git clone https://github.com/WireGuard/wireguard-go /opt/wgwitness/wireguard-go
$ git clone https://github.com/golang/net /opt/wgwitness/net && git -C /opt/wgwitness/net checkout v0.39.0
$ git clone https://github.com/golang/time /opt/wgwitness/time && git -C /opt/wgwitness/time checkout v0.7.0
$ # crypto and sys as for XChaCha20 above; stand-ins: a go.mod naming each module, nothing else
$ cat >> /opt/wgwitness/wireguard-go/go.mod    # replace lines: x/crypto, net, sys, time => ../...,
$                                              # wintun, gvisor, btree => ../stubs/...
$ cp scripts/witness/wgwitness/witness_test.go /opt/wgwitness/wireguard-go/device/
$ (cd /opt/wgwitness/wireguard-go && GOFLAGS=-mod=mod GOPROXY=off go test -c -o /opt/wgwitness/wgwitness ./device)
$ cargo build --release --example wireguard
$ python3 scripts/check_wireguard.py
$ python3 scripts/check_wireguard.py --record    # rewrites examples/products/fixtures/wireguard.vec
```

**Smart cards**: no hardware. The card is CanoKey's firmware core
(`canokeys/canokey-core` at e558d5c, with its submodules) built as
`apdu-replay`, a process that reads APDUs on standard input and keeps
its state for as long as it runs; `scripts/witness/cardsim.py` serves it
on a TCP port and answers for the YubiKey OTP application, which CanoKey
does not have. yubikit is a `Yubico/yubikey-manager` checkout (4ca60f7),
used from its source tree. For the PC/SC path, pcsc-lite 2.3.0
(`LudovicRousseau/PCSC`) without udev, libusb, systemd or polkit, with
two stand-ins for the files its build generates with flex
(`scripts/witness/pcsc-lite/`: reader.conf parsing, and the USB bundle
parser the build leaves out), and `scripts/witness/ifd-tcpcard`, a
reader driver whose card is `cardsim.py`'s port.

```console
$ git clone --recursive https://github.com/canokeys/canokey-core && cd canokey-core
$ git checkout e558d5c && git submodule update --init --recursive
$ cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_APDU_REPLAY=ON
$ ninja -C build apdu-replay && install -D build/apdu-replay /opt/canokey/apdu-replay
$ git clone https://github.com/Yubico/yubikey-manager /opt/yubikit/yubikey-manager
$ git clone https://github.com/LudovicRousseau/PCSC && cd PCSC && git checkout 2.3.0
$ cp $ALLCRYPT/scripts/witness/pcsc-lite/*.c src/   # m4/: ax_pthread.m4, ax_recursive_eval.m4
$                                                  # from autoconf-archive
$ ./bootstrap && ./configure --prefix=/opt/pcsclite --disable-libudev --disable-libusb \
      --disable-libsystemd --disable-polkit --disable-documentation && make install
$ gcc -shared -fPIC -I/opt/pcsclite/include/PCSC -o /opt/pcsclite/lib/ifd-tcpcard.so \
      scripts/witness/ifd-tcpcard/ifd-tcpcard.c
$ cargo build --release --example smartcard
$ python3 scripts/check_smartcard.py --pcsc /opt/pcsclite
$ python3 scripts/check_smartcard.py --record    # rewrites examples/products/fixtures/smartcard.vec
$ cargo test --example smartcard
```

To try a real card by hand, the commands are the ones above without
`--card`: the example finds the first reader with a card, or the one
`--reader NAME` names.

**Git signing**: the system's git 2.43 and GnuPG 2.4.4, and OpenSSH
10.0's `ssh-keygen` from `/opt/openssh` (git's own `ssh-keygen` would do
as well; this one is the one the SSH work is checked against). The
script makes its keys and repositories in a temporary directory.

```console
$ cargo build --release --example gitsign
$ python3 scripts/check_gitsign.py
$ python3 scripts/check_gitsign.py --record    # rewrites examples/products/fixtures/gitsign/
$ cargo test --example gitsign
```

**DNSSEC**: dnspython at its v2.7.0 tag, from a git checkout in
`/opt/dnswitness/` (the current main branch needs a newer
python-cryptography than the one here, for ML-DSA), with
python-cryptography for its keys. Nothing else: GOST and SM2, which
dnspython does not have, are checked against their RFCs' examples by
`cargo test`.

```console
$ git clone --depth 1 --branch v2.7.0 https://github.com/rthalley/dnspython /opt/dnswitness/dnspython
$ cargo build --release --example dnssec
$ python3 scripts/check_dnssec.py
$ python3 scripts/check_dnssec.py --record    # rewrites examples/products/fixtures/dnssec/
$ cargo test --example dnssec
$ cargo test --release --example dnssec -- --ignored    # RSA and DSA key generation
```

**PDF**: the system's qpdf 11.9.0 and pdftk-java 3.3.3 (`apt install
qpdf pdftk-java`), and qpdf's source tree for its test files - a clone
of `qpdf/qpdf` at `v11.9.0`, only read. pdftk-java reads up to
revision 4, so the script asks it nothing about AES-256.

```console
$ cargo build --release --example pdf
$ python3 scripts/check_pdf.py --qpdf-tests ~/src/qpdf/qpdf/qtest/qpdf
$ python3 scripts/check_pdf.py --qpdf-tests ~/src/qpdf/qpdf/qtest/qpdf --record
$ cargo test --example pdf
```

`--record` rewrites `examples/products/fixtures/pdf*`; the files ours
and qpdf encrypt carry random IVs and salts, so every recording
differs from the last in those files while listing the same.

**Office**: msoffcrypto-tool (`nolze/msoffcrypto-tool`) and olefile
(`decalage2/olefile`), both pure Python, cloned - only put on the path,
not installed - with python-cryptography from the system; and
LibreOffice 24.2 with `python3-uno`, which the script starts headless
with a profile of its own.

```console
$ cargo build --release --example office
$ python3 scripts/check_office.py --msoffcrypto ~/src/msoffcrypto-tool --olefile ~/src/olefile
$ python3 scripts/check_office.py --msoffcrypto ~/src/msoffcrypto-tool --olefile ~/src/olefile --record
$ python3 scripts/make_office_xor_vectors.py --msoffcrypto ~/src/msoffcrypto-tool    # rewrites vectors/office_xor.vec
$ cargo test --example office
```

**OpenDocument**: the same LibreOffice, through `scripts/libreoffice_uno.py`.
The check sets `DefaultVersion` (ODF 1.1 for Blowfish) and
`ExperimentalMode` (the whole-package scheme) in its own profile.

```console
$ cargo build --release --example odf
$ python3 scripts/check_odf.py
$ python3 scripts/check_odf.py --record    # rewrites examples/products/fixtures/odf*
$ cargo test --example odf
```

**Key stores**: the system's OpenSSL 3.0 and `/opt/openssl35` (PBMAC1),
python-cryptography, NSS's `pk12util` and `certutil` (`libnss3-tools`),
and the JDK's `keytool` and `java`, which runs
`scripts/witness/javakeystore/Rewrite.java` from source - the KeyStore
API writes a store under the empty password, which keytool will not.
A store under a NULL password comes from OpenSSL's `PKCS12_create`
through ctypes, since the command line cannot pass one.

```console
$ cargo build --release --example keystore
$ python3 scripts/check_keystore.py
$ python3 scripts/check_keystore.py --record    # rewrites examples/products/fixtures/keystore*
$ cargo test --example keystore
```

keytool writes JCEKS at 10,000 iterations, the JDK's floor
(`-J-Djdk.jceks.iterationCount`), rather than its default of 200,000,
and only one of NSS's stores is recorded: its MAC is 600,000 iterations
with no option to lower it, which a debug build takes twelve seconds
over.

**JOSE**: jwcrypto (`latchset/jwcrypto`), pure Python over the
system's python-cryptography, cloned and only put on the path; and the
system's PyJWT.

```console
$ cargo build --release --example jose
$ python3 scripts/check_jose.py --jwcrypto ~/src/jwcrypto
$ python3 scripts/check_jose.py --jwcrypto ~/src/jwcrypto --record    # rewrites examples/products/fixtures/jose.vec
$ cargo test --example jose
```

`/opt/cryptsetup/run.sh` is a wrapper that sets `LD_LIBRARY_PATH` to
the prefix. Without root, cryptsetup can read and write headers and
keyslots and, through `cryptsetup reencrypt`, encrypt and decrypt data
in userspace; it cannot activate a volume, which is what the
`--cryptsetup-tests` images make up for: the kernel wrote those.

## Checking constant time

```
python3 scripts/ct_check.py              # the whole table
python3 scripts/ct_check.py pow_ct       # one case, with the reports
```

Needs `valgrind` and `objdump` on the path and nothing else — no network, no
extra crates. On Debian or Ubuntu that is `apt install valgrind binutils`;
under WSL, install them inside the distribution rather than on Windows.

The technique is ctgrind. Memcheck already tracks which bits of memory are
"undefined" and complains when one reaches a conditional jump, a conditional
move or a memory address. Rename "undefined" to "secret" and that is exactly
the property constant-time code has to have. So `tools/src/bin/ct_bignum.rs` marks
the secrets and runs the operation, and every complaint is a place where a
secret reached a branch.

The table in `ct_check.py` has three kinds of row, and the mix is the point:

- **clean** — must produce no reports. `Montgomery::pow_ct`, the `Secret`
  comparisons, fixed-width serialisation, bitsliced AES and the modes that
  use it, GHASH.
- **leaks** — must produce some. `BigUint::add`, `mod_inverse`, `mod_pow`,
  and AES's one-block table route.
  These are the positive controls. A harness that only ever asserts "no
  reports" passes just as well when it has silently stopped working, so a
  clean result from one of these rows **fails the run**.
- **a set of names** — the call sites, where a small, argued set of branches
  remain. The row lists the functions allowed to appear, each one explained
  beside it, and a leak anywhere else fails the run with the new function
  named. Deliberately not a count: counts held for about an hour and broke
  when an unrelated change shifted the optimiser's inlining, because a
  valgrind count is the number of distinct stacks rather than a property of
  the code.

What it catches: data dependent branches, secret-indexed table lookups, early
exits. What it does not: variable-latency instructions, and anything the
optimiser folded away before valgrind saw it. It is a lower bound on the
problems, not a proof of their absence.

**One variable-latency instruction is checked separately: division.**
Before the valgrind rows, `ct_check.py` disassembles the harness and
fails if a division instruction (`div`, `idiv`, or a call to the
compiler's wide-division routines such as `__udivti3`) comes from a
source file whose code runs on secrets: the fixed-width bignum and
Montgomery code, the curve fields and point arithmetic, X25519 and X448,
EdDSA and ECDSA, RSA and Diffie-Hellman, ML-KEM and ML-DSA, AES, GHASH,
ChaCha, Salsa20, Poly1305 and the NaCl boxes. A division's latency
depends on its operands on many processors, and a division on a secret
in ML-KEM is the KyberSlash leak. Each division is attributed through
the debug line table's whole inline chain (`addr2line -i`), so code
inlined into another function, or a `div_ceil` inlined from the standard
library, is still charged to the file it was written in. Divisions in
those files on public values - a length, a modulus - are listed in
`PUBLIC_DIVISIONS` with the line's text and the reason; anything else
fails with the file, line and source. The scan has a control of its own
- a function in the harness that only divides - so a scan that has
stopped reading the disassembly fails rather than reporting nothing.

The harness's list of cases (`ct_bignum --list`) is compared with the
table before anything runs, so a case written in one and not the other
fails instead of silently not running.

### Timing on the machine itself: dudect

Valgrind checks the compiled code against a model of the processor. The
other half is the processor: `tools/src/bin/dudect.rs` times each target
on two classes of input - one fixed secret and fresh random ones,
interleaved at random - and applies Welch's t-test to the two
distributions of cycle counts (Reparaz, Balasch and Verbauwhede, "Dude,
is my code constant time?", 2017). It sees what valgrind cannot: an
instruction whose latency depends on its data, and whatever the
microarchitecture adds.

```
cargo run --release -p allcrypt-tools --bin dudect                    # every row, 10 s each
cargo run --release -p allcrypt-tools --bin dudect -- --seconds 60 x25519
cargo run --release -p allcrypt-tools --bin dudect -- --list
```

It prints, per row, the measurements taken, the mean cycles and the
largest |t| over the whole sample and twenty cropped versions of it
(the cropping removes the long tail of interrupts, where a small shift
in the body would otherwise hide). |t| above 10 means the two classes
take different time; 4.5 to 10 is inconclusive and wants a longer run.
The rows:

- **`control_xor`** - no difference between the classes but the data.
  If its |t| is large, the machine is the cause, not the code: pin the
  run to one core (`taskset -c 2 ...`), stop other work, and run again.
  The tool exits non-zero and says so.
- **`control_memcmp`, `control_biguint_pow`** - variable time on
  purpose, and they must show a large |t|. If they do not, the
  measurement is not working on this machine and no clean row means
  anything.
- **the targets** - X25519, Ed25519 and ECDSA signing, ML-KEM-768
  decapsulation (a valid ciphertext against random ones, which is the
  implicit-rejection path), bitsliced AES, Poly1305, ChaCha20-Poly1305,
  the secretbox tag comparison and the box key. Each must stay under 10.

A clean result is evidence over the inputs and the time it ran, not a
proof: a leak smaller than the noise is not seen, and a busy machine
hides more. A target that fails twice on a quiet machine, with the
controls behaving, is a finding.

### After a new toolchain, or on a new machine

Constant time is a property of the binary, so it is re-established
whenever the compiler or the processor changes - a Rust upgrade can
turn a mask back into a branch (`Montgomery::conditional_subtract` did,
which is why `bignum::ct::opaque` exists), and a processor can have a
data-dependent instruction its predecessor did not. After building, on
the machine that matters:

```
rustc -V                                              # record it with the results
python3 scripts/ct_check.py                           # valgrind rows, division scan
python3 scripts/ct_check.py --aes-ni                  # if the build uses the aes-ni feature
taskset -c 2 cargo run --release -p allcrypt-tools --bin dudect -- --seconds 30
taskset -c 2 cargo run --release -p allcrypt-tools --features aes-ni,simd --bin dudect -- --seconds 30
```

`ct_check.py` needs `valgrind` and binutils (`objdump`, `addr2line`);
dudect needs nothing. Both exit non-zero on anything unexpected. The
first two answer "does this compiler still emit what the code claims";
the dudect runs answer "does this processor run it in constant time",
and the second of them covers the hardware AES and vectorised ChaCha
paths. On a machine without Rust, a static binary built elsewhere runs
as it is:

```
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p allcrypt-tools \
    --bin dudect --target x86_64-unknown-linux-gnu
# then, on the machine: target/x86_64-unknown-linux-gnu/release/dudect --seconds 30
```

GHASH relies on the opposite assumption about **multiplication**: its
carry-less products are built from 64-bit integer multiplies on secret
operands, which take a fixed time on every x86-64 and 64-bit ARM core in
use. Some small 32-bit cores have an early-terminating multiplier; the
library does not target them, and BearSSL documents the same limitation
for the same code.

## Building for speed

A plain `cargo build --release` runs on every x86-64 processor (and on
the other architectures Rust targets), and everything in it is portable
Rust. Two kinds of option make it faster: a CPU level for the whole
build, and features that add hand-written paths for particular
instructions. They are independent and combine.

| | portable | `x86-64-v3` | `aes-ni` feature | both | OpenSSL 3.0 |
|---|---|---|---|---|---|
| AES-128-ECB | 243 | 742 | 8,361 | 8,577 | 10,161 |
| AES-128-CTR | 243 | 769 | 5,119 | 4,781 | 9,748 |
| AES-128-CBC encrypt | 236 | 234 | 1,051 | 1,001 | 1,534 |
| AES-128-CBC decrypt | 185 | 664 | 6,635 | 7,574 | 9,977 |
| AES-128-GCM | 139 | 204 | 3,174 | 3,015 | 5,750 |
| AES-256-XTS | 175 | 557 | 4,088 | 4,407 | 6,158 |
| AES-128-CCM | 110 | 164 | 558 | 459 | 1,570 |
| ChaCha20 | 914 | 1,078 | 933 | 1,034 | 3,717 |
| SHA-1 | 387 | 364 | | | 852 |
| SHA-256 | 182 | 233 | | | 384 |
| SHA3-256 | 260 | 324 | 259 | 321 | 365 |
| DES / 3DES (CBC) | 54 / 20 | 46 / 20 | | | 66 / 26 |

MB/s on a 2-core Xeon (Cascade Lake) at 2.8 GHz; the `aes-ni` column is
the portable build plus the feature, and "both" adds `x86-64-v3` to it.
That processor has no SHA extensions, so the `sha-ni` feature changes
nothing there; [its own section](#the-sha-ni-feature-hardware-sha-1-and-sha-256)
has numbers from one that does. The ChaCha20 row is without the `simd`
feature, which [has its own section too](#the-simd-feature-chacha20-on-vector-registers).
GCM and XTS are keyed once and run message after message, as
`openssl speed` runs them. Runs differ by ten or fifteen percent, and
`scripts/bench_compare.py` (below) prints this table, every column, on
any machine.

Public-key operations, per second on the same machine, are not affected
by either option:

| | allcrypt | OpenSSL 3.0 |
|---|---|---|
| X25519 | 17,700 | 26,400 |
| X448 | 3,500 | 4,800 |
| Ed25519 sign / verify | 16,900 / 7,000 | 22,400 / 7,900 |
| Ed448 sign / verify | 3,900 / 1,500 | 4,300 / 4,300 |
| ECDSA P-256 sign / verify | 18,500 / 5,600 | 40,100 / 13,300 |
| RSA-2048 sign / verify | 716 / 25,700 | 2,625 / 48,200 |

The Curve25519 and Curve448 algorithms have fields of their own
(`ec/field25519.rs`, `ec/field448.rs`) and Edwards arithmetic on them
(`ec/edwards.rs`), all constant time. The Weierstrass curves - the NIST
ones, secp256k1, Brainpool, SM2, GOST - run on `ec/fixed.rs`: Montgomery
arithmetic on fixed-size arrays (`bignum/fixed.rs`), with P-256's
modulus compiled in as a constant, a table of the base point's multiples
for `k * G`, and a sliding window for the public half of verification.
RSA and finite-field Diffie-Hellman run on `Montgomery` over
`bignum::ct::Secret`, whose multiplication and squaring are compiled
separately for the common limb counts (4, 6, 8, 16, 24 and 32) so their
loops have constant bounds. On an i9-13900K RSA-2048 signs 1,455 times a
second against OpenSSL's 2,810, and verifies 50,000 times against
93,600. OpenSSL's lead in public-key work is mostly its
assembly multipliers: a 256-bit Montgomery product here is about 25 ns,
a chain of carries that Rust without `asm!` cannot split the way
`mulx`/`adcx`/`adox` do.

### `-C target-cpu=x86-64-v3`: AVX2

The bitsliced AES, ChaCha20, DES and Serpent are written as loops the
compiler vectorises. The portable build gets 128-bit SSE2, which every
x86-64 has; `x86-64-v3` lets it use 256-bit AVX2, which every Intel
processor since Haswell (2013) and every AMD since Excavator has. A
binary built this way **does not start on an older processor**, so it is
a choice for builds that run on known machines - your own, a server
fleet - and not for something distributed to strangers.

    # Linux, macOS
    RUSTFLAGS="-C target-cpu=x86-64-v3" cargo build --release
    # Windows, PowerShell
    $env:RUSTFLAGS = "-C target-cpu=x86-64-v3"; cargo build --release
    # Windows, cmd
    set RUSTFLAGS=-C target-cpu=x86-64-v3 && cargo build --release

    # The Python module
    python3 scripts/build_python.py --target-cpu x86-64-v3

    # Every build in your own checkout, in .cargo/config.toml
    # (this repository's copy of that file is local and not committed):
    [build]
    rustflags = ["-C", "target-cpu=x86-64-v3"]

Changing `RUSTFLAGS` rebuilds everything once. The same applies to
`cargo test` and to maturin, which both read the variable.

**Do not use `-C target-cpu=native` on a recent Intel processor without
reading this.** On top of AVX2 it lets LLVM turn table lookups into
AVX2 *gather* instructions, which Intel's microcode mitigation for
Gather Data Sampling (2023) made very slow. Measured on the machine
above, `native` made the table-driven code three to five times slower -
AES's one-block path and CBC encryption 0.22x, Whirlpool 0.19x,
Streebog 0.40x - while helping the vectorised code exactly as much as
`x86-64-v3` does. `x86-64-v3` produces no gathers. If you want `native`
anyway, add `-C target-feature=+prefer-no-gather`, which rustc accepts
with a warning that the flag is unstable.

On 64-bit ARM nothing is needed: NEON is part of the baseline and the
same loops vectorise without a flag.

### The `aes-ni` feature: hardware AES and GHASH

    cargo build --release --features aes-ni
    python3 scripts/build_python.py --features aes-ni

    # As a dependency
    allcrypt = { path = "...", features = ["aes-ni"] }

With the feature, on an x86-64 processor that has AES-NI and PCLMULQDQ
(every Intel since 2010, every AMD since 2011), AES runs on `aesenc` and
`aesdec` and GCM's GHASH on `pclmulqdq`. The check is made once, at run
time, so a build with the feature still runs on a processor without the
instructions and falls back to the portable code. `api::hardware_aes()`
(`allcrypt.hardware_aes()` in Python) says which one this process got.
On other architectures the feature does nothing.

**Why it is not on by default.** Reaching these instructions needs
`unsafe`. Rust makes a call into a function compiled for a CPU feature
unsafe from any caller that is not itself compiled for it, and that
holds even after the run-time check and even with the feature enabled
for the whole build - so there is no way round it, and the library's
cryptography is otherwise free of `unsafe`. The feature confines it to
one module, `src/block_ciphers/aes_ni.rs`: the call sites that enter
it, in `aes.rs` and `ghash.rs`, are each reached only after the CPU
check, and that is all their `unsafe` asserts. Inside, blocks move
between memory and registers through two functions, `load` and
`store_into`, whose pointer comes from a reference to exactly the
sixteen bytes moved.

**Why you would want it.** Two reasons, and the second matters more
than the numbers suggest.

- *Speed*: AES-128 is 8 GB/s in ECB, 6.6 GB/s for CBC decryption, 5
  GB/s in CTR, 3 GB/s in GCM and 4 GB/s in AES-256-XTS - twenty to
  thirty times the portable build. CTR, GCM and XTS run in one pass
  (`ctr_xor` and `xts_blocks` in the cipher, eight blocks side by side,
  counters and tweaks made in registers), GHASH eight blocks to a
  reduction, and CBC encryption through `encrypt_block_in_place`. What
  is left of the gap to OpenSSL is its interleaving: OpenSSL computes
  GCM's AES and GHASH in one loop, and CBC encryption and CCM's MAC are
  one block at a time for both.
- *Timing*: the instructions take the same time whatever the key and
  data. In the portable build the multi-block modes (ECB, CTR, GCM,
  XTS, CBC decryption, CCM's keystream) are constant time already,
  because they are bitsliced; the **one-block-at-a-time modes - CBC
  encryption, CFB, OFB, CMAC, CCM's CBC-MAC - use lookup tables and leak
  the key through the cache**. With the feature they are constant time
  too. `python3 scripts/ct_check.py --aes-ni` measures exactly that: the
  same valgrind table, built with the feature, where the one-block row
  that must report in the portable build must come back clean.

If you run CBC encryption, CMAC or CCM on a machine where other code
shares the processor, and the hardware has AES-NI, this feature is the
fix for a real side channel, not an optimisation.

### The `sha-ni` feature: hardware SHA-1 and SHA-256

    cargo build --release --features sha-ni
    cargo build --release --features aes-ni,sha-ni
    python3 scripts/build_python.py --features aes-ni,sha-ni

With the feature, on an x86-64 processor that has the SHA extensions,
SHA-1, SHA-224 and SHA-256 run on `sha1rnds4` and `sha256rnds2`. Intel
added them with Goldmont (2016) for its small cores and Ice Lake (2019)
and Alder Lake (2021) for its large ones, so many Skylake-derived
desktops and servers lack them; AMD has had them since Zen (2017). As
with `aes-ni`, the check is made once at run time and a processor
without them gets the portable code. SHA-0 always does, since the
instructions apply SHA-1's schedule rotation, and SHA-384 and SHA-512
have no instructions on x86-64.

It is off by default for the same reason as `aes-ni`, and the `unsafe`
is confined the same way, to `src/hash_functions/sha_ni.rs`. Timing is
not a reason here: SHA has no table lookups or secret-dependent
branches, so the portable code is constant time already.

| | portable | `sha-ni` feature | OpenSSL 3.0 | OpenSSL, SHA extensions masked |
|---|---|---|---|---|
| SHA-1 | 800 | 2,793 | 2,911 | 1,497 |
| SHA-256 | 474 | 2,527 | 2,578 | 739 |

MB/s on one core of an i9-13900K, 16 KiB buffers. The feature brings
both within a few percent of OpenSSL. Against OpenSSL without the
extensions the portable build is 0.53x for SHA-1 and 0.64x for
SHA-256: OpenSSL's remaining lead there is computing the message
schedule four words at a time in vector registers, alongside the scalar
rounds.

### The `simd` feature: ChaCha20 on vector registers

    cargo build --release --features simd
    cargo build --release --features aes-ni,sha-ni,simd

With the feature, on x86-64, ChaCha20 - and XChaCha20, and the
keystream of ChaCha20-Poly1305 - computes eight blocks at a time in
AVX2 registers when the processor has AVX2, chosen at run time, and
four at a time in SSE2 otherwise. Without it, the compiler is left to
vectorise the portable code and does not: it keeps the rounds scalar
whatever the code looks like, `x86-64-v3` included. On other
architectures the feature does nothing.

It is off by default for the same reason as the other two, and its
`unsafe` is confined the same way, to
`src/stream_ciphers/chacha_simd.rs`. Like SHA, ChaCha has no secret
table lookups or branches, so the portable code is constant time
already; this is only speed.

| | portable | `simd` feature | OpenSSL 3.0 |
|---|---|---|---|
| ChaCha20, i9-13900K | 1,651 | 3,550 | 4,594 |
| ChaCha20, Xeon above | 920 | 2,009 | 3,654 |

MB/s, 16 KiB buffers; the i9 row is the best of five runs. On the i9
that is 0.77x of
OpenSSL's AVX2 code; on the Xeon OpenSSL uses AVX-512, which this
library does not. A processor without AVX2 gets the SSE2 path, which is
barely faster than the portable code (985 MB/s on the Xeon): sixteen
words of state fill all sixteen SSE registers, and SSE2 has no byte
shuffle for the rotations.

ChaCha20-Poly1305 is the two run one after the other. Poly1305 is
portable code in every build - four blocks at a time against
precomputed powers of r, so the multiplications do not wait on each
other - and runs at 4,868 MB/s on the i9, against 4,405 for OpenSSL's
through python-cryptography (`openssl speed` has no Poly1305). The AEAD
with the `simd` feature is 2,016 MB/s there against OpenSSL's 3,233:
OpenSSL computes the cipher and the MAC in one interleaved pass.

### Measuring

```
cargo run --release -p allcrypt-tools --bin bench_speed [filter]
cargo run --release -p allcrypt-tools --features aes-ni,sha-ni,simd --bin bench_speed [filter]
python3 scripts/bench_compare.py [filter]
python3 scripts/bench_compare.py --builds portable,hw [filter]
```

`bench_speed` prints throughput for the hashes, ciphers, AEADs and KDFs
and the rate of the public-key operations, one row per line; a filter
keeps the rows whose name contains it. `bench_compare.py` builds it four
ways - `portable`, `x86-64-v3`, `hw` (the three hardware features) and
`v3+hw`, each in its own directory under `target/bench/` - and sets each
row's four numbers beside
`openssl speed` on the same 16 KiB buffers, with `hashlib` and
python-cryptography for the KDFs and Poly1305; the ratio is the best of ours against
OpenSSL. On a processor without AVX2 the `x86-64-v3` builds are skipped,
since they would not start, and off x86-64 there is only the portable
one. The AES, SHA-1 and SHA-256 rows carry one more OpenSSL column,
"no NI", with the hardware instructions masked off through
`OPENSSL_ia32cap`: the software-against-software comparison for the
portable build.

Speed is not this library's first concern. The script is for finding
something unreasonably slow, not for ranking.

## Checking the documentation

Every fenced `rust` and `python` block in `README.md` and `docs/` is real,
compiled code. To verify after changing either the docs or the API:

```
python3 scripts/check_docs.py
```

It extracts the snippets, compiles the Rust ones as an example, and runs the
Python ones against the built module. Blocks tagged ```` ```rust,ignore ````
or ```` ```python,ignore ```` are skipped — use that only for genuinely
illustrative fragments.

The Rust blocks go into `examples/doc_examples.rs`, which is generated and
gitignored. **It is deleted again when the run succeeds**, and that is not
tidiness. cargo auto-discovers `examples/*.rs`, so while that file exists
it is compiled by every `cargo build`, `cargo test` and `cargo clippy`,
and it is regenerated only by this script. Change a signature the docs use,
run `cargo test` without running this first, and the workspace stops
compiling with an error inside a file nobody wrote:

```
error[E0061]: this function takes 6 arguments but 5 arguments were supplied
   --> examples/doc_examples.rs:626:32
```

That is a stale artifact, not a broken tree, and `rm examples/doc_examples.rs`
clears it. It is invisible to anyone who runs the whole gate — doing so
regenerates the file — and it is exactly what somebody running a single
`cargo test` hits, which is how it was reported.

On a **failure** the file is kept, because the line numbers in the error
refer to it, and the script says so. `cargo test` then keeps failing until
the doc block is fixed, which is correct: the docs are broken.

Gating the target behind a cargo feature was tried first and does not
work. cargo validates a declared `[[example]]`'s path when it parses the
manifest, feature or no feature, so a fresh clone without the generated
file fails to parse `Cargo.toml` at all.

## Checking the error messages

```
python3 scripts/check_messages.py
```

A Rust string literal split across source lines keeps the newline **and
every continuation line's indentation**, unless each line ends with a
backslash. Forget one and the message reaches a user as

```
...and every one of them                          needs TLSv1.3 or later
```

Nothing notices: it compiles, the wording is right, and every test that
looks at such a message uses `contains` with a substring that does not
straddle the join. A user asked what one of these meant, which is how the
first was found; five had accumulated in four files, the oldest in the
TLS 1.3 record layer.

The lint flags a one-line prose literal — no `\n`, longer than 40
characters — containing a run of three or more spaces. It skips raw
strings and any literal with a **width or alignment** format spec
(`{:11}`, `{:>9.2?}`), because that is a table row where the runs are
column separators; `tools/src/bin/bench_ec.rs` and `bench_modpow.rs` were the
false positives that rule exists for. `{}` and `{:?}` are not enough to
exempt a literal, since four of the five real findings used nothing else.

It carries its own cases, in `SELF_TEST`: the five findings as they were
before the fix, and the false positives from its first run. A lint with no
cases of its own reports nothing on a clean tree, which is
indistinguishable from a lint that has stopped working.


## Checking against real servers, by hand

**No test in this repository uses the network, and none should.** The gate
is offline, deterministic and fast, and a test that fails because a host
is down or a CA rotated is a test that teaches people to ignore failures.

`scripts/check_live.py` is a development tool, kept out of `pytests/` for
exactly that reason:

```console
$ python3 scripts/check_live.py              # the badssl.com matrix
$ python3 scripts/check_live.py --general    # ordinary public servers too
$ python3 scripts/check_live.py --host expired.badssl.com --expect reject
$ python3 scripts/check_live.py --gost       # the public GOST endpoints
$ python3 scripts/check_live.py --gost-host 127.0.0.1:4433   # any server
```

Run it by hand after changing certificate verification or the handshake.

### The GOST suite matrix

`--gost` sends **one suite per connection** rather than offering
everything and letting the server choose. That is not a stylistic
preference. All three CryptoPro endpoints prefer
`KUZNYECHIK_CTR_OMAC`, so for as long as this section offered the whole
list, three green rows exercised **one** of the nine GOST suites — and
Magma is a different block cipher, IMIT a different MAC, the `LEGACY`
spelling a different key derivation, and the 2001 suite a different
signature algorithm and key encoding. Each row now checks that the suite
negotiated is the one it asked for, because a restriction that silently
failed would print nine green rows having measured one.

The summary at the end lists what was **not** reached, with the reason:
`TLS 1.3 only` for the four RFC 9367 MGM suites, `needs a GOST R
34.10-2001 certificate` for the 2001 one, and `no endpoint here offered
it` otherwise. A matrix that reported "1 spoken" as a pass would be the
same mistake one level up.

Each row also prints the server key's **parameter-set OID**, not just
its curve. `id-GostR3410-2001-CryptoPro-A-ParamSet` and
`...-XchA-ParamSet` are the same domain parameters under two OIDs, so
both read as `gost256-a`, and a ClientKeyExchange naming the wrong one is
refused with a fatal `decode_error`. Two of the three CryptoPro
endpoints are on XchA. Printing the curve and not the OID is what made
that invisible.

`--gost-host` points the same matrix at any server, including a local
one, which is what makes it usable without the internet.

`scripts/fetch_chain.py` is the companion to it, and exists because
`check_live.py` throws away the evidence: a row saying *"reject:
certificate: ..."* tells you something is wrong and gives you nothing to
work on. It drives the handshake by hand and reads the peer chain
**before** deciding anything, so the certificate is saved whether the
handshake succeeded, failed at verification, or failed at parsing.

```console
$ python3 scripts/fetch_chain.py tlsgost-256.cryptopro.ru
$ python3 scripts/fetch_chain.py www.cryptopro.ru --suites legacy
```

What comes out goes in `vectors/live/` and becomes an offline test -
which is worth far more than the live check that found it.
`tests/test_live_gost_certificates.rs` is the result of the first run.

`--gost` is the one row set that is about somebody else's servers rather
than badssl's. It tries the public CryptoPro GOST TLS endpoints, which
this project does not control and cannot vouch for — a failure there may
be the network, a renamed host, or the endpoint being gone, and the
script prints those three cases apart for that reason. **It also says
loudly when nothing negotiated a GOST suite**, because that is what a
TLS-terminating proxy between you and the server looks like, and every
row goes green while measuring the proxy. Run from a sandbox, that is
exactly what happens; `detect_interception()` names the CA doing it.

It exists because of a gap the offline suite cannot close: every
certificate our verifier has judged is one we generated, and the ways we
make them wrong are the ways we already thought of.
[badssl.com](https://badssl.com) is a standing set of deliberately broken
servers maintained by other people, which is the point. Each row says what
should happen and why, and the rows that matter are the ones that must
**fail** - a client that accepts everything passes every happy-path check
ever written.

It also drives `tls-v1-0.badssl.com:1010` and its siblings, which is the
most direct check available that the TLS 1.0 and 1.1 support is real.

### The thing that makes this lie

A TLS-terminating middlebox - a corporate proxy, a sandbox egress gateway,
some antivirus - mints a fresh certificate for whatever name is in the
SNI, signed by a CA that is already in your trust store. Behind one of
those, `expired.badssl.com` returns a **valid, unexpired** certificate, and
accepting it is correct. Every deliberately broken case is laundered into
a working one.

The script probes for that before anything else and refuses to report
certificate results if it finds one. That check is the most important
thing in the file: without it a run behind a proxy produces a screenful of
failures against correct code, which is worse than no run at all.
