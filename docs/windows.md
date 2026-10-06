# Windows

The library is portable Rust and builds and runs here. The two pieces
that reach *outside* the process — the system trust store and the
random source — have native implementations already
(`CertOpenSystemStoreW` and `BCryptGenRandom`, in `src/trust/mod.rs`
and `src/random/mod.rs`). What does not port is the **shim**, and the
rest of this file is about what to do instead.

## What runs where

| | Linux / macOS | Windows |
|---|---|---|
| `cargo build`, `cargo test` | yes | yes |
| The Python module | `allcrypt.so` | `allcrypt.pyd` — see [building.md](building.md) |
| `allcrypt_ssl.py`, the `SSLContext` replacement | yes | yes, it is pure Python over the module |
| `allcrypt-proxy` | yes | yes |
| The `LD_PRELOAD` shim | yes | **no** — read on |
| `python3 -m pytest` | yes | needs `openssl.exe` on `PATH`; use WSL |
| `scripts/ct_check.py` | yes | needs valgrind; use WSL |

`cargo test` builds the shim crate on Windows too, because it is in
`default-members`, but the crate is `#![cfg(unix)]` and compiles to an
empty library there. That is the whole of its Windows support: the
workspace builds and the tests pass, and no `ssl.dll` worth loading
comes out.

The pytest row is not a portability claim about our code. Twenty-one of
the twenty-seven files drive a real `openssl s_server` or `s_client` as
the other end of the connection — that is the point of them — and a
Windows Python install does not normally have one. Running the suite
under WSL is the path of least resistance, and it is the one this
repository is developed against.

## There is no `LD_PRELOAD` on Windows

Not a missing feature, a different mechanism. Unix and Windows resolve
an import at different times and with different fallbacks, and every
consequence below follows from that one difference.

| | ELF / `LD_PRELOAD` | PE / Windows |
|---|---|---|
| When a name is bound | lazily, through the PLT, against a flat global scope | at load, per importing module, against one named DLL |
| Where "libssl" is named | the soname in `DT_NEEDED` | the file name in the import table |
| Inserting ahead of it | `LD_PRELOAD`, one environment variable | nothing equivalent |
| The real library | still loaded, just unused | not loaded at all if ours takes its name |
| A function we forgot to define | silently resolves to the real one | the process **fails to start** |

That last row is the one that changes the size of the job. On Unix the
shim can implement the sixty-three functions `curl` and `wget` actually
call and let the rest fall through — which is a hazard, and
[shim.md](shim.md) says so at length, because a fall-through gets one
of our structs handed to OpenSSL's code. On Windows there is no falling
through: the loader binds every import by name against the one file, so
a missing export means `curl.exe` will not launch, with "The specified
procedure could not be found." Louder, and considerably more work.

## What Windows does have

Four things get used for this, in descending order of sanity.

### 1. The DLL search order

The loader looks in the **directory the executable was loaded from**
before the system directories. So a DLL of ours, named exactly what the
program's import table names, placed next to the program, is what gets
loaded. No injection, no driver, no privileges beyond writing that one
file.

This is the nearest thing to `LD_PRELOAD` that exists, and the
differences matter:

- **The name has to be exact**, and it is not one name. OpenSSL 3 on
  x64 is `libssl-3-x64.dll`, 1.1.1 is `libssl-1_1-x64.dll`, 1.0.2 is
  `ssleay32.dll`, and a program built against vcpkg or MSYS2 may name
  something else again. `dumpbin /imports` on the executable says which.
- **We would have to export the program's whole import set**, per the
  table above, not the useful subset.
- **The real DLL is displaced, not layered.** Our file *is* libssl for
  that program, so anything it does that we do not implement is simply
  gone rather than delegated.
- **libcrypto is untouched and still loaded**, since the program
  imports from it directly. The shim's existing design ports
  unchanged: `GetModuleHandleW("libcrypto-3-x64.dll")` and
  `GetProcAddress` are the exact analogue of the `dlopen(NULL, ..)` and
  `dlsym` it already does, and for the same reason — bind to the
  libcrypto the program is *already* using rather than loading a second
  one.
- **It is a file named after somebody else's library, in somebody
  else's directory.** In `Program Files` that needs administrator, and
  the next update to the program overwrites or is confused by it.

Mechanically sound; socially unpleasant. Nothing here implements it.

### 2. IAT patching — Detours, MinHook, EasyHook

Inject a DLL into the target process and rewrite its import address
table so the entries for `SSL_connect` and its neighbours point at us.
This is the honest semantic equivalent of `LD_PRELOAD`: the real libssl
stays loaded, and we intercept a chosen subset while everything else
goes where it always went. The sixty-three-function surface would be
enough again.

The price is that it is process injection. It means a hooking library
and its trampolines, launching the target suspended and injecting
before its entry point (or a system-wide hook, which is worse), and
being indistinguishable to any endpoint protection product from the
thing it is there to stop. For a tool whose purpose is reaching old
equipment safely, shipping something that must be allow-listed in the
antivirus is a poor trade.

### 3. `AppInit_DLLs` and `AppCertDlls`

Registry keys that load a DLL of your choosing into processes
machine-wide. Administrator, a code-signing certificate since Windows 8,
and a blast radius of "every process on the machine" to change the
behaviour of one `curl` invocation. Listed for completeness and
because someone always suggests it.

### 4. Delay-load hooks

If the target was compiled with `/DELAYLOAD:libssl-3-x64.dll` it has a
`__pfnDliNotifyHook2` the program itself can set. That is a decision
made by whoever built the program, not by us, and the programs in
question were not built that way.

## The supported answer: use the proxy

`allcrypt-proxy` is ordinary portable Rust — no interposition, no
injection, nothing to place in anybody's install directory. It is a
program you run and a client you point at it:

```console
> cargo build --release
> target\release\allcrypt-proxy.exe --legacy --port 8080
```

Then set the HTTPS proxy to `127.0.0.1:8080` and import the `ca.pem` it
writes. It reaches the same old equipment the shim reaches, from any
client that can be pointed at a proxy — which on Windows includes the
browsers the shim could never have helped with anyway, since Chromium
links BoringSSL statically. [proxy.md](proxy.md) covers what it shows
the client and what it deliberately refuses to launder.

For **Python** programs specifically there is a better answer still:
`allcrypt_ssl.py` replaces `ssl.SSLContext` in the process that wants
it, with no proxy and no interposition at all. It is pure Python over
the extension module and works on Windows exactly as it does
elsewhere. See [python.md](python.md).

## If this changes

The shim is `#![cfg(unix)]` in one place, at the top of
`shim/src/lib.rs`, rather than scattered over the modules. There is no
partial version of it — `LD_PRELOAD`, file descriptors and `dlopen` are
the mechanism, and a Windows build that got half of them would be an
`ssl.dll` that loads and does nothing, which is worse than no file.

A Windows port would be option 1 above, and it would be its own crate
producing its own DLL under its own name, not a `cfg` branch inside
this one. The parts that would carry over are the ones that already
speak in Rust types: `shim/src/state.rs`, `shim/src/config.rs`, and the
whole of `allcrypt` underneath. What would be rewritten is
`shim/src/lib.rs`'s entry points — the same sixty-three functions,
exported and bound a different way — and `shim/src/objects.rs`, whose
`dlopen`/`dlsym` become `GetModuleHandleW`/`GetProcAddress` and
otherwise stay as they are.
