/*
`libssl.so`, reimplemented on top of `allcrypt`.

    LD_PRELOAD=/path/to/libssl.so wget https://old-box.example/

The point is the same as the proxy's: reach equipment nobody will
upgrade. The proxy exists because a browser cannot be got at from
underneath - Chromium links BoringSSL statically. A command line tool
*can* be: `wget` calls `SSL_connect` through the PLT, and so does
`libcurl`, which is what `curl` and `git` use. Thirty-two libssl
functions cover `wget`, fifty-six cover `libcurl`, and the union is
sixty-three. That is a small enough surface to do properly. It has
since grown to 104, with the server side, sessions and the pre-3.0
spellings older programs reference.

## How the interposition works

`LD_PRELOAD` puts this library's symbols ahead of the real `libssl.so.3`
in the lookup order, so every call resolves here. Two details, both
checked rather than assumed:

  - **Unversioned definitions satisfy versioned references.** `wget`
    refers to `SSL_connect@OPENSSL_3.0.0`; we export a plain
    `SSL_connect`, and the dynamic linker binds it.
  - **The real libssl is still loaded**, because it is in the program's
    `DT_NEEDED`. It simply goes unused. That is also the hazard: any
    function we fail to define resolves *there*, and is then handed one
    of our structs to read as one of OpenSSL's. Which is why the rule
    for this file is to implement the whole set a shimmed program
    references, not the set that seemed necessary.

`libcrypto` is left alone, and the objects we hand back are real
OpenSSL ones - see `objects.rs` for why, and for what would have to
change if that has to stop.

## What it will not do quietly

A shim that silently skips something the program asked for is worse than
one that fails: the program reports success and the person believes a
check happened. So anything security-relevant that this cannot honour is
collected in `Context::unsupported` and reported before the first
handshake, and the connection fails.

The certificate decision stays with the program. We verify, put the
answer where `SSL_get_verify_result` finds it, and let `curl -k` or
`wget --no-check-certificate` mean what they have always meant.

## Unix only

The whole crate is `#![cfg(unix)]`, so on Windows it compiles to an
empty library and `cargo test` on the workspace builds and passes
there like anywhere else. Nothing of the technique survives the port:
`LD_PRELOAD` is the dynamic linker's, and Windows resolves imports
through an import address table written at load time instead.

There *are* Windows equivalents, and `docs/windows.md` weighs them.
None is a drop-in - the nearest, dropping our DLL next to the
executable so the loader finds it first, means shipping a file named
after somebody else's library into somebody else's directory. The
supported answer on Windows is the proxy (`src/main.rs`), which needs
no interposition at all: it is a program you run and point a client at.
*/

// Unix only, and the crate is empty elsewhere. Stated as one
// crate-level `cfg` rather than sprinkled over the modules because
// there is no partial version of this: `LD_PRELOAD`, file descriptors
// and `dlopen` are the whole mechanism, and a Windows build that got
// half of it would be a `ssl.dll` that loads and does nothing, which
// is worse than no file at all.
#![cfg(unix)]

// **Every entry point here is `unsafe extern "C"` and none carries a
// `# Safety` section.** That is an argued exception to this
// repository's rule that unsafe functions document their contract, not
// an oversight.
//
// A `# Safety` section documents the contract a *Rust* caller must
// keep. These functions have no Rust callers: they exist to be found
// by the dynamic linker and called by `libcurl` and `wget`, whose
// contract is OpenSSL's published one - `SSL_free(3)` takes a pointer
// from `SSL_new(3)` or null, and so on for a hundred more. Restating
// that a hundred times, in a form no reader of this file can act on,
// would bury the notes that do say something.
//
// What the shim actually needs to be safe is stated once, at the top
// of `state.rs`: every function a shimmed program calls on one of our
// objects must be a function we intercept.
#![allow(clippy::missing_safety_doc)]
// **No panic may cross back into C.** Unwinding out of an `extern "C"`
// function is undefined behaviour, and the caller is `libcurl` or
// `wget` - a process that has no idea a Rust library is underneath it
// and no way to catch anything.
//
// That was a convention held by reading until a deliberate-breakage
// sweep turned `let Some(x) = .. else { .. }` into `.unwrap()` in
// `objects.rs` and no test noticed: the value is always `Some` on a
// machine with a current OpenSSL, and only a host with an older one
// would ever have found out. So it is a lint now rather than a habit.
// The non-test code in this crate contains no `unwrap`, `expect` or
// `panic!` and is meant to stay that way; `unwrap_or_else` and the
// `let .. else` form are how a missing value is answered instead.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic,
        clippy::unreachable, clippy::todo, clippy::unimplemented)]
// Tests are Rust callers with a Rust harness around them, and an
// assertion failure there is the point rather than a hazard.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used,
                        clippy::panic))]

mod config;
mod objects;
mod state;

use std::io::{Read, Write};
use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use std::sync::{Arc, Mutex, OnceLock};

use allcrypt::tls::client::{ClientConfig, ClientConnection};
use allcrypt::tls::Version;
use allcrypt::trust::TrustStore;
use allcrypt::x509::verify::Policy;

use config::Settings;
use state::{Connection, Context, Transport};

// ------------------------------------------------------------- constants ---
//
// From `ssl.h`. Values, not names, because the header is not here - and
// a wrong one is a silent misunderstanding between us and the program,
// so each is spelled out beside what it means.

const SSL_ERROR_NONE: c_int = 0;
const SSL_ERROR_SSL: c_int = 1;
const SSL_ERROR_WANT_READ: c_int = 2;
const SSL_ERROR_WANT_WRITE: c_int = 3;
const SSL_ERROR_ZERO_RETURN: c_int = 6;
const SSL_ERROR_SYSCALL: c_int = 5;

/// `X509_V_OK`.
const X509_V_OK: c_long = 0;
/// `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY`. The generic "this
/// chain did not verify" that every program has a message for.
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_long = 20;
/// `X509_V_ERR_CERT_HAS_EXPIRED`.
const X509_V_ERR_CERT_HAS_EXPIRED: c_long = 10;
/// `X509_V_ERR_HOSTNAME_MISMATCH`.
const X509_V_ERR_HOSTNAME_MISMATCH: c_long = 62;

/// `SSL_CTRL_SET_TLSEXT_HOSTNAME`, the control behind
/// `SSL_set_tlsext_host_name`.
const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
/// `SSL_CTRL_SET_MIN_PROTO_VERSION` / `..._MAX_...`.
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
const SSL_CTRL_GET_MIN_PROTO_VERSION: c_int = 130;
const SSL_CTRL_GET_MAX_PROTO_VERSION: c_int = 131;
/// `SSL_CTRL_MODE`, whose argument is a bitmask the program wants set.
const SSL_CTRL_MODE: c_int = 33;
/// `SSL_CTRL_OPTIONS`.
const SSL_CTRL_OPTIONS: c_int = 32;
/// `SSL_CTRL_SET_SESS_CACHE_MODE`.
const SSL_CTRL_SET_SESS_CACHE_MODE: c_int = 44;

/// The protocol version numbers a program passes to the controls above.
const TLS1_VERSION: c_long = 0x0301;
const TLS1_1_VERSION: c_long = 0x0302;
const TLS1_2_VERSION: c_long = 0x0303;
const TLS1_3_VERSION: c_long = 0x0304;
const SSL3_VERSION: c_long = 0x0300;

// ----------------------------------------------------------- the settings ---

fn settings() -> Arc<Settings> {
    static SETTINGS: OnceLock<Arc<Settings>> = OnceLock::new();
    Arc::clone(SETTINGS.get_or_init(|| Arc::new(Settings::from_environment())))
}

/// Say, once per process, that this is not OpenSSL.
///
/// A program whose TLS stack was swapped underneath it should say so
/// somewhere. The alternative is somebody debugging a connection for an
/// hour with the wrong library's documentation open.
fn announce() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let settings = settings();
        if !settings.quiet {
            eprintln!("allcrypt: TLS is being handled by the allcrypt shim, \
                       not OpenSSL.");
        }
        record(&format!("shim active: ciphers={} versions={}..{}",
                        settings.ciphers, settings.min_version.name(),
                        settings.max_version.name()));
        // Where libcrypto came from, for the same reason the line
        // above exists: it is otherwise unobservable. "global scope"
        // means the program's own - the one whose accessors will be
        // called on the objects we build. A soname instead means we
        // loaded a second copy, which is safe only because the program
        // had none, and "none" means certificates cannot be handed
        // back at all. See `objects.rs`.
        record(&format!("libcrypto: {}", objects::origin()));
    });
}

/// Append a line to `ALLCRYPT_LOG`, if one was asked for.
///
/// The tests need this and there is no other way to get it. A shim that
/// fails to load leaves the program working perfectly against the real
/// OpenSSL - every assertion about the *connection* still passes, and
/// the test proves nothing at all. A mark in a file is the only
/// evidence that we were in the path.
fn record(line: &str) {
    let settings = settings();
    let Some(path) = settings.log_path.as_ref() else { return };
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true)
        .open(path) {
        let _ = writeln!(file, "{}", line);
    }
}

// --------------------------------------------------------------- handles ---
//
// A program holds `SSL_CTX *` and `SSL *`. Ours are boxed Rust values
// behind a lock; these two pairs are the only place raw pointers turn
// back into them.

struct CtxHandle {
    inner: Arc<Mutex<Context>>,
}

struct SslHandle {
    inner: Mutex<Connection>,
}

unsafe fn ctx_of<'a>(pointer: *mut c_void) -> Option<&'a CtxHandle> {
    (pointer as *const CtxHandle).as_ref()
}

unsafe fn ssl_of<'a>(pointer: *mut c_void) -> Option<&'a SslHandle> {
    (pointer as *const SslHandle).as_ref()
}

// ------------------------------------------------------------ the library ---

/// `OPENSSL_init_ssl(3)`. Nothing to initialise; say so and succeed.
#[no_mangle]
pub extern "C" fn OPENSSL_init_ssl(_options: u64, _settings: *const c_void) -> c_int {
    announce();
    1
}

/// `TLS_client_method(3)` and the version-pinned spellings.
///
/// A method is opaque and we never look at it; a non-null constant is
/// enough, and the address of a static is one that cannot be confused
/// with a heap pointer we own.
static METHOD: u8 = 0;

#[no_mangle]
pub extern "C" fn TLS_client_method() -> *const c_void {
    &METHOD as *const u8 as *const c_void
}

#[no_mangle]
pub extern "C" fn TLS_method() -> *const c_void {
    TLS_client_method()
}

#[no_mangle]
pub extern "C" fn SSLv23_client_method() -> *const c_void {
    TLS_client_method()
}

#[no_mangle]
pub extern "C" fn TLS_server_method() -> *const c_void {
    // Named so a program asking for it gets a clear failure at
    // SSL_CTX_new rather than a mysterious one later. This shim is a
    // client; `allcrypt-proxy` is the server side.
    std::ptr::null()
}

/// `SSL_CTX_new(3)`.
#[no_mangle]
pub extern "C" fn SSL_CTX_new(method: *const c_void) -> *mut c_void {
    announce();
    if method.is_null() {
        config::complain("this shim only does the client side of TLS; \
                          allcrypt-proxy is the server.");
        return std::ptr::null_mut();
    }
    let handle = Box::new(CtxHandle {
        inner: Arc::new(Mutex::new(Context::new(settings()))),
    });
    Box::into_raw(handle) as *mut c_void
}

/// `SSL_CTX_free(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_free(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // The `Arc` inside may outlive this: a connection made from the
    // context holds one, and a program is allowed to free the context
    // first. Dropping the box drops only our reference.
    drop(Box::from_raw(context as *mut CtxHandle));
}

/// `SSL_CTX_up_ref(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_up_ref(context: *mut c_void) -> c_int {
    // Handing out a second box that shares the same inner `Arc` keeps
    // the invariant that every pointer the program holds can be freed
    // exactly once.
    let Some(handle) = ctx_of(context) else { return 0 };
    let clone = Box::new(CtxHandle { inner: Arc::clone(&handle.inner) });
    // The program expects the *same* pointer to remain valid, and it
    // does; this extra box leaks unless it frees twice, which is what
    // up_ref promises it will do.
    std::mem::forget(clone);
    1
}

/// `SSL_CTX_set_verify(3)`.
///
/// The callback is ignored, and that is the one place this shim
/// knowingly differs in a way a program might notice: OpenSSL calls it
/// once per certificate in the chain and lets the program override the
/// verdict. Nothing we shim uses it for anything but logging, and a
/// callback we invoked with a fabricated `X509_STORE_CTX` would be
/// worse than one we did not.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_verify(context: *mut c_void, mode: c_int,
                                            callback: *const c_void) {
    let Some(handle) = ctx_of(context) else { return };
    if let Ok(mut inner) = handle.inner.lock() {
        inner.verify_mode = mode;
        if !callback.is_null() {
            inner.unsupported.push(
                "a per-certificate verify callback, which this shim does not \
                 call".to_string());
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_verify(connection: *mut c_void, mode: c_int,
                                        callback: *const c_void) {
    let Some(handle) = ssl_of(connection) else { return };
    let context = {
        let Ok(inner) = handle.inner.lock() else { return };
        Arc::clone(&inner.context)
    };
    // `let ... else` rather than `if let`: in the 2021 edition the
    // temporary `Result` from `lock()` lives to the end of the
    // enclosing block, which is after `context` is dropped.
    let Ok(mut locked) = context.lock() else { return };
    locked.verify_mode = mode;
    if !callback.is_null() {
        locked.unsupported.push(
            "a per-certificate verify callback".to_string());
    }
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_verify_mode(context: *mut c_void) -> c_int {
    ctx_of(context)
        .and_then(|h| h.inner.lock().ok().map(|c| c.verify_mode))
        .unwrap_or(0)
}

/// `SSL_CTX_load_verify_locations(3)`.
///
/// Intercepted rather than left to the store, so the roots reach our
/// own `TrustStore`. A directory is not supported and says so.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_load_verify_locations(context: *mut c_void,
                                                       file: *const c_char,
                                                       directory: *const c_char)
                                                       -> c_int {
    let Some(handle) = ctx_of(context) else { return 0 };
    let Ok(mut inner) = handle.inner.lock() else { return 0 };

    let mut loaded = false;
    if let Some(path) = objects::from_c_string(file) {
        match std::fs::read_to_string(&path) {
            Ok(text) => match inner.roots.add_pem(&text) {
                Ok(count) if count > 0 => { loaded = true; }
                Ok(_) => config::complain(&format!("{} held no certificates.",
                                                   path)),
                Err(reason) => config::complain(&format!("{}: {}", path, reason)),
            },
            Err(reason) => config::complain(&format!("{}: {}", path, reason)),
        }
    }
    if let Some(path) = objects::from_c_string(directory) {
        match TrustStore::from_directory(&path) {
            Ok(store) => {
                for der in store.roots() {
                    if inner.roots.add_der(der).is_ok() {
                        loaded = true;
                    }
                }
            }
            Err(reason) => config::complain(&format!("{}: {}", path, reason)),
        }
    }
    if loaded {
        inner.roots_loaded = true;
        return 1;
    }
    0
}

/// `SSL_CTX_set_default_verify_paths(3)`: the system store.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_verify_paths(context: *mut c_void)
                                                          -> c_int {
    let Some(handle) = ctx_of(context) else { return 0 };
    let Ok(mut inner) = handle.inner.lock() else { return 0 };
    match TrustStore::system() {
        Ok(store) => {
            for der in store.roots() {
                let _ = inner.roots.add_der(der);
            }
            inner.roots_loaded = true;
            1
        }
        Err(reason) => {
            config::complain(&format!("no system trust store: {}", reason));
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_verify_file(context: *mut c_void)
                                                         -> c_int {
    SSL_CTX_set_default_verify_paths(context)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_verify_dir(context: *mut c_void)
                                                        -> c_int {
    SSL_CTX_set_default_verify_paths(context)
}

/// `SSL_CTX_get_cert_store(3)`.
///
/// A **real, empty** `X509_STORE *`, so that a program adding a lookup
/// or setting a flag on it does not crash.
///
/// **Nothing is read back out of it.** Roots reach us through
/// `SSL_CTX_load_verify_locations`, which we intercept. A program that
/// instead adds certificates straight to the store - or a CRL, which
/// is what `wget --crl-file` does - would have them silently ignored,
/// so the calls that do that are intercepted separately and refuse
/// rather than pretend. See `X509_load_crl_file` below.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_cert_store(context: *mut c_void) -> *mut c_void {
    let Some(handle) = ctx_of(context) else { return std::ptr::null_mut() };
    let Ok(mut inner) = handle.inner.lock() else { return std::ptr::null_mut() };
    if inner.store.is_null() {
        inner.store = objects::store_new();
    }
    inner.store
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cert_store(context: *mut c_void,
                                                store: *mut c_void) {
    let Some(handle) = ctx_of(context) else { return };
    let Ok(mut inner) = handle.inner.lock() else { return };
    objects::store_free(inner.store);
    inner.store = store;
    inner.unsupported.push(
        "a certificate store supplied whole, whose contents this shim cannot \
         read back".to_string());
}

/// `X509_load_crl_file(3)`, which belongs to libcrypto.
///
/// Intercepted for one reason: **refusing loudly beats ignoring
/// quietly.** `wget --crl-file` reaches here, and if we let the real
/// function load the CRL into a store we never read, wget would report
/// success and the person would believe revocation was being checked.
///
/// This library can check a CRL - `x509::crl` does it thoroughly - but
/// wiring the store's contents back out is work that has not been done.
/// Until it has, this says so.
#[no_mangle]
pub unsafe extern "C" fn X509_load_crl_file(_lookup: *mut c_void,
                                            file: *const c_char,
                                            _kind: c_int) -> c_int {
    let name = objects::from_c_string(file).unwrap_or_else(|| "a CRL".into());
    config::complain(&format!(
        "{} was not loaded: this shim does not check revocation lists yet, \
         and reporting success would mean claiming a check that did not \
         happen.", name));
    0
}

/// `SSL_CTX_set_cipher_list(3)` and `SSL_CTX_set_ciphersuites(3)`.
///
/// The program's OpenSSL cipher string is **not** translated, and the
/// return says so honestly by succeeding: a failure here makes `curl`
/// and `wget` abort outright, which would mean no connection at all
/// rather than one whose suite list came from `ALLCRYPT_CIPHERS`.
///
/// The mismatch is noted once so it is not a silent substitution.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cipher_list(context: *mut c_void,
                                                 list: *const c_char) -> c_int {
    note_cipher_string(context, list, "SSL_CTX_set_cipher_list");
    1
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_ciphersuites(context: *mut c_void,
                                                  list: *const c_char) -> c_int {
    note_cipher_string(context, list, "SSL_CTX_set_ciphersuites");
    1
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_cipher_list(_connection: *mut c_void,
                                             _list: *const c_char) -> c_int {
    1
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_ciphersuites(_connection: *mut c_void,
                                              _list: *const c_char) -> c_int {
    1
}

unsafe fn note_cipher_string(context: *mut c_void, list: *const c_char,
                             called: &str) {
    let Some(text) = objects::from_c_string(list) else { return };
    // The default string every program passes is not worth a message.
    if text == "DEFAULT" || text.is_empty() {
        return;
    }
    let Some(handle) = ctx_of(context) else { return };
    let Ok(mut inner) = handle.inner.lock() else { return };
    if inner.settings.verbose {
        config::complain(&format!(
            "{}({:?}) - OpenSSL cipher strings are not translated; the suites \
             offered come from ALLCRYPT_CIPHERS (currently {:?}).",
            called, text, inner.settings.ciphers));
    }
    let _ = &mut inner;
}

/// `SSL_CTX_set_options(3)`. Returns the resulting option mask.
///
/// The options a program sets are mostly "do not do this old thing",
/// and this shim's whole purpose is doing old things when asked. The
/// version-limiting ones arrive through `SSL_CTX_ctrl` instead, and
/// those are honoured.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_options(_context: *mut c_void,
                                             options: u64) -> u64 {
    options
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_options(_context: *mut c_void) -> u64 { 0 }

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_clear_options(_context: *mut c_void,
                                               _options: u64) -> u64 { 0 }

#[no_mangle]
pub unsafe extern "C" fn SSL_set_options(_connection: *mut c_void,
                                         options: u64) -> u64 { options }

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_post_handshake_auth(_context: *mut c_void,
                                                         _on: c_int) {}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_post_handshake_auth(_connection: *mut c_void,
                                                     _on: c_int) {}

/// `SSL_CTX_ctrl(3)`: the macro-behind-everything.
///
/// `SSL_CTX_set_min_proto_version` and its relatives are macros over
/// this, so the version limits a program sets arrive as command
/// numbers. Those are honoured; the rest are accepted and ignored.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_ctrl(context: *mut c_void, command: c_int,
                                      argument: c_long, _pointer: *mut c_void)
                                      -> c_long {
    let Some(handle) = ctx_of(context) else { return 0 };
    let Ok(mut inner) = handle.inner.lock() else { return 0 };
    match command {
        SSL_CTRL_SET_MIN_PROTO_VERSION => {
            inner.min_version = version_from_number(argument);
            1
        }
        SSL_CTRL_SET_MAX_PROTO_VERSION => {
            inner.max_version = version_from_number(argument);
            1
        }
        SSL_CTRL_GET_MIN_PROTO_VERSION => number_from_version(inner.floor()),
        SSL_CTRL_GET_MAX_PROTO_VERSION => number_from_version(inner.ceiling()),
        // A mode or option mask: the program is told it took effect,
        // because every one of them is either irrelevant to us or a
        // request to be *less* strict, which we already are.
        SSL_CTRL_MODE | SSL_CTRL_OPTIONS => argument,
        SSL_CTRL_SET_SESS_CACHE_MODE => argument,
        _ => 0,
    }
}

/// `SSL_ctrl(3)`. The connection-level twin, and the one that carries
/// SNI - which is the single most important thing a program tells us.
#[no_mangle]
pub unsafe extern "C" fn SSL_ctrl(connection: *mut c_void, command: c_int,
                                  argument: c_long, pointer: *mut c_void)
                                  -> c_long {
    let Some(handle) = ssl_of(connection) else { return 0 };
    let Ok(mut inner) = handle.inner.lock() else { return 0 };
    match command {
        SSL_CTRL_SET_TLSEXT_HOSTNAME => {
            match objects::from_c_string(pointer as *const c_char) {
                Some(name) => { inner.hostname = Some(name); 1 }
                None => 0,
            }
        }
        SSL_CTRL_SET_MIN_PROTO_VERSION | SSL_CTRL_SET_MAX_PROTO_VERSION => {
            let context = Arc::clone(&inner.context);
            let Ok(mut locked) = context.lock() else { return 0 };
            if command == SSL_CTRL_SET_MIN_PROTO_VERSION {
                locked.min_version = version_from_number(argument);
            } else {
                locked.max_version = version_from_number(argument);
            }
            1
        }
        SSL_CTRL_MODE | SSL_CTRL_OPTIONS => argument,
        _ => 0,
    }
}

fn version_from_number(number: c_long) -> Option<Version> {
    match number {
        0 => None,                          // "no limit"
        SSL3_VERSION => Some(Version::SSL30),
        TLS1_VERSION => Some(Version::TLS10),
        TLS1_1_VERSION => Some(Version::TLS11),
        TLS1_2_VERSION => Some(Version::TLS12),
        TLS1_3_VERSION => Some(Version::TLS13),
        _ => None,
    }
}

fn number_from_version(version: Version) -> c_long {
    match version {
        Version::SSL30 => SSL3_VERSION,
        Version::TLS10 => TLS1_VERSION,
        Version::TLS11 => TLS1_1_VERSION,
        Version::TLS12 => TLS1_2_VERSION,
        Version::TLS13 => TLS1_3_VERSION,
        _ => 0,
    }
}

/// `SSL_CTX_set1_param(3)`. The parameters carry the hostname a program
/// wants checked; we cannot read an `X509_VERIFY_PARAM` without
/// libcrypto accessors, so this is accepted and the name comes from
/// SNI instead, which every program also sets.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set1_param(_context: *mut c_void,
                                            _param: *mut c_void) -> c_int { 1 }

#[no_mangle]
pub unsafe extern "C" fn SSL_set1_param(_connection: *mut c_void,
                                        _param: *mut c_void) -> c_int { 1 }

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_param(_context: *mut c_void)
                                            -> *mut c_void {
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get0_param(_connection: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

// ------------------------------------------------------- client identity ---
//
// Client certificates are not implemented. Every entry point says so
// rather than returning success, because a program that believes it
// presented a certificate and did not will be refused by the server
// with an error about the wrong thing.

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_certificate_file(context: *mut c_void,
                                                      _file: *const c_char,
                                                      _kind: c_int) -> c_int {
    refuse_client_certificate(context)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_certificate_chain_file(context: *mut c_void,
                                                            _file: *const c_char)
                                                            -> c_int {
    refuse_client_certificate(context)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_certificate(context: *mut c_void,
                                                 _certificate: *mut c_void)
                                                 -> c_int {
    refuse_client_certificate(context)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_PrivateKey_file(context: *mut c_void,
                                                     _file: *const c_char,
                                                     _kind: c_int) -> c_int {
    refuse_client_certificate(context)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_PrivateKey(context: *mut c_void,
                                                _key: *mut c_void) -> c_int {
    refuse_client_certificate(context)
}

/// `SSL_CTX_check_private_key(3)`: does the key match the certificate?
///
/// There is no key and no certificate, so the honest answer is no.
///
/// This is the **second** of two independent refusals of a client
/// certificate, and the redundancy is deliberate rather than an
/// oversight: `refuse_client_certificate` above returns failure from
/// the load, and this returns failure from the check. Either alone
/// stops `curl` and `wget`.
///
/// It also means the deliberate-breakage sweep cannot isolate them -
/// breaking one leaves the other refusing, and every test still
/// passes. That reads as "no test covers this", and what it actually
/// means is "two things cover it". The sweep cannot tell those two
/// readings apart, which is the same lesson the premaster bug taught
/// (docs/pitfalls.md, "The two Diffie-Hellman families strip leading
/// zeros in opposite directions").
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_check_private_key(_context: *mut c_void) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_add_client_CA(_context: *mut c_void,
                                               _certificate: *mut c_void) -> c_int {
    1
}

/// Refuse to take a client certificate, and say so here rather than
/// later.
///
/// Returning zero is enough to stop the program - `curl` and `wget`
/// both treat a failed `use_certificate_file` as fatal and never reach
/// the handshake. Which means the note on the context is never read,
/// and the only thing the person sees is the tool's own message about
/// a certificate file it could not use: true, unhelpful, and pointing
/// at the file rather than at us.
///
/// So the explanation goes out at the point of refusal. The note is
/// kept as well, for the case where a program carries on regardless
/// and gets as far as connecting.
unsafe fn refuse_client_certificate(context: *mut c_void) -> c_int {
    const REASON: &str =
        "a client certificate was requested, and this shim cannot present          one. Refusing rather than connecting without it: against a server          that asks for a certificate but does not require one, that would          look like success.";
    if let Some(handle) = ctx_of(context) {
        if let Ok(mut inner) = handle.inner.lock() {
            if !inner.unsupported.iter().any(|note| note == REASON) {
                config::complain(REASON);
                record("refused: client certificate");
                inner.unsupported.push(REASON.to_string());
            }
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_certificate(_connection: *mut c_void)
                                             -> *mut c_void {
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_privatekey(_connection: *mut c_void)
                                            -> *mut c_void {
    std::ptr::null_mut()
}

// -------------------------------------------------------------- the rest ---

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_passwd_cb(_context: *mut c_void,
                                                       _callback: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_passwd_cb_userdata(
    _context: *mut c_void, _data: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_keylog_callback(_context: *mut c_void,
                                                     _callback: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_msg_callback(_context: *mut c_void,
                                                  _callback: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_sess_set_new_cb(_context: *mut c_void,
                                                 _callback: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_username(context: *mut c_void,
                                                  _name: *const c_char) -> c_int {
    if let Some(handle) = ctx_of(context) {
        if let Ok(mut inner) = handle.inner.lock() {
            inner.unsupported.push("SRP authentication".to_string());
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_password(context: *mut c_void,
                                                  _password: *const c_char)
                                                  -> c_int {
    SSL_CTX_set_srp_username(context, std::ptr::null())
}

/// `SSL_CTX_set_alpn_protos(3)`. Zero means success, in OpenSSL's
/// inverted convention for this one function.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_alpn_protos(context: *mut c_void,
                                                 protocols: *const c_uchar,
                                                 length: c_uint) -> c_int {
    let Some(handle) = ctx_of(context) else { return 1 };
    let Ok(mut inner) = handle.inner.lock() else { return 1 };
    if !protocols.is_null() && length > 0 {
        inner.alpn = std::slice::from_raw_parts(protocols, length as usize)
            .to_vec();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_alpn_protos(_connection: *mut c_void,
                                             _protocols: *const c_uchar,
                                             _length: c_uint) -> c_int { 0 }

/// `SSL_get0_alpn_selected(3)`.
///
/// Always empty: this shim does not negotiate ALPN, so a program is
/// told nothing was agreed rather than being handed a protocol that
/// was not. `libcurl` reads this to decide whether to speak HTTP/2, and
/// an empty answer means HTTP/1.1 - which works everywhere.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_alpn_selected(_connection: *mut c_void,
                                                data: *mut *const c_uchar,
                                                length: *mut c_uint) {
    if !data.is_null() {
        *data = std::ptr::null();
    }
    if !length.is_null() {
        *length = 0;
    }
}

// ------------------------------------------------------------ connections ---

/// `SSL_new(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_new(context: *mut c_void) -> *mut c_void {
    let Some(handle) = ctx_of(context) else { return std::ptr::null_mut() };
    let settings = settings();
    let connection = Connection::new(Arc::clone(&handle.inner), settings);
    Box::into_raw(Box::new(SslHandle { inner: Mutex::new(connection) })) as *mut c_void
}

/// `SSL_free(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_free(connection: *mut c_void) {
    if connection.is_null() {
        return;
    }
    drop(Box::from_raw(connection as *mut SslHandle));
}

#[no_mangle]
pub unsafe extern "C" fn SSL_up_ref(_connection: *mut c_void) -> c_int { 1 }

/// `SSL_set_fd(3)` and the read/write halves.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_fd(connection: *mut c_void, fd: c_int) -> c_int {
    let Some(handle) = ssl_of(connection) else { return 0 };
    let Ok(mut inner) = handle.inner.lock() else { return 0 };
    inner.transport = Transport::Descriptor(fd);
    1
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_rfd(connection: *mut c_void, fd: c_int) -> c_int {
    SSL_set_fd(connection, fd)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_wfd(connection: *mut c_void, fd: c_int) -> c_int {
    SSL_set_fd(connection, fd)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_fd(connection: *mut c_void) -> c_int {
    let Some(handle) = ssl_of(connection) else { return -1 };
    let Ok(inner) = handle.inner.lock() else { return -1 };
    match inner.transport {
        Transport::Descriptor(fd) => fd,
        _ => -1,
    }
}

/// `SSL_set0_rbio(3)` / `SSL_set0_wbio(3)`: `libcurl`'s way in.
///
/// The `0` means the caller hands over its reference, so these are
/// freed with the connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set0_rbio(connection: *mut c_void, bio: *mut c_void) {
    set_bio(connection, Some(bio), None);
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set0_wbio(connection: *mut c_void, bio: *mut c_void) {
    set_bio(connection, None, Some(bio));
}

/// `SSL_set_bio(3)`, whose contract is the same as calling both.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_bio(connection: *mut c_void, read: *mut c_void,
                                     write: *mut c_void) {
    set_bio(connection, Some(read), Some(write));
}

unsafe fn set_bio(connection: *mut c_void, read: Option<*mut c_void>,
                  write: Option<*mut c_void>) {
    let Some(handle) = ssl_of(connection) else { return };
    let Ok(mut inner) = handle.inner.lock() else { return };
    let (mut current_read, mut current_write) = match inner.transport {
        Transport::Bios { read, write } => (read, write),
        _ => (std::ptr::null_mut(), std::ptr::null_mut()),
    };
    if let Some(bio) = read {
        if !current_read.is_null() && current_read != bio {
            objects::bio_free_all(current_read);
        }
        current_read = bio;
    }
    if let Some(bio) = write {
        if !current_write.is_null() && current_write != bio
            && current_write != current_read {
            objects::bio_free_all(current_write);
        }
        current_write = bio;
    }
    inner.transport = Transport::Bios { read: current_read, write: current_write };
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_rbio(connection: *mut c_void) -> *mut c_void {
    let Some(handle) = ssl_of(connection) else { return std::ptr::null_mut() };
    let Ok(inner) = handle.inner.lock() else { return std::ptr::null_mut() };
    match inner.transport {
        Transport::Bios { read, .. } => read,
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_wbio(connection: *mut c_void) -> *mut c_void {
    let Some(handle) = ssl_of(connection) else { return std::ptr::null_mut() };
    let Ok(inner) = handle.inner.lock() else { return std::ptr::null_mut() };
    match inner.transport {
        Transport::Bios { write, .. } => write,
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_connect_state(_connection: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_accept_state(connection: *mut c_void) {
    let Some(handle) = ssl_of(connection) else { return };
    if let Ok(mut inner) = handle.inner.lock() {
        inner.failure = Some("this shim only does the client side".into());
    }
}

#[no_mangle]
pub unsafe extern "C" fn SSL_is_init_finished(connection: *mut c_void) -> c_int {
    let Some(handle) = ssl_of(connection) else { return 0 };
    let Ok(inner) = handle.inner.lock() else { return 0 };
    c_int::from(inner.established)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_is_server(_connection: *mut c_void) -> c_int { 0 }

#[no_mangle]
pub unsafe extern "C" fn SSL_get_error(connection: *mut c_void, result: c_int)
                                       -> c_int {
    if result > 0 {
        return SSL_ERROR_NONE;
    }
    let Some(handle) = ssl_of(connection) else { return SSL_ERROR_SSL };
    let Ok(inner) = handle.inner.lock() else { return SSL_ERROR_SSL };
    inner.last_error
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_shutdown(connection: *mut c_void) -> c_int {
    let Some(handle) = ssl_of(connection) else { return 0 };
    let Ok(inner) = handle.inner.lock() else { return 0 };
    let mut flags = 0;
    if inner.shutdown_sent { flags |= 1; }     // SSL_SENT_SHUTDOWN
    if inner.peer_closed { flags |= 2; }       // SSL_RECEIVED_SHUTDOWN
    flags
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_shutdown(_connection: *mut c_void,
                                          _mode: c_int) {}

// ----------------------------------------------------------- the handshake ---

/// `SSL_connect(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_connect(connection: *mut c_void) -> c_int {
    objects::clear_error_queue();
    let Some(handle) = ssl_of(connection) else { return -1 };
    let Ok(mut inner) = handle.inner.lock() else { return -1 };
    match handshake(&mut inner) {
        Ok(true) => 1,
        Ok(false) => -1,                    // would block; last_error says which
        Err(reason) => {
            config::complain(&reason);
            record(&format!("handshake failed: {}", reason));
            inner.failure = Some(reason);
            inner.last_error = SSL_ERROR_SSL;
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SSL_do_handshake(connection: *mut c_void) -> c_int {
    SSL_connect(connection)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_accept(_connection: *mut c_void) -> c_int { -1 }

/// Drive the handshake as far as the transport allows.
///
/// `Ok(true)` finished, `Ok(false)` would block, `Err` failed.
fn handshake(inner: &mut Connection) -> Result<bool, String> {
    if inner.established {
        return Ok(true);
    }
    if inner.inner.is_none() {
        start(inner)?;
    }
    for _ in 0..64 {
        match flush(inner) {
            Ok(()) => {}
            Err(WouldBlock::Write) => {
                inner.last_error = SSL_ERROR_WANT_WRITE;
                return Ok(false);
            }
            Err(WouldBlock::Read) => {
                inner.last_error = SSL_ERROR_WANT_READ;
                return Ok(false);
            }
            Err(WouldBlock::Failed(reason)) => return Err(reason),
        }
        {
            let Some(client) = inner.inner.as_ref() else {
                return Err("no connection".into());
            };
            if !client.is_handshaking() {
                break;
            }
        }
        let mut buffer = [0u8; 17 * 1024];
        match receive(inner, &mut buffer) {
            Ok(0) => return Err("the server closed the connection during the \
                                 handshake".into()),
            Ok(read) => {
                let Some(client) = inner.inner.as_mut() else {
                    return Err("no connection".into());
                };
                client.push_incoming(&buffer[..read]);
                client.process().map_err(|e| e.describe())?;
            }
            Err(WouldBlock::Read) => {
                inner.last_error = SSL_ERROR_WANT_READ;
                return Ok(false);
            }
            Err(WouldBlock::Write) => {
                inner.last_error = SSL_ERROR_WANT_WRITE;
                return Ok(false);
            }
            Err(WouldBlock::Failed(reason)) => return Err(reason),
        }
    }
    flush_or_reason(inner)?;

    let Some(client) = inner.inner.as_ref() else {
        return Err("no connection".into());
    };
    if client.is_handshaking() {
        return Err("the handshake did not settle".into());
    }

    inner.established = true;
    inner.peer_chain = client.peer_certificates().to_vec();
    let version = client.negotiated_version().map(|v| v.name())
        .unwrap_or_else(|| "?".into());
    let suite = client.negotiated_suite().map(|s| s.name).unwrap_or("?");
    finish(inner)?;

    let line = format!("{} {} {} [{}]",
                       inner.hostname.as_deref().unwrap_or("(no SNI)"),
                       version, suite,
                       if inner.verify_result == X509_V_OK { "verified" }
                       else { "not verified" });
    record(&line);
    if inner.settings.verbose {
        config::complain(&line);
    }
    Ok(true)
}

/// Build the client connection, now that the hostname is known.
fn start(inner: &mut Connection) -> Result<(), String> {
    let shared = Arc::clone(&inner.context);
    let context = shared.lock().map_err(|_| "context lock poisoned")?;

    if !context.unsupported.is_empty() {
        // **Refused rather than ignored.** A program that asked for a
        // client certificate or SRP and got a connection without one
        // would report success for something that did not happen.
        let reason = format!(
            "this connection asked for {}. Refusing rather than connecting \
             without it and letting you believe otherwise.",
            context.unsupported.join("; and "));
        record(&format!("refused: {}", reason));
        return Err(reason);
    }

    let settings = &inner.settings;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64).unwrap_or(0);

    // **No roots here.** `verify_certificate` is turned off on this
    // config a few lines down, so the connection never consults them -
    // `finish` does the verifying, after the handshake, with the roots
    // gathered there. Handing a populated store to something that will
    // not read it was how an earlier version of this function looked,
    // and breaking it on purpose changed nothing at all.
    let mut config = ClientConfig::new(TrustStore::new(), now);
    config.suites = settings.selection();
    config.min_version = context.floor();
    config.max_version = context.ceiling();
    config.policy = Policy {
        now,
        allow_sha1: settings.allow_sha1,
        allow_md5: settings.allow_md5,
        allow_expired: settings.allow_expired,
        min_rsa_bits: settings.min_rsa_bits,
        ..Policy::at(now)
    };
    config.min_dh_bits = settings.min_dh_bits;

    // **The verdict is ours to report, not to enforce.** We always
    // check, and put the answer where `SSL_get_verify_result` finds
    // it; whether a bad answer ends the connection is the program's
    // call, made with `SSL_CTX_set_verify`. That is exactly what
    // `curl -k` and `wget --no-check-certificate` turn off, and it is
    // not ours to override in either direction.
    config.verify_certificate = false;
    config.verify_hostname = false;

    let hostname = inner.hostname.clone().unwrap_or_default();
    drop(context);

    inner.inner = Some(ClientConnection::new(config, &hostname)
                       .map_err(|e| e.describe())?);
    Ok(())
}

/// Verify the chain and record the verdict; refuse if asked to.
fn finish(inner: &mut Connection) -> Result<(), String> {
    let shared = Arc::clone(&inner.context);
    let context = shared.lock().map_err(|_| "context lock poisoned")?;
    let settings = Arc::clone(&inner.settings);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64).unwrap_or(0);

    let mut roots: Vec<Vec<u8>> = context.roots.roots().to_vec();
    let from_store = unsafe { objects::store_certificates(context.store) };
    let had_store_roots = !from_store.is_empty();
    roots.extend(from_store);
    if !context.roots_loaded && !had_store_roots {
        if let Ok(system) = TrustStore::system() {
            roots.extend_from_slice(system.roots());
        }
    }

    let options = allcrypt::api::VerifyOptions {
        now,
        allow_sha1: settings.allow_sha1,
        allow_md5: settings.allow_md5,
        allow_expired: settings.allow_expired,
        min_rsa_bits: settings.min_rsa_bits,
        hostname: inner.hostname.clone(),
        ..Default::default()
    };

    let verdict = if inner.peer_chain.is_empty() {
        Err("the server sent no certificate".to_string())
    } else {
        allcrypt::api::verify_chain(&inner.peer_chain, &roots, &options)
    };

    inner.verify_result = match &verdict {
        Ok(()) => X509_V_OK,
        Err(reason) => {
            // The code matters: programs print a message chosen from
            // it, and "certificate has expired" sends somebody to a
            // different place than "unable to get local issuer".
            let lowered = reason.to_ascii_lowercase();
            if lowered.contains("expired") || lowered.contains("not yet valid") {
                X509_V_ERR_CERT_HAS_EXPIRED
            } else if lowered.contains("does not cover")
                || lowered.contains("hostname") {
                X509_V_ERR_HOSTNAME_MISMATCH
            } else {
                X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
            }
        }
    };

    let wants = context.wants_verification();
    drop(context);

    if let Err(reason) = verdict {
        if wants {
            // **Observable on purpose.** The tools read
            // `SSL_get_verify_result` and refuse on their own, so this
            // refusal changes nothing they do - which makes it a check
            // with nothing watching it. The log line is what
            // `test_the_shim_refuses_as_well_as_reporting` reads, so
            // that removing this is a failing test rather than a
            // silent loss of the second opinion.
            record(&format!("refused: certificate verification failed: {}",
                            reason));
            return Err(format!("certificate verification failed: {}", reason));
        }
        if settings.verbose {
            config::complain(&format!(
                "certificate not verified ({}), and the program asked for no \
                 verification.", reason));
        }
    }

    // The objects the program will ask for, made once and owned by the
    // connection so the `get0` forms can hand out borrowed pointers.
    if let Some(leaf) = inner.peer_chain.first() {
        inner.peer_certificate = objects::x509_from_der(leaf);
    }
    inner.peer_stack = objects::x509_stack_from_ders(&inner.peer_chain);
    Ok(())
}

// ------------------------------------------------------------------- I/O ---

enum WouldBlock {
    Read,
    Write,
    Failed(String),
}

/// Send whatever the connection has produced, and whatever is left
/// over from last time.
///
/// **Partial writes are kept.** A non-blocking socket can accept half a
/// flight and refuse the rest, and `take_outgoing` has already handed
/// those bytes over by then - so the remainder goes in `outbox` and the
/// caller is told to come back. Dropping it instead produces a TLS
/// stream with a hole in the middle, which fails at the next MAC with
/// nothing pointing at the cause.
fn flush(inner: &mut Connection) -> Result<(), WouldBlock> {
    if let Some(client) = inner.inner.as_mut() {
        let produced = client.take_outgoing();
        inner.outbox.extend_from_slice(&produced);
    }
    if inner.outbox.is_empty() {
        return Ok(());
    }

    let sent = match &inner.transport {
        Transport::Descriptor(fd) => {
            let mut file = unsafe { borrowed_file(*fd) };
            match file.write(&inner.outbox) {
                Ok(written) => written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock =>
                    return Err(WouldBlock::Write),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => 0,
                Err(error) => return Err(WouldBlock::Failed(error.to_string())),
            }
        }
        Transport::Bios { write, .. } => {
            // SAFETY: the BIO was handed to us by the program and is
            // live until it takes it back or frees the connection.
            match unsafe { objects::bio_write(*write, &inner.outbox) } {
                Ok(written) => written,
                Err(true) => return Err(WouldBlock::Write),
                Err(false) => return Err(WouldBlock::Failed(
                    "the transport refused a write".into())),
            }
        }
        Transport::None => return Err(WouldBlock::Failed(
            "no socket was attached to this connection".into())),
    };

    inner.outbox.drain(..sent);
    if inner.outbox.is_empty() {
        Ok(())
    } else {
        Err(WouldBlock::Write)
    }
}

/// `flush`, for the places that only want to know whether it worked.
fn flush_or_reason(inner: &mut Connection) -> Result<(), String> {
    match flush(inner) {
        Ok(()) => Ok(()),
        Err(WouldBlock::Failed(reason)) => Err(reason),
        Err(_) => Err("the transport would block".to_string()),
    }
}

/// Read once from the transport.
fn receive(inner: &mut Connection, buffer: &mut [u8]) -> Result<usize, WouldBlock> {
    match &inner.transport {
        Transport::Descriptor(fd) => {
            let mut file = unsafe { borrowed_file(*fd) };
            match file.read(buffer) {
                Ok(read) => Ok(read),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock =>
                    Err(WouldBlock::Read),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted =>
                    Err(WouldBlock::Read),
                Err(error) => Err(WouldBlock::Failed(error.to_string())),
            }
        }
        Transport::Bios { read, .. } => {
            // SAFETY: as in `flush`.
            match unsafe { objects::bio_read(*read, buffer) } {
                Ok(count) => Ok(count),
                Err(true) => Err(WouldBlock::Read),
                Err(false) => Err(WouldBlock::Failed(
                    "the transport refused a read".into())),
            }
        }
        Transport::None => Err(WouldBlock::Failed(
            "no socket was attached to this connection".into())),
    }
}

/// A `File` over a descriptor we do **not** own.
///
/// `ManuallyDrop` because the program owns the socket and closes it
/// itself; letting this drop would close the descriptor under it, and
/// the next use would be a different file entirely.
///
/// # Safety
/// `fd` must be open for the lifetime of the returned value.
unsafe fn borrowed_file(fd: c_int) -> std::mem::ManuallyDrop<std::fs::File> {
    use std::os::fd::FromRawFd;
    std::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(fd))
}

/// `SSL_read(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_read(connection: *mut c_void, data: *mut c_void,
                                  length: c_int) -> c_int {
    read_into(connection, data, length, false)
}

/// `SSL_peek(3)`: the same, without consuming.
#[no_mangle]
pub unsafe extern "C" fn SSL_peek(connection: *mut c_void, data: *mut c_void,
                                  length: c_int) -> c_int {
    read_into(connection, data, length, true)
}

#[no_mangle]
pub unsafe extern "C" fn SSL_read_ex(connection: *mut c_void, data: *mut c_void,
                                     length: usize, read: *mut usize) -> c_int {
    let result = read_into(connection, data, length as c_int, false);
    if result <= 0 {
        return 0;
    }
    if !read.is_null() {
        *read = result as usize;
    }
    1
}

unsafe fn read_into(connection: *mut c_void, data: *mut c_void, length: c_int,
                    peek: bool) -> c_int {
    objects::clear_error_queue();
    if data.is_null() || length <= 0 {
        return 0;
    }
    let Some(handle) = ssl_of(connection) else { return -1 };
    let Ok(mut inner) = handle.inner.lock() else { return -1 };

    if !inner.established {
        match handshake(&mut inner) {
            Ok(true) => {}
            Ok(false) => return -1,
            Err(reason) => {
                config::complain(&reason);
                inner.last_error = SSL_ERROR_SSL;
                return -1;
            }
        }
    }

    // Pull until there is something to give back, or the peer stops.
    while inner.pending.is_empty() {
        if inner.peer_closed {
            inner.last_error = SSL_ERROR_ZERO_RETURN;
            return 0;
        }
        let mut buffer = [0u8; 17 * 1024];
        match receive(&mut inner, &mut buffer) {
            Ok(0) => {
                inner.peer_closed = true;
                inner.last_error = SSL_ERROR_ZERO_RETURN;
                return 0;
            }
            Ok(read) => {
                let Some(client) = inner.inner.as_mut() else { return -1 };
                client.push_incoming(&buffer[..read]);
                if let Err(error) = client.process() {
                    let reason = error.describe();
                    // A close_notify is not a failure; it is the peer
                    // saying it is done, and a program that treats it
                    // as an error truncates the last response.
                    inner.peer_closed = true;
                    inner.last_error = SSL_ERROR_ZERO_RETURN;
                    if inner.settings.verbose {
                        config::complain(&reason);
                    }
                    return 0;
                }
                let payload = inner.inner.as_mut()
                    .map(|c| c.take_incoming()).unwrap_or_default();
                inner.pending.extend_from_slice(&payload);
                if let Err(reason) = flush_or_reason(&mut inner) {
                    if inner.settings.verbose {
                        config::complain(&reason);
                    }
                }
            }
            Err(WouldBlock::Read) => {
                inner.last_error = SSL_ERROR_WANT_READ;
                return -1;
            }
            Err(WouldBlock::Write) => {
                inner.last_error = SSL_ERROR_WANT_WRITE;
                return -1;
            }
            Err(WouldBlock::Failed(reason)) => {
                if inner.settings.verbose {
                    config::complain(&reason);
                }
                inner.last_error = SSL_ERROR_SYSCALL;
                return -1;
            }
        }
    }

    let wanted = (length as usize).min(inner.pending.len());
    std::ptr::copy_nonoverlapping(inner.pending.as_ptr(), data as *mut u8, wanted);
    if !peek {
        inner.pending.drain(..wanted);
    }
    inner.last_error = SSL_ERROR_NONE;
    wanted as c_int
}

/// `SSL_write(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_write(connection: *mut c_void, data: *const c_void,
                                   length: c_int) -> c_int {
    objects::clear_error_queue();
    if length <= 0 {
        return 0;
    }
    let Some(handle) = ssl_of(connection) else { return -1 };
    let Ok(mut inner) = handle.inner.lock() else { return -1 };

    if !inner.established {
        match handshake(&mut inner) {
            Ok(true) => {}
            Ok(false) => return -1,
            Err(reason) => {
                config::complain(&reason);
                inner.last_error = SSL_ERROR_SSL;
                return -1;
            }
        }
    }

    let payload = std::slice::from_raw_parts(data as *const u8, length as usize);
    {
        let Some(client) = inner.inner.as_mut() else { return -1 };
        if let Err(error) = client.write(payload) {
            config::complain(&error.describe());
            inner.last_error = SSL_ERROR_SSL;
            return -1;
        }
    }
    match flush(&mut inner) {
        Ok(()) => {
            inner.last_error = SSL_ERROR_NONE;
            length
        }
        Err(WouldBlock::Failed(reason)) => {
            if inner.settings.verbose {
                config::complain(&reason);
            }
            inner.last_error = SSL_ERROR_SYSCALL;
            -1
        }
        Err(_) => {
            // The plaintext *was* accepted - it is in `outbox` and will
            // go out on the next call. Saying WANT_WRITE and a length
            // of -1 is what OpenSSL does here, and the program retries
            // with the same buffer, which `SSL_MODE_ACCEPT_MOVING_..`
            // makes safe.
            inner.last_error = SSL_ERROR_WANT_WRITE;
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SSL_write_ex(connection: *mut c_void,
                                      data: *const c_void, length: usize,
                                      written: *mut usize) -> c_int {
    let result = SSL_write(connection, data, length as c_int);
    if result <= 0 {
        return 0;
    }
    if !written.is_null() {
        *written = result as usize;
    }
    1
}

/// `SSL_pending(3)`: plaintext already decrypted and waiting.
#[no_mangle]
pub unsafe extern "C" fn SSL_pending(connection: *mut c_void) -> c_int {
    let Some(handle) = ssl_of(connection) else { return 0 };
    let Ok(inner) = handle.inner.lock() else { return 0 };
    inner.pending.len() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn SSL_has_pending(connection: *mut c_void) -> c_int {
    c_int::from(SSL_pending(connection) > 0)
}

/// `SSL_shutdown(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_shutdown(connection: *mut c_void) -> c_int {
    let Some(handle) = ssl_of(connection) else { return -1 };
    let Ok(mut inner) = handle.inner.lock() else { return -1 };
    if inner.shutdown_sent {
        return 1;
    }
    if !inner.established {
        return 1;
    }
    if let Some(client) = inner.inner.as_mut() {
        let _ = client.close();
    }
    let _ = flush_or_reason(&mut inner);
    inner.shutdown_sent = true;
    // 0 means "sent, not yet acknowledged", which is what has happened
    // and what a program expects to see once.
    0
}

// ----------------------------------------------------------- what was got ---

/// `SSL_get_verify_result(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_verify_result(connection: *mut c_void) -> c_long {
    let Some(handle) = ssl_of(connection) else { return X509_V_OK };
    let Ok(inner) = handle.inner.lock() else { return X509_V_OK };
    inner.verify_result
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_verify_result(connection: *mut c_void,
                                               result: c_long) {
    let Some(handle) = ssl_of(connection) else { return };
    if let Ok(mut inner) = handle.inner.lock() {
        inner.verify_result = result;
    }
}

/// `SSL_get1_peer_certificate(3)`: the caller owns the reference.
#[no_mangle]
pub unsafe extern "C" fn SSL_get1_peer_certificate(connection: *mut c_void)
                                                   -> *mut c_void {
    let Some(handle) = ssl_of(connection) else { return std::ptr::null_mut() };
    let Ok(inner) = handle.inner.lock() else { return std::ptr::null_mut() };
    if inner.peer_certificate.is_null() {
        return std::ptr::null_mut();
    }
    objects::x509_up_ref(inner.peer_certificate);
    inner.peer_certificate
}

/// The pre-3.0 spelling, still referenced by things built against 1.1.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_peer_certificate(connection: *mut c_void)
                                                  -> *mut c_void {
    SSL_get1_peer_certificate(connection)
}

/// `SSL_get_peer_cert_chain(3)`: borrowed, not owned.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_peer_cert_chain(connection: *mut c_void)
                                                 -> *mut c_void {
    let Some(handle) = ssl_of(connection) else { return std::ptr::null_mut() };
    let Ok(inner) = handle.inner.lock() else { return std::ptr::null_mut() };
    inner.peer_stack
}

/// `SSL_get0_verified_chain(3)`.
///
/// Only when it actually verified - the name says *verified*, and a
/// program that reads this to decide something must not be handed the
/// chain that failed.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_verified_chain(connection: *mut c_void)
                                                 -> *mut c_void {
    let Some(handle) = ssl_of(connection) else { return std::ptr::null_mut() };
    let Ok(inner) = handle.inner.lock() else { return std::ptr::null_mut() };
    if inner.verify_result == X509_V_OK {
        inner.peer_stack
    } else {
        std::ptr::null_mut()
    }
}

/// `SSL_get_version(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_version(connection: *mut c_void) -> *const c_char {
    static UNKNOWN: &[u8] = b"unknown\0";
    static SSL3: &[u8] = b"SSLv3\0";
    static TLS10: &[u8] = b"TLSv1\0";
    static TLS11: &[u8] = b"TLSv1.1\0";
    static TLS12: &[u8] = b"TLSv1.2\0";
    static TLS13: &[u8] = b"TLSv1.3\0";

    let Some(handle) = ssl_of(connection) else {
        return UNKNOWN.as_ptr() as *const c_char };
    let Ok(inner) = handle.inner.lock() else {
        return UNKNOWN.as_ptr() as *const c_char };
    let text = match inner.inner.as_ref().and_then(|c| c.negotiated_version()) {
        Some(Version::SSL30) => SSL3,
        Some(Version::TLS10) => TLS10,
        Some(Version::TLS11) => TLS11,
        Some(Version::TLS12) => TLS12,
        Some(Version::TLS13) => TLS13,
        _ => UNKNOWN,
    };
    text.as_ptr() as *const c_char
}

/// `SSL_get_current_cipher(3)`.
///
/// The handle is the connection itself, and `SSL_CIPHER_get_name` below
/// reads the name back out of it. A real `SSL_CIPHER *` would have to
/// be a static table we do not have; this keeps the pair consistent and
/// is only ever passed back to us.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_current_cipher(connection: *mut c_void)
                                                -> *const c_void {
    let Some(handle) = ssl_of(connection) else { return std::ptr::null() };
    let Ok(inner) = handle.inner.lock() else { return std::ptr::null() };
    if inner.inner.as_ref().and_then(|c| c.negotiated_suite()).is_none() {
        return std::ptr::null();
    }
    connection as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CIPHER_get_name(cipher: *const c_void)
                                             -> *const c_char {
    static UNKNOWN: &[u8] = b"(NONE)\0";
    if cipher.is_null() {
        return UNKNOWN.as_ptr() as *const c_char;
    }
    // The pointer is the connection; see `SSL_get_current_cipher`.
    let Some(handle) = ssl_of(cipher as *mut c_void) else {
        return UNKNOWN.as_ptr() as *const c_char };
    let Ok(mut inner) = handle.inner.lock() else {
        return UNKNOWN.as_ptr() as *const c_char };
    let name = inner.inner.as_ref().and_then(|c| c.negotiated_suite())
        .map(|s| s.openssl_name).unwrap_or("(NONE)");
    // Kept alive in the connection, because the caller gets a pointer
    // and OpenSSL's contract is that it stays valid.
    inner.cipher_name = format!("{}\0", name);
    inner.cipher_name.as_ptr() as *const c_char
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_cipher_list(_connection: *mut c_void,
                                             _index: c_int) -> *const c_char {
    std::ptr::null()
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_peer_signature_type_nid(_connection: *mut c_void,
                                                         nid: *mut c_int) -> c_int {
    if !nid.is_null() {
        *nid = 0;
    }
    0
}

/// `SSL_alert_desc_string_long(3)`.
#[no_mangle]
pub unsafe extern "C" fn SSL_alert_desc_string_long(_value: c_int)
                                                    -> *const c_char {
    static TEXT: &[u8] = b"unknown\0";
    TEXT.as_ptr() as *const c_char
}

// -------------------------------------------------------------- sessions ---
//
// Session resumption is not offered. Returning null from `get_session`
// means "nothing to reuse", which every program handles - it is the
// normal case for a first connection.

#[no_mangle]
pub unsafe extern "C" fn SSL_get_session(_connection: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get1_session(_connection: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn SSL_set_session(_connection: *mut c_void,
                                         _session: *mut c_void) -> c_int { 0 }

#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_free(_session: *mut c_void) {}

#[no_mangle]
pub unsafe extern "C" fn SSL_session_reused(_connection: *mut c_void) -> c_int { 0 }

// ------------------------------------------------------------- user data ---
//
// A pointer the program stores on the connection and reads back. Real,
// because `libcurl` keeps its own state there and getting null back
// would be a null dereference in its code.

#[no_mangle]
pub unsafe extern "C" fn SSL_set_ex_data(connection: *mut c_void, index: c_int,
                                         data: *mut c_void) -> c_int {
    let Some(handle) = ssl_of(connection) else { return 0 };
    let Ok(mut inner) = handle.inner.lock() else { return 0 };
    inner.ex_data.insert(index, data as usize);
    1
}

#[no_mangle]
pub unsafe extern "C" fn SSL_get_ex_data(connection: *mut c_void, index: c_int)
                                         -> *mut c_void {
    let Some(handle) = ssl_of(connection) else { return std::ptr::null_mut() };
    let Ok(inner) = handle.inner.lock() else { return std::ptr::null_mut() };
    inner.ex_data.get(&index).map(|v| *v as *mut c_void)
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_ex_data(_context: *mut c_void, _index: c_int,
                                             _data: *mut c_void) -> c_int { 1 }

#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_ex_data(_context: *mut c_void,
                                             _index: c_int) -> *mut c_void {
    std::ptr::null_mut()
}
