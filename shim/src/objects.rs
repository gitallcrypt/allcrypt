/*
The boundary with the real libcrypto.

**This is the only file in the shim that calls OpenSSL**, and it is kept
that way on purpose.

The shim replaces libssl - the protocol - and leaves libcrypto alone.
That is not laziness: the programs being shimmed do not only call
libssl. `wget` takes the `X509 *` our `SSL_get1_peer_certificate`
returns and calls `X509_get_subject_name`, `X509_get_ext_d2i`,
`X509_NAME_get_text_by_NID` and a dozen more on it, none of which we
intercept. If we handed back a pointer to something of our own, every
one of those would read our bytes as an OpenSSL struct and crash.

So we hand back **genuine OpenSSL objects**, built from our DER with
`d2i_X509`. Everything the program then does to them works because they
are the real thing.

**No cryptography happens here.** Nothing in this file verifies a
signature, derives a key or decides whether to trust anything - it
converts between our byte strings and OpenSSL's structs, and that is
all. The judgement is `allcrypt`'s, in Rust, as everywhere else.

## If this has to go

Keeping a libcrypto dependency at all is a compromise with "minimise
dependencies, all fault is our own". The alternative is to shim
libcrypto too - to implement `X509_get_subject_name` and its relatives
over our own parsed certificates - which is a much larger surface where
every accessor we miss is a crash rather than an error.

That may become necessary. The file is arranged so that it can: every
call out is `unsafe extern` declared here and nowhere else, and the rest
of the shim speaks only in Rust types and opaque handles. Replacing this
module with one that builds our own objects is a contained change, and
nothing above it needs to know.
*/

use std::os::raw::{c_char, c_int, c_long, c_void};
use std::sync::OnceLock;

// ------------------------------------------------------- what we call out to ---
//
// Declared, not bound to a header: there is no C toolchain in this
// build. Each signature is from the OpenSSL 3.0 manual page named
// beside it, and a wrong one here is a crash rather than a compile
// error - which is why the list is short and why nothing else in the
// shim is allowed to grow it.
//
// ## Found at run time, not linked
//
// `#[link(name = "crypto")]` is shorter and is what this did first.
// Two things are wrong with it:
//
//   * It makes OpenSSL's *development* package a build dependency of
//     the whole workspace. `-lcrypto` resolves through the unversioned
//     `libcrypto.so` symlink, which only `libssl-dev` installs, so on
//     an ordinary machine that merely runs OpenSSL `cargo test` fails
//     to link - and `cargo test` has nothing to do with the shim.
//     On Windows there is no `crypto.lib` at all.
//
//   * It writes a `DT_NEEDED` for whichever soname happened to be
//     installed when we built. Preload that into a program linked
//     against a different libcrypto and the process now holds two of
//     them: we build an `X509` with one and the program calls
//     `X509_get_subject_name` on it from the other. Same name, other
//     struct layout, other allocator - a crash, and a baffling one.
//
// So the pointers are looked up with `dlsym` in the **global** symbol
// scope. `dlopen(NULL, ..)` is a handle onto the running program and
// everything it has already loaded, which under `LD_PRELOAD` is
// precisely the libcrypto the program is itself using - the one whose
// objects it is about to call accessors on. Opening a copy by soname
// is only a fallback, for a host program that has none of its own.
//
// `dlopen`/`dlsym` are declared without a `#[link]` of their own
// because glibc 2.34 and later have them in `libc.so.6`, which every
// Rust binary already links. On a glibc older than that they live in
// `libdl.so.2` and this needs `#[link(name = "dl")]` - which is safe
// to add, since `libdl.so` comes from `libc6-dev` and you cannot link
// a Rust program at all without that.
extern "C" {
    fn dlopen(file: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

/// `RTLD_LAZY` from dlfcn.h. `0x1` on both Linux and macOS.
///
/// Lazy rather than `RTLD_NOW` because we bind every symbol we care
/// about by hand below; there is nothing left for the loader to
/// resolve eagerly, and `RTLD_NOW` on a library this size is work for
/// nothing.
const RTLD_LAZY: c_int = 0x1;

/// Sonames to try when the host program brought no libcrypto of its
/// own, most likely first.
///
/// This list exists for completeness, not for the normal path: reached
/// only when `dlopen(NULL, ..)` turned up nothing, which under
/// `LD_PRELOAD` means the program was not an OpenSSL program to begin
/// with. Each is NUL terminated in the literal so it can be passed
/// straight out.
const SONAMES: &[&str] = &[
    "libcrypto.so.3\0",
    "libcrypto.so.1.1\0",
    "libcrypto.so.1.0.0\0",
    "libcrypto.so\0",
    "libcrypto.3.dylib\0",
    "libcrypto.1.1.dylib\0",
    "libcrypto.dylib\0",
];

/// Build the table of entry points from a list written the way the
/// `extern` block used to be.
///
/// The macro only removes the repetition of naming each signature
/// twice - once to declare it and once to transmute to it. It
/// deliberately does **not** generate free functions that stand in for
/// the old `extern` ones, because that would need a made-up answer per
/// function for the case where libcrypto is missing. Every caller
/// below asks `libcrypto()` and says for itself what it does with
/// `None`, which is the interesting half of this change.
macro_rules! entry_points {
    (
        required { $(
            $(#[doc = $needed_doc:literal])*
            fn $needed:ident($($_na:ident: $needed_type:ty),* $(,)?) $(-> $needed_result:ty)?;
        )* }
        optional { $(
            $(#[doc = $spare_doc:literal])*
            fn $spare:ident($($_sa:ident: $spare_type:ty),* $(,)?) $(-> $spare_result:ty)?;
        )* }
    ) => {
        /// Every libcrypto function the shim uses, resolved once.
        #[allow(non_snake_case)]
        struct Libcrypto {
            $( $(#[doc = $needed_doc])*
               $needed: unsafe extern "C" fn($($needed_type),*) $(-> $needed_result)?, )*
            $( $(#[doc = $spare_doc])*
               $spare: Option<unsafe extern "C" fn($($spare_type),*) $(-> $spare_result)?>, )*
        }

        impl Libcrypto {
            /// # Safety
            /// `handle` must be live, from `dlopen`.
            unsafe fn resolve(handle: *mut c_void) -> Option<Self> {
                Some(Self {
                    $( $needed: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn($($needed_type),*) $(-> $needed_result)?,
                    >(symbol(handle, concat!(stringify!($needed), "\0"))?), )*
                    $( $spare: symbol(handle, concat!(stringify!($spare), "\0"))
                        .map(|found| std::mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn($($spare_type),*) $(-> $spare_result)?,
                        >(found)), )*
                })
            }
        }
    };
}

entry_points! {
    // Every one of these or none. A libcrypto missing one is not a
    // libcrypto we can use, and finding that out halfway through a
    // handshake is worse than finding it out at the first call.
    //
    // The floor this sets is **OpenSSL 1.1.0**: that is where the
    // generic `OPENSSL_sk_*` replaced the per-type `sk_X509_*` macros,
    // where `X509_up_ref` and `BIO_test_flags` became functions rather
    // than reaching into the struct, and where `CRYPTO_free` grew its
    // file and line arguments. Against 1.0.2 nothing here resolves -
    // which is the right answer rather than a gap, because the shim's
    // whole interposition story assumes the symbol versioning 1.1.0
    // introduced.
    required {
        /// d2i_X509(3): DER in, `X509 *` out. The pointer argument is
        /// advanced by the call, which is why it is passed by address
        /// and then discarded.
        fn d2i_X509(out: *mut *mut c_void, der: *mut *const u8, len: c_long) -> *mut c_void;
        /// X509_free(3).
        fn X509_free(certificate: *mut c_void);
        /// X509_up_ref(3) - for handing the same certificate out twice.
        fn X509_up_ref(certificate: *mut c_void) -> c_int;

        /// OPENSSL_sk_new_null(3) and relatives. `STACK_OF(X509)` is
        /// this with a cast; the generic functions are what actually
        /// exist.
        fn OPENSSL_sk_new_null() -> *mut c_void;
        fn OPENSSL_sk_push(stack: *mut c_void, item: *const c_void) -> c_int;
        fn OPENSSL_sk_free(stack: *mut c_void);
        fn OPENSSL_sk_num(stack: *const c_void) -> c_int;
        fn OPENSSL_sk_value(stack: *const c_void, index: c_int) -> *mut c_void;

        /// BIO_read(3)/BIO_write(3). libcurl hands the connection its
        /// own socket BIOs rather than a file descriptor, so this is
        /// the other half of the I/O story.
        fn BIO_read(bio: *mut c_void, data: *mut c_void, len: c_int) -> c_int;
        fn BIO_write(bio: *mut c_void, data: *const c_void, len: c_int) -> c_int;
        fn BIO_free_all(bio: *mut c_void);
        /// BIO_ctrl(3). Used for BIO_should_retry's underlying flags
        /// and for flush; the command numbers are from `bio.h`.
        fn BIO_ctrl(bio: *mut c_void, command: c_int, larg: c_long, parg: *mut c_void) -> c_long;
        fn BIO_test_flags(bio: *mut c_void, flags: c_int) -> c_int;

        /// X509_STORE_new(3). A program may ask for the context's
        /// store and add lookups to it; it gets a real one so those
        /// calls work.
        fn X509_STORE_new() -> *mut c_void;
        fn X509_STORE_free(store: *mut c_void);
        /// i2d_X509(3): back to DER, so the roots can cross into our
        /// own `TrustStore` as bytes rather than as somebody's struct.
        fn i2d_X509(certificate: *mut c_void, out: *mut *mut u8) -> c_int;
        /// CRYPTO_free(3), for what `i2d_X509` allocated.
        fn CRYPTO_free(pointer: *mut c_void, file: *const c_char, line: c_int);

        /// ERR_clear_error(3). The programs we shim check the error
        /// queue after a failure, and a stale entry from something
        /// unrelated reads as our failure.
        fn ERR_clear_error();
    }

    // Absent on a libcrypto older than we would like, and worth less
    // than everything else put together.
    optional {
        /// X509_STORE_get1_all_certs(3), **OpenSSL 3.0 and later**.
        /// The only way to read a store back out: `libcurl` puts
        /// `--cacert` in there with `X509_STORE_add_cert` and
        /// `X509_STORE_load_file` rather than through any libssl call
        /// we could intercept.
        ///
        /// Optional rather than required because 1.1.1 does not have
        /// it, and 1.1.1 is exactly the sort of host this library
        /// exists for. Requiring it would mean that on such a host
        /// *nothing* resolved and every certificate object was lost,
        /// to save a feature only `libcurl --cacert` uses. Its absence
        /// is reported rather than hidden - see `origin`.
        fn X509_STORE_get1_all_certs(store: *mut c_void) -> *mut c_void;
    }
}

/// One symbol, or `None` if this library does not have it.
///
/// # Safety
/// `handle` must be live and `name` NUL terminated.
unsafe fn symbol(handle: *mut c_void, name: &str) -> Option<*mut c_void> {
    let found = dlsym(handle, name.as_ptr() as *const c_char);
    if found.is_null() { None } else { Some(found) }
}

/// A resolved table and where it came from.
struct Found {
    table: Libcrypto,
    /// `"global scope"` or the soname that was opened. Reported in the
    /// shim's log because it is otherwise unobservable, and the
    /// difference between the two is the difference between using the
    /// program's own libcrypto and loading a second one.
    origin: &'static str,
}

/// Where libcrypto was found, for the log line in `lib.rs`.
///
/// `"global scope"` is the answer under `LD_PRELOAD` and the one that
/// matters: it means the objects we build come from the same libcrypto
/// the program will call accessors from. Anything else means we loaded
/// a copy, which is safe only because the program had none.
pub fn origin() -> String {
    match found() {
        None => "none".to_string(),
        Some(found) if found.table.X509_STORE_get1_all_certs.is_none() =>
            format!("{} (pre-3.0: a store cannot be read back)", found.origin),
        Some(found) => found.origin.to_string(),
    }
}

/// The library, or `None` if there is no usable libcrypto.
///
/// Resolved once and kept forever. Nothing ever calls `dlclose`: the
/// table holds pointers into the library, and closing it would leave
/// every one of them dangling for the sake of tidiness at exit.
fn found() -> Option<&'static Found> {
    static FOUND: OnceLock<Option<Found>> = OnceLock::new();
    FOUND.get_or_init(|| {
        // SAFETY: `dlopen` and `dlsym` take what they are given here,
        // and `resolve` only transmutes pointers `dlsym` returned for
        // the signatures listed above.
        let found = unsafe {
            let global = dlopen(std::ptr::null(), RTLD_LAZY);
            let mut found = if global.is_null() {
                None
            } else {
                Libcrypto::resolve(global)
                    .map(|table| Found { table, origin: "global scope" })
            };
            for soname in SONAMES {
                if found.is_some() {
                    break;
                }
                let handle = dlopen(soname.as_ptr() as *const c_char, RTLD_LAZY);
                if !handle.is_null() {
                    found = Libcrypto::resolve(handle).map(|table| Found {
                        table,
                        // Without the NUL, which is in the literal so
                        // it can be passed straight to `dlopen`.
                        origin: &soname[..soname.len() - 1],
                    });
                }
            }
            found
        };
        if found.is_none() {
            // Said once, to stderr, because the failure is otherwise
            // invisible: the handshake still works - all of that is
            // ours - but `SSL_get1_peer_certificate` starts answering
            // null, and a program that reads the certificate for its
            // own reasons will behave as though the peer sent none.
            eprintln!("allcrypt shim: no libcrypto found; certificates cannot be \
                       handed back as OpenSSL objects");
        }
        found
    })
    .as_ref()
}

/// The table alone, which is all any caller below wants.
fn libcrypto() -> Option<&'static Libcrypto> {
    Some(&found()?.table)
}

/// `BIO_CTRL_FLUSH` from bio.h.
const BIO_CTRL_FLUSH: c_int = 11;
/// `BIO_FLAGS_SHOULD_RETRY` from bio.h.
const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;

// ----------------------------------------------------------------- the API ---

/// A real `X509 *` built from DER, or null if it would not parse.
///
/// Null is a legitimate answer: `SSL_get1_peer_certificate` returns
/// null when there is no peer certificate, and every caller has to
/// handle that already.
///
/// # Safety
/// The returned pointer is owned by the caller and must reach
/// `X509_free`, which is what the programs we shim do with it - the
/// `1` in the function's name is OpenSSL's convention for "you now own
/// a reference".
pub fn x509_from_der(der: &[u8]) -> *mut c_void {
    // No libcrypto is the same answer as an unparseable certificate:
    // null, which every caller already handles.
    let Some(crypto) = libcrypto() else { return std::ptr::null_mut() };
    if der.is_empty() {
        return std::ptr::null_mut();
    }
    let mut pointer = der.as_ptr();
    // SAFETY: `der` is a valid slice for the length passed, and
    // `d2i_X509` only reads through it. A malformed certificate makes
    // it return null, which is the documented behaviour rather than an
    // error we have to catch.
    unsafe { (crypto.d2i_X509)(std::ptr::null_mut(), &mut pointer, der.len() as c_long) }
}

/// Drop a certificate we made.
///
/// # Safety
/// `certificate` must be null or an `X509 *` from `x509_from_der`.
pub unsafe fn x509_free(certificate: *mut c_void) {
    // Nothing to do without libcrypto, and nothing lost: a non-null
    // pointer here can only have come from `x509_from_der`, which
    // answers null when there is none.
    let Some(crypto) = libcrypto() else { return };
    if !certificate.is_null() {
        (crypto.X509_free)(certificate);
    }
}

/// Take another reference, for handing the same certificate out twice.
///
/// # Safety
/// `certificate` must be a live `X509 *`.
pub unsafe fn x509_up_ref(certificate: *mut c_void) {
    let Some(crypto) = libcrypto() else { return };
    if !certificate.is_null() {
        (crypto.X509_up_ref)(certificate);
    }
}

/// A `STACK_OF(X509) *` holding the chain, leaf first.
///
/// Returns null if the stack could not be made. The stack owns its
/// certificates: a caller that frees it with `sk_X509_pop_free` frees
/// them too, which is what `SSL_get0_verified_chain`'s contract says
/// happens to the *connection's* copy - so this is used for the `get1`
/// forms and kept alive by us for the `get0` ones.
pub fn x509_stack_from_ders(chain: &[Vec<u8>]) -> *mut c_void {
    // Null, as for an allocation that failed - which is the other way
    // this returns null and is already handled.
    let Some(crypto) = libcrypto() else { return std::ptr::null_mut() };
    // SAFETY: OPENSSL_sk_new_null allocates or returns null.
    let stack = unsafe { (crypto.OPENSSL_sk_new_null)() };
    if stack.is_null() {
        return stack;
    }
    for der in chain {
        let certificate = x509_from_der(der);
        if certificate.is_null() {
            continue;
        }
        // SAFETY: `stack` is a live stack and `certificate` a live
        // X509; push takes ownership of the pointer.
        unsafe {
            if (crypto.OPENSSL_sk_push)(stack, certificate) == 0 {
                x509_free(certificate);
            }
        }
    }
    stack
}

/// Free a stack made above, and the certificates in it.
///
/// # Safety
/// `stack` must be null or from `x509_stack_from_ders`, and not
/// already freed.
pub unsafe fn x509_stack_free(stack: *mut c_void) {
    let Some(crypto) = libcrypto() else { return };
    if stack.is_null() {
        return;
    }
    // Freed by hand rather than with `OPENSSL_sk_pop_free`, whose
    // second argument is a function pointer whose ABI we would have to
    // get exactly right for no benefit.
    let count = (crypto.OPENSSL_sk_num)(stack);
    for index in 0..count {
        x509_free((crypto.OPENSSL_sk_value)(stack, index));
    }
    (crypto.OPENSSL_sk_free)(stack);
}

/// An empty, real `X509_STORE *`.
///
/// Handed out by `SSL_CTX_get_cert_store` so that a program adding a
/// lookup or setting a flag on it does not crash. **Nothing is read
/// back out of it**: the roots this shim verifies against come from
/// `SSL_CTX_load_verify_locations` and friends, which are libssl calls
/// we intercept directly. See the note in `lib.rs` about what that
/// means for anything loaded through the store instead.
pub fn store_new() -> *mut c_void {
    let Some(crypto) = libcrypto() else { return std::ptr::null_mut() };
    // SAFETY: allocates or returns null.
    unsafe { (crypto.X509_STORE_new)() }
}

/// Every certificate in a store, as DER.
///
/// This is how `--cacert` reaches us from `libcurl`, which never calls
/// a libssl function to load it: it takes the context's store and uses
/// `X509_STORE_add_cert` and `X509_STORE_load_file` on it directly.
/// Without reading the store back, every curl connection would verify
/// against nothing.
///
/// # Safety
/// `store` must be null or a live `X509_STORE *`.
pub unsafe fn store_certificates(store: *mut c_void) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some(crypto) = libcrypto() else { return out };
    // Absent before OpenSSL 3.0. Empty is then the honest answer:
    // there is no other way to read a store back, so roots that only
    // ever went in through `X509_STORE_add_cert` are out of reach.
    // `origin()` says so in the log rather than leaving it to be
    // discovered by a connection that verified against nothing.
    let Some(get1_all_certs) = crypto.X509_STORE_get1_all_certs else { return out };
    if store.is_null() {
        return out;
    }
    let stack = get1_all_certs(store);
    if stack.is_null() {
        return out;
    }
    let count = (crypto.OPENSSL_sk_num)(stack);
    for index in 0..count {
        let certificate = (crypto.OPENSSL_sk_value)(stack, index);
        if certificate.is_null() {
            continue;
        }
        if let Some(der) = x509_to_der(certificate) {
            out.push(der);
        }
    }
    // `get1` means we own the stack and the references in it.
    x509_stack_free(stack);
    out
}

/// One certificate back to DER.
///
/// # Safety
/// `certificate` must be a live `X509 *`.
unsafe fn x509_to_der(certificate: *mut c_void) -> Option<Vec<u8>> {
    let crypto = libcrypto()?;
    let mut buffer: *mut u8 = std::ptr::null_mut();
    let length = (crypto.i2d_X509)(certificate, &mut buffer);
    if length <= 0 || buffer.is_null() {
        return None;
    }
    let der = std::slice::from_raw_parts(buffer, length as usize).to_vec();
    // Allocated by OpenSSL, so freed by OpenSSL.
    (crypto.CRYPTO_free)(buffer as *mut c_void, std::ptr::null(), 0);
    Some(der)
}

/// # Safety
/// `store` must be null or from `store_new`.
pub unsafe fn store_free(store: *mut c_void) {
    let Some(crypto) = libcrypto() else { return };
    if !store.is_null() {
        (crypto.X509_STORE_free)(store);
    }
}

/// Read from a BIO. `Ok(0)` means end of stream; `Err(true)` means the
/// BIO said to retry.
///
/// # Safety
/// `bio` must be a live `BIO *` the caller gave us.
pub unsafe fn bio_read(bio: *mut c_void, buffer: &mut [u8]) -> Result<usize, bool> {
    // `Err(false)` - failed, not "try again". A retry would call back
    // into here and fail the same way forever, and a BIO transport is
    // unusable without libcrypto whatever we say about it.
    let Some(crypto) = libcrypto() else { return Err(false) };
    let read = (crypto.BIO_read)(bio, buffer.as_mut_ptr() as *mut c_void,
                                 buffer.len() as c_int);
    if read > 0 {
        return Ok(read as usize);
    }
    // A non-positive return is "nothing this time"; whether it is worth
    // trying again is a flag on the BIO, not the return value. Reading
    // it the other way round turns a would-block into an end of stream
    // and truncates the response.
    if (crypto.BIO_test_flags)(bio, BIO_FLAGS_SHOULD_RETRY) != 0 {
        return Err(true);
    }
    if read == 0 {
        Ok(0)
    } else {
        Err(false)
    }
}

/// Write to a BIO once, returning how much it took.
///
/// **Not a loop.** A BIO may accept part of a buffer and then say
/// "later", and the caller has to keep the remainder rather than spin
/// here - the whole point of a non-blocking transport is that the
/// program gets control back. `Err(true)` means retry, `Err(false)`
/// means it failed.
///
/// # Safety
/// `bio` must be a live `BIO *`.
pub unsafe fn bio_write(bio: *mut c_void, data: &[u8]) -> Result<usize, bool> {
    let Some(crypto) = libcrypto() else { return Err(false) };
    let written = (crypto.BIO_write)(bio, data.as_ptr() as *const c_void,
                                     data.len() as c_int);
    if written > 0 {
        // Flushed because a buffering BIO otherwise holds our flight
        // until the next write, and the peer is waiting for it.
        (crypto.BIO_ctrl)(bio, BIO_CTRL_FLUSH, 0, std::ptr::null_mut());
        return Ok(written as usize);
    }
    if (crypto.BIO_test_flags)(bio, BIO_FLAGS_SHOULD_RETRY) != 0 {
        return Err(true);
    }
    Err(false)
}

/// # Safety
/// `bio` must be null or a live `BIO *` we own.
pub unsafe fn bio_free_all(bio: *mut c_void) {
    let Some(crypto) = libcrypto() else { return };
    if !bio.is_null() {
        (crypto.BIO_free_all)(bio);
    }
}

/// Empty OpenSSL's error queue.
///
/// Called before each operation that can fail, because the programs we
/// shim read the queue afterwards and a leftover entry from something
/// unrelated reads as our failure. We never *put* anything in it - our
/// errors travel through `SSL_get_error`.
pub fn clear_error_queue() {
    // Nothing to clear if there is no queue.
    let Some(crypto) = libcrypto() else { return };
    // SAFETY: no arguments, always safe.
    unsafe { (crypto.ERR_clear_error)() }
}

/// A NUL-terminated C string as a Rust `String`, or `None` for null.
///
/// # Safety
/// `text` must be null or point at a NUL-terminated string.
pub unsafe fn from_c_string(text: *const c_char) -> Option<String> {
    if text.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(text).to_str().ok().map(|s| s.to_string())
}

// ------------------------------------------------------------------ tests ---
//
// These cover what `pytests/test_shim.py` structurally cannot. That
// suite runs the shim under `LD_PRELOAD` inside `curl` and `wget`, so
// the global scope always holds a libcrypto and always wins: with the
// soname list emptied, every one of its twenty tests still passes.
// The cargo test binary is the opposite environment - it links no
// libcrypto at all, so `dlopen(NULL, ..)` turns up nothing and the
// fallback is the only path there is.
//
// Between the two, both branches of `found` are exercised by something.

#[cfg(test)]
mod tests {
    use super::*;

    /// Every spelling of OpenSSL's soname this machine can actually
    /// open.
    ///
    /// Written as a literal rather than read from `SONAMES`, on
    /// purpose: a test that probed the same list the code reads would
    /// agree with itself when an entry was deleted from that list, and
    /// noticing exactly that is what these are for.
    fn openable() -> Vec<&'static str> {
        ["libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so.1.0.0",
         "libcrypto.so", "libcrypto.3.dylib", "libcrypto.1.1.dylib",
         "libcrypto.dylib"]
            .iter()
            .copied()
            .filter(|name| {
                let terminated = format!("{}\0", name);
                unsafe {
                    !dlopen(terminated.as_ptr() as *const c_char, RTLD_LAZY).is_null()
                }
            })
            .collect()
    }

    fn openssl_is_installed() -> bool {
        !openable().is_empty()
    }

    /// Everything this machine has must be named in `SONAMES`.
    ///
    /// The equivalence test below passes with entries missing, as long
    /// as *one* that resolves survives - and on a development machine
    /// the one that survives is often `libcrypto.so`, which is the
    /// symlink from the development package. A host that has only
    /// `libcrypto.so.3` would then find nothing, which is precisely
    /// the machine this change was made for.
    #[test]
    fn every_soname_this_machine_has_is_in_the_list() {
        let listed: Vec<&str> =
            SONAMES.iter().map(|soname| &soname[..soname.len() - 1]).collect();
        for name in openable() {
            assert!(listed.contains(&name),
                    "{} can be opened on this machine but is not in SONAMES: a \
                     host with only that spelling would find no libcrypto",
                    name);
        }
    }

    /// A machine with a libcrypto must find it, and one without must
    /// say so. Asserted as an equivalence rather than as "it is
    /// found", because the second form is untrue on a machine with no
    /// OpenSSL and this library must build and test on one of those -
    /// that being the entire reason the linking went away.
    #[test]
    fn an_installed_libcrypto_is_the_one_that_is_found() {
        assert_eq!(openssl_is_installed(), found().is_some(),
                   "libcrypto is installed here but `found` did not find it, \
                    or the reverse: the soname list in SONAMES is wrong");
    }

    /// Here, where nothing links libcrypto, it can only have come from
    /// a soname. Pins the fallback branch specifically: the pytest
    /// suite exercises only the other one.
    #[test]
    fn without_one_in_scope_it_comes_from_a_soname() {
        if !openssl_is_installed() {
            return;
        }
        let origin = origin();
        assert!(origin.starts_with("libcrypto."),
                "a test binary links no libcrypto, so the global scope cannot \
                 have supplied one - but the origin is {:?}", origin);
    }

    /// The null return from `dlsym` means "not here" and must not be
    /// stored as a function pointer. Nothing else notices this: every
    /// symbol in the required set exists on any libcrypto new enough
    /// to matter, so a `symbol` that returned `Some(null)` would
    /// behave identically until the day it did not.
    #[test]
    fn a_symbol_that_is_not_there_is_none() {
        let handle = unsafe { dlopen(std::ptr::null(), RTLD_LAZY) };
        assert!(!handle.is_null(), "dlopen(NULL) should always succeed");
        assert!(unsafe { symbol(handle, "malloc\0") }.is_some(),
                "malloc is not in the global scope, which cannot be");
        assert!(unsafe { symbol(handle, "allcrypt_no_such_symbol_exists\0") }
                    .is_none(),
                "a missing symbol resolved to something");
    }

    /// DER in, `X509 *`, DER out, byte for byte.
    ///
    /// The end-to-end check that the table is wired to the functions
    /// it names. A macro that resolved the right *number* of symbols
    /// in the wrong *order* would pass everything above this and fail
    /// here, because `d2i_X509` would be some other function of one
    /// pointer argument.
    #[test]
    fn a_certificate_makes_the_round_trip_through_the_resolved_table() {
        if !openssl_is_installed() {
            eprintln!("no libcrypto on this machine; the round trip cannot be \
                       checked here. pytests/test_shim.py is where it is \
                       checked against a real curl.");
            return;
        }

        let curve = allcrypt::ec::curves::p256();
        let (private, point) = curve.generate_key_pair().unwrap();
        let encoded = curve.encode_point(&point, false).unwrap();
        let mut certificate = allcrypt::x509::builder::CertificateBuilder::new(
            "round.trip.test",
            allcrypt::x509::builder::SubjectKey::Ec { curve: &curve, point: &encoded });
        certificate.serial = vec![7];
        let der = certificate
            .sign(&allcrypt::x509::builder::SigningKey::Ec {
                curve: &curve, private: &private })
            .expect("could not build a certificate to round trip");

        let object = x509_from_der(&der);
        assert!(!object.is_null(),
                "OpenSSL would not parse a certificate we built; either the \
                 table is mis-wired or d2i_X509 is not d2i_X509");
        let back = unsafe { x509_to_der(object) }
            .expect("i2d_X509 gave nothing back");
        unsafe { x509_free(object) };
        assert_eq!(back, der,
                   "the certificate changed on the way through OpenSSL");
    }

    /// The optional entry is the one thing allowed to be missing, and
    /// its absence has to reach the log rather than being swallowed.
    #[test]
    fn a_missing_store_reader_is_reported_in_the_origin() {
        if !openssl_is_installed() {
            return;
        }
        let table = &found().unwrap().table;
        let origin = origin();
        assert_eq!(table.X509_STORE_get1_all_certs.is_none(),
                   origin.contains("pre-3.0"),
                   "the origin line and the table disagree about whether a \
                    store can be read back: {:?}", origin);
    }
}
