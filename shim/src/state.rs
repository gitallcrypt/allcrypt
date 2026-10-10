/*
The two objects a program holds: `SSL_CTX` and `SSL`.

OpenSSL's are opaque - a program only ever has a pointer - so ours can
be whatever we like, as long as every function the program calls on one
is a function we intercept. That last clause is the whole hazard of this
approach and the reason `lib.rs` implements the *complete* set of libssl
symbols the shimmed programs reference rather than the ones that looked
necessary. A single un-intercepted call reads our struct as OpenSSL's.

`SSL_CTX` is reference counted here as it is there. A program may free
the context while a connection made from it is still open - `libcurl`
does, on a connection it is keeping for reuse - and in OpenSSL that is
legal because the `SSL` holds a reference. An `Arc` says the same thing.
*/

use std::os::raw::{c_int, c_long, c_void};
use std::sync::{Arc, Mutex};

use allcrypt::tls::client::ClientConnection;
use allcrypt::tls::Version;
use allcrypt::trust::TrustStore;

use crate::config::Settings;

/// Where a connection's bytes come from and go.
///
/// The two shapes are not a detail: `wget` hands over a file descriptor
/// and expects us to read and write it, while `libcurl` hands over its
/// own pair of BIOs and expects us to go through them. A shim that
/// implemented only one works perfectly with one program and not at all
/// with the other.
pub enum Transport {
    /// Nothing set yet.
    None,
    /// `SSL_set_fd` and relatives.
    Descriptor(c_int),
    /// `SSL_set0_rbio` / `SSL_set0_wbio`, owned by us once set - the
    /// `0` in those names means the caller handed over its reference.
    Bios { read: *mut c_void, write: *mut c_void },
    /// A transport the tests drive by hand. See `Scripted`.
    #[cfg(test)]
    Scripted(Scripted),
}

/// A transport whose every byte is chosen by the test.
///
/// A socket pair would exercise the descriptor path, but the kernel
/// decides how many bytes one `read` returns and when a `write` blocks,
/// and neither can be made to happen on demand. Here each `receive`
/// returns exactly one queued chunk, and `flush` accepts exactly as many
/// bytes as `capacity` allows - so a flight delivered in one-byte
/// pieces, a write that blocks halfway through a record, and a peer
/// that goes away without a close_notify are each one line to set up.
#[cfg(test)]
pub struct Scripted {
    /// What `receive` hands over, one chunk per call. Empty means the
    /// peer has nothing to say yet: `WouldBlock::Read`.
    pub incoming: std::collections::VecDeque<Vec<u8>>,
    /// Set once `incoming` has been drained and the peer has hung up:
    /// `receive` then reports end of stream.
    pub closed: bool,
    /// Everything `flush` sent, in order.
    pub written: Vec<u8>,
    /// How many more bytes `flush` may accept. `None` is unlimited;
    /// `Some(0)` is a socket whose buffer is full.
    pub capacity: Option<usize>,
}

#[cfg(test)]
impl Scripted {
    pub fn new() -> Scripted {
        Scripted {
            incoming: std::collections::VecDeque::new(),
            closed: false,
            written: Vec::new(),
            capacity: None,
        }
    }
}

// SAFETY: the BIO pointers are only ever touched under the connection's
// own lock, and a `SSL` object is not shared between threads by any
// program we shim - OpenSSL's own contract for `SSL` is the same.
unsafe impl Send for Transport {}

/// What a program configured on an `SSL_CTX`.
pub struct Context {
    pub settings: Arc<Settings>,
    /// Roots from `SSL_CTX_load_verify_locations` and
    /// `SSL_CTX_set_default_verify_paths`.
    pub roots: TrustStore,
    /// True once anything put roots in. A context that verifies with
    /// none would refuse everything, and the distinction between "no
    /// roots because none were wanted" and "no roots because the file
    /// did not load" is worth keeping.
    pub roots_loaded: bool,
    /// From `SSL_CTX_set_verify`. `SSL_VERIFY_NONE` is 0.
    pub verify_mode: c_int,
    /// From `SSL_CTX_set_min_proto_version` (an `SSL_CTX_ctrl`).
    /// `None` means the program did not say and the settings decide.
    pub min_version: Option<Version>,
    pub max_version: Option<Version>,
    /// ALPN protocols, in wire format, from `SSL_CTX_set_alpn_protos`.
    /// Offered on every connection made from this context, unless the
    /// connection was given its own list.
    pub alpn: Vec<u8>,
    /// The `SSL_OP_*` mask from `SSL_CTX_set_options`. Copied onto each
    /// connection at `SSL_new`, as OpenSSL does; most bits ask for less
    /// strictness than this shim already has, and the one that changes
    /// what a program is told is read where it matters, in `SSL_read`.
    pub options: u64,
    /// A real `X509_STORE *`, handed out by `SSL_CTX_get_cert_store`.
    /// See the note there about what is and is not read back from it.
    pub store: *mut c_void,
    /// Set if the program asked for something this shim does not do,
    /// so the first handshake can say so rather than quietly not
    /// doing it.
    pub unsupported: Vec<String>,
    /// The OpenSSL cipher strings the program passed, none of which is
    /// honoured. Kept rather than dropped, and reported at the call
    /// rather than refused: see `SSL_CTX_set_cipher_list`.
    pub cipher_strings: Vec<String>,
}

// SAFETY: as `Transport` - the store pointer is only used from the
// thread holding the context's lock, and is freed exactly once.
unsafe impl Send for Context {}

impl Context {
    pub fn new(settings: Arc<Settings>) -> Context {
        Context {
            settings,
            roots: TrustStore::new(),
            roots_loaded: false,
            // OpenSSL's default is SSL_VERIFY_NONE, and a program that
            // wants verification says so. Defaulting to *on* here would
            // be us deciding.
            verify_mode: 0,
            min_version: None,
            max_version: None,
            alpn: Vec::new(),
            options: 0,
            store: std::ptr::null_mut(),
            unsupported: Vec::new(),
            cipher_strings: Vec::new(),
        }
    }

    pub fn floor(&self) -> Version {
        self.min_version.unwrap_or(self.settings.min_version)
    }

    pub fn ceiling(&self) -> Version {
        self.max_version.unwrap_or(self.settings.max_version)
    }

    /// Whether the program asked for the certificate to be checked.
    ///
    /// `SSL_VERIFY_PEER` is 1. Anything with that bit set means the
    /// program cares; everything else means it does not. We verify
    /// either way and *report* through `SSL_get_verify_result` - this
    /// only decides whether a bad result stops the handshake, which is
    /// the same thing OpenSSL does with the flag.
    pub fn wants_verification(&self) -> bool {
        self.verify_mode & 1 != 0
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: `store` is null or from `objects::store_new`, and
        // this runs once.
        unsafe { crate::objects::store_free(self.store) };
        self.store = std::ptr::null_mut();
    }
}

/// The state of one connection.
pub struct Connection {
    pub context: Arc<Mutex<Context>>,
    pub settings: Arc<Settings>,
    /// From `SSL_set_tlsext_host_name`, or from the verify parameters.
    /// Without one there is no SNI and no name to check.
    pub hostname: Option<String>,
    pub transport: Transport,
    /// The `SSL_OP_*` mask: the context's at `SSL_new`, plus whatever
    /// `SSL_set_options` added since.
    pub options: u64,
    /// ALPN protocols from `SSL_set_alpn_protos`, in wire format,
    /// overriding the context's when set.
    pub alpn: Option<Vec<u8>>,
    /// The protocol the server chose, for `SSL_get0_alpn_selected` to
    /// hand out a pointer into.
    pub alpn_selected: Option<Vec<u8>>,
    /// Built on the first `SSL_connect`, because the hostname is not
    /// known before then.
    pub inner: Option<ClientConnection>,
    pub established: bool,
    pub shutdown_sent: bool,
    pub peer_closed: bool,
    /// What `SSL_get_verify_result` returns. 0 is `X509_V_OK`.
    pub verify_result: c_long,
    /// The chain the peer sent, kept so the `get0` accessors can hand
    /// out a pointer that stays valid for the connection's lifetime.
    pub peer_chain: Vec<Vec<u8>>,
    /// Real `X509 *` and `STACK_OF(X509) *` made from the above, owned
    /// by this connection and freed with it. The `get0` forms hand
    /// these out without a reference, which is what their contract
    /// says.
    pub peer_certificate: *mut c_void,
    pub peer_stack: *mut c_void,
    /// Plaintext that arrived but has not been read yet.
    pub pending: Vec<u8>,
    /// The last failure, as an `SSL_ERROR_*` code for `SSL_get_error`.
    pub last_error: c_int,
    /// Why we failed, for the message the program cannot get from a
    /// code. Printed rather than returned - there is nowhere in the
    /// OpenSSL API to put it.
    pub failure: Option<String>,
    /// Ciphertext produced but not yet accepted by the transport.
    ///
    /// Needed because a non-blocking socket can take part of a flight
    /// and then say "later". `take_outgoing` has already handed the
    /// bytes over by then, so without somewhere to keep the remainder
    /// they are lost - and a TLS stream missing a few bytes in the
    /// middle fails at the next MAC with no hint as to why.
    pub outbox: Vec<u8>,
    /// The length of the plaintext `SSL_write` has already encrypted
    /// into `outbox` but not yet reported as written.
    ///
    /// `SSL_write` answering `SSL_ERROR_WANT_WRITE` means the program
    /// will call again with the same bytes, and OpenSSL's contract is
    /// that the retry *completes the earlier write* rather than starting
    /// a new one - the plaintext was consumed the first time and only
    /// the transport is still owed. Without this the retry encrypted
    /// the same bytes a second time, and the peer received them twice.
    pub pending_write: Option<usize>,
    /// The cipher name as a NUL-terminated string, built once when the
    /// handshake settles and never reassigned: `SSL_CIPHER_get_name`
    /// hands out a pointer into it, and OpenSSL's contract is that the
    /// pointer stays valid for as long as the connection does.
    pub cipher_name: String,
    /// Whatever the program stored with `SSL_set_ex_data`. `libcurl`
    /// keeps its own connection state there and dereferences what it
    /// gets back, so this has to be real storage rather than a stub.
    ///
    /// Held as `usize` rather than a pointer so the map stays `Send`:
    /// the value is the program's and is never dereferenced here.
    pub ex_data: std::collections::HashMap<c_int, usize>,
}

// SAFETY: as above.
unsafe impl Send for Connection {}

impl Connection {
    pub fn new(context: Arc<Mutex<Context>>, settings: Arc<Settings>) -> Connection {
        let options = context.lock().map(|c| c.options).unwrap_or(0);
        Connection {
            context,
            settings,
            hostname: None,
            transport: Transport::None,
            options,
            alpn: None,
            alpn_selected: None,
            inner: None,
            established: false,
            shutdown_sent: false,
            peer_closed: false,
            verify_result: 0,
            peer_chain: Vec::new(),
            peer_certificate: std::ptr::null_mut(),
            peer_stack: std::ptr::null_mut(),
            pending: Vec::new(),
            last_error: 0,
            failure: None,
            outbox: Vec::new(),
            pending_write: None,
            cipher_name: String::new(),
            ex_data: std::collections::HashMap::new(),
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: each pointer is null or one we made, freed once.
        unsafe {
            crate::objects::x509_free(self.peer_certificate);
            crate::objects::x509_stack_free(self.peer_stack);
            if let Transport::Bios { read, write } = self.transport {
                crate::objects::bio_free_all(read);
                if write != read {
                    crate::objects::bio_free_all(write);
                }
            }
        }
        self.peer_certificate = std::ptr::null_mut();
        self.peer_stack = std::ptr::null_mut();
    }
}
